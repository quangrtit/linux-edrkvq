#include "agent_connection.h"
#include <iostream>
#include <chrono>

namespace asio = boost::asio;
namespace ssl  = boost::asio::ssl;
using tcp = asio::ip::tcp;

AgentConnection::AgentConnection(volatile sig_atomic_t* external_exit,
                                 const std::string& host,
                                 const std::string& port,
                                 const std::string& ca,
                                 struct agent_args* args)
    : ssl_ctx(ssl::context::tls_client),
      resolver_(ioc),
      timer_(ioc),
      host_(host),
      port_(port),
      ca_cert_(ca),
      exiting(external_exit),
      stopping_(false),
      args_(args)
{
    ssl_ctx.set_verify_mode(ssl::verify_peer);
    ssl_ctx.load_verify_file(ca_cert_);
}

AgentConnection::~AgentConnection() {
    stop();
}

bool AgentConnection::start() {
    if (worker_thread.joinable()) return false;
    worker_thread = std::thread([this] {
        tryConnect();
        ioc.run();
    });
    return true;
}

void AgentConnection::stop() {
    stopping_ = true;
    ioc.stop();
    if (socket_) {
        boost::system::error_code ec;
        socket_->lowest_layer().close(ec);
    }
    if (worker_thread.joinable()) worker_thread.join();
}

void AgentConnection::tryConnect() {
    if (stopping_ || *exiting) return;

    if (socket_) {
        boost::system::error_code ec;
        socket_->lowest_layer().close(ec);
        socket_.reset();
    }

    socket_ = std::make_shared<ssl::stream<tcp::socket>>(ioc, ssl_ctx);

    auto endpoints = resolver_.resolve(host_, port_);
    asio::async_connect(socket_->lowest_layer(), endpoints,
        [this](auto ec, auto) {
            if (!ec) {
                socket_->async_handshake(ssl::stream_base::client,
                    [this](auto ec) {
                        if (!ec) {
                            std::cerr << "[Agent] TLS handshake success\n";
                            do_write_request();
                        } else {
                            std::cerr << "[Agent] Handshake error: " << ec.message() << "\n";
                            scheduleReconnect();
                        }
                    });
            } else {
                std::cerr << "[Agent] Connection error: " << ec.message() << "\n";
                scheduleReconnect();
            }
        });
}
void AgentConnection::scheduleReconnect() {
    if (stopping_ || *exiting) return;

    if (socket_) {
        boost::system::error_code ec;
        socket_->lowest_layer().close(ec);
        socket_.reset();
    }

    timer_.expires_from_now(boost::posix_time::seconds(5));
    timer_.async_wait([this](const boost::system::error_code& ec) {
        if (!ec && !stopping_ && !*exiting) {
            std::cerr << "[Agent] Retrying connection...\n";
            tryConnect();
        }
    });
}

void AgentConnection::do_write_request() {
    auto self = this;
    std::string req =
        "GET /events HTTP/1.1\r\n"
        "Host: " + host_ + "\r\n"
        "Accept: application/json\r\n"
        "Connection: keep-alive\r\n\r\n";

    asio::async_write(*socket_, asio::buffer(req),
        [this](auto ec, std::size_t) {
            if (!ec) {
                std::cerr << "[Agent] Request sent, waiting for data...\n";
                do_read();
            } else {
                std::cerr << "[Agent] Write error: " << ec.message() << "\n";
                scheduleReconnect();
            }
        });
}

void AgentConnection::do_read() {
    auto buf = std::make_shared<std::vector<char>>(4096);
    socket_->async_read_some(asio::buffer(*buf),
        [this, buf](auto ec, std::size_t n) {
            if (!ec) {
                std::string data(buf->data(), n);
                handle_message(data);
                do_read(); 
            } else {
                std::cerr << "[Agent] Read error: " << ec.message() << "\n";
                scheduleReconnect();
            }
        });
}

void AgentConnection::handle_message(const std::string& data) {
    /*
      exmaple json received:
      {
        "type": "ioc_update",
        "timestamp": 1727359200,
        "data": {
          "file_hashes": [
            {
              "value": "ccf29345b53dd399ee1a1561e99871b2d29219682392e601002099df77c18709",
              "first_seen": 1727359000,
              "last_seen": 1727359000,
              "source": "admin"
            }
          ], 
          "ips": [
            {
              "value": "192.140.87.197",
              "first_seen": 1727359000,
              "last_seen": 1727359000,
              "source": "admin"
            }
          ]
        }
    }
    */
    std::cerr << "[Agent] Received data: " << data << "\n";
    IOCDatabase *db = args_->db;
    struct self_defense_bpf *skel_self_defense = args_->skel_self_defense;
    struct ioc_block_bpf *skel_ioc_block = args_->skel_ioc_block;
    cJSON* root = cJSON_Parse(data.c_str());
    if (!root) {
        std::cerr << "[Agent] JSON parse error\n";
        return;
    }
    cJSON* action = cJSON_GetObjectItemCaseSensitive(root, "type");
    if (cJSON_IsString(action) && action->valuestring) {
        std::string cmd(action->valuestring);

        if (cmd == "stop_service") {
            std::cerr << "[Agent] Stop action received\n";
            if (exiting) *exiting = 1;
        } else if (cmd == "ioc_update") {
            std::cerr << "[Agent] Update IOC received\n";
            cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
            if (cJSON_IsObject(data)) {
                std::cerr << "Debug [Agent] Processing IOC update\n";
                // Process the IOC update
                cJSON* file_hashes = cJSON_GetObjectItemCaseSensitive(data, "file_hashes");
                cJSON* ips = cJSON_GetObjectItemCaseSensitive(data, "ips");
                if (cJSON_IsArray(file_hashes)) {
                    cJSON* file_hash = NULL;
                    cJSON_ArrayForEach(file_hash, file_hashes) {
                        if (cJSON_IsObject(file_hash)) {
                            // Extract file hash information
                            std::string value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(file_hash, "value"));
                            std::cerr << "[Agent] UpdateFile hash: " << (value.empty() ? "null" : value) << "\n";
                        }
                    }
                }
                if (cJSON_IsArray(ips)) {
                    // std::cerr << "debug: found ips array\n";
                    cJSON* ip = NULL;
                    cJSON_ArrayForEach(ip, ips) {
                        if (cJSON_IsObject(ip)) {
                            // Extract IP information
                            std::string value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ip, "value"));
                            std::cerr << "[Agent] Update IP: " << (!value.empty() ? value : "null") << "\n";
                            std::cerr << "this is size ip: " << value.size() << std::endl;
                            IOCMeta meta;
                            db->add_ip(value, meta);
                            struct ip_lpm_key lpm_key = {};
                            __u32 verdict = 1; // block
                            // std::cerr << "debug map err 1: \n";
                            if (value.find(':') != std::string::npos) {
                                // IPv6
                                lpm_key.prefixlen = 128;
                                if (inet_pton(AF_INET6, value.c_str(), lpm_key.data) != 1) {
                                    std::cerr << "Invalid IPv6: " << value << std::endl;
                                    continue;
                                }
                            } else {
                                // IPv4
                                lpm_key.prefixlen = 32;
                                if (inet_pton(AF_INET, value.c_str(), lpm_key.data) != 1) {
                                    std::cerr << "Invalid IPv4: " << value << std::endl;
                                    continue;
                                }
                            }
                            // std::cerr << "debug map err 2: \n";
                            // // debug: verify map and fd
                            // if (!skel_ioc_block || !skel_ioc_block->maps.ioc_ip_map) {
                            //     std::cerr << "[Agent][IOC] skel_ioc_block or ioc_ip_map is NULL\n";
                            //     continue;
                            // }
                            // int map_fd = bpf_map__fd(skel_ioc_block->maps.ioc_ip_map);
                            // if (map_fd < 0) {
                            //     std::cerr << "[Agent][IOC] map_fd invalid: " << map_fd << "\n";
                            //     continue;
                            // }

                            // std::cerr << "[Agent][IOC] BEFORE update fd=" << map_fd
                            //         << " key_size=" << sizeof(lpm_key)
                            //         << " value_size=" << sizeof(verdict) << "\n";
                            // static_assert(sizeof(struct ip_lpm_key) == 20,
                            // "ip_lpm_key size mismatch, must be 20");
                            if (bpf_map__update_elem(skel_ioc_block->maps.ioc_ip_map,
                                                    &lpm_key, sizeof(lpm_key),
                                                    &verdict, sizeof(verdict),
                                                    BPF_ANY) != 0) {
                                perror("update ioc_ip_map bpf_map__update_elem failed");
                            }
                             // delete cache if have 
                            if (bpf_map__delete_elem(skel_ioc_block->maps.block_list_ip, 
                                &lpm_key, sizeof(lpm_key), 0) != 0) {
                                perror("update block_list_ip bpf_map__delete_elem failed");
                            }
                        }
                    }
                }
            }
        } else if (cmd == "ioc_delete") {
            std::cerr << "[Agent] Delete IOC received\n";
            cJSON* data = cJSON_GetObjectItemCaseSensitive(root, "data");
            if (cJSON_IsObject(data)) {
                // Process the IOC deletion
                cJSON* file_hashes = cJSON_GetObjectItemCaseSensitive(data, "file_hashes");
                cJSON* ips = cJSON_GetObjectItemCaseSensitive(data, "ips");
                if (cJSON_IsArray(file_hashes)) {
                    cJSON* file_hash = NULL;
                    cJSON_ArrayForEach(file_hash, file_hashes) {
                        if (cJSON_IsObject(file_hash)) {
                            // Extract file hash information
                            std::string value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(file_hash, "value"));
                            std::cerr << "[Agent] Delete File hash: " << (value.empty() ? "null" : value) << "\n";
                        }
                    }
                }
                if (cJSON_IsArray(ips)) {
                    cJSON* ip = NULL;
                    cJSON_ArrayForEach(ip, ips) {
                        if (cJSON_IsObject(ip)) {
                            // Extract IP information
                            std::string value = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(ip, "value"));
                            std::cerr << "[Agent] Delete IP: " << (value.empty() ? "null" : value) << "\n";
                            if (db->delete_ip(value)) {
                                std::cerr << "[Agent] Deleted IP real: " << value << std::endl;
                                struct ip_lpm_key lpm_key = {};

                                if (value.find(':') != std::string::npos) {
                                    // IPv6
                                    lpm_key.prefixlen = 128;
                                    if (inet_pton(AF_INET6, value.c_str(), lpm_key.data) != 1) {
                                        std::cerr << "Invalid IPv6: " << value << std::endl;
                                        continue;
                                    }
                                } else {
                                    // IPv4
                                    lpm_key.prefixlen = 32;
                                    if (inet_pton(AF_INET, value.c_str(), lpm_key.data) != 1) {
                                        std::cerr << "Invalid IPv4: " << value << std::endl;
                                        continue;
                                    }
                                }
                                // delete ioc 
                                if (bpf_map__delete_elem(skel_ioc_block->maps.ioc_ip_map,
                                    &lpm_key, sizeof(lpm_key), 0) != 0) {
                                    perror("delete ioc_ip_map bpf_map__delete_elem failed");
                                }
                                // delete cache if have 
                                if (bpf_map__delete_elem(skel_ioc_block->maps.block_list_ip, 
                                    &lpm_key, sizeof(lpm_key), 0) != 0) {
                                    perror("delete block_list_ip bpf_map__delete_elem failed");
                                }

                            } else {
                                std::cerr << "[Server Thread] IP not found: " << value << std::endl;
                            }
                        }
                    }
                }
            }
        }
    }

    cJSON_Delete(root);
}