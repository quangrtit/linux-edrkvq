#include "agent_connection.h"
#include <iostream>
#include <chrono>

namespace asio = boost::asio;
namespace ssl  = boost::asio::ssl;
using tcp = asio::ip::tcp;

AgentConnection::AgentConnection(volatile sig_atomic_t* external_exit,
                                 const std::string& host,
                                 const std::string& port,
                                 const std::string& ca)
    : ssl_ctx(ssl::context::tls_client),
      resolver_(ioc),
      timer_(ioc),
      host_(host),
      port_(port),
      ca_cert_(ca),
      exiting(external_exit),
      stopping_(false)
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
    std::cerr << "[Agent] Received data: " << data << "\n";
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
        } else if (cmd == "add_ioc") {
            std::cerr << "[Agent] Add IOC received\n";
        } else if (cmd == "add_ip") {
            std::cerr << "[Agent] Add IP received\n";
        } else if (cmd == "delete_ip") {
            std::cerr << "[Agent] Delete IP received\n";
        }
    }

    cJSON_Delete(root);
}