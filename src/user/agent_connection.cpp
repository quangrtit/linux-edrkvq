// #include "agent_connection.h"

// AgentConnection::AgentConnection(volatile sig_atomic_t* external_exit,
//                                  const std::string& server_url,
//                                  const std::string& ca)
//     : server_url(server_url), ca_cert(ca), exiting(external_exit) {
//     curl_global_init(CURL_GLOBAL_DEFAULT);
// }

// AgentConnection::~AgentConnection() {
//     stop();
//     curl_global_cleanup();
// }

// size_t AgentConnection::write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
//     CallbackCtx* ctx = reinterpret_cast<CallbackCtx*>(userp);
//     std::string chunk((char*)contents, size * nmemb);
//     ctx->buffer += chunk;

//     size_t pos;
//     while ((pos = ctx->buffer.find("\n\n")) != std::string::npos) {
//         std::string event = ctx->buffer.substr(0, pos);
//         ctx->buffer.erase(0, pos + 2);

//         if (event.rfind("data:", 0) == 0) {
//             std::string json_str = event.substr(5); // skip "data:"
//             std::cerr << "[Agent] Event: " << json_str << std::endl;

//             if (json_str.find("\"stop\"") != std::string::npos) {
//                 std::cerr << "[Agent] Stop signal received" << std::endl;
//                 if (ctx->exiting) *ctx->exiting = 1;
//                 // Return 0 to force curl to abort and let the thread exit
//                 return 0;
//             }
//         }
//     }
//     return size * nmemb;
// }

// bool AgentConnection::start() {
//     if (worker_thread.joinable()) return false; // already started
//     worker_thread = std::thread(&AgentConnection::loop, this);
//     return true;
// }

// void AgentConnection::stop() {
//     if (worker_thread.joinable()) worker_thread.join();
// }

// void AgentConnection::loop() {
//     std::cerr << "[Agent] Connecting to SSE stream: " << server_url << "/events" << std::endl;

//     while (!*exiting) {
//         CURL* curl = curl_easy_init();
//         if (!curl) break;

//         CallbackCtx ctx;
//         ctx.exiting = exiting;
//         ctx.buffer.clear();

//         curl_easy_setopt(curl, CURLOPT_URL, (server_url + "/events").c_str());
//         curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert.c_str());
//         curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
//         curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);
//         curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L); // timeout mỗi lần connect

//         CURLcode res = curl_easy_perform(curl);
//         curl_easy_cleanup(curl);

//         if (*exiting) break;

//         // nếu lỗi hay server đóng, thử reconnect sau 1s
//         std::this_thread::sleep_for(std::chrono::seconds(1));
//     }
// }

// void AgentConnection::http_post(const std::string& path, const std::string& data) {
//     CURL* curl = curl_easy_init();
//     if(curl) {
//         curl_easy_setopt(curl, CURLOPT_URL, (server_url + path).c_str());
//         curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert.c_str());
//         curl_easy_setopt(curl, CURLOPT_POST, 1L);
//         curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

//         struct curl_slist* headers = nullptr;
//         headers = curl_slist_append(headers, "Content-Type: application/json");
//         curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

//         CURLcode res = curl_easy_perform(curl);
//         if(res != CURLE_OK) {
//             std::cerr << "POST failed: " << curl_easy_strerror(res) << std::endl;
//         }

//         curl_slist_free_all(headers);
//         curl_easy_cleanup(curl);
//     }
// }
#include "agent_connection.h"
#include <iostream>
#include <chrono>

namespace asio = boost::asio;
namespace ssl  = boost::asio::ssl;
using tcp = asio::ip::tcp;

AgentConnection::AgentConnection(volatile sig_atomic_t* external_exit,
                                 const std::string& host_,
                                 const std::string& port_,
                                 const std::string& ca)
    : ssl_ctx(ssl::context::tls_client),
      resolver(ioc),
      stream(ioc, ssl_ctx),
      host(host_), port(port_), ca_cert(ca), exiting(external_exit) 
{
    ssl_ctx.set_verify_mode(ssl::verify_peer);
    ssl_ctx.load_verify_file(ca_cert);
}

AgentConnection::~AgentConnection() {
    stop();
}

bool AgentConnection::start() {
    if (worker_thread.joinable()) return false;
    worker_thread = std::thread(&AgentConnection::loop, this);
    return true;
}

void AgentConnection::stop() {
    if (worker_thread.joinable()) {
        ioc.stop();
        worker_thread.join();
    }
}

void AgentConnection::loop() {
    while (!*exiting) {
        try {
            do_resolve();
            ioc.run();
        } catch (std::exception& e) {
            std::cerr << "[Agent] Exception: " << e.what() << std::endl;
        }

        if (*exiting) break;

        std::cerr << "[Agent] Reconnecting in 1s..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));

        ioc.restart();
    }
}

void AgentConnection::do_resolve() {
    auto self = this;
    resolver.async_resolve(host, port,
        [self](auto ec, auto results) {
            if (!ec) {
                asio::async_connect(self->stream.next_layer(), results,
                    [self](auto ec, auto) {
                        if (!ec) {
                            self->do_handshake();
                        } else {
                            std::cerr << "[Agent] Connect error: " << ec.message() << std::endl;
                        }
                    });
            } else {
                std::cerr << "[Agent] Resolve error: " << ec.message() << std::endl;
            }
        });
}

void AgentConnection::do_handshake() {
    auto self = this;
    stream.async_handshake(ssl::stream_base::client,
        [self](auto ec) {
            if (!ec) {
                std::cerr << "[Agent] TLS handshake success\n";
                self->do_read();
            } else {
                std::cerr << "[Agent] TLS handshake error: " << ec.message() << std::endl;
            }
        });
}

void AgentConnection::do_read() {
    auto buf = std::make_shared<std::vector<char>>(1024);
    auto self = this;
    std::cerr << "[Agent] Waiting for data...\n";
    stream.async_read_some(asio::buffer(*buf),
        [self, buf](auto ec, std::size_t n) {
            if (!ec) {
                std::string data(buf->data(), n);
                std::cerr << "[Agent] Received: " << data << std::endl;
                self->do_read(); 
            } else {
                if (ec != asio::error::eof)
                    std::cerr << "[Agent] Read error: " << ec.message() << std::endl;
            }
        });
}