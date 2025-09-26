// #ifndef __AGENT_CONNECTION_H
// #define __AGENT_CONNECTION_H

// #include "common_user.h"
// #include "utils.h"
// #include <curl/curl.h>
// #include <string>
// #include <thread>
// #include <atomic>

// struct CallbackCtx {
//     std::string buffer;
//     volatile sig_atomic_t* exiting;
// };
// class AgentConnection {
// public: 
//     AgentConnection(volatile sig_atomic_t* external_exit, const std::string& server_url, const std::string& ca);
//     ~AgentConnection();

//     bool start();
//     void stop();

// private:
//     // thread loop
//     void loop();
//      //  callback write data from CURL
//     static size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp);

//     // GET request
//     // std::string http_get(const std::string& path);

//     // POST request
//     void http_post(const std::string& path, const std::string& data);

//     std::string server_url;
//     std::string ca_cert;
//     volatile sig_atomic_t* exiting;
//     std::thread worker_thread;
    
// };
// #endif // __AGENT_CONNECTION_H
#ifndef __AGENT_CONNECTION_H
#define __AGENT_CONNECTION_H
#include "common_user.h"
#include "utils.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <thread>
#include <atomic>
#include <string>

class AgentConnection {
public:
    AgentConnection(volatile sig_atomic_t* external_exit, const std::string& host, const std::string& port, const std::string& ca);
    ~AgentConnection();
    bool start();
    void stop();                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
private:
    void loop();
    void do_resolve();
    void do_handshake();
    void do_read();

    boost::asio::io_context ioc;
    boost::asio::ssl::context ssl_ctx;
    boost::asio::ip::tcp::resolver resolver;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream;

    std::thread worker_thread;
    std::string host;
    std::string port;
    std::string ca_cert;
    volatile sig_atomic_t* exiting;

};

#endif // __AGENT_CONNECTION_H