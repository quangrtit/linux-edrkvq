#ifndef __AGENT_CONNECTION_H
#define __AGENT_CONNECTION_H
#include "common_user.h"
#include "utils.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <thread>
#include <atomic>
#include <string>
#include <boost/asio/deadline_timer.hpp>

class AgentConnection {
public:
    AgentConnection(volatile sig_atomic_t* external_exit, const std::string& host, const std::string& port, const std::string& ca);
    ~AgentConnection();
    bool start();
    void stop();                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        
private:
    void tryConnect();
    void scheduleReconnect();
    void do_handshake();
    void do_write_request();
    void do_read();
    void handle_message(const std::string& data);

    boost::asio::io_context ioc;
    boost::asio::ssl::context ssl_ctx;
    std::shared_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> socket_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::deadline_timer timer_;
    std::thread worker_thread;
    std::string host_;
    std::string port_;
    std::string ca_cert_;
    volatile sig_atomic_t* exiting;
    bool stopping_;
};

#endif // __AGENT_CONNECTION_H