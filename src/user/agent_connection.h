// #ifndef __AGENT_CONNECTION_H
// #define __AGENT_CONNECTION_H

// #include "common_user.h"
// #include "utils.h"
// #include <curl/curl.h>
// #include <string>
// #include <thread>
// #include <atomic>


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
//     std::string http_get(const std::string& path);

//     // POST request
//     void http_post(const std::string& path, const std::string& data);

//     std::string server_url;
//     std::string ca_cert;
//     volatile sig_atomic_t* exiting;
//     std::thread worker_thread;
    
// };
// #endif // __AGENT_CONNECTION_H