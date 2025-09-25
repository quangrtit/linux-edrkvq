#include "agent_connection.h"



AgentConnection::AgentConnection(volatile sig_atomic_t* external_exit, const std::string& server_url, const std::string& ca)
    : server_url(server_url), ca_cert(ca), exiting(external_exit) {
        // curl_global_init(CURL_GLOBAL_DEFAULT);
    }

AgentConnection::~AgentConnection() {
    stop();
    // curl_global_cleanup();
}
size_t AgentConnection::write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}
bool AgentConnection::start() {
    if (worker_thread.joinable()) return false; // already started
    worker_thread = std::thread(&AgentConnection::loop, this);
    return true;
}
void AgentConnection::stop() {
    if (worker_thread.joinable()) worker_thread.join();
}


std::string AgentConnection::http_get(const std::string& path) {
    // CURL* curl = curl_easy_init();
    // std::string response;
    // if(curl) {
    //     curl_easy_setopt(curl, CURLOPT_URL, (server_url + path).c_str());
    //     curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert.c_str());
    //     curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    //     curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    //     curl_easy_setopt(curl, CURLOPT_TIMEOUT, 65L);   
    //     curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    //     CURLcode res = curl_easy_perform(curl);
    //     if(res != CURLE_OK) {
    //         std::cerr << "GET failed: " << curl_easy_strerror(res) << std::endl;
    //     }
    //     curl_easy_cleanup(curl);
    // }
    return "response";
}

void AgentConnection::http_post(const std::string& path, const std::string& data) {
    // CURL* curl = curl_easy_init();
    // if(curl) {
    //     curl_easy_setopt(curl, CURLOPT_URL, (server_url + path).c_str());
    //     curl_easy_setopt(curl, CURLOPT_CAINFO, ca_cert.c_str());
    //     curl_easy_setopt(curl, CURLOPT_POST, 1L);
    //     curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

    //     curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    //     curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    //     struct curl_slist* headers = nullptr;
    //     headers = curl_slist_append(headers, "Content-Type: application/json");
    //     curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    //     CURLcode res = curl_easy_perform(curl);
    //     if(res != CURLE_OK) {
    //         std::cerr << "POST failed: " << curl_easy_strerror(res) << std::endl;
    //     }

    //     curl_slist_free_all(headers);
    //     curl_easy_cleanup(curl);
    // }
}
void AgentConnection::loop() {
    // std::cerr << "[Agent] Started agent connection to server: " << server_url << std::endl;
    // while (*exiting == 0) {
    //     std::string command = http_get("/command?wait=60"); 
    //     if (!command.empty()) {
    //         std::cout << "[Agent] Received command: " << command << std::endl;
    //         if (command.find("stop_agent") != std::string::npos) {
    //             *exiting = 1;
    //             break;
    //         }
    //     }
    // }
    
}
