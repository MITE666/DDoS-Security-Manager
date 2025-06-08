#pragma once

#include <chrono>
#include <cstring>
#include <mutex>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "../../src/config.hpp"

class TCPConnFloodMitigator {
public:
    TCPConnFloodMitigator(size_t idle_threshold_sec, size_t conn_threshold);
    ~TCPConnFloodMitigator();
    
    void run();

private:
    int raw_sock_;
    size_t idle_threshold_sec_;
    size_t conn_threshold_;
    
    using Clock = std::chrono::steady_clock;

    static std::string conn_key(const std::string& src_ip, uint16_t src_port);

    std::unordered_map<std::string, Clock::time_point> last_activity_;

    std::unordered_set<std::string> banned_ips_;

    std::mutex mtx_;

    void sniff_for_data();
    void scan_and_check_idle();
    void ban_ip(const std::string& src_ip);

    static std::string ip_to_string(uint32_t ip_network_order);
};