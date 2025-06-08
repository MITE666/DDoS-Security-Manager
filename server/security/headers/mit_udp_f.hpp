#pragma once

#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "../../src/config.hpp"


class UDPFloodMitigator {
public:
    UDPFloodMitigator(std::size_t threshold, std::size_t window_ms, std::size_t max_payload);
    ~UDPFloodMitigator();

    void run();

private:
    int         raw_socket_;
    std::size_t threshold_;
    std::size_t window_ms_;
    std::size_t max_payload_;

    using Clock = std::chrono::steady_clock;

    struct WindowInfo {
        std::size_t                             count;
        Clock::time_point   window_start;
    };

    std::unordered_map<std::string, WindowInfo>     counters_;
    std::unordered_set<std::string>                 already_blocked_;
    std::mutex                                      mtx_;

    void block_source(const std::string& src_ip);
    static std::string ip_to_string(uint32_t ip_network_order);
};
