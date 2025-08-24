#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <cstring>
#include <thread>
#include <set>
#include <map>
#include <unordered_map>
#include <openssl/hmac.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "../../src/config.hpp"

class TCPSYNCookieProxy {
public:
    TCPSYNCookieProxy(const std::string& secret_key, std::size_t window_secs, const int max_dropped);
    ~TCPSYNCookieProxy();

    void run();

private:
    bool                        capped_;

    int                         recv_sock_;
    int                         send_sock_;
    int                         udp_sock_;

    const std::string           secret_key_;
    const std::size_t           window_secs_;
    const int                   max_dropped_;

    std::set<std::pair<std::string, uint16_t>> promoted_flows_;
    
    std::set<std::string>                      banned_ips_;
    std::mutex                                 ban_mtx_;

    std::map<std::pair<std::string, uint16_t>, uint32_t> next_server_seq_;

    using Clock = std::chrono::steady_clock;

    std::atomic<std::size_t>    syn_counter_{0};
    std::atomic<std::size_t>    promoted_counter_{0};
    std::mutex                  cookie_mtx_;

    void sniff_for_syns();
    void periodic_logger();
    void send_synack(const std::string& src_ip, uint16_t src_port, uint32_t cookie, uint32_t client_isn, const std::string& dst_ip);
    uint32_t compute_cookie(const std::string& src_ip, uint16_t src_port, uint64_t time_slice);
    static std::string ip_to_string(uint32_t ip_network_order);
    void forge_and_send_tcp_payload(int send_sock, const std::string& client_ip, uint16_t client_port, const std::string& server_ip, const tcphdr* th, const char* payload_ptr, size_t payload_len, uint32_t client_payload_len);
    static void update_conn_activity(const std::string& ip, uint16_t port);
    static void remove_conn_activity(const std::string& ip, uint16_t port);
    static void remove_conn_activity_for_ip(const std::string& ip);
    void reload_banned_ips();
    void ban_reload_loop();
    void enable_limiter();
};
