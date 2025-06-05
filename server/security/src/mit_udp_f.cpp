#include "../headers/mit_udp_f.hpp"
#include <cstdlib>
#include <iostream>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

UDPFloodMitigator::UDPFloodMitigator(
    std::size_t threshold,
    std::size_t window_ms
)
  : raw_socket_{-1}, 
    threshold_{threshold}, 
    window_ms_{window_ms} 
{
    raw_socket_ = ::socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_socket_ < 0) {
        std::perror("UDPFloodMitigator: cannot create raw socket");
        std::exit(EXIT_FAILURE);
    }

    std::cout << "[mit_udp_f] Starting UDP-flood sniffer on raw socket. "
              << "Threshold=" << threshold_ << "packets/"
              << window_ms_ << "ms" << std::endl;
}

UDPFloodMitigator::~UDPFloodMitigator() {
    if (raw_socket_ >= 0) {
        ::close(raw_socket_);
    }
}

void UDPFloodMitigator::run() {
    char buffer[MAX_PACKET];
    
    while (true) {
        ssize_t n = ::recvfrom(raw_socket_, buffer, MAX_PACKET, 0, nullptr, nullptr);
        if (n <= 0) {
            continue;
        }
        process_one_packet(buffer, n);
    }
}

void UDPFloodMitigator::process_one_packet(const char* buffer, ssize_t len) {
    if (len < static_cast<ssize_t>(sizeof(iphdr) - sizeof(udphdr))) {
        return;
    }

    const iphdr* ip_header = reinterpret_cast<const iphdr*>(buffer);
    if (ip_header->version != 4) {
        return;
    }

    uint32_t src_ip_network_order = ip_header->saddr;
    uint32_t dst_ip_network_order = ip_header->daddr;

    std::size_t ip_header_len = ip_header->ihl * 4;
    if (len < static_cast<ssize_t>(ip_header_len + sizeof(udphdr))) {
        return;
    }

    const udphdr* udp_header = reinterpret_cast<const udphdr*>(buffer + ip_header_len);
    uint16_t dst_port = ntohs(udp_header->dest);
    uint16_t src_port = ntohs(udp_header->source);

    if (dst_port != PORT) {
        return;
    }

    std::string src_ip_str = ip_to_string(src_ip_network_order);

    {
        std::lock_guard<std::mutex> lock(mtx_);

        if (already_blocked_.count(src_ip_str)) {
            return;
        }

        auto it = counters_.find(src_ip_str);
        auto now = Clock::now();

        if (it == counters_.end()) {
            WindowInfo info;
            info.count = 1;
            info.window_start = now;
            counters_.emplace(src_ip_str, info);
        } else {
            auto& win = it->second;
            auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - win.window_start).count();

            if (static_cast<std::size_t>(elapsed_ms) > window_ms_) {
                win.count = 1;
                win.window_start = now;
            } else {
                win.count++;
            }

            if (win.count > threshold_) {
                std::cout << "[mit_udp_f] Detected UDP flood from " << src_ip_str
                          << " (" << win.count << " pkts in " << elapsed_ms << "ms) - BLOCKING" << std::endl;

                block_source(src_ip_str);
                already_blocked_.insert(src_ip_str);

                counters_.erase(it);
            }
        }
    }
}

void UDPFloodMitigator::block_source(const std::string& src_ip) {
    std::string cmd = "iptables -A INPUT -p udp -s " + src_ip
                    + " --dport " + std::to_string(PORT)
                    + " -j DROP";

    int ret = std::system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "[mit_udp_f] WARNING: iptables command failed with exit code " << ret << std::endl;
    } else {
        std::cout << "[mit_udp_f] iptables DROP rule added for " << src_ip << std::endl;
    }
}

std::string UDPFloodMitigator::ip_to_string(uint32_t ip_network_order) {
    struct in_addr in;
    in.s_addr = ip_network_order;
    char buf[INET_ADDRSTRLEN];
    if (::inet_ntop(AF_INET, &in, buf, INET_ADDRSTRLEN) == nullptr) {
        return "<bad-ip>";
    } else {
        return std::string(buf);
    }
}