#include "../headers/mit_udp_f.hpp"
#include <cstdlib>
#include <iostream>
#include <unistd.h>
#include <vector>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

UDPFloodMitigator::UDPFloodMitigator(
    std::size_t threshold,
    std::size_t window_ms,
    std::size_t max_payload
)
  : raw_socket_{-1}, 
    threshold_{threshold}, 
    window_ms_{window_ms},
    max_payload_{max_payload}
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
    int forward_sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (forward_sock < 0) {
        perror("forward socket");
        std::exit(1);
    }

    sockaddr_in srv{};
    srv.sin_family      = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr);
    srv.sin_port        = htons(UDP_PROXY_PORT);   

    char buffer[ MAX_PACKET ];
    while (true) {
        ssize_t len = ::recvfrom(raw_socket_, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len <= 0) continue;

        const iphdr*  iph = reinterpret_cast<const iphdr*>(buffer);
        std::size_t ip_hlen = iph->ihl * 4;
        const udphdr* udph = reinterpret_cast<const udphdr*>(buffer + ip_hlen);
        uint16_t srcp = ntohs(udph->source);
        uint16_t dstp = ntohs(udph->dest);

        if (dstp != PORT) continue;

        std::string src_ip = ip_to_string(iph->saddr);
        std::string key   = src_ip + ":" + std::to_string(srcp);

        {
            std::lock_guard<std::mutex> lk(mtx_);
            auto& info = counters_[key];
            auto  now  = Clock::now();
            if ( now - info.window_start > std::chrono::milliseconds(window_ms_) ) {
                info.window_start = now;
                info.count = 0;
            }
            info.count++;
            if ( info.count > threshold_ ) {
                if (already_blocked_.insert(src_ip).second) {
                    block_source(src_ip);
                }
                std::cout << "TOO MANY PER WINDOW" << std::endl;
                continue; 
            }
            if (ntohs(udph->len) - sizeof(udphdr) > max_payload_) {
                if (already_blocked_.insert(src_ip).second) {
                    block_source(src_ip);
                }
                std::cout << "TOO BIG OF A PACKET" << std::endl;
                continue;
            }
        }

        std::string header = "FROM " + src_ip + ":" + std::to_string(srcp) + "\n";
        std::vector<char> out;
        out.reserve(header.size() + (ntohs(udph->len)-sizeof(udphdr)));
        out.insert(out.end(), header.begin(), header.end());
        const char* payload_ptr = buffer + ip_hlen + sizeof(udphdr);
        std::size_t payload_len = ntohs(udph->len) - sizeof(udphdr);
        out.insert(out.end(), payload_ptr, payload_ptr + payload_len);

        ::sendto(forward_sock, out.data(), out.size(), 0,
                 reinterpret_cast<sockaddr*>(&srv), sizeof(srv));
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