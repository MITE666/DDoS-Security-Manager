#include "../headers/mit_tcp_cf.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <cstdlib>
#include <chrono>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>

TCPConnFloodMitigator::TCPConnFloodMitigator(
    size_t idle_threshold_sec,
    size_t conn_threshold
)
  : raw_sock_{-1},
    idle_threshold_sec_{idle_threshold_sec},
    conn_threshold_{conn_threshold}
{ 
    raw_sock_ = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock_ < 0) {
        std::perror("TCPConnFloodMitigator: cannot create raw socket");
        std::exit(EXIT_FAILURE);
    }
    std::cout << "[mit_tcp_cf] Raw TCP socket opened. idle_thresh="
              << idle_threshold_sec_
              << "s, conn_thresh=" << conn_threshold_   
              << "s" << std::endl;
}

TCPConnFloodMitigator::~TCPConnFloodMitigator() { 
    if (raw_sock_ >= 0) {
        ::close(raw_sock_);
    }
}

void TCPConnFloodMitigator::run() {
    std::thread sniffer([&](){ sniff_for_data(); });
    while(true) {
        scan_and_check_idle();
    }
}

void TCPConnFloodMitigator::sniff_for_data()
{
    char buffer[MAX_PACKET];

    while (true) {
        ssize_t len = ::recvfrom(raw_sock_, buffer, MAX_PACKET, 0, nullptr, nullptr);
        if (len <= 0) {
            continue;
        }

        if (len < static_cast<ssize_t>(sizeof(iphdr))) continue;
        const iphdr* iph = reinterpret_cast<const iphdr*>(buffer);
        if (iph->version != 4) continue;
        std::size_t ip_hlen = iph->ihl * 4;
        if (len < static_cast<ssize_t>(ip_hlen + sizeof(tcphdr))) continue;

        const tcphdr* th = reinterpret_cast<const tcphdr*>(buffer + ip_hlen);
        uint16_t srcp = ntohs(th->source);
        uint16_t dstp = ntohs(th->dest);
        
        
        if (dstp != PORT) continue;  

        std::string src_ip = ip_to_string(iph->saddr);
        std::string key = conn_key(src_ip, srcp);
        auto now = Clock::now();

        {
            std::lock_guard<std::mutex> lock(mtx_);
            last_activity_[key] = now;
        }
    }
}

void TCPConnFloodMitigator::scan_and_check_idle()
{
    auto now = Clock::now();

    auto conns = list_established_conns();

    std::unordered_map<std::string,std::size_t> per_ip_count;
    for (auto& kv : conns) {
        per_ip_count[kv.second] += 1;
    }

    {
        std::lock_guard<std::mutex> lock(mtx_);

        std::vector<std::string> keys_to_erase;
        for (auto& kv : last_activity_) {
            const std::string& key = kv.first;
            auto it_conn = conns.find(key);

            if (it_conn == conns.end()) {
                keys_to_erase.push_back(key);
                continue;
            }

            auto last_ts = kv.second;
            auto idle_s = std::chrono::duration_cast<std::chrono::seconds>(now - last_ts).count();
            const std::string& src_ip = it_conn->second;

            if (static_cast<std::size_t>(idle_s) > idle_threshold_sec_) {
                if (!banned_ips_.count(src_ip)) {
                    std::cout << "[mit_tcp_cf] IP " << src_ip
                              << " has an idle socket (idle " << idle_s << "s) -> BAN" << std::endl;
                    ban_ip(src_ip);
                }
                keys_to_erase.push_back(key);
                continue;
            }
        }
        for (auto& k : keys_to_erase) {
            last_activity_.erase(k);
        }

        for (auto& kv : per_ip_count) {
            const std::string& ip    = kv.first;
            std::size_t         count = kv.second;
            if (count > conn_threshold_) {
                if (!banned_ips_.count(ip)) {
                    std::cout << "[mit_tcp_cf] IP " << ip
                              << " has " << count
                              << " ESTABLISHED connections -> BAN" << std::endl;
                    ban_ip(ip);
                }
            }
        }
    }
}



void TCPConnFloodMitigator::ban_ip(const std::string& src_ip)
{
    std::string cmd = "iptables -A INPUT -p tcp -s " + src_ip
                    + " --dport " + std::to_string(PORT) + " -j DROP";

    int ret = std::system(cmd.c_str());
    if (ret == 0) {
        banned_ips_.insert(src_ip);
        std::cout << "[mit_tcp_cf] iptables DROP rule added for " << src_ip << std::endl;
    } else {
        std::cerr << "[mit_tcp_cf] WARNING: iptables ADD failed for "
                  << src_ip << " (exit " << ret << ")" << std::endl;
    }

    std::string flush_cmd = "conntrack -D -p tcp -s " + src_ip
                        + " --dport " + std::to_string(PORT) + " >/dev/null 2>&1";
    int r2 = std::system(flush_cmd.c_str());
    if (r2 != 0) {
        std::cerr << "[mit_tcp_cf] WARNING: conntrack delete failed for " << src_ip 
                << " (exit " << r2 << ")" << std::endl;
    } else {
        std::cout << "[mit_tcp_cf] conntrack state removed for " << src_ip << std::endl;
    }
}

std::unordered_map<std::string, std::string>
TCPConnFloodMitigator::list_established_conns()
{
    std::unordered_map<std::string, std::string> result;
    std::ifstream tcpf("/proc/net/tcp");
    if (!tcpf.is_open()) {
        std::cerr << "[mit_tcp_cf] ERROR: cannot open /proc/net/tcp\n";
        return result;
    }

    std::string line;
    std::getline(tcpf, line);  

    while (std::getline(tcpf, line)) {
        std::istringstream iss(line);
        std::string sl, local, rem, st;
        if (!(iss >> sl >> local >> rem >> st)) {
            continue;  
        }
        if (st != "01") {
            continue;  
        }

        auto pos1 = local.find(':');
        auto hex_lport = local.substr(pos1 + 1);
        uint16_t lport = static_cast<uint16_t>(std::stoul(hex_lport, nullptr, 16));
        if (lport != PORT) {
            continue;  
        }

        auto pos2 = rem.find(':');
        auto hex_rip   = rem.substr(0, pos2);
        auto hex_rport = rem.substr(pos2 + 1);
        uint16_t rport = static_cast<uint16_t>(std::stoul(hex_rport, nullptr, 16));
        unsigned long ipn = std::stoul(hex_rip, nullptr, 16);

        struct in_addr a;
        a.s_addr = static_cast<uint32_t>(ipn);  
        char buf[INET_ADDRSTRLEN];
        if (::inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN) == nullptr) {
            continue;  
        }
        std::string rip(buf);

        std::string key = conn_key(rip, rport);
        result.emplace(key, rip);
    }

    return result;
}

std::string TCPConnFloodMitigator::conn_key(const std::string& src_ip, uint16_t src_port)
{
    return src_ip + ":" + std::to_string(src_port)
         + "→" + std::to_string(PORT);
}

std::string TCPConnFloodMitigator::ip_to_string(uint32_t ip_network_order)
{
    struct in_addr a;
    a.s_addr = ip_network_order;  
    char buf[INET_ADDRSTRLEN];
    if (::inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN) == nullptr) {
        return "<invalid‐ip>";
    }
    return std::string(buf);
}