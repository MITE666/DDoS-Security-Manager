#include "../headers/mit_tcpc_sr_f.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <cstdlib>
#include <chrono>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <ctime>
#include <set>

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
    std::cout << "[mit_tcp] Raw TCP socket opened. idle_thresh="
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
    std::time_t now = std::time(nullptr);

    std::unordered_map<std::string, std::time_t> conn_map;

    std::ifstream ifs(CONN_LOG_PATH);
    std::string line;

    while (std::getline(ifs, line)) {
        std::istringstream iss(line);
        std::string key;
        std::time_t ts;
        if (iss >> key >> ts) {
            conn_map[key] = ts;
        }
    }

    std::set<std::pair<std::string, Flag>> ips_to_ban;
    std::unordered_map<std::string, std::size_t> per_ip_count;

    for (auto& [key, last_ts] : conn_map) {
        auto pos = key.find(':');
        if (pos == std::string::npos) continue;
        std::string ip = key.substr(0, pos);
        
        std::size_t idle_s = static_cast<std::size_t>(now - last_ts);
        
        if (idle_s > idle_threshold_sec_) {
            ips_to_ban.insert({ip, SLOW_READ});
            continue;
        } 
        per_ip_count[ip]++;
    }

    for (auto& [ip, count] : per_ip_count) {
        if (count > conn_threshold_) {
            ips_to_ban.insert({ip, FLOOD});
        }
    }

     for (auto& p : ips_to_ban) {
        if (banned_ips_.count(p.first)) continue;
        std::cout << "[mit_tcp] BANNING IP " << p.first << ((p.second == SLOW_READ) ? " (slow read)" : " (flood)") << std::endl;
        ban_ip(p.first);
        banned_ips_.insert(p.first);
    }
}

void TCPConnFloodMitigator::ban_ip(const std::string& src_ip) {
    std::string cmd = "iptables -t raw -I PREROUTING -p tcp -s " + src_ip
                    + " --dport " + std::to_string(PORT) + " -j DROP";

    int ret = std::system(cmd.c_str());
    if (ret == 0) {
        banned_ips_.insert(src_ip);
        std::cout << "[mit_tcp_cf] iptables DROP rule added for " << src_ip << std::endl;
    } else {
        std::cerr << "[mit_tcp_cf] WARNING: iptables ADD failed for "
                  << src_ip << " (exit " << ret << ")" << std::endl;
    }

    std::ofstream ofs(BANNED_IPS_PATH, std::ios::app);
    ofs << src_ip << "\n";
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
