#include "../headers/mit_syn_f.hpp"

#include <errno.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <ctime>
#include <cstdlib>
#include <cstdio>

TCPSYNCookieProxy::TCPSYNCookieProxy(
    const std::string& secret_key,
    std::size_t        window_secs
)
  : recv_sock_{-1},
    send_sock_{-1},
    udp_sock_{-1},
    secret_key_{secret_key},
    window_secs_{window_secs}
{
    int ret = std::system(
        "iptables -I OUTPUT -o eth0 "
        "-p tcp --sport 12345 "
        "--tcp-flags RST RST "
        "-j DROP"
    );
    if (ret != 0) {
        std::cerr << "[mit_syn] ERROR: failed to insert OUTPUT DROP RST rule" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    recv_sock_ = ::socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (recv_sock_ < 0) {
        std::perror("cannot create raw-capture socket");
        std::exit(EXIT_FAILURE);
    }

    send_sock_ = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock_ < 0) {
        std::perror("cannot create raw-send socket");
        std::exit(EXIT_FAILURE);
    }

    int one = 1;
    if (::setsockopt(send_sock_, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        std::perror("[mit_syn_f] setsockopt IP_HDRINCL failed");
        std::exit(EXIT_FAILURE);
    }

    udp_sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock_ < 0) {
        std::perror("[mit_syn_f] cannot create UDP socket");
        std::exit(EXIT_FAILURE);
    }

    std::cout << "[mit_syn_f] READY: raw sockets open, UDP socket ready, DROP rules installed" << std::endl;
}


TCPSYNCookieProxy::~TCPSYNCookieProxy() {
    if (recv_sock_ >= 0) {
        ::close(recv_sock_);
    }

    if (send_sock_ >= 0) {
        ::close(send_sock_);
    }

    if (udp_sock_ >= 0) {
        ::close(udp_sock_);
    }
}

void TCPSYNCookieProxy::run() {
    std::thread(&TCPSYNCookieProxy::ban_reload_loop, this).detach();

    std::thread sniffer([&](){ sniff_for_syns(); });
    std::thread logger([&](){ periodic_logger(); });

    sniffer.join();
    logger.join();
}

void TCPSYNCookieProxy::sniff_for_syns() {
    char buffer[MAX_PACKET + 1];

    while (true) {
        ssize_t len = ::recvfrom(recv_sock_, buffer, MAX_PACKET + 1, 0, nullptr, nullptr);
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
        std::string dst_ip = ip_to_string(iph->daddr);

        {
            std::lock_guard<std::mutex> ban_lk(ban_mtx_);
            if (banned_ips_.count(src_ip)) {
                promoted_flows_.erase({src_ip, srcp});
                remove_conn_activity(src_ip, srcp);
                continue;
            }
        }

        if (promoted_flows_.count({src_ip, srcp}) > 0) {
            if (th->fin == 1 || th->rst == 1) {
                std::cout << "[mit_syn_f] Client " 
                            << src_ip << ":" << srcp 
                            << (th->fin ? " sent FIN" : " sent RST")
                            << " – removing from promoted_flows_" << std::endl;
                promoted_flows_.erase({src_ip, srcp});
                {
                    std::lock_guard<std::mutex> lock(cookie_mtx_);
                    remove_conn_activity(src_ip, srcp);
                }
                continue;
            }
            

            std::size_t tcp_hlen = th->doff * 4;
            std::size_t full_hdr = ip_hlen + tcp_hlen;
            if (static_cast<size_t>(len) > full_hdr) {
                size_t payload_len = len - full_hdr;
                char* payload_ptr  = buffer + full_hdr;

                {
                    std::lock_guard<std::mutex> cookie_lk(cookie_mtx_);
                    update_conn_activity(src_ip, srcp);
                }

                std::cout << "[mit_syn_f] DATA from promoted "
                            << src_ip << ":" << srcp
                            << " - " << payload_len << " bytes" << std::endl;

                std::ostringstream oss;
                oss << "FROM " << src_ip << ":" << srcp << "\n";
                std::string header = oss.str();

                std::vector<char> udp_pkt;
                udp_pkt.reserve(header.size() + payload_len);
                udp_pkt.insert(udp_pkt.end(), header.begin(),  header.end());
                udp_pkt.insert(udp_pkt.end(), payload_ptr, payload_ptr + payload_len);

                sockaddr_in srv{};
                srv.sin_family = AF_INET;
                inet_pton(AF_INET, "127.0.0.1", &srv.sin_addr);
                srv.sin_port = htons(PROXY_PORT);

                ssize_t sent = ::sendto(
                    udp_sock_,
                    udp_pkt.data(),
                    udp_pkt.size(),
                    0,
                    reinterpret_cast<sockaddr*>(&srv),
                    sizeof(srv)
                );
                if (sent < 0) {
                    std::perror("[mit_syn_f] sendto(UDP) failed");
                    continue;
                }

                char udp_resp[MAX_PACKET];
                sockaddr_in from{};
                socklen_t   fromlen = sizeof(from);
                ssize_t rlen = ::recvfrom(
                    udp_sock_,
                    udp_resp,
                    sizeof(udp_resp),
                    0,
                    reinterpret_cast<sockaddr*>(&from),
                    &fromlen
                );
                if (rlen <= 0) {
                    std::cerr << "[mit_syn_f] No UDP response for "
                              << src_ip << ":" << srcp << std::endl;
                    continue;
                }

                std::cout << "[mit_syn_f] UDP response "
                            << rlen << " bytes back from server" << std::endl;

                forge_and_send_tcp_payload(
                    send_sock_,
                    src_ip,
                    srcp,
                    dst_ip,
                    th,
                    udp_resp,
                    static_cast<size_t>(rlen),
                    static_cast<uint32_t>(payload_len)
                );
            }
            continue;
        }

        if (th->syn == 1 && th->ack == 0) {

            syn_counter_.fetch_add(1, std::memory_order_relaxed);

            auto now = Clock::now();
            uint64_t ts = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() / window_secs_;

            uint32_t client_isn = ntohl(th->seq);

            uint32_t cookie = compute_cookie(src_ip, srcp, ts);
            
            send_synack(src_ip, srcp, cookie, client_isn, dst_ip);

            continue;
        }
        
        bool is_pure_ack = th->syn == 0 && th->ack == 1 
                        && th->psh == 0 && th->fin == 0 && th->rst == 0 && th->urg == 0 
                        && (ntohs(iph->tot_len) == ip_hlen + (th->doff * 4));

        if (!is_pure_ack) continue;

        uint32_t recv_ack = ntohl(th->ack_seq);

        auto now = Clock::now();
        uint64_t ts = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count() / window_secs_;

        uint32_t cookie1 = compute_cookie(src_ip, srcp, ts);

        uint32_t cookie0 = compute_cookie(src_ip, srcp, ts - 1);

        uint32_t ack_host = recv_ack - 1;

        if (ack_host == cookie1 || ack_host == cookie0) {
            promoted_counter_.fetch_add(1, std::memory_order_relaxed);
            promoted_flows_.emplace(src_ip, srcp);
            {
                std::lock_guard<std::mutex> cookie_lk(cookie_mtx_);
                update_conn_activity(src_ip, srcp);
           }
        }
    }
}

void TCPSYNCookieProxy::periodic_logger()
{
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(window_secs_));
        std::size_t count = syn_counter_.exchange(0, std::memory_order_relaxed);
        std::size_t promoted = promoted_counter_.exchange(0, std::memory_order_relaxed);
        std::size_t dropped = 0;

        if (count > promoted) {
            dropped = count - promoted;
        }

        // std::cout << "[mit_syn_f] Last " << window_secs_ << "s: "
        //           << count << " SYN(s) seen, "
        //           << promoted << " promoted, "
        //           << dropped << " dropped" << std::endl;
    }
}

uint32_t TCPSYNCookieProxy::compute_cookie(const std::string& src_ip, uint16_t src_port, uint64_t time_slice) {
    std::ostringstream oss;
    oss << src_ip << ":" << src_port << ":" << PORT << ":" << time_slice;
    std::string data = oss.str();

    unsigned int len = 0;
    unsigned char* hmac = HMAC (
        EVP_sha1(),
        reinterpret_cast<const unsigned char*>(secret_key_.data()),
        static_cast<int>(secret_key_.size()),
        reinterpret_cast<const unsigned char*>(data.data()),
        static_cast<int>(data.size()),
        nullptr,
        &len
    );
    if (!hmac || len < 4) {
        uint32_t fallback = 0;
        for (char c : data) {
            fallback = (fallback << 1) ^ static_cast<unsigned char>(c);
        }
        return fallback;
    }

    uint32_t cookie = 0;
    cookie = (static_cast<uint32_t>(hmac[len-4]) << 24) 
           | (static_cast<uint32_t>(hmac[len-3]) << 16)
           | (static_cast<uint32_t>(hmac[len-2]) << 8)
           | (static_cast<uint32_t>(hmac[len-1]));
    return cookie;
}

void TCPSYNCookieProxy::send_synack(
    const std::string& src_ip,
    uint16_t src_port,
    uint32_t cookie,
    uint32_t client_isn,
    const std::string& dst_ip
) {
    unsigned char packet[40];
    memset(packet, 0, sizeof(packet));

    iphdr* iph      = reinterpret_cast<iphdr*>(packet);
    iph->version    = 4;
    iph->ihl        = 5;
    iph->tos        = 0;
    iph->tot_len    = htons(20 + 20);
    iph->id         = htons(0);
    iph->frag_off   = 0;
    iph->ttl        = 64;
    iph->protocol   = IPPROTO_TCP;
    iph->check      = 0;
    iph->saddr      = inet_addr(dst_ip.c_str());
    iph->daddr      = inet_addr(src_ip.c_str());

    tcphdr* th      = reinterpret_cast<tcphdr*>(packet + 20);
    th->source      = htons(PORT);
    th->dest        = htons(src_port);
    th->seq         = htonl(cookie);
    th->ack_seq     = htonl(client_isn + 1);
    th->doff        = 5;
    th->syn         = 1;
    th->ack         = 1;
    th->rst         = 0;
    th->psh         = 0;
    th->urg         = 0;
    th->window      = htons(65535);
    th->check       = 0;
    th->urg_ptr     = 0;

    next_server_seq_[{src_ip, src_port}] = cookie + 1;

    struct {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t tcp_length;
    } pseudo_hdr;
    pseudo_hdr.src_addr     = iph->saddr;
    pseudo_hdr.dst_addr     = iph->daddr;
    pseudo_hdr.zero         = 0;
    pseudo_hdr.proto        = IPPROTO_TCP;
    pseudo_hdr.tcp_length   = htons(20);

    unsigned char checksum_buf[12 + 20];
    memcpy(checksum_buf, &pseudo_hdr, 12);
    memcpy(checksum_buf + 12, th, 20);

    uint32_t sum = 0;
    uint16_t* ptr = reinterpret_cast<uint16_t*>(checksum_buf);
    for (size_t i = 0; i < (12 + 20) / 2; i++) {
        sum += static_cast<uint32_t>(ntohs(ptr[i]));
        if (sum & 0xFFFF0000) {
            sum = (sum & 0xFFFF) + 1;
        }
    }
    th->check = htons(static_cast<uint16_t>(~sum));

    uint16_t* ip_words = reinterpret_cast<uint16_t*>(packet);
    uint32_t ip_sum = 0;
    for (int i = 0; i < 10; i++) {
        ip_sum += static_cast<uint32_t>(ntohs(ip_words[i]));
        if (ip_sum & 0xFFFF0000) {
            ip_sum = (ip_sum & 0xFFFF) + 1;
        }
    }
    iph->check = htons(static_cast<uint16_t>(~ip_sum));

    sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family  = AF_INET;
    dst.sin_port    = th->dest;
    inet_pton(AF_INET, src_ip.c_str(), &dst.sin_addr);

    ssize_t sent = ::sendto(send_sock_, packet, 40, 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    
    if (sent < 0) {
        std::perror("[mit_syn_f] send_synack failed");
    }
}

void TCPSYNCookieProxy::forge_and_send_tcp_payload(
    int send_sock_,
    const std::string& client_ip,
    uint16_t           client_port,
    const std::string& server_ip,
    const tcphdr*      th,
    const char*        payload_ptr,
    size_t             payload_len,
    uint32_t           client_payload_len
) {
    size_t packet_len = 20 + 20 + payload_len;
    std::vector<unsigned char> packet(packet_len);
    memset(packet.data(), 0, packet_len);

    iphdr* iph = reinterpret_cast<iphdr*>(packet.data());
    iph->version  = 4;
    iph->ihl      = 5;
    iph->tos      = 0;
    iph->tot_len  = htons(static_cast<uint16_t>(20 + 20 + payload_len));
    iph->id       = htons(0);
    iph->frag_off = 0;
    iph->ttl      = 64;
    iph->protocol = IPPROTO_TCP;
    iph->check    = 0;
    iph->saddr    = inet_addr(server_ip.c_str());
    iph->daddr    = inet_addr(client_ip.c_str());
    {
        uint16_t* ip_words = reinterpret_cast<uint16_t*>(packet.data());
        uint32_t ip_sum = 0;
        for (int i = 0; i < 10; i++) {
            ip_sum += static_cast<uint32_t>(ntohs(ip_words[i]));
            if (ip_sum & 0xFFFF0000) {
                ip_sum = (ip_sum & 0xFFFF) + 1;
            }
        }
        iph->check = htons(static_cast<uint16_t>(~ip_sum));
    }

    tcphdr* new_th = reinterpret_cast<tcphdr*>(packet.data() + 20);
    new_th->source   = htons(PORT);
    new_th->dest     = htons(client_port);

    uint32_t seq_n = next_server_seq_[{client_ip, client_port}];
    new_th->seq     = htonl(seq_n);

    uint32_t orig_seq = ntohl(th->seq);
    uint32_t ack_n = orig_seq + client_payload_len;
    new_th->ack_seq = htonl(ack_n);

    next_server_seq_[{client_ip, client_port}] = seq_n + static_cast<uint32_t>(payload_len);

    new_th->doff    = 5;       
    new_th->syn     = 0;
    new_th->ack     = 1;
    new_th->psh     = 1;       
    new_th->rst     = 0;
    new_th->fin     = 0;
    new_th->urg     = 0;
    new_th->window  = htons(65535);
    new_th->check   = 0;
    new_th->urg_ptr = 0;

    if (payload_len > 0) {
        memcpy(packet.data() + 20 + 20, payload_ptr, payload_len);
    }

    struct PseudoHdr {
        uint32_t src_addr;
        uint32_t dst_addr;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t tcp_length;
    } pseudo_hdr;

    pseudo_hdr.src_addr   = iph->saddr;
    pseudo_hdr.dst_addr   = iph->daddr;
    pseudo_hdr.zero       = 0;
    pseudo_hdr.proto      = IPPROTO_TCP;
    pseudo_hdr.tcp_length = htons(static_cast<uint16_t>(20 + payload_len));

    size_t ps_len = sizeof(PseudoHdr) + 20 + payload_len;
    std::vector<unsigned char> checksum_buf(ps_len);
    memcpy(checksum_buf.data(), &pseudo_hdr, sizeof(PseudoHdr));
    memcpy(checksum_buf.data() + sizeof(PseudoHdr), new_th, 20 + payload_len);

    uint32_t sum = 0;
    uint16_t* ptr = reinterpret_cast<uint16_t*>(checksum_buf.data());
    size_t words = ps_len / 2;
    for (size_t i = 0; i < words; i++) {
        sum += static_cast<uint32_t>(ntohs(ptr[i]));
        if (sum & 0xFFFF0000) {
            sum = (sum & 0xFFFF) + 1;
        }
    }
    if (ps_len & 1) {
        uint8_t last = checksum_buf[ps_len - 1];
        sum += static_cast<uint32_t>(last) << 8;
        if (sum & 0xFFFF0000) {
            sum = (sum & 0xFFFF) + 1;
        }
    }
    new_th->check = htons(static_cast<uint16_t>(~sum));

    sockaddr_in dst{};
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = new_th->dest;
    inet_pton(AF_INET, client_ip.c_str(), &dst.sin_addr);

    ssize_t sent = ::sendto(
        send_sock_,
        packet.data(),
        packet_len,
        0,
        reinterpret_cast<sockaddr*>(&dst),
        sizeof(dst)
    );
    if (sent < 0) {
        std::perror("[mit_syn_f] forge_and_send_tcp_payload: sendto() failed");
    }
}


std::string TCPSYNCookieProxy::ip_to_string(uint32_t ip_network_order) {
    struct in_addr a;
    a.s_addr = ip_network_order;
    char buf[INET_ADDRSTRLEN];
    if (::inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN) == nullptr) {
        return "<invalid-ip>";
    }
    return std::string(buf);
}

void TCPSYNCookieProxy::update_conn_activity(const std::string& ip, uint16_t port) {
    std::time_t now = std::time(nullptr);
    std::string key = ip + ":" + std::to_string(port);

    std::map<std::string, std::time_t> m;

    std::ifstream ifs(CONN_LOG_PATH);
    std::string line;
    while (std::getline(ifs, line)) {
        std::istringstream iss(line);
        std::string existing_key;
        std::time_t ts;
        if (iss >> existing_key >> ts) {
            m[existing_key] = ts;
        }
    }

    m[key] = now;
    std::string tmp = std::string(CONN_LOG_PATH) + ".tmp";

    std::ofstream ofs(tmp, std::ios::trunc);
    for (auto& kv : m) {
        ofs << kv.first << " " << kv.second << "\n";
    }

    std::rename(tmp.c_str(), CONN_LOG_PATH);
}

void TCPSYNCookieProxy::remove_conn_activity(const std::string& ip, uint16_t port) {
    std::string key = ip + ":" + std::to_string(port);

    std::map<std::string, std::time_t> m;

    std::ifstream ifs(CONN_LOG_PATH);
    std::string line;
    while (std::getline(ifs, line)) {
        std::istringstream iss(line);
        std::string existing_key;
        std::time_t ts;
        if (iss >> existing_key >> ts) {
            m[existing_key] = ts;
        }
    }

    m.erase(key);

    std::string tmp = std::string(CONN_LOG_PATH) + ".tmp";
    {
        std::ofstream ofs(tmp, std::ios::trunc);
        for (auto& kv : m) {
            ofs << kv.first << " " << kv.second << "\n";
        }
    }
    std::rename(tmp.c_str(), CONN_LOG_PATH);
}

void TCPSYNCookieProxy::remove_conn_activity_for_ip(const std::string& ip) {
    std::map<std::string, std::time_t> m;
    {
        std::ifstream ifs(CONN_LOG_PATH);
        std::string line;
        while (std::getline(ifs, line)) {
            std::istringstream iss(line);
            std::string key; std::time_t ts;
            if (iss >> key >> ts) {
                m[key] = ts;
            }
        }
    }
    auto prefix = ip + ":";
    for (auto it = m.begin(); it != m.end();) {
        if (it->first.rfind(prefix, 0) == 0) {
            it = m.erase(it);
        } else {
            ++it;
        }
    }
    std::string tmp = std::string(CONN_LOG_PATH) + ".tmp";
    {
        std::ofstream ofs(tmp, std::ios::trunc);
        for (auto& kv : m) {
            ofs << kv.first << " " << kv.second << "\n";
        }
    }
    std::rename(tmp.c_str(), CONN_LOG_PATH);
}

void TCPSYNCookieProxy::reload_banned_ips() {
    std::set<std::string> new_bans;
    std::ifstream ifs(BANNED_IPS_PATH);
    std::string ip;
    while (std::getline(ifs, ip)) {
        if (!ip.empty()) new_bans.insert(ip);
    }

    for (auto const& ip : new_bans) {
        auto [it, inserted] = banned_ips_.insert(ip);
        if (inserted) {
            remove_conn_activity_for_ip(ip);
        }
    }

    {
        std::lock_guard<std::mutex> lk(ban_mtx_);
        banned_ips_.swap(new_bans);
    }
}

void TCPSYNCookieProxy::ban_reload_loop() {
    while (true) {
        reload_banned_ips();
        for (auto const& ip : banned_ips_) {
            remove_conn_activity_for_ip(ip);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}