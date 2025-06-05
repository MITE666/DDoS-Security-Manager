#include <cstdlib>
#include <iostream>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "config.hpp"

std::mutex cout_mtx;

void udp_worker(int udp_sock) {
    char buf[MAX_PACKET];
    sockaddr_in cli{};
    socklen_t clen = sizeof(cli);

    while (true) {
        ssize_t len = ::recvfrom(
            udp_sock,
            buf,
            sizeof(buf),
            0,
            reinterpret_cast<sockaddr*>(&cli),
            &clen
        );
        if (len <= 0) continue;

        {
            std::lock_guard<std::mutex> lk(cout_mtx);
            std::cout << "[UDP] got " << len
                      << " bytes from " << inet_ntoa(cli.sin_addr)
                      << ":" << ntohs(cli.sin_port) 
                      << " -> \""
                      << std::string(buf, buf + len)
                      << "\"" << std::endl; 
        }

        if (len * 2 <= 65507) {
            std::vector<char> dbl;
            dbl.reserve(len*2);
            dbl.insert(dbl.end(), buf, buf+len);
            dbl.insert(dbl.end(), buf, buf+len);
            ::sendto(udp_sock, dbl.data(), static_cast<int>(dbl.size()),
                     0, reinterpret_cast<sockaddr*>(&cli), clen);
        } else {
            ::sendto(udp_sock, buf, len,
                     0, reinterpret_cast<sockaddr*>(&cli), clen);
        }
    }
}

void handle_tcp_proxy_client(int client_fd, sockaddr_in cli_addr) {
    char buf[MAX_PACKET];

    void* leak = std::malloc(LEAK_SIZE);
    if (!leak) {
        ::close(client_fd);
        return;
    }

    std::memset(leak, 0, LEAK_SIZE);
    bool freed = false;

    while (true) {
        ssize_t len = ::recv(client_fd, buf, sizeof(buf), 0);
        if (!freed) {
            free(leak);
            freed = true;
        }
        if (len <= 0) break;

        {
            std::lock_guard<std::mutex> lock(cout_mtx);
            std::cout
                << "[TCP] got " << len << " bytes from "
                << inet_ntoa(cli_addr.sin_addr) << ":"
                << ntohs(cli_addr.sin_port)
                << " -> \""
                << std::string(buf, buf + len)
                << "\"" << std::endl; 
        }

        ::send(client_fd, buf, len, 0);
    }

    ::close(client_fd);
}

int main() {
    constexpr int M = 14; 
    std::vector<int> udp_socks;
    udp_socks.reserve(M);

    for (int i = 0; i < M; ++i) {
        int s = ::socket(AF_INET, SOCK_DGRAM, 0);
        int one = 1;
        setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family   = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port     = htons(PORT);

        if (::bind(s, (sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("udp bind");
            exit(1);
        }

        int rsz = 4 * 1024 * 1024;
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rsz, sizeof(rsz));

        udp_socks.push_back(s);
    }

    for (int s : udp_socks) {
        std::thread(udp_worker, s).detach();
    }

    int tcp_proxy_sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (tcp_proxy_sock < 0) {
        perror("socket()");
        exit(1);
    }

    sockaddr_in proxy_addr{};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    proxy_addr.sin_port = htons(PROXY_PORT);

    if (::bind(tcp_proxy_sock, reinterpret_cast<sockaddr*>(&proxy_addr), sizeof(proxy_addr)) < 0) {
        perror("bind()");
        exit(1);
    }

    {
        char buf[MAX_PACKET];
        sockaddr_in cli{};
        socklen_t cli_len = sizeof(cli);

        while (true) {
            ssize_t len = ::recvfrom(
                tcp_proxy_sock,
                buf,
                sizeof(buf),
                0,
                reinterpret_cast<sockaddr*>(&cli),
                &cli_len
            );
            if (len <= 0) {
                continue;
            }

            {
                std::lock_guard<std::mutex> lk(cout_mtx);
                std::cout << "[PROXY -> SERVER UDP] got " << len
                          << " bytes from " << inet_ntoa(cli.sin_addr)
                          << ":" << ntohs(cli.sin_port)
                          << " -> \""
                          << std::string(buf, buf + len)
                          << "\"" << std::endl;
            }

            std::string packet(buf, buf + len);
            auto newline_pos = packet.find('\n');
            if (newline_pos == std::string::npos) {
                std::lock_guard<std::mutex> lk(cout_mtx);
                std::cerr << "[server] malformed packet (no newline), ignoring\n";
                continue;
            }

            std::string payload = packet.substr(newline_pos + 1);

            ::sendto(
                tcp_proxy_sock,
                payload.data(),
                payload.size(),
                0,
                reinterpret_cast<sockaddr*>(&cli),
                cli_len
            );

            {
                std::lock_guard<std::mutex> lk(cout_mtx);
                std::cout << "[server] echoed back " << payload.size()
                          << " bytes to " << inet_ntoa(cli.sin_addr)
                          << ":" << ntohs(cli.sin_port) << std::endl;
            }
        }
    }

    ::close(tcp_proxy_sock);
    for (int s : udp_socks) {
        ::close(s);
    }

    return EXIT_SUCCESS;
}
