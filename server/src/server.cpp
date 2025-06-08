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

auto handle_udp_forwarder = [](){
    int recv_sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_sock < 0) {
        perror("udp_forwarder socket");
        return;
    }

    sockaddr_in bind_addr{};
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port   = htons(UDP_PROXY_PORT);
    inet_pton(AF_INET, "127.0.0.1", &bind_addr.sin_addr);
    if (::bind(recv_sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)) < 0) {
        perror("udp_forwarder bind");
        ::close(recv_sock);
        return;
    }

    int send_sock = ::socket(AF_INET, SOCK_DGRAM, 0);

    int on = 1;
    setsockopt(send_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    sockaddr_in send_addr{};
    send_addr.sin_family      = AF_INET;
    send_addr.sin_port        = htons(12345);
    send_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (::bind(send_sock, (sockaddr*)&send_addr, sizeof(send_addr)) < 0) {
        perror("bind send_sock");
        exit(1);
    }

    char buf[MAX_PACKET];
    while (true) {
        ssize_t len = ::recvfrom(recv_sock, buf, sizeof(buf), 0, nullptr, nullptr);
        if (len <= 0) continue;

        std::string packet(buf, buf + len);
        auto nl = packet.find('\n');
        if (nl == std::string::npos) {
            std::cerr << "[udp_forwarder] no header newline, dropping" << std::endl;
            continue;
        }

        std::string header = packet.substr(0, nl);
        std::string payload = packet.substr(nl + 1);

        std::string from_prefix = "FROM ";
        if (header.rfind(from_prefix, 0) != 0) {
            std::cerr << "[udp_forwarder] bad header prefix, dropping\n";
            continue;
        }
        std::string ip_and_port = header.substr(from_prefix.size());
        auto colon = ip_and_port.find(':');
        if (colon == std::string::npos) {
            std::cerr << "[udp_forwarder] bad header format, dropping\n";
            continue;
        }
        std::string ip_str   = ip_and_port.substr(0, colon);
        int         port     = std::stoi(ip_and_port.substr(colon + 1));

        sockaddr_in dest{};
        dest.sin_family = AF_INET;
        dest.sin_port   = htons(port);
        inet_pton(AF_INET, ip_str.c_str(), &dest.sin_addr);

        ssize_t sent = ::sendto(
            send_sock,
            payload.data(),
            payload.size(),
            0,
            reinterpret_cast<sockaddr*>(&dest),
            sizeof(dest)
        );
        if (sent < 0) {
            perror("[udp_forwarder] sendto");
        }
    }

    ::close(recv_sock);
    ::close(send_sock);
};

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
    std::thread(handle_udp_forwarder).detach();

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
                std::cerr << "[server] malformed packet (no newline), ignoring" << std::endl;
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

    return EXIT_SUCCESS;
}
