#include <iostream>
#include <cstring>
#include <mutex>
#include <thread>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#include "config.hpp"

std::mutex cout_mtx;

void handle_client(int client_fd, sockaddr_in cli_addr) {
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
    int udp_sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    int tcp_sock = ::socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr{};
    addr.sin_family         = AF_INET;
    addr.sin_addr.s_addr    = INADDR_ANY;
    addr.sin_port           = htons(PORT);

    ::bind(udp_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    ::bind(tcp_sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

    ::listen(tcp_sock, 10);

    std::cout << "echo server on UDP and TCP port " << PORT << std::endl;

    fd_set readset;
    int maxfd = std::max(udp_sock, tcp_sock);

    while (true) {
        FD_ZERO(&readset);
        FD_SET(udp_sock, &readset);
        FD_SET(tcp_sock, &readset);

        int err = ::select(maxfd + 1, &readset, nullptr, nullptr, nullptr); 

        if (err < 0) {
            perror("select");
            break;
        } 

        if (FD_ISSET(udp_sock, &readset)) {
            char buf[MAX_PACKET];
            sockaddr_in cli{};
            socklen_t clen = sizeof(cli);
            ssize_t len = ::recvfrom(
                udp_sock, 
                buf, 
                sizeof(buf), 
                0, 
                reinterpret_cast<sockaddr*>(&cli), 
                &clen
            );

            if (len > 0) {
                std::string msg(buf, len);

                std::cout << "[UDP] got " << len << "bytes from "
                          << inet_ntoa(cli.sin_addr) << ":"
                          << ntohs(cli.sin_port)
                          << " -> \"" << msg << "\"" << std::endl;

                ::sendto(
                    udp_sock, 
                    buf, 
                    len, 
                    0, 
                    reinterpret_cast<sockaddr*>(&cli), 
                    clen
                );
            }
        }

        if (FD_ISSET(tcp_sock, &readset)) {
            sockaddr_in cli_addr{};
            socklen_t   cli_len = sizeof(cli_addr);
            int client_fd = ::accept(tcp_sock, reinterpret_cast<sockaddr*>(&cli_addr), &cli_len);
            if (client_fd < 0) continue;

            std::thread(handle_client, client_fd, cli_addr).detach();
        }
    }

    ::close(udp_sock);
    ::close(tcp_sock);

    return EXIT_SUCCESS;
}
