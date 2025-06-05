#include <iostream>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <chrono>
#include <vector>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static constexpr int PORT = 12345;
static constexpr int MAX_PACKET = 65535;

using Clock = std::chrono::high_resolution_clock;
using ms_t  = std::chrono::duration<double, std::milli>;
auto t0 = Clock::now();

char ipstr[INET_ADDRSTRLEN];

int main(int argc, char* argv[]) {
    std::this_thread::sleep_for(std::chrono::seconds(15));

    const char* cid_env     = std::getenv("CLIENT_ID");
    std::string client_id   = cid_env ? cid_env : "unknown";

    const char* proto_env = std::getenv("PROTOCOL");
    bool use_tcp = proto_env && std::strcmp(proto_env, "tcp") == 0;

    std::cout << "Starting client " << client_id
              << " over " << (use_tcp ? "TCP" : "UDP") << std::endl;

    const char* server_host = std::getenv("SERVER_HOST");
    if (!server_host) server_host = "server";

    struct addrinfo hints{}, *res;
    hints.ai_family     = AF_INET;    
    hints.ai_socktype   = use_tcp ? SOCK_STREAM : SOCK_DGRAM;

    int err = getaddrinfo(
        server_host, 
        std::to_string(PORT).c_str(), 
        &hints, 
        &res
    ); 
    
    if (err != 0) {
        std::perror("getaddrinfo");
        return EXIT_FAILURE;
    }

    int sockfd = -1;

    for (auto p = res; p; p = p->ai_next) {
        void* addr_ptr = nullptr;
        if (p->ai_family == AF_INET) {  
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            addr_ptr = &ipv4->sin_addr;
        } else {
            continue; 
        }

        inet_ntop(p->ai_family, addr_ptr, ipstr, sizeof(ipstr));
        std::cout << "Trying " << ipstr << std::endl;

        sockfd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (sockfd < 0) continue;        

        bool ok = false;
        for (int i = 0; i < 5; ++i) {
            if (::connect(sockfd, p->ai_addr, p->ai_addrlen) == 0) {
                ok = true;
                break;
            }
            std::perror("connect");
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!ok) {
            ::close(sockfd);
            sockfd = -1;
            continue;    
        }

        break;
    }

    freeaddrinfo(res);

    if (sockfd < 0) {
        std::cerr << "Failed to create/connect socket" << std::endl;
        return EXIT_FAILURE;
    }

    std::vector<char> buf(MAX_PACKET);
    int counter = 0;
    bool created = false;

    while (true) {
        std::string msg = "client " + client_id + " msg " + std::to_string(counter++);

        if (use_tcp) {
            auto t0 = Clock::now();

            if (::send(sockfd, msg.data(), msg.size(), 0) < 0) {
                std::perror("send");
                break;  
            }

            ssize_t recvd = ::recv(sockfd, buf.data(), buf.size(), 0);

            auto t1 = Clock::now();

            if (recvd > 0) {
                double latency_ms = ms_t(t1 - t0).count();

                std::string reply(buf.data(), recvd);
                std::cout << "[TCP]"
                        << " echo: \"" << reply << "\""
                        << "  (RTT=" << latency_ms << "ms)"
                        << std::endl;
            }
        } else {
            t0 = Clock::now();

            if (::send(sockfd, msg.data(), msg.size(), 0) < 0) {
                std::perror("send");
                break;  
            }
        }
        if (!use_tcp && !created) {
            created = true;
            std::thread([sockfd]() {
                std::vector<char> buf(MAX_PACKET);
                while (true) {
                    ssize_t recvd = ::recv(sockfd, buf.data(), buf.size(), 0);
                    
                    auto t1 = Clock::now();
                    
                    if (recvd > 0) {
                        std::string reply(buf.data(), recvd);
                        if (reply.find('c') != std::string::npos) {
                            double latency_ms = ms_t(t1 - t0).count();

                            std::cout << "[UDP]"
                            << " echo: \"" << reply << "\""
                            << "  (RTT=" << latency_ms << "ms)"
                            << std::endl;
                        } else {
                            std::cout << "[UDP async] echo: \"" << reply << "\"" << std::endl;
                        }
                    }
                }
                }).detach();
        }

        std::this_thread::sleep_for(std::chrono::seconds(use_tcp ? 4 : 3));
    }


    ::close(sockfd);

    return 0;
}
