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

int main(int argc, char* argv[]) {
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

    while (true) {
        std::string msg = "client " + client_id + " msg " + std::to_string(counter++);

        const int MAX_RETRIES = 3;
        int       retries    = 0;
        bool      got_reply  = false;

        while (retries++ < MAX_RETRIES) {
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
                std::cout << (use_tcp ? "[TCP]" : "[UDP]")
                          << " echo: \"" << reply << "\""
                          << "  (RTT=" << latency_ms << "ms)"
                          << std::endl;
                got_reply = true;
                break;
            }

            if (errno == ECONNREFUSED) {
                std::cout << "Fot ECONNREFUSED, retrying ("
                          << retries << "/" << MAX_RETRIES 
                          << ")..." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }

            std::perror("recv");
            break;
    }

        if (!got_reply) {
            std::cerr << "No reply after " << MAX_RETRIES 
                      << " attempts. Giving up." << std::endl;
            break;
        }

        std::this_thread::sleep_for(std::chrono::seconds(use_tcp ? 4 : 3));
    }


    ::close(sockfd);

    return 0;
}
