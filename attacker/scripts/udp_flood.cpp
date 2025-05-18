#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <netdb.h>
#include <thread>
#include <chrono>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    const char* target  = argv[1];
    const char* port = "12345";

    struct addrinfo hints{}, *res;
    hints.ai_family     = AF_INET;
    hints.ai_socktype   = SOCK_DGRAM;

    if (getaddrinfo(target, port, &hints, &res) != 0) return 1;

    int sock = -1;

    for (auto p = res; p; p = p->ai_next) {
        sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (sock < 0) continue;        

        bool ok = false;
        for (int i = 0; i < 5; ++i) {
            if (::connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
                ok = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!ok) {
            ::close(sock);
            sock = -1;
            continue;    
        }

        break;
    }

    freeaddrinfo(res);

    char buf = 0;

    while (true) {
        ::send(sock, &buf, 1, 0);
    }
    
    ::close(sock);
    return 0;
}