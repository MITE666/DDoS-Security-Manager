#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <iostream>

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    const char* target = argv[1];
    const char* port = "12345";

    struct addrinfo hints{}, *res;
    hints.ai_family     = AF_INET;
    hints.ai_socktype   = SOCK_STREAM;

    if (getaddrinfo(target, port, &hints, &res) != 0) return 1;


    int n_clients = 1000;
    std::vector<int> conns;
    conns.reserve(n_clients);

    for (int i = 0; i < n_clients; i++) {
        int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (s < 0) { i--; continue; }

        if (connect(s, res->ai_addr, res->ai_addrlen) == 0) {
            std::cout << "Connected " << i << std::endl;
            ::send(s, "X", 1, 0);
            conns.push_back(s);
        } else {
            close(s);
            --i;  
        }
    }

    freeaddrinfo(res);

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(60));
    }

    return 0;
}