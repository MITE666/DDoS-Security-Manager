#include "../headers/mit_udp_f.hpp"
#include "../headers/mit_tcp_cf.hpp"
#include <iostream>
#include <thread>

int main() {
    constexpr std::size_t UDP_TH        = 50;
    constexpr std::size_t UDP_WIN_MS    = 1000;

    constexpr std::size_t CONN_IDLE_TH  = 5;
    constexpr std::size_t CONN_TH       = 20;

    UDPFloodMitigator udp_mit{UDP_TH, UDP_WIN_MS};
    std::thread udp_th([&](){ udp_mit.run(); });  

    TCPConnFloodMitigator tcpc_mit{CONN_IDLE_TH, CONN_TH};
    std::thread conn_th([&](){ tcpc_mit.run(); });

    udp_th.join();
    conn_th.join();

    return 0;
}
