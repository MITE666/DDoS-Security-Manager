#include "../headers/mit_udp_f.hpp"
#include "../headers/mit_tcpc_sr_f.hpp"
#include "../headers/mit_syn_f.hpp"
#include <iostream>
#include <thread>

int main() {
    constexpr std::size_t UDP_TH        = 50;
    constexpr std::size_t UDP_WIN_MS    = 1000;
    constexpr std::size_t MAX_PAYLOAD   = 1500;

    UDPFloodMitigator udp_mit{UDP_TH, UDP_WIN_MS, MAX_PAYLOAD};
    std::thread udp_th([&](){ udp_mit.run(); });  

    constexpr std::size_t CONN_IDLE_TH  = 10;
    constexpr std::size_t CONN_TH       = 20;

    TCPConnFloodMitigator tcpc_mit{CONN_IDLE_TH, CONN_TH};
    std::thread conn_th([&](){ tcpc_mit.run(); });

    const std::string SYN_KEY           = "my_very_secret_key";
    constexpr std::size_t SYN_WIN_S     = 5;
    const int SYN_MAX_DROPPED           = 500;

    TCPSYNCookieProxy syn_mit{SYN_KEY, SYN_WIN_S, SYN_MAX_DROPPED};
    std::thread syn_th([&](){ syn_mit.run(); });

    udp_th.join();
    conn_th.join();
    syn_th.join();

    return 0;
}
