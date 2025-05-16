#pragma once

#include "../config.hpp"
#include <thread>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

class EchoThreadPool {

public:
    explicit EchoThreadPool(size_t num_workers);
    ~EchoThreadPool();
    bool enqueue_client(int client_fd, const sockaddr_in &cli_addr);
    
private:
    void worker_loop();
    std::vector<std::thread>                    workers_;
    std::queue<std::pair<int, sockaddr_in>>     clients_;
    std::mutex                                  mutex_;
    std::condition_variable                     cond_;
    bool                                        stop_{false};
};