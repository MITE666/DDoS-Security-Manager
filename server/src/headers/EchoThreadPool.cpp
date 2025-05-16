#include "EchoThreadPool.hpp"

EchoThreadPool::EchoThreadPool(size_t num_workers) {
    for (size_t i = 0; i < num_workers; i++) {
        workers_.emplace_back([this] { worker_loop(); });
    }
}

EchoThreadPool::~EchoThreadPool() {
    std::lock_guard<std::mutex> lock(mutex_);
    stop_ = true;

    cond_.notify_all();
    for (auto &t : workers_) t.join();
}

bool EchoThreadPool::enqueue_client(int client_fd, const sockaddr_in &cli_addr) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stop_) return false;
    clients_.emplace(client_fd, cli_addr);

    cond_.notify_one();
    return true;
}

void EchoThreadPool::worker_loop() {
    while (true) {
        std::unique_lock<std::mutex> lock(mutex_);
        cond_.wait(lock, [this] { return stop_ || !clients_.empty(); });
        if (stop_ && clients_.empty()) return;

        auto [client_fd, cli_addr] = clients_.front();

        clients_.pop();
        lock.unlock();

        char buf[MAX_PACKET];
        while (true) {
            ssize_t len = ::recv(client_fd, buf, sizeof(buf), 0);
            if (len <= 0) break;

            std::string msg(buf, len);

            std::cout
              << "[TCP] got " << len << "bytes from "
              << inet_ntoa(cli_addr.sin_addr) << ":"
              << ntohs(cli_addr.sin_port)
              << " -> \"" << msg << "\"" << std::endl;
            
            ::send(client_fd, buf, len, 0);
        }
        ::close(client_fd);
    }
}