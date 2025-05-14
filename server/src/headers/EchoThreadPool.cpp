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

bool EchoThreadPool::enqueue_client(int client_fd) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stop_) return false;
    clients_.push(client_fd);

    cond_.notify_one();
    return true;
}

void EchoThreadPool::worker_loop() {
    while (true) {
        int client_fd;

        std::unique_lock<std::mutex> lock(mutex_);
        cond_.wait(lock, [this] { return stop_ || !clients_.empty(); });

        if (stop_ && clients_.empty()) return;
        client_fd = clients_.front();
        clients_.pop();
        
        char buf[MAX_PACKET];
        while (true) {
            ssize_t len = ::recv(client_fd, buf, sizeof(buf), 0);
            if (len <= 0) break;
            ::send(client_fd, buf, len, 0);
        }
        ::close(client_fd);
    }
}