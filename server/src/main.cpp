#include <iostream>
#include <chrono>
#include <thread>

int main() {
    while (true) {
        std::cout << "i am server" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
    return 0;
}
