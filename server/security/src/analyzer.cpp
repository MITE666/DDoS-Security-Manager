#include <iostream>
#include <chrono>
#include <thread>

int main() {
    while (true) {  
        std::cout << "i am analyzer" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(4));
    }
    return 0;
}