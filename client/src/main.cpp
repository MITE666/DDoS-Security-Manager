#include <iostream>
#include <cstdlib>

int main(int argc, char* argv[]) {
    const char* cid = std::getenv("CLIENT_ID");
    if (!cid) {
        cid = "unknown";
    }
    std::cout << "client " << cid << "\n";
    return 0;
}