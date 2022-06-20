#include <iostream>
#include "mx3.h"

int main() {
    std::cout << std::hex << mx3::mix(123456789) << std::endl;

    uint8_t b[] = "abcdefghijklmnopqrstuvwxyz";

    for (size_t len = 0; len <= 26; len++) {
        std::cout << len << "\t" << std::hex << mx3::hash(b, len, 123456789) << std::endl;
    }

    std::cout << "Hash 2" << std::endl;

    uint8_t b2[] = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
    std::cout << mx3::hash(b2, 89, 123456789) << std::endl;

    std::cout << "Rand 1" << std::endl;

    mx3::random r(1);

    std::cout << std::hex << r() << std::endl;
    std::cout << std::hex << r() << std::endl;
    std::cout << std::hex << r() << std::endl;

    return 0;
}
