#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <array>
#include <ctime>

#include "TOTP.h"

std::string toHexString(long T);
std::string toHexString(std::string &base32);

int main(int argc, char **argv)
{
    std::string seed = "3132333435363738393031323334353637383930";
    std::string seed32 = "3132333435363738393031323334353637383930313233343536373839303132";
    std::string seed64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";

    std::string steps = "0";
    std::string return_digits = "8";

    long T0 = 0;
    long X = 30;
    std::array<long, 6> test_time = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};

    std::cout << "+--------------+-----------------------+------------------+----------+--------+\n";
    std::cout << "|   Time (sec) |   Time (UTC format)   | Value of T (Hex) |   TOTP   |  Mode  |\n";
    std::cout << "+--------------+-----------------------+------------------+----------+--------+\n";

    for (auto curr : test_time)
    {
        std::time_t rawtime(curr);

        long T = (curr - T0) / X;
        steps = toHexString(T);
        while (steps.length() < 16) steps = "0" + steps;

        (curr == 59L) ? std::cout << "|      " << curr << "    " : std::cout << "| " << std::setw(11) << curr << std::setw(1);
        std::cout << "  |  " << std::put_time(std::gmtime(&rawtime), "%F %X") << "  | " << steps << " | " << TOTP::generateTOTP(seed, steps, return_digits, TOTP::Hash::HMACSHA1) << " |  SHA1  |\n";

        (curr == 59L) ? std::cout << "|      " << curr << "    " : std::cout << "| " << std::setw(11) << curr << std::setw(1);
        std::cout << "  |  " << std::put_time(std::gmtime(&rawtime), "%F %X") << "  | " << steps << " | " << TOTP::generateTOTP(seed32, steps, return_digits, TOTP::Hash::HMACSHA256) << " | SHA256 |\n";

        (curr == 59L) ? std::cout << "|      " << curr << "    " : std::cout << "| " << std::setw(11) << curr << std::setw(1);
        std::cout << "  |  " << std::put_time(std::gmtime(&rawtime), "%F %X") << "  | " << steps << " | " << TOTP::generateTOTP(seed64, steps, return_digits, TOTP::Hash::HMACSHA512) << " | SHA512 |\n";
    }

    std::cout << "+--------------+-----------------------+------------------+----------+--------+\n";

    return 0;
}

std::string toHexString(long T)
{
    std::string hex;
    std::ostringstream oss;

    oss << std::hex << T;
    hex = oss.str();
    std::transform(hex.begin(), hex.end(), hex.begin(), ::toupper);

    return hex;
}
