#ifndef __TOTP_H
#define __TOTP_H

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

class TOTP
{
public:
	enum class Hash {HMACSHA1, HMACSHA256, HMACSHA512};

private:
	static const int DIGITS_POWER[];
#ifdef __APPLE__
    static void hmac_sha(Hash hash, const void *key, size_t key_len, const void *data, size_t data_len, void *mac_out);
#else
	static unsigned char * hmac_sha(Hash hash, const void *key, int key_len, const unsigned char *d, int n, unsigned char *md, unsigned int *md_len);
#endif
	static std::vector<unsigned char> hexStr2Bytes(std::string &hex);

public:
	static std::string generateTOTP(std::string &key, std::string &time, std::string &returnDigits);
	static std::string generateTOTP256(std::string &key, std::string &time, std::string &returnDigits);
	static std::string generateTOTP512(std::string &key, std::string &time, std::string &returnDigits);
	static std::string generateTOTP(std::string &key, std::string &time, std::string &returnDigits, Hash hash);
};

#endif
