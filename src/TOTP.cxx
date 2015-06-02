#ifdef __APPLE__
    #include <CommonCrypto/CommonHMAC.h>
#else
    #include <openssl/evp.h>
    #include <openssl/hmac.h>
#endif

#include <vector>

#include "TOTP.h"

const int TOTP::DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};


std::vector<unsigned char> TOTP::hexStr2Bytes(std::string &hex)
{
    std::stringstream ss;
    unsigned int buffer;
    unsigned int offset = 0;

    std::vector<unsigned char> bytes;

    while (offset < hex.length())
    {
        ss.clear();
        ss << std::hex << hex.substr(offset, 2);
        ss >> buffer;

        bytes.emplace_back(static_cast<unsigned char>(buffer));
        offset += 2;
    }

    return bytes;
}

#ifdef __APPLE__
void TOTP::hmac_sha(Hash hash, const void *key, size_t key_len, const void *data, size_t data_len, void *mac_out)
{
    CCHmacAlgorithm algorithm;

    switch (hash) {
        default:
        case Hash::HMACSHA1: algorithm = kCCHmacAlgSHA1; break;
        case Hash::HMACSHA256: algorithm = kCCHmacAlgSHA256; break;
        case Hash::HMACSHA512: algorithm = kCCHmacAlgSHA512; break;
    }

    CCHmac(algorithm, key, key_len, data, data_len, mac_out);
}
#else
unsigned char * TOTP::hmac_sha(Hash hash, const void *key, int key_len, const unsigned char *d, int n, unsigned char *md, unsigned int *md_len)
{
    const EVP_MD *evp_md;

    switch(hash)
    {
        default:
        case Hash::HMACSHA1: evp_md = EVP_sha1(); break;
        case Hash::HMACSHA256: evp_md = EVP_sha256(); break;
        case Hash::HMACSHA512: evp_md = EVP_sha512(); break;
    }

    return HMAC(evp_md, key, key_len, d, n, md, md_len);
}
#endif

std::string TOTP::generateTOTP(std::string &key, std::string &time, std::string &returnDigits)
{
    return generateTOTP(key, time, returnDigits, Hash::HMACSHA1);
}

std::string TOTP::generateTOTP256(std::string &key, std::string &time, std::string &returnDigits)
{
    return generateTOTP(key, time, returnDigits, Hash::HMACSHA256);
}

std::string TOTP::generateTOTP512(std::string &key, std::string &time, std::string &returnDigits)
{
    return generateTOTP(key, time, returnDigits, Hash::HMACSHA512);
}

std::string TOTP::generateTOTP(std::string &key, std::string &time, std::string &returnDigits, Hash hash)
{
    unsigned int codeDigits = atoi(returnDigits.c_str());
    std::string result;

	while (time.length() < 16)
    {
        time = "0" + time;
    }

    std::vector<unsigned char> msg = hexStr2Bytes(time);
    std::vector<unsigned char> k = hexStr2Bytes(key);

    unsigned int HASH_LENGTH;
    switch (hash) {
        default:
        case Hash::HMACSHA1: HASH_LENGTH = CC_SHA1_DIGEST_LENGTH; break;
        case Hash::HMACSHA256: HASH_LENGTH = CC_SHA256_DIGEST_LENGTH; break;
        case Hash::HMACSHA512: HASH_LENGTH = CC_SHA512_DIGEST_LENGTH; break;
    }

    unsigned char hmac[HASH_LENGTH];
    unsigned int hmac_length;
#ifdef __APPLE__
    hmac_sha(hash, k.data(), k.size(), msg.data(), msg.size(), hmac);

    hmac_length = HASH_LENGTH;
#else
    hmac_sha(hash, k.data(), k.size(), msg.data(), msg.size(), hmac, &hmac_length);
#endif

    int offset = hmac[hmac_length - 1] & 0xf;
    int binary =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);

    int otp = binary % DIGITS_POWER[codeDigits];
    result = std::to_string(otp);

    while (result.length() < codeDigits)
        result = "0" + result;

    return result;
}
