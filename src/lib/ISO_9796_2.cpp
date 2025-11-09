#include "ISO_9796_2.hpp"
#include <openssl/rand.h>
#include <openssl/sha.h>

int iso9796_2::max_msg_size(const rsa::rsa_ctx &ctx)
{
    int k = (ctx.bits + 7) / 8;
    k = k - 2 * SHA256_DIGEST_LENGTH - 2;
    int mx = k - 1 - SHA256_DIGEST_LENGTH - 1 - (2 + 1 + 16);
    return std::min(mx, 0xffff);
}

mpz_class iso9796_2::sign(const rsa::rsa_ctx &ctx,
                          const std::vector<unsigned char> &message)
{
    if (message.size() > iso9796_2::max_msg_size(ctx))
    {
        throw std::runtime_error("Message too long for ISO 9796-2 signing");
    }

    std::vector<unsigned char> salt(16);
    if (RAND_bytes(salt.data(), salt.size()) != 1)
    {
        throw std::runtime_error("Failed to generate random salt");
    }

    std::vector<unsigned char> trailer;
    trailer.resize(2);
    trailer[0] = message.size() & 0xFF;
    trailer[1] = (message.size() >> 8) & 0xFF;

    trailer.push_back(0x34);

    trailer.insert(trailer.end(), salt.begin(), salt.end());

    std::vector<unsigned char> M_prime = message;
    M_prime.insert(M_prime.end(), trailer.begin(), trailer.end());

    std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
    SHA256(M_prime.data(), M_prime.size(), digest.data());

    std::vector<unsigned char> mu;
    mu.push_back(0x6A);
    mu.insert(mu.end(), digest.begin(), digest.end());

    int pad_len =
        rsa::max_msg_size(ctx) - 2 - SHA256_DIGEST_LENGTH - M_prime.size();

    mu.insert(mu.end(), pad_len, 0xBB);
    mu.insert(mu.end(), M_prime.begin(), M_prime.end());
    mu.push_back(0xBC);

    rsa::rsa_ctx ctx_copy = ctx;
    std::swap(ctx_copy.e, ctx_copy.d);

    return rsa::encrypt_bytes(ctx_copy, mu);
}

iso9796_2::status iso9796_2::verify(const rsa::rsa_ctx &ctx,
                                    const mpz_class &signature)
{
    rsa::rsa_ctx ctx_copy = ctx;
    std::swap(ctx_copy.e, ctx_copy.d);
    std::vector<unsigned char> mu = rsa::decrypt_bytes(ctx_copy, signature);

    if (mu.empty() || mu[0] != 0x6A || mu.back() != 0xBC)
    {
        return {false, {}};
    }
    std::vector<unsigned char> digest(mu.begin() + 1,
                                      mu.begin() + 1 + SHA256_DIGEST_LENGTH);
    mu.pop_back();
    std::vector<unsigned char> salt;
    for (int i = 0; i < 16; i++)
    {
        if (mu.empty())
        {
            return {false, {}};
        }
        salt.push_back(mu.back());
        mu.pop_back();
    }
    std::reverse(salt.begin(), salt.end());

    if (mu.empty() || mu.back() != 0x34)
    {
        return {false, {}};
    }
    mu.pop_back();

    int msg_len = 0;
    if (mu.size() < 1 + 2 + SHA256_DIGEST_LENGTH)
    {
        return {false, {}};
    }
    msg_len |= mu.back() << 8;
    mu.pop_back();
    msg_len |= mu.back();
    mu.pop_back();

    if (mu.size() < 1 + SHA256_DIGEST_LENGTH + msg_len)
    {
        return {false, {}};
    }

    std::vector<unsigned char> message(mu.end() - msg_len, mu.end());
    mu.resize(mu.size() - msg_len);

    if (mu.size() < 1 + SHA256_DIGEST_LENGTH)
    {
        return {false, {}};
    }

    std::vector<unsigned char> digest_prime(
        mu.begin() + 1, mu.begin() + 1 + SHA256_DIGEST_LENGTH);
    int index = 1 + SHA256_DIGEST_LENGTH;
    while (index < mu.size())
    {
        if (mu[index] != 0xBB)
        {
            return {false, {}};
        }
        index++;
    }

    std::vector<unsigned char> trailer;
    trailer.resize(2);
    trailer[0] = msg_len & 0xFF;
    trailer[1] = (msg_len >> 8) & 0xFF;

    trailer.push_back(0x34);
    trailer.insert(trailer.end(), salt.begin(), salt.end());

    std::vector<unsigned char> M_prime = message;

    M_prime.insert(M_prime.end(), trailer.begin(), trailer.end());
    std::vector<unsigned char> digest_check(SHA256_DIGEST_LENGTH);
    SHA256(M_prime.data(), M_prime.size(), digest_check.data());

    if (digest != digest_check)
    {
        return {false, {}};
    }

    return {true, message};
}
