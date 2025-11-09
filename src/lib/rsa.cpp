#include "rsa.hpp"
#include "maths.hpp"
#include <cstdlib>
#include <fstream>
#include <openssl/sha.h>
#include <random>
#include <utility>

void rsa::ctx_init(rsa_ctx &ctx, int bits)
{
    if (bits < 2048)
    {
        throw std::runtime_error("number of bits used must be atleast 2048");
    }

    ctx.bits = bits;

    auto check = [bits](const mpz_class &p, const mpz_class &q)
    {
        int bits_p = mpz_sizeinbase(p.get_mpz_t(), 2);
        int bits_q = mpz_sizeinbase(q.get_mpz_t(), 2);
        if (std::min(bits_p, bits_q) < 1024)
        {
            return false;
        }

        auto gcd = maths::gcd(p - 1, q - 1);
        if (gcd > mpz_class(1) << 64)
        {
            return false;
        }

        mpz_class diff = p - q;
        if (diff < 0)
        {
            diff = -diff;
        }
        int bits_diff = mpz_sizeinbase(diff.get_mpz_t(), 2);
        if (bits_diff < bits / 2 - 100)
        {
            return false;
        }

        mpz_class phi = (p - 1) * (q - 1);
        if (maths::gcd(phi, RSA_E) != 1)
        {
            return false;
        }

        return true;
    };

    do
    {
        ctx.p = maths::primes::generate_prime(bits / 2);
        do
        {
            ctx.q = maths::primes::generate_prime(bits / 2);
        } while (ctx.p == ctx.q);
    } while (!check(ctx.p, ctx.q));

    ctx.n = ctx.p * ctx.q;
}

bool rsa::ctx_gen_exponent(rsa_ctx &ctx)
{
    ctx.e = RSA_E;

    mpz_class phi = (ctx.p - 1) * (ctx.q - 1);
    ctx.d = maths::mod_inv(ctx.e, phi);

    if (ctx.d < (mpz_class(1) << ctx.bits / 4))
    {
        return false;
    }
    if (ctx.d > maths::lcm(ctx.p - 1, ctx.q - 1))
    {
        return false;
    }
    return true;
}

void rsa::build_secure_ctx(rsa_ctx &ctx, int bits)
{
    do
    {
        ctx_init(ctx, bits);
    } while (!ctx_gen_exponent(ctx));
}

mpz_class rsa::apply_exponent(const mpz_class &num, const mpz_class &exp,
                              const mpz_class &mod)
{
    return maths::power(num, exp, mod);
}

mpz_class rsa::encrypt(const rsa_ctx &ctx, const mpz_class &plaintext)
{
    return apply_exponent(plaintext, ctx.e, ctx.n);
}

mpz_class rsa::decrypt(const rsa_ctx &ctx, const mpz_class &ciphertext)
{
    return apply_exponent(ciphertext, ctx.d, ctx.n);
}

mpz_class rsa::bytes_to_number(const std::vector<unsigned char> &msg)
{
    mpz_class num;
    for (unsigned char c : msg)
    {
        num = (num << 8) | c;
    }
    return num;
}

std::vector<unsigned char> rsa::number_to_bytes(const rsa_ctx &ctx,
                                                const mpz_class &num)
{
    mpz_class temp = num;
    std::vector<unsigned char> msg;
    while (temp > 0)
    {
        mpz_class rem = temp & 0xff;
        unsigned char c = static_cast<unsigned char>(rem.get_ui());
        msg.push_back(c);
        temp >>= 8;
    }
    if (msg.size() * 8 > ctx.bits)
    {
        throw std::runtime_error("Message size exceeds modulus size");
    }
    msg.resize((ctx.bits + 7) / 8, 0);
    std::reverse(msg.begin(), msg.end());
    return msg;
}

std::vector<unsigned char> rsa::MGF1(const std::vector<unsigned char> &seed,
                                     int maskLen)
{
    const int hLen = SHA256_DIGEST_LENGTH;
    std::vector<unsigned char> mask(maskLen);
    int counter = 0;
    for (int i = 0; i < (maskLen + hLen - 1) / hLen; ++i)
    {
        std::vector<unsigned char> C(4);
        C[0] = (counter >> 24) & 0xff;
        C[1] = (counter >> 16) & 0xff;
        C[2] = (counter >> 8) & 0xff;
        C[3] = counter & 0xff;

        std::vector<unsigned char> data(seed);
        data.insert(data.end(), C.begin(), C.end());

        unsigned char hash[hLen];
        SHA256(data.data(), data.size(), hash);

        for (int j = 0; j < hLen && (i * hLen + j) < maskLen; ++j)
        {
            mask[i * hLen + j] = hash[j];
        }
        counter++;
    }
    return mask;
}

int rsa::max_msg_size(const rsa_ctx &ctx)
{
    const int hLen = SHA256_DIGEST_LENGTH;
    int k = (ctx.bits + 7) / 8;
    return k - 2 * hLen - 2;
}

std::vector<unsigned char>
rsa::OAEP_padding(const std::vector<unsigned char> &msg, int k)
{
    const int hLen = SHA256_DIGEST_LENGTH;
    if (k < 2 * hLen + 2)
    {
        throw std::runtime_error("Modulus too short for OAEP padding");
    }

    if (msg.size() > rsa::max_msg_size(rsa::rsa_ctx{.bits = k * 8}))
    {
        throw std::runtime_error("Message too long for OAEP padding");
    }

    std::vector<unsigned char> lHash(hLen);
    SHA256(nullptr, 0, lHash.data());

    std::vector<unsigned char> PS(k - msg.size() - 2 * hLen - 2, 0x00);

    std::vector<unsigned char> DB;
    DB.insert(DB.end(), lHash.begin(), lHash.end());
    DB.insert(DB.end(), PS.begin(), PS.end());
    DB.push_back(0x01);
    DB.insert(DB.end(), msg.begin(), msg.end());

    std::vector<unsigned char> seed(hLen);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < hLen; ++i)
    {
        seed[i] = static_cast<unsigned char>(dis(gen));
    }

    std::vector<unsigned char> dbMask = MGF1(seed, k - hLen - 1);
    std::vector<unsigned char> maskedDB(DB.size());
    for (size_t i = 0; i < DB.size(); ++i)
    {
        maskedDB[i] = DB[i] ^ dbMask[i];
    }

    std::vector<unsigned char> seedMask = MGF1(maskedDB, hLen);
    std::vector<unsigned char> maskedSeed(hLen);
    for (int i = 0; i < hLen; ++i)
    {
        maskedSeed[i] = seed[i] ^ seedMask[i];
    }

    std::vector<unsigned char> EM;
    EM.push_back(0x00);
    EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
    EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());

    return EM;
}

std::vector<unsigned char>
rsa::OAEP_unpadding(const std::vector<unsigned char> &EM, int k)
{
    const int hLen = SHA256_DIGEST_LENGTH;

    if (EM.size() != k || k < 2 * hLen + 2)
    {
        throw std::runtime_error(
            "Decryption error: Invalid padded message length");
    }

    if (EM[0] != 0x00)
    {
        throw std::runtime_error("Decryption error: Invalid padding format");
    }

    std::vector<unsigned char> maskedSeed(EM.begin() + 1,
                                          EM.begin() + 1 + hLen);
    std::vector<unsigned char> maskedDB(EM.begin() + 1 + hLen, EM.end());

    std::vector<unsigned char> seedMask = MGF1(maskedDB, hLen);
    std::vector<unsigned char> seed(hLen);
    for (int i = 0; i < hLen; ++i)
    {
        seed[i] = maskedSeed[i] ^ seedMask[i];
    }

    std::vector<unsigned char> dbMask = MGF1(seed, k - hLen - 1);
    std::vector<unsigned char> DB(maskedDB.size());
    for (size_t i = 0; i < maskedDB.size(); ++i)
    {
        DB[i] = maskedDB[i] ^ dbMask[i];
    }

    std::vector<unsigned char> lHash(hLen);
    SHA256(nullptr, 0, lHash.data());

    std::vector<unsigned char> lHashPrime(DB.begin(), DB.begin() + hLen);
    if (lHash != lHashPrime)
    {
        throw std::runtime_error("Decryption error: Hash verification failed");
    }

    size_t separatorIndex = hLen;
    bool foundSeparator = false;

    for (size_t i = hLen; i < DB.size(); ++i)
    {
        if (DB[i] == 0x01)
        {
            separatorIndex = i;
            foundSeparator = true;
            break;
        }
        else if (DB[i] != 0x00)
        {
            throw std::runtime_error(
                "Decryption error: Invalid padding structure");
        }
    }

    if (!foundSeparator)
    {
        throw std::runtime_error("Decryption error: No 0x01 separator found");
    }

    std::vector<unsigned char> msg(DB.begin() + separatorIndex + 1, DB.end());

    return msg;
}

mpz_class rsa::encrypt_bytes(const rsa_ctx &ctx,
                             const std::vector<unsigned char> &plaintext)
{
    auto padded_plaintext = OAEP_padding(plaintext, (ctx.bits + 7) / 8);
    mpz_class num = bytes_to_number(padded_plaintext);
    mpz_class ciphertext = encrypt(ctx, num);
    return ciphertext;
}

std::vector<unsigned char> rsa::decrypt_bytes(const rsa_ctx &ctx,
                                              const mpz_class &ciphertext)
{
    mpz_class num = ciphertext;
    mpz_class plaintext = decrypt(ctx, num);
    auto padded_plaintext = number_to_bytes(ctx, plaintext);
    return OAEP_unpadding(padded_plaintext, (ctx.bits + 7) / 8);
}

mpz_class rsa::sign(const rsa_ctx &ctx,
                    const std::vector<unsigned char> &message)
{
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(message.data(), message.size(), hash.data());
    rsa_ctx ctx_copy = ctx;
    std::swap(ctx_copy.e, ctx_copy.d);
    return encrypt_bytes(ctx_copy, hash);
}

bool rsa::sign_verify(const rsa_ctx &ctx,
                      const std::vector<unsigned char> &message,
                      const mpz_class &signature)
{
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(message.data(), message.size(), hash.data());
    rsa_ctx ctx_copy = ctx;
    std::swap(ctx_copy.e, ctx_copy.d);
    std::vector<unsigned char> hash_ = decrypt_bytes(ctx_copy, signature);
    return hash == hash_;
}

void rsa::write_public_key(const rsa_ctx &ctx, const std::string &filename)
{
    std::ofstream out(filename, std::ios::binary);
    if (!out)
    {
        throw std::runtime_error("Failed to open file for writing");
    }

    out << ctx.n << std::endl;
    out << ctx.e << std::endl;
    out << ctx.bits << std::endl;

    out.close();
}

void rsa::read_public_key(rsa_ctx &ctx, const std::string &filename)
{
    std::ifstream in(filename, std::ios::binary);
    if (!in)
    {
        throw std::runtime_error("Failed to open file for reading");
    }

    in >> ctx.n;
    in >> ctx.e;
    in >> ctx.bits;

    in.close();
}

void rsa::write_private_key(const rsa_ctx &ctx, const std::string &filename)
{
    std::ofstream out(filename, std::ios::binary);
    if (!out)
    {
        throw std::runtime_error("Failed to open file for writing");
    }

    out << ctx.n << std::endl;
    out << ctx.d << std::endl;
    out << ctx.bits << std::endl;

    out.close();
}

void rsa::read_private_key(rsa_ctx &ctx, const std::string &filename)
{
    std::ifstream in(filename, std::ios::binary);
    if (!in)
    {
        throw std::runtime_error("Failed to open file for reading");
    }

    in >> ctx.n;
    in >> ctx.d;
    in >> ctx.bits;

    in.close();
}