#pragma once

#include <gmpxx.h>
#include <vector>

namespace rsa
{
constexpr int RSA_E = 65537;

struct rsa_ctx
{
    mpz_class p;
    mpz_class q;
    mpz_class n;
    mpz_class e;
    mpz_class d;
    int bits;
};

void ctx_init(rsa_ctx &ctx, int bits = 2048);

bool ctx_gen_exponent(rsa_ctx &ctx);

void build_secure_ctx(rsa_ctx &ctx, int bits = 2048);

mpz_class apply_exponent(const mpz_class &num, const mpz_class &exp,
                         const mpz_class &mod);

mpz_class encrypt(const rsa_ctx &ctx, const mpz_class &plaintext);

mpz_class decrypt(const rsa_ctx &ctx, const mpz_class &ciphertext);

mpz_class bytes_to_number(const std::vector<unsigned char> &msg);

std::vector<unsigned char> number_to_bytes(const rsa_ctx &ctx,
                                           const mpz_class &num);

std::vector<unsigned char> MGF1(const std::vector<unsigned char> &seed,
                                int maskLen);

int max_msg_size(const rsa_ctx &ctx);

std::vector<unsigned char> OAEP_padding(const std::vector<unsigned char> &msg,
                                        int k);

std::vector<unsigned char> OAEP_unpadding(const std::vector<unsigned char> &EM,
                                          int k);

mpz_class encrypt_bytes(const rsa_ctx &ctx,
                        const std::vector<unsigned char> &plaintext);

std::vector<unsigned char> decrypt_bytes(const rsa_ctx &ctx,
                                         const mpz_class &ciphertext);

mpz_class sign(const rsa_ctx &ctx, const std::vector<unsigned char> &message);

bool sign_verify(const rsa_ctx &ctx, const std::vector<unsigned char> &message,
                 const mpz_class &signature);

void write_public_key(const rsa_ctx &ctx, const std::string &filename);

void read_public_key(rsa_ctx &ctx, const std::string &filename);

void write_private_key(const rsa_ctx &ctx, const std::string &filename);

void read_private_key(rsa_ctx &ctx, const std::string &filename);
} // namespace rsa