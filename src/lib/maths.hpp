#pragma once

#include <gmpxx.h>

namespace maths
{
mpz_class power(const mpz_class &a, const mpz_class &exp, const mpz_class &MOD);

mpz_class gcd(const mpz_class &a, const mpz_class &b);

mpz_class lcm(const mpz_class &a, const mpz_class &b);

mpz_class mod_inv(const mpz_class &a, const mpz_class &MOD);

mpz_class gen_random(const mpz_class &lower, const mpz_class &upper);

namespace primes
{
bool is_prime(const mpz_class &n, int rounds = 25);

mpz_class generate_prime(int bits);
} // namespace primes
} // namespace maths