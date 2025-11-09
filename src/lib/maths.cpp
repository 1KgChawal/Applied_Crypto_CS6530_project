#include "maths.hpp"
#include <random>

mpz_class maths::power(const mpz_class &a, const mpz_class &exp,
                       const mpz_class &MOD)
{
    mpz_class result;
    mpz_powm(
        result.get_mpz_t(), a.get_mpz_t(), exp.get_mpz_t(), MOD.get_mpz_t());
    return result;
}

mpz_class maths::gcd(const mpz_class &a, const mpz_class &b)
{
    mpz_class result;
    mpz_gcd(result.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
    return result;
}

mpz_class maths::lcm(const mpz_class &a, const mpz_class &b)
{
    return (a * b) / gcd(a, b);
}

mpz_class maths::mod_inv(const mpz_class &a, const mpz_class &MOD)
{
    mpz_class result;
    if (mpz_invert(result.get_mpz_t(), a.get_mpz_t(), MOD.get_mpz_t()) != 1)
    {
        throw std::runtime_error("Inverse do not exist");
    }
    return result;
}

mpz_class maths::gen_random(const mpz_class &lower, const mpz_class &upper)
{
    static std::random_device rd;
    static std::mt19937_64 eng(rd());
    mpz_class range = upper - lower + 1;

    mpz_class temp = range;
    size_t bits = 0;
    while (temp > 0)
    {
        bits++;
        temp >>= 1;
    }

    unsigned int words = (bits + 63) / 64;

    mpz_class random_number;
    random_number = 0;
    for (unsigned int i = 0; i < words; ++i)
    {
        uint64_t rand_word = eng();
        random_number = (random_number << 64) | rand_word;
    }
    random_number = (random_number % range) + lower;

    return random_number;
}

bool maths::primes::is_prime(const mpz_class &n, int rounds)
{
    if (n < 2)
    {
        return false;
    }
    if (n % 2 == 0)
    {
        return n == 2;
    }
    mpz_class d = n - 1;
    int r = 0;
    while (d % 2 == 0)
    {
        d /= 2;
        r++;
    }

    for (int i = 0; i < rounds; i++)
    {
        mpz_class a = gen_random(2, n - 2);
        mpz_class x = power(a, d, n);
        for (int j = 0; j < r; j++)
        {
            mpz_class y = power(x, 2, n);
            if (y == 1 && x != 1 && x != n - 1)
            {
                return false;
            }
            x = std::move(y);
        }
        if (x != 1)
        {
            return false;
        }
    }
    return true;
}

mpz_class maths::primes::generate_prime(int bits)
{
    mpz_class lower = mpz_class(1) << (bits - 1);
    mpz_class upper = (mpz_class(1) << bits) - 1;

    mpz_class prime;
    do
    {
        prime = gen_random(lower, upper);
        prime |= 1;
        while (prime <= upper && !is_prime(prime))
        {
            prime += 2;
        }
    } while (prime > upper);

    return prime;
}