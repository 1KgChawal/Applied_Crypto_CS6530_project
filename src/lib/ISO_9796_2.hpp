#pragma once

#include "rsa.hpp"
#include <gmpxx.h>
#include <vector>

namespace iso9796_2
{
struct status
{
    bool valid;
    std::vector<unsigned char> message;
};

int max_msg_size(const rsa::rsa_ctx &ctx);

mpz_class sign(const rsa::rsa_ctx &ctx,
               const std::vector<unsigned char> &message);

status verify(const rsa::rsa_ctx &ctx, const mpz_class &signature);
} // namespace iso9796_2