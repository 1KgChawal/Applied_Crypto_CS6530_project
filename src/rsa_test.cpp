#include "lib/rsa.hpp"
#include <iostream>

using namespace std;

int main()
{
    rsa::rsa_ctx ctx;
    rsa::build_secure_ctx(ctx);
    rsa::write_private_key(ctx, "priv.key");
    rsa::write_public_key(ctx, "pub.key");

    rsa::rsa_ctx pub_ctx, priv_ctx;
    rsa::read_public_key(pub_ctx, "pub.key");
    rsa::read_private_key(priv_ctx, "priv.key");

    cout << "---- RSA Public Key -----" << endl;
    cout << "Modulus (n): 0x" << pub_ctx.n.get_str(16) << endl;
    cout << "Public Exponent (e): 0x" << pub_ctx.e.get_str(16) << endl;
    cout << "Key Size (bits): " << pub_ctx.bits << endl;

    cout << endl;

    cout << "---- RSA Private Key -----" << endl;
    cout << "Modulus (n): 0x" << priv_ctx.n.get_str(16) << endl;
    cout << "Private Exponent (d): 0x" << priv_ctx.d.get_str(16) << endl;
    cout << "Key Size (bits): " << priv_ctx.bits << endl;

    cout << endl;

    string plaintext_str = "Hello, RSA!";
    vector<unsigned char> plaintext(plaintext_str.begin(), plaintext_str.end());
    cout << "Original: " << plaintext_str << endl;
    auto ciphertext = rsa::encrypt_bytes(pub_ctx, plaintext);
    cout << "Encrypted: 0x" << ciphertext.get_str(16) << endl;
    auto decrypted = rsa::decrypt_bytes(priv_ctx, ciphertext);
    cout << "Decrypted: " << string(decrypted.begin(), decrypted.end()) << endl;
    cout << "Is Decryption Successful: "
         << (plaintext == decrypted ? "Yes" : "No") << endl;

    auto signature = rsa::sign(priv_ctx, plaintext);

    if (rsa::sign_verify(pub_ctx, plaintext, signature))
    {
        cout << "Signature Verified Successfully!" << endl;
    }
    else
    {
        cout << "Signature Verification Failed!" << endl;
    }

    return 0;
}