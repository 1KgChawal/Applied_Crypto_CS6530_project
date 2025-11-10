#include "lib/rsa.hpp"
#include <iostream>
#include <chrono>
#include <cassert>
#include <iomanip>

using namespace std;

template <typename Func>
auto timed(Func f, const string &label) {
    auto start = chrono::high_resolution_clock::now();
    auto result = f();
    auto end = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = end - start;
    cout << "[Timing] " << label << ": " << diff.count() << " s" << endl;
    return result;
}

void basic_encryption_test(const rsa::rsa_ctx &pub_ctx, const rsa::rsa_ctx &priv_ctx) {
    cout << "\n=== Basic Encryption/Decryption Test ===" << endl;

    string plaintext_str = "Hello, RSA!";
    vector<unsigned char> plaintext(plaintext_str.begin(), plaintext_str.end());

    auto ciphertext = rsa::encrypt_bytes(pub_ctx, plaintext);
    auto decrypted = rsa::decrypt_bytes(priv_ctx, ciphertext);

    cout << "Plaintext: " << plaintext_str << endl;
    cout << "Ciphertext (hex): " << ciphertext.get_str(16) << endl;
    cout << "Decrypted: " << string(decrypted.begin(), decrypted.end()) << endl;

    assert(plaintext == decrypted);
    cout << "[PASS] Decryption successful." << endl;
}

void signature_test(const rsa::rsa_ctx &pub_ctx, const rsa::rsa_ctx &priv_ctx) {
    cout << "\n=== Signature Test ===" << endl;

    string message = "This is a test message for RSA signature.";
    vector<unsigned char> msg(message.begin(), message.end());

    auto signature = rsa::sign(priv_ctx, msg);
    bool verified = rsa::sign_verify(pub_ctx, msg, signature);

    cout << "Message: " << message << endl;
    cout << "Signature (hex): " << signature.get_str(16) << endl;
    cout << "Verification result: " << (verified ? "SUCCESS" : "FAIL") << endl;

    assert(verified);
    cout << "[PASS] Signature verified successfully." << endl;
}

void edge_case_tests(const rsa::rsa_ctx &pub_ctx, const rsa::rsa_ctx &priv_ctx) {
    cout << "\n=== Edge Case Tests ===" << endl;

    vector<unsigned char> empty_msg;
    auto sig_empty = rsa::sign(priv_ctx, empty_msg);
    bool verify_empty = rsa::sign_verify(pub_ctx, empty_msg, sig_empty);
    assert(verify_empty);
    cout << "[PASS] Empty message signature verification successful." << endl;

    vector<unsigned char> binary_data = {0x00, 0xFF, 0x10, 0x23, 0xAB, 0xCD};
    auto encrypted = rsa::encrypt_bytes(pub_ctx, binary_data);
    auto decrypted = rsa::decrypt_bytes(priv_ctx, encrypted);
    assert(binary_data == decrypted);
    cout << "[PASS] Binary data encryption/decryption successful." << endl;
}

void performance_test(int bits) {
    cout << "\n=== Performance Test (" << bits << " bits) ===" << endl;

    rsa::rsa_ctx ctx;
    timed([&]() { rsa::build_secure_ctx(ctx, bits); return 0; }, "Key generation");

    string msg = "Performance test message";
    vector<unsigned char> data(msg.begin(), msg.end());

    auto ciphertext = timed([&]() { return rsa::encrypt_bytes(ctx, data); }, "Encryption");
    timed([&]() { return rsa::decrypt_bytes(ctx, ciphertext); }, "Decryption");

    auto signature = timed([&]() { return rsa::sign(ctx, data); }, "Signing");
    timed([&]() { return rsa::sign_verify(ctx, data, signature); }, "Verification");
}

int main() {
    cout << "===== RSA TEST SUITE =====" << endl;

    rsa::rsa_ctx ctx;
    rsa::build_secure_ctx(ctx);
    rsa::write_private_key(ctx, "priv.key");
    rsa::write_public_key(ctx, "pub.key");

    rsa::rsa_ctx pub_ctx, priv_ctx;
    rsa::read_public_key(pub_ctx, "pub.key");
    rsa::read_private_key(priv_ctx, "priv.key");

    cout << "\n---- RSA Key Info ----" << endl;
    cout << "Modulus (n): 0x" << pub_ctx.n.get_str(16).substr(0, 32) << "..." << endl;
    cout << "Public Exponent (e): 0x" << pub_ctx.e.get_str(16) << endl;
    cout << "Key Size (bits): " << pub_ctx.bits << endl;

    basic_encryption_test(pub_ctx, priv_ctx);
    signature_test(pub_ctx, priv_ctx);
    edge_case_tests(pub_ctx, priv_ctx);

    performance_test(2048);
    performance_test(4096);

    cout << "\n===== ALL TESTS PASSED SUCCESSFULLY =====" << endl;
    return 0;
}
