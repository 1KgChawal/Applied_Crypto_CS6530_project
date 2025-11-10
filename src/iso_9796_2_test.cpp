#include "lib/ISO_9796_2.hpp"
#include <iostream>
#include <vector>
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

void basic_sign_verify_test(const rsa::rsa_ctx &pub_ctx, const rsa::rsa_ctx &priv_ctx) {
    cout << "\n=== Basic ISO 9796-2 Sign/Verify Test ===" << endl;

    string msg = "This is a test message for ISO 9796-2 signing.";
    vector<unsigned char> message(msg.begin(), msg.end());

    auto signature = iso9796_2::sign(priv_ctx, message);
    cout << "Message: " << msg << endl;
    cout << "Signature (hex): " << signature.get_str(16) << endl;

    auto result = iso9796_2::verify(pub_ctx, signature);
    assert(result.valid);
    string recovered(result.message.begin(), result.message.end());
    cout << "Recovered Message: " << recovered << endl;

    assert(message == result.message);
    cout << "[PASS] Message successfully recovered and verified." << endl;
}

void tamper_detection_test(const rsa::rsa_ctx &pub_ctx, const rsa::rsa_ctx &priv_ctx) {
    cout << "\n=== Tamper Detection Test ===" << endl;

    string msg = "Tamper test message.";
    vector<unsigned char> message(msg.begin(), msg.end());
    auto signature = iso9796_2::sign(priv_ctx, message);

    auto tampered = signature;
    string sig_str = tampered.get_str(16);
    mpz_class tampered_val(sig_str, 16);
    tampered_val ^= 0x01;
    tampered = tampered_val;

    iso9796_2::status result;
    try
    {
        result = iso9796_2::verify(pub_ctx, tampered);
    }
    catch(...)
    {
        result = iso9796_2::status{false, {}};
    }
    cout << "Verification status after tampering: "
            << (result.valid ? "VALID (unexpected)" : "INVALID (expected)") << endl;
    assert(!result.valid);
    cout << "[PASS] Tampering correctly detected." << endl;
}

void edge_case_tests(const rsa::rsa_ctx &pub_ctx, const rsa::rsa_ctx &priv_ctx) {
    cout << "\n=== Edge Case Tests ===" << endl;

    vector<unsigned char> empty;
    auto sig_empty = iso9796_2::sign(priv_ctx, empty);
    auto res_empty = iso9796_2::verify(pub_ctx, sig_empty);
    assert(res_empty.valid && res_empty.message.empty());
    cout << "[PASS] Empty message signing and verification successful." << endl;

    vector<unsigned char> binary = {0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x55};
    auto sig_bin = iso9796_2::sign(priv_ctx, binary);
    auto res_bin = iso9796_2::verify(pub_ctx, sig_bin);
    assert(res_bin.valid && binary == res_bin.message);
    cout << "[PASS] Binary data signing and recovery successful." << endl;
}

void performance_test(int bits) {
    cout << "\n=== Performance Test (" << bits << "-bit key) ===" << endl;
    rsa::rsa_ctx ctx;
    timed([&]() { rsa::build_secure_ctx(ctx, bits); return 0; }, "Key generation");

    string msg = "Performance test message for ISO 9796-2.";
    vector<unsigned char> data(msg.begin(), msg.end());

    auto sig = timed([&]() { return iso9796_2::sign(ctx, data); }, "Signing");
    timed([&]() { return iso9796_2::verify(ctx, sig); }, "Verification");
}

int main() {
    cout << "===== ISO 9796-2 TEST SUITE =====" << endl;

    rsa::rsa_ctx ctx;
    rsa::build_secure_ctx(ctx);
    rsa::write_private_key(ctx, "priv.key");
    rsa::write_public_key(ctx, "pub.key");

    rsa::rsa_ctx pub_ctx, priv_ctx;
    rsa::read_public_key(pub_ctx, "pub.key");
    rsa::read_private_key(priv_ctx, "priv.key");

    cout << "\n---- RSA Key Info ----" << endl;
    cout << "Modulus (n): 0x" << pub_ctx.n.get_str(16).substr(0, 32) << "..." << endl;
    cout << "Exponent (e): 0x" << pub_ctx.e.get_str(16) << endl;
    cout << "Key Size: " << pub_ctx.bits << " bits" << endl;

    basic_sign_verify_test(pub_ctx, priv_ctx);
    tamper_detection_test(pub_ctx, priv_ctx);
    edge_case_tests(pub_ctx, priv_ctx);

    performance_test(2048);
    performance_test(4096);

    cout << "\n===== ALL ISO 9796-2 TESTS PASSED SUCCESSFULLY =====" << endl;
    return 0;
}
