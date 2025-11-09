#include "lib/ISO_9796_2.hpp"
#include <iostream>
#include <vector>

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


    string msg = "This is a test message for ISO 9796-2 signing.";
    vector<unsigned char> message(msg.begin(), msg.end());
    cout << "Original: " << msg << endl;
    auto signature = iso9796_2::sign(priv_ctx, message);
    cout << "Signature: 0x" << signature.get_str(16) << endl;

    auto ver_status = iso9796_2::verify(pub_ctx, signature);

    if (ver_status.valid)
    {
        string recovered_msg(ver_status.message.begin(),
                             ver_status.message.end());
        cout << "Signature verification successful." << endl;
        cout << "Recovered Message: " << recovered_msg << endl;
    }
    else
    {
        cout << "Signature verification failed." << endl;
    }

    return 0;
}