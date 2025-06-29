#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "protocol.h"

bool send_all(int sockfd, const unsigned char *data, size_t len)
{
    LOG(DEBUG, "Sending %zu bytes", len);
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t n = send(sockfd, data + sent, len - sent, 0);
        if (n <= 0)
            return false;
        sent += n;
    }
    return true;
}

bool send_message(int sockfd, const byte_vec &data)
{
    if (data.size() > UINT32_MAX)
        error("Data size exceeds maximum limit");
    uint32_t len = htonl(data.size());
    if (!send_all(sockfd, reinterpret_cast<unsigned char *>(&len), sizeof(len)))
        return false;
    if (!send_all(sockfd, data.data(), data.size()))
        return false;
    return true;
}

bool recv_all(int sockfd, unsigned char *data, size_t len)
{
    LOG(DEBUG, "Receiving %zu bytes", len);
    size_t received = 0;
    while (received < len)
    {
        ssize_t n = recv(sockfd, data + received, len - received, 0);
        if (n <= 0)
            return false;
        received += n;
    }
    return true;
}

bool recv_message(int sockfd, byte_vec &out)
{
    uint32_t len_net = 0;
    if (!recv_all(sockfd, reinterpret_cast<unsigned char *>(&len_net), sizeof(len_net)))
        return false;

    uint32_t len = ntohl(len_net);
    if (len > MAX_DOC_SIZE) // Optional: limit to 10 MB
        return false;

    out.resize(len);
    return recv_all(sockfd, out.data(), len);
}

void send_secure_message(int sockfd,
                         const byte_vec &plaintext,
                         const byte_vec &key,
                         uint64_t &message_counter)
{

    uint64_t old_counter = message_counter;

    // Derive IV from counter: first 4 bytes zero, last 8 bytes = counter (big-endian)
    byte_vec iv(12, 0);
    uint64_t counter_be = htobe64(++message_counter);
    memcpy(iv.data() + 4, &counter_be, sizeof(uint64_t));

    if (old_counter > message_counter)
        error("Message counter overflow");


    // Pad plaintext to 64 bytes with pkcs7 padding
    size_t padding_len = 64 - (plaintext.size() % 64);

    byte_vec padded_plaintext = plaintext;
    padded_plaintext.insert(padded_plaintext.end(), padding_len, padding_len);

    // Encrypt padded plaintext
    byte_vec ciphertext, tag;
    aes256gcm_encrypt(padded_plaintext, key, iv, ciphertext, tag);

    // Build message: [12-byte IV][ciphertext][16-byte tag]
    byte_vec msg;
    msg.resize(iv.size() + ciphertext.size() + tag.size());

    size_t offset = 0;
    memcpy(msg.data() + offset, iv.data(), iv.size());
    offset += iv.size();

    memcpy(msg.data() + offset, ciphertext.data(), ciphertext.size());
    offset += ciphertext.size();

    memcpy(msg.data() + offset, tag.data(), tag.size());

    LOG(DEBUG, "IV, ciphertext and tag from sent message");
    LOG(DEBUG, "IV: %s", byte_vec_to_hex(iv).c_str());
    LOG(DEBUG, "Ciphertext: %s", byte_vec_to_hex(ciphertext).c_str());
    LOG(DEBUG, "Tag: %s", byte_vec_to_hex(tag).c_str());
    LOG(DEBUG, "Message counter: %llu", message_counter);
    LOG(DEBUG, "Padded Plaintext: %s", byte_vec_to_hex(padded_plaintext).c_str());

    memzero(padded_plaintext); // Clear padded plaintext from memory

    // Send with length prefix framing
    if (!send_message(sockfd, msg))
    {
        error("send_message failed");
        return;
    }
}

bool recv_secure_message(int sockfd,
                         const byte_vec &key,
                         uint64_t &last_received_counter,
                         byte_vec &plaintext)
{
    // Receive the full framed message
    byte_vec msg;
    if (!recv_message(sockfd, msg))
    {
        LOG(ERROR, "recv_message failed: disconnected client");
        return false;
    }

    if (msg.size() < (12 + 16))
    {
        // minimum size: IV + tag (ciphertext could be empty)
        LOG(WARN, "Received message too short: %zu bytes", msg.size());
        return false;
    }
    size_t offset = 0;

    // Extract IV (12 bytes)
    byte_vec iv(msg.data() + offset, msg.data() + offset + 12);
    offset += 12;

    // Extract counter from last 8 bytes of IV
    uint64_t counter_be = 0;
    memcpy(&counter_be, iv.data() + 4, sizeof(uint64_t));

    uint64_t counter = be64toh(counter_be);

    // Replay protection: must be the next one
    if (counter != last_received_counter + 1)
    {
        LOG(WARN, "Received message with non-increasing counter: %llu <= %llu",
            counter, last_received_counter);
        return false;
    }
    last_received_counter++;

    // Extract ciphertext
    size_t ciphertext_len = msg.size() - offset - 16;
    byte_vec ciphertext(msg.data() + offset, msg.data() + offset + ciphertext_len);
    offset += ciphertext_len;

    // Extract tag (16 bytes)
    byte_vec tag(msg.data() + offset, msg.data() + offset + 16);

    LOG(DEBUG, "Extracted IV, ciphertext and tag from received message");
    LOG(DEBUG, "IV: %s", byte_vec_to_hex(iv).c_str());
    LOG(DEBUG, "Ciphertext: %s", byte_vec_to_hex(ciphertext).c_str());
    LOG(DEBUG, "Tag: %s", byte_vec_to_hex(tag).c_str());
    LOG(DEBUG, "Message counter: %llu", last_received_counter);

    byte_vec padded_plaintext;
    try
    {
        aes256gcm_decrypt(ciphertext, key, iv, tag, padded_plaintext);
    }
    catch (exception &e)
    {

        LOG(ERROR, "Decryption failed: %s", e.what());
        memzero(padded_plaintext);
        return false;
    }

    // Remove PKCS7 padding
    size_t padding_len = padded_plaintext.back();

    plaintext.resize(padded_plaintext.size() - padding_len);
    memcpy(plaintext.data(), padded_plaintext.data(), plaintext.size());

    LOG(DEBUG, "Padded Plaintext: %s", byte_vec_to_hex(padded_plaintext).c_str());
    LOG(DEBUG, "Plaintext: %s", byte_vec_to_hex(plaintext).c_str());

    memzero(padded_plaintext); // Clear padded plaintext from memory

    return true;
}

bool init_secure_conversation_client(int sockfd,
                                     EVP_PKEY *server_rsa_pub,
                                     byte_vec &shared_key)
{
    LOG(INFO, "Initializing secure conversation with server");
    // 1. Generate client's DH key pair and send public key
    byte_vec my_pub_dh_msg;
    EVP_PKEY *my_dh_keypair = nullptr;
    ffdhe2048GenMsgAndKeys(my_pub_dh_msg, my_dh_keypair);
    if (!send_message(sockfd, my_pub_dh_msg))
        error("Failed to send client DH public key");
    LOG(DEBUG, "Sent client DH public key (%zu bytes)", my_pub_dh_msg.size());

    // 2. Receive server's DH public key
    byte_vec server_pub_dh_msg;
    if (!recv_message(sockfd, server_pub_dh_msg))
        error("Failed to receive server DH public key");
    LOG(DEBUG, "Received server DH public key (%zu bytes)", server_pub_dh_msg.size());

    // 3. Receive signature over both pubkeys (order: client_pub || server_pub)
    byte_vec signature;
    if (!recv_message(sockfd, signature))
        error("Failed to receive server signature");
    LOG(DEBUG, "Received server signature (%zu bytes)", signature.size());

    // 4. Verify signature
    byte_vec signed_data = my_pub_dh_msg; // concat(client_pub || server_pub)
    signed_data.insert(signed_data.end(), server_pub_dh_msg.begin(), server_pub_dh_msg.end());

    if (!verifyRsaSha256(signed_data, signature, server_rsa_pub))
        error("Server signature verification failed");
    LOG(DEBUG, "Server signature verified successfully");

    // 5. Decode server DH pubkey and compute shared secret
    const unsigned char *p = server_pub_dh_msg.data();
    EVP_PKEY *server_dh_pubkey = d2i_PUBKEY(NULL, &p, server_pub_dh_msg.size());
    if (!server_dh_pubkey)
        error("Failed to parse server DH public key");
    LOG(DEBUG, "Parsed server DH public key successfully");

    byte_vec shared_secret;

    if (!derive_shared_secret_and_key(my_dh_keypair, server_dh_pubkey, shared_secret, shared_key))
    {
        memzero(shared_secret); // Clear shared secret from memory
        EVP_PKEY_free(my_dh_keypair);
        EVP_PKEY_free(server_dh_pubkey);
        error("Shared key derivation failed");
    }
    LOG(DEBUG, "Derived shared secret successfully");

    memzero(shared_secret); // Clear shared secret from memory
    EVP_PKEY_free(my_dh_keypair);
    EVP_PKEY_free(server_dh_pubkey);
    return true;
}

bool init_secure_conversation_server(int sockfd,
                                     EVP_PKEY *server_rsa_priv,
                                     byte_vec &shared_key)
{
    LOG(INFO, "Initializing secure conversation with client");
    // 1. Receive client's DH public key
    byte_vec client_pub_dh_msg;
    if (!recv_message(sockfd, client_pub_dh_msg))
        error("Failed to receive client DH public key");

    // 2. Generate server's DH key pair and encode public key
    byte_vec my_pub_dh_msg;
    EVP_PKEY *my_dh_keypair = nullptr;
    ffdhe2048GenMsgAndKeys(my_pub_dh_msg, my_dh_keypair);

    // 3. Create signature over (client_pub || server_pub)
    byte_vec signed_data = client_pub_dh_msg;
    signed_data.insert(signed_data.end(), my_pub_dh_msg.begin(), my_pub_dh_msg.end());

    byte_vec signature;
    signRsaSha256(signature, signed_data, server_rsa_priv);

    // 4. Send server's DH public key and the signature
    if (!send_message(sockfd, my_pub_dh_msg))
        error("Failed to send server DH public key");

    if (!send_message(sockfd, signature))
        error("Failed to send server signature");

    // 5. Decode client DH public key
    const unsigned char *p = client_pub_dh_msg.data();
    EVP_PKEY *client_dh_pubkey = d2i_PUBKEY(nullptr, &p, client_pub_dh_msg.size());
    if (!client_dh_pubkey)
        error("Failed to parse client DH public key");

    byte_vec shared_secret;
    if (!derive_shared_secret_and_key(my_dh_keypair, client_dh_pubkey, shared_secret, shared_key))
    {
        memzero(shared_secret); // Clear shared secret from memory
        EVP_PKEY_free(my_dh_keypair);
        EVP_PKEY_free(client_dh_pubkey);
        error("Shared key derivation failed");
    }

    memzero(shared_secret);
    EVP_PKEY_free(my_dh_keypair);
    EVP_PKEY_free(client_dh_pubkey);
    return true;
}
