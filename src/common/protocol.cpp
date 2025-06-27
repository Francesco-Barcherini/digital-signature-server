#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "protocol.h"

// TODO

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
    uint32_t len = htonl(data.size());
    if (!send_all(sockfd, reinterpret_cast<unsigned char *>(&len), sizeof(len)))
        return false;
    if (!send_all(sockfd, data.data(), data.size()))
        return false;
    return true;
}

bool send_bytes(int sockfd, const byte_vec &data)
{
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

bool recv_bytes(int sockfd, byte_vec &out, size_t len)
{
    out.resize(len);
    return recv_all(sockfd, out.data(), len);
}

void send_secure_message(int sockfd,
                         const byte_vec &plaintext,
                         const byte_vec &key,
                         uint64_t &message_counter)
{
    byte_vec iv_header(12, 0);
    byte_vec iv_body(12, 0);
    uint64_t counter_be, old_counter;

    old_counter = message_counter;

    // Set IV for header
    counter_be = htobe64(++message_counter);
    std::memcpy(iv_header.data() + 4, &counter_be, sizeof(uint64_t));

    // Set IV for body
    counter_be = htobe64(++message_counter);
    std::memcpy(iv_body.data() + 4, &counter_be, sizeof(uint64_t));

    if (old_counter > message_counter)
        error("Message counter overflow");

    // Encrypt body
    byte_vec ciphertext_body, tag_body;

    aes256gcm_encrypt(plaintext, key, iv_body, ciphertext_body, tag_body);

    size_t body_message_len = iv_body.size() + ciphertext_body.size() + tag_body.size();

    // Encrypt header
    byte_vec ciphertext_header, tag_header, plaintext_header;
    plaintext_header.resize(4);

    uint32_t body_len = htonl((uint32_t)body_message_len);
    std::memcpy(plaintext_header.data(), &body_len, 4);

    aes256gcm_encrypt(plaintext_header, key, iv_header, ciphertext_header, tag_header);

    // Send header
    byte_vec msg_header;
    msg_header.resize(iv_header.size() + ciphertext_header.size() + tag_header.size());
    size_t offset = 0;
    std::memcpy(msg_header.data() + offset, iv_header.data(), iv_header.size());
    offset += iv_header.size();
    std::memcpy(msg_header.data() + offset, ciphertext_header.data(), ciphertext_header.size());
    offset += ciphertext_header.size();
    std::memcpy(msg_header.data() + offset, tag_header.data(), tag_header.size());
    size_t header_size = msg_header.size();

    LOG(DEBUG, "Sending secure message with header size %zu and body size %zu",
        header_size, body_message_len);

    // Send with length prefix framing
    if (!send_bytes(sockfd, msg_header))
    {
        error("send_message failed");
        return;
    }

    // Send body

    byte_vec msg_body;
    msg_body.resize(iv_body.size() + ciphertext_body.size() + tag_body.size());
    offset = 0;
    std::memcpy(msg_body.data() + offset, iv_body.data(), iv_body.size());
    offset += iv_body.size();
    std::memcpy(msg_body.data() + offset, ciphertext_body.data(), ciphertext_body.size());
    offset += ciphertext_body.size();
    std::memcpy(msg_body.data() + offset, tag_body.data(), tag_body.size());

    // Send with length prefix framing
    if (!send_bytes(sockfd, msg_body))
    {
        error("send_message failed");
        return;
    }
}

bool recv_secure_message(int sockfd,
                         const byte_vec &key,
                         uint64_t &last_received_counter, // TODO: reset the value on new session
                         byte_vec &plaintext)
{
    // Receive the full framed message
    byte_vec msg_header;
    if (!recv_bytes(sockfd, msg_header, 32)) // Expecting exactly 32 bytes for the header
    {
        LOG(ERROR, "recv_message failed for header");
        return false;
    }

    byte_vec iv_header(msg_header.data(), msg_header.data() + 12);              // First 12 bytes are the IV
    byte_vec ciphertext_header(msg_header.data() + 12, msg_header.data() + 16); // Next 4 bytes are the ciphertext
    byte_vec tag_header(msg_header.data() + 16, msg_header.data() + 32);        // Last 16 bytes are the tag

    // Receive the header counter
    uint64_t counter_be;
    std::memcpy(&counter_be, iv_header.data() + 4, sizeof(uint64_t));
    uint64_t counter = be64toh(counter_be);

    if (counter <= last_received_counter)
    {
        LOG(WARN, "Received message with non-increasing counter: %llu <= %llu",
            counter, last_received_counter);
        return false;
    }
    last_received_counter = counter;

    // Decrypt header
    byte_vec plaintext_header;
    try
    {
        aes256gcm_decrypt(ciphertext_header, key, iv_header, tag_header, plaintext_header);
    }
    catch (...)
    {
        LOG(ERROR, "Decryption of header failed");
        return false;
    }
    if (plaintext_header.size() != 4)
    {
        LOG(ERROR, "Decrypted header wrong length: %zu bytes", plaintext_header.size());
        return false;
    }
    uint32_t body_message_len;
    std::memcpy(&body_message_len, plaintext_header.data(), sizeof(body_message_len));
    body_message_len = ntohl(body_message_len);

    byte_vec msg_body;
    if (!recv_bytes(sockfd, msg_body, body_message_len))
    {
        LOG(ERROR, "recv_message failed for body");
        return false;
    }

    if (msg_body.size() < (12 + 16))
    {
        // minimum size: IV + tag (ciphertext could be empty)
        LOG(WARN, "Received message too short: %zu bytes", msg_body.size());
        return false;
    }
    size_t offset = 0;

    // Extract IV (12 bytes)
    byte_vec iv(msg_body.data() + offset, msg_body.data() + offset + 12);
    offset += 12;

    // Extract counter from last 8 bytes of IV
    counter_be = 0;
    std::memcpy(&counter_be, iv.data() + 4, sizeof(uint64_t));

    counter = be64toh(counter_be);

    // Replay protection: must be strictly increasing
    if (counter <= last_received_counter)
    {
        LOG(WARN, "Received message with non-increasing counter: %llu <= %llu",
            counter, last_received_counter);
        return false;
    }
    last_received_counter = counter;

    // Extract ciphertext
    size_t ciphertext_len = msg_body.size() - offset - 16;
    byte_vec ciphertext(msg_body.data() + offset, msg_body.data() + offset + ciphertext_len);
    offset += ciphertext_len;

    // Extract tag (16 bytes)
    byte_vec tag(msg_body.data() + offset, msg_body.data() + offset + 16);

    LOG(DEBUG, "Extracted IV, ciphertext and tag from received message");
    LOG(DEBUG, "IV: %s", byte_vec_to_hex(iv).c_str());
    LOG(DEBUG, "Ciphertext: %s", byte_vec_to_hex(ciphertext).c_str());
    LOG(DEBUG, "Tag: %s", byte_vec_to_hex(tag).c_str());
    LOG(DEBUG, "Message counter: %llu", counter);

    try
    {
        aes256gcm_decrypt(ciphertext, key, iv, tag, plaintext);
    }
    catch (...)
    {
        LOG(ERROR, "Decryption failed");
        return false;
    }
    return true;
}

bool init_secure_conversation_client(int sockfd,
                                     EVP_PKEY *server_rsa_pub,
                                     byte_vec &shared_key)
{
    LOG(DEBUG, "Initializing secure conversation with server");
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
        EVP_PKEY_free(server_dh_pubkey);
        error("Shared key derivation failed");
    }
    LOG(DEBUG, "Derived shared secret successfully");

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
        EVP_PKEY_free(client_dh_pubkey);
        error("Shared key derivation failed");
    }

    EVP_PKEY_free(client_dh_pubkey);
    return true;
}
