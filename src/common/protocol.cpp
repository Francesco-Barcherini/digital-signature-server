#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "protocol.h"

// TODO

bool send_all(int sockfd, const unsigned char *data, size_t len)
{
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

bool recv_all(int sockfd, unsigned char *data, size_t len)
{
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
    if (len > 10 * 1024 * 1024) // Optional: limit to 10 MB
        return false;

    out.resize(len);
    return recv_all(sockfd, out.data(), len);
}

void send_secure_message(int sockfd,
                         const byte_vec &plaintext,
                         const byte_vec &key,
                         uint64_t &message_counter)
{
    // Derive IV from counter: first 4 bytes zero, last 8 bytes = counter
    byte_vec iv(12, 0);
    std::memcpy(iv.data() + 4, &message_counter, sizeof(uint64_t));

    // Encrypt plaintext
    byte_vec ciphertext, tag;
    aes256gcm_encrypt(plaintext, key, iv, ciphertext, tag);

    // Build message: [12-byte IV][ciphertext][16-byte tag]
    byte_vec msg;
    msg.resize(iv.size() + ciphertext.size() + tag.size());

    size_t offset = 0;
    std::memcpy(msg.data() + offset, iv.data(), iv.size());
    offset += iv.size();

    std::memcpy(msg.data() + offset, ciphertext.data(), ciphertext.size());
    offset += ciphertext.size();

    std::memcpy(msg.data() + offset, tag.data(), tag.size());

    // Send with length prefix framing
    if (!send_message(sockfd, msg))
    {
        error("send_message failed");
        return;
    }

    message_counter++;
}

bool recv_secure_message(int sockfd,
                         const byte_vec &key,
                         uint64_t &last_received_counter,
                         byte_vec &plaintext)
{
    // Receive the full framed message
    byte_vec msg;
    if (!recv_message(sockfd, msg))
        return false;

    // TODO ???
    if (msg.size() < (12 + 16)) // minimum size: IV + tag (ciphertext could be empty)
        LOG(WARN, "Received message too short: %zu bytes", msg.size());
    return false;

    size_t offset = 0;

    // Extract IV (12 bytes)
    byte_vec iv(msg.data() + offset, msg.data() + offset + 12);
    offset += 12;

    // Extract counter from last 8 bytes of IV
    uint64_t msg_counter = 0;
    std::memcpy(&msg_counter, iv.data() + 4, sizeof(uint64_t));

    // Replay protection: must be strictly increasing
    if (msg_counter <= last_received_counter)
    {
        LOG(WARN, "Received message with non-increasing counter: %llu <= %llu",
            msg_counter, last_received_counter);
        return false;
    }

    // Extract ciphertext
    size_t ciphertext_len = msg.size() - offset - 16;
    byte_vec ciphertext(msg.data() + offset, msg.data() + offset + ciphertext_len);
    offset += ciphertext_len;

    // Extract tag (16 bytes)
    byte_vec tag(msg.data() + offset, msg.data() + offset + 16);

    try
    {
        aes256gcm_decrypt(ciphertext, key, iv, tag, plaintext);
    }
    catch (...)
    {
        LOG(ERROR, "Decryption failed");
        return false;
    }
    last_received_counter = msg_counter;
    return true;
}
