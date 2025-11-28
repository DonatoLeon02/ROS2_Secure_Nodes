#include <ament_index_cpp/get_package_share_directory.hpp>
#include <custom_msgs/msg/signed_data.hpp>
#include <custom_msgs/msg/handshake.hpp>
#include <custom_msgs/srv/handshake.hpp>
#include <fstream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <rclcpp/rclcpp.hpp>
#include <sstream>
#include <string>
#include <ctime>

class SecureSubscriber : public rclcpp::Node {
public:
  SecureSubscriber() : Node("secure_subscriber") {
    // Ensure OpenSSL PRNG is properly seeded
    RAND_poll();

    subscription_ = this->create_subscription<custom_msgs::msg::SignedData>(
        "secure_topic", 10,
        std::bind(&SecureSubscriber::verify_callback, this,
                  std::placeholders::_1));
    handshake_pub = this->create_publisher<custom_msgs::msg::Handshake>("handshake_topic", 10);
    handshake_sub = this->create_subscription<custom_msgs::msg::Handshake>(
        "handshake_topic", 10,
        std::bind(&SecureSubscriber::handshake_callback, this, std::placeholders::_1));

    generate_ecdh_keypair();
    generate_ed25519_keypair();
    handshake_srv = this->create_service<custom_msgs::srv::Handshake>(
      "handshake_service",
      std::bind(&SecureSubscriber::handshake_service_callback, this, std::placeholders::_1, std::placeholders::_2)
    );

    // Periodically resend handshake until handshake completes
    handshake_timer = this->create_wall_timer(std::chrono::seconds(1), std::bind(&SecureSubscriber::send_handshake, this));
    // No RSA key loading needed
  }

private:
  rclcpp::Subscription<custom_msgs::msg::SignedData>::SharedPtr subscription_;
  rclcpp::Publisher<custom_msgs::msg::Handshake>::SharedPtr handshake_pub;
  rclcpp::Subscription<custom_msgs::msg::Handshake>::SharedPtr handshake_sub;
  rclcpp::Service<custom_msgs::srv::Handshake>::SharedPtr handshake_srv;
  rclcpp::TimerBase::SharedPtr timer;
  rclcpp::TimerBase::SharedPtr handshake_timer;
  std::string aes_key;
  std::string aes_gcm_iv;
  std::string aes_gcm_tag;
  std::string share_dir = ament_index_cpp::get_package_share_directory("secure_node");
  EVP_PKEY *ecdh_keypair = nullptr;
  EVP_PKEY *peer_ecdh_pubkey = nullptr;
  EVP_PKEY *ed25519_keypair = nullptr;
  EVP_PKEY *peer_ed25519_pubkey = nullptr;
  bool handshake_complete = false;
  int handshake_attempts = 0;
  std::string peer_ed25519_pubkey_pem;

  void generate_ecdh_keypair() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_keygen(pctx, &ecdh_keypair);
    EVP_PKEY_CTX_free(pctx);
  }

  void generate_ed25519_keypair() {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx) {
      RCLCPP_ERROR(this->get_logger(), "Failed to create Ed25519 keygen context");
      return;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
      RCLCPP_ERROR(this->get_logger(), "Failed to init Ed25519 keygen");
      EVP_PKEY_CTX_free(pctx);
      return;
    }
    if (EVP_PKEY_keygen(pctx, &ed25519_keypair) <= 0) {
      RCLCPP_ERROR(this->get_logger(), "Failed to generate Ed25519 keypair");
      EVP_PKEY_CTX_free(pctx);
      return;
    }
    EVP_PKEY_CTX_free(pctx);
    RCLCPP_INFO(this->get_logger(), "Ed25519 keypair generated successfully");
  }

  std::string get_public_key_pem(EVP_PKEY *key) {
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, key);
    BUF_MEM *buf;
    BIO_get_mem_ptr(bio, &buf);
    std::string pubkey(buf->data, buf->length);
    BIO_free(bio);
    return pubkey;
  }

  // Use EVP_MD_CTX for Ed25519 (one-shot signing)
  std::string sign_data_ed25519(const std::string &data) {
    if (!ed25519_keypair) {
      RCLCPP_ERROR(this->get_logger(), "Ed25519 keypair is null, cannot sign");
      return "";
    }
    size_t siglen = 64; // Ed25519 signature is always 64 bytes
    std::vector<unsigned char> sig(siglen);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
      RCLCPP_ERROR(this->get_logger(), "Failed to create MD_CTX");
      return "";
    }
    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, ed25519_keypair) <= 0) {
      unsigned long err = ERR_get_error();
      char buf[256];
      ERR_error_string_n(err, buf, sizeof(buf));
      RCLCPP_ERROR(this->get_logger(), "EVP_DigestSignInit failed: %s", buf);
      EVP_MD_CTX_free(mdctx);
      return "";
    }
    if (EVP_DigestSign(mdctx, sig.data(), &siglen, reinterpret_cast<const unsigned char *>(data.data()), data.size()) <= 0) {
      unsigned long err = ERR_get_error();
      char buf[256];
      ERR_error_string_n(err, buf, sizeof(buf));
      RCLCPP_ERROR(this->get_logger(), "EVP_DigestSign failed: %s", buf);
      EVP_MD_CTX_free(mdctx);
      return "";
    }
    EVP_MD_CTX_free(mdctx);
    return std::string(reinterpret_cast<char *>(sig.data()), siglen);
  }

  // Use EVP_MD_CTX for Ed25519 verify
  bool verify_signature_ed25519(const std::string &data, const std::string &signature, EVP_PKEY *pubkey) {
    if (!pubkey) return false;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) return false;
    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, pubkey) <= 0) {
      EVP_MD_CTX_free(mdctx);
      return false;
    }
    int rv = EVP_DigestVerify(mdctx, reinterpret_cast<const unsigned char *>(signature.data()), signature.size(),
                              reinterpret_cast<const unsigned char *>(data.data()), data.size());
    EVP_MD_CTX_free(mdctx);
    return rv == 1;
  }
  
  void send_handshake() {
    custom_msgs::msg::Handshake msg;
    std::string ecdh_pub_pem = get_public_key_pem(ecdh_keypair);
    std::string ed_pub = get_public_key_pem(ed25519_keypair);

    unsigned char *der = NULL;
    int derlen = i2d_PUBKEY(ecdh_keypair, &der);
    std::string ecdh_der;
    if (derlen > 0 && der) {
      ecdh_der.assign(reinterpret_cast<char *>(der), derlen);
      OPENSSL_free(der);
    }
    std::string signature_raw = sign_data_ed25519(ecdh_der);
    if (signature_raw.empty()) {
      RCLCPP_ERROR(this->get_logger(), "Failed to sign ECDH DER, aborting handshake send");
      return;
    }
    std::string signature_b64 = base64_encode(signature_raw);
    // Debug: log deterministic DER length and a small base64 snippet for comparison
    std::string ecdh_der_b64 = base64_encode(ecdh_der);
    std::string der_snip = ecdh_der_b64.substr(0, std::min<size_t>(ecdh_der_b64.size(), 32));
    RCLCPP_DEBUG(this->get_logger(), "send_handshake: ecdh_der_len=%lu signature_len=%lu der_b64_snip=\"%s\"",
                 (unsigned long)ecdh_der.size(), (unsigned long)signature_raw.size(), der_snip.c_str());
    msg.ecdh_pubkey = ecdh_pub_pem;
    msg.ed25519_pubkey = ed_pub;
    msg.signature = signature_b64;
    handshake_pub->publish(msg);
  }
 
  void handshake_callback(const custom_msgs::msg::Handshake::SharedPtr msg) {
    if (handshake_complete) return;

    std::string local_ecdh_pem = get_public_key_pem(ecdh_keypair);
    RCLCPP_INFO(this->get_logger(), "Received handshake PEM: %s", msg->ecdh_pubkey.c_str());
    if (msg->ecdh_pubkey == local_ecdh_pem) {
      RCLCPP_INFO(this->get_logger(), "Received own handshake, ignoring.");
      return;
    }

    // Log local public keys
    unsigned char *local_der = NULL;
    int local_derlen = i2d_PUBKEY(ecdh_keypair, &local_der);
    std::string local_ecdh_der;
    if (local_derlen > 0 && local_der) {
      local_ecdh_der.assign(reinterpret_cast<char *>(local_der), local_derlen);
      OPENSSL_free(local_der);
    }
    RCLCPP_INFO(this->get_logger(), "local_ecdh_pubkey_pem_b64: %s", base64_encode(local_ecdh_pem).c_str());
    RCLCPP_INFO(this->get_logger(), "local_ecdh_pubkey_der_b64: %s", base64_encode(local_ecdh_der).c_str());

    // Log peer public keys
    RCLCPP_INFO(this->get_logger(), "peer_ecdh_pubkey_pem_b64: %s", base64_encode(msg->ecdh_pubkey).c_str());

    BIO *bio = BIO_new_mem_buf(msg->ecdh_pubkey.data(), msg->ecdh_pubkey.size());
    if (peer_ecdh_pubkey) { EVP_PKEY_free(peer_ecdh_pubkey); peer_ecdh_pubkey = nullptr; }
    peer_ecdh_pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    unsigned char *peer_der = NULL;
    int peer_derlen = i2d_PUBKEY(peer_ecdh_pubkey, &peer_der);
    std::string peer_ecdh_der;
    if (peer_derlen > 0 && peer_der) {
      peer_ecdh_der.assign(reinterpret_cast<char *>(peer_der), peer_derlen);
      OPENSSL_free(peer_der);
    }
    RCLCPP_INFO(this->get_logger(), "peer_ecdh_pubkey_der_b64: %s", base64_encode(peer_ecdh_der).c_str());

    // Load peer Ed25519 public key
    BIO *bio_ed = BIO_new_mem_buf(msg->ed25519_pubkey.data(), msg->ed25519_pubkey.size());
    if (peer_ed25519_pubkey) { EVP_PKEY_free(peer_ed25519_pubkey); peer_ed25519_pubkey = nullptr; }
    peer_ed25519_pubkey = PEM_read_bio_PUBKEY(bio_ed, NULL, NULL, NULL);
    BIO_free(bio_ed);
    // decode signature
    std::string signature_raw = base64_decode(msg->signature);
    RCLCPP_DEBUG(this->get_logger(), "handshake_callback: received signature_len=%lu", (unsigned long)signature_raw.size());
    if (signature_raw.size() != 64) {
      RCLCPP_ERROR(this->get_logger(), "handshake_callback: unexpected Ed25519 signature length=%lu (expected 64)", (unsigned long)signature_raw.size());
      return;
    }
    // create DER from the peer ECDH EVP_PKEY for deterministic verification
    if (peer_ecdh_pubkey) {
      unsigned char *peer_der = NULL;
      int peer_derlen = i2d_PUBKEY(peer_ecdh_pubkey, &peer_der);
      if (peer_derlen > 0 && peer_der) {
        peer_ecdh_der.assign(reinterpret_cast<char *>(peer_der), peer_derlen);
        OPENSSL_free(peer_der);
      }
    }
    // Debug: log peer DER length and small snippet
    std::string peer_der_b64 = base64_encode(peer_ecdh_der);
    std::string peer_der_snip = peer_der_b64.substr(0, std::min<size_t>(peer_der_b64.size(), 32));
    RCLCPP_INFO(this->get_logger(), "handshake_callback: peer_ecdh_der_len=%lu der_b64_snip=\"%s\"",
                 (unsigned long)peer_ecdh_der.size(), peer_der_snip.c_str());
    if (!verify_signature_ed25519(peer_ecdh_der, signature_raw, peer_ed25519_pubkey)) {
      unsigned long err = ERR_get_error();
      if (err) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        RCLCPP_ERROR(this->get_logger(), "OpenSSL verify error: %s", buf);
      }
      handshake_attempts++;
      if (handshake_attempts > 2) {
        RCLCPP_ERROR(this->get_logger(), "Handshake signature verification failed after %d attempts!", handshake_attempts);
      }
      return;
    }
    handshake_attempts = 0;
    // Derive shared secret using own private key and peer's public key
    unsigned char secret[32];
    size_t secret_len = sizeof(secret);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(ecdh_keypair, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_ecdh_pubkey);
    int rv = EVP_PKEY_derive(ctx, secret, &secret_len);
    EVP_PKEY_CTX_free(ctx);
    if (rv <= 0) {
      RCLCPP_ERROR(this->get_logger(), "EVP_PKEY_derive failed: rv=%d", rv);
      return;
    }
    RCLCPP_INFO(this->get_logger(), "secret_len: %lu", (unsigned long)secret_len);
    std::string secret_b64 = base64_encode(std::string((char*)secret, secret_len));
    RCLCPP_INFO(this->get_logger(), "shared_secret_raw_b64: %s", secret_b64.c_str());
    // Ensure AES key is exactly 32 bytes for AES-256
    if (secret_len >= 32) {
      aes_key = std::string((char *)secret, 32);
    } else {
      std::string tmp((char *)secret, secret_len);
      tmp.resize(32, 0);
      aes_key = tmp;
    }
    RCLCPP_INFO(this->get_logger(), "aes_key_raw_b64: %s", base64_encode(aes_key).c_str());
    handshake_complete = true;
    if (handshake_timer) handshake_timer.reset();
    std::string key_hash_b64 = base64_encode(sha256(aes_key));
    RCLCPP_INFO(this->get_logger(), "AES key hash b64: %s", key_hash_b64.c_str());
    RCLCPP_INFO(this->get_logger(), "ECDH handshake complete. AES key derived.");
  }

  void handshake_service_callback(
    const std::shared_ptr<custom_msgs::srv::Handshake::Request> request,
    std::shared_ptr<custom_msgs::srv::Handshake::Response> response
  ) {
    // Load peer ECDH public key
    BIO *bio = BIO_new_mem_buf(request->ecdh_pubkey.data(), request->ecdh_pubkey.size());
    if (peer_ecdh_pubkey) { EVP_PKEY_free(peer_ecdh_pubkey); peer_ecdh_pubkey = nullptr; }
    peer_ecdh_pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    // Load peer Ed25519 public key
    BIO *bio_ed = BIO_new_mem_buf(request->ed25519_pubkey.data(), request->ed25519_pubkey.size());
    if (peer_ed25519_pubkey) { EVP_PKEY_free(peer_ed25519_pubkey); peer_ed25519_pubkey = nullptr; }
    peer_ed25519_pubkey = PEM_read_bio_PUBKEY(bio_ed, NULL, NULL, NULL);
    BIO_free(bio_ed);

    // Derive shared secret
    unsigned char secret[32];
    size_t secret_len = sizeof(secret);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(ecdh_keypair, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_ecdh_pubkey);
    int rv = EVP_PKEY_derive(ctx, secret, &secret_len);
    EVP_PKEY_CTX_free(ctx);
    if (rv <= 0) {
      RCLCPP_ERROR(this->get_logger(), "EVP_PKEY_derive failed: rv=%d", rv);
      return;
    }
    aes_key = std::string((char *)secret, secret_len >= 32 ? 32 : secret_len);
    handshake_complete = true;
    RCLCPP_INFO(this->get_logger(), "Subscriber derived AES key.");

    // Respond with own keys and signature
    std::string ecdh_pub_pem = get_public_key_pem(ecdh_keypair);
    std::string ed_pub = get_public_key_pem(ed25519_keypair);
    unsigned char *der = NULL;
    int derlen = i2d_PUBKEY(ecdh_keypair, &der);
    std::string ecdh_der;
    if (derlen > 0 && der) {
      ecdh_der.assign(reinterpret_cast<char *>(der), derlen);
      OPENSSL_free(der);
    }
    std::string signature_raw = sign_data_ed25519(ecdh_der);
    std::string signature_b64 = base64_encode(signature_raw);

    response->ecdh_pubkey = ecdh_pub_pem;
    response->ed25519_pubkey = ed_pub;
    response->signature = signature_b64;
  }

  std::string aes_gcm_decrypt(const std::string &ciphertext, const std::string &iv, const std::string &tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::string plaintext;
    plaintext.resize(ciphertext.size());
    int len;
    int plaintext_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                       reinterpret_cast<const unsigned char *>(aes_key.data()),
                       reinterpret_cast<const unsigned char *>(iv.data()));
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<char *>(tag.data()));
    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(&plaintext[0]), &len,
                      reinterpret_cast<const unsigned char *>(ciphertext.data()), ciphertext.size());
    plaintext_len = len;
    int final_len = 0;
    int rv = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(&plaintext[0]) + len, &final_len);
    if (rv <= 0) {
      // Authentication failed
      EVP_CIPHER_CTX_free(ctx);
      return "";
    }
    plaintext_len += final_len;
    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
  }

  std::string base64_encode(const std::string &in) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Remove for padded base64
    BIO_write(bio, in.c_str(), in.size());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
  }

  std::string base64_decode(const std::string &in) {
    BIO *bio, *b64;
    // allocate safe buffer for decoded data
    size_t max_decoded = (in.size() * 3) / 4 + 4;
    std::vector<char> buffer(max_decoded);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(in.data(), (int)in.size());
    bio = BIO_push(b64, bio);

    // BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Remove for padded base64
    int decoded_size = BIO_read(bio, buffer.data(), (int)buffer.size());
    BIO_free_all(bio);

    RCLCPP_DEBUG(this->get_logger(), "base64_decode: input_size=%lu decoded_size=%lu",
                 (unsigned long)in.size(), (unsigned long)decoded_size);

    if (decoded_size <= 0) return std::string();
    return std::string(buffer.data(), decoded_size);
  }

  void verify_callback(const custom_msgs::msg::SignedData::SharedPtr msg) {
    if (aes_key.empty()) {
      RCLCPP_ERROR(this->get_logger(), "AES key not loaded.");
      return;
    }
    auto start = std::chrono::high_resolution_clock::now();
    std::string encrypted_data = base64_decode(msg->data);
    std::string signature = base64_decode(msg->signature);
    std::string iv = base64_decode(msg->iv);
    std::string tag = base64_decode(msg->tag);
    std::string decrypted_data = aes_gcm_decrypt(encrypted_data, iv, tag);
    if (decrypted_data.empty()) {
      RCLCPP_ERROR(this->get_logger(), "Decryption failed or authentication failed.");
      return;
    }
    bool result = false;
    if (peer_ed25519_pubkey) {
      result = verify_signature_ed25519(decrypted_data, signature, peer_ed25519_pubkey);
    } else {
      RCLCPP_ERROR(this->get_logger(), "Peer Ed25519 pubkey not loaded.");
    }
    auto end = std::chrono::high_resolution_clock::now();
    long elapsed_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start)
            .count();
    RCLCPP_INFO(this->get_logger(), "Decryption/verification time: %ld µs",
                elapsed_us);
    std::ofstream log_file("/tmp/dec_verify_time.csv",
                           std::ios::app);
    if (log_file.is_open()) {
      log_file << elapsed_us << std::endl;
      log_file.close();
    } else {
      RCLCPP_ERROR(this->get_logger(), "Failed to open CSV log file.");
    }
    if (result) {
      RCLCPP_INFO_STREAM(this->get_logger(), "✅ Valid signature! Data: '"
                                                 << decrypted_data << "'");
    } else {
      RCLCPP_WARN(this->get_logger(), "❌ Invalid signature!");
    }
  }

  std::string sha256(const std::string &data) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data.data(), data.size());
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);
    return std::string((char *)hash, hash_len);
  }

  void message_callback(const custom_msgs::msg::SignedData::SharedPtr msg) {
    if (aes_key.empty()) {
      RCLCPP_ERROR(this->get_logger(), "AES key not loaded.");
      return;
    }
    std::string decoded_data = base64_decode(msg->data);
    std::string decoded_signature = base64_decode(msg->signature);
    std::string decoded_iv = base64_decode(msg->iv);
    std::string decoded_tag = base64_decode(msg->tag);

    RCLCPP_INFO(this->get_logger(), "decoded sizes: data=%lu iv=%lu tag=%lu sig=%lu",
                 (unsigned long)decoded_data.size(), (unsigned long)decoded_iv.size(),
                 (unsigned long)decoded_tag.size(), (unsigned long)decoded_signature.size());

    std::string decrypted_data = aes_gcm_decrypt(decoded_data, decoded_iv, decoded_tag);
    if (decrypted_data.empty()) {
      RCLCPP_ERROR(this->get_logger(), "Decryption failed or authentication failed.");
      return;
    }
    // Load peer Ed25519 pubkey
    BIO *bio = BIO_new_mem_buf(peer_ed25519_pubkey_pem.data(), peer_ed25519_pubkey_pem.size());
    EVP_PKEY *peer_ed_pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    bool sig_valid = verify_signature_ed25519(decrypted_data, decoded_signature, peer_ed_pubkey);
    EVP_PKEY_free(peer_ed_pubkey);
    if (!sig_valid) {
      RCLCPP_WARN(this->get_logger(), "❌ Invalid signature!");
      return;
    }
    RCLCPP_INFO_STREAM(this->get_logger(), "✅ Valid signature! Data: '"
                                               << decrypted_data << "'");
  }
};

int main(int argc, char *argv[]) {
  rclcpp::init(argc, argv);
  rclcpp::spin(std::make_shared<SecureSubscriber>());
  rclcpp::shutdown();
  return 0;
}
