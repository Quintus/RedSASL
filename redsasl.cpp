/* Copyright © 2017 Marvin Gülker
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials provided
 *    with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "redsasl.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <algorithm>
#include <stdexcept>
#include <map>
#include <locale>

using namespace Redsasl;

enum {
    STEP_INITIAL_RESPONSE = 0,
    SCRAM_STEP_1,

    // Keep this last
    STEP_ADDITIONAL_DATA_WITH_SUCCESS
};

/**
 * Convert the given string to lowercase under ASCII rules. Does NOT
 * handle Unicode characters!
 */
static void lowercase(std::string& str)
{
    std::locale loc("C"); // Ensure ASCII semantics are observed
    std::transform(str.begin(), str.end(), str.begin(), [&](char c){return std::tolower(c, loc);});
}

/**
 * Replaces patterns in a string with another string.
 * This function modifies its first argument.
 *
 * \param str[in, out]
 * String to work on. This string is changed by this function.
 *
 * \param[in] target
 * Pattern to replace.
 *
 * \param[in] replacement
 * String to put in place of the pattern in the string.
 *
 * \returns The parameter `str`.
 */
static std::string& strgsub(std::string& str, const std::string& target, const std::string& replacement)
{
    size_t pos = 0;
    while (str.find(target, pos) != std::string::npos) {
        str.replace(pos, target.length(), replacement);
        pos += target.length();
    }

    return str;
}

/**
 * Encode the given string with Base64 so it can be used in ASCII-only
 * contexts.  Returns a new, base-64 encoded string.
 *
 * \see base64_decode()
 */
static std::string base64_encode(const std::string& plain)
{
    BIO* p_b64    = BIO_new(BIO_f_base64());
    BIO* p_target = BIO_new(BIO_s_mem());

    BIO_set_flags(p_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(p_b64, p_target);

    while (true) {
        if (BIO_write(p_b64, plain.data(), plain.length()) < 0) {
            if (BIO_should_retry(p_b64)) {
                // temporary error, retry
            }
            else {
                // permanent error
                BIO_free_all(p_b64);
                throw(std::runtime_error("Encoding to Base64 failed"));
            }
        }
        else {
            // Success
            break;
        }
    }

    // Ensure everything ends up in the memory BIO
    if (BIO_flush(p_b64) < 0) {
        // Ignore failure
    }

    // Wire it out of the memory BIO
    const char* cresult = NULL;
    long len = BIO_get_mem_data(p_b64, &cresult);

    // Convert to C++ string
    std::string result(cresult, len);

    // Fin
    BIO_free_all(p_b64);
    return result;
}

/**
 * Decode a base64-encoded string back into plain text; inverse
 * operation of base64_encode(). Returns a new string that has the
 * base64-encoding removed.
 *
 * \see base64_encode()
 */
static std::string base64_decode(const std::string& base64)
{
    BIO* p_b64    = BIO_new(BIO_f_base64());
    BIO* p_source = BIO_new_mem_buf(base64.c_str(), base64.length());

    BIO_set_flags(p_b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(p_b64, p_source);

    std::string result;
    char buf[4096];
    int len = 0;
    while ((len = BIO_read(p_b64, buf, 4096)) > 0) {
        result += std::string(buf, len);
    }

    BIO_free_all(p_b64);
    return result;
}

/**
 * Small wrapper around OpenSSL's HMAC() function that makes its
 * interface more C++ish.
 *
 * \param algorithm
 * Master hash algorithm for this HMAC algorithm.
 *
 * \param key[in]
 * HMAC key.
 *
 * \param str[in]
 * Message to digest.
 *
 * \returns The message authentication code (MAC). This is a binary
 * blob, i.e. *not* hex-encoded.
 */
static std::string hmac(hashalgo algorithm, const std::string& key, const std::string& str)
{
    using namespace Redsasl;

    const EVP_MD* evp = NULL;
    switch (algorithm) {
    case hashalgo::MD5:
        evp = EVP_md5();
        break;
    case hashalgo::SHA1:
        evp = EVP_sha1();
        break;
    case hashalgo::SHA256:
        evp = EVP_sha256();
        break;
    // No default clause so compiler can warn about missing values
    }

    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(evp, key.data(),
         key.length(),
         (unsigned char*) str.data(),
         str.length(),
         buf,
         &len);

    return std::string((char*) buf, len);
}

/**
 * Calculates the digest checksum of the given string (e.g., SHA1). The
 * result is returned as a binary blob, i.e. it is *not*
 * hex-encoded.
 */
static std::string digest_hash(hashalgo algo, const std::string& str)
{
    EVP_MD_CTX* p_md_ctx = EVP_MD_CTX_create();
    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    std::string result;
    const EVP_MD* p_hashfunc = NULL;

    switch(algo) {
    case hashalgo::MD5:
        p_hashfunc = EVP_md5();
        break;
    case hashalgo::SHA1:
        p_hashfunc = EVP_sha1();
        break;
    case hashalgo::SHA256:
        p_hashfunc = EVP_sha256();
        break;
    // No default so the compiler can warn about missing values
    }

    if (EVP_DigestInit_ex(p_md_ctx, p_hashfunc, NULL) != 1)
        goto fail;

    if (EVP_DigestUpdate(p_md_ctx, str.data(), str.length()) != 1)
        goto fail;

    if (EVP_DigestFinal(p_md_ctx, buf, &len) != 1)
        goto fail;

    result = std::string((char*) buf, len);

    EVP_MD_CTX_cleanup(p_md_ctx);
    EVP_MD_CTX_destroy(p_md_ctx);
    return result;

 fail:
    EVP_MD_CTX_cleanup(p_md_ctx);
    EVP_MD_CTX_destroy(p_md_ctx);
    throw(std::runtime_error("OpenSSL message digest hash calculation failed"));
}

/**
 * Apply bitwise XOR on each element of the two strings given as parameters
 * (which must be of equal length, otherwise an exception is thrown).
 * This function implements the XOR operator of RFC 5802, §2.2(7th point).
 */
static std::string strxor(const std::string& str1, const std::string& str2)
{
    size_t len = str1.length();
    if (len != str2.length())
        throw(new std::invalid_argument("XOR strings as per RFC 5802, section 2.2(point 7), must be of equal length!"));

    char result[len];
    for(size_t i=0; i < len; i++) {
        result[i] = str1[i] ^ str2[i];
    }

    return std::string(result, len);
}

/**
 * Generates an RFC 5802, §5.1, nonce suitable for use in an 'r' attribute.
 */
static std::string scram_generate_nonce()
{
    int len = 10 + rand() % 32;
    std::string nonce(len, ' ');

    for(int i=0; i < len; i++) {
        nonce[i] = '!' + (rand() % ('~' - '!')); // Range as per RFC 5802, p. 16 on "printable"

        // ',' is a prohibited value in a nonce as per RFC 5802 §5.1(4th bullet),
        // so try again if that once was found.
        if (nonce[i] == ',') {
            i--;
        }
    }

    return nonce;
}

/**
 * This function quotes user names for use in SASL SCRAM auth
 * as per RFC 5802, §5.1(3)(2nd point)(5), i.e. it replaces
 * the chars "," and "=" with escape sequences.
 *
 * Does not modify its argument, instead returns the
 * modified version of the username string.
 */
static std::string scram_quote_username(std::string username)
{
    strgsub(username, "=", "=3D");
    strgsub(username, ",", "=2C");
    return username;
}


/**
 * This function parses the SCRAM messages (challenges),
 * which come as comma-separated key-value pairs into a hashmap.
 *
 * RFC 5802, §5(1).
 */
static std::map<std::string, std::string> scram_parse_challenge(const std::string& challenge)
{
    std::map<std::string, std::string> result;
    std::string key;
    std::string value;
    bool in_key = true;

    for(const char& byte: challenge) {
        if (byte == '=' && in_key) // Nonce ('r') may include '=' in its value
            in_key = false;
        else if (byte == ',') {
            result[key] = value;
            key.clear();
            value.clear();
            in_key = true;
        }
        else if (in_key)
            key.append(1, byte);
        else
            value.append(1, byte);
    }

    // Process last key-value pair
    result[key] = value;

    return result;
}

/**
 * This implements SCRAM's Hi() function as per RFC 5802, §2.2(8th point).
 * The return value is a binary blob (*not* hex-encoded for printability).
 *
 * Since RFC 5802, §2.2 a.e. explains that Hi() is actually PBKDF2, this
 * function just uses OpenSSL's PBKDF2 function rather than calculating
 * this itself.
 *
 * It supports SHA1 and SHA256 as hash algorithms.
 */
static std::string scram_hi(hashalgo algorithm, std::string str, std::string salt, int i)
{
    const EVP_MD* p_hashfunc = NULL;

    switch(algorithm) {
    case hashalgo::SHA1:
        p_hashfunc = EVP_sha1();
        break;
    case hashalgo::SHA256:
        p_hashfunc = EVP_sha256();
        break;
    default:
        throw(std::invalid_argument("Unsupported hash function for scram_hi()"));
    }

    int keylen = EVP_MD_size(p_hashfunc); // e.g., 20 for SHA1, see RFC 5802, p. 6f.
    char buf[keylen];

    PKCS5_PBKDF2_HMAC(str.c_str(),
                      str.length(),
                      (unsigned char*) salt.c_str(),
                      salt.length(),
                      i,
                      p_hashfunc,
                      keylen,
                      (unsigned char*) buf);

    return std::string(buf, keylen);
    /*
    std::string u = salt + "\000\000\000\001"; // Hope I got the INT(1) from RFC 5802, §2.2(8th point) right
    std::string hi;
    for(int j=0; j < i; j++) {
        u = hmac(algorithm, str, u);

        if (hi.empty())
            hi = u;
        else
            hi = strxor(hi, u);
    }

    return hi;
    */
}

/**
 * This method does the computations outlined in RFC 5802, §3.
 * It returns the client proof and server signature.
 */
static void scram_compute(hashalgo algo,
                          const std::string& password,
                          const std::string& salt,
                          int iterations,
                          const std::string& client_first_message_bare,
                          const std::string& server_first_message,
                          const std::string& client_final_message_without_proof,
                          std::string& client_proof,
                          std::string& server_signature)
{
    std::string salted_password = scram_hi(algo, password, salt, iterations); // TODO: Normalize()
    std::string client_key = hmac(algo, salted_password, "Client Key");
    std::string stored_key = digest_hash(algo, client_key);
    std::string auth_message = client_first_message_bare + "," +
        server_first_message + "," +
        client_final_message_without_proof;
    std::string client_signature = hmac(algo, stored_key, auth_message);
    client_proof = strxor(client_key, client_signature);

    std::string server_key = hmac(algo, salted_password, "Server Key");
    server_signature = hmac(algo, server_key, auth_message);
}

/******************** Sasl class ********************/

/**
 * Returns the sasl_mech enum identifier for the given string representation
 * of a SASL mechanism (so for "EXTERNAL" sasl_mech::SASL_EXTERNAL is returned)
 * Case does not matter; the parameter is downcased automatically.
 */
sasl_mech Sasl::str2saslmech(std::string mechanism_name)
{
    lowercase(mechanism_name);

    if (mechanism_name == "anonymous")
        return sasl_mech::SASL_ANONYMOUS;
    else if (mechanism_name == "plain")
        return sasl_mech::SASL_PLAIN;
    else if (mechanism_name == "digest-md5")
        return sasl_mech::SASL_DIGEST_MD5;
    else if (mechanism_name == "scram-sha-1")
        return sasl_mech::SASL_SCRAM_SHA1;
    else if (mechanism_name == "scram-sha-256")
        return sasl_mech::SASL_SCRAM_SHA256;
    else if (mechanism_name == "external")
        return sasl_mech::SASL_EXTERNAL;
    else
        return sasl_mech::SASL_UNKNOWN;
}

/**
 * Inverse of str2saslmech, except that it returns the empty string
 * if you pass SASL_UNKNOWN as the mechanism.
 */
std::string Sasl::saslmech2str(sasl_mech mech)
{
    switch (mech) {
    case sasl_mech::SASL_UNKNOWN:
        return ""; // Invalid input
    case sasl_mech::SASL_ANONYMOUS:
        return "ANONYMOUS";
    case sasl_mech::SASL_PLAIN:
        return "PLAIN";
    case sasl_mech::SASL_DIGEST_MD5:
        return "DIGEST-MD5";
    case sasl_mech::SASL_SCRAM_SHA1:
        return "SCRAM-SHA-1";
    case sasl_mech::SASL_SCRAM_SHA256:
        return "SCRAM-SHA-256";
    case sasl_mech::SASL_EXTERNAL:
        return "EXTERNAL";
    // No default clause so the compiler can warn about missing values
    }

    // Not reached; only to make compiler happy
    return "";
}

/**
 * Returns the list of SASL mechanisms supported by this library.
 * The returned vector is in the order in which the SASL mechanisms
 * are to be preferred (RFC 6120, §6.3.3).
 */
std::vector<sasl_mech> Sasl::supported_mechanisms()
{
    std::vector<sasl_mech> result;

    result.push_back(sasl_mech::SASL_SCRAM_SHA256);
    result.push_back(sasl_mech::SASL_SCRAM_SHA1);
    //result.push_back(sasl_mech::SASL_DIGEST_MD5);
    result.push_back(sasl_mech::SASL_PLAIN);
    return result;
}

/**
 * Construct a new Sasl instance.
 *
 * \param[in] authcid
 * The RFC 4422 §2(Nr.1) authentication identity, colloquially known
 * as the "username". If you ever manually configured an email client,
 * you know the conceptual difference between email address and
 * username to use on the SMTP/POP/IMAP server; the idea is the
 * same here. This parameter is ignored if the mechanism choice
 * results in the EXTERNAL mechanism to be used.
 *
 * \param[in] password
 * Your password, which will be used in answering the server's challenges.
 * This class does not support SASL mechanisms which are based on
 * things other than passwords. This parameter is ignored if
 * the mechanism choice results in the EXTERNAL mechanism to be
 * used.
 *
 * \param[in] authzid
 * The RFC 4422 §2(Nr.2) authorization identity. You use this when you
 * want to impersonate another user; if you leave it empty (default),
 * you indicate you just want to act as yourself (which is in 95% of
 * the cases what you want).
 */
Sasl::Sasl(const std::string& authcid, const std::string& password, const std::string& authzid)
    : m_chosen_mechanism(sasl_mech::SASL_UNKNOWN),
      m_authcid(authcid),
      m_authzid(authzid),
      m_password(password),
      m_step(STEP_INITIAL_RESPONSE)
{
}

/**
 * This method chooses the strongest SASL authentication
 * method supported both my this programme and the server.
 *
 * \param[in] servers_machanisms
 * The list of SASL mechanisms the server has handed to you.
 *
 * \returns The chosen SASL mechanism. If that is
 * sasl_mech::SASL_UNKNOWN, then no common SASL mechanisms could be
 * found.
 */
sasl_mech Sasl::choose_mechanism(const std::vector<sasl_mech>& servers_mechanisms)
{
    for(sasl_mech cm: supported_mechanisms()) {
        if (std::find(servers_mechanisms.begin(), servers_mechanisms.end(), cm) != servers_mechanisms.end()) {
            m_chosen_mechanism = cm;
            break; // First found mechanism has highest priority, RFC 6120, §6.3.3.
        }
    }

    return m_chosen_mechanism;
}

/**
 * Generate a response to the challenge the server sent to you.
 *
 * \param[in] challenge
 * This parameter specifies the challenge as sent to
 * you by the server (please decode it from any transfer
 * encoding used in the protocol below (such as base64 in
 * case of XMPP) prior to handing it here. For an initial
 * response in a client-first mechanism, you set this to
 * an empty string.
 *
 * \param[out] msg
 *  The response you need to encode in some protocol-specific
 * mannor (in case of XMPP, base64) and then send it to the server.
 *
 * \returns Whether or not the challenge was valid. If you get
 * a false result, this means the connection has been tempered
 * with or the server experienced an error and you should refrain
 * from further use of the connection.
 *
 * \remark It is not this method's job to tell you when the
 * authentication exchange is complete. This is protocol-specific,
 * and in case of XMPP this happens when the server sends you
 * a <success/> element (RFC 6120, §6.4.6).
 */
bool Sasl::response(const std::string& challenge, std::string& msg)
{
    msg.clear();

    switch (m_chosen_mechanism) {
    case sasl_mech::SASL_PLAIN: // SASL PLAIN auth; RFC 4616
        if (!m_authzid.empty())
            msg += m_authzid;

        msg += std::string("\0", 1) + m_authcid + std::string("\0", 1) + m_password;
        break;
    case sasl_mech::SASL_SCRAM_SHA1: // SASL SCRAM with SHA1, RFC 5802
        return scram_response(hashalgo::SHA1, challenge, msg);
        break;
    case sasl_mech::SASL_SCRAM_SHA256: // SASL SCRAM with SHA256, RFC 7677
        return scram_response(hashalgo::SHA256, challenge, msg);
        break;
    case sasl_mech::SASL_EXTERNAL: // SASL EXTERNAL auth; RFC 4422, Appendix A.
        /* The EXTERNAL machanism doesn't transfer authcids; it
         * assumes that has already been negotiated elsewhere (e.g.,
         * by means of a TLS client certificate). It only transfers
         * the authzid, and that only optionally (if left out, it
         * should be an empty string). See RFC 4422, Appendix A.1. */
        msg = m_authzid;
        break;
    case sasl_mech::SASL_ANONYMOUS: // SASL ANONYMOUS, RFC 4505
        // ANONYMOUS does not require any data. Trace information
        // is optional per RFC 4505, §2, and not supported by this class.
        return "";
        break;
    case sasl_mech::SASL_UNKNOWN: // Unimplemented mechanism
        return "";
    // No default so the compiler can warn about missing values
    }

    return true;
}

bool Sasl::scram_response(hashalgo algo, const std::string& challenge, std::string& msg)
{
    if (m_step == STEP_INITIAL_RESPONSE) { // Initial response
        // Unused manadtory extension, RFC 5802, p. 17
        // m_scram_client_first_message_bare += "m=" + "..." + ","

        // username, RFC 5802, p. 17
        m_scram_client_first_message_bare = "n=" + scram_quote_username(m_authcid) + ","; // TODO: Normalize()

        // Nonce, RFC 5802, p. 17
        m_scram_client_nonce = scram_generate_nonce();
        m_scram_client_first_message_bare += "r=" + m_scram_client_nonce;

        // Unused further extensions, RFC 5802, p. 17
        // m_scram_client_first_message_bare += "," + "..."

        /* GS2 header (RFC 5802, p. 17). RFC 5802, §4 p. 9 declares
         * only SCRAM-SHA1 as a MUST requirement and makes it clear in
         * §6 that there may well be clients that do not support
         * channel binding, thus do not implement
         * SCRAM-SHA-1-PLUS. That is, to conform to RFC 5802,
         * supporting channel binding and SCRAM-SHA1-PLUS is not
         * required. I was unable to comprehend what it actually is
         * and trying to figure it out yielded a wealth of further
         * RFCs I had neither time nor fun reading, I do not support
         * channel binding here, period. Use TLS if you need
         * encryption. Thus, the below line hardcodes the GS2 header
         * to "Client does not support channel binding" as allowed and
         * defined by RFC 5802, §6(4th bullet). */
        m_scram_gs2_header = "n,";

        // Authorization ID (part of GS2 header), RFC 5802, §7 p. 17
        if (!m_authzid.empty())
            m_scram_gs2_header += "a=" + scram_quote_username(m_authzid); // TODO: Normalize()
        m_scram_gs2_header += ",";

        // client-first-message-bare, RFC 5802, p. 17
        std::string client_first_message;
        client_first_message = m_scram_gs2_header + m_scram_client_first_message_bare;

        m_step = SCRAM_STEP_1;
        msg = client_first_message;
    }
    else if (m_step == SCRAM_STEP_1) {
        std::map<std::string, std::string> attrs = scram_parse_challenge(challenge);

        // Check server sent back this programme's nonce; RFC 5802, §5.1 p. 12
        if (attrs["r"].substr(0, m_scram_client_nonce.length()) != m_scram_client_nonce) {
            // Nonce mismatch. Someone is tampering with the connection.
            return false;
        }

        std::string full_nonce = attrs["r"];
        std::string salt       = base64_decode(attrs["s"]);
        int iterations         = std::stoi(attrs["i"]);

        // Check for protocol violations
        if (salt.empty())
            return false;
        if (iterations <= 0)
            return false;

        std::string client_final_message_without_proof;
        // channel-binding (since channel binding is not supported, no cbind-data included)
        // RFC 5802, p. 18f.
        client_final_message_without_proof = "c=" + base64_encode(m_scram_gs2_header) + ",";

        // full nonce (= m_scram_client_nonce + server nonce)
        client_final_message_without_proof += "r=" + full_nonce;

        // Unused extensions, RFC 5802, p. 18
        // client_final_message_without_proof += "," + "...";

        // Calculate client proof and server signature, RFC 5802, §3.
        std::string proof;
        scram_compute(algo,
                      m_password,
                      salt,
                      iterations,
                      m_scram_client_first_message_bare,
                      challenge,
                      client_final_message_without_proof,
                      proof,
                      m_scram_server_signature);

        std::string client_final_message;
        // client-final-message-without-proof, RFC 5802, p.18
        client_final_message = client_final_message_without_proof + ",";
        // proof, RFC 5802, p. 18
        client_final_message += "p=" + base64_encode(proof);

        m_step = STEP_ADDITIONAL_DATA_WITH_SUCCESS;
        msg = client_final_message;
    }
    else if (m_step == STEP_ADDITIONAL_DATA_WITH_SUCCESS) {
        std::map<std::string, std::string> attrs = scram_parse_challenge(challenge);

        if (!attrs["e"].empty()) {
            // server error
            return false;
        }

        std::string received_server_signature = base64_decode(attrs["v"]);

        if (received_server_signature != m_scram_server_signature) {
            // Someone is tampering with the connection
            return false;
        }

        // Auth is okay at this point
        m_step = STEP_INITIAL_RESPONSE;
    }

    return true;
}
