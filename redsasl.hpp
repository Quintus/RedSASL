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

#ifndef REDSASL_SASL_HPP
#define REDSASL_SASL_HPP
#include <vector>
#include <string>

namespace Redsasl {

    /**
     * Constants used to identify different SASL mechanisms.
     */
    enum class sasl_mech {
        SASL_UNKNOWN,
        SASL_ANONYMOUS,
        SASL_PLAIN,
        SASL_DIGEST_MD5,
        SASL_SCRAM_SHA1,
        SASL_SCRAM_SHA256,
        SASL_EXTERNAL
    };

    /**
     * Supported hash algorithms.
     */
    enum class hashalgo {
        MD5,
        SHA1,
        SHA256
    };

    /**
     * Implementation of RFC 4422 (Simple Authentication and Security
     * Layer -- SASL), which is, despite its name, not simple. That
     * is, if one wants to support more than PLAIN auth. As of now,
     * this class only supports PLAIN, EXTERNAL, and SCRAM-SHA1 auth.
     *
     * An authentication exchange as per RFC 4422 works like this
     * (paraphrasing RFC 4422, §3).
     *
     * 1. Request server's supported SASL mechanisms.
     *    This is protocol-specific.
     * 2. Tell the server the chosen SASL mechanism.
     *    This is protocol-specific.
     * 3. If you chose a client-first mechanism, you can
     *    optionally (but recommended to save bandwidth)
     *    include an "initial response" in the same Auth
     *    message. This is shown for XMPP in RFC 6120, §6.4.2.
     * 4. The server replies with a challenge, if the SASL
     *    mechanism requires one, otherwise it tells you
     *    success or failure of the authentication exchange
     *    (in that case, go to 7).
     * 5. You reply with a response to the challenge.
     * 6. Go to 4.
     * 7. Authentication exchange is complete.
     *
     * If you don't include the optional "initial response" in
     * step 3 for a client-first mechanism, the server will
     * reply with an empty challenge (thus you can continue just
     * as usual in the above step list).
     *
     * Translated to method calls on an instance of this class,
     * this means:
     *
     * 1. (none, you receive the mechanisms outside of this class)
     * 2. Sasl::choose_mechanism()
     * 3. Sasl::response()
     * 4. (nothing, you receive the challenge outside of this class)
     * 5. Sasl::response()
     * 6. Go to 4.
     * 7. (none, you receive an Auth stanza which is Auth::successful())
     */
    class Sasl
    {
    public:
        Sasl(const std::string& authcid, const std::string& password, const std::string& authzid = "");

        sasl_mech choose_mechanism(const std::vector<sasl_mech>& servers_mechanisms);
        bool response(const std::string& challenge, std::string& msg);

        /// Returns the authentication id ("username" credentials are provided for)
        inline std::string get_authcid() const { return m_authcid; }
        /// Returns the authorization id ("username" you want to impersonate); usually empty string
        /// (i.e. no impersonation).
        inline std::string get_authzid() const { return m_authzid; }
        /// Returns the cleartext password.
        inline std::string get_password() const { return m_password; }

        static std::vector<sasl_mech> supported_mechanisms();
        static sasl_mech str2saslmech(std::string mechanism_name);
        static std::string saslmech2str(sasl_mech mech);
    private:
        bool scram_response(hashalgo algo, const std::string& challenge, std::string& msg);
        sasl_mech m_chosen_mechanism;
        std::string m_authcid;
        std::string m_authzid;
        std::string m_password;
        std::string m_nonce;
        int m_step;

        // These are used during SCRAM auth (RFC 5802)
        std::string m_scram_gs2_header;
        std::string m_scram_client_nonce;
        std::string m_scram_client_first_message_bare;
        std::string m_scram_server_signature;
    };

}

#endif /* REDSASL_SASL_HPP */
