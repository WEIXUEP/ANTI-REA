#include "diagnostics.hpp"
#if ANTI_REA_CODE_PROTECTION
#include <sodium.h>
#endif
#include <stdexcept>

namespace aegis {
#if ANTI_REA_CODE_PROTECTION
static std::string quote(const std::string& text) {
    std::string out = "\"";
    constexpr char hex[] = "0123456789abcdef";
    for (unsigned char c : text) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 32) {
            out += "\\u00";
            out += hex[c >> 4];
            out += hex[c & 15];
        } else {
            out += static_cast<char>(c);
        }
    }
    return out + '"';
}
#endif

void emit(const Site& site, const std::vector<std::string>& values) {
    std::cerr << site.kind << "\nDiagnostic ID: " << site.id << '\n';
#if ANTI_REA_CODE_PROTECTION
    std::cerr << "File: " << site.file << "\nLine: " << site.line << '\n';
    try {
        if (sodium_init() < 0) {
            throw std::runtime_error("Crypto unavailable");
        }
        std::string body = "{\"schema\":1,\"id\":" + quote(site.id) +
                           ",\"template\":" + quote(site.message) + ",\"fields\":[";
        for (std::size_t i = 0; i < values.size(); ++i) {
            if (i) {
                body += ',';
            }
            body += quote(values[i]);
        }
        body += "]}";
        std::vector<unsigned char> cipher(body.size() + crypto_box_SEALBYTES);
        if (crypto_box_seal(cipher.data(), reinterpret_cast<const unsigned char*>(body.data()),
                            body.size(), public_key) != 0) {
            throw std::runtime_error("Crypto unavailable");
        }
        std::vector<char> encoded(
            sodium_base64_ENCODED_LEN(cipher.size(), sodium_base64_VARIANT_ORIGINAL));
        sodium_bin2base64(encoded.data(), encoded.size(), cipher.data(), cipher.size(),
                          sodium_base64_VARIANT_ORIGINAL);
        std::cerr << "Payload: AR1:" << public_key_id << ':' << encoded.data() << '\n';
    } catch (...) {
        std::cerr << "Payload: <unavailable>\n";
    }
#else
    std::string message = site.message;
    for (const auto& value : values) {
        auto position = message.find("{}");
        if (position != std::string::npos) {
            message.replace(position, 2, value);
        }
    }
    std::cerr << message << "\nFile: " << site.file << "\nLine: " << site.line << '\n';
#endif
}
} // namespace aegis
