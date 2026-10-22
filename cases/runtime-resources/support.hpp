#pragma once
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace resources {
using Bytes = std::vector<unsigned char>;
using View = std::span<const unsigned char>;
using Hash = std::array<unsigned char, 32>;
namespace fs = std::filesystem;
constexpr size_t limit = 4 * 1024 * 1024;
void require(bool ok, const char* code);
void wipe(Bytes& bytes);
struct WipeGuard {
    Bytes& value;
    bool active = true;
    ~WipeGuard() { if (active) wipe(value); }
};
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE handle) : value(handle) {}
    ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
};
Bytes read_file(const fs::path& path, size_t maximum = limit);
void write_file(const fs::path& path, View bytes, bool exclusive = false);
void publish(const fs::path& path, View bytes);
void reject_reparse(const fs::path& path);
Hash sha256(View bytes);
std::string hex(View bytes);
Bytes random_bytes(size_t size);
void append(Bytes& to, View from);
void text(Bytes& to, std::string_view from);
void u32(Bytes& to, uint32_t value);
uint32_t take_u32(View bytes, size_t& position);
View take(View bytes, size_t& position, size_t count);
bool logical_name(std::string_view name);
Bytes manifest(const fs::path& root, const std::vector<std::string>& names);
struct Entry { std::string_view name; View content; };
struct ResourceSet {
    Bytes plaintext;
    std::vector<Entry> entries;
    explicit ResourceSet(Bytes data);
    ResourceSet(const ResourceSet&) = delete;
    ResourceSet& operator=(const ResourceSet&) = delete;
    ~ResourceSet() { wipe(plaintext); }
    View get(std::string_view name) const;
};
struct Cipher { Bytes ciphertext; std::array<unsigned char, 16> tag{}; };
Cipher encrypt(View key, View nonce, View aad, View plaintext);
Bytes decrypt(View key, View nonce, View aad, View ciphertext, View tag);
Bytes envelope(View key, View nonce, View plaintext);
Bytes open_envelope(View key, View bundle);
std::vector<std::string> inventory(const fs::path& root);
fs::path executable();
} // namespace resources
