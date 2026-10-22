#include "support.hpp"
#include <algorithm>
#include <cstring>

namespace resources {
void require(bool ok, const char* code) { if (!ok) throw std::runtime_error(code); }
void wipe(Bytes& bytes) { if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size()); }
void append(Bytes& to, View from) { to.insert(to.end(), from.begin(), from.end()); }
void text(Bytes& to, std::string_view from) {
    append(to, View(reinterpret_cast<const unsigned char*>(from.data()), from.size()));
}
void u32(Bytes& to, uint32_t value) {
    for (int i = 0; i < 4; ++i) to.push_back(static_cast<unsigned char>(value >> (i * 8)));
}
View take(View bytes, size_t& position, size_t count) {
    require(position <= bytes.size() && count <= bytes.size() - position, "format-bounds");
    auto result = bytes.subspan(position, count);
    position += count;
    return result;
}
uint32_t take_u32(View bytes, size_t& position) {
    auto value = take(bytes, position, 4);
    return uint32_t(value[0]) | uint32_t(value[1]) << 8 | uint32_t(value[2]) << 16 | uint32_t(value[3]) << 24;
}
void reject_reparse(const fs::path& path) {
    fs::path current;
    for (const auto& part : fs::absolute(path)) {
        current /= part;
        DWORD attributes = GetFileAttributesW(current.c_str());
        require(attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_REPARSE_POINT), "reparse-path");
    }
}
Bytes read_file(const fs::path& path, size_t maximum) {
    reject_reparse(path);
    Handle file(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    require(file.value != INVALID_HANDLE_VALUE, "file-read");
    BY_HANDLE_FILE_INFORMATION info{};
    require(GetFileInformationByHandle(file.value, &info) && !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "file-type");
    LARGE_INTEGER size{};
    require(GetFileSizeEx(file.value, &size) && size.QuadPart >= 0 &&
            static_cast<uint64_t>(size.QuadPart) <= maximum, "file-size");
    Bytes bytes(static_cast<size_t>(size.QuadPart));
    WipeGuard guard{bytes};
    DWORD done = 0;
    require(bytes.empty() || (ReadFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()), &done, nullptr)
            && done == bytes.size()), "file-read");
    guard.active = false;
    return bytes;
}
void write_file(const fs::path& path, View bytes, bool exclusive) {
    reject_reparse(path);
    Handle file(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            exclusive ? CREATE_NEW : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    require(file.value != INVALID_HANDLE_VALUE, "file-write");
    DWORD done = 0;
    require(WriteFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()), &done, nullptr)
            && done == bytes.size() && FlushFileBuffers(file.value), "file-write");
}
void publish(const fs::path& path, View bytes) {
    reject_reparse(path);
    fs::path temporary = path.parent_path() / (L".resource-" + fs::path(hex(random_bytes(16))).wstring() + L".tmp");
    bool owned = false;
    try {
        write_file(temporary, bytes, true);
        owned = true;
        require(MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH), "file-publish");
    } catch (...) {
        if (owned) { std::error_code error; fs::remove(temporary, error); }
        throw;
    }
}
struct Algorithm {
    BCRYPT_ALG_HANDLE value = nullptr;
    explicit Algorithm(LPCWSTR name) { require(BCryptOpenAlgorithmProvider(&value, name, nullptr, 0) >= 0, "crypto-provider"); }
    ~Algorithm() { if (value) BCryptCloseAlgorithmProvider(value, 0); }
};
Hash sha256(View bytes) {
    Algorithm algorithm(BCRYPT_SHA256_ALGORITHM);
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD object_size = 0, result_size = 0;
    require(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size), &result_size, 0) >= 0, "crypto-hash");
    Bytes object(object_size);
    require(BCryptCreateHash(algorithm.value, &hash, object.data(), object_size, nullptr, 0, 0) >= 0, "crypto-hash");
    Hash result{};
    NTSTATUS status = BCryptHashData(hash, const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0);
    if (status >= 0) status = BCryptFinishHash(hash, result.data(), static_cast<ULONG>(result.size()), 0);
    BCryptDestroyHash(hash);
    require(status >= 0, "crypto-hash");
    return result;
}
std::string hex(View bytes) {
    const char* alphabet = "0123456789abcdef";
    std::string result;
    for (auto value : bytes) { result += alphabet[value >> 4]; result += alphabet[value & 15]; }
    return result;
}
Bytes random_bytes(size_t size) {
    Bytes bytes(size);
    require(BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0, "crypto-random");
    return bytes;
}
static Bytes gcm(bool sealing, View key, View nonce, View aad, View input, std::array<unsigned char, 16>& tag) {
    require(key.size() == 32 && nonce.size() == 12 && input.size() <= limit, "crypto-size");
    Algorithm algorithm(BCRYPT_AES_ALGORITHM);
    require(BCryptSetProperty(algorithm.value, BCRYPT_CHAINING_MODE,
            reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_GCM)), sizeof(BCRYPT_CHAIN_MODE_GCM), 0) >= 0, "crypto-mode");
    DWORD object_size = 0, result_size = 0;
    require(BCryptGetProperty(algorithm.value, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size), &result_size, 0) >= 0, "crypto-key");
    Bytes object(object_size);
    WipeGuard object_guard{object};
    BCRYPT_KEY_HANDLE handle = nullptr;
    require(BCryptGenerateSymmetricKey(algorithm.value, &handle, object.data(), object_size,
            const_cast<PUCHAR>(key.data()), 32, 0) >= 0, "crypto-key");
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
    BCRYPT_INIT_AUTH_MODE_INFO(auth);
    auth.pbNonce = const_cast<PUCHAR>(nonce.data()); auth.cbNonce = 12;
    auth.pbAuthData = const_cast<PUCHAR>(aad.data()); auth.cbAuthData = static_cast<ULONG>(aad.size());
    auth.pbTag = tag.data(); auth.cbTag = 16;
    Bytes output(input.size());
    ULONG written = 0;
    NTSTATUS status = sealing
        ? BCryptEncrypt(handle, const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()), &auth,
                        nullptr, 0, output.data(), static_cast<ULONG>(output.size()), &written, 0)
        : BCryptDecrypt(handle, const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()), &auth,
                        nullptr, 0, output.data(), static_cast<ULONG>(output.size()), &written, 0);
    BCryptDestroyKey(handle);
    wipe(object);
    if (status < 0 || written != input.size()) { wipe(output); throw std::runtime_error("resource-auth"); }
    return output;
}
Cipher encrypt(View key, View nonce, View aad, View plaintext) {
    Cipher result; result.ciphertext = gcm(true, key, nonce, aad, plaintext, result.tag); return result;
}
Bytes decrypt(View key, View nonce, View aad, View ciphertext, View tag) {
    require(tag.size() == 16, "resource-auth");
    std::array<unsigned char, 16> copy{};
    std::copy(tag.begin(), tag.end(), copy.begin());
    return gcm(false, key, nonce, aad, ciphertext, copy);
}
Bytes envelope(View key, View nonce, View plaintext) {
    require(plaintext.size() <= limit, "bundle-size");
    Bytes header; text(header, "ARRES001"); u32(header, 1); u32(header, 1);
    append(header, nonce); u32(header, static_cast<uint32_t>(plaintext.size())); append(header, sha256(key));
    auto sealed = encrypt(key, nonce, header, plaintext);
    append(header, sealed.ciphertext); append(header, sealed.tag); return header;
}
Bytes open_envelope(View key, View bundle) {
    require(bundle.size() >= 80 && bundle.size() <= limit + 80, "bundle-size");
    size_t position = 0;
    auto magic = take(bundle, position, 8);
    require(std::string_view(reinterpret_cast<const char*>(magic.data()), magic.size()) == "ARRES001", "bundle-format");
    require(take_u32(bundle, position) == 1 && take_u32(bundle, position) == 1, "bundle-version");
    auto nonce = take(bundle, position, 12);
    auto length = take_u32(bundle, position);
    auto identity = take(bundle, position, 32);
    auto expected = sha256(key);
    require(std::equal(identity.begin(), identity.end(), expected.begin()), "resource-key");
    require(length <= limit && bundle.size() - 80 == length, "bundle-length");
    return decrypt(key, nonce, bundle.first(64), bundle.subspan(64, length), bundle.last(16));
}
bool logical_name(std::string_view name) {
    if (name.empty() || name.size() > 200 || name.front() == '/' || name.back() == '/') return false;
    size_t position = 0;
    while (position < name.size()) {
        auto end = name.find('/', position);
        auto part = name.substr(position, end == name.npos ? name.size() - position : end - position);
        if (part.empty() || part == "." || part == ".." || part.back() == '.') return false;
        for (char c : part) if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '_' && c != '-' && c != '.') return false;
        if (end == name.npos) break;
        position = end + 1;
    }
    return true;
}
std::vector<std::string> inventory(const fs::path& root) {
    reject_reparse(root);
    std::vector<std::string> names;
    for (const auto& item : fs::recursive_directory_iterator(root)) {
        reject_reparse(item.path());
        if (item.is_regular_file()) names.push_back(item.path().lexically_relative(root).generic_string());
    }
    std::sort(names.begin(), names.end()); return names;
}
Bytes manifest(const fs::path& root, const std::vector<std::string>& names) {
    require(!names.empty() && names.size() <= 128, "resource-count");
    Bytes bytes; u32(bytes, static_cast<uint32_t>(names.size()));
    WipeGuard guard{bytes};
    std::string previous;
    for (const auto& name : names) {
        require(logical_name(name) && (previous.empty() || previous < name), "resource-name");
        auto content = read_file(root / fs::path(name), 1024 * 1024);
        u32(bytes, static_cast<uint32_t>(name.size())); text(bytes, name);
        u32(bytes, static_cast<uint32_t>(content.size())); append(bytes, content); wipe(content);
        require(bytes.size() <= limit, "manifest-size"); previous = name;
    }
    guard.active = false;
    return bytes;
}
ResourceSet::ResourceSet(Bytes data) : plaintext(std::move(data)) {
    try {
        require(plaintext.size() <= limit, "manifest-size");
        size_t position = 0;
        auto count = take_u32(plaintext, position);
        require(count > 0 && count <= 128, "resource-count");
        std::string_view previous;
        for (uint32_t i = 0; i < count; ++i) {
            auto name_size = take_u32(plaintext, position);
            require(name_size > 0 && name_size <= 200, "resource-name");
            auto raw_name = take(plaintext, position, name_size);
            std::string_view name(reinterpret_cast<const char*>(raw_name.data()), raw_name.size());
            require(logical_name(name) && (previous.empty() || previous < name), "resource-name");
            auto content_size = take_u32(plaintext, position);
            require(content_size <= 1024 * 1024, "resource-size");
            entries.push_back({name, take(plaintext, position, content_size)}); previous = name;
        }
        require(position == plaintext.size(), "manifest-trailing");
    } catch (...) { wipe(plaintext); throw; }
}
View ResourceSet::get(std::string_view name) const {
    for (const auto& entry : entries) if (entry.name == name) return entry.content;
    throw std::runtime_error("resource-missing");
}
fs::path executable() {
    std::wstring path(32768, L'\0');
    auto count = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    require(count && count < path.size(), "executable-path"); path.resize(count); return fs::path(path);
}
} // namespace resources
