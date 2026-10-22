#include "support.hpp"
#include <algorithm>
#include <iostream>
#include <sstream>

using namespace resources;

static Bytes reserve_key_nonce(const fs::path& path) {
    reject_reparse(path);
    HANDLE raw = INVALID_HANDLE_VALUE;
    for (int retry = 0; retry < 100; ++retry) {
        raw = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                          OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (raw != INVALID_HANDLE_VALUE || GetLastError() != ERROR_SHARING_VIOLATION) break;
        Sleep(50);
    }
    Handle file(raw);
    require(raw != INVALID_HANDLE_VALUE, "key-open");
    BY_HANDLE_FILE_INFORMATION info{};
    require(GetFileInformationByHandle(raw, &info) && !(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT), "key-type");
    LARGE_INTEGER size{};
    require(GetFileSizeEx(raw, &size) && size.QuadPart == 80, "key-format");
    Bytes state(80);
    WipeGuard guard{state};
    DWORD done = 0;
    require(ReadFile(raw, state.data(), 80, &done, nullptr) && done == 80, "key-read");
    require(std::string_view(reinterpret_cast<const char*>(state.data()), 4) == "ARK2", "key-format");
    auto checksum = sha256(View(state).first(48));
    require(std::equal(checksum.begin(), checksum.end(), state.begin() + 48), "key-checksum");
    uint64_t counter = 0;
    for (int i = 0; i < 8; ++i) counter |= uint64_t(state[40 + i]) << (8 * i);
    require(counter < (uint64_t{1} << 20), "nonce-exhausted");
    ++counter;
    for (int i = 0; i < 8; ++i) state[40 + i] = static_cast<unsigned char>(counter >> (8 * i));
    checksum = sha256(View(state).first(48));
    std::copy(checksum.begin(), checksum.end(), state.begin() + 48);
    LARGE_INTEGER start{};
    require(SetFilePointerEx(raw, start, nullptr, FILE_BEGIN) &&
            WriteFile(raw, state.data(), 80, &done, nullptr) && done == 80 && FlushFileBuffers(raw), "nonce-persist");
    guard.active = false;
    return state;
}

static void seal(const fs::path& key_file, Bytes plaintext, const fs::path& bundle_file,
                 const fs::path& header_file = {}) {
    Bytes state;
    try {
        state = reserve_key_nonce(key_file);
        View key(state.data() + 4, 32), nonce(state.data() + 36, 12);
        auto bundle = envelope(key, nonce, plaintext);
        publish(bundle_file, bundle);
        if (!header_file.empty()) {
            std::ostringstream header;
            header << "#pragma once\n#include <array>\ninline constexpr std::array<unsigned char,32> resource_key={";
            for (auto value : key) header << unsigned(value) << ',';
            header << "};\ninline constexpr std::array<unsigned char," << bundle.size() << "> resource_bundle={";
            for (auto value : bundle) header << unsigned(value) << ',';
            header << "};\n";
            auto content = header.str();
            publish(header_file, View(reinterpret_cast<const unsigned char*>(content.data()), content.size()));
            SecureZeroMemory(content.data(), content.size());
        }
        wipe(state); wipe(plaintext);
    } catch (...) { wipe(state); wipe(plaintext); throw; }
}

static void selftest() {
    Bytes key(32), nonce(12), input(16);
    auto cipher = encrypt(key, nonce, {}, input);
    require(hex(cipher.ciphertext) == "cea7403d4d606b6e074ec5d3baf39d18" &&
            hex(cipher.tag) == "d0d1c8a799996bf0265b98b5d48ab919", "gcm-known-vector");
    require(decrypt(key, nonce, {}, cipher.ciphertext, cipher.tag) == input, "gcm-roundtrip");
    key[0] = 1;
    bool rejected = false;
    try { auto provisional = decrypt(key, nonce, {}, cipher.ciphertext, cipher.tag); wipe(provisional); }
    catch (const std::runtime_error&) { rejected = true; }
    require(rejected, "gcm-wrong-key");
    key[0] = 0;
    nonce[0] = 1;
    Bytes aad{1, 2, 3};
    cipher = encrypt(key, nonce, aad, input);
    aad[0] ^= 1;
    rejected = false;
    try { auto provisional = decrypt(key, nonce, aad, cipher.ciphertext, cipher.tag); wipe(provisional); }
    catch (const std::runtime_error&) { rejected = true; }
    require(rejected, "gcm-aad");
    std::cout << "{\"known_vector\":true,\"roundtrip\":true,\"wrong_key_rejected\":true,\"aad_rejected\":true}\n";
}

int wmain(int argc, wchar_t** argv) {
    try {
        require(argc >= 2, "usage");
        std::wstring command = argv[1];
        if (command == L"selftest" && argc == 2) { selftest(); return 0; }
        if (command == L"keygen" && argc == 3) {
            Bytes state; text(state, "ARK2"); append(state, random_bytes(36));
            state.resize(48, 0);
            append(state, sha256(state));
            try { write_file(argv[2], state, true); } catch (...) { wipe(state); throw; }
            wipe(state);
        } else if (command == L"pack" && argc == 7) {
            auto list_bytes = read_file(argv[3], 32768);
            std::string list(reinterpret_cast<const char*>(list_bytes.data()), list_bytes.size());
            std::istringstream lines(list);
            std::vector<std::string> names;
            std::string name;
            while (std::getline(lines, name)) { if (!name.empty() && name.back() == '\r') name.pop_back(); if (!name.empty()) names.push_back(name); }
            require(names == inventory(argv[2]), "inventory-mismatch");
            seal(argv[4], manifest(argv[2], names), argv[6], argv[5]);
        } else if (command == L"seal" && argc == 5) {
            // Acceptance fixtures use this build-only command for authenticated malformed manifests.
            seal(argv[3], read_file(argv[2]), argv[4]);
        } else { throw std::runtime_error("usage"); }
        std::cout << "{\"status\":\"ok\"}\n";
        return 0;
    } catch (const fs::filesystem_error&) {
        std::cerr << "ERROR filesystem\n"; return 2;
    } catch (const std::exception& error) {
        std::cerr << "ERROR " << error.what() << '\n'; return 2;
    }
}
