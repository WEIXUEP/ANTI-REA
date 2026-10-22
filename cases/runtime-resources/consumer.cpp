#include "support.hpp"
#if AR_ENCRYPT_RESOURCES
#include "resource_bundle.hpp"
#endif
#include <algorithm>
#include <charconv>
#include <chrono>
#include <iostream>
#include <memory>

using namespace resources;
using Clock = std::chrono::steady_clock;
constexpr uint32_t table_count = 32768;

static std::vector<std::string_view> lines(View data) {
    std::string_view input(reinterpret_cast<const char*>(data.data()), data.size());
    std::vector<std::string_view> result;
    while (!input.empty()) {
        auto end = input.find('\n');
        auto line = input.substr(0, end);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        result.push_back(line);
        if (end == input.npos) break;
        input.remove_prefix(end + 1);
    }
    return result;
}
static std::string_view field(std::string_view line, std::string_view prefix) {
    require(line.starts_with(prefix), "consumer-syntax"); return line.substr(prefix.size());
}
static uint32_t number(std::string_view input) {
    uint32_t result = 0;
    auto parsed = std::from_chars(input.data(), input.data() + input.size(), result);
    require(parsed.ec == std::errc{} && parsed.ptr == input.data() + input.size() && result <= 1000, "consumer-number");
    return result;
}
static std::string dependency(std::string_view parent, std::string_view line) {
    std::string name(field(line, "include "));
    require(logical_name(name), "consumer-include");
    std::string resolved = (fs::path(parent).parent_path() / name).generic_string();
    require(logical_name(resolved), "consumer-include"); return resolved;
}
struct Model { uint32_t bias, scale; std::array<uint32_t, 4> weights; };
static Model model(const ResourceSet& data) {
    auto root = lines(data.get("model.txt"));
    require(root.size() == 4 && root[0] == "model-v1", "consumer-model");
    require(!field(root[1], "label ").empty(), "consumer-label");
    auto coefficient_name = dependency("model.txt", root[2]);
    auto coefficients = lines(data.get(coefficient_name));
    require(coefficients.size() == 4 && coefficients[0] == "coefficients-v1", "consumer-coefficients");
    require(!field(coefficients[1], "label ").empty(), "consumer-label");
    auto weights = lines(data.get(dependency(coefficient_name, coefficients[2])));
    require(weights.size() == 3 && weights[0] == "weights-v1", "consumer-weights");
    require(!field(weights[1], "label ").empty(), "consumer-label");
    Model result{number(field(root[3], "bias ")), number(field(coefficients[3], "scale ")), {}};
    auto values = field(weights[2], "values ");
    for (size_t i = 0; i < 4; ++i) {
        auto end = values.find(' ');
        result.weights[i] = number(values.substr(0, end));
        if (i < 3) { require(end != values.npos, "consumer-weights"); values.remove_prefix(end + 1); }
        else require(end == values.npos, "consumer-weights");
    }
    return result;
}
static Bytes derive(const Model& input, uint32_t option) {
    Bytes output; output.reserve(table_count * 4);
    for (uint32_t i = 0; i < table_count; ++i) {
        uint32_t value = i + input.bias + option * input.scale;
        for (uint32_t round = 0; round < 128; ++round)
            value = (value * 1664525u + 1013904223u + input.weights[(i + round) % 4]) ^ (value >> 13);
        u32(output, value);
    }
    return output;
}
static fs::path default_cache() {
    std::wstring value(32768, L'\0');
    DWORD size = GetEnvironmentVariableW(L"LOCALAPPDATA", value.data(), static_cast<DWORD>(value.size()));
    require(size > 0 && size < value.size(), "cache-root"); value.resize(size);
    return fs::path(value) / L"ANTI-REA" / L"resource-demo" / L"v1";
}
static Bytes load_cache(const fs::path& file, const Hash& identity) {
    auto raw = read_file(file, 76 + table_count * 4);
    require(raw.size() == 76 + table_count * 4, "cache-size");
    size_t position = 0;
    auto magic = take(raw, position, 8);
    require(std::string_view(reinterpret_cast<const char*>(magic.data()), 8) == "ARCACHE1", "cache-format");
    auto key = take(raw, position, 32);
    require(std::equal(key.begin(), key.end(), identity.begin()), "cache-key");
    auto expected = take(raw, position, 32);
    require(take_u32(raw, position) == table_count * 4, "cache-size");
    auto payload = take(raw, position, table_count * 4);
    auto actual = sha256(payload);
    require(std::equal(actual.begin(), actual.end(), expected.begin()), "cache-hash");
    return Bytes(payload.begin(), payload.end());
}
static void store_cache(const fs::path& file, const Hash& identity, View payload) {
    reject_reparse(file.parent_path()); fs::create_directories(file.parent_path()); reject_reparse(file.parent_path());
    Bytes raw; text(raw, "ARCACHE1"); append(raw, identity); append(raw, sha256(payload));
    u32(raw, static_cast<uint32_t>(payload.size())); append(raw, payload); publish(file, raw);
}

int wmain(int argc, wchar_t** argv) {
    try {
        auto start = Clock::now();
        fs::path cache, bundle_override, external;
        bool disabled = false;
        uint32_t option = 1;
        for (int i = 1; i < argc; ++i) {
            std::wstring argument = argv[i];
            if (argument == L"--no-cache") { disabled = true; continue; }
            require(i + 1 < argc, "usage");
            if (argument == L"--cache-dir") cache = argv[++i];
            else if (argument == L"--bundle") bundle_override = argv[++i];
            else if (argument == L"--external-dir") external = argv[++i];
            else if (argument == L"--option") {
                std::wstring value = argv[++i];
                require(!value.empty() && value.find_first_not_of(L"0123456789") == value.npos && value.size() <= 2, "usage");
                option = static_cast<uint32_t>(std::stoul(value)); require(option > 0 && option <= 32, "usage");
            } else throw std::runtime_error("usage");
        }
        Bytes plaintext;
#if AR_ENCRYPT_RESOURCES
        auto bundle = bundle_override.empty() ? Bytes(resource_bundle.begin(), resource_bundle.end()) : read_file(bundle_override, limit + 80);
        plaintext = open_envelope(resource_key, bundle);
#else
        require(bundle_override.empty(), "bundle-unavailable");
        auto root = executable().parent_path() / L"resources";
        plaintext = manifest(root, inventory(root));
#endif
        // Authenticate the required bundle before allowing a cache hit or explicit external input.
        auto selected = std::make_unique<ResourceSet>(std::move(plaintext));
        if (!external.empty()) {
            selected = std::make_unique<ResourceSet>(manifest(external, inventory(external)));
        }
        auto input = model(*selected);
        Bytes identity_data; text(identity_data, "resource-cache-v1"); text(identity_data, AR_PRODUCER_ID);
        u32(identity_data, sizeof(void*)); u32(identity_data, option); append(identity_data, selected->plaintext);
        Hash identity = sha256(identity_data); wipe(identity_data);
        std::string cache_status = disabled ? "disabled" : "miss";
        Bytes payload;
        fs::path cache_file;
        if (!disabled) {
            try {
                if (cache.empty()) cache = default_cache();
                cache_file = cache / fs::path(hex(identity) + ".cache");
                try { payload = load_cache(cache_file, identity); cache_status = "hit"; }
                catch (const std::exception&) { payload.clear(); }
            } catch (const std::exception&) { cache_status = "unavailable"; }
        }
        auto derive_start = Clock::now();
        if (payload.empty()) payload = derive(input, option);
        auto derive_ms = std::chrono::duration<double, std::milli>(Clock::now() - derive_start).count();
        bool stored = false;
        if (!disabled && cache_status != "hit" && !cache_file.empty()) {
            try { store_cache(cache_file, identity, payload); stored = true; }
            catch (const std::exception&) { cache_status = "unavailable"; }
        }
        auto output_hash = sha256(payload);
        auto total_ms = std::chrono::duration<double, std::milli>(Clock::now() - start).count();
        std::cout << "{\"sha256\":\"" << hex(output_hash) << "\",\"cache_key\":\"" << hex(identity)
                  << "\",\"cache\":\"" << cache_status << "\",\"stored\":" << (stored ? "true" : "false")
                  << ",\"protected\":" << (AR_ENCRYPT_RESOURCES ? "true" : "false")
                  << ",\"external\":" << (!external.empty() ? "true" : "false")
                  << ",\"derive_ms\":" << derive_ms << ",\"total_ms\":" << total_ms << "}\n";
        return 0;
    } catch (const fs::filesystem_error&) {
        std::cerr << "ERROR filesystem\n"; return 2;
    } catch (const std::exception& error) {
        std::cerr << "ERROR " << error.what() << '\n'; return 2;
    }
}
