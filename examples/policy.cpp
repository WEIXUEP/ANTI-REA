#include "engine.hpp"
#include "obfuscation.hpp"
#include <iostream>

AR_CONTROL std::uint32_t policy_dispatch(std::uint32_t value) {
    switch (value & 3u) {
    case 0:
        return (value * 17u) ^ 0xa341316cu;
    case 1:
        return (value + 0xc8013ea4u) ^ (value >> 3);
    case 2:
        return (value ^ 0xad90777du) + (value << 5);
    default:
        return (value * 31u) + 0x7e95761eu;
    }
}
AR_TOKEN std::uint32_t policy_token(std::uint32_t value) {
    return ((value ^ 0x5a827999u) * 33u) + (value >> 7);
}
void print_rtti() {
    using namespace aegis::internal;
    Storage<ResonantKernel> object;
    auto local_callback = [&object] { return object.value.evaluate(); };
    std::cout << typeid(object).name() << '\n' << typeid(local_callback).name() << '\n';
    // A runtime-decrypted ordinary string is not equivalent to a sealed diagnostic.
    std::cout << "Internal dispatch schedule uses a calibrated branch table" << '\n';
}
const std::type_info& peer_type(unsigned kind) {
    using namespace aegis::internal;
    return kind == 0 ? typeid(ResonantKernel) : typeid(third_party::Box<ResonantKernel>);
}
