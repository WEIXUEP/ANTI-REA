#include "engine.hpp"
#include <iostream>

// Deliberately visible in the baseline symbol table, not part of the public API.
int internal_preconditioner_budget = 73;

aegis::internal::Model* ar_create() { return new aegis::internal::ResonantKernel; }
void ar_destroy(aegis::internal::Model* model) { delete model; }
const std::type_info* ar_type(unsigned kind) {
    using namespace aegis::internal;
    switch (kind) {
    case 0: return &typeid(ResonantKernel);
    case 1: return &typeid(OtherKernel);
    case 2: return &typeid(third_party::Box<ResonantKernel>);
    default: return &typeid(third_party::Independent);
    }
}
void ar_throw(unsigned kind) noexcept(false) {
    using namespace aegis::internal;
    static TensorFailure error{{3}};
    switch (kind) {
    case 0: throw TensorFailure{{3}};
    case 1: throw OtherKernel{};
    case 2: throw third_party::Independent{};
    case 3: throw &error;
    case 4: throw static_cast<const TensorFailure*>(&error);
    default: throw static_cast<TensorFailure*>(nullptr);
    }
}
aegis::internal::Model* ar_create_kind(unsigned kind) {
    using namespace aegis::internal;
    switch (kind) {
    case 0: return new SingleKernel;
    case 1: return new ResonantKernel;
    default: return new DiamondKernel;
    }
}
bool ar_reverse_cast(aegis::internal::Model* model) {
    return dynamic_cast<aegis::internal::SingleKernel*>(model) != nullptr;
}
std::uint32_t ar_compute(std::uint32_t value) {
    // A numerical hot loop intentionally excluded from obfuscation.
    for (unsigned i = 0; i < 4096; ++i) {
        value = value * 1664525u + 1013904223u;
    }
    return value;
}
