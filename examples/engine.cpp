#include "engine.hpp"
#include <iostream>

// Deliberately visible in the baseline symbol table, not part of the public API.
int internal_preconditioner_budget = 73;

aegis::internal::Model* ar_create() { return new aegis::internal::ResonantKernel; }
void ar_destroy(aegis::internal::Model* model) { delete model; }
const std::type_info* ar_type() { return &typeid(aegis::internal::ResonantKernel); }
void ar_throw() { throw aegis::internal::TensorFailure{3}; }
std::uint32_t ar_compute(std::uint32_t value) {
    // A numerical hot loop intentionally excluded from obfuscation.
    for (unsigned i = 0; i < 4096; ++i) {
        value = value * 1664525u + 1013904223u;
    }
    return value;
}
