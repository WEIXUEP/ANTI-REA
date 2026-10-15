#pragma once
#include <cstdint>
#include <stdexcept>
#include <typeinfo>
#ifdef _WIN32
#ifdef AR_BUILD_LIBRARY
#define AR_API __declspec(dllexport)
#else
#define AR_API __declspec(dllimport)
#endif
#else
#define AR_API __attribute__((visibility("default")))
#endif

namespace aegis::internal {
struct Model {
    virtual ~Model() = default;
    virtual int evaluate() const { return 41; }
};
struct Tag {
    virtual ~Tag() = default;
    virtual int tag() const { return 7; }
};
struct ResonantKernel : virtual Model, Tag {
    int evaluate() const override { return 42; }
};
struct TensorFailure {
    int pivot;
};
template <class T> struct Storage {
    T value;
};
} // namespace aegis::internal

extern "C" {
AR_API aegis::internal::Model* ar_create();
AR_API void ar_destroy(aegis::internal::Model*);
AR_API const std::type_info* ar_type();
AR_API void ar_throw();
AR_API std::uint32_t ar_compute(std::uint32_t);
}
std::uint32_t policy_dispatch(std::uint32_t);
std::uint32_t policy_token(std::uint32_t);
void print_rtti();
