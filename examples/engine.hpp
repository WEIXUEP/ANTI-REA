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
struct SingleKernel : Model {};
struct OtherKernel : Model {};
struct LeftModel : virtual Model {};
struct RightModel : virtual Model {};
struct DiamondKernel : LeftModel, RightModel {};
struct FailureBase {
    int pivot;
};
struct TensorFailure : FailureBase {};
template <class T> struct Storage {
    T value;
};
} // namespace aegis::internal

namespace third_party {
struct Independent {};
template <class T> struct Box {};
}

extern "C" {
AR_API aegis::internal::Model* ar_create();
AR_API void ar_destroy(aegis::internal::Model*);
AR_API const std::type_info* ar_type(unsigned kind = 0);
AR_API void ar_throw(unsigned kind = 0) noexcept(false);
AR_API aegis::internal::Model* ar_create_kind(unsigned kind);
AR_API bool ar_reverse_cast(aegis::internal::Model*);
AR_API std::uint32_t ar_compute(std::uint32_t);
}
std::uint32_t policy_dispatch(std::uint32_t);
std::uint32_t policy_token(std::uint32_t);
void print_rtti();
const std::type_info& peer_type(unsigned kind);
int test_rtti();
