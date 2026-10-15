#pragma once
#include "diagnostic_catalog.hpp"
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace aegis {
void emit(const Site&, const std::vector<std::string>&);
template <class T> std::string field(const T& value) {
    std::ostringstream output;
    output << value;
    return output.str();
}
template <class... T> void report(const Site& site, const T&... values) {
    emit(site, {field(values)...});
}
} // namespace aegis

#if ANTI_REA_CODE_PROTECTION
#define AR_LOCATION(condition) ((void)0)
#else
#if defined(_MSC_VER)
#define AR_FUNCTION __FUNCSIG__
#else
#define AR_FUNCTION __PRETTY_FUNCTION__
#endif
#define AR_LOCATION(condition)                                                                     \
    (std::cerr << #condition << "\n" << __FILE__ << ":" << __LINE__ << "\n" << AR_FUNCTION << "\n")
#endif
#define AR_VERIFY(condition, site, ...)                                                            \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            AR_LOCATION(condition);                                                                \
            aegis::report(aegis::sites::site, __VA_ARGS__);                                        \
            std::abort();                                                                          \
        }                                                                                          \
    } while (false)
#define AR_ASSERT(condition, site, ...) AR_VERIFY(condition, site, __VA_ARGS__)
