#include "engine.hpp"
#include <cstring>
#include <exception>
#include <iostream>
#include <set>
#include <typeindex>
#include <unordered_set>

namespace aegis::internal {
static const std::type_info& local_type() {
    struct Local {};
    return typeid(Local);
}
}

int test_rtti() {
    using namespace aegis::internal;
    unsigned checks = 0, failures = 0;
    auto check = [&](bool ok, const char* label) {
        ++checks;
        failures += !ok;
        std::cout << "CHECK\t" << (ok ? "PASS" : "FAIL") << '\t' << label << '\n';
    };
    const auto& local = typeid(ResonantKernel);
    const auto& remote = *ar_type();
#ifdef _WIN32
    check(&local != &remote, "distinct EXE/library descriptors");
#else
    check(true, "ELF permits type descriptor interposition");
#endif
    check(local == remote && remote == local, "cross DLL equality both directions");
    check(local.hash_code() == remote.hash_code(), "equal types have equal hashes");
    check(local != *ar_type(1), "different types stay unequal");
    check(local == peer_type(0), "cross TU equality");
    check(local != peer_type(1), "cross TU inequality");
    const auto& box = typeid(third_party::Box<ResonantKernel>);
    check(box == peer_type(1) && box == *ar_type(2), "template cross TU and DLL equality");
    check(box.hash_code() == ar_type(2)->hash_code(), "template cross DLL hash");
    check(typeid(third_party::Independent) == *ar_type(3), "unrelated type equality");
    check(!local.before(remote) && !remote.before(local), "equal type ordering");
    check(local.before(*ar_type(1)) != ar_type(1)->before(local), "different type ordering");
    std::set<std::type_index> ordered{local, remote, *ar_type(1)};
    check(ordered.size() == 2 && ordered.count(remote) == 1, "ordered type_index lookup");
    std::unordered_set<std::type_index> hashed{local};
    check(hashed.count(remote) == 1, "unordered type_index lookup");
    Model* empty = nullptr;
    check(dynamic_cast<ResonantKernel*>(empty) == nullptr, "null pointer cast");
    bool bad_type = false;
    try { (void)typeid(*empty); } catch (const std::bad_typeid&) { bad_type = true; }
    check(bad_type, "null polymorphic typeid throws bad_typeid");
    for (unsigned kind = 0; kind < 3; ++kind) {
        Model* object = ar_create_kind(kind);
        check(dynamic_cast<OtherKernel*>(object) == nullptr, "wrong pointer cast");
        bool bad_cast = false;
        try { (void)dynamic_cast<OtherKernel&>(*object); }
        catch (const std::bad_cast&) { bad_cast = true; }
        check(bad_cast, "wrong reference cast throws bad_cast");
        if (kind == 0) {
            check(dynamic_cast<SingleKernel*>(object) != nullptr, "single inheritance downcast");
        } else if (kind == 1) {
            auto* derived = dynamic_cast<ResonantKernel*>(object);
            auto* sibling = dynamic_cast<Tag*>(object);
            check(derived && sibling && sibling->tag() == 7, "multiple inheritance crosscast");
            check(sibling && dynamic_cast<void*>(sibling) == derived, "complete object pointer");
        } else {
            auto* left = dynamic_cast<LeftModel*>(object);
            auto* right = dynamic_cast<RightModel*>(object);
            check(left && right && dynamic_cast<RightModel*>(left) == right, "diamond crosscast");
            check(left && right && static_cast<Model*>(left) == static_cast<Model*>(right), "shared virtual base");
        }
        ar_destroy(object);
    }
    SingleKernel object;
    check(ar_reverse_cast(&object), "DLL casts EXE object");
    bool exact = false, base = false, wrong = false, foreign = false;
    try { ar_throw(); } catch (const TensorFailure& e) { exact = e.pivot == 3; } catch (...) {}
    try { ar_throw(); } catch (const FailureBase& e) { base = e.pivot == 3; } catch (...) {}
    try { ar_throw(1); } catch (const TensorFailure&) {} catch (const OtherKernel&) { wrong = true; } catch (...) {}
    try { ar_throw(2); } catch (const third_party::Independent&) { foreign = true; } catch (...) {}
    check(exact, "exact exception match");
    check(base, "base exception match");
    check(wrong, "wrong exception catch skipped");
    check(foreign, "unrelated exception match");
    bool rethrown = false;
    try {
        try { ar_throw(); } catch (const FailureBase&) { throw; }
    } catch (const TensorFailure& e) { rethrown = e.pivot == 3; }
    check(rethrown, "rethrow preserves dynamic exception type");
    std::exception_ptr stored;
    try { ar_throw(); } catch (...) { stored = std::current_exception(); }
    bool stored_exact = false, stored_base = false;
    try { std::rethrow_exception(stored); } catch (const TensorFailure& e) { stored_exact = e.pivot == 3; }
    try { std::rethrow_exception(stored); } catch (const FailureBase& e) { stored_base = e.pivot == 3; }
    check(stored_exact && stored_base, "exception_ptr exact and base catches");
    bool pointer_base = false, pointer_const = false, pointer_void = false, pointer_null = false, cv = false;
    try { ar_throw(3); } catch (FailureBase* e) { pointer_base = e && e->pivot == 3; } catch (...) {}
    try { ar_throw(3); } catch (const FailureBase* e) { pointer_const = e && e->pivot == 3; } catch (...) {}
    try { ar_throw(3); } catch (void* e) { pointer_void = e != nullptr; } catch (...) {}
    try { ar_throw(5); } catch (const FailureBase* e) { pointer_null = e == nullptr; } catch (...) {}
    try { ar_throw(4); } catch (FailureBase*) {} catch (const FailureBase* e) { cv = e && e->pivot == 3; } catch (...) {}
    check(pointer_base, "pointer exception derived to base");
    check(pointer_const, "pointer exception adds const");
    check(pointer_void, "pointer exception to void");
    check(pointer_null, "typed null pointer exception");
    check(cv, "const pointer rejects mutable catch");
    check(std::strcmp(local.name(), remote.name()) == 0, "cross DLL name consistency");
    auto name = [](const char* label, const std::type_info& info) {
        std::cout << "TYPE\t" << label << '\t';
#ifdef _WIN32
        std::cout << info.raw_name() << '\t';
#else
        std::cout << info.name() << '\t';
#endif
        std::cout << info.name() << '\n';
    };
    name("class", local);
    name("template", box);
    name("nested", typeid(third_party::Box<third_party::Box<ResonantKernel>>));
    name("local", local_type());
    name("pointer", typeid(ResonantKernel*));
    name("const_pointer", typeid(const ResonantKernel*));
    name("foreign", typeid(third_party::Independent));
    name("foreign_template", typeid(third_party::Box<int>));
    std::cout << "RESULT\t" << checks << '\t' << failures << '\n';
    return failures ? 1 : 0;
}
