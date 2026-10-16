#include "diagnostics.hpp"
#include "engine.hpp"
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#ifdef _WIN32
#include <windows.h>
#include <cstdlib>
#ifdef _DEBUG
#include <crtdbg.h>
#endif
#else
#include <unistd.h>
#endif

static std::filesystem::path executable_directory() {
#ifdef _WIN32
    std::wstring buffer(32768, L'\0');
    auto size = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (!size || size >= buffer.size()) {
        throw std::runtime_error("Executable location unavailable");
    }
    buffer.resize(size);
    return std::filesystem::path(buffer).parent_path();
#else
    return std::filesystem::canonical("/proc/self/exe").parent_path();
#endif
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#ifdef _DEBUG
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
#endif
#endif
    std::string mode = argc > 1 ? argv[1] : "selftest";
    if (mode == "rtti-test") {
        return test_rtti();
    }
    if (mode == "warning") {
        aegis::report(aegis::sites::iteration, 37);
        return 0;
    }
    if (mode == "verify") {
        int elements = 0;
        AR_VERIFY(elements++ > 0, invalid_mesh, elements);
    }
    if (mode == "assert") {
        AR_ASSERT(false, assertion, 17);
    }
    if (mode == "exception") {
        try {
            aegis::report(aegis::sites::exception, 3);
#if ANTI_REA_CODE_PROTECTION
            throw std::runtime_error(aegis::sites::exception.id);
#else
            throw std::runtime_error("Internal constitutive tensor inversion failed: pivot 3");
#endif
        } catch (const std::exception& error) {
            std::cerr << error.what() << '\n';
            return 3;
        }
    }
    if (mode == "rtti") {
        print_rtti();
        std::cout << ar_type()->name() << '\n';
        return 0;
    }
    if (mode == "resource") {
        std::ifstream resource(executable_directory() / "resources" / aegis::resource_name);
        std::string text;
        std::getline(resource, text);
        std::cout << text << '\n';
        return resource && text == "kernel-coefficient=7" ? 0 : 4;
    }
    if (mode == "location") {
#if ANTI_REA_CODE_PROTECTION
        std::cout << aegis::sites::invalid_mesh.file << '\n';
#else
        std::cout << __FILE__ << '\n' << __PRETTY_FUNCTION__ << '\n';
#endif
        return 0;
    }
    if (mode == "bench" || mode == "startup") {
        std::uint32_t result = argc > 2 ? static_cast<std::uint32_t>(std::stoul(argv[2])) : 123u;
        auto start = std::chrono::steady_clock::now();
        unsigned rounds = mode == "startup" ? 1 : 500000;
        for (unsigned i = 0; i < rounds; ++i) {
            result = policy_token(policy_dispatch(result));
        }
        auto end = std::chrono::steady_clock::now();
        std::cout << result << ' ' << std::chrono::duration<double>(end - start).count() << '\n';
        return 0;
    }
    if (mode != "selftest") {
        std::cerr << "Unknown command\n";
        return 2;
    }
    using namespace aegis::internal;
    Model* model = ar_create();
    auto* derived = dynamic_cast<ResonantKernel*>(model);
    auto* sibling = dynamic_cast<Tag*>(model);
    bool ok = derived && sibling && sibling->tag() == 7 && derived->evaluate() == 42;
    ok = ok && typeid(*model) == typeid(ResonantKernel) && *ar_type() == typeid(ResonantKernel);
    ar_destroy(model);
    try {
        ar_throw();
        ok = false;
    } catch (const TensorFailure& error) {
        ok = ok && error.pivot == 3;
    }
    int evaluations = 0;
    AR_VERIFY(++evaluations == 1, single_evaluation, evaluations);
    ok = ok && evaluations == 1;
    std::cout << (ok ? "PASS" : "FAIL") << ' ' << ar_compute(123u) << '\n';
    return ok ? 0 : 1;
}
