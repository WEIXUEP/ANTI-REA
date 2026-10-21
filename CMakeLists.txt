cmake_minimum_required(VERSION 3.24)
project(ANTI_REA VERSION 0.1.0 LANGUAGES CXX)
include(CTest)
find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
option(ANTI_REA_CODE_PROTECTION "Protect internal diagnostics, RTTI and paths" ON)
option(ANTI_REA_CONSTANT_PROTECTION "Runtime-mask the five selected policy constants when protection is ON" ON)
option(ANTI_REA_STRIP_RELEASE "Strip the installed ELF release copy" ON)
set(ANTI_REA_OBFUSCATION "NONE" CACHE STRING "NONE, LIGHT, MEDIUM, HEAVY, MIXED_VM")
set_property(CACHE ANTI_REA_OBFUSCATION PROPERTY STRINGS NONE LIGHT MEDIUM HEAVY MIXED_VM)
set(ANTI_REA_NAME_STYLE "OPAQUE" CACHE STRING "OPAQUE (existing policy) or DECOY (common-word internal aliases)")
set_property(CACHE ANTI_REA_NAME_STYLE PROPERTY STRINGS OPAQUE DECOY)
option(ANTI_REA_RETAIN_DECOY_EXPORTS "Windows only: expose selected decoy function labels in the EXE export table" OFF)
set(ANTI_REA_NAME_POLICY "${CMAKE_CURRENT_SOURCE_DIR}/examples/name-policy.json" CACHE FILEPATH
    "Explicit owned function symbols eligible for DECOY naming")
set(ANTI_REA_KEYS "${CMAKE_CURRENT_SOURCE_DIR}/demo-keys/keys.json" CACHE FILEPATH
    "PUBLIC teaching keys by default; use private keys for real deployment")
set(ANTI_REA_OPT "" CACHE FILEPATH "opt from the compiler's LLVM toolchain")
set(ANTI_REA_XOLLVM_PLUGIN "" CACHE FILEPATH "Optional matching Linux xollvm plugin")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_INSTALL_RPATH "$ORIGIN")
include(cmake/Protection.cmake)

set(generated "${CMAKE_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${generated}")
file(GLOB_RECURSE example_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.cpp")
file(GLOB protection_scripts CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/anti_rea/*.py")
set_source_files_properties(${example_sources} PROPERTIES OBJECT_DEPENDS "${protection_scripts};${ANTI_REA_KEYS};${ANTI_REA_NAME_POLICY};${CMAKE_CURRENT_SOURCE_DIR}/examples/policy-constants.json")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${ANTI_REA_KEYS}" "${CMAKE_CURRENT_SOURCE_DIR}/examples/diagnostics.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/examples/policy-constants.json"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/anti_rea/constants.py"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/anti_rea/generate.py" ${example_sources})
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/anti_rea/crypto.py")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/anti_rea.py"
    generate --root "${CMAKE_CURRENT_SOURCE_DIR}" --build "${CMAKE_BINARY_DIR}"
    --keys "${ANTI_REA_KEYS}" --protected "${ANTI_REA_CODE_PROTECTION}"
    --constants "${ANTI_REA_CONSTANT_PROTECTION}"
    RESULT_VARIABLE generation_status COMMAND_ERROR_IS_FATAL ANY)

add_library(engine SHARED examples/engine.cpp examples/diagnostics.cpp)
target_compile_definitions(engine PRIVATE AR_BUILD_LIBRARY)
add_executable(anti-rea-demo examples/main.cpp examples/policy.cpp examples/diagnostics.cpp examples/rtti.cpp)
target_link_libraries(anti-rea-demo PRIVATE engine)
foreach(target IN ITEMS engine anti-rea-demo)
    target_include_directories(${target} PRIVATE examples "${generated}")
    target_compile_definitions(${target} PRIVATE
        ANTI_REA_CODE_PROTECTION=$<BOOL:${ANTI_REA_CODE_PROTECTION}>)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /EHsc)
        # Keep PDBs private and remove the developer path from CodeView.
        target_link_options(${target} PRIVATE "/PDBALTPATH:$<TARGET_PDB_FILE_NAME:${target}>")
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    anti_rea_protect(${target})
endforeach()
if(ANTI_REA_CODE_PROTECTION)
    if(UNIX AND NOT APPLE)
        target_link_options(engine PRIVATE "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/cmake/exports.map")
        set_property(TARGET engine APPEND PROPERTY LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/exports.map")
    endif()
    find_path(SODIUM_INCLUDE_DIR sodium.h REQUIRED)
    find_library(SODIUM_LIBRARY NAMES sodium libsodium REQUIRED)
    foreach(target IN ITEMS engine anti-rea-demo)
        target_include_directories(${target} PRIVATE "${SODIUM_INCLUDE_DIR}")
        target_link_libraries(${target} PRIVATE "${SODIUM_LIBRARY}")
        set_target_properties(${target} PROPERTIES CXX_VISIBILITY_PRESET hidden
                              VISIBILITY_INLINES_HIDDEN YES)
    endforeach()
endif()
set_target_properties(anti-rea-demo PROPERTIES BUILD_RPATH "$ORIGIN")
install(TARGETS anti-rea-demo engine RUNTIME DESTINATION bin LIBRARY DESTINATION bin)
file(READ "${generated}/resource-name.txt" resource_name)
install(FILES "${generated}/resources/${resource_name}" DESTINATION bin/resources)
if(ANTI_REA_STRIP_RELEASE AND UNIX AND NOT APPLE)
    install(CODE "execute_process(COMMAND \"${CMAKE_STRIP}\" --strip-all
        \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/bin/anti-rea-demo\"
        \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/bin/${CMAKE_SHARED_LIBRARY_PREFIX}engine${CMAKE_SHARED_LIBRARY_SUFFIX}\"
        COMMAND_ERROR_IS_FATAL ANY)")
endif()
if(BUILD_TESTING)
    add_test(NAME runtime COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime.py"
        --exe "$<TARGET_FILE:anti-rea-demo>" --build "${CMAKE_BINARY_DIR}"
        --keys "${ANTI_REA_KEYS}" --protected "${ANTI_REA_CODE_PROTECTION}")
    add_test(NAME python COMMAND "${Python3_EXECUTABLE}" -m unittest discover
        -s "${CMAKE_CURRENT_SOURCE_DIR}/tests" -p "test_*.py" -v)
endif()
