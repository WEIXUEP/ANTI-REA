if(NOT ANTI_REA_OBFUSCATION MATCHES "^(NONE|LIGHT|MEDIUM|HEAVY|MIXED_VM)$")
    message(FATAL_ERROR "Unknown ANTI_REA_OBFUSCATION value")
endif()
if(ANTI_REA_CODE_PROTECTION OR NOT ANTI_REA_OBFUSCATION STREQUAL "NONE")
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(FATAL_ERROR "Protected builds require Clang or clang-cl; ordinary cl.exe is not supported")
    endif()
    if(CMAKE_INTERPROCEDURAL_OPTIMIZATION)
        message(FATAL_ERROR "The teaching launcher supports non-LTO builds only")
    endif()
    get_filename_component(compiler_dir "${CMAKE_CXX_COMPILER}" DIRECTORY)
    if(NOT ANTI_REA_OPT)
        find_program(local_opt NAMES opt HINTS "${compiler_dir}" NO_DEFAULT_PATH REQUIRED)
        set(ANTI_REA_OPT "${local_opt}" CACHE FILEPATH "Matching LLVM opt" FORCE)
    endif()
    execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/anti_rea.py"
        doctor --compiler "${CMAKE_CXX_COMPILER}" --opt "${ANTI_REA_OPT}"
        --level "${ANTI_REA_OBFUSCATION}" --plugin "${ANTI_REA_XOLLVM_PLUGIN}"
        RESULT_VARIABLE doctor_status COMMAND_ERROR_IS_FATAL ANY)
endif()

function(anti_rea_protect target)
    if(NOT ANTI_REA_CODE_PROTECTION AND ANTI_REA_OBFUSCATION STREQUAL "NONE")
        return()
    endif()
    set_property(TARGET ${target} PROPERTY CXX_COMPILER_LAUNCHER
        "${Python3_EXECUTABLE};${CMAKE_CURRENT_SOURCE_DIR}/tools/anti_rea.py;launch;--build;${CMAKE_BINARY_DIR};--keys;${ANTI_REA_KEYS};--opt;${ANTI_REA_OPT};--plugin=${ANTI_REA_XOLLVM_PLUGIN};--level;${ANTI_REA_OBFUSCATION};--protected;${ANTI_REA_CODE_PROTECTION};--")
    if(MSVC)
        target_compile_options(${target} PRIVATE "/pathmap:${CMAKE_CURRENT_SOURCE_DIR}=src"
            "/pathmap:${CMAKE_BINARY_DIR}=build")
    else()
        target_compile_options(${target} PRIVATE
            "-ffile-prefix-map=${CMAKE_CURRENT_SOURCE_DIR}=src"
            "-ffile-prefix-map=${CMAKE_BINARY_DIR}=build")
    endif()
    string(TOUPPER "${ANTI_REA_OBFUSCATION}" level)
    target_compile_definitions(${target} PRIVATE "AR_OBF_${level}=1")
endfunction()
