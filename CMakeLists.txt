cmake_minimum_required(VERSION 3.20)
project(ShadowForge LANGUAGES CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Sources ──────────────────────────────────────────────
set(SOURCES
    src/main.cpp
    src/pe_parser.cpp
    src/syscalls.cpp
    src/unhooker.cpp
    src/etw_patcher.cpp
    src/injector.cpp
    src/obfuscator.cpp
)

set(HEADERS
    include/shadowforge.h
    include/pe_parser.h
    include/syscalls.h
    include/unhooker.h
    include/etw_patcher.h
    include/injector.h
    include/obfuscator.h
)

# ── Assembly ─────────────────────────────────────────────
if(MSVC)
    # MASM for Visual Studio
    enable_language(ASM_MASM)
    set(ASM_SOURCES asm/syscall_stub.asm)
    set_source_files_properties(${ASM_SOURCES} PROPERTIES LANGUAGE ASM_MASM)
else()
    # GAS for MinGW-w64 / GCC
    set(ASM_SOURCES asm/syscall_stub.S)
    set_source_files_properties(${ASM_SOURCES} PROPERTIES LANGUAGE ASM)
endif()

# ── Executable ───────────────────────────────────────────
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS} ${ASM_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ── Compiler-specific flags ──────────────────────────────
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W3 /EHsc /D_CRT_SECURE_NO_WARNINGS /DUNICODE /D_UNICODE)
    target_link_libraries(${PROJECT_NAME} PRIVATE ntdll dbghelp)
else()
    # MinGW-w64
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -DUNICODE -D_UNICODE)
    target_link_libraries(${PROJECT_NAME} PRIVATE ntdll dbghelp)
    # Static link for portability
    target_link_options(${PROJECT_NAME} PRIVATE -static -static-libgcc -static-libstdc++)
endif()

# Output directory
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
