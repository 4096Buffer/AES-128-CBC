cmake_minimum_required(VERSION 3.16)

project(aes128_cbc
    VERSION 1.0.0
    DESCRIPTION "AES-128 in CBC mode with PKCS#7 padding, implemented from scratch"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Core library
add_library(aes STATIC aes256/aes.cpp)
target_include_directories(aes PUBLIC aes256)

if(MSVC)
    target_compile_options(aes PRIVATE /W4 /permissive-)
else()
    target_compile_options(aes PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Demo executable
add_executable(aes_demo aes256/main.cpp)
target_link_libraries(aes_demo PRIVATE aes)

# Tests (ctest)
include(CTest)
if(BUILD_TESTING AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/aes256/tests/test_aes.cpp")
    add_executable(aes_tests aes256/tests/test_aes.cpp)
    target_link_libraries(aes_tests PRIVATE aes)
    add_test(NAME aes_tests COMMAND aes_tests)
endif()
