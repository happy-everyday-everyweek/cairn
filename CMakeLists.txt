cmake_minimum_required(VERSION 3.16)
project(cairn C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Both the library and the Android JNI bridge need this list, so define it once.
set(CAIRN_VENDORED
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/monocypher/monocypher.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/monocypher/monocypher-ed25519.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/fips202/fips202.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/mlkem768/cbd.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/mlkem768/indcpa.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/mlkem768/kem.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/mlkem768/ntt.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/mlkem768/poly.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/mlkem768/polyvec.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/mlkem768/reduce.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/mlkem768/symmetric-shake.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/mlkem768/verify.c
)

file(GLOB CAIRN_OWN CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*/*.c)

# The Android demo needs one shared object containing both the library and the JNI
# entry points, so the library becomes shared there. Every other target gets a
# static library, which is what an application wants to link.
option(CAIRN_ANDROID_SHARED "Build cairn as a shared library for the Android demo" OFF)

if(CAIRN_ANDROID_SHARED)
    add_library(cairn SHARED ${CAIRN_OWN} ${CAIRN_VENDORED}
        ${CMAKE_CURRENT_SOURCE_DIR}/android/cairn_jni.c)
else()
    add_library(cairn STATIC ${CAIRN_OWN} ${CAIRN_VENDORED})
endif()

target_include_directories(cairn PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(cairn PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/monocypher
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/fips202
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/common
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor/pqclean/mlkem768
)

# Vendored sources are third party code: their warnings are not ours to fix, so
# the strict flags go on our own translation units only.
if(NOT MSVC)
    set_source_files_properties(${CAIRN_VENDORED} PROPERTIES COMPILE_OPTIONS "-w")
    set_source_files_properties(${CAIRN_OWN} PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra")
endif()

if(WIN32 AND NOT CAIRN_ANDROID_SHARED)
    target_link_libraries(cairn PUBLIC bcrypt ws2_32)
endif()

option(CAIRN_BUILD_TESTS "Build the test binary" ON)
if(CAIRN_BUILD_TESTS)
    file(GLOB CAIRN_TEST_SRC CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c)
    add_executable(cairn_tests ${CAIRN_TEST_SRC})
    target_link_libraries(cairn_tests PRIVATE cairn)
    target_include_directories(cairn_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

    enable_testing()
    add_test(NAME cairn_tests COMMAND cairn_tests)
endif()

# The CLI is a demonstration, not part of the library, so it is optional: a build
# for a target without a shell, such as the Android demo, skips it.
option(CAIRN_BUILD_CLI "Build the cairn command line demo" ON)
if(CAIRN_BUILD_CLI)
    add_executable(cairn_cli ${CMAKE_CURRENT_SOURCE_DIR}/cli/main.c)
    target_link_libraries(cairn_cli PRIVATE cairn)
    if(WIN32)
        target_link_libraries(cairn_cli PRIVATE ws2_32)
    endif()
endif()