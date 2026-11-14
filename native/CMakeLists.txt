cmake_minimum_required(VERSION 3.22.1)
project(procspoof LANGUAGES CXX)

# CMake >= 4 removed support for cmake_minimum_required < 3.5, which breaks
# LSPlt's bundled build script when pulled in via FetchContent.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
message(STATUS "CMake ${CMAKE_VERSION}, toolchain: ${CMAKE_TOOLCHAIN_FILE}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT ANDROID)
    message(FATAL_ERROR "Build with the Android NDK toolchain: -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK_HOME/build/cmake/android.toolchain.cmake")
endif()

# LSPlt (PLT hook) — no root CMakeLists in the repo, point at the jni subdir.
set(LSPLT_BUILD_SHARED OFF CACHE BOOL "" FORCE)
include(FetchContent)
FetchContent_Declare(lsplt
    GIT_REPOSITORY https://github.com/LSPosed/LSPlt.git
    GIT_TAG master
    GIT_SHALLOW TRUE
    SOURCE_SUBDIR lsplt/src/main/jni)
FetchContent_MakeAvailable(lsplt)

add_library(procspoof SHARED main.cpp)
target_compile_options(procspoof PRIVATE
    -fvisibility=hidden -ffunction-sections -fdata-sections -Wall)
target_link_options(procspoof PRIVATE
    -Wl,--gc-sections -Wl,--exclude-libs,ALL -s)
target_link_libraries(procspoof PRIVATE lsplt_static log)
