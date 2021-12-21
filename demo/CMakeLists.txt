cmake_minimum_required (VERSION 3.0)

project(demo)

set(CMAKE_CXX_STANDARD 11)

if (CMAKE_BUILD_TYPE STREQUAL Debug)
    add_definitions(-D_DEBUG)
endif()

include_directories("../src")

if (CMAKE_HOST_WIN32)
    set(SRC_FILES ../src/netstat_windows.cpp)
elseif (CMAKE_HOST_APPLE)
    set(SRC_FILES ../src/netstat_darwin.cpp)
elseif (CMAKE_HOST_UNIX)
    set(SRC_FILES ../src/netstat_linux.cpp)
endif ()

aux_source_directory(. SRC_FILES)

add_executable(demo ${SRC_FILES})