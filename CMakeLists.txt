cmake_minimum_required(VERSION 3.27)
project(kfc CXX)
set(CMAKE_CXX_STANDARD 17)

# IDASDK env var must point to the idasdk repo root (or src/ subfolder).
# If not set, try to resolve relative to this file's location.
if(NOT DEFINED ENV{IDASDK})
    get_filename_component(_SDK_GUESS "${CMAKE_CURRENT_SOURCE_DIR}/third-party/idasdk" ABSOLUTE)
    if(EXISTS "${_SDK_GUESS}/src/cmake/bootstrap.cmake")
        set(ENV{IDASDK} "${_SDK_GUESS}")
    else()
        message(FATAL_ERROR "Set IDASDK env to the idasdk repo root (contains src/cmake/bootstrap.cmake).")
    endif()
endif()

include($ENV{IDASDK}/src/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

ida_add_loader(kfc
    SOURCES
        kfc.cpp
)
