cmake_minimum_required(VERSION 3.10)
project(analyzer)

set(CMAKE_CXX_STANDARD 11)

include_directories(${CMAKE_SOURCE_DIR}/src)

add_executable(analyzer
    src/analyzer.cpp
)
