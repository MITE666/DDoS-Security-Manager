cmake_minimum_required(VERSION 3.10)
project(attacker)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(attacker
  src/control_server.cpp
  src/httplib.h
)   