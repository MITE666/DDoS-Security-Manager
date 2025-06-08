cmake_minimum_required(VERSION 3.10)
project(dispatcher)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
    ${CMAKE_SOURCE_DIR}/headers
    ${CMAKE_SOURCE_DIR}/../src
)

add_executable(dispatcher
    src/mit_udp_f.cpp
    src/mit_tcpc_sr_f.cpp
    src/mit_syn_f.cpp   
    src/dispatcher.cpp
)

find_package(Threads REQUIRED)
target_link_libraries(dispatcher 
    PRIVATE Threads::Threads
            crypto
)
