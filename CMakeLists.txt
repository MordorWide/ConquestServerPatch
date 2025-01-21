cmake_minimum_required(VERSION 3.20)
project(ConquestServer)

set(CMAKE_CXX_STANDARD 17)
add_definitions(-D_UNICODE -DUNICODE)

add_executable(ConquestServer ConquestServer.cpp)
