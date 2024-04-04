cmake_minimum_required(VERSION 3.0)
project(compress)

set(CMAKE_CXX_STANDARD 20)

file(GLOB srcs src/*.cpp include/*.hpp)

include_directories(include)

add_executable(${PROJECT_NAME} ${srcs})