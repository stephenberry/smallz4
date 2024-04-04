cmake_minimum_required(VERSION 3.0)
project(compress)

set(CMAKE_CXX_STANDARD 20)

file(GLOB srcs src/*.cpp include/*.hpp)

include_directories(include "/opt/homebrew/Cellar/lz4/1.9.4/include")

add_executable(${PROJECT_NAME} ${srcs})

target_link_libraries(${PROJECT_NAME} PRIVATE
   "/opt/homebrew/Cellar/lz4/1.9.4/lib/liblz4.a"
)