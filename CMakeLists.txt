cmake_minimum_required(VERSION 2.8)
find_package(DynamoRIO)

set(DRTRACE_C_FLAGS "-g3 -O3 -Wall -Wextra -Werror -Wno-unused-parameter")
set(DRTRACE_CXX_FLAGS "${DRTRACE_C_FLAGS} -std=c++0x")

set(CMAKE_C_FLAGS "${DRTRACE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${DRTRACE_CXX_FLAGS}")
add_library(drtrace SHARED drtrace.c trace_buffer.c crc32.c)
configure_DynamoRIO_client(drtrace)
use_DynamoRIO_extension(drtrace drcontainers)
target_link_libraries(drtrace -Wl,-no-undefined)

set(CMAKE_C_FLAGS "${DRTRACE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${DRTRACE_CXX_FLAGS}")
add_executable(drtrace_view32 drtrace_view.cpp crc32.c)
set_target_properties(drtrace_view32 PROPERTIES COMPILE_FLAGS "-DDRTRACE_X86_32")
configure_DynamoRIO_decoder(drtrace_view32)

set(CMAKE_C_FLAGS "${DRTRACE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${DRTRACE_CXX_FLAGS}")
add_executable(drtrace_view64 drtrace_view.cpp crc32.c)
set_target_properties(drtrace_view64 PROPERTIES COMPILE_FLAGS "-DDRTRACE_X86_64")
configure_DynamoRIO_decoder(drtrace_view64)
