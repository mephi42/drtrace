cmake_minimum_required(VERSION 2.8)
find_package(DynamoRIO)

add_definitions(-g3 -Wall -Wextra -Werror -Wno-unused-parameter)
add_library(drtrace SHARED drtrace.c)
configure_DynamoRIO_client(drtrace)
target_link_libraries(drtrace -Wl,-no-undefined)
