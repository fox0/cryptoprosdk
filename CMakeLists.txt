cmake_minimum_required(VERSION 3.16)
project(cryptoprosdk C)

set(CMAKE_C_STANDARD 11)

add_executable(cryptoprosdk main.c)

include_directories(/opt/cprocsp/include)
include_directories(/opt/cprocsp/include/cpcsp)
include_directories(/opt/cprocsp/include/pki)
target_link_libraries(cryptoprosdk "-L/opt/cprocsp/lib/amd64" capi20 cades rdrsup)

#enable_testing()
#add_subdirectory(tests)
