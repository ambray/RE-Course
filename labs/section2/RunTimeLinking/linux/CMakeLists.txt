cmake_minimum_required(VERSION 3.2)
project(LOADER C CXX)

file(GLOB LOADER_C_FILES "*.c")
file(GLOB LOADER_CPP_FILES "*.cpp")

add_executable(loader ${LOADER_C_FILES} ${LOADER_CPP_FILES})
target_link_libraries(loader LINK_PUBLIC "dl")
