cmake_minimum_required(VERSION 3.10)

set(prj_name pak)

# Enable compile commands output
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Set the project name
project(${prj_name})

# Enable debugging and disable optimizations
set(CMAKE_C_FLAGS_DEBUG "-g -O0")
set(CMAKE_BUILD_TYPE Debug)

# Add the executable
add_executable(${prj_name} main.c crc32.c md5-c/md5.c)

# Include directories
target_include_directories(${prj_name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} md5-c)