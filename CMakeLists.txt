cmake_minimum_required(VERSION 3.20)
project(goodnight)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

# Third Party Libraries
add_subdirectory(external/Lyra)

# Base Library
add_library(goodnight-lib
    src/goodnight.cpp src/placeholder-window.cpp
)

target_link_libraries(goodnight-lib
    wevtapi
)

target_include_directories(goodnight-lib
    PUBLIC ./include
)

# CLI
add_executable(goodnight-cli
    cli/cli.cpp
)

target_link_libraries(goodnight-cli
    goodnight-lib bfg::lyra
)
