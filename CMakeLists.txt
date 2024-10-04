cmake_minimum_required(VERSION 3.20)
project(goodnight)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

# Third Party Libraries
add_subdirectory(external/Lyra)

### Dependencies for GUI
set(BUILD_SHARED_LIBS OFF)
set(RMLUI_SAMPLES ON)
set(RMLUI_SVG_PLUGIN OFF)
add_subdirectory(external/glfw)
add_subdirectory(external/lunasvg)

add_library(glfw::glfw ALIAS glfw)
add_library(opengl INTERFACE)
add_library(OpenGL::GL ALIAS opengl)
add_subdirectory(external/freetype)
add_library(Freetype::Freetype ALIAS freetype)
add_subdirectory(external/RmlUi)

# Base Library
add_library(goodnight-lib
    src/goodnight.cpp src/placeholder-window.cpp
)

target_link_libraries(goodnight-lib
    wevtapi Setupapi Newdev
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

# GUI

add_executable(goodnight-gui
    gui/gui.cpp
)

target_include_directories(goodnight-gui
PRIVATE external/RmlUi/include external/
)
target_link_options(goodnight-gui PRIVATE -Xlinker /MANIFESTUAC:"level='requireAdministrator' uiAccess='false'")
target_link_directories(goodnight-gui
    PRIVATE external/prebuilts
)
target_link_libraries(goodnight-gui
    goodnight-lib RmlUi::RmlUi freetype
    rmlui_backend_GLFW_GL3 glfw3_mt
)
