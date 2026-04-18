cmake_minimum_required(VERSION 3.15)
project(DCPatch)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_CXX_STANDARD 20)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Error: Building for x64, but x86 expected. Use x86 Native Tools Command Prompt.")
endif()

# Detours library
set(DETOURS_DIR "${CMAKE_SOURCE_DIR}/Detours/src")
include_directories(${DETOURS_DIR})

add_library(detours STATIC
    ${DETOURS_DIR}/detours.cpp
    ${DETOURS_DIR}/modules.cpp
    ${DETOURS_DIR}/disasm.cpp
    ${DETOURS_DIR}/image.cpp
    ${DETOURS_DIR}/creatwth.cpp
    ${DETOURS_DIR}/disolx86.cpp
)

# ============================================================================
# DCPatch.dll - Generic Circus-engine patch (auto-detects addresses)
# ============================================================================
add_library(DCPatch SHARED
    src/dcpatch.cpp
)

target_link_libraries(DCPatch PRIVATE 
    detours
    gdi32
    user32
    advapi32
    comdlg32
)

set_target_properties(DCPatch PROPERTIES
    LINK_FLAGS "/DYNAMICBASE:NO"
    OUTPUT_NAME "DCPatch"
)

# ============================================================================
# DCLauncher.exe - Starts the game and injects DCPatch.dll
# ============================================================================
add_executable(DCLauncher WIN32
    src/launcher.cpp
    src/launcher.rc
)

target_include_directories(DCLauncher PRIVATE src)

target_link_libraries(DCLauncher PRIVATE
    user32
    advapi32
)

set_target_properties(DCLauncher PROPERTIES OUTPUT_NAME "DCLauncher")


