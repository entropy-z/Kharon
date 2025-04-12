cmake_minimum_required(VERSION 3.27)

# Project name
project( VelkorLdr )

# Set architecture and compiler based on ARCH variable
if( ARCH STREQUAL "64")
    set( CMAKE_CXX_COMPILER "clang++-14" )
    set( CMAKE_CXX_FLAGS "-target x86_64-w64-mingw32 -m64" )
elseif( ARCH STREQUAL "86" )
    set( CMAKE_CXX_COMPILER "clang++-14" )
    set( CMAKE_CXX_FLAGS "-target i686-w64-mingw32 -m32" )
endif()

# Set debug compilation options
if ( DEBUG STREQUAL "on" )
    set( CMAKE_CXX_FLAGS "-D DEBUG" )
endif()

# Set output directory
set( OUTPUT_DIR "${CMAKE_SOURCE_DIR}/../Bin" )
set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR} )

# Include directory
include_directories( ${CMAKE_SOURCE_DIR}/Include )

# C++ Compiler Flags
set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive -mrdrnd -nostdlib -fno-ident -s -w" )

# Main source file conditional
if( MAIN STREQUAL "exe" )
    set( LOADER_MAIN "${CMAKE_SOURCE_DIR}/Source/Main/ExeMain.cc" )
elseif( MAIN STREQUAL "dll" )
    set( LOADER_MAIN "${CMAKE_SOURCE_DIR}/Source/Main/DllMain.cc" )
elseif( MAIN STREQUAL "svc" )
    set( LOADER_MAIN "${CMAKE_SOURCE_DIR}/Source/Main/SvcMain.cc" )
endif()

# Collect source files
file( GLOB LOADER_SRC  "${CMAKE_SOURCE_DIR}/Source/*.cc" )

# Create executable
add_executable( ${PROJECT_NAME}.x${ARCH}.exe
    ${LOADER_SRC}
    ${LOADER_MAIN}
)

target_link_libraries( ${PROJECT_NAME}.x${ARCH}.exe PRIVATE msvcrt )

