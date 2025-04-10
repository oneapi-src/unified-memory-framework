# Install script for directory: /home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xlevel-zero-develx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/./include/level_zero" TYPE FILE FILES
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src/include/ze_api.h"
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src/include/ze_ddi.h"
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src/include/zes_api.h"
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src/include/zes_ddi.h"
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src/include/zet_api.h"
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src/include/zet_ddi.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xlevel-zero-develx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/./include/level_zero/layers" TYPE FILE FILES
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src/include/layers/zel_tracing_api.h"
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src/include/layers/zel_tracing_ddi.h"
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src/include/layers/zel_tracing_register_cb.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xlevel-zero-develx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/./include/level_zero/loader" TYPE FILE FILES "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src/include/loader/ze_loader.h")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-build/source/cmake_install.cmake")
  include("/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-build/samples/cmake_install.cmake")

endif()

