# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.16.3)

# We name the project and the target for the ExternalProject_Add() call
# to something that will highlight to the user what we are working on if
# something goes wrong and an error message is produced.

project(cuda-headers-populate NONE)

include(ExternalProject)
ExternalProject_Add(cuda-headers-populate
                     "UPDATE_DISCONNECTED" "False" "GIT_REPOSITORY" "https://gitlab.com/nvidia/headers/cuda-individual/cudart.git" "GIT_TAG" "cuda-12.5.1" "EXCLUDE_FROM_ALL"
                    SOURCE_DIR          "/home/kluszcze/unified-memory-framework/_deps/cuda-headers-src"
                    BINARY_DIR          "/home/kluszcze/unified-memory-framework/_deps/cuda-headers-build"
                    CONFIGURE_COMMAND   ""
                    BUILD_COMMAND       ""
                    INSTALL_COMMAND     ""
                    TEST_COMMAND        ""
                    USES_TERMINAL_DOWNLOAD  YES
                    USES_TERMINAL_UPDATE    YES
)
