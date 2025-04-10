# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.16.3)

# We name the project and the target for the ExternalProject_Add() call
# to something that will highlight to the user what we are working on if
# something goes wrong and an error message is produced.

project(level-zero-loader-populate NONE)

include(ExternalProject)
ExternalProject_Add(level-zero-loader-populate
                     "UPDATE_DISCONNECTED" "False" "GIT_REPOSITORY" "https://github.com/oneapi-src/level-zero.git" "GIT_TAG" "v1.19.2" "EXCLUDE_FROM_ALL"
                    SOURCE_DIR          "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src"
                    BINARY_DIR          "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-build"
                    CONFIGURE_COMMAND   ""
                    BUILD_COMMAND       ""
                    INSTALL_COMMAND     ""
                    TEST_COMMAND        ""
                    USES_TERMINAL_DOWNLOAD  YES
                    USES_TERMINAL_UPDATE    YES
)
