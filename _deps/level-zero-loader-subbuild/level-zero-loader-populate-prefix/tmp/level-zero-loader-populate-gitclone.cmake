
if(NOT "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-subbuild/level-zero-loader-populate-prefix/src/level-zero-loader-populate-stamp/level-zero-loader-populate-gitinfo.txt" IS_NEWER_THAN "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-subbuild/level-zero-loader-populate-prefix/src/level-zero-loader-populate-stamp/level-zero-loader-populate-gitclone-lastrun.txt")
  message(STATUS "Avoiding repeated git clone, stamp file is up to date: '/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-subbuild/level-zero-loader-populate-prefix/src/level-zero-loader-populate-stamp/level-zero-loader-populate-gitclone-lastrun.txt'")
  return()
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E remove_directory "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to remove directory: '/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src'")
endif()

# try the clone 3 times in case there is an odd git clone issue
set(error_code 1)
set(number_of_tries 0)
while(error_code AND number_of_tries LESS 3)
  execute_process(
    COMMAND "/usr/bin/git"  clone --no-checkout "https://github.com/oneapi-src/level-zero.git" "level-zero-loader-src"
    WORKING_DIRECTORY "/home/kluszcze/unified-memory-framework/_deps"
    RESULT_VARIABLE error_code
    )
  math(EXPR number_of_tries "${number_of_tries} + 1")
endwhile()
if(number_of_tries GREATER 1)
  message(STATUS "Had to git clone more than once:
          ${number_of_tries} times.")
endif()
if(error_code)
  message(FATAL_ERROR "Failed to clone repository: 'https://github.com/oneapi-src/level-zero.git'")
endif()

execute_process(
  COMMAND "/usr/bin/git"  checkout v1.19.2 --
  WORKING_DIRECTORY "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to checkout tag: 'v1.19.2'")
endif()

set(init_submodules TRUE)
if(init_submodules)
  execute_process(
    COMMAND "/usr/bin/git"  submodule update --recursive --init 
    WORKING_DIRECTORY "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src"
    RESULT_VARIABLE error_code
    )
endif()
if(error_code)
  message(FATAL_ERROR "Failed to update submodules in: '/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-src'")
endif()

# Complete success, update the script-last-run stamp file:
#
execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-subbuild/level-zero-loader-populate-prefix/src/level-zero-loader-populate-stamp/level-zero-loader-populate-gitinfo.txt"
    "/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-subbuild/level-zero-loader-populate-prefix/src/level-zero-loader-populate-stamp/level-zero-loader-populate-gitclone-lastrun.txt"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to copy script-last-run stamp file: '/home/kluszcze/unified-memory-framework/_deps/level-zero-loader-subbuild/level-zero-loader-populate-prefix/src/level-zero-loader-populate-stamp/level-zero-loader-populate-gitclone-lastrun.txt'")
endif()

