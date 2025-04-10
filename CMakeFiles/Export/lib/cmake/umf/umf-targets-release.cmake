#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "umf::umf" for configuration "Release"
set_property(TARGET umf::umf APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(umf::umf PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "C"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libumf.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS umf::umf )
list(APPEND _IMPORT_CHECK_FILES_FOR_umf::umf "${_IMPORT_PREFIX}/lib/libumf.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
