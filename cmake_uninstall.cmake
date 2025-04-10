# From: https://cmake.org/Wiki/CMake_FAQ

if(NOT EXISTS "/home/kluszcze/unified-memory-framework/install_manifest.txt")
	message(FATAL_ERROR "Cannot find install manifest: /home/kluszcze/unified-memory-framework/install_manifest.txt")
endif(NOT EXISTS "/home/kluszcze/unified-memory-framework/install_manifest.txt")

file(READ "/home/kluszcze/unified-memory-framework/install_manifest.txt" files)
string(REGEX REPLACE "\n" ";" files "${files}")
foreach(file ${files})
	message(STATUS "Uninstalling $ENV{DESTDIR}${file}")
	if(IS_SYMLINK "$ENV{DESTDIR}${file}" OR EXISTS "$ENV{DESTDIR}${file}")
		FILE(REMOVE $ENV{DESTDIR}${file})
	else(IS_SYMLINK "$ENV{DESTDIR}${file}" OR EXISTS "$ENV{DESTDIR}${file}")
		message(STATUS "File $ENV{DESTDIR}${file} does not exist.")
	endif(IS_SYMLINK "$ENV{DESTDIR}${file}" OR EXISTS "$ENV{DESTDIR}${file}")
endforeach(file)
