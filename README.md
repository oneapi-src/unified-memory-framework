# Unified Memory Framework

## Building

### Requirements

Required packages:
- C compiler
- [CMake](https://cmake.org/) >= 3.14.0

### Windows

Generating Visual Studio Project. EXE and binaries will be in **build/bin/{build_config}**

```bash
$ mkdir build
$ cd build
$ cmake {path_to_source_dir} -G "Visual Studio 15 2017 Win64"
```

### Linux

Executable and binaries will be in **build/bin**

```bash
$ mkdir build
$ cd build
$ cmake {path_to_source_dir}
$ make
```

### CMake standard options

List of options provided by CMake:

| Name | Description | Values | Default |
| - | - | - | - |
| UMF_DEVELOPER_MODE | Treat warnings as errors and enables additional checks | ON/OFF | OFF |
| UMF_BUILD_SHARED_LIBRARY | Build UMF as shared library | ON/OFF | OFF |
