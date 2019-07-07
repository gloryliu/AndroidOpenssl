# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# 设置变量 找到存放资源的目录，".."代表上一级目录
set(export_dir ${CMAKE_SOURCE_DIR}/../../../../export)

add_library(
        lib_so_crypto
        SHARED
        IMPORTED
)

set_target_properties(
        lib_so_crypto
        PROPERTIES IMPORTED_LOCATION ${export_dir}/openssl/lib/${ANDROID_ABI}/libcrypto.so)


add_library(
        lib_so_ssl
        SHARED
        IMPORTED
)

set_target_properties(
        lib_so_ssl
        PROPERTIES IMPORTED_LOCATION ${export_dir}/openssl/lib/${ANDROID_ABI}/libssl.so)


# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.


# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

# build application's shared lib
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

add_library( # Sets the name of the library.
        native-lib

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        native-lib.cpp)


target_include_directories(
        native-lib
        PRIVATE
        ${export_dir}/openssl/include
)


target_link_libraries( # Specifies the target library.
        native-lib

        lib_so_crypto
        lib_so_ssl
        # Links the target library to the log library
        # included in the NDK.
        ${log-lib})