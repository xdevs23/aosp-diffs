```diff
diff --git a/.github/workflows/cmake_android.yml b/.github/workflows/cmake_android.yml
index 25ab455..50e1e7a 100644
--- a/.github/workflows/cmake_android.yml
+++ b/.github/workflows/cmake_android.yml
@@ -41,7 +41,7 @@ jobs:
       shell: bash
       run: |
         mkdir build
-        cmake -G Ninja -B build -DCMAKE_TOOLCHAIN_FILE=./cmake/toolchains/android.cmake -DUHDR_ANDROID_NDK_PATH=${{ steps.setup-ndk.outputs.ndk-path }} -DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1 -DANDROID_ABI=${{ matrix.abi }} -DANDROID_PLATFORM=android-23 -DUHDR_BUILD_JAVA=1
+        cmake -G Ninja -B build -DCMAKE_TOOLCHAIN_FILE=./cmake/toolchains/android.cmake -DUHDR_ANDROID_NDK_PATH=${{ steps.setup-ndk.outputs.ndk-path }} -DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1 -DANDROID_ABI=${{ matrix.abi }} -DANDROID_PLATFORM=android-23 -DUHDR_BUILD_JAVA=1 -DUHDR_ENABLE_WERROR=1
 
     - name: Build
       run: cmake --build build
diff --git a/.github/workflows/cmake_linux.yml b/.github/workflows/cmake_linux.yml
index 72aef4b..667cda7 100644
--- a/.github/workflows/cmake_linux.yml
+++ b/.github/workflows/cmake_linux.yml
@@ -17,7 +17,7 @@ jobs:
             build_type: Release
             cc: gcc
             cxx: g++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DUHDR_ENABLE_WERROR=1'
 
           # <Ubuntu-latest Platform, Release Build, Clang toolchain, Ninja generator>
           - name: "ubuntu latest clang rel ninja"
@@ -25,7 +25,7 @@ jobs:
             build_type: Release
             cc: clang
             cxx: clang++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DUHDR_ENABLE_WERROR=1'
 
           # <Ubuntu-latest Platform, Release Build, GCC toolchain, Ninja generator, Build Deps>
           - name: "ubuntu latest gcc rel ninja with deps"
@@ -33,7 +33,7 @@ jobs:
             build_type: Release
             cc: gcc
             cxx: g++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1 -DUHDR_ENABLE_WERROR=1'
 
           # <Ubuntu-latest Platform, Release Build, Clang toolchain, Ninja generator, Build Deps, Sanitizer Address>
           - name: "ubuntu latest clang rel ninja with deps sanitize address"
@@ -41,7 +41,7 @@ jobs:
             build_type: Release
             cc: clang
             cxx: clang++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1 -DUHDR_SANITIZE_OPTIONS=address'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1 -DUHDR_SANITIZE_OPTIONS=address -DUHDR_ENABLE_WERROR=1'
 
           # <Ubuntu-latest Platform, Release Build, Clang toolchain, Ninja generator, Build Fuzzers, Sanitizer Address>
           - name: "ubuntu latest clang rel ninja fuzzers sanitize address"
@@ -49,7 +49,7 @@ jobs:
             build_type: Release
             cc: clang
             cxx: clang++
-            cmake-opts: '-DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address'
+            cmake-opts: '-DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address -DUHDR_ENABLE_WERROR=1'
 
           # <Ubuntu-latest Platform, Release Build, GCC toolchain, Ninja generator, Static linking>
           - name: "ubuntu latest gcc rel ninja static"
@@ -57,7 +57,7 @@ jobs:
             build_type: Release
             cc: gcc
             cxx: g++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0 -DUHDR_ENABLE_WERROR=1'
 
           # <Ubuntu-latest Platform, Release Build, Clang toolchain, Ninja generator, Static linking>
           - name: "ubuntu latest clang rel ninja static"
@@ -65,7 +65,7 @@ jobs:
             build_type: Release
             cc: clang
             cxx: clang++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0 -DUHDR_ENABLE_WERROR=1'
 
     steps:
     - name: Checkout the repository
diff --git a/.github/workflows/cmake_mac.yml b/.github/workflows/cmake_mac.yml
index 0f75979..75b9f3e 100644
--- a/.github/workflows/cmake_mac.yml
+++ b/.github/workflows/cmake_mac.yml
@@ -17,7 +17,7 @@ jobs:
             build_type: Release
             cc: clang
             cxx: clang++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DUHDR_ENABLE_WERROR=1'
 
           # <macOS-13 Platform, Release Build, Clang toolchain, Ninja generator>
           - name: "macOS-13 clang rel ninja"
@@ -25,7 +25,7 @@ jobs:
             build_type: Release
             cc: clang
             cxx: clang++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DUHDR_ENABLE_WERROR=1'
 
           # <macOS-latest ARM64 Platform, Release Build, Clang toolchain, Ninja generator, Build Deps>
           - name: "macOS latest ARM64 clang rel ninja with deps"
@@ -33,7 +33,7 @@ jobs:
             build_type: Release
             cc: clang
             cxx: clang++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1 -DUHDR_ENABLE_WERROR=1'
 
           # <macOS-latest ARM64 Platform, Release Build, Clang toolchain, Ninja generator, Static linking>
           - name: "macOS latest ARM64 clang rel ninja static"
@@ -41,7 +41,7 @@ jobs:
             build_type: Release
             cc: clang
             cxx: clang++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0 -DUHDR_ENABLE_WERROR=1'
 
           # <macOS-13 Platform, Release Build, Clang toolchain, Ninja generator, Static linking>
           - name: "macOS-13 clang rel ninja static"
@@ -49,7 +49,7 @@ jobs:
             build_type: Release
             cc: clang
             cxx: clang++
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0 -DUHDR_ENABLE_WERROR=1'
 
     steps:
     - name: Checkout the repository
diff --git a/.github/workflows/cmake_win.yml b/.github/workflows/cmake_win.yml
index d1f5b96..0778d3c 100644
--- a/.github/workflows/cmake_win.yml
+++ b/.github/workflows/cmake_win.yml
@@ -17,7 +17,7 @@ jobs:
             build_type: Release
             cc: cl
             cxx: cl
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1'
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1 -DUHDR_ENABLE_WERROR=1'
 
     steps:
     - name: Checkout the repository
diff --git a/.gitignore b/.gitignore
new file mode 100644
index 0000000..f768721
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1,9 @@
+# build output directories
+build
+build*
+
+# downloaded dependencies
+third_party/googletest
+third_party/turbojpeg
+third_party/benchmark
+tests/data
\ No newline at end of file
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 4a72f01..c518d85 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -22,7 +22,12 @@ if(POLICY CMP0091)
   cmake_policy(SET CMP0091 OLD)
 endif()
 
-project(libuhdr VERSION 1.2.0 LANGUAGES C CXX
+set(UHDR_MAJOR_VERSION 1)
+set(UHDR_MINOR_VERSION 3)
+set(UHDR_PATCH_VERSION 0)
+project(libuhdr
+        VERSION ${UHDR_MAJOR_VERSION}.${UHDR_MINOR_VERSION}.${UHDR_PATCH_VERSION}
+        LANGUAGES C CXX
         DESCRIPTION "Library for encoding and decoding ultrahdr images")
 
 ###########################################################
@@ -39,12 +44,12 @@ endif()
 
 if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64.*|x86_64.*|AMD64.*")
   if(CMAKE_SIZEOF_VOID_P EQUAL 8)
-    set(ARCH "x86_64")
+    set(ARCH "amd64")
   else()
-    set(ARCH "x86")
+    set(ARCH "i386")
   endif()
 elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i686.*|i386.*|x86.*")
-  set(ARCH "x86")
+  set(ARCH "i386")
 elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*|arm64.*|ARM64.*)")
   if(CMAKE_SIZEOF_VOID_P EQUAL 8)
     set(ARCH "aarch64")
@@ -55,6 +60,10 @@ elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm.*|ARM.*)")
   set(ARCH "arm")
 elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^riscv64")
   set(ARCH "riscv64")
+elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^riscv32")
+  set(ARCH "riscv32")
+elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^loongarch64")
+  set(ARCH "loong64")
 else()
   message(FATAL_ERROR "Architecture: ${CMAKE_SYSTEM_PROCESSOR} not recognized")
 endif()
@@ -86,7 +95,11 @@ if(NOT IS_MULTI)
   endif()
 endif()
 
-if(NOT DEFINED BUILD_SHARED_LIBS)
+if(EMSCRIPTEN)
+  # platform does not support dynamic linking?
+  message(STATUS "For wasm targets, selecting static only builds")
+  option(BUILD_SHARED_LIBS "Build shared libraries" FALSE)
+elseif(NOT DEFINED BUILD_SHARED_LIBS)
   message(STATUS "No target type chosen, selecting Shared")
   option(BUILD_SHARED_LIBS "Build shared libraries" TRUE)
 endif()
@@ -102,15 +115,18 @@ option_if_not_defined(UHDR_BUILD_TESTS "Build unit tests " FALSE)
 option_if_not_defined(UHDR_BUILD_BENCHMARK "Build benchmark tests " FALSE)
 option_if_not_defined(UHDR_BUILD_FUZZERS "Build fuzz test applications " FALSE)
 option_if_not_defined(UHDR_BUILD_DEPS "Build deps and not use pre-installed packages " FALSE)
+option_if_not_defined(UHDR_BUILD_JAVA "Build JNI wrapper and Java front-end classes " FALSE)
+option_if_not_defined(UHDR_BUILD_PACKAGING "Build distribution packages using CPack " FALSE)
+
 option_if_not_defined(UHDR_ENABLE_LOGS "Build with verbose logging " FALSE)
 option_if_not_defined(UHDR_ENABLE_INSTALL "Enable install and uninstall targets for libuhdr package " TRUE)
 option_if_not_defined(UHDR_ENABLE_INTRINSICS "Build with SIMD acceleration " TRUE)
 option_if_not_defined(UHDR_ENABLE_GLES "Build with GPU acceleration " FALSE)
-option_if_not_defined(UHDR_BUILD_JAVA "Build JNI wrapper and Java front-end classes " FALSE)
+option_if_not_defined(UHDR_ENABLE_WERROR "Build with -Werror" FALSE)
 
 # pre-requisites
 if(UHDR_BUILD_TESTS AND EMSCRIPTEN)
-  message(FATAL_ERROR "Building tests not supported in Web Assembly Path")
+  message(FATAL_ERROR "Building tests not supported for wasm targets")
 endif()
 
 if(UHDR_BUILD_BENCHMARK AND WIN32)
@@ -118,7 +134,7 @@ if(UHDR_BUILD_BENCHMARK AND WIN32)
 endif()
 
 if(UHDR_BUILD_BENCHMARK AND EMSCRIPTEN)
-  message(FATAL_ERROR "Building benchmarks not supported in Web Assembly Path")
+  message(FATAL_ERROR "Building benchmarks not supported for wasm targets")
 endif()
 
 # side effects
@@ -156,6 +172,7 @@ if(BUILD_SHARED_LIBS)
   set(CMAKE_POSITION_INDEPENDENT_CODE ON)
   set(CMAKE_CXX_VISIBILITY_PRESET hidden)
   set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
+  set(UHDR_ENABLE_STATIC_LINKING OFF)
   add_compile_options(-DUHDR_BUILDING_SHARED_LIBRARY)
 else()
   if(WIN32)
@@ -163,6 +180,18 @@ else()
   else()
     set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
   endif()
+  if(APPLE)
+    message(STATUS "Apple does not support statically linking an entire executable, disabling '-static' option")
+    set(UHDR_ENABLE_STATIC_LINKING OFF)
+  elseif(DEFINED UHDR_SANITIZE_OPTIONS OR UHDR_BUILD_FUZZERS)
+    message(STATUS "Possible that sanitizer libraries are only DSO's, disabling '-static' option")
+    set(UHDR_ENABLE_STATIC_LINKING OFF)
+  elseif(MSVC)
+    message(STATUS "Disabling '-static' option in MSVC platforms")
+    set(UHDR_ENABLE_STATIC_LINKING OFF)
+  else()
+    set(UHDR_ENABLE_STATIC_LINKING ON)
+  endif()
 endif()
 if(UHDR_ENABLE_LOGS)
   add_compile_options(-DLOG_NDEBUG)
@@ -192,6 +221,7 @@ if(UHDR_BUILD_FUZZERS)
   add_compile_options(-fsanitize=fuzzer-no-link)
 endif()
 
+set(UHDR_WERROR_FLAGS "")
 if(MSVC)
   add_definitions(-D_CRT_SECURE_NO_WARNINGS)
   # Disable specific warnings
@@ -203,16 +233,37 @@ if(MSVC)
   add_compile_options(/wd4838) # conversion from 'type1' to 'type2' requires a narrowing conversion
   add_compile_options(/wd26812) # Prefer enum class over enum
 elseif(EMSCRIPTEN)
+  if(NOT UHDR_BUILD_DEPS)
+    include(CheckCSourceCompiles)
+    set(CMAKE_REQUIRED_FLAGS "--use-port=libjpeg")
+    set(CMAKE_REQUIRED_LINK_OPTIONS "--use-port=libjpeg")
+    check_c_source_compiles([=[
+       #include <stdio.h>
+       #include <jpeglib.h>
+       int main(void) {
+         struct jpeg_compress_struct cinfo;
+         struct jpeg_error_mgr jerr;
+         cinfo.err=jpeg_std_error(&jerr);
+         jpeg_create_compress(&cinfo);
+         jpeg_destroy_compress(&cinfo);
+         return 0;
+       }
+     ]=] HAVE_JPEG)
+    if(NOT HAVE_JPEG)
+      message(FATAL_ERROR "Could NOT compile with --use-port=libjpeg, resolve this \
+                           or try 'cmake -DUHDR_BUILD_DEPS=1'")
+    endif()
+  endif()
 else()
   add_compile_options(-ffunction-sections)
   add_compile_options(-fdata-sections)
   add_compile_options(-fomit-frame-pointer)
   add_compile_options(-ffp-contract=fast)
-  if(ARCH STREQUAL "x86")
+  if(ARCH STREQUAL "i386")
     add_compile_options(-m32)
     add_compile_options(-march=i386)
     add_compile_options(-mtune=generic)
-  elseif(ARCH STREQUAL "x86_64")
+  elseif(ARCH STREQUAL "amd64")
     add_compile_options(-m64)
     add_compile_options(-march=x86-64)
     add_compile_options(-mtune=generic)
@@ -230,6 +281,17 @@ else()
   elseif(ARCH STREQUAL "riscv64")
     add_compile_options(-march=rv64gc)
     add_compile_options(-mabi=lp64d)
+  elseif(ARCH STREQUAL "riscv32")
+    add_compile_options(-march=rv32gc)
+    add_compile_options(-mabi=ilp32d)
+  elseif(ARCH STREQUAL "loong64")
+    add_compile_options(-march=loongarch64)
+    add_compile_options(-mabi=lp64d)
+  endif()
+
+  if(UHDR_ENABLE_WERROR)
+    CheckCompilerOption("-Werror" SUPPORTS_WERROR)
+    set(UHDR_WERROR_FLAGS "-Werror")
   endif()
 endif()
 
@@ -520,6 +582,7 @@ target_include_directories(${IMAGEIO_TARGET_NAME} PRIVATE
 
 set(UHDR_CORE_LIB_NAME core)
 add_library(${UHDR_CORE_LIB_NAME} STATIC ${UHDR_CORE_SRCS_LIST})
+target_compile_options(${UHDR_CORE_LIB_NAME} PRIVATE ${UHDR_WERROR_FLAGS})
 if(NOT JPEG_FOUND)
   add_dependencies(${UHDR_CORE_LIB_NAME} ${JPEGTURBO_TARGET_NAME})
 endif()
@@ -543,12 +606,17 @@ endif()
 target_link_libraries(${UHDR_CORE_LIB_NAME} PRIVATE ${COMMON_LIBS_LIST} ${IMAGEIO_TARGET_NAME})
 
 if(UHDR_BUILD_EXAMPLES)
-  add_executable(ultrahdr_app "${EXAMPLES_DIR}/ultrahdr_app.cpp")
-  add_dependencies(ultrahdr_app ${UHDR_CORE_LIB_NAME})
+  set(UHDR_SAMPLE_APP ultrahdr_app)
+  add_executable(${UHDR_SAMPLE_APP} "${EXAMPLES_DIR}/ultrahdr_app.cpp")
+  add_dependencies(${UHDR_SAMPLE_APP} ${UHDR_CORE_LIB_NAME})
+  target_compile_options(${UHDR_SAMPLE_APP} PRIVATE ${UHDR_WERROR_FLAGS})
   if(UHDR_BUILD_FUZZERS)
-    target_link_options(ultrahdr_app PRIVATE -fsanitize=fuzzer-no-link)
+    target_link_options(${UHDR_SAMPLE_APP} PRIVATE -fsanitize=fuzzer-no-link)
+  endif()
+  if(UHDR_ENABLE_STATIC_LINKING)
+    target_link_options(${UHDR_SAMPLE_APP} PRIVATE -static)
   endif()
-  target_link_libraries(ultrahdr_app PRIVATE ${UHDR_CORE_LIB_NAME})
+  target_link_libraries(${UHDR_SAMPLE_APP} PRIVATE ${UHDR_CORE_LIB_NAME})
 endif()
 
 if(UHDR_BUILD_TESTS OR UHDR_BUILD_BENCHMARK)
@@ -570,6 +638,7 @@ endif()
 if(UHDR_BUILD_TESTS)
   add_executable(ultrahdr_unit_test ${UHDR_TEST_SRCS_LIST})
   add_dependencies(ultrahdr_unit_test ${GTEST_TARGET_NAME} ${UHDR_CORE_LIB_NAME})
+  target_compile_options(ultrahdr_unit_test PRIVATE ${UHDR_WERROR_FLAGS})
   target_include_directories(ultrahdr_unit_test PRIVATE
     ${PRIVATE_INCLUDE_DIR}
     ${GTEST_INCLUDE_DIRS}
@@ -584,6 +653,7 @@ endif()
 if(UHDR_BUILD_BENCHMARK)
   add_executable(ultrahdr_bm ${UHDR_BM_SRCS_LIST})
   add_dependencies(ultrahdr_bm ${BM_TARGET_NAME} ${UHDR_CORE_LIB_NAME})
+  target_compile_options(ultrahdr_bm PRIVATE ${UHDR_WERROR_FLAGS})
   target_include_directories(ultrahdr_bm PRIVATE
     ${PRIVATE_INCLUDE_DIR}
     ${BENCHMARK_INCLUDE_DIR}
@@ -593,8 +663,8 @@ if(UHDR_BUILD_BENCHMARK)
   endif()
   target_link_libraries(ultrahdr_bm ${UHDR_CORE_LIB_NAME} ${BENCHMARK_LIBRARIES})
 
-  set(RES_FILE "${TESTS_DIR}/data/UltrahdrBenchmarkTestRes-1.0.zip")
-  set(RES_FILE_MD5SUM "96651c5c07505c37aa017c57f480e6c1")
+  set(RES_FILE "${TESTS_DIR}/data/UltrahdrBenchmarkTestRes-1.2.zip")
+  set(RES_FILE_MD5SUM "31fc352444f95bc1ab4b9d6e397de6c1")
   set(GET_RES_FILE TRUE)
   if(EXISTS ${RES_FILE})
     file(MD5 ${RES_FILE} CURR_MD5_SUM)
@@ -608,7 +678,7 @@ if(UHDR_BUILD_BENCHMARK)
 
   if(GET_RES_FILE)
     message("-- Downloading benchmark test resources")
-    set(RES_URL "https://storage.googleapis.com/android_media/external/libultrahdr/benchmark/UltrahdrBenchmarkTestRes-1.0.zip")
+    set(RES_URL "https://storage.googleapis.com/android_media/external/libultrahdr/benchmark/UltrahdrBenchmarkTestRes-1.2.zip")
     file(DOWNLOAD ${RES_URL} ${RES_FILE} STATUS result EXPECTED_MD5 ${RES_FILE_MD5SUM})
     list(GET result 0 retval)
     if(retval)
@@ -632,6 +702,7 @@ endif()
 if(UHDR_BUILD_FUZZERS)
   add_executable(ultrahdr_enc_fuzzer ${FUZZERS_DIR}/ultrahdr_enc_fuzzer.cpp)
   add_dependencies(ultrahdr_enc_fuzzer ${UHDR_CORE_LIB_NAME})
+  target_compile_options(ultrahdr_enc_fuzzer PRIVATE ${UHDR_WERROR_FLAGS})
   target_include_directories(ultrahdr_enc_fuzzer PRIVATE ${PRIVATE_INCLUDE_DIR})
   if(DEFINED ENV{LIB_FUZZING_ENGINE})
     target_link_options(ultrahdr_enc_fuzzer PRIVATE $ENV{LIB_FUZZING_ENGINE})
@@ -642,6 +713,7 @@ if(UHDR_BUILD_FUZZERS)
 
   add_executable(ultrahdr_dec_fuzzer ${FUZZERS_DIR}/ultrahdr_dec_fuzzer.cpp)
   add_dependencies(ultrahdr_dec_fuzzer ${UHDR_CORE_LIB_NAME})
+  target_compile_options(ultrahdr_dec_fuzzer PRIVATE ${UHDR_WERROR_FLAGS})
   target_include_directories(ultrahdr_dec_fuzzer PRIVATE ${PRIVATE_INCLUDE_DIR})
   if(DEFINED ENV{LIB_FUZZING_ENGINE})
     target_link_options(ultrahdr_dec_fuzzer PRIVATE $ENV{LIB_FUZZING_ENGINE})
@@ -649,11 +721,23 @@ if(UHDR_BUILD_FUZZERS)
     target_link_options(ultrahdr_dec_fuzzer PRIVATE -fsanitize=fuzzer)
   endif()
   target_link_libraries(ultrahdr_dec_fuzzer ${UHDR_CORE_LIB_NAME})
+
+  add_executable(ultrahdr_legacy_fuzzer ${FUZZERS_DIR}/ultrahdr_legacy_fuzzer.cpp)
+  add_dependencies(ultrahdr_legacy_fuzzer ${UHDR_CORE_LIB_NAME})
+  target_compile_options(ultrahdr_legacy_fuzzer PRIVATE ${UHDR_WERROR_FLAGS})
+  target_include_directories(ultrahdr_legacy_fuzzer PRIVATE ${PRIVATE_INCLUDE_DIR})
+  if(DEFINED ENV{LIB_FUZZING_ENGINE})
+    target_link_options(ultrahdr_legacy_fuzzer PRIVATE $ENV{LIB_FUZZING_ENGINE})
+  else()
+    target_link_options(ultrahdr_legacy_fuzzer PRIVATE -fsanitize=fuzzer)
+  endif()
+  target_link_libraries(ultrahdr_legacy_fuzzer ${UHDR_CORE_LIB_NAME})
 endif()
 
 set(UHDR_TARGET_NAME uhdr)
 add_library(${UHDR_TARGET_NAME})
 add_dependencies(${UHDR_TARGET_NAME} ${UHDR_CORE_LIB_NAME})
+target_compile_options(${UHDR_TARGET_NAME} PRIVATE ${UHDR_WERROR_FLAGS})
 if(UHDR_ENABLE_GLES)
   target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${EGL_LIBRARIES} ${OPENGLES3_LIBRARIES})
 endif()
@@ -676,6 +760,7 @@ if(BUILD_SHARED_LIBS)
   set(UHDR_TARGET_NAME_STATIC uhdr-static)
   add_library(${UHDR_TARGET_NAME_STATIC} STATIC)
   add_dependencies(${UHDR_TARGET_NAME_STATIC} ${UHDR_CORE_LIB_NAME})
+  target_compile_options(${UHDR_TARGET_NAME_STATIC} PRIVATE ${UHDR_WERROR_FLAGS})
   if(UHDR_ENABLE_GLES)
     target_link_libraries(${UHDR_TARGET_NAME_STATIC} PRIVATE ${EGL_LIBRARIES} ${OPENGLES3_LIBRARIES})
   endif()
@@ -697,6 +782,7 @@ if(UHDR_BUILD_JAVA)
   add_library(${UHDR_JNI_TARGET_NAME} SHARED ${UHDR_JNI_SRCS_LIST})
   add_dependencies(${UHDR_JNI_TARGET_NAME} ${UHDR_TARGET_NAME})
   target_include_directories(${UHDR_JNI_TARGET_NAME} PRIVATE ${UHDR_JNI_INCLUDE_PATH} ${EXPORT_INCLUDE_DIR})
+  target_compile_options(${UHDR_JNI_TARGET_NAME} PRIVATE ${UHDR_WERROR_FLAGS})
   target_link_libraries(${UHDR_JNI_TARGET_NAME} PRIVATE ${UHDR_TARGET_NAME})
 
   add_jar(uhdr-java SOURCES ${UHDR_JAVA_SRCS_LIST} ${UHDR_APP_SRC} ENTRY_POINT UltraHdrApp)
@@ -711,7 +797,7 @@ if(UHDR_ENABLE_INSTALL)
                    "${CMAKE_CURRENT_BINARY_DIR}/libuhdr.pc" @ONLY NEWLINE_STYLE UNIX)
     install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libuhdr.pc"
             DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
-    install(TARGETS ${UHDR_TARGET_NAME} ${UHDR_TARGET_NAME_STATIC}
+    install(TARGETS ${UHDR_TARGET_NAME} ${UHDR_TARGET_NAME_STATIC} ${UHDR_SAMPLE_APP}
             RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
             LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
             ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
@@ -734,5 +820,12 @@ if(UHDR_ENABLE_INSTALL)
                    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake" IMMEDIATE @ONLY)
     add_custom_target(uninstall
       COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
+
+    # packaging
+    if(UHDR_BUILD_PACKAGING)
+      include(cmake/package.cmake)
+      include(CPack)
+    endif()
+
   endif()
 endif()
diff --git a/DESCRIPTION b/DESCRIPTION
new file mode 100644
index 0000000..593322e
--- /dev/null
+++ b/DESCRIPTION
@@ -0,0 +1,12 @@
+libultrahdr is an image compression library that uses gain map technology
+to store and distribute HDR images. Conceptually on the encoding side, the
+library accepts SDR and HDR rendition of an image and from these a Gain Map
+(quotient between the two renditions) is computed. The library then uses
+backward compatible means to store the base image (SDR), gain map image and
+some associated metadata. Legacy readers that do not support handling the
+gain map image and/or metadata, will display the base image. Readers that
+support the format combine the base image with the gain map and render a
+high dynamic range image on compatible displays.
+
+For additional information, see android hdr-image-format
+https://developer.android.com/guide/topics/media/platform/hdr-image-format.
diff --git a/METADATA b/METADATA
index 31e0fd8..e6c20d4 100644
--- a/METADATA
+++ b/METADATA
@@ -8,12 +8,12 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 9
-    day: 20
+    month: 11
+    day: 21
   }
   identifier {
     type: "Git"
     value: "https://github.com/google/libultrahdr.git"
-    version: "2188c35c95aee9c66ede526ab1c8187a3bc82416"
+    version: "285824d15db48ef11a556455ae0927c50e325d8b"
   }
 }
diff --git a/OWNERS b/OWNERS
new file mode 100644
index 0000000..f55581c
--- /dev/null
+++ b/OWNERS
@@ -0,0 +1,2 @@
+include platform/frameworks/av:/media/janitors/avic_OWNERS
+include platform/system/core:/janitors/OWNERS
diff --git a/README.md b/README.md
index da5279f..965fd99 100644
--- a/README.md
+++ b/README.md
@@ -34,10 +34,10 @@ libultrahdr includes two classes of APIs, one to compress and the other to decom
 
 | Scenario  | Hdr intent raw | Sdr intent raw | Sdr intent compressed | Gain map compressed | Quality |   Exif   | Use Case |
 |:---------:| :----------: | :----------: | :---------------------: | :-------------------: | :-------: | :---------: | :-------- |
-| API - 0 | P010 or rgb1010102 |    No   |  No  |  No  | Optional| Optional | Used if, only hdr raw intent is present. [^1] |
-| API - 1 | P010 or rgb1010102 | YUV420 or rgba8888 |  No  |  No  | Optional| Optional | Used if, hdr raw and sdr raw intents are present.[^2] |
-| API - 2 | P010 or rgb1010102 | YUV420 or rgba8888 | Yes  |  No  |    No   |    No    | Used if, hdr raw, sdr raw and sdr compressed intents are present.[^3] |
-| API - 3 | P010 or rgb1010102 |    No   | Yes  |  No  |    No   |    No    | Used if, hdr raw and sdr compressed intents are present.[^4] |
+| API - 0 | P010 or rgba1010102 or rgbaf16 |    No   |  No  |  No  | Optional| Optional | Used if, only hdr raw intent is present. [^1] |
+| API - 1 | P010 or rgba1010102 or rgbaf16 | YUV420 or rgba8888 |  No  |  No  | Optional| Optional | Used if, hdr raw and sdr raw intents are present.[^2] |
+| API - 2 | P010 or rgba1010102 or rgbaf16 | YUV420 or rgba8888 | Yes  |  No  |    No   |    No    | Used if, hdr raw, sdr raw and sdr compressed intents are present.[^3] |
+| API - 3 | P010 or rgba1010102 or rgbaf16 |    No   | Yes  |  No  |    No   |    No    | Used if, hdr raw and sdr compressed intents are present.[^4] |
 | API - 4 |  No  |    No   | Yes  | Yes  |    No   |    No    | Used if, sdr compressed, gain map compressed and GainMap Metadata are present.[^5] |
 
 [^1]: Tonemap hdr to sdr. Compute gain map from hdr and sdr. Compress sdr and gainmap at quality configured. Add exif if provided. Combine sdr compressed, gainmap in multi picture format with gainmap metadata.
diff --git a/benchmark/AndroidTest.xml b/benchmark/AndroidTest.xml
index f002f65..114739d 100644
--- a/benchmark/AndroidTest.xml
+++ b/benchmark/AndroidTest.xml
@@ -22,11 +22,11 @@
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.DynamicConfigPusher">
         <option name="target" value="host" />
         <option name="config-filename" value="ultrahdr_benchmark" />
-        <option name="version" value="1.0"/>
+        <option name="version" value="1.2"/>
     </target_preparer>
     <target_preparer class="com.android.compatibility.common.tradefed.targetprep.MediaPreparer">
         <option name="push-all" value="true" />
-        <option name="media-folder-name" value="UltrahdrBenchmarkTestRes-1.0"/>
+        <option name="media-folder-name" value="UltrahdrBenchmarkTestRes-1.2"/>
         <option name="dynamic-config-module" value="ultrahdr_benchmark" />
     </target_preparer>
     <test class="com.android.tradefed.testtype.GoogleBenchmarkTest" >
diff --git a/benchmark/DynamicConfig.xml b/benchmark/DynamicConfig.xml
index 9953ef2..0bc56e9 100644
--- a/benchmark/DynamicConfig.xml
+++ b/benchmark/DynamicConfig.xml
@@ -15,6 +15,6 @@
 
 <dynamicConfig>
     <entry key="media_files_url">
-          <value>https://storage.googleapis.com/android_media/external/libultrahdr/benchmark/UltrahdrBenchmarkTestRes-1.0.zip</value>
+          <value>https://storage.googleapis.com/android_media/external/libultrahdr/benchmark/UltrahdrBenchmarkTestRes-1.2.zip</value>
     </entry>
 </dynamicConfig>
\ No newline at end of file
diff --git a/benchmark/benchmark_test.cpp b/benchmark/benchmark_test.cpp
index 4d5da3a..22d3f94 100644
--- a/benchmark/benchmark_test.cpp
+++ b/benchmark/benchmark_test.cpp
@@ -16,633 +16,539 @@
 
 #include <fstream>
 #include <iostream>
+#include <cstring>
 
 #include <benchmark/benchmark.h>
 
-#include "ultrahdr/jpegrutils.h"
-
-using namespace ultrahdr;
+#include "ultrahdr_api.h"
 
 #ifdef __ANDROID__
-std::string kTestImagesPath = "/sdcard/test/UltrahdrBenchmarkTestRes-1.0/";
-#else
-std::string kTestImagesPath = "./data/UltrahdrBenchmarkTestRes-1.0/";
+std::string kTestImagesPath = "/sdcard/test/UltrahdrBenchmarkTestRes-1.2/";
+
+#ifdef LOG_NDEBUG
+#include "android/log.h"
+
+#ifndef LOG_TAG
+#define LOG_TAG "UHDR_BENCHMARK"
 #endif
 
-std::vector<std::string> kDecodeAPITestImages{
-    // 12mp test vectors
-    "mountains.jpg",
-    "mountain_lake.jpg",
-    "desert_wanda.jpg",
-    // 3mp test vectors
-    "mountains_3mp.jpg",
-    "mountain_lake_3mp.jpg",
-    "desert_wanda_3mp.jpg",
-};
+#ifndef ALOGE
+#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
+#endif
 
-std::vector<std::string> kEncodeApi0TestImages12MpName{
-    // 12mp test vectors
-    "mountains.p010",
-    "mountain_lake.p010",
-};
+#else
+#define ALOGE(...) ((void)0)
+#endif
 
-std::vector<std::string> kEncodeApi0TestImages3MpName{
-    // 3mp test vectors
-    "mountains_3mp.p010",
-    "mountain_lake_3mp.p010",
-};
+#else
+std::string kTestImagesPath = "./data/UltrahdrBenchmarkTestRes-1.2/";
 
-std::vector<std::pair<std::string, std::string>> kEncodeApi1TestImages12MpName{
-    // 12mp test vectors
-    {"mountains.p010", "mountains.yuv"},
-    {"mountain_lake.p010", "mountain_lake.yuv"},
-};
+#ifdef LOG_NDEBUG
+#include <cstdio>
 
-std::vector<std::pair<std::string, std::string>> kEncodeApi1TestImages3MpName{
-    // 3mp test vectors
-    {"mountains_3mp.p010", "mountains_3mp.yuv"},
-    {"mountain_lake_3mp.p010", "mountain_lake_3mp.yuv"},
-};
+#define ALOGE(...)                \
+  do {                            \
+    fprintf(stderr, __VA_ARGS__); \
+    fprintf(stderr, "\n");        \
+  } while (0)
 
-std::vector<std::tuple<std::string, std::string, std::string>> kEncodeApi2TestImages12MpName{
-    // 12mp test vectors
-    {"mountains.p010", "mountains.yuv", "mountains.jpg"},
-    {"mountain_lake.p010", "mountain_lake.yuv", "mountain_lake.jpg"},
-};
+#else
+#define ALOGE(...) ((void)0)
+#endif
 
-std::vector<std::tuple<std::string, std::string, std::string>> kEncodeApi2TestImages3MpName{
-    // 3mp test vectors
-    {"mountains_3mp.p010", "mountains_3mp.yuv", "mountains_3mp.jpg"},
-    {"mountain_lake_3mp.p010", "mountain_lake_3mp.yuv", "mountain_lake_3mp.jpg"},
-};
+#endif
 
-std::vector<std::pair<std::string, std::string>> kEncodeApi3TestImages12MpName{
-    // 12mp test vectors
-    {"mountains.p010", "mountains.jpg"},
-    {"mountain_lake.p010", "mountain_lake.jpg"},
+std::vector<std::string> kDecodeAPITestImages = {
+    "mountains_singlechannelgainmap.jpg",
+    "mountains_multichannelgainmap.jpg",
+    "mountains_singlechannelgamma.jpg",
+    "mountains_multichannelgamma.jpg",
 };
 
-std::vector<std::pair<std::string, std::string>> kEncodeApi3TestImages3MpName{
-    // 3mp test vectors
-    {"mountains_3mp.p010", "mountains_3mp.jpg"},
-    {"mountain_lake_3mp.p010", "mountain_lake_3mp.jpg"},
+std::vector<std::string> kEncodeApi0TestImages12MpName = {
+    "mountains_rgba1010102.raw",
+    "mountains_rgba16F.raw",
+    "mountains_p010.p010",
 };
 
-std::vector<std::string> kEncodeApi4TestImages12MpName{
-    // 12mp test vectors
-    "mountains.jpg",
-    "mountain_lake.jpg",
-    "desert_wanda.jpg",
+std::vector<std::pair<std::string, std::string>> kEncodeApi1TestImages12MpName = {
+    {"mountains_rgba1010102.raw", "mountains_rgba8888.raw"},
+    {"mountains_rgba16F.raw", "mountains_rgba8888.raw"},
+    {"mountains_p010.p010", "mountains_yuv420.yuv"},
 };
 
-std::vector<std::string> kEncodeApi4TestImages3MpName{
-    // 3mp test vectors
-    "mountains_3mp.jpg",
-    "mountain_lake_3mp.jpg",
-    "desert_wanda_3mp.jpg",
-};
+using TestParamsDecodeAPI = std::tuple<std::string, uhdr_color_transfer_t, uhdr_img_fmt_t, bool>;
+using TestParamsEncoderAPI0 =
+    std::tuple<std::string, int, int, uhdr_color_gamut_t, uhdr_color_transfer_t, int, float>;
+using TestParamsEncoderAPI1 =
+    std::tuple<std::string, std::string, int, int, uhdr_color_gamut_t, uhdr_color_transfer_t,
+               uhdr_color_gamut_t, int, float, uhdr_enc_preset_t>;
+
+std::vector<TestParamsDecodeAPI> testParamsDecodeAPI;
+std::vector<TestParamsEncoderAPI0> testParamsAPI0;
+std::vector<TestParamsEncoderAPI1> testParamsAPI1;
 
-std::string ofToString(const ultrahdr_output_format of) {
+std::string imgFmtToString(const uhdr_img_fmt of) {
   switch (of) {
-    case ULTRAHDR_OUTPUT_SDR:
-      return "sdr";
-    case ULTRAHDR_OUTPUT_HDR_LINEAR:
-      return "hdr linear";
-    case ULTRAHDR_OUTPUT_HDR_PQ:
-      return "hdr pq";
-    case ULTRAHDR_OUTPUT_HDR_HLG:
-      return "hdr hlg";
+    case UHDR_IMG_FMT_32bppRGBA8888:
+      return "rgba8888";
+    case UHDR_IMG_FMT_64bppRGBAHalfFloat:
+      return "64rgbaHalftoFloat";
+    case UHDR_IMG_FMT_32bppRGBA1010102:
+      return "rgba1010102";
     default:
       return "Unknown";
   }
 }
 
-std::string colorGamutToString(const ultrahdr_color_gamut cg) {
+std::string colorGamutToString(const uhdr_color_gamut_t cg) {
   switch (cg) {
-    case ULTRAHDR_COLORGAMUT_BT709:
+    case UHDR_CG_BT_709:
       return "bt709";
-    case ULTRAHDR_COLORGAMUT_P3:
+    case UHDR_CG_DISPLAY_P3:
       return "p3";
-    case ULTRAHDR_COLORGAMUT_BT2100:
+    case UHDR_CG_BT_2100:
       return "bt2100";
     default:
       return "Unknown";
   }
 }
 
-std::string tfToString(const ultrahdr_transfer_function of) {
+std::string tfToString(const uhdr_color_transfer_t of) {
   switch (of) {
-    case ULTRAHDR_TF_LINEAR:
+    case UHDR_CT_LINEAR:
       return "linear";
-    case ULTRAHDR_TF_HLG:
+    case UHDR_CT_HLG:
       return "hlg";
-    case ULTRAHDR_TF_PQ:
+    case UHDR_CT_PQ:
       return "pq";
-    case ULTRAHDR_TF_SRGB:
+    case UHDR_CT_SRGB:
       return "srgb";
     default:
       return "Unknown";
   }
 }
 
+#define READ_BYTES(DESC, ADDR, LEN)                                         \
+  DESC.read(static_cast<char*>(ADDR), (LEN));                               \
+  if (DESC.gcount() != (LEN)) {                                             \
+    ALOGE("Failed to read: %u bytes, read: %zu bytes", LEN, DESC.gcount()); \
+    return false;                                                           \
+  }
+
+static bool loadFile(const char* filename, uhdr_raw_image_t* handle) {
+  std::ifstream ifd(filename, std::ios::binary);
+  if (ifd.good()) {
+    if (handle->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
+      const int bpp = 2;
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_Y], handle->w * handle->h * bpp)
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_UV], (handle->w / 2) * (handle->h / 2) * bpp * 2)
+      return true;
+    } else if (handle->fmt == UHDR_IMG_FMT_32bppRGBA1010102 ||
+               handle->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
+               handle->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+      const int bpp = handle->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_PACKED], handle->w * handle->h * bpp)
+      return true;
+    } else if (handle->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_Y], handle->w * handle->h)
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_U], (handle->w / 2) * (handle->h / 2))
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_V], (handle->w / 2) * (handle->h / 2))
+      return true;
+    }
+    return false;
+  }
+  ALOGE("Unable to open file: %s", filename);
+  return false;
+}
+
 static bool loadFile(const char* filename, void*& result, int length) {
   std::ifstream ifd(filename, std::ios::binary | std::ios::ate);
   if (ifd.good()) {
     int size = ifd.tellg();
     if (size < length) {
-      std::cerr << "requested to read " << length << " bytes from file : " << filename
-                << ", file contains only " << size << " bytes" << std::endl;
+      ALOGE("Requested to read %d bytes from file: %s, file contains only %d bytes", length,
+            filename, size);
       return false;
     }
     ifd.seekg(0, std::ios::beg);
-    result = new uint8_t[length];
+    result = malloc(length);
     if (result == nullptr) {
-      std::cerr << "failed to allocate memory to store contents of file : " << filename
-                << std::endl;
+      ALOGE("Failed to allocate memory to store contents of file: %s", filename);
       return false;
     }
-    ifd.read(static_cast<char*>(result), length);
+    READ_BYTES(ifd, result, length)
     return true;
   }
-  std::cerr << "unable to open file : " << filename << std::endl;
+  ALOGE("Unable to open file: %s", filename);
   return false;
 }
 
-bool fillRawImageHandle(jpegr_uncompressed_struct* rawImage, int width, int height,
-                        std::string file, ultrahdr_color_gamut cg, bool isP010) {
-  const int bpp = isP010 ? 2 : 1;
-  int imgSize = width * height * bpp * 1.5;
-  rawImage->width = width;
-  rawImage->height = height;
-  rawImage->colorGamut = cg;
-  return loadFile(file.c_str(), rawImage->data, imgSize);
-}
-
-bool fillJpgImageHandle(jpegr_compressed_struct* jpgImg, std::string file,
-                        ultrahdr_color_gamut colorGamut) {
-  std::ifstream ifd(file.c_str(), std::ios::binary | std::ios::ate);
-  if (!ifd.good()) {
-    return false;
-  }
-  int size = ifd.tellg();
-  jpgImg->length = size;
-  jpgImg->maxLength = size;
-  jpgImg->data = nullptr;
-  jpgImg->colorGamut = colorGamut;
-  ifd.close();
-  return loadFile(file.c_str(), jpgImg->data, size);
-}
+class DecBenchmark {
+ public:
+  std::string mUhdrFile;
+  uhdr_color_transfer_t mTf;
+  uhdr_img_fmt_t mOfmt;
+  bool mEnableGLES;
 
-static void BM_Decode(benchmark::State& s) {
-  std::string srcFileName = kTestImagesPath + "jpegr/" + kDecodeAPITestImages[s.range(0)];
-  ultrahdr_output_format of = static_cast<ultrahdr_output_format>(s.range(1));
+  uhdr_compressed_image_t mUhdrImg{};
 
-  std::ifstream ifd(srcFileName.c_str(), std::ios::binary | std::ios::ate);
-  if (!ifd.good()) {
-    s.SkipWithError("unable to open file " + srcFileName);
-    return;
+  DecBenchmark(TestParamsDecodeAPI testParams) {
+    mUhdrFile = std::get<0>(testParams);
+    mTf = std::get<1>(testParams);
+    mOfmt = std::get<2>(testParams);
+    mEnableGLES = std::get<3>(testParams);
   }
-  int size = ifd.tellg();
-
-  jpegr_compressed_struct jpegImgR{};
-  jpegImgR.length = size;
-  jpegImgR.maxLength = size;
-  jpegImgR.data = nullptr;
-  jpegImgR.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-  ifd.close();
-  if (!loadFile(srcFileName.c_str(), jpegImgR.data, size)) {
-    s.SkipWithError("unable to load file " + srcFileName);
-    return;
+  ~DecBenchmark() {
+    if (mUhdrImg.data) {
+      free(mUhdrImg.data);
+      mUhdrImg.data = nullptr;
+    }
   }
 
-  std::unique_ptr<uint8_t[]> compData;
-  compData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));
+  bool fillJpegImageHandle(uhdr_compressed_image_t* uhdrImg, std::string mUhdrFile);
+};
 
-  JpegR jpegHdr;
-  jpegr_info_struct info{};
-  status_t status = jpegHdr.getJPEGRInfo(&jpegImgR, &info);
-  if (JPEGR_NO_ERROR != status) {
-    s.SkipWithError("getJPEGRInfo returned with error " + std::to_string(status));
-    return;
+bool DecBenchmark::fillJpegImageHandle(uhdr_compressed_image_t* uhdrImg, std::string filename) {
+  std::ifstream ifd(filename, std::ios::binary | std::ios::ate);
+  if (ifd.good()) {
+    int size = ifd.tellg();
+    uhdrImg->capacity = size;
+    uhdrImg->data_sz = size;
+    uhdrImg->data = nullptr;
+    uhdrImg->cg = UHDR_CG_UNSPECIFIED;
+    uhdrImg->ct = UHDR_CT_UNSPECIFIED;
+    uhdrImg->range = UHDR_CR_UNSPECIFIED;
+    ifd.close();
+    return loadFile(filename.c_str(), uhdrImg->data, size);
   }
+  return false;
+}
 
-  size_t outSize = info.width * info.height * ((of == ULTRAHDR_OUTPUT_HDR_LINEAR) ? 8 : 4);
-  std::unique_ptr<uint8_t[]> data = std::make_unique<uint8_t[]>(outSize);
-  jpegr_uncompressed_struct destImage{};
-  destImage.data = data.get();
-  for (auto _ : s) {
-    status = jpegHdr.decodeJPEGR(&jpegImgR, &destImage, FLT_MAX, nullptr, of);
-    if (JPEGR_NO_ERROR != status) {
-      s.SkipWithError("decodeJPEGR returned with error " + std::to_string(status));
-      return;
-    }
+class EncBenchmark {
+ public:
+  std::string mHdrFile, mSdrFile;
+  uhdr_color_gamut_t mHdrCg, mSdrCg;
+  uhdr_img_fmt_t mHdrCf, mSdrCf;
+  int mWidth, mHeight;
+  uhdr_color_transfer_t mHdrCt, mSdrCt = UHDR_CT_SRGB;
+  int mUseMultiChannelGainMap;
+  int mMapDimensionScaleFactor = 1;
+  float mGamma;
+  uhdr_enc_preset_t mEncPreset;
+
+  uhdr_raw_image_t mHdrImg{}, mSdrImg{};
+
+  EncBenchmark(TestParamsEncoderAPI0 testParams) {
+    mHdrFile = std::get<0>(testParams);
+    mWidth = std::get<1>(testParams);
+    mHeight = std::get<2>(testParams);
+    mHdrCg = std::get<3>(testParams);
+    mHdrCt = std::get<4>(testParams);
+    mUseMultiChannelGainMap = std::get<5>(testParams);
+    mGamma = std::get<6>(testParams);
+  };
+
+  EncBenchmark(TestParamsEncoderAPI1 testParams) {
+    mHdrFile = std::get<0>(testParams);
+    mSdrFile = std::get<1>(testParams);
+    mWidth = std::get<2>(testParams);
+    mHeight = std::get<3>(testParams);
+    mHdrCg = std::get<4>(testParams);
+    mHdrCt = std::get<5>(testParams);
+    mSdrCg = std::get<6>(testParams);
+    mUseMultiChannelGainMap = std::get<7>(testParams);
+    mGamma = std::get<8>(testParams);
+    mEncPreset = std::get<9>(testParams);
   }
-  if (info.width != destImage.width || info.height != destImage.height) {
-    s.SkipWithError("received unexpected width/height");
-    return;
+
+  ~EncBenchmark() {
+    int count = sizeof mHdrImg.planes / sizeof mHdrImg.planes[0];
+    for (int i = 0; i < count; i++) {
+      if (mHdrImg.planes[i]) {
+        free(mHdrImg.planes[i]);
+        mHdrImg.planes[i] = nullptr;
+      }
+      if (mSdrImg.planes[i]) {
+        free(mSdrImg.planes[i]);
+        mSdrImg.planes[i] = nullptr;
+      }
+    }
   }
 
-  s.SetLabel(srcFileName + ", OutputFormat: " + ofToString(of) + ", " + std::to_string(info.width) +
-             "x" + std::to_string(info.height));
+  bool fillRawImageHandle(uhdr_raw_image_t* rawImg, int width, int height, std::string file,
+                          uhdr_img_fmt_t cf, uhdr_color_gamut_t cg, uhdr_color_transfer_t ct);
+};
+
+bool EncBenchmark::fillRawImageHandle(uhdr_raw_image_t* rawImg, int width, int height,
+                                      std::string file, uhdr_img_fmt_t cf, uhdr_color_gamut_t cg,
+                                      uhdr_color_transfer_t ct) {
+  rawImg->fmt = cf;
+  rawImg->cg = cg;
+  rawImg->ct = ct;
+  rawImg->w = width;
+  rawImg->h = height;
+  if (cf == UHDR_IMG_FMT_24bppYCbCrP010) {
+    const int bpp = 2;
+    rawImg->range = std::rand() % 2 ? UHDR_CR_FULL_RANGE : UHDR_CR_LIMITED_RANGE;
+    rawImg->planes[UHDR_PLANE_Y] = malloc(width * height * bpp);
+    rawImg->planes[UHDR_PLANE_UV] = malloc((width / 2) * (height / 2) * bpp * 2);
+    rawImg->planes[UHDR_PLANE_V] = nullptr;
+    rawImg->stride[UHDR_PLANE_Y] = width;
+    rawImg->stride[UHDR_PLANE_UV] = width;
+    rawImg->stride[UHDR_PLANE_V] = 0;
+    return loadFile(file.c_str(), rawImg);
+  } else if (cf == UHDR_IMG_FMT_32bppRGBA1010102 || cf == UHDR_IMG_FMT_32bppRGBA8888 ||
+             cf == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+    const int bpp = cf == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
+    rawImg->range = UHDR_CR_FULL_RANGE;
+    rawImg->planes[UHDR_PLANE_PACKED] = malloc(width * height * bpp);
+    rawImg->planes[UHDR_PLANE_UV] = nullptr;
+    rawImg->planes[UHDR_PLANE_V] = nullptr;
+    rawImg->stride[UHDR_PLANE_PACKED] = width;
+    rawImg->stride[UHDR_PLANE_UV] = 0;
+    rawImg->stride[UHDR_PLANE_V] = 0;
+    return loadFile(file.c_str(), rawImg);
+  } else if (cf == UHDR_IMG_FMT_12bppYCbCr420) {
+    rawImg->range = UHDR_CR_FULL_RANGE;
+    rawImg->planes[UHDR_PLANE_Y] = malloc(width * height);
+    rawImg->planes[UHDR_PLANE_U] = malloc((width / 2) * (height / 2));
+    rawImg->planes[UHDR_PLANE_V] = malloc((width / 2) * (height / 2));
+    rawImg->stride[UHDR_PLANE_Y] = width;
+    rawImg->stride[UHDR_PLANE_U] = width / 2;
+    rawImg->stride[UHDR_PLANE_V] = width / 2;
+    return loadFile(file.c_str(), rawImg);
+  }
+  return false;
 }
 
-static void BM_Encode_Api0(benchmark::State& s, std::vector<std::string> testVectors) {
-  int width = s.range(1);
-  int height = s.range(2);
-  ultrahdr_color_gamut p010Cg = static_cast<ultrahdr_color_gamut>(s.range(3));
-  ultrahdr_transfer_function tf = static_cast<ultrahdr_transfer_function>(s.range(4));
+static void BM_UHDRDecode(benchmark::State& s, TestParamsDecodeAPI testVectors) {
+  DecBenchmark benchmark(testVectors);
 
-  s.SetLabel(testVectors[s.range(0)] + ", " + colorGamutToString(p010Cg) + ", " + tfToString(tf) +
-             ", " + std::to_string(width) + "x" + std::to_string(height));
+  s.SetLabel(benchmark.mUhdrFile + ", OutputFormat: " + imgFmtToString(benchmark.mOfmt) +
+             ", ColorTransfer: " + tfToString(benchmark.mTf) +
+             ", enableGLES: " + (benchmark.mEnableGLES ? "true" : "false"));
 
-  std::string p010File{kTestImagesPath + "p010/" + testVectors[s.range(0)]};
+  benchmark.mUhdrFile = kTestImagesPath + "jpegr/" + benchmark.mUhdrFile;
 
-  jpegr_uncompressed_struct rawP010Image{};
-  if (!fillRawImageHandle(&rawP010Image, width, height, p010File, p010Cg, true)) {
-    s.SkipWithError("unable to load file : " + p010File);
+  if (!benchmark.fillJpegImageHandle(&benchmark.mUhdrImg, benchmark.mUhdrFile)) {
+    s.SkipWithError("unable to load file : " + benchmark.mUhdrFile);
     return;
   }
-  std::unique_ptr<uint8_t[]> rawP010ImgData;
-  rawP010ImgData.reset(reinterpret_cast<uint8_t*>(rawP010Image.data));
-
-  jpegr_compressed_struct jpegImgR{};
-  jpegImgR.maxLength = (std::max)(static_cast<size_t>(8 * 1024) /* min size 8kb */,
-                                  rawP010Image.width * rawP010Image.height * 3 * 2);
-  jpegImgR.data = new uint8_t[jpegImgR.maxLength];
-  if (jpegImgR.data == nullptr) {
-    s.SkipWithError("unable to allocate memory to store compressed image");
-    return;
+
+#define RET_IF_ERR(x)                                                       \
+  {                                                                         \
+    uhdr_error_info_t status = (x);                                         \
+    if (status.error_code != UHDR_CODEC_OK) {                               \
+      uhdr_release_decoder(decHandle);                                      \
+      s.SkipWithError(status.has_detail ? status.detail : "Unknown error"); \
+      return;                                                               \
+    }                                                                       \
   }
-  std::unique_ptr<uint8_t[]> jpegImgRData;
-  jpegImgRData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));
 
-  JpegR jpegHdr;
+  uhdr_codec_private_t* decHandle = uhdr_create_decoder();
   for (auto _ : s) {
-    status_t status = jpegHdr.encodeJPEGR(&rawP010Image, tf, &jpegImgR, 95, nullptr);
-    if (JPEGR_NO_ERROR != status) {
-      s.SkipWithError("encodeJPEGR returned with error : " + std::to_string(status));
-      return;
-    }
+    RET_IF_ERR(uhdr_dec_set_image(decHandle, &benchmark.mUhdrImg))
+    RET_IF_ERR(uhdr_dec_set_out_color_transfer(decHandle, benchmark.mTf))
+    RET_IF_ERR(uhdr_dec_set_out_img_format(decHandle, benchmark.mOfmt))
+    RET_IF_ERR(uhdr_enable_gpu_acceleration(decHandle, benchmark.mEnableGLES))
+    RET_IF_ERR(uhdr_decode(decHandle))
+    uhdr_reset_decoder(decHandle);
   }
+  uhdr_release_decoder(decHandle);
+#undef RET_IF_ERR
 }
 
-static void BM_Encode_Api1(benchmark::State& s,
-                           std::vector<std::pair<std::string, std::string>> testVectors) {
-  int width = s.range(1);
-  int height = s.range(2);
-  ultrahdr_color_gamut p010Cg = static_cast<ultrahdr_color_gamut>(s.range(3));
-  ultrahdr_color_gamut yuv420Cg = static_cast<ultrahdr_color_gamut>(s.range(4));
-  ultrahdr_transfer_function tf = static_cast<ultrahdr_transfer_function>(s.range(5));
-
-  s.SetLabel(testVectors[s.range(0)].first + ", " + testVectors[s.range(0)].second + ", " +
-             "p010_" + colorGamutToString(p010Cg) + ", " + "yuv420_" +
-             colorGamutToString(yuv420Cg) + ", " + tfToString(tf) + ", " + std::to_string(width) +
-             "x" + std::to_string(height));
-
-  std::string p010File{kTestImagesPath + "p010/" + testVectors[s.range(0)].first};
+#define RET_IF_ERR(x)                                                       \
+  {                                                                         \
+    uhdr_error_info_t status = (x);                                         \
+    if (status.error_code != UHDR_CODEC_OK) {                               \
+      uhdr_release_encoder(encHandle);                                      \
+      s.SkipWithError(status.has_detail ? status.detail : "Unknown error"); \
+      return;                                                               \
+    }                                                                       \
+  }
 
-  jpegr_uncompressed_struct rawP010Image{};
-  if (!fillRawImageHandle(&rawP010Image, width, height, p010File, p010Cg, true)) {
-    s.SkipWithError("unable to load file : " + p010File);
+static void BM_UHDREncode_Api0(benchmark::State& s, TestParamsEncoderAPI0 testVectors) {
+  EncBenchmark benchmark(testVectors);
+
+  s.SetLabel(
+      benchmark.mHdrFile + ", " + std::to_string(benchmark.mWidth) + "x" +
+      std::to_string(benchmark.mHeight) + ", " + colorGamutToString(benchmark.mHdrCg) + ", " +
+      (benchmark.mHdrFile.find("rgba16F") != std::string::npos ? "linear"
+                                                               : tfToString(benchmark.mHdrCt)) +
+      ", " +
+      (benchmark.mUseMultiChannelGainMap == 0 ? "singlechannelgainmap" : "multichannelgainmap") +
+      ", gamma: " + std::to_string(benchmark.mGamma));
+
+  if (benchmark.mHdrFile.find("p010") != std::string::npos) {
+    benchmark.mHdrFile = kTestImagesPath + "p010/" + benchmark.mHdrFile;
+    benchmark.mHdrCf = UHDR_IMG_FMT_24bppYCbCrP010;
+  } else if (benchmark.mHdrFile.find("rgba1010102") != std::string::npos) {
+    benchmark.mHdrFile = kTestImagesPath + "rgba1010102/" + benchmark.mHdrFile;
+    benchmark.mHdrCf = UHDR_IMG_FMT_32bppRGBA1010102;
+  } else if (benchmark.mHdrFile.find("rgba16F") != std::string::npos) {
+    benchmark.mHdrFile = kTestImagesPath + "rgba16F/" + benchmark.mHdrFile;
+    benchmark.mHdrCf = UHDR_IMG_FMT_64bppRGBAHalfFloat;
+    benchmark.mHdrCt = UHDR_CT_LINEAR;
+  } else {
+    s.SkipWithError("Invalid file format : " + benchmark.mHdrFile);
     return;
   }
-  std::unique_ptr<uint8_t[]> rawP010ImgData;
-  rawP010ImgData.reset(reinterpret_cast<uint8_t*>(rawP010Image.data));
 
-  std::string yuv420File{kTestImagesPath + "yuv420/" + testVectors[s.range(0)].second};
-
-  jpegr_uncompressed_struct rawYuv420Image{};
-  if (!fillRawImageHandle(&rawYuv420Image, width, height, yuv420File, yuv420Cg, false)) {
-    s.SkipWithError("unable to load file : " + yuv420File);
+  if (!benchmark.fillRawImageHandle(&benchmark.mHdrImg, benchmark.mWidth, benchmark.mHeight,
+                                    benchmark.mHdrFile, benchmark.mHdrCf, benchmark.mHdrCg,
+                                    benchmark.mHdrCt)) {
+    s.SkipWithError("unable to load file : " + benchmark.mHdrFile);
     return;
   }
-  std::unique_ptr<uint8_t[]> rawYuv420ImgData;
-  rawYuv420ImgData.reset(reinterpret_cast<uint8_t*>(rawYuv420Image.data));
-
-  jpegr_compressed_struct jpegImgR{};
-  jpegImgR.maxLength = (std::max)(static_cast<size_t>(8 * 1024) /* min size 8kb */,
-                                  rawP010Image.width * rawP010Image.height * 3 * 2);
-  jpegImgR.data = new uint8_t[jpegImgR.maxLength];
-
-  std::unique_ptr<uint8_t[]> jpegImgRData;
-  jpegImgRData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));
 
-  JpegR jpegHdr;
+  uhdr_codec_private_t* encHandle = uhdr_create_encoder();
   for (auto _ : s) {
-    status_t status =
-        jpegHdr.encodeJPEGR(&rawP010Image, &rawYuv420Image, tf, &jpegImgR, 95, nullptr);
-    if (JPEGR_NO_ERROR != status) {
-      s.SkipWithError("encodeJPEGR returned with error : " + std::to_string(status));
-      return;
-    }
+    RET_IF_ERR(uhdr_enc_set_raw_image(encHandle, &benchmark.mHdrImg, UHDR_HDR_IMG))
+    RET_IF_ERR(
+        uhdr_enc_set_using_multi_channel_gainmap(encHandle, benchmark.mUseMultiChannelGainMap))
+    RET_IF_ERR(uhdr_enc_set_gainmap_scale_factor(encHandle, benchmark.mMapDimensionScaleFactor))
+    RET_IF_ERR(uhdr_enc_set_gainmap_gamma(encHandle, benchmark.mGamma))
+    RET_IF_ERR(uhdr_encode(encHandle))
+    uhdr_reset_encoder(encHandle);
   }
+  uhdr_release_encoder(encHandle);
 }
 
-static void BM_Encode_Api2(
-    benchmark::State& s,
-    std::vector<std::tuple<std::string, std::string, std::string>> testVectors) {
-  int width = s.range(1);
-  int height = s.range(2);
-  ultrahdr_color_gamut p010Cg = static_cast<ultrahdr_color_gamut>(s.range(3));
-  ultrahdr_transfer_function tf = static_cast<ultrahdr_transfer_function>(s.range(4));
-
-  s.SetLabel(std::get<0>(testVectors[s.range(0)]) + ", " + std::get<1>(testVectors[s.range(0)]) +
-             ", " + std::get<2>(testVectors[s.range(0)]) + ", " + colorGamutToString(p010Cg) +
-             ", " + tfToString(tf) + ", " + std::to_string(width) + "x" + std::to_string(height));
-
-  std::string p010File{kTestImagesPath + "p010/" + std::get<0>(testVectors[s.range(0)])};
-
-  jpegr_uncompressed_struct rawP010Image{};
-  if (!fillRawImageHandle(&rawP010Image, width, height, p010File, p010Cg, true)) {
-    s.SkipWithError("unable to load file : " + p010File);
+static void BM_UHDREncode_Api1(benchmark::State& s, TestParamsEncoderAPI1 testVectors) {
+  EncBenchmark benchmark(testVectors);
+
+  s.SetLabel(
+      benchmark.mHdrFile + ", " + benchmark.mSdrFile + ", " + std::to_string(benchmark.mWidth) +
+      "x" + std::to_string(benchmark.mHeight) + ", hdrCg: " + colorGamutToString(benchmark.mHdrCg) +
+      ", hdrCt: " +
+      (benchmark.mHdrFile.find("rgba16F") != std::string::npos ? "linear"
+                                                               : tfToString(benchmark.mHdrCt)) +
+      ", sdrCg: " + colorGamutToString(benchmark.mSdrCg) + ", " +
+      (benchmark.mUseMultiChannelGainMap == 0 ? "singlechannelgainmap" : "multichannelgainmap") +
+      ", gamma: " + std::to_string(benchmark.mGamma) + ", " +
+      (benchmark.mEncPreset == UHDR_USAGE_BEST_QUALITY ? "best_quality" : "realtime"));
+
+  if (benchmark.mHdrFile.find("p010") != std::string::npos) {
+    benchmark.mHdrFile = kTestImagesPath + "p010/" + benchmark.mHdrFile;
+    benchmark.mHdrCf = UHDR_IMG_FMT_24bppYCbCrP010;
+  } else if (benchmark.mHdrFile.find("rgba1010102") != std::string::npos) {
+    benchmark.mHdrFile = kTestImagesPath + "rgba1010102/" + benchmark.mHdrFile;
+    benchmark.mHdrCf = UHDR_IMG_FMT_32bppRGBA1010102;
+  } else if (benchmark.mHdrFile.find("rgba16F") != std::string::npos) {
+    benchmark.mHdrFile = kTestImagesPath + "rgba16F/" + benchmark.mHdrFile;
+    benchmark.mHdrCf = UHDR_IMG_FMT_64bppRGBAHalfFloat;
+    benchmark.mHdrCt = UHDR_CT_LINEAR;
+  } else {
+    s.SkipWithError("Invalid hdr file format : " + benchmark.mHdrFile);
     return;
   }
-  std::unique_ptr<uint8_t[]> rawP010ImgData;
-  rawP010ImgData.reset(reinterpret_cast<uint8_t*>(rawP010Image.data));
-
-  std::string yuv420File{kTestImagesPath + "yuv420/" + std::get<1>(testVectors[s.range(0)])};
 
-  jpegr_uncompressed_struct rawYuv420Image{};
-  if (!fillRawImageHandle(&rawYuv420Image, width, height, yuv420File, ULTRAHDR_COLORGAMUT_P3,
-                          false)) {
-    s.SkipWithError("unable to load file : " + yuv420File);
+  if (benchmark.mSdrFile.find("yuv420") != std::string::npos) {
+    benchmark.mSdrFile = kTestImagesPath + "yuv420/" + benchmark.mSdrFile;
+    benchmark.mSdrCf = UHDR_IMG_FMT_12bppYCbCr420;
+  } else if (benchmark.mSdrFile.find("rgba8888") != std::string::npos) {
+    benchmark.mSdrFile = kTestImagesPath + "rgba8888/" + benchmark.mSdrFile;
+    benchmark.mSdrCf = UHDR_IMG_FMT_32bppRGBA8888;
+  } else {
+    s.SkipWithError("Invalid sdr file format : " + benchmark.mSdrFile);
     return;
   }
-  std::unique_ptr<uint8_t[]> rawYuv420ImgData;
-  rawYuv420ImgData.reset(reinterpret_cast<uint8_t*>(rawYuv420Image.data));
-
-  std::string yuv420JpegFile{
-      (kTestImagesPath + "yuv420jpeg/" + std::get<2>(testVectors[s.range(0)]))};
 
-  jpegr_compressed_struct yuv420JpegImage{};
-  if (!fillJpgImageHandle(&yuv420JpegImage, yuv420JpegFile, ULTRAHDR_COLORGAMUT_P3)) {
-    s.SkipWithError("unable to load file : " + yuv420JpegFile);
+  if (!benchmark.fillRawImageHandle(&benchmark.mHdrImg, benchmark.mWidth, benchmark.mHeight,
+                                    benchmark.mHdrFile, benchmark.mHdrCf, benchmark.mHdrCg,
+                                    benchmark.mHdrCt)) {
+    s.SkipWithError("unable to load file : " + benchmark.mHdrFile);
     return;
   }
-  std::unique_ptr<uint8_t[]> yuv420jpegImgData;
-  yuv420jpegImgData.reset(reinterpret_cast<uint8_t*>(yuv420JpegImage.data));
-
-  jpegr_compressed_struct jpegImgR{};
-  jpegImgR.maxLength = (std::max)(static_cast<size_t>(8 * 1024) /* min size 8kb */,
-                                  rawP010Image.width * rawP010Image.height * 3 * 2);
-  jpegImgR.data = new uint8_t[jpegImgR.maxLength];
-  if (jpegImgR.data == nullptr) {
-    s.SkipWithError("unable to allocate memory to store compressed image");
+  if (!benchmark.fillRawImageHandle(&benchmark.mSdrImg, benchmark.mWidth, benchmark.mHeight,
+                                    benchmark.mSdrFile, benchmark.mSdrCf, benchmark.mSdrCg,
+                                    benchmark.mSdrCt)) {
+    s.SkipWithError("unable to load sdr file : " + benchmark.mSdrFile);
     return;
   }
-  std::unique_ptr<uint8_t[]> jpegImgRData;
-  jpegImgRData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));
 
-  JpegR jpegHdr;
+  uhdr_codec_private_t* encHandle = uhdr_create_encoder();
   for (auto _ : s) {
-    status_t status =
-        jpegHdr.encodeJPEGR(&rawP010Image, &rawYuv420Image, &yuv420JpegImage, tf, &jpegImgR);
-    if (JPEGR_NO_ERROR != status) {
-      s.SkipWithError("encodeJPEGR returned with error : " + std::to_string(status));
-      return;
-    }
+    RET_IF_ERR(uhdr_enc_set_raw_image(encHandle, &benchmark.mHdrImg, UHDR_HDR_IMG))
+    RET_IF_ERR(uhdr_enc_set_raw_image(encHandle, &benchmark.mSdrImg, UHDR_SDR_IMG))
+    RET_IF_ERR(
+        uhdr_enc_set_using_multi_channel_gainmap(encHandle, benchmark.mUseMultiChannelGainMap))
+    RET_IF_ERR(uhdr_enc_set_gainmap_scale_factor(encHandle, benchmark.mMapDimensionScaleFactor))
+    RET_IF_ERR(uhdr_enc_set_gainmap_gamma(encHandle, benchmark.mGamma))
+    RET_IF_ERR(uhdr_enc_set_preset(encHandle, benchmark.mEncPreset))
+    RET_IF_ERR(uhdr_encode(encHandle))
+    uhdr_reset_encoder(encHandle);
   }
+  uhdr_release_encoder(encHandle);
 }
 
-static void BM_Encode_Api3(benchmark::State& s,
-                           std::vector<std::pair<std::string, std::string>> testVectors) {
-  int width = s.range(1);
-  int height = s.range(2);
-  ultrahdr_color_gamut p010Cg = static_cast<ultrahdr_color_gamut>(s.range(3));
-  ultrahdr_transfer_function tf = static_cast<ultrahdr_transfer_function>(s.range(4));
-
-  s.SetLabel(testVectors[s.range(0)].first + ", " + testVectors[s.range(0)].second + ", " +
-             colorGamutToString(p010Cg) + ", " + tfToString(tf) + ", " + std::to_string(width) +
-             "x" + std::to_string(height));
-
-  std::string p010File{kTestImagesPath + "p010/" + testVectors[s.range(0)].first};
-
-  jpegr_uncompressed_struct rawP010Image{};
-  if (!fillRawImageHandle(&rawP010Image, width, height, p010File, p010Cg, true)) {
-    s.SkipWithError("unable to load file : " + p010File);
-    return;
+void addTestVectors() {
+  for (const auto& uhdrFile : kDecodeAPITestImages) {
+    /* Decode API - uhdrFile, colorTransfer, imgFormat, enableGLES */
+    testParamsDecodeAPI.push_back({uhdrFile, UHDR_CT_HLG, UHDR_IMG_FMT_32bppRGBA1010102, false});
+    testParamsDecodeAPI.push_back({uhdrFile, UHDR_CT_PQ, UHDR_IMG_FMT_32bppRGBA1010102, false});
+    testParamsDecodeAPI.push_back(
+        {uhdrFile, UHDR_CT_LINEAR, UHDR_IMG_FMT_64bppRGBAHalfFloat, false});
+    testParamsDecodeAPI.push_back({uhdrFile, UHDR_CT_HLG, UHDR_IMG_FMT_32bppRGBA1010102, true});
+    testParamsDecodeAPI.push_back({uhdrFile, UHDR_CT_PQ, UHDR_IMG_FMT_32bppRGBA1010102, true});
+    testParamsDecodeAPI.push_back(
+        {uhdrFile, UHDR_CT_LINEAR, UHDR_IMG_FMT_64bppRGBAHalfFloat, true});
+    testParamsDecodeAPI.push_back({uhdrFile, UHDR_CT_SRGB, UHDR_IMG_FMT_32bppRGBA8888, false});
   }
-  std::unique_ptr<uint8_t[]> rawP010ImgData;
-  rawP010ImgData.reset(reinterpret_cast<uint8_t*>(rawP010Image.data));
 
-  std::string yuv420JpegFile{(kTestImagesPath + "yuv420jpeg/" + testVectors[s.range(0)].second)};
-
-  jpegr_compressed_struct yuv420JpegImage{};
-  if (!fillJpgImageHandle(&yuv420JpegImage, yuv420JpegFile, ULTRAHDR_COLORGAMUT_P3)) {
-    s.SkipWithError("unable to load file : " + yuv420JpegFile);
-    return;
-  }
-  std::unique_ptr<uint8_t[]> yuv420jpegImgData;
-  yuv420jpegImgData.reset(reinterpret_cast<uint8_t*>(yuv420JpegImage.data));
-
-  jpegr_compressed_struct jpegImgR{};
-  jpegImgR.maxLength = (std::max)(static_cast<size_t>(8 * 1024) /* min size 8kb */,
-                                  rawP010Image.width * rawP010Image.height * 3 * 2);
-  jpegImgR.data = new uint8_t[jpegImgR.maxLength];
-  if (jpegImgR.data == nullptr) {
-    s.SkipWithError("unable to allocate memory to store compressed image");
-    return;
+  for (const auto& hdrFile : kEncodeApi0TestImages12MpName) {
+    /* Encode API 0 - hdrFile, width, height, hdrColorGamut, hdrColorTransfer,
+       useMultiChannelGainmap, gamma */
+    testParamsAPI0.push_back({hdrFile, 4080, 3072, UHDR_CG_BT_2100, UHDR_CT_PQ, 0, 1.0f});
+    testParamsAPI0.push_back({hdrFile, 4080, 3072, UHDR_CG_BT_2100, UHDR_CT_PQ, 1, 1.0f});
+    testParamsAPI0.push_back({hdrFile, 4080, 3072, UHDR_CG_BT_2100, UHDR_CT_PQ, 0, 1.571f});
+    testParamsAPI0.push_back({hdrFile, 4080, 3072, UHDR_CG_BT_2100, UHDR_CT_PQ, 1, 1.616f});
   }
-  std::unique_ptr<uint8_t[]> jpegImgRData;
-  jpegImgRData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));
 
-  JpegR jpegHdr;
-  for (auto _ : s) {
-    status_t status = jpegHdr.encodeJPEGR(&rawP010Image, &yuv420JpegImage, tf, &jpegImgR);
-    if (JPEGR_NO_ERROR != status) {
-      s.SkipWithError("encodeJPEGR returned with error : " + std::to_string(status));
-      return;
-    }
+  for (const auto& inputFiles : kEncodeApi1TestImages12MpName) {
+    /* Encode API 1 - hdrFile, sdrFile, width, height, hdrColorGamut, hdrColorTransfer,
+       sdrColorGamut, useMultiChannelGainmap, gamma, encPreset */
+    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
+                              UHDR_CT_PQ, UHDR_CG_BT_709, 0, 1.0f, UHDR_USAGE_REALTIME});
+    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
+                              UHDR_CT_PQ, UHDR_CG_BT_709, 1, 1.0f, UHDR_USAGE_REALTIME});
+    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
+                              UHDR_CT_PQ, UHDR_CG_BT_709, 0, 1.571f, UHDR_USAGE_REALTIME});
+    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
+                              UHDR_CT_PQ, UHDR_CG_BT_709, 0, 1.0f, UHDR_USAGE_BEST_QUALITY});
+    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
+                              UHDR_CT_PQ, UHDR_CG_BT_709, 1, 1.571f, UHDR_USAGE_REALTIME});
+    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
+                              UHDR_CT_PQ, UHDR_CG_BT_709, 1, 1.0f, UHDR_USAGE_BEST_QUALITY});
+    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
+                              UHDR_CT_PQ, UHDR_CG_BT_709, 0, 1.571f, UHDR_USAGE_BEST_QUALITY});
+    testParamsAPI1.push_back({inputFiles.first, inputFiles.second, 4080, 3072, UHDR_CG_BT_2100,
+                              UHDR_CT_PQ, UHDR_CG_BT_709, 1, 1.571f, UHDR_USAGE_BEST_QUALITY});
   }
 }
 
-static void BM_Encode_Api4(benchmark::State& s) {
-  std::string srcFileName = kTestImagesPath + "jpegr/" + kDecodeAPITestImages[s.range(0)];
-
-  std::ifstream ifd(srcFileName.c_str(), std::ios::binary | std::ios::ate);
-  if (!ifd.good()) {
-    s.SkipWithError("unable to open file " + srcFileName);
-    return;
+void registerBenchmarks() {
+  for (auto& param : testParamsDecodeAPI) {
+    benchmark::RegisterBenchmark("BM_UHDRDecode", BM_UHDRDecode, param)
+        ->Unit(benchmark::kMillisecond);
   }
-  int size = ifd.tellg();
-
-  jpegr_compressed_struct inpJpegImgR{};
-  inpJpegImgR.length = size;
-  inpJpegImgR.maxLength = size;
-  inpJpegImgR.data = nullptr;
-  inpJpegImgR.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-  ifd.close();
-  if (!loadFile(srcFileName.c_str(), inpJpegImgR.data, size)) {
-    s.SkipWithError("unable to load file " + srcFileName);
-    return;
+  for (auto& param : testParamsAPI0) {
+    benchmark::RegisterBenchmark("BM_UHDREncode_Api0", BM_UHDREncode_Api0, param)
+        ->Unit(benchmark::kMillisecond);
   }
-  std::unique_ptr<uint8_t[]> inpJpegImgRData;
-  inpJpegImgRData.reset(reinterpret_cast<uint8_t*>(inpJpegImgR.data));
-
-  JpegR jpegHdr;
-  jpeg_info_struct primaryImgInfo;
-  jpeg_info_struct gainmapImgInfo;
-  jpegr_info_struct info{};
-  info.primaryImgInfo = &primaryImgInfo;
-  info.gainmapImgInfo = &gainmapImgInfo;
-  status_t status = jpegHdr.getJPEGRInfo(&inpJpegImgR, &info);
-  if (JPEGR_NO_ERROR != status) {
-    s.SkipWithError("getJPEGRInfo returned with error " + std::to_string(status));
-    return;
-  }
-
-  jpegr_compressed_struct jpegImgR{};
-  jpegImgR.maxLength = (std::max)(static_cast<size_t>(8 * 1024) /* min size 8kb */,
-                                  info.width * info.height * 3 * 2);
-  jpegImgR.data = new uint8_t[jpegImgR.maxLength];
-  if (jpegImgR.data == nullptr) {
-    s.SkipWithError("unable to allocate memory to store compressed image");
-    return;
-  }
-  std::unique_ptr<uint8_t[]> jpegImgRData;
-  jpegImgRData.reset(reinterpret_cast<uint8_t*>(jpegImgR.data));
-
-  jpegr_compressed_struct primaryImg;
-  primaryImg.data = primaryImgInfo.imgData.data();
-  primaryImg.maxLength = primaryImg.length = primaryImgInfo.imgData.size();
-  primaryImg.colorGamut = static_cast<ultrahdr_color_gamut>(s.range(1));
-  jpegr_compressed_struct gainmapImg;
-  gainmapImg.data = gainmapImgInfo.imgData.data();
-  gainmapImg.maxLength = gainmapImg.length = gainmapImgInfo.imgData.size();
-  gainmapImg.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-  uhdr_gainmap_metadata_ext_t meta;
-  if (getMetadataFromXMP(gainmapImgInfo.xmpData.data(), gainmapImgInfo.xmpData.size(), &meta)
-          .error_code != UHDR_CODEC_OK) {
-    s.SkipWithError("getMetadataFromXMP returned with error");
-    return;
+  for (auto& param : testParamsAPI1) {
+    benchmark::RegisterBenchmark("BM_UHDREncode_Api1", BM_UHDREncode_Api1, param)
+        ->Unit(benchmark::kMillisecond);
   }
-  ultrahdr_metadata_struct uhdr_metadata;
-  uhdr_metadata.version = meta.version;
-  uhdr_metadata.hdrCapacityMax = meta.hdr_capacity_max;
-  uhdr_metadata.hdrCapacityMin = meta.hdr_capacity_min;
-  uhdr_metadata.gamma = meta.gamma;
-  uhdr_metadata.offsetSdr = meta.offset_sdr;
-  uhdr_metadata.offsetHdr = meta.offset_hdr;
-  uhdr_metadata.maxContentBoost = meta.max_content_boost;
-  uhdr_metadata.minContentBoost = meta.min_content_boost;
-  for (auto _ : s) {
-    status = jpegHdr.encodeJPEGR(&primaryImg, &gainmapImg, &uhdr_metadata, &jpegImgR);
-    if (JPEGR_NO_ERROR != status) {
-      s.SkipWithError("encodeJPEGR returned with error " + std::to_string(status));
-      return;
-    }
-  }
-
-  s.SetLabel(srcFileName + ", " + std::to_string(info.width) + "x" + std::to_string(info.height));
 }
 
-BENCHMARK(BM_Decode)
-    ->ArgsProduct({{benchmark::CreateDenseRange(0, kDecodeAPITestImages.size() - 1, 1)},
-                   {ULTRAHDR_OUTPUT_HDR_HLG, ULTRAHDR_OUTPUT_HDR_PQ, ULTRAHDR_OUTPUT_SDR}})
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK_CAPTURE(BM_Encode_Api0, TestVectorName, kEncodeApi0TestImages12MpName)
-    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi0TestImages12MpName.size() - 1, 1)},
-                   {4080},
-                   {3072},
-                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-                   {
-                       ULTRAHDR_TF_HLG,
-                       ULTRAHDR_TF_PQ,
-                   }})
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK_CAPTURE(BM_Encode_Api0, TestVectorName, kEncodeApi0TestImages3MpName)
-    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi0TestImages3MpName.size() - 1, 1)},
-                   {2048},
-                   {1536},
-                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-                   {
-                       ULTRAHDR_TF_HLG,
-                       ULTRAHDR_TF_PQ,
-                   }})
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK_CAPTURE(BM_Encode_Api1, TestVectorName, kEncodeApi1TestImages12MpName)
-    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi1TestImages12MpName.size() - 1, 1)},
-                   {4080},
-                   {3072},
-                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-                   {
-                       ULTRAHDR_TF_HLG,
-                       ULTRAHDR_TF_PQ,
-                   }})
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK_CAPTURE(BM_Encode_Api1, TestVectorName, kEncodeApi1TestImages3MpName)
-    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi1TestImages3MpName.size() - 1, 1)},
-                   {2048},
-                   {1536},
-                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-                   {
-                       ULTRAHDR_TF_HLG,
-                       ULTRAHDR_TF_PQ,
-                   }})
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK_CAPTURE(BM_Encode_Api2, TestVectorName, kEncodeApi2TestImages12MpName)
-    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi2TestImages12MpName.size() - 1, 1)},
-                   {4080},
-                   {3072},
-                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-                   {
-                       ULTRAHDR_TF_HLG,
-                       ULTRAHDR_TF_PQ,
-                   }})
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK_CAPTURE(BM_Encode_Api2, TestVectorName, kEncodeApi2TestImages3MpName)
-    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi2TestImages3MpName.size() - 1, 1)},
-                   {2048},
-                   {1536},
-                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-                   {
-                       ULTRAHDR_TF_HLG,
-                       ULTRAHDR_TF_PQ,
-                   }})
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK_CAPTURE(BM_Encode_Api3, TestVectorName, kEncodeApi3TestImages12MpName)
-    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi3TestImages12MpName.size() - 1, 1)},
-                   {4080},
-                   {3072},
-                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-                   {
-                       ULTRAHDR_TF_HLG,
-                       ULTRAHDR_TF_PQ,
-                   }})
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK_CAPTURE(BM_Encode_Api3, TestVectorName, kEncodeApi3TestImages3MpName)
-    ->ArgsProduct({{benchmark::CreateDenseRange(0, kEncodeApi3TestImages3MpName.size() - 1, 1)},
-                   {2048},
-                   {1536},
-                   {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-                   {
-                       ULTRAHDR_TF_HLG,
-                       ULTRAHDR_TF_PQ,
-                   }})
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK(BM_Encode_Api4)
-    ->ArgsProduct({
-        {benchmark::CreateDenseRange(0, kEncodeApi4TestImages12MpName.size() - 1, 1)},
-        {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-    })
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK(BM_Encode_Api4)
-    ->ArgsProduct({
-        {benchmark::CreateDenseRange(0, kEncodeApi4TestImages3MpName.size() - 1, 1)},
-        {ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100},
-    })
-    ->Unit(benchmark::kMillisecond);
-
-BENCHMARK_MAIN();
+int main(int argc, char** argv) {
+  addTestVectors();
+  registerBenchmarks();
+  benchmark::Initialize(&argc, argv);
+  benchmark::RunSpecifiedBenchmarks(nullptr, nullptr);
+  benchmark::Shutdown();
+  return 0;
+}
diff --git a/cmake/package.cmake b/cmake/package.cmake
new file mode 100644
index 0000000..2e3649a
--- /dev/null
+++ b/cmake/package.cmake
@@ -0,0 +1,58 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License"); you may not
+# use this file except in compliance with the License. You may obtain a copy of
+# the License at
+#
+# http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+# License for the specific language governing permissions and limitations under
+# the License.
+#
+
+# common package configuration
+set(CPACK_PACKAGE_NAME ${CMAKE_PROJECT_NAME})
+set(CPACK_PACKAGE_VENDOR "Google, Inc.")
+set(CPACK_PACKAGE_CONTACT "Dichen Zhang <dichenzhang@google.com>")
+set(CPACK_PACKAGE_VERSION_MAJOR ${UHDR_MAJOR_VERSION})
+set(CPACK_PACKAGE_VERSION_MINOR ${UHDR_MINOR_VERSION})
+set(CPACK_PACKAGE_VERSION_PATCH ${UHDR_PATCH_VERSION})
+set(CPACK_PACKAGE_VERSION "${UHDR_MAJOR_VERSION}.${UHDR_MINOR_VERSION}.${UHDR_PATCH_VERSION}")
+set(CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_SOURCE_DIR}/DESCRIPTION)
+set(CPACK_PACKAGE_DESCRIPTION_SUMMARY ${CMAKE_PROJECT_DESCRIPTION})
+set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/google/libultrahdr")
+if("${CMAKE_SYSTEM_NAME}" STREQUAL "")
+  message(FATAL_ERROR "Failed to determine CPACK_SYSTEM_NAME. Is CMAKE_SYSTEM_NAME set?" )
+endif()
+string(TOLOWER "${CMAKE_SYSTEM_NAME}" CPACK_SYSTEM_NAME)
+set(CPACK_PACKAGE_ARCHITECTURE ${ARCH})
+set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_SYSTEM_NAME}")
+set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_FILE_NAME}-${CPACK_PACKAGE_ARCHITECTURE}")
+set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_SOURCE_DIR}/LICENSE)
+set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
+
+# platform specific configuration
+if(APPLE)
+  set(CPACK_GENERATOR "DragNDrop")
+elseif(UNIX)
+  if(EXISTS "/etc/debian_version")
+    set(CPACK_GENERATOR "DEB")
+    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
+    set(CPACK_DEBIAN_PACKAGE_RELEASE 1)
+    set(CPACK_DEBIAN_PACKAGE_HOMEPAGE ${CPACK_PACKAGE_HOMEPAGE_URL})
+  elseif(EXISTS "/etc/redhat-release")
+    set(CPACK_GENERATOR "RPM")
+    set(CPACK_RPM_PACKAGE_ARCHITECTURE ${CPACK_PACKAGE_ARCHITECTURE})
+    set(CPACK_RPM_PACKAGE_RELEASE 1)
+    set(CPACK_RPM_PACKAGE_LICENSE "Apache 2.0")
+    set(CPACK_RPM_PACKAGE_URL ${CPACK_PACKAGE_HOMEPAGE_URL})
+  else()
+    set(CPACK_GENERATOR "TGZ")
+  endif()
+else()
+  set(CPACK_GENERATOR "ZIP")
+endif()
diff --git a/cmake/toolchains/loong64-linux-gnu.cmake b/cmake/toolchains/loong64-linux-gnu.cmake
new file mode 100644
index 0000000..721a07f
--- /dev/null
+++ b/cmake/toolchains/loong64-linux-gnu.cmake
@@ -0,0 +1,43 @@
+#
+# Copyright (C) 2023 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License"); you may not
+# use this file except in compliance with the License. You may obtain a copy of
+# the License at
+#
+# http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+# License for the specific language governing permissions and limitations under
+# the License.
+#
+
+if(UHDR_BUILD_CMAKE_TOOLCHAINS_LOONG64_LINUX_GNU_CMAKE_)
+  return()
+endif()
+
+set(UHDR_BUILD_CMAKE_TOOLCHAINS_LOONG64_LINUX_GNU_CMAKE_ 1)
+
+set(CMAKE_SYSTEM_NAME "Linux")
+set(CMAKE_SYSTEM_PROCESSOR "loongarch64")
+
+if("${CROSS}" STREQUAL "")
+  set(CROSS loongarch64-linux-gnu-)
+endif()
+
+if(NOT CMAKE_C_COMPILER)
+  set(CMAKE_C_COMPILER ${CROSS}gcc)
+endif()
+if(NOT CMAKE_CXX_COMPILER)
+  set(CMAKE_CXX_COMPILER ${CROSS}g++)
+endif()
+if(NOT AS_EXECUTABLE)
+  set(AS_EXECUTABLE ${CROSS}as)
+endif()
+
+set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
+set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
diff --git a/cmake/toolchains/riscv32-linux-gnu.cmake b/cmake/toolchains/riscv32-linux-gnu.cmake
new file mode 100644
index 0000000..fd5594e
--- /dev/null
+++ b/cmake/toolchains/riscv32-linux-gnu.cmake
@@ -0,0 +1,43 @@
+#
+# Copyright (C) 2023 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License"); you may not
+# use this file except in compliance with the License. You may obtain a copy of
+# the License at
+#
+# http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+# License for the specific language governing permissions and limitations under
+# the License.
+#
+
+if(UHDR_BUILD_CMAKE_TOOLCHAINS_RISCV32_LINUX_GNU_CMAKE_)
+  return()
+endif()
+
+set(UHDR_BUILD_CMAKE_TOOLCHAINS_RISCV32_LINUX_GNU_CMAKE_ 1)
+
+set(CMAKE_SYSTEM_NAME "Linux")
+set(CMAKE_SYSTEM_PROCESSOR "riscv32")
+
+if("${CROSS}" STREQUAL "")
+  set(CROSS riscv32-linux-gnu-)
+endif()
+
+if(NOT CMAKE_C_COMPILER)
+  set(CMAKE_C_COMPILER ${CROSS}gcc)
+endif()
+if(NOT CMAKE_CXX_COMPILER)
+  set(CMAKE_CXX_COMPILER ${CROSS}g++)
+endif()
+if(NOT AS_EXECUTABLE)
+  set(AS_EXECUTABLE ${CROSS}as)
+endif()
+
+set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
+set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
diff --git a/docs/building.md b/docs/building.md
index 2c5db9d..bb2a3cf 100644
--- a/docs/building.md
+++ b/docs/building.md
@@ -4,11 +4,11 @@
 [![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_mac.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_mac.yml?query=event%3Apush)
 [![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_win.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_win.yml?query=event%3Apush)
 [![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_android.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_android.yml?query=event%3Apush)
-[![Fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/libultrahdr.svg)](https://oss-fuzz-build-logs.storage.googleapis.com/index.html#libultrahdr)
+[![Fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/libultrahdr.svg)](https://introspector.oss-fuzz.com/project-profile?project=libultrahdr)
 
 ### Requirements
 
-- [CMake](http://www.cmake.org) v3.13 or later
+- [CMake](http://www.cmake.org) v3.15 or later
 - C++ compiler, supporting at least C++17.
 - libultrahdr uses jpeg compression format to store sdr image and gainmap quotient.
   So, libjpeg or any other jpeg codec that is ABI and API compatible with libjpeg.
@@ -52,18 +52,20 @@ Following is a list of available options:
 |:-------------|:--------------|:-----|
 | `CMAKE_BUILD_TYPE` | Release | See CMake documentation [here](https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html). |
 | `BUILD_SHARED_LIBS` | ON | See CMake documentation [here](https://cmake.org/cmake/help/latest/variable/BUILD_SHARED_LIBS.html). <ul><li> If `BUILD_SHARED_LIBS` is **OFF**, in the linking phase, static versions of dependencies are chosen. However, the executable targets are not purely static because the system libraries used are still dynamic. </li></ul> |
-| `UHDR_BUILD_EXAMPLES` | ON | Build sample application. This application demonstrates how to use [ultrahdr_api.h](ultrahdr_api.h). |
+| `UHDR_BUILD_EXAMPLES` | ON | Build sample application. This application demonstrates how to use [ultrahdr_api.h](../ultrahdr_api.h). |
 | `UHDR_BUILD_TESTS` | OFF | Build Unit Tests. Mostly for Devs. During development, different modules of libuhdr library are validated using GoogleTest framework. Developers after making changes to library are expected to run these tests to ensure every thing is functional. |
-| `UHDR_BUILD_BENCHMARK` | OFF | Build Benchmark Tests. These are for profiling libuhdr encode/decode API. Resources used by benchmark tests are shared [here](https://storage.googleapis.com/android_media/external/libultrahdr/benchmark/UltrahdrBenchmarkTestRes-1.0.zip). These are downloaded and extracted automatically during the build process for later benchmarking. <ul><li> Since [v1.0.0](https://github.com/google/libultrahdr/releases/tag/1.0.0), considerable API changes were made and benchmark tests need to be updated accordingly. So the current profile numbers may not be accurate and/or give a complete picture. </li><li> Benchmark tests are not supported on Windows and this parameter is forced to **OFF** internally while building on **WIN32** platforms. </li></ul>|
+| `UHDR_BUILD_BENCHMARK` | OFF | Build Benchmark Tests. These are for profiling libuhdr encode/decode API. Resources used by benchmark tests are shared [here](https://storage.googleapis.com/android_media/external/libultrahdr/benchmark/UltrahdrBenchmarkTestRes-1.1.zip). These are downloaded and extracted automatically during the build process for later benchmarking. <ul><li> Benchmark tests are not supported on Windows and this parameter is forced to **OFF** internally while building on **WIN32** platforms. </li></ul>|
 | `UHDR_BUILD_FUZZERS` | OFF | Build Fuzz Test Applications. Mostly for Devs. <ul><li> Fuzz applications are built by instrumenting the entire software suite. This includes dependency libraries. This is done by forcing `UHDR_BUILD_DEPS` to **ON** internally. </li></ul> |
 | `UHDR_BUILD_DEPS` | OFF | Clone and Build project dependencies and not use pre-installed packages. |
+| `UHDR_BUILD_JAVA` | OFF | Build JNI wrapper, Java front-end classes and Java sample application. |
 | `UHDR_ENABLE_LOGS` | OFF | Build with verbose logging. |
 | `UHDR_ENABLE_INSTALL` | ON | Enable install and uninstall targets for libuhdr package. <ul><li> For system wide installation it is best if dependencies are acquired from OS package manager instead of building from source. This is to avoid conflicts with software that is using a different version of the said dependency and also links to libuhdr. So if `UHDR_BUILD_DEPS` is **ON** then `UHDR_ENABLE_INSTALL` is forced to **OFF** internally. |
 | `UHDR_ENABLE_INTRINSICS` | ON | Build with SIMD acceleration. Sections of libuhdr are accelerated for Arm Neon architectures and these are enabled. <ul><li> For x86/x86_64 architectures currently no SIMD acceleration is present. Consequently this option has no effect. </li><li> This parameter has no effect no SIMD configuration settings of dependencies. </li></ul> |
 | `UHDR_ENABLE_GLES` | OFF | Build with GPU acceleration. |
+| `UHDR_ENABLE_WERROR` | OFF | Enable -Werror when building. |
 | `UHDR_MAX_DIMENSION` | 8192 | Maximum dimension supported by the library. The library defaults to handling images upto resolution 8192x8192. For different resolution needs use this option. For example, `-DUHDR_MAX_DIMENSION=4096`. |
-| `UHDR_BUILD_JAVA` | OFF | Build JNI wrapper, Java front-end classes and Java sample application. |
 | `UHDR_SANITIZE_OPTIONS` | OFF | Build library with sanitize options. Values set to this parameter are passed to directly to compilation option `-fsanitize`. For example, `-DUHDR_SANITIZE_OPTIONS=address,undefined` adds `-fsanitize=address,undefined` to the list of compilation options. CMake configuration errors are raised if the compiler does not support these flags. This is useful during fuzz testing. <ul><li> As `-fsanitize` is an instrumentation option, dependencies are also built from source instead of using pre-builts. This is done by forcing `UHDR_BUILD_DEPS` to **ON** internally. </li></ul> |
+| `UHDR_BUILD_PACKAGING` | OFF | Build distribution packages using CPack. |
 | | | |
 
 ### Generator
@@ -159,12 +161,12 @@ Uninstallation:
 sudo ninja uninstall
 ```
 
-### Windows Platform - MSYS Env
+### Windows Platform - MSYS2 Env
 
 Install the prerequisite packages before building:
 
 ```sh
-pacman -S mingw-w64-x86_64-libjpeg-turbo mingw-w64-x86_64-ninja
+pacman -S mingw-w64-ucrt-x86_64-libjpeg-turbo mingw-w64-ucrt-x86_64-ninja
 ```
 
 Compile and Test:
@@ -269,6 +271,46 @@ This will generate the following files under `build_directory`:
 **ultrahdr_app** - sample application <br>
 **ultrahdr_unit_test** - unit tests <br>
 
+#### Target - Linux Platform - RISC-V Arch (32 bit)
+
+Install the prerequisite packages before building:
+
+```sh
+# Download from https://github.com/riscv-collab/riscv-gnu-toolchain/releases
+sudo ln -s {your_dir}/riscv/bin/riscv32-unknown-linux-gnu-g++ /usr/bin/riscv32-linux-gnu-g++
+sudo ln -s {your_dir}/riscv/bin/riscv32-unknown-linux-gnu-gcc /usr/bin/riscv32-linux-gnu-gcc
+```
+
+Compile:
+
+```sh
+cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/riscv32-linux-gnu.cmake -DUHDR_BUILD_DEPS=1 ../
+ninja
+```
+
+This will generate the following files under `build_directory`:
+
+**libuhdr.so.{version}** - Shared library for the libuhdr API <br>
+**libuhdr.so** - Symlink to shared library <br>
+**libuhdr.a** - Static link library for the libuhdr API <br>
+**ultrahdr_app** - sample application <br>
+**ultrahdr_unit_test** - unit tests <br>
+
+#### Target - Linux Platform - LOONG Arch (64 bit)
+
+Install the prerequisite packages before building:
+
+```sh
+sudo apt install gcc-loongarch64-linux-gnu g++-loongarch64-linux-gnu
+```
+
+Compile:
+
+```sh
+cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/loong64-linux-gnu.cmake -DUHDR_BUILD_DEPS=1 ../
+ninja
+```
+
 #### Target - Android Platform
 
 Install the prerequisite packages before building:
@@ -293,6 +335,21 @@ This will generate the following files under `build_directory`:
 **ultrahdr_app** - sample application <br>
 **ultrahdr_unit_test** - unit tests <br>
 
+#### Target - Wasm
+
+Install the prerequisite packages before building: Follow the instructions given [here](https://emscripten.org/docs/getting_started/downloads.html#installation-instructions-using-the-emsdk-recommended).
+
+Compile:
+```sh
+emcmake cmake -G Ninja ../
+ninja
+```
+
+This will generate the following files under `build_directory`:
+
+**ultrahdr_app.wasm** - wasm module <br>
+**ultrahdr_app.js** - sample application <br>
+
 ## Building Fuzzers
 
 Refer to [fuzzers.md](fuzzers.md) for complete instructions.
diff --git a/examples/ultrahdr_app.cpp b/examples/ultrahdr_app.cpp
index 90f83ba..e963f81 100644
--- a/examples/ultrahdr_app.cpp
+++ b/examples/ultrahdr_app.cpp
@@ -33,33 +33,40 @@
 #include "ultrahdr_api.h"
 
 const float BT601YUVtoRGBMatrix[9] = {
-    1, 0, 1.402, 1, (-0.202008 / 0.587), (-0.419198 / 0.587), 1.0, 1.772, 0.0};
+    1.f, 0.f, 1.402f, 1.f, (-0.202008f / 0.587f), (-0.419198f / 0.587f), 1.0f, 1.772f, 0.0f};
 const float BT709YUVtoRGBMatrix[9] = {
-    1, 0, 1.5748, 1, (-0.13397432 / 0.7152), (-0.33480248 / 0.7152), 1.0, 1.8556, 0.0};
+    1.f,  0.f,     1.5748f, 1.f, (-0.13397432f / 0.7152f), (-0.33480248f / 0.7152f),
+    1.0f, 1.8556f, 0.0f};
 const float BT2020YUVtoRGBMatrix[9] = {
-    1, 0, 1.4746, 1, (-0.11156702 / 0.6780), (-0.38737742 / 0.6780), 1, 1.8814, 0};
-
-const float BT601RGBtoYUVMatrix[9] = {
-    0.299,           0.587, 0.114, (-0.299 / 1.772), (-0.587 / 1.772), 0.5, 0.5, (-0.587 / 1.402),
-    (-0.114 / 1.402)};
-const float BT709RGBtoYUVMatrix[9] = {0.2126,
-                                      0.7152,
-                                      0.0722,
-                                      (-0.2126 / 1.8556),
-                                      (-0.7152 / 1.8556),
-                                      0.5,
-                                      0.5,
-                                      (-0.7152 / 1.5748),
-                                      (-0.0722 / 1.5748)};
-const float BT2020RGBtoYUVMatrix[9] = {0.2627,
-                                       0.6780,
-                                       0.0593,
-                                       (-0.2627 / 1.8814),
-                                       (-0.6780 / 1.8814),
-                                       0.5,
-                                       0.5,
-                                       (-0.6780 / 1.4746),
-                                       (-0.0593 / 1.4746)};
+    1.f, 0.f, 1.4746f, 1.f, (-0.11156702f / 0.6780f), (-0.38737742f / 0.6780f), 1.f, 1.8814f, 0.f};
+
+const float BT601RGBtoYUVMatrix[9] = {0.299f,
+                                      0.587f,
+                                      0.114f,
+                                      (-0.299f / 1.772f),
+                                      (-0.587f / 1.772f),
+                                      0.5f,
+                                      0.5f,
+                                      (-0.587f / 1.402f),
+                                      (-0.114f / 1.402f)};
+const float BT709RGBtoYUVMatrix[9] = {0.2126f,
+                                      0.7152f,
+                                      0.0722f,
+                                      (-0.2126f / 1.8556f),
+                                      (-0.7152f / 1.8556f),
+                                      0.5f,
+                                      0.5f,
+                                      (-0.7152f / 1.5748f),
+                                      (-0.0722f / 1.5748f)};
+const float BT2020RGBtoYUVMatrix[9] = {0.2627f,
+                                       0.6780f,
+                                       0.0593f,
+                                       (-0.2627f / 1.8814f),
+                                       (-0.6780f / 1.8814f),
+                                       0.5f,
+                                       0.5f,
+                                       (-0.6780f / 1.4746f),
+                                       (-0.0593f / 1.4746f)};
 
 // remove these once introduced in ultrahdr_api.h
 const int UHDR_IMG_FMT_48bppYCbCr444 = 101;
@@ -105,7 +112,7 @@ class Profiler {
 
   void timerStop() { QueryPerformanceCounter(&mEndingTime); }
 
-  int64_t elapsedTime() {
+  double elapsedTime() {
     LARGE_INTEGER frequency;
     LARGE_INTEGER elapsedMicroseconds;
     QueryPerformanceFrequency(&frequency);
@@ -145,10 +152,15 @@ class Profiler {
     return false;                                                                               \
   }
 
-static bool loadFile(const char* filename, void*& result, int length) {
+static bool loadFile(const char* filename, void*& result, std::streamoff length) {
+  if (length <= 0) {
+    std::cerr << "requested to read invalid length : " << length
+              << " bytes from file : " << filename << std::endl;
+    return false;
+  }
   std::ifstream ifd(filename, std::ios::binary | std::ios::ate);
   if (ifd.good()) {
-    int size = ifd.tellg();
+    auto size = ifd.tellg();
     if (size < length) {
       std::cerr << "requested to read " << length << " bytes from file : " << filename
                 << ", file contains only " << size << " bytes" << std::endl;
@@ -172,19 +184,23 @@ static bool loadFile(const char* filename, uhdr_raw_image_t* handle) {
   std::ifstream ifd(filename, std::ios::binary);
   if (ifd.good()) {
     if (handle->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
-      const int bpp = 2;
-      READ_BYTES(ifd, handle->planes[UHDR_PLANE_Y], handle->w * handle->h * bpp)
-      READ_BYTES(ifd, handle->planes[UHDR_PLANE_UV], (handle->w / 2) * (handle->h / 2) * bpp * 2)
+      const size_t bpp = 2;
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_Y], bpp * handle->w * handle->h)
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_UV], bpp * (handle->w / 2) * (handle->h / 2) * 2)
       return true;
     } else if (handle->fmt == UHDR_IMG_FMT_32bppRGBA1010102 ||
                handle->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
-      const int bpp = 4;
-      READ_BYTES(ifd, handle->planes[UHDR_PLANE_PACKED], handle->w * handle->h * bpp)
+      const size_t bpp = 4;
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_PACKED], bpp * handle->w * handle->h)
+      return true;
+    } else if (handle->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+      const size_t bpp = 8;
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_PACKED], bpp * handle->w * handle->h)
       return true;
     } else if (handle->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
-      READ_BYTES(ifd, handle->planes[UHDR_PLANE_Y], handle->w * handle->h)
-      READ_BYTES(ifd, handle->planes[UHDR_PLANE_U], (handle->w / 2) * (handle->h / 2))
-      READ_BYTES(ifd, handle->planes[UHDR_PLANE_V], (handle->w / 2) * (handle->h / 2))
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_Y], (size_t)handle->w * handle->h)
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_U], (size_t)(handle->w / 2) * (handle->h / 2))
+      READ_BYTES(ifd, handle->planes[UHDR_PLANE_V], (size_t)(handle->w / 2) * (handle->h / 2))
       return true;
     }
     return false;
@@ -193,7 +209,7 @@ static bool loadFile(const char* filename, uhdr_raw_image_t* handle) {
   return false;
 }
 
-static bool writeFile(const char* filename, void*& result, int length) {
+static bool writeFile(const char* filename, void*& result, size_t length) {
   std::ofstream ofd(filename, std::ios::binary);
   if (ofd.is_open()) {
     ofd.write(static_cast<char*>(result), length);
@@ -209,7 +225,7 @@ static bool writeFile(const char* filename, uhdr_raw_image_t* img) {
     if (img->fmt == UHDR_IMG_FMT_32bppRGBA8888 || img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ||
         img->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
       char* data = static_cast<char*>(img->planes[UHDR_PLANE_PACKED]);
-      int bpp = img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
+      const size_t bpp = img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
       const size_t stride = img->stride[UHDR_PLANE_PACKED] * bpp;
       const size_t length = img->w * bpp;
       for (unsigned i = 0; i < img->h; i++, data += stride) {
@@ -219,7 +235,7 @@ static bool writeFile(const char* filename, uhdr_raw_image_t* img) {
     } else if ((int)img->fmt == UHDR_IMG_FMT_24bppYCbCr444 ||
                (int)img->fmt == UHDR_IMG_FMT_48bppYCbCr444) {
       char* data = static_cast<char*>(img->planes[UHDR_PLANE_Y]);
-      int bpp = (int)img->fmt == UHDR_IMG_FMT_48bppYCbCr444 ? 2 : 1;
+      const size_t bpp = (int)img->fmt == UHDR_IMG_FMT_48bppYCbCr444 ? 2 : 1;
       size_t stride = img->stride[UHDR_PLANE_Y] * bpp;
       size_t length = img->w * bpp;
       for (unsigned i = 0; i < img->h; i++, data += stride) {
@@ -248,8 +264,7 @@ class UltraHdrAppInput {
   UltraHdrAppInput(const char* hdrIntentRawFile, const char* sdrIntentRawFile,
                    const char* sdrIntentCompressedFile, const char* gainmapCompressedFile,
                    const char* gainmapMetadataCfgFile, const char* exifFile, const char* outputFile,
-                   size_t width, size_t height,
-                   uhdr_img_fmt_t hdrCf = UHDR_IMG_FMT_32bppRGBA1010102,
+                   int width, int height, uhdr_img_fmt_t hdrCf = UHDR_IMG_FMT_32bppRGBA1010102,
                    uhdr_img_fmt_t sdrCf = UHDR_IMG_FMT_32bppRGBA8888,
                    uhdr_color_gamut_t hdrCg = UHDR_CG_DISPLAY_P3,
                    uhdr_color_gamut_t sdrCg = UHDR_CG_BT_709,
@@ -259,7 +274,8 @@ class UltraHdrAppInput {
                    int gainmapScaleFactor = 1, int gainmapQuality = 95,
                    bool enableMultiChannelGainMap = true, float gamma = 1.0f,
                    bool enableGLES = false, uhdr_enc_preset_t encPreset = UHDR_USAGE_BEST_QUALITY,
-                   float minContentBoost = FLT_MIN, float maxContentBoost = FLT_MAX)
+                   float minContentBoost = FLT_MIN, float maxContentBoost = FLT_MAX,
+                   float targetDispPeakBrightness = -1.0f)
       : mHdrIntentRawFile(hdrIntentRawFile),
         mSdrIntentRawFile(sdrIntentRawFile),
         mSdrIntentCompressedFile(sdrIntentCompressedFile),
@@ -287,6 +303,7 @@ class UltraHdrAppInput {
         mEncPreset(encPreset),
         mMinContentBoost(minContentBoost),
         mMaxContentBoost(maxContentBoost),
+        mTargetDispPeakBrightness(targetDispPeakBrightness),
         mMode(0){};
 
   UltraHdrAppInput(const char* gainmapMetadataCfgFile, const char* uhdrFile, const char* outputFile,
@@ -310,7 +327,7 @@ class UltraHdrAppInput {
         mQuality(95),
         mOTf(oTf),
         mOfmt(oFmt),
-        mFullRange(UHDR_CR_UNSPECIFIED),
+        mFullRange(false),
         mMapDimensionScaleFactor(1),
         mMapCompressQuality(95),
         mUseMultiChannelGainMap(true),
@@ -319,6 +336,7 @@ class UltraHdrAppInput {
         mEncPreset(UHDR_USAGE_BEST_QUALITY),
         mMinContentBoost(FLT_MIN),
         mMaxContentBoost(FLT_MAX),
+        mTargetDispPeakBrightness(-1.0f),
         mMode(1){};
 
   ~UltraHdrAppInput() {
@@ -332,6 +350,10 @@ class UltraHdrAppInput {
         free(mRawRgba1010102Image.planes[i]);
         mRawRgba1010102Image.planes[i] = nullptr;
       }
+      if (mRawRgbaF16Image.planes[i]) {
+        free(mRawRgbaF16Image.planes[i]);
+        mRawRgbaF16Image.planes[i] = nullptr;
+      }
       if (mRawYuv420Image.planes[i]) {
         free(mRawYuv420Image.planes[i]);
         mRawYuv420Image.planes[i] = nullptr;
@@ -356,6 +378,7 @@ class UltraHdrAppInput {
   bool fillUhdrImageHandle();
   bool fillP010ImageHandle();
   bool fillRGBA1010102ImageHandle();
+  bool fillRGBAF16ImageHandle();
   bool convertP010ToRGBImage();
   bool fillYuv420ImageHandle();
   bool fillRGBA8888ImageHandle();
@@ -393,7 +416,7 @@ class UltraHdrAppInput {
   const uhdr_color_transfer_t mOTf;
   const uhdr_img_fmt_t mOfmt;
   const bool mFullRange;
-  const size_t mMapDimensionScaleFactor;
+  const int mMapDimensionScaleFactor;
   const int mMapCompressQuality;
   const bool mUseMultiChannelGainMap;
   const float mGamma;
@@ -401,10 +424,12 @@ class UltraHdrAppInput {
   const uhdr_enc_preset_t mEncPreset;
   const float mMinContentBoost;
   const float mMaxContentBoost;
+  const float mTargetDispPeakBrightness;
   const int mMode;
 
   uhdr_raw_image_t mRawP010Image{};
   uhdr_raw_image_t mRawRgba1010102Image{};
+  uhdr_raw_image_t mRawRgbaF16Image{};
   uhdr_raw_image_t mRawYuv420Image{};
   uhdr_raw_image_t mRawRgba8888Image{};
   uhdr_compressed_image_t mSdrIntentCompressedImage{};
@@ -418,8 +443,8 @@ class UltraHdrAppInput {
 };
 
 bool UltraHdrAppInput::fillP010ImageHandle() {
-  const int bpp = 2;
-  int p010Size = mWidth * mHeight * bpp * 1.5;
+  const size_t bpp = 2;
+  size_t p010Size = bpp * mWidth * mHeight * 3 / 2;
   mRawP010Image.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
   mRawP010Image.cg = mHdrCg;
   mRawP010Image.ct = mHdrTf;
@@ -427,8 +452,8 @@ bool UltraHdrAppInput::fillP010ImageHandle() {
   mRawP010Image.range = mFullRange ? UHDR_CR_FULL_RANGE : UHDR_CR_LIMITED_RANGE;
   mRawP010Image.w = mWidth;
   mRawP010Image.h = mHeight;
-  mRawP010Image.planes[UHDR_PLANE_Y] = malloc(mWidth * mHeight * bpp);
-  mRawP010Image.planes[UHDR_PLANE_UV] = malloc((mWidth / 2) * (mHeight / 2) * bpp * 2);
+  mRawP010Image.planes[UHDR_PLANE_Y] = malloc(bpp * mWidth * mHeight);
+  mRawP010Image.planes[UHDR_PLANE_UV] = malloc(bpp * (mWidth / 2) * (mHeight / 2) * 2);
   mRawP010Image.planes[UHDR_PLANE_V] = nullptr;
   mRawP010Image.stride[UHDR_PLANE_Y] = mWidth;
   mRawP010Image.stride[UHDR_PLANE_UV] = mWidth;
@@ -437,16 +462,16 @@ bool UltraHdrAppInput::fillP010ImageHandle() {
 }
 
 bool UltraHdrAppInput::fillYuv420ImageHandle() {
-  int yuv420Size = mWidth * mHeight * 1.5;
+  size_t yuv420Size = (size_t)mWidth * mHeight * 3 / 2;
   mRawYuv420Image.fmt = UHDR_IMG_FMT_12bppYCbCr420;
   mRawYuv420Image.cg = mSdrCg;
   mRawYuv420Image.ct = UHDR_CT_SRGB;
   mRawYuv420Image.range = UHDR_CR_FULL_RANGE;
   mRawYuv420Image.w = mWidth;
   mRawYuv420Image.h = mHeight;
-  mRawYuv420Image.planes[UHDR_PLANE_Y] = malloc(mWidth * mHeight);
-  mRawYuv420Image.planes[UHDR_PLANE_U] = malloc((mWidth / 2) * (mHeight / 2));
-  mRawYuv420Image.planes[UHDR_PLANE_V] = malloc((mWidth / 2) * (mHeight / 2));
+  mRawYuv420Image.planes[UHDR_PLANE_Y] = malloc((size_t)mWidth * mHeight);
+  mRawYuv420Image.planes[UHDR_PLANE_U] = malloc((size_t)(mWidth / 2) * (mHeight / 2));
+  mRawYuv420Image.planes[UHDR_PLANE_V] = malloc((size_t)(mWidth / 2) * (mHeight / 2));
   mRawYuv420Image.stride[UHDR_PLANE_Y] = mWidth;
   mRawYuv420Image.stride[UHDR_PLANE_U] = mWidth / 2;
   mRawYuv420Image.stride[UHDR_PLANE_V] = mWidth / 2;
@@ -454,14 +479,14 @@ bool UltraHdrAppInput::fillYuv420ImageHandle() {
 }
 
 bool UltraHdrAppInput::fillRGBA1010102ImageHandle() {
-  const int bpp = 4;
+  const size_t bpp = 4;
   mRawRgba1010102Image.fmt = UHDR_IMG_FMT_32bppRGBA1010102;
   mRawRgba1010102Image.cg = mHdrCg;
   mRawRgba1010102Image.ct = mHdrTf;
   mRawRgba1010102Image.range = UHDR_CR_FULL_RANGE;
   mRawRgba1010102Image.w = mWidth;
   mRawRgba1010102Image.h = mHeight;
-  mRawRgba1010102Image.planes[UHDR_PLANE_PACKED] = malloc(mWidth * mHeight * bpp);
+  mRawRgba1010102Image.planes[UHDR_PLANE_PACKED] = malloc(bpp * mWidth * mHeight);
   mRawRgba1010102Image.planes[UHDR_PLANE_UV] = nullptr;
   mRawRgba1010102Image.planes[UHDR_PLANE_V] = nullptr;
   mRawRgba1010102Image.stride[UHDR_PLANE_PACKED] = mWidth;
@@ -470,15 +495,32 @@ bool UltraHdrAppInput::fillRGBA1010102ImageHandle() {
   return loadFile(mHdrIntentRawFile, &mRawRgba1010102Image);
 }
 
+bool UltraHdrAppInput::fillRGBAF16ImageHandle() {
+  const size_t bpp = 8;
+  mRawRgbaF16Image.fmt = UHDR_IMG_FMT_64bppRGBAHalfFloat;
+  mRawRgbaF16Image.cg = mHdrCg;
+  mRawRgbaF16Image.ct = mHdrTf;
+  mRawRgbaF16Image.range = UHDR_CR_FULL_RANGE;
+  mRawRgbaF16Image.w = mWidth;
+  mRawRgbaF16Image.h = mHeight;
+  mRawRgbaF16Image.planes[UHDR_PLANE_PACKED] = malloc(bpp * mWidth * mHeight);
+  mRawRgbaF16Image.planes[UHDR_PLANE_UV] = nullptr;
+  mRawRgbaF16Image.planes[UHDR_PLANE_V] = nullptr;
+  mRawRgbaF16Image.stride[UHDR_PLANE_PACKED] = mWidth;
+  mRawRgbaF16Image.stride[UHDR_PLANE_UV] = 0;
+  mRawRgbaF16Image.stride[UHDR_PLANE_V] = 0;
+  return loadFile(mHdrIntentRawFile, &mRawRgbaF16Image);
+}
+
 bool UltraHdrAppInput::fillRGBA8888ImageHandle() {
-  const int bpp = 4;
+  const size_t bpp = 4;
   mRawRgba8888Image.fmt = UHDR_IMG_FMT_32bppRGBA8888;
   mRawRgba8888Image.cg = mSdrCg;
   mRawRgba8888Image.ct = UHDR_CT_SRGB;
   mRawRgba8888Image.range = UHDR_CR_FULL_RANGE;
   mRawRgba8888Image.w = mWidth;
   mRawRgba8888Image.h = mHeight;
-  mRawRgba8888Image.planes[UHDR_PLANE_PACKED] = malloc(mWidth * mHeight * bpp);
+  mRawRgba8888Image.planes[UHDR_PLANE_PACKED] = malloc(bpp * mWidth * mHeight);
   mRawRgba8888Image.planes[UHDR_PLANE_U] = nullptr;
   mRawRgba8888Image.planes[UHDR_PLANE_V] = nullptr;
   mRawRgba8888Image.stride[UHDR_PLANE_Y] = mWidth;
@@ -490,7 +532,7 @@ bool UltraHdrAppInput::fillRGBA8888ImageHandle() {
 bool UltraHdrAppInput::fillSdrCompressedImageHandle() {
   std::ifstream ifd(mSdrIntentCompressedFile, std::ios::binary | std::ios::ate);
   if (ifd.good()) {
-    int size = ifd.tellg();
+    auto size = ifd.tellg();
     mSdrIntentCompressedImage.capacity = size;
     mSdrIntentCompressedImage.data_sz = size;
     mSdrIntentCompressedImage.data = nullptr;
@@ -506,7 +548,7 @@ bool UltraHdrAppInput::fillSdrCompressedImageHandle() {
 bool UltraHdrAppInput::fillGainMapCompressedImageHandle() {
   std::ifstream ifd(mGainMapCompressedFile, std::ios::binary | std::ios::ate);
   if (ifd.good()) {
-    int size = ifd.tellg();
+    auto size = ifd.tellg();
     mGainMapCompressedImage.capacity = size;
     mGainMapCompressedImage.data_sz = size;
     mGainMapCompressedImage.data = nullptr;
@@ -558,7 +600,7 @@ bool UltraHdrAppInput::fillGainMapMetadataDescriptor() {
 bool UltraHdrAppInput::fillExifMemoryBlock() {
   std::ifstream ifd(mExifFile, std::ios::binary | std::ios::ate);
   if (ifd.good()) {
-    int size = ifd.tellg();
+    auto size = ifd.tellg();
     ifd.close();
     return loadFile(mExifFile, mExifBlock.data, size);
   }
@@ -584,7 +626,7 @@ bool UltraHdrAppInput::writeGainMapMetadataToFile(uhdr_gainmap_metadata_t* metad
 bool UltraHdrAppInput::fillUhdrImageHandle() {
   std::ifstream ifd(mUhdrFile, std::ios::binary | std::ios::ate);
   if (ifd.good()) {
-    int size = ifd.tellg();
+    auto size = ifd.tellg();
     mUhdrImage.capacity = size;
     mUhdrImage.data_sz = size;
     mUhdrImage.data = nullptr;
@@ -609,6 +651,11 @@ bool UltraHdrAppInput::encode() {
         std::cerr << " failed to load file " << mHdrIntentRawFile << std::endl;
         return false;
       }
+    } else if (mHdrCf == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+      if (!fillRGBAF16ImageHandle()) {
+        std::cerr << " failed to load file " << mHdrIntentRawFile << std::endl;
+        return false;
+      }
     } else {
       std::cerr << " invalid hdr intent color format " << mHdrCf << std::endl;
       return false;
@@ -670,6 +717,8 @@ bool UltraHdrAppInput::encode() {
       RET_IF_ERR(uhdr_enc_set_raw_image(handle, &mRawP010Image, UHDR_HDR_IMG))
     } else if (mHdrCf == UHDR_IMG_FMT_32bppRGBA1010102) {
       RET_IF_ERR(uhdr_enc_set_raw_image(handle, &mRawRgba1010102Image, UHDR_HDR_IMG))
+    } else if (mHdrCf == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+      RET_IF_ERR(uhdr_enc_set_raw_image(handle, &mRawRgbaF16Image, UHDR_HDR_IMG))
     }
   }
   if (mSdrIntentRawFile != nullptr) {
@@ -701,6 +750,9 @@ bool UltraHdrAppInput::encode() {
   if (mMinContentBoost != FLT_MIN || mMaxContentBoost != FLT_MAX) {
     RET_IF_ERR(uhdr_enc_set_min_max_content_boost(handle, mMinContentBoost, mMaxContentBoost))
   }
+  if (mTargetDispPeakBrightness != -1.0f) {
+    RET_IF_ERR(uhdr_enc_set_target_display_peak_brightness(handle, mTargetDispPeakBrightness))
+  }
   if (mEnableGLES) {
     RET_IF_ERR(uhdr_enable_gpu_acceleration(handle, mEnableGLES))
   }
@@ -787,8 +839,8 @@ bool UltraHdrAppInput::decode() {
   mDecodedUhdrRgbImage.range = output->range;
   mDecodedUhdrRgbImage.w = output->w;
   mDecodedUhdrRgbImage.h = output->h;
-  int bpp = (output->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) ? 8 : 4;
-  mDecodedUhdrRgbImage.planes[UHDR_PLANE_PACKED] = malloc(output->w * output->h * bpp);
+  size_t bpp = (output->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) ? 8 : 4;
+  mDecodedUhdrRgbImage.planes[UHDR_PLANE_PACKED] = malloc(bpp * output->w * output->h);
   char* inData = static_cast<char*>(output->planes[UHDR_PLANE_PACKED]);
   char* outData = static_cast<char*>(mDecodedUhdrRgbImage.planes[UHDR_PLANE_PACKED]);
   const size_t inStride = output->stride[UHDR_PLANE_PACKED] * bpp;
@@ -817,13 +869,14 @@ bool UltraHdrAppInput::convertP010ToRGBImage() {
               << std::endl;
   }
 
+  size_t bpp = 4;
   mRawRgba1010102Image.fmt = UHDR_IMG_FMT_32bppRGBA1010102;
   mRawRgba1010102Image.cg = mRawP010Image.cg;
   mRawRgba1010102Image.ct = mRawP010Image.ct;
   mRawRgba1010102Image.range = UHDR_CR_FULL_RANGE;
   mRawRgba1010102Image.w = mRawP010Image.w;
   mRawRgba1010102Image.h = mRawP010Image.h;
-  mRawRgba1010102Image.planes[UHDR_PLANE_PACKED] = malloc(mRawP010Image.w * mRawP010Image.h * 4);
+  mRawRgba1010102Image.planes[UHDR_PLANE_PACKED] = malloc(bpp * mRawP010Image.w * mRawP010Image.h);
   mRawRgba1010102Image.planes[UHDR_PLANE_U] = nullptr;
   mRawRgba1010102Image.planes[UHDR_PLANE_V] = nullptr;
   mRawRgba1010102Image.stride[UHDR_PLANE_PACKED] = mWidth;
@@ -883,13 +936,14 @@ bool UltraHdrAppInput::convertP010ToRGBImage() {
 }
 
 bool UltraHdrAppInput::convertYuv420ToRGBImage() {
+  size_t bpp = 4;
   mRawRgba8888Image.fmt = UHDR_IMG_FMT_32bppRGBA8888;
   mRawRgba8888Image.cg = mRawYuv420Image.cg;
   mRawRgba8888Image.ct = mRawYuv420Image.ct;
   mRawRgba8888Image.range = UHDR_CR_FULL_RANGE;
   mRawRgba8888Image.w = mRawYuv420Image.w;
   mRawRgba8888Image.h = mRawYuv420Image.h;
-  mRawRgba8888Image.planes[UHDR_PLANE_PACKED] = malloc(mRawYuv420Image.w * mRawYuv420Image.h * 4);
+  mRawRgba8888Image.planes[UHDR_PLANE_PACKED] = malloc(bpp * mRawYuv420Image.w * mRawYuv420Image.h);
   mRawRgba8888Image.planes[UHDR_PLANE_U] = nullptr;
   mRawRgba8888Image.planes[UHDR_PLANE_V] = nullptr;
   mRawRgba8888Image.stride[UHDR_PLANE_PACKED] = mWidth;
@@ -956,11 +1010,11 @@ bool UltraHdrAppInput::convertRgba8888ToYUV444Image() {
   mDecodedUhdrYuv444Image.w = mDecodedUhdrRgbImage.w;
   mDecodedUhdrYuv444Image.h = mDecodedUhdrRgbImage.h;
   mDecodedUhdrYuv444Image.planes[UHDR_PLANE_Y] =
-      malloc(mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
+      malloc((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mDecodedUhdrYuv444Image.planes[UHDR_PLANE_U] =
-      malloc(mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
+      malloc((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mDecodedUhdrYuv444Image.planes[UHDR_PLANE_V] =
-      malloc(mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
+      malloc((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mDecodedUhdrYuv444Image.stride[UHDR_PLANE_Y] = mWidth;
   mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] = mWidth;
   mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] = mWidth;
@@ -1031,6 +1085,7 @@ bool UltraHdrAppInput::convertRgba1010102ToYUV444Image() {
               << " using BT2020Matrix" << std::endl;
   }
 
+  size_t bpp = 2;
   mDecodedUhdrYuv444Image.fmt = static_cast<uhdr_img_fmt_t>(UHDR_IMG_FMT_48bppYCbCr444);
   mDecodedUhdrYuv444Image.cg = mDecodedUhdrRgbImage.cg;
   mDecodedUhdrYuv444Image.ct = mDecodedUhdrRgbImage.ct;
@@ -1038,11 +1093,11 @@ bool UltraHdrAppInput::convertRgba1010102ToYUV444Image() {
   mDecodedUhdrYuv444Image.w = mDecodedUhdrRgbImage.w;
   mDecodedUhdrYuv444Image.h = mDecodedUhdrRgbImage.h;
   mDecodedUhdrYuv444Image.planes[UHDR_PLANE_Y] =
-      malloc(mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h * 2);
+      malloc(bpp * mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mDecodedUhdrYuv444Image.planes[UHDR_PLANE_U] =
-      malloc(mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h * 2);
+      malloc(bpp * mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mDecodedUhdrYuv444Image.planes[UHDR_PLANE_V] =
-      malloc(mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h * 2);
+      malloc(bpp * mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mDecodedUhdrYuv444Image.stride[UHDR_PLANE_Y] = mWidth;
   mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] = mWidth;
   mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] = mWidth;
@@ -1120,7 +1175,7 @@ void UltraHdrAppInput::computeRGBHdrPSNR() {
               << std::endl;
   }
   uint64_t rSqError = 0, gSqError = 0, bSqError = 0;
-  for (size_t i = 0; i < mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h; i++) {
+  for (size_t i = 0; i < (size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h; i++) {
     int rSrc = *rgbDataSrc & 0x3ff;
     int rDst = *rgbDataDst & 0x3ff;
     rSqError += (rSrc - rDst) * (rSrc - rDst);
@@ -1136,13 +1191,14 @@ void UltraHdrAppInput::computeRGBHdrPSNR() {
     rgbDataSrc++;
     rgbDataDst++;
   }
-  double meanSquareError = (double)rSqError / (mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
+  double meanSquareError =
+      (double)rSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mPsnr[0] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;
 
-  meanSquareError = (double)gSqError / (mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
+  meanSquareError = (double)gSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mPsnr[1] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;
 
-  meanSquareError = (double)bSqError / (mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
+  meanSquareError = (double)bSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mPsnr[2] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;
 
   std::cout << "psnr rgb: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
@@ -1161,7 +1217,7 @@ void UltraHdrAppInput::computeRGBSdrPSNR() {
   }
 
   uint64_t rSqError = 0, gSqError = 0, bSqError = 0;
-  for (size_t i = 0; i < mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h; i++) {
+  for (size_t i = 0; i < (size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h; i++) {
     int rSrc = *rgbDataSrc & 0xff;
     int rDst = *rgbDataDst & 0xff;
     rSqError += (rSrc - rDst) * (rSrc - rDst);
@@ -1177,13 +1233,14 @@ void UltraHdrAppInput::computeRGBSdrPSNR() {
     rgbDataSrc++;
     rgbDataDst++;
   }
-  double meanSquareError = (double)rSqError / (mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
+  double meanSquareError =
+      (double)rSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mPsnr[0] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;
 
-  meanSquareError = (double)gSqError / (mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
+  meanSquareError = (double)gSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mPsnr[1] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;
 
-  meanSquareError = (double)bSqError / (mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
+  meanSquareError = (double)bSqError / ((size_t)mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mPsnr[2] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;
 
   std::cout << "psnr rgb: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
@@ -1255,13 +1312,15 @@ void UltraHdrAppInput::computeYUVHdrPSNR() {
   }
 
   double meanSquareError =
-      (double)ySqError / (mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h);
+      (double)ySqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h);
   mPsnr[0] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;
 
-  meanSquareError = (double)uSqError / (mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
+  meanSquareError =
+      (double)uSqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
   mPsnr[1] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;
 
-  meanSquareError = (double)vSqError / (mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
+  meanSquareError =
+      (double)vSqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
   mPsnr[2] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;
 
   std::cout << "psnr yuv: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
@@ -1308,13 +1367,15 @@ void UltraHdrAppInput::computeYUVSdrPSNR() {
     }
   }
   double meanSquareError =
-      (double)ySqError / (mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h);
+      (double)ySqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h);
   mPsnr[0] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;
 
-  meanSquareError = (double)uSqError / (mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
+  meanSquareError =
+      (double)uSqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
   mPsnr[1] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;
 
-  meanSquareError = (double)vSqError / (mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
+  meanSquareError =
+      (double)vSqError / ((size_t)mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
   mPsnr[2] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;
 
   std::cout << "psnr yuv: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
@@ -1332,7 +1393,8 @@ static void usage(const char* name) {
       stderr,
       "    -y    raw sdr intent input resource (8-bit), required for encoding scenarios 1, 2. \n");
   fprintf(stderr,
-          "    -a    raw hdr intent color format, optional. [0:p010, 5:rgba1010102 (default)] \n");
+          "    -a    raw hdr intent color format, optional. [0:p010, 4: rgbahalffloat, "
+          "5:rgba1010102 (default)] \n");
   fprintf(stderr,
           "    -b    raw sdr intent color format, optional. [1:yuv420, 3:rgba8888 (default)] \n");
   fprintf(stderr,
@@ -1349,6 +1411,12 @@ static void usage(const char* name) {
           "    -c    sdr intent color gamut, optional. [0:bt709 (default), 1:p3, 2:bt2100] \n");
   fprintf(stderr,
           "    -t    hdr intent color transfer, optional. [0:linear, 1:hlg (default), 2:pq] \n");
+  fprintf(stderr,
+          "          It should be noted that not all combinations of input color format and input "
+          "color transfer are supported. \n"
+          "          srgb color transfer shall be paired with rgba8888 or yuv420 only. \n"
+          "          hlg, pq shall be paired with rgba1010102 or p010. \n"
+          "          linear shall be paired with rgbahalffloat. \n");
   fprintf(stderr,
           "    -q    quality factor to be used while encoding sdr intent, optional. [0-100], 95 : "
           "default.\n");
@@ -1376,6 +1444,11 @@ static void usage(const char* name) {
   fprintf(stderr,
           "    -K    max content boost recommendation, must be in linear scale, optional.[any "
           "positive real number] \n");
+  fprintf(stderr,
+          "    -L    set target display peak brightness in nits, optional. \n"
+          "          For HLG content, this defaults to 1000 nits. \n"
+          "          For PQ content, this defaults to 10000 nits. \n"
+          "          any real number in range [203, 10000]. \n");
   fprintf(stderr, "    -x    binary input resource containing exif data to insert, optional. \n");
   fprintf(stderr, "\n## decoder options : \n");
   fprintf(stderr, "    -j    ultra hdr compressed input resource, required. \n");
@@ -1463,7 +1536,7 @@ static void usage(const char* name) {
 }
 
 int main(int argc, char* argv[]) {
-  char opt_string[] = "p:y:i:g:f:w:h:C:c:t:q:o:O:m:j:e:a:b:z:R:s:M:Q:G:x:u:D:k:K:";
+  char opt_string[] = "p:y:i:g:f:w:h:C:c:t:q:o:O:m:j:e:a:b:z:R:s:M:Q:G:x:u:D:k:K:L:";
   char *hdr_intent_raw_file = nullptr, *sdr_intent_raw_file = nullptr, *uhdr_file = nullptr,
        *sdr_intent_compressed_file = nullptr, *gainmap_compressed_file = nullptr,
        *gainmap_metadata_cfg_file = nullptr, *output_file = nullptr, *exif_file = nullptr;
@@ -1487,6 +1560,7 @@ int main(int argc, char* argv[]) {
   uhdr_enc_preset_t enc_preset = UHDR_USAGE_BEST_QUALITY;
   float min_content_boost = FLT_MIN;
   float max_content_boost = FLT_MAX;
+  float target_disp_peak_brightness = -1.0f;
   int ch;
   while ((ch = getopt_s(argc, argv, opt_string)) != -1) {
     switch (ch) {
@@ -1555,7 +1629,7 @@ int main(int argc, char* argv[]) {
         gainmap_compression_quality = atoi(optarg_s);
         break;
       case 'G':
-        gamma = atof(optarg_s);
+        gamma = (float)atof(optarg_s);
         break;
       case 'j':
         uhdr_file = optarg_s;
@@ -1576,10 +1650,13 @@ int main(int argc, char* argv[]) {
         enc_preset = static_cast<uhdr_enc_preset_t>(atoi(optarg_s));
         break;
       case 'k':
-        min_content_boost = atof(optarg_s);
+        min_content_boost = (float)atof(optarg_s);
         break;
       case 'K':
-        max_content_boost = atof(optarg_s);
+        max_content_boost = (float)atof(optarg_s);
+        break;
+      case 'L':
+        target_disp_peak_brightness = (float)atof(optarg_s);
         break;
       default:
         usage(argv[0]);
@@ -1603,13 +1680,13 @@ int main(int argc, char* argv[]) {
       std::cerr << "did not receive raw resources for encoding." << std::endl;
       return -1;
     }
-    UltraHdrAppInput appInput(hdr_intent_raw_file, sdr_intent_raw_file, sdr_intent_compressed_file,
-                              gainmap_compressed_file, gainmap_metadata_cfg_file, exif_file,
-                              output_file ? output_file : "out.jpeg", width, height, hdr_cf, sdr_cf,
-                              hdr_cg, sdr_cg, hdr_tf, quality, out_tf, out_cf,
-                              use_full_range_color_hdr, gainmap_scale_factor,
-                              gainmap_compression_quality, use_multi_channel_gainmap, gamma,
-                              enable_gles, enc_preset, min_content_boost, max_content_boost);
+    UltraHdrAppInput appInput(
+        hdr_intent_raw_file, sdr_intent_raw_file, sdr_intent_compressed_file,
+        gainmap_compressed_file, gainmap_metadata_cfg_file, exif_file,
+        output_file ? output_file : "out.jpeg", width, height, hdr_cf, sdr_cf, hdr_cg, sdr_cg,
+        hdr_tf, quality, out_tf, out_cf, use_full_range_color_hdr, gainmap_scale_factor,
+        gainmap_compression_quality, use_multi_channel_gainmap, gamma, enable_gles, enc_preset,
+        min_content_boost, max_content_boost, target_disp_peak_brightness);
     if (!appInput.encode()) return -1;
     if (compute_psnr == 1) {
       if (!appInput.decode()) return -1;
@@ -1622,7 +1699,8 @@ int main(int argc, char* argv[]) {
           appInput.convertRgba8888ToYUV444Image();
           appInput.computeYUVSdrPSNR();
         }
-      } else if (out_cf == UHDR_IMG_FMT_32bppRGBA1010102 && hdr_intent_raw_file != nullptr) {
+      } else if (out_cf == UHDR_IMG_FMT_32bppRGBA1010102 && hdr_intent_raw_file != nullptr &&
+                 hdr_cf != UHDR_IMG_FMT_64bppRGBAHalfFloat) {
         if (hdr_cf == UHDR_IMG_FMT_24bppYCbCrP010) {
           appInput.convertP010ToRGBImage();
         }
diff --git a/fuzzer/Android.bp b/fuzzer/Android.bp
index bbbd88f..4fd32dd 100644
--- a/fuzzer/Android.bp
+++ b/fuzzer/Android.bp
@@ -73,3 +73,11 @@ cc_fuzz {
         "ultrahdr_dec_fuzzer.cpp",
     ],
 }
+
+cc_fuzz {
+    name: "ultrahdr_legacy_fuzzer",
+    defaults: ["ultrahdr_fuzzer_defaults"],
+    srcs: [
+        "ultrahdr_legacy_fuzzer.cpp",
+    ],
+}
diff --git a/fuzzer/ossfuzz.sh b/fuzzer/ossfuzz.sh
index 3f241e7..4af0ee3 100755
--- a/fuzzer/ossfuzz.sh
+++ b/fuzzer/ossfuzz.sh
@@ -17,20 +17,15 @@
 test "${SRC}" != "" || exit 1
 test "${WORK}" != "" || exit 1
 
-#Opt out of shift sanitizer in undefined sanitizer
-if [[ $SANITIZER = *undefined* ]]; then
-  CFLAGS="$CFLAGS -fno-sanitize=shift"
-  CXXFLAGS="$CXXFLAGS -fno-sanitize=shift"
-fi
-
 # Build libultrahdr
 build_dir=$WORK/build
 rm -rf ${build_dir}
 mkdir -p ${build_dir}
 pushd ${build_dir}
 
-cmake $SRC/libultrahdr -DUHDR_BUILD_FUZZERS=1
-make -j$(nproc) ultrahdr_dec_fuzzer ultrahdr_enc_fuzzer
+cmake $SRC/libultrahdr -DUHDR_BUILD_FUZZERS=1 -DUHDR_MAX_DIMENSION=1280
+make -j$(nproc) ultrahdr_dec_fuzzer ultrahdr_enc_fuzzer ultrahdr_legacy_fuzzer
 cp ${build_dir}/ultrahdr_dec_fuzzer $OUT/
 cp ${build_dir}/ultrahdr_enc_fuzzer $OUT/
+cp ${build_dir}/ultrahdr_legacy_fuzzer $OUT/
 popd
diff --git a/fuzzer/ultrahdr_dec_fuzzer.cpp b/fuzzer/ultrahdr_dec_fuzzer.cpp
index 1343ea3..dba543b 100644
--- a/fuzzer/ultrahdr_dec_fuzzer.cpp
+++ b/fuzzer/ultrahdr_dec_fuzzer.cpp
@@ -15,8 +15,6 @@
  */
 
 #include <fuzzer/FuzzedDataProvider.h>
-#include <iostream>
-#include <memory>
 
 #include "ultrahdr_api.h"
 #include "ultrahdr/ultrahdrcommon.h"
@@ -24,12 +22,12 @@
 using namespace ultrahdr;
 
 // Transfer functions for image data, sync with ultrahdr.h
-constexpr int kTfMin = UHDR_CT_UNSPECIFIED + 1;
-constexpr int kTfMax = UHDR_CT_PQ;
+constexpr int kTfMin = UHDR_CT_UNSPECIFIED;
+constexpr int kTfMax = UHDR_CT_SRGB;
 
 class UltraHdrDecFuzzer {
  public:
-  UltraHdrDecFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
+  UltraHdrDecFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {};
   void process();
 
  private:
@@ -37,9 +35,31 @@ class UltraHdrDecFuzzer {
 };
 
 void UltraHdrDecFuzzer::process() {
-  // hdr_of
-  auto tf = static_cast<uhdr_color_transfer>(mFdp.ConsumeIntegralInRange<int>(kTfMin, kTfMax));
+  auto output_ct =
+      static_cast<uhdr_color_transfer>(mFdp.ConsumeIntegralInRange<int8_t>(kTfMin, kTfMax));
+  auto displayBoost = mFdp.ConsumeFloatingPointInRange<float>(-10.0f, 100.0f);
+  auto enableGpu = mFdp.ConsumeBool();
+
+  // editing effects
+  auto applyMirror = mFdp.ConsumeBool();
+  uhdr_mirror_direction_t direction =
+      mFdp.ConsumeBool() ? UHDR_MIRROR_VERTICAL : UHDR_MIRROR_HORIZONTAL;
+
+  auto applyRotate = mFdp.ConsumeBool();
+  int degrees = degrees = mFdp.PickValueInArray({-90, 0, 90, 180, 270});
+
+  auto applyCrop = mFdp.ConsumeBool();
+  int left = mFdp.ConsumeIntegral<int16_t>();
+  int right = mFdp.ConsumeIntegral<int16_t>();
+  int top = mFdp.ConsumeIntegral<int16_t>();
+  int bottom = mFdp.ConsumeIntegral<int16_t>();
+
+  auto applyResize = mFdp.ConsumeBool();
+  int resizeWidth = mFdp.ConsumeIntegralInRange<int32_t>(-32, kMaxWidth + 128);
+  int resizeHeight = mFdp.ConsumeIntegralInRange<int32_t>(-32, kMaxHeight + 128);
+
   auto buffer = mFdp.ConsumeRemainingBytes<uint8_t>();
+
   uhdr_compressed_image_t jpegImgR{
       buffer.data(),       (unsigned int)buffer.size(), (unsigned int)buffer.size(),
       UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED,         UHDR_CR_UNSPECIFIED};
@@ -52,21 +72,44 @@ void UltraHdrDecFuzzer::process() {
       }                                        \
     }                                          \
   }
+
+  (void)is_uhdr_image(buffer.data(), buffer.size());
+
   uhdr_codec_private_t* dec_handle = uhdr_create_decoder();
   if (dec_handle) {
     ON_ERR(uhdr_dec_set_image(dec_handle, &jpegImgR))
-    ON_ERR(uhdr_dec_set_out_color_transfer(dec_handle, tf))
-    if (tf == UHDR_CT_LINEAR)
+    ON_ERR(uhdr_dec_set_out_color_transfer(dec_handle, output_ct))
+    if (output_ct == UHDR_CT_LINEAR)
       ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_64bppRGBAHalfFloat))
-    else if (tf == UHDR_CT_SRGB)
+    else if (output_ct == UHDR_CT_SRGB)
       ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA8888))
     else
       ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA1010102))
+    ON_ERR(uhdr_dec_set_out_max_display_boost(dec_handle, displayBoost))
+    ON_ERR(uhdr_enable_gpu_acceleration(dec_handle, enableGpu))
+    if (applyMirror) ON_ERR(uhdr_add_effect_mirror(dec_handle, direction))
+    if (applyRotate) ON_ERR(uhdr_add_effect_rotate(dec_handle, degrees))
+    if (applyCrop) ON_ERR(uhdr_add_effect_crop(dec_handle, left, right, top, bottom))
+    if (applyResize) ON_ERR(uhdr_add_effect_resize(dec_handle, resizeWidth, resizeHeight))
     uhdr_dec_probe(dec_handle);
-    uhdr_dec_get_image_width(dec_handle);
-    uhdr_dec_get_image_height(dec_handle);
-    uhdr_dec_get_gainmap_width(dec_handle);
-    uhdr_dec_get_gainmap_height(dec_handle);
+    auto width = uhdr_dec_get_image_width(dec_handle);
+    auto height = uhdr_dec_get_image_height(dec_handle);
+    auto gainmap_width = uhdr_dec_get_gainmap_width(dec_handle);
+    auto gainmap_height = uhdr_dec_get_gainmap_height(dec_handle);
+
+    ALOGV("image dimensions %d x %d ", (int)width, (int)height);
+    ALOGV("gainmap image dimensions %d x %d ", (int)gainmap_width, (int)gainmap_height);
+    ALOGV("output color transfer %d ", (int)output_ct);
+    ALOGV("max display boost %f ", (float)displayBoost);
+    ALOGV("enable gpu %d ", (int)enableGpu);
+    if (applyMirror) ALOGV("added mirror effect, direction %d", (int)direction);
+    if (applyRotate) ALOGV("added rotate effect, degrees %d", (int)degrees);
+    if (applyCrop)
+      ALOGV("added crop effect, crop-left %d, crop-right %d, crop-top %d, crop-bottom %d", left,
+            right, top, bottom);
+    if (applyResize)
+      ALOGV("added resize effect, resize wd %d, resize ht %d", resizeWidth, resizeHeight);
+
     uhdr_dec_get_exif(dec_handle);
     uhdr_dec_get_icc(dec_handle);
     uhdr_dec_get_base_image(dec_handle);
@@ -75,6 +118,7 @@ void UltraHdrDecFuzzer::process() {
     uhdr_decode(dec_handle);
     uhdr_get_decoded_image(dec_handle);
     uhdr_get_decoded_gainmap_image(dec_handle);
+    uhdr_reset_decoder(dec_handle);
     uhdr_release_decoder(dec_handle);
   }
 }
diff --git a/fuzzer/ultrahdr_enc_fuzzer.cpp b/fuzzer/ultrahdr_enc_fuzzer.cpp
index 7287b69..cf8b889 100644
--- a/fuzzer/ultrahdr_enc_fuzzer.cpp
+++ b/fuzzer/ultrahdr_enc_fuzzer.cpp
@@ -16,9 +16,8 @@
 
 #include <fuzzer/FuzzedDataProvider.h>
 #include <algorithm>
-#include <iostream>
-#include <memory>
 #include <random>
+#include <type_traits>
 
 #include "ultrahdr_api.h"
 #include "ultrahdr/ultrahdrcommon.h"
@@ -27,20 +26,20 @@
 using namespace ultrahdr;
 
 // Color gamuts for image data, sync with ultrahdr_api.h
-constexpr int kCgMin = UHDR_CG_UNSPECIFIED + 1;
+constexpr int kCgMin = UHDR_CG_UNSPECIFIED;
 constexpr int kCgMax = UHDR_CG_BT_2100;
 
-// Transfer functions for image data, sync with ultrahdr_api.h
-constexpr int kTfMin = UHDR_CT_UNSPECIFIED + 1;
-constexpr int kTfMax = UHDR_CT_PQ;
+// Color ranges for image data, sync with ultrahdr_api.h
+constexpr int kCrMin = UHDR_CR_UNSPECIFIED;
+constexpr int kCrMax = UHDR_CR_FULL_RANGE;
 
-// quality factor
-constexpr int kQfMin = 0;
-constexpr int kQfMax = 100;
+// Transfer functions for image data, sync with ultrahdr_api.h
+constexpr int kTfMin = UHDR_CT_UNSPECIFIED;
+constexpr int kTfMax = UHDR_CT_SRGB;
 
 class UltraHdrEncFuzzer {
  public:
-  UltraHdrEncFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
+  UltraHdrEncFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {};
   void process();
   template <typename T>
   void fillBuffer(T* data, int width, int height, int stride);
@@ -51,10 +50,12 @@ class UltraHdrEncFuzzer {
 
 template <typename T>
 void UltraHdrEncFuzzer::fillBuffer(T* data, int width, int height, int stride) {
+  if (!mFdp.remaining_bytes()) return;
+
   T* tmp = data;
-  std::vector<T> buffer(16);
+  std::vector<T> buffer(width);
   for (int i = 0; i < buffer.size(); i++) {
-    buffer[i] = (mFdp.ConsumeIntegralInRange<int>(0, (1 << 10) - 1)) << 6;
+    buffer[i] = mFdp.ConsumeIntegral<T>();
   }
   for (int j = 0; j < height; j++) {
     for (int i = 0; i < width; i += buffer.size()) {
@@ -67,59 +68,146 @@ void UltraHdrEncFuzzer::fillBuffer(T* data, int width, int height, int stride) {
 }
 
 void UltraHdrEncFuzzer::process() {
-  while (mFdp.remaining_bytes()) {
-    struct uhdr_raw_image hdrImg {};
-    struct uhdr_raw_image sdrImg {};
-    struct uhdr_raw_image gainmapImg {};
+  if (mFdp.remaining_bytes()) {
+    struct uhdr_raw_image hdrImg{};
+    struct uhdr_raw_image sdrImg{};
+    struct uhdr_raw_image gainmapImg{};
 
     // which encode api to select
-    int muxSwitch = mFdp.ConsumeIntegralInRange<int>(0, 4);
-
-    // base quality factor
-    int base_quality = mFdp.ConsumeIntegralInRange<int>(kQfMin, kQfMax);
-
-    // gain_map quality factor
-    int gainmap_quality = mFdp.ConsumeIntegralInRange<int>(kQfMin, kQfMax);
-
-    // hdr_tf
-    auto tf = static_cast<uhdr_color_transfer>(mFdp.ConsumeIntegralInRange<int>(kTfMin, kTfMax));
-
-    // hdr Cg
-    auto hdr_cg = static_cast<uhdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));
-
-    // sdr Cg
-    auto sdr_cg = static_cast<uhdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));
-
-    // color range
-    auto color_range = mFdp.ConsumeBool() ? UHDR_CR_LIMITED_RANGE : UHDR_CR_FULL_RANGE;
+    int muxSwitch = mFdp.ConsumeIntegralInRange<int8_t>(0, 4);
 
     // hdr_img_fmt
-    auto hdr_img_fmt =
-        mFdp.ConsumeBool() ? UHDR_IMG_FMT_24bppYCbCrP010 : UHDR_IMG_FMT_32bppRGBA1010102;
+    uhdr_img_fmt_t hdr_img_fmt =
+        mFdp.PickValueInArray({UHDR_IMG_FMT_24bppYCbCrP010, UHDR_IMG_FMT_32bppRGBA1010102,
+                               UHDR_IMG_FMT_64bppRGBAHalfFloat});
 
     // sdr_img_fmt
-    auto sdr_img_fmt = mFdp.ConsumeBool() ? UHDR_IMG_FMT_12bppYCbCr420 : UHDR_IMG_FMT_32bppRGBA8888;
+    uhdr_img_fmt_t sdr_img_fmt =
+        mFdp.ConsumeBool() ? UHDR_IMG_FMT_12bppYCbCr420 : UHDR_IMG_FMT_32bppRGBA8888;
     if (muxSwitch > 1) sdr_img_fmt = UHDR_IMG_FMT_12bppYCbCr420;
 
-    // multi channel gainmap
-    auto multi_channel_gainmap = mFdp.ConsumeBool();
-
-    int width = mFdp.ConsumeIntegralInRange<int>(kMinWidth, kMaxWidth);
+    // width
+    int width = mFdp.ConsumeIntegralInRange<uint16_t>(kMinWidth, kMaxWidth);
     if (hdr_img_fmt == UHDR_IMG_FMT_24bppYCbCrP010 || sdr_img_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
       width = (width >> 1) << 1;
     }
 
-    int height = mFdp.ConsumeIntegralInRange<int>(kMinHeight, kMaxHeight);
+    // height
+    int height = mFdp.ConsumeIntegralInRange<uint16_t>(kMinHeight, kMaxHeight);
     if (hdr_img_fmt == UHDR_IMG_FMT_24bppYCbCrP010 || sdr_img_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
       height = (height >> 1) << 1;
     }
 
+    // hdr Ct
+    auto hdr_ct =
+        static_cast<uhdr_color_transfer_t>(mFdp.ConsumeIntegralInRange<int8_t>(kTfMin, kTfMax));
+
+    // hdr Cg
+    auto hdr_cg =
+        static_cast<uhdr_color_gamut_t>(mFdp.ConsumeIntegralInRange<int8_t>(kCgMin, kCgMax));
+
+    // sdr Cg
+    auto sdr_cg =
+        static_cast<uhdr_color_gamut_t>(mFdp.ConsumeIntegralInRange<int8_t>(kCgMin, kCgMax));
+
+    // color range
+    auto hdr_cr =
+        static_cast<uhdr_color_range_t>(mFdp.ConsumeIntegralInRange<int8_t>(kCrMin, kCrMax));
+
+    // base quality factor
+    auto base_quality = mFdp.ConsumeIntegral<int8_t>();
+
+    // gain_map quality factor
+    auto gainmap_quality = mFdp.ConsumeIntegral<int8_t>();
+
+    // multi channel gainmap
+    auto multi_channel_gainmap = mFdp.ConsumeIntegral<int8_t>();
+
     // gainmap scale factor
-    auto gm_scale_factor = mFdp.ConsumeIntegralInRange<int>(1, 128);
+    auto gm_scale_factor = mFdp.ConsumeIntegralInRange<int16_t>(-32, 192);
 
     // encoding speed preset
-    auto enc_preset = static_cast<uhdr_enc_preset_t>(mFdp.ConsumeIntegralInRange<int>(0, 1));
+    auto enc_preset = mFdp.ConsumeBool() ? UHDR_USAGE_REALTIME : UHDR_USAGE_BEST_QUALITY;
+
+    // gainmap metadata
+    auto minBoost = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
+    auto maxBoost = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
+    auto gamma = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 5);
+    auto offsetSdr = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
+    auto offsetHdr = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
+    auto minCapacity = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
+    auto maxCapacity = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
+
+    // target display peak brightness
+    auto targetDispPeakBrightness = mFdp.ConsumeFloatingPointInRange<float>(100.0f, 10500.0f);
+
+    // raw buffer config
+    bool hasHdrStride = mFdp.ConsumeBool();
+    size_t yHdrStride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
+    if (!hasHdrStride) yHdrStride = width;
+    bool isHdrUVContiguous = mFdp.ConsumeBool();
+    bool hasHdrUVStride = mFdp.ConsumeBool();
+    size_t uvHdrStride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
+    if (!hasHdrUVStride) uvHdrStride = width;
+
+    bool hasSdrStride = mFdp.ConsumeBool();
+    size_t ySdrStride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
+    if (!hasSdrStride) ySdrStride = width;
+    bool isSdrUVContiguous = mFdp.ConsumeBool();
+    bool hasSdrUVStride = mFdp.ConsumeBool();
+    size_t uvSdrStride = mFdp.ConsumeIntegralInRange<uint16_t>(width / 2, width / 2 + 128);
+    if (!hasSdrUVStride) uvSdrStride = width / 2;
 
+    // editing effects
+    auto applyMirror = mFdp.ConsumeBool();
+    uhdr_mirror_direction_t direction =
+        mFdp.ConsumeBool() ? UHDR_MIRROR_VERTICAL : UHDR_MIRROR_HORIZONTAL;
+
+    auto applyRotate = mFdp.ConsumeBool();
+    int degrees = degrees = mFdp.PickValueInArray({-90, 0, 90, 180, 270});
+
+    auto applyCrop = mFdp.ConsumeBool();
+    int left = mFdp.ConsumeIntegral<int16_t>();
+    int right = mFdp.ConsumeIntegral<int16_t>();
+    int top = mFdp.ConsumeIntegral<int16_t>();
+    int bottom = mFdp.ConsumeIntegral<int16_t>();
+
+    auto applyResize = mFdp.ConsumeBool();
+    int resizeWidth = mFdp.ConsumeIntegralInRange<int32_t>(-32, kMaxWidth + 128);
+    int resizeHeight = mFdp.ConsumeIntegralInRange<int32_t>(-32, kMaxHeight + 128);
+
+    // exif
+    char greeting[] = "Exif says hello world";
+    uhdr_mem_block_t exif{greeting, mFdp.ConsumeIntegralInRange<uint8_t>(0, sizeof greeting * 2),
+                          sizeof greeting};
+
+    ALOGV("encoding configuration options : ");
+    ALOGV("encoding api - %d ", (int)muxSwitch);
+    ALOGV("image dimensions %d x %d ", (int)width, (int)height);
+    ALOGV("hdr intent color aspects: gamut %d, transfer %d, range %d, format %d ", (int)hdr_cg,
+          (int)hdr_ct, (int)hdr_cr, (int)hdr_img_fmt);
+    ALOGV("sdr intent color aspects: gamut %d, format %d ", (int)sdr_cg, (int)sdr_img_fmt);
+    ALOGV(
+        "gainmap img config: scale factor %d, enabled multichannel gainmap %s, gainmap quality %d ",
+        (int)gm_scale_factor, (int)multi_channel_gainmap ? "Yes" : "No", (int)gainmap_quality);
+    ALOGV("base image quality %d ", (int)base_quality);
+    ALOGV("encoding preset %d ", (int)enc_preset);
+    ALOGV(
+        "gainmap metadata: min content boost %f, max content boost %f, gamma %f, offset sdr %f, "
+        "offset hdr %f, hdr min capacity %f, hdr max capacity %f",
+        (float)minBoost, (float)maxBoost, (float)gamma, (float)offsetSdr, (float)offsetHdr,
+        (float)minCapacity, (float)maxCapacity);
+    ALOGV("hdr intent luma stride %d, chroma stride %d", yHdrStride, uvHdrStride);
+    ALOGV("sdr intent luma stride %d, chroma stride %d", ySdrStride, uvSdrStride);
+    if (applyMirror) ALOGV("added mirror effect, direction %d", (int)direction);
+    if (applyRotate) ALOGV("added rotate effect, degrees %d", (int)degrees);
+    if (applyCrop)
+      ALOGV("added crop effect, crop-left %d, crop-right %d, crop-top %d, crop-bottom %d", left,
+            right, top, bottom);
+    if (applyResize)
+      ALOGV("added resize effect, resize wd %d, resize ht %d", resizeWidth, resizeHeight);
+
+    std::unique_ptr<uint64_t[]> bufferFpHdr = nullptr;
     std::unique_ptr<uint32_t[]> bufferHdr = nullptr;
     std::unique_ptr<uint16_t[]> bufferYHdr = nullptr;
     std::unique_ptr<uint16_t[]> bufferUVHdr = nullptr;
@@ -129,7 +217,7 @@ void UltraHdrEncFuzzer::process() {
     uhdr_codec_private_t* enc_handle = uhdr_create_encoder();
     if (!enc_handle) {
       ALOGE("Failed to create encoder");
-      continue;
+      return;
     }
 
 #define ON_ERR(x)                              \
@@ -143,42 +231,46 @@ void UltraHdrEncFuzzer::process() {
   }
     if (muxSwitch != 4) {
       // init p010/rgba1010102 image
-      bool hasStride = mFdp.ConsumeBool();
-      int yStride = hasStride ? mFdp.ConsumeIntegralInRange<int>(width, width + 128) : width;
       hdrImg.w = width;
       hdrImg.h = height;
       hdrImg.cg = hdr_cg;
       hdrImg.fmt = hdr_img_fmt;
-      hdrImg.ct = tf;
-      hdrImg.range = color_range;
-      hdrImg.stride[UHDR_PLANE_Y] = yStride;
+      hdrImg.ct = hdr_ct;
+      hdrImg.range = hdr_cr;
+      hdrImg.stride[UHDR_PLANE_Y] = yHdrStride;
       if (hdr_img_fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
-        bool isUVContiguous = mFdp.ConsumeBool();
-        if (isUVContiguous) {
-          size_t p010Size = yStride * height * 3 / 2;
+        if (isHdrUVContiguous) {
+          size_t p010Size = yHdrStride * height * 3 / 2;
           bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
           hdrImg.planes[UHDR_PLANE_Y] = bufferYHdr.get();
-          fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yStride);
-          fillBuffer<uint16_t>(bufferYHdr.get() + yStride * height, width, height / 2, yStride);
-          hdrImg.planes[UHDR_PLANE_UV] = bufferYHdr.get() + yStride * height;
-          hdrImg.stride[UHDR_PLANE_UV] = yStride;
+          fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yHdrStride);
+          fillBuffer<uint16_t>(bufferYHdr.get() + yHdrStride * height, width, height / 2,
+                               yHdrStride);
+          hdrImg.planes[UHDR_PLANE_UV] = bufferYHdr.get() + yHdrStride * height;
+          hdrImg.stride[UHDR_PLANE_UV] = yHdrStride;
         } else {
-          int uvStride = mFdp.ConsumeIntegralInRange<int>(width, width + 128);
-          size_t p010Size = yStride * height;
+          size_t p010Size = yHdrStride * height;
           bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
           hdrImg.planes[UHDR_PLANE_Y] = bufferYHdr.get();
-          fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yStride);
-          size_t p010UVSize = uvStride * hdrImg.h / 2;
+          fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yHdrStride);
+          size_t p010UVSize = uvHdrStride * hdrImg.h / 2;
           bufferUVHdr = std::make_unique<uint16_t[]>(p010UVSize);
           hdrImg.planes[UHDR_PLANE_UV] = bufferUVHdr.get();
-          hdrImg.stride[UHDR_PLANE_UV] = uvStride;
-          fillBuffer<uint16_t>(bufferUVHdr.get(), width, height / 2, uvStride);
+          hdrImg.stride[UHDR_PLANE_UV] = uvHdrStride;
+          fillBuffer<uint16_t>(bufferUVHdr.get(), width, height / 2, uvHdrStride);
         }
       } else if (hdr_img_fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
-        size_t rgba1010102Size = yStride * height;
+        size_t rgba1010102Size = yHdrStride * height;
         bufferHdr = std::make_unique<uint32_t[]>(rgba1010102Size);
         hdrImg.planes[UHDR_PLANE_PACKED] = bufferHdr.get();
-        fillBuffer<uint32_t>(bufferHdr.get(), width, height, yStride);
+        fillBuffer<uint32_t>(bufferHdr.get(), width, height, yHdrStride);
+        hdrImg.planes[UHDR_PLANE_U] = nullptr;
+        hdrImg.stride[UHDR_PLANE_U] = 0;
+      } else if (hdr_img_fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+        size_t rgbafp16Size = yHdrStride * height;
+        bufferFpHdr = std::make_unique<uint64_t[]>(rgbafp16Size);
+        hdrImg.planes[UHDR_PLANE_PACKED] = bufferFpHdr.get();
+        fillBuffer<uint64_t>(bufferFpHdr.get(), width, height, yHdrStride);
         hdrImg.planes[UHDR_PLANE_U] = nullptr;
         hdrImg.stride[UHDR_PLANE_U] = 0;
       }
@@ -186,8 +278,8 @@ void UltraHdrEncFuzzer::process() {
       hdrImg.stride[UHDR_PLANE_V] = 0;
       ON_ERR(uhdr_enc_set_raw_image(enc_handle, &hdrImg, UHDR_HDR_IMG))
     } else {
-      size_t map_width = width / gm_scale_factor;
-      size_t map_height = height / gm_scale_factor;
+      size_t map_width = width / ((gm_scale_factor <= 0) ? 1 : gm_scale_factor);
+      size_t map_height = height / ((gm_scale_factor <= 0) ? 1 : gm_scale_factor);
       gainmapImg.fmt = UHDR_IMG_FMT_8bppYCbCr400;
       gainmapImg.w = map_width;
       gainmapImg.h = map_height;
@@ -206,46 +298,42 @@ void UltraHdrEncFuzzer::process() {
     }
 
     if (muxSwitch > 0) {
-      bool hasStride = mFdp.ConsumeBool();
-      int yStride = hasStride ? mFdp.ConsumeIntegralInRange<int>(width, width + 128) : width;
       // init yuv420 Image
       if (sdr_img_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
-        bool isUVContiguous = mFdp.ConsumeBool();
         sdrImg.w = width;
         sdrImg.h = height;
         sdrImg.cg = sdr_cg;
         sdrImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
         sdrImg.ct = UHDR_CT_SRGB;
         sdrImg.range = UHDR_CR_FULL_RANGE;
-        sdrImg.stride[UHDR_PLANE_Y] = yStride;
-        if (isUVContiguous) {
-          size_t yuv420Size = yStride * height * 3 / 2;
+        sdrImg.stride[UHDR_PLANE_Y] = ySdrStride;
+        if (isSdrUVContiguous) {
+          size_t yuv420Size = ySdrStride * height * 3 / 2;
           bufferYSdr = std::make_unique<uint8_t[]>(yuv420Size);
           sdrImg.planes[UHDR_PLANE_Y] = bufferYSdr.get();
-          sdrImg.planes[UHDR_PLANE_U] = bufferYSdr.get() + yStride * height;
-          sdrImg.planes[UHDR_PLANE_V] = bufferYSdr.get() + yStride * height * 5 / 4;
-          sdrImg.stride[UHDR_PLANE_U] = yStride / 2;
-          sdrImg.stride[UHDR_PLANE_V] = yStride / 2;
-          fillBuffer<uint8_t>(bufferYSdr.get(), width, height, yStride);
-          fillBuffer<uint8_t>(bufferYSdr.get() + yStride * height, width / 2, height / 2,
-                              yStride / 2);
-          fillBuffer<uint8_t>(bufferYSdr.get() + yStride * height * 5 / 4, width / 2, height / 2,
-                              yStride / 2);
+          sdrImg.planes[UHDR_PLANE_U] = bufferYSdr.get() + ySdrStride * height;
+          sdrImg.planes[UHDR_PLANE_V] = bufferYSdr.get() + ySdrStride * height * 5 / 4;
+          sdrImg.stride[UHDR_PLANE_U] = ySdrStride / 2;
+          sdrImg.stride[UHDR_PLANE_V] = ySdrStride / 2;
+          fillBuffer<uint8_t>(bufferYSdr.get(), width, height, ySdrStride);
+          fillBuffer<uint8_t>(bufferYSdr.get() + ySdrStride * height, width / 2, height / 2,
+                              ySdrStride / 2);
+          fillBuffer<uint8_t>(bufferYSdr.get() + ySdrStride * height * 5 / 4, width / 2, height / 2,
+                              ySdrStride / 2);
         } else {
-          int uvStride = mFdp.ConsumeIntegralInRange<int>(width / 2, width / 2 + 128);
-          size_t yuv420YSize = yStride * height;
+          size_t yuv420YSize = ySdrStride * height;
           bufferYSdr = std::make_unique<uint8_t[]>(yuv420YSize);
           sdrImg.planes[UHDR_PLANE_Y] = bufferYSdr.get();
-          fillBuffer<uint8_t>(bufferYSdr.get(), width, height, yStride);
-          size_t yuv420UVSize = uvStride * sdrImg.h / 2 * 2;
+          fillBuffer<uint8_t>(bufferYSdr.get(), width, height, ySdrStride);
+          size_t yuv420UVSize = uvSdrStride * sdrImg.h / 2 * 2;
           bufferUVSdr = std::make_unique<uint8_t[]>(yuv420UVSize);
           sdrImg.planes[UHDR_PLANE_U] = bufferUVSdr.get();
-          sdrImg.stride[UHDR_PLANE_U] = uvStride;
-          fillBuffer<uint8_t>(bufferUVSdr.get(), width / 2, height / 2, uvStride);
-          fillBuffer<uint8_t>(bufferUVSdr.get() + uvStride * height / 2, width / 2, height / 2,
-                              uvStride);
-          sdrImg.planes[UHDR_PLANE_V] = bufferUVSdr.get() + uvStride * height / 2;
-          sdrImg.stride[UHDR_PLANE_V] = uvStride;
+          sdrImg.stride[UHDR_PLANE_U] = uvSdrStride;
+          fillBuffer<uint8_t>(bufferUVSdr.get(), width / 2, height / 2, uvSdrStride);
+          fillBuffer<uint8_t>(bufferUVSdr.get() + uvSdrStride * height / 2, width / 2, height / 2,
+                              uvSdrStride);
+          sdrImg.planes[UHDR_PLANE_V] = bufferUVSdr.get() + uvSdrStride * height / 2;
+          sdrImg.stride[UHDR_PLANE_V] = uvSdrStride;
         }
       } else if (sdr_img_fmt == UHDR_IMG_FMT_32bppRGBA8888) {
         sdrImg.w = width;
@@ -254,11 +342,11 @@ void UltraHdrEncFuzzer::process() {
         sdrImg.fmt = UHDR_IMG_FMT_32bppRGBA8888;
         sdrImg.ct = UHDR_CT_SRGB;
         sdrImg.range = UHDR_CR_FULL_RANGE;
-        sdrImg.stride[UHDR_PLANE_PACKED] = yStride;
-        size_t rgba8888Size = yStride * height;
+        sdrImg.stride[UHDR_PLANE_PACKED] = ySdrStride;
+        size_t rgba8888Size = ySdrStride * height;
         bufferHdr = std::make_unique<uint32_t[]>(rgba8888Size);
         sdrImg.planes[UHDR_PLANE_PACKED] = bufferHdr.get();
-        fillBuffer<uint32_t>(bufferHdr.get(), width, height, yStride);
+        fillBuffer<uint32_t>(bufferHdr.get(), width, height, ySdrStride);
         sdrImg.planes[UHDR_PLANE_U] = nullptr;
         sdrImg.planes[UHDR_PLANE_V] = nullptr;
         sdrImg.stride[UHDR_PLANE_U] = 0;
@@ -270,9 +358,18 @@ void UltraHdrEncFuzzer::process() {
     }
     ON_ERR(uhdr_enc_set_quality(enc_handle, base_quality, UHDR_BASE_IMG))
     ON_ERR(uhdr_enc_set_quality(enc_handle, gainmap_quality, UHDR_GAIN_MAP_IMG))
-    ON_ERR(uhdr_enc_set_gainmap_scale_factor(enc_handle, gm_scale_factor))
+    ON_ERR(uhdr_enc_set_exif_data(enc_handle, &exif))
     ON_ERR(uhdr_enc_set_using_multi_channel_gainmap(enc_handle, multi_channel_gainmap))
+    ON_ERR(uhdr_enc_set_gainmap_scale_factor(enc_handle, gm_scale_factor))
+    ON_ERR(uhdr_enc_set_gainmap_gamma(enc_handle, gamma))
+    ON_ERR(uhdr_enc_set_min_max_content_boost(enc_handle, minBoost, maxBoost))
+    ON_ERR(uhdr_enc_set_target_display_peak_brightness(enc_handle, targetDispPeakBrightness))
     ON_ERR(uhdr_enc_set_preset(enc_handle, enc_preset))
+    ON_ERR(uhdr_enable_gpu_acceleration(enc_handle, 1))
+    if (applyMirror) ON_ERR(uhdr_add_effect_mirror(enc_handle, direction))
+    if (applyRotate) ON_ERR(uhdr_add_effect_rotate(enc_handle, degrees))
+    if (applyCrop) ON_ERR(uhdr_add_effect_crop(enc_handle, left, right, top, bottom))
+    if (applyResize) ON_ERR(uhdr_add_effect_resize(enc_handle, resizeWidth, resizeHeight))
 
     uhdr_error_info_t status = {UHDR_CODEC_OK, 0, ""};
     if (muxSwitch == 0 || muxSwitch == 1) {  // api 0 or api 1
@@ -295,13 +392,13 @@ void UltraHdrEncFuzzer::process() {
               UHDR_CODEC_OK) {
             struct uhdr_compressed_image jpegGainMap = gainMapEncoder.getCompressedImage();
             uhdr_gainmap_metadata metadata;
-            metadata.max_content_boost = 17.0f;
-            metadata.min_content_boost = 1.0f;
-            metadata.gamma = 1.0f;
-            metadata.offset_sdr = 0.0f;
-            metadata.offset_hdr = 0.0f;
-            metadata.hdr_capacity_min = 1.0f;
-            metadata.hdr_capacity_max = metadata.max_content_boost;
+            metadata.max_content_boost = maxBoost;
+            metadata.min_content_boost = minBoost;
+            metadata.gamma = gamma;
+            metadata.offset_sdr = offsetSdr;
+            metadata.offset_hdr = offsetHdr;
+            metadata.hdr_capacity_min = minCapacity;
+            metadata.hdr_capacity_max = maxCapacity;
             ON_ERR(uhdr_enc_set_compressed_image(enc_handle, &jpegImg, UHDR_BASE_IMG))
             ON_ERR(uhdr_enc_set_gainmap_image(enc_handle, &jpegGainMap, &metadata))
             status = uhdr_encode(enc_handle);
@@ -315,10 +412,10 @@ void UltraHdrEncFuzzer::process() {
         uhdr_codec_private_t* dec_handle = uhdr_create_decoder();
         if (dec_handle) {
           ON_ERR(uhdr_dec_set_image(dec_handle, output))
-          ON_ERR(uhdr_dec_set_out_color_transfer(dec_handle, tf))
-          if (tf == UHDR_CT_LINEAR)
+          ON_ERR(uhdr_dec_set_out_color_transfer(dec_handle, hdr_ct))
+          if (hdr_ct == UHDR_CT_LINEAR)
             ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_64bppRGBAHalfFloat))
-          else if (tf == UHDR_CT_SRGB)
+          else if (hdr_ct == UHDR_CT_SRGB)
             ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA8888))
           else
             ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA1010102))
@@ -326,11 +423,10 @@ void UltraHdrEncFuzzer::process() {
           uhdr_release_decoder(dec_handle);
         }
       }
-      uhdr_release_encoder(enc_handle);
-    } else {
-      uhdr_release_encoder(enc_handle);
-      ON_ERR(status);
     }
+    uhdr_reset_encoder(enc_handle);
+    uhdr_release_encoder(enc_handle);
+    ON_ERR(status);
   }
 }
 
diff --git a/fuzzer/ultrahdr_legacy_fuzzer.cpp b/fuzzer/ultrahdr_legacy_fuzzer.cpp
new file mode 100644
index 0000000..2b78340
--- /dev/null
+++ b/fuzzer/ultrahdr_legacy_fuzzer.cpp
@@ -0,0 +1,344 @@
+/*
+ * Copyright 2023 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <fuzzer/FuzzedDataProvider.h>
+#include <algorithm>
+#include <iostream>
+#include <memory>
+#include <random>
+
+#include "ultrahdr/ultrahdrcommon.h"
+#include "ultrahdr/gainmapmath.h"
+#include "ultrahdr/jpegr.h"
+
+using namespace ultrahdr;
+
+// Color gamuts for image data, sync with ultrahdr.h
+const int kCgMin = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+const int kCgMax = ULTRAHDR_COLORGAMUT_BT2100;
+
+// Transfer functions for image data, sync with ultrahdr.h
+const int kTfMin = ULTRAHDR_TF_UNSPECIFIED;
+const int kTfMax = ULTRAHDR_TF_SRGB;
+
+// Transfer functions for image data, sync with ultrahdr.h
+const int kOfMin = ULTRAHDR_OUTPUT_UNSPECIFIED;
+const int kOfMax = ULTRAHDR_OUTPUT_HDR_HLG;
+
+// quality factor
+const int kQfMin = -10;
+const int kQfMax = 110;
+
+class UltraHdrEncFuzzer {
+ public:
+  UltraHdrEncFuzzer(const uint8_t* data, size_t size) : mFdp(data, size) {};
+  void process();
+  template <typename T>
+  void fillBuffer(T* data, int width, int height, int stride);
+
+ private:
+  FuzzedDataProvider mFdp;
+};
+
+template <typename T>
+void UltraHdrEncFuzzer::fillBuffer(T* data, int width, int height, int stride) {
+  if (!mFdp.remaining_bytes()) return;
+
+  T* tmp = data;
+  std::vector<T> buffer(width);
+  for (int i = 0; i < buffer.size(); i++) {
+    buffer[i] = mFdp.ConsumeIntegral<T>();
+  }
+  for (int j = 0; j < height; j++) {
+    for (int i = 0; i < width; i += buffer.size()) {
+      memcpy(tmp + i, buffer.data(), std::min((int)buffer.size(), (width - i)) * sizeof(*data));
+      std::shuffle(buffer.begin(), buffer.end(),
+                   std::default_random_engine(std::random_device{}()));
+    }
+    tmp += stride;
+  }
+}
+
+void UltraHdrEncFuzzer::process() {
+  if (mFdp.remaining_bytes()) {
+    struct jpegr_uncompressed_struct p010Img{};
+    struct jpegr_uncompressed_struct yuv420Img{};
+    struct jpegr_uncompressed_struct grayImg{};
+    struct jpegr_compressed_struct jpegImgR{};
+    struct jpegr_compressed_struct jpegImg{};
+    struct jpegr_compressed_struct jpegGainMap{};
+
+    // which encode api to select
+    int muxSwitch = mFdp.ConsumeIntegralInRange<int>(0, 4);
+
+    // quality factor
+    int quality = mFdp.ConsumeIntegralInRange<int>(kQfMin, kQfMax);
+
+    // hdr_tf
+    auto tf =
+        static_cast<ultrahdr_transfer_function>(mFdp.ConsumeIntegralInRange<int>(kTfMin, kTfMax));
+
+    // p010 Cg
+    auto p010Cg =
+        static_cast<ultrahdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));
+
+    // 420 Cg
+    auto yuv420Cg =
+        static_cast<ultrahdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));
+
+    // hdr_of
+    auto of = static_cast<ultrahdr_output_format>(mFdp.ConsumeIntegralInRange<int>(kOfMin, kOfMax));
+
+    int width = mFdp.ConsumeIntegralInRange<int>(kMinWidth, kMaxWidth);
+    width = (width >> 1) << 1;
+
+    int height = mFdp.ConsumeIntegralInRange<int>(kMinHeight, kMaxHeight);
+    height = (height >> 1) << 1;
+
+    // gain_map quality factor
+    auto gainmap_quality = mFdp.ConsumeIntegral<int8_t>();
+
+    // multi channel gainmap
+    auto multi_channel_gainmap = mFdp.ConsumeIntegral<int8_t>();
+
+    // gainmap scale factor
+    auto gm_scale_factor = mFdp.ConsumeIntegralInRange<int16_t>(-32, 192);
+
+    // encoding speed preset
+    auto enc_preset = mFdp.ConsumeBool() ? UHDR_USAGE_REALTIME : UHDR_USAGE_BEST_QUALITY;
+
+    // gainmap metadata
+    auto minBoost = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
+    auto maxBoost = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 64.0f);
+    auto gamma = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 5);
+    auto offsetSdr = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
+    auto offsetHdr = mFdp.ConsumeFloatingPointInRange<float>(-1.0f, 1.0f);
+    auto minCapacity = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
+    auto maxCapacity = mFdp.ConsumeFloatingPointInRange<float>(-4.0f, 48.0f);
+
+    // target display peak brightness
+    auto targetDispPeakBrightness = mFdp.ConsumeFloatingPointInRange<float>(100.0f, 10500.0f);
+
+    // raw buffer config
+    bool hasP010Stride = mFdp.ConsumeBool();
+    size_t yP010Stride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
+    if (!hasP010Stride) yP010Stride = width;
+    bool isP010UVContiguous = mFdp.ConsumeBool();
+    bool hasP010UVStride = mFdp.ConsumeBool();
+    size_t uvP010Stride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
+    if (!hasP010UVStride) uvP010Stride = width;
+
+    bool hasYuv420Stride = mFdp.ConsumeBool();
+    size_t yYuv420Stride = mFdp.ConsumeIntegralInRange<uint16_t>(width, width + 128);
+    if (!hasYuv420Stride) yYuv420Stride = width;
+    bool isYuv420UVContiguous = mFdp.ConsumeBool();
+    bool hasYuv420UVStride = mFdp.ConsumeBool();
+    size_t uvYuv420Stride = mFdp.ConsumeIntegralInRange<uint16_t>(width / 2, width / 2 + 128);
+    if (!hasYuv420UVStride) uvYuv420Stride = width / 2;
+
+    // display boost
+    float displayBoost = mFdp.ConsumeFloatingPointInRange<float>(1.0, FLT_MAX);
+
+    std::unique_ptr<uint16_t[]> bufferYHdr = nullptr;
+    std::unique_ptr<uint16_t[]> bufferUVHdr = nullptr;
+    std::unique_ptr<uint8_t[]> bufferYSdr = nullptr;
+    std::unique_ptr<uint8_t[]> bufferUVSdr = nullptr;
+    std::unique_ptr<uint8_t[]> grayImgRaw = nullptr;
+    if (muxSwitch != 4) {
+      // init p010 image
+      p010Img.width = width;
+      p010Img.height = height;
+      p010Img.colorGamut = p010Cg;
+      p010Img.luma_stride = yP010Stride;
+      if (isP010UVContiguous) {
+        size_t p010Size = yP010Stride * height * 3 / 2;
+        bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
+        p010Img.data = bufferYHdr.get();
+        p010Img.chroma_data = nullptr;
+        p010Img.chroma_stride = 0;
+        fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yP010Stride);
+        fillBuffer<uint16_t>(bufferYHdr.get() + yP010Stride * height, width, height / 2,
+                             yP010Stride);
+      } else {
+        size_t p010YSize = yP010Stride * height;
+        bufferYHdr = std::make_unique<uint16_t[]>(p010YSize);
+        p010Img.data = bufferYHdr.get();
+        fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yP010Stride);
+        size_t p010UVSize = uvP010Stride * p010Img.height / 2;
+        bufferUVHdr = std::make_unique<uint16_t[]>(p010UVSize);
+        p010Img.chroma_data = bufferUVHdr.get();
+        p010Img.chroma_stride = uvP010Stride;
+        fillBuffer<uint16_t>(bufferUVHdr.get(), width, height / 2, uvP010Stride);
+      }
+    } else {
+      size_t map_width = width / kMapDimensionScaleFactorDefault;
+      size_t map_height = height / kMapDimensionScaleFactorDefault;
+      // init 400 image
+      grayImg.width = map_width;
+      grayImg.height = map_height;
+      grayImg.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+      const size_t graySize = map_width * map_height;
+      grayImgRaw = std::make_unique<uint8_t[]>(graySize);
+      grayImg.data = grayImgRaw.get();
+      fillBuffer<uint8_t>(grayImgRaw.get(), map_width, map_height, map_width);
+      grayImg.chroma_data = nullptr;
+      grayImg.luma_stride = 0;
+      grayImg.chroma_stride = 0;
+    }
+
+    if (muxSwitch > 0) {
+      // init 420 image
+      yuv420Img.width = width;
+      yuv420Img.height = height;
+      yuv420Img.colorGamut = yuv420Cg;
+      yuv420Img.luma_stride = yYuv420Stride;
+      if (isYuv420UVContiguous) {
+        size_t yuv420Size = yYuv420Stride * height * 3 / 2;
+        bufferYSdr = std::make_unique<uint8_t[]>(yuv420Size);
+        yuv420Img.data = bufferYSdr.get();
+        yuv420Img.chroma_data = nullptr;
+        yuv420Img.chroma_stride = 0;
+        fillBuffer<uint8_t>(bufferYSdr.get(), width, height, yYuv420Stride);
+        fillBuffer<uint8_t>(bufferYSdr.get() + yYuv420Stride * height, width / 2, height / 2,
+                            yYuv420Stride / 2);
+        fillBuffer<uint8_t>(bufferYSdr.get() + yYuv420Stride * height * 5 / 4, width / 2,
+                            height / 2, yYuv420Stride / 2);
+      } else {
+        size_t yuv420YSize = yYuv420Stride * height;
+        bufferYSdr = std::make_unique<uint8_t[]>(yuv420YSize);
+        yuv420Img.data = bufferYSdr.get();
+        fillBuffer<uint8_t>(bufferYSdr.get(), width, height, yYuv420Stride);
+        size_t yuv420UVSize = uvYuv420Stride * yuv420Img.height / 2 * 2;
+        bufferUVSdr = std::make_unique<uint8_t[]>(yuv420UVSize);
+        yuv420Img.chroma_data = bufferUVSdr.get();
+        yuv420Img.chroma_stride = uvYuv420Stride;
+        fillBuffer<uint8_t>(bufferUVSdr.get(), width / 2, height / 2, uvYuv420Stride);
+        fillBuffer<uint8_t>(bufferUVSdr.get() + uvYuv420Stride * height / 2, width / 2, height / 2,
+                            uvYuv420Stride);
+      }
+    }
+
+    // dest
+    // 2 * p010 size as input data is random, DCT compression might not behave as expected
+    jpegImgR.maxLength = std::max(8 * 1024 /* min size 8kb */, width * height * 3 * 2);
+    auto jpegImgRaw = std::make_unique<uint8_t[]>(jpegImgR.maxLength);
+    jpegImgR.data = jpegImgRaw.get();
+// #define DUMP_PARAM
+#ifdef DUMP_PARAM
+    std::cout << "Api Select " << muxSwitch << std::endl;
+    std::cout << "image dimensions " << width << " x " << height << std::endl;
+    std::cout << "p010 color gamut " << p010Img.colorGamut << std::endl;
+    std::cout << "p010 luma stride " << p010Img.luma_stride << std::endl;
+    std::cout << "p010 chroma stride " << p010Img.chroma_stride << std::endl;
+    std::cout << "420 color gamut " << yuv420Img.colorGamut << std::endl;
+    std::cout << "420 luma stride " << yuv420Img.luma_stride << std::endl;
+    std::cout << "420 chroma stride " << yuv420Img.chroma_stride << std::endl;
+    std::cout << "quality factor " << quality << std::endl;
+#endif
+    JpegR jpegHdr(nullptr, gm_scale_factor, gainmap_quality, multi_channel_gainmap, gamma,
+                  enc_preset, minBoost, maxBoost, targetDispPeakBrightness);
+    status_t status = JPEGR_UNKNOWN_ERROR;
+    if (muxSwitch == 0) {  // api 0
+      jpegImgR.length = 0;
+      status = jpegHdr.encodeJPEGR(&p010Img, tf, &jpegImgR, quality, nullptr);
+    } else if (muxSwitch == 1) {  // api 1
+      jpegImgR.length = 0;
+      status = jpegHdr.encodeJPEGR(&p010Img, &yuv420Img, tf, &jpegImgR, quality, nullptr);
+    } else {
+      // compressed img
+      JpegEncoderHelper encoder;
+      struct jpegr_uncompressed_struct yuv420ImgCopy = yuv420Img;
+      if (yuv420ImgCopy.luma_stride == 0) yuv420ImgCopy.luma_stride = yuv420Img.width;
+      if (!yuv420ImgCopy.chroma_data) {
+        uint8_t* data = reinterpret_cast<uint8_t*>(yuv420Img.data);
+        yuv420ImgCopy.chroma_data = data + yuv420Img.luma_stride * yuv420Img.height;
+        yuv420ImgCopy.chroma_stride = yuv420Img.luma_stride >> 1;
+      }
+      const uint8_t* planes[3]{reinterpret_cast<uint8_t*>(yuv420ImgCopy.data),
+                               reinterpret_cast<uint8_t*>(yuv420ImgCopy.chroma_data),
+                               reinterpret_cast<uint8_t*>(yuv420ImgCopy.chroma_data) +
+                                   yuv420ImgCopy.chroma_stride * yuv420ImgCopy.height / 2};
+      const unsigned int strides[3]{yuv420ImgCopy.luma_stride, yuv420ImgCopy.chroma_stride,
+                                    yuv420ImgCopy.chroma_stride};
+      if (encoder
+              .compressImage(planes, strides, yuv420ImgCopy.width, yuv420ImgCopy.height,
+                             UHDR_IMG_FMT_12bppYCbCr420, quality, nullptr, 0)
+              .error_code == UHDR_CODEC_OK) {
+        jpegImg.length = encoder.getCompressedImageSize();
+        jpegImg.maxLength = jpegImg.length;
+        jpegImg.data = encoder.getCompressedImagePtr();
+        jpegImg.colorGamut = yuv420Cg;
+        if (muxSwitch == 2) {  // api 2
+          jpegImgR.length = 0;
+          status = jpegHdr.encodeJPEGR(&p010Img, &yuv420Img, &jpegImg, tf, &jpegImgR);
+        } else if (muxSwitch == 3) {  // api 3
+          jpegImgR.length = 0;
+          status = jpegHdr.encodeJPEGR(&p010Img, &jpegImg, tf, &jpegImgR);
+        } else if (muxSwitch == 4) {  // api 4
+          jpegImgR.length = 0;
+          JpegEncoderHelper gainMapEncoder;
+          const uint8_t* planeGm[1]{reinterpret_cast<uint8_t*>(grayImg.data)};
+          const unsigned int strideGm[1]{grayImg.width};
+          if (gainMapEncoder
+                  .compressImage(planeGm, strideGm, grayImg.width, grayImg.height,
+                                 UHDR_IMG_FMT_8bppYCbCr400, quality, nullptr, 0)
+                  .error_code == UHDR_CODEC_OK) {
+            jpegGainMap.length = gainMapEncoder.getCompressedImageSize();
+            jpegGainMap.maxLength = jpegImg.length;
+            jpegGainMap.data = gainMapEncoder.getCompressedImagePtr();
+            jpegGainMap.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+            ultrahdr_metadata_struct metadata;
+            metadata.version = kJpegrVersion;
+            metadata.maxContentBoost = maxBoost;
+            metadata.minContentBoost = minBoost;
+            metadata.gamma = gamma;
+            metadata.offsetSdr = offsetSdr;
+            metadata.offsetHdr = offsetHdr;
+            metadata.hdrCapacityMin = minCapacity;
+            metadata.hdrCapacityMax = maxCapacity;
+            status = jpegHdr.encodeJPEGR(&jpegImg, &jpegGainMap, &metadata, &jpegImgR);
+          }
+        }
+      }
+    }
+    if (status == JPEGR_NO_ERROR) {
+      jpegr_info_struct info{};
+      status = jpegHdr.getJPEGRInfo(&jpegImgR, &info);
+      if (status == JPEGR_NO_ERROR) {
+        size_t outSize = info.width * info.height * ((of == ULTRAHDR_OUTPUT_HDR_LINEAR) ? 8 : 4);
+        jpegr_uncompressed_struct decodedJpegR;
+        auto decodedRaw = std::make_unique<uint8_t[]>(outSize);
+        decodedJpegR.data = decodedRaw.get();
+        ultrahdr_metadata_struct metadata;
+        status = jpegHdr.decodeJPEGR(&jpegImgR, &decodedJpegR, displayBoost, nullptr, of, nullptr,
+                                     &metadata);
+        if (status != JPEGR_NO_ERROR) {
+          ALOGE("encountered error during decoding %d", status);
+        }
+      } else {
+        ALOGE("encountered error during get jpeg info %d", status);
+      }
+    } else {
+      ALOGE("encountered error during encoding %d", status);
+    }
+  }
+}
+
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+  UltraHdrEncFuzzer fuzzHandle(data, size);
+  fuzzHandle.process();
+  return 0;
+}
diff --git a/java/UltraHdrApp.java b/java/UltraHdrApp.java
index e6376e5..2b90dab 100644
--- a/java/UltraHdrApp.java
+++ b/java/UltraHdrApp.java
@@ -64,10 +64,12 @@ public class UltraHdrApp {
     private final int mEncPreset;
     private final float mMinContentBoost;
     private final float mMaxContentBoost;
+    private final float mTargetDispPeakBrightness;
 
     byte[] mYuv420YData, mYuv420CbData, mYuv420CrData;
     short[] mP010YData, mP010CbCrData;
     int[] mRgba1010102Data, mRgba8888Data;
+    long[] mRgbaF16Data;
     byte[] mCompressedImageData;
     byte[] mGainMapCompressedImageData;
     byte[] mExifData;
@@ -81,7 +83,7 @@ public class UltraHdrApp {
             int height, int hdrCf, int sdrCf, int hdrCg, int sdrCg, int hdrTf, int quality, int oTf,
             int oFmt, boolean isHdrCrFull, int gainmapScaleFactor, int gainmapQuality,
             boolean enableMultiChannelGainMap, float gamma, int encPreset, float minContentBoost,
-            float maxContentBoost) {
+            float maxContentBoost, float targetDispPeakBrightness) {
         mHdrIntentRawFile = hdrIntentRawFile;
         mSdrIntentRawFile = sdrIntentRawFile;
         mSdrIntentCompressedFile = sdrIntentCompressedFile;
@@ -109,6 +111,7 @@ public class UltraHdrApp {
         mEncPreset = encPreset;
         mMinContentBoost = minContentBoost;
         mMaxContentBoost = maxContentBoost;
+        mTargetDispPeakBrightness = targetDispPeakBrightness;
     }
 
     public UltraHdrApp(String gainmapMetadataCfgFile, String uhdrFile, String outputFile, int oTF,
@@ -140,6 +143,7 @@ public class UltraHdrApp {
         mEncPreset = UHDR_USAGE_BEST_QUALITY;
         mMinContentBoost = Float.MIN_VALUE;
         mMaxContentBoost = Float.MAX_VALUE;
+        mTargetDispPeakBrightness = -1.0f;
     }
 
     public byte[] readFile(String filename) throws IOException {
@@ -194,6 +198,22 @@ public class UltraHdrApp {
         byteBuffer.asIntBuffer().get(mRgba1010102Data);
     }
 
+    public void fillRGBAF16ImageHandle() throws IOException {
+        final int bpp = 8;
+        final int rgbSampleCount = mHeight * mWidth;
+        final int expectedSize = rgbSampleCount * bpp;
+        byte[] data = readFile(mHdrIntentRawFile);
+        if (data.length < expectedSize) {
+            throw new RuntimeException("For the configured width, height, RGBA1010102 Image File is"
+                    + " expected to contain " + expectedSize + " bytes, but the file has "
+                    + data.length + " bytes");
+        }
+        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
+        byteBuffer.order(ByteOrder.nativeOrder());
+        mRgbaF16Data = new long[mHeight * mWidth];
+        byteBuffer.asLongBuffer().get(mRgbaF16Data);
+    }
+
     public void fillRGBA8888Handle() throws IOException {
         final int bpp = 4;
         final int rgbSampleCount = mHeight * mWidth;
@@ -341,6 +361,10 @@ public class UltraHdrApp {
                     fillRGBA1010102ImageHandle();
                     handle.setRawImage(mRgba1010102Data, mWidth, mHeight, mWidth, mHdrCg, mHdrTf,
                             UHDR_CR_FULL_RANGE, mHdrCf, UHDR_HDR_IMG);
+                } else if (mHdrCf == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+                    fillRGBAF16ImageHandle();
+                    handle.setRawImage(mRgbaF16Data, mWidth, mHeight, mWidth, mHdrCg, mHdrTf,
+                            UHDR_CR_FULL_RANGE, mHdrCf, UHDR_HDR_IMG);
                 } else {
                     throw new IllegalArgumentException("invalid hdr intent color format " + mHdrCf);
                 }
@@ -387,6 +411,9 @@ public class UltraHdrApp {
             if (mMinContentBoost != Float.MIN_VALUE || mMaxContentBoost != Float.MAX_VALUE) {
                 handle.setMinMaxContentBoost(mMinContentBoost, mMaxContentBoost);
             }
+            if (mTargetDispPeakBrightness != -1.0f) {
+                handle.setTargetDisplayPeakBrightness(mTargetDispPeakBrightness);
+            }
             handle.encode();
             mUhdrImagedata = handle.getOutput();
             writeFile(mOutputFile, mUhdrImagedata);
@@ -423,8 +450,8 @@ public class UltraHdrApp {
                 + " scenarios 0, 1, 2, 3.");
         System.out.println("    -y    raw sdr intent input resource (8-bit), required for encoding"
                 + " scenarios 1, 2.");
-        System.out.println("    -a    raw hdr intent color format, optional. [0:p010, 5:rgba1010102"
-                + " (default)]");
+        System.out.println("    -a    raw hdr intent color format, optional. [0:p010, "
+                + "4: rgbahalffloat, 5:rgba1010102 (default)]");
         System.out.println("    -b    raw sdr intent color format, optional. [1:yuv420, 3:rgba8888"
                 + " (default)]");
         System.out.println("    -i    compressed sdr intent input resource (jpeg), required for "
@@ -441,6 +468,13 @@ public class UltraHdrApp {
                 "    -c    sdr intent color gamut, optional. [0:bt709 (default), 1:p3, 2:bt2100]");
         System.out.println(
                 "    -t    hdr intent color transfer, optional. [0:linear, 1:hlg (default), 2:pq]");
+        System.out.println(
+                "          It should be noted that not all combinations of input color format and"
+                        + " input color transfer are supported.");
+        System.out.println(
+                "          srgb color transfer shall be paired with rgba8888 or yuv420 only.");
+        System.out.println("          hlg, pq shall be paired with rgba1010102 or p010.");
+        System.out.println("          linear shall be paired with rgbahalffloat.");
         System.out.println("    -q    quality factor to be used while encoding sdr intent, "
                 + "optional. [0-100], 95 : default.");
         System.out.println("    -R    color range of hdr intent, optional. [0:narrow-range "
@@ -459,6 +493,10 @@ public class UltraHdrApp {
                 + " optional. any positive real number");
         System.out.println("    -K    max content boost recommendation, must be in linear scale,"
                 + " optional. any positive real number");
+        System.out.println("    -L    set target display peak brightness in nits, optional");
+        System.out.println("          For HLG content, this defaults to 1000 nits.");
+        System.out.println("          For PQ content, this defaults to 10000 nits.");
+        System.out.println("          any real number in range [203, 10000].");
         System.out.println("    -x    binary input resource containing exif data to insert, "
                 + "optional.");
         System.out.println("\n## decoder options :");
@@ -552,7 +590,7 @@ public class UltraHdrApp {
         String output_file = null;
         String exif_file = null;
         int width = 0, height = 0;
-        int hdr_cg = UHDR_CG_DISPlAY_P3;
+        int hdr_cg = UHDR_CG_DISPLAY_P3;
         int sdr_cg = UHDR_CG_BT709;
         int hdr_cf = UHDR_IMG_FMT_32bppRGBA1010102;
         int sdr_cf = UHDR_IMG_FMT_32bppRGBA8888;
@@ -568,6 +606,7 @@ public class UltraHdrApp {
         boolean enable_gles = false;
         float min_content_boost = Float.MIN_VALUE;
         float max_content_boost = Float.MAX_VALUE;
+        float target_disp_max_brightness = -1.0f;
         boolean use_full_range_color_hdr = false;
         boolean use_multi_channel_gainmap = true;
 
@@ -658,6 +697,9 @@ public class UltraHdrApp {
                     case 'K':
                         max_content_boost = Float.parseFloat(args[++i]);
                         break;
+                    case 'L':
+                        target_disp_max_brightness = Float.parseFloat(args[++i]);
+                        break;
                     default:
                         System.err.println("Unrecognized option, arg: " + args[i]);
                         usage();
@@ -691,7 +733,7 @@ public class UltraHdrApp {
                     hdr_cf, sdr_cf, hdr_cg, sdr_cg, hdr_tf, quality, out_tf, out_cf,
                     use_full_range_color_hdr, gain_map_scale_factor, gainmap_compression_quality,
                     use_multi_channel_gainmap, gamma, enc_preset, min_content_boost,
-                    max_content_boost);
+                    max_content_boost, target_disp_max_brightness);
             appInput.encode();
         } else if (mode == 1) {
             if (uhdr_file == null) {
diff --git a/java/com/google/media/codecs/ultrahdr/UltraHDRCommon.java b/java/com/google/media/codecs/ultrahdr/UltraHDRCommon.java
index 4deb117..ec8d111 100644
--- a/java/com/google/media/codecs/ultrahdr/UltraHDRCommon.java
+++ b/java/com/google/media/codecs/ultrahdr/UltraHDRCommon.java
@@ -79,8 +79,9 @@ public class UltraHDRCommon {
     public static final int UHDR_IMG_FMT_32bppRGBA8888 = 3;
 
     /**
-     * 64 bits per pixel RGBA color format, with 16-bit signed
-     * floating point red, green, blue, and alpha components.
+     * 64 bits per pixel, 16 bits per channel, half-precision floating point RGBA color format.
+     * In a pixel even though each channel has storage space of 16 bits, the nominal range is
+     * expected to be [0.0..(10000/203)]
      * <p>
      *
      * <pre>
@@ -125,7 +126,7 @@ public class UltraHDRCommon {
     /**
      * Display P3 color chromaticity coordinates with KR = 0.22897, KB = 0.07929
      */
-    public static final int UHDR_CG_DISPlAY_P3 = 1;
+    public static final int UHDR_CG_DISPLAY_P3 = 1;
 
     /**
      * BT.2020 color chromaticity coordinates with KR = 0.2627, KB = 0.0593
diff --git a/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java b/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java
index e297d56..bc3427d 100644
--- a/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java
+++ b/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java
@@ -20,6 +20,7 @@ import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_12bpp
 import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_24bppYCbCrP010;
 import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_32bppRGBA1010102;
 import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_32bppRGBA8888;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_64bppRGBAHalfFloat;
 
 import java.io.IOException;
 
@@ -117,6 +118,44 @@ public class UltraHDREncoder implements AutoCloseable {
                 colorFormat, intent);
     }
 
+    /**
+     * Add raw image info to encoder context. This interface is used for adding 64 bits-per-pixel
+     * packed formats. The function goes through all the arguments and checks for their sanity.
+     * If no anomalies are seen then the image info is added to internal list. Repeated calls to
+     * this function will replace the old entry with the current.
+     *
+     * @param rgbBuff       rgb buffer handle
+     * @param width         image width
+     * @param height        image height
+     * @param rgbStride     rgb buffer stride
+     * @param colorGamut    color gamut of input image
+     * @param colorTransfer color transfer of input image
+     * @param colorRange    color range of input image
+     * @param colorFormat   color format of input image
+     * @param intent        {@link UltraHDRCommon#UHDR_HDR_IMG} for hdr intent
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setRawImage(long[] rgbBuff, int width, int height, int rgbStride, int colorGamut,
+            int colorTransfer, int colorRange, int colorFormat, int intent) throws IOException {
+        if (rgbBuff == null) {
+            throw new IOException("received null for image data handle");
+        }
+        if (width <= 0 || height <= 0) {
+            throw new IOException("received bad width and/or height, width or height is <= 0");
+        }
+        if (rgbStride <= 0) {
+            throw new IOException("received bad stride, stride is <= 0");
+        }
+        if (colorFormat != UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+            throw new IOException("received unsupported color format. supported color formats are"
+                    + "{UHDR_IMG_FMT_64bppRGBAHalfFloat}");
+        }
+        setRawImageNative(rgbBuff, width, height, rgbStride, colorGamut, colorTransfer, colorRange,
+                colorFormat, intent);
+    }
+
     /**
      * Add raw image info to encoder context. This interface is used for adding 16 bits-per-sample
      * pixel formats. The function goes through all the arguments and checks for their sanity. If
@@ -414,6 +453,25 @@ public class UltraHDREncoder implements AutoCloseable {
         setMinMaxContentBoostNative(minContentBoost, maxContentBoost);
     }
 
+    /**
+     * Set target display peak brightness in nits. This is used for configuring
+     * {@link UltraHDRDecoder.GainMapMetadata#hdrCapacityMax}. This value determines the weight
+     * by which the gain map coefficients are scaled during decode. If this is not configured,
+     * then default peak luminance of HDR intent's color transfer under test is used. For
+     * {@link UltraHDRCommon#UHDR_CT_HLG} input, this corresponds to 1000 nits and for
+     * {@link UltraHDRCommon#UHDR_CT_LINEAR} and {@link UltraHDRCommon#UHDR_CT_PQ} inputs, this
+     * corresponds to 10000 nits.
+     *
+     * @param nits target display peak brightness in nits. Any positive real number in range
+     *             [203, 10000]
+     * @throws IOException If parameters are not valid or current encoder instance
+     *                     is not valid or current encoder instance is not suitable
+     *                     for configuration exception is thrown
+     */
+    public void setTargetDisplayPeakBrightness(float nits) throws IOException {
+        setTargetDisplayPeakBrightnessNative(nits);
+    }
+
     /**
      * Encode process call.
      * <p>
@@ -457,6 +515,10 @@ public class UltraHDREncoder implements AutoCloseable {
             int colorGamut, int colorTransfer, int colorRange, int colorFormat, int intent)
             throws IOException;
 
+    private native void setRawImageNative(long[] rgbBuff, int width, int height, int rgbStride,
+            int colorGamut, int colorTransfer, int colorRange, int colorFormat, int intent)
+            throws IOException;
+
     private native void setRawImageNative(short[] yBuff, short[] uvBuff, int width, int height,
             int yStride, int uvStride, int colorGamut, int colorTransfer, int colorRange,
             int colorFormat, int intent) throws IOException;
@@ -489,6 +551,8 @@ public class UltraHDREncoder implements AutoCloseable {
     private native void setMinMaxContentBoostNative(float minContentBoost,
             float maxContentBoost) throws IOException;
 
+    private native void setTargetDisplayPeakBrightnessNative(float nits) throws IOException;
+
     private native void encodeNative() throws IOException;
 
     private native byte[] getOutputNative() throws IOException;
diff --git a/java/jni/com_google_media_codecs_ultrahdr_UltraHDRCommon.h b/java/jni/com_google_media_codecs_ultrahdr_UltraHDRCommon.h
index 2537686..ab26b88 100644
--- a/java/jni/com_google_media_codecs_ultrahdr_UltraHDRCommon.h
+++ b/java/jni/com_google_media_codecs_ultrahdr_UltraHDRCommon.h
@@ -25,8 +25,8 @@ extern "C" {
 #define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_UNSPECIFIED -1L
 #undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_BT709
 #define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_BT709 0L
-#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_DISPlAY_P3
-#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_DISPlAY_P3 1L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_DISPLAY_P3
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_DISPLAY_P3 1L
 #undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_BT2100
 #define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_BT2100 2L
 #undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_UNSPECIFIED
diff --git a/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h b/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h
index bd55537..985b6ae 100644
--- a/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h
+++ b/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h
@@ -41,6 +41,14 @@ JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_des
 JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3IIIIIIIII
   (JNIEnv *, jobject, jintArray, jint, jint, jint, jint, jint, jint, jint, jint);
 
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setRawImageNative
+ * Signature: ([JIIIIIIII)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3JIIIIIIII
+  (JNIEnv *, jobject, jlongArray, jint, jint, jint, jint, jint, jint, jint, jint);
+
 /*
  * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
  * Method:    setRawImageNative
@@ -137,6 +145,14 @@ JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_set
 JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setMinMaxContentBoostNative
   (JNIEnv *, jobject, jfloat, jfloat);
 
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setTargetDisplayPeakBrightnessNative
+ * Signature: (F)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setTargetDisplayPeakBrightnessNative
+  (JNIEnv *, jobject, jfloat);
+
 /*
  * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
  * Method:    encodeNative
diff --git a/java/jni/ultrahdr-jni.cpp b/java/jni/ultrahdr-jni.cpp
index c545462..0fa8f4b 100644
--- a/java/jni/ultrahdr-jni.cpp
+++ b/java/jni/ultrahdr-jni.cpp
@@ -98,7 +98,7 @@ Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3IIIII
   RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
   jsize length = env->GetArrayLength(rgb_buff);
   RET_IF_TRUE(length < height * rgb_stride, "java/io/IOException",
-              "compressed image luma byteArray size is less than required size")
+              "raw image rgba byteArray size is less than required size")
   jint *rgbBody = env->GetIntArrayElements(rgb_buff, nullptr);
   uhdr_raw_image_t img{(uhdr_img_fmt_t)color_format,
                        (uhdr_color_gamut_t)color_gamut,
@@ -115,6 +115,31 @@ Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3IIIII
               status.has_detail ? status.detail : "uhdr_enc_set_raw_image() returned with error")
 }
 
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3JIIIIIIII(
+    JNIEnv *env, jobject thiz, jlongArray rgb_buff, jint width, jint height, jint rgb_stride,
+    jint color_gamut, jint color_transfer, jint color_range, jint color_format, jint intent) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  jsize length = env->GetArrayLength(rgb_buff);
+  RET_IF_TRUE(length < height * rgb_stride, "java/io/IOException",
+              "raw image rgba byteArray size is less than required size")
+  jlong *rgbBody = env->GetLongArrayElements(rgb_buff, nullptr);
+  uhdr_raw_image_t img{(uhdr_img_fmt_t)color_format,
+                       (uhdr_color_gamut_t)color_gamut,
+                       (uhdr_color_transfer_t)color_transfer,
+                       (uhdr_color_range_t)color_range,
+                       (unsigned int)width,
+                       (unsigned int)height,
+                       {rgbBody, nullptr, nullptr},
+                       {(unsigned int)rgb_stride, 0u, 0u}};
+  auto status =
+      uhdr_enc_set_raw_image((uhdr_codec_private_t *)handle, &img, (uhdr_img_label_t)intent);
+  env->ReleaseLongArrayElements(rgb_buff, rgbBody, 0);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_enc_set_raw_image() returned with error")
+}
+
 extern "C" JNIEXPORT void JNICALL
 Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3S_3SIIIIIIIII(
     JNIEnv *env, jobject thiz, jshortArray y_buff, jshortArray uv_buff, jint width, jint height,
@@ -124,10 +149,10 @@ Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3S_3SI
   RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
   jsize length = env->GetArrayLength(y_buff);
   RET_IF_TRUE(length < height * y_stride, "java/io/IOException",
-              "compressed image luma byteArray size is less than required size")
+              "raw image luma byteArray size is less than required size")
   length = env->GetArrayLength(uv_buff);
   RET_IF_TRUE(length < height * uv_stride / 2, "java/io/IOException",
-              "compressed image cb byteArray size is less than required size")
+              "raw image chroma byteArray size is less than required size")
   jshort *lumaBody = env->GetShortArrayElements(y_buff, nullptr);
   jshort *chromaBody = env->GetShortArrayElements(uv_buff, nullptr);
   uhdr_raw_image_t img{(uhdr_img_fmt_t)color_format,
@@ -155,13 +180,13 @@ Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3B_3B_
   RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
   jsize length = env->GetArrayLength(y_buff);
   RET_IF_TRUE(length < height * y_stride, "java/io/IOException",
-              "compressed image luma byteArray size is less than required size")
+              "raw image luma byteArray size is less than required size")
   length = env->GetArrayLength(u_buff);
   RET_IF_TRUE(length < height * u_stride / 4, "java/io/IOException",
-              "compressed image cb byteArray size is less than required size")
+              "raw image cb byteArray size is less than required size")
   length = env->GetArrayLength(v_buff);
   RET_IF_TRUE(length < height * v_stride / 4, "java/io/IOException",
-              "compressed image cb byteArray size is less than required size")
+              "raw image cb byteArray size is less than required size")
   jbyte *lumaBody = env->GetByteArrayElements(y_buff, nullptr);
   jbyte *cbBody = env->GetByteArrayElements(u_buff, nullptr);
   jbyte *crBody = env->GetByteArrayElements(v_buff, nullptr);
@@ -333,6 +358,18 @@ Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setMinMaxContentBoostNativ
                                 : "uhdr_enc_set_min_max_content_boost() returned with error")
 }
 
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setTargetDisplayPeakBrightnessNative(
+    JNIEnv *env, jobject thiz, jfloat nits) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  auto status = uhdr_enc_set_target_display_peak_brightness((uhdr_codec_private_t *)handle, nits);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail
+                  ? status.detail
+                  : "uhdr_enc_set_target_display_peak_brightness() returned with error")
+}
+
 extern "C" JNIEXPORT void JNICALL
 Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_encodeNative(JNIEnv *env, jobject thiz) {
   GET_HANDLE()
@@ -351,6 +388,8 @@ Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_getOutputNative(JNIEnv *en
                   "no output returned, may be call to uhdr_encode() was not made or encountered "
                   "error during encoding process.",
                   nullptr)
+  RET_VAL_IF_TRUE(enc_output->data_sz >= INT32_MAX, "java/lang/OutOfMemoryError",
+                  "encoded output size exceeds integer max", nullptr)
   jbyteArray output = env->NewByteArray(enc_output->data_sz);
   RET_VAL_IF_TRUE(output == nullptr, "java/io/IOException", "failed to allocate storage for output",
                   nullptr)
diff --git a/lib/include/ultrahdr/editorhelper.h b/lib/include/ultrahdr/editorhelper.h
index 9ad1762..efa46f1 100644
--- a/lib/include/ultrahdr/editorhelper.h
+++ b/lib/include/ultrahdr/editorhelper.h
@@ -65,8 +65,7 @@ typedef struct uhdr_rotate_effect : uhdr_effect_desc {
 
 /*!\brief crop effect descriptor */
 typedef struct uhdr_crop_effect : uhdr_effect_desc {
-  uhdr_crop_effect(int left, int right, int top, int bottom)
-      : m_left{left}, m_right{right}, m_top{top}, m_bottom{bottom} {}
+  uhdr_crop_effect(int left, int right, int top, int bottom);
 
   std::string to_string() {
     return "effect : crop, metadata : left, right, top, bottom - " + std::to_string(m_left) + " ," +
@@ -77,6 +76,11 @@ typedef struct uhdr_crop_effect : uhdr_effect_desc {
   int m_right;
   int m_top;
   int m_bottom;
+
+  void (*m_crop_uint8_t)(uint8_t*, uint8_t*, int, int, int, int, int, int);
+  void (*m_crop_uint16_t)(uint16_t*, uint16_t*, int, int, int, int, int, int);
+  void (*m_crop_uint32_t)(uint32_t*, uint32_t*, int, int, int, int, int, int);
+  void (*m_crop_uint64_t)(uint64_t*, uint64_t*, int, int, int, int, int, int);
 } uhdr_crop_effect_t; /**< alias for struct uhdr_crop_effect */
 
 /*!\brief resize effect descriptor */
@@ -109,6 +113,8 @@ template <typename T>
 extern void resize_buffer(T* src_buffer, T* dst_buffer, int src_w, int src_h, int dst_w, int dst_h,
                           int src_stride, int dst_stride);
 
+std::unique_ptr<uhdr_raw_image_ext_t> resize_image(uhdr_raw_image_t* src, int dst_w, int dst_h);
+
 #if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
 template <typename T>
 extern void mirror_buffer_neon(T* src_buffer, T* dst_buffer, int src_w, int src_h, int src_stride,
@@ -135,8 +141,9 @@ std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate_gles(ultrahdr::uhdr_rotate_ef
                                                         uhdr_opengl_ctxt* gl_ctxt,
                                                         GLuint* srcTexture);
 
-void apply_crop_gles(uhdr_raw_image_t* src, int left, int top, int wd, int ht,
-                     uhdr_opengl_ctxt* gl_ctxt, GLuint* srcTexture);
+std::unique_ptr<uhdr_raw_image_ext_t> apply_crop_gles(uhdr_raw_image_t* src, int left, int top,
+                                                      int wd, int ht, uhdr_opengl_ctxt* gl_ctxt,
+                                                      GLuint* srcTexture);
 #endif
 
 std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate(ultrahdr::uhdr_rotate_effect_t* desc,
@@ -152,8 +159,10 @@ std::unique_ptr<uhdr_raw_image_ext_t> apply_resize(ultrahdr::uhdr_resize_effect_
                                                    void* gl_ctxt = nullptr,
                                                    void* texture = nullptr);
 
-void apply_crop(uhdr_raw_image_t* src, int left, int top, int wd, int ht, void* gl_ctxt = nullptr,
-                void* texture = nullptr);
+std::unique_ptr<uhdr_raw_image_ext_t> apply_crop(ultrahdr::uhdr_crop_effect_t* desc,
+                                                 uhdr_raw_image_t* src, int left, int top, int wd,
+                                                 int ht, void* gl_ctxt = nullptr,
+                                                 void* texture = nullptr);
 
 }  // namespace ultrahdr
 
diff --git a/lib/include/ultrahdr/gainmapmath.h b/lib/include/ultrahdr/gainmapmath.h
index 8e65ba1..d604ad2 100644
--- a/lib/include/ultrahdr/gainmapmath.h
+++ b/lib/include/ultrahdr/gainmapmath.h
@@ -44,14 +44,18 @@ namespace ultrahdr {
 ////////////////////////////////////////////////////////////////////////////////
 // Framework
 
-// This aligns with the suggested default reference diffuse white from
-// ISO/TS 22028-5
-const float kSdrWhiteNits = 203.0f;
-const float kHlgMaxNits = 1000.0f;
-const float kPqMaxNits = 10000.0f;
-
-static const float kMaxPixelFloat = 1.0f;
-
+// nominal {SDR, HLG, PQ} peak display luminance
+// This aligns with the suggested default reference diffuse white from ISO/TS 22028-5
+// sdr white
+static const float kSdrWhiteNits = 203.0f;
+// hlg peak white. 75% of hlg peak white maps to reference diffuse white
+static const float kHlgMaxNits = 1000.0f;
+// pq peak white. 58% of pq peak white maps to reference diffuse white
+static const float kPqMaxNits = 10000.0f;
+
+float getReferenceDisplayPeakLuminanceInNits(uhdr_color_transfer_t transfer);
+
+// Image pixel descriptor
 struct Color {
   union {
     struct {
@@ -68,40 +72,19 @@ struct Color {
 };
 
 typedef Color (*ColorTransformFn)(Color);
-typedef float (*ColorCalculationFn)(Color);
+typedef float (*LuminanceFn)(Color);
+typedef Color (*SceneToDisplayLuminanceFn)(Color, LuminanceFn);
 typedef Color (*GetPixelFn)(uhdr_raw_image_t*, size_t, size_t);
 typedef Color (*SamplePixelFn)(uhdr_raw_image_t*, size_t, size_t, size_t);
 typedef void (*PutPixelFn)(uhdr_raw_image_t*, size_t, size_t, Color&);
 
-static inline float clampPixelFloat(float value) {
-  return (value < 0.0f) ? 0.0f : (value > kMaxPixelFloat) ? kMaxPixelFloat : value;
-}
-static inline Color clampPixelFloat(Color e) {
-  return {{{clampPixelFloat(e.r), clampPixelFloat(e.g), clampPixelFloat(e.b)}}};
-}
-
-// A transfer function mapping encoded values to linear values,
-// represented by this 7-parameter piecewise function:
-//
-//   linear = sign(encoded) *  (c*|encoded| + f)       , 0 <= |encoded| < d
-//          = sign(encoded) * ((a*|encoded| + b)^g + e), d <= |encoded|
-//
-// (A simple gamma transfer function sets g to gamma and a to 1.)
-typedef struct TransferFunction {
-  float g, a, b, c, d, e, f;
-} TransferFunction;
-
-static constexpr TransferFunction kSRGB_TransFun = {
-    2.4f, (float)(1 / 1.055), (float)(0.055 / 1.055), (float)(1 / 12.92), 0.04045f, 0.0f, 0.0f};
-
-static constexpr TransferFunction kLinear_TransFun = {1.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
-
 inline Color operator+=(Color& lhs, const Color& rhs) {
   lhs.r += rhs.r;
   lhs.g += rhs.g;
   lhs.b += rhs.b;
   return lhs;
 }
+
 inline Color operator-=(Color& lhs, const Color& rhs) {
   lhs.r -= rhs.r;
   lhs.g -= rhs.g;
@@ -113,6 +96,7 @@ inline Color operator+(const Color& lhs, const Color& rhs) {
   Color temp = lhs;
   return temp += rhs;
 }
+
 inline Color operator-(const Color& lhs, const Color& rhs) {
   Color temp = lhs;
   return temp -= rhs;
@@ -124,18 +108,21 @@ inline Color operator+=(Color& lhs, const float rhs) {
   lhs.b += rhs;
   return lhs;
 }
+
 inline Color operator-=(Color& lhs, const float rhs) {
   lhs.r -= rhs;
   lhs.g -= rhs;
   lhs.b -= rhs;
   return lhs;
 }
+
 inline Color operator*=(Color& lhs, const float rhs) {
   lhs.r *= rhs;
   lhs.g *= rhs;
   lhs.b *= rhs;
   return lhs;
 }
+
 inline Color operator/=(Color& lhs, const float rhs) {
   lhs.r /= rhs;
   lhs.g /= rhs;
@@ -147,29 +134,40 @@ inline Color operator+(const Color& lhs, const float rhs) {
   Color temp = lhs;
   return temp += rhs;
 }
+
 inline Color operator-(const Color& lhs, const float rhs) {
   Color temp = lhs;
   return temp -= rhs;
 }
+
 inline Color operator*(const Color& lhs, const float rhs) {
   Color temp = lhs;
   return temp *= rhs;
 }
+
 inline Color operator/(const Color& lhs, const float rhs) {
   Color temp = lhs;
   return temp /= rhs;
 }
 
+////////////////////////////////////////////////////////////////////////////////
+// Float to Half and Half to Float conversions
 union FloatUIntUnion {
-  uint32_t fUInt;
-  float fFloat;
+  uint32_t mUInt;
+  float mFloat;
 };
 
+// FIXME: The shift operations in this function are causing UBSAN (Undefined-shift) errors
+// Precisely,
+// runtime error: left shift of negative value -112
+// runtime error : shift exponent 125 is too large for 32 - bit type 'uint32_t'(aka 'unsigned int')
+// These need to be addressed. Until then, disable ubsan analysis for this function
+UHDR_NO_SANITIZE_UNDEFINED
 inline uint16_t floatToHalf(float f) {
   FloatUIntUnion floatUnion;
-  floatUnion.fFloat = f;
+  floatUnion.mFloat = f;
   // round-to-nearest-even: add last bit after truncated mantissa
-  const uint32_t b = floatUnion.fUInt + 0x00001000;
+  const uint32_t b = floatUnion.mUInt + 0x00001000;
 
   const int32_t e = (b & 0x7F800000) >> 23;  // exponent
   const uint32_t m = b & 0x007FFFFF;         // mantissa
@@ -180,45 +178,53 @@ inline uint16_t floatToHalf(float f) {
          (e > 143) * 0x7FFF;
 }
 
-constexpr int32_t kGainFactorPrecision = 10;
-constexpr int32_t kGainFactorNumEntries = 1 << kGainFactorPrecision;
-struct GainLUT {
-  GainLUT(uhdr_gainmap_metadata_ext_t* metadata) {
-    this->mGammaInv = 1.0f / metadata->gamma;
-    for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
-      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
-      float logBoost = log2(metadata->min_content_boost) * (1.0f - value) +
-                       log2(metadata->max_content_boost) * value;
-      mGainTable[idx] = exp2(logBoost);
-    }
-  }
+// Taken from frameworks/base/libs/hwui/jni/android_graphics_ColorSpace.cpp
 
-  GainLUT(uhdr_gainmap_metadata_ext_t* metadata, float displayBoost) {
-    this->mGammaInv = 1.0f / metadata->gamma;
-    float boostFactor = displayBoost > 0 ? displayBoost / metadata->hdr_capacity_max : 1.0f;
-    for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
-      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
-      float logBoost = log2(metadata->min_content_boost) * (1.0f - value) +
-                       log2(metadata->max_content_boost) * value;
-      mGainTable[idx] = exp2(logBoost * boostFactor);
+#if defined(__ANDROID__)  // __fp16 is not defined on non-Android builds
+inline float halfToFloat(uint16_t bits) {
+  __fp16 h;
+  memcpy(&h, &bits, 2);
+  return (float)h;
+}
+#else
+// This is Skia's implementation of SkHalfToFloat, which is
+// based on Fabien Giesen's half_to_float_fast2()
+// see https://fgiesen.wordpress.com/2012/03/28/half-to-float-done-quic/
+inline uint16_t halfMantissa(uint16_t h) { return h & 0x03ff; }
+
+inline uint16_t halfExponent(uint16_t h) { return (h >> 10) & 0x001f; }
+
+inline uint16_t halfSign(uint16_t h) { return h >> 15; }
+
+inline float halfToFloat(uint16_t bits) {
+  static const FloatUIntUnion magic = {126 << 23};
+  FloatUIntUnion o;
+
+  if (halfExponent(bits) == 0) {
+    // Zero / Denormal
+    o.mUInt = magic.mUInt + halfMantissa(bits);
+    o.mFloat -= magic.mFloat;
+  } else {
+    // Set mantissa
+    o.mUInt = halfMantissa(bits) << 13;
+    // Set exponent
+    if (halfExponent(bits) == 0x1f) {
+      // Inf/NaN
+      o.mUInt |= (255 << 23);
+    } else {
+      o.mUInt |= ((127 - 15 + halfExponent(bits)) << 23);
     }
   }
 
-  ~GainLUT() {}
-
-  float getGainFactor(float gain) {
-    if (mGammaInv != 1.0f) gain = pow(gain, mGammaInv);
-    int32_t idx = static_cast<int32_t>(gain * (kGainFactorNumEntries - 1) + 0.5);
-    // TODO() : Remove once conversion modules have appropriate clamping in place
-    idx = CLIP3(idx, 0, kGainFactorNumEntries - 1);
-    return mGainTable[idx];
-  }
-
- private:
-  float mGainTable[kGainFactorNumEntries];
-  float mGammaInv;
-};
+  // Set sign
+  o.mUInt |= (halfSign(bits) << 31);
+  return o.mFloat;
+}
+#endif  // defined(__ANDROID__)
 
+////////////////////////////////////////////////////////////////////////////////
+// Use Shepard's method for inverse distance weighting. For more information:
+// en.wikipedia.org/wiki/Inverse_distance_weighting#Shepard's_method
 struct ShepardsIDW {
   ShepardsIDW(int mapScaleFactor) : mMapScaleFactor{mapScaleFactor} {
     const int size = mMapScaleFactor * mMapScaleFactor * 4;
@@ -231,6 +237,7 @@ struct ShepardsIDW {
     fillShepardsIDW(mWeightsNB, 1, 0);
     fillShepardsIDW(mWeightsC, 0, 0);
   }
+
   ~ShepardsIDW() {
     delete[] mWeights;
     delete[] mWeightsNR;
@@ -239,24 +246,8 @@ struct ShepardsIDW {
   }
 
   int mMapScaleFactor;
-  // Image :-
-  // p00 p01 p02 p03 p04 p05 p06 p07
-  // p10 p11 p12 p13 p14 p15 p16 p17
-  // p20 p21 p22 p23 p24 p25 p26 p27
-  // p30 p31 p32 p33 p34 p35 p36 p37
-  // p40 p41 p42 p43 p44 p45 p46 p47
-  // p50 p51 p52 p53 p54 p55 p56 p57
-  // p60 p61 p62 p63 p64 p65 p66 p67
-  // p70 p71 p72 p73 p74 p75 p76 p77
-
-  // Gain Map (for 4 scale factor) :-
-  // m00 p01
-  // m10 m11
-
-  // Gain sample of curr 4x4, right 4x4, bottom 4x4, bottom right 4x4 are used during
-  // reconstruction. hence table weight size is 4.
-  float* mWeights;
-  // TODO: check if its ok to mWeights at places
+  // curr, right, bottom, bottom-right are used during interpolation. hence table weight size is 4.
+  float* mWeights;    // default
   float* mWeightsNR;  // no right
   float* mWeightsNB;  // no bottom
   float* mWeightsC;   // no right & bottom
@@ -265,63 +256,24 @@ struct ShepardsIDW {
   void fillShepardsIDW(float* weights, int incR, int incB);
 };
 
-class LookUpTable {
- public:
-  LookUpTable(size_t numEntries, std::function<float(float)> computeFunc) {
-    for (size_t idx = 0; idx < numEntries; idx++) {
-      float value = static_cast<float>(idx) / static_cast<float>(numEntries - 1);
-      table.push_back(computeFunc(value));
-    }
-  }
-  const std::vector<float>& getTable() const { return table; }
-
- private:
-  std::vector<float> table;
-};
-
 ////////////////////////////////////////////////////////////////////////////////
-// sRGB transformations
-// NOTE: sRGB has the same color primaries as BT.709, but different transfer
-// function. For this reason, all sRGB transformations here apply to BT.709,
-// except for those concerning transfer functions.
+// sRGB transformations.
+// for all functions range in and out [0.0, 1.0]
 
-/*
- * Calculate the luminance of a linear RGB sRGB pixel, according to
- * IEC 61966-2-1/Amd 1:2003.
- *
- * [0.0, 1.0] range in and out.
- */
+// sRGB luminance
 float srgbLuminance(Color e);
 
-/*
- * Convert from OETF'd srgb RGB to YUV, according to ITU-R BT.709-6.
- *
- * BT.709 YUV<->RGB matrix is used to match expectations for DataSpace.
- */
+// sRGB rgb <-> yuv  conversion
 Color srgbRgbToYuv(Color e_gamma);
-
-/*
- * Convert from OETF'd srgb YUV to RGB, according to ITU-R BT.709-6.
- *
- * BT.709 YUV<->RGB matrix is used to match expectations for DataSpace.
- */
 Color srgbYuvToRgb(Color e_gamma);
 
-/*
- * Convert from srgb to linear, according to IEC 61966-2-1/Amd 1:2003.
- *
- * [0.0, 1.0] range in and out.
- */
+// sRGB eotf
 float srgbInvOetf(float e_gamma);
 Color srgbInvOetf(Color e_gamma);
 float srgbInvOetfLUT(float e_gamma);
 Color srgbInvOetfLUT(Color e_gamma);
 
-/*
- * Convert from linear to srgb, according to IEC 61966-2-1/Amd 1:2003.
- *
- * [0.0, 1.0] range in and out.
- */
+// sRGB oetf
 float srgbOetf(float e);
 Color srgbOetf(Color e);
 
@@ -330,57 +282,27 @@ constexpr int32_t kSrgbInvOETFNumEntries = 1 << kSrgbInvOETFPrecision;
 
 ////////////////////////////////////////////////////////////////////////////////
 // Display-P3 transformations
+// for all functions range in and out [0.0, 1.0]
 
-/*
- * Calculated the luminance of a linear RGB P3 pixel, according to SMPTE EG 432-1.
- *
- * [0.0, 1.0] range in and out.
- */
+// DispP3 luminance
 float p3Luminance(Color e);
 
-/*
- * Convert from OETF'd P3 RGB to YUV, according to ITU-R BT.601-7.
- *
- * BT.601 YUV<->RGB matrix is used to match expectations for DataSpace.
- */
+// DispP3 rgb <-> yuv  conversion
 Color p3RgbToYuv(Color e_gamma);
-
-/*
- * Convert from OETF'd P3 YUV to RGB, according to ITU-R BT.601-7.
- *
- * BT.601 YUV<->RGB matrix is used to match expectations for DataSpace.
- */
 Color p3YuvToRgb(Color e_gamma);
 
 ////////////////////////////////////////////////////////////////////////////////
-// BT.2100 transformations - according to ITU-R BT.2100-2
+// BT.2100 transformations
+// for all functions range in and out [0.0, 1.0]
 
-/*
- * Calculate the luminance of a linear RGB BT.2100 pixel.
- *
- * [0.0, 1.0] range in and out.
- */
+// bt2100 luminance
 float bt2100Luminance(Color e);
 
-/*
- * Convert from OETF'd BT.2100 RGB to YUV, according to ITU-R BT.2100-2.
- *
- * BT.2100 YUV<->RGB matrix is used to match expectations for DataSpace.
- */
+// bt2100 rgb <-> yuv  conversion
 Color bt2100RgbToYuv(Color e_gamma);
-
-/*
- * Convert from OETF'd BT.2100 YUV to RGB, according to ITU-R BT.2100-2.
- *
- * BT.2100 YUV<->RGB matrix is used to match expectations for DataSpace.
- */
 Color bt2100YuvToRgb(Color e_gamma);
 
-/*
- * Convert from scene luminance to HLG.
- *
- * [0.0, 1.0] range in and out.
- */
+// hlg oetf (normalized)
 float hlgOetf(float e);
 Color hlgOetf(Color e);
 float hlgOetfLUT(float e);
@@ -389,11 +311,7 @@ Color hlgOetfLUT(Color e);
 constexpr int32_t kHlgOETFPrecision = 16;
 constexpr int32_t kHlgOETFNumEntries = 1 << kHlgOETFPrecision;
 
-/*
- * Convert from HLG to scene luminance.
- *
- * [0.0, 1.0] range in and out.
- */
+// hlg inverse oetf (normalized)
 float hlgInvOetf(float e_gamma);
 Color hlgInvOetf(Color e_gamma);
 float hlgInvOetfLUT(float e_gamma);
@@ -402,11 +320,16 @@ Color hlgInvOetfLUT(Color e_gamma);
 constexpr int32_t kHlgInvOETFPrecision = 12;
 constexpr int32_t kHlgInvOETFNumEntries = 1 << kHlgInvOETFPrecision;
 
-/*
- * Convert from scene luminance to PQ.
- *
- * [0.0, 1.0] range in and out.
- */
+// hlg ootf (normalized)
+Color hlgOotf(Color e, LuminanceFn luminance);
+Color hlgOotfApprox(Color e, [[maybe_unused]] LuminanceFn luminance);
+inline Color identityOotf(Color e, [[maybe_unused]] LuminanceFn) { return e; }
+
+// hlg inverse ootf (normalized)
+Color hlgInverseOotf(Color e, LuminanceFn luminance);
+Color hlgInverseOotfApprox(Color e);
+
+// pq oetf
 float pqOetf(float e);
 Color pqOetf(Color e);
 float pqOetfLUT(float e);
@@ -415,11 +338,7 @@ Color pqOetfLUT(Color e);
 constexpr int32_t kPqOETFPrecision = 16;
 constexpr int32_t kPqOETFNumEntries = 1 << kPqOETFPrecision;
 
-/*
- * Convert from PQ to scene luminance in nits.
- *
- * [0.0, 1.0] range in and out.
- */
+// pq inverse oetf
 float pqInvOetf(float e_gamma);
 Color pqInvOetf(Color e_gamma);
 float pqInvOetfLUT(float e_gamma);
@@ -428,16 +347,58 @@ Color pqInvOetfLUT(Color e_gamma);
 constexpr int32_t kPqInvOETFPrecision = 12;
 constexpr int32_t kPqInvOETFNumEntries = 1 << kPqInvOETFPrecision;
 
+// util class to prepare look up tables for oetf/eotf functions
+class LookUpTable {
+ public:
+  LookUpTable(size_t numEntries, std::function<float(float)> computeFunc) {
+    for (size_t idx = 0; idx < numEntries; idx++) {
+      float value = static_cast<float>(idx) / static_cast<float>(numEntries - 1);
+      table.push_back(computeFunc(value));
+    }
+  }
+  const std::vector<float>& getTable() const { return table; }
+
+ private:
+  std::vector<float> table;
+};
+
+////////////////////////////////////////////////////////////////////////////////
+// Color access functions
+
+// Get pixel from the image at the provided location.
+Color getYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getYuv422Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getYuv420Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getYuv400Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getP010Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getYuv444Pixel10bit(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getRgb888Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getRgba1010102Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getRgbaF16Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+
+// Sample the image at the provided location, with a weighting based on nearby pixels and the map
+// scale factor.
+Color sampleYuv444(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
+Color sampleYuv422(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
+Color sampleYuv420(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
+Color sampleP010(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
+Color sampleYuv44410bit(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y);
+Color sampleRgba8888(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y);
+Color sampleRgba1010102(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y);
+Color sampleRgbaF16(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y);
+
+// Put pixel in the image at the provided location.
+void putRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel);
+void putRgb888Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel);
+void putYuv400Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel);
+void putYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel);
+
 ////////////////////////////////////////////////////////////////////////////////
 // Color space conversions
 
-/*
- * Convert between color spaces with linear RGB data, according to ITU-R BT.2407 and EG 432-1.
- *
- * All conversions are derived from multiplying the matrix for XYZ to output RGB color gamut by the
- * matrix for input RGB color gamut to XYZ. The matrix for converting from XYZ to an RGB gamut is
- * always the inverse of the RGB gamut to XYZ matrix.
- */
+// color gamut conversion (rgb) functions
+inline Color identityConversion(Color e) { return e; }
 Color bt709ToP3(Color e);
 Color bt709ToBt2100(Color e);
 Color p3ToBt709(Color e);
@@ -445,62 +406,7 @@ Color p3ToBt2100(Color e);
 Color bt2100ToBt709(Color e);
 Color bt2100ToP3(Color e);
 
-/*
- * Identity conversion.
- */
-inline Color identityConversion(Color e) { return e; }
-
-/*
- * Get the conversion to apply to the HDR image for gain map generation
- */
-ColorTransformFn getGamutConversionFn(uhdr_color_gamut_t dst_gamut, uhdr_color_gamut_t src_gamut);
-
-/*
- * Get the conversion to convert yuv to rgb
- */
-ColorTransformFn getYuvToRgbFn(uhdr_color_gamut_t gamut);
-
-/*
- * Get function to compute luminance
- */
-ColorCalculationFn getLuminanceFn(uhdr_color_gamut_t gamut);
-
-/*
- * Get function to linearize transfer characteristics
- */
-ColorTransformFn getInverseOetfFn(uhdr_color_transfer_t transfer);
-
-/*
- * Get function to read pixels from raw image for a given color format
- */
-GetPixelFn getPixelFn(uhdr_img_fmt_t format);
-
-/*
- * Get function to sample pixels from raw image for a given color format
- */
-SamplePixelFn getSamplePixelFn(uhdr_img_fmt_t format);
-
-/*
- * Get function to put pixels to raw image for a given color format
- */
-PutPixelFn putPixelFn(uhdr_img_fmt_t format);
-
-/*
- * Returns true if the pixel format is rgb
- */
-bool isPixelFormatRgb(uhdr_img_fmt_t format);
-
-/*
- * Get max display mastering luminance in nits
- */
-float getMaxDisplayMasteringLuminance(uhdr_color_transfer_t transfer);
-
-/*
- * Convert between YUV encodings, according to ITU-R BT.709-6, ITU-R BT.601-7, and ITU-R BT.2100-2.
- *
- * Bt.709 and Bt.2100 have well-defined YUV encodings; Display-P3's is less well defined, but is
- * treated as Bt.601 by DataSpace, hence we do the same.
- */
+// convert between yuv encodings
 extern const std::array<float, 9> kYuvBt709ToBt601;
 extern const std::array<float, 9> kYuvBt709ToBt2100;
 extern const std::array<float, 9> kYuvBt601ToBt709;
@@ -508,8 +414,6 @@ extern const std::array<float, 9> kYuvBt601ToBt2100;
 extern const std::array<float, 9> kYuvBt2100ToBt709;
 extern const std::array<float, 9> kYuvBt2100ToBt601;
 
-Color yuvColorGamutConversion(Color e_gamma, const std::array<float, 9>& coeffs);
-
 #if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
 
 extern const int16_t kYuv709To601_coeffs_neon[8];
@@ -533,22 +437,53 @@ uhdr_error_info_t convertYuv_neon(uhdr_raw_image_t* image, uhdr_color_gamut_t sr
                                   uhdr_color_gamut_t dst_encoding);
 #endif
 
-/*
- * Performs a color gamut transformation on an entire YUV420 image.
- *
- * Apply the transformation by determining transformed YUV for each of the 4 Y + 1 UV; each Y gets
- * this result, and UV gets the averaged result.
- */
+// Performs a color gamut transformation on an yuv image.
+Color yuvColorGamutConversion(Color e_gamma, const std::array<float, 9>& coeffs);
 void transformYuv420(uhdr_raw_image_t* image, const std::array<float, 9>& coeffs);
-
-/*
- * Performs a color gamut transformation on an entire YUV444 image.
- */
 void transformYuv444(uhdr_raw_image_t* image, const std::array<float, 9>& coeffs);
 
 ////////////////////////////////////////////////////////////////////////////////
 // Gain map calculations
 
+constexpr int32_t kGainFactorPrecision = 10;
+constexpr int32_t kGainFactorNumEntries = 1 << kGainFactorPrecision;
+
+struct GainLUT {
+  GainLUT(uhdr_gainmap_metadata_ext_t* metadata) {
+    this->mGammaInv = 1.0f / metadata->gamma;
+    for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
+      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
+      float logBoost = log2(metadata->min_content_boost) * (1.0f - value) +
+                       log2(metadata->max_content_boost) * value;
+      mGainTable[idx] = exp2(logBoost);
+    }
+  }
+
+  GainLUT(uhdr_gainmap_metadata_ext_t* metadata, float gainmapWeight) {
+    this->mGammaInv = 1.0f / metadata->gamma;
+    for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
+      float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
+      float logBoost = log2(metadata->min_content_boost) * (1.0f - value) +
+                       log2(metadata->max_content_boost) * value;
+      mGainTable[idx] = exp2(logBoost * gainmapWeight);
+    }
+  }
+
+  ~GainLUT() {}
+
+  float getGainFactor(float gain) {
+    if (mGammaInv != 1.0f) gain = pow(gain, mGammaInv);
+    int32_t idx = static_cast<int32_t>(gain * (kGainFactorNumEntries - 1) + 0.5);
+    // TODO() : Remove once conversion modules have appropriate clamping in place
+    idx = CLIP3(idx, 0, kGainFactorNumEntries - 1);
+    return mGainTable[idx];
+  }
+
+ private:
+  float mGainTable[kGainFactorNumEntries];
+  float mGammaInv;
+};
+
 /*
  * Calculate the 8-bit unsigned integer gain value for the given SDR and HDR
  * luminances in linear space and gainmap metadata fields.
@@ -564,45 +499,16 @@ uint8_t affineMapGain(float gainlog2, float mingainlog2, float maxgainlog2, floa
  * value, with the given hdr ratio, to the given sdr input in the range [0, 1].
  */
 Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata);
-Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata, float displayBoost);
-Color applyGainLUT(Color e, float gain, GainLUT& gainLUT);
+Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata, float gainmapWeight);
+Color applyGainLUT(Color e, float gain, GainLUT& gainLUT, uhdr_gainmap_metadata_ext_t* metadata);
 
 /*
  * Apply gain in R, G and B channels, with the given hdr ratio, to the given sdr input
  * in the range [0, 1].
  */
 Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata);
-Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata, float displayBoost);
-Color applyGainLUT(Color e, Color gain, GainLUT& gainLUT);
-
-/*
- * Get pixel from the image at the provided location.
- */
-Color getYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
-Color getYuv422Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
-Color getYuv420Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
-Color getP010Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
-Color getYuv444Pixel10bit(uhdr_raw_image_t* image, size_t x, size_t y);
-Color getRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
-Color getRgba1010102Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
-
-/*
- * Sample the image at the provided location, with a weighting based on nearby
- * pixels and the map scale factor.
- */
-Color sampleYuv444(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
-Color sampleYuv422(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
-Color sampleYuv420(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
-Color sampleP010(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
-Color sampleYuv44410bit(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y);
-Color sampleRgba8888(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y);
-Color sampleRgba1010102(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y);
-
-/*
- * Put pixel in the image at the provided location.
- */
-void putRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel);
-void putYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel);
+Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata, float gainmapWeight);
+Color applyGainLUT(Color e, Color gain, GainLUT& gainLUT, uhdr_gainmap_metadata_ext_t* metadata);
 
 /*
  * Sample the gain value for the map from a given x,y coordinate on a scale
@@ -616,35 +522,74 @@ Color sampleMap3Channel(uhdr_raw_image_t* map, float map_scale_factor, size_t x,
 Color sampleMap3Channel(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y,
                         ShepardsIDW& weightTables, bool has_alpha);
 
-/*
- * Convert from Color to RGBA1010102.
- *
- * Alpha always set to 1.0.
- */
-uint32_t colorToRgba1010102(Color e_gamma);
+////////////////////////////////////////////////////////////////////////////////
+// function selectors
 
-/*
- * Convert from Color to F16.
- *
- * Alpha always set to 1.0.
- */
+ColorTransformFn getGamutConversionFn(uhdr_color_gamut_t dst_gamut, uhdr_color_gamut_t src_gamut);
+ColorTransformFn getYuvToRgbFn(uhdr_color_gamut_t gamut);
+LuminanceFn getLuminanceFn(uhdr_color_gamut_t gamut);
+ColorTransformFn getInverseOetfFn(uhdr_color_transfer_t transfer);
+SceneToDisplayLuminanceFn getOotfFn(uhdr_color_transfer_t transfer);
+GetPixelFn getPixelFn(uhdr_img_fmt_t format);
+SamplePixelFn getSamplePixelFn(uhdr_img_fmt_t format);
+PutPixelFn putPixelFn(uhdr_img_fmt_t format);
+
+////////////////////////////////////////////////////////////////////////////////
+// common utils
+
+// maximum limit of normalized pixel value in float representation
+static const float kMaxPixelFloat = 1.0f;
+
+static inline float clampPixelFloat(float value) {
+  return (value < 0.0f) ? 0.0f : (value > kMaxPixelFloat) ? kMaxPixelFloat : value;
+}
+
+static inline Color clampPixelFloat(Color e) {
+  return {{{clampPixelFloat(e.r), clampPixelFloat(e.g), clampPixelFloat(e.b)}}};
+}
+
+// maximum limit of pixel value for linear hdr intent raw resource
+static const float kMaxPixelFloatHdrLinear = 10000.0f / 203.0f;
+
+static inline float clampPixelFloatLinear(float value) {
+  return CLIP3(value, 0.0f, kMaxPixelFloatHdrLinear);
+}
+
+static inline Color clampPixelFloatLinear(Color e) {
+  return {{{clampPixelFloatLinear(e.r), clampPixelFloatLinear(e.g), clampPixelFloatLinear(e.b)}}};
+}
+
+static float mapNonFiniteFloats(float val) {
+  if (std::isinf(val)) {
+    return val > 0 ? kMaxPixelFloatHdrLinear : 0.0f;
+  }
+  // nan
+  return 0.0f;
+}
+
+static inline Color sanitizePixel(Color e) {
+  float r = std::isfinite(e.r) ? clampPixelFloatLinear(e.r) : mapNonFiniteFloats(e.r);
+  float g = std::isfinite(e.g) ? clampPixelFloatLinear(e.g) : mapNonFiniteFloats(e.g);
+  float b = std::isfinite(e.b) ? clampPixelFloatLinear(e.b) : mapNonFiniteFloats(e.b);
+  return {{{r, g, b}}};
+}
+
+bool isPixelFormatRgb(uhdr_img_fmt_t format);
+
+uint32_t colorToRgba1010102(Color e_gamma);
 uint64_t colorToRgbaF16(Color e_gamma);
 
-/*
- * Helper for copying raw image descriptor
- */
 std::unique_ptr<uhdr_raw_image_ext_t> copy_raw_image(uhdr_raw_image_t* src);
+
 uhdr_error_info_t copy_raw_image(uhdr_raw_image_t* src, uhdr_raw_image_t* dst);
 
-/*
- * Helper for preparing encoder raw inputs for encoding
- */
 std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(
     uhdr_raw_image_t* src, bool chroma_sampling_enabled = false);
 
-/*
- * Helper for converting float to fraction
- */
+#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
+std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr_neon(uhdr_raw_image_t* src);
+#endif
+
 bool floatToSignedFraction(float v, int32_t* numerator, uint32_t* denominator);
 bool floatToUnsignedFraction(float v, uint32_t* numerator, uint32_t* denominator);
 
diff --git a/lib/include/ultrahdr/gainmapmetadata.h b/lib/include/ultrahdr/gainmapmetadata.h
index 5ba6200..3ba05d0 100644
--- a/lib/include/ultrahdr/gainmapmetadata.h
+++ b/lib/include/ultrahdr/gainmapmetadata.h
@@ -23,20 +23,22 @@
 #include <vector>
 
 namespace ultrahdr {
+constexpr uint8_t kIsMultiChannelMask = (1u << 7);
+constexpr uint8_t kUseBaseColorSpaceMask = (1u << 6);
 
 // Gain map metadata, for tone mapping between SDR and HDR.
 // This is the fraction version of {@code uhdr_gainmap_metadata_ext_t}.
 struct uhdr_gainmap_metadata_frac {
-  uint32_t gainMapMinN[3];
+  int32_t gainMapMinN[3];
   uint32_t gainMapMinD[3];
-  uint32_t gainMapMaxN[3];
+  int32_t gainMapMaxN[3];
   uint32_t gainMapMaxD[3];
   uint32_t gainMapGammaN[3];
   uint32_t gainMapGammaD[3];
 
-  uint32_t baseOffsetN[3];
+  int32_t baseOffsetN[3];
   uint32_t baseOffsetD[3];
-  uint32_t alternateOffsetN[3];
+  int32_t alternateOffsetN[3];
   uint32_t alternateOffsetD[3];
 
   uint32_t baseHdrHeadroomN;
@@ -59,6 +61,8 @@ struct uhdr_gainmap_metadata_frac {
   static uhdr_error_info_t gainmapMetadataFloatToFraction(const uhdr_gainmap_metadata_ext_t* from,
                                                           uhdr_gainmap_metadata_frac* to);
 
+  bool allChannelsIdentical() const;
+
   void dump() const {
     ALOGD("GAIN MAP METADATA: \n");
     ALOGD("min numerator:                       %d, %d, %d\n", gainMapMinN[0], gainMapMinN[1],
diff --git a/lib/include/ultrahdr/icc.h b/lib/include/ultrahdr/icc.h
index be9d3d0..9f71e30 100644
--- a/lib/include/ultrahdr/icc.h
+++ b/lib/include/ultrahdr/icc.h
@@ -49,6 +49,22 @@ typedef struct Matrix3x3 {
   float vals[3][3];
 } Matrix3x3;
 
+// A transfer function mapping encoded values to linear values,
+// represented by this 7-parameter piecewise function:
+//
+//   linear = sign(encoded) *  (c*|encoded| + f)       , 0 <= |encoded| < d
+//          = sign(encoded) * ((a*|encoded| + b)^g + e), d <= |encoded|
+//
+// (A simple gamma transfer function sets g to gamma and a to 1.)
+typedef struct TransferFunction {
+  float g, a, b, c, d, e, f;
+} TransferFunction;
+
+static constexpr TransferFunction kSRGB_TransFun = {
+    2.4f, (float)(1 / 1.055), (float)(0.055 / 1.055), (float)(1 / 12.92), 0.04045f, 0.0f, 0.0f};
+
+static constexpr TransferFunction kLinear_TransFun = {1.0f, 1.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
+
 // The D50 illuminant.
 constexpr float kD50_x = 0.9642f;
 constexpr float kD50_y = 1.0000f;
@@ -164,7 +180,7 @@ static inline Fixed float_round_to_fixed(float x) {
 }
 
 static inline uint16_t float_round_to_unorm16(float x) {
-  x = x * 65535.f + 0.5;
+  x = x * 65535.f + 0.5f;
   if (x > 65535) return 65535;
   if (x < 0) return 0;
   return static_cast<uint16_t>(x);
diff --git a/lib/include/ultrahdr/jpegdecoderhelper.h b/lib/include/ultrahdr/jpegdecoderhelper.h
index 19f5835..5abbb0d 100644
--- a/lib/include/ultrahdr/jpegdecoderhelper.h
+++ b/lib/include/ultrahdr/jpegdecoderhelper.h
@@ -63,7 +63,7 @@ class JpegDecoderHelper {
    *
    * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  uhdr_error_info_t decompressImage(const void* image, int length,
+  uhdr_error_info_t decompressImage(const void* image, size_t length,
                                     decode_mode_t mode = DECODE_TO_YCBCR_CS);
 
   /*!\brief This function parses the bitstream that is passed to it and makes image information
@@ -75,7 +75,7 @@ class JpegDecoderHelper {
    *
    * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  uhdr_error_info_t parseImage(const void* image, int length) {
+  uhdr_error_info_t parseImage(const void* image, size_t length) {
     return decompressImage(image, length, PARSE_STREAM);
   }
 
@@ -99,13 +99,13 @@ class JpegDecoderHelper {
    * and it returned true. */
 
   /*!\brief returns image width */
-  size_t getDecompressedImageWidth() { return mPlaneWidth[0]; }
+  unsigned int getDecompressedImageWidth() { return mPlaneWidth[0]; }
 
   /*!\brief returns image height */
-  size_t getDecompressedImageHeight() { return mPlaneHeight[0]; }
+  unsigned int getDecompressedImageHeight() { return mPlaneHeight[0]; }
 
   /*!\brief returns number of components in image */
-  size_t getNumComponentsInImage() { return mNumComponents; }
+  unsigned int getNumComponentsInImage() { return mNumComponents; }
 
   /*!\brief returns pointer to xmp block present in input image */
   void* getXMPPtr() { return mXMPBuffer.data(); }
@@ -135,13 +135,13 @@ class JpegDecoderHelper {
    * via parseImage()/decompressImage() call. Note this does not include jpeg marker (0xffe1) and
    * the next 2 bytes indicating the size of the payload. If exif block is not present in the image
    * passed, then it returns -1. */
-  int getEXIFPos() { return mExifPayLoadOffset; }
+  long getEXIFPos() { return mExifPayLoadOffset; }
 
  private:
   // max number of components supported
   static constexpr int kMaxNumComponents = 3;
 
-  uhdr_error_info_t decode(const void* image, int length, decode_mode_t mode);
+  uhdr_error_info_t decode(const void* image, size_t length, decode_mode_t mode);
   uhdr_error_info_t decode(jpeg_decompress_struct* cinfo, uint8_t* dest);
   uhdr_error_info_t decodeToCSYCbCr(jpeg_decompress_struct* cinfo, uint8_t* dest);
   uhdr_error_info_t decodeToCSRGB(jpeg_decompress_struct* cinfo, uint8_t* dest);
@@ -157,14 +157,14 @@ class JpegDecoderHelper {
 
   // image attributes
   uhdr_img_fmt_t mOutFormat;
-  size_t mNumComponents;
-  size_t mPlaneWidth[kMaxNumComponents];
-  size_t mPlaneHeight[kMaxNumComponents];
-  size_t mPlaneHStride[kMaxNumComponents];
-  size_t mPlaneVStride[kMaxNumComponents];
-
-  int mExifPayLoadOffset;  // Position of EXIF package, default value is -1 which means no EXIF
-                           // package appears.
+  unsigned int mNumComponents;
+  unsigned int mPlaneWidth[kMaxNumComponents];
+  unsigned int mPlaneHeight[kMaxNumComponents];
+  unsigned int mPlaneHStride[kMaxNumComponents];
+  unsigned int mPlaneVStride[kMaxNumComponents];
+
+  long mExifPayLoadOffset;  // Position of EXIF package, default value is -1 which means no EXIF
+                            // package appears.
 };
 
 } /* namespace ultrahdr  */
diff --git a/lib/include/ultrahdr/jpegencoderhelper.h b/lib/include/ultrahdr/jpegencoderhelper.h
index 1335671..e0b106f 100644
--- a/lib/include/ultrahdr/jpegencoderhelper.h
+++ b/lib/include/ultrahdr/jpegencoderhelper.h
@@ -61,7 +61,7 @@ class JpegEncoderHelper {
    * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
   uhdr_error_info_t compressImage(const uhdr_raw_image_t* img, const int qfactor,
-                                  const void* iccBuffer, const unsigned int iccSize);
+                                  const void* iccBuffer, const size_t iccSize);
 
   /*!\brief This function encodes the raw image that is passed to it and stores the results
    * internally. The result is accessible via getter functions.
@@ -77,10 +77,9 @@ class JpegEncoderHelper {
    *
    * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  uhdr_error_info_t compressImage(const uint8_t* planes[3], const size_t strides[3],
+  uhdr_error_info_t compressImage(const uint8_t* planes[3], const unsigned int strides[3],
                                   const int width, const int height, const uhdr_img_fmt_t format,
-                                  const int qfactor, const void* iccBuffer,
-                                  const unsigned int iccSize);
+                                  const int qfactor, const void* iccBuffer, const size_t iccSize);
 
   /*! Below public methods are only effective if a call to compressImage() is made and it returned
    * true. */
@@ -102,20 +101,20 @@ class JpegEncoderHelper {
   // max number of components supported
   static constexpr int kMaxNumComponents = 3;
 
-  uhdr_error_info_t encode(const uint8_t* planes[3], const size_t strides[3], const int width,
+  uhdr_error_info_t encode(const uint8_t* planes[3], const unsigned int strides[3], const int width,
                            const int height, const uhdr_img_fmt_t format, const int qfactor,
-                           const void* iccBuffer, const unsigned int iccSize);
+                           const void* iccBuffer, const size_t iccSize);
 
   uhdr_error_info_t compressYCbCr(jpeg_compress_struct* cinfo, const uint8_t* planes[3],
-                                  const size_t strides[3]);
+                                  const unsigned int strides[3]);
 
   destination_mgr_impl mDestMgr;  // object for managing output
 
   // temporary storage
   std::unique_ptr<uint8_t[]> mPlanesMCURow[kMaxNumComponents];
 
-  size_t mPlaneWidth[kMaxNumComponents];
-  size_t mPlaneHeight[kMaxNumComponents];
+  unsigned int mPlaneWidth[kMaxNumComponents];
+  unsigned int mPlaneHeight[kMaxNumComponents];
 };
 
 } /* namespace ultrahdr  */
diff --git a/lib/include/ultrahdr/jpegr.h b/lib/include/ultrahdr/jpegr.h
index ea5b0eb..2b7bbaa 100644
--- a/lib/include/ultrahdr/jpegr.h
+++ b/lib/include/ultrahdr/jpegr.h
@@ -30,8 +30,8 @@ namespace ultrahdr {
 
 // Default configurations
 // gainmap image downscale factor
-static const size_t kMapDimensionScaleFactorDefault = 1;
-static const size_t kMapDimensionScaleFactorAndroidDefault = 4;
+static const int kMapDimensionScaleFactorDefault = 1;
+static const int kMapDimensionScaleFactorAndroidDefault = 4;
 
 // JPEG compress quality (0 ~ 100) for base image
 static const int kBaseCompressQualityDefault = 95;
@@ -63,17 +63,17 @@ struct jpeg_info_struct {
   std::vector<uint8_t> exifData = std::vector<uint8_t>(0);
   std::vector<uint8_t> xmpData = std::vector<uint8_t>(0);
   std::vector<uint8_t> isoData = std::vector<uint8_t>(0);
-  size_t width;
-  size_t height;
-  size_t numComponents;
+  unsigned int width;
+  unsigned int height;
+  unsigned int numComponents;
 };
 
 /*
  * Holds information of jpegr image
  */
 struct jpegr_info_struct {
-  size_t width;   // copy of primary image width (for easier access)
-  size_t height;  // copy of primary image height (for easier access)
+  unsigned int width;   // copy of primary image width (for easier access)
+  unsigned int height;  // copy of primary image height (for easier access)
   jpeg_info_struct* primaryImgInfo = nullptr;
   jpeg_info_struct* gainmapImgInfo = nullptr;
 };
@@ -84,12 +84,12 @@ typedef struct jpegr_info_struct* jr_info_ptr;
 class JpegR {
  public:
   JpegR(void* uhdrGLESCtxt = nullptr,
-        size_t mapDimensionScaleFactor = kMapDimensionScaleFactorAndroidDefault,
+        int mapDimensionScaleFactor = kMapDimensionScaleFactorAndroidDefault,
         int mapCompressQuality = kMapCompressQualityAndroidDefault,
         bool useMultiChannelGainMap = kUseMultiChannelGainMapAndroidDefault,
         float gamma = kGainMapGammaDefault,
         uhdr_enc_preset_t preset = kEncSpeedPresetAndroidDefault, float minContentBoost = FLT_MIN,
-        float maxContentBoost = FLT_MAX);
+        float maxContentBoost = FLT_MAX, float targetDispPeakBrightness = -1.0f);
 
   /*!\brief Encode API-0.
    *
@@ -260,7 +260,7 @@ class JpegR {
    *
    * \return none
    */
-  void setMapDimensionScaleFactor(size_t mapDimensionScaleFactor) {
+  void setMapDimensionScaleFactor(int mapDimensionScaleFactor) {
     this->mMapDimensionScaleFactor = mapDimensionScaleFactor;
   }
 
@@ -269,7 +269,7 @@ class JpegR {
    *
    * \return mapDimensionScaleFactor
    */
-  size_t getMapDimensionScaleFactor() { return this->mMapDimensionScaleFactor; }
+  int getMapDimensionScaleFactor() { return this->mMapDimensionScaleFactor; }
 
   /*!\brief set gain map compression quality factor
    * NOTE: Applicable only in encoding scenario
@@ -415,10 +415,19 @@ class JpegR {
    *
    * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  uhdr_error_info_t parseGainMapMetadata(uint8_t* iso_data, int iso_size, uint8_t* xmp_data,
-                                         int xmp_size, uhdr_gainmap_metadata_ext_t* uhdr_metadata);
+  uhdr_error_info_t parseGainMapMetadata(uint8_t* iso_data, size_t iso_size, uint8_t* xmp_data,
+                                         size_t xmp_size,
+                                         uhdr_gainmap_metadata_ext_t* uhdr_metadata);
+
+  /*!\brief This method is used to tone map a hdr image
+   *
+   * \param[in]            hdr_intent      hdr image descriptor
+   * \param[in, out]       sdr_intent      sdr image descriptor
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   */
+  uhdr_error_info_t toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent);
 
- protected:
   /*!\brief This method takes hdr intent and sdr intent and computes gainmap coefficient.
    *
    * This method is called in the encoding pipeline. It takes uncompressed 8-bit and 10-bit yuv
@@ -448,6 +457,7 @@ class JpegR {
                                     std::unique_ptr<uhdr_raw_image_ext_t>& gainmap_img,
                                     bool sdr_is_601 = false, bool use_luminance = true);
 
+ protected:
   /*!\brief This method takes sdr intent, gainmap image and gainmap metadata and computes hdr
    * intent. This method is called in the decoding pipeline. The output hdr intent image will have
    * same color gamut as sdr intent.
@@ -505,7 +515,8 @@ class JpegR {
    * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
   uhdr_error_info_t parseJpegInfo(uhdr_compressed_image_t* jpeg_image, j_info_ptr image_info,
-                                  size_t* img_width = nullptr, size_t* img_height = nullptr);
+                                  unsigned int* img_width = nullptr,
+                                  unsigned int* img_height = nullptr);
 
   /*!\brief This method takes compressed sdr intent, compressed gainmap coefficient, gainmap
    * metadata and creates a ultrahdr image. This is done by first generating XMP packet from gainmap
@@ -537,15 +548,6 @@ class JpegR {
                                   uhdr_gainmap_metadata_ext_t* metadata,
                                   uhdr_compressed_image_t* dest);
 
-  /*!\brief This method is used to tone map a hdr image
-   *
-   * \param[in]            hdr_intent      hdr image descriptor
-   * \param[in, out]       sdr_intent      sdr image descriptor
-   *
-   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
-   */
-  uhdr_error_info_t toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent);
-
   /*!\brief This method is used to convert a raw image from one gamut space to another gamut space
    * in-place.
    *
@@ -597,30 +599,38 @@ class JpegR {
 
   // Configurations
   void* mUhdrGLESCtxt;              // opengl es context
-  size_t mMapDimensionScaleFactor;  // gain map scale factor
+  int mMapDimensionScaleFactor;     // gain map scale factor
   int mMapCompressQuality;          // gain map quality factor
   bool mUseMultiChannelGainMap;     // enable multichannel gain map
   float mGamma;                     // gain map gamma parameter
   uhdr_enc_preset_t mEncPreset;     // encoding speed preset
   float mMinContentBoost;           // min content boost recommendation
   float mMaxContentBoost;           // max content boost recommendation
+  float mTargetDispPeakBrightness;  // target display max luminance in nits
 };
 
+/*
+ * Holds tonemapping results of a pixel
+ */
 struct GlobalTonemapOutputs {
   std::array<float, 3> rgb_out;
   float y_hdr;
   float y_sdr;
 };
 
-// Applies a global tone mapping, based on Chrome's HLG/PQ rendering implemented
-// at
-// https://source.chromium.org/chromium/chromium/src/+/main:ui/gfx/color_transform.cc;l=1198-1232;drc=ac505aff1d29ec3bfcf317cb77d5e196a3664e92
-// `rgb_in` is expected to be in the normalized range of [0.0, 1.0] and
-// `rgb_out` is returned in this same range. `headroom` describes the ratio
-// between the HDR and SDR peak luminances and must be > 1. The `y_sdr` output
-// is in the range [0.0, 1.0] while `y_hdr` is in the range [0.0, headroom].
+/*!\brief Applies a global tone mapping, based on Chrome's HLG/PQ rendering implemented at
+ *  https://source.chromium.org/chromium/chromium/src/+/main:ui/gfx/color_transform.cc;l=1197-1252;drc=ac505aff1d29ec3bfcf317cb77d5e196a3664e92
+ *
+ * \param[in]       rgb_in              hdr intent pixel in array format.
+ * \param[in]       headroom            ratio between hdr and sdr peak luminances. Must be greater
+ *                                      than 1. If the input is normalized, then this is used to
+ *                                      stretch it linearly from [0.0..1.0] to [0.0..headroom]
+ * \param[in]       is_normalized       marker to differentiate, if the input is normalized.
+ *
+ * \return tonemapped pixel in the normalized range [0.0..1.0]
+ */
 GlobalTonemapOutputs globalTonemap(const std::array<float, 3>& rgb_in, float headroom,
-                                   float luminance);
+                                   bool is_normalized);
 
 }  // namespace ultrahdr
 
diff --git a/lib/include/ultrahdr/jpegrutils.h b/lib/include/ultrahdr/jpegrutils.h
index 2ddcb74..63698d4 100644
--- a/lib/include/ultrahdr/jpegrutils.h
+++ b/lib/include/ultrahdr/jpegrutils.h
@@ -39,20 +39,20 @@ static inline uint16_t EndianSwap16(uint16_t value) {
 class DataStruct {
  private:
   void* data;
-  int writePos;
-  int length;
+  size_t writePos;
+  size_t length;
 
  public:
-  DataStruct(int s);
+  DataStruct(size_t s);
   ~DataStruct();
 
   void* getData();
-  int getLength();
-  int getBytesWritten();
+  size_t getLength();
+  size_t getBytesWritten();
   bool write8(uint8_t value);
   bool write16(uint16_t value);
   bool write32(uint32_t value);
-  bool write(const void* src, int size);
+  bool write(const void* src, size_t size);
 };
 
 /*
@@ -64,8 +64,8 @@ class DataStruct {
  * @param position cursor in desitination where the data is to be written.
  * @return success or error code.
  */
-uhdr_error_info_t Write(uhdr_compressed_image_t* destination, const void* source, int length,
-                        int& position);
+uhdr_error_info_t Write(uhdr_compressed_image_t* destination, const void* source, size_t length,
+                        size_t& position);
 
 /*
  * Parses XMP packet and fills metadata with data from XMP
@@ -75,7 +75,7 @@ uhdr_error_info_t Write(uhdr_compressed_image_t* destination, const void* source
  * @param metadata place to store HDR metadata values
  * @return success or error code.
  */
-uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, int xmp_size,
+uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size,
                                      uhdr_gainmap_metadata_ext_t* metadata);
 
 /*
@@ -118,7 +118,7 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, int xmp_size,
  * @param secondary_image_length length of secondary image
  * @return XMP metadata in type of string
  */
-std::string generateXmpForPrimaryImage(int secondary_image_length,
+std::string generateXmpForPrimaryImage(size_t secondary_image_length,
                                        uhdr_gainmap_metadata_ext_t& metadata);
 
 /*
diff --git a/lib/include/ultrahdr/multipictureformat.h b/lib/include/ultrahdr/multipictureformat.h
index 434b2ba..42b4400 100644
--- a/lib/include/ultrahdr/multipictureformat.h
+++ b/lib/include/ultrahdr/multipictureformat.h
@@ -69,8 +69,8 @@ constexpr uint32_t kMPEntryAttributeFormatJpeg = 0x0000000;
 constexpr uint32_t kMPEntryAttributeTypePrimary = 0x030000;
 
 size_t calculateMpfSize();
-std::shared_ptr<DataStruct> generateMpf(int primary_image_size, int primary_image_offset,
-                                        int secondary_image_size, int secondary_image_offset);
+std::shared_ptr<DataStruct> generateMpf(size_t primary_image_size, size_t primary_image_offset,
+                                        size_t secondary_image_size, size_t secondary_image_offset);
 
 }  // namespace ultrahdr
 
diff --git a/lib/include/ultrahdr/ultrahdr.h b/lib/include/ultrahdr/ultrahdr.h
index 53617ba..24a43ac 100644
--- a/lib/include/ultrahdr/ultrahdr.h
+++ b/lib/include/ultrahdr/ultrahdr.h
@@ -46,6 +46,9 @@ typedef enum {
   ERROR_JPEGR_INVALID_OUTPUT_FORMAT = JPEGR_IO_ERROR_BASE - 9,
   ERROR_JPEGR_BAD_METADATA = JPEGR_IO_ERROR_BASE - 10,
   ERROR_JPEGR_INVALID_CROPPING_PARAMETERS = JPEGR_IO_ERROR_BASE - 11,
+  ERROR_JPEGR_INVALID_GAMMA = JPEGR_IO_ERROR_BASE - 12,
+  ERROR_JPEGR_INVALID_ENC_PRESET = JPEGR_IO_ERROR_BASE - 13,
+  ERROR_JPEGR_INVALID_TARGET_DISP_PEAK_BRIGHTNESS = JPEGR_IO_ERROR_BASE - 14,
 
   JPEGR_RUNTIME_ERROR_BASE = -20000,
   ERROR_JPEGR_ENCODE_ERROR = JPEGR_RUNTIME_ERROR_BASE - 1,
@@ -124,9 +127,9 @@ struct jpegr_uncompressed_struct {
   // Pointer to the data location.
   void* data;
   // Width of the gain map or the luma plane of the image in pixels.
-  size_t width;
+  unsigned int width;
   // Height of the gain map or the luma plane of the image in pixels.
-  size_t height;
+  unsigned int height;
   // Color gamut.
   ultrahdr_color_gamut colorGamut;
 
@@ -137,7 +140,7 @@ struct jpegr_uncompressed_struct {
   // Stride of Y plane in number of pixels. 0 indicates the member is uninitialized. If
   // non-zero this value must be larger than or equal to luma width. If stride is
   // uninitialized then it is assumed to be equal to luma width.
-  size_t luma_stride = 0;
+  unsigned int luma_stride = 0;
   // Stride of UV plane in number of pixels.
   // 1. If this handle points to P010 image then this value must be larger than
   //    or equal to luma width.
@@ -145,7 +148,7 @@ struct jpegr_uncompressed_struct {
   //    or equal to (luma width / 2).
   // NOTE: if chroma_data is nullptr, chroma_stride is irrelevant. Just as the way,
   // chroma_data is derived from luma ptr, chroma stride is derived from luma stride.
-  size_t chroma_stride = 0;
+  unsigned int chroma_stride = 0;
   // Pixel format.
   uhdr_img_fmt_t pixelFormat = UHDR_IMG_FMT_UNSPECIFIED;
   // Color range.
@@ -159,9 +162,9 @@ struct jpegr_compressed_struct {
   // Pointer to the data location.
   void* data;
   // Used data length in bytes.
-  int length;
+  size_t length;
   // Maximum available data length in bytes.
-  int maxLength;
+  size_t maxLength;
   // Color gamut.
   ultrahdr_color_gamut colorGamut;
 };
diff --git a/lib/include/ultrahdr/ultrahdrcommon.h b/lib/include/ultrahdr/ultrahdrcommon.h
index e0c7cc1..67a3d06 100644
--- a/lib/include/ultrahdr/ultrahdrcommon.h
+++ b/lib/include/ultrahdr/ultrahdrcommon.h
@@ -140,6 +140,23 @@
 #define INLINE inline
 #endif
 
+// '__has_attribute' macro was introduced by clang. later picked up by gcc.
+// If not supported by the current toolchain, define it to zero.
+#ifndef __has_attribute
+#define __has_attribute(x) 0
+#endif
+
+// Disables undefined behavior analysis for a function.
+// GCC 4.9+ uses __attribute__((no_sanitize_undefined))
+// clang uses __attribute__((no_sanitize("undefined")))
+#if defined(__GNUC__) && ((__GNUC__ * 100 + __GNUC_MINOR__) >= 409)
+#define UHDR_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize_undefined))
+#elif __has_attribute(no_sanitize)
+#define UHDR_NO_SANITIZE_UNDEFINED __attribute__((no_sanitize("undefined")))
+#else
+#define UHDR_NO_SANITIZE_UNDEFINED
+#endif
+
 static const uhdr_error_info_t g_no_error = {UHDR_CODEC_OK, 0, ""};
 
 namespace ultrahdr {
@@ -174,7 +191,7 @@ typedef struct uhdr_raw_image_ext : uhdr_raw_image_t {
 /**\brief extended compressed image descriptor */
 typedef struct uhdr_compressed_image_ext : uhdr_compressed_image_t {
   uhdr_compressed_image_ext(uhdr_color_gamut_t cg, uhdr_color_transfer_t ct,
-                            uhdr_color_range_t range, unsigned sz);
+                            uhdr_color_range_t range, size_t sz);
 
  private:
   std::unique_ptr<ultrahdr::uhdr_memory_block> m_block;
@@ -324,6 +341,8 @@ bool isBufferDataContiguous(uhdr_raw_image_t* img);
 
 #endif
 
+uhdr_error_info_t uhdr_validate_gainmap_metadata_descriptor(uhdr_gainmap_metadata_t* metadata);
+
 }  // namespace ultrahdr
 
 // ===============================================================================================
@@ -356,6 +375,7 @@ struct uhdr_encoder_private : uhdr_codec_private {
   uhdr_enc_preset_t m_enc_preset;
   float m_min_content_boost;
   float m_max_content_boost;
+  float m_target_disp_max_brightness;
 
   // internal data
   std::unique_ptr<ultrahdr::uhdr_compressed_image_ext_t> m_compressed_output_buffer;
diff --git a/lib/src/dsp/arm/gainmapmath_neon.cpp b/lib/src/dsp/arm/gainmapmath_neon.cpp
index b6b879f..306a971 100644
--- a/lib/src/dsp/arm/gainmapmath_neon.cpp
+++ b/lib/src/dsp/arm/gainmapmath_neon.cpp
@@ -317,4 +317,163 @@ uhdr_error_info_t convertYuv_neon(uhdr_raw_image_t* image, uhdr_color_gamut_t sr
   return status;
 }
 
+// Scale all coefficients by 2^14 to avoid needing floating-point arithmetic. This can cause an off
+// by one error compared to the scalar floating-point implementation.
+
+// In the 3x3 conversion matrix, 0.5 is duplicated. But represented as only one entry in lut leaving
+// with an array size of 8 elements.
+
+// RGB Bt709 -> Yuv Bt709
+// Y = 0.212639 * R + 0.715169 * G + 0.072192 * B
+// U = -0.114592135 * R + -0.385407865 * G + 0.5 * B
+// V = 0.5 * R + -0.454155718 * G + -0.045844282 * B
+ALIGNED(16)
+const uint16_t kRgb709ToYuv_coeffs_neon[8] = {3484, 11717, 1183, 1877, 6315, 8192, 7441, 751};
+
+// RGB Display P3 -> Yuv Display P3
+// Y = 0.2289746 * R + 0.6917385 * G + 0.0792869 * B
+// U = -0.124346335 * R + -0.375653665 * G + 0.5 * B
+// V = 0.5 * R + -0.448583471 * G + -0.051416529 * B
+ALIGNED(16)
+const uint16_t kRgbDispP3ToYuv_coeffs_neon[8] = {3752, 11333, 1299, 2037, 6155, 8192, 7350, 842};
+
+// RGB Bt2100 -> Yuv Bt2100
+// Y = 0.2627 * R + 0.677998 * G + 0.059302 * B
+// U = -0.13963036 * R + -0.36036964 * G + 0.5 * B
+// V = 0.5 * R + -0.459784348 * G + -0.040215652 * B
+ALIGNED(16)
+const uint16_t kRgb2100ToYuv_coeffs_neon[8] = {4304, 11108, 972, 2288, 5904, 8192, 7533, 659};
+
+// The core logic is taken from jsimd_rgb_ycc_convert_neon implementation in jccolext-neon.c of
+// libjpeg-turbo
+static void ConvertRgba8888ToYuv444_neon(uhdr_raw_image_t* src, uhdr_raw_image_t* dst,
+                                         const uint16_t* coeffs_ptr) {
+  // Implementation processes 16 pixel per iteration.
+  assert(src->stride[UHDR_PLANE_PACKED] % 16 == 0);
+  uint8_t* rgba_base_ptr = static_cast<uint8_t*>(src->planes[UHDR_PLANE_PACKED]);
+
+  uint8_t* y_base_ptr = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
+  uint8_t* u_base_ptr = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_U]);
+  uint8_t* v_base_ptr = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_V]);
+
+  const uint16x8_t coeffs = vld1q_u16(coeffs_ptr);
+  const uint32x4_t bias = vdupq_n_u32((128 << 14) + 8191);
+
+  unsigned int h = 0;
+  do {
+    unsigned int w = 0;
+    uint8_t* rgba_ptr = rgba_base_ptr + (size_t)src->stride[UHDR_PLANE_PACKED] * 4 * h;
+    uint8_t* y_ptr = y_base_ptr + (size_t)dst->stride[UHDR_PLANE_Y] * h;
+    uint8_t* u_ptr = u_base_ptr + (size_t)dst->stride[UHDR_PLANE_U] * h;
+    uint8_t* v_ptr = v_base_ptr + (size_t)dst->stride[UHDR_PLANE_V] * h;
+    do {
+      uint8x16x4_t rgb_pixels = vld4q_u8(rgba_ptr);
+
+      uint16x8_t r_l = vmovl_u8(vget_low_u8(rgb_pixels.val[0]));
+      uint16x8_t g_l = vmovl_u8(vget_low_u8(rgb_pixels.val[1]));
+      uint16x8_t b_l = vmovl_u8(vget_low_u8(rgb_pixels.val[2]));
+      uint16x8_t r_h = vmovl_u8(vget_high_u8(rgb_pixels.val[0]));
+      uint16x8_t g_h = vmovl_u8(vget_high_u8(rgb_pixels.val[1]));
+      uint16x8_t b_h = vmovl_u8(vget_high_u8(rgb_pixels.val[2]));
+
+      /* Compute Y */
+      uint32x4_t y_ll = vmull_lane_u16(vget_low_u16(r_l), vget_low_u16(coeffs), 0);
+      y_ll = vmlal_lane_u16(y_ll, vget_low_u16(g_l), vget_low_u16(coeffs), 1);
+      y_ll = vmlal_lane_u16(y_ll, vget_low_u16(b_l), vget_low_u16(coeffs), 2);
+      uint32x4_t y_lh = vmull_lane_u16(vget_high_u16(r_l), vget_low_u16(coeffs), 0);
+      y_lh = vmlal_lane_u16(y_lh, vget_high_u16(g_l), vget_low_u16(coeffs), 1);
+      y_lh = vmlal_lane_u16(y_lh, vget_high_u16(b_l), vget_low_u16(coeffs), 2);
+      uint32x4_t y_hl = vmull_lane_u16(vget_low_u16(r_h), vget_low_u16(coeffs), 0);
+      y_hl = vmlal_lane_u16(y_hl, vget_low_u16(g_h), vget_low_u16(coeffs), 1);
+      y_hl = vmlal_lane_u16(y_hl, vget_low_u16(b_h), vget_low_u16(coeffs), 2);
+      uint32x4_t y_hh = vmull_lane_u16(vget_high_u16(r_h), vget_low_u16(coeffs), 0);
+      y_hh = vmlal_lane_u16(y_hh, vget_high_u16(g_h), vget_low_u16(coeffs), 1);
+      y_hh = vmlal_lane_u16(y_hh, vget_high_u16(b_h), vget_low_u16(coeffs), 2);
+
+      /* Compute Cb */
+      uint32x4_t cb_ll = bias;
+      cb_ll = vmlsl_lane_u16(cb_ll, vget_low_u16(r_l), vget_low_u16(coeffs), 3);
+      cb_ll = vmlsl_lane_u16(cb_ll, vget_low_u16(g_l), vget_high_u16(coeffs), 0);
+      cb_ll = vmlal_lane_u16(cb_ll, vget_low_u16(b_l), vget_high_u16(coeffs), 1);
+      uint32x4_t cb_lh = bias;
+      cb_lh = vmlsl_lane_u16(cb_lh, vget_high_u16(r_l), vget_low_u16(coeffs), 3);
+      cb_lh = vmlsl_lane_u16(cb_lh, vget_high_u16(g_l), vget_high_u16(coeffs), 0);
+      cb_lh = vmlal_lane_u16(cb_lh, vget_high_u16(b_l), vget_high_u16(coeffs), 1);
+      uint32x4_t cb_hl = bias;
+      cb_hl = vmlsl_lane_u16(cb_hl, vget_low_u16(r_h), vget_low_u16(coeffs), 3);
+      cb_hl = vmlsl_lane_u16(cb_hl, vget_low_u16(g_h), vget_high_u16(coeffs), 0);
+      cb_hl = vmlal_lane_u16(cb_hl, vget_low_u16(b_h), vget_high_u16(coeffs), 1);
+      uint32x4_t cb_hh = bias;
+      cb_hh = vmlsl_lane_u16(cb_hh, vget_high_u16(r_h), vget_low_u16(coeffs), 3);
+      cb_hh = vmlsl_lane_u16(cb_hh, vget_high_u16(g_h), vget_high_u16(coeffs), 0);
+      cb_hh = vmlal_lane_u16(cb_hh, vget_high_u16(b_h), vget_high_u16(coeffs), 1);
+
+      /* Compute Cr */
+      uint32x4_t cr_ll = bias;
+      cr_ll = vmlal_lane_u16(cr_ll, vget_low_u16(r_l), vget_high_u16(coeffs), 1);
+      cr_ll = vmlsl_lane_u16(cr_ll, vget_low_u16(g_l), vget_high_u16(coeffs), 2);
+      cr_ll = vmlsl_lane_u16(cr_ll, vget_low_u16(b_l), vget_high_u16(coeffs), 3);
+      uint32x4_t cr_lh = bias;
+      cr_lh = vmlal_lane_u16(cr_lh, vget_high_u16(r_l), vget_high_u16(coeffs), 1);
+      cr_lh = vmlsl_lane_u16(cr_lh, vget_high_u16(g_l), vget_high_u16(coeffs), 2);
+      cr_lh = vmlsl_lane_u16(cr_lh, vget_high_u16(b_l), vget_high_u16(coeffs), 3);
+      uint32x4_t cr_hl = bias;
+      cr_hl = vmlal_lane_u16(cr_hl, vget_low_u16(r_h), vget_high_u16(coeffs), 1);
+      cr_hl = vmlsl_lane_u16(cr_hl, vget_low_u16(g_h), vget_high_u16(coeffs), 2);
+      cr_hl = vmlsl_lane_u16(cr_hl, vget_low_u16(b_h), vget_high_u16(coeffs), 3);
+      uint32x4_t cr_hh = bias;
+      cr_hh = vmlal_lane_u16(cr_hh, vget_high_u16(r_h), vget_high_u16(coeffs), 1);
+      cr_hh = vmlsl_lane_u16(cr_hh, vget_high_u16(g_h), vget_high_u16(coeffs), 2);
+      cr_hh = vmlsl_lane_u16(cr_hh, vget_high_u16(b_h), vget_high_u16(coeffs), 3);
+
+      /* Descale Y values (rounding right shift) and narrow to 16-bit. */
+      uint16x8_t y_l = vcombine_u16(vrshrn_n_u32(y_ll, 14), vrshrn_n_u32(y_lh, 14));
+      uint16x8_t y_h = vcombine_u16(vrshrn_n_u32(y_hl, 14), vrshrn_n_u32(y_hh, 14));
+      /* Descale Cb values (right shift) and narrow to 16-bit. */
+      uint16x8_t cb_l = vcombine_u16(vshrn_n_u32(cb_ll, 14), vshrn_n_u32(cb_lh, 14));
+      uint16x8_t cb_h = vcombine_u16(vshrn_n_u32(cb_hl, 14), vshrn_n_u32(cb_hh, 14));
+      /* Descale Cr values (right shift) and narrow to 16-bit. */
+      uint16x8_t cr_l = vcombine_u16(vshrn_n_u32(cr_ll, 14), vshrn_n_u32(cr_lh, 14));
+      uint16x8_t cr_h = vcombine_u16(vshrn_n_u32(cr_hl, 14), vshrn_n_u32(cr_hh, 14));
+
+      /* Narrow Y, Cb, and Cr values to 8-bit and store to memory.  Buffer
+       * overwrite is permitted up to the next multiple of ALIGN_SIZE bytes.
+       */
+      vst1q_u8(y_ptr, vcombine_u8(vmovn_u16(y_l), vmovn_u16(y_h)));
+      vst1q_u8(u_ptr, vcombine_u8(vmovn_u16(cb_l), vmovn_u16(cb_h)));
+      vst1q_u8(v_ptr, vcombine_u8(vmovn_u16(cr_l), vmovn_u16(cr_h)));
+
+      /* Increment pointers. */
+      rgba_ptr += (16 * 4);
+      y_ptr += 16;
+      u_ptr += 16;
+      v_ptr += 16;
+
+      w += 16;
+    } while (w < src->w);
+  } while (++h < src->h);
+}
+
+std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr_neon(uhdr_raw_image_t* src) {
+  if (src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
+    std::unique_ptr<uhdr_raw_image_ext_t> dst = nullptr;
+    const uint16_t* coeffs_ptr = nullptr;
+
+    if (src->cg == UHDR_CG_BT_709) {
+      coeffs_ptr = kRgb709ToYuv_coeffs_neon;
+    } else if (src->cg == UHDR_CG_BT_2100) {
+      coeffs_ptr = kRgbDispP3ToYuv_coeffs_neon;
+    } else if (src->cg == UHDR_CG_DISPLAY_P3) {
+      coeffs_ptr = kRgb2100ToYuv_coeffs_neon;
+    } else {
+      return dst;
+    }
+    dst = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_24bppYCbCr444, src->cg, src->ct,
+                                                 UHDR_CR_FULL_RANGE, src->w, src->h, 64);
+    ConvertRgba8888ToYuv444_neon(src, dst.get(), coeffs_ptr);
+    return dst;
+  }
+  return nullptr;
+}
+
 }  // namespace ultrahdr
diff --git a/lib/src/editorhelper.cpp b/lib/src/editorhelper.cpp
index f916723..f8da4b9 100644
--- a/lib/src/editorhelper.cpp
+++ b/lib/src/editorhelper.cpp
@@ -19,6 +19,7 @@
 #include <cmath>
 
 #include "ultrahdr/editorhelper.h"
+#include "ultrahdr/gainmapmath.h"
 
 namespace ultrahdr {
 
@@ -69,6 +70,15 @@ void mirror_buffer(T* src_buffer, T* dst_buffer, int src_w, int src_h, int src_s
   }
 }
 
+template <typename T>
+void crop_buffer(T* src_buffer, T* dst_buffer, int src_stride, int dst_stride, int left, int top,
+                 int wd, int ht) {
+  for (int row = 0; row < ht; row++) {
+    memcpy(&dst_buffer[row * dst_stride], &src_buffer[(top + row) * src_stride + left],
+           wd * sizeof(T));
+  }
+}
+
 // TODO (dichenzhang): legacy method, need to be removed
 template <typename T>
 void resize_buffer(T* src_buffer, T* dst_buffer, int src_w, int src_h, int dst_w, int dst_h,
@@ -93,42 +103,52 @@ double bicubic_interpolate(double p0, double p1, double p2, double p3, double x)
   return w0 * p0 + w1 * p1 + w2 * p2 + w3 * p3;
 }
 
-template <typename T>
-void resize_buffer(T* src_buffer, T* dst_buffer, int src_w, int src_h, int dst_w, int dst_h,
-                   int src_stride, int dst_stride, uhdr_img_fmt_t img_fmt, size_t plane) {
+std::unique_ptr<uhdr_raw_image_ext_t> resize_image(uhdr_raw_image_t* src, int dst_w, int dst_h) {
+  GetPixelFn get_pixel_fn = getPixelFn(src->fmt);
+  if (get_pixel_fn == nullptr) {
+    return nullptr;
+  }
+
+  PutPixelFn put_pixel_fn = putPixelFn(src->fmt);
+  if (put_pixel_fn == nullptr) {
+    return nullptr;
+  }
+
+  std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
+      src->fmt, src->cg, src->ct, src->range, dst_w, dst_h, 64);
+
+  int src_w = src->w;
+  int src_h = src->h;
   double scale_x = (double)src_w / dst_w;
   double scale_y = (double)src_h / dst_h;
   for (int y = 0; y < dst_h; y++) {
     for (int x = 0; x < dst_w; x++) {
       double ori_x = x * scale_x;
       double ori_y = y * scale_y;
-      int p0_x = (int)floor(ori_x);
-      int p0_y = (int)floor(ori_y);
-      int p1_x = p0_x + 1;
+      int p0_x = CLIP3((int)floor(ori_x), 0, src_w - 1);
+      int p0_y = CLIP3((int)floor(ori_y), 0, src_h - 1);
+      int p1_x = CLIP3((p0_x + 1), 0, src_w - 1);
       int p1_y = p0_y;
       int p2_x = p0_x;
-      int p2_y = p0_y + 1;
-      int p3_x = p0_x + 1;
-      int p3_y = p0_y + 1;
-
-      if ((img_fmt == UHDR_IMG_FMT_8bppYCbCr400) ||
-          (img_fmt == UHDR_IMG_FMT_12bppYCbCr420 && plane == UHDR_PLANE_Y) ||
-          (img_fmt == UHDR_IMG_FMT_12bppYCbCr420 && plane == UHDR_PLANE_U) ||
-          (img_fmt == UHDR_IMG_FMT_12bppYCbCr420 && plane == UHDR_PLANE_V)) {
-        double p0 = (double)src_buffer[p0_y * src_stride + p0_x];
-        double p1 = (double)src_buffer[p1_y * src_stride + p1_x];
-        double p2 = (double)src_buffer[p2_y * src_stride + p2_x];
-        double p3 = (double)src_buffer[p3_y * src_stride + p3_x];
-
-        double new_pix_val = bicubic_interpolate(p0, p1, p2, p3, ori_x - p0_x);
-
-        dst_buffer[y * dst_stride + x] = (uint8_t)floor(new_pix_val + 0.5);
-      } else {
-        // Unsupported feature.
-        return;
+      int p2_y = CLIP3((p0_y + 1), 0, src_h - 1);
+      int p3_x = CLIP3((p0_x + 1), 0, src_w - 1);
+      int p3_y = CLIP3((p0_y + 1), 0, src_h - 1);
+
+      Color p0 = get_pixel_fn(src, p0_x, p0_y);
+      Color p1 = get_pixel_fn(src, p1_x, p1_y);
+      Color p2 = get_pixel_fn(src, p2_x, p2_y);
+      Color p3 = get_pixel_fn(src, p3_x, p3_y);
+
+      Color interp;
+      interp.r = (float)bicubic_interpolate(p0.r, p1.r, p2.r, p3.r, ori_x - p0_x);
+      if (src->fmt != UHDR_IMG_FMT_8bppYCbCr400) {
+        interp.g = (float)bicubic_interpolate(p0.g, p1.g, p2.g, p3.g, ori_x - p0_x);
+        interp.b = (float)bicubic_interpolate(p0.b, p1.b, p2.b, p3.b, ori_x - p0_x);
       }
+      put_pixel_fn(dst.get(), x, y, interp);
     }
   }
+  return dst;
 }
 
 template void mirror_buffer<uint8_t>(uint8_t*, uint8_t*, int, int, int, int,
@@ -178,6 +198,14 @@ uhdr_rotate_effect::uhdr_rotate_effect(int degree) : m_degree{degree} {
 #endif
 }
 
+uhdr_crop_effect::uhdr_crop_effect(int left, int right, int top, int bottom)
+    : m_left(left), m_right(right), m_top(top), m_bottom(bottom) {
+  m_crop_uint8_t = crop_buffer<uint8_t>;
+  m_crop_uint16_t = crop_buffer<uint16_t>;
+  m_crop_uint32_t = crop_buffer<uint32_t>;
+  m_crop_uint64_t = crop_buffer<uint64_t>;
+}
+
 uhdr_resize_effect::uhdr_resize_effect(int width, int height) : m_width{width}, m_height{height} {
   m_resize_uint8_t = resize_buffer<uint8_t>;
   m_resize_uint16_t = resize_buffer<uint16_t>;
@@ -326,8 +354,10 @@ std::unique_ptr<uhdr_raw_image_ext_t> apply_mirror(ultrahdr::uhdr_mirror_effect_
   return dst;
 }
 
-void apply_crop(uhdr_raw_image_t* src, int left, int top, int wd, int ht,
-                [[maybe_unused]] void* gl_ctxt, [[maybe_unused]] void* texture) {
+std::unique_ptr<uhdr_raw_image_ext_t> apply_crop(ultrahdr::uhdr_crop_effect_t* desc,
+                                                 uhdr_raw_image_t* src, int left, int top, int wd,
+                                                 int ht, [[maybe_unused]] void* gl_ctxt,
+                                                 [[maybe_unused]] void* texture) {
 #ifdef UHDR_ENABLE_GLES
   if ((src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
        src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) &&
@@ -337,40 +367,57 @@ void apply_crop(uhdr_raw_image_t* src, int left, int top, int wd, int ht,
                            static_cast<GLuint*>(texture));
   }
 #endif
+  std::unique_ptr<uhdr_raw_image_ext_t> dst =
+      std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, wd, ht, 64);
+
   if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
     uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
-    src->planes[UHDR_PLANE_Y] = &src_buffer[top * src->stride[UHDR_PLANE_Y] + left];
+    uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
+    desc->m_crop_uint16_t(src_buffer, dst_buffer, src->stride[UHDR_PLANE_Y],
+                          dst->stride[UHDR_PLANE_Y], left, top, wd, ht);
     uint32_t* src_uv_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_UV]);
-    src->planes[UHDR_PLANE_UV] =
-        &src_uv_buffer[(top / 2) * (src->stride[UHDR_PLANE_UV] / 2) + (left / 2)];
+    uint32_t* dst_uv_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_UV]);
+    desc->m_crop_uint32_t(src_uv_buffer, dst_uv_buffer, src->stride[UHDR_PLANE_UV] / 2,
+                          dst->stride[UHDR_PLANE_UV] / 2, left / 2, top / 2, wd / 2, ht / 2);
   } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
     uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
-    src->planes[UHDR_PLANE_Y] = &src_buffer[top * src->stride[UHDR_PLANE_Y] + left];
+    uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
+    desc->m_crop_uint8_t(src_buffer, dst_buffer, src->stride[UHDR_PLANE_Y],
+                         dst->stride[UHDR_PLANE_Y], left, top, wd, ht);
     if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
       for (int i = 1; i < 3; i++) {
         src_buffer = static_cast<uint8_t*>(src->planes[i]);
-        src->planes[i] = &src_buffer[(top / 2) * src->stride[i] + (left / 2)];
+        dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
+        desc->m_crop_uint8_t(src_buffer, dst_buffer, src->stride[i], dst->stride[i], left / 2,
+                             top / 2, wd / 2, ht / 2);
       }
     }
   } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
     uint32_t* src_buffer = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
-    src->planes[UHDR_PLANE_PACKED] = &src_buffer[top * src->stride[UHDR_PLANE_PACKED] + left];
+    uint32_t* dst_buffer = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_PACKED]);
+    desc->m_crop_uint32_t(src_buffer, dst_buffer, src->stride[UHDR_PLANE_PACKED],
+                          dst->stride[UHDR_PLANE_PACKED], left, top, wd, ht);
   } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
     uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
-    src->planes[UHDR_PLANE_PACKED] = &src_buffer[top * src->stride[UHDR_PLANE_PACKED] + left];
+    uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
+    desc->m_crop_uint64_t(src_buffer, dst_buffer, src->stride[UHDR_PLANE_PACKED],
+                          dst->stride[UHDR_PLANE_PACKED], left, top, wd, ht);
   } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
     for (int i = 0; i < 3; i++) {
       uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[i]);
-      src->planes[i] = &src_buffer[top * src->stride[i] + left];
+      uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
+      desc->m_crop_uint8_t(src_buffer, dst_buffer, src->stride[i], dst->stride[i], left, top, wd,
+                           ht);
     }
   } else if (src->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
     for (int i = 0; i < 3; i++) {
       uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[i]);
-      src->planes[i] = &src_buffer[top * src->stride[i] + left];
+      uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[i]);
+      desc->m_crop_uint16_t(src_buffer, dst_buffer, src->stride[UHDR_PLANE_PACKED],
+                            dst->stride[UHDR_PLANE_PACKED], left, top, wd, ht);
     }
   }
-  src->w = wd;
-  src->h = ht;
+  return dst;
 }
 
 std::unique_ptr<uhdr_raw_image_ext_t> apply_resize(ultrahdr::uhdr_resize_effect_t* desc,
diff --git a/lib/src/gainmapmath.cpp b/lib/src/gainmapmath.cpp
index 47e9eac..fa56c3e 100644
--- a/lib/src/gainmapmath.cpp
+++ b/lib/src/gainmapmath.cpp
@@ -20,8 +20,27 @@
 
 namespace ultrahdr {
 
-// Use Shepard's method for inverse distance weighting. For more information:
-// en.wikipedia.org/wiki/Inverse_distance_weighting#Shepard's_method
+////////////////////////////////////////////////////////////////////////////////
+// Framework
+
+float getReferenceDisplayPeakLuminanceInNits(uhdr_color_transfer_t transfer) {
+  switch (transfer) {
+    case UHDR_CT_LINEAR:
+      return kPqMaxNits;
+    case UHDR_CT_HLG:
+      return kHlgMaxNits;
+    case UHDR_CT_PQ:
+      return kPqMaxNits;
+    case UHDR_CT_SRGB:
+      return kSdrWhiteNits;
+    case UHDR_CT_UNSPECIFIED:
+      return -1.0f;
+  }
+  return -1.0f;
+}
+
+////////////////////////////////////////////////////////////////////////////////
+// Use Shepard's method for inverse distance weighting.
 
 float ShepardsIDW::euclideanDistance(float x1, float x2, float y1, float y2) {
   return sqrt(((y2 - y1) * (y2 - y1)) + (x2 - x1) * (x2 - x1));
@@ -267,6 +286,28 @@ Color hlgInvOetfLUT(Color e_gamma) {
   return {{{hlgInvOetfLUT(e_gamma.r), hlgInvOetfLUT(e_gamma.g), hlgInvOetfLUT(e_gamma.b)}}};
 }
 
+// 1.2f + 0.42 * log(kHlgMaxNits / 1000)
+static const float kOotfGamma = 1.2f;
+
+Color hlgOotf(Color e, LuminanceFn luminance) {
+  float y = luminance(e);
+  return e * std::pow(y, kOotfGamma - 1.0f);
+}
+
+Color hlgOotfApprox(Color e, [[maybe_unused]] LuminanceFn luminance) {
+  return {{{std::pow(e.r, kOotfGamma), std::pow(e.g, kOotfGamma), std::pow(e.b, kOotfGamma)}}};
+}
+
+Color hlgInverseOotf(Color e, LuminanceFn luminance) {
+  float y = luminance(e);
+  return e * std::pow(y, (1.0f / kOotfGamma) - 1.0f);
+}
+
+Color hlgInverseOotfApprox(Color e) {
+  return {{{std::pow(e.r, 1.0f / kOotfGamma), std::pow(e.g, 1.0f / kOotfGamma),
+            std::pow(e.b, 1.0f / kOotfGamma)}}};
+}
+
 // See ITU-R BT.2100-2, Table 4, Reference PQ OETF.
 static const float kPqM1 = 2610.0f / 16384.0f, kPqM2 = 2523.0f / 4096.0f * 128.0f;
 static const float kPqC1 = 3424.0f / 4096.0f, kPqC2 = 2413.0f / 4096.0f * 32.0f,
@@ -311,222 +352,289 @@ Color pqInvOetfLUT(Color e_gamma) {
 }
 
 ////////////////////////////////////////////////////////////////////////////////
-// Color conversions
+// Color access functions
 
-Color bt709ToP3(Color e) {
-  return {{{clampPixelFloat(0.82254f * e.r + 0.17755f * e.g + 0.00006f * e.b),
-            clampPixelFloat(0.03312f * e.r + 0.96684f * e.g + -0.00001f * e.b),
-            clampPixelFloat(0.01706f * e.r + 0.07240f * e.g + 0.91049f * e.b)}}};
-}
+Color getYuv4abPixel(uhdr_raw_image_t* image, size_t x, size_t y, int h_factor, int v_factor) {
+  uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
+  size_t luma_stride = image->stride[UHDR_PLANE_Y];
+  uint8_t* cb_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_U]);
+  size_t cb_stride = image->stride[UHDR_PLANE_U];
+  uint8_t* cr_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_V]);
+  size_t cr_stride = image->stride[UHDR_PLANE_V];
 
-Color bt709ToBt2100(Color e) {
-  return {{{clampPixelFloat(0.62740f * e.r + 0.32930f * e.g + 0.04332f * e.b),
-            clampPixelFloat(0.06904f * e.r + 0.91958f * e.g + 0.01138f * e.b),
-            clampPixelFloat(0.01636f * e.r + 0.08799f * e.g + 0.89555f * e.b)}}};
+  size_t pixel_y_idx = x + y * luma_stride;
+  size_t pixel_cb_idx = x / h_factor + (y / v_factor) * cb_stride;
+  size_t pixel_cr_idx = x / h_factor + (y / v_factor) * cr_stride;
+
+  uint8_t y_uint = luma_data[pixel_y_idx];
+  uint8_t u_uint = cb_data[pixel_cb_idx];
+  uint8_t v_uint = cr_data[pixel_cr_idx];
+
+  // 128 bias for UV given we are using jpeglib; see:
+  // https://github.com/kornelski/libjpeg/blob/master/structure.doc
+  return {
+      {{static_cast<float>(y_uint) * (1 / 255.0f), static_cast<float>(u_uint - 128) * (1 / 255.0f),
+        static_cast<float>(v_uint - 128) * (1 / 255.0f)}}};
 }
 
-Color p3ToBt709(Color e) {
-  return {{{clampPixelFloat(1.22482f * e.r + -0.22490f * e.g + -0.00007f * e.b),
-            clampPixelFloat(-0.04196f * e.r + 1.04199f * e.g + 0.00001f * e.b),
-            clampPixelFloat(-0.01961f * e.r + -0.07865f * e.g + 1.09831f * e.b)}}};
+Color getYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  return getYuv4abPixel(image, x, y, 1, 1);
 }
 
-Color p3ToBt2100(Color e) {
-  return {{{clampPixelFloat(0.75378f * e.r + 0.19862f * e.g + 0.04754f * e.b),
-            clampPixelFloat(0.04576f * e.r + 0.94177f * e.g + 0.01250f * e.b),
-            clampPixelFloat(-0.00121f * e.r + 0.01757f * e.g + 0.98359f * e.b)}}};
+Color getYuv422Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  return getYuv4abPixel(image, x, y, 2, 1);
 }
 
-Color bt2100ToBt709(Color e) {
-  return {{{clampPixelFloat(1.66045f * e.r + -0.58764f * e.g + -0.07286f * e.b),
-            clampPixelFloat(-0.12445f * e.r + 1.13282f * e.g + -0.00837f * e.b),
-            clampPixelFloat(-0.01811f * e.r + -0.10057f * e.g + 1.11878f * e.b)}}};
+Color getYuv420Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  return getYuv4abPixel(image, x, y, 2, 2);
 }
 
-Color bt2100ToP3(Color e) {
-  return {{{clampPixelFloat(1.34369f * e.r + -0.28223f * e.g + -0.06135f * e.b),
-            clampPixelFloat(-0.06533f * e.r + 1.07580f * e.g + -0.01051f * e.b),
-            clampPixelFloat(0.00283f * e.r + -0.01957f * e.g + 1.01679f * e.b)}}};
+Color getYuv400Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
+  size_t luma_stride = image->stride[UHDR_PLANE_Y];
+  size_t pixel_y_idx = x + y * luma_stride;
+  uint8_t y_uint = luma_data[pixel_y_idx];
+
+  return {{{static_cast<float>(y_uint) * (1 / 255.0f), 0.f, 0.f}}};
 }
 
-// TODO: confirm we always want to convert like this before calculating
-// luminance.
-ColorTransformFn getGamutConversionFn(uhdr_color_gamut_t dst_gamut, uhdr_color_gamut_t src_gamut) {
-  switch (dst_gamut) {
-    case UHDR_CG_BT_709:
-      switch (src_gamut) {
-        case UHDR_CG_BT_709:
-          return identityConversion;
-        case UHDR_CG_DISPLAY_P3:
-          return p3ToBt709;
-        case UHDR_CG_BT_2100:
-          return bt2100ToBt709;
-        case UHDR_CG_UNSPECIFIED:
-          return nullptr;
-      }
-      break;
-    case UHDR_CG_DISPLAY_P3:
-      switch (src_gamut) {
-        case UHDR_CG_BT_709:
-          return bt709ToP3;
-        case UHDR_CG_DISPLAY_P3:
-          return identityConversion;
-        case UHDR_CG_BT_2100:
-          return bt2100ToP3;
-        case UHDR_CG_UNSPECIFIED:
-          return nullptr;
-      }
-      break;
-    case UHDR_CG_BT_2100:
-      switch (src_gamut) {
-        case UHDR_CG_BT_709:
-          return bt709ToBt2100;
-        case UHDR_CG_DISPLAY_P3:
-          return p3ToBt2100;
-        case UHDR_CG_BT_2100:
-          return identityConversion;
-        case UHDR_CG_UNSPECIFIED:
-          return nullptr;
-      }
-      break;
-    case UHDR_CG_UNSPECIFIED:
-      return nullptr;
+Color getYuv444Pixel10bit(uhdr_raw_image_t* image, size_t x, size_t y) {
+  uint16_t* luma_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_Y]);
+  size_t luma_stride = image->stride[UHDR_PLANE_Y];
+  uint16_t* cb_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_U]);
+  size_t cb_stride = image->stride[UHDR_PLANE_U];
+  uint16_t* cr_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_V]);
+  size_t cr_stride = image->stride[UHDR_PLANE_V];
+
+  size_t pixel_y_idx = y * luma_stride + x;
+  size_t pixel_u_idx = y * cb_stride + x;
+  size_t pixel_v_idx = y * cr_stride + x;
+
+  uint16_t y_uint = luma_data[pixel_y_idx];
+  uint16_t u_uint = cb_data[pixel_u_idx];
+  uint16_t v_uint = cr_data[pixel_v_idx];
+
+  if (image->range == UHDR_CR_FULL_RANGE) {
+    return {{{static_cast<float>(y_uint) / 1023.0f, static_cast<float>(u_uint) / 1023.0f - 0.5f,
+              static_cast<float>(v_uint) / 1023.0f - 0.5f}}};
   }
-  return nullptr;
+
+  // Conversions include taking narrow-range into account.
+  return {{{static_cast<float>(y_uint - 64) * (1 / 876.0f),
+            static_cast<float>(u_uint - 64) * (1 / 896.0f) - 0.5f,
+            static_cast<float>(v_uint - 64) * (1 / 896.0f) - 0.5f}}};
 }
 
-ColorTransformFn getYuvToRgbFn(uhdr_color_gamut_t gamut) {
-  switch (gamut) {
-    case UHDR_CG_BT_709:
-      return srgbYuvToRgb;
-    case UHDR_CG_DISPLAY_P3:
-      return p3YuvToRgb;
-    case UHDR_CG_BT_2100:
-      return bt2100YuvToRgb;
-    case UHDR_CG_UNSPECIFIED:
-      return nullptr;
+Color getP010Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  uint16_t* luma_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_Y]);
+  size_t luma_stride = image->stride[UHDR_PLANE_Y];
+  uint16_t* chroma_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_UV]);
+  size_t chroma_stride = image->stride[UHDR_PLANE_UV];
+
+  size_t pixel_y_idx = y * luma_stride + x;
+  size_t pixel_u_idx = (y >> 1) * chroma_stride + (x & ~0x1);
+  size_t pixel_v_idx = pixel_u_idx + 1;
+
+  uint16_t y_uint = luma_data[pixel_y_idx] >> 6;
+  uint16_t u_uint = chroma_data[pixel_u_idx] >> 6;
+  uint16_t v_uint = chroma_data[pixel_v_idx] >> 6;
+
+  if (image->range == UHDR_CR_FULL_RANGE) {
+    return {{{static_cast<float>(y_uint) / 1023.0f, static_cast<float>(u_uint) / 1023.0f - 0.5f,
+              static_cast<float>(v_uint) / 1023.0f - 0.5f}}};
   }
-  return nullptr;
+
+  // Conversions include taking narrow-range into account.
+  return {{{static_cast<float>(y_uint - 64) * (1 / 876.0f),
+            static_cast<float>(u_uint - 64) * (1 / 896.0f) - 0.5f,
+            static_cast<float>(v_uint - 64) * (1 / 896.0f) - 0.5f}}};
 }
 
-ColorCalculationFn getLuminanceFn(uhdr_color_gamut_t gamut) {
-  switch (gamut) {
-    case UHDR_CG_BT_709:
-      return srgbLuminance;
-    case UHDR_CG_DISPLAY_P3:
-      return p3Luminance;
-    case UHDR_CG_BT_2100:
-      return bt2100Luminance;
-    case UHDR_CG_UNSPECIFIED:
-      return nullptr;
-  }
-  return nullptr;
+Color getRgb888Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  uint8_t* rgbData = static_cast<uint8_t*>(image->planes[UHDR_PLANE_PACKED]);
+  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
+  size_t offset = x * 3 + y * srcStride * 3;
+  Color pixel;
+  pixel.r = float(rgbData[offset]);
+  pixel.g = float(rgbData[offset + 1]);
+  pixel.b = float(rgbData[offset + 2]);
+  return pixel / 255.0f;
 }
 
-ColorTransformFn getInverseOetfFn(uhdr_color_transfer_t transfer) {
-  switch (transfer) {
-    case UHDR_CT_LINEAR:
-      return identityConversion;
-    case UHDR_CT_HLG:
-#if USE_HLG_INVOETF_LUT
-      return hlgInvOetfLUT;
-#else
-      return hlgInvOetf;
-#endif
-    case UHDR_CT_PQ:
-#if USE_PQ_INVOETF_LUT
-      return pqInvOetfLUT;
-#else
-      return pqInvOetf;
-#endif
-    case UHDR_CT_SRGB:
-#if USE_SRGB_INVOETF_LUT
-      return srgbInvOetfLUT;
-#else
-      return srgbInvOetf;
-#endif
-    case UHDR_CT_UNSPECIFIED:
-      return nullptr;
-  }
-  return nullptr;
+Color getRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  uint32_t* rgbData = static_cast<uint32_t*>(image->planes[UHDR_PLANE_PACKED]);
+  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
+
+  Color pixel;
+  pixel.r = float(rgbData[x + y * srcStride] & 0xff);
+  pixel.g = float((rgbData[x + y * srcStride] >> 8) & 0xff);
+  pixel.b = float((rgbData[x + y * srcStride] >> 16) & 0xff);
+  return pixel / 255.0f;
 }
 
-GetPixelFn getPixelFn(uhdr_img_fmt_t format) {
-  switch (format) {
-    case UHDR_IMG_FMT_24bppYCbCr444:
-      return getYuv444Pixel;
-    case UHDR_IMG_FMT_16bppYCbCr422:
-      return getYuv422Pixel;
-    case UHDR_IMG_FMT_12bppYCbCr420:
-      return getYuv420Pixel;
-    case UHDR_IMG_FMT_24bppYCbCrP010:
-      return getP010Pixel;
-    case UHDR_IMG_FMT_30bppYCbCr444:
-      return getYuv444Pixel10bit;
-    case UHDR_IMG_FMT_32bppRGBA8888:
-      return getRgba8888Pixel;
-    case UHDR_IMG_FMT_32bppRGBA1010102:
-      return getRgba1010102Pixel;
-    default:
-      return nullptr;
-  }
-  return nullptr;
+Color getRgba1010102Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  uint32_t* rgbData = static_cast<uint32_t*>(image->planes[UHDR_PLANE_PACKED]);
+  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
+
+  Color pixel;
+  pixel.r = float(rgbData[x + y * srcStride] & 0x3ff);
+  pixel.g = float((rgbData[x + y * srcStride] >> 10) & 0x3ff);
+  pixel.b = float((rgbData[x + y * srcStride] >> 20) & 0x3ff);
+  return pixel / 1023.0f;
 }
 
-PutPixelFn putPixelFn(uhdr_img_fmt_t format) {
-  switch (format) {
-    case UHDR_IMG_FMT_24bppYCbCr444:
-      return putYuv444Pixel;
-    case UHDR_IMG_FMT_32bppRGBA8888:
-      return putRgba8888Pixel;
-    default:
-      return nullptr;
-  }
-  return nullptr;
+Color getRgbaF16Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  uint64_t* rgbData = static_cast<uint64_t*>(image->planes[UHDR_PLANE_PACKED]);
+  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
+
+  Color pixel;
+  pixel.r = halfToFloat(rgbData[x + y * srcStride] & 0xffff);
+  pixel.g = halfToFloat((rgbData[x + y * srcStride] >> 16) & 0xffff);
+  pixel.b = halfToFloat((rgbData[x + y * srcStride] >> 32) & 0xffff);
+  return sanitizePixel(pixel);
 }
 
-SamplePixelFn getSamplePixelFn(uhdr_img_fmt_t format) {
-  switch (format) {
-    case UHDR_IMG_FMT_24bppYCbCr444:
-      return sampleYuv444;
-    case UHDR_IMG_FMT_16bppYCbCr422:
-      return sampleYuv422;
-    case UHDR_IMG_FMT_12bppYCbCr420:
-      return sampleYuv420;
-    case UHDR_IMG_FMT_24bppYCbCrP010:
-      return sampleP010;
-    case UHDR_IMG_FMT_30bppYCbCr444:
-      return sampleYuv44410bit;
-    case UHDR_IMG_FMT_32bppRGBA8888:
-      return sampleRgba8888;
-    case UHDR_IMG_FMT_32bppRGBA1010102:
-      return sampleRgba1010102;
-    default:
-      return nullptr;
+static Color samplePixels(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y,
+                          GetPixelFn get_pixel_fn) {
+  Color e = {{{0.0f, 0.0f, 0.0f}}};
+  for (size_t dy = 0; dy < map_scale_factor; ++dy) {
+    for (size_t dx = 0; dx < map_scale_factor; ++dx) {
+      e += get_pixel_fn(image, x * map_scale_factor + dx, y * map_scale_factor + dy);
+    }
   }
-  return nullptr;
+
+  return e / static_cast<float>(map_scale_factor * map_scale_factor);
 }
 
-bool isPixelFormatRgb(uhdr_img_fmt_t format) {
-  return format == UHDR_IMG_FMT_64bppRGBAHalfFloat || format == UHDR_IMG_FMT_32bppRGBA8888 ||
-         format == UHDR_IMG_FMT_32bppRGBA1010102;
+Color sampleYuv444(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
+  return samplePixels(image, map_scale_factor, x, y, getYuv444Pixel);
 }
 
-float getMaxDisplayMasteringLuminance(uhdr_color_transfer_t transfer) {
-  switch (transfer) {
-    case UHDR_CT_LINEAR:
-      // TODO: configure MDML correctly for linear tf
-      return kHlgMaxNits;
-    case UHDR_CT_HLG:
-      return kHlgMaxNits;
-    case UHDR_CT_PQ:
-      return kPqMaxNits;
-    case UHDR_CT_SRGB:
-      return kSdrWhiteNits;
-    case UHDR_CT_UNSPECIFIED:
-      return -1.0f;
-  }
-  return -1.0f;
+Color sampleYuv422(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
+  return samplePixels(image, map_scale_factor, x, y, getYuv422Pixel);
+}
+
+Color sampleYuv420(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
+  return samplePixels(image, map_scale_factor, x, y, getYuv420Pixel);
+}
+
+Color sampleP010(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
+  return samplePixels(image, map_scale_factor, x, y, getP010Pixel);
+}
+
+Color sampleYuv44410bit(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
+  return samplePixels(image, map_scale_factor, x, y, getYuv444Pixel10bit);
+}
+
+Color sampleRgba8888(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
+  return samplePixels(image, map_scale_factor, x, y, getRgba8888Pixel);
+}
+
+Color sampleRgba1010102(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
+  return samplePixels(image, map_scale_factor, x, y, getRgba1010102Pixel);
+}
+
+Color sampleRgbaF16(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
+  return samplePixels(image, map_scale_factor, x, y, getRgbaF16Pixel);
+}
+
+void putRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel) {
+  uint32_t* rgbData = static_cast<uint32_t*>(image->planes[UHDR_PLANE_PACKED]);
+  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
+
+  pixel *= 255.0f;
+  pixel += 0.5f;
+  pixel.r = CLIP3(pixel.r, 0.0f, 255.0f);
+  pixel.g = CLIP3(pixel.g, 0.0f, 255.0f);
+  pixel.b = CLIP3(pixel.b, 0.0f, 255.0f);
+
+  int32_t r0 = int32_t(pixel.r);
+  int32_t g0 = int32_t(pixel.g);
+  int32_t b0 = int32_t(pixel.b);
+  rgbData[x + y * srcStride] = r0 | (g0 << 8) | (b0 << 16) | (255 << 24);  // Set alpha to 1.0
+}
+
+void putRgb888Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel) {
+  uint8_t* rgbData = static_cast<uint8_t*>(image->planes[UHDR_PLANE_PACKED]);
+  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
+  size_t offset = x * 3 + y * srcStride * 3;
+  pixel *= 255.0f;
+  pixel += 0.5f;
+  pixel.r = CLIP3(pixel.r, 0.0f, 255.0f);
+  pixel.g = CLIP3(pixel.g, 0.0f, 255.0f);
+  pixel.b = CLIP3(pixel.b, 0.0f, 255.0f);
+  rgbData[offset] = uint8_t(pixel.r);
+  rgbData[offset + 1] = uint8_t(pixel.r);
+  rgbData[offset + 2] = uint8_t(pixel.b);
+}
+
+void putYuv400Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel) {
+  uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
+  size_t luma_stride = image->stride[UHDR_PLANE_Y];
+
+  pixel *= 255.0f;
+  pixel += 0.5f;
+  pixel.y = CLIP3(pixel.y, 0.0f, 255.0f);
+
+  luma_data[x + y * luma_stride] = uint8_t(pixel.y);
+}
+
+void putYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel) {
+  uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
+  uint8_t* cb_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_U]);
+  uint8_t* cr_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_V]);
+  size_t luma_stride = image->stride[UHDR_PLANE_Y];
+  size_t cb_stride = image->stride[UHDR_PLANE_U];
+  size_t cr_stride = image->stride[UHDR_PLANE_V];
+
+  pixel *= 255.0f;
+  pixel += 0.5f;
+  pixel.y = CLIP3(pixel.y, 0.0f, 255.0f);
+  pixel.u = CLIP3(pixel.u, 0.0f, 255.0f);
+  pixel.v = CLIP3(pixel.v, 0.0f, 255.0f);
+
+  luma_data[x + y * luma_stride] = uint8_t(pixel.y);
+  cb_data[x + y * cb_stride] = uint8_t(pixel.u);
+  cr_data[x + y * cr_stride] = uint8_t(pixel.v);
+}
+
+////////////////////////////////////////////////////////////////////////////////
+// Color space conversions
+
+Color bt709ToP3(Color e) {
+  return {{{0.82254f * e.r + 0.17755f * e.g + 0.00006f * e.b,
+            0.03312f * e.r + 0.96684f * e.g + -0.00001f * e.b,
+            0.01706f * e.r + 0.07240f * e.g + 0.91049f * e.b}}};
+}
+
+Color bt709ToBt2100(Color e) {
+  return {{{0.62740f * e.r + 0.32930f * e.g + 0.04332f * e.b,
+            0.06904f * e.r + 0.91958f * e.g + 0.01138f * e.b,
+            0.01636f * e.r + 0.08799f * e.g + 0.89555f * e.b}}};
+}
+
+Color p3ToBt709(Color e) {
+  return {{{1.22482f * e.r + -0.22490f * e.g + -0.00007f * e.b,
+            -0.04196f * e.r + 1.04199f * e.g + 0.00001f * e.b,
+            -0.01961f * e.r + -0.07865f * e.g + 1.09831f * e.b}}};
+}
+
+Color p3ToBt2100(Color e) {
+  return {{{0.75378f * e.r + 0.19862f * e.g + 0.04754f * e.b,
+            0.04576f * e.r + 0.94177f * e.g + 0.01250f * e.b,
+            -0.00121f * e.r + 0.01757f * e.g + 0.98359f * e.b}}};
+}
+
+Color bt2100ToBt709(Color e) {
+  return {{{1.66045f * e.r + -0.58764f * e.g + -0.07286f * e.b,
+            -0.12445f * e.r + 1.13282f * e.g + -0.00837f * e.b,
+            -0.01811f * e.r + -0.10057f * e.g + 1.11878f * e.b}}};
+}
+
+Color bt2100ToP3(Color e) {
+  return {{{1.34369f * e.r + -0.28223f * e.g + -0.06135f * e.b,
+            -0.06533f * e.r + 1.07580f * e.g + -0.01051f * e.b,
+            0.00283f * e.r + -0.01957f * e.g + 1.01679f * e.b}}};
 }
 
 // All of these conversions are derived from the respective input YUV->RGB conversion followed by
@@ -652,6 +760,7 @@ void transformYuv444(uhdr_raw_image_t* image, const std::array<float, 9>& coeffs
 
 ////////////////////////////////////////////////////////////////////////////////
 // Gain map calculations
+
 uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata) {
   return encodeGain(y_sdr, y_hdr, metadata, log2(metadata->min_content_boost),
                     log2(metadata->max_content_boost));
@@ -693,20 +802,20 @@ Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata) {
   float logBoost =
       log2(metadata->min_content_boost) * (1.0f - gain) + log2(metadata->max_content_boost) * gain;
   float gainFactor = exp2(logBoost);
-  return e * gainFactor;
+  return ((e + metadata->offset_sdr) * gainFactor) - metadata->offset_hdr;
 }
 
-Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata, float displayBoost) {
+Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata, float gainmapWeight) {
   if (metadata->gamma != 1.0f) gain = pow(gain, 1.0f / metadata->gamma);
   float logBoost =
       log2(metadata->min_content_boost) * (1.0f - gain) + log2(metadata->max_content_boost) * gain;
-  float gainFactor = exp2(logBoost * displayBoost / metadata->hdr_capacity_max);
-  return e * gainFactor;
+  float gainFactor = exp2(logBoost * gainmapWeight);
+  return ((e + metadata->offset_sdr) * gainFactor) - metadata->offset_hdr;
 }
 
-Color applyGainLUT(Color e, float gain, GainLUT& gainLUT) {
+Color applyGainLUT(Color e, float gain, GainLUT& gainLUT, uhdr_gainmap_metadata_ext_t* metadata) {
   float gainFactor = gainLUT.getGainFactor(gain);
-  return e * gainFactor;
+  return ((e + metadata->offset_sdr) * gainFactor) - metadata->offset_hdr;
 }
 
 Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata) {
@@ -724,10 +833,12 @@ Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata) {
   float gainFactorR = exp2(logBoostR);
   float gainFactorG = exp2(logBoostG);
   float gainFactorB = exp2(logBoostB);
-  return {{{e.r * gainFactorR, e.g * gainFactorG, e.b * gainFactorB}}};
+  return {{{((e.r + metadata->offset_sdr) * gainFactorR) - metadata->offset_hdr,
+            ((e.g + metadata->offset_sdr) * gainFactorG) - metadata->offset_hdr,
+            ((e.b + metadata->offset_sdr) * gainFactorB) - metadata->offset_hdr}}};
 }
 
-Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata, float displayBoost) {
+Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata, float gainmapWeight) {
   if (metadata->gamma != 1.0f) {
     gain.r = pow(gain.r, 1.0f / metadata->gamma);
     gain.g = pow(gain.g, 1.0f / metadata->gamma);
@@ -739,201 +850,21 @@ Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata, floa
                     log2(metadata->max_content_boost) * gain.g;
   float logBoostB = log2(metadata->min_content_boost) * (1.0f - gain.b) +
                     log2(metadata->max_content_boost) * gain.b;
-  float gainFactorR = exp2(logBoostR * displayBoost / metadata->hdr_capacity_max);
-  float gainFactorG = exp2(logBoostG * displayBoost / metadata->hdr_capacity_max);
-  float gainFactorB = exp2(logBoostB * displayBoost / metadata->hdr_capacity_max);
-  return {{{e.r * gainFactorR, e.g * gainFactorG, e.b * gainFactorB}}};
+  float gainFactorR = exp2(logBoostR * gainmapWeight);
+  float gainFactorG = exp2(logBoostG * gainmapWeight);
+  float gainFactorB = exp2(logBoostB * gainmapWeight);
+  return {{{((e.r + metadata->offset_sdr) * gainFactorR) - metadata->offset_hdr,
+            ((e.g + metadata->offset_sdr) * gainFactorG) - metadata->offset_hdr,
+            ((e.b + metadata->offset_sdr) * gainFactorB) - metadata->offset_hdr}}};
 }
 
-Color applyGainLUT(Color e, Color gain, GainLUT& gainLUT) {
+Color applyGainLUT(Color e, Color gain, GainLUT& gainLUT, uhdr_gainmap_metadata_ext_t* metadata) {
   float gainFactorR = gainLUT.getGainFactor(gain.r);
   float gainFactorG = gainLUT.getGainFactor(gain.g);
   float gainFactorB = gainLUT.getGainFactor(gain.b);
-  return {{{e.r * gainFactorR, e.g * gainFactorG, e.b * gainFactorB}}};
-}
-
-Color getYuv4abPixel(uhdr_raw_image_t* image, size_t x, size_t y, int h_factor, int v_factor) {
-  uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
-  size_t luma_stride = image->stride[UHDR_PLANE_Y];
-  uint8_t* cb_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_U]);
-  size_t cb_stride = image->stride[UHDR_PLANE_U];
-  uint8_t* cr_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_V]);
-  size_t cr_stride = image->stride[UHDR_PLANE_V];
-
-  size_t pixel_y_idx = x + y * luma_stride;
-  size_t pixel_cb_idx = x / h_factor + (y / v_factor) * cb_stride;
-  size_t pixel_cr_idx = x / h_factor + (y / v_factor) * cr_stride;
-
-  uint8_t y_uint = luma_data[pixel_y_idx];
-  uint8_t u_uint = cb_data[pixel_cb_idx];
-  uint8_t v_uint = cr_data[pixel_cr_idx];
-
-  // 128 bias for UV given we are using jpeglib; see:
-  // https://github.com/kornelski/libjpeg/blob/master/structure.doc
-  return {
-      {{static_cast<float>(y_uint) * (1 / 255.0f), static_cast<float>(u_uint - 128) * (1 / 255.0f),
-        static_cast<float>(v_uint - 128) * (1 / 255.0f)}}};
-}
-
-Color getYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
-  return getYuv4abPixel(image, x, y, 1, 1);
-}
-
-Color getYuv422Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
-  return getYuv4abPixel(image, x, y, 2, 1);
-}
-
-Color getYuv420Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
-  return getYuv4abPixel(image, x, y, 2, 2);
-}
-
-Color getYuv444Pixel10bit(uhdr_raw_image_t* image, size_t x, size_t y) {
-  uint16_t* luma_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_Y]);
-  size_t luma_stride = image->stride[UHDR_PLANE_Y];
-  uint16_t* cb_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_U]);
-  size_t cb_stride = image->stride[UHDR_PLANE_U];
-  uint16_t* cr_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_V]);
-  size_t cr_stride = image->stride[UHDR_PLANE_V];
-
-  size_t pixel_y_idx = y * luma_stride + x;
-  size_t pixel_u_idx = y * cb_stride + x;
-  size_t pixel_v_idx = y * cr_stride + x;
-
-  uint16_t y_uint = luma_data[pixel_y_idx];
-  uint16_t u_uint = cb_data[pixel_u_idx];
-  uint16_t v_uint = cr_data[pixel_v_idx];
-
-  if (image->range == UHDR_CR_FULL_RANGE) {
-    return {{{static_cast<float>(y_uint) / 1023.0f, static_cast<float>(u_uint) / 1023.0f - 0.5f,
-              static_cast<float>(v_uint) / 1023.0f - 0.5f}}};
-  }
-
-  // Conversions include taking narrow-range into account.
-  return {{{static_cast<float>(y_uint - 64) * (1 / 876.0f),
-            static_cast<float>(u_uint - 64) * (1 / 896.0f) - 0.5f,
-            static_cast<float>(v_uint - 64) * (1 / 896.0f) - 0.5f}}};
-}
-
-Color getP010Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
-  uint16_t* luma_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_Y]);
-  size_t luma_stride = image->stride[UHDR_PLANE_Y];
-  uint16_t* chroma_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_UV]);
-  size_t chroma_stride = image->stride[UHDR_PLANE_UV];
-
-  size_t pixel_y_idx = y * luma_stride + x;
-  size_t pixel_u_idx = (y >> 1) * chroma_stride + (x & ~0x1);
-  size_t pixel_v_idx = pixel_u_idx + 1;
-
-  uint16_t y_uint = luma_data[pixel_y_idx] >> 6;
-  uint16_t u_uint = chroma_data[pixel_u_idx] >> 6;
-  uint16_t v_uint = chroma_data[pixel_v_idx] >> 6;
-
-  if (image->range == UHDR_CR_FULL_RANGE) {
-    return {{{static_cast<float>(y_uint) / 1023.0f, static_cast<float>(u_uint) / 1023.0f - 0.5f,
-              static_cast<float>(v_uint) / 1023.0f - 0.5f}}};
-  }
-
-  // Conversions include taking narrow-range into account.
-  return {{{static_cast<float>(y_uint - 64) * (1 / 876.0f),
-            static_cast<float>(u_uint - 64) * (1 / 896.0f) - 0.5f,
-            static_cast<float>(v_uint - 64) * (1 / 896.0f) - 0.5f}}};
-}
-
-Color getRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
-  uint32_t* rgbData = static_cast<uint32_t*>(image->planes[UHDR_PLANE_PACKED]);
-  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
-
-  Color pixel;
-  pixel.r = float(rgbData[x + y * srcStride] & 0xff);
-  pixel.g = float((rgbData[x + y * srcStride] >> 8) & 0xff);
-  pixel.b = float((rgbData[x + y * srcStride] >> 16) & 0xff);
-  return pixel / 255.0f;
-}
-
-Color getRgba1010102Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
-  uint32_t* rgbData = static_cast<uint32_t*>(image->planes[UHDR_PLANE_PACKED]);
-  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
-
-  Color pixel;
-  pixel.r = float(rgbData[x + y * srcStride] & 0x3ff);
-  pixel.g = float((rgbData[x + y * srcStride] >> 10) & 0x3ff);
-  pixel.b = float((rgbData[x + y * srcStride] >> 20) & 0x3ff);
-  return pixel / 1023.0f;
-}
-
-static Color samplePixels(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y,
-                          GetPixelFn get_pixel_fn) {
-  Color e = {{{0.0f, 0.0f, 0.0f}}};
-  for (size_t dy = 0; dy < map_scale_factor; ++dy) {
-    for (size_t dx = 0; dx < map_scale_factor; ++dx) {
-      e += get_pixel_fn(image, x * map_scale_factor + dx, y * map_scale_factor + dy);
-    }
-  }
-
-  return e / static_cast<float>(map_scale_factor * map_scale_factor);
-}
-
-Color sampleYuv444(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
-  return samplePixels(image, map_scale_factor, x, y, getYuv444Pixel);
-}
-
-Color sampleYuv422(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
-  return samplePixels(image, map_scale_factor, x, y, getYuv422Pixel);
-}
-
-Color sampleYuv420(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
-  return samplePixels(image, map_scale_factor, x, y, getYuv420Pixel);
-}
-
-Color sampleP010(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
-  return samplePixels(image, map_scale_factor, x, y, getP010Pixel);
-}
-
-Color sampleYuv44410bit(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
-  return samplePixels(image, map_scale_factor, x, y, getYuv444Pixel10bit);
-}
-
-Color sampleRgba8888(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
-  return samplePixels(image, map_scale_factor, x, y, getRgba8888Pixel);
-}
-
-Color sampleRgba1010102(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
-  return samplePixels(image, map_scale_factor, x, y, getRgba1010102Pixel);
-}
-
-void putRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel) {
-  uint32_t* rgbData = static_cast<uint32_t*>(image->planes[UHDR_PLANE_PACKED]);
-  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
-
-  pixel *= 255.0f;
-  pixel += 0.5f;
-  pixel.r = CLIP3(pixel.r, 0.0f, 255.0f);
-  pixel.g = CLIP3(pixel.g, 0.0f, 255.0f);
-  pixel.b = CLIP3(pixel.b, 0.0f, 255.0f);
-
-  int32_t r0 = int32_t(pixel.r);
-  int32_t g0 = int32_t(pixel.g);
-  int32_t b0 = int32_t(pixel.b);
-  rgbData[x + y * srcStride] = r0 | (g0 << 8) | (b0 << 16) | (255 << 24);  // Set alpha to 1.0
-}
-
-void putYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel) {
-  uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
-  uint8_t* cb_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_U]);
-  uint8_t* cr_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_V]);
-  size_t luma_stride = image->stride[UHDR_PLANE_Y];
-  size_t cb_stride = image->stride[UHDR_PLANE_U];
-  size_t cr_stride = image->stride[UHDR_PLANE_V];
-
-  pixel *= 255.0f;
-  pixel += 0.5f;
-  pixel.y = CLIP3(pixel.y, 0.0f, 255.0f);
-  pixel.u = CLIP3(pixel.u, 0.0f, 255.0f);
-  pixel.v = CLIP3(pixel.v, 0.0f, 255.0f);
-
-  luma_data[x + y * luma_stride] = uint8_t(pixel.y);
-  cb_data[x + y * cb_stride] = uint8_t(pixel.u);
-  cr_data[x + y * cr_stride] = uint8_t(pixel.v);
+  return {{{((e.r + metadata->offset_sdr) * gainFactorR) - metadata->offset_hdr,
+            ((e.g + metadata->offset_sdr) * gainFactorG) - metadata->offset_hdr,
+            ((e.b + metadata->offset_sdr) * gainFactorB) - metadata->offset_hdr}}};
 }
 
 // TODO: do we need something more clever for filtering either the map or images
@@ -1022,8 +953,8 @@ float sampleMap(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t
 
   // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
   // following by using & (map_scale_factor - 1)
-  int offset_x = x % map_scale_factor;
-  int offset_y = y % map_scale_factor;
+  size_t offset_x = x % map_scale_factor;
+  size_t offset_y = y % map_scale_factor;
 
   float* weights = weightTables.mWeights;
   if (x_lower == x_upper && y_lower == y_upper)
@@ -1146,8 +1077,8 @@ Color sampleMap3Channel(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x
 
   // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
   // following by using & (map_scale_factor - 1)
-  int offset_x = x % map_scale_factor;
-  int offset_y = y % map_scale_factor;
+  size_t offset_x = x % map_scale_factor;
+  size_t offset_y = y % map_scale_factor;
 
   float* weights = weightTables.mWeights;
   if (x_lower == x_upper && y_lower == y_upper)
@@ -1161,6 +1092,203 @@ Color sampleMap3Channel(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x
   return rgb1 * weights[0] + rgb2 * weights[1] + rgb3 * weights[2] + rgb4 * weights[3];
 }
 
+////////////////////////////////////////////////////////////////////////////////
+// function selectors
+
+// TODO: confirm we always want to convert like this before calculating
+// luminance.
+ColorTransformFn getGamutConversionFn(uhdr_color_gamut_t dst_gamut, uhdr_color_gamut_t src_gamut) {
+  switch (dst_gamut) {
+    case UHDR_CG_BT_709:
+      switch (src_gamut) {
+        case UHDR_CG_BT_709:
+          return identityConversion;
+        case UHDR_CG_DISPLAY_P3:
+          return p3ToBt709;
+        case UHDR_CG_BT_2100:
+          return bt2100ToBt709;
+        case UHDR_CG_UNSPECIFIED:
+          return nullptr;
+      }
+      break;
+    case UHDR_CG_DISPLAY_P3:
+      switch (src_gamut) {
+        case UHDR_CG_BT_709:
+          return bt709ToP3;
+        case UHDR_CG_DISPLAY_P3:
+          return identityConversion;
+        case UHDR_CG_BT_2100:
+          return bt2100ToP3;
+        case UHDR_CG_UNSPECIFIED:
+          return nullptr;
+      }
+      break;
+    case UHDR_CG_BT_2100:
+      switch (src_gamut) {
+        case UHDR_CG_BT_709:
+          return bt709ToBt2100;
+        case UHDR_CG_DISPLAY_P3:
+          return p3ToBt2100;
+        case UHDR_CG_BT_2100:
+          return identityConversion;
+        case UHDR_CG_UNSPECIFIED:
+          return nullptr;
+      }
+      break;
+    case UHDR_CG_UNSPECIFIED:
+      return nullptr;
+  }
+  return nullptr;
+}
+
+ColorTransformFn getYuvToRgbFn(uhdr_color_gamut_t gamut) {
+  switch (gamut) {
+    case UHDR_CG_BT_709:
+      return srgbYuvToRgb;
+    case UHDR_CG_DISPLAY_P3:
+      return p3YuvToRgb;
+    case UHDR_CG_BT_2100:
+      return bt2100YuvToRgb;
+    case UHDR_CG_UNSPECIFIED:
+      return nullptr;
+  }
+  return nullptr;
+}
+
+LuminanceFn getLuminanceFn(uhdr_color_gamut_t gamut) {
+  switch (gamut) {
+    case UHDR_CG_BT_709:
+      return srgbLuminance;
+    case UHDR_CG_DISPLAY_P3:
+      return p3Luminance;
+    case UHDR_CG_BT_2100:
+      return bt2100Luminance;
+    case UHDR_CG_UNSPECIFIED:
+      return nullptr;
+  }
+  return nullptr;
+}
+
+ColorTransformFn getInverseOetfFn(uhdr_color_transfer_t transfer) {
+  switch (transfer) {
+    case UHDR_CT_LINEAR:
+      return identityConversion;
+    case UHDR_CT_HLG:
+#if USE_HLG_INVOETF_LUT
+      return hlgInvOetfLUT;
+#else
+      return hlgInvOetf;
+#endif
+    case UHDR_CT_PQ:
+#if USE_PQ_INVOETF_LUT
+      return pqInvOetfLUT;
+#else
+      return pqInvOetf;
+#endif
+    case UHDR_CT_SRGB:
+#if USE_SRGB_INVOETF_LUT
+      return srgbInvOetfLUT;
+#else
+      return srgbInvOetf;
+#endif
+    case UHDR_CT_UNSPECIFIED:
+      return nullptr;
+  }
+  return nullptr;
+}
+
+SceneToDisplayLuminanceFn getOotfFn(uhdr_color_transfer_t transfer) {
+  switch (transfer) {
+    case UHDR_CT_LINEAR:
+      return identityOotf;
+    case UHDR_CT_HLG:
+      return hlgOotfApprox;
+    case UHDR_CT_PQ:
+      return identityOotf;
+    case UHDR_CT_SRGB:
+      return identityOotf;
+    case UHDR_CT_UNSPECIFIED:
+      return nullptr;
+  }
+  return nullptr;
+}
+
+GetPixelFn getPixelFn(uhdr_img_fmt_t format) {
+  switch (format) {
+    case UHDR_IMG_FMT_24bppYCbCr444:
+      return getYuv444Pixel;
+    case UHDR_IMG_FMT_16bppYCbCr422:
+      return getYuv422Pixel;
+    case UHDR_IMG_FMT_12bppYCbCr420:
+      return getYuv420Pixel;
+    case UHDR_IMG_FMT_24bppYCbCrP010:
+      return getP010Pixel;
+    case UHDR_IMG_FMT_30bppYCbCr444:
+      return getYuv444Pixel10bit;
+    case UHDR_IMG_FMT_32bppRGBA8888:
+      return getRgba8888Pixel;
+    case UHDR_IMG_FMT_32bppRGBA1010102:
+      return getRgba1010102Pixel;
+    case UHDR_IMG_FMT_64bppRGBAHalfFloat:
+      return getRgbaF16Pixel;
+    case UHDR_IMG_FMT_8bppYCbCr400:
+      return getYuv400Pixel;
+    case UHDR_IMG_FMT_24bppRGB888:
+      return getRgb888Pixel;
+    default:
+      return nullptr;
+  }
+  return nullptr;
+}
+
+PutPixelFn putPixelFn(uhdr_img_fmt_t format) {
+  switch (format) {
+    case UHDR_IMG_FMT_24bppYCbCr444:
+      return putYuv444Pixel;
+    case UHDR_IMG_FMT_32bppRGBA8888:
+      return putRgba8888Pixel;
+    case UHDR_IMG_FMT_8bppYCbCr400:
+      return putYuv400Pixel;
+    case UHDR_IMG_FMT_24bppRGB888:
+      return putRgb888Pixel;
+    default:
+      return nullptr;
+  }
+  return nullptr;
+}
+
+SamplePixelFn getSamplePixelFn(uhdr_img_fmt_t format) {
+  switch (format) {
+    case UHDR_IMG_FMT_24bppYCbCr444:
+      return sampleYuv444;
+    case UHDR_IMG_FMT_16bppYCbCr422:
+      return sampleYuv422;
+    case UHDR_IMG_FMT_12bppYCbCr420:
+      return sampleYuv420;
+    case UHDR_IMG_FMT_24bppYCbCrP010:
+      return sampleP010;
+    case UHDR_IMG_FMT_30bppYCbCr444:
+      return sampleYuv44410bit;
+    case UHDR_IMG_FMT_32bppRGBA8888:
+      return sampleRgba8888;
+    case UHDR_IMG_FMT_32bppRGBA1010102:
+      return sampleRgba1010102;
+    case UHDR_IMG_FMT_64bppRGBAHalfFloat:
+      return sampleRgbaF16;
+    default:
+      return nullptr;
+  }
+  return nullptr;
+}
+
+////////////////////////////////////////////////////////////////////////////////
+// common utils
+
+bool isPixelFormatRgb(uhdr_img_fmt_t format) {
+  return format == UHDR_IMG_FMT_64bppRGBAHalfFloat || format == UHDR_IMG_FMT_32bppRGBA8888 ||
+         format == UHDR_IMG_FMT_32bppRGBA1010102;
+}
+
 uint32_t colorToRgba1010102(Color e_gamma) {
   uint32_t r = CLIP3((e_gamma.r * 1023 + 0.5f), 0.0f, 1023.0f);
   uint32_t g = CLIP3((e_gamma.g * 1023 + 0.5f), 0.0f, 1023.0f);
@@ -1331,8 +1459,8 @@ std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_
         pixel[0].u = (pixel[0].u + pixel[1].u + pixel[2].u + pixel[3].u) / 4;
         pixel[0].v = (pixel[0].v + pixel[1].v + pixel[2].v + pixel[3].v) / 4;
 
-        pixel[0].u = pixel[0].u * 255.0f + 0.5 + 128.0f;
-        pixel[0].v = pixel[0].v * 255.0f + 0.5 + 128.0f;
+        pixel[0].u = pixel[0].u * 255.0f + 0.5f + 128.0f;
+        pixel[0].v = pixel[0].v * 255.0f + 0.5f + 128.0f;
 
         pixel[0].u = CLIP3(pixel[0].u, 0.0f, 255.0f);
         pixel[0].v = CLIP3(pixel[0].v, 0.0f, 255.0f);
@@ -1366,8 +1494,8 @@ std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_
         pixel.y = CLIP3(pixel.y, 0.0f, 255.0f);
         yData[dst->stride[UHDR_PLANE_Y] * i + j] = uint8_t(pixel.y);
 
-        pixel.u = pixel.u * 255.0f + 0.5 + 128.0f;
-        pixel.v = pixel.v * 255.0f + 0.5 + 128.0f;
+        pixel.u = pixel.u * 255.0f + 0.5f + 128.0f;
+        pixel.v = pixel.v * 255.0f + 0.5f + 128.0f;
 
         pixel.u = CLIP3(pixel.u, 0.0f, 255.0f);
         pixel.v = CLIP3(pixel.v, 0.0f, 255.0f);
@@ -1410,7 +1538,7 @@ uhdr_error_info_t copy_raw_image(uhdr_raw_image_t* src, uhdr_raw_image_t* dst) {
   dst->range = src->range;
   if (dst->fmt == src->fmt) {
     if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
-      int bpp = 2;
+      size_t bpp = 2;
       uint8_t* y_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
       uint8_t* y_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
       uint8_t* uv_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_UV]);
@@ -1458,7 +1586,7 @@ uhdr_error_info_t copy_raw_image(uhdr_raw_image_t* src, uhdr_raw_image_t* dst) {
                src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_24bppRGB888) {
       uint8_t* plane_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_PACKED]);
       uint8_t* plane_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_PACKED]);
-      int bpp = 1;
+      size_t bpp = 1;
 
       if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888)
         bpp = 4;
@@ -1486,7 +1614,7 @@ uhdr_error_info_t copy_raw_image(uhdr_raw_image_t* src, uhdr_raw_image_t* dst) {
           pixel_dst += 1;
         }
         plane_dst += dst->stride[UHDR_PLANE_PACKED];
-        plane_src += 3 * src->stride[UHDR_PLANE_PACKED];
+        plane_src += (size_t)3 * src->stride[UHDR_PLANE_PACKED];
       }
       return g_no_error;
     }
diff --git a/lib/src/gainmapmetadata.cpp b/lib/src/gainmapmetadata.cpp
index 972e6fa..6979c82 100644
--- a/lib/src/gainmapmetadata.cpp
+++ b/lib/src/gainmapmetadata.cpp
@@ -14,6 +14,9 @@
  * limitations under the License.
  */
 
+#include <algorithm>
+#include <cmath>
+
 #include "ultrahdr/gainmapmath.h"
 #include "ultrahdr/gainmapmetadata.h"
 
@@ -21,6 +24,11 @@ namespace ultrahdr {
 
 void streamWriteU8(std::vector<uint8_t> &data, uint8_t value) { data.push_back(value); }
 
+void streamWriteU16(std::vector<uint8_t> &data, uint16_t value) {
+  data.push_back((value >> 8) & 0xff);
+  data.push_back(value & 0xff);
+}
+
 void streamWriteU32(std::vector<uint8_t> &data, uint32_t value) {
   data.push_back((value >> 24) & 0xff);
   data.push_back((value >> 16) & 0xff);
@@ -28,6 +36,13 @@ void streamWriteU32(std::vector<uint8_t> &data, uint32_t value) {
   data.push_back(value & 0xff);
 }
 
+void streamWriteS32(std::vector<uint8_t> &data, int32_t value) {
+  data.push_back((value >> 24) & 0xff);
+  data.push_back((value >> 16) & 0xff);
+  data.push_back((value >> 8) & 0xff);
+  data.push_back(value & 0xff);
+}
+
 uhdr_error_info_t streamReadU8(const std::vector<uint8_t> &data, uint8_t &value, size_t &pos) {
   if (pos >= data.size()) {
     uhdr_error_info_t status;
@@ -42,6 +57,21 @@ uhdr_error_info_t streamReadU8(const std::vector<uint8_t> &data, uint8_t &value,
   return g_no_error;
 }
 
+uhdr_error_info_t streamReadU16(const std::vector<uint8_t> &data, uint16_t &value, size_t &pos) {
+  if (pos + 1 >= data.size()) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_MEM_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "attempting to read 2 bytes from position %d when the buffer size is %d", (int)pos,
+             (int)data.size());
+    return status;
+  }
+  value = (data[pos] << 8 | data[pos + 1]);
+  pos += 2;
+  return g_no_error;
+}
+
 uhdr_error_info_t streamReadU32(const std::vector<uint8_t> &data, uint32_t &value, size_t &pos) {
   if (pos + 3 >= data.size()) {
     uhdr_error_info_t status;
@@ -57,6 +87,34 @@ uhdr_error_info_t streamReadU32(const std::vector<uint8_t> &data, uint32_t &valu
   return g_no_error;
 }
 
+uhdr_error_info_t streamReadS32(const std::vector<uint8_t> &data, int32_t &value, size_t &pos) {
+  if (pos + 3 >= data.size()) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_MEM_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "attempting to read 4 bytes from position %d when the buffer size is %d", (int)pos,
+             (int)data.size());
+    return status;
+  }
+  value = (data[pos] << 24 | data[pos + 1] << 16 | data[pos + 2] << 8 | data[pos + 3]);
+  pos += 4;
+  return g_no_error;
+}
+
+bool uhdr_gainmap_metadata_frac::allChannelsIdentical() const {
+  return gainMapMinN[0] == gainMapMinN[1] && gainMapMinN[0] == gainMapMinN[2] &&
+         gainMapMinD[0] == gainMapMinD[1] && gainMapMinD[0] == gainMapMinD[2] &&
+         gainMapMaxN[0] == gainMapMaxN[1] && gainMapMaxN[0] == gainMapMaxN[2] &&
+         gainMapMaxD[0] == gainMapMaxD[1] && gainMapMaxD[0] == gainMapMaxD[2] &&
+         gainMapGammaN[0] == gainMapGammaN[1] && gainMapGammaN[0] == gainMapGammaN[2] &&
+         gainMapGammaD[0] == gainMapGammaD[1] && gainMapGammaD[0] == gainMapGammaD[2] &&
+         baseOffsetN[0] == baseOffsetN[1] && baseOffsetN[0] == baseOffsetN[2] &&
+         baseOffsetD[0] == baseOffsetD[1] && baseOffsetD[0] == baseOffsetD[2] &&
+         alternateOffsetN[0] == alternateOffsetN[1] && alternateOffsetN[0] == alternateOffsetN[2] &&
+         alternateOffsetD[0] == alternateOffsetD[1] && alternateOffsetD[0] == alternateOffsetD[2];
+}
+
 uhdr_error_info_t uhdr_gainmap_metadata_frac::encodeGainmapMetadata(
     const uhdr_gainmap_metadata_frac *in_metadata, std::vector<uint8_t> &out_data) {
   if (in_metadata == nullptr) {
@@ -68,42 +126,22 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::encodeGainmapMetadata(
     return status;
   }
 
-  const uint8_t version = 0;
-  streamWriteU8(out_data, version);
+  const uint16_t min_version = 0, writer_version = 0;
+  streamWriteU16(out_data, min_version);
+  streamWriteU16(out_data, writer_version);
 
   uint8_t flags = 0u;
   // Always write three channels for now for simplicity.
   // TODO(maryla): the draft says that this specifies the count of channels of the
   // gain map. But tone mapping is done in RGB space so there are always three
   // channels, even if the gain map is grayscale. Should this be revised?
-  const bool allChannelsIdentical =
-      in_metadata->gainMapMinN[0] == in_metadata->gainMapMinN[1] &&
-      in_metadata->gainMapMinN[0] == in_metadata->gainMapMinN[2] &&
-      in_metadata->gainMapMinD[0] == in_metadata->gainMapMinD[1] &&
-      in_metadata->gainMapMinD[0] == in_metadata->gainMapMinD[2] &&
-      in_metadata->gainMapMaxN[0] == in_metadata->gainMapMaxN[1] &&
-      in_metadata->gainMapMaxN[0] == in_metadata->gainMapMaxN[2] &&
-      in_metadata->gainMapMaxD[0] == in_metadata->gainMapMaxD[1] &&
-      in_metadata->gainMapMaxD[0] == in_metadata->gainMapMaxD[2] &&
-      in_metadata->gainMapGammaN[0] == in_metadata->gainMapGammaN[1] &&
-      in_metadata->gainMapGammaN[0] == in_metadata->gainMapGammaN[2] &&
-      in_metadata->gainMapGammaD[0] == in_metadata->gainMapGammaD[1] &&
-      in_metadata->gainMapGammaD[0] == in_metadata->gainMapGammaD[2] &&
-      in_metadata->baseOffsetN[0] == in_metadata->baseOffsetN[1] &&
-      in_metadata->baseOffsetN[0] == in_metadata->baseOffsetN[2] &&
-      in_metadata->baseOffsetD[0] == in_metadata->baseOffsetD[1] &&
-      in_metadata->baseOffsetD[0] == in_metadata->baseOffsetD[2] &&
-      in_metadata->alternateOffsetN[0] == in_metadata->alternateOffsetN[1] &&
-      in_metadata->alternateOffsetN[0] == in_metadata->alternateOffsetN[2] &&
-      in_metadata->alternateOffsetD[0] == in_metadata->alternateOffsetD[1] &&
-      in_metadata->alternateOffsetD[0] == in_metadata->alternateOffsetD[2];
-  const uint8_t channelCount = allChannelsIdentical ? 1u : 3u;
+  const uint8_t channelCount = in_metadata->allChannelsIdentical() ? 1u : 3u;
 
   if (channelCount == 3) {
-    flags |= 1;
+    flags |= kIsMultiChannelMask;
   }
   if (in_metadata->useBaseColorSpace) {
-    flags |= 2;
+    flags |= kUseBaseColorSpaceMask;
   }
   if (in_metadata->backwardDirection) {
     flags |= 4;
@@ -131,11 +169,11 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::encodeGainmapMetadata(
     streamWriteU32(out_data, in_metadata->baseHdrHeadroomN);
     streamWriteU32(out_data, in_metadata->alternateHdrHeadroomN);
     for (int c = 0; c < channelCount; ++c) {
-      streamWriteU32(out_data, (uint32_t)in_metadata->gainMapMinN[c]);
-      streamWriteU32(out_data, (uint32_t)in_metadata->gainMapMaxN[c]);
+      streamWriteS32(out_data, in_metadata->gainMapMinN[c]);
+      streamWriteS32(out_data, in_metadata->gainMapMaxN[c]);
       streamWriteU32(out_data, in_metadata->gainMapGammaN[c]);
-      streamWriteU32(out_data, (uint32_t)in_metadata->baseOffsetN[c]);
-      streamWriteU32(out_data, (uint32_t)in_metadata->alternateOffsetN[c]);
+      streamWriteS32(out_data, in_metadata->baseOffsetN[c]);
+      streamWriteS32(out_data, in_metadata->alternateOffsetN[c]);
     }
   } else {
     streamWriteU32(out_data, in_metadata->baseHdrHeadroomN);
@@ -143,15 +181,15 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::encodeGainmapMetadata(
     streamWriteU32(out_data, in_metadata->alternateHdrHeadroomN);
     streamWriteU32(out_data, in_metadata->alternateHdrHeadroomD);
     for (int c = 0; c < channelCount; ++c) {
-      streamWriteU32(out_data, (uint32_t)in_metadata->gainMapMinN[c]);
+      streamWriteS32(out_data, in_metadata->gainMapMinN[c]);
       streamWriteU32(out_data, in_metadata->gainMapMinD[c]);
-      streamWriteU32(out_data, (uint32_t)in_metadata->gainMapMaxN[c]);
+      streamWriteS32(out_data, in_metadata->gainMapMaxN[c]);
       streamWriteU32(out_data, in_metadata->gainMapMaxD[c]);
       streamWriteU32(out_data, in_metadata->gainMapGammaN[c]);
       streamWriteU32(out_data, in_metadata->gainMapGammaD[c]);
-      streamWriteU32(out_data, (uint32_t)in_metadata->baseOffsetN[c]);
+      streamWriteS32(out_data, in_metadata->baseOffsetN[c]);
       streamWriteU32(out_data, in_metadata->baseOffsetD[c]);
-      streamWriteU32(out_data, (uint32_t)in_metadata->alternateOffsetN[c]);
+      streamWriteS32(out_data, in_metadata->alternateOffsetN[c]);
       streamWriteU32(out_data, in_metadata->alternateOffsetD[c]);
     }
   }
@@ -171,20 +209,22 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::decodeGainmapMetadata(
   }
 
   size_t pos = 0;
-  uint8_t version = 0xff;
-  UHDR_ERR_CHECK(streamReadU8(in_data, version, pos))
-  if (version != 0) {
+  uint16_t min_version = 0xffff;
+  uint16_t writer_version = 0xffff;
+  UHDR_ERR_CHECK(streamReadU16(in_data, min_version, pos))
+  if (min_version != 0) {
     uhdr_error_info_t status;
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
     status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail, "received unexpected version %d, expected 0",
-             version);
+    snprintf(status.detail, sizeof status.detail,
+             "received unexpected minimum version %d, expected 0", min_version);
     return status;
   }
+  UHDR_ERR_CHECK(streamReadU16(in_data, writer_version, pos))
 
   uint8_t flags = 0xff;
   UHDR_ERR_CHECK(streamReadU8(in_data, flags, pos))
-  uint8_t channelCount = (flags & 1) * 2 + 1;
+  uint8_t channelCount = ((flags & kIsMultiChannelMask) != 0) * 2 + 1;
   if (!(channelCount == 1 || channelCount == 3)) {
     uhdr_error_info_t status;
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
@@ -193,7 +233,7 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::decodeGainmapMetadata(
              "received unexpected channel count %d, expects one of {1, 3}", channelCount);
     return status;
   }
-  out_metadata->useBaseColorSpace = (flags & 2) != 0;
+  out_metadata->useBaseColorSpace = (flags & kUseBaseColorSpaceMask) != 0;
   out_metadata->backwardDirection = (flags & 4) != 0;
   const bool useCommonDenominator = (flags & 8) != 0;
 
@@ -207,15 +247,15 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::decodeGainmapMetadata(
     out_metadata->alternateHdrHeadroomD = commonDenominator;
 
     for (int c = 0; c < channelCount; ++c) {
-      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMinN[c], pos))
+      UHDR_ERR_CHECK(streamReadS32(in_data, out_metadata->gainMapMinN[c], pos))
       out_metadata->gainMapMinD[c] = commonDenominator;
-      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMaxN[c], pos))
+      UHDR_ERR_CHECK(streamReadS32(in_data, out_metadata->gainMapMaxN[c], pos))
       out_metadata->gainMapMaxD[c] = commonDenominator;
       UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapGammaN[c], pos))
       out_metadata->gainMapGammaD[c] = commonDenominator;
-      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->baseOffsetN[c], pos))
+      UHDR_ERR_CHECK(streamReadS32(in_data, out_metadata->baseOffsetN[c], pos))
       out_metadata->baseOffsetD[c] = commonDenominator;
-      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateOffsetN[c], pos))
+      UHDR_ERR_CHECK(streamReadS32(in_data, out_metadata->alternateOffsetN[c], pos))
       out_metadata->alternateOffsetD[c] = commonDenominator;
     }
   } else {
@@ -224,15 +264,15 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::decodeGainmapMetadata(
     UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateHdrHeadroomN, pos))
     UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateHdrHeadroomD, pos))
     for (int c = 0; c < channelCount; ++c) {
-      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMinN[c], pos))
+      UHDR_ERR_CHECK(streamReadS32(in_data, out_metadata->gainMapMinN[c], pos))
       UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMinD[c], pos))
-      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMaxN[c], pos))
+      UHDR_ERR_CHECK(streamReadS32(in_data, out_metadata->gainMapMaxN[c], pos))
       UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMaxD[c], pos))
       UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapGammaN[c], pos))
       UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapGammaD[c], pos))
-      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->baseOffsetN[c], pos))
+      UHDR_ERR_CHECK(streamReadS32(in_data, out_metadata->baseOffsetN[c], pos))
       UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->baseOffsetD[c], pos))
-      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateOffsetN[c], pos))
+      UHDR_ERR_CHECK(streamReadS32(in_data, out_metadata->alternateOffsetN[c], pos))
       UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateOffsetD[c], pos))
     }
   }
@@ -283,16 +323,48 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(
     UHDR_CHECK_NON_ZERO(from->baseOffsetD[i], "baseOffset denominator");
     UHDR_CHECK_NON_ZERO(from->alternateOffsetD[i], "alternateOffset denominator");
   }
+
+  // TODO: extend uhdr_gainmap_metadata_ext_t to cover multi-channel
+  if (!from->allChannelsIdentical()) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "current implementation does not handle images with gainmap metadata different "
+             "across r/g/b channels");
+    return status;
+  }
+
+  // jpeg supports only 8 bits per component, applying gainmap in inverse direction is unexpected
+  if (from->backwardDirection) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "hdr intent as base rendition is not supported");
+    return status;
+  }
+
+  // TODO: parse gainmap image icc and use it for color conversion during applygainmap
+  if (!from->useBaseColorSpace) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "current implementation requires gainmap application space to match base color space");
+    return status;
+  }
+
   to->version = kJpegrVersion;
-  to->max_content_boost = (float)from->gainMapMaxN[0] / from->gainMapMaxD[0];
-  to->min_content_boost = (float)from->gainMapMinN[0] / from->gainMapMinD[0];
+  to->max_content_boost = exp2((float)from->gainMapMaxN[0] / from->gainMapMaxD[0]);
+  to->min_content_boost = exp2((float)from->gainMapMinN[0] / from->gainMapMinD[0]);
+
   to->gamma = (float)from->gainMapGammaN[0] / from->gainMapGammaD[0];
 
   // BaseRenditionIsHDR is false
   to->offset_sdr = (float)from->baseOffsetN[0] / from->baseOffsetD[0];
   to->offset_hdr = (float)from->alternateOffsetN[0] / from->alternateOffsetD[0];
-  to->hdr_capacity_max = (float)from->alternateHdrHeadroomN / from->alternateHdrHeadroomD;
-  to->hdr_capacity_min = (float)from->baseHdrHeadroomN / from->baseHdrHeadroomD;
+  to->hdr_capacity_max = exp2((float)from->alternateHdrHeadroomN / from->alternateHdrHeadroomD);
+  to->hdr_capacity_min = exp2((float)from->baseHdrHeadroomN / from->baseHdrHeadroomD);
 
   return g_no_error;
 }
@@ -311,30 +383,56 @@ uhdr_error_info_t uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(
   to->backwardDirection = false;
   to->useBaseColorSpace = true;
 
-  floatToUnsignedFraction(from->max_content_boost, &to->gainMapMaxN[0], &to->gainMapMaxD[0]);
+#define CONVERT_FLT_TO_UNSIGNED_FRACTION(flt, numerator, denominator)                          \
+  if (!floatToUnsignedFraction(flt, numerator, denominator)) {                                 \
+    uhdr_error_info_t status;                                                                  \
+    status.error_code = UHDR_CODEC_INVALID_PARAM;                                              \
+    status.has_detail = 1;                                                                     \
+    snprintf(status.detail, sizeof status.detail,                                              \
+             "encountered error while representing float %f as a rational number (p/q form) ", \
+             flt);                                                                             \
+    return status;                                                                             \
+  }
+
+#define CONVERT_FLT_TO_SIGNED_FRACTION(flt, numerator, denominator)                            \
+  if (!floatToSignedFraction(flt, numerator, denominator)) {                                   \
+    uhdr_error_info_t status;                                                                  \
+    status.error_code = UHDR_CODEC_INVALID_PARAM;                                              \
+    status.has_detail = 1;                                                                     \
+    snprintf(status.detail, sizeof status.detail,                                              \
+             "encountered error while representing float %f as a rational number (p/q form) ", \
+             flt);                                                                             \
+    return status;                                                                             \
+  }
+
+  CONVERT_FLT_TO_SIGNED_FRACTION(log2(from->max_content_boost), &to->gainMapMaxN[0],
+                                 &to->gainMapMaxD[0])
   to->gainMapMaxN[2] = to->gainMapMaxN[1] = to->gainMapMaxN[0];
   to->gainMapMaxD[2] = to->gainMapMaxD[1] = to->gainMapMaxD[0];
 
-  floatToUnsignedFraction(from->min_content_boost, &to->gainMapMinN[0], &to->gainMapMinD[0]);
+  CONVERT_FLT_TO_SIGNED_FRACTION(log2(from->min_content_boost), &to->gainMapMinN[0],
+                                 &to->gainMapMinD[0]);
   to->gainMapMinN[2] = to->gainMapMinN[1] = to->gainMapMinN[0];
   to->gainMapMinD[2] = to->gainMapMinD[1] = to->gainMapMinD[0];
 
-  floatToUnsignedFraction(from->gamma, &to->gainMapGammaN[0], &to->gainMapGammaD[0]);
+  CONVERT_FLT_TO_UNSIGNED_FRACTION(from->gamma, &to->gainMapGammaN[0], &to->gainMapGammaD[0]);
   to->gainMapGammaN[2] = to->gainMapGammaN[1] = to->gainMapGammaN[0];
   to->gainMapGammaD[2] = to->gainMapGammaD[1] = to->gainMapGammaD[0];
 
-  floatToUnsignedFraction(from->offset_sdr, &to->baseOffsetN[0], &to->baseOffsetD[0]);
+  CONVERT_FLT_TO_SIGNED_FRACTION(from->offset_sdr, &to->baseOffsetN[0], &to->baseOffsetD[0]);
   to->baseOffsetN[2] = to->baseOffsetN[1] = to->baseOffsetN[0];
   to->baseOffsetD[2] = to->baseOffsetD[1] = to->baseOffsetD[0];
 
-  floatToUnsignedFraction(from->offset_hdr, &to->alternateOffsetN[0], &to->alternateOffsetD[0]);
+  CONVERT_FLT_TO_SIGNED_FRACTION(from->offset_hdr, &to->alternateOffsetN[0],
+                                 &to->alternateOffsetD[0]);
   to->alternateOffsetN[2] = to->alternateOffsetN[1] = to->alternateOffsetN[0];
   to->alternateOffsetD[2] = to->alternateOffsetD[1] = to->alternateOffsetD[0];
 
-  floatToUnsignedFraction(from->hdr_capacity_min, &to->baseHdrHeadroomN, &to->baseHdrHeadroomD);
+  CONVERT_FLT_TO_UNSIGNED_FRACTION(log2(from->hdr_capacity_min), &to->baseHdrHeadroomN,
+                                   &to->baseHdrHeadroomD);
 
-  floatToUnsignedFraction(from->hdr_capacity_max, &to->alternateHdrHeadroomN,
-                          &to->alternateHdrHeadroomD);
+  CONVERT_FLT_TO_UNSIGNED_FRACTION(log2(from->hdr_capacity_max), &to->alternateHdrHeadroomN,
+                                   &to->alternateHdrHeadroomD);
 
   return g_no_error;
 }
diff --git a/lib/src/gpu/applygainmap_gl.cpp b/lib/src/gpu/applygainmap_gl.cpp
index 7657796..100d5fd 100644
--- a/lib/src/gpu/applygainmap_gl.cpp
+++ b/lib/src/gpu/applygainmap_gl.cpp
@@ -136,13 +136,15 @@ static const std::string applyGainMapShader = R"__SHADER__(
   uniform float logMinBoost;
   uniform float logMaxBoost;
   uniform float weight;
-  uniform float displayBoost;
+  uniform float offsetSdr;
+  uniform float offsetHdr;
+  uniform float normalize;
 
   float applyGainMapSample(const float channel, float gain) {
     gain = pow(gain, 1.0f / gamma);
     float logBoost = logMinBoost * (1.0f - gain) + logMaxBoost * gain;
     logBoost = exp2(logBoost * weight);
-    return channel * logBoost / displayBoost;
+    return ((channel + offsetSdr) * logBoost - offsetHdr) / normalize;
   }
 
   vec3 applyGain(const vec3 color, const vec3 gain) {
@@ -182,6 +184,21 @@ static const std::string pqOETFShader = R"__SHADER__(
   }
 )__SHADER__";
 
+static const std::string hlgInverseOOTFShader = R"__SHADER__(
+  float InverseOOTF(const float linear) {
+    const float kOotfGamma = 1.2f;
+    return pow(linear, 1.0f / kOotfGamma);
+  }
+
+  vec3 InverseOOTF(const vec3 linear) {
+    return vec3(InverseOOTF(linear.r), InverseOOTF(linear.g), InverseOOTF(linear.b));
+  }
+)__SHADER__";
+
+static const std::string IdentityInverseOOTFShader = R"__SHADER__(
+  vec3 InverseOOTF(const vec3 linear) { return linear; }
+)__SHADER__";
+
 std::string getApplyGainMapFragmentShader(uhdr_img_fmt sdr_fmt, uhdr_img_fmt gm_fmt,
                                           uhdr_color_transfer output_ct) {
   std::string shader_code = R"__SHADER__(#version 300 es
@@ -205,10 +222,13 @@ std::string getApplyGainMapFragmentShader(uhdr_img_fmt sdr_fmt, uhdr_img_fmt gm_
                                                          : getGainMapSampleMultiChannel);
   shader_code.append(applyGainMapShader);
   if (output_ct == UHDR_CT_LINEAR) {
+    shader_code.append(IdentityInverseOOTFShader);
     shader_code.append(linearOETFShader);
   } else if (output_ct == UHDR_CT_HLG) {
+    shader_code.append(hlgInverseOOTFShader);
     shader_code.append(hlgOETFShader);
   } else if (output_ct == UHDR_CT_PQ) {
+    shader_code.append(IdentityInverseOOTFShader);
     shader_code.append(pqOETFShader);
   }
 
@@ -219,6 +239,7 @@ std::string getApplyGainMapFragmentShader(uhdr_img_fmt sdr_fmt, uhdr_img_fmt gm_
       vec3 rgb_sdr = sRGBEOTF(rgb_gamma_sdr);
       vec3 gain = sampleMap(gainMapTexture);
       vec3 rgb_hdr = applyGain(rgb_sdr, gain);
+      rgb_hdr = InverseOOTF(rgb_hdr);
       vec3 rgb_gamma_hdr = OETF(rgb_hdr);
       FragColor = vec4(rgb_gamma_hdr, 1.0);
     }
@@ -298,15 +319,32 @@ uhdr_error_info_t applyGainMapGLES(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_
   GLint logMinBoostLocation = glGetUniformLocation(shaderProgram, "logMinBoost");
   GLint logMaxBoostLocation = glGetUniformLocation(shaderProgram, "logMaxBoost");
   GLint weightLocation = glGetUniformLocation(shaderProgram, "weight");
-  GLint displayBoostLocation = glGetUniformLocation(shaderProgram, "displayBoost");
+  GLint offsetSdrLocation = glGetUniformLocation(shaderProgram, "offsetSdr");
+  GLint offsetHdrLocation = glGetUniformLocation(shaderProgram, "offsetHdr");
+  GLint normalizeLocation = glGetUniformLocation(shaderProgram, "normalize");
 
   glUniform1i(pWidthLocation, sdr_intent->w);
   glUniform1i(pHeightLocation, sdr_intent->h);
   glUniform1f(gammaLocation, gainmap_metadata->gamma);
   glUniform1f(logMinBoostLocation, log2(gainmap_metadata->min_content_boost));
   glUniform1f(logMaxBoostLocation, log2(gainmap_metadata->max_content_boost));
-  glUniform1f(weightLocation, display_boost / gainmap_metadata->hdr_capacity_max);
-  glUniform1f(displayBoostLocation, display_boost);
+  glUniform1f(offsetSdrLocation, gainmap_metadata->offset_sdr);
+  glUniform1f(offsetHdrLocation, gainmap_metadata->offset_hdr);
+  float gainmap_weight;
+  if (display_boost != gainmap_metadata->hdr_capacity_max) {
+    gainmap_weight =
+        (log2(display_boost) - log2(gainmap_metadata->hdr_capacity_min)) /
+        (log2(gainmap_metadata->hdr_capacity_max) - log2(gainmap_metadata->hdr_capacity_min));
+    // avoid extrapolating the gain map to fill the displayable range
+    gainmap_weight = CLIP3(0.0f, gainmap_weight, 1.0f);
+  } else {
+    gainmap_weight = 1.0f;
+  }
+  glUniform1f(weightLocation, gainmap_weight);
+  float normalize = 1.0f;
+  if (output_ct == UHDR_CT_HLG) normalize = kHlgMaxNits / kSdrWhiteNits;
+  else if (output_ct == UHDR_CT_PQ) normalize = kPqMaxNits / kSdrWhiteNits;
+  glUniform1f(normalizeLocation, normalize);
 
   glActiveTexture(GL_TEXTURE0);
   glBindTexture(GL_TEXTURE_2D, yuvTexture);
diff --git a/lib/src/gpu/editorhelper_gl.cpp b/lib/src/gpu/editorhelper_gl.cpp
index 3726a6d..c734c36 100644
--- a/lib/src/gpu/editorhelper_gl.cpp
+++ b/lib/src/gpu/editorhelper_gl.cpp
@@ -269,15 +269,14 @@ std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate_gles(ultrahdr::uhdr_rotate_ef
   return dst;
 }
 
-void apply_crop_gles(uhdr_raw_image_t* src, int left, int top, int wd, int ht,
-                     uhdr_opengl_ctxt* gl_ctxt, GLuint* srcTexture) {
+std::unique_ptr<uhdr_raw_image_ext_t> apply_crop_gles(uhdr_raw_image_t* src, int left, int top,
+                                                      int wd, int ht, uhdr_opengl_ctxt* gl_ctxt,
+                                                      GLuint* srcTexture) {
+  std::unique_ptr<uhdr_raw_image_ext_t> dst =
+      std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, wd, ht, 1);
   GLuint dstTexture = 0;
   GLuint frameBuffer = 0;
-#define RETURN_IF_ERR()                                    \
-  if (gl_ctxt->mErrorStatus.error_code != UHDR_CODEC_OK) { \
-    release_resources(&dstTexture, &frameBuffer);          \
-    return;                                                \
-  }
+
   if (gl_ctxt->mShaderProgram[UHDR_CROP] == 0) {
     gl_ctxt->mShaderProgram[UHDR_CROP] =
         gl_ctxt->create_shader_program(vertex_shader.c_str(), crop_fragmentSource.c_str());
@@ -285,7 +284,7 @@ void apply_crop_gles(uhdr_raw_image_t* src, int left, int top, int wd, int ht,
   dstTexture = gl_ctxt->create_texture(src->fmt, wd, ht, NULL);
   frameBuffer = gl_ctxt->setup_framebuffer(dstTexture);
 
-  glViewport(0, 0, wd, ht);
+  glViewport(0, 0, dst->w, dst->h);
   glUseProgram(gl_ctxt->mShaderProgram[UHDR_CROP]);
 
   float normCropX = (float)left / src->w;
@@ -296,22 +295,19 @@ void apply_crop_gles(uhdr_raw_image_t* src, int left, int top, int wd, int ht,
   glActiveTexture(GL_TEXTURE0);
   glBindTexture(GL_TEXTURE_2D, *srcTexture);
   glUniform1i(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_CROP], "srcTexture"), 0);
-  glUniform2f(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_CROP], "cropStart"),
-              normCropX, normCropY);
-  glUniform2f(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_CROP], "cropSize"),
-              normCropW, normCropH);
+  glUniform2f(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_CROP], "cropStart"), normCropX,
+              normCropY);
+  glUniform2f(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_CROP], "cropSize"), normCropW,
+              normCropH);
   gl_ctxt->check_gl_errors("binding values to uniform");
-  RETURN_IF_ERR()
+  RET_IF_ERR()
 
   glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, 0);
-  RETURN_IF_ERR()
+  RET_IF_ERR()
 
   std::swap(*srcTexture, dstTexture);
-  src->w = wd;
-  src->h = ht;
-  src->stride[UHDR_PLANE_PACKED] = wd;
   release_resources(&dstTexture, &frameBuffer);
-#undef RETURN_IF_ERR
+  return dst;
 }
 
 std::unique_ptr<uhdr_raw_image_ext_t> apply_resize_gles(uhdr_raw_image_t* src, int dst_w, int dst_h,
diff --git a/lib/src/jpegdecoderhelper.cpp b/lib/src/jpegdecoderhelper.cpp
index 7b107a1..76c4c78 100644
--- a/lib/src/jpegdecoderhelper.cpp
+++ b/lib/src/jpegdecoderhelper.cpp
@@ -65,7 +65,7 @@ const int kMaxHeight = UHDR_MAX_DIMENSION;
 
 /*!\brief module for managing input */
 struct jpeg_source_mgr_impl : jpeg_source_mgr {
-  jpeg_source_mgr_impl(const uint8_t* ptr, int len);
+  jpeg_source_mgr_impl(const uint8_t* ptr, size_t len);
   ~jpeg_source_mgr_impl() = default;
 
   const uint8_t* mBufferPtr;
@@ -101,7 +101,7 @@ static void jpegr_skip_input_data(j_decompress_ptr cinfo, long num_bytes) {
 
 static void jpegr_term_source(j_decompress_ptr /*cinfo*/) {}
 
-jpeg_source_mgr_impl::jpeg_source_mgr_impl(const uint8_t* ptr, int len)
+jpeg_source_mgr_impl::jpeg_source_mgr_impl(const uint8_t* ptr, size_t len)
     : mBufferPtr(ptr), mBufferLength(len) {
   init_source = jpegr_init_source;
   fill_input_buffer = jpegr_fill_input_buffer;
@@ -126,8 +126,8 @@ static void jpeg_extract_marker_payload(const j_decompress_ptr cinfo, const uint
                                         const uint8_t* marker_fourcc_code,
                                         const uint32_t fourcc_length,
                                         std::vector<JOCTET>& destination,
-                                        int& markerPayloadOffsetRelativeToSourceBuffer) {
-  size_t pos = 2; /* position after reading SOI marker (0xffd8) */
+                                        long& markerPayloadOffsetRelativeToSourceBuffer) {
+  unsigned int pos = 2; /* position after reading SOI marker (0xffd8) */
   markerPayloadOffsetRelativeToSourceBuffer = -1;
 
   for (jpeg_marker_struct* marker = cinfo->marker_list; marker; marker = marker->next) {
@@ -172,7 +172,7 @@ static uhdr_img_fmt_t getOutputSamplingFormat(const j_decompress_ptr cinfo) {
   return UHDR_IMG_FMT_UNSPECIFIED;
 }
 
-uhdr_error_info_t JpegDecoderHelper::decompressImage(const void* image, int length,
+uhdr_error_info_t JpegDecoderHelper::decompressImage(const void* image, size_t length,
                                                      decode_mode_t mode) {
   if (image == nullptr) {
     uhdr_error_info_t status;
@@ -185,7 +185,7 @@ uhdr_error_info_t JpegDecoderHelper::decompressImage(const void* image, int leng
     uhdr_error_info_t status;
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail, "received bad compressed image size %d", length);
+    snprintf(status.detail, sizeof status.detail, "received bad compressed image size %zd", length);
     return status;
   }
 
@@ -209,7 +209,7 @@ uhdr_error_info_t JpegDecoderHelper::decompressImage(const void* image, int leng
   return decode(image, length, mode);
 }
 
-uhdr_error_info_t JpegDecoderHelper::decode(const void* image, int length, decode_mode_t mode) {
+uhdr_error_info_t JpegDecoderHelper::decode(const void* image, size_t length, decode_mode_t mode) {
   jpeg_source_mgr_impl mgr(static_cast<const uint8_t*>(image), length);
   jpeg_decompress_struct cinfo;
   jpeg_error_mgr_impl myerr;
@@ -234,7 +234,7 @@ uhdr_error_info_t JpegDecoderHelper::decode(const void* image, int length, decod
       jpeg_destroy_decompress(&cinfo);
       return status;
     }
-    int payloadOffset = -1;
+    long payloadOffset = -1;
     jpeg_extract_marker_payload(&cinfo, kAPP1Marker, kXmpNameSpace,
                                 sizeof kXmpNameSpace / sizeof kXmpNameSpace[0], mXMPBuffer,
                                 payloadOffset);
@@ -373,10 +373,10 @@ uhdr_error_info_t JpegDecoderHelper::decode(const void* image, int length, decod
         mPlaneVStride[i] = 0;
       }
 #ifdef JCS_ALPHA_EXTENSIONS
-      mResultBuffer.resize(mPlaneHStride[0] * mPlaneVStride[0] * 4);
+      mResultBuffer.resize((size_t)mPlaneHStride[0] * mPlaneVStride[0] * 4);
       cinfo.out_color_space = JCS_EXT_RGBA;
 #else
-      mResultBuffer.resize(mPlaneHStride[0] * mPlaneVStride[0] * 3);
+      mResultBuffer.resize((size_t)mPlaneHStride[0] * mPlaneVStride[0] * 3);
       cinfo.out_color_space = JCS_RGB;
 #endif
     } else if (DECODE_TO_YCBCR_CS == mode) {
@@ -389,11 +389,11 @@ uhdr_error_info_t JpegDecoderHelper::decode(const void* image, int length, decod
         jpeg_destroy_decompress(&cinfo);
         return status;
       }
-      int size = 0;
+      size_t size = 0;
       for (int i = 0; i < cinfo.num_components; i++) {
         mPlaneHStride[i] = ALIGNM(mPlaneWidth[i], cinfo.max_h_samp_factor);
         mPlaneVStride[i] = ALIGNM(mPlaneHeight[i], cinfo.max_v_samp_factor);
-        size += mPlaneHStride[i] * mPlaneVStride[i];
+        size += (size_t)mPlaneHStride[i] * mPlaneVStride[i];
       }
       mResultBuffer.resize(size);
       cinfo.out_color_space = cinfo.jpeg_color_space;
@@ -463,9 +463,9 @@ uhdr_error_info_t JpegDecoderHelper::decodeToCSRGB(jpeg_decompress_struct* cinfo
       return status;
     }
 #ifdef JCS_ALPHA_EXTENSIONS
-    out += mPlaneHStride[0] * 4;
+    out += (size_t)mPlaneHStride[0] * 4;
 #else
-    out += mPlaneHStride[0] * 3;
+    out += (size_t)mPlaneHStride[0] * 3;
 #endif
   }
   return g_no_error;
@@ -508,7 +508,7 @@ uhdr_error_info_t JpegDecoderHelper::decodeToCSYCbCr(jpeg_decompress_struct* cin
         JDIMENSION scanline = mcu_scanline_start[i] + j;
 
         if (scanline < mPlaneVStride[i]) {
-          mcuRows[i][j] = planes[i] + scanline * mPlaneHStride[i];
+          mcuRows[i][j] = planes[i] + (size_t)scanline * mPlaneHStride[i];
         } else {
           mcuRows[i][j] = mPlanesMCURow[i].get();
         }
@@ -553,7 +553,7 @@ uhdr_raw_image_t JpegDecoderHelper::getDecompressedImage() {
   for (int i = 0; i < 3; i++) {
     img.planes[i] = data;
     img.stride[i] = mPlaneHStride[i];
-    data += mPlaneHStride[i] * mPlaneVStride[i];
+    data += (size_t)mPlaneHStride[i] * mPlaneVStride[i];
   }
 
   return img;
diff --git a/lib/src/jpegencoderhelper.cpp b/lib/src/jpegencoderhelper.cpp
index dc2e94d..2bbec62 100644
--- a/lib/src/jpegencoderhelper.cpp
+++ b/lib/src/jpegencoderhelper.cpp
@@ -72,7 +72,7 @@ static boolean emptyOutputBuffer(j_compress_ptr cinfo) {
   buffer.resize(oldsize + dest->kBlockSize);
   dest->next_output_byte = &buffer[oldsize];
   dest->free_in_buffer = dest->kBlockSize;
-  return true;
+  return TRUE;
 }
 
 /*!\brief  called by jpeg_finish_compress() to flush out all the remaining encoded data. client
@@ -105,21 +105,20 @@ static void outputErrorMessage(j_common_ptr cinfo) {
 }
 
 uhdr_error_info_t JpegEncoderHelper::compressImage(const uhdr_raw_image_t* img, const int qfactor,
-                                                   const void* iccBuffer,
-                                                   const unsigned int iccSize) {
+                                                   const void* iccBuffer, const size_t iccSize) {
   const uint8_t* planes[3]{reinterpret_cast<uint8_t*>(img->planes[UHDR_PLANE_Y]),
                            reinterpret_cast<uint8_t*>(img->planes[UHDR_PLANE_U]),
                            reinterpret_cast<uint8_t*>(img->planes[UHDR_PLANE_V])};
-  const size_t strides[3]{img->stride[UHDR_PLANE_Y], img->stride[UHDR_PLANE_U],
-                          img->stride[UHDR_PLANE_V]};
+  const unsigned int strides[3]{img->stride[UHDR_PLANE_Y], img->stride[UHDR_PLANE_U],
+                                img->stride[UHDR_PLANE_V]};
   return compressImage(planes, strides, img->w, img->h, img->fmt, qfactor, iccBuffer, iccSize);
 }
 
 uhdr_error_info_t JpegEncoderHelper::compressImage(const uint8_t* planes[3],
-                                                   const size_t strides[3], const int width,
+                                                   const unsigned int strides[3], const int width,
                                                    const int height, const uhdr_img_fmt_t format,
                                                    const int qfactor, const void* iccBuffer,
-                                                   const unsigned int iccSize) {
+                                                   const size_t iccSize) {
   return encode(planes, strides, width, height, format, qfactor, iccBuffer, iccSize);
 }
 
@@ -135,10 +134,10 @@ uhdr_compressed_image_t JpegEncoderHelper::getCompressedImage() {
   return img;
 }
 
-uhdr_error_info_t JpegEncoderHelper::encode(const uint8_t* planes[3], const size_t strides[3],
+uhdr_error_info_t JpegEncoderHelper::encode(const uint8_t* planes[3], const unsigned int strides[3],
                                             const int width, const int height,
                                             const uhdr_img_fmt_t format, const int qfactor,
-                                            const void* iccBuffer, const unsigned int iccSize) {
+                                            const void* iccBuffer, const size_t iccSize) {
   jpeg_compress_struct cinfo;
   jpeg_error_mgr_impl myerr;
   uhdr_error_info_t status = g_no_error;
@@ -252,7 +251,7 @@ uhdr_error_info_t JpegEncoderHelper::encode(const uint8_t* planes[3], const size
 
 uhdr_error_info_t JpegEncoderHelper::compressYCbCr(jpeg_compress_struct* cinfo,
                                                    const uint8_t* planes[3],
-                                                   const size_t strides[3]) {
+                                                   const unsigned int strides[3]) {
   JSAMPROW mcuRows[kMaxNumComponents][2 * DCTSIZE];
   JSAMPROW mcuRowsTmp[kMaxNumComponents][2 * DCTSIZE];
   size_t alignedPlaneWidth[kMaxNumComponents]{};
@@ -292,7 +291,7 @@ uhdr_error_info_t JpegEncoderHelper::compressYCbCr(jpeg_compress_struct* cinfo,
         JDIMENSION scanline = mcu_scanline_start[i] + j;
 
         if (scanline < mPlaneHeight[i]) {
-          mcuRows[i][j] = const_cast<uint8_t*>(planes[i] + scanline * strides[i]);
+          mcuRows[i][j] = const_cast<uint8_t*>(planes[i] + (size_t)scanline * strides[i]);
           if (strides[i] < alignedPlaneWidth[i]) {
             memcpy(mcuRowsTmp[i][j], mcuRows[i][j], mPlaneWidth[i]);
           }
diff --git a/lib/src/jpegr.cpp b/lib/src/jpegr.cpp
index 90053f2..1f83b34 100644
--- a/lib/src/jpegr.cpp
+++ b/lib/src/jpegr.cpp
@@ -27,6 +27,7 @@
 #include <mutex>
 #include <thread>
 
+#include "ultrahdr/editorhelper.h"
 #include "ultrahdr/gainmapmetadata.h"
 #include "ultrahdr/ultrahdrcommon.h"
 #include "ultrahdr/jpegr.h"
@@ -63,19 +64,19 @@ static_assert(kWriteXmpMetadata || kWriteIso21496_1Metadata,
 
 class JobQueue {
  public:
-  bool dequeueJob(size_t& rowStart, size_t& rowEnd);
-  void enqueueJob(size_t rowStart, size_t rowEnd);
+  bool dequeueJob(unsigned int& rowStart, unsigned int& rowEnd);
+  void enqueueJob(unsigned int rowStart, unsigned int rowEnd);
   void markQueueForEnd();
   void reset();
 
  private:
   bool mQueuedAllJobs = false;
-  std::deque<std::tuple<size_t, size_t>> mJobs;
+  std::deque<std::tuple<unsigned int, unsigned int>> mJobs;
   std::mutex mMutex;
   std::condition_variable mCv;
 };
 
-bool JobQueue::dequeueJob(size_t& rowStart, size_t& rowEnd) {
+bool JobQueue::dequeueJob(unsigned int& rowStart, unsigned int& rowEnd) {
   std::unique_lock<std::mutex> lock{mMutex};
   while (true) {
     if (mJobs.empty()) {
@@ -95,7 +96,7 @@ bool JobQueue::dequeueJob(size_t& rowStart, size_t& rowEnd) {
   return false;
 }
 
-void JobQueue::enqueueJob(size_t rowStart, size_t rowEnd) {
+void JobQueue::enqueueJob(unsigned int rowStart, unsigned int rowEnd) {
   std::unique_lock<std::mutex> lock{mMutex};
   mJobs.push_back(std::make_tuple(rowStart, rowEnd));
   lock.unlock();
@@ -126,28 +127,11 @@ class AlogMessageWriter : public MessageWriter {
   }
 };
 
-int GetCPUCoreCount() {
-  int cpuCoreCount = 1;
-
-#if defined(_WIN32)
-  SYSTEM_INFO system_info;
-  ZeroMemory(&system_info, sizeof(system_info));
-  GetSystemInfo(&system_info);
-  cpuCoreCount = (size_t)system_info.dwNumberOfProcessors;
-#elif defined(_SC_NPROCESSORS_ONLN)
-  cpuCoreCount = sysconf(_SC_NPROCESSORS_ONLN);
-#elif defined(_SC_NPROCESSORS_CONF)
-  cpuCoreCount = sysconf(_SC_NPROCESSORS_CONF);
-#else
-#error platform-specific implementation for GetCPUCoreCount() missing.
-#endif
-  if (cpuCoreCount <= 0) cpuCoreCount = 1;
-  return cpuCoreCount;
-}
+unsigned int GetCPUCoreCount() { return (std::max)(1u, std::thread::hardware_concurrency()); }
 
-JpegR::JpegR(void* uhdrGLESCtxt, size_t mapDimensionScaleFactor, int mapCompressQuality,
+JpegR::JpegR(void* uhdrGLESCtxt, int mapDimensionScaleFactor, int mapCompressQuality,
              bool useMultiChannelGainMap, float gamma, uhdr_enc_preset_t preset,
-             float minContentBoost, float maxContentBoost) {
+             float minContentBoost, float maxContentBoost, float targetDispPeakBrightness) {
   mUhdrGLESCtxt = uhdrGLESCtxt;
   mMapDimensionScaleFactor = mapDimensionScaleFactor;
   mMapCompressQuality = mapCompressQuality;
@@ -156,6 +140,7 @@ JpegR::JpegR(void* uhdrGLESCtxt, size_t mapDimensionScaleFactor, int mapCompress
   mEncPreset = preset;
   mMinContentBoost = minContentBoost;
   mMaxContentBoost = maxContentBoost;
+  mTargetDispPeakBrightness = targetDispPeakBrightness;
 }
 
 /*
@@ -189,7 +174,8 @@ uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_compress
     sdr_intent_fmt = UHDR_IMG_FMT_12bppYCbCr420;
   } else if (hdr_intent->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
     sdr_intent_fmt = UHDR_IMG_FMT_24bppYCbCr444;
-  } else if (hdr_intent->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
+  } else if (hdr_intent->fmt == UHDR_IMG_FMT_32bppRGBA1010102 ||
+             hdr_intent->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
     sdr_intent_fmt = UHDR_IMG_FMT_32bppRGBA8888;
   } else {
     uhdr_error_info_t status;
@@ -228,7 +214,11 @@ uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_compress
   std::unique_ptr<uhdr_raw_image_ext_t> sdr_intent_yuv_ext;
   uhdr_raw_image_t* sdr_intent_yuv = sdr_intent.get();
   if (isPixelFormatRgb(sdr_intent->fmt)) {
+#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
+    sdr_intent_yuv_ext = convert_raw_input_to_ycbcr_neon(sdr_intent.get());
+#else
     sdr_intent_yuv_ext = convert_raw_input_to_ycbcr(sdr_intent.get());
+#endif
     sdr_intent_yuv = sdr_intent_yuv_ext.get();
   }
 
@@ -263,7 +253,11 @@ uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_raw_imag
   std::unique_ptr<uhdr_raw_image_ext_t> sdr_intent_yuv_ext;
   uhdr_raw_image_t* sdr_intent_yuv = sdr_intent;
   if (isPixelFormatRgb(sdr_intent->fmt)) {
+#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
+    sdr_intent_yuv_ext = convert_raw_input_to_ycbcr_neon(sdr_intent);
+#else
     sdr_intent_yuv_ext = convert_raw_input_to_ycbcr(sdr_intent);
+#endif
     sdr_intent_yuv = sdr_intent_yuv_ext.get();
   }
 
@@ -524,13 +518,14 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
   }
   if (hdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCrP010 &&
       hdr_intent->fmt != UHDR_IMG_FMT_30bppYCbCr444 &&
-      hdr_intent->fmt != UHDR_IMG_FMT_32bppRGBA1010102) {
+      hdr_intent->fmt != UHDR_IMG_FMT_32bppRGBA1010102 &&
+      hdr_intent->fmt != UHDR_IMG_FMT_64bppRGBAHalfFloat) {
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
              "generate gainmap method expects hdr intent color format to be one of "
              "{UHDR_IMG_FMT_24bppYCbCrP010, UHDR_IMG_FMT_30bppYCbCr444, "
-             "UHDR_IMG_FMT_32bppRGBA1010102}. Received %d",
+             "UHDR_IMG_FMT_32bppRGBA1010102, UHDR_IMG_FMT_64bppRGBAHalfFloat}. Received %d",
              hdr_intent->fmt);
     return status;
   }
@@ -555,16 +550,37 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     return status;
   }
 
-  float hdr_white_nits = getMaxDisplayMasteringLuminance(hdr_intent->ct);
-  if (hdr_white_nits == -1.0f) {
+  LuminanceFn hdrLuminanceFn = getLuminanceFn(hdr_intent->cg);
+  if (hdrLuminanceFn == nullptr) {
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
-             "Did not receive valid MDML for display with transfer characteristics %d",
+             "No implementation available for calculating luminance for color gamut %d",
+             hdr_intent->cg);
+    return status;
+  }
+
+  SceneToDisplayLuminanceFn hdrOotfFn = getOotfFn(hdr_intent->ct);
+  if (hdrOotfFn == nullptr) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for calculating Ootf for color transfer %d",
              hdr_intent->ct);
     return status;
   }
 
+  float hdr_white_nits = getReferenceDisplayPeakLuminanceInNits(hdr_intent->ct);
+  if (hdr_white_nits == -1.0f) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received invalid peak brightness %f nits for hdr reference display with color "
+             "transfer %d ",
+             hdr_white_nits, hdr_intent->ct);
+    return status;
+  }
+
   ColorTransformFn hdrGamutConversionFn = getGamutConversionFn(sdr_intent->cg, hdr_intent->cg);
   if (hdrGamutConversionFn == nullptr) {
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
@@ -595,7 +611,7 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     return status;
   }
 
-  ColorCalculationFn luminanceFn = getLuminanceFn(sdr_intent->cg);
+  LuminanceFn luminanceFn = getLuminanceFn(sdr_intent->cg);
   if (luminanceFn == nullptr) {
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
     status.has_detail = 1;
@@ -627,17 +643,17 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     sdrYuvToRgbFn = p3YuvToRgb;
   }
 
-  size_t image_width = sdr_intent->w;
-  size_t image_height = sdr_intent->h;
-  size_t map_width = image_width / mMapDimensionScaleFactor;
-  size_t map_height = image_height / mMapDimensionScaleFactor;
+  unsigned int image_width = sdr_intent->w;
+  unsigned int image_height = sdr_intent->h;
+  unsigned int map_width = image_width / mMapDimensionScaleFactor;
+  unsigned int map_height = image_height / mMapDimensionScaleFactor;
   if (map_width == 0 || map_height == 0) {
     int scaleFactor = (std::min)(image_width, image_height);
     scaleFactor = (scaleFactor >= DCTSIZE) ? (scaleFactor / DCTSIZE) : 1;
     ALOGW(
         "configured gainmap scale factor is resulting in gainmap width and/or height to be zero, "
-        "image width %d, image height %d, scale factor %d. Modifying gainmap scale factor to %d ",
-        (int)image_width, (int)image_height, (int)mMapDimensionScaleFactor, scaleFactor);
+        "image width %u, image height %u, scale factor %d. Modifying gainmap scale factor to %d ",
+        image_width, image_height, mMapDimensionScaleFactor, scaleFactor);
     setMapDimensionScaleFactor(scaleFactor);
     map_width = image_width / mMapDimensionScaleFactor;
     map_height = image_height / mMapDimensionScaleFactor;
@@ -649,31 +665,41 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
   uhdr_raw_image_ext_t* dest = gainmap_img.get();
 
   auto generateGainMapOnePass = [this, sdr_intent, hdr_intent, gainmap_metadata, dest, map_height,
-                                 hdrInvOetf, hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn,
-                                 hdrYuvToRgbFn, sdr_sample_pixel_fn, hdr_sample_pixel_fn,
-                                 hdr_white_nits, use_luminance]() -> void {
+                                 hdrInvOetf, hdrLuminanceFn, hdrOotfFn, hdrGamutConversionFn,
+                                 luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn, sdr_sample_pixel_fn,
+                                 hdr_sample_pixel_fn, hdr_white_nits, use_luminance]() -> void {
     gainmap_metadata->max_content_boost = hdr_white_nits / kSdrWhiteNits;
     gainmap_metadata->min_content_boost = 1.0f;
     gainmap_metadata->gamma = mGamma;
     gainmap_metadata->offset_sdr = 0.0f;
     gainmap_metadata->offset_hdr = 0.0f;
     gainmap_metadata->hdr_capacity_min = 1.0f;
-    gainmap_metadata->hdr_capacity_max = gainmap_metadata->max_content_boost;
+    if (this->mTargetDispPeakBrightness != -1.0f) {
+      gainmap_metadata->hdr_capacity_max = this->mTargetDispPeakBrightness / kSdrWhiteNits;
+    } else {
+      gainmap_metadata->hdr_capacity_max = gainmap_metadata->max_content_boost;
+    }
 
     float log2MinBoost = log2(gainmap_metadata->min_content_boost);
     float log2MaxBoost = log2(gainmap_metadata->max_content_boost);
 
-    const int threads = (std::min)(GetCPUCoreCount(), 4);
+    const int threads = (std::min)(GetCPUCoreCount(), 4u);
     const int jobSizeInRows = 1;
-    size_t rowStep = threads == 1 ? map_height : jobSizeInRows;
+    unsigned int rowStep = threads == 1 ? map_height : jobSizeInRows;
     JobQueue jobQueue;
     std::function<void()> generateMap =
-        [this, sdr_intent, hdr_intent, gainmap_metadata, dest, hdrInvOetf, hdrGamutConversionFn,
-         luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn, sdr_sample_pixel_fn, hdr_sample_pixel_fn,
-         hdr_white_nits, log2MinBoost, log2MaxBoost, use_luminance, &jobQueue]() -> void {
-      size_t rowStart, rowEnd;
+        [this, sdr_intent, hdr_intent, gainmap_metadata, dest, hdrInvOetf, hdrLuminanceFn,
+         hdrOotfFn, hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn,
+         sdr_sample_pixel_fn, hdr_sample_pixel_fn, hdr_white_nits, log2MinBoost, log2MaxBoost,
+         use_luminance, &jobQueue]() -> void {
+      unsigned int rowStart, rowEnd;
       const bool isHdrIntentRgb = isPixelFormatRgb(hdr_intent->fmt);
       const bool isSdrIntentRgb = isPixelFormatRgb(sdr_intent->fmt);
+      const float hdrSampleToNitsFactor =
+          hdr_intent->ct == UHDR_CT_LINEAR ? kSdrWhiteNits : hdr_white_nits;
+      ColorTransformFn clampPixel = hdr_intent->ct == UHDR_CT_LINEAR
+                                        ? static_cast<ColorTransformFn>(clampPixelFloatLinear)
+                                        : static_cast<ColorTransformFn>(clampPixelFloat);
       while (jobQueue.dequeueJob(rowStart, rowEnd)) {
         for (size_t y = rowStart; y < rowEnd; ++y) {
           for (size_t x = 0; x < dest->w; ++x) {
@@ -702,11 +728,13 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
               hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
             }
             Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
+            hdr_rgb = hdrOotfFn(hdr_rgb, hdrLuminanceFn);
             hdr_rgb = hdrGamutConversionFn(hdr_rgb);
+            hdr_rgb = clampPixel(hdr_rgb);
 
             if (mUseMultiChannelGainMap) {
               Color sdr_rgb_nits = sdr_rgb * kSdrWhiteNits;
-              Color hdr_rgb_nits = hdr_rgb * hdr_white_nits;
+              Color hdr_rgb_nits = hdr_rgb * hdrSampleToNitsFactor;
               size_t pixel_idx = (x + y * dest->stride[UHDR_PLANE_PACKED]) * 3;
 
               reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] = encodeGain(
@@ -722,10 +750,10 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
               float hdr_y_nits;
               if (use_luminance) {
                 sdr_y_nits = luminanceFn(sdr_rgb) * kSdrWhiteNits;
-                hdr_y_nits = luminanceFn(hdr_rgb) * hdr_white_nits;
+                hdr_y_nits = luminanceFn(hdr_rgb) * hdrSampleToNitsFactor;
               } else {
                 sdr_y_nits = fmax(sdr_rgb.r, fmax(sdr_rgb.g, sdr_rgb.b)) * kSdrWhiteNits;
-                hdr_y_nits = fmax(hdr_rgb.r, fmax(hdr_rgb.g, hdr_rgb.b)) * hdr_white_nits;
+                hdr_y_nits = fmax(hdr_rgb.r, fmax(hdr_rgb.g, hdr_rgb.b)) * hdrSampleToNitsFactor;
               }
 
               size_t pixel_idx = x + y * dest->stride[UHDR_PLANE_Y];
@@ -744,8 +772,8 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
       workers.push_back(std::thread(generateMap));
     }
 
-    for (size_t rowStart = 0; rowStart < map_height;) {
-      size_t rowEnd = (std::min)(rowStart + rowStep, map_height);
+    for (unsigned int rowStart = 0; rowStart < map_height;) {
+      unsigned int rowEnd = (std::min)(rowStart + rowStep, map_height);
       jobQueue.enqueueJob(rowStart, rowEnd);
       rowStart = rowEnd;
     }
@@ -754,29 +782,34 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
   };
 
-  auto generateGainMapTwoPass = [this, sdr_intent, hdr_intent, gainmap_metadata, dest, map_width,
-                                 map_height, hdrInvOetf, hdrGamutConversionFn, luminanceFn,
-                                 sdrYuvToRgbFn, hdrYuvToRgbFn, sdr_sample_pixel_fn,
-                                 hdr_sample_pixel_fn, hdr_white_nits, use_luminance]() -> void {
-    uhdr_memory_block_t gainmap_mem(map_width * map_height * sizeof(float) *
+  auto generateGainMapTwoPass =
+      [this, sdr_intent, hdr_intent, gainmap_metadata, dest, map_width, map_height, hdrInvOetf,
+       hdrLuminanceFn, hdrOotfFn, hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn,
+       sdr_sample_pixel_fn, hdr_sample_pixel_fn, hdr_white_nits, use_luminance]() -> void {
+    uhdr_memory_block_t gainmap_mem((size_t)map_width * map_height * sizeof(float) *
                                     (mUseMultiChannelGainMap ? 3 : 1));
     float* gainmap_data = reinterpret_cast<float*>(gainmap_mem.m_buffer.get());
     float gainmap_min[3] = {127.0f, 127.0f, 127.0f};
     float gainmap_max[3] = {-128.0f, -128.0f, -128.0f};
     std::mutex gainmap_minmax;
 
-    const int threads = (std::min)(GetCPUCoreCount(), 4);
+    const int threads = (std::min)(GetCPUCoreCount(), 4u);
     const int jobSizeInRows = 1;
-    size_t rowStep = threads == 1 ? map_height : jobSizeInRows;
+    unsigned int rowStep = threads == 1 ? map_height : jobSizeInRows;
     JobQueue jobQueue;
     std::function<void()> generateMap =
-        [this, sdr_intent, hdr_intent, gainmap_data, map_width, hdrInvOetf, hdrGamutConversionFn,
-         luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn, sdr_sample_pixel_fn, hdr_sample_pixel_fn,
-         hdr_white_nits, use_luminance, &gainmap_min, &gainmap_max, &gainmap_minmax,
-         &jobQueue]() -> void {
-      size_t rowStart, rowEnd;
+        [this, sdr_intent, hdr_intent, gainmap_data, map_width, hdrInvOetf, hdrLuminanceFn,
+         hdrOotfFn, hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn,
+         sdr_sample_pixel_fn, hdr_sample_pixel_fn, hdr_white_nits, use_luminance, &gainmap_min,
+         &gainmap_max, &gainmap_minmax, &jobQueue]() -> void {
+      unsigned int rowStart, rowEnd;
       const bool isHdrIntentRgb = isPixelFormatRgb(hdr_intent->fmt);
       const bool isSdrIntentRgb = isPixelFormatRgb(sdr_intent->fmt);
+      const float hdrSampleToNitsFactor =
+          hdr_intent->ct == UHDR_CT_LINEAR ? kSdrWhiteNits : hdr_white_nits;
+      ColorTransformFn clampPixel = hdr_intent->ct == UHDR_CT_LINEAR
+                                        ? static_cast<ColorTransformFn>(clampPixelFloatLinear)
+                                        : static_cast<ColorTransformFn>(clampPixelFloat);
       float gainmap_min_th[3] = {127.0f, 127.0f, 127.0f};
       float gainmap_max_th[3] = {-128.0f, -128.0f, -128.0f};
 
@@ -808,11 +841,13 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
               hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
             }
             Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
+            hdr_rgb = hdrOotfFn(hdr_rgb, hdrLuminanceFn);
             hdr_rgb = hdrGamutConversionFn(hdr_rgb);
+            hdr_rgb = clampPixel(hdr_rgb);
 
             if (mUseMultiChannelGainMap) {
               Color sdr_rgb_nits = sdr_rgb * kSdrWhiteNits;
-              Color hdr_rgb_nits = hdr_rgb * hdr_white_nits;
+              Color hdr_rgb_nits = hdr_rgb * hdrSampleToNitsFactor;
               size_t pixel_idx = (x + y * map_width) * 3;
 
               gainmap_data[pixel_idx] = computeGain(sdr_rgb_nits.r, hdr_rgb_nits.r);
@@ -828,10 +863,10 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
 
               if (use_luminance) {
                 sdr_y_nits = luminanceFn(sdr_rgb) * kSdrWhiteNits;
-                hdr_y_nits = luminanceFn(hdr_rgb) * hdr_white_nits;
+                hdr_y_nits = luminanceFn(hdr_rgb) * hdrSampleToNitsFactor;
               } else {
                 sdr_y_nits = fmax(sdr_rgb.r, fmax(sdr_rgb.g, sdr_rgb.b)) * kSdrWhiteNits;
-                hdr_y_nits = fmax(hdr_rgb.r, fmax(hdr_rgb.g, hdr_rgb.b)) * hdr_white_nits;
+                hdr_y_nits = fmax(hdr_rgb.r, fmax(hdr_rgb.g, hdr_rgb.b)) * hdrSampleToNitsFactor;
               }
 
               size_t pixel_idx = x + y * map_width;
@@ -857,8 +892,8 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
       workers.push_back(std::thread(generateMap));
     }
 
-    for (size_t rowStart = 0; rowStart < map_height;) {
-      size_t rowEnd = (std::min)(rowStart + rowStep, map_height);
+    for (unsigned int rowStart = 0; rowStart < map_height;) {
+      unsigned int rowEnd = (std::min)(rowStart + rowStep, map_height);
       jobQueue.enqueueJob(rowStart, rowEnd);
       rowStart = rowEnd;
     }
@@ -890,7 +925,7 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
 
     std::function<void()> encodeMap = [this, gainmap_data, map_width, dest, min_content_boost_log2,
                                        max_content_boost_log2, &jobQueue]() -> void {
-      size_t rowStart, rowEnd;
+      unsigned int rowStart, rowEnd;
 
       while (jobQueue.dequeueJob(rowStart, rowEnd)) {
         if (mUseMultiChannelGainMap) {
@@ -922,8 +957,8 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     for (int th = 0; th < threads - 1; th++) {
       workers.push_back(std::thread(encodeMap));
     }
-    for (size_t rowStart = 0; rowStart < map_height;) {
-      size_t rowEnd = (std::min)(rowStart + rowStep, map_height);
+    for (unsigned int rowStart = 0; rowStart < map_height;) {
+      unsigned int rowEnd = (std::min)(rowStart + rowStep, map_height);
       jobQueue.enqueueJob(rowStart, rowEnd);
       rowStart = rowEnd;
     }
@@ -937,7 +972,11 @@ uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_
     gainmap_metadata->offset_sdr = 0.0f;
     gainmap_metadata->offset_hdr = 0.0f;
     gainmap_metadata->hdr_capacity_min = 1.0f;
-    gainmap_metadata->hdr_capacity_max = hdr_white_nits / kSdrWhiteNits;
+    if (this->mTargetDispPeakBrightness != -1.0f) {
+      gainmap_metadata->hdr_capacity_max = this->mTargetDispPeakBrightness / kSdrWhiteNits;
+    } else {
+      gainmap_metadata->hdr_capacity_max = hdr_white_nits / kSdrWhiteNits;
+    }
   };
 
   if (mEncPreset == UHDR_USAGE_REALTIME) {
@@ -999,34 +1038,42 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
                                        uhdr_mem_block_t* pExif, void* pIcc, size_t icc_size,
                                        uhdr_gainmap_metadata_ext_t* metadata,
                                        uhdr_compressed_image_t* dest) {
-  const int xmpNameSpaceLength = kXmpNameSpace.size() + 1;  // need to count the null terminator
-  const int isoNameSpaceLength = kIsoNameSpace.size() + 1;  // need to count the null terminator
+  const size_t xmpNameSpaceLength = kXmpNameSpace.size() + 1;  // need to count the null terminator
+  const size_t isoNameSpaceLength = kIsoNameSpace.size() + 1;  // need to count the null terminator
 
   /////////////////////////////////////////////////////////////////////////////////////////////////
   // calculate secondary image length first, because the length will be written into the primary //
   // image xmp                                                                                   //
   /////////////////////////////////////////////////////////////////////////////////////////////////
+
   // XMP
-  const string xmp_secondary = generateXmpForSecondaryImage(*metadata);
-  // xmp_secondary_length = 2 bytes representing the length of the package +
-  //  + xmpNameSpaceLength = 29 bytes length
-  //  + length of xmp packet = xmp_secondary.size()
-  const int xmp_secondary_length = 2 + xmpNameSpaceLength + xmp_secondary.size();
+  string xmp_secondary;
+  size_t xmp_secondary_length;
+  if (kWriteXmpMetadata) {
+    xmp_secondary = generateXmpForSecondaryImage(*metadata);
+    // xmp_secondary_length = 2 bytes representing the length of the package +
+    //  + xmpNameSpaceLength = 29 bytes length
+    //  + length of xmp packet = xmp_secondary.size()
+    xmp_secondary_length = 2 + xmpNameSpaceLength + xmp_secondary.size();
+  }
+
   // ISO
   uhdr_gainmap_metadata_frac iso_secondary_metadata;
   std::vector<uint8_t> iso_secondary_data;
-  UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(
-      metadata, &iso_secondary_metadata));
-
-  UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&iso_secondary_metadata,
-                                                                   iso_secondary_data));
+  size_t iso_secondary_length;
+  if (kWriteIso21496_1Metadata) {
+    UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(
+        metadata, &iso_secondary_metadata));
 
-  // iso_secondary_length = 2 bytes representing the length of the package +
-  //  + isoNameSpaceLength = 28 bytes length
-  //  + length of iso metadata packet = iso_secondary_data.size()
-  const int iso_secondary_length = 2 + isoNameSpaceLength + iso_secondary_data.size();
+    UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&iso_secondary_metadata,
+                                                                     iso_secondary_data));
+    // iso_secondary_length = 2 bytes representing the length of the package +
+    //  + isoNameSpaceLength = 28 bytes length
+    //  + length of iso metadata packet = iso_secondary_data.size()
+    iso_secondary_length = 2 + isoNameSpaceLength + iso_secondary_data.size();
+  }
 
-  int secondary_image_size = 2 /* 2 bytes length of APP1 sign */ + gainmap_compressed->data_sz;
+  size_t secondary_image_size = 2 /* 2 bytes length of APP1 sign */ + gainmap_compressed->data_sz;
   if (kWriteXmpMetadata) {
     secondary_image_size += xmp_secondary_length;
   }
@@ -1073,7 +1120,7 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
   uhdr_compressed_image_t* final_primary_jpg_image_ptr =
       new_jpg_image.data_sz == 0 ? sdr_intent_compressed : &new_jpg_image;
 
-  int pos = 0;
+  size_t pos = 0;
   // Begin primary image
   // Write SOI
   UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
@@ -1081,7 +1128,7 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
 
   // Write EXIF
   if (pExif != nullptr) {
-    const int length = 2 + pExif->data_sz;
+    const size_t length = 2 + pExif->data_sz;
     const uint8_t lengthH = ((length >> 8) & 0xff);
     const uint8_t lengthL = (length & 0xff);
     UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
@@ -1094,7 +1141,7 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
   // Prepare and write XMP
   if (kWriteXmpMetadata) {
     const string xmp_primary = generateXmpForPrimaryImage(secondary_image_size, *metadata);
-    const int length = 2 + xmpNameSpaceLength + xmp_primary.size();
+    const size_t length = 2 + xmpNameSpaceLength + xmp_primary.size();
     const uint8_t lengthH = ((length >> 8) & 0xff);
     const uint8_t lengthL = (length & 0xff);
     UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
@@ -1107,7 +1154,7 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
 
   // Write ICC
   if (pIcc != nullptr && icc_size > 0) {
-    const int length = icc_size + 2;
+    const size_t length = icc_size + 2;
     const uint8_t lengthH = ((length >> 8) & 0xff);
     const uint8_t lengthL = (length & 0xff);
     UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
@@ -1119,7 +1166,7 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
 
   // Prepare and write ISO 21496-1 metadata
   if (kWriteIso21496_1Metadata) {
-    const int length = 2 + isoNameSpaceLength + 4;
+    const size_t length = 2 + isoNameSpaceLength + 4;
     uint8_t zero = 0;
     const uint8_t lengthH = ((length >> 8) & 0xff);
     const uint8_t lengthL = (length & 0xff);
@@ -1136,15 +1183,15 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
 
   // Prepare and write MPF
   {
-    const int length = 2 + calculateMpfSize();
+    const size_t length = 2 + calculateMpfSize();
     const uint8_t lengthH = ((length >> 8) & 0xff);
     const uint8_t lengthL = (length & 0xff);
-    int primary_image_size = pos + length + final_primary_jpg_image_ptr->data_sz;
+    size_t primary_image_size = pos + length + final_primary_jpg_image_ptr->data_sz;
     // between APP2 + package size + signature
     // ff e2 00 58 4d 50 46 00
     // 2 + 2 + 4 = 8 (bytes)
     // and ff d8 sign of the secondary image
-    int secondary_image_offset = primary_image_size - pos - 8;
+    size_t secondary_image_offset = primary_image_size - pos - 8;
     std::shared_ptr<DataStruct> mpf = generateMpf(primary_image_size, 0, /* primary_image_offset */
                                                   secondary_image_size, secondary_image_offset);
     UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
@@ -1166,7 +1213,7 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
 
   // Prepare and write XMP
   if (kWriteXmpMetadata) {
-    const int length = xmp_secondary_length;
+    const size_t length = xmp_secondary_length;
     const uint8_t lengthH = ((length >> 8) & 0xff);
     const uint8_t lengthL = (length & 0xff);
     UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
@@ -1179,7 +1226,7 @@ uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compr
 
   // Prepare and write ISO 21496-1 metadata
   if (kWriteIso21496_1Metadata) {
-    const int length = iso_secondary_length;
+    const size_t length = iso_secondary_length;
     const uint8_t lengthH = ((length >> 8) & 0xff);
     const uint8_t lengthL = (length & 0xff);
     UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
@@ -1216,22 +1263,22 @@ uhdr_error_info_t JpegR::getJPEGRInfo(uhdr_compressed_image_t* uhdr_compressed_i
   return g_no_error;
 }
 
-uhdr_error_info_t JpegR::parseGainMapMetadata(uint8_t* iso_data, int iso_size, uint8_t* xmp_data,
-                                              int xmp_size,
+uhdr_error_info_t JpegR::parseGainMapMetadata(uint8_t* iso_data, size_t iso_size, uint8_t* xmp_data,
+                                              size_t xmp_size,
                                               uhdr_gainmap_metadata_ext_t* uhdr_metadata) {
   if (iso_size > 0) {
-    if (iso_size < (int)kIsoNameSpace.size() + 1) {
+    if (iso_size < kIsoNameSpace.size() + 1) {
       uhdr_error_info_t status;
       status.error_code = UHDR_CODEC_ERROR;
       status.has_detail = 1;
       snprintf(status.detail, sizeof status.detail,
-               "iso block size needs to be atleast %d but got %d", (int)kIsoNameSpace.size() + 1,
+               "iso block size needs to be atleast %zd but got %zd", kIsoNameSpace.size() + 1,
                iso_size);
       return status;
     }
     uhdr_gainmap_metadata_frac decodedMetadata;
     std::vector<uint8_t> iso_vec;
-    for (int i = (int)kIsoNameSpace.size() + 1; i < iso_size; i++) {
+    for (size_t i = kIsoNameSpace.size() + 1; i < iso_size; i++) {
       iso_vec.push_back(iso_data[i]);
     }
 
@@ -1323,24 +1370,7 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
              gainmap_metadata->version.c_str());
     return status;
   }
-  if (gainmap_metadata->offset_sdr != 0.0f) {
-    uhdr_error_info_t status;
-    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "Unsupported gainmap metadata, offset_sdr. Expected %f, Got %f", 0.0f,
-             gainmap_metadata->offset_sdr);
-    return status;
-  }
-  if (gainmap_metadata->offset_hdr != 0.0f) {
-    uhdr_error_info_t status;
-    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "Unsupported gainmap metadata, offset_hdr. Expected %f, Got %f", 0.0f,
-             gainmap_metadata->offset_hdr);
-    return status;
-  }
+  UHDR_ERR_CHECK(uhdr_validate_gainmap_metadata_descriptor(gainmap_metadata));
   if (sdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCr444 &&
       sdr_intent->fmt != UHDR_IMG_FMT_16bppYCbCr422 &&
       sdr_intent->fmt != UHDR_IMG_FMT_12bppYCbCr420) {
@@ -1386,6 +1416,7 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
   }
 #endif
 
+  std::unique_ptr<uhdr_raw_image_ext_t> resized_gainmap = nullptr;
   {
     float primary_aspect_ratio = (float)sdr_intent->w / sdr_intent->h;
     float gainmap_aspect_ratio = (float)gainmap_img->w / gainmap_img->h;
@@ -1393,25 +1424,39 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
     // Allow 1% delta
     const float delta_tolerance = 0.01;
     if (delta_aspect_ratio / primary_aspect_ratio > delta_tolerance) {
-      uhdr_error_info_t status;
-      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
-      status.has_detail = 1;
-      snprintf(
-          status.detail, sizeof status.detail,
-          "gain map dimensions scale factor values for height and width are different, \n primary "
-          "image resolution is %ux%u, received gain map resolution is %ux%u",
-          sdr_intent->w, sdr_intent->h, gainmap_img->w, gainmap_img->h);
-      return status;
+      resized_gainmap = resize_image(gainmap_img, sdr_intent->w, sdr_intent->h);
+      if (resized_gainmap == nullptr) {
+        uhdr_error_info_t status;
+        status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "encountered error while resizing the gainmap image from %ux%u to %ux%u",
+                 gainmap_img->w, gainmap_img->h, sdr_intent->w, sdr_intent->h);
+        return status;
+      }
+      gainmap_img = resized_gainmap.get();
     }
   }
 
   float map_scale_factor = (float)sdr_intent->w / gainmap_img->w;
+  int map_scale_factor_rnd = (std::max)(1, (int)std::roundf(map_scale_factor));
 
   dest->cg = sdr_intent->cg;
   // Table will only be used when map scale factor is integer.
-  ShepardsIDW idwTable(static_cast<int>(map_scale_factor));
+  ShepardsIDW idwTable(map_scale_factor_rnd);
   float display_boost = (std::min)(max_display_boost, gainmap_metadata->hdr_capacity_max);
-  GainLUT gainLUT(gainmap_metadata, display_boost);
+
+  float gainmap_weight;
+  if (display_boost != gainmap_metadata->hdr_capacity_max) {
+    gainmap_weight =
+        (log2(display_boost) - log2(gainmap_metadata->hdr_capacity_min)) /
+        (log2(gainmap_metadata->hdr_capacity_max) - log2(gainmap_metadata->hdr_capacity_min));
+    // avoid extrapolating the gain map to fill the displayable range
+    gainmap_weight = CLIP3(0.0f, gainmap_weight, 1.0f);
+  } else {
+    gainmap_weight = 1.0f;
+  }
+  GainLUT gainLUT(gainmap_metadata, gainmap_weight);
 
   GetPixelFn get_pixel_fn = getPixelFn(sdr_intent->fmt);
   if (get_pixel_fn == nullptr) {
@@ -1425,13 +1470,13 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
 
   JobQueue jobQueue;
   std::function<void()> applyRecMap = [sdr_intent, gainmap_img, dest, &jobQueue, &idwTable,
-                                       output_ct, &gainLUT, display_boost,
+                                       output_ct, &gainLUT, gainmap_metadata,
 #if !USE_APPLY_GAIN_LUT
-                                       gainmap_metadata,
+                                       gainmap_weight,
 #endif
                                        map_scale_factor, get_pixel_fn]() -> void {
-    size_t width = sdr_intent->w;
-    size_t rowStart, rowEnd;
+    unsigned int width = sdr_intent->w;
+    unsigned int rowStart, rowEnd;
 
     while (jobQueue.dequeueJob(rowStart, rowEnd)) {
       for (size_t y = rowStart; y < rowEnd; ++y) {
@@ -1456,9 +1501,9 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
             }
 
 #if USE_APPLY_GAIN_LUT
-            rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT);
+            rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT, gainmap_metadata);
 #else
-            rgb_hdr = applyGain(rgb_sdr, gain, gainmap_metadata, display_boost);
+            rgb_hdr = applyGain(rgb_sdr, gain, gainmap_metadata, gainmap_weight);
 #endif
           } else {
             Color gain;
@@ -1472,13 +1517,12 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
             }
 
 #if USE_APPLY_GAIN_LUT
-            rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT);
+            rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT, gainmap_metadata);
 #else
-            rgb_hdr = applyGain(rgb_sdr, gain, gainmap_metadata, display_boost);
+            rgb_hdr = applyGain(rgb_sdr, gain, gainmap_metadata, gainmap_weight);
 #endif
           }
 
-          rgb_hdr = rgb_hdr / display_boost;
           size_t pixel_idx = x + y * dest->stride[UHDR_PLANE_PACKED];
 
           switch (output_ct) {
@@ -1493,6 +1537,8 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
 #else
               ColorTransformFn hdrOetf = hlgOetf;
 #endif
+              rgb_hdr = rgb_hdr * kSdrWhiteNits / kHlgMaxNits;
+              rgb_hdr = hlgInverseOotfApprox(rgb_hdr);
               Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
               uint32_t rgba_1010102 = colorToRgba1010102(rgb_gamma_hdr);
               reinterpret_cast<uint32_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
@@ -1505,6 +1551,7 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
 #else
               ColorTransformFn hdrOetf = pqOetf;
 #endif
+              rgb_hdr = rgb_hdr * kSdrWhiteNits / kPqMaxNits;
               Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
               uint32_t rgba_1010102 = colorToRgba1010102(rgb_gamma_hdr);
               reinterpret_cast<uint32_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
@@ -1520,14 +1567,14 @@ uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_ima
     }
   };
 
-  const int threads = (std::min)(GetCPUCoreCount(), 4);
+  const int threads = (std::min)(GetCPUCoreCount(), 4u);
   std::vector<std::thread> workers;
   for (int th = 0; th < threads - 1; th++) {
     workers.push_back(std::thread(applyRecMap));
   }
-  const int rowStep = threads == 1 ? sdr_intent->h : map_scale_factor;
-  for (size_t rowStart = 0; rowStart < sdr_intent->h;) {
-    int rowEnd = (std::min)(rowStart + rowStep, (size_t)sdr_intent->h);
+  const unsigned int rowStep = threads == 1 ? sdr_intent->h : map_scale_factor_rnd;
+  for (unsigned int rowStart = 0; rowStart < sdr_intent->h;) {
+    unsigned int rowEnd = (std::min)(rowStart + rowStep, sdr_intent->h);
     jobQueue.enqueueJob(rowStart, rowEnd);
     rowStart = rowEnd;
   }
@@ -1607,10 +1654,10 @@ uhdr_error_info_t JpegR::extractPrimaryImageAndGainMap(uhdr_compressed_image_t*
 }
 
 uhdr_error_info_t JpegR::parseJpegInfo(uhdr_compressed_image_t* jpeg_image, j_info_ptr image_info,
-                                       size_t* img_width, size_t* img_height) {
+                                       unsigned int* img_width, unsigned int* img_height) {
   JpegDecoderHelper jpeg_dec_obj;
   UHDR_ERR_CHECK(jpeg_dec_obj.parseImage(jpeg_image->data, jpeg_image->data_sz))
-  size_t imgWidth, imgHeight, numComponents;
+  unsigned int imgWidth, imgHeight, numComponents;
   imgWidth = jpeg_dec_obj.getDecompressedImageWidth();
   imgHeight = jpeg_dec_obj.getDecompressedImageHeight();
   numComponents = jpeg_dec_obj.getNumComponentsInImage();
@@ -1655,16 +1702,13 @@ static float ReinhardMap(float y_hdr, float headroom) {
   return out * y_hdr;
 }
 
-GlobalTonemapOutputs globalTonemap(const std::array<float, 3>& rgb_in, float headroom, float y_in) {
-  constexpr float kOotfGamma = 1.2f;
-
-  // Apply OOTF and Scale to Headroom to get HDR values that are referenced to
-  // SDR white. The range [0.0, 1.0] is linearly stretched to [0.0, headroom]
-  // after the OOTF.
-  const float y_ootf_div_y_in = std::pow(y_in, kOotfGamma - 1.0f);
+GlobalTonemapOutputs globalTonemap(const std::array<float, 3>& rgb_in, float headroom,
+                                   bool is_normalized) {
+  // Scale to Headroom to get HDR values that are referenced to SDR white. The range [0.0, 1.0] is
+  // linearly stretched to [0.0, headroom].
   std::array<float, 3> rgb_hdr;
   std::transform(rgb_in.begin(), rgb_in.end(), rgb_hdr.begin(),
-                 [&](float x) { return x * headroom * y_ootf_div_y_in; });
+                 [&](float x) { return is_normalized ? x * headroom : x; });
 
   // Apply a tone mapping to compress the range [0, headroom] to [0, 1] by
   // keeping the shadows the same and crushing the highlights.
@@ -1695,15 +1739,16 @@ uint8_t ScaleTo8Bit(float value) {
 uhdr_error_info_t JpegR::toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent) {
   if (hdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCrP010 &&
       hdr_intent->fmt != UHDR_IMG_FMT_30bppYCbCr444 &&
-      hdr_intent->fmt != UHDR_IMG_FMT_32bppRGBA1010102) {
+      hdr_intent->fmt != UHDR_IMG_FMT_32bppRGBA1010102 &&
+      hdr_intent->fmt != UHDR_IMG_FMT_64bppRGBAHalfFloat) {
     uhdr_error_info_t status;
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
     status.has_detail = 1;
-    snprintf(
-        status.detail, sizeof status.detail,
-        "tonemap method expects hdr intent color format to be one of {UHDR_IMG_FMT_24bppYCbCrP010, "
-        "UHDR_IMG_FMT_30bppYCbCr444, UHDR_IMG_FMT_32bppRGBA1010102}. Received %d",
-        hdr_intent->fmt);
+    snprintf(status.detail, sizeof status.detail,
+             "tonemap method expects hdr intent color format to be one of "
+             "{UHDR_IMG_FMT_24bppYCbCrP010, UHDR_IMG_FMT_30bppYCbCr444, "
+             "UHDR_IMG_FMT_32bppRGBA1010102, UHDR_IMG_FMT_64bppRGBAHalfFloat}. Received %d",
+             hdr_intent->fmt);
     return status;
   }
 
@@ -1731,14 +1776,16 @@ uhdr_error_info_t JpegR::toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t*
     return status;
   }
 
-  if (hdr_intent->fmt == UHDR_IMG_FMT_32bppRGBA1010102 &&
+  if ((hdr_intent->fmt == UHDR_IMG_FMT_32bppRGBA1010102 ||
+       hdr_intent->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) &&
       sdr_intent->fmt != UHDR_IMG_FMT_32bppRGBA8888) {
     uhdr_error_info_t status;
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
              "tonemap method expects sdr intent color format to be UHDR_IMG_FMT_32bppRGBA8888, if "
-             "hdr intent color format is UHDR_IMG_FMT_32bppRGBA1010102. Received %d",
+             "hdr intent color format is UHDR_IMG_FMT_32bppRGBA1010102 or "
+             "UHDR_IMG_FMT_64bppRGBAHalfFloat. Received %d",
              sdr_intent->fmt);
     return status;
   }
@@ -1754,7 +1801,7 @@ uhdr_error_info_t JpegR::toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t*
     return status;
   }
 
-  ColorCalculationFn hdrLuminanceFn = getLuminanceFn(hdr_intent->cg);
+  LuminanceFn hdrLuminanceFn = getLuminanceFn(hdr_intent->cg);
   if (hdrLuminanceFn == nullptr) {
     uhdr_error_info_t status;
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
@@ -1765,6 +1812,17 @@ uhdr_error_info_t JpegR::toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t*
     return status;
   }
 
+  SceneToDisplayLuminanceFn hdrOotfFn = getOotfFn(hdr_intent->ct);
+  if (hdrOotfFn == nullptr) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for calculating Ootf for color transfer %d",
+             hdr_intent->ct);
+    return status;
+  }
+
   ColorTransformFn hdrInvOetf = getInverseOetfFn(hdr_intent->ct);
   if (hdrInvOetf == nullptr) {
     uhdr_error_info_t status;
@@ -1776,14 +1834,15 @@ uhdr_error_info_t JpegR::toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t*
     return status;
   }
 
-  float hdr_white_nits = getMaxDisplayMasteringLuminance(hdr_intent->ct);
+  float hdr_white_nits = getReferenceDisplayPeakLuminanceInNits(hdr_intent->ct);
   if (hdr_white_nits == -1.0f) {
     uhdr_error_info_t status;
     status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
-             "Did not receive valid MDML for display with transfer characteristics %d",
-             hdr_intent->ct);
+             "received invalid peak brightness %f nits for hdr reference display with color "
+             "transfer %d ",
+             hdr_white_nits, hdr_intent->ct);
     return status;
   }
 
@@ -1815,22 +1874,23 @@ uhdr_error_info_t JpegR::toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t*
 
   ColorTransformFn hdrGamutConversionFn = getGamutConversionFn(sdr_intent->cg, hdr_intent->cg);
 
-  size_t height = hdr_intent->h;
-  const int threads = (std::min)(GetCPUCoreCount(), 4);
+  unsigned int height = hdr_intent->h;
+  const int threads = (std::min)(GetCPUCoreCount(), 4u);
   // for 420 subsampling, process 2 rows at once
   const int jobSizeInRows = hdr_intent->fmt == UHDR_IMG_FMT_24bppYCbCrP010 ? 2 : 1;
-  size_t rowStep = threads == 1 ? height : jobSizeInRows;
+  unsigned int rowStep = threads == 1 ? height : jobSizeInRows;
   JobQueue jobQueue;
   std::function<void()> toneMapInternal;
 
   toneMapInternal = [hdr_intent, sdr_intent, hdrInvOetf, hdrGamutConversionFn, hdrYuvToRgbFn,
-                     hdr_white_nits, get_pixel_fn, put_pixel_fn, hdrLuminanceFn,
+                     hdr_white_nits, get_pixel_fn, put_pixel_fn, hdrLuminanceFn, hdrOotfFn,
                      &jobQueue]() -> void {
-    size_t rowStart, rowEnd;
+    unsigned int rowStart, rowEnd;
     const int hfactor = hdr_intent->fmt == UHDR_IMG_FMT_24bppYCbCrP010 ? 2 : 1;
     const int vfactor = hdr_intent->fmt == UHDR_IMG_FMT_24bppYCbCrP010 ? 2 : 1;
     const bool isHdrIntentRgb = isPixelFormatRgb(hdr_intent->fmt);
     const bool isSdrIntentRgb = isPixelFormatRgb(sdr_intent->fmt);
+    const bool is_normalized = hdr_intent->ct != UHDR_CT_LINEAR;
     uint8_t* luma_data = reinterpret_cast<uint8_t*>(sdr_intent->planes[UHDR_PLANE_Y]);
     uint8_t* cb_data = reinterpret_cast<uint8_t*>(sdr_intent->planes[UHDR_PLANE_U]);
     uint8_t* cr_data = reinterpret_cast<uint8_t*>(sdr_intent->planes[UHDR_PLANE_V]);
@@ -1856,10 +1916,10 @@ uhdr_error_info_t JpegR::toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t*
                 hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
               }
               Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
+              hdr_rgb = hdrOotfFn(hdr_rgb, hdrLuminanceFn);
 
-              GlobalTonemapOutputs tonemap_outputs =
-                  globalTonemap({hdr_rgb.r, hdr_rgb.g, hdr_rgb.b}, hdr_white_nits / kSdrWhiteNits,
-                                hdrLuminanceFn({{{hdr_rgb.r, hdr_rgb.g, hdr_rgb.b}}}));
+              GlobalTonemapOutputs tonemap_outputs = globalTonemap(
+                  {hdr_rgb.r, hdr_rgb.g, hdr_rgb.b}, hdr_white_nits / kSdrWhiteNits, is_normalized);
               Color sdr_rgb_linear_bt2100 = {
                   {{tonemap_outputs.rgb_out[0], tonemap_outputs.rgb_out[1],
                     tonemap_outputs.rgb_out[2]}}};
@@ -1903,8 +1963,8 @@ uhdr_error_info_t JpegR::toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t*
     workers.push_back(std::thread(toneMapInternal));
   }
 
-  for (size_t rowStart = 0; rowStart < height;) {
-    size_t rowEnd = (std::min)(rowStart + rowStep, height);
+  for (unsigned int rowStart = 0; rowStart < height;) {
+    unsigned int rowEnd = (std::min)(rowStart + rowStep, height);
     jobQueue.enqueueJob(rowStart, rowEnd);
     rowStart = rowEnd;
   }
@@ -1924,17 +1984,17 @@ status_t JpegR::areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
     return ERROR_JPEGR_BAD_PTR;
   }
   if (p010_image_ptr->width % 2 != 0 || p010_image_ptr->height % 2 != 0) {
-    ALOGE("Image dimensions cannot be odd, image dimensions %zux%zu", p010_image_ptr->width,
+    ALOGE("Image dimensions cannot be odd, image dimensions %ux%u", p010_image_ptr->width,
           p010_image_ptr->height);
     return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
   }
   if ((int)p010_image_ptr->width < kMinWidth || (int)p010_image_ptr->height < kMinHeight) {
-    ALOGE("Image dimensions cannot be less than %dx%d, image dimensions %zux%zu", kMinWidth,
+    ALOGE("Image dimensions cannot be less than %dx%d, image dimensions %ux%u", kMinWidth,
           kMinHeight, p010_image_ptr->width, p010_image_ptr->height);
     return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
   }
   if ((int)p010_image_ptr->width > kMaxWidth || (int)p010_image_ptr->height > kMaxHeight) {
-    ALOGE("Image dimensions cannot be larger than %dx%d, image dimensions %zux%zu", kMaxWidth,
+    ALOGE("Image dimensions cannot be larger than %dx%d, image dimensions %ux%u", kMaxWidth,
           kMaxHeight, p010_image_ptr->width, p010_image_ptr->height);
     return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
   }
@@ -1944,13 +2004,13 @@ status_t JpegR::areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
     return ERROR_JPEGR_INVALID_COLORGAMUT;
   }
   if (p010_image_ptr->luma_stride != 0 && p010_image_ptr->luma_stride < p010_image_ptr->width) {
-    ALOGE("Luma stride must not be smaller than width, stride=%zu, width=%zu",
+    ALOGE("Luma stride must not be smaller than width, stride=%u, width=%u",
           p010_image_ptr->luma_stride, p010_image_ptr->width);
     return ERROR_JPEGR_INVALID_STRIDE;
   }
   if (p010_image_ptr->chroma_data != nullptr &&
       p010_image_ptr->chroma_stride < p010_image_ptr->width) {
-    ALOGE("Chroma stride must not be smaller than width, stride=%zu, width=%zu",
+    ALOGE("Chroma stride must not be smaller than width, stride=%u, width=%u",
           p010_image_ptr->chroma_stride, p010_image_ptr->width);
     return ERROR_JPEGR_INVALID_STRIDE;
   }
@@ -1962,6 +2022,38 @@ status_t JpegR::areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
     ALOGE("Invalid hdr transfer function %d", hdr_tf);
     return ERROR_JPEGR_INVALID_TRANS_FUNC;
   }
+  if (mMapDimensionScaleFactor <= 0 || mMapDimensionScaleFactor > 128) {
+    ALOGE("gainmap scale factor is ecpected to be in range (0, 128], received %d",
+          mMapDimensionScaleFactor);
+    return ERROR_JPEGR_UNSUPPORTED_MAP_SCALE_FACTOR;
+  }
+  if (mMapCompressQuality < 0 || mMapCompressQuality > 100) {
+    ALOGE("invalid quality factor %d, expects in range [0-100]", mMapCompressQuality);
+    return ERROR_JPEGR_INVALID_QUALITY_FACTOR;
+  }
+  if (!std::isfinite(mGamma) || mGamma <= 0.0f) {
+    ALOGE("unsupported gainmap gamma %f, expects to be > 0", mGamma);
+    return ERROR_JPEGR_INVALID_GAMMA;
+  }
+  if (mEncPreset != UHDR_USAGE_REALTIME && mEncPreset != UHDR_USAGE_BEST_QUALITY) {
+    ALOGE("invalid preset %d, expects one of {UHDR_USAGE_REALTIME, UHDR_USAGE_BEST_QUALITY}",
+          mEncPreset);
+    return ERROR_JPEGR_INVALID_ENC_PRESET;
+  }
+  if (!std::isfinite(mMinContentBoost) || !std::isfinite(mMaxContentBoost) ||
+      mMaxContentBoost < mMinContentBoost || mMinContentBoost <= 0.0f) {
+    ALOGE("Invalid min boost / max boost configuration. Configured max boost %f, min boost %f",
+          mMaxContentBoost, mMinContentBoost);
+    return ERROR_JPEGR_INVALID_DISPLAY_BOOST;
+  }
+  if ((!std::isfinite(mTargetDispPeakBrightness) ||
+       mTargetDispPeakBrightness < ultrahdr::kSdrWhiteNits ||
+       mTargetDispPeakBrightness > ultrahdr::kPqMaxNits) &&
+      mTargetDispPeakBrightness != -1.0f) {
+    ALOGE("unexpected target display peak brightness nits %f, expects to be with in range [%f %f]",
+          mTargetDispPeakBrightness, ultrahdr::kSdrWhiteNits, ultrahdr::kPqMaxNits);
+    return ERROR_JPEGR_INVALID_TARGET_DISP_PEAK_BRIGHTNESS;
+  }
   if (yuv420_image_ptr == nullptr) {
     return JPEGR_NO_ERROR;
   }
@@ -1971,19 +2063,19 @@ status_t JpegR::areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
   }
   if (yuv420_image_ptr->luma_stride != 0 &&
       yuv420_image_ptr->luma_stride < yuv420_image_ptr->width) {
-    ALOGE("Luma stride must not be smaller than width, stride=%zu, width=%zu",
+    ALOGE("Luma stride must not be smaller than width, stride=%u, width=%u",
           yuv420_image_ptr->luma_stride, yuv420_image_ptr->width);
     return ERROR_JPEGR_INVALID_STRIDE;
   }
   if (yuv420_image_ptr->chroma_data != nullptr &&
       yuv420_image_ptr->chroma_stride < yuv420_image_ptr->width / 2) {
-    ALOGE("Chroma stride must not be smaller than (width / 2), stride=%zu, width=%zu",
+    ALOGE("Chroma stride must not be smaller than (width / 2), stride=%u, width=%u",
           yuv420_image_ptr->chroma_stride, yuv420_image_ptr->width);
     return ERROR_JPEGR_INVALID_STRIDE;
   }
   if (p010_image_ptr->width != yuv420_image_ptr->width ||
       p010_image_ptr->height != yuv420_image_ptr->height) {
-    ALOGE("Image resolutions mismatch: P010: %zux%zu, YUV420: %zux%zu", p010_image_ptr->width,
+    ALOGE("Image resolutions mismatch: P010: %ux%u, YUV420: %ux%u", p010_image_ptr->width,
           p010_image_ptr->height, yuv420_image_ptr->width, yuv420_image_ptr->height);
     return ERROR_JPEGR_RESOLUTION_MISMATCH;
   }
@@ -2062,7 +2154,7 @@ status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, ultrahdr_transfe
   if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
   if (!p010_image.chroma_data) {
     uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
-    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
+    p010_image.chroma_data = data + (size_t)p010_image.luma_stride * p010_image.height;
     p010_image.chroma_stride = p010_image.luma_stride;
   }
 
@@ -2123,7 +2215,7 @@ status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
   if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
   if (!p010_image.chroma_data) {
     uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
-    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
+    p010_image.chroma_data = data + (size_t)p010_image.luma_stride * p010_image.height;
     p010_image.chroma_stride = p010_image.luma_stride;
   }
   uhdr_raw_image_t hdr_intent;
@@ -2144,7 +2236,7 @@ status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
   if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
   if (!yuv420_image.chroma_data) {
     uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
-    yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;
+    yuv420_image.chroma_data = data + (size_t)yuv420_image.luma_stride * yuv420_image.height;
     yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
   }
   uhdr_raw_image_t sdrRawImg;
@@ -2209,7 +2301,7 @@ status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
   if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
   if (!p010_image.chroma_data) {
     uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
-    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
+    p010_image.chroma_data = data + (size_t)p010_image.luma_stride * p010_image.height;
     p010_image.chroma_stride = p010_image.luma_stride;
   }
   uhdr_raw_image_t hdr_intent;
@@ -2230,7 +2322,7 @@ status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
   if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
   if (!yuv420_image.chroma_data) {
     uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
-    yuv420_image.chroma_data = data + yuv420_image.luma_stride * p010_image.height;
+    yuv420_image.chroma_data = data + (size_t)yuv420_image.luma_stride * p010_image.height;
     yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
   }
   uhdr_raw_image_t sdrRawImg;
@@ -2291,7 +2383,7 @@ status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
   if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
   if (!p010_image.chroma_data) {
     uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
-    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
+    p010_image.chroma_data = data + (size_t)p010_image.luma_stride * p010_image.height;
     p010_image.chroma_stride = p010_image.luma_stride;
   }
   uhdr_raw_image_t hdr_intent;
diff --git a/lib/src/jpegrutils.cpp b/lib/src/jpegrutils.cpp
index 4233847..463a359 100644
--- a/lib/src/jpegrutils.cpp
+++ b/lib/src/jpegrutils.cpp
@@ -45,7 +45,7 @@ static inline string Name(const string& prefix, const string& suffix) {
   return ss.str();
 }
 
-DataStruct::DataStruct(int s) {
+DataStruct::DataStruct(size_t s) {
   data = malloc(s);
   length = s;
   memset(data, 0, s);
@@ -60,9 +60,9 @@ DataStruct::~DataStruct() {
 
 void* DataStruct::getData() { return data; }
 
-int DataStruct::getLength() { return length; }
+size_t DataStruct::getLength() { return length; }
 
-int DataStruct::getBytesWritten() { return writePos; }
+size_t DataStruct::getBytesWritten() { return writePos; }
 
 bool DataStruct::write8(uint8_t value) {
   uint8_t v = value;
@@ -79,9 +79,9 @@ bool DataStruct::write32(uint32_t value) {
   return write(&v, 4);
 }
 
-bool DataStruct::write(const void* src, int size) {
+bool DataStruct::write(const void* src, size_t size) {
   if (writePos + size > length) {
-    ALOGE("Writing out of boundary: write position: %d, size: %d, capacity: %d", writePos, size,
+    ALOGE("Writing out of boundary: write position: %zd, size: %zd, capacity: %zd", writePos, size,
           length);
     return false;
   }
@@ -93,14 +93,16 @@ bool DataStruct::write(const void* src, int size) {
 /*
  * Helper function used for writing data to destination.
  */
-uhdr_error_info_t Write(uhdr_compressed_image_t* destination, const void* source, int length,
-                        int& position) {
-  if (position + length > (int)destination->capacity) {
+uhdr_error_info_t Write(uhdr_compressed_image_t* destination, const void* source, size_t length,
+                        size_t& position) {
+  if (position + length > destination->capacity) {
     uhdr_error_info_t status;
     status.error_code = UHDR_CODEC_MEM_ERROR;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
-             "output buffer to store compressed data is too small");
+             "output buffer to store compressed data is too small: write position: %zd, size: %zd, "
+             "capacity: %zd",
+             position, length, destination->capacity);
     return status;
   }
 
@@ -440,17 +442,17 @@ const string XMPXmlHandler::hdrCapacityMinAttrName = kMapHDRCapacityMin;
 const string XMPXmlHandler::hdrCapacityMaxAttrName = kMapHDRCapacityMax;
 const string XMPXmlHandler::baseRenditionIsHdrAttrName = kMapBaseRenditionIsHDR;
 
-uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, int xmp_size,
+uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, size_t xmp_size,
                                      uhdr_gainmap_metadata_ext_t* metadata) {
   string nameSpace = "http://ns.adobe.com/xap/1.0/\0";
 
-  if (xmp_size < (int)nameSpace.size() + 2) {
+  if (xmp_size < nameSpace.size() + 2) {
     uhdr_error_info_t status;
     status.error_code = UHDR_CODEC_ERROR;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
-             "size of xmp block is expected to be atleast %d bytes, received only %d bytes",
-             (int)nameSpace.size() + 2, xmp_size);
+             "size of xmp block is expected to be atleast %zd bytes, received only %zd bytes",
+             nameSpace.size() + 2, xmp_size);
     return status;
   }
 
@@ -472,8 +474,8 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, int xmp_size,
   // xml parser fails to parse packet header, wrapper. remove them before handing the data to
   // parser. if there is no packet header, do nothing otherwise go to the position of '<' without
   // '?' after it.
-  int offset = 0;
-  for (int i = 0; i < xmp_size - 1; ++i) {
+  size_t offset = 0;
+  for (size_t i = 0; i < xmp_size - 1; ++i) {
     if (xmp_data[i] == '<') {
       if (xmp_data[i + 1] != '?') {
         offset = i;
@@ -487,7 +489,7 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, int xmp_size,
   // If there is no packet wrapper, do nothing other wise go to the position of last '>' without '?'
   // before it.
   offset = 0;
-  for (int i = xmp_size - 1; i >= 1; --i) {
+  for (size_t i = xmp_size - 1; i >= 1; --i) {
     if (xmp_data[i] == '>') {
       if (xmp_data[i - 1] != '?') {
         offset = xmp_size - (i + 1);
@@ -625,7 +627,7 @@ uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, int xmp_size,
   return g_no_error;
 }
 
-string generateXmpForPrimaryImage(int secondary_image_length,
+string generateXmpForPrimaryImage(size_t secondary_image_length,
                                   uhdr_gainmap_metadata_ext_t& metadata) {
   const vector<string> kConDirSeq({kConDirectory, string("rdf:Seq")});
   const vector<string> kLiItem({string("rdf:li"), kConItem});
diff --git a/lib/src/multipictureformat.cpp b/lib/src/multipictureformat.cpp
index 59efc66..4a82a8b 100644
--- a/lib/src/multipictureformat.cpp
+++ b/lib/src/multipictureformat.cpp
@@ -27,8 +27,9 @@ size_t calculateMpfSize() {
          kNumPictures * kMPEntrySize;      // MP Entries for each image
 }
 
-std::shared_ptr<DataStruct> generateMpf(int primary_image_size, int primary_image_offset,
-                                        int secondary_image_size, int secondary_image_offset) {
+std::shared_ptr<DataStruct> generateMpf(size_t primary_image_size, size_t primary_image_offset,
+                                        size_t secondary_image_size,
+                                        size_t secondary_image_offset) {
   size_t mpf_size = calculateMpfSize();
   std::shared_ptr<DataStruct> dataStruct = std::make_shared<DataStruct>(mpf_size);
 
diff --git a/lib/src/ultrahdr_api.cpp b/lib/src/ultrahdr_api.cpp
index bf882ac..95264fd 100644
--- a/lib/src/ultrahdr_api.cpp
+++ b/lib/src/ultrahdr_api.cpp
@@ -52,7 +52,7 @@ uhdr_raw_image_ext::uhdr_raw_image_ext(uhdr_img_fmt_t fmt_, uhdr_color_gamut_t c
 
   int aligned_width = ALIGNM(w_, align_stride_to);
 
-  int bpp = 1;
+  size_t bpp = 1;
   if (fmt_ == UHDR_IMG_FMT_24bppYCbCrP010 || fmt_ == UHDR_IMG_FMT_30bppYCbCr444) {
     bpp = 2;
   } else if (fmt_ == UHDR_IMG_FMT_24bppRGB888) {
@@ -67,14 +67,14 @@ uhdr_raw_image_ext::uhdr_raw_image_ext(uhdr_img_fmt_t fmt_, uhdr_color_gamut_t c
   size_t plane_2_sz;
   size_t plane_3_sz;
   if (fmt_ == UHDR_IMG_FMT_24bppYCbCrP010) {
-    plane_2_sz = (2 /* planes */ * ((aligned_width / 2) * (h_ / 2) * bpp));
+    plane_2_sz = (2 /* planes */ * bpp * (aligned_width / 2) * (h_ / 2));
     plane_3_sz = 0;
   } else if (fmt_ == UHDR_IMG_FMT_30bppYCbCr444 || fmt_ == UHDR_IMG_FMT_24bppYCbCr444) {
     plane_2_sz = bpp * aligned_width * h_;
     plane_3_sz = bpp * aligned_width * h_;
   } else if (fmt_ == UHDR_IMG_FMT_12bppYCbCr420) {
-    plane_2_sz = (((aligned_width / 2) * (h_ / 2) * bpp));
-    plane_3_sz = (((aligned_width / 2) * (h_ / 2) * bpp));
+    plane_2_sz = (bpp * (aligned_width / 2) * (h_ / 2));
+    plane_3_sz = (bpp * (aligned_width / 2) * (h_ / 2));
   } else {
     plane_2_sz = 0;
     plane_3_sz = 0;
@@ -110,7 +110,7 @@ uhdr_raw_image_ext::uhdr_raw_image_ext(uhdr_img_fmt_t fmt_, uhdr_color_gamut_t c
 
 uhdr_compressed_image_ext::uhdr_compressed_image_ext(uhdr_color_gamut_t cg_,
                                                      uhdr_color_transfer_t ct_,
-                                                     uhdr_color_range_t range_, unsigned size) {
+                                                     uhdr_color_range_t range_, size_t size) {
   this->m_block = std::make_unique<uhdr_memory_block_t>(size);
   this->data = this->m_block->m_buffer.get();
   this->capacity = size;
@@ -187,7 +187,8 @@ uhdr_error_info_t apply_effects(uhdr_encoder_private* enc) {
                  crop_height);
         return status;
       }
-      apply_crop(hdr_raw_entry.get(), left, top, crop_width, crop_height);
+      hdr_img = apply_crop(dynamic_cast<ultrahdr::uhdr_crop_effect_t*>(it), hdr_raw_entry.get(),
+                           left, top, crop_width, crop_height);
       if (enc->m_raw_images.find(UHDR_SDR_IMG) != enc->m_raw_images.end()) {
         auto& sdr_raw_entry = enc->m_raw_images.find(UHDR_SDR_IMG)->second;
         if (crop_width % 2 != 0 && sdr_raw_entry->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
@@ -210,21 +211,21 @@ uhdr_error_info_t apply_effects(uhdr_encoder_private* enc) {
                    crop_height);
           return status;
         }
-        apply_crop(sdr_raw_entry.get(), left, top, crop_width, crop_height);
+        sdr_img = apply_crop(dynamic_cast<ultrahdr::uhdr_crop_effect_t*>(it), sdr_raw_entry.get(),
+                             left, top, crop_width, crop_height);
       }
-      continue;
     } else if (nullptr != dynamic_cast<uhdr_resize_effect_t*>(it)) {
       auto resize_effect = dynamic_cast<uhdr_resize_effect_t*>(it);
       int dst_w = resize_effect->m_width;
       int dst_h = resize_effect->m_height;
       auto& hdr_raw_entry = enc->m_raw_images.find(UHDR_HDR_IMG)->second;
-      if (dst_w <= 0 || dst_h <= 0) {
+      if (dst_w <= 0 || dst_h <= 0 || dst_w > ultrahdr::kMaxWidth || dst_h > ultrahdr::kMaxHeight) {
         uhdr_error_info_t status;
         status.error_code = UHDR_CODEC_INVALID_PARAM;
         snprintf(status.detail, sizeof status.detail,
-                 "destination dimensions cannot be <= zero. dest image width is %d, dest image "
-                 "height is %d",
-                 dst_w, dst_h);
+                 "destination dimensions must be in range (0, %d] x (0, %d]. dest image width "
+                 "is %d, dest image height is %d",
+                 ultrahdr::kMaxWidth, ultrahdr::kMaxHeight, dst_w, dst_h);
         return status;
       }
       if ((dst_w % 2 != 0 || dst_h % 2 != 0) && hdr_raw_entry->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
@@ -346,8 +347,8 @@ uhdr_error_info_t apply_effects(uhdr_decoder_private* dec) {
 
       float wd_ratio = ((float)disp->w) / gm->w;
       float ht_ratio = ((float)disp->h) / gm->h;
-      int gm_left = left / wd_ratio;
-      int gm_right = right / wd_ratio;
+      int gm_left = (int)(left / wd_ratio);
+      int gm_right = (int)(right / wd_ratio);
       if (gm_right <= gm_left) {
         uhdr_error_info_t status;
         status.error_code = UHDR_CODEC_INVALID_PARAM;
@@ -359,8 +360,8 @@ uhdr_error_info_t apply_effects(uhdr_decoder_private* dec) {
         return status;
       }
 
-      int gm_top = top / ht_ratio;
-      int gm_bottom = bottom / ht_ratio;
+      int gm_top = (int)(top / ht_ratio);
+      int gm_bottom = (int)(bottom / ht_ratio);
       if (gm_bottom <= gm_top) {
         uhdr_error_info_t status;
         status.error_code = UHDR_CODEC_INVALID_PARAM;
@@ -372,10 +373,10 @@ uhdr_error_info_t apply_effects(uhdr_decoder_private* dec) {
         return status;
       }
 
-      apply_crop(disp, left, top, right - left, bottom - top, gl_ctxt, disp_texture_ptr);
-      apply_crop(gm, gm_left, gm_top, (gm_right - gm_left), (gm_bottom - gm_top), gl_ctxt,
-                 gm_texture_ptr);
-      continue;
+      disp_img = apply_crop(dynamic_cast<ultrahdr::uhdr_crop_effect_t*>(it), disp, left, top,
+                            right - left, bottom - top, gl_ctxt, disp_texture_ptr);
+      gm_img = apply_crop(dynamic_cast<ultrahdr::uhdr_crop_effect_t*>(it), gm, gm_left, gm_top,
+                          (gm_right - gm_left), (gm_bottom - gm_top), gl_ctxt, gm_texture_ptr);
     } else if (nullptr != dynamic_cast<uhdr_resize_effect_t*>(it)) {
       auto resize_effect = dynamic_cast<uhdr_resize_effect_t*>(it);
       int dst_w = resize_effect->m_width;
@@ -384,15 +385,17 @@ uhdr_error_info_t apply_effects(uhdr_decoder_private* dec) {
           ((float)dec->m_decoded_img_buffer.get()->w) / dec->m_gainmap_img_buffer.get()->w;
       float ht_ratio =
           ((float)dec->m_decoded_img_buffer.get()->h) / dec->m_gainmap_img_buffer.get()->h;
-      int dst_gm_w = dst_w / wd_ratio;
-      int dst_gm_h = dst_h / ht_ratio;
-      if (dst_w <= 0 || dst_h <= 0 || dst_gm_w <= 0 || dst_gm_h <= 0) {
+      int dst_gm_w = (int)(dst_w / wd_ratio);
+      int dst_gm_h = (int)(dst_h / ht_ratio);
+      if (dst_w <= 0 || dst_h <= 0 || dst_gm_w <= 0 || dst_gm_h <= 0 ||
+          dst_w > ultrahdr::kMaxWidth || dst_h > ultrahdr::kMaxHeight ||
+          dst_gm_w > ultrahdr::kMaxWidth || dst_gm_h > ultrahdr::kMaxHeight) {
         uhdr_error_info_t status;
         status.error_code = UHDR_CODEC_INVALID_PARAM;
         snprintf(status.detail, sizeof status.detail,
-                 "destination dimension cannot be <= zero. dest image width is %d, dest image "
-                 "height is %d, dest gainmap width is %d, dest gainmap height is %d",
-                 dst_w, dst_h, dst_gm_w, dst_gm_h);
+                 "destination dimension must be in range (0, %d] x (0, %d]. dest image width is "
+                 "%d, dest image height is %d, dest gainmap width is %d, dest gainmap height is %d",
+                 ultrahdr::kMaxWidth, ultrahdr::kMaxHeight, dst_w, dst_h, dst_gm_w, dst_gm_h);
         return status;
       }
       disp_img =
@@ -417,6 +420,70 @@ uhdr_error_info_t apply_effects(uhdr_decoder_private* dec) {
   return g_no_error;
 }
 
+uhdr_error_info_t uhdr_validate_gainmap_metadata_descriptor(uhdr_gainmap_metadata_t* metadata) {
+  uhdr_error_info_t status = g_no_error;
+
+  if (metadata == nullptr) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received nullptr for gainmap metadata descriptor");
+  } else if (!std::isfinite(metadata->min_content_boost) ||
+             !std::isfinite(metadata->max_content_boost) || !std::isfinite(metadata->offset_sdr) ||
+             !std::isfinite(metadata->offset_hdr) || !std::isfinite(metadata->hdr_capacity_min) ||
+             !std::isfinite(metadata->hdr_capacity_max) || !std::isfinite(metadata->gamma)) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "Field(s) of gainmap metadata descriptor are either NaN or infinite. min content "
+             "boost %f, max content boost %f, offset sdr %f, offset hdr %f, hdr capacity min %f, "
+             "hdr capacity max %f, gamma %f",
+             metadata->min_content_boost, metadata->max_content_boost, metadata->offset_sdr,
+             metadata->offset_hdr, metadata->hdr_capacity_min, metadata->hdr_capacity_max,
+             metadata->gamma);
+  } else if (metadata->max_content_boost < metadata->min_content_boost) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received bad value for content boost max %f, expects to be >= content boost min %f",
+             metadata->max_content_boost, metadata->min_content_boost);
+  } else if (metadata->min_content_boost <= 0.0f) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received bad value for min boost %f, expects > 0.0f", metadata->min_content_boost);
+    return status;
+  } else if (metadata->gamma <= 0.0f) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received bad value for gamma %f, expects > 0.0f",
+             metadata->gamma);
+  } else if (metadata->offset_sdr < 0.0f) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received bad value for offset sdr %f, expects to be >= 0.0f", metadata->offset_sdr);
+  } else if (metadata->offset_hdr < 0.0f) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received bad value for offset hdr %f, expects to be >= 0.0f", metadata->offset_hdr);
+  } else if (metadata->hdr_capacity_max <= metadata->hdr_capacity_min) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received bad value for hdr capacity max %f, expects to be > hdr capacity min %f",
+             metadata->hdr_capacity_max, metadata->hdr_capacity_min);
+  } else if (metadata->hdr_capacity_min < 1.0f) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received bad value for hdr capacity min %f, expects to be >= 1.0f",
+             metadata->hdr_capacity_min);
+  }
+  return status;
+}
+
 }  // namespace ultrahdr
 
 uhdr_codec_private::~uhdr_codec_private() {
@@ -445,7 +512,7 @@ uhdr_error_info_t uhdr_enc_validate_and_set_compressed_img(uhdr_codec_private_t*
   } else if (img->capacity < img->data_sz) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail, "img->capacity %d is less than img->data_sz %d",
+    snprintf(status.detail, sizeof status.detail, "img->capacity %zd is less than img->data_sz %zd",
              img->capacity, img->data_sz);
   }
   if (status.error_code != UHDR_CODEC_OK) return status;
@@ -590,7 +657,7 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_gamma(uhdr_codec_private_t* e
     return status;
   }
 
-  if (gamma <= 0.0f) {
+  if (!std::isfinite(gamma) || gamma <= 0.0f) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail, "unsupported gainmap gamma %f, expects to be > 0",
@@ -660,6 +727,16 @@ uhdr_error_info_t uhdr_enc_set_min_max_content_boost(uhdr_codec_private_t* enc,
     return status;
   }
 
+  if (!std::isfinite(min_boost) || !std::isfinite(max_boost)) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received an argument with value either NaN or infinite. Configured min boost %f, "
+             "max boost %f",
+             max_boost, min_boost);
+    return status;
+  }
+
   if (max_boost < min_boost) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
@@ -670,11 +747,11 @@ uhdr_error_info_t uhdr_enc_set_min_max_content_boost(uhdr_codec_private_t* enc,
     return status;
   }
 
-  if (min_boost < 0) {
+  if (min_boost <= 0.0f) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
-             "Invalid min boost configuration. configured min boost %f is less than 0", min_boost);
+             "Invalid min boost configuration %f, expects > 0.0f", min_boost);
     return status;
   }
 
@@ -695,6 +772,42 @@ uhdr_error_info_t uhdr_enc_set_min_max_content_boost(uhdr_codec_private_t* enc,
   return status;
 }
 
+uhdr_error_info_t uhdr_enc_set_target_display_peak_brightness(uhdr_codec_private_t* enc,
+                                                              float nits) {
+  uhdr_error_info_t status = g_no_error;
+
+  if (dynamic_cast<uhdr_encoder_private*>(enc) == nullptr) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
+    return status;
+  }
+
+  if (!std::isfinite(nits) || nits < ultrahdr::kSdrWhiteNits || nits > ultrahdr::kPqMaxNits) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(
+        status.detail, sizeof status.detail,
+        "unexpected target display peak brightness nits %f, expects to be with in range [%f, %f]",
+        nits, ultrahdr::kSdrWhiteNits, ultrahdr::kPqMaxNits);
+  }
+
+  uhdr_encoder_private* handle = dynamic_cast<uhdr_encoder_private*>(enc);
+
+  if (handle->m_sailed) {
+    status.error_code = UHDR_CODEC_INVALID_OPERATION;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "An earlier call to uhdr_encode() has switched the context from configurable state to "
+             "end state. The context is no longer configurable. To reuse, call reset()");
+    return status;
+  }
+
+  handle->m_target_disp_max_brightness = nits;
+
+  return status;
+}
+
 uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_image_t* img,
                                          uhdr_img_label_t intent) {
   uhdr_error_info_t status = g_no_error;
@@ -713,12 +826,14 @@ uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_ima
     snprintf(status.detail, sizeof status.detail,
              "invalid intent %d, expects one of {UHDR_HDR_IMG, UHDR_SDR_IMG}", intent);
   } else if (intent == UHDR_HDR_IMG && (img->fmt != UHDR_IMG_FMT_24bppYCbCrP010 &&
-                                        img->fmt != UHDR_IMG_FMT_32bppRGBA1010102)) {
+                                        img->fmt != UHDR_IMG_FMT_32bppRGBA1010102 &&
+                                        img->fmt != UHDR_IMG_FMT_64bppRGBAHalfFloat)) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
              "unsupported input pixel format for hdr intent %d, expects one of "
-             "{UHDR_IMG_FMT_24bppYCbCrP010, UHDR_IMG_FMT_32bppRGBA1010102}",
+             "{UHDR_IMG_FMT_24bppYCbCrP010, UHDR_IMG_FMT_32bppRGBA1010102, "
+             "UHDR_IMG_FMT_64bppRGBAHalfFloat}",
              img->fmt);
   } else if (intent == UHDR_SDR_IMG &&
              (img->fmt != UHDR_IMG_FMT_12bppYCbCr420 && img->fmt != UHDR_IMG_FMT_32bppRGBA8888)) {
@@ -741,14 +856,22 @@ uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_ima
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
              "invalid input color transfer for sdr intent image %d, expects UHDR_CT_SRGB", img->ct);
-  } else if (intent == UHDR_HDR_IMG &&
-             (img->ct != UHDR_CT_HLG && img->ct != UHDR_CT_LINEAR && img->ct != UHDR_CT_PQ)) {
+  } else if (intent == UHDR_HDR_IMG && img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat &&
+             img->ct != UHDR_CT_LINEAR) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
-             "invalid input color transfer for hdr intent image %d, expects one of {UHDR_CT_HLG, "
-             "UHDR_CT_LINEAR, UHDR_CT_PQ}",
+             "invalid input color transfer for hdr intent image %d with format "
+             "UHDR_IMG_FMT_64bppRGBAHalfFloat, expects one of {UHDR_CT_LINEAR}",
              img->ct);
+  } else if (intent == UHDR_HDR_IMG && img->fmt != UHDR_IMG_FMT_64bppRGBAHalfFloat &&
+             (img->ct != UHDR_CT_HLG && img->ct != UHDR_CT_PQ)) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "invalid input color transfer for hdr intent image %d with format %d, expects one of "
+             "{UHDR_CT_HLG, UHDR_CT_PQ}",
+             img->fmt, img->ct);
   } else if ((img->w % 2 != 0 || img->h % 2 != 0) &&
              (img->fmt == UHDR_IMG_FMT_12bppYCbCr420 || img->fmt == UHDR_IMG_FMT_24bppYCbCrP010)) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
@@ -832,7 +955,8 @@ uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_ima
       snprintf(status.detail, sizeof status.detail,
                "invalid range, expects one of {UHDR_CR_FULL_RANGE}");
     }
-  } else if (img->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || img->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
+  } else if (img->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || img->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
+             img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
     if (img->planes[UHDR_PLANE_PACKED] == nullptr) {
       status.error_code = UHDR_CODEC_INVALID_PARAM;
       status.has_detail = 1;
@@ -921,47 +1045,7 @@ uhdr_error_info_t uhdr_enc_set_compressed_image(uhdr_codec_private_t* enc,
 uhdr_error_info_t uhdr_enc_set_gainmap_image(uhdr_codec_private_t* enc,
                                              uhdr_compressed_image_t* img,
                                              uhdr_gainmap_metadata_t* metadata) {
-  uhdr_error_info_t status = g_no_error;
-
-  if (metadata == nullptr) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received nullptr for gainmap metadata descriptor");
-  } else if (metadata->max_content_boost < metadata->min_content_boost) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for content boost min %f > max %f", metadata->min_content_boost,
-             metadata->max_content_boost);
-  } else if (metadata->gamma <= 0.0f) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail, "received bad value for gamma %f, expects > 0.0f",
-             metadata->gamma);
-  } else if (metadata->offset_sdr < 0.0f) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for offset sdr %f, expects to be >= 0.0f", metadata->offset_sdr);
-  } else if (metadata->offset_hdr < 0.0f) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for offset hdr %f, expects to be >= 0.0f", metadata->offset_hdr);
-  } else if (metadata->hdr_capacity_max < metadata->hdr_capacity_min) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for hdr capacity min %f > max %f", metadata->hdr_capacity_min,
-             metadata->hdr_capacity_max);
-  } else if (metadata->hdr_capacity_min < 1.0f) {
-    status.error_code = UHDR_CODEC_INVALID_PARAM;
-    status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail,
-             "received bad value for hdr capacity min %f, expects to be >= 1.0f",
-             metadata->hdr_capacity_min);
-  }
+  uhdr_error_info_t status = ultrahdr::uhdr_validate_gainmap_metadata_descriptor(metadata);
   if (status.error_code != UHDR_CODEC_OK) return status;
 
   status = uhdr_enc_validate_and_set_compressed_img(enc, img, UHDR_GAIN_MAP_IMG);
@@ -1030,8 +1114,8 @@ uhdr_error_info_t uhdr_enc_set_exif_data(uhdr_codec_private_t* enc, uhdr_mem_blo
   } else if (exif->capacity < exif->data_sz) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail, "exif->capacity %d is less than exif->data_sz %d",
-             exif->capacity, exif->data_sz);
+    snprintf(status.detail, sizeof status.detail,
+             "exif->capacity %zd is less than exif->data_sz %zd", exif->capacity, exif->data_sz);
   }
   if (status.error_code != UHDR_CODEC_OK) return status;
 
@@ -1153,16 +1237,18 @@ uhdr_error_info_t uhdr_encode(uhdr_codec_private_t* enc) {
       exif.capacity = exif.data_sz = handle->m_exif.size();
     }
 
-    ultrahdr::JpegR jpegr(
-        nullptr, handle->m_gainmap_scale_factor, handle->m_quality.find(UHDR_GAIN_MAP_IMG)->second,
-        handle->m_use_multi_channel_gainmap, handle->m_gamma, handle->m_enc_preset,
-        handle->m_min_content_boost, handle->m_max_content_boost);
+    ultrahdr::JpegR jpegr(nullptr, handle->m_gainmap_scale_factor,
+                          handle->m_quality.find(UHDR_GAIN_MAP_IMG)->second,
+                          handle->m_use_multi_channel_gainmap, handle->m_gamma,
+                          handle->m_enc_preset, handle->m_min_content_boost,
+                          handle->m_max_content_boost, handle->m_target_disp_max_brightness);
     if (handle->m_compressed_images.find(UHDR_BASE_IMG) != handle->m_compressed_images.end() &&
         handle->m_compressed_images.find(UHDR_GAIN_MAP_IMG) != handle->m_compressed_images.end()) {
       auto& base_entry = handle->m_compressed_images.find(UHDR_BASE_IMG)->second;
       auto& gainmap_entry = handle->m_compressed_images.find(UHDR_GAIN_MAP_IMG)->second;
 
-      size_t size = (std::max)((8u * 1024), 2 * (base_entry->data_sz + gainmap_entry->data_sz));
+      size_t size =
+          (std::max)(((size_t)8 * 1024), 2 * (base_entry->data_sz + gainmap_entry->data_sz));
       handle->m_compressed_output_buffer = std::make_unique<ultrahdr::uhdr_compressed_image_ext_t>(
           UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, size);
 
@@ -1259,6 +1345,7 @@ void uhdr_reset_encoder(uhdr_codec_private_t* enc) {
     handle->m_enc_preset = ultrahdr::kEncSpeedPresetDefault;
     handle->m_min_content_boost = FLT_MIN;
     handle->m_max_content_boost = FLT_MAX;
+    handle->m_target_disp_max_brightness = -1.0f;
 
     handle->m_compressed_output_buffer.reset();
     handle->m_encode_call_status = g_no_error;
@@ -1328,7 +1415,7 @@ uhdr_error_info_t uhdr_dec_set_image(uhdr_codec_private_t* dec, uhdr_compressed_
   } else if (img->capacity < img->data_sz) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
-    snprintf(status.detail, sizeof status.detail, "img->capacity %d is less than img->data_sz %d",
+    snprintf(status.detail, sizeof status.detail, "img->capacity %zd is less than img->data_sz %zd",
              img->capacity, img->data_sz);
   }
   if (status.error_code != UHDR_CODEC_OK) return status;
@@ -1425,7 +1512,7 @@ uhdr_error_info_t uhdr_dec_set_out_max_display_boost(uhdr_codec_private_t* dec,
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
-  } else if (display_boost < 1.0f) {
+  } else if (!std::isfinite(display_boost) || display_boost < 1.0f) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
diff --git a/tests/editorhelper_test.cpp b/tests/editorhelper_test.cpp
index a59c921..c2f8ce5 100644
--- a/tests/editorhelper_test.cpp
+++ b/tests/editorhelper_test.cpp
@@ -333,28 +333,28 @@ TEST_P(EditorHelperTest, Crop) {
                     std::to_string(height) + " format: " + std::to_string(fmt);
   initImageHandle(&img_a, width, height, fmt);
   ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
-  uhdr_raw_image_t img_copy = img_a;
+  ultrahdr::uhdr_crop_effect_t crop(left, left + crop_wd, top, top + crop_ht);
 #ifdef UHDR_ENABLE_GLES
   if (gl_ctxt != nullptr) {
     Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
     texture = static_cast<void*>(&Texture);
   }
 #endif
-  apply_crop(&img_copy, left, top, crop_wd, crop_ht, gl_ctxt, texture);
+  auto dst = apply_crop(&crop, &img_a, left, top, crop_wd, crop_ht, gl_ctxt, texture);
 #ifdef UHDR_ENABLE_GLES
   if (gl_ctxt != nullptr) {
-    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), img_copy.fmt, img_copy.w, img_copy.h,
-                              img_copy.planes[0]);
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
+                              dst->planes[0]);
   }
 #endif
-  ASSERT_EQ(img_a.fmt, img_copy.fmt) << msg;
-  ASSERT_EQ(img_a.cg, img_copy.cg) << msg;
-  ASSERT_EQ(img_a.ct, img_copy.ct) << msg;
-  ASSERT_EQ(img_a.range, img_copy.range) << msg;
-  ASSERT_EQ(img_copy.w, crop_wd) << msg;
-  ASSERT_EQ(img_copy.h, crop_ht) << msg;
+  ASSERT_EQ(img_a.fmt, dst->fmt) << msg;
+  ASSERT_EQ(img_a.cg, dst->cg) << msg;
+  ASSERT_EQ(img_a.ct, dst->ct) << msg;
+  ASSERT_EQ(img_a.range, dst->range) << msg;
+  ASSERT_EQ(dst->w, crop_wd) << msg;
+  ASSERT_EQ(dst->h, crop_ht) << msg;
 #ifdef DUMP_OUTPUT
-  if (!writeFile("cropped", &img_copy)) {
+  if (!writeFile("cropped", dst.get())) {
     std::cerr << "unable to write output file" << std::endl;
   }
 #endif
@@ -470,20 +470,20 @@ TEST_P(EditorHelperTest, MultipleEffects) {
                         std::to_string(dst->w) + " x " + std::to_string(dst->h) +
                         " format: " + std::to_string(fmt);
   }
-  uhdr_raw_image_ext_t* img_copy = dst.get();
-  apply_crop(img_copy, left, top, crop_wd, crop_ht, gl_ctxt, texture);
+  ultrahdr::uhdr_crop_effect_t crop(left, left + crop_wd, top, top + crop_ht);
+  dst = apply_crop(&crop, dst.get(), left, top, crop_wd, crop_ht, gl_ctxt, texture);
 #ifdef UHDR_ENABLE_GLES
   if (gl_ctxt != nullptr) {
-    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), img_copy->fmt, img_copy->w,
-                              img_copy->h, img_copy->planes[0]);
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
+                              dst->planes[0]);
   }
 #endif
-  ASSERT_EQ(dst->fmt, img_copy->fmt) << msg;
-  ASSERT_EQ(dst->cg, img_copy->cg) << msg;
-  ASSERT_EQ(dst->ct, img_copy->ct) << msg;
-  ASSERT_EQ(dst->range, img_copy->range) << msg;
-  ASSERT_EQ(crop_wd, img_copy->w) << msg;
-  ASSERT_EQ(crop_ht, img_copy->h) << msg;
+  ASSERT_EQ(img_a.fmt, dst->fmt) << msg;
+  ASSERT_EQ(img_a.cg, dst->cg) << msg;
+  ASSERT_EQ(img_a.ct, dst->ct) << msg;
+  ASSERT_EQ(img_a.range, dst->range) << msg;
+  ASSERT_EQ(crop_wd, dst->w) << msg;
+  ASSERT_EQ(crop_ht, dst->h) << msg;
 }
 
 INSTANTIATE_TEST_SUITE_P(
diff --git a/tests/gainmapmath_test.cpp b/tests/gainmapmath_test.cpp
index 9bf9eab..91d942a 100644
--- a/tests/gainmapmath_test.cpp
+++ b/tests/gainmapmath_test.cpp
@@ -124,14 +124,14 @@ class GainMapMathTest : public testing::Test {
   Pixel Bt2100YuvGreenPixel() { return {173, -92, -117}; }
   Pixel Bt2100YuvBluePixel() { return {15, 128, -10}; }
 
-  float SrgbYuvToLuminance(Color yuv_gamma, ColorCalculationFn luminanceFn) {
+  float SrgbYuvToLuminance(Color yuv_gamma, LuminanceFn luminanceFn) {
     Color rgb_gamma = srgbYuvToRgb(yuv_gamma);
     Color rgb = srgbInvOetf(rgb_gamma);
     float luminance_scaled = luminanceFn(rgb);
     return luminance_scaled * kSdrWhiteNits;
   }
 
-  float P3YuvToLuminance(Color yuv_gamma, ColorCalculationFn luminanceFn) {
+  float P3YuvToLuminance(Color yuv_gamma, LuminanceFn luminanceFn) {
     Color rgb_gamma = p3YuvToRgb(yuv_gamma);
     Color rgb = srgbInvOetf(rgb_gamma);
     float luminance_scaled = luminanceFn(rgb);
@@ -139,7 +139,7 @@ class GainMapMathTest : public testing::Test {
   }
 
   float Bt2100YuvToLuminance(Color yuv_gamma, ColorTransformFn hdrInvOetf,
-                             ColorTransformFn gamutConversionFn, ColorCalculationFn luminanceFn,
+                             ColorTransformFn gamutConversionFn, LuminanceFn luminanceFn,
                              float scale_factor) {
     Color rgb_gamma = bt2100YuvToRgb(yuv_gamma);
     Color rgb = hdrInvOetf(rgb_gamma);
@@ -1126,108 +1126,117 @@ TEST_F(GainMapMathTest, srgbInvOetfLUT) {
 }
 
 TEST_F(GainMapMathTest, applyGainLUT) {
-  for (int boost = 1; boost <= 10; boost++) {
+  for (float boost = 1.5; boost <= 12; boost++) {
     uhdr_gainmap_metadata_ext_t metadata;
 
-    metadata.min_content_boost = 1.0f / static_cast<float>(boost);
-    metadata.max_content_boost = static_cast<float>(boost);
+    metadata.min_content_boost = 1.0f / boost;
+    metadata.max_content_boost = boost;
     metadata.gamma = 1.0f;
     metadata.hdr_capacity_max = metadata.max_content_boost;
     metadata.hdr_capacity_min = metadata.min_content_boost;
     GainLUT gainLUT(&metadata);
-    GainLUT gainLUTWithBoost(&metadata, metadata.max_content_boost);
+    float weight = (log2(boost) - log2(metadata.hdr_capacity_min)) /
+                   (log2(metadata.hdr_capacity_max) - log2(metadata.hdr_capacity_min));
+    weight = CLIP3(weight, 0.0f, 1.0f);
+    GainLUT gainLUTWithBoost(&metadata, weight);
     for (size_t idx = 0; idx < kGainFactorNumEntries; idx++) {
       float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
       EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata),
-                      applyGainLUT(RgbBlack(), value, gainLUT));
+                      applyGainLUT(RgbBlack(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbWhite(), value, &metadata),
-                      applyGainLUT(RgbWhite(), value, gainLUT));
+                      applyGainLUT(RgbWhite(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbRed(), value, &metadata),
-                      applyGainLUT(RgbRed(), value, gainLUT));
+                      applyGainLUT(RgbRed(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbGreen(), value, &metadata),
-                      applyGainLUT(RgbGreen(), value, gainLUT));
+                      applyGainLUT(RgbGreen(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbBlue(), value, &metadata),
-                      applyGainLUT(RgbBlue(), value, gainLUT));
-      EXPECT_RGB_EQ(applyGainLUT(RgbBlack(), value, gainLUT),
-                    applyGainLUT(RgbBlack(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbWhite(), value, gainLUT),
-                    applyGainLUT(RgbWhite(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbRed(), value, gainLUT),
-                    applyGainLUT(RgbRed(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbGreen(), value, gainLUT),
-                    applyGainLUT(RgbGreen(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbBlue(), value, gainLUT),
-                    applyGainLUT(RgbBlue(), value, gainLUTWithBoost));
+                      applyGainLUT(RgbBlue(), value, gainLUT, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata, weight),
+                      applyGainLUT(RgbBlack(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbWhite(), value, &metadata, weight),
+                      applyGainLUT(RgbWhite(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbRed(), value, &metadata, weight),
+                      applyGainLUT(RgbRed(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbGreen(), value, &metadata, weight),
+                      applyGainLUT(RgbGreen(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbBlue(), value, &metadata, weight),
+                      applyGainLUT(RgbBlue(), value, gainLUTWithBoost, &metadata));
     }
   }
 
-  for (int boost = 1; boost <= 10; boost++) {
+  for (float boost = 1.5; boost <= 12; boost++) {
     uhdr_gainmap_metadata_ext_t metadata;
 
     metadata.min_content_boost = 1.0f;
-    metadata.max_content_boost = static_cast<float>(boost);
+    metadata.max_content_boost = boost;
     metadata.gamma = 1.0f;
     metadata.hdr_capacity_max = metadata.max_content_boost;
     metadata.hdr_capacity_min = metadata.min_content_boost;
     GainLUT gainLUT(&metadata);
-    GainLUT gainLUTWithBoost(&metadata, metadata.max_content_boost);
+    float weight = (log2(boost) - log2(metadata.hdr_capacity_min)) /
+                   (log2(metadata.hdr_capacity_max) - log2(metadata.hdr_capacity_min));
+    weight = CLIP3(weight, 0.0f, 1.0f);
+    GainLUT gainLUTWithBoost(&metadata, weight);
     for (size_t idx = 0; idx < kGainFactorNumEntries; idx++) {
       float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
       EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata),
-                      applyGainLUT(RgbBlack(), value, gainLUT));
+                      applyGainLUT(RgbBlack(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbWhite(), value, &metadata),
-                      applyGainLUT(RgbWhite(), value, gainLUT));
+                      applyGainLUT(RgbWhite(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbRed(), value, &metadata),
-                      applyGainLUT(RgbRed(), value, gainLUT));
+                      applyGainLUT(RgbRed(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbGreen(), value, &metadata),
-                      applyGainLUT(RgbGreen(), value, gainLUT));
+                      applyGainLUT(RgbGreen(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbBlue(), value, &metadata),
-                      applyGainLUT(RgbBlue(), value, gainLUT));
-      EXPECT_RGB_EQ(applyGainLUT(RgbBlack(), value, gainLUT),
-                    applyGainLUT(RgbBlack(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbWhite(), value, gainLUT),
-                    applyGainLUT(RgbWhite(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbRed(), value, gainLUT),
-                    applyGainLUT(RgbRed(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbGreen(), value, gainLUT),
-                    applyGainLUT(RgbGreen(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbBlue(), value, gainLUT),
-                    applyGainLUT(RgbBlue(), value, gainLUTWithBoost));
+                      applyGainLUT(RgbBlue(), value, gainLUT, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata, weight),
+                      applyGainLUT(RgbBlack(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbWhite(), value, &metadata, weight),
+                      applyGainLUT(RgbWhite(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbRed(), value, &metadata, weight),
+                      applyGainLUT(RgbRed(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbGreen(), value, &metadata, weight),
+                      applyGainLUT(RgbGreen(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbBlue(), value, &metadata, weight),
+                      applyGainLUT(RgbBlue(), value, gainLUTWithBoost, &metadata));
     }
   }
 
-  for (int boost = 1; boost <= 10; boost++) {
+  for (float boost = 1.5; boost <= 12; boost++) {
     uhdr_gainmap_metadata_ext_t metadata;
 
-    metadata.min_content_boost = 1.0f / powf(static_cast<float>(boost), 1.0f / 3.0f);
-    metadata.max_content_boost = static_cast<float>(boost);
+    metadata.min_content_boost = 1.0f / powf(boost, 1.0f / 3.0f);
+    metadata.max_content_boost = boost;
     metadata.gamma = 1.0f;
     metadata.hdr_capacity_max = metadata.max_content_boost;
     metadata.hdr_capacity_min = metadata.min_content_boost;
     GainLUT gainLUT(&metadata);
-    GainLUT gainLUTWithBoost(&metadata, metadata.max_content_boost);
+    float weight = (log2(boost) - log2(metadata.hdr_capacity_min)) /
+                   (log2(metadata.hdr_capacity_max) - log2(metadata.hdr_capacity_min));
+    weight = CLIP3(weight, 0.0f, 1.0f);
+    GainLUT gainLUTWithBoost(&metadata, weight);
     for (size_t idx = 0; idx < kGainFactorNumEntries; idx++) {
       float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
       EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata),
-                      applyGainLUT(RgbBlack(), value, gainLUT));
+                      applyGainLUT(RgbBlack(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbWhite(), value, &metadata),
-                      applyGainLUT(RgbWhite(), value, gainLUT));
+                      applyGainLUT(RgbWhite(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbRed(), value, &metadata),
-                      applyGainLUT(RgbRed(), value, gainLUT));
+                      applyGainLUT(RgbRed(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbGreen(), value, &metadata),
-                      applyGainLUT(RgbGreen(), value, gainLUT));
+                      applyGainLUT(RgbGreen(), value, gainLUT, &metadata));
       EXPECT_RGB_NEAR(applyGain(RgbBlue(), value, &metadata),
-                      applyGainLUT(RgbBlue(), value, gainLUT));
-      EXPECT_RGB_EQ(applyGainLUT(RgbBlack(), value, gainLUT),
-                    applyGainLUT(RgbBlack(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbWhite(), value, gainLUT),
-                    applyGainLUT(RgbWhite(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbRed(), value, gainLUT),
-                    applyGainLUT(RgbRed(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbGreen(), value, gainLUT),
-                    applyGainLUT(RgbGreen(), value, gainLUTWithBoost));
-      EXPECT_RGB_EQ(applyGainLUT(RgbBlue(), value, gainLUT),
-                    applyGainLUT(RgbBlue(), value, gainLUTWithBoost));
+                      applyGainLUT(RgbBlue(), value, gainLUT, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata, weight),
+                      applyGainLUT(RgbBlack(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbWhite(), value, &metadata, weight),
+                      applyGainLUT(RgbWhite(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbRed(), value, &metadata, weight),
+                      applyGainLUT(RgbRed(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbGreen(), value, &metadata, weight),
+                      applyGainLUT(RgbGreen(), value, gainLUTWithBoost, &metadata));
+      EXPECT_RGB_NEAR(applyGain(RgbBlue(), value, &metadata, weight),
+                      applyGainLUT(RgbBlue(), value, gainLUTWithBoost, &metadata));
     }
   }
 }
@@ -1325,8 +1334,9 @@ TEST_F(GainMapMathTest, ApplyGain) {
   metadata.max_content_boost = 4.0f;
   metadata.hdr_capacity_max = metadata.max_content_boost;
   metadata.hdr_capacity_min = metadata.min_content_boost;
+  metadata.offset_sdr = 0.0f;
+  metadata.offset_hdr = 0.0f;
   metadata.gamma = 1.0f;
-  float displayBoost = metadata.max_content_boost;
 
   EXPECT_RGB_NEAR(applyGain(RgbBlack(), 0.0f, &metadata), RgbBlack());
   EXPECT_RGB_NEAR(applyGain(RgbBlack(), 0.5f, &metadata), RgbBlack());
@@ -1392,18 +1402,6 @@ TEST_F(GainMapMathTest, ApplyGain) {
   EXPECT_RGB_NEAR(applyGain(e, 0.5f, &metadata), e);
   EXPECT_RGB_NEAR(applyGain(e, 0.75f, &metadata), e * 2.0f);
   EXPECT_RGB_NEAR(applyGain(e, 1.0f, &metadata), e * 4.0f);
-
-  EXPECT_RGB_EQ(applyGain(RgbBlack(), 1.0f, &metadata),
-                applyGain(RgbBlack(), 1.0f, &metadata, displayBoost));
-  EXPECT_RGB_EQ(applyGain(RgbWhite(), 1.0f, &metadata),
-                applyGain(RgbWhite(), 1.0f, &metadata, displayBoost));
-  EXPECT_RGB_EQ(applyGain(RgbRed(), 1.0f, &metadata),
-                applyGain(RgbRed(), 1.0f, &metadata, displayBoost));
-  EXPECT_RGB_EQ(applyGain(RgbGreen(), 1.0f, &metadata),
-                applyGain(RgbGreen(), 1.0f, &metadata, displayBoost));
-  EXPECT_RGB_EQ(applyGain(RgbBlue(), 1.0f, &metadata),
-                applyGain(RgbBlue(), 1.0f, &metadata, displayBoost));
-  EXPECT_RGB_EQ(applyGain(e, 1.0f, &metadata), applyGain(e, 1.0f, &metadata, displayBoost));
 }
 
 TEST_F(GainMapMathTest, GetYuv420Pixel) {
@@ -1629,6 +1627,8 @@ TEST_F(GainMapMathTest, ApplyMap) {
 
   metadata.min_content_boost = 1.0f / 8.0f;
   metadata.max_content_boost = 8.0f;
+  metadata.offset_sdr = 0.0f;
+  metadata.offset_hdr = 0.0f;
   metadata.gamma = 1.0f;
 
   EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
diff --git a/tests/gainmapmetadata_test.cpp b/tests/gainmapmetadata_test.cpp
index 88e9a7c..18eb68e 100644
--- a/tests/gainmapmetadata_test.cpp
+++ b/tests/gainmapmetadata_test.cpp
@@ -46,31 +46,64 @@ TEST_F(GainMapMetadataTest, encodeMetadataThenDecode) {
   expected.max_content_boost = 100.5f;
   expected.min_content_boost = 1.5f;
   expected.gamma = 1.0f;
-  expected.offset_sdr = 0.0f;
-  expected.offset_hdr = 0.0f;
+  expected.offset_sdr = 0.0625f;
+  expected.offset_hdr = 0.0625f;
   expected.hdr_capacity_min = 1.0f;
-  expected.hdr_capacity_max = expected.max_content_boost;
+  expected.hdr_capacity_max = 10000.0f / 203.0f;
 
   uhdr_gainmap_metadata_frac metadata;
-  uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(&expected, &metadata);
+  EXPECT_EQ(
+      uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(&expected, &metadata).error_code,
+      UHDR_CODEC_OK);
   //  metadata.dump();
 
   std::vector<uint8_t> data;
-  uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata, data);
+  EXPECT_EQ(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata, data).error_code,
+            UHDR_CODEC_OK);
 
   uhdr_gainmap_metadata_frac decodedMetadata;
-  uhdr_gainmap_metadata_frac::decodeGainmapMetadata(data, &decodedMetadata);
+  EXPECT_EQ(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(data, &decodedMetadata).error_code,
+            UHDR_CODEC_OK);
 
   uhdr_gainmap_metadata_ext_t decodedUHdrMetadata;
-  uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decodedMetadata,
-                                                             &decodedUHdrMetadata);
-
-  EXPECT_EQ(expected.max_content_boost, decodedUHdrMetadata.max_content_boost);
-  EXPECT_EQ(expected.min_content_boost, decodedUHdrMetadata.min_content_boost);
-  EXPECT_EQ(expected.gamma, decodedUHdrMetadata.gamma);
-  EXPECT_EQ(expected.offset_sdr, decodedUHdrMetadata.offset_sdr);
-  EXPECT_EQ(expected.offset_hdr, decodedUHdrMetadata.offset_hdr);
-  EXPECT_EQ(expected.hdr_capacity_min, decodedUHdrMetadata.hdr_capacity_min);
-  EXPECT_EQ(expected.hdr_capacity_max, decodedUHdrMetadata.hdr_capacity_max);
+  EXPECT_EQ(uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decodedMetadata,
+                                                                       &decodedUHdrMetadata)
+                .error_code,
+            UHDR_CODEC_OK);
+
+  EXPECT_FLOAT_EQ(expected.max_content_boost, decodedUHdrMetadata.max_content_boost);
+  EXPECT_FLOAT_EQ(expected.min_content_boost, decodedUHdrMetadata.min_content_boost);
+  EXPECT_FLOAT_EQ(expected.gamma, decodedUHdrMetadata.gamma);
+  EXPECT_FLOAT_EQ(expected.offset_sdr, decodedUHdrMetadata.offset_sdr);
+  EXPECT_FLOAT_EQ(expected.offset_hdr, decodedUHdrMetadata.offset_hdr);
+  EXPECT_FLOAT_EQ(expected.hdr_capacity_min, decodedUHdrMetadata.hdr_capacity_min);
+  EXPECT_FLOAT_EQ(expected.hdr_capacity_max, decodedUHdrMetadata.hdr_capacity_max);
+
+  data.clear();
+  expected.min_content_boost = 0.000578369f;
+  expected.offset_sdr = -0.0625f;
+  expected.offset_hdr = -0.0625f;
+  expected.hdr_capacity_max = 1000.0f / 203.0f;
+
+  EXPECT_EQ(
+      uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(&expected, &metadata).error_code,
+      UHDR_CODEC_OK);
+  EXPECT_EQ(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata, data).error_code,
+            UHDR_CODEC_OK);
+  EXPECT_EQ(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(data, &decodedMetadata).error_code,
+            UHDR_CODEC_OK);
+  EXPECT_EQ(uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decodedMetadata,
+                                                                       &decodedUHdrMetadata)
+                .error_code,
+            UHDR_CODEC_OK);
+
+  EXPECT_FLOAT_EQ(expected.max_content_boost, decodedUHdrMetadata.max_content_boost);
+  EXPECT_FLOAT_EQ(expected.min_content_boost, decodedUHdrMetadata.min_content_boost);
+  EXPECT_FLOAT_EQ(expected.gamma, decodedUHdrMetadata.gamma);
+  EXPECT_FLOAT_EQ(expected.offset_sdr, decodedUHdrMetadata.offset_sdr);
+  EXPECT_FLOAT_EQ(expected.offset_hdr, decodedUHdrMetadata.offset_hdr);
+  EXPECT_FLOAT_EQ(expected.hdr_capacity_min, decodedUHdrMetadata.hdr_capacity_min);
+  EXPECT_FLOAT_EQ(expected.hdr_capacity_max, decodedUHdrMetadata.hdr_capacity_max);
 }
+
 }  // namespace ultrahdr
diff --git a/tests/jpegencoderhelper_test.cpp b/tests/jpegencoderhelper_test.cpp
index 703d085..0783ab2 100644
--- a/tests/jpegencoderhelper_test.cpp
+++ b/tests/jpegencoderhelper_test.cpp
@@ -47,8 +47,8 @@ class JpegEncoderHelperTest : public testing::Test {
  public:
   struct Image {
     std::unique_ptr<uint8_t[]> buffer;
-    size_t width;
-    size_t height;
+    unsigned int width;
+    unsigned int height;
   };
   JpegEncoderHelperTest();
   ~JpegEncoderHelperTest();
@@ -108,7 +108,8 @@ TEST_F(JpegEncoderHelperTest, encodeAlignedImage) {
   const uint8_t* uPlane = yPlane + mAlignedImage.width * mAlignedImage.height;
   const uint8_t* vPlane = uPlane + mAlignedImage.width * mAlignedImage.height / 4;
   const uint8_t* planes[3]{yPlane, uPlane, vPlane};
-  const size_t strides[3]{mAlignedImage.width, mAlignedImage.width / 2, mAlignedImage.width / 2};
+  const unsigned int strides[3]{mAlignedImage.width, mAlignedImage.width / 2,
+                                mAlignedImage.width / 2};
   EXPECT_EQ(encoder
                 .compressImage(planes, strides, mAlignedImage.width, mAlignedImage.height,
                                UHDR_IMG_FMT_12bppYCbCr420, JPEG_QUALITY, NULL, 0)
@@ -123,8 +124,8 @@ TEST_F(JpegEncoderHelperTest, encodeUnalignedImage) {
   const uint8_t* uPlane = yPlane + mUnalignedImage.width * mUnalignedImage.height;
   const uint8_t* vPlane = uPlane + mUnalignedImage.width * mUnalignedImage.height / 4;
   const uint8_t* planes[3]{yPlane, uPlane, vPlane};
-  const size_t strides[3]{mUnalignedImage.width, mUnalignedImage.width / 2,
-                          mUnalignedImage.width / 2};
+  const unsigned int strides[3]{mUnalignedImage.width, mUnalignedImage.width / 2,
+                                mUnalignedImage.width / 2};
   EXPECT_EQ(encoder
                 .compressImage(planes, strides, mUnalignedImage.width, mUnalignedImage.height,
                                UHDR_IMG_FMT_12bppYCbCr420, JPEG_QUALITY, NULL, 0)
@@ -137,7 +138,7 @@ TEST_F(JpegEncoderHelperTest, encodeSingleChannelImage) {
   JpegEncoderHelper encoder;
   const uint8_t* yPlane = mSingleChannelImage.buffer.get();
   const uint8_t* planes[1]{yPlane};
-  const size_t strides[1]{mSingleChannelImage.width};
+  const unsigned int strides[1]{mSingleChannelImage.width};
   EXPECT_EQ(
       encoder
           .compressImage(planes, strides, mSingleChannelImage.width, mSingleChannelImage.height,
@@ -151,7 +152,7 @@ TEST_F(JpegEncoderHelperTest, encodeRGBImage) {
   JpegEncoderHelper encoder;
   const uint8_t* rgbPlane = mRgbImage.buffer.get();
   const uint8_t* planes[1]{rgbPlane};
-  const size_t strides[1]{mRgbImage.width};
+  const unsigned int strides[1]{mRgbImage.width};
   EXPECT_EQ(encoder
                 .compressImage(planes, strides, mRgbImage.width, mRgbImage.height,
                                UHDR_IMG_FMT_24bppRGB888, JPEG_QUALITY, NULL, 0)
diff --git a/tests/jpegr_test.cpp b/tests/jpegr_test.cpp
index dc4cde5..82db6bf 100644
--- a/tests/jpegr_test.cpp
+++ b/tests/jpegr_test.cpp
@@ -66,11 +66,11 @@ typedef enum {
  */
 class UhdrUnCompressedStructWrapper {
  public:
-  UhdrUnCompressedStructWrapper(size_t width, size_t height, UhdrInputFormat format);
+  UhdrUnCompressedStructWrapper(unsigned int width, unsigned int height, UhdrInputFormat format);
   ~UhdrUnCompressedStructWrapper() = default;
 
   bool setChromaMode(bool isChromaContiguous);
-  bool setImageStride(size_t lumaStride, size_t chromaStride);
+  bool setImageStride(unsigned int lumaStride, unsigned int chromaStride);
   bool setImageColorGamut(ultrahdr_color_gamut colorGamut);
   bool allocateMemory();
   bool loadRawResource(const char* fileName);
@@ -92,7 +92,7 @@ class UhdrUnCompressedStructWrapper {
  */
 class UhdrCompressedStructWrapper {
  public:
-  UhdrCompressedStructWrapper(size_t width, size_t height);
+  UhdrCompressedStructWrapper(unsigned int width, unsigned int height);
   ~UhdrCompressedStructWrapper() = default;
 
   bool allocateMemory();
@@ -101,11 +101,12 @@ class UhdrCompressedStructWrapper {
  private:
   std::unique_ptr<uint8_t[]> mData;
   jpegr_compressed_struct mImg{};
-  size_t mWidth;
-  size_t mHeight;
+  unsigned int mWidth;
+  unsigned int mHeight;
 };
 
-UhdrUnCompressedStructWrapper::UhdrUnCompressedStructWrapper(size_t width, size_t height,
+UhdrUnCompressedStructWrapper::UhdrUnCompressedStructWrapper(unsigned int width,
+                                                             unsigned int height,
                                                              UhdrInputFormat format) {
   mImg.data = nullptr;
   mImg.width = width;
@@ -127,7 +128,8 @@ bool UhdrUnCompressedStructWrapper::setChromaMode(bool isChromaContiguous) {
   return true;
 }
 
-bool UhdrUnCompressedStructWrapper::setImageStride(size_t lumaStride, size_t chromaStride) {
+bool UhdrUnCompressedStructWrapper::setImageStride(unsigned int lumaStride,
+                                                   unsigned int chromaStride) {
   if (mLumaData.get() != nullptr) {
     std::cerr << "Object has sailed, no further modifications are allowed" << std::endl;
     return false;
@@ -255,7 +257,7 @@ bool UhdrUnCompressedStructWrapper::loadRawResource(const char* fileName) {
 
 jr_uncompressed_ptr UhdrUnCompressedStructWrapper::getImageHandle() { return &mImg; }
 
-UhdrCompressedStructWrapper::UhdrCompressedStructWrapper(size_t width, size_t height) {
+UhdrCompressedStructWrapper::UhdrCompressedStructWrapper(unsigned int width, unsigned int height) {
   mWidth = width;
   mHeight = height;
 }
@@ -287,7 +289,7 @@ static bool writeFile(const char* filename, void*& result, int length) {
 }
 #endif
 
-static bool readFile(const char* fileName, void*& result, int maxLength, int& length) {
+static bool readFile(const char* fileName, void*& result, size_t maxLength, size_t& length) {
   std::ifstream ifd(fileName, std::ios::binary | std::ios::ate);
   if (ifd.good()) {
     length = ifd.tellg();
@@ -1409,7 +1411,7 @@ TEST(JpegRTest, writeXmpThenRead) {
   metadata_expected.hdr_capacity_min = 1.0f;
   metadata_expected.hdr_capacity_max = metadata_expected.max_content_boost;
   const std::string nameSpace = "http://ns.adobe.com/xap/1.0/\0";
-  const int nameSpaceLength = nameSpace.size() + 1;  // need to count the null terminator
+  const size_t nameSpaceLength = nameSpace.size() + 1;  // need to count the null terminator
 
   std::string xmp = generateXmpForSecondaryImage(metadata_expected);
 
@@ -2209,7 +2211,7 @@ class Profiler {
 
   void timerStop() { QueryPerformanceCounter(&mEndingTime); }
 
-  int64_t elapsedTime() {
+  double elapsedTime() {
     LARGE_INTEGER frequency;
     LARGE_INTEGER elapsedMicroseconds;
     QueryPerformanceFrequency(&frequency);
diff --git a/ultrahdr_api.h b/ultrahdr_api.h
index d2d3627..6a6edec 100644
--- a/ultrahdr_api.h
+++ b/ultrahdr_api.h
@@ -23,6 +23,8 @@
 #ifndef ULTRAHDR_API_H
 #define ULTRAHDR_API_H
 
+#include <stddef.h>
+
 #if defined(_WIN32) || defined(__CYGWIN__)
 #if defined(UHDR_BUILDING_SHARED_LIBRARY)
 #define UHDR_API __declspec(dllexport)
@@ -69,11 +71,12 @@
  *   1.2.0           1.2.0                       Some bug fixes, introduced new API and renamed
  *                                               existing API which warrants a major version update.
  *                                               But indicated as a minor update.
+ *   1.3.0           1.3.0                       Some bug fixes, introduced new API.
  */
 
 // This needs to be kept in sync with version in CMakeLists.txt
 #define UHDR_LIB_VER_MAJOR 1
-#define UHDR_LIB_VER_MINOR 2
+#define UHDR_LIB_VER_MINOR 3
 #define UHDR_LIB_VER_PATCH 0
 
 #define UHDR_LIB_VERSION \
@@ -100,20 +103,23 @@ typedef enum uhdr_img_fmt {
       3, /**< 32 bits per pixel RGBA color format, with 8-bit red, green, blue
         and alpha components. Using 32-bit little-endian representation,
         colors stored as Red 7:0, Green 15:8, Blue 23:16, Alpha 31:24. */
-  UHDR_IMG_FMT_64bppRGBAHalfFloat = 4, /**< 64 bits per pixel RGBA color format, with 16-bit signed
-                                   floating point red, green, blue, and alpha components */
-  UHDR_IMG_FMT_32bppRGBA1010102 = 5,   /**< 32 bits per pixel RGBA color format, with 10-bit red,
-                                      green,   blue, and 2-bit alpha components. Using 32-bit
-                                      little-endian   representation, colors stored as Red 9:0, Green
-                                      19:10, Blue   29:20, and Alpha 31:30. */
-  UHDR_IMG_FMT_24bppYCbCr444 = 6,      /**< 8-bit-per component 4:4:4 YCbCr planar format */
-  UHDR_IMG_FMT_16bppYCbCr422 = 7,      /**< 8-bit-per component 4:2:2 YCbCr planar format */
-  UHDR_IMG_FMT_16bppYCbCr440 = 8,      /**< 8-bit-per component 4:4:0 YCbCr planar format */
-  UHDR_IMG_FMT_12bppYCbCr411 = 9,      /**< 8-bit-per component 4:1:1 YCbCr planar format */
-  UHDR_IMG_FMT_10bppYCbCr410 = 10,     /**< 8-bit-per component 4:1:0 YCbCr planar format */
-  UHDR_IMG_FMT_24bppRGB888 = 11,       /**< 8-bit-per component RGB interleaved format */
-  UHDR_IMG_FMT_30bppYCbCr444 = 12,     /**< 10-bit-per component 4:4:4 YCbCr planar format */
-} uhdr_img_fmt_t;                      /**< alias for enum uhdr_img_fmt */
+  UHDR_IMG_FMT_64bppRGBAHalfFloat =
+      4, /**< 64 bits per pixel, 16 bits per channel, half-precision floating point RGBA color
+            format. colors stored as Red 15:0, Green 31:16, Blue 47:32, Alpha 63:48. In a pixel
+            even though each channel has storage space of 16 bits, the nominal range is expected to
+            be [0.0..(10000/203)] */
+  UHDR_IMG_FMT_32bppRGBA1010102 = 5, /**< 32 bits per pixel RGBA color format, with 10-bit red,
+                                    green,   blue, and 2-bit alpha components. Using 32-bit
+                                    little-endian   representation, colors stored as Red 9:0, Green
+                                    19:10, Blue   29:20, and Alpha 31:30. */
+  UHDR_IMG_FMT_24bppYCbCr444 = 6,    /**< 8-bit-per component 4:4:4 YCbCr planar format */
+  UHDR_IMG_FMT_16bppYCbCr422 = 7,    /**< 8-bit-per component 4:2:2 YCbCr planar format */
+  UHDR_IMG_FMT_16bppYCbCr440 = 8,    /**< 8-bit-per component 4:4:0 YCbCr planar format */
+  UHDR_IMG_FMT_12bppYCbCr411 = 9,    /**< 8-bit-per component 4:1:1 YCbCr planar format */
+  UHDR_IMG_FMT_10bppYCbCr410 = 10,   /**< 8-bit-per component 4:1:0 YCbCr planar format */
+  UHDR_IMG_FMT_24bppRGB888 = 11,     /**< 8-bit-per component RGB interleaved format */
+  UHDR_IMG_FMT_30bppYCbCr444 = 12,   /**< 10-bit-per component 4:4:4 YCbCr planar format */
+} uhdr_img_fmt_t;                    /**< alias for enum uhdr_img_fmt */
 
 /*!\brief List of supported color gamuts */
 typedef enum uhdr_color_gamut {
@@ -231,8 +237,8 @@ typedef struct uhdr_raw_image {
 /**\brief Compressed Image Descriptor */
 typedef struct uhdr_compressed_image {
   void* data;               /**< Pointer to a block of data to decode */
-  unsigned int data_sz;     /**< size of the data buffer */
-  unsigned int capacity;    /**< maximum size of the data buffer */
+  size_t data_sz;           /**< size of the data buffer */
+  size_t capacity;          /**< maximum size of the data buffer */
   uhdr_color_gamut_t cg;    /**< Color Gamut */
   uhdr_color_transfer_t ct; /**< Color Transfer */
   uhdr_color_range_t range; /**< Color Range */
@@ -240,10 +246,10 @@ typedef struct uhdr_compressed_image {
 
 /**\brief Buffer Descriptor */
 typedef struct uhdr_mem_block {
-  void* data;            /**< Pointer to a block of data to decode */
-  unsigned int data_sz;  /**< size of the data buffer */
-  unsigned int capacity; /**< maximum size of the data buffer */
-} uhdr_mem_block_t;      /**< alias for struct uhdr_mem_block */
+  void* data;       /**< Pointer to a block of data to decode */
+  size_t data_sz;   /**< size of the data buffer */
+  size_t capacity;  /**< maximum size of the data buffer */
+} uhdr_mem_block_t; /**< alias for struct uhdr_mem_block */
 
 /**\brief Gain map metadata. */
 typedef struct uhdr_gainmap_metadata {
@@ -441,6 +447,22 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_gamma(uhdr_codec_private_t* e
 UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_min_max_content_boost(uhdr_codec_private_t* enc,
                                                                  float min_boost, float max_boost);
 
+/*!\brief Set target display peak brightness in nits. This is used for configuring #hdr_capacity_max
+ * of gainmap metadata. This value determines the weight by which the gain map coefficients are
+ * scaled during decode. If this is not configured, then default peak luminance of HDR intent's
+ * color transfer under test is used. For #UHDR_CT_HLG, this corresponds to 1000 nits and for
+ * #UHDR_CT_LINEAR and #UHDR_CT_PQ, this corresponds to 10000 nits.
+ *
+ * \param[in]  enc  encoder instance.
+ * \param[in]  nits  target display peak brightness in nits. Any positive real number in range
+ *                   [203, 10000].
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
+ *                           #UHDR_CODEC_INVALID_PARAM otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_target_display_peak_brightness(uhdr_codec_private_t* enc,
+                                                                          float nits);
+
 /*!\brief Set encoding preset. Tunes the encoder configurations for performance or quality. Default
  * configuration is #UHDR_USAGE_BEST_QUALITY.
  *
@@ -488,6 +510,10 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_output_format(uhdr_codec_private_t* e
  *   - uhdr_enc_set_using_multi_channel_gainmap()
  * - If the application wants to set gainmap image gamma
  *   - uhdr_enc_set_gainmap_gamma()
+ * - If the application wants to recommend min max content boost
+ *   - uhdr_enc_set_min_max_content_boost()
+ * - If the application wants to set target display peak brightness
+ *   - uhdr_enc_set_target_display_peak_brightness()
  * - If the application wants to set encoding preset
  *   - uhdr_enc_set_preset()
  * - If the application wants to control target compression format
@@ -532,6 +558,8 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_output_format(uhdr_codec_private_t* e
  * - uhdr_enc_set_gainmap_scale_factor() // optional
  * - uhdr_enc_set_using_multi_channel_gainmap() // optional
  * - uhdr_enc_set_gainmap_gamma() // optional
+ * - uhdr_enc_set_min_max_content_boost() // optional
+ * - uhdr_enc_set_target_display_peak_brightness() // optional
  * - uhdr_encode()
  * - uhdr_get_encoded_stream()
  * - uhdr_release_encoder()
```

