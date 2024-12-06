```diff
diff --git a/.github/workflows/cmake.yml b/.github/workflows/cmake.yml
deleted file mode 100644
index dd840d2..0000000
--- a/.github/workflows/cmake.yml
+++ /dev/null
@@ -1,95 +0,0 @@
-name: CMake
-
-on:
-  push:
-  pull_request:
-
-env:
-  BUILD_TYPE: Release
-
-jobs:
-  build:
-    strategy:
-      matrix:
-        include:
-          - name: ubuntu-latest-gcc-cmake
-            os: ubuntu-latest
-            cc: gcc
-            cxx: g++
-            build-system: cmake
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_INSTALL=0 -DUHDR_BUILD_FUZZERS=0'
-
-          - name: ubuntu-latest-gcc-cmake-deps
-            os: ubuntu-latest
-            cc: gcc
-            cxx: g++
-            build-system: cmake
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_INSTALL=0 -DUHDR_BUILD_FUZZERS=0 -DUHDR_BUILD_DEPS=1'
-
-          - name: ubuntu-latest-clang-cmake
-            os: ubuntu-latest
-            cc: clang
-            cxx: clang++
-            build-system: cmake
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_INSTALL=0 -DUHDR_BUILD_FUZZERS=0'
-
-          - name: ubuntu-latest-clang-cmake-deps
-            os: ubuntu-latest
-            cc: clang
-            cxx: clang++
-            build-system: cmake
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_INSTALL=0 -DUHDR_BUILD_DEPS=1'
-
-          - name: ubuntu-latest-clang-cmake-fuzzers
-            os: ubuntu-latest
-            cc: clang
-            cxx: clang++
-            build-system: cmake
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_INSTALL=0 -DUHDR_BUILD_FUZZERS=1'
-
-          - name: macos-latest-clang-cmake
-            os: macos-latest
-            cc: clang
-            cxx: clang++
-            build-system: cmake
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_INSTALL=0 -DUHDR_BUILD_FUZZERS=0'
-
-          - name: macos-latest-clang-cmake-deps
-            os: macos-latest
-            cc: clang
-            cxx: clang++
-            build-system: cmake
-            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_INSTALL=0 -DUHDR_BUILD_DEPS=1'
-
-          - name: windows-latest-vs-cmake
-            os: windows-latest
-            cc: clang
-            cxx: clang++
-            build-system: cmake
-            cmake-opts: '-G "Visual Studio 17 2022" -DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_INSTALL=0 -DUHDR_BUILD_DEPS=1 -DUHDR_BUILD_FUZZERS=0'
-
-    runs-on: ${{ matrix.os }}
-
-    steps:
-    - uses: actions/checkout@v4
-
-    - name: Install MacOS dependencies
-      if: startsWith(matrix.os,'macos')
-      run: |
-        brew update
-        brew install pkg-config jpeg-turbo
-
-    - name: Install Linux dependencies
-      if: startsWith(matrix.os,'ubuntu')
-      run: |
-        sudo apt-get update
-        sudo apt-get install -y libjpeg-dev
-
-    - name: Configure CMake
-      env:
-        CC: ${{ matrix.cc }}
-        CXX: ${{ matrix.cxx }}
-      run: cmake -B ${{github.workspace}}/out -DCMAKE_BUILD_TYPE=${{env.BUILD_TYPE}} ${{ matrix.cmake-opts }}
-
-    - name: Build
-      run: cmake --build ${{github.workspace}}/out --config ${{env.BUILD_TYPE}}
diff --git a/.github/workflows/cmake_android.yml b/.github/workflows/cmake_android.yml
new file mode 100644
index 0000000..25ab455
--- /dev/null
+++ b/.github/workflows/cmake_android.yml
@@ -0,0 +1,47 @@
+name: Build CI - Android
+# Build CI for Android
+
+on: [ push, pull_request ]
+
+jobs:
+  build:
+    runs-on: ${{ matrix.os }}
+
+    strategy:
+      fail-fast: true
+      matrix:
+        os: [ubuntu-latest]
+        abi: [armeabi-v7a, arm64-v8a, x86, x86_64]
+
+    steps:
+    - name: Checkout the repository
+      uses: actions/checkout@v3
+
+    - name: Set up JDK 17
+      uses: actions/setup-java@v3
+      with:
+        java-version: '17'
+        distribution: 'temurin'
+
+    - name: Download and Setup the Android NDK
+      uses: nttld/setup-ndk@v1
+      id: setup-ndk
+      with:
+        # r25c is the same as 25.2.9519653.
+        ndk-version: r25c
+        add-to-path: false
+
+    - name: Setup ninja
+      uses: seanmiddleditch/gha-setup-ninja@master
+
+    - name: Setup cmake
+      uses: jwlawson/actions-setup-cmake@v2
+
+    - name: Configure CMake
+      shell: bash
+      run: |
+        mkdir build
+        cmake -G Ninja -B build -DCMAKE_TOOLCHAIN_FILE=./cmake/toolchains/android.cmake -DUHDR_ANDROID_NDK_PATH=${{ steps.setup-ndk.outputs.ndk-path }} -DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1 -DANDROID_ABI=${{ matrix.abi }} -DANDROID_PLATFORM=android-23 -DUHDR_BUILD_JAVA=1
+
+    - name: Build
+      run: cmake --build build
diff --git a/.github/workflows/cmake_linux.yml b/.github/workflows/cmake_linux.yml
new file mode 100644
index 0000000..72aef4b
--- /dev/null
+++ b/.github/workflows/cmake_linux.yml
@@ -0,0 +1,96 @@
+name: Build and Test CI - Linux
+# Build and Test CI for ubuntu-latest
+
+on: [ push, pull_request ]
+
+jobs:
+  build:
+    name: ${{ matrix.config.name }}
+    runs-on: ${{ matrix.config.os }}
+    strategy:
+      fail-fast: true
+      matrix:
+        config:
+          # <Ubuntu-latest Platform, Release Build, GCC toolchain, Ninja generator>
+          - name: "ubuntu latest gcc rel ninja"
+            os: ubuntu-latest
+            build_type: Release
+            cc: gcc
+            cxx: g++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1'
+
+          # <Ubuntu-latest Platform, Release Build, Clang toolchain, Ninja generator>
+          - name: "ubuntu latest clang rel ninja"
+            os: ubuntu-latest
+            build_type: Release
+            cc: clang
+            cxx: clang++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1'
+
+          # <Ubuntu-latest Platform, Release Build, GCC toolchain, Ninja generator, Build Deps>
+          - name: "ubuntu latest gcc rel ninja with deps"
+            os: ubuntu-latest
+            build_type: Release
+            cc: gcc
+            cxx: g++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1'
+
+          # <Ubuntu-latest Platform, Release Build, Clang toolchain, Ninja generator, Build Deps, Sanitizer Address>
+          - name: "ubuntu latest clang rel ninja with deps sanitize address"
+            os: ubuntu-latest
+            build_type: Release
+            cc: clang
+            cxx: clang++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1 -DUHDR_SANITIZE_OPTIONS=address'
+
+          # <Ubuntu-latest Platform, Release Build, Clang toolchain, Ninja generator, Build Fuzzers, Sanitizer Address>
+          - name: "ubuntu latest clang rel ninja fuzzers sanitize address"
+            os: ubuntu-latest
+            build_type: Release
+            cc: clang
+            cxx: clang++
+            cmake-opts: '-DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address'
+
+          # <Ubuntu-latest Platform, Release Build, GCC toolchain, Ninja generator, Static linking>
+          - name: "ubuntu latest gcc rel ninja static"
+            os: ubuntu-latest
+            build_type: Release
+            cc: gcc
+            cxx: g++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0'
+
+          # <Ubuntu-latest Platform, Release Build, Clang toolchain, Ninja generator, Static linking>
+          - name: "ubuntu latest clang rel ninja static"
+            os: ubuntu-latest
+            build_type: Release
+            cc: clang
+            cxx: clang++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0'
+
+    steps:
+    - name: Checkout the repository
+      uses: actions/checkout@v4
+
+    - name: Setup ninja
+      uses: seanmiddleditch/gha-setup-ninja@master
+
+    - name: Setup cmake
+      uses: jwlawson/actions-setup-cmake@v2
+
+    - name: Install dependencies on Ubuntu
+      run: sudo apt install -y libjpeg-dev
+
+    - name: Configure CMake
+      shell: bash
+      run: |
+        export CC=${{ matrix.config.cc }}
+        export CXX=${{ matrix.config.cxx }}
+        mkdir build
+        cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=${{ matrix.config.build_type }} ${{ matrix.config.cmake-opts }}
+
+    - name: Build
+      run: cmake --build build --config ${{ matrix.config.build_type }}
+
+    - name: Test
+      working-directory: build
+      run: ctest --build-config ${{ matrix.config.build_type }}
\ No newline at end of file
diff --git a/.github/workflows/cmake_mac.yml b/.github/workflows/cmake_mac.yml
new file mode 100644
index 0000000..0f75979
--- /dev/null
+++ b/.github/workflows/cmake_mac.yml
@@ -0,0 +1,80 @@
+name: Build and Test CI - macOS
+# Build and Test CI for macOS-latest
+
+on: [ push, pull_request ]
+
+jobs:
+  build:
+    name: ${{ matrix.config.name }}
+    runs-on: ${{ matrix.config.os }}
+    strategy:
+      fail-fast: true
+      matrix:
+        config:
+          # <macOS-latest ARM64 Platform, Release Build, Clang toolchain, Ninja generator>
+          - name: "macOS latest ARM64 clang rel ninja"
+            os: macos-latest
+            build_type: Release
+            cc: clang
+            cxx: clang++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1'
+
+          # <macOS-13 Platform, Release Build, Clang toolchain, Ninja generator>
+          - name: "macOS-13 clang rel ninja"
+            os: macos-13
+            build_type: Release
+            cc: clang
+            cxx: clang++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1'
+
+          # <macOS-latest ARM64 Platform, Release Build, Clang toolchain, Ninja generator, Build Deps>
+          - name: "macOS latest ARM64 clang rel ninja with deps"
+            os: macos-latest
+            build_type: Release
+            cc: clang
+            cxx: clang++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1'
+
+          # <macOS-latest ARM64 Platform, Release Build, Clang toolchain, Ninja generator, Static linking>
+          - name: "macOS latest ARM64 clang rel ninja static"
+            os: macos-latest
+            build_type: Release
+            cc: clang
+            cxx: clang++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0'
+
+          # <macOS-13 Platform, Release Build, Clang toolchain, Ninja generator, Static linking>
+          - name: "macOS-13 clang rel ninja static"
+            os: macos-13
+            build_type: Release
+            cc: clang
+            cxx: clang++
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_ENABLE_INSTALL=1 -DBUILD_SHARED_LIBS=0'
+
+    steps:
+    - name: Checkout the repository
+      uses: actions/checkout@v4
+
+    - name: Setup ninja
+      uses: seanmiddleditch/gha-setup-ninja@master
+
+    - name: Setup cmake
+      uses: jwlawson/actions-setup-cmake@v2
+
+    - name: Install dependencies on macOS
+      run: brew install pkg-config jpeg-turbo
+
+    - name: Configure CMake
+      shell: bash
+      run: |
+        export CC=${{ matrix.config.cc }}
+        export CXX=${{ matrix.config.cxx }}
+        mkdir build
+        cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=${{ matrix.config.build_type }} ${{ matrix.config.cmake-opts }}
+
+    - name: Build
+      run: cmake --build build --config ${{ matrix.config.build_type }}
+
+    - name: Test
+      working-directory: build
+      run: ctest --build-config ${{ matrix.config.build_type }}
\ No newline at end of file
diff --git a/.github/workflows/cmake_win.yml b/.github/workflows/cmake_win.yml
new file mode 100644
index 0000000..d1f5b96
--- /dev/null
+++ b/.github/workflows/cmake_win.yml
@@ -0,0 +1,42 @@
+name: Build and Test CI - Windows
+# Build and Test CI for windows-latest
+
+on: [ push, pull_request ]
+
+jobs:
+  build:
+    name: ${{ matrix.config.name }}
+    runs-on: ${{ matrix.config.os }}
+    strategy:
+      fail-fast: true
+      matrix:
+        config:
+          # <Windows-latest, Release Build, Cl compiler toolchain, Visual Studio 17 2022 generator>
+          - name: "windows latest cl rel visual studio 17 2022 with deps"
+            os: windows-latest
+            build_type: Release
+            cc: cl
+            cxx: cl
+            cmake-opts: '-DUHDR_BUILD_TESTS=1 -DUHDR_ENABLE_LOGS=1 -DUHDR_BUILD_DEPS=1'
+
+    steps:
+    - name: Checkout the repository
+      uses: actions/checkout@v4
+
+    - name: Setup cmake
+      uses: jwlawson/actions-setup-cmake@v2
+
+    - name: Configure CMake
+      shell: bash
+      run: |
+        export CC=${{ matrix.config.cc }}
+        export CXX=${{ matrix.config.cxx }}
+        mkdir build
+        cmake -G "Visual Studio 17 2022" -B build -DCMAKE_BUILD_TYPE=${{ matrix.config.build_type }} ${{ matrix.config.cmake-opts }}
+
+    - name: Build
+      run: cmake --build build --config ${{ matrix.config.build_type }}
+
+    - name: Test
+      working-directory: build
+      run: ctest --build-config ${{ matrix.config.build_type }}
\ No newline at end of file
diff --git a/Android.bp b/Android.bp
index 889fc0b..194fc1c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -41,7 +41,6 @@ cc_library {
     ],
     local_include_dirs: ["lib/include"],
     cflags: ["-DUHDR_ENABLE_INTRINSICS"],
-
     srcs: [
         "lib/src/icc.cpp",
         "lib/src/jpegr.cpp",
@@ -52,7 +51,6 @@ cc_library {
         "lib/src/editorhelper.cpp",
         "lib/src/ultrahdr_api.cpp",
     ],
-
     shared_libs: [
         "libimage_io",
         "libjpeg",
@@ -61,17 +59,28 @@ cc_library {
         "liblog",
     ],
     rtti: true,
-
     target: {
         windows: {
             enabled: true,
         },
+        android: {
+            srcs: [
+                "lib/src/gpu/applygainmap_gl.cpp",
+                "lib/src/gpu/editorhelper_gl.cpp",
+                "lib/src/gpu/uhdr_gl_utils.cpp",
+            ],
+            cflags: ["-DUHDR_ENABLE_GLES"],
+            shared_libs: [
+                "libEGL",
+                "libGLESv3",
+            ],
+        },
     },
-
     arch: {
         arm: {
             srcs: [
                 "lib/src/dsp/arm/editorhelper_neon.cpp",
+                "lib/src/dsp/arm/gainmapmath_neon.cpp",
             ],
         },
         arm64: {
@@ -87,18 +96,14 @@ cc_library {
     name: "libjpegencoder",
     host_supported: true,
     vendor_available: true,
-
     shared_libs: [
         "libjpeg",
         "liblog",
     ],
-
     export_include_dirs: ["lib/include"],
-
     srcs: [
         "lib/src/jpegencoderhelper.cpp",
     ],
-
     target: {
         windows: {
             enabled: true,
@@ -110,18 +115,14 @@ cc_library {
     name: "libjpegdecoder",
     host_supported: true,
     vendor_available: true,
-
     shared_libs: [
         "libjpeg",
         "liblog",
     ],
-
     export_include_dirs: ["lib/include"],
-
     srcs: [
         "lib/src/jpegdecoderhelper.cpp",
     ],
-
     target: {
         windows: {
             enabled: true,
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 1827267..4a72f01 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -14,9 +14,15 @@
 # the License.
 #
 
-cmake_minimum_required(VERSION 3.13)
+cmake_minimum_required(VERSION 3.15)
 
-project(libuhdr VERSION 1.0 LANGUAGES C CXX
+# CMP0091: MSVC runtime library flags are selected by an abstraction.
+# New in CMake 3.15. https://cmake.org/cmake/help/latest/policy/CMP0091.html
+if(POLICY CMP0091)
+  cmake_policy(SET CMP0091 OLD)
+endif()
+
+project(libuhdr VERSION 1.2.0 LANGUAGES C CXX
         DESCRIPTION "Library for encoding and decoding ultrahdr images")
 
 ###########################################################
@@ -47,6 +53,8 @@ elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*|arm64.*|ARM64.*)")
   endif()
 elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm.*|ARM.*)")
   set(ARCH "arm")
+elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^riscv64")
+  set(ARCH "riscv64")
 else()
   message(FATAL_ERROR "Architecture: ${CMAKE_SYSTEM_PROCESSOR} not recognized")
 endif()
@@ -56,6 +64,7 @@ endif()
 ###########################################################
 set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)
 set(THIRD_PARTY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
+set(JAVA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/java)
 set(TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)
 set(BENCHMARK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/benchmark)
 set(FUZZERS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fuzzer)
@@ -88,14 +97,16 @@ function(option_if_not_defined name description default)
   endif()
 endfunction()
 
-option_if_not_defined(UHDR_BUILD_EXAMPLES "Build examples " TRUE)
+option_if_not_defined(UHDR_BUILD_EXAMPLES "Build sample application " TRUE)
 option_if_not_defined(UHDR_BUILD_TESTS "Build unit tests " FALSE)
-option_if_not_defined(UHDR_BUILD_BENCHMARK "Build benchmark " FALSE)
-option_if_not_defined(UHDR_BUILD_FUZZERS "Build fuzzers " FALSE)
+option_if_not_defined(UHDR_BUILD_BENCHMARK "Build benchmark tests " FALSE)
+option_if_not_defined(UHDR_BUILD_FUZZERS "Build fuzz test applications " FALSE)
 option_if_not_defined(UHDR_BUILD_DEPS "Build deps and not use pre-installed packages " FALSE)
 option_if_not_defined(UHDR_ENABLE_LOGS "Build with verbose logging " FALSE)
-option_if_not_defined(UHDR_ENABLE_INSTALL "Add install and uninstall targets for libuhdr package" TRUE)
-option_if_not_defined(UHDR_ENABLE_INTRINSICS "Build with intrinsics " TRUE)
+option_if_not_defined(UHDR_ENABLE_INSTALL "Enable install and uninstall targets for libuhdr package " TRUE)
+option_if_not_defined(UHDR_ENABLE_INTRINSICS "Build with SIMD acceleration " TRUE)
+option_if_not_defined(UHDR_ENABLE_GLES "Build with GPU acceleration " FALSE)
+option_if_not_defined(UHDR_BUILD_JAVA "Build JNI wrapper and Java front-end classes " FALSE)
 
 # pre-requisites
 if(UHDR_BUILD_TESTS AND EMSCRIPTEN)
@@ -111,17 +122,6 @@ if(UHDR_BUILD_BENCHMARK AND EMSCRIPTEN)
 endif()
 
 # side effects
-if(NOT BUILD_SHARED_LIBS AND UHDR_ENABLE_INSTALL)
-  set(UHDR_ENABLE_INSTALL FALSE) # libjpeg dependency is correctly mentioned as Requires.private in libuhdr.pc
-                                 # `pkg-config --libs libuhdr` returns -L/usr/local/lib -luhdr
-                                 # `pkg-config --libs --static libuhdr` returns -L/usr/local/lib -luhdr -ljpeg
-                                 # Not many build systems pass `--static` argument to pkg-config
-                                 # So if pc file to work universally for static and shared libs its best to
-                                 # elevate libjpeg dependency from Requires.private to Requires.
-                                 # But, for now, disable install and uninstall targets if target type is static.
-  message(STATUS "Install and uninstall targets - Disabled")
-endif()
-
 if(CMAKE_CROSSCOMPILING AND UHDR_ENABLE_INSTALL)
   set(UHDR_ENABLE_INSTALL FALSE) # disable install and uninstall targets during cross compilation.
   message(STATUS "Install and uninstall targets - Disabled")
@@ -157,6 +157,12 @@ if(BUILD_SHARED_LIBS)
   set(CMAKE_CXX_VISIBILITY_PRESET hidden)
   set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
   add_compile_options(-DUHDR_BUILDING_SHARED_LIBRARY)
+else()
+  if(WIN32)
+    set(CMAKE_FIND_LIBRARY_SUFFIXES .lib .a)
+  else()
+    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
+  endif()
 endif()
 if(UHDR_ENABLE_LOGS)
   add_compile_options(-DLOG_NDEBUG)
@@ -213,10 +219,17 @@ else()
   elseif(ARCH STREQUAL "arm")
     add_compile_options(-march=armv7-a)
     add_compile_options(-marm)
-    add_compile_options(-mfloat-abi=hard)
-    add_compile_options(-mfpu=vfpv3)
+    if(NOT ANDROID_ABI)
+      add_compile_options(-mfloat-abi=hard)
+    endif()
+    add_compile_options(-mfpu=neon-vfpv3)
+    add_compile_options(-fno-lax-vector-conversions)
   elseif(ARCH STREQUAL "aarch64")
     add_compile_options(-march=armv8-a)
+    add_compile_options(-fno-lax-vector-conversions)
+  elseif(ARCH STREQUAL "riscv64")
+    add_compile_options(-march=rv64gc)
+    add_compile_options(-mabi=lp64d)
   endif()
 endif()
 
@@ -251,8 +264,18 @@ endfunction()
 ###########################################################
 # Dependencies
 ###########################################################
+list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
+
 if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
-  find_library(log-lib log)
+  if (UHDR_ENABLE_LOGS)
+    find_library(log-lib log QUIET)
+    if(NOT log-lib)
+      message(FATAL_ERROR "Could NOT find log library, retry after installing \
+                           log library at sysroot or try 'cmake -DUHDR_ENABLE_LOGS=0'")
+    else()
+      message(STATUS "Found log-lib: ${log-lib}")
+    endif()
+  endif()
 endif()
 
 # Threads
@@ -288,10 +311,43 @@ endif()
 if(DEFINED CMAKE_TOOLCHAIN_FILE)
   list(APPEND UHDR_CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE:FILEPATH=${CMAKE_TOOLCHAIN_FILE})
 endif()
+if(DEFINED ANDROID_PLATFORM)
+  list(APPEND UHDR_CMAKE_ARGS -DANDROID_PLATFORM=${ANDROID_PLATFORM})
+endif()
+if(DEFINED ANDROID_ABI)
+  list(APPEND UHDR_CMAKE_ARGS -DANDROID_ABI=${ANDROID_ABI})
+endif()
 if(DEFINED UHDR_ANDROID_NDK_PATH)
   list(APPEND UHDR_CMAKE_ARGS -DUHDR_ANDROID_NDK_PATH=${UHDR_ANDROID_NDK_PATH})
 endif()
 
+# opengl es libraries
+if(UHDR_ENABLE_GLES)
+  find_package(EGL QUIET)
+  if(EGL_FOUND)
+    message(STATUS "Found EGL: ${EGL_LIBRARIES}")
+    find_package(OpenGLES3 QUIET)
+    if(OpenGLES3_FOUND)
+      message(STATUS "Found GLESv3: ${OPENGLES3_LIBRARIES} (API version \"${OpenGLES3_API_VERSION}\")")
+    else()
+      message(STATUS "Could NOT find GLESv3")
+    endif()
+  else()
+    message(STATUS "Could NOT find EGL")
+  endif()
+  if(EGL_FOUND AND OpenGLES3_FOUND)
+    add_compile_options(-DUHDR_ENABLE_GLES)
+    string(FIND "${OPENGLES3_LIBRARIES}" "GLESv3" result)
+    if(result GREATER -1)
+      set(UHDR_GL_DEPS "-lEGL -lGLESv3")
+    else()
+      set(UHDR_GL_DEPS "-lEGL -lGLESv2")
+    endif()
+  else()
+    set(UHDR_ENABLE_GLES FALSE)
+  endif()
+endif()
+
 # libjpeg-turbo
 if(NOT UHDR_BUILD_DEPS)
   find_package(JPEG QUIET)
@@ -348,6 +404,23 @@ if(NOT JPEG_FOUND)
   endif()
 endif()
 
+if(UHDR_BUILD_JAVA)
+  # build jni and java util classes
+  find_package(Java REQUIRED)
+  if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
+    find_package(JNI QUIET)
+    if(NOT JAVA_INCLUDE_PATH)
+      message(FATAL_ERROR "Could NOT find JNI Component")
+    else()
+      message(STATUS "Found JNI Component")
+    endif()
+    set(UHDR_JNI_INCLUDE_PATH ${JAVA_INCLUDE_PATH})
+  else()
+    find_package(JNI REQUIRED)
+    set(UHDR_JNI_INCLUDE_PATH ${JNI_INCLUDE_DIRS})
+  endif()
+endif()
+
 if(UHDR_BUILD_TESTS)
   # gtest and gmock
   set(GTEST_TARGET_NAME googletest)
@@ -419,6 +492,15 @@ if(UHDR_ENABLE_INTRINSICS)
     list(APPEND UHDR_CORE_SRCS_LIST ${UHDR_CORE_NEON_SRCS_LIST})
   endif()
 endif()
+if(UHDR_ENABLE_GLES)
+  file(GLOB UHDR_CORE_GLES_SRCS_LIST "${SOURCE_DIR}/src/gpu/*.cpp")
+  list(APPEND UHDR_CORE_SRCS_LIST ${UHDR_CORE_GLES_SRCS_LIST})
+endif()
+if(UHDR_BUILD_JAVA)
+  file(GLOB UHDR_JNI_SRCS_LIST "${JAVA_DIR}/jni/*.cpp")
+  file(GLOB UHDR_JAVA_SRCS_LIST "${JAVA_DIR}/com/google/media/codecs/ultrahdr/*.java")
+  file(GLOB UHDR_APP_SRC "${JAVA_DIR}/UltraHdrApp.java")
+endif()
 file(GLOB UHDR_TEST_SRCS_LIST "${TESTS_DIR}/*.cpp")
 file(GLOB UHDR_BM_SRCS_LIST "${BENCHMARK_DIR}/*.cpp")
 file(GLOB IMAGE_IO_SRCS_LIST "${THIRD_PARTY_DIR}/image_io/src/**/*.cc")
@@ -444,6 +526,9 @@ endif()
 if(NOT MSVC)
   target_compile_options(${UHDR_CORE_LIB_NAME} PRIVATE -Wall -Wextra -Wshadow)
 endif()
+if(DEFINED UHDR_MAX_DIMENSION)
+  target_compile_options(${UHDR_CORE_LIB_NAME} PRIVATE -DUHDR_MAX_DIMENSION=${UHDR_MAX_DIMENSION})
+endif()
 target_include_directories(${UHDR_CORE_LIB_NAME} PRIVATE
   ${PRIVATE_INCLUDE_DIR}
   "${THIRD_PARTY_DIR}/image_io/includes/"
@@ -452,6 +537,9 @@ target_include_directories(${UHDR_CORE_LIB_NAME} PUBLIC ${EXPORT_INCLUDE_DIR})
 if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
   target_link_libraries(${UHDR_CORE_LIB_NAME} PUBLIC ${log-lib})
 endif()
+if(UHDR_ENABLE_GLES)
+  target_link_libraries(${UHDR_CORE_LIB_NAME} PRIVATE ${EGL_LIBRARIES} ${OPENGLES3_LIBRARIES})
+endif()
 target_link_libraries(${UHDR_CORE_LIB_NAME} PRIVATE ${COMMON_LIBS_LIST} ${IMAGEIO_TARGET_NAME})
 
 if(UHDR_BUILD_EXAMPLES)
@@ -566,10 +654,54 @@ endif()
 set(UHDR_TARGET_NAME uhdr)
 add_library(${UHDR_TARGET_NAME})
 add_dependencies(${UHDR_TARGET_NAME} ${UHDR_CORE_LIB_NAME})
+if(UHDR_ENABLE_GLES)
+  target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${EGL_LIBRARIES} ${OPENGLES3_LIBRARIES})
+endif()
+if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
+  target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${log-lib})
+endif()
 target_link_libraries(${UHDR_TARGET_NAME} PRIVATE ${JPEG_LIBRARIES})
-set_target_properties(${UHDR_TARGET_NAME} PROPERTIES PUBLIC_HEADER ultrahdr_api.h)
+set_target_properties(${UHDR_TARGET_NAME}
+                      PROPERTIES PUBLIC_HEADER ultrahdr_api.h)
+if(BUILD_SHARED_LIBS)
+  # If target is STATIC no need to set VERSION and SOVERSION
+  set_target_properties(${UHDR_TARGET_NAME}
+                        PROPERTIES VERSION ${PROJECT_VERSION}
+                        SOVERSION ${PROJECT_VERSION_MAJOR})
+endif()
 combine_static_libs(${UHDR_CORE_LIB_NAME} ${UHDR_TARGET_NAME})
 
+# Build static library as well
+if(BUILD_SHARED_LIBS)
+  set(UHDR_TARGET_NAME_STATIC uhdr-static)
+  add_library(${UHDR_TARGET_NAME_STATIC} STATIC)
+  add_dependencies(${UHDR_TARGET_NAME_STATIC} ${UHDR_CORE_LIB_NAME})
+  if(UHDR_ENABLE_GLES)
+    target_link_libraries(${UHDR_TARGET_NAME_STATIC} PRIVATE ${EGL_LIBRARIES} ${OPENGLES3_LIBRARIES})
+  endif()
+  if(${CMAKE_SYSTEM_NAME} MATCHES "Android")
+    target_link_libraries(${UHDR_TARGET_NAME_STATIC} PRIVATE ${log-lib})
+  endif()
+  target_link_libraries(${UHDR_TARGET_NAME_STATIC} PRIVATE ${JPEG_LIBRARIES})
+  combine_static_libs(${UHDR_CORE_LIB_NAME} ${UHDR_TARGET_NAME_STATIC})
+  if(NOT MSVC)
+    set_target_properties(${UHDR_TARGET_NAME_STATIC}
+                          PROPERTIES OUTPUT_NAME ${UHDR_TARGET_NAME})
+  endif()
+endif()
+
+if(UHDR_BUILD_JAVA)
+  include(UseJava)
+
+  set(UHDR_JNI_TARGET_NAME uhdrjni)
+  add_library(${UHDR_JNI_TARGET_NAME} SHARED ${UHDR_JNI_SRCS_LIST})
+  add_dependencies(${UHDR_JNI_TARGET_NAME} ${UHDR_TARGET_NAME})
+  target_include_directories(${UHDR_JNI_TARGET_NAME} PRIVATE ${UHDR_JNI_INCLUDE_PATH} ${EXPORT_INCLUDE_DIR})
+  target_link_libraries(${UHDR_JNI_TARGET_NAME} PRIVATE ${UHDR_TARGET_NAME})
+
+  add_jar(uhdr-java SOURCES ${UHDR_JAVA_SRCS_LIST} ${UHDR_APP_SRC} ENTRY_POINT UltraHdrApp)
+endif()
+
 if(UHDR_ENABLE_INSTALL)
   if(NOT(MSVC OR XCODE))
     include(GNUInstallDirs)
@@ -579,7 +711,7 @@ if(UHDR_ENABLE_INSTALL)
                    "${CMAKE_CURRENT_BINARY_DIR}/libuhdr.pc" @ONLY NEWLINE_STYLE UNIX)
     install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libuhdr.pc"
             DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
-    install(TARGETS ${UHDR_TARGET_NAME}
+    install(TARGETS ${UHDR_TARGET_NAME} ${UHDR_TARGET_NAME_STATIC}
             RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
             LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
             ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
diff --git a/METADATA b/METADATA
index 1aa7e16..31e0fd8 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/libultrahdr
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libultrahdr"
 description: "Android fork of the libultrahdr library."
@@ -8,12 +8,12 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 6
-    day: 5
+    month: 9
+    day: 20
   }
   identifier {
     type: "Git"
     value: "https://github.com/google/libultrahdr.git"
-    version: "27c3d0f0204884d8f95b61a0301f8fc86d6d662a"
+    version: "2188c35c95aee9c66ede526ab1c8187a3bc82416"
   }
 }
diff --git a/README.md b/README.md
index e11404c..da5279f 100644
--- a/README.md
+++ b/README.md
@@ -1,4 +1,4 @@
-# Background
+## Introduction
 
 libultrahdr is an image compression library that uses gain map technology
 to store and distribute HDR images. Conceptually on the encoding side, the
@@ -10,124 +10,18 @@ gain map image and/or metadata, will display the base image. Readers that
 support the format combine the base image with the gain map and render a
 high dynamic range image on compatible displays.
 
-For additional information about libultrahdr, see android hdr-image-format
+For additional information, see android hdr-image-format
 [guide](https://developer.android.com/guide/topics/media/platform/hdr-image-format).
 
+## Build from source using CMake
 
-## Building libultrahdr
+This software suite has been built and tested on platforms:
+- Android
+- Linux
+- macOS
+- Windows
 
-### Requirements
-
-- [CMake](http://www.cmake.org) v3.13 or later
-- C++ compiler, supporting at least C++17.
-- libultrahdr uses jpeg compression format to store sdr image and gainmap quotient.
-  So, libjpeg or any other jpeg codec that is ABI and API compatible with libjpeg.
-
-The library offers a way to skip installing libjpeg by passing `UHDR_BUILD_DEPS=1`
-at the time of configure. That is, `cmake -DUHDR_BUILD_DEPS=1` will clone jpeg codec
-from [link](https://github.com/libjpeg-turbo/libjpeg-turbo.git) and include it in
-the build process. This is however not recommended.
-
-If jpeg is included in the build process then to build jpeg with simd extensions,
-- C compiler
-- [NASM](http://www.nasm.us) or [Yasm](http://yasm.tortall.net) are needed.
-  * If using NASM, 2.13 or later is required.
-  * If using Yasm, 1.2.0 or later is required.
-
-### Build Procedure
-
-To build libultrahdr, examples, unit tests:
-
-### Un*x (including Linux, Mac)
-
-    mkdir build_directory
-    cd build_directory
-    cmake -G "Unix Makefiles" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_TESTS=1 ../
-    make
-    ctest
-    make install
-
-This will generate the following files under `build_directory`:
-
-**libuhdr.so or libuhdr.dylib**<br> ultrahdr shared library
-
-**libuhdr.pc**<br> ultrahdr pkg-config file
-
-**ultrahdr_app**<br> Statically linked sample application demonstrating ultrahdr API usage
-
-**ultrahdr_unit_test**<br> Unit tests
-
-`make install` will install libuhdr.so, ultrahdr_api.h, libuhdr.pc for system-wide usage and
-`make uninstall` will remove the same.
-
-### MinGW
-
-NOTE: This assumes that you are building on a Windows machine using the MSYS
-environment.
-
-    mkdir build_directory
-    cd build_directory
-    cmake -G "MSYS Makefiles" -DUHDR_BUILD_TESTS=1 ../
-    cmake --build ./
-    ctest
-
-    mkdir build_directory
-    cd build_directory
-    cmake -G "MinGW Makefiles" -DUHDR_BUILD_TESTS=1 ../
-    cmake --build ./
-    ctest
-
-This will generate the following files under `build_directory`:
-
-**libuhdr.dll**<br> ultrahdr shared library
-
-**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API
-
-**ultrahdr_unit_test.exe**<br> Unit tests
-
-### Visual C++ (IDE)
-
-    mkdir build_directory
-    cd build_directory
-    cmake -G "Visual Studio 16 2019" -DUHDR_BUILD_DEPS=1 -DUHDR_BUILD_TESTS=1 ../
-    cmake --build ./ --config=Release
-    ctest -C Release
-
-This will generate the following files under `build_directory/Release`:
-
-**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API
-
-**ultrahdr_unit_test.exe**<br> Unit tests
-
-### Visual C++ (Command line)
-
-    mkdir build_directory
-    cd build_directory
-    cmake -G "NMake Makefiles" -DUHDR_BUILD_DEPS=1 -DUHDR_BUILD_TESTS=1 ../
-    cmake --build ./
-    ctest
-
-This will generate the following files under `build_directory`:
-
-**ultrahdr_app.exe**<br> Sample application demonstrating ultrahdr API
-
-**ultrahdr_unit_test.exe**<br> Unit tests
-
-
-NOTE: To not build unit tests, skip passing `-DUHDR_BUILD_TESTS=1`
-
-### Building Benchmark
-
-To build benchmarks, pass `-DUHDR_BUILD_BENCHMARK=1` to cmake configure command and build.
-
-This will additionally generate,
-
-**ultrahdr_bm**<br> Benchmark tests
-
-
-### Building Fuzzers
-
-Refer to [README.md](fuzzer/README.md) for complete instructions.
+Refer to [building.md](docs/building.md) for complete instructions.
 
 ## Using libultrahdr
 
@@ -140,10 +34,10 @@ libultrahdr includes two classes of APIs, one to compress and the other to decom
 
 | Scenario  | Hdr intent raw | Sdr intent raw | Sdr intent compressed | Gain map compressed | Quality |   Exif   | Use Case |
 |:---------:| :----------: | :----------: | :---------------------: | :-------------------: | :-------: | :---------: | :-------- |
-| API - 0 | P010 |    No   |  No  |  No  | Optional| Optional | Used if, only hdr raw intent is present. [^1] |
-| API - 1 | P010 | YUV420  |  No  |  No  | Optional| Optional | Used if, hdr raw and sdr raw intents are present.[^2] |
-| API - 2 | P010 | YUV420  | Yes  |  No  |    No   |    No    | Used if, hdr raw, sdr raw and sdr compressed intents are present.[^3] |
-| API - 3 | P010 |    No   | Yes  |  No  |    No   |    No    | Used if, hdr raw and sdr compressed intents are present.[^4] |
+| API - 0 | P010 or rgb1010102 |    No   |  No  |  No  | Optional| Optional | Used if, only hdr raw intent is present. [^1] |
+| API - 1 | P010 or rgb1010102 | YUV420 or rgba8888 |  No  |  No  | Optional| Optional | Used if, hdr raw and sdr raw intents are present.[^2] |
+| API - 2 | P010 or rgb1010102 | YUV420 or rgba8888 | Yes  |  No  |    No   |    No    | Used if, hdr raw, sdr raw and sdr compressed intents are present.[^3] |
+| API - 3 | P010 or rgb1010102 |    No   | Yes  |  No  |    No   |    No    | Used if, hdr raw and sdr compressed intents are present.[^4] |
 | API - 4 |  No  |    No   | Yes  | Yes  |    No   |    No    | Used if, sdr compressed, gain map compressed and GainMap Metadata are present.[^5] |
 
 [^1]: Tonemap hdr to sdr. Compute gain map from hdr and sdr. Compress sdr and gainmap at quality configured. Add exif if provided. Combine sdr compressed, gainmap in multi picture format with gainmap metadata.
diff --git a/benchmark/Android.bp b/benchmark/Android.bp
index 6cd91a8..52038fe 100644
--- a/benchmark/Android.bp
+++ b/benchmark/Android.bp
@@ -35,4 +35,13 @@ cc_benchmark {
         "libjpeg",
         "liblog",
     ],
+    target: {
+        android: {
+            cflags: ["-DUHDR_ENABLE_GLES"],
+            shared_libs: [
+                "libEGL",
+                "libGLESv3",
+            ],
+        },
+    },
 }
diff --git a/benchmark/benchmark_test.cpp b/benchmark/benchmark_test.cpp
index 4148802..4d5da3a 100644
--- a/benchmark/benchmark_test.cpp
+++ b/benchmark/benchmark_test.cpp
@@ -510,12 +510,21 @@ static void BM_Encode_Api4(benchmark::State& s) {
   gainmapImg.data = gainmapImgInfo.imgData.data();
   gainmapImg.maxLength = gainmapImg.length = gainmapImgInfo.imgData.size();
   gainmapImg.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-  ultrahdr_metadata_struct uhdr_metadata;
-  if (!getMetadataFromXMP(gainmapImgInfo.xmpData.data(), gainmapImgInfo.xmpData.size(),
-                          &uhdr_metadata)) {
+  uhdr_gainmap_metadata_ext_t meta;
+  if (getMetadataFromXMP(gainmapImgInfo.xmpData.data(), gainmapImgInfo.xmpData.size(), &meta)
+          .error_code != UHDR_CODEC_OK) {
     s.SkipWithError("getMetadataFromXMP returned with error");
     return;
   }
+  ultrahdr_metadata_struct uhdr_metadata;
+  uhdr_metadata.version = meta.version;
+  uhdr_metadata.hdrCapacityMax = meta.hdr_capacity_max;
+  uhdr_metadata.hdrCapacityMin = meta.hdr_capacity_min;
+  uhdr_metadata.gamma = meta.gamma;
+  uhdr_metadata.offsetSdr = meta.offset_sdr;
+  uhdr_metadata.offsetHdr = meta.offset_hdr;
+  uhdr_metadata.maxContentBoost = meta.max_content_boost;
+  uhdr_metadata.minContentBoost = meta.min_content_boost;
   for (auto _ : s) {
     status = jpegHdr.encodeJPEGR(&primaryImg, &gainmapImg, &uhdr_metadata, &jpegImgR);
     if (JPEGR_NO_ERROR != status) {
diff --git a/cmake/FindEGL.cmake b/cmake/FindEGL.cmake
new file mode 100644
index 0000000..1b22751
--- /dev/null
+++ b/cmake/FindEGL.cmake
@@ -0,0 +1,32 @@
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
+#
+# Finds the EGL library. This module defines:
+#
+#  EGL_FOUND            - True if EGL library is found, False otherwise
+#  EGL_LIBRARIES        - EGL library
+#  EGL_INCLUDE_DIRS     - Include dir
+#
+
+find_path(EGL_INCLUDE_DIRS EGL/egl.h)
+
+find_library(EGL_LIBRARIES NAMES EGL libEGL)
+
+include(FindPackageHandleStandardArgs)
+find_package_handle_standard_args(EGL DEFAULT_MSG EGL_INCLUDE_DIRS EGL_LIBRARIES)
+
+mark_as_advanced(EGL_INCLUDE_DIRS EGL_LIBRARIES)
diff --git a/cmake/FindOpenGLES3.cmake b/cmake/FindOpenGLES3.cmake
new file mode 100644
index 0000000..341f5cb
--- /dev/null
+++ b/cmake/FindOpenGLES3.cmake
@@ -0,0 +1,45 @@
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
+#
+# Finds the OpenGLES3 library. This module defines:
+#
+#  OpenGLES3_FOUND            - True if OpenGLES 3 library is found, False otherwise
+#  OPENGLES3_LIBRARIES        - OpenGLES3 library
+#  OPENGLES3_INCLUDE_DIRS     - Include dir
+#  OpenGLES3_API_VERSION      - OpenGLES3 Supported API version
+#
+
+find_path(OPENGLES3_INCLUDE_DIRS GLES3/gl3.h)
+
+# Android has separate library for OpenGLES3 in the form GLESv3
+# Many platforms support OpenGLES3 via OpenGLES2 lib. In this case, presence of GLES3/gl*.h will be indicative of GLES3 support
+find_library(OPENGLES3_LIBRARIES NAMES GLESv3 GLESv2 libGLESv2)
+
+if(OPENGLES3_INCLUDE_DIRS)
+  if(EXISTS ${OPENGLES3_INCLUDE_DIRS}/GLES3/gl32.h)
+    set(OpenGLES3_API_VERSION "3.2")
+  elseif(EXISTS ${OPENGLES3_INCLUDE_DIRS}/GLES3/gl31.h)
+    set(OpenGLES3_API_VERSION "3.1")
+  else()
+    set(OpenGLES3_API_VERSION "3.0")
+  endif()
+endif()
+
+include(FindPackageHandleStandardArgs)
+find_package_handle_standard_args(OpenGLES3 OPENGLES3_INCLUDE_DIRS OPENGLES3_LIBRARIES)
+
+mark_as_advanced(OPENGLES3_INCLUDE_DIRS OPENGLES3_LIBRARIES)
diff --git a/cmake/libuhdr.pc.in b/cmake/libuhdr.pc.in
index d50ec00..920d1cf 100644
--- a/cmake/libuhdr.pc.in
+++ b/cmake/libuhdr.pc.in
@@ -8,4 +8,4 @@ Version: @PROJECT_VERSION@
 Requires.private: libjpeg
 Cflags: -I${includedir}
 Libs: -L${libdir} -l@UHDR_TARGET_NAME@
-Libs.private: @CMAKE_THREAD_LIBS_INIT@
+Libs.private: @CMAKE_THREAD_LIBS_INIT@ @UHDR_GL_DEPS@
diff --git a/cmake/toolchains/android.cmake b/cmake/toolchains/android.cmake
index e620385..25588bf 100644
--- a/cmake/toolchains/android.cmake
+++ b/cmake/toolchains/android.cmake
@@ -25,7 +25,7 @@ if(NOT ANDROID_PLATFORM)
 endif()
 
 # Choose target architecture with:
-# -DANDROID_ABI={armeabi-v7a, armeabi-v7a with NEON, arm64-v8a, x86, x86_64}
+# -DANDROID_ABI={armeabi-v7a, arm64-v8a, x86, x86_64}
 if(NOT ANDROID_ABI)
   set(ANDROID_ABI arm64-v8a)
 endif()
diff --git a/cmake/toolchains/riscv64-linux-gnu.cmake b/cmake/toolchains/riscv64-linux-gnu.cmake
new file mode 100644
index 0000000..564ae20
--- /dev/null
+++ b/cmake/toolchains/riscv64-linux-gnu.cmake
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
+if(UHDR_BUILD_CMAKE_TOOLCHAINS_RISCV64_LINUX_GNU_CMAKE_)
+  return()
+endif()
+
+set(UHDR_BUILD_CMAKE_TOOLCHAINS_RISCV64_LINUX_GNU_CMAKE_ 1)
+
+set(CMAKE_SYSTEM_NAME "Linux")
+set(CMAKE_SYSTEM_PROCESSOR "riscv64")
+
+if("${CROSS}" STREQUAL "")
+  set(CROSS riscv64-linux-gnu-)
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
new file mode 100644
index 0000000..2c5db9d
--- /dev/null
+++ b/docs/building.md
@@ -0,0 +1,298 @@
+## libultrahdr CMake Build Instructions
+
+[![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_linux.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_linux.yml?query=event%3Apush)
+[![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_mac.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_mac.yml?query=event%3Apush)
+[![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_win.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_win.yml?query=event%3Apush)
+[![Build Status](https://github.com/google/libultrahdr/actions/workflows/cmake_android.yml/badge.svg?event=push)](https://github.com/google/libultrahdr/actions/workflows/cmake_android.yml?query=event%3Apush)
+[![Fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/libultrahdr.svg)](https://oss-fuzz-build-logs.storage.googleapis.com/index.html#libultrahdr)
+
+### Requirements
+
+- [CMake](http://www.cmake.org) v3.13 or later
+- C++ compiler, supporting at least C++17.
+- libultrahdr uses jpeg compression format to store sdr image and gainmap quotient.
+  So, libjpeg or any other jpeg codec that is ABI and API compatible with libjpeg.
+
+The library offers a way to skip installing libjpeg by passing `UHDR_BUILD_DEPS=1`
+at the time of configure. That is, `cmake -DUHDR_BUILD_DEPS=1` will clone jpeg codec
+from [link](https://github.com/libjpeg-turbo/libjpeg-turbo.git) and include it in
+the build process. This is however not recommended.
+
+If jpeg is included in the build process then,
+- C compiler
+- For building x86/x86_64 SIMD optimizations, [NASM](http://www.nasm.us) or
+ [Yasm](http://yasm.tortall.net).
+  * If using NASM, 2.13 or later is required.
+  * If using Yasm, 1.2.0 or later is required.
+
+### CMake Options
+
+There are a few options that can be passed to CMake to modify how the code
+is built.<br>
+To set these options and parameters, use `-D<Parameter_name>=<value>`.
+
+All CMake options are passed at configure time, i.e., by running
+`cmake -DOPTION_ONE=1 -DOPTION_TWO=0 ...` <br>
+before running `cmake --build ...`<br>
+
+For example, to build unit tests in a new subdirectory called 'build', run:
+
+```sh
+cmake -G "Unix Makefiles" -S. -Bbuild -DUHDR_BUILD_TESTS=1 ../
+```
+and then build with:
+
+```sh
+cmake --build build
+```
+
+Following is a list of available options:
+
+| CMake Option | Default Value | Notes |
+|:-------------|:--------------|:-----|
+| `CMAKE_BUILD_TYPE` | Release | See CMake documentation [here](https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html). |
+| `BUILD_SHARED_LIBS` | ON | See CMake documentation [here](https://cmake.org/cmake/help/latest/variable/BUILD_SHARED_LIBS.html). <ul><li> If `BUILD_SHARED_LIBS` is **OFF**, in the linking phase, static versions of dependencies are chosen. However, the executable targets are not purely static because the system libraries used are still dynamic. </li></ul> |
+| `UHDR_BUILD_EXAMPLES` | ON | Build sample application. This application demonstrates how to use [ultrahdr_api.h](ultrahdr_api.h). |
+| `UHDR_BUILD_TESTS` | OFF | Build Unit Tests. Mostly for Devs. During development, different modules of libuhdr library are validated using GoogleTest framework. Developers after making changes to library are expected to run these tests to ensure every thing is functional. |
+| `UHDR_BUILD_BENCHMARK` | OFF | Build Benchmark Tests. These are for profiling libuhdr encode/decode API. Resources used by benchmark tests are shared [here](https://storage.googleapis.com/android_media/external/libultrahdr/benchmark/UltrahdrBenchmarkTestRes-1.0.zip). These are downloaded and extracted automatically during the build process for later benchmarking. <ul><li> Since [v1.0.0](https://github.com/google/libultrahdr/releases/tag/1.0.0), considerable API changes were made and benchmark tests need to be updated accordingly. So the current profile numbers may not be accurate and/or give a complete picture. </li><li> Benchmark tests are not supported on Windows and this parameter is forced to **OFF** internally while building on **WIN32** platforms. </li></ul>|
+| `UHDR_BUILD_FUZZERS` | OFF | Build Fuzz Test Applications. Mostly for Devs. <ul><li> Fuzz applications are built by instrumenting the entire software suite. This includes dependency libraries. This is done by forcing `UHDR_BUILD_DEPS` to **ON** internally. </li></ul> |
+| `UHDR_BUILD_DEPS` | OFF | Clone and Build project dependencies and not use pre-installed packages. |
+| `UHDR_ENABLE_LOGS` | OFF | Build with verbose logging. |
+| `UHDR_ENABLE_INSTALL` | ON | Enable install and uninstall targets for libuhdr package. <ul><li> For system wide installation it is best if dependencies are acquired from OS package manager instead of building from source. This is to avoid conflicts with software that is using a different version of the said dependency and also links to libuhdr. So if `UHDR_BUILD_DEPS` is **ON** then `UHDR_ENABLE_INSTALL` is forced to **OFF** internally. |
+| `UHDR_ENABLE_INTRINSICS` | ON | Build with SIMD acceleration. Sections of libuhdr are accelerated for Arm Neon architectures and these are enabled. <ul><li> For x86/x86_64 architectures currently no SIMD acceleration is present. Consequently this option has no effect. </li><li> This parameter has no effect no SIMD configuration settings of dependencies. </li></ul> |
+| `UHDR_ENABLE_GLES` | OFF | Build with GPU acceleration. |
+| `UHDR_MAX_DIMENSION` | 8192 | Maximum dimension supported by the library. The library defaults to handling images upto resolution 8192x8192. For different resolution needs use this option. For example, `-DUHDR_MAX_DIMENSION=4096`. |
+| `UHDR_BUILD_JAVA` | OFF | Build JNI wrapper, Java front-end classes and Java sample application. |
+| `UHDR_SANITIZE_OPTIONS` | OFF | Build library with sanitize options. Values set to this parameter are passed to directly to compilation option `-fsanitize`. For example, `-DUHDR_SANITIZE_OPTIONS=address,undefined` adds `-fsanitize=address,undefined` to the list of compilation options. CMake configuration errors are raised if the compiler does not support these flags. This is useful during fuzz testing. <ul><li> As `-fsanitize` is an instrumentation option, dependencies are also built from source instead of using pre-builts. This is done by forcing `UHDR_BUILD_DEPS` to **ON** internally. </li></ul> |
+| | | |
+
+### Generator
+
+The CMake generator preferred is ninja. Consequently, ninja is added to the list of prerequisite packages. This need not be the case. If the platform is equipped with a different generator, it can be tried and ninja installation can be skipped.
+
+### Build Steps
+
+Check out the source code:
+
+```sh
+git clone https://github.com/google/libultrahdr.git
+cd libultrahdr
+mkdir build_directory
+cd build_directory
+```
+
+### Linux Platform
+
+Install the prerequisite packages before building:
+
+```sh
+sudo apt install cmake pkg-config libjpeg-dev ninja-build
+```
+
+Compile and Test:
+
+```sh
+cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_TESTS=1 ../
+ninja
+ctest
+```
+
+This will generate the following files under `build_directory`:
+
+**libuhdr.so.{version}** - Shared library for the libuhdr API <br>
+**libuhdr.so** - Symlink to shared library <br>
+**libuhdr.a** - Static link library for the libuhdr API <br>
+**libuhdr.pc** - libuhdr pkg-config file <br>
+**ultrahdr_app** - sample application <br>
+**ultrahdr_unit_test** - unit tests <br>
+
+Installation:
+
+```sh
+sudo ninja install
+```
+
+This installs the headers, pkg-config, and shared libraries. By default the headers are put in `/usr/local/include/`, libraries in `/usr/local/lib/` and pkg-config file in `/usr/local/lib/pkgconfig/`. You may need to add path `/usr/local/lib/` to `LD_LIBRARY_PATH` if binaries linking with ultrahdr library are unable to load it at run time. e.g. `export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/`.
+
+Uninstallation:
+
+```sh
+sudo ninja uninstall
+```
+
+### macOS Platform
+
+Install the prerequisite packages before building:
+
+```sh
+brew install cmake pkg-config jpeg ninja
+```
+
+Compile and Test:
+
+```sh
+cmake -G Ninja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_TESTS=1 ../
+ninja
+ctest
+```
+
+This will generate the following files under `build_directory`:
+
+**libuhdr.{version}.dylib** - Shared library for the libuhdr API <br>
+**libuhdr.dylib** - Symlink to shared library <br>
+**libuhdr.a** - Static link library for the libuhdr API <br>
+**libuhdr.pc** - libuhdr pkg-config file <br>
+**ultrahdr_app** - sample application <br>
+**ultrahdr_unit_test** - unit tests <br>
+
+Installation:
+
+```sh
+sudo ninja install
+```
+
+This installs the headers, pkg-config, and shared libraries. By default the headers are put in `/usr/local/include/`, libraries in `/usr/local/lib/` and pkg-config file in `/usr/local/lib/pkgconfig/`. You may need to add path `/usr/local/lib/` to `DYLD_FALLBACK_LIBRARY_PATH` if binaries are unable to load uhdr library e.g. `export DYLD_FALLBACK_LIBRARY_PATH=$DYLD_FALLBACK_LIBRARY_PATH:/usr/local/lib/`.
+
+Uninstallation:
+
+```sh
+sudo ninja uninstall
+```
+
+### Windows Platform - MSYS Env
+
+Install the prerequisite packages before building:
+
+```sh
+pacman -S mingw-w64-x86_64-libjpeg-turbo mingw-w64-x86_64-ninja
+```
+
+Compile and Test:
+
+```sh
+cmake -G Ninja -DUHDR_BUILD_TESTS=1 ../
+ninja
+ctest
+```
+
+This will generate the following files under `build_directory`:
+
+**libuhdr.dll** - Shared library for the libuhdr API <br>
+**libuhdr.dll.a** - Import library for the libuhdr API <br>
+**libuhdr.a** - Static link library for the libuhdr API <br>
+**libuhdr.pc** - libuhdr pkg-config file <br>
+**ultrahdr_app** - sample application <br>
+**ultrahdr_unit_test** - unit tests <br>
+
+### Windows Platform - MSVC Env
+
+#### IDE
+
+Compile and Test:
+
+```sh
+cmake -G "Visual Studio 16 2019" -DUHDR_BUILD_DEPS=1 -DUHDR_BUILD_TESTS=1 ../
+cmake --build ./ --config=Release
+ctest -C Release
+```
+
+#### Command Line
+
+Compile and Test:
+
+```sh
+cmake -G "NMake Makefiles" -DUHDR_BUILD_DEPS=1 -DUHDR_BUILD_TESTS=1 ../
+cmake --build ./
+ctest
+```
+
+This will generate the following files under `build_directory`:
+
+**uhdr.dll** - Shared library for the libuhdr API <br>
+**uhdr.lib** - Import library for the libuhdr API <br>
+**uhdr-static.lib** - Static link library for the libuhdr API <br>
+**ultrahdr_app** - sample application <br>
+**ultrahdr_unit_test** - unit tests <br>
+
+### Cross-Compilation - Build System Linux
+
+#### Target - Linux Platform - Armv7 Arch
+
+Install the prerequisite packages before building:
+
+```sh
+sudo apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
+```
+
+Compile:
+
+```sh
+cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/arm-linux-gnueabihf.cmake -DUHDR_BUILD_DEPS=1 ../
+ninja
+```
+
+#### Target - Linux Platform - Armv8 Arch
+
+Install the prerequisite packages before building:
+
+```sh
+sudo apt install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
+```
+
+Compile:
+
+```sh
+cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/aarch64-linux-gnu.cmake -DUHDR_BUILD_DEPS=1 ../
+ninja
+```
+
+#### Target - Linux Platform - RISC-V Arch (64 bit)
+
+Install the prerequisite packages before building:
+
+```sh
+sudo apt install gcc-riscv64-linux-gnu g++-riscv64-linux-gnu
+```
+
+Compile:
+
+```sh
+cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/riscv64-linux-gnu.cmake -DUHDR_BUILD_DEPS=1 ../
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
+#### Target - Android Platform
+
+Install the prerequisite packages before building:
+
+```sh
+wget https://dl.google.com/android/repository/android-ndk-r26d-linux.zip
+unzip android-ndk-r26d-linux.zip
+```
+
+Choose target architecture with -DANDROID_ABI={armeabi-v7a, arm64-v8a, x86, x86_64}
+
+Compile:
+```sh
+cmake -G Ninja -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/android.cmake -DUHDR_ANDROID_NDK_PATH=/opt/android-ndk-r26d/ -DUHDR_BUILD_DEPS=1 -DANDROID_ABI="Selected Architecture" -DANDROID_PLATFORM=android-23 ../
+ninja
+```
+
+This will generate the following files under `build_directory`:
+
+**libuhdr.so** - Shared library for the libuhdr API <br>
+**libuhdr.a** - Static link library for the libuhdr API <br>
+**ultrahdr_app** - sample application <br>
+**ultrahdr_unit_test** - unit tests <br>
+
+## Building Fuzzers
+
+Refer to [fuzzers.md](fuzzers.md) for complete instructions.
diff --git a/docs/fuzzers.md b/docs/fuzzers.md
new file mode 100644
index 0000000..bc3f599
--- /dev/null
+++ b/docs/fuzzers.md
@@ -0,0 +1,74 @@
+## Building fuzzers for libultrahdr
+
+### Requirements
+
+- Refer [Requirements](./building.md#Requirements)
+
+- Additionally compilers are required to support options `-fsanitize=fuzzer, -fsanitize=fuzzer-no-link`.
+  For instance, `clang 12` (or later)
+
+### Building Commands
+
+```sh
+cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1
+ninja
+```
+
+This will generate the following files under `build_directory`:
+
+**ultrahdr_enc_fuzzer** - ultrahdr encoder fuzzer <br>
+**ultrahdr_dec_fuzzer** - ultrahdr decoder fuzzer <br>
+
+Additionally, while building fuzzers, user can enable sanitizers by providing desired
+sanitizer option(s) through `UHDR_SANITIZE_OPTIONS`.
+
+To enable ASan,
+
+```sh
+cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address
+ninja
+```
+
+To enable MSan,
+
+```sh
+cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=memory
+ninja
+```
+To enable TSan,
+
+```sh
+cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=thread
+ninja
+```
+
+To enable UBSan,
+
+```sh
+cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=undefined
+ninja
+```
+
+UBSan can be grouped with ASan, MSan or TSan.
+
+For example, to enable ASan and UBSan,
+
+```sh
+cmake -G Ninja ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address,undefined
+ninja
+```
+
+### Running
+
+To run the fuzzer(s), first create a corpus directory that holds the initial
+"seed" sample inputs. For decoder fuzzer, ultrahdr jpeg images can be used and
+for encoder fuzzer, sample yuv files can be used.
+
+Then run the fuzzers on the corpus directory.
+
+```sh
+mkdir CORPUS_DIR
+cp seeds/* CORPUS_DIR
+./ultrahdr_dec_fuzzer CORPUS_DIR
+./ultrahdr_enc_fuzzer CORPUS_DIR
+```
diff --git a/examples/Android.bp b/examples/Android.bp
index 72b0777..22afbed 100644
--- a/examples/Android.bp
+++ b/examples/Android.bp
@@ -38,4 +38,12 @@ cc_binary {
         "libjpegencoder",
         "libultrahdr",
     ],
+    target: {
+        android: {
+            shared_libs: [
+                "libEGL",
+                "libGLESv3",
+            ],
+        },
+    },
 }
diff --git a/examples/ultrahdr_app.cpp b/examples/ultrahdr_app.cpp
index 8050fd5..90f83ba 100644
--- a/examples/ultrahdr_app.cpp
+++ b/examples/ultrahdr_app.cpp
@@ -23,6 +23,7 @@
 #include <string.h>
 
 #include <algorithm>
+#include <cfloat>
 #include <cmath>
 #include <cstdint>
 #include <fstream>
@@ -246,19 +247,25 @@ class UltraHdrAppInput {
  public:
   UltraHdrAppInput(const char* hdrIntentRawFile, const char* sdrIntentRawFile,
                    const char* sdrIntentCompressedFile, const char* gainmapCompressedFile,
-                   const char* gainmapMetadataCfgFile, const char* outputFile, size_t width,
-                   size_t height, uhdr_img_fmt_t hdrCf = UHDR_IMG_FMT_32bppRGBA1010102,
+                   const char* gainmapMetadataCfgFile, const char* exifFile, const char* outputFile,
+                   size_t width, size_t height,
+                   uhdr_img_fmt_t hdrCf = UHDR_IMG_FMT_32bppRGBA1010102,
                    uhdr_img_fmt_t sdrCf = UHDR_IMG_FMT_32bppRGBA8888,
                    uhdr_color_gamut_t hdrCg = UHDR_CG_DISPLAY_P3,
                    uhdr_color_gamut_t sdrCg = UHDR_CG_BT_709,
                    uhdr_color_transfer_t hdrTf = UHDR_CT_HLG, int quality = 95,
                    uhdr_color_transfer_t oTf = UHDR_CT_HLG,
-                   uhdr_img_fmt_t oFmt = UHDR_IMG_FMT_32bppRGBA1010102)
+                   uhdr_img_fmt_t oFmt = UHDR_IMG_FMT_32bppRGBA1010102, bool isHdrCrFull = false,
+                   int gainmapScaleFactor = 1, int gainmapQuality = 95,
+                   bool enableMultiChannelGainMap = true, float gamma = 1.0f,
+                   bool enableGLES = false, uhdr_enc_preset_t encPreset = UHDR_USAGE_BEST_QUALITY,
+                   float minContentBoost = FLT_MIN, float maxContentBoost = FLT_MAX)
       : mHdrIntentRawFile(hdrIntentRawFile),
         mSdrIntentRawFile(sdrIntentRawFile),
         mSdrIntentCompressedFile(sdrIntentCompressedFile),
         mGainMapCompressedFile(gainmapCompressedFile),
         mGainMapMetadataCfgFile(gainmapMetadataCfgFile),
+        mExifFile(exifFile),
         mUhdrFile(nullptr),
         mOutputFile(outputFile),
         mWidth(width),
@@ -271,13 +278,26 @@ class UltraHdrAppInput {
         mQuality(quality),
         mOTf(oTf),
         mOfmt(oFmt),
+        mFullRange(isHdrCrFull),
+        mMapDimensionScaleFactor(gainmapScaleFactor),
+        mMapCompressQuality(gainmapQuality),
+        mUseMultiChannelGainMap(enableMultiChannelGainMap),
+        mGamma(gamma),
+        mEnableGLES(enableGLES),
+        mEncPreset(encPreset),
+        mMinContentBoost(minContentBoost),
+        mMaxContentBoost(maxContentBoost),
         mMode(0){};
 
-  UltraHdrAppInput(const char* uhdrFile, const char* outputFile,
+  UltraHdrAppInput(const char* gainmapMetadataCfgFile, const char* uhdrFile, const char* outputFile,
                    uhdr_color_transfer_t oTf = UHDR_CT_HLG,
-                   uhdr_img_fmt_t oFmt = UHDR_IMG_FMT_32bppRGBA1010102)
+                   uhdr_img_fmt_t oFmt = UHDR_IMG_FMT_32bppRGBA1010102, bool enableGLES = false)
       : mHdrIntentRawFile(nullptr),
         mSdrIntentRawFile(nullptr),
+        mSdrIntentCompressedFile(nullptr),
+        mGainMapCompressedFile(nullptr),
+        mGainMapMetadataCfgFile(gainmapMetadataCfgFile),
+        mExifFile(nullptr),
         mUhdrFile(uhdrFile),
         mOutputFile(outputFile),
         mWidth(0),
@@ -290,6 +310,15 @@ class UltraHdrAppInput {
         mQuality(95),
         mOTf(oTf),
         mOfmt(oFmt),
+        mFullRange(UHDR_CR_UNSPECIFIED),
+        mMapDimensionScaleFactor(1),
+        mMapCompressQuality(95),
+        mUseMultiChannelGainMap(true),
+        mGamma(1.0f),
+        mEnableGLES(enableGLES),
+        mEncPreset(UHDR_USAGE_BEST_QUALITY),
+        mMinContentBoost(FLT_MIN),
+        mMaxContentBoost(FLT_MAX),
         mMode(1){};
 
   ~UltraHdrAppInput() {
@@ -320,6 +349,7 @@ class UltraHdrAppInput {
         mDecodedUhdrYuv444Image.planes[i] = nullptr;
       }
     }
+    if (mExifBlock.data) free(mExifBlock.data);
     if (mUhdrImage.data) free(mUhdrImage.data);
   }
 
@@ -333,6 +363,8 @@ class UltraHdrAppInput {
   bool fillSdrCompressedImageHandle();
   bool fillGainMapCompressedImageHandle();
   bool fillGainMapMetadataDescriptor();
+  bool fillExifMemoryBlock();
+  bool writeGainMapMetadataToFile(uhdr_gainmap_metadata_t* metadata);
   bool convertRgba8888ToYUV444Image();
   bool convertRgba1010102ToYUV444Image();
   bool encode();
@@ -347,6 +379,7 @@ class UltraHdrAppInput {
   const char* mSdrIntentCompressedFile;
   const char* mGainMapCompressedFile;
   const char* mGainMapMetadataCfgFile;
+  const char* mExifFile;
   const char* mUhdrFile;
   const char* mOutputFile;
   const int mWidth;
@@ -359,6 +392,15 @@ class UltraHdrAppInput {
   const int mQuality;
   const uhdr_color_transfer_t mOTf;
   const uhdr_img_fmt_t mOfmt;
+  const bool mFullRange;
+  const size_t mMapDimensionScaleFactor;
+  const int mMapCompressQuality;
+  const bool mUseMultiChannelGainMap;
+  const float mGamma;
+  const bool mEnableGLES;
+  const uhdr_enc_preset_t mEncPreset;
+  const float mMinContentBoost;
+  const float mMaxContentBoost;
   const int mMode;
 
   uhdr_raw_image_t mRawP010Image{};
@@ -368,6 +410,7 @@ class UltraHdrAppInput {
   uhdr_compressed_image_t mSdrIntentCompressedImage{};
   uhdr_compressed_image_t mGainMapCompressedImage{};
   uhdr_gainmap_metadata mGainMapMetadata{};
+  uhdr_mem_block_t mExifBlock{};
   uhdr_compressed_image_t mUhdrImage{};
   uhdr_raw_image_t mDecodedUhdrRgbImage{};
   uhdr_raw_image_t mDecodedUhdrYuv444Image{};
@@ -380,7 +423,8 @@ bool UltraHdrAppInput::fillP010ImageHandle() {
   mRawP010Image.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
   mRawP010Image.cg = mHdrCg;
   mRawP010Image.ct = mHdrTf;
-  mRawP010Image.range = UHDR_CR_LIMITED_RANGE;
+
+  mRawP010Image.range = mFullRange ? UHDR_CR_FULL_RANGE : UHDR_CR_LIMITED_RANGE;
   mRawP010Image.w = mWidth;
   mRawP010Image.h = mHeight;
   mRawP010Image.planes[UHDR_PLANE_Y] = malloc(mWidth * mHeight * bpp);
@@ -511,6 +555,32 @@ bool UltraHdrAppInput::fillGainMapMetadataDescriptor() {
   return true;
 }
 
+bool UltraHdrAppInput::fillExifMemoryBlock() {
+  std::ifstream ifd(mExifFile, std::ios::binary | std::ios::ate);
+  if (ifd.good()) {
+    int size = ifd.tellg();
+    ifd.close();
+    return loadFile(mExifFile, mExifBlock.data, size);
+  }
+  return false;
+}
+
+bool UltraHdrAppInput::writeGainMapMetadataToFile(uhdr_gainmap_metadata_t* metadata) {
+  std::ofstream file(mGainMapMetadataCfgFile);
+  if (!file.is_open()) {
+    return false;
+  }
+  file << "--maxContentBoost " << metadata->max_content_boost << std::endl;
+  file << "--minContentBoost " << metadata->min_content_boost << std::endl;
+  file << "--gamma " << metadata->gamma << std::endl;
+  file << "--offsetSdr " << metadata->offset_sdr << std::endl;
+  file << "--offsetHdr " << metadata->offset_hdr << std::endl;
+  file << "--hdrCapacityMin " << metadata->hdr_capacity_min << std::endl;
+  file << "--hdrCapacityMax " << metadata->hdr_capacity_max << std::endl;
+  file.close();
+  return true;
+}
+
 bool UltraHdrAppInput::fillUhdrImageHandle() {
   std::ifstream ifd(mUhdrFile, std::ios::binary | std::ios::ate);
   if (ifd.good()) {
@@ -576,6 +646,12 @@ bool UltraHdrAppInput::encode() {
       return false;
     }
   }
+  if (mExifFile != nullptr) {
+    if (!fillExifMemoryBlock()) {
+      std::cerr << " failed to load file " << mExifFile << std::endl;
+      return false;
+    }
+  }
 
 #define RET_IF_ERR(x)                            \
   {                                              \
@@ -612,18 +688,30 @@ bool UltraHdrAppInput::encode() {
   if (mGainMapCompressedFile != nullptr && mGainMapMetadataCfgFile != nullptr) {
     RET_IF_ERR(uhdr_enc_set_gainmap_image(handle, &mGainMapCompressedImage, &mGainMapMetadata))
   }
+  if (mExifFile != nullptr) {
+    RET_IF_ERR(uhdr_enc_set_exif_data(handle, &mExifBlock))
+  }
+
   RET_IF_ERR(uhdr_enc_set_quality(handle, mQuality, UHDR_BASE_IMG))
+  RET_IF_ERR(uhdr_enc_set_quality(handle, mMapCompressQuality, UHDR_GAIN_MAP_IMG))
+  RET_IF_ERR(uhdr_enc_set_using_multi_channel_gainmap(handle, mUseMultiChannelGainMap))
+  RET_IF_ERR(uhdr_enc_set_gainmap_scale_factor(handle, mMapDimensionScaleFactor))
+  RET_IF_ERR(uhdr_enc_set_gainmap_gamma(handle, mGamma))
+  RET_IF_ERR(uhdr_enc_set_preset(handle, mEncPreset))
+  if (mMinContentBoost != FLT_MIN || mMaxContentBoost != FLT_MAX) {
+    RET_IF_ERR(uhdr_enc_set_min_max_content_boost(handle, mMinContentBoost, mMaxContentBoost))
+  }
+  if (mEnableGLES) {
+    RET_IF_ERR(uhdr_enable_gpu_acceleration(handle, mEnableGLES))
+  }
 #ifdef PROFILE_ENABLE
-  const int profileCount = 10;
   Profiler profileEncode;
   profileEncode.timerStart();
-  for (auto i = 0; i < profileCount; i++) {
 #endif
-    RET_IF_ERR(uhdr_encode(handle))
+  RET_IF_ERR(uhdr_encode(handle))
 #ifdef PROFILE_ENABLE
-  }
   profileEncode.timerStop();
-  auto avgEncTime = profileEncode.elapsedTime() / (profileCount * 1000.f);
+  auto avgEncTime = profileEncode.elapsedTime() / 1000.f;
   printf("Average encode time for res %d x %d is %f ms \n", mWidth, mHeight, avgEncTime);
 #endif
 
@@ -638,10 +726,9 @@ bool UltraHdrAppInput::encode() {
   mUhdrImage.cg = output->cg;
   mUhdrImage.ct = output->ct;
   mUhdrImage.range = output->range;
-  writeFile(mOutputFile, output->data, output->data_sz);
   uhdr_release_encoder(handle);
 
-  return true;
+  return writeFile(mOutputFile, mUhdrImage.data, mUhdrImage.data_sz);
 }
 
 bool UltraHdrAppInput::decode() {
@@ -666,19 +753,28 @@ bool UltraHdrAppInput::decode() {
   RET_IF_ERR(uhdr_dec_set_image(handle, &mUhdrImage))
   RET_IF_ERR(uhdr_dec_set_out_color_transfer(handle, mOTf))
   RET_IF_ERR(uhdr_dec_set_out_img_format(handle, mOfmt))
+  if (mEnableGLES) {
+    RET_IF_ERR(uhdr_enable_gpu_acceleration(handle, mEnableGLES))
+  }
+  RET_IF_ERR(uhdr_dec_probe(handle))
+  if (mGainMapMetadataCfgFile != nullptr) {
+    uhdr_gainmap_metadata_t* metadata = uhdr_dec_get_gainmap_metadata(handle);
+    if (!writeGainMapMetadataToFile(metadata)) {
+      std::cerr << "failed to write gainmap metadata to file: " << mGainMapMetadataCfgFile
+                << std::endl;
+    }
+  }
 
 #ifdef PROFILE_ENABLE
-  const int profileCount = 10;
   Profiler profileDecode;
   profileDecode.timerStart();
-  for (auto i = 0; i < profileCount; i++) {
 #endif
-    RET_IF_ERR(uhdr_decode(handle))
+  RET_IF_ERR(uhdr_decode(handle))
 #ifdef PROFILE_ENABLE
-  }
   profileDecode.timerStop();
-  auto avgDecTime = profileDecode.elapsedTime() / (profileCount * 1000.f);
-  printf("Average decode time for res %ld x %ld is %f ms \n", info.width, info.height, avgDecTime);
+  auto avgDecTime = profileDecode.elapsedTime() / 1000.f;
+  printf("Average decode time for res %d x %d is %f ms \n", uhdr_dec_get_image_width(handle),
+         uhdr_dec_get_image_height(handle), avgDecTime);
 #endif
 
 #undef RET_IF_ERR
@@ -702,10 +798,9 @@ bool UltraHdrAppInput::decode() {
   for (unsigned i = 0; i < output->h; i++, inData += inStride, outData += outStride) {
     memcpy(outData, inData, length);
   }
-  writeFile(mOutputFile, output);
   uhdr_release_decoder(handle);
 
-  return true;
+  return mMode == 1 ? writeFile(mOutputFile, &mDecodedUhdrRgbImage) : true;
 }
 
 #define CLIP3(x, min, max) ((x) < (min)) ? (min) : ((x) > (max)) ? (max) : (x)
@@ -746,13 +841,23 @@ bool UltraHdrAppInput::convertP010ToRGBImage() {
       float u0 = float(u[mRawP010Image.stride[UHDR_PLANE_UV] * (i / 2) + (j / 2) * 2] >> 6);
       float v0 = float(v[mRawP010Image.stride[UHDR_PLANE_UV] * (i / 2) + (j / 2) * 2] >> 6);
 
-      y0 = CLIP3(y0, 64.0f, 940.0f);
-      u0 = CLIP3(u0, 64.0f, 960.0f);
-      v0 = CLIP3(v0, 64.0f, 960.0f);
+      if (mRawP010Image.range == UHDR_CR_FULL_RANGE) {
+        y0 = CLIP3(y0, 0.0f, 1023.0f);
+        u0 = CLIP3(u0, 0.0f, 1023.0f);
+        v0 = CLIP3(v0, 0.0f, 1023.0f);
 
-      y0 = (y0 - 64.0f) / 876.0f;
-      u0 = (u0 - 512.0f) / 896.0f;
-      v0 = (v0 - 512.0f) / 896.0f;
+        y0 = y0 / 1023.0f;
+        u0 = u0 / 1023.0f - 0.5f;
+        v0 = v0 / 1023.0f - 0.5f;
+      } else {
+        y0 = CLIP3(y0, 64.0f, 940.0f);
+        u0 = CLIP3(u0, 64.0f, 960.0f);
+        v0 = CLIP3(v0, 64.0f, 960.0f);
+
+        y0 = (y0 - 64.0f) / 876.0f;
+        u0 = (u0 - 512.0f) / 896.0f;
+        v0 = (v0 - 512.0f) / 896.0f;
+      }
 
       float r = coeffs[0] * y0 + coeffs[1] * u0 + coeffs[2] * v0;
       float g = coeffs[3] * y0 + coeffs[4] * u0 + coeffs[5] * v0;
@@ -929,7 +1034,7 @@ bool UltraHdrAppInput::convertRgba1010102ToYUV444Image() {
   mDecodedUhdrYuv444Image.fmt = static_cast<uhdr_img_fmt_t>(UHDR_IMG_FMT_48bppYCbCr444);
   mDecodedUhdrYuv444Image.cg = mDecodedUhdrRgbImage.cg;
   mDecodedUhdrYuv444Image.ct = mDecodedUhdrRgbImage.ct;
-  mDecodedUhdrYuv444Image.range = UHDR_CR_LIMITED_RANGE;
+  mDecodedUhdrYuv444Image.range = mRawP010Image.range;
   mDecodedUhdrYuv444Image.w = mDecodedUhdrRgbImage.w;
   mDecodedUhdrYuv444Image.h = mDecodedUhdrRgbImage.h;
   mDecodedUhdrYuv444Image.planes[UHDR_PLANE_Y] =
@@ -964,13 +1069,23 @@ bool UltraHdrAppInput::convertRgba1010102ToYUV444Image() {
       float u = coeffs[3] * r0 + coeffs[4] * g0 + coeffs[5] * b0;
       float v = coeffs[6] * r0 + coeffs[7] * g0 + coeffs[8] * b0;
 
-      y = (y * 876.0f) + 64.0f + 0.5f;
-      u = (u * 896.0f) + 512.0f + 0.5f;
-      v = (v * 896.0f) + 512.0f + 0.5f;
+      if (mRawP010Image.range == UHDR_CR_FULL_RANGE) {
+        y = y * 1023.0f + 0.5f;
+        u = (u + 0.5f) * 1023.0f + 0.5f;
+        v = (v + 0.5f) * 1023.0f + 0.5f;
+
+        y = CLIP3(y, 0.0f, 1023.0f);
+        u = CLIP3(u, 0.0f, 1023.0f);
+        v = CLIP3(v, 0.0f, 1023.0f);
+      } else {
+        y = (y * 876.0f) + 64.0f + 0.5f;
+        u = (u * 896.0f) + 512.0f + 0.5f;
+        v = (v * 896.0f) + 512.0f + 0.5f;
 
-      y = CLIP3(y, 64.0f, 940.0f);
-      u = CLIP3(u, 64.0f, 960.0f);
-      v = CLIP3(v, 64.0f, 960.0f);
+        y = CLIP3(y, 64.0f, 940.0f);
+        u = CLIP3(u, 64.0f, 960.0f);
+        v = CLIP3(v, 64.0f, 960.0f);
+      }
 
       yData[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_Y] * i + j] = uint16_t(y);
       uData[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * i + j] = uint16_t(u);
@@ -994,8 +1109,13 @@ void UltraHdrAppInput::computeRGBHdrPSNR() {
     std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
     return;
   }
-  if (mOTf != mHdrTf) {
-    std::cout << "input transfer function and output format are not compatible, psnr results "
+  if (mRawRgba1010102Image.ct != mDecodedUhdrRgbImage.ct) {
+    std::cout << "input color transfer and output color transfer are not identical, rgb psnr "
+                 "results may be unreliable"
+              << std::endl;
+  }
+  if (mRawRgba1010102Image.cg != mDecodedUhdrRgbImage.cg) {
+    std::cout << "input color gamut and output color gamut are not identical, rgb psnr results "
                  "may be unreliable"
               << std::endl;
   }
@@ -1025,8 +1145,7 @@ void UltraHdrAppInput::computeRGBHdrPSNR() {
   meanSquareError = (double)bSqError / (mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mPsnr[2] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;
 
-  std::cout << "psnr r :: " << mPsnr[0] << " psnr g :: " << mPsnr[1] << " psnr b :: " << mPsnr[2]
-            << std::endl;
+  std::cout << "psnr rgb: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
 }
 
 void UltraHdrAppInput::computeRGBSdrPSNR() {
@@ -1067,8 +1186,7 @@ void UltraHdrAppInput::computeRGBSdrPSNR() {
   meanSquareError = (double)bSqError / (mDecodedUhdrRgbImage.w * mDecodedUhdrRgbImage.h);
   mPsnr[2] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;
 
-  std::cout << "psnr r :: " << mPsnr[0] << " psnr g :: " << mPsnr[1] << " psnr b :: " << mPsnr[2]
-            << std::endl;
+  std::cout << "psnr rgb: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
 }
 
 void UltraHdrAppInput::computeYUVHdrPSNR() {
@@ -1088,8 +1206,18 @@ void UltraHdrAppInput::computeYUVHdrPSNR() {
     std::cerr << "invalid src or dst pointer for psnr computation " << std::endl;
     return;
   }
-  if (mOTf != mHdrTf) {
-    std::cout << "input transfer function and output format are not compatible, psnr results "
+  if (mRawP010Image.ct != mDecodedUhdrYuv444Image.ct) {
+    std::cout << "input color transfer and output color transfer are not identical, yuv psnr "
+                 "results may be unreliable"
+              << std::endl;
+  }
+  if (mRawP010Image.cg != mDecodedUhdrYuv444Image.cg) {
+    std::cout << "input color gamut and output color gamut are not identical, yuv psnr results "
+                 "may be unreliable"
+              << std::endl;
+  }
+  if (mRawP010Image.range != mDecodedUhdrYuv444Image.range) {
+    std::cout << "input range and output range are not identical, yuv psnr results "
                  "may be unreliable"
               << std::endl;
   }
@@ -1098,27 +1226,27 @@ void UltraHdrAppInput::computeYUVHdrPSNR() {
   for (size_t i = 0; i < mDecodedUhdrYuv444Image.h; i++) {
     for (size_t j = 0; j < mDecodedUhdrYuv444Image.w; j++) {
       int ySrc = (yDataSrc[mRawP010Image.stride[UHDR_PLANE_Y] * i + j] >> 6) & 0x3ff;
-      ySrc = CLIP3(ySrc, 64, 940);
+      if (mRawP010Image.range == UHDR_CR_LIMITED_RANGE) ySrc = CLIP3(ySrc, 64, 940);
       int yDst = yDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_Y] * i + j] & 0x3ff;
       ySqError += (ySrc - yDst) * (ySrc - yDst);
 
       if (i % 2 == 0 && j % 2 == 0) {
         int uSrc =
             (uDataSrc[mRawP010Image.stride[UHDR_PLANE_UV] * (i / 2) + (j / 2) * 2] >> 6) & 0x3ff;
-        uSrc = CLIP3(uSrc, 64, 960);
+        if (mRawP010Image.range == UHDR_CR_LIMITED_RANGE) uSrc = CLIP3(uSrc, 64, 960);
         int uDst = uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * i + j] & 0x3ff;
         uDst += uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * i + j + 1] & 0x3ff;
-        uDst += uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * (i + 1) + j + 1] & 0x3ff;
+        uDst += uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * (i + 1) + j] & 0x3ff;
         uDst += uDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_U] * (i + 1) + j + 1] & 0x3ff;
         uDst = (uDst + 2) >> 2;
         uSqError += (uSrc - uDst) * (uSrc - uDst);
 
         int vSrc =
             (vDataSrc[mRawP010Image.stride[UHDR_PLANE_UV] * (i / 2) + (j / 2) * 2] >> 6) & 0x3ff;
-        vSrc = CLIP3(vSrc, 64, 960);
+        if (mRawP010Image.range == UHDR_CR_LIMITED_RANGE) vSrc = CLIP3(vSrc, 64, 960);
         int vDst = vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * i + j] & 0x3ff;
         vDst += vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * i + j + 1] & 0x3ff;
-        vDst += vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * (i + 1) + j + 1] & 0x3ff;
+        vDst += vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * (i + 1) + j] & 0x3ff;
         vDst += vDataDst[mDecodedUhdrYuv444Image.stride[UHDR_PLANE_V] * (i + 1) + j + 1] & 0x3ff;
         vDst = (vDst + 2) >> 2;
         vSqError += (vSrc - vDst) * (vSrc - vDst);
@@ -1136,8 +1264,7 @@ void UltraHdrAppInput::computeYUVHdrPSNR() {
   meanSquareError = (double)vSqError / (mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
   mPsnr[2] = meanSquareError ? 10 * log10((double)1023 * 1023 / meanSquareError) : 100;
 
-  std::cout << "psnr y :: " << mPsnr[0] << " psnr u :: " << mPsnr[1] << " psnr v :: " << mPsnr[2]
-            << std::endl;
+  std::cout << "psnr yuv: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
 }
 
 void UltraHdrAppInput::computeYUVSdrPSNR() {
@@ -1190,45 +1317,68 @@ void UltraHdrAppInput::computeYUVSdrPSNR() {
   meanSquareError = (double)vSqError / (mDecodedUhdrYuv444Image.w * mDecodedUhdrYuv444Image.h / 4);
   mPsnr[2] = meanSquareError ? 10 * log10((double)255 * 255 / meanSquareError) : 100;
 
-  std::cout << "psnr y :: " << mPsnr[0] << " psnr u :: " << mPsnr[1] << " psnr v :: " << mPsnr[2]
-            << std::endl;
+  std::cout << "psnr yuv: \t" << mPsnr[0] << " \t " << mPsnr[1] << " \t " << mPsnr[2] << std::endl;
 }
 
 static void usage(const char* name) {
-  fprintf(stderr, "\n## ultra hdr demo application.\nUsage : %s \n", name);
+  fprintf(stderr, "\n## ultra hdr demo application. lib version: v%s \nUsage : %s \n",
+          UHDR_LIB_VERSION_STR, name);
   fprintf(stderr, "    -m    mode of operation. [0:encode, 1:decode] \n");
   fprintf(stderr, "\n## encoder options : \n");
   fprintf(stderr,
-          "    -p    raw 10 bit input resource, required for encoding scenarios 0, 1, 2, 3. \n");
-  fprintf(stderr, "    -y    raw 8 bit input resource, required for encoding scenarios 1, 2. \n");
+          "    -p    raw hdr intent input resource (10-bit), required for encoding scenarios 0, 1, "
+          "2, 3. \n");
+  fprintf(
+      stderr,
+      "    -y    raw sdr intent input resource (8-bit), required for encoding scenarios 1, 2. \n");
+  fprintf(stderr,
+          "    -a    raw hdr intent color format, optional. [0:p010, 5:rgba1010102 (default)] \n");
+  fprintf(stderr,
+          "    -b    raw sdr intent color format, optional. [1:yuv420, 3:rgba8888 (default)] \n");
   fprintf(stderr,
-          "    -a    raw 10 bit input resource color format, optional. [0:p010, 5:rgba1010102 "
-          "(default)] \n");
+          "    -i    compressed sdr intent input resource (jpeg), required for encoding scenarios "
+          "2, 3, 4. \n");
+  fprintf(
+      stderr,
+      "    -g    compressed gainmap input resource (jpeg), required for encoding scenario 4. \n");
+  fprintf(stderr, "    -w    input file width, required for encoding scenarios 0, 1, 2, 3. \n");
+  fprintf(stderr, "    -h    input file height, required for encoding scenarios 0, 1, 2, 3. \n");
   fprintf(stderr,
-          "    -b    raw 8 bit input resource color format, optional. [1:yuv420, 3:rgba8888 "
-          "(default)] \n");
+          "    -C    hdr intent color gamut, optional. [0:bt709, 1:p3 (default), 2:bt2100] \n");
+  fprintf(stderr,
+          "    -c    sdr intent color gamut, optional. [0:bt709 (default), 1:p3, 2:bt2100] \n");
+  fprintf(stderr,
+          "    -t    hdr intent color transfer, optional. [0:linear, 1:hlg (default), 2:pq] \n");
+  fprintf(stderr,
+          "    -q    quality factor to be used while encoding sdr intent, optional. [0-100], 95 : "
+          "default.\n");
+  fprintf(stderr, "    -e    compute psnr, optional. [0:no (default), 1:yes] \n");
   fprintf(stderr,
-          "    -i    compressed 8 bit jpeg file path, required for encoding scenarios 2, 3, 4. \n");
+          "    -R    color range of hdr intent, optional. [0:narrow-range (default), "
+          "1:full-range]. \n");
   fprintf(stderr,
-          "    -g    compressed 8 bit gainmap file path, required for encoding scenario 4. \n");
-  fprintf(stderr, "    -f    gainmap metadata config file, required for encoding scenario 4. \n");
-  fprintf(stderr, "    -w    input file width. \n");
-  fprintf(stderr, "    -h    input file height. \n");
+          "    -s    gainmap image downsample factor, optional. [integer values in range [1 - 128] "
+          "(1 : default)]. \n");
   fprintf(stderr,
-          "    -C    10 bit input color gamut, optional. [0:bt709, 1:p3 (default), 2:bt2100] \n");
+          "    -Q    quality factor to be used while encoding gain map image, optional. [0-100], "
+          "95 : default. \n");
   fprintf(stderr,
-          "    -c    8 bit input color gamut, optional. [0:bt709 (default), 1:p3, 2:bt2100] \n");
+          "    -G    gamma correction to be applied on the gainmap image, optional. [any positive "
+          "real number (1.0 : default)].\n");
+  fprintf(stderr,
+          "    -M    select multi channel gain map, optional. [0:disable, 1:enable (default)]. \n");
   fprintf(
       stderr,
-      "    -t    10 bit input transfer function, optional. [0:linear, 1:hlg (default), 2:pq] \n");
+      "    -D    select encoding preset, optional. [0:real time, 1:best quality (default)]. \n");
   fprintf(stderr,
-          "    -q    quality factor to be used while encoding 8 bit image, optional. [0-100], 95 : "
-          "default.\n"
-          "          gain map image does not use this quality factor. \n"
-          "          for now gain map image quality factor is not configurable. \n");
-  fprintf(stderr, "    -e    compute psnr, optional. [0:no (default), 1:yes] \n");
+          "    -k    min content boost recommendation, must be in linear scale, optional. [any "
+          "positive real number] \n");
+  fprintf(stderr,
+          "    -K    max content boost recommendation, must be in linear scale, optional.[any "
+          "positive real number] \n");
+  fprintf(stderr, "    -x    binary input resource containing exif data to insert, optional. \n");
   fprintf(stderr, "\n## decoder options : \n");
-  fprintf(stderr, "    -j    ultra hdr compressed input resource. \n");
+  fprintf(stderr, "    -j    ultra hdr compressed input resource, required. \n");
   fprintf(
       stderr,
       "    -o    output transfer function, optional. [0:linear, 1:hlg (default), 2:pq, 3:srgb] \n");
@@ -1241,11 +1391,19 @@ static void usage(const char* name) {
       "          srgb output color transfer shall be paired with rgba8888 only. \n"
       "          hlg, pq shall be paired with rgba1010102. \n"
       "          linear shall be paired with rgbahalffloat. \n");
+  fprintf(stderr,
+          "    -u    enable gles acceleration, optional. [0:disable (default), 1:enable]. \n");
   fprintf(stderr, "\n## common options : \n");
   fprintf(stderr,
           "    -z    output filename, optional. \n"
           "          in encoding mode, default output filename 'out.jpeg'. \n"
           "          in decoding mode, default output filename 'outrgb.raw'. \n");
+  fprintf(
+      stderr,
+      "    -f    gainmap metadata config file. \n"
+      "          in encoding mode, resource from which gainmap metadata is read, required for "
+      "encoding scenario 4. \n"
+      "          in decoding mode, resource to which gainmap metadata is written, optional. \n");
   fprintf(stderr, "\n## examples of usage :\n");
   fprintf(stderr, "\n## encode scenario 0 :\n");
   fprintf(stderr,
@@ -1292,6 +1450,11 @@ static void usage(const char* name) {
   fprintf(stderr,
           "    ultrahdr_app -m 0 -i cosmat_1920x1080_420_8bit.jpg -g cosmat_1920x1080_420_8bit.jpg "
           "-f metadata.cfg\n");
+  fprintf(stderr, "\n## encode at high quality :\n");
+  fprintf(stderr,
+          "    ultrahdr_app -m 0 -p hdr_intent.raw -y sdr_intent.raw -w 640 -h 480 -c <select> -C "
+          "<select> -t <select> -s 1 -M 1 -Q 98 -q 98 -D 1\n");
+
   fprintf(stderr, "\n## decode api :\n");
   fprintf(stderr, "    ultrahdr_app -m 1 -j cosmat_1920x1080_hdr.jpg \n");
   fprintf(stderr, "    ultrahdr_app -m 1 -j cosmat_1920x1080_hdr.jpg -o 3 -O 3\n");
@@ -1300,10 +1463,10 @@ static void usage(const char* name) {
 }
 
 int main(int argc, char* argv[]) {
-  char opt_string[] = "p:y:i:g:f:w:h:C:c:t:q:o:O:m:j:e:a:b:z:";
+  char opt_string[] = "p:y:i:g:f:w:h:C:c:t:q:o:O:m:j:e:a:b:z:R:s:M:Q:G:x:u:D:k:K:";
   char *hdr_intent_raw_file = nullptr, *sdr_intent_raw_file = nullptr, *uhdr_file = nullptr,
        *sdr_intent_compressed_file = nullptr, *gainmap_compressed_file = nullptr,
-       *gainmap_metadata_cfg_file = nullptr, *output_file = nullptr;
+       *gainmap_metadata_cfg_file = nullptr, *output_file = nullptr, *exif_file = nullptr;
   int width = 0, height = 0;
   uhdr_color_gamut_t hdr_cg = UHDR_CG_DISPLAY_P3;
   uhdr_color_gamut_t sdr_cg = UHDR_CG_BT_709;
@@ -1314,7 +1477,16 @@ int main(int argc, char* argv[]) {
   uhdr_color_transfer_t out_tf = UHDR_CT_HLG;
   uhdr_img_fmt_t out_cf = UHDR_IMG_FMT_32bppRGBA1010102;
   int mode = -1;
+  int gainmap_scale_factor = 1;
+  bool use_multi_channel_gainmap = true;
+  bool use_full_range_color_hdr = false;
+  int gainmap_compression_quality = 95;
   int compute_psnr = 0;
+  float gamma = 1.0f;
+  bool enable_gles = false;
+  uhdr_enc_preset_t enc_preset = UHDR_USAGE_BEST_QUALITY;
+  float min_content_boost = FLT_MIN;
+  float max_content_boost = FLT_MAX;
   int ch;
   while ((ch = getopt_s(argc, argv, opt_string)) != -1) {
     switch (ch) {
@@ -1366,6 +1538,25 @@ int main(int argc, char* argv[]) {
       case 'm':
         mode = atoi(optarg_s);
         break;
+      case 'R':
+        use_full_range_color_hdr = atoi(optarg_s) == 1 ? true : false;
+        break;
+      // TODO
+      /*case 'r':
+        use_full_range_color_sdr = atoi(optarg_s) == 1 ? true : false;
+        break;*/
+      case 's':
+        gainmap_scale_factor = atoi(optarg_s);
+        break;
+      case 'M':
+        use_multi_channel_gainmap = atoi(optarg_s) == 1 ? true : false;
+        break;
+      case 'Q':
+        gainmap_compression_quality = atoi(optarg_s);
+        break;
+      case 'G':
+        gamma = atof(optarg_s);
+        break;
       case 'j':
         uhdr_file = optarg_s;
         break;
@@ -1375,18 +1566,33 @@ int main(int argc, char* argv[]) {
       case 'z':
         output_file = optarg_s;
         break;
+      case 'x':
+        exif_file = optarg_s;
+        break;
+      case 'u':
+        enable_gles = atoi(optarg_s) == 1 ? true : false;
+        break;
+      case 'D':
+        enc_preset = static_cast<uhdr_enc_preset_t>(atoi(optarg_s));
+        break;
+      case 'k':
+        min_content_boost = atof(optarg_s);
+        break;
+      case 'K':
+        max_content_boost = atof(optarg_s);
+        break;
       default:
         usage(argv[0]);
         return -1;
     }
   }
   if (mode == 0) {
-    if (width <= 0) {
+    if (width <= 0 && gainmap_metadata_cfg_file == nullptr) {
       std::cerr << "did not receive valid image width for encoding. width :  " << width
                 << std::endl;
       return -1;
     }
-    if (height <= 0) {
+    if (height <= 0 && gainmap_metadata_cfg_file == nullptr) {
       std::cerr << "did not receive valid image height for encoding. height :  " << height
                 << std::endl;
       return -1;
@@ -1398,9 +1604,12 @@ int main(int argc, char* argv[]) {
       return -1;
     }
     UltraHdrAppInput appInput(hdr_intent_raw_file, sdr_intent_raw_file, sdr_intent_compressed_file,
-                              gainmap_compressed_file, gainmap_metadata_cfg_file,
+                              gainmap_compressed_file, gainmap_metadata_cfg_file, exif_file,
                               output_file ? output_file : "out.jpeg", width, height, hdr_cf, sdr_cf,
-                              hdr_cg, sdr_cg, hdr_tf, quality, out_tf, out_cf);
+                              hdr_cg, sdr_cg, hdr_tf, quality, out_tf, out_cf,
+                              use_full_range_color_hdr, gainmap_scale_factor,
+                              gainmap_compression_quality, use_multi_channel_gainmap, gamma,
+                              enable_gles, enc_preset, min_content_boost, max_content_boost);
     if (!appInput.encode()) return -1;
     if (compute_psnr == 1) {
       if (!appInput.decode()) return -1;
@@ -1431,10 +1640,12 @@ int main(int argc, char* argv[]) {
       std::cerr << "did not receive resources for decoding " << std::endl;
       return -1;
     }
-    UltraHdrAppInput appInput(uhdr_file, output_file ? output_file : "outrgb.raw", out_tf, out_cf);
+    UltraHdrAppInput appInput(gainmap_metadata_cfg_file, uhdr_file,
+                              output_file ? output_file : "outrgb.raw", out_tf, out_cf,
+                              enable_gles);
     if (!appInput.decode()) return -1;
   } else {
-    std::cerr << "unrecognized input mode " << mode << std::endl;
+    if (argc > 1) std::cerr << "did not receive valid mode of operation " << mode << std::endl;
     usage(argv[0]);
     return -1;
   }
diff --git a/fuzzer/Android.bp b/fuzzer/Android.bp
index b366fd8..bbbd88f 100644
--- a/fuzzer/Android.bp
+++ b/fuzzer/Android.bp
@@ -38,6 +38,13 @@ cc_defaults {
         darwin: {
             enabled: false,
         },
+        android: {
+            cflags: ["-DUHDR_ENABLE_GLES"],
+            shared_libs: [
+                "libEGL",
+                "libGLESv3",
+            ],
+        },
     },
     fuzz_config: {
         cc: [
diff --git a/fuzzer/README.md b/fuzzer/README.md
deleted file mode 100644
index 0550eae..0000000
--- a/fuzzer/README.md
+++ /dev/null
@@ -1,69 +0,0 @@
-## Building fuzzers for libultrahdr
-
-### Requirements
-
-- Refer [Requirements](../README.md#Requirements)
-
-- Additionally compilers are required to support options `-fsanitize=fuzzer, -fsanitize=fuzzer-no-link`.
-  For instance, `clang 12` (or later)
-
-### Building Commands
-
-    mkdir {build_directory}
-    cd {build_directory}
-    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DUHDR_BUILD_FUZZERS=1
-    make
-
-This will generate the following files under `build_directory`:
-
-**ultrahdr_enc_fuzzer**<br> ultrahdr encoder fuzzer
-
-**ultrahdr_dec_fuzzer**<br> ultrahdr decoder fuzzer
-
-Additionally, while building fuzzers, user can enable sanitizers by providing desired
-sanitizer option(s) through `UHDR_SANITIZE_OPTIONS`.
-
-To enable ASan,
-
-    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
-    -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address
-    make
-
-To enable MSan,
-
-    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
-    -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=memory
-    make
-
-To enable TSan,
-
-    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
-    -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=thread
-    make
-
-To enable UBSan,
-
-    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
-    -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=undefined
-    make
-
-UBSan can be grouped with ASan, MSan or TSan.
-
-For example, to enable ASan and UBSan,
-
-    cmake ../ -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
-    -DUHDR_BUILD_FUZZERS=1 -DUHDR_SANITIZE_OPTIONS=address,undefined
-    make
-
-### Running
-
-To run the fuzzer(s), first create a corpus directory that holds the initial
-"seed" sample inputs. For decoder fuzzer, ultrahdr jpeg images can be used and
-for encoder fuzzer, sample yuv files can be used.
-
-Then run the fuzzers on the corpus directory.
-
-    mkdir CORPUS_DIR
-    cp seeds/* CORPUS_DIR
-    ./ultrahdr_dec_fuzzer CORPUS_DIR
-    ./ultrahdr_enc_fuzzer CORPUS_DIR
diff --git a/fuzzer/ossfuzz.sh b/fuzzer/ossfuzz.sh
index 262d629..3f241e7 100755
--- a/fuzzer/ossfuzz.sh
+++ b/fuzzer/ossfuzz.sh
@@ -17,6 +17,12 @@
 test "${SRC}" != "" || exit 1
 test "${WORK}" != "" || exit 1
 
+#Opt out of shift sanitizer in undefined sanitizer
+if [[ $SANITIZER = *undefined* ]]; then
+  CFLAGS="$CFLAGS -fno-sanitize=shift"
+  CXXFLAGS="$CXXFLAGS -fno-sanitize=shift"
+fi
+
 # Build libultrahdr
 build_dir=$WORK/build
 rm -rf ${build_dir}
diff --git a/fuzzer/ultrahdr_dec_fuzzer.cpp b/fuzzer/ultrahdr_dec_fuzzer.cpp
index 9a1f179..1343ea3 100644
--- a/fuzzer/ultrahdr_dec_fuzzer.cpp
+++ b/fuzzer/ultrahdr_dec_fuzzer.cpp
@@ -18,13 +18,14 @@
 #include <iostream>
 #include <memory>
 
-#include "ultrahdr/jpegr.h"
+#include "ultrahdr_api.h"
+#include "ultrahdr/ultrahdrcommon.h"
 
 using namespace ultrahdr;
 
 // Transfer functions for image data, sync with ultrahdr.h
-const int kOfMin = ULTRAHDR_OUTPUT_UNSPECIFIED + 1;
-const int kOfMax = ULTRAHDR_OUTPUT_MAX;
+constexpr int kTfMin = UHDR_CT_UNSPECIFIED + 1;
+constexpr int kTfMax = UHDR_CT_PQ;
 
 class UltraHdrDecFuzzer {
  public:
@@ -37,28 +38,45 @@ class UltraHdrDecFuzzer {
 
 void UltraHdrDecFuzzer::process() {
   // hdr_of
-  auto of = static_cast<ultrahdr_output_format>(mFdp.ConsumeIntegralInRange<int>(kOfMin, kOfMax));
+  auto tf = static_cast<uhdr_color_transfer>(mFdp.ConsumeIntegralInRange<int>(kTfMin, kTfMax));
   auto buffer = mFdp.ConsumeRemainingBytes<uint8_t>();
-  jpegr_compressed_struct jpegImgR{buffer.data(), (int)buffer.size(), (int)buffer.size(),
-                                   ULTRAHDR_COLORGAMUT_UNSPECIFIED};
-
-  jpegr_info_struct info{};
-  JpegR jpegHdr;
-  (void)jpegHdr.getJPEGRInfo(&jpegImgR, &info);
-//#define DUMP_PARAM
-#ifdef DUMP_PARAM
-  std::cout << "input buffer size " << jpegImgR.length << std::endl;
-  std::cout << "image dimensions " << info.width << " x " << info.width << std::endl;
-#endif
-  if (info.width > kMaxWidth || info.height > kMaxHeight) return;
-  size_t outSize = info.width * info.height * ((of == ULTRAHDR_OUTPUT_HDR_LINEAR) ? 8 : 4);
-  jpegr_uncompressed_struct decodedJpegR;
-  auto decodedRaw = std::make_unique<uint8_t[]>(outSize);
-  decodedJpegR.data = decodedRaw.get();
-  ultrahdr_metadata_struct metadata;
-  (void)jpegHdr.decodeJPEGR(&jpegImgR, &decodedJpegR,
-                            mFdp.ConsumeFloatingPointInRange<float>(1.0, FLT_MAX), nullptr, of,
-                            nullptr, &metadata);
+  uhdr_compressed_image_t jpegImgR{
+      buffer.data(),       (unsigned int)buffer.size(), (unsigned int)buffer.size(),
+      UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED,         UHDR_CR_UNSPECIFIED};
+#define ON_ERR(x)                              \
+  {                                            \
+    uhdr_error_info_t status_ = (x);           \
+    if (status_.error_code != UHDR_CODEC_OK) { \
+      if (status_.has_detail) {                \
+        ALOGE("%s", status_.detail);           \
+      }                                        \
+    }                                          \
+  }
+  uhdr_codec_private_t* dec_handle = uhdr_create_decoder();
+  if (dec_handle) {
+    ON_ERR(uhdr_dec_set_image(dec_handle, &jpegImgR))
+    ON_ERR(uhdr_dec_set_out_color_transfer(dec_handle, tf))
+    if (tf == UHDR_CT_LINEAR)
+      ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_64bppRGBAHalfFloat))
+    else if (tf == UHDR_CT_SRGB)
+      ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA8888))
+    else
+      ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA1010102))
+    uhdr_dec_probe(dec_handle);
+    uhdr_dec_get_image_width(dec_handle);
+    uhdr_dec_get_image_height(dec_handle);
+    uhdr_dec_get_gainmap_width(dec_handle);
+    uhdr_dec_get_gainmap_height(dec_handle);
+    uhdr_dec_get_exif(dec_handle);
+    uhdr_dec_get_icc(dec_handle);
+    uhdr_dec_get_base_image(dec_handle);
+    uhdr_dec_get_gainmap_image(dec_handle);
+    uhdr_dec_get_gainmap_metadata(dec_handle);
+    uhdr_decode(dec_handle);
+    uhdr_get_decoded_image(dec_handle);
+    uhdr_get_decoded_gainmap_image(dec_handle);
+    uhdr_release_decoder(dec_handle);
+  }
 }
 
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
diff --git a/fuzzer/ultrahdr_enc_fuzzer.cpp b/fuzzer/ultrahdr_enc_fuzzer.cpp
index db8ba0b..7287b69 100644
--- a/fuzzer/ultrahdr_enc_fuzzer.cpp
+++ b/fuzzer/ultrahdr_enc_fuzzer.cpp
@@ -20,42 +20,39 @@
 #include <memory>
 #include <random>
 
+#include "ultrahdr_api.h"
 #include "ultrahdr/ultrahdrcommon.h"
-#include "ultrahdr/gainmapmath.h"
 #include "ultrahdr/jpegr.h"
 
 using namespace ultrahdr;
 
-// Color gamuts for image data, sync with ultrahdr.h
-const int kCgMin = ULTRAHDR_COLORGAMUT_UNSPECIFIED + 1;
-const int kCgMax = ULTRAHDR_COLORGAMUT_MAX;
+// Color gamuts for image data, sync with ultrahdr_api.h
+constexpr int kCgMin = UHDR_CG_UNSPECIFIED + 1;
+constexpr int kCgMax = UHDR_CG_BT_2100;
 
-// Transfer functions for image data, sync with ultrahdr.h
-const int kTfMin = ULTRAHDR_TF_UNSPECIFIED + 1;
-const int kTfMax = ULTRAHDR_TF_PQ;
-
-// Transfer functions for image data, sync with ultrahdr.h
-const int kOfMin = ULTRAHDR_OUTPUT_UNSPECIFIED + 1;
-const int kOfMax = ULTRAHDR_OUTPUT_MAX;
+// Transfer functions for image data, sync with ultrahdr_api.h
+constexpr int kTfMin = UHDR_CT_UNSPECIFIED + 1;
+constexpr int kTfMax = UHDR_CT_PQ;
 
 // quality factor
-const int kQfMin = 0;
-const int kQfMax = 100;
+constexpr int kQfMin = 0;
+constexpr int kQfMax = 100;
 
 class UltraHdrEncFuzzer {
  public:
   UltraHdrEncFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
   void process();
-  void fillP010Buffer(uint16_t* data, int width, int height, int stride);
-  void fill420Buffer(uint8_t* data, int width, int height, int stride);
+  template <typename T>
+  void fillBuffer(T* data, int width, int height, int stride);
 
  private:
   FuzzedDataProvider mFdp;
 };
 
-void UltraHdrEncFuzzer::fillP010Buffer(uint16_t* data, int width, int height, int stride) {
-  uint16_t* tmp = data;
-  std::vector<uint16_t> buffer(16);
+template <typename T>
+void UltraHdrEncFuzzer::fillBuffer(T* data, int width, int height, int stride) {
+  T* tmp = data;
+  std::vector<T> buffer(16);
   for (int i = 0; i < buffer.size(); i++) {
     buffer[i] = (mFdp.ConsumeIntegralInRange<int>(0, (1 << 10) - 1)) << 6;
   }
@@ -69,249 +66,270 @@ void UltraHdrEncFuzzer::fillP010Buffer(uint16_t* data, int width, int height, in
   }
 }
 
-void UltraHdrEncFuzzer::fill420Buffer(uint8_t* data, int width, int height, int stride) {
-  uint8_t* tmp = data;
-  std::vector<uint8_t> buffer(16);
-  mFdp.ConsumeData(buffer.data(), buffer.size());
-  for (int j = 0; j < height; j++) {
-    for (int i = 0; i < width; i += buffer.size()) {
-      memcpy(tmp + i, buffer.data(), std::min((int)buffer.size(), (width - i)) * sizeof(*data));
-      std::shuffle(buffer.begin(), buffer.end(),
-                   std::default_random_engine(std::random_device{}()));
-    }
-    tmp += stride;
-  }
-}
-
 void UltraHdrEncFuzzer::process() {
   while (mFdp.remaining_bytes()) {
-    struct jpegr_uncompressed_struct p010Img {};
-    struct jpegr_uncompressed_struct yuv420Img {};
-    struct jpegr_uncompressed_struct grayImg {};
-    struct jpegr_compressed_struct jpegImgR {};
-    struct jpegr_compressed_struct jpegImg {};
-    struct jpegr_compressed_struct jpegGainMap {};
+    struct uhdr_raw_image hdrImg {};
+    struct uhdr_raw_image sdrImg {};
+    struct uhdr_raw_image gainmapImg {};
 
     // which encode api to select
     int muxSwitch = mFdp.ConsumeIntegralInRange<int>(0, 4);
 
-    // quality factor
-    int quality = mFdp.ConsumeIntegralInRange<int>(kQfMin, kQfMax);
+    // base quality factor
+    int base_quality = mFdp.ConsumeIntegralInRange<int>(kQfMin, kQfMax);
+
+    // gain_map quality factor
+    int gainmap_quality = mFdp.ConsumeIntegralInRange<int>(kQfMin, kQfMax);
 
     // hdr_tf
-    auto tf =
-        static_cast<ultrahdr_transfer_function>(mFdp.ConsumeIntegralInRange<int>(kTfMin, kTfMax));
+    auto tf = static_cast<uhdr_color_transfer>(mFdp.ConsumeIntegralInRange<int>(kTfMin, kTfMax));
 
-    // p010 Cg
-    auto p010Cg =
-        static_cast<ultrahdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));
+    // hdr Cg
+    auto hdr_cg = static_cast<uhdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));
 
-    // 420 Cg
-    auto yuv420Cg =
-        static_cast<ultrahdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));
+    // sdr Cg
+    auto sdr_cg = static_cast<uhdr_color_gamut>(mFdp.ConsumeIntegralInRange<int>(kCgMin, kCgMax));
 
-    // hdr_of
-    auto of = static_cast<ultrahdr_output_format>(mFdp.ConsumeIntegralInRange<int>(kOfMin, kOfMax));
+    // color range
+    auto color_range = mFdp.ConsumeBool() ? UHDR_CR_LIMITED_RANGE : UHDR_CR_FULL_RANGE;
+
+    // hdr_img_fmt
+    auto hdr_img_fmt =
+        mFdp.ConsumeBool() ? UHDR_IMG_FMT_24bppYCbCrP010 : UHDR_IMG_FMT_32bppRGBA1010102;
+
+    // sdr_img_fmt
+    auto sdr_img_fmt = mFdp.ConsumeBool() ? UHDR_IMG_FMT_12bppYCbCr420 : UHDR_IMG_FMT_32bppRGBA8888;
+    if (muxSwitch > 1) sdr_img_fmt = UHDR_IMG_FMT_12bppYCbCr420;
+
+    // multi channel gainmap
+    auto multi_channel_gainmap = mFdp.ConsumeBool();
 
     int width = mFdp.ConsumeIntegralInRange<int>(kMinWidth, kMaxWidth);
-    width = (width >> 1) << 1;
+    if (hdr_img_fmt == UHDR_IMG_FMT_24bppYCbCrP010 || sdr_img_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+      width = (width >> 1) << 1;
+    }
 
     int height = mFdp.ConsumeIntegralInRange<int>(kMinHeight, kMaxHeight);
-    height = (height >> 1) << 1;
+    if (hdr_img_fmt == UHDR_IMG_FMT_24bppYCbCrP010 || sdr_img_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+      height = (height >> 1) << 1;
+    }
+
+    // gainmap scale factor
+    auto gm_scale_factor = mFdp.ConsumeIntegralInRange<int>(1, 128);
 
+    // encoding speed preset
+    auto enc_preset = static_cast<uhdr_enc_preset_t>(mFdp.ConsumeIntegralInRange<int>(0, 1));
+
+    std::unique_ptr<uint32_t[]> bufferHdr = nullptr;
     std::unique_ptr<uint16_t[]> bufferYHdr = nullptr;
     std::unique_ptr<uint16_t[]> bufferUVHdr = nullptr;
     std::unique_ptr<uint8_t[]> bufferYSdr = nullptr;
     std::unique_ptr<uint8_t[]> bufferUVSdr = nullptr;
-    std::unique_ptr<uint8_t[]> grayImgRaw = nullptr;
+    std::unique_ptr<uint8_t[]> gainMapImageRaw = nullptr;
+    uhdr_codec_private_t* enc_handle = uhdr_create_encoder();
+    if (!enc_handle) {
+      ALOGE("Failed to create encoder");
+      continue;
+    }
+
+#define ON_ERR(x)                              \
+  {                                            \
+    uhdr_error_info_t status_ = (x);           \
+    if (status_.error_code != UHDR_CODEC_OK) { \
+      if (status_.has_detail) {                \
+        ALOGE("%s", status_.detail);           \
+      }                                        \
+    }                                          \
+  }
     if (muxSwitch != 4) {
-      // init p010 image
-      bool isUVContiguous = mFdp.ConsumeBool();
-      bool hasYStride = mFdp.ConsumeBool();
-      int yStride = hasYStride ? mFdp.ConsumeIntegralInRange<int>(width, width + 128) : width;
-      p010Img.width = width;
-      p010Img.height = height;
-      p010Img.colorGamut = p010Cg;
-      p010Img.luma_stride = hasYStride ? yStride : 0;
-      if (isUVContiguous) {
-        size_t p010Size = yStride * height * 3 / 2;
-        bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
-        p010Img.data = bufferYHdr.get();
-        p010Img.chroma_data = nullptr;
-        p010Img.chroma_stride = 0;
-        fillP010Buffer(bufferYHdr.get(), width, height, yStride);
-        fillP010Buffer(bufferYHdr.get() + yStride * height, width, height / 2, yStride);
-      } else {
-        int uvStride = mFdp.ConsumeIntegralInRange<int>(width, width + 128);
-        size_t p010YSize = yStride * height;
-        bufferYHdr = std::make_unique<uint16_t[]>(p010YSize);
-        p010Img.data = bufferYHdr.get();
-        fillP010Buffer(bufferYHdr.get(), width, height, yStride);
-        size_t p010UVSize = uvStride * p010Img.height / 2;
-        bufferUVHdr = std::make_unique<uint16_t[]>(p010UVSize);
-        p010Img.chroma_data = bufferUVHdr.get();
-        p010Img.chroma_stride = uvStride;
-        fillP010Buffer(bufferUVHdr.get(), width, height / 2, uvStride);
+      // init p010/rgba1010102 image
+      bool hasStride = mFdp.ConsumeBool();
+      int yStride = hasStride ? mFdp.ConsumeIntegralInRange<int>(width, width + 128) : width;
+      hdrImg.w = width;
+      hdrImg.h = height;
+      hdrImg.cg = hdr_cg;
+      hdrImg.fmt = hdr_img_fmt;
+      hdrImg.ct = tf;
+      hdrImg.range = color_range;
+      hdrImg.stride[UHDR_PLANE_Y] = yStride;
+      if (hdr_img_fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
+        bool isUVContiguous = mFdp.ConsumeBool();
+        if (isUVContiguous) {
+          size_t p010Size = yStride * height * 3 / 2;
+          bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
+          hdrImg.planes[UHDR_PLANE_Y] = bufferYHdr.get();
+          fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yStride);
+          fillBuffer<uint16_t>(bufferYHdr.get() + yStride * height, width, height / 2, yStride);
+          hdrImg.planes[UHDR_PLANE_UV] = bufferYHdr.get() + yStride * height;
+          hdrImg.stride[UHDR_PLANE_UV] = yStride;
+        } else {
+          int uvStride = mFdp.ConsumeIntegralInRange<int>(width, width + 128);
+          size_t p010Size = yStride * height;
+          bufferYHdr = std::make_unique<uint16_t[]>(p010Size);
+          hdrImg.planes[UHDR_PLANE_Y] = bufferYHdr.get();
+          fillBuffer<uint16_t>(bufferYHdr.get(), width, height, yStride);
+          size_t p010UVSize = uvStride * hdrImg.h / 2;
+          bufferUVHdr = std::make_unique<uint16_t[]>(p010UVSize);
+          hdrImg.planes[UHDR_PLANE_UV] = bufferUVHdr.get();
+          hdrImg.stride[UHDR_PLANE_UV] = uvStride;
+          fillBuffer<uint16_t>(bufferUVHdr.get(), width, height / 2, uvStride);
+        }
+      } else if (hdr_img_fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
+        size_t rgba1010102Size = yStride * height;
+        bufferHdr = std::make_unique<uint32_t[]>(rgba1010102Size);
+        hdrImg.planes[UHDR_PLANE_PACKED] = bufferHdr.get();
+        fillBuffer<uint32_t>(bufferHdr.get(), width, height, yStride);
+        hdrImg.planes[UHDR_PLANE_U] = nullptr;
+        hdrImg.stride[UHDR_PLANE_U] = 0;
       }
+      hdrImg.planes[UHDR_PLANE_V] = nullptr;
+      hdrImg.stride[UHDR_PLANE_V] = 0;
+      ON_ERR(uhdr_enc_set_raw_image(enc_handle, &hdrImg, UHDR_HDR_IMG))
     } else {
-      size_t map_width = width / kMapDimensionScaleFactor;
-      size_t map_height = height / kMapDimensionScaleFactor;
-      // init 400 image
-      grayImg.width = map_width;
-      grayImg.height = map_height;
-      grayImg.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-
+      size_t map_width = width / gm_scale_factor;
+      size_t map_height = height / gm_scale_factor;
+      gainmapImg.fmt = UHDR_IMG_FMT_8bppYCbCr400;
+      gainmapImg.w = map_width;
+      gainmapImg.h = map_height;
+      gainmapImg.cg = UHDR_CG_UNSPECIFIED;
+      gainmapImg.ct = UHDR_CT_UNSPECIFIED;
+      gainmapImg.range = UHDR_CR_FULL_RANGE;
       const size_t graySize = map_width * map_height;
-      grayImgRaw = std::make_unique<uint8_t[]>(graySize);
-      grayImg.data = grayImgRaw.get();
-      fill420Buffer(grayImgRaw.get(), map_width, map_height, map_width);
-      grayImg.chroma_data = nullptr;
-      grayImg.luma_stride = 0;
-      grayImg.chroma_stride = 0;
+      gainMapImageRaw = std::make_unique<uint8_t[]>(graySize);
+      gainmapImg.planes[UHDR_PLANE_Y] = gainMapImageRaw.get();
+      gainmapImg.stride[UHDR_PLANE_Y] = map_width;
+      gainmapImg.planes[UHDR_PLANE_U] = nullptr;
+      gainmapImg.planes[UHDR_PLANE_V] = nullptr;
+      gainmapImg.stride[UHDR_PLANE_U] = 0;
+      gainmapImg.stride[UHDR_PLANE_V] = 0;
+      fillBuffer<uint8_t>(gainMapImageRaw.get(), map_width, map_height, map_width);
     }
 
     if (muxSwitch > 0) {
-      // init 420 image
-      bool isUVContiguous = mFdp.ConsumeBool();
-      bool hasYStride = mFdp.ConsumeBool();
-      int yStride = hasYStride ? mFdp.ConsumeIntegralInRange<int>(width, width + 128) : width;
-      yuv420Img.width = width;
-      yuv420Img.height = height;
-      yuv420Img.colorGamut = yuv420Cg;
-      yuv420Img.luma_stride = hasYStride ? yStride : 0;
-      if (isUVContiguous) {
-        size_t yuv420Size = yStride * height * 3 / 2;
-        bufferYSdr = std::make_unique<uint8_t[]>(yuv420Size);
-        yuv420Img.data = bufferYSdr.get();
-        yuv420Img.chroma_data = nullptr;
-        yuv420Img.chroma_stride = 0;
-        fill420Buffer(bufferYSdr.get(), width, height, yStride);
-        fill420Buffer(bufferYSdr.get() + yStride * height, width / 2, height / 2, yStride / 2);
-        fill420Buffer(bufferYSdr.get() + yStride * height * 5 / 4, width / 2, height / 2,
-                      yStride / 2);
-      } else {
-        int uvStride = mFdp.ConsumeIntegralInRange<int>(width / 2, width / 2 + 128);
-        size_t yuv420YSize = yStride * height;
-        bufferYSdr = std::make_unique<uint8_t[]>(yuv420YSize);
-        yuv420Img.data = bufferYSdr.get();
-        fill420Buffer(bufferYSdr.get(), width, height, yStride);
-        size_t yuv420UVSize = uvStride * yuv420Img.height / 2 * 2;
-        bufferUVSdr = std::make_unique<uint8_t[]>(yuv420UVSize);
-        yuv420Img.chroma_data = bufferUVSdr.get();
-        yuv420Img.chroma_stride = uvStride;
-        fill420Buffer(bufferUVSdr.get(), width / 2, height / 2, uvStride);
-        fill420Buffer(bufferUVSdr.get() + uvStride * height / 2, width / 2, height / 2, uvStride);
+      bool hasStride = mFdp.ConsumeBool();
+      int yStride = hasStride ? mFdp.ConsumeIntegralInRange<int>(width, width + 128) : width;
+      // init yuv420 Image
+      if (sdr_img_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+        bool isUVContiguous = mFdp.ConsumeBool();
+        sdrImg.w = width;
+        sdrImg.h = height;
+        sdrImg.cg = sdr_cg;
+        sdrImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
+        sdrImg.ct = UHDR_CT_SRGB;
+        sdrImg.range = UHDR_CR_FULL_RANGE;
+        sdrImg.stride[UHDR_PLANE_Y] = yStride;
+        if (isUVContiguous) {
+          size_t yuv420Size = yStride * height * 3 / 2;
+          bufferYSdr = std::make_unique<uint8_t[]>(yuv420Size);
+          sdrImg.planes[UHDR_PLANE_Y] = bufferYSdr.get();
+          sdrImg.planes[UHDR_PLANE_U] = bufferYSdr.get() + yStride * height;
+          sdrImg.planes[UHDR_PLANE_V] = bufferYSdr.get() + yStride * height * 5 / 4;
+          sdrImg.stride[UHDR_PLANE_U] = yStride / 2;
+          sdrImg.stride[UHDR_PLANE_V] = yStride / 2;
+          fillBuffer<uint8_t>(bufferYSdr.get(), width, height, yStride);
+          fillBuffer<uint8_t>(bufferYSdr.get() + yStride * height, width / 2, height / 2,
+                              yStride / 2);
+          fillBuffer<uint8_t>(bufferYSdr.get() + yStride * height * 5 / 4, width / 2, height / 2,
+                              yStride / 2);
+        } else {
+          int uvStride = mFdp.ConsumeIntegralInRange<int>(width / 2, width / 2 + 128);
+          size_t yuv420YSize = yStride * height;
+          bufferYSdr = std::make_unique<uint8_t[]>(yuv420YSize);
+          sdrImg.planes[UHDR_PLANE_Y] = bufferYSdr.get();
+          fillBuffer<uint8_t>(bufferYSdr.get(), width, height, yStride);
+          size_t yuv420UVSize = uvStride * sdrImg.h / 2 * 2;
+          bufferUVSdr = std::make_unique<uint8_t[]>(yuv420UVSize);
+          sdrImg.planes[UHDR_PLANE_U] = bufferUVSdr.get();
+          sdrImg.stride[UHDR_PLANE_U] = uvStride;
+          fillBuffer<uint8_t>(bufferUVSdr.get(), width / 2, height / 2, uvStride);
+          fillBuffer<uint8_t>(bufferUVSdr.get() + uvStride * height / 2, width / 2, height / 2,
+                              uvStride);
+          sdrImg.planes[UHDR_PLANE_V] = bufferUVSdr.get() + uvStride * height / 2;
+          sdrImg.stride[UHDR_PLANE_V] = uvStride;
+        }
+      } else if (sdr_img_fmt == UHDR_IMG_FMT_32bppRGBA8888) {
+        sdrImg.w = width;
+        sdrImg.h = height;
+        sdrImg.cg = sdr_cg;
+        sdrImg.fmt = UHDR_IMG_FMT_32bppRGBA8888;
+        sdrImg.ct = UHDR_CT_SRGB;
+        sdrImg.range = UHDR_CR_FULL_RANGE;
+        sdrImg.stride[UHDR_PLANE_PACKED] = yStride;
+        size_t rgba8888Size = yStride * height;
+        bufferHdr = std::make_unique<uint32_t[]>(rgba8888Size);
+        sdrImg.planes[UHDR_PLANE_PACKED] = bufferHdr.get();
+        fillBuffer<uint32_t>(bufferHdr.get(), width, height, yStride);
+        sdrImg.planes[UHDR_PLANE_U] = nullptr;
+        sdrImg.planes[UHDR_PLANE_V] = nullptr;
+        sdrImg.stride[UHDR_PLANE_U] = 0;
+        sdrImg.stride[UHDR_PLANE_V] = 0;
       }
     }
+    if (muxSwitch == 1 || muxSwitch == 2) {
+      ON_ERR(uhdr_enc_set_raw_image(enc_handle, &sdrImg, UHDR_SDR_IMG))
+    }
+    ON_ERR(uhdr_enc_set_quality(enc_handle, base_quality, UHDR_BASE_IMG))
+    ON_ERR(uhdr_enc_set_quality(enc_handle, gainmap_quality, UHDR_GAIN_MAP_IMG))
+    ON_ERR(uhdr_enc_set_gainmap_scale_factor(enc_handle, gm_scale_factor))
+    ON_ERR(uhdr_enc_set_using_multi_channel_gainmap(enc_handle, multi_channel_gainmap))
+    ON_ERR(uhdr_enc_set_preset(enc_handle, enc_preset))
 
-    // dest
-    // 2 * p010 size as input data is random, DCT compression might not behave as expected
-    jpegImgR.maxLength = std::max(8 * 1024 /* min size 8kb */, width * height * 3 * 2);
-    auto jpegImgRaw = std::make_unique<uint8_t[]>(jpegImgR.maxLength);
-    jpegImgR.data = jpegImgRaw.get();
-
-//#define DUMP_PARAM
-#ifdef DUMP_PARAM
-    std::cout << "Api Select " << muxSwitch << std::endl;
-    std::cout << "image dimensions " << width << " x " << height << std::endl;
-    std::cout << "p010 color gamut " << p010Img.colorGamut << std::endl;
-    std::cout << "p010 luma stride " << p010Img.luma_stride << std::endl;
-    std::cout << "p010 chroma stride " << p010Img.chroma_stride << std::endl;
-    std::cout << "420 color gamut " << yuv420Img.colorGamut << std::endl;
-    std::cout << "420 luma stride " << yuv420Img.luma_stride << std::endl;
-    std::cout << "420 chroma stride " << yuv420Img.chroma_stride << std::endl;
-    std::cout << "quality factor " << quality << std::endl;
-#endif
-
-    JpegR jpegHdr;
-    status_t status = JPEGR_UNKNOWN_ERROR;
-    if (muxSwitch == 0) {  // api 0
-      jpegImgR.length = 0;
-      status = jpegHdr.encodeJPEGR(&p010Img, tf, &jpegImgR, quality, nullptr);
-    } else if (muxSwitch == 1) {  // api 1
-      jpegImgR.length = 0;
-      status = jpegHdr.encodeJPEGR(&p010Img, &yuv420Img, tf, &jpegImgR, quality, nullptr);
+    uhdr_error_info_t status = {UHDR_CODEC_OK, 0, ""};
+    if (muxSwitch == 0 || muxSwitch == 1) {  // api 0 or api 1
+      status = uhdr_encode(enc_handle);
     } else {
       // compressed img
       JpegEncoderHelper encoder;
-      struct jpegr_uncompressed_struct yuv420ImgCopy = yuv420Img;
-      if (yuv420ImgCopy.luma_stride == 0) yuv420ImgCopy.luma_stride = yuv420Img.width;
-      if (!yuv420ImgCopy.chroma_data) {
-        uint8_t* data = reinterpret_cast<uint8_t*>(yuv420Img.data);
-        yuv420ImgCopy.chroma_data = data + yuv420Img.luma_stride * yuv420Img.height;
-        yuv420ImgCopy.chroma_stride = yuv420Img.luma_stride >> 1;
-      }
-
-      const uint8_t* planes[3]{reinterpret_cast<uint8_t*>(yuv420ImgCopy.data),
-                               reinterpret_cast<uint8_t*>(yuv420ImgCopy.chroma_data),
-                               reinterpret_cast<uint8_t*>(yuv420ImgCopy.chroma_data) +
-                                   yuv420ImgCopy.chroma_stride * yuv420ImgCopy.height / 2};
-      const size_t strides[3]{yuv420ImgCopy.luma_stride, yuv420ImgCopy.chroma_stride,
-                              yuv420ImgCopy.chroma_stride};
-      if (encoder.compressImage(planes, strides, yuv420ImgCopy.width, yuv420ImgCopy.height,
-                                UHDR_IMG_FMT_12bppYCbCr420, quality, nullptr, 0)) {
-        jpegImg.length = encoder.getCompressedImageSize();
-        jpegImg.maxLength = jpegImg.length;
-        jpegImg.data = encoder.getCompressedImagePtr();
-        jpegImg.colorGamut = yuv420Cg;
-
-        if (muxSwitch == 2) {  // api 2
-          jpegImgR.length = 0;
-          status = jpegHdr.encodeJPEGR(&p010Img, &yuv420Img, &jpegImg, tf, &jpegImgR);
-        } else if (muxSwitch == 3) {  // api 3
-          jpegImgR.length = 0;
-          status = jpegHdr.encodeJPEGR(&p010Img, &jpegImg, tf, &jpegImgR);
+      if (encoder.compressImage(&sdrImg, base_quality, nullptr, 0).error_code == UHDR_CODEC_OK) {
+        struct uhdr_compressed_image jpegImg = encoder.getCompressedImage();
+        jpegImg.cg = sdr_cg;
+        if (muxSwitch != 4) {
+          // for api 4 compressed image will be set with UHDR_BASE_IMG intent
+          uhdr_enc_set_compressed_image(enc_handle, &jpegImg, UHDR_SDR_IMG);
+        }
+        if (muxSwitch == 2 || muxSwitch == 3) {  // api 2 or api 3
+          status = uhdr_encode(enc_handle);
         } else if (muxSwitch == 4) {  // api 4
-          jpegImgR.length = 0;
           JpegEncoderHelper gainMapEncoder;
-          const uint8_t* planeGm[1]{reinterpret_cast<uint8_t*>(grayImg.data)};
-          const size_t strideGm[1]{grayImg.width};
-          if (gainMapEncoder.compressImage(planeGm, strideGm, grayImg.width, grayImg.height,
-                                           UHDR_IMG_FMT_8bppYCbCr400, quality, nullptr, 0)) {
-            jpegGainMap.length = gainMapEncoder.getCompressedImageSize();
-            jpegGainMap.maxLength = jpegImg.length;
-            jpegGainMap.data = gainMapEncoder.getCompressedImagePtr();
-            jpegGainMap.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-            ultrahdr_metadata_struct metadata;
-            metadata.version = kJpegrVersion;
-            if (tf == ULTRAHDR_TF_HLG) {
-              metadata.maxContentBoost = kHlgMaxNits / kSdrWhiteNits;
-            } else if (tf == ULTRAHDR_TF_PQ) {
-              metadata.maxContentBoost = kPqMaxNits / kSdrWhiteNits;
-            } else {
-              metadata.maxContentBoost = 1.0f;
-            }
-            metadata.minContentBoost = 1.0f;
+          if (gainMapEncoder.compressImage(&gainmapImg, gainmap_quality, nullptr, 0).error_code ==
+              UHDR_CODEC_OK) {
+            struct uhdr_compressed_image jpegGainMap = gainMapEncoder.getCompressedImage();
+            uhdr_gainmap_metadata metadata;
+            metadata.max_content_boost = 17.0f;
+            metadata.min_content_boost = 1.0f;
             metadata.gamma = 1.0f;
-            metadata.offsetSdr = 0.0f;
-            metadata.offsetHdr = 0.0f;
-            metadata.hdrCapacityMin = 1.0f;
-            metadata.hdrCapacityMax = metadata.maxContentBoost;
-            status = jpegHdr.encodeJPEGR(&jpegImg, &jpegGainMap, &metadata, &jpegImgR);
+            metadata.offset_sdr = 0.0f;
+            metadata.offset_hdr = 0.0f;
+            metadata.hdr_capacity_min = 1.0f;
+            metadata.hdr_capacity_max = metadata.max_content_boost;
+            ON_ERR(uhdr_enc_set_compressed_image(enc_handle, &jpegImg, UHDR_BASE_IMG))
+            ON_ERR(uhdr_enc_set_gainmap_image(enc_handle, &jpegGainMap, &metadata))
+            status = uhdr_encode(enc_handle);
           }
         }
       }
     }
-    if (status == JPEGR_NO_ERROR) {
-      jpegr_info_struct info{};
-      status = jpegHdr.getJPEGRInfo(&jpegImgR, &info);
-      if (status == JPEGR_NO_ERROR) {
-        size_t outSize = info.width * info.height * ((of == ULTRAHDR_OUTPUT_HDR_LINEAR) ? 8 : 4);
-        jpegr_uncompressed_struct decodedJpegR;
-        auto decodedRaw = std::make_unique<uint8_t[]>(outSize);
-        decodedJpegR.data = decodedRaw.get();
-        ultrahdr_metadata_struct metadata;
-        status = jpegHdr.decodeJPEGR(&jpegImgR, &decodedJpegR,
-                                     mFdp.ConsumeFloatingPointInRange<float>(1.0, FLT_MAX), nullptr,
-                                     of, nullptr, &metadata);
-        if (status != JPEGR_NO_ERROR) {
-          ALOGE("encountered error during decoding %d", status);
+    if (status.error_code == UHDR_CODEC_OK) {
+      auto output = uhdr_get_encoded_stream(enc_handle);
+      if (output != nullptr) {
+        uhdr_codec_private_t* dec_handle = uhdr_create_decoder();
+        if (dec_handle) {
+          ON_ERR(uhdr_dec_set_image(dec_handle, output))
+          ON_ERR(uhdr_dec_set_out_color_transfer(dec_handle, tf))
+          if (tf == UHDR_CT_LINEAR)
+            ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_64bppRGBAHalfFloat))
+          else if (tf == UHDR_CT_SRGB)
+            ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA8888))
+          else
+            ON_ERR(uhdr_dec_set_out_img_format(dec_handle, UHDR_IMG_FMT_32bppRGBA1010102))
+          ON_ERR(uhdr_decode(dec_handle))
+          uhdr_release_decoder(dec_handle);
         }
-      } else {
-        ALOGE("encountered error during get jpeg info %d", status);
       }
+      uhdr_release_encoder(enc_handle);
     } else {
-      ALOGE("encountered error during encoding %d", status);
+      uhdr_release_encoder(enc_handle);
+      ON_ERR(status);
     }
   }
 }
diff --git a/java/UltraHdrApp.java b/java/UltraHdrApp.java
new file mode 100644
index 0000000..e6376e5
--- /dev/null
+++ b/java/UltraHdrApp.java
@@ -0,0 +1,711 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.*;
+import static com.google.media.codecs.ultrahdr.UltraHDREncoder.UHDR_USAGE_BEST_QUALITY;
+
+import java.io.File;
+import java.io.FileInputStream;
+import java.io.BufferedReader;
+import java.io.FileReader;
+import java.io.BufferedWriter;
+import java.io.FileWriter;
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
+
+import com.google.media.codecs.ultrahdr.UltraHDRDecoder;
+import com.google.media.codecs.ultrahdr.UltraHDREncoder;
+import com.google.media.codecs.ultrahdr.UltraHDRDecoder.GainMapMetadata;
+import com.google.media.codecs.ultrahdr.UltraHDRDecoder.RawImage;
+
+/**
+ * Ultra HDR Encoding/Decoding Demo Application
+ */
+public class UltraHdrApp {
+    private final String mHdrIntentRawFile;
+    private final String mSdrIntentRawFile;
+    private final String mSdrIntentCompressedFile;
+    private final String mGainMapCompressedFile;
+    private final String mGainMapMetadaCfgFile;
+    private final String mExifFile;
+    private final String mUhdrFile;
+    private final String mOutputFile;
+    private final int mWidth;
+    private final int mHeight;
+    private final int mHdrCf;
+    private final int mSdrCf;
+    private final int mHdrCg;
+    private final int mSdrCg;
+    private final int mHdrTf;
+    private final int mQuality;
+    private final int mOTF;
+    private final int mOfmt;
+    private final boolean mFullRange;
+    private final int mMapDimensionScaleFactor;
+    private final int mMapCompressQuality;
+    private final boolean mUseMultiChannelGainMap;
+    private final float mGamma;
+    private final boolean mEnableGLES;
+    private final int mEncPreset;
+    private final float mMinContentBoost;
+    private final float mMaxContentBoost;
+
+    byte[] mYuv420YData, mYuv420CbData, mYuv420CrData;
+    short[] mP010YData, mP010CbCrData;
+    int[] mRgba1010102Data, mRgba8888Data;
+    byte[] mCompressedImageData;
+    byte[] mGainMapCompressedImageData;
+    byte[] mExifData;
+    byte[] mUhdrImagedata;
+    GainMapMetadata mMetadata;
+    RawImage mDecodedUhdrRgbImage;
+
+    public UltraHdrApp(String hdrIntentRawFile, String sdrIntentRawFile,
+            String sdrIntentCompressedFile, String gainmapCompressedFile,
+            String gainmapMetadataCfgFile, String exifFile, String outputFile, int width,
+            int height, int hdrCf, int sdrCf, int hdrCg, int sdrCg, int hdrTf, int quality, int oTf,
+            int oFmt, boolean isHdrCrFull, int gainmapScaleFactor, int gainmapQuality,
+            boolean enableMultiChannelGainMap, float gamma, int encPreset, float minContentBoost,
+            float maxContentBoost) {
+        mHdrIntentRawFile = hdrIntentRawFile;
+        mSdrIntentRawFile = sdrIntentRawFile;
+        mSdrIntentCompressedFile = sdrIntentCompressedFile;
+        mGainMapCompressedFile = gainmapCompressedFile;
+        mGainMapMetadaCfgFile = gainmapMetadataCfgFile;
+        mExifFile = exifFile;
+        mUhdrFile = null;
+        mOutputFile = outputFile;
+        mWidth = width;
+        mHeight = height;
+        mHdrCf = hdrCf;
+        mSdrCf = sdrCf;
+        mHdrCg = hdrCg;
+        mSdrCg = sdrCg;
+        mHdrTf = hdrTf;
+        mQuality = quality;
+        mOTF = oTf;
+        mOfmt = oFmt;
+        mFullRange = isHdrCrFull;
+        mMapDimensionScaleFactor = gainmapScaleFactor;
+        mMapCompressQuality = gainmapQuality;
+        mUseMultiChannelGainMap = enableMultiChannelGainMap;
+        mGamma = gamma;
+        mEnableGLES = false;
+        mEncPreset = encPreset;
+        mMinContentBoost = minContentBoost;
+        mMaxContentBoost = maxContentBoost;
+    }
+
+    public UltraHdrApp(String gainmapMetadataCfgFile, String uhdrFile, String outputFile, int oTF,
+            int oFmt, boolean enableGLES) {
+        mHdrIntentRawFile = null;
+        mSdrIntentRawFile = null;
+        mSdrIntentCompressedFile = null;
+        mGainMapCompressedFile = null;
+        mGainMapMetadaCfgFile = gainmapMetadataCfgFile;
+        mExifFile = null;
+        mUhdrFile = uhdrFile;
+        mOutputFile = outputFile;
+        mWidth = 0;
+        mHeight = 0;
+        mHdrCf = UHDR_IMG_FMT_UNSPECIFIED;
+        mSdrCf = UHDR_IMG_FMT_UNSPECIFIED;
+        mHdrCg = UHDR_CG_UNSPECIFIED;
+        mSdrCg = UHDR_CG_UNSPECIFIED;
+        mHdrTf = UHDR_CT_UNSPECIFIED;
+        mQuality = 95;
+        mOTF = oTF;
+        mOfmt = oFmt;
+        mFullRange = false;
+        mMapDimensionScaleFactor = 1;
+        mMapCompressQuality = 95;
+        mUseMultiChannelGainMap = true;
+        mGamma = 1.0f;
+        mEnableGLES = enableGLES;
+        mEncPreset = UHDR_USAGE_BEST_QUALITY;
+        mMinContentBoost = Float.MIN_VALUE;
+        mMaxContentBoost = Float.MAX_VALUE;
+    }
+
+    public byte[] readFile(String filename) throws IOException {
+        byte[] data;
+        try (FileInputStream fis = new FileInputStream(filename)) {
+            File descriptor = new File(filename);
+            long size = descriptor.length();
+            if (size <= 0 || size > Integer.MAX_VALUE) {
+                throw new IOException("Unexpected file size received for file: " + filename);
+            }
+            data = new byte[(int) size];
+            if (fis.read(data) != size) {
+                throw new IOException("Failed to read file: " + filename + " completely");
+            }
+        }
+        return data;
+    }
+
+    public void fillP010ImageHandle() throws IOException {
+        final int bpp = 2;
+        final int lumaSampleCount = mWidth * mHeight;
+        final int chromaSampleCount = (mWidth / 2) * (mHeight / 2) * 2;
+        final int expectedSize = (lumaSampleCount + chromaSampleCount) * bpp;
+        byte[] data = readFile(mHdrIntentRawFile);
+        if (data.length < expectedSize) {
+            throw new RuntimeException(
+                    "For the configured width, height, P010 Image File is expected to contain "
+                            + expectedSize + " bytes, but the file has " + data.length + " bytes");
+        }
+        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
+        byteBuffer.order(ByteOrder.nativeOrder());
+        mP010YData = new short[lumaSampleCount];
+        byteBuffer.asShortBuffer().get(mP010YData);
+        byteBuffer.position(lumaSampleCount * bpp);
+        mP010CbCrData = new short[chromaSampleCount];
+        byteBuffer.asShortBuffer().get(mP010CbCrData);
+    }
+
+    public void fillRGBA1010102ImageHandle() throws IOException {
+        final int bpp = 4;
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
+        mRgba1010102Data = new int[mHeight * mWidth];
+        byteBuffer.asIntBuffer().get(mRgba1010102Data);
+    }
+
+    public void fillRGBA8888Handle() throws IOException {
+        final int bpp = 4;
+        final int rgbSampleCount = mHeight * mWidth;
+        final int expectedSize = rgbSampleCount * bpp;
+        byte[] data = readFile(mSdrIntentRawFile);
+        if (data.length < expectedSize) {
+            throw new RuntimeException("For the configured width, height, RGBA8888 Image File is"
+                    + " expected to contain " + expectedSize + " bytes, but the file has "
+                    + data.length + " bytes");
+        }
+        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
+        byteBuffer.order(ByteOrder.nativeOrder());
+        mRgba8888Data = new int[mHeight * mWidth];
+        byteBuffer.asIntBuffer().get(mRgba8888Data);
+    }
+
+    public void fillYUV420ImageHandle() throws IOException {
+        final int lumaSampleCount = mWidth * mHeight;
+        final int cbSampleCount = (mWidth / 2) * (mHeight / 2);
+        final int crSampleCount = (mWidth / 2) * (mHeight / 2);
+        try (FileInputStream fis = new FileInputStream(mSdrIntentRawFile)) {
+            mYuv420YData = new byte[lumaSampleCount];
+            int bytesRead = fis.read(mYuv420YData);
+            if (bytesRead != lumaSampleCount) {
+                throw new IOException("Failed to read " + lumaSampleCount + " bytes from file: "
+                        + mSdrIntentRawFile);
+            }
+            mYuv420CbData = new byte[cbSampleCount];
+            bytesRead = fis.read(mYuv420CbData);
+            if (bytesRead != cbSampleCount) {
+                throw new IOException("Failed to read " + cbSampleCount + " bytes from file: "
+                        + mSdrIntentRawFile);
+            }
+            mYuv420CrData = new byte[crSampleCount];
+            bytesRead = fis.read(mYuv420CrData);
+            if (bytesRead != crSampleCount) {
+                throw new IOException("Failed to read " + crSampleCount + " bytes from file: "
+                        + mSdrIntentRawFile);
+            }
+        }
+    }
+
+    public void fillSdrCompressedImageHandle() throws IOException {
+        mCompressedImageData = readFile(mSdrIntentCompressedFile);
+    }
+
+    public void fillGainMapCompressedImageHandle() throws IOException {
+        mGainMapCompressedImageData = readFile(mGainMapCompressedFile);
+    }
+
+    public void fillExifMemoryBlock() throws IOException {
+        mExifData = readFile(mExifFile);
+    }
+
+    public void fillUhdrImageHandle() throws IOException {
+        mUhdrImagedata = readFile(mUhdrFile);
+    }
+
+    public void fillGainMapMetadataDescriptor() throws IOException {
+        mMetadata = new GainMapMetadata();
+        try (BufferedReader reader = new BufferedReader(new FileReader(mGainMapMetadaCfgFile))) {
+            String line;
+            while ((line = reader.readLine()) != null) {
+                String[] parts = line.split("\\s+");
+                if (parts.length == 2 && parts[0].startsWith("--")) {
+                    String option = parts[0].substring(2); // remove the "--" prefix
+                    float value = Float.parseFloat(parts[1]);
+                    switch (option) {
+                        case "maxContentBoost":
+                            mMetadata.maxContentBoost = value;
+                            break;
+                        case "minContentBoost":
+                            mMetadata.minContentBoost = value;
+                            break;
+                        case "gamma":
+                            mMetadata.gamma = value;
+                            break;
+                        case "offsetSdr":
+                            mMetadata.offsetSdr = value;
+                            break;
+                        case "offsetHdr":
+                            mMetadata.offsetHdr = value;
+                            break;
+                        case "hdrCapacityMin":
+                            mMetadata.hdrCapacityMin = value;
+                            break;
+                        case "hdrCapacityMax":
+                            mMetadata.hdrCapacityMax = value;
+                            break;
+                        default:
+                            System.err.println("ignoring option: " + option);
+                            break;
+                    }
+                } else {
+                    System.err.println("Unable to parse line : " + line);
+                }
+            }
+        }
+    }
+
+    public void writeGainMapMetadataToFile(GainMapMetadata metadata) throws IOException {
+        try (BufferedWriter writer = new BufferedWriter(new FileWriter(mGainMapMetadaCfgFile))) {
+            writer.write("--maxContentBoost " + metadata.maxContentBoost + "\n");
+            writer.write("--minContentBoost " + metadata.minContentBoost + "\n");
+            writer.write("--gamma " + metadata.gamma + "\n");
+            writer.write("--offsetSdr " + metadata.offsetSdr + "\n");
+            writer.write("--offsetHdr " + metadata.offsetHdr + "\n");
+            writer.write("--hdrCapacityMin " + metadata.hdrCapacityMin + "\n");
+            writer.write("--hdrCapacityMax " + metadata.hdrCapacityMax + "\n");
+        }
+    }
+
+    public void writeFile(String fileName, RawImage img) throws IOException {
+        try (FileOutputStream fos = new FileOutputStream(fileName)) {
+            if (img.fmt == UHDR_IMG_FMT_32bppRGBA8888 || img.fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat
+                    || img.fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
+                byte[] data = img.nativeOrderBuffer;
+                int bpp = img.fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
+                int stride = img.stride * bpp;
+                int length = img.w * bpp;
+                for (int i = 0; i < img.h; i++) {
+                    fos.write(data, i * stride, length);
+                }
+            } else {
+                throw new RuntimeException("Unsupported color format ");
+            }
+        }
+    }
+
+    public void writeFile(String fileName, byte[] data) throws IOException {
+        try (FileOutputStream fos = new FileOutputStream(fileName)) {
+            fos.write(data);
+        }
+    }
+
+    public void encode() throws Exception {
+        try (UltraHDREncoder handle = new UltraHDREncoder()) {
+            if (mHdrIntentRawFile != null) {
+                if (mHdrCf == UHDR_IMG_FMT_24bppYCbCrP010) {
+                    fillP010ImageHandle();
+                    handle.setRawImage(mP010YData, mP010CbCrData, mWidth, mHeight, mWidth, mWidth,
+                            mHdrCg, mHdrTf, mFullRange ? UHDR_CR_FULL_RANGE : UHDR_CR_LIMITED_RANGE,
+                            mHdrCf, UHDR_HDR_IMG);
+                } else if (mHdrCf == UHDR_IMG_FMT_32bppRGBA1010102) {
+                    fillRGBA1010102ImageHandle();
+                    handle.setRawImage(mRgba1010102Data, mWidth, mHeight, mWidth, mHdrCg, mHdrTf,
+                            UHDR_CR_FULL_RANGE, mHdrCf, UHDR_HDR_IMG);
+                } else {
+                    throw new IllegalArgumentException("invalid hdr intent color format " + mHdrCf);
+                }
+            }
+            if (mSdrIntentRawFile != null) {
+                if (mSdrCf == UHDR_IMG_FMT_12bppYCbCr420) {
+                    fillYUV420ImageHandle();
+                    handle.setRawImage(mYuv420YData, mYuv420CbData, mYuv420CrData, mWidth, mHeight,
+                            mWidth, mWidth / 2, mWidth / 2, mSdrCg, UHDR_CT_SRGB,
+                            UHDR_CR_FULL_RANGE, mSdrCf, UHDR_SDR_IMG);
+                } else if (mSdrCf == UHDR_IMG_FMT_32bppRGBA8888) {
+                    fillRGBA8888Handle();
+                    handle.setRawImage(mRgba8888Data, mWidth, mHeight, mWidth, mSdrCg, UHDR_CT_SRGB,
+                            UHDR_CR_FULL_RANGE, mSdrCf, UHDR_SDR_IMG);
+                } else {
+                    throw new IllegalArgumentException("invalid sdr intent color format " + mSdrCf);
+                }
+            }
+            if (mSdrIntentCompressedFile != null) {
+                fillSdrCompressedImageHandle();
+                handle.setCompressedImage(mCompressedImageData, mCompressedImageData.length, mSdrCg,
+                        UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED,
+                        (mGainMapCompressedFile != null && mGainMapMetadaCfgFile != null) ?
+                                UHDR_BASE_IMG : UHDR_SDR_IMG);
+            }
+            if (mGainMapCompressedFile != null && mGainMapMetadaCfgFile != null) {
+                fillGainMapCompressedImageHandle();
+                fillGainMapMetadataDescriptor();
+                handle.setGainMapImageInfo(mGainMapCompressedImageData,
+                        mGainMapCompressedImageData.length, mMetadata.maxContentBoost,
+                        mMetadata.minContentBoost, mMetadata.gamma, mMetadata.offsetSdr,
+                        mMetadata.offsetHdr, mMetadata.hdrCapacityMin, mMetadata.hdrCapacityMax);
+            }
+            if (mExifFile != null) {
+                fillExifMemoryBlock();
+                handle.setExifData(mExifData, mExifData.length);
+            }
+            handle.setQualityFactor(mQuality, UHDR_BASE_IMG);
+            handle.setQualityFactor(mMapCompressQuality, UHDR_GAIN_MAP_IMG);
+            handle.setMultiChannelGainMapEncoding(mUseMultiChannelGainMap);
+            handle.setGainMapScaleFactor(mMapDimensionScaleFactor);
+            handle.setGainMapGamma(mGamma);
+            handle.setEncPreset(mEncPreset);
+            if (mMinContentBoost != Float.MIN_VALUE || mMaxContentBoost != Float.MAX_VALUE) {
+                handle.setMinMaxContentBoost(mMinContentBoost, mMaxContentBoost);
+            }
+            handle.encode();
+            mUhdrImagedata = handle.getOutput();
+            writeFile(mOutputFile, mUhdrImagedata);
+        }
+    }
+
+    public void decode() throws Exception {
+        fillUhdrImageHandle();
+        try (UltraHDRDecoder handle = new UltraHDRDecoder()) {
+            handle.setCompressedImage(mUhdrImagedata, mUhdrImagedata.length, UHDR_CG_UNSPECIFIED,
+                    UHDR_CG_UNSPECIFIED, UHDR_CR_UNSPECIFIED);
+            handle.setColorTransfer(mOTF);
+            handle.setOutputFormat(mOfmt);
+            if (mEnableGLES) {
+                handle.enableGpuAcceleration(mEnableGLES ? 1 : 0);
+            }
+            handle.probe();
+            if (mGainMapMetadaCfgFile != null) {
+                GainMapMetadata metadata = handle.getGainmapMetadata();
+                writeGainMapMetadataToFile(metadata);
+            }
+            handle.decode();
+            mDecodedUhdrRgbImage = handle.getDecodedImage();
+            writeFile(mOutputFile, mDecodedUhdrRgbImage);
+        }
+    }
+
+    public static void usage() {
+        System.out.println("\n## uhdr demo application. lib version: " + getVersionString());
+        System.out.println("Usage : java -Djava.library.path=<path> -jar uhdr-java.jar");
+        System.out.println("    -m    mode of operation. [0:encode, 1:decode]");
+        System.out.println("\n## encoder options :");
+        System.out.println("    -p    raw hdr intent input resource (10-bit), required for encoding"
+                + " scenarios 0, 1, 2, 3.");
+        System.out.println("    -y    raw sdr intent input resource (8-bit), required for encoding"
+                + " scenarios 1, 2.");
+        System.out.println("    -a    raw hdr intent color format, optional. [0:p010, 5:rgba1010102"
+                + " (default)]");
+        System.out.println("    -b    raw sdr intent color format, optional. [1:yuv420, 3:rgba8888"
+                + " (default)]");
+        System.out.println("    -i    compressed sdr intent input resource (jpeg), required for "
+                + "encoding scenarios 2, 3, 4.");
+        System.out.println("    -g    compressed gainmap input resource (jpeg), required for "
+                + "encoding scenario 4.");
+        System.out.println(
+                "    -w    input file width, required for encoding scenarios 0, 1, 2, 3.");
+        System.out.println(
+                "    -h    input file height, required for encoding scenarios 0, 1, 2, 3.");
+        System.out.println(
+                "    -C    hdr intent color gamut, optional. [0:bt709, 1:p3 (default), 2:bt2100]");
+        System.out.println(
+                "    -c    sdr intent color gamut, optional. [0:bt709 (default), 1:p3, 2:bt2100]");
+        System.out.println(
+                "    -t    hdr intent color transfer, optional. [0:linear, 1:hlg (default), 2:pq]");
+        System.out.println("    -q    quality factor to be used while encoding sdr intent, "
+                + "optional. [0-100], 95 : default.");
+        System.out.println("    -R    color range of hdr intent, optional. [0:narrow-range "
+                + "(default), 1:full-range].");
+        System.out.println("    -s    gainmap image downsample factor, optional. [integer values"
+                + " in range [1 - 128] (1 : default)].");
+        System.out.println("    -Q    quality factor to be used while encoding gain map image,"
+                + " optional. [0-100], 95 : default.");
+        System.out.println("    -G    gamma correction to be applied on the gainmap image, "
+                + "optional. [any positive real number (1.0 : default)].");
+        System.out.println("    -M    select multi channel gain map, optional. [0:disable, "
+                + " 1:enable (default)].");
+        System.out.println("    -D    select encoding preset, optional. [0:real time,"
+                + " 1:best quality (default)].");
+        System.out.println("    -k    min content boost recommendation, must be in linear scale,"
+                + " optional. any positive real number");
+        System.out.println("    -K    max content boost recommendation, must be in linear scale,"
+                + " optional. any positive real number");
+        System.out.println("    -x    binary input resource containing exif data to insert, "
+                + "optional.");
+        System.out.println("\n## decoder options :");
+        System.out.println("    -j    ultra hdr compressed input resource, required.");
+        System.out.println("    -o    output transfer function, optional. [0:linear,"
+                + " 1:hlg (default), 2:pq, 3:srgb]");
+        System.out.println("    -O    output color format, optional. [3:rgba8888, 4:rgbahalffloat, "
+                + "5:rgba1010102 (default)]");
+        System.out.println("          It should be noted that not all combinations of output color"
+                + " format and output");
+        System.out.println("          transfer function are supported.");
+        System.out.println(
+                "          srgb output color transfer shall be paired with rgba8888 only.");
+        System.out.println("          hlg, pq shall be paired with rgba1010102.");
+        System.out.println("          linear shall be paired with rgbahalffloat.");
+        System.out.println(
+                "    -u    enable gles acceleration, optional. [0:disable (default), 1:enable].");
+        System.out.println("\n## common options :");
+        System.out.println("    -z    output filename, optional.");
+        System.out.println("          in encoding mode, default output filename 'out.jpeg'.");
+        System.out.println("          in decoding mode, default output filename 'outrgb.raw'.");
+        System.out.println("    -f    gainmap metadata config file.");
+        System.out.println("          in encoding mode, resource from which gainmap metadata is "
+                + "read, required for encoding scenario 4.");
+        System.out.println("          in decoding mode, resource to which gainmap metadata is "
+                + "written, optional.");
+        System.out.println("\n## examples of usage :");
+        System.out.println("\n## encode scenario 0 :");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_p010.yuv -w 1920 -h 1080 -q 97 -a 0");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_rgba1010102.raw -w  1920 -h 1080 -q 97 -a 5");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_p010.yuv -w 1920 -h 1080 -q 97 -C 1 -t 2 -a 0");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_rgba1010102.raw -w 1920 -h 1080 -q 97 -C 1 -t 2 -a 5");
+        System.out.println("\n## encode scenario 1 :");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 -h 1080 -q 97 "
+                + "-a 0 -b 1");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_rgba1010102.raw -y cosmat_1920x1080_rgba8888.raw -w 1920 -h "
+                + "1080 -q 97 -a 5 -b 3");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 -h 1080 -q 97 -C"
+                + " 2 -c 1 -t 1 -a 0 -b 1");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_rgba1010102.raw -y cosmat_1920x1080_rgba8888.raw -w 1920 "
+                + "-h 1080 -q 97 -C 2 -c 1 -t 1 -a 5 -b 3");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -w 1920 -h 1080 -q 97 -C"
+                + " 2 -c 1 -t 1 -a 0 -b 1");
+        System.out.println("\n## encode scenario 2 :");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_p010.yuv -y cosmat_1920x1080_420.yuv -i "
+                + "cosmat_1920x1080_420_8bit.jpg -w 1920 -h 1080 -t 1 -o 3 -O 3 -a 0 -b 1");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_rgba1010102.raw -y cosmat_1920x1080_420.yuv -i "
+                + "cosmat_1920x1080_420_8bit.jpg -w 1920 -h 1080 -t 1 -o 3 -O 3 -a 5 -b 1");
+        System.out.println("\n## encode scenario 3 :");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_p010.yuv -i cosmat_1920x1080_420_8bit.jpg -w 1920 -h 1080 -t "
+                + "1 -o 1 -O 5 -a 0");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "cosmat_1920x1080_rgba1010102.raw -i cosmat_1920x1080_420_8bit.jpg -w 1920 -h "
+                + "1080 -t 1 -o 1 -O 5 -a 5");
+        System.out.println("\n## encode scenario 4 :");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -i "
+                + "cosmat_1920x1080_420_8bit.jpg -g cosmat_1920x1080_420_8bit.jpg -f metadata.cfg");
+        System.out.println("\n## encode at high quality :");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 0 -p "
+                + "hdr_intent.raw -y sdr_intent.raw -w 640 -h 480 -c <select> -C <select> -t "
+                + "<select> -s 1 -M 1 -Q 98 -q 98 -D 1");
+        System.out.println("\n## decode api :");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 1 "
+                + "-j cosmat_1920x1080_hdr.jpg");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 1 -j "
+                + "cosmat_1920x1080_hdr.jpg -o 3 -O 3");
+        System.out.println("    java -Djava.library.path=<path> -jar uhdr-java.jar -m 1 -j "
+                + "cosmat_1920x1080_hdr.jpg -o 1 -O 5");
+        System.out.println("\n");
+    }
+
+    public static void main(String[] args) throws Exception {
+        String hdr_intent_raw_file = null;
+        String sdr_intent_raw_file = null;
+        String sdr_intent_compressed_file = null;
+        String gainmap_compressed_file = null;
+        String uhdr_file = null;
+        String gainmap_metadata_cfg_file = null;
+        String output_file = null;
+        String exif_file = null;
+        int width = 0, height = 0;
+        int hdr_cg = UHDR_CG_DISPlAY_P3;
+        int sdr_cg = UHDR_CG_BT709;
+        int hdr_cf = UHDR_IMG_FMT_32bppRGBA1010102;
+        int sdr_cf = UHDR_IMG_FMT_32bppRGBA8888;
+        int hdr_tf = UHDR_CT_HLG;
+        int quality = 95;
+        int out_tf = UHDR_CT_HLG;
+        int out_cf = UHDR_IMG_FMT_32bppRGBA1010102;
+        int mode = -1;
+        int gain_map_scale_factor = 1;
+        int gainmap_compression_quality = 95;
+        int enc_preset = UHDR_USAGE_BEST_QUALITY;
+        float gamma = 1.0f;
+        boolean enable_gles = false;
+        float min_content_boost = Float.MIN_VALUE;
+        float max_content_boost = Float.MAX_VALUE;
+        boolean use_full_range_color_hdr = false;
+        boolean use_multi_channel_gainmap = true;
+
+        for (int i = 0; i < args.length; i++) {
+            if (args[i].length() == 2 && args[i].charAt(0) == '-') {
+                switch (args[i].charAt(1)) {
+                    case 'a':
+                        hdr_cf = Integer.parseInt(args[++i]);
+                        break;
+                    case 'b':
+                        sdr_cf = Integer.parseInt(args[++i]);
+                        break;
+                    case 'p':
+                        hdr_intent_raw_file = args[++i];
+                        break;
+                    case 'y':
+                        sdr_intent_raw_file = args[++i];
+                        break;
+                    case 'i':
+                        sdr_intent_compressed_file = args[++i];
+                        break;
+                    case 'g':
+                        gainmap_compressed_file = args[++i];
+                        break;
+                    case 'f':
+                        gainmap_metadata_cfg_file = args[++i];
+                        break;
+                    case 'w':
+                        width = Integer.parseInt(args[++i]);
+                        break;
+                    case 'h':
+                        height = Integer.parseInt(args[++i]);
+                        break;
+                    case 'C':
+                        hdr_cg = Integer.parseInt(args[++i]);
+                        break;
+                    case 'c':
+                        sdr_cg = Integer.parseInt(args[++i]);
+                        break;
+                    case 't':
+                        hdr_tf = Integer.parseInt(args[++i]);
+                        break;
+                    case 'q':
+                        quality = Integer.parseInt(args[++i]);
+                        break;
+                    case 'O':
+                        out_cf = Integer.parseInt(args[++i]);
+                        break;
+                    case 'o':
+                        out_tf = Integer.parseInt(args[++i]);
+                        break;
+                    case 'm':
+                        mode = Integer.parseInt(args[++i]);
+                        break;
+                    case 'R':
+                        use_full_range_color_hdr = Integer.parseInt(args[++i]) == 1;
+                        break;
+                    case 's':
+                        gain_map_scale_factor = Integer.parseInt(args[++i]);
+                        break;
+                    case 'M':
+                        use_multi_channel_gainmap = Integer.parseInt(args[++i]) == 1;
+                        break;
+                    case 'Q':
+                        gainmap_compression_quality = Integer.parseInt(args[++i]);
+                        break;
+                    case 'G':
+                        gamma = Float.parseFloat(args[++i]);
+                        break;
+                    case 'j':
+                        uhdr_file = args[++i];
+                        break;
+                    case 'z':
+                        output_file = args[++i];
+                        break;
+                    case 'x':
+                        exif_file = args[++i];
+                        break;
+                    case 'u':
+                        enable_gles = Integer.parseInt(args[++i]) == 1;
+                        break;
+                    case 'D':
+                        enc_preset = Integer.parseInt(args[++i]);
+                        break;
+                    case 'k':
+                        min_content_boost = Float.parseFloat(args[++i]);
+                        break;
+                    case 'K':
+                        max_content_boost = Float.parseFloat(args[++i]);
+                        break;
+                    default:
+                        System.err.println("Unrecognized option, arg: " + args[i]);
+                        usage();
+                        return;
+                }
+            } else {
+                System.err.println("Invalid argument format, arg: " + args[i]);
+                usage();
+                return;
+            }
+        }
+        if (mode == 0) {
+            if (width <= 0 && gainmap_metadata_cfg_file == null) {
+                System.err.println("did not receive valid image width for encoding. width : "
+                        + width);
+                return;
+            }
+            if (height <= 0 && gainmap_metadata_cfg_file == null) {
+                System.err.println("did not receive valid image height for encoding. height : "
+                        + height);
+                return;
+            }
+            if (hdr_intent_raw_file == null && (sdr_intent_compressed_file == null
+                    || gainmap_compressed_file == null || gainmap_metadata_cfg_file == null)) {
+                System.err.println("did not receive raw resources for encoding.");
+                return;
+            }
+            UltraHdrApp appInput = new UltraHdrApp(hdr_intent_raw_file, sdr_intent_raw_file,
+                    sdr_intent_compressed_file, gainmap_compressed_file, gainmap_metadata_cfg_file,
+                    exif_file, output_file != null ? output_file : "out.jpeg", width, height,
+                    hdr_cf, sdr_cf, hdr_cg, sdr_cg, hdr_tf, quality, out_tf, out_cf,
+                    use_full_range_color_hdr, gain_map_scale_factor, gainmap_compression_quality,
+                    use_multi_channel_gainmap, gamma, enc_preset, min_content_boost,
+                    max_content_boost);
+            appInput.encode();
+        } else if (mode == 1) {
+            if (uhdr_file == null) {
+                System.err.println("did not receive resources for decoding");
+                return;
+            }
+            UltraHdrApp appInput = new UltraHdrApp(gainmap_metadata_cfg_file, uhdr_file,
+                    output_file != null ? output_file : "outrgb.raw", out_tf, out_cf, enable_gles);
+            appInput.decode();
+        } else {
+            if (args.length > 0) {
+                System.err.println("did not receive valid mode of operation");
+            }
+            usage();
+        }
+    }
+}
diff --git a/java/com/google/media/codecs/ultrahdr/UltraHDRCommon.java b/java/com/google/media/codecs/ultrahdr/UltraHDRCommon.java
new file mode 100644
index 0000000..4deb117
--- /dev/null
+++ b/java/com/google/media/codecs/ultrahdr/UltraHDRCommon.java
@@ -0,0 +1,226 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.google.media.codecs.ultrahdr;
+
+/**
+ * Ultra HDR common utility class (cannot be instantiated). These constants MUST be kept in sync
+ * with the constants defined ultrahdr_api.h
+ */
+public class UltraHDRCommon {
+    // Fields describing the color format of raw image
+    /**
+     * Unspecified color format
+     */
+    public static final int UHDR_IMG_FMT_UNSPECIFIED = -1;
+
+    /**
+     * P010 is 10-bit-per component 4:2:0 YCbCr semiplanar format.
+     * <p>
+     * This format uses 24 allocated bits per pixel with 15 bits of
+     * data per pixel. Chroma planes are subsampled by 2 both
+     * horizontally and vertically. Each chroma and luma component
+     * has 16 allocated bits in little-endian configuration with 10
+     * MSB of actual data.
+     *
+     * <pre>
+     *            byte                   byte
+     *  <--------- i --------> | <------ i + 1 ------>
+     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+     * |     UNUSED      |      Y/Cb/Cr                |
+     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
+     *  0               5 6   7 0                    7
+     * bit
+     * </pre>
+     */
+    public static final int UHDR_IMG_FMT_24bppYCbCrP010 = 0;
+
+    /**
+     * Flexible 12 bits per pixel, subsampled YUV color format with 8-bit chroma and luma
+     * components.
+     * <p>
+     * Chroma planes are subsampled by 2 both horizontally and vertically.
+     */
+    public static final int UHDR_IMG_FMT_12bppYCbCr420 = 1;
+
+    /**
+     * 8 bits per pixel Y color format.
+     * <p>
+     * Each byte contains a single pixel.
+     */
+    public static final int UHDR_IMG_FMT_8bppYCbCr400 = 2;
+
+    /**
+     * 32 bits per pixel RGBA color format, with 8-bit red, green, blue, and alpha components.
+     * <p>
+     * Using 32-bit little-endian representation, colors stored as Red 7:0, Green 15:8,
+     * Blue 23:16, and Alpha 31:24.
+     * <pre>
+     *         byte              byte             byte              byte
+     *  <------ i -----> | <---- i+1 ----> | <---- i+2 ----> | <---- i+3 ----->
+     * +-----------------+-----------------+-----------------+-----------------+
+     * |       RED       |      GREEN      |       BLUE      |      ALPHA      |
+     * +-----------------+-----------------+-----------------+-----------------+
+     * </pre>
+     */
+    public static final int UHDR_IMG_FMT_32bppRGBA8888 = 3;
+
+    /**
+     * 64 bits per pixel RGBA color format, with 16-bit signed
+     * floating point red, green, blue, and alpha components.
+     * <p>
+     *
+     * <pre>
+     *         byte              byte             byte              byte
+     *  <-- i -->|<- i+1 ->|<- i+2 ->|<- i+3 ->|<- i+4 ->|<- i+5 ->|<- i+6 ->|<- i+7 ->
+     * +---------+---------+-------------------+---------+---------+---------+---------+
+     * |        RED        |       GREEN       |       BLUE        |       ALPHA       |
+     * +---------+---------+-------------------+---------+---------+---------+---------+
+     *  0       7 0       7 0       7 0       7 0       7 0       7 0       7 0       7
+     * </pre>
+     */
+    public static final int UHDR_IMG_FMT_64bppRGBAHalfFloat = 4;
+
+    /**
+     * 32 bits per pixel RGBA color format, with 10-bit red, green,
+     * blue, and 2-bit alpha components.
+     * <p>
+     * Using 32-bit little-endian representation, colors stored as
+     * Red 9:0, Green 19:10, Blue 29:20, and Alpha 31:30.
+     * <pre>
+     *         byte              byte             byte              byte
+     *  <------ i -----> | <---- i+1 ----> | <---- i+2 ----> | <---- i+3 ----->
+     * +-----------------+---+-------------+-------+---------+-----------+-----+
+     * |       RED           |      GREEN          |       BLUE          |ALPHA|
+     * +-----------------+---+-------------+-------+---------+-----------+-----+
+     *  0               7 0 1 2           7 0     3 4       7 0         5 6   7
+     * </pre>
+     */
+    public static final int UHDR_IMG_FMT_32bppRGBA1010102 = 5;
+
+    // Fields describing the color primaries of the content
+    /**
+     * Unspecified color gamut
+     */
+    public static final int UHDR_CG_UNSPECIFIED = -1;
+
+    /**
+     * BT.709 color chromaticity coordinates with KR = 0.2126, KB = 0.0722
+     */
+    public static final int UHDR_CG_BT709 = 0;
+
+    /**
+     * Display P3 color chromaticity coordinates with KR = 0.22897, KB = 0.07929
+     */
+    public static final int UHDR_CG_DISPlAY_P3 = 1;
+
+    /**
+     * BT.2020 color chromaticity coordinates with KR = 0.2627, KB = 0.0593
+     */
+    public static final int UHDR_CG_BT2100 = 2;
+
+    // Fields describing the opto-electronic transfer function of the content
+    /**
+     * Unspecified color transfer
+     */
+    public static final int UHDR_CT_UNSPECIFIED = -1;
+
+    /**
+     * Linear transfer characteristic curve
+     */
+    public static final int UHDR_CT_LINEAR = 0;
+
+    /**
+     * hybrid-log-gamma transfer function
+     */
+    public static final int UHDR_CT_HLG = 1;
+
+    /**
+     * PQ transfer function
+     */
+    public static final int UHDR_CT_PQ = 2;
+
+    /**
+     * sRGB transfer function
+     */
+    public static final int UHDR_CT_SRGB = 3;
+
+    // Fields describing the data range of the content
+    /**
+     * Unspecified color range
+     */
+    public static final int UHDR_CR_UNSPECIFIED = -1;
+
+    /**
+     * Limited range. Y component values range from [16 - 235] * pow(2, (bpc - 8)) and Cb, Cr
+     * component values range from [16 - 240] * pow(2, (bpc - 8)). Here, bpc is bits per channel
+     */
+    public static final int UHDR_CR_LIMITED_RANGE = 0;
+
+    /**
+     * Full range. Y component values range from [0 - 255] * pow(2, (bpc - 8)) and Cb, Cr
+     * component values range from [0 - 255] * pow(2, (bpc - 8)). Here, bpc is bits per channel
+     */
+    public static final int UHDR_CR_FULL_RANGE = 1;
+
+    // Fields describing the technology associated with the content
+    /**
+     * Hdr rendition of an image
+     */
+    public static final int UHDR_HDR_IMG = 0;
+
+    /**
+     * Sdr rendition of an image
+     */
+    public static final int UHDR_SDR_IMG = 1;
+
+    /**
+     * Base rendition of an ultrahdr image
+     */
+    public static final int UHDR_BASE_IMG = 2;
+
+    /**
+     * GainMap rendition of an ultrahdr image
+     */
+    public static final int UHDR_GAIN_MAP_IMG = 3;
+
+    private UltraHDRCommon() {
+    }
+
+    /**
+     * Get library version in string format
+     * @return version string
+     */
+    public static String getVersionString() {
+        return getVersionStringNative();
+    }
+
+    /**
+     * Get library version
+     * @return version
+     */
+    public static int getVersion() {
+        return getVersionNative();
+    }
+
+    private static native String getVersionStringNative();
+
+    private static native int getVersionNative();
+
+    static {
+        System.loadLibrary("uhdrjni");
+    }
+}
diff --git a/java/com/google/media/codecs/ultrahdr/UltraHDRDecoder.java b/java/com/google/media/codecs/ultrahdr/UltraHDRDecoder.java
new file mode 100644
index 0000000..f383cdc
--- /dev/null
+++ b/java/com/google/media/codecs/ultrahdr/UltraHDRDecoder.java
@@ -0,0 +1,592 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.google.media.codecs.ultrahdr;
+
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_CG_UNSPECIFIED;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_CR_UNSPECIFIED;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_CT_UNSPECIFIED;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_32bppRGBA1010102;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_32bppRGBA8888;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_64bppRGBAHalfFloat;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_8bppYCbCr400;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_UNSPECIFIED;
+
+import java.io.IOException;
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
+
+/**
+ * Ultra HDR decoding utility class.
+ */
+public class UltraHDRDecoder implements AutoCloseable {
+
+    /**
+     * GainMap Metadata Descriptor
+     */
+    public static class GainMapMetadata {
+        public float maxContentBoost;
+        public float minContentBoost;
+        public float gamma;
+        public float offsetSdr;
+        public float offsetHdr;
+        public float hdrCapacityMin;
+        public float hdrCapacityMax;
+
+        public GainMapMetadata() {
+            this.maxContentBoost = 1.0f;
+            this.minContentBoost = 1.0f;
+            this.gamma = 1.0f;
+            this.offsetSdr = 0.0f;
+            this.offsetHdr = 0.0f;
+            this.hdrCapacityMin = 1.0f;
+            this.hdrCapacityMax = 1.0f;
+        }
+
+        public GainMapMetadata(float maxContentBoost, float minContentBoost, float gamma,
+                float offsetSdr, float offsetHdr, float hdrCapacityMin, float hdrCapacityMax) {
+            this.maxContentBoost = maxContentBoost;
+            this.minContentBoost = minContentBoost;
+            this.gamma = gamma;
+            this.offsetSdr = offsetSdr;
+            this.offsetHdr = offsetHdr;
+            this.hdrCapacityMin = hdrCapacityMin;
+            this.hdrCapacityMax = hdrCapacityMax;
+        }
+    }
+
+    /**
+     * Raw Image Descriptor.
+     */
+    public static abstract class RawImage {
+        public byte[] nativeOrderBuffer;
+        public int fmt;
+        public int cg;
+        public int ct;
+        public int range;
+        public int w;
+        public int h;
+        public int stride;
+
+        public RawImage(byte[] nativeOrderBuffer, int fmt, int cg, int ct, int range, int w, int h,
+                int stride) {
+            this.nativeOrderBuffer = nativeOrderBuffer;
+            this.fmt = fmt;
+            this.cg = cg;
+            this.ct = ct;
+            this.range = range;
+            this.w = w;
+            this.h = h;
+            this.stride = stride;
+        }
+    }
+
+    /**
+     * To represent packed pixel formats with 4 bytes-per-sample.
+     */
+    public static class RawImage32 extends RawImage {
+        public int[] data;
+
+        public RawImage32(byte[] nativeOrderBuffer, int fmt, int cg, int ct, int range, int w,
+                int h, int[] data, int stride) {
+            super(nativeOrderBuffer, fmt, cg, ct, range, w, h, stride);
+            this.data = data;
+        }
+    }
+
+    /**
+     * To represent packed pixel formats with 8 bits-per-sample.
+     */
+    public static class RawImage8 extends RawImage {
+        public byte[] data;
+
+        public RawImage8(byte[] nativeOrderBuffer, int fmt, int cg, int ct, int range, int w, int h,
+                byte[] data, int stride) {
+            super(nativeOrderBuffer, fmt, cg, ct, range, w, h, stride);
+            this.data = data;
+        }
+    }
+
+    /**
+     * To represent packed pixel formats with 8 bytes-per-sample.
+     */
+    public static class RawImage64 extends RawImage {
+        public long[] data;
+
+        public RawImage64(byte[] nativeOrderBuffer, int fmt, int cg, int ct, int range, int w,
+                int h, long[] data, int stride) {
+            super(nativeOrderBuffer, fmt, cg, ct, range, w, h, stride);
+            this.data = data;
+        }
+    }
+
+    // APIs
+
+    /**
+     * Checks if the current input image is a valid ultrahdr image
+     *
+     * @param data The compressed image data.
+     * @param size The size of the compressed image data.
+     * @return TRUE if the input data has a primary image, gainmap image and gainmap metadata.
+     * FALSE if any errors are encountered during parsing process or if the image does not have
+     * primary image or gainmap image or gainmap metadata
+     * @throws IOException If parameters are not valid exception is thrown.
+     */
+    public static boolean isUHDRImage(byte[] data, int size) throws IOException {
+        if (data == null) {
+            throw new IOException("received null for image data handle");
+        }
+        if (size <= 0) {
+            throw new IOException("received invalid compressed image size, size is <= 0");
+        }
+        return (isUHDRImageNative(data, size) == 1);
+    }
+
+    /**
+     * Create and Initialize an ultrahdr decoder instance
+     *
+     * @throws IOException If the codec cannot be created then exception is thrown
+     */
+    public UltraHDRDecoder() throws IOException {
+        handle = 0;
+        init();
+        resetState();
+    }
+
+    /**
+     * Release current ultrahdr decoder instance
+     *
+     * @throws Exception during release, if errors are seen, then exception is thrown
+     */
+    @Override
+    public void close() throws Exception {
+        destroy();
+        resetState();
+    }
+
+    /**
+     * Add compressed image data to be decoded to the decoder context. The function goes through
+     * all the arguments and checks for their sanity. If no anomalies are seen then the image
+     * info is added to internal list. Repeated calls to this function will replace the old entry
+     * with the current.
+     *
+     * @param data          The compressed image data.
+     * @param size          The size of the compressed image data.
+     * @param colorGamut    color standard of the image. Certain image formats are capable of
+     *                      storing color standard information in the bitstream, for instance heif.
+     *                      Some formats are not capable of storing the same. This field can be used
+     *                      as an additional source to convey this information. If unknown, this can
+     *                      be set to {@link UltraHDRCommon#UHDR_CG_UNSPECIFIED}.
+     * @param colorTransfer color transfer of the image. Just like colorGamut parameter, this
+     *                      field can be used as an additional source to convey image transfer
+     *                      characteristics. If unknown, this can be set to
+     *                      {@link UltraHDRCommon#UHDR_CT_UNSPECIFIED}.
+     * @param range         color range. Just like colorGamut parameter, this field can be used
+     *                      as an additional source to convey color range characteristics. If
+     *                      unknown, this can be set to {@link UltraHDRCommon#UHDR_CR_UNSPECIFIED}.
+     * @throws IOException If parameters are not valid or current decoder instance is not valid
+     *                     or current decoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setCompressedImage(byte[] data, int size, int colorGamut, int colorTransfer,
+            int range) throws IOException {
+        if (data == null) {
+            throw new IOException("received null for image data handle");
+        }
+        if (size <= 0) {
+            throw new IOException("received invalid compressed image size, size is <= 0");
+        }
+        setCompressedImageNative(data, size, colorGamut, colorTransfer, range);
+    }
+
+    /**
+     * Set output image color format
+     *
+     * @param fmt output image color format. Supported values are
+     *            {@link UltraHDRCommon#UHDR_IMG_FMT_32bppRGBA8888},
+     *            {@link UltraHDRCommon#UHDR_IMG_FMT_32bppRGBA1010102},
+     *            {@link UltraHDRCommon#UHDR_IMG_FMT_64bppRGBAHalfFloat}
+     * @throws IOException If parameters are not valid or current decoder instance is not valid
+     *                     or current decoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setOutputFormat(int fmt) throws IOException {
+        setOutputFormatNative(fmt);
+    }
+
+    /**
+     * Set output image color transfer characteristics. It should be noted that not all
+     * combinations of output color format and output transfer function are supported.
+     * {@link UltraHDRCommon#UHDR_CT_SRGB} output color transfer shall be paired with
+     * {@link UltraHDRCommon#UHDR_IMG_FMT_32bppRGBA8888} only. {@link UltraHDRCommon#UHDR_CT_HLG}
+     * and {@link UltraHDRCommon#UHDR_CT_PQ} shall be paired with
+     * {@link UltraHDRCommon#UHDR_IMG_FMT_32bppRGBA1010102}.
+     * {@link UltraHDRCommon#UHDR_CT_LINEAR} shall be paired with
+     * {@link UltraHDRCommon#UHDR_IMG_FMT_64bppRGBAHalfFloat}.
+     *
+     * @param ct output image color transfer.
+     * @throws IOException If parameters are not valid or current decoder instance is not valid
+     *                     or current decoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setColorTransfer(int ct) throws IOException {
+        setColorTransferNative(ct);
+    }
+
+    /**
+     * Set output display's HDR capacity. Value MUST be in linear scale. This value determines
+     * the weight by which the gain map coefficients are scaled. If no value is configured, no
+     * weight is applied to gainmap image.
+     *
+     * @param displayBoost hdr capacity of target display. Any real number >= 1.0f
+     * @throws IOException If parameters are not valid or current decoder instance is not valid
+     *                     or current decoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setMaxDisplayBoost(float displayBoost) throws IOException {
+        setMaxDisplayBoostNative(displayBoost);
+    }
+
+    /**
+     * Enable/Disable GPU acceleration. If enabled, certain operations (if possible) of uhdr
+     * decode will be offloaded to GPU.
+     * <p>
+     * NOTE: It is entirely possible for this API to have no effect on the decode operation
+     *
+     * @param enable enable/disable gpu acceleration
+     * @throws IOException If current decoder instance is not valid or current decoder instance
+     *                     is not suitable for configuration exception is thrown.
+     */
+    public void enableGpuAcceleration(int enable) throws IOException {
+        enableGpuAccelerationNative(enable);
+    }
+
+    /**
+     * This function parses the bitstream that is registered with the decoder context and makes
+     * image information available to the client via getter functions. It does not decompress the
+     * image. That is done by {@link UltraHDRDecoder#decode()}.
+     *
+     * @throws IOException during parsing process if any errors are seen exception is thrown
+     */
+    public void probe() throws IOException {
+        probeNative();
+    }
+
+    /**
+     * Get base image width
+     *
+     * @return base image width
+     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
+     *                     process if any errors are seen exception is thrown
+     */
+    public int getImageWidth() throws IOException {
+        return getImageWidthNative();
+    }
+
+    /**
+     * Get base image height
+     *
+     * @return base image height
+     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
+     *                     process if any errors are seen exception is thrown
+     */
+    public int getImageHeight() throws IOException {
+        return getImageHeightNative();
+    }
+
+    /**
+     * Get gainmap image width
+     *
+     * @return gainmap image width
+     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
+     *                     process if any errors are seen exception is thrown
+     */
+    public int getGainMapWidth() throws IOException {
+        return getGainMapWidthNative();
+    }
+
+    /**
+     * Get gainmap image height
+     *
+     * @return gainmap image height
+     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
+     *                     process if any errors are seen exception is thrown
+     */
+    public int getGainMapHeight() throws IOException {
+        return getGainMapHeightNative();
+    }
+
+    /**
+     * Get exif information
+     *
+     * @return A byte array containing the EXIF metadata
+     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
+     *                     process if any errors are seen exception is thrown
+     */
+    public byte[] getExif() throws IOException {
+        return getExifNative();
+    }
+
+    /**
+     * Get icc information
+     *
+     * @return A byte array containing the icc data
+     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
+     *                     process if any errors are seen exception is thrown
+     */
+    public byte[] getIcc() throws IOException {
+        return getIccNative();
+    }
+
+    /**
+     * Get base image (compressed)
+     *
+     * @return A byte array containing the base image data
+     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
+     *                     process if any errors are seen exception is thrown
+     */
+    public byte[] getBaseImage() throws IOException {
+        return getBaseImageNative();
+    }
+
+    /**
+     * Get gain map image (compressed)
+     *
+     * @return A byte array containing the gain map image data
+     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
+     *                     process if any errors are seen exception is thrown
+     */
+    public byte[] getGainMapImage() throws IOException {
+        return getGainMapImageNative();
+    }
+
+    /**
+     * Get gain map metadata
+     *
+     * @return gainmap metadata descriptor
+     * @throws IOException If {@link UltraHDRDecoder#probe()} is not yet called or during parsing
+     *                     process if any errors are seen exception is thrown
+     */
+    public GainMapMetadata getGainmapMetadata() throws IOException {
+        getGainmapMetadataNative();
+        return new GainMapMetadata(maxContentBoost, minContentBoost, gamma, offsetSdr,
+                offsetHdr, hdrCapacityMin, hdrCapacityMax);
+    }
+
+    /**
+     * Decode process call.
+     * <p>
+     * After initializing the decode context, call to this function will submit data for
+     * encoding. If the call is successful, the decode output is stored internally and is
+     * accessible via {@link UltraHDRDecoder#getDecodedImage()}.
+     *
+     * @throws IOException If any errors are encountered during the decoding process, exception is
+     *                     thrown
+     */
+    public void decode() throws IOException {
+        decodeNative();
+    }
+
+    /**
+     * Get decoded image data
+     *
+     * @return Raw image descriptor containing decoded image data
+     * @throws IOException If {@link UltraHDRDecoder#decode()} is not called or decoding process
+     *                     is not successful, exception is thrown
+     */
+    public RawImage getDecodedImage() throws IOException {
+        if (decodedDataNativeOrder == null) {
+            decodedDataNativeOrder = getDecodedImageNative();
+        }
+        if (imgFormat == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+            if (decodedDataInt64 == null) {
+                ByteBuffer data = ByteBuffer.wrap(decodedDataNativeOrder);
+                data.order(ByteOrder.nativeOrder());
+                decodedDataInt64 = new long[imgWidth * imgHeight];
+                data.asLongBuffer().get(decodedDataInt64);
+            }
+            return new RawImage64(decodedDataNativeOrder, imgFormat, imgGamut, imgTransfer,
+                    imgRange, imgWidth, imgHeight, decodedDataInt64, imgStride);
+        } else if (imgFormat == UHDR_IMG_FMT_32bppRGBA8888
+                || imgFormat == UHDR_IMG_FMT_32bppRGBA1010102) {
+            if (decodedDataInt32 == null) {
+                ByteBuffer data = ByteBuffer.wrap(decodedDataNativeOrder);
+                data.order(ByteOrder.nativeOrder());
+                decodedDataInt32 = new int[imgWidth * imgHeight];
+                data.asIntBuffer().get(decodedDataInt32);
+            }
+            return new RawImage32(decodedDataNativeOrder, imgFormat, imgGamut, imgTransfer,
+                    imgRange, imgWidth, imgHeight, decodedDataInt32, imgStride);
+        }
+        return null;
+    }
+
+    /**
+     * Get decoded gainmap image data
+     *
+     * @return Raw image descriptor containing decoded gainmap image data
+     * @throws IOException If {@link UltraHDRDecoder#decode()} is not called or decoding process
+     *                     is not successful, exception is thrown
+     */
+    public RawImage getDecodedGainMapImage() throws IOException {
+        if (decodedGainMapDataNativeOrder == null) {
+            decodedGainMapDataNativeOrder = getDecodedGainMapImageNative();
+        }
+        if (gainmapFormat == UHDR_IMG_FMT_32bppRGBA8888) {
+            if (decodedGainMapDataInt32 == null) {
+                ByteBuffer data = ByteBuffer.wrap(decodedGainMapDataNativeOrder);
+                data.order(ByteOrder.nativeOrder());
+                decodedGainMapDataInt32 = new int[imgWidth * imgHeight];
+                data.asIntBuffer().get(decodedGainMapDataInt32);
+            }
+            return new RawImage32(decodedGainMapDataNativeOrder, imgFormat, imgGamut, imgTransfer,
+                    imgRange, imgWidth, imgHeight, decodedGainMapDataInt32, imgStride);
+        } else if (imgFormat == UHDR_IMG_FMT_8bppYCbCr400) {
+            return new RawImage8(decodedGainMapDataNativeOrder, gainmapFormat, UHDR_CG_UNSPECIFIED,
+                    UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, gainmapWidth, gainmapHeight,
+                    decodedGainMapDataNativeOrder, gainmapStride);
+        }
+        return null;
+    }
+
+    /**
+     * Reset decoder instance. Clears all previous settings and resets to default state and ready
+     * for re-initialization and usage.
+     *
+     * @throws IOException If the current decoder instance is not valid exception is thrown.
+     */
+    public void reset() throws IOException {
+        resetNative();
+        resetState();
+    }
+
+    private void resetState() {
+        maxContentBoost = 1.0f;
+        minContentBoost = 1.0f;
+        gamma = 1.0f;
+        offsetSdr = 0.0f;
+        offsetHdr = 0.0f;
+        hdrCapacityMin = 1.0f;
+        hdrCapacityMax = 1.0f;
+
+        decodedDataNativeOrder = null;
+        decodedDataInt32 = null;
+        decodedDataInt64 = null;
+        imgWidth = -1;
+        imgHeight = -1;
+        imgStride = 0;
+        imgFormat = UHDR_IMG_FMT_UNSPECIFIED;
+        imgGamut = UHDR_CG_UNSPECIFIED;
+        imgTransfer = UHDR_CG_UNSPECIFIED;
+        imgRange = UHDR_CG_UNSPECIFIED;
+
+        decodedGainMapDataNativeOrder = null;
+        decodedGainMapDataInt32 = null;
+        gainmapWidth = -1;
+        gainmapHeight = -1;
+        gainmapStride = 0;
+        gainmapFormat = UHDR_IMG_FMT_UNSPECIFIED;
+    }
+
+    private static native int isUHDRImageNative(byte[] data, int size) throws IOException;
+
+    private native void init() throws IOException;
+
+    private native void destroy() throws IOException;
+
+    private native void setCompressedImageNative(byte[] data, int size, int colorGamut,
+            int colorTransfer, int range) throws IOException;
+
+    private native void setOutputFormatNative(int fmt) throws IOException;
+
+    private native void setColorTransferNative(int ct) throws IOException;
+
+    private native void setMaxDisplayBoostNative(float displayBoost) throws IOException;
+
+    private native void enableGpuAccelerationNative(int enable) throws IOException;
+
+    private native void probeNative() throws IOException;
+
+    private native int getImageWidthNative() throws IOException;
+
+    private native int getImageHeightNative() throws IOException;
+
+    private native int getGainMapWidthNative() throws IOException;
+
+    private native int getGainMapHeightNative() throws IOException;
+
+    private native byte[] getExifNative() throws IOException;
+
+    private native byte[] getIccNative() throws IOException;
+
+    private native byte[] getBaseImageNative() throws IOException;
+
+    private native byte[] getGainMapImageNative() throws IOException;
+
+    private native void getGainmapMetadataNative() throws IOException;
+
+    private native void decodeNative() throws IOException;
+
+    private native byte[] getDecodedImageNative() throws IOException;
+
+    private native byte[] getDecodedGainMapImageNative() throws IOException;
+
+    private native void resetNative() throws IOException;
+
+    /**
+     * Decoder handle. Filled by {@link UltraHDRDecoder#init()}
+     */
+    private long handle;
+
+    /**
+     * gainmap metadata fields. Filled by {@link UltraHDRDecoder#getGainmapMetadataNative()}
+     */
+    private float maxContentBoost;
+    private float minContentBoost;
+    private float gamma;
+    private float offsetSdr;
+    private float offsetHdr;
+    private float hdrCapacityMin;
+    private float hdrCapacityMax;
+
+    /**
+     * decoded image fields. Filled by {@link UltraHDRDecoder#getDecodedImageNative()}
+     */
+    private byte[] decodedDataNativeOrder;
+    private int[] decodedDataInt32;
+    private long[] decodedDataInt64;
+    private int imgWidth;
+    private int imgHeight;
+    private int imgStride;
+    private int imgFormat;
+    private int imgGamut;
+    private int imgTransfer;
+    private int imgRange;
+
+    /**
+     * decoded image fields. Filled by {@link UltraHDRDecoder#getDecodedGainMapImageNative()}
+     */
+    private byte[] decodedGainMapDataNativeOrder;
+    private int[] decodedGainMapDataInt32;
+    private int gainmapWidth;
+    private int gainmapHeight;
+    private int gainmapStride;
+    private int gainmapFormat;
+
+    static {
+        System.loadLibrary("uhdrjni");
+    }
+}
diff --git a/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java b/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java
new file mode 100644
index 0000000..e297d56
--- /dev/null
+++ b/java/com/google/media/codecs/ultrahdr/UltraHDREncoder.java
@@ -0,0 +1,506 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+package com.google.media.codecs.ultrahdr;
+
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_12bppYCbCr420;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_24bppYCbCrP010;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_32bppRGBA1010102;
+import static com.google.media.codecs.ultrahdr.UltraHDRCommon.UHDR_IMG_FMT_32bppRGBA8888;
+
+import java.io.IOException;
+
+/**
+ * Ultra HDR encoding utility class.
+ */
+public class UltraHDREncoder implements AutoCloseable {
+
+    // Fields describing the compression technology used to encode the content
+    /**
+     * Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using jpeg
+     */
+    public static final int UHDR_CODEC_JPG = 0;
+
+    /**
+     * Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using heif
+     */
+    public static final int UHDR_CODEC_HEIF = 1;
+
+    /**
+     * Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using avif
+     */
+    public static final int UHDR_CODEC_AVIF = 2;
+
+    // Fields describing the encoder tuning configurations
+    /**
+     * Tune encoder settings for best performance
+     */
+    public static final int UHDR_USAGE_REALTIME = 0;
+
+    /**
+     * Tune encoder settings for best quality
+     */
+    public static final int UHDR_USAGE_BEST_QUALITY = 1;
+
+    // APIs
+
+    /**
+     * Create and Initialize an ultrahdr encoder instance
+     *
+     * @throws IOException If the codec cannot be created then exception is thrown
+     */
+    public UltraHDREncoder() throws IOException {
+        handle = 0;
+        init();
+    }
+
+    /**
+     * Release current ultrahdr encoder instance
+     *
+     * @throws Exception During release, if errors are seen, then exception is thrown
+     */
+    @Override
+    public void close() throws Exception {
+        destroy();
+    }
+
+    /**
+     * Add raw image info to encoder context. This interface is used for adding 32 bits-per-pixel
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
+     * @param intent        {@link UltraHDRCommon#UHDR_HDR_IMG} for hdr intent,
+     *                      {@link UltraHDRCommon#UHDR_SDR_IMG} for sdr intent
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setRawImage(int[] rgbBuff, int width, int height, int rgbStride, int colorGamut,
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
+        if (colorFormat != UHDR_IMG_FMT_32bppRGBA8888
+                && colorFormat != UHDR_IMG_FMT_32bppRGBA1010102) {
+            throw new IOException("received unsupported color format. supported color formats are"
+                    + "{UHDR_IMG_FMT_32bppRGBA8888, UHDR_IMG_FMT_32bppRGBA1010102}");
+        }
+        setRawImageNative(rgbBuff, width, height, rgbStride, colorGamut, colorTransfer, colorRange,
+                colorFormat, intent);
+    }
+
+    /**
+     * Add raw image info to encoder context. This interface is used for adding 16 bits-per-sample
+     * pixel formats. The function goes through all the arguments and checks for their sanity. If
+     * no anomalies are seen then the image info is added to internal list. Repeated calls to
+     * this function will replace the old entry with the current.
+     *
+     * @param yBuff         luma buffer handle
+     * @param uvBuff        Chroma buffer handle
+     * @param width         image width
+     * @param height        image height
+     * @param yStride       luma buffer stride
+     * @param uvStride      Chroma buffer stride
+     * @param colorGamut    color gamut of input image
+     * @param colorTransfer color transfer of input image
+     * @param colorRange    color range of input image
+     * @param colorFormat   color format of input image
+     * @param intent        {@link UltraHDRCommon#UHDR_HDR_IMG} for hdr intent
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setRawImage(short[] yBuff, short[] uvBuff, int width, int height,
+            int yStride, int uvStride, int colorGamut, int colorTransfer,
+            int colorRange, int colorFormat, int intent) throws IOException {
+        if (yBuff == null || uvBuff == null) {
+            throw new IOException("received null for image data handle");
+        }
+        if (width <= 0 || height <= 0) {
+            throw new IOException("received bad width and/or height, width or height is <= 0");
+        }
+        if (yStride <= 0 || uvStride <= 0) {
+            throw new IOException("received bad stride, stride is <= 0");
+        }
+        if (colorFormat != UHDR_IMG_FMT_24bppYCbCrP010) {
+            throw new IOException("received unsupported color format. supported color formats are"
+                    + "{UHDR_IMG_FMT_24bppYCbCrP010}");
+        }
+        setRawImageNative(yBuff, uvBuff, width, height, yStride, uvStride, colorGamut,
+                colorTransfer, colorRange, colorFormat, intent);
+    }
+
+    /**
+     * Add raw image info to encoder context. This interface is used for adding 8 bits-per-sample
+     * pixel formats. The function goes through all the arguments and checks for their sanity. If
+     * no anomalies are seen then the image info is added to internal list. Repeated calls to
+     * this function will replace the old entry with the current.
+     *
+     * @param yBuff         luma buffer handle
+     * @param uBuff         Cb buffer handle
+     * @param vBuff         Cr buffer handle
+     * @param width         image width
+     * @param height        image height
+     * @param yStride       luma buffer stride
+     * @param uStride       Cb buffer stride
+     * @param vStride       Cr buffer stride
+     * @param colorGamut    color gamut of input image
+     * @param colorTransfer color transfer of input image
+     * @param colorRange    color range of input image
+     * @param colorFormat   color format of input image
+     * @param intent        {@link UltraHDRCommon#UHDR_SDR_IMG} for sdr intent
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setRawImage(byte[] yBuff, byte[] uBuff, byte[] vBuff, int width, int height,
+            int yStride, int uStride, int vStride, int colorGamut, int colorTransfer,
+            int colorRange, int colorFormat, int intent) throws IOException {
+        if (yBuff == null || uBuff == null || vBuff == null) {
+            throw new IOException("received null for image data handle");
+        }
+        if (width <= 0 || height <= 0) {
+            throw new IOException("received bad width and/or height, width or height is <= 0");
+        }
+        if (yStride <= 0 || uStride <= 0 || vStride <= 0) {
+            throw new IOException("received bad stride, stride is <= 0");
+        }
+        if (colorFormat != UHDR_IMG_FMT_12bppYCbCr420) {
+            throw new IOException("received unsupported color format. supported color formats are"
+                    + "{UHDR_IMG_FMT_12bppYCbCr420}");
+        }
+        setRawImageNative(yBuff, uBuff, vBuff, width, height, yStride, uStride, vStride, colorGamut,
+                colorTransfer, colorRange, colorFormat, intent);
+    }
+
+    /**
+     * Add compressed image info to encoder context. The function goes through all the arguments
+     * and checks for their sanity. If no anomalies are seen then the image info is added to
+     * internal list. Repeated calls to this function will replace the old entry with the current.
+     * <p>
+     * If both {@link UltraHDREncoder#setRawImage} and this function are called during a session
+     * for the same intent, it is assumed that raw image descriptor and compressed image
+     * descriptor are relatable via compress <-> decompress process.
+     *
+     * @param data          byteArray containing compressed image data
+     * @param size          compressed image size
+     * @param colorGamut    color standard of the image. Certain image formats are capable of
+     *                      storing color standard information in the bitstream, for instance heif.
+     *                      Some formats are not capable of storing the same. This field can be used
+     *                      as an additional source to convey this information. If unknown, this can
+     *                      be set to {@link UltraHDRCommon#UHDR_CG_UNSPECIFIED}.
+     * @param colorTransfer color transfer of the image. Just like colorGamut parameter, this
+     *                      field can be used as an additional source to convey image transfer
+     *                      characteristics. If unknown, this can be set to
+     *                      {@link UltraHDRCommon#UHDR_CT_UNSPECIFIED}.
+     * @param range         color range. Just like colorGamut parameter, this field can be used
+     *                      as an additional source to convey color range characteristics. If
+     *                      unknown, this can be set to {@link UltraHDRCommon#UHDR_CR_UNSPECIFIED}.
+     * @param intent        {@link UltraHDRCommon#UHDR_HDR_IMG} for hdr intent,
+     *                      {@link UltraHDRCommon#UHDR_SDR_IMG} for sdr intent,
+     *                      {@link UltraHDRCommon#UHDR_BASE_IMG} for base image intent
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setCompressedImage(byte[] data, int size, int colorGamut, int colorTransfer,
+            int range, int intent) throws IOException {
+        if (data == null) {
+            throw new IOException("received null for image data handle");
+        }
+        if (size <= 0) {
+            throw new IOException("received invalid compressed image size, size is <= 0");
+        }
+        setCompressedImageNative(data, size, colorGamut, colorTransfer, range, intent);
+    }
+
+    /**
+     * Add gain map image descriptor and gainmap metadata info that was used to generate the
+     * aforth gainmap image to encoder context. The function internally goes through all the
+     * arguments and checks for their sanity. If no anomalies are seen then the image is added to
+     * internal list. Repeated calls to this function will replace the old entry with the current.
+     * <p>
+     * NOTE: There are apis that allow configuration of gainmap info separately. For instance
+     * {@link UltraHDREncoder#setGainMapGamma(float)},
+     * {@link UltraHDREncoder#setGainMapScaleFactor(int)}, ... They have no effect on the
+     * information that is configured via this api. The information configured here is treated as
+     * immutable and used as-is in encoding scenario where gainmap computations are intended to
+     * be by-passed.
+     *
+     * @param data            byteArray containing compressed image data
+     * @param size            compressed image size
+     * @param maxContentBoost value to control how much brighter an image can get, when shown on
+     *                        an HDR display, relative to the SDR rendition. This is constant for
+     *                        a given image. Value MUST be in linear scale.
+     * @param minContentBoost value to control how much darker an image can get, when shown on
+     *                        an HDR display, relative to the SDR rendition. This is constant for
+     *                        a given image. Value MUST be in linear scale.
+     * @param gainmapGamma    Encoding gamma of gainmap image.
+     * @param offsetSdr       The offset to apply to the SDR pixel values during gainmap
+     *                        generation and application.
+     * @param offsetHdr       The offset to apply to the HDR pixel values during gainmap
+     *                        generation and application.
+     * @param hdrCapacityMin  Minimum display boost value for which the map is applied completely.
+     *                        Value MUST be in linear scale.
+     * @param hdrCapacityMax  Maximum display boost value for which the map is applied completely.
+     *                        Value MUST be in linear scale.
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setGainMapImageInfo(byte[] data, int size, float maxContentBoost,
+            float minContentBoost, float gainmapGamma, float offsetSdr, float offsetHdr,
+            float hdrCapacityMin, float hdrCapacityMax) throws IOException {
+        if (data == null) {
+            throw new IOException("received null for image data handle");
+        }
+        if (size <= 0) {
+            throw new IOException("received invalid compressed image size, size is <= 0");
+        }
+        setGainMapImageInfoNative(data, size, maxContentBoost, minContentBoost, gainmapGamma,
+                offsetSdr, offsetHdr, hdrCapacityMin, hdrCapacityMax);
+    }
+
+    /**
+     * Set Exif data that needs to be inserted in the output compressed stream. This function
+     * does not generate or validate exif data on its own. It merely copies the supplied
+     * information into the bitstream.
+     *
+     * @param data exif data
+     * @param size exif size
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setExifData(byte[] data, int size) throws IOException {
+        if (data == null) {
+            throw new IOException("received null for exif data handle");
+        }
+        if (size <= 0) {
+            throw new IOException("received invalid compressed image size, size is <= 0");
+        }
+        setExifDataNative(data, size);
+    }
+
+    /**
+     * Set quality factor for compressing base image and/or gainmap image. Default configured
+     * quality factor of base image and gainmap image are 95 and 95 respectively.
+     *
+     * @param qualityFactor Any integer in range [0 - 100]
+     * @param intent        {@link UltraHDRCommon#UHDR_BASE_IMG} or
+     *                      {@link UltraHDRCommon#UHDR_GAIN_MAP_IMG}
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setQualityFactor(int qualityFactor, int intent) throws IOException {
+        setQualityFactorNative(qualityFactor, intent);
+    }
+
+    /**
+     * Enable/Disable multi-channel gainmap. By default, multi-channel gainmap is enabled.
+     *
+     * @param enable if true, multi-channel gainmap is enabled, else, single-channel gainmap is
+     *               enabled
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setMultiChannelGainMapEncoding(boolean enable) throws IOException {
+        setMultiChannelGainMapEncodingNative(enable);
+    }
+
+    /**
+     * Set gain map scaling factor. The encoding process allows signalling a downscaled gainmap
+     * image instead of full resolution. This setting controls the factor by which the renditions
+     * are downscaled. For instance, gain_map_scale_factor = 2 implies gainmap_image_width =
+     * primary_image_width / 2 and gainmap image height = primary_image_height / 2.
+     * Default gain map scaling factor is 1.
+     * <p>
+     * NOTE: This has no effect on base image rendition. Base image is signalled in full resolution
+     * always.
+     *
+     * @param scaleFactor gain map scale factor. Any integer in range (0, 128]
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setGainMapScaleFactor(int scaleFactor) throws IOException {
+        setGainMapScaleFactorNative(scaleFactor);
+    }
+
+    /**
+     * Set encoding gamma of gainmap image. For multi-channel gainmap image, set gamma is used
+     * for gamma correction of all planes separately. Default gamma value is 1.0.
+     *
+     * @param gamma gamma of gainmap image. Any positive real number
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setGainMapGamma(float gamma) throws IOException {
+        setGainMapGammaNative(gamma);
+    }
+
+    /**
+     * Set encoding preset. Tunes the encoder configurations for performance or quality. Default
+     * configuration is {@link UltraHDREncoder#UHDR_USAGE_BEST_QUALITY}.
+     *
+     * @param preset encoding preset. {@link UltraHDREncoder#UHDR_USAGE_REALTIME} for best
+     *               performance {@link UltraHDREncoder#UHDR_USAGE_BEST_QUALITY} for best quality
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setEncPreset(int preset) throws IOException {
+        setEncPresetNative(preset);
+    }
+
+    /**
+     * Set output image compression format. Selects the compression format for encoding base
+     * image and gainmap image. Default configuration is {@link UltraHDREncoder#UHDR_CODEC_JPG}.
+     *
+     * @param mediaType output image compression format. Supported values are
+     *                  {@link UltraHDREncoder#UHDR_CODEC_JPG}
+     * @throws IOException If parameters are not valid or current encoder instance is not valid
+     *                     or current encoder instance is not suitable for configuration
+     *                     exception is thrown
+     */
+    public void setOutputFormat(int mediaType) throws IOException {
+        setOutputFormatNative(mediaType);
+    }
+
+    /**
+     * Set min max content boost. This configuration is treated as a recommendation by the
+     * library. It is entirely possible for the library to use a different set of values. Value
+     * MUST be in linear scale.
+     *
+     * @param minContentBoost min content boost. Any positive real number
+     * @param maxContentBoost max content boost. Any positive real numer >= minContentBoost
+     * @throws IOException If parameters are not valid or current encoder instance
+     *                     is not valid or current encoder instance is not suitable
+     *                     for configuration exception is thrown
+     */
+    public void setMinMaxContentBoost(float minContentBoost, float maxContentBoost)
+            throws IOException {
+        setMinMaxContentBoostNative(minContentBoost, maxContentBoost);
+    }
+
+    /**
+     * Encode process call.
+     * <p>
+     * After initializing the encoder context, call to this function will submit data for
+     * encoding. If the call is successful, the encoded output is stored internally and is
+     * accessible via {@link UltraHDREncoder#getOutput()}.
+     *
+     * @throws IOException If any errors are encountered during the encoding process, exception is
+     *                     thrown
+     */
+    public void encode() throws IOException {
+        encodeNative();
+    }
+
+    /**
+     * Get encoded ultra hdr stream
+     *
+     * @return byte array contains encoded output data
+     * @throws IOException If {@link UltraHDREncoder#encode()} is not called or encoding process
+     *                     is not successful, exception is thrown
+     */
+    public byte[] getOutput() throws IOException {
+        return getOutputNative();
+    }
+
+    /**
+     * Reset encoder instance. Clears all previous settings and resets to default state and ready
+     * for re-initialization and usage.
+     *
+     * @throws IOException If the current encoder instance is not valid exception is thrown.
+     */
+    public void reset() throws IOException {
+        resetNative();
+    }
+
+    private native void init() throws IOException;
+
+    private native void destroy() throws IOException;
+
+    private native void setRawImageNative(int[] rgbBuff, int width, int height, int rgbStride,
+            int colorGamut, int colorTransfer, int colorRange, int colorFormat, int intent)
+            throws IOException;
+
+    private native void setRawImageNative(short[] yBuff, short[] uvBuff, int width, int height,
+            int yStride, int uvStride, int colorGamut, int colorTransfer, int colorRange,
+            int colorFormat, int intent) throws IOException;
+
+    private native void setRawImageNative(byte[] yBuff, byte[] uBuff, byte[] vBuff, int width,
+            int height, int yStride, int uStride, int vStride, int colorGamut, int colorTransfer,
+            int colorRange, int colorFormat, int intent) throws IOException;
+
+    private native void setCompressedImageNative(byte[] data, int size, int colorGamut,
+            int colorTransfer, int range, int intent) throws IOException;
+
+    private native void setGainMapImageInfoNative(byte[] data, int size, float maxContentBoost,
+            float minContentBoost, float gainmapGamma, float offsetSdr, float offsetHdr,
+            float hdrCapacityMin, float hdrCapacityMax) throws IOException;
+
+    private native void setExifDataNative(byte[] data, int size) throws IOException;
+
+    private native void setQualityFactorNative(int qualityFactor, int intent) throws IOException;
+
+    private native void setMultiChannelGainMapEncodingNative(boolean enable) throws IOException;
+
+    private native void setGainMapScaleFactorNative(int scaleFactor) throws IOException;
+
+    private native void setGainMapGammaNative(float gamma) throws IOException;
+
+    private native void setEncPresetNative(int preset) throws IOException;
+
+    private native void setOutputFormatNative(int mediaType) throws IOException;
+
+    private native void setMinMaxContentBoostNative(float minContentBoost,
+            float maxContentBoost) throws IOException;
+
+    private native void encodeNative() throws IOException;
+
+    private native byte[] getOutputNative() throws IOException;
+
+    private native void resetNative() throws IOException;
+
+    /**
+     * Encoder handle. Filled by {@link UltraHDREncoder#init()}
+     */
+    private long handle;
+
+    static {
+        System.loadLibrary("uhdrjni");
+    }
+}
diff --git a/java/jni/com_google_media_codecs_ultrahdr_UltraHDRCommon.h b/java/jni/com_google_media_codecs_ultrahdr_UltraHDRCommon.h
new file mode 100644
index 0000000..2537686
--- /dev/null
+++ b/java/jni/com_google_media_codecs_ultrahdr_UltraHDRCommon.h
@@ -0,0 +1,75 @@
+/* DO NOT EDIT THIS FILE - it is machine generated */
+#include <jni.h>
+/* Header for class com_google_media_codecs_ultrahdr_UltraHDRCommon */
+
+#ifndef _Included_com_google_media_codecs_ultrahdr_UltraHDRCommon
+#define _Included_com_google_media_codecs_ultrahdr_UltraHDRCommon
+#ifdef __cplusplus
+extern "C" {
+#endif
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_UNSPECIFIED
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_UNSPECIFIED -1L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_24bppYCbCrP010
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_24bppYCbCrP010 0L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_12bppYCbCr420
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_12bppYCbCr420 1L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_8bppYCbCr400
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_8bppYCbCr400 2L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_32bppRGBA8888
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_32bppRGBA8888 3L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_64bppRGBAHalfFloat
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_64bppRGBAHalfFloat 4L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_32bppRGBA1010102
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_IMG_FMT_32bppRGBA1010102 5L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_UNSPECIFIED
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_UNSPECIFIED -1L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_BT709
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_BT709 0L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_DISPlAY_P3
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_DISPlAY_P3 1L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_BT2100
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CG_BT2100 2L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_UNSPECIFIED
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_UNSPECIFIED -1L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_LINEAR
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_LINEAR 0L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_HLG
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_HLG 1L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_PQ
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_PQ 2L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_SRGB
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CT_SRGB 3L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CR_UNSPECIFIED
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CR_UNSPECIFIED -1L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CR_LIMITED_RANGE
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CR_LIMITED_RANGE 0L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CR_FULL_RANGE
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_CR_FULL_RANGE 1L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_HDR_IMG
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_HDR_IMG 0L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_SDR_IMG
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_SDR_IMG 1L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_BASE_IMG
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_BASE_IMG 2L
+#undef com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_GAIN_MAP_IMG
+#define com_google_media_codecs_ultrahdr_UltraHDRCommon_UHDR_GAIN_MAP_IMG 3L
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRCommon
+ * Method:    getVersionStringNative
+ * Signature: ()Ljava/lang/String;
+ */
+JNIEXPORT jstring JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRCommon_getVersionStringNative
+  (JNIEnv *, jclass);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRCommon
+ * Method:    getVersionNative
+ * Signature: ()I
+ */
+JNIEXPORT jint JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRCommon_getVersionNative
+  (JNIEnv *, jclass);
+
+#ifdef __cplusplus
+}
+#endif
+#endif
diff --git a/java/jni/com_google_media_codecs_ultrahdr_UltraHDRDecoder.h b/java/jni/com_google_media_codecs_ultrahdr_UltraHDRDecoder.h
new file mode 100644
index 0000000..d6a4d3e
--- /dev/null
+++ b/java/jni/com_google_media_codecs_ultrahdr_UltraHDRDecoder.h
@@ -0,0 +1,189 @@
+/* DO NOT EDIT THIS FILE - it is machine generated */
+#include <jni.h>
+/* Header for class com_google_media_codecs_ultrahdr_UltraHDRDecoder */
+
+#ifndef _Included_com_google_media_codecs_ultrahdr_UltraHDRDecoder
+#define _Included_com_google_media_codecs_ultrahdr_UltraHDRDecoder
+#ifdef __cplusplus
+extern "C" {
+#endif
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    isUHDRImageNative
+ * Signature: ([BI)I
+ */
+JNIEXPORT jint JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_isUHDRImageNative
+  (JNIEnv *, jclass, jbyteArray, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    init
+ * Signature: ()V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_init
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    destroy
+ * Signature: ()V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_destroy
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    setCompressedImageNative
+ * Signature: ([BIIII)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setCompressedImageNative
+  (JNIEnv *, jobject, jbyteArray, jint, jint, jint, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    setOutputFormatNative
+ * Signature: (I)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setOutputFormatNative
+  (JNIEnv *, jobject, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    setColorTransferNative
+ * Signature: (I)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setColorTransferNative
+  (JNIEnv *, jobject, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    setMaxDisplayBoostNative
+ * Signature: (F)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setMaxDisplayBoostNative
+  (JNIEnv *, jobject, jfloat);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    enableGpuAccelerationNative
+ * Signature: (I)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_enableGpuAccelerationNative
+  (JNIEnv *, jobject, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    probeNative
+ * Signature: ()V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_probeNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getImageWidthNative
+ * Signature: ()I
+ */
+JNIEXPORT jint JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getImageWidthNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getImageHeightNative
+ * Signature: ()I
+ */
+JNIEXPORT jint JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getImageHeightNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getGainMapWidthNative
+ * Signature: ()I
+ */
+JNIEXPORT jint JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainMapWidthNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getGainMapHeightNative
+ * Signature: ()I
+ */
+JNIEXPORT jint JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainMapHeightNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getExifNative
+ * Signature: ()[B
+ */
+JNIEXPORT jbyteArray JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getExifNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getIccNative
+ * Signature: ()[B
+ */
+JNIEXPORT jbyteArray JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getIccNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getBaseImageNative
+ * Signature: ()[B
+ */
+JNIEXPORT jbyteArray JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getBaseImageNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getGainMapImageNative
+ * Signature: ()[B
+ */
+JNIEXPORT jbyteArray JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainMapImageNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getGainmapMetadataNative
+ * Signature: ()V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainmapMetadataNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    decodeNative
+ * Signature: ()V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_decodeNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getDecodedImageNative
+ * Signature: ()[B
+ */
+JNIEXPORT jbyteArray JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getDecodedImageNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    getDecodedGainMapImageNative
+ * Signature: ()[B
+ */
+JNIEXPORT jbyteArray JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getDecodedGainMapImageNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDRDecoder
+ * Method:    resetNative
+ * Signature: ()V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_resetNative
+  (JNIEnv *, jobject);
+
+#ifdef __cplusplus
+}
+#endif
+#endif
diff --git a/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h b/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h
new file mode 100644
index 0000000..bd55537
--- /dev/null
+++ b/java/jni/com_google_media_codecs_ultrahdr_UltraHDREncoder.h
@@ -0,0 +1,167 @@
+/* DO NOT EDIT THIS FILE - it is machine generated */
+#include <jni.h>
+/* Header for class com_google_media_codecs_ultrahdr_UltraHDREncoder */
+
+#ifndef _Included_com_google_media_codecs_ultrahdr_UltraHDREncoder
+#define _Included_com_google_media_codecs_ultrahdr_UltraHDREncoder
+#ifdef __cplusplus
+extern "C" {
+#endif
+#undef com_google_media_codecs_ultrahdr_UltraHDREncoder_UHDR_CODEC_JPG
+#define com_google_media_codecs_ultrahdr_UltraHDREncoder_UHDR_CODEC_JPG 0L
+#undef com_google_media_codecs_ultrahdr_UltraHDREncoder_UHDR_CODEC_HEIF
+#define com_google_media_codecs_ultrahdr_UltraHDREncoder_UHDR_CODEC_HEIF 1L
+#undef com_google_media_codecs_ultrahdr_UltraHDREncoder_UHDR_CODEC_AVIF
+#define com_google_media_codecs_ultrahdr_UltraHDREncoder_UHDR_CODEC_AVIF 2L
+#undef com_google_media_codecs_ultrahdr_UltraHDREncoder_UHDR_USAGE_REALTIME
+#define com_google_media_codecs_ultrahdr_UltraHDREncoder_UHDR_USAGE_REALTIME 0L
+#undef com_google_media_codecs_ultrahdr_UltraHDREncoder_UHDR_USAGE_BEST_QUALITY
+#define com_google_media_codecs_ultrahdr_UltraHDREncoder_UHDR_USAGE_BEST_QUALITY 1L
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    init
+ * Signature: ()V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_init
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    destroy
+ * Signature: ()V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_destroy
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setRawImageNative
+ * Signature: ([IIIIIIIII)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3IIIIIIIII
+  (JNIEnv *, jobject, jintArray, jint, jint, jint, jint, jint, jint, jint, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setRawImageNative
+ * Signature: ([S[SIIIIIIIII)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3S_3SIIIIIIIII
+  (JNIEnv *, jobject, jshortArray, jshortArray, jint, jint, jint, jint, jint, jint, jint, jint, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setRawImageNative
+ * Signature: ([B[B[BIIIIIIIIII)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3B_3B_3BIIIIIIIIII
+  (JNIEnv *, jobject, jbyteArray, jbyteArray, jbyteArray, jint, jint, jint, jint, jint, jint, jint, jint, jint, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setCompressedImageNative
+ * Signature: ([BIIIII)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setCompressedImageNative
+  (JNIEnv *, jobject, jbyteArray, jint, jint, jint, jint, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setGainMapImageInfoNative
+ * Signature: ([BIFFFFFFF)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapImageInfoNative
+  (JNIEnv *, jobject, jbyteArray, jint, jfloat, jfloat, jfloat, jfloat, jfloat, jfloat, jfloat);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setExifDataNative
+ * Signature: ([BI)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setExifDataNative
+  (JNIEnv *, jobject, jbyteArray, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setQualityFactorNative
+ * Signature: (II)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setQualityFactorNative
+  (JNIEnv *, jobject, jint, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setMultiChannelGainMapEncodingNative
+ * Signature: (Z)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setMultiChannelGainMapEncodingNative
+  (JNIEnv *, jobject, jboolean);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setGainMapScaleFactorNative
+ * Signature: (I)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapScaleFactorNative
+  (JNIEnv *, jobject, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setGainMapGammaNative
+ * Signature: (F)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapGammaNative
+  (JNIEnv *, jobject, jfloat);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setEncPresetNative
+ * Signature: (I)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setEncPresetNative
+  (JNIEnv *, jobject, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setOutputFormatNative
+ * Signature: (I)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setOutputFormatNative
+  (JNIEnv *, jobject, jint);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    setMinMaxContentBoostNative
+ * Signature: (FF)V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setMinMaxContentBoostNative
+  (JNIEnv *, jobject, jfloat, jfloat);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    encodeNative
+ * Signature: ()V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_encodeNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    getOutputNative
+ * Signature: ()[B
+ */
+JNIEXPORT jbyteArray JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_getOutputNative
+  (JNIEnv *, jobject);
+
+/*
+ * Class:     com_google_media_codecs_ultrahdr_UltraHDREncoder
+ * Method:    resetNative
+ * Signature: ()V
+ */
+JNIEXPORT void JNICALL Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_resetNative
+  (JNIEnv *, jobject);
+
+#ifdef __cplusplus
+}
+#endif
+#endif
diff --git a/java/jni/ultrahdr-jni.cpp b/java/jni/ultrahdr-jni.cpp
new file mode 100644
index 0000000..c545462
--- /dev/null
+++ b/java/jni/ultrahdr-jni.cpp
@@ -0,0 +1,680 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include <cstring>
+#include <string>
+
+#include "com_google_media_codecs_ultrahdr_UltraHDRCommon.h"
+#include "com_google_media_codecs_ultrahdr_UltraHDRDecoder.h"
+#include "com_google_media_codecs_ultrahdr_UltraHDREncoder.h"
+#include "ultrahdr_api.h"
+
+static_assert(sizeof(void *) <= sizeof(jlong),
+              "unsupported architecture, size of pointer address exceeds jlong storage");
+
+#define RET_IF_TRUE(cond, exception_class, msg)      \
+  {                                                  \
+    if ((cond) || env->ExceptionCheck()) {           \
+      env->ExceptionClear();                         \
+      auto _clazz = env->FindClass(exception_class); \
+      if (!_clazz || env->ExceptionCheck()) {        \
+        return;                                      \
+      }                                              \
+      env->ThrowNew(_clazz, msg);                    \
+      return;                                        \
+    }                                                \
+  }
+
+#define GET_HANDLE()                                                                         \
+  jclass clazz = env->GetObjectClass(thiz);                                                  \
+  RET_IF_TRUE(clazz == nullptr, "java/io/IOException", "GetObjectClass returned with error") \
+  jfieldID fid = env->GetFieldID(clazz, "handle", "J");                                      \
+  RET_IF_TRUE(fid == nullptr, "java/io/IOException",                                         \
+              "GetFieldID for field 'handle' returned with error")                           \
+  jlong handle = env->GetLongField(thiz, fid);
+
+#define RET_VAL_IF_TRUE(cond, exception_class, msg, val) \
+  {                                                      \
+    if ((cond) || env->ExceptionCheck()) {               \
+      env->ExceptionClear();                             \
+      auto _clazz = env->FindClass(exception_class);     \
+      if (!_clazz || env->ExceptionCheck()) {            \
+        return (val);                                    \
+      }                                                  \
+      env->ThrowNew(_clazz, msg);                        \
+      return (val);                                      \
+    }                                                    \
+  }
+
+#define GET_HANDLE_VAL(val)                                                                      \
+  jclass clazz = env->GetObjectClass(thiz);                                                      \
+  RET_VAL_IF_TRUE(clazz == nullptr, "java/io/IOException", "GetObjectClass returned with error", \
+                  (val))                                                                         \
+  jfieldID fid = env->GetFieldID(clazz, "handle", "J");                                          \
+  RET_VAL_IF_TRUE(fid == nullptr, "java/io/IOException",                                         \
+                  "GetFieldID for field 'handle' returned with error", (val))                    \
+  jlong handle = env->GetLongField(thiz, fid);
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_init(JNIEnv *env, jobject thiz) {
+  jclass clazz = env->GetObjectClass(thiz);
+  RET_IF_TRUE(clazz == nullptr, "java/io/IOException", "GetObjectClass returned with error")
+  jfieldID fid = env->GetFieldID(clazz, "handle", "J");
+  RET_IF_TRUE(fid == nullptr, "java/io/IOException",
+              "GetFieldID for field 'handle' returned with error")
+  uhdr_codec_private_t *handle = uhdr_create_encoder();
+  RET_IF_TRUE(handle == nullptr, "java/lang/OutOfMemoryError",
+              "Unable to allocate encoder instance")
+  env->SetLongField(thiz, fid, (jlong)handle);
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_destroy(JNIEnv *env, jobject thiz) {
+  GET_HANDLE()
+  if (!handle) {
+    uhdr_release_encoder((uhdr_codec_private_t *)handle);
+    env->SetLongField(thiz, fid, (jlong)0);
+  }
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3IIIIIIIII(
+    JNIEnv *env, jobject thiz, jintArray rgb_buff, jint width, jint height, jint rgb_stride,
+    jint color_gamut, jint color_transfer, jint color_range, jint color_format, jint intent) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  jsize length = env->GetArrayLength(rgb_buff);
+  RET_IF_TRUE(length < height * rgb_stride, "java/io/IOException",
+              "compressed image luma byteArray size is less than required size")
+  jint *rgbBody = env->GetIntArrayElements(rgb_buff, nullptr);
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
+  env->ReleaseIntArrayElements(rgb_buff, rgbBody, 0);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_enc_set_raw_image() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3S_3SIIIIIIIII(
+    JNIEnv *env, jobject thiz, jshortArray y_buff, jshortArray uv_buff, jint width, jint height,
+    jint y_stride, jint uv_stride, jint color_gamut, jint color_transfer, jint color_range,
+    jint color_format, jint intent) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  jsize length = env->GetArrayLength(y_buff);
+  RET_IF_TRUE(length < height * y_stride, "java/io/IOException",
+              "compressed image luma byteArray size is less than required size")
+  length = env->GetArrayLength(uv_buff);
+  RET_IF_TRUE(length < height * uv_stride / 2, "java/io/IOException",
+              "compressed image cb byteArray size is less than required size")
+  jshort *lumaBody = env->GetShortArrayElements(y_buff, nullptr);
+  jshort *chromaBody = env->GetShortArrayElements(uv_buff, nullptr);
+  uhdr_raw_image_t img{(uhdr_img_fmt_t)color_format,
+                       (uhdr_color_gamut_t)color_gamut,
+                       (uhdr_color_transfer_t)color_transfer,
+                       (uhdr_color_range_t)color_range,
+                       (unsigned int)width,
+                       (unsigned int)height,
+                       {lumaBody, chromaBody, nullptr},
+                       {(unsigned int)y_stride, (unsigned int)uv_stride, 0u}};
+  auto status =
+      uhdr_enc_set_raw_image((uhdr_codec_private_t *)handle, &img, (uhdr_img_label_t)intent);
+  env->ReleaseShortArrayElements(y_buff, lumaBody, 0);
+  env->ReleaseShortArrayElements(uv_buff, chromaBody, 0);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_enc_set_raw_image() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setRawImageNative___3B_3B_3BIIIIIIIIII(
+    JNIEnv *env, jobject thiz, jbyteArray y_buff, jbyteArray u_buff, jbyteArray v_buff, jint width,
+    jint height, jint y_stride, jint u_stride, jint v_stride, jint color_gamut, jint color_transfer,
+    jint color_range, jint color_format, jint intent) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  jsize length = env->GetArrayLength(y_buff);
+  RET_IF_TRUE(length < height * y_stride, "java/io/IOException",
+              "compressed image luma byteArray size is less than required size")
+  length = env->GetArrayLength(u_buff);
+  RET_IF_TRUE(length < height * u_stride / 4, "java/io/IOException",
+              "compressed image cb byteArray size is less than required size")
+  length = env->GetArrayLength(v_buff);
+  RET_IF_TRUE(length < height * v_stride / 4, "java/io/IOException",
+              "compressed image cb byteArray size is less than required size")
+  jbyte *lumaBody = env->GetByteArrayElements(y_buff, nullptr);
+  jbyte *cbBody = env->GetByteArrayElements(u_buff, nullptr);
+  jbyte *crBody = env->GetByteArrayElements(v_buff, nullptr);
+  uhdr_raw_image_t img{(uhdr_img_fmt_t)color_format,
+                       (uhdr_color_gamut_t)color_gamut,
+                       (uhdr_color_transfer_t)color_transfer,
+                       (uhdr_color_range_t)color_range,
+                       (unsigned int)width,
+                       (unsigned int)height,
+                       {lumaBody, cbBody, crBody},
+                       {(unsigned int)y_stride, (unsigned int)u_stride, (unsigned int)v_stride}};
+  auto status =
+      uhdr_enc_set_raw_image((uhdr_codec_private_t *)handle, &img, (uhdr_img_label_t)intent);
+  env->ReleaseByteArrayElements(y_buff, lumaBody, 0);
+  env->ReleaseByteArrayElements(u_buff, cbBody, 0);
+  env->ReleaseByteArrayElements(v_buff, crBody, 0);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_enc_set_raw_image() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setCompressedImageNative(
+    JNIEnv *env, jobject thiz, jbyteArray data, jint size, jint color_gamut, jint color_transfer,
+    jint range, jint intent) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  jsize length = env->GetArrayLength(data);
+  RET_IF_TRUE(length < size, "java/io/IOException",
+              "compressed image byteArray size is less than configured size")
+  jbyte *body = env->GetByteArrayElements(data, nullptr);
+  uhdr_compressed_image_t img{body,
+                              (unsigned int)size,
+                              (unsigned int)length,
+                              (uhdr_color_gamut_t)color_gamut,
+                              (uhdr_color_transfer_t)color_transfer,
+                              (uhdr_color_range_t)range};
+  auto status =
+      uhdr_enc_set_compressed_image((uhdr_codec_private_t *)handle, &img, (uhdr_img_label_t)intent);
+  env->ReleaseByteArrayElements(data, body, 0);
+  RET_IF_TRUE(
+      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+      status.has_detail ? status.detail : "uhdr_enc_set_compressed_image() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapImageInfoNative(
+    JNIEnv *env, jobject thiz, jbyteArray data, jint size, jfloat max_content_boost,
+    jfloat min_content_boost, jfloat gainmap_gamma, jfloat offset_sdr, jfloat offset_hdr,
+    jfloat hdr_capacity_min, jfloat hdr_capacity_max) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  jsize length = env->GetArrayLength(data);
+  RET_IF_TRUE(length < size, "java/io/IOException",
+              "compressed image byteArray size is less than configured size")
+  jbyte *body = env->GetByteArrayElements(data, nullptr);
+  uhdr_compressed_image_t img{body,
+                              (unsigned int)size,
+                              (unsigned int)length,
+                              UHDR_CG_UNSPECIFIED,
+                              UHDR_CT_UNSPECIFIED,
+                              UHDR_CR_UNSPECIFIED};
+  uhdr_gainmap_metadata_t metadata{max_content_boost, min_content_boost, gainmap_gamma,
+                                   offset_sdr,        offset_hdr,        hdr_capacity_min,
+                                   hdr_capacity_max};
+  auto status = uhdr_enc_set_gainmap_image((uhdr_codec_private_t *)handle, &img, &metadata);
+  env->ReleaseByteArrayElements(data, body, 0);
+  RET_IF_TRUE(
+      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+      status.has_detail ? status.detail : "uhdr_enc_set_gainmap_image() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setExifDataNative(JNIEnv *env, jobject thiz,
+                                                                        jbyteArray data,
+                                                                        jint size) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  jsize length = env->GetArrayLength(data);
+  RET_IF_TRUE(length < size, "java/io/IOException",
+              "compressed image byteArray size is less than configured size")
+  jbyte *body = env->GetByteArrayElements(data, nullptr);
+  uhdr_mem_block_t exif{body, (unsigned int)size, (unsigned int)length};
+  auto status = uhdr_enc_set_exif_data((uhdr_codec_private_t *)handle, &exif);
+  env->ReleaseByteArrayElements(data, body, 0);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_enc_set_exif_data() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setQualityFactorNative(JNIEnv *env,
+                                                                             jobject thiz,
+                                                                             jint quality_factor,
+                                                                             jint intent) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  auto status = uhdr_enc_set_quality((uhdr_codec_private_t *)handle, quality_factor,
+                                     (uhdr_img_label_t)intent);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_enc_set_quality() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setMultiChannelGainMapEncodingNative(
+    JNIEnv *env, jobject thiz, jboolean enable) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  auto status =
+      uhdr_enc_set_using_multi_channel_gainmap((uhdr_codec_private_t *)handle, enable ? 1 : 0);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail
+                                : "uhdr_enc_set_using_multi_channel_gainmap() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapScaleFactorNative(
+    JNIEnv *env, jobject thiz, jint scale_factor) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  auto status = uhdr_enc_set_gainmap_scale_factor((uhdr_codec_private_t *)handle, scale_factor);
+  RET_IF_TRUE(
+      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+      status.has_detail ? status.detail : "uhdr_enc_set_gainmap_scale_factor() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setGainMapGammaNative(JNIEnv *env,
+                                                                            jobject thiz,
+                                                                            jfloat gamma) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  auto status = uhdr_enc_set_gainmap_gamma((uhdr_codec_private_t *)handle, gamma);
+  RET_IF_TRUE(
+      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+      status.has_detail ? status.detail : "uhdr_enc_set_gainmap_gamma() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setEncPresetNative(JNIEnv *env, jobject thiz,
+                                                                         jint preset) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  auto status = uhdr_enc_set_preset((uhdr_codec_private_t *)handle, (uhdr_enc_preset_t)preset);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_enc_set_preset() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setOutputFormatNative(JNIEnv *env,
+                                                                            jobject thiz,
+                                                                            jint media_type) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  auto status =
+      uhdr_enc_set_output_format((uhdr_codec_private_t *)handle, (uhdr_codec_t)media_type);
+  RET_IF_TRUE(
+      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+      status.has_detail ? status.detail : "uhdr_enc_set_output_format() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_setMinMaxContentBoostNative(
+    JNIEnv *env, jobject thiz, jfloat min_content_boost, jfloat max_content_boost) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  auto status = uhdr_enc_set_min_max_content_boost((uhdr_codec_private_t *)handle,
+                                                   min_content_boost, max_content_boost);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail
+                                : "uhdr_enc_set_min_max_content_boost() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_encodeNative(JNIEnv *env, jobject thiz) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  auto status = uhdr_encode((uhdr_codec_private_t *)handle);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_encode() returned with error")
+}
+
+extern "C" JNIEXPORT jbyteArray JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_getOutputNative(JNIEnv *env, jobject thiz) {
+  GET_HANDLE_VAL(nullptr)
+  RET_VAL_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance", nullptr)
+  auto enc_output = uhdr_get_encoded_stream((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(enc_output == nullptr, "java/io/IOException",
+                  "no output returned, may be call to uhdr_encode() was not made or encountered "
+                  "error during encoding process.",
+                  nullptr)
+  jbyteArray output = env->NewByteArray(enc_output->data_sz);
+  RET_VAL_IF_TRUE(output == nullptr, "java/io/IOException", "failed to allocate storage for output",
+                  nullptr)
+  env->SetByteArrayRegion(output, 0, enc_output->data_sz, (jbyte *)enc_output->data);
+  return output;
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDREncoder_resetNative(JNIEnv *env, jobject thiz) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid encoder instance")
+  uhdr_reset_encoder((uhdr_codec_private_t *)handle);
+}
+
+extern "C" JNIEXPORT jint JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_isUHDRImageNative(JNIEnv *env, jclass clazz,
+                                                                        jbyteArray data,
+                                                                        jint size) {
+  jsize length = env->GetArrayLength(data);
+  RET_VAL_IF_TRUE(length < size, "java/io/IOException",
+                  "compressed image byteArray size is less than configured size", 0)
+  jbyte *body = env->GetByteArrayElements(data, nullptr);
+  auto status = is_uhdr_image(body, size);
+  env->ReleaseByteArrayElements(data, body, 0);
+  return status;
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_init(JNIEnv *env, jobject thiz) {
+  jclass clazz = env->GetObjectClass(thiz);
+  RET_IF_TRUE(clazz == nullptr, "java/io/IOException", "GetObjectClass returned with error")
+  jfieldID fid = env->GetFieldID(clazz, "handle", "J");
+  RET_IF_TRUE(fid == nullptr, "java/io/IOException",
+              "GetFieldID for field 'handle' returned with error")
+  uhdr_codec_private_t *handle = uhdr_create_decoder();
+  RET_IF_TRUE(handle == nullptr, "java/lang/OutOfMemoryError",
+              "Unable to allocate decoder instance")
+  env->SetLongField(thiz, fid, (jlong)handle);
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_destroy(JNIEnv *env, jobject thiz) {
+  GET_HANDLE()
+  if (!handle) {
+    uhdr_release_decoder((uhdr_codec_private *)handle);
+    env->SetLongField(thiz, fid, (jlong)0);
+  }
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setCompressedImageNative(
+    JNIEnv *env, jobject thiz, jbyteArray data, jint size, jint color_gamut, jint color_transfer,
+    jint range) {
+  RET_IF_TRUE(size < 0, "java/io/IOException", "invalid compressed image size")
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
+  jsize length = env->GetArrayLength(data);
+  RET_IF_TRUE(length < size, "java/io/IOException",
+              "compressed image byteArray size is less than configured size")
+  jbyte *body = env->GetByteArrayElements(data, nullptr);
+  uhdr_compressed_image_t img{body,
+                              (unsigned int)size,
+                              (unsigned int)length,
+                              (uhdr_color_gamut_t)color_gamut,
+                              (uhdr_color_transfer_t)color_transfer,
+                              (uhdr_color_range_t)range};
+  uhdr_error_info_t status = uhdr_dec_set_image((uhdr_codec_private_t *)handle, &img);
+  env->ReleaseByteArrayElements(data, body, 0);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_dec_set_image() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setOutputFormatNative(JNIEnv *env,
+                                                                            jobject thiz,
+                                                                            jint fmt) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
+  uhdr_error_info_t status =
+      uhdr_dec_set_out_img_format((uhdr_codec_private_t *)handle, (uhdr_img_fmt_t)fmt);
+  RET_IF_TRUE(
+      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+      status.has_detail ? status.detail : "uhdr_dec_set_out_img_format() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setColorTransferNative(JNIEnv *env,
+                                                                             jobject thiz,
+                                                                             jint ct) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
+  uhdr_error_info_t status =
+      uhdr_dec_set_out_color_transfer((uhdr_codec_private_t *)handle, (uhdr_color_transfer_t)ct);
+  RET_IF_TRUE(
+      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+      status.has_detail ? status.detail : "uhdr_dec_set_out_color_transfer() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_setMaxDisplayBoostNative(
+    JNIEnv *env, jobject thiz, jfloat display_boost) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
+  uhdr_error_info_t status =
+      uhdr_dec_set_out_max_display_boost((uhdr_codec_private_t *)handle, (float)display_boost);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail
+                                : "uhdr_dec_set_out_max_display_boost() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_enableGpuAccelerationNative(JNIEnv *env,
+                                                                                  jobject thiz,
+                                                                                  jint enable) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
+  uhdr_error_info_t status = uhdr_enable_gpu_acceleration((uhdr_codec_private_t *)handle, enable);
+  RET_IF_TRUE(
+      status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+      status.has_detail ? status.detail : "uhdr_enable_gpu_acceleration() returned with error")
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_probeNative(JNIEnv *env, jobject thiz) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
+  uhdr_error_info_t status = uhdr_dec_probe((uhdr_codec_private_t *)handle);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_dec_probe() returned with error")
+}
+
+extern "C" JNIEXPORT jint JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getImageWidthNative(JNIEnv *env,
+                                                                          jobject thiz) {
+  GET_HANDLE_VAL(-1)
+  auto val = uhdr_dec_get_image_width((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(val == -1, "java/io/IOException",
+                  "uhdr_dec_probe() is not yet called or it has returned with error", -1)
+  return val;
+}
+
+extern "C" JNIEXPORT jint JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getImageHeightNative(JNIEnv *env,
+                                                                           jobject thiz) {
+  GET_HANDLE_VAL(-1)
+  auto val = uhdr_dec_get_image_height((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(val == -1, "java/io/IOException",
+                  "uhdr_dec_probe() is not yet called or it has returned with error", -1)
+  return val;
+}
+
+extern "C" JNIEXPORT jint JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainMapWidthNative(JNIEnv *env,
+                                                                            jobject thiz) {
+  GET_HANDLE_VAL(-1)
+  auto val = uhdr_dec_get_gainmap_width((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(val == -1, "java/io/IOException",
+                  "uhdr_dec_probe() is not yet called or it has returned with error", -1)
+  return val;
+}
+
+extern "C" JNIEXPORT jint JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainMapHeightNative(JNIEnv *env,
+                                                                             jobject thiz) {
+  GET_HANDLE_VAL(-1)
+  auto val = uhdr_dec_get_gainmap_height((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(val == -1, "java/io/IOException",
+                  "uhdr_dec_probe() is not yet called or it has returned with error", -1)
+  return val;
+}
+
+extern "C" JNIEXPORT jbyteArray JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getExifNative(JNIEnv *env, jobject thiz) {
+  GET_HANDLE_VAL(nullptr)
+  uhdr_mem_block_t *exifData = uhdr_dec_get_exif((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(exifData == nullptr, "java/io/IOException",
+                  "uhdr_dec_probe() is not yet called or it has returned with error", nullptr)
+  jbyteArray data = env->NewByteArray(exifData->data_sz);
+  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
+  std::memcpy(dataptr, exifData->data, exifData->data_sz);
+  env->ReleaseByteArrayElements(data, dataptr, 0);
+  return data;
+}
+
+extern "C" JNIEXPORT jbyteArray JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getIccNative(JNIEnv *env, jobject thiz) {
+  GET_HANDLE_VAL(nullptr)
+  uhdr_mem_block_t *iccData = uhdr_dec_get_icc((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(iccData == nullptr, "java/io/IOException",
+                  "uhdr_dec_probe() is not yet called or it has returned with error", nullptr)
+  jbyteArray data = env->NewByteArray(iccData->data_sz);
+  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
+  std::memcpy(dataptr, iccData->data, iccData->data_sz);
+  env->ReleaseByteArrayElements(data, dataptr, 0);
+  return data;
+}
+
+extern "C" JNIEXPORT jbyteArray JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getBaseImageNative(JNIEnv *env,
+                                                                         jobject thiz) {
+  GET_HANDLE_VAL(nullptr)
+  uhdr_mem_block_t *baseImgData = uhdr_dec_get_base_image((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(baseImgData == nullptr, "java/io/IOException",
+                  "uhdr_dec_probe() is not yet called or it has returned with error", nullptr)
+  jbyteArray data = env->NewByteArray(baseImgData->data_sz);
+  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
+  std::memcpy(dataptr, baseImgData->data, baseImgData->data_sz);
+  env->ReleaseByteArrayElements(data, dataptr, 0);
+  return data;
+}
+
+extern "C" JNIEXPORT jbyteArray JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainMapImageNative(JNIEnv *env,
+                                                                            jobject thiz) {
+  GET_HANDLE_VAL(nullptr)
+  uhdr_mem_block_t *gainmapImgData = uhdr_dec_get_gainmap_image((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(gainmapImgData == nullptr, "java/io/IOException",
+                  "uhdr_dec_probe() is not yet called or it has returned with error", nullptr)
+  jbyteArray data = env->NewByteArray(gainmapImgData->data_sz);
+  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
+  std::memcpy(dataptr, gainmapImgData->data, gainmapImgData->data_sz);
+  env->ReleaseByteArrayElements(data, dataptr, 0);
+  return data;
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getGainmapMetadataNative(JNIEnv *env,
+                                                                               jobject thiz) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
+  uhdr_gainmap_metadata_t *gainmap_metadata =
+      uhdr_dec_get_gainmap_metadata((uhdr_codec_private_t *)handle);
+  RET_IF_TRUE(gainmap_metadata == nullptr, "java/io/IOException",
+              "uhdr_dec_probe() is not yet called or it has returned with error")
+#define SET_FLOAT_FIELD(name, val)                                    \
+  {                                                                   \
+    jfieldID fID = env->GetFieldID(clazz, name, "F");                 \
+    RET_IF_TRUE(fID == nullptr, "java/io/IOException",                \
+                "GetFieldID for field " #name " returned with error") \
+    env->SetFloatField(thiz, fID, (jfloat)val);                       \
+  }
+  SET_FLOAT_FIELD("maxContentBoost", gainmap_metadata->max_content_boost)
+  SET_FLOAT_FIELD("minContentBoost", gainmap_metadata->min_content_boost)
+  SET_FLOAT_FIELD("gamma", gainmap_metadata->gamma)
+  SET_FLOAT_FIELD("offsetSdr", gainmap_metadata->offset_sdr)
+  SET_FLOAT_FIELD("offsetHdr", gainmap_metadata->offset_hdr)
+  SET_FLOAT_FIELD("hdrCapacityMin", gainmap_metadata->hdr_capacity_min)
+  SET_FLOAT_FIELD("hdrCapacityMax", gainmap_metadata->hdr_capacity_max)
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_decodeNative(JNIEnv *env, jobject thiz) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
+  auto status = uhdr_decode((uhdr_codec_private_t *)handle);
+  RET_IF_TRUE(status.error_code != UHDR_CODEC_OK, "java/io/IOException",
+              status.has_detail ? status.detail : "uhdr_decode() returned with error")
+}
+
+extern "C" JNIEXPORT jbyteArray JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getDecodedImageNative(JNIEnv *env,
+                                                                            jobject thiz) {
+  GET_HANDLE_VAL(nullptr)
+  uhdr_raw_image_t *decodedImg = uhdr_get_decoded_image((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(decodedImg == nullptr, "java/io/IOException",
+                  "uhdr_decode() is not yet called or it has returned with error", nullptr)
+  int bpp = decodedImg->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ? 8 : 4;
+  jbyteArray data = env->NewByteArray(decodedImg->stride[UHDR_PLANE_PACKED] * decodedImg->h * bpp);
+  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
+  std::memcpy(dataptr, decodedImg->planes[UHDR_PLANE_PACKED],
+              decodedImg->stride[UHDR_PLANE_PACKED] * decodedImg->h * bpp);
+  env->ReleaseByteArrayElements(data, dataptr, 0);
+#define SET_INT_FIELD(name, val)                                                   \
+  {                                                                                \
+    jfieldID fID = env->GetFieldID(clazz, name, "I");                              \
+    RET_VAL_IF_TRUE(fID == nullptr, "java/io/IOException",                         \
+                    "GetFieldID for field " #name " returned with error", nullptr) \
+    env->SetIntField(thiz, fID, (jint)val);                                        \
+  }
+  SET_INT_FIELD("imgWidth", decodedImg->w)
+  SET_INT_FIELD("imgHeight", decodedImg->h)
+  SET_INT_FIELD("imgStride", decodedImg->stride[UHDR_PLANE_PACKED])
+  SET_INT_FIELD("imgFormat", decodedImg->fmt)
+  SET_INT_FIELD("imgGamut", decodedImg->cg)
+  SET_INT_FIELD("imgTransfer", decodedImg->ct)
+  SET_INT_FIELD("imgRange", decodedImg->range)
+  return data;
+}
+
+extern "C" JNIEXPORT jbyteArray JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_getDecodedGainMapImageNative(JNIEnv *env,
+                                                                                   jobject thiz) {
+  GET_HANDLE_VAL(nullptr)
+  uhdr_raw_image_t *gainmapImg = uhdr_get_decoded_gainmap_image((uhdr_codec_private_t *)handle);
+  RET_VAL_IF_TRUE(gainmapImg == nullptr, "java/io/IOException",
+                  "uhdr_decode() is not yet called or it has returned with error", nullptr)
+  int bpp = gainmapImg->fmt == UHDR_IMG_FMT_32bppRGBA8888 ? 4 : 1;
+  jbyteArray data = env->NewByteArray(gainmapImg->stride[UHDR_PLANE_PACKED] * gainmapImg->h * bpp);
+  jbyte *dataptr = env->GetByteArrayElements(data, nullptr);
+  std::memcpy(dataptr, gainmapImg->planes[UHDR_PLANE_PACKED],
+              gainmapImg->stride[UHDR_PLANE_PACKED] * gainmapImg->h * bpp);
+  env->ReleaseByteArrayElements(data, dataptr, 0);
+  SET_INT_FIELD("gainmapWidth", gainmapImg->w)
+  SET_INT_FIELD("gainmapHeight", gainmapImg->h)
+  SET_INT_FIELD("gainmapStride", gainmapImg->stride[UHDR_PLANE_PACKED])
+  SET_INT_FIELD("gainmapFormat", gainmapImg->fmt)
+  return data;
+}
+
+extern "C" JNIEXPORT void JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRDecoder_resetNative(JNIEnv *env, jobject thiz) {
+  GET_HANDLE()
+  RET_IF_TRUE(handle == 0, "java/io/IOException", "invalid decoder instance")
+  uhdr_reset_decoder((uhdr_codec_private_t *)handle);
+}
+
+extern "C" JNIEXPORT jstring JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRCommon_getVersionStringNative(JNIEnv *env,
+                                                                            jclass clazz) {
+  std::string version{"v" UHDR_LIB_VERSION_STR};
+  return env->NewStringUTF(version.c_str());
+}
+
+extern "C" JNIEXPORT jint JNICALL
+Java_com_google_media_codecs_ultrahdr_UltraHDRCommon_getVersionNative(JNIEnv *env, jclass clazz) {
+  return UHDR_LIB_VERSION;
+}
diff --git a/java/metadata.cfg b/java/metadata.cfg
new file mode 100644
index 0000000..baf8f2f
--- /dev/null
+++ b/java/metadata.cfg
@@ -0,0 +1,7 @@
+--maxContentBoost 6.0
+--minContentBoost 1.0
+--gamma 1.0
+--offsetSdr 0.0
+--offsetHdr 0.0
+--hdrCapacityMin 1.0
+--hdrCapacityMax 6.0
diff --git a/lib/include/ultrahdr/dsp/arm/mem_neon.h b/lib/include/ultrahdr/dsp/arm/mem_neon.h
new file mode 100644
index 0000000..90657bf
--- /dev/null
+++ b/lib/include/ultrahdr/dsp/arm/mem_neon.h
@@ -0,0 +1,151 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#ifndef ULTRAHDR_DSP_ARM_MEM_NEON_H
+#define ULTRAHDR_DSP_ARM_MEM_NEON_H
+
+#include <arm_neon.h>
+
+#include "ultrahdr/ultrahdrcommon.h"
+
+namespace ultrahdr {
+
+// The multi-vector load/store intrinsics are well-supported on AArch64 but
+// only supported from GCC 14.1 (and not at all on Clang) for 32-bit platforms.
+#if __aarch64__ || (!__clang__ && __GNUC__ >= 14)
+#define COMPILER_SUPPORTS_LDST_MULTIPLE 1
+#endif
+
+static FORCE_INLINE uint8x16x2_t load_u8x16_x2(const uint8_t *src) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  return vld1q_u8_x2(src);
+#else
+  uint8x16x2_t res = {{vld1q_u8(src + 0), vld1q_u8(src + 16)}};
+  return res;
+#endif
+}
+
+static FORCE_INLINE uint8x16x4_t load_u8x16_x4(const uint8_t *src) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  return vld1q_u8_x4(src);
+#else
+  uint8x16x4_t res = {
+      {vld1q_u8(src + 0), vld1q_u8(src + 16), vld1q_u8(src + 32), vld1q_u8(src + 48)}};
+  return res;
+#endif
+}
+
+static FORCE_INLINE uint16x8x2_t load_u16x8_x2(const uint16_t *src) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  return vld1q_u16_x2(src);
+#else
+  uint16x8x2_t res = {{vld1q_u16(src + 0), vld1q_u16(src + 8)}};
+  return res;
+#endif
+}
+
+static FORCE_INLINE uint16x8x4_t load_u16x8_x4(const uint16_t *src) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  return vld1q_u16_x4(src);
+#else
+  uint16x8x4_t res = {
+      {vld1q_u16(src + 0), vld1q_u16(src + 8), vld1q_u16(src + 16), vld1q_u16(src + 24)}};
+  return res;
+#endif
+}
+
+static FORCE_INLINE uint32x4x2_t load_u32x4_x2(const uint32_t *src) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  return vld1q_u32_x2(src);
+#else
+  uint32x4x2_t res = {{vld1q_u32(src + 0), vld1q_u32(src + 4)}};
+  return res;
+#endif
+}
+
+static FORCE_INLINE uint32x4x4_t load_u32x4_x4(const uint32_t *src) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  return vld1q_u32_x4(src);
+#else
+  uint32x4x4_t res = {
+      {vld1q_u32(src + 0), vld1q_u32(src + 4), vld1q_u32(src + 8), vld1q_u32(src + 12)}};
+  return res;
+#endif
+}
+
+static FORCE_INLINE void store_u8x16_x2(uint8_t *dst, uint8x16x2_t a) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  vst1q_u8_x2(dst, a);
+#else
+  vst1q_u8(dst + 0, a.val[0]);
+  vst1q_u8(dst + 16, a.val[1]);
+#endif
+}
+
+static FORCE_INLINE void store_u8x16_x4(uint8_t *dst, uint8x16x4_t a) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  vst1q_u8_x4(dst, a);
+#else
+  vst1q_u8(dst + 0, a.val[0]);
+  vst1q_u8(dst + 16, a.val[1]);
+  vst1q_u8(dst + 32, a.val[2]);
+  vst1q_u8(dst + 48, a.val[3]);
+#endif
+}
+
+static FORCE_INLINE void store_u16x8_x2(uint16_t *dst, uint16x8x2_t a) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  vst1q_u16_x2(dst, a);
+#else
+  vst1q_u16(dst + 0, a.val[0]);
+  vst1q_u16(dst + 8, a.val[1]);
+#endif
+}
+
+static FORCE_INLINE void store_u16x8_x4(uint16_t *dst, uint16x8x4_t a) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  vst1q_u16_x4(dst, a);
+#else
+  vst1q_u16(dst + 0, a.val[0]);
+  vst1q_u16(dst + 8, a.val[1]);
+  vst1q_u16(dst + 16, a.val[2]);
+  vst1q_u16(dst + 24, a.val[3]);
+#endif
+}
+
+static FORCE_INLINE void store_u32x4_x2(uint32_t *dst, uint32x4x2_t a) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  vst1q_u32_x2(dst, a);
+#else
+  vst1q_u32(dst + 0, a.val[0]);
+  vst1q_u32(dst + 4, a.val[1]);
+#endif
+}
+
+static FORCE_INLINE void store_u32x4_x4(uint32_t *dst, uint32x4x4_t a) {
+#ifdef COMPILER_SUPPORTS_LDST_MULTIPLE
+  vst1q_u32_x4(dst, a);
+#else
+  vst1q_u32(dst + 0, a.val[0]);
+  vst1q_u32(dst + 4, a.val[1]);
+  vst1q_u32(dst + 8, a.val[2]);
+  vst1q_u32(dst + 12, a.val[3]);
+#endif
+}
+
+}  // namespace ultrahdr
+
+#endif  // ULTRAHDR_DSP_ARM_MEM_NEON_H
diff --git a/lib/include/ultrahdr/editorhelper.h b/lib/include/ultrahdr/editorhelper.h
index 3a83c9f..9ad1762 100644
--- a/lib/include/ultrahdr/editorhelper.h
+++ b/lib/include/ultrahdr/editorhelper.h
@@ -20,13 +20,6 @@
 #include "ultrahdr_api.h"
 #include "ultrahdr/ultrahdrcommon.h"
 
-// todo: move this to ultrahdr_api.h
-/*!\brief List of supported mirror directions */
-typedef enum uhdr_mirror_direction {
-  UHDR_MIRROR_VERTICAL,    /**< flip image over x axis */
-  UHDR_MIRROR_HORIZONTAL,  /**< flip image over y axis */
-} uhdr_mirror_direction_t; /**< alias for enum uhdr_mirror_direction */
-
 namespace ultrahdr {
 
 /*!\brief uhdr image effect descriptor */
@@ -126,16 +119,41 @@ extern void rotate_buffer_clockwise_neon(T* src_buffer, T* dst_buffer, int src_w
                                          int src_stride, int dst_stride, int degrees);
 #endif
 
+#ifdef UHDR_ENABLE_GLES
+
+std::unique_ptr<uhdr_raw_image_ext_t> apply_resize_gles(uhdr_raw_image_t* src, int dst_w, int dst_h,
+                                                        uhdr_opengl_ctxt* gl_ctxt,
+                                                        GLuint* srcTexture);
+
+std::unique_ptr<uhdr_raw_image_ext_t> apply_mirror_gles(ultrahdr::uhdr_mirror_effect_t* desc,
+                                                        uhdr_raw_image_t* src,
+                                                        uhdr_opengl_ctxt* gl_ctxt,
+                                                        GLuint* srcTexture);
+
+std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate_gles(ultrahdr::uhdr_rotate_effect_t* desc,
+                                                        uhdr_raw_image_t* src,
+                                                        uhdr_opengl_ctxt* gl_ctxt,
+                                                        GLuint* srcTexture);
+
+void apply_crop_gles(uhdr_raw_image_t* src, int left, int top, int wd, int ht,
+                     uhdr_opengl_ctxt* gl_ctxt, GLuint* srcTexture);
+#endif
+
 std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate(ultrahdr::uhdr_rotate_effect_t* desc,
-                                                   uhdr_raw_image_t* src);
+                                                   uhdr_raw_image_t* src, void* gl_ctxt = nullptr,
+                                                   void* texture = nullptr);
 
 std::unique_ptr<uhdr_raw_image_ext_t> apply_mirror(ultrahdr::uhdr_mirror_effect_t* desc,
-                                                   uhdr_raw_image_t* src);
+                                                   uhdr_raw_image_t* src, void* gl_ctxt = nullptr,
+                                                   void* texture = nullptr);
 
 std::unique_ptr<uhdr_raw_image_ext_t> apply_resize(ultrahdr::uhdr_resize_effect_t* desc,
-                                                   uhdr_raw_image* src, int dst_w, int dst_h);
+                                                   uhdr_raw_image* src, int dst_w, int dst_h,
+                                                   void* gl_ctxt = nullptr,
+                                                   void* texture = nullptr);
 
-void apply_crop(uhdr_raw_image_t* src, int left, int top, int wd, int ht);
+void apply_crop(uhdr_raw_image_t* src, int left, int top, int wd, int ht, void* gl_ctxt = nullptr,
+                void* texture = nullptr);
 
 }  // namespace ultrahdr
 
diff --git a/lib/include/ultrahdr/gainmapmath.h b/lib/include/ultrahdr/gainmapmath.h
index 85661aa..8e65ba1 100644
--- a/lib/include/ultrahdr/gainmapmath.h
+++ b/lib/include/ultrahdr/gainmapmath.h
@@ -20,16 +20,23 @@
 #include <array>
 #include <cmath>
 #include <cstring>
+#include <functional>
 
 #include "ultrahdr_api.h"
 #include "ultrahdr/ultrahdrcommon.h"
-#include "ultrahdr/ultrahdr.h"
 #include "ultrahdr/jpegr.h"
 
 #if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
 #include <arm_neon.h>
 #endif
 
+#define USE_SRGB_INVOETF_LUT 1
+#define USE_HLG_OETF_LUT 1
+#define USE_PQ_OETF_LUT 1
+#define USE_HLG_INVOETF_LUT 1
+#define USE_PQ_INVOETF_LUT 1
+#define USE_APPLY_GAIN_LUT 1
+
 #define CLIP3(x, min, max) ((x) < (min)) ? (min) : ((x) > (max)) ? (max) : (x)
 
 namespace ultrahdr {
@@ -45,9 +52,6 @@ const float kPqMaxNits = 10000.0f;
 
 static const float kMaxPixelFloat = 1.0f;
 
-// Describes the tone-mapping operation & gain-map encoding parameters.
-const float kHlgHeadroom = 1000.0f / 203.0f;
-
 struct Color {
   union {
     struct {
@@ -65,6 +69,9 @@ struct Color {
 
 typedef Color (*ColorTransformFn)(Color);
 typedef float (*ColorCalculationFn)(Color);
+typedef Color (*GetPixelFn)(uhdr_raw_image_t*, size_t, size_t);
+typedef Color (*SamplePixelFn)(uhdr_raw_image_t*, size_t, size_t, size_t);
+typedef void (*PutPixelFn)(uhdr_raw_image_t*, size_t, size_t, Color&);
 
 static inline float clampPixelFloat(float value) {
   return (value < 0.0f) ? 0.0f : (value > kMaxPixelFloat) ? kMaxPixelFloat : value;
@@ -176,21 +183,23 @@ inline uint16_t floatToHalf(float f) {
 constexpr int32_t kGainFactorPrecision = 10;
 constexpr int32_t kGainFactorNumEntries = 1 << kGainFactorPrecision;
 struct GainLUT {
-  GainLUT(ultrahdr_metadata_ptr metadata) {
+  GainLUT(uhdr_gainmap_metadata_ext_t* metadata) {
+    this->mGammaInv = 1.0f / metadata->gamma;
     for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
       float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
-      float logBoost = log2(metadata->minContentBoost) * (1.0f - value) +
-                       log2(metadata->maxContentBoost) * value;
+      float logBoost = log2(metadata->min_content_boost) * (1.0f - value) +
+                       log2(metadata->max_content_boost) * value;
       mGainTable[idx] = exp2(logBoost);
     }
   }
 
-  GainLUT(ultrahdr_metadata_ptr metadata, float displayBoost) {
-    float boostFactor = displayBoost > 0 ? displayBoost / metadata->maxContentBoost : 1.0f;
+  GainLUT(uhdr_gainmap_metadata_ext_t* metadata, float displayBoost) {
+    this->mGammaInv = 1.0f / metadata->gamma;
+    float boostFactor = displayBoost > 0 ? displayBoost / metadata->hdr_capacity_max : 1.0f;
     for (int32_t idx = 0; idx < kGainFactorNumEntries; idx++) {
       float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
-      float logBoost = log2(metadata->minContentBoost) * (1.0f - value) +
-                       log2(metadata->maxContentBoost) * value;
+      float logBoost = log2(metadata->min_content_boost) * (1.0f - value) +
+                       log2(metadata->max_content_boost) * value;
       mGainTable[idx] = exp2(logBoost * boostFactor);
     }
   }
@@ -198,6 +207,7 @@ struct GainLUT {
   ~GainLUT() {}
 
   float getGainFactor(float gain) {
+    if (mGammaInv != 1.0f) gain = pow(gain, mGammaInv);
     int32_t idx = static_cast<int32_t>(gain * (kGainFactorNumEntries - 1) + 0.5);
     // TODO() : Remove once conversion modules have appropriate clamping in place
     idx = CLIP3(idx, 0, kGainFactorNumEntries - 1);
@@ -206,6 +216,7 @@ struct GainLUT {
 
  private:
   float mGainTable[kGainFactorNumEntries];
+  float mGammaInv;
 };
 
 struct ShepardsIDW {
@@ -254,6 +265,20 @@ struct ShepardsIDW {
   void fillShepardsIDW(float* weights, int incR, int incB);
 };
 
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
 ////////////////////////////////////////////////////////////////////////////////
 // sRGB transformations
 // NOTE: sRGB has the same color primaries as BT.709, but different transfer
@@ -428,7 +453,47 @@ inline Color identityConversion(Color e) { return e; }
 /*
  * Get the conversion to apply to the HDR image for gain map generation
  */
-ColorTransformFn getHdrConversionFn(ultrahdr_color_gamut sdr_gamut, ultrahdr_color_gamut hdr_gamut);
+ColorTransformFn getGamutConversionFn(uhdr_color_gamut_t dst_gamut, uhdr_color_gamut_t src_gamut);
+
+/*
+ * Get the conversion to convert yuv to rgb
+ */
+ColorTransformFn getYuvToRgbFn(uhdr_color_gamut_t gamut);
+
+/*
+ * Get function to compute luminance
+ */
+ColorCalculationFn getLuminanceFn(uhdr_color_gamut_t gamut);
+
+/*
+ * Get function to linearize transfer characteristics
+ */
+ColorTransformFn getInverseOetfFn(uhdr_color_transfer_t transfer);
+
+/*
+ * Get function to read pixels from raw image for a given color format
+ */
+GetPixelFn getPixelFn(uhdr_img_fmt_t format);
+
+/*
+ * Get function to sample pixels from raw image for a given color format
+ */
+SamplePixelFn getSamplePixelFn(uhdr_img_fmt_t format);
+
+/*
+ * Get function to put pixels to raw image for a given color format
+ */
+PutPixelFn putPixelFn(uhdr_img_fmt_t format);
+
+/*
+ * Returns true if the pixel format is rgb
+ */
+bool isPixelFormatRgb(uhdr_img_fmt_t format);
+
+/*
+ * Get max display mastering luminance in nits
+ */
+float getMaxDisplayMasteringLuminance(uhdr_color_transfer_t transfer);
 
 /*
  * Convert between YUV encodings, according to ITU-R BT.709-6, ITU-R BT.601-7, and ITU-R BT.2100-2.
@@ -460,10 +525,12 @@ extern const int16_t kYuv2100To601_coeffs_neon[8];
  */
 int16x8x3_t yuvConversion_neon(uint8x8_t y, int16x8_t u, int16x8_t v, int16x8_t coeffs);
 
-void transformYuv420_neon(jr_uncompressed_ptr image, const int16_t* coeffs_ptr);
+void transformYuv420_neon(uhdr_raw_image_t* image, const int16_t* coeffs_ptr);
 
-status_t convertYuv_neon(jr_uncompressed_ptr image, ultrahdr_color_gamut src_encoding,
-                         ultrahdr_color_gamut dst_encoding);
+void transformYuv444_neon(uhdr_raw_image_t* image, const int16_t* coeffs_ptr);
+
+uhdr_error_info_t convertYuv_neon(uhdr_raw_image_t* image, uhdr_color_gamut_t src_encoding,
+                                  uhdr_color_gamut_t dst_encoding);
 #endif
 
 /*
@@ -471,87 +538,82 @@ status_t convertYuv_neon(jr_uncompressed_ptr image, ultrahdr_color_gamut src_enc
  *
  * Apply the transformation by determining transformed YUV for each of the 4 Y + 1 UV; each Y gets
  * this result, and UV gets the averaged result.
- *
- * The chroma channels should be less than or equal to half the image's width and height
- * respectively, since input is 4:2:0 subsampled.
  */
-void transformYuv420(jr_uncompressed_ptr image, const std::array<float, 9>& coeffs);
+void transformYuv420(uhdr_raw_image_t* image, const std::array<float, 9>& coeffs);
+
+/*
+ * Performs a color gamut transformation on an entire YUV444 image.
+ */
+void transformYuv444(uhdr_raw_image_t* image, const std::array<float, 9>& coeffs);
 
 ////////////////////////////////////////////////////////////////////////////////
 // Gain map calculations
 
 /*
  * Calculate the 8-bit unsigned integer gain value for the given SDR and HDR
- * luminances in linear space, and the hdr ratio to encode against.
- *
- * Note: since this library always uses gamma of 1.0, offsetSdr of 0.0, and
- * offsetHdr of 0.0, this function doesn't handle different metadata values for
- * these fields.
+ * luminances in linear space and gainmap metadata fields.
  */
-uint8_t encodeGain(float y_sdr, float y_hdr, ultrahdr_metadata_ptr metadata);
-uint8_t encodeGain(float y_sdr, float y_hdr, ultrahdr_metadata_ptr metadata,
+uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata);
+uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata,
                    float log2MinContentBoost, float log2MaxContentBoost);
+float computeGain(float sdr, float hdr);
+uint8_t affineMapGain(float gainlog2, float mingainlog2, float maxgainlog2, float gamma);
 
 /*
  * Calculates the linear luminance in nits after applying the given gain
  * value, with the given hdr ratio, to the given sdr input in the range [0, 1].
- *
- * Note: similar to encodeGain(), this function only supports gamma 1.0,
- * offsetSdr 0.0, offsetHdr 0.0, hdrCapacityMin 1.0, and hdrCapacityMax equal to
- * gainMapMax, as this library encodes.
  */
-Color applyGain(Color e, float gain, ultrahdr_metadata_ptr metadata);
-Color applyGain(Color e, float gain, ultrahdr_metadata_ptr metadata, float displayBoost);
+Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata);
+Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata, float displayBoost);
 Color applyGainLUT(Color e, float gain, GainLUT& gainLUT);
 
 /*
  * Apply gain in R, G and B channels, with the given hdr ratio, to the given sdr input
  * in the range [0, 1].
- *
- * Note: similar to encodeGain(), this function only supports gamma 1.0,
- * offsetSdr 0.0, offsetHdr 0.0, hdrCapacityMin 1.0, and hdrCapacityMax equal to
- * gainMapMax, as this library encodes.
  */
-Color applyGain(Color e, Color gain, ultrahdr_metadata_ptr metadata);
-Color applyGain(Color e, Color gain, ultrahdr_metadata_ptr metadata, float displayBoost);
+Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata);
+Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata, float displayBoost);
 Color applyGainLUT(Color e, Color gain, GainLUT& gainLUT);
 
 /*
- * Helper for sampling from YUV 420 images.
- */
-Color getYuv420Pixel(jr_uncompressed_ptr image, size_t x, size_t y);
-
-/*
- * Helper for sampling from P010 images.
- *
- * Expect narrow-range image data for P010.
+ * Get pixel from the image at the provided location.
  */
-Color getP010Pixel(jr_uncompressed_ptr image, size_t x, size_t y);
+Color getYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getYuv422Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getYuv420Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getP010Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getYuv444Pixel10bit(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
+Color getRgba1010102Pixel(uhdr_raw_image_t* image, size_t x, size_t y);
 
 /*
  * Sample the image at the provided location, with a weighting based on nearby
  * pixels and the map scale factor.
  */
-Color sampleYuv420(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y);
+Color sampleYuv444(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
+Color sampleYuv422(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
+Color sampleYuv420(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
+Color sampleP010(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y);
+Color sampleYuv44410bit(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y);
+Color sampleRgba8888(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y);
+Color sampleRgba1010102(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y);
 
 /*
- * Sample the image at the provided location, with a weighting based on nearby
- * pixels and the map scale factor.
- *
- * Expect narrow-range image data for P010.
+ * Put pixel in the image at the provided location.
  */
-Color sampleP010(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y);
+void putRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel);
+void putYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y, Color& pixel);
 
 /*
  * Sample the gain value for the map from a given x,y coordinate on a scale
  * that is map scale factor larger than the map size.
  */
-float sampleMap(jr_uncompressed_ptr map, float map_scale_factor, size_t x, size_t y);
-float sampleMap(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y,
+float sampleMap(uhdr_raw_image_t* map, float map_scale_factor, size_t x, size_t y);
+float sampleMap(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y,
                 ShepardsIDW& weightTables);
-Color sampleMap3Channel(jr_uncompressed_ptr map, float map_scale_factor, size_t x, size_t y,
+Color sampleMap3Channel(uhdr_raw_image_t* map, float map_scale_factor, size_t x, size_t y,
                         bool has_alpha);
-Color sampleMap3Channel(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y,
+Color sampleMap3Channel(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y,
                         ShepardsIDW& weightTables, bool has_alpha);
 
 /*
@@ -568,10 +630,17 @@ uint32_t colorToRgba1010102(Color e_gamma);
  */
 uint64_t colorToRgbaF16(Color e_gamma);
 
+/*
+ * Helper for copying raw image descriptor
+ */
+std::unique_ptr<uhdr_raw_image_ext_t> copy_raw_image(uhdr_raw_image_t* src);
+uhdr_error_info_t copy_raw_image(uhdr_raw_image_t* src, uhdr_raw_image_t* dst);
+
 /*
  * Helper for preparing encoder raw inputs for encoding
  */
-std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_t* src);
+std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(
+    uhdr_raw_image_t* src, bool chroma_sampling_enabled = false);
 
 /*
  * Helper for converting float to fraction
diff --git a/lib/include/ultrahdr/gainmapmetadata.h b/lib/include/ultrahdr/gainmapmetadata.h
index 172bba0..5ba6200 100644
--- a/lib/include/ultrahdr/gainmapmetadata.h
+++ b/lib/include/ultrahdr/gainmapmetadata.h
@@ -18,24 +18,15 @@
 #define ULTRAHDR_GAINMAPMETADATA_H
 
 #include "ultrahdr/ultrahdrcommon.h"
-#include "ultrahdr/ultrahdr.h"
 
 #include <memory>
 #include <vector>
 
 namespace ultrahdr {
 
-#define JPEGR_CHECK(x)                \
-  {                                   \
-    status_t status = (x);            \
-    if ((status) != JPEGR_NO_ERROR) { \
-      return status;                  \
-    }                                 \
-  }
-
 // Gain map metadata, for tone mapping between SDR and HDR.
-// This is the fraction version of {@code ultrahdr_metadata_struct}.
-struct gain_map_metadata {
+// This is the fraction version of {@code uhdr_gainmap_metadata_ext_t}.
+struct uhdr_gainmap_metadata_frac {
   uint32_t gainMapMinN[3];
   uint32_t gainMapMinD[3];
   uint32_t gainMapMaxN[3];
@@ -56,17 +47,17 @@ struct gain_map_metadata {
   bool backwardDirection;
   bool useBaseColorSpace;
 
-  static status_t encodeGainmapMetadata(const gain_map_metadata* gain_map_metadata,
-                                        std::vector<uint8_t>& out_data);
+  static uhdr_error_info_t encodeGainmapMetadata(const uhdr_gainmap_metadata_frac* in_metadata,
+                                                 std::vector<uint8_t>& out_data);
 
-  static status_t decodeGainmapMetadata(const std::vector<uint8_t>& data,
-                                        gain_map_metadata* out_gain_map_metadata);
+  static uhdr_error_info_t decodeGainmapMetadata(const std::vector<uint8_t>& in_data,
+                                                 uhdr_gainmap_metadata_frac* out_metadata);
 
-  static status_t gainmapMetadataFractionToFloat(const gain_map_metadata* from,
-                                                 ultrahdr_metadata_ptr to);
+  static uhdr_error_info_t gainmapMetadataFractionToFloat(const uhdr_gainmap_metadata_frac* from,
+                                                          uhdr_gainmap_metadata_ext_t* to);
 
-  static status_t gainmapMetadataFloatToFraction(const ultrahdr_metadata_ptr from,
-                                                 gain_map_metadata* to);
+  static uhdr_error_info_t gainmapMetadataFloatToFraction(const uhdr_gainmap_metadata_ext_t* from,
+                                                          uhdr_gainmap_metadata_frac* to);
 
   void dump() const {
     ALOGD("GAIN MAP METADATA: \n");
@@ -98,6 +89,7 @@ struct gain_map_metadata {
     ALOGD("use base color space:                %s\n", useBaseColorSpace ? "true" : "false");
   }
 };
+
 }  // namespace ultrahdr
 
 #endif  // ULTRAHDR_GAINMAPMETADATA_H
diff --git a/lib/include/ultrahdr/icc.h b/lib/include/ultrahdr/icc.h
index 38c5107..be9d3d0 100644
--- a/lib/include/ultrahdr/icc.h
+++ b/lib/include/ultrahdr/icc.h
@@ -33,7 +33,6 @@
 #define Endian_SwapBE16(n) (n)
 #endif
 
-#include "ultrahdr/ultrahdr.h"
 #include "ultrahdr/jpegr.h"
 #include "ultrahdr/gainmapmath.h"
 #include "ultrahdr/jpegrutils.h"
@@ -164,7 +163,7 @@ static inline Fixed float_round_to_fixed(float x) {
   return float_saturate2int((float)floor((double)x * Fixed1 + 0.5));
 }
 
-static uint16_t float_round_to_unorm16(float x) {
+static inline uint16_t float_round_to_unorm16(float x) {
   x = x * 65535.f + 0.5;
   if (x > 65535) return 65535;
   if (x < 0) return 0;
@@ -227,12 +226,12 @@ class IccHelper {
   static constexpr size_t kNumChannels = 3;
 
   static std::shared_ptr<DataStruct> write_text_tag(const char* text);
-  static std::string get_desc_string(const ultrahdr_transfer_function tf,
-                                     const ultrahdr_color_gamut gamut);
+  static std::string get_desc_string(const uhdr_color_transfer_t tf,
+                                     const uhdr_color_gamut_t gamut);
   static std::shared_ptr<DataStruct> write_xyz_tag(float x, float y, float z);
   static std::shared_ptr<DataStruct> write_trc_tag(const int table_entries, const void* table_16);
   static std::shared_ptr<DataStruct> write_trc_tag(const TransferFunction& fn);
-  static float compute_tone_map_gain(const ultrahdr_transfer_function tf, float L);
+  static float compute_tone_map_gain(const uhdr_color_transfer_t tf, float L);
   static std::shared_ptr<DataStruct> write_cicp_tag(uint32_t color_primaries,
                                                     uint32_t transfer_characteristics);
   static std::shared_ptr<DataStruct> write_mAB_or_mBA_tag(uint32_t type, bool has_a_curves,
@@ -249,13 +248,14 @@ class IccHelper {
  public:
   // Output includes JPEG embedding identifier and chunk information, but not
   // APPx information.
-  static std::shared_ptr<DataStruct> writeIccProfile(const ultrahdr_transfer_function tf,
-                                                     const ultrahdr_color_gamut gamut);
+  static std::shared_ptr<DataStruct> writeIccProfile(const uhdr_color_transfer_t tf,
+                                                     const uhdr_color_gamut_t gamut);
   // NOTE: this function is not robust; it can infer gamuts that IccHelper
   // writes out but should not be considered a reference implementation for
   // robust parsing of ICC profiles or their gamuts.
-  static ultrahdr_color_gamut readIccColorGamut(void* icc_data, size_t icc_size);
+  static uhdr_color_gamut_t readIccColorGamut(void* icc_data, size_t icc_size);
 };
+
 }  // namespace ultrahdr
 
 #endif  // ULTRAHDR_ICC_H
diff --git a/lib/include/ultrahdr/jpegdecoderhelper.h b/lib/include/ultrahdr/jpegdecoderhelper.h
index 352d427..19f5835 100644
--- a/lib/include/ultrahdr/jpegdecoderhelper.h
+++ b/lib/include/ultrahdr/jpegdecoderhelper.h
@@ -39,11 +39,6 @@ extern "C" {
 
 namespace ultrahdr {
 
-// constraint on max width and max height is only due to device alloc constraints
-// can tune these values basing on the target device
-static const int kMaxWidth = 8192;
-static const int kMaxHeight = 8192;
-
 /*!\brief List of supported operations */
 typedef enum {
   PARSE_STREAM = (1 << 0),   /**< Parse jpeg header, APPn markers (Exif, Icc, Xmp, Iso) */
@@ -56,7 +51,6 @@ typedef enum {
 /*!\brief Encapsulates a converter from JPEG to raw image format. This class is not thread-safe */
 class JpegDecoderHelper {
  public:
-
   JpegDecoderHelper() = default;
   ~JpegDecoderHelper() = default;
 
@@ -67,9 +61,10 @@ class JpegDecoderHelper {
    * \param[in]  length   length of compressed image
    * \param[in]  mode     output decode format
    *
-   * \returns true if operation succeeds, false otherwise.
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  bool decompressImage(const void* image, int length, decode_mode_t mode = DECODE_TO_YCBCR_CS);
+  uhdr_error_info_t decompressImage(const void* image, int length,
+                                    decode_mode_t mode = DECODE_TO_YCBCR_CS);
 
   /*!\brief This function parses the bitstream that is passed to it and makes image information
    * available to the client via getter() functions. It does not decompress the image. That is done
@@ -78,24 +73,28 @@ class JpegDecoderHelper {
    * \param[in]  image    pointer to compressed image
    * \param[in]  length   length of compressed image
    *
-   * \returns true if operation succeeds, false otherwise.
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  bool parseImage(const void* image, int length) {
+  uhdr_error_info_t parseImage(const void* image, int length) {
     return decompressImage(image, length, PARSE_STREAM);
   }
 
   /*! Below public methods are only effective if a call to decompressImage() is made and it returned
    * true. */
 
-  /*!\brief returns pointer to decompressed image */
+  /*!\brief returns decompressed image descriptor */
+  uhdr_raw_image_t getDecompressedImage();
+
+  /*!\brief returns pointer to decompressed image
+   * \deprecated This function is deprecated instead use getDecompressedImage().
+   */
   void* getDecompressedImagePtr() { return mResultBuffer.data(); }
 
-  /*!\brief returns size of decompressed image */
+  /*!\brief returns size of decompressed image
+   * \deprecated This function is deprecated instead use getDecompressedImage().
+   */
   size_t getDecompressedImageSize() { return mResultBuffer.size(); }
 
-  /*!\brief returns format of decompressed image */
-  uhdr_img_fmt_t getDecompressedImageFormat() { return mOutFormat; }
-
   /*! Below public methods are only effective if a call to parseImage() or decompressImage() is made
    * and it returned true. */
 
@@ -105,6 +104,9 @@ class JpegDecoderHelper {
   /*!\brief returns image height */
   size_t getDecompressedImageHeight() { return mPlaneHeight[0]; }
 
+  /*!\brief returns number of components in image */
+  size_t getNumComponentsInImage() { return mNumComponents; }
+
   /*!\brief returns pointer to xmp block present in input image */
   void* getXMPPtr() { return mXMPBuffer.data(); }
 
@@ -139,10 +141,10 @@ class JpegDecoderHelper {
   // max number of components supported
   static constexpr int kMaxNumComponents = 3;
 
-  bool decode(const void* image, int length, decode_mode_t mode);
-  bool decode(jpeg_decompress_struct* cinfo, uint8_t* dest);
-  bool decodeToCSYCbCr(jpeg_decompress_struct* cinfo, uint8_t* dest);
-  bool decodeToCSRGB(jpeg_decompress_struct* cinfo, uint8_t* dest);
+  uhdr_error_info_t decode(const void* image, int length, decode_mode_t mode);
+  uhdr_error_info_t decode(jpeg_decompress_struct* cinfo, uint8_t* dest);
+  uhdr_error_info_t decodeToCSYCbCr(jpeg_decompress_struct* cinfo, uint8_t* dest);
+  uhdr_error_info_t decodeToCSRGB(jpeg_decompress_struct* cinfo, uint8_t* dest);
 
   // temporary storage
   std::unique_ptr<uint8_t[]> mPlanesMCURow[kMaxNumComponents];
@@ -155,8 +157,11 @@ class JpegDecoderHelper {
 
   // image attributes
   uhdr_img_fmt_t mOutFormat;
+  size_t mNumComponents;
   size_t mPlaneWidth[kMaxNumComponents];
   size_t mPlaneHeight[kMaxNumComponents];
+  size_t mPlaneHStride[kMaxNumComponents];
+  size_t mPlaneVStride[kMaxNumComponents];
 
   int mExifPayLoadOffset;  // Position of EXIF package, default value is -1 which means no EXIF
                            // package appears.
diff --git a/lib/include/ultrahdr/jpegencoderhelper.h b/lib/include/ultrahdr/jpegencoderhelper.h
index cdfdb37..1335671 100644
--- a/lib/include/ultrahdr/jpegencoderhelper.h
+++ b/lib/include/ultrahdr/jpegencoderhelper.h
@@ -47,10 +47,22 @@ struct destination_mgr_impl : jpeg_destination_mgr {
 /*!\brief Encapsulates a converter from raw to jpg image format. This class is not thread-safe */
 class JpegEncoderHelper {
  public:
-
   JpegEncoderHelper() = default;
   ~JpegEncoderHelper() = default;
 
+  /*!\brief This function encodes the raw image that is passed to it and stores the results
+   * internally. The result is accessible via getter functions.
+   *
+   * \param[in]  img        image to encode
+   * \param[in]  qfactor    quality factor [1 - 100, 1 being poorest and 100 being best quality]
+   * \param[in]  iccBuffer  pointer to icc segment that needs to be added to the compressed image
+   * \param[in]  iccSize    size of icc segment
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   */
+  uhdr_error_info_t compressImage(const uhdr_raw_image_t* img, const int qfactor,
+                                  const void* iccBuffer, const unsigned int iccSize);
+
   /*!\brief This function encodes the raw image that is passed to it and stores the results
    * internally. The result is accessible via getter functions.
    *
@@ -63,31 +75,39 @@ class JpegEncoderHelper {
    * \param[in]  iccBuffer  pointer to icc segment that needs to be added to the compressed image
    * \param[in]  iccSize    size of icc segment
    *
-   * \returns true if operation succeeds, false otherwise.
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  bool compressImage(const uint8_t* planes[3], const size_t strides[3], const int width,
-                     const int height, const uhdr_img_fmt_t format, const int qfactor,
-                     const void* iccBuffer, const unsigned int iccSize);
+  uhdr_error_info_t compressImage(const uint8_t* planes[3], const size_t strides[3],
+                                  const int width, const int height, const uhdr_img_fmt_t format,
+                                  const int qfactor, const void* iccBuffer,
+                                  const unsigned int iccSize);
 
   /*! Below public methods are only effective if a call to compressImage() is made and it returned
    * true. */
 
   /*!\brief returns pointer to compressed image output */
+  uhdr_compressed_image_t getCompressedImage();
+
+  /*!\brief returns pointer to compressed image output
+   * \deprecated This function is deprecated instead use getCompressedImage().
+   */
   void* getCompressedImagePtr() { return mDestMgr.mResultBuffer.data(); }
 
-  /*!\brief returns size of compressed image */
+  /*!\brief returns size of compressed image
+   * \deprecated This function is deprecated instead use getCompressedImage().
+   */
   size_t getCompressedImageSize() { return mDestMgr.mResultBuffer.size(); }
 
  private:
   // max number of components supported
   static constexpr int kMaxNumComponents = 3;
 
-  bool encode(const uint8_t* planes[3], const size_t strides[3], const int width, const int height,
-              const uhdr_img_fmt_t format, const int qfactor, const void* iccBuffer,
-              const unsigned int iccSize);
+  uhdr_error_info_t encode(const uint8_t* planes[3], const size_t strides[3], const int width,
+                           const int height, const uhdr_img_fmt_t format, const int qfactor,
+                           const void* iccBuffer, const unsigned int iccSize);
 
-  bool compressYCbCr(jpeg_compress_struct* cinfo, const uint8_t* planes[3],
-                     const size_t strides[3]);
+  uhdr_error_info_t compressYCbCr(jpeg_compress_struct* cinfo, const uint8_t* planes[3],
+                                  const size_t strides[3]);
 
   destination_mgr_impl mDestMgr;  // object for managing output
 
diff --git a/lib/include/ultrahdr/jpegr.h b/lib/include/ultrahdr/jpegr.h
index 9aa94a1..ea5b0eb 100644
--- a/lib/include/ultrahdr/jpegr.h
+++ b/lib/include/ultrahdr/jpegr.h
@@ -20,23 +20,39 @@
 #include <array>
 #include <cfloat>
 
+#include "ultrahdr_api.h"
 #include "ultrahdr/ultrahdr.h"
+#include "ultrahdr/ultrahdrcommon.h"
 #include "ultrahdr/jpegdecoderhelper.h"
 #include "ultrahdr/jpegencoderhelper.h"
 
 namespace ultrahdr {
 
-// The current JPEGR version that we encode to
-static const char* const kJpegrVersion = kGainMapVersion;
+// Default configurations
+// gainmap image downscale factor
+static const size_t kMapDimensionScaleFactorDefault = 1;
+static const size_t kMapDimensionScaleFactorAndroidDefault = 4;
+
+// JPEG compress quality (0 ~ 100) for base image
+static const int kBaseCompressQualityDefault = 95;
+
+// JPEG compress quality (0 ~ 100) for gain map
+static const int kMapCompressQualityDefault = 95;
+static const int kMapCompressQualityAndroidDefault = 85;
 
-// Map is quarter res / sixteenth size
-static const size_t kMapDimensionScaleFactor = 4;
+// Gain map calculation
+static const bool kUseMultiChannelGainMapDefault = true;
+static const bool kUseMultiChannelGainMapAndroidDefault = false;
 
-// Gain Map width is (image_width / kMapDimensionScaleFactor). If we were to
-// compress 420 GainMap in jpeg, then we need at least 2 samples. For Grayscale
-// 1 sample is sufficient. We are using 2 here anyways
-static const int kMinWidth = 2 * kMapDimensionScaleFactor;
-static const int kMinHeight = 2 * kMapDimensionScaleFactor;
+// encoding preset
+static const uhdr_enc_preset_t kEncSpeedPresetDefault = UHDR_USAGE_BEST_QUALITY;
+static const uhdr_enc_preset_t kEncSpeedPresetAndroidDefault = UHDR_USAGE_REALTIME;
+
+// Default gamma value for gain map
+static const float kGainMapGammaDefault = 1.0f;
+
+// The current JPEGR version that we encode to
+static const char* const kJpegrVersion = "1.0";
 
 /*
  * Holds information of jpeg image
@@ -46,8 +62,10 @@ struct jpeg_info_struct {
   std::vector<uint8_t> iccData = std::vector<uint8_t>(0);
   std::vector<uint8_t> exifData = std::vector<uint8_t>(0);
   std::vector<uint8_t> xmpData = std::vector<uint8_t>(0);
+  std::vector<uint8_t> isoData = std::vector<uint8_t>(0);
   size_t width;
   size_t height;
+  size_t numComponents;
 };
 
 /*
@@ -60,222 +78,318 @@ struct jpegr_info_struct {
   jpeg_info_struct* gainmapImgInfo = nullptr;
 };
 
-/*
- * Holds information for uncompressed image or gain map.
- */
-struct jpegr_uncompressed_struct {
-  // Pointer to the data location.
-  void* data;
-  // Width of the gain map or the luma plane of the image in pixels.
-  size_t width;
-  // Height of the gain map or the luma plane of the image in pixels.
-  size_t height;
-  // Color gamut.
-  ultrahdr_color_gamut colorGamut;
-
-  // Values below are optional
-  // Pointer to chroma data, if it's NULL, chroma plane is considered to be immediately
-  // after the luma plane.
-  void* chroma_data = nullptr;
-  // Stride of Y plane in number of pixels. 0 indicates the member is uninitialized. If
-  // non-zero this value must be larger than or equal to luma width. If stride is
-  // uninitialized then it is assumed to be equal to luma width.
-  size_t luma_stride = 0;
-  // Stride of UV plane in number of pixels.
-  // 1. If this handle points to P010 image then this value must be larger than
-  //    or equal to luma width.
-  // 2. If this handle points to 420 image then this value must be larger than
-  //    or equal to (luma width / 2).
-  // NOTE: if chroma_data is nullptr, chroma_stride is irrelevant. Just as the way,
-  // chroma_data is derived from luma ptr, chroma stride is derived from luma stride.
-  size_t chroma_stride = 0;
-  // Pixel format.
-  uhdr_img_fmt_t pixelFormat = UHDR_IMG_FMT_UNSPECIFIED;
-};
-
-/*
- * Holds information for compressed image or gain map.
- */
-struct jpegr_compressed_struct {
-  // Pointer to the data location.
-  void* data;
-  // Used data length in bytes.
-  int length;
-  // Maximum available data length in bytes.
-  int maxLength;
-  // Color gamut.
-  ultrahdr_color_gamut colorGamut;
-};
-
-/*
- * Holds information for EXIF metadata.
- */
-struct jpegr_exif_struct {
-  // Pointer to the data location.
-  void* data;
-  // Data length;
-  size_t length;
-};
-
-typedef struct jpegr_uncompressed_struct* jr_uncompressed_ptr;
-typedef struct jpegr_compressed_struct* jr_compressed_ptr;
-typedef struct jpegr_exif_struct* jr_exif_ptr;
 typedef struct jpeg_info_struct* j_info_ptr;
 typedef struct jpegr_info_struct* jr_info_ptr;
 
 class JpegR {
  public:
-  /*
-   * Experimental only
+  JpegR(void* uhdrGLESCtxt = nullptr,
+        size_t mapDimensionScaleFactor = kMapDimensionScaleFactorAndroidDefault,
+        int mapCompressQuality = kMapCompressQualityAndroidDefault,
+        bool useMultiChannelGainMap = kUseMultiChannelGainMapAndroidDefault,
+        float gamma = kGainMapGammaDefault,
+        uhdr_enc_preset_t preset = kEncSpeedPresetAndroidDefault, float minContentBoost = FLT_MIN,
+        float maxContentBoost = FLT_MAX);
+
+  /*!\brief Encode API-0.
    *
-   * Encode API-0
-   * Compress JPEGR image from 10-bit HDR YUV.
+   * Create ultrahdr jpeg image from raw hdr intent.
    *
-   * Tonemap the HDR input to a SDR image, generate gain map from the HDR and SDR images,
-   * compress SDR YUV to 8-bit JPEG and append the gain map to the end of the compressed
-   * JPEG.
-   * @param p010_image_ptr uncompressed HDR image in P010 color format
-   * @param hdr_tf transfer function of the HDR image
-   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
-   *             represents the maximum available size of the destination buffer, and it must be
-   *             set before calling this method. If the encoded JPEGR size exceeds
-   *             {@code maxLength}, this method will return {@code ERROR_JPEGR_BUFFER_TOO_SMALL}.
-   * @param quality target quality of the JPEG encoding, must be in range of 0-100 where 100 is
-   *                the highest quality
-   * @param exif pointer to the exif metadata.
-   * @return NO_ERROR if encoding succeeds, error code if error occurs.
+   * Experimental only.
+   *
+   * Input hdr image is tonemapped to sdr image. A gainmap coefficient is computed between hdr and
+   * sdr intent. sdr intent and gain map coefficient are compressed using jpeg encoding. compressed
+   * gainmap is appended at the end of compressed sdr image.
+   *
+   * \param[in]       hdr_intent        hdr intent raw input image descriptor
+   * \param[in, out]  dest              output image descriptor to store compressed ultrahdr image
+   * \param[in]       quality           quality factor for sdr intent jpeg compression
+   * \param[in]       exif              optional exif metadata that needs to be inserted in
+   *                                    compressed output
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   */
+  uhdr_error_info_t encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_compressed_image_t* dest,
+                                int quality, uhdr_mem_block_t* exif);
+
+  /*!\brief Encode API-1.
+   *
+   * Create ultrahdr jpeg image from raw hdr intent and raw sdr intent.
+   *
+   * A gainmap coefficient is computed between hdr and sdr intent. sdr intent and gain map
+   * coefficient are compressed using jpeg encoding. compressed gainmap is appended at the end of
+   * compressed sdr image.
+   * NOTE: Color transfer of sdr intent is expected to be sRGB.
+   *
+   * \param[in]       hdr_intent        hdr intent raw input image descriptor
+   * \param[in]       sdr_intent        sdr intent raw input image descriptor
+   * \param[in, out]  dest              output image descriptor to store compressed ultrahdr image
+   * \param[in]       quality           quality factor for sdr intent jpeg compression
+   * \param[in]       exif              optional exif metadata that needs to be inserted in
+   *                                    compressed output
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   */
+  uhdr_error_info_t encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
+                                uhdr_compressed_image_t* dest, int quality, uhdr_mem_block_t* exif);
+
+  /*!\brief Encode API-2.
+   *
+   * Create ultrahdr jpeg image from raw hdr intent, raw sdr intent and compressed sdr intent.
+   *
+   * A gainmap coefficient is computed between hdr and sdr intent. gain map coefficient is
+   * compressed using jpeg encoding. compressed gainmap is appended at the end of compressed sdr
+   * intent. ICC profile is added if one isn't present in the sdr intent JPEG image.
+   * NOTE: Color transfer of sdr intent is expected to be sRGB.
+   * NOTE: sdr intent raw and compressed inputs are expected to be related via compress/decompress
+   * operations.
+   *
+   * \param[in]       hdr_intent               hdr intent raw input image descriptor
+   * \param[in]       sdr_intent               sdr intent raw input image descriptor
+   * \param[in]       sdr_intent_compressed    sdr intent compressed input image descriptor
+   * \param[in, out]  dest                     output image descriptor to store compressed ultrahdr
+   *                                           image
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   */
+  uhdr_error_info_t encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
+                                uhdr_compressed_image_t* sdr_intent_compressed,
+                                uhdr_compressed_image_t* dest);
+
+  /*!\brief Encode API-3.
+   *
+   * Create ultrahdr jpeg image from raw hdr intent and compressed sdr intent.
+   *
+   * The sdr intent is decoded and a gainmap coefficient is computed between hdr and sdr intent.
+   * gain map coefficient is compressed using jpeg encoding. compressed gainmap is appended at the
+   * end of compressed sdr image. ICC profile is added if one isn't present in the sdr intent JPEG
+   * image.
+   * NOTE: Color transfer of sdr intent is expected to be sRGB.
+   *
+   * \param[in]       hdr_intent               hdr intent raw input image descriptor
+   * \param[in]       sdr_intent_compressed    sdr intent compressed input image descriptor
+   * \param[in, out]  dest                     output image descriptor to store compressed ultrahdr
+   *                                           image
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   */
+  uhdr_error_info_t encodeJPEGR(uhdr_raw_image_t* hdr_intent,
+                                uhdr_compressed_image_t* sdr_intent_compressed,
+                                uhdr_compressed_image_t* dest);
+
+  /*!\brief Encode API-4.
+   *
+   * Create ultrahdr jpeg image from compressed sdr image and compressed gainmap image
+   *
+   * compressed gainmap image is added at the end of compressed sdr image. ICC profile is added if
+   * one isn't present in the sdr intent compressed image.
+   *
+   * \param[in]       base_img_compressed      sdr intent compressed input image descriptor
+   * \param[in]       gainmap_img_compressed   gainmap compressed image descriptor
+   * \param[in]       metadata                 gainmap metadata descriptor
+   * \param[in, out]  dest                     output image descriptor to store compressed ultrahdr
+   *                                           image
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   */
+  uhdr_error_info_t encodeJPEGR(uhdr_compressed_image_t* base_img_compressed,
+                                uhdr_compressed_image_t* gainmap_img_compressed,
+                                uhdr_gainmap_metadata_ext_t* metadata,
+                                uhdr_compressed_image_t* dest);
+
+  /*!\brief Decode API.
+   *
+   * Decompress ultrahdr jpeg image.
+   *
+   * NOTE: This method requires that the ultrahdr input image contains an ICC profile with primaries
+   * that match those of a color gamut that this library is aware of; Bt.709, Display-P3, or
+   * Bt.2100. It also assumes the base image color transfer characteristics are sRGB.
+   *
+   * \param[in]       uhdr_compressed_img      compressed ultrahdr image descriptor
+   * \param[in, out]  dest                     output image descriptor to store decoded output
+   * \param[in]       max_display_boost        (optional) the maximum available boost supported by a
+   *                                           display, the value must be greater than or equal
+   *                                           to 1.0
+   * \param[in]       output_ct                (optional) output color transfer
+   * \param[in]       output_format            (optional) output pixel format
+   * \param[in, out]  gainmap_img              (optional) output image descriptor to store decoded
+   *                                           gainmap image
+   * \param[in, out]  gainmap_metadata         (optional) descriptor to store gainmap metadata
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   *
+   * NOTE: This method only supports single gain map metadata values for fields that allow
+   * multi-channel metadata values.
+   *
+   * NOTE: Not all combinations of output color transfer and output pixel format are supported.
+   * Refer below table for supported combinations.
+   *         ----------------------------------------------------------------------
+   *         |           color transfer	       |          color format            |
+   *         ----------------------------------------------------------------------
+   *         |                 SDR             |          32bppRGBA8888           |
+   *         ----------------------------------------------------------------------
+   *         |             HDR_LINEAR          |          64bppRGBAHalfFloat      |
+   *         ----------------------------------------------------------------------
+   *         |               HDR_PQ            |          32bppRGBA1010102        |
+   *         ----------------------------------------------------------------------
+   *         |               HDR_HLG           |          32bppRGBA1010102        |
+   *         ----------------------------------------------------------------------
+   */
+  uhdr_error_info_t decodeJPEGR(uhdr_compressed_image_t* uhdr_compressed_img,
+                                uhdr_raw_image_t* dest, float max_display_boost = FLT_MAX,
+                                uhdr_color_transfer_t output_ct = UHDR_CT_LINEAR,
+                                uhdr_img_fmt_t output_format = UHDR_IMG_FMT_64bppRGBAHalfFloat,
+                                uhdr_raw_image_t* gainmap_img = nullptr,
+                                uhdr_gainmap_metadata_t* gainmap_metadata = nullptr);
+
+  /*!\brief This function parses the bitstream and returns information that is useful for actual
+   * decoding. This does not decode the image. That is handled by decodeJPEGR
+   *
+   * \param[in]       uhdr_compressed_img      compressed ultrahdr image descriptor
+   * \param[in, out]  uhdr_image_info          image info descriptor
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   */
+  uhdr_error_info_t getJPEGRInfo(uhdr_compressed_image_t* uhdr_compressed_img,
+                                 jr_info_ptr uhdr_image_info);
+
+  /*!\brief set gain map dimension scale factor
+   * NOTE: Applicable only in encoding scenario
+   *
+   * \param[in]       mapDimensionScaleFactor      scale factor
+   *
+   * \return none
+   */
+  void setMapDimensionScaleFactor(size_t mapDimensionScaleFactor) {
+    this->mMapDimensionScaleFactor = mapDimensionScaleFactor;
+  }
+
+  /*!\brief get gain map dimension scale factor
+   * NOTE: Applicable only in encoding scenario
+   *
+   * \return mapDimensionScaleFactor
+   */
+  size_t getMapDimensionScaleFactor() { return this->mMapDimensionScaleFactor; }
+
+  /*!\brief set gain map compression quality factor
+   * NOTE: Applicable only in encoding scenario
+   *
+   * \param[in]       mapCompressQuality      quality factor for gain map image compression
+   *
+   * \return none
+   */
+  void setMapCompressQuality(int mapCompressQuality) {
+    this->mMapCompressQuality = mapCompressQuality;
+  }
+
+  /*!\brief get gain map quality factor
+   * NOTE: Applicable only in encoding scenario
+   *
+   * \return quality factor
+   */
+  int getMapCompressQuality() { return this->mMapCompressQuality; }
+
+  /*!\brief set gain map gamma
+   * NOTE: Applicable only in encoding scenario
+   *
+   * \param[in]       gamma      gamma parameter that is used for gain map calculation
+   *
+   * \return none
+   */
+  void setGainMapGamma(float gamma) { this->mGamma = gamma; }
+
+  /*!\brief get gain map gamma
+   * NOTE: Applicable only in encoding scenario
+   *
+   * \return gamma parameter
+   */
+  float getGainMapGamma() { return this->mGamma; }
+
+  /*!\brief enable / disable multi channel gain map
+   * NOTE: Applicable only in encoding scenario
+   *
+   * \param[in]       useMultiChannelGainMap      enable / disable multi channel gain map
+   *
+   * \return none
+   */
+  void setUseMultiChannelGainMap(bool useMultiChannelGainMap) {
+    this->mUseMultiChannelGainMap = useMultiChannelGainMap;
+  }
+
+  /*!\brief check if multi channel gain map is enabled
+   * NOTE: Applicable only in encoding scenario
+   *
+   * \return true if multi channel gain map is enabled, false otherwise
+   */
+  bool isUsingMultiChannelGainMap() { return this->mUseMultiChannelGainMap; }
+
+  /*!\brief set gain map min and max content boost
+   * NOTE: Applicable only in encoding scenario
+   *
+   * \param[in]       minBoost      gain map min content boost
+   * \param[in]       maxBoost      gain map max content boost
+   *
+   * \return none
+   */
+  void setGainMapMinMaxContentBoost(float minBoost, float maxBoost) {
+    this->mMinContentBoost = minBoost;
+    this->mMaxContentBoost = maxBoost;
+  }
+
+  /*!\brief get gain map min max content boost
+   * NOTE: Applicable only in encoding scenario
+   *
+   * \param[out]       minBoost      gain map min content boost
+   * \param[out]       maxBoost      gain map max content boost
+   *
+   * \return none
+   */
+  void getGainMapMinMaxContentBoost(float& minBoost, float& maxBoost) {
+    minBoost = this->mMinContentBoost;
+    maxBoost = this->mMaxContentBoost;
+  }
+
+  /* \brief Alias of Encode API-0.
+   *
+   * \deprecated This function is deprecated. Use its alias
    */
   status_t encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, ultrahdr_transfer_function hdr_tf,
                        jr_compressed_ptr dest, int quality, jr_exif_ptr exif);
 
-  /*
-   * Encode API-1
-   * Compress JPEGR image from 10-bit HDR YUV and 8-bit SDR YUV.
+  /* \brief Alias of Encode API-1.
    *
-   * Generate gain map from the HDR and SDR inputs, compress SDR YUV to 8-bit JPEG and append
-   * the gain map to the end of the compressed JPEG. HDR and SDR inputs must be the same
-   * resolution. SDR input is assumed to use the sRGB transfer function.
-   * @param p010_image_ptr uncompressed HDR image in P010 color format
-   * @param yuv420_image_ptr uncompressed SDR image in YUV_420 color format
-   * @param hdr_tf transfer function of the HDR image
-   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
-   *             represents the maximum available size of the desitination buffer, and it must be
-   *             set before calling this method. If the encoded JPEGR size exceeds
-   *             {@code maxLength}, this method will return {@code ERROR_JPEGR_BUFFER_TOO_SMALL}.
-   * @param quality target quality of the JPEG encoding, must be in range of 0-100 where 100 is
-   *                the highest quality
-   * @param exif pointer to the exif metadata.
-   * @return NO_ERROR if encoding succeeds, error code if error occurs.
+   * \deprecated This function is deprecated. Use its actual
    */
   status_t encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, jr_uncompressed_ptr yuv420_image_ptr,
                        ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest, int quality,
                        jr_exif_ptr exif);
 
-  /*
-   * Encode API-2
-   * Compress JPEGR image from 10-bit HDR YUV, 8-bit SDR YUV and compressed 8-bit JPEG.
-   *
-   * This method requires HAL Hardware JPEG encoder.
+  /* \brief Alias of Encode API-2.
    *
-   * Generate gain map from the HDR and SDR inputs, append the gain map to the end of the
-   * compressed JPEG. Adds an ICC profile if one isn't present in the input JPEG image. HDR and
-   * SDR inputs must be the same resolution and color space. SDR image is assumed to use the sRGB
-   * transfer function.
-   * @param p010_image_ptr uncompressed HDR image in P010 color format
-   * @param yuv420_image_ptr uncompressed SDR image in YUV_420 color format
-   * @param yuv420jpg_image_ptr SDR image compressed in jpeg format
-   * @param hdr_tf transfer function of the HDR image
-   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
-   *             represents the maximum available size of the desitination buffer, and it must be
-   *             set before calling this method. If the encoded JPEGR size exceeds
-   *             {@code maxLength}, this method will return {@code ERROR_JPEGR_BUFFER_TOO_SMALL}.
-   * @return NO_ERROR if encoding succeeds, error code if error occurs.
+   * \deprecated This function is deprecated. Use its actual
    */
   status_t encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, jr_uncompressed_ptr yuv420_image_ptr,
                        jr_compressed_ptr yuv420jpg_image_ptr, ultrahdr_transfer_function hdr_tf,
                        jr_compressed_ptr dest);
 
-  /*
-   * Encode API-3
-   * Compress JPEGR image from 10-bit HDR YUV and 8-bit SDR YUV.
+  /* \brief Alias of Encode API-3.
    *
-   * This method requires HAL Hardware JPEG encoder.
-   *
-   * Decode the compressed 8-bit JPEG image to YUV SDR, generate gain map from the HDR input
-   * and the decoded SDR result, append the gain map to the end of the compressed JPEG. Adds an
-   * ICC profile if one isn't present in the input JPEG image. HDR and SDR inputs must be the same
-   * resolution. JPEG image is assumed to use the sRGB transfer function.
-   * @param p010_image_ptr uncompressed HDR image in P010 color format
-   * @param yuv420jpg_image_ptr SDR image compressed in jpeg format
-   * @param hdr_tf transfer function of the HDR image
-   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
-   *             represents the maximum available size of the desitination buffer, and it must be
-   *             set before calling this method. If the encoded JPEGR size exceeds
-   *             {@code maxLength}, this method will return {@code ERROR_JPEGR_BUFFER_TOO_SMALL}.
-   * @return NO_ERROR if encoding succeeds, error code if error occurs.
+   * \deprecated This function is deprecated. Use its actual
    */
   status_t encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, jr_compressed_ptr yuv420jpg_image_ptr,
                        ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest);
 
-  /*
-   * Encode API-4
-   * Assemble JPEGR image from SDR JPEG and gainmap JPEG.
-   *
-   * Assemble the primary JPEG image, the gain map and the metadata to JPEG/R format. Adds an ICC
-   * profile if one isn't present in the input JPEG image.
-   * @param yuv420jpg_image_ptr SDR image compressed in jpeg format
-   * @param gainmapjpg_image_ptr gain map image compressed in jpeg format
-   * @param metadata metadata to be written in XMP of the primary jpeg
-   * @param dest destination of the compressed JPEGR image. Please note that {@code maxLength}
-   *             represents the maximum available size of the desitination buffer, and it must be
-   *             set before calling this method. If the encoded JPEGR size exceeds
-   *             {@code maxLength}, this method will return {@code ERROR_JPEGR_BUFFER_TOO_SMALL}.
-   * @return NO_ERROR if encoding succeeds, error code if error occurs.
+  /* \brief Alias of Encode API-4.
+   *
+   * \deprecated This function is deprecated. Use its actual
    */
   status_t encodeJPEGR(jr_compressed_ptr yuv420jpg_image_ptr,
                        jr_compressed_ptr gainmapjpg_image_ptr, ultrahdr_metadata_ptr metadata,
                        jr_compressed_ptr dest);
 
-  /*
-   * Decode API
-   * Decompress JPEGR image.
-   *
-   * This method assumes that the JPEGR image contains an ICC profile with primaries that match
-   * those of a color gamut that this library is aware of; Bt.709, Display-P3, or Bt.2100. It also
-   * assumes the base image uses the sRGB transfer function.
-   *
-   * This method only supports single gain map metadata values for fields that allow multi-channel
-   * metadata values.
-   * @param jpegr_image_ptr compressed JPEGR image.
-   * @param dest destination of the uncompressed JPEGR image.
-   * @param max_display_boost (optional) the maximum available boost supported by a display,
-   *                          the value must be greater than or equal to 1.0.
-   * @param exif destination of the decoded EXIF metadata. The default value is NULL where the
-                 decoder will do nothing about it. If configured not NULL the decoder will write
-                 EXIF data into this structure. The format is defined in {@code jpegr_exif_struct}
-   * @param output_format flag for setting output color format. Its value configures the output
-                          color format. The default value is {@code JPEGR_OUTPUT_HDR_LINEAR}.
-                          ----------------------------------------------------------------------
-                          |      output_format       |    decoded color format to be written   |
-                          ----------------------------------------------------------------------
-                          |     JPEGR_OUTPUT_SDR     |                RGBA_8888                |
-                          ----------------------------------------------------------------------
-                          | JPEGR_OUTPUT_HDR_LINEAR  |        (default)RGBA_F16 linear         |
-                          ----------------------------------------------------------------------
-                          |   JPEGR_OUTPUT_HDR_PQ    |             RGBA_1010102 PQ             |
-                          ----------------------------------------------------------------------
-                          |   JPEGR_OUTPUT_HDR_HLG   |            RGBA_1010102 HLG             |
-                          ----------------------------------------------------------------------
-   * @param gainmap_image_ptr destination of the decoded gain map. The default value is NULL
-                              where the decoder will do nothing about it. If configured not NULL
-                              the decoder will write the decoded gain_map data into this
-                              structure. The format is defined in
-                              {@code jpegr_uncompressed_struct}.
-   * @param metadata destination of the decoded metadata. The default value is NULL where the
-                     decoder will do nothing about it. If configured not NULL the decoder will
-                     write metadata into this structure. the format of metadata is defined in
-                     {@code ultrahdr_metadata_struct}.
-   * @return NO_ERROR if decoding succeeds, error code if error occurs.
+  /* \brief Alias of Decode API
+   *
+   * \deprecated This function is deprecated. Use its actual
    */
   status_t decodeJPEGR(jr_compressed_ptr jpegr_image_ptr, jr_uncompressed_ptr dest,
                        float max_display_boost = FLT_MAX, jr_exif_ptr exif = nullptr,
@@ -283,149 +397,166 @@ class JpegR {
                        jr_uncompressed_ptr gainmap_image_ptr = nullptr,
                        ultrahdr_metadata_ptr metadata = nullptr);
 
-  /*
-   * Gets Info from JPEGR file without decoding it.
+  /* \brief Alias of getJPEGRInfo
    *
-   * This method only supports single gain map metadata values for fields that allow multi-channel
-   * metadata values.
+   * \deprecated This function is deprecated. Use its actual
+   */
+  status_t getJPEGRInfo(jr_compressed_ptr jpegr_image_ptr, jr_info_ptr jpegr_image_info_ptr);
+
+  /*!\brief This function receives iso block and / or xmp block and parses gainmap metadata and fill
+   * the output descriptor. If both iso block and xmp block are available, then iso block is
+   * preferred over xmp.
+   *
+   * \param[in]       iso_data                  iso memory block
+   * \param[in]       iso_size                  iso block size
+   * \param[in]       xmp_data                  xmp memory block
+   * \param[in]       xmp_size                  xmp block size
+   * \param[in, out]  gainmap_metadata          gainmap metadata descriptor
    *
-   * The output is filled jpegr_info structure
-   * @param jpegr_image_ptr compressed JPEGR image
-   * @param jpeg_image_info_ptr pointer to jpegr info struct. Members of jpegr_info
-   *                            are owned by the caller
-   * @return NO_ERROR if JPEGR parsing succeeds, error code otherwise
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  status_t getJPEGRInfo(jr_compressed_ptr jpegr_image_ptr, jr_info_ptr jpeg_image_info_ptr);
+  uhdr_error_info_t parseGainMapMetadata(uint8_t* iso_data, int iso_size, uint8_t* xmp_data,
+                                         int xmp_size, uhdr_gainmap_metadata_ext_t* uhdr_metadata);
 
  protected:
-  /*
-   * This method is called in the encoding pipeline. It will take the uncompressed 8-bit and
-   * 10-bit yuv images as input, and calculate the uncompressed gain map. The input images
-   * must be the same resolution. The SDR input is assumed to use the sRGB transfer function.
+  /*!\brief This method takes hdr intent and sdr intent and computes gainmap coefficient.
    *
-   * @param yuv420_image_ptr uncompressed SDR image in YUV_420 color format
-   * @param p010_image_ptr uncompressed HDR image in P010 color format
-   * @param hdr_tf transfer function of the HDR image
-   * @param metadata everything but "version" is filled in this struct
-   * @param dest location at which gain map image is stored (caller responsible for memory
-                 of data).
-   * @param sdr_is_601 if true, then use BT.601 decoding of YUV regardless of SDR image gamut
-   * @return NO_ERROR if calculation succeeds, error code if error occurs.
+   * This method is called in the encoding pipeline. It takes uncompressed 8-bit and 10-bit yuv
+   * images as input and calculates gainmap.
+   *
+   * NOTE: The input images must be the same resolution.
+   * NOTE: The SDR input is assumed to use the sRGB transfer function.
+   *
+   * \param[in]       sdr_intent               sdr intent raw input image descriptor
+   * \param[in]       hdr_intent               hdr intent raw input image descriptor
+   * \param[in, out]  gainmap_metadata         gainmap metadata descriptor
+   * \param[in, out]  gainmap_img              gainmap image descriptor
+   * \param[in]       sdr_is_601               (optional) if sdr_is_601 is true, then use BT.601
+   *                                           gamut to represent sdr intent regardless of the value
+   *                                           present in the sdr intent image descriptor
+   * \param[in]       use_luminance            (optional) used for single channel gainmap. If
+   *                                           use_luminance is true, gainmap calculation is based
+   *                                           on the pixel's luminance which is a weighted
+   *                                           combination of r, g, b channels; otherwise, gainmap
+   *                                           calculation is based of the maximun value of r, g, b
+   *                                           channels.
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  status_t generateGainMap(jr_uncompressed_ptr yuv420_image_ptr, jr_uncompressed_ptr p010_image_ptr,
-                           ultrahdr_transfer_function hdr_tf, ultrahdr_metadata_ptr metadata,
-                           jr_uncompressed_ptr dest, bool sdr_is_601 = false);
-
-  /*
-   * This method is called in the decoding pipeline. It will take the uncompressed (decoded)
-   * 8-bit yuv image, the uncompressed (decoded) gain map, and extracted JPEG/R metadata as
-   * input, and calculate the 10-bit recovered image. The recovered output image is the same
-   * color gamut as the SDR image, with HLG transfer function, and is in RGBA1010102 data format.
-   * The SDR image is assumed to use the sRGB transfer function. The SDR image is also assumed to
-   * be a decoded JPEG for the purpose of YUV interpration.
-   *
-   * @param yuv420_image_ptr uncompressed SDR image in YUV_420 color format
-   * @param gainmap_image_ptr pointer to uncompressed gain map image struct.
-   * @param metadata JPEG/R metadata extracted from XMP.
-   * @param output_format flag for setting output color format. if set to
-   *                      {@code JPEGR_OUTPUT_SDR}, decoder will only decode the primary image
-   *                      which is SDR. Default value is JPEGR_OUTPUT_HDR_LINEAR.
-   * @param max_display_boost the maximum available boost supported by a display
-   * @param dest reconstructed HDR image
-   * @return NO_ERROR if calculation succeeds, error code if error occurs.
-   */
-  status_t applyGainMap(jr_uncompressed_ptr yuv420_image_ptr, jr_uncompressed_ptr gainmap_image_ptr,
-                        ultrahdr_metadata_ptr metadata, ultrahdr_output_format output_format,
-                        float max_display_boost, jr_uncompressed_ptr dest);
+  uhdr_error_info_t generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* hdr_intent,
+                                    uhdr_gainmap_metadata_ext_t* gainmap_metadata,
+                                    std::unique_ptr<uhdr_raw_image_ext_t>& gainmap_img,
+                                    bool sdr_is_601 = false, bool use_luminance = true);
+
+  /*!\brief This method takes sdr intent, gainmap image and gainmap metadata and computes hdr
+   * intent. This method is called in the decoding pipeline. The output hdr intent image will have
+   * same color gamut as sdr intent.
+   *
+   * NOTE: The SDR input is assumed to use the sRGB transfer function.
+   *
+   * \param[in]       sdr_intent               sdr intent raw input image descriptor
+   * \param[in]       gainmap_img              gainmap image descriptor
+   * \param[in]       gainmap_metadata         gainmap metadata descriptor
+   * \param[in]       output_ct                output color transfer
+   * \param[in]       output_format            output pixel format
+   * \param[in]       max_display_boost        the maximum available boost supported by a
+   *                                           display, the value must be greater than or equal
+   *                                           to 1.0
+   * \param[in, out]  dest                     output image descriptor to store output
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   */
+  uhdr_error_info_t applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
+                                 uhdr_gainmap_metadata_ext_t* gainmap_metadata,
+                                 uhdr_color_transfer_t output_ct, uhdr_img_fmt_t output_format,
+                                 float max_display_boost, uhdr_raw_image_t* dest);
 
  private:
-  /*
-   * This method is called in the encoding pipeline. It will encode the gain map.
+  /*!\brief compress gainmap image
    *
-   * @param gainmap_image_ptr pointer to uncompressed gain map image struct
-   * @param jpeg_enc_obj_ptr helper resource to compress gain map
-   * @return NO_ERROR if encoding succeeds, error code if error occurs.
+   * \param[in]       gainmap_img              gainmap image descriptor
+   * \param[in]       jpeg_enc_obj             jpeg encoder object handle
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  status_t compressGainMap(jr_uncompressed_ptr gainmap_image_ptr,
-                           JpegEncoderHelper* jpeg_enc_obj_ptr);
+  uhdr_error_info_t compressGainMap(uhdr_raw_image_t* gainmap_img, JpegEncoderHelper* jpeg_enc_obj);
 
-  /*
-   * This method is called to separate primary image and gain map image from JPEGR
+  /*!\brief This method is called to separate base image and gain map image from compressed
+   * ultrahdr image
+   *
+   * \param[in]            jpegr_image               compressed ultrahdr image descriptor
+   * \param[in, out]       primary_image             sdr image descriptor
+   * \param[in, out]       gainmap_image             gainmap image descriptor
    *
-   * @param jpegr_image_ptr pointer to compressed JPEGR image.
-   * @param primary_jpg_image_ptr destination of primary image
-   * @param gainmap_jpg_image_ptr destination of compressed gain map image
-   * @return NO_ERROR if calculation succeeds, error code if error occurs.
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  status_t extractPrimaryImageAndGainMap(jr_compressed_ptr jpegr_image_ptr,
-                                         jr_compressed_ptr primary_jpg_image_ptr,
-                                         jr_compressed_ptr gainmap_jpg_image_ptr);
+  uhdr_error_info_t extractPrimaryImageAndGainMap(uhdr_compressed_image_t* jpegr_image,
+                                                  uhdr_compressed_image_t* primary_image,
+                                                  uhdr_compressed_image_t* gainmap_image);
 
-  /*
-   * Gets Info from JPEG image without decoding it.
+  /*!\brief This function parses the bitstream and returns metadata that is useful for actual
+   * decoding. This does not decode the image. That is handled by decompressImage().
+   *
+   * \param[in]            jpeg_image      compressed jpeg image descriptor
+   * \param[in, out]       image_info      image info descriptor
+   * \param[in, out]       img_width       (optional) image width
+   * \param[in, out]       img_height      (optional) image height
    *
-   * The output is filled jpeg_info structure
-   * @param jpegr_image_ptr compressed JPEG image
-   * @param jpeg_image_info_ptr pointer to jpeg info struct. Members of jpeg_info_struct
-   *                            are owned by the caller
-   * @param img_width (optional) pointer to store width of jpeg image
-   * @param img_height (optional) pointer to store height of jpeg image
-   * @return NO_ERROR if JPEGR parsing succeeds, error code otherwise
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  status_t parseJpegInfo(jr_compressed_ptr jpeg_image_ptr, j_info_ptr jpeg_image_info_ptr,
-                         size_t* img_width = nullptr, size_t* img_height = nullptr);
+  uhdr_error_info_t parseJpegInfo(uhdr_compressed_image_t* jpeg_image, j_info_ptr image_info,
+                                  size_t* img_width = nullptr, size_t* img_height = nullptr);
 
-  /*
-   * This method is called in the encoding pipeline. It will take the standard 8-bit JPEG image,
-   * the compressed gain map and optionally the exif package as inputs, and generate the XMP
-   * metadata, and finally append everything in the order of:
-   *     SOI, APP2(EXIF) (if EXIF is from outside), APP2(XMP), primary image, gain map
-   *
-   * Note that in the final JPEG/R output, EXIF package will appear if ONLY ONE of the following
-   * conditions is fulfilled:
-   *  (1) EXIF package is available from outside input. I.e. pExif != nullptr.
-   *  (2) Input JPEG has EXIF.
-   * If both conditions are fulfilled, this method will return ERROR_JPEGR_INVALID_INPUT_TYPE
-   *
-   * @param primary_jpg_image_ptr destination of primary image
-   * @param gainmap_jpg_image_ptr destination of compressed gain map image
-   * @param (nullable) pExif EXIF package
-   * @param (nullable) pIcc ICC package
-   * @param icc_size length in bytes of ICC package
-   * @param metadata JPEG/R metadata to encode in XMP of the jpeg
-   * @param dest compressed JPEGR image
-   * @return NO_ERROR if calculation succeeds, error code if error occurs.
-   */
-  status_t appendGainMap(jr_compressed_ptr primary_jpg_image_ptr,
-                         jr_compressed_ptr gainmap_jpg_image_ptr, jr_exif_ptr pExif, void* pIcc,
-                         size_t icc_size, ultrahdr_metadata_ptr metadata, jr_compressed_ptr dest);
+  /*!\brief This method takes compressed sdr intent, compressed gainmap coefficient, gainmap
+   * metadata and creates a ultrahdr image. This is done by first generating XMP packet from gainmap
+   * metadata, then appending in the order,
+   *    SOI, APP2 (Exif is present), APP2 (XMP), base image, gain map image.
+   *
+   * NOTE: In the final output, EXIF package will appear if ONLY ONE of the following conditions is
+   * fulfilled:
+   * (1) EXIF package is available from outside input. I.e. pExif != nullptr.
+   * (2) Compressed sdr intent has EXIF.
+   * If both conditions are fulfilled, this method will return error indicating that it is unable to
+   * choose which exif to be placed in the bitstream.
+   *
+   * \param[in]       sdr_intent_compressed    sdr intent image descriptor
+   * \param[in]       gainmap_compressed       gainmap intent input image descriptor
+   * \param[in]       pExif                    exif block to be placed in the bitstream
+   * \param[in]       pIcc                     pointer to icc segment that needs to be added to the
+   *                                           compressed image
+   * \param[in]       icc_size                 size of icc segment
+   * \param[in]       metadata                 gainmap metadata descriptor
+   * \param[in, out]  dest                     output image descriptor to store compressed ultrahdr
+   *                                           image
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
+   */
+  uhdr_error_info_t appendGainMap(uhdr_compressed_image_t* sdr_intent_compressed,
+                                  uhdr_compressed_image_t* gainmap_compressed,
+                                  uhdr_mem_block_t* pExif, void* pIcc, size_t icc_size,
+                                  uhdr_gainmap_metadata_ext_t* metadata,
+                                  uhdr_compressed_image_t* dest);
 
-  /*
-   * This method will tone map a HDR image to an SDR image.
+  /*!\brief This method is used to tone map a hdr image
    *
-   * @param src pointer to uncompressed HDR image struct. HDR image is expected to be
-   *            in p010 color format
-   * @param dest pointer to store tonemapped SDR image
-   * @param hdr_tf transfer function of the HDR image
-   * @return NO_ERROR if calculation succeeds, error code if error occurs.
+   * \param[in]            hdr_intent      hdr image descriptor
+   * \param[in, out]       sdr_intent      sdr image descriptor
+   *
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  status_t toneMap(jr_uncompressed_ptr src, jr_uncompressed_ptr dest,
-                   ultrahdr_transfer_function hdr_tf);
+  uhdr_error_info_t toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent);
 
-  /*
-   * This method will convert a YUV420 image from one YUV encoding to another in-place (eg.
-   * Bt.709 to Bt.601 YUV encoding).
+  /*!\brief This method is used to convert a raw image from one gamut space to another gamut space
+   * in-place.
    *
-   * src_encoding and dest_encoding indicate the encoding via the YUV conversion defined for that
-   * gamut. P3 indicates Rec.601, since this is how DataSpace encodes Display-P3 YUV data.
+   * \param[in, out]  image              raw image descriptor
+   * \param[in]       src_encoding       input gamut space
+   * \param[in]       dst_encoding       destination gamut space
    *
-   * @param image the YUV420 image to convert
-   * @param src_encoding input YUV encoding
-   * @param dest_encoding output YUV encoding
-   * @return NO_ERROR if calculation succeeds, error code if error occurs.
+   * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, uhdr_codec_err_t otherwise.
    */
-  status_t convertYuv(jr_uncompressed_ptr image, ultrahdr_color_gamut src_encoding,
-                      ultrahdr_color_gamut dest_encoding);
+  uhdr_error_info_t convertYuv(uhdr_raw_image_t* image, uhdr_color_gamut_t src_encoding,
+                               uhdr_color_gamut_t dst_encoding);
 
   /*
    * This method will check the validity of the input arguments.
@@ -463,6 +594,16 @@ class JpegR {
                                   jr_uncompressed_ptr yuv420_image_ptr,
                                   ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest,
                                   int quality);
+
+  // Configurations
+  void* mUhdrGLESCtxt;              // opengl es context
+  size_t mMapDimensionScaleFactor;  // gain map scale factor
+  int mMapCompressQuality;          // gain map quality factor
+  bool mUseMultiChannelGainMap;     // enable multichannel gain map
+  float mGamma;                     // gain map gamma parameter
+  uhdr_enc_preset_t mEncPreset;     // encoding speed preset
+  float mMinContentBoost;           // min content boost recommendation
+  float mMaxContentBoost;           // max content boost recommendation
 };
 
 struct GlobalTonemapOutputs {
@@ -478,7 +619,8 @@ struct GlobalTonemapOutputs {
 // `rgb_out` is returned in this same range. `headroom` describes the ratio
 // between the HDR and SDR peak luminances and must be > 1. The `y_sdr` output
 // is in the range [0.0, 1.0] while `y_hdr` is in the range [0.0, headroom].
-GlobalTonemapOutputs hlgGlobalTonemap(const std::array<float, 3>& rgb_in, float headroom);
+GlobalTonemapOutputs globalTonemap(const std::array<float, 3>& rgb_in, float headroom,
+                                   float luminance);
 
 }  // namespace ultrahdr
 
diff --git a/lib/include/ultrahdr/jpegrutils.h b/lib/include/ultrahdr/jpegrutils.h
index ce523c8..2ddcb74 100644
--- a/lib/include/ultrahdr/jpegrutils.h
+++ b/lib/include/ultrahdr/jpegrutils.h
@@ -17,7 +17,6 @@
 #ifndef ULTRAHDR_JPEGRUTILS_H
 #define ULTRAHDR_JPEGRUTILS_H
 
-#include "ultrahdr/ultrahdr.h"
 #include "ultrahdr/jpegr.h"
 
 // TODO (dichenzhang): This is old version metadata, new version can be found in
@@ -34,7 +33,6 @@ static inline uint16_t EndianSwap16(uint16_t value) {
   return static_cast<uint16_t>((value >> 8) | ((value & 0xFF) << 8));
 }
 
-struct ultrahdr_metadata_struct;
 /*
  * Mutable data structure. Holds information for metadata.
  */
@@ -64,9 +62,10 @@ class DataStruct {
  * @param source source of data being written.
  * @param length length of the data to be written.
  * @param position cursor in desitination where the data is to be written.
- * @return status of succeed or error code.
+ * @return success or error code.
  */
-status_t Write(jr_compressed_ptr destination, const void* source, int length, int& position);
+uhdr_error_info_t Write(uhdr_compressed_image_t* destination, const void* source, int length,
+                        int& position);
 
 /*
  * Parses XMP packet and fills metadata with data from XMP
@@ -74,9 +73,10 @@ status_t Write(jr_compressed_ptr destination, const void* source, int length, in
  * @param xmp_data pointer to XMP packet
  * @param xmp_size size of XMP packet
  * @param metadata place to store HDR metadata values
- * @return true if metadata is successfully retrieved, false otherwise
+ * @return success or error code.
  */
-bool getMetadataFromXMP(uint8_t* xmp_data, int xmp_size, ultrahdr_metadata_struct* metadata);
+uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, int xmp_size,
+                                     uhdr_gainmap_metadata_ext_t* metadata);
 
 /*
  * This method generates XMP metadata for the primary image.
@@ -119,7 +119,7 @@ bool getMetadataFromXMP(uint8_t* xmp_data, int xmp_size, ultrahdr_metadata_struc
  * @return XMP metadata in type of string
  */
 std::string generateXmpForPrimaryImage(int secondary_image_length,
-                                       ultrahdr_metadata_struct& metadata);
+                                       uhdr_gainmap_metadata_ext_t& metadata);
 
 /*
  * This method generates XMP metadata for the recovery map image.
@@ -151,7 +151,8 @@ std::string generateXmpForPrimaryImage(int secondary_image_length,
  * @param metadata JPEG/R metadata to encode as XMP
  * @return XMP metadata in type of string
  */
-std::string generateXmpForSecondaryImage(ultrahdr_metadata_struct& metadata);
+std::string generateXmpForSecondaryImage(uhdr_gainmap_metadata_ext_t& metadata);
+
 }  // namespace ultrahdr
 
 #endif  // ULTRAHDR_JPEGRUTILS_H
diff --git a/lib/include/ultrahdr/multipictureformat.h b/lib/include/ultrahdr/multipictureformat.h
index 9a9141b..434b2ba 100644
--- a/lib/include/ultrahdr/multipictureformat.h
+++ b/lib/include/ultrahdr/multipictureformat.h
@@ -33,7 +33,6 @@
 #define Endian_SwapBE16(n) (n)
 #endif
 
-#include "ultrahdr/ultrahdr.h"
 #include "ultrahdr/jpegr.h"
 #include "ultrahdr/gainmapmath.h"
 #include "ultrahdr/jpegrutils.h"
diff --git a/lib/include/ultrahdr/ultrahdr.h b/lib/include/ultrahdr/ultrahdr.h
index 3170b1a..53617ba 100644
--- a/lib/include/ultrahdr/ultrahdr.h
+++ b/lib/include/ultrahdr/ultrahdr.h
@@ -21,8 +21,13 @@
 
 namespace ultrahdr {
 
-// The current JPEGR version that we encode to
-static const char* const kGainMapVersion = "1.0";
+#define JPEGR_CHECK(x)                \
+  {                                   \
+    status_t status = (x);            \
+    if ((status) != JPEGR_NO_ERROR) { \
+      return status;                  \
+    }                                 \
+  }
 
 // TODO (dichenzhang): rename these to "ULTRAHDR".
 typedef enum {
@@ -111,6 +116,69 @@ struct ultrahdr_metadata_struct {
   // HDR capacity to apply the map completely
   float hdrCapacityMax;
 };
+
+/*
+ * Holds information for uncompressed image or gain map.
+ */
+struct jpegr_uncompressed_struct {
+  // Pointer to the data location.
+  void* data;
+  // Width of the gain map or the luma plane of the image in pixels.
+  size_t width;
+  // Height of the gain map or the luma plane of the image in pixels.
+  size_t height;
+  // Color gamut.
+  ultrahdr_color_gamut colorGamut;
+
+  // Values below are optional
+  // Pointer to chroma data, if it's NULL, chroma plane is considered to be immediately
+  // after the luma plane.
+  void* chroma_data = nullptr;
+  // Stride of Y plane in number of pixels. 0 indicates the member is uninitialized. If
+  // non-zero this value must be larger than or equal to luma width. If stride is
+  // uninitialized then it is assumed to be equal to luma width.
+  size_t luma_stride = 0;
+  // Stride of UV plane in number of pixels.
+  // 1. If this handle points to P010 image then this value must be larger than
+  //    or equal to luma width.
+  // 2. If this handle points to 420 image then this value must be larger than
+  //    or equal to (luma width / 2).
+  // NOTE: if chroma_data is nullptr, chroma_stride is irrelevant. Just as the way,
+  // chroma_data is derived from luma ptr, chroma stride is derived from luma stride.
+  size_t chroma_stride = 0;
+  // Pixel format.
+  uhdr_img_fmt_t pixelFormat = UHDR_IMG_FMT_UNSPECIFIED;
+  // Color range.
+  uhdr_color_range_t colorRange = UHDR_CR_UNSPECIFIED;
+};
+
+/*
+ * Holds information for compressed image or gain map.
+ */
+struct jpegr_compressed_struct {
+  // Pointer to the data location.
+  void* data;
+  // Used data length in bytes.
+  int length;
+  // Maximum available data length in bytes.
+  int maxLength;
+  // Color gamut.
+  ultrahdr_color_gamut colorGamut;
+};
+
+/*
+ * Holds information for EXIF metadata.
+ */
+struct jpegr_exif_struct {
+  // Pointer to the data location.
+  void* data;
+  // Data length;
+  size_t length;
+};
+
+typedef struct jpegr_uncompressed_struct* jr_uncompressed_ptr;
+typedef struct jpegr_compressed_struct* jr_compressed_ptr;
+typedef struct jpegr_exif_struct* jr_exif_ptr;
 typedef struct ultrahdr_metadata_struct* ultrahdr_metadata_ptr;
 
 }  // namespace ultrahdr
diff --git a/lib/include/ultrahdr/ultrahdrcommon.h b/lib/include/ultrahdr/ultrahdrcommon.h
index 53c9e3d..e0c7cc1 100644
--- a/lib/include/ultrahdr/ultrahdrcommon.h
+++ b/lib/include/ultrahdr/ultrahdrcommon.h
@@ -19,6 +19,11 @@
 
 //#define LOG_NDEBUG 0
 
+#ifdef UHDR_ENABLE_GLES
+#include <EGL/egl.h>
+#include <GLES3/gl3.h>
+#endif
+
 #include <deque>
 #include <map>
 #include <memory>
@@ -119,6 +124,14 @@
 
 #define ALIGNM(x, m) ((((x) + ((m)-1)) / (m)) * (m))
 
+#define UHDR_ERR_CHECK(x)                     \
+  {                                           \
+    uhdr_error_info_t status = (x);           \
+    if (status.error_code != UHDR_CODEC_OK) { \
+      return status;                          \
+    }                                         \
+  }
+
 #if defined(_MSC_VER)
 #define FORCE_INLINE __forceinline
 #define INLINE __inline
@@ -127,8 +140,16 @@
 #define INLINE inline
 #endif
 
+static const uhdr_error_info_t g_no_error = {UHDR_CODEC_OK, 0, ""};
+
 namespace ultrahdr {
 
+// ===============================================================================================
+// Globals
+// ===============================================================================================
+extern const int kMinWidth, kMinHeight;
+extern const int kMaxWidth, kMaxHeight;
+
 // ===============================================================================================
 // Structure Definitions
 // ===============================================================================================
@@ -162,6 +183,147 @@ typedef struct uhdr_compressed_image_ext : uhdr_compressed_image_t {
 /*!\brief forward declaration for image effect descriptor */
 typedef struct uhdr_effect_desc uhdr_effect_desc_t;
 
+/**\brief Gain map metadata. */
+typedef struct uhdr_gainmap_metadata_ext : uhdr_gainmap_metadata {
+  uhdr_gainmap_metadata_ext() {}
+
+  uhdr_gainmap_metadata_ext(std::string ver) { version = ver; }
+
+  uhdr_gainmap_metadata_ext(uhdr_gainmap_metadata& metadata, std::string ver) {
+    max_content_boost = metadata.max_content_boost;
+    min_content_boost = metadata.min_content_boost;
+    gamma = metadata.gamma;
+    offset_sdr = metadata.offset_sdr;
+    offset_hdr = metadata.offset_hdr;
+    hdr_capacity_min = metadata.hdr_capacity_min;
+    hdr_capacity_max = metadata.hdr_capacity_max;
+    version = ver;
+  }
+
+  std::string version;         /**< Ultra HDR format version */
+} uhdr_gainmap_metadata_ext_t; /**< alias for struct uhdr_gainmap_metadata */
+
+#ifdef UHDR_ENABLE_GLES
+
+typedef enum uhdr_effect_shader {
+  UHDR_MIR_HORZ,
+  UHDR_MIR_VERT,
+  UHDR_ROT_90,
+  UHDR_ROT_180,
+  UHDR_ROT_270,
+  UHDR_CROP,
+  UHDR_RESIZE,
+} uhdr_effect_shader_t;
+
+/**\brief OpenGL context */
+typedef struct uhdr_opengl_ctxt {
+  // EGL Context
+  EGLDisplay mEGLDisplay; /**< EGL display connection */
+  EGLContext mEGLContext; /**< EGL rendering context */
+  EGLSurface mEGLSurface; /**< EGL surface for rendering */
+  EGLConfig mEGLConfig;   /**< EGL frame buffer configuration */
+
+  // GLES Context
+  GLuint mQuadVAO, mQuadVBO, mQuadEBO;           /**< GL objects */
+  GLuint mShaderProgram[UHDR_RESIZE + 1];        /**< Shader programs */
+  GLuint mDecodedImgTexture, mGainmapImgTexture; /**< GL Textures */
+  uhdr_error_info_t mErrorStatus;                /**< Context status */
+
+  uhdr_opengl_ctxt();
+  ~uhdr_opengl_ctxt();
+
+  /*!\brief Initializes the OpenGL context. Mainly it prepares EGL. We want a GLES3.0 context and a
+   * surface that supports pbuffer. Once this is done and surface is made current, the gl state is
+   * initialized
+   *
+   * \return none
+   */
+  void init_opengl_ctxt();
+
+  /*!\brief This method is used to compile a shader
+   *
+   * \param[in]   type    shader type
+   * \param[in]   source  shader source code
+   *
+   * \return GLuint #shader_id if operation succeeds, 0 otherwise.
+   */
+  GLuint compile_shader(GLenum type, const char* source);
+
+  /*!\brief This method is used to create a shader program
+   *
+   * \param[in]   vertex_source      vertex shader source code
+   * \param[in]   fragment_source    fragment shader source code
+   *
+   * \return GLuint #shader_program_id if operation succeeds, 0 otherwise.
+   */
+  GLuint create_shader_program(const char* vertex_source, const char* fragment_source);
+
+  /*!\brief This method is used to create a 2D texture for a raw image
+   * NOTE: For multichannel planar image, this method assumes the channel data to be contiguous
+   * NOTE: For any channel, this method assumes width and stride to be identical
+   *
+   * \param[in]   fmt       image format
+   * \param[in]   w         image width
+   * \param[in]   h         image height
+   * \param[in]   data      image data
+   *
+   * \return GLuint #texture_id if operation succeeds, 0 otherwise.
+   */
+  GLuint create_texture(uhdr_img_fmt_t fmt, int w, int h, void* data);
+
+  /*!\breif This method is used to read data from texture into a raw image
+   * NOTE: For any channel, this method assumes width and stride to be identical
+   *
+   * \param[in]   texture    texture_id
+   * \param[in]   fmt        image format
+   * \param[in]   w          image width
+   * \param[in]   h          image height
+   * \param[in]   data       image data
+   *
+   * \return none
+   */
+  void read_texture(GLuint* texture, uhdr_img_fmt_t fmt, int w, int h, void* data);
+
+  /*!\brief This method is used to set up quad buffers and arrays
+   *
+   * \return none
+   */
+  void setup_quad();
+
+  /*!\brief This method is used to set up frame buffer for a 2D texture
+   *
+   * \param[in]   texture         texture id
+   *
+   * \return GLuint #framebuffer_id if operation succeeds, 0 otherwise.
+   */
+  GLuint setup_framebuffer(GLuint& texture);
+
+  /*!\brief Checks for gl errors. On error, internal error state is updated with details
+   *
+   * \param[in]   msg     useful description for logging
+   *
+   * \return none
+   */
+  void check_gl_errors(const char* msg);
+
+  /*!\brief Reset the current context to default state for reuse
+   *
+   * \return none
+   */
+  void reset_opengl_ctxt();
+
+  /*!\brief Deletes the current context
+   *
+   * \return none
+   */
+  void delete_opengl_ctxt();
+
+} uhdr_opengl_ctxt_t; /**< alias for struct uhdr_opengl_ctxt */
+
+bool isBufferDataContiguous(uhdr_raw_image_t* img);
+
+#endif
+
 }  // namespace ultrahdr
 
 // ===============================================================================================
@@ -170,6 +332,11 @@ typedef struct uhdr_effect_desc uhdr_effect_desc_t;
 
 struct uhdr_codec_private {
   std::deque<ultrahdr::uhdr_effect_desc_t*> m_effects;
+#ifdef UHDR_ENABLE_GLES
+  ultrahdr::uhdr_opengl_ctxt_t m_uhdr_gl_ctxt;
+  bool m_enable_gles;
+#endif
+  bool m_sailed;
 
   virtual ~uhdr_codec_private();
 };
@@ -183,9 +350,14 @@ struct uhdr_encoder_private : uhdr_codec_private {
   std::vector<uint8_t> m_exif;
   uhdr_gainmap_metadata_t m_metadata;
   uhdr_codec_t m_output_format;
+  int m_gainmap_scale_factor;
+  bool m_use_multi_channel_gainmap;
+  float m_gamma;
+  uhdr_enc_preset_t m_enc_preset;
+  float m_min_content_boost;
+  float m_max_content_boost;
 
   // internal data
-  bool m_sailed;
   std::unique_ptr<ultrahdr::uhdr_compressed_image_ext_t> m_compressed_output_buffer;
   uhdr_error_info_t m_encode_call_status;
 };
@@ -199,17 +371,18 @@ struct uhdr_decoder_private : uhdr_codec_private {
 
   // internal data
   bool m_probed;
-  bool m_sailed;
   std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> m_decoded_img_buffer;
   std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> m_gainmap_img_buffer;
   int m_img_wd, m_img_ht;
-  int m_gainmap_wd, m_gainmap_ht;
+  int m_gainmap_wd, m_gainmap_ht, m_gainmap_num_comp;
   std::vector<uint8_t> m_exif;
   uhdr_mem_block_t m_exif_block;
   std::vector<uint8_t> m_icc;
   uhdr_mem_block_t m_icc_block;
-  std::vector<uint8_t> m_base_xmp;
-  std::vector<uint8_t> m_gainmap_xmp;
+  std::vector<uint8_t> m_base_img;
+  uhdr_mem_block_t m_base_img_block;
+  std::vector<uint8_t> m_gainmap_img;
+  uhdr_mem_block_t m_gainmap_img_block;
   uhdr_gainmap_metadata_t m_metadata;
   uhdr_error_info_t m_probe_call_status;
   uhdr_error_info_t m_decode_call_status;
diff --git a/lib/src/dsp/arm/editorhelper_neon.cpp b/lib/src/dsp/arm/editorhelper_neon.cpp
index 2ff9ad6..35b28a1 100644
--- a/lib/src/dsp/arm/editorhelper_neon.cpp
+++ b/lib/src/dsp/arm/editorhelper_neon.cpp
@@ -17,6 +17,7 @@
 #include <arm_neon.h>
 #include <cstring>
 
+#include "ultrahdr/dsp/arm/mem_neon.h"
 #include "ultrahdr/editorhelper.h"
 
 namespace ultrahdr {
@@ -47,21 +48,21 @@ static void mirror_buffer_horizontal_neon_uint8_t(uint8_t* src_buffer, uint8_t*
     int j = 0;
 
     for (; j + 64 <= src_w; src_blk -= 64, dst_blk += 64, j += 64) {
-      uint8x16x4_t s0 = vld1q_u8_x4(src_blk - 64);
+      uint8x16x4_t s0 = load_u8x16_x4(src_blk - 64);
       uint8x16x4_t d0;
       vrev128q_u8(s0.val[0], d0.val[3]);
       vrev128q_u8(s0.val[1], d0.val[2]);
       vrev128q_u8(s0.val[2], d0.val[1]);
       vrev128q_u8(s0.val[3], d0.val[0]);
-      vst1q_u8_x4(dst_blk, d0);
+      store_u8x16_x4(dst_blk, d0);
     }
 
     for (; j + 32 <= src_w; src_blk -= 32, dst_blk += 32, j += 32) {
-      uint8x16x2_t s0 = vld1q_u8_x2(src_blk - 32);
+      uint8x16x2_t s0 = load_u8x16_x2(src_blk - 32);
       uint8x16x2_t d0;
       vrev128q_u8(s0.val[0], d0.val[1]);
       vrev128q_u8(s0.val[1], d0.val[0]);
-      vst1q_u8_x2(dst_blk, d0);
+      store_u8x16_x2(dst_blk, d0);
     }
 
     for (; j + 16 <= src_w; src_blk -= 16, dst_blk += 16, j += 16) {
@@ -94,21 +95,21 @@ static void mirror_buffer_horizontal_neon_uint16_t(uint16_t* src_buffer, uint16_
     int j = 0;
 
     for (; j + 32 <= src_w; src_blk -= 32, dst_blk += 32, j += 32) {
-      uint16x8x4_t s0 = vld1q_u16_x4(src_blk - 32);
+      uint16x8x4_t s0 = load_u16x8_x4(src_blk - 32);
       uint16x8x4_t d0;
       vrev128q_u16(s0.val[0], d0.val[3]);
       vrev128q_u16(s0.val[1], d0.val[2]);
       vrev128q_u16(s0.val[2], d0.val[1]);
       vrev128q_u16(s0.val[3], d0.val[0]);
-      vst1q_u16_x4(dst_blk, d0);
+      store_u16x8_x4(dst_blk, d0);
     }
 
     for (; j + 16 <= src_w; src_blk -= 16, dst_blk += 16, j += 16) {
-      uint16x8x2_t s0 = vld1q_u16_x2(src_blk - 16);
+      uint16x8x2_t s0 = load_u16x8_x2(src_blk - 16);
       uint16x8x2_t d0;
       vrev128q_u16(s0.val[0], d0.val[1]);
       vrev128q_u16(s0.val[1], d0.val[0]);
-      vst1q_u16_x2(dst_blk, d0);
+      store_u16x8_x2(dst_blk, d0);
     }
 
     for (; j + 8 <= src_w; src_blk -= 8, dst_blk += 8, j += 8) {
@@ -135,21 +136,21 @@ static void mirror_buffer_horizontal_neon_uint32_t(uint32_t* src_buffer, uint32_
     int j = 0;
 
     for (; j + 16 <= src_w; src_blk -= 16, dst_blk += 16, j += 16) {
-      uint32x4x4_t s0 = vld1q_u32_x4(src_blk - 16);
+      uint32x4x4_t s0 = load_u32x4_x4(src_blk - 16);
       uint32x4x4_t d0;
       vrev128q_u32(s0.val[0], d0.val[3]);
       vrev128q_u32(s0.val[1], d0.val[2]);
       vrev128q_u32(s0.val[2], d0.val[1]);
       vrev128q_u32(s0.val[3], d0.val[0]);
-      vst1q_u32_x4(dst_blk, d0);
+      store_u32x4_x4(dst_blk, d0);
     }
 
     for (; j + 8 <= src_w; src_blk -= 8, dst_blk += 8, j += 8) {
-      uint32x4x2_t s0 = vld1q_u32_x2(src_blk - 8);
+      uint32x4x2_t s0 = load_u32x4_x2(src_blk - 8);
       uint32x4x2_t d0;
       vrev128q_u32(s0.val[0], d0.val[1]);
       vrev128q_u32(s0.val[1], d0.val[0]);
-      vst1q_u32_x2(dst_blk, d0);
+      store_u32x4_x2(dst_blk, d0);
     }
 
     for (; j + 4 <= src_w; src_blk -= 4, dst_blk += 4, j += 4) {
@@ -197,13 +198,13 @@ static void mirror_buffer_vertical_neon_uint8_t(uint8_t* src_buffer, uint8_t* ds
     int j = 0;
 
     for (; j + 64 <= src_w; src_blk += 64, dst_blk += 64, j += 64) {
-      uint8x16x4_t s0 = vld1q_u8_x4(src_blk);
-      vst1q_u8_x4(dst_blk, s0);
+      uint8x16x4_t s0 = load_u8x16_x4(src_blk);
+      store_u8x16_x4(dst_blk, s0);
     }
 
     for (; j + 32 <= src_w; src_blk += 32, dst_blk += 32, j += 32) {
-      uint8x16x2_t s0 = vld1q_u8_x2(src_blk);
-      vst1q_u8_x2(dst_blk, s0);
+      uint8x16x2_t s0 = load_u8x16_x2(src_blk);
+      store_u8x16_x2(dst_blk, s0);
     }
 
     for (; j + 16 <= src_w; src_blk += 16, dst_blk += 16, j += 16) {
@@ -232,13 +233,13 @@ static void mirror_buffer_vertical_neon_uint16_t(uint16_t* src_buffer, uint16_t*
     int j = 0;
 
     for (; j + 32 <= src_w; src_blk += 32, dst_blk += 32, j += 32) {
-      uint16x8x4_t s0 = vld1q_u16_x4(src_blk);
-      vst1q_u16_x4(dst_blk, s0);
+      uint16x8x4_t s0 = load_u16x8_x4(src_blk);
+      store_u16x8_x4(dst_blk, s0);
     }
 
     for (; j + 16 <= src_w; src_blk += 16, dst_blk += 16, j += 16) {
-      uint16x8x2_t s0 = vld1q_u16_x2(src_blk);
-      vst1q_u16_x2(dst_blk, s0);
+      uint16x8x2_t s0 = load_u16x8_x2(src_blk);
+      store_u16x8_x2(dst_blk, s0);
     }
 
     for (; j + 8 <= src_w; src_blk += 8, dst_blk += 8, j += 8) {
@@ -262,13 +263,13 @@ static void mirror_buffer_vertical_neon_uint32_t(uint32_t* src_buffer, uint32_t*
     int j = 0;
 
     for (; j + 16 <= src_w; src_blk += 16, dst_blk += 16, j += 16) {
-      uint32x4x4_t s0 = vld1q_u32_x4(src_blk);
-      vst1q_u32_x4(dst_blk, s0);
+      uint32x4x4_t s0 = load_u32x4_x4(src_blk);
+      store_u32x4_x4(dst_blk, s0);
     }
 
     for (; j + 8 <= src_w; src_blk += 8, dst_blk += 8, j += 8) {
-      uint32x4x2_t s0 = vld1q_u32_x2(src_blk);
-      vst1q_u32_x2(dst_blk, s0);
+      uint32x4x2_t s0 = load_u32x4_x2(src_blk);
+      store_u32x4_x2(dst_blk, s0);
     }
 
     for (; j + 4 <= src_w; src_blk += 4, dst_blk += 4, j += 4) {
@@ -376,7 +377,7 @@ static INLINE uint16x8x2_t vtrnq_u64_to_u16(uint32x4_t a0, uint32x4_t a1) {
   b0.val[0] =
       vcombine_u16(vreinterpret_u16_u32(vget_low_u32(a0)), vreinterpret_u16_u32(vget_low_u32(a1)));
   b0.val[1] = vcombine_u16(vreinterpret_u16_u32(vget_high_u32(a0)),
-                           vreinterpret_u16_u32(vget_high_s32(a1)));
+                           vreinterpret_u16_u32(vget_high_u32(a1)));
 #endif
   return b0;
 }
diff --git a/lib/src/dsp/arm/gainmapmath_neon.cpp b/lib/src/dsp/arm/gainmapmath_neon.cpp
index f23767e..b6b879f 100644
--- a/lib/src/dsp/arm/gainmapmath_neon.cpp
+++ b/lib/src/dsp/arm/gainmapmath_neon.cpp
@@ -19,6 +19,12 @@
 #include <arm_neon.h>
 #include <cassert>
 
+#ifdef _MSC_VER
+#define ALIGNED(x) __declspec(align(x))
+#else
+#define ALIGNED(x) __attribute__((aligned(x)))
+#endif
+
 namespace ultrahdr {
 
 // Scale all coefficients by 2^14 to avoid needing floating-point arithmetic. This can cause an off
@@ -32,49 +38,49 @@ namespace ultrahdr {
 // Y' = (1.0f * Y) + ( 0.101579f * U) + ( 0.196076f * V)
 // U' = (0.0f * Y) + ( 0.989854f * U) + (-0.110653f * V)
 // V' = (0.0f * Y) + (-0.072453f * U) + ( 0.983398f * V)
-__attribute__((aligned(16)))
+ALIGNED(16)
 const int16_t kYuv709To601_coeffs_neon[8] = {1664, 3213, 16218, -1813, -1187, 16112, 0, 0};
 
 // Yuv Bt709 -> Yuv Bt2100
 // Y' = (1.0f * Y) + (-0.016969f * U) + ( 0.096312f * V)
 // U' = (0.0f * Y) + ( 0.995306f * U) + (-0.051192f * V)
 // V' = (0.0f * Y) + ( 0.011507f * U) + ( 1.002637f * V)
-__attribute__((aligned(16)))
+ALIGNED(16)
 const int16_t kYuv709To2100_coeffs_neon[8] = {-278, 1578, 16307, -839, 189, 16427, 0, 0};
 
 // Yuv Bt601 -> Yuv Bt709
 // Y' = (1.0f * Y) + (-0.118188f * U) + (-0.212685f * V),
 // U' = (0.0f * Y) + ( 1.018640f * U) + ( 0.114618f * V),
 // V' = (0.0f * Y) + ( 0.075049f * U) + ( 1.025327f * V);
-__attribute__((aligned(16)))
+ALIGNED(16)
 const int16_t kYuv601To709_coeffs_neon[8] = {-1936, -3485, 16689, 1878, 1230, 16799, 0, 0};
 
 // Yuv Bt601 -> Yuv Bt2100
 // Y' = (1.0f * Y) + (-0.128245f * U) + (-0.115879f * V)
 // U' = (0.0f * Y) + ( 1.010016f * U) + ( 0.061592f * V)
 // V' = (0.0f * Y) + ( 0.086969f * U) + ( 1.029350f * V)
-__attribute__((aligned(16)))
+ALIGNED(16)
 const int16_t kYuv601To2100_coeffs_neon[8] = {-2101, -1899, 16548, 1009, 1425, 16865, 0, 0};
 
 // Yuv Bt2100 -> Yuv Bt709
 // Y' = (1.0f * Y) + ( 0.018149f * U) + (-0.095132f * V)
 // U' = (0.0f * Y) + ( 1.004123f * U) + ( 0.051267f * V)
 // V' = (0.0f * Y) + (-0.011524f * U) + ( 0.996782f * V)
-__attribute__((aligned(16)))
+ALIGNED(16)
 const int16_t kYuv2100To709_coeffs_neon[8] = {297, -1559, 16452, 840, -189, 16331, 0, 0};
 
 // Yuv Bt2100 -> Yuv Bt601
 // Y' = (1.0f * Y) + ( 0.117887f * U) + ( 0.105521f * V)
 // U' = (0.0f * Y) + ( 0.995211f * U) + (-0.059549f * V)
 // V' = (0.0f * Y) + (-0.084085f * U) + ( 0.976518f * V)
-__attribute__((aligned(16)))
+ALIGNED(16)
 const int16_t kYuv2100To601_coeffs_neon[8] = {1931, 1729, 16306, -976, -1378, 15999, 0, 0};
 
 static inline int16x8_t yConversion_neon(uint8x8_t y, int16x8_t u, int16x8_t v, int16x8_t coeffs) {
-  int32x4_t lo = vmull_laneq_s16(vget_low_s16(u), coeffs, 0);
-  int32x4_t hi = vmull_laneq_s16(vget_high_s16(u), coeffs, 0);
-  lo = vmlal_laneq_s16(lo, vget_low_s16(v), coeffs, 1);
-  hi = vmlal_laneq_s16(hi, vget_high_s16(v), coeffs, 1);
+  int32x4_t lo = vmull_lane_s16(vget_low_s16(u), vget_low_s16(coeffs), 0);
+  int32x4_t hi = vmull_lane_s16(vget_high_s16(u), vget_low_s16(coeffs), 0);
+  lo = vmlal_lane_s16(lo, vget_low_s16(v), vget_low_s16(coeffs), 1);
+  hi = vmlal_lane_s16(hi, vget_high_s16(v), vget_low_s16(coeffs), 1);
 
   // Descale result to account for coefficients being scaled by 2^14.
   uint16x8_t y_output =
@@ -83,10 +89,10 @@ static inline int16x8_t yConversion_neon(uint8x8_t y, int16x8_t u, int16x8_t v,
 }
 
 static inline int16x8_t uConversion_neon(int16x8_t u, int16x8_t v, int16x8_t coeffs) {
-  int32x4_t u_lo = vmull_laneq_s16(vget_low_s16(u), coeffs, 2);
-  int32x4_t u_hi = vmull_laneq_s16(vget_high_s16(u), coeffs, 2);
-  u_lo = vmlal_laneq_s16(u_lo, vget_low_s16(v), coeffs, 3);
-  u_hi = vmlal_laneq_s16(u_hi, vget_high_s16(v), coeffs, 3);
+  int32x4_t u_lo = vmull_lane_s16(vget_low_s16(u), vget_low_s16(coeffs), 2);
+  int32x4_t u_hi = vmull_lane_s16(vget_high_s16(u), vget_low_s16(coeffs), 2);
+  u_lo = vmlal_lane_s16(u_lo, vget_low_s16(v), vget_low_s16(coeffs), 3);
+  u_hi = vmlal_lane_s16(u_hi, vget_high_s16(v), vget_low_s16(coeffs), 3);
 
   // Descale result to account for coefficients being scaled by 2^14.
   const int16x8_t u_output = vcombine_s16(vqrshrn_n_s32(u_lo, 14), vqrshrn_n_s32(u_hi, 14));
@@ -94,10 +100,10 @@ static inline int16x8_t uConversion_neon(int16x8_t u, int16x8_t v, int16x8_t coe
 }
 
 static inline int16x8_t vConversion_neon(int16x8_t u, int16x8_t v, int16x8_t coeffs) {
-  int32x4_t v_lo = vmull_laneq_s16(vget_low_s16(u), coeffs, 4);
-  int32x4_t v_hi = vmull_laneq_s16(vget_high_s16(u), coeffs, 4);
-  v_lo = vmlal_laneq_s16(v_lo, vget_low_s16(v), coeffs, 5);
-  v_hi = vmlal_laneq_s16(v_hi, vget_high_s16(v), coeffs, 5);
+  int32x4_t v_lo = vmull_lane_s16(vget_low_s16(u), vget_high_s16(coeffs), 0);
+  int32x4_t v_hi = vmull_lane_s16(vget_high_s16(u), vget_high_s16(coeffs), 0);
+  v_lo = vmlal_lane_s16(v_lo, vget_low_s16(v), vget_high_s16(coeffs), 1);
+  v_hi = vmlal_lane_s16(v_hi, vget_high_s16(v), vget_high_s16(coeffs), 1);
 
   // Descale result to account for coefficients being scaled by 2^14.
   const int16x8_t v_output = vcombine_s16(vqrshrn_n_s32(v_lo, 14), vqrshrn_n_s32(v_hi, 14));
@@ -111,13 +117,13 @@ int16x8x3_t yuvConversion_neon(uint8x8_t y, int16x8_t u, int16x8_t v, int16x8_t
   return {y_output, u_output, v_output};
 }
 
-void transformYuv420_neon(jr_uncompressed_ptr image, const int16_t* coeffs_ptr) {
+void transformYuv420_neon(uhdr_raw_image_t* image, const int16_t* coeffs_ptr) {
   // Implementation assumes image buffer is multiple of 16.
-  assert(image->width % 16 == 0);
-  uint8_t* y0_ptr = static_cast<uint8_t*>(image->data);
-  uint8_t* y1_ptr = y0_ptr + image->luma_stride;
-  uint8_t* u_ptr = static_cast<uint8_t*>(image->chroma_data);
-  uint8_t* v_ptr = u_ptr + image->chroma_stride * (image->height / 2);
+  assert(image->w % 16 == 0);
+  uint8_t* y0_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
+  uint8_t* y1_ptr = y0_ptr + image->stride[UHDR_PLANE_Y];
+  uint8_t* u_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_U]);
+  uint8_t* v_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_V]);
 
   const int16x8_t coeffs = vld1q_s16(coeffs_ptr);
   const uint16x8_t uv_bias = vreinterpretq_u16_s16(vdupq_n_s16(-128));
@@ -135,10 +141,10 @@ void transformYuv420_neon(jr_uncompressed_ptr image, const int16_t* coeffs_ptr)
       int16x8_t u_wide_s16 = vreinterpretq_s16_u16(vaddw_u8(uv_bias, u));  // -128 + u
       int16x8_t v_wide_s16 = vreinterpretq_s16_u16(vaddw_u8(uv_bias, v));  // -128 + v
 
-      const int16x8_t u_wide_lo = vzip1q_s16(u_wide_s16, u_wide_s16);
-      const int16x8_t u_wide_hi = vzip2q_s16(u_wide_s16, u_wide_s16);
-      const int16x8_t v_wide_lo = vzip1q_s16(v_wide_s16, v_wide_s16);
-      const int16x8_t v_wide_hi = vzip2q_s16(v_wide_s16, v_wide_s16);
+      const int16x8_t u_wide_lo = vzipq_s16(u_wide_s16, u_wide_s16).val[0];
+      const int16x8_t u_wide_hi = vzipq_s16(u_wide_s16, u_wide_s16).val[1];
+      const int16x8_t v_wide_lo = vzipq_s16(v_wide_s16, v_wide_s16).val[0];
+      const int16x8_t v_wide_hi = vzipq_s16(v_wide_s16, v_wide_s16).val[1];
 
       const int16x8_t y0_lo = yConversion_neon(vget_low_u8(y0), u_wide_lo, v_wide_lo, coeffs);
       const int16x8_t y0_hi = yConversion_neon(vget_high_u8(y0), u_wide_hi, v_wide_hi, coeffs);
@@ -160,83 +166,155 @@ void transformYuv420_neon(jr_uncompressed_ptr image, const int16_t* coeffs_ptr)
       vst1_u8(v_ptr + w, v_output);
 
       w += 8;
-    } while (w < image->width / 2);
-    y0_ptr += image->luma_stride * 2;
-    y1_ptr += image->luma_stride * 2;
-    u_ptr += image->chroma_stride;
-    v_ptr += image->chroma_stride;
-  } while (++h < image->height / 2);
+    } while (w < image->w / 2);
+    y0_ptr += image->stride[UHDR_PLANE_Y] * 2;
+    y1_ptr += image->stride[UHDR_PLANE_Y] * 2;
+    u_ptr += image->stride[UHDR_PLANE_U];
+    v_ptr += image->stride[UHDR_PLANE_V];
+  } while (++h < image->h / 2);
 }
 
-status_t convertYuv_neon(jr_uncompressed_ptr image, ultrahdr_color_gamut src_encoding,
-                         ultrahdr_color_gamut dst_encoding) {
-  if (image == nullptr) {
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (src_encoding == ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
-      dst_encoding == ULTRAHDR_COLORGAMUT_UNSPECIFIED) {
-    return ERROR_JPEGR_INVALID_COLORGAMUT;
-  }
+void transformYuv444_neon(uhdr_raw_image_t* image, const int16_t* coeffs_ptr) {
+  // Implementation assumes image buffer is multiple of 16.
+  assert(image->w % 16 == 0);
+  uint8_t* y_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
+  uint8_t* u_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_U]);
+  uint8_t* v_ptr = static_cast<uint8_t*>(image->planes[UHDR_PLANE_V]);
+
+  const int16x8_t coeffs = vld1q_s16(coeffs_ptr);
+  const uint16x8_t uv_bias = vreinterpretq_u16_s16(vdupq_n_s16(-128));
+  size_t h = 0;
+  do {
+    size_t w = 0;
+    do {
+      uint8x16_t y = vld1q_u8(y_ptr + w);
+      uint8x16_t u = vld1q_u8(u_ptr + w);
+      uint8x16_t v = vld1q_u8(v_ptr + w);
+
+      // 128 bias for UV given we are using libjpeg; see:
+      // https://github.com/kornelski/libjpeg/blob/master/structure.doc
+      int16x8_t u_wide_low_s16 =
+          vreinterpretq_s16_u16(vaddw_u8(uv_bias, vget_low_u8(u)));  // -128 + u
+      int16x8_t v_wide_low_s16 =
+          vreinterpretq_s16_u16(vaddw_u8(uv_bias, vget_low_u8(v)));  // -128 + v
+      int16x8_t u_wide_high_s16 =
+          vreinterpretq_s16_u16(vaddw_u8(uv_bias, vget_high_u8(u)));  // -128 + u
+      int16x8_t v_wide_high_s16 =
+          vreinterpretq_s16_u16(vaddw_u8(uv_bias, vget_high_u8(v)));  // -128 + v
+
+      const int16x8_t y_lo =
+          yConversion_neon(vget_low_u8(y), u_wide_low_s16, v_wide_low_s16, coeffs);
+      const int16x8_t y_hi =
+          yConversion_neon(vget_high_u8(y), u_wide_high_s16, v_wide_high_s16, coeffs);
+
+      const int16x8_t new_u_lo = uConversion_neon(u_wide_low_s16, v_wide_low_s16, coeffs);
+      const int16x8_t new_v_lo = vConversion_neon(u_wide_low_s16, v_wide_low_s16, coeffs);
+      const int16x8_t new_u_hi = uConversion_neon(u_wide_high_s16, v_wide_high_s16, coeffs);
+      const int16x8_t new_v_hi = vConversion_neon(u_wide_high_s16, v_wide_high_s16, coeffs);
 
+      // Narrow from 16-bit to 8-bit with saturation.
+      const uint8x16_t y_output = vcombine_u8(vqmovun_s16(y_lo), vqmovun_s16(y_hi));
+      const uint8x8_t u_output_lo = vqmovun_s16(vaddq_s16(new_u_lo, vdupq_n_s16(128)));
+      const uint8x8_t u_output_hi = vqmovun_s16(vaddq_s16(new_u_hi, vdupq_n_s16(128)));
+      const uint8x8_t v_output_lo = vqmovun_s16(vaddq_s16(new_v_lo, vdupq_n_s16(128)));
+      const uint8x8_t v_output_hi = vqmovun_s16(vaddq_s16(new_v_hi, vdupq_n_s16(128)));
+      const uint8x16_t u_output = vcombine_u8(u_output_lo, u_output_hi);
+      const uint8x16_t v_output = vcombine_u8(v_output_lo, v_output_hi);
+
+      vst1q_u8(y_ptr + w, y_output);
+      vst1q_u8(u_ptr + w, u_output);
+      vst1q_u8(v_ptr + w, v_output);
+
+      w += 16;
+    } while (w < image->w);
+    y_ptr += image->stride[UHDR_PLANE_Y];
+    u_ptr += image->stride[UHDR_PLANE_U];
+    v_ptr += image->stride[UHDR_PLANE_V];
+  } while (++h < image->h);
+}
+
+uhdr_error_info_t convertYuv_neon(uhdr_raw_image_t* image, uhdr_color_gamut_t src_encoding,
+                                  uhdr_color_gamut_t dst_encoding) {
+  uhdr_error_info_t status = g_no_error;
   const int16_t* coeffs = nullptr;
+
   switch (src_encoding) {
-    case ULTRAHDR_COLORGAMUT_BT709:
+    case UHDR_CG_BT_709:
       switch (dst_encoding) {
-        case ULTRAHDR_COLORGAMUT_BT709:
-          return JPEGR_NO_ERROR;
-        case ULTRAHDR_COLORGAMUT_P3:
+        case UHDR_CG_BT_709:
+          return status;
+        case UHDR_CG_DISPLAY_P3:
           coeffs = kYuv709To601_coeffs_neon;
           break;
-        case ULTRAHDR_COLORGAMUT_BT2100:
+        case UHDR_CG_BT_2100:
           coeffs = kYuv709To2100_coeffs_neon;
           break;
         default:
-          // Should be impossible to hit after input validation
-          return ERROR_JPEGR_INVALID_COLORGAMUT;
+          status.error_code = UHDR_CODEC_INVALID_PARAM;
+          status.has_detail = 1;
+          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
+                   dst_encoding);
+          return status;
       }
       break;
-    case ULTRAHDR_COLORGAMUT_P3:
+    case UHDR_CG_DISPLAY_P3:
       switch (dst_encoding) {
-        case ULTRAHDR_COLORGAMUT_BT709:
+        case UHDR_CG_BT_709:
           coeffs = kYuv601To709_coeffs_neon;
           break;
-        case ULTRAHDR_COLORGAMUT_P3:
-          return JPEGR_NO_ERROR;
-        case ULTRAHDR_COLORGAMUT_BT2100:
+        case UHDR_CG_DISPLAY_P3:
+          return status;
+        case UHDR_CG_BT_2100:
           coeffs = kYuv601To2100_coeffs_neon;
           break;
         default:
-          // Should be impossible to hit after input validation
-          return ERROR_JPEGR_INVALID_COLORGAMUT;
+          status.error_code = UHDR_CODEC_INVALID_PARAM;
+          status.has_detail = 1;
+          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
+                   dst_encoding);
+          return status;
       }
       break;
-    case ULTRAHDR_COLORGAMUT_BT2100:
+    case UHDR_CG_BT_2100:
       switch (dst_encoding) {
-        case ULTRAHDR_COLORGAMUT_BT709:
+        case UHDR_CG_BT_709:
           coeffs = kYuv2100To709_coeffs_neon;
           break;
-        case ULTRAHDR_COLORGAMUT_P3:
+        case UHDR_CG_DISPLAY_P3:
           coeffs = kYuv2100To601_coeffs_neon;
           break;
-        case ULTRAHDR_COLORGAMUT_BT2100:
-          return JPEGR_NO_ERROR;
+        case UHDR_CG_BT_2100:
+          return status;
         default:
-          // Should be impossible to hit after input validation
-          return ERROR_JPEGR_INVALID_COLORGAMUT;
+          status.error_code = UHDR_CODEC_INVALID_PARAM;
+          status.has_detail = 1;
+          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
+                   dst_encoding);
+          return status;
       }
       break;
     default:
-      // Should be impossible to hit after input validation
-      return ERROR_JPEGR_INVALID_COLORGAMUT;
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "Unrecognized src color gamut %d",
+               src_encoding);
+      return status;
   }
 
-  if (coeffs == nullptr) {
-    // Should be impossible to hit after input validation
-    return ERROR_JPEGR_INVALID_COLORGAMUT;
+  if (image->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+    transformYuv420_neon(image, coeffs);
+  } else if (image->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
+    transformYuv444_neon(image, coeffs);
+  } else {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for performing gamut conversion for color format %d",
+             image->fmt);
+    return status;
   }
 
-  transformYuv420_neon(image, coeffs);
-  return JPEGR_NO_ERROR;
+  return status;
 }
 
 }  // namespace ultrahdr
diff --git a/lib/src/editorhelper.cpp b/lib/src/editorhelper.cpp
index d86cc09..f916723 100644
--- a/lib/src/editorhelper.cpp
+++ b/lib/src/editorhelper.cpp
@@ -186,7 +186,17 @@ uhdr_resize_effect::uhdr_resize_effect(int width, int height) : m_width{width},
 }
 
 std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate(ultrahdr::uhdr_rotate_effect_t* desc,
-                                                   uhdr_raw_image_t* src) {
+                                                   uhdr_raw_image_t* src,
+                                                   [[maybe_unused]] void* gl_ctxt,
+                                                   [[maybe_unused]] void* texture) {
+#ifdef UHDR_ENABLE_GLES
+  if ((src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
+       src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) &&
+      gl_ctxt != nullptr && *static_cast<GLuint*>(texture) != 0) {
+    return apply_rotate_gles(desc, src, static_cast<ultrahdr::uhdr_opengl_ctxt*>(gl_ctxt),
+                             static_cast<GLuint*>(texture));
+  }
+#endif
   std::unique_ptr<uhdr_raw_image_ext_t> dst;
 
   if (desc->m_degree == 90 || desc->m_degree == 270) {
@@ -232,12 +242,36 @@ std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate(ultrahdr::uhdr_rotate_effect_
     uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
     desc->m_rotate_uint64_t(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_PACKED],
                             dst->stride[UHDR_PLANE_PACKED], desc->m_degree);
+  } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
+    for (int i = 0; i < 3; i++) {
+      uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[i]);
+      uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
+      desc->m_rotate_uint8_t(src_buffer, dst_buffer, src->w, src->h, src->stride[i], dst->stride[i],
+                             desc->m_degree);
+    }
+  } else if (src->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
+    for (int i = 0; i < 3; i++) {
+      uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[i]);
+      uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[i]);
+      desc->m_rotate_uint16_t(src_buffer, dst_buffer, src->w, src->h, src->stride[i],
+                              dst->stride[i], desc->m_degree);
+    }
   }
   return dst;
 }
 
 std::unique_ptr<uhdr_raw_image_ext_t> apply_mirror(ultrahdr::uhdr_mirror_effect_t* desc,
-                                                   uhdr_raw_image_t* src) {
+                                                   uhdr_raw_image_t* src,
+                                                   [[maybe_unused]] void* gl_ctxt,
+                                                   [[maybe_unused]] void* texture) {
+#ifdef UHDR_ENABLE_GLES
+  if ((src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
+       src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) &&
+      gl_ctxt != nullptr && *static_cast<GLuint*>(texture) != 0) {
+    return apply_mirror_gles(desc, src, static_cast<ultrahdr::uhdr_opengl_ctxt*>(gl_ctxt),
+                             static_cast<GLuint*>(texture));
+  }
+#endif
   std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
       src->fmt, src->cg, src->ct, src->range, src->w, src->h, 64);
 
@@ -274,11 +308,35 @@ std::unique_ptr<uhdr_raw_image_ext_t> apply_mirror(ultrahdr::uhdr_mirror_effect_
     uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
     desc->m_mirror_uint64_t(src_buffer, dst_buffer, src->w, src->h, src->stride[UHDR_PLANE_PACKED],
                             dst->stride[UHDR_PLANE_PACKED], desc->m_direction);
+  } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
+    for (int i = 0; i < 3; i++) {
+      uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[i]);
+      uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
+      desc->m_mirror_uint8_t(src_buffer, dst_buffer, src->w, src->h, src->stride[i], dst->stride[i],
+                             desc->m_direction);
+    }
+  } else if (src->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
+    for (int i = 0; i < 3; i++) {
+      uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[i]);
+      uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[i]);
+      desc->m_mirror_uint16_t(src_buffer, dst_buffer, src->w, src->h, src->stride[i],
+                              dst->stride[i], desc->m_direction);
+    }
   }
   return dst;
 }
 
-void apply_crop(uhdr_raw_image_t* src, int left, int top, int wd, int ht) {
+void apply_crop(uhdr_raw_image_t* src, int left, int top, int wd, int ht,
+                [[maybe_unused]] void* gl_ctxt, [[maybe_unused]] void* texture) {
+#ifdef UHDR_ENABLE_GLES
+  if ((src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
+       src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) &&
+      gl_ctxt != nullptr && *static_cast<GLuint*>(texture) != 0) {
+    return apply_crop_gles(src, left, top, wd, ht,
+                           static_cast<ultrahdr::uhdr_opengl_ctxt*>(gl_ctxt),
+                           static_cast<GLuint*>(texture));
+  }
+#endif
   if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
     uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[UHDR_PLANE_Y]);
     src->planes[UHDR_PLANE_Y] = &src_buffer[top * src->stride[UHDR_PLANE_Y] + left];
@@ -300,13 +358,33 @@ void apply_crop(uhdr_raw_image_t* src, int left, int top, int wd, int ht) {
   } else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
     uint64_t* src_buffer = static_cast<uint64_t*>(src->planes[UHDR_PLANE_PACKED]);
     src->planes[UHDR_PLANE_PACKED] = &src_buffer[top * src->stride[UHDR_PLANE_PACKED] + left];
+  } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
+    for (int i = 0; i < 3; i++) {
+      uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[i]);
+      src->planes[i] = &src_buffer[top * src->stride[i] + left];
+    }
+  } else if (src->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
+    for (int i = 0; i < 3; i++) {
+      uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[i]);
+      src->planes[i] = &src_buffer[top * src->stride[i] + left];
+    }
   }
   src->w = wd;
   src->h = ht;
 }
 
 std::unique_ptr<uhdr_raw_image_ext_t> apply_resize(ultrahdr::uhdr_resize_effect_t* desc,
-                                                   uhdr_raw_image_t* src, int dst_w, int dst_h) {
+                                                   uhdr_raw_image_t* src, int dst_w, int dst_h,
+                                                   [[maybe_unused]] void* gl_ctxt,
+                                                   [[maybe_unused]] void* texture) {
+#ifdef UHDR_ENABLE_GLES
+  if ((src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
+       src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat || src->fmt == UHDR_IMG_FMT_8bppYCbCr400) &&
+      gl_ctxt != nullptr && *static_cast<GLuint*>(texture) != 0) {
+    return apply_resize_gles(src, dst_w, dst_h, static_cast<ultrahdr::uhdr_opengl_ctxt*>(gl_ctxt),
+                             static_cast<GLuint*>(texture));
+  }
+#endif
   std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
       src->fmt, src->cg, src->ct, src->range, dst_w, dst_h, 64);
 
@@ -343,6 +421,20 @@ std::unique_ptr<uhdr_raw_image_ext_t> apply_resize(ultrahdr::uhdr_resize_effect_
     uint64_t* dst_buffer = static_cast<uint64_t*>(dst->planes[UHDR_PLANE_PACKED]);
     desc->m_resize_uint64_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
                             src->stride[UHDR_PLANE_PACKED], dst->stride[UHDR_PLANE_PACKED]);
+  } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
+    for (int i = 0; i < 3; i++) {
+      uint8_t* src_buffer = static_cast<uint8_t*>(src->planes[i]);
+      uint8_t* dst_buffer = static_cast<uint8_t*>(dst->planes[i]);
+      desc->m_resize_uint8_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h, src->stride[i],
+                             dst->stride[i]);
+    }
+  } else if (src->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
+    for (int i = 0; i < 3; i++) {
+      uint16_t* src_buffer = static_cast<uint16_t*>(src->planes[i]);
+      uint16_t* dst_buffer = static_cast<uint16_t*>(dst->planes[i]);
+      desc->m_resize_uint16_t(src_buffer, dst_buffer, src->w, src->h, dst->w, dst->h,
+                              src->stride[i], dst->stride[i]);
+    }
   }
   return dst;
 }
diff --git a/lib/src/gainmapmath.cpp b/lib/src/gainmapmath.cpp
index 19b421b..47e9eac 100644
--- a/lib/src/gainmapmath.cpp
+++ b/lib/src/gainmapmath.cpp
@@ -15,55 +15,11 @@
  */
 
 #include <cmath>
+
 #include "ultrahdr/gainmapmath.h"
 
 namespace ultrahdr {
 
-static const std::vector<float> kPqOETF = [] {
-  std::vector<float> result;
-  for (size_t idx = 0; idx < kPqOETFNumEntries; idx++) {
-    float value = static_cast<float>(idx) / static_cast<float>(kPqOETFNumEntries - 1);
-    result.push_back(pqOetf(value));
-  }
-  return result;
-}();
-
-static const std::vector<float> kPqInvOETF = [] {
-  std::vector<float> result;
-  for (size_t idx = 0; idx < kPqInvOETFNumEntries; idx++) {
-    float value = static_cast<float>(idx) / static_cast<float>(kPqInvOETFNumEntries - 1);
-    result.push_back(pqInvOetf(value));
-  }
-  return result;
-}();
-
-static const std::vector<float> kHlgOETF = [] {
-  std::vector<float> result;
-  for (size_t idx = 0; idx < kHlgOETFNumEntries; idx++) {
-    float value = static_cast<float>(idx) / static_cast<float>(kHlgOETFNumEntries - 1);
-    result.push_back(hlgOetf(value));
-  }
-  return result;
-}();
-
-static const std::vector<float> kHlgInvOETF = [] {
-  std::vector<float> result;
-  for (size_t idx = 0; idx < kHlgInvOETFNumEntries; idx++) {
-    float value = static_cast<float>(idx) / static_cast<float>(kHlgInvOETFNumEntries - 1);
-    result.push_back(hlgInvOetf(value));
-  }
-  return result;
-}();
-
-static const std::vector<float> kSrgbInvOETF = [] {
-  std::vector<float> result;
-  for (size_t idx = 0; idx < kSrgbInvOETFNumEntries; idx++) {
-    float value = static_cast<float>(idx) / static_cast<float>(kSrgbInvOETFNumEntries - 1);
-    result.push_back(srgbInvOetf(value));
-  }
-  return result;
-}();
-
 // Use Shepard's method for inverse distance weighting. For more information:
 // en.wikipedia.org/wiki/Inverse_distance_weighting#Shepard's_method
 
@@ -159,7 +115,8 @@ float srgbInvOetfLUT(float e_gamma) {
   int32_t value = static_cast<int32_t>(e_gamma * (kSrgbInvOETFNumEntries - 1) + 0.5);
   // TODO() : Remove once conversion modules have appropriate clamping in place
   value = CLIP3(value, 0, kSrgbInvOETFNumEntries - 1);
-  return kSrgbInvOETF[value];
+  static LookUpTable kSrgbLut(kSrgbInvOETFNumEntries, static_cast<float (*)(float)>(srgbInvOetf));
+  return kSrgbLut.getTable()[value];
 }
 
 Color srgbInvOetfLUT(Color e_gamma) {
@@ -167,11 +124,11 @@ Color srgbInvOetfLUT(Color e_gamma) {
 }
 
 float srgbOetf(float e) {
-  constexpr float kThreshold = 0.00304;
+  constexpr float kThreshold = 0.0031308;
   constexpr float kLowSlope = 12.92;
   constexpr float kHighOffset = 0.055;
   constexpr float kPowerExponent = 1.0 / 2.4;
-  if (e < kThreshold) {
+  if (e <= kThreshold) {
     return kLowSlope * e;
   }
   return (1.0 + kHighOffset) * std::pow(e, kPowerExponent) - kHighOffset;
@@ -279,8 +236,8 @@ float hlgOetfLUT(float e) {
   int32_t value = static_cast<int32_t>(e * (kHlgOETFNumEntries - 1) + 0.5);
   // TODO() : Remove once conversion modules have appropriate clamping in place
   value = CLIP3(value, 0, kHlgOETFNumEntries - 1);
-
-  return kHlgOETF[value];
+  static LookUpTable kHlgLut(kHlgOETFNumEntries, static_cast<float (*)(float)>(hlgOetf));
+  return kHlgLut.getTable()[value];
 }
 
 Color hlgOetfLUT(Color e) { return {{{hlgOetfLUT(e.r), hlgOetfLUT(e.g), hlgOetfLUT(e.b)}}}; }
@@ -302,8 +259,8 @@ float hlgInvOetfLUT(float e_gamma) {
   int32_t value = static_cast<int32_t>(e_gamma * (kHlgInvOETFNumEntries - 1) + 0.5);
   // TODO() : Remove once conversion modules have appropriate clamping in place
   value = CLIP3(value, 0, kHlgInvOETFNumEntries - 1);
-
-  return kHlgInvOETF[value];
+  static LookUpTable kHlgInvLut(kHlgInvOETFNumEntries, static_cast<float (*)(float)>(hlgInvOetf));
+  return kHlgInvLut.getTable()[value];
 }
 
 Color hlgInvOetfLUT(Color e_gamma) {
@@ -326,24 +283,15 @@ float pqOetfLUT(float e) {
   int32_t value = static_cast<int32_t>(e * (kPqOETFNumEntries - 1) + 0.5);
   // TODO() : Remove once conversion modules have appropriate clamping in place
   value = CLIP3(value, 0, kPqOETFNumEntries - 1);
-
-  return kPqOETF[value];
+  static LookUpTable kPqLut(kPqOETFNumEntries, static_cast<float (*)(float)>(pqOetf));
+  return kPqLut.getTable()[value];
 }
 
 Color pqOetfLUT(Color e) { return {{{pqOetfLUT(e.r), pqOetfLUT(e.g), pqOetfLUT(e.b)}}}; }
 
-// Derived from the inverse of the Reference PQ OETF.
-static const float kPqInvA = 128.0f, kPqInvB = 107.0f, kPqInvC = 2413.0f, kPqInvD = 2392.0f,
-                   kPqInvE = 6.2773946361f, kPqInvF = 0.0126833f;
-
 float pqInvOetf(float e_gamma) {
-  // This equation blows up if e_gamma is 0.0, and checking on <= 0.0 doesn't
-  // always catch 0.0. So, check on 0.0001, since anything this small will
-  // effectively be crushed to zero anyways.
-  if (e_gamma <= 0.0001f) return 0.0f;
-  return pow(
-      (kPqInvA * pow(e_gamma, kPqInvF) - kPqInvB) / (kPqInvC - kPqInvD * pow(e_gamma, kPqInvF)),
-      kPqInvE);
+  float val = pow(e_gamma, (1 / kPqM2));
+  return pow((((std::max)(val - kPqC1, 0.0f)) / (kPqC2 - kPqC3 * val)), 1 / kPqM1);
 }
 
 Color pqInvOetf(Color e_gamma) {
@@ -354,8 +302,8 @@ float pqInvOetfLUT(float e_gamma) {
   int32_t value = static_cast<int32_t>(e_gamma * (kPqInvOETFNumEntries - 1) + 0.5);
   // TODO() : Remove once conversion modules have appropriate clamping in place
   value = CLIP3(value, 0, kPqInvOETFNumEntries - 1);
-
-  return kPqInvOETF[value];
+  static LookUpTable kPqInvLut(kPqInvOETFNumEntries, static_cast<float (*)(float)>(pqInvOetf));
+  return kPqInvLut.getTable()[value];
 }
 
 Color pqInvOetfLUT(Color e_gamma) {
@@ -366,88 +314,221 @@ Color pqInvOetfLUT(Color e_gamma) {
 // Color conversions
 
 Color bt709ToP3(Color e) {
-  return {{{0.82254f * e.r + 0.17755f * e.g + 0.00006f * e.b,
-            0.03312f * e.r + 0.96684f * e.g + -0.00001f * e.b,
-            0.01706f * e.r + 0.07240f * e.g + 0.91049f * e.b}}};
+  return {{{clampPixelFloat(0.82254f * e.r + 0.17755f * e.g + 0.00006f * e.b),
+            clampPixelFloat(0.03312f * e.r + 0.96684f * e.g + -0.00001f * e.b),
+            clampPixelFloat(0.01706f * e.r + 0.07240f * e.g + 0.91049f * e.b)}}};
 }
 
 Color bt709ToBt2100(Color e) {
-  return {{{0.62740f * e.r + 0.32930f * e.g + 0.04332f * e.b,
-            0.06904f * e.r + 0.91958f * e.g + 0.01138f * e.b,
-            0.01636f * e.r + 0.08799f * e.g + 0.89555f * e.b}}};
+  return {{{clampPixelFloat(0.62740f * e.r + 0.32930f * e.g + 0.04332f * e.b),
+            clampPixelFloat(0.06904f * e.r + 0.91958f * e.g + 0.01138f * e.b),
+            clampPixelFloat(0.01636f * e.r + 0.08799f * e.g + 0.89555f * e.b)}}};
 }
 
 Color p3ToBt709(Color e) {
-  return {{{1.22482f * e.r + -0.22490f * e.g + -0.00007f * e.b,
-            -0.04196f * e.r + 1.04199f * e.g + 0.00001f * e.b,
-            -0.01961f * e.r + -0.07865f * e.g + 1.09831f * e.b}}};
+  return {{{clampPixelFloat(1.22482f * e.r + -0.22490f * e.g + -0.00007f * e.b),
+            clampPixelFloat(-0.04196f * e.r + 1.04199f * e.g + 0.00001f * e.b),
+            clampPixelFloat(-0.01961f * e.r + -0.07865f * e.g + 1.09831f * e.b)}}};
 }
 
 Color p3ToBt2100(Color e) {
-  return {{{0.75378f * e.r + 0.19862f * e.g + 0.04754f * e.b,
-            0.04576f * e.r + 0.94177f * e.g + 0.01250f * e.b,
-            -0.00121f * e.r + 0.01757f * e.g + 0.98359f * e.b}}};
+  return {{{clampPixelFloat(0.75378f * e.r + 0.19862f * e.g + 0.04754f * e.b),
+            clampPixelFloat(0.04576f * e.r + 0.94177f * e.g + 0.01250f * e.b),
+            clampPixelFloat(-0.00121f * e.r + 0.01757f * e.g + 0.98359f * e.b)}}};
 }
 
 Color bt2100ToBt709(Color e) {
-  return {{{1.66045f * e.r + -0.58764f * e.g + -0.07286f * e.b,
-            -0.12445f * e.r + 1.13282f * e.g + -0.00837f * e.b,
-            -0.01811f * e.r + -0.10057f * e.g + 1.11878f * e.b}}};
+  return {{{clampPixelFloat(1.66045f * e.r + -0.58764f * e.g + -0.07286f * e.b),
+            clampPixelFloat(-0.12445f * e.r + 1.13282f * e.g + -0.00837f * e.b),
+            clampPixelFloat(-0.01811f * e.r + -0.10057f * e.g + 1.11878f * e.b)}}};
 }
 
 Color bt2100ToP3(Color e) {
-  return {{{1.34369f * e.r + -0.28223f * e.g + -0.06135f * e.b,
-            -0.06533f * e.r + 1.07580f * e.g + -0.01051f * e.b,
-            0.00283f * e.r + -0.01957f * e.g + 1.01679f * e.b}}};
+  return {{{clampPixelFloat(1.34369f * e.r + -0.28223f * e.g + -0.06135f * e.b),
+            clampPixelFloat(-0.06533f * e.r + 1.07580f * e.g + -0.01051f * e.b),
+            clampPixelFloat(0.00283f * e.r + -0.01957f * e.g + 1.01679f * e.b)}}};
 }
 
 // TODO: confirm we always want to convert like this before calculating
 // luminance.
-ColorTransformFn getHdrConversionFn(ultrahdr_color_gamut sdr_gamut,
-                                    ultrahdr_color_gamut hdr_gamut) {
-  switch (sdr_gamut) {
-    case ULTRAHDR_COLORGAMUT_BT709:
-      switch (hdr_gamut) {
-        case ULTRAHDR_COLORGAMUT_BT709:
+ColorTransformFn getGamutConversionFn(uhdr_color_gamut_t dst_gamut, uhdr_color_gamut_t src_gamut) {
+  switch (dst_gamut) {
+    case UHDR_CG_BT_709:
+      switch (src_gamut) {
+        case UHDR_CG_BT_709:
           return identityConversion;
-        case ULTRAHDR_COLORGAMUT_P3:
+        case UHDR_CG_DISPLAY_P3:
           return p3ToBt709;
-        case ULTRAHDR_COLORGAMUT_BT2100:
+        case UHDR_CG_BT_2100:
           return bt2100ToBt709;
-        case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
+        case UHDR_CG_UNSPECIFIED:
           return nullptr;
       }
       break;
-    case ULTRAHDR_COLORGAMUT_P3:
-      switch (hdr_gamut) {
-        case ULTRAHDR_COLORGAMUT_BT709:
+    case UHDR_CG_DISPLAY_P3:
+      switch (src_gamut) {
+        case UHDR_CG_BT_709:
           return bt709ToP3;
-        case ULTRAHDR_COLORGAMUT_P3:
+        case UHDR_CG_DISPLAY_P3:
           return identityConversion;
-        case ULTRAHDR_COLORGAMUT_BT2100:
+        case UHDR_CG_BT_2100:
           return bt2100ToP3;
-        case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
+        case UHDR_CG_UNSPECIFIED:
           return nullptr;
       }
       break;
-    case ULTRAHDR_COLORGAMUT_BT2100:
-      switch (hdr_gamut) {
-        case ULTRAHDR_COLORGAMUT_BT709:
+    case UHDR_CG_BT_2100:
+      switch (src_gamut) {
+        case UHDR_CG_BT_709:
           return bt709ToBt2100;
-        case ULTRAHDR_COLORGAMUT_P3:
+        case UHDR_CG_DISPLAY_P3:
           return p3ToBt2100;
-        case ULTRAHDR_COLORGAMUT_BT2100:
+        case UHDR_CG_BT_2100:
           return identityConversion;
-        case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
+        case UHDR_CG_UNSPECIFIED:
           return nullptr;
       }
       break;
-    case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
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
       return nullptr;
   }
   return nullptr;
 }
 
+ColorCalculationFn getLuminanceFn(uhdr_color_gamut_t gamut) {
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
+    default:
+      return nullptr;
+  }
+  return nullptr;
+}
+
+bool isPixelFormatRgb(uhdr_img_fmt_t format) {
+  return format == UHDR_IMG_FMT_64bppRGBAHalfFloat || format == UHDR_IMG_FMT_32bppRGBA8888 ||
+         format == UHDR_IMG_FMT_32bppRGBA1010102;
+}
+
+float getMaxDisplayMasteringLuminance(uhdr_color_transfer_t transfer) {
+  switch (transfer) {
+    case UHDR_CT_LINEAR:
+      // TODO: configure MDML correctly for linear tf
+      return kHlgMaxNits;
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
 // All of these conversions are derived from the respective input YUV->RGB conversion followed by
 // the RGB->YUV for the receiving encoding. They are consistent with the RGB<->YUV functions in
 // gainmapmath.cpp, given that we use BT.709 encoding for sRGB and BT.601 encoding for Display-P3,
@@ -505,9 +586,9 @@ Color yuvColorGamutConversion(Color e_gamma, const std::array<float, 9>& coeffs)
   return {{{y, u, v}}};
 }
 
-void transformYuv420(jr_uncompressed_ptr image, const std::array<float, 9>& coeffs) {
-  for (size_t y = 0; y < image->height / 2; ++y) {
-    for (size_t x = 0; x < image->width / 2; ++x) {
+void transformYuv420(uhdr_raw_image_t* image, const std::array<float, 9>& coeffs) {
+  for (size_t y = 0; y < image->h / 2; ++y) {
+    for (size_t x = 0; x < image->w / 2; ++x) {
       Color yuv1 = getYuv420Pixel(image, x * 2, y * 2);
       Color yuv2 = getYuv420Pixel(image, x * 2 + 1, y * 2);
       Color yuv3 = getYuv420Pixel(image, x * 2, y * 2 + 1);
@@ -520,21 +601,21 @@ void transformYuv420(jr_uncompressed_ptr image, const std::array<float, 9>& coef
 
       Color new_uv = (yuv1 + yuv2 + yuv3 + yuv4) / 4.0f;
 
-      size_t pixel_y1_idx = x * 2 + y * 2 * image->luma_stride;
-      size_t pixel_y2_idx = (x * 2 + 1) + y * 2 * image->luma_stride;
-      size_t pixel_y3_idx = x * 2 + (y * 2 + 1) * image->luma_stride;
-      size_t pixel_y4_idx = (x * 2 + 1) + (y * 2 + 1) * image->luma_stride;
+      size_t pixel_y1_idx = x * 2 + y * 2 * image->stride[UHDR_PLANE_Y];
+      size_t pixel_y2_idx = (x * 2 + 1) + y * 2 * image->stride[UHDR_PLANE_Y];
+      size_t pixel_y3_idx = x * 2 + (y * 2 + 1) * image->stride[UHDR_PLANE_Y];
+      size_t pixel_y4_idx = (x * 2 + 1) + (y * 2 + 1) * image->stride[UHDR_PLANE_Y];
 
-      uint8_t& y1_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_y1_idx];
-      uint8_t& y2_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_y2_idx];
-      uint8_t& y3_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_y3_idx];
-      uint8_t& y4_uint = reinterpret_cast<uint8_t*>(image->data)[pixel_y4_idx];
+      uint8_t& y1_uint = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y])[pixel_y1_idx];
+      uint8_t& y2_uint = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y])[pixel_y2_idx];
+      uint8_t& y3_uint = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y])[pixel_y3_idx];
+      uint8_t& y4_uint = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y])[pixel_y4_idx];
 
-      size_t pixel_count = image->chroma_stride * image->height / 2;
-      size_t pixel_uv_idx = x + y * (image->chroma_stride);
+      size_t pixel_u_idx = x + y * image->stride[UHDR_PLANE_U];
+      uint8_t& u_uint = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_U])[pixel_u_idx];
 
-      uint8_t& u_uint = reinterpret_cast<uint8_t*>(image->chroma_data)[pixel_uv_idx];
-      uint8_t& v_uint = reinterpret_cast<uint8_t*>(image->chroma_data)[pixel_count + pixel_uv_idx];
+      size_t pixel_v_idx = x + y * image->stride[UHDR_PLANE_V];
+      uint8_t& v_uint = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_V])[pixel_v_idx];
 
       y1_uint = static_cast<uint8_t>(CLIP3((yuv1.y * 255.0f + 0.5f), 0, 255));
       y2_uint = static_cast<uint8_t>(CLIP3((yuv2.y * 255.0f + 0.5f), 0, 255));
@@ -547,38 +628,79 @@ void transformYuv420(jr_uncompressed_ptr image, const std::array<float, 9>& coef
   }
 }
 
+void transformYuv444(uhdr_raw_image_t* image, const std::array<float, 9>& coeffs) {
+  for (size_t y = 0; y < image->h; ++y) {
+    for (size_t x = 0; x < image->w; ++x) {
+      Color yuv = getYuv444Pixel(image, x, y);
+      yuv = yuvColorGamutConversion(yuv, coeffs);
+
+      size_t pixel_y_idx = x + y * image->stride[UHDR_PLANE_Y];
+      uint8_t& y1_uint = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y])[pixel_y_idx];
+
+      size_t pixel_u_idx = x + y * image->stride[UHDR_PLANE_U];
+      uint8_t& u_uint = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_U])[pixel_u_idx];
+
+      size_t pixel_v_idx = x + y * image->stride[UHDR_PLANE_V];
+      uint8_t& v_uint = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_V])[pixel_v_idx];
+
+      y1_uint = static_cast<uint8_t>(CLIP3((yuv.y * 255.0f + 0.5f), 0, 255));
+      u_uint = static_cast<uint8_t>(CLIP3((yuv.u * 255.0f + 128.0f + 0.5f), 0, 255));
+      v_uint = static_cast<uint8_t>(CLIP3((yuv.v * 255.0f + 128.0f + 0.5f), 0, 255));
+    }
+  }
+}
+
 ////////////////////////////////////////////////////////////////////////////////
 // Gain map calculations
-uint8_t encodeGain(float y_sdr, float y_hdr, ultrahdr_metadata_ptr metadata) {
-  return encodeGain(y_sdr, y_hdr, metadata, log2(metadata->minContentBoost),
-                    log2(metadata->maxContentBoost));
+uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata) {
+  return encodeGain(y_sdr, y_hdr, metadata, log2(metadata->min_content_boost),
+                    log2(metadata->max_content_boost));
 }
 
-uint8_t encodeGain(float y_sdr, float y_hdr, ultrahdr_metadata_ptr metadata,
+uint8_t encodeGain(float y_sdr, float y_hdr, uhdr_gainmap_metadata_ext_t* metadata,
                    float log2MinContentBoost, float log2MaxContentBoost) {
   float gain = 1.0f;
   if (y_sdr > 0.0f) {
     gain = y_hdr / y_sdr;
   }
 
-  if (gain < metadata->minContentBoost) gain = metadata->minContentBoost;
-  if (gain > metadata->maxContentBoost) gain = metadata->maxContentBoost;
+  if (gain < metadata->min_content_boost) gain = metadata->min_content_boost;
+  if (gain > metadata->max_content_boost) gain = metadata->max_content_boost;
+  float gain_normalized =
+      (log2(gain) - log2MinContentBoost) / (log2MaxContentBoost - log2MinContentBoost);
+  float gain_normalized_gamma = powf(gain_normalized, metadata->gamma);
+  return static_cast<uint8_t>(gain_normalized_gamma * 255.0f);
+}
+
+float computeGain(float sdr, float hdr) {
+  if (sdr == 0.0f) return 0.0f;  // for sdr black return no gain
+  if (hdr == 0.0f) {  // for hdr black, return a gain large enough to attenuate the sdr pel
+    float offset = (1.0f / 64);
+    return log2(offset / (offset + sdr));
+  }
+  return log2(hdr / sdr);
+}
 
-  return static_cast<uint8_t>((log2(gain) - log2MinContentBoost) /
-                              (log2MaxContentBoost - log2MinContentBoost) * 255.0f);
+uint8_t affineMapGain(float gainlog2, float mingainlog2, float maxgainlog2, float gamma) {
+  float mappedVal = (gainlog2 - mingainlog2) / (maxgainlog2 - mingainlog2);
+  if (gamma != 1.0f) mappedVal = pow(mappedVal, gamma);
+  mappedVal *= 255;
+  return CLIP3(mappedVal + 0.5f, 0, 255);
 }
 
-Color applyGain(Color e, float gain, ultrahdr_metadata_ptr metadata) {
+Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata) {
+  if (metadata->gamma != 1.0f) gain = pow(gain, 1.0f / metadata->gamma);
   float logBoost =
-      log2(metadata->minContentBoost) * (1.0f - gain) + log2(metadata->maxContentBoost) * gain;
+      log2(metadata->min_content_boost) * (1.0f - gain) + log2(metadata->max_content_boost) * gain;
   float gainFactor = exp2(logBoost);
   return e * gainFactor;
 }
 
-Color applyGain(Color e, float gain, ultrahdr_metadata_ptr metadata, float displayBoost) {
+Color applyGain(Color e, float gain, uhdr_gainmap_metadata_ext_t* metadata, float displayBoost) {
+  if (metadata->gamma != 1.0f) gain = pow(gain, 1.0f / metadata->gamma);
   float logBoost =
-      log2(metadata->minContentBoost) * (1.0f - gain) + log2(metadata->maxContentBoost) * gain;
-  float gainFactor = exp2(logBoost * displayBoost / metadata->maxContentBoost);
+      log2(metadata->min_content_boost) * (1.0f - gain) + log2(metadata->max_content_boost) * gain;
+  float gainFactor = exp2(logBoost * displayBoost / metadata->hdr_capacity_max);
   return e * gainFactor;
 }
 
@@ -587,29 +709,39 @@ Color applyGainLUT(Color e, float gain, GainLUT& gainLUT) {
   return e * gainFactor;
 }
 
-Color applyGain(Color e, Color gain, ultrahdr_metadata_ptr metadata) {
-  float logBoostR =
-      log2(metadata->minContentBoost) * (1.0f - gain.r) + log2(metadata->maxContentBoost) * gain.r;
-  float logBoostG =
-      log2(metadata->minContentBoost) * (1.0f - gain.g) + log2(metadata->maxContentBoost) * gain.g;
-  float logBoostB =
-      log2(metadata->minContentBoost) * (1.0f - gain.b) + log2(metadata->maxContentBoost) * gain.b;
+Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata) {
+  if (metadata->gamma != 1.0f) {
+    gain.r = pow(gain.r, 1.0f / metadata->gamma);
+    gain.g = pow(gain.g, 1.0f / metadata->gamma);
+    gain.b = pow(gain.b, 1.0f / metadata->gamma);
+  }
+  float logBoostR = log2(metadata->min_content_boost) * (1.0f - gain.r) +
+                    log2(metadata->max_content_boost) * gain.r;
+  float logBoostG = log2(metadata->min_content_boost) * (1.0f - gain.g) +
+                    log2(metadata->max_content_boost) * gain.g;
+  float logBoostB = log2(metadata->min_content_boost) * (1.0f - gain.b) +
+                    log2(metadata->max_content_boost) * gain.b;
   float gainFactorR = exp2(logBoostR);
   float gainFactorG = exp2(logBoostG);
   float gainFactorB = exp2(logBoostB);
   return {{{e.r * gainFactorR, e.g * gainFactorG, e.b * gainFactorB}}};
 }
 
-Color applyGain(Color e, Color gain, ultrahdr_metadata_ptr metadata, float displayBoost) {
-  float logBoostR =
-      log2(metadata->minContentBoost) * (1.0f - gain.r) + log2(metadata->maxContentBoost) * gain.r;
-  float logBoostG =
-      log2(metadata->minContentBoost) * (1.0f - gain.g) + log2(metadata->maxContentBoost) * gain.g;
-  float logBoostB =
-      log2(metadata->minContentBoost) * (1.0f - gain.b) + log2(metadata->maxContentBoost) * gain.b;
-  float gainFactorR = exp2(logBoostR * displayBoost / metadata->maxContentBoost);
-  float gainFactorG = exp2(logBoostG * displayBoost / metadata->maxContentBoost);
-  float gainFactorB = exp2(logBoostB * displayBoost / metadata->maxContentBoost);
+Color applyGain(Color e, Color gain, uhdr_gainmap_metadata_ext_t* metadata, float displayBoost) {
+  if (metadata->gamma != 1.0f) {
+    gain.r = pow(gain.r, 1.0f / metadata->gamma);
+    gain.g = pow(gain.g, 1.0f / metadata->gamma);
+    gain.b = pow(gain.b, 1.0f / metadata->gamma);
+  }
+  float logBoostR = log2(metadata->min_content_boost) * (1.0f - gain.r) +
+                    log2(metadata->max_content_boost) * gain.r;
+  float logBoostG = log2(metadata->min_content_boost) * (1.0f - gain.g) +
+                    log2(metadata->max_content_boost) * gain.g;
+  float logBoostB = log2(metadata->min_content_boost) * (1.0f - gain.b) +
+                    log2(metadata->max_content_boost) * gain.b;
+  float gainFactorR = exp2(logBoostR * displayBoost / metadata->hdr_capacity_max);
+  float gainFactorG = exp2(logBoostG * displayBoost / metadata->hdr_capacity_max);
+  float gainFactorB = exp2(logBoostB * displayBoost / metadata->hdr_capacity_max);
   return {{{e.r * gainFactorR, e.g * gainFactorG, e.b * gainFactorB}}};
 }
 
@@ -620,19 +752,21 @@ Color applyGainLUT(Color e, Color gain, GainLUT& gainLUT) {
   return {{{e.r * gainFactorR, e.g * gainFactorG, e.b * gainFactorB}}};
 }
 
-Color getYuv420Pixel(jr_uncompressed_ptr image, size_t x, size_t y) {
-  uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->data);
-  size_t luma_stride = image->luma_stride;
-  uint8_t* chroma_data = reinterpret_cast<uint8_t*>(image->chroma_data);
-  size_t chroma_stride = image->chroma_stride;
+Color getYuv4abPixel(uhdr_raw_image_t* image, size_t x, size_t y, int h_factor, int v_factor) {
+  uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
+  size_t luma_stride = image->stride[UHDR_PLANE_Y];
+  uint8_t* cb_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_U]);
+  size_t cb_stride = image->stride[UHDR_PLANE_U];
+  uint8_t* cr_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_V]);
+  size_t cr_stride = image->stride[UHDR_PLANE_V];
 
-  size_t offset_cr = chroma_stride * (image->height / 2);
   size_t pixel_y_idx = x + y * luma_stride;
-  size_t pixel_chroma_idx = x / 2 + (y / 2) * chroma_stride;
+  size_t pixel_cb_idx = x / h_factor + (y / v_factor) * cb_stride;
+  size_t pixel_cr_idx = x / h_factor + (y / v_factor) * cr_stride;
 
   uint8_t y_uint = luma_data[pixel_y_idx];
-  uint8_t u_uint = chroma_data[pixel_chroma_idx];
-  uint8_t v_uint = chroma_data[offset_cr + pixel_chroma_idx];
+  uint8_t u_uint = cb_data[pixel_cb_idx];
+  uint8_t v_uint = cr_data[pixel_cr_idx];
 
   // 128 bias for UV given we are using jpeglib; see:
   // https://github.com/kornelski/libjpeg/blob/master/structure.doc
@@ -641,11 +775,50 @@ Color getYuv420Pixel(jr_uncompressed_ptr image, size_t x, size_t y) {
         static_cast<float>(v_uint - 128) * (1 / 255.0f)}}};
 }
 
-Color getP010Pixel(jr_uncompressed_ptr image, size_t x, size_t y) {
-  uint16_t* luma_data = reinterpret_cast<uint16_t*>(image->data);
-  size_t luma_stride = image->luma_stride == 0 ? image->width : image->luma_stride;
-  uint16_t* chroma_data = reinterpret_cast<uint16_t*>(image->chroma_data);
-  size_t chroma_stride = image->chroma_stride;
+Color getYuv444Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  return getYuv4abPixel(image, x, y, 1, 1);
+}
+
+Color getYuv422Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  return getYuv4abPixel(image, x, y, 2, 1);
+}
+
+Color getYuv420Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  return getYuv4abPixel(image, x, y, 2, 2);
+}
+
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
+  }
+
+  // Conversions include taking narrow-range into account.
+  return {{{static_cast<float>(y_uint - 64) * (1 / 876.0f),
+            static_cast<float>(u_uint - 64) * (1 / 896.0f) - 0.5f,
+            static_cast<float>(v_uint - 64) * (1 / 896.0f) - 0.5f}}};
+}
+
+Color getP010Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  uint16_t* luma_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_Y]);
+  size_t luma_stride = image->stride[UHDR_PLANE_Y];
+  uint16_t* chroma_data = reinterpret_cast<uint16_t*>(image->planes[UHDR_PLANE_UV]);
+  size_t chroma_stride = image->stride[UHDR_PLANE_UV];
 
   size_t pixel_y_idx = y * luma_stride + x;
   size_t pixel_u_idx = (y >> 1) * chroma_stride + (x & ~0x1);
@@ -655,16 +828,41 @@ Color getP010Pixel(jr_uncompressed_ptr image, size_t x, size_t y) {
   uint16_t u_uint = chroma_data[pixel_u_idx] >> 6;
   uint16_t v_uint = chroma_data[pixel_v_idx] >> 6;
 
+  if (image->range == UHDR_CR_FULL_RANGE) {
+    return {{{static_cast<float>(y_uint) / 1023.0f, static_cast<float>(u_uint) / 1023.0f - 0.5f,
+              static_cast<float>(v_uint) / 1023.0f - 0.5f}}};
+  }
+
   // Conversions include taking narrow-range into account.
   return {{{static_cast<float>(y_uint - 64) * (1 / 876.0f),
             static_cast<float>(u_uint - 64) * (1 / 896.0f) - 0.5f,
             static_cast<float>(v_uint - 64) * (1 / 896.0f) - 0.5f}}};
 }
 
-typedef Color (*getPixelFn)(jr_uncompressed_ptr, size_t, size_t);
+Color getRgba8888Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  uint32_t* rgbData = static_cast<uint32_t*>(image->planes[UHDR_PLANE_PACKED]);
+  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
 
-static Color samplePixels(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y,
-                          getPixelFn get_pixel_fn) {
+  Color pixel;
+  pixel.r = float(rgbData[x + y * srcStride] & 0xff);
+  pixel.g = float((rgbData[x + y * srcStride] >> 8) & 0xff);
+  pixel.b = float((rgbData[x + y * srcStride] >> 16) & 0xff);
+  return pixel / 255.0f;
+}
+
+Color getRgba1010102Pixel(uhdr_raw_image_t* image, size_t x, size_t y) {
+  uint32_t* rgbData = static_cast<uint32_t*>(image->planes[UHDR_PLANE_PACKED]);
+  unsigned int srcStride = image->stride[UHDR_PLANE_PACKED];
+
+  Color pixel;
+  pixel.r = float(rgbData[x + y * srcStride] & 0x3ff);
+  pixel.g = float((rgbData[x + y * srcStride] >> 10) & 0x3ff);
+  pixel.b = float((rgbData[x + y * srcStride] >> 20) & 0x3ff);
+  return pixel / 1023.0f;
+}
+
+static Color samplePixels(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y,
+                          GetPixelFn get_pixel_fn) {
   Color e = {{{0.0f, 0.0f, 0.0f}}};
   for (size_t dy = 0; dy < map_scale_factor; ++dy) {
     for (size_t dx = 0; dx < map_scale_factor; ++dx) {
@@ -675,14 +873,69 @@ static Color samplePixels(jr_uncompressed_ptr image, size_t map_scale_factor, si
   return e / static_cast<float>(map_scale_factor * map_scale_factor);
 }
 
-Color sampleYuv420(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y) {
+Color sampleYuv444(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
+  return samplePixels(image, map_scale_factor, x, y, getYuv444Pixel);
+}
+
+Color sampleYuv422(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
+  return samplePixels(image, map_scale_factor, x, y, getYuv422Pixel);
+}
+
+Color sampleYuv420(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
   return samplePixels(image, map_scale_factor, x, y, getYuv420Pixel);
 }
 
-Color sampleP010(jr_uncompressed_ptr image, size_t map_scale_factor, size_t x, size_t y) {
+Color sampleP010(uhdr_raw_image_t* image, size_t map_scale_factor, size_t x, size_t y) {
   return samplePixels(image, map_scale_factor, x, y, getP010Pixel);
 }
 
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
 // TODO: do we need something more clever for filtering either the map or images
 // to generate the map?
 
@@ -697,7 +950,7 @@ static float pythDistance(float x_diff, float y_diff) {
 }
 
 // TODO: If map_scale_factor is guaranteed to be an integer, then remove the following.
-float sampleMap(jr_uncompressed_ptr map, float map_scale_factor, size_t x, size_t y) {
+float sampleMap(uhdr_raw_image_t* map, float map_scale_factor, size_t x, size_t y) {
   float x_map = static_cast<float>(x) / map_scale_factor;
   float y_map = static_cast<float>(y) / map_scale_factor;
 
@@ -706,30 +959,32 @@ float sampleMap(jr_uncompressed_ptr map, float map_scale_factor, size_t x, size_
   size_t y_lower = static_cast<size_t>(floor(y_map));
   size_t y_upper = y_lower + 1;
 
-  x_lower = clamp(x_lower, 0, map->width - 1);
-  x_upper = clamp(x_upper, 0, map->width - 1);
-  y_lower = clamp(y_lower, 0, map->height - 1);
-  y_upper = clamp(y_upper, 0, map->height - 1);
+  x_lower = clamp(x_lower, 0, map->w - 1);
+  x_upper = clamp(x_upper, 0, map->w - 1);
+  y_lower = clamp(y_lower, 0, map->h - 1);
+  y_upper = clamp(y_upper, 0, map->h - 1);
 
   // Use Shepard's method for inverse distance weighting. For more information:
   // en.wikipedia.org/wiki/Inverse_distance_weighting#Shepard's_method
+  uint8_t* data = reinterpret_cast<uint8_t*>(map->planes[UHDR_PLANE_Y]);
+  size_t stride = map->stride[UHDR_PLANE_Y];
 
-  float e1 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_lower * map->width]);
+  float e1 = mapUintToFloat(data[x_lower + y_lower * stride]);
   float e1_dist =
       pythDistance(x_map - static_cast<float>(x_lower), y_map - static_cast<float>(y_lower));
   if (e1_dist == 0.0f) return e1;
 
-  float e2 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_upper * map->width]);
+  float e2 = mapUintToFloat(data[x_lower + y_upper * stride]);
   float e2_dist =
       pythDistance(x_map - static_cast<float>(x_lower), y_map - static_cast<float>(y_upper));
   if (e2_dist == 0.0f) return e2;
 
-  float e3 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_lower * map->width]);
+  float e3 = mapUintToFloat(data[x_upper + y_lower * stride]);
   float e3_dist =
       pythDistance(x_map - static_cast<float>(x_upper), y_map - static_cast<float>(y_lower));
   if (e3_dist == 0.0f) return e3;
 
-  float e4 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_upper * map->width]);
+  float e4 = mapUintToFloat(data[x_upper + y_upper * stride]);
   float e4_dist =
       pythDistance(x_map - static_cast<float>(x_upper), y_map - static_cast<float>(y_upper));
   if (e4_dist == 0.0f) return e2;
@@ -744,7 +999,7 @@ float sampleMap(jr_uncompressed_ptr map, float map_scale_factor, size_t x, size_
          e3 * (e3_weight / total_weight) + e4 * (e4_weight / total_weight);
 }
 
-float sampleMap(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y,
+float sampleMap(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y,
                 ShepardsIDW& weightTables) {
   // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
   // following by computing log2(map_scale_factor) once and then using >> log2(map_scale_factor)
@@ -753,15 +1008,17 @@ float sampleMap(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size
   size_t y_lower = y / map_scale_factor;
   size_t y_upper = y_lower + 1;
 
-  x_lower = std::min(x_lower, map->width - 1);
-  x_upper = std::min(x_upper, map->width - 1);
-  y_lower = std::min(y_lower, map->height - 1);
-  y_upper = std::min(y_upper, map->height - 1);
+  x_lower = std::min(x_lower, (size_t)map->w - 1);
+  x_upper = std::min(x_upper, (size_t)map->w - 1);
+  y_lower = std::min(y_lower, (size_t)map->h - 1);
+  y_upper = std::min(y_upper, (size_t)map->h - 1);
 
-  float e1 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_lower * map->width]);
-  float e2 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_lower + y_upper * map->width]);
-  float e3 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_lower * map->width]);
-  float e4 = mapUintToFloat(reinterpret_cast<uint8_t*>(map->data)[x_upper + y_upper * map->width]);
+  uint8_t* data = reinterpret_cast<uint8_t*>(map->planes[UHDR_PLANE_Y]);
+  size_t stride = map->stride[UHDR_PLANE_Y];
+  float e1 = mapUintToFloat(data[x_lower + y_lower * stride]);
+  float e2 = mapUintToFloat(data[x_lower + y_upper * stride]);
+  float e3 = mapUintToFloat(data[x_upper + y_lower * stride]);
+  float e4 = mapUintToFloat(data[x_upper + y_upper * stride]);
 
   // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
   // following by using & (map_scale_factor - 1)
@@ -780,7 +1037,7 @@ float sampleMap(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size
   return e1 * weights[0] + e2 * weights[1] + e3 * weights[2] + e4 * weights[3];
 }
 
-Color sampleMap3Channel(jr_uncompressed_ptr map, float map_scale_factor, size_t x, size_t y,
+Color sampleMap3Channel(uhdr_raw_image_t* map, float map_scale_factor, size_t x, size_t y,
                         bool has_alpha) {
   float x_map = static_cast<float>(x) / map_scale_factor;
   float y_map = static_cast<float>(y) / map_scale_factor;
@@ -790,39 +1047,30 @@ Color sampleMap3Channel(jr_uncompressed_ptr map, float map_scale_factor, size_t
   size_t y_lower = static_cast<size_t>(floor(y_map));
   size_t y_upper = y_lower + 1;
 
-  x_lower = std::min(x_lower, map->width - 1);
-  x_upper = std::min(x_upper, map->width - 1);
-  y_lower = std::min(y_lower, map->height - 1);
-  y_upper = std::min(y_upper, map->height - 1);
+  x_lower = std::min(x_lower, (size_t)map->w - 1);
+  x_upper = std::min(x_upper, (size_t)map->w - 1);
+  y_lower = std::min(y_lower, (size_t)map->h - 1);
+  y_upper = std::min(y_upper, (size_t)map->h - 1);
 
   int factor = has_alpha ? 4 : 3;
 
-  float r1 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor]);
-  float r2 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor]);
-  float r3 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor]);
-  float r4 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor]);
-
-  float g1 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor + 1]);
-  float g2 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor + 1]);
-  float g3 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor + 1]);
-  float g4 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor + 1]);
-
-  float b1 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor + 2]);
-  float b2 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor + 2]);
-  float b3 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor + 2]);
-  float b4 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor + 2]);
+  uint8_t* data = reinterpret_cast<uint8_t*>(map->planes[UHDR_PLANE_PACKED]);
+  size_t stride = map->stride[UHDR_PLANE_PACKED];
+
+  float r1 = mapUintToFloat(data[(x_lower + y_lower * stride) * factor]);
+  float r2 = mapUintToFloat(data[(x_lower + y_upper * stride) * factor]);
+  float r3 = mapUintToFloat(data[(x_upper + y_lower * stride) * factor]);
+  float r4 = mapUintToFloat(data[(x_upper + y_upper * stride) * factor]);
+
+  float g1 = mapUintToFloat(data[(x_lower + y_lower * stride) * factor + 1]);
+  float g2 = mapUintToFloat(data[(x_lower + y_upper * stride) * factor + 1]);
+  float g3 = mapUintToFloat(data[(x_upper + y_lower * stride) * factor + 1]);
+  float g4 = mapUintToFloat(data[(x_upper + y_upper * stride) * factor + 1]);
+
+  float b1 = mapUintToFloat(data[(x_lower + y_lower * stride) * factor + 2]);
+  float b2 = mapUintToFloat(data[(x_lower + y_upper * stride) * factor + 2]);
+  float b3 = mapUintToFloat(data[(x_upper + y_lower * stride) * factor + 2]);
+  float b4 = mapUintToFloat(data[(x_upper + y_upper * stride) * factor + 2]);
 
   Color rgb1 = {{{r1, g1, b1}}};
   Color rgb2 = {{{r2, g2, b2}}};
@@ -857,7 +1105,7 @@ Color sampleMap3Channel(jr_uncompressed_ptr map, float map_scale_factor, size_t
          rgb3 * (e3_weight / total_weight) + rgb4 * (e4_weight / total_weight);
 }
 
-Color sampleMap3Channel(jr_uncompressed_ptr map, size_t map_scale_factor, size_t x, size_t y,
+Color sampleMap3Channel(uhdr_raw_image_t* map, size_t map_scale_factor, size_t x, size_t y,
                         ShepardsIDW& weightTables, bool has_alpha) {
   // TODO: If map_scale_factor is guaranteed to be an integer power of 2, then optimize the
   // following by computing log2(map_scale_factor) once and then using >> log2(map_scale_factor)
@@ -866,39 +1114,30 @@ Color sampleMap3Channel(jr_uncompressed_ptr map, size_t map_scale_factor, size_t
   size_t y_lower = y / map_scale_factor;
   size_t y_upper = y_lower + 1;
 
-  x_lower = std::min(x_lower, map->width - 1);
-  x_upper = std::min(x_upper, map->width - 1);
-  y_lower = std::min(y_lower, map->height - 1);
-  y_upper = std::min(y_upper, map->height - 1);
+  x_lower = std::min(x_lower, (size_t)map->w - 1);
+  x_upper = std::min(x_upper, (size_t)map->w - 1);
+  y_lower = std::min(y_lower, (size_t)map->h - 1);
+  y_upper = std::min(y_upper, (size_t)map->h - 1);
 
   int factor = has_alpha ? 4 : 3;
 
-  float r1 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor]);
-  float r2 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor]);
-  float r3 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor]);
-  float r4 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor]);
-
-  float g1 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor + 1]);
-  float g2 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor + 1]);
-  float g3 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor + 1]);
-  float g4 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor + 1]);
-
-  float b1 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_lower * map->width) * factor + 2]);
-  float b2 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_lower + y_upper * map->width) * factor + 2]);
-  float b3 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_lower * map->width) * factor + 2]);
-  float b4 = mapUintToFloat(
-      reinterpret_cast<uint8_t*>(map->data)[(x_upper + y_upper * map->width) * factor + 2]);
+  uint8_t* data = reinterpret_cast<uint8_t*>(map->planes[UHDR_PLANE_PACKED]);
+  size_t stride = map->stride[UHDR_PLANE_PACKED];
+
+  float r1 = mapUintToFloat(data[(x_lower + y_lower * stride) * factor]);
+  float r2 = mapUintToFloat(data[(x_lower + y_upper * stride) * factor]);
+  float r3 = mapUintToFloat(data[(x_upper + y_lower * stride) * factor]);
+  float r4 = mapUintToFloat(data[(x_upper + y_upper * stride) * factor]);
+
+  float g1 = mapUintToFloat(data[(x_lower + y_lower * stride) * factor + 1]);
+  float g2 = mapUintToFloat(data[(x_lower + y_upper * stride) * factor + 1]);
+  float g3 = mapUintToFloat(data[(x_upper + y_lower * stride) * factor + 1]);
+  float g4 = mapUintToFloat(data[(x_upper + y_upper * stride) * factor + 1]);
+
+  float b1 = mapUintToFloat(data[(x_lower + y_lower * stride) * factor + 2]);
+  float b2 = mapUintToFloat(data[(x_lower + y_upper * stride) * factor + 2]);
+  float b3 = mapUintToFloat(data[(x_upper + y_lower * stride) * factor + 2]);
+  float b4 = mapUintToFloat(data[(x_upper + y_upper * stride) * factor + 2]);
 
   Color rgb1 = {{{r1, g1, b1}}};
   Color rgb2 = {{{r2, g2, b2}}};
@@ -923,10 +1162,10 @@ Color sampleMap3Channel(jr_uncompressed_ptr map, size_t map_scale_factor, size_t
 }
 
 uint32_t colorToRgba1010102(Color e_gamma) {
-  return (0x3ff & static_cast<uint32_t>(e_gamma.r * 1023.0f)) |
-         ((0x3ff & static_cast<uint32_t>(e_gamma.g * 1023.0f)) << 10) |
-         ((0x3ff & static_cast<uint32_t>(e_gamma.b * 1023.0f)) << 20) |
-         (0x3 << 30);  // Set alpha to 1.0
+  uint32_t r = CLIP3((e_gamma.r * 1023 + 0.5f), 0.0f, 1023.0f);
+  uint32_t g = CLIP3((e_gamma.g * 1023 + 0.5f), 0.0f, 1023.0f);
+  uint32_t b = CLIP3((e_gamma.b * 1023 + 0.5f), 0.0f, 1023.0f);
+  return (r | (g << 10) | (b << 20) | (0x3 << 30));  // Set alpha to 1.0
 }
 
 uint64_t colorToRgbaF16(Color e_gamma) {
@@ -934,7 +1173,8 @@ uint64_t colorToRgbaF16(Color e_gamma) {
          (((uint64_t)floatToHalf(e_gamma.b)) << 32) | (((uint64_t)floatToHalf(1.0f)) << 48);
 }
 
-std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_t* src) {
+std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_t* src,
+                                                                 bool chroma_sampling_enabled) {
   std::unique_ptr<uhdr_raw_image_ext_t> dst = nullptr;
   Color (*rgbToyuv)(Color) = nullptr;
 
@@ -950,9 +1190,9 @@ std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_
     }
   }
 
-  if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
+  if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 && chroma_sampling_enabled) {
     dst = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_24bppYCbCrP010, src->cg, src->ct,
-                                                 UHDR_CR_LIMITED_RANGE, src->w, src->h, 64);
+                                                 UHDR_CR_FULL_RANGE, src->w, src->h, 64);
 
     uint32_t* rgbData = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
     unsigned int srcStride = src->stride[UHDR_PLANE_PACKED];
@@ -982,11 +1222,12 @@ std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_
         pixel[3].b = float((rgbData[srcStride * (i + 1) + j + 1] >> 20) & 0x3ff);
 
         for (int k = 0; k < 4; k++) {
+          // Now we only support the RGB input being full range
           pixel[k] /= 1023.0f;
           pixel[k] = (*rgbToyuv)(pixel[k]);
 
-          pixel[k].y = (pixel[k].y * 876.0f) + 64.0f + 0.5f;
-          pixel[k].y = CLIP3(pixel[k].y, 64.0f, 940.0f);
+          pixel[k].y = (pixel[k].y * 1023.0f) + 0.5f;
+          pixel[k].y = CLIP3(pixel[k].y, 0.0f, 1023.0f);
         }
 
         yData[dst->stride[UHDR_PLANE_Y] * i + j] = uint16_t(pixel[0].y) << 6;
@@ -997,17 +1238,55 @@ std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_
         pixel[0].u = (pixel[0].u + pixel[1].u + pixel[2].u + pixel[3].u) / 4;
         pixel[0].v = (pixel[0].v + pixel[1].v + pixel[2].v + pixel[3].v) / 4;
 
-        pixel[0].u = (pixel[0].u * 896.0f) + 512.0f + 0.5f;
-        pixel[0].v = (pixel[0].v * 896.0f) + 512.0f + 0.5f;
+        pixel[0].u = (pixel[0].u * 1023.0f) + 512.0f + 0.5f;
+        pixel[0].v = (pixel[0].v * 1023.0f) + 512.0f + 0.5f;
 
-        pixel[0].u = CLIP3(pixel[0].u, 64.0f, 960.0f);
-        pixel[0].v = CLIP3(pixel[0].v, 64.0f, 960.0f);
+        pixel[0].u = CLIP3(pixel[0].u, 0.0f, 1023.0f);
+        pixel[0].v = CLIP3(pixel[0].v, 0.0f, 1023.0f);
 
         uData[dst->stride[UHDR_PLANE_UV] * (i / 2) + j] = uint16_t(pixel[0].u) << 6;
         vData[dst->stride[UHDR_PLANE_UV] * (i / 2) + j] = uint16_t(pixel[0].v) << 6;
       }
     }
-  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
+  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
+    dst = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_30bppYCbCr444, src->cg, src->ct,
+                                                 UHDR_CR_FULL_RANGE, src->w, src->h, 64);
+
+    uint32_t* rgbData = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
+    unsigned int srcStride = src->stride[UHDR_PLANE_PACKED];
+
+    uint16_t* yData = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_Y]);
+    uint16_t* uData = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_U]);
+    uint16_t* vData = static_cast<uint16_t*>(dst->planes[UHDR_PLANE_V]);
+
+    for (size_t i = 0; i < dst->h; i++) {
+      for (size_t j = 0; j < dst->w; j++) {
+        Color pixel;
+
+        pixel.r = float(rgbData[srcStride * i + j] & 0x3ff);
+        pixel.g = float((rgbData[srcStride * i + j] >> 10) & 0x3ff);
+        pixel.b = float((rgbData[srcStride * i + j] >> 20) & 0x3ff);
+
+        // Now we only support the RGB input being full range
+        pixel /= 1023.0f;
+        pixel = (*rgbToyuv)(pixel);
+
+        pixel.y = (pixel.y * 1023.0f) + 0.5f;
+        pixel.y = CLIP3(pixel.y, 0.0f, 1023.0f);
+
+        yData[dst->stride[UHDR_PLANE_Y] * i + j] = uint16_t(pixel.y);
+
+        pixel.u = (pixel.u * 1023.0f) + 512.0f + 0.5f;
+        pixel.v = (pixel.v * 1023.0f) + 512.0f + 0.5f;
+
+        pixel.u = CLIP3(pixel.u, 0.0f, 1023.0f);
+        pixel.v = CLIP3(pixel.v, 0.0f, 1023.0f);
+
+        uData[dst->stride[UHDR_PLANE_U] * i + j] = uint16_t(pixel.u);
+        vData[dst->stride[UHDR_PLANE_V] * i + j] = uint16_t(pixel.v);
+      }
+    }
+  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA8888 && chroma_sampling_enabled) {
     dst = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_12bppYCbCr420, src->cg, src->ct,
                                                  UHDR_CR_FULL_RANGE, src->w, src->h, 64);
     uint32_t* rgbData = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
@@ -1037,6 +1316,7 @@ std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_
         pixel[3].b = float((rgbData[srcStride * (i + 1) + (j + 1)] >> 16) & 0xff);
 
         for (int k = 0; k < 4; k++) {
+          // Now we only support the RGB input being full range
           pixel[k] /= 255.0f;
           pixel[k] = (*rgbToyuv)(pixel[k]);
 
@@ -1061,57 +1341,166 @@ std::unique_ptr<uhdr_raw_image_ext_t> convert_raw_input_to_ycbcr(uhdr_raw_image_
         vData[dst->stride[UHDR_PLANE_V] * (i / 2) + (j / 2)] = uint8_t(pixel[0].v);
       }
     }
-  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
-    dst = std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range,
-                                                           src->w, src->h, 64);
+  } else if (src->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
+    dst = std::make_unique<uhdr_raw_image_ext_t>(UHDR_IMG_FMT_24bppYCbCr444, src->cg, src->ct,
+                                                 UHDR_CR_FULL_RANGE, src->w, src->h, 64);
+    uint32_t* rgbData = static_cast<uint32_t*>(src->planes[UHDR_PLANE_PACKED]);
+    unsigned int srcStride = src->stride[UHDR_PLANE_PACKED];
 
-    uint8_t* y_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
-    uint8_t* y_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
-    uint8_t* u_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_U]);
-    uint8_t* u_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_U]);
-    uint8_t* v_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_V]);
-    uint8_t* v_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_V]);
-
-    // copy y
-    for (size_t i = 0; i < src->h; i++) {
-      memcpy(y_dst, y_src, src->w);
-      y_dst += dst->stride[UHDR_PLANE_Y];
-      y_src += src->stride[UHDR_PLANE_Y];
-    }
-    // copy cb & cr
-    for (size_t i = 0; i < src->h / 2; i++) {
-      memcpy(u_dst, u_src, src->w / 2);
-      memcpy(v_dst, v_src, src->w / 2);
-      u_dst += dst->stride[UHDR_PLANE_U];
-      v_dst += dst->stride[UHDR_PLANE_V];
-      u_src += src->stride[UHDR_PLANE_U];
-      v_src += src->stride[UHDR_PLANE_V];
+    uint8_t* yData = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
+    uint8_t* uData = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_U]);
+    uint8_t* vData = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_V]);
+    for (size_t i = 0; i < dst->h; i++) {
+      for (size_t j = 0; j < dst->w; j++) {
+        Color pixel;
+
+        pixel.r = float(rgbData[srcStride * i + j] & 0xff);
+        pixel.g = float((rgbData[srcStride * i + j] >> 8) & 0xff);
+        pixel.b = float((rgbData[srcStride * i + j] >> 16) & 0xff);
+
+        // Now we only support the RGB input being full range
+        pixel /= 255.0f;
+        pixel = (*rgbToyuv)(pixel);
+
+        pixel.y = pixel.y * 255.0f + 0.5f;
+        pixel.y = CLIP3(pixel.y, 0.0f, 255.0f);
+        yData[dst->stride[UHDR_PLANE_Y] * i + j] = uint8_t(pixel.y);
+
+        pixel.u = pixel.u * 255.0f + 0.5 + 128.0f;
+        pixel.v = pixel.v * 255.0f + 0.5 + 128.0f;
+
+        pixel.u = CLIP3(pixel.u, 0.0f, 255.0f);
+        pixel.v = CLIP3(pixel.v, 0.0f, 255.0f);
+
+        uData[dst->stride[UHDR_PLANE_U] * i + j] = uint8_t(pixel.u);
+        vData[dst->stride[UHDR_PLANE_V] * i + j] = uint8_t(pixel.v);
+      }
     }
-  } else if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
+  } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420 || src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
     dst = std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range,
                                                            src->w, src->h, 64);
+    auto status = copy_raw_image(src, dst.get());
+    if (status.error_code != UHDR_CODEC_OK) return nullptr;
+  }
+  return dst;
+}
+
+std::unique_ptr<uhdr_raw_image_ext_t> copy_raw_image(uhdr_raw_image_t* src) {
+  std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(
+      src->fmt, src->cg, src->ct, src->range, src->w, src->h, 64);
+  auto status = copy_raw_image(src, dst.get());
+  if (status.error_code != UHDR_CODEC_OK) return nullptr;
+  return dst;
+}
+
+uhdr_error_info_t copy_raw_image(uhdr_raw_image_t* src, uhdr_raw_image_t* dst) {
+  if (dst->w != src->w || dst->h != src->h) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_MEM_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "destination image dimensions %dx%d and source image dimensions %dx%d are not "
+             "identical for copy_raw_image",
+             dst->w, dst->h, src->w, src->h);
+    return status;
+  }
 
-    int bpp = 2;
-    uint8_t* y_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
-    uint8_t* y_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
-    uint8_t* uv_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_UV]);
-    uint8_t* uv_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_UV]);
-
-    // copy y
-    for (size_t i = 0; i < src->h; i++) {
-      memcpy(y_dst, y_src, src->w * bpp);
-      y_dst += (dst->stride[UHDR_PLANE_Y] * bpp);
-      y_src += (src->stride[UHDR_PLANE_Y] * bpp);
+  dst->cg = src->cg;
+  dst->ct = src->ct;
+  dst->range = src->range;
+  if (dst->fmt == src->fmt) {
+    if (src->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
+      int bpp = 2;
+      uint8_t* y_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
+      uint8_t* y_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
+      uint8_t* uv_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_UV]);
+      uint8_t* uv_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_UV]);
+
+      // copy y
+      for (size_t i = 0; i < src->h; i++) {
+        memcpy(y_dst, y_src, src->w * bpp);
+        y_dst += (dst->stride[UHDR_PLANE_Y] * bpp);
+        y_src += (src->stride[UHDR_PLANE_Y] * bpp);
+      }
+      // copy cbcr
+      for (size_t i = 0; i < src->h / 2; i++) {
+        memcpy(uv_dst, uv_src, src->w * bpp);
+        uv_dst += (dst->stride[UHDR_PLANE_UV] * bpp);
+        uv_src += (src->stride[UHDR_PLANE_UV] * bpp);
+      }
+      return g_no_error;
+    } else if (src->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+      uint8_t* y_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_Y]);
+      uint8_t* y_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_Y]);
+      uint8_t* u_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_U]);
+      uint8_t* u_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_U]);
+      uint8_t* v_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_V]);
+      uint8_t* v_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_V]);
+
+      // copy y
+      for (size_t i = 0; i < src->h; i++) {
+        memcpy(y_dst, y_src, src->w);
+        y_dst += dst->stride[UHDR_PLANE_Y];
+        y_src += src->stride[UHDR_PLANE_Y];
+      }
+      // copy cb & cr
+      for (size_t i = 0; i < src->h / 2; i++) {
+        memcpy(u_dst, u_src, src->w / 2);
+        memcpy(v_dst, v_src, src->w / 2);
+        u_dst += dst->stride[UHDR_PLANE_U];
+        v_dst += dst->stride[UHDR_PLANE_V];
+        u_src += src->stride[UHDR_PLANE_U];
+        v_src += src->stride[UHDR_PLANE_V];
+      }
+      return g_no_error;
+    } else if (src->fmt == UHDR_IMG_FMT_8bppYCbCr400 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888 ||
+               src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat ||
+               src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_24bppRGB888) {
+      uint8_t* plane_dst = static_cast<uint8_t*>(dst->planes[UHDR_PLANE_PACKED]);
+      uint8_t* plane_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_PACKED]);
+      int bpp = 1;
+
+      if (src->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || src->fmt == UHDR_IMG_FMT_32bppRGBA8888)
+        bpp = 4;
+      else if (src->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat)
+        bpp = 8;
+      else if (src->fmt == UHDR_IMG_FMT_24bppRGB888)
+        bpp = 3;
+      for (size_t i = 0; i < src->h; i++) {
+        memcpy(plane_dst, plane_src, src->w * bpp);
+        plane_dst += (bpp * dst->stride[UHDR_PLANE_PACKED]);
+        plane_src += (bpp * src->stride[UHDR_PLANE_PACKED]);
+      }
+      return g_no_error;
     }
-    // copy cbcr
-    for (size_t i = 0; i < src->h / 2; i++) {
-      memcpy(uv_dst, uv_src, src->w * bpp);
-      uv_dst += (dst->stride[UHDR_PLANE_UV] * bpp);
-      uv_src += (src->stride[UHDR_PLANE_UV] * bpp);
+  } else {
+    if (src->fmt == UHDR_IMG_FMT_24bppRGB888 && dst->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
+      uint32_t* plane_dst = static_cast<uint32_t*>(dst->planes[UHDR_PLANE_PACKED]);
+      uint8_t* plane_src = static_cast<uint8_t*>(src->planes[UHDR_PLANE_PACKED]);
+      for (size_t i = 0; i < src->h; i++) {
+        uint32_t* pixel_dst = plane_dst;
+        uint8_t* pixel_src = plane_src;
+        for (size_t j = 0; j < src->w; j++) {
+          *pixel_dst = pixel_src[0] | (pixel_src[1] << 8) | (pixel_src[2] << 16) | (0xff << 24);
+          pixel_src += 3;
+          pixel_dst += 1;
+        }
+        plane_dst += dst->stride[UHDR_PLANE_PACKED];
+        plane_src += 3 * src->stride[UHDR_PLANE_PACKED];
+      }
+      return g_no_error;
     }
   }
-  return dst;
+  uhdr_error_info_t status;
+  status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+  status.has_detail = 1;
+  snprintf(
+      status.detail, sizeof status.detail,
+      "unsupported source / destinations color formats in copy_raw_image, src fmt %d, dst fmt %d",
+      src->fmt, dst->fmt);
+  return status;
 }
+
 // Use double type for intermediate results for better precision.
 static bool floatToUnsignedFractionImpl(float v, uint32_t maxNumerator, uint32_t* numerator,
                                         uint32_t* denominator) {
diff --git a/lib/src/gainmapmetadata.cpp b/lib/src/gainmapmetadata.cpp
index a2ab54c..972e6fa 100644
--- a/lib/src/gainmapmetadata.cpp
+++ b/lib/src/gainmapmetadata.cpp
@@ -19,40 +19,53 @@
 
 namespace ultrahdr {
 
-status_t streamWriteU8(std::vector<uint8_t> &data, uint8_t value) {
-  data.push_back(value);
-  return JPEGR_NO_ERROR;
-}
+void streamWriteU8(std::vector<uint8_t> &data, uint8_t value) { data.push_back(value); }
 
-status_t streamWriteU32(std::vector<uint8_t> &data, uint32_t value) {
+void streamWriteU32(std::vector<uint8_t> &data, uint32_t value) {
   data.push_back((value >> 24) & 0xff);
   data.push_back((value >> 16) & 0xff);
   data.push_back((value >> 8) & 0xff);
   data.push_back(value & 0xff);
-  return JPEGR_NO_ERROR;
 }
 
-status_t streamReadU8(const std::vector<uint8_t> &data, uint8_t &value, size_t &pos) {
+uhdr_error_info_t streamReadU8(const std::vector<uint8_t> &data, uint8_t &value, size_t &pos) {
   if (pos >= data.size()) {
-    return ERROR_JPEGR_METADATA_ERROR;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_MEM_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "attempting to read byte at position %d when the buffer size is %d", (int)pos,
+             (int)data.size());
+    return status;
   }
   value = data[pos++];
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
-status_t streamReadU32(const std::vector<uint8_t> &data, uint32_t &value, size_t &pos) {
+uhdr_error_info_t streamReadU32(const std::vector<uint8_t> &data, uint32_t &value, size_t &pos) {
   if (pos + 3 >= data.size()) {
-    return ERROR_JPEGR_METADATA_ERROR;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_MEM_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "attempting to read 4 bytes from position %d when the buffer size is %d", (int)pos,
+             (int)data.size());
+    return status;
   }
   value = (data[pos] << 24 | data[pos + 1] << 16 | data[pos + 2] << 8 | data[pos + 3]);
   pos += 4;
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
-status_t gain_map_metadata::encodeGainmapMetadata(const gain_map_metadata *metadata,
-                                                  std::vector<uint8_t> &out_data) {
-  if (metadata == nullptr) {
-    return ERROR_JPEGR_METADATA_ERROR;
+uhdr_error_info_t uhdr_gainmap_metadata_frac::encodeGainmapMetadata(
+    const uhdr_gainmap_metadata_frac *in_metadata, std::vector<uint8_t> &out_data) {
+  if (in_metadata == nullptr) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received nullptr for gain map metadata descriptor");
+    return status;
   }
 
   const uint8_t version = 0;
@@ -64,47 +77,47 @@ status_t gain_map_metadata::encodeGainmapMetadata(const gain_map_metadata *metad
   // gain map. But tone mapping is done in RGB space so there are always three
   // channels, even if the gain map is grayscale. Should this be revised?
   const bool allChannelsIdentical =
-      metadata->gainMapMinN[0] == metadata->gainMapMinN[1] &&
-      metadata->gainMapMinN[0] == metadata->gainMapMinN[2] &&
-      metadata->gainMapMinD[0] == metadata->gainMapMinD[1] &&
-      metadata->gainMapMinD[0] == metadata->gainMapMinD[2] &&
-      metadata->gainMapMaxN[0] == metadata->gainMapMaxN[1] &&
-      metadata->gainMapMaxN[0] == metadata->gainMapMaxN[2] &&
-      metadata->gainMapMaxD[0] == metadata->gainMapMaxD[1] &&
-      metadata->gainMapMaxD[0] == metadata->gainMapMaxD[2] &&
-      metadata->gainMapGammaN[0] == metadata->gainMapGammaN[1] &&
-      metadata->gainMapGammaN[0] == metadata->gainMapGammaN[2] &&
-      metadata->gainMapGammaD[0] == metadata->gainMapGammaD[1] &&
-      metadata->gainMapGammaD[0] == metadata->gainMapGammaD[2] &&
-      metadata->baseOffsetN[0] == metadata->baseOffsetN[1] &&
-      metadata->baseOffsetN[0] == metadata->baseOffsetN[2] &&
-      metadata->baseOffsetD[0] == metadata->baseOffsetD[1] &&
-      metadata->baseOffsetD[0] == metadata->baseOffsetD[2] &&
-      metadata->alternateOffsetN[0] == metadata->alternateOffsetN[1] &&
-      metadata->alternateOffsetN[0] == metadata->alternateOffsetN[2] &&
-      metadata->alternateOffsetD[0] == metadata->alternateOffsetD[1] &&
-      metadata->alternateOffsetD[0] == metadata->alternateOffsetD[2];
+      in_metadata->gainMapMinN[0] == in_metadata->gainMapMinN[1] &&
+      in_metadata->gainMapMinN[0] == in_metadata->gainMapMinN[2] &&
+      in_metadata->gainMapMinD[0] == in_metadata->gainMapMinD[1] &&
+      in_metadata->gainMapMinD[0] == in_metadata->gainMapMinD[2] &&
+      in_metadata->gainMapMaxN[0] == in_metadata->gainMapMaxN[1] &&
+      in_metadata->gainMapMaxN[0] == in_metadata->gainMapMaxN[2] &&
+      in_metadata->gainMapMaxD[0] == in_metadata->gainMapMaxD[1] &&
+      in_metadata->gainMapMaxD[0] == in_metadata->gainMapMaxD[2] &&
+      in_metadata->gainMapGammaN[0] == in_metadata->gainMapGammaN[1] &&
+      in_metadata->gainMapGammaN[0] == in_metadata->gainMapGammaN[2] &&
+      in_metadata->gainMapGammaD[0] == in_metadata->gainMapGammaD[1] &&
+      in_metadata->gainMapGammaD[0] == in_metadata->gainMapGammaD[2] &&
+      in_metadata->baseOffsetN[0] == in_metadata->baseOffsetN[1] &&
+      in_metadata->baseOffsetN[0] == in_metadata->baseOffsetN[2] &&
+      in_metadata->baseOffsetD[0] == in_metadata->baseOffsetD[1] &&
+      in_metadata->baseOffsetD[0] == in_metadata->baseOffsetD[2] &&
+      in_metadata->alternateOffsetN[0] == in_metadata->alternateOffsetN[1] &&
+      in_metadata->alternateOffsetN[0] == in_metadata->alternateOffsetN[2] &&
+      in_metadata->alternateOffsetD[0] == in_metadata->alternateOffsetD[1] &&
+      in_metadata->alternateOffsetD[0] == in_metadata->alternateOffsetD[2];
   const uint8_t channelCount = allChannelsIdentical ? 1u : 3u;
 
   if (channelCount == 3) {
     flags |= 1;
   }
-  if (metadata->useBaseColorSpace) {
+  if (in_metadata->useBaseColorSpace) {
     flags |= 2;
   }
-  if (metadata->backwardDirection) {
+  if (in_metadata->backwardDirection) {
     flags |= 4;
   }
 
-  const uint32_t denom = metadata->baseHdrHeadroomD;
+  const uint32_t denom = in_metadata->baseHdrHeadroomD;
   bool useCommonDenominator = true;
-  if (metadata->baseHdrHeadroomD != denom || metadata->alternateHdrHeadroomD != denom) {
+  if (in_metadata->baseHdrHeadroomD != denom || in_metadata->alternateHdrHeadroomD != denom) {
     useCommonDenominator = false;
   }
   for (int c = 0; c < channelCount; ++c) {
-    if (metadata->gainMapMinD[c] != denom || metadata->gainMapMaxD[c] != denom ||
-        metadata->gainMapGammaD[c] != denom || metadata->baseOffsetD[c] != denom ||
-        metadata->alternateOffsetD[c] != denom) {
+    if (in_metadata->gainMapMinD[c] != denom || in_metadata->gainMapMaxD[c] != denom ||
+        in_metadata->gainMapGammaD[c] != denom || in_metadata->baseOffsetD[c] != denom ||
+        in_metadata->alternateOffsetD[c] != denom) {
       useCommonDenominator = false;
     }
   }
@@ -115,100 +128,112 @@ status_t gain_map_metadata::encodeGainmapMetadata(const gain_map_metadata *metad
 
   if (useCommonDenominator) {
     streamWriteU32(out_data, denom);
-    streamWriteU32(out_data, metadata->baseHdrHeadroomN);
-    streamWriteU32(out_data, metadata->alternateHdrHeadroomN);
+    streamWriteU32(out_data, in_metadata->baseHdrHeadroomN);
+    streamWriteU32(out_data, in_metadata->alternateHdrHeadroomN);
     for (int c = 0; c < channelCount; ++c) {
-      streamWriteU32(out_data, (uint32_t)metadata->gainMapMinN[c]);
-      streamWriteU32(out_data, (uint32_t)metadata->gainMapMaxN[c]);
-      streamWriteU32(out_data, metadata->gainMapGammaN[c]);
-      streamWriteU32(out_data, (uint32_t)metadata->baseOffsetN[c]);
-      streamWriteU32(out_data, (uint32_t)metadata->alternateOffsetN[c]);
+      streamWriteU32(out_data, (uint32_t)in_metadata->gainMapMinN[c]);
+      streamWriteU32(out_data, (uint32_t)in_metadata->gainMapMaxN[c]);
+      streamWriteU32(out_data, in_metadata->gainMapGammaN[c]);
+      streamWriteU32(out_data, (uint32_t)in_metadata->baseOffsetN[c]);
+      streamWriteU32(out_data, (uint32_t)in_metadata->alternateOffsetN[c]);
     }
   } else {
-    streamWriteU32(out_data, metadata->baseHdrHeadroomN);
-    streamWriteU32(out_data, metadata->baseHdrHeadroomD);
-    streamWriteU32(out_data, metadata->alternateHdrHeadroomN);
-    streamWriteU32(out_data, metadata->alternateHdrHeadroomD);
+    streamWriteU32(out_data, in_metadata->baseHdrHeadroomN);
+    streamWriteU32(out_data, in_metadata->baseHdrHeadroomD);
+    streamWriteU32(out_data, in_metadata->alternateHdrHeadroomN);
+    streamWriteU32(out_data, in_metadata->alternateHdrHeadroomD);
     for (int c = 0; c < channelCount; ++c) {
-      streamWriteU32(out_data, (uint32_t)metadata->gainMapMinN[c]);
-      streamWriteU32(out_data, metadata->gainMapMinD[c]);
-      streamWriteU32(out_data, (uint32_t)metadata->gainMapMaxN[c]);
-      streamWriteU32(out_data, metadata->gainMapMaxD[c]);
-      streamWriteU32(out_data, metadata->gainMapGammaN[c]);
-      streamWriteU32(out_data, metadata->gainMapGammaD[c]);
-      streamWriteU32(out_data, (uint32_t)metadata->baseOffsetN[c]);
-      streamWriteU32(out_data, metadata->baseOffsetD[c]);
-      streamWriteU32(out_data, (uint32_t)metadata->alternateOffsetN[c]);
-      streamWriteU32(out_data, metadata->alternateOffsetD[c]);
+      streamWriteU32(out_data, (uint32_t)in_metadata->gainMapMinN[c]);
+      streamWriteU32(out_data, in_metadata->gainMapMinD[c]);
+      streamWriteU32(out_data, (uint32_t)in_metadata->gainMapMaxN[c]);
+      streamWriteU32(out_data, in_metadata->gainMapMaxD[c]);
+      streamWriteU32(out_data, in_metadata->gainMapGammaN[c]);
+      streamWriteU32(out_data, in_metadata->gainMapGammaD[c]);
+      streamWriteU32(out_data, (uint32_t)in_metadata->baseOffsetN[c]);
+      streamWriteU32(out_data, in_metadata->baseOffsetD[c]);
+      streamWriteU32(out_data, (uint32_t)in_metadata->alternateOffsetN[c]);
+      streamWriteU32(out_data, in_metadata->alternateOffsetD[c]);
     }
   }
 
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
-status_t gain_map_metadata::decodeGainmapMetadata(const std::vector<uint8_t> &data,
-                                                  gain_map_metadata *out_metadata) {
+uhdr_error_info_t uhdr_gainmap_metadata_frac::decodeGainmapMetadata(
+    const std::vector<uint8_t> &in_data, uhdr_gainmap_metadata_frac *out_metadata) {
   if (out_metadata == nullptr) {
-    return ERROR_JPEGR_BAD_PTR;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received nullptr for gain map metadata descriptor");
+    return status;
   }
 
   size_t pos = 0;
   uint8_t version = 0xff;
-  JPEGR_CHECK(streamReadU8(data, version, pos))
-
+  UHDR_ERR_CHECK(streamReadU8(in_data, version, pos))
   if (version != 0) {
-    return ERROR_JPEGR_UNSUPPORTED_FEATURE;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received unexpected version %d, expected 0",
+             version);
+    return status;
   }
 
   uint8_t flags = 0xff;
-  JPEGR_CHECK(streamReadU8(data, flags, pos))
-
+  UHDR_ERR_CHECK(streamReadU8(in_data, flags, pos))
   uint8_t channelCount = (flags & 1) * 2 + 1;
-
   if (!(channelCount == 1 || channelCount == 3)) {
-    return ERROR_JPEGR_UNSUPPORTED_FEATURE;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received unexpected channel count %d, expects one of {1, 3}", channelCount);
+    return status;
   }
   out_metadata->useBaseColorSpace = (flags & 2) != 0;
   out_metadata->backwardDirection = (flags & 4) != 0;
   const bool useCommonDenominator = (flags & 8) != 0;
 
   if (useCommonDenominator) {
-    uint32_t commonDenominator;
-    JPEGR_CHECK(streamReadU32(data, commonDenominator, pos))
+    uint32_t commonDenominator = 1u;
+    UHDR_ERR_CHECK(streamReadU32(in_data, commonDenominator, pos))
 
-    JPEGR_CHECK(streamReadU32(data, out_metadata->baseHdrHeadroomN, pos))
+    UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->baseHdrHeadroomN, pos))
     out_metadata->baseHdrHeadroomD = commonDenominator;
-    JPEGR_CHECK(streamReadU32(data, out_metadata->alternateHdrHeadroomN, pos))
+    UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateHdrHeadroomN, pos))
     out_metadata->alternateHdrHeadroomD = commonDenominator;
 
     for (int c = 0; c < channelCount; ++c) {
-      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMinN[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMinN[c], pos))
       out_metadata->gainMapMinD[c] = commonDenominator;
-      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMaxN[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMaxN[c], pos))
       out_metadata->gainMapMaxD[c] = commonDenominator;
-      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapGammaN[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapGammaN[c], pos))
       out_metadata->gainMapGammaD[c] = commonDenominator;
-      JPEGR_CHECK(streamReadU32(data, out_metadata->baseOffsetN[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->baseOffsetN[c], pos))
       out_metadata->baseOffsetD[c] = commonDenominator;
-      JPEGR_CHECK(streamReadU32(data, out_metadata->alternateOffsetN[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateOffsetN[c], pos))
       out_metadata->alternateOffsetD[c] = commonDenominator;
     }
   } else {
-    JPEGR_CHECK(streamReadU32(data, out_metadata->baseHdrHeadroomN, pos))
-    JPEGR_CHECK(streamReadU32(data, out_metadata->baseHdrHeadroomD, pos))
-    JPEGR_CHECK(streamReadU32(data, out_metadata->alternateHdrHeadroomN, pos))
-    JPEGR_CHECK(streamReadU32(data, out_metadata->alternateHdrHeadroomD, pos))
+    UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->baseHdrHeadroomN, pos))
+    UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->baseHdrHeadroomD, pos))
+    UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateHdrHeadroomN, pos))
+    UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateHdrHeadroomD, pos))
     for (int c = 0; c < channelCount; ++c) {
-      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMinN[c], pos))
-      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMinD[c], pos))
-      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMaxN[c], pos))
-      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapMaxD[c], pos))
-      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapGammaN[c], pos))
-      JPEGR_CHECK(streamReadU32(data, out_metadata->gainMapGammaD[c], pos))
-      JPEGR_CHECK(streamReadU32(data, out_metadata->baseOffsetN[c], pos))
-      JPEGR_CHECK(streamReadU32(data, out_metadata->baseOffsetD[c], pos))
-      JPEGR_CHECK(streamReadU32(data, out_metadata->alternateOffsetN[c], pos))
-      JPEGR_CHECK(streamReadU32(data, out_metadata->alternateOffsetD[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMinN[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMinD[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMaxN[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapMaxD[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapGammaN[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->gainMapGammaD[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->baseOffsetN[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->baseOffsetD[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateOffsetN[c], pos))
+      UHDR_ERR_CHECK(streamReadU32(in_data, out_metadata->alternateOffsetD[c], pos))
     }
   }
 
@@ -226,59 +251,71 @@ status_t gain_map_metadata::decodeGainmapMetadata(const std::vector<uint8_t> &da
     out_metadata->alternateOffsetD[c] = out_metadata->alternateOffsetD[0];
   }
 
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
-#define CHECK_NOT_ZERO(x)                \
-  do {                                   \
-    if (x == 0) {                        \
-      return ERROR_JPEGR_METADATA_ERROR; \
-    }                                    \
-  } while (0)
+#define UHDR_CHECK_NON_ZERO(x, message)                                                            \
+  if (x == 0) {                                                                                    \
+    uhdr_error_info_t status;                                                                      \
+    status.error_code = UHDR_CODEC_INVALID_PARAM;                                                  \
+    status.has_detail = 1;                                                                         \
+    snprintf(status.detail, sizeof status.detail, "received 0 (bad value) for field %s", message); \
+    return status;                                                                                 \
+  }
 
-status_t gain_map_metadata::gainmapMetadataFractionToFloat(const gain_map_metadata *from,
-                                                           ultrahdr_metadata_ptr to) {
+uhdr_error_info_t uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(
+    const uhdr_gainmap_metadata_frac *from, uhdr_gainmap_metadata_ext_t *to) {
   if (from == nullptr || to == nullptr) {
-    return ERROR_JPEGR_BAD_PTR;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received nullptr for gain map metadata descriptor");
+    return status;
   }
 
-  CHECK_NOT_ZERO(from->baseHdrHeadroomD);
-  CHECK_NOT_ZERO(from->alternateHdrHeadroomD);
+  UHDR_CHECK_NON_ZERO(from->baseHdrHeadroomD, "baseHdrHeadroom denominator");
+  UHDR_CHECK_NON_ZERO(from->alternateHdrHeadroomD, "alternateHdrHeadroom denominator");
   for (int i = 0; i < 3; ++i) {
-    CHECK_NOT_ZERO(from->gainMapMaxD[i]);
-    CHECK_NOT_ZERO(from->gainMapGammaD[i]);
-    CHECK_NOT_ZERO(from->gainMapMinD[i]);
-    CHECK_NOT_ZERO(from->baseOffsetD[i]);
-    CHECK_NOT_ZERO(from->alternateOffsetD[i]);
+    UHDR_CHECK_NON_ZERO(from->gainMapMaxD[i], "gainMapMax denominator");
+    UHDR_CHECK_NON_ZERO(from->gainMapGammaD[i], "gainMapGamma denominator");
+    UHDR_CHECK_NON_ZERO(from->gainMapMinD[i], "gainMapMin denominator");
+    UHDR_CHECK_NON_ZERO(from->baseOffsetD[i], "baseOffset denominator");
+    UHDR_CHECK_NON_ZERO(from->alternateOffsetD[i], "alternateOffset denominator");
   }
-  to->version = kGainMapVersion;
-  to->maxContentBoost = (float)from->gainMapMaxN[0] / from->gainMapMaxD[0];
-  to->minContentBoost = (float)from->gainMapMinN[0] / from->gainMapMinD[0];
+  to->version = kJpegrVersion;
+  to->max_content_boost = (float)from->gainMapMaxN[0] / from->gainMapMaxD[0];
+  to->min_content_boost = (float)from->gainMapMinN[0] / from->gainMapMinD[0];
   to->gamma = (float)from->gainMapGammaN[0] / from->gainMapGammaD[0];
 
   // BaseRenditionIsHDR is false
-  to->offsetSdr = (float)from->baseOffsetN[0] / from->baseOffsetD[0];
-  to->offsetHdr = (float)from->alternateOffsetN[0] / from->alternateOffsetD[0];
-  to->hdrCapacityMax = (float)from->alternateHdrHeadroomN / from->alternateHdrHeadroomD;
-  to->hdrCapacityMin = (float)from->baseHdrHeadroomN / from->baseHdrHeadroomD;
+  to->offset_sdr = (float)from->baseOffsetN[0] / from->baseOffsetD[0];
+  to->offset_hdr = (float)from->alternateOffsetN[0] / from->alternateOffsetD[0];
+  to->hdr_capacity_max = (float)from->alternateHdrHeadroomN / from->alternateHdrHeadroomD;
+  to->hdr_capacity_min = (float)from->baseHdrHeadroomN / from->baseHdrHeadroomD;
 
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
-status_t gain_map_metadata::gainmapMetadataFloatToFraction(const ultrahdr_metadata_ptr from,
-                                                           gain_map_metadata *to) {
+uhdr_error_info_t uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(
+    const uhdr_gainmap_metadata_ext_t *from, uhdr_gainmap_metadata_frac *to) {
   if (from == nullptr || to == nullptr) {
-    return ERROR_JPEGR_BAD_PTR;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received nullptr for gain map metadata descriptor");
+    return status;
   }
 
   to->backwardDirection = false;
   to->useBaseColorSpace = true;
 
-  floatToUnsignedFraction(from->maxContentBoost, &to->gainMapMaxN[0], &to->gainMapMaxD[0]);
+  floatToUnsignedFraction(from->max_content_boost, &to->gainMapMaxN[0], &to->gainMapMaxD[0]);
   to->gainMapMaxN[2] = to->gainMapMaxN[1] = to->gainMapMaxN[0];
   to->gainMapMaxD[2] = to->gainMapMaxD[1] = to->gainMapMaxD[0];
 
-  floatToUnsignedFraction(from->minContentBoost, &to->gainMapMinN[0], &to->gainMapMinD[0]);
+  floatToUnsignedFraction(from->min_content_boost, &to->gainMapMinN[0], &to->gainMapMinD[0]);
   to->gainMapMinN[2] = to->gainMapMinN[1] = to->gainMapMinN[0];
   to->gainMapMinD[2] = to->gainMapMinD[1] = to->gainMapMinD[0];
 
@@ -286,20 +323,20 @@ status_t gain_map_metadata::gainmapMetadataFloatToFraction(const ultrahdr_metada
   to->gainMapGammaN[2] = to->gainMapGammaN[1] = to->gainMapGammaN[0];
   to->gainMapGammaD[2] = to->gainMapGammaD[1] = to->gainMapGammaD[0];
 
-  floatToUnsignedFraction(from->offsetSdr, &to->baseOffsetN[0], &to->baseOffsetD[0]);
+  floatToUnsignedFraction(from->offset_sdr, &to->baseOffsetN[0], &to->baseOffsetD[0]);
   to->baseOffsetN[2] = to->baseOffsetN[1] = to->baseOffsetN[0];
   to->baseOffsetD[2] = to->baseOffsetD[1] = to->baseOffsetD[0];
 
-  floatToUnsignedFraction(from->offsetHdr, &to->alternateOffsetN[0], &to->alternateOffsetD[0]);
+  floatToUnsignedFraction(from->offset_hdr, &to->alternateOffsetN[0], &to->alternateOffsetD[0]);
   to->alternateOffsetN[2] = to->alternateOffsetN[1] = to->alternateOffsetN[0];
   to->alternateOffsetD[2] = to->alternateOffsetD[1] = to->alternateOffsetD[0];
 
-  floatToUnsignedFraction(from->hdrCapacityMin, &to->baseHdrHeadroomN, &to->baseHdrHeadroomD);
+  floatToUnsignedFraction(from->hdr_capacity_min, &to->baseHdrHeadroomN, &to->baseHdrHeadroomD);
 
-  floatToUnsignedFraction(from->hdrCapacityMax, &to->alternateHdrHeadroomN,
+  floatToUnsignedFraction(from->hdr_capacity_max, &to->alternateHdrHeadroomN,
                           &to->alternateHdrHeadroomD);
 
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
 }  // namespace ultrahdr
diff --git a/lib/src/gpu/applygainmap_gl.cpp b/lib/src/gpu/applygainmap_gl.cpp
new file mode 100644
index 0000000..7657796
--- /dev/null
+++ b/lib/src/gpu/applygainmap_gl.cpp
@@ -0,0 +1,338 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include "ultrahdr/ultrahdrcommon.h"
+#include "ultrahdr/gainmapmath.h"
+#include "ultrahdr/jpegr.h"
+
+namespace ultrahdr {
+
+extern const std::string vertex_shader = R"__SHADER__(#version 300 es
+  precision highp float;
+
+  layout(location = 0) in vec4 aPos;
+  layout(location = 1) in vec2 aTexCoord;
+
+  out vec2 TexCoord;
+
+  void main() {
+    gl_Position = aPos;
+    TexCoord = aTexCoord;
+  }
+)__SHADER__";
+
+static const std::string getYuv444PixelShader = R"__SHADER__(
+  uniform sampler2D yuvTexture;
+  uniform int pWidth, pHeight;
+
+  vec3 getYUVPixel() {
+    // Convert texCoord to pixel coordinates
+    ivec2 pixelCoord = ivec2(TexCoord * vec2(pWidth, pHeight));
+
+    float y = texelFetch(yuvTexture, ivec2(pixelCoord.r, pixelCoord.g), 0).r;
+    float u = texelFetch(yuvTexture, ivec2(pixelCoord.r, pixelCoord.g + pHeight), 0).r;
+    float v = texelFetch(yuvTexture, ivec2(pixelCoord.r, pixelCoord.g + 2 * pHeight), 0).r;
+
+    return vec3(y, u, v);
+  }
+)__SHADER__";
+
+static const std::string getYuv422PixelShader = R"__SHADER__(
+  uniform sampler2D yuvTexture;
+  uniform int pWidth, pHeight;
+
+  vec3 getYUVPixel() {
+    // Convert texCoord to pixel coordinates
+    ivec2 pixelCoord = ivec2(TexCoord * vec2(pWidth, pHeight));
+    ivec2 uvCoord = ivec2(pixelCoord.r / 2, pixelCoord.g);
+    int uvWidth = pWidth / 2;
+    int uvHeight = pHeight;
+    uint yPlaneSize = uint(pWidth) * uint(pHeight);
+    uint uPlaneSize = uint(uvWidth) * uint(uvHeight);
+    uint yIndex = uint(pixelCoord.g * pWidth + pixelCoord.r);
+    uint uIndex = yPlaneSize + uint(uvCoord.g * uvWidth + uvCoord.r);
+    uint vIndex = yPlaneSize + uPlaneSize + uint(uvCoord.g * uvWidth + uvCoord.r);
+
+    float y = texelFetch(yuvTexture, ivec2(yIndex % uint(pWidth), yIndex / uint(pWidth)), 0).r;
+    float u = texelFetch(yuvTexture, ivec2(uIndex % uint(pWidth), uIndex / uint(pWidth)), 0).r;
+    float v = texelFetch(yuvTexture, ivec2(vIndex % uint(pWidth), vIndex / uint(pWidth)), 0).r;
+
+    return vec3(y, u, v);
+  }
+)__SHADER__";
+
+static const std::string getYuv420PixelShader = R"__SHADER__(
+  uniform sampler2D yuvTexture;
+  uniform int pWidth, pHeight;
+
+  vec3 getYUVPixel() {
+    // Convert texCoord to pixel coordinates
+    ivec2 pixelCoord = ivec2(TexCoord * vec2(pWidth, pHeight));
+    ivec2 uvCoord = pixelCoord / 2;
+    int uvWidth = pWidth / 2;
+    int uvHeight = pHeight / 2;
+    uint yPlaneSize = uint(pWidth) * uint(pHeight);
+    uint uPlaneSize = uint(uvWidth) * uint(uvHeight);
+    uint yIndex = uint(pixelCoord.g * pWidth + pixelCoord.r);
+    uint uIndex = yPlaneSize + uint(uvCoord.g * uvWidth + uvCoord.r);
+    uint vIndex = yPlaneSize + uPlaneSize + uint(uvCoord.g * uvWidth + uvCoord.r);
+
+    float y = texelFetch(yuvTexture, ivec2(yIndex % uint(pWidth), yIndex / uint(pWidth)), 0).r;
+    float u = texelFetch(yuvTexture, ivec2(uIndex % uint(pWidth), uIndex / uint(pWidth)), 0).r;
+    float v = texelFetch(yuvTexture, ivec2(vIndex % uint(pWidth), vIndex / uint(pWidth)), 0).r;
+
+    return vec3(y, u, v);
+  }
+)__SHADER__";
+
+static const std::string p3YUVToRGBShader = R"__SHADER__(
+  vec3 p3YuvToRgb(const vec3 color) {
+    const vec3 offset = vec3(0.0, 128.0f / 255.0f, 128.0f / 255.0f);
+    const mat3 transform = mat3(
+        1.0,  1.0, 1.0,
+        0.0, -0.344136286, 1.772,
+        1.402, -0.714136286, 0.0);
+    return clamp(transform * (color - offset), 0.0, 1.0);
+  }
+)__SHADER__";
+
+static const std::string sRGBEOTFShader = R"__SHADER__(
+  float sRGBEOTF(float e_gamma) {
+    return e_gamma <= 0.04045 ? e_gamma / 12.92 : pow((e_gamma + 0.055) / 1.055, 2.4);
+  }
+
+  vec3 sRGBEOTF(const vec3 e_gamma) {
+    return vec3(sRGBEOTF(e_gamma.r), sRGBEOTF(e_gamma.g), sRGBEOTF(e_gamma.b));
+  }
+)__SHADER__";
+
+static const std::string getGainMapSampleSingleChannel = R"__SHADER__(
+  uniform sampler2D gainMapTexture;
+
+  vec3 sampleMap(sampler2D map) { return vec3(texture(map, TexCoord).r); }
+)__SHADER__";
+
+static const std::string getGainMapSampleMultiChannel = R"__SHADER__(
+  uniform sampler2D gainMapTexture;
+
+  vec3 sampleMap(sampler2D map) { return texture(map, TexCoord).rgb; }
+)__SHADER__";
+
+static const std::string applyGainMapShader = R"__SHADER__(
+  uniform float gamma;
+  uniform float logMinBoost;
+  uniform float logMaxBoost;
+  uniform float weight;
+  uniform float displayBoost;
+
+  float applyGainMapSample(const float channel, float gain) {
+    gain = pow(gain, 1.0f / gamma);
+    float logBoost = logMinBoost * (1.0f - gain) + logMaxBoost * gain;
+    logBoost = exp2(logBoost * weight);
+    return channel * logBoost / displayBoost;
+  }
+
+  vec3 applyGain(const vec3 color, const vec3 gain) {
+    return vec3(applyGainMapSample(color.r, gain.r),
+            applyGainMapSample(color.g, gain.g),
+            applyGainMapSample(color.b, gain.b));
+  }
+)__SHADER__";
+
+static const std::string linearOETFShader = R"__SHADER__(
+  vec3 OETF(const vec3 linear) { return linear; }
+)__SHADER__";
+
+static const std::string hlgOETFShader = R"__SHADER__(
+  float OETF(const float linear) {
+    const float kHlgA = 0.17883277;
+    const float kHlgB = 0.28466892;
+    const float kHlgC = 0.55991073;
+    return linear <= 1.0 / 12.0 ? sqrt(3.0 * linear) : kHlgA * log(12.0 * linear - kHlgB) + kHlgC;
+  }
+
+  vec3 OETF(const vec3 linear) {
+    return vec3(OETF(linear.r), OETF(linear.g), OETF(linear.b));
+  }
+)__SHADER__";
+
+static const std::string pqOETFShader = R"__SHADER__(
+  vec3 OETF(const vec3 linear) {
+    const float kPqM1 = (2610.0 / 4096.0) / 4.0;
+    const float kPqM2 = (2523.0 / 4096.0) * 128.0;
+    const float kPqC1 = (3424.0 / 4096.0);
+    const float kPqC2 = (2413.0 / 4096.0) * 32.0;
+    const float kPqC3 = (2392.0 / 4096.0) * 32.0;
+    vec3 tmp = pow(linear, vec3(kPqM1));
+    tmp = (kPqC1 + kPqC2 * tmp) / (1.0 + kPqC3 * tmp);
+    return pow(tmp, vec3(kPqM2));
+  }
+)__SHADER__";
+
+std::string getApplyGainMapFragmentShader(uhdr_img_fmt sdr_fmt, uhdr_img_fmt gm_fmt,
+                                          uhdr_color_transfer output_ct) {
+  std::string shader_code = R"__SHADER__(#version 300 es
+    precision highp float;
+    precision highp int;
+
+    out vec4 FragColor;
+    in vec2 TexCoord;
+  )__SHADER__";
+
+  if (sdr_fmt == UHDR_IMG_FMT_24bppYCbCr444) {
+    shader_code.append(getYuv444PixelShader);
+  } else if (sdr_fmt == UHDR_IMG_FMT_16bppYCbCr422) {
+    shader_code.append(getYuv422PixelShader);
+  } else if (sdr_fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+    shader_code.append(getYuv420PixelShader);
+  }
+  shader_code.append(p3YUVToRGBShader);
+  shader_code.append(sRGBEOTFShader);
+  shader_code.append(gm_fmt == UHDR_IMG_FMT_8bppYCbCr400 ? getGainMapSampleSingleChannel
+                                                         : getGainMapSampleMultiChannel);
+  shader_code.append(applyGainMapShader);
+  if (output_ct == UHDR_CT_LINEAR) {
+    shader_code.append(linearOETFShader);
+  } else if (output_ct == UHDR_CT_HLG) {
+    shader_code.append(hlgOETFShader);
+  } else if (output_ct == UHDR_CT_PQ) {
+    shader_code.append(pqOETFShader);
+  }
+
+  shader_code.append(R"__SHADER__(
+    void main() {
+      vec3 yuv_gamma_sdr = getYUVPixel();
+      vec3 rgb_gamma_sdr = p3YuvToRgb(yuv_gamma_sdr);
+      vec3 rgb_sdr = sRGBEOTF(rgb_gamma_sdr);
+      vec3 gain = sampleMap(gainMapTexture);
+      vec3 rgb_hdr = applyGain(rgb_sdr, gain);
+      vec3 rgb_gamma_hdr = OETF(rgb_hdr);
+      FragColor = vec4(rgb_gamma_hdr, 1.0);
+    }
+  )__SHADER__");
+  return shader_code;
+}
+
+bool isBufferDataContiguous(uhdr_raw_image_t* img) {
+  if (img->fmt == UHDR_IMG_FMT_32bppRGBA8888 || img->fmt == UHDR_IMG_FMT_24bppRGB888 ||
+      img->fmt == UHDR_IMG_FMT_8bppYCbCr400 || img->fmt == UHDR_IMG_FMT_32bppRGBA1010102 ||
+      img->fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+    return img->stride[UHDR_PLANE_PACKED] == img->w;
+  } else if (img->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
+    uint16_t* y = static_cast<uint16_t*>(img->planes[UHDR_PLANE_Y]);
+    uint16_t* u = static_cast<uint16_t*>(img->planes[UHDR_PLANE_UV]);
+    std::ptrdiff_t sz = u - y;
+    long pixels = img->w * img->h;
+    return img->stride[UHDR_PLANE_Y] == img->w && img->stride[UHDR_PLANE_UV] == img->w &&
+           sz == pixels;
+  } else if (img->fmt == UHDR_IMG_FMT_12bppYCbCr420 || img->fmt == UHDR_IMG_FMT_24bppYCbCr444 ||
+             img->fmt == UHDR_IMG_FMT_16bppYCbCr422) {
+    int h_samp_factor = img->fmt == UHDR_IMG_FMT_24bppYCbCr444 ? 1 : 2;
+    int v_samp_factor = img->fmt == UHDR_IMG_FMT_12bppYCbCr420 ? 2 : 1;
+    uint8_t* y = static_cast<uint8_t*>(img->planes[UHDR_PLANE_Y]);
+    uint8_t* u = static_cast<uint8_t*>(img->planes[UHDR_PLANE_U]);
+    uint8_t* v = static_cast<uint8_t*>(img->planes[UHDR_PLANE_V]);
+    std::ptrdiff_t sz_a = u - y, sz_b = v - u;
+    long pixels = img->w * img->h;
+    return img->stride[UHDR_PLANE_Y] == img->w &&
+           img->stride[UHDR_PLANE_U] == img->w / h_samp_factor &&
+           img->stride[UHDR_PLANE_V] == img->w / h_samp_factor && sz_a == pixels &&
+           sz_b == pixels / (h_samp_factor * v_samp_factor);
+  }
+  return false;
+}
+
+uhdr_error_info_t applyGainMapGLES(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
+                                   uhdr_gainmap_metadata_ext_t* gainmap_metadata,
+                                   uhdr_color_transfer_t output_ct, float display_boost,
+                                   uhdr_raw_image_t* dest, uhdr_opengl_ctxt_t* opengl_ctxt) {
+  GLuint shaderProgram = 0;   // shader program
+  GLuint yuvTexture = 0;      // sdr intent texture
+  GLuint frameBuffer = 0;
+
+#define RET_IF_ERR()                                           \
+  if (opengl_ctxt->mErrorStatus.error_code != UHDR_CODEC_OK) { \
+    if (frameBuffer) glDeleteFramebuffers(1, &frameBuffer);    \
+    if (yuvTexture) glDeleteTextures(1, &yuvTexture);          \
+    if (shaderProgram) glDeleteProgram(shaderProgram);         \
+    return opengl_ctxt->mErrorStatus;                          \
+  }
+
+  shaderProgram = opengl_ctxt->create_shader_program(
+      vertex_shader.c_str(),
+      getApplyGainMapFragmentShader(sdr_intent->fmt, gainmap_img->fmt, output_ct).c_str());
+  RET_IF_ERR()
+
+  yuvTexture = opengl_ctxt->create_texture(sdr_intent->fmt, sdr_intent->w, sdr_intent->h,
+                                           sdr_intent->planes[0]);
+  opengl_ctxt->mGainmapImgTexture = opengl_ctxt->create_texture(
+      gainmap_img->fmt, gainmap_img->w, gainmap_img->h, gainmap_img->planes[0]);
+  opengl_ctxt->mDecodedImgTexture = opengl_ctxt->create_texture(
+      output_ct == UHDR_CT_LINEAR ? UHDR_IMG_FMT_64bppRGBAHalfFloat : UHDR_IMG_FMT_32bppRGBA1010102,
+      sdr_intent->w, sdr_intent->h, nullptr);
+  RET_IF_ERR()
+
+  frameBuffer = opengl_ctxt->setup_framebuffer(opengl_ctxt->mDecodedImgTexture);
+  RET_IF_ERR()
+
+  glViewport(0, 0, sdr_intent->w, sdr_intent->h);
+  glUseProgram(shaderProgram);
+
+  // Get the location of the uniform variables
+  GLint pWidthLocation = glGetUniformLocation(shaderProgram, "pWidth");
+  GLint pHeightLocation = glGetUniformLocation(shaderProgram, "pHeight");
+  GLint gammaLocation = glGetUniformLocation(shaderProgram, "gamma");
+  GLint logMinBoostLocation = glGetUniformLocation(shaderProgram, "logMinBoost");
+  GLint logMaxBoostLocation = glGetUniformLocation(shaderProgram, "logMaxBoost");
+  GLint weightLocation = glGetUniformLocation(shaderProgram, "weight");
+  GLint displayBoostLocation = glGetUniformLocation(shaderProgram, "displayBoost");
+
+  glUniform1i(pWidthLocation, sdr_intent->w);
+  glUniform1i(pHeightLocation, sdr_intent->h);
+  glUniform1f(gammaLocation, gainmap_metadata->gamma);
+  glUniform1f(logMinBoostLocation, log2(gainmap_metadata->min_content_boost));
+  glUniform1f(logMaxBoostLocation, log2(gainmap_metadata->max_content_boost));
+  glUniform1f(weightLocation, display_boost / gainmap_metadata->hdr_capacity_max);
+  glUniform1f(displayBoostLocation, display_boost);
+
+  glActiveTexture(GL_TEXTURE0);
+  glBindTexture(GL_TEXTURE_2D, yuvTexture);
+  glUniform1i(glGetUniformLocation(shaderProgram, "yuvTexture"), 0);
+
+  glActiveTexture(GL_TEXTURE1);
+  glBindTexture(GL_TEXTURE_2D, opengl_ctxt->mGainmapImgTexture);
+  glUniform1i(glGetUniformLocation(shaderProgram, "gainMapTexture"), 1);
+
+  opengl_ctxt->check_gl_errors("binding values to uniforms");
+  RET_IF_ERR()
+
+  glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, 0);
+
+  glBindFramebuffer(GL_FRAMEBUFFER, 0);
+
+  opengl_ctxt->check_gl_errors("reading gles output");
+  RET_IF_ERR()
+
+  dest->cg = sdr_intent->cg;
+
+  if (frameBuffer) glDeleteFramebuffers(1, &frameBuffer);
+  if (yuvTexture) glDeleteTextures(1, &yuvTexture);
+  if (shaderProgram) glDeleteProgram(shaderProgram);
+
+  return opengl_ctxt->mErrorStatus;
+}
+
+}  // namespace ultrahdr
diff --git a/lib/src/gpu/editorhelper_gl.cpp b/lib/src/gpu/editorhelper_gl.cpp
new file mode 100644
index 0000000..3726a6d
--- /dev/null
+++ b/lib/src/gpu/editorhelper_gl.cpp
@@ -0,0 +1,365 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include <ultrahdr/editorhelper.h>
+
+
+namespace ultrahdr {
+
+extern const std::string vertex_shader;
+
+static const std::string mirror_horz_fragmentSource = R"__SHADER__(#version 300 es
+  precision highp float;
+  precision highp sampler2D;
+  in vec2 TexCoord;
+  out vec4 outColor;
+  uniform sampler2D srcTexture;
+  void main() {
+      vec2 texCoord = TexCoord;
+      texCoord.y = 1.0 - TexCoord.y; // Horizontal mirror
+      ivec2 texelCoord = ivec2(texCoord * vec2(textureSize(srcTexture, 0)));
+      vec4 sampledColor = texelFetch(srcTexture, texelCoord, 0);
+      outColor = sampledColor;
+  }
+)__SHADER__";
+
+static const std::string mirror_vert_fragmentSource = R"__SHADER__(#version 300 es
+  precision highp float;
+  precision highp sampler2D;
+  in vec2 TexCoord;
+  out vec4 outColor;
+  uniform sampler2D srcTexture;
+  void main() {
+      vec2 texCoord = TexCoord;
+      texCoord.x = 1.0 - TexCoord.x; // Vertical mirror
+      ivec2 texelCoord = ivec2(texCoord * vec2(textureSize(srcTexture, 0)));
+      vec4 sampledColor = texelFetch(srcTexture, texelCoord, 0);
+      outColor = sampledColor;
+  }
+)__SHADER__";
+
+static const std::string rotate_90_fragmentSource = R"__SHADER__(#version 300 es
+  precision highp float;
+  precision highp sampler2D;
+  in vec2 TexCoord;
+  out vec4 outColor;
+  uniform sampler2D srcTexture;
+  void main() {
+      vec2 texCoord = TexCoord;
+      texCoord = vec2(TexCoord.y, 1.0 - TexCoord.x); // 90 degree
+      ivec2 texelCoord = ivec2(texCoord * vec2(textureSize(srcTexture, 0)));
+      vec4 sampledColor = texelFetch(srcTexture, texelCoord, 0);
+      outColor = sampledColor;
+  }
+)__SHADER__";
+
+static const std::string rotate_180_fragmentSource = R"__SHADER__(#version 300 es
+  precision highp float;
+  precision highp sampler2D;
+  in vec2 TexCoord;
+  out vec4 outColor;
+  uniform sampler2D srcTexture;
+  uniform int rotateDegree;
+  void main() {
+      vec2 texCoord = TexCoord;
+      texCoord = vec2(1.0 - TexCoord.x, 1.0 - TexCoord.y); // 180 degree
+      ivec2 texelCoord = ivec2(texCoord * vec2(textureSize(srcTexture, 0)));
+      vec4 sampledColor = texelFetch(srcTexture, texelCoord, 0);
+      outColor = sampledColor;
+  }
+)__SHADER__";
+
+static const std::string rotate_270_fragmentSource = R"__SHADER__(#version 300 es
+  precision highp float;
+  precision highp sampler2D;
+  in vec2 TexCoord;
+  out vec4 outColor;
+  uniform sampler2D srcTexture;
+  void main() {
+      vec2 texCoord = TexCoord;
+      texCoord = vec2(1.0 - TexCoord.y, TexCoord.x); // 270 degree
+      ivec2 texelCoord = ivec2(texCoord * vec2(textureSize(srcTexture, 0)));
+      vec4 sampledColor = texelFetch(srcTexture, texelCoord, 0);
+      outColor = sampledColor;
+  }
+)__SHADER__";
+
+static const std::string crop_fragmentSource = R"__SHADER__(#version 300 es
+  precision highp float;
+  precision highp sampler2D;
+  in vec2 TexCoord;
+  out vec4 outColor;
+  uniform sampler2D srcTexture;
+  uniform vec2 cropStart; // Crop start coordinate (normalized)
+  uniform vec2 cropSize;  // Size of the crop region (normalized)
+  void main() {
+    vec2 texCoord = cropStart + TexCoord * cropSize;
+    ivec2 texelCoord = ivec2(texCoord * vec2(textureSize(srcTexture, 0)));
+    vec4 sampledColor = texelFetch(srcTexture, texelCoord, 0);
+    outColor = sampledColor;
+  }
+)__SHADER__";
+
+static const std::string resizeShader = R"__SHADER__(
+  uniform sampler2D srcTexture;
+  uniform int srcWidth;
+  uniform int srcHeight;
+  uniform int dstWidth;
+  uniform int dstHeight;
+
+  // Cubic interpolation function
+  float cubic(float x) {
+    const float a = -0.5;
+    float absX = abs(x);
+    float absX2 = absX * absX;
+    float absX3 = absX2 * absX;
+    if (absX <= 1.0) {
+      return (a + 2.0) * absX3 - (a + 3.0) * absX2 + 1.0;
+    } else if (absX < 2.0) {
+      return a * absX3 - 5.0 * a * absX2 + 8.0 * a * absX - 4.0 * a;
+    }
+    return 0.0;
+  }
+
+  // Resizing function using bicubic interpolation
+  vec4 resize() {
+    vec2 texCoord = gl_FragCoord.xy / vec2(float(dstWidth), float(dstHeight));
+    vec2 srcCoord = texCoord * vec2(float(srcWidth), float(srcHeight));
+
+    // Separate the integer and fractional parts of the source coordinates
+    vec2 srcCoordFloor = floor(srcCoord);
+    vec2 srcCoordFrac = fract(srcCoord);
+    vec4 color = vec4(0.0);
+
+    // Perform bicubic interpolation
+    // Loop through the 4x4 neighborhood of pixels around the source coordinate
+    for (int y = -1; y <= 2; ++y) {
+      float yWeight = cubic(srcCoordFrac.y - float(y));
+      vec4 rowColor = vec4(0.0);
+      for (int x = -1; x <= 2; ++x) {
+          float xWeight = cubic(srcCoordFrac.x - float(x));
+          vec2 sampleCoord = clamp(
+              (srcCoordFloor + vec2(float(x), float(y))) / vec2(float(srcWidth), float(srcHeight)),
+              0.0, 1.0);
+          rowColor += texture(srcTexture, sampleCoord) * xWeight;
+      }
+      color += rowColor * yWeight;
+    }
+    return color;
+  }
+)__SHADER__";
+
+void release_resources(GLuint* texture, GLuint* frameBuffer) {
+  if (frameBuffer) glDeleteFramebuffers(1, frameBuffer);
+  if (texture) glDeleteTextures(1, texture);
+}
+
+#define RET_IF_ERR()                                       \
+  if (gl_ctxt->mErrorStatus.error_code != UHDR_CODEC_OK) { \
+    release_resources(&dstTexture, &frameBuffer);          \
+    return nullptr;                                        \
+  }
+
+std::unique_ptr<uhdr_raw_image_ext_t> apply_mirror_gles(ultrahdr::uhdr_mirror_effect_t* desc,
+                                                        uhdr_raw_image_t* src,
+                                                        uhdr_opengl_ctxt* gl_ctxt,
+                                                        GLuint* srcTexture) {
+  std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
+      src->fmt, src->cg, src->ct, src->range, src->w, src->h, 1);
+  GLuint* shaderProgram = nullptr;
+
+  if (desc->m_direction == UHDR_MIRROR_HORIZONTAL) {
+    if (gl_ctxt->mShaderProgram[UHDR_MIR_HORZ] == 0) {
+      gl_ctxt->mShaderProgram[UHDR_MIR_HORZ] =
+          gl_ctxt->create_shader_program(vertex_shader.c_str(), mirror_horz_fragmentSource.c_str());
+    }
+    shaderProgram = &gl_ctxt->mShaderProgram[UHDR_MIR_HORZ];
+  } else if (desc->m_direction == UHDR_MIRROR_VERTICAL) {
+    if (gl_ctxt->mShaderProgram[UHDR_MIR_VERT] == 0) {
+      gl_ctxt->mShaderProgram[UHDR_MIR_VERT] =
+          gl_ctxt->create_shader_program(vertex_shader.c_str(), mirror_vert_fragmentSource.c_str());
+    }
+    shaderProgram = &gl_ctxt->mShaderProgram[UHDR_MIR_VERT];
+  }
+  GLuint dstTexture = gl_ctxt->create_texture(src->fmt, dst->w, dst->h, NULL);
+  GLuint frameBuffer = gl_ctxt->setup_framebuffer(dstTexture);
+
+  glViewport(0, 0, dst->w, dst->h);
+  glUseProgram(*shaderProgram);
+  RET_IF_ERR()
+
+  glActiveTexture(GL_TEXTURE0);
+  glBindTexture(GL_TEXTURE_2D, *srcTexture);
+  glUniform1i(glGetUniformLocation(*shaderProgram, "srcTexture"), 0);
+  gl_ctxt->check_gl_errors("binding values to uniform");
+  RET_IF_ERR()
+
+  glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, 0);
+  RET_IF_ERR()
+
+  std::swap(*srcTexture, dstTexture);
+  release_resources(&dstTexture, &frameBuffer);
+  return dst;
+}
+
+std::unique_ptr<uhdr_raw_image_ext_t> apply_rotate_gles(ultrahdr::uhdr_rotate_effect_t* desc,
+                                                        uhdr_raw_image_t* src,
+                                                        uhdr_opengl_ctxt* gl_ctxt,
+                                                        GLuint* srcTexture) {
+  std::unique_ptr<uhdr_raw_image_ext_t> dst;
+  GLuint* shaderProgram;
+  if (desc->m_degree == 90 || desc->m_degree == 270) {
+    dst = std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, src->h,
+                                                 src->w, 1);
+    if (desc->m_degree == 90) {
+      if (gl_ctxt->mShaderProgram[UHDR_ROT_90] == 0) {
+        gl_ctxt->mShaderProgram[UHDR_ROT_90] =
+            gl_ctxt->create_shader_program(vertex_shader.c_str(), rotate_90_fragmentSource.c_str());
+      }
+      shaderProgram = &gl_ctxt->mShaderProgram[UHDR_ROT_90];
+    } else {
+      if (gl_ctxt->mShaderProgram[UHDR_ROT_270] == 0) {
+        gl_ctxt->mShaderProgram[UHDR_ROT_270] = gl_ctxt->create_shader_program(
+            vertex_shader.c_str(), rotate_270_fragmentSource.c_str());
+      }
+      shaderProgram = &gl_ctxt->mShaderProgram[UHDR_ROT_270];
+    }
+  } else if (desc->m_degree == 180) {
+    dst = std::make_unique<uhdr_raw_image_ext_t>(src->fmt, src->cg, src->ct, src->range, src->w,
+                                                 src->h, 1);
+    if (gl_ctxt->mShaderProgram[UHDR_ROT_180] == 0) {
+      gl_ctxt->mShaderProgram[UHDR_ROT_180] =
+          gl_ctxt->create_shader_program(vertex_shader.c_str(), rotate_180_fragmentSource.c_str());
+    }
+    shaderProgram = &gl_ctxt->mShaderProgram[UHDR_ROT_180];
+  } else {
+    return nullptr;
+  }
+  GLuint dstTexture = gl_ctxt->create_texture(src->fmt, dst->w, dst->h, NULL);
+  GLuint frameBuffer = gl_ctxt->setup_framebuffer(dstTexture);
+
+  glViewport(0, 0, dst->w, dst->h);
+  glUseProgram(*shaderProgram);
+  RET_IF_ERR()
+
+  glActiveTexture(GL_TEXTURE0);
+  glBindTexture(GL_TEXTURE_2D, *srcTexture);
+  glUniform1i(glGetUniformLocation(*shaderProgram, "srcTexture"), 0);
+  gl_ctxt->check_gl_errors("binding values to uniform");
+  RET_IF_ERR()
+
+  glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, 0);
+  RET_IF_ERR()
+
+  std::swap(*srcTexture, dstTexture);
+  release_resources(&dstTexture, &frameBuffer);
+  return dst;
+}
+
+void apply_crop_gles(uhdr_raw_image_t* src, int left, int top, int wd, int ht,
+                     uhdr_opengl_ctxt* gl_ctxt, GLuint* srcTexture) {
+  GLuint dstTexture = 0;
+  GLuint frameBuffer = 0;
+#define RETURN_IF_ERR()                                    \
+  if (gl_ctxt->mErrorStatus.error_code != UHDR_CODEC_OK) { \
+    release_resources(&dstTexture, &frameBuffer);          \
+    return;                                                \
+  }
+  if (gl_ctxt->mShaderProgram[UHDR_CROP] == 0) {
+    gl_ctxt->mShaderProgram[UHDR_CROP] =
+        gl_ctxt->create_shader_program(vertex_shader.c_str(), crop_fragmentSource.c_str());
+  }
+  dstTexture = gl_ctxt->create_texture(src->fmt, wd, ht, NULL);
+  frameBuffer = gl_ctxt->setup_framebuffer(dstTexture);
+
+  glViewport(0, 0, wd, ht);
+  glUseProgram(gl_ctxt->mShaderProgram[UHDR_CROP]);
+
+  float normCropX = (float)left / src->w;
+  float normCropY = (float)top / src->h;
+  float normCropW = (float)wd / src->w;
+  float normCropH = (float)ht / src->h;
+
+  glActiveTexture(GL_TEXTURE0);
+  glBindTexture(GL_TEXTURE_2D, *srcTexture);
+  glUniform1i(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_CROP], "srcTexture"), 0);
+  glUniform2f(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_CROP], "cropStart"),
+              normCropX, normCropY);
+  glUniform2f(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_CROP], "cropSize"),
+              normCropW, normCropH);
+  gl_ctxt->check_gl_errors("binding values to uniform");
+  RETURN_IF_ERR()
+
+  glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, 0);
+  RETURN_IF_ERR()
+
+  std::swap(*srcTexture, dstTexture);
+  src->w = wd;
+  src->h = ht;
+  src->stride[UHDR_PLANE_PACKED] = wd;
+  release_resources(&dstTexture, &frameBuffer);
+#undef RETURN_IF_ERR
+}
+
+std::unique_ptr<uhdr_raw_image_ext_t> apply_resize_gles(uhdr_raw_image_t* src, int dst_w, int dst_h,
+                                                        uhdr_opengl_ctxt* gl_ctxt,
+                                                        GLuint* srcTexture) {
+  std::unique_ptr<uhdr_raw_image_ext_t> dst = std::make_unique<uhdr_raw_image_ext_t>(
+      src->fmt, src->cg, src->ct, src->range, dst_w, dst_h, 1);
+  std::string shader_code = R"__SHADER__(#version 300 es
+    precision highp float;
+    in vec2 TexCoord;
+    out vec4 fragColor;
+  )__SHADER__";
+  shader_code.append(resizeShader);
+  shader_code.append(R"__SHADER__(
+    void main() {
+      fragColor = resize();
+    }
+  )__SHADER__");
+  if (gl_ctxt->mShaderProgram[UHDR_RESIZE] == 0) {
+    gl_ctxt->mShaderProgram[UHDR_RESIZE] =
+        gl_ctxt->create_shader_program(vertex_shader.c_str(), shader_code.c_str());
+  }
+  GLuint dstTexture = gl_ctxt->create_texture(src->fmt, dst_w, dst_h, NULL);
+  GLuint frameBuffer = gl_ctxt->setup_framebuffer(dstTexture);
+
+  glViewport(0, 0, dst->w, dst->h);
+  glUseProgram(gl_ctxt->mShaderProgram[UHDR_RESIZE]);
+  RET_IF_ERR()
+
+  glActiveTexture(GL_TEXTURE0);
+  glBindTexture(GL_TEXTURE_2D, *srcTexture);
+  glUniform1i(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_RESIZE], "srcTexture"), 0);
+  glUniform1i(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_RESIZE], "srcWidth"),
+              src->w);
+  glUniform1i(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_RESIZE], "srcHeight"),
+              src->h);
+  glUniform1i(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_RESIZE], "dstWidth"), dst_w);
+  glUniform1i(glGetUniformLocation(gl_ctxt->mShaderProgram[UHDR_RESIZE], "dstHeight"),
+              dst_h);
+  gl_ctxt->check_gl_errors("binding values to uniform");
+  RET_IF_ERR()
+
+  glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, 0);
+  RET_IF_ERR()
+
+  std::swap(*srcTexture, dstTexture);
+  release_resources(&dstTexture, &frameBuffer);
+  return dst;
+}
+#undef RET_IF_ERR
+}  // namespace ultrahdr
diff --git a/lib/src/gpu/uhdr_gl_utils.cpp b/lib/src/gpu/uhdr_gl_utils.cpp
new file mode 100644
index 0000000..6b57982
--- /dev/null
+++ b/lib/src/gpu/uhdr_gl_utils.cpp
@@ -0,0 +1,406 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include "ultrahdr/ultrahdrcommon.h"
+
+namespace ultrahdr {
+
+uhdr_opengl_ctxt::uhdr_opengl_ctxt() {
+  mEGLDisplay = EGL_NO_DISPLAY;
+  mEGLContext = EGL_NO_CONTEXT;
+  mEGLSurface = EGL_NO_SURFACE;
+  mEGLConfig = 0;
+  mQuadVAO = 0;
+  mQuadVBO = 0;
+  mQuadEBO = 0;
+  mErrorStatus = g_no_error;
+  mDecodedImgTexture = 0;
+  mGainmapImgTexture = 0;
+  for (int i = 0; i < UHDR_RESIZE + 1; i++) {
+    mShaderProgram[i] = 0;
+  }
+}
+
+uhdr_opengl_ctxt::~uhdr_opengl_ctxt() { delete_opengl_ctxt(); }
+
+void uhdr_opengl_ctxt::init_opengl_ctxt() {
+#define RET_IF_TRUE(cond, msg)                                          \
+  {                                                                     \
+    if (cond) {                                                         \
+      mErrorStatus.error_code = UHDR_CODEC_ERROR;                       \
+      mErrorStatus.has_detail = 1;                                      \
+      snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail,         \
+               "%s, received egl error code 0x%x", msg, eglGetError()); \
+      return;                                                           \
+    }                                                                   \
+  }
+
+  mEGLDisplay = eglGetDisplay(EGL_DEFAULT_DISPLAY);
+  RET_IF_TRUE(mEGLDisplay == EGL_NO_DISPLAY, "eglGetDisplay() failed")
+
+  RET_IF_TRUE(!eglInitialize(mEGLDisplay, NULL, NULL), "eglInitialize() failed")
+
+  EGLint num_config;
+  EGLint attribs[] = {EGL_SURFACE_TYPE, EGL_PBUFFER_BIT, EGL_RENDERABLE_TYPE, EGL_OPENGL_ES3_BIT,
+                      EGL_NONE};
+  RET_IF_TRUE(!eglChooseConfig(mEGLDisplay, attribs, &mEGLConfig, 1, &num_config) || num_config < 1,
+              "eglChooseConfig() failed")
+
+  EGLint context_attribs[] = {EGL_CONTEXT_CLIENT_VERSION, 3, EGL_NONE};
+  mEGLContext = eglCreateContext(mEGLDisplay, mEGLConfig, EGL_NO_CONTEXT, context_attribs);
+  RET_IF_TRUE(mEGLContext == EGL_NO_CONTEXT, "eglCreateContext() failed")
+
+  EGLint pbuffer_attribs[] = {
+      EGL_WIDTH, 1, EGL_HEIGHT, 1, EGL_NONE,
+  };
+  mEGLSurface = eglCreatePbufferSurface(mEGLDisplay, mEGLConfig, pbuffer_attribs);
+  RET_IF_TRUE(mEGLSurface == EGL_NO_SURFACE, "eglCreatePbufferSurface() failed")
+
+  RET_IF_TRUE(!eglMakeCurrent(mEGLDisplay, mEGLSurface, mEGLSurface, mEGLContext),
+              "eglMakeCurrent() failed")
+#undef RET_IF_TRUE
+
+  setup_quad();
+}
+
+GLuint uhdr_opengl_ctxt::compile_shader(GLenum type, const char* source) {
+  GLuint shader = glCreateShader(type);
+  if (!shader) {
+    mErrorStatus.error_code = UHDR_CODEC_ERROR;
+    mErrorStatus.has_detail = 1;
+    snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail,
+             "glCreateShader() failed, received gl error code 0x%x", glGetError());
+    return 0;
+  }
+  glShaderSource(shader, 1, &source, nullptr);
+  glCompileShader(shader);
+  GLint compileStatus;
+  glGetShaderiv(shader, GL_COMPILE_STATUS, &compileStatus);
+  if (compileStatus != GL_TRUE) {
+    GLint logLength;
+    glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &logLength);
+    // Info log length includes the null terminator, so 1 means that the info log is an empty
+    // string.
+    if (logLength > 1) {
+      std::vector<char> log(logLength);
+      glGetShaderInfoLog(shader, logLength, nullptr, log.data());
+      mErrorStatus.error_code = UHDR_CODEC_ERROR;
+      mErrorStatus.has_detail = 1;
+      snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail,
+               "Unable to compile shader, error log: %s", log.data());
+    } else {
+      mErrorStatus.error_code = UHDR_CODEC_ERROR;
+      mErrorStatus.has_detail = 1;
+      snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail,
+               "Unable to compile shader, <empty log message>");
+    }
+    glDeleteShader(shader);
+    return 0;
+  }
+  return shader;
+}
+
+GLuint uhdr_opengl_ctxt::create_shader_program(const char* vertex_source,
+                                               const char* fragment_source) {
+  if (vertex_source == nullptr || *vertex_source == '\0') {
+    mErrorStatus.error_code = UHDR_CODEC_INVALID_PARAM;
+    mErrorStatus.has_detail = 1;
+    snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail, "empty vertex source shader");
+    return 0;
+  }
+
+  if (fragment_source == nullptr || *fragment_source == '\0') {
+    mErrorStatus.error_code = UHDR_CODEC_INVALID_PARAM;
+    mErrorStatus.has_detail = 1;
+    snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail, "empty fragment source shader");
+    return 0;
+  }
+
+  GLuint program = glCreateProgram();
+  if (!program) {
+    mErrorStatus.error_code = UHDR_CODEC_ERROR;
+    mErrorStatus.has_detail = 1;
+    snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail,
+             "glCreateProgram() failed, received gl error code 0x%x", glGetError());
+    return 0;
+  }
+
+  GLuint vertexShader = compile_shader(GL_VERTEX_SHADER, vertex_source);
+  GLuint fragmentShader = compile_shader(GL_FRAGMENT_SHADER, fragment_source);
+  if (vertexShader == 0 || fragmentShader == 0) {
+    glDeleteShader(vertexShader);
+    glDeleteShader(fragmentShader);
+    glDeleteProgram(program);
+    return 0;
+  }
+
+  glAttachShader(program, vertexShader);
+  glDeleteShader(vertexShader);
+
+  glAttachShader(program, fragmentShader);
+  glDeleteShader(fragmentShader);
+
+  glLinkProgram(program);
+  GLint linkStatus;
+  glGetProgramiv(program, GL_LINK_STATUS, &linkStatus);
+  if (linkStatus != GL_TRUE) {
+    GLint logLength;
+    glGetProgramiv(program, GL_INFO_LOG_LENGTH, &logLength);
+    // Info log length includes the null terminator, so 1 means that the info log is an empty
+    // string.
+    if (logLength > 1) {
+      std::vector<char> log(logLength);
+      glGetProgramInfoLog(program, logLength, nullptr, log.data());
+      mErrorStatus.error_code = UHDR_CODEC_ERROR;
+      mErrorStatus.has_detail = 1;
+      snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail,
+               "Unable to link shader program, error log: %s", log.data());
+    } else {
+      mErrorStatus.error_code = UHDR_CODEC_ERROR;
+      mErrorStatus.has_detail = 1;
+      snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail,
+               "Unable to link shader program, <empty log message>");
+    }
+    glDeleteProgram(program);
+    return 0;
+  }
+  return program;
+}
+
+GLuint uhdr_opengl_ctxt::create_texture(uhdr_img_fmt_t fmt, int w, int h, void* data) {
+  GLuint textureID;
+
+  glGenTextures(1, &textureID);
+  glBindTexture(GL_TEXTURE_2D, textureID);
+  switch (fmt) {
+    case UHDR_IMG_FMT_12bppYCbCr420:
+      glTexImage2D(GL_TEXTURE_2D, 0, GL_R8, w, h * 3 / 2, 0, GL_RED, GL_UNSIGNED_BYTE, data);
+      break;
+    case UHDR_IMG_FMT_8bppYCbCr400:
+      glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
+      glTexImage2D(GL_TEXTURE_2D, 0, GL_R8, w, h, 0, GL_RED, GL_UNSIGNED_BYTE, data);
+      glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
+      break;
+    case UHDR_IMG_FMT_32bppRGBA8888:
+      glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, data);
+      break;
+    case UHDR_IMG_FMT_64bppRGBAHalfFloat:
+      glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA16F, w, h, 0, GL_RGBA, GL_HALF_FLOAT, data);
+      break;
+    case UHDR_IMG_FMT_32bppRGBA1010102:
+      glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB10_A2, w, h, 0, GL_RGBA, GL_UNSIGNED_INT_2_10_10_10_REV,
+                   data);
+      break;
+    case UHDR_IMG_FMT_24bppRGB888:
+      glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, w, h, 0, GL_RGB, GL_UNSIGNED_BYTE, data);
+      break;
+    case UHDR_IMG_FMT_24bppYCbCr444:
+      glTexImage2D(GL_TEXTURE_2D, 0, GL_R8, w, h * 3, 0, GL_RED, GL_UNSIGNED_BYTE, data);
+      break;
+    case UHDR_IMG_FMT_16bppYCbCr422:
+      glTexImage2D(GL_TEXTURE_2D, 0, GL_R8, w, h * 2, 0, GL_RED, GL_UNSIGNED_BYTE, data);
+      break;
+    case UHDR_IMG_FMT_16bppYCbCr440:
+      [[fallthrough]];
+    case UHDR_IMG_FMT_12bppYCbCr411:
+      [[fallthrough]];
+    case UHDR_IMG_FMT_10bppYCbCr410:
+      [[fallthrough]];
+    case UHDR_IMG_FMT_30bppYCbCr444:
+      [[fallthrough]];
+    default:
+      mErrorStatus.error_code = UHDR_CODEC_INVALID_PARAM;
+      mErrorStatus.has_detail = 1;
+      snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail,
+               "unsupported color format option in create_texture(), color format %d", fmt);
+      glDeleteTextures(1, &textureID);
+      return 0;
+  }
+  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
+  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
+  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
+  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
+
+  check_gl_errors("create_texture()");
+  if (mErrorStatus.error_code != UHDR_CODEC_OK) {
+    glDeleteTextures(1, &textureID);
+    return 0;
+  }
+
+  return textureID;
+}
+
+void uhdr_opengl_ctxt::setup_quad() {
+  const float quadVertices[] = { // Positions    // TexCoords
+                                -1.0f,  1.0f,    0.0f, 1.0f,
+                                -1.0f, -1.0f,    0.0f, 0.0f,
+                                 1.0f, -1.0f,    1.0f, 0.0f,
+                                 1.0f,  1.0f,    1.0f, 1.0f};
+  const unsigned int quadIndices[] = {0, 1, 2,  0, 2, 3};
+
+  glGenVertexArrays(1, &mQuadVAO);
+  glGenBuffers(1, &mQuadVBO);
+  glGenBuffers(1, &mQuadEBO);
+  glBindVertexArray(mQuadVAO);
+  glBindBuffer(GL_ARRAY_BUFFER, mQuadVBO);
+  glBufferData(GL_ARRAY_BUFFER, sizeof(quadVertices), quadVertices, GL_STATIC_DRAW);
+  glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, mQuadEBO);
+  glBufferData(GL_ELEMENT_ARRAY_BUFFER, sizeof(quadIndices), quadIndices, GL_STATIC_DRAW);
+  glEnableVertexAttribArray(0);
+  glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(float), (void*)0);
+  glEnableVertexAttribArray(1);
+  glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 4 * sizeof(float), (void*)(2 * sizeof(float)));
+
+  check_gl_errors("setup_quad()");
+  if (mErrorStatus.error_code != UHDR_CODEC_OK) {
+    if (mQuadVAO) {
+      glDeleteVertexArrays(1, &mQuadVAO);
+      mQuadVAO = 0;
+    }
+    if (mQuadVBO) {
+      glDeleteBuffers(1, &mQuadVBO);
+      mQuadVBO = 0;
+    }
+    if (mQuadEBO) {
+      glDeleteBuffers(1, &mQuadEBO);
+      mQuadEBO = 0;
+    }
+  }
+}
+
+GLuint uhdr_opengl_ctxt::setup_framebuffer(GLuint& texture) {
+  GLuint frameBufferID;
+
+  glGenFramebuffers(1, &frameBufferID);
+  glBindFramebuffer(GL_FRAMEBUFFER, frameBufferID);
+  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
+  GLenum err;
+  if ((err = glCheckFramebufferStatus(GL_FRAMEBUFFER)) != GL_FRAMEBUFFER_COMPLETE) {
+    mErrorStatus.error_code = UHDR_CODEC_ERROR;
+    mErrorStatus.has_detail = 1;
+    snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail,
+             "glCheckFramebufferStatus() returned with error code : 0x%x", err);
+    glDeleteFramebuffers(1, &frameBufferID);
+    return 0;
+  }
+
+  check_gl_errors("setup_framebuffer()");
+  if (mErrorStatus.error_code != UHDR_CODEC_OK) {
+    glDeleteFramebuffers(1, &frameBufferID);
+    return 0;
+  }
+  return frameBufferID;
+}
+
+void uhdr_opengl_ctxt::check_gl_errors(const char* msg) {
+  GLenum err;
+  if ((err = glGetError()) != GL_NO_ERROR) {
+    mErrorStatus.error_code = UHDR_CODEC_ERROR;
+    mErrorStatus.has_detail = 1;
+    const char* err_str;
+    switch (err) {
+      case GL_INVALID_ENUM:
+        err_str = "GL_INVALID_ENUM";
+        break;
+      case GL_INVALID_VALUE:
+        err_str = "GL_INVALID_VALUE";
+        break;
+      case GL_INVALID_OPERATION:
+        err_str = "GL_INVALID_OPERATION";
+        break;
+      case GL_INVALID_FRAMEBUFFER_OPERATION:
+        err_str = "GL_INVALID_FRAMEBUFFER_OPERATION";
+        break;
+      case GL_OUT_OF_MEMORY:
+        err_str = "GL_OUT_OF_MEMORY";
+        break;
+      default:
+        err_str = "Unknown";
+        break;
+    }
+    snprintf(mErrorStatus.detail, sizeof mErrorStatus.detail,
+             "call to %s has raised one or more error flags, value of one error flag : %s", msg,
+             err_str);
+  }
+}
+
+void uhdr_opengl_ctxt::read_texture(GLuint* texture, uhdr_img_fmt_t fmt, int w, int h, void* data) {
+  GLuint frm_buffer;
+  glGenFramebuffers(1, &frm_buffer);
+  glBindFramebuffer(GL_FRAMEBUFFER, frm_buffer);
+  glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, *texture, 0);
+  if (fmt == UHDR_IMG_FMT_32bppRGBA8888) {
+    glReadPixels(0, 0, w, h, GL_RGBA, GL_UNSIGNED_BYTE, data);
+  } else if (fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
+    glReadPixels(0, 0, w, h, GL_RGBA, GL_UNSIGNED_INT_2_10_10_10_REV, data);
+  } else if (fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
+    glReadPixels(0, 0, w, h, GL_RGBA, GL_HALF_FLOAT, data);
+  } else if (fmt == UHDR_IMG_FMT_8bppYCbCr400) {
+    glPixelStorei(GL_PACK_ALIGNMENT, 1);
+    glReadPixels(0, 0, w, h, GL_RED, GL_UNSIGNED_BYTE, data);
+    glPixelStorei(GL_PACK_ALIGNMENT, 4);
+  }
+  glBindFramebuffer(GL_FRAMEBUFFER, 0);
+  glDeleteFramebuffers(1, &frm_buffer);
+}
+
+void uhdr_opengl_ctxt::reset_opengl_ctxt() {
+  delete_opengl_ctxt();
+  mErrorStatus = g_no_error;
+}
+
+void uhdr_opengl_ctxt::delete_opengl_ctxt() {
+  if (mQuadVAO) {
+    glDeleteVertexArrays(1, &mQuadVAO);
+    mQuadVAO = 0;
+  }
+  if (mQuadVBO) {
+    glDeleteBuffers(1, &mQuadVBO);
+    mQuadVBO = 0;
+  }
+  if (mQuadEBO) {
+    glDeleteBuffers(1, &mQuadEBO);
+    mQuadEBO = 0;
+  }
+  if (mEGLSurface != EGL_NO_SURFACE) {
+    eglDestroySurface(mEGLDisplay, mEGLSurface);
+    mEGLSurface = EGL_NO_SURFACE;
+  }
+  if (mEGLContext != EGL_NO_CONTEXT) {
+    eglDestroyContext(mEGLDisplay, mEGLContext);
+    mEGLContext = EGL_NO_CONTEXT;
+  }
+  mEGLConfig = 0;
+  if (mEGLDisplay != EGL_NO_DISPLAY) {
+    eglTerminate(mEGLDisplay);
+    mEGLDisplay = EGL_NO_DISPLAY;
+  }
+  if (mDecodedImgTexture) {
+    glDeleteTextures(1, &mDecodedImgTexture);
+    mDecodedImgTexture = 0;
+  }
+  if (mGainmapImgTexture) {
+    glDeleteTextures(1, &mGainmapImgTexture);
+    mGainmapImgTexture = 0;
+  }
+  for (int i = 0; i < UHDR_RESIZE + 1; i++) {
+    if (mShaderProgram[i]) {
+      glDeleteProgram(mShaderProgram[i]);
+      mShaderProgram[i] = 0;
+    }
+  }
+}
+}  // namespace ultrahdr
diff --git a/lib/src/icc.cpp b/lib/src/icc.cpp
index b489816..b4fd11c 100644
--- a/lib/src/icc.cpp
+++ b/lib/src/icc.cpp
@@ -122,17 +122,17 @@ static void float_XYZD50_to_grid16_lab(const float* xyz_float, uint8_t* grid16_l
   }
 }
 
-std::string IccHelper::get_desc_string(const ultrahdr_transfer_function tf,
-                                       const ultrahdr_color_gamut gamut) {
+std::string IccHelper::get_desc_string(const uhdr_color_transfer_t tf,
+                                       const uhdr_color_gamut_t gamut) {
   std::string result;
   switch (gamut) {
-    case ULTRAHDR_COLORGAMUT_BT709:
+    case UHDR_CG_BT_709:
       result += "sRGB";
       break;
-    case ULTRAHDR_COLORGAMUT_P3:
+    case UHDR_CG_DISPLAY_P3:
       result += "Display P3";
       break;
-    case ULTRAHDR_COLORGAMUT_BT2100:
+    case UHDR_CG_BT_2100:
       result += "Rec2020";
       break;
     default:
@@ -141,16 +141,16 @@ std::string IccHelper::get_desc_string(const ultrahdr_transfer_function tf,
   }
   result += " Gamut with ";
   switch (tf) {
-    case ULTRAHDR_TF_SRGB:
+    case UHDR_CT_SRGB:
       result += "sRGB";
       break;
-    case ULTRAHDR_TF_LINEAR:
+    case UHDR_CT_LINEAR:
       result += "Linear";
       break;
-    case ULTRAHDR_TF_PQ:
+    case UHDR_CT_PQ:
       result += "PQ";
       break;
-    case ULTRAHDR_TF_HLG:
+    case UHDR_CT_HLG:
       result += "HLG";
       break;
     default:
@@ -245,11 +245,11 @@ std::shared_ptr<DataStruct> IccHelper::write_trc_tag(const TransferFunction& fn)
   return dataStruct;
 }
 
-float IccHelper::compute_tone_map_gain(const ultrahdr_transfer_function tf, float L) {
+float IccHelper::compute_tone_map_gain(const uhdr_color_transfer_t tf, float L) {
   if (L <= 0.f) {
     return 1.f;
   }
-  if (tf == ULTRAHDR_TF_PQ) {
+  if (tf == UHDR_CT_PQ) {
     // The PQ transfer function will map to the range [0, 1]. Linearly scale
     // it up to the range [0, 10,000/203]. We will then tone map that back
     // down to [0, 1].
@@ -262,7 +262,7 @@ float IccHelper::compute_tone_map_gain(const ultrahdr_transfer_function tf, floa
     constexpr float kToneMapB = 1.f / kOutputMaxLuminance;
     return kInputMaxLuminance * (1.f + kToneMapA * L) / (1.f + kToneMapB * L);
   }
-  if (tf == ULTRAHDR_TF_HLG) {
+  if (tf == UHDR_CT_HLG) {
     // Let Lw be the brightness of the display in nits.
     constexpr float Lw = 203.f;
     const float gamma = 1.2f + 0.42f * std::log(Lw / 1000.f) / std::log(10.f);
@@ -306,7 +306,7 @@ void IccHelper::compute_lut_entry(const Matrix3x3& src_to_XYZD50, float rgb[3])
   float L = bt2100Luminance({{{rgb[0], rgb[1], rgb[2]}}});
 
   // Compute the tone map gain based on the luminance.
-  float tone_map_gain = compute_tone_map_gain(ULTRAHDR_TF_PQ, L);
+  float tone_map_gain = compute_tone_map_gain(UHDR_CT_PQ, L);
 
   // Apply the tone map gain.
   for (size_t i = 0; i < kNumChannels; ++i) {
@@ -408,8 +408,8 @@ std::shared_ptr<DataStruct> IccHelper::write_mAB_or_mBA_tag(uint32_t type, bool
   return dataStruct;
 }
 
-std::shared_ptr<DataStruct> IccHelper::writeIccProfile(ultrahdr_transfer_function tf,
-                                                       ultrahdr_color_gamut gamut) {
+std::shared_ptr<DataStruct> IccHelper::writeIccProfile(uhdr_color_transfer_t tf,
+                                                       uhdr_color_gamut_t gamut) {
   ICCHeader header;
 
   std::vector<std::pair<uint32_t, std::shared_ptr<DataStruct>>> tags;
@@ -421,13 +421,13 @@ std::shared_ptr<DataStruct> IccHelper::writeIccProfile(ultrahdr_transfer_functio
 
   Matrix3x3 toXYZD50;
   switch (gamut) {
-    case ULTRAHDR_COLORGAMUT_BT709:
+    case UHDR_CG_BT_709:
       toXYZD50 = kSRGB;
       break;
-    case ULTRAHDR_COLORGAMUT_P3:
+    case UHDR_CG_DISPLAY_P3:
       toXYZD50 = kDisplayP3;
       break;
-    case ULTRAHDR_COLORGAMUT_BT2100:
+    case UHDR_CG_BT_2100:
       toXYZD50 = kRec2020;
       break;
     default:
@@ -449,8 +449,8 @@ std::shared_ptr<DataStruct> IccHelper::writeIccProfile(ultrahdr_transfer_functio
   tags.emplace_back(kTAG_wtpt, write_xyz_tag(kD50_x, kD50_y, kD50_z));
 
   // Compute transfer curves.
-  if (tf != ULTRAHDR_TF_PQ) {
-    if (tf == ULTRAHDR_TF_HLG) {
+  if (tf != UHDR_CT_PQ) {
+    if (tf == UHDR_CT_HLG) {
       std::vector<uint8_t> trc_table;
       trc_table.resize(kTrcTableSize * 2);
       for (uint32_t i = 0; i < kTrcTableSize; ++i) {
@@ -474,32 +474,32 @@ std::shared_ptr<DataStruct> IccHelper::writeIccProfile(ultrahdr_transfer_functio
   }
 
   // Compute CICP.
-  if (tf == ULTRAHDR_TF_HLG || tf == ULTRAHDR_TF_PQ) {
+  if (tf == UHDR_CT_HLG || tf == UHDR_CT_PQ) {
     // The CICP tag is present in ICC 4.4, so update the header's version.
     header.version = Endian_SwapBE32(0x04400000);
 
     uint32_t color_primaries = 0;
-    if (gamut == ULTRAHDR_COLORGAMUT_BT709) {
+    if (gamut == UHDR_CG_BT_709) {
       color_primaries = kCICPPrimariesSRGB;
-    } else if (gamut == ULTRAHDR_COLORGAMUT_P3) {
+    } else if (gamut == UHDR_CG_DISPLAY_P3) {
       color_primaries = kCICPPrimariesP3;
     }
 
     uint32_t transfer_characteristics = 0;
-    if (tf == ULTRAHDR_TF_SRGB) {
+    if (tf == UHDR_CT_SRGB) {
       transfer_characteristics = kCICPTrfnSRGB;
-    } else if (tf == ULTRAHDR_TF_LINEAR) {
+    } else if (tf == UHDR_CT_LINEAR) {
       transfer_characteristics = kCICPTrfnLinear;
-    } else if (tf == ULTRAHDR_TF_PQ) {
+    } else if (tf == UHDR_CT_PQ) {
       transfer_characteristics = kCICPTrfnPQ;
-    } else if (tf == ULTRAHDR_TF_HLG) {
+    } else if (tf == UHDR_CT_HLG) {
       transfer_characteristics = kCICPTrfnHLG;
     }
     tags.emplace_back(kTAG_cicp, write_cicp_tag(color_primaries, transfer_characteristics));
   }
 
   // Compute A2B0.
-  if (tf == ULTRAHDR_TF_PQ) {
+  if (tf == UHDR_CT_PQ) {
     std::vector<uint8_t> a2b_grid;
     a2b_grid.resize(kGridSize * kGridSize * kGridSize * kNumChannels * 2);
     size_t a2b_grid_index = 0;
@@ -530,7 +530,7 @@ std::shared_ptr<DataStruct> IccHelper::writeIccProfile(ultrahdr_transfer_functio
   }
 
   // Compute B2A0.
-  if (tf == ULTRAHDR_TF_PQ) {
+  if (tf == UHDR_CT_PQ) {
     auto b2a_data = write_mAB_or_mBA_tag(kTAG_mBAType,
                                          /* has_a_curves */ false,
                                          /* grid_points */ nullptr,
@@ -561,7 +561,7 @@ std::shared_ptr<DataStruct> IccHelper::writeIccProfile(ultrahdr_transfer_functio
 
   // Write the header.
   header.data_color_space = Endian_SwapBE32(Signature_RGB);
-  header.pcs = Endian_SwapBE32(tf == ULTRAHDR_TF_PQ ? Signature_Lab : Signature_XYZ);
+  header.pcs = Endian_SwapBE32(tf == UHDR_CT_PQ ? Signature_Lab : Signature_XYZ);
   header.size = Endian_SwapBE32(profile_size);
   header.tag_count = Endian_SwapBE32(tags.size());
 
@@ -609,9 +609,8 @@ bool IccHelper::tagsEqualToMatrix(const Matrix3x3& matrix, const uint8_t* red_ta
   float r_x = FixedToFloat(r_x_fixed);
   float r_y = FixedToFloat(r_y_fixed);
   float r_z = FixedToFloat(r_z_fixed);
-  if (fabs(r_x - matrix.vals[0][0]) > tolerance ||
-          fabs(r_y - matrix.vals[1][0]) > tolerance ||
-          fabs(r_z - matrix.vals[2][0]) > tolerance) {
+  if (fabs(r_x - matrix.vals[0][0]) > tolerance || fabs(r_y - matrix.vals[1][0]) > tolerance ||
+      fabs(r_z - matrix.vals[2][0]) > tolerance) {
     return false;
   }
 
@@ -621,9 +620,8 @@ bool IccHelper::tagsEqualToMatrix(const Matrix3x3& matrix, const uint8_t* red_ta
   float g_x = FixedToFloat(g_x_fixed);
   float g_y = FixedToFloat(g_y_fixed);
   float g_z = FixedToFloat(g_z_fixed);
-  if (fabs(g_x - matrix.vals[0][1]) > tolerance ||
-          fabs(g_y - matrix.vals[1][1]) > tolerance ||
-          fabs(g_z - matrix.vals[2][1]) > tolerance) {
+  if (fabs(g_x - matrix.vals[0][1]) > tolerance || fabs(g_y - matrix.vals[1][1]) > tolerance ||
+      fabs(g_z - matrix.vals[2][1]) > tolerance) {
     return false;
   }
 
@@ -633,29 +631,39 @@ bool IccHelper::tagsEqualToMatrix(const Matrix3x3& matrix, const uint8_t* red_ta
   float b_x = FixedToFloat(b_x_fixed);
   float b_y = FixedToFloat(b_y_fixed);
   float b_z = FixedToFloat(b_z_fixed);
-  if (fabs(b_x - matrix.vals[0][2]) > tolerance ||
-          fabs(b_y - matrix.vals[1][2]) > tolerance ||
-          fabs(b_z - matrix.vals[2][2]) > tolerance) {
+  if (fabs(b_x - matrix.vals[0][2]) > tolerance || fabs(b_y - matrix.vals[1][2]) > tolerance ||
+      fabs(b_z - matrix.vals[2][2]) > tolerance) {
     return false;
   }
 
   return true;
 }
 
-ultrahdr_color_gamut IccHelper::readIccColorGamut(void* icc_data, size_t icc_size) {
+uhdr_color_gamut_t IccHelper::readIccColorGamut(void* icc_data, size_t icc_size) {
   // Each tag table entry consists of 3 fields of 4 bytes each.
   static const size_t kTagTableEntrySize = 12;
 
   if (icc_data == nullptr || icc_size < sizeof(ICCHeader) + kICCIdentifierSize) {
-    return ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+    return UHDR_CG_UNSPECIFIED;
   }
 
   if (memcmp(icc_data, kICCIdentifier, sizeof(kICCIdentifier)) != 0) {
-    return ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+    return UHDR_CG_UNSPECIFIED;
   }
 
   uint8_t* icc_bytes = reinterpret_cast<uint8_t*>(icc_data) + kICCIdentifierSize;
-
+  auto alignment_needs = alignof(ICCHeader);
+  uint8_t* aligned_block = nullptr;
+  if (((uintptr_t)icc_bytes) % alignment_needs != 0) {
+    aligned_block = static_cast<uint8_t*>(
+        ::operator new[](icc_size - kICCIdentifierSize, std::align_val_t(alignment_needs)));
+    if (!aligned_block) {
+      ALOGE("unable allocate memory, icc parsing failed");
+      return UHDR_CG_UNSPECIFIED;
+    }
+    std::memcpy(aligned_block, icc_bytes, icc_size - kICCIdentifierSize);
+    icc_bytes = aligned_block;
+  }
   ICCHeader* header = reinterpret_cast<ICCHeader*>(icc_bytes);
 
   // Use 0 to indicate not found, since offsets are always relative to start
@@ -668,7 +676,8 @@ ultrahdr_color_gamut IccHelper::readIccColorGamut(void* icc_data, size_t icc_siz
           "Insufficient buffer size during icc parsing. tag index %zu, header %zu, tag size %zu, "
           "icc size %zu",
           tag_idx, kICCIdentifierSize + sizeof(ICCHeader), kTagTableEntrySize, icc_size);
-      return ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+      if (aligned_block) ::operator delete[](aligned_block, std::align_val_t(alignment_needs));
+      return UHDR_CG_UNSPECIFIED;
     }
     uint32_t* tag_entry_start =
         reinterpret_cast<uint32_t*>(icc_bytes + sizeof(ICCHeader) + tag_idx * kTagTableEntrySize);
@@ -692,7 +701,8 @@ ultrahdr_color_gamut IccHelper::readIccColorGamut(void* icc_data, size_t icc_siz
       kICCIdentifierSize + green_primary_offset + green_primary_size > icc_size ||
       blue_primary_offset == 0 || blue_primary_size != kColorantTagSize ||
       kICCIdentifierSize + blue_primary_offset + blue_primary_size > icc_size) {
-    return ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+    if (aligned_block) ::operator delete[](aligned_block, std::align_val_t(alignment_needs));
+    return UHDR_CG_UNSPECIFIED;
   }
 
   uint8_t* red_tag = icc_bytes + red_primary_offset;
@@ -701,17 +711,19 @@ ultrahdr_color_gamut IccHelper::readIccColorGamut(void* icc_data, size_t icc_siz
 
   // Serialize tags as we do on encode and compare what we find to that to
   // determine the gamut (since we don't have a need yet for full deserialize).
+  uhdr_color_gamut_t gamut = UHDR_CG_UNSPECIFIED;
   if (tagsEqualToMatrix(kSRGB, red_tag, green_tag, blue_tag)) {
-    return ULTRAHDR_COLORGAMUT_BT709;
+    gamut = UHDR_CG_BT_709;
   } else if (tagsEqualToMatrix(kDisplayP3, red_tag, green_tag, blue_tag)) {
-    return ULTRAHDR_COLORGAMUT_P3;
+    gamut = UHDR_CG_DISPLAY_P3;
   } else if (tagsEqualToMatrix(kRec2020, red_tag, green_tag, blue_tag)) {
-    return ULTRAHDR_COLORGAMUT_BT2100;
+    gamut = UHDR_CG_BT_2100;
   }
 
+  if (aligned_block) ::operator delete[](aligned_block, std::align_val_t(alignment_needs));
   // Didn't find a match to one of the profiles we write; indicate the gamut
   // is unspecified since we don't understand it.
-  return ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+  return gamut;
 }
 
 }  // namespace ultrahdr
diff --git a/lib/src/jpegdecoderhelper.cpp b/lib/src/jpegdecoderhelper.cpp
index e5c3f81..7b107a1 100644
--- a/lib/src/jpegdecoderhelper.cpp
+++ b/lib/src/jpegdecoderhelper.cpp
@@ -21,7 +21,6 @@
 #include <cstring>
 
 #include "ultrahdr/ultrahdrcommon.h"
-#include "ultrahdr/ultrahdr.h"
 #include "ultrahdr/jpegdecoderhelper.h"
 
 using namespace std;
@@ -50,6 +49,20 @@ static constexpr uint8_t kIsoMetadataNameSpace[] = {
     'o', ':', 't', 's', ':', '2', '1', '4', '9', '6', ':', '-', '1', '\0',
 };
 
+const int kMinWidth = 8;
+const int kMinHeight = 8;
+
+// if max dimension is not defined, default to 8k resolution
+#ifndef UHDR_MAX_DIMENSION
+#define UHDR_MAX_DIMENSION 8192
+#endif
+static_assert(UHDR_MAX_DIMENSION >= (std::max)(kMinHeight, kMinWidth),
+              "configured UHDR_MAX_DIMENSION must be atleast max(minWidth, minHeight)");
+static_assert(UHDR_MAX_DIMENSION <= JPEG_MAX_DIMENSION,
+              "configured UHDR_MAX_DIMENSION must be <= JPEG_MAX_DIMENSION");
+const int kMaxWidth = UHDR_MAX_DIMENSION;
+const int kMaxHeight = UHDR_MAX_DIMENSION;
+
 /*!\brief module for managing input */
 struct jpeg_source_mgr_impl : jpeg_source_mgr {
   jpeg_source_mgr_impl(const uint8_t* ptr, int len);
@@ -135,32 +148,45 @@ static uhdr_img_fmt_t getOutputSamplingFormat(const j_decompress_ptr cinfo) {
   if (cinfo->num_components == 1)
     return UHDR_IMG_FMT_8bppYCbCr400;
   else {
-    int a = cinfo->max_h_samp_factor / cinfo->comp_info[1].h_samp_factor;
-    int b = cinfo->max_v_samp_factor / cinfo->comp_info[1].v_samp_factor;
-    if (a == 1 && b == 1)
-      return UHDR_IMG_FMT_24bppYCbCr444;
-    else if (a == 1 && b == 2)
-      return UHDR_IMG_FMT_16bppYCbCr440;
-    else if (a == 2 && b == 1)
-      return UHDR_IMG_FMT_16bppYCbCr422;
-    else if (a == 2 && b == 2)
-      return UHDR_IMG_FMT_12bppYCbCr420;
-    else if (a == 4 && b == 1)
-      return UHDR_IMG_FMT_12bppYCbCr411;
-    else if (a == 4 && b == 2)
-      return UHDR_IMG_FMT_10bppYCbCr410;
+    float ratios[6];
+    for (int i = 0; i < 3; i++) {
+      ratios[i * 2] = ((float)cinfo->comp_info[i].h_samp_factor) / cinfo->max_h_samp_factor;
+      ratios[i * 2 + 1] = ((float)cinfo->comp_info[i].v_samp_factor) / cinfo->max_v_samp_factor;
+    }
+    if (ratios[0] == 1 && ratios[1] == 1 && ratios[2] == ratios[4] && ratios[3] == ratios[5]) {
+      if (ratios[2] == 1 && ratios[3] == 1) {
+        return UHDR_IMG_FMT_24bppYCbCr444;
+      } else if (ratios[2] == 1 && ratios[3] == 0.5) {
+        return UHDR_IMG_FMT_16bppYCbCr440;
+      } else if (ratios[2] == 0.5 && ratios[3] == 1) {
+        return UHDR_IMG_FMT_16bppYCbCr422;
+      } else if (ratios[2] == 0.5 && ratios[3] == 0.5) {
+        return UHDR_IMG_FMT_12bppYCbCr420;
+      } else if (ratios[2] == 0.25 && ratios[3] == 1) {
+        return UHDR_IMG_FMT_12bppYCbCr411;
+      } else if (ratios[2] == 0.25 && ratios[3] == 0.5) {
+        return UHDR_IMG_FMT_10bppYCbCr410;
+      }
+    }
   }
   return UHDR_IMG_FMT_UNSPECIFIED;
 }
 
-bool JpegDecoderHelper::decompressImage(const void* image, int length, decode_mode_t mode) {
+uhdr_error_info_t JpegDecoderHelper::decompressImage(const void* image, int length,
+                                                     decode_mode_t mode) {
   if (image == nullptr) {
-    ALOGE("received nullptr for compressed image data");
-    return false;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received nullptr for compressed image data");
+    return status;
   }
   if (length <= 0) {
-    ALOGE("received bad compressed image size %d", length);
-    return false;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received bad compressed image size %d", length);
+    return status;
   }
 
   // reset context
@@ -170,20 +196,24 @@ bool JpegDecoderHelper::decompressImage(const void* image, int length, decode_mo
   mICCBuffer.clear();
   mIsoMetadataBuffer.clear();
   mOutFormat = UHDR_IMG_FMT_UNSPECIFIED;
+  mNumComponents = 1;
   for (int i = 0; i < kMaxNumComponents; i++) {
     mPlanesMCURow[i].reset();
     mPlaneWidth[i] = 0;
     mPlaneHeight[i] = 0;
+    mPlaneHStride[i] = 0;
+    mPlaneVStride[i] = 0;
   }
   mExifPayLoadOffset = -1;
 
   return decode(image, length, mode);
 }
 
-bool JpegDecoderHelper::decode(const void* image, int length, decode_mode_t mode) {
+uhdr_error_info_t JpegDecoderHelper::decode(const void* image, int length, decode_mode_t mode) {
   jpeg_source_mgr_impl mgr(static_cast<const uint8_t*>(image), length);
   jpeg_decompress_struct cinfo;
   jpeg_error_mgr_impl myerr;
+  uhdr_error_info_t status = g_no_error;
 
   cinfo.err = jpeg_std_error(&myerr);
   myerr.error_exit = jpegrerror_exit;
@@ -197,9 +227,12 @@ bool JpegDecoderHelper::decode(const void* image, int length, decode_mode_t mode
     jpeg_save_markers(&cinfo, kAPP2Marker, 0xFFFF);
     int ret_val = jpeg_read_header(&cinfo, TRUE /* require an image to be present */);
     if (JPEG_HEADER_OK != ret_val) {
-      ALOGE("jpeg_read_header(...) returned %d, expected %d", ret_val, JPEG_HEADER_OK);
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "jpeg_read_header(...) returned %d, expected %d", ret_val, JPEG_HEADER_OK);
       jpeg_destroy_decompress(&cinfo);
-      return false;
+      return status;
     }
     int payloadOffset = -1;
     jpeg_extract_marker_payload(&cinfo, kAPP1Marker, kXmpNameSpace,
@@ -215,75 +248,108 @@ bool JpegDecoderHelper::decode(const void* image, int length, decode_mode_t mode
                                 mIsoMetadataBuffer, payloadOffset);
 
     if (cinfo.image_width < 1 || cinfo.image_height < 1) {
-      ALOGE("received bad image width or height, wd = %d, ht = %d. wd and height shall be >= 1",
-            cinfo.image_width, cinfo.image_height);
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "received bad image width or height, wd = %d, ht = %d. wd and height shall be >= 1",
+               cinfo.image_width, cinfo.image_height);
       jpeg_destroy_decompress(&cinfo);
-      return false;
+      return status;
     }
-    if (cinfo.image_width > kMaxWidth || cinfo.image_height > kMaxHeight) {
-      ALOGE(
+    if ((int)cinfo.image_width > kMaxWidth || (int)cinfo.image_height > kMaxHeight) {
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(
+          status.detail, sizeof status.detail,
           "max width, max supported by library are %d, %d respectively. Current image width and "
           "height are %d, %d. Recompile library with updated max supported dimensions to proceed",
           kMaxWidth, kMaxHeight, cinfo.image_width, cinfo.image_height);
       jpeg_destroy_decompress(&cinfo);
-      return false;
+      return status;
     }
     if (cinfo.num_components != 1 && cinfo.num_components != 3) {
-      ALOGE(
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(
+          status.detail, sizeof status.detail,
           "ultrahdr primary image and supplimentary images are images encoded with 1 component "
           "(grayscale) or 3 components (YCbCr / RGB). Unrecognized number of components %d",
           cinfo.num_components);
       jpeg_destroy_decompress(&cinfo);
-      return false;
+      return status;
     }
 
     for (int i = 0, product = 0; i < cinfo.num_components; i++) {
       if (cinfo.comp_info[i].h_samp_factor < 1 || cinfo.comp_info[i].h_samp_factor > 4) {
-        ALOGE(
-            "received bad horizontal sampling factor for component index %d, sample factor h = %d, "
-            "this is expected to be with in range [1-4]",
-            i, cinfo.comp_info[i].h_samp_factor);
+        status.error_code = UHDR_CODEC_ERROR;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "received bad horizontal sampling factor for component index %d, sample factor h "
+                 "= %d, this is expected to be with in range [1-4]",
+                 i, cinfo.comp_info[i].h_samp_factor);
         jpeg_destroy_decompress(&cinfo);
-        return false;
+        return status;
       }
       if (cinfo.comp_info[i].v_samp_factor < 1 || cinfo.comp_info[i].v_samp_factor > 4) {
-        ALOGE(
-            "received bad vertical sampling factor for component index %d, sample factor v = %d, "
-            "this is expected to be with in range [1-4]",
-            i, cinfo.comp_info[i].v_samp_factor);
+        status.error_code = UHDR_CODEC_ERROR;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "received bad vertical sampling factor for component index %d, sample factor v = "
+                 "%d, this is expected to be with in range [1-4]",
+                 i, cinfo.comp_info[i].v_samp_factor);
         jpeg_destroy_decompress(&cinfo);
-        return false;
+        return status;
       }
       product += cinfo.comp_info[i].h_samp_factor * cinfo.comp_info[i].v_samp_factor;
       if (product > 10) {
-        ALOGE(
-            "received bad sampling factors for components, sum of product of h_samp_factor, "
-            "v_samp_factor across all components exceeds 10");
+        status.error_code = UHDR_CODEC_ERROR;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "received bad sampling factors for components, sum of product of h_samp_factor, "
+                 "v_samp_factor across all components exceeds 10");
         jpeg_destroy_decompress(&cinfo);
-        return false;
+        return status;
       }
     }
 
+    mNumComponents = cinfo.num_components;
     for (int i = 0; i < cinfo.num_components; i++) {
       mPlaneWidth[i] = std::ceil(((float)cinfo.image_width * cinfo.comp_info[i].h_samp_factor) /
                                  cinfo.max_h_samp_factor);
+      mPlaneHStride[i] = mPlaneWidth[i];
       mPlaneHeight[i] = std::ceil(((float)cinfo.image_height * cinfo.comp_info[i].v_samp_factor) /
                                   cinfo.max_v_samp_factor);
+      mPlaneVStride[i] = mPlaneHeight[i];
     }
 
-    if (cinfo.num_components == 3 &&
-        (mPlaneWidth[1] != mPlaneWidth[2] || mPlaneHeight[1] != mPlaneHeight[2])) {
-      ALOGE(
-          "cb, cr planes are not sampled identically. cb width %d, cb height %d, cr width %d, cr "
-          "height %d",
-          (int)mPlaneWidth[1], (int)mPlaneWidth[2], (int)mPlaneHeight[1], (int)mPlaneHeight[2]);
-      jpeg_destroy_decompress(&cinfo);
-      return false;
+    if (cinfo.num_components == 3) {
+      if (mPlaneWidth[1] > mPlaneWidth[0] || mPlaneHeight[2] > mPlaneHeight[0]) {
+        status.error_code = UHDR_CODEC_ERROR;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "cb, cr planes are upsampled wrt luma plane. luma width %d, luma height %d, cb "
+                 "width %d, cb height %d, cr width %d, cr height %d",
+                 (int)mPlaneWidth[0], (int)mPlaneHeight[0], (int)mPlaneWidth[1],
+                 (int)mPlaneHeight[1], (int)mPlaneWidth[2], (int)mPlaneHeight[2]);
+        jpeg_destroy_decompress(&cinfo);
+        return status;
+      }
+      if (mPlaneWidth[1] != mPlaneWidth[2] || mPlaneHeight[1] != mPlaneHeight[2]) {
+        status.error_code = UHDR_CODEC_ERROR;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "cb, cr planes are not sampled identically. cb width %d, cb height %d, cr width "
+                 "%d, cr height %d",
+                 (int)mPlaneWidth[1], (int)mPlaneHeight[1], (int)mPlaneWidth[2],
+                 (int)mPlaneHeight[2]);
+        jpeg_destroy_decompress(&cinfo);
+        return status;
+      }
     }
 
     if (PARSE_STREAM == mode) {
       jpeg_destroy_decompress(&cinfo);
-      return true;
+      return status;
     }
 
     if (DECODE_STREAM == mode) {
@@ -292,37 +358,42 @@ bool JpegDecoderHelper::decode(const void* image, int length, decode_mode_t mode
 
     if (DECODE_TO_RGB_CS == mode) {
       if (cinfo.jpeg_color_space != JCS_YCbCr && cinfo.jpeg_color_space != JCS_RGB) {
-        ALOGE("expected input color space to be JCS_YCbCr or JCS_RGB but got %d",
-              cinfo.jpeg_color_space);
+        status.error_code = UHDR_CODEC_ERROR;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "expected input color space to be JCS_YCbCr or JCS_RGB but got %d",
+                 cinfo.jpeg_color_space);
         jpeg_destroy_decompress(&cinfo);
-        return false;
+        return status;
+      }
+      mPlaneHStride[0] = cinfo.image_width;
+      mPlaneVStride[0] = cinfo.image_height;
+      for (int i = 1; i < kMaxNumComponents; i++) {
+        mPlaneHStride[i] = 0;
+        mPlaneVStride[i] = 0;
       }
 #ifdef JCS_ALPHA_EXTENSIONS
-      mResultBuffer.resize(cinfo.image_width * cinfo.image_height * 4);
+      mResultBuffer.resize(mPlaneHStride[0] * mPlaneVStride[0] * 4);
       cinfo.out_color_space = JCS_EXT_RGBA;
 #else
-      mResultBuffer.resize(cinfo.image_width * cinfo.image_height * 3);
+      mResultBuffer.resize(mPlaneHStride[0] * mPlaneVStride[0] * 3);
       cinfo.out_color_space = JCS_RGB;
 #endif
     } else if (DECODE_TO_YCBCR_CS == mode) {
       if (cinfo.jpeg_color_space != JCS_YCbCr && cinfo.jpeg_color_space != JCS_GRAYSCALE) {
-        ALOGE("expected input color space to be JCS_YCbCr or JCS_GRAYSCALE but got %d",
-              cinfo.jpeg_color_space);
+        status.error_code = UHDR_CODEC_ERROR;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "expected input color space to be JCS_YCbCr or JCS_GRAYSCALE but got %d",
+                 cinfo.jpeg_color_space);
         jpeg_destroy_decompress(&cinfo);
-        return false;
-      }
-      if (cinfo.jpeg_color_space == JCS_YCbCr) {
-        if (cinfo.comp_info[0].h_samp_factor != 2 || cinfo.comp_info[0].v_samp_factor != 2 ||
-            cinfo.comp_info[1].h_samp_factor != 1 || cinfo.comp_info[1].v_samp_factor != 1 ||
-            cinfo.comp_info[2].h_samp_factor != 1 || cinfo.comp_info[2].v_samp_factor != 1) {
-          ALOGE("apply gainmap supports only 4:2:0 sub sampling format, stopping image decode");
-          jpeg_destroy_decompress(&cinfo);
-          return false;
-        }
+        return status;
       }
       int size = 0;
       for (int i = 0; i < cinfo.num_components; i++) {
-        size += mPlaneWidth[i] * mPlaneHeight[i];
+        mPlaneHStride[i] = ALIGNM(mPlaneWidth[i], cinfo.max_h_samp_factor);
+        mPlaneVStride[i] = ALIGNM(mPlaneHeight[i], cinfo.max_v_samp_factor);
+        size += mPlaneHStride[i] * mPlaneVStride[i];
       }
       mResultBuffer.resize(size);
       cinfo.out_color_space = cinfo.jpeg_color_space;
@@ -330,26 +401,36 @@ bool JpegDecoderHelper::decode(const void* image, int length, decode_mode_t mode
     }
     cinfo.dct_method = JDCT_ISLOW;
     jpeg_start_decompress(&cinfo);
-    if (!decode(&cinfo, static_cast<uint8_t*>(mResultBuffer.data()))) {
+    status = decode(&cinfo, static_cast<uint8_t*>(mResultBuffer.data()));
+    if (status.error_code != UHDR_CODEC_OK) {
       jpeg_destroy_decompress(&cinfo);
-      return false;
+      return status;
     }
   } else {
-    cinfo.err->output_message((j_common_ptr)&cinfo);
+    status.error_code = UHDR_CODEC_ERROR;
+    status.has_detail = 1;
+    cinfo.err->format_message((j_common_ptr)&cinfo, status.detail);
     jpeg_destroy_decompress(&cinfo);
-    return false;
+    return status;
   }
   jpeg_finish_decompress(&cinfo);
   jpeg_destroy_decompress(&cinfo);
-  return true;
+  return status;
 }
 
-bool JpegDecoderHelper::decode(jpeg_decompress_struct* cinfo, uint8_t* dest) {
+uhdr_error_info_t JpegDecoderHelper::decode(jpeg_decompress_struct* cinfo, uint8_t* dest) {
+  uhdr_error_info_t status = g_no_error;
   switch (cinfo->out_color_space) {
     case JCS_GRAYSCALE:
       [[fallthrough]];
     case JCS_YCbCr:
       mOutFormat = getOutputSamplingFormat(cinfo);
+      if (mOutFormat == UHDR_IMG_FMT_UNSPECIFIED) {
+        status.error_code = UHDR_CODEC_ERROR;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "unrecognized subsampling format for output color space JCS_YCbCr");
+      }
       return decodeToCSYCbCr(cinfo, dest);
 #ifdef JCS_ALPHA_EXTENSIONS
     case JCS_EXT_RGBA:
@@ -360,30 +441,37 @@ bool JpegDecoderHelper::decode(jpeg_decompress_struct* cinfo, uint8_t* dest) {
       mOutFormat = UHDR_IMG_FMT_24bppRGB888;
       return decodeToCSRGB(cinfo, dest);
     default:
-      ALOGE("unrecognized output color space %d", cinfo->out_color_space);
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "unrecognized output color space %d",
+               cinfo->out_color_space);
   }
-  return false;
+  return status;
 }
 
-bool JpegDecoderHelper::decodeToCSRGB(jpeg_decompress_struct* cinfo, uint8_t* dest) {
+uhdr_error_info_t JpegDecoderHelper::decodeToCSRGB(jpeg_decompress_struct* cinfo, uint8_t* dest) {
   JSAMPLE* out = (JSAMPLE*)dest;
 
   while (cinfo->output_scanline < cinfo->image_height) {
     JDIMENSION read_lines = jpeg_read_scanlines(cinfo, &out, 1);
     if (1 != read_lines) {
-      ALOGE("jpeg_read_scanlines returned %d, expected %d", read_lines, 1);
-      return false;
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "jpeg_read_scanlines returned %d, expected %d",
+               read_lines, 1);
+      return status;
     }
 #ifdef JCS_ALPHA_EXTENSIONS
-    out += cinfo->image_width * 4;
+    out += mPlaneHStride[0] * 4;
 #else
-    out += cinfo->image_width * 3;
+    out += mPlaneHStride[0] * 3;
 #endif
   }
-  return true;
+  return g_no_error;
 }
 
-bool JpegDecoderHelper::decodeToCSYCbCr(jpeg_decompress_struct* cinfo, uint8_t* dest) {
+uhdr_error_info_t JpegDecoderHelper::decodeToCSYCbCr(jpeg_decompress_struct* cinfo, uint8_t* dest) {
   JSAMPROW mcuRows[kMaxNumComponents][4 * DCTSIZE];
   JSAMPROW mcuRowsTmp[kMaxNumComponents][4 * DCTSIZE];
   uint8_t* planes[kMaxNumComponents]{};
@@ -392,9 +480,9 @@ bool JpegDecoderHelper::decodeToCSYCbCr(jpeg_decompress_struct* cinfo, uint8_t*
 
   for (int i = 0, plane_offset = 0; i < cinfo->num_components; i++) {
     planes[i] = dest + plane_offset;
-    plane_offset += mPlaneWidth[i] * mPlaneHeight[i];
-    alignedPlaneWidth[i] = ALIGNM(mPlaneWidth[i], DCTSIZE);
-    if (mPlaneWidth[i] != alignedPlaneWidth[i]) {
+    plane_offset += mPlaneHStride[i] * mPlaneVStride[i];
+    alignedPlaneWidth[i] = ALIGNM(mPlaneHStride[i], DCTSIZE);
+    if (mPlaneHStride[i] != alignedPlaneWidth[i]) {
       mPlanesMCURow[i] = std::make_unique<uint8_t[]>(alignedPlaneWidth[i] * DCTSIZE *
                                                      cinfo->comp_info[i].v_samp_factor);
       uint8_t* mem = mPlanesMCURow[i].get();
@@ -402,10 +490,10 @@ bool JpegDecoderHelper::decodeToCSYCbCr(jpeg_decompress_struct* cinfo, uint8_t*
            j++, mem += alignedPlaneWidth[i]) {
         mcuRowsTmp[i][j] = mem;
       }
-    } else if (mPlaneHeight[i] % DCTSIZE != 0) {
+    } else if (mPlaneVStride[i] % DCTSIZE != 0) {
       mPlanesMCURow[i] = std::make_unique<uint8_t[]>(alignedPlaneWidth[i]);
     }
-    subImage[i] = mPlaneWidth[i] == alignedPlaneWidth[i] ? mcuRows[i] : mcuRowsTmp[i];
+    subImage[i] = mPlaneHStride[i] == alignedPlaneWidth[i] ? mcuRows[i] : mcuRowsTmp[i];
   }
 
   while (cinfo->output_scanline < cinfo->image_height) {
@@ -419,8 +507,8 @@ bool JpegDecoderHelper::decodeToCSYCbCr(jpeg_decompress_struct* cinfo, uint8_t*
       for (int j = 0; j < cinfo->comp_info[i].v_samp_factor * DCTSIZE; j++) {
         JDIMENSION scanline = mcu_scanline_start[i] + j;
 
-        if (scanline < mPlaneHeight[i]) {
-          mcuRows[i][j] = planes[i] + scanline * mPlaneWidth[i];
+        if (scanline < mPlaneVStride[i]) {
+          mcuRows[i][j] = planes[i] + scanline * mPlaneHStride[i];
         } else {
           mcuRows[i][j] = mPlanesMCURow[i].get();
         }
@@ -429,23 +517,46 @@ bool JpegDecoderHelper::decodeToCSYCbCr(jpeg_decompress_struct* cinfo, uint8_t*
 
     int processed = jpeg_read_raw_data(cinfo, subImage, DCTSIZE * cinfo->max_v_samp_factor);
     if (processed != DCTSIZE * cinfo->max_v_samp_factor) {
-      ALOGE("number of scan lines read %d does not equal requested scan lines %d ", processed,
-            DCTSIZE * cinfo->max_v_samp_factor);
-      return false;
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "number of scan lines read %d does not equal requested scan lines %d ", processed,
+               DCTSIZE * cinfo->max_v_samp_factor);
+      return status;
     }
 
     for (int i = 0; i < cinfo->num_components; i++) {
-      if (mPlaneWidth[i] != alignedPlaneWidth[i]) {
+      if (mPlaneHStride[i] != alignedPlaneWidth[i]) {
         for (int j = 0; j < cinfo->comp_info[i].v_samp_factor * DCTSIZE; j++) {
           JDIMENSION scanline = mcu_scanline_start[i] + j;
-          if (scanline < mPlaneHeight[i]) {
+          if (scanline < mPlaneVStride[i]) {
             memcpy(mcuRows[i][j], mcuRowsTmp[i][j], mPlaneWidth[i]);
           }
         }
       }
     }
   }
-  return true;
+  return g_no_error;
+}
+
+uhdr_raw_image_t JpegDecoderHelper::getDecompressedImage() {
+  uhdr_raw_image_t img;
+
+  img.fmt = mOutFormat;
+  img.cg = UHDR_CG_UNSPECIFIED;
+  img.ct = UHDR_CT_UNSPECIFIED;
+  img.range = UHDR_CR_FULL_RANGE;
+  img.w = mPlaneWidth[0];
+  img.h = mPlaneHeight[0];
+  uint8_t* data = mResultBuffer.data();
+  for (int i = 0; i < 3; i++) {
+    img.planes[i] = data;
+    img.stride[i] = mPlaneHStride[i];
+    data += mPlaneHStride[i] * mPlaneVStride[i];
+  }
+
+  return img;
 }
 
 }  // namespace ultrahdr
diff --git a/lib/src/jpegencoderhelper.cpp b/lib/src/jpegencoderhelper.cpp
index 97b101a..dc2e94d 100644
--- a/lib/src/jpegencoderhelper.cpp
+++ b/lib/src/jpegencoderhelper.cpp
@@ -24,7 +24,6 @@
 #include <string>
 
 #include "ultrahdr/ultrahdrcommon.h"
-#include "ultrahdr/ultrahdr.h"
 #include "ultrahdr/jpegencoderhelper.h"
 
 namespace ultrahdr {
@@ -105,22 +104,50 @@ static void outputErrorMessage(j_common_ptr cinfo) {
   ALOGE("%s\n", buffer);
 }
 
-bool JpegEncoderHelper::compressImage(const uint8_t* planes[3], const size_t strides[3],
-                                      const int width, const int height, const uhdr_img_fmt_t format,
-                                      const int qfactor, const void* iccBuffer,
-                                      const unsigned int iccSize) {
+uhdr_error_info_t JpegEncoderHelper::compressImage(const uhdr_raw_image_t* img, const int qfactor,
+                                                   const void* iccBuffer,
+                                                   const unsigned int iccSize) {
+  const uint8_t* planes[3]{reinterpret_cast<uint8_t*>(img->planes[UHDR_PLANE_Y]),
+                           reinterpret_cast<uint8_t*>(img->planes[UHDR_PLANE_U]),
+                           reinterpret_cast<uint8_t*>(img->planes[UHDR_PLANE_V])};
+  const size_t strides[3]{img->stride[UHDR_PLANE_Y], img->stride[UHDR_PLANE_U],
+                          img->stride[UHDR_PLANE_V]};
+  return compressImage(planes, strides, img->w, img->h, img->fmt, qfactor, iccBuffer, iccSize);
+}
+
+uhdr_error_info_t JpegEncoderHelper::compressImage(const uint8_t* planes[3],
+                                                   const size_t strides[3], const int width,
+                                                   const int height, const uhdr_img_fmt_t format,
+                                                   const int qfactor, const void* iccBuffer,
+                                                   const unsigned int iccSize) {
   return encode(planes, strides, width, height, format, qfactor, iccBuffer, iccSize);
 }
 
-bool JpegEncoderHelper::encode(const uint8_t* planes[3], const size_t strides[3], const int width,
-                               const int height, const uhdr_img_fmt_t format, const int qfactor,
-                               const void* iccBuffer, const unsigned int iccSize) {
+uhdr_compressed_image_t JpegEncoderHelper::getCompressedImage() {
+  uhdr_compressed_image_t img;
+
+  img.data = mDestMgr.mResultBuffer.data();
+  img.capacity = img.data_sz = mDestMgr.mResultBuffer.size();
+  img.cg = UHDR_CG_UNSPECIFIED;
+  img.ct = UHDR_CT_UNSPECIFIED;
+  img.range = UHDR_CR_UNSPECIFIED;
+
+  return img;
+}
+
+uhdr_error_info_t JpegEncoderHelper::encode(const uint8_t* planes[3], const size_t strides[3],
+                                            const int width, const int height,
+                                            const uhdr_img_fmt_t format, const int qfactor,
+                                            const void* iccBuffer, const unsigned int iccSize) {
   jpeg_compress_struct cinfo;
   jpeg_error_mgr_impl myerr;
+  uhdr_error_info_t status = g_no_error;
 
   if (sample_factors.find(format) == sample_factors.end()) {
-    ALOGE("unrecognized format %d", format);
-    return false;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "unrecognized input format %d", format);
+    return status;
   }
   std::vector<int>& factors = sample_factors.find(format)->second;
 
@@ -141,6 +168,7 @@ bool JpegEncoderHelper::encode(const uint8_t* planes[3], const size_t strides[3]
     // initialize configuration parameters
     cinfo.image_width = width;
     cinfo.image_height = height;
+    bool isGainMapImg = true;
     if (format == UHDR_IMG_FMT_24bppRGB888) {
       cinfo.input_components = 3;
       cinfo.in_color_space = JCS_RGB;
@@ -148,9 +176,19 @@ bool JpegEncoderHelper::encode(const uint8_t* planes[3], const size_t strides[3]
       if (format == UHDR_IMG_FMT_8bppYCbCr400) {
         cinfo.input_components = 1;
         cinfo.in_color_space = JCS_GRAYSCALE;
-      } else {
+      } else if (format == UHDR_IMG_FMT_12bppYCbCr420 || format == UHDR_IMG_FMT_24bppYCbCr444 ||
+                 format == UHDR_IMG_FMT_16bppYCbCr422 || format == UHDR_IMG_FMT_16bppYCbCr440 ||
+                 format == UHDR_IMG_FMT_12bppYCbCr411 || format == UHDR_IMG_FMT_10bppYCbCr410) {
         cinfo.input_components = 3;
         cinfo.in_color_space = JCS_YCbCr;
+        isGainMapImg = false;
+      } else {
+        status.error_code = UHDR_CODEC_ERROR;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "unrecognized input color format for encoding, color format %d", format);
+        jpeg_destroy_compress(&cinfo);
+        return status;
       }
     }
     jpeg_set_defaults(&cinfo);
@@ -171,35 +209,50 @@ bool JpegEncoderHelper::encode(const uint8_t* planes[3], const size_t strides[3]
     if (iccBuffer != nullptr && iccSize > 0) {
       jpeg_write_marker(&cinfo, JPEG_APP0 + 2, static_cast<const JOCTET*>(iccBuffer), iccSize);
     }
+    if (isGainMapImg) {
+      char comment[255];
+      snprintf(comment, sizeof comment,
+               "Source: google libuhdr v%s, Coder: libjpeg v%d, Attrib: GainMap Image",
+               UHDR_LIB_VERSION_STR, JPEG_LIB_VERSION);
+      jpeg_write_marker(&cinfo, JPEG_COM, reinterpret_cast<JOCTET*>(comment), strlen(comment));
+    }
     if (format == UHDR_IMG_FMT_24bppRGB888) {
       while (cinfo.next_scanline < cinfo.image_height) {
-        JSAMPROW row_pointer[]{const_cast<JSAMPROW>(&planes[0][cinfo.next_scanline * strides[0]])};
+        JSAMPROW row_pointer[]{
+            const_cast<JSAMPROW>(&planes[0][cinfo.next_scanline * strides[0] * 3])};
         JDIMENSION processed = jpeg_write_scanlines(&cinfo, row_pointer, 1);
         if (1 != processed) {
-          ALOGE("jpeg_read_scanlines returned %d, expected %d", processed, 1);
+          status.error_code = UHDR_CODEC_ERROR;
+          status.has_detail = 1;
+          snprintf(status.detail, sizeof status.detail,
+                   "jpeg_read_scanlines returned %d, expected %d", processed, 1);
           jpeg_destroy_compress(&cinfo);
-          return false;
+          return status;
         }
       }
     } else {
-      if (!compressYCbCr(&cinfo, planes, strides)) {
+      status = compressYCbCr(&cinfo, planes, strides);
+      if (status.error_code != UHDR_CODEC_OK) {
         jpeg_destroy_compress(&cinfo);
-        return false;
+        return status;
       }
     }
   } else {
-    cinfo.err->output_message((j_common_ptr)&cinfo);
+    status.error_code = UHDR_CODEC_ERROR;
+    status.has_detail = 1;
+    cinfo.err->format_message((j_common_ptr)&cinfo, status.detail);
     jpeg_destroy_compress(&cinfo);
-    return false;
+    return status;
   }
 
   jpeg_finish_compress(&cinfo);
   jpeg_destroy_compress(&cinfo);
-  return true;
+  return status;
 }
 
-bool JpegEncoderHelper::compressYCbCr(jpeg_compress_struct* cinfo, const uint8_t* planes[3],
-                                      const size_t strides[3]) {
+uhdr_error_info_t JpegEncoderHelper::compressYCbCr(jpeg_compress_struct* cinfo,
+                                                   const uint8_t* planes[3],
+                                                   const size_t strides[3]) {
   JSAMPROW mcuRows[kMaxNumComponents][2 * DCTSIZE];
   JSAMPROW mcuRowsTmp[kMaxNumComponents][2 * DCTSIZE];
   size_t alignedPlaneWidth[kMaxNumComponents]{};
@@ -250,12 +303,16 @@ bool JpegEncoderHelper::compressYCbCr(jpeg_compress_struct* cinfo, const uint8_t
     }
     int processed = jpeg_write_raw_data(cinfo, subImage, DCTSIZE * cinfo->max_v_samp_factor);
     if (processed != DCTSIZE * cinfo->max_v_samp_factor) {
-      ALOGE("number of scan lines processed %d does not equal requested scan lines %d ", processed,
-            DCTSIZE * cinfo->max_v_samp_factor);
-      return false;
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "number of scan lines processed %d does not equal requested scan lines %d ",
+               processed, DCTSIZE * cinfo->max_v_samp_factor);
+      return status;
     }
   }
-  return true;
+  return g_no_error;
 }
 
 }  // namespace ultrahdr
diff --git a/lib/src/jpegr.cpp b/lib/src/jpegr.cpp
index 4f2e1ae..90053f2 100644
--- a/lib/src/jpegr.cpp
+++ b/lib/src/jpegr.cpp
@@ -44,22 +44,87 @@ using namespace photos_editing_formats::image_io;
 
 namespace ultrahdr {
 
-#define USE_SRGB_INVOETF_LUT 1
-#define USE_HLG_OETF_LUT 1
-#define USE_PQ_OETF_LUT 1
-#define USE_HLG_INVOETF_LUT 1
-#define USE_PQ_INVOETF_LUT 1
-#define USE_APPLY_GAIN_LUT 1
-
-// JPEG compress quality (0 ~ 100) for gain map
-static const int kMapCompressQuality = 85;
+#ifdef UHDR_ENABLE_GLES
+uhdr_error_info_t applyGainMapGLES(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
+                                   uhdr_gainmap_metadata_ext_t* gainmap_metadata,
+                                   uhdr_color_transfer_t output_ct, float display_boost,
+                                   uhdr_raw_image_t* dest, uhdr_opengl_ctxt_t* opengl_ctxt);
+#endif
 
 // Gain map metadata
 static const bool kWriteXmpMetadata = true;
 static const bool kWriteIso21496_1Metadata = false;
 
-// Gain map calculation
-static const bool kUseMultiChannelGainMap = false;
+static const string kXmpNameSpace = "http://ns.adobe.com/xap/1.0/";
+static const string kIsoNameSpace = "urn:iso:std:iso:ts:21496:-1";
+
+static_assert(kWriteXmpMetadata || kWriteIso21496_1Metadata,
+              "Must write gain map metadata in XMP format, or iso 21496-1 format, or both.");
+
+class JobQueue {
+ public:
+  bool dequeueJob(size_t& rowStart, size_t& rowEnd);
+  void enqueueJob(size_t rowStart, size_t rowEnd);
+  void markQueueForEnd();
+  void reset();
+
+ private:
+  bool mQueuedAllJobs = false;
+  std::deque<std::tuple<size_t, size_t>> mJobs;
+  std::mutex mMutex;
+  std::condition_variable mCv;
+};
+
+bool JobQueue::dequeueJob(size_t& rowStart, size_t& rowEnd) {
+  std::unique_lock<std::mutex> lock{mMutex};
+  while (true) {
+    if (mJobs.empty()) {
+      if (mQueuedAllJobs) {
+        return false;
+      } else {
+        mCv.wait_for(lock, std::chrono::milliseconds(100));
+      }
+    } else {
+      auto it = mJobs.begin();
+      rowStart = std::get<0>(*it);
+      rowEnd = std::get<1>(*it);
+      mJobs.erase(it);
+      return true;
+    }
+  }
+  return false;
+}
+
+void JobQueue::enqueueJob(size_t rowStart, size_t rowEnd) {
+  std::unique_lock<std::mutex> lock{mMutex};
+  mJobs.push_back(std::make_tuple(rowStart, rowEnd));
+  lock.unlock();
+  mCv.notify_one();
+}
+
+void JobQueue::markQueueForEnd() {
+  std::unique_lock<std::mutex> lock{mMutex};
+  mQueuedAllJobs = true;
+  lock.unlock();
+  mCv.notify_all();
+}
+
+void JobQueue::reset() {
+  std::unique_lock<std::mutex> lock{mMutex};
+  mJobs.clear();
+  mQueuedAllJobs = false;
+}
+
+/*
+ * MessageWriter implementation for ALOG functions.
+ */
+class AlogMessageWriter : public MessageWriter {
+ public:
+  void WriteMessage(const Message& message) override {
+    std::string log = GetFormattedMessage(message);
+    ALOGD("%s", log.c_str());
+  }
+};
 
 int GetCPUCoreCount() {
   int cpuCoreCount = 1;
@@ -80,19 +145,18 @@ int GetCPUCoreCount() {
   return cpuCoreCount;
 }
 
-/*
- * MessageWriter implementation for ALOG functions.
- */
-class AlogMessageWriter : public MessageWriter {
- public:
-  void WriteMessage(const Message& message) override {
-    std::string log = GetFormattedMessage(message);
-    ALOGD("%s", log.c_str());
-  }
-};
-
-const string kXmpNameSpace = "http://ns.adobe.com/xap/1.0/";
-const string kIsoNameSpace = "urn:iso:std:iso:ts:21496:-1";
+JpegR::JpegR(void* uhdrGLESCtxt, size_t mapDimensionScaleFactor, int mapCompressQuality,
+             bool useMultiChannelGainMap, float gamma, uhdr_enc_preset_t preset,
+             float minContentBoost, float maxContentBoost) {
+  mUhdrGLESCtxt = uhdrGLESCtxt;
+  mMapDimensionScaleFactor = mapDimensionScaleFactor;
+  mMapCompressQuality = mapCompressQuality;
+  mUseMultiChannelGainMap = useMultiChannelGainMap;
+  mGamma = gamma;
+  mEncPreset = preset;
+  mMinContentBoost = minContentBoost;
+  mMaxContentBoost = maxContentBoost;
+}
 
 /*
  * Helper function copies the JPEG image from without EXIF.
@@ -103,1081 +167,1276 @@ const string kIsoNameSpace = "urn:iso:std:iso:ts:21496:-1";
  *                 (4 bytes offset to FF sign, the byte after FF E1 XX XX <this byte>).
  * @param exif_size exif size without the initial 4 bytes, aligned with jpegdecoder.getEXIFSize().
  */
-static void copyJpegWithoutExif(jr_compressed_ptr pDest, jr_compressed_ptr pSource, size_t exif_pos,
-                                size_t exif_size) {
+static void copyJpegWithoutExif(uhdr_compressed_image_t* pDest, uhdr_compressed_image_t* pSource,
+                                size_t exif_pos, size_t exif_size) {
   const size_t exif_offset = 4;  // exif_pos has 4 bytes offset to the FF sign
-  pDest->length = pSource->length - exif_size - exif_offset;
-  pDest->data = new uint8_t[pDest->length];
-  pDest->maxLength = pDest->length;
-  pDest->colorGamut = pSource->colorGamut;
+  pDest->data_sz = pSource->data_sz - exif_size - exif_offset;
+  pDest->data = new uint8_t[pDest->data_sz];
+  pDest->capacity = pDest->data_sz;
+  pDest->cg = pSource->cg;
+  pDest->ct = pSource->ct;
+  pDest->range = pSource->range;
   memcpy(pDest->data, pSource->data, exif_pos - exif_offset);
   memcpy((uint8_t*)pDest->data + exif_pos - exif_offset,
-         (uint8_t*)pSource->data + exif_pos + exif_size, pSource->length - exif_pos - exif_size);
-}
-
-status_t JpegR::areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
-                                       jr_uncompressed_ptr yuv420_image_ptr,
-                                       ultrahdr_transfer_function hdr_tf,
-                                       jr_compressed_ptr dest_ptr) {
-  if (p010_image_ptr == nullptr || p010_image_ptr->data == nullptr) {
-    ALOGE("Received nullptr for input p010 image");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (p010_image_ptr->width % 2 != 0 || p010_image_ptr->height % 2 != 0) {
-    ALOGE("Image dimensions cannot be odd, image dimensions %zux%zu", p010_image_ptr->width,
-          p010_image_ptr->height);
-    return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
-  }
-  if (p010_image_ptr->width < kMinWidth || p010_image_ptr->height < kMinHeight) {
-    ALOGE("Image dimensions cannot be less than %dx%d, image dimensions %zux%zu", kMinWidth,
-          kMinHeight, p010_image_ptr->width, p010_image_ptr->height);
-    return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
-  }
-  if (p010_image_ptr->width > kMaxWidth || p010_image_ptr->height > kMaxHeight) {
-    ALOGE("Image dimensions cannot be larger than %dx%d, image dimensions %zux%zu", kMaxWidth,
-          kMaxHeight, p010_image_ptr->width, p010_image_ptr->height);
-    return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
-  }
-  if (p010_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
-      p010_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
-    ALOGE("Unrecognized p010 color gamut %d", p010_image_ptr->colorGamut);
-    return ERROR_JPEGR_INVALID_COLORGAMUT;
-  }
-  if (p010_image_ptr->luma_stride != 0 && p010_image_ptr->luma_stride < p010_image_ptr->width) {
-    ALOGE("Luma stride must not be smaller than width, stride=%zu, width=%zu",
-          p010_image_ptr->luma_stride, p010_image_ptr->width);
-    return ERROR_JPEGR_INVALID_STRIDE;
-  }
-  if (p010_image_ptr->chroma_data != nullptr &&
-      p010_image_ptr->chroma_stride < p010_image_ptr->width) {
-    ALOGE("Chroma stride must not be smaller than width, stride=%zu, width=%zu",
-          p010_image_ptr->chroma_stride, p010_image_ptr->width);
-    return ERROR_JPEGR_INVALID_STRIDE;
-  }
-  if (dest_ptr == nullptr || dest_ptr->data == nullptr) {
-    ALOGE("Received nullptr for destination");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (hdr_tf <= ULTRAHDR_TF_UNSPECIFIED || hdr_tf > ULTRAHDR_TF_MAX || hdr_tf == ULTRAHDR_TF_SRGB) {
-    ALOGE("Invalid hdr transfer function %d", hdr_tf);
-    return ERROR_JPEGR_INVALID_TRANS_FUNC;
-  }
-  if (yuv420_image_ptr == nullptr) {
-    return JPEGR_NO_ERROR;
-  }
-  if (yuv420_image_ptr->data == nullptr) {
-    ALOGE("Received nullptr for uncompressed 420 image");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (yuv420_image_ptr->luma_stride != 0 &&
-      yuv420_image_ptr->luma_stride < yuv420_image_ptr->width) {
-    ALOGE("Luma stride must not be smaller than width, stride=%zu, width=%zu",
-          yuv420_image_ptr->luma_stride, yuv420_image_ptr->width);
-    return ERROR_JPEGR_INVALID_STRIDE;
-  }
-  if (yuv420_image_ptr->chroma_data != nullptr &&
-      yuv420_image_ptr->chroma_stride < yuv420_image_ptr->width / 2) {
-    ALOGE("Chroma stride must not be smaller than (width / 2), stride=%zu, width=%zu",
-          yuv420_image_ptr->chroma_stride, yuv420_image_ptr->width);
-    return ERROR_JPEGR_INVALID_STRIDE;
-  }
-  if (p010_image_ptr->width != yuv420_image_ptr->width ||
-      p010_image_ptr->height != yuv420_image_ptr->height) {
-    ALOGE("Image resolutions mismatch: P010: %zux%zu, YUV420: %zux%zu", p010_image_ptr->width,
-          p010_image_ptr->height, yuv420_image_ptr->width, yuv420_image_ptr->height);
-    return ERROR_JPEGR_RESOLUTION_MISMATCH;
-  }
-  if (yuv420_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
-      yuv420_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
-    ALOGE("Unrecognized 420 color gamut %d", yuv420_image_ptr->colorGamut);
-    return ERROR_JPEGR_INVALID_COLORGAMUT;
-  }
-  return JPEGR_NO_ERROR;
-}
-
-status_t JpegR::areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
-                                       jr_uncompressed_ptr yuv420_image_ptr,
-                                       ultrahdr_transfer_function hdr_tf,
-                                       jr_compressed_ptr dest_ptr, int quality) {
-  if (quality < 0 || quality > 100) {
-    ALOGE("quality factor is out side range [0-100], quality factor : %d", quality);
-    return ERROR_JPEGR_INVALID_QUALITY_FACTOR;
-  }
-  return areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest_ptr);
+         (uint8_t*)pSource->data + exif_pos + exif_size, pSource->data_sz - exif_pos - exif_size);
 }
 
 /* Encode API-0 */
-status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, ultrahdr_transfer_function hdr_tf,
-                            jr_compressed_ptr dest, int quality, jr_exif_ptr exif) {
-  // validate input arguments
-  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, nullptr, hdr_tf, dest, quality));
-  if (exif != nullptr && exif->data == nullptr) {
-    ALOGE("received nullptr for exif metadata");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-
-  // clean up input structure for later usage
-  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
-  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
-  if (!p010_image.chroma_data) {
-    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
-    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
-    p010_image.chroma_stride = p010_image.luma_stride;
+uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_compressed_image_t* dest,
+                                     int quality, uhdr_mem_block_t* exif) {
+  uhdr_img_fmt_t sdr_intent_fmt;
+  if (hdr_intent->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
+    sdr_intent_fmt = UHDR_IMG_FMT_12bppYCbCr420;
+  } else if (hdr_intent->fmt == UHDR_IMG_FMT_30bppYCbCr444) {
+    sdr_intent_fmt = UHDR_IMG_FMT_24bppYCbCr444;
+  } else if (hdr_intent->fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
+    sdr_intent_fmt = UHDR_IMG_FMT_32bppRGBA8888;
+  } else {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "unsupported hdr intent color format %d",
+             hdr_intent->fmt);
+    return status;
   }
-
-  const size_t yu420_luma_stride = ALIGNM(p010_image.width, 16);
-  unique_ptr<uint8_t[]> yuv420_image_data =
-      make_unique<uint8_t[]>(yu420_luma_stride * p010_image.height * 3 / 2);
-  jpegr_uncompressed_struct yuv420_image;
-  yuv420_image.data = yuv420_image_data.get();
-  yuv420_image.width = p010_image.width;
-  yuv420_image.height = p010_image.height;
-  yuv420_image.colorGamut = p010_image.colorGamut;
-  yuv420_image.chroma_data = nullptr;
-  yuv420_image.luma_stride = yu420_luma_stride;
-  yuv420_image.chroma_stride = yu420_luma_stride >> 1;
-  uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
-  yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;
+  std::unique_ptr<uhdr_raw_image_ext_t> sdr_intent = std::make_unique<uhdr_raw_image_ext_t>(
+      sdr_intent_fmt, UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, hdr_intent->w,
+      hdr_intent->h, 64);
 
   // tone map
-  JPEGR_CHECK(toneMap(&p010_image, &yuv420_image, hdr_tf));
+  UHDR_ERR_CHECK(toneMap(hdr_intent, sdr_intent.get()));
+
+  // If hdr intent is tonemapped internally, it is observed from quality pov,
+  // generateGainMapOnePass() is sufficient
+  mEncPreset = UHDR_USAGE_REALTIME;  // overriding the config option
 
-  // gain map
-  ultrahdr_metadata_struct metadata;
-  metadata.version = kJpegrVersion;
-  jpegr_uncompressed_struct gainmap_image;
-  JPEGR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image));
-  std::unique_ptr<uint8_t[]> map_data;
-  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));
+  // generate gain map
+  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
+  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
+  UHDR_ERR_CHECK(generateGainMap(sdr_intent.get(), hdr_intent, &metadata, gainmap,
+                                 /* sdr_is_601 */ false,
+                                 /* use_luminance */ false));
 
   // compress gain map
   JpegEncoderHelper jpeg_enc_obj_gm;
-  JPEGR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
-  jpegr_compressed_struct compressed_map;
-  compressed_map.data = jpeg_enc_obj_gm.getCompressedImagePtr();
-  compressed_map.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
-  compressed_map.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
-  compressed_map.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-
-  std::shared_ptr<DataStruct> icc =
-      IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, yuv420_image.colorGamut);
-
-  // convert to Bt601 YUV encoding for JPEG encode
-  if (yuv420_image.colorGamut != ULTRAHDR_COLORGAMUT_P3) {
-#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)) && \
-     defined(__aarch64__))
-    JPEGR_CHECK(convertYuv_neon(&yuv420_image, yuv420_image.colorGamut, ULTRAHDR_COLORGAMUT_P3));
-#else
-    JPEGR_CHECK(convertYuv(&yuv420_image, yuv420_image.colorGamut, ULTRAHDR_COLORGAMUT_P3));
-#endif
+  UHDR_ERR_CHECK(compressGainMap(gainmap.get(), &jpeg_enc_obj_gm));
+  uhdr_compressed_image_t gainmap_compressed = jpeg_enc_obj_gm.getCompressedImage();
+
+  std::shared_ptr<DataStruct> icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, sdr_intent->cg);
+
+  // compress sdr image
+  std::unique_ptr<uhdr_raw_image_ext_t> sdr_intent_yuv_ext;
+  uhdr_raw_image_t* sdr_intent_yuv = sdr_intent.get();
+  if (isPixelFormatRgb(sdr_intent->fmt)) {
+    sdr_intent_yuv_ext = convert_raw_input_to_ycbcr(sdr_intent.get());
+    sdr_intent_yuv = sdr_intent_yuv_ext.get();
   }
 
-  // compress 420 image
-  JpegEncoderHelper jpeg_enc_obj_yuv420;
-  const uint8_t* planes[3]{reinterpret_cast<uint8_t*>(yuv420_image.data),
-                           reinterpret_cast<uint8_t*>(yuv420_image.chroma_data),
-                           reinterpret_cast<uint8_t*>(yuv420_image.chroma_data) +
-                               yuv420_image.chroma_stride * yuv420_image.height / 2};
-  const size_t strides[3]{yuv420_image.luma_stride, yuv420_image.chroma_stride,
-                          yuv420_image.chroma_stride};
-  if (!jpeg_enc_obj_yuv420.compressImage(planes, strides, yuv420_image.width, yuv420_image.height,
-                                         UHDR_IMG_FMT_12bppYCbCr420, quality, icc->getData(),
-                                         icc->getLength())) {
-    return ERROR_JPEGR_ENCODE_ERROR;
-  }
-  jpegr_compressed_struct jpeg;
-  jpeg.data = jpeg_enc_obj_yuv420.getCompressedImagePtr();
-  jpeg.length = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
-  jpeg.maxLength = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
-  jpeg.colorGamut = yuv420_image.colorGamut;
+  JpegEncoderHelper jpeg_enc_obj_sdr;
+  UHDR_ERR_CHECK(
+      jpeg_enc_obj_sdr.compressImage(sdr_intent_yuv, quality, icc->getData(), icc->getLength()));
+  uhdr_compressed_image_t sdr_intent_compressed = jpeg_enc_obj_sdr.getCompressedImage();
+  sdr_intent_compressed.cg = sdr_intent_yuv->cg;
 
   // append gain map, no ICC since JPEG encode already did it
-  JPEGR_CHECK(appendGainMap(&jpeg, &compressed_map, exif, /* icc */ nullptr, /* icc size */ 0,
-                            &metadata, dest));
-
-  return JPEGR_NO_ERROR;
+  UHDR_ERR_CHECK(appendGainMap(&sdr_intent_compressed, &gainmap_compressed, exif, /* icc */ nullptr,
+                               /* icc size */ 0, &metadata, dest));
+  return g_no_error;
 }
 
 /* Encode API-1 */
-status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
-                            jr_uncompressed_ptr yuv420_image_ptr, ultrahdr_transfer_function hdr_tf,
-                            jr_compressed_ptr dest, int quality, jr_exif_ptr exif) {
-  // validate input arguments
-  if (yuv420_image_ptr == nullptr) {
-    ALOGE("received nullptr for uncompressed 420 image");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (exif != nullptr && exif->data == nullptr) {
-    ALOGE("received nullptr for exif metadata");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest, quality))
+uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
+                                     uhdr_compressed_image_t* dest, int quality,
+                                     uhdr_mem_block_t* exif) {
+  // generate gain map
+  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
+  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
+  UHDR_ERR_CHECK(generateGainMap(sdr_intent, hdr_intent, &metadata, gainmap));
 
-  // clean up input structure for later usage
-  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
-  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
-  if (!p010_image.chroma_data) {
-    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
-    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
-    p010_image.chroma_stride = p010_image.luma_stride;
-  }
-  jpegr_uncompressed_struct yuv420_image = *yuv420_image_ptr;
-  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
-  if (!yuv420_image.chroma_data) {
-    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
-    yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;
-    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
+  // compress gain map
+  JpegEncoderHelper jpeg_enc_obj_gm;
+  UHDR_ERR_CHECK(compressGainMap(gainmap.get(), &jpeg_enc_obj_gm));
+  uhdr_compressed_image_t gainmap_compressed = jpeg_enc_obj_gm.getCompressedImage();
+
+  std::shared_ptr<DataStruct> icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, sdr_intent->cg);
+
+  std::unique_ptr<uhdr_raw_image_ext_t> sdr_intent_yuv_ext;
+  uhdr_raw_image_t* sdr_intent_yuv = sdr_intent;
+  if (isPixelFormatRgb(sdr_intent->fmt)) {
+    sdr_intent_yuv_ext = convert_raw_input_to_ycbcr(sdr_intent);
+    sdr_intent_yuv = sdr_intent_yuv_ext.get();
   }
 
-  // gain map
-  ultrahdr_metadata_struct metadata;
-  metadata.version = kJpegrVersion;
-  jpegr_uncompressed_struct gainmap_image;
-  JPEGR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image));
-  std::unique_ptr<uint8_t[]> map_data;
-  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));
+  // convert to bt601 YUV encoding for JPEG encode
+#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)))
+  UHDR_ERR_CHECK(convertYuv_neon(sdr_intent_yuv, sdr_intent_yuv->cg, UHDR_CG_DISPLAY_P3));
+#else
+  UHDR_ERR_CHECK(convertYuv(sdr_intent_yuv, sdr_intent_yuv->cg, UHDR_CG_DISPLAY_P3));
+#endif
+
+  // compress sdr image
+  JpegEncoderHelper jpeg_enc_obj_sdr;
+  UHDR_ERR_CHECK(
+      jpeg_enc_obj_sdr.compressImage(sdr_intent_yuv, quality, icc->getData(), icc->getLength()));
+  uhdr_compressed_image_t sdr_intent_compressed = jpeg_enc_obj_sdr.getCompressedImage();
+  sdr_intent_compressed.cg = sdr_intent_yuv->cg;
+
+  // append gain map, no ICC since JPEG encode already did it
+  UHDR_ERR_CHECK(appendGainMap(&sdr_intent_compressed, &gainmap_compressed, exif, /* icc */ nullptr,
+                               /* icc size */ 0, &metadata, dest));
+  return g_no_error;
+}
+
+/* Encode API-2 */
+uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent,
+                                     uhdr_compressed_image_t* sdr_intent_compressed,
+                                     uhdr_compressed_image_t* dest) {
+  JpegDecoderHelper jpeg_dec_obj_sdr;
+  UHDR_ERR_CHECK(jpeg_dec_obj_sdr.decompressImage(sdr_intent_compressed->data,
+                                                  sdr_intent_compressed->data_sz, PARSE_STREAM));
+  if (hdr_intent->w != jpeg_dec_obj_sdr.getDecompressedImageWidth() ||
+      hdr_intent->h != jpeg_dec_obj_sdr.getDecompressedImageHeight()) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(
+        status.detail, sizeof status.detail,
+        "sdr intent resolution %dx%d and compressed image sdr intent resolution %dx%d do not match",
+        sdr_intent->w, sdr_intent->h, (int)jpeg_dec_obj_sdr.getDecompressedImageWidth(),
+        (int)jpeg_dec_obj_sdr.getDecompressedImageHeight());
+    return status;
+  }
+
+  // generate gain map
+  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
+  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
+  UHDR_ERR_CHECK(generateGainMap(sdr_intent, hdr_intent, &metadata, gainmap));
 
   // compress gain map
   JpegEncoderHelper jpeg_enc_obj_gm;
-  JPEGR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
-  jpegr_compressed_struct compressed_map;
-  compressed_map.data = jpeg_enc_obj_gm.getCompressedImagePtr();
-  compressed_map.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
-  compressed_map.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
-  compressed_map.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-
-  std::shared_ptr<DataStruct> icc =
-      IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, yuv420_image.colorGamut);
-
-  jpegr_uncompressed_struct yuv420_bt601_image = yuv420_image;
-  unique_ptr<uint8_t[]> yuv_420_bt601_data;
-  // Convert to bt601 YUV encoding for JPEG encode
-  if (yuv420_image.colorGamut != ULTRAHDR_COLORGAMUT_P3) {
-    const size_t yuv_420_bt601_luma_stride = ALIGNM(yuv420_image.width, 16);
-    yuv_420_bt601_data =
-        make_unique<uint8_t[]>(yuv_420_bt601_luma_stride * yuv420_image.height * 3 / 2);
-    yuv420_bt601_image.data = yuv_420_bt601_data.get();
-    yuv420_bt601_image.colorGamut = yuv420_image.colorGamut;
-    yuv420_bt601_image.luma_stride = yuv_420_bt601_luma_stride;
-    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_bt601_image.data);
-    yuv420_bt601_image.chroma_data = data + yuv_420_bt601_luma_stride * yuv420_image.height;
-    yuv420_bt601_image.chroma_stride = yuv_420_bt601_luma_stride >> 1;
-
-    {
-      // copy luma
-      uint8_t* y_dst = reinterpret_cast<uint8_t*>(yuv420_bt601_image.data);
-      uint8_t* y_src = reinterpret_cast<uint8_t*>(yuv420_image.data);
-      if (yuv420_bt601_image.luma_stride == yuv420_image.luma_stride) {
-        memcpy(y_dst, y_src, yuv420_bt601_image.luma_stride * yuv420_image.height);
-      } else {
-        for (size_t i = 0; i < yuv420_image.height; i++) {
-          memcpy(y_dst, y_src, yuv420_image.width);
-          if (yuv420_image.width != yuv420_bt601_image.luma_stride) {
-            memset(y_dst + yuv420_image.width, 0,
-                   yuv420_bt601_image.luma_stride - yuv420_image.width);
-          }
-          y_dst += yuv420_bt601_image.luma_stride;
-          y_src += yuv420_image.luma_stride;
-        }
-      }
-    }
+  UHDR_ERR_CHECK(compressGainMap(gainmap.get(), &jpeg_enc_obj_gm));
+  uhdr_compressed_image_t gainmap_compressed = jpeg_enc_obj_gm.getCompressedImage();
 
-    if (yuv420_bt601_image.chroma_stride == yuv420_image.chroma_stride) {
-      // copy luma
-      uint8_t* ch_dst = reinterpret_cast<uint8_t*>(yuv420_bt601_image.chroma_data);
-      uint8_t* ch_src = reinterpret_cast<uint8_t*>(yuv420_image.chroma_data);
-      memcpy(ch_dst, ch_src, yuv420_bt601_image.chroma_stride * yuv420_image.height);
-    } else {
-      // copy cb & cr
-      uint8_t* cb_dst = reinterpret_cast<uint8_t*>(yuv420_bt601_image.chroma_data);
-      uint8_t* cb_src = reinterpret_cast<uint8_t*>(yuv420_image.chroma_data);
-      uint8_t* cr_dst = cb_dst + (yuv420_bt601_image.chroma_stride * yuv420_bt601_image.height / 2);
-      uint8_t* cr_src = cb_src + (yuv420_image.chroma_stride * yuv420_image.height / 2);
-      for (size_t i = 0; i < yuv420_image.height / 2; i++) {
-        memcpy(cb_dst, cb_src, yuv420_image.width / 2);
-        memcpy(cr_dst, cr_src, yuv420_image.width / 2);
-        if (yuv420_bt601_image.width / 2 != yuv420_bt601_image.chroma_stride) {
-          memset(cb_dst + yuv420_image.width / 2, 0,
-                 yuv420_bt601_image.chroma_stride - yuv420_image.width / 2);
-          memset(cr_dst + yuv420_image.width / 2, 0,
-                 yuv420_bt601_image.chroma_stride - yuv420_image.width / 2);
-        }
-        cb_dst += yuv420_bt601_image.chroma_stride;
-        cb_src += yuv420_image.chroma_stride;
-        cr_dst += yuv420_bt601_image.chroma_stride;
-        cr_src += yuv420_image.chroma_stride;
-      }
-    }
+  return encodeJPEGR(sdr_intent_compressed, &gainmap_compressed, &metadata, dest);
+}
 
-#if (defined(UHDR_ENABLE_INTRINSICS) && (defined(__ARM_NEON__) || defined(__ARM_NEON)) && \
-     defined(__aarch64__))
-    JPEGR_CHECK(
-        convertYuv_neon(&yuv420_bt601_image, yuv420_image.colorGamut, ULTRAHDR_COLORGAMUT_P3));
-#else
-    JPEGR_CHECK(convertYuv(&yuv420_bt601_image, yuv420_image.colorGamut, ULTRAHDR_COLORGAMUT_P3));
-#endif
+/* Encode API-3 */
+uhdr_error_info_t JpegR::encodeJPEGR(uhdr_raw_image_t* hdr_intent,
+                                     uhdr_compressed_image_t* sdr_intent_compressed,
+                                     uhdr_compressed_image_t* dest) {
+  // decode input jpeg, gamut is going to be bt601.
+  JpegDecoderHelper jpeg_dec_obj_sdr;
+  UHDR_ERR_CHECK(jpeg_dec_obj_sdr.decompressImage(sdr_intent_compressed->data,
+                                                  sdr_intent_compressed->data_sz));
+
+  uhdr_raw_image_t sdr_intent = jpeg_dec_obj_sdr.getDecompressedImage();
+  if (jpeg_dec_obj_sdr.getICCSize() > 0) {
+    uhdr_color_gamut_t cg =
+        IccHelper::readIccColorGamut(jpeg_dec_obj_sdr.getICCPtr(), jpeg_dec_obj_sdr.getICCSize());
+    if (cg == UHDR_CG_UNSPECIFIED ||
+        (sdr_intent_compressed->cg != UHDR_CG_UNSPECIFIED && sdr_intent_compressed->cg != cg)) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "configured color gamut %d does not match with color gamut specified in icc box %d",
+               sdr_intent_compressed->cg, cg);
+      return status;
+    }
+    sdr_intent.cg = cg;
+  } else {
+    if (sdr_intent_compressed->cg <= UHDR_CG_UNSPECIFIED ||
+        sdr_intent_compressed->cg > UHDR_CG_BT_2100) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "Unrecognized 420 color gamut %d",
+               sdr_intent_compressed->cg);
+      return status;
+    }
+    sdr_intent.cg = sdr_intent_compressed->cg;
   }
 
-  // compress 420 image
-  JpegEncoderHelper jpeg_enc_obj_yuv420;
-  const uint8_t* planes[3]{reinterpret_cast<uint8_t*>(yuv420_bt601_image.data),
-                           reinterpret_cast<uint8_t*>(yuv420_bt601_image.chroma_data),
-                           reinterpret_cast<uint8_t*>(yuv420_bt601_image.chroma_data) +
-                               yuv420_bt601_image.chroma_stride * yuv420_bt601_image.height / 2};
-  const size_t strides[3]{yuv420_bt601_image.luma_stride, yuv420_bt601_image.chroma_stride,
-                          yuv420_bt601_image.chroma_stride};
-  if (!jpeg_enc_obj_yuv420.compressImage(planes, strides, yuv420_bt601_image.width,
-                                         yuv420_bt601_image.height, UHDR_IMG_FMT_12bppYCbCr420,
-                                         quality, icc->getData(), icc->getLength())) {
-    return ERROR_JPEGR_ENCODE_ERROR;
+  if (hdr_intent->w != sdr_intent.w || hdr_intent->h != sdr_intent.h) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "sdr intent resolution %dx%d and hdr intent resolution %dx%d do not match",
+             sdr_intent.w, sdr_intent.h, hdr_intent->w, hdr_intent->h);
+    return status;
   }
 
-  jpegr_compressed_struct jpeg;
-  jpeg.data = jpeg_enc_obj_yuv420.getCompressedImagePtr();
-  jpeg.length = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
-  jpeg.maxLength = static_cast<int>(jpeg_enc_obj_yuv420.getCompressedImageSize());
-  jpeg.colorGamut = yuv420_image.colorGamut;
+  // generate gain map
+  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
+  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
+  UHDR_ERR_CHECK(
+      generateGainMap(&sdr_intent, hdr_intent, &metadata, gainmap, true /* sdr_is_601 */));
 
-  // append gain map, no ICC since JPEG encode already did it
-  JPEGR_CHECK(appendGainMap(&jpeg, &compressed_map, exif, /* icc */ nullptr, /* icc size */ 0,
-                            &metadata, dest));
-  return JPEGR_NO_ERROR;
-}
-
-/* Encode API-2 */
-status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
-                            jr_uncompressed_ptr yuv420_image_ptr,
-                            jr_compressed_ptr yuv420jpg_image_ptr,
-                            ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest) {
-  // validate input arguments
-  if (yuv420_image_ptr == nullptr) {
-    ALOGE("received nullptr for uncompressed 420 image");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
-    ALOGE("received nullptr for compressed jpeg image");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest))
-
-  // clean up input structure for later usage
-  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
-  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
-  if (!p010_image.chroma_data) {
-    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
-    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
-    p010_image.chroma_stride = p010_image.luma_stride;
-  }
-  jpegr_uncompressed_struct yuv420_image = *yuv420_image_ptr;
-  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
-  if (!yuv420_image.chroma_data) {
-    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
-    yuv420_image.chroma_data = data + yuv420_image.luma_stride * p010_image.height;
-    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
-  }
-
-  // gain map
-  ultrahdr_metadata_struct metadata;
-  metadata.version = kJpegrVersion;
-  jpegr_uncompressed_struct gainmap_image;
-  JPEGR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image));
-  std::unique_ptr<uint8_t[]> map_data;
-  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));
-
-  // compress gain map
-  JpegEncoderHelper jpeg_enc_obj_gm;
-  JPEGR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
-  jpegr_compressed_struct gainmapjpg_image;
-  gainmapjpg_image.data = jpeg_enc_obj_gm.getCompressedImagePtr();
-  gainmapjpg_image.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
-  gainmapjpg_image.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
-  gainmapjpg_image.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-
-  return encodeJPEGR(yuv420jpg_image_ptr, &gainmapjpg_image, &metadata, dest);
-}
-
-/* Encode API-3 */
-status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
-                            jr_compressed_ptr yuv420jpg_image_ptr,
-                            ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest) {
-  // validate input arguments
-  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
-    ALOGE("received nullptr for compressed jpeg image");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, nullptr, hdr_tf, dest))
-
-  // clean up input structure for later usage
-  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
-  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
-  if (!p010_image.chroma_data) {
-    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
-    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
-    p010_image.chroma_stride = p010_image.luma_stride;
-  }
-
-  // decode input jpeg, gamut is going to be bt601.
-  JpegDecoderHelper jpeg_dec_obj_yuv420;
-  if (!jpeg_dec_obj_yuv420.decompressImage(yuv420jpg_image_ptr->data,
-                                           yuv420jpg_image_ptr->length)) {
-    return ERROR_JPEGR_DECODE_ERROR;
-  }
-  jpegr_uncompressed_struct yuv420_image{};
-  yuv420_image.data = jpeg_dec_obj_yuv420.getDecompressedImagePtr();
-  yuv420_image.width = jpeg_dec_obj_yuv420.getDecompressedImageWidth();
-  yuv420_image.height = jpeg_dec_obj_yuv420.getDecompressedImageHeight();
-  if (jpeg_dec_obj_yuv420.getICCSize() > 0) {
-    ultrahdr_color_gamut cg = IccHelper::readIccColorGamut(jpeg_dec_obj_yuv420.getICCPtr(),
-                                                           jpeg_dec_obj_yuv420.getICCSize());
-    if (cg == ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
-        (yuv420jpg_image_ptr->colorGamut != ULTRAHDR_COLORGAMUT_UNSPECIFIED &&
-         yuv420jpg_image_ptr->colorGamut != cg)) {
-      ALOGE("configured color gamut  %d does not match with color gamut specified in icc box %d",
-            yuv420jpg_image_ptr->colorGamut, cg);
-      return ERROR_JPEGR_INVALID_COLORGAMUT;
-    }
-    yuv420_image.colorGamut = cg;
-  } else {
-    if (yuv420jpg_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
-        yuv420jpg_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
-      ALOGE("Unrecognized 420 color gamut %d", yuv420jpg_image_ptr->colorGamut);
-      return ERROR_JPEGR_INVALID_COLORGAMUT;
-    }
-    yuv420_image.colorGamut = yuv420jpg_image_ptr->colorGamut;
-  }
-  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
-  if (!yuv420_image.chroma_data) {
-    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
-    yuv420_image.chroma_data = data + yuv420_image.luma_stride * p010_image.height;
-    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
-  }
-
-  if (p010_image_ptr->width != yuv420_image.width ||
-      p010_image_ptr->height != yuv420_image.height) {
-    return ERROR_JPEGR_RESOLUTION_MISMATCH;
-  }
-
-  // gain map
-  ultrahdr_metadata_struct metadata;
-  metadata.version = kJpegrVersion;
-  jpegr_uncompressed_struct gainmap_image;
-  JPEGR_CHECK(generateGainMap(&yuv420_image, &p010_image, hdr_tf, &metadata, &gainmap_image,
-                              true /* sdr_is_601 */));
-  std::unique_ptr<uint8_t[]> map_data;
-  map_data.reset(reinterpret_cast<uint8_t*>(gainmap_image.data));
-
-  // compress gain map
-  JpegEncoderHelper jpeg_enc_obj_gm;
-  JPEGR_CHECK(compressGainMap(&gainmap_image, &jpeg_enc_obj_gm));
-  jpegr_compressed_struct gainmapjpg_image;
-  gainmapjpg_image.data = jpeg_enc_obj_gm.getCompressedImagePtr();
-  gainmapjpg_image.length = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
-  gainmapjpg_image.maxLength = static_cast<int>(jpeg_enc_obj_gm.getCompressedImageSize());
-  gainmapjpg_image.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-
-  return encodeJPEGR(yuv420jpg_image_ptr, &gainmapjpg_image, &metadata, dest);
+  // compress gain map
+  JpegEncoderHelper jpeg_enc_obj_gm;
+  UHDR_ERR_CHECK(compressGainMap(gainmap.get(), &jpeg_enc_obj_gm));
+  uhdr_compressed_image_t gainmap_compressed = jpeg_enc_obj_gm.getCompressedImage();
+
+  return encodeJPEGR(sdr_intent_compressed, &gainmap_compressed, &metadata, dest);
 }
 
 /* Encode API-4 */
-status_t JpegR::encodeJPEGR(jr_compressed_ptr yuv420jpg_image_ptr,
-                            jr_compressed_ptr gainmapjpg_image_ptr, ultrahdr_metadata_ptr metadata,
-                            jr_compressed_ptr dest) {
-  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
-    ALOGE("received nullptr for compressed jpeg image");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (gainmapjpg_image_ptr == nullptr || gainmapjpg_image_ptr->data == nullptr) {
-    ALOGE("received nullptr for compressed gain map");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (dest == nullptr || dest->data == nullptr) {
-    ALOGE("received nullptr for destination");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-
+uhdr_error_info_t JpegR::encodeJPEGR(uhdr_compressed_image_t* base_img_compressed,
+                                     uhdr_compressed_image_t* gainmap_img_compressed,
+                                     uhdr_gainmap_metadata_ext_t* metadata,
+                                     uhdr_compressed_image_t* dest) {
   // We just want to check if ICC is present, so don't do a full decode. Note,
   // this doesn't verify that the ICC is valid.
   JpegDecoderHelper decoder;
-  if (!decoder.parseImage(yuv420jpg_image_ptr->data, yuv420jpg_image_ptr->length)) {
-    return ERROR_JPEGR_DECODE_ERROR;
-  }
+  UHDR_ERR_CHECK(decoder.parseImage(base_img_compressed->data, base_img_compressed->data_sz));
 
   // Add ICC if not already present.
   if (decoder.getICCSize() > 0) {
-    JPEGR_CHECK(appendGainMap(yuv420jpg_image_ptr, gainmapjpg_image_ptr, /* exif */ nullptr,
-                              /* icc */ nullptr, /* icc size */ 0, metadata, dest));
+    UHDR_ERR_CHECK(appendGainMap(base_img_compressed, gainmap_img_compressed, /* exif */ nullptr,
+                                 /* icc */ nullptr, /* icc size */ 0, metadata, dest));
   } else {
-    if (yuv420jpg_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
-        yuv420jpg_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
-      ALOGE("Unrecognized 420 color gamut %d", yuv420jpg_image_ptr->colorGamut);
-      return ERROR_JPEGR_INVALID_COLORGAMUT;
+    if (base_img_compressed->cg <= UHDR_CG_UNSPECIFIED ||
+        base_img_compressed->cg > UHDR_CG_BT_2100) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "Unrecognized 420 color gamut %d",
+               base_img_compressed->cg);
+      return status;
     }
     std::shared_ptr<DataStruct> newIcc =
-        IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, yuv420jpg_image_ptr->colorGamut);
-    JPEGR_CHECK(appendGainMap(yuv420jpg_image_ptr, gainmapjpg_image_ptr, /* exif */ nullptr,
-                              newIcc->getData(), newIcc->getLength(), metadata, dest));
+        IccHelper::writeIccProfile(UHDR_CT_SRGB, base_img_compressed->cg);
+    UHDR_ERR_CHECK(appendGainMap(base_img_compressed, gainmap_img_compressed, /* exif */ nullptr,
+                                 newIcc->getData(), newIcc->getLength(), metadata, dest));
   }
 
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
-status_t JpegR::getJPEGRInfo(jr_compressed_ptr jpegr_image_ptr, jr_info_ptr jpegr_image_info_ptr) {
-  if (jpegr_image_ptr == nullptr || jpegr_image_ptr->data == nullptr) {
-    ALOGE("received nullptr for compressed jpegr image");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (jpegr_image_info_ptr == nullptr) {
-    ALOGE("received nullptr for compressed jpegr info struct");
-    return ERROR_JPEGR_BAD_PTR;
-  }
+uhdr_error_info_t JpegR::convertYuv(uhdr_raw_image_t* image, uhdr_color_gamut_t src_encoding,
+                                    uhdr_color_gamut_t dst_encoding) {
+  const std::array<float, 9>* coeffs_ptr = nullptr;
+  uhdr_error_info_t status = g_no_error;
 
-  jpegr_compressed_struct primary_image, gainmap_image;
-  JPEGR_CHECK(extractPrimaryImageAndGainMap(jpegr_image_ptr, &primary_image, &gainmap_image))
+  switch (src_encoding) {
+    case UHDR_CG_BT_709:
+      switch (dst_encoding) {
+        case UHDR_CG_BT_709:
+          return status;
+        case UHDR_CG_DISPLAY_P3:
+          coeffs_ptr = &kYuvBt709ToBt601;
+          break;
+        case UHDR_CG_BT_2100:
+          coeffs_ptr = &kYuvBt709ToBt2100;
+          break;
+        default:
+          status.error_code = UHDR_CODEC_INVALID_PARAM;
+          status.has_detail = 1;
+          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
+                   dst_encoding);
+          return status;
+      }
+      break;
+    case UHDR_CG_DISPLAY_P3:
+      switch (dst_encoding) {
+        case UHDR_CG_BT_709:
+          coeffs_ptr = &kYuvBt601ToBt709;
+          break;
+        case UHDR_CG_DISPLAY_P3:
+          return status;
+        case UHDR_CG_BT_2100:
+          coeffs_ptr = &kYuvBt601ToBt2100;
+          break;
+        default:
+          status.error_code = UHDR_CODEC_INVALID_PARAM;
+          status.has_detail = 1;
+          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
+                   dst_encoding);
+          return status;
+      }
+      break;
+    case UHDR_CG_BT_2100:
+      switch (dst_encoding) {
+        case UHDR_CG_BT_709:
+          coeffs_ptr = &kYuvBt2100ToBt709;
+          break;
+        case UHDR_CG_DISPLAY_P3:
+          coeffs_ptr = &kYuvBt2100ToBt601;
+          break;
+        case UHDR_CG_BT_2100:
+          return status;
+        default:
+          status.error_code = UHDR_CODEC_INVALID_PARAM;
+          status.has_detail = 1;
+          snprintf(status.detail, sizeof status.detail, "Unrecognized dest color gamut %d",
+                   dst_encoding);
+          return status;
+      }
+      break;
+    default:
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "Unrecognized src color gamut %d",
+               src_encoding);
+      return status;
+  }
 
-  JPEGR_CHECK(parseJpegInfo(&primary_image, jpegr_image_info_ptr->primaryImgInfo,
-                            &jpegr_image_info_ptr->width, &jpegr_image_info_ptr->height))
-  if (jpegr_image_info_ptr->gainmapImgInfo != nullptr) {
-    JPEGR_CHECK(parseJpegInfo(&gainmap_image, jpegr_image_info_ptr->gainmapImgInfo))
+  if (image->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+    transformYuv420(image, *coeffs_ptr);
+  } else if (image->fmt == UHDR_IMG_FMT_24bppYCbCr444) {
+    transformYuv444(image, *coeffs_ptr);
+  } else {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for performing gamut conversion for color format %d",
+             image->fmt);
+    return status;
   }
 
-  return JPEGR_NO_ERROR;
+  return status;
 }
 
-/* Decode API */
-status_t JpegR::decodeJPEGR(jr_compressed_ptr jpegr_image_ptr, jr_uncompressed_ptr dest,
-                            float max_display_boost, jr_exif_ptr exif,
-                            ultrahdr_output_format output_format,
-                            jr_uncompressed_ptr gainmap_image_ptr, ultrahdr_metadata_ptr metadata) {
-  if (jpegr_image_ptr == nullptr || jpegr_image_ptr->data == nullptr) {
-    ALOGE("received nullptr for compressed jpegr image");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (dest == nullptr || dest->data == nullptr) {
-    ALOGE("received nullptr for dest image");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (max_display_boost < 1.0f) {
-    ALOGE("received bad value for max_display_boost %f", max_display_boost);
-    return ERROR_JPEGR_INVALID_DISPLAY_BOOST;
-  }
-  if (exif != nullptr && exif->data == nullptr) {
-    ALOGE("received nullptr address for exif data");
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (gainmap_image_ptr != nullptr && gainmap_image_ptr->data == nullptr) {
-    ALOGE("received nullptr address for gainmap data");
-    return ERROR_JPEGR_BAD_PTR;
+uhdr_error_info_t JpegR::compressGainMap(uhdr_raw_image_t* gainmap_img,
+                                         JpegEncoderHelper* jpeg_enc_obj) {
+  return jpeg_enc_obj->compressImage(gainmap_img, mMapCompressQuality, nullptr, 0);
+}
+
+uhdr_error_info_t JpegR::generateGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* hdr_intent,
+                                         uhdr_gainmap_metadata_ext_t* gainmap_metadata,
+                                         std::unique_ptr<uhdr_raw_image_ext_t>& gainmap_img,
+                                         bool sdr_is_601, bool use_luminance) {
+  uhdr_error_info_t status = g_no_error;
+
+  if (sdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCr444 &&
+      sdr_intent->fmt != UHDR_IMG_FMT_16bppYCbCr422 &&
+      sdr_intent->fmt != UHDR_IMG_FMT_12bppYCbCr420 &&
+      sdr_intent->fmt != UHDR_IMG_FMT_32bppRGBA8888) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "generate gainmap method expects sdr intent color format to be one of "
+             "{UHDR_IMG_FMT_24bppYCbCr444, UHDR_IMG_FMT_16bppYCbCr422, "
+             "UHDR_IMG_FMT_12bppYCbCr420, UHDR_IMG_FMT_32bppRGBA8888}. Received %d",
+             sdr_intent->fmt);
+    return status;
+  }
+  if (hdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCrP010 &&
+      hdr_intent->fmt != UHDR_IMG_FMT_30bppYCbCr444 &&
+      hdr_intent->fmt != UHDR_IMG_FMT_32bppRGBA1010102) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "generate gainmap method expects hdr intent color format to be one of "
+             "{UHDR_IMG_FMT_24bppYCbCrP010, UHDR_IMG_FMT_30bppYCbCr444, "
+             "UHDR_IMG_FMT_32bppRGBA1010102}. Received %d",
+             hdr_intent->fmt);
+    return status;
+  }
+
+  /*if (mUseMultiChannelGainMap) {
+    if (!kWriteIso21496_1Metadata || kWriteXmpMetadata) {
+      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "Multi-channel gain map is only supported for ISO 21496-1 metadata");
+      return status;
+    }
+  }*/
+
+  ColorTransformFn hdrInvOetf = getInverseOetfFn(hdr_intent->ct);
+  if (hdrInvOetf == nullptr) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for converting transfer characteristics %d to linear",
+             hdr_intent->ct);
+    return status;
+  }
+
+  float hdr_white_nits = getMaxDisplayMasteringLuminance(hdr_intent->ct);
+  if (hdr_white_nits == -1.0f) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "Did not receive valid MDML for display with transfer characteristics %d",
+             hdr_intent->ct);
+    return status;
+  }
+
+  ColorTransformFn hdrGamutConversionFn = getGamutConversionFn(sdr_intent->cg, hdr_intent->cg);
+  if (hdrGamutConversionFn == nullptr) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for gamut conversion from %d to %d", hdr_intent->cg,
+             sdr_intent->cg);
+    return status;
+  }
+
+  ColorTransformFn sdrYuvToRgbFn = getYuvToRgbFn(sdr_intent->cg);
+  if (sdrYuvToRgbFn == nullptr) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for converting yuv to rgb for color gamut %d",
+             sdr_intent->cg);
+    return status;
+  }
+
+  ColorTransformFn hdrYuvToRgbFn = getYuvToRgbFn(hdr_intent->cg);
+  if (hdrYuvToRgbFn == nullptr) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for converting yuv to rgb for color gamut %d",
+             hdr_intent->cg);
+    return status;
+  }
+
+  ColorCalculationFn luminanceFn = getLuminanceFn(sdr_intent->cg);
+  if (luminanceFn == nullptr) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for computing luminance for color gamut %d",
+             sdr_intent->cg);
+    return status;
+  }
+
+  SamplePixelFn sdr_sample_pixel_fn = getSamplePixelFn(sdr_intent->fmt);
+  if (sdr_sample_pixel_fn == nullptr) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for reading pixels for color format %d", sdr_intent->fmt);
+    return status;
+  }
+
+  SamplePixelFn hdr_sample_pixel_fn = getSamplePixelFn(hdr_intent->fmt);
+  if (hdr_sample_pixel_fn == nullptr) {
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for reading pixels for color format %d", hdr_intent->fmt);
+    return status;
   }
-  if (output_format <= ULTRAHDR_OUTPUT_UNSPECIFIED || output_format > ULTRAHDR_OUTPUT_MAX) {
-    ALOGE("received bad value for output format %d", output_format);
-    return ERROR_JPEGR_INVALID_OUTPUT_FORMAT;
+
+  if (sdr_is_601) {
+    sdrYuvToRgbFn = p3YuvToRgb;
   }
 
-  jpegr_compressed_struct primary_jpeg_image, gainmap_jpeg_image;
-  JPEGR_CHECK(
-      extractPrimaryImageAndGainMap(jpegr_image_ptr, &primary_jpeg_image, &gainmap_jpeg_image))
+  size_t image_width = sdr_intent->w;
+  size_t image_height = sdr_intent->h;
+  size_t map_width = image_width / mMapDimensionScaleFactor;
+  size_t map_height = image_height / mMapDimensionScaleFactor;
+  if (map_width == 0 || map_height == 0) {
+    int scaleFactor = (std::min)(image_width, image_height);
+    scaleFactor = (scaleFactor >= DCTSIZE) ? (scaleFactor / DCTSIZE) : 1;
+    ALOGW(
+        "configured gainmap scale factor is resulting in gainmap width and/or height to be zero, "
+        "image width %d, image height %d, scale factor %d. Modifying gainmap scale factor to %d ",
+        (int)image_width, (int)image_height, (int)mMapDimensionScaleFactor, scaleFactor);
+    setMapDimensionScaleFactor(scaleFactor);
+    map_width = image_width / mMapDimensionScaleFactor;
+    map_height = image_height / mMapDimensionScaleFactor;
+  }
+
+  gainmap_img = std::make_unique<uhdr_raw_image_ext_t>(
+      mUseMultiChannelGainMap ? UHDR_IMG_FMT_24bppRGB888 : UHDR_IMG_FMT_8bppYCbCr400,
+      UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, map_width, map_height, 64);
+  uhdr_raw_image_ext_t* dest = gainmap_img.get();
+
+  auto generateGainMapOnePass = [this, sdr_intent, hdr_intent, gainmap_metadata, dest, map_height,
+                                 hdrInvOetf, hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn,
+                                 hdrYuvToRgbFn, sdr_sample_pixel_fn, hdr_sample_pixel_fn,
+                                 hdr_white_nits, use_luminance]() -> void {
+    gainmap_metadata->max_content_boost = hdr_white_nits / kSdrWhiteNits;
+    gainmap_metadata->min_content_boost = 1.0f;
+    gainmap_metadata->gamma = mGamma;
+    gainmap_metadata->offset_sdr = 0.0f;
+    gainmap_metadata->offset_hdr = 0.0f;
+    gainmap_metadata->hdr_capacity_min = 1.0f;
+    gainmap_metadata->hdr_capacity_max = gainmap_metadata->max_content_boost;
+
+    float log2MinBoost = log2(gainmap_metadata->min_content_boost);
+    float log2MaxBoost = log2(gainmap_metadata->max_content_boost);
+
+    const int threads = (std::min)(GetCPUCoreCount(), 4);
+    const int jobSizeInRows = 1;
+    size_t rowStep = threads == 1 ? map_height : jobSizeInRows;
+    JobQueue jobQueue;
+    std::function<void()> generateMap =
+        [this, sdr_intent, hdr_intent, gainmap_metadata, dest, hdrInvOetf, hdrGamutConversionFn,
+         luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn, sdr_sample_pixel_fn, hdr_sample_pixel_fn,
+         hdr_white_nits, log2MinBoost, log2MaxBoost, use_luminance, &jobQueue]() -> void {
+      size_t rowStart, rowEnd;
+      const bool isHdrIntentRgb = isPixelFormatRgb(hdr_intent->fmt);
+      const bool isSdrIntentRgb = isPixelFormatRgb(sdr_intent->fmt);
+      while (jobQueue.dequeueJob(rowStart, rowEnd)) {
+        for (size_t y = rowStart; y < rowEnd; ++y) {
+          for (size_t x = 0; x < dest->w; ++x) {
+            Color sdr_rgb_gamma;
 
-  JpegDecoderHelper jpeg_dec_obj_yuv420;
-  if (!jpeg_dec_obj_yuv420.decompressImage(
-          primary_jpeg_image.data, primary_jpeg_image.length,
-          (output_format == ULTRAHDR_OUTPUT_SDR) ? DECODE_TO_RGB_CS : DECODE_TO_YCBCR_CS)) {
-    return ERROR_JPEGR_DECODE_ERROR;
-  }
+            if (isSdrIntentRgb) {
+              sdr_rgb_gamma = sdr_sample_pixel_fn(sdr_intent, mMapDimensionScaleFactor, x, y);
+            } else {
+              Color sdr_yuv_gamma = sdr_sample_pixel_fn(sdr_intent, mMapDimensionScaleFactor, x, y);
+              sdr_rgb_gamma = sdrYuvToRgbFn(sdr_yuv_gamma);
+            }
 
-  if (output_format == ULTRAHDR_OUTPUT_SDR) {
-#ifdef JCS_ALPHA_EXTENSIONS
-    if ((jpeg_dec_obj_yuv420.getDecompressedImageWidth() *
-         jpeg_dec_obj_yuv420.getDecompressedImageHeight() * 4) >
-        jpeg_dec_obj_yuv420.getDecompressedImageSize()) {
-      return ERROR_JPEGR_DECODE_ERROR;
-    }
+            // We are assuming the SDR input is always sRGB transfer.
+#if USE_SRGB_INVOETF_LUT
+            Color sdr_rgb = srgbInvOetfLUT(sdr_rgb_gamma);
 #else
-    if ((jpeg_dec_obj_yuv420.getDecompressedImageWidth() *
-         jpeg_dec_obj_yuv420.getDecompressedImageHeight() * 3) >
-        jpeg_dec_obj_yuv420.getDecompressedImageSize()) {
-      return ERROR_JPEGR_DECODE_ERROR;
-    }
+            Color sdr_rgb = srgbInvOetf(sdr_rgb_gamma);
 #endif
-  } else {
-    if ((jpeg_dec_obj_yuv420.getDecompressedImageWidth() *
-         jpeg_dec_obj_yuv420.getDecompressedImageHeight() * 3 / 2) >
-        jpeg_dec_obj_yuv420.getDecompressedImageSize()) {
-      return ERROR_JPEGR_DECODE_ERROR;
-    }
-  }
 
-  if (exif != nullptr) {
-    if (exif->length < jpeg_dec_obj_yuv420.getEXIFSize()) {
-      return ERROR_JPEGR_BUFFER_TOO_SMALL;
-    }
-    memcpy(exif->data, jpeg_dec_obj_yuv420.getEXIFPtr(), jpeg_dec_obj_yuv420.getEXIFSize());
-    exif->length = jpeg_dec_obj_yuv420.getEXIFSize();
-  }
+            Color hdr_rgb_gamma;
 
-  JpegDecoderHelper jpeg_dec_obj_gm;
-  jpegr_uncompressed_struct gainmap_image;
-  if (gainmap_image_ptr != nullptr || output_format != ULTRAHDR_OUTPUT_SDR) {
-    if (!jpeg_dec_obj_gm.decompressImage(gainmap_jpeg_image.data, gainmap_jpeg_image.length,
-                                         DECODE_STREAM)) {
-      return ERROR_JPEGR_DECODE_ERROR;
-    }
-    gainmap_image.data = jpeg_dec_obj_gm.getDecompressedImagePtr();
-    gainmap_image.width = jpeg_dec_obj_gm.getDecompressedImageWidth();
-    gainmap_image.height = jpeg_dec_obj_gm.getDecompressedImageHeight();
-    gainmap_image.pixelFormat = jpeg_dec_obj_gm.getDecompressedImageFormat();
-
-    if (gainmap_image_ptr != nullptr) {
-      gainmap_image_ptr->width = gainmap_image.width;
-      gainmap_image_ptr->height = gainmap_image.height;
-      gainmap_image_ptr->pixelFormat = gainmap_image.pixelFormat;
-      memcpy(gainmap_image_ptr->data, gainmap_image.data,
-             gainmap_image_ptr->width * gainmap_image_ptr->height);
-    }
-  }
+            if (isHdrIntentRgb) {
+              hdr_rgb_gamma = hdr_sample_pixel_fn(hdr_intent, mMapDimensionScaleFactor, x, y);
+            } else {
+              Color hdr_yuv_gamma = hdr_sample_pixel_fn(hdr_intent, mMapDimensionScaleFactor, x, y);
+              hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
+            }
+            Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
+            hdr_rgb = hdrGamutConversionFn(hdr_rgb);
 
-  ultrahdr_metadata_struct uhdr_metadata;
-  if (metadata != nullptr || output_format != ULTRAHDR_OUTPUT_SDR) {
-    uint8_t* iso_ptr = static_cast<uint8_t*>(jpeg_dec_obj_gm.getIsoMetadataPtr());
-    if (iso_ptr != nullptr) {
-      size_t iso_size = jpeg_dec_obj_gm.getIsoMetadataSize();
-      if (iso_size < kIsoNameSpace.size() + 1) {
-        return ERROR_JPEGR_METADATA_ERROR;
-      }
-      gain_map_metadata decodedMetadata;
-      std::vector<uint8_t> iso_vec;
-      for (size_t i = kIsoNameSpace.size() + 1; i < iso_size; i++) {
-        iso_vec.push_back(iso_ptr[i]);
+            if (mUseMultiChannelGainMap) {
+              Color sdr_rgb_nits = sdr_rgb * kSdrWhiteNits;
+              Color hdr_rgb_nits = hdr_rgb * hdr_white_nits;
+              size_t pixel_idx = (x + y * dest->stride[UHDR_PLANE_PACKED]) * 3;
+
+              reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] = encodeGain(
+                  sdr_rgb_nits.r, hdr_rgb_nits.r, gainmap_metadata, log2MinBoost, log2MaxBoost);
+              reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx + 1] =
+                  encodeGain(sdr_rgb_nits.g, hdr_rgb_nits.g, gainmap_metadata, log2MinBoost,
+                             log2MaxBoost);
+              reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx + 2] =
+                  encodeGain(sdr_rgb_nits.b, hdr_rgb_nits.b, gainmap_metadata, log2MinBoost,
+                             log2MaxBoost);
+            } else {
+              float sdr_y_nits;
+              float hdr_y_nits;
+              if (use_luminance) {
+                sdr_y_nits = luminanceFn(sdr_rgb) * kSdrWhiteNits;
+                hdr_y_nits = luminanceFn(hdr_rgb) * hdr_white_nits;
+              } else {
+                sdr_y_nits = fmax(sdr_rgb.r, fmax(sdr_rgb.g, sdr_rgb.b)) * kSdrWhiteNits;
+                hdr_y_nits = fmax(hdr_rgb.r, fmax(hdr_rgb.g, hdr_rgb.b)) * hdr_white_nits;
+              }
+
+              size_t pixel_idx = x + y * dest->stride[UHDR_PLANE_Y];
+
+              reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_Y])[pixel_idx] =
+                  encodeGain(sdr_y_nits, hdr_y_nits, gainmap_metadata, log2MinBoost, log2MaxBoost);
+            }
+          }
+        }
       }
+    };
 
-      JPEGR_CHECK(gain_map_metadata::decodeGainmapMetadata(iso_vec, &decodedMetadata));
-      JPEGR_CHECK(
-          gain_map_metadata::gainmapMetadataFractionToFloat(&decodedMetadata, &uhdr_metadata));
-    } else {
-      if (!getMetadataFromXMP(static_cast<uint8_t*>(jpeg_dec_obj_gm.getXMPPtr()),
-                              jpeg_dec_obj_gm.getXMPSize(), &uhdr_metadata)) {
-        return ERROR_JPEGR_METADATA_ERROR;
-      }
+    // generate map
+    std::vector<std::thread> workers;
+    for (int th = 0; th < threads - 1; th++) {
+      workers.push_back(std::thread(generateMap));
     }
-    if (metadata != nullptr) {
-      metadata->version = uhdr_metadata.version;
-      metadata->minContentBoost = uhdr_metadata.minContentBoost;
-      metadata->maxContentBoost = uhdr_metadata.maxContentBoost;
-      metadata->gamma = uhdr_metadata.gamma;
-      metadata->offsetSdr = uhdr_metadata.offsetSdr;
-      metadata->offsetHdr = uhdr_metadata.offsetHdr;
-      metadata->hdrCapacityMin = uhdr_metadata.hdrCapacityMin;
-      metadata->hdrCapacityMax = uhdr_metadata.hdrCapacityMax;
+
+    for (size_t rowStart = 0; rowStart < map_height;) {
+      size_t rowEnd = (std::min)(rowStart + rowStep, map_height);
+      jobQueue.enqueueJob(rowStart, rowEnd);
+      rowStart = rowEnd;
     }
-  }
+    jobQueue.markQueueForEnd();
+    generateMap();
+    std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
+  };
+
+  auto generateGainMapTwoPass = [this, sdr_intent, hdr_intent, gainmap_metadata, dest, map_width,
+                                 map_height, hdrInvOetf, hdrGamutConversionFn, luminanceFn,
+                                 sdrYuvToRgbFn, hdrYuvToRgbFn, sdr_sample_pixel_fn,
+                                 hdr_sample_pixel_fn, hdr_white_nits, use_luminance]() -> void {
+    uhdr_memory_block_t gainmap_mem(map_width * map_height * sizeof(float) *
+                                    (mUseMultiChannelGainMap ? 3 : 1));
+    float* gainmap_data = reinterpret_cast<float*>(gainmap_mem.m_buffer.get());
+    float gainmap_min[3] = {127.0f, 127.0f, 127.0f};
+    float gainmap_max[3] = {-128.0f, -128.0f, -128.0f};
+    std::mutex gainmap_minmax;
+
+    const int threads = (std::min)(GetCPUCoreCount(), 4);
+    const int jobSizeInRows = 1;
+    size_t rowStep = threads == 1 ? map_height : jobSizeInRows;
+    JobQueue jobQueue;
+    std::function<void()> generateMap =
+        [this, sdr_intent, hdr_intent, gainmap_data, map_width, hdrInvOetf, hdrGamutConversionFn,
+         luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn, sdr_sample_pixel_fn, hdr_sample_pixel_fn,
+         hdr_white_nits, use_luminance, &gainmap_min, &gainmap_max, &gainmap_minmax,
+         &jobQueue]() -> void {
+      size_t rowStart, rowEnd;
+      const bool isHdrIntentRgb = isPixelFormatRgb(hdr_intent->fmt);
+      const bool isSdrIntentRgb = isPixelFormatRgb(sdr_intent->fmt);
+      float gainmap_min_th[3] = {127.0f, 127.0f, 127.0f};
+      float gainmap_max_th[3] = {-128.0f, -128.0f, -128.0f};
+
+      while (jobQueue.dequeueJob(rowStart, rowEnd)) {
+        for (size_t y = rowStart; y < rowEnd; ++y) {
+          for (size_t x = 0; x < map_width; ++x) {
+            Color sdr_rgb_gamma;
 
-  if (output_format == ULTRAHDR_OUTPUT_SDR) {
-    dest->width = jpeg_dec_obj_yuv420.getDecompressedImageWidth();
-    dest->height = jpeg_dec_obj_yuv420.getDecompressedImageHeight();
-#ifdef JCS_ALPHA_EXTENSIONS
-    memcpy(dest->data, jpeg_dec_obj_yuv420.getDecompressedImagePtr(),
-           dest->width * dest->height * 4);
+            if (isSdrIntentRgb) {
+              sdr_rgb_gamma = sdr_sample_pixel_fn(sdr_intent, mMapDimensionScaleFactor, x, y);
+            } else {
+              Color sdr_yuv_gamma = sdr_sample_pixel_fn(sdr_intent, mMapDimensionScaleFactor, x, y);
+              sdr_rgb_gamma = sdrYuvToRgbFn(sdr_yuv_gamma);
+            }
+
+            // We are assuming the SDR input is always sRGB transfer.
+#if USE_SRGB_INVOETF_LUT
+            Color sdr_rgb = srgbInvOetfLUT(sdr_rgb_gamma);
 #else
-    uint32_t* pixelDst = static_cast<uint32_t*>(dest->data);
-    uint8_t* pixelSrc = static_cast<uint8_t*>(jpeg_dec_obj_yuv420.getDecompressedImagePtr());
-    for (int i = 0; i < dest->width * dest->height; i++) {
-      *pixelDst = pixelSrc[0] | (pixelSrc[1] << 8) | (pixelSrc[2] << 16) | (0xff << 24);
-      pixelSrc += 3;
-      pixelDst += 1;
-    }
+            Color sdr_rgb = srgbInvOetf(sdr_rgb_gamma);
 #endif
-    dest->colorGamut = IccHelper::readIccColorGamut(jpeg_dec_obj_yuv420.getICCPtr(),
-                                                    jpeg_dec_obj_yuv420.getICCSize());
-    return JPEGR_NO_ERROR;
-  }
 
-  jpegr_uncompressed_struct yuv420_image;
-  yuv420_image.data = jpeg_dec_obj_yuv420.getDecompressedImagePtr();
-  yuv420_image.width = jpeg_dec_obj_yuv420.getDecompressedImageWidth();
-  yuv420_image.height = jpeg_dec_obj_yuv420.getDecompressedImageHeight();
-  yuv420_image.colorGamut = IccHelper::readIccColorGamut(jpeg_dec_obj_yuv420.getICCPtr(),
-                                                         jpeg_dec_obj_yuv420.getICCSize());
-  yuv420_image.luma_stride = yuv420_image.width;
-  uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
-  yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;
-  yuv420_image.chroma_stride = yuv420_image.width >> 1;
+            Color hdr_rgb_gamma;
 
-  JPEGR_CHECK(applyGainMap(&yuv420_image, &gainmap_image, &uhdr_metadata, output_format,
-                           max_display_boost, dest));
-  return JPEGR_NO_ERROR;
-}
+            if (isHdrIntentRgb) {
+              hdr_rgb_gamma = hdr_sample_pixel_fn(hdr_intent, mMapDimensionScaleFactor, x, y);
+            } else {
+              Color hdr_yuv_gamma = hdr_sample_pixel_fn(hdr_intent, mMapDimensionScaleFactor, x, y);
+              hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
+            }
+            Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
+            hdr_rgb = hdrGamutConversionFn(hdr_rgb);
 
-status_t JpegR::compressGainMap(jr_uncompressed_ptr gainmap_image_ptr,
-                                JpegEncoderHelper* jpeg_enc_obj_ptr) {
-  if (gainmap_image_ptr == nullptr || jpeg_enc_obj_ptr == nullptr) {
-    return ERROR_JPEGR_BAD_PTR;
-  }
+            if (mUseMultiChannelGainMap) {
+              Color sdr_rgb_nits = sdr_rgb * kSdrWhiteNits;
+              Color hdr_rgb_nits = hdr_rgb * hdr_white_nits;
+              size_t pixel_idx = (x + y * map_width) * 3;
+
+              gainmap_data[pixel_idx] = computeGain(sdr_rgb_nits.r, hdr_rgb_nits.r);
+              gainmap_data[pixel_idx + 1] = computeGain(sdr_rgb_nits.g, hdr_rgb_nits.g);
+              gainmap_data[pixel_idx + 2] = computeGain(sdr_rgb_nits.b, hdr_rgb_nits.b);
+              for (int i = 0; i < 3; i++) {
+                gainmap_min_th[i] = (std::min)(gainmap_data[pixel_idx + i], gainmap_min_th[i]);
+                gainmap_max_th[i] = (std::max)(gainmap_data[pixel_idx + i], gainmap_max_th[i]);
+              }
+            } else {
+              float sdr_y_nits;
+              float hdr_y_nits;
+
+              if (use_luminance) {
+                sdr_y_nits = luminanceFn(sdr_rgb) * kSdrWhiteNits;
+                hdr_y_nits = luminanceFn(hdr_rgb) * hdr_white_nits;
+              } else {
+                sdr_y_nits = fmax(sdr_rgb.r, fmax(sdr_rgb.g, sdr_rgb.b)) * kSdrWhiteNits;
+                hdr_y_nits = fmax(hdr_rgb.r, fmax(hdr_rgb.g, hdr_rgb.b)) * hdr_white_nits;
+              }
+
+              size_t pixel_idx = x + y * map_width;
+              gainmap_data[pixel_idx] = computeGain(sdr_y_nits, hdr_y_nits);
+              gainmap_min_th[0] = (std::min)(gainmap_data[pixel_idx], gainmap_min_th[0]);
+              gainmap_max_th[0] = (std::max)(gainmap_data[pixel_idx], gainmap_max_th[0]);
+            }
+          }
+        }
+      }
+      {
+        std::unique_lock<std::mutex> lock{gainmap_minmax};
+        for (int index = 0; index < (mUseMultiChannelGainMap ? 3 : 1); index++) {
+          gainmap_min[index] = (std::min)(gainmap_min[index], gainmap_min_th[index]);
+          gainmap_max[index] = (std::max)(gainmap_max[index], gainmap_max_th[index]);
+        }
+      }
+    };
 
-  const uint8_t* planes[]{reinterpret_cast<uint8_t*>(gainmap_image_ptr->data)};
-  if (kUseMultiChannelGainMap) {
-    const size_t strides[]{gainmap_image_ptr->width * 3};
-    if (!jpeg_enc_obj_ptr->compressImage(planes, strides, gainmap_image_ptr->width,
-                                         gainmap_image_ptr->height, UHDR_IMG_FMT_24bppRGB888,
-                                         kMapCompressQuality, nullptr, 0)) {
-      return ERROR_JPEGR_ENCODE_ERROR;
+    // generate map
+    std::vector<std::thread> workers;
+    for (int th = 0; th < threads - 1; th++) {
+      workers.push_back(std::thread(generateMap));
     }
-  } else {
-    const size_t strides[]{gainmap_image_ptr->width};
-    // Don't need to convert YUV to Bt601 since single channel
-    if (!jpeg_enc_obj_ptr->compressImage(planes, strides, gainmap_image_ptr->width,
-                                         gainmap_image_ptr->height, UHDR_IMG_FMT_8bppYCbCr400,
-                                         kMapCompressQuality, nullptr, 0)) {
-      return ERROR_JPEGR_ENCODE_ERROR;
+
+    for (size_t rowStart = 0; rowStart < map_height;) {
+      size_t rowEnd = (std::min)(rowStart + rowStep, map_height);
+      jobQueue.enqueueJob(rowStart, rowEnd);
+      rowStart = rowEnd;
+    }
+    jobQueue.markQueueForEnd();
+    generateMap();
+    std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
+
+    float min_content_boost_log2 = gainmap_min[0];
+    float max_content_boost_log2 = gainmap_max[0];
+    for (int index = 1; index < (mUseMultiChannelGainMap ? 3 : 1); index++) {
+      min_content_boost_log2 = (std::min)(gainmap_min[index], min_content_boost_log2);
+      max_content_boost_log2 = (std::max)(gainmap_max[index], max_content_boost_log2);
+    }
+    // -13.0 emphirically is a small enough gain factor that is capable of representing hdr
+    // black from any sdr luminance. Allowing further excursion might not offer any benefit and on
+    // the downside can cause bigger error during affine map and inverse map.
+    min_content_boost_log2 = (std::max)(-13.0f, min_content_boost_log2);
+    if (this->mMaxContentBoost != FLT_MAX) {
+      float suggestion = log2(this->mMaxContentBoost);
+      max_content_boost_log2 = (std::min)(max_content_boost_log2, suggestion);
+    }
+    if (this->mMinContentBoost != FLT_MIN) {
+      float suggestion = log2(this->mMinContentBoost);
+      min_content_boost_log2 = (std::max)(min_content_boost_log2, suggestion);
+    }
+    if (fabs(max_content_boost_log2 - min_content_boost_log2) < FLT_EPSILON) {
+      max_content_boost_log2 += 0.1;  // to avoid div by zero during affine transform
     }
-  }
 
-  return JPEGR_NO_ERROR;
-}
+    std::function<void()> encodeMap = [this, gainmap_data, map_width, dest, min_content_boost_log2,
+                                       max_content_boost_log2, &jobQueue]() -> void {
+      size_t rowStart, rowEnd;
 
-const int kJobSzInRows = 16;
-static_assert(kJobSzInRows > 0 && kJobSzInRows % kMapDimensionScaleFactor == 0,
-              "align job size to kMapDimensionScaleFactor");
+      while (jobQueue.dequeueJob(rowStart, rowEnd)) {
+        if (mUseMultiChannelGainMap) {
+          for (size_t j = rowStart; j < rowEnd; j++) {
+            size_t dst_pixel_idx = j * dest->stride[UHDR_PLANE_PACKED] * 3;
+            size_t src_pixel_idx = j * map_width * 3;
+            for (size_t i = 0; i < map_width * 3; i++) {
+              reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_PACKED])[dst_pixel_idx + i] =
+                  affineMapGain(gainmap_data[src_pixel_idx + i], min_content_boost_log2,
+                                max_content_boost_log2, this->mGamma);
+            }
+          }
+        } else {
+          for (size_t j = rowStart; j < rowEnd; j++) {
+            size_t dst_pixel_idx = j * dest->stride[UHDR_PLANE_Y];
+            size_t src_pixel_idx = j * map_width;
+            for (size_t i = 0; i < map_width; i++) {
+              reinterpret_cast<uint8_t*>(dest->planes[UHDR_PLANE_Y])[dst_pixel_idx + i] =
+                  affineMapGain(gainmap_data[src_pixel_idx + i], min_content_boost_log2,
+                                max_content_boost_log2, this->mGamma);
+            }
+          }
+        }
+      }
+    };
+    workers.clear();
+    jobQueue.reset();
+    rowStep = threads == 1 ? map_height : 1;
+    for (int th = 0; th < threads - 1; th++) {
+      workers.push_back(std::thread(encodeMap));
+    }
+    for (size_t rowStart = 0; rowStart < map_height;) {
+      size_t rowEnd = (std::min)(rowStart + rowStep, map_height);
+      jobQueue.enqueueJob(rowStart, rowEnd);
+      rowStart = rowEnd;
+    }
+    jobQueue.markQueueForEnd();
+    encodeMap();
+    std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
+
+    gainmap_metadata->max_content_boost = exp2(max_content_boost_log2);
+    gainmap_metadata->min_content_boost = exp2(min_content_boost_log2);
+    gainmap_metadata->gamma = this->mGamma;
+    gainmap_metadata->offset_sdr = 0.0f;
+    gainmap_metadata->offset_hdr = 0.0f;
+    gainmap_metadata->hdr_capacity_min = 1.0f;
+    gainmap_metadata->hdr_capacity_max = hdr_white_nits / kSdrWhiteNits;
+  };
 
-class JobQueue {
- public:
-  bool dequeueJob(size_t& rowStart, size_t& rowEnd);
-  void enqueueJob(size_t rowStart, size_t rowEnd);
-  void markQueueForEnd();
-  void reset();
-
- private:
-  bool mQueuedAllJobs = false;
-  std::deque<std::tuple<size_t, size_t>> mJobs;
-  std::mutex mMutex;
-  std::condition_variable mCv;
-};
-
-bool JobQueue::dequeueJob(size_t& rowStart, size_t& rowEnd) {
-  std::unique_lock<std::mutex> lock{mMutex};
-  while (true) {
-    if (mJobs.empty()) {
-      if (mQueuedAllJobs) {
-        return false;
-      } else {
-        mCv.wait_for(lock, std::chrono::milliseconds(100));
-      }
-    } else {
-      auto it = mJobs.begin();
-      rowStart = std::get<0>(*it);
-      rowEnd = std::get<1>(*it);
-      mJobs.erase(it);
-      return true;
-    }
+  if (mEncPreset == UHDR_USAGE_REALTIME) {
+    generateGainMapOnePass();
+  } else {
+    generateGainMapTwoPass();
   }
-  return false;
-}
 
-void JobQueue::enqueueJob(size_t rowStart, size_t rowEnd) {
-  std::unique_lock<std::mutex> lock{mMutex};
-  mJobs.push_back(std::make_tuple(rowStart, rowEnd));
-  lock.unlock();
-  mCv.notify_one();
+  return status;
 }
 
-void JobQueue::markQueueForEnd() {
-  std::unique_lock<std::mutex> lock{mMutex};
-  mQueuedAllJobs = true;
-  lock.unlock();
-  mCv.notify_all();
-}
+// JPEG/R structure:
+// SOI (ff d8)
+//
+// (Optional, if EXIF package is from outside (Encode API-0 API-1), or if EXIF package presents
+// in the JPEG input (Encode API-2, API-3, API-4))
+// APP1 (ff e1)
+// 2 bytes of length (2 + length of exif package)
+// EXIF package (this includes the first two bytes representing the package length)
+//
+// (Required, XMP package) APP1 (ff e1)
+// 2 bytes of length (2 + 29 + length of xmp package)
+// name space ("http://ns.adobe.com/xap/1.0/\0")
+// XMP
+//
+// (Required, ISO 21496-1 metadata, version only) APP2 (ff e2)
+// 2 bytes of length
+// name space (""urn:iso:std:iso:ts:21496:-1\0")
+// 2 bytes minimum_version: (00 00)
+// 2 bytes writer_version: (00 00)
+//
+// (Required, MPF package) APP2 (ff e2)
+// 2 bytes of length
+// MPF
+//
+// (Required) primary image (without the first two bytes (SOI) and EXIF, may have other packages)
+//
+// SOI (ff d8)
+//
+// (Required, XMP package) APP1 (ff e1)
+// 2 bytes of length (2 + 29 + length of xmp package)
+// name space ("http://ns.adobe.com/xap/1.0/\0")
+// XMP
+//
+// (Required, ISO 21496-1 metadata) APP2 (ff e2)
+// 2 bytes of length
+// name space (""urn:iso:std:iso:ts:21496:-1\0")
+// metadata
+//
+// (Required) secondary image (the gain map, without the first two bytes (SOI))
+//
+// Metadata versions we are using:
+// ECMA TR-98 for JFIF marker
+// Exif 2.2 spec for EXIF marker
+// Adobe XMP spec part 3 for XMP marker
+// ICC v4.3 spec for ICC
+uhdr_error_info_t JpegR::appendGainMap(uhdr_compressed_image_t* sdr_intent_compressed,
+                                       uhdr_compressed_image_t* gainmap_compressed,
+                                       uhdr_mem_block_t* pExif, void* pIcc, size_t icc_size,
+                                       uhdr_gainmap_metadata_ext_t* metadata,
+                                       uhdr_compressed_image_t* dest) {
+  const int xmpNameSpaceLength = kXmpNameSpace.size() + 1;  // need to count the null terminator
+  const int isoNameSpaceLength = kIsoNameSpace.size() + 1;  // need to count the null terminator
 
-void JobQueue::reset() {
-  std::unique_lock<std::mutex> lock{mMutex};
-  mJobs.clear();
-  mQueuedAllJobs = false;
-}
+  /////////////////////////////////////////////////////////////////////////////////////////////////
+  // calculate secondary image length first, because the length will be written into the primary //
+  // image xmp                                                                                   //
+  /////////////////////////////////////////////////////////////////////////////////////////////////
+  // XMP
+  const string xmp_secondary = generateXmpForSecondaryImage(*metadata);
+  // xmp_secondary_length = 2 bytes representing the length of the package +
+  //  + xmpNameSpaceLength = 29 bytes length
+  //  + length of xmp packet = xmp_secondary.size()
+  const int xmp_secondary_length = 2 + xmpNameSpaceLength + xmp_secondary.size();
+  // ISO
+  uhdr_gainmap_metadata_frac iso_secondary_metadata;
+  std::vector<uint8_t> iso_secondary_data;
+  UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(
+      metadata, &iso_secondary_metadata));
 
-status_t JpegR::generateGainMap(jr_uncompressed_ptr yuv420_image_ptr,
-                                jr_uncompressed_ptr p010_image_ptr,
-                                ultrahdr_transfer_function hdr_tf, ultrahdr_metadata_ptr metadata,
-                                jr_uncompressed_ptr dest, bool sdr_is_601) {
-  /*if (kUseMultiChannelGainMap) {
-    static_assert(kWriteIso21496_1Metadata && !kWriteXmpMetadata,
-                  "Multi-channel gain map now is only supported for ISO 21496-1 metadata");
-  }*/
+  UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&iso_secondary_metadata,
+                                                                   iso_secondary_data));
 
-  int gainMapChannelCount = kUseMultiChannelGainMap ? 3 : 1;
+  // iso_secondary_length = 2 bytes representing the length of the package +
+  //  + isoNameSpaceLength = 28 bytes length
+  //  + length of iso metadata packet = iso_secondary_data.size()
+  const int iso_secondary_length = 2 + isoNameSpaceLength + iso_secondary_data.size();
 
-  if (yuv420_image_ptr == nullptr || p010_image_ptr == nullptr || metadata == nullptr ||
-      dest == nullptr || yuv420_image_ptr->data == nullptr ||
-      yuv420_image_ptr->chroma_data == nullptr || p010_image_ptr->data == nullptr ||
-      p010_image_ptr->chroma_data == nullptr) {
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (yuv420_image_ptr->width != p010_image_ptr->width ||
-      yuv420_image_ptr->height != p010_image_ptr->height) {
-    return ERROR_JPEGR_RESOLUTION_MISMATCH;
+  int secondary_image_size = 2 /* 2 bytes length of APP1 sign */ + gainmap_compressed->data_sz;
+  if (kWriteXmpMetadata) {
+    secondary_image_size += xmp_secondary_length;
   }
-  if (yuv420_image_ptr->colorGamut == ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
-      p010_image_ptr->colorGamut == ULTRAHDR_COLORGAMUT_UNSPECIFIED) {
-    return ERROR_JPEGR_INVALID_COLORGAMUT;
+  if (kWriteIso21496_1Metadata) {
+    secondary_image_size += iso_secondary_length;
   }
 
-  size_t image_width = yuv420_image_ptr->width;
-  size_t image_height = yuv420_image_ptr->height;
-  size_t map_width = image_width / kMapDimensionScaleFactor;
-  size_t map_height = image_height / kMapDimensionScaleFactor;
-
-  dest->data = new uint8_t[map_width * map_height * gainMapChannelCount];
-  dest->width = map_width;
-  dest->height = map_height;
-  dest->colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-  dest->luma_stride = map_width;
-  dest->chroma_data = nullptr;
-  dest->chroma_stride = 0;
-  std::unique_ptr<uint8_t[]> map_data;
-  map_data.reset(reinterpret_cast<uint8_t*>(dest->data));
-
-  ColorTransformFn hdrInvOetf = nullptr;
-  float hdr_white_nits;
-  switch (hdr_tf) {
-    case ULTRAHDR_TF_LINEAR:
-      hdrInvOetf = identityConversion;
-      // Note: this will produce clipping if the input exceeds kHlgMaxNits.
-      // TODO: TF LINEAR will be deprecated.
-      hdr_white_nits = kHlgMaxNits;
-      break;
-    case ULTRAHDR_TF_HLG:
-#if USE_HLG_INVOETF_LUT
-      hdrInvOetf = hlgInvOetfLUT;
-#else
-      hdrInvOetf = hlgInvOetf;
-#endif
-      hdr_white_nits = kHlgMaxNits;
-      break;
-    case ULTRAHDR_TF_PQ:
-#if USE_PQ_INVOETF_LUT
-      hdrInvOetf = pqInvOetfLUT;
-#else
-      hdrInvOetf = pqInvOetf;
-#endif
-      hdr_white_nits = kPqMaxNits;
-      break;
-    default:
-      // Should be impossible to hit after input validation.
-      return ERROR_JPEGR_INVALID_TRANS_FUNC;
-  }
-
-  metadata->maxContentBoost = hdr_white_nits / kSdrWhiteNits;
-  metadata->minContentBoost = 1.0f;
-  metadata->gamma = 1.0f;
-  metadata->offsetSdr = 0.0f;
-  metadata->offsetHdr = 0.0f;
-  metadata->hdrCapacityMin = 1.0f;
-  metadata->hdrCapacityMax = metadata->maxContentBoost;
-
-  float log2MinBoost = log2(metadata->minContentBoost);
-  float log2MaxBoost = log2(metadata->maxContentBoost);
-
-  ColorTransformFn hdrGamutConversionFn =
-      getHdrConversionFn(yuv420_image_ptr->colorGamut, p010_image_ptr->colorGamut);
-
-  ColorCalculationFn luminanceFn = nullptr;
-  ColorTransformFn sdrYuvToRgbFn = nullptr;
-  switch (yuv420_image_ptr->colorGamut) {
-    case ULTRAHDR_COLORGAMUT_BT709:
-      luminanceFn = srgbLuminance;
-      sdrYuvToRgbFn = srgbYuvToRgb;
-      break;
-    case ULTRAHDR_COLORGAMUT_P3:
-      luminanceFn = p3Luminance;
-      sdrYuvToRgbFn = p3YuvToRgb;
-      break;
-    case ULTRAHDR_COLORGAMUT_BT2100:
-      luminanceFn = bt2100Luminance;
-      sdrYuvToRgbFn = bt2100YuvToRgb;
-      break;
-    case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
-      // Should be impossible to hit after input validation.
-      return ERROR_JPEGR_INVALID_COLORGAMUT;
-  }
-  if (sdr_is_601) {
-    sdrYuvToRgbFn = p3YuvToRgb;
-  }
+  // Check if EXIF package presents in the JPEG input.
+  // If so, extract and remove the EXIF package.
+  JpegDecoderHelper decoder;
+  UHDR_ERR_CHECK(decoder.parseImage(sdr_intent_compressed->data, sdr_intent_compressed->data_sz));
 
-  ColorTransformFn hdrYuvToRgbFn = nullptr;
-  switch (p010_image_ptr->colorGamut) {
-    case ULTRAHDR_COLORGAMUT_BT709:
-      hdrYuvToRgbFn = srgbYuvToRgb;
-      break;
-    case ULTRAHDR_COLORGAMUT_P3:
-      hdrYuvToRgbFn = p3YuvToRgb;
-      break;
-    case ULTRAHDR_COLORGAMUT_BT2100:
-      hdrYuvToRgbFn = bt2100YuvToRgb;
-      break;
-    case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
-      // Should be impossible to hit after input validation.
-      return ERROR_JPEGR_INVALID_COLORGAMUT;
-  }
+  uhdr_mem_block_t exif_from_jpg;
+  exif_from_jpg.data = nullptr;
+  exif_from_jpg.data_sz = 0;
 
-  const int threads = (std::min)(GetCPUCoreCount(), 4);
-  size_t rowStep = threads == 1 ? image_height : kJobSzInRows;
-  JobQueue jobQueue;
-  std::function<void()> generateMap;
+  uhdr_compressed_image_t new_jpg_image;
+  new_jpg_image.data = nullptr;
+  new_jpg_image.data_sz = 0;
+  new_jpg_image.capacity = 0;
+  new_jpg_image.cg = UHDR_CG_UNSPECIFIED;
+  new_jpg_image.ct = UHDR_CT_UNSPECIFIED;
+  new_jpg_image.range = UHDR_CR_UNSPECIFIED;
 
-  if (kUseMultiChannelGainMap) {
-    generateMap = [yuv420_image_ptr, p010_image_ptr, metadata, dest, hdrInvOetf,
-                   hdrGamutConversionFn, sdrYuvToRgbFn, gainMapChannelCount, hdrYuvToRgbFn,
-                   hdr_white_nits, log2MinBoost, log2MaxBoost, &jobQueue]() -> void {
-      size_t rowStart, rowEnd;
-      while (jobQueue.dequeueJob(rowStart, rowEnd)) {
-        for (size_t y = rowStart; y < rowEnd; ++y) {
-          for (size_t x = 0; x < dest->width; ++x) {
-            Color sdr_yuv_gamma = sampleYuv420(yuv420_image_ptr, kMapDimensionScaleFactor, x, y);
-            Color sdr_rgb_gamma = sdrYuvToRgbFn(sdr_yuv_gamma);
-            // We are assuming the SDR input is always sRGB transfer.
-#if USE_SRGB_INVOETF_LUT
-            Color sdr_rgb = srgbInvOetfLUT(sdr_rgb_gamma);
-#else
-            Color sdr_rgb = srgbInvOetf(sdr_rgb_gamma);
-#endif
-            Color sdr_rgb_nits = sdr_rgb * kSdrWhiteNits;
+  std::unique_ptr<uint8_t[]> dest_data;
+  if (decoder.getEXIFPos() >= 0) {
+    if (pExif != nullptr) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "received exif from uhdr_enc_set_exif_data() while the base image intent already "
+               "contains exif, unsure which one to use");
+      return status;
+    }
+    copyJpegWithoutExif(&new_jpg_image, sdr_intent_compressed, decoder.getEXIFPos(),
+                        decoder.getEXIFSize());
+    dest_data.reset(reinterpret_cast<uint8_t*>(new_jpg_image.data));
+    exif_from_jpg.data = decoder.getEXIFPtr();
+    exif_from_jpg.data_sz = decoder.getEXIFSize();
+    pExif = &exif_from_jpg;
+  }
 
-            Color hdr_yuv_gamma = sampleP010(p010_image_ptr, kMapDimensionScaleFactor, x, y);
-            Color hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
-            Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
-            hdr_rgb = hdrGamutConversionFn(hdr_rgb);
-            Color hdr_rgb_nits = hdr_rgb * hdr_white_nits;
-
-            size_t pixel_idx = (x + y * dest->width) * gainMapChannelCount;
-
-            // R
-            reinterpret_cast<uint8_t*>(dest->data)[pixel_idx] =
-                encodeGain(sdr_rgb_nits.r, hdr_rgb_nits.r, metadata, log2MinBoost, log2MaxBoost);
-            // G
-            reinterpret_cast<uint8_t*>(dest->data)[pixel_idx + 1] =
-                encodeGain(sdr_rgb_nits.g, hdr_rgb_nits.g, metadata, log2MinBoost, log2MaxBoost);
-            // B
-            reinterpret_cast<uint8_t*>(dest->data)[pixel_idx + 2] =
-                encodeGain(sdr_rgb_nits.b, hdr_rgb_nits.b, metadata, log2MinBoost, log2MaxBoost);
-          }
-        }
-      }
-    };
-  } else {
-    generateMap = [yuv420_image_ptr, p010_image_ptr, metadata, dest, hdrInvOetf,
-                   hdrGamutConversionFn, luminanceFn, sdrYuvToRgbFn, hdrYuvToRgbFn, hdr_white_nits,
-                   log2MinBoost, log2MaxBoost, &jobQueue]() -> void {
-      size_t rowStart, rowEnd;
-      while (jobQueue.dequeueJob(rowStart, rowEnd)) {
-        for (size_t y = rowStart; y < rowEnd; ++y) {
-          for (size_t x = 0; x < dest->width; ++x) {
-            Color sdr_yuv_gamma = sampleYuv420(yuv420_image_ptr, kMapDimensionScaleFactor, x, y);
-            Color sdr_rgb_gamma = sdrYuvToRgbFn(sdr_yuv_gamma);
-            // We are assuming the SDR input is always sRGB transfer.
-#if USE_SRGB_INVOETF_LUT
-            Color sdr_rgb = srgbInvOetfLUT(sdr_rgb_gamma);
-#else
-            Color sdr_rgb = srgbInvOetf(sdr_rgb_gamma);
-#endif
-            float sdr_y_nits = luminanceFn(sdr_rgb) * kSdrWhiteNits;
+  uhdr_compressed_image_t* final_primary_jpg_image_ptr =
+      new_jpg_image.data_sz == 0 ? sdr_intent_compressed : &new_jpg_image;
 
-            Color hdr_yuv_gamma = sampleP010(p010_image_ptr, kMapDimensionScaleFactor, x, y);
-            Color hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
-            Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
-            hdr_rgb = hdrGamutConversionFn(hdr_rgb);
-            float hdr_y_nits = luminanceFn(hdr_rgb) * hdr_white_nits;
+  int pos = 0;
+  // Begin primary image
+  // Write SOI
+  UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
+  UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));
 
-            size_t pixel_idx = x + y * dest->width;
-            reinterpret_cast<uint8_t*>(dest->data)[pixel_idx] =
-                encodeGain(sdr_y_nits, hdr_y_nits, metadata, log2MinBoost, log2MaxBoost);
-          }
-        }
-      }
-    };
+  // Write EXIF
+  if (pExif != nullptr) {
+    const int length = 2 + pExif->data_sz;
+    const uint8_t lengthH = ((length >> 8) & 0xff);
+    const uint8_t lengthL = (length & 0xff);
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, pExif->data, pExif->data_sz, pos));
   }
 
-  // generate map
-  std::vector<std::thread> workers;
-  for (int th = 0; th < threads - 1; th++) {
-    workers.push_back(std::thread(generateMap));
+  // Prepare and write XMP
+  if (kWriteXmpMetadata) {
+    const string xmp_primary = generateXmpForPrimaryImage(secondary_image_size, *metadata);
+    const int length = 2 + xmpNameSpaceLength + xmp_primary.size();
+    const uint8_t lengthH = ((length >> 8) & 0xff);
+    const uint8_t lengthL = (length & 0xff);
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, (void*)kXmpNameSpace.c_str(), xmpNameSpaceLength, pos));
+    UHDR_ERR_CHECK(Write(dest, (void*)xmp_primary.c_str(), xmp_primary.size(), pos));
   }
 
-  rowStep = (threads == 1 ? image_height : kJobSzInRows) / kMapDimensionScaleFactor;
-  for (size_t rowStart = 0; rowStart < map_height;) {
-    size_t rowEnd = (std::min)(rowStart + rowStep, map_height);
-    jobQueue.enqueueJob(rowStart, rowEnd);
-    rowStart = rowEnd;
+  // Write ICC
+  if (pIcc != nullptr && icc_size > 0) {
+    const int length = icc_size + 2;
+    const uint8_t lengthH = ((length >> 8) & 0xff);
+    const uint8_t lengthL = (length & 0xff);
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, pIcc, icc_size, pos));
   }
-  jobQueue.markQueueForEnd();
-  generateMap();
-  std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
-
-  map_data.release();
-
-  return JPEGR_NO_ERROR;
-}
 
-status_t JpegR::applyGainMap(jr_uncompressed_ptr yuv420_image_ptr,
-                             jr_uncompressed_ptr gainmap_image_ptr, ultrahdr_metadata_ptr metadata,
-                             ultrahdr_output_format output_format, float max_display_boost,
-                             jr_uncompressed_ptr dest) {
-  if (yuv420_image_ptr == nullptr || gainmap_image_ptr == nullptr || metadata == nullptr ||
-      dest == nullptr || yuv420_image_ptr->data == nullptr ||
-      yuv420_image_ptr->chroma_data == nullptr || gainmap_image_ptr->data == nullptr) {
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (metadata->version.compare(kJpegrVersion)) {
-    ALOGE("Unsupported metadata version: %s", metadata->version.c_str());
-    return ERROR_JPEGR_BAD_METADATA;
-  }
-  if (metadata->gamma != 1.0f) {
-    ALOGE("Unsupported metadata gamma: %f", metadata->gamma);
-    return ERROR_JPEGR_BAD_METADATA;
-  }
-  if (metadata->offsetSdr != 0.0f || metadata->offsetHdr != 0.0f) {
-    ALOGE("Unsupported metadata offset sdr, hdr: %f, %f", metadata->offsetSdr, metadata->offsetHdr);
-    return ERROR_JPEGR_BAD_METADATA;
-  }
-  if (metadata->hdrCapacityMin != metadata->minContentBoost ||
-      metadata->hdrCapacityMax != metadata->maxContentBoost) {
-    ALOGE("Unsupported metadata hdr capacity min, max: %f, %f", metadata->hdrCapacityMin,
-          metadata->hdrCapacityMax);
-    return ERROR_JPEGR_BAD_METADATA;
+  // Prepare and write ISO 21496-1 metadata
+  if (kWriteIso21496_1Metadata) {
+    const int length = 2 + isoNameSpaceLength + 4;
+    uint8_t zero = 0;
+    const uint8_t lengthH = ((length >> 8) & 0xff);
+    const uint8_t lengthL = (length & 0xff);
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, (void*)kIsoNameSpace.c_str(), isoNameSpaceLength, pos));
+    UHDR_ERR_CHECK(Write(dest, &zero, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &zero, 1, pos));  // 2 bytes minimum_version: (00 00)
+    UHDR_ERR_CHECK(Write(dest, &zero, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &zero, 1, pos));  // 2 bytes writer_version: (00 00)
   }
 
+  // Prepare and write MPF
   {
-    float primary_aspect_ratio = (float) yuv420_image_ptr->width / yuv420_image_ptr->height;
-    float gainmap_aspect_ratio = (float) gainmap_image_ptr->width / gainmap_image_ptr->height;
-    float delta_aspect_ratio = fabs(primary_aspect_ratio - gainmap_aspect_ratio);
-    // Allow 1% delta
-    const float delta_tolerance = 0.01;
-    if (delta_aspect_ratio / primary_aspect_ratio > delta_tolerance) {
-      ALOGE(
-          "gain map dimensions scale factor values for height and width are different, \n primary "
-          "image resolution is %zux%zu, received gain map resolution is %zux%zu",
-          yuv420_image_ptr->width, yuv420_image_ptr->height, gainmap_image_ptr->width,
-          gainmap_image_ptr->height);
-      return ERROR_JPEGR_UNSUPPORTED_MAP_SCALE_FACTOR;
-    }
+    const int length = 2 + calculateMpfSize();
+    const uint8_t lengthH = ((length >> 8) & 0xff);
+    const uint8_t lengthL = (length & 0xff);
+    int primary_image_size = pos + length + final_primary_jpg_image_ptr->data_sz;
+    // between APP2 + package size + signature
+    // ff e2 00 58 4d 50 46 00
+    // 2 + 2 + 4 = 8 (bytes)
+    // and ff d8 sign of the secondary image
+    int secondary_image_offset = primary_image_size - pos - 8;
+    std::shared_ptr<DataStruct> mpf = generateMpf(primary_image_size, 0, /* primary_image_offset */
+                                                  secondary_image_size, secondary_image_offset);
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, (void*)mpf->getData(), mpf->getLength(), pos));
   }
 
-  float map_scale_factor = (float) yuv420_image_ptr->width / gainmap_image_ptr->width;
+  // Write primary image
+  UHDR_ERR_CHECK(Write(dest, (uint8_t*)final_primary_jpg_image_ptr->data + 2,
+                       final_primary_jpg_image_ptr->data_sz - 2, pos));
+  // Finish primary image
 
-  dest->width = yuv420_image_ptr->width;
-  dest->height = yuv420_image_ptr->height;
-  dest->colorGamut = yuv420_image_ptr->colorGamut;
-  // Table will only be used when map scale factor is integer.
-  ShepardsIDW idwTable(static_cast<int>(map_scale_factor));
-  float display_boost = (std::min)(max_display_boost, metadata->maxContentBoost);
-  GainLUT gainLUT(metadata, display_boost);
+  // Begin secondary image (gain map)
+  // Write SOI
+  UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
+  UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));
 
-  JobQueue jobQueue;
-  std::function<void()> applyRecMap = [yuv420_image_ptr, gainmap_image_ptr, dest, &jobQueue,
-                                       &idwTable, output_format, &gainLUT, display_boost,
-                                       map_scale_factor]() -> void {
-    size_t width = yuv420_image_ptr->width;
+  // Prepare and write XMP
+  if (kWriteXmpMetadata) {
+    const int length = xmp_secondary_length;
+    const uint8_t lengthH = ((length >> 8) & 0xff);
+    const uint8_t lengthL = (length & 0xff);
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, (void*)kXmpNameSpace.c_str(), xmpNameSpaceLength, pos));
+    UHDR_ERR_CHECK(Write(dest, (void*)xmp_secondary.c_str(), xmp_secondary.size(), pos));
+  }
+
+  // Prepare and write ISO 21496-1 metadata
+  if (kWriteIso21496_1Metadata) {
+    const int length = iso_secondary_length;
+    const uint8_t lengthH = ((length >> 8) & 0xff);
+    const uint8_t lengthL = (length & 0xff);
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthH, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, &lengthL, 1, pos));
+    UHDR_ERR_CHECK(Write(dest, (void*)kIsoNameSpace.c_str(), isoNameSpaceLength, pos));
+    UHDR_ERR_CHECK(Write(dest, (void*)iso_secondary_data.data(), iso_secondary_data.size(), pos));
+  }
+
+  // Write secondary image
+  UHDR_ERR_CHECK(
+      Write(dest, (uint8_t*)gainmap_compressed->data + 2, gainmap_compressed->data_sz - 2, pos));
+
+  // Set back length
+  dest->data_sz = pos;
+
+  // Done!
+  return g_no_error;
+}
+
+uhdr_error_info_t JpegR::getJPEGRInfo(uhdr_compressed_image_t* uhdr_compressed_img,
+                                      jr_info_ptr uhdr_image_info) {
+  uhdr_compressed_image_t primary_image, gainmap;
+
+  UHDR_ERR_CHECK(extractPrimaryImageAndGainMap(uhdr_compressed_img, &primary_image, &gainmap))
+
+  UHDR_ERR_CHECK(parseJpegInfo(&primary_image, uhdr_image_info->primaryImgInfo,
+                               &uhdr_image_info->width, &uhdr_image_info->height))
+  if (uhdr_image_info->gainmapImgInfo != nullptr) {
+    UHDR_ERR_CHECK(parseJpegInfo(&gainmap, uhdr_image_info->gainmapImgInfo))
+  }
+
+  return g_no_error;
+}
+
+uhdr_error_info_t JpegR::parseGainMapMetadata(uint8_t* iso_data, int iso_size, uint8_t* xmp_data,
+                                              int xmp_size,
+                                              uhdr_gainmap_metadata_ext_t* uhdr_metadata) {
+  if (iso_size > 0) {
+    if (iso_size < (int)kIsoNameSpace.size() + 1) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "iso block size needs to be atleast %d but got %d", (int)kIsoNameSpace.size() + 1,
+               iso_size);
+      return status;
+    }
+    uhdr_gainmap_metadata_frac decodedMetadata;
+    std::vector<uint8_t> iso_vec;
+    for (int i = (int)kIsoNameSpace.size() + 1; i < iso_size; i++) {
+      iso_vec.push_back(iso_data[i]);
+    }
+
+    UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::decodeGainmapMetadata(iso_vec, &decodedMetadata));
+    UHDR_ERR_CHECK(uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decodedMetadata,
+                                                                              uhdr_metadata));
+  } else if (xmp_size > 0) {
+    UHDR_ERR_CHECK(getMetadataFromXMP(xmp_data, xmp_size, uhdr_metadata));
+  } else {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "received no valid buffer to parse gainmap metadata");
+    return status;
+  }
+
+  return g_no_error;
+}
+
+/* Decode API */
+uhdr_error_info_t JpegR::decodeJPEGR(uhdr_compressed_image_t* uhdr_compressed_img,
+                                     uhdr_raw_image_t* dest, float max_display_boost,
+                                     uhdr_color_transfer_t output_ct, uhdr_img_fmt_t output_format,
+                                     uhdr_raw_image_t* gainmap_img,
+                                     uhdr_gainmap_metadata_t* gainmap_metadata) {
+  uhdr_compressed_image_t primary_jpeg_image, gainmap_jpeg_image;
+  UHDR_ERR_CHECK(
+      extractPrimaryImageAndGainMap(uhdr_compressed_img, &primary_jpeg_image, &gainmap_jpeg_image))
+
+  JpegDecoderHelper jpeg_dec_obj_sdr;
+  UHDR_ERR_CHECK(jpeg_dec_obj_sdr.decompressImage(
+      primary_jpeg_image.data, primary_jpeg_image.data_sz,
+      (output_ct == UHDR_CT_SRGB) ? DECODE_TO_RGB_CS : DECODE_TO_YCBCR_CS));
+
+  JpegDecoderHelper jpeg_dec_obj_gm;
+  uhdr_raw_image_t gainmap;
+  if (gainmap_img != nullptr || output_ct != UHDR_CT_SRGB) {
+    UHDR_ERR_CHECK(jpeg_dec_obj_gm.decompressImage(gainmap_jpeg_image.data,
+                                                   gainmap_jpeg_image.data_sz, DECODE_STREAM));
+    gainmap = jpeg_dec_obj_gm.getDecompressedImage();
+    if (gainmap_img != nullptr) {
+      UHDR_ERR_CHECK(copy_raw_image(&gainmap, gainmap_img));
+    }
+  }
+
+  uhdr_gainmap_metadata_ext_t uhdr_metadata;
+  if (gainmap_metadata != nullptr || output_ct != UHDR_CT_SRGB) {
+    UHDR_ERR_CHECK(parseGainMapMetadata(static_cast<uint8_t*>(jpeg_dec_obj_gm.getIsoMetadataPtr()),
+                                        jpeg_dec_obj_gm.getIsoMetadataSize(),
+                                        static_cast<uint8_t*>(jpeg_dec_obj_gm.getXMPPtr()),
+                                        jpeg_dec_obj_gm.getXMPSize(), &uhdr_metadata))
+    if (gainmap_metadata != nullptr) {
+      gainmap_metadata->min_content_boost = uhdr_metadata.min_content_boost;
+      gainmap_metadata->max_content_boost = uhdr_metadata.max_content_boost;
+      gainmap_metadata->gamma = uhdr_metadata.gamma;
+      gainmap_metadata->offset_sdr = uhdr_metadata.offset_sdr;
+      gainmap_metadata->offset_hdr = uhdr_metadata.offset_hdr;
+      gainmap_metadata->hdr_capacity_min = uhdr_metadata.hdr_capacity_min;
+      gainmap_metadata->hdr_capacity_max = uhdr_metadata.hdr_capacity_max;
+    }
+  }
+
+  uhdr_raw_image_t sdr_intent = jpeg_dec_obj_sdr.getDecompressedImage();
+  sdr_intent.cg =
+      IccHelper::readIccColorGamut(jpeg_dec_obj_sdr.getICCPtr(), jpeg_dec_obj_sdr.getICCSize());
+  if (output_ct == UHDR_CT_SRGB) {
+    UHDR_ERR_CHECK(copy_raw_image(&sdr_intent, dest));
+    return g_no_error;
+  }
+
+  UHDR_ERR_CHECK(applyGainMap(&sdr_intent, &gainmap, &uhdr_metadata, output_ct, output_format,
+                              max_display_boost, dest));
+
+  return g_no_error;
+}
+
+uhdr_error_info_t JpegR::applyGainMap(uhdr_raw_image_t* sdr_intent, uhdr_raw_image_t* gainmap_img,
+                                      uhdr_gainmap_metadata_ext_t* gainmap_metadata,
+                                      uhdr_color_transfer_t output_ct,
+                                      [[maybe_unused]] uhdr_img_fmt_t output_format,
+                                      float max_display_boost, uhdr_raw_image_t* dest) {
+  if (gainmap_metadata->version.compare(kJpegrVersion)) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "Unsupported gainmap metadata, version. Expected %s, Got %s", kJpegrVersion,
+             gainmap_metadata->version.c_str());
+    return status;
+  }
+  if (gainmap_metadata->offset_sdr != 0.0f) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "Unsupported gainmap metadata, offset_sdr. Expected %f, Got %f", 0.0f,
+             gainmap_metadata->offset_sdr);
+    return status;
+  }
+  if (gainmap_metadata->offset_hdr != 0.0f) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "Unsupported gainmap metadata, offset_hdr. Expected %f, Got %f", 0.0f,
+             gainmap_metadata->offset_hdr);
+    return status;
+  }
+  if (sdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCr444 &&
+      sdr_intent->fmt != UHDR_IMG_FMT_16bppYCbCr422 &&
+      sdr_intent->fmt != UHDR_IMG_FMT_12bppYCbCr420) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "apply gainmap method expects base image color format to be one of "
+             "{UHDR_IMG_FMT_24bppYCbCr444, UHDR_IMG_FMT_16bppYCbCr422, "
+             "UHDR_IMG_FMT_12bppYCbCr420}. Received %d",
+             sdr_intent->fmt);
+    return status;
+  }
+  if (gainmap_img->fmt != UHDR_IMG_FMT_8bppYCbCr400 &&
+      gainmap_img->fmt != UHDR_IMG_FMT_24bppRGB888 &&
+      gainmap_img->fmt != UHDR_IMG_FMT_32bppRGBA8888) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "apply gainmap method expects gainmap image color format to be one of "
+             "{UHDR_IMG_FMT_8bppYCbCr400, UHDR_IMG_FMT_24bppRGB888, UHDR_IMG_FMT_32bppRGBA8888}. "
+             "Received %d",
+             gainmap_img->fmt);
+    return status;
+  }
+
+#ifdef UHDR_ENABLE_GLES
+  if (mUhdrGLESCtxt != nullptr) {
+    if (((sdr_intent->fmt == UHDR_IMG_FMT_12bppYCbCr420 && sdr_intent->w % 2 == 0 &&
+          sdr_intent->h % 2 == 0) ||
+         (sdr_intent->fmt == UHDR_IMG_FMT_16bppYCbCr422 && sdr_intent->w % 2 == 0) ||
+         (sdr_intent->fmt == UHDR_IMG_FMT_24bppYCbCr444)) &&
+        isBufferDataContiguous(sdr_intent) && isBufferDataContiguous(gainmap_img) &&
+        isBufferDataContiguous(dest)) {
+      // TODO: both inputs and outputs of GLES implementation assumes that raw image is contiguous
+      // and without strides. If not, handle the same by using temp copy
+      float display_boost = (std::min)(max_display_boost, gainmap_metadata->hdr_capacity_max);
+
+      return applyGainMapGLES(sdr_intent, gainmap_img, gainmap_metadata, output_ct, display_boost,
+                              dest, static_cast<uhdr_opengl_ctxt_t*>(mUhdrGLESCtxt));
+    }
+  }
+#endif
+
+  {
+    float primary_aspect_ratio = (float)sdr_intent->w / sdr_intent->h;
+    float gainmap_aspect_ratio = (float)gainmap_img->w / gainmap_img->h;
+    float delta_aspect_ratio = fabs(primary_aspect_ratio - gainmap_aspect_ratio);
+    // Allow 1% delta
+    const float delta_tolerance = 0.01;
+    if (delta_aspect_ratio / primary_aspect_ratio > delta_tolerance) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+      status.has_detail = 1;
+      snprintf(
+          status.detail, sizeof status.detail,
+          "gain map dimensions scale factor values for height and width are different, \n primary "
+          "image resolution is %ux%u, received gain map resolution is %ux%u",
+          sdr_intent->w, sdr_intent->h, gainmap_img->w, gainmap_img->h);
+      return status;
+    }
+  }
+
+  float map_scale_factor = (float)sdr_intent->w / gainmap_img->w;
+
+  dest->cg = sdr_intent->cg;
+  // Table will only be used when map scale factor is integer.
+  ShepardsIDW idwTable(static_cast<int>(map_scale_factor));
+  float display_boost = (std::min)(max_display_boost, gainmap_metadata->hdr_capacity_max);
+  GainLUT gainLUT(gainmap_metadata, display_boost);
+
+  GetPixelFn get_pixel_fn = getPixelFn(sdr_intent->fmt);
+  if (get_pixel_fn == nullptr) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for reading pixels for color format %d", sdr_intent->fmt);
+    return status;
+  }
+
+  JobQueue jobQueue;
+  std::function<void()> applyRecMap = [sdr_intent, gainmap_img, dest, &jobQueue, &idwTable,
+                                       output_ct, &gainLUT, display_boost,
+#if !USE_APPLY_GAIN_LUT
+                                       gainmap_metadata,
+#endif
+                                       map_scale_factor, get_pixel_fn]() -> void {
+    size_t width = sdr_intent->w;
+    size_t rowStart, rowEnd;
 
-    size_t rowStart, rowEnd;
     while (jobQueue.dequeueJob(rowStart, rowEnd)) {
       for (size_t y = rowStart; y < rowEnd; ++y) {
         for (size_t x = 0; x < width; ++x) {
-          Color yuv_gamma_sdr = getYuv420Pixel(yuv420_image_ptr, x, y);
+          Color yuv_gamma_sdr = get_pixel_fn(sdr_intent, x, y);
           // Assuming the sdr image is a decoded JPEG, we should always use Rec.601 YUV coefficients
           Color rgb_gamma_sdr = p3YuvToRgb(yuv_gamma_sdr);
           // We are assuming the SDR base image is always sRGB transfer.
@@ -1187,50 +1446,48 @@ status_t JpegR::applyGainMap(jr_uncompressed_ptr yuv420_image_ptr,
           Color rgb_sdr = srgbInvOetf(rgb_gamma_sdr);
 #endif
           Color rgb_hdr;
-          if (gainmap_image_ptr->pixelFormat == UHDR_IMG_FMT_8bppYCbCr400) {
+          if (gainmap_img->fmt == UHDR_IMG_FMT_8bppYCbCr400) {
             float gain;
 
             if (map_scale_factor != floorf(map_scale_factor)) {
-              gain = sampleMap(gainmap_image_ptr, map_scale_factor, x, y);
+              gain = sampleMap(gainmap_img, map_scale_factor, x, y);
             } else {
-              gain = sampleMap(gainmap_image_ptr, map_scale_factor, x, y, idwTable);
+              gain = sampleMap(gainmap_img, map_scale_factor, x, y, idwTable);
             }
 
 #if USE_APPLY_GAIN_LUT
             rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT);
 #else
-            rgb_hdr = applyGain(rgb_sdr, gain, metadata, display_boost);
+            rgb_hdr = applyGain(rgb_sdr, gain, gainmap_metadata, display_boost);
 #endif
           } else {
             Color gain;
 
             if (map_scale_factor != floorf(map_scale_factor)) {
-              gain =
-                  sampleMap3Channel(gainmap_image_ptr, map_scale_factor, x, y,
-                                    gainmap_image_ptr->pixelFormat == UHDR_IMG_FMT_32bppRGBA8888);
+              gain = sampleMap3Channel(gainmap_img, map_scale_factor, x, y,
+                                       gainmap_img->fmt == UHDR_IMG_FMT_32bppRGBA8888);
             } else {
-              gain =
-                  sampleMap3Channel(gainmap_image_ptr, map_scale_factor, x, y, idwTable,
-                                    gainmap_image_ptr->pixelFormat == UHDR_IMG_FMT_32bppRGBA8888);
+              gain = sampleMap3Channel(gainmap_img, map_scale_factor, x, y, idwTable,
+                                       gainmap_img->fmt == UHDR_IMG_FMT_32bppRGBA8888);
             }
 
 #if USE_APPLY_GAIN_LUT
             rgb_hdr = applyGainLUT(rgb_sdr, gain, gainLUT);
 #else
-            rgb_hdr = applyGain(rgb_sdr, gain, metadata, display_boost);
+            rgb_hdr = applyGain(rgb_sdr, gain, gainmap_metadata, display_boost);
 #endif
           }
 
           rgb_hdr = rgb_hdr / display_boost;
-          size_t pixel_idx = x + y * width;
+          size_t pixel_idx = x + y * dest->stride[UHDR_PLANE_PACKED];
 
-          switch (output_format) {
-            case ULTRAHDR_OUTPUT_HDR_LINEAR: {
+          switch (output_ct) {
+            case UHDR_CT_LINEAR: {
               uint64_t rgba_f16 = colorToRgbaF16(rgb_hdr);
-              reinterpret_cast<uint64_t*>(dest->data)[pixel_idx] = rgba_f16;
+              reinterpret_cast<uint64_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] = rgba_f16;
               break;
             }
-            case ULTRAHDR_OUTPUT_HDR_HLG: {
+            case UHDR_CT_HLG: {
 #if USE_HLG_OETF_LUT
               ColorTransformFn hdrOetf = hlgOetfLUT;
 #else
@@ -1238,10 +1495,11 @@ status_t JpegR::applyGainMap(jr_uncompressed_ptr yuv420_image_ptr,
 #endif
               Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
               uint32_t rgba_1010102 = colorToRgba1010102(rgb_gamma_hdr);
-              reinterpret_cast<uint32_t*>(dest->data)[pixel_idx] = rgba_1010102;
+              reinterpret_cast<uint32_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
+                  rgba_1010102;
               break;
             }
-            case ULTRAHDR_OUTPUT_HDR_PQ: {
+            case UHDR_CT_PQ: {
 #if USE_PQ_OETF_LUT
               ColorTransformFn hdrOetf = pqOetfLUT;
 #else
@@ -1249,7 +1507,8 @@ status_t JpegR::applyGainMap(jr_uncompressed_ptr yuv420_image_ptr,
 #endif
               Color rgb_gamma_hdr = hdrOetf(rgb_hdr);
               uint32_t rgba_1010102 = colorToRgba1010102(rgb_gamma_hdr);
-              reinterpret_cast<uint32_t*>(dest->data)[pixel_idx] = rgba_1010102;
+              reinterpret_cast<uint32_t*>(dest->planes[UHDR_PLANE_PACKED])[pixel_idx] =
+                  rgba_1010102;
               break;
             }
             default: {
@@ -1266,62 +1525,76 @@ status_t JpegR::applyGainMap(jr_uncompressed_ptr yuv420_image_ptr,
   for (int th = 0; th < threads - 1; th++) {
     workers.push_back(std::thread(applyRecMap));
   }
-  const int rowStep = threads == 1 ? yuv420_image_ptr->height : map_scale_factor;
-  for (size_t rowStart = 0; rowStart < yuv420_image_ptr->height;) {
-    int rowEnd = (std::min)(rowStart + rowStep, yuv420_image_ptr->height);
+  const int rowStep = threads == 1 ? sdr_intent->h : map_scale_factor;
+  for (size_t rowStart = 0; rowStart < sdr_intent->h;) {
+    int rowEnd = (std::min)(rowStart + rowStep, (size_t)sdr_intent->h);
     jobQueue.enqueueJob(rowStart, rowEnd);
     rowStart = rowEnd;
   }
   jobQueue.markQueueForEnd();
   applyRecMap();
   std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
-  return JPEGR_NO_ERROR;
-}
 
-status_t JpegR::extractPrimaryImageAndGainMap(jr_compressed_ptr jpegr_image_ptr,
-                                              jr_compressed_ptr primary_jpg_image_ptr,
-                                              jr_compressed_ptr gainmap_jpg_image_ptr) {
-  if (jpegr_image_ptr == nullptr) {
-    return ERROR_JPEGR_BAD_PTR;
-  }
+  return g_no_error;
+}
 
+uhdr_error_info_t JpegR::extractPrimaryImageAndGainMap(uhdr_compressed_image_t* jpegr_image,
+                                                       uhdr_compressed_image_t* primary_image,
+                                                       uhdr_compressed_image_t* gainmap_image) {
   MessageHandler msg_handler;
   msg_handler.SetMessageWriter(make_unique<AlogMessageWriter>(AlogMessageWriter()));
+
   std::shared_ptr<DataSegment> seg = DataSegment::Create(
-      DataRange(0, jpegr_image_ptr->length), static_cast<const uint8_t*>(jpegr_image_ptr->data),
+      DataRange(0, jpegr_image->data_sz), static_cast<const uint8_t*>(jpegr_image->data),
       DataSegment::BufferDispositionPolicy::kDontDelete);
   DataSegmentDataSource data_source(seg);
+
   JpegInfoBuilder jpeg_info_builder;
   jpeg_info_builder.SetImageLimit(2);
+
   JpegScanner jpeg_scanner(&msg_handler);
   jpeg_scanner.Run(&data_source, &jpeg_info_builder);
   data_source.Reset();
 
   if (jpeg_scanner.HasError()) {
-    return JPEGR_UNKNOWN_ERROR;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_ERROR;
+    status.has_detail = 1;
+    auto messages = msg_handler.GetMessages();
+    std::string append{};
+    for (auto message : messages) append += message.GetText();
+    snprintf(status.detail, sizeof status.detail, "%s", append.c_str());
+    return status;
   }
 
   const auto& jpeg_info = jpeg_info_builder.GetInfo();
   const auto& image_ranges = jpeg_info.GetImageRanges();
 
   if (image_ranges.empty()) {
-    return ERROR_JPEGR_NO_IMAGES_FOUND;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "input uhdr image does not any valid images");
+    return status;
   }
 
-  if (primary_jpg_image_ptr != nullptr) {
-    primary_jpg_image_ptr->data =
-        static_cast<uint8_t*>(jpegr_image_ptr->data) + image_ranges[0].GetBegin();
-    primary_jpg_image_ptr->length = image_ranges[0].GetLength();
+  if (primary_image != nullptr) {
+    primary_image->data = static_cast<uint8_t*>(jpegr_image->data) + image_ranges[0].GetBegin();
+    primary_image->data_sz = image_ranges[0].GetLength();
   }
 
   if (image_ranges.size() == 1) {
-    return ERROR_JPEGR_GAIN_MAP_IMAGE_NOT_FOUND;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "input uhdr image does not contain gainmap image");
+    return status;
   }
 
-  if (gainmap_jpg_image_ptr != nullptr) {
-    gainmap_jpg_image_ptr->data =
-        static_cast<uint8_t*>(jpegr_image_ptr->data) + image_ranges[1].GetBegin();
-    gainmap_jpg_image_ptr->length = image_ranges[1].GetLength();
+  if (gainmap_image != nullptr) {
+    gainmap_image->data = static_cast<uint8_t*>(jpegr_image->data) + image_ranges[1].GetBegin();
+    gainmap_image->data_sz = image_ranges[1].GetLength();
   }
 
   // TODO: choose primary image and gain map image carefully
@@ -1330,566 +1603,951 @@ status_t JpegR::extractPrimaryImageAndGainMap(jr_compressed_ptr jpegr_image_ptr,
           (int)image_ranges.size());
   }
 
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
-status_t JpegR::parseJpegInfo(jr_compressed_ptr jpeg_image_ptr, j_info_ptr jpeg_image_info_ptr,
-                              size_t* img_width, size_t* img_height) {
+uhdr_error_info_t JpegR::parseJpegInfo(uhdr_compressed_image_t* jpeg_image, j_info_ptr image_info,
+                                       size_t* img_width, size_t* img_height) {
   JpegDecoderHelper jpeg_dec_obj;
-  if (!jpeg_dec_obj.parseImage(jpeg_image_ptr->data, jpeg_image_ptr->length)) {
-    return ERROR_JPEGR_DECODE_ERROR;
-  }
-  size_t imgWidth, imgHeight;
+  UHDR_ERR_CHECK(jpeg_dec_obj.parseImage(jpeg_image->data, jpeg_image->data_sz))
+  size_t imgWidth, imgHeight, numComponents;
   imgWidth = jpeg_dec_obj.getDecompressedImageWidth();
   imgHeight = jpeg_dec_obj.getDecompressedImageHeight();
-
-  if (jpeg_image_info_ptr != nullptr) {
-    jpeg_image_info_ptr->width = imgWidth;
-    jpeg_image_info_ptr->height = imgHeight;
-    jpeg_image_info_ptr->imgData.resize(jpeg_image_ptr->length, 0);
-    memcpy(static_cast<void*>(jpeg_image_info_ptr->imgData.data()), jpeg_image_ptr->data,
-           jpeg_image_ptr->length);
+  numComponents = jpeg_dec_obj.getNumComponentsInImage();
+
+  if (image_info != nullptr) {
+    image_info->width = imgWidth;
+    image_info->height = imgHeight;
+    image_info->numComponents = numComponents;
+    image_info->imgData.resize(jpeg_image->data_sz, 0);
+    memcpy(static_cast<void*>(image_info->imgData.data()), jpeg_image->data, jpeg_image->data_sz);
     if (jpeg_dec_obj.getICCSize() != 0) {
-      jpeg_image_info_ptr->iccData.resize(jpeg_dec_obj.getICCSize(), 0);
-      memcpy(static_cast<void*>(jpeg_image_info_ptr->iccData.data()), jpeg_dec_obj.getICCPtr(),
+      image_info->iccData.resize(jpeg_dec_obj.getICCSize(), 0);
+      memcpy(static_cast<void*>(image_info->iccData.data()), jpeg_dec_obj.getICCPtr(),
              jpeg_dec_obj.getICCSize());
     }
     if (jpeg_dec_obj.getEXIFSize() != 0) {
-      jpeg_image_info_ptr->exifData.resize(jpeg_dec_obj.getEXIFSize(), 0);
-      memcpy(static_cast<void*>(jpeg_image_info_ptr->exifData.data()), jpeg_dec_obj.getEXIFPtr(),
+      image_info->exifData.resize(jpeg_dec_obj.getEXIFSize(), 0);
+      memcpy(static_cast<void*>(image_info->exifData.data()), jpeg_dec_obj.getEXIFPtr(),
              jpeg_dec_obj.getEXIFSize());
     }
     if (jpeg_dec_obj.getXMPSize() != 0) {
-      jpeg_image_info_ptr->xmpData.resize(jpeg_dec_obj.getXMPSize(), 0);
-      memcpy(static_cast<void*>(jpeg_image_info_ptr->xmpData.data()), jpeg_dec_obj.getXMPPtr(),
+      image_info->xmpData.resize(jpeg_dec_obj.getXMPSize(), 0);
+      memcpy(static_cast<void*>(image_info->xmpData.data()), jpeg_dec_obj.getXMPPtr(),
              jpeg_dec_obj.getXMPSize());
     }
+    if (jpeg_dec_obj.getIsoMetadataSize() != 0) {
+      image_info->isoData.resize(jpeg_dec_obj.getIsoMetadataSize(), 0);
+      memcpy(static_cast<void*>(image_info->isoData.data()), jpeg_dec_obj.getIsoMetadataPtr(),
+             jpeg_dec_obj.getIsoMetadataSize());
+    }
   }
   if (img_width != nullptr && img_height != nullptr) {
     *img_width = imgWidth;
     *img_height = imgHeight;
   }
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
-// JPEG/R structure:
-// SOI (ff d8)
-//
-// (Optional, if EXIF package is from outside (Encode API-0 API-1), or if EXIF package presents
-// in the JPEG input (Encode API-2, API-3, API-4))
-// APP1 (ff e1)
-// 2 bytes of length (2 + length of exif package)
-// EXIF package (this includes the first two bytes representing the package length)
-//
-// (Required, XMP package) APP1 (ff e1)
-// 2 bytes of length (2 + 29 + length of xmp package)
-// name space ("http://ns.adobe.com/xap/1.0/\0")
-// XMP
-//
-// (Required, ISO 21496-1 metadata, version only) APP2 (ff e2)
-// 2 bytes of length
-// name space (""urn:iso:std:iso:ts:21496:-1\0")
-// 2 bytes minimum_version: (00 00)
-// 2 bytes writer_version: (00 00)
-//
-// (Required, MPF package) APP2 (ff e2)
-// 2 bytes of length
-// MPF
-//
-// (Required) primary image (without the first two bytes (SOI) and EXIF, may have other packages)
-//
-// SOI (ff d8)
-//
-// (Required, XMP package) APP1 (ff e1)
-// 2 bytes of length (2 + 29 + length of xmp package)
-// name space ("http://ns.adobe.com/xap/1.0/\0")
-// XMP
-//
-// (Required, ISO 21496-1 metadata) APP2 (ff e2)
-// 2 bytes of length
-// name space (""urn:iso:std:iso:ts:21496:-1\0")
-// metadata
-//
-// (Required) secondary image (the gain map, without the first two bytes (SOI))
-//
-// Metadata versions we are using:
-// ECMA TR-98 for JFIF marker
-// Exif 2.2 spec for EXIF marker
-// Adobe XMP spec part 3 for XMP marker
-// ICC v4.3 spec for ICC
-status_t JpegR::appendGainMap(jr_compressed_ptr primary_jpg_image_ptr,
-                              jr_compressed_ptr gainmap_jpg_image_ptr, jr_exif_ptr pExif,
-                              void* pIcc, size_t icc_size, ultrahdr_metadata_ptr metadata,
-                              jr_compressed_ptr dest) {
-  static_assert(kWriteXmpMetadata || kWriteIso21496_1Metadata,
-                "Must write gain map metadata in XMP format, or iso 21496-1 format, or both.");
-  if (primary_jpg_image_ptr == nullptr || gainmap_jpg_image_ptr == nullptr || metadata == nullptr ||
-      dest == nullptr) {
-    return ERROR_JPEGR_BAD_PTR;
-  }
-  if (metadata->version.compare("1.0")) {
-    ALOGE("received bad value for version: %s", metadata->version.c_str());
-    return ERROR_JPEGR_BAD_METADATA;
-  }
-  if (metadata->maxContentBoost < metadata->minContentBoost) {
-    ALOGE("received bad value for content boost min %f, max %f", metadata->minContentBoost,
-          metadata->maxContentBoost);
-    return ERROR_JPEGR_BAD_METADATA;
-  }
-  if (metadata->hdrCapacityMax < metadata->hdrCapacityMin || metadata->hdrCapacityMin < 1.0f) {
-    ALOGE("received bad value for hdr capacity min %f, max %f", metadata->hdrCapacityMin,
-          metadata->hdrCapacityMax);
-    return ERROR_JPEGR_BAD_METADATA;
-  }
-  if (metadata->offsetSdr < 0.0f || metadata->offsetHdr < 0.0f) {
-    ALOGE("received bad value for offset sdr %f, hdr %f", metadata->offsetSdr, metadata->offsetHdr);
-    return ERROR_JPEGR_BAD_METADATA;
-  }
-  if (metadata->gamma <= 0.0f) {
-    ALOGE("received bad value for gamma %f", metadata->gamma);
-    return ERROR_JPEGR_BAD_METADATA;
-  }
-
-  const int xmpNameSpaceLength = kXmpNameSpace.size() + 1;  // need to count the null terminator
-  const int isoNameSpaceLength = kIsoNameSpace.size() + 1;  // need to count the null terminator
+static float ReinhardMap(float y_hdr, float headroom) {
+  float out = 1.0 + y_hdr / (headroom * headroom);
+  out /= 1.0 + y_hdr;
+  return out * y_hdr;
+}
 
-  /////////////////////////////////////////////////////////////////////////////////////////////////
-  // calculate secondary image length first, because the length will be written into the primary //
-  // image xmp                                                                                   //
-  /////////////////////////////////////////////////////////////////////////////////////////////////
-  // XMP
-  const string xmp_secondary = generateXmpForSecondaryImage(*metadata);
-  // xmp_secondary_length = 2 bytes representing the length of the package +
-  //  + xmpNameSpaceLength = 29 bytes length
-  //  + length of xmp packet = xmp_secondary.size()
-  const int xmp_secondary_length = 2 + xmpNameSpaceLength + xmp_secondary.size();
-  // ISO
-  gain_map_metadata iso_secondary_metadata;
-  std::vector<uint8_t> iso_secondary_data;
-  gain_map_metadata::gainmapMetadataFloatToFraction(metadata, &iso_secondary_metadata);
+GlobalTonemapOutputs globalTonemap(const std::array<float, 3>& rgb_in, float headroom, float y_in) {
+  constexpr float kOotfGamma = 1.2f;
 
-  gain_map_metadata::encodeGainmapMetadata(&iso_secondary_metadata, iso_secondary_data);
+  // Apply OOTF and Scale to Headroom to get HDR values that are referenced to
+  // SDR white. The range [0.0, 1.0] is linearly stretched to [0.0, headroom]
+  // after the OOTF.
+  const float y_ootf_div_y_in = std::pow(y_in, kOotfGamma - 1.0f);
+  std::array<float, 3> rgb_hdr;
+  std::transform(rgb_in.begin(), rgb_in.end(), rgb_hdr.begin(),
+                 [&](float x) { return x * headroom * y_ootf_div_y_in; });
 
-  // iso_secondary_length = 2 bytes representing the length of the package +
-  //  + isoNameSpaceLength = 28 bytes length
-  //  + length of iso metadata packet = iso_secondary_data.size()
-  const int iso_secondary_length = 2 + isoNameSpaceLength + iso_secondary_data.size();
+  // Apply a tone mapping to compress the range [0, headroom] to [0, 1] by
+  // keeping the shadows the same and crushing the highlights.
+  float max_hdr = *std::max_element(rgb_hdr.begin(), rgb_hdr.end());
+  float max_sdr = ReinhardMap(max_hdr, headroom);
+  std::array<float, 3> rgb_sdr;
+  std::transform(rgb_hdr.begin(), rgb_hdr.end(), rgb_sdr.begin(), [&](float x) {
+    if (x > 0.0f) {
+      return x * max_sdr / max_hdr;
+    }
+    return 0.0f;
+  });
 
-  int secondary_image_size = 2 /* 2 bytes length of APP1 sign */ + gainmap_jpg_image_ptr->length;
-  if (kWriteXmpMetadata) {
-    secondary_image_size += xmp_secondary_length;
-  }
-  if (kWriteIso21496_1Metadata) {
-    secondary_image_size += iso_secondary_length;
-  }
+  GlobalTonemapOutputs tonemap_outputs;
+  tonemap_outputs.rgb_out = rgb_sdr;
+  tonemap_outputs.y_hdr = max_hdr;
+  tonemap_outputs.y_sdr = max_sdr;
 
-  // Check if EXIF package presents in the JPEG input.
-  // If so, extract and remove the EXIF package.
-  JpegDecoderHelper decoder;
-  if (!decoder.parseImage(primary_jpg_image_ptr->data, primary_jpg_image_ptr->length)) {
-    return ERROR_JPEGR_DECODE_ERROR;
-  }
-  jpegr_exif_struct exif_from_jpg;
-  exif_from_jpg.data = nullptr;
-  exif_from_jpg.length = 0;
-  jpegr_compressed_struct new_jpg_image;
-  new_jpg_image.data = nullptr;
-  new_jpg_image.length = 0;
-  new_jpg_image.maxLength = 0;
-  new_jpg_image.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-  std::unique_ptr<uint8_t[]> dest_data;
-  if (decoder.getEXIFPos() >= 0) {
-    if (pExif != nullptr) {
-      ALOGE("received EXIF from outside while the primary image already contains EXIF");
-      return ERROR_JPEGR_MULTIPLE_EXIFS_RECEIVED;
-    }
-    copyJpegWithoutExif(&new_jpg_image, primary_jpg_image_ptr, decoder.getEXIFPos(),
-                        decoder.getEXIFSize());
-    dest_data.reset(reinterpret_cast<uint8_t*>(new_jpg_image.data));
-    exif_from_jpg.data = decoder.getEXIFPtr();
-    exif_from_jpg.length = decoder.getEXIFSize();
-    pExif = &exif_from_jpg;
-  }
+  return tonemap_outputs;
+}
 
-  jr_compressed_ptr final_primary_jpg_image_ptr =
-      new_jpg_image.length == 0 ? primary_jpg_image_ptr : &new_jpg_image;
+uint8_t ScaleTo8Bit(float value) {
+  constexpr float kMaxValFloat = 255.0f;
+  constexpr int kMaxValInt = 255;
+  return std::clamp(static_cast<int>(std::round(value * kMaxValFloat)), 0, kMaxValInt);
+}
 
-  int pos = 0;
-  // Begin primary image
-  // Write SOI
-  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
-  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));
+uhdr_error_info_t JpegR::toneMap(uhdr_raw_image_t* hdr_intent, uhdr_raw_image_t* sdr_intent) {
+  if (hdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCrP010 &&
+      hdr_intent->fmt != UHDR_IMG_FMT_30bppYCbCr444 &&
+      hdr_intent->fmt != UHDR_IMG_FMT_32bppRGBA1010102) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(
+        status.detail, sizeof status.detail,
+        "tonemap method expects hdr intent color format to be one of {UHDR_IMG_FMT_24bppYCbCrP010, "
+        "UHDR_IMG_FMT_30bppYCbCr444, UHDR_IMG_FMT_32bppRGBA1010102}. Received %d",
+        hdr_intent->fmt);
+    return status;
+  }
+
+  if (hdr_intent->fmt == UHDR_IMG_FMT_24bppYCbCrP010 &&
+      sdr_intent->fmt != UHDR_IMG_FMT_12bppYCbCr420) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "tonemap method expects sdr intent color format to be UHDR_IMG_FMT_12bppYCbCr420, if "
+             "hdr intent color format is UHDR_IMG_FMT_24bppYCbCrP010. Received %d",
+             sdr_intent->fmt);
+    return status;
+  }
+
+  if (hdr_intent->fmt == UHDR_IMG_FMT_30bppYCbCr444 &&
+      sdr_intent->fmt != UHDR_IMG_FMT_24bppYCbCr444) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "tonemap method expects sdr intent color format to be UHDR_IMG_FMT_24bppYCbCr444, if "
+             "hdr intent color format is UHDR_IMG_FMT_30bppYCbCr444. Received %d",
+             sdr_intent->fmt);
+    return status;
+  }
+
+  if (hdr_intent->fmt == UHDR_IMG_FMT_32bppRGBA1010102 &&
+      sdr_intent->fmt != UHDR_IMG_FMT_32bppRGBA8888) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "tonemap method expects sdr intent color format to be UHDR_IMG_FMT_32bppRGBA8888, if "
+             "hdr intent color format is UHDR_IMG_FMT_32bppRGBA1010102. Received %d",
+             sdr_intent->fmt);
+    return status;
+  }
+
+  ColorTransformFn hdrYuvToRgbFn = getYuvToRgbFn(hdr_intent->cg);
+  if (hdrYuvToRgbFn == nullptr) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for converting yuv to rgb for color gamut %d",
+             hdr_intent->cg);
+    return status;
+  }
+
+  ColorCalculationFn hdrLuminanceFn = getLuminanceFn(hdr_intent->cg);
+  if (hdrLuminanceFn == nullptr) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for calculating luminance for color gamut %d",
+             hdr_intent->cg);
+    return status;
+  }
+
+  ColorTransformFn hdrInvOetf = getInverseOetfFn(hdr_intent->ct);
+  if (hdrInvOetf == nullptr) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for converting transfer characteristics %d to linear",
+             hdr_intent->ct);
+    return status;
+  }
+
+  float hdr_white_nits = getMaxDisplayMasteringLuminance(hdr_intent->ct);
+  if (hdr_white_nits == -1.0f) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "Did not receive valid MDML for display with transfer characteristics %d",
+             hdr_intent->ct);
+    return status;
+  }
+
+  GetPixelFn get_pixel_fn = getPixelFn(hdr_intent->fmt);
+  if (get_pixel_fn == nullptr) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for reading pixels for color format %d", hdr_intent->fmt);
+    return status;
+  }
+
+  PutPixelFn put_pixel_fn = putPixelFn(sdr_intent->fmt);
+  // for subsampled formats, we are writing to raw image buffers directly instead of using
+  // put_pixel_fn
+  if (put_pixel_fn == nullptr && sdr_intent->fmt != UHDR_IMG_FMT_12bppYCbCr420) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "No implementation available for writing pixels for color format %d", sdr_intent->fmt);
+    return status;
+  }
+
+  sdr_intent->cg = UHDR_CG_DISPLAY_P3;
+  sdr_intent->ct = UHDR_CT_SRGB;
+  sdr_intent->range = UHDR_CR_FULL_RANGE;
+
+  ColorTransformFn hdrGamutConversionFn = getGamutConversionFn(sdr_intent->cg, hdr_intent->cg);
+
+  size_t height = hdr_intent->h;
+  const int threads = (std::min)(GetCPUCoreCount(), 4);
+  // for 420 subsampling, process 2 rows at once
+  const int jobSizeInRows = hdr_intent->fmt == UHDR_IMG_FMT_24bppYCbCrP010 ? 2 : 1;
+  size_t rowStep = threads == 1 ? height : jobSizeInRows;
+  JobQueue jobQueue;
+  std::function<void()> toneMapInternal;
 
-  // Write EXIF
-  if (pExif != nullptr) {
-    const int length = 2 + pExif->length;
-    const uint8_t lengthH = ((length >> 8) & 0xff);
-    const uint8_t lengthL = (length & 0xff);
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
-    JPEGR_CHECK(Write(dest, pExif->data, pExif->length, pos));
-  }
+  toneMapInternal = [hdr_intent, sdr_intent, hdrInvOetf, hdrGamutConversionFn, hdrYuvToRgbFn,
+                     hdr_white_nits, get_pixel_fn, put_pixel_fn, hdrLuminanceFn,
+                     &jobQueue]() -> void {
+    size_t rowStart, rowEnd;
+    const int hfactor = hdr_intent->fmt == UHDR_IMG_FMT_24bppYCbCrP010 ? 2 : 1;
+    const int vfactor = hdr_intent->fmt == UHDR_IMG_FMT_24bppYCbCrP010 ? 2 : 1;
+    const bool isHdrIntentRgb = isPixelFormatRgb(hdr_intent->fmt);
+    const bool isSdrIntentRgb = isPixelFormatRgb(sdr_intent->fmt);
+    uint8_t* luma_data = reinterpret_cast<uint8_t*>(sdr_intent->planes[UHDR_PLANE_Y]);
+    uint8_t* cb_data = reinterpret_cast<uint8_t*>(sdr_intent->planes[UHDR_PLANE_U]);
+    uint8_t* cr_data = reinterpret_cast<uint8_t*>(sdr_intent->planes[UHDR_PLANE_V]);
+    size_t luma_stride = sdr_intent->stride[UHDR_PLANE_Y];
+    size_t cb_stride = sdr_intent->stride[UHDR_PLANE_U];
+    size_t cr_stride = sdr_intent->stride[UHDR_PLANE_V];
 
-  // Prepare and write XMP
-  if (kWriteXmpMetadata) {
-    const string xmp_primary = generateXmpForPrimaryImage(secondary_image_size, *metadata);
-    const int length = 2 + xmpNameSpaceLength + xmp_primary.size();
-    const uint8_t lengthH = ((length >> 8) & 0xff);
-    const uint8_t lengthL = (length & 0xff);
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
-    JPEGR_CHECK(Write(dest, (void*)kXmpNameSpace.c_str(), xmpNameSpaceLength, pos));
-    JPEGR_CHECK(Write(dest, (void*)xmp_primary.c_str(), xmp_primary.size(), pos));
-  }
+    while (jobQueue.dequeueJob(rowStart, rowEnd)) {
+      for (size_t y = rowStart; y < rowEnd; y += vfactor) {
+        for (size_t x = 0; x < hdr_intent->w; x += hfactor) {
+          // meant for p010 input
+          float sdr_u_gamma = 0.0f;
+          float sdr_v_gamma = 0.0f;
 
-  // Write ICC
-  if (pIcc != nullptr && icc_size > 0) {
-    const int length = icc_size + 2;
-    const uint8_t lengthH = ((length >> 8) & 0xff);
-    const uint8_t lengthL = (length & 0xff);
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
-    JPEGR_CHECK(Write(dest, pIcc, icc_size, pos));
-  }
+          for (int i = 0; i < vfactor; i++) {
+            for (int j = 0; j < hfactor; j++) {
+              Color hdr_rgb_gamma;
 
-  // Prepare and write ISO 21496-1 metadata
-  if (kWriteIso21496_1Metadata) {
-    const int length = 2 + isoNameSpaceLength + 4;
-    uint8_t zero = 0;
-    const uint8_t lengthH = ((length >> 8) & 0xff);
-    const uint8_t lengthL = (length & 0xff);
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
-    JPEGR_CHECK(Write(dest, (void*)kIsoNameSpace.c_str(), isoNameSpaceLength, pos));
-    JPEGR_CHECK(Write(dest, &zero, 1, pos));
-    JPEGR_CHECK(Write(dest, &zero, 1, pos));  // 2 bytes minimum_version: (00 00)
-    JPEGR_CHECK(Write(dest, &zero, 1, pos));
-    JPEGR_CHECK(Write(dest, &zero, 1, pos));  // 2 bytes writer_version: (00 00)
-  }
+              if (isHdrIntentRgb) {
+                hdr_rgb_gamma = get_pixel_fn(hdr_intent, x + j, y + i);
+              } else {
+                Color hdr_yuv_gamma = get_pixel_fn(hdr_intent, x + j, y + i);
+                hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
+              }
+              Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
 
-  // Prepare and write MPF
-  {
-    const int length = 2 + calculateMpfSize();
-    const uint8_t lengthH = ((length >> 8) & 0xff);
-    const uint8_t lengthL = (length & 0xff);
-    int primary_image_size = pos + length + final_primary_jpg_image_ptr->length;
-    // between APP2 + package size + signature
-    // ff e2 00 58 4d 50 46 00
-    // 2 + 2 + 4 = 8 (bytes)
-    // and ff d8 sign of the secondary image
-    int secondary_image_offset = primary_image_size - pos - 8;
-    std::shared_ptr<DataStruct> mpf = generateMpf(primary_image_size, 0, /* primary_image_offset */
-                                                  secondary_image_size, secondary_image_offset);
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
-    JPEGR_CHECK(Write(dest, (void*)mpf->getData(), mpf->getLength(), pos));
-  }
+              GlobalTonemapOutputs tonemap_outputs =
+                  globalTonemap({hdr_rgb.r, hdr_rgb.g, hdr_rgb.b}, hdr_white_nits / kSdrWhiteNits,
+                                hdrLuminanceFn({{{hdr_rgb.r, hdr_rgb.g, hdr_rgb.b}}}));
+              Color sdr_rgb_linear_bt2100 = {
+                  {{tonemap_outputs.rgb_out[0], tonemap_outputs.rgb_out[1],
+                    tonemap_outputs.rgb_out[2]}}};
+              Color sdr_rgb = hdrGamutConversionFn(sdr_rgb_linear_bt2100);
 
-  // Write primary image
-  JPEGR_CHECK(Write(dest, (uint8_t*)final_primary_jpg_image_ptr->data + 2,
-                    final_primary_jpg_image_ptr->length - 2, pos));
-  // Finish primary image
+              // Hard clip out-of-gamut values;
+              sdr_rgb = clampPixelFloat(sdr_rgb);
 
-  // Begin secondary image (gain map)
-  // Write SOI
-  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
-  JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kSOI, 1, pos));
+              Color sdr_rgb_gamma = srgbOetf(sdr_rgb);
+              if (isSdrIntentRgb) {
+                put_pixel_fn(sdr_intent, (x + j), (y + i), sdr_rgb_gamma);
+              } else {
+                Color sdr_yuv_gamma = p3RgbToYuv(sdr_rgb_gamma);
+                sdr_yuv_gamma += {{{0.0f, 0.5f, 0.5f}}};
+                if (sdr_intent->fmt != UHDR_IMG_FMT_12bppYCbCr420) {
+                  put_pixel_fn(sdr_intent, (x + j), (y + i), sdr_yuv_gamma);
+                } else {
+                  size_t out_y_idx = (y + i) * luma_stride + x + j;
+                  luma_data[out_y_idx] = ScaleTo8Bit(sdr_yuv_gamma.y);
+
+                  sdr_u_gamma += sdr_yuv_gamma.u;
+                  sdr_v_gamma += sdr_yuv_gamma.v;
+                }
+              }
+            }
+          }
+          if (sdr_intent->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+            sdr_u_gamma /= (hfactor * vfactor);
+            sdr_v_gamma /= (hfactor * vfactor);
+            cb_data[x / hfactor + (y / vfactor) * cb_stride] = ScaleTo8Bit(sdr_u_gamma);
+            cr_data[x / hfactor + (y / vfactor) * cr_stride] = ScaleTo8Bit(sdr_v_gamma);
+          }
+        }
+      }
+    }
+  };
 
-  // Prepare and write XMP
-  if (kWriteXmpMetadata) {
-    const int length = xmp_secondary_length;
-    const uint8_t lengthH = ((length >> 8) & 0xff);
-    const uint8_t lengthL = (length & 0xff);
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP1, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
-    JPEGR_CHECK(Write(dest, (void*)kXmpNameSpace.c_str(), xmpNameSpaceLength, pos));
-    JPEGR_CHECK(Write(dest, (void*)xmp_secondary.c_str(), xmp_secondary.size(), pos));
+  // tone map
+  std::vector<std::thread> workers;
+  for (int th = 0; th < threads - 1; th++) {
+    workers.push_back(std::thread(toneMapInternal));
   }
 
-  // Prepare and write ISO 21496-1 metadata
-  if (kWriteIso21496_1Metadata) {
-    const int length = iso_secondary_length;
-    const uint8_t lengthH = ((length >> 8) & 0xff);
-    const uint8_t lengthL = (length & 0xff);
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kStart, 1, pos));
-    JPEGR_CHECK(Write(dest, &photos_editing_formats::image_io::JpegMarker::kAPP2, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthH, 1, pos));
-    JPEGR_CHECK(Write(dest, &lengthL, 1, pos));
-    JPEGR_CHECK(Write(dest, (void*)kIsoNameSpace.c_str(), isoNameSpaceLength, pos));
-    JPEGR_CHECK(Write(dest, (void*)iso_secondary_data.data(), iso_secondary_data.size(), pos));
+  for (size_t rowStart = 0; rowStart < height;) {
+    size_t rowEnd = (std::min)(rowStart + rowStep, height);
+    jobQueue.enqueueJob(rowStart, rowEnd);
+    rowStart = rowEnd;
   }
+  jobQueue.markQueueForEnd();
+  toneMapInternal();
+  std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
 
-  // Write secondary image
-  JPEGR_CHECK(Write(dest, (uint8_t*)gainmap_jpg_image_ptr->data + 2,
-                    gainmap_jpg_image_ptr->length - 2, pos));
-
-  // Set back length
-  dest->length = pos;
-
-  // Done!
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
-status_t JpegR::convertYuv(jr_uncompressed_ptr image, ultrahdr_color_gamut src_encoding,
-                           ultrahdr_color_gamut dest_encoding) {
-  if (image == nullptr) {
+status_t JpegR::areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
+                                       jr_uncompressed_ptr yuv420_image_ptr,
+                                       ultrahdr_transfer_function hdr_tf,
+                                       jr_compressed_ptr dest_ptr) {
+  if (p010_image_ptr == nullptr || p010_image_ptr->data == nullptr) {
+    ALOGE("Received nullptr for input p010 image");
     return ERROR_JPEGR_BAD_PTR;
   }
-  if (src_encoding == ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
-      dest_encoding == ULTRAHDR_COLORGAMUT_UNSPECIFIED) {
+  if (p010_image_ptr->width % 2 != 0 || p010_image_ptr->height % 2 != 0) {
+    ALOGE("Image dimensions cannot be odd, image dimensions %zux%zu", p010_image_ptr->width,
+          p010_image_ptr->height);
+    return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
+  }
+  if ((int)p010_image_ptr->width < kMinWidth || (int)p010_image_ptr->height < kMinHeight) {
+    ALOGE("Image dimensions cannot be less than %dx%d, image dimensions %zux%zu", kMinWidth,
+          kMinHeight, p010_image_ptr->width, p010_image_ptr->height);
+    return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
+  }
+  if ((int)p010_image_ptr->width > kMaxWidth || (int)p010_image_ptr->height > kMaxHeight) {
+    ALOGE("Image dimensions cannot be larger than %dx%d, image dimensions %zux%zu", kMaxWidth,
+          kMaxHeight, p010_image_ptr->width, p010_image_ptr->height);
+    return ERROR_JPEGR_UNSUPPORTED_WIDTH_HEIGHT;
+  }
+  if (p010_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
+      p010_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
+    ALOGE("Unrecognized p010 color gamut %d", p010_image_ptr->colorGamut);
     return ERROR_JPEGR_INVALID_COLORGAMUT;
   }
-
-  const std::array<float, 9>* coeffs_ptr = nullptr;
-  switch (src_encoding) {
-    case ULTRAHDR_COLORGAMUT_BT709:
-      switch (dest_encoding) {
-        case ULTRAHDR_COLORGAMUT_BT709:
-          return JPEGR_NO_ERROR;
-        case ULTRAHDR_COLORGAMUT_P3:
-          coeffs_ptr = &kYuvBt709ToBt601;
-          break;
-        case ULTRAHDR_COLORGAMUT_BT2100:
-          coeffs_ptr = &kYuvBt709ToBt2100;
-          break;
-        default:
-          // Should be impossible to hit after input validation
-          return ERROR_JPEGR_INVALID_COLORGAMUT;
-      }
-      break;
-    case ULTRAHDR_COLORGAMUT_P3:
-      switch (dest_encoding) {
-        case ULTRAHDR_COLORGAMUT_BT709:
-          coeffs_ptr = &kYuvBt601ToBt709;
-          break;
-        case ULTRAHDR_COLORGAMUT_P3:
-          return JPEGR_NO_ERROR;
-        case ULTRAHDR_COLORGAMUT_BT2100:
-          coeffs_ptr = &kYuvBt601ToBt2100;
-          break;
-        default:
-          // Should be impossible to hit after input validation
-          return ERROR_JPEGR_INVALID_COLORGAMUT;
-      }
-      break;
-    case ULTRAHDR_COLORGAMUT_BT2100:
-      switch (dest_encoding) {
-        case ULTRAHDR_COLORGAMUT_BT709:
-          coeffs_ptr = &kYuvBt2100ToBt709;
-          break;
-        case ULTRAHDR_COLORGAMUT_P3:
-          coeffs_ptr = &kYuvBt2100ToBt601;
-          break;
-        case ULTRAHDR_COLORGAMUT_BT2100:
-          return JPEGR_NO_ERROR;
-        default:
-          // Should be impossible to hit after input validation
-          return ERROR_JPEGR_INVALID_COLORGAMUT;
-      }
-      break;
-    default:
-      // Should be impossible to hit after input validation
-      return ERROR_JPEGR_INVALID_COLORGAMUT;
+  if (p010_image_ptr->luma_stride != 0 && p010_image_ptr->luma_stride < p010_image_ptr->width) {
+    ALOGE("Luma stride must not be smaller than width, stride=%zu, width=%zu",
+          p010_image_ptr->luma_stride, p010_image_ptr->width);
+    return ERROR_JPEGR_INVALID_STRIDE;
+  }
+  if (p010_image_ptr->chroma_data != nullptr &&
+      p010_image_ptr->chroma_stride < p010_image_ptr->width) {
+    ALOGE("Chroma stride must not be smaller than width, stride=%zu, width=%zu",
+          p010_image_ptr->chroma_stride, p010_image_ptr->width);
+    return ERROR_JPEGR_INVALID_STRIDE;
+  }
+  if (dest_ptr == nullptr || dest_ptr->data == nullptr) {
+    ALOGE("Received nullptr for destination");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (hdr_tf <= ULTRAHDR_TF_UNSPECIFIED || hdr_tf > ULTRAHDR_TF_MAX || hdr_tf == ULTRAHDR_TF_SRGB) {
+    ALOGE("Invalid hdr transfer function %d", hdr_tf);
+    return ERROR_JPEGR_INVALID_TRANS_FUNC;
+  }
+  if (yuv420_image_ptr == nullptr) {
+    return JPEGR_NO_ERROR;
+  }
+  if (yuv420_image_ptr->data == nullptr) {
+    ALOGE("Received nullptr for uncompressed 420 image");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (yuv420_image_ptr->luma_stride != 0 &&
+      yuv420_image_ptr->luma_stride < yuv420_image_ptr->width) {
+    ALOGE("Luma stride must not be smaller than width, stride=%zu, width=%zu",
+          yuv420_image_ptr->luma_stride, yuv420_image_ptr->width);
+    return ERROR_JPEGR_INVALID_STRIDE;
+  }
+  if (yuv420_image_ptr->chroma_data != nullptr &&
+      yuv420_image_ptr->chroma_stride < yuv420_image_ptr->width / 2) {
+    ALOGE("Chroma stride must not be smaller than (width / 2), stride=%zu, width=%zu",
+          yuv420_image_ptr->chroma_stride, yuv420_image_ptr->width);
+    return ERROR_JPEGR_INVALID_STRIDE;
   }
-
-  if (coeffs_ptr == nullptr) {
-    // Should be impossible to hit after input validation
+  if (p010_image_ptr->width != yuv420_image_ptr->width ||
+      p010_image_ptr->height != yuv420_image_ptr->height) {
+    ALOGE("Image resolutions mismatch: P010: %zux%zu, YUV420: %zux%zu", p010_image_ptr->width,
+          p010_image_ptr->height, yuv420_image_ptr->width, yuv420_image_ptr->height);
+    return ERROR_JPEGR_RESOLUTION_MISMATCH;
+  }
+  if (yuv420_image_ptr->colorGamut <= ULTRAHDR_COLORGAMUT_UNSPECIFIED ||
+      yuv420_image_ptr->colorGamut > ULTRAHDR_COLORGAMUT_MAX) {
+    ALOGE("Unrecognized 420 color gamut %d", yuv420_image_ptr->colorGamut);
     return ERROR_JPEGR_INVALID_COLORGAMUT;
   }
-
-  transformYuv420(image, *coeffs_ptr);
   return JPEGR_NO_ERROR;
 }
 
-namespace {
-float ReinhardMap(float y_hdr, float headroom) {
-  float out = 1.0 + y_hdr / (headroom * headroom);
-  out /= 1.0 + y_hdr;
-  return out * y_hdr;
+status_t JpegR::areInputArgumentsValid(jr_uncompressed_ptr p010_image_ptr,
+                                       jr_uncompressed_ptr yuv420_image_ptr,
+                                       ultrahdr_transfer_function hdr_tf,
+                                       jr_compressed_ptr dest_ptr, int quality) {
+  if (quality < 0 || quality > 100) {
+    ALOGE("quality factor is out side range [0-100], quality factor : %d", quality);
+    return ERROR_JPEGR_INVALID_QUALITY_FACTOR;
+  }
+  return areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest_ptr);
 }
-}  // namespace
-
-GlobalTonemapOutputs hlgGlobalTonemap(const std::array<float, 3>& rgb_in, float headroom) {
-  constexpr float kRgbToYBt2020[3] = {0.2627f, 0.6780f, 0.0593f};
-  constexpr float kOotfGamma = 1.2f;
-
-  // Apply OOTF and Scale to Headroom to get HDR values that are referenced to
-  // SDR white. The range [0.0, 1.0] is linearly stretched to [0.0, headroom]
-  // after the OOTF.
-  const float y_in =
-      rgb_in[0] * kRgbToYBt2020[0] + rgb_in[1] * kRgbToYBt2020[1] + rgb_in[2] * kRgbToYBt2020[2];
-  const float y_ootf_div_y_in = std::pow(y_in, kOotfGamma - 1.0f);
-  std::array<float, 3> rgb_hdr;
-  std::transform(rgb_in.begin(), rgb_in.end(), rgb_hdr.begin(),
-                 [&](float x) { return x * headroom * y_ootf_div_y_in; });
 
-  // Apply a tone mapping to compress the range [0, headroom] to [0, 1] by
-  // keeping the shadows the same and crushing the highlights.
-  float max_hdr = *std::max_element(rgb_hdr.begin(), rgb_hdr.end());
-  float max_sdr = ReinhardMap(max_hdr, headroom);
-  std::array<float, 3> rgb_sdr;
-  std::transform(rgb_hdr.begin(), rgb_hdr.end(), rgb_sdr.begin(), [&](float x) {
-    if (x > 0.0f) {
-      return x * max_sdr / max_hdr;
-    }
-    return 0.0f;
-  });
+uhdr_color_transfer_t map_legacy_ct_to_ct(ultrahdr::ultrahdr_transfer_function ct) {
+  switch (ct) {
+    case ultrahdr::ULTRAHDR_TF_HLG:
+      return UHDR_CT_HLG;
+    case ultrahdr::ULTRAHDR_TF_PQ:
+      return UHDR_CT_PQ;
+    case ultrahdr::ULTRAHDR_TF_LINEAR:
+      return UHDR_CT_LINEAR;
+    case ultrahdr::ULTRAHDR_TF_SRGB:
+      return UHDR_CT_SRGB;
+    default:
+      return UHDR_CT_UNSPECIFIED;
+  }
+}
 
-  GlobalTonemapOutputs tonemap_outputs;
-  tonemap_outputs.rgb_out = rgb_sdr;
-  tonemap_outputs.y_hdr = max_hdr;
-  tonemap_outputs.y_sdr = max_sdr;
-  return tonemap_outputs;
+uhdr_color_gamut_t map_legacy_cg_to_cg(ultrahdr::ultrahdr_color_gamut cg) {
+  switch (cg) {
+    case ultrahdr::ULTRAHDR_COLORGAMUT_BT2100:
+      return UHDR_CG_BT_2100;
+    case ultrahdr::ULTRAHDR_COLORGAMUT_BT709:
+      return UHDR_CG_BT_709;
+    case ultrahdr::ULTRAHDR_COLORGAMUT_P3:
+      return UHDR_CG_DISPLAY_P3;
+    default:
+      return UHDR_CG_UNSPECIFIED;
+  }
 }
 
-uint8_t ScaleTo8Bit(float value) {
-  constexpr float kMaxValFloat = 255.0f;
-  constexpr int kMaxValInt = 255;
-  return std::clamp(static_cast<int>(std::round(value * kMaxValFloat)), 0, kMaxValInt);
+ultrahdr::ultrahdr_color_gamut map_cg_to_legacy_cg(uhdr_color_gamut_t cg) {
+  switch (cg) {
+    case UHDR_CG_BT_2100:
+      return ultrahdr::ULTRAHDR_COLORGAMUT_BT2100;
+    case UHDR_CG_BT_709:
+      return ultrahdr::ULTRAHDR_COLORGAMUT_BT709;
+    case UHDR_CG_DISPLAY_P3:
+      return ultrahdr::ULTRAHDR_COLORGAMUT_P3;
+    default:
+      return ultrahdr::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+  }
 }
 
-status_t JpegR::toneMap(jr_uncompressed_ptr src, jr_uncompressed_ptr dest,
-                        ultrahdr_transfer_function hdr_tf) {
-  if (src == nullptr || dest == nullptr) {
+/* Encode API-0 */
+status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr, ultrahdr_transfer_function hdr_tf,
+                            jr_compressed_ptr dest, int quality, jr_exif_ptr exif) {
+  // validate input arguments
+  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, nullptr, hdr_tf, dest, quality));
+  if (exif != nullptr && exif->data == nullptr) {
+    ALOGE("received nullptr for exif metadata");
     return ERROR_JPEGR_BAD_PTR;
   }
-  if (src->width != dest->width || src->height != dest->height) {
-    return ERROR_JPEGR_RESOLUTION_MISMATCH;
+
+  // clean up input structure for later usage
+  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
+  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
+  if (!p010_image.chroma_data) {
+    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
+    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
+    p010_image.chroma_stride = p010_image.luma_stride;
   }
 
-  dest->colorGamut = ULTRAHDR_COLORGAMUT_P3;
+  uhdr_raw_image_t hdr_intent;
+  hdr_intent.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
+  hdr_intent.cg = map_legacy_cg_to_cg(p010_image.colorGamut);
+  hdr_intent.ct = map_legacy_ct_to_ct(hdr_tf);
+  hdr_intent.range = p010_image.colorRange;
+  hdr_intent.w = p010_image.width;
+  hdr_intent.h = p010_image.height;
+  hdr_intent.planes[UHDR_PLANE_Y] = p010_image.data;
+  hdr_intent.stride[UHDR_PLANE_Y] = p010_image.luma_stride;
+  hdr_intent.planes[UHDR_PLANE_UV] = p010_image.chroma_data;
+  hdr_intent.stride[UHDR_PLANE_UV] = p010_image.chroma_stride;
+  hdr_intent.planes[UHDR_PLANE_V] = nullptr;
+  hdr_intent.stride[UHDR_PLANE_V] = 0;
+
+  uhdr_compressed_image_t output;
+  output.data = dest->data;
+  output.data_sz = 0;
+  output.capacity = dest->maxLength;
+  output.cg = UHDR_CG_UNSPECIFIED;
+  output.ct = UHDR_CT_UNSPECIFIED;
+  output.range = UHDR_CR_UNSPECIFIED;
+
+  uhdr_mem_block_t exifBlock;
+  if (exif) {
+    exifBlock.data = exif->data;
+    exifBlock.data_sz = exifBlock.capacity = exif->length;
+  }
+
+  auto result = encodeJPEGR(&hdr_intent, &output, quality, exif ? &exifBlock : nullptr);
+  if (result.error_code == UHDR_CODEC_OK) {
+    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
+    dest->length = output.data_sz;
+  }
+
+  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
+}
 
-  size_t height = src->height;
+/* Encode API-1 */
+status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
+                            jr_uncompressed_ptr yuv420_image_ptr, ultrahdr_transfer_function hdr_tf,
+                            jr_compressed_ptr dest, int quality, jr_exif_ptr exif) {
+  // validate input arguments
+  if (yuv420_image_ptr == nullptr) {
+    ALOGE("received nullptr for uncompressed 420 image");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (exif != nullptr && exif->data == nullptr) {
+    ALOGE("received nullptr for exif metadata");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest, quality))
 
-  ColorTransformFn hdrYuvToRgbFn = nullptr;
-  switch (src->colorGamut) {
-    case ULTRAHDR_COLORGAMUT_BT709:
-      hdrYuvToRgbFn = srgbYuvToRgb;
-      break;
-    case ULTRAHDR_COLORGAMUT_P3:
-      hdrYuvToRgbFn = p3YuvToRgb;
-      break;
-    case ULTRAHDR_COLORGAMUT_BT2100:
-      hdrYuvToRgbFn = bt2100YuvToRgb;
-      break;
-    case ULTRAHDR_COLORGAMUT_UNSPECIFIED:
-      // Should be impossible to hit after input validation.
-      return ERROR_JPEGR_INVALID_COLORGAMUT;
+  // clean up input structure for later usage
+  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
+  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
+  if (!p010_image.chroma_data) {
+    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
+    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
+    p010_image.chroma_stride = p010_image.luma_stride;
   }
+  uhdr_raw_image_t hdr_intent;
+  hdr_intent.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
+  hdr_intent.cg = map_legacy_cg_to_cg(p010_image.colorGamut);
+  hdr_intent.ct = map_legacy_ct_to_ct(hdr_tf);
+  hdr_intent.range = p010_image.colorRange;
+  hdr_intent.w = p010_image.width;
+  hdr_intent.h = p010_image.height;
+  hdr_intent.planes[UHDR_PLANE_Y] = p010_image.data;
+  hdr_intent.stride[UHDR_PLANE_Y] = p010_image.luma_stride;
+  hdr_intent.planes[UHDR_PLANE_UV] = p010_image.chroma_data;
+  hdr_intent.stride[UHDR_PLANE_UV] = p010_image.chroma_stride;
+  hdr_intent.planes[UHDR_PLANE_V] = nullptr;
+  hdr_intent.stride[UHDR_PLANE_V] = 0;
 
-  ColorTransformFn hdrInvOetf = nullptr;
-  switch (hdr_tf) {
-    case ULTRAHDR_TF_HLG:
-#if USE_HLG_INVOETF_LUT
-      hdrInvOetf = hlgInvOetfLUT;
-#else
-      hdrInvOetf = hlgInvOetf;
-#endif
-      break;
-    case ULTRAHDR_TF_PQ:
-#if USE_PQ_INVOETF_LUT
-      hdrInvOetf = pqInvOetfLUT;
-#else
-      hdrInvOetf = pqInvOetf;
-#endif
-      break;
-    default:
-      // Should be impossible to hit after input validation.
-      return ERROR_JPEGR_INVALID_TRANS_FUNC;
+  jpegr_uncompressed_struct yuv420_image = *yuv420_image_ptr;
+  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
+  if (!yuv420_image.chroma_data) {
+    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
+    yuv420_image.chroma_data = data + yuv420_image.luma_stride * yuv420_image.height;
+    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
   }
+  uhdr_raw_image_t sdrRawImg;
+  sdrRawImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
+  sdrRawImg.cg = map_legacy_cg_to_cg(yuv420_image.colorGamut);
+  sdrRawImg.ct = UHDR_CT_SRGB;
+  sdrRawImg.range = yuv420_image.colorRange;
+  sdrRawImg.w = yuv420_image.width;
+  sdrRawImg.h = yuv420_image.height;
+  sdrRawImg.planes[UHDR_PLANE_Y] = yuv420_image.data;
+  sdrRawImg.stride[UHDR_PLANE_Y] = yuv420_image.luma_stride;
+  sdrRawImg.planes[UHDR_PLANE_U] = yuv420_image.chroma_data;
+  sdrRawImg.stride[UHDR_PLANE_U] = yuv420_image.chroma_stride;
+  uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.chroma_data);
+  data += (yuv420_image.height * yuv420_image.chroma_stride) / 2;
+  sdrRawImg.planes[UHDR_PLANE_V] = data;
+  sdrRawImg.stride[UHDR_PLANE_V] = yuv420_image.chroma_stride;
+  auto sdr_intent = convert_raw_input_to_ycbcr(&sdrRawImg);
+
+  uhdr_compressed_image_t output;
+  output.data = dest->data;
+  output.data_sz = 0;
+  output.capacity = dest->maxLength;
+  output.cg = UHDR_CG_UNSPECIFIED;
+  output.ct = UHDR_CT_UNSPECIFIED;
+  output.range = UHDR_CR_UNSPECIFIED;
+
+  uhdr_mem_block_t exifBlock;
+  if (exif) {
+    exifBlock.data = exif->data;
+    exifBlock.data_sz = exifBlock.capacity = exif->length;
+  }
+
+  auto result =
+      encodeJPEGR(&hdr_intent, sdr_intent.get(), &output, quality, exif ? &exifBlock : nullptr);
+  if (result.error_code == UHDR_CODEC_OK) {
+    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
+    dest->length = output.data_sz;
+  }
+
+  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
+}
 
-  ColorTransformFn hdrGamutConversionFn = getHdrConversionFn(dest->colorGamut, src->colorGamut);
+/* Encode API-2 */
+status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
+                            jr_uncompressed_ptr yuv420_image_ptr,
+                            jr_compressed_ptr yuv420jpg_image_ptr,
+                            ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest) {
+  // validate input arguments
+  if (yuv420_image_ptr == nullptr) {
+    ALOGE("received nullptr for uncompressed 420 image");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
+    ALOGE("received nullptr for compressed jpeg image");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, yuv420_image_ptr, hdr_tf, dest))
 
-  size_t luma_stride = dest->luma_stride == 0 ? dest->width : dest->luma_stride;
-  size_t chroma_stride = dest->chroma_stride == 0 ? luma_stride / 2 : dest->chroma_stride;
-  if (dest->chroma_data == nullptr) {
-    uint8_t* data = reinterpret_cast<uint8_t*>(dest->data);
-    dest->chroma_data = data + luma_stride * dest->height;
+  // clean up input structure for later usage
+  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
+  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
+  if (!p010_image.chroma_data) {
+    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
+    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
+    p010_image.chroma_stride = p010_image.luma_stride;
   }
-  uint8_t* luma_data = reinterpret_cast<uint8_t*>(dest->data);
-  uint8_t* chroma_data = reinterpret_cast<uint8_t*>(dest->chroma_data);
+  uhdr_raw_image_t hdr_intent;
+  hdr_intent.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
+  hdr_intent.cg = map_legacy_cg_to_cg(p010_image.colorGamut);
+  hdr_intent.ct = map_legacy_ct_to_ct(hdr_tf);
+  hdr_intent.range = p010_image.colorRange;
+  hdr_intent.w = p010_image.width;
+  hdr_intent.h = p010_image.height;
+  hdr_intent.planes[UHDR_PLANE_Y] = p010_image.data;
+  hdr_intent.stride[UHDR_PLANE_Y] = p010_image.luma_stride;
+  hdr_intent.planes[UHDR_PLANE_UV] = p010_image.chroma_data;
+  hdr_intent.stride[UHDR_PLANE_UV] = p010_image.chroma_stride;
+  hdr_intent.planes[UHDR_PLANE_V] = nullptr;
+  hdr_intent.stride[UHDR_PLANE_V] = 0;
 
-  const int threads = (std::min)(GetCPUCoreCount(), 4);
-  size_t rowStep = threads == 1 ? height : kJobSzInRows;
-  JobQueue jobQueue;
-  std::function<void()> toneMapInternal;
+  jpegr_uncompressed_struct yuv420_image = *yuv420_image_ptr;
+  if (yuv420_image.luma_stride == 0) yuv420_image.luma_stride = yuv420_image.width;
+  if (!yuv420_image.chroma_data) {
+    uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.data);
+    yuv420_image.chroma_data = data + yuv420_image.luma_stride * p010_image.height;
+    yuv420_image.chroma_stride = yuv420_image.luma_stride >> 1;
+  }
+  uhdr_raw_image_t sdrRawImg;
+  sdrRawImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
+  sdrRawImg.cg = map_legacy_cg_to_cg(yuv420_image.colorGamut);
+  sdrRawImg.ct = UHDR_CT_SRGB;
+  sdrRawImg.range = yuv420_image.colorRange;
+  sdrRawImg.w = yuv420_image.width;
+  sdrRawImg.h = yuv420_image.height;
+  sdrRawImg.planes[UHDR_PLANE_Y] = yuv420_image.data;
+  sdrRawImg.stride[UHDR_PLANE_Y] = yuv420_image.luma_stride;
+  sdrRawImg.planes[UHDR_PLANE_U] = yuv420_image.chroma_data;
+  sdrRawImg.stride[UHDR_PLANE_U] = yuv420_image.chroma_stride;
+  uint8_t* data = reinterpret_cast<uint8_t*>(yuv420_image.chroma_data);
+  data += (yuv420_image.height * yuv420_image.chroma_stride) / 2;
+  sdrRawImg.planes[UHDR_PLANE_V] = data;
+  sdrRawImg.stride[UHDR_PLANE_V] = yuv420_image.chroma_stride;
+  auto sdr_intent = convert_raw_input_to_ycbcr(&sdrRawImg);
+
+  uhdr_compressed_image_t input;
+  input.data = yuv420jpg_image_ptr->data;
+  input.data_sz = yuv420jpg_image_ptr->length;
+  input.capacity = yuv420jpg_image_ptr->maxLength;
+  input.cg = map_legacy_cg_to_cg(yuv420jpg_image_ptr->colorGamut);
+  input.ct = UHDR_CT_UNSPECIFIED;
+  input.range = UHDR_CR_UNSPECIFIED;
+
+  uhdr_compressed_image_t output;
+  output.data = dest->data;
+  output.data_sz = 0;
+  output.capacity = dest->maxLength;
+  output.cg = UHDR_CG_UNSPECIFIED;
+  output.ct = UHDR_CT_UNSPECIFIED;
+  output.range = UHDR_CR_UNSPECIFIED;
+
+  auto result = encodeJPEGR(&hdr_intent, sdr_intent.get(), &input, &output);
+  if (result.error_code == UHDR_CODEC_OK) {
+    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
+    dest->length = output.data_sz;
+  }
+
+  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
+}
 
-  toneMapInternal = [src, dest, luma_data, chroma_data, hdrInvOetf, hdrGamutConversionFn,
-                     hdrYuvToRgbFn, luma_stride, chroma_stride, &jobQueue]() -> void {
-    size_t rowStart, rowEnd;
-    while (jobQueue.dequeueJob(rowStart, rowEnd)) {
-      for (size_t y = rowStart; y < rowEnd; y += 2) {
-        for (size_t x = 0; x < dest->width; x += 2) {
-          // We assume the input is P010, and output is YUV420
-          float sdr_u_gamma = 0.0f;
-          float sdr_v_gamma = 0.0f;
-          for (int i = 0; i < 2; i++) {
-            for (int j = 0; j < 2; j++) {
-              Color hdr_yuv_gamma = getP010Pixel(src, x + j, y + i);
-              Color hdr_rgb_gamma = hdrYuvToRgbFn(hdr_yuv_gamma);
+/* Encode API-3 */
+status_t JpegR::encodeJPEGR(jr_uncompressed_ptr p010_image_ptr,
+                            jr_compressed_ptr yuv420jpg_image_ptr,
+                            ultrahdr_transfer_function hdr_tf, jr_compressed_ptr dest) {
+  // validate input arguments
+  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
+    ALOGE("received nullptr for compressed jpeg image");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  JPEGR_CHECK(areInputArgumentsValid(p010_image_ptr, nullptr, hdr_tf, dest))
 
-              Color hdr_rgb = hdrInvOetf(hdr_rgb_gamma);
+  // clean up input structure for later usage
+  jpegr_uncompressed_struct p010_image = *p010_image_ptr;
+  if (p010_image.luma_stride == 0) p010_image.luma_stride = p010_image.width;
+  if (!p010_image.chroma_data) {
+    uint16_t* data = reinterpret_cast<uint16_t*>(p010_image.data);
+    p010_image.chroma_data = data + p010_image.luma_stride * p010_image.height;
+    p010_image.chroma_stride = p010_image.luma_stride;
+  }
+  uhdr_raw_image_t hdr_intent;
+  hdr_intent.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
+  hdr_intent.cg = map_legacy_cg_to_cg(p010_image.colorGamut);
+  hdr_intent.ct = map_legacy_ct_to_ct(hdr_tf);
+  hdr_intent.range = p010_image.colorRange;
+  hdr_intent.w = p010_image.width;
+  hdr_intent.h = p010_image.height;
+  hdr_intent.planes[UHDR_PLANE_Y] = p010_image.data;
+  hdr_intent.stride[UHDR_PLANE_Y] = p010_image.luma_stride;
+  hdr_intent.planes[UHDR_PLANE_UV] = p010_image.chroma_data;
+  hdr_intent.stride[UHDR_PLANE_UV] = p010_image.chroma_stride;
+  hdr_intent.planes[UHDR_PLANE_V] = nullptr;
+  hdr_intent.stride[UHDR_PLANE_V] = 0;
+
+  uhdr_compressed_image_t input;
+  input.data = yuv420jpg_image_ptr->data;
+  input.data_sz = yuv420jpg_image_ptr->length;
+  input.capacity = yuv420jpg_image_ptr->maxLength;
+  input.cg = map_legacy_cg_to_cg(yuv420jpg_image_ptr->colorGamut);
+  input.ct = UHDR_CT_UNSPECIFIED;
+  input.range = UHDR_CR_UNSPECIFIED;
+
+  uhdr_compressed_image_t output;
+  output.data = dest->data;
+  output.data_sz = 0;
+  output.capacity = dest->maxLength;
+  output.cg = UHDR_CG_UNSPECIFIED;
+  output.ct = UHDR_CT_UNSPECIFIED;
+  output.range = UHDR_CR_UNSPECIFIED;
+
+  auto result = encodeJPEGR(&hdr_intent, &input, &output);
+  if (result.error_code == UHDR_CODEC_OK) {
+    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
+    dest->length = output.data_sz;
+  }
+
+  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
+}
 
-              GlobalTonemapOutputs tonemap_outputs =
-                  hlgGlobalTonemap({hdr_rgb.r, hdr_rgb.g, hdr_rgb.b}, kHlgHeadroom);
-              Color sdr_rgb_linear_bt2100 = {{{tonemap_outputs.rgb_out[0],
-                                               tonemap_outputs.rgb_out[1],
-                                               tonemap_outputs.rgb_out[2]}}};
-              Color sdr_rgb = hdrGamutConversionFn(sdr_rgb_linear_bt2100);
+/* Encode API-4 */
+status_t JpegR::encodeJPEGR(jr_compressed_ptr yuv420jpg_image_ptr,
+                            jr_compressed_ptr gainmapjpg_image_ptr, ultrahdr_metadata_ptr metadata,
+                            jr_compressed_ptr dest) {
+  if (yuv420jpg_image_ptr == nullptr || yuv420jpg_image_ptr->data == nullptr) {
+    ALOGE("received nullptr for compressed jpeg image");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (gainmapjpg_image_ptr == nullptr || gainmapjpg_image_ptr->data == nullptr) {
+    ALOGE("received nullptr for compressed gain map");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (dest == nullptr || dest->data == nullptr) {
+    ALOGE("received nullptr for destination");
+    return ERROR_JPEGR_BAD_PTR;
+  }
 
-              // Hard clip out-of-gamut values;
-              sdr_rgb = clampPixelFloat(sdr_rgb);
+  uhdr_compressed_image_t input;
+  input.data = yuv420jpg_image_ptr->data;
+  input.data_sz = yuv420jpg_image_ptr->length;
+  input.capacity = yuv420jpg_image_ptr->maxLength;
+  input.cg = map_legacy_cg_to_cg(yuv420jpg_image_ptr->colorGamut);
+  input.ct = UHDR_CT_UNSPECIFIED;
+  input.range = UHDR_CR_UNSPECIFIED;
+
+  uhdr_compressed_image_t gainmap;
+  gainmap.data = gainmapjpg_image_ptr->data;
+  gainmap.data_sz = gainmapjpg_image_ptr->length;
+  gainmap.capacity = gainmapjpg_image_ptr->maxLength;
+  gainmap.cg = UHDR_CG_UNSPECIFIED;
+  gainmap.ct = UHDR_CT_UNSPECIFIED;
+  gainmap.range = UHDR_CR_UNSPECIFIED;
+
+  uhdr_compressed_image_t output;
+  output.data = dest->data;
+  output.data_sz = 0;
+  output.capacity = dest->maxLength;
+  output.cg = UHDR_CG_UNSPECIFIED;
+  output.ct = UHDR_CT_UNSPECIFIED;
+  output.range = UHDR_CR_UNSPECIFIED;
+
+  uhdr_gainmap_metadata_ext_t meta;
+  meta.version = metadata->version;
+  meta.hdr_capacity_max = metadata->hdrCapacityMax;
+  meta.hdr_capacity_min = metadata->hdrCapacityMin;
+  meta.gamma = metadata->gamma;
+  meta.offset_sdr = metadata->offsetSdr;
+  meta.offset_hdr = metadata->offsetHdr;
+  meta.max_content_boost = metadata->maxContentBoost;
+  meta.min_content_boost = metadata->minContentBoost;
+
+  auto result = encodeJPEGR(&input, &gainmap, &meta, &output);
+  if (result.error_code == UHDR_CODEC_OK) {
+    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
+    dest->length = output.data_sz;
+  }
+
+  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
+}
 
-              Color sdr_rgb_gamma = srgbOetf(sdr_rgb);
-              Color sdr_yuv_gamma = srgbRgbToYuv(sdr_rgb_gamma);
+/* Decode API */
+status_t JpegR::getJPEGRInfo(jr_compressed_ptr jpegr_image_ptr, jr_info_ptr jpegr_image_info_ptr) {
+  if (jpegr_image_ptr == nullptr || jpegr_image_ptr->data == nullptr) {
+    ALOGE("received nullptr for compressed jpegr image");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (jpegr_image_info_ptr == nullptr) {
+    ALOGE("received nullptr for compressed jpegr info struct");
+    return ERROR_JPEGR_BAD_PTR;
+  }
 
-              sdr_yuv_gamma += {{{0.0f, 0.5f, 0.5f}}};
+  uhdr_compressed_image_t input;
+  input.data = jpegr_image_ptr->data;
+  input.data_sz = jpegr_image_ptr->length;
+  input.capacity = jpegr_image_ptr->maxLength;
+  input.cg = map_legacy_cg_to_cg(jpegr_image_ptr->colorGamut);
+  input.ct = UHDR_CT_UNSPECIFIED;
+  input.range = UHDR_CR_UNSPECIFIED;
 
-              size_t out_y_idx = (y + i) * luma_stride + x + j;
-              luma_data[out_y_idx] = ScaleTo8Bit(sdr_yuv_gamma.y);
+  auto result = getJPEGRInfo(&input, jpegr_image_info_ptr);
 
-              sdr_u_gamma += sdr_yuv_gamma.u * 0.25f;
-              sdr_v_gamma += sdr_yuv_gamma.v * 0.25f;
-            }
-          }
-          size_t out_chroma_idx = x / 2 + (y / 2) * chroma_stride;
-          size_t offset_cr = chroma_stride * (dest->height / 2);
-          chroma_data[out_chroma_idx] = ScaleTo8Bit(sdr_u_gamma);
-          chroma_data[out_chroma_idx + offset_cr] = ScaleTo8Bit(sdr_v_gamma);
-        }
-      }
-    }
-  };
+  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
+}
 
-  // tone map
-  std::vector<std::thread> workers;
-  for (int th = 0; th < threads - 1; th++) {
-    workers.push_back(std::thread(toneMapInternal));
+status_t JpegR::decodeJPEGR(jr_compressed_ptr jpegr_image_ptr, jr_uncompressed_ptr dest,
+                            float max_display_boost, jr_exif_ptr exif,
+                            ultrahdr_output_format output_format,
+                            jr_uncompressed_ptr gainmap_image_ptr, ultrahdr_metadata_ptr metadata) {
+  if (jpegr_image_ptr == nullptr || jpegr_image_ptr->data == nullptr) {
+    ALOGE("received nullptr for compressed jpegr image");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (dest == nullptr || dest->data == nullptr) {
+    ALOGE("received nullptr for dest image");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (max_display_boost < 1.0f) {
+    ALOGE("received bad value for max_display_boost %f", max_display_boost);
+    return ERROR_JPEGR_INVALID_DISPLAY_BOOST;
+  }
+  if (exif != nullptr && exif->data == nullptr) {
+    ALOGE("received nullptr address for exif data");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (gainmap_image_ptr != nullptr && gainmap_image_ptr->data == nullptr) {
+    ALOGE("received nullptr address for gainmap data");
+    return ERROR_JPEGR_BAD_PTR;
+  }
+  if (output_format <= ULTRAHDR_OUTPUT_UNSPECIFIED || output_format > ULTRAHDR_OUTPUT_MAX) {
+    ALOGE("received bad value for output format %d", output_format);
+    return ERROR_JPEGR_INVALID_OUTPUT_FORMAT;
   }
 
-  rowStep = (threads == 1 ? height : kJobSzInRows) / kMapDimensionScaleFactor;
-  for (size_t rowStart = 0; rowStart < height;) {
-    size_t rowEnd = (std::min)(rowStart + rowStep, height);
-    jobQueue.enqueueJob(rowStart, rowEnd);
-    rowStart = rowEnd;
+  uhdr_color_transfer_t ct;
+  uhdr_img_fmt fmt;
+  if (output_format == ULTRAHDR_OUTPUT_HDR_HLG) {
+    fmt = UHDR_IMG_FMT_32bppRGBA1010102;
+    ct = UHDR_CT_HLG;
+  } else if (output_format == ULTRAHDR_OUTPUT_HDR_PQ) {
+    fmt = UHDR_IMG_FMT_32bppRGBA1010102;
+    ct = UHDR_CT_PQ;
+  } else if (output_format == ULTRAHDR_OUTPUT_HDR_LINEAR) {
+    fmt = UHDR_IMG_FMT_64bppRGBAHalfFloat;
+    ct = UHDR_CT_LINEAR;
+  } else if (output_format == ULTRAHDR_OUTPUT_SDR) {
+    fmt = UHDR_IMG_FMT_32bppRGBA8888;
+    ct = UHDR_CT_SRGB;
+  }
+
+  uhdr_compressed_image_t input;
+  input.data = jpegr_image_ptr->data;
+  input.data_sz = jpegr_image_ptr->length;
+  input.capacity = jpegr_image_ptr->maxLength;
+  input.cg = map_legacy_cg_to_cg(jpegr_image_ptr->colorGamut);
+  input.ct = UHDR_CT_UNSPECIFIED;
+  input.range = UHDR_CR_UNSPECIFIED;
+
+  jpeg_info_struct primary_image;
+  jpeg_info_struct gainmap_image;
+  jpegr_info_struct jpegr_info;
+  jpegr_info.primaryImgInfo = &primary_image;
+  jpegr_info.gainmapImgInfo = &gainmap_image;
+  if (getJPEGRInfo(&input, &jpegr_info).error_code != UHDR_CODEC_OK) return JPEGR_UNKNOWN_ERROR;
+
+  if (exif != nullptr) {
+    if (exif->length < primary_image.exifData.size()) {
+      return ERROR_JPEGR_BUFFER_TOO_SMALL;
+    }
+    memcpy(exif->data, primary_image.exifData.data(), primary_image.exifData.size());
+    exif->length = primary_image.exifData.size();
+  }
+
+  uhdr_raw_image_t output;
+  output.fmt = fmt;
+  output.cg = UHDR_CG_UNSPECIFIED;
+  output.ct = UHDR_CT_UNSPECIFIED;
+  output.range = UHDR_CR_UNSPECIFIED;
+  output.w = jpegr_info.width;
+  output.h = jpegr_info.height;
+  output.planes[UHDR_PLANE_PACKED] = dest->data;
+  output.stride[UHDR_PLANE_PACKED] = jpegr_info.width;
+  output.planes[UHDR_PLANE_U] = nullptr;
+  output.stride[UHDR_PLANE_U] = 0;
+  output.planes[UHDR_PLANE_V] = nullptr;
+  output.stride[UHDR_PLANE_V] = 0;
+
+  uhdr_raw_image_t output_gm;
+  if (gainmap_image_ptr) {
+    output.fmt =
+        gainmap_image.numComponents == 1 ? UHDR_IMG_FMT_8bppYCbCr400 : UHDR_IMG_FMT_24bppRGB888;
+    output.cg = UHDR_CG_UNSPECIFIED;
+    output.ct = UHDR_CT_UNSPECIFIED;
+    output.range = UHDR_CR_UNSPECIFIED;
+    output.w = gainmap_image.width;
+    output.h = gainmap_image.height;
+    output.planes[UHDR_PLANE_PACKED] = gainmap_image_ptr->data;
+    output.stride[UHDR_PLANE_PACKED] = gainmap_image.width;
+    output.planes[UHDR_PLANE_U] = nullptr;
+    output.stride[UHDR_PLANE_U] = 0;
+    output.planes[UHDR_PLANE_V] = nullptr;
+    output.stride[UHDR_PLANE_V] = 0;
+  }
+
+  uhdr_gainmap_metadata_ext_t meta;
+  auto result = decodeJPEGR(&input, &output, max_display_boost, ct, fmt,
+                            gainmap_image_ptr ? &output_gm : nullptr, metadata ? &meta : nullptr);
+
+  if (result.error_code == UHDR_CODEC_OK) {
+    dest->width = output.w;
+    dest->height = output.h;
+    dest->colorGamut = map_cg_to_legacy_cg(output.cg);
+    dest->colorRange = output.range;
+    dest->pixelFormat = output.fmt;
+    dest->chroma_data = nullptr;
+    if (gainmap_image_ptr) {
+      gainmap_image_ptr->width = output_gm.w;
+      gainmap_image_ptr->height = output_gm.h;
+      gainmap_image_ptr->colorGamut = map_cg_to_legacy_cg(output_gm.cg);
+      gainmap_image_ptr->colorRange = output_gm.range;
+      gainmap_image_ptr->pixelFormat = output_gm.fmt;
+      gainmap_image_ptr->chroma_data = nullptr;
+    }
+    if (metadata) {
+      metadata->version = meta.version;
+      metadata->hdrCapacityMax = meta.hdr_capacity_max;
+      metadata->hdrCapacityMin = meta.hdr_capacity_min;
+      metadata->gamma = meta.gamma;
+      metadata->offsetSdr = meta.offset_sdr;
+      metadata->offsetHdr = meta.offset_hdr;
+      metadata->maxContentBoost = meta.max_content_boost;
+      metadata->minContentBoost = meta.min_content_boost;
+    }
   }
-  jobQueue.markQueueForEnd();
-  toneMapInternal();
-  std::for_each(workers.begin(), workers.end(), [](std::thread& t) { t.join(); });
 
-  return JPEGR_NO_ERROR;
+  return result.error_code == UHDR_CODEC_OK ? JPEGR_NO_ERROR : JPEGR_UNKNOWN_ERROR;
 }
 
 }  // namespace ultrahdr
diff --git a/lib/src/jpegrutils.cpp b/lib/src/jpegrutils.cpp
index d9647c5..4233847 100644
--- a/lib/src/jpegrutils.cpp
+++ b/lib/src/jpegrutils.cpp
@@ -73,6 +73,7 @@ bool DataStruct::write16(uint16_t value) {
   uint16_t v = value;
   return write(&v, 2);
 }
+
 bool DataStruct::write32(uint32_t value) {
   uint32_t v = value;
   return write(&v, 4);
@@ -92,14 +93,20 @@ bool DataStruct::write(const void* src, int size) {
 /*
  * Helper function used for writing data to destination.
  */
-status_t Write(jr_compressed_ptr destination, const void* source, int length, int& position) {
-  if (position + length > destination->maxLength) {
-    return ERROR_JPEGR_BUFFER_TOO_SMALL;
+uhdr_error_info_t Write(uhdr_compressed_image_t* destination, const void* source, int length,
+                        int& position) {
+  if (position + length > (int)destination->capacity) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_MEM_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "output buffer to store compressed data is too small");
+    return status;
   }
 
   memcpy((uint8_t*)destination->data + sizeof(uint8_t) * position, source, length);
   position += length;
-  return JPEGR_NO_ERROR;
+  return g_no_error;
 }
 
 // Extremely simple XML Handler - just searches for interesting elements
@@ -433,17 +440,28 @@ const string XMPXmlHandler::hdrCapacityMinAttrName = kMapHDRCapacityMin;
 const string XMPXmlHandler::hdrCapacityMaxAttrName = kMapHDRCapacityMax;
 const string XMPXmlHandler::baseRenditionIsHdrAttrName = kMapBaseRenditionIsHDR;
 
-bool getMetadataFromXMP(uint8_t* xmp_data, int xmp_size, ultrahdr_metadata_struct* metadata) {
+uhdr_error_info_t getMetadataFromXMP(uint8_t* xmp_data, int xmp_size,
+                                     uhdr_gainmap_metadata_ext_t* metadata) {
   string nameSpace = "http://ns.adobe.com/xap/1.0/\0";
 
   if (xmp_size < (int)nameSpace.size() + 2) {
-    // Data too short
-    return false;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "size of xmp block is expected to be atleast %d bytes, received only %d bytes",
+             (int)nameSpace.size() + 2, xmp_size);
+    return status;
   }
 
   if (strncmp(reinterpret_cast<char*>(xmp_data), nameSpace.c_str(), nameSpace.size())) {
-    // Not correct namespace
-    return false;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "mismatch in namespace of xmp block. Expected %s, Got %.*s", nameSpace.c_str(),
+             (int)nameSpace.size(), reinterpret_cast<char*>(xmp_data));
+    return status;
   }
 
   // Position the pointers to the start of XMP XML portion
@@ -492,8 +510,11 @@ bool getMetadataFromXMP(uint8_t* xmp_data, int xmp_size, ultrahdr_metadata_struc
   reader.Parse(str);
   reader.FinishParse();
   if (reader.HasErrors()) {
-    // Parse error
-    return false;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "xml parser returned with error");
+    return status;
   }
 
   // Apply default values to any not-present fields, except for Version,
@@ -502,49 +523,110 @@ bool getMetadataFromXMP(uint8_t* xmp_data, int xmp_size, ultrahdr_metadata_struc
   // indicates it is invalid (eg. string where there should be a float).
   bool present = false;
   if (!handler.getVersion(&metadata->version, &present) || !present) {
-    return false;
-  }
-  if (!handler.getMaxContentBoost(&metadata->maxContentBoost, &present) || !present) {
-    return false;
-  }
-  if (!handler.getHdrCapacityMax(&metadata->hdrCapacityMax, &present) || !present) {
-    return false;
-  }
-  if (!handler.getMinContentBoost(&metadata->minContentBoost, &present)) {
-    if (present) return false;
-    metadata->minContentBoost = 1.0f;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "xml parse error, could not find attribute %s",
+             kMapVersion.c_str());
+    return status;
+  }
+  if (!handler.getMaxContentBoost(&metadata->max_content_boost, &present) || !present) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "xml parse error, could not find attribute %s",
+             kMapGainMapMax.c_str());
+    return status;
+  }
+  if (!handler.getHdrCapacityMax(&metadata->hdr_capacity_max, &present) || !present) {
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "xml parse error, could not find attribute %s",
+             kMapHDRCapacityMax.c_str());
+    return status;
+  }
+  if (!handler.getMinContentBoost(&metadata->min_content_boost, &present)) {
+    if (present) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
+               kMapGainMapMin.c_str());
+      return status;
+    }
+    metadata->min_content_boost = 1.0f;
   }
   if (!handler.getGamma(&metadata->gamma, &present)) {
-    if (present) return false;
+    if (present) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
+               kMapGamma.c_str());
+      return status;
+    }
     metadata->gamma = 1.0f;
   }
-  if (!handler.getOffsetSdr(&metadata->offsetSdr, &present)) {
-    if (present) return false;
-    metadata->offsetSdr = 1.0f / 64.0f;
-  }
-  if (!handler.getOffsetHdr(&metadata->offsetHdr, &present)) {
-    if (present) return false;
-    metadata->offsetHdr = 1.0f / 64.0f;
-  }
-  if (!handler.getHdrCapacityMin(&metadata->hdrCapacityMin, &present)) {
-    if (present) return false;
-    metadata->hdrCapacityMin = 1.0f;
+  if (!handler.getOffsetSdr(&metadata->offset_sdr, &present)) {
+    if (present) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
+               kMapOffsetSdr.c_str());
+      return status;
+    }
+    metadata->offset_sdr = 1.0f / 64.0f;
+  }
+  if (!handler.getOffsetHdr(&metadata->offset_hdr, &present)) {
+    if (present) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
+               kMapOffsetHdr.c_str());
+      return status;
+    }
+    metadata->offset_hdr = 1.0f / 64.0f;
+  }
+  if (!handler.getHdrCapacityMin(&metadata->hdr_capacity_min, &present)) {
+    if (present) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
+               kMapHDRCapacityMin.c_str());
+      return status;
+    }
+    metadata->hdr_capacity_min = 1.0f;
   }
 
   bool base_rendition_is_hdr;
   if (!handler.getBaseRenditionIsHdr(&base_rendition_is_hdr, &present)) {
-    if (present) return false;
+    if (present) {
+      uhdr_error_info_t status;
+      status.error_code = UHDR_CODEC_ERROR;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail, "xml parse error, unable to parse attribute %s",
+               kMapBaseRenditionIsHDR.c_str());
+      return status;
+    }
     base_rendition_is_hdr = false;
   }
   if (base_rendition_is_hdr) {
-    ALOGE("Base rendition of HDR is not supported!");
-    return false;
+    uhdr_error_info_t status;
+    status.error_code = UHDR_CODEC_ERROR;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "hdr intent as base rendition is not supported");
+    return status;
   }
 
-  return true;
+  return g_no_error;
 }
 
-string generateXmpForPrimaryImage(int secondary_image_length, ultrahdr_metadata_struct& metadata) {
+string generateXmpForPrimaryImage(int secondary_image_length,
+                                  uhdr_gainmap_metadata_ext_t& metadata) {
   const vector<string> kConDirSeq({kConDirectory, string("rdf:Seq")});
   const vector<string> kLiItem({string("rdf:li"), kConItem});
 
@@ -582,7 +664,7 @@ string generateXmpForPrimaryImage(int secondary_image_length, ultrahdr_metadata_
   return ss.str();
 }
 
-string generateXmpForSecondaryImage(ultrahdr_metadata_struct& metadata) {
+string generateXmpForSecondaryImage(uhdr_gainmap_metadata_ext_t& metadata) {
   const vector<string> kConDirSeq({kConDirectory, string("rdf:Seq")});
 
   std::stringstream ss;
@@ -595,13 +677,13 @@ string generateXmpForSecondaryImage(ultrahdr_metadata_struct& metadata) {
   writer.StartWritingElement("rdf:Description");
   writer.WriteXmlns(kGainMapPrefix, kGainMapUri);
   writer.WriteAttributeNameAndValue(kMapVersion, metadata.version);
-  writer.WriteAttributeNameAndValue(kMapGainMapMin, log2(metadata.minContentBoost));
-  writer.WriteAttributeNameAndValue(kMapGainMapMax, log2(metadata.maxContentBoost));
+  writer.WriteAttributeNameAndValue(kMapGainMapMin, log2(metadata.min_content_boost));
+  writer.WriteAttributeNameAndValue(kMapGainMapMax, log2(metadata.max_content_boost));
   writer.WriteAttributeNameAndValue(kMapGamma, metadata.gamma);
-  writer.WriteAttributeNameAndValue(kMapOffsetSdr, metadata.offsetSdr);
-  writer.WriteAttributeNameAndValue(kMapOffsetHdr, metadata.offsetHdr);
-  writer.WriteAttributeNameAndValue(kMapHDRCapacityMin, log2(metadata.hdrCapacityMin));
-  writer.WriteAttributeNameAndValue(kMapHDRCapacityMax, log2(metadata.hdrCapacityMax));
+  writer.WriteAttributeNameAndValue(kMapOffsetSdr, metadata.offset_sdr);
+  writer.WriteAttributeNameAndValue(kMapOffsetHdr, metadata.offset_hdr);
+  writer.WriteAttributeNameAndValue(kMapHDRCapacityMin, log2(metadata.hdr_capacity_min));
+  writer.WriteAttributeNameAndValue(kMapHDRCapacityMax, log2(metadata.hdr_capacity_max));
   writer.WriteAttributeNameAndValue(kMapBaseRenditionIsHDR, "False");
   writer.FinishWriting();
 
diff --git a/lib/src/ultrahdr_api.cpp b/lib/src/ultrahdr_api.cpp
index 96ccd38..bf882ac 100644
--- a/lib/src/ultrahdr_api.cpp
+++ b/lib/src/ultrahdr_api.cpp
@@ -24,7 +24,13 @@
 #include "ultrahdr/jpegr.h"
 #include "ultrahdr/jpegrutils.h"
 
-static const uhdr_error_info_t g_no_error = {UHDR_CODEC_OK, 0, ""};
+#include "image_io/base/data_segment_data_source.h"
+#include "image_io/jpeg/jpeg_info.h"
+#include "image_io/jpeg/jpeg_info_builder.h"
+#include "image_io/jpeg/jpeg_marker.h"
+#include "image_io/jpeg/jpeg_scanner.h"
+
+using namespace photos_editing_formats::image_io;
 
 namespace ultrahdr {
 
@@ -47,8 +53,10 @@ uhdr_raw_image_ext::uhdr_raw_image_ext(uhdr_img_fmt_t fmt_, uhdr_color_gamut_t c
   int aligned_width = ALIGNM(w_, align_stride_to);
 
   int bpp = 1;
-  if (fmt_ == UHDR_IMG_FMT_24bppYCbCrP010) {
+  if (fmt_ == UHDR_IMG_FMT_24bppYCbCrP010 || fmt_ == UHDR_IMG_FMT_30bppYCbCr444) {
     bpp = 2;
+  } else if (fmt_ == UHDR_IMG_FMT_24bppRGB888) {
+    bpp = 3;
   } else if (fmt_ == UHDR_IMG_FMT_32bppRGBA8888 || fmt_ == UHDR_IMG_FMT_32bppRGBA1010102) {
     bpp = 4;
   } else if (fmt_ == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
@@ -61,6 +69,9 @@ uhdr_raw_image_ext::uhdr_raw_image_ext(uhdr_img_fmt_t fmt_, uhdr_color_gamut_t c
   if (fmt_ == UHDR_IMG_FMT_24bppYCbCrP010) {
     plane_2_sz = (2 /* planes */ * ((aligned_width / 2) * (h_ / 2) * bpp));
     plane_3_sz = 0;
+  } else if (fmt_ == UHDR_IMG_FMT_30bppYCbCr444 || fmt_ == UHDR_IMG_FMT_24bppYCbCr444) {
+    plane_2_sz = bpp * aligned_width * h_;
+    plane_3_sz = bpp * aligned_width * h_;
   } else if (fmt_ == UHDR_IMG_FMT_12bppYCbCr420) {
     plane_2_sz = (((aligned_width / 2) * (h_ / 2) * bpp));
     plane_3_sz = (((aligned_width / 2) * (h_ / 2) * bpp));
@@ -79,6 +90,11 @@ uhdr_raw_image_ext::uhdr_raw_image_ext(uhdr_img_fmt_t fmt_, uhdr_color_gamut_t c
     this->stride[UHDR_PLANE_UV] = aligned_width;
     this->planes[UHDR_PLANE_V] = nullptr;
     this->stride[UHDR_PLANE_V] = 0;
+  } else if (fmt_ == UHDR_IMG_FMT_30bppYCbCr444 || fmt_ == UHDR_IMG_FMT_24bppYCbCr444) {
+    this->planes[UHDR_PLANE_U] = data + plane_1_sz;
+    this->stride[UHDR_PLANE_U] = aligned_width;
+    this->planes[UHDR_PLANE_V] = data + plane_1_sz + plane_2_sz;
+    this->stride[UHDR_PLANE_V] = aligned_width;
   } else if (fmt_ == UHDR_IMG_FMT_12bppYCbCr420) {
     this->planes[UHDR_PLANE_U] = data + plane_1_sz;
     this->stride[UHDR_PLANE_U] = aligned_width / 2;
@@ -129,13 +145,22 @@ uhdr_error_info_t apply_effects(uhdr_encoder_private* enc) {
       int left = (std::max)(0, crop_effect->m_left);
       int right = (std::min)((int)hdr_raw_entry->w, crop_effect->m_right);
       int crop_width = right - left;
-      if (crop_width <= 0 || (crop_width % 2 != 0)) {
+      if (crop_width <= 0) {
+        uhdr_error_info_t status;
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "unexpected crop dimensions. crop width is expected to be > 0, crop width is %d",
+                 crop_width);
+        return status;
+      }
+      if (crop_width % 2 != 0 && hdr_raw_entry->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
         uhdr_error_info_t status;
         status.error_code = UHDR_CODEC_INVALID_PARAM;
         status.has_detail = 1;
         snprintf(status.detail, sizeof status.detail,
-                 "unexpected crop dimensions. crop width is expected to be > 0 and even, crop "
-                 "width is %d",
+                 "unexpected crop dimensions. crop width is expected to even for format "
+                 "{UHDR_IMG_FMT_24bppYCbCrP010}, crop width is %d",
                  crop_width);
         return status;
       }
@@ -143,19 +168,48 @@ uhdr_error_info_t apply_effects(uhdr_encoder_private* enc) {
       int top = (std::max)(0, crop_effect->m_top);
       int bottom = (std::min)((int)hdr_raw_entry->h, crop_effect->m_bottom);
       int crop_height = bottom - top;
-      if (crop_height <= 0 || (crop_height % 2 != 0)) {
+      if (crop_height <= 0) {
         uhdr_error_info_t status;
         status.error_code = UHDR_CODEC_INVALID_PARAM;
         status.has_detail = 1;
         snprintf(status.detail, sizeof status.detail,
-                 "unexpected crop dimensions. crop height is expected to be > 0 and even, crop "
-                 "height is %d",
+                 "unexpected crop dimensions. crop height is expected to be > 0, crop height is %d",
+                 crop_height);
+        return status;
+      }
+      if (crop_height % 2 != 0 && hdr_raw_entry->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
+        uhdr_error_info_t status;
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        status.has_detail = 1;
+        snprintf(status.detail, sizeof status.detail,
+                 "unexpected crop dimensions. crop height is expected to even for format "
+                 "{UHDR_IMG_FMT_24bppYCbCrP010}. crop height is %d",
                  crop_height);
         return status;
       }
       apply_crop(hdr_raw_entry.get(), left, top, crop_width, crop_height);
       if (enc->m_raw_images.find(UHDR_SDR_IMG) != enc->m_raw_images.end()) {
         auto& sdr_raw_entry = enc->m_raw_images.find(UHDR_SDR_IMG)->second;
+        if (crop_width % 2 != 0 && sdr_raw_entry->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+          uhdr_error_info_t status;
+          status.error_code = UHDR_CODEC_INVALID_PARAM;
+          status.has_detail = 1;
+          snprintf(status.detail, sizeof status.detail,
+                   "unexpected crop dimensions. crop width is expected to even for format "
+                   "{UHDR_IMG_FMT_12bppYCbCr420}, crop width is %d",
+                   crop_width);
+          return status;
+        }
+        if (crop_height % 2 != 0 && sdr_raw_entry->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+          uhdr_error_info_t status;
+          status.error_code = UHDR_CODEC_INVALID_PARAM;
+          status.has_detail = 1;
+          snprintf(status.detail, sizeof status.detail,
+                   "unexpected crop dimensions. crop height is expected to even for format "
+                   "{UHDR_IMG_FMT_12bppYCbCr420}. crop height is %d",
+                   crop_height);
+          return status;
+        }
         apply_crop(sdr_raw_entry.get(), left, top, crop_width, crop_height);
       }
       continue;
@@ -163,20 +217,39 @@ uhdr_error_info_t apply_effects(uhdr_encoder_private* enc) {
       auto resize_effect = dynamic_cast<uhdr_resize_effect_t*>(it);
       int dst_w = resize_effect->m_width;
       int dst_h = resize_effect->m_height;
-      if (dst_w == 0 || dst_h == 0 || dst_w % 2 != 0 || dst_h % 2 != 0) {
+      auto& hdr_raw_entry = enc->m_raw_images.find(UHDR_HDR_IMG)->second;
+      if (dst_w <= 0 || dst_h <= 0) {
         uhdr_error_info_t status;
         status.error_code = UHDR_CODEC_INVALID_PARAM;
         snprintf(status.detail, sizeof status.detail,
-                 "destination dimension cannot be zero or odd. dest image width is %d, dest image "
+                 "destination dimensions cannot be <= zero. dest image width is %d, dest image "
                  "height is %d",
                  dst_w, dst_h);
         return status;
       }
-      auto& hdr_raw_entry = enc->m_raw_images.find(UHDR_HDR_IMG)->second;
+      if ((dst_w % 2 != 0 || dst_h % 2 != 0) && hdr_raw_entry->fmt == UHDR_IMG_FMT_24bppYCbCrP010) {
+        uhdr_error_info_t status;
+        status.error_code = UHDR_CODEC_INVALID_PARAM;
+        snprintf(status.detail, sizeof status.detail,
+                 "destination dimensions cannot be odd for format {UHDR_IMG_FMT_24bppYCbCrP010}. "
+                 "dest image width is %d, dest image height is %d",
+                 dst_w, dst_h);
+        return status;
+      }
       hdr_img =
           apply_resize(dynamic_cast<uhdr_resize_effect_t*>(it), hdr_raw_entry.get(), dst_w, dst_h);
       if (enc->m_raw_images.find(UHDR_SDR_IMG) != enc->m_raw_images.end()) {
         auto& sdr_raw_entry = enc->m_raw_images.find(UHDR_SDR_IMG)->second;
+        if ((dst_w % 2 != 0 || dst_h % 2 != 0) &&
+            sdr_raw_entry->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
+          uhdr_error_info_t status;
+          status.error_code = UHDR_CODEC_INVALID_PARAM;
+          snprintf(status.detail, sizeof status.detail,
+                   "destination dimensions cannot be odd for format {UHDR_IMG_FMT_12bppYCbCr420}. "
+                   "dest image width is %d, dest image height is %d",
+                   dst_w, dst_h);
+          return status;
+        }
         sdr_img = apply_resize(dynamic_cast<uhdr_resize_effect_t*>(it), sdr_raw_entry.get(), dst_w,
                                dst_h);
       }
@@ -196,37 +269,51 @@ uhdr_error_info_t apply_effects(uhdr_encoder_private* enc) {
       enc->m_raw_images.insert_or_assign(UHDR_SDR_IMG, std::move(sdr_img));
     }
   }
-  if (enc->m_effects.size() > 0) {
-    auto it = enc->m_effects.back();
-    if (nullptr != dynamic_cast<uhdr_crop_effect_t*>(it) &&
-        enc->m_raw_images.find(UHDR_SDR_IMG) != enc->m_raw_images.end()) {
-      // As cropping is handled via pointer arithmetic as opposed to buffer copy, u and v data of
-      // yuv420 inputs are no longer contiguous. As the library does not accept distinct buffer
-      // pointers for u and v for 420 input, copy the sdr intent to a contiguous buffer
-      auto& sdr_raw_entry = enc->m_raw_images.find(UHDR_SDR_IMG)->second;
-      enc->m_raw_images.insert_or_assign(UHDR_SDR_IMG,
-                                         convert_raw_input_to_ycbcr(sdr_raw_entry.get()));
-    }
-  }
 
   return g_no_error;
 }
 
+bool is_resize_effect(const ultrahdr::uhdr_effect_desc_t* effect) {
+  return dynamic_cast<const ultrahdr::uhdr_resize_effect_t*>(effect) != nullptr;
+}
+
 uhdr_error_info_t apply_effects(uhdr_decoder_private* dec) {
+  void *gl_ctxt = nullptr, *disp_texture_ptr = nullptr, *gm_texture_ptr = nullptr;
+#ifdef UHDR_ENABLE_GLES
+  if (dec->m_enable_gles) {
+    gl_ctxt = &dec->m_uhdr_gl_ctxt;
+    bool texture_created =
+        dec->m_uhdr_gl_ctxt.mDecodedImgTexture != 0 && dec->m_uhdr_gl_ctxt.mGainmapImgTexture != 0;
+    bool resize_effect_present = std::find_if(dec->m_effects.begin(), dec->m_effects.end(),
+                                              is_resize_effect) != dec->m_effects.end();
+    if (!texture_created && resize_effect_present &&
+        isBufferDataContiguous(dec->m_decoded_img_buffer.get()) &&
+        isBufferDataContiguous(dec->m_gainmap_img_buffer.get())) {
+      dec->m_uhdr_gl_ctxt.mDecodedImgTexture = dec->m_uhdr_gl_ctxt.create_texture(
+          dec->m_decoded_img_buffer->fmt, dec->m_decoded_img_buffer->w,
+          dec->m_decoded_img_buffer->h, dec->m_decoded_img_buffer->planes[0]);
+      dec->m_uhdr_gl_ctxt.mGainmapImgTexture = dec->m_uhdr_gl_ctxt.create_texture(
+          dec->m_gainmap_img_buffer->fmt, dec->m_gainmap_img_buffer->w,
+          dec->m_gainmap_img_buffer->h, dec->m_gainmap_img_buffer->planes[0]);
+    }
+    disp_texture_ptr = &dec->m_uhdr_gl_ctxt.mDecodedImgTexture;
+    gm_texture_ptr = &dec->m_uhdr_gl_ctxt.mGainmapImgTexture;
+  }
+#endif
   for (auto& it : dec->m_effects) {
     std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> disp_img = nullptr;
     std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> gm_img = nullptr;
 
     if (nullptr != dynamic_cast<uhdr_rotate_effect_t*>(it)) {
-      disp_img =
-          apply_rotate(dynamic_cast<uhdr_rotate_effect_t*>(it), dec->m_decoded_img_buffer.get());
-      gm_img =
-          apply_rotate(dynamic_cast<uhdr_rotate_effect_t*>(it), dec->m_gainmap_img_buffer.get());
+      disp_img = apply_rotate(dynamic_cast<uhdr_rotate_effect_t*>(it),
+                              dec->m_decoded_img_buffer.get(), gl_ctxt, disp_texture_ptr);
+      gm_img = apply_rotate(dynamic_cast<uhdr_rotate_effect_t*>(it),
+                            dec->m_gainmap_img_buffer.get(), gl_ctxt, gm_texture_ptr);
     } else if (nullptr != dynamic_cast<uhdr_mirror_effect_t*>(it)) {
-      disp_img =
-          apply_mirror(dynamic_cast<uhdr_mirror_effect_t*>(it), dec->m_decoded_img_buffer.get());
-      gm_img =
-          apply_mirror(dynamic_cast<uhdr_mirror_effect_t*>(it), dec->m_gainmap_img_buffer.get());
+      disp_img = apply_mirror(dynamic_cast<uhdr_mirror_effect_t*>(it),
+                              dec->m_decoded_img_buffer.get(), gl_ctxt, disp_texture_ptr);
+      gm_img = apply_mirror(dynamic_cast<uhdr_mirror_effect_t*>(it),
+                            dec->m_gainmap_img_buffer.get(), gl_ctxt, gm_texture_ptr);
     } else if (nullptr != dynamic_cast<uhdr_crop_effect_t*>(it)) {
       auto crop_effect = dynamic_cast<uhdr_crop_effect_t*>(it);
       uhdr_raw_image_t* disp = dec->m_decoded_img_buffer.get();
@@ -285,8 +372,9 @@ uhdr_error_info_t apply_effects(uhdr_decoder_private* dec) {
         return status;
       }
 
-      apply_crop(disp, left, top, right - left, bottom - top);
-      apply_crop(gm, gm_left, gm_top, (gm_right - gm_left), (gm_bottom - gm_top));
+      apply_crop(disp, left, top, right - left, bottom - top, gl_ctxt, disp_texture_ptr);
+      apply_crop(gm, gm_left, gm_top, (gm_right - gm_left), (gm_bottom - gm_top), gl_ctxt,
+                 gm_texture_ptr);
       continue;
     } else if (nullptr != dynamic_cast<uhdr_resize_effect_t*>(it)) {
       auto resize_effect = dynamic_cast<uhdr_resize_effect_t*>(it);
@@ -298,19 +386,21 @@ uhdr_error_info_t apply_effects(uhdr_decoder_private* dec) {
           ((float)dec->m_decoded_img_buffer.get()->h) / dec->m_gainmap_img_buffer.get()->h;
       int dst_gm_w = dst_w / wd_ratio;
       int dst_gm_h = dst_h / ht_ratio;
-      if (dst_w == 0 || dst_h == 0 || dst_gm_w == 0 || dst_gm_h == 0) {
+      if (dst_w <= 0 || dst_h <= 0 || dst_gm_w <= 0 || dst_gm_h <= 0) {
         uhdr_error_info_t status;
         status.error_code = UHDR_CODEC_INVALID_PARAM;
         snprintf(status.detail, sizeof status.detail,
-                 "destination dimension cannot be zero. dest image width is %d, dest image height "
-                 "is %d, dest gainmap width is %d, dest gainmap height is %d",
+                 "destination dimension cannot be <= zero. dest image width is %d, dest image "
+                 "height is %d, dest gainmap width is %d, dest gainmap height is %d",
                  dst_w, dst_h, dst_gm_w, dst_gm_h);
         return status;
       }
-      disp_img = apply_resize(dynamic_cast<uhdr_resize_effect_t*>(it),
-                              dec->m_decoded_img_buffer.get(), dst_w, dst_h);
-      gm_img = apply_resize(dynamic_cast<uhdr_resize_effect_t*>(it),
-                            dec->m_gainmap_img_buffer.get(), dst_gm_w, dst_gm_h);
+      disp_img =
+          apply_resize(dynamic_cast<uhdr_resize_effect_t*>(it), dec->m_decoded_img_buffer.get(),
+                       dst_w, dst_h, gl_ctxt, disp_texture_ptr);
+      gm_img =
+          apply_resize(dynamic_cast<uhdr_resize_effect_t*>(it), dec->m_gainmap_img_buffer.get(),
+                       dst_gm_w, dst_gm_h, gl_ctxt, gm_texture_ptr);
     }
 
     if (disp_img == nullptr || gm_img == nullptr) {
@@ -324,7 +414,6 @@ uhdr_error_info_t apply_effects(uhdr_decoder_private* dec) {
     dec->m_decoded_img_buffer = std::move(disp_img);
     dec->m_gainmap_img_buffer = std::move(gm_img);
   }
-
   return g_no_error;
 }
 
@@ -335,105 +424,6 @@ uhdr_codec_private::~uhdr_codec_private() {
   m_effects.clear();
 }
 
-ultrahdr::ultrahdr_color_gamut map_cg_to_internal_cg(uhdr_color_gamut_t cg) {
-  switch (cg) {
-    case UHDR_CG_BT_2100:
-      return ultrahdr::ULTRAHDR_COLORGAMUT_BT2100;
-    case UHDR_CG_BT_709:
-      return ultrahdr::ULTRAHDR_COLORGAMUT_BT709;
-    case UHDR_CG_DISPLAY_P3:
-      return ultrahdr::ULTRAHDR_COLORGAMUT_P3;
-    default:
-      return ultrahdr::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-  }
-}
-
-uhdr_color_gamut_t map_internal_cg_to_cg(ultrahdr::ultrahdr_color_gamut cg) {
-  switch (cg) {
-    case ultrahdr::ULTRAHDR_COLORGAMUT_BT2100:
-      return UHDR_CG_BT_2100;
-    case ultrahdr::ULTRAHDR_COLORGAMUT_BT709:
-      return UHDR_CG_BT_709;
-    case ultrahdr::ULTRAHDR_COLORGAMUT_P3:
-      return UHDR_CG_DISPLAY_P3;
-    default:
-      return UHDR_CG_UNSPECIFIED;
-  }
-}
-
-ultrahdr::ultrahdr_transfer_function map_ct_to_internal_ct(uhdr_color_transfer_t ct) {
-  switch (ct) {
-    case UHDR_CT_HLG:
-      return ultrahdr::ULTRAHDR_TF_HLG;
-    case UHDR_CT_PQ:
-      return ultrahdr::ULTRAHDR_TF_PQ;
-    case UHDR_CT_LINEAR:
-      return ultrahdr::ULTRAHDR_TF_LINEAR;
-    case UHDR_CT_SRGB:
-      return ultrahdr::ULTRAHDR_TF_SRGB;
-    default:
-      return ultrahdr::ULTRAHDR_TF_UNSPECIFIED;
-  }
-}
-
-ultrahdr::ultrahdr_output_format map_ct_fmt_to_internal_output_fmt(uhdr_color_transfer_t ct,
-                                                                   uhdr_img_fmt fmt) {
-  if (ct == UHDR_CT_HLG && fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
-    return ultrahdr::ULTRAHDR_OUTPUT_HDR_HLG;
-  } else if (ct == UHDR_CT_PQ && fmt == UHDR_IMG_FMT_32bppRGBA1010102) {
-    return ultrahdr::ULTRAHDR_OUTPUT_HDR_PQ;
-  } else if (ct == UHDR_CT_LINEAR && fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat) {
-    return ultrahdr::ULTRAHDR_OUTPUT_HDR_LINEAR;
-  } else if (ct == UHDR_CT_SRGB && fmt == UHDR_IMG_FMT_32bppRGBA8888) {
-    return ultrahdr::ULTRAHDR_OUTPUT_SDR;
-  }
-  return ultrahdr::ULTRAHDR_OUTPUT_UNSPECIFIED;
-}
-
-void map_internal_error_status_to_error_info(ultrahdr::status_t internal_status,
-                                             uhdr_error_info_t& status) {
-  if (internal_status == ultrahdr::JPEGR_NO_ERROR) {
-    status = g_no_error;
-  } else {
-    status.has_detail = 1;
-    if (internal_status == ultrahdr::ERROR_JPEGR_RESOLUTION_MISMATCH) {
-      status.error_code = UHDR_CODEC_INVALID_PARAM;
-      snprintf(status.detail, sizeof status.detail,
-               "dimensions of sdr intent and hdr intent do not match");
-    } else if (internal_status == ultrahdr::ERROR_JPEGR_ENCODE_ERROR) {
-      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
-      snprintf(status.detail, sizeof status.detail, "encountered unknown error during encoding");
-    } else if (internal_status == ultrahdr::ERROR_JPEGR_DECODE_ERROR) {
-      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
-      snprintf(status.detail, sizeof status.detail, "encountered unknown error during decoding");
-    } else if (internal_status == ultrahdr::ERROR_JPEGR_NO_IMAGES_FOUND) {
-      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
-      snprintf(status.detail, sizeof status.detail, "input uhdr image does not any valid images");
-    } else if (internal_status == ultrahdr::ERROR_JPEGR_GAIN_MAP_IMAGE_NOT_FOUND) {
-      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
-      snprintf(status.detail, sizeof status.detail,
-               "input uhdr image does not contain gainmap image");
-    } else if (internal_status == ultrahdr::ERROR_JPEGR_BUFFER_TOO_SMALL) {
-      status.error_code = UHDR_CODEC_MEM_ERROR;
-      snprintf(status.detail, sizeof status.detail,
-               "output buffer to store compressed data is too small");
-    } else if (internal_status == ultrahdr::ERROR_JPEGR_MULTIPLE_EXIFS_RECEIVED) {
-      status.error_code = UHDR_CODEC_INVALID_OPERATION;
-      snprintf(status.detail, sizeof status.detail,
-               "received exif from uhdr_enc_set_exif_data() while the base image intent already "
-               "contains exif, unsure which one to use");
-    } else if (internal_status == ultrahdr::ERROR_JPEGR_UNSUPPORTED_MAP_SCALE_FACTOR) {
-      status.error_code = UHDR_CODEC_UNSUPPORTED_FEATURE;
-      snprintf(status.detail, sizeof status.detail,
-               "say base image wd to gain map image wd ratio is 'k1' and base image ht to gain map "
-               "image ht ratio is 'k2', we found k1 != k2.");
-    } else {
-      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
-      status.has_detail = 0;
-    }
-  }
-}
-
 uhdr_error_info_t uhdr_enc_validate_and_set_compressed_img(uhdr_codec_private_t* enc,
                                                            uhdr_compressed_image_t* img,
                                                            uhdr_img_label_t intent) {
@@ -470,10 +460,42 @@ uhdr_error_info_t uhdr_enc_validate_and_set_compressed_img(uhdr_codec_private_t*
     return status;
   }
 
+  std::shared_ptr<DataSegment> seg =
+      DataSegment::Create(DataRange(0, img->data_sz), static_cast<const uint8_t*>(img->data),
+                          DataSegment::BufferDispositionPolicy::kDontDelete);
+  DataSegmentDataSource data_source(seg);
+  JpegInfoBuilder jpeg_info_builder;
+  JpegScanner jpeg_scanner(nullptr);
+  jpeg_scanner.Run(&data_source, &jpeg_info_builder);
+  data_source.Reset();
+  if (jpeg_scanner.HasError()) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    snprintf(status.detail, sizeof status.detail,
+             "received bad/corrupted jpeg image as part of input configuration");
+    return status;
+  }
+
+  const auto& image_ranges = jpeg_info_builder.GetInfo().GetImageRanges();
+  if (image_ranges.empty()) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "compressed image received as part of input config contains no valid jpeg images");
+    return status;
+  }
+
+  if (image_ranges.size() > 1) {
+    ALOGW(
+        "compressed image received as part of input config contains multiple jpeg images, "
+        "selecting first image for intent %d, rest are ignored",
+        intent);
+  }
+
   auto entry = std::make_unique<ultrahdr::uhdr_compressed_image_ext_t>(img->cg, img->ct, img->range,
-                                                                       img->data_sz);
-  memcpy(entry->data, img->data, img->data_sz);
-  entry->data_sz = img->data_sz;
+                                                                       image_ranges[0].GetLength());
+  memcpy(entry->data, static_cast<uint8_t*>(img->data) + image_ranges[0].GetBegin(),
+         image_ranges[0].GetLength());
+  entry->data_sz = image_ranges[0].GetLength();
   handle->m_compressed_images.insert_or_assign(intent, std::move(entry));
 
   return status;
@@ -495,6 +517,184 @@ void uhdr_release_encoder(uhdr_codec_private_t* enc) {
   }
 }
 
+UHDR_EXTERN uhdr_error_info_t
+uhdr_enc_set_using_multi_channel_gainmap(uhdr_codec_private_t* enc, int use_multi_channel_gainmap) {
+  uhdr_error_info_t status = g_no_error;
+
+  if (dynamic_cast<uhdr_encoder_private*>(enc) == nullptr) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
+    return status;
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
+  handle->m_use_multi_channel_gainmap = use_multi_channel_gainmap;
+
+  return status;
+}
+
+UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_scale_factor(uhdr_codec_private_t* enc,
+                                                                int gainmap_scale_factor) {
+  uhdr_error_info_t status = g_no_error;
+
+  if (dynamic_cast<uhdr_encoder_private*>(enc) == nullptr) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
+    return status;
+  }
+
+  if (gainmap_scale_factor <= 0 || gainmap_scale_factor > 128) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "gainmap scale factor is expected to be in range (0, 128], received %d",
+             gainmap_scale_factor);
+    return status;
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
+  handle->m_gainmap_scale_factor = gainmap_scale_factor;
+
+  return status;
+}
+
+UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_gamma(uhdr_codec_private_t* enc, float gamma) {
+  uhdr_error_info_t status = g_no_error;
+
+  if (dynamic_cast<uhdr_encoder_private*>(enc) == nullptr) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
+    return status;
+  }
+
+  if (gamma <= 0.0f) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "unsupported gainmap gamma %f, expects to be > 0",
+             gamma);
+    return status;
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
+  handle->m_gamma = gamma;
+
+  return status;
+}
+
+uhdr_error_info_t uhdr_enc_set_preset(uhdr_codec_private_t* enc, uhdr_enc_preset_t preset) {
+  uhdr_error_info_t status = g_no_error;
+
+  if (dynamic_cast<uhdr_encoder_private*>(enc) == nullptr) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
+    return status;
+  }
+
+  if (preset != UHDR_USAGE_REALTIME && preset != UHDR_USAGE_BEST_QUALITY) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "invalid preset %d, expects one of {UHDR_USAGE_REALTIME, UHDR_USAGE_BEST_QUALITY}",
+             preset);
+    return status;
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
+  handle->m_enc_preset = preset;
+
+  return status;
+}
+
+uhdr_error_info_t uhdr_enc_set_min_max_content_boost(uhdr_codec_private_t* enc, float min_boost,
+                                                     float max_boost) {
+  uhdr_error_info_t status = g_no_error;
+
+  if (dynamic_cast<uhdr_encoder_private*>(enc) == nullptr) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
+    return status;
+  }
+
+  if (max_boost < min_boost) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "Invalid min boost / max boost configuration. configured max boost %f is less than "
+             "min boost %f",
+             max_boost, min_boost);
+    return status;
+  }
+
+  if (min_boost < 0) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail,
+             "Invalid min boost configuration. configured min boost %f is less than 0", min_boost);
+    return status;
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
+  handle->m_min_content_boost = min_boost;
+  handle->m_max_content_boost = max_boost;
+
+  return status;
+}
+
 uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_image_t* img,
                                          uhdr_img_label_t intent) {
   uhdr_error_info_t status = g_no_error;
@@ -536,12 +736,12 @@ uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_ima
              "invalid input color gamut %d, expects one of {UHDR_CG_BT_2100, UHDR_CG_DISPLAY_P3, "
              "UHDR_CG_BT_709}",
              img->cg);
-  } else if (img->fmt == UHDR_IMG_FMT_12bppYCbCr420 && img->ct != UHDR_CT_SRGB) {
+  } else if (intent == UHDR_SDR_IMG && img->ct != UHDR_CT_SRGB) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
              "invalid input color transfer for sdr intent image %d, expects UHDR_CT_SRGB", img->ct);
-  } else if (img->fmt == UHDR_IMG_FMT_24bppYCbCrP010 &&
+  } else if (intent == UHDR_HDR_IMG &&
              (img->ct != UHDR_CT_HLG && img->ct != UHDR_CT_LINEAR && img->ct != UHDR_CT_PQ)) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
@@ -549,18 +749,21 @@ uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_ima
              "invalid input color transfer for hdr intent image %d, expects one of {UHDR_CT_HLG, "
              "UHDR_CT_LINEAR, UHDR_CT_PQ}",
              img->ct);
-  } else if (img->w % 2 != 0 || img->h % 2 != 0) {
+  } else if ((img->w % 2 != 0 || img->h % 2 != 0) &&
+             (img->fmt == UHDR_IMG_FMT_12bppYCbCr420 || img->fmt == UHDR_IMG_FMT_24bppYCbCrP010)) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
-             "image dimensions cannot be odd, received image dimensions %dx%d", img->w, img->h);
-  } else if (img->w < ultrahdr::kMinWidth || img->h < ultrahdr::kMinHeight) {
+             "image dimensions cannot be odd for formats {UHDR_IMG_FMT_12bppYCbCr420, "
+             "UHDR_IMG_FMT_24bppYCbCrP010}, received image dimensions %dx%d",
+             img->w, img->h);
+  } else if ((int)img->w < ultrahdr::kMinWidth || (int)img->h < ultrahdr::kMinHeight) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
              "image dimensions cannot be less than %dx%d, received image dimensions %dx%d",
              ultrahdr::kMinWidth, ultrahdr::kMinHeight, img->w, img->h);
-  } else if (img->w > ultrahdr::kMaxWidth || img->h > ultrahdr::kMaxHeight) {
+  } else if ((int)img->w > ultrahdr::kMaxWidth || (int)img->h > ultrahdr::kMaxHeight) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
@@ -585,6 +788,17 @@ uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_ima
       snprintf(status.detail, sizeof status.detail,
                "chroma_uv stride must not be smaller than width, stride=%d, width=%d",
                img->stride[UHDR_PLANE_UV], img->w);
+    } else if (img->fmt == UHDR_IMG_FMT_24bppYCbCrP010 &&
+               (img->range != UHDR_CR_FULL_RANGE && img->range != UHDR_CR_LIMITED_RANGE)) {
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "invalid range, expects one of {UHDR_CR_FULL_RANGE, UHDR_CR_LIMITED_RANGE}");
+    } else if (img->fmt == UHDR_IMG_FMT_32bppRGBA1010102 && img->range != UHDR_CR_FULL_RANGE) {
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "invalid range, expects one of {UHDR_CR_FULL_RANGE}");
     }
   } else if (img->fmt == UHDR_IMG_FMT_12bppYCbCr420) {
     if (img->planes[UHDR_PLANE_Y] == nullptr || img->planes[UHDR_PLANE_U] == nullptr ||
@@ -612,6 +826,30 @@ uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_ima
       snprintf(status.detail, sizeof status.detail,
                "chroma_v stride must not be smaller than width / 2, stride=%d, width=%d",
                img->stride[UHDR_PLANE_V], img->w);
+    } else if (img->range != UHDR_CR_FULL_RANGE) {
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "invalid range, expects one of {UHDR_CR_FULL_RANGE}");
+    }
+  } else if (img->fmt == UHDR_IMG_FMT_32bppRGBA1010102 || img->fmt == UHDR_IMG_FMT_32bppRGBA8888) {
+    if (img->planes[UHDR_PLANE_PACKED] == nullptr) {
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "received nullptr for data field(s) rgb plane packed ptr %p",
+               img->planes[UHDR_PLANE_PACKED]);
+    } else if (img->stride[UHDR_PLANE_PACKED] < img->w) {
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "rgb planar stride must not be smaller than width, stride=%d, width=%d",
+               img->stride[UHDR_PLANE_PACKED], img->w);
+    } else if (img->range != UHDR_CR_FULL_RANGE) {
+      status.error_code = UHDR_CODEC_INVALID_PARAM;
+      status.has_detail = 1;
+      snprintf(status.detail, sizeof status.detail,
+               "invalid range, expects one of {UHDR_CR_FULL_RANGE}");
     }
   }
   if (status.error_code != UHDR_CODEC_OK) return status;
@@ -650,7 +888,7 @@ uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc, uhdr_raw_ima
     return status;
   }
 
-  std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> entry = ultrahdr::convert_raw_input_to_ycbcr(img);
+  std::unique_ptr<ultrahdr::uhdr_raw_image_ext_t> entry = ultrahdr::copy_raw_image(img);
   if (entry == nullptr) {
     status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
     status.has_detail = 1;
@@ -908,52 +1146,31 @@ uhdr_error_info_t uhdr_encode(uhdr_codec_private_t* enc) {
     }
   }
 
-  ultrahdr::status_t internal_status = ultrahdr::JPEGR_NO_ERROR;
   if (handle->m_output_format == UHDR_CODEC_JPG) {
-    ultrahdr::jpegr_exif_struct exif{};
+    uhdr_mem_block_t exif{};
     if (handle->m_exif.size() > 0) {
       exif.data = handle->m_exif.data();
-      exif.length = handle->m_exif.size();
+      exif.capacity = exif.data_sz = handle->m_exif.size();
     }
 
-    ultrahdr::JpegR jpegr;
-    ultrahdr::jpegr_compressed_struct dest{};
+    ultrahdr::JpegR jpegr(
+        nullptr, handle->m_gainmap_scale_factor, handle->m_quality.find(UHDR_GAIN_MAP_IMG)->second,
+        handle->m_use_multi_channel_gainmap, handle->m_gamma, handle->m_enc_preset,
+        handle->m_min_content_boost, handle->m_max_content_boost);
     if (handle->m_compressed_images.find(UHDR_BASE_IMG) != handle->m_compressed_images.end() &&
         handle->m_compressed_images.find(UHDR_GAIN_MAP_IMG) != handle->m_compressed_images.end()) {
       auto& base_entry = handle->m_compressed_images.find(UHDR_BASE_IMG)->second;
-      ultrahdr::jpegr_compressed_struct primary_image;
-      primary_image.data = base_entry->data;
-      primary_image.length = primary_image.maxLength = base_entry->data_sz;
-      primary_image.colorGamut = map_cg_to_internal_cg(base_entry->cg);
-
       auto& gainmap_entry = handle->m_compressed_images.find(UHDR_GAIN_MAP_IMG)->second;
-      ultrahdr::jpegr_compressed_struct gainmap_image;
-      gainmap_image.data = gainmap_entry->data;
-      gainmap_image.length = gainmap_image.maxLength = gainmap_entry->data_sz;
-      gainmap_image.colorGamut = map_cg_to_internal_cg(gainmap_entry->cg);
-
-      ultrahdr::ultrahdr_metadata_struct metadata;
-      metadata.version = ultrahdr::kJpegrVersion;
-      metadata.maxContentBoost = handle->m_metadata.max_content_boost;
-      metadata.minContentBoost = handle->m_metadata.min_content_boost;
-      metadata.gamma = handle->m_metadata.gamma;
-      metadata.offsetSdr = handle->m_metadata.offset_sdr;
-      metadata.offsetHdr = handle->m_metadata.offset_hdr;
-      metadata.hdrCapacityMin = handle->m_metadata.hdr_capacity_min;
-      metadata.hdrCapacityMax = handle->m_metadata.hdr_capacity_max;
-
-      size_t size = (std::max)((8 * 1024), 2 * (primary_image.length + gainmap_image.length));
+
+      size_t size = (std::max)((8u * 1024), 2 * (base_entry->data_sz + gainmap_entry->data_sz));
       handle->m_compressed_output_buffer = std::make_unique<ultrahdr::uhdr_compressed_image_ext_t>(
           UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, size);
 
-      dest.data = handle->m_compressed_output_buffer->data;
-      dest.length = 0;
-      dest.maxLength = handle->m_compressed_output_buffer->capacity;
-      dest.colorGamut = ultrahdr::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+      ultrahdr::uhdr_gainmap_metadata_ext_t metadata(handle->m_metadata, ultrahdr::kJpegrVersion);
 
       // api - 4
-      internal_status = jpegr.encodeJPEGR(&primary_image, &gainmap_image, &metadata, &dest);
-      map_internal_error_status_to_error_info(internal_status, status);
+      status = jpegr.encodeJPEGR(base_entry.get(), gainmap_entry.get(), &metadata,
+                                 handle->m_compressed_output_buffer.get());
     } else if (handle->m_raw_images.find(UHDR_HDR_IMG) != handle->m_raw_images.end()) {
       auto& hdr_raw_entry = handle->m_raw_images.find(UHDR_HDR_IMG)->second;
 
@@ -961,82 +1178,42 @@ uhdr_error_info_t uhdr_encode(uhdr_codec_private_t* enc) {
       handle->m_compressed_output_buffer = std::make_unique<ultrahdr::uhdr_compressed_image_ext_t>(
           UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, size);
 
-      dest.data = handle->m_compressed_output_buffer->data;
-      dest.length = 0;
-      dest.maxLength = handle->m_compressed_output_buffer->capacity;
-      dest.colorGamut = ultrahdr::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-
-      ultrahdr::jpegr_uncompressed_struct p010_image;
-      p010_image.data = hdr_raw_entry->planes[UHDR_PLANE_Y];
-      p010_image.width = hdr_raw_entry->w;
-      p010_image.height = hdr_raw_entry->h;
-      p010_image.colorGamut = map_cg_to_internal_cg(hdr_raw_entry->cg);
-      p010_image.luma_stride = hdr_raw_entry->stride[UHDR_PLANE_Y];
-      p010_image.chroma_data = hdr_raw_entry->planes[UHDR_PLANE_UV];
-      p010_image.chroma_stride = hdr_raw_entry->stride[UHDR_PLANE_UV];
-      p010_image.pixelFormat = hdr_raw_entry->fmt;
-
       if (handle->m_compressed_images.find(UHDR_SDR_IMG) == handle->m_compressed_images.end() &&
           handle->m_raw_images.find(UHDR_SDR_IMG) == handle->m_raw_images.end()) {
         // api - 0
-        internal_status = jpegr.encodeJPEGR(&p010_image, map_ct_to_internal_ct(hdr_raw_entry->ct),
-                                            &dest, handle->m_quality.find(UHDR_BASE_IMG)->second,
-                                            handle->m_exif.size() > 0 ? &exif : nullptr);
+        status = jpegr.encodeJPEGR(hdr_raw_entry.get(), handle->m_compressed_output_buffer.get(),
+                                   handle->m_quality.find(UHDR_BASE_IMG)->second,
+                                   handle->m_exif.size() > 0 ? &exif : nullptr);
       } else if (handle->m_compressed_images.find(UHDR_SDR_IMG) !=
                      handle->m_compressed_images.end() &&
                  handle->m_raw_images.find(UHDR_SDR_IMG) == handle->m_raw_images.end()) {
         auto& sdr_compressed_entry = handle->m_compressed_images.find(UHDR_SDR_IMG)->second;
-        ultrahdr::jpegr_compressed_struct sdr_compressed_image;
-        sdr_compressed_image.data = sdr_compressed_entry->data;
-        sdr_compressed_image.length = sdr_compressed_image.maxLength =
-            sdr_compressed_entry->data_sz;
-        sdr_compressed_image.colorGamut = map_cg_to_internal_cg(sdr_compressed_entry->cg);
         // api - 3
-        internal_status = jpegr.encodeJPEGR(&p010_image, &sdr_compressed_image,
-                                            map_ct_to_internal_ct(hdr_raw_entry->ct), &dest);
+        status = jpegr.encodeJPEGR(hdr_raw_entry.get(), sdr_compressed_entry.get(),
+                                   handle->m_compressed_output_buffer.get());
       } else if (handle->m_raw_images.find(UHDR_SDR_IMG) != handle->m_raw_images.end()) {
         auto& sdr_raw_entry = handle->m_raw_images.find(UHDR_SDR_IMG)->second;
 
-        ultrahdr::jpegr_uncompressed_struct yuv420_image;
-        yuv420_image.data = sdr_raw_entry->planes[UHDR_PLANE_Y];
-        yuv420_image.width = sdr_raw_entry->w;
-        yuv420_image.height = sdr_raw_entry->h;
-        yuv420_image.colorGamut = map_cg_to_internal_cg(sdr_raw_entry->cg);
-        yuv420_image.luma_stride = sdr_raw_entry->stride[UHDR_PLANE_Y];
-        yuv420_image.chroma_data = nullptr;
-        yuv420_image.chroma_stride = 0;
-        yuv420_image.pixelFormat = sdr_raw_entry->fmt;
-
         if (handle->m_compressed_images.find(UHDR_SDR_IMG) == handle->m_compressed_images.end()) {
           // api - 1
-          internal_status = jpegr.encodeJPEGR(&p010_image, &yuv420_image,
-                                              map_ct_to_internal_ct(hdr_raw_entry->ct), &dest,
-                                              handle->m_quality.find(UHDR_BASE_IMG)->second,
-                                              handle->m_exif.size() > 0 ? &exif : nullptr);
+          status = jpegr.encodeJPEGR(hdr_raw_entry.get(), sdr_raw_entry.get(),
+                                     handle->m_compressed_output_buffer.get(),
+                                     handle->m_quality.find(UHDR_BASE_IMG)->second,
+                                     handle->m_exif.size() > 0 ? &exif : nullptr);
         } else {
           auto& sdr_compressed_entry = handle->m_compressed_images.find(UHDR_SDR_IMG)->second;
-          ultrahdr::jpegr_compressed_struct sdr_compressed_image;
-          sdr_compressed_image.data = sdr_compressed_entry->data;
-          sdr_compressed_image.length = sdr_compressed_image.maxLength =
-              sdr_compressed_entry->data_sz;
-          sdr_compressed_image.colorGamut = map_cg_to_internal_cg(sdr_compressed_entry->cg);
-
           // api - 2
-          internal_status = jpegr.encodeJPEGR(&p010_image, &yuv420_image, &sdr_compressed_image,
-                                              map_ct_to_internal_ct(hdr_raw_entry->ct), &dest);
+          status = jpegr.encodeJPEGR(hdr_raw_entry.get(), sdr_raw_entry.get(),
+                                     sdr_compressed_entry.get(),
+                                     handle->m_compressed_output_buffer.get());
         }
       }
-      map_internal_error_status_to_error_info(internal_status, status);
     } else {
       status.error_code = UHDR_CODEC_INVALID_OPERATION;
       status.has_detail = 1;
       snprintf(status.detail, sizeof status.detail,
                "resources required for uhdr_encode() operation are not present");
     }
-    if (status.error_code == UHDR_CODEC_OK) {
-      handle->m_compressed_output_buffer->data_sz = dest.length;
-      handle->m_compressed_output_buffer->cg = map_internal_cg_to_cg(dest.colorGamut);
-    }
   }
 
   return status;
@@ -1062,17 +1239,27 @@ void uhdr_reset_encoder(uhdr_codec_private_t* enc) {
     // clear entries and restore defaults
     for (auto it : handle->m_effects) delete it;
     handle->m_effects.clear();
+#ifdef UHDR_ENABLE_GLES
+    handle->m_uhdr_gl_ctxt.reset_opengl_ctxt();
+    handle->m_enable_gles = false;
+#endif
+    handle->m_sailed = false;
     handle->m_raw_images.clear();
     handle->m_compressed_images.clear();
     handle->m_quality.clear();
-    handle->m_quality.emplace(UHDR_HDR_IMG, 95);
-    handle->m_quality.emplace(UHDR_SDR_IMG, 95);
-    handle->m_quality.emplace(UHDR_BASE_IMG, 95);
-    handle->m_quality.emplace(UHDR_GAIN_MAP_IMG, 85);
+    handle->m_quality.emplace(UHDR_HDR_IMG, ultrahdr::kBaseCompressQualityDefault);
+    handle->m_quality.emplace(UHDR_SDR_IMG, ultrahdr::kBaseCompressQualityDefault);
+    handle->m_quality.emplace(UHDR_BASE_IMG, ultrahdr::kBaseCompressQualityDefault);
+    handle->m_quality.emplace(UHDR_GAIN_MAP_IMG, ultrahdr::kMapCompressQualityDefault);
     handle->m_exif.clear();
     handle->m_output_format = UHDR_CODEC_JPG;
+    handle->m_gainmap_scale_factor = ultrahdr::kMapDimensionScaleFactorDefault;
+    handle->m_use_multi_channel_gainmap = ultrahdr::kUseMultiChannelGainMapDefault;
+    handle->m_gamma = ultrahdr::kGainMapGammaDefault;
+    handle->m_enc_preset = ultrahdr::kEncSpeedPresetDefault;
+    handle->m_min_content_boost = FLT_MIN;
+    handle->m_max_content_boost = FLT_MAX;
 
-    handle->m_sailed = false;
     handle->m_compressed_output_buffer.reset();
     handle->m_encode_call_status = g_no_error;
   }
@@ -1289,45 +1476,42 @@ uhdr_error_info_t uhdr_dec_probe(uhdr_codec_private_t* dec) {
     jpegr_info.primaryImgInfo = &primary_image;
     jpegr_info.gainmapImgInfo = &gainmap_image;
 
-    ultrahdr::jpegr_compressed_struct uhdr_image;
-    uhdr_image.data = handle->m_uhdr_compressed_img->data;
-    uhdr_image.length = uhdr_image.maxLength = handle->m_uhdr_compressed_img->data_sz;
-    uhdr_image.colorGamut = map_cg_to_internal_cg(handle->m_uhdr_compressed_img->cg);
-
     ultrahdr::JpegR jpegr;
-    ultrahdr::status_t internal_status = jpegr.getJPEGRInfo(&uhdr_image, &jpegr_info);
-    map_internal_error_status_to_error_info(internal_status, status);
+    status = jpegr.getJPEGRInfo(handle->m_uhdr_compressed_img.get(), &jpegr_info);
     if (status.error_code != UHDR_CODEC_OK) return status;
 
-    ultrahdr::ultrahdr_metadata_struct metadata;
-    if (ultrahdr::getMetadataFromXMP(gainmap_image.xmpData.data(), gainmap_image.xmpData.size(),
-                                     &metadata)) {
-      handle->m_metadata.max_content_boost = metadata.maxContentBoost;
-      handle->m_metadata.min_content_boost = metadata.minContentBoost;
-      handle->m_metadata.gamma = metadata.gamma;
-      handle->m_metadata.offset_sdr = metadata.offsetSdr;
-      handle->m_metadata.offset_hdr = metadata.offsetHdr;
-      handle->m_metadata.hdr_capacity_min = metadata.hdrCapacityMin;
-      handle->m_metadata.hdr_capacity_max = metadata.hdrCapacityMax;
-    } else {
-      status.error_code = UHDR_CODEC_UNKNOWN_ERROR;
-      status.has_detail = 1;
-      snprintf(status.detail, sizeof status.detail, "encountered error while parsing metadata");
-      return status;
-    }
+    ultrahdr::uhdr_gainmap_metadata_ext_t metadata;
+    status = jpegr.parseGainMapMetadata(gainmap_image.isoData.data(), gainmap_image.isoData.size(),
+                                        gainmap_image.xmpData.data(), gainmap_image.xmpData.size(),
+                                        &metadata);
+    if (status.error_code != UHDR_CODEC_OK) return status;
+    handle->m_metadata.max_content_boost = metadata.max_content_boost;
+    handle->m_metadata.min_content_boost = metadata.min_content_boost;
+    handle->m_metadata.gamma = metadata.gamma;
+    handle->m_metadata.offset_sdr = metadata.offset_sdr;
+    handle->m_metadata.offset_hdr = metadata.offset_hdr;
+    handle->m_metadata.hdr_capacity_min = metadata.hdr_capacity_min;
+    handle->m_metadata.hdr_capacity_max = metadata.hdr_capacity_max;
 
     handle->m_img_wd = primary_image.width;
     handle->m_img_ht = primary_image.height;
     handle->m_gainmap_wd = gainmap_image.width;
     handle->m_gainmap_ht = gainmap_image.height;
+    handle->m_gainmap_num_comp = gainmap_image.numComponents;
     handle->m_exif = std::move(primary_image.exifData);
     handle->m_exif_block.data = handle->m_exif.data();
     handle->m_exif_block.data_sz = handle->m_exif_block.capacity = handle->m_exif.size();
     handle->m_icc = std::move(primary_image.iccData);
     handle->m_icc_block.data = handle->m_icc.data();
     handle->m_icc_block.data_sz = handle->m_icc_block.capacity = handle->m_icc.size();
-    handle->m_base_xmp = std::move(primary_image.xmpData);
-    handle->m_gainmap_xmp = std::move(gainmap_image.xmpData);
+    handle->m_base_img = std::move(primary_image.imgData);
+    handle->m_base_img_block.data = handle->m_base_img.data();
+    handle->m_base_img_block.data_sz = handle->m_base_img_block.capacity =
+        handle->m_base_img.size();
+    handle->m_gainmap_img = std::move(gainmap_image.imgData);
+    handle->m_gainmap_img_block.data = handle->m_gainmap_img.data();
+    handle->m_gainmap_img_block.data_sz = handle->m_gainmap_img_block.capacity =
+        handle->m_gainmap_img.size();
   }
 
   return status;
@@ -1411,7 +1595,33 @@ uhdr_mem_block_t* uhdr_dec_get_icc(uhdr_codec_private_t* dec) {
   return &handle->m_icc_block;
 }
 
-uhdr_gainmap_metadata_t* uhdr_dec_get_gain_map_metadata(uhdr_codec_private_t* dec) {
+uhdr_mem_block_t* uhdr_dec_get_base_image(uhdr_codec_private_t* dec) {
+  if (dynamic_cast<uhdr_decoder_private*>(dec) == nullptr) {
+    return nullptr;
+  }
+
+  uhdr_decoder_private* handle = dynamic_cast<uhdr_decoder_private*>(dec);
+  if (!handle->m_probed || handle->m_probe_call_status.error_code != UHDR_CODEC_OK) {
+    return nullptr;
+  }
+
+  return &handle->m_base_img_block;
+}
+
+uhdr_mem_block_t* uhdr_dec_get_gainmap_image(uhdr_codec_private_t* dec) {
+  if (dynamic_cast<uhdr_decoder_private*>(dec) == nullptr) {
+    return nullptr;
+  }
+
+  uhdr_decoder_private* handle = dynamic_cast<uhdr_decoder_private*>(dec);
+  if (!handle->m_probed || handle->m_probe_call_status.error_code != UHDR_CODEC_OK) {
+    return nullptr;
+  }
+
+  return &handle->m_gainmap_img_block;
+}
+
+uhdr_gainmap_metadata_t* uhdr_dec_get_gainmap_metadata(uhdr_codec_private_t* dec) {
   if (dynamic_cast<uhdr_decoder_private*>(dec) == nullptr) {
     return nullptr;
   }
@@ -1445,9 +1655,11 @@ uhdr_error_info_t uhdr_decode(uhdr_codec_private_t* dec) {
 
   handle->m_sailed = true;
 
-  ultrahdr::ultrahdr_output_format outputFormat =
-      map_ct_fmt_to_internal_output_fmt(handle->m_output_ct, handle->m_output_fmt);
-  if (outputFormat == ultrahdr::ultrahdr_output_format::ULTRAHDR_OUTPUT_UNSPECIFIED) {
+  if ((handle->m_output_fmt == UHDR_IMG_FMT_32bppRGBA1010102 &&
+       (handle->m_output_ct != UHDR_CT_HLG && handle->m_output_ct != UHDR_CT_PQ)) ||
+      (handle->m_output_fmt == UHDR_IMG_FMT_64bppRGBAHalfFloat &&
+       handle->m_output_ct != UHDR_CT_LINEAR) ||
+      (handle->m_output_fmt == UHDR_IMG_FMT_32bppRGBA8888 && handle->m_output_ct != UHDR_CT_SRGB)) {
     status.error_code = UHDR_CODEC_INVALID_PARAM;
     status.has_detail = 1;
     snprintf(status.detail, sizeof status.detail,
@@ -1455,39 +1667,54 @@ uhdr_error_info_t uhdr_decode(uhdr_codec_private_t* dec) {
     return status;
   }
 
-  ultrahdr::jpegr_compressed_struct uhdr_image;
-  uhdr_image.data = handle->m_uhdr_compressed_img->data;
-  uhdr_image.length = uhdr_image.maxLength = handle->m_uhdr_compressed_img->data_sz;
-  uhdr_image.colorGamut = map_cg_to_internal_cg(handle->m_uhdr_compressed_img->cg);
-
   handle->m_decoded_img_buffer = std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(
       handle->m_output_fmt, UHDR_CG_UNSPECIFIED, handle->m_output_ct, UHDR_CR_UNSPECIFIED,
       handle->m_img_wd, handle->m_img_ht, 1);
-  // alias
-  ultrahdr::jpegr_uncompressed_struct dest;
-  dest.data = handle->m_decoded_img_buffer->planes[UHDR_PLANE_PACKED];
-  dest.colorGamut = ultrahdr::ULTRAHDR_COLORGAMUT_UNSPECIFIED;
 
   handle->m_gainmap_img_buffer = std::make_unique<ultrahdr::uhdr_raw_image_ext_t>(
-      UHDR_IMG_FMT_8bppYCbCr400, UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED,
-      handle->m_gainmap_wd, handle->m_gainmap_ht, 1);
-  // alias
-  ultrahdr::jpegr_uncompressed_struct dest_gainmap;
-  dest_gainmap.data = handle->m_gainmap_img_buffer->planes[UHDR_PLANE_Y];
-
-  ultrahdr::JpegR jpegr;
-  ultrahdr::status_t internal_status =
-      jpegr.decodeJPEGR(&uhdr_image, &dest, handle->m_output_max_disp_boost, nullptr, outputFormat,
-                        &dest_gainmap, nullptr);
-  map_internal_error_status_to_error_info(internal_status, status);
-  if (status.error_code == UHDR_CODEC_OK) {
-    handle->m_decoded_img_buffer->cg = map_internal_cg_to_cg(dest.colorGamut);
+      handle->m_gainmap_num_comp == 1 ? UHDR_IMG_FMT_8bppYCbCr400 : UHDR_IMG_FMT_32bppRGBA8888,
+      UHDR_CG_UNSPECIFIED, UHDR_CT_UNSPECIFIED, UHDR_CR_UNSPECIFIED, handle->m_gainmap_wd,
+      handle->m_gainmap_ht, 1);
+
+#ifdef UHDR_ENABLE_GLES
+  ultrahdr::uhdr_opengl_ctxt_t* uhdrGLESCtxt = nullptr;
+  if (handle->m_enable_gles &&
+      (handle->m_output_ct != UHDR_CT_SRGB || handle->m_effects.size() > 0)) {
+    handle->m_uhdr_gl_ctxt.init_opengl_ctxt();
+    status = handle->m_uhdr_gl_ctxt.mErrorStatus;
+    if (status.error_code != UHDR_CODEC_OK) return status;
+    uhdrGLESCtxt = &handle->m_uhdr_gl_ctxt;
   }
+  ultrahdr::JpegR jpegr(uhdrGLESCtxt);
+#else
+  ultrahdr::JpegR jpegr;
+#endif
+
+  status =
+      jpegr.decodeJPEGR(handle->m_uhdr_compressed_img.get(), handle->m_decoded_img_buffer.get(),
+                        handle->m_output_max_disp_boost, handle->m_output_ct, handle->m_output_fmt,
+                        handle->m_gainmap_img_buffer.get(), nullptr);
 
   if (status.error_code == UHDR_CODEC_OK && dec->m_effects.size() != 0) {
     status = ultrahdr::apply_effects(handle);
   }
 
+#ifdef UHDR_ENABLE_GLES
+  if (handle->m_enable_gles) {
+    if (handle->m_uhdr_gl_ctxt.mDecodedImgTexture != 0) {
+      handle->m_uhdr_gl_ctxt.read_texture(
+          &handle->m_uhdr_gl_ctxt.mDecodedImgTexture, handle->m_decoded_img_buffer->fmt,
+          handle->m_decoded_img_buffer->w, handle->m_decoded_img_buffer->h,
+          handle->m_decoded_img_buffer->planes[0]);
+    }
+    if (handle->m_uhdr_gl_ctxt.mGainmapImgTexture != 0 && dec->m_effects.size() != 0) {
+      handle->m_uhdr_gl_ctxt.read_texture(
+          &handle->m_uhdr_gl_ctxt.mGainmapImgTexture, handle->m_gainmap_img_buffer->fmt,
+          handle->m_gainmap_img_buffer->w, handle->m_gainmap_img_buffer->h,
+          handle->m_gainmap_img_buffer->planes[0]);
+    }
+  }
+#endif
   return status;
 }
 
@@ -1504,7 +1731,7 @@ uhdr_raw_image_t* uhdr_get_decoded_image(uhdr_codec_private_t* dec) {
   return handle->m_decoded_img_buffer.get();
 }
 
-uhdr_raw_image_t* uhdr_get_gain_map_image(uhdr_codec_private_t* dec) {
+uhdr_raw_image_t* uhdr_get_decoded_gainmap_image(uhdr_codec_private_t* dec) {
   if (dynamic_cast<uhdr_decoder_private*>(dec) == nullptr) {
     return nullptr;
   }
@@ -1524,6 +1751,11 @@ void uhdr_reset_decoder(uhdr_codec_private_t* dec) {
     // clear entries and restore defaults
     for (auto it : handle->m_effects) delete it;
     handle->m_effects.clear();
+#ifdef UHDR_ENABLE_GLES
+    handle->m_uhdr_gl_ctxt.reset_opengl_ctxt();
+    handle->m_enable_gles = false;
+#endif
+    handle->m_sailed = false;
     handle->m_uhdr_compressed_img.reset();
     handle->m_output_fmt = UHDR_IMG_FMT_64bppRGBAHalfFloat;
     handle->m_output_ct = UHDR_CT_LINEAR;
@@ -1531,25 +1763,55 @@ void uhdr_reset_decoder(uhdr_codec_private_t* dec) {
 
     // ready to be configured
     handle->m_probed = false;
-    handle->m_sailed = false;
     handle->m_decoded_img_buffer.reset();
     handle->m_gainmap_img_buffer.reset();
     handle->m_img_wd = 0;
     handle->m_img_ht = 0;
     handle->m_gainmap_wd = 0;
     handle->m_gainmap_ht = 0;
+    handle->m_gainmap_num_comp = 0;
     handle->m_exif.clear();
     memset(&handle->m_exif_block, 0, sizeof handle->m_exif_block);
     handle->m_icc.clear();
     memset(&handle->m_icc_block, 0, sizeof handle->m_icc_block);
-    handle->m_base_xmp.clear();
-    handle->m_gainmap_xmp.clear();
+    handle->m_base_img.clear();
+    memset(&handle->m_base_img_block, 0, sizeof handle->m_base_img_block);
+    handle->m_gainmap_img.clear();
+    memset(&handle->m_gainmap_img_block, 0, sizeof handle->m_gainmap_img_block);
     memset(&handle->m_metadata, 0, sizeof handle->m_metadata);
     handle->m_probe_call_status = g_no_error;
     handle->m_decode_call_status = g_no_error;
   }
 }
 
+uhdr_error_info_t uhdr_enable_gpu_acceleration(uhdr_codec_private_t* codec,
+                                               [[maybe_unused]] int enable) {
+  uhdr_error_info_t status = g_no_error;
+
+  if (codec == nullptr) {
+    status.error_code = UHDR_CODEC_INVALID_PARAM;
+    status.has_detail = 1;
+    snprintf(status.detail, sizeof status.detail, "received nullptr for uhdr codec instance");
+    return status;
+  }
+
+  if (codec->m_sailed) {
+    status.error_code = UHDR_CODEC_INVALID_OPERATION;
+    status.has_detail = 1;
+    snprintf(
+        status.detail, sizeof status.detail,
+        "An earlier call to uhdr_encode()/uhdr_decode() has switched the context from configurable "
+        "state to end state. The context is no longer configurable. To reuse, call reset()");
+    return status;
+  }
+
+#ifdef UHDR_ENABLE_GLES
+  codec->m_enable_gles = enable;
+#endif
+
+  return status;
+}
+
 uhdr_error_info_t uhdr_add_effect_mirror(uhdr_codec_private_t* codec,
                                          uhdr_mirror_direction_t direction) {
   uhdr_error_info_t status = g_no_error;
@@ -1570,6 +1832,16 @@ uhdr_error_info_t uhdr_add_effect_mirror(uhdr_codec_private_t* codec,
     return status;
   }
 
+  if (codec->m_sailed) {
+    status.error_code = UHDR_CODEC_INVALID_OPERATION;
+    status.has_detail = 1;
+    snprintf(
+        status.detail, sizeof status.detail,
+        "An earlier call to uhdr_encode()/uhdr_decode() has switched the context from configurable "
+        "state to end state. The context is no longer configurable. To reuse, call reset()");
+    return status;
+  }
+
   codec->m_effects.push_back(new ultrahdr::uhdr_mirror_effect_t(direction));
 
   return status;
@@ -1593,6 +1865,16 @@ uhdr_error_info_t uhdr_add_effect_rotate(uhdr_codec_private_t* codec, int degree
     return status;
   }
 
+  if (codec->m_sailed) {
+    status.error_code = UHDR_CODEC_INVALID_OPERATION;
+    status.has_detail = 1;
+    snprintf(
+        status.detail, sizeof status.detail,
+        "An earlier call to uhdr_encode()/uhdr_decode() has switched the context from configurable "
+        "state to end state. The context is no longer configurable. To reuse, call reset()");
+    return status;
+  }
+
   codec->m_effects.push_back(new ultrahdr::uhdr_rotate_effect_t(degrees));
 
   return status;
@@ -1609,6 +1891,16 @@ uhdr_error_info_t uhdr_add_effect_crop(uhdr_codec_private_t* codec, int left, in
     return status;
   }
 
+  if (codec->m_sailed) {
+    status.error_code = UHDR_CODEC_INVALID_OPERATION;
+    status.has_detail = 1;
+    snprintf(
+        status.detail, sizeof status.detail,
+        "An earlier call to uhdr_encode()/uhdr_decode() has switched the context from configurable "
+        "state to end state. The context is no longer configurable. To reuse, call reset()");
+    return status;
+  }
+
   codec->m_effects.push_back(new ultrahdr::uhdr_crop_effect_t(left, right, top, bottom));
 
   return status;
@@ -1624,6 +1916,16 @@ uhdr_error_info_t uhdr_add_effect_resize(uhdr_codec_private_t* codec, int width,
     return status;
   }
 
+  if (codec->m_sailed) {
+    status.error_code = UHDR_CODEC_INVALID_OPERATION;
+    status.has_detail = 1;
+    snprintf(
+        status.detail, sizeof status.detail,
+        "An earlier call to uhdr_encode()/uhdr_decode() has switched the context from configurable "
+        "state to end state. The context is no longer configurable. To reuse, call reset()");
+    return status;
+  }
+
   codec->m_effects.push_back(new ultrahdr::uhdr_resize_effect_t(width, height));
 
   return status;
diff --git a/tests/Android.bp b/tests/Android.bp
index cac1fc9..975b68c 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -44,6 +44,15 @@ cc_test {
         "libjpegencoder",
         "libultrahdr",
     ],
+    target: {
+        android: {
+            cflags: ["-DUHDR_ENABLE_GLES"],
+            shared_libs: [
+                "libEGL",
+                "libGLESv3",
+            ],
+        },
+    },
     data: [
         "./data/*.*",
     ],
diff --git a/tests/editorhelper_test.cpp b/tests/editorhelper_test.cpp
index a0e6293..a59c921 100644
--- a/tests/editorhelper_test.cpp
+++ b/tests/editorhelper_test.cpp
@@ -223,7 +223,18 @@ class EditorHelperTest
       : filename(std::get<0>(GetParam())),
         width(std::get<1>(GetParam())),
         height(std::get<2>(GetParam())),
-        fmt(std::get<3>(GetParam())){};
+        fmt(std::get<3>(GetParam())) {
+#ifdef UHDR_ENABLE_GLES
+    gl_ctxt = new uhdr_opengl_ctxt();
+    opengl_ctxt = static_cast<uhdr_opengl_ctxt*>(gl_ctxt);
+    opengl_ctxt->init_opengl_ctxt();
+    if (opengl_ctxt->mErrorStatus.error_code != UHDR_CODEC_OK) {
+      opengl_ctxt->delete_opengl_ctxt();
+      delete opengl_ctxt;
+      gl_ctxt = nullptr;
+    }
+#endif
+  };
 
   ~EditorHelperTest() {
     int count = sizeof img_a.planes / sizeof img_a.planes[0];
@@ -233,6 +244,14 @@ class EditorHelperTest
         img_a.planes[i] = nullptr;
       }
     }
+#ifdef UHDR_ENABLE_GLES
+    if (gl_ctxt) {
+      uhdr_opengl_ctxt* opengl_ctxt = static_cast<uhdr_opengl_ctxt*>(gl_ctxt);
+      opengl_ctxt->delete_opengl_ctxt();
+      delete opengl_ctxt;
+    }
+    if (Texture) glDeleteTextures(1, &Texture);
+#endif
   }
 
   std::string filename;
@@ -240,19 +259,37 @@ class EditorHelperTest
   int height;
   uhdr_img_fmt_t fmt;
   uhdr_raw_image_t img_a{};
+  void* gl_ctxt = nullptr;
+  void* texture = nullptr;
+#ifdef UHDR_ENABLE_GLES
+  GLuint Texture = 0;
+  uhdr_opengl_ctxt* opengl_ctxt = nullptr;
+#endif
 };
 
 TEST_P(EditorHelperTest, Rotate) {
   initImageHandle(&img_a, width, height, fmt);
   ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
   ultrahdr::uhdr_rotate_effect_t r90(90), r180(180), r270(270);
-  auto dst = apply_rotate(&r90, &img_a);
-  dst = apply_rotate(&r90, dst.get());
-  dst = apply_rotate(&r180, dst.get());
-  dst = apply_rotate(&r270, dst.get());
-  dst = apply_rotate(&r90, dst.get());
-  dst = apply_rotate(&r90, dst.get());
-  dst = apply_rotate(&r270, dst.get());
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
+    texture = static_cast<void*>(&Texture);
+  }
+#endif
+  auto dst = apply_rotate(&r90, &img_a, gl_ctxt, texture);
+  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
+  dst = apply_rotate(&r180, dst.get(), gl_ctxt, texture);
+  dst = apply_rotate(&r270, dst.get(), gl_ctxt, texture);
+  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
+  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
+  dst = apply_rotate(&r270, dst.get(), gl_ctxt, texture);
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
+                              dst->planes[0]);
+  }
+#endif
   ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get()))
       << "failed for resolution " << width << " x " << height << " format: " << fmt;
 }
@@ -261,10 +298,22 @@ TEST_P(EditorHelperTest, Mirror) {
   initImageHandle(&img_a, width, height, fmt);
   ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
   ultrahdr::uhdr_mirror_effect_t mhorz(UHDR_MIRROR_HORIZONTAL), mvert(UHDR_MIRROR_VERTICAL);
-  auto dst = apply_mirror(&mhorz, &img_a);
-  dst = apply_mirror(&mvert, dst.get());
-  dst = apply_mirror(&mhorz, dst.get());
-  dst = apply_mirror(&mvert, dst.get());
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
+    texture = static_cast<void*>(&Texture);
+  }
+#endif
+  auto dst = apply_mirror(&mhorz, &img_a, gl_ctxt, texture);
+  dst = apply_mirror(&mvert, dst.get(), gl_ctxt, texture);
+  dst = apply_mirror(&mhorz, dst.get(), gl_ctxt, texture);
+  dst = apply_mirror(&mvert, dst.get(), gl_ctxt, texture);
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
+                              dst->planes[0]);
+  }
+#endif
   ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get()))
       << "failed for resolution " << width << " x " << height << " format: " << fmt;
 }
@@ -285,8 +334,19 @@ TEST_P(EditorHelperTest, Crop) {
   initImageHandle(&img_a, width, height, fmt);
   ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
   uhdr_raw_image_t img_copy = img_a;
-  apply_crop(&img_copy, left, top, crop_wd, crop_ht);
-
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
+    texture = static_cast<void*>(&Texture);
+  }
+#endif
+  apply_crop(&img_copy, left, top, crop_wd, crop_ht, gl_ctxt, texture);
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), img_copy.fmt, img_copy.w, img_copy.h,
+                              img_copy.planes[0]);
+  }
+#endif
   ASSERT_EQ(img_a.fmt, img_copy.fmt) << msg;
   ASSERT_EQ(img_a.cg, img_copy.cg) << msg;
   ASSERT_EQ(img_a.ct, img_copy.ct) << msg;
@@ -311,8 +371,19 @@ TEST_P(EditorHelperTest, Resize) {
   initImageHandle(&img_a, width, height, fmt);
   ASSERT_TRUE(loadFile(filename.c_str(), &img_a)) << "unable to load file " << filename;
   ultrahdr::uhdr_resize_effect_t resize(width / 2, height / 2);
-  auto dst = apply_resize(&resize, &img_a, width / 2, height / 2);
-
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
+    texture = static_cast<void*>(&Texture);
+  }
+#endif
+  auto dst = apply_resize(&resize, &img_a, width / 2, height / 2, gl_ctxt, texture);
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
+                              dst->planes[0]);
+  }
+#endif
   ASSERT_EQ(img_a.fmt, dst->fmt) << msg;
   ASSERT_EQ(img_a.cg, dst->cg) << msg;
   ASSERT_EQ(img_a.ct, dst->ct) << msg;
@@ -334,25 +405,55 @@ TEST_P(EditorHelperTest, MultipleEffects) {
   ultrahdr::uhdr_rotate_effect_t r90(90), r180(180), r270(270);
   ultrahdr::uhdr_mirror_effect_t mhorz(UHDR_MIRROR_HORIZONTAL), mvert(UHDR_MIRROR_VERTICAL);
   ultrahdr::uhdr_resize_effect_t resize(width / 2, height / 2);
-  auto dst = apply_mirror(&mhorz, &img_a);
-  dst = apply_rotate(&r180, dst.get());
-  dst = apply_mirror(&mhorz, dst.get());
-  dst = apply_rotate(&r180, dst.get());
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    Texture = opengl_ctxt->create_texture(img_a.fmt, img_a.w, img_a.h, img_a.planes[0]);
+    texture = static_cast<void*>(&Texture);
+  }
+#endif
+  auto dst = apply_mirror(&mhorz, &img_a, gl_ctxt, texture);
+  dst = apply_rotate(&r180, dst.get(), gl_ctxt, texture);
+  dst = apply_mirror(&mhorz, dst.get(), gl_ctxt, texture);
+  dst = apply_rotate(&r180, dst.get(), gl_ctxt, texture);
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
+                              dst->planes[0]);
+  }
+#endif
   ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get())) << msg;
 
-  dst = apply_mirror(&mhorz, dst.get());
-  dst = apply_rotate(&r90, dst.get());
-  dst = apply_rotate(&r90, dst.get());
-  dst = apply_mirror(&mvert, dst.get());
+  dst = apply_mirror(&mhorz, dst.get(), gl_ctxt, texture);
+  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
+  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
+  dst = apply_mirror(&mvert, dst.get(), gl_ctxt, texture);
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
+                              dst->planes[0]);
+  }
+#endif
   ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get())) << msg;
 
-  dst = apply_rotate(&r270, dst.get());
-  dst = apply_mirror(&mvert, dst.get());
-  dst = apply_rotate(&r90, dst.get());
-  dst = apply_mirror(&mhorz, dst.get());
+  dst = apply_rotate(&r270, dst.get(), gl_ctxt, texture);
+  dst = apply_mirror(&mvert, dst.get(), gl_ctxt, texture);
+  dst = apply_rotate(&r90, dst.get(), gl_ctxt, texture);
+  dst = apply_mirror(&mhorz, dst.get(), gl_ctxt, texture);
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
+                              dst->planes[0]);
+  }
+#endif
   ASSERT_NO_FATAL_FAILURE(compareImg(&img_a, dst.get())) << msg;
 
-  dst = apply_resize(&resize, dst.get(), width * 2, height * 2);
+  dst = apply_resize(&resize, dst.get(), width * 2, height * 2, gl_ctxt, texture);
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), dst->fmt, dst->w, dst->h,
+                              dst->planes[0]);
+  }
+#endif
   ASSERT_EQ(img_a.fmt, dst->fmt) << msg;
   ASSERT_EQ(img_a.cg, dst->cg) << msg;
   ASSERT_EQ(img_a.ct, dst->ct) << msg;
@@ -370,7 +471,13 @@ TEST_P(EditorHelperTest, MultipleEffects) {
                         " format: " + std::to_string(fmt);
   }
   uhdr_raw_image_ext_t* img_copy = dst.get();
-  apply_crop(img_copy, left, top, crop_wd, crop_ht);
+  apply_crop(img_copy, left, top, crop_wd, crop_ht, gl_ctxt, texture);
+#ifdef UHDR_ENABLE_GLES
+  if (gl_ctxt != nullptr) {
+    opengl_ctxt->read_texture(static_cast<GLuint*>(texture), img_copy->fmt, img_copy->w,
+                              img_copy->h, img_copy->planes[0]);
+  }
+#endif
   ASSERT_EQ(dst->fmt, img_copy->fmt) << msg;
   ASSERT_EQ(dst->cg, img_copy->cg) << msg;
   ASSERT_EQ(dst->ct, img_copy->ct) << msg;
diff --git a/tests/gainmapmath_test.cpp b/tests/gainmapmath_test.cpp
index e1e00d5..9bf9eab 100644
--- a/tests/gainmapmath_test.cpp
+++ b/tests/gainmapmath_test.cpp
@@ -48,19 +48,21 @@ class GainMapMathTest : public testing::Test {
     int16_t v;
   };
 
-  Pixel getYuv420Pixel_uint(jr_uncompressed_ptr image, size_t x, size_t y) {
-    uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->data);
-    size_t luma_stride = image->luma_stride;
-    uint8_t* chroma_data = reinterpret_cast<uint8_t*>(image->chroma_data);
-    size_t chroma_stride = image->chroma_stride;
+  Pixel getYuv420Pixel_uint(uhdr_raw_image_t* image, size_t x, size_t y) {
+    uint8_t* luma_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_Y]);
+    size_t luma_stride = image->stride[UHDR_PLANE_Y];
+    uint8_t* cb_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_U]);
+    size_t cb_stride = image->stride[UHDR_PLANE_U];
+    uint8_t* cr_data = reinterpret_cast<uint8_t*>(image->planes[UHDR_PLANE_V]);
+    size_t cr_stride = image->stride[UHDR_PLANE_V];
 
-    size_t offset_cr = chroma_stride * (image->height / 2);
     size_t pixel_y_idx = x + y * luma_stride;
-    size_t pixel_chroma_idx = x / 2 + (y / 2) * chroma_stride;
+    size_t pixel_cb_idx = x / 2 + (y / 2) * cb_stride;
+    size_t pixel_cr_idx = x / 2 + (y / 2) * cr_stride;
 
     uint8_t y_uint = luma_data[pixel_y_idx];
-    uint8_t u_uint = chroma_data[pixel_chroma_idx];
-    uint8_t v_uint = chroma_data[offset_cr + pixel_chroma_idx];
+    uint8_t u_uint = cb_data[pixel_cb_idx];
+    uint8_t v_uint = cr_data[pixel_cr_idx];
 
     return {y_uint, u_uint, v_uint};
   }
@@ -146,13 +148,13 @@ class GainMapMathTest : public testing::Test {
     return luminance_scaled * scale_factor;
   }
 
-  Color Recover(Color yuv_gamma, float gain, ultrahdr_metadata_ptr metadata) {
+  Color Recover(Color yuv_gamma, float gain, uhdr_gainmap_metadata_ext_t* metadata) {
     Color rgb_gamma = srgbYuvToRgb(yuv_gamma);
     Color rgb = srgbInvOetf(rgb_gamma);
     return applyGain(rgb, gain, metadata);
   }
 
-  jpegr_uncompressed_struct Yuv420Image() {
+  uhdr_raw_image_t Yuv420Image() {
     static uint8_t pixels[] = {
         // Y
         0x00,
@@ -182,10 +184,23 @@ class GainMapMathTest : public testing::Test {
         0xB2,
         0xB3,
     };
-    return {pixels, 4, 4, ULTRAHDR_COLORGAMUT_BT709, pixels + 16, 4, 2};
+    uhdr_raw_image_t img;
+    img.cg = UHDR_CG_BT_709;
+    img.ct = UHDR_CT_SRGB;
+    img.range = UHDR_CR_FULL_RANGE;
+    img.fmt = UHDR_IMG_FMT_12bppYCbCr420;
+    img.w = 4;
+    img.h = 4;
+    img.planes[UHDR_PLANE_Y] = pixels;
+    img.planes[UHDR_PLANE_U] = pixels + 16;
+    img.planes[UHDR_PLANE_V] = pixels + 16 + 4;
+    img.stride[UHDR_PLANE_Y] = 4;
+    img.stride[UHDR_PLANE_U] = 2;
+    img.stride[UHDR_PLANE_V] = 2;
+    return img;
   }
 
-  jpegr_uncompressed_struct Yuv420Image32x4() {
+  uhdr_raw_image_t Yuv420Image32x4() {
     // clang-format off
     static uint8_t pixels[] = {
     // Y
@@ -205,7 +220,20 @@ class GainMapMathTest : public testing::Test {
     0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDD, 0xDD, 0xDC, 0xDD, 0xDE, 0xDF,
     };
     // clang-format on
-    return {pixels, 32, 4, ULTRAHDR_COLORGAMUT_BT709, pixels + 128, 32, 16};
+    uhdr_raw_image_t img;
+    img.cg = UHDR_CG_BT_709;
+    img.ct = UHDR_CT_SRGB;
+    img.range = UHDR_CR_FULL_RANGE;
+    img.fmt = UHDR_IMG_FMT_12bppYCbCr420;
+    img.w = 32;
+    img.h = 4;
+    img.planes[UHDR_PLANE_Y] = pixels;
+    img.planes[UHDR_PLANE_U] = pixels + 128;
+    img.planes[UHDR_PLANE_V] = pixels + 128 + 32;
+    img.stride[UHDR_PLANE_Y] = 32;
+    img.stride[UHDR_PLANE_U] = 16;
+    img.stride[UHDR_PLANE_V] = 16;
+    return img;
   }
 
   Color (*Yuv420Colors())[4] {
@@ -238,7 +266,7 @@ class GainMapMathTest : public testing::Test {
     return colors;
   }
 
-  jpegr_uncompressed_struct P010Image() {
+  uhdr_raw_image_t P010Image() {
     static uint16_t pixels[] = {
         // Y
         0x00 << 6,
@@ -267,7 +295,20 @@ class GainMapMathTest : public testing::Test {
         0xA3 << 6,
         0xB3 << 6,
     };
-    return {pixels, 4, 4, ULTRAHDR_COLORGAMUT_BT709, pixels + 16, 4, 4};
+    uhdr_raw_image_t img;
+    img.cg = UHDR_CG_BT_709;
+    img.ct = UHDR_CT_HLG;
+    img.range = UHDR_CR_LIMITED_RANGE;
+    img.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
+    img.w = 4;
+    img.h = 4;
+    img.planes[UHDR_PLANE_Y] = pixels;
+    img.planes[UHDR_PLANE_UV] = pixels + 16;
+    img.planes[UHDR_PLANE_V] = nullptr;
+    img.stride[UHDR_PLANE_Y] = 4;
+    img.stride[UHDR_PLANE_UV] = 4;
+    img.stride[UHDR_PLANE_V] = 0;
+    return img;
   }
 
   Color (*P010Colors())[4] {
@@ -300,12 +341,26 @@ class GainMapMathTest : public testing::Test {
     return colors;
   }
 
-  jpegr_uncompressed_struct MapImage() {
+  uhdr_raw_image_t MapImage() {
     static uint8_t pixels[] = {
         0x00, 0x10, 0x20, 0x30, 0x01, 0x11, 0x21, 0x31,
         0x02, 0x12, 0x22, 0x32, 0x03, 0x13, 0x23, 0x33,
     };
-    return {pixels, 4, 4, ULTRAHDR_COLORGAMUT_UNSPECIFIED};
+
+    uhdr_raw_image_t img;
+    img.cg = UHDR_CG_UNSPECIFIED;
+    img.ct = UHDR_CT_UNSPECIFIED;
+    img.range = UHDR_CR_UNSPECIFIED;
+    img.fmt = UHDR_IMG_FMT_8bppYCbCr400;
+    img.w = 4;
+    img.h = 4;
+    img.planes[UHDR_PLANE_Y] = pixels;
+    img.planes[UHDR_PLANE_U] = nullptr;
+    img.planes[UHDR_PLANE_V] = nullptr;
+    img.stride[UHDR_PLANE_Y] = 4;
+    img.stride[UHDR_PLANE_U] = 0;
+    img.stride[UHDR_PLANE_V] = 0;
+    return img;
   }
 
   float (*MapValues())[4] {
@@ -826,27 +881,31 @@ TEST_F(GainMapMathTest, YuvConversionNeon) {
 #endif
 
 TEST_F(GainMapMathTest, TransformYuv420) {
-  jpegr_uncompressed_struct input = Yuv420Image();
-  const size_t buf_size = input.width * input.height * 3 / 2;
+  auto input = Yuv420Image();
+  const size_t buf_size = input.w * input.h * 3 / 2;
   std::unique_ptr<uint8_t[]> out_buf = std::make_unique<uint8_t[]>(buf_size);
+  uint8_t* luma = out_buf.get();
+  uint8_t* cb = luma + input.w * input.h;
+  uint8_t* cr = cb + input.w * input.h / 4;
 
   const std::array<std::array<float, 9>, 6> conversion_coeffs = {
       kYuvBt709ToBt601,  kYuvBt709ToBt2100, kYuvBt601ToBt709,
       kYuvBt601ToBt2100, kYuvBt2100ToBt709, kYuvBt2100ToBt601};
 
   for (size_t coeffs_idx = 0; coeffs_idx < conversion_coeffs.size(); ++coeffs_idx) {
-    jpegr_uncompressed_struct output = Yuv420Image();
-    memcpy(out_buf.get(), input.data, buf_size);
-    output.data = out_buf.get();
-    output.chroma_data = out_buf.get() + input.width * input.height;
-    output.luma_stride = input.width;
-    output.chroma_stride = input.width / 2;
+    auto output = Yuv420Image();
+    memcpy(luma, input.planes[UHDR_PLANE_Y], input.w * input.h);
+    memcpy(cb, input.planes[UHDR_PLANE_U], input.w * input.h / 4);
+    memcpy(cr, input.planes[UHDR_PLANE_V], input.w * input.h / 4);
+    output.planes[UHDR_PLANE_Y] = luma;
+    output.planes[UHDR_PLANE_U] = cb;
+    output.planes[UHDR_PLANE_V] = cr;
 
     // Perform a color gamut conversion to the entire 4:2:0 image.
     transformYuv420(&output, conversion_coeffs.at(coeffs_idx));
 
-    for (size_t y = 0; y < input.height; y += 2) {
-      for (size_t x = 0; x < input.width; x += 2) {
+    for (size_t y = 0; y < input.h; y += 2) {
+      for (size_t x = 0; x < input.w; x += 2) {
         Pixel out1 = getYuv420Pixel_uint(&output, x, y);
         Pixel out2 = getYuv420Pixel_uint(&output, x + 1, y);
         Pixel out3 = getYuv420Pixel_uint(&output, x, y + 1);
@@ -907,21 +966,25 @@ TEST_F(GainMapMathTest, TransformYuv420Neon) {
        {kYuv2100To601_coeffs_neon, kYuvBt2100ToBt601}}};
 
   for (const auto& [neon_coeffs_ptr, floating_point_coeffs] : fixed_floating_coeffs) {
-    jpegr_uncompressed_struct input = Yuv420Image32x4();
-    const size_t buf_size = input.width * input.height * 3 / 2;
-
+    uhdr_raw_image_t input = Yuv420Image32x4();
+    const size_t buf_size = input.w * input.h * 3 / 2;
     std::unique_ptr<uint8_t[]> out_buf = std::make_unique<uint8_t[]>(buf_size);
-    memcpy(out_buf.get(), input.data, buf_size);
-    jpegr_uncompressed_struct output = Yuv420Image32x4();
-    output.data = out_buf.get();
-    output.chroma_data = out_buf.get() + input.width * input.height;
-    output.luma_stride = input.width;
-    output.chroma_stride = input.width / 2;
+    uint8_t* luma = out_buf.get();
+    uint8_t* cb = luma + input.w * input.h;
+    uint8_t* cr = cb + input.w * input.h / 4;
+
+    uhdr_raw_image_t output = Yuv420Image32x4();
+    memcpy(luma, input.planes[UHDR_PLANE_Y], input.w * input.h);
+    memcpy(cb, input.planes[UHDR_PLANE_U], input.w * input.h / 4);
+    memcpy(cr, input.planes[UHDR_PLANE_V], input.w * input.h / 4);
+    output.planes[UHDR_PLANE_Y] = luma;
+    output.planes[UHDR_PLANE_U] = cb;
+    output.planes[UHDR_PLANE_V] = cr;
 
     transformYuv420_neon(&output, neon_coeffs_ptr);
 
-    for (size_t y = 0; y < input.height / 2; ++y) {
-      for (size_t x = 0; x < input.width / 2; ++x) {
+    for (size_t y = 0; y < input.h / 2; ++y) {
+      for (size_t x = 0; x < input.w / 2; ++x) {
         const Pixel out1 = getYuv420Pixel_uint(&output, x * 2, y * 2);
         const Pixel out2 = getYuv420Pixel_uint(&output, x * 2 + 1, y * 2);
         const Pixel out3 = getYuv420Pixel_uint(&output, x * 2, y * 2 + 1);
@@ -1064,12 +1127,15 @@ TEST_F(GainMapMathTest, srgbInvOetfLUT) {
 
 TEST_F(GainMapMathTest, applyGainLUT) {
   for (int boost = 1; boost <= 10; boost++) {
-    ultrahdr_metadata_struct metadata;
+    uhdr_gainmap_metadata_ext_t metadata;
 
-    metadata.minContentBoost = 1.0f / static_cast<float>(boost);
-    metadata.maxContentBoost = static_cast<float>(boost);
+    metadata.min_content_boost = 1.0f / static_cast<float>(boost);
+    metadata.max_content_boost = static_cast<float>(boost);
+    metadata.gamma = 1.0f;
+    metadata.hdr_capacity_max = metadata.max_content_boost;
+    metadata.hdr_capacity_min = metadata.min_content_boost;
     GainLUT gainLUT(&metadata);
-    GainLUT gainLUTWithBoost(&metadata, metadata.maxContentBoost);
+    GainLUT gainLUTWithBoost(&metadata, metadata.max_content_boost);
     for (size_t idx = 0; idx < kGainFactorNumEntries; idx++) {
       float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
       EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata),
@@ -1096,12 +1162,15 @@ TEST_F(GainMapMathTest, applyGainLUT) {
   }
 
   for (int boost = 1; boost <= 10; boost++) {
-    ultrahdr_metadata_struct metadata;
+    uhdr_gainmap_metadata_ext_t metadata;
 
-    metadata.minContentBoost = 1.0f;
-    metadata.maxContentBoost = static_cast<float>(boost);
+    metadata.min_content_boost = 1.0f;
+    metadata.max_content_boost = static_cast<float>(boost);
+    metadata.gamma = 1.0f;
+    metadata.hdr_capacity_max = metadata.max_content_boost;
+    metadata.hdr_capacity_min = metadata.min_content_boost;
     GainLUT gainLUT(&metadata);
-    GainLUT gainLUTWithBoost(&metadata, metadata.maxContentBoost);
+    GainLUT gainLUTWithBoost(&metadata, metadata.max_content_boost);
     for (size_t idx = 0; idx < kGainFactorNumEntries; idx++) {
       float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
       EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata),
@@ -1128,12 +1197,15 @@ TEST_F(GainMapMathTest, applyGainLUT) {
   }
 
   for (int boost = 1; boost <= 10; boost++) {
-    ultrahdr_metadata_struct metadata;
+    uhdr_gainmap_metadata_ext_t metadata;
 
-    metadata.minContentBoost = 1.0f / powf(static_cast<float>(boost), 1.0f / 3.0f);
-    metadata.maxContentBoost = static_cast<float>(boost);
+    metadata.min_content_boost = 1.0f / powf(static_cast<float>(boost), 1.0f / 3.0f);
+    metadata.max_content_boost = static_cast<float>(boost);
+    metadata.gamma = 1.0f;
+    metadata.hdr_capacity_max = metadata.max_content_boost;
+    metadata.hdr_capacity_min = metadata.min_content_boost;
     GainLUT gainLUT(&metadata);
-    GainLUT gainLUTWithBoost(&metadata, metadata.maxContentBoost);
+    GainLUT gainLUTWithBoost(&metadata, metadata.max_content_boost);
     for (size_t idx = 0; idx < kGainFactorNumEntries; idx++) {
       float value = static_cast<float>(idx) / static_cast<float>(kGainFactorNumEntries - 1);
       EXPECT_RGB_NEAR(applyGain(RgbBlack(), value, &metadata),
@@ -1169,102 +1241,92 @@ TEST_F(GainMapMathTest, PqTransferFunctionRoundtrip) {
 }
 
 TEST_F(GainMapMathTest, ColorConversionLookup) {
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_UNSPECIFIED),
-            nullptr);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_BT709),
-            identityConversion);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_P3), p3ToBt709);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT709, ULTRAHDR_COLORGAMUT_BT2100),
-            bt2100ToBt709);
-
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_UNSPECIFIED), nullptr);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT709), bt709ToP3);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_P3), identityConversion);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_P3, ULTRAHDR_COLORGAMUT_BT2100), bt2100ToP3);
-
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT2100, ULTRAHDR_COLORGAMUT_UNSPECIFIED),
-            nullptr);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT2100, ULTRAHDR_COLORGAMUT_BT709),
-            bt709ToBt2100);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT2100, ULTRAHDR_COLORGAMUT_P3), p3ToBt2100);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_BT2100, ULTRAHDR_COLORGAMUT_BT2100),
-            identityConversion);
-
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_UNSPECIFIED, ULTRAHDR_COLORGAMUT_UNSPECIFIED),
-            nullptr);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_UNSPECIFIED, ULTRAHDR_COLORGAMUT_BT709),
-            nullptr);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_UNSPECIFIED, ULTRAHDR_COLORGAMUT_P3), nullptr);
-  EXPECT_EQ(getHdrConversionFn(ULTRAHDR_COLORGAMUT_UNSPECIFIED, ULTRAHDR_COLORGAMUT_BT2100),
-            nullptr);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_BT_709, UHDR_CG_UNSPECIFIED), nullptr);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_BT_709, UHDR_CG_BT_709), identityConversion);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_BT_709, UHDR_CG_DISPLAY_P3), p3ToBt709);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_BT_709, UHDR_CG_BT_2100), bt2100ToBt709);
+
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_DISPLAY_P3, UHDR_CG_UNSPECIFIED), nullptr);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_DISPLAY_P3, UHDR_CG_BT_709), bt709ToP3);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_DISPLAY_P3, UHDR_CG_DISPLAY_P3), identityConversion);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_DISPLAY_P3, UHDR_CG_BT_2100), bt2100ToP3);
+
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_BT_2100, UHDR_CG_UNSPECIFIED), nullptr);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_BT_2100, UHDR_CG_BT_709), bt709ToBt2100);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_BT_2100, UHDR_CG_DISPLAY_P3), p3ToBt2100);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_BT_2100, UHDR_CG_BT_2100), identityConversion);
+
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_UNSPECIFIED, UHDR_CG_UNSPECIFIED), nullptr);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_UNSPECIFIED, UHDR_CG_BT_709), nullptr);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_UNSPECIFIED, UHDR_CG_DISPLAY_P3), nullptr);
+  EXPECT_EQ(getGamutConversionFn(UHDR_CG_UNSPECIFIED, UHDR_CG_BT_2100), nullptr);
 }
 
 TEST_F(GainMapMathTest, EncodeGain) {
-  ultrahdr_metadata_struct metadata;
-
-  metadata.minContentBoost = 1.0f / 4.0f;
-  metadata.maxContentBoost = 4.0f;
-
-  EXPECT_EQ(encodeGain(0.0f, 0.0f, &metadata), 127);
-  EXPECT_EQ(encodeGain(0.0f, 1.0f, &metadata), 127);
-  EXPECT_EQ(encodeGain(1.0f, 0.0f, &metadata), 0);
-  EXPECT_EQ(encodeGain(0.5f, 0.0f, &metadata), 0);
-
-  EXPECT_EQ(encodeGain(1.0f, 1.0f, &metadata), 127);
-  EXPECT_EQ(encodeGain(1.0f, 4.0f, &metadata), 255);
-  EXPECT_EQ(encodeGain(1.0f, 5.0f, &metadata), 255);
-  EXPECT_EQ(encodeGain(4.0f, 1.0f, &metadata), 0);
-  EXPECT_EQ(encodeGain(4.0f, 0.5f, &metadata), 0);
-  EXPECT_EQ(encodeGain(1.0f, 2.0f, &metadata), 191);
-  EXPECT_EQ(encodeGain(2.0f, 1.0f, &metadata), 63);
-
-  metadata.maxContentBoost = 2.0f;
-  metadata.minContentBoost = 1.0f / 2.0f;
-
-  EXPECT_EQ(encodeGain(1.0f, 2.0f, &metadata), 255);
-  EXPECT_EQ(encodeGain(2.0f, 1.0f, &metadata), 0);
-  EXPECT_EQ(encodeGain(1.0f, 1.41421f, &metadata), 191);
-  EXPECT_EQ(encodeGain(1.41421f, 1.0f, &metadata), 63);
-
-  metadata.maxContentBoost = 8.0f;
-  metadata.minContentBoost = 1.0f / 8.0f;
-
-  EXPECT_EQ(encodeGain(1.0f, 8.0f, &metadata), 255);
-  EXPECT_EQ(encodeGain(8.0f, 1.0f, &metadata), 0);
-  EXPECT_EQ(encodeGain(1.0f, 2.82843f, &metadata), 191);
-  EXPECT_EQ(encodeGain(2.82843f, 1.0f, &metadata), 63);
-
-  metadata.maxContentBoost = 8.0f;
-  metadata.minContentBoost = 1.0f;
-
-  EXPECT_EQ(encodeGain(0.0f, 0.0f, &metadata), 0);
-  EXPECT_EQ(encodeGain(1.0f, 0.0f, &metadata), 0);
-
-  EXPECT_EQ(encodeGain(1.0f, 1.0f, &metadata), 0);
-  EXPECT_EQ(encodeGain(1.0f, 8.0f, &metadata), 255);
-  EXPECT_EQ(encodeGain(1.0f, 4.0f, &metadata), 170);
-  EXPECT_EQ(encodeGain(1.0f, 2.0f, &metadata), 85);
-
-  metadata.maxContentBoost = 8.0f;
-  metadata.minContentBoost = 0.5f;
-
-  EXPECT_EQ(encodeGain(0.0f, 0.0f, &metadata), 63);
-  EXPECT_EQ(encodeGain(1.0f, 0.0f, &metadata), 0);
-
-  EXPECT_EQ(encodeGain(1.0f, 1.0f, &metadata), 63);
-  EXPECT_EQ(encodeGain(1.0f, 8.0f, &metadata), 255);
-  EXPECT_EQ(encodeGain(1.0f, 4.0f, &metadata), 191);
-  EXPECT_EQ(encodeGain(1.0f, 2.0f, &metadata), 127);
-  EXPECT_EQ(encodeGain(1.0f, 0.7071f, &metadata), 31);
-  EXPECT_EQ(encodeGain(1.0f, 0.5f, &metadata), 0);
+  float min_boost = log2(1.0f / 4.0f);
+  float max_boost = log2(4.0f);
+  float gamma = 1.0f;
+
+  EXPECT_EQ(affineMapGain(computeGain(0.0f, 1.0f), min_boost, max_boost, 1.0f), 128);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 0.0f), min_boost, max_boost, 1.0f), 0);
+  EXPECT_EQ(affineMapGain(computeGain(0.5f, 0.0f), min_boost, max_boost, 1.0f), 0);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 1.0), min_boost, max_boost, 1.0f), 128);
+
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 4.0f), min_boost, max_boost, 1.0f), 255);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 5.0f), min_boost, max_boost, 1.0f), 255);
+  EXPECT_EQ(affineMapGain(computeGain(4.0f, 1.0f), min_boost, max_boost, 1.0f), 0);
+  EXPECT_EQ(affineMapGain(computeGain(4.0f, 0.5f), min_boost, max_boost, 1.0f), 0);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 2.0f), min_boost, max_boost, 1.0f), 191);
+  EXPECT_EQ(affineMapGain(computeGain(2.0f, 1.0f), min_boost, max_boost, 1.0f), 64);
+
+  min_boost = log2(1.0f / 2.0f);
+  max_boost = log2(2.0f);
+
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 2.0f), min_boost, max_boost, 1.0f), 255);
+  EXPECT_EQ(affineMapGain(computeGain(2.0f, 1.0f), min_boost, max_boost, 1.0f), 0);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 1.41421f), min_boost, max_boost, 1.0f), 191);
+  EXPECT_EQ(affineMapGain(computeGain(1.41421f, 1.0f), min_boost, max_boost, 1.0f), 64);
+
+  min_boost = log2(1.0f / 8.0f);
+  max_boost = log2(8.0f);
+
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 8.0f), min_boost, max_boost, 1.0f), 255);
+  EXPECT_EQ(affineMapGain(computeGain(8.0f, 1.0f), min_boost, max_boost, 1.0f), 0);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 2.82843f), min_boost, max_boost, 1.0f), 191);
+  EXPECT_EQ(affineMapGain(computeGain(2.82843f, 1.0f), min_boost, max_boost, 1.0f), 64);
+
+  min_boost = log2(1.0f);
+  max_boost = log2(8.0f);
+
+  EXPECT_EQ(affineMapGain(computeGain(0.0f, 0.0f), min_boost, max_boost, 1.0f), 0);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 0.0f), min_boost, max_boost, 1.0f), 0);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 1.0f), min_boost, max_boost, 1.0f), 0);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 8.0f), min_boost, max_boost, 1.0f), 255);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 4.0f), min_boost, max_boost, 1.0f), 170);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 2.0f), min_boost, max_boost, 1.0f), 85);
+
+  min_boost = log2(1.0f / 2.0f);
+  max_boost = log2(8.0f);
+
+  EXPECT_EQ(affineMapGain(computeGain(0.0f, 0.0f), min_boost, max_boost, 1.0f), 64);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 0.0f), min_boost, max_boost, 1.0f), 0);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 1.0f), min_boost, max_boost, 1.0f), 64);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 8.0f), min_boost, max_boost, 1.0f), 255);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 4.0f), min_boost, max_boost, 1.0f), 191);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 2.0f), min_boost, max_boost, 1.0f), 128);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 0.7071f), min_boost, max_boost, 1.0f), 32);
+  EXPECT_EQ(affineMapGain(computeGain(1.0f, 0.5f), min_boost, max_boost, 1.0f), 0);
 }
 
 TEST_F(GainMapMathTest, ApplyGain) {
-  ultrahdr_metadata_struct metadata;
+  uhdr_gainmap_metadata_ext_t metadata;
 
-  metadata.minContentBoost = 1.0f / 4.0f;
-  metadata.maxContentBoost = 4.0f;
-  float displayBoost = metadata.maxContentBoost;
+  metadata.min_content_boost = 1.0f / 4.0f;
+  metadata.max_content_boost = 4.0f;
+  metadata.hdr_capacity_max = metadata.max_content_boost;
+  metadata.hdr_capacity_min = metadata.min_content_boost;
+  metadata.gamma = 1.0f;
+  float displayBoost = metadata.max_content_boost;
 
   EXPECT_RGB_NEAR(applyGain(RgbBlack(), 0.0f, &metadata), RgbBlack());
   EXPECT_RGB_NEAR(applyGain(RgbBlack(), 0.5f, &metadata), RgbBlack());
@@ -1276,8 +1338,10 @@ TEST_F(GainMapMathTest, ApplyGain) {
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.75f, &metadata), RgbWhite() * 2.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 4.0f);
 
-  metadata.maxContentBoost = 2.0f;
-  metadata.minContentBoost = 1.0f / 2.0f;
+  metadata.max_content_boost = 2.0f;
+  metadata.min_content_boost = 1.0f / 2.0f;
+  metadata.hdr_capacity_max = metadata.max_content_boost;
+  metadata.hdr_capacity_min = metadata.min_content_boost;
 
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite() / 2.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.25f, &metadata), RgbWhite() / 1.41421f);
@@ -1285,8 +1349,10 @@ TEST_F(GainMapMathTest, ApplyGain) {
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.75f, &metadata), RgbWhite() * 1.41421f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 2.0f);
 
-  metadata.maxContentBoost = 8.0f;
-  metadata.minContentBoost = 1.0f / 8.0f;
+  metadata.max_content_boost = 8.0f;
+  metadata.min_content_boost = 1.0f / 8.0f;
+  metadata.hdr_capacity_max = metadata.max_content_boost;
+  metadata.hdr_capacity_min = metadata.min_content_boost;
 
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite() / 8.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.25f, &metadata), RgbWhite() / 2.82843f);
@@ -1294,16 +1360,20 @@ TEST_F(GainMapMathTest, ApplyGain) {
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.75f, &metadata), RgbWhite() * 2.82843f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
 
-  metadata.maxContentBoost = 8.0f;
-  metadata.minContentBoost = 1.0f;
+  metadata.max_content_boost = 8.0f;
+  metadata.min_content_boost = 1.0f;
+  metadata.hdr_capacity_max = metadata.max_content_boost;
+  metadata.hdr_capacity_min = metadata.min_content_boost;
 
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite());
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f / 3.0f, &metadata), RgbWhite() * 2.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 2.0f / 3.0f, &metadata), RgbWhite() * 4.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
 
-  metadata.maxContentBoost = 8.0f;
-  metadata.minContentBoost = 0.5f;
+  metadata.max_content_boost = 8.0f;
+  metadata.min_content_boost = 0.5f;
+  metadata.hdr_capacity_max = metadata.max_content_boost;
+  metadata.hdr_capacity_min = metadata.min_content_boost;
 
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.0f, &metadata), RgbWhite() / 2.0f);
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 0.25f, &metadata), RgbWhite());
@@ -1312,8 +1382,10 @@ TEST_F(GainMapMathTest, ApplyGain) {
   EXPECT_RGB_NEAR(applyGain(RgbWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
 
   Color e = {{{0.0f, 0.5f, 1.0f}}};
-  metadata.maxContentBoost = 4.0f;
-  metadata.minContentBoost = 1.0f / 4.0f;
+  metadata.max_content_boost = 4.0f;
+  metadata.min_content_boost = 1.0f / 4.0f;
+  metadata.hdr_capacity_max = metadata.max_content_boost;
+  metadata.hdr_capacity_min = metadata.min_content_boost;
 
   EXPECT_RGB_NEAR(applyGain(e, 0.0f, &metadata), e / 4.0f);
   EXPECT_RGB_NEAR(applyGain(e, 0.25f, &metadata), e / 2.0f);
@@ -1335,7 +1407,7 @@ TEST_F(GainMapMathTest, ApplyGain) {
 }
 
 TEST_F(GainMapMathTest, GetYuv420Pixel) {
-  jpegr_uncompressed_struct image = Yuv420Image();
+  auto image = Yuv420Image();
   Color(*colors)[4] = Yuv420Colors();
 
   for (size_t y = 0; y < 4; ++y) {
@@ -1346,7 +1418,7 @@ TEST_F(GainMapMathTest, GetYuv420Pixel) {
 }
 
 TEST_F(GainMapMathTest, GetP010Pixel) {
-  jpegr_uncompressed_struct image = P010Image();
+  auto image = P010Image();
   Color(*colors)[4] = P010Colors();
 
   for (size_t y = 0; y < 4; ++y) {
@@ -1357,7 +1429,7 @@ TEST_F(GainMapMathTest, GetP010Pixel) {
 }
 
 TEST_F(GainMapMathTest, SampleYuv420) {
-  jpegr_uncompressed_struct image = Yuv420Image();
+  auto image = Yuv420Image();
   Color(*colors)[4] = Yuv420Colors();
 
   static const size_t kMapScaleFactor = 2;
@@ -1383,7 +1455,7 @@ TEST_F(GainMapMathTest, SampleYuv420) {
 }
 
 TEST_F(GainMapMathTest, SampleP010) {
-  jpegr_uncompressed_struct image = P010Image();
+  auto image = P010Image();
   Color(*colors)[4] = P010Colors();
 
   static const size_t kMapScaleFactor = 2;
@@ -1409,7 +1481,7 @@ TEST_F(GainMapMathTest, SampleP010) {
 }
 
 TEST_F(GainMapMathTest, SampleMap) {
-  jpegr_uncompressed_struct image = MapImage();
+  auto image = MapImage();
   float(*values)[4] = MapValues();
 
   static const size_t kMapScaleFactor = 2;
@@ -1457,9 +1529,9 @@ TEST_F(GainMapMathTest, ColorToRgba1010102) {
 
   Color e_gamma = {{{0.1f, 0.2f, 0.3f}}};
   EXPECT_EQ(colorToRgba1010102(e_gamma),
-            0x3 << 30 | static_cast<uint32_t>(0.1f * static_cast<float>(0x3ff)) |
-                static_cast<uint32_t>(0.2f * static_cast<float>(0x3ff)) << 10 |
-                static_cast<uint32_t>(0.3f * static_cast<float>(0x3ff)) << 20);
+            0x3 << 30 | static_cast<uint32_t>(0.1f * static_cast<float>(0x3ff) + 0.5) |
+                static_cast<uint32_t>(0.2f * static_cast<float>(0x3ff) + 0.5) << 10 |
+                static_cast<uint32_t>(0.3f * static_cast<float>(0x3ff) + 0.5) << 20);
 }
 
 TEST_F(GainMapMathTest, ColorToRgbaF16) {
@@ -1553,10 +1625,11 @@ TEST_F(GainMapMathTest, GenerateMapLuminancePq) {
 }
 
 TEST_F(GainMapMathTest, ApplyMap) {
-  ultrahdr_metadata_struct metadata;
+  uhdr_gainmap_metadata_ext_t metadata;
 
-  metadata.minContentBoost = 1.0f / 8.0f;
-  metadata.maxContentBoost = 8.0f;
+  metadata.min_content_boost = 1.0f / 8.0f;
+  metadata.max_content_boost = 8.0f;
+  metadata.gamma = 1.0f;
 
   EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
   EXPECT_RGB_EQ(Recover(YuvBlack(), 1.0f, &metadata), RgbBlack());
@@ -1588,17 +1661,16 @@ TEST_F(GainMapMathTest, ApplyMap) {
   EXPECT_RGB_CLOSE(Recover(SrgbYuvGreen(), 0.0f, &metadata), RgbGreen() / 8.0f);
   EXPECT_RGB_CLOSE(Recover(SrgbYuvBlue(), 0.0f, &metadata), RgbBlue() / 8.0f);
 
-  metadata.maxContentBoost = 8.0f;
-  metadata.minContentBoost = 1.0f;
+  metadata.max_content_boost = 8.0f;
+  metadata.min_content_boost = 1.0f;
 
   EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
   EXPECT_RGB_EQ(Recover(YuvWhite(), 2.0f / 3.0f, &metadata), RgbWhite() * 4.0f);
   EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f / 3.0f, &metadata), RgbWhite() * 2.0f);
   EXPECT_RGB_EQ(Recover(YuvWhite(), 0.0f, &metadata), RgbWhite());
 
-  metadata.maxContentBoost = 8.0f;
-  metadata.minContentBoost = 0.5f;
-  ;
+  metadata.max_content_boost = 8.0f;
+  metadata.min_content_boost = 0.5f;
 
   EXPECT_RGB_EQ(Recover(YuvWhite(), 1.0f, &metadata), RgbWhite() * 8.0f);
   EXPECT_RGB_EQ(Recover(YuvWhite(), 0.75, &metadata), RgbWhite() * 4.0f);
diff --git a/tests/gainmapmetadata_test.cpp b/tests/gainmapmetadata_test.cpp
index 5131bed..88e9a7c 100644
--- a/tests/gainmapmetadata_test.cpp
+++ b/tests/gainmapmetadata_test.cpp
@@ -42,35 +42,35 @@ void GainMapMetadataTest::TearDown() {}
 const std::string kIso = "urn:iso:std:iso:ts:21496:-1";
 
 TEST_F(GainMapMetadataTest, encodeMetadataThenDecode) {
-  ultrahdr_metadata_struct expected;
-  expected.version = "1.0";
-  expected.maxContentBoost = 100.5f;
-  expected.minContentBoost = 1.5f;
+  uhdr_gainmap_metadata_ext_t expected("1.0");
+  expected.max_content_boost = 100.5f;
+  expected.min_content_boost = 1.5f;
   expected.gamma = 1.0f;
-  expected.offsetSdr = 0.0f;
-  expected.offsetHdr = 0.0f;
-  expected.hdrCapacityMin = 1.0f;
-  expected.hdrCapacityMax = expected.maxContentBoost;
+  expected.offset_sdr = 0.0f;
+  expected.offset_hdr = 0.0f;
+  expected.hdr_capacity_min = 1.0f;
+  expected.hdr_capacity_max = expected.max_content_boost;
 
-  gain_map_metadata metadata;
-  gain_map_metadata::gainmapMetadataFloatToFraction(&expected, &metadata);
+  uhdr_gainmap_metadata_frac metadata;
+  uhdr_gainmap_metadata_frac::gainmapMetadataFloatToFraction(&expected, &metadata);
   //  metadata.dump();
 
   std::vector<uint8_t> data;
-  gain_map_metadata::encodeGainmapMetadata(&metadata, data);
+  uhdr_gainmap_metadata_frac::encodeGainmapMetadata(&metadata, data);
 
-  gain_map_metadata decodedMetadata;
-  gain_map_metadata::decodeGainmapMetadata(data, &decodedMetadata);
+  uhdr_gainmap_metadata_frac decodedMetadata;
+  uhdr_gainmap_metadata_frac::decodeGainmapMetadata(data, &decodedMetadata);
 
-  ultrahdr_metadata_struct decodedUHdrMetadata;
-  gain_map_metadata::gainmapMetadataFractionToFloat(&decodedMetadata, &decodedUHdrMetadata);
+  uhdr_gainmap_metadata_ext_t decodedUHdrMetadata;
+  uhdr_gainmap_metadata_frac::gainmapMetadataFractionToFloat(&decodedMetadata,
+                                                             &decodedUHdrMetadata);
 
-  EXPECT_EQ(expected.maxContentBoost, decodedUHdrMetadata.maxContentBoost);
-  EXPECT_EQ(expected.minContentBoost, decodedUHdrMetadata.minContentBoost);
+  EXPECT_EQ(expected.max_content_boost, decodedUHdrMetadata.max_content_boost);
+  EXPECT_EQ(expected.min_content_boost, decodedUHdrMetadata.min_content_boost);
   EXPECT_EQ(expected.gamma, decodedUHdrMetadata.gamma);
-  EXPECT_EQ(expected.offsetSdr, decodedUHdrMetadata.offsetSdr);
-  EXPECT_EQ(expected.offsetHdr, decodedUHdrMetadata.offsetHdr);
-  EXPECT_EQ(expected.hdrCapacityMin, decodedUHdrMetadata.hdrCapacityMin);
-  EXPECT_EQ(expected.hdrCapacityMax, decodedUHdrMetadata.hdrCapacityMax);
+  EXPECT_EQ(expected.offset_sdr, decodedUHdrMetadata.offset_sdr);
+  EXPECT_EQ(expected.offset_hdr, decodedUHdrMetadata.offset_hdr);
+  EXPECT_EQ(expected.hdr_capacity_min, decodedUHdrMetadata.hdr_capacity_min);
+  EXPECT_EQ(expected.hdr_capacity_max, decodedUHdrMetadata.hdr_capacity_max);
 }
 }  // namespace ultrahdr
diff --git a/tests/icchelper_test.cpp b/tests/icchelper_test.cpp
index 26f78a6..2f71afe 100644
--- a/tests/icchelper_test.cpp
+++ b/tests/icchelper_test.cpp
@@ -39,31 +39,26 @@ void IccHelperTest::SetUp() {}
 void IccHelperTest::TearDown() {}
 
 TEST_F(IccHelperTest, iccWriteThenRead) {
-  std::shared_ptr<DataStruct> iccBt709 =
-      IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, ULTRAHDR_COLORGAMUT_BT709);
+  std::shared_ptr<DataStruct> iccBt709 = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709);
   ASSERT_NE(iccBt709->getLength(), 0);
   ASSERT_NE(iccBt709->getData(), nullptr);
   EXPECT_EQ(IccHelper::readIccColorGamut(iccBt709->getData(), iccBt709->getLength()),
-            ULTRAHDR_COLORGAMUT_BT709);
+            UHDR_CG_BT_709);
 
-  std::shared_ptr<DataStruct> iccP3 =
-      IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, ULTRAHDR_COLORGAMUT_P3);
+  std::shared_ptr<DataStruct> iccP3 = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_DISPLAY_P3);
   ASSERT_NE(iccP3->getLength(), 0);
   ASSERT_NE(iccP3->getData(), nullptr);
-  EXPECT_EQ(IccHelper::readIccColorGamut(iccP3->getData(), iccP3->getLength()),
-            ULTRAHDR_COLORGAMUT_P3);
+  EXPECT_EQ(IccHelper::readIccColorGamut(iccP3->getData(), iccP3->getLength()), UHDR_CG_DISPLAY_P3);
 
-  std::shared_ptr<DataStruct> iccBt2100 =
-      IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, ULTRAHDR_COLORGAMUT_BT2100);
+  std::shared_ptr<DataStruct> iccBt2100 = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_2100);
   ASSERT_NE(iccBt2100->getLength(), 0);
   ASSERT_NE(iccBt2100->getData(), nullptr);
   EXPECT_EQ(IccHelper::readIccColorGamut(iccBt2100->getData(), iccBt2100->getLength()),
-            ULTRAHDR_COLORGAMUT_BT2100);
+            UHDR_CG_BT_2100);
 }
 
 TEST_F(IccHelperTest, iccEndianness) {
-  std::shared_ptr<DataStruct> icc =
-      IccHelper::writeIccProfile(ULTRAHDR_TF_SRGB, ULTRAHDR_COLORGAMUT_BT709);
+  std::shared_ptr<DataStruct> icc = IccHelper::writeIccProfile(UHDR_CT_SRGB, UHDR_CG_BT_709);
   size_t profile_size = icc->getLength() - kICCIdentifierSize;
 
   uint8_t* icc_bytes = reinterpret_cast<uint8_t*>(icc->getData()) + kICCIdentifierSize;
diff --git a/tests/jpegdecoderhelper_test.cpp b/tests/jpegdecoderhelper_test.cpp
index cde8ff8..b34ce2e 100644
--- a/tests/jpegdecoderhelper_test.cpp
+++ b/tests/jpegdecoderhelper_test.cpp
@@ -101,47 +101,56 @@ void JpegDecoderHelperTest::TearDown() {}
 
 TEST_F(JpegDecoderHelperTest, decodeYuvImage) {
   JpegDecoderHelper decoder;
-  EXPECT_TRUE(decoder.decompressImage(mYuvImage.buffer.get(), mYuvImage.size));
+  EXPECT_EQ(decoder.decompressImage(mYuvImage.buffer.get(), mYuvImage.size).error_code,
+            UHDR_CODEC_OK);
   ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
   EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
-            ULTRAHDR_COLORGAMUT_UNSPECIFIED);
+            UHDR_CG_UNSPECIFIED);
 }
 
 TEST_F(JpegDecoderHelperTest, decodeYuvImageToRgba) {
   JpegDecoderHelper decoder;
-  EXPECT_TRUE(decoder.decompressImage(mYuvImage.buffer.get(), mYuvImage.size, DECODE_TO_RGB_CS));
+  EXPECT_EQ(
+      decoder.decompressImage(mYuvImage.buffer.get(), mYuvImage.size, DECODE_TO_RGB_CS).error_code,
+      UHDR_CODEC_OK);
   ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
   EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
-            ULTRAHDR_COLORGAMUT_UNSPECIFIED);
+            UHDR_CG_UNSPECIFIED);
 }
 
 TEST_F(JpegDecoderHelperTest, decodeYuvIccImage) {
   JpegDecoderHelper decoder;
-  EXPECT_TRUE(decoder.decompressImage(mYuvIccImage.buffer.get(), mYuvIccImage.size));
+  EXPECT_EQ(decoder.decompressImage(mYuvIccImage.buffer.get(), mYuvIccImage.size).error_code,
+            UHDR_CODEC_OK);
   ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
   EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
-            ULTRAHDR_COLORGAMUT_BT709);
+            UHDR_CG_BT_709);
 }
 
 TEST_F(JpegDecoderHelperTest, decodeGreyImage) {
   JpegDecoderHelper decoder;
-  EXPECT_TRUE(decoder.decompressImage(mGreyImage.buffer.get(), mGreyImage.size));
+  EXPECT_EQ(decoder.decompressImage(mGreyImage.buffer.get(), mGreyImage.size).error_code,
+            UHDR_CODEC_OK);
   ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
-  EXPECT_TRUE(decoder.decompressImage(mGreyImage.buffer.get(), mGreyImage.size, DECODE_STREAM));
+  EXPECT_EQ(
+      decoder.decompressImage(mGreyImage.buffer.get(), mGreyImage.size, DECODE_STREAM).error_code,
+      UHDR_CODEC_OK);
   ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
 }
 
 TEST_F(JpegDecoderHelperTest, decodeRgbImageToRgba) {
   JpegDecoderHelper decoder;
-  EXPECT_TRUE(decoder.decompressImage(mRgbImage.buffer.get(), mRgbImage.size, DECODE_STREAM));
+  EXPECT_EQ(
+      decoder.decompressImage(mRgbImage.buffer.get(), mRgbImage.size, DECODE_STREAM).error_code,
+      UHDR_CODEC_OK);
   ASSERT_GT(decoder.getDecompressedImageSize(), static_cast<uint32_t>(0));
   EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
-            ULTRAHDR_COLORGAMUT_UNSPECIFIED);
+            UHDR_CG_UNSPECIFIED);
 }
 
 TEST_F(JpegDecoderHelperTest, getCompressedImageParameters) {
   JpegDecoderHelper decoder;
-  EXPECT_TRUE(decoder.parseImage(mYuvImage.buffer.get(), mYuvImage.size));
+  EXPECT_EQ(decoder.parseImage(mYuvImage.buffer.get(), mYuvImage.size).error_code, UHDR_CODEC_OK);
   EXPECT_EQ(IMAGE_WIDTH, decoder.getDecompressedImageWidth());
   EXPECT_EQ(IMAGE_HEIGHT, decoder.getDecompressedImageHeight());
   EXPECT_EQ(decoder.getICCSize(), 0);
@@ -150,13 +159,14 @@ TEST_F(JpegDecoderHelperTest, getCompressedImageParameters) {
 
 TEST_F(JpegDecoderHelperTest, getCompressedImageParametersIcc) {
   JpegDecoderHelper decoder;
-  EXPECT_TRUE(decoder.parseImage(mYuvIccImage.buffer.get(), mYuvIccImage.size));
+  EXPECT_EQ(decoder.parseImage(mYuvIccImage.buffer.get(), mYuvIccImage.size).error_code,
+            UHDR_CODEC_OK);
   EXPECT_EQ(IMAGE_WIDTH, decoder.getDecompressedImageWidth());
   EXPECT_EQ(IMAGE_HEIGHT, decoder.getDecompressedImageHeight());
   EXPECT_GT(decoder.getICCSize(), 0);
   EXPECT_GT(decoder.getEXIFSize(), 0);
   EXPECT_EQ(IccHelper::readIccColorGamut(decoder.getICCPtr(), decoder.getICCSize()),
-            ULTRAHDR_COLORGAMUT_BT709);
+            UHDR_CG_BT_709);
 }
 
 }  // namespace ultrahdr
diff --git a/tests/jpegencoderhelper_test.cpp b/tests/jpegencoderhelper_test.cpp
index 4adc93f..703d085 100644
--- a/tests/jpegencoderhelper_test.cpp
+++ b/tests/jpegencoderhelper_test.cpp
@@ -20,7 +20,6 @@
 #include <iostream>
 
 #include "ultrahdr/ultrahdrcommon.h"
-#include "ultrahdr/ultrahdr.h"
 #include "ultrahdr/jpegencoderhelper.h"
 
 namespace ultrahdr {
@@ -110,8 +109,11 @@ TEST_F(JpegEncoderHelperTest, encodeAlignedImage) {
   const uint8_t* vPlane = uPlane + mAlignedImage.width * mAlignedImage.height / 4;
   const uint8_t* planes[3]{yPlane, uPlane, vPlane};
   const size_t strides[3]{mAlignedImage.width, mAlignedImage.width / 2, mAlignedImage.width / 2};
-  EXPECT_TRUE(encoder.compressImage(planes, strides, mAlignedImage.width, mAlignedImage.height,
-                                    UHDR_IMG_FMT_12bppYCbCr420, JPEG_QUALITY, NULL, 0));
+  EXPECT_EQ(encoder
+                .compressImage(planes, strides, mAlignedImage.width, mAlignedImage.height,
+                               UHDR_IMG_FMT_12bppYCbCr420, JPEG_QUALITY, NULL, 0)
+                .error_code,
+            UHDR_CODEC_OK);
   ASSERT_GT(encoder.getCompressedImageSize(), static_cast<uint32_t>(0));
 }
 
@@ -123,8 +125,11 @@ TEST_F(JpegEncoderHelperTest, encodeUnalignedImage) {
   const uint8_t* planes[3]{yPlane, uPlane, vPlane};
   const size_t strides[3]{mUnalignedImage.width, mUnalignedImage.width / 2,
                           mUnalignedImage.width / 2};
-  EXPECT_TRUE(encoder.compressImage(planes, strides, mUnalignedImage.width, mUnalignedImage.height,
-                                    UHDR_IMG_FMT_12bppYCbCr420, JPEG_QUALITY, NULL, 0));
+  EXPECT_EQ(encoder
+                .compressImage(planes, strides, mUnalignedImage.width, mUnalignedImage.height,
+                               UHDR_IMG_FMT_12bppYCbCr420, JPEG_QUALITY, NULL, 0)
+                .error_code,
+            UHDR_CODEC_OK);
   ASSERT_GT(encoder.getCompressedImageSize(), static_cast<uint32_t>(0));
 }
 
@@ -133,9 +138,12 @@ TEST_F(JpegEncoderHelperTest, encodeSingleChannelImage) {
   const uint8_t* yPlane = mSingleChannelImage.buffer.get();
   const uint8_t* planes[1]{yPlane};
   const size_t strides[1]{mSingleChannelImage.width};
-  EXPECT_TRUE(encoder.compressImage(planes, strides, mSingleChannelImage.width,
-                                    mSingleChannelImage.height, UHDR_IMG_FMT_8bppYCbCr400,
-                                    JPEG_QUALITY, NULL, 0));
+  EXPECT_EQ(
+      encoder
+          .compressImage(planes, strides, mSingleChannelImage.width, mSingleChannelImage.height,
+                         UHDR_IMG_FMT_8bppYCbCr400, JPEG_QUALITY, NULL, 0)
+          .error_code,
+      UHDR_CODEC_OK);
   ASSERT_GT(encoder.getCompressedImageSize(), static_cast<uint32_t>(0));
 }
 
@@ -143,9 +151,12 @@ TEST_F(JpegEncoderHelperTest, encodeRGBImage) {
   JpegEncoderHelper encoder;
   const uint8_t* rgbPlane = mRgbImage.buffer.get();
   const uint8_t* planes[1]{rgbPlane};
-  const size_t strides[1]{mRgbImage.width * 3};
-  EXPECT_TRUE(encoder.compressImage(planes, strides, mRgbImage.width, mRgbImage.height,
-                                    UHDR_IMG_FMT_24bppRGB888, JPEG_QUALITY, NULL, 0));
+  const size_t strides[1]{mRgbImage.width};
+  EXPECT_EQ(encoder
+                .compressImage(planes, strides, mRgbImage.width, mRgbImage.height,
+                               UHDR_IMG_FMT_24bppRGB888, JPEG_QUALITY, NULL, 0)
+                .error_code,
+            UHDR_CODEC_OK);
   ASSERT_GT(encoder.getCompressedImageSize(), static_cast<uint32_t>(0));
 }
 
diff --git a/tests/jpegr_test.cpp b/tests/jpegr_test.cpp
index f687efc..dc4cde5 100644
--- a/tests/jpegr_test.cpp
+++ b/tests/jpegr_test.cpp
@@ -1399,15 +1399,15 @@ TEST(JpegRTest, DecodeAPIWithInvalidArgs) {
 }
 
 TEST(JpegRTest, writeXmpThenRead) {
-  ultrahdr_metadata_struct metadata_expected;
+  uhdr_gainmap_metadata_ext_t metadata_expected;
   metadata_expected.version = "1.0";
-  metadata_expected.maxContentBoost = 1.25f;
-  metadata_expected.minContentBoost = 0.75f;
+  metadata_expected.max_content_boost = 1.25f;
+  metadata_expected.min_content_boost = 0.75f;
   metadata_expected.gamma = 1.0f;
-  metadata_expected.offsetSdr = 0.0f;
-  metadata_expected.offsetHdr = 0.0f;
-  metadata_expected.hdrCapacityMin = 1.0f;
-  metadata_expected.hdrCapacityMax = metadata_expected.maxContentBoost;
+  metadata_expected.offset_sdr = 0.0f;
+  metadata_expected.offset_hdr = 0.0f;
+  metadata_expected.hdr_capacity_min = 1.0f;
+  metadata_expected.hdr_capacity_max = metadata_expected.max_content_boost;
   const std::string nameSpace = "http://ns.adobe.com/xap/1.0/\0";
   const int nameSpaceLength = nameSpace.size() + 1;  // need to count the null terminator
 
@@ -1420,15 +1420,16 @@ TEST(JpegRTest, writeXmpThenRead) {
   xmpData.insert(xmpData.end(), reinterpret_cast<const uint8_t*>(xmp.c_str()),
                  reinterpret_cast<const uint8_t*>(xmp.c_str()) + xmp.size());
 
-  ultrahdr_metadata_struct metadata_read;
-  EXPECT_TRUE(getMetadataFromXMP(xmpData.data(), xmpData.size(), &metadata_read));
-  EXPECT_FLOAT_EQ(metadata_expected.maxContentBoost, metadata_read.maxContentBoost);
-  EXPECT_FLOAT_EQ(metadata_expected.minContentBoost, metadata_read.minContentBoost);
+  uhdr_gainmap_metadata_ext_t metadata_read;
+  EXPECT_EQ(getMetadataFromXMP(xmpData.data(), xmpData.size(), &metadata_read).error_code,
+            UHDR_CODEC_OK);
+  EXPECT_FLOAT_EQ(metadata_expected.max_content_boost, metadata_read.max_content_boost);
+  EXPECT_FLOAT_EQ(metadata_expected.min_content_boost, metadata_read.min_content_boost);
   EXPECT_FLOAT_EQ(metadata_expected.gamma, metadata_read.gamma);
-  EXPECT_FLOAT_EQ(metadata_expected.offsetSdr, metadata_read.offsetSdr);
-  EXPECT_FLOAT_EQ(metadata_expected.offsetHdr, metadata_read.offsetHdr);
-  EXPECT_FLOAT_EQ(metadata_expected.hdrCapacityMin, metadata_read.hdrCapacityMin);
-  EXPECT_FLOAT_EQ(metadata_expected.hdrCapacityMax, metadata_read.hdrCapacityMax);
+  EXPECT_FLOAT_EQ(metadata_expected.offset_sdr, metadata_read.offset_sdr);
+  EXPECT_FLOAT_EQ(metadata_expected.offset_hdr, metadata_read.offset_hdr);
+  EXPECT_FLOAT_EQ(metadata_expected.hdr_capacity_min, metadata_read.hdr_capacity_min);
+  EXPECT_FLOAT_EQ(metadata_expected.hdr_capacity_max, metadata_read.hdr_capacity_max);
 }
 
 class JpegRAPIEncodeAndDecodeTest
@@ -1461,7 +1462,7 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI0AndDecodeTest) {
   uhdrRawImg.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
   uhdrRawImg.cg = map_internal_cg_to_cg(mP010ColorGamut);
   uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_HLG);
-  uhdrRawImg.range = UHDR_CR_UNSPECIFIED;
+  uhdrRawImg.range = UHDR_CR_LIMITED_RANGE;
   uhdrRawImg.w = kImageWidth;
   uhdrRawImg.h = kImageHeight;
   uhdrRawImg.planes[UHDR_PLANE_Y] = rawImg.getImageHandle()->data;
@@ -1473,6 +1474,14 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI0AndDecodeTest) {
   ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
   status = uhdr_enc_set_quality(obj, kQuality, UHDR_BASE_IMG);
   ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+  status = uhdr_enc_set_using_multi_channel_gainmap(obj, false);
+  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+  status = uhdr_enc_set_gainmap_scale_factor(obj, 4);
+  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+  status = uhdr_enc_set_quality(obj, 85, UHDR_GAIN_MAP_IMG);
+  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+  status = uhdr_enc_set_preset(obj, UHDR_USAGE_REALTIME);
+  ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
   status = uhdr_encode(obj);
   ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
   uhdr_compressed_image_t* compressedImage = uhdr_get_encoded_stream(obj);
@@ -1524,7 +1533,7 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI0AndDecodeTest) {
     uhdrRawImg.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
     uhdrRawImg.cg = map_internal_cg_to_cg(mP010ColorGamut);
     uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_HLG);
-    uhdrRawImg.range = UHDR_CR_UNSPECIFIED;
+    uhdrRawImg.range = UHDR_CR_LIMITED_RANGE;
     uhdrRawImg.w = kImageWidth;
     uhdrRawImg.h = kImageHeight;
     uhdrRawImg.planes[UHDR_PLANE_Y] = rawImg2.getImageHandle()->data;
@@ -1535,6 +1544,14 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI0AndDecodeTest) {
     ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
     status = uhdr_enc_set_quality(obj, kQuality, UHDR_BASE_IMG);
     ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_using_multi_channel_gainmap(obj, false);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_gainmap_scale_factor(obj, 4);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_quality(obj, 85, UHDR_GAIN_MAP_IMG);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_preset(obj, UHDR_USAGE_REALTIME);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
     status = uhdr_encode(obj);
     ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
     uhdr_compressed_image_t* compressedImage = uhdr_get_encoded_stream(obj);
@@ -1724,7 +1741,7 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI1AndDecodeTest) {
     uhdrRawImg.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
     uhdrRawImg.cg = map_internal_cg_to_cg(mP010ColorGamut);
     uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_HLG);
-    uhdrRawImg.range = UHDR_CR_UNSPECIFIED;
+    uhdrRawImg.range = UHDR_CR_LIMITED_RANGE;
     uhdrRawImg.w = kImageWidth;
     uhdrRawImg.h = kImageHeight;
     uhdrRawImg.planes[UHDR_PLANE_Y] = rawImgP010.getImageHandle()->data;
@@ -1738,7 +1755,7 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI1AndDecodeTest) {
     uhdrRawImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
     uhdrRawImg.cg = map_internal_cg_to_cg(mYuv420ColorGamut);
     uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_SRGB);
-    uhdrRawImg.range = UHDR_CR_UNSPECIFIED;
+    uhdrRawImg.range = UHDR_CR_FULL_RANGE;
     uhdrRawImg.w = kImageWidth;
     uhdrRawImg.h = kImageHeight;
     uhdrRawImg.planes[UHDR_PLANE_Y] = rawImg2420.getImageHandle()->data;
@@ -1753,6 +1770,14 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI1AndDecodeTest) {
 
     status = uhdr_enc_set_quality(obj, kQuality, UHDR_BASE_IMG);
     ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_using_multi_channel_gainmap(obj, false);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_gainmap_scale_factor(obj, 4);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_quality(obj, 85, UHDR_GAIN_MAP_IMG);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_preset(obj, UHDR_USAGE_REALTIME);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
     status = uhdr_encode(obj);
     ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
     uhdr_compressed_image_t* compressedImage = uhdr_get_encoded_stream(obj);
@@ -1930,7 +1955,7 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI2AndDecodeTest) {
     uhdrRawImg.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
     uhdrRawImg.cg = map_internal_cg_to_cg(mP010ColorGamut);
     uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_HLG);
-    uhdrRawImg.range = UHDR_CR_UNSPECIFIED;
+    uhdrRawImg.range = UHDR_CR_LIMITED_RANGE;
     uhdrRawImg.w = kImageWidth;
     uhdrRawImg.h = kImageHeight;
     uhdrRawImg.planes[UHDR_PLANE_Y] = rawImgP010.getImageHandle()->data;
@@ -1944,7 +1969,7 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI2AndDecodeTest) {
     uhdrRawImg.fmt = UHDR_IMG_FMT_12bppYCbCr420;
     uhdrRawImg.cg = map_internal_cg_to_cg(mYuv420ColorGamut);
     uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_SRGB);
-    uhdrRawImg.range = UHDR_CR_UNSPECIFIED;
+    uhdrRawImg.range = UHDR_CR_FULL_RANGE;
     uhdrRawImg.w = kImageWidth;
     uhdrRawImg.h = kImageHeight;
     uhdrRawImg.planes[UHDR_PLANE_Y] = rawImg2420.getImageHandle()->data;
@@ -1969,6 +1994,14 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI2AndDecodeTest) {
 
     status = uhdr_enc_set_quality(obj, kQuality, UHDR_BASE_IMG);
     ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_using_multi_channel_gainmap(obj, false);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_gainmap_scale_factor(obj, 4);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_quality(obj, 85, UHDR_GAIN_MAP_IMG);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_preset(obj, UHDR_USAGE_REALTIME);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
     status = uhdr_encode(obj);
     ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
     uhdr_compressed_image_t* compressedImage = uhdr_get_encoded_stream(obj);
@@ -2107,7 +2140,7 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI3AndDecodeTest) {
     uhdrRawImg.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
     uhdrRawImg.cg = map_internal_cg_to_cg(mP010ColorGamut);
     uhdrRawImg.ct = map_internal_ct_to_ct(ultrahdr_transfer_function::ULTRAHDR_TF_HLG);
-    uhdrRawImg.range = UHDR_CR_UNSPECIFIED;
+    uhdrRawImg.range = UHDR_CR_LIMITED_RANGE;
     uhdrRawImg.w = kImageWidth;
     uhdrRawImg.h = kImageHeight;
     uhdrRawImg.planes[UHDR_PLANE_Y] = rawImgP010.getImageHandle()->data;
@@ -2130,6 +2163,14 @@ TEST_P(JpegRAPIEncodeAndDecodeTest, EncodeAPI3AndDecodeTest) {
 
     status = uhdr_enc_set_quality(obj, kQuality, UHDR_BASE_IMG);
     ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_using_multi_channel_gainmap(obj, false);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_gainmap_scale_factor(obj, 4);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_quality(obj, 85, UHDR_GAIN_MAP_IMG);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
+    status = uhdr_enc_set_preset(obj, UHDR_USAGE_REALTIME);
+    ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
     status = uhdr_encode(obj);
     ASSERT_EQ(UHDR_CODEC_OK, status.error_code) << status.detail;
     uhdr_compressed_image_t* compressedImage = uhdr_get_encoded_stream(obj);
@@ -2202,48 +2243,47 @@ class Profiler {
 
 class JpegRBenchmark : public JpegR {
  public:
-  void BenchmarkGenerateGainMap(jr_uncompressed_ptr yuv420Image, jr_uncompressed_ptr p010Image,
-                                ultrahdr_metadata_ptr metadata, jr_uncompressed_ptr map);
-  void BenchmarkApplyGainMap(jr_uncompressed_ptr yuv420Image, jr_uncompressed_ptr map,
-                             ultrahdr_metadata_ptr metadata, jr_uncompressed_ptr dest);
+#ifdef UHDR_ENABLE_GLES
+  JpegRBenchmark(uhdr_opengl_ctxt_t* uhdrGLCtxt) : JpegR(uhdrGLCtxt) {}
+#endif
+  void BenchmarkGenerateGainMap(uhdr_raw_image_t* yuv420Image, uhdr_raw_image_t* p010Image,
+                                uhdr_gainmap_metadata_ext_t* metadata,
+                                std::unique_ptr<uhdr_raw_image_ext_t>& gainmap);
+  void BenchmarkApplyGainMap(uhdr_raw_image_t* yuv420Image, uhdr_raw_image_t* map,
+                             uhdr_gainmap_metadata_ext_t* metadata, uhdr_raw_image_t* dest);
 
  private:
   const int kProfileCount = 10;
 };
 
-void JpegRBenchmark::BenchmarkGenerateGainMap(jr_uncompressed_ptr yuv420Image,
-                                              jr_uncompressed_ptr p010Image,
-                                              ultrahdr_metadata_ptr metadata,
-                                              jr_uncompressed_ptr map) {
-  ASSERT_EQ(yuv420Image->width, p010Image->width);
-  ASSERT_EQ(yuv420Image->height, p010Image->height);
+void JpegRBenchmark::BenchmarkGenerateGainMap(uhdr_raw_image_t* yuv420Image,
+                                              uhdr_raw_image_t* p010Image,
+                                              uhdr_gainmap_metadata_ext_t* metadata,
+                                              std::unique_ptr<uhdr_raw_image_ext_t>& gainmap) {
+  ASSERT_EQ(yuv420Image->w, p010Image->w);
+  ASSERT_EQ(yuv420Image->h, p010Image->h);
   Profiler profileGenerateMap;
   profileGenerateMap.timerStart();
   for (auto i = 0; i < kProfileCount; i++) {
-    ASSERT_EQ(JPEGR_NO_ERROR,
-              generateGainMap(yuv420Image, p010Image, ultrahdr_transfer_function::ULTRAHDR_TF_HLG,
-                              metadata, map));
-    if (i != kProfileCount - 1) {
-      delete[] static_cast<uint8_t*>(map->data);
-      map->data = nullptr;
-    }
+    ASSERT_EQ(UHDR_CODEC_OK, generateGainMap(yuv420Image, p010Image, metadata, gainmap).error_code);
   }
   profileGenerateMap.timerStop();
-  ALOGE("Generate Gain Map:- Res = %zu x %zu, time = %f ms", yuv420Image->width,
-        yuv420Image->height, profileGenerateMap.elapsedTime() / (kProfileCount * 1000.f));
+  ALOGV("Generate Gain Map:- Res = %u x %u, time = %f ms", yuv420Image->w, yuv420Image->h,
+        profileGenerateMap.elapsedTime() / (kProfileCount * 1000.f));
 }
 
-void JpegRBenchmark::BenchmarkApplyGainMap(jr_uncompressed_ptr yuv420Image, jr_uncompressed_ptr map,
-                                           ultrahdr_metadata_ptr metadata,
-                                           jr_uncompressed_ptr dest) {
+void JpegRBenchmark::BenchmarkApplyGainMap(uhdr_raw_image_t* yuv420Image, uhdr_raw_image_t* map,
+                                           uhdr_gainmap_metadata_ext_t* metadata,
+                                           uhdr_raw_image_t* dest) {
   Profiler profileRecMap;
   profileRecMap.timerStart();
   for (auto i = 0; i < kProfileCount; i++) {
-    ASSERT_EQ(JPEGR_NO_ERROR, applyGainMap(yuv420Image, map, metadata, ULTRAHDR_OUTPUT_HDR_HLG,
-                                           metadata->maxContentBoost /* displayBoost */, dest));
+    ASSERT_EQ(UHDR_CODEC_OK, applyGainMap(yuv420Image, map, metadata, UHDR_CT_HLG,
+                                          UHDR_IMG_FMT_32bppRGBA1010102, FLT_MAX, dest)
+                                 .error_code);
   }
   profileRecMap.timerStop();
-  ALOGE("Apply Gain Map:- Res = %zu x %zu, time = %f ms", yuv420Image->width, yuv420Image->height,
+  ALOGV("Apply Gain Map:- Res = %u x %u, time = %f ms", yuv420Image->w, yuv420Image->h,
         profileRecMap.elapsedTime() / (kProfileCount * 1000.f));
 }
 
@@ -2256,14 +2296,9 @@ TEST(JpegRTest, ProfileGainMapFuncs) {
   ASSERT_TRUE(rawImg420.setImageColorGamut(ultrahdr_color_gamut::ULTRAHDR_COLORGAMUT_BT709));
   ASSERT_TRUE(rawImg420.allocateMemory());
   ASSERT_TRUE(rawImg420.loadRawResource(kYCbCr420FileName));
-  ultrahdr_metadata_struct metadata;
-  metadata.version = kJpegrVersion;
-  jpegr_uncompressed_struct map;
-  map.data = NULL;
-  map.width = 0;
-  map.height = 0;
-  map.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
-  map.pixelFormat = UHDR_IMG_FMT_8bppYCbCr400;
+  uhdr_gainmap_metadata_ext_t metadata(kJpegrVersion);
+
+  uhdr_raw_image_t hdr_intent, sdr_intent;
 
   {
     auto rawImg = rawImgP010.getImageHandle();
@@ -2273,6 +2308,18 @@ TEST(JpegRTest, ProfileGainMapFuncs) {
       rawImg->chroma_data = data + rawImg->luma_stride * rawImg->height;
       rawImg->chroma_stride = rawImg->luma_stride;
     }
+    hdr_intent.fmt = UHDR_IMG_FMT_24bppYCbCrP010;
+    hdr_intent.cg = UHDR_CG_BT_2100;
+    hdr_intent.ct = UHDR_CT_HLG;
+    hdr_intent.range = UHDR_CR_LIMITED_RANGE;
+    hdr_intent.w = rawImg->width;
+    hdr_intent.h = rawImg->height;
+    hdr_intent.planes[UHDR_PLANE_Y] = rawImg->data;
+    hdr_intent.stride[UHDR_PLANE_Y] = rawImg->luma_stride;
+    hdr_intent.planes[UHDR_PLANE_UV] = rawImg->chroma_data;
+    hdr_intent.stride[UHDR_PLANE_UV] = rawImg->chroma_stride;
+    hdr_intent.planes[UHDR_PLANE_V] = nullptr;
+    hdr_intent.stride[UHDR_PLANE_V] = 0;
   }
   {
     auto rawImg = rawImg420.getImageHandle();
@@ -2282,27 +2329,57 @@ TEST(JpegRTest, ProfileGainMapFuncs) {
       rawImg->chroma_data = data + rawImg->luma_stride * rawImg->height;
       rawImg->chroma_stride = rawImg->luma_stride / 2;
     }
-  }
-
+    sdr_intent.fmt = UHDR_IMG_FMT_12bppYCbCr420;
+    sdr_intent.cg = UHDR_CG_DISPLAY_P3;
+    sdr_intent.ct = UHDR_CT_SRGB;
+    sdr_intent.range = rawImg->colorRange;
+    sdr_intent.w = rawImg->width;
+    sdr_intent.h = rawImg->height;
+    sdr_intent.planes[UHDR_PLANE_Y] = rawImg->data;
+    sdr_intent.stride[UHDR_PLANE_Y] = rawImg->luma_stride;
+    sdr_intent.planes[UHDR_PLANE_U] = rawImg->chroma_data;
+    sdr_intent.stride[UHDR_PLANE_U] = rawImg->chroma_stride;
+    uint8_t* data = reinterpret_cast<uint8_t*>(rawImg->chroma_data);
+    data += (rawImg->height * rawImg->chroma_stride) / 2;
+    sdr_intent.planes[UHDR_PLANE_V] = data;
+    sdr_intent.stride[UHDR_PLANE_V] = rawImg->chroma_stride;
+  }
+
+  std::unique_ptr<uhdr_raw_image_ext_t> gainmap;
+
+#ifdef UHDR_ENABLE_GLES
+  uhdr_opengl_ctxt_t glCtxt;
+  glCtxt.init_opengl_ctxt();
+  JpegRBenchmark benchmark(glCtxt.mErrorStatus.error_code == UHDR_CODEC_OK ? &glCtxt : nullptr);
+#else
   JpegRBenchmark benchmark;
-  ASSERT_NO_FATAL_FAILURE(benchmark.BenchmarkGenerateGainMap(
-      rawImg420.getImageHandle(), rawImgP010.getImageHandle(), &metadata, &map));
+#endif
+
+  ASSERT_NO_FATAL_FAILURE(
+      benchmark.BenchmarkGenerateGainMap(&sdr_intent, &hdr_intent, &metadata, gainmap));
 
   const int dstSize = kImageWidth * kImageWidth * 4;
   auto bufferDst = std::make_unique<uint8_t[]>(dstSize);
-  jpegr_uncompressed_struct dest;
-  dest.data = bufferDst.get();
-  dest.width = 0;
-  dest.height = 0;
-  dest.colorGamut = ULTRAHDR_COLORGAMUT_UNSPECIFIED;
+  uhdr_raw_image_t output;
+  output.fmt = UHDR_IMG_FMT_32bppRGBA1010102;
+  output.cg = UHDR_CG_UNSPECIFIED;
+  output.ct = UHDR_CT_UNSPECIFIED;
+  output.range = UHDR_CR_UNSPECIFIED;
+  output.w = kImageWidth;
+  output.h = kImageHeight;
+  output.planes[UHDR_PLANE_PACKED] = bufferDst.get();
+  output.stride[UHDR_PLANE_PACKED] = kImageWidth;
+  output.planes[UHDR_PLANE_U] = nullptr;
+  output.stride[UHDR_PLANE_U] = 0;
+  output.planes[UHDR_PLANE_V] = nullptr;
+  output.stride[UHDR_PLANE_V] = 0;
 
   ASSERT_NO_FATAL_FAILURE(
-      benchmark.BenchmarkApplyGainMap(rawImg420.getImageHandle(), &map, &metadata, &dest));
+      benchmark.BenchmarkApplyGainMap(&sdr_intent, gainmap.get(), &metadata, &output));
 
-  if (map.data) {
-    delete[] static_cast<uint8_t*>(map.data);
-    map.data = nullptr;
-  }
+#ifdef UHDR_ENABLE_GLES
+  glCtxt.delete_opengl_ctxt();
+#endif
 }
 
 }  // namespace ultrahdr
diff --git a/third_party/image_io/src/jpeg/jpeg_xmp_info.cc b/third_party/image_io/src/jpeg/jpeg_xmp_info.cc
index e6ad8c6..21978d8 100644
--- a/third_party/image_io/src/jpeg/jpeg_xmp_info.cc
+++ b/third_party/image_io/src/jpeg/jpeg_xmp_info.cc
@@ -24,6 +24,7 @@ string JpegXmpInfo::GetIdentifier(Type jpeg_xmp_info_type) {
     case kGImageInfoType:
       return kXmpGImageV1Id;
   }
+  return "";
 }
 
 string JpegXmpInfo::GetDataPropertyName(Type jpeg_xmp_info_type) {
@@ -33,6 +34,7 @@ string JpegXmpInfo::GetDataPropertyName(Type jpeg_xmp_info_type) {
     case kGImageInfoType:
       return kGImageDataPropertyName;
   }
+  return "";
 }
 
 string JpegXmpInfo::GetMimePropertyName(Type jpeg_xmp_info_type) {
@@ -42,6 +44,7 @@ string JpegXmpInfo::GetMimePropertyName(Type jpeg_xmp_info_type) {
     case kGImageInfoType:
       return kGImageMimePropertyName;
   }
+  return "";
 }
 
 }  // namespace image_io
diff --git a/ultrahdr_api.h b/ultrahdr_api.h
index 1139c1c..d2d3627 100644
--- a/ultrahdr_api.h
+++ b/ultrahdr_api.h
@@ -44,6 +44,46 @@
 #define UHDR_EXTERN extern UHDR_API
 #endif
 
+/*
+ * A Note on version numbering:
+ * Over the course of development multiple changes were made to the interface that are not entirely
+ * backward compatible. Some APIs were renamed for consistency and better readability. New APIs were
+ * introduced to allow configuration of encoding/decoding parameters. As per convention, breaking
+ * backward compatibility MUST be indicated with a major version update, introducing new APIs /
+ * features MUST be indicated with a minor version update and bug fixes MUST be indicated with a
+ * patch version update. This convention however, is not followed. Below table summarizes these
+ * details:
+ *
+ * source version    ultrahdr_api.h                 Details
+ *                   version string
+ * --------------    --------------              -------------
+ *   1.0.0           Not available               This version did not have a public API. Apps,
+ *                                               directly included the project header files.
+ *   1.1.0           Not available               ultrahdr_api.h is introduced in this release. The
+ *                                               API header file did not advertise any version
+ *                                               string.
+ *   1.1.1           Not available               The API header file did not advertise any version
+ *                                               string. Some bug fixes and introduced one new API
+ *                                               which warrants a minor version update. But
+ *                                               indicated as a patch update.
+ *   1.2.0           1.2.0                       Some bug fixes, introduced new API and renamed
+ *                                               existing API which warrants a major version update.
+ *                                               But indicated as a minor update.
+ */
+
+// This needs to be kept in sync with version in CMakeLists.txt
+#define UHDR_LIB_VER_MAJOR 1
+#define UHDR_LIB_VER_MINOR 2
+#define UHDR_LIB_VER_PATCH 0
+
+#define UHDR_LIB_VERSION \
+  ((UHDR_LIB_VER_MAJOR * 10000) + (UHDR_LIB_VER_MINOR * 100) + UHDR_LIB_VER_PATCH)
+
+#define XSTR(s) STR(s)
+#define STR(s) #s
+#define UHDR_LIB_VERSION_STR \
+  XSTR(UHDR_LIB_VER_MAJOR) "." XSTR(UHDR_LIB_VER_MINOR) "." XSTR(UHDR_LIB_VER_PATCH)
+
 // ===============================================================================================
 // Enum Definitions
 // ===============================================================================================
@@ -66,14 +106,14 @@ typedef enum uhdr_img_fmt {
                                       green,   blue, and 2-bit alpha components. Using 32-bit
                                       little-endian   representation, colors stored as Red 9:0, Green
                                       19:10, Blue   29:20, and Alpha 31:30. */
-
-  UHDR_IMG_FMT_24bppYCbCr444 = 6,  /**< 8-bit-per component 4:4:4 YCbCr planar format */
-  UHDR_IMG_FMT_16bppYCbCr422 = 7,  /**< 8-bit-per component 4:2:2 YCbCr planar format */
-  UHDR_IMG_FMT_16bppYCbCr440 = 8,  /**< 8-bit-per component 4:4:0 YCbCr planar format */
-  UHDR_IMG_FMT_12bppYCbCr411 = 9,  /**< 8-bit-per component 4:1:1 YCbCr planar format */
-  UHDR_IMG_FMT_10bppYCbCr410 = 10, /**< 8-bit-per component 4:1:0 YCbCr planar format */
-  UHDR_IMG_FMT_24bppRGB888 = 11,   /**< 8-bit-per component RGB interleaved format */
-} uhdr_img_fmt_t;                  /**< alias for enum uhdr_img_fmt */
+  UHDR_IMG_FMT_24bppYCbCr444 = 6,      /**< 8-bit-per component 4:4:4 YCbCr planar format */
+  UHDR_IMG_FMT_16bppYCbCr422 = 7,      /**< 8-bit-per component 4:2:2 YCbCr planar format */
+  UHDR_IMG_FMT_16bppYCbCr440 = 8,      /**< 8-bit-per component 4:4:0 YCbCr planar format */
+  UHDR_IMG_FMT_12bppYCbCr411 = 9,      /**< 8-bit-per component 4:1:1 YCbCr planar format */
+  UHDR_IMG_FMT_10bppYCbCr410 = 10,     /**< 8-bit-per component 4:1:0 YCbCr planar format */
+  UHDR_IMG_FMT_24bppRGB888 = 11,       /**< 8-bit-per component RGB interleaved format */
+  UHDR_IMG_FMT_30bppYCbCr444 = 12,     /**< 10-bit-per component 4:4:4 YCbCr planar format */
+} uhdr_img_fmt_t;                      /**< alias for enum uhdr_img_fmt */
 
 /*!\brief List of supported color gamuts */
 typedef enum uhdr_color_gamut {
@@ -101,9 +141,10 @@ typedef enum uhdr_color_range {
 
 /*!\brief List of supported codecs */
 typedef enum uhdr_codec {
-  UHDR_CODEC_JPG, /**< Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using
-                  jpeg */
-} uhdr_codec_t;   /**< alias for enum uhdr_codec */
+  UHDR_CODEC_JPG,  /**< Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using jpeg */
+  UHDR_CODEC_HEIF, /**< Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using heif */
+  UHDR_CODEC_AVIF, /**< Compress {Hdr, Sdr rendition} to an {Sdr rendition + Gain Map} using avif */
+} uhdr_codec_t;    /**< alias for enum uhdr_codec */
 
 /*!\brief Image identifiers in gain map technology */
 typedef enum uhdr_img_label {
@@ -113,13 +154,22 @@ typedef enum uhdr_img_label {
   UHDR_GAIN_MAP_IMG, /**< Gain map image */
 } uhdr_img_label_t;  /**< alias for enum uhdr_img_label */
 
+/*!\brief uhdr encoder usage parameter */
+typedef enum uhdr_enc_preset {
+  UHDR_USAGE_REALTIME,     /**< tune encoder settings for performance */
+  UHDR_USAGE_BEST_QUALITY, /**< tune encoder settings for quality */
+} uhdr_enc_preset_t;       /**< alias for enum uhdr_enc_preset */
+
 /*!\brief Algorithm return codes */
 typedef enum uhdr_codec_err {
 
   /*!\brief Operation completed without error */
   UHDR_CODEC_OK,
 
-  /*!\brief Unspecified error */
+  /*!\brief Generic codec error, refer detail field for more information */
+  UHDR_CODEC_ERROR,
+
+  /*!\brief Unknown error, refer detail field for more information */
   UHDR_CODEC_UNKNOWN_ERROR,
 
   /*!\brief An application-supplied parameter is not valid. */
@@ -128,31 +178,37 @@ typedef enum uhdr_codec_err {
   /*!\brief Memory operation failed */
   UHDR_CODEC_MEM_ERROR,
 
-  /*!\brief An application-invoked operation is not valid. */
+  /*!\brief An application-invoked operation is not valid */
   UHDR_CODEC_INVALID_OPERATION,
 
   /*!\brief The library does not implement a feature required for the operation */
   UHDR_CODEC_UNSUPPORTED_FEATURE,
 
-  /*!\brief An iterator reached the end of list. */
+  /*!\brief Not for usage, indicates end of list */
   UHDR_CODEC_LIST_END,
 
 } uhdr_codec_err_t; /**< alias for enum uhdr_codec_err */
 
+/*!\brief List of supported mirror directions. */
+typedef enum uhdr_mirror_direction {
+  UHDR_MIRROR_VERTICAL,    /**< flip image over x axis */
+  UHDR_MIRROR_HORIZONTAL,  /**< flip image over y axis */
+} uhdr_mirror_direction_t; /**< alias for enum uhdr_mirror_direction */
+
 // ===============================================================================================
 // Structure Definitions
 // ===============================================================================================
 
 /*!\brief Detailed return status */
 typedef struct uhdr_error_info {
-  uhdr_codec_err_t error_code;
-  int has_detail;
-  char detail[256];
-} uhdr_error_info_t; /**< alias for struct uhdr_error_info */
+  uhdr_codec_err_t error_code; /**< error code */
+  int has_detail;              /**< has detailed error logs. 0 - no, else - yes */
+  char detail[256];            /**< error logs */
+} uhdr_error_info_t;           /**< alias for struct uhdr_error_info */
 
 /**\brief Raw Image Descriptor */
 typedef struct uhdr_raw_image {
-  /* Color model, primaries, transfer, range */
+  /* Color Aspects: Color model, primaries, transfer, range */
   uhdr_img_fmt_t fmt;       /**< Image Format */
   uhdr_color_gamut_t cg;    /**< Color Gamut */
   uhdr_color_transfer_t ct; /**< Color Transfer */
@@ -189,19 +245,23 @@ typedef struct uhdr_mem_block {
   unsigned int capacity; /**< maximum size of the data buffer */
 } uhdr_mem_block_t;      /**< alias for struct uhdr_mem_block */
 
-/**\brief Gain map metadata.
- * Note: all values stored in linear space. This differs from the metadata encoded in XMP, where
- * max_content_boost (aka gainMapMax), min_content_boost (aka gainMapMin), hdr_capacity_min, and
- * hdr_capacity_max are stored in log2 space.
- */
+/**\brief Gain map metadata. */
 typedef struct uhdr_gainmap_metadata {
-  float max_content_boost; /**< Max Content Boost for the map */
-  float min_content_boost; /**< Min Content Boost for the map */
-  float gamma;             /**< Gamma of the map data */
-  float offset_sdr;        /**< Offset for SDR data in map calculations */
-  float offset_hdr;        /**< Offset for HDR data in map calculations */
-  float hdr_capacity_min;  /**< Min HDR capacity values for interpolating the Gain Map */
-  float hdr_capacity_max;  /**< Max HDR capacity value for interpolating the Gain Map */
+  float max_content_boost; /**< Value to control how much brighter an image can get, when shown on
+                              an HDR display, relative to the SDR rendition. This is constant for a
+                              given image. Value MUST be in linear scale. */
+  float min_content_boost; /**< Value to control how much darker an image can get, when shown on
+                              an HDR display, relative to the SDR rendition. This is constant for a
+                              given image. Value MUST be in linear scale. */
+  float gamma;             /**< Encoding Gamma of the gainmap image. */
+  float offset_sdr; /**< The offset to apply to the SDR pixel values during gainmap generation and
+                       application. */
+  float offset_hdr; /**< The offset to apply to the HDR pixel values during gainmap generation and
+                       application. */
+  float hdr_capacity_min;  /**< Minimum display boost value for which the map is applied completely.
+                              Value MUST be in linear scale. */
+  float hdr_capacity_max;  /**< Maximum display boost value for which the map is applied completely.
+                              Value MUST be in linear scale. */
 } uhdr_gainmap_metadata_t; /**< alias for struct uhdr_gainmap_metadata */
 
 /**\brief ultrahdr codec context opaque descriptor */
@@ -256,6 +316,14 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_raw_image(uhdr_codec_private_t* enc,
  * for the same intent, it is assumed that raw image descriptor and compressed image descriptor are
  * relatable via compress <-> decompress process.
  *
+ * The compressed image descriptors has fields cg, ct and range. Certain media formats are capable
+ * of storing color standard, color transfer and color range characteristics in the bitstream (for
+ * example heif, avif, ...). Other formats may not support this (jpeg, ...). These fields serve as
+ * an additional source for conveying this information. If the user is unaware of the color aspects
+ * of the image, #UHDR_CG_UNSPECIFIED, #UHDR_CT_UNSPECIFIED, #UHDR_CR_UNSPECIFIED can be used. If
+ * color aspects are present inside the bitstream and supplied via these fields both are expected to
+ * be identical.
+ *
  * \param[in]  enc  encoder instance.
  * \param[in]  img  image descriptor.
  * \param[in]  intent  UHDR_HDR_IMG for hdr intent,
@@ -269,10 +337,17 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_compressed_image(uhdr_codec_private_t
                                                             uhdr_compressed_image_t* img,
                                                             uhdr_img_label_t intent);
 
-/*!\brief Add gain map image descriptor and gainmap metadata info to encoder context. The function
- * internally goes through all the fields of the image descriptor and checks for their sanity. If no
- * anomalies are seen then the image is added to internal list. Repeated calls to this function will
- * replace the old entry with the current.
+/*!\brief Add gain map image descriptor and gainmap metadata info that was used to generate the
+ * aforth gainmap image to encoder context. The function internally goes through all the fields of
+ * the image descriptor and checks for their sanity. If no anomalies are seen then the image is
+ * added to internal list. Repeated calls to this function will replace the old entry with the
+ * current.
+ *
+ * NOTE: There are apis that allow configuration of gainmap info separately. For instance
+ * #uhdr_enc_set_gainmap_gamma, #uhdr_enc_set_gainmap_scale_factor, ... They have no effect on the
+ * information that is configured via this api. The information configured here is treated as
+ * immutable and used as-is in encoding scenario where gainmap computations are intended to be
+ * by-passed.
  *
  * \param[in]  enc  encoder instance.
  * \param[in]  img  gain map image desciptor.
@@ -285,11 +360,12 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_image(uhdr_codec_private_t* e
                                                          uhdr_compressed_image_t* img,
                                                          uhdr_gainmap_metadata_t* metadata);
 
-/*!\brief Set quality for compression
+/*!\brief Set quality factor for compressing base image and/or gainmap image. Default configured
+ * quality factor of base image and gainmap image are 95 and 95 respectively.
  *
  * \param[in]  enc  encoder instance.
- * \param[in]  quality  quality factor.
- * \param[in]  intent  UHDR_BASE_IMG for base image and UHDR_GAIN_MAP_IMG for gain map image.
+ * \param[in]  quality  quality factor. Any integer in range [0 - 100].
+ * \param[in]  intent  #UHDR_BASE_IMG for base image and #UHDR_GAIN_MAP_IMG for gain map image.
  *
  * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
  *                           #UHDR_CODEC_INVALID_PARAM otherwise.
@@ -297,10 +373,12 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_image(uhdr_codec_private_t* e
 UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_quality(uhdr_codec_private_t* enc, int quality,
                                                    uhdr_img_label_t intent);
 
-/*!\brief Set Exif data that needs to be inserted in the output compressed stream
+/*!\brief Set Exif data that needs to be inserted in the output compressed stream. This function
+ * does not generate or validate exif data on its own. It merely copies the supplied information
+ * into the bitstream.
  *
  * \param[in]  enc  encoder instance.
- * \param[in]  img  exif data descriptor.
+ * \param[in]  exif  exif data memory block.
  *
  * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
  *                           #UHDR_CODEC_INVALID_PARAM otherwise.
@@ -308,10 +386,79 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_quality(uhdr_codec_private_t* enc, in
 UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_exif_data(uhdr_codec_private_t* enc,
                                                      uhdr_mem_block_t* exif);
 
-/*!\brief Set output image compression format.
+/*!\brief Enable/Disable multi-channel gainmap. By default multi-channel gainmap is enabled.
+ *
+ * \param[in]  enc  encoder instance.
+ * \param[in]  use_multi_channel_gainmap  enable/disable multichannel gain map.
+ *                                        0 - single-channel gainmap is enabled,
+ *                                        otherwise - multi-channel gainmap is enabled.
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
+ *                           #UHDR_CODEC_INVALID_PARAM otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t
+uhdr_enc_set_using_multi_channel_gainmap(uhdr_codec_private_t* enc, int use_multi_channel_gainmap);
+
+/*!\brief Set gain map scaling factor. The encoding process allows signalling a downscaled gainmap
+ * image instead of full resolution. This setting controls the factor by which the renditions are
+ * downscaled. For instance, gainmap_scale_factor = 2 implies gainmap_image_width =
+ * primary_image_width / 2 and gainmap image height = primary_image_height / 2.
+ * Default gain map scaling factor is 1.
+ * NOTE: This has no effect on base image rendition. Base image is signalled in full resolution
+ * always.
+ *
+ * \param[in]  enc  encoder instance.
+ * \param[in]  gainmap_scale_factor  gain map scale factor. Any integer in range (0, 128]
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
+ *                           #UHDR_CODEC_INVALID_PARAM otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_scale_factor(uhdr_codec_private_t* enc,
+                                                                int gainmap_scale_factor);
+
+/*!\brief Set encoding gamma of gainmap image. For multi-channel gainmap image, set gamma is used
+ * for gamma correction of all planes separately. Default gamma value is 1.0.
+ *
+ * \param[in]  enc  encoder instance.
+ * \param[in]  gamma  gamma of gainmap image. Any positive real number.
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
+ *                           #UHDR_CODEC_INVALID_PARAM otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_gainmap_gamma(uhdr_codec_private_t* enc, float gamma);
+
+/*!\brief Set min max content boost. This configuration is treated as a recommendation by the
+ * library. It is entirely possible for the library to use a different set of values. Value MUST be
+ * in linear scale.
+ *
+ * \param[in]  enc  encoder instance.
+ * \param[in]  min_boost min content boost. Any positive real number.
+ * \param[in]  max_boost max content boost. Any positive real number >= min_boost.
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
+ *                           #UHDR_CODEC_INVALID_PARAM otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_min_max_content_boost(uhdr_codec_private_t* enc,
+                                                                 float min_boost, float max_boost);
+
+/*!\brief Set encoding preset. Tunes the encoder configurations for performance or quality. Default
+ * configuration is #UHDR_USAGE_BEST_QUALITY.
+ *
+ * \param[in]  enc  encoder instance.
+ * \param[in]  preset  encoding preset. #UHDR_USAGE_REALTIME - Tune settings for best performance
+ *                                      #UHDR_USAGE_BEST_QUALITY - Tune settings for best quality
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
+ *                           #UHDR_CODEC_INVALID_PARAM otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_preset(uhdr_codec_private_t* enc,
+                                                  uhdr_enc_preset_t preset);
+
+/*!\brief Set output image compression format. Selects the compression format for encoding base
+ * image and gainmap image. Default configuration is #UHDR_CODEC_JPG
  *
  * \param[in]  enc  encoder instance.
- * \param[in]  media_type  output image compression format.
+ * \param[in]  media_type  output image compression format. Supported values are #UHDR_CODEC_JPG
  *
  * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
  *                           #UHDR_CODEC_INVALID_PARAM otherwise.
@@ -335,6 +482,14 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_output_format(uhdr_codec_private_t* e
  *   - uhdr_enc_set_quality()
  * - If the application wants to insert exif data
  *   - uhdr_enc_set_exif_data()
+ * - If the application wants to set gainmap scale factor
+ *   - uhdr_enc_set_gainmap_scale_factor()
+ * - If the application wants to enable multi channel gain map
+ *   - uhdr_enc_set_using_multi_channel_gainmap()
+ * - If the application wants to set gainmap image gamma
+ *   - uhdr_enc_set_gainmap_gamma()
+ * - If the application wants to set encoding preset
+ *   - uhdr_enc_set_preset()
  * - If the application wants to control target compression format
  *   - uhdr_enc_set_output_format()
  * - The program calls uhdr_encode() to encode data. This call would initiate the process of
@@ -374,6 +529,9 @@ UHDR_EXTERN uhdr_error_info_t uhdr_enc_set_output_format(uhdr_codec_private_t* e
  * - uhdr_enc_set_quality() // optional
  * - uhdr_enc_set_exif_data() // optional
  * - uhdr_enc_set_output_format() // optional
+ * - uhdr_enc_set_gainmap_scale_factor() // optional
+ * - uhdr_enc_set_using_multi_channel_gainmap() // optional
+ * - uhdr_enc_set_gainmap_gamma() // optional
  * - uhdr_encode()
  * - uhdr_get_encoded_stream()
  * - uhdr_release_encoder()
@@ -398,7 +556,8 @@ UHDR_EXTERN uhdr_error_info_t uhdr_encode(uhdr_codec_private_t* enc);
 UHDR_EXTERN uhdr_compressed_image_t* uhdr_get_encoded_stream(uhdr_codec_private_t* enc);
 
 /*!\brief Reset encoder instance.
- * Clears all previous settings and resets to default state and ready for re-initialization
+ * Clears all previous settings and resets to default state and ready for re-initialization and
+ * usage
  *
  * \param[in]  enc  encoder instance.
  *
@@ -415,8 +574,9 @@ UHDR_EXTERN void uhdr_reset_encoder(uhdr_codec_private_t* enc);
  * @param[in]  data  pointer to input compressed stream
  * @param[in]  size  size of compressed stream
  *
- * @returns 1 if the input data has a primary image, gain map image and gain map metadata. 0
- * otherwise.
+ * @returns 1 if the input data has a primary image, gain map image and gain map metadata. 0 if any
+ *          errors are encountered during parsing process or if the image does not have primary
+ *          image or gainmap image or gainmap metadata
  */
 UHDR_EXTERN int is_uhdr_image(void* data, int size);
 
@@ -450,10 +610,12 @@ UHDR_EXTERN void uhdr_release_decoder(uhdr_codec_private_t* dec);
 UHDR_EXTERN uhdr_error_info_t uhdr_dec_set_image(uhdr_codec_private_t* dec,
                                                  uhdr_compressed_image_t* img);
 
-/*!\brief Set output image format
+/*!\brief Set output image color format
  *
  * \param[in]  dec  decoder instance.
- * \param[in]  fmt  output image format.
+ * \param[in]  fmt  output image color format. Supported values are
+ *                  #UHDR_IMG_FMT_64bppRGBAHalfFloat, #UHDR_IMG_FMT_32bppRGBA1010102,
+ *                  #UHDR_IMG_FMT_32bppRGBA8888
  *
  * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
  *                           #UHDR_CODEC_INVALID_PARAM otherwise.
@@ -461,7 +623,11 @@ UHDR_EXTERN uhdr_error_info_t uhdr_dec_set_image(uhdr_codec_private_t* dec,
 UHDR_EXTERN uhdr_error_info_t uhdr_dec_set_out_img_format(uhdr_codec_private_t* dec,
                                                           uhdr_img_fmt_t fmt);
 
-/*!\brief Set output color transfer
+/*!\brief Set output image color transfer characteristics. It should be noted that not all
+ * combinations of output color format and output transfer function are supported. #UHDR_CT_SRGB
+ * output color transfer shall be paired with #UHDR_IMG_FMT_32bppRGBA8888 only. #UHDR_CT_HLG,
+ * #UHDR_CT_PQ shall be paired with #UHDR_IMG_FMT_32bppRGBA1010102. #UHDR_CT_LINEAR shall be paired
+ * with #UHDR_IMG_FMT_64bppRGBAHalfFloat.
  *
  * \param[in]  dec  decoder instance.
  * \param[in]  ct  output color transfer
@@ -472,10 +638,12 @@ UHDR_EXTERN uhdr_error_info_t uhdr_dec_set_out_img_format(uhdr_codec_private_t*
 UHDR_EXTERN uhdr_error_info_t uhdr_dec_set_out_color_transfer(uhdr_codec_private_t* dec,
                                                               uhdr_color_transfer_t ct);
 
-/*!\brief Set output max display boost
+/*!\brief Set output display's HDR capacity. Value MUST be in linear scale. This value determines
+ * the weight by which the gain map coefficients are scaled. If no value is configured, no weight is
+ * applied to gainmap image.
  *
  * \param[in]  dec  decoder instance.
- * \param[in]  display_boost  max display boost
+ * \param[in]  display_boost  hdr capacity of target display. Any real number >= 1.0f
  *
  * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds,
  *                           #UHDR_CODEC_INVALID_PARAM otherwise.
@@ -541,13 +709,31 @@ UHDR_EXTERN uhdr_mem_block_t* uhdr_dec_get_exif(uhdr_codec_private_t* dec);
  */
 UHDR_EXTERN uhdr_mem_block_t* uhdr_dec_get_icc(uhdr_codec_private_t* dec);
 
+/*!\brief Get base image (compressed)
+ *
+ * \param[in]  dec  decoder instance.
+ *
+ * \return nullptr if probe process call is unsuccessful, memory block with base image data
+ * otherwise
+ */
+UHDR_EXTERN uhdr_mem_block_t* uhdr_dec_get_base_image(uhdr_codec_private_t* dec);
+
+/*!\brief Get gain map image (compressed)
+ *
+ * \param[in]  dec  decoder instance.
+ *
+ * \return nullptr if probe process call is unsuccessful, memory block with gainmap image data
+ * otherwise
+ */
+UHDR_EXTERN uhdr_mem_block_t* uhdr_dec_get_gainmap_image(uhdr_codec_private_t* dec);
+
 /*!\brief Get gain map metadata
  *
  * \param[in]  dec  decoder instance.
  *
  * \return nullptr if probe process call is unsuccessful, gainmap metadata descriptor otherwise
  */
-UHDR_EXTERN uhdr_gainmap_metadata_t* uhdr_dec_get_gain_map_metadata(uhdr_codec_private_t* dec);
+UHDR_EXTERN uhdr_gainmap_metadata_t* uhdr_dec_get_gainmap_metadata(uhdr_codec_private_t* dec);
 
 /*!\brief Decode process call
  * After initializing the decoder context, call to this function will submit data for decoding. If
@@ -566,6 +752,8 @@ UHDR_EXTERN uhdr_gainmap_metadata_t* uhdr_dec_get_gain_map_metadata(uhdr_codec_p
  *   - uhdr_dec_set_out_color_transfer()
  * - If the application wants to control the output display boost,
  *   - uhdr_dec_set_out_max_display_boost()
+ * - If the application wants to enable/disable gpu acceleration,
+ *   - uhdr_enable_gpu_acceleration()
  * - The program calls uhdr_decode() to decode uhdr stream. This call would initiate the process
  * of decoding base image and gain map image. These two are combined to give the final rendition
  * image.
@@ -592,10 +780,11 @@ UHDR_EXTERN uhdr_raw_image_t* uhdr_get_decoded_image(uhdr_codec_private_t* dec);
  *
  * \return nullptr if decoded process call is unsuccessful, raw image descriptor otherwise
  */
-UHDR_EXTERN uhdr_raw_image_t* uhdr_get_gain_map_image(uhdr_codec_private_t* dec);
+UHDR_EXTERN uhdr_raw_image_t* uhdr_get_decoded_gainmap_image(uhdr_codec_private_t* dec);
 
 /*!\brief Reset decoder instance.
- * Clears all previous settings and resets to default state and ready for re-initialization
+ * Clears all previous settings and resets to default state and ready for re-initialization and
+ * usage
  *
  * \param[in]  dec  decoder instance.
  *
@@ -603,4 +792,76 @@ UHDR_EXTERN uhdr_raw_image_t* uhdr_get_gain_map_image(uhdr_codec_private_t* dec)
  */
 UHDR_EXTERN void uhdr_reset_decoder(uhdr_codec_private_t* dec);
 
+// ===============================================================================================
+// Common APIs
+// ===============================================================================================
+
+/*!\brief Enable/Disable GPU acceleration.
+ * If enabled, certain operations (if possible) of uhdr encode/decode will be offloaded to GPU.
+ * NOTE: It is entirely possible for this API to have no effect on the encode/decode operation
+ *
+ * \param[in]  codec  codec instance.
+ * \param[in]  enable  enable enable/disbale gpu acceleration
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, #UHDR_CODEC_INVALID_PARAM
+ * otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t uhdr_enable_gpu_acceleration(uhdr_codec_private_t* codec, int enable);
+
+/*!\brief Add image editing operations (pre-encode or post-decode).
+ * Below functions list the set of edits supported. Program can set any combination of these during
+ * initialization. Once the encode/decode process call is made, before encoding or after decoding
+ * the edits are applied in the order of configuration.
+ */
+
+/*!\brief Add mirror effect
+ *
+ * \param[in]  codec  codec instance.
+ * \param[in]  direction  mirror directions. #UHDR_MIRROR_VERTICAL for vertical mirroring
+ *                                           #UHDR_MIRROR_HORIZONTAL for horizontal mirroing
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, #UHDR_CODEC_INVALID_PARAM
+ * otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t uhdr_add_effect_mirror(uhdr_codec_private_t* codec,
+                                                     uhdr_mirror_direction_t direction);
+
+/*!\brief Add rotate effect
+ *
+ * \param[in]  codec  codec instance.
+ * \param[in]  degrees  clockwise degrees. 90 - rotate clockwise by 90 degrees
+ *                                         180 - rotate clockwise by 180 degrees
+ *                                         270 - rotate clockwise by 270 degrees
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, #UHDR_CODEC_INVALID_PARAM
+ * otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t uhdr_add_effect_rotate(uhdr_codec_private_t* codec, int degrees);
+
+/*!\brief Add crop effect
+ *
+ * \param[in]  codec  codec instance.
+ * \param[in]  left  crop coordinate left in pixels.
+ * \param[in]  right  crop coordinate right in pixels.
+ * \param[in]  top  crop coordinate top in pixels.
+ * \param[in]  bottom  crop coordinate bottom in pixels.
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, #UHDR_CODEC_INVALID_PARAM
+ * otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t uhdr_add_effect_crop(uhdr_codec_private_t* codec, int left, int right,
+                                                   int top, int bottom);
+
+/*!\brief Add resize effect
+ *
+ * \param[in]  codec  codec instance.
+ * \param[in]  width  target width.
+ * \param[in]  height  target height.
+ *
+ * \return uhdr_error_info_t #UHDR_CODEC_OK if operation succeeds, #UHDR_CODEC_INVALID_PARAM
+ * otherwise.
+ */
+UHDR_EXTERN uhdr_error_info_t uhdr_add_effect_resize(uhdr_codec_private_t* codec, int width,
+                                                     int height);
+
 #endif  // ULTRAHDR_API_H
```

