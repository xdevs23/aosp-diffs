```diff
diff --git a/.github/workflows/bazel.yml b/.github/workflows/bazel.yml
index a669cda..b50a8f6 100644
--- a/.github/workflows/bazel.yml
+++ b/.github/workflows/bazel.yml
@@ -17,7 +17,7 @@ jobs:
     - uses: actions/checkout@v4
 
     - name: mount bazel cache
-      uses: actions/cache@v3
+      uses: actions/cache@v4
       env:
         cache-name: bazel-cache
       with:
diff --git a/.github/workflows/build-and-test-min-cmake.yml b/.github/workflows/build-and-test-min-cmake.yml
index e3e3217..b498006 100644
--- a/.github/workflows/build-and-test-min-cmake.yml
+++ b/.github/workflows/build-and-test-min-cmake.yml
@@ -16,7 +16,7 @@ jobs:
         os: [ubuntu-latest, macos-latest]
 
     steps:
-      - uses: actions/checkout@v3
+      - uses: actions/checkout@v4
 
       - uses: lukka/get-cmake@latest
         with:
diff --git a/.github/workflows/build-and-test-perfcounters.yml b/.github/workflows/build-and-test-perfcounters.yml
index 97e4d8e..319d42d 100644
--- a/.github/workflows/build-and-test-perfcounters.yml
+++ b/.github/workflows/build-and-test-perfcounters.yml
@@ -17,7 +17,7 @@ jobs:
         os: [ubuntu-22.04, ubuntu-20.04]
         build_type: ['Release', 'Debug']
     steps:
-    - uses: actions/checkout@v3
+    - uses: actions/checkout@v4
 
     - name: install libpfm
       run: |
diff --git a/.github/workflows/build-and-test.yml b/.github/workflows/build-and-test.yml
index 95e0482..d05300d 100644
--- a/.github/workflows/build-and-test.yml
+++ b/.github/workflows/build-and-test.yml
@@ -23,7 +23,7 @@ jobs:
         lib: ['shared', 'static']
 
     steps:
-      - uses: actions/checkout@v3
+      - uses: actions/checkout@v4
 
       - uses: lukka/get-cmake@latest
 
@@ -87,7 +87,7 @@ jobs:
             generator: 'Visual Studio 17 2022'
 
     steps:
-      - uses: actions/checkout@v2
+      - uses: actions/checkout@v4
 
       - uses: lukka/get-cmake@latest
 
@@ -129,7 +129,7 @@ jobs:
           - static
 
     steps:
-      - uses: actions/checkout@v2
+      - uses: actions/checkout@v4
 
       - name: Install Base Dependencies
         uses: msys2/setup-msys2@v2
diff --git a/.github/workflows/clang-format-lint.yml b/.github/workflows/clang-format-lint.yml
index 328fe36..8f089dc 100644
--- a/.github/workflows/clang-format-lint.yml
+++ b/.github/workflows/clang-format-lint.yml
@@ -9,8 +9,8 @@ jobs:
     runs-on: ubuntu-latest
 
     steps:
-    - uses: actions/checkout@v3
-    - uses: DoozyX/clang-format-lint-action@v0.13
+    - uses: actions/checkout@v4
+    - uses: DoozyX/clang-format-lint-action@v0.15
       with:
         source: './include/benchmark ./src ./test'
         extensions: 'h,cc'
diff --git a/.github/workflows/clang-tidy.yml b/.github/workflows/clang-tidy.yml
index 2eaab9c..558375e 100644
--- a/.github/workflows/clang-tidy.yml
+++ b/.github/workflows/clang-tidy.yml
@@ -11,7 +11,7 @@ jobs:
     strategy:
       fail-fast: false
     steps:
-    - uses: actions/checkout@v3
+    - uses: actions/checkout@v4
 
     - name: install clang-tidy
       run: sudo apt update && sudo apt -y install clang-tidy
diff --git a/.github/workflows/doxygen.yml b/.github/workflows/doxygen.yml
index da92c46..40c1cb4 100644
--- a/.github/workflows/doxygen.yml
+++ b/.github/workflows/doxygen.yml
@@ -12,7 +12,7 @@ jobs:
     runs-on: ubuntu-latest
     steps:
     - name: Fetching sources
-      uses: actions/checkout@v3
+      uses: actions/checkout@v4
 
     - name: Installing build dependencies
       run: |
diff --git a/.github/workflows/pre-commit.yml b/.github/workflows/pre-commit.yml
index 5d65b99..8b217e9 100644
--- a/.github/workflows/pre-commit.yml
+++ b/.github/workflows/pre-commit.yml
@@ -27,7 +27,7 @@ jobs:
     - name: Install dependencies
       run: python -m pip install ".[dev]"
     - name: Cache pre-commit tools
-      uses: actions/cache@v3
+      uses: actions/cache@v4
       with:
         path: |
           ${{ env.MYPY_CACHE_DIR }}
diff --git a/.github/workflows/sanitizer.yml b/.github/workflows/sanitizer.yml
index 86cccf4..4992153 100644
--- a/.github/workflows/sanitizer.yml
+++ b/.github/workflows/sanitizer.yml
@@ -18,7 +18,7 @@ jobs:
         sanitizer: ['asan', 'ubsan', 'tsan', 'msan']
 
     steps:
-    - uses: actions/checkout@v3
+    - uses: actions/checkout@v4
 
     - name: configure msan env
       if: matrix.sanitizer == 'msan'
diff --git a/.github/workflows/wheels.yml b/.github/workflows/wheels.yml
index 8b772cd..1a00069 100644
--- a/.github/workflows/wheels.yml
+++ b/.github/workflows/wheels.yml
@@ -81,10 +81,11 @@ jobs:
     name: Publish google-benchmark wheels to PyPI
     needs: [merge_wheels]
     runs-on: ubuntu-latest
-    permissions:
-      id-token: write
     steps:
       - uses: actions/download-artifact@v4
         with:
           path: dist
-      - uses: pypa/gh-action-pypi-publish@v1
+      - uses: pypa/gh-action-pypi-publish@release/v1
+        with:
+          user: __token__
+          password: ${{ secrets.PYPI_PASSWORD }}
diff --git a/.pre-commit-config.yaml b/.pre-commit-config.yaml
index 93455ab..99976d9 100644
--- a/.pre-commit-config.yaml
+++ b/.pre-commit-config.yaml
@@ -5,14 +5,14 @@ repos:
       -   id: buildifier
       -   id: buildifier-lint
   - repo: https://github.com/pre-commit/mirrors-mypy
-    rev: v1.8.0
+    rev: v1.11.0
     hooks:
       - id: mypy
         types_or: [ python, pyi ]
         args: [ "--ignore-missing-imports", "--scripts-are-modules" ]
   - repo: https://github.com/astral-sh/ruff-pre-commit
-    rev: v0.3.1
+    rev: v0.4.10
     hooks:
       - id: ruff
         args: [ --fix, --exit-non-zero-on-fix ]
-      - id: ruff-format
\ No newline at end of file
+      - id: ruff-format
diff --git a/.travis.yml b/.travis.yml
deleted file mode 100644
index 8cfed3d..0000000
--- a/.travis.yml
+++ /dev/null
@@ -1,208 +0,0 @@
-sudo: required
-dist: trusty
-language: cpp
-
-matrix:
-  include:
-    - compiler: gcc
-      addons:
-        apt:
-          packages:
-            - lcov
-      env: COMPILER=g++ C_COMPILER=gcc BUILD_TYPE=Coverage
-    - compiler: gcc
-      addons:
-        apt:
-          packages:
-            - g++-multilib
-            - libc6:i386
-      env:
-        - COMPILER=g++
-        - C_COMPILER=gcc
-        - BUILD_TYPE=Debug
-        - BUILD_32_BITS=ON
-        - EXTRA_FLAGS="-m32"
-    - compiler: gcc
-      addons:
-        apt:
-          packages:
-            - g++-multilib
-            - libc6:i386
-      env:
-        - COMPILER=g++
-        - C_COMPILER=gcc
-        - BUILD_TYPE=Release
-        - BUILD_32_BITS=ON
-        - EXTRA_FLAGS="-m32"
-    - compiler: gcc
-      env:
-        - INSTALL_GCC6_FROM_PPA=1
-        - COMPILER=g++-6 C_COMPILER=gcc-6  BUILD_TYPE=Debug
-        - ENABLE_SANITIZER=1
-        - EXTRA_FLAGS="-fno-omit-frame-pointer -g -O2 -fsanitize=undefined,address -fuse-ld=gold"
-    # Clang w/ libc++
-    - compiler: clang
-      dist: xenial
-      addons:
-        apt:
-          packages:
-            clang-3.8
-      env:
-        - INSTALL_GCC6_FROM_PPA=1
-        - COMPILER=clang++-3.8 C_COMPILER=clang-3.8 BUILD_TYPE=Debug
-        - LIBCXX_BUILD=1
-        - EXTRA_CXX_FLAGS="-stdlib=libc++"
-    - compiler: clang
-      dist: xenial
-      addons:
-        apt:
-          packages:
-            clang-3.8
-      env:
-        - INSTALL_GCC6_FROM_PPA=1
-        - COMPILER=clang++-3.8 C_COMPILER=clang-3.8 BUILD_TYPE=Release
-        - LIBCXX_BUILD=1
-        - EXTRA_CXX_FLAGS="-stdlib=libc++"
-    # Clang w/ 32bit libc++
-    - compiler: clang
-      dist: xenial
-      addons:
-        apt:
-          packages:
-            - clang-3.8
-            - g++-multilib
-            - libc6:i386
-      env:
-        - INSTALL_GCC6_FROM_PPA=1
-        - COMPILER=clang++-3.8 C_COMPILER=clang-3.8 BUILD_TYPE=Debug
-        - LIBCXX_BUILD=1
-        - BUILD_32_BITS=ON
-        - EXTRA_FLAGS="-m32"
-        - EXTRA_CXX_FLAGS="-stdlib=libc++"
-    # Clang w/ 32bit libc++
-    - compiler: clang
-      dist: xenial
-      addons:
-        apt:
-          packages:
-            - clang-3.8
-            - g++-multilib
-            - libc6:i386
-      env:
-        - INSTALL_GCC6_FROM_PPA=1
-        - COMPILER=clang++-3.8 C_COMPILER=clang-3.8 BUILD_TYPE=Release
-        - LIBCXX_BUILD=1
-        - BUILD_32_BITS=ON
-        - EXTRA_FLAGS="-m32"
-        - EXTRA_CXX_FLAGS="-stdlib=libc++"
-    # Clang w/ libc++, ASAN, UBSAN
-    - compiler: clang
-      dist: xenial
-      addons:
-        apt:
-          packages:
-            clang-3.8
-      env:
-        - INSTALL_GCC6_FROM_PPA=1
-        - COMPILER=clang++-3.8 C_COMPILER=clang-3.8 BUILD_TYPE=Debug
-        - LIBCXX_BUILD=1 LIBCXX_SANITIZER="Undefined;Address"
-        - ENABLE_SANITIZER=1
-        - EXTRA_FLAGS="-g -O2 -fno-omit-frame-pointer -fsanitize=undefined,address -fno-sanitize-recover=all"
-        - EXTRA_CXX_FLAGS="-stdlib=libc++"
-        - UBSAN_OPTIONS=print_stacktrace=1
-    # Clang w/ libc++ and MSAN
-    - compiler: clang
-      dist: xenial
-      addons:
-        apt:
-          packages:
-            clang-3.8
-      env:
-        - INSTALL_GCC6_FROM_PPA=1
-        - COMPILER=clang++-3.8 C_COMPILER=clang-3.8 BUILD_TYPE=Debug
-        - LIBCXX_BUILD=1 LIBCXX_SANITIZER=MemoryWithOrigins
-        - ENABLE_SANITIZER=1
-        - EXTRA_FLAGS="-g -O2 -fno-omit-frame-pointer -fsanitize=memory -fsanitize-memory-track-origins"
-        - EXTRA_CXX_FLAGS="-stdlib=libc++"
-    # Clang w/ libc++ and MSAN
-    - compiler: clang
-      dist: xenial
-      addons:
-        apt:
-          packages:
-            clang-3.8
-      env:
-        - INSTALL_GCC6_FROM_PPA=1
-        - COMPILER=clang++-3.8 C_COMPILER=clang-3.8 BUILD_TYPE=RelWithDebInfo
-        - LIBCXX_BUILD=1 LIBCXX_SANITIZER=Thread
-        - ENABLE_SANITIZER=1
-        - EXTRA_FLAGS="-g -O2 -fno-omit-frame-pointer -fsanitize=thread -fno-sanitize-recover=all"
-        - EXTRA_CXX_FLAGS="-stdlib=libc++"
-    - os: osx
-      osx_image: xcode8.3
-      compiler: clang
-      env:
-        - COMPILER=clang++
-        - BUILD_TYPE=Release
-        - BUILD_32_BITS=ON
-        - EXTRA_FLAGS="-m32"
-
-before_script:
-  - if [ -n "${LIBCXX_BUILD}" ]; then
-      source .libcxx-setup.sh;
-    fi
-  - if [ -n "${ENABLE_SANITIZER}" ]; then
-      export EXTRA_OPTIONS="-DBENCHMARK_ENABLE_ASSEMBLY_TESTS=OFF";
-    else
-      export EXTRA_OPTIONS="";
-    fi
-  - mkdir -p build && cd build
-
-before_install:
-  - if [ -z "$BUILD_32_BITS" ]; then
-      export BUILD_32_BITS=OFF && echo disabling 32 bit build;
-    fi
-  - if [ -n "${INSTALL_GCC6_FROM_PPA}" ]; then
-      sudo add-apt-repository -y "ppa:ubuntu-toolchain-r/test";
-      sudo apt-get update --option Acquire::Retries=100 --option Acquire::http::Timeout="60";
-    fi
-
-install:
-  - if [ -n "${INSTALL_GCC6_FROM_PPA}" ]; then
-      travis_wait sudo -E apt-get -yq --no-install-suggests --no-install-recommends install g++-6;
-    fi
-  - if [ "${TRAVIS_OS_NAME}" == "linux" -a "${BUILD_32_BITS}" == "OFF" ]; then
-      travis_wait sudo -E apt-get -y --no-install-suggests --no-install-recommends install llvm-3.9-tools;
-      sudo cp /usr/lib/llvm-3.9/bin/FileCheck /usr/local/bin/;
-    fi
-  - if [ "${BUILD_TYPE}" == "Coverage" -a "${TRAVIS_OS_NAME}" == "linux" ]; then
-      PATH=~/.local/bin:${PATH};
-      pip install --user --upgrade pip;
-      travis_wait pip install --user cpp-coveralls;
-    fi
-  - if [ "${C_COMPILER}" == "gcc-7" -a "${TRAVIS_OS_NAME}" == "osx" ]; then
-      rm -f /usr/local/include/c++;
-      brew update;
-      travis_wait brew install gcc@7;
-    fi
-  - if [ "${TRAVIS_OS_NAME}" == "linux" ]; then
-      sudo apt-get update -qq;
-      sudo apt-get install -qq unzip cmake3;
-      wget https://github.com/bazelbuild/bazel/releases/download/3.2.0/bazel-3.2.0-installer-linux-x86_64.sh --output-document bazel-installer.sh;
-      travis_wait sudo bash bazel-installer.sh;
-    fi
-  - if [ "${TRAVIS_OS_NAME}" == "osx" ]; then
-      curl -L -o bazel-installer.sh https://github.com/bazelbuild/bazel/releases/download/3.2.0/bazel-3.2.0-installer-darwin-x86_64.sh;
-      travis_wait sudo bash bazel-installer.sh;
-    fi
-
-script:
-  - cmake -DCMAKE_C_COMPILER=${C_COMPILER} -DCMAKE_CXX_COMPILER=${COMPILER} -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DCMAKE_C_FLAGS="${EXTRA_FLAGS}" -DCMAKE_CXX_FLAGS="${EXTRA_FLAGS} ${EXTRA_CXX_FLAGS}" -DBENCHMARK_DOWNLOAD_DEPENDENCIES=ON -DBENCHMARK_BUILD_32_BITS=${BUILD_32_BITS} ${EXTRA_OPTIONS} ..
-  - make
-  - ctest -C ${BUILD_TYPE} --output-on-failure
-  - bazel test -c dbg --define google_benchmark.have_regex=posix --announce_rc --verbose_failures --test_output=errors --keep_going //test/...
-
-after_success:
-  - if [ "${BUILD_TYPE}" == "Coverage" -a "${TRAVIS_OS_NAME}" == "linux" ]; then
-      coveralls --include src --include include --gcov-options '\-lp' --root .. --build-root .;
-    fi
diff --git a/Android.bp b/Android.bp
index 1f1a2d6..42854a3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -50,6 +50,7 @@ cc_defaults {
 // For benchmarks that define their own main().
 cc_library_static {
     name: "libgoogle-benchmark",
+    cmake_snapshot_supported: true,
     defaults: ["libgoogle-benchmark-defaults"],
     exclude_srcs: [
         "src/benchmark_main.cc",
diff --git a/BUILD.bazel b/BUILD.bazel
index 15d8369..094ed62 100644
--- a/BUILD.bazel
+++ b/BUILD.bazel
@@ -3,7 +3,7 @@ licenses(["notice"])
 COPTS = [
     "-pedantic",
     "-pedantic-errors",
-    "-std=c++11",
+    "-std=c++14",
     "-Wall",
     "-Wconversion",
     "-Wextra",
@@ -73,6 +73,7 @@ cc_library(
         ":perfcounters": ["HAVE_LIBPFM"],
         "//conditions:default": [],
     }),
+    includes = ["include"],
     linkopts = select({
         ":windows": ["-DEFAULTLIB:shlwapi.lib"],
         "//conditions:default": ["-pthread"],
@@ -87,7 +88,6 @@ cc_library(
         "_LARGEFILE64_SOURCE",
         "_LARGEFILE_SOURCE",
     ],
-    strip_include_prefix = "include",
     visibility = ["//visibility:public"],
     deps = select({
         ":perfcounters": ["@libpfm"],
@@ -102,7 +102,7 @@ cc_library(
         "include/benchmark/benchmark.h",
         "include/benchmark/export.h",
     ],
-    strip_include_prefix = "include",
+    includes = ["include"],
     visibility = ["//visibility:public"],
     deps = [":benchmark"],
 )
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 71396ed..40ff758 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,7 +1,7 @@
 # Require CMake 3.10. If available, use the policies up to CMake 3.22.
 cmake_minimum_required (VERSION 3.10...3.22)
 
-project (benchmark VERSION 1.8.4 LANGUAGES CXX)
+project (benchmark VERSION 1.9.0 LANGUAGES CXX)
 
 option(BENCHMARK_ENABLE_TESTING "Enable testing of the benchmark library." ON)
 option(BENCHMARK_ENABLE_EXCEPTIONS "Enable the use of exceptions in the benchmark library." ON)
@@ -104,7 +104,7 @@ get_git_version(GIT_VERSION)
 
 # If no git version can be determined, use the version
 # from the project() command
-if ("${GIT_VERSION}" STREQUAL "0.0.0")
+if ("${GIT_VERSION}" STREQUAL "v0.0.0")
   set(VERSION "v${benchmark_VERSION}")
 else()
   set(VERSION "${GIT_VERSION}")
@@ -138,11 +138,7 @@ if (BENCHMARK_BUILD_32_BITS)
   add_required_cxx_compiler_flag(-m32)
 endif()
 
-if (MSVC OR CMAKE_CXX_SIMULATE_ID STREQUAL "MSVC")
-  set(BENCHMARK_CXX_STANDARD 14)
-else()
-  set(BENCHMARK_CXX_STANDARD 11)
-endif()
+set(BENCHMARK_CXX_STANDARD 14)
 
 set(CMAKE_CXX_STANDARD ${BENCHMARK_CXX_STANDARD})
 set(CMAKE_CXX_STANDARD_REQUIRED YES)
diff --git a/CONTRIBUTORS b/CONTRIBUTORS
index 9ca2caa..54aba7b 100644
--- a/CONTRIBUTORS
+++ b/CONTRIBUTORS
@@ -42,6 +42,7 @@ Dominic Hamon <dma@stripysock.com> <dominic@google.com>
 Dominik Czarnota <dominik.b.czarnota@gmail.com>
 Dominik Korman <kormandominik@gmail.com>
 Donald Aingworth <donalds_junk_mail@yahoo.com>
+Doug Evans <xdje42@gmail.com>
 Eric Backus <eric_backus@alum.mit.edu>
 Eric Fiselier <eric@efcs.ca>
 Eugene Zhuk <eugene.zhuk@gmail.com>
diff --git a/METADATA b/METADATA
index 563019d..c138c5d 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/google-benchmark
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "google-benchmark"
 description: "A library to support the benchmarking of functions, similar to unit-tests."
@@ -8,13 +8,13 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 6
-    day: 7
+    month: 8
+    day: 28
   }
   homepage: "https://github.com/google/benchmark"
   identifier {
     type: "Git"
     value: "https://github.com/google/benchmark.git"
-    version: "v1.8.4"
+    version: "v1.9.0"
   }
 }
diff --git a/MODULE.bazel b/MODULE.bazel
index 0624a34..e4f170c 100644
--- a/MODULE.bazel
+++ b/MODULE.bazel
@@ -1,6 +1,6 @@
 module(
     name = "google_benchmark",
-    version = "1.8.4",
+    version = "1.9.0",
 )
 
 bazel_dep(name = "bazel_skylib", version = "1.5.0")
@@ -38,4 +38,4 @@ use_repo(pip, "tools_pip_deps")
 
 # -- bazel_dep definitions -- #
 
-bazel_dep(name = "nanobind_bazel", version = "1.0.0", dev_dependency = True)
+bazel_dep(name = "nanobind_bazel", version = "2.1.0", dev_dependency = True)
diff --git a/README.md b/README.md
index a5e5d39..8e5428f 100644
--- a/README.md
+++ b/README.md
@@ -50,15 +50,13 @@ IRC channels:
 
 ## Requirements
 
-The library can be used with C++03. However, it requires C++11 to build,
+The library can be used with C++03. However, it requires C++14 to build,
 including compiler and standard library support.
 
-The following minimum versions are required to build the library:
+_See [dependencies.md](docs/dependencies.md) for more details regarding supported
+compilers and standards._
 
-* GCC 4.8
-* Clang 3.4
-* Visual Studio 14 2015
-* Intel 2015 Update 1
+If you have need for a particular compiler to be supported, patches are very welcome.
 
 See [Platform-Specific Build Instructions](docs/platform_specific_build_instructions.md).
 
diff --git a/bazel/benchmark_deps.bzl b/bazel/benchmark_deps.bzl
index 4fb45a5..cb908cd 100644
--- a/bazel/benchmark_deps.bzl
+++ b/bazel/benchmark_deps.bzl
@@ -45,7 +45,7 @@ def benchmark_deps():
         new_git_repository(
             name = "nanobind",
             remote = "https://github.com/wjakob/nanobind.git",
-            tag = "v1.8.0",
+            tag = "v1.9.2",
             build_file = "@//bindings/python:nanobind.BUILD",
             recursive_init_submodules = True,
         )
diff --git a/bindings/python/google_benchmark/BUILD b/bindings/python/google_benchmark/BUILD
index 0c8e3c1..30e3893 100644
--- a/bindings/python/google_benchmark/BUILD
+++ b/bindings/python/google_benchmark/BUILD
@@ -1,4 +1,4 @@
-load("@nanobind_bazel//:build_defs.bzl", "nanobind_extension")
+load("@nanobind_bazel//:build_defs.bzl", "nanobind_extension", "nanobind_stubgen")
 
 py_library(
     name = "google_benchmark",
@@ -15,6 +15,12 @@ nanobind_extension(
     deps = ["//:benchmark"],
 )
 
+nanobind_stubgen(
+    name = "benchmark_stubgen",
+    marker_file = "bindings/python/google_benchmark/py.typed",
+    module = ":_benchmark",
+)
+
 py_test(
     name = "example",
     srcs = ["example.py"],
diff --git a/bindings/python/google_benchmark/benchmark.cc b/bindings/python/google_benchmark/benchmark.cc
index f444769..64ffb92 100644
--- a/bindings/python/google_benchmark/benchmark.cc
+++ b/bindings/python/google_benchmark/benchmark.cc
@@ -118,7 +118,7 @@ NB_MODULE(_benchmark, m) {
   using benchmark::Counter;
   nb::class_<Counter> py_counter(m, "Counter");
 
-  nb::enum_<Counter::Flags>(py_counter, "Flags")
+  nb::enum_<Counter::Flags>(py_counter, "Flags", nb::is_arithmetic())
       .value("kDefaults", Counter::Flags::kDefaults)
       .value("kIsRate", Counter::Flags::kIsRate)
       .value("kAvgThreads", Counter::Flags::kAvgThreads)
@@ -130,7 +130,9 @@ NB_MODULE(_benchmark, m) {
       .value("kAvgIterationsRate", Counter::Flags::kAvgIterationsRate)
       .value("kInvert", Counter::Flags::kInvert)
       .export_values()
-      .def(nb::self | nb::self);
+      .def("__or__", [](Counter::Flags a, Counter::Flags b) {
+        return static_cast<int>(a) | static_cast<int>(b);
+      });
 
   nb::enum_<Counter::OneK>(py_counter, "OneK")
       .value("kIs1000", Counter::OneK::kIs1000)
@@ -138,10 +140,15 @@ NB_MODULE(_benchmark, m) {
       .export_values();
 
   py_counter
-      .def(nb::init<double, Counter::Flags, Counter::OneK>(),
-           nb::arg("value") = 0., nb::arg("flags") = Counter::kDefaults,
-           nb::arg("k") = Counter::kIs1000)
-      .def("__init__", ([](Counter *c, double value) { new (c) Counter(value); }))
+      .def(
+          "__init__",
+          [](Counter* c, double value, int flags, Counter::OneK oneK) {
+            new (c) Counter(value, static_cast<Counter::Flags>(flags), oneK);
+          },
+          nb::arg("value") = 0., nb::arg("flags") = Counter::kDefaults,
+          nb::arg("k") = Counter::kIs1000)
+      .def("__init__",
+           ([](Counter* c, double value) { new (c) Counter(value); }))
       .def_rw("value", &Counter::value)
       .def_rw("flags", &Counter::flags)
       .def_rw("oneK", &Counter::oneK)
diff --git a/cmake/Config.cmake.in b/cmake/Config.cmake.in
index 2e15f0c..3659cfa 100644
--- a/cmake/Config.cmake.in
+++ b/cmake/Config.cmake.in
@@ -4,4 +4,8 @@ include (CMakeFindDependencyMacro)
 
 find_dependency (Threads)
 
+if (@BENCHMARK_ENABLE_LIBPFM@)
+    find_dependency (PFM)
+endif()
+
 include("${CMAKE_CURRENT_LIST_DIR}/@targets_export_name@.cmake")
diff --git a/cmake/benchmark.pc.in b/cmake/benchmark.pc.in
index 9dae881..043f2fc 100644
--- a/cmake/benchmark.pc.in
+++ b/cmake/benchmark.pc.in
@@ -8,5 +8,5 @@ Description: Google microbenchmark framework
 Version: @VERSION@
 
 Libs: -L${libdir} -lbenchmark
-Libs.private: -lpthread
+Libs.private: -lpthread @BENCHMARK_PRIVATE_LINK_LIBRARIES@
 Cflags: -I${includedir}
diff --git a/docs/user_guide.md b/docs/user_guide.md
index d22a906..e382620 100644
--- a/docs/user_guide.md
+++ b/docs/user_guide.md
@@ -624,20 +624,22 @@ public:
   }
 };
 
+// Defines and registers `FooTest` using the class `MyFixture`.
 BENCHMARK_F(MyFixture, FooTest)(benchmark::State& st) {
    for (auto _ : st) {
      ...
   }
 }
 
+// Only defines `BarTest` using the class `MyFixture`.
 BENCHMARK_DEFINE_F(MyFixture, BarTest)(benchmark::State& st) {
    for (auto _ : st) {
      ...
   }
 }
-/* BarTest is NOT registered */
+// `BarTest` is NOT registered.
 BENCHMARK_REGISTER_F(MyFixture, BarTest)->Threads(2);
-/* BarTest is now registered */
+// `BarTest` is now registered.
 ```
 
 ### Templated Fixtures
@@ -653,19 +655,22 @@ For example:
 template<typename T>
 class MyFixture : public benchmark::Fixture {};
 
+// Defines and registers `IntTest` using the class template `MyFixture<int>`.
 BENCHMARK_TEMPLATE_F(MyFixture, IntTest, int)(benchmark::State& st) {
    for (auto _ : st) {
      ...
   }
 }
 
+// Only defines `DoubleTest` using the class template `MyFixture<double>`.
 BENCHMARK_TEMPLATE_DEFINE_F(MyFixture, DoubleTest, double)(benchmark::State& st) {
    for (auto _ : st) {
      ...
   }
 }
-
+// `DoubleTest` is NOT registered.
 BENCHMARK_REGISTER_F(MyFixture, DoubleTest)->Threads(2);
+// `DoubleTest` is now registered.
 ```
 
 <a name="custom-counters" />
@@ -1012,11 +1017,11 @@ in any way. `<expr>` may even be removed entirely when the result is already
 known. For example:
 
 ```c++
-  /* Example 1: `<expr>` is removed entirely. */
+  // Example 1: `<expr>` is removed entirely.
   int foo(int x) { return x + 42; }
   while (...) DoNotOptimize(foo(0)); // Optimized to DoNotOptimize(42);
 
-  /*  Example 2: Result of '<expr>' is only reused */
+  // Example 2: Result of '<expr>' is only reused.
   int bar(int) __attribute__((const));
   while (...) DoNotOptimize(bar(0)); // Optimized to:
   // int __result__ = bar(0);
@@ -1134,6 +1139,21 @@ a report on the number of allocations, bytes used, etc.
 This data will then be reported alongside other performance data, currently
 only when using JSON output.
 
+<a name="profiling" />
+
+## Profiling
+
+It's often useful to also profile benchmarks in particular ways, in addition to
+CPU performance. For this reason, benchmark offers the `RegisterProfilerManager`
+method that allows a custom `ProfilerManager` to be injected.
+
+If set, the `ProfilerManager::AfterSetupStart` and
+`ProfilerManager::BeforeTeardownStop` methods will be called at the start and
+end of a separate benchmark run to allow user code to collect and report
+user-provided profile metrics.
+
+Output collected from this profiling run must be reported separately.
+
 <a name="using-register-benchmark" />
 
 ## Using RegisterBenchmark(name, fn, args...)
diff --git a/include/benchmark/benchmark.h b/include/benchmark/benchmark.h
index 08cfe29..4cdb451 100644
--- a/include/benchmark/benchmark.h
+++ b/include/benchmark/benchmark.h
@@ -416,6 +416,26 @@ class MemoryManager {
 BENCHMARK_EXPORT
 void RegisterMemoryManager(MemoryManager* memory_manager);
 
+// If a ProfilerManager is registered (via RegisterProfilerManager()), the
+// benchmark will be run an additional time under the profiler to collect and
+// report profile metrics for the run of the benchmark.
+class ProfilerManager {
+ public:
+  virtual ~ProfilerManager() {}
+
+  // This is called after `Setup()` code and right before the benchmark is run.
+  virtual void AfterSetupStart() = 0;
+
+  // This is called before `Teardown()` code and right after the benchmark
+  // completes.
+  virtual void BeforeTeardownStop() = 0;
+};
+
+// Register a ProfilerManager instance that will be used to collect and report
+// profile measurements for benchmark runs.
+BENCHMARK_EXPORT
+void RegisterProfilerManager(ProfilerManager* profiler_manager);
+
 // Add a key-value pair to output as part of the context stanza in the report.
 BENCHMARK_EXPORT
 void AddCustomContext(const std::string& key, const std::string& value);
@@ -984,7 +1004,8 @@ class BENCHMARK_EXPORT State {
   State(std::string name, IterationCount max_iters,
         const std::vector<int64_t>& ranges, int thread_i, int n_threads,
         internal::ThreadTimer* timer, internal::ThreadManager* manager,
-        internal::PerfCountersMeasurement* perf_counters_measurement);
+        internal::PerfCountersMeasurement* perf_counters_measurement,
+        ProfilerManager* profiler_manager);
 
   void StartKeepRunning();
   // Implementation of KeepRunning() and KeepRunningBatch().
@@ -999,6 +1020,7 @@ class BENCHMARK_EXPORT State {
   internal::ThreadTimer* const timer_;
   internal::ThreadManager* const manager_;
   internal::PerfCountersMeasurement* const perf_counters_measurement_;
+  ProfilerManager* const profiler_manager_;
 
   friend class internal::BenchmarkInstance;
 };
diff --git a/setup.py b/setup.py
index 40cdc8d..d171476 100644
--- a/setup.py
+++ b/setup.py
@@ -99,7 +99,7 @@ class BuildBazelExtension(build_ext.build_ext):
 
         bazel_argv = [
             "bazel",
-            "build",
+            "run",
             ext.bazel_target,
             f"--symlink_prefix={temp_path / 'bazel-'}",
             f"--compilation_mode={'dbg' if self.debug else 'opt'}",
@@ -127,20 +127,42 @@ class BuildBazelExtension(build_ext.build_ext):
         else:
             suffix = ".abi3.so" if ext.py_limited_api else ".so"
 
-        ext_name = ext.target_name + suffix
-        ext_bazel_bin_path = temp_path / "bazel-bin" / ext.relpath / ext_name
-        ext_dest_path = Path(self.get_ext_fullpath(ext.name)).with_name(
-            ext_name
-        )
-        shutil.copyfile(ext_bazel_bin_path, ext_dest_path)
+        # copy the Bazel build artifacts into setuptools' libdir,
+        # from where the wheel is built.
+        pkgname = "google_benchmark"
+        pythonroot = Path("bindings") / "python" / "google_benchmark"
+        srcdir = temp_path / "bazel-bin" / pythonroot
+        libdir = Path(self.build_lib) / pkgname
+        for root, dirs, files in os.walk(srcdir, topdown=True):
+            # exclude runfiles directories and children.
+            dirs[:] = [d for d in dirs if "runfiles" not in d]
+
+            for f in files:
+                print(f)
+                fp = Path(f)
+                should_copy = False
+                # we do not want the bare .so file included
+                # when building for ABI3, so we require a
+                # full and exact match on the file extension.
+                if "".join(fp.suffixes) == suffix:
+                    should_copy = True
+                elif fp.suffix == ".pyi":
+                    should_copy = True
+                elif Path(root) == srcdir and f == "py.typed":
+                    # copy py.typed, but only at the package root.
+                    should_copy = True
+
+                if should_copy:
+                    shutil.copyfile(root / fp, libdir / fp)
 
 
 setuptools.setup(
     cmdclass=dict(build_ext=BuildBazelExtension),
+    package_data={"google_benchmark": ["py.typed", "*.pyi"]},
     ext_modules=[
         BazelExtension(
             name="google_benchmark._benchmark",
-            bazel_target="//bindings/python/google_benchmark:_benchmark",
+            bazel_target="//bindings/python/google_benchmark:benchmark_stubgen",
             py_limited_api=py_limited_api,
         )
     ],
diff --git a/src/CMakeLists.txt b/src/CMakeLists.txt
index 5551099..32126c0 100644
--- a/src/CMakeLists.txt
+++ b/src/CMakeLists.txt
@@ -1,4 +1,4 @@
-# Allow the source files to find headers in src/
+#Allow the source files to find headers in src /
 include(GNUInstallDirs)
 include_directories(${PROJECT_SOURCE_DIR}/src)
 
@@ -64,6 +64,7 @@ endif()
 # We need extra libraries on Solaris
 if(${CMAKE_SYSTEM_NAME} MATCHES "SunOS")
   target_link_libraries(benchmark PRIVATE kstat)
+  set(BENCHMARK_PRIVATE_LINK_LIBRARIES -lkstat)
 endif()
 
 if (NOT BUILD_SHARED_LIBS)
diff --git a/src/benchmark.cc b/src/benchmark.cc
index 337bb3f..b7767bd 100644
--- a/src/benchmark.cc
+++ b/src/benchmark.cc
@@ -168,7 +168,8 @@ void UseCharPointer(char const volatile* const v) {
 State::State(std::string name, IterationCount max_iters,
              const std::vector<int64_t>& ranges, int thread_i, int n_threads,
              internal::ThreadTimer* timer, internal::ThreadManager* manager,
-             internal::PerfCountersMeasurement* perf_counters_measurement)
+             internal::PerfCountersMeasurement* perf_counters_measurement,
+             ProfilerManager* profiler_manager)
     : total_iterations_(0),
       batch_leftover_(0),
       max_iterations(max_iters),
@@ -182,7 +183,8 @@ State::State(std::string name, IterationCount max_iters,
       threads_(n_threads),
       timer_(timer),
       manager_(manager),
-      perf_counters_measurement_(perf_counters_measurement) {
+      perf_counters_measurement_(perf_counters_measurement),
+      profiler_manager_(profiler_manager) {
   BM_CHECK(max_iterations != 0) << "At least one iteration must be run";
   BM_CHECK_LT(thread_index_, threads_)
       << "thread_index must be less than threads";
@@ -207,7 +209,7 @@ State::State(std::string name, IterationCount max_iters,
 #if defined(__INTEL_COMPILER)
 #pragma warning push
 #pragma warning(disable : 1875)
-#elif defined(__GNUC__)
+#elif defined(__GNUC__) || defined(__clang__)
 #pragma GCC diagnostic push
 #pragma GCC diagnostic ignored "-Winvalid-offsetof"
 #endif
@@ -225,7 +227,7 @@ State::State(std::string name, IterationCount max_iters,
       offsetof(State, skipped_) <= (cache_line_size - sizeof(skipped_)), "");
 #if defined(__INTEL_COMPILER)
 #pragma warning pop
-#elif defined(__GNUC__)
+#elif defined(__GNUC__) || defined(__clang__)
 #pragma GCC diagnostic pop
 #endif
 #if defined(__NVCC__)
@@ -302,6 +304,8 @@ void State::StartKeepRunning() {
   BM_CHECK(!started_ && !finished_);
   started_ = true;
   total_iterations_ = skipped() ? 0 : max_iterations;
+  if (BENCHMARK_BUILTIN_EXPECT(profiler_manager_ != nullptr, false))
+    profiler_manager_->AfterSetupStart();
   manager_->StartStopBarrier();
   if (!skipped()) ResumeTiming();
 }
@@ -315,6 +319,8 @@ void State::FinishKeepRunning() {
   total_iterations_ = 0;
   finished_ = true;
   manager_->StartStopBarrier();
+  if (BENCHMARK_BUILTIN_EXPECT(profiler_manager_ != nullptr, false))
+    profiler_manager_->BeforeTeardownStop();
 }
 
 namespace internal {
@@ -656,6 +662,10 @@ void RegisterMemoryManager(MemoryManager* manager) {
   internal::memory_manager = manager;
 }
 
+void RegisterProfilerManager(ProfilerManager* manager) {
+  internal::profiler_manager = manager;
+}
+
 void AddCustomContext(const std::string& key, const std::string& value) {
   if (internal::global_context == nullptr) {
     internal::global_context = new std::map<std::string, std::string>();
diff --git a/src/benchmark_api_internal.cc b/src/benchmark_api_internal.cc
index 286f986..4b569d7 100644
--- a/src/benchmark_api_internal.cc
+++ b/src/benchmark_api_internal.cc
@@ -92,9 +92,10 @@ BenchmarkInstance::BenchmarkInstance(Benchmark* benchmark, int family_idx,
 State BenchmarkInstance::Run(
     IterationCount iters, int thread_id, internal::ThreadTimer* timer,
     internal::ThreadManager* manager,
-    internal::PerfCountersMeasurement* perf_counters_measurement) const {
+    internal::PerfCountersMeasurement* perf_counters_measurement,
+    ProfilerManager* profiler_manager) const {
   State st(name_.function_name, iters, args_, thread_id, threads_, timer,
-           manager, perf_counters_measurement);
+           manager, perf_counters_measurement, profiler_manager);
   benchmark_.Run(st);
   return st;
 }
@@ -102,7 +103,7 @@ State BenchmarkInstance::Run(
 void BenchmarkInstance::Setup() const {
   if (setup_) {
     State st(name_.function_name, /*iters*/ 1, args_, /*thread_id*/ 0, threads_,
-             nullptr, nullptr, nullptr);
+             nullptr, nullptr, nullptr, nullptr);
     setup_(st);
   }
 }
@@ -110,7 +111,7 @@ void BenchmarkInstance::Setup() const {
 void BenchmarkInstance::Teardown() const {
   if (teardown_) {
     State st(name_.function_name, /*iters*/ 1, args_, /*thread_id*/ 0, threads_,
-             nullptr, nullptr, nullptr);
+             nullptr, nullptr, nullptr, nullptr);
     teardown_(st);
   }
 }
diff --git a/src/benchmark_api_internal.h b/src/benchmark_api_internal.h
index 94f5165..659a714 100644
--- a/src/benchmark_api_internal.h
+++ b/src/benchmark_api_internal.h
@@ -44,7 +44,8 @@ class BenchmarkInstance {
 
   State Run(IterationCount iters, int thread_id, internal::ThreadTimer* timer,
             internal::ThreadManager* manager,
-            internal::PerfCountersMeasurement* perf_counters_measurement) const;
+            internal::PerfCountersMeasurement* perf_counters_measurement,
+            ProfilerManager* profiler_manager) const;
 
  private:
   BenchmarkName name_;
diff --git a/src/benchmark_runner.cc b/src/benchmark_runner.cc
index a74bdad..a380939 100644
--- a/src/benchmark_runner.cc
+++ b/src/benchmark_runner.cc
@@ -62,6 +62,8 @@ namespace internal {
 
 MemoryManager* memory_manager = nullptr;
 
+ProfilerManager* profiler_manager = nullptr;
+
 namespace {
 
 static constexpr IterationCount kMaxIterations = 1000000000000;
@@ -123,14 +125,15 @@ BenchmarkReporter::Run CreateRunReport(
 // Adds the stats collected for the thread into manager->results.
 void RunInThread(const BenchmarkInstance* b, IterationCount iters,
                  int thread_id, ThreadManager* manager,
-                 PerfCountersMeasurement* perf_counters_measurement) {
+                 PerfCountersMeasurement* perf_counters_measurement,
+                 ProfilerManager* profiler_manager) {
   internal::ThreadTimer timer(
       b->measure_process_cpu_time()
           ? internal::ThreadTimer::CreateProcessCpuTime()
           : internal::ThreadTimer::Create());
 
-  State st =
-      b->Run(iters, thread_id, &timer, manager, perf_counters_measurement);
+  State st = b->Run(iters, thread_id, &timer, manager,
+                    perf_counters_measurement, profiler_manager);
   BM_CHECK(st.skipped() || st.iterations() >= st.max_iterations)
       << "Benchmark returned before State::KeepRunning() returned false!";
   {
@@ -266,12 +269,14 @@ BenchmarkRunner::IterationResults BenchmarkRunner::DoNIterations() {
   // Run all but one thread in separate threads
   for (std::size_t ti = 0; ti < pool.size(); ++ti) {
     pool[ti] = std::thread(&RunInThread, &b, iters, static_cast<int>(ti + 1),
-                           manager.get(), perf_counters_measurement_ptr);
+                           manager.get(), perf_counters_measurement_ptr,
+                           /*profiler_manager=*/nullptr);
   }
   // And run one thread here directly.
   // (If we were asked to run just one thread, we don't create new threads.)
   // Yes, we need to do this here *after* we start the separate threads.
-  RunInThread(&b, iters, 0, manager.get(), perf_counters_measurement_ptr);
+  RunInThread(&b, iters, 0, manager.get(), perf_counters_measurement_ptr,
+              /*profiler_manager=*/nullptr);
 
   // The main thread has finished. Now let's wait for the other threads.
   manager->WaitForAllThreads();
@@ -287,12 +292,6 @@ BenchmarkRunner::IterationResults BenchmarkRunner::DoNIterations() {
   // And get rid of the manager.
   manager.reset();
 
-  // Adjust real/manual time stats since they were reported per thread.
-  i.results.real_time_used /= b.threads();
-  i.results.manual_time_used /= b.threads();
-  // If we were measuring whole-process CPU usage, adjust the CPU time too.
-  if (b.measure_process_cpu_time()) i.results.cpu_time_used /= b.threads();
-
   BM_VLOG(2) << "Ran in " << i.results.cpu_time_used << "/"
              << i.results.real_time_used << "\n";
 
@@ -401,6 +400,41 @@ void BenchmarkRunner::RunWarmUp() {
   }
 }
 
+MemoryManager::Result* BenchmarkRunner::RunMemoryManager(
+    IterationCount memory_iterations) {
+  // TODO(vyng): Consider making BenchmarkReporter::Run::memory_result an
+  // optional so we don't have to own the Result here.
+  // Can't do it now due to cxx03.
+  memory_results.push_back(MemoryManager::Result());
+  MemoryManager::Result* memory_result = &memory_results.back();
+  memory_manager->Start();
+  std::unique_ptr<internal::ThreadManager> manager;
+  manager.reset(new internal::ThreadManager(1));
+  b.Setup();
+  RunInThread(&b, memory_iterations, 0, manager.get(),
+              perf_counters_measurement_ptr,
+              /*profiler_manager=*/nullptr);
+  manager->WaitForAllThreads();
+  manager.reset();
+  b.Teardown();
+  memory_manager->Stop(*memory_result);
+  return memory_result;
+}
+
+void BenchmarkRunner::RunProfilerManager() {
+  // TODO: Provide a way to specify the number of iterations.
+  IterationCount profile_iterations = 1;
+  std::unique_ptr<internal::ThreadManager> manager;
+  manager.reset(new internal::ThreadManager(1));
+  b.Setup();
+  RunInThread(&b, profile_iterations, 0, manager.get(),
+              /*perf_counters_measurement_ptr=*/nullptr,
+              /*profiler_manager=*/profiler_manager);
+  manager->WaitForAllThreads();
+  manager.reset();
+  b.Teardown();
+}
+
 void BenchmarkRunner::DoOneRepetition() {
   assert(HasRepeatsRemaining() && "Already done all repetitions?");
 
@@ -445,28 +479,18 @@ void BenchmarkRunner::DoOneRepetition() {
            "then we should have accepted the current iteration run.");
   }
 
-  // Oh, one last thing, we need to also produce the 'memory measurements'..
+  // Produce memory measurements if requested.
   MemoryManager::Result* memory_result = nullptr;
   IterationCount memory_iterations = 0;
   if (memory_manager != nullptr) {
-    // TODO(vyng): Consider making BenchmarkReporter::Run::memory_result an
-    // optional so we don't have to own the Result here.
-    // Can't do it now due to cxx03.
-    memory_results.push_back(MemoryManager::Result());
-    memory_result = &memory_results.back();
     // Only run a few iterations to reduce the impact of one-time
     // allocations in benchmarks that are not properly managed.
     memory_iterations = std::min<IterationCount>(16, iters);
-    memory_manager->Start();
-    std::unique_ptr<internal::ThreadManager> manager;
-    manager.reset(new internal::ThreadManager(1));
-    b.Setup();
-    RunInThread(&b, memory_iterations, 0, manager.get(),
-                perf_counters_measurement_ptr);
-    manager->WaitForAllThreads();
-    manager.reset();
-    b.Teardown();
-    memory_manager->Stop(*memory_result);
+    memory_result = RunMemoryManager(memory_iterations);
+  }
+
+  if (profiler_manager != nullptr) {
+    RunProfilerManager();
   }
 
   // Ok, now actually report.
diff --git a/src/benchmark_runner.h b/src/benchmark_runner.h
index db2fa04..cd34d2d 100644
--- a/src/benchmark_runner.h
+++ b/src/benchmark_runner.h
@@ -35,6 +35,7 @@ BM_DECLARE_string(benchmark_perf_counters);
 namespace internal {
 
 extern MemoryManager* memory_manager;
+extern ProfilerManager* profiler_manager;
 
 struct RunResults {
   std::vector<BenchmarkReporter::Run> non_aggregates;
@@ -113,6 +114,10 @@ class BenchmarkRunner {
   };
   IterationResults DoNIterations();
 
+  MemoryManager::Result* RunMemoryManager(IterationCount memory_iterations);
+
+  void RunProfilerManager();
+
   IterationCount PredictNumItersNeeded(const IterationResults& i) const;
 
   bool ShouldReportIterationResults(const IterationResults& i) const;
diff --git a/src/complexity.cc b/src/complexity.cc
index eee3122..63acd50 100644
--- a/src/complexity.cc
+++ b/src/complexity.cc
@@ -27,7 +27,6 @@ namespace benchmark {
 
 // Internal function to calculate the different scalability forms
 BigOFunc* FittingCurve(BigO complexity) {
-  static const double kLog2E = 1.44269504088896340736;
   switch (complexity) {
     case oN:
       return [](IterationCount n) -> double { return static_cast<double>(n); };
@@ -36,15 +35,12 @@ BigOFunc* FittingCurve(BigO complexity) {
     case oNCubed:
       return [](IterationCount n) -> double { return std::pow(n, 3); };
     case oLogN:
-      /* Note: can't use log2 because Android's GNU STL lacks it */
-      return [](IterationCount n) {
-        return kLog2E * std::log(static_cast<double>(n));
+      return [](IterationCount n) -> double {
+        return std::log2(static_cast<double>(n));
       };
     case oNLogN:
-      /* Note: can't use log2 because Android's GNU STL lacks it */
-      return [](IterationCount n) {
-        return kLog2E * static_cast<double>(n) *
-               std::log(static_cast<double>(n));
+      return [](IterationCount n) -> double {
+        return static_cast<double>(n) * std::log2(static_cast<double>(n));
       };
     case o1:
     default:
diff --git a/src/cycleclock.h b/src/cycleclock.h
index a258437..bd62f5d 100644
--- a/src/cycleclock.h
+++ b/src/cycleclock.h
@@ -205,11 +205,12 @@ inline BENCHMARK_ALWAYS_INLINE int64_t Now() {
       "sub %0, zero, %0\n"
       "and %1, %1, %0\n"
       : "=r"(cycles_hi0), "=r"(cycles_lo), "=r"(cycles_hi1));
-  return (static_cast<uint64_t>(cycles_hi1) << 32) | cycles_lo;
+  return static_cast<int64_t>((static_cast<uint64_t>(cycles_hi1) << 32) |
+                              cycles_lo);
 #else
   uint64_t cycles;
   asm volatile("rdtime %0" : "=r"(cycles));
-  return cycles;
+  return static_cast<int64_t>(cycles);
 #endif
 #elif defined(__e2k__) || defined(__elbrus__)
   struct timeval tv;
diff --git a/src/perf_counters.cc b/src/perf_counters.cc
index 2eb97eb..fc9586b 100644
--- a/src/perf_counters.cc
+++ b/src/perf_counters.cc
@@ -157,7 +157,8 @@ PerfCounters PerfCounters::Create(
     attr.exclude_hv = true;
 
     // Read all counters in a group in one read.
-    attr.read_format = PERF_FORMAT_GROUP;
+    attr.read_format = PERF_FORMAT_GROUP;  //| PERF_FORMAT_TOTAL_TIME_ENABLED |
+                                           // PERF_FORMAT_TOTAL_TIME_RUNNING;
 
     int id = -1;
     while (id < 0) {
@@ -217,7 +218,7 @@ PerfCounters PerfCounters::Create(
       GetErrorLogInstance() << "***WARNING*** Failed to start counters. "
                                "Claring out all counters.\n";
 
-      // Close all peformance counters
+      // Close all performance counters
       for (int id : counter_ids) {
         ::close(id);
       }
diff --git a/src/sysinfo.cc b/src/sysinfo.cc
index 7261e2a..a153b20 100644
--- a/src/sysinfo.cc
+++ b/src/sysinfo.cc
@@ -508,7 +508,8 @@ int GetNumCPUsImpl() {
   int max_id = -1;
   std::ifstream f("/proc/cpuinfo");
   if (!f.is_open()) {
-    PrintErrorAndDie("Failed to open /proc/cpuinfo");
+    std::cerr << "Failed to open /proc/cpuinfo\n";
+    return -1;
   }
 #if defined(__alpha__)
   const std::string Key = "cpus detected";
@@ -557,9 +558,8 @@ int GetNumCPUsImpl() {
 int GetNumCPUs() {
   const int num_cpus = GetNumCPUsImpl();
   if (num_cpus < 1) {
-    PrintErrorAndDie(
-        "Unable to extract number of CPUs.  If your platform uses "
-        "/proc/cpuinfo, custom support may need to be added.");
+    std::cerr << "Unable to extract number of CPUs.  If your platform uses "
+                 "/proc/cpuinfo, custom support may need to be added.\n";
   }
   return num_cpus;
 }
diff --git a/src/timers.cc b/src/timers.cc
index d0821f3..7ba540b 100644
--- a/src/timers.cc
+++ b/src/timers.cc
@@ -126,8 +126,12 @@ double ProcessCPUUsage() {
     return MakeTime(kernel_time, user_time);
   DiagnoseAndExit("GetProccessTimes() failed");
 #elif defined(BENCHMARK_OS_QURT)
+  // Note that qurt_timer_get_ticks() is no longer documented as of SDK 5.3.0,
+  // and doesn't appear to work on at least some devices (eg Samsung S22),
+  // so let's use the actually-documented and apparently-equivalent
+  // qurt_sysclock_get_hw_ticks() call instead.
   return static_cast<double>(
-             qurt_timer_timetick_to_us(qurt_timer_get_ticks())) *
+             qurt_timer_timetick_to_us(qurt_sysclock_get_hw_ticks())) *
          1.0e-6;
 #elif defined(BENCHMARK_OS_EMSCRIPTEN)
   // clock_gettime(CLOCK_PROCESS_CPUTIME_ID, ...) returns 0 on Emscripten.
@@ -160,8 +164,12 @@ double ThreadCPUUsage() {
                  &user_time);
   return MakeTime(kernel_time, user_time);
 #elif defined(BENCHMARK_OS_QURT)
+  // Note that qurt_timer_get_ticks() is no longer documented as of SDK 5.3.0,
+  // and doesn't appear to work on at least some devices (eg Samsung S22),
+  // so let's use the actually-documented and apparently-equivalent
+  // qurt_sysclock_get_hw_ticks() call instead.
   return static_cast<double>(
-             qurt_timer_timetick_to_us(qurt_timer_get_ticks())) *
+             qurt_timer_timetick_to_us(qurt_sysclock_get_hw_ticks())) *
          1.0e-6;
 #elif defined(BENCHMARK_OS_MACOSX)
   // FIXME We want to use clock_gettime, but its not available in MacOS 10.11.
diff --git a/src/timers.h b/src/timers.h
index 65606cc..690086b 100644
--- a/src/timers.h
+++ b/src/timers.h
@@ -15,6 +15,29 @@ double ChildrenCPUUsage();
 // Return the CPU usage of the current thread
 double ThreadCPUUsage();
 
+#if defined(BENCHMARK_OS_QURT)
+
+// std::chrono::now() can return 0 on some Hexagon devices;
+// this reads the value of a 56-bit, 19.2MHz hardware counter
+// and converts it to seconds. Unlike std::chrono, this doesn't
+// return an absolute time, but since ChronoClockNow() is only used
+// to compute elapsed time, this shouldn't matter.
+struct QuRTClock {
+  typedef uint64_t rep;
+  typedef std::ratio<1, 19200000> period;
+  typedef std::chrono::duration<rep, period> duration;
+  typedef std::chrono::time_point<QuRTClock> time_point;
+  static const bool is_steady = false;
+
+  static time_point now() {
+    unsigned long long count;
+    asm volatile(" %0 = c31:30 " : "=r"(count));
+    return time_point(static_cast<duration>(count));
+  }
+};
+
+#else
+
 #if defined(HAVE_STEADY_CLOCK)
 template <bool HighResIsSteady = std::chrono::high_resolution_clock::is_steady>
 struct ChooseSteadyClock {
@@ -25,10 +48,14 @@ template <>
 struct ChooseSteadyClock<false> {
   typedef std::chrono::steady_clock type;
 };
+#endif  // HAVE_STEADY_CLOCK
+
 #endif
 
 struct ChooseClockType {
-#if defined(HAVE_STEADY_CLOCK)
+#if defined(BENCHMARK_OS_QURT)
+  typedef QuRTClock type;
+#elif defined(HAVE_STEADY_CLOCK)
   typedef ChooseSteadyClock<>::type type;
 #else
   typedef std::chrono::high_resolution_clock type;
diff --git a/test/CMakeLists.txt b/test/CMakeLists.txt
index 1de175f..815b581 100644
--- a/test/CMakeLists.txt
+++ b/test/CMakeLists.txt
@@ -192,6 +192,9 @@ benchmark_add_test(NAME user_counters_thousands_test COMMAND user_counters_thous
 compile_output_test(memory_manager_test)
 benchmark_add_test(NAME memory_manager_test COMMAND memory_manager_test --benchmark_min_time=0.01s)
 
+compile_output_test(profiler_manager_test)
+benchmark_add_test(NAME profiler_manager_test COMMAND profiler_manager_test --benchmark_min_time=0.01s)
+
 # MSVC does not allow to set the language standard to C++98/03.
 if(NOT (MSVC OR CMAKE_CXX_SIMULATE_ID STREQUAL "MSVC"))
   compile_benchmark_test(cxx03_test)
diff --git a/test/profiler_manager_test.cc b/test/profiler_manager_test.cc
new file mode 100644
index 0000000..3b08a60
--- /dev/null
+++ b/test/profiler_manager_test.cc
@@ -0,0 +1,50 @@
+// FIXME: WIP
+
+#include <memory>
+
+#include "benchmark/benchmark.h"
+#include "output_test.h"
+
+class TestProfilerManager : public benchmark::ProfilerManager {
+ public:
+  void AfterSetupStart() override { ++start_called; }
+  void BeforeTeardownStop() override { ++stop_called; }
+
+  int start_called = 0;
+  int stop_called = 0;
+};
+
+void BM_empty(benchmark::State& state) {
+  for (auto _ : state) {
+    auto iterations = state.iterations();
+    benchmark::DoNotOptimize(iterations);
+  }
+}
+BENCHMARK(BM_empty);
+
+ADD_CASES(TC_ConsoleOut, {{"^BM_empty %console_report$"}});
+ADD_CASES(TC_JSONOut, {{"\"name\": \"BM_empty\",$"},
+                       {"\"family_index\": 0,$", MR_Next},
+                       {"\"per_family_instance_index\": 0,$", MR_Next},
+                       {"\"run_name\": \"BM_empty\",$", MR_Next},
+                       {"\"run_type\": \"iteration\",$", MR_Next},
+                       {"\"repetitions\": 1,$", MR_Next},
+                       {"\"repetition_index\": 0,$", MR_Next},
+                       {"\"threads\": 1,$", MR_Next},
+                       {"\"iterations\": %int,$", MR_Next},
+                       {"\"real_time\": %float,$", MR_Next},
+                       {"\"cpu_time\": %float,$", MR_Next},
+                       {"\"time_unit\": \"ns\"$", MR_Next},
+                       {"}", MR_Next}});
+ADD_CASES(TC_CSVOut, {{"^\"BM_empty\",%csv_report$"}});
+
+int main(int argc, char* argv[]) {
+  std::unique_ptr<TestProfilerManager> pm(new TestProfilerManager());
+
+  benchmark::RegisterProfilerManager(pm.get());
+  RunOutputTests(argc, argv);
+  benchmark::RegisterProfilerManager(nullptr);
+
+  assert(pm->start_called == 1);
+  assert(pm->stop_called == 1);
+}
```

