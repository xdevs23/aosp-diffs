```diff
diff --git a/.github/workflows/c-cpp.yml b/.github/workflows/c-cpp.yml
new file mode 100644
index 0000000..7eabe3b
--- /dev/null
+++ b/.github/workflows/c-cpp.yml
@@ -0,0 +1,279 @@
+name: C/C++ CI
+
+on:
+  push:
+    branches:
+      - master
+      - github_actions
+  pull_request:
+    branches:
+      - master
+      - github_actions
+
+env:
+  # Customize the CMake build type here (Release, Debug, RelWithDebInfo, etc.)
+  BUILD_TYPE: Release
+
+jobs:
+  build_w_mipp_ubuntu-amd64:
+    runs-on: ubuntu-latest
+
+    steps:
+    - name: check out MIPP
+      uses: actions/checkout@master
+      with:
+          repository: hayguen/MIPP
+          path: ./MIPP
+    - name: cmake configure MIPP
+      run: cmake -S MIPP -B MIPP_build -DCMAKE_INSTALL_PREFIX=$HOME/.local
+    - name: cmake install MIPP headers
+      run: cmake --build MIPP_build --target install && ls -alh $HOME/.local/ && ls -alh $HOME/.local/include/
+
+    - uses: actions/checkout@v2
+    - name: cmake_make_simd_float_double
+      run: mkdir build_simd_full && cmake -S . -B build_simd_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_full
+    - name: cmake_make_simd_float
+      run: mkdir build_simd_float && cmake -S . -B build_simd_float -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_TYPE_DOUBLE=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_float
+    - name: cmake_make_simd_double
+      run: mkdir build_simd_double && cmake -S . -B build_simd_double -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_TYPE_FLOAT=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_double
+    - name: cmake_make_no-simd_float_double
+      run: mkdir build_no-simd_full && cmake -S . -B build_no-simd_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_SIMD=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_no-simd_full
+    - name: cmake_make_no-simd_scalar_float_double
+      run: mkdir build_no-simd_scalar_full && cmake -S . -B build_no-simd_scalar_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_SIMD=OFF -DPFFFT_USE_SCALAR_VECT=ON -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native && cmake --build build_no-simd_scalar_full
+    - name: compress
+      run: tar zcvf pffft_w_mipp_ubuntu-amd64.tar.gz --exclude=CMakeFiles --exclude=*.cmake --exclude=Makefile --exclude=CMakeCache.txt build_simd_full build_simd_float build_simd_double build_no-simd_full build_no-simd_scalar_full
+    - name: 'Upload Artifact'
+      uses: actions/upload-artifact@v2
+      with:
+        name: pffft_ubuntu_builds
+        path: pffft_w_mipp_ubuntu-amd64.tar.gz
+
+  build_ubuntu-amd64:
+    runs-on: ubuntu-latest
+
+    steps:
+    - uses: actions/checkout@v2
+    - name: cmake_make_simd_float_double
+      run: mkdir build_simd_full && cmake -S . -B build_simd_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_full
+    - name: cmake_make_simd_float
+      run: mkdir build_simd_float && cmake -S . -B build_simd_float -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_TYPE_DOUBLE=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_float
+    - name: cmake_make_simd_double
+      run: mkdir build_simd_double && cmake -S . -B build_simd_double -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_TYPE_FLOAT=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_double
+    - name: cmake_make_no-simd_float_double
+      run: mkdir build_no-simd_full && cmake -S . -B build_no-simd_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_SIMD=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_no-simd_full
+    - name: cmake_make_no-simd_scalar_float_double
+      run: mkdir build_no-simd_scalar_full && cmake -S . -B build_no-simd_scalar_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_SIMD=OFF -DPFFFT_USE_SCALAR_VECT=ON -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native && cmake --build build_no-simd_scalar_full
+    - name: compress
+      run: tar zcvf pffft_ubuntu-amd64.tar.gz --exclude=CMakeFiles --exclude=*.cmake --exclude=Makefile --exclude=CMakeCache.txt build_simd_full build_simd_float build_simd_double build_no-simd_full build_no-simd_scalar_full
+    - name: 'Upload Artifact'
+      uses: actions/upload-artifact@v2
+      with:
+        name: pffft_ubuntu_builds
+        path: pffft_ubuntu-amd64.tar.gz
+
+  cross_build_win_from_linux:
+    runs-on: ubuntu-20.04
+
+    steps:
+    - name: prerequisites
+      run: sudo apt -qq update && sudo apt -yqq install gcc-mingw-w64 g++-mingw-w64
+
+    - name: check out MIPP
+      uses: actions/checkout@master
+      with:
+          repository: hayguen/MIPP
+          path: ./MIPP
+    - name: cmake configure MIPP
+      working-directory: ${{runner.workspace}}
+      run: cmake -S pffft/MIPP -B MIPP_build -DCMAKE_INSTALL_PREFIX=$(pwd)
+    - name: cmake install MIPP headers
+      working-directory: ${{runner.workspace}}
+      run: cmake --build MIPP_build --target install
+
+    - uses: actions/checkout@v2
+    - name: build_w32_no-simd
+      working-directory: ${{runner.workspace}}
+      run: cd $GITHUB_WORKSPACE && bash ./cross_build_mingw32.sh no-simd -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_SIMD=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF
+    - name: build_w32_simd_full
+      working-directory: ${{runner.workspace}}
+      run: X=$(pwd) && cd $GITHUB_WORKSPACE && bash ./cross_build_mingw32.sh simd_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=pentium4 -DTARGET_C_ARCH=pentium4 -DMIPP_INCLUDE_DIRS=$X/include/mipp
+
+    - name: build_w64_no-simd
+      working-directory: ${{runner.workspace}}
+      run: cd $GITHUB_WORKSPACE && bash ./cross_build_mingw64.sh no-simd -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_SIMD=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF
+    - name: build_w64_simd_full
+      working-directory: ${{runner.workspace}}
+      run: X=$(pwd) && cd $GITHUB_WORKSPACE && bash ./cross_build_mingw64.sh simd_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=sandybridge -DTARGET_C_ARCH=sandybridge -DMIPP_INCLUDE_DIRS=$X/include/mipp
+
+    - name: compress
+      run: tar zcvf pffft_cross-build-windows-from-linux-amd64.tar.gz --exclude=CMakeFiles --exclude=*.cmake --exclude=Makefile --exclude=CMakeCache.txt  build_w32_no-simd build_w32_simd_full build_w64_no-simd build_w64_simd_full
+    - name: 'Upload Artifact'
+      uses: actions/upload-artifact@v2
+      with:
+        name: pffft_windows_from_cross_builds
+        path: pffft_cross-build-windows-from-linux-amd64.tar.gz
+
+
+  build_win_msvc:
+    # The CMake configure and build commands are platform agnostic and should work equally
+    # well on Windows or Mac.  You can convert this to a matrix build if you need
+    # cross-platform coverage.
+    # See: https://docs.github.com/en/free-pro-team@latest/actions/learn-github-actions/managing-complex-workflows#using-a-build-matrix
+    runs-on: windows-2019
+
+    steps:
+    - name: check out MIPP
+      uses: actions/checkout@master
+      with:
+          repository: hayguen/MIPP
+          path: ./MIPP
+    - name: cmake configure MIPP
+      shell: bash
+      working-directory: ${{runner.workspace}}
+      run: cmake -S pffft/MIPP -B MIPP_build -DCMAKE_INSTALL_PREFIX=$(pwd)
+    - name: cmake install MIPP headers
+      working-directory: ${{runner.workspace}}
+      run: cmake --build MIPP_build --target install
+
+    - uses: actions/checkout@v2
+
+    - name: Configure CMake No-SIMD
+      shell: bash
+      working-directory: ${{runner.workspace}}
+      run: cmake -S $GITHUB_WORKSPACE -B build_no-simd -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DENABLE_PFDSP=ON -DPFFFT_USE_SIMD=OFF -DTARGET_CXX_ARCH=none -DTARGET_C_ARCH=none
+    - name: Build No-SIMD
+      shell: bash
+      working-directory: ${{runner.workspace}}
+      # Execute the build.  You can specify a specific target with "--target <NAME>"
+      run: cmake --build build_no-simd --config $BUILD_TYPE
+
+    - name: Configure CMake SSE2
+      shell: bash
+      working-directory: ${{runner.workspace}}
+      run: cmake -S $GITHUB_WORKSPACE -B build_sse2 -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DENABLE_PFDSP=ON -DTARGET_CXX_ARCH=SSE2 -DTARGET_C_ARCH=SSE2 -DMIPP_INCLUDE_DIRS=$(pwd)/include/mipp
+    - name: Build SSE2
+      shell: bash
+      working-directory: ${{runner.workspace}}
+      # Execute the build.  You can specify a specific target with "--target <NAME>"
+      run: cmake --build build_sse2 --config $BUILD_TYPE
+
+    - name: Configure CMake AVX
+      # Use a bash shell so we can use the same syntax for environment variable
+      # access regardless of the host operating system
+      shell: bash
+      working-directory: ${{runner.workspace}}
+      run: cmake -S $GITHUB_WORKSPACE -B build_avx -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DENABLE_PFDSP=ON -DTARGET_CXX_ARCH=AVX -DTARGET_C_ARCH=AVX -DMIPP_INCLUDE_DIRS=$(pwd)/include/mipp
+    - name: Build AVX
+      working-directory: ${{runner.workspace}}
+      shell: bash
+      # Execute the build.  You can specify a specific target with "--target <NAME>"
+      run: cmake --build build_avx --config $BUILD_TYPE
+
+    - name: Configure CMake AVX2
+      # Use a bash shell so we can use the same syntax for environment variable
+      # access regardless of the host operating system
+      shell: bash
+      working-directory: ${{runner.workspace}}
+      run: cmake -S $GITHUB_WORKSPACE -B build_avx2 -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DENABLE_PFDSP=ON -DTARGET_CXX_ARCH=AVX2 -DTARGET_C_ARCH=AVX2 -DMIPP_INCLUDE_DIRS=$(pwd)/include/mipp
+    - name: Build AVX2
+      working-directory: ${{runner.workspace}}
+      shell: bash
+      # Execute the build.  You can specify a specific target with "--target <NAME>"
+      run: cmake --build build_avx2 --config $BUILD_TYPE
+
+    - name: compress
+      working-directory: ${{runner.workspace}}
+      run: tar zcvf pffft_windows-msvc-amd64.tar.gz --exclude=CMakeFiles --exclude=*.cmake --exclude=Makefile --exclude=CMakeCache.txt  build_no-simd build_sse2 build_avx build_avx2
+    - name: 'Upload Artifact'
+      uses: actions/upload-artifact@v2
+      with:
+        name: pffft_windows_msvc_builds
+        path: ${{runner.workspace}}/pffft_windows-msvc-amd64.tar.gz
+
+
+  build_win_mingw:
+    runs-on: windows-2019
+    strategy:
+      matrix:
+        compiler: [gcc]
+        msystem: [MINGW64]
+    defaults:
+      run:
+        shell: msys2 {0}
+    steps:
+    - uses: actions/checkout@v2
+    - uses: msys2/setup-msys2@v2
+      with:
+        msystem: MINGW64
+        install: gcc cmake make
+    - name: Configure cmake
+      run: CC=gcc cmake -DMINGW=ON -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native -S . -B build_mgw64
+    - name: Build
+      run: cmake --build build_mgw64
+
+    - name: compress
+      run: tar zcvf pffft_windows-mingw-amd64.tar.gz --exclude=CMakeFiles --exclude=*.cmake --exclude=Makefile --exclude=CMakeCache.txt  build_mgw64
+    - name: 'Upload Artifact'
+      uses: actions/upload-artifact@v2
+      with:
+        name: pffft_windows_mingw_builds
+        path: pffft_windows-mingw-amd64.tar.gz
+
+
+  build_macos11:
+    # copied from build_ubuntu-amd64 with minor renaming
+    runs-on: macos-11
+
+    steps:
+    - uses: actions/checkout@v2
+    - name: cmake_make_simd_float_double
+      run: mkdir build_simd_full && cmake -S . -B build_simd_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_full
+    - name: cmake_make_simd_float
+      run: mkdir build_simd_float && cmake -S . -B build_simd_float -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_TYPE_DOUBLE=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_float
+    - name: cmake_make_simd_double
+      run: mkdir build_simd_double && cmake -S . -B build_simd_double -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_TYPE_FLOAT=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_double
+    - name: cmake_make_no-simd_float_double
+      run: mkdir build_no-simd_full && cmake -S . -B build_no-simd_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_SIMD=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_no-simd_full
+    - name: cmake_make_no-simd_scalar_float_double
+      run: mkdir build_no-simd_scalar_full && cmake -S . -B build_no-simd_scalar_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_SIMD=OFF -DPFFFT_USE_SCALAR_VECT=ON -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native && cmake --build build_no-simd_scalar_full
+    - name: compress
+      run: tar zcvf pffft_macos-11.tar.gz --exclude=CMakeFiles --exclude=*.cmake --exclude=Makefile --exclude=CMakeCache.txt build_simd_full build_simd_float build_simd_double build_no-simd_full build_no-simd_scalar_full
+    - name: 'Upload Artifact'
+      uses: actions/upload-artifact@v2
+      with:
+        name: pffft_macos_builds
+        path: pffft_macos-11.tar.gz
+
+  build_w_mipp_macos11:
+    # copied from build_w_mipp_ubuntu-amd64 with minor renaming
+    runs-on: macos-11
+
+    steps:
+    - name: check out MIPP
+      uses: actions/checkout@master
+      with:
+          repository: hayguen/MIPP
+          path: ./MIPP
+    - name: cmake configure MIPP
+      run: cmake -S MIPP -B MIPP_build -DCMAKE_INSTALL_PREFIX=$HOME/.local
+    - name: cmake install MIPP headers
+      run: cmake --build MIPP_build --target install && ls -alh $HOME/.local/ && ls -alh $HOME/.local/include/
+
+    - uses: actions/checkout@v2
+    - name: cmake_make_simd_float_double
+      run: mkdir build_simd_full && cmake -S . -B build_simd_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_full
+    - name: cmake_make_simd_float
+      run: mkdir build_simd_float && cmake -S . -B build_simd_float -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_TYPE_DOUBLE=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_float
+    - name: cmake_make_simd_double
+      run: mkdir build_simd_double && cmake -S . -B build_simd_double -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_TYPE_FLOAT=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_simd_double
+    - name: cmake_make_no-simd_float_double
+      run: mkdir build_no-simd_full && cmake -S . -B build_no-simd_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_SIMD=OFF -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native  && cmake --build build_no-simd_full
+    - name: cmake_make_no-simd_scalar_float_double
+      run: mkdir build_no-simd_scalar_full && cmake -S . -B build_no-simd_scalar_full -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DPFFFT_USE_SIMD=OFF -DPFFFT_USE_SCALAR_VECT=ON -DPFFFT_USE_BENCH_GREEN=OFF -DPFFFT_USE_BENCH_KISS=OFF -DPFFFT_USE_BENCH_POCKET=OFF -DTARGET_CXX_ARCH=native -DTARGET_C_ARCH=native && cmake --build build_no-simd_scalar_full
+    - name: compress
+      run: tar zcvf pffft_w_mipp_macos-11.tar.gz --exclude=CMakeFiles --exclude=*.cmake --exclude=Makefile --exclude=CMakeCache.txt build_simd_full build_simd_float build_simd_double build_no-simd_full build_no-simd_scalar_full
+    - name: 'Upload Artifact'
+      uses: actions/upload-artifact@v2
+      with:
+        name: pffft_macos_builds
+        path: pffft_w_mipp_macos-11.tar.gz
diff --git a/.gitignore b/.gitignore
index 378eac2..a476319 100644
--- a/.gitignore
+++ b/.gitignore
@@ -1 +1,4 @@
 build
+build_benches
+build_*
+.vscode
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 7856b75..c159a91 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -2,24 +2,29 @@ cmake_minimum_required(VERSION 2.8)
 project(PRETTY_FAST_FFT)
 
 # smaller library size?
-option(USE_TYPE_FLOAT  "activate single precision 'float'?" ON)
-option(USE_TYPE_DOUBLE "activate 'double' precision float?" ON)
+option(PFFFT_USE_TYPE_FLOAT  "activate single precision 'float'?" ON)
+option(PFFFT_USE_TYPE_DOUBLE "activate 'double' precision float?" ON)
 
 # architecture/optimization options
-option(USE_SIMD        "use SIMD (SSE/AVX/NEON/ALTIVEC) CPU features? - " ON)
-option(DISABLE_SIMD_AVX "disable AVX CPU features? - " OFF)
-option(USE_SIMD_NEON   "force using NEON on ARM? (requires USE_SIMD)" OFF)
-option(USE_SCALAR_VECT "use 4-element vector scalar operations (if no other SIMD)" ON)
+option(PFFFT_USE_SIMD        "use SIMD (SSE/AVX/NEON/ALTIVEC) CPU features? - " ON)
+option(PFFFT_USE_SCALAR_VECT "use 4-element vector scalar operations (if no other SIMD)" ON)
+
+# what to install?
+option(INSTALL_PFFFT      "install pffft to CMAKE_INSTALL_PREFIX?" ON)
+option(INSTALL_PFDSP      "install pfdsp to CMAKE_INSTALL_PREFIX?" OFF)
+option(INSTALL_PFFASTCONV "install pffastconv to CMAKE_INSTALL_PREFIX?" OFF)
 
 # test options
-option(USE_BENCH_FFTW   "use (system-installed) FFTW3 in fft benchmark?" OFF)
-option(USE_BENCH_GREEN  "use Green FFT in fft benchmark? - if exists in subdir" ON)
-option(USE_BENCH_KISS   "use KissFFT in fft benchmark? - if exists in subdir" ON)
-option(USE_BENCH_POCKET "use PocketFFT in fft benchmark? - if exists in subdir" ON)
+option(PFFFT_USE_BENCH_FFTW   "use (system-installed) FFTW3 in fft benchmark?" OFF)
+option(PFFFT_USE_BENCH_GREEN  "use Green FFT in fft benchmark? - if exists in subdir" ON)
+option(PFFFT_USE_BENCH_KISS   "use KissFFT in fft benchmark? - if exists in subdir" ON)
+option(PFFFT_USE_BENCH_POCKET "use PocketFFT in fft benchmark? - if exists in subdir" ON)
+option(PFFFT_USE_BENCH_MKL    "use Intel MKL in fft benchmark? needs to be installed" OFF)
+option(PFFFT_USE_FFTPACK      "compile and use FFTPACK in fft benchmark & validation?" ON)
 
-option(USE_DEBUG_ASAN  "use GCC's address sanitizer?" OFF)
+option(PFFFT_USE_DEBUG_ASAN  "use GCC's address sanitizer?" OFF)
 
-option(DISABLE_LINK_WITH_M "Disables linking with m library to build with clangCL from MSVC" OFF)
+option(PFFFT_DISABLE_LINK_WITH_M "Disables linking with m library to build with clangCL from MSVC" OFF)
 
 # C90 requires the gcc extensions for function attributes like always_inline
 # C99 provides the function attributes: no gcc extensions required
@@ -30,20 +35,52 @@ set(CMAKE_CXX_STANDARD 98)
 set(CMAKE_CXX_STANDARD_REQUIRED ON)
 set(CMAKE_CXX_EXTENSIONS OFF)
 
+# populate what to install
+set(INSTALL_TARGETS "")
+set(INSTALL_HEADERS "")
+
 
-if ( (NOT USE_TYPE_FLOAT) AND (NOT USE_TYPE_DOUBLE) )
-  message(FATAL_ERROR "activate at least one of USE_TYPE_FLOAT or USE_TYPE_DOUBLE")
+if ( (NOT PFFFT_USE_TYPE_FLOAT) AND (NOT PFFFT_USE_TYPE_DOUBLE) )
+  message(FATAL_ERROR "activate at least one of PFFFT_USE_TYPE_FLOAT or PFFFT_USE_TYPE_DOUBLE")
 endif()
 
+list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
+include(cmake/target_optimizations.cmake)
+include(cmake/compiler_warnings.cmake)
+find_package(PAPI)
+find_package(MIPP)
+if (MIPP_FOUND)
+# if (TARGET MIPP)
+    message(STATUS "found MIPP")
+else()
+    message(STATUS "NOT found MIPP")
+endif()
 
-if (USE_DEBUG_ASAN)
+
+if (PFFFT_USE_DEBUG_ASAN)
   set(ASANLIB "asan")
 else()
   set(ASANLIB "")
 endif()
 
+message(STATUS "INFO: CMAKE_C_COMPILER_ID is ${CMAKE_C_COMPILER_ID}")
+message(STATUS "INFO: CMAKE_CXX_COMPILER_ID is ${CMAKE_CXX_COMPILER_ID}")
+if (WIN32)
+  message(STATUS "INFO: detected WIN32")
+else()
+  message(STATUS "INFO: NOT WIN32")
+endif()
+if (MINGW)
+  message(STATUS "INFO: detected MINGW with compiler ${CMAKE_C_COMPILER_ID}")
+else()
+  message(STATUS "INFO: NOT MINGW")
+endif()
+if ( CMAKE_C_COMPILER_ID MATCHES "MSVC" )
+  message(STATUS "INFO: detected MSVC with compiler ${CMAKE_C_COMPILER_ID}")
+endif()
+
 
-if (USE_BENCH_GREEN)
+if (PFFFT_USE_BENCH_GREEN)
   if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/greenffts/CMakeLists.txt")
     message(STATUS "found subdir greenffts")
     set(PATH_GREEN "${CMAKE_CURRENT_LIST_DIR}/greenffts")
@@ -53,7 +90,7 @@ if (USE_BENCH_GREEN)
   endif()
 endif()
 
-if (USE_BENCH_KISS)
+if (PFFFT_USE_BENCH_KISS)
   # git submodule add https://github.com/hayguen/kissfft.git
   if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/kissfft/CMakeLists.txt")
     message(STATUS "found subdir kissfft")
@@ -64,7 +101,7 @@ if (USE_BENCH_KISS)
   endif()
 endif()
 
-if (USE_BENCH_POCKET)
+if (PFFFT_USE_BENCH_POCKET)
   # git submodule add https://github.com/hayguen/pocketfft.git
   if (EXISTS "${CMAKE_CURRENT_LIST_DIR}/pocketfft/pocketfft_double.c")
     message(STATUS "found subdir pocketfft")
@@ -96,25 +133,37 @@ if ( CMAKE_C_COMPILER_ID MATCHES "MSVC" )
   )
 
 else()
-  if(DISABLE_LINK_WITH_M)
+  if(PFFFT_DISABLE_LINK_WITH_M)
   else()
     message(STATUS "INFO: detected NO MSVC: ${CMAKE_C_COMPILER_ID}: will link math lib m")
     set(MATHLIB "m")
   endif()
 endif()
 
+set(STDCXXLIB "")
+if (MINGW)
+  set(STDCXXLIB "stdc++")
+endif()
+
+
 set( SIMD_FLOAT_HDRS simd/pf_float.h simd/pf_sse1_float.h simd/pf_altivec_float.h simd/pf_neon_float.h simd/pf_scalar_float.h )
 set( SIMD_DOUBLE_HDRS simd/pf_double.h simd/pf_avx_double.h simd/pf_scalar_double.h )
 
-if (USE_TYPE_FLOAT)
+if (PFFFT_USE_TYPE_FLOAT)
   set( FLOAT_SOURCES pffft.c pffft.h ${SIMD_FLOAT_HDRS} )
+  if (INSTALL_PFFFT)
+    set(INSTALL_HEADERS ${INSTALL_HEADERS} pffft.h)
+  endif()
 else()
   set( FLOAT_SOURCES  )
 endif()
 
 
-if (USE_TYPE_DOUBLE)
+if (PFFFT_USE_TYPE_DOUBLE)
   set( DOUBLE_SOURCES pffft_double.c pffft_double.h ${SIMD_DOUBLE_HDRS} )
+  if (INSTALL_PFFFT)
+    set(INSTALL_HEADERS ${INSTALL_HEADERS} pffft_double.h)
+  endif()
 else()
   set( DOUBLE_SOURCES )
 endif()
@@ -122,85 +171,123 @@ endif()
 ######################################################
 
 add_library(PFFFT STATIC ${FLOAT_SOURCES} ${DOUBLE_SOURCES} pffft_common.c pffft_priv_impl.h pffft.hpp )
+set_target_properties(PFFFT PROPERTIES OUTPUT_NAME "pffft")
 target_compile_definitions(PFFFT PRIVATE _USE_MATH_DEFINES)
-if (USE_SCALAR_VECT)
+target_activate_c_compiler_warnings(PFFFT)
+if (PFFFT_USE_SCALAR_VECT)
   target_compile_definitions(PFFFT PRIVATE PFFFT_SCALVEC_ENABLED=1)
 endif()
-if (USE_DEBUG_ASAN)
+if (PFFFT_USE_DEBUG_ASAN)
   target_compile_options(PFFFT PRIVATE "-fsanitize=address")
 endif()
-if (NOT USE_SIMD)
+target_set_c_arch_flags(PFFFT)
+if (NOT PFFFT_USE_SIMD)
   target_compile_definitions(PFFFT PRIVATE PFFFT_SIMD_DISABLE=1)
 endif()
-if (USE_SIMD AND USE_SIMD_NEON)
-  target_compile_definitions(PFFFT PRIVATE PFFFT_ENABLE_NEON=1)
-  target_compile_options(PFFFT PRIVATE "-mfpu=neon")
-endif()
-if (USE_SIMD AND USE_TYPE_DOUBLE)
-  if(WIN32)
-    if(DISABLE_SIMD_AVX)
-      set_property(SOURCE pffft_double.c PROPERTY COMPILE_FLAGS "/arch:SSE2")
-    else()
-      set_property(SOURCE pffft_double.c PROPERTY COMPILE_FLAGS "/arch:AVX")
-    endif()
-  else()
-    set_property(SOURCE pffft_double.c PROPERTY COMPILE_FLAGS "-march=native")
-  endif()
-  if(DISABLE_SIMD_AVX)
-    target_compile_definitions(PFFFT PRIVATE PFFFT_AVX_DISABLE=1)
-  endif()
-endif()
-target_link_libraries( PFFFT ${MATHLIB} )
+target_link_libraries( PFFFT ${ASANLIB} ${MATHLIB} )
 set_property(TARGET PFFFT APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
 )
+if (INSTALL_PFFFT)
+  set(INSTALL_TARGETS ${INSTALL_TARGETS} PFFFT)
+  set(INSTALL_HEADERS ${INSTALL_HEADERS} pffft.hpp)
+endif()
 
 ######################################################
 
-if (USE_TYPE_FLOAT)
-
-  add_library(PFDSP STATIC pf_mixer.cpp pf_mixer.h pf_carrier.cpp pf_carrier.h pf_cic.cpp pf_cic.h fmv.h )
+if (PFFFT_USE_TYPE_FLOAT)
+  add_library(PFDSP STATIC pf_mixer.cpp pf_mixer.h pf_cplx.h pf_carrier.cpp pf_carrier.h pf_cic.cpp pf_cic.h fmv.h )
+  set_property(TARGET PFDSP PROPERTY CXX_STANDARD 11)
+  set_property(TARGET PFDSP PROPERTY CXX_STANDARD_REQUIRED ON)
+  set_target_properties(PFDSP PROPERTIES OUTPUT_NAME "pfdsp")
   target_compile_definitions(PFDSP PRIVATE _USE_MATH_DEFINES)
-  if (USE_DEBUG_ASAN)
-    target_compile_options(PFDSP PRIVATE "-fsanitize=address")
+  target_activate_cxx_compiler_warnings(PFDSP)
+  if (PFFFT_USE_DEBUG_ASAN)
+      target_compile_options(PFDSP PRIVATE "-fsanitize=address")
   endif()
-  if (USE_SIMD AND USE_SIMD_NEON)
-    target_compile_definitions(PFDSP PRIVATE PFFFT_ENABLE_NEON=1)
-    target_compile_options(PFDSP PRIVATE "-march=armv7-a" "-mfpu=neon")
+  if (PFFFT_USE_SIMD)
+      target_set_cxx_arch_flags(PFDSP)
+  else()
+      target_compile_definitions(PFDSP PRIVATE PFFFT_SIMD_DISABLE=1)
   endif()
   target_link_libraries( PFDSP ${MATHLIB} )
   set_property(TARGET PFDSP APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
-    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
+      $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
   )
+  if (INSTALL_PFDSP)
+      set(INSTALL_TARGETS ${INSTALL_TARGETS} PFDSP)
+      set(INSTALL_HEADERS ${INSTALL_HEADERS} pf_mixer.h pf_cplx.h pf_carrier.h pf_cic.h)
+  endif()
 endif()
 
 ######################################################
 
-add_library(FFTPACK STATIC fftpack.c fftpack.h)
-target_compile_definitions(FFTPACK PRIVATE _USE_MATH_DEFINES)
-target_link_libraries( FFTPACK ${MATHLIB} )
-set_property(TARGET FFTPACK APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
-  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
-)
+if (PFFFT_USE_FFTPACK)
+
+  # float / single precision
+  add_library(FFTPACK_FLOAT STATIC fftpack.c fftpack.h)
+  target_compile_definitions(FFTPACK_FLOAT PRIVATE _USE_MATH_DEFINES)
+  target_activate_c_compiler_warnings(FFTPACK_FLOAT)
+  target_link_libraries( FFTPACK_FLOAT ${MATHLIB} )
+  set_property(TARGET FFTPACK_FLOAT APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
+    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
+  )
+
+  # double precision
+  add_library(FFTPACK_DOUBLE STATIC fftpack.c fftpack.h)
+  target_compile_definitions(FFTPACK_DOUBLE PRIVATE _USE_MATH_DEFINES)
+  target_compile_definitions(FFTPACK_DOUBLE PUBLIC FFTPACK_DOUBLE_PRECISION)
+  target_activate_c_compiler_warnings(FFTPACK_DOUBLE)
+  target_link_libraries( FFTPACK_DOUBLE ${MATHLIB} )
+  set_property(TARGET FFTPACK_DOUBLE APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
+    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
+  )
+
+  # builtin test program of fftpack
+  add_executable(test_fftpack_float fftpack.c fftpack.h)
+  target_compile_definitions(test_fftpack_float PRIVATE _USE_MATH_DEFINES TESTING_FFTPACK)
+  target_link_libraries(test_fftpack_float ${MATHLIB})
+
+  add_executable(test_fftpack_double fftpack.c fftpack.h)
+  target_compile_definitions(test_fftpack_double PRIVATE _USE_MATH_DEFINES FFTPACK_DOUBLE_PRECISION TESTING_FFTPACK)
+  target_link_libraries(test_fftpack_double ${MATHLIB})
+
+endif()
 
 ######################################################
 
-if (USE_TYPE_FLOAT)
+if (PFFFT_USE_TYPE_FLOAT)
   # only 'float' supported in PFFASTCONV
   add_library(PFFASTCONV STATIC pffastconv.c pffastconv.h pffft.h )
+  set_target_properties(PFFASTCONV PROPERTIES OUTPUT_NAME "pffastconv")
   target_compile_definitions(PFFASTCONV PRIVATE _USE_MATH_DEFINES)
-  if (USE_DEBUG_ASAN)
+  target_activate_c_compiler_warnings(PFFASTCONV)
+  if (PFFFT_USE_DEBUG_ASAN)
     target_compile_options(PFFASTCONV PRIVATE "-fsanitize=address")
   endif()
   target_link_libraries( PFFASTCONV PFFFT ${ASANLIB} ${MATHLIB} )
   set_property(TARGET PFFASTCONV APPEND PROPERTY INTERFACE_INCLUDE_DIRECTORIES
     $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
   )
+  if (INSTALL_PFFASTCONV)
+    set(INSTALL_TARGETS ${INSTALL_TARGETS} PFFASTCONV)
+    set(INSTALL_HEADERS ${INSTALL_HEADERS} pffastconv.h)
+  endif()
 endif()
 
+
+######################################################
+
+install( TARGETS ${INSTALL_TARGETS}  DESTINATION lib)
+install( FILES  ${INSTALL_HEADERS}  DESTINATION include)
+
+add_custom_target(uninstall
+    "${CMAKE_COMMAND}" -P "${CMAKE_SOURCE_DIR}/uninstall.cmake"
+)
+
 #######################################################
 
-if (USE_TYPE_FLOAT)
+if (PFFFT_USE_TYPE_FLOAT)
   add_executable( test_pffft_float  test_pffft.c )
   target_compile_definitions(test_pffft_float PRIVATE _USE_MATH_DEFINES)
   target_compile_definitions(test_pffft_float PRIVATE PFFFT_ENABLE_FLOAT)
@@ -209,7 +296,7 @@ endif()
 
 ######################################################
 
-if (USE_TYPE_DOUBLE)
+if (PFFFT_USE_TYPE_DOUBLE)
   add_executable( test_pffft_double  test_pffft.c )
   target_compile_definitions(test_pffft_double PRIVATE _USE_MATH_DEFINES)
   target_compile_definitions(test_pffft_double PRIVATE PFFFT_ENABLE_DOUBLE)
@@ -218,131 +305,340 @@ endif()
 
 ######################################################
 
+add_executable( test_fft_factors  test_fft_factors.c )
+if (PFFFT_USE_TYPE_FLOAT)
+  target_compile_definitions(test_fft_factors PRIVATE PFFFT_ENABLE_FLOAT)
+endif()
+if (PFFFT_USE_TYPE_DOUBLE)
+  target_compile_definitions(test_fft_factors PRIVATE PFFFT_ENABLE_DOUBLE)
+endif()
+target_link_libraries(test_fft_factors PFFFT ${ASANLIB} ${MATHLIB})
+
+######################################################
+
 add_executable( test_pffft_cpp test_pffft.cpp )
 target_compile_definitions(test_pffft_cpp PRIVATE _USE_MATH_DEFINES)
-if (USE_TYPE_FLOAT)
+if (PFFFT_USE_TYPE_FLOAT)
   target_compile_definitions(test_pffft_cpp PRIVATE PFFFT_ENABLE_FLOAT)
 endif()
-if (USE_TYPE_DOUBLE)
+if (PFFFT_USE_TYPE_DOUBLE)
   target_compile_definitions(test_pffft_cpp PRIVATE PFFFT_ENABLE_DOUBLE)
 endif()
-target_link_libraries( test_pffft_cpp  PFFFT ${ASANLIB} )
+target_link_libraries( test_pffft_cpp  PFFFT ${STDCXXLIB} ${ASANLIB} )
 
 ######################################################
 
 add_executable( test_pffft_cpp_11 test_pffft.cpp )
 target_compile_definitions(test_pffft_cpp_11 PRIVATE _USE_MATH_DEFINES)
-if (USE_TYPE_FLOAT)
+if (PFFFT_USE_TYPE_FLOAT)
   target_compile_definitions(test_pffft_cpp_11 PRIVATE PFFFT_ENABLE_FLOAT)
 endif()
-if (USE_TYPE_DOUBLE)
+if (PFFFT_USE_TYPE_DOUBLE)
   target_compile_definitions(test_pffft_cpp_11 PRIVATE PFFFT_ENABLE_DOUBLE)
 endif()
-target_link_libraries( test_pffft_cpp_11  PFFFT ${ASANLIB} )
+target_link_libraries( test_pffft_cpp_11  PFFFT ${STDCXXLIB} ${ASANLIB} )
 
 set_property(TARGET test_pffft_cpp_11 PROPERTY CXX_STANDARD 11)
 set_property(TARGET test_pffft_cpp_11 PROPERTY CXX_STANDARD_REQUIRED ON)
 
 ######################################################
 
-if (USE_TYPE_FLOAT)
+if (PFFFT_USE_TYPE_FLOAT)
   add_executable(test_pffastconv   test_pffastconv.c
     ${SIMD_FLOAT_HDRS} ${SIMD_DOUBLE_HDRS}
   )
   target_compile_definitions(test_pffastconv PRIVATE _USE_MATH_DEFINES)
-  if (USE_DEBUG_ASAN)
+  if (PFFFT_USE_DEBUG_ASAN)
     target_compile_options(test_pffastconv PRIVATE "-fsanitize=address")
   endif()
-  if (NOT USE_SIMD)
+  target_set_c_arch_flags(test_pffastconv)
+  if (NOT PFFFT_USE_SIMD)
     target_compile_definitions(test_pffastconv PRIVATE PFFFT_SIMD_DISABLE=1)
   endif()
-  if (USE_SIMD AND USE_SIMD_NEON)
-    target_compile_definitions(test_pffastconv PRIVATE PFFFT_ENABLE_NEON=1)
-    target_compile_options(test_pffastconv PRIVATE "-mfpu=neon")
-  endif()
   target_link_libraries( test_pffastconv  PFFASTCONV ${ASANLIB} ${MATHLIB} )
+
 endif()
 
 ######################################################
 
-if (USE_TYPE_FLOAT)
-  add_executable(bench_pffft_float   bench_pffft.c pffft.h fftpack.h)
+if (PFFFT_USE_TYPE_FLOAT)
+  add_executable(bench_pffft_float   bench_pffft.c pffft.h)
   target_compile_definitions(bench_pffft_float PRIVATE _USE_MATH_DEFINES)
   target_compile_definitions(bench_pffft_float PRIVATE PFFFT_ENABLE_FLOAT)
+  if (PFFFT_USE_DEBUG_ASAN)
+    target_compile_options(bench_pffft_float PRIVATE "-fsanitize=address")
+  endif()
+
+  target_link_libraries( bench_pffft_float  PFFFT ${ASANLIB} )
 
-  target_link_libraries( bench_pffft_float  PFFFT FFTPACK ${ASANLIB} )
+  if (PFFFT_USE_FFTPACK)
+    target_compile_definitions(bench_pffft_float PRIVATE HAVE_FFTPACK=1)
+    target_link_libraries(bench_pffft_float  FFTPACK_FLOAT)
+  endif()
 
-  if (USE_BENCH_FFTW)
+  if (PFFFT_USE_BENCH_FFTW)
     target_compile_definitions(bench_pffft_float PRIVATE HAVE_FFTW=1)
     target_link_libraries(bench_pffft_float  fftw3f)
   endif()
 
-  if (PATH_GREEN AND USE_BENCH_GREEN)
+  if (PATH_GREEN AND PFFFT_USE_BENCH_GREEN)
     target_compile_definitions(bench_pffft_float PRIVATE HAVE_GREEN_FFTS=1)
     target_link_libraries(bench_pffft_float  GreenFFT)
   endif()
 
-  if (PATH_KISS AND USE_BENCH_KISS)
+  if (PATH_KISS AND PFFFT_USE_BENCH_KISS)
     target_compile_definitions(bench_pffft_float PRIVATE HAVE_KISS_FFT=1)
     target_link_libraries(bench_pffft_float  KissFFT)
   endif()
 
-  if (PATH_POCKET AND USE_BENCH_POCKET)
+  if (PATH_POCKET AND PFFFT_USE_BENCH_POCKET)
     target_compile_definitions(bench_pffft_float PRIVATE HAVE_POCKET_FFT=1)
     target_link_libraries(bench_pffft_float  PocketFFT)
   endif()
 
+  if (PFFFT_USE_BENCH_MKL)
+    if ( (CMAKE_SYSTEM_PROCESSOR STREQUAL "i686") OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64") )
+      # has chances to work
+    else()
+      # other PROCESSORs could be "ppc", "ppc64",  "arm", "aarch64", "armv7l" - or something else?!
+      message(WARNING "using Intel MKL on '${CMAKE_SYSTEM_PROCESSOR}' might fail.")
+    endif()
+    message(STATUS "In case compiling/linking with Intel MKL fails, check CMakeLists.txt or deactivate PFFFT_USE_BENCH_MKL")
+    target_compile_definitions(bench_pffft_float PRIVATE HAVE_MKL=1)
+    target_link_libraries(bench_pffft_float  mkl_intel_lp64 mkl_sequential -lmkl_core)
+  endif()
 endif()
 
-if (USE_TYPE_DOUBLE)
-  add_executable(bench_pffft_double   bench_pffft.c pffft.h fftpack.h)
+if (PFFFT_USE_TYPE_DOUBLE)
+  add_executable(bench_pffft_double   bench_pffft.c pffft.h)
   target_compile_definitions(bench_pffft_double PRIVATE _USE_MATH_DEFINES)
   target_compile_definitions(bench_pffft_double PRIVATE PFFFT_ENABLE_DOUBLE)
+  if (PFFFT_USE_DEBUG_ASAN)
+    target_compile_options(bench_pffft_double PRIVATE "-fsanitize=address")
+  endif()
   target_link_libraries( bench_pffft_double  PFFFT ${ASANLIB} )
 
-  if (USE_BENCH_FFTW)
+  if (PFFFT_USE_FFTPACK)
+    target_compile_definitions(bench_pffft_double PRIVATE HAVE_FFTPACK=1)
+    target_link_libraries(bench_pffft_double  FFTPACK_DOUBLE)
+  endif()
+
+  if (PFFFT_USE_BENCH_FFTW)
     target_compile_definitions(bench_pffft_double PRIVATE HAVE_FFTW=1)
     target_link_libraries(bench_pffft_double  fftw3)
   endif()
 
-  if (PATH_POCKET AND USE_BENCH_POCKET)
+  if (PATH_POCKET AND PFFFT_USE_BENCH_POCKET)
     target_compile_definitions(bench_pffft_double PRIVATE HAVE_POCKET_FFT=1)
     target_link_libraries(bench_pffft_double  PocketFFT)
   endif()
+
+  if (PFFFT_USE_BENCH_MKL)
+    if ( (CMAKE_SYSTEM_PROCESSOR STREQUAL "i686") OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64") )
+      # has chances to work
+    else()
+      # other PROCESSORs could be "ppc", "ppc64",  "arm", "aarch64", "armv7l" - or something else?!
+      message(WARNING "using Intel MKL on '${CMAKE_SYSTEM_PROCESSOR}' might fail.")
+    endif()
+    message(STATUS "In case compiling/linking with Intel MKL fails, check CMakeLists.txt or deactivate PFFFT_USE_BENCH_MKL")
+    target_compile_definitions(bench_pffft_double PRIVATE HAVE_MKL=1)
+    target_link_libraries(bench_pffft_double  mkl_intel_lp64 mkl_sequential -lmkl_core)
+  endif()
 endif()
 
 ######################################################
 
-if (USE_TYPE_FLOAT)
-  add_executable(bench_pf_mixer_float   bench_mixers.c)
-  target_compile_definitions(bench_pf_mixer_float PRIVATE _USE_MATH_DEFINES)
-  target_compile_definitions(bench_pf_mixer_float PRIVATE PFFFT_ENABLE_FLOAT)
+if (PFFFT_USE_TYPE_FLOAT)
+
+    add_executable(bench_pf_mixer_float   bench_mixers.cpp papi_perf_counter.h)
+    target_compile_definitions(bench_pf_mixer_float PRIVATE _USE_MATH_DEFINES)
+    target_compile_definitions(bench_pf_mixer_float PRIVATE PFFFT_ENABLE_FLOAT)
+    target_link_libraries( bench_pf_mixer_float  ${ASANLIB} )
+    if (PFFFT_USE_DEBUG_ASAN)
+      target_compile_options(bench_pf_mixer_float PRIVATE "-fsanitize=address")
+    endif()
+    if (PAPI_FOUND)
+        target_compile_definitions(bench_pf_mixer_float PRIVATE HAVE_PAPI=1)
+        target_link_libraries(bench_pf_mixer_float ${PAPI_LIBRARIES})
+    endif()
+    target_link_libraries( bench_pf_mixer_float  PFDSP $<$<CXX_COMPILER_ID:GNU>:stdc++> )
+
+
+  ############################################################################
+
+  add_library(pf_conv_arch_none pf_conv.cpp pf_conv.h pf_cplx.h)
+  target_compile_definitions(pf_conv_arch_none PRIVATE CONV_ARCH_POST=none MIPP_NO_INTRINSICS=1)
+  set_property(TARGET pf_conv_arch_none PROPERTY CXX_STANDARD 11)
+  set_property(TARGET pf_conv_arch_none PROPERTY CXX_STANDARD_REQUIRED ON)
+  target_activate_cxx_compiler_warnings(pf_conv_arch_none)
+  add_library(pf_conv_dispatcher  pf_conv_dispatcher.cpp pf_conv_dispatcher.h pf_conv.h pf_cplx.h)
+  set_property(TARGET pf_conv_dispatcher PROPERTY CXX_STANDARD 11)
+  set_property(TARGET pf_conv_dispatcher PROPERTY CXX_STANDARD_REQUIRED ON)
+  target_activate_cxx_compiler_warnings(pf_conv_dispatcher)
+
+  add_library(pf_conv_arch_dflt pf_conv.cpp pf_conv.h pf_cplx.h)
+  target_compile_definitions(pf_conv_arch_dflt PRIVATE CONV_ARCH_POST=dflt)
+  set_property(TARGET pf_conv_arch_dflt PROPERTY CXX_STANDARD 11)
+  set_property(TARGET pf_conv_arch_dflt PROPERTY CXX_STANDARD_REQUIRED ON)
+  target_activate_cxx_compiler_warnings(pf_conv_arch_dflt)
+  target_set_cxx_arch_flags(pf_conv_arch_dflt)
+
+  target_link_libraries(pf_conv_dispatcher pf_conv_arch_none pf_conv_arch_dflt)
+
+  if ((CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64") OR (CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64"))
+
+    if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
+        set(PF_CONV_ARCHES "sse3;sse4;avx;avx2")
+        set(PF_CONV_OPT_sse3 "core2")  # emulate a map
+        set(PF_CONV_OPT_sse4 "nehalem")
+        set(PF_CONV_OPT_avx  "sandybridge")
+        set(PF_CONV_OPT_avx2 "haswell")
+        target_compile_definitions(pf_conv_dispatcher PRIVATE CONV_ARCH_GCC_AMD64)
+    elseif (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
+        set(PF_CONV_ARCHES "sse2;avx;avx2")
+        set(PF_CONV_OPT_sse2 "SSE2")  # emulate a map
+        set(PF_CONV_OPT_avx  "AVX")
+        set(PF_CONV_OPT_avx2 "AVX2")
+        target_compile_definitions(pf_conv_dispatcher PRIVATE CONV_ARCH_MSVC_AMD64)
+    else()
+        set(PF_CONV_ARCHES "")
+        message(WARNING "unknown compiler ${CMAKE_CXX_COMPILER_ID} on CMAKE_SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR}: can't do architecture specific compilation")
+    endif()
+
+  elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
+
+      if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
+          set(PF_CONV_ARCHES "armv8a")
+          set(PF_CONV_OPT_armv8a   "armv8-a")  # emulate a map for arch
+
+          target_compile_definitions(pf_conv_dispatcher PRIVATE CONV_ARCH_GCC_AARCH64)
+      else()
+          set(PF_CONV_ARCHES "")
+          message(WARNING "unknown compiler ${CMAKE_CXX_COMPILER_ID} on CMAKE_SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR}: can't do architecture specific compilation")
+      endif()
+
+  elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "armv7l")
+
+    if ((CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
+        set(PF_CONV_ARCHES "neon_vfpv4;neon_rpi3_a53;neon_rpi4_a72")
+        set(PF_CONV_OPT_neon_vfpv4        "armv7-a")    # emulate a map for arch
+        set(PF_CONV_EXTRA_neon_vfpv4      "neon_vfpv4") # emulate a map for additional options (EXTRA)
+        set(PF_CONV_OPT_neon_rpi3_a53     "armv7-a")
+        set(PF_CONV_EXTRA_neon_rpi3_a53   "neon_rpi3_a53")
+        set(PF_CONV_OPT_neon_rpi4_a72     "armv7-a")
+        set(PF_CONV_EXTRA_neon_rpi4_a72   "neon_rpi4_a72")
+
+        target_compile_definitions(pf_conv_dispatcher PRIVATE CONV_ARCH_GCC_ARM32NEON)
+    else()
+        set(PF_CONV_ARCHES "")
+        message(WARNING "unknown compiler ${CMAKE_CXX_COMPILER_ID} on CMAKE_SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR}: can't do architecture specific compilation")
+    endif()
+
+  else()
+      message(WARNING "this is unforseen CMAKE_SYSTEM_PROCESSOR ${CMAKE_SYSTEM_PROCESSOR}: can't do architecture specific compilation")
+  endif()
+
+  foreach (arch_opt ${PF_CONV_ARCHES})
+      add_library(pf_conv_arch_${arch_opt} pf_conv.cpp pf_conv.h pf_cplx.h)
+      set_property(TARGET pf_conv_arch_${arch_opt} PROPERTY CXX_STANDARD 11)
+      set_property(TARGET pf_conv_arch_${arch_opt} PROPERTY CXX_STANDARD_REQUIRED ON)
+      target_activate_cxx_compiler_warnings(pf_conv_arch_${arch_opt})
+      target_compile_definitions(pf_conv_arch_${arch_opt} PRIVATE CONV_ARCH_POST=${arch_opt})
+
+      target_set_cxx_arch_option(pf_conv_arch_${arch_opt} "${PF_CONV_OPT_${arch_opt}}" "${PF_CONV_EXTRA_${arch_opt}}"  "${PF_CONV_OPT_${arch_opt}}")
+      target_link_libraries(pf_conv_dispatcher  pf_conv_arch_${arch_opt})
+      message(STATUS "added library pf_conv_arch_${arch_opt}  with CONV_ARCH_POST=${arch_opt}")
+  endforeach()
+
+  if (PFFFT_USE_DEBUG_ASAN)
+      foreach (arch_opt ${PF_CONV_ARCHES})
+          target_compile_options(pf_conv_arch_${arch_opt} PRIVATE "-fsanitize=address")
+          target_link_libraries( pf_conv_arch_${arch_opt} ${ASANLIB})
+      endforeach()
+
+      target_compile_options(pf_conv_arch_none  PRIVATE "-fsanitize=address")
+      target_link_libraries( pf_conv_arch_none  ${ASANLIB})
+
+      target_compile_options(pf_conv_dispatcher  PRIVATE "-fsanitize=address")
+      target_link_libraries(pf_conv_dispatcher ${ASANLIB})
+  endif()
+
+  if(MIPP_FOUND)
+      foreach (arch_opt ${PF_CONV_ARCHES})
+          message(STATUS "link pf_conv_arch_${arch_opt} against MIPP")
+          target_link_libraries(pf_conv_arch_${arch_opt} MIPP)
+      endforeach()
+
+      message(STATUS "link pf_conv_arch_none against MIPP")
+      target_link_libraries(pf_conv_arch_none MIPP)
+  endif()
 
-  target_link_libraries( bench_pf_mixer_float  PFDSP ${ASANLIB} )
+  ############################################################################
+
+  add_executable(bench_pf_conv_float   bench_conv.cpp papi_perf_counter.h)
+  set_property(TARGET bench_pf_conv_float PROPERTY CXX_STANDARD 11)
+  set_property(TARGET bench_pf_conv_float PROPERTY CXX_STANDARD_REQUIRED ON)
+  target_compile_definitions(bench_pf_conv_float PRIVATE _USE_MATH_DEFINES)
+  target_compile_definitions(bench_pf_conv_float PRIVATE PFFFT_ENABLE_FLOAT)
+  if (PFFFT_USE_DEBUG_ASAN)
+      target_compile_options(bench_pf_conv_float PRIVATE "-fsanitize=address")
+  endif()
+  target_link_libraries( bench_pf_conv_float  ${ASANLIB} )
+  if (PAPI_FOUND)
+      target_compile_definitions(bench_pf_conv_float PRIVATE HAVE_PAPI=1)
+      target_link_libraries(bench_pf_conv_float ${PAPI_LIBRARIES})
+  endif()
+  if(MIPP_FOUND)
+      target_link_libraries(bench_pf_conv_float MIPP)
+  endif()
+  target_link_libraries( bench_pf_conv_float  pf_conv_dispatcher PFDSP $<$<CXX_COMPILER_ID:GNU>:stdc++> )
 
 endif()
 
 ######################################################
 
+add_subdirectory(examples)
+
+######################################################
+
 enable_testing()
 
-if (USE_TYPE_FLOAT)
 
-  add_test(NAME bench_pffft_pow2
-    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/bench_pffft_float"
+add_test(NAME test_fft_factors
+  COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test_fft_factors"
+  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
+)
+
+if (PFFFT_USE_FFTPACK)
+  add_test(NAME test_fftpack_float
+    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test_fftpack_float"
     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
   )
 
-  add_test(NAME bench_pffft_non2
-    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/bench_pffft_float" "--non-pow2"
+  add_test(NAME test_fftpack_double
+    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test_fftpack_double"
     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
   )
+endif()
+
+
+if (PFFFT_USE_TYPE_FLOAT)
 
-  add_test(NAME bench_plots
-    COMMAND bash "-c" "${CMAKE_CURRENT_SOURCE_DIR}/plots.sh"
+  add_test(NAME bench_pffft_pow2
+    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/bench_pffft_float" "--max-len" "128" "--quick"
+    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
+  )
+
+  add_test(NAME bench_pffft_non2
+    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/bench_pffft_float" "--non-pow2" "--max-len" "192" "--quick"
     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
   )
 
+  # add_test(NAME bench_plots
+  #   COMMAND bash "-c" "${CMAKE_CURRENT_SOURCE_DIR}/plots.sh"
+  #   WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
+  # )
+
   add_test(NAME test_pfconv_lens_symetric
     COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test_pffastconv" "--no-bench" "--quick" "--sym"
     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
@@ -354,12 +650,12 @@ if (USE_TYPE_FLOAT)
   )
 
   add_test(NAME bench_pfconv_symetric
-    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test_pffastconv" "--no-len" "--sym"
+    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test_pffastconv" "--no-len" "--quick" "--sym"
     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
   )
 
   add_test(NAME bench_pfconv_non_sym
-    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test_pffastconv" "--no-len"
+    COMMAND "${CMAKE_CURRENT_BINARY_DIR}/test_pffastconv" "--no-len" "--quick"
     WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
   )
 
diff --git a/METADATA b/METADATA
index 5103d33..c71a9c4 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,20 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/<absolute path to project>
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "pffft"
 description: "A pretty fast FFT. This is a fork of Julien Pommier\'s PFFFT. The original hasn\'t been maintained since 2016, while this one is actively developed on."
 third_party {
-  url {
-    type: HOMEPAGE
-    value: "https://github.com/marton78/pffft"
-  }
-  url {
-    type: GIT
-    value: "https://github.com/marton78/pffft.git"
-  }
-  version: "3f1559f08223c8dfc276170e4b43ab2d07ecd188"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2021
+    year: 2025
     month: 1
-    day: 28
+    day: 27
+  }
+  homepage: "https://github.com/marton78/pffft"
+  identifier {
+    type: "Git"
+    value: "https://github.com/marton78/pffft.git"
+    version: "e0bf595c98ded55cc457a371c1b29c8cab552628"
   }
 }
diff --git a/OWNERS b/OWNERS
new file mode 100644
index 0000000..2e8f086
--- /dev/null
+++ b/OWNERS
@@ -0,0 +1 @@
+include platform/system/core:main:/janitors/OWNERS
diff --git a/README.md b/README.md
index f11e32f..275c4e1 100644
--- a/README.md
+++ b/README.md
@@ -1,6 +1,25 @@
+
+---
+
 # PFFFT: a pretty fast FFT and fast convolution with PFFASTCONV
 
-## TL;DR
+---
+
+<!-- toc -->
+
+- [Brief Description](#brief-description)
+- [Why does it exist?](#why-does-it-exist)
+- [CMake](#cmake)
+- [History / Origin / Changes](#history--origin--changes)
+- [Comparison with other FFTs](#comparison-with-other-ffts)
+- [Dependencies / Required Linux packages](#dependencies--required-linux-packages)
+- [Benchmarks and results](#benchmarks-and-results)
+
+<!-- tocstop -->
+
+---
+
+## Brief description:
 
 PFFFT does 1D Fast Fourier Transforms, of single precision real and
 complex vectors. It tries do it fast, it tries to be correct, and it
@@ -8,6 +27,9 @@ tries to be small. Computations do take advantage of SSE1 instructions
 on x86 cpus, Altivec on powerpc cpus, and NEON on ARM cpus. The
 license is BSD-like.
 
+PFFFT is a fork of [Julien Pommier's library on bitbucket](https://bitbucket.org/jpommier/pffft/)
+with some changes and additions.
+
 
 PFFASTCONV does fast convolution (FIR filtering), of single precision 
 real vectors, utilizing the PFFFT library. The license is BSD-like.
@@ -20,8 +42,8 @@ The fast convolution from PFFASTCONV might get merged into PFDSP.
 
 ## Why does it exist:
 
-I was in search of a good performing FFT library , preferably very
-small and with a very liberal license.
+I (Julien Pommier) was in search of a good performing FFT library ,
+preferably very small and with a very liberal license.
 
 When one says "fft library", FFTW ("Fastest Fourier Transform in the
 West") is probably the first name that comes to mind -- I guess that
@@ -81,20 +103,19 @@ in `pffastconv.h`.
 ### C++:
 A simple C++ wrapper is available in `pffft.hpp`.
 
-
 ### Git:
-This archive's source can be downloaded with git including the submodules:
+This archive's source can be downloaded with git (without the submodules):
 ```
-git clone --recursive https://github.com/hayguen/pffft.git
+git clone https://github.com/marton78/pffft.git
 ```
 
-With `--recursive` the submodules for Green and Kiss-FFT are also fetched,
-to use them in the benchmark. You can omit the `--recursive`-option.
+### Only two files?:
+_"Only two files, in good old C, pffft.c and pffft.h"_
 
-For retrieving the submodules later:
-```
-git submodule update --init
-```
+This statement does **NO LONGER** hold!
+
+With new functionality and support for AVX, there was need to restructure the sources.
+But you can compile and link **pffft** as a static library.
 
 
 ## CMake:
@@ -102,14 +123,75 @@ There's now CMake support to build the static libraries `libPFFFT.a`
 and `libPFFASTCONV.a` from the source files, plus the additional 
 `libFFTPACK.a` library. Later one's sources are there anyway for the benchmark.
 
+There are several CMake options to modify library size and optimization.
+You can explore all available options with `cmake-gui` or `ccmake`,
+the console version - after having installed (on Debian/Ubuntu Linux) one of
+```
+sudo apt-get install cmake-qt-gui
+sudo apt-get install cmake-curses-gui
+```
+
+Some of the options:
+* `PFFFT_USE_TYPE_FLOAT` to activate single precision 'float' (default: ON)
+* `PFFFT_USE_TYPE_DOUBLE` to activate 'double' precision float (default: ON)
+* `PFFFT_USE_SIMD` to use SIMD (SSE/AVX/NEON/ALTIVEC) CPU features? (default: ON)
+* `DISABLE_SIMD_AVX` to disable AVX CPU features (default: OFF)
+* `PFFFT_USE_SIMD_NEON` to force using NEON on ARM (requires PFFFT_USE_SIMD) (default: OFF)
+* `PFFFT_USE_SCALAR_VECT` to use 4-element vector scalar operations (if no other SIMD) (default: ON)
+
+Options can be passed to `cmake` at command line, e.g.
+```
+cmake -DPFFFT_USE_TYPE_FLOAT=OFF -DPFFFT_USE_TYPE_DOUBLE=ON
+```
+
+My Linux distribution defaults to GCC. With installed CLANG and the bash shell, you can use it with
+```
+mkdir build
+cd build
+CC=/usr/bin/clang CXX=/usr/bin/clang++ cmake -DCMAKE_BUILD_TYPE=Debug ../
+cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=~ ../
+ccmake .                          # or: cmake-gui .
+cmake --build .                   # or simply: make
+ctest                             # to execute some tests - including benchmarks
+cmake --build . --target install  # or simply: [sudo] make install
+```
+
+With MSVC on Windows, you need some different options. Following ones to build a 64-bit Release with Visual Studio 2019:
+```
+mkdir build
+cd build
+cmake -G "Visual Studio 16 2019" -A x64 ..
+cmake --build . --config Release
+ctest -C Release
+```
+
+see [https://cmake.org/cmake/help/v3.15/manual/cmake-generators.7.html#visual-studio-generators](https://cmake.org/cmake/help/v3.15/manual/cmake-generators.7.html#visual-studio-generators)
+
 
-## Origin:
-Origin for this code is Julien Pommier's pffft on bitbucket:
+## History / Origin / Changes:
+Origin for this code/fork is Julien Pommier's pffft on bitbucket:
 [https://bitbucket.org/jpommier/pffft/](https://bitbucket.org/jpommier/pffft/)
 
+Git history shows following first commits of the major contributors:
+* Julien Pommier: November 19, 2011
+* Marton Danoczy: September 30, 2015
+* Hayati Ayguen: December 22, 2019
+* Dario Mambro: March 24, 2020
 
-## Comparison with other FFTs:
+There are a few other contributors not listed here.
+
+The main changes include:
+* improved benchmarking, see [https://github.com/hayguen/pffft_benchmarks](https://github.com/hayguen/pffft_benchmarks)
+* double support
+* avx(2) support
+* c++ headers (wrapper)
+* additional API helper functions
+* additional library for fast convolution
+* cmake support
+* ctest
 
+
+## Comparison with other FFTs:
 The idea was not to break speed records, but to get a decently fast
 fft that is at least 50% as fast as the fastest FFT -- especially on
 slowest computers . I'm more focused on getting the best performance
@@ -137,19 +219,134 @@ On Debian/Ubuntu Linux following packages should be installed:
 sudo apt-get install build-essential gcc g++ cmake
 ```
 
-for benchmarking, you should have additional packages:
+
+## Benchmarks and results
+
+#### Quicklink
+Find results at [https://github.com/hayguen/pffft_benchmarks](https://github.com/hayguen/pffft_benchmarks).
+
+#### General
+My (Hayati Ayguen) first look at FFT-benchmarks was with [benchFFT](http://www.fftw.org/benchfft/)
+and especially the results of the benchmarks [results](http://www.fftw.org/speed/),
+which demonstrate the performance of the [FFTW](http://www.fftw.org/).
+Looking at the benchmarked computer systems from todays view (2021), these are quite outdated.
+
+Having a look into the [benchFFT source code](http://www.fftw.org/benchfft/benchfft-3.1.tar.gz),
+the latest source changes, including competitive fft implementations, are dated November 2003.
+
+In 2019, when pffft got my attention at [bitbucket](https://bitbucket.org/jpommier/pffft/src/master/),
+there were also some benchmark results.
+Unfortunately the results are tables with numbers - without graphical plots.
+Without the plots, i could not get an impression. That was, why i started
+[https://github.com/hayguen/pffft_benchmarks](https://github.com/hayguen/pffft_benchmarks),
+which includes GnuPlot figures.
+
+Today in June 2021, i realized the existence of [https://github.com/FFTW/benchfft](https://github.com/FFTW/benchfft).
+This repository is much more up-to-date with a commit in December 2020.
+Unfortunately, it looks not so simple to get it run - including the generation of plots.
+
+Is there any website showing benchFFT results of more recent computer systems?
+
+Of course, it's very important, that a benchmark can be compared with a bunch
+of different FFT algorithms/implementations.
+This requires to have these compiled/built and utilizable.
+
+
+#### Git submodules for Green-, Kiss- and Pocket-FFT
+Sources for [Green-](https://github.com/hayguen/greenffts),
+[Kiss-](https://github.com/hayguen/kissfft)
+and [Pocket-FFT](https://github.com/hayguen/pocketfft)
+can be downloaded directly with the sources of this repository - using git submodules:
+```
+git clone --recursive https://github.com/marton78/pffft.git
+```
+
+Important is `--recursive`, that does also fetch the submodules directly.
+But you might retrieve the submodules later, too:
+```
+git submodule update --init
+```
+
+#### Fastest Fourier Transform in the West: FFTW
+To allow comparison with FFTW [http://www.fftw.org/](http://www.fftw.org/),
+cmake option `-DPFFFT_USE_BENCH_FFTW=ON` has to be used with following commands.
+The cmake option requires previous setup of following (debian/ubuntu) package:
 ```
-sudo apt-get install libfftw3-dev gnuplot
+sudo apt-get install libfftw3-dev
 ```
 
-run the benchmarks with `./bench_all.sh ON` , to include benchmarks of fftw3 ..
-more details in README of [https://github.com/hayguen/pffft_benchmarks](https://github.com/hayguen/pffft_benchmarks)
+#### Intel Math Kernel Library: MKL
+Intel's MKL [https://software.intel.com/content/www/us/en/develop/tools/oneapi/components/onemkl.html](https://software.intel.com/content/www/us/en/develop/tools/oneapi/components/onemkl.html)
+currently looks even faster than FFTW.
+
+On Ubuntu-Linux it's easy to setup with the package `intel-mkl`.
+Similar on Debian: `intel-mkl-full`.
+
+There are special repositories for following Linux distributions:
+* Debian/apt: [https://software.intel.com/content/www/us/en/develop/articles/installing-intel-free-libs-and-python-apt-repo.html](https://software.intel.com/content/www/us/en/develop/articles/installing-intel-free-libs-and-python-apt-repo.html)
+* RedHat/yum: [https://software.intel.com/content/www/us/en/develop/articles/installing-intel-free-libs-and-python-yum-repo.html](https://software.intel.com/content/www/us/en/develop/articles/installing-intel-free-libs-and-python-yum-repo.html)
+* Gentoo/ebuild: [https://packages.gentoo.org/packages/sci-libs/mkl](https://packages.gentoo.org/packages/sci-libs/mkl)
+
+#### Performing the benchmarks - with CMake
+Benchmarks should be prepared by creating a special build folder
+```
+mkdir build_benches
+cd build_benches
+cmake ../bench
+```
+
+There are several CMake options to parametrize, which fft implementations should be benched.
+You can explore all available options with `cmake-gui` or `ccmake`, see [CMake](#cmake).
+
+Some of the options:
+* `BENCH_ID`         name the benchmark - used in filename
+* `BENCH_ARCH`       target architecture passed to compiler for code optimization
+* `PFFFT_USE_BENCH_FFTW`   use (system-installed) FFTW3 in fft benchmark? (default: OFF)
+* `PFFFT_USE_BENCH_GREEN`  use Green FFT in fft benchmark? (default: ON)
+* `PFFFT_USE_BENCH_KISS`   use KissFFT in fft benchmark? (default: ON)
+* `PFFFT_USE_BENCH_POCKET` use PocketFFT in fft benchmark? (default: ON)
+* `PFFFT_USE_BENCH_MKL`    use Intel MKL in fft benchmark?  (default: OFF)
+
+These options can be passed to `cmake` at command line, e.g.
+```
+cmake -DBENCH_ARCH=native -DPFFFT_USE_BENCH_FFTW=ON -DPFFFT_USE_BENCH_MKL=ON ../bench
+```
+
+The benchmarks are built and executed with
+```
+cmake --build .
+```
+
+You can also specify to use a different compiler/version with the cmake step, e.g.:
+
+```
+CC=/usr/bin/gcc-9 CXX=/usr/bin/g++-9 cmake -DBENCH_ID=gcc9 -DBENCH_ARCH=native -DPFFFT_USE_BENCH_FFTW=ON -DPFFFT_USE_BENCH_MKL=ON ../bench
+```
+
+```
+CC=/usr/bin/clang-11 CXX=/usr/bin/clang++-11 cmake -DBENCH_ID=clang11 -DBENCH_ARCH=native -DPFFFT_USE_BENCH_FFTW=ON -DPFFFT_USE_BENCH_MKL=ON ../bench
+```
+
+For using MSVC/Windows, the cmake command requires/needs the generator and architecture options and to be called from the VS Developer prompt:
+```
+cmake -G "Visual Studio 16 2019" -A x64 ../bench/
+```
+
+see [https://cmake.org/cmake/help/v3.15/manual/cmake-generators.7.html#visual-studio-generators](https://cmake.org/cmake/help/v3.15/manual/cmake-generators.7.html#visual-studio-generators)
+
+
+
+For running with different compiler version(s):
+* copy the result file (.tgz), e.g. `cp *.tgz ../`
+* delete the build directory: `rm -rf *`
+* then continue with the cmake step
 
 
-## Benchmark results
+#### Benchmark results and contribution
+You might contribute by providing us the results of your computer(s).
 
 The benchmark results are stored in a separate git-repository:
 See [https://github.com/hayguen/pffft_benchmarks](https://github.com/hayguen/pffft_benchmarks).
 
-This is to keep the sources small.
+This is to keep this repositories' sources small.
 
diff --git a/bench/CMakeLists.txt b/bench/CMakeLists.txt
new file mode 100644
index 0000000..2bc49c6
--- /dev/null
+++ b/bench/CMakeLists.txt
@@ -0,0 +1,224 @@
+cmake_minimum_required(VERSION 2.8)
+project(BENCH_PFFFT)
+
+set(BENCH_ID  "default" CACHE STRING "ID: use single word without spaces. gets part of result filename")
+
+option(BENCH_FAST_MATH  "Build with fast math - non IEEE compliant" ON)
+
+if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
+  set(BENCH_ARCH "native" CACHE STRING "target architecture (-march): native/SSE:core2/AVX:sandybridge/ARM-NEON:armv7-a")
+elseif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
+  set(BENCH_ARCH "native" CACHE STRING "target architecture (-march): native/SSE:core2/AVX:sandybridge")
+elseif (CMAKE_C_COMPILER_ID STREQUAL "MSVC")  # others: "Intel"
+  set(BENCH_ARCH "AVX" CACHE STRING "target architecture (/arch): SSE2/AVX")
+else()
+  set(BENCH_ARCH "" CACHE STRING "target architecture - use full compiler option!")
+endif()
+
+# architecture/optimization options
+option(PFFFT_USE_SIMD        "use SIMD (SSE/AVX/NEON/ALTIVEC) CPU features? - " ON)
+option(DISABLE_SIMD_AVX "disable AVX CPU features? - " OFF)
+option(PFFFT_USE_SIMD_NEON   "force using NEON on ARM? (requires PFFFT_USE_SIMD)" OFF)
+option(PFFFT_USE_SCALAR_VECT "use 4-element vector scalar operations (if no other SIMD)" ON)
+
+option(PFFFT_USE_BENCH_FFTW   "use (system-installed) FFTW3 in fft benchmark?" OFF)
+option(PFFFT_USE_BENCH_GREEN  "use Green FFT in fft benchmark? - if exists in subdir" ON)
+option(PFFFT_USE_BENCH_KISS   "use KissFFT in fft benchmark? - if exists in subdir" ON)
+option(PFFFT_USE_BENCH_POCKET "use PocketFFT in fft benchmark? - if exists in subdir" ON)
+option(PFFFT_USE_BENCH_MKL    "use Intel MKL in fft benchmark? needs to be installed" OFF)
+
+
+set(OSSTR "")
+if (WIN32)
+  set(OSSTR "Win32")
+endif (WIN32)
+if (UNIX)
+  set(OSSTR "Unix")
+endif (UNIX)
+
+set(BUILD_DIR_TO_EXE "")
+set(CMAKE_PLATFORM_OPT "")
+set(CMAKE_MAKE_OPT "")
+if (MSVC)
+  set(BUILD_DIR_TO_EXE "Release/")
+  set(CMAKE_PLATFORM_OPT "-A \"${CMAKE_GENERATOR_PLATFORM}\"")
+  set(CMAKE_MAKE_OPT "-DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}")
+endif()
+
+
+set(benchdir "${CMAKE_BINARY_DIR}/bench_${BENCH_ID}")
+set(benchdir_flt "${CMAKE_BINARY_DIR}/bench_${BENCH_ID}/float")
+set(benchdir_dbl "${CMAKE_BINARY_DIR}/bench_${BENCH_ID}/double")
+set(builddir_flt "${CMAKE_BINARY_DIR}/build_${BENCH_ID}_float")
+set(builddir_dbl "${CMAKE_BINARY_DIR}/build_${BENCH_ID}_double")
+
+add_custom_command(OUTPUT "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E make_directory "${benchdir}"
+  COMMAND ${CMAKE_COMMAND} -E echo "benchmark ${BENCH_ID}"   > "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "CMake major:    ${CMAKE_MAJOR_VERSION}"        >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "CMake minor:    ${CMAKE_MINOR_VERSION}"        >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "OS:             ${OSSTR}"                      >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "System:         ${CMAKE_SYSTEM_NAME}"          >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "System CPU:     ${CMAKE_SYSTEM_PROCESSOR}"     >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "System Version: ${CMAKE_HOST_SYSTEM_VERSION}"  >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "C   Compiler:   ${CMAKE_C_COMPILER_ID}"        >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "C   Version:    ${CMAKE_C_COMPILER_VERSION}"   >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "C++ Compiler:   ${CMAKE_CXX_COMPILER_ID}"      >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "C++ Version:    ${CMAKE_CXX_COMPILER_VERSION}" >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "MSVC Version:   ${MSVC_VERSION}"               >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "MSVC Toolset:   ${MSVC_TOOLSET_VERSION}"       >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "Exe Suffix:     ${CMAKE_EXECUTABLE_SUFFIX}"    >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "C   Byte Order: ${CMAKE_C_BYTE_ORDER}"         >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "C++ Byte Order: ${CMAKE_CXX_BYTE_ORDER}"       >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo ""                                              >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "Architecture:   ${BENCH_ARCH}"                 >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "Fast math:      ${BENCH_FAST_MATH}"            >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "config PFFFT_USE_SIMD=${PFFFT_USE_SIMD}"                   >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "config DISABLE_SIMD_AVX=${DISABLE_SIMD_AVX}"   >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "config PFFFT_USE_SIMD_NEON=${PFFFT_USE_SIMD_NEON}"         >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "config PFFFT_USE_SCALAR_VECT=${PFFFT_USE_SCALAR_VECT}"     >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "config PFFFT_USE_BENCH_FFTW=${PFFFT_USE_BENCH_FFTW}"       >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "config PFFFT_USE_BENCH_GREEN=${PFFFT_USE_BENCH_GREEN}"     >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "config PFFFT_USE_BENCH_KISS=${PFFFT_USE_BENCH_KISS}"       >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "config PFFFT_USE_BENCH_POCKET=${PFFFT_USE_BENCH_POCKET}"   >> "${benchdir}/info.txt"
+  COMMAND ${CMAKE_COMMAND} -E echo "config PFFFT_USE_BENCH_MKL=${PFFFT_USE_BENCH_MKL}"         >> "${benchdir}/info.txt"
+)
+
+if (UNIX)
+  add_custom_command(OUTPUT "${benchdir}/unix_info.txt"
+    COMMAND ${CMAKE_COMMAND} -E touch "${benchdir}/unix_info.txt"
+    COMMAND bash "-c" "${CMAKE_CURRENT_SOURCE_DIR}/unix_info.sh"
+    DEPENDS "${benchdir}/info.txt"
+    WORKING_DIRECTORY ${benchdir}
+  )
+else()
+  add_custom_command(OUTPUT "${benchdir}/unix_info.txt"
+    COMMAND ${CMAKE_COMMAND} -E touch "${benchdir}/unix_info.txt"
+    DEPENDS "${benchdir}/info.txt"
+    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
+  )
+endif()
+
+
+add_custom_command(OUTPUT "${builddir_flt}/directory.txt"
+  COMMAND ${CMAKE_COMMAND} -E make_directory "${builddir_flt}"
+  COMMAND ${CMAKE_COMMAND} -E touch "${builddir_flt}/directory.txt"
+)
+
+add_custom_command(OUTPUT "${builddir_dbl}/directory.txt"
+  COMMAND ${CMAKE_COMMAND} -E make_directory "${builddir_dbl}"
+  COMMAND ${CMAKE_COMMAND} -E touch "${builddir_dbl}/directory.txt"
+)
+
+add_custom_command(OUTPUT "${benchdir_flt}/directory.txt"
+  COMMAND ${CMAKE_COMMAND} -E make_directory "${benchdir_flt}"
+  COMMAND ${CMAKE_COMMAND} -E touch "${benchdir_flt}/directory.txt"
+)
+
+add_custom_command(OUTPUT "${benchdir_dbl}/directory.txt"
+  COMMAND ${CMAKE_COMMAND} -E make_directory "${benchdir_dbl}"
+  COMMAND ${CMAKE_COMMAND} -E touch "${benchdir_dbl}/directory.txt"
+)
+
+
+
+add_custom_target(build_float
+  COMMAND ${CMAKE_COMMAND} -E echo "start cmake for float in ${builddir_flt}"
+  COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" ${CMAKE_PLATFORM_OPT}
+                        "${CMAKE_MAKE_OPT}"
+                        -DCMAKE_BUILD_TYPE=Release
+                        "-DARCH=${BENCH_ARCH}"
+                        -DUSE_FAST_MATH=${BENCH_FAST_MATH}
+                        -DPFFFT_USE_TYPE_FLOAT=ON
+                        -DPFFFT_USE_TYPE_DOUBLE=OFF
+                        -DUSE_FLOAT_PREC=ON
+                        -DPFFFT_USE_SIMD=${PFFFT_USE_SIMD}
+                        -DDISABLE_SIMD_AVX=${DISABLE_SIMD_AVX}
+                        -DPFFFT_USE_SIMD_NEON=${PFFFT_USE_SIMD_NEON}
+                        -DPFFFT_USE_SCALAR_VECT=${PFFFT_USE_SCALAR_VECT}
+                        -DPFFFT_USE_BENCH_FFTW=${PFFFT_USE_BENCH_FFTW}
+                        -DPFFFT_USE_BENCH_GREEN=${PFFFT_USE_BENCH_GREEN}
+                        -DPFFFT_USE_BENCH_KISS=${PFFFT_USE_BENCH_KISS}
+                        -DPFFFT_USE_BENCH_POCKET=${PFFFT_USE_BENCH_POCKET}
+                        -DPFFFT_USE_BENCH_MKL=${PFFFT_USE_BENCH_MKL}
+                        "${CMAKE_SOURCE_DIR}/.."
+  # COMMAND ${CMAKE_COMMAND} -E echo "start cmake --build . for float in ${builddir_flt}"
+  COMMAND ${CMAKE_COMMAND} --build . --config Release
+  DEPENDS "${builddir_flt}/directory.txt"
+  WORKING_DIRECTORY "${builddir_flt}"
+)
+
+add_custom_target(build_double
+  COMMAND ${CMAKE_COMMAND} -E echo "start cmake for double in ${builddir_dbl}"
+  COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" ${CMAKE_PLATFORM_OPT}
+                        "${CMAKE_MAKE_OPT}"
+                        -DCMAKE_BUILD_TYPE=Release
+                        "-DARCH=${BENCH_ARCH}"
+                        -DUSE_FAST_MATH=${BENCH_FAST_MATH}
+                        -DPFFFT_USE_TYPE_FLOAT=OFF
+                        -DPFFFT_USE_TYPE_DOUBLE=ON
+                        -DUSE_FLOAT_PREC=OFF
+                        -DPFFFT_USE_SIMD=${PFFFT_USE_SIMD}
+                        -DDISABLE_SIMD_AVX=${DISABLE_SIMD_AVX}
+                        -DPFFFT_USE_SIMD_NEON=${PFFFT_USE_SIMD_NEON}
+                        -DPFFFT_USE_SCALAR_VECT=${PFFFT_USE_SCALAR_VECT}
+                        -DPFFFT_USE_BENCH_FFTW=${PFFFT_USE_BENCH_FFTW}
+                        -DPFFFT_USE_BENCH_GREEN=${PFFFT_USE_BENCH_GREEN}
+                        -DPFFFT_USE_BENCH_KISS=${PFFFT_USE_BENCH_KISS}
+                        -DPFFFT_USE_BENCH_POCKET=${PFFFT_USE_BENCH_POCKET}
+                        -DPFFFT_USE_BENCH_MKL=${PFFFT_USE_BENCH_MKL}
+                        "${CMAKE_SOURCE_DIR}/.."
+  COMMAND ${CMAKE_COMMAND} -E echo "start cmake --build . for double in ${builddir_dbl}"
+  COMMAND ${CMAKE_COMMAND} --build . --config Release
+  DEPENDS "${builddir_dbl}/directory.txt"
+  WORKING_DIRECTORY "${builddir_dbl}"
+)
+
+add_custom_target(bench_float
+  COMMAND ${CMAKE_COMMAND} -E echo "start benchmark for float"
+  COMMAND "${builddir_flt}/${BUILD_DIR_TO_EXE}bench_pffft_float${CMAKE_EXECUTABLE_SUFFIX}"
+  DEPENDS "${benchdir_flt}/directory.txt" build_float
+  WORKING_DIRECTORY "${benchdir_flt}"
+)
+
+add_custom_target(bench_double
+  COMMAND ${CMAKE_COMMAND} -E echo "start benchmark for double"
+  COMMAND "${builddir_dbl}/${BUILD_DIR_TO_EXE}bench_pffft_double${CMAKE_EXECUTABLE_SUFFIX}"
+  DEPENDS "${benchdir_dbl}/directory.txt" build_double
+  WORKING_DIRECTORY "${benchdir_dbl}"
+)
+
+add_custom_target(bench ALL
+  COMMAND ${CMAKE_COMMAND} -E echo ""
+  COMMAND ${CMAKE_COMMAND} -E tar cvz "bench_${BENCH_ID}.tgz" ${benchdir}
+  COMMAND ${CMAKE_COMMAND} -E echo ""
+  COMMAND ${CMAKE_COMMAND} -E echo "now mail result file bench_${BENCH_ID}.tgz"
+  # DEPENDS "${benchdir}/info.txt" "${benchdir}/unix_info.txt"
+  DEPENDS "${benchdir}/info.txt" bench_float bench_double "${benchdir}/unix_info.txt"
+  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
+)
+
+add_custom_target(bench_float_tar
+  COMMAND ${CMAKE_COMMAND} -E echo ""
+  COMMAND ${CMAKE_COMMAND} -E tar cvz "bench_${BENCH_ID}.tgz" ${benchdir}
+  COMMAND ${CMAKE_COMMAND} -E echo ""
+  COMMAND ${CMAKE_COMMAND} -E echo "now mail result file bench_${BENCH_ID}.tgz"
+  DEPENDS "${benchdir}/info.txt" bench_float "${benchdir}/unix_info.txt"
+  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
+)
+
+add_custom_target(bench_double_tar
+  COMMAND ${CMAKE_COMMAND} -E echo ""
+  COMMAND ${CMAKE_COMMAND} -E tar cvz "bench_${BENCH_ID}.tgz" ${benchdir}
+  COMMAND ${CMAKE_COMMAND} -E echo ""
+  COMMAND ${CMAKE_COMMAND} -E echo "now mail result file bench_${BENCH_ID}.tgz"
+  DEPENDS "${benchdir}/info.txt" bench_double "${benchdir}/unix_info.txt"
+  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
+)
+
+add_custom_target(clean_results
+  COMMAND ${CMAKE_COMMAND} -E remove_directory "${builddir_flt}"
+  COMMAND ${CMAKE_COMMAND} -E remove_directory "${builddir_dbl}"
+  WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
+)
+
diff --git a/bench/unix_info.sh b/bench/unix_info.sh
new file mode 100755
index 0000000..7ef6687
--- /dev/null
+++ b/bench/unix_info.sh
@@ -0,0 +1,9 @@
+#!/bin/bash
+
+lscpu > unix_lscpu.txt
+cat /proc/cpuinfo > unix_cpuinfo.txt
+lsb_release -a  > unix_lsb_release.txt
+FILES=$(ls -1 /etc/*-release)
+if [ ! -z "$FILES" ]; then
+  cp /etc/*-release ./
+fi
diff --git a/bench_all.sh b/bench_all.sh
deleted file mode 100755
index b4c6b23..0000000
--- a/bench_all.sh
+++ /dev/null
@@ -1,81 +0,0 @@
-#!/bin/bash
-
-FFTW="ON"
-CMAKEOPT=""
-# CMAKEOPT="-DUSE_NEON=ON"
-
-if [ ! -z "$1" ]; then
-  FFTW="$1"
-fi
-
-if [ ! -d build ]; then
-  mkdir build
-  cd build
-else
-  cd build
-  make clean
-  rm *.csv *.txt *.png
-fi
-
-echo "" >ToolChain.cmake
-if [ -z "${GCC_WITH_CMAKE}" ]; then
-  GCC_WITH_CMAKE="gcc"
-else
-  GCCPATH=$(basename "${GCC_WITH_CMAKE}")
-  echo "SET(CMAKE_C_COMPILER     ${GCCPATH})" >>ToolChain.cmake
-fi
-if [ -z "${GPP_WITH_CMAKE}" ]; then
-  GPP_WITH_CMAKE="g++"
-else
-  GPPPATH=$(basename "${GPP_WITH_CMAKE}")
-  echo "SET(CMAKE_CXX_COMPILER   ${GPPPATH})" >>ToolChain.cmake
-fi
-
-
-#cmake -DCMAKE_TOOLCHAIN_FILE=ToolChain.cmake -DUSE_BENCH_FFTW=${FFTW} -DUSE_SIMD=OFF ${CMAKEOPT} ../
-#make clean
-#make
-#echo -e "\n\nrunning without simd (==scalar) .."
-#time ctest -V
-
-cmake -DCMAKE_TOOLCHAIN_FILE=ToolChain.cmake -DUSE_BENCH_FFTW=${FFTW} -DUSE_SIMD=ON ${CMAKEOPT} ../
-#make clean
-make
-echo -e "\n\nrunning with simd .."
-time ctest -V
-
-
-echo "$@" >infos.txt
-echo "FFTW=${FFTW}" >>infos.txt
-echo "CMAKEOPT=${CMAKEOPT}" >>infos.txt
-
-
-echo "" >>infos.txt
-echo "${GCC_WITH_CMAKE} --version:" >>infos.txt
-${GCC_WITH_CMAKE} --version &>>infos.txt
-
-echo "" >>infos.txt
-echo "${GPP_WITH_CMAKE} --version:" >>infos.txt
-${GPP_WITH_CMAKE} --version &>>infos.txt
-
-
-echo "" >>infos.txt
-echo "lscpu:" >>infos.txt
-lscpu >>infos.txt
-
-echo "" >>infos.txt
-echo "lsb_release -a" >>infos.txt
-lsb_release -a &>>infos.txt
-
-echo "" >>infos.txt
-echo "cat /etc/*-release" >>infos.txt
-cat /etc/*-release &>>infos.txt
-
-
-echo "" >>infos.txt
-echo "cat /proc/cpuinfo:" >>infos.txt
-cat /proc/cpuinfo >>infos.txt
-
-
-tar zcvf ../pffft_bench_${GCCPATH}_${HOSTNAME}.tar.gz --exclude=CMakeCache.txt *.csv *.txt *.png
-echo "all benchmark results in pffft_bench_${GCCPATH}_${HOSTNAME}.tar.gz"
diff --git a/bench_conv.cpp b/bench_conv.cpp
new file mode 100644
index 0000000..a42d8ef
--- /dev/null
+++ b/bench_conv.cpp
@@ -0,0 +1,345 @@
+
+#include <math.h>
+#include <stdio.h>
+#include <string.h>
+#include <assert.h>
+
+#include <algorithm>
+#include <random>
+#include <cstdint>
+#include <complex>
+
+#include "papi_perf_counter.h"
+
+//#if defined(HAVE_MIPP) && !defined(NO_MIPP)
+#if defined(HAVE_MIPP)
+#include <mipp.h>
+
+#define MIPP_VECTOR  mipp::vector
+#else
+#define MIPP_VECTOR  std::vector
+#endif
+
+#include "pf_conv_dispatcher.h"
+#include "pf_conv.h"
+
+
+#define TEST_WITH_MIN_LEN     0
+
+
+MIPP_VECTOR<float> generate_rng_vec(int M, int N = -1, int seed_value = 1)
+{
+    MIPP_VECTOR<float> v(N < 0 ? M : N);
+    std::mt19937 g;
+    g.seed(seed_value);
+    constexpr float scale = 1.0F / (1.0F + float(INT_FAST32_MAX));
+    for (int k = 0; k < M; ++k)
+        v[k] = float(int_fast32_t(g())) * scale;
+    for (int k = M; k < N; ++k)
+        v[k] = 0.0F;
+    return v;
+}
+
+
+int bench_oop_core(
+        const conv_f_ptrs & conv_arch,
+        const float * signal, const int sz_signal,
+        const float * filter, const int sz_filter,
+        const int blockLen,
+        float * y
+        )
+{
+    conv_buffer_state state;
+    const auto conv_oop = conv_arch.fp_conv_float_oop;
+    int n_out_sum = 0;
+    state.offset = 0;
+    state.size = 0;
+    papi_perf_counter perf_counter(1);
+    for (int off = 0; off + blockLen <= sz_signal; off += blockLen)
+    {
+        state.size += blockLen;
+        int n_out = conv_oop(signal, &state, filter, sz_filter, y);
+        n_out_sum += n_out;
+    }
+    return n_out_sum;
+}
+
+int bench_inplace_core(
+        const conv_f_ptrs & conv_arch,
+        float * signal, const int sz_signal,
+        const float * filter, const int sz_filter,
+        const int blockLen
+        )
+{
+    conv_buffer_state state;
+    const auto conv_inplace = conv_arch.fp_conv_float_inplace;
+    int n_out_sum = 0;
+    state.offset = 0;
+    state.size = 0;
+    papi_perf_counter perf_counter(1);
+    for (int off = 0; off + blockLen <= sz_signal; off += blockLen)
+    {
+        state.size += blockLen;
+        int n_out = conv_inplace(signal, &state, filter, sz_filter);
+        n_out_sum += n_out;
+    }
+    return n_out_sum;
+}
+
+
+int bench_oop(
+        const conv_f_ptrs & conv_arch,
+        float * buffer,
+        const float * signal, const int sz_signal,
+        const float * filter, const int sz_filter,
+        const int blockLen,
+        float * y
+        )
+{
+    conv_buffer_state state;
+    const auto conv_oop = conv_arch.fp_conv_float_oop;
+    const auto move_rest = conv_arch.fp_conv_float_move_rest;
+    int n_out_sum = 0;
+    state.offset = 0;
+    state.size = 0;
+    papi_perf_counter perf_counter(1);
+    for (int off = 0; off + blockLen <= sz_signal; off += blockLen)
+    {
+        move_rest(buffer, &state);
+        //memcpy(buffer+state.size, &s[off], B * sizeof(s[0]));
+        std::copy(&signal[off], &signal[off+blockLen], buffer+state.size);
+        state.size += blockLen;
+        int n_out = conv_oop(buffer, &state, filter, sz_filter, &y[n_out_sum]);
+        n_out_sum += n_out;
+    }
+    return n_out_sum;
+}
+
+int bench_cx_real_oop(
+        const conv_f_ptrs & conv_arch,
+        complexf * buffer,
+        const float * signal_re, const int sz_signal_re,
+        const float * filter, const int sz_filter,
+        const int blockLen,
+        float * y_re
+        )
+{
+    conv_buffer_state state;
+    const auto conv_oop = conv_arch.fp_conv_cplx_float_oop;
+    const auto move_rest = conv_arch.fp_conv_cplx_move_rest;
+    // interpret buffer, signal and output vector y  as complex data
+    complexf * y = reinterpret_cast<complexf *>(y_re);
+    const complexf * signal = reinterpret_cast<const complexf *>(signal_re);
+    const int sz_signal = sz_signal_re / 2;
+    int n_out_sum = 0;
+    state.offset = 0;
+    state.size = 0;
+    papi_perf_counter perf_counter(1);
+    for (int off = 0; off + blockLen <= sz_signal; off += blockLen)
+    {
+        move_rest(buffer, &state);
+        //memcpy(buffer+state.size, &s[off], B * sizeof(s[0]));
+        std::copy(&signal[off], &signal[off+blockLen], &buffer[state.size]);
+        state.size += blockLen;
+        int n_out = conv_oop(buffer, &state, filter, sz_filter, &y[n_out_sum]);
+        n_out_sum += n_out;
+    }
+    return n_out_sum;
+}
+
+
+int main(int argc, char *argv[])
+{
+    // cli defaults:
+    // process up to 64 MSample (512 MByte) in blocks of 1 kSamples (=64 kByte) with filterLen 128
+    int arch = 0, N = 64 * 1024 * 1024;
+    int filterLen = 128, blockLen = 1024;
+    int seed_sig = 1, seed_filter = 2;
+    bool verbose = false, exitFromUsage = false, showUsage = (argc <= 1);
+
+    for (int i = 1; i < argc; ++i)
+    {
+        if (i+1 < argc && !strcmp(argv[i], "-a"))
+            arch = atoi(argv[++i]);
+        else if (i+1 < argc && !strcmp(argv[i], "-n"))
+            N = atoi(argv[++i]) * 1024 * 1024;
+        else if (i+1 < argc && !strcmp(argv[i], "-f"))
+            filterLen = atoi(argv[++i]);
+        else if (i+1 < argc && !strcmp(argv[i], "-b"))
+            blockLen = atoi(argv[++i]);
+        else if (i+1 < argc && !strcmp(argv[i], "-ss"))
+            seed_sig = atoi(argv[++i]);
+        else if (i+1 < argc && !strcmp(argv[i], "-sf"))
+            seed_filter = atoi(argv[++i]);
+        else if (!strcmp(argv[i], "-v"))
+            verbose = true;
+        else if (!strcmp(argv[i], "-h"))
+            showUsage = exitFromUsage = true;
+        else
+            fprintf(stderr, "warning: ignoring/skipping unknown option '%s'\n", argv[i]);
+    }
+
+    int num_arch = 0;
+    const ptr_to_conv_f_ptrs * conv_arch_ptrs = get_all_conv_arch_ptrs(&num_arch);
+
+    if (verbose)
+    {
+        fprintf(stderr, "num_arch is %d\n", num_arch);
+        for (int a = 0; a < num_arch; ++a)
+            if (conv_arch_ptrs[a])
+                fprintf(stderr, " arch %d is '%s'\n", a, conv_arch_ptrs[a]->id );
+            else
+                fprintf(stderr, " arch %d is nullptr !!!\n", a );
+        fprintf(stderr, "\n");
+    }
+
+    if ( arch < 0 || arch >= num_arch || !blockLen || !N || !filterLen || showUsage )
+    {
+        fprintf(stderr, "%s [-v] [-a <arch>] [-n <total # of MSamples> [-f <filter length>] [-b <blockLength in samples>]\n", argv[0]);
+        fprintf(stderr, "    [-ss <random seed for signal>] [-sf <random seed for filter coeffs>]\n");
+        fprintf(stderr, "arch is one of:");
+        for (int a = 0; a < num_arch; ++a)
+            if (conv_arch_ptrs[a])
+                fprintf(stderr, " %d for '%s'%s", a, conv_arch_ptrs[a]->id, (a < num_arch-1 ? ",":"") );
+        fprintf(stderr, "\n");
+        if ( exitFromUsage || !blockLen || !N || !filterLen || arch < 0 || arch >= num_arch )
+            return 0;
+    }
+
+    if (verbose)
+    {
+        #ifdef HAVE_PAPI
+        fprintf(stderr, "PAPI is available\n");
+        #else
+        fprintf(stderr, "PAPI is NOT available!\n");
+        #endif
+    }
+    #if !defined(HAVE_MIPP)
+    fprintf(stderr, "MIPP is NOT available!\n");
+    #endif
+
+    //int float_simd_size[num_arch];
+    int max_simd_size = -1;
+    for (int a = 0; a < num_arch; ++a)
+    {
+        if (conv_arch_ptrs[a])
+        {
+            const int sz = conv_arch_ptrs[a]->fp_conv_float_simd_size();
+            //float_simd_size[a] = sz;
+            if (max_simd_size < sz)
+                max_simd_size = sz;
+            if (verbose)
+                fprintf(stderr, "float simd size for '%s': %d\n", conv_arch_ptrs[a]->id, sz);
+        }
+        //else
+        //    float_simd_size[a] = 0;
+    }
+    //const int max_simd_size = *std::max_element( &float_simd_size[0], &float_simd_size[num_arch] );
+    if (verbose)
+        fprintf(stderr, "max float simd size: %d\n", max_simd_size);
+
+#if TEST_WITH_MIN_LEN
+    filterLen = 2;
+#endif
+
+    // round up filter length
+    filterLen = max_simd_size * ( ( filterLen + max_simd_size -1 ) / max_simd_size );
+
+#if TEST_WITH_MIN_LEN
+    blockLen = 1;
+    N = 2 * (3 + filterLen);    // produce 3+1 samples
+#endif
+
+    if (!conv_arch_ptrs[arch])
+    {
+        fprintf(stderr, "Error: architecture %d is NOT available!\n", arch);
+        return 1;
+    }
+    const conv_f_ptrs & conv_arch =  *conv_arch_ptrs[arch];
+    if (verbose)
+        fprintf(stderr, "arch is using mipp: %d\n", conv_arch.using_mipp);
+
+    fprintf(stderr, "processing N = %d MSamples with block length of %d samples with filter length %d taps on '%s'\n",
+        N / (1024 * 1024), blockLen, filterLen, conv_arch.id );
+
+    MIPP_VECTOR<float> s = generate_rng_vec(N + 1, N + 1, seed_sig);
+    MIPP_VECTOR<float> y(N + 1, 0.0F);
+    MIPP_VECTOR<float> filter = generate_rng_vec(filterLen, filterLen, seed_filter);
+    MIPP_VECTOR<float> buffer(blockLen + filterLen + 1, 0.0F);
+    MIPP_VECTOR<complexf> buffer_cx(blockLen + filterLen + 1);
+
+#if 1 && TEST_WITH_MIN_LEN
+    for (int k = 0; k < N; ++k)
+        s[k] = (k+1);
+    for (int k = 0; k < filterLen; ++k)
+        filter[k] = (k+1);
+#endif
+
+    s[N] = 123.0F;
+    y[N] = 321.0F;
+    buffer[blockLen + filterLen] = 789.0F;
+    buffer_cx[blockLen + filterLen].i = 987.0F;
+
+    fprintf(stderr, "\nrunning out-of-place convolution core for '%s':\n", conv_arch.id);
+    int n_oop_out = bench_oop_core(conv_arch, s.data(), N, filter.data(), filterLen, blockLen, y.data());
+    fprintf(stderr, "oop produced %d output samples\n", n_oop_out);
+#if TEST_WITH_MIN_LEN
+    for (int k = 0; k < n_oop_out; ++k )
+        fprintf(stderr, "y[%2d] = %g\n", k, y[k]);
+    fprintf(stderr, "\n");
+#endif
+
+    fprintf(stderr, "\nrunning out-of-place convolution for '%s':\n", conv_arch.id);
+    n_oop_out = bench_oop(conv_arch, buffer.data(), s.data(), N, filter.data(), filterLen, blockLen, y.data());
+    fprintf(stderr, "oop produced %d output samples\n", n_oop_out);
+    assert(s[N] == 123.0F);
+    assert(y[N] == 321.0F);
+    assert(buffer[blockLen + filterLen] == 789.0F);
+    assert(buffer_cx[blockLen + filterLen].i == 987.0F);
+#if TEST_WITH_MIN_LEN
+    for (int k = 0; k < n_oop_out; ++k )
+        fprintf(stderr, "y[%2d] = %g\n", k, y[k]);
+    fprintf(stderr, "\n");
+#endif
+
+    fprintf(stderr, "\nrunning out-of-place complex/real convolution for '%s':\n", conv_arch.id);
+    n_oop_out = bench_cx_real_oop(conv_arch, buffer_cx.data(), s.data(), N, filter.data(), filterLen, blockLen, y.data());
+    fprintf(stderr, "oop produced %d output samples\n", n_oop_out);
+    assert(s[N] == 123.0F);
+    assert(y[N] == 321.0F);
+    assert(buffer[blockLen + filterLen] == 789.0F);
+    assert(buffer_cx[blockLen + filterLen].i == 987.0F);
+#if TEST_WITH_MIN_LEN
+    fprintf(stderr, "complex output (%d complex samples):\n", n_oop_out);
+    for (int k = 0; k < n_oop_out; ++k )
+        fprintf(stderr, "y[%2d] = %g  %+g * i\n", k, y[2*k], y[2*k+1]);
+    fprintf(stderr, "\n");
+
+    const std::complex<float> * sc = reinterpret_cast< std::complex<float>* >( s.data() );
+    const int Nc = N /2;
+    fprintf(stderr, "reference with std::complex<float>:\n");
+    for (int off = 0; off +filterLen <= Nc; ++off )
+    {
+        std::complex<float> sum(0.0F, 0.0F);
+        for (int k=0; k < filterLen; ++k)
+            sum += sc[off+k] * filter[k];
+        fprintf(stderr, "yv[%2d] = %g  %+g * i\n", off, sum.real(), sum.imag() );
+    }
+#endif
+
+    fprintf(stderr, "\nrunning inplace convolution core for '%s':\n", conv_arch.id);
+    int n_inp_out = bench_inplace_core(conv_arch, s.data(), N, filter.data(), filterLen, blockLen);
+    fprintf(stderr, "inp produced %d output samples\n", n_inp_out);
+    assert(s[N] == 123.0F);
+    assert(y[N] == 321.0F);
+    assert(buffer[blockLen + filterLen] == 789.0F);
+    assert(buffer_cx[blockLen + filterLen].i == 987.0F);
+#if TEST_WITH_MIN_LEN
+    for (int k = 0; k < n_inp_out; ++k )
+        fprintf(stderr, "y[%2d] = %g\n", k, s[k]);
+    fprintf(stderr, "\n");
+#endif
+
+    fprintf(stderr, "\n");
+    return 0;
+}
diff --git a/bench_mixers.c b/bench_mixers.cpp
similarity index 66%
rename from bench_mixers.c
rename to bench_mixers.cpp
index 5b22b3f..c08a51a 100644
--- a/bench_mixers.c
+++ b/bench_mixers.cpp
@@ -14,13 +14,23 @@
 #include <assert.h>
 #include <string.h>
 
+#include "papi_perf_counter.h"
+
+#if defined(__linux__)
 #define HAVE_SYS_TIMES
+#endif
 
 #ifdef HAVE_SYS_TIMES
 #  include <sys/times.h>
 #  include <unistd.h>
 #endif
 
+#ifdef WIN32
+#define WIN32_LEAN_AND_MEAN
+#define VC_EXTRALEAN
+#include <windows.h>
+#endif
+
 #define BENCH_REF_TRIG_FUNC       1
 #define BENCH_OUT_OF_PLACE_ALGOS  0
 #define BENCH_INPLACE_ALGOS       1
@@ -78,7 +88,7 @@
         return ((double)t.tms_utime) / ttclk;
     }
 
-#elif 0
+#elif defined(WIN32)
     // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
     double uclock_sec(int find_start)
     {
@@ -126,10 +136,35 @@ void save(complexf * d, int B, int N, const char * fn)
 }
 
 
-double bench_shift_math_cc(int B, int N) {
-    double t0, t1, tstop, T, nI;
-    int iter, off;
+double bench_core_shift_math_cc(
+        const int B, const int N, const bool ignore_time,
+        const complexf *input,
+        complexf *output,
+        int &iters_out, int &off_out
+        )
+{
+    const double t0 = uclock_sec(1);
+    const double tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
+    double t1;
     float phase = 0.0F;
+    int off = 0, iter = 0;
+    papi_perf_counter perf_counter(1);
+
+    do {
+        // work
+        phase = shift_math_cc(input+off, output+off, B, -0.0009F, phase);
+        off += B;
+        ++iter;
+        t1 = uclock_sec(0);
+    } while ( off + B < N && (ignore_time || t1 < tstop) );
+
+    iters_out = iter;
+    off_out = off;
+    return t1 - t0;
+}
+
+double bench_shift_math_cc(const int B, const int N, const bool ignore_time) {
+    int iter, off;
     complexf *input = (complexf *)malloc(N * sizeof(complexf));
     complexf *output = (complexf *)malloc(N * sizeof(complexf));
     shift_recursive_osc_t gen_state;
@@ -138,25 +173,14 @@ double bench_shift_math_cc(int B, int N) {
     shift_recursive_osc_init(0.001F, 0.0F, &gen_conf, &gen_state);
     gen_recursive_osc_c(input, N, &gen_conf, &gen_state);
 
-    iter = 0;
-    off = 0;
-    t0 = uclock_sec(1);
-    tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
-    do {
-        // work
-        phase = shift_math_cc(input+off, output+off, B, -0.0009F, phase);
-        off += B;
-        ++iter;
-        t1 = uclock_sec(0);
-    } while ( t1 < tstop && off + B < N );
+    double T = bench_core_shift_math_cc(B, N, ignore_time, input, output,  iter, off);
 
     save(output, B, off, BENCH_FILE_SHIFT_MATH_CC);
 
     free(input);
     free(output);
-    T = ( t1 - t0 );  /* duration per fft() */
     printf("processed %f Msamples in %f ms\n", off * 1E-6, T*1E3);
-    nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
+    double nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
     return (nI / T);    /* normalized iterations per second */
 }
 
@@ -235,37 +259,54 @@ double bench_shift_addfast(int B, int N) {
     return (nI / T);    /* normalized iterations per second */
 }
 
-double bench_shift_addfast_inp(int B, int N) {
-    double t0, t1, tstop, T, nI;
-    int iter, off;
+
+double bench_core_shift_addfast_inplace(
+        const int B, const int N, const bool ignore_time,
+        complexf *data,
+        shift_addfast_data_t &state,
+        int &iters_out, int &off_out
+        )
+{
+    const double t0 = uclock_sec(1);
+    const double tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
+    double t1;
     float phase = 0.0F;
+    int off = 0, iter = 0;
+    papi_perf_counter perf_counter(1);
+
+    do {
+        // work
+        phase = shift_addfast_inp_c(data+off, B, &state, phase);
+        off += B;
+        ++iter;
+        t1 = uclock_sec(0);
+    } while ( off + B < N && (ignore_time || t1 < tstop) );
+
+    iters_out = iter;
+    off_out = off;
+    return t1 - t0;
+}
+
+double bench_shift_addfast_inp(int B, int N, const bool ignore_time) {
     complexf *input = (complexf *)malloc(N * sizeof(complexf));
     shift_recursive_osc_t gen_state;
     shift_recursive_osc_conf_t gen_conf;
     shift_addfast_data_t state = shift_addfast_init(-0.0009F);
+    int iter, off;
 
     shift_recursive_osc_init(0.001F, 0.0F, &gen_conf, &gen_state);
     gen_recursive_osc_c(input, N, &gen_conf, &gen_state);
 
-    iter = 0;
-    off = 0;
-    t0 = uclock_sec(1);
-    tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
-    do {
-        // work
-        phase = shift_addfast_inp_c(input+off, B, &state, phase);
-
-        off += B;
-        ++iter;
-        t1 = uclock_sec(0);
-    } while ( t1 < tstop && off + B < N );
+    double T = bench_core_shift_addfast_inplace(
+                B, N, ignore_time, input, state,
+                iter, off
+                );
 
     save(input, B, off, BENCH_FILE_ADD_FAST_INP_C);
 
     free(input);
-    T = ( t1 - t0 );  /* duration per fft() */
     printf("processed %f Msamples in %f ms\n", off * 1E-6, T*1E3);
-    nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
+    double nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
     return (nI / T);    /* normalized iterations per second */
 }
 
@@ -305,37 +346,55 @@ double bench_shift_unroll_oop(int B, int N) {
     return (nI / T);    /* normalized iterations per second */
 }
 
-double bench_shift_unroll_inp(int B, int N) {
-    double t0, t1, tstop, T, nI;
-    int iter, off;
+
+double bench_core_shift_unroll_inplace(
+        const int B, const int N, const bool ignore_time,
+        complexf *data,
+        shift_unroll_data_t &state,
+        int &iters_out, int &off_out
+        )
+{
+    const double t0 = uclock_sec(1);
+    const double tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
+    double t1;
     float phase = 0.0F;
+    int off = 0, iter = 0;
+    papi_perf_counter perf_counter(1);
+
+    do {
+        // work
+        phase = shift_unroll_inp_c(data+off, B, &state, phase);
+        off += B;
+        ++iter;
+        t1 = uclock_sec(0);
+    } while ( off + B < N && (ignore_time || t1 < tstop) );
+
+    iters_out = iter;
+    off_out = off;
+    return t1 - t0;
+}
+
+double bench_shift_unroll_inp(const int B, const int N, const bool ignore_time) {
     complexf *input = (complexf *)malloc(N * sizeof(complexf));
     shift_recursive_osc_t gen_state;
     shift_recursive_osc_conf_t gen_conf;
     shift_unroll_data_t state = shift_unroll_init(-0.0009F, B);
+    int iter, off;
 
     shift_recursive_osc_init(0.001F, 0.0F, &gen_conf, &gen_state);
     gen_recursive_osc_c(input, N, &gen_conf, &gen_state);
 
-    iter = 0;
-    off = 0;
-    t0 = uclock_sec(1);
-    tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
-    do {
-        // work
-        phase = shift_unroll_inp_c(input+off, B, &state, phase);
-
-        off += B;
-        ++iter;
-        t1 = uclock_sec(0);
-    } while ( t1 < tstop && off + B < N );
+    double T = bench_core_shift_unroll_inplace(
+                B, N, ignore_time, input, state,
+                iter, off
+                );
 
     save(input, B, off, BENCH_FILE_UNROLL_INP_C);
 
     free(input);
-    T = ( t1 - t0 );  /* duration per fft() */
+    shift_unroll_deinit(&state);
     printf("processed %f Msamples in %f ms\n", off * 1E-6, T*1E3);
-    nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
+    double nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
     return (nI / T);    /* normalized iterations per second */
 }
 
@@ -376,82 +435,141 @@ double bench_shift_limited_unroll_oop(int B, int N) {
 }
 
 
-double bench_shift_limited_unroll_inp(int B, int N) {
-    double t0, t1, tstop, T, nI;
-    int iter, off;
+double bench_core_shift_limited_unroll_inplace(
+        const int B, const int N, const bool ignore_time,
+        complexf *data,
+        shift_limited_unroll_data_t &state,
+        int &iters_out, int &off_out
+        )
+{
+    const double t0 = uclock_sec(1);
+    const double tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
+    double t1;
+    int off = 0, iter = 0;
+    papi_perf_counter perf_counter(1);
+
+    do {
+        // work
+        shift_limited_unroll_inp_c(data+off, B, &state);
+        off += B;
+        ++iter;
+        t1 = uclock_sec(0);
+    } while ( off + B < N && (ignore_time || t1 < tstop) );
+
+    iters_out = iter;
+    off_out = off;
+    return t1 - t0;
+}
+
+double bench_shift_limited_unroll_inp(const int B, const int N, const bool ignore_time) {
     complexf *input = (complexf *)malloc(N * sizeof(complexf));
     shift_recursive_osc_t gen_state;
     shift_recursive_osc_conf_t gen_conf;
     shift_limited_unroll_data_t state = shift_limited_unroll_init(-0.0009F);
+    int iter, off;
 
     shift_recursive_osc_init(0.001F, 0.0F, &gen_conf, &gen_state);
     gen_recursive_osc_c(input, N, &gen_conf, &gen_state);
 
-    iter = 0;
-    off = 0;
-    t0 = uclock_sec(1);
-    tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
-    do {
-        // work
-        shift_limited_unroll_inp_c(input+off, B, &state);
-
-        off += B;
-        ++iter;
-        t1 = uclock_sec(0);
-    } while ( t1 < tstop && off + B < N );
+    double T = bench_core_shift_limited_unroll_inplace(
+                B, N, ignore_time, input, state,
+                iter, off
+                );
 
     save(input, B, off, BENCH_FILE_LTD_UNROLL_INP_C);
 
     free(input);
-    T = ( t1 - t0 );  /* duration per fft() */
     printf("processed %f Msamples in %f ms\n", off * 1E-6, T*1E3);
-    nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
+    double nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
     return (nI / T);    /* normalized iterations per second */
 }
 
 
-double bench_shift_limited_unroll_A_sse_inp(int B, int N) {
-    double t0, t1, tstop, T, nI;
-    int iter, off;
+double bench_core_shift_limited_unroll_A_sse_inplace(
+        const int B, const int N, const bool ignore_time,
+        complexf *data,
+        shift_limited_unroll_A_sse_data_t &state,
+        int &iters_out, int &off_out
+        )
+{
+    const double t0 = uclock_sec(1);
+    const double tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
+    double t1;
+    int off = 0, iter = 0;
+    papi_perf_counter perf_counter(1);
+
+    do {
+        // work
+        shift_limited_unroll_A_sse_inp_c(data+off, B, &state);
+        off += B;
+        ++iter;
+        t1 = uclock_sec(0);
+    } while ( off + B < N && (ignore_time || t1 < tstop) );
+
+    iters_out = iter;
+    off_out = off;
+    return t1 - t0;
+}
+
+double bench_shift_limited_unroll_A_sse_inp(const int B, const int N, const bool ignore_time) {
     complexf *input = (complexf *)malloc(N * sizeof(complexf));
     shift_recursive_osc_t gen_state;
     shift_recursive_osc_conf_t gen_conf;
-    shift_limited_unroll_A_sse_data_t *state = malloc(sizeof(shift_limited_unroll_A_sse_data_t));
+    shift_limited_unroll_A_sse_data_t *state = (shift_limited_unroll_A_sse_data_t*)malloc(sizeof(shift_limited_unroll_A_sse_data_t));
+    int iter, off;
 
     *state = shift_limited_unroll_A_sse_init(-0.0009F, 0.0F);
 
     shift_recursive_osc_init(0.001F, 0.0F, &gen_conf, &gen_state);
     gen_recursive_osc_c(input, N, &gen_conf, &gen_state);
 
-    iter = 0;
-    off = 0;
-    t0 = uclock_sec(1);
-    tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
+    double T = bench_core_shift_limited_unroll_A_sse_inplace(
+                B, N, ignore_time, input, *state,
+                iter, off
+                );
+
+    save(input, B, off, BENCH_FILE_LTD_UNROLL_A_SSE_INP_C);
+
+    free(input);
+    free(state);
+    printf("processed %f Msamples in %f ms\n", off * 1E-6, T*1E3);
+    double nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
+    return (nI / T);    /* normalized iterations per second */
+}
+
+
+double bench_core_shift_limited_unroll_B_sse_inplace(
+        const int B, const int N, const bool ignore_time,
+        complexf *data,
+        shift_limited_unroll_B_sse_data_t &state,
+        int &iters_out, int &off_out
+        )
+{
+    const double t0 = uclock_sec(1);
+    const double tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
+    double t1;
+    int off = 0, iter = 0;
+    papi_perf_counter perf_counter(1);
+
     do {
         // work
-        shift_limited_unroll_A_sse_inp_c(input+off, B, state);
-
+        shift_limited_unroll_B_sse_inp_c(data+off, B, &state);
         off += B;
         ++iter;
         t1 = uclock_sec(0);
-    } while ( t1 < tstop && off + B < N );
+    } while ( off + B < N && (ignore_time || t1 < tstop) );
 
-    save(input, B, off, BENCH_FILE_LTD_UNROLL_A_SSE_INP_C);
-    
-    free(input);
-    T = ( t1 - t0 );  /* duration per fft() */
-    printf("processed %f Msamples in %f ms\n", off * 1E-6, T*1E3);
-    nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
-    return (nI / T);    /* normalized iterations per second */
+    iters_out = iter;
+    off_out = off;
+    return t1 - t0;
 }
 
-double bench_shift_limited_unroll_B_sse_inp(int B, int N) {
-    double t0, t1, tstop, T, nI;
-    int iter, off;
+double bench_shift_limited_unroll_B_sse_inp(const int B, const int N, const bool ignore_time) {
     complexf *input = (complexf *)malloc(N * sizeof(complexf));
     shift_recursive_osc_t gen_state;
     shift_recursive_osc_conf_t gen_conf;
-    shift_limited_unroll_B_sse_data_t *state = malloc(sizeof(shift_limited_unroll_B_sse_data_t));
+    shift_limited_unroll_B_sse_data_t *state = (shift_limited_unroll_B_sse_data_t*)malloc(sizeof(shift_limited_unroll_B_sse_data_t));
+    int iter, off;
 
     *state = shift_limited_unroll_B_sse_init(-0.0009F, 0.0F);
 
@@ -459,60 +577,70 @@ double bench_shift_limited_unroll_B_sse_inp(int B, int N) {
     //shift_recursive_osc_init(0.0F, 0.0F, &gen_conf, &gen_state);
     gen_recursive_osc_c(input, N, &gen_conf, &gen_state);
 
-    iter = 0;
-    off = 0;
-    t0 = uclock_sec(1);
-    tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
-    do {
-        // work
-        shift_limited_unroll_B_sse_inp_c(input+off, B, state);
-
-        off += B;
-        ++iter;
-        t1 = uclock_sec(0);
-    } while ( t1 < tstop && off + B < N );
+    double T = bench_core_shift_limited_unroll_B_sse_inplace(
+                B, N, ignore_time, input, *state,
+                iter, off
+                );
 
     save(input, B, off, BENCH_FILE_LTD_UNROLL_B_SSE_INP_C);
     
     free(input);
-    T = ( t1 - t0 );  /* duration per fft() */
+    free(state);
     printf("processed %f Msamples in %f ms\n", off * 1E-6, T*1E3);
-    nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
+    double nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
     return (nI / T);    /* normalized iterations per second */
 }
 
-double bench_shift_limited_unroll_C_sse_inp(int B, int N) {
-    double t0, t1, tstop, T, nI;
-    int iter, off;
+
+double bench_core_shift_limited_unroll_C_sse_inplace(
+        const int B, const int N, const bool ignore_time,
+        complexf *data,
+        shift_limited_unroll_C_sse_data_t &state,
+        int &iters_out, int &off_out
+        )
+{
+    const double t0 = uclock_sec(1);
+    const double tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
+    double t1;
+    int off = 0, iter = 0;
+    papi_perf_counter perf_counter(1);
+
+    do {
+        // work
+        shift_limited_unroll_C_sse_inp_c(data+off, B, &state);
+        off += B;
+        ++iter;
+        t1 = uclock_sec(0);
+    } while ( off + B < N && (ignore_time || t1 < tstop) );
+
+    iters_out = iter;
+    off_out = off;
+    return t1 - t0;
+}
+
+double bench_shift_limited_unroll_C_sse_inp(const int B, const int N, const bool ignore_time) {
     complexf *input = (complexf *)malloc(N * sizeof(complexf));
     shift_recursive_osc_t gen_state;
     shift_recursive_osc_conf_t gen_conf;
-    shift_limited_unroll_C_sse_data_t *state = malloc(sizeof(shift_limited_unroll_C_sse_data_t));
+    shift_limited_unroll_C_sse_data_t *state = (shift_limited_unroll_C_sse_data_t*)malloc(sizeof(shift_limited_unroll_C_sse_data_t));
+    int iter, off;
 
     *state = shift_limited_unroll_C_sse_init(-0.0009F, 0.0F);
 
     shift_recursive_osc_init(0.001F, 0.0F, &gen_conf, &gen_state);
     gen_recursive_osc_c(input, N, &gen_conf, &gen_state);
 
-    iter = 0;
-    off = 0;
-    t0 = uclock_sec(1);
-    tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
-    do {
-        // work
-        shift_limited_unroll_C_sse_inp_c(input+off, B, state);
-
-        off += B;
-        ++iter;
-        t1 = uclock_sec(0);
-    } while ( t1 < tstop && off + B < N );
+    double T = bench_core_shift_limited_unroll_C_sse_inplace(
+                B, N, ignore_time, input, *state,
+                iter, off
+                );
 
     save(input, B, off, BENCH_FILE_LTD_UNROLL_C_SSE_INP_C);
-    
+
     free(input);
-    T = ( t1 - t0 );  /* duration per fft() */
+    free(state);
     printf("processed %f Msamples in %f ms\n", off * 1E-6, T*1E3);
-    nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
+    double nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
     return (nI / T);    /* normalized iterations per second */
 }
 
@@ -520,7 +648,6 @@ double bench_shift_limited_unroll_C_sse_inp(int B, int N) {
 double bench_shift_rec_osc_cc_oop(int B, int N) {
     double t0, t1, tstop, T, nI;
     int iter, off;
-    float phase = 0.0F;
     complexf *input = (complexf *)malloc(N * sizeof(complexf));
     complexf *output = (complexf *)malloc(N * sizeof(complexf));
     shift_recursive_osc_t gen_state, shift_state;
@@ -555,74 +682,105 @@ double bench_shift_rec_osc_cc_oop(int B, int N) {
 }
 
 
-double bench_shift_rec_osc_cc_inp(int B, int N) {
-    double t0, t1, tstop, T, nI;
-    int iter, off;
-    float phase = 0.0F;
+double bench_core_shift_rec_osc_cc_inplace(
+        const int B, const int N, const bool ignore_time,
+        complexf *data,
+        shift_recursive_osc_conf_t &conf, shift_recursive_osc_t &state,
+        int &iters_out, int &off_out
+        )
+{
+    const double t0 = uclock_sec(1);
+    const double tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
+    double t1;
+    int off = 0, iter = 0;
+    papi_perf_counter perf_counter(1);
+
+    do {
+        // work
+        shift_recursive_osc_inp_c(data+off, B, &conf, &state);
+        off += B;
+        ++iter;
+        t1 = uclock_sec(0);
+    } while ( off + B < N && (ignore_time || t1 < tstop) );
+
+    iters_out = iter;
+    off_out = off;
+    return t1 - t0;
+}
+
+double bench_shift_rec_osc_cc_inp(const int B, const int N, const bool ignore_time) {
     complexf *input = (complexf *)malloc(N * sizeof(complexf));
     shift_recursive_osc_t gen_state, shift_state;
     shift_recursive_osc_conf_t gen_conf, shift_conf;
+    int iter, off;
 
     shift_recursive_osc_init(0.001F, 0.0F, &gen_conf, &gen_state);
     gen_recursive_osc_c(input, N, &gen_conf, &gen_state);
     shift_recursive_osc_init(-0.0009F, 0.0F, &shift_conf, &shift_state);
 
-    iter = 0;
-    off = 0;
-    t0 = uclock_sec(1);
-    tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
-    do {
-        // work
-        shift_recursive_osc_inp_c(input+off, B, &shift_conf, &shift_state);
-
-        off += B;
-        ++iter;
-        t1 = uclock_sec(0);
-    } while ( t1 < tstop && off + B < N );
+    double T = bench_core_shift_rec_osc_cc_inplace(
+                B, N, ignore_time, input, shift_conf, shift_state,
+                iter, off
+                );
 
     save(input, B, off, BENCH_FILE_REC_OSC_INP_C);
     free(input);
-    T = ( t1 - t0 );  /* duration per fft() */
     printf("processed %f Msamples in %f ms\n", off * 1E-6, T*1E3);
-    nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
+    double nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
     return (nI / T);    /* normalized iterations per second */
 }
 
 
-double bench_shift_rec_osc_sse_c_inp(int B, int N) {
-    double t0, t1, tstop, T, nI;
-    int iter, off;
-    float phase = 0.0F;
+double bench_core_shift_rec_osc_sse_c_inplace(
+        const int B, const int N, const bool ignore_time,
+        complexf *data,
+        shift_recursive_osc_sse_conf_t &conf, shift_recursive_osc_sse_t &state,
+        int &iters_out, int &off_out
+        )
+{
+    const double t0 = uclock_sec(1);
+    const double tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
+    double t1;
+    int off = 0, iter = 0;
+    papi_perf_counter perf_counter(1);
+
+    do {
+        // work
+        shift_recursive_osc_sse_inp_c(data+off, B, &conf, &state);
+        off += B;
+        ++iter;
+        t1 = uclock_sec(0);
+    } while ( off + B < N && (ignore_time || t1 < tstop) );
+
+    iters_out = iter;
+    off_out = off;
+    return t1 - t0;
+}
+
+double bench_shift_rec_osc_sse_c_inp(const int B, const int N, const bool ignore_time) {
     complexf *input = (complexf *)malloc(N * sizeof(complexf));
     shift_recursive_osc_t gen_state;
     shift_recursive_osc_conf_t gen_conf;
 
-    shift_recursive_osc_sse_t *shift_state = malloc(sizeof(shift_recursive_osc_sse_t));
+    shift_recursive_osc_sse_t *shift_state = (shift_recursive_osc_sse_t*)malloc(sizeof(shift_recursive_osc_sse_t));
     shift_recursive_osc_sse_conf_t shift_conf;
+    int iter, off;
 
     shift_recursive_osc_init(0.001F, 0.0F, &gen_conf, &gen_state);
     gen_recursive_osc_c(input, N, &gen_conf, &gen_state);
 
     shift_recursive_osc_sse_init(-0.0009F, 0.0F, &shift_conf, shift_state);
 
-    iter = 0;
-    off = 0;
-    t0 = uclock_sec(1);
-    tstop = t0 + 0.5;  /* benchmark duration: 500 ms */
-    do {
-        // work
-        shift_recursive_osc_sse_inp_c(input+off, B, &shift_conf, shift_state);
-
-        off += B;
-        ++iter;
-        t1 = uclock_sec(0);
-    } while ( t1 < tstop && off + B < N );
+    double T = bench_core_shift_rec_osc_sse_c_inplace(
+                B, N, ignore_time, input, shift_conf, *shift_state,
+                iter, off
+                );
 
     save(input, B, off, BENCH_FILE_REC_OSC_SSE_INP_C);
     free(input);
-    T = ( t1 - t0 );  /* duration per fft() */
+    free(shift_state);
     printf("processed %f Msamples in %f ms\n", off * 1E-6, T*1E3);
-    nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
+    double nI = ((double)iter) * B;  /* number of iterations "normalized" to O(N) = N */
     return (nI / T);    /* normalized iterations per second */
 }
 
@@ -636,6 +794,7 @@ int main(int argc, char **argv)
     int B = 8 * 1024;
     int N = 64 * 1024 * 1024;
     int showUsage = 0;
+    bool ignore_time = true;
 
     if (argc == 1)
         showUsage = 1;
@@ -652,13 +811,13 @@ int main(int argc, char **argv)
             return 0;
     }
 
-    fprintf(stderr, "processing up to N = %d MSamples with blocke length of %d samples\n",
+    fprintf(stderr, "processing up to N = %d MSamples with block length of %d samples\n",
         N / (1024 * 1024), B );
 
 
 #if BENCH_REF_TRIG_FUNC
     printf("\nstarting bench of shift_math_cc (out-of-place) with trig functions ..\n");
-    rt = bench_shift_math_cc(B, N);
+    rt = bench_shift_math_cc(B, N, ignore_time);
     printf("  %f MSamples/sec\n\n", rt * 1E-6);
 #endif
 
@@ -687,40 +846,40 @@ int main(int argc, char **argv)
 #if BENCH_INPLACE_ALGOS
 
     printf("starting bench of shift_addfast_inp_c in-place ..\n");
-    rt = bench_shift_addfast_inp(B, N);
+    rt = bench_shift_addfast_inp(B, N, ignore_time);
     printf("  %f MSamples/sec\n\n", rt * 1E-6);
 
     printf("starting bench of shift_unroll_inp_c in-place ..\n");
-    rt = bench_shift_unroll_inp(B, N);
+    rt = bench_shift_unroll_inp(B, N, ignore_time);
     printf("  %f MSamples/sec\n\n", rt * 1E-6);
 
     printf("starting bench of shift_limited_unroll_inp_c in-place ..\n");
-    rt = bench_shift_limited_unroll_inp(B, N);
+    rt = bench_shift_limited_unroll_inp(B, N, ignore_time);
     printf("  %f MSamples/sec\n\n", rt * 1E-6);
 
     if ( have_sse_shift_mixer_impl() )
     {
         printf("starting bench of shift_limited_unroll_A_sse_inp_c in-place ..\n");
-        rt = bench_shift_limited_unroll_A_sse_inp(B, N);
+        rt = bench_shift_limited_unroll_A_sse_inp(B, N, ignore_time);
         printf("  %f MSamples/sec\n\n", rt * 1E-6);
 
         printf("starting bench of shift_limited_unroll_B_sse_inp_c in-place ..\n");
-        rt = bench_shift_limited_unroll_B_sse_inp(B, N);
+        rt = bench_shift_limited_unroll_B_sse_inp(B, N, ignore_time);
         printf("  %f MSamples/sec\n\n", rt * 1E-6);
 
         printf("starting bench of shift_limited_unroll_C_sse_inp_c in-place ..\n");
-        rt = bench_shift_limited_unroll_C_sse_inp(B, N);
+        rt = bench_shift_limited_unroll_C_sse_inp(B, N, ignore_time);
         printf("  %f MSamples/sec\n\n", rt * 1E-6);
     }
 
     printf("starting bench of shift_recursive_osc_cc in-place ..\n");
-    rt = bench_shift_rec_osc_cc_inp(B, N);
+    rt = bench_shift_rec_osc_cc_inp(B, N, ignore_time);
     printf("  %f MSamples/sec\n\n", rt * 1E-6);
 
     if ( have_sse_shift_mixer_impl() )
     {
         printf("starting bench of shift_recursive_osc_sse_c in-place ..\n");
-        rt = bench_shift_rec_osc_sse_c_inp(B, N);
+        rt = bench_shift_rec_osc_sse_c_inp(B, N, ignore_time);
         printf("  %f MSamples/sec\n\n", rt * 1E-6);
     }
 #endif
diff --git a/bench_pffft.c b/bench_pffft.c
index e3a9e9e..7abb48d 100644
--- a/bench_pffft.c
+++ b/bench_pffft.c
@@ -1,8 +1,8 @@
 /*
   Copyright (c) 2013 Julien Pommier.
-  Copyright (c) 2019  Hayati Ayguen ( h_ayguen@web.de )
+  Copyright (c) 2019 Hayati Ayguen ( h_ayguen@web.de )
 
-  Small test & bench for PFFFT, comparing its performance with the scalar FFTPACK, FFTW, and Apple vDSP
+  Small test & bench for PFFFT, comparing its performance with the scalar FFTPACK, FFTW, Intel MKL, and Apple vDSP
 
   How to build: 
 
@@ -17,6 +17,9 @@
 
   as alternative: replace clang by gcc.
 
+  on macos, with fftw3 and Intel MKL:
+  clang -o test_pffft -I /opt/intel/mkl/include -DHAVE_FFTW -DHAVE_VECLIB -DHAVE_MKL  -O3 -Wall -W pffft.c test_pffft.c fftpack.c -L/usr/local/lib -I/usr/local/include/ -lfftw3f -framework Accelerate /opt/intel/mkl/lib/libmkl_{intel_lp64,sequential,core}.a
+
   on windows, with visual c++:
   cl /Ox -D_USE_MATH_DEFINES /arch:SSE test_pffft.c pffft.c fftpack.c
   
@@ -46,9 +49,11 @@ typedef PFFFTD_Setup PFFFT_SETUP;
 #define PFFFT_FUNC(F)  CONCAT_TOKENS(pffftd_, F)
 #endif
 
-#ifdef PFFFT_ENABLE_FLOAT
-
+#ifdef HAVE_FFTPACK
 #include "fftpack.h"
+#endif
+
+#ifdef PFFFT_ENABLE_FLOAT
 
 #ifdef HAVE_GREEN_FFTS
 #include "fftext.h"
@@ -111,12 +116,16 @@ typedef fftw_complex FFTW_COMPLEX;
 
 #endif /* HAVE_FFTW */
 
+#ifdef HAVE_MKL
+#  include <mkl/mkl_dfti.h>
+#endif
+
 #ifndef M_LN2
   #define M_LN2   0.69314718055994530942  /* log_e 2 */
 #endif
 
 
-#define NUM_FFT_ALGOS  9
+#define NUM_FFT_ALGOS  10
 enum {
   ALGO_FFTPACK = 0,
   ALGO_VECLIB,
@@ -125,8 +134,9 @@ enum {
   ALGO_GREEN,
   ALGO_KISS,
   ALGO_POCKET,
-  ALGO_PFFFT_U, /* = 7 */
-  ALGO_PFFFT_O  /* = 8 */
+  ALGO_MKL,
+  ALGO_PFFFT_U, /* = 8 */
+  ALGO_PFFFT_O  /* = 9 */
 };
 
 #define NUM_TYPES      7
@@ -149,13 +159,14 @@ const char * algoName[NUM_FFT_ALGOS] = {
   "Green        ",
   "Kiss         ",
   "Pocket       ",
+  "Intel MKL    ",
   "PFFFT-U(simd)",  /* unordered */
   "PFFFT (simd) "   /* ordered */
 };
 
 
 int compiledInAlgo[NUM_FFT_ALGOS] = {
-#ifdef PFFFT_ENABLE_FLOAT
+#ifdef HAVE_FFTPACK
   1, /* "FFTPack    " */
 #else
   0, /* "FFTPack    " */
@@ -185,6 +196,11 @@ int compiledInAlgo[NUM_FFT_ALGOS] = {
   1, /* "Pocket     " */
 #else
   0,
+#endif
+#if defined(HAVE_MKL)
+  1, /* "Intel MKL  " */
+#else
+  0,
 #endif
   1, /* "PFFFT_U    " */
   1  /* "PFFFT_O    " */
@@ -198,6 +214,7 @@ const char * algoTableHeader[NUM_FFT_ALGOS][2] = {
 { "|  real  Green ", "|  cplx  Green " },
 { "|  real   Kiss ", "|  cplx   Kiss " },
 { "|  real Pocket ", "|  cplx Pocket " },
+{ "|  real   MKL  ", "|  cplx   MKL  " },
 { "| real PFFFT-U ", "| cplx PFFFT-U " },
 { "|  real  PFFFT ", "|  cplx  PFFFT " } };
 
@@ -272,18 +289,18 @@ double frand() {
 
 
 /* compare results with the regular fftpack */
-void pffft_validate_N(int N, int cplx) {
+int pffft_validate_N(int N, int cplx) {
 
-#ifdef PFFFT_ENABLE_FLOAT
+#ifdef HAVE_FFTPACK
 
   int Nfloat = N*(cplx?2:1);
   int Nbytes = Nfloat * sizeof(pffft_scalar);
-  float *ref, *in, *out, *tmp, *tmp2;
+  pffft_scalar *ref, *in, *out, *tmp, *tmp2;
   PFFFT_SETUP *s = PFFFT_FUNC(new_setup)(N, cplx ? PFFFT_COMPLEX : PFFFT_REAL);
   int pass;
 
 
-  if (!s) { printf("Skipping N=%d, not supported\n", N); return; }
+  if (!s) { printf("Skipping N=%d, not supported\n", N); return 0; }
   ref = PFFFT_FUNC(aligned_malloc)(Nbytes);
   in = PFFFT_FUNC(aligned_malloc)(Nbytes);
   out = PFFFT_FUNC(aligned_malloc)(Nbytes);
@@ -296,7 +313,7 @@ void pffft_validate_N(int N, int cplx) {
     /* printf("N=%d pass=%d cplx=%d\n", N, pass, cplx); */
     /* compute reference solution with FFTPACK */
     if (pass == 0) {
-      float *wrk = malloc(2*Nbytes+15*sizeof(pffft_scalar));
+      fftpack_real *wrk = malloc(2*Nbytes+15*sizeof(pffft_scalar));
       for (k=0; k < Nfloat; ++k) {
         ref[k] = in[k] = (float)( frand()*2-1 );
         out[k] = 1e30F;
@@ -319,7 +336,7 @@ void pffft_validate_N(int N, int cplx) {
 
     for (k = 0; k < Nfloat; ++k) ref_max = MAX(ref_max, (float)( fabs(ref[k]) ));
 
-      
+
     /* pass 0 : non canonical ordering of transform coefficients */
     if (pass == 0) {
       /* test forward transform, with different input / output */
@@ -354,7 +371,7 @@ void pffft_validate_N(int N, int cplx) {
       for (k=0; k < Nfloat; ++k) {
         if (!(fabs(ref[k] - out[k]) < 1e-3*ref_max)) {
           printf("%s forward PFFFT mismatch found for N=%d\n", (cplx?"CPLX":"REAL"), N);
-          exit(1);
+          return 1;
         }
       }
 
@@ -371,7 +388,7 @@ void pffft_validate_N(int N, int cplx) {
       for (k = 0; k < Nfloat; ++k) {
         if (fabs(in[k] - out[k]) > 1e-3 * ref_max) {
           printf("pass=%d, %s IFFFT does not match for N=%d\n", pass, (cplx?"CPLX":"REAL"), N); break;
-          exit(1);
+          return 1;
         }
       }
     }
@@ -402,7 +419,8 @@ void pffft_validate_N(int N, int cplx) {
         if (e > conv_max) conv_max = e;
       }
       if (conv_err > 1e-5*conv_max) {
-        printf("zconvolve error ? %g %g\n", conv_err, conv_max); exit(1);
+        printf("zconvolve error ? %g %g\n", conv_err, conv_max);
+        return 1;
       }
     }
 
@@ -416,18 +434,24 @@ void pffft_validate_N(int N, int cplx) {
   PFFFT_FUNC(aligned_free)(out);
   PFFFT_FUNC(aligned_free)(tmp);
   PFFFT_FUNC(aligned_free)(tmp2);
+  return 0;
 
-#endif /* PFFFT_ENABLE_FLOAT */
+#else
+  return 2;
+#endif /* HAVE_FFTPACK */
 }
 
-void pffft_validate(int cplx) {
+int pffft_validate(int cplx) {
   static int Ntest[] = { 16, 32, 64, 96, 128, 160, 192, 256, 288, 384, 5*96, 512, 576, 5*128, 800, 864, 1024, 2048, 2592, 4000, 4096, 12000, 36864, 0};
-  int k;
+  int k, r;
   for (k = 0; Ntest[k]; ++k) {
     int N = Ntest[k];
     if (N == 16 && !cplx) continue;
-    pffft_validate_N(N, cplx);
+    r = pffft_validate_N(N, cplx);
+    if (r)
+      return r;
   }
+  return 0;
 }
 
 int array_output_format = 1;
@@ -548,10 +572,10 @@ void benchmark_ffts(int N, int cplx, int withFFTWfullMeas, double iterCal, doubl
   /* FFTPack benchmark */
   Nmax = (cplx ? N*2 : N);
   X[Nmax] = checkVal;
-#ifdef PFFFT_ENABLE_FLOAT
+#ifdef HAVE_FFTPACK
   {
-    float *wrk = malloc(2*Nbytes + 15*sizeof(pffft_scalar));
-    te = uclock_sec();  
+    fftpack_real *wrk = malloc(2*Nbytes + 15*sizeof(pffft_scalar));
+    te = uclock_sec();
     if (cplx) cffti(N, wrk);
     else      rffti(N, wrk);
     t0 = uclock_sec();
@@ -909,6 +933,66 @@ void benchmark_ffts(int N, int cplx, int withFFTWfullMeas, double iterCal, doubl
 #endif
 
 
+#if defined(HAVE_MKL)
+  {
+    DFTI_DESCRIPTOR_HANDLE fft_handle;
+    MKL_LONG mkl_status, mkl_ret;
+    te = uclock_sec();
+    if (sizeof(float) == sizeof(pffft_scalar))
+      mkl_status = DftiCreateDescriptor(&fft_handle, DFTI_SINGLE, (cplx ? DFTI_COMPLEX : DFTI_REAL), 1, N);
+    else if (sizeof(double) == sizeof(pffft_scalar))
+      mkl_status = DftiCreateDescriptor(&fft_handle, DFTI_DOUBLE, (cplx ? DFTI_COMPLEX : DFTI_REAL), 1, N);
+    else
+      mkl_status = 1;
+
+    while (mkl_status == 0) {
+      mkl_ret = DftiSetValue(fft_handle, DFTI_PLACEMENT, DFTI_NOT_INPLACE);
+      if (mkl_ret) {
+        DftiFreeDescriptor(&fft_handle);
+        mkl_status = 1;
+        break;
+      }
+      mkl_ret = DftiCommitDescriptor(fft_handle);
+      if (mkl_ret) {
+        DftiFreeDescriptor(&fft_handle);
+        mkl_status = 1;
+        break;
+      }
+      break;
+    }
+
+    if (mkl_status == 0) {
+      t0 = uclock_sec();
+      tstop = t0 + max_test_duration;
+      max_iter = 0;
+
+      do {
+        for ( k = 0; k < step_iter; ++k ) {
+          assert( X[Nmax] == checkVal );
+          DftiComputeForward(fft_handle, &X[0], &Y[0]);
+          assert( X[Nmax] == checkVal );
+          DftiComputeBackward(fft_handle, &X[0], &Y[0]);
+          assert( X[Nmax] == checkVal );
+          ++max_iter;
+        }
+        t1 = uclock_sec();
+      } while ( t1 < tstop );
+
+      DftiFreeDescriptor(&fft_handle);
+
+      flops = (max_iter*2) * ((cplx ? 5 : 2.5)*N*log((double)N)/M_LN2); /* see http://www.fftw.org/speed/method.html */
+      tmeas[TYPE_ITER][ALGO_MKL] = max_iter;
+      tmeas[TYPE_MFLOPS][ALGO_MKL] = flops/1e6/(t1 - t0 + 1e-16);
+      tmeas[TYPE_DUR_TOT][ALGO_MKL] = t1 - t0;
+      tmeas[TYPE_DUR_NS][ALGO_MKL] = show_output("MKL", N, cplx, flops, t0, t1, max_iter, tableFile);
+      tmeas[TYPE_PREP][ALGO_MKL] = (t0 - te) * 1e3;
+      haveAlgo[ALGO_MKL] = 1;
+    } else {
+      show_output("MKL", N, cplx, -1, -1, -1, -1, tableFile);
+    }
+  }
+#endif
+
   /* PFFFT-U (unordered) benchmark */
   Nmax = (cplx ? pffftPow2N*2 : pffftPow2N);
   X[Nmax] = checkVal;
@@ -1070,9 +1154,11 @@ int main(int argc, char **argv) {
   int Npow2[NUMPOW2FFTLENS];  /* exp = 1 .. 21, -1 */
   const int *Nvalues = NULL;
   double tmeas[2][MAXNUMFFTLENS][NUM_TYPES][NUM_FFT_ALGOS];
-  double iterCalReal, iterCalCplx;
+  double iterCalReal = 0.0, iterCalCplx = 0.0;
 
   int benchReal=1, benchCplx=1, withFFTWfullMeas=0, outputTable2File=1, usePow2=1;
+  int max_N = 1024 * 1024 * 2;
+  int quicktest = 0;
   int realCplxIdx, typeIdx;
   int i, k;
   FILE *tableFile = NULL;
@@ -1113,8 +1199,28 @@ int main(int argc, char **argv) {
       Nvalues = NnonPow2;
       usePow2 = 0;
     }
+    else if (!strcmp(argv[i], "--max-len") && i+1 < argc) {
+      max_N = atoi(argv[i+1]);
+      ++i;
+    }
+    else if (!strcmp(argv[i], "--quick")) {
+      fprintf(stdout, "actived quicktest mode\n");
+      quicktest = 1;
+    }
+    else if (!strcmp(argv[i], "--validate")) {
+#ifdef HAVE_FFTPACK
+      int r;
+      fprintf(stdout, "validating PFFFT against %s FFTPACK ..\n", (benchCplx ? "complex" : "real"));
+      r = pffft_validate(benchCplx);
+      fprintf((r ? stderr : stderr), "pffft %s\n", (r ? "validation failed!" : "successful"));
+      return r;
+#else
+      fprintf(stderr, "validation not available without FFTPACK!\n");
+#endif
+      return 0;
+    }
     else /* if (!strcmp(argv[i], "--help")) */ {
-      printf("usage: %s [--array-format|--table] [--no-tab] [--real|--cplx] [--fftw-full-measure] [--non-pow2]\n", argv[0]);
+      printf("usage: %s [--array-format|--table] [--no-tab] [--real|--cplx] [--validate] [--fftw-full-measure] [--non-pow2] [--max-len <N>] [--quick]\n", argv[0]);
       exit(0);
     }
   }
@@ -1132,8 +1238,8 @@ int main(int argc, char **argv) {
 #else
     algoName[ALGO_FFTW_AUTO] = "FFTWD(meas)"; /* "FFTW (auto)" */
 #endif
-    algoTableHeader[NUM_FFT_ALGOS][0] = "|real FFTWmeas "; /* "|real FFTWauto " */
-    algoTableHeader[NUM_FFT_ALGOS][0] = "|cplx FFTWmeas "; /* "|cplx FFTWauto " */
+    algoTableHeader[ALGO_FFTW_AUTO][0] = "|real FFTWmeas "; /* "|real FFTWauto " */
+    algoTableHeader[ALGO_FFTW_AUTO][1] = "|cplx FFTWmeas "; /* "|cplx FFTWauto " */
   }
 #endif
 
@@ -1155,6 +1261,7 @@ int main(int argc, char **argv) {
   */
 
   /* calibrate test duration */
+  if (!quicktest)
   {
     double t0, t1, dur;
     printf("calibrating fft benchmark duration at size N = 512 ..\n");
@@ -1174,11 +1281,11 @@ int main(int argc, char **argv) {
 
   if (!array_output_format) {
     if (benchReal) {
-      for (i=0; Nvalues[i] > 0; ++i)
+      for (i=0; Nvalues[i] > 0 && Nvalues[i] <= max_N; ++i)
         benchmark_ffts(Nvalues[i], 0 /* real fft */, withFFTWfullMeas, iterCalReal, tmeas[0][i], haveAlgo, NULL);
     }
     if (benchCplx) {
-      for (i=0; Nvalues[i] > 0; ++i)
+      for (i=0; Nvalues[i] > 0 && Nvalues[i] <= max_N; ++i)
         benchmark_ffts(Nvalues[i], 1 /* cplx fft */, withFFTWfullMeas, iterCalCplx, tmeas[1][i], haveAlgo, NULL);
     }
 
@@ -1220,7 +1327,7 @@ int main(int argc, char **argv) {
       print_table(":|\n", tableFile);
     }
 
-    for (i=0; Nvalues[i] > 0; ++i) {
+    for (i=0; Nvalues[i] > 0 && Nvalues[i] <= max_N; ++i) {
       {
         double t0, t1;
         print_table_fftsize(Nvalues[i], tableFile);
@@ -1275,7 +1382,7 @@ int main(int argc, char **argv) {
               fprintf(f, "%s, ", algoName[k]);
           fprintf(f, "\n");
         }
-        for (i=0; Nvalues[i] > 0; ++i)
+        for (i=0; Nvalues[i] > 0 && Nvalues[i] <= max_N; ++i)
         {
           {
             fprintf(f, "%d, %.3f, ", Nvalues[i], log10((double)Nvalues[i])/log10(2.0) );
diff --git a/cmake/FindMIPP.cmake b/cmake/FindMIPP.cmake
new file mode 100644
index 0000000..afd840d
--- /dev/null
+++ b/cmake/FindMIPP.cmake
@@ -0,0 +1,26 @@
+
+if(MIPP_INCLUDE_DIRS)
+  set(MIPP_FIND_QUIETLY TRUE)
+endif()
+
+find_path(MIPP_INCLUDE_DIRS NAMES mipp.h
+    HINTS
+        ${MIPP_ROOT}
+        $ENV{HOME}/.local
+    PATH_SUFFIXES include/mipp
+)
+
+include(FindPackageHandleStandardArgs)
+find_package_handle_standard_args(MIPP DEFAULT_MSG MIPP_INCLUDE_DIRS)
+
+if(MIPP_FOUND AND NOT TARGET MIPP)
+    message(STATUS "MIPP_FOUND -> creating interface library MIPP at ${MIPP_INCLUDE_DIRS}")
+    add_library(MIPP INTERFACE)
+    target_compile_definitions(MIPP INTERFACE HAVE_MIPP=1)
+    target_include_directories(MIPP INTERFACE ${MIPP_INCLUDE_DIRS})
+    target_compile_features(MIPP INTERFACE cxx_std_11)
+else()
+    message(WARNING "MIPP not found.")
+endif()
+
+mark_as_advanced(MIPP_INCLUDE_DIRS)
diff --git a/cmake/FindPAPI.cmake b/cmake/FindPAPI.cmake
new file mode 100644
index 0000000..81e7a6a
--- /dev/null
+++ b/cmake/FindPAPI.cmake
@@ -0,0 +1,25 @@
+# Find PAPI libraries
+# Once done this will define
+#  PAPI_FOUND - System has PAPI
+#  PAPI_INCLUDE_DIRS - The PAPI include directories
+#  PAPI_LIBRARIES - The libraries needed to use PAPI
+
+if(PAPI_INCLUDE_DIRS AND PAPI_LIBRARIES)
+  set(PAPI_FIND_QUIETLY TRUE)
+endif()
+
+find_path(PAPI_INCLUDE_DIRS NAMES papi.h HINTS ${PAPI_ROOT} PATH_SUFFIXES include)
+find_library(PAPI_LIBRARIES NAMES papi HINTS ${PAPI_ROOT} PATH_SUFFIXES lib lib64)
+
+include(FindPackageHandleStandardArgs)
+find_package_handle_standard_args(PAPI DEFAULT_MSG PAPI_LIBRARIES PAPI_INCLUDE_DIRS)
+if(PAPI_FOUND AND NOT TARGET PAPI::PAPI)
+    set(PAPI_LIBRARIES ${PAPI_LIBRARIES} rt)
+
+    add_library(PAPI::PAPI SHARED IMPORTED)
+    set_target_properties(PAPI::PAPI PROPERTIES
+        INTERFACE_INCLUDE_DIRECTORIES "${PAPI_INCLUDE_DIRS}"
+        IMPORTED_LOCATION "${PAPI_LIBRARIES}")
+endif()
+
+mark_as_advanced(PAPI_INCLUDE_DIRS PAPI_LIBRARIES)
diff --git a/cmake/compiler_warnings.cmake b/cmake/compiler_warnings.cmake
new file mode 100644
index 0000000..32c1782
--- /dev/null
+++ b/cmake/compiler_warnings.cmake
@@ -0,0 +1,11 @@
+
+function(target_activate_cxx_compiler_warnings target)
+    target_compile_options(${target} PRIVATE $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -pedantic>)
+    target_compile_options(${target} PRIVATE $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -pedantic>)
+endfunction()
+
+function(target_activate_c_compiler_warnings target)
+    target_compile_options(${target} PRIVATE $<$<C_COMPILER_ID:GNU>:-Wall -Wextra -pedantic>)
+    target_compile_options(${target} PRIVATE $<$<C_COMPILER_ID:Clang>:-Wall -Wextra -pedantic>)
+endfunction()
+
diff --git a/cmake/target_optimizations.cmake b/cmake/target_optimizations.cmake
new file mode 100644
index 0000000..6d19fdb
--- /dev/null
+++ b/cmake/target_optimizations.cmake
@@ -0,0 +1,197 @@
+
+# cmake options: TARGET_C_ARCH / TARGET_CPP_ARCH:
+#   and optionally:  TARGET_C_EXTRA TARGET_CXX_EXTRA
+#
+# provided:
+#   - function: target_set_c_arch_flags(<target>)    # uses options TARGET_C_ARCH and TARGET_C_EXTRA
+#   - function: target_set_cxx_arch_flags(<target>)  # uses options TARGET_CXX_ARCH and TARGET_CXX_EXTRA
+#   - macro:    target_set_cxx_arch_option(<target> <gcc/clang_march> <gcc/clang_extra> <msvc_arch>)
+#
+# see https://en.wikichip.org/wiki/x86/extensions
+# and https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html
+#   for gcc specific architecture options
+# and https://docs.microsoft.com/en-us/cpp/build/reference/arch-x64
+# or  https://docs.microsoft.com/en-us/cpp/build/reference/arch-x86
+#   for msvc specific architecture options
+
+# https://en.wikichip.org/wiki/arm/versions
+# https://en.wikipedia.org/wiki/Raspberry_Pi
+# https://gcc.gnu.org/onlinedocs/gcc/ARM-Options.html#ARM-Options
+# https://en.wikipedia.org/wiki/Comparison_of_ARMv7-A_cores
+# https://en.wikipedia.org/wiki/Comparison_of_ARMv8-A_cores
+
+# arm32_rpi1 untested
+#   -mcpu=arm1176jzf-s -mfloat-abi=hard -mfpu=vfp         -mtune=arm1176jzf-s
+# arm32_rpi2 untested
+#   "-march=armv7-a"   "-mfloat-abi=hard" "-mfpu=neon-vfpv4"
+#   "-march=armv8-a"   "-mfloat-abi=hard" "-mfpu=neon-vfpv4"
+# arm32_rpi3 with "armv7-a" tested on Raspbian GNU/Linux 10 (buster), 32-bit  => MIPP test reports: NEONv1, 128 bits
+#   "-march=armv7-a"   "-mfloat-abi=hard" "-mfpu=neon-vfpv4"
+# arm32_rpi3 with "armv8-a" tested on Raspbian GNU/Linux 10 (buster), 32-bit  => MIPP test reports: NEONv1, 128 bits
+#   "-march=armv8-a"   "-mfloat-abi=hard" "-mfpu=neon-vfpv4"
+# arm32_rpi3 with "armv8-a" tested on Raspbian GNU/Linux 10 (buster), 32-bit  => MIPP test reports: NEONv1, 128 bits
+#   "-march=armv8-a"   "-mfloat-abi=hard" "-mfpu=neon-vfpv4" "-mtune=cortex-a53"
+# arm32_rpi4 untested
+#   RPi 4 Model B:    Cortex-A72  =>  "-mtune=cortex-a72"  ?
+#   "-mcpu=cortex-a72 -mfloat-abi=hard -mfpu=neon-fp-armv8 -mneon-for-64bits  -mtune=cortex-a72"
+
+set(MSVC_EXTRA_OPT_none "")
+set(GCC_EXTRA_OPT_none "")
+set(GCC_EXTRA_OPT_neon_vfpv4    "-mfloat-abi=hard" "-mfpu=neon-vfpv4")
+set(GCC_EXTRA_OPT_neon_rpi3_a53 "-mfloat-abi=hard" "-mfpu=neon-vfpv4" "-mtune=cortex-a53")
+set(GCC_EXTRA_OPT_neon_rpi4_a72 "-mfloat-abi=hard" "-mfpu=neon-fp-armv8" "-mtune=cortex-a72")
+
+if ( (CMAKE_SYSTEM_PROCESSOR STREQUAL "i686") OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64") )
+    set(GCC_MARCH_DESC "native/SSE2:pentium4/SSE3:core2/SSE4:nehalem/AVX:sandybridge/AVX2:haswell")
+    set(GCC_MARCH_VALUES "none;native;pentium4;core2;nehalem;sandybridge;haswell" CACHE INTERNAL "List of possible architectures")
+    set(GCC_EXTRA_VALUES "" CACHE INTERNAL "List of possible EXTRA options")
+elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
+    set(GCC_MARCH_DESC "native/ARMwNEON:armv8-a")
+    set(GCC_MARCH_VALUES "none;native;armv8-a" CACHE INTERNAL "List of possible architectures")
+    set(GCC_EXTRA_VALUES "" CACHE INTERNAL "List of possible additional options")
+elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "armv7l")
+    set(GCC_MARCH_DESC "native/ARMwNEON:armv7-a")
+    set(GCC_MARCH_VALUES "none;native;armv7-a" CACHE INTERNAL "List of possible architectures")
+    set(GCC_EXTRA_VALUES "none;neon_vfpv4;neon_rpi3_a53;neon_rpi4_a72" CACHE INTERNAL "List of possible additional options")
+else()
+    message(WARNING "unsupported CMAKE_SYSTEM_PROCESSOR '${CMAKE_SYSTEM_PROCESSOR}'")
+    # other PROCESSORs could be "ppc", "ppc64",  "arm" - or something else?!
+    set(GCC_MARCH_DESC "native")
+    set(GCC_MARCH_VALUES "none;native" CACHE INTERNAL "List of possible architectures")
+    set(GCC_EXTRA_VALUES "" CACHE INTERNAL "List of possible additional options")
+endif()
+
+# cmake options - depending on C/C++ compiler
+# how are chances, that C and C++ compilers are from different vendors?
+if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
+    set(TARGET_C_ARCH "none" CACHE STRING "gcc target C architecture (-march): ${GCC_MARCH_DESC}")
+    set_property(CACHE TARGET_C_ARCH PROPERTY STRINGS ${GCC_MARCH_VALUES})
+    if ( NOT (GCC_EXTRA_VALUES STREQUAL "") )
+        set(TARGET_C_EXTRA "none" CACHE STRING "gcc additional options for C")
+        set_property(CACHE TARGET_C_EXTRA PROPERTY STRINGS ${GCC_EXTRA_VALUES})
+    endif()
+elseif (CMAKE_C_COMPILER_ID STREQUAL "Clang")
+    set(TARGET_C_ARCH "none" CACHE STRING "clang target C architecture (-march): ${GCC_MARCH_DESC}")
+    set_property(CACHE TARGET_C_ARCH PROPERTY STRINGS ${GCC_MARCH_VALUES})
+    if ( NOT (GCC_EXTRA_VALUES STREQUAL "") )
+        set(TARGET_C_EXTRA "none" CACHE STRING "gcc additional options for C")
+        set_property(CACHE TARGET_C_EXTRA PROPERTY STRINGS ${GCC_EXTRA_VALUES})
+    endif()
+elseif (CMAKE_C_COMPILER_ID MATCHES "MSVC")
+    set(TARGET_C_ARCH "none" CACHE STRING "msvc target C architecture (/arch): SSE2/AVX/AVX2/AVX512")
+    set(TARGET_C_EXTRA "none" CACHE STRING "msvc additional options")
+else()
+    message(WARNING "unsupported C compiler '${CMAKE_C_COMPILER_ID}', see https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_COMPILER_ID.html")
+endif()
+
+if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
+    set(TARGET_CXX_ARCH "none" CACHE STRING "gcc target C++ architecture (-march): ${GCC_MARCH_DESC}")
+    set_property(CACHE TARGET_CXX_ARCH PROPERTY STRINGS ${GCC_MARCH_VALUES})
+    if ( NOT (GCC_EXTRA_VALUES STREQUAL "") )
+        set(TARGET_CXX_EXTRA "none" CACHE STRING "gcc additional options for C++")
+        set_property(CACHE TARGET_CXX_EXTRA PROPERTY STRINGS ${GCC_EXTRA_VALUES})
+    endif()
+elseif (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
+    set(TARGET_CXX_ARCH "none" CACHE STRING "clang target C++ architecture (-march): ${GCC_MARCH_DESC}")
+    set_property(CACHE TARGET_CXX_ARCH PROPERTY STRINGS ${GCC_MARCH_VALUES})
+    if ( NOT (GCC_EXTRA_VALUES STREQUAL "") )
+        set(TARGET_CXX_EXTRA "none" CACHE STRING "clang additional options for C++")
+        set_property(CACHE TARGET_CXX_EXTRA PROPERTY STRINGS ${GCC_EXTRA_VALUES})
+    endif()
+elseif (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
+    set(TARGET_CXX_ARCH "none" CACHE STRING "msvc target C++ architecture (/arch): SSE2/AVX/AVX2/AVX512")
+    set(TARGET_CXX_EXTRA "none" CACHE STRING "msvc additional options")
+else()
+    message(WARNING "unsupported C++ compiler '${CMAKE_CXX_COMPILER_ID}', see https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_COMPILER_ID.html")
+endif()
+
+######################################################
+
+function(target_set_c_arch_flags target)
+    if ( ("${TARGET_C_ARCH}" STREQUAL "") OR ("${TARGET_C_ARCH}" STREQUAL "none") )
+        message(STATUS "C ARCH for target ${target} is not set!")
+    else()
+        if ( (CMAKE_C_COMPILER_ID STREQUAL "GNU") OR (CMAKE_C_COMPILER_ID STREQUAL "Clang") )
+            target_compile_options(${target} PRIVATE "-march=${TARGET_C_ARCH}")
+            message(STATUS "C ARCH for target ${target} set: ${TARGET_C_ARCH}")
+        elseif (CMAKE_C_COMPILER_ID MATCHES "MSVC")
+            target_compile_options(${target} PRIVATE "/arch:${TARGET_C_ARCH}")
+            message(STATUS "C ARCH for target ${target} set: ${TARGET_C_ARCH}")
+        else()
+            message(WARNING "unsupported C compiler '${CMAKE_C_COMPILER_ID}' for target_set_c_arch_flags(), see https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_COMPILER_ID.html")
+        endif()
+    endif()
+    if ( ("${TARGET_C_EXTRA}" STREQUAL "") OR ("${TARGET_C_EXTRA}" STREQUAL "none") )
+        message(STATUS "C additional options for target ${target} is not set!")
+    else()
+        if ( (CMAKE_C_COMPILER_ID STREQUAL "GNU") OR (CMAKE_C_COMPILER_ID STREQUAL "Clang") )
+            target_compile_options(${target} PRIVATE "${GCC_EXTRA_OPT_${TARGET_C_EXTRA}}")
+            message(STATUS "C additional options for target ${target} set: ${GCC_EXTRA_OPT_${TARGET_C_EXTRA}}")
+        elseif (CMAKE_C_COMPILER_ID MATCHES "MSVC")
+            # target_compile_options(${target} PRIVATE "${MSVC_EXTRA_OPT_${TARGET_C_EXTRA}}")
+            message(STATUS "C additional options for target ${target} not usable with MSVC")
+        else()
+            message(WARNING "unsupported C compiler '${CMAKE_C_COMPILER_ID}' for target_set_c_arch_flags(), see https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_COMPILER_ID.html")
+        endif()
+        if ( ("${TARGET_C_EXTRA}" MATCHES "^neon_.*") OR (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64") )
+            message(STATUS "additional option contains neon: setting PFFFT_ENABLE_NEON for C target ${target}")
+            target_compile_definitions(${target} PRIVATE PFFFT_ENABLE_NEON=1)
+        endif()
+    endif()
+endfunction()
+
+function(target_set_cxx_arch_flags target)
+    if ( ("${TARGET_CXX_ARCH}" STREQUAL "") OR ("${TARGET_CXX_ARCH}" STREQUAL "none") )
+        message(STATUS "C++ ARCH for target ${target} is not set!")
+    else()
+        if ( (CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") )
+            target_compile_options(${target} PRIVATE "-march=${TARGET_CXX_ARCH}")
+            message(STATUS "C++ ARCH for target ${target} set: ${TARGET_CXX_ARCH}")
+        elseif (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
+            target_compile_options(${target} PRIVATE "/arch:${TARGET_CXX_ARCH}")
+            message(STATUS "C++ ARCH for target ${target} set: ${TARGET_CXX_ARCH}")
+        else()
+            message(WARNING "unsupported C++ compiler '${CMAKE_CXX_COMPILER_ID}' for target_set_cxx_arch_flags(), see https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_COMPILER_ID.html")
+        endif()
+    endif()
+    if ( ("${TARGET_CXX_EXTRA}" STREQUAL "") OR ("${TARGET_CXX_EXTRA}" STREQUAL "none") )
+        message(STATUS "C++ additional options for target ${target} is not set!")
+    else()
+        if ( (CMAKE_C_COMPILER_ID STREQUAL "GNU") OR (CMAKE_C_COMPILER_ID STREQUAL "Clang") )
+            target_compile_options(${target} PRIVATE "${GCC_EXTRA_OPT_${TARGET_CXX_EXTRA}}")
+            message(STATUS "C++ additional options for target ${target} set: ${GCC_EXTRA_OPT_${TARGET_CXX_EXTRA}}")
+        elseif (CMAKE_C_COMPILER_ID MATCHES "MSVC")
+            # target_compile_options(${target} PRIVATE "${MSVC_EXTRA_OPT_${TARGET_CXX_EXTRA}}")
+            message(STATUS "C++ additional options for target ${target} not usable with MSVC")
+        else()
+          message(WARNING "unsupported C compiler '${CMAKE_C_COMPILER_ID}' for target_set_c_arch_flags(), see https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_COMPILER_ID.html")
+        endif()
+        if ( ("${TARGET_CXX_EXTRA}" MATCHES "^neon_.*") OR (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64") )
+            message(STATUS "additional option contains 'neon': setting PFFFT_ENABLE_NEON for C++ target ${target}")
+            target_compile_definitions(${target} PRIVATE PFFFT_ENABLE_NEON=1)
+        endif()
+    endif()
+endfunction()
+
+
+macro(target_set_cxx_arch_option target gcc_clang_arch gcc_clang_extra msvc_arch )
+    if ( (CMAKE_CXX_COMPILER_ID STREQUAL "GNU") OR (CMAKE_CXX_COMPILER_ID STREQUAL "Clang") )
+
+        if ( NOT (("${gcc_clang_arch}" STREQUAL "") OR ("${gcc_clang_arch}" STREQUAL "none") ) )
+            target_compile_options(${target} PRIVATE "-march=${gcc_clang_arch}")
+            message(STATUS "C++ ARCH for target ${target}: ${gcc_clang_arch}")
+        endif()
+        if (NOT ( ("${gcc_clang_extra}" STREQUAL "") OR ("${gcc_clang_extra}" STREQUAL "none") ) )
+            target_compile_options(${target} PRIVATE "${GCC_EXTRA_OPT_${gcc_clang_extra}}")
+            message(STATUS "C++ additional options for target ${target}: ${GCC_EXTRA_OPT_${gcc_clang_extra}}")
+        endif()
+    elseif (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
+        if ( NOT (("${msvc_arch}" STREQUAL "") OR ("${msvc_arch}" STREQUAL "none") ) )
+            target_compile_options(${target} PRIVATE "/arch:${msvc_arch}")
+            message(STATUS "C++ ARCH for target ${target} set: ${msvc_arch}")
+        endif()
+    else()
+        message(WARNING "unsupported C++ compiler '${CMAKE_CXX_COMPILER_ID}' for target_set_cxx_arch_option(), see https://cmake.org/cmake/help/latest/variable/CMAKE_LANG_COMPILER_ID.html")
+    endif()
+endmacro()
+
diff --git a/cross_build_mingw32.sh b/cross_build_mingw32.sh
new file mode 100755
index 0000000..94f05f9
--- /dev/null
+++ b/cross_build_mingw32.sh
@@ -0,0 +1,25 @@
+#!/bin/bash
+
+# requires debian/ubuntu packages: zip gcc-mingw-w64
+
+if [ -z "$1" ]; then
+  echo "usage: $0 <zip-post> <any other cmake options>"
+  exit 1
+fi
+
+ZIP_POST="$1"
+shift
+
+CROSS="i686-w64-mingw32"
+WN="w32"
+TOOLCHAIN="mingw-w32-i686.cmake"
+
+rm -rf build_${WN}_${ZIP_POST}
+echo -e "\n\n********************************************************"
+echo "start build of pffft_${WN}_${ZIP_POST}"
+mkdir build_${WN}_${ZIP_POST} && \
+cmake -S . -B build_${WN}_${ZIP_POST} \
+  -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN} \
+  -DCMAKE_INSTALL_PREFIX=pffft_bin-${WN}_${ZIP_POST} \
+  "$@" && \
+cmake --build build_${WN}_${ZIP_POST}
diff --git a/cross_build_mingw64.sh b/cross_build_mingw64.sh
new file mode 100755
index 0000000..23c251f
--- /dev/null
+++ b/cross_build_mingw64.sh
@@ -0,0 +1,25 @@
+#!/bin/bash
+
+# requires debian/ubuntu packages: zip gcc-mingw-w64
+
+if [ -z "$1" ]; then
+  echo "usage: $0 <zip-post> <any other cmake options>"
+  exit 1
+fi
+
+ZIP_POST="$1"
+shift
+
+# CROSS="x86_64-w64-mingw32"
+WN="w64"
+TOOLCHAIN="mingw-w64-x64_64.cmake"
+
+rm -rf build_${WN}_${ZIP_POST}
+echo -e "\n\n********************************************************"
+echo "start build of pffft_${WN}_${ZIP_POST}"
+mkdir build_${WN}_${ZIP_POST} && \
+cmake -S . -B build_${WN}_${ZIP_POST} \
+  -DCMAKE_TOOLCHAIN_FILE=${TOOLCHAIN} \
+  -DCMAKE_INSTALL_PREFIX=pffft_bin-${WN}_${ZIP_POST} \
+  "$@" && \
+cmake --build build_${WN}_${ZIP_POST}
diff --git a/examples/CMakeLists.txt b/examples/CMakeLists.txt
new file mode 100644
index 0000000..0fe733b
--- /dev/null
+++ b/examples/CMakeLists.txt
@@ -0,0 +1,63 @@
+cmake_minimum_required(VERSION 3.1)
+project(examples)
+
+if ( CMAKE_C_COMPILER_ID MATCHES "MSVC" )
+  # using Visual Studio C++
+  message(STATUS "INFO: detected MSVC: will not link math lib m")
+  set(MATHLIB "")
+  add_definitions("/D_CRT_SECURE_NO_WARNINGS")
+  set(MSVC_DISABLED_WARNINGS_LIST "C4996")
+else()
+  if(PFFFT_DISABLE_LINK_WITH_M)
+  else()
+    message(STATUS "INFO: detected NO MSVC: ${CMAKE_C_COMPILER_ID}: will link math lib m")
+    set(MATHLIB "m")
+  endif()
+endif()
+
+set(STDCXXLIB "")
+if (MINGW)
+  set(STDCXXLIB "stdc++")
+endif()
+
+
+set(CMAKE_CXX_EXTENSIONS OFF)
+
+
+if (PFFFT_USE_TYPE_DOUBLE)
+  add_executable(example_cpp11_real_dbl_fwd example_cpp11_real_dbl_fwd.cpp)
+  target_compile_definitions(example_cpp11_real_dbl_fwd PRIVATE PFFFT_ENABLE_DOUBLE)
+  target_link_libraries(example_cpp11_real_dbl_fwd PFFFT ${STDCXXLIB} ${MATHLIB})
+  set_property(TARGET example_cpp11_real_dbl_fwd PROPERTY CXX_STANDARD 11)
+  set_property(TARGET example_cpp11_real_dbl_fwd PROPERTY CXX_STANDARD_REQUIRED ON)
+
+  add_executable(example_cpp11_cplx_dbl_fwd example_cpp11_cplx_dbl_fwd.cpp)
+  target_compile_definitions(example_cpp11_cplx_dbl_fwd PRIVATE PFFFT_ENABLE_DOUBLE)
+  target_link_libraries(example_cpp11_cplx_dbl_fwd PFFFT ${STDCXXLIB} ${MATHLIB})
+  set_property(TARGET example_cpp11_cplx_dbl_fwd PROPERTY CXX_STANDARD 11)
+  set_property(TARGET example_cpp11_cplx_dbl_fwd PROPERTY CXX_STANDARD_REQUIRED ON)
+
+  add_executable(example_c_cplx_dbl_fwd example_c_cplx_dbl_fwd.c)
+  target_compile_definitions(example_c_cplx_dbl_fwd PRIVATE PFFFT_ENABLE_FLOAT)
+  target_link_libraries(example_c_cplx_dbl_fwd PFFFT ${MATHLIB})
+endif()
+
+
+if (PFFFT_USE_TYPE_FLOAT)
+  add_executable(example_cpp98_real_flt_fwd example_cpp98_real_flt_fwd.cpp)
+  target_compile_definitions(example_cpp98_real_flt_fwd PRIVATE PFFFT_ENABLE_FLOAT)
+  target_link_libraries(example_cpp98_real_flt_fwd PFFFT ${STDCXXLIB} ${MATHLIB})
+  set_property(TARGET example_cpp98_real_flt_fwd PROPERTY CXX_STANDARD 98)
+  set_property(TARGET example_cpp98_real_flt_fwd PROPERTY CXX_STANDARD_REQUIRED ON)
+
+  add_executable(example_cpp98_cplx_flt_fwd example_cpp98_cplx_flt_fwd.cpp)
+  target_compile_definitions(example_cpp98_cplx_flt_fwd PRIVATE PFFFT_ENABLE_FLOAT)
+  target_link_libraries(example_cpp98_cplx_flt_fwd PFFFT ${STDCXXLIB} ${MATHLIB})
+  set_property(TARGET example_cpp98_cplx_flt_fwd PROPERTY CXX_STANDARD 98)
+  set_property(TARGET example_cpp98_cplx_flt_fwd PROPERTY CXX_STANDARD_REQUIRED ON)
+
+  add_executable(example_c_real_flt_fwd example_c_real_flt_fwd.c)
+  target_compile_definitions(example_c_real_flt_fwd PRIVATE PFFFT_ENABLE_FLOAT)
+  target_link_libraries(example_c_real_flt_fwd PFFFT ${MATHLIB})
+endif()
+
diff --git a/examples/example_c_cplx_dbl_fwd.c b/examples/example_c_cplx_dbl_fwd.c
new file mode 100644
index 0000000..e9adcd9
--- /dev/null
+++ b/examples/example_c_cplx_dbl_fwd.c
@@ -0,0 +1,69 @@
+
+#include "pffft_double.h"
+
+#include <stdio.h>
+#include <stdlib.h>
+
+
+void c_forward_complex_double(const int transformLen)
+{
+  printf("running %s()\n", __FUNCTION__);
+
+  /* first check - might be skipped */
+  if (transformLen < pffftd_min_fft_size(PFFFT_COMPLEX))
+  {
+    fprintf(stderr, "Error: minimum FFT transformation length is %d\n", pffftd_min_fft_size(PFFFT_COMPLEX));
+    return;
+  }
+
+  /* instantiate FFT and prepare transformation for length N */
+  PFFFTD_Setup *ffts = pffftd_new_setup(transformLen, PFFFT_COMPLEX);
+
+  /* one more check */
+  if (!ffts)
+  {
+    fprintf(stderr,
+            "Error: transformation length %d is not decomposable into small prime factors. "
+            "Next valid transform size is: %d ; next power of 2 is: %d\n",
+            transformLen,
+            pffftd_nearest_transform_size(transformLen, PFFFT_COMPLEX, 1),
+            pffftd_next_power_of_two(transformLen) );
+    return;
+  }
+
+  /* allocate aligned vectors for input X and output Y */
+  double *X = (double*)pffftd_aligned_malloc(transformLen * 2 * sizeof(double));  /* complex: re/im interleaved */
+  double *Y = (double*)pffftd_aligned_malloc(transformLen * 2 * sizeof(double));  /* complex: re/im interleaved */
+  double *W = (double*)pffftd_aligned_malloc(transformLen * 2 * sizeof(double));
+
+  /* prepare some input data */
+  for (int k = 0; k < 2 * transformLen; k += 4)
+  {
+    X[k] = k / 2;  /* real */
+    X[k+1] = (k / 2) & 1;  /* imag */
+
+    X[k+2] = -1 - k / 2;  /* real */
+    X[k+3] = (k / 2) & 1;  /* imag */
+  }
+
+  /* do the forward transform; write complex spectrum result into Y */
+  pffftd_transform_ordered(ffts, X, Y, W, PFFFT_FORWARD);
+
+  /* print spectral output */
+  printf("output should be complex spectrum with %d complex bins\n", transformLen);
+  for (int k = 0; k < 2 * transformLen; k += 2)
+    printf("Y[%d] = %f + i * %f\n", k/2, Y[k], Y[k+1]);
+
+  pffftd_aligned_free(W);
+  pffftd_aligned_free(Y);
+  pffftd_aligned_free(X);
+  pffftd_destroy_setup(ffts);
+}
+
+
+int main(int argc, char *argv[])
+{
+  int N = (1 < argc) ? atoi(argv[1]) : 16;
+  c_forward_complex_double(N);
+  return 0;
+}
diff --git a/examples/example_c_real_flt_fwd.c b/examples/example_c_real_flt_fwd.c
new file mode 100644
index 0000000..f52df41
--- /dev/null
+++ b/examples/example_c_real_flt_fwd.c
@@ -0,0 +1,66 @@
+
+#include "pffft.h"
+
+#include <stdio.h>
+#include <stdlib.h>
+
+
+void c_forward_real_float(const int transformLen)
+{
+  printf("running %s()\n", __FUNCTION__);
+
+  /* first check - might be skipped */
+  if (transformLen < pffft_min_fft_size(PFFFT_REAL))
+  {
+    fprintf(stderr, "Error: minimum FFT transformation length is %d\n", pffft_min_fft_size(PFFFT_REAL));
+    return;
+  }
+
+  /* instantiate FFT and prepare transformation for length N */
+  PFFFT_Setup *ffts = pffft_new_setup(transformLen, PFFFT_REAL);
+
+  /* one more check */
+  if (!ffts)
+  {
+    fprintf(stderr,
+            "Error: transformation length %d is not decomposable into small prime factors. "
+            "Next valid transform size is: %d ; next power of 2 is: %d\n",
+            transformLen,
+            pffft_nearest_transform_size(transformLen, PFFFT_REAL, 1),
+            pffft_next_power_of_two(transformLen) );
+    return;
+  }
+
+  /* allocate aligned vectors for input X and output Y */
+  float *X = (float*)pffft_aligned_malloc(transformLen * sizeof(float));
+  float *Y = (float*)pffft_aligned_malloc(transformLen * sizeof(float));  /* complex: re/im interleaved */
+  float *W = (float*)pffft_aligned_malloc(transformLen * sizeof(float));
+
+  /* prepare some input data */
+  for (int k = 0; k < transformLen; k += 2)
+  {
+    X[k] = k;
+    X[k+1] = -1-k;
+  }
+
+  /* do the forward transform; write complex spectrum result into Y */
+  pffft_transform_ordered(ffts, X, Y, W, PFFFT_FORWARD);
+
+  /* print spectral output */
+  printf("output should be complex spectrum with %d complex bins\n", transformLen /2);
+  for (int k = 0; k < transformLen; k += 2)
+    printf("Y[%d] = %f + i * %f\n", k/2, Y[k], Y[k+1]);
+
+  pffft_aligned_free(W);
+  pffft_aligned_free(Y);
+  pffft_aligned_free(X);
+  pffft_destroy_setup(ffts);
+}
+
+
+int main(int argc, char *argv[])
+{
+  int N = (1 < argc) ? atoi(argv[1]) : 32;
+  c_forward_real_float(N);
+  return 0;
+}
diff --git a/examples/example_cpp11_cplx_dbl_fwd.cpp b/examples/example_cpp11_cplx_dbl_fwd.cpp
new file mode 100644
index 0000000..e60dbc9
--- /dev/null
+++ b/examples/example_cpp11_cplx_dbl_fwd.cpp
@@ -0,0 +1,66 @@
+
+#include "pffft.hpp"
+
+#include <complex>
+#include <iostream>
+
+
+void cxx11_forward_complex_double(const int transformLen)
+{
+  std::cout << "running " << __FUNCTION__ << "()" << std::endl;
+
+  // first check - might be skipped
+  using FFT_T = pffft::Fft< std::complex<double> >;
+  if (transformLen < FFT_T::minFFtsize())
+  {
+    std::cerr << "Error: minimum FFT transformation length is " << FFT_T::minFFtsize() << std::endl;
+    return;
+  }
+
+  // instantiate FFT and prepare transformation for length N
+  pffft::Fft< std::complex<double> > fft(transformLen);
+
+  // one more check
+  if (!fft.isValid())
+  {
+    std::cerr << "Error: transformation length " << transformLen << " is not decomposable into small prime factors. "
+              << "Next valid transform size is: " << FFT_T::nearestTransformSize(transformLen)
+              << "; next power of 2 is: " << FFT_T::nextPowerOfTwo(transformLen) << std::endl;
+    return;
+  }
+
+  // allocate aligned vectors for input X and output Y
+  auto X = fft.valueVector();
+  auto Y = fft.spectrumVector();
+
+  // alternative access: get raw pointers to aligned vectors
+  std::complex<double> *Xs = X.data();
+  std::complex<double> *Ys = Y.data();
+
+  // prepare some input data
+  for (int k = 0; k < transformLen; k += 2)
+  {
+    X[k] = std::complex<double>(k, k&1);        // access through AlignedVector<double>
+    Xs[k+1] = std::complex<double>(-1-k, k&1);  // access through raw pointer
+  }
+
+  // do the forward transform; write complex spectrum result into Y
+  fft.forward(X, Y);
+
+  // print spectral output
+  std::cout << "output should be complex spectrum with " << fft.getSpectrumSize() << " bins" << std::endl;
+  std::cout << "output vector has size " << Y.size() << " (complex bins):" << std::endl;
+  for (unsigned k = 0; k < Y.size(); k += 2)
+  {
+    std::cout << "Y[" << k << "] = " << Y[k] << std::endl;
+    std::cout << "Y[" << k+1 << "] = " << Ys[k+1] << std::endl;
+  }
+}
+
+
+int main(int argc, char *argv[])
+{
+  int N = (1 < argc) ? atoi(argv[1]) : 16;
+  cxx11_forward_complex_double(N);
+  return 0;
+}
diff --git a/examples/example_cpp11_real_dbl_fwd.cpp b/examples/example_cpp11_real_dbl_fwd.cpp
new file mode 100644
index 0000000..433865a
--- /dev/null
+++ b/examples/example_cpp11_real_dbl_fwd.cpp
@@ -0,0 +1,66 @@
+
+#include "pffft.hpp"
+
+#include <complex>
+#include <iostream>
+
+
+void cxx11_forward_real_double(const int transformLen)
+{
+  std::cout << "running " << __FUNCTION__ << "()" << std::endl;
+
+  // first check - might be skipped
+  using FFT_T = pffft::Fft<double>;
+  if (transformLen < FFT_T::minFFtsize())
+  {
+    std::cerr << "Error: minimum FFT transformation length is " << FFT_T::minFFtsize() << std::endl;
+    return;
+  }
+
+  // instantiate FFT and prepare transformation for length N
+  pffft::Fft<double> fft { transformLen };
+
+  // one more check
+  if (!fft.isValid())
+  {
+    std::cerr << "Error: transformation length " << transformLen << " is not decomposable into small prime factors. "
+              << "Next valid transform size is: " << FFT_T::nearestTransformSize(transformLen)
+              << "; next power of 2 is: " << FFT_T::nextPowerOfTwo(transformLen) << std::endl;
+    return;
+  }
+
+  // allocate aligned vectors for (real) input X and (complex) output Y
+  auto X = fft.valueVector();     // input vector;  type is AlignedVector<double>
+  auto Y = fft.spectrumVector();  // output vector; type is AlignedVector< std::complex<double> >
+
+  // alternative access: get raw pointers to aligned vectors
+  double *Xs = X.data();
+  std::complex<double> *Ys = Y.data();
+
+  // prepare some input data
+  for (int k = 0; k < transformLen; k += 2)
+  {
+    X[k] = k;        // access through AlignedVector<double>
+    Xs[k+1] = -1-k;  // access through raw pointer
+  }
+
+  // do the forward transform; write complex spectrum result into Y
+  fft.forward(X, Y);
+
+  // print spectral output
+  std::cout << "output should be complex spectrum with " << fft.getSpectrumSize() << " bins" << std::endl;
+  std::cout << "output vector has size " << Y.size() << " (complex bins):" << std::endl;
+  for (unsigned k = 0; k < Y.size(); k += 2)
+  {
+    std::cout << "Y[" << k << "] = " << Y[k] << std::endl;
+    std::cout << "Y[" << k+1 << "] = " << Ys[k+1] << std::endl;
+  }
+}
+
+
+int main(int argc, char *argv[])
+{
+  int N = (1 < argc) ? atoi(argv[1]) : 32;
+  cxx11_forward_real_double(N);
+  return 0;
+}
diff --git a/examples/example_cpp98_cplx_flt_fwd.cpp b/examples/example_cpp98_cplx_flt_fwd.cpp
new file mode 100644
index 0000000..91e48cd
--- /dev/null
+++ b/examples/example_cpp98_cplx_flt_fwd.cpp
@@ -0,0 +1,66 @@
+
+#include "pffft.hpp"
+
+#include <complex>
+#include <iostream>
+
+
+void cxx98_forward_complex_float(const int transformLen)
+{
+  std::cout << "running " << __FUNCTION__ << "()" << std::endl;
+
+  // first check - might be skipped
+  typedef pffft::Fft< std::complex<float> > FFT_T;
+  if (transformLen < FFT_T::minFFtsize())
+  {
+    std::cerr << "Error: minimum FFT transformation length is " << FFT_T::minFFtsize() << std::endl;
+    return;
+  }
+
+  // instantiate FFT and prepare transformation for length N
+  pffft::Fft< std::complex<float> > fft(transformLen);
+
+  // one more check
+  if (!fft.isValid())
+  {
+    std::cerr << "Error: transformation length " << transformLen << " is not decomposable into small prime factors. "
+              << "Next valid transform size is: " << FFT_T::nearestTransformSize(transformLen)
+              << "; next power of 2 is: " << FFT_T::nextPowerOfTwo(transformLen) << std::endl;
+    return;
+  }
+
+  // allocate aligned vectors for input X and output Y
+  pffft::AlignedVector< std::complex<float> > X = fft.valueVector();
+  pffft::AlignedVector< std::complex<float> > Y = fft.spectrumVector();
+
+  // alternative access: get raw pointers to aligned vectors
+  std::complex<float> *Xs = X.data();
+  std::complex<float> *Ys = Y.data();
+
+  // prepare some input data
+  for (int k = 0; k < transformLen; k += 2)
+  {
+    X[k] = std::complex<float>(k, k&1);        // access through AlignedVector<float>
+    Xs[k+1] = std::complex<float>(-1-k, k&1);  // access through raw pointer
+  }
+
+  // do the forward transform; write complex spectrum result into Y
+  fft.forward(X, Y);
+
+  // print spectral output
+  std::cout << "output should be complex spectrum with " << fft.getSpectrumSize() << " bins" << std::endl;
+  std::cout << "output vector has size " << Y.size() << " (complex bins):" << std::endl;
+  for (unsigned k = 0; k < Y.size(); k += 2)
+  {
+    std::cout << "Y[" << k << "] = " << Y[k] << std::endl;
+    std::cout << "Y[" << k+1 << "] = " << Ys[k+1] << std::endl;
+  }
+}
+
+
+int main(int argc, char *argv[])
+{
+  int N = (1 < argc) ? atoi(argv[1]) : 16;
+  cxx98_forward_complex_float(N);
+  return 0;
+}
diff --git a/examples/example_cpp98_real_flt_fwd.cpp b/examples/example_cpp98_real_flt_fwd.cpp
new file mode 100644
index 0000000..c5ffe2b
--- /dev/null
+++ b/examples/example_cpp98_real_flt_fwd.cpp
@@ -0,0 +1,66 @@
+
+#include "pffft.hpp"
+
+#include <complex>
+#include <iostream>
+
+
+void cxx98_forward_real_float(const int transformLen)
+{
+  std::cout << "running " << __FUNCTION__ << "()" << std::endl;
+
+  // first check - might be skipped
+  typedef pffft::Fft<float> FFT_T;
+  if (transformLen < FFT_T::minFFtsize())
+  {
+    std::cerr << "Error: minimum FFT transformation length is " << FFT_T::minFFtsize() << std::endl;
+    return;
+  }
+
+  // instantiate FFT and prepare transformation for length N
+  pffft::Fft<float> fft(transformLen);
+
+  // one more check
+  if (!fft.isValid())
+  {
+    std::cerr << "Error: transformation length " << transformLen << " is not decomposable into small prime factors. "
+              << "Next valid transform size is: " << FFT_T::nearestTransformSize(transformLen)
+              << "; next power of 2 is: " << FFT_T::nextPowerOfTwo(transformLen) << std::endl;
+    return;
+  }
+
+  // allocate aligned vectors for input X and output Y
+  pffft::AlignedVector<float> X = fft.valueVector();
+  pffft::AlignedVector< std::complex<float> > Y = fft.spectrumVector();
+
+  // alternative access: get raw pointers to aligned vectors
+  float *Xs = X.data();
+  std::complex<float> *Ys = Y.data();
+
+  // prepare some input data
+  for (int k = 0; k < transformLen; k += 2)
+  {
+    X[k] = k;        // access through AlignedVector<float>
+    Xs[k+1] = -1-k;  // access through raw pointer
+  }
+
+  // do the forward transform; write complex spectrum result into Y
+  fft.forward(X, Y);
+
+  // print spectral output
+  std::cout << "output should be complex spectrum with " << fft.getSpectrumSize() << " bins" << std::endl;
+  std::cout << "output vector has size " << Y.size() << " (complex bins):" << std::endl;
+  for (unsigned k = 0; k < Y.size(); k += 2)
+  {
+    std::cout << "Y[" << k << "] = " << Y[k] << std::endl;
+    std::cout << "Y[" << k+1 << "] = " << Ys[k+1] << std::endl;
+  }
+}
+
+
+int main(int argc, char *argv[])
+{
+  int N = (1 < argc) ? atoi(argv[1]) : 32;
+  cxx98_forward_real_float(N);
+  return 0;
+}
diff --git a/fftpack.c b/fftpack.c
index d412780..0645390 100644
--- a/fftpack.c
+++ b/fftpack.c
@@ -57,6 +57,15 @@
 typedef fftpack_real real;
 typedef fftpack_int  integer;
 
+#ifndef FFTPACK_DOUBLE_PRECISION
+  #define FFTPACK_COS  cosf
+  #define FFTPACK_SIN  sinf
+#else
+  #define FFTPACK_COS  cos
+  #define FFTPACK_SIN  sin
+#endif
+
+
 typedef struct f77complex {    
   real r, i;
 } f77complex;   
@@ -1065,8 +1074,8 @@ static void radbg(integer ido, integer ip, integer l1, integer idl1,
 
   /* Function Body */
   arg = (2*M_PI) / (real) (ip);
-  dcp = cos(arg);
-  dsp = sin(arg);
+  dcp = FFTPACK_COS(arg);
+  dsp = FFTPACK_SIN(arg);
   idp2 = ido + 2;
   nbd = (ido - 1) / 2;
   ipp2 = ip + 2;
@@ -1581,8 +1590,8 @@ static void radfg(integer ido, integer ip, integer l1, integer idl1,
 
   /* Function Body */
   arg = (2*M_PI) / (real) (ip);
-  dcp = cos(arg);
-  dsp = sin(arg);
+  dcp = FFTPACK_COS(arg);
+  dsp = FFTPACK_SIN(arg);
   ipph = (ip + 1) / 2;
   ipp2 = ip + 2;
   idp2 = ido + 2;
@@ -2003,8 +2012,8 @@ static void cffti1(integer n, real *wa, integer *ifac)
         i += 2;
         fi += 1.f;
         arg = fi * argld;
-        wa[i - 1] = cos(arg);
-        wa[i] = sin(arg);
+        wa[i - 1] = FFTPACK_COS(arg);
+        wa[i] = FFTPACK_SIN(arg);
       }
       if (ip > 5) {
         wa[i1 - 1] = wa[i - 1];
@@ -2207,8 +2216,8 @@ static void rffti1(integer n, real *wa, integer *ifac)
         i += 2;
         fi += 1.f;
         arg = fi * argld;
-        wa[i - 1] = cos(arg);
-        wa[i] = sin(arg);
+        wa[i - 1] = FFTPACK_COS(arg);
+        wa[i] = FFTPACK_SIN(arg);
       }
       is += ido;
     }
@@ -2380,7 +2389,7 @@ void cosqi(integer n, real *wsave)
   fk = 0.f;
   for (k = 1; k <= n; ++k) {
     fk += 1.f;
-    wsave[k] = cos(fk * dt);
+    wsave[k] = FFTPACK_COS(fk * dt);
   }
   rffti(n, &wsave[n + 1]);
 } /* cosqi */
@@ -2406,8 +2415,7 @@ void cost(integer n, real *x, real *wsave)
   nm1 = n - 1;
   np1 = n + 1;
   ns2 = n / 2;
-  if (n < 2) {
-  } else if (n == 2) {
+  if (n == 2) {
     x1h = x[1] + x[2];
     x[2] = x[1] - x[2];
     x[1] = x1h;
@@ -2417,7 +2425,7 @@ void cost(integer n, real *x, real *wsave)
     x[2] = x[1] - x[3];
     x[1] = x1p3 + tx2;
     x[3] = x1p3 - tx2;
-  } else {
+  } else if (n > 3) {
     c1 = x[1] - x[n];
     x[1] += x[n];
     for (k = 2; k <= ns2; ++k) {
@@ -2472,8 +2480,8 @@ void costi(integer n, real *wsave)
   for (k = 2; k <= ns2; ++k) {
     kc = np1 - k;
     fk += 1.f;
-    wsave[k] = sin(fk * dt) * 2.f;
-    wsave[kc] = cos(fk * dt) * 2.f;
+    wsave[k] = FFTPACK_SIN(fk * dt) * 2.f;
+    wsave[kc] = FFTPACK_COS(fk * dt) * 2.f;
   }
   rffti(nm1, &wsave[n + 1]);
 } /* costi */
@@ -2866,7 +2874,7 @@ int main(void)
       y[i - 1] = (x[0] + (real) pow(-1, i+1) * x[n]) * .5f;
       arg = (real) (i - 1) * dt;
       for (k = 2; k <= n; ++k) {
-        y[i - 1] += x[k - 1] * cos((real) (k - 1) * arg);
+        y[i - 1] += x[k - 1] * FFTPACK_COS((real) (k - 1) * arg);
       }
       y[i - 1] += y[i - 1];
     }
@@ -2954,7 +2962,7 @@ int main(void)
       x[i - 1] = 0.f;
       arg = (real) (i - 1) * dt;
       for (k = 1; k <= n; ++k) {
-        x[i - 1] += y[k - 1] * cos((real) (k + k - 1) * arg);
+        x[i - 1] += y[k - 1] * FFTPACK_COS((real) (k + k - 1) * arg);
       }
       x[i - 1] *= 4.f;
     }
@@ -2973,7 +2981,7 @@ int main(void)
       y[i - 1] = x[0] * .5f;
       arg = (real) (i + i - 1) * dt;
       for (k = 2; k <= n; ++k) {
-        y[i - 1] += x[k - 1] * cos((real) (k - 1) * arg);
+        y[i - 1] += x[k - 1] * FFTPACK_COS((real) (k - 1) * arg);
       }
       y[i - 1] += y[i - 1];
     }
@@ -3000,8 +3008,8 @@ int main(void)
     /*     TEST  CFFTI,CFFTF,CFFTB */
 
     for (i = 1; i <= n; ++i) {
-      r1 = cos(sqrt2 * (real) i);
-      r2 = sin(sqrt2 * (real) (i * i));
+      r1 = FFTPACK_COS(sqrt2 * (real) i);
+      r2 = FFTPACK_SIN(sqrt2 * (real) (i * i));
       q1.r = r1, q1.i = r2;
       cx[i-1].r = q1.r, cx[i-1].i = q1.i;
     }
@@ -3011,8 +3019,8 @@ int main(void)
       cy[i-1].r = 0.f, cy[i-1].i = 0.f;
       for (k = 1; k <= n; ++k) {
         arg2 = (real) (k - 1) * arg1;
-        r1 = cos(arg2);
-        r2 = sin(arg2);
+        r1 = FFTPACK_COS(arg2);
+        r2 = FFTPACK_SIN(arg2);
         q3.r = r1, q3.i = r2;
         q2.r = q3.r * cx[k-1].r - q3.i * cx[k-1].i, q2.i = 
           q3.r * cx[k-1].i + q3.i * cx[k-1].r;
@@ -3038,8 +3046,8 @@ int main(void)
       cy[i-1].r = 0.f, cy[i-1].i = 0.f;
       for (k = 1; k <= n; ++k) {
         arg2 = (real) (k - 1) * arg1;
-        r1 = cos(arg2);
-        r2 = sin(arg2);
+        r1 = FFTPACK_COS(arg2);
+        r2 = FFTPACK_SIN(arg2);
         q3.r = r1, q3.i = r2;
         q2.r = q3.r * cx[k-1].r - q3.i * cx[k-1].i, q2.i = 
           q3.r * cx[k-1].i + q3.i * cx[k-1].r;
diff --git a/mingw-w32-i686.cmake b/mingw-w32-i686.cmake
new file mode 100644
index 0000000..eecd236
--- /dev/null
+++ b/mingw-w32-i686.cmake
@@ -0,0 +1,25 @@
+# Sample toolchain file for building for Windows from an Ubuntu Linux system.
+#
+# Typical usage:
+#    *) install cross compiler: `sudo apt-get install mingw-w64`
+#    *) cd build
+#    *) cmake -DCMAKE_TOOLCHAIN_FILE=~/mingw-w32-i686.cmake ..
+#
+# build for Windows' 32 bit architecture
+
+set(CMAKE_SYSTEM_NAME Windows)
+set(CMAKE_SYSTEM_PROCESSOR x86_64)
+set(TOOLCHAIN_PREFIX i686-w64-mingw32)
+
+# cross compilers to use for C, C++ and Fortran
+set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc)
+set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
+set(CMAKE_RC_COMPILER ${TOOLCHAIN_PREFIX}-windres)
+
+# target environment on the build host system
+set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX})
+
+# modify default behavior of FIND_XXX() commands
+set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
+set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
diff --git a/mingw-w64-x64_64.cmake b/mingw-w64-x64_64.cmake
new file mode 100644
index 0000000..1ed08f0
--- /dev/null
+++ b/mingw-w64-x64_64.cmake
@@ -0,0 +1,25 @@
+# Sample toolchain file for building for Windows from an Ubuntu Linux system.
+#
+# Typical usage:
+#    *) install cross compiler: `sudo apt-get install mingw-w64`
+#    *) cd build
+#    *) cmake -DCMAKE_TOOLCHAIN_FILE=~/mingw-w64-x86_64.cmake ..
+#
+# build for Windows' 64 bit architecture
+
+set(CMAKE_SYSTEM_NAME Windows)
+set(CMAKE_SYSTEM_PROCESSOR x86_64)
+set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)
+
+# cross compilers to use for C, C++ and Fortran
+set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc)
+set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
+set(CMAKE_RC_COMPILER ${TOOLCHAIN_PREFIX}-windres)
+
+# target environment on the build host system
+set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX})
+
+# modify default behavior of FIND_XXX() commands
+set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
+set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
diff --git a/papi_perf_counter.h b/papi_perf_counter.h
new file mode 100644
index 0000000..c8e7943
--- /dev/null
+++ b/papi_perf_counter.h
@@ -0,0 +1,97 @@
+#pragma once
+
+/* for measurement of CPU cycles ..
+ *
+ * requires
+ *   sudo apt-get install libpapi-dev papi-tools
+ * on debian/ubuntu linux distributions
+ *
+ */
+
+#ifdef HAVE_PAPI
+#include <papi.h>
+#endif
+
+#include <stdio.h>
+
+
+struct papi_perf_counter
+{
+    papi_perf_counter()
+        : realTime(0.0F), processTime(0.0F), instructions(0LL), ipc(0.0F)
+        , started(false), finished(false), print_at_destruction(false)
+    { }
+
+    papi_perf_counter(int _start, bool print_at_destruction_ = true)
+        : print_at_destruction(print_at_destruction_)
+    {
+        (void)_start;
+        start();
+    }
+
+    ~papi_perf_counter()
+    {
+        if (print_at_destruction)
+            print(stderr);
+    }
+
+    bool start()
+    {
+        static bool reported_start_error = false;
+#ifdef HAVE_PAPI
+        int ret = PAPI_ipc(&realTime, &processTime, &instructions, &ipc);
+        if (ret && !reported_start_error)
+        {
+            reported_start_error = true;
+            fprintf(stderr, "papi_perf_counter::start(): PAPI_ipc() returned error %d\n", ret);
+        }
+#else
+        if (!reported_start_error)
+        {
+            reported_start_error = true;
+            fprintf(stderr, "papi_perf_counter::start(): no HAVE_PAPI\n");
+        }
+        int ret = 1;
+#endif
+        started = (!ret);
+        finished = false;
+        return started;
+    }
+
+    bool finish()
+    {
+        papi_perf_counter end(1, false);
+        if (started && !finished && end.started)
+        {
+            realTime = end.realTime - realTime;
+            processTime = end.processTime - processTime;
+            instructions = end.instructions - instructions;
+            ipc = end.ipc;
+            finished = true;
+            return true;
+        }
+        return false;
+    }
+
+    void print(FILE *f = stdout)
+    {
+        if (started && !finished)
+            finish();
+        if (!started || !finished)
+            return;
+        double cycles = instructions / ipc;
+        fprintf(f, "real %g, process %g, instructions %lld, ins/cycle %f => cycles %g\n"
+                , realTime, processTime, instructions, ipc, cycles
+                );
+        started = false;
+    }
+
+    float realTime;
+    float processTime;
+    long long instructions;
+    float ipc;
+    bool started;
+    bool finished;
+    bool print_at_destruction;
+};
+
diff --git a/pf_cic.cpp b/pf_cic.cpp
index 34b90c5..2362853 100644
--- a/pf_cic.cpp
+++ b/pf_cic.cpp
@@ -28,6 +28,9 @@ ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
 
+/* gcc requires this for M_PI !? */
+#undef __STRICT_ANSI__
+
 /* include own header first, to see missing includes */
 #include "pf_cic.h"
 #include "fmv.h"
@@ -70,7 +73,7 @@ void *cicddc_init(int factor) {
     s->gain = 1.0f / SHRT_MAX / sineamp / factor / factor / factor; // compensate for gain of 3 integrators
 
     s->sinetable = (int16_t *)malloc(sinesize2 * sizeof(*s->sinetable));
-    double f = 2.0*M_PI / (double)SINESIZE;
+    double f = 2.0 * M_PI / (double)SINESIZE;
     for(i = 0; i < sinesize2; i++) {
         s->sinetable[i] = sineamp * cos(f * i);
     }
diff --git a/pf_conv.cpp b/pf_conv.cpp
new file mode 100644
index 0000000..45e56d5
--- /dev/null
+++ b/pf_conv.cpp
@@ -0,0 +1,322 @@
+
+#include "pf_conv.h"
+
+#include <string.h>
+#include <assert.h>
+
+#include <algorithm>
+
+#if 0
+#include <stdio.h>
+
+#define DPRINT(...) fprintf(stderr, __VA_ARGS__)
+
+#else
+#define DPRINT(...) do { } while (0)
+#endif
+
+
+#ifdef HAVE_MIPP
+#include <mipp.h>
+#endif
+
+
+#ifndef CONV_ARCH_POST
+#error CONV_ARCH_POST not defined
+#endif
+
+#define PP_STRINGIFY(X) #X
+#define PP_TOSTRING(X)  PP_STRINGIFY(X)
+#define PP_CONCAT_IMPL(x, y) x##y
+#define PP_CONCAT(x, y) PP_CONCAT_IMPL( x, y )
+
+#define ARCHFUNCNAME(X) PP_CONCAT(X##_,CONV_ARCH_POST)
+
+
+const char * ARCHFUNCNAME(id)()
+{
+    return PP_TOSTRING(CONV_ARCH_POST);
+}
+
+
+int ARCHFUNCNAME(conv_float_simd_size)()
+{
+#if defined(MIPP_NO_INTRINSICS) || !defined(HAVE_MIPP)
+    // have a completely MIPP independent implementation
+    return 1;
+#else
+    return mipp::N<float>();
+#endif
+}
+
+
+void ARCHFUNCNAME(conv_float_move_rest)(float * RESTRICT s, conv_buffer_state * RESTRICT state)
+{
+    int R = state->size - state->offset;    // this many samples from prev conv_float were not processed
+    if (R > 0)
+    {
+        // memmove(s, &s[state->offset], R * sizeof(s[0]));   // move them to the begin
+        std::copy(&s[state->offset], &s[state->size], s);
+    }
+    else
+        R = 0;
+    state->offset = 0;      // data - to be processed - is at begin
+    state->size = R;        // this many unprocessed samples
+}
+
+
+void ARCHFUNCNAME(conv_cplx_move_rest)(complexf * RESTRICT s, conv_buffer_state * RESTRICT state)
+{
+    int R = state->size - state->offset;    // this many samples from prev conv_float were not processed
+    if (R > 0)
+    {
+        // memmove(s, &s[state->offset], R * sizeof(s[0]));   // move them to the begin
+        std::copy(&s[state->offset], &s[state->size], s);
+    }
+    else
+        R = 0;
+    state->offset = 0;      // data - to be processed - is at begin
+    state->size = R;        // this many unprocessed samples
+}
+
+
+#if defined(MIPP_NO_INTRINSICS)
+// have a completely MIPP independent implementation
+// #error missing HAVE_MIPP: there is no MIPP-independent implementation
+
+int ARCHFUNCNAME(conv_float_inplace)(
+        float * RESTRICT s, conv_buffer_state * RESTRICT state,
+        const float * RESTRICT filter, const int sz_filter
+        )
+{
+    const int off0 = state->offset;
+    const int sz_s = state->size;
+    int offset;
+
+    for ( offset = off0; offset + sz_filter <= sz_s; ++offset)
+    {
+        float accu = 0.0F;
+        for (int k = 0; k < sz_filter; ++k)
+            accu += s[offset+k] * filter[k];
+        s[offset] = accu;
+    }
+
+    state->offset = offset;
+    return offset - off0;
+}
+
+
+int ARCHFUNCNAME(conv_float_oop)(
+        const float * RESTRICT s, conv_buffer_state * RESTRICT state,
+        const float * RESTRICT filter, const int sz_filter,
+        float * RESTRICT y
+        )
+{
+    const int off0 = state->offset;
+    const int sz_s = state->size;
+    int offset;
+
+    for ( offset = off0; offset + sz_filter <= sz_s; ++offset)
+    {
+        float accu = 0.0F;
+        for (int k = 0; k < sz_filter; ++k)
+            accu += s[offset+k] * filter[k];
+        y[offset] = accu;
+    }
+
+    state->offset = offset;
+    return offset - off0;
+}
+
+
+int ARCHFUNCNAME(conv_cplx_float_oop)(
+        const complexf * RESTRICT s_cplx, conv_buffer_state * RESTRICT state,
+        const float * RESTRICT filter, const int sz_filter,
+        complexf * RESTRICT y_cplx
+        )
+{
+    const int off0 = state->offset;
+    const int sz_s = state->size;
+    const int sz_f = sz_filter;
+    int offset;
+
+    for ( offset = off0; offset + sz_f <= sz_s; ++offset)
+    {
+        float accu_re = 0.0F;
+        float accu_im = 0.0F;
+        for (int k = 0; k < sz_filter; ++k)
+        {
+            accu_re = s_cplx[offset+k].i * filter[k];   // accu += rS * rH;
+            accu_im = s_cplx[offset+k].q * filter[k];   // accu += rS * rH;
+        }
+        y_cplx[offset].i = accu_re;  // == hadd() == sum of real parts
+        y_cplx[offset].q = accu_im;  // == hadd() == sum of imag parts
+    }
+
+    state->offset = offset;
+    return offset - off0;
+}
+
+
+#elif defined(HAVE_MIPP)
+
+
+int ARCHFUNCNAME(conv_float_inplace)(
+        float * RESTRICT s, conv_buffer_state * RESTRICT state,
+        const float * RESTRICT filter, const int sz_filter
+        )
+{
+    assert( (sz_filter % mipp::N<float>()) == 0 );  // size of filter must be divisible by conv_float_simd_size()
+
+    mipp::Reg<float> accu, rS, rH;
+    const int off0 = state->offset;
+    const int sz_s = state->size;
+    int offset;
+
+    for ( offset = off0; offset + sz_filter <= sz_s; ++offset)
+    {
+        accu.set0();
+        for (int k = 0; k < sz_filter; k += mipp::N<float>())
+        {
+            rS.load(&s[offset+k]);
+            rH.load(&filter[k]);
+            accu = mipp::fmadd(rS, rH, accu);   // accu += rS * rH;
+        }
+        s[offset] = accu.sum();    // == hadd()
+    }
+
+    state->offset = offset;
+    return offset - off0;
+}
+
+
+int ARCHFUNCNAME(conv_float_oop)(
+        const float * RESTRICT s, conv_buffer_state * RESTRICT state,
+        const float * RESTRICT filter, const int sz_filter,
+        float * RESTRICT y
+        )
+{
+    assert( (sz_filter % mipp::N<float>()) == 0 );  // size of filter must be divisible by conv_float_simd_size()
+
+    mipp::Reg<float> accu, rS, rH;
+    const int off0 = state->offset;
+    const int sz_s = state->size;
+    int offset;
+
+    for ( offset = off0; offset + sz_filter <= sz_s; ++offset)
+    {
+        accu.set0();
+        for (int k = 0; k < sz_filter; k += mipp::N<float>())
+        {
+            rS.loadu(&s[offset+k]);
+            rH.load(&filter[k]);
+            accu = mipp::fmadd(rS, rH, accu);   // accu += rS * rH;
+        }
+        y[offset] = accu.sum();    // == hadd()
+    }
+
+    state->offset = offset;
+    return offset - off0;
+}
+
+
+int ARCHFUNCNAME(conv_cplx_float_oop)(
+        const complexf * RESTRICT s_cplx, conv_buffer_state * RESTRICT state,
+        const float * RESTRICT filter, const int sz_filter,
+        complexf * RESTRICT y_cplx
+        )
+{
+    assert( (sz_filter % mipp::N<float>()) == 0 );  // size of filter must be divisible by conv_float_simd_size()
+    const float * RESTRICT s = &(s_cplx[0].i);
+    float * RESTRICT y = &(y_cplx[0].i);
+
+    mipp::Regx2<float> accu_x2, rS_x2, H_x2;
+    const int off0 = 2 * state->offset;
+    const int sz_s = 2 * state->size;
+    const int sz_f2 = 2 * sz_filter;
+    int offset;
+
+    for ( offset = off0; offset + sz_f2 <= sz_s; offset += 2)
+    {
+        accu_x2.val[0].set0();
+        accu_x2.val[1].set0();
+        for (int k = 0; k < sz_filter; k += mipp::N<float>())
+        {
+            mipp::Reg<float> rH;
+            rS_x2.loadu(&s[offset+2*k]);
+            rH.load(&filter[k]);
+            H_x2 = mipp::interleave<float>(rH, rH);
+            accu_x2.val[0] = mipp::fmadd(rS_x2.val[0], H_x2.val[0], accu_x2.val[0]);   // accu += rS * rH;
+            accu_x2.val[1] = mipp::fmadd(rS_x2.val[1], H_x2.val[1], accu_x2.val[1]);   // accu += rS * rH;
+        }
+        H_x2 = mipp::deinterleave(accu_x2);
+        y[offset]   = H_x2.val[0].sum();  // == hadd() == sum of real parts
+        y[offset+1] = H_x2.val[1].sum();  // == hadd() == sum of imag parts
+    }
+
+    state->offset = offset /2;
+    return (offset - off0) / 2;
+}
+
+#endif
+
+
+static const conv_f_ptrs conv_ptrs =
+{
+    PP_TOSTRING(CONV_ARCH_POST),
+#ifndef MIPP_NO_INTRINSICS
+    1,
+#else
+    0,
+#endif
+
+    ARCHFUNCNAME(id),
+    ARCHFUNCNAME(conv_float_simd_size),
+
+#if defined(MIPP_NO_INTRINSICS) || defined(HAVE_MIPP)
+    ARCHFUNCNAME(conv_float_move_rest),
+    ARCHFUNCNAME(conv_float_inplace),
+    ARCHFUNCNAME(conv_float_oop),
+
+    ARCHFUNCNAME(conv_cplx_move_rest),
+    ARCHFUNCNAME(conv_cplx_float_oop)
+#else
+    nullptr,
+    nullptr,
+    nullptr,
+
+    nullptr,
+    nullptr
+#endif
+};
+
+
+const conv_f_ptrs* ARCHFUNCNAME(conv_ptrs)()
+{
+    DPRINT("arch pointer for '%s':\n", conv_ptrs.id);
+    if (!strcmp(conv_ptrs.id, "none"))
+        return &conv_ptrs;
+
+#if defined(MIPP_NO_INTRINSICS)
+    DPRINT("arch pointer for '%s' - BUT defined(MIPP_NO_INTRINSICS)\n", conv_ptrs.id);
+    return &conv_ptrs;
+#elif defined(HAVE_MIPP)
+    DPRINT("arch pointer for '%s' - defined(HAVE_MIPP)\n", conv_ptrs.id);
+    DPRINT("'%s': conv_ptrs.using_mipp %d\n", conv_ptrs.id, conv_ptrs.using_mipp);
+    DPRINT("'%s': simd_size() %d\n", conv_ptrs.id, conv_ptrs.fp_conv_float_simd_size());
+    if (conv_ptrs.using_mipp && conv_ptrs.fp_conv_float_simd_size() > 1)
+        return &conv_ptrs;
+    else
+        DPRINT("arch pointer for '%s': HAVE_MIPP BUT using_mipp %d, float_simd_size %d\n", conv_ptrs.id, conv_ptrs.using_mipp, conv_ptrs.fp_conv_float_simd_size());
+#else
+    DPRINT("arch pointer for '%s': neither MIPP_NO_INTRINSICS nor HAVE_MIPP\n", conv_ptrs.id);
+#endif
+    DPRINT("arch pointer for '%s' => nullptr\n", conv_ptrs.id);
+    return nullptr;
+}
+
+#if defined(__cplusplus) && (__cplusplus >= 201703L)
+[[maybe_unused]]
+#endif
+static f_conv_ptrs test_f_ptrs = ARCHFUNCNAME(conv_ptrs);
+
diff --git a/pf_conv.h b/pf_conv.h
new file mode 100644
index 0000000..0194b98
--- /dev/null
+++ b/pf_conv.h
@@ -0,0 +1,109 @@
+#pragma once
+
+/* pf_conv.h/.cpp implements linear "slow" convolution.
+ * this code is primarily for test/demonstration of runtime dispatching.
+ * each "kernel" is compiled with different compiler/architecture options,
+ * that activates different implementations in the MIPP headers.
+ *
+ * the dispatcher library 'pf_conv_dispatcher' collects (links agains)
+ * all the pf_conv_arch_<opt> libraries ..
+ * and provides the  get_all_conv_arch_ptrs() function,
+ * which delivers an array of pointers to the struct (conv_f_ptrs)
+ * containing the function pointers for the different implementations.
+ *
+ * requirement(s):
+ * - installed MIPP headers
+ * - compiler definitions for the different architecture types:
+ *   see CMakeLists.txt CONV_ARCH_MSVC_AMD64, CONV_ARCH_GCC_ARM32NEON, ..
+ * - one cmake library target pf_conv_arch_<opt> for each architecture option.
+ *   each one gets it's specific  architecture/compiler  options
+ *    utilizing the target_set_cxx_arch_option() macro in the CMakeLists.txt
+ */
+
+#include "pf_cplx.h"
+
+#if defined(_MSC_VER)
+#  define RESTRICT __restrict
+#elif defined(__GNUC__)
+#  define RESTRICT __restrict
+#else
+#  define RESTRICT
+#endif
+
+
+struct conv_buffer_state
+{
+    int offset; // sample index where data (to process) starts
+    int size;   // actual - or previous - size in amount of samples from buffer start (NOT offset)
+};
+
+// declare provided function pointer types
+
+typedef const char * (*f_conv_id)();
+
+typedef int  (*f_conv_float_simd_size)();
+
+typedef void (*f_conv_float_move_rest)(float * RESTRICT s, conv_buffer_state * RESTRICT state);
+typedef void (*f_conv_cplx_move_rest)(complexf * RESTRICT s, conv_buffer_state * RESTRICT state);
+
+typedef int  (*f_conv_float_inplace)(
+        float * RESTRICT s, conv_buffer_state * RESTRICT state,
+        const float * RESTRICT filter, const int sz_filter
+        );
+
+typedef int  (*f_conv_float_oop)(
+        const float * RESTRICT s, conv_buffer_state * RESTRICT state,
+        const float * RESTRICT filter, const int sz_filter,
+        float * RESTRICT y
+        );
+
+typedef int  (*f_conv_cplx_float_oop)(
+        const complexf * RESTRICT s, conv_buffer_state * RESTRICT state,
+        const float * RESTRICT filter, const int sz_filter,
+        complexf * RESTRICT y
+        );
+
+
+// struct with the provided function pointers
+struct conv_f_ptrs
+{
+    const char * id;
+    const int using_mipp;
+    f_conv_id               fp_id;
+    f_conv_float_simd_size  fp_conv_float_simd_size;
+
+    f_conv_float_move_rest  fp_conv_float_move_rest;
+    f_conv_float_inplace    fp_conv_float_inplace;
+    f_conv_float_oop        fp_conv_float_oop;
+
+    f_conv_cplx_move_rest   fp_conv_cplx_move_rest;
+    f_conv_cplx_float_oop   fp_conv_cplx_float_oop;
+};
+
+typedef const conv_f_ptrs * ptr_to_conv_f_ptrs;
+
+// function pointer type, delivering the struct with the function pointers
+typedef const conv_f_ptrs* (*f_conv_ptrs)();
+
+
+// helper for systematic function names
+#define CONV_FN_ARCH(FN, ARCH) FN##_##ARCH
+
+// declare all functions - returning the structs with the function pointers
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, none)();  // = conv_ptrs_none()
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, dflt)();  // simd / mipp is activated
+
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, sse3)();  // = conv_ptrs_sse3()
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, sse4)();
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, avx)();
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, avx2)();
+
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, sse2)();
+//extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, avx)();  // already declared
+//extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, avx2)(); // already declared
+
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, neon_vfpv4)();    // for armv7l / 32-bit ARM
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, neon_rpi3_a53)();
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, neon_rpi4_a72)();
+
+extern const conv_f_ptrs* CONV_FN_ARCH(conv_ptrs, armv8a)();  // for aarch64
diff --git a/pf_conv_dispatcher.cpp b/pf_conv_dispatcher.cpp
new file mode 100644
index 0000000..8a5f725
--- /dev/null
+++ b/pf_conv_dispatcher.cpp
@@ -0,0 +1,61 @@
+
+#include "pf_conv_dispatcher.h"
+
+#if 0
+#include <stdio.h>
+
+#define DPRINT(...) fprintf(stderr, __VA_ARGS__)
+
+#else
+#define DPRINT(...) do { } while (0)
+#endif
+
+
+#define N_DEFAULT_ARCHES  2
+// 0 is "none"
+// 1 "dflt"
+
+ptr_to_conv_f_ptrs * get_all_conv_arch_ptrs(int * p_num_arch)
+{
+    static ptr_to_conv_f_ptrs * all_arches = nullptr;
+    static int n_arch = 0;
+    if (!all_arches)
+    {
+        n_arch = N_DEFAULT_ARCHES;
+        // @TODO: runtime check if actual CPU supports specific architecture
+#if defined(CONV_ARCH_GCC_AMD64)
+        static const conv_f_ptrs *conv_arch_ptrs[N_DEFAULT_ARCHES+4] = {0};
+        DPRINT("CONV_ARCH_GCC_AMD64: sse3, sse4, avx, avx2\n");
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, sse3)();
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, sse4)();
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, avx) ();
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, avx2)();
+#elif defined(CONV_ARCH_MSVC_AMD64)
+        static const conv_f_ptrs *conv_arch_ptrs[N_DEFAULT_ARCHES+3] = {0};
+        DPRINT("CONV_ARCH_MSVC_AMD64: sse2, avx, avx2\n");
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, sse2)();
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, avx) ();
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, avx2)();
+#elif defined(CONV_ARCH_GCC_ARM32NEON)
+        static const conv_f_ptrs *conv_arch_ptrs[N_DEFAULT_ARCHES+3] = {0};
+        DPRINT("CONV_ARCH_GCC_ARM32NEON: neon_vfpv4, neon_rpi3_a53\n");
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, neon_vfpv4)();
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, neon_rpi3_a53)();
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, neon_rpi4_a72)();
+#elif defined(CONV_ARCH_GCC_AARCH64)
+        static const conv_f_ptrs *conv_arch_ptrs[N_DEFAULT_ARCHES+1] = {0};
+        DPRINT("CONV_ARCH_GCC_AARCH64: -\n");
+        conv_arch_ptrs[n_arch++] = CONV_FN_ARCH(conv_ptrs, armv8a)();
+#else
+        static const conv_f_ptrs *conv_arch_ptrs[N_DEFAULT_ARCHES] = {0};
+        DPRINT("unknown CONV_ARCH: -\n");
+#endif
+        conv_arch_ptrs[0] = CONV_FN_ARCH(conv_ptrs, none)();
+        conv_arch_ptrs[1] = CONV_FN_ARCH(conv_ptrs, dflt)();
+        all_arches = conv_arch_ptrs;
+    }
+    if (p_num_arch)
+        *p_num_arch = n_arch;
+    return all_arches;
+}
+
diff --git a/pf_conv_dispatcher.h b/pf_conv_dispatcher.h
new file mode 100644
index 0000000..eb70d5e
--- /dev/null
+++ b/pf_conv_dispatcher.h
@@ -0,0 +1,6 @@
+#pragma once
+
+#include "pf_conv.h"
+
+ptr_to_conv_f_ptrs * get_all_conv_arch_ptrs(int * p_num_arch);
+
diff --git a/pf_cplx.h b/pf_cplx.h
new file mode 100644
index 0000000..61d8486
--- /dev/null
+++ b/pf_cplx.h
@@ -0,0 +1,44 @@
+/*
+This software is part of pffft/pfdsp, a set of simple DSP routines.
+
+Copyright (c) 2020  Hayati Ayguen <h_ayguen@web.de>
+All rights reserved.
+
+Redistribution and use in source and binary forms, with or without
+modification, are permitted provided that the following conditions are met:
+    * Redistributions of source code must retain the above copyright
+      notice, this list of conditions and the following disclaimer.
+    * Redistributions in binary form must reproduce the above copyright
+      notice, this list of conditions and the following disclaimer in the
+      documentation and/or other materials provided with the distribution.
+    * Neither the name of the copyright holder nor the
+      names of its contributors may be used to endorse or promote products
+      derived from this software without specific prior written permission.
+
+THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
+ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
+WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
+DISCLAIMED. IN NO EVENT SHALL ANDRAS RETZLER BE LIABLE FOR ANY
+DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
+(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
+LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
+ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
+(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
+SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+*/
+
+#pragma once
+
+/*
+   _____                      _
+  / ____|                    | |
+ | |     ___  _ __ ___  _ __ | | _____  __
+ | |    / _ \| '_ ` _ \| '_ \| |/ _ \ \/ /
+ | |___| (_) | | | | | | |_) | |  __/>  <
+  \_____\___/|_| |_| |_| .__/|_|\___/_/\_\
+                       | |
+                       |_|
+*/
+
+typedef struct complexf_s { float i; float q; } complexf;
+
diff --git a/pf_mixer.cpp b/pf_mixer.cpp
index 0f2c310..504e059 100644
--- a/pf_mixer.cpp
+++ b/pf_mixer.cpp
@@ -69,7 +69,7 @@ SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 
 #ifndef PFFFT_SIMD_DISABLE
 #if (defined(__x86_64__) || defined(_M_X64) || defined(i386) || defined(_M_IX86))
-  #pragma message "Manual SSE x86/x64 optimizations are ON"
+  #pragma message("Manual SSE x86/x64 optimizations are ON")
   #include <xmmintrin.h>
   #define HAVE_SSE_INTRINSICS 1
   
@@ -139,7 +139,7 @@ int have_sse_shift_mixer_impl()
 /**************/
 
 PF_TARGET_CLONES
-float shift_math_cc(complexf *input, complexf* output, int input_size, float rate, float starting_phase)
+float shift_math_cc(const complexf *input, complexf* output, int input_size, float rate, float starting_phase)
 {
     rate*=2;
     //Shifts the complex spectrum. Basically a complex mixer. This version uses cmath.
@@ -148,8 +148,8 @@ float shift_math_cc(complexf *input, complexf* output, int input_size, float rat
     float cosval, sinval;
     for(int i=0;i<input_size; i++)
     {
-        cosval=cos(phase);
-        sinval=sin(phase);
+        cosval=cosf(phase);
+        sinval=sinf(phase);
         //we multiply two complex numbers.
         //how? enter this to maxima (software) for explanation:
         //   (a+b*%i)*(c+d*%i), rectform;
@@ -175,7 +175,7 @@ shift_table_data_t shift_table_init(int table_size)
     output.table_size=table_size;
     for(int i=0;i<table_size;i++)
     {
-        output.table[i]=sin(((float)i/table_size)*(PI/2));
+        output.table[i]=sinf(((float)i/table_size)*(PI/2));
     }
     return output;
 }
@@ -197,9 +197,9 @@ float shift_table_cc(complexf* input, complexf* output, int input_size, float ra
     for(int i=0;i<input_size; i++) //@shift_math_cc
     {
         int sin_index, cos_index, temp_index, sin_sign, cos_sign;
-        int quadrant=phase/(PI/2); //between 0 and 3
-        float vphase=phase-quadrant*(PI/2);
-        sin_index=(vphase/(PI/2))*table_data.table_size;
+        int quadrant=(int)(phase/(PI/2.0f)); //between 0 and 3
+        float vphase=phase-quadrant*(PI/2.0f);
+        sin_index=(int)(vphase/(PI/2.0f))*table_data.table_size;
         cos_index=table_data.table_size-1-sin_index;
         if(quadrant&1) //in quadrant 1 and 3
         {
@@ -235,8 +235,8 @@ shift_addfast_data_t shift_addfast_init(float rate)
     output.phase_increment=2*rate*PI;
     for(int i=0;i<4;i++)
     {
-        output.dsin[i]=sin(output.phase_increment*(i+1));
-        output.dcos[i]=cos(output.phase_increment*(i+1));
+        output.dsin[i]=sinf(output.phase_increment*(i+1));
+        output.dcos[i]=cosf(output.phase_increment*(i+1));
     }
     return output;
 }
@@ -253,9 +253,9 @@ float shift_addfast_cc(complexf *input, complexf* output, int input_size, shift_
 {
     //input_size should be multiple of 4
     //fprintf(stderr, "shift_addfast_cc: input_size = %d\n", input_size);
-    float cos_start=cos(starting_phase);
-    float sin_start=sin(starting_phase);
-    float register cos_vals_0, cos_vals_1, cos_vals_2, cos_vals_3,
+    float cos_start=cosf(starting_phase);
+    float sin_start=sinf(starting_phase);
+    float cos_vals_0, cos_vals_1, cos_vals_2, cos_vals_3,
         sin_vals_0, sin_vals_1, sin_vals_2, sin_vals_3,
         dsin_0 = d->dsin[0], dsin_1 = d->dsin[1], dsin_2 = d->dsin[2], dsin_3 = d->dsin[3],
         dcos_0 = d->dcos[0], dcos_1 = d->dcos[1], dcos_2 = d->dcos[2], dcos_3 = d->dcos[3];
@@ -293,9 +293,9 @@ float shift_addfast_inp_c(complexf *in_out, int N_cplx, shift_addfast_data_t* d,
 {
     //input_size should be multiple of 4
     //fprintf(stderr, "shift_addfast_cc: input_size = %d\n", input_size);
-    float cos_start=cos(starting_phase);
-    float sin_start=sin(starting_phase);
-    float register tmp_inp_cos, tmp_inp_sin,
+    float cos_start=cosf(starting_phase);
+    float sin_start=sinf(starting_phase);
+    float tmp_inp_cos, tmp_inp_sin,
         cos_vals_0, cos_vals_1, cos_vals_2, cos_vals_3,
         sin_vals_0, sin_vals_1, sin_vals_2, sin_vals_3,
         dsin_0 = d->dsin[0], dsin_1 = d->dsin[1], dsin_2 = d->dsin[2], dsin_3 = d->dsin[3],
@@ -343,8 +343,8 @@ shift_unroll_data_t shift_unroll_init(float rate, int size)
         myphase += output.phase_increment;
         while(myphase>PI) myphase-=2*PI;
         while(myphase<-PI) myphase+=2*PI;
-        output.dsin[i]=sin(myphase);
-        output.dcos[i]=cos(myphase);
+        output.dsin[i]=sinf(myphase);
+        output.dcos[i]=cosf(myphase);
     }
     return output;
 }
@@ -364,9 +364,9 @@ float shift_unroll_cc(complexf *input, complexf* output, int input_size, shift_u
 {
     //input_size should be multiple of 4
     //fprintf(stderr, "shift_addfast_cc: input_size = %d\n", input_size);
-    float cos_start = cos(starting_phase);
-    float sin_start = sin(starting_phase);
-    register float cos_val = cos_start, sin_val = sin_start;
+    float cos_start = cosf(starting_phase);
+    float sin_start = sinf(starting_phase);
+    float cos_val = cos_start, sin_val = sin_start;
     for(int i=0;i<input_size; i++)
     {
         iof(output,i) = cos_val*iof(input,i) - sin_val*qof(input,i);
@@ -384,13 +384,13 @@ float shift_unroll_cc(complexf *input, complexf* output, int input_size, shift_u
 PF_TARGET_CLONES
 float shift_unroll_inp_c(complexf* in_out, int size, shift_unroll_data_t* d, float starting_phase)
 {
-    float cos_start = cos(starting_phase);
-    float sin_start = sin(starting_phase);
-    register float cos_val = cos_start, sin_val = sin_start;
+    float cos_start = cosf(starting_phase);
+    float sin_start = sinf(starting_phase);
+    float cos_val = cos_start, sin_val = sin_start;
     for(int i=0;i<size; i++)
     {
-        register float inp_i = iof(in_out,i);
-        register float inp_q = qof(in_out,i);
+        float inp_i = iof(in_out,i);
+        float inp_q = qof(in_out,i);
         iof(in_out,i) = cos_val*inp_i - sin_val*inp_q;
         qof(in_out,i) = sin_val*inp_i + cos_val*inp_q;
         // calculate complex phasor for next iteration
@@ -420,8 +420,8 @@ shift_limited_unroll_data_t shift_limited_unroll_init(float rate)
         myphase += output.phase_increment;
         while(myphase>PI) myphase-=2*PI;
         while(myphase<-PI) myphase+=2*PI;
-        output.dcos[i] = cos(myphase);
-        output.dsin[i] = sin(myphase);
+        output.dcos[i] = cosf(myphase);
+        output.dsin[i] = sinf(myphase);
     }
     output.complex_phase.i = 1.0F;
     output.complex_phase.q = 0.0F;
@@ -433,7 +433,7 @@ void shift_limited_unroll_cc(const complexf *input, complexf* output, int size,
 {
     float cos_start = d->complex_phase.i;
     float sin_start = d->complex_phase.q;
-    register float cos_val = cos_start, sin_val = sin_start, mag;
+    float cos_val = cos_start, sin_val = sin_start, mag;
     while (size > 0)
     {
         int N = (size >= PF_SHIFT_LIMITED_UNROLL_SIZE) ? PF_SHIFT_LIMITED_UNROLL_SIZE : size;
@@ -471,7 +471,7 @@ void shift_limited_unroll_inp_c(complexf* in_out, int N_cplx, shift_limited_unro
     // "vals := starts := phase_state"
     float cos_start = d->complex_phase.i;
     float sin_start = d->complex_phase.q;
-    register float cos_val = cos_start, sin_val = sin_start, mag;
+    float cos_val = cos_start, sin_val = sin_start, mag;
     while (N_cplx)
     {
         int N = (N_cplx >= PF_SHIFT_LIMITED_UNROLL_SIZE) ? PF_SHIFT_LIMITED_UNROLL_SIZE : N_cplx;
@@ -532,8 +532,8 @@ shift_limited_unroll_A_sse_data_t shift_limited_unroll_A_sse_init(float relative
             while(myphase>PI) myphase-=2*PI;
             while(myphase<-PI) myphase+=2*PI;
         }
-        output.dcos[i] = cos(myphase);
-        output.dsin[i] = sin(myphase);
+        output.dcos[i] = cosf(myphase);
+        output.dsin[i] = sinf(myphase);
         for (int k = 1; k < PF_SHIFT_LIMITED_SIMD_SZ; k++)
         {
             output.dcos[i+k] = output.dcos[i];
@@ -547,8 +547,8 @@ shift_limited_unroll_A_sse_data_t shift_limited_unroll_A_sse_init(float relative
     myphase = phase_start_rad;
     for (int i = 0; i < PF_SHIFT_LIMITED_SIMD_SZ; i++)
     {
-        output.phase_state_i[i] = cos(myphase);
-        output.phase_state_q[i] = sin(myphase);
+        output.phase_state_i[i] = cosf(myphase);
+        output.phase_state_q[i] = sinf(myphase);
         myphase += output.phase_increment;
         while(myphase>PI) myphase-=2*PI;
         while(myphase<-PI) myphase+=2*PI;
@@ -650,8 +650,8 @@ shift_limited_unroll_B_sse_data_t shift_limited_unroll_B_sse_init(float relative
             while(myphase>PI) myphase-=2*PI;
             while(myphase<-PI) myphase+=2*PI;
         }
-        output.dtrig[i+0] = cos(myphase);
-        output.dtrig[i+1] = sin(myphase);
+        output.dtrig[i+0] = cosf(myphase);
+        output.dtrig[i+1] = sinf(myphase);
         output.dtrig[i+2] = output.dtrig[i+0];
         output.dtrig[i+3] = output.dtrig[i+1];
     }
@@ -662,8 +662,8 @@ shift_limited_unroll_B_sse_data_t shift_limited_unroll_B_sse_init(float relative
     myphase = phase_start_rad;
     for (int i = 0; i < PF_SHIFT_LIMITED_SIMD_SZ; i++)
     {
-        output.phase_state_i[i] = cos(myphase);
-        output.phase_state_q[i] = sin(myphase);
+        output.phase_state_i[i] = cosf(myphase);
+        output.phase_state_q[i] = sinf(myphase);
         myphase += output.phase_increment;
         while(myphase>PI) myphase-=2*PI;
         while(myphase<-PI) myphase+=2*PI;
@@ -763,8 +763,8 @@ shift_limited_unroll_C_sse_data_t shift_limited_unroll_C_sse_init(float relative
             while(myphase>PI) myphase-=2*PI;
             while(myphase<-PI) myphase+=2*PI;
         }
-        output.dinterl_trig[2*i] = cos(myphase);
-        output.dinterl_trig[2*i+4] = sin(myphase);
+        output.dinterl_trig[2*i] = cosf(myphase);
+        output.dinterl_trig[2*i+4] = sinf(myphase);
         for (int k = 1; k < PF_SHIFT_LIMITED_SIMD_SZ; k++)
         {
             output.dinterl_trig[2*i+k] = output.dinterl_trig[2*i];
@@ -778,8 +778,8 @@ shift_limited_unroll_C_sse_data_t shift_limited_unroll_C_sse_init(float relative
     myphase = phase_start_rad;
     for (int i = 0; i < PF_SHIFT_LIMITED_SIMD_SZ; i++)
     {
-        output.phase_state_i[i] = cos(myphase);
-        output.phase_state_q[i] = sin(myphase);
+        output.phase_state_i[i] = cosf(myphase);
+        output.phase_state_q[i] = sinf(myphase);
         myphase += output.phase_increment;
         while(myphase>PI) myphase-=2*PI;
         while(myphase<-PI) myphase+=2*PI;
@@ -899,7 +899,7 @@ void shift_recursive_osc_update_rate(float rate, shift_recursive_osc_conf_t *con
 {
     // constants for single phase step
     float phase_increment_s = rate*PI;
-    float k1 = tan(0.5*phase_increment_s);
+    float k1 = tanf(0.5f*phase_increment_s);
     float k2 = 2*k1 /(1 + k1 * k1);
     for (int j=1; j<PF_SHIFT_RECURSIVE_SIMD_SZ; j++)
     {
@@ -916,7 +916,7 @@ void shift_recursive_osc_update_rate(float rate, shift_recursive_osc_conf_t *con
     float phase_increment_b = phase_increment_s * PF_SHIFT_RECURSIVE_SIMD_SZ;
     while(phase_increment_b > PI) phase_increment_b-=2*PI;
     while(phase_increment_b < -PI) phase_increment_b+=2*PI;
-    conf->k1 = tan(0.5*phase_increment_b);
+    conf->k1 = tanf(0.5f*phase_increment_b);
     conf->k2 = 2*conf->k1 / (1 + conf->k1 * conf->k1);
 }
 
@@ -924,8 +924,8 @@ void shift_recursive_osc_init(float rate, float starting_phase, shift_recursive_
 {
     if (starting_phase != 0.0F)
     {
-        state->u_cos[0] = cos(starting_phase);
-        state->v_sin[0] = sin(starting_phase);
+        state->u_cos[0] = cosf(starting_phase);
+        state->v_sin[0] = sinf(starting_phase);
     }
     else
     {
@@ -1044,7 +1044,7 @@ void shift_recursive_osc_sse_update_rate(float rate, shift_recursive_osc_sse_con
 {
     // constants for single phase step
     float phase_increment_s = rate*PI;
-    float k1 = tan(0.5*phase_increment_s);
+    float k1 = tanf(0.5f*phase_increment_s);
     float k2 = 2*k1 /(1 + k1 * k1);
     for (int j=1; j<PF_SHIFT_RECURSIVE_SIMD_SSE_SZ; j++)
     {
@@ -1061,7 +1061,7 @@ void shift_recursive_osc_sse_update_rate(float rate, shift_recursive_osc_sse_con
     float phase_increment_b = phase_increment_s * PF_SHIFT_RECURSIVE_SIMD_SSE_SZ;
     while(phase_increment_b > PI) phase_increment_b-=2*PI;
     while(phase_increment_b < -PI) phase_increment_b+=2*PI;
-    conf->k1 = tan(0.5*phase_increment_b);
+    conf->k1 = tanf(0.5f*phase_increment_b);
     conf->k2 = 2*conf->k1 / (1 + conf->k1 * conf->k1);
 }
 
@@ -1070,8 +1070,8 @@ void shift_recursive_osc_sse_init(float rate, float starting_phase, shift_recurs
 {
     if (starting_phase != 0.0F)
     {
-        state->u_cos[0] = cos(starting_phase);
-        state->v_sin[0] = sin(starting_phase);
+        state->u_cos[0] = cosf(starting_phase);
+        state->v_sin[0] = sinf(starting_phase);
     }
     else
     {
diff --git a/pf_mixer.h b/pf_mixer.h
index f407c21..e153ad0 100644
--- a/pf_mixer.h
+++ b/pf_mixer.h
@@ -33,24 +33,13 @@ SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 #include <stdio.h>
 #include <stdint.h>
 
+#include "pf_cplx.h"
+
 #ifdef __cplusplus
 extern "C" {
 #endif
 
 
-/*
-   _____                      _
-  / ____|                    | |
- | |     ___  _ __ ___  _ __ | | _____  __
- | |    / _ \| '_ ` _ \| '_ \| |/ _ \ \/ /
- | |___| (_) | | | | | | |_) | |  __/>  <
-  \_____\___/|_| |_| |_| .__/|_|\___/_/\_\
-                       | |
-                       |_|
-*/
-
-typedef struct complexf_s { float i; float q; } complexf;
-
 // =================================================================================
 
 int have_sse_shift_mixer_impl();
@@ -62,7 +51,7 @@ int have_sse_shift_mixer_impl();
 /*** ALGO A ***/
 /**************/
 
-float shift_math_cc(complexf *input, complexf* output, int input_size, float rate, float starting_phase);
+float shift_math_cc(const complexf *input, complexf* output, int input_size, float rate, float starting_phase);
 
 
 /*********************************************************************/
diff --git a/pffft.c b/pffft.c
index 059f2d7..4862a4f 100644
--- a/pffft.c
+++ b/pffft.c
@@ -110,6 +110,9 @@
 #define FUNC_ALIGNED_MALLOC        pffft_aligned_malloc
 #define FUNC_ALIGNED_FREE          pffft_aligned_free
 #define FUNC_SIMD_SIZE             pffft_simd_size
+#define FUNC_MIN_FFT_SIZE          pffft_min_fft_size
+#define FUNC_IS_VALID_SIZE         pffft_is_valid_size
+#define FUNC_NEAREST_SIZE          pffft_nearest_transform_size
 #define FUNC_SIMD_ARCH             pffft_simd_arch
 #define FUNC_VALIDATE_SIMD_A       validate_pffft_simd
 #define FUNC_VALIDATE_SIMD_EX      validate_pffft_simd_ex
diff --git a/pffft.h b/pffft.h
index 31bb731..7ad925c 100644
--- a/pffft.h
+++ b/pffft.h
@@ -117,7 +117,7 @@ extern "C" {
 
      Transforms are not scaled: PFFFT_BACKWARD(PFFFT_FORWARD(x)) = N*x.
      Typically you will want to scale the backward transform by 1/N.
-     
+
      The 'work' pointer should point to an area of N (2*N for complex
      fft) floats, properly aligned. If 'work' is NULL, then stack will
      be used instead (this is probably the best strategy for small
@@ -125,6 +125,19 @@ extern "C" {
      there's no sufficient amount of memory, usually leading to a crash!
      Use the heap with pffft_aligned_malloc() in this case.
 
+     For a real forward transform (PFFFT_REAL | PFFFT_FORWARD) with real
+     input with input(=transformation) length N, the output array is
+     'mostly' complex:
+       index k in 1 .. N/2 -1  corresponds to frequency k * Samplerate / N
+       index k == 0 is a special case:
+         the real() part contains the result for the DC frequency 0,
+         the imag() part contains the result for the Nyquist frequency Samplerate/2
+     both 0-frequency and half frequency components, which are real,
+     are assembled in the first entry as  F(0)+i*F(N/2).
+     With the output size N/2 complex values (=N real/imag values), it is
+     obvious, that the result for negative frequencies are not output,
+     cause of symmetry.
+
      input and output may alias.
   */
   void pffft_transform(PFFFT_Setup *setup, const float *input, float *output, float *work, pffft_direction_t direction);
@@ -200,6 +213,18 @@ extern "C" {
   /* simple helper to determine if power of 2 - returns bool */
   int pffft_is_power_of_two(int N);
 
+  /* simple helper to determine size N is valid
+     - factorizable to pffft_min_fft_size() with factors 2, 3, 5
+     returns bool
+  */
+  int pffft_is_valid_size(int N, pffft_transform_t cplx);
+
+  /* determine nearest valid transform size  (by brute-force testing)
+     - factorizable to pffft_min_fft_size() with factors 2, 3, 5.
+     higher: bool-flag to find nearest higher value; else lower.
+  */
+  int pffft_nearest_transform_size(int N, pffft_transform_t cplx, int higher);
+
   /*
     the float buffers must have the correct alignment (16-byte boundary
     on intel and powerpc). This function may be used to obtain such
diff --git a/pffft.hpp b/pffft.hpp
index 8437e05..28e9db1 100644
--- a/pffft.hpp
+++ b/pffft.hpp
@@ -33,8 +33,10 @@
 #include <complex>
 #include <vector>
 #include <limits>
+#include <cassert>
 
-namespace {
+namespace pffft {
+namespace detail {
 #if defined(PFFFT_ENABLE_FLOAT) || ( !defined(PFFFT_ENABLE_FLOAT) && !defined(PFFFT_ENABLE_DOUBLE) )
 #include "pffft.h"
 #endif
@@ -42,11 +44,12 @@ namespace {
 #include "pffft_double.h"
 #endif
 }
+}
 
 namespace pffft {
 
 // enum { PFFFT_REAL, PFFFT_COMPLEX }
-typedef pffft_transform_t TransformType;
+typedef detail::pffft_transform_t TransformType;
 
 // define 'Scalar' and 'Complex' (in namespace pffft) with template Types<>
 // and other type specific helper functions
@@ -55,35 +58,47 @@ template<typename T> struct Types {};
 template<> struct Types<float>  {
   typedef float  Scalar;
   typedef std::complex<Scalar> Complex;
-  static int simd_size() { return pffft_simd_size(); }
-  static const char * simd_arch() { return pffft_simd_arch(); }
+  static int simd_size() { return detail::pffft_simd_size(); }
+  static const char * simd_arch() { return detail::pffft_simd_arch(); }
+  static int minFFtsize() { return pffft_min_fft_size(detail::PFFFT_REAL); }
+  static bool isValidSize(int N) { return pffft_is_valid_size(N, detail::PFFFT_REAL); }
+  static int nearestTransformSize(int N, bool higher) { return pffft_nearest_transform_size(N, detail::PFFFT_REAL, higher ? 1 : 0); }
 };
 template<> struct Types< std::complex<float> >  {
   typedef float  Scalar;
   typedef std::complex<float>  Complex;
-  static int simd_size() { return pffft_simd_size(); }
-  static const char * simd_arch() { return pffft_simd_arch(); }
+  static int simd_size() { return detail::pffft_simd_size(); }
+  static const char * simd_arch() { return detail::pffft_simd_arch(); }
+  static int minFFtsize() { return pffft_min_fft_size(detail::PFFFT_COMPLEX); }
+  static bool isValidSize(int N) { return pffft_is_valid_size(N, detail::PFFFT_COMPLEX); }
+  static int nearestTransformSize(int N, bool higher) { return pffft_nearest_transform_size(N, detail::PFFFT_COMPLEX, higher ? 1 : 0); }
 };
 #endif
 #if defined(PFFFT_ENABLE_DOUBLE)
 template<> struct Types<double> {
   typedef double Scalar;
   typedef std::complex<Scalar> Complex;
-  static int simd_size() { return pffftd_simd_size(); }
-  static const char * simd_arch() { return pffftd_simd_arch(); }
+  static int simd_size() { return detail::pffftd_simd_size(); }
+  static const char * simd_arch() { return detail::pffftd_simd_arch(); }
+  static int minFFtsize() { return pffftd_min_fft_size(detail::PFFFT_REAL); }
+  static bool isValidSize(int N) { return pffftd_is_valid_size(N, detail::PFFFT_REAL); }
+  static int nearestTransformSize(int N, bool higher) { return pffftd_nearest_transform_size(N, detail::PFFFT_REAL, higher ? 1 : 0); }
 };
 template<> struct Types< std::complex<double> > {
   typedef double Scalar;
   typedef std::complex<double> Complex;
-  static int simd_size() { return pffftd_simd_size(); }
-  static const char * simd_arch() { return pffftd_simd_arch(); }
+  static int simd_size() { return detail::pffftd_simd_size(); }
+  static const char * simd_arch() { return detail::pffftd_simd_arch(); }
+  static int minFFtsize() { return pffftd_min_fft_size(detail::PFFFT_COMPLEX); }
+  static bool isValidSize(int N) { return pffftd_is_valid_size(N, detail::PFFFT_COMPLEX); }
+  static int nearestTransformSize(int N, bool higher) { return pffftd_nearest_transform_size(N, detail::PFFFT_COMPLEX, higher ? 1 : 0); }
 };
 #endif
 
 // Allocator
 template<typename T> class PFAlloc;
 
-namespace {
+namespace detail {
   template<typename T> class Setup;
 }
 
@@ -122,16 +137,22 @@ public:
   static bool isFloatScalar()  { return sizeof(Scalar) == sizeof(float); }
   static bool isDoubleScalar() { return sizeof(Scalar) == sizeof(double); }
 
-  // simple helper to get minimum possible fft length
-  static int minFFtsize() { return pffft_min_fft_size( isComplexTransform() ? PFFFT_COMPLEX : PFFFT_REAL ); }
-
   // simple helper to determine next power of 2 - without inexact/rounding floating point operations
-  static int nextPowerOfTwo(int N) { return pffft_next_power_of_two(N); }
-  static bool isPowerOfTwo(int N) { return pffft_is_power_of_two(N) ? true : false; }
+  static int nextPowerOfTwo(int N) { return detail::pffft_next_power_of_two(N); }
+  static bool isPowerOfTwo(int N) { return detail::pffft_is_power_of_two(N) ? true : false; }
+
 
   static int simd_size() { return Types<T>::simd_size(); }
   static const char * simd_arch() { return Types<T>::simd_arch(); }
 
+  // simple helper to get minimum possible fft length
+  static int minFFtsize() { return Types<T>::minFFtsize(); }
+
+  // helper to determine nearest transform size - factorizable to minFFtsize() with factors 2, 3, 5
+  static bool isValidSize(int N) { return Types<T>::isValidSize(N); }
+  static int nearestTransformSize(int N, bool higher=true) { return Types<T>::nearestTransformSize(N, higher); }
+
+
   //////////////////
 
   /*
@@ -146,6 +167,14 @@ public:
    */
   Fft( int length, int stackThresholdLen = 4096 );
 
+
+  /*
+   * constructor or prepareLength() produced a valid FFT instance?
+   * delivers false for invalid FFT sizes
+   */
+  bool isValid() const;
+
+
   ~Fft();
 
   /*
@@ -153,8 +182,9 @@ public:
    * length is identical to forward()'s input vector's size,
    * and also equals inverse()'s output vector size.
    * this function is no simple setter. it pre-calculates twiddle factors.
+   * returns true if newLength is >= minFFtsize, false otherwise
    */
-  void prepareLength(int newLength);
+  bool prepareLength(int newLength);
 
   /*
    * retrieve the transformation length.
@@ -216,6 +246,8 @@ public:
    *     the imag() part contains the result for the Nyquist frequency Samplerate/2
    *   both 0-frequency and half frequency components, which are real,
    *   are assembled in the first entry as  F(0)+i*F(N/2).
+   *   with the output size N/2 complex values, it is obvious, that the
+   *   result for negative frequencies are not output, cause of symmetry.
    *
    * input and output may alias - if you do nasty type conversion.
    * return is just the given output parameter 'spectrum'.
@@ -355,7 +387,7 @@ public:
                              const Scalar scaling);
 
 private:
-  Setup<T> setup;
+  detail::Setup<T> setup;
   Scalar* work;
   int length;
   int stackThresholdLen;
@@ -364,26 +396,21 @@ private:
 
 template<typename T>
 inline T* alignedAlloc(int length) {
-  return (T*)pffft_aligned_malloc( length * sizeof(T) );
+  return (T*)detail::pffft_aligned_malloc( length * sizeof(T) );
 }
 
 inline void alignedFree(void *ptr) {
-  pffft_aligned_free(ptr);
+    detail::pffft_aligned_free(ptr);
 }
 
 
-// simple helper to get minimum possible fft length
-inline int minFFtsize(pffft_transform_t transform) {
-  return pffft_min_fft_size(transform);
-}
-
 // simple helper to determine next power of 2 - without inexact/rounding floating point operations
 inline int nextPowerOfTwo(int N) {
-  return pffft_next_power_of_two(N);
+  return detail::pffft_next_power_of_two(N);
 }
 
 inline bool isPowerOfTwo(int N) {
-  return pffft_is_power_of_two(N) ? true : false;
+  return detail::pffft_is_power_of_two(N) ? true : false;
 }
 
 
@@ -392,7 +419,7 @@ inline bool isPowerOfTwo(int N) {
 
 // implementation
 
-namespace {
+namespace detail {
 
 template<typename T>
 class Setup
@@ -413,6 +440,8 @@ public:
     : self(NULL)
   {}
 
+  ~Setup() { pffft_destroy_setup(self); }
+
   void prepareLength(int length)
   {
     if (self) {
@@ -421,7 +450,7 @@ public:
     self = pffft_new_setup(length, PFFFT_REAL);
   }
 
-  ~Setup() { pffft_destroy_setup(self); }
+  bool isValid() const { return (self); }
 
   void transform_ordered(const Scalar* input,
                          Scalar* output,
@@ -461,6 +490,7 @@ public:
   }
 };
 
+
 template<>
 class Setup< std::complex<float> >
 {
@@ -484,6 +514,8 @@ public:
     self = pffft_new_setup(length, PFFFT_COMPLEX);
   }
 
+  bool isValid() const { return (self); }
+
   void transform_ordered(const Scalar* input,
                          Scalar* output,
                          Scalar* work,
@@ -545,6 +577,8 @@ public:
     }
   }
 
+  bool isValid() const { return (self); }
+
   void transform_ordered(const Scalar* input,
                          Scalar* output,
                          Scalar* work,
@@ -606,6 +640,8 @@ public:
     self = pffftd_new_setup(length, PFFFT_COMPLEX);
   }
 
+  bool isValid() const { return (self); }
+
   void transform_ordered(const Scalar* input,
                          Scalar* output,
                          Scalar* work,
@@ -651,9 +687,9 @@ public:
 
 template<typename T>
 inline Fft<T>::Fft(int length, int stackThresholdLen)
-  : length(0)
+  : work(NULL)
+  , length(0)
   , stackThresholdLen(stackThresholdLen)
-  , work(NULL)
 {
 #if (__cplusplus >= 201103L || (defined(_MSC_VER) && _MSC_VER >= 1900))
   static_assert( sizeof(Complex) == 2 * sizeof(Scalar), "pffft requires sizeof(std::complex<>) == 2 * sizeof(Scalar)" );
@@ -670,20 +706,34 @@ inline Fft<T>::~Fft()
 }
 
 template<typename T>
-inline void
+inline bool
+Fft<T>::isValid() const
+{
+  return setup.isValid();
+}
+
+template<typename T>
+inline bool
 Fft<T>::prepareLength(int newLength)
 {
+  if(newLength < minFFtsize())
+    return false;
+
   const bool wasOnHeap = ( work != NULL );
 
   const bool useHeap = newLength > stackThresholdLen;
 
   if (useHeap == wasOnHeap && newLength == length) {
-    return;
+    return true;
   }
 
-  length = newLength;
+  length = 0;
 
-  setup.prepareLength(length);
+  setup.prepareLength(newLength);
+  if (!setup.isValid())
+    return false;
+
+  length = newLength;
 
   if (work) {
     alignedFree(work);
@@ -693,6 +743,8 @@ Fft<T>::prepareLength(int newLength)
   if (useHeap) {
     work = reinterpret_cast<Scalar*>( alignedAllocType(length) );
   }
+
+  return true;
 }
 
 
@@ -795,10 +847,11 @@ template<typename T>
 inline typename Fft<T>::Complex *
 Fft<T>::forward(const T* input, Complex * spectrum)
 {
+  assert(isValid());
   setup.transform_ordered(reinterpret_cast<const Scalar*>(input),
                           reinterpret_cast<Scalar*>(spectrum),
                           work,
-                          PFFFT_FORWARD);
+                          detail::PFFFT_FORWARD);
   return spectrum;
 }
 
@@ -806,10 +859,11 @@ template<typename T>
 inline T*
 Fft<T>::inverse(Complex const* spectrum, T* output)
 {
+  assert(isValid());
   setup.transform_ordered(reinterpret_cast<const Scalar*>(spectrum),
                           reinterpret_cast<Scalar*>(output),
                           work,
-                          PFFFT_BACKWARD);
+                          detail::PFFFT_BACKWARD);
   return output;
 }
 
@@ -817,10 +871,11 @@ template<typename T>
 inline typename pffft::Fft<T>::Scalar*
 Fft<T>::forwardToInternalLayout(const T* input, Scalar* spectrum_internal_layout)
 {
+  assert(isValid());
   setup.transform(reinterpret_cast<const Scalar*>(input),
                   spectrum_internal_layout,
                   work,
-                  PFFFT_FORWARD);
+                  detail::PFFFT_FORWARD);
   return spectrum_internal_layout;
 }
 
@@ -828,10 +883,11 @@ template<typename T>
 inline T*
 Fft<T>::inverseFromInternalLayout(const Scalar* spectrum_internal_layout, T* output)
 {
+  assert(isValid());
   setup.transform(spectrum_internal_layout,
                   reinterpret_cast<Scalar*>(output),
                   work,
-                  PFFFT_BACKWARD);
+                  detail::PFFFT_BACKWARD);
   return output;
 }
 
@@ -839,7 +895,8 @@ template<typename T>
 inline void
 Fft<T>::reorderSpectrum( const Scalar* input, Complex* output )
 {
-  setup.reorder(input, reinterpret_cast<Scalar*>(output), PFFFT_FORWARD);
+  assert(isValid());
+  setup.reorder(input, reinterpret_cast<Scalar*>(output), detail::PFFFT_FORWARD);
 }
 
 template<typename T>
@@ -849,6 +906,7 @@ Fft<T>::convolveAccumulate(const Scalar* dft_a,
                            Scalar* dft_ab,
                            const Scalar scaling)
 {
+  assert(isValid());
   setup.convolveAccumulate(dft_a, dft_b, dft_ab, scaling);
   return dft_ab;
 }
@@ -860,6 +918,7 @@ Fft<T>::convolve(const Scalar* dft_a,
                  Scalar* dft_ab,
                  const Scalar scaling)
 {
+  assert(isValid());
   setup.convolve(dft_a, dft_b, dft_ab, scaling);
   return dft_ab;
 }
@@ -961,7 +1020,7 @@ class PFAlloc {
 
     // allocate but don't initialize num elements of type T
     pointer allocate (size_type num, const void* = 0) {
-        pointer ret = (pointer)( alignedAlloc<T>(num) );
+        pointer ret = (pointer)( alignedAlloc<T>(int(num)) );
         return ret;
     }
 
diff --git a/pffft_common.c b/pffft_common.c
index 1121ac7..106fdd2 100644
--- a/pffft_common.c
+++ b/pffft_common.c
@@ -40,29 +40,14 @@ static int is_power_of_two(int N) {
   return f;
 }
 
-static int min_fft_size(pffft_transform_t transform) {
-  /* unfortunately, the fft size must be a multiple of 16 for complex FFTs
-     and 32 for real FFTs -- a lot of stuff would need to be rewritten to
-     handle other cases (or maybe just switch to a scalar fft, I don't know..) */
-  int simdSz = pffft_simd_size();
-  if (transform == PFFFT_REAL)
-    return ( 2 * simdSz * simdSz );
-  else if (transform == PFFFT_COMPLEX)
-    return ( simdSz * simdSz );
-  else
-    return 1;
-}
 
 
 void *pffft_aligned_malloc(size_t nb_bytes) { return Valigned_malloc(nb_bytes); }
 void pffft_aligned_free(void *p) { Valigned_free(p); }
 int pffft_next_power_of_two(int N) { return next_power_of_two(N); }
 int pffft_is_power_of_two(int N) { return is_power_of_two(N); }
-int pffft_min_fft_size(pffft_transform_t transform) { return min_fft_size(transform); }
 
 void *pffftd_aligned_malloc(size_t nb_bytes) { return Valigned_malloc(nb_bytes); }
 void pffftd_aligned_free(void *p) { Valigned_free(p); }
 int pffftd_next_power_of_two(int N) { return next_power_of_two(N); }
 int pffftd_is_power_of_two(int N) { return is_power_of_two(N); }
-int pffftd_min_fft_size(pffft_transform_t transform) { return min_fft_size(transform); }
-
diff --git a/pffft_double.c b/pffft_double.c
index 28c0832..066782b 100644
--- a/pffft_double.c
+++ b/pffft_double.c
@@ -73,6 +73,8 @@
 #ifdef COMPILER_MSVC
 #  define _USE_MATH_DEFINES
 #  include <malloc.h>
+#elif defined(__MINGW32__) || defined(__MINGW64__)
+#  include <malloc.h>
 #else
 #  include <alloca.h>
 #endif
@@ -121,6 +123,9 @@
 #define FUNC_ALIGNED_MALLOC        pffftd_aligned_malloc
 #define FUNC_ALIGNED_FREE          pffftd_aligned_free
 #define FUNC_SIMD_SIZE             pffftd_simd_size
+#define FUNC_MIN_FFT_SIZE          pffftd_min_fft_size
+#define FUNC_IS_VALID_SIZE         pffftd_is_valid_size
+#define FUNC_NEAREST_SIZE          pffftd_nearest_transform_size
 #define FUNC_SIMD_ARCH             pffftd_simd_arch
 #define FUNC_VALIDATE_SIMD_A       validate_pffftd_simd
 #define FUNC_VALIDATE_SIMD_EX      validate_pffftd_simd_ex
diff --git a/pffft_double.h b/pffft_double.h
index d83c06d..afa8de0 100644
--- a/pffft_double.h
+++ b/pffft_double.h
@@ -191,19 +191,32 @@ extern "C" {
   /* return string identifier of used architecture (AVX/..) */
   const char * pffftd_simd_arch();
 
-
-  /* following functions are identical to the pffft_ functions */
-
   /* simple helper to get minimum possible fft size */
   int pffftd_min_fft_size(pffft_transform_t transform);
 
+  /* simple helper to determine size N is valid
+     - factorizable to pffft_min_fft_size() with factors 2, 3, 5
+  */
+  int pffftd_is_valid_size(int N, pffft_transform_t cplx);
+
+  /* determine nearest valid transform size  (by brute-force testing)
+     - factorizable to pffft_min_fft_size() with factors 2, 3, 5.
+     higher: bool-flag to find nearest higher value; else lower.
+  */
+  int pffftd_nearest_transform_size(int N, pffft_transform_t cplx, int higher);
+
+
+  /* following functions are identical to the pffft_ functions - both declared */
+
   /* simple helper to determine next power of 2
      - without inexact/rounding floating point operations
   */
   int pffftd_next_power_of_two(int N);
+  int pffft_next_power_of_two(int N);
 
   /* simple helper to determine if power of 2 - returns bool */
   int pffftd_is_power_of_two(int N);
+  int pffft_is_power_of_two(int N);
 
   /*
     the double buffers must have the correct alignment (32-byte boundary
@@ -211,7 +224,9 @@ extern "C" {
     correctly aligned buffers.  
   */
   void *pffftd_aligned_malloc(size_t nb_bytes);
+  void *pffft_aligned_malloc(size_t nb_bytes);
   void pffftd_aligned_free(void *);
+  void pffft_aligned_free(void *);
 
 #ifdef __cplusplus
 }
diff --git a/pffft_priv_impl.h b/pffft_priv_impl.h
index e1b7b94..ff13cac 100644
--- a/pffft_priv_impl.h
+++ b/pffft_priv_impl.h
@@ -71,6 +71,44 @@
 
 int FUNC_SIMD_SIZE() { return SIMD_SZ; }
 
+int FUNC_MIN_FFT_SIZE(pffft_transform_t transform) {
+  /* unfortunately, the fft size must be a multiple of 16 for complex FFTs
+     and 32 for real FFTs -- a lot of stuff would need to be rewritten to
+     handle other cases (or maybe just switch to a scalar fft, I don't know..) */
+  int simdSz = FUNC_SIMD_SIZE();
+  if (transform == PFFFT_REAL)
+    return ( 2 * simdSz * simdSz );
+  else if (transform == PFFFT_COMPLEX)
+    return ( simdSz * simdSz );
+  else
+    return 1;
+}
+
+int FUNC_IS_VALID_SIZE(int N, pffft_transform_t cplx) {
+  const int N_min = FUNC_MIN_FFT_SIZE(cplx);
+  int R = N;
+  while (R >= 5*N_min && (R % 5) == 0)  R /= 5;
+  while (R >= 3*N_min && (R % 3) == 0)  R /= 3;
+  while (R >= 2*N_min && (R % 2) == 0)  R /= 2;
+  return (R == N_min) ? 1 : 0;
+}
+
+int FUNC_NEAREST_SIZE(int N, pffft_transform_t cplx, int higher) {
+  int d;
+  const int N_min = FUNC_MIN_FFT_SIZE(cplx);
+  if (N < N_min)
+    N = N_min;
+  d = (higher) ? N_min : -N_min;
+  if (d > 0)
+    N = N_min * ((N+N_min-1) / N_min);  /* round up */
+  else
+    N = N_min * (N / N_min);  /* round down */
+
+  for (; ; N += d)
+    if (FUNC_IS_VALID_SIZE(N, cplx))
+      return N;
+}
+
 const char * FUNC_SIMD_ARCH() { return VARCH; }
 
 
@@ -1015,13 +1053,14 @@ struct SETUP_STRUCT {
 };
 
 SETUP_STRUCT *FUNC_NEW_SETUP(int N, pffft_transform_t transform) {
-  SETUP_STRUCT *s = (SETUP_STRUCT*)malloc(sizeof(SETUP_STRUCT));
+  SETUP_STRUCT *s = 0;
   int k, m;
   /* unfortunately, the fft size must be a multiple of 16 for complex FFTs 
      and 32 for real FFTs -- a lot of stuff would need to be rewritten to
      handle other cases (or maybe just switch to a scalar fft, I don't know..) */
-  if (transform == PFFFT_REAL) { assert((N%(2*SIMD_SZ*SIMD_SZ))==0 && N>0); }
-  if (transform == PFFFT_COMPLEX) { assert((N%(SIMD_SZ*SIMD_SZ))==0 && N>0); }
+  if (transform == PFFFT_REAL)    { if ((N%(2*SIMD_SZ*SIMD_SZ)) || N<=0) return s; }
+  if (transform == PFFFT_COMPLEX) { if ((N%(  SIMD_SZ*SIMD_SZ)) || N<=0) return s; }
+  s = (SETUP_STRUCT*)malloc(sizeof(SETUP_STRUCT));
   /* assert((N % 32) == 0); */
   s->N = N;
   s->transform = transform;  
@@ -1066,6 +1105,8 @@ SETUP_STRUCT *FUNC_NEW_SETUP(int N, pffft_transform_t transform) {
 
 
 void FUNC_DESTROY(SETUP_STRUCT *s) {
+  if (!s)
+    return;
   FUNC_ALIGNED_FREE(s->data);
   free(s);
 }
@@ -1818,7 +1859,7 @@ void FUNC_VALIDATE_SIMD_A() {
 
 static void pffft_assert1( float result, float ref, const char * vartxt, const char * functxt, int * numErrs, const char * f, int lineNo )
 {
-  if ( !( fabsf( result - ref ) < 0.01F ) )
+  if ( !( fabs( result - ref ) < 0.01F ) )
   {
     fprintf(stderr, "%s: assert for %s at %s(%d)\n  expected %f  value %f\n", functxt, vartxt, f, lineNo, ref, result);
     ++(*numErrs);
diff --git a/simd/pf_avx_double.h b/simd/pf_avx_double.h
index 251f0b9..fe0efa8 100644
--- a/simd/pf_avx_double.h
+++ b/simd/pf_avx_double.h
@@ -46,7 +46,7 @@
 /*
   AVX support macros
 */
-#if !defined(SIMD_SZ) && !defined(PFFFT_SIMD_DISABLE) && !defined(PFFFT_AVX_DISABLE) && defined(__AVX__)
+#if !defined(SIMD_SZ) && !defined(PFFFT_SIMD_DISABLE) && defined(__AVX__)
 #pragma message( __FILE__ ": AVX macros are defined" )
 
 #include <immintrin.h>
diff --git a/simd/pf_sse1_float.h b/simd/pf_sse1_float.h
index ac649db..df73c2e 100644
--- a/simd/pf_sse1_float.h
+++ b/simd/pf_sse1_float.h
@@ -36,7 +36,7 @@
 /*
   SSE1 support macros
 */
-#if !defined(SIMD_SZ) && !defined(PFFFT_SIMD_DISABLE) && (defined(__x86_64__) || defined(_M_X64) || defined(i386) || defined(_M_IX86))
+#if !defined(SIMD_SZ) && !defined(PFFFT_SIMD_DISABLE) && (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(i386) || defined(_M_IX86))
 #pragma message( __FILE__ ": SSE1 float macros are defined" )
 
 #include <xmmintrin.h>
diff --git a/simd/pf_sse2_double.h b/simd/pf_sse2_double.h
index ba01c47..da87951 100644
--- a/simd/pf_sse2_double.h
+++ b/simd/pf_sse2_double.h
@@ -48,7 +48,7 @@
 /*
   SSE2 64bit support macros
 */
-#if !defined(SIMD_SZ) && !defined(PFFFT_SIMD_DISABLE) && (defined( __SSE4_2__ ) |  defined( __SSE4_1__ ) || defined( __SSE3__ ) || defined( __SSE2__ ) || defined ( __x86_64__ ))
+#if !defined(SIMD_SZ) && !defined(PFFFT_SIMD_DISABLE) && (defined( __SSE4_2__ ) |  defined( __SSE4_1__ ) || defined( __SSE3__ ) || defined( __SSE2__ ) || defined ( __x86_64__ ) || defined( _M_AMD64 ) || defined( _M_X64 ) || defined( __amd64 ))
 #pragma message (__FILE__ ": SSE2 double macros are defined" )
 
 #include <emmintrin.h>
diff --git a/test_fft_factors.c b/test_fft_factors.c
new file mode 100644
index 0000000..cefb2cc
--- /dev/null
+++ b/test_fft_factors.c
@@ -0,0 +1,142 @@
+
+#ifdef PFFFT_ENABLE_FLOAT
+#include "pffft.h"
+#endif
+
+
+#ifdef PFFFT_ENABLE_DOUBLE
+#include "pffft_double.h"
+#endif
+
+#include <stdio.h>
+#include <stdlib.h>
+#include <assert.h>
+
+
+
+#ifdef PFFFT_ENABLE_FLOAT
+int test_float(int TL)
+{
+  PFFFT_Setup * S;
+
+  for (int dir_i = 0; dir_i <= 1; ++dir_i)
+  {
+    for (int cplx_i = 0; cplx_i <= 1; ++cplx_i)
+    {
+      const pffft_direction_t dir = (!dir_i) ? PFFFT_FORWARD : PFFFT_BACKWARD;
+      const pffft_transform_t cplx = (!cplx_i) ? PFFFT_REAL : PFFFT_COMPLEX;
+      const int N_min = pffft_min_fft_size(cplx);
+      const int N_max = N_min * 11 + N_min;
+      int NTL = pffft_nearest_transform_size(TL, cplx, (!dir_i));
+      double near_off = (NTL - TL) * 100.0 / (double)TL;
+
+      fprintf(stderr, "testing float, %s, %s ..\tminimum transform %d; nearest transform for %d is %d (%.2f%% off)\n",
+          (!dir_i) ? "FORWARD" : "BACKWARD", (!cplx_i) ? "REAL" : "COMPLEX", N_min, TL, NTL, near_off );
+
+      for (int N = (N_min/2); N <= N_max; N += (N_min/2))
+      {
+        int R = N, f2 = 0, f3 = 0, f5 = 0, tmp_f;
+        const int factorizable = pffft_is_valid_size(N, cplx);
+        while (R >= 5*N_min && (R % 5) == 0) {  R /= 5; ++f5; }
+        while (R >= 3*N_min && (R % 3) == 0) {  R /= 3; ++f3; }
+        while (R >= 2*N_min && (R % 2) == 0) {  R /= 2; ++f2; }
+        tmp_f = (R == N_min) ? 1 : 0;
+        assert( factorizable == tmp_f );
+
+        S = pffft_new_setup(N, cplx);
+
+        if ( S && !factorizable )
+        {
+          fprintf(stderr, "fft setup successful, but NOT factorizable into min(=%d), 2^%d, 3^%d, 5^%d for N = %d (R = %d)\n", N_min, f2, f3, f5, N, R);
+          return 1;
+        }
+        else if ( !S && factorizable)
+        {
+          fprintf(stderr, "fft setup UNsuccessful, but factorizable into min(=%d), 2^%d, 3^%d, 5^%d for N = %d (R = %d)\n", N_min, f2, f3, f5, N, R);
+          return 1;
+        }
+        
+        if (S)
+          pffft_destroy_setup(S);
+      }
+
+    }
+  }
+  return 0;
+}
+
+#endif
+
+
+#ifdef PFFFT_ENABLE_DOUBLE
+int test_double(int TL)
+{
+  PFFFTD_Setup * S;
+  for (int dir_i = 0; dir_i <= 1; ++dir_i)
+  {
+    for (int cplx_i = 0; cplx_i <= 1; ++cplx_i)
+    {
+      const pffft_direction_t dir = (!dir_i) ? PFFFT_FORWARD : PFFFT_BACKWARD;
+      const pffft_transform_t cplx = (!cplx_i) ? PFFFT_REAL : PFFFT_COMPLEX;
+      const int N_min = pffftd_min_fft_size(cplx);
+      const int N_max = N_min * 11 + N_min;
+      int NTL = pffftd_nearest_transform_size(TL, cplx, (!dir_i));
+      double near_off = (NTL - TL) * 100.0 / (double)TL;
+
+      fprintf(stderr, "testing double, %s, %s ..\tminimum transform %d; nearest transform for %d is %d (%.2f%% off)\n",
+          (!dir_i) ? "FORWARD" : "BACKWARD", (!cplx_i) ? "REAL" : "COMPLEX", N_min, TL, NTL, near_off );
+
+      for (int N = (N_min/2); N <= N_max; N += (N_min/2))
+      {
+        int R = N, f2 = 0, f3 = 0, f5 = 0, tmp_f;
+        const int factorizable = pffftd_is_valid_size(N, cplx);
+        while (R >= 5*N_min && (R % 5) == 0) {  R /= 5; ++f5; }
+        while (R >= 3*N_min && (R % 3) == 0) {  R /= 3; ++f3; }
+        while (R >= 2*N_min && (R % 2) == 0) {  R /= 2; ++f2; }
+        tmp_f = (R == N_min) ? 1 : 0;
+        assert( factorizable == tmp_f );
+
+        S = pffftd_new_setup(N, cplx);
+
+        if ( S && !factorizable )
+        {
+          fprintf(stderr, "fft setup successful, but NOT factorizable into min(=%d), 2^%d, 3^%d, 5^%d for N = %d (R = %d)\n", N_min, f2, f3, f5, N, R);
+          return 1;
+        }
+        else if ( !S && factorizable)
+        {
+          fprintf(stderr, "fft setup UNsuccessful, but factorizable into min(=%d), 2^%d, 3^%d, 5^%d for N = %d (R = %d)\n", N_min, f2, f3, f5, N, R);
+          return 1;
+        }
+        
+        if (S)
+          pffftd_destroy_setup(S);
+      }
+
+    }
+  }
+  return 0;
+}
+
+#endif
+
+
+
+int main(int argc, char *argv[])
+{
+  int N = (1 < argc) ? atoi(argv[1]) : 2;
+
+  int r = 0;
+#ifdef PFFFT_ENABLE_FLOAT
+  r = test_float(N);
+  if (r)
+    return r;
+#endif
+
+#ifdef PFFFT_ENABLE_DOUBLE
+  r = test_double(N);
+#endif
+
+  return r;
+}
+
diff --git a/test_pffastconv.c b/test_pffastconv.c
index 90d36ca..4fdd94d 100644
--- a/test_pffastconv.c
+++ b/test_pffastconv.c
@@ -23,6 +23,9 @@
 #  include <unistd.h>
 #endif
 
+/* benchmark duration: 250 ms */
+#define BENCH_TEST_DURATION_IN_SEC      0.5
+
 /* 
    vector support macros: the rest of the code is independant of
    SSE/Altivec/NEON -- adding support for other platforms with 4-element
@@ -459,10 +462,10 @@ void printFirst( const float * V, const char * st, const int N, const int perLin
 
 
 
-#define NUMY       11
+#define NUMY       15
 
 
-int test(int FILTERLEN, int convFlags, const int testOutLen, int printDbg, int printSpeed) {
+int test(int FILTERLEN, int convFlags, const int testOutLen, int printDbg, int printSpeed, int abortFirstFastAlgo, int printErrValues, int printAsCSV, int *pIsFirstFilterLen) {
   double t0, t1, tstop, td, tdref;
   float *X, *H;
   float *Y[NUMY];
@@ -483,23 +486,25 @@ int test(int FILTERLEN, int convFlags, const int testOutLen, int printDbg, int p
   int i, j, numErrOverLimit, iter;
   int retErr = 0;
 
-  /*                                  0               1               2               3                   4                   5                   6                   7                   8                      9  */
-  pfnConvSetup   aSetup[NUMY]     = { convSetupRev,   convSetupRev,   convSetupRev,   fastConvSetup,      fastConvSetup,      fastConvSetup,      fastConvSetup,      fastConvSetup,      fastConvSetup,         fastConvSetup   };
-  pfnConvDestroy aDestroy[NUMY]   = { convDestroyRev, convDestroyRev, convDestroyRev, fastConvDestroy,    fastConvDestroy,    fastConvDestroy,    fastConvDestroy,    fastConvDestroy,    fastConvDestroy,       fastConvDestroy };
-  pfnGetConvFnPtr aGetFnPtr[NUMY] = { NULL,           NULL,           NULL,           NULL,               NULL,               NULL,               NULL,               NULL,               NULL,                  NULL,           };
-  pfnConvolution aConv[NUMY]      = { slow_conv_R,    slow_conv_A,    slow_conv_B,    fast_conv,          fast_conv,          fast_conv,          fast_conv,          fast_conv,          fast_conv,             fast_conv       };
-  const char * convText[NUMY]     = { "R(non-simd)",  "A(non-simd)",  "B(non-simd)",  "fast_conv_64",     "fast_conv_128",    "fast_conv_256",    "fast_conv_512",    "fast_conv_1K",     "fast_conv_2K",        "fast_conv_4K"  };
-  int    aFastAlgo[NUMY]          = { 0,              0,              0,              1,                  1,                  1,                  1,                  1,                  1,                     1               };
-  void * aSetupCfg[NUMY]          = { NULL,           NULL,           NULL,           NULL,               NULL,               NULL,               NULL,               NULL,               NULL,                  NULL            };
-  int    aBlkLen[NUMY]            = { 1024,           1024,           1024,           64,                 128,                256,                512,                1024,               2048,                  4096            };
+  /*                                  0               1               2               3                   4                   5                   6                   7                   8                      9,                   10,                  11,                   12,                   13                     */
+  pfnConvSetup   aSetup[NUMY]     = { convSetupRev,   convSetupRev,   convSetupRev,   fastConvSetup,      fastConvSetup,      fastConvSetup,      fastConvSetup,      fastConvSetup,      fastConvSetup,         fastConvSetup,       fastConvSetup,       fastConvSetup,        fastConvSetup,        fastConvSetup,         };
+  pfnConvDestroy aDestroy[NUMY]   = { convDestroyRev, convDestroyRev, convDestroyRev, fastConvDestroy,    fastConvDestroy,    fastConvDestroy,    fastConvDestroy,    fastConvDestroy,    fastConvDestroy,       fastConvDestroy,     fastConvDestroy,     fastConvDestroy,      fastConvDestroy,      fastConvDestroy,       };
+  pfnGetConvFnPtr aGetFnPtr[NUMY] = { NULL,           NULL,           NULL,           NULL,               NULL,               NULL,               NULL,               NULL,               NULL,                  NULL,                NULL,                NULL,                 NULL,                 NULL,                  };
+  pfnConvolution aConv[NUMY]      = { slow_conv_R,    slow_conv_A,    slow_conv_B,    fast_conv,          fast_conv,          fast_conv,          fast_conv,          fast_conv,          fast_conv,             fast_conv,           fast_conv,           fast_conv,            fast_conv,            fast_conv,             };
+  const char * convText[NUMY]     = { "R(non-simd)",  "A(non-simd)",  "B(non-simd)",  "fast_conv_64",     "fast_conv_128",    "fast_conv_256",    "fast_conv_512",    "fast_conv_1K",     "fast_conv_2K",        "fast_conv_4K",      "fast_conv_8K",      "fast_conv_16K",      "fast_conv_32K",      "fast_conv_64K",       };
+  int    aFastAlgo[NUMY]          = { 0,              0,              0,              1,                  1,                  1,                  1,                  1,                  1,                     1,                   1,                   1,                    1,                    1,                     };
+  void * aSetupCfg[NUMY]          = { NULL,           NULL,           NULL,           NULL,               NULL,               NULL,               NULL,               NULL,               NULL,                  NULL,                NULL,                NULL,                 NULL,                 NULL,                  };
+//int    aBlkLen[NUMY]            = { 1024,           1024,           1024,           64,                 128,                256,                512,                1024,               2048,                  4096,                8192,                16384,                32768,                65536,                 };
+  int    aBlkLen[NUMY]            = { 8192,           8192,           8192,           64,                 128,                256,                512,                1024,               2048,                  4096,                8192,                16384,                32768,                65536,                 };
 #if 1
-  int    aRunAlgo[NUMY]           = { 1,              1,              1,              FILTERLEN<64,       FILTERLEN<128,      FILTERLEN<256,      FILTERLEN<512,      FILTERLEN<1024,     FILTERLEN<2048,        FILTERLEN<4096  };
+  int    aRunAlgo[NUMY]           = { 1,              1,              1,              FILTERLEN<64,       FILTERLEN<128,      FILTERLEN<256,      FILTERLEN<512,      FILTERLEN<1024,     FILTERLEN<2048,        FILTERLEN<4096,      FILTERLEN<8192,      FILTERLEN<16384,      FILTERLEN<32768,      FILTERLEN<65536,       };
 #elif 0
-  int    aRunAlgo[NUMY]           = { 1,              0,              0,              0 && FILTERLEN<64,  1 && FILTERLEN<128, 1 && FILTERLEN<256, 0 && FILTERLEN<512, 0 && FILTERLEN<1024, 0 && FILTERLEN<2048,  0 && FILTERLEN<4096  };
+  int    aRunAlgo[NUMY]           = { 1,              0,              0,              0 && FILTERLEN<64,  1 && FILTERLEN<128, 1 && FILTERLEN<256, 0 && FILTERLEN<512, 0 && FILTERLEN<1024, 0 && FILTERLEN<2048,  0 && FILTERLEN<4096, 0 && FILTERLEN<8192, 0 && FILTERLEN<16384, 0 && FILTERLEN<32768, 0 && FILTERLEN<65536,  };
 #else
-  int    aRunAlgo[NUMY]           = { 1,              1,              1,              0 && FILTERLEN<64,  0 && FILTERLEN<128, 1 && FILTERLEN<256, 0 && FILTERLEN<512, 0 && FILTERLEN<1024, 0 && FILTERLEN<2048,  0 && FILTERLEN<4096  };
+  int    aRunAlgo[NUMY]           = { 1,              1,              1,              0 && FILTERLEN<64,  0 && FILTERLEN<128, 1 && FILTERLEN<256, 0 && FILTERLEN<512, 0 && FILTERLEN<1024, 0 && FILTERLEN<2048,  0 && FILTERLEN<4096, 0 && FILTERLEN<8192, 0 && FILTERLEN<16384, 0 && FILTERLEN<32768, 0 && FILTERLEN<65536,  };
 #endif
   double aSpeedFactor[NUMY], aDuration[NUMY], procSmpPerSec[NUMY];
+  int aNumIters[NUMY], aNumLoops[NUMY];
 
   X = pffastconv_malloc( (unsigned)(len+4) * sizeof(float) );
   for ( i=0; i < NUMY; ++i)
@@ -513,6 +518,8 @@ int test(int FILTERLEN, int convFlags, const int testOutLen, int printDbg, int p
     aSpeedFactor[i] = -1.0;
     aDuration[i] = -1.0;
     procSmpPerSec[i] = -1.0;
+    aNumIters[i] = 0;
+    aNumLoops[i] = 0;
   }
 
   H = pffastconv_malloc((unsigned)FILTERLEN * sizeof(float));
@@ -570,11 +577,16 @@ int test(int FILTERLEN, int convFlags, const int testOutLen, int printDbg, int p
   if (!testOutLen)
     printFirst( H, "H", FILTERLEN, 8 );
 
-  printf("\n");
-  printf("filterLen = %d\t%s%s\t%s:\n", FILTERLEN,
-    ((convFlags & PFFASTCONV_CPLX_INP_OUT)?"cplx":"real"),
-    (convFlags & PFFASTCONV_CPLX_INP_OUT)?((convFlags & PFFASTCONV_CPLX_SINGLE_FFT)?" single":" 2x") : "",
-    ((convFlags & PFFASTCONV_SYMMETRIC)?"symmetric":"non-sym") );
+  if (!printAsCSV)
+  {
+    printf("\n");
+    printf("filterLen = %d\t%s%s\t%s:\n", FILTERLEN,
+      ((convFlags & PFFASTCONV_CPLX_INP_OUT)?"cplx":"real"),
+      (convFlags & PFFASTCONV_CPLX_INP_OUT)?((convFlags & PFFASTCONV_CPLX_SINGLE_FFT)?" single":" 2x") : "",
+      ((convFlags & PFFASTCONV_SYMMETRIC)?"symmetric":"non-sym") );
+  }
+
+  int hadFastAlgo = 0;
 
   while (1)
   {
@@ -584,13 +596,22 @@ int test(int FILTERLEN, int convFlags, const int testOutLen, int printDbg, int p
       if (!aRunAlgo[yi])
         continue;
 
+      if ( aFastAlgo[yi] && abortFirstFastAlgo && hadFastAlgo )
+      {
+        aRunAlgo[yi] = 0;
+        continue;
+      }
+
+      hadFastAlgo = hadFastAlgo | aFastAlgo[yi];
+
       aSetupCfg[yi] = aSetup[yi]( H, FILTERLEN, &aBlkLen[yi], convFlags );
 
       /* get effective apply function ptr */
       if ( aSetupCfg[yi] && aGetFnPtr[yi] )
         aConv[yi] = aGetFnPtr[yi]( aSetupCfg[yi] );
 
-      if ( aSetupCfg[yi] && aConv[yi] ) {
+      if ( aSetupCfg[yi] && aConv[yi] )
+      {
         if (testOutLen)
         {
           t0 = uclock_sec();
@@ -600,41 +621,50 @@ int test(int FILTERLEN, int convFlags, const int testOutLen, int printDbg, int p
         }
         else
         {
-          const int blkLen = 4096;  /* required for 'fast_conv_4K' */
+          //const int blkLen = 4096;  /* required for 'fast_conv_4K' */
+          const int blkLen = aBlkLen[yi];
           int64_t offC = 0, offS, Nout;
           int k;
           iter = 0;
           outN[yi] = 0;
+          aNumLoops[yi] = 1;
           t0 = uclock_sec();
-          tstop = t0 + 0.25;  /* benchmark duration: 250 ms */
-          do {
+          tstop = t0 + BENCH_TEST_DURATION_IN_SEC;
+          do
+          {
+            const int prev_iter = iter;
             for ( k = 0; k < 128 && offC +blkLen < lenC; ++k )
             {
               offS = cplxFactor * offC;
-              Nout = aConv[yi]( aSetupCfg[yi], X +offS, blkLen, Y[yi] +offS, Y[0], (offC +blkLen >= lenC) /* applyFlush */ );
+              Nout = aConv[yi]( aSetupCfg[yi], X +offS, blkLen, Y[yi] +offS, Y[0], 0 /* applyFlush */ );
               offC += Nout;
               ++iter;
               if ( !Nout )
                 break;
-              if ( offC +blkLen >= lenC )
-              {
-                outN[yi] += offC;
-                offC = 0;
-              }
             }
+            //if ( !Nout )
+            //  break;
             t1 = uclock_sec();
+            if ( prev_iter == iter )    // restart from begin of input?
+            {
+                offC = 0;
+                ++aNumLoops[yi];
+            }
           } while ( t1 < tstop );
-          outN[yi] += offC;
+          outN[yi] = offC;
           td = t1 - t0;
-          procSmpPerSec[yi] = cplxFactor * (double)outN[yi] / td;
+          procSmpPerSec[yi] = cplxFactor * (double)outN[yi] * (1.0 / td);
+          aNumIters[yi] = iter;
+          aDuration[yi] = td;
+
+          //printf("algo '%s':\t%.2f MSmp\tin\t%.1f ms\t= %g kSmpPerSec\t%d iters\t%.1f ms\n",
+          //  convText[yi], (double)outN[yi]/(1000.0 * 1000.0), 1000.0 * aDuration[yi], procSmpPerSec[yi] * 0.001, aNumIters[yi], 1000.0 * td );
         }
       }
       else
       {
-        t0 = t1 = td = 0.0;
         outN[yi] = 0;
       }
-      aDuration[yi] = td;
       if ( yi == 0 ) {
         const float * Yvals = Y[0];
         const int64_t refOutLen = cplxFactor * outN[0];
@@ -721,12 +751,38 @@ int test(int FILTERLEN, int convFlags, const int testOutLen, int printDbg, int p
         }
         else
         {
+          // print columns in 1st line
+          if (printAsCSV && *pIsFirstFilterLen)
+          {
+            printf("\n# filterLen, filterOrder, Re/Cx, type, sym, ");
+            for ( yc = 0; yc < NUMY; ++yc )
+            {
+              if (!aRunAlgo[yc] || procSmpPerSec[yc] <= 0.0)
+                continue;
+              if (printAsCSV)
+                printf("%s, ", convText[yc]);
+            }
+            *pIsFirstFilterLen = 0;
+          }
+
           for ( yc = 0; yc < NUMY; ++yc )
           {
+            if (!yc)
+            {
+              double filterExp = log10((double)FILTERLEN) / log10(2.0);
+              printf("\n%5d, %5.1f, %s, %s, %s, ", FILTERLEN, filterExp,
+                     ((convFlags & PFFASTCONV_CPLX_INP_OUT)?"cplx":"real"),
+                     (convFlags & PFFASTCONV_CPLX_INP_OUT)?((convFlags & PFFASTCONV_CPLX_SINGLE_FFT)?" single":" 2x") : "",
+                     ((convFlags & PFFASTCONV_SYMMETRIC)?"symmetric":"non-sym")
+                     );
+            }
             if (!aRunAlgo[yc] || procSmpPerSec[yc] <= 0.0)
               continue;
-            printf("algo '%s':\t%.2f MSmp\tin\t%.1f ms\t= %g kSmpPerSec\n",
-              convText[yc], (double)outN[yc]/(1000.0 * 1000.0), 1000.0 * aDuration[yc], procSmpPerSec[yc] * 0.001 );
+            if (printAsCSV)
+              printf("%.0f, ", procSmpPerSec[yc] * 0.001);
+            else
+              printf("algo '%s':\t%.2f MSmp\tin\t%.1f ms\t= %g kSmpPerSec\t%d iters\t%d loops\n",
+                     convText[yc], (double)outN[yc]/(1000.0 * 1000.0), 1000.0 * aDuration[yc], procSmpPerSec[yc] * 0.001, aNumIters[yc], aNumLoops[yc] );
           }
         }
 
@@ -748,7 +804,8 @@ int test(int FILTERLEN, int convFlags, const int testOutLen, int printDbg, int p
 
       if ( outN[yc] == 0 )
       {
-        printf("output size 0: '%s' not implemented\n", convText[yc]);
+        if (!printAsCSV)
+          printf("output size 0: '%s' not implemented\n", convText[yc]);
       }
       else if ( outN[0] != outN[yc] /* && aFastAlgo[yc] */ && testOutLen )
       {
@@ -770,7 +827,7 @@ int test(int FILTERLEN, int convFlags, const int testOutLen, int printDbg, int p
       numErrOverLimit = 0;
       for ( i = 0; i < outMin; ++i )
       {
-        if ( numErrOverLimit < 6 && fabs(Ycurr[i] - Yref[i]) >= yErrLimit )
+        if ( numErrOverLimit < 6 && fabs(Ycurr[i] - Yref[i]) >= yErrLimit && printErrValues )
         {
           printf("algo '%s': at %d: ***ERROR*** = %f, errLimit = %f, ref = %f, actual = %f\n",
             convText[yc], i, fabs(Ycurr[i] - Yref[i]), yErrLimit, Yref[i], Ycurr[i] );
@@ -816,7 +873,8 @@ int main(int argc, char **argv)
   int result = 0;
   int i, k, M, flagsA, flagsB, flagsC, testOutLen, printDbg, printSpeed;
   int testOutLens = 1, benchConv = 1, quickTest = 0, slowTest = 0;
-  int testReal = 1, testCplx = 1, testSymetric = 0;
+  int testReal = 1, testCplx = 1, testSymetric = 0, abortFirstFastAlgo = 1, printErrValues = 0, printAsCSV = 1;
+  int isFirstFilterLen = 1;
 
   for ( i = 1; i < argc; ++i ) {
 
@@ -873,20 +931,26 @@ int main(int argc, char **argv)
       {
         if ( (M % 16) != 0 && testSymetric )
           continue;
-        result |= test(M, flagsB, testOutLen, printDbg, printSpeed);
+        result |= test(M, flagsB, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, 0, &isFirstFilterLen);
       }
     }
   }
 
   if (benchConv)
   {
+      printf("quickTest is %d\n", quickTest);
+      printf("slowTest is %d\n", slowTest);
+
     for ( k = 0; k < 3; ++k )
     {
       if ( (k == 0 && !testReal) || (k > 0 && !testCplx) )
         continue;
-      printf("\n\n==========\n");
-      printf("starting %s %s benchmark against linear convolutions ..\n", (k == 0 ? "real" : "cplx"), ( k == 0 ? "" : (k==1 ? "2x" : "single") ) );
-      printf("==========\n");
+      if (!printAsCSV)
+      {
+        printf("\n\n==========\n");
+        printf("starting %s %s benchmark against linear convolutions ..\n", (k == 0 ? "real" : "cplx"), ( k == 0 ? "" : (k==1 ? "2x" : "single") ) );
+        printf("==========\n");
+      }
       flagsA = (k == 0) ? 0 : PFFASTCONV_CPLX_INP_OUT;
       flagsB = flagsA | ( testSymetric ? PFFASTCONV_SYMMETRIC : 0 );
       flagsC = flagsB | ( k == 2 ? PFFASTCONV_CPLX_SINGLE_FFT : 0 );
@@ -894,19 +958,31 @@ int main(int argc, char **argv)
       printDbg = 0;
       printSpeed = 1;
       if (!slowTest) {
-        result |= test( 32,     flagsC, testOutLen, printDbg, printSpeed);
-        result |= test( 32+ 16, flagsC, testOutLen, printDbg, printSpeed);
-        result |= test( 64,     flagsC, testOutLen, printDbg, printSpeed);
-        result |= test( 64+ 32, flagsC, testOutLen, printDbg, printSpeed);
-        result |= test(128,     flagsC, testOutLen, printDbg, printSpeed);
+        if (!quickTest) {
+          result |= test(32, flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+          result |= test(32 + 16, flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        }
+        result |= test(64, flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        if (!quickTest) {
+          result |= test(64 + 32, flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+          result |= test(128, flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        }
       }
       if (!quickTest) {
-        result |= test(128+ 64, flagsC, testOutLen, printDbg, printSpeed);
-        result |= test(256,     flagsC, testOutLen, printDbg, printSpeed);
-        result |= test(256+128, flagsC, testOutLen, printDbg, printSpeed);
-        result |= test(512,     flagsC, testOutLen, printDbg, printSpeed);
-        result |= test(1024,    flagsC, testOutLen, printDbg, printSpeed);
+        result |= test(128+ 64, flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        result |= test(256,     flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        result |= test(256+128, flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        result |= test(512,     flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        result |= test(1024,    flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+
+        result |= test(2048,    flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        result |= test(4096,    flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        result |= test(8192,    flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        result |= test(16384,   flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
+        result |= test(32768,   flagsC, testOutLen, printDbg, printSpeed, abortFirstFastAlgo, printErrValues, printAsCSV, &isFirstFilterLen);
       }
+      if (printAsCSV)
+        printf("\n");
     }
   }
 
diff --git a/test_pffft.c b/test_pffft.c
index 2eb185a..a86bdb4 100644
--- a/test_pffft.c
+++ b/test_pffft.c
@@ -1,7 +1,7 @@
 /*
   Copyright (c) 2013 Julien Pommier.
 
-  Small test & bench for PFFFT, comparing its performance with the scalar FFTPACK, FFTW, and Apple vDSP
+  Small test for PFFFT
 
   How to build: 
 
diff --git a/uninstall.cmake b/uninstall.cmake
new file mode 100644
index 0000000..290d1f1
--- /dev/null
+++ b/uninstall.cmake
@@ -0,0 +1,24 @@
+set(MANIFEST "${CMAKE_CURRENT_BINARY_DIR}/install_manifest.txt")
+
+if(NOT EXISTS ${MANIFEST})
+    message(FATAL_ERROR "Cannot find install manifest: '${MANIFEST}'")
+endif()
+
+file(STRINGS ${MANIFEST} files)
+foreach(file ${files})
+    if(EXISTS ${file})
+        message(STATUS "Removing file: '${file}'")
+
+        exec_program(
+            ${CMAKE_COMMAND} ARGS "-E remove ${file}"
+            OUTPUT_VARIABLE stdout
+            RETURN_VALUE result
+        )
+
+        if(NOT "${result}" STREQUAL 0)
+            message(FATAL_ERROR "Failed to remove file: '${file}'.")
+        endif()
+    else()
+        MESSAGE(STATUS "File '${file}' does not exist.")
+    endif()
+endforeach(file)
```

