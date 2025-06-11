```diff
diff --git a/.github/workflows/linux.yml b/.github/workflows/linux.yml
deleted file mode 100644
index f301de6..0000000
--- a/.github/workflows/linux.yml
+++ /dev/null
@@ -1,342 +0,0 @@
-name: Linux
-
-on: [push, pull_request]
-
-env:
-  OPENCL_PKGCONFIG_PATHS: ${{ github.workspace }}/install/lib/pkgconfig:${{ github.workspace }}/external/OpenCL-Headers/install/share/pkgconfig
-
-jobs:
-
-  tools:
-    runs-on: ubuntu-20.04
-    strategy:
-      matrix:
-        CMAKE: [3.21.2]
-    env:
-      CMAKE_URL: https://github.com/Kitware/CMake/releases/download/v${{ matrix.CMAKE }}/cmake-${{ matrix.CMAKE }}-Linux-x86_64.tar.gz
-
-    steps:
-    - name: Cache CMake
-      uses: actions/cache@v3
-      id: cmake
-      env:
-        cache-name: cache-cmake
-      with:
-        path: ~/cmake-${{matrix.CMAKE}}-Linux-x86_64.tar.gz
-        key: ${{ runner.os }}-${{ env.cache-name }}-${{matrix.CMAKE}}
-    - name: Checkout CMake
-      if: steps.cmake.outputs.cache-hit != 'true'
-      run: wget -c -O ~/cmake-${{matrix.CMAKE}}-Linux-x86_64.tar.gz $CMAKE_URL
-
-  cmake-minimum:
-    runs-on: ${{ matrix.OS }}
-    container: streamhpc/opencl-sdk-base:ubuntu-18.04-20220127
-    strategy:
-      matrix:
-        OS: [ubuntu-20.04]
-        COMPILER: [gcc-7, clang-8] #gcc-8 clang-10
-        EXT: [ON, OFF]
-        GEN: [Unix Makefiles]
-        CONFIG: [Debug, Release]
-        STD: [99, 11]
-        BIN: [32, 64]
-        CMAKE: [3.1.3] #3.21.2
-    env:
-      CMAKE_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/cmake
-      CTEST_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/ctest
-      OPENCL_PKGCONFIG_PATHS: /__w/OpenCL-ICD-Loader/OpenCL-ICD-Loader/install/lib/pkgconfig:/__w/OpenCL-ICD-Loader/OpenCL-ICD-Loader/external/OpenCL-Headers/install/share/pkgconfig
-
-
-    steps:
-    - name: Checkout OpenCL-ICD-Loader
-      uses: actions/checkout@v3
-
-    - name: Checkout OpenCL-Headers
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-Headers
-        path: external/OpenCL-Headers
-
-    - name: Build & install OpenCL-Headers
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
-        -D CMAKE_C_FLAGS="-w -m${{matrix.BIN}}"
-        -D CMAKE_C_COMPILER=${{matrix.COMPILER}}
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -D BUILD_TESTING=OFF
-        -B$GITHUB_WORKSPACE/external/OpenCL-Headers/build
-        -H$GITHUB_WORKSPACE/external/OpenCL-Headers &&
-        $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/external/OpenCL-Headers/build
-        --target install
-        --
-        -j`nproc`
-
-    - name: Configure
-      shell: bash
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D BUILD_TESTING=ON
-        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
-        -D CMAKE_C_FLAGS="-Wall -Wextra -Werror -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_C_COMPILER=${{matrix.COMPILER}}
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
-        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -B$GITHUB_WORKSPACE/build
-        -H$GITHUB_WORKSPACE
-
-    - name: Build
-      shell: bash
-      run: $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/build
-        --
-        -j`nproc`
-
-    - name: Test
-      working-directory: ${{runner.workspace}}/OpenCL-ICD-Loader/build
-      shell: bash
-      run: $CTEST_EXE --output-on-failure --parallel `nproc`
-
-    - name: Install
-      shell: bash
-      run: $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/build
-        --target install
-        --
-        -j`nproc`
-
-    - name: "Consume (standalone): Configure/Build/Test"
-      shell: bash
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
-        -D CMAKE_C_COMPILER=${{matrix.COMPILER}}
-        -D CMAKE_C_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/install"
-        -D DRIVER_STUB_PATH=$GITHUB_WORKSPACE/build/libOpenCLDriverStub.so
-        -B$GITHUB_WORKSPACE/build/downstream/bare
-        -H$GITHUB_WORKSPACE/test/pkgconfig/bare ;
-        $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/build/downstream/bare ;
-        cd $GITHUB_WORKSPACE/build/downstream/bare ;
-        $CTEST_EXE --output-on-failure
-
-    - name: "Consume (SDK): Configure/Build/Test"
-      shell: bash
-      run: $CMAKE_EXE -E make_directory $GITHUB_WORKSPACE/install/share/cmake/OpenCL ;
-        echo -e "include(\"$GITHUB_WORKSPACE/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake\")\ninclude(\"\${CMAKE_CURRENT_LIST_DIR}/../OpenCLICDLoader/OpenCLICDLoaderTargets.cmake\")" > $GITHUB_WORKSPACE/install/share/cmake/OpenCL/OpenCLConfig.cmake ;
-        $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
-        -D CMAKE_C_COMPILER=${{matrix.COMPILER}}
-        -D CMAKE_C_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/install"
-        -D DRIVER_STUB_PATH=$GITHUB_WORKSPACE/build/libOpenCLDriverStub.so
-        -B$GITHUB_WORKSPACE/build/downstream/sdk
-        -H$GITHUB_WORKSPACE/test/pkgconfig/sdk ;
-        $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/build/downstream/sdk ;
-        cd $GITHUB_WORKSPACE/build/downstream/sdk ;
-        $CTEST_EXE --output-on-failure
-
-    - name: Test pkg-config --cflags
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL --cflags | grep -q "\-I$GITHUB_WORKSPACE/external/OpenCL-Headers/install/include"
-
-    - name: Test pkg-config --libs
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL --libs | grep -q "\-L$GITHUB_WORKSPACE/install/lib -lOpenCL"
-
-    - name: Consume pkg-config
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_C_COMPILER=${{matrix.COMPILER}}
-        -D CMAKE_C_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D DRIVER_STUB_PATH=$GITHUB_WORKSPACE/build/libOpenCLDriverStub.so
-        -B$GITHUB_WORKSPACE/build/downstream/pkgconfig
-        -H$GITHUB_WORKSPACE/test/pkgconfig/pkgconfig ;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/pkgconfig ;
-        cd $GITHUB_WORKSPACE/build/downstream/pkgconfig ;
-        $CTEST_EXE --output-on-failure
-
-
-
-
-
-  cmake-latest:
-    needs: [tools]
-    runs-on: ${{ matrix.OS }}
-    strategy:
-      matrix:
-        OS : [ubuntu-20.04]
-        COMPILER: [gcc-9, gcc-11, clang-11, clang-13]
-        EXT: [ON, OFF]
-        GEN: [Ninja Multi-Config]
-        STD: [99, 11, 17]
-        BIN: [32, 64]
-        CMAKE: [3.21.2]
-    env:
-      CMAKE_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/cmake
-      CTEST_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/ctest
-
-
-    steps:
-    - name: Checkout OpenCL-ICD-Loader
-      uses: actions/checkout@v3
-
-    - name: Checkout OpenCL-Headers
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-Headers
-        path: external/OpenCL-Headers
-
-    - name: Restore CMake
-      uses: actions/cache@v3
-      id: cmake
-      env:
-        cache-name: cache-cmake
-      with:
-        path: ~/cmake-${{matrix.CMAKE}}-Linux-x86_64.tar.gz
-        key: ${{ runner.os }}-${{ env.cache-name }}-${{matrix.CMAKE}}
-
-    - name: Create Build Environment
-      run: sudo apt-get update -q;
-        if [[ "${{matrix.GEN}}" =~ "Ninja" && ! `which ninja` ]]; then sudo apt install -y ninja-build; fi;
-        if [[ "${{matrix.COMPILER}}" =~ "gcc-11" ]]; then sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test; fi;
-        if [[ "${{matrix.COMPILER}}" =~ "clang-13" ]]; then wget -q -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -; sudo apt-add-repository -y 'deb [arch=amd64] https://apt.llvm.org/focal/ llvm-toolchain-focal-13 main'; fi;
-        sudo apt install -y ${{matrix.COMPILER}};
-        if [[ "${{matrix.BIN}}" == "32" && "${{matrix.COMPILER}}" =~ "gcc" ]]; then sudo apt install -y ${{matrix.COMPILER}}-multilib; fi;
-        if [[ "${{matrix.BIN}}" == "32" && "${{matrix.COMPILER}}" =~ "clang" ]]; then sudo apt install -y gcc-multilib ; fi;
-        mkdir -p /opt/Kitware/CMake;
-        tar -xzf ~/cmake-${{matrix.CMAKE}}-Linux-x86_64.tar.gz --directory /opt/Kitware/CMake;
-        mv /opt/Kitware/CMake/cmake-${{ matrix.CMAKE }}-* /opt/Kitware/CMake/${{ matrix.CMAKE }}
-      # Install Ninja only if it's the selected generator and it's not available.
-
-    - name: Build & install OpenCL-Headers
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_C_FLAGS="-w -m${{matrix.BIN}}"
-        -D CMAKE_C_COMPILER=${{matrix.COMPILER}}
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -D BUILD_TESTING=OFF
-        -B $GITHUB_WORKSPACE/external/OpenCL-Headers/build
-        -S $GITHUB_WORKSPACE/external/OpenCL-Headers;
-        $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/external/OpenCL-Headers/build
-        --target install
-        --config Release
-        --
-        -j`nproc`
-
-    - name: Configure
-      shell: bash
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D BUILD_TESTING=ON
-        -D CMAKE_C_FLAGS="-Wall -Wextra -Werror -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_C_COMPILER=${{matrix.COMPILER}}
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
-        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -B $GITHUB_WORKSPACE/build
-        -S $GITHUB_WORKSPACE
-
-    - name: Build
-      shell: bash
-      run: |
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config Release -- -j`nproc`;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config Debug   -- -j`nproc`
-
-    - name: Test
-      working-directory: ${{runner.workspace}}/OpenCL-ICD-Loader/build
-      shell: bash
-      run: |
-        $CTEST_EXE --output-on-failure -C Release --parallel `nproc`;
-        $CTEST_EXE --output-on-failure -C Debug   --parallel `nproc`;
-
-    - name: Install
-      shell: bash
-      run: $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/build
-        --target install
-        --config Release
-        --
-        -j`nproc`
-
-    - name: "Consume (standalone): Configure/Build/Test"
-      shell: bash
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_C_COMPILER=${{matrix.COMPILER}}
-        -D CMAKE_C_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/install"
-        -D DRIVER_STUB_PATH=$GITHUB_WORKSPACE/build/Release/libOpenCLDriverStub.so
-        -B $GITHUB_WORKSPACE/build/downstream/bare
-        -S $GITHUB_WORKSPACE/test/pkgconfig/bare;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/bare --config Release;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/bare --config Debug;
-        cd $GITHUB_WORKSPACE/build/downstream/bare;
-        $CTEST_EXE --output-on-failure -C Release;
-        $CTEST_EXE --output-on-failure -C Debug;
-
-    - name: "Consume (SDK): Configure/Build/Test"
-      shell: bash
-      run: $CMAKE_EXE -E make_directory $GITHUB_WORKSPACE/install/share/cmake/OpenCL ;
-        echo -e "include(\"$GITHUB_WORKSPACE/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake\")\ninclude(\"\${CMAKE_CURRENT_LIST_DIR}/../OpenCLICDLoader/OpenCLICDLoaderTargets.cmake\")" > $GITHUB_WORKSPACE/install/share/cmake/OpenCL/OpenCLConfig.cmake ;
-        $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_C_COMPILER=${{matrix.COMPILER}}
-        -D CMAKE_C_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/install"
-        -D DRIVER_STUB_PATH=$GITHUB_WORKSPACE/build/Release/libOpenCLDriverStub.so
-        -B $GITHUB_WORKSPACE/build/downstream/sdk
-        -S $GITHUB_WORKSPACE/test/pkgconfig/sdk;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/sdk --config Release;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/sdk --config Debug;
-        cd $GITHUB_WORKSPACE/build/downstream/sdk;
-        $CTEST_EXE --output-on-failure -C Release;
-        $CTEST_EXE --output-on-failure -C Debug;
-
-    - name: Test pkg-config --cflags
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL --cflags | grep -q "\-I$GITHUB_WORKSPACE/external/OpenCL-Headers/install/include"
-
-    - name: Test pkg-config --libs
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL --libs | grep -q "\-L$GITHUB_WORKSPACE/install/lib -lOpenCL"
-
-    - name: Consume pkg-config
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_C_COMPILER=${{matrix.COMPILER}}
-        -D CMAKE_C_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D DRIVER_STUB_PATH=$GITHUB_WORKSPACE/build/Release/libOpenCLDriverStub.so
-        -B $GITHUB_WORKSPACE/build/downstream/pkgconfig
-        -S $GITHUB_WORKSPACE/test/pkgconfig/pkgconfig;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/pkgconfig --config Release;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/pkgconfig --config Debug;
-        cd $GITHUB_WORKSPACE/build/downstream/pkgconfig;
-        $CTEST_EXE --output-on-failure -C Release;
-        $CTEST_EXE --output-on-failure -C Debug;
diff --git a/.github/workflows/macos.yml b/.github/workflows/macos.yml
deleted file mode 100644
index 53fc5e7..0000000
--- a/.github/workflows/macos.yml
+++ /dev/null
@@ -1,132 +0,0 @@
-name: MacOS
-
-on: [push, pull_request]
-
-env:
-  OPENCL_PKGCONFIG_PATHS: ${{ github.workspace }}/install/lib/pkgconfig:${{ github.workspace }}/external/OpenCL-Headers/install/share/pkgconfig
-
-jobs:
-  macos-gcc:
-    #runs-on: macos-latest
-    runs-on: macos-11 # temporary, macos-latest only supports gcc-12
-    strategy:
-      matrix:
-        VER: [9, 10, 11]
-        EXT: [ON, OFF]
-        GEN: [Xcode, Ninja Multi-Config]
-        STD: [99, 11] # 90 results in errors
-
-    steps:
-    - name: Checkout OpenCL-ICD-Loader
-      uses: actions/checkout@v3
-
-    - name: Checkout OpenCL-Headers
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-Headers
-        path: external/OpenCL-Headers
-
-    - name: Install gcc if required
-      run: |
-        if [[ ! `which /usr/local/bin/gcc-${{matrix.VER}}` ]]; then brew install gcc@${{matrix.VER}}; fi;
-
-    - name: Create Build Environment
-      run: |
-        cmake -E make_directory $GITHUB_WORKSPACE/build;
-        cmake -E make_directory $GITHUB_WORKSPACE/install;
-        if [[ "${{matrix.GEN}}" == "Ninja Multi-Config" && ! `which ninja` ]]; then brew install ninja; fi;
-        # Install Ninja only if it's the selected generator and it's not available.
-
-    - name: Build & install OpenCL-Headers
-      run: cmake
-        -G "${{matrix.GEN}}"
-        -D CMAKE_C_FLAGS="-w"
-        -D CMAKE_C_COMPILER=/usr/local/bin/gcc-${{matrix.VER}}
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -D BUILD_TESTING=OFF
-        -S $GITHUB_WORKSPACE/external/OpenCL-Headers
-        -B $GITHUB_WORKSPACE/external/OpenCL-Headers/build &&
-        cmake
-        --build $GITHUB_WORKSPACE/external/OpenCL-Headers/build
-        --target install
-        --config Release
-        --parallel `sysctl -n hw.logicalcpu`
-
-    - name: Configure CMake
-      # no -Werror during configuration because:
-      # warning: ISO C forbids assignment between function pointer and ‘void *’ [-Wpedantic]
-      # warning: unused parameter [-Wunused-parameter]
-      shell: bash
-      run: cmake
-        -G "${{matrix.GEN}}"
-        -D BUILD_TESTING=ON
-        -D CMAKE_C_FLAGS="-Wall -Wextra -pedantic -Wno-format"
-        -D CMAKE_C_COMPILER=/usr/local/bin/gcc-${{matrix.VER}}
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
-        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -S $GITHUB_WORKSPACE
-        -B $GITHUB_WORKSPACE/build
-
-    - name: Build (Xcode)
-      if: matrix.GEN == 'Xcode'
-      shell: bash
-      run: |
-        cmake --build $GITHUB_WORKSPACE/build --config Release --parallel `sysctl -n hw.logicalcpu`
-        cmake --build $GITHUB_WORKSPACE/build --config Debug --parallel `sysctl -n hw.logicalcpu`
-
-    - name: Build (Ninja)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: bash
-      run: |
-        cmake --build $GITHUB_WORKSPACE/build --config Release --parallel `sysctl -n hw.logicalcpu`
-        cmake --build $GITHUB_WORKSPACE/build --config Debug --parallel `sysctl -n hw.logicalcpu`
-
-    - name: Test
-      working-directory: ${{runner.workspace}}/OpenCL-ICD-Loader/build
-      shell: bash
-      run: |
-        ctest -C Release --output-on-failure --parallel `sysctl -n hw.logicalcpu`
-        ctest -C Debug --output-on-failure --parallel `sysctl -n hw.logicalcpu`
-
-    - name: Install (Xcode)
-      if: matrix.GEN == 'Xcode'
-      shell: bash
-      run: |
-        cmake --build $GITHUB_WORKSPACE/build --config Release --target install
-
-    - name: Install (Ninja)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: bash
-      run: |
-        cmake --build $GITHUB_WORKSPACE/build --config Release --target install
-
-    - name: Test pkg-config --cflags
-      shell: bash
-      run: |
-        if [[ ! `which pkg-config` ]]; then brew install pkg-config; fi;
-        PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL --cflags | grep -q "\-I$GITHUB_WORKSPACE/external/OpenCL-Headers/install/include"
-
-    - name: Test pkg-config --libs
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL --libs | grep -q "\-L$GITHUB_WORKSPACE/install/lib -lOpenCL"
-
-    - name: Consume pkg-config
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" cmake
-        -G "${{matrix.GEN}}"
-        -D CMAKE_C_FLAGS="-Wall -Wextra -pedantic -Wno-format"
-        -D CMAKE_C_COMPILER=/usr/local/bin/gcc-${{matrix.VER}}
-        -D CMAKE_C_STANDARD=${{matrix.STD}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D DRIVER_STUB_PATH=$GITHUB_WORKSPACE/build/Release/libOpenCLDriverStub.dylib
-        -B $GITHUB_WORKSPACE/build/downstream/pkgconfig
-        -S $GITHUB_WORKSPACE/test/pkgconfig/pkgconfig;
-        cmake --build $GITHUB_WORKSPACE/build/downstream/pkgconfig --config Release;
-        cmake --build $GITHUB_WORKSPACE/build/downstream/pkgconfig --config Debug;
-        cd $GITHUB_WORKSPACE/build/downstream/pkgconfig;
-        ctest --output-on-failure -C Release
-        ctest --output-on-failure -C Debug
diff --git a/.github/workflows/presubmit.yml b/.github/workflows/presubmit.yml
new file mode 100644
index 0000000..ccada19
--- /dev/null
+++ b/.github/workflows/presubmit.yml
@@ -0,0 +1,725 @@
+name: Presubmit
+
+on:
+  push:
+    paths-ignore:
+      - '**/*.md'
+  pull_request:
+    paths-ignore:
+      - '**/*.md'
+
+jobs:
+  linux:
+    runs-on: ubuntu-latest
+    defaults:
+      run:
+        shell: bash
+    strategy:
+      matrix:
+        CMAKE: [3.26.4]
+        C_COMPILER:
+          - gcc-11
+          - gcc-13
+          - clang-14
+          - clang-16
+        BIN: [64]
+        CONF:
+          - GEN: Unix Makefiles
+            CONFIG: Debug
+          - GEN: Unix Makefiles
+            CONFIG: Release
+          - GEN: Ninja Multi-Config
+            CONFIG: Release
+        IMAGE:
+          - khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-22.04.20230717
+        include:
+          - CMAKE: system
+            C_COMPILER: gcc-9
+            BIN: 64
+            CONF:
+              GEN: Unix Makefiles
+              CONFIG: Debug
+            IMAGE: khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-20.04.20230717
+          - CMAKE: system
+            C_COMPILER: gcc-9
+            BIN: 64
+            CONF:
+              GEN: Unix Makefiles
+              CONFIG: Release
+            IMAGE: khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-20.04.20230717
+          - CMAKE: system
+            C_COMPILER: gcc-9
+            BIN: 32
+            CONF:
+              GEN: Unix Makefiles
+              CONFIG: Debug
+            IMAGE: khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-20.04.20230717
+          - CMAKE: system
+            C_COMPILER: gcc-9
+            BIN: 32
+            CONF:
+              GEN: Unix Makefiles
+              CONFIG: Release
+            IMAGE: khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-20.04.20230717
+    container: ${{matrix.IMAGE}}
+    env:
+      CMAKE_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/cmake
+      CPACK_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/cpack
+      CTEST_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/ctest
+      CC: ${{matrix.C_COMPILER}}
+      CFLAGS: -Wall -Wextra -Werror -pedantic -m${{matrix.BIN}}
+      DEB_INSTALLATION_PATH: /usr
+
+    steps:
+    - name: Install system CMake
+      if: ${{matrix.CMAKE}} == 'system'
+      run: apt-get update -qq && apt-get install -y cmake &&
+        echo "CMAKE_EXE=cmake" >> "$GITHUB_ENV" &&
+        echo "CPACK_EXE=cpack" >> "$GITHUB_ENV" &&
+        echo "CTEST_EXE=ctest" >> "$GITHUB_ENV"
+
+    - name: Checkout OpenCL-ICD-Loader
+      uses: actions/checkout@v4
+
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+      with:
+        path: external/OpenCL-Headers
+        repository: KhronosGroup/OpenCL-Headers
+
+    - name: Configure, install & package OpenCL-Headers
+      run: $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
+        -D CPACK_PACKAGING_INSTALL_PREFIX=$DEB_INSTALLATION_PATH
+        -D BUILD_TESTING=OFF
+        -S $GITHUB_WORKSPACE/external/OpenCL-Headers
+        -B $GITHUB_WORKSPACE/external/OpenCL-Headers/build &&
+        $CMAKE_EXE
+        --build $GITHUB_WORKSPACE/external/OpenCL-Headers/build
+        --target install
+        --parallel `nproc` &&
+        $CPACK_EXE
+        --config "$GITHUB_WORKSPACE/external/OpenCL-Headers/build/CPackConfig.cmake"
+        -G DEB
+        -C ${{matrix.CONF.CONFIG}}
+        -B "$GITHUB_WORKSPACE/external/OpenCL-Headers/package-deb"
+
+    - name: Configure
+      run: $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D BUILD_TESTING=ON
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
+        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
+        -D CPACK_PACKAGING_INSTALL_PREFIX=$DEB_INSTALLATION_PATH
+        -S $GITHUB_WORKSPACE
+        -B $GITHUB_WORKSPACE/build
+
+    - name: Build
+      run: if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config ${{matrix.CONF.CONFIG}} --parallel `nproc`;
+        else
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config Debug;
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config Release;
+        fi
+
+    - name: Test
+      working-directory: ${{runner.workspace}}/OpenCL-ICD-Loader/build
+      run: if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CTEST_EXE --output-on-failure --no-tests=error --parallel `nproc`;
+        else
+          $CTEST_EXE --output-on-failure --no-tests=error -C Debug   --parallel `nproc`;
+          $CTEST_EXE --output-on-failure --no-tests=error -C Release --parallel `nproc`;
+        fi
+
+    - name: Package DEB
+      run: $CPACK_EXE
+        --config "$GITHUB_WORKSPACE/build/CPackConfig.cmake"
+        -G DEB
+        -C ${{matrix.CONF.CONFIG}}
+        -B "$GITHUB_WORKSPACE/package-deb"
+
+    - name: Consume (DEB)
+      run: dpkg -i $GITHUB_WORKSPACE/external/OpenCL-Headers/package-deb/*.deb &&
+        dpkg -i $GITHUB_WORKSPACE/package-deb/*.deb &&
+        $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D DRIVER_STUB_PATH=$GITHUB_WORKSPACE/build/`if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "libOpenCLDriverStub.so"; else echo "${{ matrix.CONF.CONFIG }}/libOpenCLDriverStub.so"; fi`
+        -S $GITHUB_WORKSPACE/test/pkgconfig/bare
+        -B $GITHUB_WORKSPACE/build_package &&
+        if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_package --config ${{matrix.CONF.CONFIG}} --parallel `nproc`;
+        else
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_package --config Debug;
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_package --config Release;
+        fi
+
+    - name: Run consume test (DEB)
+      if: matrix.BIN != 32
+      working-directory: ${{runner.workspace}}/OpenCL-ICD-Loader/build_package
+      run: if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CTEST_EXE -C ${{matrix.CONF.CONFIG}} --output-on-failure --no-tests=error --parallel `nproc`;
+        else
+          $CTEST_EXE -C Debug --output-on-failure --no-tests=error --parallel `nproc`;
+          $CTEST_EXE -C Release --output-on-failure --no-tests=error --parallel `nproc`;
+        fi
+
+    - name: Test pkg-config (DEB)
+      # We expect no pre-processor and compile flags (--cflags) but we do expect link flags (--libs)
+      run: if [[ $(pkg-config OpenCL --cflags) ]];
+        then
+          exit 1;
+        fi &&
+        pkg-config OpenCL --libs | grep -q "\-lOpenCL"
+
+    - name: Test cllayerinfo (DEB)
+      run: cllayerinfo
+
+    - name: Uninstall (DEB)
+      run: apt-get remove -y "khronos-opencl-loader*" opencl-c-headers
+
+    - name: Test install
+      run: $CMAKE_EXE --build $GITHUB_WORKSPACE/build --target install --config ${{matrix.CONF.CONFIG}} --parallel `nproc`
+
+    - name: Consume (install)
+      run: $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/install;$GITHUB_WORKSPACE/external/OpenCL-Headers/install"
+        -D DRIVER_STUB_PATH=$GITHUB_WORKSPACE/build/`if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "libOpenCLDriverStub.so"; else echo "${{ matrix.CONF.CONFIG }}/libOpenCLDriverStub.so"; fi`
+        -S $GITHUB_WORKSPACE/test/pkgconfig/bare
+        -B $GITHUB_WORKSPACE/build_install &&
+        if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_install --parallel `nproc`;
+        else
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_install --config Debug;
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_install --config Release;
+        fi
+
+    - name: Run consume test (install)
+      if: matrix.BIN != 32
+      working-directory: ${{runner.workspace}}/OpenCL-ICD-Loader/build_install
+      run: if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CTEST_EXE -C ${{matrix.CONF.CONFIG}} --output-on-failure --no-tests=error --parallel `nproc`;
+        else
+          $CTEST_EXE -C Debug --output-on-failure --no-tests=error --parallel `nproc`;
+          $CTEST_EXE -C Release --output-on-failure --no-tests=error --parallel `nproc`;
+        fi
+
+    - name: Test pkg-config (install)
+      # We expect no pre-processor and compile flags (--cflags) but we do expect link flags (--libs)
+      run: export PKG_CONFIG_PATH="$GITHUB_WORKSPACE/install/lib/pkgconfig:$GITHUB_WORKSPACE/external/OpenCL-Headers/install/share/pkgconfig" &&
+        pkg-config OpenCL --cflags | grep -q "\-I$GITHUB_WORKSPACE/external/OpenCL-Headers/install/include" &&
+        pkg-config OpenCL --libs | grep -q "\-L$GITHUB_WORKSPACE/install/lib \-lOpenCL"
+
+  windows:
+    runs-on: windows-latest
+    defaults:
+      run:
+        shell: pwsh
+    strategy:
+      matrix:
+        VER: [v142, v143, clangcl]
+        GEN: [Visual Studio 17 2022, Ninja Multi-Config]
+        BIN: [x64]
+        exclude:
+        - VER: clangcl
+          GEN: Ninja Multi-Config
+        include:
+        - VER: v142
+          GEN: Visual Studio 17 2022
+          BIN: x86
+    env:
+      NINJA_URL: https://github.com/ninja-build/ninja/releases/download/v1.10.2/ninja-win.zip
+      NINJA_ROOT: C:\Tools\Ninja
+      VS_ROOT: 'C:\Program Files\Microsoft Visual Studio\2022\Enterprise'
+      UseMultiToolTask: true # Better parallel MSBuild execution
+      EnforceProcessCountAcrossBuilds: 'true'
+      MultiProcMaxCount: '3'
+      # C4152: nonstandard extension, function/data pointer conversion in expression
+      # C4201: nonstandard extension used: nameless struct/union
+      # C4310: cast truncates constant value
+      CFLAGS: /W4 /WX /wd4152 /wd4201 /wd4310
+
+    steps:
+    - name: Cache Ninja install
+      if: matrix.GEN == 'Ninja Multi-Config'
+      id: ninja-install
+      uses: actions/cache@v4
+      with:
+        path: |
+          C:\Tools\Ninja
+        key: ${{runner.os}}-ninja-${{env.NINJA_URL}}
+
+    - name: Install Ninja
+      if: matrix.GEN == 'Ninja Multi-Config' && steps.ninja-install.outputs.cache-hit != 'true'
+      run: |
+        Invoke-WebRequest ${env:NINJA_URL} -OutFile ~\Downloads\ninja-win.zip
+        Expand-Archive ~\Downloads\ninja-win.zip -DestinationPath ${env:NINJA_ROOT}\
+        Remove-Item ~\Downloads\*
+
+    - name: Checkout OpenCL-ICD-Loader
+      uses: actions/checkout@v4
+
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+      with:
+        repository: KhronosGroup/OpenCL-Headers
+        path: external/OpenCL-Headers
+
+    - name: Build & install OpenCL-Headers (MSBuild)
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G "${{matrix.GEN}}" `
+          -A $BIN `
+          -T ${{matrix.VER}} `
+          -D BUILD_TESTING=OFF `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_INSTALL_PREFIX=${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install `
+          -S ${env:GITHUB_WORKSPACE}\external\OpenCL-Headers `
+          -B ${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\build
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-Headers failed." }
+        & cmake `
+          --build "${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\build" `
+          --target install `
+          -- `
+          /verbosity:minimal `
+          /maxCpuCount `
+          /noLogo
+        if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-Headers failed." }
+
+    - name: Build & install OpenCL-Headers (Ninja Multi-Config)
+      if: matrix.GEN == 'Ninja Multi-Config'
+      run: |
+        $VER = switch ('${{matrix.VER}}') { `
+          'v142' {'14.2'} `
+          'v143' {'14.4'} }
+        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
+        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=$VER"
+        & cmake `
+          -G "${{matrix.GEN}}" `
+          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe"  `
+          -D BUILD_TESTING=OFF `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_INSTALL_PREFIX=${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install `
+          -S ${env:GITHUB_WORKSPACE}\external\OpenCL-Headers `
+          -B ${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\build
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-Headers failed." }
+        & cmake `
+          --build "${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\build" `
+          --target install `
+          -- `
+          -j ${env:NUMBER_OF_PROCESSORS}
+        if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-Headers failed." }
+
+    - name: Configure (MSBuild)
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G "${{matrix.GEN}}" `
+          -A $BIN `
+          -T ${{matrix.VER}} `
+          -D BUILD_TESTING=ON `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_INSTALL_PREFIX=${env:GITHUB_WORKSPACE}\install `
+          -D CMAKE_PREFIX_PATH=${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install `
+          -S ${env:GITHUB_WORKSPACE} `
+          -B ${env:GITHUB_WORKSPACE}\build
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-ICD-Loader failed." }
+
+    - name: Configure (Ninja Multi-Config)
+      if: matrix.GEN == 'Ninja Multi-Config'
+      run: |
+        $VER = switch ('${{matrix.VER}}') { `
+          'v142' {'14.2'} `
+          'v143' {'14.4'} }
+        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
+        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=$VER"
+        & cmake `
+          -G "${{matrix.GEN}}" `
+          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe" `
+          -D BUILD_TESTING=ON `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL `
+          -D CMAKE_INSTALL_PREFIX=${env:GITHUB_WORKSPACE}\install `
+          -D CMAKE_PREFIX_PATH=${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install `
+          -S ${env:GITHUB_WORKSPACE} `
+          -B ${env:GITHUB_WORKSPACE}\build
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-ICD-Loader failed." }
+
+    - name: Build (MSBuild)
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\build" `
+            --config $Config `
+            -- `
+            /verbosity:minimal `
+            /maxCpuCount `
+            /noLogo
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-ICD-Loader in $Config failed." }
+        }
+
+    - name: Build (Ninja Multi-Config)
+      if: matrix.GEN == 'Ninja Multi-Config'
+      run: |
+        $VER = switch ('${{matrix.VER}}') { `
+          'v142' {'14.2'} `
+          'v143' {'14.4'} }
+        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
+        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=$VER"
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\build" `
+            --config $Config `
+            -- `
+            -j ${env:NUMBER_OF_PROCESSORS}
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-ICD-Loader in $Config failed." }
+        }
+
+    - name: Test
+      working-directory: ${{runner.workspace}}/OpenCL-ICD-Loader/build
+      run: |
+        $REG = if('${{matrix.BIN}}' -eq 'x64') {"reg"} else {"${env:SystemRoot}\Syswow64\reg.exe"}
+        $KEY_NAME = "HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors"
+        foreach ($Config in 'Release','Debug') {
+          $VALUE_NAME = "${env:GITHUB_WORKSPACE}/build/$Config/OpenCLDriverStub.dll"
+          & $REG ADD $KEY_NAME /v $VALUE_NAME /t REG_DWORD /d 0
+          & ctest -C $Config --output-on-failure --no-tests=error --parallel ${env:NUMBER_OF_PROCESSORS}
+          if ($LASTEXITCODE -ne 0) { throw "Testing OpenCL-ICD-Loader in $Config failed." }
+          & $REG DELETE $KEY_NAME /v $VALUE_NAME /f
+        }
+
+    - name: Install
+      run: |
+        & cmake `
+          --build "${env:GITHUB_WORKSPACE}\build" `
+          --config Release `
+          --target install
+        if ($LASTEXITCODE -ne 0) { throw "Installing OpenCL-ICD-Loader failed." }
+
+    - name: "Consume (MSBuild standalone): Configure/Build/Test"
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -A $BIN `
+          -T ${{matrix.VER}} `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install;${env:GITHUB_WORKSPACE}\install" `
+          -D DRIVER_STUB_PATH="${env:GITHUB_WORKSPACE}\build\Release\OpenCLDriverStub.dll" `
+          -S "${env:GITHUB_WORKSPACE}\test\pkgconfig\bare" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-ICD-Loader standalone consume test failed." }
+        $REG = if('${{matrix.BIN}}' -eq 'x64') {"reg"} else {"${env:SystemRoot}\Syswow64\reg.exe"}
+        $KEY_NAME = "HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors"
+        $VALUE_NAME = "${env:GITHUB_WORKSPACE}/build/Release/OpenCLDriverStub.dll"
+        & $REG ADD $KEY_NAME /v $VALUE_NAME /t REG_DWORD /d 0
+        if ($LASTEXITCODE -ne 0) { throw "Editing registry failed." }
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare" `
+            --config $Config
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-ICD-Loader standalone consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare
+          & ctest --output-on-failure --no-tests=error -C $Config
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-ICD-Loader standalone consume test in $Config failed." }
+        }
+        & $REG DELETE $KEY_NAME /v $VALUE_NAME /f
+        if ($LASTEXITCODE -ne 0) { throw "Editing registry failed." }
+
+    - name: "Consume (Ninja-Multi-Config standalone): Configure/Build/Test"
+      if: matrix.GEN == 'Ninja Multi-Config'
+      run: |
+        $VER = switch ('${{matrix.VER}}') { `
+          'v142' {'14.2'} `
+          'v143' {'14.4'} }
+        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
+        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=$VER"
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe" `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install;${env:GITHUB_WORKSPACE}\install" `
+          -D DRIVER_STUB_PATH="${env:GITHUB_WORKSPACE}\build\Release\OpenCLDriverStub.dll" `
+          -S "${env:GITHUB_WORKSPACE}\test\pkgconfig\bare" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-ICD-Loader standalone consume test failed." }
+        $REG = if('${{matrix.BIN}}' -eq 'x64') {"reg"} else {"${env:SystemRoot}\Syswow64\reg.exe"}
+        $KEY_NAME = "HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors"
+        $VALUE_NAME = "${env:GITHUB_WORKSPACE}/build/Release/OpenCLDriverStub.dll"
+        & $REG ADD $KEY_NAME /v $VALUE_NAME /t REG_DWORD /d 0
+        if ($LASTEXITCODE -ne 0) { throw "Editing registry failed." }
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare" `
+            --config $Config
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-ICD-Loader standalone consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare
+          & ctest --output-on-failure --no-tests=error -C $Config
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-ICD-Loader standalone consume test in $Config failed." }
+        }
+        & $REG DELETE $KEY_NAME /v $VALUE_NAME /f
+        if ($LASTEXITCODE -ne 0) { throw "Editing registry failed." }
+
+    - name: Consume (Emulate SDK presence)
+      run: |
+        New-Item -Type Directory -Path ${env:GITHUB_WORKSPACE}\install\share\cmake\OpenCL
+        $workspace = ${env:GITHUB_WORKSPACE}.replace("\", "/")
+        New-Item -Type File -Path ${env:GITHUB_WORKSPACE}\install\share\cmake\OpenCL\OpenCLConfig.cmake -Value "include(`"$workspace/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake`")`r`ninclude(`"`${CMAKE_CURRENT_LIST_DIR}/../OpenCLICDLoader/OpenCLICDLoaderTargets.cmake`")"
+
+    - name: "Consume (MSBuild SDK): Configure/Build/Test"
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -A $BIN `
+          -T ${{matrix.VER}} `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install;${env:GITHUB_WORKSPACE}\install" `
+          -D DRIVER_STUB_PATH="${env:GITHUB_WORKSPACE}\build\Release\OpenCLDriverStub.dll" `
+          -S "${env:GITHUB_WORKSPACE}\test\pkgconfig\sdk" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-ICD-Loader in-SDK consume test failed." }
+        $REG = if('${{matrix.BIN}}' -eq 'x64') {"reg"} else {"${env:SystemRoot}\Syswow64\reg.exe"}
+        $KEY_NAME = "HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors"
+        $VALUE_NAME = "${env:GITHUB_WORKSPACE}/build/Release/OpenCLDriverStub.dll"
+        & $REG ADD $KEY_NAME /v $VALUE_NAME /t REG_DWORD /d 0
+        if ($LASTEXITCODE -ne 0) { throw "Editing registry failed." }
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk" `
+            --config $Config
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-ICD-Loader in-SDK consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk
+          & ctest --output-on-failure --no-tests=error -C $Config
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-ICD-Loader in-SDK consume test in $Config failed." }
+        }
+        & $REG DELETE $KEY_NAME /v $VALUE_NAME /f
+        if ($LASTEXITCODE -ne 0) { throw "Editing registry failed." }
+
+    - name: "Consume (Ninja-Multi-Config SDK): Configure/Build/Test"
+      if: matrix.GEN == 'Ninja Multi-Config'
+      run: |
+        $VER = switch ('${{matrix.VER}}') { `
+          'v142' {'14.2'} `
+          'v143' {'14.4'} }
+        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
+        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=$VER"
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe" `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install;${env:GITHUB_WORKSPACE}\install" `
+          -D DRIVER_STUB_PATH="${env:GITHUB_WORKSPACE}\build\Release\OpenCLDriverStub.dll" `
+          -S "${env:GITHUB_WORKSPACE}\test\pkgconfig\sdk" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-ICD-Loader in-SDK consume test failed." }
+        $REG = if('${{matrix.BIN}}' -eq 'x64') {"reg"} else {"${env:SystemRoot}\Syswow64\reg.exe"}
+        $KEY_NAME = "HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors"
+        $VALUE_NAME = "${env:GITHUB_WORKSPACE}/build/Release/OpenCLDriverStub.dll"
+        & $REG ADD $KEY_NAME /v $VALUE_NAME /t REG_DWORD /d 0
+        if ($LASTEXITCODE -ne 0) { throw "Editing registry failed." }
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk" `
+            --config $Config
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-ICD-Loader in-SDK consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk
+          & ctest --output-on-failure --no-tests=error -C $Config
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-ICD-Loader in-SDK consume test in $Config failed." }
+        }
+        & $REG DELETE $KEY_NAME /v $VALUE_NAME /f
+        if ($LASTEXITCODE -ne 0) { throw "Editing registry failed." }
+
+  macos:
+    runs-on: macos-latest
+    defaults:
+      run:
+        shell: bash
+    strategy:
+      matrix:
+        C_COMPILER:
+        - /usr/bin/clang
+        # Disabled due to problems with __has_cpp_attribute
+        # See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=114007
+        # - gcc-11
+        # Disabled due to problems with the __API_AVAILABLE macro
+        # - gcc-13
+        GEN:
+        - Xcode
+        - Ninja Multi-Config
+        exclude:
+        # These entries are excluded, since XCode selects its own compiler
+        - C_COMPILER: gcc-11
+          GEN: Xcode
+        - C_COMPILER: gcc-13
+          GEN: Xcode
+    env:
+      CFLAGS: -Wall -Wextra -pedantic -Werror
+      CC: ${{ matrix.C_COMPILER }}
+
+    steps:
+    - name: Checkout OpenCL-ICD-Loader
+      uses: actions/checkout@v4
+
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+      with:
+        repository: KhronosGroup/OpenCL-Headers
+        path: external/OpenCL-Headers
+
+    - name: Create Build Environment
+      run: |
+        # Install Ninja only if it's the selected generator and it's not available.
+        if [[ "${{matrix.GEN}}" == "Ninja Multi-Config" && ! `which ninja` ]]; then brew install ninja; fi &&
+        if [[ ! `which pkg-config` ]]; then brew install pkg-config; fi &&
+        cmake --version
+
+    - name: Build & install OpenCL-Headers
+      run: cmake
+        -G "${{matrix.GEN}}"
+        -D BUILD_TESTING=OFF
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
+        -S $GITHUB_WORKSPACE/external/OpenCL-Headers
+        -B $GITHUB_WORKSPACE/external/OpenCL-Headers/build &&
+        cmake
+        --build $GITHUB_WORKSPACE/external/OpenCL-Headers/build
+        --target install
+        --config Release
+        --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Configure
+      run: cmake
+        -G "${{matrix.GEN}}"
+        -D BUILD_TESTING=ON
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
+        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
+        -S $GITHUB_WORKSPACE
+        -B $GITHUB_WORKSPACE/build
+
+    - name: Build
+      run: |
+        cmake --build $GITHUB_WORKSPACE/build --config Release --parallel `sysctl -n hw.logicalcpu`
+        cmake --build $GITHUB_WORKSPACE/build --config Debug --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Test
+      working-directory: ${{runner.workspace}}/OpenCL-ICD-Loader/build
+      run: |
+        ctest -C Release --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu`
+        ctest -C Debug --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Test install
+      run: |
+        cmake --build $GITHUB_WORKSPACE/build --config Release --target install
+
+    - name: Consume (install)
+      run: cmake
+        -G "${{matrix.GEN}}"
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/install"
+        -S $GITHUB_WORKSPACE/test/pkgconfig/bare
+        -B $GITHUB_WORKSPACE/build_install &&
+        cmake --build $GITHUB_WORKSPACE/build_install --config Release --parallel `sysctl -n hw.logicalcpu` &&
+        cmake --build $GITHUB_WORKSPACE/build_install --config Debug --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Test pkg-config
+      run: |
+        export PKG_CONFIG_PATH=$GITHUB_WORKSPACE/install/lib/pkgconfig:$GITHUB_WORKSPACE/external/OpenCL-Headers/install/share/pkgconfig &&
+        pkg-config OpenCL --cflags | grep -q "\-I$GITHUB_WORKSPACE/external/OpenCL-Headers/install/include" &&
+        pkg-config OpenCL --libs | grep -q "\-L$GITHUB_WORKSPACE/install/lib -lOpenCL"
+
+    - name: Consume pkg-config
+      run: export PKG_CONFIG_PATH=$GITHUB_WORKSPACE/install/lib/pkgconfig:$GITHUB_WORKSPACE/external/OpenCL-Headers/install/share/pkgconfig &&
+        cmake
+        -G "${{matrix.GEN}}"
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install"
+        -D DRIVER_STUB_PATH=$GITHUB_WORKSPACE/build/Release/libOpenCLDriverStub.dylib
+        -B $GITHUB_WORKSPACE/build/downstream/pkgconfig
+        -S $GITHUB_WORKSPACE/test/pkgconfig/pkgconfig &&
+        cmake --build $GITHUB_WORKSPACE/build/downstream/pkgconfig --config Release --parallel `sysctl -n hw.logicalcpu` &&
+        cmake --build $GITHUB_WORKSPACE/build/downstream/pkgconfig --config Debug --parallel `sysctl -n hw.logicalcpu` &&
+        cd $GITHUB_WORKSPACE/build/downstream/pkgconfig &&
+        ctest -C Release --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu` &&
+        ctest -C Debug --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu`
+
+  android:
+    runs-on: ubuntu-latest
+    defaults:
+      run:
+        shell: bash
+    strategy:
+      matrix:
+        ABI:
+        - arm64-v8a
+        - x86_64
+        API_LEVEL:
+        - android-19
+        - android-33
+        CONFIG:
+        - Debug
+        - Release
+    env:
+      CFLAGS: -Wall -Wextra -pedantic -Werror
+    steps:
+    - name: Checkout OpenCL-ICD-Loader
+      uses: actions/checkout@v4
+
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+      with:
+        repository: KhronosGroup/OpenCL-Headers
+        path: external/OpenCL-Headers
+
+    - name: Configure & install OpenCL-Headers
+      run: cmake
+        -G "Unix Makefiles"
+        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
+        -D BUILD_TESTING=OFF
+        -S $GITHUB_WORKSPACE/external/OpenCL-Headers
+        -B $GITHUB_WORKSPACE/external/OpenCL-Headers/build &&
+        cmake
+        --build $GITHUB_WORKSPACE/external/OpenCL-Headers/build
+        --target install
+        --
+        -j`nproc`
+
+    - name: Configure
+      run: cmake
+        -G "Unix Makefiles"
+        -D BUILD_TESTING=ON
+        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
+        -D CMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake
+        -D ANDROID_ABI=${{matrix.ABI}}
+        -D ANDROID_PLATFORM=${{matrix.API_LEVEL}}
+        -D CMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY
+        -D CMAKE_FIND_ROOT_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
+        -S $GITHUB_WORKSPACE
+        -B $GITHUB_WORKSPACE/build
+
+    - name: Build
+      run: cmake --build $GITHUB_WORKSPACE/build --parallel `nproc`
diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
new file mode 100644
index 0000000..06a8c28
--- /dev/null
+++ b/.github/workflows/release.yml
@@ -0,0 +1,74 @@
+name: Release
+
+on:
+  push:
+    tags:
+    - "v*"
+env:
+  distroseries: jammy
+
+jobs:
+  release:
+    if: false
+    runs-on: ubuntu-latest
+    defaults:
+      run:
+        shell: bash
+    steps:
+    - name: Add PPA
+      run: sudo add-apt-repository -y ppa:${{ vars.PPA }}
+
+    - name: Install prerequisites
+      run: sudo apt-get update -qq && sudo apt-get install -y cmake devscripts debhelper-compat=13 opencl-c-headers
+
+    - name: Import GPG signing key
+      run: echo "${{ secrets.DEB_SIGNING_KEY }}" | gpg --import
+
+    - name: Download and extract source code
+      run: |
+        wget -O $GITHUB_WORKSPACE/source.orig.tar.gz https://github.com/$GITHUB_REPOSITORY/archive/refs/tags/$GITHUB_REF_NAME.tar.gz
+        tar -xvf $GITHUB_WORKSPACE/source.orig.tar.gz
+
+    - name: Configure project out-of-tree
+      run: cmake
+        -S $GITHUB_WORKSPACE/OpenCL-ICD-Loader*
+        -B $GITHUB_WORKSPACE/../build
+        -D CMAKE_BUILD_TYPE=Release
+        -D CMAKE_INSTALL_PREFIX=/usr
+        -D BUILD_TESTING=OFF
+        -D LATEST_RELEASE_VERSION=$GITHUB_REF_NAME
+        -D CPACK_DEBIAN_PACKAGE_MAINTAINER="${{ vars.DEB_MAINTAINER }}"
+        -D DEBIAN_VERSION_SUFFIX=${{ vars.DEB_VERSION_SUFFIX }}
+
+    - name: Generate packaging scripts
+      run: cmake
+        -D CMAKE_CACHE_PATH=$GITHUB_WORKSPACE/../build/CMakeCache.txt
+        -D ORIG_ARCHIVE=$GITHUB_WORKSPACE/source.orig.tar.gz
+        -D LATEST_RELEASE_VERSION=$GITHUB_REF_NAME
+        -D DEBIAN_DISTROSERIES=${{ env.distroseries }}
+        -D DEBIAN_PACKAGE_MAINTAINER="${{ vars.DEB_MAINTAINER }}"
+        -D DEBIAN_VERSION_SUFFIX=${{ vars.DEB_VERSION_SUFFIX }}
+        -P $GITHUB_WORKSPACE/OpenCL-ICD-Loader*/cmake/DebSourcePkg.cmake
+
+    - name: Build source package
+      run: |
+        cd $GITHUB_WORKSPACE/OpenCL-ICD-Loader*/
+        debuild -S -sa
+
+    - name: Build binary package
+      run: cpack
+        -G DEB
+        -C Release
+        -B $GITHUB_WORKSPACE/../build
+        --config $GITHUB_WORKSPACE/../build/CPackConfig.cmake
+
+    # The following step does not depend on the previous step "Build binary package",
+    # but if the binary package build is unsuccessful, it is better not to push the
+    # source packages to the PPA
+    - name: Push source package to the PPA
+      run: dput ppa:${{ vars.PPA }} $GITHUB_WORKSPACE/*source.changes
+
+    - name: Create GitHub release
+      uses: softprops/action-gh-release@v1
+      with:
+        files: ${{ github.workspace }}/../build/*.deb
diff --git a/.github/workflows/windows.yml b/.github/workflows/windows.yml
deleted file mode 100644
index 407a7e2..0000000
--- a/.github/workflows/windows.yml
+++ /dev/null
@@ -1,246 +0,0 @@
-name: Windows
-
-on: [push, pull_request]
-
-jobs:
-
-  tools:
-    runs-on: windows-2022
-    strategy:
-      matrix:
-        CMAKE: [3.22.0]
-        NINJA: [1.10.2]
-    env:
-      CMAKE_URL: https://github.com/Kitware/CMake/releases/download/v${{matrix.CMAKE}}/cmake-${{matrix.CMAKE}}-windows-x86_64.zip
-      NINJA_URL: https://github.com/ninja-build/ninja/releases/download/v${{matrix.NINJA}}/ninja-win.zip
-
-    steps:
-    - name: Cache CMake
-      uses: actions/cache@v3
-      id: cmake
-      env:
-        cache-name: cache-cmake
-      with:
-        path: ~/Downloads/cmake-${{matrix.CMAKE}}-windows-x86_64.zip
-        key: ${{ runner.os }}-${{ env.cache-name }}-${{matrix.CMAKE}}
-    - name: Cache Ninja
-      uses: actions/cache@v3
-      id: ninja
-      env:
-        cache-name: cache-ninja
-      with:
-        path: ~/Downloads/ninja-win.zip
-        key: ${{ runner.os }}-${{ env.cache-name }}-${{matrix.NINJA}}
-    - name: Checkout CMake
-      if: steps.cmake.outputs.cache-hit != 'true'
-      shell: pwsh
-      run: Invoke-WebRequest ${env:CMAKE_URL} -OutFile ~\Downloads\cmake-${{matrix.CMAKE}}-windows-x86_64.zip
-    - name: Checkout Ninja
-      if: steps.ninja.outputs.cache-hit != 'true'
-      shell: pwsh
-      run: Invoke-WebRequest ${env:NINJA_URL} -OutFile ~\Downloads\ninja-win.zip
-
-  msvc:
-    needs: [tools]
-    runs-on: windows-2022
-    strategy:
-      matrix:
-        VER: [v141, v142, v143]
-        EXT: [ON, OFF]
-        GEN: [Visual Studio 17 2022, Ninja Multi-Config]
-        BIN: [x64, x86]
-        STD: [90, 11, 17]
-        CMAKE: [3.22.0]
-        NINJA: [1.10.2]
-    env:
-      CMAKE_EXE: C:\Tools\Kitware\CMake\${{matrix.CMAKE}}\bin\cmake.exe
-      CTEST_EXE: C:\Tools\Kitware\CMake\${{matrix.CMAKE}}\bin\ctest.exe
-      NINJA_EXE: C:\Tools\Ninja\ninja.exe
-
-    steps:
-    - name: Checkout OpenCL-ICD-Loader
-      uses: actions/checkout@v3
-
-    - name: Checkout OpenCL-Headers
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-Headers
-        path: external/OpenCL-Headers
-
-    - name: Restore CMake
-      uses: actions/cache@v3
-      id: cmake
-      env:
-        cache-name: cache-cmake
-      with:
-        path: ~/Downloads/cmake-${{matrix.CMAKE}}-windows-x86_64.zip
-        key: ${{ runner.os }}-${{ env.cache-name }}-${{matrix.CMAKE}}
-
-    - name: Restore Ninja
-      uses: actions/cache@v3
-      id: ninja
-      env:
-        cache-name: cache-ninja
-      with:
-        path: ~/Downloads/ninja-win.zip
-        key: ${{ runner.os }}-${{ env.cache-name }}-${{matrix.NINJA}}
-
-    - name: Create Build Environment
-      shell: pwsh
-      run: |
-        Expand-Archive ~\Downloads\cmake-${{matrix.CMAKE}}-windows-x86_64.zip -DestinationPath C:\Tools\Kitware\CMake\
-        Rename-Item C:\Tools\Kitware\CMake\* ${{matrix.CMAKE}}
-        Expand-Archive ~\Downloads\ninja-win.zip -DestinationPath C:\Tools\Ninja\
-        & ${env:CMAKE_EXE} --version
-        & ${env:NINJA_EXE} --version
-
-    - name: Build & install OpenCL-Headers (MSBuild)
-      if: matrix.GEN == 'Visual Studio 17 2022'
-      shell: cmd
-      run: |
-        set C_FLAGS="/W4 /WX"
-        if /I "${{matrix.BIN}}"=="x86" (set BIN=Win32) else (set BIN=x64)
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -A %BIN% -T ${{matrix.VER}} -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\external\OpenCL-Headers\install -D BUILD_TESTING=OFF -S %GITHUB_WORKSPACE%\external\OpenCL-Headers -B %GITHUB_WORKSPACE%\external\OpenCL-Headers\build
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/external/OpenCL-Headers/build --target install --config Release -- /verbosity:minimal /maxCpuCount /noLogo
-
-    - name: Build & install OpenCL-Headers (Ninja Multi-Config)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: cmd
-      run: |
-        set C_FLAGS="/W4 /WX"
-        if /I "${{matrix.VER}}"=="v140" (set VER=14.0)
-        if /I "${{matrix.VER}}"=="v141" (set VER=14.1)
-        if /I "${{matrix.VER}}"=="v142" (set VER=14.2)
-        if /I "${{matrix.VER}}"=="v143" (set VER=14.3)
-        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" ${{matrix.BIN}} /vcvars_ver=%VER%
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_MAKE_PROGRAM=%NINJA_EXE% -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\external\OpenCL-Headers\install -D BUILD_TESTING=OFF -S %GITHUB_WORKSPACE%\external\OpenCL-Headers -B %GITHUB_WORKSPACE%\external\OpenCL-Headers\build
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/external/OpenCL-Headers/build --target install -- -j%NUMBER_OF_PROCESSORS%
-
-    - name: Configure (MSBuild)
-      if: matrix.GEN == 'Visual Studio 17 2022'
-      shell: cmd
-      # no /WX during configuration because:
-      # warning C4459: declaration of 'platform' hides global declaration
-      # warning C4100: 'input_headers': unreferenced formal parameter
-      run: |
-        set C_FLAGS="/W4"
-        if /I "${{matrix.BIN}}"=="x86" (set BIN=Win32) else (set BIN=x64)
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -A %BIN% -T ${{matrix.VER}} -D BUILD_TESTING=ON -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH=%GITHUB_WORKSPACE%\external\OpenCL-Headers\install -S %GITHUB_WORKSPACE% -B %GITHUB_WORKSPACE%\build
-
-    - name: Configure (Ninja Multi-Config)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: cmd
-      # no /WX during configuration because:
-      # warning C4459: declaration of 'platform' hides global declaration
-      # warning C4100: 'input_headers': unreferenced formal parameter
-      run: |
-        set C_FLAGS="/W4"
-        if /I "${{matrix.VER}}"=="v140" (set VER=14.0)
-        if /I "${{matrix.VER}}"=="v141" (set VER=14.1)
-        if /I "${{matrix.VER}}"=="v142" (set VER=14.2)
-        if /I "${{matrix.VER}}"=="v143" (set VER=14.3)
-        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" ${{matrix.BIN}} /vcvars_ver=%VER%
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_MAKE_PROGRAM=%NINJA_EXE% -D BUILD_TESTING=ON -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH=%GITHUB_WORKSPACE%\external\OpenCL-Headers\install -S %GITHUB_WORKSPACE% -B %GITHUB_WORKSPACE%\build
-
-    - name: Build (MSBuild)
-      if: matrix.GEN == 'Visual Studio 17 2022'
-      shell: cmd
-      run: |
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%\build --config Release -- /verbosity:minimal /maxCpuCount /noLogo
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%\build --config Debug -- /verbosity:minimal /maxCpuCount /noLogo
-
-    - name: Build (Ninja)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: cmd
-      run: |
-        if /I "${{matrix.VER}}"=="v140" set VER=14.0
-        if /I "${{matrix.VER}}"=="v141" set VER=14.1
-        if /I "${{matrix.VER}}"=="v142" set VER=14.2
-        if /I "${{matrix.VER}}"=="v143" set VER=14.3
-        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" ${{matrix.BIN}} /vcvars_ver=%VER%
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%\build --config Release
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%\build --config Debug
-
-    - name: Test
-      working-directory: ${{runner.workspace}}/OpenCL-ICD-Loader/build
-      shell: cmd
-      run: |
-        if /I "${{matrix.BIN}}"=="x64" set REG=reg
-        if /I "${{matrix.BIN}}"=="x86" set REG=%systemroot%\Syswow64\reg.exe
-        %REG% ADD HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors /v %GITHUB_WORKSPACE%/build/Release/OpenCLDriverStub.dll /t REG_DWORD /d 0
-        %CTEST_EXE% -C Release --output-on-failure --parallel %NUMBER_OF_PROCESSORS%
-        if errorlevel 1 (
-          exit /b %errorlevel%
-        )
-        %REG% DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors /v %GITHUB_WORKSPACE%/build/Release/OpenCLDriverStub.dll /f
-        %REG% ADD HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors /v %GITHUB_WORKSPACE%/build/Debug/OpenCLDriverStub.dll /t REG_DWORD /d 0
-        %CTEST_EXE% -C Debug --output-on-failure --parallel %NUMBER_OF_PROCESSORS%
-        if errorlevel 1 (
-          exit /b %errorlevel%
-        )
-        %REG% DELETE HKEY_LOCAL_MACHINE\SOFTWARE\Khronos\OpenCL\Vendors /v %GITHUB_WORKSPACE%/build/Debug/OpenCLDriverStub.dll /f
-
-    - name: Install
-      shell: cmd
-      run: |
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/build --config Release --target install
-
-    - name: "Consume (MSBuild standalone): Configure/Build/Test"
-      shell: cmd
-      run: |
-        set C_FLAGS="/W4"
-        if /I "${{matrix.BIN}}"=="x86" (set BIN=Win32) else (set BIN=x64)
-        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" ${{matrix.BIN}} /vcvars_ver=%VER%
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH="%GITHUB_WORKSPACE%\external\OpenCL-Headers\install;%GITHUB_WORKSPACE%\install" -D DRIVER_STUB_PATH=%GITHUB_WORKSPACE%/build/Release/OpenCLDriverStub.dll -B %GITHUB_WORKSPACE%/build/downstream/bare -S %GITHUB_WORKSPACE%/test/pkgconfig/bare
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/test/pkgconfig/bare --config Release
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/test/pkgconfig/bare --config Debug
-        cd %GITHUB_WORKSPACE%/test/pkgconfig/bare
-        %CTEST_EXE% --output-on-failure -C Release
-        %CTEST_EXE% --output-on-failure -C Debug
-
-    - name: "Consume (MSBuild SDK): Configure/Build/Test"
-      shell: cmd
-      run: |
-        set C_FLAGS="/W4"
-        if /I "${{matrix.BIN}}"=="x86" (set BIN=Win32) else (set BIN=x64)
-        %CMAKE_EXE% -E make_directory $GITHUB_WORKSPACE/install/share/cmake/OpenCL
-        echo -e 'include("/home/runner/work/OpenCL-ICD-Loader/OpenCL-ICD-Loader/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake")\ninclude("${CMAKE_CURRENT_LIST_DIR}/../OpenCLICDLoader/OpenCLICDLoaderTargets.cmake")' > $GITHUB_WORKSPACE/install/share/cmake/OpenCL/OpenCLConfig.cmake
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH="%GITHUB_WORKSPACE%\external\OpenCL-Headers\install;%GITHUB_WORKSPACE%\install" -D DRIVER_STUB_PATH=%GITHUB_WORKSPACE%/build/Release/OpenCLDriverStub.dll -B %GITHUB_WORKSPACE%/build/downstream/bare -S %GITHUB_WORKSPACE%/test/pkgconfig/bare
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/test/pkgconfig/bare --config Release
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/test/pkgconfig/bare --config Debug
-        cd %GITHUB_WORKSPACE%/test/pkgconfig/bare
-        %CTEST_EXE% --output-on-failure -C Release
-        %CTEST_EXE% --output-on-failure -C Debug
-
-    - name: "Consume (Ninja-Multi-Config standalone): Configure/Build/Test"
-      shell: cmd
-      run: |
-        set C_FLAGS="/W4"
-        if /I "${{matrix.VER}}"=="v140" (set VER=14.0)
-        if /I "${{matrix.VER}}"=="v141" (set VER=14.1)
-        if /I "${{matrix.VER}}"=="v142" (set VER=14.2)
-        if /I "${{matrix.VER}}"=="v143" (set VER=14.3)
-        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" ${{matrix.BIN}} /vcvars_ver=%VER%
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_MAKE_PROGRAM=%NINJA_EXE% -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH="%GITHUB_WORKSPACE%\external\OpenCL-Headers\install;%GITHUB_WORKSPACE%\install" -D DRIVER_STUB_PATH=%GITHUB_WORKSPACE%/build/Release/OpenCLDriverStub.dll -B %GITHUB_WORKSPACE%/build/downstream/bare -S %GITHUB_WORKSPACE%/test/pkgconfig/bare
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/test/pkgconfig/bare --config Release
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/test/pkgconfig/bare --config Debug
-        cd %GITHUB_WORKSPACE%/test/pkgconfig/bare
-        %CTEST_EXE% --output-on-failure -C Release
-        %CTEST_EXE% --output-on-failure -C Debug
-
-    - name: "Consume (Ninja-Multi-Config SDK): Configure/Build/Test"
-      shell: cmd
-      run: |
-        set C_FLAGS="/W4"
-        if /I "${{matrix.VER}}"=="v140" (set VER=14.0)
-        if /I "${{matrix.VER}}"=="v141" (set VER=14.1)
-        if /I "${{matrix.VER}}"=="v142" (set VER=14.2)
-        if /I "${{matrix.VER}}"=="v143" (set VER=14.3)
-        %CMAKE_EXE% -E make_directory $GITHUB_WORKSPACE/install/share/cmake/OpenCL
-        echo -e 'include("/home/runner/work/OpenCL-ICD-Loader/OpenCL-ICD-Loader/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake")\ninclude("${CMAKE_CURRENT_LIST_DIR}/../OpenCLICDLoader/OpenCLICDLoaderTargets.cmake")' > $GITHUB_WORKSPACE/install/share/cmake/OpenCL/OpenCLConfig.cmake
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_MAKE_PROGRAM=%NINJA_EXE% -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH="%GITHUB_WORKSPACE%\external\OpenCL-Headers\install;%GITHUB_WORKSPACE%\install" -D DRIVER_STUB_PATH=%GITHUB_WORKSPACE%/build/Release/OpenCLDriverStub.dll -B %GITHUB_WORKSPACE%/build/downstream/bare -S %GITHUB_WORKSPACE%/test/pkgconfig/bare
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/test/pkgconfig/bare --config Release
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/test/pkgconfig/bare --config Debug
-        cd %GITHUB_WORKSPACE%/test/pkgconfig/bare
-        %CTEST_EXE% --output-on-failure -C Release
-        %CTEST_EXE% --output-on-failure -C Debug
diff --git a/.gitignore b/.gitignore
index 9bb7c13..8a9dc70 100644
--- a/.gitignore
+++ b/.gitignore
@@ -1,4 +1,22 @@
+# Build dir
+[Bb]uild/
+
+# Install dir
+[Ii]nstall/
+
+# External dir
+[Ee]xternal/
+
+# Package dir
+[Pp]ackage[-_\s\d]*/
+
+# Tackage dir
+[T]esting/
+
+# inc subdirs
 inc/CL/
 inc/EGL/
 inc/KHR/
-build/
+
+# Visual Studio Code
+.vscode
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 7cb3079..a1617d0 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required (VERSION 3.1)
+cmake_minimum_required (VERSION 3.16)
 
 # Include guard for including this project multiple times
 if(TARGET OpenCL)
@@ -6,7 +6,7 @@ if(TARGET OpenCL)
 endif()
 
 project (OpenCL-ICD-Loader
-    VERSION 1.2
+    VERSION 3.0
     LANGUAGES C)
 
 find_package (Threads REQUIRED)
@@ -46,7 +46,7 @@ if(DEFINED BUILD_SHARED_LIBS)
 else()
   set(OPENCL_ICD_LOADER_BUILD_SHARED_LIBS_DEFAULT ON)
 endif()
-  option(OPENCL_ICD_LOADER_BUILD_SHARED_LIBS "Build OpenCL ICD Loader as shared library" ${OPENCL_ICD_LOADER_BUILD_SHARED_LIBS_DEFAULT})
+option(OPENCL_ICD_LOADER_BUILD_SHARED_LIBS "Build OpenCL ICD Loader as shared library" ${OPENCL_ICD_LOADER_BUILD_SHARED_LIBS_DEFAULT})
 
 # This option enables/disables support for OpenCL layers in the ICD loader.
 # It is currently needed default while the specification is being formalized,
@@ -55,10 +55,13 @@ option (ENABLE_OPENCL_LAYERS "Enable OpenCL Layers" ON)
 include(CMakeDependentOption)
 cmake_dependent_option(ENABLE_OPENCL_LAYERINFO "Enable building cllayerinfo tool" ON ENABLE_OPENCL_LAYERS OFF)
 
+include(GNUInstallDirs)
+
 set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
+include(CheckFunctionExists)
 include(JoinPaths)
+include(Package)
 
-include(CheckFunctionExists)
 check_function_exists(secure_getenv HAVE_SECURE_GETENV)
 check_function_exists(__secure_getenv HAVE___SECURE_GETENV)
 configure_file(${CMAKE_CURRENT_SOURCE_DIR}/loader/icd_cmake_config.h.in
@@ -118,7 +121,7 @@ endif()
 
 add_library (OpenCL::OpenCL ALIAS OpenCL)
 
-set_target_properties (OpenCL PROPERTIES VERSION "1.2" SOVERSION "1")
+set_target_properties (OpenCL PROPERTIES VERSION 1\.0\.0 SOVERSION "1")
 
 if (WIN32)
     target_link_libraries (OpenCL PRIVATE cfgmgr32.lib runtimeobject.lib)
@@ -219,13 +222,11 @@ if((CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR OPENCL_ICD_LOADER_BUILD_TESTING)
     add_subdirectory (test)
 endif()
 
-include (GNUInstallDirs)
-
 install(
   TARGETS OpenCL
   EXPORT OpenCLICDLoaderTargets
   LIBRARY
-    DESTINATION ${CMAKE_INSTALL_LIBDIR} # obtained from GNUInstallDirs
+  DESTINATION ${CMAKE_INSTALL_LIBDIR} # obtained from GNUInstallDirs
 )
 install(
 # FILES $<TARGET_PDB_FILE:OpenCL> is cleanest, but is MSVC link.exe specific. LLVM's lld.exe and lld-link.exe don't support it (configure-time error)
@@ -238,9 +239,9 @@ install(
 if (ENABLE_OPENCL_LAYERINFO)
   install(
     TARGETS cllayerinfo
-    EXPORT OpenCLICDLoaderTargets
     RUNTIME
       DESTINATION ${CMAKE_INSTALL_BINDIR}
+    COMPONENT cllayerinfo
   )
 endif()
 
@@ -260,10 +261,12 @@ install(
   FILE OpenCLICDLoaderTargets.cmake
   NAMESPACE OpenCL::
   DESTINATION ${config_package_location}
+  COMPONENT dev
 )
 install(
   FILES ${CMAKE_CURRENT_BINARY_DIR}/OpenCLICDLoader/OpenCLICDLoaderConfig.cmake
   DESTINATION ${config_package_location}
+  COMPONENT dev
 )
 
 unset(CMAKE_SIZEOF_VOID_P)
@@ -276,20 +279,18 @@ write_basic_package_version_file(
 install(
   FILES ${CMAKE_CURRENT_BINARY_DIR}/OpenCLICDLoader/OpenCLICDLoaderConfigVersion.cmake
   DESTINATION ${config_package_location}
+  COMPONENT dev
 )
 
+# Separate namelink from shared library and symlink for DEB packaging
 install (TARGETS OpenCL
-    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
-    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
-    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
+    LIBRARY
+      DESTINATION ${CMAKE_INSTALL_LIBDIR}
+    COMPONENT runtime
+    NAMELINK_SKIP)
 
-join_paths(OPENCL_LIBDIR_PC "\${exec_prefix}" "${CMAKE_INSTALL_LIBDIR}")
-join_paths(OPENCL_INCLUDEDIR_PC "\${prefix}" "${CMAKE_INSTALL_INCLUDEDIR}")
-
-if (NOT MSVC)
-  configure_file(OpenCL.pc.in OpenCL.pc @ONLY)
-  set(pkg_config_location ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
-  install(
-    FILES ${CMAKE_CURRENT_BINARY_DIR}/OpenCL.pc
-    DESTINATION ${pkg_config_location})
-endif()
+install (TARGETS OpenCL
+    LIBRARY
+      DESTINATION ${CMAKE_INSTALL_LIBDIR}
+    COMPONENT dev
+    NAMELINK_ONLY)
diff --git a/METADATA b/METADATA
index 2e434ec..8b238f6 100644
--- a/METADATA
+++ b/METADATA
@@ -1,15 +1,21 @@
-name: "OpenCL-ICD-Loader"
-description:
-    "OpenCL Installable Client Driver Loader"
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/OpenCL-ICD-Loader
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "OpenCL-ICD-Loader"
+description: "OpenCL Installable Client Driver Loader"
 third_party {
-homepage: "https://github.com/KhronosGroup/OpenCL-ICD-Loader"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 1
+    day: 17
+  }
+  homepage: "https://github.com/KhronosGroup/OpenCL-ICD-Loader"
   identifier {
     type: "Archive"
     value: "https://github.com/KhronosGroup/OpenCL-ICD-Loader"
+    version: "v2024.10.24"
     primary_source: true
   }
-  version: "v2023.12.14"
-  last_upgrade_date { year: 2024 month: 2 day: 8 }
-  license_type: NOTICE
-}
\ No newline at end of file
+}
diff --git a/OWNERS b/OWNERS
index 584f012..bb229c6 100644
--- a/OWNERS
+++ b/OWNERS
@@ -5,3 +5,4 @@ jorwag@google.com
 jpakaravoor@google.com
 kevindubois@google.com
 include platform/system/core:main:/janitors/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/OpenCL.pc.in b/OpenCL.pc.in
index 1b6730c..ef35333 100644
--- a/OpenCL.pc.in
+++ b/OpenCL.pc.in
@@ -1,4 +1,4 @@
-prefix=@CMAKE_INSTALL_PREFIX@
+prefix=@PKGCONFIG_PREFIX@
 exec_prefix=${prefix}
 libdir=@OPENCL_LIBDIR_PC@
 
diff --git a/cmake/DebSourcePkg.cmake b/cmake/DebSourcePkg.cmake
new file mode 100644
index 0000000..eb10e6a
--- /dev/null
+++ b/cmake/DebSourcePkg.cmake
@@ -0,0 +1,160 @@
+# This script produces the changelog, control and rules file in the debian
+# directory. These files are needed to build a Debian source package from the repository.
+# Run this in CMake script mode, e.g.
+# $ cd OpenCL-ICD-Loader
+# $ cmake -S . -B ../build -D BUILD_TESTING=OFF
+# $ cmake
+#    -DCMAKE_CACHE_PATH=../build/CMakeCache.txt
+#    -DCPACK_DEBIAN_PACKAGE_MAINTAINER="Example Name <example@example.com>"
+#    -DDEBIAN_DISTROSERIES=jammy
+#    -DORIG_ARCHIVE=../OpenCL-ICD-Loader.tar.gz
+#    -DLATEST_RELEASE_VERSION=v2023.08.29
+#    -P cmake/DebSourcePkg.cmake
+# $ debuild -S -sa
+
+cmake_minimum_required(VERSION 3.21) # file(COPY_FILE) is added in CMake 3.21
+
+if(NOT EXISTS "${CMAKE_CACHE_PATH}")
+    message(FATAL_ERROR "CMAKE_CACHE_PATH is not set or does not exist")
+endif()
+if(NOT DEFINED DEBIAN_PACKAGE_MAINTAINER)
+    message(FATAL_ERROR "DEBIAN_PACKAGE_MAINTAINER is not set")
+endif()
+if(NOT DEFINED DEBIAN_DISTROSERIES)
+    message(FATAL_ERROR "DEBIAN_DISTROSERIES is not set")
+endif()
+if(NOT DEFINED ORIG_ARCHIVE)
+    message(WARNING "ORIG_ARCHIVE is not set")
+elseif(NOT EXISTS "${ORIG_ARCHIVE}")
+    message(FATAL_ERROR "ORIG_ARCHIVE is defined, but the file does not exist at \"${ORIG_ARCHIVE}\"")
+endif()
+if(NOT DEFINED LATEST_RELEASE_VERSION)
+    message(WARNING "LATEST_RELEASE_VERSION is not set")
+endif()
+if(NOT DEFINED DEBIAN_VERSION_SUFFIX)
+    message(WARNING "DEBIAN_VERSION_SUFFIX is not set")
+endif()
+
+# Extracting the project version from the main CMakeLists.txt via regex
+file(READ "${CMAKE_CACHE_PATH}" CMAKE_CACHE)
+string(REGEX MATCH "CMAKE_PROJECT_VERSION[^=]*=([^\n]*)" REGEX_MATCH "${CMAKE_CACHE}")
+if(NOT REGEX_MATCH)
+    message(FATAL_ERROR "Could not extract project version from CMakeLists.txt")
+endif()
+set(PROJECT_VERSION "${CMAKE_MATCH_1}")
+
+list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}")
+# Package.cmake contains all details for packaging
+include(PackageSetup)
+
+# Append a space after every newline in the description. This format is required
+# in the control file.
+string(REPLACE "\n" "\n " CPACK_DEBIAN_DEV_DESCRIPTION "${CPACK_DEBIAN_DEV_DESCRIPTION}")
+string(REPLACE "\n" "\n " CPACK_DEBIAN_RUNTIME_DESCRIPTION "${CPACK_DEBIAN_RUNTIME_DESCRIPTION}")
+string(REPLACE "\n" "\n " CPACK_DEBIAN_CLLAYERINFO_DESCRIPTION "${CPACK_DEBIAN_CLLAYERINFO_DESCRIPTION}")
+
+set(DEB_SOURCE_PKG_DIR "${CMAKE_CURRENT_LIST_DIR}/../debian")
+# Write debian/control
+file(WRITE "${DEB_SOURCE_PKG_DIR}/control"
+"Source: ${PACKAGE_NAME_PREFIX}
+Section: ${CPACK_DEBIAN_DEV_PACKAGE_SECTION}
+Priority: optional
+Maintainer: ${DEBIAN_PACKAGE_MAINTAINER}
+Build-Depends: cmake, debhelper-compat (=13), opencl-c-headers
+Rules-Requires-Root: no
+Homepage: ${CPACK_DEBIAN_PACKAGE_HOMEPAGE}
+Standards-Version: 4.6.2
+
+Package: ${CPACK_DEBIAN_DEV_PACKAGE_NAME}
+Architecture: any
+Multi-Arch: same
+Depends: ${CPACK_DEBIAN_DEV_PACKAGE_DEPENDS}, ${CPACK_DEBIAN_RUNTIME_PACKAGE_NAME} (=${PACKAGE_VERSION_REVISION})
+Recommends: ${CPACK_DEBIAN_DEV_PACKAGE_RECOMMENDS}
+Conflicts: ${CPACK_DEBIAN_DEV_PACKAGE_CONFLICTS}
+Breaks: ${CPACK_DEBIAN_DEV_PACKAGE_BREAKS}
+Replaces: ${CPACK_DEBIAN_DEV_PACKAGE_REPLACES}
+Provides: ${CPACK_DEBIAN_DEV_PACKAGE_PROVIDES}
+Description: ${CPACK_DEBIAN_DEV_DESCRIPTION}
+
+Package: ${CPACK_DEBIAN_RUNTIME_PACKAGE_NAME}
+Section: ${CPACK_DEBIAN_RUNTIME_PACKAGE_SECTION}
+Architecture: any
+Multi-Arch: same
+Depends: ${CPACK_DEBIAN_RUNTIME_PACKAGE_DEPENDS}
+# Conflicts and replaces deliberately not added
+# The runtime package provides libOpenCL.so.1.0.0 and libOpenCL.so.1 via update-alternatives
+# Conflicts: ${CPACK_DEBIAN_RUNTIME_PACKAGE_CONFLICTS}
+# Replaces: ${CPACK_DEBIAN_RUNTIME_PACKAGE_REPLACES}
+Provides: ${CPACK_DEBIAN_RUNTIME_PACKAGE_PROVIDES}
+Description: ${CPACK_DEBIAN_RUNTIME_DESCRIPTION}
+
+Package: ${CPACK_DEBIAN_CLLAYERINFO_PACKAGE_NAME}
+Section: ${CPACK_DEBIAN_CLLAYERINFO_PACKAGE_SECTION}
+Architecture: any
+Depends: ${CPACK_DEBIAN_CLLAYERINFO_PACKAGE_DEPENDS}, ${CPACK_DEBIAN_RUNTIME_PACKAGE_NAME} (=${PACKAGE_VERSION_REVISION})
+Conflicts: ${CPACK_DEBIAN_CLLAYERINFO_PACKAGE_CONFLICTS}
+Replaces: ${CPACK_DEBIAN_CLLAYERINFO_PACKAGE_REPLACES}
+Provides: ${CPACK_DEBIAN_CLLAYERINFO_PACKAGE_PROVIDES}
+Description: ${CPACK_DEBIAN_CLLAYERINFO_DESCRIPTION}
+"
+)
+# Write debian/changelog
+string(TIMESTAMP CURRENT_TIMESTAMP "%a, %d %b %Y %H:%M:%S +0000" UTC)
+file(WRITE "${DEB_SOURCE_PKG_DIR}/changelog"
+"${PACKAGE_NAME_PREFIX} (${PACKAGE_VERSION_REVISION}) ${DEBIAN_DISTROSERIES}; urgency=medium
+
+  * Released version ${PACKAGE_VERSION_REVISION}
+
+ -- ${DEBIAN_PACKAGE_MAINTAINER}  ${CURRENT_TIMESTAMP}
+")
+# Write debian/rules
+file(WRITE "${DEB_SOURCE_PKG_DIR}/rules"
+"#!/usr/bin/make -f
+%:
+\tdh $@
+
+override_dh_auto_configure:
+\tdh_auto_configure -- -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
+
+GENERATED_MAINTAINER_SCRIPTS := $(patsubst %.in,%,$(wildcard debian/*.alternatives.in))
+
+$(GENERATED_MAINTAINER_SCRIPTS): %: %.in
+\tsed \"s%@DEB_HOST_MULTIARCH@%$(DEB_HOST_MULTIARCH)%g\" < $< > $@
+
+execute_before_dh_install: $(GENERATED_MAINTAINER_SCRIPTS)
+\ttrue # An empty rule would confuse dh
+")
+file(WRITE "${DEB_SOURCE_PKG_DIR}/${CPACK_DEBIAN_DEV_PACKAGE_NAME}.install"
+"usr/lib/*/pkgconfig
+usr/lib/*/lib*.so
+usr/share
+")
+# The .so files are installed to a different directory, and then linked back
+# the the original location via update-alternatives.
+file(WRITE "${DEB_SOURCE_PKG_DIR}/${CPACK_DEBIAN_RUNTIME_PACKAGE_NAME}.install"
+"usr/lib/*/lib*.so.* usr/lib/\${DEB_HOST_MULTIARCH}/KhronosOpenCLICDLoader
+")
+file(WRITE "${DEB_SOURCE_PKG_DIR}/${CPACK_DEBIAN_RUNTIME_PACKAGE_NAME}.alternatives.in"
+"Name: libOpenCL.so.1.0.0-@DEB_HOST_MULTIARCH@
+Link: /usr/lib/@DEB_HOST_MULTIARCH@/libOpenCL.so.1.0.0
+Alternative: /usr/lib/@DEB_HOST_MULTIARCH@/KhronosOpenCLICDLoader/libOpenCL.so.1.0.0
+Dependents:
+  /usr/lib/@DEB_HOST_MULTIARCH@/libOpenCL.so.1 libOpenCL.so.1-@DEB_HOST_MULTIARCH@ /usr/lib/@DEB_HOST_MULTIARCH@/KhronosOpenCLICDLoader/libOpenCL.so.1
+Priority: 100
+")
+file(WRITE "${DEB_SOURCE_PKG_DIR}/${CPACK_DEBIAN_CLLAYERINFO_PACKAGE_NAME}.install"
+"usr/bin
+")
+
+if(DEFINED ORIG_ARCHIVE)
+    # Copy the passed orig.tar.gz file. The target filename is deduced from the version number, as expected by debuild
+    cmake_path(IS_ABSOLUTE ORIG_ARCHIVE IS_ORIG_ARCHIVE_ABSOLUTE)
+    if (NOT IS_ORIG_ARCHIVE_ABSOLUTE)
+        message(FATAL_ERROR "ORIG_ARCHIVE must be an absolute path (passed: \"${ORIG_ARCHIVE}\")")
+    endif()
+    cmake_path(GET ORIG_ARCHIVE EXTENSION ORIG_ARCHIVE_EXT)
+    cmake_path(GET ORIG_ARCHIVE PARENT_PATH ORIG_ARCHIVE_PARENT)
+    set(TARGET_PATH "${ORIG_ARCHIVE_PARENT}/${PACKAGE_NAME_PREFIX}_${CPACK_DEBIAN_PACKAGE_VERSION}${ORIG_ARCHIVE_EXT}")
+    message(STATUS "Copying \"${ORIG_ARCHIVE}\" to \"${TARGET_PATH}\"")
+    file(COPY_FILE "${ORIG_ARCHIVE}" "${TARGET_PATH}")
+endif()
diff --git a/cmake/Package.cmake b/cmake/Package.cmake
new file mode 100644
index 0000000..adfa505
--- /dev/null
+++ b/cmake/Package.cmake
@@ -0,0 +1,40 @@
+include("${CMAKE_CURRENT_LIST_DIR}/PackageSetup.cmake")
+
+# Configuring pkgconfig
+
+# We need two different instances of OpenCL.pc
+# One for installing (cmake --install), which contains CMAKE_INSTALL_PREFIX as prefix
+# And another for the Debian development package, which contains CPACK_PACKAGING_INSTALL_PREFIX as prefix
+
+join_paths(OPENCL_INCLUDEDIR_PC "\${prefix}" "${CMAKE_INSTALL_INCLUDEDIR}")
+join_paths(OPENCL_LIBDIR_PC "\${exec_prefix}" "${CMAKE_INSTALL_LIBDIR}")
+
+set(pkg_config_location ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
+set(PKGCONFIG_PREFIX "${CMAKE_INSTALL_PREFIX}")
+
+# Configure and install OpenCL.pc for installing the project
+configure_file(
+  OpenCL.pc.in
+  ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_install/OpenCL.pc
+  @ONLY)
+install(
+  FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_install/OpenCL.pc
+  DESTINATION ${pkg_config_location}
+  COMPONENT pkgconfig_install)
+
+# Configure and install OpenCL.pc for the Debian package
+set(PKGCONFIG_PREFIX "${CPACK_PACKAGING_INSTALL_PREFIX}")
+configure_file(
+  OpenCL.pc.in
+  ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_package/OpenCL.pc
+  @ONLY)
+
+install(
+  FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_package/OpenCL.pc
+  DESTINATION ${pkg_config_location}
+  COMPONENT dev
+  EXCLUDE_FROM_ALL)
+
+set(CPACK_DEBIAN_PACKAGE_DEBUG ON)
+
+include(CPack)
diff --git a/cmake/PackageSetup.cmake b/cmake/PackageSetup.cmake
new file mode 100644
index 0000000..b4aade8
--- /dev/null
+++ b/cmake/PackageSetup.cmake
@@ -0,0 +1,112 @@
+set(CPACK_PACKAGE_VENDOR "khronos")
+
+set(CPACK_DEBIAN_RUNTIME_DESCRIPTION "Generic OpenCL ICD Loader
+OpenCL (Open Computing Language) is a multivendor open standard for
+general-purpose parallel programming of heterogeneous systems that include
+CPUs, GPUs and other processors.
+.
+This package contains an installable client driver loader (ICD Loader)
+library that can be used to load any (free or non-free) installable client
+driver (ICD) for OpenCL. It acts as a demultiplexer so several ICD can
+be installed and used together.")
+
+set(CPACK_DEBIAN_DEV_DESCRIPTION "OpenCL development files
+OpenCL (Open Computing Language) is a multivendor open standard for
+general-purpose parallel programming of heterogeneous systems that include
+CPUs, GPUs and other processors.
+.
+This package provides the development files: headers and libraries.
+.
+It also ensures that the ocl-icd ICD loader is installed so its additional
+features (compared to the OpenCL norm) can be used: .pc file, ability to
+select an ICD without root privilege, etc.")
+
+set(CPACK_DEBIAN_CLLAYERINFO_DESCRIPTION "Query OpenCL Layer system information
+OpenCL (Open Computing Language) is a multivendor open standard for
+general-purpose parallel programming of heterogeneous systems that include
+CPUs, GPUs and other processors. It supports system and user configured layers
+to intercept OpenCL API calls.
+.
+This package contains a tool that lists the layers loaded by the the ocl-icd
+OpenCL ICD Loader.")
+
+set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
+
+set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
+
+if(NOT CPACK_PACKAGING_INSTALL_PREFIX)
+  set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
+endif()
+
+# DEB packaging configuration
+set(CPACK_DEBIAN_PACKAGE_MAINTAINER ${CPACK_PACKAGE_VENDOR})
+
+set(CPACK_DEBIAN_PACKAGE_HOMEPAGE
+    "https://github.com/KhronosGroup/OpenCL-ICD-Loader")
+
+# Version number [epoch:]upstream_version[-debian_revision]
+set(CPACK_DEBIAN_PACKAGE_VERSION "${PROJECT_VERSION}") # upstream_version
+if(DEFINED LATEST_RELEASE_VERSION)
+  # Remove leading "v", if exists
+  string(LENGTH "${LATEST_RELEASE_VERSION}" LATEST_RELEASE_VERSION_LENGTH)
+  string(SUBSTRING "${LATEST_RELEASE_VERSION}" 0 1 LATEST_RELEASE_VERSION_FRONT)
+  if(LATEST_RELEASE_VERSION_FRONT STREQUAL "v")
+    string(SUBSTRING "${LATEST_RELEASE_VERSION}" 1 ${LATEST_RELEASE_VERSION_LENGTH} LATEST_RELEASE_VERSION)
+  endif()
+
+  string(APPEND CPACK_DEBIAN_PACKAGE_VERSION "~${LATEST_RELEASE_VERSION}")
+endif()
+set(CPACK_DEBIAN_PACKAGE_RELEASE "1") # debian_revision (because this is a
+                                      # non-native pkg)
+set(PACKAGE_VERSION_REVISION "${CPACK_DEBIAN_PACKAGE_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}${DEBIAN_VERSION_SUFFIX}")
+
+# Get architecture
+execute_process(COMMAND dpkg "--print-architecture" OUTPUT_VARIABLE CPACK_DEBIAN_PACKAGE_ARCHITECTURE)
+string(STRIP "${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}" CPACK_DEBIAN_PACKAGE_ARCHITECTURE)
+
+##########################################################
+#                       Components                       #
+##########################################################
+
+set(CPACK_DEB_COMPONENT_INSTALL ON)
+set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS OFF) # Component dependencies are NOT reflected in package relationships
+set(CPACK_COMPONENTS_ALL runtime dev cllayerinfo)
+
+set(PACKAGE_NAME_PREFIX "khronos-opencl-loader")
+
+## Package runtime component
+set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "${PACKAGE_NAME_PREFIX}-libopencl1")
+
+# Package file name in deb format:
+# <PackageName>_<VersionNumber>-<DebianRevisionNumber>_<DebianArchitecture>.deb
+set(CPACK_DEBIAN_RUNTIME_FILE_NAME "${CPACK_DEBIAN_RUNTIME_PACKAGE_NAME}_${PACKAGE_VERSION_REVISION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}.deb")
+set(CPACK_DEBIAN_RUNTIME_PACKAGE_SECTION "libs")
+# Dependencies
+set(CPACK_DEBIAN_RUNTIME_PACKAGE_DEPENDS "libc6")
+set(CPACK_DEBIAN_RUNTIME_PACKAGE_SUGGESTS "opencl-icd")
+set(CPACK_DEBIAN_RUNTIME_PACKAGE_CONFLICTS "amd-app, libopencl1, nvidia-libopencl1-dev")
+set(CPACK_DEBIAN_RUNTIME_PACKAGE_REPLACES "amd-app, libopencl1, nvidia-libopencl1-dev")
+set(CPACK_DEBIAN_RUNTIME_PACKAGE_PROVIDES "libopencl-1.1-1, libopencl-1.2-1, libopencl-2.0-1, libopencl-2.1-1, libopencl-2.2-1, libopencl-3.0-1, libopencl1")
+
+## Package dev component
+set(CPACK_DEBIAN_DEV_PACKAGE_NAME "${PACKAGE_NAME_PREFIX}-opencl-dev")
+
+# Package file name in deb format:
+# <PackageName>_<VersionNumber>-<DebianRevisionNumber>_<DebianArchitecture>.deb
+set(CPACK_DEBIAN_DEV_FILE_NAME "${CPACK_DEBIAN_DEV_PACKAGE_NAME}_${PACKAGE_VERSION_REVISION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}.deb")
+set(CPACK_DEBIAN_DEV_PACKAGE_SECTION "libdevel")
+
+# Dependencies
+set(CPACK_DEBIAN_DEV_PACKAGE_DEPENDS "opencl-c-headers (>= ${CPACK_DEBIAN_PACKAGE_VERSION}) | opencl-headers (>= ${CPACK_DEBIAN_PACKAGE_VERSION}), ${CPACK_DEBIAN_RUNTIME_PACKAGE_NAME} (>= ${CPACK_DEBIAN_PACKAGE_VERSION}) | libopencl1")
+set(CPACK_DEBIAN_DEV_PACKAGE_RECOMMENDS "libgl1-mesa-dev | libgl-dev")
+set(CPACK_DEBIAN_DEV_PACKAGE_CONFLICTS "opencl-dev")
+set(CPACK_DEBIAN_DEV_PACKAGE_BREAKS "amd-libopencl1, nvidia-libopencl1")
+set(CPACK_DEBIAN_DEV_PACKAGE_REPLACES "amd-libopencl1, nvidia-libopencl1, opencl-dev")
+set(CPACK_DEBIAN_DEV_PACKAGE_PROVIDES "opencl-dev")
+
+## Package cllayerinfo component
+set(CPACK_DEBIAN_CLLAYERINFO_PACKAGE_NAME "${PACKAGE_NAME_PREFIX}-cllayerinfo")
+set(CPACK_DEBIAN_CLLAYERINFO_FILE_NAME "${CPACK_DEBIAN_CLLAYERINFO_PACKAGE_NAME}_${PACKAGE_VERSION_REVISION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}.deb")
+# Dependencies
+set(CPACK_DEBIAN_CLLAYERINFO_PACKAGE_DEPENDS "libc6")
+set(CPACK_DEBIAN_CLLAYERINFO_PACKAGE_SECTION "admin")
diff --git a/loader/icd.c b/loader/icd.c
index bbd6ec3..b92a9b4 100644
--- a/loader/icd.c
+++ b/loader/icd.c
@@ -326,11 +326,11 @@ void khrIcdLayerAdd(const char *libraryName)
 
     for (cl_uint i = 0; i < limit; i++) {
         ((void **)&(layer->dispatch))[i] =
-            ((void **)layerDispatch)[i] ?
-                ((void **)layerDispatch)[i] : ((void **)targetDispatch)[i];
+            ((void *const*)layerDispatch)[i] ?
+                ((void *const*)layerDispatch)[i] : ((void *const*)targetDispatch)[i];
     }
     for (cl_uint i = limit; i < loaderDispatchNumEntries; i++) {
-        ((void **)&(layer->dispatch))[i] = ((void **)targetDispatch)[i];
+        ((void **)&(layer->dispatch))[i] = ((void *const*)targetDispatch)[i];
     }
 
     KHR_ICD_TRACE("successfully added layer %s\n", libraryName);
diff --git a/loader/icd_dispatch.c b/loader/icd_dispatch.c
index 3eb18d2..51ec52d 100644
--- a/loader/icd_dispatch.c
+++ b/loader/icd_dispatch.c
@@ -36,12 +36,12 @@ clGetICDLoaderInfoOCLICD(
     static const char cl_icdl_NAME[]        = OPENCL_ICD_LOADER_NAME_STRING;
     static const char cl_icdl_VENDOR[]      = OPENCL_ICD_LOADER_VENDOR_STRING;
     size_t            pvs;
-    void *            pv;
+    const void *      pv = NULL;
 
 #define KHR_ICD_CASE_STRING_PARAM_NAME(name)                                   \
     case CL_ICDL_ ## name:                                                     \
         pvs = strlen(cl_icdl_ ## name) + 1;                                    \
-        pv = (void *)cl_icdl_ ## name;                                         \
+        pv = (const void *)cl_icdl_ ## name;                                   \
         break
 
     switch (param_name) {
diff --git a/loader/linux/icd_linux.c b/loader/linux/icd_linux.c
index 44915fe..265215e 100644
--- a/loader/linux/icd_linux.c
+++ b/loader/linux/icd_linux.c
@@ -129,7 +129,7 @@ struct dirElem
 static int compareDirElem(const void *a, const void *b)
 {
     // sort files the same way libc alpahnumerically sorts directory entries.
-    return strcoll(((struct dirElem *)a)->d_name, ((struct dirElem *)b)->d_name);
+    return strcoll(((const struct dirElem *)a)->d_name, ((const struct dirElem *)b)->d_name);
 }
 
 static inline void khrIcdOsDirEnumerate(const char *path, const char *env,
diff --git a/loader/windows/icd_windows.c b/loader/windows/icd_windows.c
index 237ec5c..44a8a98 100644
--- a/loader/windows/icd_windows.c
+++ b/loader/windows/icd_windows.c
@@ -109,7 +109,7 @@ static WinLayer* pWinLayerBegin;
 static WinLayer* pWinLayerEnd;
 static WinLayer* pWinLayerCapacity;
 
-static int compareLayer(const void *a, const void *b)
+static int __cdecl compareLayer(const void *a, const void *b)
 {
     return ((WinLayer *)a)->priority < ((WinLayer *)b)->priority ? -1 :
            ((WinLayer *)a)->priority > ((WinLayer *)b)->priority ? 1 : 0;
@@ -185,6 +185,10 @@ void layerFree(WinLayer *pWinLayer)
 // for each vendor encountered
 BOOL CALLBACK khrIcdOsVendorsEnumerate(PINIT_ONCE InitOnce, PVOID Parameter, PVOID *lpContext)
 {
+    (void)InitOnce;
+    (void)Parameter;
+    (void)lpContext;
+
     LONG result;
     BOOL status = FALSE, currentStatus = FALSE;
     const char* platformsName = "SOFTWARE\\Khronos\\OpenCL\\Vendors";
diff --git a/test/driver_stub/cl.c b/test/driver_stub/cl.c
index 9b78e58..ba37a85 100644
--- a/test/driver_stub/cl.c
+++ b/test/driver_stub/cl.c
@@ -93,11 +93,9 @@ clGetPlatformIDs(cl_uint           num_entries ,
 }
 
 CL_API_ENTRY cl_int CL_API_CALL
-clGetPlatformInfo(cl_platform_id    platform,
-                  cl_platform_info  param_name,
-                  size_t            param_value_size,
-                  void *            param_value,
-                  size_t *          param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
+clGetPlatformInfo(cl_platform_id platform_id, cl_platform_info param_name,
+                  size_t param_value_size, void *param_value,
+                  size_t *param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
 {
     cl_int ret = CL_SUCCESS;
     const char *returnString = NULL;
@@ -116,23 +114,15 @@ clGetPlatformInfo(cl_platform_id    platform,
     }
     // select the string to return
     switch(param_name) {
-        case CL_PLATFORM_PROFILE:
-            returnString = platform->profile;
-            break;
-        case CL_PLATFORM_VERSION:
-            returnString = platform->version;
-            break;
-        case CL_PLATFORM_NAME:
-            returnString = platform->name;
-            break;
-        case CL_PLATFORM_VENDOR:
-            returnString = platform->vendor;
-            break;
+        case CL_PLATFORM_PROFILE: returnString = platform_id->profile; break;
+        case CL_PLATFORM_VERSION: returnString = platform_id->version; break;
+        case CL_PLATFORM_NAME: returnString = platform_id->name; break;
+        case CL_PLATFORM_VENDOR: returnString = platform_id->vendor; break;
         case CL_PLATFORM_EXTENSIONS:
-            returnString = platform->extensions;
+            returnString = platform_id->extensions;
             break;
         case CL_PLATFORM_ICD_SUFFIX_KHR:
-            returnString = platform->suffix;
+            returnString = platform_id->suffix;
             break;
         default:
             ret = CL_INVALID_VALUE;
@@ -162,12 +152,9 @@ done:
 
 
 /* Device APIs */
-CL_API_ENTRY cl_int CL_API_CALL
-clGetDeviceIDs(cl_platform_id   platform,
-               cl_device_type   device_type,
-               cl_uint          num_entries,
-               cl_device_id *   devices,
-               cl_uint *        num_devices) CL_API_SUFFIX__VERSION_1_0
+CL_API_ENTRY cl_int CL_API_CALL clGetDeviceIDs(
+    cl_platform_id platform_id, cl_device_type device_type, cl_uint num_entries,
+    cl_device_id *devices, cl_uint *num_devices) CL_API_SUFFIX__VERSION_1_0
 {
     cl_int ret = CL_SUCCESS;
 
@@ -186,12 +173,8 @@ clGetDeviceIDs(cl_platform_id   platform,
     }
 
 done:
-    test_icd_stub_log("clGetDeviceIDs(%p, %x, %u, %p, %p)\n",
-                      platform,
-                      device_type,
-                      num_entries,
-                      devices,
-                      num_devices);
+    test_icd_stub_log("clGetDeviceIDs(%p, %x, %u, %p, %p)\n", platform_id,
+                      device_type, num_entries, devices, num_devices);
     test_icd_stub_log("Value returned: %d\n", ret);
     return ret;
 }
@@ -950,10 +933,10 @@ clLinkProgram(cl_context            context ,
 
 
 CL_API_ENTRY cl_int CL_API_CALL
-clUnloadPlatformCompiler(cl_platform_id  platform) CL_API_SUFFIX__VERSION_1_2
+clUnloadPlatformCompiler(cl_platform_id platform_id) CL_API_SUFFIX__VERSION_1_2
 {
     cl_int return_value = CL_OUT_OF_RESOURCES;
-    test_icd_stub_log("clUnloadPlatformCompiler(%p)\n", platform);
+    test_icd_stub_log("clUnloadPlatformCompiler(%p)\n", platform_id);
     test_icd_stub_log("Value returned: %d\n", return_value);
     return return_value;
 }
@@ -1835,14 +1818,15 @@ clEnqueueNativeKernel(cl_command_queue   command_queue ,
     return return_value;
 }
 
-CL_API_ENTRY void * CL_API_CALL
-clGetExtensionFunctionAddressForPlatform(cl_platform_id  platform ,
-                                         const char *    func_name) CL_API_SUFFIX__VERSION_1_2
+static void extFunc(void) { }
+
+CL_API_ENTRY void *CL_API_CALL clGetExtensionFunctionAddressForPlatform(
+    cl_platform_id platform_id,
+    const char *func_name) CL_API_SUFFIX__VERSION_1_2
 {
-    void *return_value = (void *) malloc(sizeof(void *));
+    void *return_value = (void *)(size_t)&extFunc;
     test_icd_stub_log("clGetExtensionFunctionAddressForPlatform(%p, %p)\n",
-                      platform,
-                      func_name);
+                      platform_id, func_name);
 
     test_icd_stub_log("Value returned: %p\n", return_value);
     return return_value;
diff --git a/test/loader_test/icd_test_match.c b/test/loader_test/icd_test_match.c
index b70e741..cf79181 100644
--- a/test/loader_test/icd_test_match.c
+++ b/test/loader_test/icd_test_match.c
@@ -6,7 +6,7 @@
 #endif
 #include <platform/icd_test_log.h>
 
-int test_icd_match()
+int test_icd_match(void)
 {
     int error = 0;
     char *app_log = NULL, *stub_log = NULL;
diff --git a/test/loader_test/main.c b/test/loader_test/main.c
index b8b7304..e10bee5 100644
--- a/test/loader_test/main.c
+++ b/test/loader_test/main.c
@@ -3,18 +3,17 @@
 #include<platform/icd_test_log.h>
 #include "param_struct.h"
 
-extern int test_create_calls();
-extern int test_platforms();
-extern int test_cl_runtime();
-extern int test_kernel();
-extern int test_buffer_object();
-extern int test_program_objects();
-extern int test_image_objects();
-extern int test_sampler_objects();
-extern int test_OpenGL_share();
-extern int test_release_calls();
-
-extern int test_icd_match();
+extern int test_create_calls(void);
+extern int test_platforms(void);
+extern int test_cl_runtime(void);
+extern int test_kernel(void);
+extern int test_buffer_object(void);
+extern int test_program_objects(void);
+extern int test_image_objects(void);
+extern int test_sampler_objects(void);
+extern int test_OpenGL_share(void);
+extern int test_release_calls(void);
+extern int test_icd_match(void);
 
 int main(int argc, char **argv)
 {
diff --git a/test/loader_test/test_buffer_object.c b/test/loader_test/test_buffer_object.c
index 38d5b90..d133875 100644
--- a/test/loader_test/test_buffer_object.c
+++ b/test/loader_test/test_buffer_object.c
@@ -408,7 +408,7 @@ int test_clGetMemObjectInfo (const struct clGetMemObjectInfo_st *data)
     return 0;
 }
 
-int test_buffer_object()
+int test_buffer_object(void)
 {
     int i;
     for (i=0; i<NUM_ITEMS_clEnqueueReadBuffer; i++) {
diff --git a/test/loader_test/test_cl_runtime.c b/test/loader_test/test_cl_runtime.c
index 380627d..c957bac 100644
--- a/test/loader_test/test_cl_runtime.c
+++ b/test/loader_test/test_cl_runtime.c
@@ -50,7 +50,7 @@ int test_clGetCommandQueueInfo(const struct clGetCommandQueueInfo_st *data)
 
 }
 
-int test_cl_runtime()
+int test_cl_runtime(void)
 {
 	int i;
 
diff --git a/test/loader_test/test_clgl.c b/test/loader_test/test_clgl.c
index 27fa96e..76213f9 100644
--- a/test/loader_test/test_clgl.c
+++ b/test/loader_test/test_clgl.c
@@ -324,7 +324,7 @@ int test_clGetGLContextInfoKHR(const struct clGetGLContextInfoKHR_st* data)
 
 }
 
-int test_OpenGL_share()
+int test_OpenGL_share(void)
 {
 	int i;
 
diff --git a/test/loader_test/test_create_calls.c b/test/loader_test/test_create_calls.c
index 510035f..8dbf3ca 100644
--- a/test/loader_test/test_create_calls.c
+++ b/test/loader_test/test_create_calls.c
@@ -11,7 +11,6 @@
 
 extern void CL_CALLBACK createcontext_callback(const char* a, const void* b, size_t c, void* d);
 
-cl_platform_id*  all_platforms;
 cl_platform_id platform;
 cl_uint num_platforms;
 cl_context context;
@@ -96,10 +95,17 @@ struct clReleaseMemObject_st clReleaseMemObjectData[NUM_ITEMS_clReleaseMemObject
     {NULL}
 };
 
+struct clReleaseMemObject_st clReleaseMemObjectDataSubBuffer[NUM_ITEMS_clReleaseMemObject] =
+{
+    {NULL}
+};
+
 struct clReleaseMemObject_st clReleaseMemObjectDataImage[NUM_ITEMS_clReleaseMemObject] =
 {
     {NULL}
-};const struct clCreateProgramWithSource_st clCreateProgramWithSourceData[NUM_ITEMS_clCreateProgramWithSource] =
+};
+
+const struct clCreateProgramWithSource_st clCreateProgramWithSourceData[NUM_ITEMS_clCreateProgramWithSource] =
 {
     {NULL, 0, NULL, NULL, NULL}
 };
@@ -151,6 +157,7 @@ int test_clGetPlatformIDs(const struct clGetPlatformIDs_st* data)
     #define PLATFORM_NAME_SIZE 80
     char platform_name[PLATFORM_NAME_SIZE];
     cl_uint i;    
+    cl_platform_id *all_platforms;
 
 #if ENABLE_MISMATCHING_PRINTS
     test_icd_app_log("clGetPlatformIDs(%u, %p, %p)\n",
@@ -192,6 +199,7 @@ int test_clGetPlatformIDs(const struct clGetPlatformIDs_st* data)
             }
         }
     }
+    free(all_platforms);
 
 #if ENABLE_MISMATCHING_PRINTS
     test_icd_app_log("Value returned: %d\n", ret_val);
@@ -351,7 +359,7 @@ int test_clCreateSubBuffer(const struct clCreateSubBuffer_st *data)
                                 data->buffer_create_info,
                                 data->errcode_ret);
 
-    clReleaseMemObjectData->memobj = buffer;
+    clReleaseMemObjectDataSubBuffer->memobj = subBuffer;
 
     test_icd_app_log("Value returned: %p\n", subBuffer);
 
@@ -762,7 +770,7 @@ int test_clReleaseDevice(const struct clReleaseDevice_st* data)
 
 }
 
-int test_create_calls()
+int test_create_calls(void)
 {
     test_clGetPlatformIDs(clGetPlatformIDsData);
 
@@ -780,12 +788,16 @@ int test_create_calls()
 
     test_clCreateBuffer(clCreateBufferData);
 
+    test_clReleaseMemObject(clReleaseMemObjectData);
+
     test_clCreateBufferWithProperties(clCreateBufferWithPropertiesData);
 
     test_clCreateSubBuffer(clCreateSubBufferData);
 
     test_clCreateImage(clCreateImageData);
 
+    test_clReleaseMemObject(clReleaseMemObjectDataImage);
+
     test_clCreateImageWithProperties(clCreateImageWithPropertiesData);
 
     test_clReleaseMemObject(clReleaseMemObjectDataImage);
@@ -818,12 +830,14 @@ int test_create_calls()
 
 }
 
-int test_release_calls()
+int test_release_calls(void)
 {
     test_clReleaseSampler(clReleaseSamplerData);
 
     test_clReleaseMemObject(clReleaseMemObjectData);
 
+    test_clReleaseMemObject(clReleaseMemObjectDataSubBuffer);
+
     test_clReleaseMemObject(clReleaseMemObjectDataImage);
 
     test_clReleaseEvent(clReleaseEventData);
diff --git a/test/loader_test/test_image_objects.c b/test/loader_test/test_image_objects.c
index c6b99e7..f214a30 100644
--- a/test/loader_test/test_image_objects.c
+++ b/test/loader_test/test_image_objects.c
@@ -333,7 +333,7 @@ int test_clGetImageInfo(const struct clGetImageInfo_st *data)
 
 }
 
-int test_image_objects()
+int test_image_objects(void)
 {
     int i;
 
diff --git a/test/loader_test/test_kernel.c b/test/loader_test/test_kernel.c
index 2382eab..e76c77f 100644
--- a/test/loader_test/test_kernel.c
+++ b/test/loader_test/test_kernel.c
@@ -514,7 +514,7 @@ int test_clFinish(const struct clFinish_st* data)
     return 0;
 }
 
-int test_kernel()
+int test_kernel(void)
 {
     int i;
 
diff --git a/test/loader_test/test_platforms.c b/test/loader_test/test_platforms.c
index 5700738..ca83628 100644
--- a/test/loader_test/test_platforms.c
+++ b/test/loader_test/test_platforms.c
@@ -189,7 +189,7 @@ int test_clRetainDevice(const struct clRetainDevice_st* data)
     return 0;
 }
 
-int test_platforms()
+int test_platforms(void)
 {
     int i;
 
diff --git a/test/loader_test/test_program_objects.c b/test/loader_test/test_program_objects.c
index 8e64372..ec59da1 100644
--- a/test/loader_test/test_program_objects.c
+++ b/test/loader_test/test_program_objects.c
@@ -123,7 +123,8 @@ int test_clCompileProgram(const struct clCompileProgram_st *data)
 
 int test_clLinkProgram(const struct clLinkProgram_st *data)
 {
-    cl_program program;
+    cl_program linked_program;
+    cl_int ret_val;
     test_icd_app_log("clLinkProgram(%p, %u, %p, %p, %u, %p, %p, %p, %p)\n",
                      context,
                      data->num_devices,
@@ -135,7 +136,7 @@ int test_clLinkProgram(const struct clLinkProgram_st *data)
                      data->user_data,
                      data->errcode_ret);
 
-    program=clLinkProgram(context,
+    linked_program=clLinkProgram(context,
                         data->num_devices,
                         data->device_list,
                         data->options,
@@ -145,7 +146,11 @@ int test_clLinkProgram(const struct clLinkProgram_st *data)
                         data->user_data,
                         data->errcode_ret);
 
-    test_icd_app_log("Value returned: %p\n", program);
+    test_icd_app_log("Value returned: %p\n", linked_program);
+
+    test_icd_app_log("clReleaseProgram(%p)\n", linked_program);
+    ret_val = clReleaseProgram(linked_program);
+    test_icd_app_log("Value returned: %d\n", ret_val);
 
     return 0;
 
@@ -230,7 +235,7 @@ int test_clGetProgramBuildInfo(const struct clGetProgramBuildInfo_st *data)
 
 }
 
-int test_program_objects()
+int test_program_objects(void)
 {
     int i;
 
diff --git a/test/loader_test/test_sampler_objects.c b/test/loader_test/test_sampler_objects.c
index afc11be..a7fbcb7 100644
--- a/test/loader_test/test_sampler_objects.c
+++ b/test/loader_test/test_sampler_objects.c
@@ -51,7 +51,7 @@ int test_clGetSamplerInfo(const struct clGetSamplerInfo_st *data)
     return 0;
 }
 
-int test_sampler_objects()
+int test_sampler_objects(void)
 {
     int i;
 
diff --git a/test/pkgconfig/bare/CMakeLists.txt b/test/pkgconfig/bare/CMakeLists.txt
index 5e4c099..f58f21e 100644
--- a/test/pkgconfig/bare/CMakeLists.txt
+++ b/test/pkgconfig/bare/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required(VERSION 3.0)
+cmake_minimum_required(VERSION 3.16)
 
 project(PkgConfigTest
   LANGUAGES C
@@ -35,7 +35,12 @@ add_test(
   COMMAND ${PROJECT_NAME}
 )
 
-set_tests_properties(${PROJECT_NAME}
-  PROPERTIES
-    ENVIRONMENT "OCL_ICD_FILENAMES=${DRIVER_STUB_PATH}"
-)
+if(DEFINED DRIVER_STUB_PATH)
+  file(TO_CMAKE_PATH "${DRIVER_STUB_PATH}" DRIVER_STUB_PATH_CMAKE)
+  string(REGEX MATCH ".*/" DRIVER_STUB_DIR "${DRIVER_STUB_PATH_CMAKE}")
+  set_tests_properties(${PROJECT_NAME}
+    PROPERTIES
+      ENVIRONMENT "OCL_ICD_FILENAMES=${DRIVER_STUB_PATH}"
+      WORKING_DIRECTORY "${DRIVER_STUB_DIR}"
+  )
+endif()
diff --git a/test/pkgconfig/pkgconfig.c b/test/pkgconfig/pkgconfig.c
index 7228099..aadd25f 100644
--- a/test/pkgconfig/pkgconfig.c
+++ b/test/pkgconfig/pkgconfig.c
@@ -7,6 +7,7 @@
 #include <stdio.h>  // printf
 #include <stdlib.h> // malloc
 #include <stdint.h> // UINTMAX_MAX
+#include <string.h> // strcmp
 
 void checkErr(cl_int err, const char * name)
 {
@@ -17,10 +18,11 @@ void checkErr(cl_int err, const char * name)
     }
 }
 
-int main()
+int main(void)
 {
     cl_int CL_err = CL_SUCCESS;
     cl_uint numPlatforms = 0;
+    cl_int stub_platform_found = CL_FALSE;
 
     CL_err = clGetPlatformIDs(0, NULL, &numPlatforms);
     checkErr(CL_err, "clGetPlatformIDs(numPlatforms)");
@@ -48,9 +50,21 @@ int main()
         checkErr(CL_err, "clGetPlatformInfo(CL_PLATFORM_VENDOR, vendor_length, platform_name)");
 
         printf("%s\n", platform_name);
+
+        if (strcmp(platform_name, "stubvendorxxx") == 0)
+        {
+            stub_platform_found = CL_TRUE;
+        }
+
         fflush(NULL);
         free(platform_name);
     }
 
+    if (!stub_platform_found)
+    {
+        printf("Did not locate stub platform\n");
+        return -1;
+    }
+
     return 0;
 }
diff --git a/test/pkgconfig/pkgconfig/CMakeLists.txt b/test/pkgconfig/pkgconfig/CMakeLists.txt
index cffce75..436fffd 100644
--- a/test/pkgconfig/pkgconfig/CMakeLists.txt
+++ b/test/pkgconfig/pkgconfig/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required(VERSION 3.1)
+cmake_minimum_required(VERSION 3.16)
 find_package(PkgConfig REQUIRED)
 
 project(PkgConfigTest
@@ -49,7 +49,12 @@ add_test(
   COMMAND ${PROJECT_NAME}
 )
 
-set_tests_properties(${PROJECT_NAME}
-  PROPERTIES
-    ENVIRONMENT "OCL_ICD_FILENAMES=${DRIVER_STUB_PATH}"
-)
+if(DEFINED DRIVER_STUB_PATH)
+  file(TO_CMAKE_PATH "${DRIVER_STUB_PATH}" DRIVER_STUB_PATH_CMAKE)
+  string(REGEX MATCH ".*/" DRIVER_STUB_DIR "${DRIVER_STUB_PATH_CMAKE}")
+  set_tests_properties(${PROJECT_NAME}
+    PROPERTIES
+      ENVIRONMENT "OCL_ICD_FILENAMES=${DRIVER_STUB_PATH}"
+      WORKING_DIRECTORY "${DRIVER_STUB_DIR}"
+  )
+endif()
diff --git a/test/pkgconfig/sdk/CMakeLists.txt b/test/pkgconfig/sdk/CMakeLists.txt
index fced859..83a52b7 100644
--- a/test/pkgconfig/sdk/CMakeLists.txt
+++ b/test/pkgconfig/sdk/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required(VERSION 3.0)
+cmake_minimum_required(VERSION 3.16)
 
 project(PkgConfigTest
   LANGUAGES C
@@ -34,7 +34,12 @@ add_test(
   COMMAND ${PROJECT_NAME}
 )
 
-set_tests_properties(${PROJECT_NAME}
-  PROPERTIES
-    ENVIRONMENT "OCL_ICD_FILENAMES=${DRIVER_STUB_PATH}"
-)
+if(DEFINED DRIVER_STUB_PATH)
+  file(TO_CMAKE_PATH "${DRIVER_STUB_PATH}" DRIVER_STUB_PATH_CMAKE)
+  string(REGEX MATCH ".*/" DRIVER_STUB_DIR "${DRIVER_STUB_PATH_CMAKE}")
+  set_tests_properties(${PROJECT_NAME}
+    PROPERTIES
+      ENVIRONMENT "OCL_ICD_FILENAMES=${DRIVER_STUB_PATH}"
+      WORKING_DIRECTORY "${DRIVER_STUB_DIR}"
+  )
+endif()
```

