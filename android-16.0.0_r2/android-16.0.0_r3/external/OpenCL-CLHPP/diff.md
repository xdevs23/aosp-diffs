```diff
diff --git a/.github/workflows/linux.yml b/.github/workflows/linux.yml
deleted file mode 100644
index 5792620..0000000
--- a/.github/workflows/linux.yml
+++ /dev/null
@@ -1,334 +0,0 @@
-name: Linux
-
-on: [push, pull_request]
-
-env:
-  OPENCL_PKGCONFIG_PATHS: ${{ github.workspace }}/install/share/pkgconfig:${{ github.workspace }}/external/OpenCL-Headers/install/share/pkgconfig:${{ github.workspace }}/external/OpenCL-ICD-Loader/install/lib/pkgconfig
-
-jobs:
-  cmake-minimum:
-    runs-on: ${{ matrix.OS }}
-    container: streamhpc/opencl-sdk-base:ubuntu-18.04-20220127
-    strategy:
-      matrix:
-        OS: [ubuntu-20.04]
-        VER: [7] # gcc-8, clang-8, clang-10
-        EXT: [ON, OFF]
-        GEN: [Unix Makefiles]
-        CONFIG: [Debug, Release]
-        STD: [11, 14]
-        BIN: [64] # Temporarily disable cross-compilation (will need toolchain files)
-        CMAKE: [3.1.3]
-    env:
-      CMAKE_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/cmake
-      CTEST_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/ctest
-      # Workaround for https://github.com/actions/runner/issues/2058
-      OPENCL_PKGCONFIG_PATHS: /__w/OpenCL-CLHPP/OpenCL-CLHPP/install/share/pkgconfig:/__w/OpenCL-CLHPP/OpenCL-CLHPP/external/OpenCL-Headers/install/share/pkgconfig:/__w/OpenCL-CLHPP/OpenCL-CLHPP/external/OpenCL-ICD-Loader/install/lib/pkgconfig
-
-
-    steps:
-    - name: Checkout OpenCL-CLHPP
-      uses: actions/checkout@v3
-      with:
-        submodules: recursive
-
-    - name: Checkout OpenCL-Headers
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-Headers
-        path: external/OpenCL-Headers
-
-    - name: Checkout OpenCL-ICD-Loader
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-ICD-Loader
-        path: external/OpenCL-ICD-Loader
-
-    - name: Build & install OpenCL-Headers
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
-        -D CMAKE_C_FLAGS="-w -m${{matrix.BIN}}"
-        -D CMAKE_C_COMPILER=gcc-${{matrix.VER}}
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
-    - name: Build & install OpenCL-ICD-Loader
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
-        -D CMAKE_C_FLAGS="-w -m${{matrix.BIN}}"
-        -D CMAKE_C_COMPILER=gcc-${{matrix.VER}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install
-        -D BUILD_TESTING=OFF
-        -B$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build
-        -H$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader &&
-        $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build
-        --target install
-        --
-        -j`nproc`
-
-    - name: Configure
-      shell: bash
-      # no -Werror during configuration because:
-      # warning: ISO C forbids assignment between function pointer and ‘void *’ [-Wpedantic]
-      # warning: unused parameter [-Wunused-parameter]
-      run: 
-        $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D BUILD_TESTING=ON
-        -D BUILD_EXAMPLES=ON
-        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_CXX_COMPILER=g++-${{matrix.VER}}
-        -D CMAKE_CXX_STANDARD=${{matrix.STD}}
-        -D CMAKE_CXX_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install"
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
-      working-directory: ${{runner.workspace}}/OpenCL-CLHPP/build
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
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_CXX_COMPILER=g++-${{matrix.VER}}
-        -D CMAKE_CXX_STANDARD=${{matrix.STD}}
-        -D CMAKE_CXX_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install;$GITHUB_WORKSPACE/install"
-        -B$GITHUB_WORKSPACE/build/downstream/bare
-        -H$GITHUB_WORKSPACE/tests/pkgconfig/bare ;
-        $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/build/downstream/bare ;
-        cd $GITHUB_WORKSPACE/build/downstream/bare ;
-        $CTEST_EXE --output-on-failure
-
-    - name: "Consume (SDK): Configure/Build/Test"
-      shell: bash
-      run: $CMAKE_EXE -E make_directory $GITHUB_WORKSPACE/install/share/cmake/OpenCL ;
-        echo -e "include(\"$GITHUB_WORKSPACE/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake\")\ninclude(\"$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install/share/cmake/OpenCLICDLoader/OpenCLICDLoaderTargets.cmake\")\ninclude(\"\${CMAKE_CURRENT_LIST_DIR}/../OpenCLHeadersCpp/OpenCLHeadersCppTargets.cmake\")" > $GITHUB_WORKSPACE/install/share/cmake/OpenCL/OpenCLConfig.cmake ;
-        $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_CXX_COMPILER=g++-${{matrix.VER}}
-        -D CMAKE_CXX_STANDARD=${{matrix.STD}}
-        -D CMAKE_CXX_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install;$GITHUB_WORKSPACE/install"
-        -B$GITHUB_WORKSPACE/build/downstream/sdk
-        -H$GITHUB_WORKSPACE/tests/pkgconfig/sdk ;
-        $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/build/downstream/sdk ;
-        cd $GITHUB_WORKSPACE/build/downstream/sdk ;
-        $CTEST_EXE --output-on-failure
-
-    - name: Test pkg-config
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL-CLHPP --cflags | grep -q "\-I$GITHUB_WORKSPACE/install/include"
-
-    - name: Test pkg-config dependency
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL-CLHPP --cflags | grep -q "\-I$GITHUB_WORKSPACE/external/OpenCL-Headers/install/include"
-
-
-
-
-
-  cmake-latest:
-    runs-on: ${{ matrix.OS }}
-    strategy:
-      matrix:
-        OS : [ubuntu-20.04]
-        VER: [9, 11] # clang-11, clang-13
-        EXT: [ON, OFF]
-        GEN: [Ninja Multi-Config]
-        STD: [11, 14]
-        BIN: [64] # Temporarily disable cross-compilation (will need toolchain files)
-        CMAKE: [3.21.2]
-    env:
-      CMAKE_URL: https://github.com/Kitware/CMake/releases/download/v${{ matrix.CMAKE }}/cmake-${{ matrix.CMAKE }}-Linux-x86_64.tar.gz
-      CMAKE_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/cmake
-      CTEST_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/ctest
-
-
-    steps:
-    - name: Checkout OpenCL-CLHPP
-      uses: actions/checkout@v3
-      with:
-        submodules: recursive
-
-    - name: Checkout OpenCL-Headers
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-Headers
-        path: external/OpenCL-Headers
-
-    - name: Checkout OpenCL-ICD-Loader
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-ICD-Loader
-        path: external/OpenCL-ICD-Loader
-
-    - name: Create Build Environment
-      run: sudo apt-get update -q;
-        if [[ "${{matrix.GEN}}" =~ "Ninja" && ! `which ninja` ]]; then sudo apt install -y ninja-build; fi;
-        sudo apt install gcc-${{matrix.VER}} g++-${{matrix.VER}}; 
-        if [[ "${{matrix.BIN}}" == "32" ]];
-        then sudo apt install gcc-${COMPILER_VER}-multilib;
-        fi;
-        mkdir -p /opt/Kitware/CMake;
-        wget -c $CMAKE_URL -O - | tar -xz --directory /opt/Kitware/CMake;
-        mv /opt/Kitware/CMake/cmake-${{ matrix.CMAKE }}-* /opt/Kitware/CMake/${{ matrix.CMAKE }}
-      # Install Ninja only if it's the selected generator and it's not available.
-
-    - name: Build & install OpenCL-Headers
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_C_FLAGS="-w -m${{matrix.BIN}}"
-        -D CMAKE_C_COMPILER=gcc-${{matrix.VER}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -D BUILD_TESTING=OFF
-        -B$GITHUB_WORKSPACE/external/OpenCL-Headers/build
-        -H$GITHUB_WORKSPACE/external/OpenCL-Headers &&
-        $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/external/OpenCL-Headers/build
-        --target install
-        --config Release
-        --
-        -j`nproc`
-
-    - name: Build & install OpenCL-ICD-Loader
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_C_FLAGS="-w -m${{matrix.BIN}}"
-        -D CMAKE_C_COMPILER=gcc-${{matrix.VER}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install
-        -D BUILD_TESTING=OFF
-        -B$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build
-        -H$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader &&
-        $CMAKE_EXE
-        --build $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build
-        --target install
-        --config Release
-        --
-        -j`nproc`
-
-    - name: Configure
-      shell: bash
-      # no -Werror during configuration because:
-      # warning: ISO C forbids assignment between function pointer and ‘void *’ [-Wpedantic]
-      # warning: unused parameter [-Wunused-parameter]
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D BUILD_TESTING=ON
-        -D BUILD_EXAMPLES=ON
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_CXX_COMPILER=g++-${{matrix.VER}}
-        -D CMAKE_CXX_STANDARD=${{matrix.STD}}
-        -D CMAKE_CXX_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install"
-        -B$GITHUB_WORKSPACE/build
-        -H$GITHUB_WORKSPACE
-
-    - name: Build
-      shell: bash
-      run: |
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config Release -- -j`nproc`;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config Debug   -- -j`nproc`
-
-    - name: Test
-      working-directory: ${{runner.workspace}}/OpenCL-CLHPP/build
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
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_CXX_COMPILER=g++-${{matrix.VER}}
-        -D CMAKE_CXX_STANDARD=${{matrix.STD}}
-        -D CMAKE_CXX_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install;$GITHUB_WORKSPACE/install"
-        -B$GITHUB_WORKSPACE/build/downstream/bare
-        -H$GITHUB_WORKSPACE/tests/pkgconfig/bare ;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/bare --config Release;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/bare --config Debug;
-        cd $GITHUB_WORKSPACE/build/downstream/bare;
-        $CTEST_EXE --output-on-failure -C Release;
-        $CTEST_EXE --output-on-failure -C Debug;
-
-    - name: "Consume (SDK): Configure/Build/Test"
-      shell: bash
-      run: $CMAKE_EXE -E make_directory $GITHUB_WORKSPACE/install/share/cmake/OpenCL ;
-        echo -e "include(\"$GITHUB_WORKSPACE/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake\")\ninclude(\"$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install/share/cmake/OpenCLICDLoader/OpenCLICDLoaderTargets.cmake\")\ninclude(\"\${CMAKE_CURRENT_LIST_DIR}/../OpenCLHeadersCpp/OpenCLHeadersCppTargets.cmake\")" > $GITHUB_WORKSPACE/install/share/cmake/OpenCL/OpenCLConfig.cmake ;
-        $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -m${{matrix.BIN}}"
-        -D CMAKE_CXX_COMPILER=g++-${{matrix.VER}}
-        -D CMAKE_CXX_STANDARD=${{matrix.STD}}
-        -D CMAKE_CXX_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install;$GITHUB_WORKSPACE/install"
-        -B$GITHUB_WORKSPACE/build/downstream/sdk
-        -H$GITHUB_WORKSPACE/tests/pkgconfig/sdk ;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/sdk --config Release;
-        $CMAKE_EXE --build $GITHUB_WORKSPACE/build/downstream/sdk --config Debug;
-        cd $GITHUB_WORKSPACE/build/downstream/sdk;
-        $CTEST_EXE --output-on-failure -C Release;
-        $CTEST_EXE --output-on-failure -C Debug;
-
-    - name: Test pkg-config
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL-CLHPP --cflags | grep -q "\-I$GITHUB_WORKSPACE/install/include"
-
-    - name: Test pkg-config dependency
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL-CLHPP --cflags | grep -q "\-I$GITHUB_WORKSPACE/external/OpenCL-Headers/install/include"
diff --git a/.github/workflows/macos.yml b/.github/workflows/macos.yml
deleted file mode 100644
index b0a9f40..0000000
--- a/.github/workflows/macos.yml
+++ /dev/null
@@ -1,179 +0,0 @@
-name: MacOS
-
-on: [push, pull_request]
-
-env:
-  OPENCL_PKGCONFIG_PATHS: ${{ github.workspace }}/install/share/pkgconfig:${{ github.workspace }}/external/OpenCL-Headers/install/share/pkgconfig:${{ github.workspace }}/external/OpenCL-ICD-Loader/install/lib/pkgconfig
-
-jobs:
-  macos-gcc:
-    #runs-on: macos-latest
-    runs-on: macos-11 # temporary, macos-latest only supports gcc-12
-    strategy:
-      matrix:
-        VER: [9, 11]
-        EXT: [ON, OFF]
-        GEN: [Xcode, Ninja Multi-Config]
-        STD: [11, 17]
-
-    steps:
-    - name: Checkout OpenCL-CLHPP
-      uses: actions/checkout@v3
-      with:
-        submodules: recursive
-
-    - name: Checkout OpenCL-Headers
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-Headers
-        path: external/OpenCL-Headers
-
-    - name: Checkout OpenCL-ICD-Loader
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-ICD-Loader
-        path: external/OpenCL-ICD-Loader
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
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -D BUILD_TESTING=OFF
-        -S $GITHUB_WORKSPACE/external/OpenCL-Headers
-        -B $GITHUB_WORKSPACE/external/OpenCL-Headers/build &&
-        cmake
-        --build $GITHUB_WORKSPACE/external/OpenCL-Headers/build
-        --target install
-        --config Release
-        --parallel `sysctl -n hw.logicalcpu` &&
-        ls -al $GITHUB_WORKSPACE/external/OpenCL-Headers/install &&
-        ls -al $GITHUB_WORKSPACE/external/OpenCL-Headers/install/include &&
-        ls -al $GITHUB_WORKSPACE/external/OpenCL-Headers/install/include/CL &&
-        ls -al $GITHUB_WORKSPACE/external/OpenCL-Headers/install/include/OpenCL
-
-    - name: Build & install OpenCL-ICD-Loader
-      run: cmake
-        -G "${{matrix.GEN}}"
-        -D CMAKE_C_FLAGS="-w -m64"
-        -D CMAKE_C_COMPILER=/usr/local/bin/gcc-${{matrix.VER}}
-        -D CMAKE_C_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install
-        -D BUILD_TESTING=OFF
-        -S $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader
-        -B $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build &&
-        cmake
-        --build $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build
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
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -Wno-format -m64"
-        -D CMAKE_CXX_COMPILER=/usr/local/bin/g++-${{matrix.VER}}
-        -D CMAKE_CXX_STANDARD=${{matrix.STD}}
-        -D CMAKE_CXX_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install"
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
-      working-directory: ${{runner.workspace}}/OpenCL-CLHPP/build
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
-    - name: "Consume (standalone): Configure/Build/Test"
-      shell: bash
-      run: cmake
-        -G "${{matrix.GEN}}"
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -m64"
-        -D CMAKE_CXX_COMPILER=/usr/local/bin/g++-${{matrix.VER}}
-        -D CMAKE_CXX_STANDARD=${{matrix.STD}}
-        -D CMAKE_CXX_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install;$GITHUB_WORKSPACE/install"
-        -B$GITHUB_WORKSPACE/build/downstream/bare
-        -H$GITHUB_WORKSPACE/tests/pkgconfig/bare ;
-        cmake --build $GITHUB_WORKSPACE/build/downstream/bare --config Release ;
-        cmake --build $GITHUB_WORKSPACE/build/downstream/bare --config Debug ;
-        cd $GITHUB_WORKSPACE/build/downstream/bare ;
-        ctest --output-on-failure -C Release ;
-        ctest --output-on-failure -C Debug
-
-    - name: "Consume (SDK): Configure/Build/Test"
-      shell: bash
-      run: cmake -E make_directory $GITHUB_WORKSPACE/install/share/cmake/OpenCL ;
-        echo -e 'include("/Users/runner/work/OpenCL-CLHPP/OpenCL-CLHPP/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake")\ninclude("/Users/runner/work/OpenCL-CLHPP/OpenCL-CLHPP/external/OpenCL-ICD-Loader/install/share/cmake/OpenCLICDLoader/OpenCLICDLoaderTargets.cmake")\ninclude("${CMAKE_CURRENT_LIST_DIR}/../OpenCLHeadersCpp/OpenCLHeadersCppTargets.cmake")' > $GITHUB_WORKSPACE/install/share/cmake/OpenCL/OpenCLConfig.cmake ;
-        cmake
-        -G "${{matrix.GEN}}"
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -m64"
-        -D CMAKE_CXX_COMPILER=/usr/local/bin/g++-${{matrix.VER}}
-        -D CMAKE_CXX_STANDARD=${{matrix.STD}}
-        -D CMAKE_CXX_EXTENSIONS=${{matrix.EXT}}
-        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install;$GITHUB_WORKSPACE/install"
-        -B$GITHUB_WORKSPACE/build/downstream/sdk
-        -H$GITHUB_WORKSPACE/tests/pkgconfig/sdk ;
-        cmake --build $GITHUB_WORKSPACE/build/downstream/sdk --config Release ;
-        cmake --build $GITHUB_WORKSPACE/build/downstream/sdk --config Debug ;
-        cd $GITHUB_WORKSPACE/build/downstream/sdk ;
-        ctest --output-on-failure -C Release ;
-        ctest --output-on-failure -C Debug
-
-    - name: Test pkg-config
-      shell: bash
-      run: |
-        if [[ ! `which pkg-config` ]]; then brew install pkg-config; fi;
-        PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL-CLHPP --cflags | grep -q "\-I$GITHUB_WORKSPACE/install/include"
-
-    - name: Test pkg-config dependency
-      shell: bash
-      run: PKG_CONFIG_PATH="$OPENCL_PKGCONFIG_PATHS" pkg-config OpenCL-CLHPP --cflags | grep -q "\-I$GITHUB_WORKSPACE/external/OpenCL-Headers/install/include"
diff --git a/.github/workflows/presubmit.yml b/.github/workflows/presubmit.yml
new file mode 100644
index 0000000..b6f2c93
--- /dev/null
+++ b/.github/workflows/presubmit.yml
@@ -0,0 +1,860 @@
+name: Presubmit
+
+on: [push, pull_request]
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
+        COMPILER:
+          - C_NAME: gcc
+            CXX_NAME: g++
+            VER: 11
+          - C_NAME: gcc
+            CXX_NAME: g++
+            VER: 13
+          - C_NAME: clang
+            CXX_NAME: clang++
+            VER: 14
+          - C_NAME: clang
+            CXX_NAME: clang++
+            VER: 16
+        BIN: [64]
+        CXXSTD: [11, 17]
+        CONF:
+          - GEN: Unix Makefiles
+            CONFIG: Debug
+          - GEN: Unix Makefiles
+            CONFIG: Release
+          - GEN: Ninja Multi-Config
+            CONFIG: Release
+        IMAGE:
+          - khronosgroup/docker-images:opencl-sdk-base-ubuntu-22.04.20230717
+        include:
+          - CMAKE: system
+            COMPILER:
+              C_NAME: gcc
+              CXX_NAME: g++
+              VER: 9
+            BIN: 64
+            CXXSTD: 11
+            CONF:
+              GEN: Unix Makefiles
+              CONFIG: Debug
+            IMAGE: khronosgroup/docker-images:opencl-sdk-base-ubuntu-20.04.20230717
+          - CMAKE: system
+            COMPILER:
+              C_NAME: gcc
+              CXX_NAME: g++
+              VER: 9
+            BIN: 64
+            CXXSTD: 11
+            CONF:
+              GEN: Unix Makefiles
+              CONFIG: Release
+            IMAGE: khronosgroup/docker-images:opencl-sdk-base-ubuntu-20.04.20230717
+          - CMAKE: system
+            COMPILER:
+              C_NAME: gcc
+              CXX_NAME: g++
+              VER: 9
+            BIN: 32
+            CXXSTD: 11
+            CONF:
+              GEN: Unix Makefiles
+              CONFIG: Debug
+            IMAGE: khronosgroup/docker-images:opencl-sdk-base-ubuntu-20.04.20230717
+          - CMAKE: system
+            COMPILER:
+              C_NAME: gcc
+              CXX_NAME: g++
+              VER: 9
+            BIN: 32
+            CXXSTD: 11
+            CONF:
+              GEN: Unix Makefiles
+              CONFIG: Release
+            IMAGE: khronosgroup/docker-images:opencl-sdk-base-ubuntu-20.04.20230717
+    container: ${{matrix.IMAGE}}
+    env:
+      CMAKE_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/cmake
+      CPACK_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/cpack
+      CTEST_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/ctest
+      DEB_INSTALLATION_PATH: /usr
+      CC: ${{matrix.COMPILER.C_NAME}}-${{matrix.COMPILER.VER}}
+      CXX:  ${{matrix.COMPILER.CXX_NAME}}-${{matrix.COMPILER.VER}}
+      CFLAGS: -Wall -Wextra -pedantic -Werror -m${{matrix.BIN}}
+      CXXFLAGS: -Wall -Wextra -pedantic -Werror -m${{matrix.BIN}}
+
+    steps:
+    - name: Install system CMake
+      if: ${{matrix.CMAKE}} == 'system'
+      run: apt-get update -qq && apt-get install -y cmake &&
+        echo "CMAKE_EXE=cmake" >> "$GITHUB_ENV" &&
+        echo "CPACK_EXE=cpack" >> "$GITHUB_ENV" &&
+        echo "CTEST_EXE=ctest" >> "$GITHUB_ENV"
+
+    - name: Checkout OpenCL-CLHPP
+      uses: actions/checkout@v4
+      with:
+        submodules: recursive
+
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+      with:
+        path: external/OpenCL-Headers
+        repository: KhronosGroup/OpenCL-Headers
+
+    - name: Checkout OpenCL-ICD-Loader
+      uses: actions/checkout@v4
+      with:
+        path: external/OpenCL-ICD-Loader
+        repository: KhronosGroup/OpenCL-ICD-Loader
+
+    - name: Configure, install & package OpenCL-Headers
+      run: $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D CMAKE_C_EXTENSIONS=OFF
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
+    - name: Configure & install OpenCL-ICD-Loader
+      run: $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install
+        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
+        -D BUILD_TESTING=OFF
+        -S $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader
+        -B $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build &&
+        $CMAKE_EXE
+        --build $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build
+        --target install
+        --parallel `nproc`
+
+    - name: Configure
+      run: $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        -D BUILD_TESTING=ON
+        -D BUILD_EXAMPLES=ON
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D CMAKE_CXX_STANDARD=${{matrix.CXXSTD}}
+        -D CMAKE_CXX_EXTENSIONS=OFF
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
+        -D CPACK_PACKAGING_INSTALL_PREFIX=$DEB_INSTALLATION_PATH
+        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install"
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
+      working-directory: ${{runner.workspace}}/OpenCL-CLHPP/build
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
+        -D CMAKE_CXX_STANDARD=${{matrix.CXXSTD}}
+        -D CMAKE_CXX_EXTENSIONS=OFF
+        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install
+        -S $GITHUB_WORKSPACE/tests/pkgconfig/bare
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
+      working-directory: ${{runner.workspace}}/OpenCL-CLHPP/build_package
+      run: if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CTEST_EXE -C ${{matrix.CONF.CONFIG}} --output-on-failure --no-tests=error --parallel `nproc`;
+        else
+          $CTEST_EXE -C Debug --output-on-failure --no-tests=error --parallel `nproc`;
+          $CTEST_EXE -C Release --output-on-failure --no-tests=error --parallel `nproc`;
+        fi
+
+    - name: Test pkg-config (DEB)
+      # /usr/include is already on the include search path,
+      # we don't expect any output
+      run: |
+        # First check if OpenCL-Headers is locatable
+        pkg-config OpenCL-CLHPP --cflags
+        # Then check if the output is empty
+        if [[ "$(pkg-config OpenCL-CLHPP --cflags)" ]];
+        then
+          exit 1;
+        fi;
+
+    - name: Uninstall (DEB)
+      run: apt-get remove -y opencl-c-headers opencl-clhpp-headers
+
+    - name: Test install
+      run: $CMAKE_EXE --build $GITHUB_WORKSPACE/build --target install --config ${{matrix.CONF.CONFIG}} --parallel `nproc`
+
+    - name: Consume (install)
+      run: $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install;$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/install"
+        -S $GITHUB_WORKSPACE/tests/pkgconfig/bare
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
+      working-directory: ${{runner.workspace}}/OpenCL-CLHPP/build_install
+      run: if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CTEST_EXE -C ${{matrix.CONF.CONFIG}} --output-on-failure --no-tests=error --parallel `nproc`;
+        else
+          $CTEST_EXE -C Debug --output-on-failure --no-tests=error --parallel `nproc`;
+          $CTEST_EXE -C Release --output-on-failure --no-tests=error --parallel `nproc`;
+        fi
+
+    - name: Test pkg-config (install)
+      run: PKG_CONFIG_PATH=$GITHUB_WORKSPACE/install/share/pkgconfig:$GITHUB_WORKSPACE/external/OpenCL-Headers/install/share/pkgconfig
+        pkg-config OpenCL-CLHPP --cflags | grep -q "\-I$GITHUB_WORKSPACE/install/include"
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
+        CXXSTD: [11, 17]
+        exclude:
+        - VER: clangcl
+          GEN: Ninja Multi-Config
+        include:
+        - VER: v142
+          GEN: Visual Studio 17 2022
+          BIN: x86
+          CXXSTD: 11
+    env:
+      NINJA_URL: https://github.com/ninja-build/ninja/releases/download/v1.10.2/ninja-win.zip
+      NINJA_ROOT: C:\Tools\Ninja
+      VS_ROOT: 'C:\Program Files\Microsoft Visual Studio\2022\Enterprise'
+      UseMultiToolTask: true # Better parallel MSBuild execution
+      EnforceProcessCountAcrossBuilds: 'true' # -=-
+      MultiProcMaxCount: '3'                  # -=-
+      # C4152: nonstandard extension, function/data pointer conversion in expression
+      # C4201: nonstandard extension used: nameless struct/union
+      # C4310: cast truncates constant value
+      CFLAGS: /W4 /WX /wd4152 /wd4201 /wd4310
+      CXXFLAGS: /W4 /WX
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
+    - name: Checkout OpenCL-CLHPP
+      uses: actions/checkout@v4
+      with:
+        submodules: recursive
+
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+      with:
+        repository: KhronosGroup/OpenCL-Headers
+        path: external/OpenCL-Headers
+
+    - name: Checkout OpenCL-ICD-Loader
+      uses: actions/checkout@v4
+      with:
+        repository: KhronosGroup/OpenCL-ICD-Loader
+        path: external/OpenCL-ICD-Loader
+
+    - name: Build & install OpenCL-Headers (MSBuild)
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -A $BIN `
+          -T ${{matrix.VER}} `
+          -D BUILD_TESTING=OFF `
+          -D CMAKE_INSTALL_PREFIX=${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install `
+          -S ${env:GITHUB_WORKSPACE}\external\OpenCL-Headers `
+          -B ${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\build
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-Headers failed." }
+        & cmake `
+          --build "${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\build" `
+          --target install `
+          --config Release `
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
+          -G '${{matrix.GEN}}' `
+          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe"  `
+          -D BUILD_TESTING=OFF `
+          -D CMAKE_INSTALL_PREFIX=${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install `
+          -S ${env:GITHUB_WORKSPACE}\external\OpenCL-Headers `
+          -B ${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\build
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-Headers failed." }
+        & cmake `
+          --build "${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\build" `
+          --target install `
+          --config Release
+        if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-Headers failed." }
+
+    - name: Build & install OpenCL-ICD-Loader (MSBuild)
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -A $BIN `
+          -T ${{matrix.VER}} `
+          -D BUILD_TESTING=OFF `
+          -D CMAKE_INSTALL_PREFIX=${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\install `
+          -D CMAKE_PREFIX_PATH=${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install `
+          -S ${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader `
+          -B ${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\build
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-ICD-Loader failed." }
+        & cmake `
+          --build "${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\build" `
+          --target install `
+          --config Release `
+          -- `
+          /verbosity:minimal `
+          /maxCpuCount `
+          /noLogo
+        if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-ICD-Loader failed." }
+
+    - name: Build & install OpenCL-ICD-Loader (Ninja Multi-Config)
+      if: matrix.GEN == 'Ninja Multi-Config'
+      run: |
+        $VER = switch ('${{matrix.VER}}') { `
+          'v142' {'14.2'} `
+          'v143' {'14.4'} }
+        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
+        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=$VER"
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe"  `
+          -D BUILD_TESTING=OFF `
+          -D CMAKE_INSTALL_PREFIX=${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\install `
+          -D CMAKE_PREFIX_PATH=${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install `
+          -S ${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader `
+          -B ${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\build
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-ICD-Loader failed." }
+        & cmake `
+          --build "${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\build" `
+          --target install `
+          --config Release
+        if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-ICD-Loader failed." }
+
+    - name: Configure (MSBuild)
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -A $BIN `
+          -T ${{matrix.VER}} `
+          -D BUILD_TESTING=ON `
+          -D CMAKE_CXX_STANDARD=${{matrix.CXXSTD}} `
+          -D CMAKE_CXX_EXTENSIONS=OFF `
+          -D CMAKE_INSTALL_PREFIX=${env:GITHUB_WORKSPACE}\install `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install;${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\install" `
+          -S ${env:GITHUB_WORKSPACE} `
+          -B ${env:GITHUB_WORKSPACE}\build
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-CLHPP failed." }
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
+          -G '${{matrix.GEN}}' `
+          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe" `
+          -D BUILD_TESTING=ON `
+          -D CMAKE_CXX_STANDARD=${{matrix.CXXSTD}} `
+          -D CMAKE_CXX_EXTENSIONS=OFF `
+          -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL `
+          -D CMAKE_INSTALL_PREFIX=${env:GITHUB_WORKSPACE}\install `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install;${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\install" `
+          -S ${env:GITHUB_WORKSPACE} `
+          -B ${env:GITHUB_WORKSPACE}\build
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-CLHPP failed." }
+
+    - name: Build (MSBuild)
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\build" `
+            --config ${Config} `
+            -- `
+            /verbosity:minimal `
+            /maxCpuCount `
+            /noLogo
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-CLHPP in $Config failed." }
+        }
+
+    - name: Build (Ninja)
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
+            --config ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-CLHPP in $Config failed." }
+        }
+
+    - name: Test
+      run: |
+        foreach ($Config in 'Release','Debug') {
+          & ctest `
+            --test-dir "${env:GITHUB_WORKSPACE}\build" `
+            --build-config ${Config} `
+            --output-on-failure `
+            --no-tests=error `
+            --parallel ${env:NUMBER_OF_PROCESSORS}
+          if ($LASTEXITCODE -ne 0) { throw "Testing OpenCL-CLHPP in $Config failed." }
+        }
+
+    - name: Install
+      run: |
+        & cmake `
+          --install "${env:GITHUB_WORKSPACE}\build" `
+          --prefix "${env:GITHUB_WORKSPACE}\install" `
+          --config Release
+        if ($LASTEXITCODE -ne 0) { throw "Installing OpenCL-CLHPP failed." }
+
+    - name: "Consume (MSBuild standalone): Configure/Build/Test"
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -A ${BIN} `
+          -T ${{matrix.VER}} `
+          -D CMAKE_CXX_STANDARD=${{matrix.CXXSTD}} `
+          -D CMAKE_CXX_EXTENSIONS=OFF `
+          -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install;${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\install;${env:GITHUB_WORKSPACE}\install" `
+          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\bare" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-CLHPP standalone consume test failed." }
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare" `
+            --config ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-CLHPP standalone consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare
+          & ctest --output-on-failure --no-tests=error -C ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-CLHPP standalone consume test in $Config failed." }
+        }
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
+          -D CMAKE_CXX_STANDARD=${{matrix.CXXSTD}} `
+          -D CMAKE_CXX_EXTENSIONS=OFF `
+          -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install;${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\install;${env:GITHUB_WORKSPACE}\install" `
+          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\bare" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-CLHPP standalone consume test failed." }
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare" `
+            --config ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-CLHPP standalone consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare
+          & ctest --output-on-failure --no-tests=error -C ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-CLHPP standalone consume test in $Config failed." }
+        }
+
+    - name: Consume (Emulate SDK presence)
+      run: |
+        New-Item -Type Directory -Path ${env:GITHUB_WORKSPACE}\install\share\cmake\OpenCL
+        $workspace = ${env:GITHUB_WORKSPACE}.replace("\", "/")
+        New-Item -Type File -Path ${env:GITHUB_WORKSPACE}\install\share\cmake\OpenCL\OpenCLConfig.cmake -Value "include(`"$workspace/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake`")`r`ninclude(`"$workspace/external/OpenCL-ICD-Loader/install/share/cmake/OpenCLICDLoader/OpenCLICDLoaderTargets.cmake`")`r`ninclude(`"`${CMAKE_CURRENT_LIST_DIR}/../OpenCLHeadersCpp/OpenCLHeadersCppTargets.cmake`")"
+
+    - name: "Consume (MSBuild SDK): Configure/Build/Test"
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -A ${BIN} `
+          -T ${{matrix.VER}} `
+          -D CMAKE_CXX_STANDARD=${{matrix.CXXSTD}} `
+          -D CMAKE_CXX_EXTENSIONS=OFF `
+          -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install;${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\install;${env:GITHUB_WORKSPACE}\install" `
+          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\sdk" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-CLHPP in-SDK consume test failed." }
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk" `
+            --config ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-CLHPP in-SDK consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk
+          & ctest --output-on-failure --no-tests=error -C ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-CLHPP in-SDK consume test in $Config failed." }
+        }
+
+    - name: "Consume (Ninja-Multi-Config SDK): Configure/Build/Test"
+      if: matrix.GEN == 'Ninja Multi-Config'
+      run: |
+        $VER = switch ('${{matrix.VER}}') { `
+          'v142' {'14.2'} `
+          'v143' {'14.4'} }
+        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
+        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=${VER}"
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe" `
+          -D CMAKE_CXX_STANDARD=${{matrix.CXXSTD}} `
+          -D CMAKE_CXX_EXTENSIONS=OFF `
+          -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\external\OpenCL-Headers\install;${env:GITHUB_WORKSPACE}\external\OpenCL-ICD-Loader\install;${env:GITHUB_WORKSPACE}\install" `
+          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\sdk" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-CLHPP in-SDK consume test failed." }
+        foreach ($Config in 'Release','Debug') { `
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk" `
+            --config ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-CLHPP in-SDK consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk
+          & ctest --output-on-failure --no-tests=error -C ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-CLHPP in-SDK consume test in $Config failed." }
+        }
+
+  macos:
+    runs-on: macos-latest
+    defaults:
+      run:
+        shell: bash
+    strategy:
+      matrix:
+        COMPILER:
+          - C_NAME: /usr/bin/clang
+            CXX_NAME: /usr/bin/clang++
+          # Disabled due to problems with __has_cpp_attribute
+          # See https://gcc.gnu.org/bugzilla/show_bug.cgi?id=114007
+          #- C_NAME: gcc-11
+          #  CXX_NAME: g++-11
+          # Disabled due to problems with the __API_AVAILABLE macro
+          # - C_NAME: gcc-13
+          #   CXX_NAME: g++-13
+          #   # A workaround for a bug in the toolset
+          #   # See https://forums.developer.apple.com/forums/thread/737707
+          #   EXTRA_FLAGS: -Wl,-ld_classic
+        GEN:
+        - Xcode
+        - Ninja Multi-Config
+        CXXSTD: [11, 17]
+        exclude:
+        # These entries are excluded, since XCode selects its own compiler
+        - COMPILER:
+            C_NAME: gcc-11
+            CXX_NAME: g++-11
+          GEN: Xcode
+        - COMPILER:
+            C_NAME: gcc-13
+            CXX_NAME: g++-13
+          GEN: Xcode
+    env:
+      CC: ${{matrix.COMPILER.C_NAME}}
+      CXX: ${{matrix.COMPILER.CXX_NAME}}
+      CFLAGS: -Wall -Wextra -pedantic -Wno-format -Werror ${{matrix.COMPILER.EXTRA_FLAGS}}
+      CXXFLAGS: -Wall -Wextra -pedantic -Wno-format -Werror ${{matrix.COMPILER.EXTRA_FLAGS}}
+
+    steps:
+    - name: Checkout OpenCL-CLHPP
+      uses: actions/checkout@v4
+      with:
+        submodules: recursive
+
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+      with:
+        repository: KhronosGroup/OpenCL-Headers
+        path: external/OpenCL-Headers
+
+    - name: Checkout OpenCL-ICD-Loader
+      uses: actions/checkout@v4
+      with:
+        repository: KhronosGroup/OpenCL-ICD-Loader
+        path: external/OpenCL-ICD-Loader
+
+    - name: Create Build Environment
+      run: |
+        # Install Ninja only if it's the selected generator and it's not available.
+        if [[ "${{matrix.GEN}}" == "Ninja Multi-Config" && ! `which ninja` ]]; then brew install ninja; fi &&
+        if [[ ! `which pkg-config` ]]; then brew install pkg-config; fi;
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
+    - name: Build & install OpenCL-ICD-Loader
+      run: cmake
+        -G "${{matrix.GEN}}"
+        -D BUILD_TESTING=OFF
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install
+        -S $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader
+        -B $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build &&
+        cmake
+        --build $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build
+        --target install
+        --config Release
+        --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Configure
+      run: cmake
+        -G "${{matrix.GEN}}"
+        -D BUILD_TESTING=ON
+        -D CMAKE_CXX_STANDARD=${{matrix.CXXSTD}}
+        -D CMAKE_CXX_EXTENSIONS=OFF
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
+        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install"
+        -S $GITHUB_WORKSPACE
+        -B $GITHUB_WORKSPACE/build
+
+    - name: Build
+      run: |
+        cmake --build $GITHUB_WORKSPACE/build --config Release --parallel `sysctl -n hw.logicalcpu`
+        cmake --build $GITHUB_WORKSPACE/build --config Debug --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Test
+      working-directory: ${{runner.workspace}}/OpenCL-CLHPP/build
+      run: |
+        ctest -C Release --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu`
+        ctest -C Debug   --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Test install
+      run: |
+        cmake --build $GITHUB_WORKSPACE/build --config Release --target install
+
+    - name: Consume (install)
+      run: cmake
+        -G "${{matrix.GEN}}"
+        -D CMAKE_CXX_STANDARD=${{matrix.CXXSTD}}
+        -D CMAKE_CXX_EXTENSIONS=OFF
+        -D CMAKE_CXX_STANDARD_REQUIRED=ON
+        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install;$GITHUB_WORKSPACE/install"
+        -S $GITHUB_WORKSPACE/tests/pkgconfig/bare
+        -B $GITHUB_WORKSPACE/build_install &&
+        cmake --build $GITHUB_WORKSPACE/build_install --config Release --parallel `sysctl -n hw.logicalcpu` &&
+        cmake --build $GITHUB_WORKSPACE/build_install --config Debug   --parallel `sysctl -n hw.logicalcpu` &&
+        cd $GITHUB_WORKSPACE/build_install &&
+        ctest -C Release --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu` &&
+        ctest -C Debug   --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Test pkg-config
+      run: |
+        export PKG_CONFIG_PATH=$GITHUB_WORKSPACE/install/share/pkgconfig:$GITHUB_WORKSPACE/external/OpenCL-Headers/install/share/pkgconfig:$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install/lib/pkgconfig
+        pkg-config OpenCL-CLHPP --cflags | grep -q "\-I$GITHUB_WORKSPACE/install/include"
+
+    - name: Test pkg-config dependency
+      run: |
+        export PKG_CONFIG_PATH=$GITHUB_WORKSPACE/install/share/pkgconfig:$GITHUB_WORKSPACE/external/OpenCL-Headers/install/share/pkgconfig:$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install/lib/pkgconfig
+        pkg-config OpenCL-CLHPP --cflags | grep -q "\-I$GITHUB_WORKSPACE/external/OpenCL-Headers/install/include"
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
+      CXXFLAGS: -Wall -Wextra -pedantic -Werror
+    steps:
+    - name: Checkout OpenCL-CLHPP
+      uses: actions/checkout@v4
+      with:
+        submodules: recursive
+
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+      with:
+        repository: KhronosGroup/OpenCL-Headers
+        path: external/OpenCL-Headers
+
+    - name: Checkout OpenCL-ICD-Loader
+      uses: actions/checkout@v4
+      with:
+        repository: KhronosGroup/OpenCL-ICD-Loader
+        path: external/OpenCL-ICD-Loader
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
+    - name: Configure & install OpenCL-ICD-Loader
+      run:  cmake
+        -G "Unix Makefiles"
+        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install
+        -D BUILD_TESTING=ON
+        -D CMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake
+        -D ANDROID_ABI=${{matrix.ABI}}
+        -D ANDROID_PLATFORM=${{matrix.API_LEVEL}}
+        -D CMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY
+        -D CMAKE_FIND_ROOT_PATH=$GITHUB_WORKSPACE/external/OpenCL-Headers/install
+        -S $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader
+        -B $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build &&
+        sudo cmake
+        --build $GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/build
+        --target install
+        --
+        -j`nproc`
+
+    - name: Configure
+      run: cmake
+        -G "Unix Makefiles"
+        -D BUILD_TESTING=ON
+        -D BUILD_EXAMPLES=ON
+        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
+        -D CMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake
+        -D ANDROID_ABI=${{matrix.ABI}}
+        -D ANDROID_PLATFORM=${{matrix.API_LEVEL}}
+        -D CMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY
+        -D CMAKE_FIND_ROOT_PATH="$GITHUB_WORKSPACE/external/OpenCL-Headers/install;$GITHUB_WORKSPACE/external/OpenCL-ICD-Loader/install"
+        -S $GITHUB_WORKSPACE
+        -B $GITHUB_WORKSPACE/build
+
+    - name: Build
+      run: cmake --build $GITHUB_WORKSPACE/build -j `nproc`
diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
new file mode 100644
index 0000000..a39d9b0
--- /dev/null
+++ b/.github/workflows/release.yml
@@ -0,0 +1,76 @@
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
+      run: sudo apt-get update -qq && sudo apt-get install -y cmake devscripts debhelper-compat=13 opencl-c-headers doxygen
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
+        -S $GITHUB_WORKSPACE/OpenCL-CLHPP*
+        -B $GITHUB_WORKSPACE/../build
+        -D CMAKE_BUILD_TYPE=Release
+        -D CMAKE_INSTALL_PREFIX=/usr
+        -D BUILD_TESTING=OFF
+        -D BUILD_EXAMPLES=OFF
+        -D BUILD_DOCS=OFF
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
+        -P $GITHUB_WORKSPACE/OpenCL-CLHPP*/cmake/DebSourcePkg.cmake
+
+    - name: Build source package
+      run: |
+        cd $GITHUB_WORKSPACE/OpenCL-CLHPP*/
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
index fbcf6bf..0000000
--- a/.github/workflows/windows.yml
+++ /dev/null
@@ -1,213 +0,0 @@
-name: Windows
-
-on: [push, pull_request]
-
-jobs:
-  msvc:
-    runs-on: windows-2022
-    strategy:
-      matrix:
-        VER: [v141, v142, v143]
-        EXT: [ON] # OFF: error C2079: 'statbuf' uses undefined struct 'stat'
-        GEN: [Visual Studio 17 2022, Ninja Multi-Config]
-        BIN: [x64, x86]
-        STD: [11, 17]
-        CMAKE: [3.22.0]
-    env:
-      CMAKE_URL: https://github.com/Kitware/CMake/releases/download/v${{matrix.CMAKE}}/cmake-${{matrix.CMAKE}}-windows-x86_64.zip
-      CMAKE_EXE: C:\Tools\Kitware\CMake\${{matrix.CMAKE}}\bin\cmake.exe
-      CTEST_EXE: C:\Tools\Kitware\CMake\${{matrix.CMAKE}}\bin\ctest.exe
-      NINJA_URL: https://github.com/ninja-build/ninja/releases/download/v1.10.2/ninja-win.zip
-      NINJA_EXE: C:\Tools\Ninja\ninja.exe
-
-    steps:
-    - name: Checkout OpenCL-CLHPP
-      uses: actions/checkout@v3
-      with:
-        submodules: recursive
-
-    - name: Checkout OpenCL-Headers
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-Headers
-        path: external/OpenCL-Headers
-
-    - name: Checkout OpenCL-ICD-Loader
-      uses: actions/checkout@v3
-      with:
-        repository: KhronosGroup/OpenCL-ICD-Loader
-        path: external/OpenCL-ICD-Loader
-
-    - name: Create Build Environment
-      shell: pwsh
-      run: |
-        Invoke-WebRequest ${env:CMAKE_URL} -OutFile ~\Downloads\cmake-${{matrix.CMAKE}}-windows-x86_64.zip
-        Expand-Archive ~\Downloads\cmake-${{matrix.CMAKE}}-windows-x86_64.zip -DestinationPath C:\Tools\Kitware\CMake\
-        Rename-Item C:\Tools\Kitware\CMake\* ${{matrix.CMAKE}}
-        Invoke-WebRequest ${env:NINJA_URL} -OutFile ~\Downloads\ninja-win.zip
-        Expand-Archive ~\Downloads\ninja-win.zip -DestinationPath C:\Tools\Ninja\
-        Remove-Item ~\Downloads\*
-        & ${env:CMAKE_EXE} --version
-        & ${env:NINJA_EXE} --version
-
-    - name: Build & install OpenCL-Headers (MSBuild)
-      if: matrix.GEN == 'Visual Studio 17 2022'
-      shell: cmd
-      run: |
-        set C_FLAGS="/w"
-        if /I "${{matrix.BIN}}"=="x86" (set BIN=Win32) else (set BIN=x64)
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -A %BIN% -T ${{matrix.VER}} -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\external\OpenCL-Headers\install -D BUILD_TESTING=OFF -S %GITHUB_WORKSPACE%\external\OpenCL-Headers -B %GITHUB_WORKSPACE%\external\OpenCL-Headers\build
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/external/OpenCL-Headers/build --target install --config Release -- /verbosity:minimal /maxCpuCount /noLogo
-
-    - name: Build & install OpenCL-Headers (Ninja Multi-Config)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: cmd
-      run: |
-        set C_FLAGS="/w"
-        if /I "${{matrix.VER}}"=="v140" (set VER=14.0)
-        if /I "${{matrix.VER}}"=="v141" (set VER=14.1)
-        if /I "${{matrix.VER}}"=="v142" (set VER=14.2)
-        if /I "${{matrix.VER}}"=="v143" (set VER=14.3)
-        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" ${{matrix.BIN}} /vcvars_ver=%VER%
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_MAKE_PROGRAM=%NINJA_EXE% -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\external\OpenCL-Headers\install -D BUILD_TESTING=OFF -S %GITHUB_WORKSPACE%\external\OpenCL-Headers -B %GITHUB_WORKSPACE%\external\OpenCL-Headers\build
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/external/OpenCL-Headers/build --target install -- -j%NUMBER_OF_PROCESSORS%
-
-    - name: Build & install OpenCL-ICD-Loader (MSBuild)
-      if: matrix.GEN == 'Visual Studio 17 2022'
-      shell: cmd
-      run: |
-        set C_FLAGS="/w"
-        if /I "${{matrix.BIN}}"=="x86" (set BIN=Win32) else (set BIN=x64)
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -A %BIN% -T ${{matrix.VER}} -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\external\OpenCL-ICD-Loader\install -D CMAKE_PREFIX_PATH=%GITHUB_WORKSPACE%\external\OpenCL-Headers\install -D BUILD_TESTING=OFF -S %GITHUB_WORKSPACE%\external\OpenCL-ICD-Loader -B %GITHUB_WORKSPACE%\external\OpenCL-ICD-Loader\build
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/external/OpenCL-ICD-Loader/build --target install --config Release -- /verbosity:minimal /maxCpuCount /noLogo
-
-    - name: Build & install OpenCL-ICD-Loader (Ninja Multi-Config)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: cmd
-      run: |
-        set C_FLAGS="/w"
-        if /I "${{matrix.VER}}"=="v140" (set VER=14.0)
-        if /I "${{matrix.VER}}"=="v141" (set VER=14.1)
-        if /I "${{matrix.VER}}"=="v142" (set VER=14.2)
-        if /I "${{matrix.VER}}"=="v143" (set VER=14.3)
-        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" ${{matrix.BIN}} /vcvars_ver=%VER%
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_MAKE_PROGRAM=%NINJA_EXE% -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\external\OpenCL-ICD-Loader\install -D CMAKE_PREFIX_PATH=%GITHUB_WORKSPACE%\external\OpenCL-Headers\install -D BUILD_TESTING=OFF -S %GITHUB_WORKSPACE%\external\OpenCL-ICD-Loader -B %GITHUB_WORKSPACE%\external\OpenCL-ICD-Loader\build
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/external/OpenCL-ICD-Loader/build --target install --config Release -- -j%NUMBER_OF_PROCESSORS%
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
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -A %BIN% -T ${{matrix.VER}} -D BUILD_TESTING=ON -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH="%GITHUB_WORKSPACE%\external\OpenCL-Headers\install;%GITHUB_WORKSPACE%\external\OpenCL-ICD-Loader\install" -S %GITHUB_WORKSPACE% -B %GITHUB_WORKSPACE%\build
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
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_MAKE_PROGRAM=%NINJA_EXE% -D BUILD_TESTING=ON -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH="%GITHUB_WORKSPACE%\external\OpenCL-Headers\install;%GITHUB_WORKSPACE%\external\OpenCL-ICD-Loader\install" -S %GITHUB_WORKSPACE% -B %GITHUB_WORKSPACE%\build
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
-      continue-on-error: true
-      working-directory: ${{runner.workspace}}/OpenCL-CLHPP/build
-      shell: cmd
-      run: |
-        %CTEST_EXE% -C Release --output-on-failure --parallel %NUMBER_OF_PROCESSORS%
-        %CTEST_EXE% -C Debug --output-on-failure --parallel %NUMBER_OF_PROCESSORS%
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
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH="%GITHUB_WORKSPACE%\external\OpenCL-Headers\install;%GITHUB_WORKSPACE%\install" -D DRIVER_STUB_PATH=%GITHUB_WORKSPACE%/build/Release/OpenCLDriverStub.dll -B %GITHUB_WORKSPACE%/build/downstream/bare -S %GITHUB_WORKSPACE%/tests/pkgconfig/bare
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/tests/pkgconfig/bare --config Release
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/tests/pkgconfig/bare --config Debug
-        cd %GITHUB_WORKSPACE%/tests/pkgconfig/bare
-        %CTEST_EXE% --output-on-failure -C Release
-        %CTEST_EXE% --output-on-failure -C Debug
-
-    - name: "Consume (MSBuild SDK): Configure/Build/Test"
-      shell: cmd
-      run: |
-        set C_FLAGS="/W4"
-        if /I "${{matrix.BIN}}"=="x86" (set BIN=Win32) else (set BIN=x64)
-        %CMAKE_EXE% -E make_directory $GITHUB_WORKSPACE/install/share/cmake/OpenCL
-        echo -e 'include("/home/runner/work/OpenCL-CLHPP/OpenCL-CLHPP/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake")\ninclude("/home/runner/work/OpenCL-CLHPP/OpenCL-CLHPP/external/OpenCL-ICD-Loader/install/share/cmake/OpenCLICDLoader/OpenCLICDLoaderTargets.cmake")\ninclude("${CMAKE_CURRENT_LIST_DIR}/../OpenCLHeadersCpp/OpenCLHeadersCppTargets.cmake")' > $GITHUB_WORKSPACE/install/share/cmake/OpenCL/OpenCLConfig.cmake
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH="%GITHUB_WORKSPACE%\external\OpenCL-Headers\install;%GITHUB_WORKSPACE%\install" -D DRIVER_STUB_PATH=%GITHUB_WORKSPACE%/build/Release/OpenCLDriverStub.dll -B %GITHUB_WORKSPACE%/build/downstream/bare -S %GITHUB_WORKSPACE%/tests/pkgconfig/bare
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/tests/pkgconfig/bare --config Release
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/tests/pkgconfig/bare --config Debug
-        cd %GITHUB_WORKSPACE%/tests/pkgconfig/bare
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
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_MAKE_PROGRAM=%NINJA_EXE% -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH="%GITHUB_WORKSPACE%\external\OpenCL-Headers\install;%GITHUB_WORKSPACE%\install" -D DRIVER_STUB_PATH=%GITHUB_WORKSPACE%/build/Release/OpenCLDriverStub.dll -B %GITHUB_WORKSPACE%/build/downstream/bare -S %GITHUB_WORKSPACE%/tests/pkgconfig/bare
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/tests/pkgconfig/bare --config Release
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/tests/pkgconfig/bare --config Debug
-        cd %GITHUB_WORKSPACE%/tests/pkgconfig/bare
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
-        echo -e 'include("/home/runner/work/OpenCL-CLHPP/OpenCL-CLHPP/external/OpenCL-Headers/install/share/cmake/OpenCLHeaders/OpenCLHeadersTargets.cmake")\ninclude("/home/runner/work/OpenCL-CLHPP/OpenCL-CLHPP/external/OpenCL-ICD-Loader/install/share/cmake/OpenCLICDLoader/OpenCLICDLoaderTargets.cmake")\ninclude("${CMAKE_CURRENT_LIST_DIR}/../OpenCLHeadersCpp/OpenCLHeadersCppTargets.cmake")' > $GITHUB_WORKSPACE/install/share/cmake/OpenCL/OpenCLConfig.cmake
-        %CMAKE_EXE% -G "${{matrix.GEN}}" -D CMAKE_MAKE_PROGRAM=%NINJA_EXE% -D CMAKE_C_FLAGS=%C_FLAGS% -D CMAKE_C_STANDARD=${{matrix.STD}} -D CMAKE_C_EXTENSIONS=${{matrix.EXT}} -D CMAKE_EXE_LINKER_FLAGS=/INCREMENTAL -D CMAKE_INSTALL_PREFIX=%GITHUB_WORKSPACE%\install -D CMAKE_PREFIX_PATH="%GITHUB_WORKSPACE%\external\OpenCL-Headers\install;%GITHUB_WORKSPACE%\install" -D DRIVER_STUB_PATH=%GITHUB_WORKSPACE%/build/Release/OpenCLDriverStub.dll -B %GITHUB_WORKSPACE%/build/downstream/bare -S %GITHUB_WORKSPACE%/tests/pkgconfig/bare
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/tests/pkgconfig/bare --config Release
-        %CMAKE_EXE% --build %GITHUB_WORKSPACE%/tests/pkgconfig/bare --config Debug
-        cd %GITHUB_WORKSPACE%/tests/pkgconfig/bare
-        %CTEST_EXE% --output-on-failure -C Release
-        %CTEST_EXE% --output-on-failure -C Debug
diff --git a/.gitignore b/.gitignore
new file mode 100644
index 0000000..2ba6960
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1,14 @@
+# Build dir
+[Bb]uild/
+
+# Install dir
+[Ii]nstall/
+
+# Package dir
+[Pp]ackage[-_\s\d]*/
+
+# External dir
+[Ee]xternal/
+
+# Visual Studio Code
+.vscode
diff --git a/.gitmodules b/.gitmodules
deleted file mode 100644
index d51ccbf..0000000
--- a/.gitmodules
+++ /dev/null
@@ -1,3 +0,0 @@
-[submodule "external/CMock"]
-	path = external/CMock
-	url = https://github.com/ThrowTheSwitch/CMock
diff --git a/CMakeLists.txt b/CMakeLists.txt
index b9689cc..138d3dd 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required(VERSION 3.1)
+cmake_minimum_required(VERSION 3.16)
 
 project(OpenCLHeadersCpp
   VERSION 3.0
@@ -73,10 +73,11 @@ install(
   EXPORT OpenCLHeadersCppTargets
 )
 
+include(GNUInstallDirs)
+
 set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
 include(JoinPaths)
-
-include(GNUInstallDirs)
+include(Package)
 
 install(
   DIRECTORY include/CL
@@ -130,11 +131,3 @@ endif(BUILD_EXAMPLES)
 if(CLHPP_BUILD_TESTS)
   add_subdirectory(tests)
 endif(CLHPP_BUILD_TESTS)
-
-join_paths(OPENCLHPP_INCLUDEDIR_PC "\${prefix}" "${CMAKE_INSTALL_INCLUDEDIR}")
-
-configure_file(OpenCL-CLHPP.pc.in OpenCL-CLHPP.pc @ONLY)
-set(pkg_config_location ${CMAKE_INSTALL_DATADIR}/pkgconfig)
-install(
-  FILES ${CMAKE_CURRENT_BINARY_DIR}/OpenCL-CLHPP.pc
-  DESTINATION ${pkg_config_location})
diff --git a/METADATA b/METADATA
index c695e5d..1fbff0d 100644
--- a/METADATA
+++ b/METADATA
@@ -1,15 +1,21 @@
-name: "OpenCL-ICD-Loader"
-description:
-    "OpenCL API C++ bindings"
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/OpenCL-CLHPP
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "OpenCL-CLHPP"
+description: "OpenCL API C++ bindings"
 third_party {
-homepage: "https://github.com/KhronosGroup/OpenCL-CLHPP"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 4
+    day: 24
+  }
+  homepage: "https://github.com/KhronosGroup/OpenCL-CLHPP"
   identifier {
     type: "Archive"
     value: "https://github.com/KhronosGroup/OpenCL-CLHPP"
+    version: "v2024.10.24"
     primary_source: true
   }
-  version: "v2023.12.14"
-  last_upgrade_date { year: 2024 month: 5 day: 20 }
-  license_type: NOTICE
 }
diff --git a/OpenCL-CLHPP.pc.in b/OpenCL-CLHPP.pc.in
index 763bd1c..5d4a07b 100644
--- a/OpenCL-CLHPP.pc.in
+++ b/OpenCL-CLHPP.pc.in
@@ -1,4 +1,4 @@
-prefix=@CMAKE_INSTALL_PREFIX@
+prefix=@PKGCONFIG_PREFIX@
 includedir=@OPENCLHPP_INCLUDEDIR_PC@
 
 Name: OpenCL-CLHPP
diff --git a/cmake/DebSourcePkg.cmake b/cmake/DebSourcePkg.cmake
new file mode 100644
index 0000000..556ded4
--- /dev/null
+++ b/cmake/DebSourcePkg.cmake
@@ -0,0 +1,151 @@
+# This script produces the changelog, control and rules file in the debian
+# directory. These files are needed to build a Debian source package from the repository.
+# Run this in CMake script mode, e.g.
+# $ cd OpenCL-CLHPP
+# $ cmake -S . -B ../build -D BUILD_TESTING=OFF -D BUILD_EXAMPLES=OFF -D BUILD_DOCS=OFF
+# $ cmake
+#    -DCMAKE_CACHE_PATH=../build/CMakeCache.txt
+#    -DCPACK_DEBIAN_PACKAGE_MAINTAINER="Example Name <example@example.com>"
+#    -DDEBIAN_DISTROSERIES=jammy
+#    -DORIG_ARCHIVE=../OpenCL-Headers.tar.gz
+#    -DLATEST_RELEASE_VERSION=v2023.08.29
+#    -P cmake/DebSourcePkg.cmake
+# $ debuild -S -sa
+
+cmake_minimum_required(VERSION 3.21) # file(COPY_FILE) is added in CMake 3.21
+
+set(DEB_SOURCE_PKG_NAME "khronos-opencl-clhpp")
+set(DEB_C_HEADERS_PKG_NAME "opencl-c-headers")
+set(DEB_META_PKG_NAME "opencl-headers")
+set(DEB_DOC_PKG_NAME "opencl-clhpp-headers-doc")
+set(DEB_DOC_PKG_DESCRIPTION "documentation for C++ OpenCL headers
+ OpenCL (Open Computing Language) is a multi-vendor open standard for
+ general-purpose parallel programming of heterogeneous systems that include
+ CPUs, GPUs and other processors.
+ .
+ This package provides the documentation of the C++ development header files
+ for the OpenCL API as published by The Khronos Group Inc.
+")
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
+# PackageSetup.cmake contains details for packaging
+include(PackageSetup)
+
+# Append a space after every newline in the description. This format is required
+# in the control file.
+string(REPLACE "\n" "\n " CPACK_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION}")
+
+set(DEB_SOURCE_PKG_DIR "${CMAKE_CURRENT_LIST_DIR}/../debian")
+# Write debian/control
+file(WRITE "${DEB_SOURCE_PKG_DIR}/control"
+"Source: ${DEB_SOURCE_PKG_NAME}
+Section: ${CPACK_DEBIAN_PACKAGE_SECTION}
+Priority: optional
+Maintainer: ${DEBIAN_PACKAGE_MAINTAINER}
+Build-Depends: cmake, debhelper-compat (=13), doxygen, ${CPACK_DEBIAN_PACKAGE_DEPENDS}
+Rules-Requires-Root: no
+Homepage: ${CPACK_DEBIAN_PACKAGE_HOMEPAGE}
+Standards-Version: 4.6.2
+
+Package: ${DEBIAN_PACKAGE_NAME}
+Architecture: ${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}
+Multi-Arch: foreign
+Depends: ${CPACK_DEBIAN_PACKAGE_DEPENDS}
+Breaks: ${CPACK_DEBIAN_PACKAGE_BREAKS}
+Replaces: ${CPACK_DEBIAN_PACKAGE_REPLACES}
+Description: ${CPACK_PACKAGE_DESCRIPTION}
+
+Package: ${DEB_DOC_PKG_NAME}
+Section: doc
+Architecture: all
+Multi-Arch: foreign
+Description: ${DEB_DOC_PKG_DESCRIPTION}
+"
+)
+# Write debian/changelog
+string(TIMESTAMP CURRENT_TIMESTAMP "%a, %d %b %Y %H:%M:%S +0000" UTC)
+file(WRITE "${DEB_SOURCE_PKG_DIR}/changelog"
+"${DEB_SOURCE_PKG_NAME} (${PACKAGE_VERSION_REVISION}) ${DEBIAN_DISTROSERIES}; urgency=medium
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
+\tdh_auto_configure -- -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DBUILD_EXAMPLES=OFF
+
+override_dh_auto_build:
+\tdh_auto_build -- all docs
+")
+# Write installed file list for headers package
+file(WRITE "${DEB_SOURCE_PKG_DIR}/${DEBIAN_PACKAGE_NAME}.install"
+"usr/include
+usr/share
+"
+)
+# Write installed file list for docs package
+file(WRITE "${DEB_SOURCE_PKG_DIR}/${DEB_DOC_PKG_NAME}.install"
+"obj-*/docs/html   usr/share/doc/opencl-clhpp-headers/
+"
+)
+# Write doc base file
+file(WRITE "${DEB_SOURCE_PKG_DIR}/${DEB_DOC_PKG_NAME}.doc-base"
+"Document: ${DEBIAN_PACKAGE_NAME}
+Title: OpenCL C++ Bindings Documentation
+Author: The Khronos Group Inc.
+Abstract: This manual describes the OpenCL C++ Bindings
+ as provided by The Khronos Group Inc.
+Section: Programming/C++
+
+Format: HTML
+Index: /usr/share/doc/${DEBIAN_PACKAGE_NAME}/html/index.html
+Files: /usr/share/doc/${DEBIAN_PACKAGE_NAME}/html/*.html
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
+    set(TARGET_PATH "${ORIG_ARCHIVE_PARENT}/${DEB_SOURCE_PKG_NAME}_${CPACK_DEBIAN_PACKAGE_VERSION}${ORIG_ARCHIVE_EXT}")
+    message(STATUS "Copying \"${ORIG_ARCHIVE}\" to \"${TARGET_PATH}\"")
+    file(COPY_FILE "${ORIG_ARCHIVE}" "${TARGET_PATH}")
+endif()
diff --git a/cmake/Package.cmake b/cmake/Package.cmake
new file mode 100644
index 0000000..5b8a34e
--- /dev/null
+++ b/cmake/Package.cmake
@@ -0,0 +1,47 @@
+include("${CMAKE_CURRENT_LIST_DIR}/PackageSetup.cmake")
+
+# Configuring pkgconfig
+
+# We need two different instances of OpenCL.pc
+# One for installing (cmake --install), which contains CMAKE_INSTALL_PREFIX as prefix
+# And another for the Debian development package, which contains CPACK_PACKAGING_INSTALL_PREFIX as prefix
+
+join_paths(OPENCLHPP_INCLUDEDIR_PC "\${prefix}" "${CMAKE_INSTALL_INCLUDEDIR}")
+
+set(pkg_config_location ${CMAKE_INSTALL_DATADIR}/pkgconfig)
+set(PKGCONFIG_PREFIX "${CMAKE_INSTALL_PREFIX}")
+configure_file(
+  OpenCL-CLHPP.pc.in
+  ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_install/OpenCL-CLHPP.pc
+  @ONLY)
+install(
+  FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_install/OpenCL-CLHPP.pc
+  DESTINATION ${pkg_config_location}
+  COMPONENT pkgconfig_install)
+
+set(PKGCONFIG_PREFIX "${CPACK_PACKAGING_INSTALL_PREFIX}")
+configure_file(
+  OpenCL-CLHPP.pc.in
+  ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_package/OpenCL-CLHPP.pc
+  @ONLY)
+# This install component is only needed in the Debian package
+install(
+  FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_package/OpenCL-CLHPP.pc
+  DESTINATION ${pkg_config_location}
+  COMPONENT pkgconfig_package
+  EXCLUDE_FROM_ALL)
+
+# By using component based packaging, component pkgconfig_install
+# can be excluded from the package, and component pkgconfig_package
+# can be included.
+set(CPACK_DEB_COMPONENT_INSTALL ON)
+set(CPACK_COMPONENTS_GROUPING "ALL_COMPONENTS_IN_ONE")
+
+include(CPackComponent)
+cpack_add_component(pkgconfig_install)
+cpack_add_component(pkgconfig_package)
+set(CPACK_COMPONENTS_ALL "Unspecified;pkgconfig_package")
+
+set(CPACK_DEBIAN_PACKAGE_DEBUG ON)
+
+include(CPack)
diff --git a/cmake/PackageSetup.cmake b/cmake/PackageSetup.cmake
new file mode 100644
index 0000000..eeee21b
--- /dev/null
+++ b/cmake/PackageSetup.cmake
@@ -0,0 +1,56 @@
+set(CPACK_PACKAGE_VENDOR "khronos")
+
+set(CPACK_PACKAGE_DESCRIPTION "C++ headers for OpenCL development
+C++ headers for OpenCL development
+OpenCL (Open Computing Language) is a multi-vendor open standard for
+general-purpose parallel programming of heterogeneous systems that include
+CPUs, GPUs and other processors.
+.
+This package provides the C++ development header files for the OpenCL API
+as published by The Khronos Group Inc. The corresponding specification and
+documentation can be found on the Khronos website.")
+
+set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt")
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
+    "https://github.com/KhronosGroup/OpenCL-CLHPP")
+
+set(CPACK_DEBIAN_PACKAGE_VERSION "${PROJECT_VERSION}")
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
+set(CPACK_DEBIAN_PACKAGE_RELEASE "1") # debian_revision (because this is a non-native pkg)
+set(PACKAGE_VERSION_REVISION "${CPACK_DEBIAN_PACKAGE_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}${DEBIAN_VERSION_SUFFIX}")
+
+set(DEBIAN_PACKAGE_NAME "opencl-clhpp-headers")
+set(CPACK_DEBIAN_PACKAGE_NAME
+    "${DEBIAN_PACKAGE_NAME}"
+    CACHE STRING "Package name" FORCE)
+
+set(CPACK_DEBIAN_PACKAGE_SECTION "libdevel")
+set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "all")
+
+# Dependencies
+set(CPACK_DEBIAN_PACKAGE_DEPENDS "opencl-c-headers (>= ${CPACK_DEBIAN_PACKAGE_VERSION})")
+set(CPACK_DEBIAN_PACKAGE_BREAKS "opencl-headers (<< ${CPACK_DEBIAN_PACKAGE_VERSION})")
+set(CPACK_DEBIAN_PACKAGE_REPLACES "opencl-headers (<< ${CPACK_DEBIAN_PACKAGE_VERSION})")
+
+# Package file name in deb format:
+# <PackageName>_<VersionNumber>-<DebianRevisionNumber>_<DebianArchitecture>.deb
+set(CPACK_DEBIAN_FILE_NAME "${DEBIAN_PACKAGE_NAME}_${PACKAGE_VERSION_REVISION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}.deb")
diff --git a/examples/CMakeLists.txt b/examples/CMakeLists.txt
index 99df70e..27e4941 100644
--- a/examples/CMakeLists.txt
+++ b/examples/CMakeLists.txt
@@ -1,3 +1 @@
-cmake_minimum_required(VERSION 3.0)
-
 add_subdirectory(src)
diff --git a/include/CL/opencl.hpp b/include/CL/opencl.hpp
index ac0d415..600d5f7 100644
--- a/include/CL/opencl.hpp
+++ b/include/CL/opencl.hpp
@@ -1,5 +1,5 @@
 //
-// Copyright (c) 2008-2023 The Khronos Group Inc.
+// Copyright (c) 2008-2024 The Khronos Group Inc.
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -1143,7 +1143,6 @@ inline cl_int getInfoHelper(Func f, cl_uint name, vector<vector<unsigned char>>*
         }
     }
 
-
     return CL_SUCCESS;
 }
 
@@ -1562,9 +1561,6 @@ inline cl_int getInfoHelper(Func f, cl_uint name, T* param, int, typename T::cl_
     F(cl_device_info, CL_DEVICE_SEMAPHORE_EXPORT_HANDLE_TYPES_KHR,      cl::vector<cl_external_semaphore_handle_type_khr>) \
     F(cl_semaphore_info_khr, CL_SEMAPHORE_EXPORT_HANDLE_TYPES_KHR,      cl::vector<cl_external_semaphore_handle_type_khr>) \
 
-#define CL_HPP_PARAM_NAME_CL_KHR_EXTERNAL_SEMAPHORE_DX_FENCE_EXT(F) \
-    F(cl_external_semaphore_handle_type_khr, CL_SEMAPHORE_HANDLE_D3D12_FENCE_KHR, void*) \
-
 #define CL_HPP_PARAM_NAME_CL_KHR_EXTERNAL_SEMAPHORE_OPAQUE_FD_EXT(F) \
     F(cl_external_semaphore_handle_type_khr, CL_SEMAPHORE_HANDLE_OPAQUE_FD_KHR, int) \
 
@@ -1612,6 +1608,19 @@ inline cl_int getInfoHelper(Func f, cl_uint name, T* param, int, typename T::cl_
 #define CL_HPP_PARAM_NAME_CL_IMAGE_REQUIREMENTS_SLICE_PITCH_ALIGNMENT_EXT(F) \
     F(cl_image_requirements_info_ext, CL_IMAGE_REQUIREMENTS_SLICE_PITCH_ALIGNMENT_EXT, size_type) \
 
+#define CL_HPP_PARAM_NAME_CL_INTEL_COMMAND_QUEUE_FAMILIES_(F) \
+    F(cl_device_info, CL_DEVICE_QUEUE_FAMILY_PROPERTIES_INTEL, cl::vector<cl_queue_family_properties_intel>) \
+    \
+    F(cl_command_queue_info, CL_QUEUE_FAMILY_INTEL, cl_uint) \
+    F(cl_command_queue_info, CL_QUEUE_INDEX_INTEL, cl_uint)
+
+#define CL_HPP_PARAM_NAME_CL_INTEL_UNIFIED_SHARED_MEMORY_(F) \
+    F(cl_device_info, CL_DEVICE_HOST_MEM_CAPABILITIES_INTEL, cl_device_unified_shared_memory_capabilities_intel ) \
+    F(cl_device_info, CL_DEVICE_DEVICE_MEM_CAPABILITIES_INTEL, cl_device_unified_shared_memory_capabilities_intel ) \
+    F(cl_device_info, CL_DEVICE_SINGLE_DEVICE_SHARED_MEM_CAPABILITIES_INTEL, cl_device_unified_shared_memory_capabilities_intel ) \
+    F(cl_device_info, CL_DEVICE_CROSS_DEVICE_SHARED_MEM_CAPABILITIES_INTEL, cl_device_unified_shared_memory_capabilities_intel ) \
+    F(cl_device_info, CL_DEVICE_SHARED_SYSTEM_MEM_CAPABILITIES_INTEL, cl_device_unified_shared_memory_capabilities_intel )
+
 template <typename enum_type, cl_int Name>
 struct param_traits {};
 
@@ -1701,9 +1710,6 @@ CL_HPP_PARAM_NAME_CL_KHR_EXTERNAL_MEMORY_(CL_HPP_DECLARE_PARAM_TRAITS_)
 CL_HPP_PARAM_NAME_CL_KHR_EXTERNAL_SEMAPHORE_(CL_HPP_DECLARE_PARAM_TRAITS_)
 #endif // cl_khr_external_semaphore
 
-#if defined(cl_khr_external_semaphore_dx_fence)
-CL_HPP_PARAM_NAME_CL_KHR_EXTERNAL_SEMAPHORE_DX_FENCE_EXT(CL_HPP_DECLARE_PARAM_TRAITS_)
-#endif // cl_khr_external_semaphore_dx_fence
 #if defined(cl_khr_external_semaphore_opaque_fd)
 CL_HPP_PARAM_NAME_CL_KHR_EXTERNAL_SEMAPHORE_OPAQUE_FD_EXT(CL_HPP_DECLARE_PARAM_TRAITS_)
 #endif // cl_khr_external_semaphore_opaque_fd
@@ -1850,7 +1856,7 @@ CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_INTEGRATED_MEMORY_NV, cl_
 
 #if defined(cl_khr_command_buffer)
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_COMMAND_BUFFER_CAPABILITIES_KHR, cl_device_command_buffer_capabilities_khr)
-CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_COMMAND_BUFFER_REQUIRED_QUEUE_PROPERTIES_KHR, cl_command_buffer_properties_khr)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_COMMAND_BUFFER_REQUIRED_QUEUE_PROPERTIES_KHR, cl_command_queue_properties)
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_command_buffer_info_khr, CL_COMMAND_BUFFER_QUEUES_KHR, cl::vector<CommandQueue>)
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_command_buffer_info_khr, CL_COMMAND_BUFFER_NUM_QUEUES_KHR, cl_uint)
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_command_buffer_info_khr, CL_COMMAND_BUFFER_REFERENCE_COUNT_KHR, cl_uint)
@@ -1862,7 +1868,12 @@ CL_HPP_DECLARE_PARAM_TRAITS_(cl_command_buffer_info_khr, CL_COMMAND_BUFFER_PROPE
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_mutable_command_info_khr, CL_MUTABLE_COMMAND_COMMAND_QUEUE_KHR, CommandQueue)
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_mutable_command_info_khr, CL_MUTABLE_COMMAND_COMMAND_BUFFER_KHR, CommandBufferKhr)
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_mutable_command_info_khr, CL_MUTABLE_COMMAND_COMMAND_TYPE_KHR, cl_command_type)
+
+#if CL_KHR_COMMAND_BUFFER_MUTABLE_DISPATCH_EXTENSION_VERSION > CL_MAKE_VERSION(0, 9, 2)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_mutable_command_info_khr, CL_MUTABLE_COMMAND_PROPERTIES_ARRAY_KHR, cl::vector<cl_command_properties_khr>)
+#else
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_mutable_command_info_khr, CL_MUTABLE_DISPATCH_PROPERTIES_ARRAY_KHR, cl::vector<cl_ndrange_kernel_command_properties_khr>)
+#endif
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_mutable_command_info_khr, CL_MUTABLE_DISPATCH_KERNEL_KHR, cl_kernel)
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_mutable_command_info_khr, CL_MUTABLE_DISPATCH_DIMENSIONS_KHR, cl_uint)
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_mutable_command_info_khr, CL_MUTABLE_DISPATCH_GLOBAL_WORK_OFFSET_KHR, cl::vector<size_type>)
@@ -1870,6 +1881,39 @@ CL_HPP_DECLARE_PARAM_TRAITS_(cl_mutable_command_info_khr, CL_MUTABLE_DISPATCH_GL
 CL_HPP_DECLARE_PARAM_TRAITS_(cl_mutable_command_info_khr, CL_MUTABLE_DISPATCH_LOCAL_WORK_SIZE_KHR, cl::vector<size_type>)
 #endif /* cl_khr_command_buffer_mutable_dispatch */
 
+#if defined(cl_khr_kernel_clock)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_KERNEL_CLOCK_CAPABILITIES_KHR, cl_device_kernel_clock_capabilities_khr)
+#endif /* cl_khr_kernel_clock */
+
+#if defined(cl_ext_float_atomics)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_SINGLE_FP_ATOMIC_CAPABILITIES_EXT, cl_device_fp_atomic_capabilities_ext)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_DOUBLE_FP_ATOMIC_CAPABILITIES_EXT, cl_device_fp_atomic_capabilities_ext)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_HALF_FP_ATOMIC_CAPABILITIES_EXT, cl_device_fp_atomic_capabilities_ext)
+#endif /* cl_ext_float_atomics */
+
+#if defined(cl_intel_command_queue_families)
+CL_HPP_PARAM_NAME_CL_INTEL_COMMAND_QUEUE_FAMILIES_(CL_HPP_DECLARE_PARAM_TRAITS_)
+#endif // cl_intel_command_queue_families
+
+#if defined(cl_intel_device_attribute_query)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_IP_VERSION_INTEL, cl_uint)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_ID_INTEL, cl_uint)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_NUM_SLICES_INTEL, cl_uint)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_NUM_SUB_SLICES_PER_SLICE_INTEL, cl_uint)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_NUM_EUS_PER_SUB_SLICE_INTEL, cl_uint)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_NUM_THREADS_PER_EU_INTEL, cl_uint)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_FEATURE_CAPABILITIES_INTEL, cl_device_feature_capabilities_intel)
+#endif // cl_intel_device_attribute_query
+
+#if defined(cl_intel_required_subgroup_size)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_device_info, CL_DEVICE_SUB_GROUP_SIZES_INTEL, cl::vector<size_type>)
+CL_HPP_DECLARE_PARAM_TRAITS_(cl_kernel_work_group_info, CL_KERNEL_SPILL_MEM_SIZE_INTEL, cl_ulong)
+#endif // cl_intel_required_subgroup_size
+
+#if defined(cl_intel_unified_shared_memory)
+CL_HPP_PARAM_NAME_CL_INTEL_UNIFIED_SHARED_MEMORY_(CL_HPP_DECLARE_PARAM_TRAITS_)
+#endif // cl_intel_unified_shared_memory
+
 // Convenience functions
 
 template <typename Func, typename T>
@@ -2095,7 +2139,8 @@ struct ReferenceHandler<cl_mutable_command_khr>
 #endif // cl_khr_command_buffer
 
 
-#if CL_HPP_TARGET_OPENCL_VERSION >= 120 && CL_HPP_MINIMUM_OPENCL_VERSION < 200
+#if (CL_HPP_TARGET_OPENCL_VERSION >= 120 && CL_HPP_MINIMUM_OPENCL_VERSION < 120) || \
+    (CL_HPP_TARGET_OPENCL_VERSION >= 200 && CL_HPP_MINIMUM_OPENCL_VERSION < 200)
 // Extracts version number with major in the upper 16 bits, minor in the lower 16
 static cl_uint getVersion(const vector<char> &versionInfo)
 {
@@ -2145,7 +2190,7 @@ static cl_uint getContextPlatformVersion(cl_context context)
     clGetContextInfo(context, CL_CONTEXT_DEVICES, size, devices.data(), nullptr);
     return getDevicePlatformVersion(devices[0]);
 }
-#endif // CL_HPP_TARGET_OPENCL_VERSION >= 120 && CL_HPP_MINIMUM_OPENCL_VERSION < 200
+#endif // CL_HPP_TARGET_OPENCL_VERSION && CL_HPP_MINIMUM_OPENCL_VERSION
 
 template <typename T>
 class Wrapper
@@ -2254,18 +2299,16 @@ protected:
     static bool isReferenceCountable(cl_device_id device)
     {
         bool retVal = false;
-#if CL_HPP_TARGET_OPENCL_VERSION >= 120
-#if CL_HPP_MINIMUM_OPENCL_VERSION < 120
+#if CL_HPP_TARGET_OPENCL_VERSION >= 120 && CL_HPP_MINIMUM_OPENCL_VERSION < 120
         if (device != nullptr) {
             int version = getDevicePlatformVersion(device);
             if(version > ((1 << 16) + 1)) {
                 retVal = true;
             }
         }
-#else // CL_HPP_MINIMUM_OPENCL_VERSION < 120
+#elif CL_HPP_TARGET_OPENCL_VERSION >= 120
         retVal = true;
-#endif // CL_HPP_MINIMUM_OPENCL_VERSION < 120
-#endif // CL_HPP_TARGET_OPENCL_VERSION >= 120
+#endif // CL_HPP_TARGET_OPENCL_VERSION
         (void)device;
         return retVal;
     }
@@ -3204,10 +3247,10 @@ private:
 #if defined(cl_ext_image_requirements_info)
     struct ImageRequirementsInfo {
 
-        ImageRequirementsInfo(cl_mem_flags f, const cl_mem_properties* properties, const ImageFormat* format, const cl_image_desc* desc)
+        ImageRequirementsInfo(cl_mem_flags f, const cl_mem_properties* mem_properties, const ImageFormat* format, const cl_image_desc* desc)
         {
             flags = f;
-            properties = properties;
+            properties = mem_properties;
             image_format = format;
             image_desc = desc;
         }
@@ -4227,10 +4270,18 @@ cl::pointer<T, detail::Deleter<Alloc>> allocate_pointer(const Alloc &alloc_, Arg
 
     T* tmp = std::allocator_traits<Alloc>::allocate(alloc, copies);
     if (!tmp) {
+#if defined(CL_HPP_ENABLE_EXCEPTIONS)
         std::bad_alloc excep;
         throw excep;
+#else
+        return nullptr;
+#endif
     }
-    try {
+
+#if defined(CL_HPP_ENABLE_EXCEPTIONS)
+    try
+#endif
+    {
         std::allocator_traits<Alloc>::construct(
             alloc,
             std::addressof(*tmp),
@@ -4238,11 +4289,13 @@ cl::pointer<T, detail::Deleter<Alloc>> allocate_pointer(const Alloc &alloc_, Arg
 
         return cl::pointer<T, detail::Deleter<Alloc>>(tmp, detail::Deleter<Alloc>{alloc, copies});
     }
+#if defined(CL_HPP_ENABLE_EXCEPTIONS)
     catch (std::bad_alloc&)
     {
         std::allocator_traits<Alloc>::deallocate(alloc, tmp, copies);
         throw;
     }
+#endif
 }
 
 template< class T, class SVMTrait, class... Args >
@@ -4834,6 +4887,42 @@ public:
     //! \brief Default constructor - initializes to nullptr.
     Image1D() { }
 
+#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+    /*! \brief Constructs a Image1D with specified properties.
+     *
+     *  Wraps clCreateImageWithProperties().
+     *
+     *  \param properties Optional list of properties for the image object and
+     *                    their corresponding values. The non-empty list must
+     *                    end with 0.
+     *  \param host_ptr Storage to be used if the CL_MEM_USE_HOST_PTR flag was
+     *                  specified. Note alignment & exclusivity requirements.
+     */
+    Image1D(const Context &context, const vector<cl_mem_properties> &properties,
+            cl_mem_flags flags, ImageFormat format, size_type width,
+            void *host_ptr = nullptr, cl_int *err = nullptr) {
+      cl_int error;
+
+      cl_image_desc desc = {};
+      desc.image_type = CL_MEM_OBJECT_IMAGE1D;
+      desc.image_width = width;
+
+      if (properties.empty()) {
+        object_ = ::clCreateImageWithProperties(
+            context(), nullptr, flags, &format, &desc, host_ptr, &error);
+      } else {
+        object_ =
+            ::clCreateImageWithProperties(context(), properties.data(), flags,
+                                          &format, &desc, host_ptr, &error);
+      }
+
+      detail::errHandler(error, __CREATE_IMAGE_ERR);
+      if (err != nullptr) {
+        *err = error;
+      }
+    }
+#endif //#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+
     /*! \brief Constructor from cl_mem - takes ownership.
      *
      * \param retainObject will cause the constructor to retain its cl object.
@@ -4894,6 +4983,43 @@ public:
 
     Image1DBuffer() { }
 
+#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+    /*! \brief Constructs a Image1DBuffer with specified properties.
+     *
+     *  Wraps clCreateImageWithProperties().
+     *
+     *  \param properties Optional list of properties for the image object and
+     *                    their corresponding values. The non-empty list must
+     *                    end with 0.
+     *  \param buffer Refer to a valid buffer or image memory object.
+     */
+    Image1DBuffer(const Context &context,
+                  const vector<cl_mem_properties> &properties,
+                  cl_mem_flags flags, ImageFormat format, size_type width,
+                  const Buffer &buffer, cl_int *err = nullptr) {
+      cl_int error;
+
+      cl_image_desc desc = {};
+      desc.image_type = CL_MEM_OBJECT_IMAGE1D_BUFFER;
+      desc.image_width = width;
+      desc.buffer = buffer();
+
+      if (properties.empty()) {
+        object_ = ::clCreateImageWithProperties(
+            context(), nullptr, flags, &format, &desc, nullptr, &error);
+      } else {
+        object_ =
+            ::clCreateImageWithProperties(context(), properties.data(), flags,
+                                          &format, &desc, nullptr, &error);
+      }
+
+      detail::errHandler(error, __CREATE_IMAGE_ERR);
+      if (err != nullptr) {
+        *err = error;
+      }
+    }
+#endif //#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+
     /*! \brief Constructor from cl_mem - takes ownership.
      *
      * \param retainObject will cause the constructor to retain its cl object.
@@ -4909,9 +5035,6 @@ public:
         Image::operator=(rhs);
         return *this;
     }
-
-
-
 };
 
 /*! \class Image1DArray
@@ -4953,7 +5076,47 @@ public:
     }
 
     Image1DArray() { }
-  
+
+#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+    /*! \brief Constructs a Image1DArray with specified properties.
+     *
+     *  Wraps clCreateImageWithProperties().
+     *
+     *  \param properties Optional list of properties for the image object and
+     *                    their corresponding values. The non-empty list must
+     *                    end with 0.
+     *  \param host_ptr Storage to be used if the CL_MEM_USE_HOST_PTR flag was
+     *                  specified. Note alignment & exclusivity requirements.
+     */
+    Image1DArray(const Context &context,
+                 const vector<cl_mem_properties> &properties,
+                 cl_mem_flags flags, ImageFormat format, size_type arraySize,
+                 size_type width, size_type rowPitch = 0,
+                 void *host_ptr = nullptr, cl_int *err = nullptr) {
+      cl_int error;
+
+      cl_image_desc desc = {};
+      desc.image_type = CL_MEM_OBJECT_IMAGE1D_ARRAY;
+      desc.image_width = width;
+      desc.image_array_size = arraySize;
+      desc.image_row_pitch = rowPitch;
+
+      if (properties.empty()) {
+        object_ = ::clCreateImageWithProperties(
+            context(), nullptr, flags, &format, &desc, host_ptr, &error);
+      } else {
+        object_ =
+            ::clCreateImageWithProperties(context(), properties.data(), flags,
+                                          &format, &desc, host_ptr, &error);
+      }
+
+      detail::errHandler(error, __CREATE_IMAGE_ERR);
+      if (err != nullptr) {
+        *err = error;
+      }
+    }
+#endif //#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+
     /*! \brief Constructor from cl_mem - takes ownership.
      *
      * \param retainObject will cause the constructor to retain its cl object.
@@ -5156,6 +5319,83 @@ public:
     }
 #endif //#if CL_HPP_TARGET_OPENCL_VERSION >= 200
 
+#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+    /*! \brief Constructs a Image2D with specified properties.
+     *
+     *  Wraps clCreateImageWithProperties().
+     *
+     *  \param properties Optional list of properties for the image object and
+     *                    their corresponding values. The non-empty list must
+     *                    end with 0.
+     *  \param host_ptr Storage to be used if the CL_MEM_USE_HOST_PTR flag was
+     *                  specified. Note alignment & exclusivity requirements.
+     */
+    Image2D(const Context &context, const vector<cl_mem_properties> &properties,
+            cl_mem_flags flags, ImageFormat format, size_type width,
+            size_type height, size_type row_pitch = 0, void *host_ptr = nullptr,
+            cl_int *err = nullptr) {
+      cl_int error;
+
+      cl_image_desc desc = {};
+      desc.image_type = CL_MEM_OBJECT_IMAGE2D;
+      desc.image_width = width;
+      desc.image_height = height;
+      desc.image_row_pitch = row_pitch;
+
+      if (properties.empty()) {
+        object_ = ::clCreateImageWithProperties(
+            context(), nullptr, flags, &format, &desc, host_ptr, &error);
+      } else {
+        object_ =
+            ::clCreateImageWithProperties(context(), properties.data(), flags,
+                                          &format, &desc, host_ptr, &error);
+      }
+
+      detail::errHandler(error, __CREATE_IMAGE_ERR);
+      if (err != nullptr) {
+        *err = error;
+      }
+    }
+
+    /*! \brief Constructs a Image2D with specified properties.
+     *
+     *  Wraps clCreateImageWithProperties().
+     *
+     *  \param properties Optional list of properties for the image object and
+     *                    their corresponding values. The non-empty list must
+     *                    end with 0.
+     *  \param buffer Refer to a valid buffer or image memory object.
+     */
+    Image2D(const Context &context, const vector<cl_mem_properties> &properties,
+            cl_mem_flags flags, ImageFormat format, const Buffer &buffer,
+            size_type width, size_type height, size_type row_pitch = 0,
+            cl_int *err = nullptr) {
+      cl_int error;
+
+      cl_image_desc desc = {};
+      desc.image_type = CL_MEM_OBJECT_IMAGE2D;
+      desc.image_width = width;
+      desc.image_height = height;
+      desc.image_row_pitch = row_pitch;
+      desc.buffer = buffer();
+
+      if (properties.empty()) {
+        object_ = ::clCreateImageWithProperties(
+            context(), nullptr, flags, &format, &desc, nullptr, &error);
+      } else {
+        object_ =
+            ::clCreateImageWithProperties(context(), properties.data(), flags,
+                                          &format, &desc, nullptr, &error);
+      }
+
+      detail::errHandler(error, __CREATE_IMAGE_ERR);
+      if (err != nullptr) {
+        *err = error;
+      }
+    }
+
+#endif //#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+
     //! \brief Default constructor - initializes to nullptr.
     Image2D() { }
 
@@ -5178,10 +5418,6 @@ public:
         Image::operator=(rhs);
         return *this;
     }
-
-
-
-
 };
 
 
@@ -5298,6 +5534,49 @@ public:
         }
     }
 
+#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+    /*! \brief Constructs a Image2DArray with specified properties.
+     *
+     *  Wraps clCreateImageWithProperties().
+     *
+     *  \param properties Optional list of properties for the image object and
+     *                    their corresponding values. The non-empty list must
+     *                    end with 0.
+     *  \param host_ptr Storage to be used if the CL_MEM_USE_HOST_PTR flag was
+     *                  specified. Note alignment & exclusivity requirements.
+     */
+    Image2DArray(const Context &context,
+                 const vector<cl_mem_properties> &properties,
+                 cl_mem_flags flags, ImageFormat format, size_type arraySize,
+                 size_type width, size_type height, size_type rowPitch = 0,
+                 size_type slicePitch = 0, void *host_ptr = nullptr,
+                 cl_int *err = nullptr) {
+      cl_int error;
+
+      cl_image_desc desc = {};
+      desc.image_type = CL_MEM_OBJECT_IMAGE2D_ARRAY;
+      desc.image_width = width;
+      desc.image_height = height;
+      desc.image_array_size = arraySize;
+      desc.image_row_pitch = rowPitch;
+      desc.image_slice_pitch = slicePitch;
+
+      if (properties.empty()) {
+        object_ = ::clCreateImageWithProperties(
+            context(), nullptr, flags, &format, &desc, host_ptr, &error);
+      } else {
+        object_ =
+            ::clCreateImageWithProperties(context(), properties.data(), flags,
+                                          &format, &desc, host_ptr, &error);
+      }
+
+      detail::errHandler(error, __CREATE_IMAGE_ERR);
+      if (err != nullptr) {
+        *err = error;
+      }
+    }
+#endif //#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+
     Image2DArray() { }
     
     /*! \brief Constructor from cl_mem - takes ownership.
@@ -5398,6 +5677,48 @@ public:
 #endif // CL_HPP_MINIMUM_OPENCL_VERSION < 120
     }
 
+#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+    /*! \brief Constructs a Image3D with specified properties.
+     *
+     *  Wraps clCreateImageWithProperties().
+     *
+     *  \param properties Optional list of properties for the image object and
+     *                    their corresponding values. The non-empty list must
+     *                    end with 0.
+     *  \param host_ptr Storage to be used if the CL_MEM_USE_HOST_PTR flag was
+     *                  specified. Note alignment & exclusivity requirements.
+     */
+    Image3D(const Context &context, const vector<cl_mem_properties> &properties,
+            cl_mem_flags flags, ImageFormat format, size_type width,
+            size_type height, size_type depth, size_type row_pitch = 0,
+            size_type slice_pitch = 0, void *host_ptr = nullptr,
+            cl_int *err = nullptr) {
+      cl_int error;
+
+      cl_image_desc desc = {};
+      desc.image_type = CL_MEM_OBJECT_IMAGE3D;
+      desc.image_width = width;
+      desc.image_height = height;
+      desc.image_depth = depth;
+      desc.image_row_pitch = row_pitch;
+      desc.image_slice_pitch = slice_pitch;
+
+      if (properties.empty()) {
+        object_ = ::clCreateImageWithProperties(
+            context(), nullptr, flags, &format, &desc, host_ptr, &error);
+      } else {
+        object_ =
+            ::clCreateImageWithProperties(context(), properties.data(), flags,
+                                          &format, &desc, host_ptr, &error);
+      }
+
+      detail::errHandler(error, __CREATE_IMAGE_ERR);
+      if (err != nullptr) {
+        *err = error;
+      }
+    }
+#endif //#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+
     //! \brief Default constructor - initializes to nullptr.
     Image3D() : Image() { }
 
@@ -5919,6 +6240,7 @@ Local(size_type size)
 class Kernel : public detail::Wrapper<cl_kernel>
 {
 public:
+    inline Kernel(const Program& program, const string& name, cl_int* err = nullptr);
     inline Kernel(const Program& program, const char* name, cl_int* err = nullptr);
 
     //! \brief Default constructor - initializes to nullptr.
@@ -6397,7 +6719,6 @@ public:
         }
     }
 
-
 #if defined(CL_HPP_USE_IL_KHR) || CL_HPP_TARGET_OPENCL_VERSION >= 210
     /**
      * Program constructor to allow construction of program from SPIR-V or another IL.
@@ -6547,7 +6868,6 @@ public:
             return;
         }
 
-
         vector<size_type> lengths(numDevices);
         vector<const unsigned char*> images(numDevices);
 #if !defined(CL_HPP_ENABLE_PROGRAM_CONSTRUCTION_FROM_ARRAY_COMPATIBILITY)
@@ -6561,7 +6881,7 @@ public:
             lengths[i] = binaries[(int)i].second;
         }
 #endif // #if !defined(CL_HPP_ENABLE_PROGRAM_CONSTRUCTION_FROM_ARRAY_COMPATIBILITY)
-        
+
         vector<cl_device_id> deviceIDs(numDevices);
         for( size_type deviceIndex = 0; deviceIndex < numDevices; ++deviceIndex ) {
             deviceIDs[deviceIndex] = (devices[deviceIndex])();
@@ -6570,7 +6890,7 @@ public:
         if(binaryStatus) {
             binaryStatus->resize(numDevices);
         }
-        
+
         object_ = ::clCreateProgramWithBinary(
             context(), (cl_uint) devices.size(),
             deviceIDs.data(),
@@ -6637,6 +6957,14 @@ public:
         return *this;
     }
 
+    cl_int build(
+        const vector<Device>& devices,
+        const string& options,
+        void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
+        void* data = nullptr) const
+    {
+        return build(devices, options.c_str(), notifyFptr, data);
+    }
 
     cl_int build(
         const vector<Device>& devices,
@@ -6646,7 +6974,7 @@ public:
     {
         size_type numDevices = devices.size();
         vector<cl_device_id> deviceIDs(numDevices);
-        
+
         for( size_type deviceIndex = 0; deviceIndex < numDevices; ++deviceIndex ) {
             deviceIDs[deviceIndex] = (devices[deviceIndex])();
         }
@@ -6663,6 +6991,15 @@ public:
         return detail::buildErrHandler(buildError, __BUILD_PROGRAM_ERR, getBuildInfo<CL_PROGRAM_BUILD_LOG>());
     }
 
+    cl_int build(
+        const Device& device,
+        const string& options,
+        void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
+        void* data = nullptr) const
+    {
+        return build(device, options.c_str(), notifyFptr, data);
+    }
+
     cl_int build(
         const Device& device,
         const char* options = nullptr,
@@ -6684,6 +7021,14 @@ public:
         return detail::buildErrHandler(buildError, __BUILD_PROGRAM_ERR, buildLog);
     }
 
+    cl_int build(
+        const string& options,
+        void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
+        void* data = nullptr) const
+    {
+        return build(options.c_str(), notifyFptr, data);
+    }
+
     cl_int build(
         const char* options = nullptr,
         void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
@@ -6701,6 +7046,14 @@ public:
     }
 
 #if CL_HPP_TARGET_OPENCL_VERSION >= 120
+    cl_int compile(
+        const string& options,
+        void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
+        void* data = nullptr) const
+    {
+        return compile(options.c_str(), notifyFptr, data);
+    }
+
     cl_int compile(
         const char* options = nullptr,
         void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
@@ -6718,6 +7071,84 @@ public:
             data);
         return detail::buildErrHandler(error, __COMPILE_PROGRAM_ERR, getBuildInfo<CL_PROGRAM_BUILD_LOG>());
     }
+
+    cl_int compile(
+        const string& options,
+        const vector<Program>& inputHeaders,
+        const vector<string>& headerIncludeNames,
+        void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
+        void* data = nullptr) const
+    {
+        return compile(options.c_str(), inputHeaders, headerIncludeNames, notifyFptr, data);
+    }
+
+    cl_int compile(
+        const char* options,
+        const vector<Program>& inputHeaders,
+        const vector<string>& headerIncludeNames,
+        void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
+        void* data = nullptr) const
+    {
+        static_assert(sizeof(cl::Program) == sizeof(cl_program),
+            "Size of cl::Program must be equal to size of cl_program");
+        vector<const char*> headerIncludeNamesCStr;
+        for(const string& name: headerIncludeNames) {
+            headerIncludeNamesCStr.push_back(name.c_str());
+        }
+        cl_int error = ::clCompileProgram(
+            object_,
+            0,
+            nullptr,
+            options,
+            static_cast<cl_uint>(inputHeaders.size()),
+            reinterpret_cast<const cl_program*>(inputHeaders.data()),
+            reinterpret_cast<const char**>(headerIncludeNamesCStr.data()),
+            notifyFptr,
+            data);
+        return detail::buildErrHandler(error, __COMPILE_PROGRAM_ERR, getBuildInfo<CL_PROGRAM_BUILD_LOG>());
+    }
+
+    cl_int compile(
+        const string& options,
+        const vector<Device>& deviceList,
+        const vector<Program>& inputHeaders = vector<Program>(),
+        const vector<string>& headerIncludeNames = vector<string>(),
+        void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
+        void* data = nullptr) const
+    {
+        return compile(options.c_str(), deviceList, inputHeaders, headerIncludeNames, notifyFptr, data);
+    }
+
+    cl_int compile(
+        const char* options,
+        const vector<Device>& deviceList,
+        const vector<Program>& inputHeaders = vector<Program>(),
+        const vector<string>& headerIncludeNames = vector<string>(),
+        void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
+        void* data = nullptr) const
+    {
+        static_assert(sizeof(cl::Program) == sizeof(cl_program),
+            "Size of cl::Program must be equal to size of cl_program");
+        vector<const char*> headerIncludeNamesCStr;
+        for(const string& name: headerIncludeNames) {
+            headerIncludeNamesCStr.push_back(name.c_str());
+        }
+        vector<cl_device_id> deviceIDList;
+        for(const Device& device: deviceList) {
+            deviceIDList.push_back(device());
+        }
+        cl_int error = ::clCompileProgram(
+            object_,
+            static_cast<cl_uint>(deviceList.size()),
+            reinterpret_cast<const cl_device_id*>(deviceIDList.data()),
+            options,
+            static_cast<cl_uint>(inputHeaders.size()),
+            reinterpret_cast<const cl_program*>(inputHeaders.data()),
+            reinterpret_cast<const char**>(headerIncludeNamesCStr.data()),
+            notifyFptr,
+            data);
+        return detail::buildErrHandler(error, __COMPILE_PROGRAM_ERR, getBuildInfo<CL_PROGRAM_BUILD_LOG>());
+    }
 #endif // CL_HPP_TARGET_OPENCL_VERSION >= 120
 
     template <typename T>
@@ -6933,6 +7364,17 @@ inline Program linkProgram(
     return Program(prog);
 }
 
+inline Program linkProgram(
+    const Program& input1,
+    const Program& input2,
+    const string& options,
+    void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
+    void* data = nullptr,
+    cl_int* err = nullptr)
+{
+    return linkProgram(input1, input2, options.c_str(), notifyFptr, data, err);
+}
+
 inline Program linkProgram(
     const vector<Program>& inputPrograms,
     const char* options = nullptr,
@@ -6971,6 +7413,16 @@ inline Program linkProgram(
 
     return Program(prog);
 }
+
+inline Program linkProgram(
+    const vector<Program>& inputPrograms,
+    const string& options,
+    void (CL_CALLBACK * notifyFptr)(cl_program, void *) = nullptr,
+    void* data = nullptr,
+    cl_int* err = nullptr)
+{
+    return linkProgram(inputPrograms, options.c_str(), notifyFptr, data, err);
+}
 #endif // CL_HPP_TARGET_OPENCL_VERSION >= 120
 
 // Template specialization for CL_PROGRAM_BINARIES
@@ -7029,6 +7481,18 @@ inline cl_int cl::Program::setSpecializationConstant(cl_uint index, const bool &
 }
 #endif // CL_HPP_TARGET_OPENCL_VERSION >= 220
 
+inline Kernel::Kernel(const Program& program, const string& name, cl_int* err)
+{
+    cl_int error;
+
+    object_ = ::clCreateKernel(program(), name.c_str(), &error);
+    detail::errHandler(error, __CREATE_KERNEL_ERR);
+
+    if (err != nullptr) {
+        *err = error;
+    }
+}
+
 inline Kernel::Kernel(const Program& program, const char* name, cl_int* err)
 {
     cl_int error;
@@ -7039,27 +7503,24 @@ inline Kernel::Kernel(const Program& program, const char* name, cl_int* err)
     if (err != nullptr) {
         *err = error;
     }
-
 }
 
 #ifdef cl_khr_external_memory
 enum class ExternalMemoryType : cl_external_memory_handle_type_khr
 {
     None = 0,
-
+#ifdef cl_khr_external_memory_opaque_fd
     OpaqueFd = CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_FD_KHR,
+#endif // cl_khr_external_memory_opaque_fd
+#ifdef cl_khr_external_memory_win32
     OpaqueWin32 = CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_WIN32_KHR,
     OpaqueWin32Kmt = CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_WIN32_KMT_KHR,
-
-    D3D11Texture = CL_EXTERNAL_MEMORY_HANDLE_D3D11_TEXTURE_KHR,
-    D3D11TextureKmt = CL_EXTERNAL_MEMORY_HANDLE_D3D11_TEXTURE_KMT_KHR,
-
-    D3D12Heap = CL_EXTERNAL_MEMORY_HANDLE_D3D12_HEAP_KHR,
-    D3D12Resource = CL_EXTERNAL_MEMORY_HANDLE_D3D12_RESOURCE_KHR,
-
+#endif // cl_khr_external_memory_win32
+#ifdef cl_khr_external_memory_dma_buf
     DmaBuf = CL_EXTERNAL_MEMORY_HANDLE_DMA_BUF_KHR,
+#endif // cl_khr_external_memory_dma_buf
 };
-#endif
+#endif // cl_khr_external_memory
 
 enum class QueueProperties : cl_command_queue_properties
 {
@@ -9880,15 +10341,15 @@ inline cl_int copy( const CommandQueue &queue, IteratorType startIterator, Itera
     if( error != CL_SUCCESS ) {
         return error;
     }
-#if defined(_MSC_VER)
+#if defined(_MSC_VER) && _MSC_VER < 1920
     std::copy(
-        startIterator, 
-        endIterator, 
+        startIterator,
+        endIterator,
         stdext::checked_array_iterator<DataType*>(
             pointer, length));
 #else
     std::copy(startIterator, endIterator, pointer);
-#endif
+#endif // defined(_MSC_VER) && _MSC_VER < 1920
     Event endEvent;
     error = queue.enqueueUnmapMemObject(buffer, pointer, 0, &endEvent);
     // if exceptions enabled, enqueueUnmapMemObject will throw
@@ -10762,15 +11223,12 @@ namespace compatibility {
 enum ExternalSemaphoreType : cl_external_semaphore_handle_type_khr
 {
     None = 0,
-#ifdef cl_khr_external_semaphore_dx_fence
-    D3D12Fence = CL_SEMAPHORE_HANDLE_D3D12_FENCE_KHR,
-#endif
 #ifdef cl_khr_external_semaphore_opaque_fd
     OpaqueFd = CL_SEMAPHORE_HANDLE_OPAQUE_FD_KHR,
-#endif
+#endif // cl_khr_external_semaphore_opaque_fd
 #ifdef cl_khr_external_semaphore_sync_fd
     SyncFd = CL_SEMAPHORE_HANDLE_SYNC_FD_KHR,
-#endif
+#endif // cl_khr_external_semaphore_sync_fd
 #ifdef cl_khr_external_semaphore_win32
     OpaqueWin32 = CL_SEMAPHORE_HANDLE_OPAQUE_WIN32_KHR,
     OpaqueWin32Kmt = CL_SEMAPHORE_HANDLE_OPAQUE_WIN32_KMT_KHR,
@@ -11108,6 +11566,9 @@ public:
         cl_int error = detail::errHandler(
             pfn_clCommandBarrierWithWaitListKHR(object_,
                 (command_queue != nullptr) ? (*command_queue)() : nullptr,
+#if CL_KHR_COMMAND_BUFFER_EXTENSION_VERSION > CL_MAKE_VERSION(0, 9, 4)
+                nullptr, // Properties
+#endif
                 (sync_points_vec != nullptr) ? (cl_uint) sync_points_vec->size() : 0,
                 (sync_points_vec != nullptr && sync_points_vec->size() > 0) ? &sync_points_vec->front() : nullptr,
                 (sync_point != nullptr) ? &tmp_sync_point : nullptr,
@@ -11139,6 +11600,9 @@ public:
         cl_int error = detail::errHandler(
             pfn_clCommandCopyBufferKHR(object_,
                 (command_queue != nullptr) ? (*command_queue)() : nullptr,
+#if CL_KHR_COMMAND_BUFFER_EXTENSION_VERSION > CL_MAKE_VERSION(0, 9, 4)
+                nullptr, // Properties
+#endif
                 src(),
                 dst(),
                 src_offset,
@@ -11179,6 +11643,9 @@ public:
         cl_int error = detail::errHandler(
             pfn_clCommandCopyBufferRectKHR(object_,
                 (command_queue != nullptr) ? (*command_queue)() : nullptr,
+#if CL_KHR_COMMAND_BUFFER_EXTENSION_VERSION > CL_MAKE_VERSION(0, 9, 4)
+                nullptr, // Properties
+#endif
                 src(),
                 dst(),
                 src_origin.data(),
@@ -11219,6 +11686,9 @@ public:
         cl_int error = detail::errHandler(
             pfn_clCommandCopyBufferToImageKHR(object_,
                 (command_queue != nullptr) ? (*command_queue)() : nullptr,
+#if CL_KHR_COMMAND_BUFFER_EXTENSION_VERSION > CL_MAKE_VERSION(0, 9, 4)
+                nullptr, // Properties
+#endif
                 src(),
                 dst(),
                 src_offset,
@@ -11255,6 +11725,9 @@ public:
         cl_int error = detail::errHandler(
             pfn_clCommandCopyImageKHR(object_,
                 (command_queue != nullptr) ? (*command_queue)() : nullptr,
+#if CL_KHR_COMMAND_BUFFER_EXTENSION_VERSION > CL_MAKE_VERSION(0, 9, 4)
+                nullptr, // Properties
+#endif
                 src(),
                 dst(),
                 src_origin.data(),
@@ -11291,6 +11764,9 @@ public:
         cl_int error = detail::errHandler(
             pfn_clCommandCopyImageToBufferKHR(object_,
                 (command_queue != nullptr) ? (*command_queue)() : nullptr,
+#if CL_KHR_COMMAND_BUFFER_EXTENSION_VERSION > CL_MAKE_VERSION(0, 9, 4)
+                nullptr, // Properties
+#endif
                 src(),
                 dst(),
                 src_origin.data(),
@@ -11327,6 +11803,9 @@ public:
         cl_int error = detail::errHandler(
             pfn_clCommandFillBufferKHR(object_,
                 (command_queue != nullptr) ? (*command_queue)() : nullptr,
+#if CL_KHR_COMMAND_BUFFER_EXTENSION_VERSION > CL_MAKE_VERSION(0, 9, 4)
+                nullptr, // Properties
+#endif
                 buffer(),
                 static_cast<void*>(&pattern),
                 sizeof(PatternType),
@@ -11362,6 +11841,9 @@ public:
         cl_int error = detail::errHandler(
             pfn_clCommandFillImageKHR(object_,
                 (command_queue != nullptr) ? (*command_queue)() : nullptr,
+#if CL_KHR_COMMAND_BUFFER_EXTENSION_VERSION > CL_MAKE_VERSION(0, 9, 4)
+                nullptr, // Properties
+#endif
                 image(),
                 static_cast<void*>(&fillColor),
                 origin.data(),
@@ -11378,7 +11860,12 @@ public:
         return error;
     }
 
-    cl_int commandNDRangeKernel(const cl::vector<cl_ndrange_kernel_command_properties_khr> &properties,
+    cl_int commandNDRangeKernel(
+#if CL_KHR_COMMAND_BUFFER_EXTENSION_VERSION > CL_MAKE_VERSION(0, 9, 4)
+            const cl::vector<cl_command_properties_khr> &properties,
+#else
+            const cl::vector<cl_ndrange_kernel_command_properties_khr> &properties,
+#endif
         const Kernel& kernel,
         const NDRange& offset,
         const NDRange& global,
@@ -11416,6 +11903,8 @@ public:
     }
 
 #if defined(cl_khr_command_buffer_mutable_dispatch)
+#if CL_KHR_COMMAND_BUFFER_MUTABLE_DISPATCH_EXTENSION_VERSION <                 \
+    CL_MAKE_VERSION(0, 9, 2)
     cl_int updateMutableCommands(const cl_mutable_base_config_khr* mutable_config)
     {
         if (pfn_clUpdateMutableCommandsKHR == nullptr) {
@@ -11425,6 +11914,21 @@ public:
         return detail::errHandler(pfn_clUpdateMutableCommandsKHR(object_, mutable_config),
                         __UPDATE_MUTABLE_COMMANDS_KHR_ERR);
     }
+#else
+    template <int ArrayLength>
+    cl_int updateMutableCommands(std::array<cl_command_buffer_update_type_khr,
+                                            ArrayLength> &config_types,
+                                 std::array<const void *, ArrayLength> &configs) {
+        if (pfn_clUpdateMutableCommandsKHR == nullptr) {
+            return detail::errHandler(CL_INVALID_OPERATION,
+                                      __UPDATE_MUTABLE_COMMANDS_KHR_ERR);
+        }
+        return detail::errHandler(
+            pfn_clUpdateMutableCommandsKHR(object_, static_cast<cl_uint>(configs.size()),
+                                           config_types.data(), configs.data()),
+            __UPDATE_MUTABLE_COMMANDS_KHR_ERR);
+    }
+#endif /* CL_KHR_COMMAND_BUFFER_MUTABLE_DISPATCH_EXTENSION_VERSION */
 #endif /* cl_khr_command_buffer_mutable_dispatch */
 
 private:
diff --git a/tests/CMakeLists.txt b/tests/CMakeLists.txt
index 3cf61eb..5d2661e 100644
--- a/tests/CMakeLists.txt
+++ b/tests/CMakeLists.txt
@@ -152,6 +152,14 @@ foreach(VERSION 120 200 210 220 300)
     target_compile_definitions(${TEST_EXE}
         PUBLIC -DCL_HPP_TARGET_OPENCL_VERSION=${VERSION} ${DEFINE_OPTION}
     )
+    if(MSVC AND (CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
+      # This is quite hacky, but the definition noreturn in Clang's
+      # stdnoreturn.h is not compatible with stdlib.h in the Windows SDK.
+      # This could normally be resolved by changing the order of include
+      # files, but not possible in this project due to the generated nature
+      # of the source files.
+      target_compile_definitions(${TEST_EXE} PRIVATE __STDNORETURN_H UNITY_NORETURN=_Noreturn)
+    endif()
     add_dependencies(${TEST_EXE}
         strip_cl_defines
         mock_cl_header
diff --git a/tests/pkgconfig/bare/CMakeLists.txt b/tests/pkgconfig/bare/CMakeLists.txt
index e535f4e..077cdf2 100644
--- a/tests/pkgconfig/bare/CMakeLists.txt
+++ b/tests/pkgconfig/bare/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required(VERSION 3.0)
+cmake_minimum_required(VERSION 3.16)
 
 project(PkgConfigTest
   LANGUAGES CXX
diff --git a/tests/pkgconfig/sdk/CMakeLists.txt b/tests/pkgconfig/sdk/CMakeLists.txt
index f331b13..9421fb0 100644
--- a/tests/pkgconfig/sdk/CMakeLists.txt
+++ b/tests/pkgconfig/sdk/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required(VERSION 3.0)
+cmake_minimum_required(VERSION 3.16)
 
 project(PkgConfigTest
   LANGUAGES CXX
diff --git a/tests/test_openclhpp.cpp b/tests/test_openclhpp.cpp
index c564a46..28e5d55 100644
--- a/tests/test_openclhpp.cpp
+++ b/tests/test_openclhpp.cpp
@@ -60,6 +60,10 @@ static inline cl_command_buffer_khr make_command_buffer_khr(int index)
     return (cl_command_buffer_khr)(size_t)(0x8f8f8f8f + index);
 }
 
+static inline cl_mutable_command_khr make_mutable_command_khr(int index) {
+    return (cl_mutable_command_khr)(size_t)(0x77777777 + index);
+}
+
 static inline cl_event make_event(int index)
 {
     return (cl_event)(size_t)(0xd0d0d0d0 + index);
@@ -85,6 +89,7 @@ static cl::Kernel kernelPool[POOL_MAX];
 static cl::Program programPool[POOL_MAX];
 #if defined(cl_khr_command_buffer)
 static cl::CommandBufferKhr commandBufferKhrPool[POOL_MAX];
+static cl::MutableCommandKhr mutableCommandKhrPool[POOL_MAX];
 #endif
 #if defined(cl_khr_semaphore)
 static cl::Semaphore semaphorePool[POOL_MAX];
@@ -289,11 +294,11 @@ private:
 public:
     RefcountTable() : n(0), objects(nullptr), refcounts(nullptr) {}
 
-    void init(size_t n, void * const *objects, int *refcounts)
+    void init(size_t n_, void * const *objects_, int *refcounts_)
     {
-        this->n = n;
-        this->objects = objects;
-        this->refcounts = refcounts;
+        n = n_;
+        objects = objects_;
+        refcounts = refcounts_;
     }
 
     void reset()
@@ -347,8 +352,7 @@ MAKE_REFCOUNT_STUBS(cl_command_queue, clRetainCommandQueue, clReleaseCommandQueu
 MAKE_REFCOUNT_STUBS(cl_device_id, clRetainDevice, clReleaseDevice, deviceRefcounts)
 MAKE_REFCOUNT_STUBS(cl_context, clRetainContext, clReleaseContext, contextRefcounts)
 MAKE_REFCOUNT_STUBS(cl_mem, clRetainMemObject, clReleaseMemObject, memRefcounts)
-// Deactivated because unused for now.
-#if defined(cl_khr_command_buffer) && 0
+#if defined(cl_khr_command_buffer)
 MAKE_REFCOUNT_STUBS(cl_command_buffer_khr, clRetainCommandBufferKHR, clReleaseCommandBufferKHR, commandBufferKhrRefcounts)
 #endif
 
@@ -409,6 +413,10 @@ void setUp(void)
     cl::pfn_clReleaseCommandBufferKHR = ::clReleaseCommandBufferKHR;
     cl::pfn_clGetCommandBufferInfoKHR = ::clGetCommandBufferInfoKHR;
 #endif
+#if defined(cl_khr_command_buffer_mutable_dispatch)
+    cl::pfn_clUpdateMutableCommandsKHR = ::clUpdateMutableCommandsKHR;
+    cl::pfn_clGetMutableCommandInfoKHR = ::clGetMutableCommandInfoKHR;
+#endif
 #if defined(cl_khr_semaphore)
     cl::pfn_clCreateSemaphoreWithPropertiesKHR = ::clCreateSemaphoreWithPropertiesKHR;
     cl::pfn_clReleaseSemaphoreKHR = ::clReleaseSemaphoreKHR;
@@ -449,6 +457,9 @@ void setUp(void)
 #if defined(cl_khr_command_buffer)
         commandBufferKhrPool[i]() = make_command_buffer_khr(i);
 #endif
+#if defined(cl_khr_command_buffer_mutable_dispatch)
+        mutableCommandKhrPool[i]() = make_mutable_command_khr(i);
+#endif
 #if defined(cl_khr_semaphore)
         semaphorePool[i]() = make_semaphore_khr(i);
 #endif
@@ -477,6 +488,7 @@ void tearDown(void)
         devicePool[i]() = nullptr;
 #if defined(cl_khr_command_buffer)
         commandBufferKhrPool[i]() = nullptr;
+        mutableCommandKhrPool[i]() = nullptr;
 #endif
 #if defined(cl_khr_semaphore)
         semaphorePool[i]() = nullptr;
@@ -1629,6 +1641,55 @@ void testCreateImage2D_1_2(void)
     image() = nullptr;
 }
 
+#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+static cl_mem clCreateImageWithProperties_testImage2DWithProperties(
+    cl_context context, const cl_mem_properties *properties, cl_mem_flags flags,
+    const cl_image_format *image_format, const cl_image_desc *image_desc,
+    void *host_ptr, cl_int *errcode_ret, int num_calls) {
+  TEST_ASSERT_EQUAL(0, num_calls);
+  TEST_ASSERT_EQUAL_PTR(contextPool[0](), context);
+  TEST_ASSERT_NOT_NULL(properties);
+  TEST_ASSERT_EQUAL(CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_FD_KHR, properties[0]);
+  TEST_ASSERT_EQUAL(42, properties[1]);
+  TEST_ASSERT_EQUAL(0, properties[2]);
+  TEST_ASSERT_EQUAL(CL_MEM_READ_WRITE, flags);
+  TEST_ASSERT_NOT_NULL(image_format);
+  TEST_ASSERT_EQUAL(CL_RGBA, image_format->image_channel_order);
+  TEST_ASSERT_EQUAL(CL_UNORM_INT8, image_format->image_channel_data_type);
+  TEST_ASSERT_NOT_NULL(image_desc);
+  TEST_ASSERT_EQUAL(CL_MEM_OBJECT_IMAGE2D, image_desc->image_type);
+  TEST_ASSERT_EQUAL(32, image_desc->image_width);
+  TEST_ASSERT_EQUAL(16, image_desc->image_height);
+  TEST_ASSERT_EQUAL(8, image_desc->image_row_pitch);
+
+  TEST_ASSERT_NULL(host_ptr);
+  if (errcode_ret)
+    *errcode_ret = CL_SUCCESS;
+
+  return make_mem(0);
+}
+#endif // CL_HPP_TARGET_OPENCL_VERSION >= 300
+
+void testImage2DWithProperties(void) {
+#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+  clCreateImageWithProperties_StubWithCallback(
+      clCreateImageWithProperties_testImage2DWithProperties);
+
+  VECTOR_CLASS<cl_mem_properties> props = {
+      CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_FD_KHR, 42, 0};
+  cl_int err;
+  cl::Image2D image(contextPool[0], props, CL_MEM_READ_WRITE,
+                    cl::ImageFormat(CL_RGBA, CL_UNORM_INT8), 32, 16, 8, nullptr,
+                    &err);
+
+  TEST_ASSERT_EQUAL_PTR(make_mem(0), image());
+  TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+
+  // prevent destructor from interfering with the test
+  image() = nullptr;
+#endif // CL_HPP_TARGET_OPENCL_VERSION >= 300
+}
+
 /****************************************************************************
  * Tests for cl::Image3D
  ****************************************************************************/
@@ -1753,6 +1814,56 @@ void testCreateImage3D_1_2(void)
     image() = nullptr;
 }
 
+#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+static cl_mem clCreateImageWithProperties_testImage3DWithProperties(
+    cl_context context, const cl_mem_properties *properties, cl_mem_flags flags,
+    const cl_image_format *image_format, const cl_image_desc *image_desc,
+    void *host_ptr, cl_int *errcode_ret, int num_calls) {
+  TEST_ASSERT_EQUAL(0, num_calls);
+  TEST_ASSERT_EQUAL_PTR(contextPool[0](), context);
+  TEST_ASSERT_NOT_NULL(properties);
+  TEST_ASSERT_EQUAL(CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_FD_KHR, properties[0]);
+  TEST_ASSERT_EQUAL(42, properties[1]);
+  TEST_ASSERT_EQUAL(0, properties[2]);
+  TEST_ASSERT_EQUAL(CL_MEM_READ_WRITE, flags);
+  TEST_ASSERT_NOT_NULL(image_format);
+  TEST_ASSERT_EQUAL(CL_RGBA, image_format->image_channel_order);
+  TEST_ASSERT_EQUAL(CL_UNORM_INT8, image_format->image_channel_data_type);
+  TEST_ASSERT_NOT_NULL(image_desc);
+  TEST_ASSERT_EQUAL(CL_MEM_OBJECT_IMAGE3D, image_desc->image_type);
+  TEST_ASSERT_EQUAL(32, image_desc->image_width);
+  TEST_ASSERT_EQUAL(16, image_desc->image_height);
+  TEST_ASSERT_EQUAL(8, image_desc->image_depth);
+  TEST_ASSERT_EQUAL(4, image_desc->image_row_pitch);
+  TEST_ASSERT_EQUAL(2, image_desc->image_slice_pitch);
+  TEST_ASSERT_NULL(host_ptr);
+  if (errcode_ret)
+    *errcode_ret = CL_SUCCESS;
+
+  return make_mem(0);
+}
+#endif // CL_HPP_TARGET_OPENCL_VERSION >= 300
+
+void testImage3DWithProperties(void) {
+#if CL_HPP_TARGET_OPENCL_VERSION >= 300
+  clCreateImageWithProperties_StubWithCallback(
+      clCreateImageWithProperties_testImage3DWithProperties);
+
+  VECTOR_CLASS<cl_mem_properties> props = {
+      CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_FD_KHR, 42, 0};
+  cl_int err;
+  cl::Image3D image(contextPool[0], props, CL_MEM_READ_WRITE,
+                    cl::ImageFormat(CL_RGBA, CL_UNORM_INT8), 32, 16, 8, 4, 2,
+                    nullptr, &err);
+
+  TEST_ASSERT_EQUAL_PTR(make_mem(0), image());
+  TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+
+  // prevent destructor from interfering with the test
+  image() = nullptr;
+#endif // CL_HPP_TARGET_OPENCL_VERSION >= 300
+}
+
 /****************************************************************************
  * Tests for cl::Kernel
  ****************************************************************************/
@@ -1765,6 +1876,51 @@ MAKE_MOVE_TESTS(Kernel, make_kernel, clReleaseKernel, kernelPool)
 static cl_int scalarArg;
 static cl_int3 vectorArg;
 
+static cl_kernel clCreateKernel_constructor(
+    cl_program program,
+    const char* kernel_name,
+    cl_int* errcode_ret,
+    int num_calls)
+{
+    (void) num_calls;
+
+    TEST_ASSERT_EQUAL(program, make_program(0));
+    TEST_ASSERT_EQUAL_STRING(kernel_name, "test");
+    if (errcode_ret != nullptr)
+        *errcode_ret = CL_SUCCESS;
+
+    return make_kernel(0);
+}
+
+void testKernelConstructor(void)
+{
+    clCreateKernel_StubWithCallback(clCreateKernel_constructor);
+
+    cl_int errorCode;
+    cl::Program program(make_program(0));
+    cl::Kernel kernel(program, "test", &errorCode);
+    TEST_ASSERT_EQUAL(kernel(), make_kernel(0));
+    TEST_ASSERT_EQUAL(errorCode, CL_SUCCESS);
+
+    program() = nullptr;
+    kernel() = nullptr;
+}
+
+void testKernelStringConstructor(void)
+{
+    clCreateKernel_StubWithCallback(clCreateKernel_constructor);
+
+    cl_int errorCode;
+    cl::string kernelName("test");
+    cl::Program program(make_program(0));
+    cl::Kernel kernel(program, kernelName, &errorCode);
+    TEST_ASSERT_EQUAL(kernel(), make_kernel(0));
+    TEST_ASSERT_EQUAL(errorCode, CL_SUCCESS);
+
+    program() = nullptr;
+    kernel() = nullptr;
+}
+
 void testKernelSetArgScalar(void)
 {
     scalarArg = 0xcafebabe;
@@ -2090,7 +2246,7 @@ void testGetBuildInfo(void)
     cl::Device dev(fakeDevice);
     
     cl_int err;
-    std::string log = prog.getBuildInfo<CL_PROGRAM_BUILD_LOG>(dev, &err);
+    cl::string log = prog.getBuildInfo<CL_PROGRAM_BUILD_LOG>(dev, &err);
 
     prog() = nullptr;
     dev() = nullptr;
@@ -2110,7 +2266,9 @@ static cl_int clBuildProgram_testBuildProgram(
     TEST_ASSERT_EQUAL(program, make_program(0));
     TEST_ASSERT_NOT_EQUAL(num_devices, 0);
     TEST_ASSERT_NOT_EQUAL(device_list, nullptr);
-    TEST_ASSERT_EQUAL(options, nullptr);
+    if (options) {
+        TEST_ASSERT_EQUAL_STRING(options, "-cl-program-build-options");
+    }
     TEST_ASSERT_EQUAL(pfn_notify, nullptr);
     TEST_ASSERT_EQUAL(user_data, nullptr);
 
@@ -2149,168 +2307,501 @@ void testBuildProgramSingleDevice(void)
     TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
 }
 
-/**
-* Stub implementation of clGetCommandQueueInfo that returns first one image then none
-*/
-static cl_int clGetSupportedImageFormats_testGetSupportedImageFormats(
-    cl_context context,
-    cl_mem_flags flags,
-    cl_mem_object_type image_type,
-    cl_uint num_entries,
-    cl_image_format *image_formats,
-    cl_uint *num_image_formats,
-    int num_calls)
+void testBuildProgramSingleDeviceWithOptions(void)
 {
-    (void) context;
-    (void) flags;
-    (void) image_type;
+    cl_program program = make_program(0);
+    cl_device_id device_id = make_device_id(0);
 
-    // Catch failure case that causes error in bugzilla 13355:
-    // returns CL_INVALID_VALUE if flags or image_type are not valid, 
-    // or if num_entries is 0 and image_formats is not nullptr.
-    if (num_entries == 0 && image_formats != nullptr) {
-        return CL_INVALID_VALUE;
-    }
-    if (num_entries == 0)  {
-        // If num_entries was 0 this is the query for number
-        if (num_image_formats) {
-            if (num_calls == 0) {
-                *num_image_formats = 1;
-            }
-            else {
-                *num_image_formats = 0;
-            }
-        }
-    }
-    else {
-        // Should return something
-        TEST_ASSERT_NOT_NULL(image_formats);
-        
-        // For first call we should return one format here
-        if (num_calls == 1) {
-            TEST_ASSERT_EQUAL(num_entries, 1);
-            image_formats[0] = cl::ImageFormat(CL_RGB, CL_FLOAT);
-        }
-    }
+    // Creating a device queries the platform version:
+    clGetDeviceInfo_StubWithCallback(clGetDeviceInfo_platform);
+    clGetPlatformInfo_StubWithCallback(clGetPlatformInfo_version_1_2);
 
-    return CL_SUCCESS;
-}
+    clBuildProgram_StubWithCallback(clBuildProgram_testBuildProgram);
 
-void testGetSupportedImageFormats(void)
-{
-    cl_context ctx_cl = make_context(0);
+    // Building the program queries the program build log:
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clGetProgramBuildInfo_StubWithCallback(clGetProgramBuildInfo_testGetBuildInfo);
+    clGetProgramBuildInfo_StubWithCallback(clGetProgramBuildInfo_testGetBuildInfo);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
 
-    clGetSupportedImageFormats_StubWithCallback(clGetSupportedImageFormats_testGetSupportedImageFormats);
-    clGetSupportedImageFormats_StubWithCallback(clGetSupportedImageFormats_testGetSupportedImageFormats);
-    clReleaseContext_ExpectAndReturn(make_context(0), CL_SUCCESS);
+    clReleaseProgram_ExpectAndReturn(program, CL_SUCCESS);
 
-    cl::Context ctx(ctx_cl);
-    std::vector<cl::ImageFormat> formats;
-    cl_int ret = CL_SUCCESS;
+    cl::Program prog(program);
+    cl::Device dev(device_id);
 
-    ret = ctx.getSupportedImageFormats(
-        CL_MEM_READ_WRITE,
-        CL_MEM_OBJECT_IMAGE2D,
-        &formats);
-    TEST_ASSERT_EQUAL(ret, CL_SUCCESS);
-    TEST_ASSERT_EQUAL(formats.size(), 1);
-    ret = ctx.getSupportedImageFormats(
-        CL_MEM_READ_WRITE,
-        CL_MEM_OBJECT_IMAGE2D,
-        &formats);
-    TEST_ASSERT_EQUAL(formats.size(), 0);
-    TEST_ASSERT_EQUAL(ret, CL_SUCCESS);
+    cl_int errcode = prog.build(dev, "-cl-program-build-options");
+
+    TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
 }
 
-void testCreateSubDevice(void)
+void testBuildProgramSingleDeviceWithStringOptions(void)
 {
-    // TODO
+    cl_program program = make_program(0);
+    cl_device_id device_id = make_device_id(0);
+
+    // Creating a device queries the platform version:
+    clGetDeviceInfo_StubWithCallback(clGetDeviceInfo_platform);
+    clGetPlatformInfo_StubWithCallback(clGetPlatformInfo_version_1_2);
+
+    clBuildProgram_StubWithCallback(clBuildProgram_testBuildProgram);
+
+    // Building the program queries the program build log:
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clGetProgramBuildInfo_StubWithCallback(clGetProgramBuildInfo_testGetBuildInfo);
+    clGetProgramBuildInfo_StubWithCallback(clGetProgramBuildInfo_testGetBuildInfo);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
 
+    clReleaseProgram_ExpectAndReturn(program, CL_SUCCESS);
+
+    cl::Program prog(program);
+    cl::Device dev(device_id);
+
+    cl::string options("-cl-program-build-options");
+    cl_int errcode = prog.build(dev, options);
+
+    TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
 }
 
-void testGetContextInfoDevices(void)
+static cl_int clGetProgramInfo_forBuildLog(
+    cl_program         program,
+    cl_program_info    param_name,
+    size_t             param_value_size,
+    void *             param_value,
+    size_t *           param_value_size_ret,
+    int num_calls)
 {
-    // TODO
+    (void) num_calls;
+
+    TEST_ASSERT_EQUAL(program, make_program(0));
+    TEST_ASSERT_EQUAL(param_name, CL_PROGRAM_DEVICES);
+    if (param_value_size) {
+        TEST_ASSERT_EQUAL(param_value_size, sizeof(cl_device_id));
+        TEST_ASSERT_NOT_EQUAL(param_value, nullptr);
+        *(cl_device_id*)param_value = make_device_id(0);
+    }
+    if (param_value_size_ret) {
+        *param_value_size_ret = sizeof(cl_device_id);
+    }
+    return CL_SUCCESS;
 }
 
-#if CL_HPP_TARGET_OPENCL_VERSION >= 200
-static cl_mem clCreateImage_testCreateImage2DFromBuffer_2_0(
-    cl_context context,
-    cl_mem_flags flags,
-    const cl_image_format *image_format,
-    const cl_image_desc *image_desc,
-    void *host_ptr,
-    cl_int *errcode_ret,
+static cl_int clCompileProgram_basic(
+    cl_program           program,
+    cl_uint              num_devices,
+    const cl_device_id * device_list,
+    const char *         options,
+    cl_uint              num_input_headers,
+    const cl_program *   input_headers,
+    const char **        header_include_names,
+    void (CL_CALLBACK *  pfn_notify)(cl_program program,
+                                    void * user_data),
+    void *               user_data,
     int num_calls)
 {
-    (void) context;
-    (void) flags;
     (void) num_calls;
 
-    TEST_ASSERT_NOT_NULL(image_format);
-    TEST_ASSERT_NOT_NULL(image_desc);
-    TEST_ASSERT_NULL(host_ptr);
-    TEST_ASSERT_EQUAL_HEX(CL_MEM_OBJECT_IMAGE2D, image_desc->image_type);
-
-    // Return the passed buffer as the cl_mem and success for the error code
-    if (errcode_ret) {
-        *errcode_ret = CL_SUCCESS;
+    TEST_ASSERT_EQUAL(program, make_program(0));
+    TEST_ASSERT_EQUAL(num_devices, 0);
+    TEST_ASSERT_EQUAL(device_list, nullptr);
+    if (options) {
+        TEST_ASSERT_EQUAL_STRING(options, "-cl-program-compile-options");
     }
-    return image_desc->buffer;
+    TEST_ASSERT_EQUAL(num_input_headers, 0);
+    TEST_ASSERT_EQUAL(input_headers, nullptr);
+    TEST_ASSERT_EQUAL(header_include_names, nullptr);
+    TEST_ASSERT_EQUAL(pfn_notify, nullptr);
+    TEST_ASSERT_EQUAL(user_data, nullptr);
+
+    return CL_SUCCESS;
 }
-#endif
 
-void testCreateImage2DFromBuffer_2_0(void)
+void testCompileProgramBasic(void)
 {
-#if CL_HPP_TARGET_OPENCL_VERSION >= 200
-    clGetContextInfo_StubWithCallback(clGetContextInfo_device);
-    clGetDeviceInfo_StubWithCallback(clGetDeviceInfo_platform);
-    clGetPlatformInfo_StubWithCallback(clGetPlatformInfo_version_2_0);
-    clCreateImage_StubWithCallback(clCreateImage_testCreateImage2DFromBuffer_2_0);
-    clReleaseMemObject_ExpectAndReturn(make_mem(0), CL_SUCCESS);
-    clReleaseContext_ExpectAndReturn(make_context(0), CL_SUCCESS);
+#if CL_HPP_TARGET_OPENCL_VERSION >= 120
+    cl_program program = make_program(0);
 
-    cl_int err;
-    cl::Context context(make_context(0));
+    clCompileProgram_StubWithCallback(clCompileProgram_basic);
 
-    // Create buffer
-    // Create image from buffer
-    cl::Buffer buffer(make_mem(0));
-    cl::Image2D imageFromBuffer(
-        context,
-        cl::ImageFormat(CL_R, CL_FLOAT), buffer, 64, 32, 256, &err);
+    // Compiling the program queries the program build log:
+    clGetProgramInfo_StubWithCallback(clGetProgramInfo_forBuildLog);
+    clGetDeviceInfo_StubWithCallback(clGetDeviceInfo_platform);
+    clGetPlatformInfo_StubWithCallback(clGetPlatformInfo_version_1_2);
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clGetProgramBuildInfo_StubWithCallback(clGetProgramBuildInfo_testGetBuildInfo);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
 
-    TEST_ASSERT_EQUAL_PTR(buffer(), imageFromBuffer());
-    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+    clReleaseProgram_ExpectAndReturn(program, CL_SUCCESS);
 
-    buffer() = nullptr;
+    cl::Program prog(program);
+    cl_int errcode = prog.compile();
+
+    TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
 #endif
 }
 
-#if CL_HPP_TARGET_OPENCL_VERSION >= 200
-static cl_mem clCreateImage_testCreateImage2D_2_0(
-    cl_context context,
-    cl_mem_flags flags,
-    const cl_image_format *image_format,
-    const cl_image_desc *image_desc,
-    void *host_ptr,
-    cl_int *errcode_ret,
-    int num_calls)
+void testCompileProgramWithOptions(void)
 {
-    TEST_ASSERT_EQUAL(0, num_calls);
-    TEST_ASSERT_EQUAL_PTR(make_context(0), context);
-    TEST_ASSERT_EQUAL_HEX(CL_MEM_READ_WRITE, flags);
+#if CL_HPP_TARGET_OPENCL_VERSION >= 120
+    cl_program program = make_program(0);
 
-    TEST_ASSERT_NOT_NULL(image_format);
-    TEST_ASSERT_EQUAL_HEX(CL_RGBA, image_format->image_channel_order);
-    TEST_ASSERT_EQUAL_HEX(CL_FLOAT, image_format->image_channel_data_type);
+    clCompileProgram_StubWithCallback(clCompileProgram_basic);
 
-    TEST_ASSERT_NOT_NULL(image_desc);
-    TEST_ASSERT_EQUAL_HEX(CL_MEM_OBJECT_IMAGE2D, image_desc->image_type);
-    TEST_ASSERT_EQUAL(64, image_desc->image_width);
-    TEST_ASSERT_EQUAL(32, image_desc->image_height);
-    TEST_ASSERT_EQUAL(256, image_desc->image_row_pitch);
-    TEST_ASSERT_EQUAL(0, image_desc->num_mip_levels);
+    // Compiling the program queries the program build log:
+    clGetProgramInfo_StubWithCallback(clGetProgramInfo_forBuildLog);
+    clGetDeviceInfo_StubWithCallback(clGetDeviceInfo_platform);
+    clGetPlatformInfo_StubWithCallback(clGetPlatformInfo_version_1_2);
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clGetProgramBuildInfo_StubWithCallback(clGetProgramBuildInfo_testGetBuildInfo);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+
+    clReleaseProgram_ExpectAndReturn(program, CL_SUCCESS);
+
+    cl::Program prog(program);
+    cl_int errcode = prog.compile("-cl-program-compile-options");
+
+    TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
+#endif
+}
+
+void testCompileProgramWithStringOptions(void)
+{
+#if CL_HPP_TARGET_OPENCL_VERSION >= 120
+    cl_program program = make_program(0);
+
+    clCompileProgram_StubWithCallback(clCompileProgram_basic);
+
+    // Compiling the program queries the program build log:
+    clGetProgramInfo_StubWithCallback(clGetProgramInfo_forBuildLog);
+    clGetDeviceInfo_StubWithCallback(clGetDeviceInfo_platform);
+    clGetPlatformInfo_StubWithCallback(clGetPlatformInfo_version_1_2);
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clGetProgramBuildInfo_StubWithCallback(clGetProgramBuildInfo_testGetBuildInfo);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+
+    clReleaseProgram_ExpectAndReturn(program, CL_SUCCESS);
+
+    cl::Program prog(program);
+    cl::string options("-cl-program-compile-options");
+    cl_int errcode = prog.compile(options);
+
+    TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
+#endif
+}
+
+static cl_int clCompileProgram_headers(
+    cl_program           program,
+    cl_uint              num_devices,
+    const cl_device_id * device_list,
+    const char *         options,
+    cl_uint              num_input_headers,
+    const cl_program *   input_headers,
+    const char **        header_include_names,
+    void (CL_CALLBACK *  pfn_notify)(cl_program program,
+                                    void * user_data),
+    void *               user_data,
+    int num_calls)
+{
+    (void) num_calls;
+
+    TEST_ASSERT_EQUAL(program, make_program(0));
+    TEST_ASSERT_EQUAL(num_devices, 0);
+    TEST_ASSERT_EQUAL(device_list, nullptr);
+    TEST_ASSERT_EQUAL_STRING(options, "");
+    TEST_ASSERT_EQUAL(num_input_headers, 2);
+    TEST_ASSERT_NOT_EQUAL(input_headers, nullptr);
+    TEST_ASSERT_NOT_EQUAL(header_include_names, nullptr);
+    TEST_ASSERT_EQUAL(input_headers[0], make_program(1));
+    TEST_ASSERT_EQUAL(input_headers[1], make_program(2));
+    TEST_ASSERT_EQUAL_STRING(header_include_names[0], "name0");
+    TEST_ASSERT_EQUAL_STRING(header_include_names[1], "name1");
+    TEST_ASSERT_EQUAL(pfn_notify, nullptr);
+    TEST_ASSERT_EQUAL(user_data, nullptr);
+
+    return CL_SUCCESS;
+}
+
+void testCompileProgramHeaders(void)
+{
+#if CL_HPP_TARGET_OPENCL_VERSION >= 120
+    cl_program program = make_program(0);
+    cl_program header0 = make_program(1);
+    cl_program header1 = make_program(2);
+
+    clCompileProgram_StubWithCallback(clCompileProgram_headers);
+
+    // Compiling the program queries the program build log:
+    clGetProgramInfo_StubWithCallback(clGetProgramInfo_forBuildLog);
+    clGetDeviceInfo_StubWithCallback(clGetDeviceInfo_platform);
+    clGetPlatformInfo_StubWithCallback(clGetPlatformInfo_version_1_2);
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clGetProgramBuildInfo_StubWithCallback(clGetProgramBuildInfo_testGetBuildInfo);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+
+    clReleaseProgram_ExpectAndReturn(program, CL_SUCCESS);
+    clReleaseProgram_ExpectAndReturn(header0, CL_SUCCESS);
+    clReleaseProgram_ExpectAndReturn(header1, CL_SUCCESS);
+
+    std::vector<cl::Program> inputHeaders;
+    inputHeaders.push_back(cl::Program(header0));
+    inputHeaders.push_back(cl::Program(header1));
+
+    std::vector<cl::string> headerIncludeNames;
+    headerIncludeNames.push_back("name0");
+    headerIncludeNames.push_back("name1");
+
+    cl::Program prog(program);
+    cl_int errcode = prog.compile("", inputHeaders, headerIncludeNames);
+
+    TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
+
+    // Clean up in a defined order
+    prog = nullptr;
+    inputHeaders[0] = nullptr;
+    inputHeaders[1] = nullptr;
+#endif
+}
+
+static cl_int clCompileProgram_devices(
+    cl_program           program,
+    cl_uint              num_devices,
+    const cl_device_id * device_list,
+    const char *         options,
+    cl_uint              num_input_headers,
+    const cl_program *   input_headers,
+    const char **        header_include_names,
+    void (CL_CALLBACK *  pfn_notify)(cl_program program,
+                                    void * user_data),
+    void *               user_data,
+    int num_calls)
+{
+    (void) num_calls;
+
+    TEST_ASSERT_EQUAL(program, make_program(0));
+    TEST_ASSERT_EQUAL(num_devices, 2);
+    TEST_ASSERT_NOT_EQUAL(device_list, nullptr);
+    TEST_ASSERT_EQUAL(device_list[0], make_device_id(0));
+    TEST_ASSERT_EQUAL(device_list[1], make_device_id(1));
+    TEST_ASSERT_EQUAL_STRING(options, "");
+    TEST_ASSERT_EQUAL(num_input_headers, 0);
+    TEST_ASSERT_EQUAL(input_headers, nullptr);
+    TEST_ASSERT_EQUAL(header_include_names, nullptr);
+    TEST_ASSERT_EQUAL(pfn_notify, nullptr);
+    TEST_ASSERT_EQUAL(user_data, nullptr);
+
+    return CL_SUCCESS;
+}
+
+void testCompileProgramDevices(void)
+{
+#if CL_HPP_TARGET_OPENCL_VERSION >= 120
+    cl_program program = make_program(0);
+    cl_device_id device0 = make_device_id(0);
+    cl_device_id device1 = make_device_id(1);
+
+    clCompileProgram_StubWithCallback(clCompileProgram_devices);
+
+    // Compiling the program queries the program build log:
+    clGetProgramInfo_StubWithCallback(clGetProgramInfo_forBuildLog);
+    clGetDeviceInfo_StubWithCallback(clGetDeviceInfo_platform);
+    clGetPlatformInfo_StubWithCallback(clGetPlatformInfo_version_1_2);
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clRetainDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clGetProgramBuildInfo_StubWithCallback(clGetProgramBuildInfo_testGetBuildInfo);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+
+    clReleaseProgram_ExpectAndReturn(program, CL_SUCCESS);
+    clReleaseDevice_ExpectAndReturn(make_device_id(0), CL_SUCCESS);
+    clReleaseDevice_ExpectAndReturn(make_device_id(1), CL_SUCCESS);
+
+    std::vector<cl::Device> deviceList;
+    deviceList.push_back(cl::Device(device0));
+    deviceList.push_back(cl::Device(device1));
+
+    cl::Program prog(program);
+    cl_int errcode = prog.compile("", deviceList);
+
+    TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
+
+    // Clean up in a defined order
+    prog = nullptr;
+    deviceList[0] = nullptr;
+    deviceList[1] = nullptr;
+#endif
+}
+
+/**
+* Stub implementation of clGetCommandQueueInfo that returns first one image then none
+*/
+static cl_int clGetSupportedImageFormats_testGetSupportedImageFormats(
+    cl_context context,
+    cl_mem_flags flags,
+    cl_mem_object_type image_type,
+    cl_uint num_entries,
+    cl_image_format *image_formats,
+    cl_uint *num_image_formats,
+    int num_calls)
+{
+    (void) context;
+    (void) flags;
+    (void) image_type;
+
+    // Catch failure case that causes error in bugzilla 13355:
+    // returns CL_INVALID_VALUE if flags or image_type are not valid, 
+    // or if num_entries is 0 and image_formats is not nullptr.
+    if (num_entries == 0 && image_formats != nullptr) {
+        return CL_INVALID_VALUE;
+    }
+    if (num_entries == 0)  {
+        // If num_entries was 0 this is the query for number
+        if (num_image_formats) {
+            if (num_calls == 0) {
+                *num_image_formats = 1;
+            }
+            else {
+                *num_image_formats = 0;
+            }
+        }
+    }
+    else {
+        // Should return something
+        TEST_ASSERT_NOT_NULL(image_formats);
+        
+        // For first call we should return one format here
+        if (num_calls == 1) {
+            TEST_ASSERT_EQUAL(num_entries, 1);
+            image_formats[0] = cl::ImageFormat(CL_RGB, CL_FLOAT);
+        }
+    }
+
+    return CL_SUCCESS;
+}
+
+void testGetSupportedImageFormats(void)
+{
+    cl_context ctx_cl = make_context(0);
+
+    clGetSupportedImageFormats_StubWithCallback(clGetSupportedImageFormats_testGetSupportedImageFormats);
+    clGetSupportedImageFormats_StubWithCallback(clGetSupportedImageFormats_testGetSupportedImageFormats);
+    clReleaseContext_ExpectAndReturn(make_context(0), CL_SUCCESS);
+
+    cl::Context ctx(ctx_cl);
+    std::vector<cl::ImageFormat> formats;
+    cl_int ret = CL_SUCCESS;
+
+    ret = ctx.getSupportedImageFormats(
+        CL_MEM_READ_WRITE,
+        CL_MEM_OBJECT_IMAGE2D,
+        &formats);
+    TEST_ASSERT_EQUAL(ret, CL_SUCCESS);
+    TEST_ASSERT_EQUAL(formats.size(), 1);
+    ret = ctx.getSupportedImageFormats(
+        CL_MEM_READ_WRITE,
+        CL_MEM_OBJECT_IMAGE2D,
+        &formats);
+    TEST_ASSERT_EQUAL(formats.size(), 0);
+    TEST_ASSERT_EQUAL(ret, CL_SUCCESS);
+}
+
+void testCreateSubDevice(void)
+{
+    // TODO
+
+}
+
+void testGetContextInfoDevices(void)
+{
+    // TODO
+}
+
+#if CL_HPP_TARGET_OPENCL_VERSION >= 200
+static cl_mem clCreateImage_testCreateImage2DFromBuffer_2_0(
+    cl_context context,
+    cl_mem_flags flags,
+    const cl_image_format *image_format,
+    const cl_image_desc *image_desc,
+    void *host_ptr,
+    cl_int *errcode_ret,
+    int num_calls)
+{
+    (void) context;
+    (void) flags;
+    (void) num_calls;
+
+    TEST_ASSERT_NOT_NULL(image_format);
+    TEST_ASSERT_NOT_NULL(image_desc);
+    TEST_ASSERT_NULL(host_ptr);
+    TEST_ASSERT_EQUAL_HEX(CL_MEM_OBJECT_IMAGE2D, image_desc->image_type);
+
+    // Return the passed buffer as the cl_mem and success for the error code
+    if (errcode_ret) {
+        *errcode_ret = CL_SUCCESS;
+    }
+    return image_desc->buffer;
+}
+#endif
+
+void testCreateImage2DFromBuffer_2_0(void)
+{
+#if CL_HPP_TARGET_OPENCL_VERSION >= 200
+    clGetContextInfo_StubWithCallback(clGetContextInfo_device);
+    clGetDeviceInfo_StubWithCallback(clGetDeviceInfo_platform);
+    clGetPlatformInfo_StubWithCallback(clGetPlatformInfo_version_2_0);
+    clCreateImage_StubWithCallback(clCreateImage_testCreateImage2DFromBuffer_2_0);
+    clReleaseMemObject_ExpectAndReturn(make_mem(0), CL_SUCCESS);
+    clReleaseContext_ExpectAndReturn(make_context(0), CL_SUCCESS);
+
+    cl_int err;
+    cl::Context context(make_context(0));
+
+    // Create buffer
+    // Create image from buffer
+    cl::Buffer buffer(make_mem(0));
+    cl::Image2D imageFromBuffer(
+        context,
+        cl::ImageFormat(CL_R, CL_FLOAT), buffer, 64, 32, 256, &err);
+
+    TEST_ASSERT_EQUAL_PTR(buffer(), imageFromBuffer());
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+
+    buffer() = nullptr;
+#endif
+}
+
+#if CL_HPP_TARGET_OPENCL_VERSION >= 200
+static cl_mem clCreateImage_testCreateImage2D_2_0(
+    cl_context context,
+    cl_mem_flags flags,
+    const cl_image_format *image_format,
+    const cl_image_desc *image_desc,
+    void *host_ptr,
+    cl_int *errcode_ret,
+    int num_calls)
+{
+    TEST_ASSERT_EQUAL(0, num_calls);
+    TEST_ASSERT_EQUAL_PTR(make_context(0), context);
+    TEST_ASSERT_EQUAL_HEX(CL_MEM_READ_WRITE, flags);
+
+    TEST_ASSERT_NOT_NULL(image_format);
+    TEST_ASSERT_EQUAL_HEX(CL_RGBA, image_format->image_channel_order);
+    TEST_ASSERT_EQUAL_HEX(CL_FLOAT, image_format->image_channel_data_type);
+
+    TEST_ASSERT_NOT_NULL(image_desc);
+    TEST_ASSERT_EQUAL_HEX(CL_MEM_OBJECT_IMAGE2D, image_desc->image_type);
+    TEST_ASSERT_EQUAL(64, image_desc->image_width);
+    TEST_ASSERT_EQUAL(32, image_desc->image_height);
+    TEST_ASSERT_EQUAL(256, image_desc->image_row_pitch);
+    TEST_ASSERT_EQUAL(0, image_desc->num_mip_levels);
     TEST_ASSERT_EQUAL(0, image_desc->num_samples);
     TEST_ASSERT_NULL(image_desc->buffer);
 
@@ -2688,7 +3179,6 @@ static cl_int clGetKernelSubGroupInfo_testSubGroups(cl_kernel kernel,
     }
     else {
         TEST_ABORT();
-        return CL_INVALID_OPERATION;
     }
 }
 #endif
@@ -3258,7 +3748,7 @@ static cl_int clGetDeviceInfo_uuid_pci_bus_info(
                 (param_name == CL_DEVICE_UUID_KHR) ? 1 :
                 (param_name == CL_DRIVER_UUID_KHR) ? 2 :
                 0;
-            for (int i = 0; i < CL_UUID_SIZE_KHR; i++) {
+            for (cl_uchar i = 0; i < CL_UUID_SIZE_KHR; i++) {
                 pUUID[i] = i + start;
             }
         }
@@ -3282,7 +3772,7 @@ static cl_int clGetDeviceInfo_uuid_pci_bus_info(
         if (param_value_size == CL_LUID_SIZE_KHR && param_value) {
             cl_uchar* pLUID = static_cast<cl_uchar*>(param_value);
             cl_uchar start = 3;
-            for (int i = 0; i < CL_LUID_SIZE_KHR; i++) {
+            for (cl_uchar i = 0; i < CL_LUID_SIZE_KHR; i++) {
                 pLUID[i] = i + start;
             }
         }
@@ -3406,18 +3896,73 @@ static cl_program clLinkProgram_testLinkProgram(cl_context context,
     TEST_ASSERT_EQUAL_PTR(context, make_context(0));
     TEST_ASSERT_EQUAL(num_devices, 0);
     TEST_ASSERT_EQUAL(device_list, nullptr);
-    TEST_ASSERT_EQUAL(options, nullptr);
+    if (options) {
+        TEST_ASSERT_EQUAL_STRING(options, "-cl-program-link-options");
+    }
     TEST_ASSERT_NOT_EQUAL(num_input_programs, 0);
     for (int i=0; i<(int)num_input_programs; i++)
         TEST_ASSERT_EQUAL_PTR(input_programs[i], make_program(i));
     TEST_ASSERT_EQUAL(pfn_notify, nullptr);
     TEST_ASSERT_EQUAL(user_data, nullptr);
 
-    *errcode_ret = CL_SUCCESS;
-    return make_program(0);
+    *errcode_ret = CL_SUCCESS;
+    return make_program(0);
+}
+
+void testLinkProgram(void)
+{
+#if CL_HPP_TARGET_OPENCL_VERSION >= 120
+    cl_int errcode;
+    int refcount[] = {1,1};
+
+    // verify if class cl::Program was not modified
+    TEST_ASSERT_EQUAL(sizeof(cl_program), sizeof(cl::Program));
+
+    clGetProgramInfo_StubWithCallback(clGetProgramInfo_testProgramGetContext);
+    clLinkProgram_StubWithCallback(clLinkProgram_testLinkProgram);
+
+    clRetainContext_ExpectAndReturn(make_context(0), CL_SUCCESS);
+    clReleaseContext_ExpectAndReturn(make_context(0), CL_SUCCESS);
+    prepare_programRefcounts(2, reinterpret_cast<cl_program *>(programPool), refcount);
+
+    cl::Program prog = cl::linkProgram(cl::Program(make_program(0)), cl::Program(make_program(1)),
+        nullptr, nullptr, nullptr, &errcode);
+
+    TEST_ASSERT_EQUAL_PTR(prog(), make_program(0));
+    TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
+
+    prog() = nullptr;
+#endif
+}
+
+void testLinkProgramWithOptions(void)
+{
+#if CL_HPP_TARGET_OPENCL_VERSION >= 120
+    cl_int errcode;
+    int refcount[] = {1,1};
+
+    // verify if class cl::Program was not modified
+    TEST_ASSERT_EQUAL(sizeof(cl_program), sizeof(cl::Program));
+
+    clGetProgramInfo_StubWithCallback(clGetProgramInfo_testProgramGetContext);
+    clLinkProgram_StubWithCallback(clLinkProgram_testLinkProgram);
+
+    clRetainContext_ExpectAndReturn(make_context(0), CL_SUCCESS);
+    clReleaseContext_ExpectAndReturn(make_context(0), CL_SUCCESS);
+    prepare_programRefcounts(2, reinterpret_cast<cl_program *>(programPool), refcount);
+
+    cl::Program prog = cl::linkProgram(
+        cl::Program(make_program(0)), cl::Program(make_program(1)),
+        "-cl-program-link-options", nullptr, nullptr, &errcode);
+
+    TEST_ASSERT_EQUAL_PTR(prog(), make_program(0));
+    TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
+
+    prog() = nullptr;
+#endif
 }
 
-void testLinkProgram(void)
+void testLinkProgramWithStringOptions(void)
 {
 #if CL_HPP_TARGET_OPENCL_VERSION >= 120
     cl_int errcode;
@@ -3433,8 +3978,10 @@ void testLinkProgram(void)
     clReleaseContext_ExpectAndReturn(make_context(0), CL_SUCCESS);
     prepare_programRefcounts(2, reinterpret_cast<cl_program *>(programPool), refcount);
 
-    cl::Program prog = cl::linkProgram(cl::Program(make_program(0)), cl::Program(make_program(1)),
-        nullptr, nullptr, nullptr, &errcode);
+    cl::string options("-cl-program-link-options");
+    cl::Program prog = cl::linkProgram(
+        cl::Program(make_program(0)), cl::Program(make_program(1)),
+        options, nullptr, nullptr, &errcode);
 
     TEST_ASSERT_EQUAL_PTR(prog(), make_program(0));
     TEST_ASSERT_EQUAL(errcode, CL_SUCCESS);
@@ -3608,6 +4155,421 @@ void testCommandBufferInfoKHRCommandQueues(void)
     TEST_ASSERT_EQUAL_PTR(make_command_queue(2), command_queues[2]());
 #endif
 }
+
+/****************************************************************************
+ * Tests for cl::MutableCommand
+ ****************************************************************************/
+
+#if defined(cl_khr_command_buffer_mutable_dispatch)
+#if CL_KHR_COMMAND_BUFFER_MUTABLE_DISPATCH_EXTENSION_VERSION <                 \
+    CL_MAKE_VERSION(0, 9, 2)
+static cl_int clUpdateMutableCommandsKHR_testCommandBufferKhrUpdateMutableCommands(
+    cl_command_buffer_khr command_buffer,
+    const cl_mutable_base_config_khr *mutable_config, int num_calls) {
+    (void)num_calls;
+    TEST_ASSERT_EQUAL(command_buffer, commandBufferKhrPool[0]());
+    TEST_ASSERT_EQUAL(mutable_config->type,
+                      CL_STRUCTURE_TYPE_MUTABLE_BASE_CONFIG_KHR);
+    return CL_SUCCESS;
+}
+#else
+static cl_int clUpdateMutableCommandsKHR_testCommandBufferKhrUpdateMutableCommands(
+    cl_command_buffer_khr command_buffer,
+    unsigned int length, const cl_command_buffer_update_type_khr* types, const void** configs,
+    int num_calls) {
+    (void)num_calls;
+    TEST_ASSERT_EQUAL(command_buffer, commandBufferKhrPool[0]());
+    TEST_ASSERT_EQUAL(length, 1u);
+    TEST_ASSERT_EQUAL(types[0], CL_STRUCTURE_TYPE_MUTABLE_DISPATCH_CONFIG_KHR);
+
+    const void* config = configs[0];
+    cl_mutable_dispatch_config_khr casted_config = *static_cast<const cl_mutable_dispatch_config_khr*>(config);
+    cl_mutable_dispatch_config_khr default_config{};
+
+    TEST_ASSERT_EQUAL(std::memcmp(&casted_config, &default_config, sizeof(cl_mutable_dispatch_config_khr)), 0);
+    return CL_SUCCESS;
+}
+#endif
+
+void testCommandBufferKhrUpdateMutableCommands(void) {
+    cl_int response = CL_INVALID_OPERATION;
+    cl_mutable_dispatch_config_khr dispatch_list{};
+#if CL_KHR_COMMAND_BUFFER_MUTABLE_DISPATCH_EXTENSION_VERSION <                 \
+    CL_MAKE_VERSION(0, 9, 2)
+    cl_mutable_base_config_khr config = {
+        CL_STRUCTURE_TYPE_MUTABLE_BASE_CONFIG_KHR, &config, 1, &dispatch_list};
+    clUpdateMutableCommandsKHR_StubWithCallback(
+        clUpdateMutableCommandsKHR_testCommandBufferKhrUpdateMutableCommands);
+    response = commandBufferKhrPool[0].updateMutableCommands(&config);
+#else
+    constexpr cl_uint num_configs = 1;
+    std::array<cl_command_buffer_update_type_khr, num_configs> config_types = {{
+            CL_STRUCTURE_TYPE_MUTABLE_DISPATCH_CONFIG_KHR
+    }};
+    std::array<const void*, num_configs> configs = {&dispatch_list};
+    clUpdateMutableCommandsKHR_StubWithCallback(
+        clUpdateMutableCommandsKHR_testCommandBufferKhrUpdateMutableCommands);
+    response = commandBufferKhrPool[0].updateMutableCommands<num_configs>(config_types, configs);
+#endif
+    TEST_ASSERT_EQUAL(CL_SUCCESS, response);
+}
+
+static cl_int clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoCommandQueue(
+    cl_mutable_command_khr command, cl_mutable_command_info_khr param_name,
+    size_t param_value_size, void* param_value, size_t* /*param_value_size_ret*/,
+    int /*num_calls*/)
+{
+    TEST_ASSERT_EQUAL(command, mutableCommandKhrPool[0]());
+    TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_COMMAND_COMMAND_QUEUE_KHR);
+    TEST_ASSERT(param_value == nullptr || param_value_size >= sizeof(cl_command_queue));
+    if (param_value != nullptr)
+    {
+        *static_cast<cl_command_queue*>(param_value) = make_command_queue(0);
+    }
+
+    return CL_SUCCESS;
+}
+
+void testMutableCommandKhrGetInfoCommandQueue(void)
+{
+    cl_int err = CL_DEVICE_NOT_FOUND;
+
+    int cmd_que_refcount = 1;
+
+    clGetMutableCommandInfoKHR_StubWithCallback(clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoCommandQueue);
+    prepare_commandQueueRefcounts(1, reinterpret_cast<cl_command_queue*>(&commandQueuePool[0]()), &cmd_que_refcount);
+
+    cl::CommandQueue command_queue = mutableCommandKhrPool[0].getInfo<CL_MUTABLE_COMMAND_COMMAND_QUEUE_KHR>(&err);
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+    TEST_ASSERT_EQUAL(commandQueuePool[0](), command_queue());
+}
+
+static cl_int clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoCommandBuffer(
+    cl_mutable_command_khr command, cl_mutable_command_info_khr param_name,
+    size_t param_value_size, void* param_value, size_t* /*param_value_size_ret*/,
+    int /*num_calls*/)
+{
+    TEST_ASSERT_EQUAL(command, mutableCommandKhrPool[0]());
+    TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_COMMAND_COMMAND_BUFFER_KHR);
+    TEST_ASSERT(param_value == nullptr || param_value_size >= sizeof(cl_command_buffer_khr));
+    if (param_value != nullptr)
+    {
+        *static_cast<cl_command_buffer_khr*>(param_value) = make_command_buffer_khr(0);
+    }
+
+    return CL_SUCCESS;
+}
+
+void testMutableCommandKhrGetInfoCommandBuffer(void)
+{
+    cl_int err = CL_DEVICE_NOT_FOUND;
+
+    int cmd_bhr_khr_refcount = 1;
+
+    clGetMutableCommandInfoKHR_StubWithCallback(clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoCommandBuffer);
+    prepare_commandBufferKhrRefcounts(1, reinterpret_cast<cl_command_buffer_khr*>(&commandBufferKhrPool[0]()), &cmd_bhr_khr_refcount);
+
+    cl::CommandBufferKhr command_buffer_khr = mutableCommandKhrPool[0].getInfo<CL_MUTABLE_COMMAND_COMMAND_BUFFER_KHR>(&err);
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+    TEST_ASSERT_EQUAL(commandBufferKhrPool[0](), command_buffer_khr());
+}
+
+static cl_int clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoPropertiesArray(
+    cl_mutable_command_khr command, cl_mutable_command_info_khr param_name,
+    size_t param_value_size, void* param_value, size_t* param_value_size_ret,
+    int num_calls)
+{
+    TEST_ASSERT_EQUAL(command, mutableCommandKhrPool[0]());
+
+#if CL_KHR_COMMAND_BUFFER_MUTABLE_DISPATCH_EXTENSION_VERSION <                 \
+    CL_MAKE_VERSION(0, 9, 2)
+  using properties_type = cl_ndrange_kernel_command_properties_khr;
+  cl_mutable_command_info_khr properties_query = CL_MUTABLE_DISPATCH_PROPERTIES_ARRAY_KHR;
+#else
+  using properties_type = cl_command_properties_khr;
+  cl_mutable_command_info_khr properties_query = CL_MUTABLE_COMMAND_PROPERTIES_ARRAY_KHR;
+#endif
+    switch (num_calls)
+    {
+    case 0:
+
+        TEST_ASSERT_EQUAL(param_name, properties_query);
+        TEST_ASSERT(param_value == nullptr || param_value_size >= 3 * sizeof(properties_type));
+        if (param_value_size_ret != nullptr)
+        {
+            *param_value_size_ret = 3 * sizeof(properties_type);
+        }
+        break;
+    case 1:
+        TEST_ASSERT_EQUAL(param_name, properties_query);
+        TEST_ASSERT(param_value == nullptr || param_value_size >= 3 * sizeof(properties_type));
+        TEST_ASSERT_EQUAL(nullptr, param_value_size_ret);
+        if (param_value != nullptr)
+        {
+            properties_type properties[] = { 1, 2, 3 };
+            for (int i = 0; i < 3; i++)
+            {
+                *(&static_cast<properties_type*>(param_value)[i]) = properties[i];
+            }
+        }
+        break;
+    }
+
+    return CL_SUCCESS;
+}
+
+void testMutableCommandKhrGetInfoPropertiesArray(void)
+{
+    cl_int err = CL_DEVICE_NOT_FOUND;
+
+    clGetMutableCommandInfoKHR_StubWithCallback(clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoPropertiesArray);
+#if CL_KHR_COMMAND_BUFFER_MUTABLE_DISPATCH_EXTENSION_VERSION <                 \
+    CL_MAKE_VERSION(0, 9, 2)
+    cl::vector<cl_ndrange_kernel_command_properties_khr> kernel_properties = mutableCommandKhrPool[0].getInfo<CL_MUTABLE_DISPATCH_PROPERTIES_ARRAY_KHR>(&err);
+#else
+    cl::vector<cl_command_properties_khr> kernel_properties = mutableCommandKhrPool[0].getInfo<CL_MUTABLE_COMMAND_PROPERTIES_ARRAY_KHR>(&err);
+#endif
+
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+    TEST_ASSERT_EQUAL(3, kernel_properties.size());
+    for (size_t i = 0; i < kernel_properties.size(); i++)
+    {
+        TEST_ASSERT_EQUAL(i + 1, kernel_properties[i]);
+    }
+}
+
+static cl_int clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoCommandType(
+    cl_mutable_command_khr command, cl_mutable_command_info_khr param_name,
+    size_t param_value_size, void* param_value, size_t* /*param_value_size_ret*/,
+    int /*num_calls*/)
+{
+    TEST_ASSERT_EQUAL(command, mutableCommandKhrPool[0]());
+    TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_COMMAND_COMMAND_TYPE_KHR);
+    TEST_ASSERT(param_value == nullptr || param_value_size >= sizeof(cl_command_type));
+    if (param_value != nullptr)
+    {
+        *static_cast<cl_command_type*>(param_value) = 0xDEAD;
+    }
+
+    return CL_SUCCESS;
+}
+
+void testMutableCommandKhrGetInfoCommandType(void)
+{
+    cl_int err = CL_DEVICE_NOT_FOUND;
+
+    clGetMutableCommandInfoKHR_StubWithCallback(clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoCommandType);
+
+    cl_command_type command_type = mutableCommandKhrPool[0].getInfo<CL_MUTABLE_COMMAND_COMMAND_TYPE_KHR>(&err);
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+    TEST_ASSERT_EQUAL(0xDEAD, command_type);
+}
+
+static cl_int clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoDispatchKernel(
+    cl_mutable_command_khr command, cl_mutable_command_info_khr param_name,
+    size_t param_value_size, void* param_value, size_t* /*param_value_size_ret*/,
+    int /*num_calls*/)
+{
+    TEST_ASSERT_EQUAL(command, mutableCommandKhrPool[0]());
+    TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_DISPATCH_KERNEL_KHR);
+    TEST_ASSERT(param_value == nullptr || param_value_size >= sizeof(cl_kernel));
+    if (param_value != nullptr)
+    {
+        *static_cast<cl_kernel*>(param_value) = make_kernel(0);
+    }
+
+    return CL_SUCCESS;
+}
+
+void testMutableCommandKhrGetInfoDispatchKernel(void)
+{
+    cl_int err = CL_DEVICE_NOT_FOUND;
+
+    clGetMutableCommandInfoKHR_StubWithCallback(clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoDispatchKernel);
+
+    cl_kernel kernel = mutableCommandKhrPool[0].getInfo<CL_MUTABLE_DISPATCH_KERNEL_KHR>(&err);
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+    TEST_ASSERT_EQUAL(make_kernel(0), kernel);
+}
+
+static cl_int clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoDispatchDimensions(
+    cl_mutable_command_khr command, cl_mutable_command_info_khr param_name,
+    size_t param_value_size, void* param_value, size_t* /*param_value_size_ret*/,
+    int /*num_calls*/)
+{
+    TEST_ASSERT_EQUAL(command, mutableCommandKhrPool[0]());
+    TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_DISPATCH_DIMENSIONS_KHR);
+    TEST_ASSERT(param_value == nullptr || param_value_size >= sizeof(cl_uint));
+    if (param_value != nullptr)
+    {
+        *static_cast<cl_uint*>(param_value) = 3;
+    }
+
+    return CL_SUCCESS;
+}
+
+void testMutableCommandKhrGetInfoDispatchDimensions(void)
+{
+    cl_int err = CL_DEVICE_NOT_FOUND;
+
+    clGetMutableCommandInfoKHR_StubWithCallback(clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoDispatchDimensions);
+
+    cl_uint dimensions = mutableCommandKhrPool[0].getInfo<CL_MUTABLE_DISPATCH_DIMENSIONS_KHR>(&err);
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+    TEST_ASSERT_EQUAL(3, dimensions);
+}
+
+static cl_int clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoGlobalWorkOffset(
+    cl_mutable_command_khr command, cl_mutable_command_info_khr param_name,
+    size_t param_value_size, void* param_value, size_t* param_value_size_ret,
+    int num_calls)
+{
+    TEST_ASSERT_EQUAL(command, mutableCommandKhrPool[0]());
+    switch (num_calls)
+    {
+    case 0:
+        TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_DISPATCH_GLOBAL_WORK_OFFSET_KHR);
+        TEST_ASSERT_EQUAL(nullptr, param_value);
+        if (param_value_size_ret != nullptr)
+        {
+            *param_value_size_ret = 3 * sizeof(cl::size_type);
+        }
+        break;
+    case 1:
+        TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_DISPATCH_GLOBAL_WORK_OFFSET_KHR);
+        TEST_ASSERT(param_value == nullptr || param_value_size >= 3 * sizeof(cl::size_type));
+        TEST_ASSERT_EQUAL(nullptr, param_value_size_ret);
+        TEST_ASSERT_NOT_NULL(param_value);
+        if (param_value != nullptr)
+        {
+            cl::size_type data[] = { 2, 3, 4 };
+            for (int i = 0; i < 3; i++)
+            {
+                *(&(static_cast<cl::size_type*>(param_value)[i])) = data[i];
+            }
+        }
+        break;
+    }
+
+    return CL_SUCCESS;
+}
+
+void testMutableCommandKhrGetInfoGlobalWorkOffset(void)
+{
+    cl_int err = CL_DEVICE_NOT_FOUND;
+
+    clGetMutableCommandInfoKHR_StubWithCallback(clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoGlobalWorkOffset);
+
+    cl::vector<cl::size_type> global_work_offset = mutableCommandKhrPool[0].getInfo<CL_MUTABLE_DISPATCH_GLOBAL_WORK_OFFSET_KHR>(&err);
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+    TEST_ASSERT_EQUAL(3, global_work_offset.size());
+    for (cl::size_type i = 0; i < global_work_offset.size(); i++)
+    {
+        TEST_ASSERT_EQUAL(i + 2, global_work_offset[i]);
+    }
+}
+
+static cl_int clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoGlobalWorkSize(
+    cl_mutable_command_khr command, cl_mutable_command_info_khr param_name,
+    size_t param_value_size, void* param_value, size_t* param_value_size_ret,
+    int num_calls)
+{
+    TEST_ASSERT_EQUAL(command, mutableCommandKhrPool[0]());
+    switch (num_calls)
+    {
+    case 0:
+        TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_DISPATCH_GLOBAL_WORK_SIZE_KHR);
+        TEST_ASSERT_EQUAL(nullptr, param_value);
+        if (param_value_size_ret != nullptr)
+        {
+            *param_value_size_ret = 3 * sizeof(cl::size_type);
+        }
+        break;
+    case 1:
+        TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_DISPATCH_GLOBAL_WORK_SIZE_KHR);
+        TEST_ASSERT(param_value == nullptr || param_value_size >= 3 * sizeof(cl::size_type));
+        TEST_ASSERT_EQUAL(nullptr, param_value_size_ret);
+        TEST_ASSERT_NOT_NULL(param_value);
+        if (param_value != nullptr)
+        {
+            cl::size_type data[] = { 3, 4, 5 };
+            for (cl::size_type i = 0; i < 3; i++)
+            {
+                *(&(static_cast<cl::size_type*>(param_value)[i])) = data[i];
+            }
+        }
+        break;
+    }
+
+    return CL_SUCCESS;
+}
+
+void testMutableCommandKhrGetInfoGlobalWorkSize(void)
+{
+    cl_int err = CL_DEVICE_NOT_FOUND;
+
+    clGetMutableCommandInfoKHR_StubWithCallback(clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoGlobalWorkSize);
+
+    cl::vector<cl::size_type> global_work_size = mutableCommandKhrPool[0].getInfo<CL_MUTABLE_DISPATCH_GLOBAL_WORK_SIZE_KHR>(&err);
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+    TEST_ASSERT_EQUAL(3, global_work_size.size());
+    for (cl::size_type i = 0; i < global_work_size.size(); i++)
+    {
+        TEST_ASSERT_EQUAL(i + 3, global_work_size[i]);
+    }
+}
+
+static cl_int clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoLocalWorkSize(
+    cl_mutable_command_khr command, cl_mutable_command_info_khr param_name,
+    size_t param_value_size, void* param_value, size_t* param_value_size_ret,
+    int num_calls)
+{
+    TEST_ASSERT_EQUAL(command, mutableCommandKhrPool[0]());
+    switch (num_calls)
+    {
+    case 0:
+        TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_DISPATCH_LOCAL_WORK_SIZE_KHR);
+        TEST_ASSERT_EQUAL(nullptr, param_value);
+        if (param_value_size_ret != nullptr)
+        {
+            *param_value_size_ret = 3 * sizeof(cl::size_type);
+        }
+        break;
+    case 1:
+        TEST_ASSERT_EQUAL(param_name, CL_MUTABLE_DISPATCH_LOCAL_WORK_SIZE_KHR);
+        TEST_ASSERT(param_value == nullptr || param_value_size >= 3 * sizeof(cl::size_type));
+        TEST_ASSERT_EQUAL(nullptr, param_value_size_ret);
+        TEST_ASSERT_NOT_NULL(param_value);
+        if (param_value != nullptr)
+        {
+            cl::size_type data[] = { 4, 5, 6 };
+            for (int i = 0; i < 3; i++)
+            {
+                *(&(static_cast<cl::size_type*>(param_value)[i])) = data[i];
+            }
+        }
+        break;
+    }
+
+    return CL_SUCCESS;
+}
+
+void testMutableCommandKhrGetInfoLocalWorkSize(void)
+{
+    cl_int err = CL_DEVICE_NOT_FOUND;
+
+    clGetMutableCommandInfoKHR_StubWithCallback(clGetMutableCommandInfoKHR_testMutableCommandKhrGetInfoLocalWorkSize);
+
+    cl::vector<cl::size_type> local_work_size = mutableCommandKhrPool[0].getInfo<CL_MUTABLE_DISPATCH_LOCAL_WORK_SIZE_KHR>(&err);
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
+    TEST_ASSERT_EQUAL(3, local_work_size.size());
+    for (cl::size_type i = 0; i < local_work_size.size(); i++)
+    {
+        TEST_ASSERT_EQUAL(i + 4, local_work_size[i]);
+    }
+}
+#endif
+
 // Tests for Device::GetInfo
 static cl_int clGetInfo_testDeviceGetInfoCLDeviceVendorId(
     cl_device_id device, cl_device_info param_name, size_t param_value_size,
@@ -3690,28 +4652,30 @@ void testDevice_GetInfo_CLDeviceName(void)
 #if defined(cl_ext_device_fission)
 static cl_int clCreateSubDevicesEXT_testDevice_createSubDevices(
     cl_device_id device_in, const cl_device_partition_property_ext *properties,
-    cl_uint n, cl_device_id *out_devices, cl_uint *num, int num_calls) {
-  cl_int ret = CL_SUCCESS;
-
-  TEST_ASSERT_EQUAL(CL_DEVICE_PARTITION_EQUALLY_EXT, *properties);
-  if(nullptr != out_devices){
-    out_devices[0] = make_device_id(0);
-  }
-  if (nullptr != num)
-  {
-      *num = 1;
-  }
-  if (device_in == make_device_id(0)) {
-    return CL_SUCCESS;
-  } else if (device_in == make_device_id(1)) {
-    return CL_INVALID_DEVICE;
-  } else {
-    return CL_SUCCESS;
-  }
+    cl_uint num_entries, cl_device_id *out_devices, cl_uint *num_devices, int cmock_num_calls)
+{
+    (void)cmock_num_calls;
+
+    TEST_ASSERT_EQUAL(CL_DEVICE_PARTITION_EQUALLY_EXT, *properties);
+    if (nullptr != out_devices && num_entries > 0) {
+        out_devices[0] = make_device_id(0);
+    }
+    if (nullptr != num_devices)
+    {
+        *num_devices = 1;
+    }
+    if (device_in == make_device_id(0)) {
+        return CL_SUCCESS;
+    }
+    else if (device_in == make_device_id(1)) {
+        return CL_INVALID_DEVICE;
+    }
+    else {
+        return CL_SUCCESS;
+    }
 }
 
-void testDevice_createSubDevices() {
-#ifndef CL_HPP_ENABLE_EXCEPTIONS
+void testDevice_createSubDevices(void) {
   const cl_device_partition_property_ext properties =
       CL_DEVICE_PARTITION_EQUALLY_EXT;
   std::vector<cl::Device> devices(1);
@@ -3724,12 +4688,13 @@ void testDevice_createSubDevices() {
 
   cl_int ret = devicePool[0].createSubDevices(&properties, &devices);
   TEST_ASSERT_EQUAL(CL_SUCCESS, ret);
+#ifndef CL_HPP_ENABLE_EXCEPTIONS
   ret = devicePool[1].createSubDevices(&properties, &devices);
   TEST_ASSERT_EQUAL(CL_INVALID_DEVICE , ret);
+#endif /*CL_HPP_ENABLE_EXCEPTIONS*/
   ret = devicePool[2].createSubDevices(&properties, &devices);
   TEST_ASSERT_EQUAL(CL_SUCCESS, ret);
   TEST_ASSERT_EQUAL(devices[0].get(), make_device_id(0));
-#endif /*CL_HPP_ENABLE_EXCEPTIONS*/
 }
 #endif /*cl_ext_device_fission*/
 
@@ -3741,7 +4706,7 @@ void testMoveAssignSemaphoreNonNull(void);
 void testMoveAssignSemaphoreNull(void);
 void testMoveConstructSemaphoreNonNull(void);
 void testMoveConstructSemaphoreNull(void);
-MAKE_MOVE_TESTS(Semaphore, make_semaphore_khr, clReleaseSemaphoreKHR, semaphorePool);
+MAKE_MOVE_TESTS(Semaphore, make_semaphore_khr, clReleaseSemaphoreKHR, semaphorePool)
 #else
 void testMoveAssignSemaphoreNonNull(void) {}
 void testMoveAssignSemaphoreNull(void) {}
@@ -4155,20 +5120,6 @@ static cl_int clGetSemaphoreHandleForTypeKHR_GetHandles(
     (void) num_calls;
 
     switch (handle_type) {
-#if defined(cl_khr_external_semaphore_dx_fence)
-    case CL_SEMAPHORE_HANDLE_D3D12_FENCE_KHR:
-    {
-        void* ret = make_external_semaphore_handle(handle_type);
-        if (handle_size == sizeof(ret) && handle_ptr) {
-            void** pHandle = static_cast<void**>(handle_ptr);
-            *pHandle = ret;
-        }
-        if (handle_size_ret) {
-            *handle_size_ret = sizeof(ret);
-        }
-        return CL_SUCCESS;
-    }
-#endif
 #if defined(cl_khr_external_semaphore_win32)
     case CL_SEMAPHORE_HANDLE_OPAQUE_WIN32_KHR:
     case CL_SEMAPHORE_HANDLE_OPAQUE_WIN32_KMT_KHR:
@@ -4229,12 +5180,6 @@ void testTemplateGetSemaphoreHandleForTypeKHR(void)
     clGetSemaphoreHandleForTypeKHR_StubWithCallback(clGetSemaphoreHandleForTypeKHR_GetHandles);
 
     cl::Semaphore semaphore;
-#if defined(cl_khr_external_semaphore_dx_fence)
-    {
-        auto handle0 = semaphore.getHandleForTypeKHR<cl::ExternalSemaphoreType::D3D12Fence>(device);
-        TEST_ASSERT_EQUAL(handle0, make_external_semaphore_handle(cl::ExternalSemaphoreType::D3D12Fence));
-    }
-#endif
 #if defined(cl_khr_external_semaphore_opaque_fd)
     {
         auto fd0 = semaphore.getHandleForTypeKHR<cl::ExternalSemaphoreType::OpaqueFd>(device);
@@ -4530,8 +5475,10 @@ static cl_mem clCreateFromGLBuffer_testgetObjectInfo(cl_context context,
                                                      cl_mem_flags flags,
                                                      cl_GLuint bufobj,
                                                      cl_int *errcode_ret,
-                                                     int num_calls)
+                                                     int cmock_num_calls)
 {
+    (void) cmock_num_calls;
+
     TEST_ASSERT_EQUAL(0, bufobj);
     TEST_ASSERT_EQUAL_PTR(make_context(0), context);
     TEST_ASSERT_EQUAL(0, flags);
@@ -4543,8 +5490,10 @@ static cl_mem clCreateFromGLBuffer_testgetObjectInfo(cl_context context,
 static cl_int clGetGLObjectInfo_testgetObjectInfo(cl_mem memobj,
                                                   cl_gl_object_type *type,
                                                   cl_GLuint *gl_object_name,
-                                                  int num)
+                                                  int cmock_num_calls)
 {
+    (void) cmock_num_calls;
+
     TEST_ASSERT_EQUAL(memobj, make_mem(0));
     *type = CL_GL_OBJECT_BUFFER;
 
@@ -4552,22 +5501,23 @@ static cl_int clGetGLObjectInfo_testgetObjectInfo(cl_mem memobj,
     return CL_SUCCESS;
 }
 
-void testgetObjectInfo() {
-    cl_mem_flags flags = 0;
-    cl_int err = 0;
-    cl_GLuint bufobj = 0;
-    cl_mem memobj = make_mem(0);
-    cl_gl_object_type type = CL_GL_OBJECT_TEXTURE2D_ARRAY;
+void testgetObjectInfo(void)
+{
     clGetGLObjectInfo_StubWithCallback(clGetGLObjectInfo_testgetObjectInfo);
     clCreateFromGLBuffer_StubWithCallback(
         clCreateFromGLBuffer_testgetObjectInfo);
     clReleaseMemObject_ExpectAndReturn(make_mem(0), CL_SUCCESS);
-    cl::BufferGL buffer(contextPool[0], flags, bufobj, &err);
 
+    cl_mem_flags flags = 0;
+    cl_GLuint bufobj = 0;
+    cl_int err = 0;
+    cl::BufferGL buffer(contextPool[0], flags, bufobj, &err);
     TEST_ASSERT_EQUAL_PTR(make_mem(0), buffer());
     TEST_ASSERT_EQUAL(CL_SUCCESS, err);
 
-    TEST_ASSERT_EQUAL(buffer.getObjectInfo(&type, &bufobj), CL_SUCCESS);
+    cl_gl_object_type type = CL_GL_OBJECT_TEXTURE2D_ARRAY;
+    err = buffer.getObjectInfo(&type, &bufobj);
+    TEST_ASSERT_EQUAL(CL_SUCCESS, err);
     TEST_ASSERT_EQUAL(type, CL_GL_OBJECT_BUFFER);
     TEST_ASSERT_EQUAL(bufobj, 0);
 }
@@ -4581,7 +5531,7 @@ static cl_int clGetHostTimer_testgetHostTimer(cl_device_id device,
     return 0;
 }
 
-void testgetHostTimer() {
+void testgetHostTimer(void) {
     cl_ulong retVal = 0;
     cl_int *error = nullptr;
 
@@ -4590,6 +5540,6 @@ void testgetHostTimer() {
     TEST_ASSERT_EQUAL(retVal, 1);
 }
 #else
-void testgetHostTimer() {}
+void testgetHostTimer(void) {}
 #endif // CL_HPP_TARGET_OPENCL_VERSION >= 210
 } // extern "C"
```

