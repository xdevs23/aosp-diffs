```diff
diff --git a/.clang-format b/.clang-format
new file mode 100644
index 0000000..d563a41
--- /dev/null
+++ b/.clang-format
@@ -0,0 +1,123 @@
+---
+Language:        Cpp
+AccessModifierOffset: -4
+AlignAfterOpenBracket: Align
+AlignConsecutiveAssignments: false
+AlignConsecutiveDeclarations: false
+AlignEscapedNewlines: Right
+AlignOperands:   false
+AlignTrailingComments: false
+AllowAllArgumentsOnNextLine: true
+AllowAllConstructorInitializersOnNextLine: true
+AllowAllParametersOfDeclarationOnNextLine: true
+AllowShortBlocksOnASingleLine: false
+AllowShortCaseLabelsOnASingleLine: true
+AllowShortFunctionsOnASingleLine: All
+AllowShortLambdasOnASingleLine: All
+AllowShortIfStatementsOnASingleLine: WithoutElse
+AllowShortLoopsOnASingleLine: true
+AlwaysBreakAfterDefinitionReturnType: None
+AlwaysBreakAfterReturnType: None
+AlwaysBreakBeforeMultilineStrings: false
+AlwaysBreakTemplateDeclarations: MultiLine
+BinPackArguments: true
+BinPackParameters: true
+BraceWrapping:
+  AfterCaseLabel:  false
+  AfterClass:      false
+  AfterControlStatement: true
+  AfterEnum:       true
+  AfterFunction:   true
+  AfterNamespace:  false
+  AfterObjCDeclaration: false
+  AfterStruct:     true
+  AfterUnion:      false
+  AfterExternBlock: false
+  BeforeCatch:     false
+  BeforeElse:      true
+  IndentBraces:    false
+  SplitEmptyFunction: false
+  SplitEmptyRecord: true
+  SplitEmptyNamespace: true
+BreakBeforeBinaryOperators: NonAssignment
+BreakBeforeBraces: Custom
+BreakBeforeInheritanceComma: false
+BreakInheritanceList: BeforeColon
+BreakBeforeTernaryOperators: true
+BreakConstructorInitializersBeforeComma: false
+BreakConstructorInitializers: BeforeColon
+BreakAfterJavaFieldAnnotations: false
+BreakStringLiterals: true
+ColumnLimit:     80
+CommentPragmas:  '^ IWYU pragma:'
+CompactNamespaces: false
+ConstructorInitializerAllOnOneLineOrOnePerLine: false
+ConstructorInitializerIndentWidth: 4
+ContinuationIndentWidth: 4
+Cpp11BracedListStyle: false
+DerivePointerAlignment: true
+DisableFormat:   false
+ExperimentalAutoDetectBinPacking: false
+FixNamespaceComments: false
+ForEachMacros:
+  - foreach
+  - Q_FOREACH
+  - BOOST_FOREACH
+IncludeBlocks:   Preserve
+IncludeCategories:
+  - Regex:           '^"(llvm|llvm-c|clang|clang-c)/'
+    Priority:        2
+  - Regex:           '^(<|"(gtest|gmock|isl|json)/)'
+    Priority:        3
+  - Regex:           '.*'
+    Priority:        1
+IncludeIsMainRegex: '(Test)?$'
+IndentCaseLabels: true
+IndentPPDirectives: None
+IndentWidth:     4
+IndentWrappedFunctionNames: false
+JavaScriptQuotes: Leave
+JavaScriptWrapImports: true
+KeepEmptyLinesAtTheStartOfBlocks: true
+MacroBlockBegin: ''
+MacroBlockEnd:   ''
+MaxEmptyLinesToKeep: 2
+NamespaceIndentation: Inner
+ObjCBinPackProtocolList: Auto
+ObjCBlockIndentWidth: 4
+ObjCSpaceAfterProperty: true
+ObjCSpaceBeforeProtocolList: true
+PenaltyBreakAssignment: 2
+PenaltyBreakBeforeFirstCallParameter: 19
+PenaltyBreakComment: 300
+PenaltyBreakFirstLessLess: 120
+PenaltyBreakString: 1000
+PenaltyBreakTemplateDeclaration: 10
+PenaltyExcessCharacter: 1000000
+PenaltyReturnTypeOnItsOwnLine: 60
+PointerAlignment: Left
+ReflowComments:  true
+SortIncludes:    false
+SortUsingDeclarations: true
+SpaceAfterCStyleCast: false
+SpaceAfterLogicalNot: false
+SpaceAfterTemplateKeyword: true
+SpaceBeforeAssignmentOperators: true
+SpaceBeforeCpp11BracedList: false
+SpaceBeforeCtorInitializerColon: false
+SpaceBeforeInheritanceColon: true
+SpaceBeforeParens: ControlStatements
+SpaceBeforeRangeBasedForLoopColon: true
+SpaceInEmptyParentheses: false
+SpacesBeforeTrailingComments: 1
+SpacesInAngles:  false
+SpacesInContainerLiterals: true
+SpacesInCStyleCastParentheses: false
+SpacesInParentheses: false
+SpacesInSquareBrackets: false
+Standard:        Cpp11
+StatementMacros:
+  - Q_UNUSED
+  - QT_REQUIRE_VERSION
+TabWidth:        4
+UseTab:          Never
diff --git a/.github/workflows/linux.yml b/.github/workflows/linux.yml
deleted file mode 100644
index 3db0d2c..0000000
--- a/.github/workflows/linux.yml
+++ /dev/null
@@ -1,221 +0,0 @@
-name: Linux
-
-on:
-  push:
-    paths-ignore:
-      - '**/*.md'
-  pull_request:
-    paths-ignore:
-      - '**/*.md'
-
-jobs:
-  compatibility:
-    runs-on: ubuntu-20.04
-    container: streamhpc/opencl-sdk-base:ubuntu-18.04-20220127
-    strategy:
-      matrix:
-        # TODO: CMake 3.0.2 is Headers minimum (and ubuntu 18.04 canonical apt repo ver), not this repo's min
-        # Replace once backport to C++14 happened
-        include:
-          # Unix Makefiles
-            # One CMake version
-            # For all compilers
-              # For all configurations
-                # For all target architectures
-          - C_COMPILER: gcc-7
-            CXX_COMPILER: g++-7
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Debug
-            BIN: 64
-          - C_COMPILER: gcc-7
-            CXX_COMPILER: g++-7
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Release
-            BIN: 64
-          - C_COMPILER: gcc-7
-            CXX_COMPILER: g++-7
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Debug
-            BIN: 32
-          - C_COMPILER: gcc-7
-            CXX_COMPILER: g++-7
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Release
-            BIN: 32
-          - C_COMPILER: gcc-11
-            CXX_COMPILER: g++-11
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Debug
-            BIN: 64
-          - C_COMPILER: gcc-11
-            CXX_COMPILER: g++-11
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Release
-            BIN: 64
-          - C_COMPILER: gcc-11
-            CXX_COMPILER: g++-11
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Debug
-            BIN: 32
-          - C_COMPILER: gcc-11
-            CXX_COMPILER: g++-11
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Release
-            BIN: 32
-          - C_COMPILER: clang-8
-            CXX_COMPILER: clang++-8
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Debug
-            BIN: 64
-          - C_COMPILER: clang-8
-            CXX_COMPILER: clang++-8
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Release
-            BIN: 64
-          - C_COMPILER: clang-8
-            CXX_COMPILER: clang++-8
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Debug
-            BIN: 32
-          - C_COMPILER: clang-8
-            CXX_COMPILER: clang++-8
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Release
-            BIN: 32
-          - C_COMPILER: clang-13
-            CXX_COMPILER: clang++-13
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Debug
-            BIN: 64
-          - C_COMPILER: clang-13
-            CXX_COMPILER: clang++-13
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Release
-            BIN: 64
-          - C_COMPILER: clang-13
-            CXX_COMPILER: clang++-13
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Debug
-            BIN: 32
-          - C_COMPILER: clang-13
-            CXX_COMPILER: clang++-13
-            CMAKE: 3.0.2
-            GEN: Unix Makefiles
-            CONFIG: Release
-            BIN: 32
-          # Multi-config generators
-            # One CMake version
-            # For all compilers
-              # For all architectures
-          - C_COMPILER: gcc-7
-            CXX_COMPILER: g++-7
-            CMAKE: 3.22.1
-            GEN: Ninja Multi-Config
-            BIN: 64
-          - C_COMPILER: gcc-7
-            CXX_COMPILER: g++-7
-            CMAKE: 3.22.1
-            GEN: Ninja Multi-Config
-            BIN: 32
-          - C_COMPILER: gcc-11
-            CXX_COMPILER: g++-11
-            CMAKE: 3.22.1
-            GEN: Ninja Multi-Config
-            BIN: 64
-          - C_COMPILER: gcc-11
-            CXX_COMPILER: g++-11
-            CMAKE: 3.22.1
-            GEN: Ninja Multi-Config
-            BIN: 32
-          - C_COMPILER: clang-8
-            CXX_COMPILER: clang++-8
-            CMAKE: 3.22.1
-            GEN: Ninja Multi-Config
-            BIN: 64
-          - C_COMPILER: clang-8
-            CXX_COMPILER: clang++-8
-            CMAKE: 3.22.1
-            GEN: Ninja Multi-Config
-            BIN: 32
-          - C_COMPILER: clang-13
-            CXX_COMPILER: clang++-13
-            CMAKE: 3.22.1
-            GEN: Ninja Multi-Config
-            BIN: 64
-          - C_COMPILER: clang-13
-            CXX_COMPILER: clang++-13
-            CMAKE: 3.22.1
-            GEN: Ninja Multi-Config
-            BIN: 32
-    env:
-      CMAKE_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/cmake
-      CTEST_EXE: /opt/Kitware/CMake/${{ matrix.CMAKE }}/bin/ctest
-
-    steps:
-    - name: Checkout OpenCL-Headers
-      uses: actions/checkout@v3
-      
-    - name: Configure
-      shell: bash
-      run: $CMAKE_EXE
-        -G "${{matrix.GEN}}"
-        -D BUILD_TESTING=ON
-        `if [[ "${{matrix.GEN}}" == "Unix Makefiles" ]]; then echo -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}; fi;`
-        -D CMAKE_C_FLAGS="-Wall -Wextra -pedantic -Werror -m${{matrix.BIN}}"
-        -D CMAKE_C_COMPILER=${{matrix.C_COMPILER}}
-        -D CMAKE_C_EXTENSIONS=OFF
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -Werror -m${{matrix.BIN}}"
-        -D CMAKE_CXX_COMPILER=${{matrix.CXX_COMPILER}}
-        -D CMAKE_CXX_EXTENSIONS=OFF
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
-        -B$GITHUB_WORKSPACE/build
-        -H$GITHUB_WORKSPACE
-
-    - name: Build
-      shell: bash
-      run: if [[ "${{matrix.GEN}}" == "Unix Makefiles" ]];
-        then
-          $CMAKE_EXE --build $GITHUB_WORKSPACE/build -- -j`nproc`;
-        else
-          $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config Debug   -- -j`nproc`;
-          $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config Release -- -j`nproc`;
-        fi;
-
-    - name: Test
-      shell: bash
-      working-directory: ${{runner.workspace}}/OpenCL-Headers/build
-      run: if [[ "${{matrix.GEN}}" == "Unix Makefiles" ]];
-        then
-          $CTEST_EXE --output-on-failure --parallel `nproc`;
-        else
-          $CTEST_EXE --output-on-failure -C Debug   --parallel `nproc`;
-          $CTEST_EXE --output-on-failure -C Release --parallel `nproc`;
-        fi;
-
-    - name: Test install
-      shell: bash
-      run: if [[ "${{matrix.GEN}}" == "Unix Makefiles" ]];
-        then
-          $CMAKE_EXE --build $GITHUB_WORKSPACE/build --target install -- -j`nproc`;
-        else
-          $CMAKE_EXE --build $GITHUB_WORKSPACE/build --target install --config Release -- -j`nproc`;
-        fi;
-
-    - name: Test pkg-config
-      shell: bash
-      run: PKG_CONFIG_PATH="$GITHUB_WORKSPACE/install/share/pkgconfig" pkg-config OpenCL-Headers --cflags | grep -q "\-I$GITHUB_WORKSPACE/install/include"
diff --git a/.github/workflows/macos.yml b/.github/workflows/macos.yml
deleted file mode 100644
index c1b2972..0000000
--- a/.github/workflows/macos.yml
+++ /dev/null
@@ -1,73 +0,0 @@
-name: MacOS
-
-on:
-  push:
-    paths-ignore:
-      - '**/*.md'
-  pull_request:
-    paths-ignore:
-      - '**/*.md'
-
-jobs:
-  compatibility:
-    runs-on: macos-11
-    strategy:
-      matrix:
-        VER: [9, 11]
-        GEN: [Xcode, Ninja Multi-Config]
-        STD: [11, 17]
-
-    steps:
-    - name: Checkout OpenCL-Headers
-      uses: actions/checkout@v3
-
-    - name: Create Build Environment
-      shell: bash
-      run: |
-        cmake -E make_directory $GITHUB_WORKSPACE/build;
-        cmake -E make_directory $GITHUB_WORKSPACE/install;
-        if [[ "${{matrix.GEN}}" == "Ninja Multi-Config" && ! `which ninja` ]]; then brew install ninja; fi;
-        # Install Ninja only if it's the selected generator and it's not available.
-        cmake --version
-
-    - name: Install gcc if required
-      run: |
-        if [[ ! `which /usr/local/bin/gcc-${{matrix.VER}}` ]]; then brew install gcc@${{matrix.VER}}; fi;
-
-    - name: Configure CMake
-      shell: bash
-      run: cmake
-        -G "${{matrix.GEN}}"
-        -D BUILD_TESTING=ON
-        -D CMAKE_C_FLAGS="-Wall -Wextra -pedantic -Werror"
-        -D CMAKE_C_COMPILER=/usr/local/bin/gcc-${{matrix.VER}}
-        -D CMAKE_C_EXTENSIONS=OFF
-        -D CMAKE_CXX_FLAGS="-Wall -Wextra -pedantic -Werror"
-        -D CMAKE_CXX_COMPILER=/usr/local/bin/g++-${{matrix.VER}}
-        -D CMAKE_CXX_EXTENSIONS=OFF
-        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
-        -S $GITHUB_WORKSPACE
-        -B $GITHUB_WORKSPACE/build
-
-    - name: Build
-      shell: bash
-      run: |
-        cmake --build $GITHUB_WORKSPACE/build --config Release --parallel `sysctl -n hw.logicalcpu` `if [[ "${{matrix.GEN}}" == "Xcode" ]]; then echo "-- -quiet"; fi;`
-        cmake --build $GITHUB_WORKSPACE/build --config Debug   --parallel `sysctl -n hw.logicalcpu` `if [[ "${{matrix.GEN}}" == "Xcode" ]]; then echo "-- -quiet"; fi;`
-
-    - name: Test
-      working-directory: ${{runner.workspace}}/OpenCL-Headers/build
-      shell: bash
-      run: |
-        ctest -C Release --output-on-failure --parallel `sysctl -n hw.logicalcpu`
-        ctest -C Debug   --output-on-failure --parallel `sysctl -n hw.logicalcpu`
-
-    - name: Test install
-      shell: bash
-      run: cmake --build $GITHUB_WORKSPACE/build --target install --config Release
-
-    - name: Test pkg-config
-      shell: bash
-      run: |
-        if [[ ! `which pkg-config` ]]; then brew install pkg-config; fi;
-        PKG_CONFIG_PATH="$GITHUB_WORKSPACE/install/share/pkgconfig" pkg-config OpenCL-Headers --cflags | grep -q "\-I$GITHUB_WORKSPACE/install/include"
diff --git a/.github/workflows/presubmit.yml b/.github/workflows/presubmit.yml
new file mode 100644
index 0000000..ea35945
--- /dev/null
+++ b/.github/workflows/presubmit.yml
@@ -0,0 +1,651 @@
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
+  format:
+    name: Code formatting
+    runs-on: ubuntu-latest
+    defaults:
+      run:
+        shell: bash
+    steps:
+    - uses: actions/checkout@v4
+      with:
+        # repository: ${{github.repository}} (default)
+        fetch-depth: 0
+    - name: Install clang-format
+      run: sudo apt-get install clang-format
+    - name: Check format
+      run: $GITHUB_WORKSPACE/scripts/check-format.sh
+        origin/`if [[ "${{github.event_name}}" == "push" ]]; then echo "main"; else echo "${{github.base_ref}}"; fi`
+        --binary clang-format
+
+  linux:
+    runs-on: ubuntu-latest
+    needs: format
+    defaults:
+      run:
+        shell: bash
+    strategy:
+      matrix:
+        CMAKE: [3.26.4]
+        COMPILER:
+        - C_NAME: gcc
+          CXX_NAME: g++
+          VER: 11
+        - C_NAME: gcc
+          CXX_NAME: g++
+          VER: 13
+        - C_NAME: clang
+          CXX_NAME: clang++
+          VER: 14
+        - C_NAME: clang
+          CXX_NAME: clang++
+          VER: 16
+        BIN: [64]
+        STD: [99, 11, 17]
+        CONF:
+        - GEN: Unix Makefiles
+          CONFIG: Debug
+        - GEN: Unix Makefiles
+          CONFIG: Release
+        - GEN: Ninja Multi-Config
+          CONFIG: Release
+        IMAGE:
+        - khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-22.04.20230717
+        include:
+        - CMAKE: system
+          COMPILER:
+            C_NAME: gcc
+            CXX_NAME: g++
+            VER: 9
+          BIN: 64
+          STD: 99
+          CONF:
+            GEN: Unix Makefiles
+            CONFIG: Debug
+          IMAGE: khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-20.04.20230717
+        - CMAKE: system
+          COMPILER:
+            C_NAME: gcc
+            CXX_NAME: g++
+            VER: 9
+          BIN: 64
+          STD: 99
+          CONF:
+            GEN: Unix Makefiles
+            CONFIG: Release
+          IMAGE: khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-20.04.20230717
+        - CMAKE: system
+          COMPILER:
+            C_NAME: gcc
+            CXX_NAME: g++
+            VER: 9
+          BIN: 32
+          STD: 99
+          CONF:
+            GEN: Unix Makefiles
+            CONFIG: Debug
+          IMAGE: khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-20.04.20230717
+        - CMAKE: system
+          COMPILER:
+            C_NAME: gcc
+            CXX_NAME: g++
+            VER: 9
+          BIN: 32
+          STD: 99
+          CONF:
+            GEN: Unix Makefiles
+            CONFIG: Release
+          IMAGE: khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-20.04.20230717
+        - CMAKE: system
+          COMPILER:
+            C_NAME: gcc
+            CXX_NAME: g++
+            VER: 11
+          BIN: 64
+          STD: 99
+          CONF:
+            GEN: Unix Makefiles
+            CONFIG: Debug
+          IMAGE: khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-22.04.20230717
+        - CMAKE: system
+          COMPILER:
+            C_NAME: gcc
+            CXX_NAME: g++
+            VER: 11
+          BIN: 64
+          STD: 99
+          CONF:
+            GEN: Unix Makefiles
+            CONFIG: Release
+          IMAGE: khronosgroup/docker-images:opencl-sdk-intelcpu-ubuntu-22.04.20230717
+    container: ${{matrix.IMAGE}}
+    env:
+      CMAKE_EXE: /opt/Kitware/CMake/${{matrix.CMAKE}}/bin/cmake
+      CPACK_EXE: /opt/Kitware/CMake/${{matrix.CMAKE}}/bin/cpack
+      CTEST_EXE: /opt/Kitware/CMake/${{matrix.CMAKE}}/bin/ctest
+      CC: ${{matrix.COMPILER.C_NAME}}-${{matrix.COMPILER.VER}}
+      CXX: ${{matrix.COMPILER.CXX_NAME}}-${{matrix.COMPILER.VER}}
+      CFLAGS: -Wall -Wextra -pedantic -Werror -m${{matrix.BIN}}
+
+    steps:
+    - name: Install system CMake
+      if: ${{matrix.CMAKE}} == 'system'
+      run: apt-get update -qq && apt-get install -y cmake &&
+        echo "CMAKE_EXE=cmake" >> "$GITHUB_ENV" &&
+        echo "CPACK_EXE=cpack" >> "$GITHUB_ENV" &&
+        echo "CTEST_EXE=ctest" >> "$GITHUB_ENV"
+
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+
+    - name: Configure
+      run: $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        -D BUILD_TESTING=ON
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D CMAKE_C_STANDARD=${{matrix.STD}}
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
+        -D CPACK_PACKAGING_INSTALL_PREFIX=/usr
+        -S $GITHUB_WORKSPACE
+        -B $GITHUB_WORKSPACE/build
+
+    - name: Build
+      run: if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build --parallel `nproc`;
+        else
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config Debug;
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build --config Release;
+        fi;
+
+    - name: Test
+      working-directory: ${{runner.workspace}}/OpenCL-Headers/build
+      run: if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CTEST_EXE --output-on-failure --no-tests=error --parallel `nproc`;
+        else
+          $CTEST_EXE --output-on-failure --no-tests=error -C Debug   --parallel `nproc`;
+          $CTEST_EXE --output-on-failure --no-tests=error -C Release --parallel `nproc`;
+        fi;
+
+    - name: Package DEB
+      run: $CPACK_EXE
+        --config "$GITHUB_WORKSPACE/build/CPackConfig.cmake"
+        -G DEB
+        -C Release
+        -B "$GITHUB_WORKSPACE/package-deb"
+
+    - name: Consume (DEB)
+      run: dpkg -i $GITHUB_WORKSPACE/package-deb/*.deb &&
+        $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D CMAKE_C_STANDARD=${{matrix.STD}}
+        -D CMAKE_C_EXTENSIONS=OFF
+        -S $GITHUB_WORKSPACE/tests/pkgconfig/bare
+        -B $GITHUB_WORKSPACE/build_package &&
+        if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_package --parallel `nproc`;
+        else
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_package --config Debug;
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_package --config Release;
+        fi
+
+    - name: Run consume test (DEB)
+      if: matrix.BIN != 32
+      working-directory: ${{runner.workspace}}/OpenCL-Headers/build_package
+      run: if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CTEST_EXE -C ${{matrix.CONF.CONFIG}} --output-on-failure --no-tests=error --parallel `nproc`;
+        else
+          $CTEST_EXE -C Debug --output-on-failure --no-tests=error --parallel `nproc`;
+          $CTEST_EXE -C Release --output-on-failure --no-tests=error --parallel `nproc`;
+        fi
+
+    - name: Test pkg-config (DEB)
+      run: |
+        # First check if OpenCL-Headers is locatable
+        pkg-config OpenCL-Headers --cflags
+        # /usr/include is already on the include search path,
+        # we expect no output
+        if [[ "$(pkg-config OpenCL-Headers --cflags)" ]];
+        then
+          exit 1;
+        fi;
+
+    - name: Uninstall (DEB)
+      run: apt-get remove -y opencl-c-headers
+
+    - name: Test install
+      run: $CMAKE_EXE --build $GITHUB_WORKSPACE/build --target install --config ${{matrix.CONF.CONFIG}} --parallel `nproc`
+
+    - name: Consume (install)
+      run: $CMAKE_EXE
+        -G "${{matrix.CONF.GEN}}"
+        `if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]]; then echo "-D CMAKE_BUILD_TYPE=${{matrix.CONF.CONFIG}}"; fi`
+        -D CMAKE_C_STANDARD=${{matrix.STD}}
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_PREFIX_PATH=$GITHUB_WORKSPACE/install
+        -S $GITHUB_WORKSPACE/tests/pkgconfig/bare
+        -B $GITHUB_WORKSPACE/build_install &&
+        if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_install --parallel `nproc`;
+        else
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_install --config Debug;
+          $CMAKE_EXE --build $GITHUB_WORKSPACE/build_install --config Release;
+        fi;
+
+    - name: Run consume test (DEB)
+      if: matrix.BIN != 32
+      working-directory: ${{runner.workspace}}/OpenCL-Headers/build_install
+      run: if [[ "${{matrix.CONF.GEN}}" == "Unix Makefiles" ]];
+        then
+          $CTEST_EXE -C ${{matrix.CONF.CONFIG}} --output-on-failure --no-tests=error --parallel `nproc`;
+        else
+          $CTEST_EXE -C Debug --output-on-failure --no-tests=error --parallel `nproc`;
+          $CTEST_EXE -C Release --output-on-failure --no-tests=error --parallel `nproc`;
+        fi
+
+    - name: Test pkg-config (install)
+      run: PKG_CONFIG_PATH=$GITHUB_WORKSPACE/install/share/pkgconfig
+        pkg-config OpenCL-Headers --cflags | grep -q "\-I$GITHUB_WORKSPACE/install/include"
+
+  windows:
+    runs-on: windows-latest
+    needs: format
+    defaults:
+      run:
+        shell: pwsh
+    strategy:
+      matrix:
+        VER: [v142, v143, clangcl]
+        GEN: [Visual Studio 17 2022, Ninja Multi-Config]
+        BIN: [x64]
+        STD: [99, 11, 17]
+        exclude:
+        - VER: clangcl
+          GEN: Ninja Multi-Config
+        include:
+        - VER: v142
+          GEN: Visual Studio 17 2022
+          BIN: x86
+          STD: 99
+    env:
+      NINJA_URL: https://github.com/ninja-build/ninja/releases/download/v1.10.2/ninja-win.zip
+      NINJA_ROOT: C:\Tools\Ninja
+      VS_ROOT: 'C:\Program Files\Microsoft Visual Studio\2022\Enterprise'
+      UseMultiToolTask: true # Better parallel MSBuild execution
+      EnforceProcessCountAcrossBuilds: 'true' # -=-
+      MultiProcMaxCount: '3'                  # -=-
+      CFLAGS: /W4 /WX
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
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+
+    - name: Configure (MSBuild)
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -A ${BIN} `
+          -T ${{matrix.VER}} `
+          -D BUILD_TESTING=ON `
+          -D CMAKE_C_STANDARD=${{matrix.STD}} `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_C_STANDARD_REQUIRED=ON `
+          -S "${env:GITHUB_WORKSPACE}" `
+          -B "${env:GITHUB_WORKSPACE}\build"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-Headers failed." }
+
+    - name: Configure (Ninja Multi-Config)
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
+          -D BUILD_TESTING=ON `
+          -D CMAKE_C_STANDARD=${{matrix.STD}} `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_C_STANDARD_REQUIRED=ON `
+          -D CMAKE_EXE_LINKER_FLAGS='/INCREMENTAL' `
+          -S "${env:GITHUB_WORKSPACE}" `
+          -B "${env:GITHUB_WORKSPACE}\build"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-Headers failed." }
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
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-Headers in $Config failed." }
+        }
+
+    - name: Build (Ninja Multi-Config)
+      if: matrix.GEN == 'Ninja Multi-Config'
+      run: |
+        $VER = switch ('${{matrix.VER}}') { `
+          'v142' {'14.2'} `
+          'v143' {'14.4'} }
+        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
+        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=${VER}"
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\build" `
+            --config ${Config} `
+            -- `
+            -j ${env:NUMBER_OF_PROCESSORS}
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-Headers in $Config failed." }
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
+          if ($LASTEXITCODE -ne 0) { throw "OpenCL-Headers tests in $Config failed." }
+        }
+
+    - name: Install
+      run: |
+        & cmake `
+          --install "${env:GITHUB_WORKSPACE}\build" `
+          --prefix "${env:GITHUB_WORKSPACE}\install" `
+          --config Release
+        if ($LASTEXITCODE -ne 0) { throw "OpenCL-Headers install failed." }
+
+    - name: "Consume (MSBuild standalone): Configure/Build/Test"
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -A ${BIN} `
+          -T ${{matrix.VER}} `
+          -D CMAKE_C_STANDARD=${{matrix.STD}} `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_C_STANDARD_REQUIRED=ON `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\install" `
+          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\bare" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-Headers standalone consume test failed." }
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare" `
+            --config ${Config} `
+            -- `
+            /verbosity:minimal `
+            /maxCpuCount `
+            /noLogo
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-Headers standalone consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare
+          & ctest --output-on-failure --no-tests=error -C $Config
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-Headers standalone consume test in $Config failed." }
+        }
+
+    - name: "Consume (Ninja Multi-Config standalone): Configure/Build/Test"
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
+          -D BUILD_TESTING=ON `
+          -D CMAKE_C_STANDARD=${{matrix.STD}} `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_C_STANDARD_REQUIRED=ON `
+          -D CMAKE_EXE_LINKER_FLAGS='/INCREMENTAL' `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\install" `
+          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\bare" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-Headers standalone consume test failed." }
+        foreach ($Config in 'Release','Debug') {
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare" `
+            --config ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-Headers standalone consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare
+          & ctest --output-on-failure --no-tests=error -C $Config
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-Headers standalone consume test in $Config failed." }
+        }
+
+    - name: Consume (Emulate SDK presence)
+      run: |
+        New-Item -Type Directory -Path ${env:GITHUB_WORKSPACE}\install\share\cmake\OpenCL
+        New-Item -Type File -Path ${env:GITHUB_WORKSPACE}\install\share\cmake\OpenCL\OpenCLConfig.cmake -Value 'include("${CMAKE_CURRENT_LIST_DIR}/../OpenCLHeaders/OpenCLHeadersTargets.cmake")'
+
+    - name: "Consume (MSBuild SDK): Configure/Build/Test"
+      if: matrix.GEN == 'Visual Studio 17 2022'
+      run: |
+        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
+        & cmake `
+          -G '${{matrix.GEN}}' `
+          -A ${BIN} `
+          -T ${{matrix.VER}} `
+          -D CMAKE_C_STANDARD=${{matrix.STD}} `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_C_STANDARD_REQUIRED=ON `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\install" `
+          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\sdk" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk"
+        if ($LASTEXITCODE -ne 0) { throw "Configuring OpenCL-Headers in-SDK consume test failed." }
+        foreach ($Config in 'Release','Debug') {
+          cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk" `
+            --config ${Config} `
+            -- `
+            /verbosity:minimal `
+            /maxCpuCount `
+            /noLogo
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-Headers in-SDK consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk
+          & ctest --output-on-failure --no-tests=error -C $Config
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-Headers in-SDK consume test in $Config failed." }
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
+          -D BUILD_TESTING=ON `
+          -D CMAKE_C_STANDARD=${{matrix.STD}} `
+          -D CMAKE_C_EXTENSIONS=OFF `
+          -D CMAKE_C_STANDARD_REQUIRED=ON `
+          -D CMAKE_EXE_LINKER_FLAGS='/INCREMENTAL' `
+          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\install" `
+          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\sdk" `
+          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk"
+        foreach ($Config in 'Release','Debug') { `
+          & cmake `
+            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk" `
+            --config ${Config}
+          if ($LASTEXITCODE -ne 0) { throw "Building OpenCL-Headers in-SDK consume test in $Config failed." }
+          & cd ${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk
+          & ctest --output-on-failure --no-tests=error -C $Config
+          if ($LASTEXITCODE -ne 0) { throw "Running OpenCL-Headers in-SDK consume test in $Config failed." }
+        }
+
+  macos:
+    runs-on: macos-latest
+    needs: format
+    defaults:
+      run:
+        shell: bash
+    strategy:
+      matrix:
+        COMPILER:
+        - CC: /usr/bin/clang
+          CXX: /usr/bin/clang++
+        # Disabled due to "Could not find compiler set in environment variable CC: gcc-11.
+        # - CC: gcc-11
+        #   CXX: g++-11
+        # Disabled due to problems with the __API_AVAILABLE macro
+        # - CC: gcc-13
+        #   CXX: g++-13
+        GEN:
+        - Xcode
+        - Ninja Multi-Config
+        STD: [99, 11, 17]
+        exclude:
+        # These entries are excluded, since XCode selects its own compiler
+        - COMPILER:
+            CC: gcc-11
+            CXX: g++-11
+          GEN: Xcode
+        - COMPILER:
+            CC: gcc-13
+            CXX: g++-13
+          GEN: Xcode
+    env:
+      CFLAGS: -Wall -Wextra -pedantic -Werror
+      CC: ${{matrix.COMPILER.CC}}
+      CXX: ${{matrix.COMPILER.CXX}}
+    steps:
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+
+    - name: Create Build Environment
+      run: |
+        # Install Ninja only if it's the selected generator and it's not available.
+        if [[ "${{matrix.GEN}}" == "Ninja Multi-Config" && ! `which ninja` ]]; then brew install ninja; fi;
+        if [[ ! `which pkg-config` ]]; then brew install pkg-config; fi &&
+        cmake --version
+
+    - name: Configure
+      run: cmake
+        -G "${{matrix.GEN}}"
+        -D BUILD_TESTING=ON
+        -D CMAKE_C_STANDARD=${{matrix.STD}}
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_C_STANDARD_REQUIRED=ON
+        -D CMAKE_INSTALL_PREFIX=$GITHUB_WORKSPACE/install
+        -S $GITHUB_WORKSPACE
+        -B $GITHUB_WORKSPACE/build
+
+    - name: Build
+      run: |
+        cmake --build $GITHUB_WORKSPACE/build --config Release --parallel `sysctl -n hw.logicalcpu`
+        cmake --build $GITHUB_WORKSPACE/build --config Debug   --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Test
+      working-directory: ${{runner.workspace}}/OpenCL-Headers/build
+      run: |
+        ctest -C Release --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu`
+        ctest -C Debug   --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Test install
+      run: cmake --build $GITHUB_WORKSPACE/build --target install --config Release
+
+    - name: Consume (install)
+      run: cmake
+        -G "${{matrix.GEN}}"
+        -D CMAKE_C_STANDARD=${{matrix.STD}}
+        -D CMAKE_C_EXTENSIONS=OFF
+        -D CMAKE_C_STANDARD_REQUIRED=ON
+        -D CMAKE_PREFIX_PATH="$GITHUB_WORKSPACE/install"
+        -S $GITHUB_WORKSPACE/tests/pkgconfig/bare
+        -B $GITHUB_WORKSPACE/build_install &&
+        cmake --build $GITHUB_WORKSPACE/build_install --config Release --parallel `sysctl -n hw.logicalcpu` &&
+        cmake --build $GITHUB_WORKSPACE/build_install --config Debug --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Run consume test (install)
+      working-directory: ${{runner.workspace}}/OpenCL-Headers/build_install
+      run: |
+        ctest -C Release --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu`
+        ctest -C Debug --output-on-failure --no-tests=error --parallel `sysctl -n hw.logicalcpu`
+
+    - name: Test pkg-config
+      run: export PKG_CONFIG_PATH="$GITHUB_WORKSPACE/install/share/pkgconfig" &&
+        pkg-config OpenCL-Headers --cflags | grep -q "\-I$GITHUB_WORKSPACE/install/include"
+
+  android:
+    runs-on: ubuntu-latest
+    needs: format
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
+    - name: Checkout OpenCL-Headers
+      uses: actions/checkout@v4
+
+    - name: Configure
+      run: cmake
+        -G "Unix Makefiles"
+        -D BUILD_TESTING=ON
+        -D CMAKE_BUILD_TYPE=${{matrix.CONFIG}}
+        -D CMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake
+        -D ANDROID_ABI=${{matrix.ABI}}
+        -D ANDROID_PLATFORM=${{matrix.API_LEVEL}}
+        -S $GITHUB_WORKSPACE
+        -B $GITHUB_WORKSPACE/build
+
+    - name: Build
+      run: cmake --build $GITHUB_WORKSPACE/build --parallel `nproc`
diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
new file mode 100644
index 0000000..666e254
--- /dev/null
+++ b/.github/workflows/release.yml
@@ -0,0 +1,71 @@
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
+    - name: Install prerequisites
+      run: sudo apt-get update -qq && sudo apt-get install -y cmake devscripts debhelper-compat=13
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
+        -S $GITHUB_WORKSPACE/OpenCL-Headers*
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
+        -P $GITHUB_WORKSPACE/OpenCL-Headers*/cmake/DebSourcePkg.cmake
+
+    - name: Build source package
+      run: |
+        cd $GITHUB_WORKSPACE/OpenCL-Headers*/
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
index 4def21d..0000000
--- a/.github/workflows/windows.yml
+++ /dev/null
@@ -1,253 +0,0 @@
-name: Windows
-
-on:
-  push:
-    paths-ignore:
-      - '**/*.md'
-  pull_request:
-    paths-ignore:
-      - '**/*.md'
-
-jobs:
-  compatibility:
-    runs-on: windows-latest
-    strategy:
-      matrix:
-        VER: [v142, v143]
-        EXT: [ON, OFF]
-        GEN: [Visual Studio 17 2022]
-        BIN: [x64, x86]
-        STD: [99, 11, 17]
-        include:
-          - VER: v141
-            EXT: OFF
-            GEN: Ninja Multi-Config
-            BIN: x64
-            STD: 89 # /Za
-    env:
-      NINJA_URL: https://github.com/ninja-build/ninja/releases/download/v1.10.2/ninja-win.zip
-      NINJA_ROOT: C:\Tools\Ninja
-      VS_ROOT: 'C:\Program Files\Microsoft Visual Studio\2022\Enterprise'
-      UseMultiToolTask: true # Better parallel MSBuild execution
-
-    steps:
-    - uses: actions/checkout@v3
-
-    - name: Cache Ninja install
-      if: matrix.GEN == 'Ninja Multi-Config'
-      id: ninja-install
-      uses: actions/cache@v2
-      with:
-        path: |
-          C:\Tools\Ninja
-        key: ${{runner.os}}-ninja-${{env.NINJA_URL}}
-
-    - name: Install Ninja
-      if: matrix.GEN == 'Ninja Multi-Config' && steps.ninja-install.outputs.cache-hit != 'true'
-      shell: pwsh
-      run: |
-        Invoke-WebRequest ${env:NINJA_URL} -OutFile ~\Downloads\ninja-win.zip
-        Expand-Archive ~\Downloads\ninja-win.zip -DestinationPath ${env:NINJA_ROOT}\
-        Remove-Item ~\Downloads\*
-
-    - name: Configure (MSBuild)
-      if: matrix.GEN == 'Visual Studio 17 2022'
-      shell: pwsh
-      run: |
-        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
-        $C_FLAGS = '/W4 /WX'
-        & cmake `
-          -G '${{matrix.GEN}}' `
-          -A $BIN `
-          -T ${{matrix.VER}} `
-          -D BUILD_TESTING=ON `
-          -D CMAKE_C_FLAGS="${C_FLAGS}" `
-          -D CMAKE_C_EXTENSIONS='${{matrix.EXT}}' `
-          -S "${env:GITHUB_WORKSPACE}" `
-          -B "${env:GITHUB_WORKSPACE}\build"
-
-    - name: Configure (Ninja Multi-Config)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: pwsh
-      run: |
-        $VER = switch ('${{matrix.VER}}') { `
-          'v141' {'14.1'} `
-          'v142' {'14.2'} `
-          'v143' {'14.3'} }
-        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
-        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=${VER}"
-        $C_FLAGS = '/W4 /WX'
-        & cmake `
-          -G '${{matrix.GEN}}' `
-          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe" `
-          -D BUILD_TESTING=ON `
-          -D CMAKE_C_FLAGS="${C_FLAGS}" `
-          -D CMAKE_C_EXTENSIONS='${{matrix.EXT}}' `
-          -D CMAKE_EXE_LINKER_FLAGS='/INCREMENTAL' `
-          -S "${env:GITHUB_WORKSPACE}" `
-          -B "${env:GITHUB_WORKSPACE}\build"
-
-    - name: Build (MSBuild)
-      if: matrix.GEN == 'Visual Studio 17 2022'
-      shell: pwsh
-      run: |
-        foreach ($Config in 'Release','Debug') { `
-          & cmake `
-            --build "${env:GITHUB_WORKSPACE}\build" `
-            --config ${Config} `
-            -- `
-            /verbosity:minimal `
-            /maxCpuCount `
-            /noLogo
-        }
-
-    - name: Build (Ninja)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: pwsh
-      run: |
-        $VER = switch ('${{matrix.VER}}') { `
-          'v141' {'14.1'} `
-          'v142' {'14.2'} `
-          'v143' {'14.3'} }
-        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
-        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=${VER}"
-        foreach ($Config in 'Release','Debug') { `
-          & cmake `
-            --build "${env:GITHUB_WORKSPACE}\build" `
-            --config ${Config} `
-            -- `
-            -j ${env:NUMBER_OF_PROCESSORS}
-        }
-
-    - name: Test
-      shell: pwsh
-      run: |
-        foreach ($Config in 'Release','Debug') { `
-          & ctest `
-            --test-dir "${env:GITHUB_WORKSPACE}\build" `
-            --build-config ${Config} `
-            --output-on-failure `
-            --parallel ${env:NUMBER_OF_PROCESSORS}
-        }
-
-    - name: Install
-      shell: pwsh
-      run: |
-        & cmake `
-          --install "${env:GITHUB_WORKSPACE}\build" `
-          --prefix "${env:GITHUB_WORKSPACE}\install" `
-          --config Release
-
-    - name: Consume (PkgConfig - bare MSBuild)
-      if: matrix.GEN == 'Visual Studio 17 2022'
-      shell: pwsh
-      run: |
-        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
-        $C_FLAGS = '/W4 /WX'
-        & cmake `
-          -G '${{matrix.GEN}}' `
-          -A $BIN `
-          -T ${{matrix.VER}} `
-          -D CMAKE_C_FLAGS="${C_FLAGS}" `
-          -D CMAKE_C_EXTENSIONS='${{matrix.EXT}}' `
-          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\install" `
-          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\bare" `
-          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare"
-        foreach ($Config in 'Release','Debug') { `
-          & cmake `
-            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare" `
-            --config ${Config} `
-            -- `
-            /verbosity:minimal `
-            /maxCpuCount `
-            /noLogo `
-        }
-
-    - name: Consume (PkgConfig - bare Ninja)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: pwsh
-      run: |
-        $VER = switch ('${{matrix.VER}}') { `
-          'v141' {'14.1'} `
-          'v142' {'14.2'} `
-          'v143' {'14.3'} }
-        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
-        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=${VER}"
-        $C_FLAGS = '/W4 /WX'
-        & cmake `
-          -G '${{matrix.GEN}}' `
-          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe" `
-          -D BUILD_TESTING=ON `
-          -D CMAKE_C_FLAGS="${C_FLAGS}" `
-          -D CMAKE_C_EXTENSIONS='${{matrix.EXT}}' `
-          -D CMAKE_EXE_LINKER_FLAGS='/INCREMENTAL' `
-          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\install" `
-          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\bare" `
-          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare"
-        foreach ($Config in 'Release','Debug') { `
-          & cmake `
-            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\bare" `
-            --config ${Config} `
-            -- `
-            -j ${env:NUMBER_OF_PROCESSORS} `
-        }
-
-    - name: Consume (Emulate SDK presence)
-      shell: pwsh
-      run: |
-        New-Item -Type Directory -Path ${env:GITHUB_WORKSPACE}\install\share\cmake\OpenCL
-        New-Item -Type File -Path ${env:GITHUB_WORKSPACE}\install\share\cmake\OpenCL\OpenCLConfig.cmake -Value 'include("${CMAKE_CURRENT_LIST_DIR}/../OpenCLHeaders/OpenCLHeadersTargets.cmake")'
-
-    - name: Consume (PkgConfig - SDK MSBuild)
-      if: matrix.GEN == 'Visual Studio 17 2022'
-      shell: pwsh
-      run: |
-        $BIN = if('${{matrix.BIN}}' -eq 'x86') {'Win32'} else {'x64'}
-        $C_FLAGS = '/W4 /WX'
-        & cmake `
-          -G '${{matrix.GEN}}' `
-          -A $BIN `
-          -T ${{matrix.VER}} `
-          -D CMAKE_C_FLAGS="${C_FLAGS}" `
-          -D CMAKE_C_EXTENSIONS='${{matrix.EXT}}' `
-          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\install" `
-          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\sdk" `
-          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk"
-        foreach ($Config in 'Release','Debug') { `
-          & cmake `
-            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk" `
-            --config ${Config} `
-            -- `
-            /verbosity:minimal `
-            /maxCpuCount `
-            /noLogo `
-        }
-
-    - name: Consume (PkgConfig - SDK Ninja)
-      if: matrix.GEN == 'Ninja Multi-Config'
-      shell: pwsh
-      run: |
-        $VER = switch ('${{matrix.VER}}') { `
-          'v141' {'14.1'} `
-          'v142' {'14.2'} `
-          'v143' {'14.3'} }
-        Import-Module "${env:VS_ROOT}\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
-        Enter-VsDevShell -VsInstallPath ${env:VS_ROOT} -SkipAutomaticLocation -DevCmdArguments "-host_arch=x64 -arch=${{matrix.BIN}} -vcvars_ver=${VER}"
-        $C_FLAGS = '/W4 /WX'
-        & cmake `
-          -G '${{matrix.GEN}}' `
-          -D CMAKE_MAKE_PROGRAM="${env:NINJA_ROOT}\ninja.exe" `
-          -D BUILD_TESTING=ON `
-          -D CMAKE_C_FLAGS="${C_FLAGS}" `
-          -D CMAKE_C_EXTENSIONS='${{matrix.EXT}}' `
-          -D CMAKE_EXE_LINKER_FLAGS='/INCREMENTAL' `
-          -D CMAKE_PREFIX_PATH="${env:GITHUB_WORKSPACE}\install" `
-          -S "${env:GITHUB_WORKSPACE}\tests\pkgconfig\sdk" `
-          -B "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk"
-        foreach ($Config in 'Release','Debug') { `
-          & cmake `
-            --build "${env:GITHUB_WORKSPACE}\downstream\pkgconfig\sdk" `
-            --config ${Config} `
-            -- `
-            -j ${env:NUMBER_OF_PROCESSORS} `
-        }
\ No newline at end of file
diff --git a/.gitignore b/.gitignore
new file mode 100644
index 0000000..c591e64
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
+# Test dir
+[Tt]esting/
+
+# Visual Studio Code
+.vscode
diff --git a/CL/cl.h b/CL/cl.h
index afeeb4e..792e20c 100644
--- a/CL/cl.h
+++ b/CL/cl.h
@@ -112,9 +112,9 @@ typedef cl_uint             cl_kernel_exec_info;
 typedef cl_bitfield         cl_device_atomic_capabilities;
 typedef cl_bitfield         cl_device_device_enqueue_capabilities;
 typedef cl_uint             cl_khronos_vendor_id;
-typedef cl_properties       cl_mem_properties;
-typedef cl_uint             cl_version;
+typedef cl_properties cl_mem_properties;
 #endif
+typedef cl_uint cl_version;
 
 typedef struct _cl_image_format {
     cl_channel_order        image_channel_order;
@@ -914,8 +914,6 @@ typedef struct _cl_name_version {
 /* cl_khronos_vendor_id */
 #define CL_KHRONOS_VENDOR_ID_CODEPLAY               0x10004
 
-#ifdef CL_VERSION_3_0
-
 /* cl_version */
 #define CL_VERSION_MAJOR_BITS (10)
 #define CL_VERSION_MINOR_BITS (10)
@@ -939,8 +937,6 @@ typedef struct _cl_name_version {
    (((minor) & CL_VERSION_MINOR_MASK) << CL_VERSION_PATCH_BITS) | \
    ((patch) & CL_VERSION_PATCH_MASK))
 
-#endif
-
 /********************************************************************************************************/
 
 /* CL_NO_PROTOTYPES implies CL_NO_CORE_PROTOTYPES: */
diff --git a/CL/cl_d3d10.h b/CL/cl_d3d10.h
index 8404644..6b56c77 100644
--- a/CL/cl_d3d10.h
+++ b/CL/cl_d3d10.h
@@ -65,6 +65,9 @@ extern "C" {
 #define CL_KHR_D3D10_SHARING_EXTENSION_NAME \
     "cl_khr_d3d10_sharing"
 
+
+#define CL_KHR_D3D10_SHARING_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_uint             cl_d3d10_device_source_khr;
 typedef cl_uint             cl_d3d10_device_set_khr;
 
@@ -228,6 +231,9 @@ clEnqueueReleaseD3D10ObjectsKHR(
 #define CL_INTEL_SHARING_FORMAT_QUERY_D3D10_EXTENSION_NAME \
     "cl_intel_sharing_format_query_d3d10"
 
+
+#define CL_INTEL_SHARING_FORMAT_QUERY_D3D10_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* when cl_khr_d3d10_sharing is supported */
 
 typedef cl_int CL_API_CALL
diff --git a/CL/cl_d3d11.h b/CL/cl_d3d11.h
index ade8795..384c8f4 100644
--- a/CL/cl_d3d11.h
+++ b/CL/cl_d3d11.h
@@ -65,6 +65,9 @@ extern "C" {
 #define CL_KHR_D3D11_SHARING_EXTENSION_NAME \
     "cl_khr_d3d11_sharing"
 
+
+#define CL_KHR_D3D11_SHARING_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_uint             cl_d3d11_device_source_khr;
 typedef cl_uint             cl_d3d11_device_set_khr;
 
@@ -228,6 +231,9 @@ clEnqueueReleaseD3D11ObjectsKHR(
 #define CL_INTEL_SHARING_FORMAT_QUERY_D3D11_EXTENSION_NAME \
     "cl_intel_sharing_format_query_d3d11"
 
+
+#define CL_INTEL_SHARING_FORMAT_QUERY_D3D11_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* when cl_khr_d3d11_sharing is supported */
 
 typedef cl_int CL_API_CALL
diff --git a/CL/cl_dx9_media_sharing.h b/CL/cl_dx9_media_sharing.h
index c0df5c9..b079379 100644
--- a/CL/cl_dx9_media_sharing.h
+++ b/CL/cl_dx9_media_sharing.h
@@ -67,6 +67,9 @@ extern "C" {
 #define CL_KHR_DX9_MEDIA_SHARING_EXTENSION_NAME \
     "cl_khr_dx9_media_sharing"
 
+
+#define CL_KHR_DX9_MEDIA_SHARING_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_uint             cl_dx9_media_adapter_type_khr;
 typedef cl_uint             cl_dx9_media_adapter_set_khr;
 
@@ -209,6 +212,9 @@ clEnqueueReleaseDX9MediaSurfacesKHR(
 #define CL_INTEL_DX9_MEDIA_SHARING_EXTENSION_NAME \
     "cl_intel_dx9_media_sharing"
 
+
+#define CL_INTEL_DX9_MEDIA_SHARING_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef cl_uint             cl_dx9_device_source_intel;
 typedef cl_uint             cl_dx9_device_set_intel;
 
@@ -341,6 +347,9 @@ clEnqueueReleaseDX9ObjectsINTEL(
 #define CL_INTEL_SHARING_FORMAT_QUERY_DX9_EXTENSION_NAME \
     "cl_intel_sharing_format_query_dx9"
 
+
+#define CL_INTEL_SHARING_FORMAT_QUERY_DX9_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* when cl_khr_dx9_media_sharing or cl_intel_dx9_media_sharing is supported */
 
 typedef cl_int CL_API_CALL
diff --git a/CL/cl_egl.h b/CL/cl_egl.h
index 25cd5e0..68aefec 100644
--- a/CL/cl_egl.h
+++ b/CL/cl_egl.h
@@ -51,6 +51,9 @@ extern "C" {
 #define CL_KHR_EGL_IMAGE_EXTENSION_NAME \
     "cl_khr_egl_image"
 
+
+#define CL_KHR_EGL_IMAGE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* Command type for events created with clEnqueueAcquireEGLObjectsKHR */
 #define CL_COMMAND_EGL_FENCE_SYNC_OBJECT_KHR                0x202F
 #define CL_COMMAND_ACQUIRE_EGL_OBJECTS_KHR                  0x202D
@@ -144,6 +147,9 @@ clEnqueueReleaseEGLObjectsKHR(
 #define CL_KHR_EGL_EVENT_EXTENSION_NAME \
     "cl_khr_egl_event"
 
+
+#define CL_KHR_EGL_EVENT_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* CLeglDisplayKHR is an opaque handle to an EGLDisplay */
 /* type CLeglDisplayKHR */
 
diff --git a/CL/cl_ext.h b/CL/cl_ext.h
index 7eddb47..1a48985 100644
--- a/CL/cl_ext.h
+++ b/CL/cl_ext.h
@@ -51,6 +51,9 @@ extern "C" {
 #define CL_KHR_COMMAND_BUFFER_EXTENSION_NAME \
     "cl_khr_command_buffer"
 
+
+#define CL_KHR_COMMAND_BUFFER_EXTENSION_VERSION CL_MAKE_VERSION(0, 9, 5)
+
 typedef cl_bitfield         cl_device_command_buffer_capabilities_khr;
 typedef struct _cl_command_buffer_khr* cl_command_buffer_khr;
 typedef cl_uint             cl_sync_point_khr;
@@ -58,7 +61,7 @@ typedef cl_uint             cl_command_buffer_info_khr;
 typedef cl_uint             cl_command_buffer_state_khr;
 typedef cl_properties       cl_command_buffer_properties_khr;
 typedef cl_bitfield         cl_command_buffer_flags_khr;
-typedef cl_properties       cl_ndrange_kernel_command_properties_khr;
+typedef cl_properties       cl_command_properties_khr;
 typedef struct _cl_mutable_command_khr* cl_mutable_command_khr;
 
 /* cl_device_info */
@@ -146,6 +149,7 @@ typedef cl_int CL_API_CALL
 clCommandBarrierWithWaitListKHR_t(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_uint num_sync_points_in_wait_list,
     const cl_sync_point_khr* sync_point_wait_list,
     cl_sync_point_khr* sync_point,
@@ -158,6 +162,7 @@ typedef cl_int CL_API_CALL
 clCommandCopyBufferKHR_t(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem src_buffer,
     cl_mem dst_buffer,
     size_t src_offset,
@@ -175,6 +180,7 @@ typedef cl_int CL_API_CALL
 clCommandCopyBufferRectKHR_t(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem src_buffer,
     cl_mem dst_buffer,
     const size_t* src_origin,
@@ -196,6 +202,7 @@ typedef cl_int CL_API_CALL
 clCommandCopyBufferToImageKHR_t(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem src_buffer,
     cl_mem dst_image,
     size_t src_offset,
@@ -213,6 +220,7 @@ typedef cl_int CL_API_CALL
 clCommandCopyImageKHR_t(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem src_image,
     cl_mem dst_image,
     const size_t* src_origin,
@@ -230,6 +238,7 @@ typedef cl_int CL_API_CALL
 clCommandCopyImageToBufferKHR_t(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem src_image,
     cl_mem dst_buffer,
     const size_t* src_origin,
@@ -247,6 +256,7 @@ typedef cl_int CL_API_CALL
 clCommandFillBufferKHR_t(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem buffer,
     const void* pattern,
     size_t pattern_size,
@@ -264,6 +274,7 @@ typedef cl_int CL_API_CALL
 clCommandFillImageKHR_t(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem image,
     const void* fill_color,
     const size_t* origin,
@@ -280,7 +291,7 @@ typedef cl_int CL_API_CALL
 clCommandNDRangeKernelKHR_t(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
-    const cl_ndrange_kernel_command_properties_khr* properties,
+    const cl_command_properties_khr* properties,
     cl_kernel kernel,
     cl_uint work_dim,
     const size_t* global_work_offset,
@@ -294,37 +305,6 @@ clCommandNDRangeKernelKHR_t(
 typedef clCommandNDRangeKernelKHR_t *
 clCommandNDRangeKernelKHR_fn ;
 
-typedef cl_int CL_API_CALL
-clCommandSVMMemcpyKHR_t(
-    cl_command_buffer_khr command_buffer,
-    cl_command_queue command_queue,
-    void* dst_ptr,
-    const void* src_ptr,
-    size_t size,
-    cl_uint num_sync_points_in_wait_list,
-    const cl_sync_point_khr* sync_point_wait_list,
-    cl_sync_point_khr* sync_point,
-    cl_mutable_command_khr* mutable_handle);
-
-typedef clCommandSVMMemcpyKHR_t *
-clCommandSVMMemcpyKHR_fn CL_API_SUFFIX__VERSION_2_0;
-
-typedef cl_int CL_API_CALL
-clCommandSVMMemFillKHR_t(
-    cl_command_buffer_khr command_buffer,
-    cl_command_queue command_queue,
-    void* svm_ptr,
-    const void* pattern,
-    size_t pattern_size,
-    size_t size,
-    cl_uint num_sync_points_in_wait_list,
-    const cl_sync_point_khr* sync_point_wait_list,
-    cl_sync_point_khr* sync_point,
-    cl_mutable_command_khr* mutable_handle);
-
-typedef clCommandSVMMemFillKHR_t *
-clCommandSVMMemFillKHR_fn CL_API_SUFFIX__VERSION_2_0;
-
 typedef cl_int CL_API_CALL
 clGetCommandBufferInfoKHR_t(
     cl_command_buffer_khr command_buffer,
@@ -370,6 +350,7 @@ extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandBarrierWithWaitListKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_uint num_sync_points_in_wait_list,
     const cl_sync_point_khr* sync_point_wait_list,
     cl_sync_point_khr* sync_point,
@@ -379,6 +360,7 @@ extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandCopyBufferKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem src_buffer,
     cl_mem dst_buffer,
     size_t src_offset,
@@ -393,6 +375,7 @@ extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandCopyBufferRectKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem src_buffer,
     cl_mem dst_buffer,
     const size_t* src_origin,
@@ -411,6 +394,7 @@ extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandCopyBufferToImageKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem src_buffer,
     cl_mem dst_image,
     size_t src_offset,
@@ -425,6 +409,7 @@ extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandCopyImageKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem src_image,
     cl_mem dst_image,
     const size_t* src_origin,
@@ -439,6 +424,7 @@ extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandCopyImageToBufferKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem src_image,
     cl_mem dst_buffer,
     const size_t* src_origin,
@@ -453,6 +439,7 @@ extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandFillBufferKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem buffer,
     const void* pattern,
     size_t pattern_size,
@@ -467,6 +454,7 @@ extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandFillImageKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     cl_mem image,
     const void* fill_color,
     const size_t* origin,
@@ -480,7 +468,7 @@ extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandNDRangeKernelKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
-    const cl_ndrange_kernel_command_properties_khr* properties,
+    const cl_command_properties_khr* properties,
     cl_kernel kernel,
     cl_uint work_dim,
     const size_t* global_work_offset,
@@ -491,10 +479,58 @@ clCommandNDRangeKernelKHR(
     cl_sync_point_khr* sync_point,
     cl_mutable_command_khr* mutable_handle) ;
 
+extern CL_API_ENTRY cl_int CL_API_CALL
+clGetCommandBufferInfoKHR(
+    cl_command_buffer_khr command_buffer,
+    cl_command_buffer_info_khr param_name,
+    size_t param_value_size,
+    void* param_value,
+    size_t* param_value_size_ret) ;
+
+#endif /* !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES) */
+
+/* From version 0.9.4 of the extension */
+
+typedef cl_int CL_API_CALL
+clCommandSVMMemcpyKHR_t(
+    cl_command_buffer_khr command_buffer,
+    cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
+    void* dst_ptr,
+    const void* src_ptr,
+    size_t size,
+    cl_uint num_sync_points_in_wait_list,
+    const cl_sync_point_khr* sync_point_wait_list,
+    cl_sync_point_khr* sync_point,
+    cl_mutable_command_khr* mutable_handle);
+
+typedef clCommandSVMMemcpyKHR_t *
+clCommandSVMMemcpyKHR_fn CL_API_SUFFIX__VERSION_2_0;
+
+typedef cl_int CL_API_CALL
+clCommandSVMMemFillKHR_t(
+    cl_command_buffer_khr command_buffer,
+    cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
+    void* svm_ptr,
+    const void* pattern,
+    size_t pattern_size,
+    size_t size,
+    cl_uint num_sync_points_in_wait_list,
+    const cl_sync_point_khr* sync_point_wait_list,
+    cl_sync_point_khr* sync_point,
+    cl_mutable_command_khr* mutable_handle);
+
+typedef clCommandSVMMemFillKHR_t *
+clCommandSVMMemFillKHR_fn CL_API_SUFFIX__VERSION_2_0;
+
+#if !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES)
+
 extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandSVMMemcpyKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     void* dst_ptr,
     const void* src_ptr,
     size_t size,
@@ -507,6 +543,7 @@ extern CL_API_ENTRY cl_int CL_API_CALL
 clCommandSVMMemFillKHR(
     cl_command_buffer_khr command_buffer,
     cl_command_queue command_queue,
+    const cl_command_properties_khr* properties,
     void* svm_ptr,
     const void* pattern,
     size_t pattern_size,
@@ -516,14 +553,6 @@ clCommandSVMMemFillKHR(
     cl_sync_point_khr* sync_point,
     cl_mutable_command_khr* mutable_handle) CL_API_SUFFIX__VERSION_2_0;
 
-extern CL_API_ENTRY cl_int CL_API_CALL
-clGetCommandBufferInfoKHR(
-    cl_command_buffer_khr command_buffer,
-    cl_command_buffer_info_khr param_name,
-    size_t param_value_size,
-    void* param_value,
-    size_t* param_value_size_ret) ;
-
 #endif /* !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES) */
 
 /***************************************************************
@@ -533,6 +562,9 @@ clGetCommandBufferInfoKHR(
 #define CL_KHR_COMMAND_BUFFER_MULTI_DEVICE_EXTENSION_NAME \
     "cl_khr_command_buffer_multi_device"
 
+
+#define CL_KHR_COMMAND_BUFFER_MULTI_DEVICE_EXTENSION_VERSION CL_MAKE_VERSION(0, 9, 1)
+
 typedef cl_bitfield         cl_platform_command_buffer_capabilities_khr;
 
 /* cl_platform_info */
@@ -590,7 +622,10 @@ clRemapCommandBufferKHR(
 #define CL_KHR_COMMAND_BUFFER_MUTABLE_DISPATCH_EXTENSION_NAME \
     "cl_khr_command_buffer_mutable_dispatch"
 
-typedef cl_uint             cl_command_buffer_structure_type_khr;
+
+#define CL_KHR_COMMAND_BUFFER_MUTABLE_DISPATCH_EXTENSION_VERSION CL_MAKE_VERSION(0, 9, 3)
+
+typedef cl_uint             cl_command_buffer_update_type_khr;
 typedef cl_bitfield         cl_mutable_dispatch_fields_khr;
 typedef cl_uint             cl_mutable_command_info_khr;
 typedef struct _cl_mutable_dispatch_arg_khr {
@@ -604,8 +639,6 @@ typedef struct _cl_mutable_dispatch_exec_info_khr {
     const void* param_value;
 } cl_mutable_dispatch_exec_info_khr;
 typedef struct _cl_mutable_dispatch_config_khr {
-    cl_command_buffer_structure_type_khr type;
-    const void* next;
     cl_mutable_command_khr command;
     cl_uint num_args;
     cl_uint num_svm_args;
@@ -618,12 +651,7 @@ typedef struct _cl_mutable_dispatch_config_khr {
     const size_t* global_work_size;
     const size_t* local_work_size;
 } cl_mutable_dispatch_config_khr;
-typedef struct _cl_mutable_base_config_khr {
-    cl_command_buffer_structure_type_khr type;
-    const void* next;
-    cl_uint num_mutable_dispatch;
-    const cl_mutable_dispatch_config_khr* mutable_dispatch_list;
-} cl_mutable_base_config_khr;
+typedef cl_bitfield         cl_mutable_dispatch_asserts_khr;
 
 /* cl_command_buffer_flags_khr - bitfield */
 #define CL_COMMAND_BUFFER_MUTABLE_KHR                       (1 << 1)
@@ -634,7 +662,7 @@ typedef struct _cl_mutable_base_config_khr {
 /* cl_device_info */
 #define CL_DEVICE_MUTABLE_DISPATCH_CAPABILITIES_KHR         0x12B0
 
-/* cl_ndrange_kernel_command_properties_khr */
+/* cl_command_properties_khr */
 #define CL_MUTABLE_DISPATCH_UPDATABLE_FIELDS_KHR            0x12B1
 
 /* cl_mutable_dispatch_fields_khr - bitfield */
@@ -648,22 +676,32 @@ typedef struct _cl_mutable_base_config_khr {
 #define CL_MUTABLE_COMMAND_COMMAND_QUEUE_KHR                0x12A0
 #define CL_MUTABLE_COMMAND_COMMAND_BUFFER_KHR               0x12A1
 #define CL_MUTABLE_COMMAND_COMMAND_TYPE_KHR                 0x12AD
-#define CL_MUTABLE_DISPATCH_PROPERTIES_ARRAY_KHR            0x12A2
+#define CL_MUTABLE_COMMAND_PROPERTIES_ARRAY_KHR             0x12A2
 #define CL_MUTABLE_DISPATCH_KERNEL_KHR                      0x12A3
 #define CL_MUTABLE_DISPATCH_DIMENSIONS_KHR                  0x12A4
 #define CL_MUTABLE_DISPATCH_GLOBAL_WORK_OFFSET_KHR          0x12A5
 #define CL_MUTABLE_DISPATCH_GLOBAL_WORK_SIZE_KHR            0x12A6
 #define CL_MUTABLE_DISPATCH_LOCAL_WORK_SIZE_KHR             0x12A7
 
-/* cl_command_buffer_structure_type_khr */
-#define CL_STRUCTURE_TYPE_MUTABLE_BASE_CONFIG_KHR           0
-#define CL_STRUCTURE_TYPE_MUTABLE_DISPATCH_CONFIG_KHR       1
+/* cl_command_buffer_update_type_khr */
+#define CL_STRUCTURE_TYPE_MUTABLE_DISPATCH_CONFIG_KHR       0
+
+/* cl_command_buffer_properties_khr */
+#define CL_COMMAND_BUFFER_MUTABLE_DISPATCH_ASSERTS_KHR      0x12B7
+
+/* cl_command_properties_khr */
+#define CL_MUTABLE_DISPATCH_ASSERTS_KHR                     0x12B8
+
+/* cl_mutable_dispatch_asserts_khr - bitfield */
+#define CL_MUTABLE_DISPATCH_ASSERT_NO_ADDITIONAL_WORK_GROUPS_KHR (1 << 0)
 
 
 typedef cl_int CL_API_CALL
 clUpdateMutableCommandsKHR_t(
     cl_command_buffer_khr command_buffer,
-    const cl_mutable_base_config_khr* mutable_config);
+    cl_uint num_configs,
+    const cl_command_buffer_update_type_khr* config_types,
+    const void** configs);
 
 typedef clUpdateMutableCommandsKHR_t *
 clUpdateMutableCommandsKHR_fn ;
@@ -684,7 +722,9 @@ clGetMutableCommandInfoKHR_fn ;
 extern CL_API_ENTRY cl_int CL_API_CALL
 clUpdateMutableCommandsKHR(
     cl_command_buffer_khr command_buffer,
-    const cl_mutable_base_config_khr* mutable_config) ;
+    cl_uint num_configs,
+    const cl_command_buffer_update_type_khr* config_types,
+    const void** configs) ;
 
 extern CL_API_ENTRY cl_int CL_API_CALL
 clGetMutableCommandInfoKHR(
@@ -703,6 +743,9 @@ clGetMutableCommandInfoKHR(
 #define CL_KHR_FP64_EXTENSION_NAME \
     "cl_khr_fp64"
 
+
+#define CL_KHR_FP64_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 #if !defined(CL_VERSION_1_2)
 /* cl_device_info - defined in CL.h for OpenCL 1.2 and newer */
 #define CL_DEVICE_DOUBLE_FP_CONFIG                          0x1032
@@ -716,6 +759,9 @@ clGetMutableCommandInfoKHR(
 #define CL_KHR_FP16_EXTENSION_NAME \
     "cl_khr_fp16"
 
+
+#define CL_KHR_FP16_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_HALF_FP_CONFIG                            0x1033
 
@@ -727,6 +773,9 @@ clGetMutableCommandInfoKHR(
     "cl_APPLE_SetMemObjectDestructor"
 
 
+#define CL_APPLE_SETMEMOBJECTDESTRUCTOR_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
+
 typedef cl_int CL_API_CALL
 clSetMemObjectDestructorAPPLE_t(
     cl_mem memobj,
@@ -754,6 +803,9 @@ clSetMemObjectDestructorAPPLE(
     "cl_APPLE_ContextLoggingFunctions"
 
 
+#define CL_APPLE_CONTEXTLOGGINGFUNCTIONS_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
+
 typedef void CL_API_CALL
 clLogMessagesToSystemLogAPPLE_t(
     const char* errstr,
@@ -816,6 +868,9 @@ clLogMessagesToStderrAPPLE(
 #define CL_KHR_ICD_EXTENSION_NAME \
     "cl_khr_icd"
 
+
+#define CL_KHR_ICD_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_platform_info */
 #define CL_PLATFORM_ICD_SUFFIX_KHR                          0x0920
 
@@ -849,6 +904,9 @@ clIcdGetPlatformIDsKHR(
 #define CL_KHR_IL_PROGRAM_EXTENSION_NAME \
     "cl_khr_il_program"
 
+
+#define CL_KHR_IL_PROGRAM_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_IL_VERSION_KHR                            0x105B
 
@@ -884,6 +942,9 @@ clCreateProgramWithILKHR(
 #define CL_KHR_IMAGE2D_FROM_BUFFER_EXTENSION_NAME \
     "cl_khr_image2d_from_buffer"
 
+
+#define CL_KHR_IMAGE2D_FROM_BUFFER_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_IMAGE_PITCH_ALIGNMENT_KHR                 0x104A
 #define CL_DEVICE_IMAGE_BASE_ADDRESS_ALIGNMENT_KHR          0x104B
@@ -895,6 +956,9 @@ clCreateProgramWithILKHR(
 #define CL_KHR_INITIALIZE_MEMORY_EXTENSION_NAME \
     "cl_khr_initialize_memory"
 
+
+#define CL_KHR_INITIALIZE_MEMORY_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_bitfield         cl_context_memory_initialize_khr;
 
 /* cl_context_properties */
@@ -911,6 +975,9 @@ typedef cl_bitfield         cl_context_memory_initialize_khr;
 #define CL_KHR_TERMINATE_CONTEXT_EXTENSION_NAME \
     "cl_khr_terminate_context"
 
+
+#define CL_KHR_TERMINATE_CONTEXT_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_bitfield         cl_device_terminate_capability_khr;
 
 /* cl_device_info */
@@ -948,6 +1015,9 @@ clTerminateContextKHR(
 #define CL_KHR_SPIR_EXTENSION_NAME \
     "cl_khr_spir"
 
+
+#define CL_KHR_SPIR_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_SPIR_VERSIONS                             0x40E0
 
@@ -961,6 +1031,9 @@ clTerminateContextKHR(
 #define CL_KHR_CREATE_COMMAND_QUEUE_EXTENSION_NAME \
     "cl_khr_create_command_queue"
 
+
+#define CL_KHR_CREATE_COMMAND_QUEUE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_properties       cl_queue_properties_khr;
 
 
@@ -992,6 +1065,9 @@ clCreateCommandQueueWithPropertiesKHR(
 #define CL_NV_DEVICE_ATTRIBUTE_QUERY_EXTENSION_NAME \
     "cl_nv_device_attribute_query"
 
+
+#define CL_NV_DEVICE_ATTRIBUTE_QUERY_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV               0x4000
 #define CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV               0x4001
@@ -1008,6 +1084,9 @@ clCreateCommandQueueWithPropertiesKHR(
 #define CL_AMD_DEVICE_ATTRIBUTE_QUERY_EXTENSION_NAME \
     "cl_amd_device_attribute_query"
 
+
+#define CL_AMD_DEVICE_ATTRIBUTE_QUERY_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_PROFILING_TIMER_OFFSET_AMD                0x4036
 #define CL_DEVICE_TOPOLOGY_AMD                              0x4037
@@ -1038,6 +1117,9 @@ clCreateCommandQueueWithPropertiesKHR(
 #define CL_ARM_PRINTF_EXTENSION_NAME \
     "cl_arm_printf"
 
+
+#define CL_ARM_PRINTF_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_context_properties */
 #define CL_PRINTF_CALLBACK_ARM                              0x40B0
 #define CL_PRINTF_BUFFERSIZE_ARM                            0x40B1
@@ -1049,6 +1131,9 @@ clCreateCommandQueueWithPropertiesKHR(
 #define CL_EXT_DEVICE_FISSION_EXTENSION_NAME \
     "cl_ext_device_fission"
 
+
+#define CL_EXT_DEVICE_FISSION_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_ulong            cl_device_partition_property_ext;
 
 /* Error codes */
@@ -1135,6 +1220,9 @@ clCreateSubDevicesEXT(
 #define CL_EXT_MIGRATE_MEMOBJECT_EXTENSION_NAME \
     "cl_ext_migrate_memobject"
 
+
+#define CL_EXT_MIGRATE_MEMOBJECT_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_bitfield         cl_mem_migration_flags_ext;
 
 /* cl_mem_migration_flags_ext */
@@ -1178,6 +1266,9 @@ clEnqueueMigrateMemObjectEXT(
 #define CL_EXT_CXX_FOR_OPENCL_EXTENSION_NAME \
     "cl_ext_cxx_for_opencl"
 
+
+#define CL_EXT_CXX_FOR_OPENCL_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_CXX_FOR_OPENCL_NUMERIC_VERSION_EXT        0x4230
 
@@ -1188,6 +1279,9 @@ clEnqueueMigrateMemObjectEXT(
 #define CL_QCOM_EXT_HOST_PTR_EXTENSION_NAME \
     "cl_qcom_ext_host_ptr"
 
+
+#define CL_QCOM_EXT_HOST_PTR_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef cl_uint             cl_image_pitch_info_qcom;
 typedef struct _cl_mem_ext_host_ptr {
     cl_uint allocation_type;
@@ -1248,6 +1342,9 @@ clGetDeviceImageInfoQCOM(
 #define CL_QCOM_EXT_HOST_PTR_IOCOHERENT_EXTENSION_NAME \
     "cl_qcom_ext_host_ptr_iocoherent"
 
+
+#define CL_QCOM_EXT_HOST_PTR_IOCOHERENT_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_uint host_cache_policy */
 #define CL_MEM_HOST_IOCOHERENT_QCOM                         0x40A9
 
@@ -1258,6 +1355,9 @@ clGetDeviceImageInfoQCOM(
 #define CL_QCOM_ION_HOST_PTR_EXTENSION_NAME \
     "cl_qcom_ion_host_ptr"
 
+
+#define CL_QCOM_ION_HOST_PTR_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* type cl_mem_ext_host_ptr */
 typedef struct _cl_mem_ion_host_ptr {
     cl_mem_ext_host_ptr ext_host_ptr;
@@ -1275,6 +1375,9 @@ typedef struct _cl_mem_ion_host_ptr {
 #define CL_QCOM_ANDROID_NATIVE_BUFFER_HOST_PTR_EXTENSION_NAME \
     "cl_qcom_android_native_buffer_host_ptr"
 
+
+#define CL_QCOM_ANDROID_NATIVE_BUFFER_HOST_PTR_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* type cl_mem_ext_host_ptr */
 typedef struct _cl_mem_android_native_buffer_host_ptr {
     cl_mem_ext_host_ptr ext_host_ptr;
@@ -1291,6 +1394,9 @@ typedef struct _cl_mem_android_native_buffer_host_ptr {
 #define CL_IMG_YUV_IMAGE_EXTENSION_NAME \
     "cl_img_yuv_image"
 
+
+#define CL_IMG_YUV_IMAGE_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_channel_order */
 #define CL_NV21_IMG                                         0x40D0
 #define CL_YV12_IMG                                         0x40D1
@@ -1302,6 +1408,9 @@ typedef struct _cl_mem_android_native_buffer_host_ptr {
 #define CL_IMG_CACHED_ALLOCATIONS_EXTENSION_NAME \
     "cl_img_cached_allocations"
 
+
+#define CL_IMG_CACHED_ALLOCATIONS_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_mem_flags */
 #define CL_MEM_USE_UNCACHED_CPU_MEMORY_IMG                  (1 << 26)
 #define CL_MEM_USE_CACHED_CPU_MEMORY_IMG                    (1 << 27)
@@ -1313,6 +1422,9 @@ typedef struct _cl_mem_android_native_buffer_host_ptr {
 #define CL_IMG_USE_GRALLOC_PTR_EXTENSION_NAME \
     "cl_img_use_gralloc_ptr"
 
+
+#define CL_IMG_USE_GRALLOC_PTR_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* Error codes */
 #define CL_GRALLOC_RESOURCE_NOT_ACQUIRED_IMG                0x40D4
 #define CL_INVALID_GRALLOC_OBJECT_IMG                       0x40D5
@@ -1378,6 +1490,9 @@ clEnqueueReleaseGrallocObjectsIMG(
 #define CL_IMG_GENERATE_MIPMAP_EXTENSION_NAME \
     "cl_img_generate_mipmap"
 
+
+#define CL_IMG_GENERATE_MIPMAP_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef cl_uint             cl_mipmap_filter_mode_img;
 
 /* cl_mipmap_filter_mode_img */
@@ -1426,11 +1541,22 @@ clEnqueueGenerateMipmapIMG(
 #define CL_IMG_MEM_PROPERTIES_EXTENSION_NAME \
     "cl_img_mem_properties"
 
+
+#define CL_IMG_MEM_PROPERTIES_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_mem_properties */
 #define CL_MEM_ALLOC_FLAGS_IMG                              0x40D7
 
 /* cl_mem_alloc_flags_img */
 #define CL_MEM_ALLOC_RELAX_REQUIREMENTS_IMG                 (1 << 0)
+#define CL_MEM_ALLOC_GPU_WRITE_COMBINE_IMG                  (1 << 1)
+#define CL_MEM_ALLOC_GPU_CACHED_IMG                         (1 << 2)
+#define CL_MEM_ALLOC_CPU_LOCAL_IMG                          (1 << 3)
+#define CL_MEM_ALLOC_GPU_LOCAL_IMG                          (1 << 4)
+#define CL_MEM_ALLOC_GPU_PRIVATE_IMG                        (1 << 5)
+
+/* cl_device_info */
+#define CL_DEVICE_MEMORY_CAPABILITIES_IMG                   0x40D8
 
 /***************************************************************
 * cl_khr_subgroups
@@ -1439,6 +1565,9 @@ clEnqueueGenerateMipmapIMG(
 #define CL_KHR_SUBGROUPS_EXTENSION_NAME \
     "cl_khr_subgroups"
 
+
+#define CL_KHR_SUBGROUPS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 #if !defined(CL_VERSION_2_1)
 /* defined in CL.h for OpenCL 2.1 and newer */
 typedef cl_uint             cl_kernel_sub_group_info;
@@ -1486,6 +1615,9 @@ clGetKernelSubGroupInfoKHR(
 #define CL_KHR_MIPMAP_IMAGE_EXTENSION_NAME \
     "cl_khr_mipmap_image"
 
+
+#define CL_KHR_MIPMAP_IMAGE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_sampler_properties */
 #define CL_SAMPLER_MIP_FILTER_MODE_KHR                      0x1155
 #define CL_SAMPLER_LOD_MIN_KHR                              0x1156
@@ -1498,6 +1630,9 @@ clGetKernelSubGroupInfoKHR(
 #define CL_KHR_PRIORITY_HINTS_EXTENSION_NAME \
     "cl_khr_priority_hints"
 
+
+#define CL_KHR_PRIORITY_HINTS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* To be used by clGetEventInfo */
 typedef cl_uint             cl_queue_priority_khr;
 
@@ -1516,6 +1651,9 @@ typedef cl_uint             cl_queue_priority_khr;
 #define CL_KHR_THROTTLE_HINTS_EXTENSION_NAME \
     "cl_khr_throttle_hints"
 
+
+#define CL_KHR_THROTTLE_HINTS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* To be used by clGetEventInfo */
 typedef cl_uint             cl_queue_throttle_khr;
 
@@ -1534,6 +1672,9 @@ typedef cl_uint             cl_queue_throttle_khr;
 #define CL_KHR_SUBGROUP_NAMED_BARRIER_EXTENSION_NAME \
     "cl_khr_subgroup_named_barrier"
 
+
+#define CL_KHR_SUBGROUP_NAMED_BARRIER_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_MAX_NAMED_BARRIER_COUNT_KHR               0x2035
 
@@ -1544,6 +1685,9 @@ typedef cl_uint             cl_queue_throttle_khr;
 #define CL_KHR_EXTENDED_VERSIONING_EXTENSION_NAME \
     "cl_khr_extended_versioning"
 
+
+#define CL_KHR_EXTENDED_VERSIONING_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 #define CL_VERSION_MAJOR_BITS_KHR                           10
 #define CL_VERSION_MINOR_BITS_KHR                           10
 #define CL_VERSION_PATCH_BITS_KHR                           12
@@ -1587,6 +1731,9 @@ typedef struct _cl_name_version_khr {
 #define CL_KHR_DEVICE_UUID_EXTENSION_NAME \
     "cl_khr_device_uuid"
 
+
+#define CL_KHR_DEVICE_UUID_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* Size Constants */
 #define CL_UUID_SIZE_KHR                                    16
 #define CL_LUID_SIZE_KHR                                    8
@@ -1605,6 +1752,9 @@ typedef struct _cl_name_version_khr {
 #define CL_KHR_PCI_BUS_INFO_EXTENSION_NAME \
     "cl_khr_pci_bus_info"
 
+
+#define CL_KHR_PCI_BUS_INFO_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef struct _cl_device_pci_bus_info_khr {
     cl_uint pci_domain;
     cl_uint pci_bus;
@@ -1623,6 +1773,9 @@ typedef struct _cl_device_pci_bus_info_khr {
     "cl_khr_suggested_local_work_size"
 
 
+#define CL_KHR_SUGGESTED_LOCAL_WORK_SIZE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+
 typedef cl_int CL_API_CALL
 clGetKernelSuggestedLocalWorkSizeKHR_t(
     cl_command_queue command_queue,
@@ -1655,6 +1808,9 @@ clGetKernelSuggestedLocalWorkSizeKHR(
 #define CL_KHR_INTEGER_DOT_PRODUCT_EXTENSION_NAME \
     "cl_khr_integer_dot_product"
 
+
+#define CL_KHR_INTEGER_DOT_PRODUCT_EXTENSION_VERSION CL_MAKE_VERSION(2, 0, 0)
+
 typedef cl_bitfield         cl_device_integer_dot_product_capabilities_khr;
 typedef struct _cl_device_integer_dot_product_acceleration_properties_khr {
     cl_bool signed_accelerated;
@@ -1681,6 +1837,9 @@ typedef struct _cl_device_integer_dot_product_acceleration_properties_khr {
 #define CL_KHR_EXTERNAL_MEMORY_EXTENSION_NAME \
     "cl_khr_external_memory"
 
+
+#define CL_KHR_EXTERNAL_MEMORY_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 1)
+
 typedef cl_uint             cl_external_memory_handle_type_khr;
 
 /* cl_platform_info */
@@ -1752,21 +1911,11 @@ clEnqueueReleaseExternalMemObjectsKHR(
 #define CL_KHR_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_NAME \
     "cl_khr_external_memory_dma_buf"
 
-/* cl_external_memory_handle_type_khr */
-#define CL_EXTERNAL_MEMORY_HANDLE_DMA_BUF_KHR               0x2067
 
-/***************************************************************
-* cl_khr_external_memory_dx
-***************************************************************/
-#define cl_khr_external_memory_dx 1
-#define CL_KHR_EXTERNAL_MEMORY_DX_EXTENSION_NAME \
-    "cl_khr_external_memory_dx"
+#define CL_KHR_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
 
 /* cl_external_memory_handle_type_khr */
-#define CL_EXTERNAL_MEMORY_HANDLE_D3D11_TEXTURE_KHR         0x2063
-#define CL_EXTERNAL_MEMORY_HANDLE_D3D11_TEXTURE_KMT_KHR     0x2064
-#define CL_EXTERNAL_MEMORY_HANDLE_D3D12_HEAP_KHR            0x2065
-#define CL_EXTERNAL_MEMORY_HANDLE_D3D12_RESOURCE_KHR        0x2066
+#define CL_EXTERNAL_MEMORY_HANDLE_DMA_BUF_KHR               0x2067
 
 /***************************************************************
 * cl_khr_external_memory_opaque_fd
@@ -1775,6 +1924,9 @@ clEnqueueReleaseExternalMemObjectsKHR(
 #define CL_KHR_EXTERNAL_MEMORY_OPAQUE_FD_EXTENSION_NAME \
     "cl_khr_external_memory_opaque_fd"
 
+
+#define CL_KHR_EXTERNAL_MEMORY_OPAQUE_FD_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_external_memory_handle_type_khr */
 #define CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_FD_KHR             0x2060
 
@@ -1785,9 +1937,13 @@ clEnqueueReleaseExternalMemObjectsKHR(
 #define CL_KHR_EXTERNAL_MEMORY_WIN32_EXTENSION_NAME \
     "cl_khr_external_memory_win32"
 
+
+#define CL_KHR_EXTERNAL_MEMORY_WIN32_EXTENSION_VERSION CL_MAKE_VERSION(1, 1, 0)
+
 /* cl_external_memory_handle_type_khr */
 #define CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_WIN32_KHR          0x2061
 #define CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_WIN32_KMT_KHR      0x2062
+#define CL_EXTERNAL_MEMORY_HANDLE_OPAQUE_WIN32_NAME_KHR     0x2069
 
 /***************************************************************
 * cl_khr_external_semaphore
@@ -1796,6 +1952,9 @@ clEnqueueReleaseExternalMemObjectsKHR(
 #define CL_KHR_EXTERNAL_SEMAPHORE_EXTENSION_NAME \
     "cl_khr_external_semaphore"
 
+
+#define CL_KHR_EXTERNAL_SEMAPHORE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 1)
+
 typedef struct _cl_semaphore_khr * cl_semaphore_khr;
 typedef cl_uint             cl_external_semaphore_handle_type_khr;
 
@@ -1840,16 +1999,6 @@ clGetSemaphoreHandleForTypeKHR(
 
 #endif /* !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES) */
 
-/***************************************************************
-* cl_khr_external_semaphore_dx_fence
-***************************************************************/
-#define cl_khr_external_semaphore_dx_fence 1
-#define CL_KHR_EXTERNAL_SEMAPHORE_DX_FENCE_EXTENSION_NAME \
-    "cl_khr_external_semaphore_dx_fence"
-
-/* cl_external_semaphore_handle_type_khr */
-#define CL_SEMAPHORE_HANDLE_D3D12_FENCE_KHR                 0x2059
-
 /***************************************************************
 * cl_khr_external_semaphore_opaque_fd
 ***************************************************************/
@@ -1857,6 +2006,9 @@ clGetSemaphoreHandleForTypeKHR(
 #define CL_KHR_EXTERNAL_SEMAPHORE_OPAQUE_FD_EXTENSION_NAME \
     "cl_khr_external_semaphore_opaque_fd"
 
+
+#define CL_KHR_EXTERNAL_SEMAPHORE_OPAQUE_FD_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_external_semaphore_handle_type_khr */
 #define CL_SEMAPHORE_HANDLE_OPAQUE_FD_KHR                   0x2055
 
@@ -1867,6 +2019,9 @@ clGetSemaphoreHandleForTypeKHR(
 #define CL_KHR_EXTERNAL_SEMAPHORE_SYNC_FD_EXTENSION_NAME \
     "cl_khr_external_semaphore_sync_fd"
 
+
+#define CL_KHR_EXTERNAL_SEMAPHORE_SYNC_FD_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_properties       cl_semaphore_reimport_properties_khr;
 
 /* cl_external_semaphore_handle_type_khr */
@@ -1899,9 +2054,13 @@ clReImportSemaphoreSyncFdKHR(
 #define CL_KHR_EXTERNAL_SEMAPHORE_WIN32_EXTENSION_NAME \
     "cl_khr_external_semaphore_win32"
 
+
+#define CL_KHR_EXTERNAL_SEMAPHORE_WIN32_EXTENSION_VERSION CL_MAKE_VERSION(0, 9, 1)
+
 /* cl_external_semaphore_handle_type_khr */
 #define CL_SEMAPHORE_HANDLE_OPAQUE_WIN32_KHR                0x2056
 #define CL_SEMAPHORE_HANDLE_OPAQUE_WIN32_KMT_KHR            0x2057
+#define CL_SEMAPHORE_HANDLE_OPAQUE_WIN32_NAME_KHR           0x2068
 
 /***************************************************************
 * cl_khr_semaphore
@@ -1910,6 +2069,9 @@ clReImportSemaphoreSyncFdKHR(
 #define CL_KHR_SEMAPHORE_EXTENSION_NAME \
     "cl_khr_semaphore"
 
+
+#define CL_KHR_SEMAPHORE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* type cl_semaphore_khr */
 typedef cl_properties       cl_semaphore_properties_khr;
 typedef cl_uint             cl_semaphore_info_khr;
@@ -2057,6 +2219,9 @@ clRetainSemaphoreKHR(
 #define CL_ARM_IMPORT_MEMORY_EXTENSION_NAME \
     "cl_arm_import_memory"
 
+
+#define CL_ARM_IMPORT_MEMORY_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef intptr_t            cl_import_properties_arm;
 
 /* cl_import_properties_arm */
@@ -2103,6 +2268,9 @@ clImportMemoryARM(
 #define CL_ARM_SHARED_VIRTUAL_MEMORY_EXTENSION_NAME \
     "cl_arm_shared_virtual_memory"
 
+
+#define CL_ARM_SHARED_VIRTUAL_MEMORY_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef cl_bitfield         cl_svm_mem_flags_arm;
 typedef cl_uint             cl_kernel_exec_info_arm;
 typedef cl_bitfield         cl_device_svm_capabilities_arm;
@@ -2329,6 +2497,9 @@ clSetKernelExecInfoARM(
 #define CL_ARM_GET_CORE_ID_EXTENSION_NAME \
     "cl_arm_get_core_id"
 
+
+#define CL_ARM_GET_CORE_ID_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_COMPUTE_UNITS_BITFIELD_ARM                0x40BF
 
@@ -2341,6 +2512,9 @@ clSetKernelExecInfoARM(
 #define CL_ARM_JOB_SLOT_SELECTION_EXTENSION_NAME \
     "cl_arm_job_slot_selection"
 
+
+#define CL_ARM_JOB_SLOT_SELECTION_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_JOB_SLOTS_ARM                             0x41E0
 
@@ -2354,6 +2528,9 @@ clSetKernelExecInfoARM(
 #define CL_ARM_SCHEDULING_CONTROLS_EXTENSION_NAME \
     "cl_arm_scheduling_controls"
 
+
+#define CL_ARM_SCHEDULING_CONTROLS_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* Types */
 typedef cl_bitfield         cl_device_scheduling_controls_capabilities_arm;
 
@@ -2393,6 +2570,9 @@ typedef cl_bitfield         cl_device_scheduling_controls_capabilities_arm;
 #define CL_ARM_CONTROLLED_KERNEL_TERMINATION_EXTENSION_NAME \
     "cl_arm_controlled_kernel_termination"
 
+
+#define CL_ARM_CONTROLLED_KERNEL_TERMINATION_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* Types */
 typedef cl_bitfield         cl_device_controlled_termination_capabilities_arm;
 
@@ -2423,6 +2603,9 @@ typedef cl_bitfield         cl_device_controlled_termination_capabilities_arm;
 #define CL_ARM_PROTECTED_MEMORY_ALLOCATION_EXTENSION_NAME \
     "cl_arm_protected_memory_allocation"
 
+
+#define CL_ARM_PROTECTED_MEMORY_ALLOCATION_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 #define CL_MEM_PROTECTED_ALLOC_ARM                          ((cl_bitfield)1 << 36)
 
 /***************************************************************
@@ -2432,6 +2615,9 @@ typedef cl_bitfield         cl_device_controlled_termination_capabilities_arm;
 #define CL_INTEL_EXEC_BY_LOCAL_THREAD_EXTENSION_NAME \
     "cl_intel_exec_by_local_thread"
 
+
+#define CL_INTEL_EXEC_BY_LOCAL_THREAD_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_command_queue_properties - bitfield */
 #define CL_QUEUE_THREAD_LOCAL_EXEC_ENABLE_INTEL             ((cl_bitfield)1 << 31)
 
@@ -2442,6 +2628,9 @@ typedef cl_bitfield         cl_device_controlled_termination_capabilities_arm;
 #define CL_INTEL_DEVICE_ATTRIBUTE_QUERY_EXTENSION_NAME \
     "cl_intel_device_attribute_query"
 
+
+#define CL_INTEL_DEVICE_ATTRIBUTE_QUERY_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef cl_bitfield         cl_device_feature_capabilities_intel;
 
 /* cl_device_feature_capabilities_intel */
@@ -2464,6 +2653,9 @@ typedef cl_bitfield         cl_device_feature_capabilities_intel;
 #define CL_INTEL_DEVICE_PARTITION_BY_NAMES_EXTENSION_NAME \
     "cl_intel_device_partition_by_names"
 
+
+#define CL_INTEL_DEVICE_PARTITION_BY_NAMES_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 #define CL_DEVICE_PARTITION_BY_NAMES_INTEL                  0x4052
 #define CL_PARTITION_BY_NAMES_LIST_END_INTEL                -1
 
@@ -2474,6 +2666,9 @@ typedef cl_bitfield         cl_device_feature_capabilities_intel;
 #define CL_INTEL_ACCELERATOR_EXTENSION_NAME \
     "cl_intel_accelerator"
 
+
+#define CL_INTEL_ACCELERATOR_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef struct _cl_accelerator_intel* cl_accelerator_intel;
 typedef cl_uint             cl_accelerator_type_intel;
 typedef cl_uint             cl_accelerator_info_intel;
@@ -2562,6 +2757,9 @@ clReleaseAcceleratorINTEL(
 #define CL_INTEL_MOTION_ESTIMATION_EXTENSION_NAME \
     "cl_intel_motion_estimation"
 
+
+#define CL_INTEL_MOTION_ESTIMATION_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef struct _cl_motion_estimation_desc_intel {
     cl_uint mb_block_type;
     cl_uint subpixel_mode;
@@ -2598,6 +2796,9 @@ typedef struct _cl_motion_estimation_desc_intel {
 #define CL_INTEL_ADVANCED_MOTION_ESTIMATION_EXTENSION_NAME \
     "cl_intel_advanced_motion_estimation"
 
+
+#define CL_INTEL_ADVANCED_MOTION_ESTIMATION_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_ME_VERSION_INTEL                          0x407E
 
@@ -2654,6 +2855,9 @@ typedef struct _cl_motion_estimation_desc_intel {
 #define CL_INTEL_SIMULTANEOUS_SHARING_EXTENSION_NAME \
     "cl_intel_simultaneous_sharing"
 
+
+#define CL_INTEL_SIMULTANEOUS_SHARING_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_SIMULTANEOUS_INTEROPS_INTEL               0x4104
 #define CL_DEVICE_NUM_SIMULTANEOUS_INTEROPS_INTEL           0x4105
@@ -2665,6 +2869,9 @@ typedef struct _cl_motion_estimation_desc_intel {
 #define CL_INTEL_EGL_IMAGE_YUV_EXTENSION_NAME \
     "cl_intel_egl_image_yuv"
 
+
+#define CL_INTEL_EGL_IMAGE_YUV_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_egl_image_properties_khr */
 #define CL_EGL_YUV_PLANE_INTEL                              0x4107
 
@@ -2675,6 +2882,9 @@ typedef struct _cl_motion_estimation_desc_intel {
 #define CL_INTEL_PACKED_YUV_EXTENSION_NAME \
     "cl_intel_packed_yuv"
 
+
+#define CL_INTEL_PACKED_YUV_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_channel_order */
 #define CL_YUYV_INTEL                                       0x4076
 #define CL_UYVY_INTEL                                       0x4077
@@ -2688,6 +2898,9 @@ typedef struct _cl_motion_estimation_desc_intel {
 #define CL_INTEL_REQUIRED_SUBGROUP_SIZE_EXTENSION_NAME \
     "cl_intel_required_subgroup_size"
 
+
+#define CL_INTEL_REQUIRED_SUBGROUP_SIZE_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_SUB_GROUP_SIZES_INTEL                     0x4108
 
@@ -2704,10 +2917,15 @@ typedef struct _cl_motion_estimation_desc_intel {
 #define CL_INTEL_DRIVER_DIAGNOSTICS_EXTENSION_NAME \
     "cl_intel_driver_diagnostics"
 
-typedef cl_uint             cl_diagnostics_verbose_level;
+
+#define CL_INTEL_DRIVER_DIAGNOSTICS_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
+typedef cl_bitfield         cl_diagnostic_verbose_level_intel;
 
 /* cl_context_properties */
 #define CL_CONTEXT_SHOW_DIAGNOSTICS_INTEL                   0x4106
+
+/* cl_diagnostic_verbose_level_intel */
 #define CL_CONTEXT_DIAGNOSTICS_LEVEL_ALL_INTEL              0xff
 #define CL_CONTEXT_DIAGNOSTICS_LEVEL_GOOD_INTEL             (1 << 0)
 #define CL_CONTEXT_DIAGNOSTICS_LEVEL_BAD_INTEL              (1 << 1)
@@ -2720,6 +2938,9 @@ typedef cl_uint             cl_diagnostics_verbose_level;
 #define CL_INTEL_PLANAR_YUV_EXTENSION_NAME \
     "cl_intel_planar_yuv"
 
+
+#define CL_INTEL_PLANAR_YUV_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_channel_order */
 #define CL_NV12_INTEL                                       0x410E
 
@@ -2738,6 +2959,9 @@ typedef cl_uint             cl_diagnostics_verbose_level;
 #define CL_INTEL_DEVICE_SIDE_AVC_MOTION_ESTIMATION_EXTENSION_NAME \
     "cl_intel_device_side_avc_motion_estimation"
 
+
+#define CL_INTEL_DEVICE_SIDE_AVC_MOTION_ESTIMATION_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_device_info */
 #define CL_DEVICE_AVC_ME_VERSION_INTEL                      0x410B
 #define CL_DEVICE_AVC_ME_SUPPORTS_TEXTURE_SAMPLER_USE_INTEL 0x410C
@@ -2895,6 +3119,9 @@ typedef cl_uint             cl_diagnostics_verbose_level;
 #define CL_INTEL_UNIFIED_SHARED_MEMORY_EXTENSION_NAME \
     "cl_intel_unified_shared_memory"
 
+
+#define CL_INTEL_UNIFIED_SHARED_MEMORY_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef cl_bitfield         cl_device_unified_shared_memory_capabilities_intel;
 typedef cl_properties       cl_mem_properties_intel;
 typedef cl_bitfield         cl_mem_alloc_flags_intel;
@@ -3216,6 +3443,9 @@ clEnqueueMemsetINTEL(
 #define CL_INTEL_MEM_ALLOC_BUFFER_LOCATION_EXTENSION_NAME \
     "cl_intel_mem_alloc_buffer_location"
 
+
+#define CL_INTEL_MEM_ALLOC_BUFFER_LOCATION_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_mem_properties_intel */
 #define CL_MEM_ALLOC_BUFFER_LOCATION_INTEL                  0x419E
 
@@ -3229,6 +3459,9 @@ clEnqueueMemsetINTEL(
 #define CL_INTEL_CREATE_BUFFER_WITH_PROPERTIES_EXTENSION_NAME \
     "cl_intel_create_buffer_with_properties"
 
+
+#define CL_INTEL_CREATE_BUFFER_WITH_PROPERTIES_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* type cl_mem_properties_intel */
 
 
@@ -3264,6 +3497,9 @@ clCreateBufferWithPropertiesINTEL(
 #define CL_INTEL_PROGRAM_SCOPE_HOST_PIPE_EXTENSION_NAME \
     "cl_intel_program_scope_host_pipe"
 
+
+#define CL_INTEL_PROGRAM_SCOPE_HOST_PIPE_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* clGetEventInfo response when param_name is CL_EVENT_COMMAND_TYPE */
 #define CL_COMMAND_READ_HOST_PIPE_INTEL                     0x4214
 #define CL_COMMAND_WRITE_HOST_PIPE_INTEL                    0x4215
@@ -3338,6 +3574,9 @@ clEnqueueWriteHostPipeINTEL(
 #define CL_INTEL_MEM_CHANNEL_PROPERTY_EXTENSION_NAME \
     "cl_intel_mem_channel_property"
 
+
+#define CL_INTEL_MEM_CHANNEL_PROPERTY_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_mem_properties_intel */
 #define CL_MEM_CHANNEL_INTEL                                0x4213
 
@@ -3348,6 +3587,9 @@ clEnqueueWriteHostPipeINTEL(
 #define CL_INTEL_MEM_FORCE_HOST_MEMORY_EXTENSION_NAME \
     "cl_intel_mem_force_host_memory"
 
+
+#define CL_INTEL_MEM_FORCE_HOST_MEMORY_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_mem_flags */
 #define CL_MEM_FORCE_HOST_MEMORY_INTEL                      (1 << 20)
 
@@ -3358,6 +3600,9 @@ clEnqueueWriteHostPipeINTEL(
 #define CL_INTEL_COMMAND_QUEUE_FAMILIES_EXTENSION_NAME \
     "cl_intel_command_queue_families"
 
+
+#define CL_INTEL_COMMAND_QUEUE_FAMILIES_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef cl_bitfield         cl_command_queue_capabilities_intel;
 
 #define CL_QUEUE_FAMILY_MAX_NAME_SIZE_INTEL                 64
@@ -3402,6 +3647,9 @@ typedef struct _cl_queue_family_properties_intel {
 #define CL_INTEL_QUEUE_NO_SYNC_OPERATIONS_EXTENSION_NAME \
     "cl_intel_queue_no_sync_operations"
 
+
+#define CL_INTEL_QUEUE_NO_SYNC_OPERATIONS_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_command_queue_properties */
 #define CL_QUEUE_NO_SYNC_OPERATIONS_INTEL                   (1 << 29)
 
@@ -3412,6 +3660,9 @@ typedef struct _cl_queue_family_properties_intel {
 #define CL_INTEL_SHARING_FORMAT_QUERY_EXTENSION_NAME \
     "cl_intel_sharing_format_query"
 
+
+#define CL_INTEL_SHARING_FORMAT_QUERY_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /***************************************************************
 * cl_ext_image_requirements_info
 ***************************************************************/
@@ -3421,6 +3672,9 @@ typedef struct _cl_queue_family_properties_intel {
 #define CL_EXT_IMAGE_REQUIREMENTS_INFO_EXTENSION_NAME \
     "cl_ext_image_requirements_info"
 
+
+#define CL_EXT_IMAGE_REQUIREMENTS_INFO_EXTENSION_VERSION CL_MAKE_VERSION(0, 5, 0)
+
 /* Types */
 typedef cl_uint             cl_image_requirements_info_ext;
 
@@ -3477,6 +3731,9 @@ clGetImageRequirementsInfoEXT(
 #define CL_EXT_IMAGE_FROM_BUFFER_EXTENSION_NAME \
     "cl_ext_image_from_buffer"
 
+
+#define CL_EXT_IMAGE_FROM_BUFFER_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_image_requirements_info_ext */
 #define CL_IMAGE_REQUIREMENTS_SLICE_PITCH_ALIGNMENT_EXT     0x1291
 
@@ -3489,6 +3746,9 @@ clGetImageRequirementsInfoEXT(
 #define CL_LOADER_INFO_EXTENSION_NAME \
     "cl_loader_info"
 
+
+#define CL_LOADER_INFO_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_uint             cl_icdl_info;
 
 /* cl_icdl_info */
@@ -3526,6 +3786,9 @@ clGetICDLoaderInfoOCLICD(
 #define CL_KHR_DEPTH_IMAGES_EXTENSION_NAME \
     "cl_khr_depth_images"
 
+
+#define CL_KHR_DEPTH_IMAGES_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 #if !defined(CL_VERSION_2_0)
 /* cl_channel_order - defined in CL.h for OpenCL 2.0 and newer */
 #define CL_DEPTH                                            0x10BD
@@ -3539,6 +3802,9 @@ clGetICDLoaderInfoOCLICD(
 #define CL_EXT_FLOAT_ATOMICS_EXTENSION_NAME \
     "cl_ext_float_atomics"
 
+
+#define CL_EXT_FLOAT_ATOMICS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_bitfield         cl_device_fp_atomic_capabilities_ext;
 
 /* cl_device_fp_atomic_capabilities_ext */
@@ -3561,6 +3827,9 @@ typedef cl_bitfield         cl_device_fp_atomic_capabilities_ext;
 #define CL_INTEL_CREATE_MEM_OBJECT_PROPERTIES_EXTENSION_NAME \
     "cl_intel_create_mem_object_properties"
 
+
+#define CL_INTEL_CREATE_MEM_OBJECT_PROPERTIES_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* cl_mem_properties */
 #define CL_MEM_LOCALLY_UNCACHED_RESOURCE_INTEL              0x4218
 #define CL_MEM_DEVICE_ID_INTEL                              0x4219
@@ -3573,6 +3842,9 @@ typedef cl_bitfield         cl_device_fp_atomic_capabilities_ext;
     "cl_pocl_content_size"
 
 
+#define CL_POCL_CONTENT_SIZE_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
+
 typedef cl_int CL_API_CALL
 clSetContentSizeBufferPoCL_t(
     cl_mem buffer,
@@ -3597,10 +3869,357 @@ clSetContentSizeBufferPoCL(
 #define CL_EXT_IMAGE_RAW10_RAW12_EXTENSION_NAME \
     "cl_ext_image_raw10_raw12"
 
+
+#define CL_EXT_IMAGE_RAW10_RAW12_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_channel_type */
 #define CL_UNSIGNED_INT_RAW10_EXT                           0x10E3
 #define CL_UNSIGNED_INT_RAW12_EXT                           0x10E4
 
+/***************************************************************
+* cl_khr_3d_image_writes
+***************************************************************/
+#define cl_khr_3d_image_writes 1
+#define CL_KHR_3D_IMAGE_WRITES_EXTENSION_NAME \
+    "cl_khr_3d_image_writes"
+
+
+#define CL_KHR_3D_IMAGE_WRITES_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_async_work_group_copy_fence
+***************************************************************/
+#define cl_khr_async_work_group_copy_fence 1
+#define CL_KHR_ASYNC_WORK_GROUP_COPY_FENCE_EXTENSION_NAME \
+    "cl_khr_async_work_group_copy_fence"
+
+
+#define CL_KHR_ASYNC_WORK_GROUP_COPY_FENCE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_byte_addressable_store
+***************************************************************/
+#define cl_khr_byte_addressable_store 1
+#define CL_KHR_BYTE_ADDRESSABLE_STORE_EXTENSION_NAME \
+    "cl_khr_byte_addressable_store"
+
+
+#define CL_KHR_BYTE_ADDRESSABLE_STORE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_device_enqueue_local_arg_types
+***************************************************************/
+#define cl_khr_device_enqueue_local_arg_types 1
+#define CL_KHR_DEVICE_ENQUEUE_LOCAL_ARG_TYPES_EXTENSION_NAME \
+    "cl_khr_device_enqueue_local_arg_types"
+
+
+#define CL_KHR_DEVICE_ENQUEUE_LOCAL_ARG_TYPES_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_expect_assume
+***************************************************************/
+#define cl_khr_expect_assume 1
+#define CL_KHR_EXPECT_ASSUME_EXTENSION_NAME \
+    "cl_khr_expect_assume"
+
+
+#define CL_KHR_EXPECT_ASSUME_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_extended_async_copies
+***************************************************************/
+#define cl_khr_extended_async_copies 1
+#define CL_KHR_EXTENDED_ASYNC_COPIES_EXTENSION_NAME \
+    "cl_khr_extended_async_copies"
+
+
+#define CL_KHR_EXTENDED_ASYNC_COPIES_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_extended_bit_ops
+***************************************************************/
+#define cl_khr_extended_bit_ops 1
+#define CL_KHR_EXTENDED_BIT_OPS_EXTENSION_NAME \
+    "cl_khr_extended_bit_ops"
+
+
+#define CL_KHR_EXTENDED_BIT_OPS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_global_int32_base_atomics
+***************************************************************/
+#define cl_khr_global_int32_base_atomics 1
+#define CL_KHR_GLOBAL_INT32_BASE_ATOMICS_EXTENSION_NAME \
+    "cl_khr_global_int32_base_atomics"
+
+
+#define CL_KHR_GLOBAL_INT32_BASE_ATOMICS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_global_int32_extended_atomics
+***************************************************************/
+#define cl_khr_global_int32_extended_atomics 1
+#define CL_KHR_GLOBAL_INT32_EXTENDED_ATOMICS_EXTENSION_NAME \
+    "cl_khr_global_int32_extended_atomics"
+
+
+#define CL_KHR_GLOBAL_INT32_EXTENDED_ATOMICS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_int64_base_atomics
+***************************************************************/
+#define cl_khr_int64_base_atomics 1
+#define CL_KHR_INT64_BASE_ATOMICS_EXTENSION_NAME \
+    "cl_khr_int64_base_atomics"
+
+
+#define CL_KHR_INT64_BASE_ATOMICS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_int64_extended_atomics
+***************************************************************/
+#define cl_khr_int64_extended_atomics 1
+#define CL_KHR_INT64_EXTENDED_ATOMICS_EXTENSION_NAME \
+    "cl_khr_int64_extended_atomics"
+
+
+#define CL_KHR_INT64_EXTENDED_ATOMICS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_kernel_clock
+***************************************************************/
+#define cl_khr_kernel_clock 1
+#define CL_KHR_KERNEL_CLOCK_EXTENSION_NAME \
+    "cl_khr_kernel_clock"
+
+
+#define CL_KHR_KERNEL_CLOCK_EXTENSION_VERSION CL_MAKE_VERSION(0, 9, 0)
+
+/* cl_device_info */
+#define CL_DEVICE_KERNEL_CLOCK_CAPABILITIES_KHR             0x1076
+
+typedef cl_bitfield         cl_device_kernel_clock_capabilities_khr;
+
+/* cl_device_kernel_clock_capabilities_khr */
+#define CL_DEVICE_KERNEL_CLOCK_SCOPE_DEVICE_KHR             (1 << 0)
+#define CL_DEVICE_KERNEL_CLOCK_SCOPE_WORK_GROUP_KHR         (1 << 1)
+#define CL_DEVICE_KERNEL_CLOCK_SCOPE_SUB_GROUP_KHR          (1 << 2)
+
+/***************************************************************
+* cl_khr_local_int32_base_atomics
+***************************************************************/
+#define cl_khr_local_int32_base_atomics 1
+#define CL_KHR_LOCAL_INT32_BASE_ATOMICS_EXTENSION_NAME \
+    "cl_khr_local_int32_base_atomics"
+
+
+#define CL_KHR_LOCAL_INT32_BASE_ATOMICS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_local_int32_extended_atomics
+***************************************************************/
+#define cl_khr_local_int32_extended_atomics 1
+#define CL_KHR_LOCAL_INT32_EXTENDED_ATOMICS_EXTENSION_NAME \
+    "cl_khr_local_int32_extended_atomics"
+
+
+#define CL_KHR_LOCAL_INT32_EXTENDED_ATOMICS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_mipmap_image_writes
+***************************************************************/
+#define cl_khr_mipmap_image_writes 1
+#define CL_KHR_MIPMAP_IMAGE_WRITES_EXTENSION_NAME \
+    "cl_khr_mipmap_image_writes"
+
+
+#define CL_KHR_MIPMAP_IMAGE_WRITES_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_select_fprounding_mode
+***************************************************************/
+#define cl_khr_select_fprounding_mode 1
+#define CL_KHR_SELECT_FPROUNDING_MODE_EXTENSION_NAME \
+    "cl_khr_select_fprounding_mode"
+
+
+#define CL_KHR_SELECT_FPROUNDING_MODE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_spirv_extended_debug_info
+***************************************************************/
+#define cl_khr_spirv_extended_debug_info 1
+#define CL_KHR_SPIRV_EXTENDED_DEBUG_INFO_EXTENSION_NAME \
+    "cl_khr_spirv_extended_debug_info"
+
+
+#define CL_KHR_SPIRV_EXTENDED_DEBUG_INFO_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_spirv_linkonce_odr
+***************************************************************/
+#define cl_khr_spirv_linkonce_odr 1
+#define CL_KHR_SPIRV_LINKONCE_ODR_EXTENSION_NAME \
+    "cl_khr_spirv_linkonce_odr"
+
+
+#define CL_KHR_SPIRV_LINKONCE_ODR_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_spirv_no_integer_wrap_decoration
+***************************************************************/
+#define cl_khr_spirv_no_integer_wrap_decoration 1
+#define CL_KHR_SPIRV_NO_INTEGER_WRAP_DECORATION_EXTENSION_NAME \
+    "cl_khr_spirv_no_integer_wrap_decoration"
+
+
+#define CL_KHR_SPIRV_NO_INTEGER_WRAP_DECORATION_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_srgb_image_writes
+***************************************************************/
+#define cl_khr_srgb_image_writes 1
+#define CL_KHR_SRGB_IMAGE_WRITES_EXTENSION_NAME \
+    "cl_khr_srgb_image_writes"
+
+
+#define CL_KHR_SRGB_IMAGE_WRITES_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_subgroup_ballot
+***************************************************************/
+#define cl_khr_subgroup_ballot 1
+#define CL_KHR_SUBGROUP_BALLOT_EXTENSION_NAME \
+    "cl_khr_subgroup_ballot"
+
+
+#define CL_KHR_SUBGROUP_BALLOT_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_subgroup_clustered_reduce
+***************************************************************/
+#define cl_khr_subgroup_clustered_reduce 1
+#define CL_KHR_SUBGROUP_CLUSTERED_REDUCE_EXTENSION_NAME \
+    "cl_khr_subgroup_clustered_reduce"
+
+
+#define CL_KHR_SUBGROUP_CLUSTERED_REDUCE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_subgroup_extended_types
+***************************************************************/
+#define cl_khr_subgroup_extended_types 1
+#define CL_KHR_SUBGROUP_EXTENDED_TYPES_EXTENSION_NAME \
+    "cl_khr_subgroup_extended_types"
+
+
+#define CL_KHR_SUBGROUP_EXTENDED_TYPES_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_subgroup_non_uniform_arithmetic
+***************************************************************/
+#define cl_khr_subgroup_non_uniform_arithmetic 1
+#define CL_KHR_SUBGROUP_NON_UNIFORM_ARITHMETIC_EXTENSION_NAME \
+    "cl_khr_subgroup_non_uniform_arithmetic"
+
+
+#define CL_KHR_SUBGROUP_NON_UNIFORM_ARITHMETIC_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_subgroup_non_uniform_vote
+***************************************************************/
+#define cl_khr_subgroup_non_uniform_vote 1
+#define CL_KHR_SUBGROUP_NON_UNIFORM_VOTE_EXTENSION_NAME \
+    "cl_khr_subgroup_non_uniform_vote"
+
+
+#define CL_KHR_SUBGROUP_NON_UNIFORM_VOTE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_subgroup_rotate
+***************************************************************/
+#define cl_khr_subgroup_rotate 1
+#define CL_KHR_SUBGROUP_ROTATE_EXTENSION_NAME \
+    "cl_khr_subgroup_rotate"
+
+
+#define CL_KHR_SUBGROUP_ROTATE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_subgroup_shuffle
+***************************************************************/
+#define cl_khr_subgroup_shuffle 1
+#define CL_KHR_SUBGROUP_SHUFFLE_EXTENSION_NAME \
+    "cl_khr_subgroup_shuffle"
+
+
+#define CL_KHR_SUBGROUP_SHUFFLE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_subgroup_shuffle_relative
+***************************************************************/
+#define cl_khr_subgroup_shuffle_relative 1
+#define CL_KHR_SUBGROUP_SHUFFLE_RELATIVE_EXTENSION_NAME \
+    "cl_khr_subgroup_shuffle_relative"
+
+
+#define CL_KHR_SUBGROUP_SHUFFLE_RELATIVE_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_khr_work_group_uniform_arithmetic
+***************************************************************/
+#define cl_khr_work_group_uniform_arithmetic 1
+#define CL_KHR_WORK_GROUP_UNIFORM_ARITHMETIC_EXTENSION_NAME \
+    "cl_khr_work_group_uniform_arithmetic"
+
+
+#define CL_KHR_WORK_GROUP_UNIFORM_ARITHMETIC_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/***************************************************************
+* cl_ext_image_unorm_int_2_101010
+***************************************************************/
+#define cl_ext_image_unorm_int_2_101010 1
+#define CL_EXT_IMAGE_UNORM_INT_2_101010_EXTENSION_NAME \
+    "cl_ext_image_unorm_int_2_101010"
+
+
+#define CL_EXT_IMAGE_UNORM_INT_2_101010_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+/* cl_channel_type */
+#define CL_UNORM_INT_2_101010_EXT                           0x10E5
+
+/***************************************************************
+* cl_img_cancel_command
+***************************************************************/
+#define cl_img_cancel_command 1
+#define CL_IMG_CANCEL_COMMAND_EXTENSION_NAME \
+    "cl_img_cancel_command"
+
+
+#define CL_IMG_CANCEL_COMMAND_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
+/* Error codes */
+#define CL_CANCELLED_IMG                                    -1126
+
+
+typedef cl_int CL_API_CALL
+clCancelCommandsIMG_t(
+    const cl_event* event_list,
+    size_t num_events_in_list);
+
+typedef clCancelCommandsIMG_t *
+clCancelCommandsIMG_fn ;
+
+#if !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES)
+
+extern CL_API_ENTRY cl_int CL_API_CALL
+clCancelCommandsIMG(
+    const cl_event* event_list,
+    size_t num_events_in_list) ;
+
+#endif /* !defined(CL_NO_NON_ICD_DISPATCH_EXTENSION_PROTOTYPES) */
+
 #ifdef __cplusplus
 }
 #endif
diff --git a/CL/cl_gl.h b/CL/cl_gl.h
index f5b1e37..552560f 100644
--- a/CL/cl_gl.h
+++ b/CL/cl_gl.h
@@ -51,6 +51,13 @@ extern "C" {
 #define CL_KHR_GL_SHARING_EXTENSION_NAME \
     "cl_khr_gl_sharing"
 
+
+#define CL_KHR_GL_SHARING_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
+typedef int                 cl_GLint;
+typedef unsigned int        cl_GLenum;
+typedef unsigned int        cl_GLuint;
+
 typedef cl_uint             cl_gl_context_info;
 
 /* Error codes */
@@ -313,6 +320,9 @@ clCreateFromGLTexture3D(
 #define CL_KHR_GL_EVENT_EXTENSION_NAME \
     "cl_khr_gl_event"
 
+
+#define CL_KHR_GL_EVENT_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef struct __GLsync *   cl_GLsync;
 
 /* cl_command_type */
@@ -345,6 +355,9 @@ clCreateEventFromGLsyncKHR(
 #define CL_KHR_GL_DEPTH_IMAGES_EXTENSION_NAME \
     "cl_khr_gl_depth_images"
 
+
+#define CL_KHR_GL_DEPTH_IMAGES_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_channel_order */
 #define CL_DEPTH_STENCIL                                    0x10BE
 
@@ -358,6 +371,9 @@ clCreateEventFromGLsyncKHR(
 #define CL_KHR_GL_MSAA_SHARING_EXTENSION_NAME \
     "cl_khr_gl_msaa_sharing"
 
+
+#define CL_KHR_GL_MSAA_SHARING_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 /* cl_gl_texture_info */
 #define CL_GL_NUM_SAMPLES                                   0x2012
 
@@ -368,6 +384,9 @@ clCreateEventFromGLsyncKHR(
 #define CL_INTEL_SHARING_FORMAT_QUERY_GL_EXTENSION_NAME \
     "cl_intel_sharing_format_query_gl"
 
+
+#define CL_INTEL_SHARING_FORMAT_QUERY_GL_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* when cl_khr_gl_sharing is supported */
 
 typedef cl_int CL_API_CALL
diff --git a/CL/cl_layer.h b/CL/cl_layer.h
index a43b897..245f7b5 100644
--- a/CL/cl_layer.h
+++ b/CL/cl_layer.h
@@ -53,6 +53,9 @@ extern "C" {
 #define CL_LOADER_LAYERS_EXTENSION_NAME \
     "cl_loader_layers"
 
+
+#define CL_LOADER_LAYERS_EXTENSION_VERSION CL_MAKE_VERSION(1, 0, 0)
+
 typedef cl_uint             cl_layer_info;
 typedef cl_uint             cl_layer_api_version;
 
diff --git a/CL/cl_platform.h b/CL/cl_platform.h
index e7a0d6f..5f92d6f 100644
--- a/CL/cl_platform.h
+++ b/CL/cl_platform.h
@@ -77,7 +77,7 @@ extern "C" {
 #ifdef __GNUC__
   #define CL_API_SUFFIX_DEPRECATED __attribute__((deprecated))
   #define CL_API_PREFIX_DEPRECATED
-#elif defined(_WIN32)
+#elif defined(_MSC_VER) && !defined(__clang__)
   #define CL_API_SUFFIX_DEPRECATED
   #define CL_API_PREFIX_DEPRECATED __declspec(deprecated)
 #else
@@ -361,11 +361,6 @@ typedef double          cl_double;
 
 #include <stddef.h>
 
-/* Mirror types to GL types. Mirror types allow us to avoid deciding which 87s to load based on whether we are using GL or GLES here. */
-typedef unsigned int cl_GLuint;
-typedef int          cl_GLint;
-typedef unsigned int cl_GLenum;
-
 /*
  * Vector types
  *
diff --git a/CL/cl_va_api_media_sharing_intel.h b/CL/cl_va_api_media_sharing_intel.h
index 93f5d8b..9fb8863 100644
--- a/CL/cl_va_api_media_sharing_intel.h
+++ b/CL/cl_va_api_media_sharing_intel.h
@@ -53,6 +53,9 @@ extern "C" {
 #define CL_INTEL_SHARING_FORMAT_QUERY_VA_API_EXTENSION_NAME \
     "cl_intel_sharing_format_query_va_api"
 
+
+#define CL_INTEL_SHARING_FORMAT_QUERY_VA_API_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 /* when cl_intel_va_api_media_sharing is supported */
 
 typedef cl_int CL_API_CALL
@@ -89,6 +92,9 @@ clGetSupportedVA_APIMediaSurfaceFormatsINTEL(
 #define CL_INTEL_VA_API_MEDIA_SHARING_EXTENSION_NAME \
     "cl_intel_va_api_media_sharing"
 
+
+#define CL_INTEL_VA_API_MEDIA_SHARING_EXTENSION_VERSION CL_MAKE_VERSION(0, 0, 0)
+
 typedef cl_uint             cl_va_api_device_source_intel;
 typedef cl_uint             cl_va_api_device_set_intel;
 
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 7002c37..1b20774 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,5 +1,4 @@
-cmake_minimum_required(VERSION 3.0)
-cmake_policy(VERSION 3.0...3.22)
+cmake_minimum_required(VERSION 3.16...3.26)
 
 # Include guard for including this project multiple times
 if(TARGET Headers)
@@ -7,7 +6,7 @@ if(TARGET Headers)
 endif()
 
 project(OpenCLHeaders
-  VERSION 2.2
+  VERSION 3.0
   LANGUAGES C # Ideally should be NONE, but GNUInstallDirs detects platform arch using try_compile
   # https://stackoverflow.com/questions/43379311/why-does-project-affect-cmakes-opinion-on-cmake-sizeof-void-p
 )
@@ -16,9 +15,9 @@ option(OPENCL_HEADERS_BUILD_TESTING "Enable support for OpenCL C headers testing
 option(OPENCL_HEADERS_BUILD_CXX_TESTS "Enable support for OpenCL C headers testing in C++ mode." ON)
 
 set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
-include(JoinPaths)
-
 include(GNUInstallDirs)
+include(JoinPaths)
+include(Package)
 
 add_library(Headers INTERFACE)
 add_library(OpenCL::Headers ALIAS Headers)
@@ -140,11 +139,3 @@ if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
     set_target_properties(headers_generate PROPERTIES FOLDER "Generation")
     set_target_properties(headers_copy PROPERTIES FOLDER "Generation")
 endif()
-
-join_paths(OPENCL_INCLUDEDIR_PC "\${prefix}" "${CMAKE_INSTALL_INCLUDEDIR}")
-
-configure_file(OpenCL-Headers.pc.in OpenCL-Headers.pc @ONLY)
-set(pkg_config_location ${CMAKE_INSTALL_DATADIR}/pkgconfig)
-install(
-  FILES ${CMAKE_CURRENT_BINARY_DIR}/OpenCL-Headers.pc
-  DESTINATION ${pkg_config_location})
diff --git a/METADATA b/METADATA
index bcd95f1..6605653 100644
--- a/METADATA
+++ b/METADATA
@@ -1,15 +1,21 @@
-name: "OpenCL-Headers"
-description:
-    "OpenCL Headers"
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/OpenCL-Headers
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "OpenCL-Headers"
+description: "OpenCL Headers"
 third_party {
-homepage: "https://github.com/KhronosGroup/OpenCL-Headers"
+  license_type: NOTICE
+  last_upgrade_date {
+    year: 2025
+    month: 4
+    day: 24
+  }
+  homepage: "https://github.com/KhronosGroup/OpenCL-Headers"
   identifier {
     type: "Archive"
     value: "https://github.com/KhronosGroup/OpenCL-Headers"
+    version: "v2024.10.24"
     primary_source: true
   }
-  version: "v2023.12.14"
-  last_upgrade_date { year: 2024 month: 2 day: 22 }
-  license_type: NOTICE
 }
diff --git a/OpenCL-Headers.pc.in b/OpenCL-Headers.pc.in
index 92d241c..5cc13fb 100644
--- a/OpenCL-Headers.pc.in
+++ b/OpenCL-Headers.pc.in
@@ -1,4 +1,4 @@
-prefix=@CMAKE_INSTALL_PREFIX@
+prefix=@PKGCONFIG_PREFIX@
 includedir=@OPENCL_INCLUDEDIR_PC@
 
 Name: OpenCL-Headers
diff --git a/README.md b/README.md
index 1a49189..93756c8 100644
--- a/README.md
+++ b/README.md
@@ -123,6 +123,11 @@ LICENSE                 Source license for the OpenCL API headers
 CL/                     Unified OpenCL API headers tree
 ```
 
+## Packaging
+
+For packaging instructions, see [RELEASE.md](https://github.com/KhronosGroup/OpenCL-SDK/blob/main/docs/RELEASE.md)
+in the OpenCL SDK repository.
+
 ## License
 
 See [LICENSE](LICENSE).
diff --git a/cmake/DebSourcePkg.cmake b/cmake/DebSourcePkg.cmake
new file mode 100644
index 0000000..9199a8c
--- /dev/null
+++ b/cmake/DebSourcePkg.cmake
@@ -0,0 +1,125 @@
+# This script produces the changelog, control and rules file in the debian
+# directory. These files are needed to build a Debian source package from the repository.
+# Run this in CMake script mode, e.g.
+# $ cd OpenCL-Headers
+# $ cmake -S . -B ../build -D BUILD_TESTING=OFF
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
+set(DEB_SOURCE_PKG_NAME "khronos-opencl-headers")
+set(DEB_CLHPP_PKG_NAME "opencl-clhpp-headers")
+set(DEB_META_PKG_NAME "opencl-headers")
+set(DEB_META_PKG_DESCRIPTION "OpenCL (Open Computing Language) header files
+ OpenCL (Open Computing Language) is a multi-vendor open standard for
+ general-purpose parallel programming of heterogeneous systems that include
+ CPUs, GPUs and other processors.
+ .
+ This metapackage depends on packages providing the C and C++ headers files
+ for the OpenCL API as published by The Khronos Group Inc.  The corresponding
+ specification and documentation can be found on the Khronos website.")
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
+string(REPLACE "\n" "\n " CPACK_PACKAGE_DESCRIPTION "${CPACK_PACKAGE_DESCRIPTION}")
+
+set(DEB_SOURCE_PKG_DIR "${CMAKE_CURRENT_LIST_DIR}/../debian")
+# Write debian/control
+file(WRITE "${DEB_SOURCE_PKG_DIR}/control"
+"Source: ${DEB_SOURCE_PKG_NAME}
+Section: ${CPACK_DEBIAN_PACKAGE_SECTION}
+Priority: optional
+Maintainer: ${DEBIAN_PACKAGE_MAINTAINER}
+Build-Depends: cmake, debhelper-compat (=13)
+Rules-Requires-Root: no
+Homepage: ${CPACK_DEBIAN_PACKAGE_HOMEPAGE}
+Standards-Version: 4.6.2
+
+Package: ${DEBIAN_PACKAGE_NAME}
+Architecture: ${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}
+Multi-Arch: foreign
+Breaks: ${CPACK_DEBIAN_PACKAGE_BREAKS}
+Replaces: ${CPACK_DEBIAN_PACKAGE_REPLACES}
+Description: ${CPACK_PACKAGE_DESCRIPTION}
+
+Package: ${DEB_META_PKG_NAME}
+Architecture: ${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}
+Multi-Arch: foreign
+Depends: ${DEBIAN_PACKAGE_NAME} (= ${PACKAGE_VERSION_REVISION}), ${DEB_CLHPP_PKG_NAME} (= ${PACKAGE_VERSION_REVISION})
+Description: ${DEB_META_PKG_DESCRIPTION}
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
+\tdh_auto_configure -- -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
+
+override_dh_auto_install:
+\tdh_auto_install --destdir=debian/${DEBIAN_PACKAGE_NAME}/
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
index 0000000..6e207c1
--- /dev/null
+++ b/cmake/Package.cmake
@@ -0,0 +1,47 @@
+include("${CMAKE_CURRENT_LIST_DIR}/PackageSetup.cmake")
+
+# Configuring pkgconfig
+
+# We need two different instances of OpenCL-Headers.pc
+# One for installing (cmake --install), which contains CMAKE_INSTALL_PREFIX as prefix
+# And another for the Debian package, which contains CPACK_PACKAGING_INSTALL_PREFIX as prefix
+
+join_paths(OPENCL_INCLUDEDIR_PC "\${prefix}" "${CMAKE_INSTALL_INCLUDEDIR}")
+
+set(pkg_config_location ${CMAKE_INSTALL_DATADIR}/pkgconfig)
+set(PKGCONFIG_PREFIX "${CMAKE_INSTALL_PREFIX}")
+configure_file(
+  OpenCL-Headers.pc.in
+  ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_install/OpenCL-Headers.pc
+  @ONLY)
+install(
+  FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_install/OpenCL-Headers.pc
+  DESTINATION ${pkg_config_location}
+  COMPONENT pkgconfig_install)
+
+set(PKGCONFIG_PREFIX "${CPACK_PACKAGING_INSTALL_PREFIX}")
+configure_file(
+  OpenCL-Headers.pc.in
+  ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_package/OpenCL-Headers.pc
+  @ONLY)
+# This install component is only needed in the Debian package
+install(
+  FILES ${CMAKE_CURRENT_BINARY_DIR}/pkgconfig_package/OpenCL-Headers.pc
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
index 0000000..92075a0
--- /dev/null
+++ b/cmake/PackageSetup.cmake
@@ -0,0 +1,56 @@
+set(CPACK_PACKAGE_VENDOR "khronos")
+
+set(CPACK_PACKAGE_DESCRIPTION "OpenCL (Open Computing Language) C header files
+OpenCL (Open Computing Language) is a multi-vendor open standard for
+general-purpose parallel programming of heterogeneous systems that include
+CPUs, GPUs and other processors.
+.
+This package provides the C development header files for the OpenCL API
+as published by The Khronos Group Inc.  The corresponding specification and
+documentation can be found on the Khronos website.")
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
+if(NOT DEFINED CPACK_DEBIAN_PACKAGE_MAINTAINER)
+  set(CPACK_DEBIAN_PACKAGE_MAINTAINER ${CPACK_PACKAGE_VENDOR})
+endif()
+
+set(CPACK_DEBIAN_PACKAGE_HOMEPAGE
+    "https://github.com/KhronosGroup/OpenCL-Headers")
+
+# Version number [epoch:]upstream_version[-debian_revision]
+set(CPACK_DEBIAN_PACKAGE_VERSION "${PROJECT_VERSION}")  # upstream_version
+if(DEFINED LATEST_RELEASE_VERSION)
+    # Remove leading "v", if exists
+    string(LENGTH "${LATEST_RELEASE_VERSION}" LATEST_RELEASE_VERSION_LENGTH)
+    string(SUBSTRING "${LATEST_RELEASE_VERSION}" 0 1 LATEST_RELEASE_VERSION_FRONT)
+    if(LATEST_RELEASE_VERSION_FRONT STREQUAL "v")
+        string(SUBSTRING "${LATEST_RELEASE_VERSION}" 1 ${LATEST_RELEASE_VERSION_LENGTH} LATEST_RELEASE_VERSION)
+    endif()
+
+  string(APPEND CPACK_DEBIAN_PACKAGE_VERSION "~${LATEST_RELEASE_VERSION}")
+endif()
+set(CPACK_DEBIAN_PACKAGE_RELEASE "1") # debian_revision (because this is a
+                                      # non-native pkg)
+set(PACKAGE_VERSION_REVISION "${CPACK_DEBIAN_PACKAGE_VERSION}-${CPACK_DEBIAN_PACKAGE_RELEASE}${DEBIAN_VERSION_SUFFIX}")
+
+set(DEBIAN_PACKAGE_NAME "opencl-c-headers")
+set(CPACK_DEBIAN_PACKAGE_NAME
+    "${DEBIAN_PACKAGE_NAME}"
+    CACHE STRING "Package name" FORCE)
+
+set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "all")
+set(CPACK_DEBIAN_PACKAGE_SECTION "libdevel")
+set(CPACK_DEBIAN_PACKAGE_BREAKS "opencl-headers (<< ${CPACK_DEBIAN_PACKAGE_VERSION}), opencl-clhpp-headers (<< ${CPACK_DEBIAN_PACKAGE_VERSION})")
+set(CPACK_DEBIAN_PACKAGE_REPLACES "opencl-headers (<< ${CPACK_DEBIAN_PACKAGE_VERSION})")
+
+# Package file name in deb format:
+# <PackageName>_<VersionNumber>-<DebianRevisionNumber>_<DebianArchitecture>.deb
+set(CPACK_DEBIAN_FILE_NAME "${DEBIAN_PACKAGE_NAME}_${PACKAGE_VERSION_REVISION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}.deb")
diff --git a/scripts/check-format.sh b/scripts/check-format.sh
new file mode 100755
index 0000000..24c6166
--- /dev/null
+++ b/scripts/check-format.sh
@@ -0,0 +1,55 @@
+#!/usr/bin/env bash
+
+SOURCE_COMMIT="$1"
+if [ "$#" -gt 0 ]; then
+    shift
+fi
+
+# If no source commit is given target the default branch
+if [ "x$SOURCE_COMMIT" = "x" ]; then
+    # If remote is not set use the remote of the current branch or fallback to "origin"
+    if [ "x$REMOTE" = "x" ]; then
+        BRANCH="$(git rev-parse --abbrev-ref HEAD)"
+        REMOTE="$(git config --local --get "branch.$BRANCH.remote" || echo 'origin')"
+    fi
+    SOURCE_COMMIT="remotes/$REMOTE/HEAD"
+fi
+
+# Force colored diff output
+DIFF_COLOR_SAVED="$(git config --local --get color.diff)"
+if [ "x$DIFF_COLOR_SAVED" != "x" ]; then
+    git config --local --replace-all "color.diff" "always"
+else
+    git config --local --add "color.diff" "always"
+fi
+
+scratch="$(mktemp -t check-format.XXXXXXXXXX)"
+finish () {
+    # Remove temporary file
+    rm -rf "$scratch"
+    # Restore setting
+    if [ "x$DIFF_COLOR_SAVED" != "x" ]; then
+        git config --local --replace-all "color.diff" "$DIFF_COLOR_SAVED"
+    else
+        git config --local --unset "color.diff"
+    fi
+}
+# The trap will be invoked whenever the script exits, even due to a signal, this is a bash only
+# feature
+trap finish EXIT
+
+GIT_CLANG_FORMAT="${GIT_CLANG_FORMAT:-git-clang-format}"
+"$GIT_CLANG_FORMAT" --style=file --extensions=cc,cp,cpp,c++,cxx,cu,cuh,hh,hpp,hxx,hip,vert,frag --diff "$@" "$SOURCE_COMMIT" > "$scratch"
+
+# Check for no-ops
+grep '^no modified files to format$\|^clang-format did not modify any files$' \
+    "$scratch" > /dev/null && exit 0
+
+# Dump formatting diff and signal failure
+printf \
+"\033[31m==== FORMATTING VIOLATIONS DETECTED ====\033[0m
+run '\033[33m%s --style=file %s %s\033[0m' to apply these formating changes\n\n" \
+"$GIT_CLANG_FORMAT" "$*" "$SOURCE_COMMIT"
+
+cat "$scratch"
+exit 1
diff --git a/scripts/cl_ext.h.mako b/scripts/cl_ext.h.mako
index c1f8926..f42bb1b 100644
--- a/scripts/cl_ext.h.mako
+++ b/scripts/cl_ext.h.mako
@@ -1,4 +1,7 @@
 <%
+# re.match used to parse extension semantic versions
+from re import match
+
 # Extensions to skip by default because they are in dedicated headers:
 skipExtensions = {
     'cl_khr_d3d10_sharing',
@@ -312,6 +315,19 @@ extern "C" {
 #define ${name.upper()}_EXTENSION_NAME ${"\\"}
     "${name}"
 
+<%
+  # Use re.match to parse semantic major.minor.patch version
+  sem_ver = match('[0-9]+\.[0-9]+\.?[0-9]+', extension.get('revision'))
+  if not sem_ver:
+    raise TypeError(name +
+      ' XML revision field is not semantically versioned as "major.minor.patch"')
+  version = sem_ver[0].split('.')
+  major = version[0]
+  minor = version[1]
+  patch = version[2]
+%>
+#define ${name.upper()}_EXTENSION_VERSION CL_MAKE_VERSION(${major}, ${minor}, ${patch})
+
 %for block in extension.findall('require'):
 %  if shouldEmit(block):
 %    if block.get('condition'):
diff --git a/tests/lang_c/CMakeLists.txt b/tests/lang_c/CMakeLists.txt
index 0678dde..df8cd5c 100644
--- a/tests/lang_c/CMakeLists.txt
+++ b/tests/lang_c/CMakeLists.txt
@@ -16,3 +16,4 @@ add_header_test(cl_platform_h test_cl_platform.h.c)
 add_header_test(cl_opencl_h test_opencl.h.c)
 add_header_test(cl_version_h test_cl_version.h.c)
 add_header_test(headers test_headers.c)
+add_header_test(ext_headers test_ext_headers.c)
diff --git a/tests/lang_cpp/CMakeLists.txt b/tests/lang_cpp/CMakeLists.txt
index 0678dde..f4ef234 100644
--- a/tests/lang_cpp/CMakeLists.txt
+++ b/tests/lang_cpp/CMakeLists.txt
@@ -15,4 +15,4 @@ add_header_test(cl_layer_h test_cl_layer.h.c)
 add_header_test(cl_platform_h test_cl_platform.h.c)
 add_header_test(cl_opencl_h test_opencl.h.c)
 add_header_test(cl_version_h test_cl_version.h.c)
-add_header_test(headers test_headers.c)
+add_header_test(ext_headers test_ext_headers.c)
diff --git a/tests/pkgconfig/bare/CMakeLists.txt b/tests/pkgconfig/bare/CMakeLists.txt
index 866831a..f3e8466 100644
--- a/tests/pkgconfig/bare/CMakeLists.txt
+++ b/tests/pkgconfig/bare/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required(VERSION 3.0)
+cmake_minimum_required(VERSION 3.16)
 
 project(PkgConfigTest
   LANGUAGES C
@@ -21,3 +21,10 @@ target_compile_definitions(${PROJECT_NAME}
   PRIVATE
     CL_TARGET_OPENCL_VERSION=120
 )
+
+include(CTest)
+
+add_test(
+  NAME ${PROJECT_NAME}
+  COMMAND ${PROJECT_NAME}
+)
diff --git a/tests/pkgconfig/pkgconfig.c b/tests/pkgconfig/pkgconfig.c
index d4c1f01..a520a13 100644
--- a/tests/pkgconfig/pkgconfig.c
+++ b/tests/pkgconfig/pkgconfig.c
@@ -1,6 +1,3 @@
 #include <CL/cl.h>
 
-int main()
-{
-    return sizeof(cl_platform_id) - sizeof(cl_context);
-}
+int main(void) { return sizeof(cl_platform_id) - sizeof(cl_context); }
diff --git a/tests/pkgconfig/sdk/CMakeLists.txt b/tests/pkgconfig/sdk/CMakeLists.txt
index 75f5604..aa36d16 100644
--- a/tests/pkgconfig/sdk/CMakeLists.txt
+++ b/tests/pkgconfig/sdk/CMakeLists.txt
@@ -1,4 +1,4 @@
-cmake_minimum_required(VERSION 3.0)
+cmake_minimum_required(VERSION 3.16)
 
 project(PkgConfigTest
   LANGUAGES C
@@ -22,3 +22,10 @@ target_compile_definitions(${PROJECT_NAME}
   PRIVATE
     CL_TARGET_OPENCL_VERSION=120
 )
+
+include(CTest)
+
+add_test(
+  NAME ${PROJECT_NAME}
+  COMMAND ${PROJECT_NAME}
+)
diff --git a/tests/test_ext_headers.c b/tests/test_ext_headers.c
new file mode 100644
index 0000000..e50ba50
--- /dev/null
+++ b/tests/test_ext_headers.c
@@ -0,0 +1,56 @@
+//
+// Copyright (c) 2024 The Khronos Group Inc.
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//    http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+#include "CL/cl_ext.h"
+#include <inttypes.h>
+#include <stdio.h>
+
+int extVersionMacro(void)
+{
+    // Test a non-provisional extension with non-placeholder semantic version.
+    printf("Checking version macro for the cl_khr_integer_dot_product "
+           "extension\n");
+
+    cl_version ExtVersion = CL_KHR_INTEGER_DOT_PRODUCT_EXTENSION_VERSION;
+    cl_version ExtMajorVersion = CL_VERSION_MAJOR(ExtVersion);
+    cl_version ExtMinorVersion = CL_VERSION_MINOR(ExtVersion);
+    cl_version ExtPatchVersion = CL_VERSION_PATCH(ExtVersion);
+
+    printf("cl_khr_integer_dot_product version value %" PRIu32
+           " which is semantic version %" PRIu32 ".%" PRIu32 ".%" PRIu32 "\n",
+           ExtVersion, ExtMajorVersion, ExtMinorVersion, ExtPatchVersion);
+
+    // Test vendor extension which uses default semantic version.
+    printf("Checking version macro for the cl_APPLE_SetMemObjectDestructor\n");
+
+    ExtVersion = CL_APPLE_SETMEMOBJECTDESTRUCTOR_EXTENSION_VERSION;
+    ExtMajorVersion = CL_VERSION_MAJOR(ExtVersion);
+    ExtMinorVersion = CL_VERSION_MINOR(ExtVersion);
+    ExtPatchVersion = CL_VERSION_PATCH(ExtVersion);
+
+    printf("cl_APPLE_SetMemObjectDestructor version value %" PRIu32
+           " which is semantic version %" PRIu32 ".%" PRIu32 ".%" PRIu32 "\n",
+           ExtVersion, ExtMajorVersion, ExtMinorVersion, ExtPatchVersion);
+
+    return 0;
+}
+
+int main(void)
+{
+    int Result = extVersionMacro();
+
+    return Result;
+}
diff --git a/tests/test_headers.c b/tests/test_headers.c
index 460a182..65e5f5d 100644
--- a/tests/test_headers.c
+++ b/tests/test_headers.c
@@ -29,7 +29,7 @@ will use inttypes.h for C compiles and cinttypes for C++ compiles.
 
 #include "CL/cl.h"
 
-int test_char()
+int test_char(void)
 {
 /* char */
     /* Constructor */
@@ -89,7 +89,7 @@ int test_char()
     return 0;
 }
 
-int test_uchar()
+int test_uchar(void)
 {
 /* uchar */
     /* Constructor */
@@ -149,7 +149,7 @@ int test_uchar()
     return 0;
 }
 
-int test_short()
+int test_short(void)
 {
 /* short */
     /* Constructor */
@@ -209,7 +209,7 @@ int test_short()
     return 0;
 }
 
-int test_ushort()
+int test_ushort(void)
 {
 /* ushort */
     /* Constructor */
@@ -269,7 +269,7 @@ int test_ushort()
     return 0;
 }
 
-int test_int()
+int test_int(void)
 {
 /* int */
     /* Constructor */
@@ -329,7 +329,7 @@ int test_int()
     return 0;
 }
 
-int test_uint()
+int test_uint(void)
 {
 /* uint */
     /* Constructor */
@@ -389,7 +389,7 @@ int test_uint()
     return 0;
 }
 
-int test_long()
+int test_long(void)
 {
 /* long */
     /* Constructor */
@@ -449,7 +449,7 @@ int test_long()
     return 0;
 }
 
-int test_ulong()
+int test_ulong(void)
 {
 /* ulong */
     /* Constructor */
@@ -509,7 +509,7 @@ int test_ulong()
     return 0;
 }
 
-int test_float()
+int test_float(void)
 {
 /* float */
     /* Constructor */
@@ -571,7 +571,7 @@ int test_float()
     return 0;
 }
 
-int test_double()
+int test_double(void)
 {
 /* double */
     /* Constructor */
```

