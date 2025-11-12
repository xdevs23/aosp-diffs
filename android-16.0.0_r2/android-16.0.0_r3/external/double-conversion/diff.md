```diff
diff --git a/.github/dependabot.yml b/.github/dependabot.yml
new file mode 100644
index 0000000..5bacb9a
--- /dev/null
+++ b/.github/dependabot.yml
@@ -0,0 +1,8 @@
+version: 2
+updates:
+  - package-ecosystem: "github-actions" # Necessary to update action hashs	
+    directory: "/"
+    schedule:
+      interval: "weekly"
+    # Allow up to 3 opened pull requests for github-actions versions
+    open-pull-requests-limit: 3
diff --git a/.github/workflows/ci.yml b/.github/workflows/ci.yml
new file mode 100644
index 0000000..a9ed08f
--- /dev/null
+++ b/.github/workflows/ci.yml
@@ -0,0 +1,71 @@
+name: ci
+
+on: push
+
+permissions:
+  contents: read
+
+jobs:
+  build:
+    strategy:
+      matrix:
+        container: [ ubuntu-latest, macos-latest, windows-latest ]
+        build_type: [ Debug, Release ]
+
+
+    # The CMake configure and build commands are platform agnostic and should work equally well on Windows or Mac.
+    # You can convert this to a matrix build if you need cross-platform coverage.
+    # See: https://docs.github.com/en/free-pro-team@latest/actions/learn-github-actions/managing-complex-workflows#using-a-build-matrix
+    runs-on: ${{ matrix.container }}
+
+    steps:
+      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
+
+      - name: Configure
+        shell: bash
+        # Configure CMake in a 'buildX' subdirectory.
+        # We can't use `build` as `BUILD` is already taken by the bazel build file.
+        # On Mac and Windows this leads to a conflict.
+        run: |
+          mkdir -p buildX
+          cd buildX
+          cmake -DBUILD_TESTING=ON \
+            -DCMAKE_BUILD_TYPE=${{ matrix.build_type }} \
+            -DCMAKE_INSTALL_PREFIX:PATH=${{ github.workspace }}/install_dir \
+            -DBUILD_SHARED_LIBS=ON \
+            ..
+
+      - name: Build shared
+        run: |
+          cmake --build buildX --config ${{ matrix.build_type }}
+
+      - name: Install shared
+        run: |
+          cmake --install buildX --config ${{ matrix.build_type }}
+
+      - name: Build static
+        run: |
+          cmake -DBUILD_SHARED_LIBS=OFF buildX
+          cmake --build buildX --config ${{ matrix.build_type }}
+
+      - name: Install static
+        run: |
+          cmake --install buildX --config ${{ matrix.build_type }}
+
+      - name: Test
+        if: runner.os != 'Windows'
+        working-directory: ${{ github.workspace }}/buildX
+        # Execute all tests.
+        run: |
+          ctest
+          # Also run the tests directly, just in case we forgot to add it to ctest.
+          test/cctest/cctest
+
+      - name: Test - Windows
+        if: runner.os == 'Windows'
+        working-directory: ${{ github.workspace }}/buildX
+        # Execute all tests.
+        run: |
+          ctest -C ${{ matrix.build_type }}
+          # Also run the tests directly, just in case we forgot to add it to ctest.
+          test/cctest/${{ matrix.build_type }}/cctest.exe
diff --git a/.github/workflows/cifuzz.yml b/.github/workflows/cifuzz.yml
new file mode 100644
index 0000000..f29b4dc
--- /dev/null
+++ b/.github/workflows/cifuzz.yml
@@ -0,0 +1,37 @@
+name: CIFuzz
+on: [pull_request]
+permissions:
+  contents: read
+jobs:
+ Fuzzing:
+   runs-on: ubuntu-latest
+   permissions:
+     security-events: write
+   steps:
+   - name: Build Fuzzers
+     id: build
+     uses: google/oss-fuzz/infra/cifuzz/actions/build_fuzzers@a790ab47e189e5e3b4941b991f4784ec769a9e70
+     with:
+       oss-fuzz-project-name: 'double-conversion'
+       language: c++
+   - name: Run Fuzzers
+     uses: google/oss-fuzz/infra/cifuzz/actions/run_fuzzers@a790ab47e189e5e3b4941b991f4784ec769a9e70
+     with:
+       oss-fuzz-project-name: 'double-conversion'
+       language: c++
+       fuzz-seconds: 300
+       output-sarif: true
+   - name: Upload Crash
+     uses: actions/upload-artifact@65d862660abb392b8c4a3d1195a2108db131dd05
+     if: failure() && steps.build.outcome == 'success'
+     with:
+       name: artifacts
+       path: ./out/artifacts
+   - name: Upload Sarif
+     if: always() && steps.build.outcome == 'success'
+     uses: github/codeql-action/upload-sarif@ce84bed59466c6755ffcf84a426881bafbb162e1
+     with:
+      # Path to SARIF file relative to the root of the repository
+      sarif_file: cifuzz-sarif/results.sarif
+      checkout_path: cifuzz-sarif
+      category: CIFuzz
diff --git a/.github/workflows/scons.yml b/.github/workflows/scons.yml
new file mode 100644
index 0000000..ccbb90d
--- /dev/null
+++ b/.github/workflows/scons.yml
@@ -0,0 +1,26 @@
+name: scons
+
+on: push
+
+permissions:
+  contents: read
+
+jobs:
+  build:
+    runs-on: ubuntu-latest
+
+    steps:
+      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
+
+      - name: Install dependencies
+        run: |
+          sudo apt-get update
+          sudo apt-get install scons
+
+      - name: Build
+        run: |
+          make
+
+      - name: Test
+        run: |
+          make test
diff --git a/.github/workflows/scorecard.yml b/.github/workflows/scorecard.yml
new file mode 100644
index 0000000..5ba1795
--- /dev/null
+++ b/.github/workflows/scorecard.yml
@@ -0,0 +1,63 @@
+# This workflow uses actions that are not certified by GitHub. They are provided
+# by a third-party and are governed by separate terms of service, privacy
+# policy, and support documentation.
+
+name: Scorecard supply-chain security
+on:
+  # For Branch-Protection check. Only the default branch is supported. See
+  # https://github.com/ossf/scorecard/blob/main/docs/checks.md#branch-protection
+  branch_protection_rule:
+  # To guarantee Maintained check is occasionally updated. See
+  # https://github.com/ossf/scorecard/blob/main/docs/checks.md#maintained
+  schedule:
+    - cron: '29 2 * * 0'
+  push:
+    branches: [ "master" ]
+
+# Declare default permissions as read only.
+permissions: read-all
+
+jobs:
+  analysis:
+    name: Scorecard analysis
+    runs-on: ubuntu-latest
+    permissions:
+      security-events: write # to upload the results to code-scanning dashboard
+      id-token: write # to publish results and get a badge
+
+    steps:
+      - name: "Checkout code"
+        uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
+        with:
+          persist-credentials: false
+
+      - name: "Run analysis"
+        uses: ossf/scorecard-action@62b2cac7ed8198b15735ed49ab1e5cf35480ba46 # v2.4.0
+        with:
+          results_file: results.sarif
+          results_format: sarif
+          # (Optional) "write" PAT token. Uncomment the `repo_token` line below if you want to enable the
+          # Branch-Protection check
+          # To create the PAT, follow the steps in https://github.com/ossf/scorecard-action#authentication-with-fine-grained-pat-optional.
+          # repo_token: ${{ secrets.SCORECARD_TOKEN }}
+
+          # Public repositories:
+          #   - Publish results to OpenSSF REST API for easy access by consumers
+          #   - Allows the repository to include the Scorecard badge.
+          #   - See https://github.com/ossf/scorecard-action#publishing-results.
+          publish_results: true
+
+      # Upload the results as artifacts (optional). Commenting out will disable uploads of run results in SARIF
+      # format to the repository Actions tab.
+      - name: "Upload artifact"
+        uses: actions/upload-artifact@v4
+        with:
+          name: SARIF file
+          path: results.sarif
+          retention-days: 5
+
+      # Upload the results to GitHub's code scanning dashboard.
+      - name: "Upload to code-scanning"
+        uses: github/codeql-action/upload-sarif@v2.20.4
+        with:
+          sarif_file: results.sarif
diff --git a/.gitignore b/.gitignore
new file mode 100644
index 0000000..e402d07
--- /dev/null
+++ b/.gitignore
@@ -0,0 +1,31 @@
+.sconsign.dblite
+*~
+*.o
+*.obj
+msvc/Release/
+msvc/Debug/
+*.suo
+*.opensdf
+*.sdf
+*.user
+*.a
+*.so
+*.so.*
+*.dylib
+/run_tests
+Makefile
+CMakeLists.txt.user
+CMakeCache.txt
+CMakeFiles
+CMakeScripts
+Testing
+cmake_install.cmake
+install_manifest.txt
+compile_commands.json
+CTestTestfile.cmake
+_deps
+*.cmake
+*.kdev4
+DartConfiguration.tcl
+bazel-*
+.cache
diff --git a/BUILD b/BUILD
index 8c2eee5..939ca12 100644
--- a/BUILD
+++ b/BUILD
@@ -1,7 +1,5 @@
 # Bazel(http://bazel.io) BUILD file
 
-load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
-
 licenses(["notice"])
 
 exports_files(["LICENSE"])
diff --git a/CMakeLists.txt b/CMakeLists.txt
index e9a82a2..8749ef8 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,14 +1,18 @@
 cmake_minimum_required(VERSION 3.0)
-project(double-conversion VERSION 3.2.0)
+project(double-conversion VERSION 3.3.0)
 
 option(BUILD_SHARED_LIBS "Build shared libraries (.dll/.so) instead of static ones (.lib/.a)" OFF)
 
-if(BUILD_SHARED_LIBS AND MSVC)
-  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
+if(MSVC)
+  if(BUILD_SHARED_LIBS)
+    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
+  endif()
+  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /D_DEBUG /D_ITERATOR_DEBUG_LEVEL=2")
 endif()
 
 set(headers
     double-conversion/bignum.h
+    double-conversion/bignum-dtoa.h
     double-conversion/cached-powers.h
     double-conversion/diy-fp.h
     double-conversion/double-conversion.h
diff --git a/Changelog b/Changelog
index 553fa84..9530b49 100644
--- a/Changelog
+++ b/Changelog
@@ -1,3 +1,22 @@
+2023-05-18:
+  Add flags to control trailing decimal and zero in exponent
+  form when input has one significant digit.
+
+  Update changelog and version number.
+
+2022-09-01:
+  Fix some compile warnings in Visual Studio.
+
+2022-07-07:
+  Fixed all -Wzero-as-null-pointer-constant warnings.
+
+2022-06-25:
+  Add a cast to silence a signedness conversion warning.
+
+2022-01-30:
+  Fix warnings on Windows.
+  Give shared-lib option.
+
 2022-01-16:
   Install Visual Studio debugger (pdb) files.
 
diff --git a/METADATA b/METADATA
index baaeb18..86e9f85 100644
--- a/METADATA
+++ b/METADATA
@@ -1,16 +1,19 @@
-name: "doubleconversion"
-description:
-    "This project (double-conversion) provides binary-decimal and "
-    "decimal-binary routines for IEEE doubles. "
-    " "
-    ""
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/double-conversion
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
+name: "double-conversion"
+description: "Efficient binary-decimal and decimal-binary conversion routines for IEEE doubles."
 third_party {
-  url {
-    type: GIT
-    value: "https://github.com/google/double-conversion"
-  }
-  version: "v3.2.1"
-  last_upgrade_date { year: 2022 month: 10 day: 18 }
   license_type: NOTICE
-}
\ No newline at end of file
+  last_upgrade_date {
+    year: 2025
+    month: 4
+    day: 28
+  }
+  identifier {
+    type: "Archive"
+    value: "https://github.com/google/double-conversion/archive/v3.3.1.tar.gz"
+    version: "v3.3.1"
+  }
+}
diff --git a/MODULE.bazel b/MODULE.bazel
new file mode 100644
index 0000000..cfda296
--- /dev/null
+++ b/MODULE.bazel
@@ -0,0 +1,7 @@
+"""This project (double-conversion) provides binary-decimal and decimal-binary routines for IEEE doubles."""
+
+module(
+    name = "double-conversion",
+    version = "3.3.0",
+    compatibility_level = 3,
+)
diff --git a/README.md b/README.md
index e5d9a4e..db5386c 100644
--- a/README.md
+++ b/README.md
@@ -1,5 +1,9 @@
+Double Conversion
+========
 https://github.com/google/double-conversion
 
+[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/double-conversion/badge)](https://securityscorecards.dev/viewer/?uri=github.com/google/double-conversion)
+
 This project (double-conversion) provides binary-decimal and decimal-binary
 routines for IEEE doubles.
 
@@ -15,7 +19,7 @@ There is extensive documentation in `double-conversion/string-to-double.h` and
 Building
 ========
 
-This library can be built with [scons][0] or [cmake][1].
+This library can be built with [scons][0], [cmake][1] or [bazel][2].
 The checked-in Makefile simply forwards to scons, and provides a
 shortcut to run all tests:
 
@@ -51,5 +55,23 @@ Use `-DBUILD_TESTING=ON` to build the test executable.
     make
     test/cctest/cctest
 
+Bazel
+---
+
+The simplest way to adopt this library is through the [Bazel Central Registry](https://registry.bazel.build/modules/double-conversion).
+
+To build the library from the latest repository, run:
+
+```
+bazel build //:double-conversion
+```
+
+To run the unit test, run:
+
+```
+bazel test //:cctest
+```
+
 [0]: http://www.scons.org/
 [1]: https://cmake.org/
+[2]: https://bazel.build/
diff --git a/SConstruct b/SConstruct
index cebd7e0..6f4d1de 100644
--- a/SConstruct
+++ b/SConstruct
@@ -16,7 +16,7 @@ optimize = ARGUMENTS.get('optimize', 0)
 env.Replace(CXX = ARGUMENTS.get('CXX', 'g++'))
 
 # for shared lib, requires scons 2.3.0
-env['SHLIBVERSION'] = '3.0.0'
+env['SHLIBVERSION'] = '3.2.0'
 
 CCFLAGS = []
 if int(debug):
diff --git a/double-conversion/double-to-string.cc b/double-conversion/double-to-string.cc
index bb369fe..215eaa9 100644
--- a/double-conversion/double-to-string.cc
+++ b/double-conversion/double-to-string.cc
@@ -79,7 +79,14 @@ void DoubleToStringConverter::CreateExponentialRepresentation(
     StringBuilder* result_builder) const {
   DOUBLE_CONVERSION_ASSERT(length != 0);
   result_builder->AddCharacter(decimal_digits[0]);
-  if (length != 1) {
+  if (length == 1) {
+    if ((flags_ & EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL) != 0) {
+      result_builder->AddCharacter('.');
+      if ((flags_ & EMIT_TRAILING_ZERO_AFTER_POINT_IN_EXPONENTIAL) != 0) {
+          result_builder->AddCharacter('0');
+      }
+    }
+  } else {
     result_builder->AddCharacter('.');
     result_builder->AddSubstring(&decimal_digits[1], length-1);
   }
diff --git a/double-conversion/double-to-string.h b/double-conversion/double-to-string.h
index 04a4ac3..abe60e8 100644
--- a/double-conversion/double-to-string.h
+++ b/double-conversion/double-to-string.h
@@ -78,7 +78,9 @@ class DoubleToStringConverter {
     EMIT_TRAILING_DECIMAL_POINT = 2,
     EMIT_TRAILING_ZERO_AFTER_POINT = 4,
     UNIQUE_ZERO = 8,
-    NO_TRAILING_ZERO = 16
+    NO_TRAILING_ZERO = 16,
+    EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL = 32,
+    EMIT_TRAILING_ZERO_AFTER_POINT_IN_EXPONENTIAL = 64
   };
 
   // Flags should be a bit-or combination of the possible Flags-enum.
@@ -97,6 +99,13 @@ class DoubleToStringConverter {
   //    of the result in precision mode. Matches printf's %g.
   //    When EMIT_TRAILING_ZERO_AFTER_POINT is also given, one trailing zero is
   //    preserved.
+  //  - EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL: when the input number has
+  //    exactly one significant digit and is converted into exponent form then a
+  //    trailing decimal point is appended to the significand in shortest mode
+  //    or in precision mode with one requested digit.
+  //  - EMIT_TRAILING_ZERO_AFTER_POINT_IN_EXPONENTIAL: in addition to a trailing
+  //    decimal point emits a trailing '0'-character. This flag requires the
+  //    EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL flag.
   //
   // Infinity symbol and nan_symbol provide the string representation for these
   // special values. If the string is NULL and the special value is encountered
@@ -132,6 +141,22 @@ class DoubleToStringConverter {
   //   ToPrecision(230.0, 2) -> "230."  with EMIT_TRAILING_DECIMAL_POINT.
   //   ToPrecision(230.0, 2) -> "2.3e2" with EMIT_TRAILING_ZERO_AFTER_POINT.
   //
+  // When converting numbers with exactly one significant digit to exponent
+  // form in shortest mode or in precision mode with one requested digit, the
+  // EMIT_TRAILING_DECIMAL_POINT and EMIT_TRAILING_ZERO_AFTER_POINT flags have
+  // no effect. Use the EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL flag to
+  // append a decimal point in this case and the
+  // EMIT_TRAILING_ZERO_AFTER_POINT_IN_EXPONENTIAL flag to also append a
+  // '0'-character in this case.
+  // Example with decimal_in_shortest_low = 0:
+  //   ToShortest(0.0009) -> "9e-4"
+  //     with EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL deactivated.
+  //   ToShortest(0.0009) -> "9.e-4"
+  //     with EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL activated.
+  //   ToShortest(0.0009) -> "9.0e-4"
+  //     with EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL activated and
+  //     EMIT_TRAILING_ZERO_AFTER_POINT_IN_EXPONENTIAL activated.
+  //
   // The min_exponent_width is used for exponential representations.
   // The converter adds leading '0's to the exponent until the exponent
   // is at least min_exponent_width digits long.
diff --git a/msvc/double-conversion.vcxproj b/msvc/double-conversion.vcxproj
index e2d2ef8..cf3aa3a 100644
--- a/msvc/double-conversion.vcxproj
+++ b/msvc/double-conversion.vcxproj
@@ -88,7 +88,7 @@
       </PrecompiledHeader>
       <WarningLevel>Level3</WarningLevel>
       <Optimization>Disabled</Optimization>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_LIB;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_LIB;_ITERATOR_DEBUG_LEVEL=2;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <SDLCheck>true</SDLCheck>
     </ClCompile>
     <Link>
@@ -102,7 +102,7 @@
       </PrecompiledHeader>
       <WarningLevel>Level3</WarningLevel>
       <Optimization>Disabled</Optimization>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_LIB;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_LIB;_ITERATOR_DEBUG_LEVEL=2;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <SDLCheck>true</SDLCheck>
     </ClCompile>
     <Link>
diff --git a/test/cctest/cctest.h b/test/cctest/cctest.h
index 6e1848c..009c1a5 100644
--- a/test/cctest/cctest.h
+++ b/test/cctest/cctest.h
@@ -28,6 +28,7 @@
 #ifndef CCTEST_H_
 #define CCTEST_H_
 
+#include <cinttypes>
 #include <stdio.h>
 #include <string.h>
 #include <inttypes.h>
diff --git a/test/cctest/test-conversions.cc b/test/cctest/test-conversions.cc
index 4343f0c..081d3ca 100644
--- a/test/cctest/test-conversions.cc
+++ b/test/cctest/test-conversions.cc
@@ -278,6 +278,32 @@ TEST(DoubleToShortest) {
   builder.Reset();
   CHECK(dc6.ToShortest(-Double::NaN(), &builder));
   CHECK_EQ("NaN", builder.Finalize());
+
+  // Test examples with one significant digit.
+  flags = DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT |
+      DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT;
+  DoubleToStringConverter dc7(flags, NULL, NULL, 'e', 0, 0, 0, 0);
+  flags = DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT |
+      DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT |
+      DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL;
+  DoubleToStringConverter dc8(flags, NULL, NULL, 'e', 0, 0, 0, 0);
+  flags = DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT |
+      DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT |
+      DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL |
+      DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT_IN_EXPONENTIAL;
+  DoubleToStringConverter dc9(flags, NULL, NULL, 'e', 0, 0, 0, 0);
+
+  builder.Reset();
+  CHECK(dc7.ToShortest(0.0009, &builder));
+  CHECK_EQ("9e-4", builder.Finalize());
+
+  builder.Reset();
+  CHECK(dc8.ToShortest(0.0009, &builder));
+  CHECK_EQ("9.e-4", builder.Finalize());
+
+  builder.Reset();
+  CHECK(dc9.ToShortest(0.0009, &builder));
+  CHECK_EQ("9.0e-4", builder.Finalize());
 }
 
 
@@ -1259,6 +1285,32 @@ TEST(DoubleToPrecision) {
   builder.Reset();
   CHECK(dc5.ToPrecision(2000080, 5, &builder));
   CHECK_EQ("2.0001e6", builder.Finalize());
+
+  // Test examples with one significant digit.
+  flags = DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT |
+      DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT;
+  DoubleToStringConverter dc12(flags, NULL, NULL, 'e', 0, 0, 0, 0);
+  flags = DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT |
+      DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT |
+      DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL;
+  DoubleToStringConverter dc13(flags, NULL, NULL, 'e', 0, 0, 0, 0);
+  flags = DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT |
+      DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT |
+      DoubleToStringConverter::EMIT_TRAILING_DECIMAL_POINT_IN_EXPONENTIAL |
+      DoubleToStringConverter::EMIT_TRAILING_ZERO_AFTER_POINT_IN_EXPONENTIAL;
+  DoubleToStringConverter dc14(flags, NULL, NULL, 'e', 0, 0, 0, 0);
+
+  builder.Reset();
+  CHECK(dc12.ToPrecision(0.0009, 1, &builder));
+  CHECK_EQ("9e-4", builder.Finalize());
+
+  builder.Reset();
+  CHECK(dc13.ToPrecision(0.0009, 1, &builder));
+  CHECK_EQ("9.e-4", builder.Finalize());
+
+  builder.Reset();
+  CHECK(dc14.ToPrecision(0.0009, 1, &builder));
+  CHECK_EQ("9.0e-4", builder.Finalize());
 }
 
 
```

