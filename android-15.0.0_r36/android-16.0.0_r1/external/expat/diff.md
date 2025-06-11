```diff
diff --git a/.ci.sh b/.ci.sh
index b75f815c..e0171f18 100755
--- a/.ci.sh
+++ b/.ci.sh
@@ -39,7 +39,7 @@ if [[ ${RUNNER_OS} = macOS ]]; then
     latest_brew_python3_bin="$(ls -1d /usr/local/Cellar/python/3.*/bin | sort -n | tail -n1)"
     export PATH="${latest_brew_python3_bin}${PATH:+:}${PATH}"
 elif [[ ${RUNNER_OS} = Linux ]]; then
-    export PATH="/usr/lib/llvm-18/bin:${PATH}"
+    export PATH="/usr/lib/llvm-19/bin:${PATH}"
 else
     echo "Unsupported RUNNER_OS \"${RUNNER_OS}\"." >&2
     exit 1
diff --git a/.github/workflows/autotools-cmake.yml b/.github/workflows/autotools-cmake.yml
index 96e8f342..060518ad 100644
--- a/.github/workflows/autotools-cmake.yml
+++ b/.github/workflows/autotools-cmake.yml
@@ -61,7 +61,7 @@ jobs:
         shell: bash
     runs-on: "${{ matrix.os }}"
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
 
     - name: (Linux) Install build dependencies
       if: "${{ runner.os == 'Linux' }}"
diff --git a/.github/workflows/clang-format.yml b/.github/workflows/clang-format.yml
index 14132259..ebee2512 100644
--- a/.github/workflows/clang-format.yml
+++ b/.github/workflows/clang-format.yml
@@ -45,19 +45,19 @@ jobs:
     name: Enforce clang-format clean code
     runs-on: ubuntu-22.04
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
 
-    - name: Install clang-format 18
+    - name: Install clang-format 19
       run: |-
         set -x
         source /etc/os-release
         wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
-        sudo add-apt-repository "deb https://apt.llvm.org/${UBUNTU_CODENAME}/ llvm-toolchain-${UBUNTU_CODENAME}-18 main"
+        sudo add-apt-repository "deb https://apt.llvm.org/${UBUNTU_CODENAME}/ llvm-toolchain-${UBUNTU_CODENAME}-19 main"
         sudo apt-get update  # due to new repository
         sudo apt-get install --yes --no-install-recommends -V \
-            clang-format-18 \
+            clang-format-19 \
             moreutils
-        echo /usr/lib/llvm-18/bin >>"${GITHUB_PATH}"
+        echo /usr/lib/llvm-19/bin >>"${GITHUB_PATH}"
 
     - name: Run clang-format
       run: |
diff --git a/.github/workflows/clang-tidy.yml b/.github/workflows/clang-tidy.yml
index 1248e5d6..2db4dac0 100644
--- a/.github/workflows/clang-tidy.yml
+++ b/.github/workflows/clang-tidy.yml
@@ -45,18 +45,18 @@ jobs:
     name: Enforce clang-tidy clean code
     runs-on: ubuntu-22.04
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
 
-    - name: Install clang-tidy 18
+    - name: Install clang-tidy 19
       run: |-
         set -x
         source /etc/os-release
         wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
-        sudo add-apt-repository "deb https://apt.llvm.org/${UBUNTU_CODENAME}/ llvm-toolchain-${UBUNTU_CODENAME}-18 main"
+        sudo add-apt-repository "deb https://apt.llvm.org/${UBUNTU_CODENAME}/ llvm-toolchain-${UBUNTU_CODENAME}-19 main"
         sudo apt-get update  # due to new repository
         sudo apt-get install --yes --no-install-recommends -V \
-            clang-tidy-18
-        echo /usr/lib/llvm-18/bin >>"${GITHUB_PATH}"
+            clang-tidy-19
+        echo /usr/lib/llvm-19/bin >>"${GITHUB_PATH}"
 
     - name: Run clang-tidy
       run: |
diff --git a/.github/workflows/cmake-required-version.yml b/.github/workflows/cmake-required-version.yml
index ff7fd441..c122c92a 100644
--- a/.github/workflows/cmake-required-version.yml
+++ b/.github/workflows/cmake-required-version.yml
@@ -46,7 +46,7 @@ jobs:
     name: Ensure realistic minimum CMake version requirement
     runs-on: ubuntu-20.04
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
 
     - name: Install ancient CMake
       run: |
diff --git a/.github/workflows/codespell.yml b/.github/workflows/codespell.yml
index 2871a846..aed97590 100644
--- a/.github/workflows/codespell.yml
+++ b/.github/workflows/codespell.yml
@@ -45,7 +45,7 @@ jobs:
     name: Enforce codespell-clean spelling
     runs-on: ubuntu-22.04
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
     - uses: codespell-project/actions-codespell@406322ec52dd7b488e48c1c4b82e2a8b3a1bf630  # v2.1
       with:
         path: expat/
diff --git a/.github/workflows/coverage.yml b/.github/workflows/coverage.yml
index 4c33b627..d2699060 100644
--- a/.github/workflows/coverage.yml
+++ b/.github/workflows/coverage.yml
@@ -48,7 +48,7 @@ jobs:
     env:
       CFLAGS: -g3 -pipe
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
     - name: Install build dependencies
       run: |-
         set -x -u
@@ -84,7 +84,7 @@ jobs:
         exec ./.ci.sh
 
     - name: Store coverage .info and HTML report
-      uses: actions/upload-artifact@834a144ee995460fba8ed112a2fc961b36a5ec5a  # v4.3.6
+      uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882  # v4.4.3
       with:
         name: coverage
         path: expat/coverage__*/
diff --git a/.github/workflows/cppcheck.yml b/.github/workflows/cppcheck.yml
index 5ed43e7b..daa51053 100644
--- a/.github/workflows/cppcheck.yml
+++ b/.github/workflows/cppcheck.yml
@@ -46,7 +46,7 @@ jobs:
     name: Run Cppcheck
     runs-on: macos-14
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
     - name: Install runtime dependencies
       run: |
         exec brew install cppcheck
diff --git a/.github/workflows/expat_config_h.yml b/.github/workflows/expat_config_h.yml
index ac8dbf68..566b22fa 100644
--- a/.github/workflows/expat_config_h.yml
+++ b/.github/workflows/expat_config_h.yml
@@ -45,7 +45,7 @@ jobs:
     name: Check expat_config.h.{in,cmake} for regressions
     runs-on: ubuntu-20.04
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
     - name: Check expat_config.h.{in,cmake} for regressions
       run: |
         set -v
diff --git a/.github/workflows/fuzzing.yml b/.github/workflows/fuzzing.yml
index 30299950..9e430c70 100644
--- a/.github/workflows/fuzzing.yml
+++ b/.github/workflows/fuzzing.yml
@@ -44,20 +44,20 @@ jobs:
     name: Run fuzzing regression tests
     runs-on: ubuntu-22.04
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
 
-    - name: Install Clang 18
+    - name: Install Clang 19
       run: |-
         set -x
         source /etc/os-release
         wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
-        sudo add-apt-repository "deb https://apt.llvm.org/${UBUNTU_CODENAME}/ llvm-toolchain-${UBUNTU_CODENAME}-18 main"
+        sudo add-apt-repository "deb https://apt.llvm.org/${UBUNTU_CODENAME}/ llvm-toolchain-${UBUNTU_CODENAME}-19 main"
         sudo apt-get update  # due to new repository
         sudo apt-get install --yes --no-install-recommends -V \
-            clang-18 \
-            libclang-rt-18-dev \
-            llvm-18
-        echo /usr/lib/llvm-18/bin >>"${GITHUB_PATH}"
+            clang-19 \
+            libclang-rt-19-dev \
+            llvm-19
+        echo /usr/lib/llvm-19/bin >>"${GITHUB_PATH}"
 
     - name: Build Expat fuzzers
       run: |
@@ -120,7 +120,7 @@ jobs:
 
     - name: Store crashing test units
       if: ${{ failure() }}
-      uses: actions/upload-artifact@834a144ee995460fba8ed112a2fc961b36a5ec5a  # v4.3.6
+      uses: actions/upload-artifact@b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882  # v4.4.3
       with:
         name: expat_fuzzing_trouble_${{ github.sha }}
         path: expat/build/*-????????????????????????????????????????
diff --git a/.github/workflows/linux.yml b/.github/workflows/linux.yml
index 215b4156..58989fad 100644
--- a/.github/workflows/linux.yml
+++ b/.github/workflows/linux.yml
@@ -88,7 +88,7 @@ jobs:
     env:
       CFLAGS: -g3 -pipe
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
     - name: Install build dependencies (MinGW)
       if: "${{ contains(matrix.FLAT_ENV, 'mingw') }}"
       run: |-
@@ -102,7 +102,7 @@ jobs:
         #   2. Revert (remaining) packages that ppa:ondrej/php and plain Ubuntu share, back to the plain Ubuntu version
         #   3. Assert that no packages from ppa:ondrej/php are left installed
         dpkg -l | grep '^ii' | grep -F deb.sury.org | awk '{print $2}' | grep '^php' \
-          | xargs -r -t sudo apt-get remove --yes libpcre2-posix3 libzip4
+          | xargs -r -t sudo apt-get remove --yes debsuryorg-archive-keyring libpcre2-posix3 libzip4
         dpkg -l | grep '^ii' | grep -F deb.sury.org | awk '{print $2}' | sed "s,\$,/${UBUNTU_CODENAME}," \
           | xargs -r -t sudo apt-get install --yes --no-install-recommends --allow-downgrades -V
         ! dpkg -l | grep '^ii' | grep -F deb.sury.org
@@ -120,12 +120,12 @@ jobs:
         set -x
         source /etc/os-release
         wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
-        sudo add-apt-repository "deb https://apt.llvm.org/${UBUNTU_CODENAME}/ llvm-toolchain-${UBUNTU_CODENAME}-18 main"
+        sudo add-apt-repository "deb https://apt.llvm.org/${UBUNTU_CODENAME}/ llvm-toolchain-${UBUNTU_CODENAME}-19 main"
         sudo apt-get update  # due to new repository
-        # NOTE: Please note the version-specific ${PATH} extension for Clang adding /usr/lib/llvm-18/bin in .ci.sh
+        # NOTE: Please note the version-specific ${PATH} extension for Clang adding /usr/lib/llvm-19/bin in .ci.sh
         sudo apt-get install --yes --no-install-recommends -V \
-            clang-18 \
-            libclang-rt-18-dev
+            clang-19 \
+            libclang-rt-19-dev
     - name: Install build dependencies (common)
       run: |-
         sudo apt-get install --yes --no-install-recommends -V \
diff --git a/.github/workflows/macos.yml b/.github/workflows/macos.yml
index 36a32732..28a44656 100644
--- a/.github/workflows/macos.yml
+++ b/.github/workflows/macos.yml
@@ -46,7 +46,7 @@ jobs:
     name: Perform checks
     strategy:
       matrix:
-        os: [macos-12, macos-14]
+        os: [macos-13, macos-15]
         include:
           - MODE: cmake-oos
           - MODE: distcheck
@@ -54,7 +54,7 @@ jobs:
             FLAT_ENV: CC=clang CXX=clang++ LD=clang++ QA_SANITIZER=address
     runs-on: ${{ matrix.os }}
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
     - name: Install build dependencies
       run: |
         sudo rm /usr/local/bin/2to3  # so that "brew link" will work
diff --git a/.github/workflows/valid-xml.yml b/.github/workflows/valid-xml.yml
index 095895c5..21c8aa5e 100644
--- a/.github/workflows/valid-xml.yml
+++ b/.github/workflows/valid-xml.yml
@@ -45,7 +45,7 @@ jobs:
     name: Ensure well-formed and valid XML
     runs-on: ubuntu-20.04
     steps:
-    - uses: actions/checkout@692973e3d937129bcbf40652eb9f2f61becf3332  # v4.1.7
+    - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
 
     - name: Install build dependencies
       run: |-
diff --git a/.mailmap b/.mailmap
index abc06f99..62f1d783 100644
--- a/.mailmap
+++ b/.mailmap
@@ -3,6 +3,7 @@ Ben Wagner <bungeman@chromium.org>
 Donghee Na <donghee.na@python.org>
 Franek Korta <fkorta@gmail.com>
 Hanno Böck <hanno@gentoo.org>
+Hanno Böck <hanno@gentoo.org> <990588+hannob@users.noreply.github.com>
 James Clark <jjc@jclark.com> <jclark@users.sourceforge.net>
 José Gutiérrez de la Concha <jose@zeroc.com>
 Joyce Brum <joycebrum@google.com>
diff --git a/METADATA b/METADATA
index f16d011a..3f46f668 100644
--- a/METADATA
+++ b/METADATA
@@ -15,14 +15,14 @@ third_party {
     tag: "NVD-CPE2.3:cpe:/a:libexpat_project:libexpat:2.5.0"
   }
   last_upgrade_date {
-    year: 2024
-    month: 9
-    day: 18
+    year: 2025
+    month: 1
+    day: 9
   }
   homepage: "https://github.com/libexpat/libexpat/"
   identifier {
     type: "Git"
     value: "https://github.com/libexpat/libexpat/"
-    version: "R_2_6_3"
+    version: "R_2_6_4"
   }
 }
diff --git a/expat/CMake.README b/expat/CMake.README
index 6e7e852f..86e1eb98 100644
--- a/expat/CMake.README
+++ b/expat/CMake.README
@@ -3,25 +3,25 @@
 The cmake based buildsystem for expat works on Windows (cygwin, mingw, Visual
 Studio) and should work on all other platform cmake supports.
 
-Assuming ~/expat-2.6.3 is the source directory of expat, add a subdirectory
+Assuming ~/expat-2.6.4 is the source directory of expat, add a subdirectory
 build and change into that directory:
-~/expat-2.6.3$ mkdir build && cd build
-~/expat-2.6.3/build$
+~/expat-2.6.4$ mkdir build && cd build
+~/expat-2.6.4/build$
 
 From that directory, call cmake first, then call make, make test and
 make install in the usual way:
-~/expat-2.6.3/build$ cmake ..
+~/expat-2.6.4/build$ cmake ..
 -- The C compiler identification is GNU
 -- The CXX compiler identification is GNU
 ....
 -- Configuring done
 -- Generating done
--- Build files have been written to: /home/patrick/expat-2.6.3/build
+-- Build files have been written to: /home/patrick/expat-2.6.4/build
 
 If you want to specify the install location for your files, append
 -DCMAKE_INSTALL_PREFIX=/your/install/path to the cmake call.
 
-~/expat-2.6.3/build$ make && make test && make install
+~/expat-2.6.4/build$ make && make test && make install
 Scanning dependencies of target expat
 [  5%] Building C object CMakeFiles/expat.dir/lib/xmlparse.c.o
 [ 11%] Building C object CMakeFiles/expat.dir/lib/xmlrole.c.o
diff --git a/expat/CMakeLists.txt b/expat/CMakeLists.txt
index b2055c18..1f650339 100644
--- a/expat/CMakeLists.txt
+++ b/expat/CMakeLists.txt
@@ -38,7 +38,7 @@ cmake_minimum_required(VERSION 3.5.0)
 
 project(expat
     VERSION
-        2.6.3
+        2.6.4
     LANGUAGES
         C
 )
@@ -425,6 +425,7 @@ else()
 endif()
 
 add_library(expat ${_SHARED} ${_EXPAT_C_SOURCES} ${_EXPAT_EXTRA_SOURCES})
+add_library(expat::expat ALIAS expat)
 if(_EXPAT_LIBM_FOUND)
     target_link_libraries(expat m)
 endif()
@@ -465,9 +466,9 @@ foreach(build_type_upper
     set_property(TARGET expat PROPERTY ${build_type_upper}_POSTFIX ${EXPAT_${build_type_upper}_POSTFIX})
 endforeach()
 
-set(LIBCURRENT 10)  # sync
-set(LIBREVISION 3)  # with
-set(LIBAGE 9)       # configure.ac!
+set(LIBCURRENT 11)  # sync
+set(LIBREVISION 0)  # with
+set(LIBAGE 10)      # configure.ac!
 math(EXPR LIBCURRENT_MINUS_AGE "${LIBCURRENT} - ${LIBAGE}")
 
 if(NOT WIN32)
diff --git a/expat/Changes b/expat/Changes
index c1d22efa..aa19f70a 100644
--- a/expat/Changes
+++ b/expat/Changes
@@ -30,6 +30,37 @@
 !! THANK YOU!                        Sebastian Pipping -- Berlin, 2024-03-09 !!
 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 
+Release 2.6.4 Wed November 6 2024
+        Security fixes:
+            #915  CVE-2024-50602 -- Fix crash within function XML_ResumeParser
+                    from a NULL pointer dereference by disallowing function
+                    XML_StopParser to (stop or) suspend an unstarted parser.
+                    A new error code XML_ERROR_NOT_STARTED was introduced to
+                    properly communicate this situation.  // CWE-476 CWE-754
+
+        Other changes:
+            #903  CMake: Add alias target "expat::expat"
+            #905  docs: Document use via CMake >=3.18 with FetchContent
+                    and SOURCE_SUBDIR and its consequences
+            #902  tests: Reduce use of global parser instance
+            #904  tests: Resolve duplicate handler
+       #317 #918  tests: Improve tests on doctype closing (ex CVE-2019-15903)
+            #914  Fix signedness of format strings
+       #919 #920  Version info bumped from 10:3:9 (libexpat*.so.1.9.3)
+                    to 11:0:10 (libexpat*.so.1.10.0); see https://verbump.de/
+                    for what these numbers do
+
+        Infrastructure:
+            #907  CI: Upgrade Clang from 18 to 19
+            #913  CI: Drop macos-12 and add macos-15
+            #910  CI: Adapt to breaking changes in GitHub Actions
+            #898  Add missing entries to .gitignore
+
+        Special thanks to:
+            Hanno Böck
+            José Eduardo Gutiérrez Conejo
+            José Ricardo Cardona Quesada
+
 Release 2.6.3 Wed September 4 2024
         Security fixes:
        #887 #890  CVE-2024-45490 -- Calling function XML_ParseBuffer with
diff --git a/expat/README.md b/expat/README.md
index 180a68e4..23d26dad 100644
--- a/expat/README.md
+++ b/expat/README.md
@@ -11,7 +11,7 @@
 > at the top of the `Changes` file.
 
 
-# Expat, Release 2.6.3
+# Expat, Release 2.6.4
 
 This is Expat, a C99 library for parsing
 [XML 1.0 Fourth Edition](https://www.w3.org/TR/2006/REC-xml-20060816/), started by
@@ -43,9 +43,9 @@ This license is the same as the MIT/X Consortium license.
 
 ## Using libexpat in your CMake-Based Project
 
-There are two ways of using libexpat with CMake:
+There are three documented ways of using libexpat with CMake:
 
-### a) Module Mode
+### a) `find_package` with Module Mode
 
 This approach leverages CMake's own [module `FindEXPAT`](https://cmake.org/cmake/help/latest/module/FindEXPAT.html).
 
@@ -70,7 +70,7 @@ target_include_directories(hello PRIVATE ${EXPAT_INCLUDE_DIRS})
 target_link_libraries(hello PUBLIC ${EXPAT_LIBRARIES})
 ```
 
-### b) Config Mode
+### b) `find_package` with Config Mode
 
 This approach requires files from…
 
@@ -98,6 +98,45 @@ add_executable(hello
 target_link_libraries(hello PUBLIC expat::expat)
 ```
 
+### c) The `FetchContent` module
+
+This approach — as demonstrated below — requires CMake >=3.18 for both the
+[`FetchContent` module](https://cmake.org/cmake/help/latest/module/FetchContent.html)
+and its support for the `SOURCE_SUBDIR` option to be available.
+
+Please note that:
+- Use of the `FetchContent` module with *non-release* SHA1s or `master`
+  of libexpat is neither advised nor considered officially supported.
+- Pinning to a specific commit is great for robust CI.
+- Pinning to a specific commit needs updating every time there is a new
+  release of libexpat — either manually or through automation —,
+  to not miss out on libexpat security updates.
+
+For an example that pulls in libexpat via Git:
+
+```cmake
+cmake_minimum_required(VERSION 3.18)
+
+include(FetchContent)
+
+project(hello VERSION 1.0.0)
+
+FetchContent_Declare(
+    expat
+    GIT_REPOSITORY https://github.com/libexpat/libexpat/
+    GIT_TAG        000000000_GIT_COMMIT_SHA1_HERE_000000000  # i.e. Git tag R_0_Y_Z
+    SOURCE_SUBDIR  expat/
+)
+
+FetchContent_MakeAvailable(expat)
+
+add_executable(hello
+    hello.c
+)
+
+target_link_libraries(hello PUBLIC expat)
+```
+
 
 ## Building from a Git Clone
 
diff --git a/expat/configure.ac b/expat/configure.ac
index 1a930413..fffcd125 100644
--- a/expat/configure.ac
+++ b/expat/configure.ac
@@ -84,9 +84,9 @@ dnl
 dnl If the API changes incompatibly set LIBAGE back to 0
 dnl
 
-LIBCURRENT=10  # sync
-LIBREVISION=3  # with
-LIBAGE=9       # CMakeLists.txt!
+LIBCURRENT=11  # sync
+LIBREVISION=0  # with
+LIBAGE=10      # CMakeLists.txt!
 
 AC_CONFIG_HEADERS([expat_config.h])
 AH_TOP([#ifndef EXPAT_CONFIG_H
diff --git a/expat/doc/reference.html b/expat/doc/reference.html
index 4cfb2ce9..c2ae9bb7 100644
--- a/expat/doc/reference.html
+++ b/expat/doc/reference.html
@@ -52,7 +52,7 @@
   <div>
     <h1>
       The Expat XML Parser
-      <small>Release 2.6.3</small>
+      <small>Release 2.6.4</small>
     </h1>
   </div>
 <div class="content">
diff --git a/expat/doc/xmlwf.xml b/expat/doc/xmlwf.xml
index 10b29782..cf6d984a 100644
--- a/expat/doc/xmlwf.xml
+++ b/expat/doc/xmlwf.xml
@@ -21,7 +21,7 @@
           "http://www.oasis-open.org/docbook/xml/4.2/docbookx.dtd" [
   <!ENTITY dhfirstname "<firstname>Scott</firstname>">
   <!ENTITY dhsurname   "<surname>Bronson</surname>">
-  <!ENTITY dhdate      "<date>September 4, 2024</date>">
+  <!ENTITY dhdate      "<date>November 6, 2024</date>">
   <!-- Please adjust this^^ date whenever cutting a new release. -->
   <!ENTITY dhsection   "<manvolnum>1</manvolnum>">
   <!ENTITY dhemail     "<email>bronson@rinspin.com</email>">
diff --git a/expat/examples/.gitignore b/expat/examples/.gitignore
index ef5b8d59..ce287263 100644
--- a/expat/examples/.gitignore
+++ b/expat/examples/.gitignore
@@ -1,4 +1,6 @@
 Makefile
+element_declarations
+element_declarations.plg
 elements
 elements.plg
 element_declarations
diff --git a/expat/examples/element_declarations.c b/expat/examples/element_declarations.c
index 7ce8544f..d644b2ff 100644
--- a/expat/examples/element_declarations.c
+++ b/expat/examples/element_declarations.c
@@ -15,6 +15,7 @@
    Copyright (c) 2016-2024 Sebastian Pipping <sebastian@pipping.org>
    Copyright (c) 2017      Rhodri James <rhodri@wildebeest.org.uk>
    Copyright (c) 2019      Zhongyuan Zhou <zhouzhongyuan@huawei.com>
+   Copyright (c) 2024      Hanno Böck <hanno@gentoo.org>
    Licensed under the MIT license:
 
    Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -127,15 +128,15 @@ dumpContentModelElement(const XML_Content *model, unsigned level,
   }
 
   // Node
-  printf("[%u] type=%s(%d), quant=%s(%d)", (unsigned)(model - root),
-         contentTypeName(model->type), model->type,
-         contentQuantName(model->quant), model->quant);
+  printf("[%u] type=%s(%u), quant=%s(%u)", (unsigned)(model - root),
+         contentTypeName(model->type), (unsigned int)model->type,
+         contentQuantName(model->quant), (unsigned int)model->quant);
   if (model->name) {
     printf(", name=\"%" XML_FMT_STR "\"", model->name);
   } else {
     printf(", name=NULL");
   }
-  printf(", numchildren=%d", model->numchildren);
+  printf(", numchildren=%u", model->numchildren);
   printf("\n");
 }
 
diff --git a/expat/lib/expat.h b/expat/lib/expat.h
index d0d6015a..523b37d8 100644
--- a/expat/lib/expat.h
+++ b/expat/lib/expat.h
@@ -130,7 +130,9 @@ enum XML_Error {
   /* Added in 2.3.0. */
   XML_ERROR_NO_BUFFER,
   /* Added in 2.4.0. */
-  XML_ERROR_AMPLIFICATION_LIMIT_BREACH
+  XML_ERROR_AMPLIFICATION_LIMIT_BREACH,
+  /* Added in 2.6.4. */
+  XML_ERROR_NOT_STARTED,
 };
 
 enum XML_Content_Type {
@@ -1066,7 +1068,7 @@ XML_SetReparseDeferralEnabled(XML_Parser parser, XML_Bool enabled);
 */
 #define XML_MAJOR_VERSION 2
 #define XML_MINOR_VERSION 6
-#define XML_MICRO_VERSION 3
+#define XML_MICRO_VERSION 4
 
 #ifdef __cplusplus
 }
diff --git a/expat/lib/xmlparse.c b/expat/lib/xmlparse.c
index d9285b21..a4e091e7 100644
--- a/expat/lib/xmlparse.c
+++ b/expat/lib/xmlparse.c
@@ -1,4 +1,4 @@
-/* ba4cdf9bdb534f355a9def4c9e25d20ee8e72f95b0a4d930be52e563f5080196 (2.6.3+)
+/* c5625880f4bf417c1463deee4eb92d86ff413f802048621c57e25fe483eb59e4 (2.6.4+)
                             __  __            _
                          ___\ \/ /_ __   __ _| |_
                         / _ \\  /| '_ \ / _` | __|
@@ -40,6 +40,7 @@
    Copyright (c) 2023      Owain Davies <owaind@bath.edu>
    Copyright (c) 2023-2024 Sony Corporation / Snild Dolkow <snild@sony.com>
    Copyright (c) 2024      Berkay Eren Ürün <berkay.ueruen@siemens.com>
+   Copyright (c) 2024      Hanno Böck <hanno@gentoo.org>
    Licensed under the MIT license:
 
    Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -2234,6 +2235,9 @@ XML_StopParser(XML_Parser parser, XML_Bool resumable) {
   if (parser == NULL)
     return XML_STATUS_ERROR;
   switch (parser->m_parsingStatus.parsing) {
+  case XML_INITIALIZED:
+    parser->m_errorCode = XML_ERROR_NOT_STARTED;
+    return XML_STATUS_ERROR;
   case XML_SUSPENDED:
     if (resumable) {
       parser->m_errorCode = XML_ERROR_SUSPENDED;
@@ -2244,7 +2248,7 @@ XML_StopParser(XML_Parser parser, XML_Bool resumable) {
   case XML_FINISHED:
     parser->m_errorCode = XML_ERROR_FINISHED;
     return XML_STATUS_ERROR;
-  default:
+  case XML_PARSING:
     if (resumable) {
 #ifdef XML_DTD
       if (parser->m_isParamEntity) {
@@ -2255,6 +2259,9 @@ XML_StopParser(XML_Parser parser, XML_Bool resumable) {
       parser->m_parsingStatus.parsing = XML_SUSPENDED;
     } else
       parser->m_parsingStatus.parsing = XML_FINISHED;
+    break;
+  default:
+    assert(0);
   }
   return XML_STATUS_OK;
 }
@@ -2519,6 +2526,9 @@ XML_ErrorString(enum XML_Error code) {
   case XML_ERROR_AMPLIFICATION_LIMIT_BREACH:
     return XML_L(
         "limit on input amplification factor (from DTD and entities) breached");
+  /* Added in 2.6.4. */
+  case XML_ERROR_NOT_STARTED:
+    return XML_L("parser not started");
   }
   return NULL;
 }
@@ -7856,7 +7866,7 @@ accountingReportDiff(XML_Parser rootParser,
   assert(! rootParser->m_parentParser);
 
   fprintf(stderr,
-          " (+" EXPAT_FMT_PTRDIFF_T("6") " bytes %s|%d, xmlparse.c:%d) %*s\"",
+          " (+" EXPAT_FMT_PTRDIFF_T("6") " bytes %s|%u, xmlparse.c:%d) %*s\"",
           bytesMore, (account == XML_ACCOUNT_DIRECT) ? "DIR" : "EXP",
           levelsAwayFromRootParser, source_line, 10, "");
 
@@ -7969,7 +7979,7 @@ entityTrackingReportStats(XML_Parser rootParser, ENTITY *entity,
 
   fprintf(
       stderr,
-      "expat: Entities(%p): Count %9d, depth %2d/%2d %*s%s%s; %s length %d (xmlparse.c:%d)\n",
+      "expat: Entities(%p): Count %9u, depth %2u/%2u %*s%s%s; %s length %d (xmlparse.c:%d)\n",
       (void *)rootParser, rootParser->m_entity_stats.countEverOpened,
       rootParser->m_entity_stats.currentDepth,
       rootParser->m_entity_stats.maximumDepthSeen,
diff --git a/expat/tests/basic_tests.c b/expat/tests/basic_tests.c
index 0d97b109..d38b8fd1 100644
--- a/expat/tests/basic_tests.c
+++ b/expat/tests/basic_tests.c
@@ -2357,11 +2357,20 @@ START_TEST(test_attributes) {
   info[0].attributes = doc_info;
   info[1].attributes = tag_info;
 
-  XML_SetStartElementHandler(g_parser, counting_start_element_handler);
-  XML_SetUserData(g_parser, info);
-  if (_XML_Parse_SINGLE_BYTES(g_parser, text, (int)strlen(text), XML_TRUE)
+  XML_Parser parser = XML_ParserCreate(NULL);
+  assert_true(parser != NULL);
+  ParserAndElementInfo parserAndElementInfos = {
+      parser,
+      info,
+  };
+
+  XML_SetStartElementHandler(parser, counting_start_element_handler);
+  XML_SetUserData(parser, &parserAndElementInfos);
+  if (_XML_Parse_SINGLE_BYTES(parser, text, (int)strlen(text), XML_TRUE)
       == XML_STATUS_ERROR)
-    xml_failure(g_parser);
+    xml_failure(parser);
+
+  XML_ParserFree(parser);
 }
 END_TEST
 
diff --git a/expat/tests/common.c b/expat/tests/common.c
index 26d0c547..3aea8d74 100644
--- a/expat/tests/common.c
+++ b/expat/tests/common.c
@@ -10,7 +10,7 @@
    Copyright (c) 2003      Greg Stein <gstein@users.sourceforge.net>
    Copyright (c) 2005-2007 Steven Solie <steven@solie.ca>
    Copyright (c) 2005-2012 Karl Waclawek <karl@waclawek.net>
-   Copyright (c) 2016-2023 Sebastian Pipping <sebastian@pipping.org>
+   Copyright (c) 2016-2024 Sebastian Pipping <sebastian@pipping.org>
    Copyright (c) 2017-2022 Rhodri James <rhodri@wildebeest.org.uk>
    Copyright (c) 2017      Joe Orton <jorton@redhat.com>
    Copyright (c) 2017      José Gutiérrez de la Concha <jose@zeroc.com>
@@ -51,6 +51,7 @@
 #include "chardata.h"
 #include "minicheck.h"
 #include "common.h"
+#include "handlers.h"
 
 /* Common test data */
 
@@ -221,30 +222,6 @@ _expect_failure(const char *text, enum XML_Error errorCode,
     _xml_failure(g_parser, file, lineno);
 }
 
-/* Character data support for handlers, built on top of the code in
- * chardata.c
- */
-void XMLCALL
-accumulate_characters(void *userData, const XML_Char *s, int len) {
-  CharData_AppendXMLChars((CharData *)userData, s, len);
-}
-
-void XMLCALL
-accumulate_attribute(void *userData, const XML_Char *name,
-                     const XML_Char **atts) {
-  CharData *storage = (CharData *)userData;
-  UNUSED_P(name);
-  /* Check there are attributes to deal with */
-  if (atts == NULL)
-    return;
-
-  while (storage->count < 0 && atts[0] != NULL) {
-    /* "accumulate" the value of the first attribute we see */
-    CharData_AppendXMLChars(storage, atts[1], -1);
-    atts += 2;
-  }
-}
-
 void
 _run_character_check(const char *text, const XML_Char *expected,
                      const char *file, int line) {
@@ -273,12 +250,6 @@ _run_attribute_check(const char *text, const XML_Char *expected,
   CharData_CheckXMLChars(&storage, expected);
 }
 
-void XMLCALL
-ext_accumulate_characters(void *userData, const XML_Char *s, int len) {
-  ExtTest *test_data = (ExtTest *)userData;
-  accumulate_characters(test_data->storage, s, len);
-}
-
 void
 _run_ext_character_check(const char *text, ExtTest *test_data,
                          const XML_Char *expected, const char *file, int line) {
diff --git a/expat/tests/common.h b/expat/tests/common.h
index 52f00cc0..bc4c7da6 100644
--- a/expat/tests/common.h
+++ b/expat/tests/common.h
@@ -10,7 +10,7 @@
    Copyright (c) 2003      Greg Stein <gstein@users.sourceforge.net>
    Copyright (c) 2005-2007 Steven Solie <steven@solie.ca>
    Copyright (c) 2005-2012 Karl Waclawek <karl@waclawek.net>
-   Copyright (c) 2016-2023 Sebastian Pipping <sebastian@pipping.org>
+   Copyright (c) 2016-2024 Sebastian Pipping <sebastian@pipping.org>
    Copyright (c) 2017-2022 Rhodri James <rhodri@wildebeest.org.uk>
    Copyright (c) 2017      Joe Orton <jorton@redhat.com>
    Copyright (c) 2017      José Gutiérrez de la Concha <jose@zeroc.com>
@@ -111,12 +111,6 @@ extern void _expect_failure(const char *text, enum XML_Error errorCode,
 /* Support functions for handlers to collect up character and attribute data.
  */
 
-extern void XMLCALL accumulate_characters(void *userData, const XML_Char *s,
-                                          int len);
-
-extern void XMLCALL accumulate_attribute(void *userData, const XML_Char *name,
-                                         const XML_Char **atts);
-
 extern void _run_character_check(const char *text, const XML_Char *expected,
                                  const char *file, int line);
 
@@ -135,9 +129,6 @@ typedef struct ExtTest {
   CharData *storage;
 } ExtTest;
 
-extern void XMLCALL ext_accumulate_characters(void *userData, const XML_Char *s,
-                                              int len);
-
 extern void _run_ext_character_check(const char *text, ExtTest *test_data,
                                      const XML_Char *expected, const char *file,
                                      int line);
diff --git a/expat/tests/handlers.c b/expat/tests/handlers.c
index 449ada70..0211985f 100644
--- a/expat/tests/handlers.c
+++ b/expat/tests/handlers.c
@@ -103,7 +103,9 @@ end_element_event_handler2(void *userData, const XML_Char *name) {
 void XMLCALL
 counting_start_element_handler(void *userData, const XML_Char *name,
                                const XML_Char **atts) {
-  ElementInfo *info = (ElementInfo *)userData;
+  ParserAndElementInfo *const parserAndElementInfos
+      = (ParserAndElementInfo *)userData;
+  ElementInfo *info = parserAndElementInfos->info;
   AttrInfo *attr;
   int count, id, i;
 
@@ -120,12 +122,12 @@ counting_start_element_handler(void *userData, const XML_Char *name,
    * is possibly a little unexpected, but it is what the
    * documentation in expat.h tells us to expect.
    */
-  count = XML_GetSpecifiedAttributeCount(g_parser);
+  count = XML_GetSpecifiedAttributeCount(parserAndElementInfos->parser);
   if (info->attr_count * 2 != count) {
     fail("Not got expected attribute count");
     return;
   }
-  id = XML_GetIdAttributeIndex(g_parser);
+  id = XML_GetIdAttributeIndex(parserAndElementInfos->parser);
   if (id == -1 && info->id_name != NULL) {
     fail("ID not present");
     return;
@@ -1880,12 +1882,6 @@ accumulate_entity_decl(void *userData, const XML_Char *entityName,
   CharData_AppendXMLChars(storage, XCS("\n"), 1);
 }
 
-void XMLCALL
-accumulate_char_data(void *userData, const XML_Char *s, int len) {
-  CharData *const storage = (CharData *)userData;
-  CharData_AppendXMLChars(storage, s, len);
-}
-
 void XMLCALL
 accumulate_start_element(void *userData, const XML_Char *name,
                          const XML_Char **atts) {
@@ -1910,6 +1906,34 @@ accumulate_start_element(void *userData, const XML_Char *name,
   CharData_AppendXMLChars(storage, XCS(")\n"), 2);
 }
 
+void XMLCALL
+accumulate_characters(void *userData, const XML_Char *s, int len) {
+  CharData *const storage = (CharData *)userData;
+  CharData_AppendXMLChars(storage, s, len);
+}
+
+void XMLCALL
+accumulate_attribute(void *userData, const XML_Char *name,
+                     const XML_Char **atts) {
+  CharData *const storage = (CharData *)userData;
+  UNUSED_P(name);
+  /* Check there are attributes to deal with */
+  if (atts == NULL)
+    return;
+
+  while (storage->count < 0 && atts[0] != NULL) {
+    /* "accumulate" the value of the first attribute we see */
+    CharData_AppendXMLChars(storage, atts[1], -1);
+    atts += 2;
+  }
+}
+
+void XMLCALL
+ext_accumulate_characters(void *userData, const XML_Char *s, int len) {
+  ExtTest *const test_data = (ExtTest *)userData;
+  accumulate_characters(test_data->storage, s, len);
+}
+
 void XMLCALL
 checking_default_handler(void *userData, const XML_Char *s, int len) {
   DefaultCheck *data = (DefaultCheck *)userData;
diff --git a/expat/tests/handlers.h b/expat/tests/handlers.h
index e1f0995f..8850bb94 100644
--- a/expat/tests/handlers.h
+++ b/expat/tests/handlers.h
@@ -92,6 +92,11 @@ typedef struct elementInfo {
   AttrInfo *attributes;
 } ElementInfo;
 
+typedef struct StructParserAndElementInfo {
+  XML_Parser parser;
+  ElementInfo *info;
+} ParserAndElementInfo;
+
 extern void XMLCALL counting_start_element_handler(void *userData,
                                                    const XML_Char *name,
                                                    const XML_Char **atts);
@@ -564,13 +569,19 @@ extern void XMLCALL accumulate_entity_decl(
     const XML_Char *systemId, const XML_Char *publicId,
     const XML_Char *notationName);
 
-extern void XMLCALL accumulate_char_data(void *userData, const XML_Char *s,
-                                         int len);
-
 extern void XMLCALL accumulate_start_element(void *userData,
                                              const XML_Char *name,
                                              const XML_Char **atts);
 
+extern void XMLCALL accumulate_characters(void *userData, const XML_Char *s,
+                                          int len);
+
+extern void XMLCALL accumulate_attribute(void *userData, const XML_Char *name,
+                                         const XML_Char **atts);
+
+extern void XMLCALL ext_accumulate_characters(void *userData, const XML_Char *s,
+                                              int len);
+
 typedef struct default_check {
   const XML_Char *expected;
   const int expectedLen;
diff --git a/expat/tests/misc_tests.c b/expat/tests/misc_tests.c
index 2ee9320b..9afe0922 100644
--- a/expat/tests/misc_tests.c
+++ b/expat/tests/misc_tests.c
@@ -208,7 +208,7 @@ START_TEST(test_misc_version) {
   if (! versions_equal(&read_version, &parsed_version))
     fail("Version mismatch");
 
-  if (xcstrcmp(version_text, XCS("expat_2.6.3"))) /* needs bump on releases */
+  if (xcstrcmp(version_text, XCS("expat_2.6.4"))) /* needs bump on releases */
     fail("XML_*_VERSION in expat.h out of sync?\n");
 }
 END_TEST
@@ -332,14 +332,15 @@ START_TEST(test_misc_deny_internal_entity_closing_doctype_issue_317) {
                                "<!ENTITY % e ']><d/>'>\n"
                                "\n"
                                "%e;";
-  const char *const inputTwo = "<!DOCTYPE d [\n"
-                               "<!ENTITY % e1 ']><d/>'><!ENTITY % e2 '&e1;'>\n"
-                               "\n"
-                               "%e2;";
+  const char *const inputTwo
+      = "<!DOCTYPE d [\n"
+        "<!ENTITY % e1 ']><d/>'><!ENTITY % e2 '&#37;e1;'>\n"
+        "\n"
+        "%e2;";
   const char *const inputThree = "<!DOCTYPE d [\n"
                                  "<!ENTITY % e ']><d'>\n"
                                  "\n"
-                                 "%e;";
+                                 "%e;/>";
   const char *const inputIssue317 = "<!DOCTYPE doc [\n"
                                     "<!ENTITY % foo ']>\n"
                                     "<doc>Hell<oc (#PCDATA)*>'>\n"
@@ -447,7 +448,7 @@ START_TEST(test_misc_general_entities_support) {
   XML_SetExternalEntityRefHandler(parser,
                                   external_entity_failer__if_not_xml_ge);
   XML_SetEntityDeclHandler(parser, accumulate_entity_decl);
-  XML_SetCharacterDataHandler(parser, accumulate_char_data);
+  XML_SetCharacterDataHandler(parser, accumulate_characters);
 
   if (_XML_Parse_SINGLE_BYTES(parser, doc, (int)strlen(doc), XML_TRUE)
       != XML_STATUS_OK) {
@@ -496,6 +497,28 @@ START_TEST(test_misc_char_handler_stop_without_leak) {
 }
 END_TEST
 
+START_TEST(test_misc_resumeparser_not_crashing) {
+  XML_Parser parser = XML_ParserCreate(NULL);
+  XML_GetBuffer(parser, 1);
+  XML_StopParser(parser, /*resumable=*/XML_TRUE);
+  XML_ResumeParser(parser); // could crash here, previously
+  XML_ParserFree(parser);
+}
+END_TEST
+
+START_TEST(test_misc_stopparser_rejects_unstarted_parser) {
+  const XML_Bool cases[] = {XML_TRUE, XML_FALSE};
+  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
+    const XML_Bool resumable = cases[i];
+    XML_Parser parser = XML_ParserCreate(NULL);
+    assert_true(XML_GetErrorCode(parser) == XML_ERROR_NONE);
+    assert_true(XML_StopParser(parser, resumable) == XML_STATUS_ERROR);
+    assert_true(XML_GetErrorCode(parser) == XML_ERROR_NOT_STARTED);
+    XML_ParserFree(parser);
+  }
+}
+END_TEST
+
 void
 make_miscellaneous_test_case(Suite *s) {
   TCase *tc_misc = tcase_create("miscellaneous tests");
@@ -520,4 +543,6 @@ make_miscellaneous_test_case(Suite *s) {
                  test_misc_create_external_entity_parser_with_null_context);
   tcase_add_test(tc_misc, test_misc_general_entities_support);
   tcase_add_test(tc_misc, test_misc_char_handler_stop_without_leak);
+  tcase_add_test(tc_misc, test_misc_resumeparser_not_crashing);
+  tcase_add_test(tc_misc, test_misc_stopparser_rejects_unstarted_parser);
 }
diff --git a/expat/win32/expat.iss b/expat/win32/expat.iss
index 23c18d14..09aa7e53 100644
--- a/expat/win32/expat.iss
+++ b/expat/win32/expat.iss
@@ -38,7 +38,7 @@
 ; OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 ; USE OR OTHER DEALINGS IN THE SOFTWARE.
 
-#define expatVer "2.6.3"
+#define expatVer "2.6.4"
 
 [Setup]
 AppName=Expat
diff --git a/expat/xmlwf/xmlfile.c b/expat/xmlwf/xmlfile.c
index 0598b86b..9c4f7f8d 100644
--- a/expat/xmlwf/xmlfile.c
+++ b/expat/xmlwf/xmlfile.c
@@ -15,6 +15,7 @@
    Copyright (c) 2017      Rhodri James <rhodri@wildebeest.org.uk>
    Copyright (c) 2019      David Loffredo <loffredo@steptools.com>
    Copyright (c) 2021      Donghee Na <donghee.na@python.org>
+   Copyright (c) 2024      Hanno Böck <hanno@gentoo.org>
    Licensed under the MIT license:
 
    Permission is  hereby granted,  free of charge,  to any  person obtaining
@@ -91,7 +92,8 @@ reportError(XML_Parser parser, const XML_Char *filename) {
              filename, XML_GetErrorLineNumber(parser),
              XML_GetErrorColumnNumber(parser), message);
   else
-    ftprintf(stderr, T("%s: (unknown message %d)\n"), filename, code);
+    ftprintf(stderr, T("%s: (unknown message %u)\n"), filename,
+             (unsigned int)code);
 }
 
 /* This implementation will give problems on files larger than INT_MAX. */
diff --git a/expat_config.h b/expat_config.h
index 4d816d19..50693657 100644
--- a/expat_config.h
+++ b/expat_config.h
@@ -91,7 +91,7 @@
 #define PACKAGE_NAME "expat"
 
 /* Define to the full name and version of this package. */
-#define PACKAGE_STRING "expat 2.6.3"
+#define PACKAGE_STRING "expat 2.6.4"
 
 /* Define to the one symbol short name of this package. */
 #define PACKAGE_TARNAME "expat"
@@ -100,7 +100,7 @@
 #define PACKAGE_URL ""
 
 /* Define to the version of this package. */
-#define PACKAGE_VERSION "2.6.3"
+#define PACKAGE_VERSION "2.6.4"
 
 /* Define to 1 if all of the C90 standard headers exist (not just the ones
    required in a freestanding environment). This macro is provided for
@@ -108,7 +108,7 @@
 #define STDC_HEADERS 1
 
 /* Version number of package */
-#define VERSION "2.6.3"
+#define VERSION "2.6.4"
 
 /* Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
    significant byte first (like Motorola and SPARC, unlike Intel). */
diff --git a/post_update.sh b/post_update.sh
new file mode 100755
index 00000000..b6d34733
--- /dev/null
+++ b/post_update.sh
@@ -0,0 +1,20 @@
+#!/bin/bash
+
+set -e
+
+T="${ANDROID_BUILD_TOP}"
+cd $(dirname "$0")
+
+source ${T}/build/envsetup.sh
+
+# Show the commands on the terminal.
+set -x
+
+cd expat
+
+./buildconf.sh
+./configure
+
+mv -f expat_config.h ../expat_config.h
+
+make
```

