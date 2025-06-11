```diff
diff --git a/.github/workflows/build.yml b/.github/workflows/build.yml
index 27b6acb..0d0e37e 100644
--- a/.github/workflows/build.yml
+++ b/.github/workflows/build.yml
@@ -7,7 +7,7 @@ on:
     branches: [ "main" ]
 
 jobs:
-  build-pc:
+  build-linux:
     runs-on: ubuntu-latest
     steps:
       - name: Checkout code
@@ -16,7 +16,7 @@ jobs:
       - name: Set up CMake
         uses: jwlawson/actions-setup-cmake@v2
 
-      - name: Build PC
+      - name: Build PC (Linux)
         run: |
           cmake -S ${{github.workspace}} -B ${{github.workspace}}/build -DCMAKE_BUILD_TYPE=Release
           cmake --build ${{github.workspace}}/build
@@ -30,6 +30,25 @@ jobs:
           name: build-PC-artifacts
           path: build-pc.tar
 
+  build-windows:
+    runs-on: ubuntu-latest
+    steps:
+      - name: Checkout code
+        uses: actions/checkout@v4
+
+      - name: Set up CMake
+        uses: jwlawson/actions-setup-cmake@v2
+
+      - name: Install Windows toolchain
+        run: |
+          sudo apt-get update
+          sudo apt-get install -y mingw-w64 mingw-w64-tools
+
+      - name: Build (crosscmopile) PC Windows
+        run: |
+          cmake -S ${{github.workspace}} -B ${{github.workspace}}/build-windows -DCMAKE_TOOLCHAIN_FILE=${{github.workspace}}/windows_x86_64_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
+          cmake --build ${{github.workspace}}/build-windows
+
   build-arm:
     runs-on: ubuntu-latest
     steps:
@@ -46,12 +65,12 @@ jobs:
 
       - name: Build ARM
         run: |
-          cmake -DCMAKE_BUILD_TYPE=Release -S ${{github.workspace}} -B ${{github.workspace}}/build-arm -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc -DARM=TRUE -DCMAKE_SYSTEM_PROCESSOR=aarch64
+          cmake -S ${{github.workspace}} -B ${{github.workspace}}/build-arm -DCMAKE_TOOLCHAIN_FILE=${{github.workspace}}/arm64_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
           cmake --build ${{github.workspace}}/build-arm
 
-  test-pc:
+  test-linux:
     runs-on: ubuntu-latest
-    needs: build-pc
+    needs: build-linux
     steps:
       - name: Checkout code
         uses: actions/checkout@v4
diff --git a/.github/workflows/release_packages.yml b/.github/workflows/release_packages.yml
new file mode 100644
index 0000000..cb92d2f
--- /dev/null
+++ b/.github/workflows/release_packages.yml
@@ -0,0 +1,122 @@
+name: Release packages
+on:
+  release:
+    types: [published]
+
+  workflow_dispatch:
+
+jobs:
+  build-linux:
+    runs-on: ubuntu-latest
+    steps:
+      - name: Checkout code
+        uses: actions/checkout@v4
+
+      - name: Set up CMake
+        uses: jwlawson/actions-setup-cmake@v2
+
+      - name: Build PC Linux version of openAPV, generate packages and md5 file
+        run: |
+          cmake -S ${{github.workspace}} -B ${{github.workspace}}/build -DCMAKE_BUILD_TYPE=Release
+          cmake --build ${{github.workspace}}/build
+          cd ${{github.workspace}}/build
+          cpack -C Release
+
+      - name: 'Upload PC Linux artifacts'
+        uses: actions/upload-artifact@v4
+        with:
+          name: openapv-linux-${{github.event.release.tag_name}}
+          path: |
+            ${{ github.workspace }}/build/*.deb
+            ${{ github.workspace }}/build/*.md5
+          retention-days: 7
+
+      - name: Upload Linux assets to GitHub Release
+        uses: xresloader/upload-to-github-release@v1
+        env:
+          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
+        with:
+          file: "build/*.deb; build/*.md5"
+          update_latest_release: true
+          draft: false
+          overwrite: true
+
+  build-arm:
+    runs-on: ubuntu-latest
+    steps:
+      - name: Checkout code
+        uses: actions/checkout@v4
+
+      - name: Set up CMake
+        uses: jwlawson/actions-setup-cmake@v2
+
+      - name: Install ARM toolchain
+        run: |
+          sudo apt-get update
+          sudo apt-get install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
+
+      - name: Build ARM
+        run: |
+          cmake -S ${{github.workspace}} -B ${{github.workspace}}/build-arm -DCMAKE_TOOLCHAIN_FILE=${{github.workspace}}/arm64_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
+          cmake --build ${{github.workspace}}/build-arm
+          cd ${{github.workspace}}/build-arm
+          cpack -C Release
+ 
+      - name: 'Upload ARM artifacts'
+        uses: actions/upload-artifact@v4
+        with:
+          name: openapv-arm-${{github.event.release.tag_name}}
+          path: |
+            ${{ github.workspace }}/build-arm/*.deb
+            ${{ github.workspace }}/build-arm/*.md5
+          retention-days: 7
+
+      - name: Upload ARM assets to GitHub Release
+        uses: xresloader/upload-to-github-release@v1
+        env:
+          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
+        with:
+          file: "build-arm/*.deb; build-arm/*.md5"
+          update_latest_release: true
+          draft: false
+          overwrite: true
+
+  build-windows:
+    runs-on: ubuntu-latest
+    steps:
+      - name: Checkout code
+        uses: actions/checkout@v4
+
+      - name: Set up CMake
+        uses: jwlawson/actions-setup-cmake@v2
+
+      - name: Install Windows toolchain
+        run: |
+          sudo apt-get update
+          sudo apt-get install -y mingw-w64 mingw-w64-tools
+
+      - name: Build (crosscmopile) PC Windows version of openAPV, generate packages and md5 file
+        run: |
+          cmake -S ${{github.workspace}} -B ${{github.workspace}}/build-windows -DCMAKE_TOOLCHAIN_FILE=${{github.workspace}}/windows_x86_64_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
+          cmake --build ${{github.workspace}}/build-windows
+          cd ${{github.workspace}}/build-windows
+          cpack -G ZIP -C Release
+
+      - name: 'Upload PC Windows artifacts'
+        uses: actions/upload-artifact@v4
+        with:
+          name: openapv-windows-${{github.event.release.tag_name}}
+          path: |
+            ${{ github.workspace }}/build-windows/*.zip
+            ${{ github.workspace }}/build-windows/*.md5
+          retention-days: 7
+
+      - name: Upload Windows assets to GitHub Release
+        uses: xresloader/upload-to-github-release@v1
+        env:
+          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
+        with:
+          file: "build-windows/*.zip; build-windows/*.md5"
+          update_latest_release: true
+          draft: false
+          overwrite: true
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 70dfbfd..b86694e 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,5 +1,9 @@
 cmake_minimum_required (VERSION 3.12)
 
+########################################
+# Project versioning
+########################################
+
 # Set project version from git tag or version.txt file
 function(get_versions versionstring VERSION_MAJOR VERSION_MINOR VERSION_PATCH)
     string(REGEX REPLACE "^([vV])([0-9]*)([.][0-9]*[.][0-9]*-?.*)$" "\\2" numbers ${versionstring} )
@@ -29,7 +33,7 @@ if(NOT RESULT EQUAL 0)
         "version.txt file doesn't exist!\n"
         "Since your working directory doesn't contain a git repository you must provide \"${CMAKE_SOURCE_DIR}/version.txt\" file containing a valid version string.\n"
         "The version string provided to version.txt must match the following format:\n\tv[VERSION_MAJOR].[VERSION_MINOR].[VERSION_PATCH]\n"
-        "To get the information on version of the downloaded library please follow the link below:\n\t https://github.com/openapv/openapv"
+        "To get the information on version of the downloaded library please follow the link below:\n\t https://github.com/AcademySoftwareFoundation/openapv"
         )
   endif()
 
@@ -52,21 +56,33 @@ if(VERSION_MAJOR STREQUAL ${VERSION_STRING})
 endif()
 message("OAPV VERSION=${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
 
+project (OAPV VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH} LANGUAGES C)
+
+########################################
+# Input arguments.
+########################################
+
 # Check input arguments.
 option(OAPV_APP_STATIC_BUILD "oapv_app will be statically linked against static oapv library" ON)
 if(OAPV_APP_STATIC_BUILD)
     add_definitions(-DOAPV_STATIC_DEFINE)
 endif(OAPV_APP_STATIC_BUILD)
 
-cmake_policy(SET CMP0048 NEW)
-set(CMAKE_C_STANDARD 99)
+# To build for arm provide in command line: -DARM=TRUE
+if(NOT ARM)
+  set(ARM "FALSE")
+else()
+  add_definitions(-DARM=1)
+  set(ARM "TRUE")
+endif()
 
-# Maps to a solution file (OAPV.sln).
-project (OAPV VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})
-set_property(GLOBAL PROPERTY USE_FOLDERS ON)
+########################################
+# Compilation flags
+########################################
 
 # Set compiler flags and options.
 if( MSVC )
+  message("Not supported yet!")
 elseif( UNIX OR MINGW )
     if(NOT CMAKE_BUILD_TYPE)
         set(CMAKE_BUILD_TYPE "Release")
@@ -81,20 +97,33 @@ elseif( UNIX OR MINGW )
         set(OPT_DBG "-DNDEBUG") # disable assert
     endif()
 
-    #set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPT_DBG} -${OPT_LV} -fomit-frame-pointer -Wall -Wno-unused-function -Wno-unused-but-set-variable -Wno-unused-variable -Wno-attributes -Werror -Wno-strict-overflow -Wno-unknown-pragmas -Wno-stringop-overflow -std=c99")
-    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPT_DBG} -${OPT_LV} -fomit-frame-pointer -Wall -Wno-unused-function -std=c99")
-    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-pointer-sign -pthread -Wno-pointer-to-int-cast")
+    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OPT_DBG} -${OPT_LV} -fomit-frame-pointer -pthread -std=c99")
+    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-unused-function -Wno-pointer-sign -Wno-pointer-to-int-cast")
     set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lm")
+else()
+    message("Unknown compiler")
 endif()
 
 # Command to output information to the console
 message ("c Flags: " ${CMAKE_C_FLAGS})
 message ("linker Flags: " ${CMAKE_EXE_LINKER_FLAGS})
 
+########################################
+# Configuration
+########################################
+
+set(CMAKE_C_STANDARD 99)
+cmake_policy(SET CMP0048 NEW)
+set_property(GLOBAL PROPERTY USE_FOLDERS ON)
+
 # Sub-directories where more CMakeLists.txt exist
 add_subdirectory(src)
 add_subdirectory(app)
 
+########################################
+# Targets
+########################################
+
 # uninstall target
 if(NOT TARGET uninstall)
   configure_file(
@@ -106,14 +135,73 @@ if(NOT TARGET uninstall)
     COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
 endif()
 
+########################################
+# CPack project packaging
+########################################
+# Check the operating system
+if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
+    message(STATUS "Linux system")
+    # Read the /etc/os-release file to determine the distribution
+    file(READ "/etc/os-release" OS_RELEASE_CONTENT)
+
+    if(OS_RELEASE_CONTENT MATCHES "ID=debian" OR OS_RELEASE_CONTENT MATCHES "ID=ubuntu")
+        message(STATUS "Debian-based system detected")
+        message(STATUS "Use DEB generator while generating installation package using CPack")
+        set(CPACK_GENERATOR "DEB")
+    elseif(OS_RELEASE_CONTENT MATCHES "ID=rhel" OR OS_RELEASE_CONTENT MATCHES "ID=fedora" OR OS_RELEASE_CONTENT MATCHES "ID=centos")
+        message(STATUS "Red Hat-based system detected")
+        message(STATUS "Use RPM generator while generating installation package using CPack")
+        set(CPACK_GENERATOR "RPM")
+    elseif(OS_RELEASE_CONTENT MATCHES "ID=opensuse")
+        message(STATUS "SUSE-based system detected")
+        message(STATUS "Use RPM generator while generating installation package using CPack")
+        set(CPACK_GENERATOR "RPM")
+    else()
+        message(STATUS "Other Linux distribution detected")
+        message(STATUS "Use TGZ generator while generating installation package using CPack")
+        set(CPACK_GENERATOR "TGZ")
+    endif()
+
+elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
+    message(STATUS "Windows system")
+    
+    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
+        # Check if the compiler path contains 'ucrt64'
+        if(CMAKE_C_COMPILER MATCHES "ucrt64")
+            message(STATUS "UCRT64 environment detected")
+            message(STATUS "Use NSIS generator while generating installation package using CPack")
+            set(CPACK_GENERATOR "NSIS")
+        else()
+            message(STATUS "Not using UCRT64 compiler. Compiler ID: ${CMAKE_C_COMPILER}")
+            message(STATUS "Use TGZ generator while generating installation package using CPack")
+            set(CPACK_GENERATOR "TGZ")
+        endif()
+    # Check if the compiler is MSVC
+    elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
+        message(STATUS "Using Microsoft Visual Studio (MSVC) compiler")
+        message(STATUS "Use NSIS generator while generating installation package using CPack")
+        set(CPACK_GENERATOR "NSIS")
+    else()
+        message(STATUS "Not using MSVC compiler. Compiler ID: ${CMAKE_C_COMPILER_ID}.")
+        message(STATUS "Use ZIP generator while generating installation package using CPack")
+        set(CPACK_GENERATOR "ZIP")
+    endif()
+else()
+    message(STATUS "Other OS: ${CMAKE_SYSTEM_NAME}")
+    message(STATUS "Use ZIP generator while generating installation package using CPack")
+    set(CPACK_GENERATOR "ZIP")
+endif()
+
 # Packaging
 include(InstallRequiredSystemLibraries)
 set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
 set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
 
 set(CPACK_PACKAGE_NAME "OpenAPV")
-set(CPACK_PACKAGE_VENDOR "OpenAPV")
-set(CPACK_PACKAGE_CONTACT "https://github.com/openapv/oapv")
+set(CPACK_PACKAGE_VENDOR "AcademySoftwareFoundation")
+set(CPACK_PACKAGE_CONTACT "https://github.com/AcademySoftwareFoundation")
+set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/AcademySoftwareFoundation/openapv/releases")
+set(CMAKE_PROJECT_HOMEPAGE_URL "https://github.com/AcademySoftwareFoundation/openapv")
 set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Open Advanced Professional Video Codec")
 set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
 set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
@@ -121,13 +209,16 @@ set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
 set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
 set(CPACK_PACKAGE_CHECKSUM MD5)
 
-set(CPACK_DEBIAN_PACKAGE_MAINTAINER "CPNCF")
-
-set(CPACK_GENERATOR "DEB")
+set(CPACK_DEBIAN_PACKAGE_MAINTAINER "AcademySoftwareFoundation")
+set(CPACK_DEBIAN_PACKAGE_SECTION "video")
+set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
 
 include(CPack)
 
-# Testing 
+########################################
+# Testing
+########################################
+
 option(ENABLE_TESTS "Enable tests" ON)
 if (${ENABLE_TESTS})
     enable_testing()
@@ -140,12 +231,20 @@ add_test(NAME Encoder_runs COMMAND ${CMAKE_CURRENT_BINARY_DIR}/bin/oapv_app_enc)
 add_test(NAME Decoder_runs COMMAND ${CMAKE_CURRENT_BINARY_DIR}/bin/oapv_app_dec)
 
 # Test - encode
-add_test(NAME encode COMMAND ${CMAKE_CURRENT_BINARY_DIR}/bin/oapv_app_enc -i ${CMAKE_CURRENT_SOURCE_DIR}/test/sequence/pattern1_yuv422p10le_320x240_25fps.y4m -o out.oapv)
-set_tests_properties(encode PROPERTIES FAIL_REGULAR_EXPRESSION "Encoded frame count               = 0")
-set_tests_properties(encode PROPERTIES PASS_REGULAR_EXPRESSION "Encoded frame count               = 125")
+add_test(NAME encode COMMAND ${CMAKE_CURRENT_BINARY_DIR}/bin/oapv_app_enc -i ${CMAKE_CURRENT_SOURCE_DIR}/test/sequence/pattern1_yuv422p10le_320x240_25fps.y4m -w 320 -h 240 -z 25 -o out.oapv)
+set_tests_properties(encode PROPERTIES
+    TIMEOUT 20
+    FAIL_REGULAR_EXPRESSION "Encoded frame count               = 0"
+    PASS_REGULAR_EXPRESSION "Encoded frame count               = 125"
+    RUN_SERIAL TRUE
+)
 
 # Test - decode
 add_test(NAME decode COMMAND ${CMAKE_CURRENT_BINARY_DIR}/bin/oapv_app_dec -i out.oapv)
-set_tests_properties(decode PROPERTIES FAIL_REGULAR_EXPRESSION "Decoded frame count               = 0")
-set_tests_properties(decode PROPERTIES PASS_REGULAR_EXPRESSION "Decoded frame count               = 125")
-
+set_tests_properties(decode PROPERTIES
+    TIMEOUT 10
+    DEPENDS encode
+    FAIL_REGULAR_EXPRESSION "Decoded frame count               = 0"
+    PASS_REGULAR_EXPRESSION "Decoded frame count               = 125"
+    RUN_SERIAL TRUE
+)
diff --git a/METADATA b/METADATA
index e7c411e..a0d5c2e 100644
--- a/METADATA
+++ b/METADATA
@@ -7,15 +7,15 @@ description: "Open source APV Video Codec implementation"
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
-    month: 11
-    day: 22
+    year: 2025
+    month: 3
+    day: 5
   }
   homepage: "https://github.com/openapv/openapv"
   identifier {
     type: "Git"
     value: "https://github.com/openapv/openapv.git"
-    version: "v0.1.9.2"
+    version: "v0.1.11.3"
     primary_source: true
   }
 }
diff --git a/OWNERS b/OWNERS
index c956c29..a2a4268 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
-include platform/system/core:main:/janitors/OWNERS
\ No newline at end of file
+include platform/system/core:main:/janitors/OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/README.md b/README.md
index 59ab57d..eb753b3 100644
--- a/README.md
+++ b/README.md
@@ -44,27 +44,37 @@ The APV codec standard has the following features:
   For ARM
   - gcc-aarch64-linux-gnu
   - binutils-aarch64-linux-gnu
+ 
+  For Windows (crosscompile)
+  - mingw-w64
+  - mingw-w64-tools
 
-- Build Instructions PC
+- Build Instructions PC (Linux)
   ```
   cmake -DCMAKE_BUILD_TYPE=Release -S . -B build
   cmake --build build
   ```
 
-- Build Instructions ARM
+- Build Instructions ARM (Crosscompile)
   ```
-  cmake -DCMAKE_BUILD_TYPE=Release -S . -B build-arm -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc -DARM=TRUE -DCMAKE_SYSTEM_PROCESSOR=aarch64
+  cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=aarch64_toolchain.cmake -DCMAKE_BUILD_TYPE=Release 
   cmake --build build-arm
   ```
 
+- Build Instructions Windows (Crosscompile)
+  ```
+  cmake -S . -B build-windows -DCMAKE_TOOLCHAIN_FILE=windows_x86_64_toolchain.cmake -DCMAKE_BUILD_TYPE=Release 
+  cmake --build build-windows
+  ```
+
 - Output Location
-  - Executable applications can be found under build/bin/ or build-arm/bin/
-  - Library files can be found under build/lib/ or build-arm/lib/
+  - Executable applications can be found under build*/bin/
+  - Library files can be found under build*/lib/
 
 ## How to use
 ### Encoder
 
-Encoder as input require raw YUV file (422, 444), 10-bit or more.
+Encoder as input require raw YCbCr file (422, 444), 10-bit or more.
 
 Displaying help:
 
@@ -87,6 +97,18 @@ Decoding:
 
     oapv_app_dec -i encoded.apv -o output.y4m
 
+## Utility
+
+### Graphical APV bitstream parser
+
+Pattern file of APV bitstream for [ImHex](https://github.com/WerWolv/ImHex) is provided [here](/util/apv.hexpat).
+1. Install [ImHex](https://github.com/WerWolv/ImHex) application
+2. Download [APV pattern file](/util/apv.hexpat)
+2. Open APV bitstream (\*.apv file) with ImHex
+3. Import the APV pattern file on Pattern editor view of ImHex and apply
+
+![APV_on_ImHex](/readme/img/apv_parser_on_imhex.png)
+
 ## Testing
 
 In build directory run ``ctest``
diff --git a/app/oapv_app_dec.c b/app/oapv_app_dec.c
index 819e258..15dcbbc 100644
--- a/app/oapv_app_dec.c
+++ b/app/oapv_app_dec.c
@@ -419,34 +419,22 @@ int main(int argc, const char **argv)
     if(fp_bs == NULL) {
         logerr("ERROR: cannot open bitstream file = %s\n", args_var->fname_inp);
         print_usage(argv);
-        return -1;
+        ret = -1; goto ERR;
     }
     /* open output file */
     if(strlen(args_var->fname_out) > 0) {
-        char  fext[16];
-        char *fname = (char *)args_var->fname_out;
-
-        if(strlen(fname) < 5) { /* at least x.yuv or x.y4m */
-            logerr("ERROR: invalide output file name\n");
-            return -1;
+        ret = check_file_name_type(args_var->fname_out);
+        if(ret > 0) {
+            is_y4m = 1;
         }
-        strncpy(fext, fname + strlen(fname) - 3, sizeof(fext) - 1);
-        fext[0] = toupper(fext[0]);
-        fext[1] = toupper(fext[1]);
-        fext[2] = toupper(fext[2]);
-
-        if(strcmp(fext, "YUV") == 0) {
+        else if(ret == 0) {
             is_y4m = 0;
         }
-        else if(strcmp(fext, "Y4M") == 0) {
-            is_y4m = 1;
-        }
-        else {
-            logerr("ERROR: unknown output format\n");
-            ret = -1;
-            goto ERR;
+        else { // invalid or unknown file name type
+            logerr("unknown file type name for decoded video\n");
+            ret = -1; goto ERR;
         }
-        clear_data(fname); /* remove decoded file contents if exists */
+        clear_data(args_var->fname_out); /* remove decoded file contents if exists */
     }
 
     // create bitstream buffer
@@ -609,10 +597,14 @@ int main(int argc, const char **argv)
                         if(write_y4m_header(args_var->fname_out, imgb_o)) {
                             logerr("cannot write Y4M header\n");
                             ret = -1;
-                            goto END;
+                            goto ERR;
                         }
                     }
-                    write_dec_img(args_var->fname_out, imgb_o, is_y4m);
+                    if(write_dec_img(args_var->fname_out, imgb_o, is_y4m)) {
+                        logerr("cannot write decoded video\n");
+                        ret = -1;
+                        goto ERR;
+                    }
                 }
                 frm_cnt[i]++;
             }
diff --git a/app/oapv_app_enc.c b/app/oapv_app_enc.c
index 6fd40c4..58fa94c 100644
--- a/app/oapv_app_enc.c
+++ b/app/oapv_app_enc.c
@@ -79,7 +79,9 @@ static const args_opt_t enc_args_opts[] = {
     },
     {
         'q',  "qp", ARGS_VAL_TYPE_INTEGER, 0, NULL,
-        "QP value (0~51)"
+        "QP value: 0 ~ (63 + (bitdepth - 10)*6) \n"
+        "      - 10bit input: 0 ~ 63\n"
+        "      - 12bit input: 0 ~ 75\n"
     },
     {
         'z',  "fps", ARGS_VAL_TYPE_STRING | ARGS_VAL_TYPE_MANDATORY, 0, NULL,
@@ -95,17 +97,17 @@ static const args_opt_t enc_args_opts[] = {
     },
     {
         'd',  "input-depth", ARGS_VAL_TYPE_INTEGER, 0, NULL,
-        "input bit depth (8, 10) "
+        "input bit depth (8, 10-12)\n"
+        "      - Note: 8bit input will be converted to 10bit"
     },
     {
         ARGS_NO_KEY,  "input-csp", ARGS_VAL_TYPE_INTEGER, 0, NULL,
         "input color space (chroma format)\n"
-        "      - 0: YUV400\n"
-        "      - 1: YUV420\n"
-        "      - 2: YUV422\n"
-        "      - 3: YUV444\n"
-        "      - 4: YUV4444\n"
-        "      - 5: P2(Planar Y, Combined UV, 422)"
+        "      - 0: 400\n"
+        "      - 2: 422\n"
+        "      - 3: 444\n"
+        "      - 4: 4444\n"
+        "      - 5: P2(Planar Y, Combined CbCr, 422)"
     },
     {
         ARGS_NO_KEY,  "profile", ARGS_VAL_TYPE_STRING, 0, NULL,
@@ -128,12 +130,16 @@ static const args_opt_t enc_args_opts[] = {
         "number of skipped access units before encoding"
     },
     {
-        ARGS_NO_KEY,  "qp-cb-offset", ARGS_VAL_TYPE_INTEGER, 0, NULL,
-        "QP offset value for Cb"
+        ARGS_NO_KEY,  "qp-offset-c1", ARGS_VAL_TYPE_INTEGER, 0, NULL,
+        "QP offset value for Component 1 (Cb)"
     },
     {
-        ARGS_NO_KEY,  "qp-cr-offset", ARGS_VAL_TYPE_INTEGER, 0, NULL,
-        "QP offset value for Cr"
+        ARGS_NO_KEY,  "qp-offset-c2", ARGS_VAL_TYPE_INTEGER, 0, NULL,
+        "QP offset value for Component 2 (Cr)"
+    },
+    {
+        ARGS_NO_KEY,  "qp-offset-c3", ARGS_VAL_TYPE_INTEGER, 0, NULL,
+        "QP offset value for Component 3"
     },
     {
         ARGS_NO_KEY,  "tile-w-mb", ARGS_VAL_TYPE_INTEGER, 0, NULL,
@@ -154,20 +160,20 @@ static const args_opt_t enc_args_opts[] = {
         "user filler flag"
     },
     {
-        ARGS_NO_KEY,  "q-matrix-y", ARGS_VAL_TYPE_STRING, 0, NULL,
-        "custom quantization matrix for Y \"q1 q2 ... q63 q64\""
+        ARGS_NO_KEY,  "q-matrix-c0", ARGS_VAL_TYPE_STRING, 0, NULL,
+        "custom quantization matrix for component 0 (Y) \"q1 q2 ... q63 q64\""
     },
     {
-        ARGS_NO_KEY,  "q-matrix-u", ARGS_VAL_TYPE_STRING, 0, NULL,
-        "custom quantization matrix for U \"q1 q2 ... q63 q64\""
+        ARGS_NO_KEY,  "q-matrix-c1", ARGS_VAL_TYPE_STRING, 0, NULL,
+        "custom quantization matrix for component 1 (Cb) \"q1 q2 ... q63 q64\""
     },
     {
-        ARGS_NO_KEY,  "q-matrix-v", ARGS_VAL_TYPE_STRING, 0, NULL,
-        "custom quantization matrix for V \"q1 q2 ... q63 q64\""
+        ARGS_NO_KEY,  "q-matrix-c2", ARGS_VAL_TYPE_STRING, 0, NULL,
+        "custom quantization matrix for component 2 (Cr) \"q1 q2 ... q63 q64\""
     },
     {
-        ARGS_NO_KEY,  "q-matrix-x", ARGS_VAL_TYPE_STRING, 0, NULL,
-        "custom quantization matrix for X \"q1 q2 ... q63 q64\""
+        ARGS_NO_KEY,  "q-matrix-c3", ARGS_VAL_TYPE_STRING, 0, NULL,
+        "custom quantization matrix for component 3 \"q1 q2 ... q63 q64\""
     },
     {
         ARGS_NO_KEY,  "hash", ARGS_VAL_TYPE_NONE, 0, NULL,
@@ -196,10 +202,7 @@ typedef struct args_var {
     int            band;
     char           bitrate[64];
     char           fps[256];
-    char           q_matrix_y[512];
-    char           q_matrix_u[512];
-    char           q_matrix_v[512];
-    char           q_matrix_x[512];
+    char           q_matrix[OAPV_MAX_CC][512]; // raster-scan order
     char           preset[32];
     oapve_param_t *param;
 } args_var_t;
@@ -230,26 +233,26 @@ static args_var_t *args_init_vars(args_parser_t *args, oapve_param_t *param)
     vars->input_csp = -1;
     args_set_variable_by_key_long(opts, "seek", &vars->seek);
     args_set_variable_by_key_long(opts, "profile", vars->profile);
-    strncpy(vars->profile, "422-10", sizeof(vars->profile) - 1);
+    strcpy(vars->profile, "422-10");
     args_set_variable_by_key_long(opts, "level", vars->level);
-    strncpy(vars->level, "4.1", sizeof(vars->level) - 1);
+    strcpy(vars->level, "4.1");
     args_set_variable_by_key_long(opts, "band", &vars->band);
     vars->band = 2; /* default */
     args_set_variable_by_key_long(opts, "bitrate", vars->bitrate);
     args_set_variable_by_key_long(opts, "fps", vars->fps);
-    strncpy(vars->fps, "60", sizeof(vars->fps) - 1);
-    args_set_variable_by_key_long(opts, "q-matrix-y", vars->q_matrix_y);
-    strncpy(vars->q_matrix_y, "", sizeof(vars->q_matrix_y) - 1);
-    args_set_variable_by_key_long(opts, "q-matrix-u", vars->q_matrix_u);
-    strncpy(vars->q_matrix_u, "", sizeof(vars->q_matrix_y) - 1);
-    args_set_variable_by_key_long(opts, "q-matrix-v", vars->q_matrix_v);
-    strncpy(vars->q_matrix_v, "", sizeof(vars->q_matrix_y) - 1);
-    args_set_variable_by_key_long(opts, "q-matrix-x", vars->q_matrix_x);
-    strncpy(vars->q_matrix_x, "", sizeof(vars->q_matrix_x) - 1);
+    strcpy(vars->fps, "60");
+    args_set_variable_by_key_long(opts, "q-matrix-c0", vars->q_matrix[0]);
+    strcpy(vars->q_matrix[0], "");
+    args_set_variable_by_key_long(opts, "q-matrix-c1", vars->q_matrix[1]);
+    strcpy(vars->q_matrix[1], "");
+    args_set_variable_by_key_long(opts, "q-matrix-c2", vars->q_matrix[2]);
+    strcpy(vars->q_matrix[2], "");
+    args_set_variable_by_key_long(opts, "q-matrix-c3", vars->q_matrix[3]);
+    strcpy(vars->q_matrix[3], "");
     args_set_variable_by_key_long(opts, "threads", &vars->threads);
     vars->threads = 1; /* default */
     args_set_variable_by_key_long(opts, "preset", vars->preset);
-    strncpy(vars->preset, "", sizeof(vars->preset) - 1);
+    strcpy(vars->preset, "");
 
     ARGS_SET_PARAM_VAR_KEY(opts, param, w);
     ARGS_SET_PARAM_VAR_KEY(opts, param, h);
@@ -257,8 +260,9 @@ static args_var_t *args_init_vars(args_parser_t *args, oapve_param_t *param)
     ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, use_filler);
     ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, tile_w_mb);
     ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, tile_h_mb);
-    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, qp_cb_offset);
-    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, qp_cr_offset);
+    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, qp_offset_c1);
+    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, qp_offset_c2);
+    ARGS_SET_PARAM_VAR_KEY_LONG(opts, param, qp_offset_c3);
 
     return vars;
 }
@@ -325,6 +329,17 @@ static int set_extra_config(oapve_t id, args_var_t *vars, oapve_param_t *param)
     return ret;
 }
 
+static int write_rec_img(char *fname, oapv_imgb_t *img, int flag_y4m)
+{
+    if(flag_y4m) {
+        if(write_y4m_frame_header(fname))
+            return -1;
+    }
+    if(imgb_write(fname, img))
+        return -1;
+    return 0;
+}
+
 static void print_commandline(int argc, const char **argv)
 {
     int i;
@@ -449,6 +464,7 @@ static int kbps_str_to_int(char *str)
 
 static int update_param(args_var_t *vars, oapve_param_t *param)
 {
+    int q_len[OAPV_MAX_CC];
     /* update reate controller  parameters */
     if(strlen(vars->bitrate) > 0) {
         param->bitrate = kbps_str_to_int(vars->bitrate);
@@ -456,126 +472,36 @@ static int update_param(args_var_t *vars, oapve_param_t *param)
     }
 
     /* update q_matrix */
-    int len_y = (int)strlen(vars->q_matrix_y);
-    if(len_y > 0) {
-        param->use_q_matrix = 1;
-        char *tmp = vars->q_matrix_y;
-        int   cnt = 0;
-        int   len_cnt = 0;
-        while(len_cnt < len_y && cnt < OAPV_BLK_D) {
-            sscanf(tmp, "%d", &param->q_matrix_y[cnt]);
-            if(param->q_matrix_y[cnt] < 1 || param->q_matrix_y[cnt] > 255) {
-                logerr("input value of q_matrix_y is invalid\n");
-                return -1;
-            }
-            len_cnt += (int)log10(param->q_matrix_y[cnt]) + 2;
-            tmp = vars->q_matrix_y + len_cnt;
-            cnt++;
-        }
-        if(cnt < OAPV_BLK_D) {
-            logerr("input number of q_matrix_y is not enough\n");
-            return -1;
-        }
-    }
-
-    int len_u = (int)strlen(vars->q_matrix_u);
-    if(len_u > 0) {
-        param->use_q_matrix = 1;
-        char *tmp = vars->q_matrix_u;
-        int   cnt = 0;
-        int   len_cnt = 0;
-        while(len_cnt < len_u && cnt < OAPV_BLK_D) {
-            sscanf(tmp, "%d", &param->q_matrix_u[cnt]);
-            if(param->q_matrix_u[cnt] < 1 || param->q_matrix_u[cnt] > 255) {
-                logerr("input value of q_matrix_u is invalid\n");
-                return -1;
-            }
-            len_cnt += (int)log10(param->q_matrix_u[cnt]) + 2;
-            tmp = vars->q_matrix_u + len_cnt;
-            cnt++;
-        }
-        if(cnt < OAPV_BLK_D) {
-            logerr("input number of q_matrix_u is not enough\n");
-            return -1;
-        }
-    }
-
-    int len_v = (int)strlen(vars->q_matrix_v);
-    if(len_v > 0) {
-        param->use_q_matrix = 1;
-        char *tmp = vars->q_matrix_v;
-        int   cnt = 0;
-        int   len_cnt = 0;
-        while(len_cnt < len_v && cnt < OAPV_BLK_D) {
-            sscanf(tmp, "%d", &param->q_matrix_v[cnt]);
-            if(param->q_matrix_v[cnt] < 1 || param->q_matrix_v[cnt] > 255) {
-                logerr("input value of q_matrix_v is invalid\n");
-                return -1;
+    for(int c = 0; c < OAPV_MAX_CC; c++) {
+        q_len[c] = (int)strlen(vars->q_matrix[c]);
+        if(q_len[c] > 0) {
+            param->use_q_matrix = 1;
+            char *qstr = vars->q_matrix[c];
+            int   qcnt = 0;
+            while(strlen(qstr) > 0 && qcnt < OAPV_BLK_D) {
+                int t0, read;
+                sscanf(qstr, "%d%n", &t0, &read);
+                if(t0 < 1 || t0 > 255) {
+                    logerr("input value (%d) for q_matrix[%d][%d] is invalid\n", t0, c, qcnt);
+                    return -1;
+                }
+                param->q_matrix[c][qcnt] = t0;
+                qstr += read;
+                qcnt++;
             }
-            len_cnt += (int)log10(param->q_matrix_v[cnt]) + 2;
-            tmp = vars->q_matrix_v + len_cnt;
-            cnt++;
-        }
-        if(cnt < OAPV_BLK_D) {
-            logerr("input number of q_matrix_v is not enough\n");
-            return -1;
-        }
-    }
-
-    int len_x = (int)strlen(vars->q_matrix_x);
-    if (len_x > 0) {
-        param->use_q_matrix = 1;
-        char* tmp = vars->q_matrix_x;
-        int   cnt = 0;
-        int   len_cnt = 0;
-        while (len_cnt < len_x && cnt < OAPV_BLK_D) {
-            sscanf(tmp, "%d", &param->q_matrix_x[cnt]);
-            if (param->q_matrix_x[cnt] < 1 || param->q_matrix_x[cnt] > 255) {
-                logerr("input value of q_matrix_x is invalid\n");
+            if(qcnt < OAPV_BLK_D) {
+                logerr("input number of q_matrix[%d] is not enough\n", c);
                 return -1;
             }
-            len_cnt += (int)log10(param->q_matrix_x[cnt]) + 2;
-            tmp = vars->q_matrix_x + len_cnt;
-            cnt++;
-        }
-        if (cnt < OAPV_BLK_D) {
-            logerr("input number of q_matrix_x is not enough\n");
-            return -1;
-        }
-    }
-
-    if(param->use_q_matrix) {
-        if(len_y == 0) {
-            for(int i = 0; i < OAPV_BLK_D; i++) {
-                param->q_matrix_y[i] = 16;
-            }
-        }
-
-        if(len_u == 0) {
-            for(int i = 0; i < OAPV_BLK_D; i++) {
-                param->q_matrix_u[i] = 16;
-            }
-        }
-
-        if(len_v == 0) {
-            for(int i = 0; i < OAPV_BLK_D; i++) {
-                param->q_matrix_v[i] = 16;
-            }
-        }
-
-        if (len_x == 0) {
-            for (int i = 0; i < OAPV_BLK_D; i++) {
-                param->q_matrix_x[i] = 16;
-            }
         }
     }
 
     param->csp = vars->input_csp;
 
     /* update level idc */
-    double tmp_level = 0;
-    sscanf(vars->level, "%lf", &tmp_level);
-    param->level_idc = tmp_level * 30;
+    float tmp_level = 0;
+    sscanf(vars->level, "%f", &tmp_level);
+    param->level_idc = (int)((tmp_level * 30.0) + 0.5);
     /* update band idc */
     param->band_idc = vars->band;
 
@@ -619,6 +545,25 @@ static int update_param(args_var_t *vars, oapve_param_t *param)
         param->preset = OAPV_PRESET_DEFAULT;
     }
 
+    /* update tile */
+    if (param->tile_w_mb < OAPV_MIN_TILE_W_MB) {
+        param->tile_w_mb = OAPV_MIN_TILE_W_MB;
+    }
+    if (param->tile_h_mb < OAPV_MIN_TILE_H_MB) {
+        param->tile_h_mb = OAPV_MIN_TILE_H_MB;
+    }
+
+    int tile_w = param->tile_w_mb << OAPV_LOG2_MB_W;
+    int tile_h = param->tile_h_mb << OAPV_LOG2_MB_H;
+    int tile_cols = (param->w + tile_w - 1) / tile_w;
+    int tile_rows = (param->h + tile_h - 1) / tile_h;
+    if (tile_cols > OAPV_MAX_TILE_COLS) {
+        param->tile_w_mb = (((param->w + OAPV_MB_W - 1) >> OAPV_LOG2_MB_W) + OAPV_MAX_TILE_COLS - 1) / OAPV_MAX_TILE_COLS;
+    }
+    if (tile_rows > OAPV_MAX_TILE_ROWS) {
+        param->tile_h_mb = (((param->h + OAPV_MB_H - 1) >> OAPV_LOG2_MB_H) + OAPV_MAX_TILE_ROWS - 1) / OAPV_MAX_TILE_ROWS;
+    }
+
     return 0;
 }
 
@@ -644,9 +589,10 @@ int main(int argc, const char **argv)
     int            ret;
     oapv_clk_t     clk_beg, clk_end, clk_tot;
     oapv_mtime_t   au_cnt, au_skip;
+    int            frm_cnt[MAX_NUM_FRMS] = { 0 };
     double         bitrate_tot; // total bitrate (byte)
     double         psnr_avg[MAX_NUM_FRMS][MAX_NUM_CC] = { 0 };
-    int            is_y4m;
+    int            is_inp_y4m, is_rec_y4m = 0;
     y4m_params_t   y4m;
     int            is_out = 0, is_rec = 0;
     char          *errstr = NULL;
@@ -713,8 +659,8 @@ int main(int argc, const char **argv)
     }
 
     /* y4m header parsing  */
-    is_y4m = y4m_test(fp_inp);
-    if(is_y4m) {
+    is_inp_y4m = y4m_test(fp_inp);
+    if(is_inp_y4m) {
         if(y4m_header_parser(fp_inp, &y4m)) {
             logerr("This y4m is not supported (%s)\n", args_var->fname_inp);
             ret = -1;
@@ -775,6 +721,17 @@ int main(int argc, const char **argv)
     }
 
     if(strlen(args_var->fname_rec) > 0) {
+        ret = check_file_name_type(args_var->fname_rec);
+        if(ret > 0) {
+            is_rec_y4m = 1;
+        }
+        else if(ret == 0) {
+            is_rec_y4m = 0;
+        }
+        else { // invalid or unknown file name type
+            logerr("unknown file name type for reconstructed video\n");
+            ret = -1; goto ERR;
+        }
         clear_data(args_var->fname_rec);
         is_rec = 1;
     }
@@ -858,7 +815,7 @@ int main(int argc, const char **argv)
             else {
                 imgb_i = imgb_r;
             }
-            ret = imgb_read(fp_inp, imgb_i, param->w, param->h, is_y4m);
+            ret = imgb_read(fp_inp, imgb_i, param->w, param->h, is_inp_y4m);
             if(ret < 0) {
                 logv3("reached out the end of input file\n");
                 ret = OAPV_OK;
@@ -885,14 +842,14 @@ int main(int argc, const char **argv)
 
             print_stat_au(&stat, au_cnt, param, args_var->max_au, bitrate_tot, clk_end, clk_tot);
 
-            for(int i = 0; i < num_frames; i++) {
+            for(int fidx = 0; fidx < num_frames; fidx++) {
                 if(is_rec) {
                     if(args_var->input_depth != 10) {
-                        imgb_cpy(imgb_w, rfrms.frm[i].imgb);
+                        imgb_cpy(imgb_w, rfrms.frm[fidx].imgb);
                         imgb_o = imgb_w;
                     }
                     else {
-                        imgb_o = rfrms.frm[i].imgb;
+                        imgb_o = rfrms.frm[fidx].imgb;
                     }
                 }
 
@@ -914,16 +871,23 @@ int main(int argc, const char **argv)
 
                 // store recon image
                 if(is_rec) {
-                    if(imgb_write(args_var->fname_rec, imgb_o)) {
-                        logerr("cannot write reconstruction image\n");
+                    if(frm_cnt[fidx] == 0 && is_rec_y4m) {
+                        if(write_y4m_header(args_var->fname_rec, imgb_o)) {
+                            logerr("cannot write Y4M header\n");
+                            ret = -1;
+                            goto ERR;
+                        }
+                    }
+                    if(write_rec_img(args_var->fname_rec, imgb_o, is_rec_y4m)) {
+                        logerr("cannot write reconstructed video\n");
                         ret = -1;
                         goto ERR;
                     }
                 }
-
                 print_stat_frms(&stat, &ifrms, &rfrms, psnr_avg);
-                au_cnt++;
+                frm_cnt[fidx] += 1;
             }
+            au_cnt++;
         }
         else if(state == STATE_SKIPPING) {
             if(au_skip < args_var->seek) {
diff --git a/app/oapv_app_y4m.h b/app/oapv_app_y4m.h
index 659eb7b..e385028 100644
--- a/app/oapv_app_y4m.h
+++ b/app/oapv_app_y4m.h
@@ -290,4 +290,32 @@ static int write_y4m_frame_header(char *fname)
     return 0;
 }
 
+// check whether file name is y4m type or not
+// return
+// - positive value : file name has y4m format name
+// - zero : YUV format name
+// - nogative value : unknown format name
+static int check_file_name_type(char * fname)
+{
+    char  fext[16];
+    if(strlen(fname) < 5) { /* at least x.yuv or x.y4m */
+        return -1;
+    }
+    strncpy(fext, fname + strlen(fname) - 3, sizeof(fext) - 1);
+    fext[0] = toupper(fext[0]);
+    fext[1] = toupper(fext[1]);
+    fext[2] = toupper(fext[2]);
+
+    if(strcmp(fext, "YUV") == 0) {
+        return 0;
+    }
+    else if(strcmp(fext, "Y4M") == 0) {
+        return 1;
+    }
+    else {
+        return -1;
+    }
+    return -1; // false
+}
+
 #endif /* _OAPV_APP_Y4M_H_ */
\ No newline at end of file
diff --git a/arm64_toolchain.cmake b/arm64_toolchain.cmake
new file mode 100644
index 0000000..9e07152
--- /dev/null
+++ b/arm64_toolchain.cmake
@@ -0,0 +1,13 @@
+set(CMAKE_SYSTEM_NAME Linux)
+set(CMAKE_SYSTEM_PROCESSOR aarch64)
+
+set(CMAKE_C_COMPILER aarch64-linux-gnu-gcc)
+set(CMAKE_CXX_COMPILER aarch64-linux-gnu-g++)
+
+set(ARM=TRUE)
+
+set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
+set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
+
+set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE arm64)
diff --git a/inc/oapv.h b/inc/oapv.h
index fbf49e1..db4a091 100644
--- a/inc/oapv.h
+++ b/inc/oapv.h
@@ -59,6 +59,13 @@ extern "C" {
 #define OAPV_BLK_H                      (1 << OAPV_LOG2_BLK)
 #define OAPV_BLK_D                      (OAPV_BLK_W * OAPV_BLK_H)
 
+/* size of tile */
+#define OAPV_MAX_TILE_ROWS              (20)
+#define OAPV_MAX_TILE_COLS              (20)
+#define OAPV_MAX_TILES                  (OAPV_MAX_TILE_ROWS * OAPV_MAX_TILE_COLS)
+#define OAPV_MIN_TILE_W_MB              (16)
+#define OAPV_MIN_TILE_H_MB              (8)
+
 /* maximum number of thread */
 #define OAPV_MAX_THREADS                (32)
 
@@ -129,7 +136,7 @@ extern "C" {
 #define OAPV_CS_YCBCR420_14LE           OAPV_CS_SET(OAPV_CF_YCBCR420, 14, 0)
 #define OAPV_CS_P210                    OAPV_CS_SET(OAPV_CF_PLANAR2, 10, 0)
 
-/* max number of color channel: YCbCr4444 -> 4 channels */
+/* max number of color channel: ex) YCbCr4444 -> 4 channels */
 #define OAPV_MAX_CC                     (4)
 
 /*****************************************************************************
@@ -342,17 +349,26 @@ struct oapv_bitb {
  *****************************************************************************/
 typedef struct oapv_frm_info oapv_frm_info_t;
 struct oapv_frm_info {
-    int w;
-    int h;
-    int cs;
-    int pbu_type;
-    int group_id;
-    int profile_idc;
-    int level_idc;
-    int band_idc;
-    int chroma_format_idc;
-    int bit_depth;
-    int capture_time_distance;
+    int           w;
+    int           h;
+    int           cs;
+    int           pbu_type;
+    int           group_id;
+    int           profile_idc;
+    int           level_idc;
+    int           band_idc;
+    int           chroma_format_idc;
+    int           bit_depth;
+    int           capture_time_distance;
+    /* custom quantization matrix */
+    int           use_q_matrix;
+    unsigned char q_matrix[OAPV_MAX_CC][OAPV_BLK_D]; // only meaningful if use_q_matrix is true
+    /* color description values */
+    int           color_description_present_flag;
+    unsigned char color_primaries;          // only meaningful if color_description_present_flag is true
+    unsigned char transfer_characteristics; // only meaningful if color_description_present_flag is true
+    unsigned char matrix_coefficients;      // only meaningful if color_description_present_flag is true
+    int           full_range_flag;          // only meaningful if color_description_present_flag is true
 };
 
 typedef struct oapv_au_info oapv_au_info_t;
@@ -367,43 +383,51 @@ struct oapv_au_info {
 typedef struct oapve_param oapve_param_t;
 struct oapve_param {
     /* profile_idc */
-    int profile_idc;
+    int           profile_idc;
     /* level */
-    int level_idc;
+    int           level_idc;
     /* band */
-    int band_idc;
+    int           band_idc;
     /* width of input frame */
-    int w;
+    int           w;
     /* height of input frame */
-    int h;
+    int           h;
     /* frame rate (Hz) numerator, denominator */
-    int fps_num;
-    int fps_den;
+    int           fps_num;
+    int           fps_den;
     /* rate control type */
-    int rc_type;
-    /* quantization parameter (0 ~ 63)*/
-    int qp;
-    /* quantization parameter offset for CB */
-    int qp_cb_offset;
-    /* quantization parameter offset for CR */
-    int qp_cr_offset;
+    int           rc_type;
+    /* quantization parameters : 0 ~ (63 + (bitdepth - 10)*6)
+       - 10bit input: 0 ~ 63
+       - 12bit input: 0 ~ 75
+    */
+    unsigned char qp;
+    /* quantization parameter offsets */
+    signed char   qp_offset_c1;
+    /* quantization parameter offsets */
+    signed char   qp_offset_c2;
+    /* quantization parameter offsets */
+    signed char   qp_offset_c3;
     /* bitrate (unit: kbps) */
-    int bitrate;
+    int           bitrate;
     /* use filler data for tight constant bitrate */
-    int use_filler;
-    /* use filler quantization matrix */
-    int use_q_matrix;
-    int q_matrix_y[OAPV_BLK_D];
-    int q_matrix_u[OAPV_BLK_D];
-    int q_matrix_v[OAPV_BLK_D];
-    int q_matrix_x[OAPV_BLK_D];
+    int           use_filler;
+    /* use quantization matrix */
+    int           use_q_matrix;
+    unsigned char q_matrix[OAPV_MAX_CC][OAPV_BLK_D]; // raster-scan order
     /* color space */
-    int csp;
-    int tile_cols;
-    int tile_rows;
-    int tile_w_mb;
-    int tile_h_mb;
-    int preset;
+    int           csp;
+    int           tile_cols;
+    int           tile_rows;
+    int           tile_w_mb;
+    int           tile_h_mb;
+    int           preset;
+    /* color description values */
+    int           color_description_present_flag;
+    unsigned char color_primaries;
+    unsigned char transfer_characteristics;
+    unsigned char matrix_coefficients;
+    int           full_range_flag;
 };
 
 /*****************************************************************************
diff --git a/readme/apv_isobmff.md b/readme/apv_isobmff.md
index 5515ab1..5b815d2 100644
--- a/readme/apv_isobmff.md
+++ b/readme/apv_isobmff.md
@@ -21,22 +21,23 @@ This document specifies methods to store data encoded with Advanced Professional
 
 ### Description
 
-The sample entry with APV1SampleEntry type specifies that the track contains APV coded video data samples. This type of sample entry shall use APVCodecConfiguraionBox.
+The sample entry with APV1SampleEntry type specifies that the track contains APV coded video data samples. This type of sample entry shall use APVCodecConfigurationBox.
 
 
 ### Syntax
-
-class APV1SmapleEntry extends VisualSampleEntry('apv1'){
+~~~~
+class APV1SampleEntry extends VisualSampleEntry('apv1'){
 	APVCodecConfigurationBox	config;
 }
+~~~~
 
 ### Semantics
 
-The value of largest_frame_width_minus1 + 1 and largest_frame_height_minus1 + 1 of the APVCodecConfigurationBox shall be used for the value of width and height fields of the VisualSampleEntry, respectively.
+The largest one among the values of the frame_width field and frame_height field of the APVCodecConfigurationBox shall be used for the value of width and height fields of the VisualSampleEntry, respectively.
 
 When the sample entry name is 'apv1', the stream to which this sample entry applies shall be a compliant APV stream as viewed by an APV decoder operating under the configuration (including profile, level, and so on) given in the APVCodecConfigurationBox.
 
-The compressorname field of the VisualSampleEntry shall have '\012APV Coding'. The sample entry with APV1SampleEntry type specifies that the track contains APV coded video data samples. This type of sample entry shall use APVCodecConfiguraionBox.
+The compressorname field of the VisualSampleEntry shall have '\012APV Coding'. The sample entry with APV1SampleEntry type specifies that the track contains APV coded video data samples. This type of sample entry shall use APVCodecConfigurationBox.
 
 ## APV Codec Configuration Box
 
@@ -52,93 +53,108 @@ The compressorname field of the VisualSampleEntry shall have '\012APV Coding'. T
 
 ### Description
 
-The box with APVCodecConfigurationBox shall contains information for initial configuration of a decoder which consumes the samples references the sample entry type of apv1.
+The box with APVCodecConfigurationBox shall contains APVDecoderConfigurationRecord as defined in {{APVDecoderConfigurationRecord}}
 
-All variation of information required to decide appropriate resource for decoding, e.g. the profiles a decoder compliant to, are carried so that the client can decide whether it has appropriate resources to completely decode the AUs in that track.
+### Syntax
+
+~~~~
+aligned(8) class APVDecoderConfigurationBox extends FullBox('apvC',version=0, flags) {
+    APVDecoderConfigurationRecord apvConfig;
+}
+~~~~
+
+## APV Decoder Configuration Record {#APVDecoderConfigurationRecord}		
 
+The APVDecoderConfigurationRecord contains the information for initial configuration of a decoder which consumes the samples references the sample entry type of apv1. The information in this record is extracted from frame_header() of the bitstream stored in the track containing this record.
+
+All variation of information required to decide appropriate resource for decoding, e.g. the profiles a decoder compliant to, are carried so that the client can decide whether it has appropriate resources to completely decode the AUs in that track.
 
 ### Syntax
 
 ~~~~
-aligned(8) class APVDecoderConfigurationBox extends FullBox('apvC',version=0, flags) {
-   unsigned int(8) configurationVersion = 1;
-   unsigned int(8) number_of_configuration_entry;
-   for (i=0; i<number_of_configuration_entry; i++) {
-      unsigned int(8) pbu_type[i];
-      unsigned int(8) number_of_frame_info[i];
-      for (j=0; j<number_of_frame_info[i]; j++) {
-         reserved_zero_6bits;
-         unsigned int(1) color_description_present_flag[i][j];
-         unsigned int(1) capture_time_distance_ignored[i][j];
-         unsigned int(8) profile_idc[i][j];
-         unsigned int(8) level_idc[i][j];
-         unsigned int(8) band_idc[i][j];
-         unsigned int(32) frame_width_minus1[i][j];
-         unsigned int(32) frame_height_minus1[i][j];
-         unsigned int(4) chroma_format_idc[i][j];
-         unsigned int(4) bit_depth_minus8[i][j];
-         unsigned int(8) capture_time_distance[i][j];
-         if (color_description_present_flag[i][j]) {
-            unsigned int(8) color_primaries[i][j];
-            unsigned int(8) transfer_characteristics[i][j];
-            unsigned int(8) matrix_coefficients[i][j];
-         }
-      }
-   }
+aligned(8) class APVDecoderConfigurationRecord {
+    unsigned int(8) configurationVersion = 1;
+    unsigned int(8) number_of_configuration_entry;
+    for (i=0; i<number_of_configuration_entry; i++) {
+        unsigned int(8) pbu_type[i];
+        unsigned int(8) number_of_frame_info[i];
+        for (j=0; j<number_of_frame_info[i]; j++) {
+            reserved_zero_6bits;
+            unsigned int(1) color_description_present_flag[i][j];
+            unsigned int(1) capture_time_distance_ignored[i][j];
+            unsigned int(8) profile_idc[i][j];
+            unsigned int(8) level_idc[i][j];
+            unsigned int(8) band_idc[i][j];
+            unsigned int(32) frame_width[i][j];
+            unsigned int(32) frame_height[i][j];
+            unsigned int(4) chroma_format_idc[i][j];
+            unsigned int(4) bit_depth_minus8[i][j];
+            unsigned int(8) capture_time_distance[i][j];
+            if (color_description_present_flag[i][j]) {
+                unsigned int(8) color_primaries[i][j];
+                unsigned int(8) transfer_characteristics[i][j];
+                unsigned int(8) matrix_coefficients[i][j];
+                unsigned int(1) full_range_flag[i][j];
+                reserved_zero_7bits;
+            }
+        }
+    }
 }
 ~~~~
 
 ### Semantics
 
 + number_of_configuration_entry
-    > indicates the number of frame header information for a specific PBU types are stored.
+> indicates the number of frame header information for a specific PBU types are stored.
 
 + pbu_type[i]
-
-   > indicates the value of the pbu_type field in the pbu header immediately preceding the frame data for a certain index i.
+> indicates the value of the pbu_type field in the pbu header immediately preceding the frame data for a certain index i.
 
 + number_of_frame_info[i]
-
-   > indicates the number of variations of the frame header information for the frames whose value of the pbu_type field in the pbu header immediately preceding it is idendtical with the value of the pub_type[i] field for a certain index i.
+> indicates the number of variations of the frame header information for the frames whose value of the pbu_type field in the pbu header immediately preceding it is idendtical with the value of the pub_type[i] field for a certain index i.
 
 + color_description_present_flag[i][j]
-   >indicates whether the color description information is provided for the jth variation of frame header whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+>indicates whether the color description information is provided for the jth variation of frame header whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 + capture_time_distance_ignored[i][j]
-   > indicates whether the value of the capture_time_distance field in the jth variation of frame header is used for the processing of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+> indicates whether the value of the capture_time_distance field in the jth variation of frame header is used for the processing of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 + profile_idc[i][j]
-   > indicates the value of the profile_idc field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the profile_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of profile_idc field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+> indicates the value of the profile_idc field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the profile_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of profile_idc field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 + level_idc[i][j]
-   > indicates the value of the level_idc field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the level_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of level_idc field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+> indicates the value of the level_idc field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the level_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of level_idc field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 + band_idc[i][j]
-   > indicates the value of the band_idc field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the band_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of band_idc field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+> indicates the value of the band_idc field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the band_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of band_idc field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
-+ frame_width_minus1[i][j]
-   > indicates the value of the frame_width_minus1 field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the frame_width_minus1 field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of frame_width_minus1 field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
++ frame_width[i][j]
+> indicates the value of the frame_width field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the frame_width field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of frame_width field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
-+ frame_height_minus1[i][j]
-   > indicates the value of the frame_height_minus1 field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the frame_height_minus1 field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of frame_height_minus1 field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
++ frame_height[i][j]
+> indicates the value of the frame_height field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the frame_height field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of frame_height field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 + chroma_format_idc[i][j]
-   > indicates the value of the chroma_format_idc field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the chroma_format_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of chroma_format_idc field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+> indicates the value of the chroma_format_idc field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the chroma_format_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of chroma_format_idc field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 + bit_depth_minus8[i]
-   > indicates the value of the bit_depth_minus8 field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the bit_depth_minus8 field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of bit_depth_minus8 field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+> indicates the value of the bit_depth_minus8 field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the bit_depth_minus8 field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of bit_depth_minus8 field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 + capture_time_distance[i][j]
-   > indicates the value of the capture_time_distance field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the capture_time_distance field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of capture_time_distance field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+> indicates the value of the capture_time_distance field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the capture_time_distance field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of capture_time_distance field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 + color_primaries[i][j]
- > indicates the value of the color_primaries field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the profile_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of color_primaries field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+> indicates the value of the color_primaries field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the color_primaries field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of color_primaries field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 + transfer_characteristics[i][j]
- > indicates the value of the transfer_characteristics field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the profile_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of transfer_characteristics field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+> indicates the value of the transfer_characteristics field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the transfer_characteristics field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of transfer_characteristics field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 + matrix_coefficients[i][j]
- > indicates the value of the matrix_coefficients field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the profile_idc field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of matrix_cofficients field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+> indicates the value of the matrix_coefficients field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of the matrix_coefficients field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of matrix_cofficients field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
+
++ full_range_flag[i][j]
+> indicates the value of the full_range_flag field in the jth variation of the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1, then the same value of this field must be used as the value of
+the full_range_flag field in the frame header of the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i. If the value of number_of_frame_info[i] is 1 is greater than 1, then the frame header in each sample must provide the value of matrix_cofficients field matched with one among the values of this field for all index j for the frames whose value of the pbu_type field in the pbu header immediately preceding it is identical with the value of the pbu_type[i] field for a certain index i.
 
 ## APV Sample Description
 
@@ -160,14 +176,14 @@ The subsample_priority field shall be set to a value in accordance with the spec
 The discardable field shall be set to 1 only if this sample would still be decodable if this sub-sample is discarded.
 
 The codec_specific_parameters field of the SubSampleInformationBox is defined for APV as follows:
-~~~~
 
-		if (flags == 0) {
-			unsigned int(32) tile_index;
-                             }
-		else {
-			bit(32) reserved = 0;
-		}
+~~~~
+if (flags == 0) {
+    unsigned int(32) tile_index;
+}
+else {
+    bit(32) reserved = 0;
+}
 ~~~~
 
 tile_index for sub-samples based on tiles, this parameter indicates the tile index in raster order in a frame.
diff --git a/readme/empty.txt b/readme/empty.txt
deleted file mode 100644
index 588fe22..0000000
--- a/readme/empty.txt
+++ /dev/null
@@ -1 +0,0 @@
-This is empy file
diff --git a/readme/img/apv_parser_on_imhex.png b/readme/img/apv_parser_on_imhex.png
new file mode 100644
index 0000000..3ad7a2e
Binary files /dev/null and b/readme/img/apv_parser_on_imhex.png differ
diff --git a/src/avx/oapv_sad_avx.c b/src/avx/oapv_sad_avx.c
index 67d773f..e114c3d 100644
--- a/src/avx/oapv_sad_avx.c
+++ b/src/avx/oapv_sad_avx.c
@@ -33,30 +33,188 @@
 
 #if X86_SSE
 
-static s64 ssd_16b_sse_8x8_avx(int w, int h, void* src1, void* src2, int s_src1, int s_src2, int bit_depth)
+/* SAD ***********************************************************************/
+static int sad_16b_avx_8x8(int w, int h, void* src1, void* src2, int s_src1, int s_src2)
 {
     s16* s1 = (s16*)src1;
     s16* s2 = (s16*)src2;
-    int t[8] = { 0 };
-    __m256i sum = _mm256_setzero_si256();
-    __m256i v1, v2;
-
-    for (int i = 0; i < 64; i += 8)
-    {
-        v1 = _mm256_loadu_si256((const __m256i*)(s1 + i));
-        v2 = _mm256_loadu_si256((const __m256i*)(s2 + i));
-        v2 = _mm256_sub_epi16(v1, v2);
-        v2 = _mm256_madd_epi16(v2, v2);
-        sum = _mm256_add_epi32(sum, v2);
-        _mm256_storeu_si256((__m256i*)(t), sum);
-    }
-    return t[0] + t[1] + t[2] + t[3];
+    __m256i zero_vector = _mm256_setzero_si256();
+    __m256i s1_vector, s2_vector, diff_vector, diff_abs1, diff_abs2;
+    // Because we are working with 16 elements at a time, stride is multiplied by 2.
+    s16 s1_stride = 2 * s_src1;
+    s16 s2_stride = 2 * s_src2;
+    { // Row 0 and Row 1
+        // Load Row 0 and Row 1 data into registers.
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s1 += s1_stride;
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        s2 += s2_stride;
+        // Calculate absolute difference between two rows.
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        diff_abs1 = _mm256_abs_epi16(diff_vector);
+    }
+    { // Row 2 and Row 3
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s1 += s1_stride;
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        s2 += s2_stride;
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        diff_abs2 = _mm256_abs_epi16(diff_vector);
+    }
+    // Add absolute differences to running total.
+    __m256i sum = _mm256_add_epi16(diff_abs1, diff_abs2);
+    { // Row 4 and Row 5
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s1 += s1_stride;
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        s2 += s2_stride;
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        diff_abs2 = _mm256_abs_epi16(diff_vector);
+        sum = _mm256_add_epi16(sum, diff_abs2);
+    }
+    { // Row 6 and Row 7
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        diff_abs2 = _mm256_abs_epi16(diff_vector);
+        sum = _mm256_add_epi16(sum, diff_abs2);
+    }
+    // Convert 16-bit integers to 32-bit integers for summation.
+    __m128i sum_low = _mm256_extracti128_si256(sum, 0);
+    __m128i sum_high = _mm256_extracti128_si256(sum, 1);
+    __m256i sum_low_32 = _mm256_cvtepi16_epi32(sum_low);
+    __m256i sum_high_32 = _mm256_cvtepi16_epi32(sum_high);
+    // Sum up all the values in the array to get final SAD value.
+    sum = _mm256_add_epi32(sum_low_32, sum_high_32);
+    __m256i sum_hadd = _mm256_hadd_epi32(sum, zero_vector); // Horizontal add with zeros
+    sum = _mm256_hadd_epi32(sum_hadd, zero_vector); // Horizontal add with zeros
+    int sum1 = _mm256_extract_epi32(sum, 0);
+    int sum2 = _mm256_extract_epi32(sum, 4);
+    int sad = sum1 + sum2;
+    return sad;
+}
+
+const oapv_fn_sad_t oapv_tbl_fn_sad_16b_avx[2] =
+{
+    sad_16b_avx_8x8,
+    NULL
+};
+
+/* SSD ***********************************************************************/
+static s64 ssd_16b_avx_8x8(int w, int h, void* src1, void* src2, int s_src1, int s_src2)
+{
+    s16* s1 = (s16*)src1;
+    s16* s2 = (s16*)src2;
+    __m256i s1_vector, s2_vector, diff_vector, sq_vector1, sq_vector2;
+    s64 sum_arr[4];
+    // Because we are working with 16 elements at a time, stride is multiplied by 2.
+    s16 s1_stride = 2 * s_src1;
+    s16 s2_stride = 2 * s_src2;
+    s64 ssd = 0;
+    { // Row 0 and Row 1
+        // Load Row 0 and Row 1 data into registers.
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s1 += s1_stride;
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        s2 += s2_stride;
+        // Calculate squared difference between two rows.
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        sq_vector1 = _mm256_madd_epi16(diff_vector, diff_vector);
+    }
+    { // Row 2 and Row 3
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s1 += s1_stride;
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        s2 += s2_stride;
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        sq_vector2 = _mm256_madd_epi16(diff_vector, diff_vector);
+    }
+    // Add squared differences to running total.
+    __m256i sum = _mm256_add_epi32(sq_vector1, sq_vector2);
+    { // Row 4 and Row 5
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s1 += s1_stride;
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        s2 += s2_stride;
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        sq_vector2 = _mm256_madd_epi16(diff_vector, diff_vector);
+        sum = _mm256_add_epi32(sum, sq_vector2);
+    }
+    { // Row 6 and Row 7
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        sq_vector2 = _mm256_madd_epi16(diff_vector, diff_vector);
+        sum = _mm256_add_epi32(sum, sq_vector2);
+    }
+    // Convert 16-bit integers to 32-bit integers for summation.
+    __m128i sum_low = _mm256_extracti128_si256(sum, 0);
+    __m128i sum_high = _mm256_extracti128_si256(sum, 1);
+    __m256i sum_low_64 = _mm256_cvtepi32_epi64(sum_low);
+    __m256i sum_high_64 = _mm256_cvtepi32_epi64(sum_high);
+    // Sum up all the values in the array to get final SSD value.
+    sum = _mm256_add_epi64(sum_low_64, sum_high_64);
+    _mm256_storeu_si256((__m256i*)sum_arr, sum); // store in array for summation.
+    ssd = sum_arr[0] + sum_arr[1] + sum_arr[2] + sum_arr[3];
+    return ssd;
 }
 
 const oapv_fn_ssd_t oapv_tbl_fn_ssd_16b_avx[2] =
 {
-    ssd_16b_sse_8x8_avx,
-        NULL
+    ssd_16b_avx_8x8,
+    NULL
 };
 
+/* DIFF ***********************************************************************/
+static void diff_16b_avx_8x8(int w, int h, void* src1, void* src2, int s_src1, int s_src2, int s_diff, s16 *diff)
+{
+    s16* s1 = (s16*)src1;
+    s16* s2 = (s16*)src2;
+    __m256i s1_vector, s2_vector, diff_vector;
+    // Because we are working with 16 elements at a time, stride is multiplied by 2.
+    s16 s1_stride = 2 * s_src1;
+    s16 s2_stride = 2 * s_src2;
+    s16 diff_stride = 2 * s_diff;
+    { // Row 0 and Row 1
+        // Load Row 0 and Row 1 data into registers.
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s1 += s1_stride;
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        s2 += s2_stride;
+        // Calculate difference between two rows and store it in diff buffer.
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        _mm256_storeu_si256((__m256i*)diff, diff_vector);
+        diff += diff_stride;
+    }
+    { // Row 2 and Row 3
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s1 += s1_stride;
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        s2 += s2_stride;
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        _mm256_storeu_si256((__m256i*)diff, diff_vector);
+        diff += diff_stride;
+    }
+    { // Row 4 and Row 5
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s1 += s1_stride;
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        s2 += s2_stride;
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        _mm256_storeu_si256((__m256i*)diff, diff_vector);
+        diff += diff_stride;
+    }
+    { // Row 6 and Row 7
+        s1_vector = _mm256_loadu_si256((const __m256i*)(s1));
+        s2_vector = _mm256_loadu_si256((const __m256i*)(s2));
+        diff_vector = _mm256_sub_epi16(s1_vector, s2_vector);
+        _mm256_storeu_si256((__m256i*)diff, diff_vector);
+    }
+}
+
+const oapv_fn_diff_t oapv_tbl_fn_diff_16b_avx[2] =
+{
+    diff_16b_avx_8x8,
+    NULL
+};
 #endif
\ No newline at end of file
diff --git a/src/avx/oapv_sad_avx.h b/src/avx/oapv_sad_avx.h
index 8cc31cd..3165316 100644
--- a/src/avx/oapv_sad_avx.h
+++ b/src/avx/oapv_sad_avx.h
@@ -36,7 +36,9 @@
 #include <immintrin.h>
 
 #if X86_SSE
+extern const oapv_fn_sad_t oapv_tbl_fn_sad_16b_avx[2];
 extern const oapv_fn_ssd_t oapv_tbl_fn_ssd_16b_avx[2];
+extern const oapv_fn_diff_t oapv_tbl_fn_diff_16b_avx[2];
 #endif /* X86_SSE */
 
 #endif /* _OAPV_SAD_AVX_H_ */
diff --git a/src/avx/oapv_tq_avx.c b/src/avx/oapv_tq_avx.c
index dba56cf..22c8d4e 100644
--- a/src/avx/oapv_tq_avx.c
+++ b/src/avx/oapv_tq_avx.c
@@ -290,10 +290,207 @@ const oapv_fn_itx_part_t oapv_tbl_fn_itx_part_avx[2] =
 
 static void oapv_itx_avx(s16* src, int shift1, int shift2, int line)
 {
-    // To Do: Merge 2 passes and optimize AVX further
-    ALIGNED_16(s16 dst[OAPV_BLK_D]);
-    oapv_itx_part_avx(src, dst, shift1, line);
-    oapv_itx_part_avx(dst, src, shift2, line);
+    const __m256i coeff_p89_p75 = _mm256_setr_epi16(89, 75, 89, 75, 89, 75, 89, 75, 89, 75, 89, 75, 89, 75, 89, 75); // 89 75
+    const __m256i coeff_p50_p18 = _mm256_setr_epi16(50, 18, 50, 18, 50, 18, 50, 18, 50, 18, 50, 18, 50, 18, 50, 18); // 50, 18
+    const __m256i coeff_p75_n18 = _mm256_setr_epi16(75, -18, 75, -18, 75, -18, 75, -18, 75, -18, 75, -18, 75, -18, 75, -18); // 75, -18
+    const __m256i coeff_n89_n50 = _mm256_setr_epi16(-89, -50, -89, -50, -89, -50, -89, -50, -89, -50, -89, -50, -89, -50, -89, -50); // -89, -50
+    const __m256i coeff_p50_n89 = _mm256_setr_epi16(50, -89, 50, -89, 50, -89, 50, -89, 50, -89, 50, -89, 50, -89, 50, -89); // 50,-89
+    const __m256i coeff_p18_p75 = _mm256_setr_epi16(18, 75, 18, 75, 18, 75, 18, 75, 18, 75, 18, 75, 18, 75, 18, 75); // 18, 75
+    const __m256i coeff_p18_n50 = _mm256_setr_epi16(18, -50, 18, -50, 18, -50, 18, -50, 18, -50, 18, -50, 18, -50, 18, -50); // 18,-50
+    const __m256i coeff_p75_n89 = _mm256_setr_epi16(75, -89, 75, -89, 75, -89, 75, -89, 75, -89, 75, -89, 75, -89, 75, -89); // 75,-89
+    const __m256i coeff_p64_p64 = _mm256_setr_epi16(64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64); // 64, 64
+    const __m256i coeff_p64_n64 = _mm256_setr_epi16(64, -64, 64, -64, 64, -64, 64, -64, 64, -64, 64, -64, 64, -64, 64, -64); // 64, -64
+    const __m256i coeff_p84_n35 = _mm256_setr_epi16(84, 35, 84, 35, 84, 35, 84, 35, 84, 35, 84, 35, 84, 35, 84, 35); // 84, 35
+    const __m256i coeff_p35_n84 = _mm256_setr_epi16(35, -84, 35, -84, 35, -84, 35, -84, 35, -84, 35, -84, 35, -84, 35, -84); // 35, -84
+
+    __m128i s0, s1, s2, s3, s4, s5, s6, s7;
+    __m128i ss0, ss1, ss2, ss3;
+    __m256i e0, e1, e2, e3, o0, o1, o2, o3, ee0, ee1, eo0, eo1;
+    __m256i t0, t1, t2, t3;
+    __m256i d0, d1, d2, d3, d4, d5, d6, d7;
+    __m256i offset1 = _mm256_set1_epi32(1 << (shift1 - 1));
+    __m256i offset2 = _mm256_set1_epi32(1 << (shift2 - 1));
+    int i_src = line;
+    int i_src2 = line << 1;
+    int i_src3 = i_src + i_src2;
+    int i_src4 = i_src << 2;
+    int i_src5 = i_src2 + i_src3;
+    int i_src6 = i_src3 << 1;
+    int i_src7 = i_src3 + i_src4;
+    {
+        // O[0] - O[3]
+        s1 = _mm_loadu_si128((__m128i*)(src + i_src));
+        s3 = _mm_loadu_si128((__m128i*)(src + i_src3));
+        s5 = _mm_loadu_si128((__m128i*)(src + i_src5));
+        s7 = _mm_loadu_si128((__m128i*)(src + i_src7));
+
+        ss0 = _mm_unpacklo_epi16(s1, s3);
+        ss1 = _mm_unpackhi_epi16(s1, s3);
+        ss2 = _mm_unpacklo_epi16(s5, s7);
+        ss3 = _mm_unpackhi_epi16(s5, s7);
+
+        e0 = _mm256_set_m128i(ss1, ss0);
+        e1 = _mm256_set_m128i(ss3, ss2);
+
+        t0 = _mm256_madd_epi16(e0, coeff_p89_p75);
+        t1 = _mm256_madd_epi16(e1, coeff_p50_p18);
+        t2 = _mm256_madd_epi16(e0, coeff_p75_n18);
+        t3 = _mm256_madd_epi16(e1, coeff_n89_n50);
+        o0 = _mm256_add_epi32(t0, t1);
+        o1 = _mm256_add_epi32(t2, t3);
+
+        t0 = _mm256_madd_epi16(e0, coeff_p50_n89);
+        t1 = _mm256_madd_epi16(e1, coeff_p18_p75);
+        t2 = _mm256_madd_epi16(e0, coeff_p18_n50);
+        t3 = _mm256_madd_epi16(e1, coeff_p75_n89);
+
+        o2 = _mm256_add_epi32(t0, t1);
+        o3 = _mm256_add_epi32(t2, t3);
+
+        // E[0] - E[3]
+        s0 = _mm_loadu_si128((__m128i*)(src));
+        s2 = _mm_loadu_si128((__m128i*)(src + i_src2));
+        s4 = _mm_loadu_si128((__m128i*)(src + i_src4));
+        s6 = _mm_loadu_si128((__m128i*)(src + i_src6));
+
+        ss0 = _mm_unpacklo_epi16(s0, s4);
+        ss1 = _mm_unpackhi_epi16(s0, s4);
+        ss2 = _mm_unpacklo_epi16(s2, s6);
+        ss3 = _mm_unpackhi_epi16(s2, s6);
+
+        e0 = _mm256_set_m128i(ss1, ss0);
+        e1 = _mm256_set_m128i(ss3, ss2);
+
+        ee0 = _mm256_madd_epi16(e0, coeff_p64_p64);
+        ee1 = _mm256_madd_epi16(e0, coeff_p64_n64);
+        eo0 = _mm256_madd_epi16(e1, coeff_p84_n35);
+        eo1 = _mm256_madd_epi16(e1, coeff_p35_n84);
+
+        e0 = _mm256_add_epi32(ee0, eo0);
+        e3 = _mm256_sub_epi32(ee0, eo0);
+        e1 = _mm256_add_epi32(ee1, eo1);
+        e2 = _mm256_sub_epi32(ee1, eo1);
+
+        e0 = _mm256_add_epi32(e0, offset1);
+        e3 = _mm256_add_epi32(e3, offset1);
+        e1 = _mm256_add_epi32(e1, offset1);
+        e2 = _mm256_add_epi32(e2, offset1);
+
+        d0 = _mm256_add_epi32(e0, o0);
+        d7 = _mm256_sub_epi32(e0, o0);
+        d1 = _mm256_add_epi32(e1, o1);
+        d6 = _mm256_sub_epi32(e1, o1);
+        d2 = _mm256_add_epi32(e2, o2);
+        d5 = _mm256_sub_epi32(e2, o2);
+        d3 = _mm256_add_epi32(e3, o3);
+        d4 = _mm256_sub_epi32(e3, o3);
+
+        d0 = _mm256_srai_epi32(d0, shift1);
+        d7 = _mm256_srai_epi32(d7, shift1);
+        d1 = _mm256_srai_epi32(d1, shift1);
+        d6 = _mm256_srai_epi32(d6, shift1);
+        d2 = _mm256_srai_epi32(d2, shift1);
+        d5 = _mm256_srai_epi32(d5, shift1);
+        d3 = _mm256_srai_epi32(d3, shift1);
+        d4 = _mm256_srai_epi32(d4, shift1);
+
+        // transpose 8x8 : 8 x 8(32bit) --> 4 x 16(16bit)
+        TRANSPOSE_8x8_32BIT_16BIT(d0, d1, d2, d3, d4, d5, d6, d7, d4, d5, d6, d7);
+        d0 = _mm256_insertf128_si256(d4, _mm256_castsi256_si128(d5), 1);
+        d1 = _mm256_insertf128_si256(d6, _mm256_castsi256_si128(d7), 1);
+        d2 = _mm256_insertf128_si256(d5, _mm256_extracti128_si256(d4, 1), 0);
+        d3 = _mm256_insertf128_si256(d7, _mm256_extracti128_si256(d6, 1), 0);
+    }
+    {
+        // O[0] - O[3]
+        s1 = _mm256_extracti128_si256(d0, 1);
+        s3 = _mm256_extracti128_si256(d1, 1);
+        s5 = _mm256_extracti128_si256(d2, 1);
+        s7 = _mm256_extracti128_si256(d3, 1);
+
+        ss0 = _mm_unpacklo_epi16(s1, s3);
+        ss1 = _mm_unpackhi_epi16(s1, s3);
+        ss2 = _mm_unpacklo_epi16(s5, s7);
+        ss3 = _mm_unpackhi_epi16(s5, s7);
+
+        e0 = _mm256_set_m128i(ss1, ss0);
+        e1 = _mm256_set_m128i(ss3, ss2);
+
+        t0 = _mm256_madd_epi16(e0, coeff_p89_p75);
+        t1 = _mm256_madd_epi16(e1, coeff_p50_p18);
+        t2 = _mm256_madd_epi16(e0, coeff_p75_n18);
+        t3 = _mm256_madd_epi16(e1, coeff_n89_n50);
+        o0 = _mm256_add_epi32(t0, t1);
+        o1 = _mm256_add_epi32(t2, t3);
+
+        t0 = _mm256_madd_epi16(e0, coeff_p50_n89);
+        t1 = _mm256_madd_epi16(e1, coeff_p18_p75);
+        t2 = _mm256_madd_epi16(e0, coeff_p18_n50);
+        t3 = _mm256_madd_epi16(e1, coeff_p75_n89);
+
+        o2 = _mm256_add_epi32(t0, t1);
+        o3 = _mm256_add_epi32(t2, t3);
+
+        // E[0] - E[3]
+        s0 = _mm256_extracti128_si256(d0, 0);
+        s2 = _mm256_extracti128_si256(d1, 0);
+        s4 = _mm256_extracti128_si256(d2, 0);
+        s6 = _mm256_extracti128_si256(d3, 0);
+
+        ss0 = _mm_unpacklo_epi16(s0, s4);
+        ss1 = _mm_unpackhi_epi16(s0, s4);
+        ss2 = _mm_unpacklo_epi16(s2, s6);
+        ss3 = _mm_unpackhi_epi16(s2, s6);
+
+        e0 = _mm256_set_m128i(ss1, ss0);
+        e1 = _mm256_set_m128i(ss3, ss2);
+
+        ee0 = _mm256_madd_epi16(e0, coeff_p64_p64);
+        ee1 = _mm256_madd_epi16(e0, coeff_p64_n64);
+        eo0 = _mm256_madd_epi16(e1, coeff_p84_n35);
+        eo1 = _mm256_madd_epi16(e1, coeff_p35_n84);
+
+        e0 = _mm256_add_epi32(ee0, eo0);
+        e3 = _mm256_sub_epi32(ee0, eo0);
+        e1 = _mm256_add_epi32(ee1, eo1);
+        e2 = _mm256_sub_epi32(ee1, eo1);
+
+        e0 = _mm256_add_epi32(e0, offset2);
+        e3 = _mm256_add_epi32(e3, offset2);
+        e1 = _mm256_add_epi32(e1, offset2);
+        e2 = _mm256_add_epi32(e2, offset2);
+
+        d0 = _mm256_add_epi32(e0, o0);
+        d7 = _mm256_sub_epi32(e0, o0);
+        d1 = _mm256_add_epi32(e1, o1);
+        d6 = _mm256_sub_epi32(e1, o1);
+        d2 = _mm256_add_epi32(e2, o2);
+        d5 = _mm256_sub_epi32(e2, o2);
+        d3 = _mm256_add_epi32(e3, o3);
+        d4 = _mm256_sub_epi32(e3, o3);
+
+        d0 = _mm256_srai_epi32(d0, shift2);
+        d7 = _mm256_srai_epi32(d7, shift2);
+        d1 = _mm256_srai_epi32(d1, shift2);
+        d6 = _mm256_srai_epi32(d6, shift2);
+        d2 = _mm256_srai_epi32(d2, shift2);
+        d5 = _mm256_srai_epi32(d5, shift2);
+        d3 = _mm256_srai_epi32(d3, shift2);
+        d4 = _mm256_srai_epi32(d4, shift2);
+
+        // transpose 8x8 : 8 x 8(32bit) --> 4 x 16(16bit)
+        TRANSPOSE_8x8_32BIT_16BIT(d0, d1, d2, d3, d4, d5, d6, d7, d4, d5, d6, d7);
+        d0 = _mm256_insertf128_si256(d4, _mm256_castsi256_si128(d5), 1);
+        d1 = _mm256_insertf128_si256(d6, _mm256_castsi256_si128(d7), 1);
+        d2 = _mm256_insertf128_si256(d5, _mm256_extracti128_si256(d4, 1), 0);
+        d3 = _mm256_insertf128_si256(d7, _mm256_extracti128_si256(d6, 1), 0);
+
+        // store line x 8
+        _mm256_storeu_si256((__m256i*)src, d0);
+        _mm256_storeu_si256((__m256i*)(src + 16), d1);
+        _mm256_storeu_si256((__m256i*)(src + 32), d2);
+        _mm256_storeu_si256((__m256i*)(src + 48), d3);
+    }
 }
 
 const oapv_fn_itx_t oapv_tbl_fn_itx_avx[2] =
@@ -322,6 +519,8 @@ static int oapv_quant_avx(s16* coef, u8 qp, int q_matrix[OAPV_BLK_D], int log2_w
     shift = QUANT_SHIFT + tr_shift + (qp / 6);
     offset = (s64)deadzone_offset << (shift - 9);
     __m256i offset_vector = _mm256_set1_epi64x(offset);
+    __m256i reg_minval_int16 = _mm256_set1_epi32(-32768);
+    __m256i reg_maxval_int16 = _mm256_set1_epi32(32767);
 
     int pixels = (1 << (log2_w + log2_h));
     int i;
@@ -336,7 +535,7 @@ static int oapv_quant_avx(s16* coef, u8 qp, int q_matrix[OAPV_BLK_D], int log2_w
         0, 1, 4, 5, 8, 9, 12, 13,
         -128, -128, -128, -128, -128, -128, -128, -128,
         -128, -128, -128, -128, -128, -128, -128, -128);
-    
+
     for (i = 0; i < pixels; i += 8)
     {
         // Load first row
@@ -344,8 +543,8 @@ static int oapv_quant_avx(s16* coef, u8 qp, int q_matrix[OAPV_BLK_D], int log2_w
         __m128i coef_row = _mm_lddqu_si128((__m128i*)(coef + i));
 
         // Extract sign
-        __m256i coef_row_cast = _mm256_castsi128_si256(coef_row);
-        __m256i sign_mask = _mm256_srai_epi16(coef_row_cast, 15);
+        __m128i sign_mask = _mm_srai_epi16(coef_row, 15);
+        __m256i sign_mask_ext = _mm256_cvtepi16_epi32(sign_mask);
 
         // Convert to 32 bits and take abs()
         __m256i coef_row_ext = _mm256_cvtepi16_epi32(coef_row);
@@ -360,25 +559,23 @@ static int oapv_quant_avx(s16* coef, u8 qp, int q_matrix[OAPV_BLK_D], int log2_w
         // First level of combination
         lev2_low = _mm256_slli_epi64(lev2_low, 32);
         __m256i combined = _mm256_or_si256(lev2_low, lev2_high);
+        __m256i levx = _mm256_permutevar8x32_epi32(combined, shuffle0);
+
+        // Apply sign and clipping
+        levx = _mm256_sub_epi32(_mm256_xor_si256(levx, sign_mask_ext), sign_mask_ext);
+        levx = _mm256_max_epi32(levx, reg_minval_int16);
+        levx = _mm256_min_epi32(levx, reg_maxval_int16);
 
         // Second level of combination
-        __m256i levx = _mm256_permutevar8x32_epi32(combined, shuffle0);
-        __m128i levx_low = _mm256_castsi256_si128(levx);
-        __m256i levx_low_ext = _mm256_castsi128_si256(levx_low);
-        levx_low_ext = _mm256_shuffle_epi8(levx_low_ext, shuffle1);
+        __m256i levx_low_sh = _mm256_shuffle_epi8(levx, shuffle1);
         __m128i levx_high = _mm256_extracti128_si256(levx, 1);
         __m256i levx_high_ext = _mm256_castsi128_si256(levx_high);
-        levx_high_ext = _mm256_shuffle_epi8(levx_high_ext, shuffle2);
-        levx = _mm256_or_si256(levx_high_ext, levx_low_ext);
+        __m256i levx_high_sh = _mm256_shuffle_epi8(levx_high_ext, shuffle2);
+        levx = _mm256_or_si256(levx_high_sh, levx_low_sh);
 
-        // Apply sign
-        levx = _mm256_sub_epi16(_mm256_xor_si256(levx, sign_mask), sign_mask);
-
-        // Clip and store in coef
+        // store in coef
         __m128i lev4 = _mm256_castsi256_si128(levx);
-        __m128i lev5 = _mm_max_epi16(lev4, _mm_set1_epi16(-32768));
-        __m128i lev6 = _mm_min_epi16(lev5, _mm_set1_epi16(32767));
-        _mm_storeu_si128((__m128i*)(coef + i), lev6);
+        _mm_storeu_si128((__m128i*)(coef + i), lev4);
     }
     return OAPV_OK;
 }
@@ -399,6 +596,8 @@ static void oapv_dquant_avx(s16 *coef, s16 q_matrix[OAPV_BLK_D], int log2_w, int
     -1, -1, -1, -1, -1, -1, -1, -1,
     -1, -1, -1, -1, -1, -1, -1, -1,
     0, 1, 4, 5, 8, 9, 12, 13 );
+    __m256i reg_minval_int16 = _mm256_set1_epi32(-32768);
+    __m256i reg_maxval_int16 = _mm256_set1_epi32( 32767);
     if (shift > 0)
     {
         s32 offset = (1 << (shift - 1));
@@ -412,15 +611,15 @@ static void oapv_dquant_avx(s16 *coef, s16 q_matrix[OAPV_BLK_D], int log2_w, int
             __m256i lev2 = _mm256_add_epi32(lev1, offset_1);
             __m256i lev3 = _mm256_srai_epi32(lev2, shift);
 
+            lev3 = _mm256_max_epi32(lev3, reg_minval_int16);
+            lev3 = _mm256_min_epi32(lev3, reg_maxval_int16);
+
             lev3 = _mm256_shuffle_epi8( lev3, shuffle );
             __m128i low = _mm256_castsi256_si128( lev3 );
             __m128i high = _mm256_extracti128_si256( lev3, 1 );
             __m128i lev4 = _mm_or_si128( low, high );
 
-            __m128i lev5 = _mm_max_epi16(lev4, _mm_set1_epi16(-32768));
-            __m128i lev6 = _mm_min_epi16(lev5, _mm_set1_epi16(32767));
-
-            _mm_storeu_si128((__m128i *)(coef + i), lev6);
+            _mm_storeu_si128((__m128i *)(coef + i), lev4);
         }
     }
     else
@@ -434,15 +633,15 @@ static void oapv_dquant_avx(s16 *coef, s16 q_matrix[OAPV_BLK_D], int log2_w, int
             __m256i lev1 = _mm256_mullo_epi32(coef_8_val_act, cur_q_matrix);
             __m256i lev3 = _mm256_slli_epi32(lev1, left_shift);
 
+            lev3 = _mm256_max_epi32(lev3, reg_minval_int16);
+            lev3 = _mm256_min_epi32(lev3, reg_maxval_int16);
+
             lev3 = _mm256_shuffle_epi8( lev3, shuffle );
             __m128i low = _mm256_castsi256_si128( lev3 );
             __m128i high = _mm256_extracti128_si256( lev3, 1 );
             __m128i lev4 = _mm_or_si128( low, high );
 
-            __m128i lev5 = _mm_max_epi16(lev4, _mm_set1_epi16(-32768));
-            __m128i lev6 = _mm_min_epi16(lev5, _mm_set1_epi16(32767));
-
-            _mm_storeu_si128((__m128i *)(coef + i), lev6);
+            _mm_storeu_si128((__m128i *)(coef + i), lev4);
         }
     }
 }
diff --git a/src/neon/oapv_sad_neon.c b/src/neon/oapv_sad_neon.c
index edc2df0..f494ae7 100644
--- a/src/neon/oapv_sad_neon.c
+++ b/src/neon/oapv_sad_neon.c
@@ -34,8 +34,150 @@
 
 #if ARM_NEON
 
+/* SAD for 16bit **************************************************************/
+int sad_16b_neon_8x2n(int w, int h, void *src1, void *src2, int s_src1, int s_src2)
+{
+    int sad = 0;
+    s16* s1 = (s16*) src1;
+    s16* s2 = (s16*) src2;
+    int16x8_t s1_vector, s2_vector;
+    int32x4_t  diff_part1, diff_part2, diff_part1_abs, diff_part2_abs, sad_vector, sad_vector_temp;
+    // Loop unrolled    
+    { // Row 0
+        // Loading one row (8 elements) each of src1 and src_2
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+        
+        // Subtracting s1_vector from s2_vector and storing in 32 bits
+        diff_part1 = vsubl_s16(vget_low_s16(s1_vector), vget_low_s16(s2_vector));
+        diff_part2 = vsubl_high_s16(s1_vector, s2_vector);
+
+        //Taking absolute value of difference and adding them
+        diff_part1_abs = vabsq_s32(diff_part1);
+        diff_part2_abs = vabsq_s32(diff_part2);
+        
+        sad_vector = vaddq_s32(diff_part1_abs, diff_part2_abs);
+    }    
+    { // Row 1
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+        
+        diff_part1 = vsubl_s16(vget_low_s16(s1_vector), vget_low_s16(s2_vector));
+        diff_part2 = vsubl_high_s16(s1_vector, s2_vector);
+
+        diff_part1_abs = vabsq_s32(diff_part1);
+        diff_part2_abs = vabsq_s32(diff_part2);
+        
+        sad_vector_temp = vaddq_s32(diff_part1_abs, diff_part2_abs);
+        // Updating sad_vector by adding the new values
+        sad_vector = vaddq_s32(sad_vector, sad_vector_temp);
+    }    
+    { // Row 2
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+        
+        diff_part1 = vsubl_s16(vget_low_s16(s1_vector), vget_low_s16(s2_vector));
+        diff_part2 = vsubl_high_s16(s1_vector, s2_vector);
+
+        diff_part1_abs = vabsq_s32(diff_part1);
+        diff_part2_abs = vabsq_s32(diff_part2);
+        
+        sad_vector_temp = vaddq_s32(diff_part1_abs, diff_part2_abs);
+        sad_vector = vaddq_s32(sad_vector, sad_vector_temp);
+    }    
+    { // Row 3
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+        
+        diff_part1 = vsubl_s16(vget_low_s16(s1_vector), vget_low_s16(s2_vector));
+        diff_part2 = vsubl_high_s16(s1_vector, s2_vector);
+
+        diff_part1_abs = vabsq_s32(diff_part1);
+        diff_part2_abs = vabsq_s32(diff_part2);
+        
+        sad_vector_temp = vaddq_s32(diff_part1_abs, diff_part2_abs);
+        sad_vector = vaddq_s32(sad_vector, sad_vector_temp);
+    }    
+    { // Row 4
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+        
+        diff_part1 = vsubl_s16(vget_low_s16(s1_vector), vget_low_s16(s2_vector));
+        diff_part2 = vsubl_high_s16(s1_vector, s2_vector);
+
+        diff_part1_abs = vabsq_s32(diff_part1);
+        diff_part2_abs = vabsq_s32(diff_part2);
+        
+        sad_vector_temp = vaddq_s32(diff_part1_abs, diff_part2_abs);
+        sad_vector = vaddq_s32(sad_vector, sad_vector_temp);
+    }    
+    { // Row 5
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+        
+        diff_part1 = vsubl_s16(vget_low_s16(s1_vector), vget_low_s16(s2_vector));
+        diff_part2 = vsubl_high_s16(s1_vector, s2_vector);
+
+        diff_part1_abs = vabsq_s32(diff_part1);
+        diff_part2_abs = vabsq_s32(diff_part2);
+        
+        sad_vector_temp = vaddq_s32(diff_part1_abs, diff_part2_abs);
+        sad_vector = vaddq_s32(sad_vector, sad_vector_temp);
+    }    
+    { // Row 6
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+        
+        diff_part1 = vsubl_s16(vget_low_s16(s1_vector), vget_low_s16(s2_vector));
+        diff_part2 = vsubl_high_s16(s1_vector, s2_vector);
+
+        diff_part1_abs = vabsq_s32(diff_part1);
+        diff_part2_abs = vabsq_s32(diff_part2);
+        
+        sad_vector_temp = vaddq_s32(diff_part1_abs, diff_part2_abs);
+        sad_vector = vaddq_s32(sad_vector, sad_vector_temp);
+    }    
+    { // Row 7
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+        
+        diff_part1 = vsubl_s16(vget_low_s16(s1_vector), vget_low_s16(s2_vector));
+        diff_part2 = vsubl_high_s16(s1_vector, s2_vector);
+
+        diff_part1_abs = vabsq_s32(diff_part1);
+        diff_part2_abs = vabsq_s32(diff_part2);
+        
+        sad_vector_temp = vaddq_s32(diff_part1_abs, diff_part2_abs);
+        sad_vector = vaddq_s32(sad_vector, sad_vector_temp);
+    }
+    // Adding all the elments in sad vector
+    sad = vaddvq_s32(sad_vector);
+    return sad;
+}
+
+const oapv_fn_sad_t oapv_tbl_fn_sad_16b_neon[2] = {
+    sad_16b_neon_8x2n,
+    NULL
+};
+
 /* SSD ***********************************************************************/
-static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int bit_depth)
+static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, int s_src2)
 {
     s64 ssd = 0;
     s16* s1 = (s16*) src1;
@@ -45,8 +187,8 @@ static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, in
     int32x4_t diff1, diff2;
     int32x2_t diff1_low, diff2_low;
     int64x2_t sq_diff1_low, sq_diff1_high, sq_diff2_low, sq_diff2_high, sq_diff;
-    
-    {
+    // Loop unrolling      
+    { // Row 0
         s1_vector = vld1q_s16(s1);
         s1 += s_src1;
         s2_vector = vld1q_s16(s2);
@@ -66,7 +208,7 @@ static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, in
         sq_diff = vaddq_s64(sq_diff, sq_diff2_low);
         sq_diff = vaddq_s64(sq_diff, sq_diff2_high);
     }
-    {
+    { // Row 1
         s1_vector = vld1q_s16(s1);
         s1 += s_src1;
         s2_vector = vld1q_s16(s2);
@@ -87,7 +229,7 @@ static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, in
         sq_diff = vaddq_s64(sq_diff, sq_diff2_low);
         sq_diff = vaddq_s64(sq_diff, sq_diff2_high);
     }
-    {
+    { // Row 2
         s1_vector = vld1q_s16(s1);
         s1 += s_src1;
         s2_vector = vld1q_s16(s2);
@@ -108,7 +250,7 @@ static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, in
         sq_diff = vaddq_s64(sq_diff, sq_diff2_low);
         sq_diff = vaddq_s64(sq_diff, sq_diff2_high);
     }
-    {
+    { // Row 3
         s1_vector = vld1q_s16(s1);
         s1 += s_src1;
         s2_vector = vld1q_s16(s2);
@@ -129,7 +271,7 @@ static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, in
         sq_diff = vaddq_s64(sq_diff, sq_diff2_low);
         sq_diff = vaddq_s64(sq_diff, sq_diff2_high);
     }
-    {
+    { // Row 4
         s1_vector = vld1q_s16(s1);
         s1 += s_src1;
         s2_vector = vld1q_s16(s2);
@@ -150,7 +292,7 @@ static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, in
         sq_diff = vaddq_s64(sq_diff, sq_diff2_low);
         sq_diff = vaddq_s64(sq_diff, sq_diff2_high);
     }
-    {
+    { // Row 5
         s1_vector = vld1q_s16(s1);
         s1 += s_src1;
         s2_vector = vld1q_s16(s2);
@@ -171,7 +313,7 @@ static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, in
         sq_diff = vaddq_s64(sq_diff, sq_diff2_low);
         sq_diff = vaddq_s64(sq_diff, sq_diff2_high);
     }
-    {
+    { // Row 6
         s1_vector = vld1q_s16(s1);
         s1 += s_src1;
         s2_vector = vld1q_s16(s2);
@@ -192,7 +334,7 @@ static s64 ssd_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, in
         sq_diff = vaddq_s64(sq_diff, sq_diff2_low);
         sq_diff = vaddq_s64(sq_diff, sq_diff2_high);
     }
-    {
+    { // Row 7
         s1_vector = vld1q_s16(s1);
         s1 += s_src1;
         s2_vector = vld1q_s16(s2);
@@ -222,6 +364,109 @@ const oapv_fn_ssd_t oapv_tbl_fn_ssd_16b_neon[2] =
         ssd_16b_neon_8x8,
             NULL};
 
+/* DIFF **********************************************************************/
+static void diff_16b_neon_8x8(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int s_diff, s16 *diff)
+{
+    s16* s1 = (s16*) src1;
+    s16* s2 = (s16*) src2;
+    int16x8_t s1_vector, s2_vector, diff_vector;
+    // Loop unrolled    
+    { // Row 0
+        // Loading one row (8 elements) each of src1 and src_2
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+
+        // Subtracting s1_vector from s2_vector
+        diff_vector = vsubq_s16(s1_vector, s2_vector);
+
+        // Storing the result in diff
+        vst1q_s16(diff, diff_vector);
+        diff += s_diff;
+    }    
+    { // Row 1
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+
+        diff_vector = vsubq_s16(s1_vector, s2_vector);
+
+        vst1q_s16(diff, diff_vector);
+        diff += s_diff;
+    }    
+    { // Row 2
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+
+        diff_vector = vsubq_s16(s1_vector, s2_vector);
+
+        vst1q_s16(diff, diff_vector);
+        diff += s_diff;
+    }   
+    { // Row 3
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+
+        diff_vector = vsubq_s16(s1_vector, s2_vector);
+
+        vst1q_s16(diff, diff_vector);
+        diff += s_diff;
+    }    
+    { // Row 4
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+
+        diff_vector = vsubq_s16(s1_vector, s2_vector);
+
+        vst1q_s16(diff, diff_vector);
+        diff += s_diff;
+    }    
+    { // Row 5
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+
+        diff_vector = vsubq_s16(s1_vector, s2_vector);
+
+        vst1q_s16(diff, diff_vector);
+        diff += s_diff;
+    }    
+    { // Row 6
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+
+        diff_vector = vsubq_s16(s1_vector, s2_vector);
+
+        vst1q_s16(diff, diff_vector);
+        diff += s_diff;
+    }    
+    { // Row 7
+        s1_vector = vld1q_s16(s1);
+        s1 += s_src1;
+        s2_vector = vld1q_s16(s2);
+        s2 += s_src2;
+
+        diff_vector = vsubq_s16(s1_vector, s2_vector);
+
+        vst1q_s16(diff, diff_vector);
+        diff += s_diff;
+    }
+}
+const oapv_fn_diff_t oapv_tbl_fn_diff_16b_neon[2] = {
+    diff_16b_neon_8x8,
+    NULL
+};
 
 int oapv_dc_removed_had8x8_neon(pel* org, int s_org)
 {
diff --git a/src/neon/oapv_sad_neon.h b/src/neon/oapv_sad_neon.h
index bde968e..addb9f0 100644
--- a/src/neon/oapv_sad_neon.h
+++ b/src/neon/oapv_sad_neon.h
@@ -36,7 +36,9 @@
 #include "oapv_sad.h"
 
 #if ARM_NEON
+extern const oapv_fn_sad_t oapv_tbl_fn_sad_16b_neon[2];
 extern const oapv_fn_ssd_t oapv_tbl_fn_ssd_16b_neon[2];
+extern const oapv_fn_diff_t oapv_tbl_fn_diff_16b_neon[2];
 
 int oapv_dc_removed_had8x8_neon(pel* org, int s_org);
 #endif /* ARM_NEON */
diff --git a/src/oapv.c b/src/oapv.c
index e6c211b..a797c6d 100644
--- a/src/oapv.c
+++ b/src/oapv.c
@@ -217,6 +217,23 @@ static void copy_fi_to_finfo(oapv_fi_t *fi, int pbu_type, int group_id, oapv_frm
     finfo->capture_time_distance = fi->capture_time_distance;
 }
 
+static void copy_fh_to_finfo(oapv_fh_t *fh, int pbu_type, int group_id, oapv_frm_info_t *finfo)
+{
+    copy_fi_to_finfo(&fh->fi, pbu_type, group_id, finfo);
+    finfo->use_q_matrix = fh->use_q_matrix;
+    for(int c = 0; c < OAPV_MAX_CC; c++) {
+        int mod = (1 << OAPV_LOG2_BLK) - 1;
+        for(int i = 0; i < OAPV_BLK_D; i++) {
+            finfo->q_matrix[c][i] = fh->q_matrix[c][i >> OAPV_LOG2_BLK][i & mod];
+        }
+    }
+    finfo->color_description_present_flag = fh->color_description_present_flag;
+    finfo->color_primaries = fh->color_primaries;
+    finfo->transfer_characteristics = fh->transfer_characteristics;
+    finfo->matrix_coefficients = fh->matrix_coefficients;
+    finfo->full_range_flag = fh->full_range_flag;
+}
+
 ///////////////////////////////////////////////////////////////////////////////
 // start of encoder code
 #if ENABLE_ENCODER
@@ -301,13 +318,11 @@ static double enc_block(oapve_ctx_t *ctx, oapve_core_t *core, int log2_w, int lo
     oapv_trans(ctx, core->coef, log2_w, log2_h, bit_depth);
     ctx->fn_quant[0](core->coef, core->qp[c], core->q_mat_enc[c], log2_w, log2_h, bit_depth, c ? 128 : 212);
 
-    int prev_dc = core->prev_dc[c];
+    core->dc_diff = core->coef[0] - core->prev_dc[c];
     core->prev_dc[c] = core->coef[0];
-    core->coef[0] = core->coef[0] - prev_dc;
 
     if(ctx->rec) {
         oapv_mcpy(core->coef_rec, core->coef, sizeof(s16) * OAPV_BLK_D);
-        core->coef_rec[0] = core->coef_rec[0] + prev_dc;
         ctx->fn_dquant[0](core->coef_rec, core->q_mat_dec[c], log2_w, log2_h, core->dq_shift[c]);
         ctx->fn_itx[0](core->coef_rec, ITX_SHIFT1, ITX_SHIFT2(bit_depth), 1 << log2_w);
     }
@@ -340,7 +355,7 @@ static double enc_block_rdo_slow(oapve_ctx_t *ctx, oapve_core_t *core, int log2_
         oapv_mcpy(recon, coeff, sizeof(s16) * OAPV_BLK_D);
         ctx->fn_dquant[0](recon, core->q_mat_dec[c], log2_w, log2_h, core->dq_shift[c]);
         ctx->fn_itx[0](recon, ITX_SHIFT1, ITX_SHIFT2(bit_depth), 1 << log2_w);
-        int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w, bit_depth);
+        int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w);
         oapv_mcpy(best_coeff, coeff, sizeof(s16) * OAPV_BLK_D);
         if(ctx->rec) {
             oapv_mcpy(best_recon, recon, sizeof(s16) * OAPV_BLK_D);
@@ -384,7 +399,7 @@ static double enc_block_rdo_slow(oapve_ctx_t *ctx, oapve_core_t *core, int log2_
                 oapv_mcpy(recon, coeff, sizeof(s16) * OAPV_BLK_D);
                 ctx->fn_dquant[0](recon, core->q_mat_dec[c], log2_w, log2_h, core->dq_shift[c]);
                 ctx->fn_itx[0](recon, ITX_SHIFT1, ITX_SHIFT2(bit_depth), 1 << log2_w);
-                int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w, bit_depth);
+                int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w);
 
                 if(cost < best_cost) {
                     best_cost = cost;
@@ -404,9 +419,8 @@ static double enc_block_rdo_slow(oapve_ctx_t *ctx, oapve_core_t *core, int log2_
         }
     }
 
-    int curr_dc = best_coeff[0];
-    best_coeff[0] -= core->prev_dc[c];
-    core->prev_dc[c] = curr_dc;
+    core->dc_diff = best_coeff[0] - core->prev_dc[c];
+    core->prev_dc[c] = best_coeff[0];
 
     return best_cost;
 }
@@ -446,7 +460,7 @@ static double enc_block_rdo_medium(oapve_ctx_t *ctx, oapve_core_t *core, int log
         ctx->fn_itx_part[0](recon, tmp_buf, ITX_SHIFT1, 1 << log2_w);
         oapv_itx_get_wo_sft(tmp_buf, recon, rec_ups, ITX_SHIFT2(bit_depth), 1 << log2_h);
 
-        int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w, bit_depth);
+        int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w);
         oapv_mcpy(best_coeff, coeff, sizeof(s16) * OAPV_BLK_D);
         if(ctx->rec) {
             oapv_mcpy(best_recon, recon, sizeof(s16) * OAPV_BLK_D);
@@ -499,7 +513,7 @@ static double enc_block_rdo_medium(oapve_ctx_t *ctx, oapve_core_t *core, int log
                     recon[k] = (rec_tmp[k] + 512) >> 10;
                 }
 
-                int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w, bit_depth);
+                int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w);
                 if(cost < best_cost) {
                     oapv_mcpy(rec_ups, rec_tmp, sizeof(int) * OAPV_BLK_D);
                     best_cost = cost;
@@ -522,9 +536,8 @@ static double enc_block_rdo_medium(oapve_ctx_t *ctx, oapve_core_t *core, int log
         ctx->fn_itx[0](best_recon, ITX_SHIFT1, ITX_SHIFT2(bit_depth), 1 << log2_w);
     }
 
-    int curr_dc = best_coeff[0];
-    best_coeff[0] -= core->prev_dc[c];
-    core->prev_dc[c] = curr_dc;
+    core->dc_diff = best_coeff[0] - core->prev_dc[c];
+    core->prev_dc[c] = best_coeff[0];
 
     return best_cost;
 }
@@ -555,7 +568,7 @@ static double enc_block_rdo_placebo(oapve_ctx_t *ctx, oapve_core_t *core, int lo
         oapv_mcpy(recon, coeff, sizeof(s16) * OAPV_BLK_D);
         ctx->fn_dquant[0](recon, core->q_mat_dec[c], log2_w, log2_h, core->dq_shift[c]);
         ctx->fn_itx[0](recon, ITX_SHIFT1, ITX_SHIFT2(bit_depth), 1 << log2_w);
-        int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w, bit_depth);
+        int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w);
         oapv_mcpy(best_coeff, coeff, sizeof(s16) * OAPV_BLK_D);
         if(ctx->rec) {
             oapv_mcpy(best_recon, recon, sizeof(s16) * OAPV_BLK_D);
@@ -599,7 +612,7 @@ static double enc_block_rdo_placebo(oapve_ctx_t *ctx, oapve_core_t *core, int lo
                 oapv_mcpy(recon, coeff, sizeof(s16) * OAPV_BLK_D);
                 ctx->fn_dquant[0](recon, core->q_mat_dec[c], log2_w, log2_h, core->dq_shift[c]);
                 ctx->fn_itx[0](recon, ITX_SHIFT1, ITX_SHIFT2(bit_depth), 1 << log2_w);
-                int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w, bit_depth);
+                int cost = (int)ctx->fn_ssd[0](blk_w, blk_h, org, recon, blk_w, blk_w);
 
                 if(cost < best_cost) {
                     best_cost = cost;
@@ -619,9 +632,8 @@ static double enc_block_rdo_placebo(oapve_ctx_t *ctx, oapve_core_t *core, int lo
         }
     }
 
-    int curr_dc = best_coeff[0];
-    best_coeff[0] -= core->prev_dc[c];
-    core->prev_dc[c] = curr_dc;
+    core->dc_diff = best_coeff[0] - core->prev_dc[c];
+    core->prev_dc[c] = best_coeff[0];
 
     return best_cost;
 }
@@ -630,36 +642,40 @@ static int enc_read_param(oapve_ctx_t *ctx, oapve_param_t *param)
 {
     /* check input parameters */
     oapv_assert_rv(param->w > 0 && param->h > 0, OAPV_ERR_INVALID_ARGUMENT);
-    oapv_assert_rv(param->qp >= MIN_QUANT && param->qp <= MAX_QUANT, OAPV_ERR_INVALID_ARGUMENT);
+    oapv_assert_rv(param->qp >= MIN_QUANT && param->qp <= MAX_QUANT(10), OAPV_ERR_INVALID_ARGUMENT);
 
-    ctx->qp[Y_C] = param->qp;
-    ctx->qp[U_C] = param->qp + param->qp_cb_offset;
-    ctx->qp[V_C] = param->qp + param->qp_cr_offset;
-    ctx->qp[X_C] = param->qp;
+    ctx->qp_offset[Y_C] = 0;
+    ctx->qp_offset[U_C] = param->qp_offset_c1;
+    ctx->qp_offset[V_C] = param->qp_offset_c2;
+    ctx->qp_offset[X_C] = param->qp_offset_c3;
 
     ctx->num_comp = get_num_comp(param->csp);
 
-    if(param->preset == OAPV_PRESET_SLOW) {
-        ctx->fn_block = enc_block_rdo_slow;
+    for(int i = 0; i < ctx->num_comp; i++) {
+        ctx->qp[i] = oapv_clip3(MIN_QUANT, MAX_QUANT(10), param->qp + ctx->qp_offset[i]);
     }
-    else if(param->preset == OAPV_PRESET_PLACEBO) {
-        ctx->fn_block = enc_block_rdo_placebo;
+
+    if(param->preset == OAPV_PRESET_PLACEBO) {
+        ctx->fn_enc_blk = enc_block_rdo_placebo;
+    }
+    else if(param->preset == OAPV_PRESET_SLOW) {
+        ctx->fn_enc_blk = enc_block_rdo_slow;
     }
     else if(param->preset == OAPV_PRESET_MEDIUM) {
-        ctx->fn_block = enc_block_rdo_medium;
+        ctx->fn_enc_blk = enc_block_rdo_medium;
     }
     else {
-        ctx->fn_block = enc_block;
+        ctx->fn_enc_blk = enc_block;
     }
 
     ctx->log2_block = OAPV_LOG2_BLK;
 
     /* set various value */
-    ctx->w = ((ctx->param->w + (OAPV_MB_W - 1)) >> OAPV_LOG2_MB_W) << OAPV_LOG2_MB_W;
-    ctx->h = ((ctx->param->h + (OAPV_MB_H - 1)) >> OAPV_LOG2_MB_H) << OAPV_LOG2_MB_H;
+    ctx->w = ((param->w + (OAPV_MB_W - 1)) >> OAPV_LOG2_MB_W) << OAPV_LOG2_MB_W;
+    ctx->h = ((param->h + (OAPV_MB_H - 1)) >> OAPV_LOG2_MB_H) << OAPV_LOG2_MB_H;
 
-    int tile_w = ctx->param->tile_w_mb * OAPV_MB_W;
-    int tile_h = ctx->param->tile_h_mb * OAPV_MB_H;
+    int tile_w = param->tile_w_mb * OAPV_MB_W;
+    int tile_h = param->tile_h_mb * OAPV_MB_H;
     enc_set_tile_info(ctx->tile, ctx->w, ctx->h, tile_w, tile_h, &ctx->num_tile_cols, &ctx->num_tile_rows, &ctx->num_tiles);
 
     return OAPV_OK;
@@ -762,16 +778,16 @@ static int enc_tile_comp(oapv_bs_t *bs, oapve_tile_t *tile, oapve_ctx_t *ctx, oa
             for(blk_y = mb_y; blk_y < (mb_y + mb_h); blk_y += OAPV_BLK_H) {
                 for(blk_x = mb_x; blk_x < (mb_x + mb_w); blk_x += OAPV_BLK_W) {
                     o16 = (s16 *)((u8 *)org + blk_y * s_org) + blk_x;
-                    ctx->fn_imgb_to_block[c](o16, OAPV_BLK_W, OAPV_BLK_H, s_org, blk_x, (OAPV_BLK_W << 1), core->coef);
+                    ctx->fn_imgb_to_blk[c](o16, OAPV_BLK_W, OAPV_BLK_H, s_org, blk_x, (OAPV_BLK_W << 1), core->coef);
 
-                    ctx->fn_block(ctx, core, OAPV_LOG2_BLK_W, OAPV_LOG2_BLK_H, c);
-                    oapve_vlc_dc_coeff(ctx, core, bs, core->coef[0], c);
+                    ctx->fn_enc_blk(ctx, core, OAPV_LOG2_BLK_W, OAPV_LOG2_BLK_H, c);
+                    oapve_vlc_dc_coeff(ctx, core, bs, core->dc_diff, c);
                     oapve_vlc_ac_coeff(ctx, core, bs, core->coef, 0, c);
                     DUMP_COEF(core->coef, OAPV_BLK_D, blk_x, blk_y, c);
 
                     if(rec != NULL) {
                         r16 = (s16 *)((u8 *)rec + blk_y * s_rec) + blk_x;
-                        ctx->fn_block_to_imgb[c](core->coef_rec, OAPV_BLK_W, OAPV_BLK_H, (OAPV_BLK_W << 1), blk_x, s_rec, r16);
+                        ctx->fn_blk_to_imgb[c](core->coef_rec, OAPV_BLK_W, OAPV_BLK_H, (OAPV_BLK_W << 1), blk_x, s_rec, r16);
                     }
                 }
             }
@@ -795,9 +811,8 @@ static int enc_tile(oapve_ctx_t *ctx, oapve_core_t *core, oapve_tile_t *tile)
     oapv_bsw_init(&bs, tile->bs_buf, tile->bs_buf_max, NULL);
 
     int qp = 0;
-    if(ctx->param->rc_type != 0) {
+    if(ctx->param->rc_type != OAPV_RC_CQP) {
         oapve_rc_get_qp(ctx, tile, ctx->qp[Y_C], &qp);
-        oapv_assert(qp != 0);
     }
     else {
         qp = ctx->qp[Y_C];
@@ -820,7 +835,7 @@ static int enc_tile(oapve_ctx_t *ctx, oapve_core_t *core, oapve_tile_t *tile)
             }
         }
 
-        if(ctx->rec || ctx->param->preset > OAPV_PRESET_MEDIUM) {
+        if(ctx->rec || ctx->param->preset >= OAPV_PRESET_MEDIUM) {
             core->dq_shift[c] = ctx->bit_depth - 2 - (core->qp[c] / 6);
 
             int cnt = 0;
@@ -1026,22 +1041,22 @@ static int enc_frm_prepare(oapve_ctx_t *ctx, oapv_imgb_t *imgb_i, oapv_imgb_t *i
     ctx->bit_depth = OAPV_CS_GET_BIT_DEPTH(imgb_i->cs);
 
     if(OAPV_CS_GET_FORMAT(imgb_i->cs) == OAPV_CF_PLANAR2) {
-        ctx->fn_imgb_to_block_rc = imgb_to_block_p210;
+        ctx->fn_imgb_to_blk_rc = imgb_to_block_p210;
 
-        ctx->fn_imgb_to_block[Y_C] = imgb_to_block_p210_y;
-        ctx->fn_imgb_to_block[U_C] = imgb_to_block_p210_uv;
-        ctx->fn_imgb_to_block[V_C] = imgb_to_block_p210_uv;
+        ctx->fn_imgb_to_blk[Y_C] = imgb_to_block_p210_y;
+        ctx->fn_imgb_to_blk[U_C] = imgb_to_block_p210_uv;
+        ctx->fn_imgb_to_blk[V_C] = imgb_to_block_p210_uv;
 
-        ctx->fn_block_to_imgb[Y_C] = block_to_imgb_p210_y;
-        ctx->fn_block_to_imgb[U_C] = block_to_imgb_p210_uv;
-        ctx->fn_block_to_imgb[V_C] = block_to_imgb_p210_uv;
+        ctx->fn_blk_to_imgb[Y_C] = block_to_imgb_p210_y;
+        ctx->fn_blk_to_imgb[U_C] = block_to_imgb_p210_uv;
+        ctx->fn_blk_to_imgb[V_C] = block_to_imgb_p210_uv;
         ctx->fn_img_pad = enc_img_pad_p210;
     }
     else {
-        ctx->fn_imgb_to_block_rc = imgb_to_block;
+        ctx->fn_imgb_to_blk_rc = imgb_to_block;
         for(int i = 0; i < ctx->num_comp; i++) {
-            ctx->fn_imgb_to_block[i] = imgb_to_block_10bit;
-            ctx->fn_block_to_imgb[i] = block_to_imgb_10bit;
+            ctx->fn_imgb_to_blk[i] = imgb_to_block_10bit;
+            ctx->fn_blk_to_imgb[i] = block_to_imgb_10bit;
         }
         ctx->fn_img_pad = enc_img_pad;
     }
@@ -1112,7 +1127,7 @@ static int enc_frame(oapve_ctx_t *ctx)
 
     /* rc init */
     u64 cost_sum = 0;
-    if(ctx->param->rc_type != 0) {
+    if(ctx->param->rc_type != OAPV_RC_CQP) {
         oapve_rc_get_tile_cost_thread(ctx, &cost_sum);
 
         double bits_pic = ((double)ctx->param->bitrate * 1000) / ((double)ctx->param->fps_num / ctx->param->fps_den);
@@ -1123,14 +1138,9 @@ static int enc_frame(oapve_ctx_t *ctx)
 
         ctx->rc_param.lambda = oapve_rc_estimate_pic_lambda(ctx, cost_sum);
         ctx->rc_param.qp = oapve_rc_estimate_pic_qp(ctx->rc_param.lambda);
+
         for(int c = 0; c < ctx->num_comp; c++) {
-            ctx->qp[c] = ctx->rc_param.qp;
-            if(c == 1) {
-                ctx->qp[c] += ctx->param->qp_cb_offset;
-            }
-            else if(c == 2) {
-                ctx->qp[c] += ctx->param->qp_cr_offset;
-            }
+            ctx->qp[c] = oapv_clip3(MIN_QUANT, MAX_QUANT(10), ctx->rc_param.qp + ctx->qp_offset[c]);
         }
     }
 
@@ -1162,6 +1172,8 @@ static int enc_frame(oapve_ctx_t *ctx)
     /* rewrite frame header */
     if(ctx->fh.tile_size_present_in_fh_flag) {
         oapve_vlc_frame_header(&bs_fh, ctx, &ctx->fh);
+        /* de-init BSW */
+        oapv_bsw_sink(&bs_fh);
     }
     if(ctx->param->rc_type != 0) {
         oapve_rc_update_after_pic(ctx, cost_sum);
@@ -1193,7 +1205,9 @@ static int enc_platform_init(oapve_ctx_t *ctx)
     support_avx2 = (check_cpu >> 2) & 1;
 
     if(support_avx2) {
+        ctx->fn_sad = oapv_tbl_fn_sad_16b_avx;
         ctx->fn_ssd = oapv_tbl_fn_ssd_16b_avx;
+        ctx->fn_diff = oapv_tbl_fn_diff_16b_avx;
         ctx->fn_itx_part = oapv_tbl_fn_itx_part_avx;
         ctx->fn_itx = oapv_tbl_fn_itx_avx;
         ctx->fn_itx_adj = oapv_tbl_fn_itx_adj_avx;
@@ -1207,7 +1221,9 @@ static int enc_platform_init(oapve_ctx_t *ctx)
         ctx->fn_had8x8 = oapv_dc_removed_had8x8_sse;
     }
 #elif ARM_NEON
+    ctx->fn_sad = oapv_tbl_fn_sad_16b_neon;
     ctx->fn_ssd = oapv_tbl_fn_ssd_16b_neon;
+    ctx->fn_diff = oapv_tbl_fn_diff_16b_neon;
     ctx->fn_itx = oapv_tbl_fn_itx_neon;
     ctx->fn_txb = oapv_tbl_fn_txb_neon;
     ctx->fn_quant = oapv_tbl_fn_quant_neon;
@@ -1285,6 +1301,8 @@ int oapve_encode(oapve_t eid, oapv_frms_t *ifrms, oapvm_t mid, oapv_bitb_t *bitb
     oapv_bs_t bs_pbu_beg;
     oapv_bsw_write(bs, 0, 32);
 
+    oapv_bsw_write(bs, 0x61507631, 32); // signature ('aPv1')
+
     for(i = 0; i < ifrms->num_frms; i++) {
         frm = &ifrms->frm[i];
 
@@ -1317,7 +1335,7 @@ int oapve_encode(oapve_t eid, oapv_frms_t *ifrms, oapvm_t mid, oapv_bitb_t *bitb
         DUMP_LOAD(1);
 
         stat->frm_size[i] = pbu_size + 4 /* PUB size length*/;
-        copy_fi_to_finfo(&ctx->fh.fi, frm->pbu_type, frm->group_id, &stat->aui.frm_info[i]);
+        copy_fh_to_finfo(&ctx->fh, frm->pbu_type, frm->group_id, &stat->aui.frm_info[i]);
 
         // add frame hash value of reconstructed frame into metadata list
         if(ctx->use_frm_hash) {
@@ -1379,7 +1397,7 @@ int oapve_config(oapve_t eid, int cfg, void *buf, int *size)
     case OAPV_CFG_SET_QP:
         oapv_assert_rv(*size == sizeof(int), OAPV_ERR_INVALID_ARGUMENT);
         t0 = *((int *)buf);
-        oapv_assert_rv(t0 >= MIN_QUANT && t0 <= MAX_QUANT,
+        oapv_assert_rv(t0 >= MIN_QUANT && t0 <= MAX_QUANT(10),
                        OAPV_ERR_INVALID_ARGUMENT);
         ctx->param->qp = t0;
         break;
@@ -1443,16 +1461,31 @@ int oapve_param_default(oapve_param_t *param)
     oapv_mset(param, 0, sizeof(oapve_param_t));
     param->preset = OAPV_PRESET_DEFAULT;
 
-    param->qp_cb_offset = 0;
-    param->qp_cr_offset = 0;
+    param->qp_offset_c1 = 0;
+    param->qp_offset_c2 = 0;
+    param->qp_offset_c3 = 0;
 
     param->tile_w_mb = 16;
     param->tile_h_mb = 16;
 
     param->profile_idc = OAPV_PROFILE_422_10;
-    param->level_idc = (int)(4.1 * 30);
+    param->level_idc = (int)((4.1 * 30.0) + 0.5);
     param->band_idc = 2;
 
+    param->use_q_matrix = 0;
+
+    param->color_description_present_flag = 0;
+    param->color_primaries = 2; // unspecified color primaries
+    param->transfer_characteristics = 2; // unspecified transfer characteristics
+    param->matrix_coefficients = 2; // unspecified matrix coefficients
+    param->full_range_flag = 0; // limited range
+
+    for(int c = 0; c < OAPV_MAX_CC; c++) {
+        for(int i = 0; i < OAPV_BLK_D; i++) {
+            param->q_matrix[c][i] = 16;
+        }
+    }
+
     return OAPV_OK;
 }
 
@@ -1513,7 +1546,7 @@ static int dec_block(oapvd_ctx_t *ctx, oapvd_core_t *core, int log2_w, int log2_
     int bit_depth = ctx->bit_depth;
 
     // DC prediction
-    core->coef[0] += core->prev_dc[c];
+    core->coef[0] = core->dc_diff + core->prev_dc[c];
     core->prev_dc[c] = core->coef[0];
     // Inverse quantization
     ctx->fn_dquant[0](core->coef, core->q_mat[c], log2_w, log2_h, core->dq_shift[c]);
@@ -1617,7 +1650,7 @@ static int dec_tile_comp(oapvd_tile_t *tile, oapvd_ctx_t *ctx, oapvd_core_t *cor
             for(blk_y = mb_y; blk_y < (mb_y + mb_h); blk_y += OAPV_BLK_H) {
                 for(blk_x = mb_x; blk_x < (mb_x + mb_w); blk_x += OAPV_BLK_W) {
                     // parse DC coefficient
-                    ret = oapvd_vlc_dc_coeff(ctx, core, bs, &core->coef[0], c);
+                    ret = oapvd_vlc_dc_coeff(ctx, core, bs, &core->dc_diff, c);
                     oapv_assert_rv(OAPV_SUCCEEDED(ret), ret);
 
                     // parse AC coefficient
@@ -1916,26 +1949,29 @@ int oapvd_decode(oapvd_t did, oapv_bitb_t *bitb, oapv_frms_t *ofrms, oapvm_t mid
     oapv_pbuh_t  pbuh;
     int          ret = OAPV_OK;
     u32          pbu_size;
-    u32          remain;
-    u8          *curpos;
+    u32          cur_read_size = 0;
     int          frame_cnt = 0;
 
     ctx = dec_id_to_ctx(did);
     oapv_assert_rv(ctx, OAPV_ERR_INVALID_ARGUMENT);
 
-    curpos = (u8 *)bitb->addr;
-    remain = bitb->ssize;
-
-    while(remain > 8) {
-        oapv_bsr_init(&ctx->bs, curpos, remain, NULL);
+    // read signature ('aPv1')
+    oapv_assert_rv(bitb->ssize > 4, OAPV_ERR_MALFORMED_BITSTREAM);
+    u32 signature = oapv_bsr_read_direct(bitb->addr, 32);
+    oapv_assert_rv(signature == 0x61507631, OAPV_ERR_MALFORMED_BITSTREAM);
+    cur_read_size += 4;
+    stat->read += 4;
+
+    do {
+        u32 remain = bitb->ssize - cur_read_size;
+        oapv_assert_gv((remain >= 8), ret, OAPV_ERR_MALFORMED_BITSTREAM, ERR);
+        oapv_bsr_init(&ctx->bs, (u8 *)bitb->addr + cur_read_size, remain, NULL);
         bs = &ctx->bs;
 
-        ret = oapvd_vlc_pbu_size(bs, &pbu_size); // 4byte
+        ret = oapvd_vlc_pbu_size(bs, &pbu_size); // read pbu_size (4 byte)
         oapv_assert_g(OAPV_SUCCEEDED(ret), ERR);
-        oapv_assert_g((pbu_size + 4) <= bs->size, ERR);
-
-        curpos += 4; // pbu_size syntax
-        remain -= 4;
+        remain -= 4; // size of pbu_size syntax
+        oapv_assert_gv(pbu_size <= remain, ret, OAPV_ERR_MALFORMED_BITSTREAM, ERR);
 
         ret = oapvd_vlc_pbu_header(bs, &pbuh);
         oapv_assert_g(OAPV_SUCCEEDED(ret), ERR);
@@ -1945,6 +1981,9 @@ int oapvd_decode(oapvd_t did, oapv_bitb_t *bitb, oapv_frms_t *ofrms, oapvm_t mid
            pbuh.pbu_type == OAPV_PBU_TYPE_PREVIEW_FRAME ||
            pbuh.pbu_type == OAPV_PBU_TYPE_DEPTH_FRAME ||
            pbuh.pbu_type == OAPV_PBU_TYPE_ALPHA_FRAME) {
+
+            oapv_assert_gv(frame_cnt < OAPV_MAX_NUM_FRAMES, ret, OAPV_ERR_REACHED_MAX, ERR);
+
             ret = oapvd_vlc_frame_header(bs, &ctx->fh);
             oapv_assert_g(OAPV_SUCCEEDED(ret), ERR);
 
@@ -1975,9 +2014,9 @@ int oapvd_decode(oapvd_t did, oapv_bitb_t *bitb, oapv_frms_t *ofrms, oapvm_t mid
             /* READ FILLER HERE !!! */
 
             oapv_bsr_move(&ctx->bs, ctx->tile_end);
-            stat->read += bsr_get_read_byte(&ctx->bs);
+            stat->read += BSR_GET_READ_BYTE(&ctx->bs);
 
-            copy_fi_to_finfo(&ctx->fh.fi, pbuh.pbu_type, pbuh.group_id, &stat->aui.frm_info[frame_cnt]);
+            copy_fh_to_finfo(&ctx->fh, pbuh.pbu_type, pbuh.group_id, &stat->aui.frm_info[frame_cnt]);
             if(ret == OAPV_OK && ctx->use_frm_hash) {
                 oapv_imgb_set_md5(ctx->imgb);
             }
@@ -1993,17 +2032,16 @@ int oapvd_decode(oapvd_t did, oapv_bitb_t *bitb, oapv_frms_t *ofrms, oapvm_t mid
             ret = oapvd_vlc_metadata(bs, pbu_size, mid, pbuh.group_id);
             oapv_assert_g(OAPV_SUCCEEDED(ret), ERR);
 
-            stat->read += bsr_get_read_byte(&ctx->bs);
+            stat->read += BSR_GET_READ_BYTE(&ctx->bs);
         }
         else if(pbuh.pbu_type == OAPV_PBU_TYPE_FILLER) {
             ret = oapvd_vlc_filler(bs, (pbu_size - 4));
             oapv_assert_g(OAPV_SUCCEEDED(ret), ERR);
         }
-        curpos += pbu_size;
-        remain = (remain < pbu_size)? 0: (remain - pbu_size);
-    }
+        cur_read_size += pbu_size + 4;
+    } while(cur_read_size < bitb->ssize);
     stat->aui.num_frms = frame_cnt;
-    oapv_assert_rv(ofrms->num_frms == frame_cnt, OAPV_ERR_MALFORMED_BITSTREAM);
+    oapv_assert_gv(ofrms->num_frms == frame_cnt, ret, OAPV_ERR_MALFORMED_BITSTREAM, ERR);
     return ret;
 
 ERR:
@@ -2032,29 +2070,32 @@ int oapvd_config(oapvd_t did, int cfg, void *buf, int *size)
 int oapvd_info(void *au, int au_size, oapv_au_info_t *aui)
 {
     int ret, frm_count = 0;
-    int pbu_cnt = 0;
-    u8 *curpos;
-    u32 remain;
-
-    curpos = (u8 *)au;
-    remain = au_size;
+    u32 cur_read_size = 0;
 
     DUMP_SET(0);
-    while(remain > 8) // FIX-ME (8byte?)
-    {
-        oapv_bs_t bs;
-        u32       pbu_size = 0;
 
-        oapv_bsr_init(&bs, curpos, remain, NULL);
+    // read signature ('aPv1')
+    oapv_assert_rv(au_size > 4, OAPV_ERR_MALFORMED_BITSTREAM);
+    u32 signature = oapv_bsr_read_direct(au, 32);
+    oapv_assert_rv(signature == 0x61507631, OAPV_ERR_MALFORMED_BITSTREAM);
+    cur_read_size += 4;
 
-        ret = oapvd_vlc_pbu_size(&bs, &pbu_size); // 4 byte
+    /* 'au' address contains series of PBU */
+    do {
+        oapv_bs_t bs;
+        u32 pbu_size = 0;
+        u32 remain = au_size - cur_read_size;
+        oapv_assert_rv((remain >= 8), OAPV_ERR_MALFORMED_BITSTREAM);
+        oapv_bsr_init(&bs, (u8 *)au + cur_read_size, remain, NULL);
+
+        ret = oapvd_vlc_pbu_size(&bs, &pbu_size); // read pbu_size (4 byte)
         oapv_assert_rv(OAPV_SUCCEEDED(ret), ret);
-        curpos += 4; // pbu_size syntax
-        remain -= 4;
+        remain -= 4; // size of pbu_size syntax
+        oapv_assert_rv(pbu_size <= remain, OAPV_ERR_MALFORMED_BITSTREAM);
 
         /* pbu header */
         oapv_pbuh_t pbuh;
-        ret = oapvd_vlc_pbu_header(&bs, &pbuh); // 4 byte
+        ret = oapvd_vlc_pbu_header(&bs, &pbuh); // read pbu_header() (4 byte)
         oapv_assert_rv(OAPV_SUCCEEDED(ret), OAPV_ERR_MALFORMED_BITSTREAM);
         if(pbuh.pbu_type == OAPV_PBU_TYPE_AU_INFO) {
             // parse access_unit_info in PBU
@@ -2085,11 +2126,8 @@ int oapvd_info(void *au, int au_size, oapv_au_info_t *aui)
             frm_count++;
         }
         aui->num_frms = frm_count;
-
-        curpos += pbu_size;
-        remain = (remain < pbu_size)? 0: (remain - pbu_size);
-        ++pbu_cnt;
-    }
+        cur_read_size += pbu_size + 4; /* 4byte is for pbu_size syntax itself */
+    } while(cur_read_size < au_size);
     DUMP_SET(1);
     return OAPV_OK;
 }
diff --git a/src/oapv_bs.c b/src/oapv_bs.c
index f9d068d..968a798 100644
--- a/src/oapv_bs.c
+++ b/src/oapv_bs.c
@@ -197,9 +197,8 @@ static int bsr_flush(oapv_bs_t *bs, int byte)
 
     bs->leftbits = byte << 3;
 
-    bs->cur += byte;
     while(byte) {
-        code |= *(bs->cur - byte) << shift;
+        code |= *(bs->cur++) << shift;
         byte--;
         shift -= 8;
     }
@@ -207,7 +206,7 @@ static int bsr_flush(oapv_bs_t *bs, int byte)
     return 0;
 }
 
-void oapv_bsr_init(oapv_bs_t *bs, u8 *buf, int size, oapv_bs_fn_flush_t fn_flush)
+void oapv_bsr_init(oapv_bs_t *bs, u8 *buf, u32 size, oapv_bs_fn_flush_t fn_flush)
 {
     bs->size = size;
     bs->cur = buf;
@@ -237,6 +236,17 @@ int oapv_bsr_clz_in_code(u32 code)
     return clz;
 }
 
+int oapv_bsr_clz(oapv_bs_t *bs)
+{
+    int clz;
+    u32 code;
+
+    code = oapv_bsr_peek(bs, 32);
+    oapv_assert(code != 0);
+    clz = oapv_bsr_clz_in_code(code);
+    return clz;
+}
+
 void oapv_bsr_align8(oapv_bs_t *bs)
 {
     /*
@@ -266,7 +276,7 @@ void oapv_bsr_skip(oapv_bs_t *bs, int size)
     bsr_skip_code(bs, size);
 }
 
-void oapv_bsr_peek(oapv_bs_t *bs, u32 *val, int size)
+u32 oapv_bsr_peek(oapv_bs_t *bs, int size)
 {
     int byte, leftbits;
     u32 code = 0;
@@ -302,7 +312,7 @@ void oapv_bsr_peek(oapv_bs_t *bs, u32 *val, int size)
             code |= *(bs->cur) >> (8 - size);
         }
     }
-    *val = code;
+    return code;
 }
 
 void *oapv_bsr_sink(oapv_bs_t *bs)
@@ -360,6 +370,26 @@ int oapv_bsr_read1(oapv_bs_t *bs)
     return code;
 }
 
+u32 oapv_bsr_read_direct(void *addr, int len)
+{
+    u32 code = 0;
+    int shift = 24;
+    u8 *p = (u8 *)addr;
+    int byte = (len + 7) >> 3;
+
+    oapv_assert(len <= 32);
+
+    while(byte) {
+        code |= *(p) << shift;
+        shift -= 8;
+        byte--;
+        p++;
+    }
+    code = code >> (32 - len);
+    return code;
+}
+
+
 ///////////////////////////////////////////////////////////////////////////////
 // end of decoder code
 #endif // ENABLE_DECODER
diff --git a/src/oapv_bs.h b/src/oapv_bs.h
index c7fcc0f..81ee317 100644
--- a/src/oapv_bs.h
+++ b/src/oapv_bs.h
@@ -81,32 +81,65 @@ int oapv_bsw_write(oapv_bs_t *bs, u32 val, int len);
 // start of decoder code
 #if ENABLE_DECODER
 ///////////////////////////////////////////////////////////////////////////////
-/*! is bitstream byte aligned? */
-static bool inline bsr_is_align8(oapv_bs_t *bs)
-{
-    return ((bs->leftbits & 0x7) == 0) ? true : false;
-}
+#if 0
+#if defined(X86F) || defined(ARMV8N_64)
+/* on X86 machine, 32-bit shift means remaining of original value, so we
+should set zero in that case. */
+#define BSR_SKIP_CODE(bs, size) \
+    oapv_assert((bs)->leftbits >= (size)); \
+    if((size) == 32) {(bs)->code = 0; (bs)->leftbits = 0;} \
+    else           {(bs)->code <<= (size); (bs)->leftbits -= (size);}
+#else
+#define BSR_SKIP_CODE(bs, size) \
+    oapv_assert((bs)->leftbits >= (size)); \
+    (bs)->code <<= (size); (bs)->leftbits -= (size);
+#endif
+#else
+#define BSR_SKIP_CODE(bs, size) \
+    oapv_assert((bs)->leftbits >= (size) && (size) <= 32); \
+    (bs)->code <<= (size); (bs)->leftbits -= (size);
+#endif
+
+/*! Is end of bitstream ? */
+#define BSR_IS_EOB(bs) (((bs)->cur > (bs)->end && (bs)->leftbits==0)? 1: 0)
+
+/*! Is bitstream byte aligned? */
+#define BSR_IS_BYTE_ALIGN(bs) ((((bs)->leftbits & 0x7) == 0)? 1: 0)
+
+/*! Is last byte of bitsteam? */
+#define BSR_IS_LAST_BYTE(bs) \
+    (((bs)->cur > (bs)->end && bs->leftbits > 0 && (bs)->leftbits <= 8)? 1: 0)
 
+/* get left byte count in BS */
+#define BSR_GET_LEFT_BYTE(bs) \
+    ((int)((bs)->end - (bs)->cur) + 1 + ((bs)->leftbits >> 3))
 /* get number of byte consumed */
-static int inline bsr_get_read_byte(oapv_bs_t *bs)
-{
-    return ((int)((bs)->cur - (bs)->beg) - ((bs)->leftbits >> 3));
-}
+#define BSR_GET_READ_BYTE(bs) \
+    ((int)((bs)->cur - (bs)->beg) - ((bs)->leftbits >> 3))
+/* get number of bit consumed */
+#define BSR_GET_READ_BIT(bs) \
+    (((int)((bs)->cur - (bs)->beg) << 3) - ((bs)->leftbits))
 
-static int inline bsr_get_remained_byte(oapv_bs_t *bs)
-{
-    return (bs->size - bsr_get_read_byte(bs));
-}
+/* get address of current reading */
+#define BSR_GET_CUR(bs) ((bs)->cur - (((bs)->leftbits + 7) >> 3))
+
+/* move to # bytes align position */
+#define BSR_MOVE_BYTE_ALIGN(bs, byte) \
+    (bs)->cur += (byte) - ((bs)->leftbits >> 3); \
+    (bs)->code = 0; \
+    (bs)->leftbits = 0;
 
-void oapv_bsr_init(oapv_bs_t *bs, u8 *buf, int size, oapv_bs_fn_flush_t fn_flush);
+void oapv_bsr_init(oapv_bs_t *bs, u8 *buf, u32 size, oapv_bs_fn_flush_t fn_flush);
 int oapv_bsr_clz_in_code(u32 code);
+int oapv_bsr_clz(oapv_bs_t *bs);
 void oapv_bsr_align8(oapv_bs_t *bs);
 void oapv_bsr_skip(oapv_bs_t *bs, int size);
-void oapv_bsr_peek(oapv_bs_t *bs, u32 *val, int size);
+u32 oapv_bsr_peek(oapv_bs_t *bs, int size);
 void *oapv_bsr_sink(oapv_bs_t *bs);
 void oapv_bsr_move(oapv_bs_t *bs, u8 *pos);
 u32 oapv_bsr_read(oapv_bs_t *bs, int size);
 int oapv_bsr_read1(oapv_bs_t *bs);
+u32 oapv_bsr_read_direct(void *addr, int len);
 
 ///////////////////////////////////////////////////////////////////////////////
 // end of decoder code
diff --git a/src/oapv_def.h b/src/oapv_def.h
index f6b1429..acb4f6f 100644
--- a/src/oapv_def.h
+++ b/src/oapv_def.h
@@ -51,7 +51,7 @@
 #define OAPVD_MAGIC_CODE          0x41503144 /* AP1D */
 
 /* Max. and min. Quantization parameter */
-#define MAX_QUANT                 63
+#define MAX_QUANT(BD)             (63 + ((BD-10)*6))
 #define MIN_QUANT                 0
 
 #define MAX_COST                  (1.7e+308) /* maximum cost value */
@@ -68,11 +68,6 @@
 #define OAPV_MIN_AC_LEVEL_CTX     0
 #define OAPV_MAX_AC_LEVEL_CTX     4
 
-/* need to check */
-#define OAPV_MAX_TILE_ROWS        20
-#define OAPV_MAX_TILE_COLS        20
-#define OAPV_MAX_TILES            (OAPV_MAX_TILE_ROWS * OAPV_MAX_TILE_COLS)
-
 /* Maximum transform dynamic range (excluding sign bit) */
 #define MAX_TX_DYNAMIC_RANGE      15
 #define MAX_TX_VAL                ((1 << MAX_TX_DYNAMIC_RANGE) - 1)
@@ -105,8 +100,8 @@ struct oapv_fi {     // 112byte
     int level_idc;   /* u( 8) */
     int band_idc;    /* u( 3) */
     // int            reserved_zero_5bits;                     /* u( 5) */
-    u32 frame_width;           /* u(32) */
-    u32 frame_height;          /* u(32) */
+    u32 frame_width;           /* u(24) */
+    u32 frame_height;          /* u(24) */
     int chroma_format_idc;     /* u( 4) */
     int bit_depth;             /* u( 4) */
     int capture_time_distance; /* u( 8) */
@@ -124,13 +119,14 @@ struct oapv_fh {
     int       color_primaries;                /* u( 8) */
     int       transfer_characteristics;       /* u( 8) */
     int       matrix_coefficients;            /* u( 8) */
+    int       full_range_flag;                /* u( 1) */
     int       use_q_matrix;                   /* u( 1) */
     /* (start) quantization_matix  */
-    int       q_matrix[N_C][OAPV_BLK_H][OAPV_BLK_W]; /* u( 8) minus 1*/
+    int       q_matrix[N_C][OAPV_BLK_H][OAPV_BLK_W]; /* u( 8) */
     /* ( end ) quantization_matix  */
     /* (start) tile_info */
-    int       tile_width_in_mbs;            /* u(28) minus 1*/
-    int       tile_height_in_mbs;           /* u(28) minus 1*/
+    int       tile_width_in_mbs;            /* u(20) */
+    int       tile_height_in_mbs;           /* u(20) */
     int       tile_size_present_in_fh_flag; /* u( 1) */
     u32       tile_size[OAPV_MAX_TILES];    /* u(32) */
     /* ( end ) tile_info  */
@@ -182,16 +178,16 @@ typedef void (*oapv_fn_tx_t)(s16 *coef, s16 *t, int shift, int line);
 typedef void (*oapv_fn_itx_adj_t)(int *src, int *dst, int itrans_diff_idx, int diff_step, int shift);
 typedef int (*oapv_fn_quant_t)(s16 *coef, u8 qp, int q_matrix[OAPV_BLK_D], int log2_w, int log2_h, int bit_depth, int deadzone_offset);
 typedef void (*oapv_fn_dquant_t)(s16 *coef, s16 q_matrix[OAPV_BLK_D], int log2_w, int log2_h, s8 shift);
-typedef int (*oapv_fn_sad_t)(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int bit_depth);
-typedef s64 (*oapv_fn_ssd_t)(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int bit_depth);
-typedef void (*oapv_fn_diff_t)(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int s_diff, s16 *diff, int bit_depth);
+typedef int (*oapv_fn_sad_t)(int w, int h, void *src1, void *src2, int s_src1, int s_src2);
+typedef s64 (*oapv_fn_ssd_t)(int w, int h, void *src1, void *src2, int s_src1, int s_src2);
+typedef void (*oapv_fn_diff_t)(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int s_diff, s16 *diff);
 
-typedef double (*oapv_fn_block_cost_t)(oapve_ctx_t *ctx, oapve_core_t *core, int log2_w, int log2_h, int c);
-typedef void (*oapv_fn_imgb_to_block_rc)(oapv_imgb_t *imgb, int c, int x_l, int y_l, int w_l, int h_l, s16 *block);
-typedef void (*oapv_fn_imgb_to_block)(void *src, int blk_w, int blk_h, int s_src, int offset_src, int s_dst, void *dst);
-typedef void (*oapv_fn_block_to_imgb)(void *src, int blk_w, int blk_h, int s_src, int offset_dst, int s_dst, void *dst);
-typedef void (*oapv_fn_img_pad)(oapve_ctx_t *ctx, oapv_imgb_t *imgb);
-typedef int (*oapv_fn_had8x8)(pel *org, int s_org);
+typedef double (*oapv_fn_enc_blk_cost_t)(oapve_ctx_t *ctx, oapve_core_t *core, int log2_w, int log2_h, int c);
+typedef void (*oapv_fn_imgb_to_blk_rc_t)(oapv_imgb_t *imgb, int c, int x_l, int y_l, int w_l, int h_l, s16 *block);
+typedef void (*oapv_fn_imgb_to_blk_t)(void *src, int blk_w, int blk_h, int s_src, int offset_src, int s_dst, void *dst);
+typedef void (*oapv_fn_blk_to_imgb_t)(void *src, int blk_w, int blk_h, int s_src, int offset_dst, int s_dst, void *dst);
+typedef void (*oapv_fn_img_pad_t)(oapve_ctx_t *ctx, oapv_imgb_t *imgb);
+typedef int (*oapv_fn_had8x8_t)(pel *org, int s_org);
 
 /*****************************************************************************
  * rate-control related
@@ -230,7 +226,8 @@ struct oapve_core {
     int          prev_1st_ac_ctx[N_C];
     int          tile_idx;
     int          prev_dc[N_C];
-
+    int          dc_diff; /* DC difference, which is represented in 17 bits */
+                          /* and coded as abs_dc_coeff_diff and sign_dc_coeff_diff */
     int          qp[N_C]; // QPs for Y, Cb(U), Cr(V)
     int          dq_shift[N_C];
 
@@ -278,6 +275,7 @@ struct oapve_ctx {
     int                       num_tile_cols;
     int                       num_tile_rows;
     int                       qp[N_C];
+    s8                        qp_offset[N_C];
     int                       w;
     int                       h;
     int                       cfi;
@@ -300,15 +298,14 @@ struct oapve_ctx {
     const oapv_fn_sad_t      *fn_sad;
     const oapv_fn_ssd_t      *fn_ssd;
     const oapv_fn_diff_t     *fn_diff;
-    oapv_fn_imgb_to_block_rc  fn_imgb_to_block_rc;
-    oapv_fn_imgb_to_block     fn_imgb_to_block[N_C];
-    oapv_fn_block_to_imgb     fn_block_to_imgb[N_C];
-    oapv_fn_img_pad           fn_img_pad;
-    oapv_fn_block_cost_t      fn_block;
-    oapv_fn_had8x8            fn_had8x8;
-    int                       use_frm_hash;
-    void                     *tx_tbl;
+    oapv_fn_imgb_to_blk_rc_t  fn_imgb_to_blk_rc;
+    oapv_fn_imgb_to_blk_t     fn_imgb_to_blk[N_C];
+    oapv_fn_blk_to_imgb_t     fn_blk_to_imgb[N_C];
+    oapv_fn_img_pad_t         fn_img_pad;
+    oapv_fn_enc_blk_cost_t    fn_enc_blk;
+    oapv_fn_had8x8_t          fn_had8x8;
 
+    int                       use_frm_hash;
     oapve_rc_param_t          rc_param;
 
     /* platform specific data, if needed */
@@ -336,7 +333,7 @@ struct oapvd_tile {
     int          y;         /* y (row) position in a frame in unit of pixel */
     int          w;         /* tile width in unit of pixel */
     int          h;         /* tile height in unit of pixel */
-    u32          data_size; /* tile size including tile_size_minus1 syntax */
+    u32          data_size; /* tile size including tile_size syntax */
 
     u8          *bs_beg; /* start position of tile in input bistream */
     u8          *bs_end; /* end position of tile() in input bistream */
@@ -353,6 +350,8 @@ struct oapvd_core {
     int          prev_dc_ctx[N_C];
     int          prev_1st_ac_ctx[N_C];
     int          prev_dc[N_C];
+    int          dc_diff; /* DC difference, which is represented in 17 bits */
+                          /* and coded as abs_dc_coeff_diff and sign_dc_coeff_diff */
     int          qp[N_C];
     int          dq_shift[N_C];
     s16          q_mat[N_C][OAPV_BLK_D];
@@ -372,7 +371,7 @@ struct oapvd_ctx {
     oapv_imgb_t            *imgb;
     const oapv_fn_itx_t    *fn_itx;
     const oapv_fn_dquant_t *fn_dquant;
-    oapv_fn_block_to_imgb   fn_block_to_imgb[N_C];
+    oapv_fn_blk_to_imgb_t   fn_block_to_imgb[N_C];
     oapv_bs_t               bs;
 
     oapv_fh_t               fh;
diff --git a/src/oapv_metadata.c b/src/oapv_metadata.c
index aea2023..d56fd90 100644
--- a/src/oapv_metadata.c
+++ b/src/oapv_metadata.c
@@ -40,6 +40,22 @@ static oapvm_ctx_t *meta_id_to_ctx(oapvm_t id)
     oapv_assert_rv(ctx->magic == OAPVM_MAGIC_CODE, NULL);
     return ctx;
 }
+#define div_255_fast(x)  (((x) + (((x) + 257) >> 8)) >> 8)
+
+static inline u32 meta_get_byte_pld_type(oapv_mdp_t *mdp)
+{
+    return (mdp->pld_type < 65536 ? div_255_fast(mdp->pld_type) : mdp->pld_type / 255) + 1;
+}
+
+static inline u32 meta_get_byte_pld_size(oapv_mdp_t *mdp)
+{
+    return (mdp->pld_size < 65536 ? div_255_fast(mdp->pld_size) : mdp->pld_size / 255) + 1;
+}
+
+static inline u32 meta_get_byte_pld_all(oapv_mdp_t *mdp)
+{
+    return meta_get_byte_pld_type(mdp) + meta_get_byte_pld_size(mdp) + mdp->pld_size;
+}
 
 static oapv_mdp_t **meta_mdp_find_last_with_check(oapv_md_t *md, int type, unsigned char *uuid)
 {
@@ -101,6 +117,7 @@ static int meta_md_rm_mdp(oapv_md_t *md, int mdt)
             mdp_prev->next = mdp->next;
         }
         meta_md_free_mdp(mdp);
+        md->md_size -= meta_get_byte_pld_all(mdp);
         md->md_num--;
         return OAPV_OK;
     }
@@ -122,8 +139,8 @@ static int meta_md_rm_usd(oapv_md_t *md, unsigned char *uuid)
                     mdp_prev->next = mdp->next;
                 }
                 oapv_assert_rv(md->md_size >= mdp->pld_size, OAPV_ERR_UNEXPECTED);
-                md->md_size -= mdp->pld_size;
                 meta_md_free_mdp(mdp);
+                md->md_size -= meta_get_byte_pld_all(mdp);
                 md->md_num--;
                 return OAPV_OK;
             }
@@ -200,7 +217,7 @@ static void meta_free_md(oapv_md_t *md)
 int oapvm_set(oapvm_t mid, int group_id, int type, void *data, int size, unsigned char *uuid)
 {
     oapvm_ctx_t *md_list = meta_id_to_ctx(mid);
-
+    oapv_assert_rv(md_list, OAPV_ERR_INVALID_ARGUMENT);
     int          ret = meta_verify_mdp_data(type, size, (u8 *)data);
     oapv_assert_rv(OAPV_SUCCEEDED(ret), ret);
 
@@ -230,24 +247,7 @@ int oapvm_set(oapvm_t mid, int group_id, int type, void *data, int size, unsigne
     tmp_mdp->pld_type = type;
     tmp_mdp->pld_data = data;
     *last_ptr = tmp_mdp;
-
-    /* calculate length of payload type */
-    int tmp_mpt = type;
-    while(tmp_mpt >= 255) {
-        tmp_mpt -= 255;
-        md_list->md_arr[md_list_idx].md_size += 1;
-    }
-    md_list->md_arr[md_list_idx].md_size += 1;
-
-    /*  calculate length of payload data size */
-    int tmp_mps = size;
-    while(tmp_mps >= 255) {
-        tmp_mps -= 255;
-        md_list->md_arr[md_list_idx].md_size += 1;
-    }
-    md_list->md_arr[md_list_idx].md_size += 1;
-
-    md_list->md_arr[md_list_idx].md_size += tmp_mdp->pld_size;
+    md_list->md_arr[md_list_idx].md_size += meta_get_byte_pld_all(tmp_mdp);
     md_list->md_arr[md_list_idx].md_num++;
     return OAPV_OK;
 }
@@ -320,7 +320,7 @@ int oapvm_set_all(oapvm_t mid, oapvm_payload_t *pld, int num_plds)
         tmp_mdp->pld_size = pld[i].data_size;
         tmp_mdp->pld_type = pld[i].type;
         tmp_mdp->pld_data = pld[i].data;
-        md_list->md_arr[md_list_idx].md_size += tmp_mdp->pld_size;
+        md_list->md_arr[md_list_idx].md_size += meta_get_byte_pld_all(tmp_mdp);
 
         *last_ptr = tmp_mdp;
     }
diff --git a/src/oapv_rc.c b/src/oapv_rc.c
index afe6385..91e2ae5 100644
--- a/src/oapv_rc.c
+++ b/src/oapv_rc.c
@@ -46,7 +46,7 @@ int oapve_rc_get_tile_cost(oapve_ctx_t* ctx, oapve_core_t* core, oapve_tile_t* t
                 int tx = tile->x + x;
                 int ty = tile->y + y;
 
-                ctx->fn_imgb_to_block_rc(ctx->imgb, c, tx, ty, 8, 8, core->coef);
+                ctx->fn_imgb_to_blk_rc(ctx->imgb, c, tx, ty, 8, 8, core->coef);
                 sum += ctx->fn_had8x8(core->coef, 8);
                 tile->rc.number_pixel += 64;
             }
@@ -157,7 +157,7 @@ double oapve_rc_estimate_pic_lambda(oapve_ctx_t* ctx, double cost)
 int oapve_rc_estimate_pic_qp(double lambda)
 {
     int qp = (int)(4.2005 * log(lambda) + 13.7122 + 0.5) + OAPV_RC_QP_OFFSET;
-    qp = oapv_clip3(MIN_QUANT, MAX_QUANT, qp);
+    qp = oapv_clip3(MIN_QUANT, MAX_QUANT(10), qp);
     return qp;
 }
 
@@ -184,7 +184,7 @@ void oapve_rc_get_qp(oapve_ctx_t* ctx, oapve_tile_t* tile, int frame_qp, int* qp
     *qp = (int)(4.2005 * log(est_lambda) + 13.7122 + 0.5);
     *qp = oapv_clip3(min_qp, max_qp, *qp);
     *qp += OAPV_RC_QP_OFFSET;
-
+    *qp = oapv_clip3(MIN_QUANT, MAX_QUANT(10), *qp);
 }
 
 void oapve_rc_update_after_pic(oapve_ctx_t* ctx, double cost)
diff --git a/src/oapv_sad.c b/src/oapv_sad.c
index a8ae8a0..de9992e 100644
--- a/src/oapv_sad.c
+++ b/src/oapv_sad.c
@@ -33,13 +33,13 @@
 #include <math.h>
 
 /* SAD for 16bit **************************************************************/
-int oapv_sad_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int bit_depth)
+int oapv_sad_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2)
 {
-    u16 *s1;
+    s16 *s1;
     s16 *s2;
     int  i, j, sad;
 
-    s1 = (u16 *)src1;
+    s1 = (s16 *)src1;
     s2 = (s16 *)src2;
 
     sad = 0;
@@ -52,7 +52,7 @@ int oapv_sad_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2, i
         s2 += s_src2;
     }
 
-    return (sad >> (bit_depth - 8));
+    return sad;
 }
 
 const oapv_fn_sad_t oapv_tbl_fn_sad_16b[2] = {
@@ -61,7 +61,7 @@ const oapv_fn_sad_t oapv_tbl_fn_sad_16b[2] = {
 };
 
 /* DIFF **********************************************************************/
-void oapv_diff_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int s_diff, s16 *diff, int bit_depth)
+void oapv_diff_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int s_diff, s16 *diff)
 {
     s16 *s1;
     s16 *s2;
@@ -86,7 +86,7 @@ const oapv_fn_diff_t oapv_tbl_fn_diff_16b[2] = {
 };
 
 /* SSD ***********************************************************************/
-s64 oapv_ssd_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int bit_depth)
+s64 oapv_ssd_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2)
 {
     s16 *s1;
     s16 *s2;
diff --git a/src/oapv_sad.h b/src/oapv_sad.h
index 7f67707..dbdd309 100644
--- a/src/oapv_sad.h
+++ b/src/oapv_sad.h
@@ -34,9 +34,9 @@
 
 #include "oapv_port.h"
 
-int oapv_sad_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int bit_depth);
-void oapv_diff_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int s_diff, s16 *diff, int bit_depth);
-s64 oapv_ssd_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int bit_depth);
+int oapv_sad_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2);
+void oapv_diff_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2, int s_diff, s16 *diff);
+s64 oapv_ssd_16b(int w, int h, void *src1, void *src2, int s_src1, int s_src2);
 int oapv_dc_removed_had8x8(pel *org, int s_org);
 
 extern const oapv_fn_sad_t  oapv_tbl_fn_sad_16b[2];
diff --git a/src/oapv_tq.c b/src/oapv_tq.c
index 8745b91..af0bad5 100644
--- a/src/oapv_tq.c
+++ b/src/oapv_tq.c
@@ -97,6 +97,11 @@ void oapv_trans(oapve_ctx_t *ctx, s16 *coef, int log2_w, int log2_h, int bit_dep
 
 static int oapv_quant(s16 *coef, u8 qp, int q_matrix[OAPV_BLK_D], int log2_w, int log2_h, int bit_depth, int deadzone_offset)
 {
+    // coef is the output of the transform, the bit range is 16
+    // q_matrix has the value of q_scale * 16 / q_matrix, the bit range is 19
+    // (precision of q_scale is 15, and the range of q_mtrix is 1~255)
+    // lev is the product of abs(coef) and q_matrix, the bit range is 35
+
     s64 lev;
     s32 offset;
     int sign;
diff --git a/src/oapv_vlc.c b/src/oapv_vlc.c
index 61ed32a..bc80e6c 100644
--- a/src/oapv_vlc.c
+++ b/src/oapv_vlc.c
@@ -205,6 +205,7 @@ static int dec_vlc_read_1bit_read(oapv_bs_t *bs, int k)
     }
     return symbol;
 }
+
 static int dec_vlc_read(oapv_bs_t *bs, int k)
 {
     u32 symbol = 0;
@@ -268,22 +269,26 @@ static int dec_vlc_read(oapv_bs_t *bs, int k)
 
 void oapve_set_frame_header(oapve_ctx_t *ctx, oapv_fh_t *fh)
 {
+    oapve_param_t * param = ctx->param;
+
     oapv_mset(fh, 0, sizeof(oapv_fh_t));
-    fh->fi.profile_idc = ctx->param->profile_idc;
-    fh->fi.level_idc = ctx->param->level_idc;
-    fh->fi.band_idc = ctx->param->band_idc;
-    fh->fi.frame_width = ctx->param->w;
-    fh->fi.frame_height = ctx->param->h;
+    fh->fi.profile_idc = param->profile_idc;
+    fh->fi.level_idc = param->level_idc;
+    fh->fi.band_idc = param->band_idc;
+    fh->fi.frame_width = param->w;
+    fh->fi.frame_height = param->h;
     fh->fi.chroma_format_idc = ctx->cfi;
     fh->fi.bit_depth = ctx->bit_depth;
-    fh->tile_width_in_mbs = ctx->param->tile_w_mb;
-    fh->tile_height_in_mbs = ctx->param->tile_h_mb;
-    if(fh->color_description_present_flag == 0) {
-        fh->color_primaries = 2;
-        fh->transfer_characteristics = 2;
-        fh->matrix_coefficients = 2;
-    }
-    fh->use_q_matrix = ctx->param->use_q_matrix;
+    fh->tile_width_in_mbs = param->tile_w_mb;
+    fh->tile_height_in_mbs = param->tile_h_mb;
+
+    fh->color_description_present_flag = param->color_description_present_flag;
+    fh->color_primaries = param->color_primaries;
+    fh->transfer_characteristics = param->transfer_characteristics;
+    fh->matrix_coefficients = param->matrix_coefficients;
+    fh->full_range_flag = param->full_range_flag;
+
+    fh->use_q_matrix = param->use_q_matrix;
     if(fh->use_q_matrix == 0) {
         for(int cidx = 0; cidx < ctx->num_comp; cidx++) {
             for(int y = 0; y < OAPV_BLK_H; y++) {
@@ -295,11 +300,10 @@ void oapve_set_frame_header(oapve_ctx_t *ctx, oapv_fh_t *fh)
     }
     else {
         int mod = (1 << OAPV_LOG2_BLK) - 1;
-        for(int i = 0; i < OAPV_BLK_D; i++) {
-            fh->q_matrix[Y_C][i >> OAPV_LOG2_BLK][i & mod] = ctx->param->q_matrix_y[i];
-            fh->q_matrix[U_C][i >> OAPV_LOG2_BLK][i & mod] = ctx->param->q_matrix_u[i];
-            fh->q_matrix[V_C][i >> OAPV_LOG2_BLK][i & mod] = ctx->param->q_matrix_v[i];
-            fh->q_matrix[X_C][i >> OAPV_LOG2_BLK][i & mod] = ctx->param->q_matrix_x[i];
+        for(int c=  0; c <OAPV_MAX_CC; c++) {
+            for(int i = 0; i < OAPV_BLK_D; i++) {
+                fh->q_matrix[c][i >> OAPV_LOG2_BLK][i & mod] = param->q_matrix[c][i];
+            }
         }
     }
     fh->tile_size_present_in_fh_flag = 0;
@@ -310,7 +314,7 @@ static int enc_vlc_quantization_matrix(oapv_bs_t *bs, oapve_ctx_t *ctx, oapv_fh_
     for(int cidx = 0; cidx < ctx->num_comp; cidx++) {
         for(int y = 0; y < 8; y++) {
             for(int x = 0; x < 8; x++) {
-                oapv_bsw_write(bs, fh->q_matrix[cidx][y][x] - 1, 8);
+                oapv_bsw_write(bs, fh->q_matrix[cidx][y][x], 8);
                 DUMP_HLS(fh->q_matrix, fh->q_matrix[cidx][y][x]);
             }
         }
@@ -320,16 +324,16 @@ static int enc_vlc_quantization_matrix(oapv_bs_t *bs, oapve_ctx_t *ctx, oapv_fh_
 
 static int enc_vlc_tile_info(oapv_bs_t *bs, oapve_ctx_t *ctx, oapv_fh_t *fh)
 {
-    oapv_bsw_write(bs, fh->tile_width_in_mbs - 1, 28);
+    oapv_bsw_write(bs, fh->tile_width_in_mbs, 20);
     DUMP_HLS(fh->tile_width_in_mbs, fh->tile_width_in_mbs);
-    oapv_bsw_write(bs, fh->tile_height_in_mbs - 1, 28);
+    oapv_bsw_write(bs, fh->tile_height_in_mbs, 20);
     DUMP_HLS(fh->tile_height_in_mbs, fh->tile_height_in_mbs);
     oapv_bsw_write(bs, fh->tile_size_present_in_fh_flag, 1);
     DUMP_HLS(fh->tile_size_present_in_fh_flag, fh->tile_size_present_in_fh_flag);
     if(fh->tile_size_present_in_fh_flag) {
         for(int i = 0; i < ctx->num_tiles; i++) {
-            oapv_bsw_write(bs, fh->tile_size[i] - 1, 32);
-            DUMP_HLS(fh->tile_size, fh->tile_size[i] - 1);
+            oapv_bsw_write(bs, fh->tile_size[i], 32);
+            DUMP_HLS(fh->tile_size, fh->tile_size[i]);
         }
     }
 
@@ -346,10 +350,10 @@ int oapve_vlc_frame_info(oapv_bs_t *bs, oapv_fi_t *fi)
     DUMP_HLS(fi->band_idc, fi->band_idc);
     oapv_bsw_write(bs, 0, 5); // reserved_zero_5bits
     DUMP_HLS(reserved_zero, 0);
-    oapv_bsw_write(bs, fi->frame_width - 1, 32);
-    DUMP_HLS(fi->frame_width, fi->frame_width - 1);
-    oapv_bsw_write(bs, fi->frame_height - 1, 32);
-    DUMP_HLS(fi->frame_height, fi->frame_height - 1);
+    oapv_bsw_write(bs, fi->frame_width, 24);
+    DUMP_HLS(fi->frame_width, fi->frame_width);
+    oapv_bsw_write(bs, fi->frame_height, 24);
+    DUMP_HLS(fi->frame_height, fi->frame_height);
     oapv_bsw_write(bs, fi->chroma_format_idc, 4);
     DUMP_HLS(fi->chroma_format_idc, fi->chroma_format_idc);
     oapv_bsw_write(bs, fi->bit_depth - 8, 4);
@@ -368,7 +372,7 @@ int oapve_vlc_frame_header(oapv_bs_t *bs, oapve_ctx_t *ctx, oapv_fh_t *fh)
     oapve_vlc_frame_info(bs, &fh->fi);
     oapv_bsw_write(bs, 0, 8); // reserved_zero_8bits
     DUMP_HLS(reserved_zero, 0);
-    oapv_bsw_write(bs, fh->color_description_present_flag, 1);
+    oapv_bsw_write1(bs, fh->color_description_present_flag);
     DUMP_HLS(fh->color_description_present_flag, fh->color_description_present_flag);
     if(fh->color_description_present_flag) {
         oapv_bsw_write(bs, fh->color_primaries, 8);
@@ -377,8 +381,10 @@ int oapve_vlc_frame_header(oapv_bs_t *bs, oapve_ctx_t *ctx, oapv_fh_t *fh)
         DUMP_HLS(fh->transfer_characteristics, fh->transfer_characteristics);
         oapv_bsw_write(bs, fh->matrix_coefficients, 8);
         DUMP_HLS(fh->matrix_coefficients, fh->matrix_coefficients);
+        oapv_bsw_write1(bs, fh->full_range_flag);
+        DUMP_HLS(fh->full_range_flag, fh->full_range_flag);
     }
-    oapv_bsw_write(bs, fh->use_q_matrix, 1);
+    oapv_bsw_write1(bs, fh->use_q_matrix);
     DUMP_HLS(fh->use_q_matrix, fh->use_q_matrix);
     if(fh->use_q_matrix) {
         enc_vlc_quantization_matrix(bs, ctx, fh);
@@ -393,22 +399,17 @@ int oapve_vlc_frame_header(oapv_bs_t *bs, oapve_ctx_t *ctx, oapv_fh_t *fh)
 int oapve_vlc_tile_size(oapv_bs_t *bs, int tile_size)
 {
     oapv_assert_rv(bsw_is_align8(bs), OAPV_ERR_MALFORMED_BITSTREAM);
-    oapv_bsw_write(bs, tile_size - 1, 32);
-    DUMP_HLS(tile_size, tile_size - 1);
+    oapv_bsw_write(bs, tile_size, 32);
+    DUMP_HLS(tile_size, tile_size);
     return OAPV_OK;
 }
 
 void oapve_set_tile_header(oapve_ctx_t *ctx, oapv_th_t *th, int tile_idx, int qp)
 {
     oapv_mset(th, 0, sizeof(oapv_th_t));
+
     for(int c = 0; c < ctx->num_comp; c++) {
-        th->tile_qp[c] = qp;
-        if(c == 1) {
-            th->tile_qp[c] += ctx->param->qp_cb_offset;
-        }
-        else if(c == 2) {
-            th->tile_qp[c] += ctx->param->qp_cr_offset;
-        }
+        th->tile_qp[c] = oapv_clip3(MIN_QUANT, MAX_QUANT(10), qp + ctx->qp_offset[c]);
     }
     th->tile_index = tile_idx;
 
@@ -429,8 +430,8 @@ int oapve_vlc_tile_header(oapve_ctx_t *ctx, oapv_bs_t *bs, oapv_th_t *th)
     oapv_bsw_write(bs, th->tile_index, 16);
     DUMP_HLS(th->tile_index, th->tile_index);
     for(int c = 0; c < ctx->num_comp; c++) {
-        oapv_bsw_write(bs, th->tile_data_size[c] - 1, 32);
-        DUMP_HLS(th->tile_data_size, th->tile_data_size[c] - 1);
+        oapv_bsw_write(bs, th->tile_data_size[c], 32);
+        DUMP_HLS(th->tile_data_size, th->tile_data_size[c]);
     }
     for(int c = 0; c < ctx->num_comp; c++) {
         oapv_bsw_write(bs, th->tile_qp[c], 8);
@@ -673,17 +674,13 @@ int oapvd_vlc_frame_info(oapv_bs_t *bs, oapv_fi_t *fi)
     DUMP_HLS(reserved_zero, reserved_zero);
     oapv_assert_rv(reserved_zero == 0, OAPV_ERR_MALFORMED_BITSTREAM);
 
-    fi->frame_width = oapv_bsr_read(bs, 32);
+    fi->frame_width = oapv_bsr_read(bs, 24);
     DUMP_HLS(fi->frame_width, fi->frame_width);
-    oapv_assert_rv(fi->frame_width > 0 && fi->frame_width < 0xFFFFFFFF, OAPV_ERR_MALFORMED_BITSTREAM);
-    fi->frame_width += 1;
-    oapv_assert_rv(fi->frame_width <= INT_MAX, OAPV_ERR_UNSUPPORTED); // frame width greater than 2^31 is unsupported in the current implementation
+    oapv_assert_rv(fi->frame_width > 0, OAPV_ERR_MALFORMED_BITSTREAM);
 
-    fi->frame_height = oapv_bsr_read(bs, 32);
+    fi->frame_height = oapv_bsr_read(bs, 24);
     DUMP_HLS(fi->frame_height, fi->frame_height);
-    oapv_assert_rv(fi->frame_height > 0 && fi->frame_height < 0xFFFFFFFF, OAPV_ERR_MALFORMED_BITSTREAM);
-    fi->frame_height += 1;
-    oapv_assert_rv(fi->frame_height <= INT_MAX, OAPV_ERR_UNSUPPORTED); // frame height greater than 2^31 is unsupported in the current implementation
+    oapv_assert_rv(fi->frame_height > 0, OAPV_ERR_MALFORMED_BITSTREAM);
 
     fi->chroma_format_idc = oapv_bsr_read(bs, 4);
     DUMP_HLS(fi->chroma_format_idc, fi->chroma_format_idc);
@@ -744,8 +741,9 @@ static int dec_vlc_q_matrix(oapv_bs_t *bs, oapv_fh_t *fh)
     for(int cidx = 0; cidx < num_comp; cidx++) {
         for(int y = 0; y < OAPV_BLK_H; y++) {
             for(int x = 0; x < OAPV_BLK_W; x++) {
-                fh->q_matrix[cidx][y][x] = oapv_bsr_read(bs, 8) + 1;
+                fh->q_matrix[cidx][y][x] = oapv_bsr_read(bs, 8);
                 DUMP_HLS(fh->q_matrix, fh->q_matrix[cidx][y][x]);
+                oapv_assert_rv(fh->q_matrix[cidx][y][x] > 0, OAPV_ERR_MALFORMED_BITSTREAM);
             }
         }
     }
@@ -756,11 +754,13 @@ static int dec_vlc_tile_info(oapv_bs_t *bs, oapv_fh_t *fh)
 {
     int pic_w, pic_h, tile_w, tile_h, tile_cols, tile_rows;
 
-    fh->tile_width_in_mbs = oapv_bsr_read(bs, 28) + 1;
+    fh->tile_width_in_mbs = oapv_bsr_read(bs, 20);
     DUMP_HLS(fh->tile_width_in_mbs, fh->tile_width_in_mbs);
+    oapv_assert_rv(fh->tile_width_in_mbs > 0, OAPV_ERR_MALFORMED_BITSTREAM);
 
-    fh->tile_height_in_mbs = oapv_bsr_read(bs, 28) + 1;
+    fh->tile_height_in_mbs = oapv_bsr_read(bs, 20);
     DUMP_HLS(fh->tile_height_in_mbs, fh->tile_height_in_mbs);
+    oapv_assert_rv(fh->tile_height_in_mbs > 0, OAPV_ERR_MALFORMED_BITSTREAM);
 
     /* set various value */
     pic_w = ((fh->fi.frame_width + (OAPV_MB_W - 1)) >> OAPV_LOG2_MB_W) << OAPV_LOG2_MB_W;
@@ -781,8 +781,7 @@ static int dec_vlc_tile_info(oapv_bs_t *bs, oapv_fh_t *fh)
         for(int i = 0; i < tile_cols * tile_rows; i++) {
             fh->tile_size[i] = oapv_bsr_read(bs, 32);
             DUMP_HLS(fh->tile_size, fh->tile_size[i]);
-            oapv_assert_rv(fh->tile_size[i] > 0 && fh->tile_size[i] < 0xFFFFFFFF, OAPV_ERR_MALFORMED_BITSTREAM);
-            fh->tile_size[i] += 1;
+            oapv_assert_rv(fh->tile_size[i] > 0, OAPV_ERR_MALFORMED_BITSTREAM);
         }
     }
     return OAPV_OK;
@@ -798,7 +797,7 @@ int oapvd_vlc_frame_header(oapv_bs_t *bs, oapv_fh_t *fh)
     DUMP_HLS(reserved_zero, reserved_zero);
     oapv_assert_rv(reserved_zero == 0, OAPV_ERR_MALFORMED_BITSTREAM);
 
-    fh->color_description_present_flag = oapv_bsr_read(bs, 1);
+    fh->color_description_present_flag = oapv_bsr_read1(bs);
     DUMP_HLS(fh->color_description_present_flag, fh->color_description_present_flag);
     if(fh->color_description_present_flag) {
         fh->color_primaries = oapv_bsr_read(bs, 8);
@@ -807,13 +806,17 @@ int oapvd_vlc_frame_header(oapv_bs_t *bs, oapv_fh_t *fh)
         DUMP_HLS(fh->transfer_characteristics, fh->transfer_characteristics);
         fh->matrix_coefficients = oapv_bsr_read(bs, 8);
         DUMP_HLS(fh->matrix_coefficients, fh->matrix_coefficients);
+        fh->full_range_flag = oapv_bsr_read1(bs);
+        DUMP_HLS(fh->full_range_flag, fh->full_range_flag);
     }
     else {
-        fh->color_primaries = 2;
-        fh->transfer_characteristics = 2;
-        fh->matrix_coefficients = 2;
+        // default value settings
+        fh->color_primaries = 2; // unspecified
+        fh->transfer_characteristics = 2; // unspecified
+        fh->matrix_coefficients = 2; // unspecified
+        fh->full_range_flag = 0; // limited range
     }
-    fh->use_q_matrix = oapv_bsr_read(bs, 1);
+    fh->use_q_matrix = oapv_bsr_read1(bs);
     DUMP_HLS(fh->use_q_matrix, fh->use_q_matrix);
     if(fh->use_q_matrix) {
         ret = dec_vlc_q_matrix(bs, fh);
@@ -848,8 +851,8 @@ int oapvd_vlc_tile_size(oapv_bs_t *bs, u32 *tile_size)
 {
     u32 size = oapv_bsr_read(bs, 32);
     DUMP_HLS(tile_size, size);
-    oapv_assert_rv(size > 0 && size < 0xFFFFFFFF, OAPV_ERR_MALFORMED_BITSTREAM);
-    *tile_size = size + 1;
+    oapv_assert_rv(size > 0, OAPV_ERR_MALFORMED_BITSTREAM);
+    *tile_size = size;
     return OAPV_OK;
 }
 
@@ -862,8 +865,7 @@ int oapvd_vlc_tile_header(oapv_bs_t *bs, oapvd_ctx_t *ctx, oapv_th_t *th)
     for(int c = 0; c < ctx->num_comp; c++) {
         th->tile_data_size[c] = oapv_bsr_read(bs, 32);
         DUMP_HLS(th->tile_data_size, th->tile_data_size[c]);
-        oapv_assert_rv(th->tile_data_size[c] > 0 && th->tile_data_size[c] < 0xFFFFFFFF, OAPV_ERR_MALFORMED_BITSTREAM);
-        th->tile_data_size[c] += 1;
+        oapv_assert_rv(th->tile_data_size[c] > 0, OAPV_ERR_MALFORMED_BITSTREAM);
     }
     for(int c = 0; c < ctx->num_comp; c++) {
         th->tile_qp[c] = oapv_bsr_read(bs, 8);
@@ -1183,7 +1185,7 @@ void oapve_vlc_ac_coeff(oapve_ctx_t *ctx, oapve_core_t *core, oapv_bs_t *bs, s16
     }
 }
 
-int oapvd_vlc_dc_coeff(oapvd_ctx_t *ctx, oapvd_core_t *core, oapv_bs_t *bs, s16 *dc_diff, int c)
+int oapvd_vlc_dc_coeff(oapvd_ctx_t *ctx, oapvd_core_t *core, oapv_bs_t *bs, int *dc_diff, int c)
 {
     int rice_level = 0;
     int abs_dc_diff;
@@ -1203,7 +1205,7 @@ int oapvd_vlc_dc_coeff(oapvd_ctx_t *ctx, oapvd_core_t *core, oapv_bs_t *bs, s16
 int oapvd_vlc_ac_coeff(oapvd_ctx_t *ctx, oapvd_core_t *core, oapv_bs_t *bs, s16 *coef, int c)
 {
     int        sign, level, prev_level, run;
-    int        scan_pos_offset, num_coeff, i, coef_cnt = 0;
+    int        scan_pos_offset, num_coeff, i;
     const u16 *scanp;
 
     scanp = oapv_tbl_scan;
@@ -1255,6 +1257,7 @@ int oapvd_vlc_ac_coeff(oapvd_ctx_t *ctx, oapvd_core_t *core, oapv_bs_t *bs, s16
         else {
             rice_level = oapv_clip3(OAPV_MIN_AC_LEVEL_CTX, OAPV_MAX_AC_LEVEL_CTX, prev_level >> 2);
         }
+
         if(rice_level == 0) {
             if(bs->leftbits == 0) {
                 OAPV_READ_FLUSH(bs, 4);
@@ -1294,8 +1297,6 @@ int oapvd_vlc_ac_coeff(oapvd_ctx_t *ctx, oapvd_core_t *core, oapv_bs_t *bs, s16
         bs->leftbits -= 1;
         coef[scanp[scan_pos_offset]] = sign ? -(s16)level : (s16)level;
 
-        coef_cnt++;
-
         if(scan_pos_offset >= num_coeff - 1) {
             break;
         }
@@ -1320,7 +1321,7 @@ int oapvd_vlc_metadata(oapv_bs_t *bs, u32 pbu_size, oapvm_t mid, int group_id)
     u32 metadata_size;
     metadata_size = oapv_bsr_read(bs, 32);
     DUMP_HLS(metadata_size, metadata_size);
-    oapv_assert_gv(metadata_size <= (pbu_size - 8), ret, OAPV_ERR_MALFORMED_BITSTREAM, ERR);
+    oapv_assert_gv(pbu_size >= 8 && metadata_size <= (pbu_size - 8), ret, OAPV_ERR_MALFORMED_BITSTREAM, ERR);
     u8 *bs_start_pos = bs->cur;
     u8 *payload_data = NULL;
 
@@ -1330,6 +1331,7 @@ int oapvd_vlc_metadata(oapv_bs_t *bs, u32 pbu_size, oapvm_t mid, int group_id)
         do {
             t0 = oapv_bsr_read(bs, 8);
             DUMP_HLS(payload_type, t0);
+            oapv_assert_gv(metadata_size > 0, ret, OAPV_ERR_MALFORMED_BITSTREAM, ERR);
             metadata_size -= 1;
             if(t0 == 0xFF) {
                 payload_type += 255;
@@ -1341,6 +1343,7 @@ int oapvd_vlc_metadata(oapv_bs_t *bs, u32 pbu_size, oapvm_t mid, int group_id)
         do {
             t0 = oapv_bsr_read(bs, 8);
             DUMP_HLS(payload_size, t0);
+            oapv_assert_gv(metadata_size > 0, ret, OAPV_ERR_MALFORMED_BITSTREAM, ERR);
             metadata_size -= 1;
             if(t0 == 0xFF) {
                 payload_size += 255;
diff --git a/src/oapv_vlc.h b/src/oapv_vlc.h
index b4788c8..01fc1a3 100644
--- a/src/oapv_vlc.h
+++ b/src/oapv_vlc.h
@@ -62,6 +62,6 @@ int  oapvd_vlc_tile_header(oapv_bs_t* bs, oapvd_ctx_t* ctx, oapv_th_t* th);
 int  oapvd_vlc_tile_dummy_data(oapv_bs_t* bs);
 int  oapvd_vlc_metadata(oapv_bs_t* bs, u32 pbu_size, oapvm_t mid, int group_id);
 int  oapvd_vlc_filler(oapv_bs_t* bs, u32 filler_size);
-int  oapvd_vlc_dc_coeff(oapvd_ctx_t* ctx, oapvd_core_t* core, oapv_bs_t* bs, s16* dc_diff, int c);
+int  oapvd_vlc_dc_coeff(oapvd_ctx_t* ctx, oapvd_core_t* core, oapv_bs_t* bs, int* dc_diff, int c);
 int  oapvd_vlc_ac_coeff(oapvd_ctx_t* ctx, oapvd_core_t* core, oapv_bs_t* bs, s16* coef, int c);
 #endif /* _OAPV_VLC_H_ */
diff --git a/src/sse/oapv_sad_sse.c b/src/sse/oapv_sad_sse.c
index 8009bbb..de047af 100644
--- a/src/sse/oapv_sad_sse.c
+++ b/src/sse/oapv_sad_sse.c
@@ -51,7 +51,7 @@
     s00a = _mm_add_epi32(s00a, s00); \
     s00a = _mm_add_epi32(s00a, s01);
 
-static s64 ssd_16b_sse_8x8(int w, int h, void * src1, void * src2, int s_src1, int s_src2, int bit_depth)
+static s64 ssd_16b_sse_8x8(int w, int h, void * src1, void * src2, int s_src1, int s_src2)
 {
     s64   ssd;
     s16 * s1;
diff --git a/test/README.md b/test/README.md
index 5f8ecca..a404bfc 100644
--- a/test/README.md
+++ b/test/README.md
@@ -5,18 +5,18 @@
 
 | No. | Bitstream Name | Description                                                  | Profile&nbsp;&nbsp; | Level | Band | Frame Rate | Resolution | # of Frame | MD5 sum of bitstream             |
 |-----|----------------|--------------------------------------------------------------|---------------------|-------|------|------------|------------|------------|----------------------------------|
-| 1   | tile_A         | one-tile per   one-picture                                   | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 0b745f686d3154bc23a8b95b486e2c03 |
-| 2   | tile_B         | Tile size = min size   tile (256x128)                        | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | c9a475186fc36cfb102638896a5d26be |
-| 3   | tile_C         | # of Tiles: max num   tile (20x20)                           | 422-10              | 5     | 0    | 30 fps     | 7680x4320  | 3          | 64da7cb68ec2161de5650a297e1954bb |
-| 4   | tile_D         | tile dummy data test                                         | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | c9a475186fc36cfb102638896a5d26be |
-| 5   | tile_E         | tile_size_present_in_fh_flag=on                              | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 2f0dc83c324876b5bf7f02be9c634cfb |
-| 6   | qp_A           | QP matrix enabled                                            | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 416800a582b7cbb6a941c4c3866de60f |
-| 7   | qp_B           | Tile QP   variation in a frame                               | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 514a2aca526820009a16907ee77c3d45 |
-| 8   | qp_C           | Set all the QPs in a   frame equal to min. QP (=0)           | 422-10              | 6     | 2    | 60 fps     | 3840x2160  | 3          | bc96b1acf6a2332404f712c1278f6d81 |
-| 9   | qp_D           | Set all the QPs in a   frame equal to max. QP (=51)          | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 90f0e32577e07c30c6b5d75e709e3126 |
-| 10  | qp_E           | Set different QP   betwee luma and chroma                    | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | d886c4e56086b5f53f4c87dcd62332ab |
-| 11  | syn_A          | Exercise a synthetic   image with QP = 0 and QP = 51         | 422-10              | 4.1   | 2    | 60 fps     | 1920x1080  | 2          | a8219946a3e9426935a53d6d55fce987 |
-| 12  | syn_B          | Exercise a synthetic   image with Tile QP variation in Frame | 422-10              | 4.1   | 2    | 60 fps     | 1920x1080  | 2          | a8219946a3e9426935a53d6d55fce987 |
+| 1   | tile_A         | one-tile per   one-picture                                   | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 74c5c0ca1bd2cfb28c6e2e0673e965f9 |
+| 2   | tile_B         | Tile size = min size   tile (256x128)                        | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 666ec80235a1e8f59db044d77a89a495 |
+| 3   | tile_C         | # of Tiles: max num   tile (20x20)                           | 422-10              | 5     | 0    | 30 fps     | 7680x4320  | 3          | 75363d036965a9dccc90a9ce8d0ae652 |
+| 4   | tile_D         | tile dummy data test                                         | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | dd492519c90409a9ca5710746f45c125 |
+| 5   | tile_E         | tile_size_present_in_fh_flag=on                              | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 134c4aa46cec9ab0299824682a89eecd |
+| 6   | qp_A           | QP matrix enabled                                            | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 5ca6d4ea0f65add261b44ed3532a0a73 |
+| 7   | qp_B           | Tile QP   variation in a frame                               | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 85bfa477911447d994c17dea9703a9c7 |
+| 8   | qp_C           | Set all the QPs in a   frame equal to min. QP (=0)           | 422-10              | 6     | 2    | 60 fps     | 3840x2160  | 3          | 8c2928ec05eb06d42d6a8bda0ceb7e8d |
+| 9   | qp_D           | Set all the QPs in a   frame equal to max. QP (=51)          | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 9c98e376fb59100f5a5585482fb33746 |
+| 10  | qp_E           | Set different QP   betwee luma and chroma                    | 422-10              | 4.1   | 2    | 60 fps     | 3840x2160  | 3          | 6d1a1bc982d412758f353c8d041979d1 |
+| 11  | syn_A          | Exercise a synthetic   image with QP = 0 and QP = 51         | 422-10              | 4.1   | 2    | 60 fps     | 1920x1080  | 2          | db9f8f7ce57871481e5b257b79149b1e |
+| 12  | syn_B          | Exercise a synthetic   image with Tile QP variation in Frame | 422-10              | 4.1   | 2    | 60 fps     | 1920x1080  | 2          | 5f6c57f0bfe7ceb2f97a56a3bec7fb7a |
 
 ## Test sequence
 "sequence" folder has the uncompressed video sequence for encoder testing.
diff --git a/test/bitstream/qp_A.apv b/test/bitstream/qp_A.apv
index 1c26cc6..39b97a6 100644
Binary files a/test/bitstream/qp_A.apv and b/test/bitstream/qp_A.apv differ
diff --git a/test/bitstream/qp_B.apv b/test/bitstream/qp_B.apv
index 8adb56d..f685630 100644
Binary files a/test/bitstream/qp_B.apv and b/test/bitstream/qp_B.apv differ
diff --git a/test/bitstream/qp_C.apv b/test/bitstream/qp_C.apv
index 3c9908f..33b599e 100644
Binary files a/test/bitstream/qp_C.apv and b/test/bitstream/qp_C.apv differ
diff --git a/test/bitstream/qp_D.apv b/test/bitstream/qp_D.apv
index 71bf431..d094042 100644
Binary files a/test/bitstream/qp_D.apv and b/test/bitstream/qp_D.apv differ
diff --git a/test/bitstream/qp_E.apv b/test/bitstream/qp_E.apv
index 44d904d..62bde8c 100644
Binary files a/test/bitstream/qp_E.apv and b/test/bitstream/qp_E.apv differ
diff --git a/test/bitstream/syn_A.apv b/test/bitstream/syn_A.apv
index 5ed865d..1d325d1 100644
Binary files a/test/bitstream/syn_A.apv and b/test/bitstream/syn_A.apv differ
diff --git a/test/bitstream/syn_B.apv b/test/bitstream/syn_B.apv
index 5ed865d..641a108 100644
Binary files a/test/bitstream/syn_B.apv and b/test/bitstream/syn_B.apv differ
diff --git a/test/bitstream/tile_A.apv b/test/bitstream/tile_A.apv
index 501d45a..1f8d213 100644
Binary files a/test/bitstream/tile_A.apv and b/test/bitstream/tile_A.apv differ
diff --git a/test/bitstream/tile_B.apv b/test/bitstream/tile_B.apv
index 9392009..f796778 100644
Binary files a/test/bitstream/tile_B.apv and b/test/bitstream/tile_B.apv differ
diff --git a/test/bitstream/tile_C.apv b/test/bitstream/tile_C.apv
index 1d4e3a3..4bf2f9b 100644
Binary files a/test/bitstream/tile_C.apv and b/test/bitstream/tile_C.apv differ
diff --git a/test/bitstream/tile_D.apv b/test/bitstream/tile_D.apv
index 9392009..7d61d5c 100644
Binary files a/test/bitstream/tile_D.apv and b/test/bitstream/tile_D.apv differ
diff --git a/test/bitstream/tile_E.apv b/test/bitstream/tile_E.apv
index 1ea72f4..66b1c3d 100644
Binary files a/test/bitstream/tile_E.apv and b/test/bitstream/tile_E.apv differ
diff --git a/util/apv.hexpat b/util/apv.hexpat
new file mode 100644
index 0000000..86431cd
--- /dev/null
+++ b/util/apv.hexpat
@@ -0,0 +1,226 @@
+#pragma pattern for Advanced Professional Video (*.apv)
+
+import std.io;
+import std.mem;
+#pragma endian big
+
+/* PBU types */
+enum PbuType : u8 {
+    FRM_PRI = 1,
+    FRM_NONPRI = 2,
+    FRM_PREVIEW = 25,
+    FRM_DEPTH = 26,
+    FRM_ALPHA = 27,
+    AUI = 65,
+    METADATA = 66,
+    FILLER = 67
+};
+
+fn get_0xff_ext_var(auto addr) {
+    u32 read = 1;
+    u32 var = 0;
+    u8 ext = std::mem::read_unsigned(addr, 1);
+    
+    while (ext == 0xFF) {
+        var += 0xFF;
+        ext = std::mem::read_unsigned(addr + read, 1);
+        read += 1;
+    }
+    var += ext; 
+    return var;
+};
+
+fn get_0xff_ext_var_bytes(auto addr) {
+    u32 read = 1;
+    u8 ext = std::mem::read_unsigned(addr, 1);
+    
+    while (ext == 0xFF) {
+        ext = std::mem::read_unsigned(addr + read, 1);
+        read += 1;
+    }
+    return read;
+};
+
+struct PbuBase {
+
+    u32 read = 0;
+    str ptype_str = "";
+    
+    /*    
+    syntax code                                                   | type
+    --------------------------------------------------------------|-----
+    pbu_header(){                                                 |
+        pbu_type                                                  | u(8)
+        group_id                                                  | u(16)
+        reserved_zero_8bits                                       | u(8)
+    }
+    */
+        
+    u32 pbu_size; // originally, this syntax is part of AuccessUnit
+    u8 pbu_type;
+    u16 group_id;
+    u8 reserved_zero_8bits;
+    read += 4;
+};
+
+/*    
+syntax code                                                   | type
+--------------------------------------------------------------|-----
+frame_info(){                                                 |
+  profile_idc                                                 | u(8)
+  level_idc                                                   | u(8)
+  band_idc                                                    | u(3)
+  reserved_zero_5bits                                         | u(5)
+  frame_width                                                 | u(24)
+  frame_height                                                | u(24)
+  chroma_format_idc                                           | u(4)
+  bit_depth_minus8                                            | u(4)
+  capture_time_distance                                       | u(8)
+  reserved_zero_8bits                                         | u(8)
+}
+*/
+
+bitfield FrmInfo {
+    profile_idc : 8;
+    level_idc : 8;
+    band_idc : 3;
+    reserved_zero_5bits: 5;
+    frame_width: 24;
+    frame_height: 24;
+    chroma_format_idc: 4;
+    bit_depth_minus8: 4;
+    capture_time_distance: 8;
+    reserved_zero_8bits: 8;
+};
+
+struct PbuFrm:PbuBase {
+    
+    if(pbu_type == PbuType::FRM_PRI) ptype_str = "Frm(Pri)";
+    else if(pbu_type == PbuType::FRM_NONPRI) ptype_str = "Frm(Nonpri)";
+    else if(pbu_type == PbuType::FRM_PREVIEW) ptype_str = "Frm(Preview)";
+    else if(pbu_type == PbuType::FRM_DEPTH) ptype_str = "Frm(Depth)";
+    else if(pbu_type == PbuType::FRM_ALPHA) ptype_str = "Frm(Alpha)";
+    else ptype_str = "Frm(Unknown)";
+    
+    FrmInfo finfo [[name("frame_info()")]];
+    read += 12; // byte size of frame_info()
+    
+    u8 frameData[pbu_size - read] [[sealed]];
+};
+
+u32 metadata_payload_count = 0;
+
+struct MetadataPayload {
+    str ptype_str = "";
+    u32 read = 0;
+    
+    u32 payloadType = get_0xff_ext_var($) [[export]];
+    read += get_0xff_ext_var_bytes($);
+    $ += get_0xff_ext_var_bytes($); // update current reading point
+
+    u32 payloadSize = get_0xff_ext_var($) [[export]];
+    read += get_0xff_ext_var_bytes($);
+    $ += get_0xff_ext_var_bytes($); // update current reading point
+    
+    u64 endOffset = $ + payloadSize;
+
+
+    if (payloadType == 4) ptype_str = "itu_t_t35";
+    else if (payloadType == 5) ptype_str = "mdcv";
+    else if (payloadType == 6) ptype_str = "cll";
+    else if (payloadType == 10) ptype_str = "filler";
+    else if (payloadType == 170) ptype_str = "user_defined";
+    else ptype_str = "undefined";
+    
+    std::print("    metadata payload[{:d}] type = {:d}({}), size = {:d}", metadata_payload_count, payloadType, ptype_str, payloadSize);                 
+
+    u8 payloadData[while($ < endOffset)] [[sealed]];
+    
+    metadata_payload_count += 1;
+    
+    
+} [[name(std::format("MetadataPayload[{}]:{}", (metadata_payload_count - 1), ptype_str))]];
+
+struct PbuMetadata:PbuBase {
+    u64 endOffset = 0;
+    ptype_str = "Metadata";
+    metadata_payload_count = 0; // reset number of metadata payload
+     
+    u32 metadata_size; // syntax
+    
+    endOffset = $ + metadata_size;
+
+    MetadataPayload pay[while($ < endOffset)] [[inline]];
+};
+
+
+struct PbuAui:PbuBase {
+    ptype_str = "aui";
+    u8 data[pbu_size - read] [[sealed]];
+};
+
+struct PbuFiller:PbuBase {
+    ptype_str = "filler";
+    u8 data[pbu_size - read] [[sealed]];
+};
+
+struct PbuUnknown:PbuBase {
+    std::warning(std::format("Unknown PBU type ({})!!!", pbu_type));
+    ptype_str = "unknown";
+    u8 data[pbu_size - read] [[sealed]];
+};
+    
+u32 pbu_count = 0;
+
+struct PBU {  
+    u32 pbu_size = std::mem::read_unsigned($, 4, std::mem::Endian::Big);
+    u8 pbu_type = std::mem::read_unsigned($ + 4, 1, std::mem::Endian::Big);
+    
+    match (pbu_type) {
+        (PbuType::FRM_PRI) : PbuFrm Pbu [[inline]];
+        (PbuType::FRM_NONPRI) :  PbuFrm Pbu [[inline]];
+        (PbuType::FRM_PREVIEW): PbuFrm Pbu [[inline]];
+        (PbuType::FRM_DEPTH):  PbuFrm Pbu [[inline]];
+        (PbuType::FRM_ALPHA): PbuFrm Pbu [[inline]];
+        (PbuType::AUI): PbuAui Pbu [[inline]];
+        (PbuType::METADATA): PbuMetadata Pbu [[inline]];
+        (PbuType::FILLER): PbuFiller Pbu [[inline]];
+        (_) : PbuUnknown Pbu [[inline]];
+    }
+    
+    std::print("  PBU[{:d}] size = {:d}, {}", pbu_count, pbu_size, Pbu.ptype_str);    
+
+    pbu_count += 1;
+
+} [[name(std::format("PBU[{}]:{}", (pbu_count - 1), Pbu.ptype_str))]];
+
+
+u32 au_count = 0;
+
+struct AccessUnit {
+    u64 au_end = 0;
+        
+    u32 au_size; // originally this syntax is part of RawBitstream
+        
+    std::print("AU[{:d}] size = {:d}", au_count, au_size);
+                
+    au_end = $ + au_size;
+    
+    pbu_count = 0; // reset number of PBU
+
+    char signature[4]; // 'aPv1'
+    PBU pbu[while($ < au_end)] [[inline]];
+};
+
+u32 raw_count = 0;
+
+struct RawBitstream {       
+    AccessUnit AU [[name(std::format("AU[{}]", raw_count))]];
+    raw_count += 1;
+} [[name(std::format("Raw[{}]", (raw_count - 1)))]];
+
+struct ApvBitstream {
+    RawBitstream Raw [[inline]];
+}[[inline]];
+
+ApvBitstream APV[while(!std::mem::eof())] @ 0x0 [[inline]];
\ No newline at end of file
diff --git a/version.txt b/version.txt
index 717d1cc..5edad9a 100644
--- a/version.txt
+++ b/version.txt
@@ -1 +1 @@
-v0.1.9.2
+v0.1.11.3.1
diff --git a/windows_x86_64_toolchain.cmake b/windows_x86_64_toolchain.cmake
new file mode 100644
index 0000000..4637a19
--- /dev/null
+++ b/windows_x86_64_toolchain.cmake
@@ -0,0 +1,15 @@
+set(CMAKE_SYSTEM_NAME Windows)
+set(CMAKE_SYSTEM_PROCESSOR x86_64)
+
+set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
+set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
+set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
+
+# Optionally, set the paths to libraries and headers
+set(CMAKE_FIND_ROOT_PATH /usr/x86_64-w64-mingw32)
+
+# Settings for searching for libraries and headers
+set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
+set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
+set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
+
```

