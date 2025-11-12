```diff
diff --git a/.appveyor.yml b/.appveyor.yml
index ee3d27ad3..70d5e00d4 100644
--- a/.appveyor.yml
+++ b/.appveyor.yml
@@ -2,8 +2,8 @@ version: 1.6.x-{build}
 
 branches:
   except:
-    - /libpng[0-1][0-7]/
-    - /v[0-1][.][0-7][.][0-9]+/
+    - /libpng[0-1][0-8]/
+    - /v[0-1][.][0-8][.][0-9]+/
 
 image:
   - Visual Studio 2022
@@ -77,5 +77,5 @@ build_script:
   - 'if "%TOOLCHAIN%"=="msys2" if "%AUTOMATION%"=="makefiles" C:\msys64\usr\bin\bash.exe -l "%APPVEYOR_BUILD_FOLDER%\ci\ci_verify_makefiles.sh"'
 
 cache:
-  - C:\tools\vcpkg\installed
-  - C:\msys64\var\cache\pacman
+  - 'C:\tools\vcpkg\installed'
+  - 'C:\msys64\var\cache\pacman'
diff --git a/.cmake-format.yaml b/.cmake-format.yaml
new file mode 100644
index 000000000..81a5e2643
--- /dev/null
+++ b/.cmake-format.yaml
@@ -0,0 +1,94 @@
+# https://pypi.org/project/cmakelang
+# https://github.com/cheshirekow/cmake_format
+
+# ----------------------
+# Options for formatting
+# ----------------------
+
+# How wide to allow formatted cmake files
+# TODO: Reflow the CMake files to allow setting the maximum line width to 100.
+line_width: 255
+
+# How many spaces to tab for indent
+tab_size: 2
+
+# If true, lines are indented using tab characters (utf-8 0x09) instead of
+# <tab_size> space characters (utf-8 0x20). In cases where the layout would
+# require a fractional tab character, the behavior of the fractional
+# indentation is governed by <fractional_tab_policy>
+use_tabchars: false
+
+# If <use_tabchars> is True, then the value of this variable indicates how
+# fractional indentions are handled during whitespace replacement. If set to
+# 'use-space', fractional indentation is left as spaces (utf-8 0x20). If set
+# to `round-up` fractional indentation is replaced with a single tab character
+# (utf-8 0x09) effectively shifting the column to the next tabstop
+fractional_tab_policy: "use-space"
+
+# Enable comment markup parsing and reflow
+enable_markup: false
+
+# -------------------
+# Options for linting
+# -------------------
+
+# Lint codes to disable
+disabled_codes: [
+  # TODO:
+  # Reconcile the CMake variable names with the patterns below, then
+  # re-enable the "invalid variable name XXX" messages.
+  "C0103",
+
+  # A custom command with one output doesn't really need a comment because
+  # the default "generating XXX" is a good message already.
+  "C0113",
+]
+
+# Regular expression pattern describing valid function names
+function_pattern: "[0-9a-z_]+"
+
+# Regular expression pattern describing valid macro names
+macro_pattern: "[0-9A-Z_]+"
+
+# Regular expression pattern describing valid names for variables with global
+# (cache) scope
+global_var_pattern: "[A-Z][0-9A-Z_]+"
+
+# Regular expression pattern describing valid names for variables with global
+# scope (but internal semantic)
+internal_var_pattern: "_[A-Z][0-9A-Z_]+"
+
+# Regular expression pattern describing valid names for variables with local
+# scope
+local_var_pattern: "[a-z][a-z0-9_]+"
+
+# Regular expression pattern describing valid names for privatedirectory
+# variables
+private_var_pattern: "_[0-9a-z_]+"
+
+# Regular expression pattern describing valid names for public directory
+# variables
+public_var_pattern: "[A-Z][0-9A-Z_]+"
+
+# Regular expression pattern describing valid names for function/macro
+# arguments and loop variables.
+argument_var_pattern: "[a-z][a-z0-9_]+"
+
+# Regular expression pattern describing valid names for keywords used in
+# functions or macros
+keyword_pattern: "[A-Z][0-9A-Z_]+"
+
+# In the heuristic for C0201, how many conditionals to match within a loop in
+# before considering the loop a parser
+max_conditionals_custom_parser: 2
+
+# Require at least this many newlines between statements
+min_statement_spacing: 1
+
+# Require no more than this many newlines between statements
+max_statement_spacing: 2
+max_returns: 6
+max_branches: 12
+max_arguments: 5
+max_localvars: 15
+max_statements: 50
diff --git a/.editorconfig b/.editorconfig
index f49b2a3e4..4181a3796 100644
--- a/.editorconfig
+++ b/.editorconfig
@@ -8,29 +8,41 @@ insert_final_newline = true
 trim_trailing_whitespace = true
 
 [*.txt]
+indent_size = unset
 indent_style = space
 
 [*.[chS]]
+indent_size = 3
 indent_style = space
 max_doc_length = 80
 max_line_length = 80
 
 [*.dfa]
+indent_size = 3
 indent_style = space
 max_doc_length = 80
 max_line_length = 80
 
-[*.{awk,cmake}]
+[*.awk]
+indent_size = 3
 indent_style = space
 max_doc_length = 80
 max_line_length = 100
 
-[*.{in,sh}]
+[*.cmake]
+indent_size = 2
+indent_style = space
+max_doc_length = 80
+max_line_length = 100
+
+[*.sh]
+indent_size = 4
 indent_style = space
 max_doc_length = 100
 max_line_length = 100
 
-[{Makefile.in,ltmain.sh}]
+[{Makefile.in,aclocal.m4,ltmain.sh}]
+indent_size = unset
 indent_style = unset
 insert_final_newline = unset
 max_doc_length = unset
diff --git a/.editorconfig-checker.json b/.editorconfig-checker.json
new file mode 100644
index 000000000..ef08e0801
--- /dev/null
+++ b/.editorconfig-checker.json
@@ -0,0 +1,9 @@
+{
+  "Disable": {
+    "IndentSize": true
+  },
+  "Exclude": [
+    ".git/",
+    "out/"
+  ]
+}
diff --git a/.github/workflows/lint.yml b/.github/workflows/lint.yml
index b41c10328..ddc483d99 100644
--- a/.github/workflows/lint.yml
+++ b/.github/workflows/lint.yml
@@ -4,9 +4,11 @@ on:
   push:
     branches:
       - libpng16
+      - libpng18
   pull_request:
     branches:
       - libpng16
+      - libpng18
 
 jobs:
   lint:
diff --git a/.gitignore b/.gitignore
index 52e789d2b..7245e536b 100644
--- a/.gitignore
+++ b/.gitignore
@@ -31,6 +31,7 @@
 # Compiled executables
 *.app/
 *.exe
+a.out
 
 # Debug files
 *.dSYM/
@@ -38,32 +39,111 @@
 *.pdb
 *.su
 
-# Libpng configuration and build artifacts
+# Tag files
+TAGS
+.TAGS
+!TAGS/
+tags
+.tags
+!tags/
+gtags.files
+GTAGS
+GRTAGS
+GPATH
+GSYMS
+cscope.files
+cscope.out
+cscope.*.out
+
+# Text editing and text processing artifacts
+\#*\#
+.\#*
+[._]*.sw[a-p]
+[._]sw[a-p]
+*.bak
+*.orig
+*.rej
+*.tmp
+*~
+
+# IDE files and directories
+## Eclipse
+.cproject/
+.project/
+.settings/
+## Embarcadero RAD Studio
+*.cbproj.*
+__recovery/
+## JetBrains
+.idea/
+## NetBeans
+nbbuild/
+nbdist/
+nbproject/
+## Visual Studio
+.vs/
+### Visual Studio user files
+*.rsuser
+*.sln.docstates
+*.suo
+*.user
+*.userprefs
+### Visual Studio cache files (for older versions)
+*.aps
+*.ncb
+*.opensdf
+*.sdf
+*.VC.db
+*.VC.opendb
+ipch/
+## Visual Studio Code
+.vscode/*
+!.vscode/extensions.json
+!.vscode/launch.json
+!.vscode/settings.json
+!.vscode/tasks.json
+## (Various)
+*.*cache
+*.cache*
+[._]*_history
+.history/
+[Bb]ackup*/
+
+# Build, test and CI output directories
+*[Dd]ebug/
+[Dd]ebug*/
+*[Rr]elease/
+[Rr]elease*/
+[._]build*/
+/[Bb]uild*/
+/[Oo]ut/
+
+# Libpng configuration and auxiliary build artifacts
 *.out
-.deps/
+*out.png
+[._]deps/
 .dirstamp
 /Makefile
 /autom4te.cache/
-/config.guess~
-/config.h.in~
+/config*~
+/config.h
 /config.log
 /config.status
-/config.sub~
-/configure~
-/install-sh~
-/libpng-config
-/libpng.pc
+/install*~
+/libpng*-config
+/libpng*.pc
 /libpng.vers
-/libpng16-config
-/libpng16.pc
 /libtool
 /stamp-h1
+CMake*.json
+!CMakePresets.json
+CMakeLists.txt.*
 pnglibconf.[ch]
 pnglibconf.dfn
 pnglibconf.pre
 pngprefix.h
 
-# Libpng test artifacts
+# Libpng test programs
 png-fix-itxt
 pngcp
 pngfix
@@ -73,7 +153,3 @@ pngtest
 pngunknown
 pngvalid
 timepng
-pngout.png
-
-# Libpng CI artifacts
-out/
diff --git a/.travis.yml b/.travis.yml
index f14e7c1ca..b93aa77d9 100644
--- a/.travis.yml
+++ b/.travis.yml
@@ -1,7 +1,7 @@
 branches:
   except:
-    - /libpng[0-1][0-7]/
-    - /v[0-1][.][0-7][.][0-9]+/
+    - /libpng[0-1][0-8]/
+    - /v[0-1][.][0-8][.][0-9]+/
 
 language: c
 
diff --git a/ANNOUNCE b/ANNOUNCE
index a2a7ac363..603b2df48 100644
--- a/ANNOUNCE
+++ b/ANNOUNCE
@@ -1,5 +1,5 @@
-libpng 1.6.44 - September 12, 2024
-==================================
+libpng 1.6.47 - February 18, 2025
+=================================
 
 This is a public release of libpng, intended for use in production code.
 
@@ -9,13 +9,13 @@ Files available for download
 
 Source files with LF line endings (for Unix/Linux):
 
- * libpng-1.6.44.tar.xz (LZMA-compressed, recommended)
- * libpng-1.6.44.tar.gz (deflate-compressed)
+ * libpng-1.6.47.tar.xz (LZMA-compressed, recommended)
+ * libpng-1.6.47.tar.gz (deflate-compressed)
 
 Source files with CRLF line endings (for Windows):
 
- * lpng1644.7z (LZMA-compressed, recommended)
- * lpng1644.zip (deflate-compressed)
+ * lpng1647.7z (LZMA-compressed, recommended)
+ * lpng1647.zip (deflate-compressed)
 
 Other information:
 
@@ -25,29 +25,19 @@ Other information:
  * TRADEMARK.md
 
 
-Changes from version 1.6.43 to version 1.6.44
+Changes from version 1.6.46 to version 1.6.47
 ---------------------------------------------
 
- * Hardened calculations in chroma handling to prevent overflows, and
-   relaxed a constraint in cHRM validation to accomodate the standard
-   ACES AP1 set of color primaries.
+ * Modified the behaviour of colorspace chunks in order to adhere
+   to the new precedence rules formulated in the latest draft of
+   the PNG Specification.
    (Contributed by John Bowler)
- * Removed the ASM implementation of ARM Neon optimizations and updated
-   the build accordingly. Only the remaining C implementation shall be
-   used from now on, thus ensuring the support of the PAC/BTI security
-   features on ARM64.
-   (Contributed by Ross Burton and John Bowler)
- * Fixed the pickup of the PNG_HARDWARE_OPTIMIZATIONS option in the
-   CMake build on FreeBSD/amd64. This is an important performance fix
-   on this platform.
- * Applied various fixes and improvements to the CMake build.
-   (Contributed by Eric Riff, Benjamin Buch and Erik Scholz)
- * Added fuzzing targets for the simplified read API.
-   (Contributed by Mikhail Khachayants)
- * Fixed a build error involving pngtest.c under a custom config.
-   This was a regression introduced in a code cleanup in libpng-1.6.43.
-   (Contributed by Ben Wagner)
- * Fixed and improved the config files for AppVeyor CI and Travis CI.
+ * Fixed a latent bug in `png_write_iCCP`.
+   This would have been a read-beyond-end-of-malloc vulnerability,
+   introduced early in the libpng-1.6.0 development, yet (fortunately!)
+   it was inaccessible before the above-mentioned modification of the
+   colorspace precedence rules, due to pre-existing colorspace checks.
+   (Reported by Bob Friesenhahn; fixed by John Bowler)
 
 
 Send comments/corrections/commendations to png-mng-implement at lists.sf.net.
diff --git a/AUTHORS b/AUTHORS
index 544341694..f30a4ee19 100644
--- a/AUTHORS
+++ b/AUTHORS
@@ -17,6 +17,7 @@ Authors, for copyright and licensing purposes.
  * James Yu
  * John Bowler
  * Kevin Bracey
+ * Lucas Chollet
  * Magnus Holmgren
  * Mandar Sahastrabuddhe
  * Mans Rullgard
diff --git a/CHANGES b/CHANGES
index 724ccca2d..834b5e192 100644
--- a/CHANGES
+++ b/CHANGES
@@ -6218,6 +6218,39 @@ Version 1.6.44 [September 12, 2024]
     (Contributed by Ben Wagner)
   Fixed and improved the config files for AppVeyor CI and Travis CI.
 
+Version 1.6.45 [January 7, 2025]
+  Added support for the cICP chunk.
+    (Contributed by Lucas Chollet and John Bowler)
+  Adjusted and improved various checks in colorspace calculations.
+    (Contributed by John Bowler)
+  Rearranged the write order of colorspace chunks for better conformance
+    with the PNG v3 draft specification.
+    (Contributed by John Bowler)
+  Raised the minimum required CMake version from 3.6 to 3.14.
+  Forked off a development branch for libpng version 1.8.
+
+Version 1.6.46 [January 23, 2025]
+  Added support for the mDCV and cLLI chunks.
+    (Contributed by John Bowler)
+  Fixed a build issue affecting C89 compilers.
+    This was a regression introduced in libpng-1.6.45.
+    (Contributed by John Bowler)
+  Added makefile.c89, specifically for testing C89 compilers.
+  Cleaned up contrib/pngminus: corrected an old typo, removed an old
+    workaround, and updated the CMake file.
+
+Version 1.6.47 [February 18, 2025]
+  Modified the behaviour of colorspace chunks in order to adhere
+    to the new precedence rules formulated in the latest draft of
+    the PNG Specification.
+    (Contributed by John Bowler)
+  Fixed a latent bug in `png_write_iCCP`.
+    This would have been a read-beyond-end-of-malloc vulnerability,
+    introduced early in the libpng-1.6.0 development, yet (fortunately!)
+    it was inaccessible before the above-mentioned modification of the
+    colorspace precedence rules, due to pre-existing colorspace checks.
+    (Reported by Bob Friesenhahn; fixed by John Bowler)
+
 Send comments/corrections/commendations to png-mng-implement at lists.sf.net.
 Subscription is required; visit
 https://lists.sourceforge.net/lists/listinfo/png-mng-implement
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 16cc2617d..4a97bd50e 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,9 +1,8 @@
-
 # CMakeLists.txt - CMake lists for libpng
 #
-# Copyright (c) 2018-2024 Cosmin Truta.
-# Copyright (c) 2007-2018 Glenn Randers-Pehrson.
-# Originally written by Christian Ehrlicher, 2007.
+# Copyright (c) 2018-2025 Cosmin Truta
+# Copyright (c) 2007-2018 Glenn Randers-Pehrson
+# Originally written by Christian Ehrlicher, 2007
 #
 # Use, modification and distribution are subject to
 # the same licensing terms and conditions as libpng.
@@ -15,11 +14,11 @@
 #
 # SPDX-License-Identifier: libpng-2.0
 
-cmake_minimum_required(VERSION 3.6)
+cmake_minimum_required(VERSION 3.14)
 
 set(PNGLIB_MAJOR 1)
 set(PNGLIB_MINOR 6)
-set(PNGLIB_REVISION 44)
+set(PNGLIB_REVISION 47)
 set(PNGLIB_SUBREVISION 0)
 #set(PNGLIB_SUBREVISION "git")
 set(PNGLIB_VERSION ${PNGLIB_MAJOR}.${PNGLIB_MINOR}.${PNGLIB_REVISION})
@@ -30,11 +29,6 @@ project(libpng
         VERSION ${PNGLIB_VERSION}
         LANGUAGES C ASM)
 
-if(POLICY CMP0074)
-  # Allow find_package() to use the ZLIB_ROOT variable, if available.
-  cmake_policy(SET CMP0074 NEW)
-endif()
-
 include(CheckCSourceCompiles)
 include(GNUInstallDirs)
 
@@ -69,7 +63,7 @@ option(PNG_TESTS "Build the libpng tests" ON)
 # Same as above, but for the third-party tools.
 # Although these tools are targetted at development environments only,
 # the users are allowed to override the option to build by default.
-if (ANDROID OR IOS)
+if(ANDROID OR IOS)
   option(PNG_TOOLS "Build the libpng tools" OFF)
 else()
   option(PNG_TOOLS "Build the libpng tools" ON)
@@ -98,7 +92,7 @@ option(PNG_HARDWARE_OPTIMIZATIONS "Enable hardware optimizations" ON)
 # to check CMAKE_OSX_ARCHITECTURES to identify which hardware-specific flags to
 # enable. Note that this will fail if you attempt to build a universal binary
 # in a single CMake invocation.
-if (APPLE AND CMAKE_OSX_ARCHITECTURES)
+if(APPLE AND CMAKE_OSX_ARCHITECTURES)
   string(TOLOWER "${CMAKE_OSX_ARCHITECTURES}" PNG_TARGET_ARCHITECTURE)
 else()
   string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" PNG_TARGET_ARCHITECTURE)
@@ -106,24 +100,25 @@ endif()
 message(STATUS "Building for target architecture: ${PNG_TARGET_ARCHITECTURE}")
 
 # Allow the users to specify a custom location of zlib.
-# This option is deprecated, and no longer needed with CMake 3.12 and newer.
-# Under the CMake policy CMP0074, if zlib is being built alongside libpng as a
-# subproject, its location can be passed on to CMake via the ZLIB_ROOT variable.
-option(PNG_BUILD_ZLIB "Custom zlib location, else find_package is used" OFF)
-if(NOT PNG_BUILD_ZLIB)
-  find_package(ZLIB REQUIRED)
-elseif(POLICY CMP0074)
+# With CMake 3.12 and newer, this option is no longer necessary.
+option(PNG_BUILD_ZLIB "[Deprecated; please use ZLIB_ROOT]" OFF)
+if(PNG_BUILD_ZLIB)
   if("x${ZLIB_ROOT}" STREQUAL "x")
-    message(DEPRECATION
-            "The option PNG_BUILD_ZLIB has been deprecated; please use ZLIB_ROOT instead")
+    message(SEND_ERROR
+            "The option PNG_BUILD_ZLIB=${PNG_BUILD_ZLIB} is no longer supported; "
+            "please use ZLIB_ROOT instead")
   else()
     message(SEND_ERROR
-            "The option PNG_BUILD_ZLIB=${PNG_BUILD_ZLIB} and "
-            "the variable ZLIB_ROOT=\"${ZLIB_ROOT}\" are mutually exclusive")
+            "The option PNG_BUILD_ZLIB=${PNG_BUILD_ZLIB} is no longer supported; "
+            "using ZLIB_ROOT=\"${ZLIB_ROOT}\"")
   endif()
 endif()
 
-if(UNIX AND NOT APPLE AND NOT BEOS AND NOT HAIKU AND NOT EMSCRIPTEN)
+find_package(ZLIB REQUIRED)
+
+if(UNIX
+   AND NOT (APPLE OR BEOS OR HAIKU)
+   AND NOT EMSCRIPTEN)
   find_library(M_LIBRARY m)
   if(M_LIBRARY)
     set(M_LIBRARY m)
@@ -136,188 +131,188 @@ endif()
 
 if(PNG_HARDWARE_OPTIMIZATIONS)
 
-# Set definitions and sources for ARM.
-if(PNG_TARGET_ARCHITECTURE MATCHES "^(arm|aarch)")
-  if(PNG_TARGET_ARCHITECTURE MATCHES "^(arm64|aarch64)")
-    set(PNG_ARM_NEON_POSSIBLE_VALUES on off)
-    set(PNG_ARM_NEON "on"
-        CACHE STRING "Enable ARM NEON optimizations: on|off; on is default")
-  else()
-    set(PNG_ARM_NEON_POSSIBLE_VALUES check on off)
-    set(PNG_ARM_NEON "off"
-        CACHE STRING "Enable ARM NEON optimizations: check|on|off; off is default")
-  endif()
-  set_property(CACHE PNG_ARM_NEON
-               PROPERTY STRINGS ${PNG_ARM_NEON_POSSIBLE_VALUES})
-  list(FIND PNG_ARM_NEON_POSSIBLE_VALUES ${PNG_ARM_NEON} index)
-  if(index EQUAL -1)
-    message(FATAL_ERROR "PNG_ARM_NEON must be one of [${PNG_ARM_NEON_POSSIBLE_VALUES}]")
-  elseif(NOT PNG_ARM_NEON STREQUAL "off")
-    set(libpng_arm_sources
-        arm/arm_init.c
-        arm/filter_neon_intrinsics.c
-        arm/palette_neon_intrinsics.c)
-    if(PNG_ARM_NEON STREQUAL "on")
-      add_definitions(-DPNG_ARM_NEON_OPT=2)
-    elseif(PNG_ARM_NEON STREQUAL "check")
-      add_definitions(-DPNG_ARM_NEON_CHECK_SUPPORTED)
+  # Set definitions and sources for ARM.
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(arm|aarch)")
+    if(PNG_TARGET_ARCHITECTURE MATCHES "^(arm64|aarch64)")
+      set(PNG_ARM_NEON_POSSIBLE_VALUES on off)
+      set(PNG_ARM_NEON "on"
+          CACHE STRING "Enable ARM NEON optimizations: on|off; on is default")
+    else()
+      set(PNG_ARM_NEON_POSSIBLE_VALUES check on off)
+      set(PNG_ARM_NEON "off"
+          CACHE STRING "Enable ARM NEON optimizations: check|on|off; off is default")
+    endif()
+    set_property(CACHE PNG_ARM_NEON
+                PROPERTY STRINGS ${PNG_ARM_NEON_POSSIBLE_VALUES})
+    list(FIND PNG_ARM_NEON_POSSIBLE_VALUES ${PNG_ARM_NEON} index)
+    if(index EQUAL -1)
+      message(FATAL_ERROR "PNG_ARM_NEON must be one of [${PNG_ARM_NEON_POSSIBLE_VALUES}]")
+    elseif(NOT PNG_ARM_NEON STREQUAL "off")
+      set(libpng_arm_sources
+          arm/arm_init.c
+          arm/filter_neon_intrinsics.c
+          arm/palette_neon_intrinsics.c)
+      if(PNG_ARM_NEON STREQUAL "on")
+        add_definitions(-DPNG_ARM_NEON_OPT=2)
+      elseif(PNG_ARM_NEON STREQUAL "check")
+        add_definitions(-DPNG_ARM_NEON_CHECK_SUPPORTED)
+      endif()
+    else()
+      add_definitions(-DPNG_ARM_NEON_OPT=0)
     endif()
-  else()
-    add_definitions(-DPNG_ARM_NEON_OPT=0)
   endif()
-endif()
 
-# Set definitions and sources for PowerPC.
-if(PNG_TARGET_ARCHITECTURE MATCHES "^(powerpc|ppc64)")
-  set(PNG_POWERPC_VSX_POSSIBLE_VALUES on off)
-  set(PNG_POWERPC_VSX "on"
-      CACHE STRING "Enable POWERPC VSX optimizations: on|off; on is default")
-  set_property(CACHE PNG_POWERPC_VSX
-               PROPERTY STRINGS ${PNG_POWERPC_VSX_POSSIBLE_VALUES})
-  list(FIND PNG_POWERPC_VSX_POSSIBLE_VALUES ${PNG_POWERPC_VSX} index)
-  if(index EQUAL -1)
-    message(FATAL_ERROR "PNG_POWERPC_VSX must be one of [${PNG_POWERPC_VSX_POSSIBLE_VALUES}]")
-  elseif(NOT PNG_POWERPC_VSX STREQUAL "off")
-    set(libpng_powerpc_sources
-        powerpc/powerpc_init.c
-        powerpc/filter_vsx_intrinsics.c)
-    if(PNG_POWERPC_VSX STREQUAL "on")
-      add_definitions(-DPNG_POWERPC_VSX_OPT=2)
+  # Set definitions and sources for PowerPC.
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(powerpc|ppc64)")
+    set(PNG_POWERPC_VSX_POSSIBLE_VALUES on off)
+    set(PNG_POWERPC_VSX "on"
+        CACHE STRING "Enable POWERPC VSX optimizations: on|off; on is default")
+    set_property(CACHE PNG_POWERPC_VSX
+                PROPERTY STRINGS ${PNG_POWERPC_VSX_POSSIBLE_VALUES})
+    list(FIND PNG_POWERPC_VSX_POSSIBLE_VALUES ${PNG_POWERPC_VSX} index)
+    if(index EQUAL -1)
+      message(FATAL_ERROR "PNG_POWERPC_VSX must be one of [${PNG_POWERPC_VSX_POSSIBLE_VALUES}]")
+    elseif(NOT PNG_POWERPC_VSX STREQUAL "off")
+      set(libpng_powerpc_sources
+          powerpc/powerpc_init.c
+          powerpc/filter_vsx_intrinsics.c)
+      if(PNG_POWERPC_VSX STREQUAL "on")
+        add_definitions(-DPNG_POWERPC_VSX_OPT=2)
+      endif()
+    else()
+      add_definitions(-DPNG_POWERPC_VSX_OPT=0)
     endif()
-  else()
-    add_definitions(-DPNG_POWERPC_VSX_OPT=0)
   endif()
-endif()
 
-# Set definitions and sources for Intel.
-if(PNG_TARGET_ARCHITECTURE MATCHES "^(i[3-6]86|x86|amd64)")
-  set(PNG_INTEL_SSE_POSSIBLE_VALUES on off)
-  set(PNG_INTEL_SSE "on"
-      CACHE STRING "Enable INTEL_SSE optimizations: on|off; on is default")
-  set_property(CACHE PNG_INTEL_SSE
-               PROPERTY STRINGS ${PNG_INTEL_SSE_POSSIBLE_VALUES})
-  list(FIND PNG_INTEL_SSE_POSSIBLE_VALUES ${PNG_INTEL_SSE} index)
-  if(index EQUAL -1)
-    message(FATAL_ERROR "PNG_INTEL_SSE must be one of [${PNG_INTEL_SSE_POSSIBLE_VALUES}]")
-  elseif(NOT PNG_INTEL_SSE STREQUAL "off")
-    set(libpng_intel_sources
-        intel/intel_init.c
-        intel/filter_sse2_intrinsics.c)
-    if(PNG_INTEL_SSE STREQUAL "on")
-      add_definitions(-DPNG_INTEL_SSE_OPT=1)
+  # Set definitions and sources for Intel.
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(i[3-6]86|x86|amd64)")
+    set(PNG_INTEL_SSE_POSSIBLE_VALUES on off)
+    set(PNG_INTEL_SSE "on"
+        CACHE STRING "Enable INTEL_SSE optimizations: on|off; on is default")
+    set_property(CACHE PNG_INTEL_SSE
+                PROPERTY STRINGS ${PNG_INTEL_SSE_POSSIBLE_VALUES})
+    list(FIND PNG_INTEL_SSE_POSSIBLE_VALUES ${PNG_INTEL_SSE} index)
+    if(index EQUAL -1)
+      message(FATAL_ERROR "PNG_INTEL_SSE must be one of [${PNG_INTEL_SSE_POSSIBLE_VALUES}]")
+    elseif(NOT PNG_INTEL_SSE STREQUAL "off")
+      set(libpng_intel_sources
+          intel/intel_init.c
+          intel/filter_sse2_intrinsics.c)
+      if(PNG_INTEL_SSE STREQUAL "on")
+        add_definitions(-DPNG_INTEL_SSE_OPT=1)
+      endif()
+    else()
+      add_definitions(-DPNG_INTEL_SSE_OPT=0)
     endif()
-  else()
-    add_definitions(-DPNG_INTEL_SSE_OPT=0)
   endif()
-endif()
 
-# Set definitions and sources for MIPS.
-if(PNG_TARGET_ARCHITECTURE MATCHES "^(mipsel|mips64el)")
-  set(PNG_MIPS_MSA_POSSIBLE_VALUES on off)
-  set(PNG_MIPS_MSA "on"
-      CACHE STRING "Enable MIPS_MSA optimizations: on|off; on is default")
-  set_property(CACHE PNG_MIPS_MSA
-               PROPERTY STRINGS ${PNG_MIPS_MSA_POSSIBLE_VALUES})
-  list(FIND PNG_MIPS_MSA_POSSIBLE_VALUES ${PNG_MIPS_MSA} index_msa)
-  if(index_msa EQUAL -1)
-    message(FATAL_ERROR "PNG_MIPS_MSA must be one of [${PNG_MIPS_MSA_POSSIBLE_VALUES}]")
-  endif()
+  # Set definitions and sources for MIPS.
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(mipsel|mips64el)")
+    set(PNG_MIPS_MSA_POSSIBLE_VALUES on off)
+    set(PNG_MIPS_MSA "on"
+        CACHE STRING "Enable MIPS_MSA optimizations: on|off; on is default")
+    set_property(CACHE PNG_MIPS_MSA
+                PROPERTY STRINGS ${PNG_MIPS_MSA_POSSIBLE_VALUES})
+    list(FIND PNG_MIPS_MSA_POSSIBLE_VALUES ${PNG_MIPS_MSA} index_msa)
+    if(index_msa EQUAL -1)
+      message(FATAL_ERROR "PNG_MIPS_MSA must be one of [${PNG_MIPS_MSA_POSSIBLE_VALUES}]")
+    endif()
 
-  set(PNG_MIPS_MMI_POSSIBLE_VALUES on off)
-  set(PNG_MIPS_MMI "on"
-      CACHE STRING "Enable MIPS_MMI optimizations: on|off; on is default")
-  set_property(CACHE PNG_MIPS_MMI
-               PROPERTY STRINGS ${PNG_MIPS_MMI_POSSIBLE_VALUES})
-  list(FIND PNG_MIPS_MMI_POSSIBLE_VALUES ${PNG_MIPS_MMI} index_mmi)
-  if(index_mmi EQUAL -1)
-    message(FATAL_ERROR "PNG_MIPS_MMI must be one of [${PNG_MIPS_MMI_POSSIBLE_VALUES}]")
-  endif()
+    set(PNG_MIPS_MMI_POSSIBLE_VALUES on off)
+    set(PNG_MIPS_MMI "on"
+        CACHE STRING "Enable MIPS_MMI optimizations: on|off; on is default")
+    set_property(CACHE PNG_MIPS_MMI
+                PROPERTY STRINGS ${PNG_MIPS_MMI_POSSIBLE_VALUES})
+    list(FIND PNG_MIPS_MMI_POSSIBLE_VALUES ${PNG_MIPS_MMI} index_mmi)
+    if(index_mmi EQUAL -1)
+      message(FATAL_ERROR "PNG_MIPS_MMI must be one of [${PNG_MIPS_MMI_POSSIBLE_VALUES}]")
+    endif()
 
-  if(PNG_MIPS_MSA STREQUAL "on" AND PNG_MIPS_MMI STREQUAL "on")
-    set(libpng_mips_sources
-        mips/mips_init.c
-        mips/filter_msa_intrinsics.c
-        mips/filter_mmi_inline_assembly.c)
-    add_definitions(-DPNG_MIPS_MSA_OPT=2)
-    add_definitions(-DPNG_MIPS_MMI_OPT=1)
-  elseif(PNG_MIPS_MSA STREQUAL "on")
-    set(libpng_mips_sources
-        mips/mips_init.c
-        mips/filter_msa_intrinsics.c)
-    add_definitions(-DPNG_MIPS_MSA_OPT=2)
-    add_definitions(-DPNG_MIPS_MMI_OPT=0)
-  elseif(PNG_MIPS_MMI STREQUAL "on")
-    set(libpng_mips_sources
-        mips/mips_init.c
-        mips/filter_mmi_inline_assembly.c)
-    add_definitions(-DPNG_MIPS_MSA_OPT=0)
-    add_definitions(-DPNG_MIPS_MMI_OPT=1)
+    if(PNG_MIPS_MSA STREQUAL "on" AND PNG_MIPS_MMI STREQUAL "on")
+      set(libpng_mips_sources
+          mips/mips_init.c
+          mips/filter_msa_intrinsics.c
+          mips/filter_mmi_inline_assembly.c)
+      add_definitions(-DPNG_MIPS_MSA_OPT=2)
+      add_definitions(-DPNG_MIPS_MMI_OPT=1)
+    elseif(PNG_MIPS_MSA STREQUAL "on")
+      set(libpng_mips_sources
+          mips/mips_init.c
+          mips/filter_msa_intrinsics.c)
+      add_definitions(-DPNG_MIPS_MSA_OPT=2)
+      add_definitions(-DPNG_MIPS_MMI_OPT=0)
+    elseif(PNG_MIPS_MMI STREQUAL "on")
+      set(libpng_mips_sources
+          mips/mips_init.c
+          mips/filter_mmi_inline_assembly.c)
+      add_definitions(-DPNG_MIPS_MSA_OPT=0)
+      add_definitions(-DPNG_MIPS_MMI_OPT=1)
     else()
-    add_definitions(-DPNG_MIPS_MSA_OPT=0)
-    add_definitions(-DPNG_MIPS_MMI_OPT=0)
+      add_definitions(-DPNG_MIPS_MSA_OPT=0)
+      add_definitions(-DPNG_MIPS_MMI_OPT=0)
     endif()
-endif()
+  endif()
 
-# Set definitions and sources for LoongArch.
-if(PNG_TARGET_ARCHITECTURE MATCHES "^(loongarch)")
-  include(CheckCCompilerFlag)
-  set(PNG_LOONGARCH_LSX_POSSIBLE_VALUES on off)
-  set(PNG_LOONGARCH_LSX "on"
-      CACHE STRING "Enable LOONGARCH_LSX optimizations: on|off; on is default")
-  set_property(CACHE PNG_LOONGARCH_LSX
-               PROPERTY STRINGS ${PNG_LOONGARCH_LSX_POSSIBLE_VALUES})
-  list(FIND PNG_LOONGARCH_LSX_POSSIBLE_VALUES ${PNG_LOONGARCH_LSX} index)
-  if(index EQUAL -1)
-    message(FATAL_ERROR "PNG_LOONGARCH_LSX must be one of [${PNG_LOONGARCH_LSX_POSSIBLE_VALUES}]")
-  elseif(NOT PNG_LOONGARCH_LSX STREQUAL "off")
-    CHECK_C_COMPILER_FLAG("-mlsx" COMPILER_SUPPORTS_LSX)
-    if(COMPILER_SUPPORTS_LSX)
-      set(libpng_loongarch_sources
-          loongarch/loongarch_lsx_init.c
-          loongarch/filter_lsx_intrinsics.c)
-      set_source_files_properties(${libpng_loongarch_sources}
-                                  PROPERTIES
-                                  COMPILE_FLAGS "-mlsx")
-      add_definitions(-DPNG_LOONGARCH_LSX_OPT=1)
+  # Set definitions and sources for LoongArch.
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(loongarch)")
+    include(CheckCCompilerFlag)
+    set(PNG_LOONGARCH_LSX_POSSIBLE_VALUES on off)
+    set(PNG_LOONGARCH_LSX "on"
+        CACHE STRING "Enable LOONGARCH_LSX optimizations: on|off; on is default")
+    set_property(CACHE PNG_LOONGARCH_LSX
+                PROPERTY STRINGS ${PNG_LOONGARCH_LSX_POSSIBLE_VALUES})
+    list(FIND PNG_LOONGARCH_LSX_POSSIBLE_VALUES ${PNG_LOONGARCH_LSX} index)
+    if(index EQUAL -1)
+      message(FATAL_ERROR "PNG_LOONGARCH_LSX must be one of [${PNG_LOONGARCH_LSX_POSSIBLE_VALUES}]")
+    elseif(NOT PNG_LOONGARCH_LSX STREQUAL "off")
+      CHECK_C_COMPILER_FLAG("-mlsx" COMPILER_SUPPORTS_LSX)
+      if(COMPILER_SUPPORTS_LSX)
+        set(libpng_loongarch_sources
+            loongarch/loongarch_lsx_init.c
+            loongarch/filter_lsx_intrinsics.c)
+        set_source_files_properties(${libpng_loongarch_sources}
+                                    PROPERTIES
+                                    COMPILE_FLAGS "-mlsx")
+        add_definitions(-DPNG_LOONGARCH_LSX_OPT=1)
+      else()
+        message(FATAL_ERROR "Compiler does not support -mlsx option")
+      endif()
     else()
-      message(FATAL_ERROR "Compiler does not support -mlsx option")
+      add_definitions(-DPNG_LOONGARCH_LSX_OPT=0)
     endif()
-  else()
-    add_definitions(-DPNG_LOONGARCH_LSX_OPT=0)
   endif()
-endif()
 
 else(PNG_HARDWARE_OPTIMIZATIONS)
 
-# Set definitions and sources for ARM.
-if(PNG_TARGET_ARCHITECTURE MATCHES "^(arm|aarch)")
-  add_definitions(-DPNG_ARM_NEON_OPT=0)
-endif()
+  # Set definitions and sources for ARM.
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(arm|aarch)")
+    add_definitions(-DPNG_ARM_NEON_OPT=0)
+  endif()
 
-# Set definitions and sources for PowerPC.
-if(PNG_TARGET_ARCHITECTURE MATCHES "^(powerpc|ppc64)")
-  add_definitions(-DPNG_POWERPC_VSX_OPT=0)
-endif()
+  # Set definitions and sources for PowerPC.
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(powerpc|ppc64)")
+    add_definitions(-DPNG_POWERPC_VSX_OPT=0)
+  endif()
 
-# Set definitions and sources for Intel.
-if(PNG_TARGET_ARCHITECTURE MATCHES "^(i[3-6]86|x86|amd64)")
-  add_definitions(-DPNG_INTEL_SSE_OPT=0)
-endif()
+  # Set definitions and sources for Intel.
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(i[3-6]86|x86|amd64)")
+    add_definitions(-DPNG_INTEL_SSE_OPT=0)
+  endif()
 
-# Set definitions and sources for MIPS.
-if(PNG_TARGET_ARCHITECTURE MATCHES "^(mipsel|mips64el)")
-  add_definitions(-DPNG_MIPS_MSA_OPT=0)
-endif()
+  # Set definitions and sources for MIPS.
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(mipsel|mips64el)")
+    add_definitions(-DPNG_MIPS_MSA_OPT=0)
+  endif()
 
-# Set definitions and sources for LoongArch.
-if(PNG_TARGET_ARCHITECTURE MATCHES "^(loongarch)")
-  add_definitions(-DPNG_LOONGARCH_LSX_OPT=0)
-endif()
+  # Set definitions and sources for LoongArch.
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(loongarch)")
+    add_definitions(-DPNG_LOONGARCH_LSX_OPT=0)
+  endif()
 
 endif(PNG_HARDWARE_OPTIMIZATIONS)
 
 option(ld-version-script "Enable linker version script" ON)
-if(ld-version-script AND NOT ANDROID AND NOT APPLE)
+if(ld-version-script AND NOT (ANDROID OR APPLE))
   # Check if LD supports linker scripts.
   file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/conftest.map" "
 VERS_1 { global: sym1; local: *; };
@@ -363,12 +358,15 @@ else()
   message(STATUS "Could not find an AWK-compatible program")
 endif()
 
-if(NOT AWK OR ANDROID OR IOS)
+if(NOT AWK OR (ANDROID OR IOS))
   # No awk available to generate sources; use pre-built pnglibconf.h
   configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/pnglibconf.h.prebuilt
                  ${CMAKE_CURRENT_BINARY_DIR}/pnglibconf.h)
   add_custom_target(png_genfiles)
 else()
+  # Include the internal module PNGGenConfig.cmake
+  include(${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake/PNGGenConfig.cmake)
+
   # Copy the awk scripts, converting their line endings to Unix (LF)
   configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/checksym.awk
                  ${CMAKE_CURRENT_BINARY_DIR}/scripts/checksym.awk
@@ -383,93 +381,6 @@ else()
                  @ONLY
                  NEWLINE_STYLE LF)
 
-  # Generate .chk from .out with awk:
-  # generate_chk(INPUT inputfile OUTPUT outputfile [DEPENDS dep1 [dep2...]])
-  function(generate_chk)
-    set(options)
-    set(oneValueArgs INPUT OUTPUT)
-    set(multiValueArgs DEPENDS)
-    cmake_parse_arguments(_GC "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
-    if(NOT _GC_INPUT)
-      message(FATAL_ERROR "generate_chk: Missing INPUT argument")
-    endif()
-    if(NOT _GC_OUTPUT)
-      message(FATAL_ERROR "generate_chk: Missing OUTPUT argument")
-    endif()
-
-    add_custom_command(OUTPUT "${_GC_OUTPUT}"
-                       COMMAND "${CMAKE_COMMAND}"
-                               "-DINPUT=${_GC_INPUT}"
-                               "-DOUTPUT=${_GC_OUTPUT}"
-                               -P "${CMAKE_CURRENT_BINARY_DIR}/scripts/cmake/genchk.cmake"
-                       DEPENDS "${_GC_INPUT}" ${_GC_DEPENDS}
-                       WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
-  endfunction()
-
-  # Generate .out from .c with awk
-  # generate_out(INPUT inputfile OUTPUT outputfile [DEPENDS dep1 [dep2...]])
-  function(generate_out)
-    set(options)
-    set(oneValueArgs INPUT OUTPUT)
-    set(multiValueArgs DEPENDS)
-    cmake_parse_arguments(_GO "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
-    if(NOT _GO_INPUT)
-      message(FATAL_ERROR "generate_out: Missing INPUT argument")
-    endif()
-    if(NOT _GO_OUTPUT)
-      message(FATAL_ERROR "generate_out: Missing OUTPUT argument")
-    endif()
-
-    add_custom_command(OUTPUT "${_GO_OUTPUT}"
-                       COMMAND "${CMAKE_COMMAND}"
-                               "-DINPUT=${_GO_INPUT}"
-                               "-DOUTPUT=${_GO_OUTPUT}"
-                               -P "${CMAKE_CURRENT_BINARY_DIR}/scripts/cmake/genout.cmake"
-                       DEPENDS "${_GO_INPUT}" ${_GO_DEPENDS}
-                       WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
-  endfunction()
-
-  # Generate specific source file with awk
-  # generate_source(OUTPUT outputfile [DEPENDS dep1 [dep2...]])
-  function(generate_source)
-    set(options)
-    set(oneValueArgs OUTPUT)
-    set(multiValueArgs DEPENDS)
-    cmake_parse_arguments(_GSO "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
-    if(NOT _GSO_OUTPUT)
-      message(FATAL_ERROR "generate_source: Missing OUTPUT argument")
-    endif()
-
-    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${_GSO_OUTPUT}"
-                       COMMAND "${CMAKE_COMMAND}"
-                               "-DOUTPUT=${_GSO_OUTPUT}"
-                               -P "${CMAKE_CURRENT_BINARY_DIR}/scripts/cmake/gensrc.cmake"
-                       DEPENDS ${_GSO_DEPENDS}
-                       WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
-  endfunction()
-
-  # Copy file
-  # generate_copy(INPUT inputfile OUTPUT outputfile [DEPENDS dep1 [dep2...]])
-  function(generate_copy)
-    set(options)
-    set(oneValueArgs INPUT OUTPUT)
-    set(multiValueArgs DEPENDS)
-    cmake_parse_arguments(_GCO "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
-    if(NOT _GCO_INPUT)
-      message(FATAL_ERROR "generate_copy: Missing INPUT argument")
-    endif()
-    if(NOT _GCO_OUTPUT)
-      message(FATAL_ERROR "generate_copy: Missing OUTPUT argument")
-    endif()
-
-    add_custom_command(OUTPUT "${_GCO_OUTPUT}"
-                       COMMAND "${CMAKE_COMMAND}"
-                               -E remove "${_GCO_OUTPUT}"
-                       COMMAND "${CMAKE_COMMAND}"
-                               -E copy "${_GCO_INPUT}" "${_GCO_OUTPUT}"
-                       DEPENDS "${source}" ${_GCO_DEPENDS})
-  endfunction()
-
   # Generate scripts/pnglibconf.h
   generate_source(OUTPUT "scripts/pnglibconf.c"
                   DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/scripts/pnglibconf.dfa"
@@ -591,7 +502,7 @@ else()
                             "${CMAKE_CURRENT_BINARY_DIR}/scripts/symbols.chk" png_scripts_symbols_chk
                             "${CMAKE_CURRENT_BINARY_DIR}/scripts/symbols.out" png_scripts_symbols_out
                             "${CMAKE_CURRENT_BINARY_DIR}/scripts/vers.out" png_scripts_vers_out)
-endif(NOT AWK OR ANDROID OR IOS)
+endif(NOT AWK OR (ANDROID OR IOS))
 
 # List the source code files.
 set(libpng_public_hdrs
@@ -605,7 +516,7 @@ set(libpng_private_hdrs
     pnginfo.h
     pngstruct.h
 )
-if(AWK AND NOT ANDROID AND NOT IOS)
+if(AWK AND NOT (ANDROID OR IOS))
   list(APPEND libpng_private_hdrs "${CMAKE_CURRENT_BINARY_DIR}/pngprefix.h")
 endif()
 set(libpng_sources
@@ -776,30 +687,8 @@ endif()
 if(PNG_TESTS AND PNG_SHARED)
   enable_testing()
 
-  function(png_add_test)
-    set(options)
-    set(oneValueArgs NAME COMMAND)
-    set(multiValueArgs OPTIONS FILES)
-    cmake_parse_arguments(_PAT "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
-    if(NOT _PAT_NAME)
-      message(FATAL_ERROR "png_add_test: Missing NAME argument")
-    endif()
-    if(NOT _PAT_COMMAND)
-      message(FATAL_ERROR "png_add_test: Missing COMMAND argument")
-    endif()
-
-    set(TEST_OPTIONS "${_PAT_OPTIONS}")
-    set(TEST_FILES "${_PAT_FILES}")
-
-    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake/test.cmake.in"
-                   "${CMAKE_CURRENT_BINARY_DIR}/tests/${_PAT_NAME}.cmake"
-                   @ONLY)
-    add_test(NAME "${_PAT_NAME}"
-             COMMAND "${CMAKE_COMMAND}"
-                     "-DLIBPNG=$<TARGET_FILE:png_shared>"
-                     "-DTEST_COMMAND=$<TARGET_FILE:${_PAT_COMMAND}>"
-                     -P "${CMAKE_CURRENT_BINARY_DIR}/tests/${_PAT_NAME}.cmake")
-  endfunction()
+  # Include the internal module PNGTest.cmake
+  include(${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake/PNGTest.cmake)
 
   # Find test PNG files by globbing, but sort lists to ensure
   # consistency between different filesystems.
@@ -807,6 +696,8 @@ if(PNG_TESTS AND PNG_SHARED)
   list(SORT PNGSUITE_PNGS)
   file(GLOB TEST_PNGS "${CMAKE_CURRENT_SOURCE_DIR}/contrib/testpngs/*.png")
   list(SORT TEST_PNGS)
+  file(GLOB TEST_PNG3_PNGS "${CMAKE_CURRENT_SOURCE_DIR}/contrib/testpngs/png-3/*.png")
+  list(SORT TEST_PNG3_PNGS)
 
   set(PNGTEST_PNG "${CMAKE_CURRENT_SOURCE_DIR}/pngtest.png")
 
@@ -817,6 +708,10 @@ if(PNG_TESTS AND PNG_SHARED)
                COMMAND pngtest
                FILES "${PNGTEST_PNG}")
 
+  png_add_test(NAME pngtest-png-3
+               COMMAND pngtest
+               FILES "${TEST_PNG3_PNGS}")
+
   add_executable(pngvalid ${pngvalid_sources})
   target_link_libraries(pngvalid PRIVATE png_shared)
 
@@ -973,9 +868,14 @@ if(PNG_SHARED AND PNG_TOOLS)
   list(APPEND PNG_BIN_TARGETS png-fix-itxt)
 endif()
 
-# Create a symlink from src to dest (if possible), or, alternatively,
-# copy src to dest if different.
+# Create a symlink that points to a target file (if symlinking is possible),
+# or make a copy of the target file (if symlinking is not possible):
+# create_symlink(<destfile> [FILE <file> | TARGET <target>])
 function(create_symlink DEST_FILE)
+  # TODO:
+  # Replace this implementation with CMake's built-in create_symlink function,
+  # which has been fully functional on all platforms, including Windows, since
+  # CMake version 3.13.
   cmake_parse_arguments(_SYM "" "FILE;TARGET" "" ${ARGN})
   if(NOT _SYM_FILE AND NOT _SYM_TARGET)
     message(FATAL_ERROR "create_symlink: Missing FILE or TARGET argument")
diff --git a/INSTALL b/INSTALL
index 042d72929..df1a49446 100644
--- a/INSTALL
+++ b/INSTALL
@@ -1,4 +1,3 @@
-
     Installing libpng
 
 Contents
diff --git a/LICENSE b/LICENSE
index 25f298f0f..ea6df986c 100644
--- a/LICENSE
+++ b/LICENSE
@@ -4,8 +4,8 @@ COPYRIGHT NOTICE, DISCLAIMER, and LICENSE
 PNG Reference Library License version 2
 ---------------------------------------
 
- * Copyright (c) 1995-2024 The PNG Reference Library Authors.
- * Copyright (c) 2018-2024 Cosmin Truta.
+ * Copyright (c) 1995-2025 The PNG Reference Library Authors.
+ * Copyright (c) 2018-2025 Cosmin Truta.
  * Copyright (c) 2000-2002, 2004, 2006-2018 Glenn Randers-Pehrson.
  * Copyright (c) 1996-1997 Andreas Dilger.
  * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
diff --git a/METADATA b/METADATA
index a16eb8122..9426f1eed 100644
--- a/METADATA
+++ b/METADATA
@@ -10,13 +10,13 @@ third_party {
     tag: "NVD-CPE2.3:cpe:/a:libpng:libpng:1.6.37"
   }
   last_upgrade_date {
-    year: 2024
-    month: 9
-    day: 16
+    year: 2025
+    month: 3
+    day: 31
   }
   identifier {
     type: "Git"
     value: "https://github.com/glennrp/libpng.git"
-    version: "v1.6.44"
+    version: "v1.6.47"
   }
 }
diff --git a/Makefile.am b/Makefile.am
index eed986c2b..217f1af84 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -1,6 +1,6 @@
 # Makefile.am, the source file for Makefile.in (and hence Makefile), is
 #
-# Copyright (c) 2018-2024 Cosmin Truta
+# Copyright (c) 2018-2025 Cosmin Truta
 # Copyright (c) 2004-2016 Glenn Randers-Pehrson
 #
 # This code is released under the libpng license.
@@ -199,7 +199,7 @@ MAINTAINERCLEANFILES = Makefile.in aclocal.m4 config.guess config.h.in \
 config.sub configure depcomp install-sh ltmain.sh missing
 
 # PNG_COPTS give extra options for the C compiler to be used on all compilation
-# steps (unless targe_CFLAGS is specified; that will take precedence over
+# steps (unless target_CFLAGS is specified; that will take precedence over
 # AM_CFLAGS)
 PNG_COPTS = @PNG_COPTS@
 AM_CFLAGS = ${PNG_COPTS}
diff --git a/Makefile.in b/Makefile.in
index 44b6936b7..a8dc362bd 100644
--- a/Makefile.in
+++ b/Makefile.in
@@ -16,7 +16,7 @@
 
 # Makefile.am, the source file for Makefile.in (and hence Makefile), is
 #
-# Copyright (c) 2018-2024 Cosmin Truta
+# Copyright (c) 2018-2025 Cosmin Truta
 # Copyright (c) 2004-2016 Glenn Randers-Pehrson
 #
 # This code is released under the libpng license.
@@ -687,7 +687,7 @@ PNGLIB_RELEASE = @PNGLIB_RELEASE@
 PNGLIB_VERSION = @PNGLIB_VERSION@
 
 # PNG_COPTS give extra options for the C compiler to be used on all compilation
-# steps (unless targe_CFLAGS is specified; that will take precedence over
+# steps (unless target_CFLAGS is specified; that will take precedence over
 # AM_CFLAGS)
 PNG_COPTS = @PNG_COPTS@
 PNG_PREFIX = @PNG_PREFIX@
diff --git a/README b/README
index 3af606889..57952fb21 100644
--- a/README
+++ b/README
@@ -1,4 +1,4 @@
-README for libpng version 1.6.44
+README for libpng version 1.6.47
 ================================
 
 See the note about version numbers near the top of `png.h`.
@@ -157,8 +157,6 @@ Files included in this distribution
                           "PNG: The Definitive Guide" by Greg Roelofs,
                           O'Reilly, 1999
         libtests/     =>  Test programs
-        oss-fuzz/     =>  Files used by the OSS-Fuzz project for fuzz-testing
-                          libpng
         pngexif/      =>  Program to inspect the EXIF information in PNG files
         pngminim/     =>  Minimal decoder, encoder, and progressive decoder
                           programs demonstrating the use of pngusr.dfa
diff --git a/TODO b/TODO
index 562dab069..8ddb7d123 100644
--- a/TODO
+++ b/TODO
@@ -1,23 +1,22 @@
-TODO - list of things to do for libpng:
+TODO list for libpng
+--------------------
 
-* Fix all defects (duh!)
-* Better C++ wrapper / full C++ implementation (?)
-* Fix the problems with C++ and 'extern "C"'.
-* cHRM transformation.
-* Palette creation.
-* "grayscale->palette" transformation and "palette->grayscale" detection.
-* Improved dithering.
-* Multi-lingual error and warning message support.
-* Complete sRGB transformation.  (Currently it simply uses gamma=0.45455.)
-* Man pages for function calls.
-* Better documentation.
-* Better filter selection
-  (e.g., counting huffman bits/precompression; filter inertia; filter costs).
-* Histogram creation.
-* Text conversion between different code pages (e.g., Latin-1 -> Mac).
-* Avoid building gamma tables whenever possible.
-* Greater precision in changing to linear gamma for compositing against
-  background, and in doing rgb-to-gray transformations.
-* Investigate pre-incremented loop counters and other loop constructions.
-* Interpolated method of handling interlacing.
-* More validations for libpng transformations.
+ * Fix all defects (duh!)
+ * cHRM transformation.
+ * Palette creation.
+ * "grayscale->palette" transformation and "palette->grayscale" detection.
+ * Improved dithering.
+ * Multi-lingual error and warning message support.
+ * Complete sRGB transformation.  (Currently it simply uses gamma=0.45455.)
+ * Man pages for function calls.
+ * Better documentation.
+ * Better filter selection
+   (e.g., counting huffman bits/precompression; filter inertia; filter costs).
+ * Histogram creation.
+ * Text conversion between different code pages (e.g., Latin-1 to Mac).
+ * Avoid building gamma tables whenever possible.
+ * Greater precision in changing to linear gamma for compositing against
+   background, and in doing rgb-to-gray transformations.
+ * Investigate pre-incremented loop counters and other loop constructions.
+ * Interpolated method of handling interlacing.
+ * More validations for libpng transformations.
diff --git a/aclocal.m4 b/aclocal.m4
index b93b608e4..0a6cb3f20 100644
--- a/aclocal.m4
+++ b/aclocal.m4
@@ -899,7 +899,7 @@ am_cv_filesystem_timestamp_resolution=2
 # Don't try 1 sec, because if 0.01 sec and 0.1 sec don't work,
 # - 1 sec is not much of a win compared to 2 sec, and
 # - it takes 2 seconds to perform the test whether 1 sec works.
-#
+# 
 # Instead, just use the default 2s on platforms that have 1s resolution,
 # accept the extra 1s delay when using $sleep in the Automake tests, in
 # exchange for not incurring the 2s delay for running the test for all
@@ -972,7 +972,7 @@ for am_try_res in $am_try_resolutions; do
       # everything else supports the subsecond mtimes, but make doesn't;
       # notably on macOS, which ships make 3.81 from 2006 (the last one
       # released under GPLv2). https://bugs.gnu.org/68808
-      #
+      # 
       # We test $MAKE if it is defined in the environment, else "make".
       # It might get overridden later, but our hope is that in practice
       # it does not matter: it is the system "make" which is (by far)
diff --git a/arm/arm_init.c b/arm/arm_init.c
index 84d05556f..50376081a 100644
--- a/arm/arm_init.c
+++ b/arm/arm_init.c
@@ -1,4 +1,3 @@
-
 /* arm_init.c - NEON optimised filter functions
  *
  * Copyright (c) 2018-2022 Cosmin Truta
diff --git a/arm/filter_neon.S b/arm/filter_neon.S
index fc3c7a296..0cbd372cb 100644
--- a/arm/filter_neon.S
+++ b/arm/filter_neon.S
@@ -1,4 +1,3 @@
-
 /* filter_neon.S - placeholder file
  *
  * Copyright (c) 2024 Cosmin Truta
diff --git a/arm/filter_neon_intrinsics.c b/arm/filter_neon_intrinsics.c
index 4466d48b2..7c3e0da4d 100644
--- a/arm/filter_neon_intrinsics.c
+++ b/arm/filter_neon_intrinsics.c
@@ -1,4 +1,3 @@
-
 /* filter_neon_intrinsics.c - NEON optimised filter functions
  *
  * Copyright (c) 2018 Cosmin Truta
diff --git a/arm/palette_neon_intrinsics.c b/arm/palette_neon_intrinsics.c
index 92c7d6f9f..3068e9b6e 100644
--- a/arm/palette_neon_intrinsics.c
+++ b/arm/palette_neon_intrinsics.c
@@ -1,4 +1,3 @@
-
 /* palette_neon_intrinsics.c - NEON optimised palette expansion functions
  *
  * Copyright (c) 2018-2019 Cosmin Truta
@@ -64,7 +63,7 @@ png_do_expand_palette_rgba8_neon(png_structrp png_ptr, png_row_infop row_info,
 {
    png_uint_32 row_width = row_info->width;
    const png_uint_32 *riffled_palette =
-      (const png_uint_32 *)png_ptr->riffled_palette;
+      png_aligncastconst(png_const_uint_32p, png_ptr->riffled_palette);
    const png_uint_32 pixels_per_chunk = 4;
    png_uint_32 i;
 
diff --git a/ci/README.md b/ci/README.md
new file mode 100644
index 000000000..f26229ce0
--- /dev/null
+++ b/ci/README.md
@@ -0,0 +1,25 @@
+Scripts for the Continuous Integration of the PNG Reference Library
+===================================================================
+
+Copyright Notice
+----------------
+
+Copyright (c) 2019-2024 Cosmin Truta.
+
+Use, modification and distribution are subject to the MIT License.
+Please see the accompanying file `LICENSE_MIT.txt` or visit
+https://opensource.org/license/mit
+
+File List
+---------
+
+    LICENSE_MIT.txt         ==>  The License file
+    README.md               ==>  This file
+    ci_lint.sh              ==>  Lint the source code
+    ci_shellify.sh          ==>  Convert select definitions to shell syntax
+    ci_verify_cmake.sh      ==>  Verify the build driven by CMakeLists.txt
+    ci_verify_configure.sh  ==>  Verify the build driven by configure
+    ci_verify_makefiles.sh  ==>  Verify the build driven by scripts/makefile.*
+    ci_verify_version.sh    ==>  Verify the consistency of version definitions
+    lib/ci.lib.sh           ==>  Shell utilities for the main ci_*.sh scripts
+    targets/*/ci_env.*.sh   ==>  Shell environments for cross-platform testing
diff --git a/ci/ci_lint.sh b/ci/ci_lint.sh
index d1754715d..163d955de 100755
--- a/ci/ci_lint.sh
+++ b/ci/ci_lint.sh
@@ -80,7 +80,7 @@ function ci_lint_text_files {
     }
     ci_info "## LINTING: text files ##"
     ci_spawn "$CI_EDITORCONFIG_CHECKER" --version
-    ci_spawn "$CI_EDITORCONFIG_CHECKER" || {
+    ci_spawn "$CI_EDITORCONFIG_CHECKER" --config .editorconfig-checker.json || {
         # Linting failed.
         return 1
     }
@@ -93,7 +93,9 @@ function ci_lint_yaml_files {
     }
     ci_info "## LINTING: YAML files ##"
     ci_spawn "$CI_YAMLLINT" --version
-    find . \( -iname "*.yml" -o -iname "*.yaml" \) -not -path "./out/*" | {
+    # Considering that the YAML format is an extension of the JSON format,
+    # we can lint both the YAML files and the plain JSON files here.
+    find . \( -iname "*.yml" -o -iname "*.yaml" -o -iname "*.json" \) -not -path "./out/*" | {
         local my_file
         while IFS="" read -r my_file
         do
diff --git a/ci/ci_verify_cmake.sh b/ci/ci_verify_cmake.sh
index 9fe634026..3e05ec309 100755
--- a/ci/ci_verify_cmake.sh
+++ b/ci/ci_verify_cmake.sh
@@ -17,12 +17,6 @@ CI_OUT_DIR="$CI_TOPLEVEL_DIR/out"
 CI_BUILD_DIR="$CI_OUT_DIR/ci_verify_cmake.$CI_TARGET_SYSTEM.$CI_TARGET_ARCH.build"
 CI_INSTALL_DIR="$CI_OUT_DIR/ci_verify_cmake.$CI_TARGET_SYSTEM.$CI_TARGET_ARCH.install"
 
-# Keep the following relative paths in sync with the absolute paths.
-# We use them for the benefit of native Windows tools that might be
-# otherwise confused by the path encoding used by Bash-on-Windows.
-CI_BUILD_TO_SRC_RELDIR="../.."
-CI_BUILD_TO_INSTALL_RELDIR="../ci_verify_cmake.$CI_TARGET_SYSTEM.$CI_TARGET_ARCH.install"
-
 function ci_init_build {
     # Ensure that the mandatory variables are initialized.
     CI_CMAKE="${CI_CMAKE:-cmake}"
@@ -70,6 +64,7 @@ function ci_trace_build {
     ci_info "environment option: \$CI_RANLIB: '$CI_RANLIB'"
     ci_info "environment option: \$CI_SANITIZERS: '$CI_SANITIZERS'"
     ci_info "environment option: \$CI_FORCE: '$CI_FORCE'"
+    ci_info "environment option: \$CI_NO_BUILD: '$CI_NO_BUILD'"
     ci_info "environment option: \$CI_NO_TEST: '$CI_NO_TEST'"
     ci_info "environment option: \$CI_NO_INSTALL: '$CI_NO_INSTALL'"
     ci_info "environment option: \$CI_NO_CLEAN: '$CI_NO_CLEAN'"
@@ -148,40 +143,35 @@ function ci_build {
     all_cmake_build_flags+=($CI_CMAKE_BUILD_FLAGS)
     all_ctest_flags+=($CI_CTEST_FLAGS)
     # And... build!
-    # Use $CI_BUILD_TO_SRC_RELDIR and $CI_BUILD_TO_INSTALL_RELDIR
-    # instead of $CI_SRC_DIR and $CI_INSTALL_DIR from this point onwards.
     ci_spawn mkdir -p "$CI_BUILD_DIR"
-    ci_spawn cd "$CI_BUILD_DIR"
-    [[ $CI_BUILD_TO_SRC_RELDIR -ef $CI_SRC_DIR ]] || {
-        ci_err_internal "bad or missing \$CI_BUILD_TO_SRC_RELDIR"
-    }
-    ci_spawn mkdir -p "$CI_INSTALL_DIR"
-    [[ $CI_BUILD_TO_INSTALL_RELDIR -ef $CI_INSTALL_DIR ]] || {
-        ci_err_internal "bad or missing \$CI_BUILD_TO_INSTALL_RELDIR"
-    }
     # Spawn "cmake ...".
-    ci_spawn "$CI_CMAKE" -DCMAKE_INSTALL_PREFIX="$CI_BUILD_TO_INSTALL_RELDIR" \
-                         "${all_cmake_vars[@]}" \
-                         "$CI_BUILD_TO_SRC_RELDIR"
-    # Spawn "cmake --build ...".
-    ci_spawn "$CI_CMAKE" --build . \
-                         --config "$CI_CMAKE_BUILD_TYPE" \
-                         "${all_cmake_build_flags[@]}"
+    ci_spawn "$CI_CMAKE" -B "$CI_BUILD_DIR" \
+                         -S . \
+                         -DCMAKE_INSTALL_PREFIX="$CI_INSTALL_DIR" \
+                         "${all_cmake_vars[@]}"
+    ci_expr $((CI_NO_BUILD)) || {
+        # Spawn "cmake --build ...".
+        ci_spawn "$CI_CMAKE" --build "$CI_BUILD_DIR" \
+                             --config "$CI_CMAKE_BUILD_TYPE" \
+                             "${all_cmake_build_flags[@]}"
+    }
     ci_expr $((CI_NO_TEST)) || {
         # Spawn "ctest" if testing is not disabled.
+        ci_spawn pushd "$CI_BUILD_DIR"
         ci_spawn "$CI_CTEST" --build-config "$CI_CMAKE_BUILD_TYPE" \
                              "${all_ctest_flags[@]}"
+        ci_spawn popd
     }
     ci_expr $((CI_NO_INSTALL)) || {
         # Spawn "cmake --build ... --target install" if installation is not disabled.
-        ci_spawn "$CI_CMAKE" --build . \
+        ci_spawn "$CI_CMAKE" --build "$CI_BUILD_DIR" \
                              --config "$CI_CMAKE_BUILD_TYPE" \
                              --target install \
                              "${all_cmake_build_flags[@]}"
     }
     ci_expr $((CI_NO_CLEAN)) || {
         # Spawn "make --build ... --target clean" if cleaning is not disabled.
-        ci_spawn "$CI_CMAKE" --build . \
+        ci_spawn "$CI_CMAKE" --build "$CI_BUILD_DIR" \
                              --config "$CI_CMAKE_BUILD_TYPE" \
                              --target clean \
                              "${all_cmake_build_flags[@]}"
diff --git a/ci/ci_verify_configure.sh b/ci/ci_verify_configure.sh
index 141c7a283..9c3a28809 100755
--- a/ci/ci_verify_configure.sh
+++ b/ci/ci_verify_configure.sh
@@ -58,6 +58,7 @@ function ci_trace_build {
     ci_info "environment option: \$CI_LD_FLAGS: '$CI_LD_FLAGS'"
     ci_info "environment option: \$CI_SANITIZERS: '$CI_SANITIZERS'"
     ci_info "environment option: \$CI_FORCE: '$CI_FORCE'"
+    ci_info "environment option: \$CI_NO_BUILD: '$CI_NO_BUILD'"
     ci_info "environment option: \$CI_NO_TEST: '$CI_NO_TEST'"
     ci_info "environment option: \$CI_NO_INSTALL: '$CI_NO_INSTALL'"
     ci_info "environment option: \$CI_NO_CLEAN: '$CI_NO_CLEAN'"
@@ -122,13 +123,19 @@ function ci_build {
         ci_spawn export CFLAGS="${CFLAGS:-"-O2"} -fsanitize=$CI_SANITIZERS"
         ci_spawn export LDFLAGS="${LDFLAGS}${LDFLAGS:+" "}-fsanitize=$CI_SANITIZERS"
     }
+    # Spawn "autogen.sh" if the configure script is not available.
+    [[ -x "$CI_SRC_DIR/configure" ]] || {
+        ci_spawn "$CI_SRC_DIR/autogen.sh" --maintainer
+    }
     # And... build!
     ci_spawn mkdir -p "$CI_BUILD_DIR"
     ci_spawn cd "$CI_BUILD_DIR"
     # Spawn "configure".
     ci_spawn "$CI_SRC_DIR/configure" --prefix="$CI_INSTALL_DIR" $CI_CONFIGURE_FLAGS
-    # Spawn "make".
-    ci_spawn "$CI_MAKE" $CI_MAKE_FLAGS
+    ci_expr $((CI_NO_BUILD)) || {
+        # Spawn "make".
+        ci_spawn "$CI_MAKE" $CI_MAKE_FLAGS
+    }
     ci_expr $((CI_NO_TEST)) || {
         # Spawn "make test" if testing is not disabled.
         ci_spawn "$CI_MAKE" $CI_MAKE_FLAGS test
diff --git a/ci/ci_verify_makefiles.sh b/ci/ci_verify_makefiles.sh
index e0681b4d8..2d3ec72ec 100755
--- a/ci/ci_verify_makefiles.sh
+++ b/ci/ci_verify_makefiles.sh
@@ -51,6 +51,7 @@ function ci_trace_build {
     ci_info "environment option: \$CI_LIBS: '$CI_LIBS'"
     ci_info "environment option: \$CI_SANITIZERS: '$CI_SANITIZERS'"
     ci_info "environment option: \$CI_FORCE: '$CI_FORCE'"
+    ci_info "environment option: \$CI_NO_BUILD: '$CI_NO_BUILD'"
     ci_info "environment option: \$CI_NO_TEST: '$CI_NO_TEST'"
     ci_info "environment option: \$CI_NO_CLEAN: '$CI_NO_CLEAN'"
     ci_info "executable: \$CI_MAKE: $(command -V "$CI_MAKE")"
@@ -145,10 +146,12 @@ function ci_build {
     for my_makefile in $CI_MAKEFILES
     do
         ci_info "using makefile: $my_makefile"
-        # Spawn "make".
-        ci_spawn "$CI_MAKE" -f "$my_makefile" \
-                            "${all_make_flags[@]}" \
-                            "${all_make_vars[@]}"
+        ci_expr $((CI_NO_BUILD)) || {
+            # Spawn "make".
+            ci_spawn "$CI_MAKE" -f "$my_makefile" \
+                                "${all_make_flags[@]}" \
+                                "${all_make_vars[@]}"
+        }
         ci_expr $((CI_NO_TEST)) || {
             # Spawn "make test" if testing is not disabled.
             ci_spawn "$CI_MAKE" -f "$my_makefile" \
diff --git a/ci/ci_verify_version.sh b/ci/ci_verify_version.sh
index c786f06ac..3203b201f 100755
--- a/ci/ci_verify_version.sh
+++ b/ci/ci_verify_version.sh
@@ -89,9 +89,9 @@ function ci_verify_version {
         fi
         if [[ $PNG_LIBPNG_BUILD_BASE_TYPE -eq $PNG_LIBPNG_BUILD_STABLE ]]
         then
-            ci_info "matched: \$PNG_LIBPNG_BUILD_BASE_TYPE -eq \$PNG_LIBPNG_BUILD_BETA"
+            ci_info "matched: \$PNG_LIBPNG_BUILD_BASE_TYPE -eq \$PNG_LIBPNG_BUILD_STABLE"
         else
-            ci_err "mismatched: \$PNG_LIBPNG_BUILD_BASE_TYPE -ne \$PNG_LIBPNG_BUILD_BETA"
+            ci_err "mismatched: \$PNG_LIBPNG_BUILD_BASE_TYPE -ne \$PNG_LIBPNG_BUILD_STABLE"
         fi
     elif [[ "$PNG_LIBPNG_VER_STRING" == "$my_expect".git ]]
     then
@@ -101,11 +101,11 @@ function ci_verify_version {
         else
             ci_err "mismatched: \$PNG_LIBPNG_VER_BUILD -eq 0"
         fi
-        if [[ $PNG_LIBPNG_BUILD_BASE_TYPE -eq $PNG_LIBPNG_BUILD_BETA ]]
+        if [[ $PNG_LIBPNG_BUILD_BASE_TYPE -ne $PNG_LIBPNG_BUILD_STABLE ]]
         then
-            ci_info "matched: \$PNG_LIBPNG_BUILD_BASE_TYPE -eq \$PNG_LIBPNG_BUILD_BETA"
+            ci_info "matched: \$PNG_LIBPNG_BUILD_BASE_TYPE -ne \$PNG_LIBPNG_BUILD_STABLE"
         else
-            ci_err "mismatched: \$PNG_LIBPNG_BUILD_BASE_TYPE -ne \$PNG_LIBPNG_BUILD_BETA"
+            ci_err "mismatched: \$PNG_LIBPNG_BUILD_BASE_TYPE -eq \$PNG_LIBPNG_BUILD_STABLE"
         fi
     else
         ci_err "unexpected: \$PNG_LIBPNG_VER_STRING == '$PNG_LIBPNG_VER_STRING'"
diff --git a/ci/lib/ci.lib.sh b/ci/lib/ci.lib.sh
index 03e866b5c..692851fc0 100644
--- a/ci/lib/ci.lib.sh
+++ b/ci/lib/ci.lib.sh
@@ -91,6 +91,9 @@ function ci_spawn {
 [[ ${CI_FORCE:-0} == [01] ]] || {
     ci_err "bad boolean option: \$CI_FORCE: '$CI_FORCE'"
 }
+[[ ${CI_NO_BUILD:-0} == [01] ]] || {
+    ci_err "bad boolean option: \$CI_NO_BUILD: '$CI_NO_BUILD'"
+}
 [[ ${CI_NO_TEST:-0} == [01] ]] || {
     ci_err "bad boolean option: \$CI_NO_TEST: '$CI_NO_TEST'"
 }
@@ -100,3 +103,9 @@ function ci_spawn {
 [[ ${CI_NO_CLEAN:-0} == [01] ]] || {
     ci_err "bad boolean option: \$CI_NO_CLEAN: '$CI_NO_CLEAN'"
 }
+if ci_expr $((CI_NO_BUILD))
+then
+    ci_expr $((CI_NO_TEST && CI_NO_INSTALL)) || {
+        ci_err "\$CI_NO_BUILD requires \$CI_NO_TEST and \$CI_NO_INSTALL"
+    }
+fi
diff --git a/configure b/configure
index f2048dd7f..bd274ab9f 100755
--- a/configure
+++ b/configure
@@ -1,6 +1,6 @@
 #! /bin/sh
 # Guess values for system-dependent variables and create Makefiles.
-# Generated by GNU Autoconf 2.72 for libpng 1.6.44.
+# Generated by GNU Autoconf 2.72 for libpng 1.6.47.
 #
 # Report bugs to <png-mng-implement@lists.sourceforge.net>.
 #
@@ -614,8 +614,8 @@ MAKEFLAGS=
 # Identity of this package.
 PACKAGE_NAME='libpng'
 PACKAGE_TARNAME='libpng'
-PACKAGE_VERSION='1.6.44'
-PACKAGE_STRING='libpng 1.6.44'
+PACKAGE_VERSION='1.6.47'
+PACKAGE_STRING='libpng 1.6.47'
 PACKAGE_BUGREPORT='png-mng-implement@lists.sourceforge.net'
 PACKAGE_URL=''
 
@@ -834,8 +834,10 @@ enable_dependency_tracking
 with_gnu_ld
 enable_shared
 enable_static
+enable_pic
 with_pic
 enable_fast_install
+enable_aix_soname
 with_aix_soname
 with_sysroot
 enable_libtool_lock
@@ -1419,7 +1421,7 @@ if test "$ac_init_help" = "long"; then
   # Omit some internal or obsolete options to make the list less imposing.
   # This message is too long to be a string in the A/UX 3.1 sh.
   cat <<_ACEOF
-'configure' configures libpng 1.6.44 to adapt to many kinds of systems.
+'configure' configures libpng 1.6.47 to adapt to many kinds of systems.
 
 Usage: $0 [OPTION]... [VAR=VALUE]...
 
@@ -1490,7 +1492,7 @@ fi
 
 if test -n "$ac_init_help"; then
   case $ac_init_help in
-     short | recursive ) echo "Configuration of libpng 1.6.44:";;
+     short | recursive ) echo "Configuration of libpng 1.6.47:";;
    esac
   cat <<\_ACEOF
 
@@ -1509,8 +1511,13 @@ Optional Features:
                           speeds up one-time build
   --enable-shared[=PKGS]  build shared libraries [default=yes]
   --enable-static[=PKGS]  build static libraries [default=yes]
+  --enable-pic[=PKGS]     try to use only PIC/non-PIC objects [default=use
+                          both]
   --enable-fast-install[=PKGS]
                           optimize for fast installation [default=yes]
+  --enable-aix-soname=aix|svr4|both
+                          shared library versioning (aka "SONAME") variant to
+                          provide on AIX, [default=aix].
   --disable-libtool-lock  avoid locking (might break parallel builds)
   --disable-tests         do not build the test programs (default is to build)
   --disable-tools         do not build the auxiliary tools (default is to
@@ -1588,11 +1595,6 @@ Optional Packages:
   --with-PACKAGE[=ARG]    use PACKAGE [ARG=yes]
   --without-PACKAGE       do not use PACKAGE (same as --with-PACKAGE=no)
   --with-gnu-ld           assume the C compiler uses GNU ld [default=no]
-  --with-pic[=PKGS]       try to use only PIC/non-PIC objects [default=use
-                          both]
-  --with-aix-soname=aix|svr4|both
-                          shared library versioning (aka "SONAME") variant to
-                          provide on AIX, [default=aix].
   --with-sysroot[=DIR]    Search for dependent libraries within DIR (or the
                           compiler's sysroot if not specified).
   --with-zlib-prefix    prefix that may have been used in installed zlib
@@ -1687,7 +1689,7 @@ fi
 test -n "$ac_init_help" && exit $ac_status
 if $ac_init_version; then
   cat <<\_ACEOF
-libpng configure 1.6.44
+libpng configure 1.6.47
 generated by GNU Autoconf 2.72
 
 Copyright (C) 2023 Free Software Foundation, Inc.
@@ -1950,7 +1952,7 @@ cat >config.log <<_ACEOF
 This file contains any messages produced by compilers while
 running configure, to aid debugging if configure makes a mistake.
 
-It was created by libpng $as_me 1.6.44, which was
+It was created by libpng $as_me 1.6.47, which was
 generated by GNU Autoconf 2.72.  Invocation command line was
 
   $ $0$ac_configure_args_raw
@@ -3431,7 +3433,7 @@ fi
 
 # Define the identity of the package.
  PACKAGE='libpng'
- VERSION='1.6.44'
+ VERSION='1.6.47'
 
 
 printf "%s\n" "#define PACKAGE \"$PACKAGE\"" >>confdefs.h
@@ -3526,10 +3528,10 @@ fi
 
 
 
-PNGLIB_VERSION=1.6.44
+PNGLIB_VERSION=1.6.47
 PNGLIB_MAJOR=1
 PNGLIB_MINOR=6
-PNGLIB_RELEASE=44
+PNGLIB_RELEASE=47
 
 
 
@@ -5436,7 +5438,7 @@ if test yes = "$GCC"; then
   { printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for ld used by $CC" >&5
 printf %s "checking for ld used by $CC... " >&6; }
   case $host in
-  *-*-mingw*)
+  *-*-mingw* | *-*-windows*)
     # gcc leaves a trailing carriage return, which upsets mingw
     ac_prog=`($CC -print-prog-name=ld) 2>&5 | tr -d '\015'` ;;
   *)
@@ -5778,8 +5780,8 @@ esac
 
 
 
-macro_version='2.4.7'
-macro_revision='2.4.7'
+macro_version='2.5.4'
+macro_revision='2.5.4'
 
 
 
@@ -5840,7 +5842,7 @@ else
 	# Tru64's nm complains that /dev/null is an invalid object file
 	# MSYS converts /dev/null to NUL, MinGW nm treats NUL as empty
 	case $build_os in
-	mingw*) lt_bad_file=conftest.nm/nofile ;;
+	mingw* | windows*) lt_bad_file=conftest.nm/nofile ;;
 	*) lt_bad_file=/dev/null ;;
 	esac
 	case `"$tmp_nm" -B $lt_bad_file 2>&1 | $SED '1q'` in
@@ -6055,14 +6057,14 @@ else case e in #(
     lt_cv_sys_max_cmd_len=12288;    # 12K is about right
     ;;
 
-  gnu*)
-    # Under GNU Hurd, this test is not required because there is
-    # no limit to the length of command line arguments.
+  gnu* | ironclad*)
+    # Under GNU Hurd and Ironclad, this test is not required because there
+    # is no limit to the length of command line arguments.
     # Libtool will interpret -1 as no limit whatsoever
     lt_cv_sys_max_cmd_len=-1;
     ;;
 
-  cygwin* | mingw* | cegcc*)
+  cygwin* | mingw* | windows* | cegcc*)
     # On Win9x/ME, this test blows up -- it succeeds, but takes
     # about 5 minutes as the teststring grows exponentially.
     # Worse, since 9x/ME are not pre-emptively multitasking,
@@ -6084,7 +6086,7 @@ else case e in #(
     lt_cv_sys_max_cmd_len=8192;
     ;;
 
-  bitrig* | darwin* | dragonfly* | freebsd* | midnightbsd* | netbsd* | openbsd*)
+  darwin* | dragonfly* | freebsd* | midnightbsd* | netbsd* | openbsd*)
     # This has been around since 386BSD, at least.  Likely further.
     if test -x /sbin/sysctl; then
       lt_cv_sys_max_cmd_len=`/sbin/sysctl -n kern.argmax`
@@ -6227,7 +6229,7 @@ else case e in #(
   e) case $host in
   *-*-mingw* )
     case $build in
-      *-*-mingw* ) # actually msys
+      *-*-mingw* | *-*-windows* ) # actually msys
         lt_cv_to_host_file_cmd=func_convert_file_msys_to_w32
         ;;
       *-*-cygwin* )
@@ -6240,7 +6242,7 @@ else case e in #(
     ;;
   *-*-cygwin* )
     case $build in
-      *-*-mingw* ) # actually msys
+      *-*-mingw* | *-*-windows* ) # actually msys
         lt_cv_to_host_file_cmd=func_convert_file_msys_to_cygwin
         ;;
       *-*-cygwin* )
@@ -6276,9 +6278,9 @@ else case e in #(
   e) #assume ordinary cross tools, or native build.
 lt_cv_to_tool_file_cmd=func_convert_file_noop
 case $host in
-  *-*-mingw* )
+  *-*-mingw* | *-*-windows* )
     case $build in
-      *-*-mingw* ) # actually msys
+      *-*-mingw* | *-*-windows* ) # actually msys
         lt_cv_to_tool_file_cmd=func_convert_file_msys_to_w32
         ;;
     esac
@@ -6314,7 +6316,7 @@ case $reload_flag in
 esac
 reload_cmds='$LD$reload_flag -o $output$reload_objs'
 case $host_os in
-  cygwin* | mingw* | pw32* | cegcc*)
+  cygwin* | mingw* | windows* | pw32* | cegcc*)
     if test yes != "$GCC"; then
       reload_cmds=false
     fi
@@ -6336,9 +6338,8 @@ esac
 
 
 
-if test -n "$ac_tool_prefix"; then
-  # Extract the first word of "${ac_tool_prefix}file", so it can be a program name with args.
-set dummy ${ac_tool_prefix}file; ac_word=$2
+# Extract the first word of "file", so it can be a program name with args.
+set dummy file; ac_word=$2
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for $ac_word" >&5
 printf %s "checking for $ac_word... " >&6; }
 if test ${ac_cv_prog_FILECMD+y}
@@ -6359,7 +6360,7 @@ do
   esac
     for ac_exec_ext in '' $ac_executable_extensions; do
   if as_fn_executable_p "$as_dir$ac_word$ac_exec_ext"; then
-    ac_cv_prog_FILECMD="${ac_tool_prefix}file"
+    ac_cv_prog_FILECMD="file"
     printf "%s\n" "$as_me:${as_lineno-$LINENO}: found $as_dir$ac_word$ac_exec_ext" >&5
     break 2
   fi
@@ -6367,6 +6368,7 @@ done
   done
 IFS=$as_save_IFS
 
+  test -z "$ac_cv_prog_FILECMD" && ac_cv_prog_FILECMD=":"
 fi ;;
 esac
 fi
@@ -6380,66 +6382,6 @@ printf "%s\n" "no" >&6; }
 fi
 
 
-fi
-if test -z "$ac_cv_prog_FILECMD"; then
-  ac_ct_FILECMD=$FILECMD
-  # Extract the first word of "file", so it can be a program name with args.
-set dummy file; ac_word=$2
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for $ac_word" >&5
-printf %s "checking for $ac_word... " >&6; }
-if test ${ac_cv_prog_ac_ct_FILECMD+y}
-then :
-  printf %s "(cached) " >&6
-else case e in #(
-  e) if test -n "$ac_ct_FILECMD"; then
-  ac_cv_prog_ac_ct_FILECMD="$ac_ct_FILECMD" # Let the user override the test.
-else
-as_save_IFS=$IFS; IFS=$PATH_SEPARATOR
-for as_dir in $PATH
-do
-  IFS=$as_save_IFS
-  case $as_dir in #(((
-    '') as_dir=./ ;;
-    */) ;;
-    *) as_dir=$as_dir/ ;;
-  esac
-    for ac_exec_ext in '' $ac_executable_extensions; do
-  if as_fn_executable_p "$as_dir$ac_word$ac_exec_ext"; then
-    ac_cv_prog_ac_ct_FILECMD="file"
-    printf "%s\n" "$as_me:${as_lineno-$LINENO}: found $as_dir$ac_word$ac_exec_ext" >&5
-    break 2
-  fi
-done
-  done
-IFS=$as_save_IFS
-
-fi ;;
-esac
-fi
-ac_ct_FILECMD=$ac_cv_prog_ac_ct_FILECMD
-if test -n "$ac_ct_FILECMD"; then
-  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $ac_ct_FILECMD" >&5
-printf "%s\n" "$ac_ct_FILECMD" >&6; }
-else
-  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: no" >&5
-printf "%s\n" "no" >&6; }
-fi
-
-  if test "x$ac_ct_FILECMD" = x; then
-    FILECMD=":"
-  else
-    case $cross_compiling:$ac_tool_warned in
-yes:)
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: WARNING: using cross tools not prefixed with host triplet" >&5
-printf "%s\n" "$as_me: WARNING: using cross tools not prefixed with host triplet" >&2;}
-ac_tool_warned=yes ;;
-esac
-    FILECMD=$ac_ct_FILECMD
-  fi
-else
-  FILECMD="$ac_cv_prog_FILECMD"
-fi
-
 
 
 
@@ -6571,7 +6513,6 @@ lt_cv_deplibs_check_method='unknown'
 # 'none' -- dependencies not supported.
 # 'unknown' -- same as none, but documents that we really don't know.
 # 'pass_all' -- all dependencies passed with no checks.
-# 'test_compile' -- check by making test program.
 # 'file_magic [[regex]]' -- check by looking for files in library path
 # that responds to the $file_magic_cmd with a given extended regex.
 # If you have 'file' or equivalent on your system and you're not sure
@@ -6598,7 +6539,7 @@ cygwin*)
   lt_cv_file_magic_cmd='func_win32_libid'
   ;;
 
-mingw* | pw32*)
+mingw* | windows* | pw32*)
   # Base MSYS/MinGW do not provide the 'file' command needed by
   # func_win32_libid shell function, so use a weaker test based on 'objdump',
   # unless we find 'file', for example because we are cross-compiling.
@@ -6607,7 +6548,7 @@ mingw* | pw32*)
     lt_cv_file_magic_cmd='func_win32_libid'
   else
     # Keep this pattern in sync with the one in func_win32_libid.
-    lt_cv_deplibs_check_method='file_magic file format (pei*-i386(.*architecture: i386)?|pe-arm-wince|pe-x86-64)'
+    lt_cv_deplibs_check_method='file_magic file format (pei*-i386(.*architecture: i386)?|pe-arm-wince|pe-x86-64|pe-aarch64)'
     lt_cv_file_magic_cmd='$OBJDUMP -f'
   fi
   ;;
@@ -6680,7 +6621,11 @@ linux* | k*bsd*-gnu | kopensolaris*-gnu | gnu*)
   lt_cv_deplibs_check_method=pass_all
   ;;
 
-netbsd*)
+*-mlibc)
+  lt_cv_deplibs_check_method=pass_all
+  ;;
+
+netbsd* | netbsdelf*-gnu)
   if echo __ELF__ | $CC -E - | $GREP __ELF__ > /dev/null; then
     lt_cv_deplibs_check_method='match_pattern /lib[^/]+(\.so\.[0-9]+\.[0-9]+|_pic\.a)$'
   else
@@ -6698,7 +6643,7 @@ newos6*)
   lt_cv_deplibs_check_method=pass_all
   ;;
 
-openbsd* | bitrig*)
+openbsd*)
   if test -z "`echo __ELF__ | $CC -E - | $GREP __ELF__`"; then
     lt_cv_deplibs_check_method='match_pattern /lib[^/]+(\.so\.[0-9]+\.[0-9]+|\.so|_pic\.a)$'
   else
@@ -6714,6 +6659,10 @@ rdos*)
   lt_cv_deplibs_check_method=pass_all
   ;;
 
+serenity*)
+  lt_cv_deplibs_check_method=pass_all
+  ;;
+
 solaris*)
   lt_cv_deplibs_check_method=pass_all
   ;;
@@ -6766,7 +6715,7 @@ file_magic_glob=
 want_nocaseglob=no
 if test "$build" = "$host"; then
   case $host_os in
-  mingw* | pw32*)
+  mingw* | windows* | pw32*)
     if ( shopt | grep nocaseglob ) >/dev/null 2>&1; then
       want_nocaseglob=yes
     else
@@ -6922,7 +6871,7 @@ else case e in #(
   e) lt_cv_sharedlib_from_linklib_cmd='unknown'
 
 case $host_os in
-cygwin* | mingw* | pw32* | cegcc*)
+cygwin* | mingw* | windows* | pw32* | cegcc*)
   # two different shell functions defined in ltmain.sh;
   # decide which one to use based on capabilities of $DLLTOOL
   case `$DLLTOOL --help 2>&1` in
@@ -6954,6 +6903,110 @@ test -z "$sharedlib_from_linklib_cmd" && sharedlib_from_linklib_cmd=$ECHO
 
 
 
+if test -n "$ac_tool_prefix"; then
+  # Extract the first word of "${ac_tool_prefix}ranlib", so it can be a program name with args.
+set dummy ${ac_tool_prefix}ranlib; ac_word=$2
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for $ac_word" >&5
+printf %s "checking for $ac_word... " >&6; }
+if test ${ac_cv_prog_RANLIB+y}
+then :
+  printf %s "(cached) " >&6
+else case e in #(
+  e) if test -n "$RANLIB"; then
+  ac_cv_prog_RANLIB="$RANLIB" # Let the user override the test.
+else
+as_save_IFS=$IFS; IFS=$PATH_SEPARATOR
+for as_dir in $PATH
+do
+  IFS=$as_save_IFS
+  case $as_dir in #(((
+    '') as_dir=./ ;;
+    */) ;;
+    *) as_dir=$as_dir/ ;;
+  esac
+    for ac_exec_ext in '' $ac_executable_extensions; do
+  if as_fn_executable_p "$as_dir$ac_word$ac_exec_ext"; then
+    ac_cv_prog_RANLIB="${ac_tool_prefix}ranlib"
+    printf "%s\n" "$as_me:${as_lineno-$LINENO}: found $as_dir$ac_word$ac_exec_ext" >&5
+    break 2
+  fi
+done
+  done
+IFS=$as_save_IFS
+
+fi ;;
+esac
+fi
+RANLIB=$ac_cv_prog_RANLIB
+if test -n "$RANLIB"; then
+  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $RANLIB" >&5
+printf "%s\n" "$RANLIB" >&6; }
+else
+  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: no" >&5
+printf "%s\n" "no" >&6; }
+fi
+
+
+fi
+if test -z "$ac_cv_prog_RANLIB"; then
+  ac_ct_RANLIB=$RANLIB
+  # Extract the first word of "ranlib", so it can be a program name with args.
+set dummy ranlib; ac_word=$2
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for $ac_word" >&5
+printf %s "checking for $ac_word... " >&6; }
+if test ${ac_cv_prog_ac_ct_RANLIB+y}
+then :
+  printf %s "(cached) " >&6
+else case e in #(
+  e) if test -n "$ac_ct_RANLIB"; then
+  ac_cv_prog_ac_ct_RANLIB="$ac_ct_RANLIB" # Let the user override the test.
+else
+as_save_IFS=$IFS; IFS=$PATH_SEPARATOR
+for as_dir in $PATH
+do
+  IFS=$as_save_IFS
+  case $as_dir in #(((
+    '') as_dir=./ ;;
+    */) ;;
+    *) as_dir=$as_dir/ ;;
+  esac
+    for ac_exec_ext in '' $ac_executable_extensions; do
+  if as_fn_executable_p "$as_dir$ac_word$ac_exec_ext"; then
+    ac_cv_prog_ac_ct_RANLIB="ranlib"
+    printf "%s\n" "$as_me:${as_lineno-$LINENO}: found $as_dir$ac_word$ac_exec_ext" >&5
+    break 2
+  fi
+done
+  done
+IFS=$as_save_IFS
+
+fi ;;
+esac
+fi
+ac_ct_RANLIB=$ac_cv_prog_ac_ct_RANLIB
+if test -n "$ac_ct_RANLIB"; then
+  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $ac_ct_RANLIB" >&5
+printf "%s\n" "$ac_ct_RANLIB" >&6; }
+else
+  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: no" >&5
+printf "%s\n" "no" >&6; }
+fi
+
+  if test "x$ac_ct_RANLIB" = x; then
+    RANLIB=":"
+  else
+    case $cross_compiling:$ac_tool_warned in
+yes:)
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: WARNING: using cross tools not prefixed with host triplet" >&5
+printf "%s\n" "$as_me: WARNING: using cross tools not prefixed with host triplet" >&2;}
+ac_tool_warned=yes ;;
+esac
+    RANLIB=$ac_ct_RANLIB
+  fi
+else
+  RANLIB="$ac_cv_prog_RANLIB"
+fi
+
 if test -n "$ac_tool_prefix"; then
   for ac_prog in ar
   do
@@ -7075,7 +7128,7 @@ fi
 
 # Use ARFLAGS variable as AR's operation code to sync the variable naming with
 # Automake.  If both AR_FLAGS and ARFLAGS are specified, AR_FLAGS should have
-# higher priority because thats what people were doing historically (setting
+# higher priority because that's what people were doing historically (setting
 # ARFLAGS for automake and AR_FLAGS for libtool).  FIXME: Make the AR_FLAGS
 # variable obsoleted/removed.
 
@@ -7267,139 +7320,29 @@ test -z "$STRIP" && STRIP=:
 
 
 
-if test -n "$ac_tool_prefix"; then
-  # Extract the first word of "${ac_tool_prefix}ranlib", so it can be a program name with args.
-set dummy ${ac_tool_prefix}ranlib; ac_word=$2
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for $ac_word" >&5
-printf %s "checking for $ac_word... " >&6; }
-if test ${ac_cv_prog_RANLIB+y}
-then :
-  printf %s "(cached) " >&6
-else case e in #(
-  e) if test -n "$RANLIB"; then
-  ac_cv_prog_RANLIB="$RANLIB" # Let the user override the test.
-else
-as_save_IFS=$IFS; IFS=$PATH_SEPARATOR
-for as_dir in $PATH
-do
-  IFS=$as_save_IFS
-  case $as_dir in #(((
-    '') as_dir=./ ;;
-    */) ;;
-    *) as_dir=$as_dir/ ;;
-  esac
-    for ac_exec_ext in '' $ac_executable_extensions; do
-  if as_fn_executable_p "$as_dir$ac_word$ac_exec_ext"; then
-    ac_cv_prog_RANLIB="${ac_tool_prefix}ranlib"
-    printf "%s\n" "$as_me:${as_lineno-$LINENO}: found $as_dir$ac_word$ac_exec_ext" >&5
-    break 2
-  fi
-done
-  done
-IFS=$as_save_IFS
 
-fi ;;
-esac
-fi
-RANLIB=$ac_cv_prog_RANLIB
-if test -n "$RANLIB"; then
-  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $RANLIB" >&5
-printf "%s\n" "$RANLIB" >&6; }
-else
-  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: no" >&5
-printf "%s\n" "no" >&6; }
-fi
+test -z "$RANLIB" && RANLIB=:
+
 
 
+
+
+
+# Determine commands to create old-style static archives.
+old_archive_cmds='$AR $AR_FLAGS $oldlib$oldobjs'
+old_postinstall_cmds='chmod 644 $oldlib'
+old_postuninstall_cmds=
+
+if test -n "$RANLIB"; then
+  old_archive_cmds="$old_archive_cmds~\$RANLIB \$tool_oldlib"
+  old_postinstall_cmds="$old_postinstall_cmds~\$RANLIB \$tool_oldlib"
 fi
-if test -z "$ac_cv_prog_RANLIB"; then
-  ac_ct_RANLIB=$RANLIB
-  # Extract the first word of "ranlib", so it can be a program name with args.
-set dummy ranlib; ac_word=$2
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for $ac_word" >&5
-printf %s "checking for $ac_word... " >&6; }
-if test ${ac_cv_prog_ac_ct_RANLIB+y}
-then :
-  printf %s "(cached) " >&6
-else case e in #(
-  e) if test -n "$ac_ct_RANLIB"; then
-  ac_cv_prog_ac_ct_RANLIB="$ac_ct_RANLIB" # Let the user override the test.
-else
-as_save_IFS=$IFS; IFS=$PATH_SEPARATOR
-for as_dir in $PATH
-do
-  IFS=$as_save_IFS
-  case $as_dir in #(((
-    '') as_dir=./ ;;
-    */) ;;
-    *) as_dir=$as_dir/ ;;
-  esac
-    for ac_exec_ext in '' $ac_executable_extensions; do
-  if as_fn_executable_p "$as_dir$ac_word$ac_exec_ext"; then
-    ac_cv_prog_ac_ct_RANLIB="ranlib"
-    printf "%s\n" "$as_me:${as_lineno-$LINENO}: found $as_dir$ac_word$ac_exec_ext" >&5
-    break 2
-  fi
-done
-  done
-IFS=$as_save_IFS
 
-fi ;;
-esac
-fi
-ac_ct_RANLIB=$ac_cv_prog_ac_ct_RANLIB
-if test -n "$ac_ct_RANLIB"; then
-  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $ac_ct_RANLIB" >&5
-printf "%s\n" "$ac_ct_RANLIB" >&6; }
-else
-  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: no" >&5
-printf "%s\n" "no" >&6; }
-fi
-
-  if test "x$ac_ct_RANLIB" = x; then
-    RANLIB=":"
-  else
-    case $cross_compiling:$ac_tool_warned in
-yes:)
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: WARNING: using cross tools not prefixed with host triplet" >&5
-printf "%s\n" "$as_me: WARNING: using cross tools not prefixed with host triplet" >&2;}
-ac_tool_warned=yes ;;
-esac
-    RANLIB=$ac_ct_RANLIB
-  fi
-else
-  RANLIB="$ac_cv_prog_RANLIB"
-fi
-
-test -z "$RANLIB" && RANLIB=:
-
-
-
-
-
-
-# Determine commands to create old-style static archives.
-old_archive_cmds='$AR $AR_FLAGS $oldlib$oldobjs'
-old_postinstall_cmds='chmod 644 $oldlib'
-old_postuninstall_cmds=
-
-if test -n "$RANLIB"; then
-  case $host_os in
-  bitrig* | openbsd*)
-    old_postinstall_cmds="$old_postinstall_cmds~\$RANLIB -t \$tool_oldlib"
-    ;;
-  *)
-    old_postinstall_cmds="$old_postinstall_cmds~\$RANLIB \$tool_oldlib"
-    ;;
-  esac
-  old_archive_cmds="$old_archive_cmds~\$RANLIB \$tool_oldlib"
-fi
-
-case $host_os in
-  darwin*)
-    lock_old_archive_extraction=yes ;;
-  *)
-    lock_old_archive_extraction=no ;;
+case $host_os in
+  darwin*)
+    lock_old_archive_extraction=yes ;;
+  *)
+    lock_old_archive_extraction=no ;;
 esac
 
 
@@ -7472,7 +7415,7 @@ case $host_os in
 aix*)
   symcode='[BCDT]'
   ;;
-cygwin* | mingw* | pw32* | cegcc*)
+cygwin* | mingw* | windows* | pw32* | cegcc*)
   symcode='[ABCDGISTW]'
   ;;
 hpux*)
@@ -7487,7 +7430,7 @@ osf*)
   symcode='[BCDEGQRST]'
   ;;
 solaris*)
-  symcode='[BDRT]'
+  symcode='[BCDRT]'
   ;;
 sco3.2v5*)
   symcode='[DT]'
@@ -7551,7 +7494,7 @@ $lt_c_name_lib_hook\
 # Handle CRLF in mingw tool chain
 opt_cr=
 case $build_os in
-mingw*)
+mingw* | windows*)
   opt_cr=`$ECHO 'x\{0,1\}' | tr x '\015'` # option cr in regexp
   ;;
 esac
@@ -7602,7 +7545,7 @@ void nm_test_func(void){}
 #ifdef __cplusplus
 }
 #endif
-int main(){nm_test_var='a';nm_test_func();return(0);}
+int main(void){nm_test_var='a';nm_test_func();return(0);}
 _LT_EOF
 
   if { { eval echo "\"\$as_me\":${as_lineno-$LINENO}: \"$ac_compile\""; } >&5
@@ -7612,11 +7555,8 @@ _LT_EOF
   test $ac_status = 0; }; then
     # Now try to grab the symbols.
     nlist=conftest.nm
-    if { { eval echo "\"\$as_me\":${as_lineno-$LINENO}: \"$NM conftest.$ac_objext \| "$lt_cv_sys_global_symbol_pipe" \> $nlist\""; } >&5
-  (eval $NM conftest.$ac_objext \| "$lt_cv_sys_global_symbol_pipe" \> $nlist) 2>&5
-  ac_status=$?
-  printf "%s\n" "$as_me:${as_lineno-$LINENO}: \$? = $ac_status" >&5
-  test $ac_status = 0; } && test -s "$nlist"; then
+    $ECHO "$as_me:$LINENO: $NM conftest.$ac_objext | $lt_cv_sys_global_symbol_pipe > $nlist" >&5
+    if eval "$NM" conftest.$ac_objext \| "$lt_cv_sys_global_symbol_pipe" \> $nlist 2>&5 && test -s "$nlist"; then
       # Try sorting and uniquifying the output.
       if sort "$nlist" | uniq > "$nlist"T; then
 	mv -f "$nlist"T "$nlist"
@@ -7787,7 +7727,9 @@ lt_sysroot=
 case $with_sysroot in #(
  yes)
    if test yes = "$GCC"; then
-     lt_sysroot=`$CC --print-sysroot 2>/dev/null`
+     # Trim trailing / since we'll always append absolute paths and we want
+     # to avoid //, if only for less confusing output for the user.
+     lt_sysroot=`$CC --print-sysroot 2>/dev/null | $SED 's:/\+$::'`
    fi
    ;; #(
  /*)
@@ -8004,7 +7946,7 @@ mips64*-*linux*)
   ;;
 
 x86_64-*kfreebsd*-gnu|x86_64-*linux*|powerpc*-*linux*| \
-s390*-*linux*|s390*-*tpf*|sparc*-*linux*)
+s390*-*linux*|s390*-*tpf*|sparc*-*linux*|x86_64-gnu*)
   # Find out what ABI is being produced by ac_compile, and set linker
   # options accordingly.  Note that the listed cases only cover the
   # situations where additional linker options are needed (such as when
@@ -8023,7 +7965,7 @@ s390*-*linux*|s390*-*tpf*|sparc*-*linux*)
 	  x86_64-*kfreebsd*-gnu)
 	    LD="${LD-ld} -m elf_i386_fbsd"
 	    ;;
-	  x86_64-*linux*)
+	  x86_64-*linux*|x86_64-gnu*)
 	    case `$FILECMD conftest.o` in
 	      *x86-64*)
 		LD="${LD-ld} -m elf32_x86_64"
@@ -8052,7 +7994,7 @@ s390*-*linux*|s390*-*tpf*|sparc*-*linux*)
 	  x86_64-*kfreebsd*-gnu)
 	    LD="${LD-ld} -m elf_x86_64_fbsd"
 	    ;;
-	  x86_64-*linux*)
+	  x86_64-*linux*|x86_64-gnu*)
 	    LD="${LD-ld} -m elf_x86_64"
 	    ;;
 	  powerpcle-*linux*)
@@ -8273,23 +8215,23 @@ fi
 test -z "$MANIFEST_TOOL" && MANIFEST_TOOL=mt
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking if $MANIFEST_TOOL is a manifest tool" >&5
 printf %s "checking if $MANIFEST_TOOL is a manifest tool... " >&6; }
-if test ${lt_cv_path_mainfest_tool+y}
+if test ${lt_cv_path_manifest_tool+y}
 then :
   printf %s "(cached) " >&6
 else case e in #(
-  e) lt_cv_path_mainfest_tool=no
+  e) lt_cv_path_manifest_tool=no
   echo "$as_me:$LINENO: $MANIFEST_TOOL '-?'" >&5
   $MANIFEST_TOOL '-?' 2>conftest.err > conftest.out
   cat conftest.err >&5
   if $GREP 'Manifest Tool' conftest.out > /dev/null; then
-    lt_cv_path_mainfest_tool=yes
+    lt_cv_path_manifest_tool=yes
   fi
   rm -f conftest* ;;
 esac
 fi
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $lt_cv_path_mainfest_tool" >&5
-printf "%s\n" "$lt_cv_path_mainfest_tool" >&6; }
-if test yes != "$lt_cv_path_mainfest_tool"; then
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $lt_cv_path_manifest_tool" >&5
+printf "%s\n" "$lt_cv_path_manifest_tool" >&6; }
+if test yes != "$lt_cv_path_manifest_tool"; then
   MANIFEST_TOOL=:
 fi
 
@@ -8884,6 +8826,45 @@ fi
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $lt_cv_apple_cc_single_mod" >&5
 printf "%s\n" "$lt_cv_apple_cc_single_mod" >&6; }
 
+    # Feature test to disable chained fixups since it is not
+    # compatible with '-undefined dynamic_lookup'
+    { printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for -no_fixup_chains linker flag" >&5
+printf %s "checking for -no_fixup_chains linker flag... " >&6; }
+if test ${lt_cv_support_no_fixup_chains+y}
+then :
+  printf %s "(cached) " >&6
+else case e in #(
+  e)  save_LDFLAGS=$LDFLAGS
+        LDFLAGS="$LDFLAGS -Wl,-no_fixup_chains"
+        cat confdefs.h - <<_ACEOF >conftest.$ac_ext
+/* end confdefs.h.  */
+
+int
+main (void)
+{
+
+  ;
+  return 0;
+}
+_ACEOF
+if ac_fn_c_try_link "$LINENO"
+then :
+  lt_cv_support_no_fixup_chains=yes
+else case e in #(
+  e) lt_cv_support_no_fixup_chains=no
+         ;;
+esac
+fi
+rm -f core conftest.err conftest.$ac_objext conftest.beam \
+    conftest$ac_exeext conftest.$ac_ext
+        LDFLAGS=$save_LDFLAGS
+
+     ;;
+esac
+fi
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $lt_cv_support_no_fixup_chains" >&5
+printf "%s\n" "$lt_cv_support_no_fixup_chains" >&6; }
+
     { printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for -exported_symbols_list linker flag" >&5
 printf %s "checking for -exported_symbols_list linker flag... " >&6; }
 if test ${lt_cv_ld_exported_symbols_list+y}
@@ -8938,7 +8919,7 @@ _LT_EOF
       echo "$RANLIB libconftest.a" >&5
       $RANLIB libconftest.a 2>&5
       cat > conftest.c << _LT_EOF
-int main() { return 0;}
+int main(void) { return 0;}
 _LT_EOF
       echo "$LTCC $LTCFLAGS $LDFLAGS -o conftest conftest.c -Wl,-force_load,./libconftest.a" >&5
       $LTCC $LTCFLAGS $LDFLAGS -o conftest conftest.c -Wl,-force_load,./libconftest.a 2>conftest.err
@@ -8967,13 +8948,32 @@ printf "%s\n" "$lt_cv_ld_force_load" >&6; }
         10.[012],*|,*powerpc*-darwin[5-8]*)
           _lt_dar_allow_undefined='$wl-flat_namespace $wl-undefined ${wl}suppress' ;;
         *)
-          _lt_dar_allow_undefined='$wl-undefined ${wl}dynamic_lookup' ;;
+          _lt_dar_allow_undefined='$wl-undefined ${wl}dynamic_lookup'
+          if test yes = "$lt_cv_support_no_fixup_chains"; then
+            as_fn_append _lt_dar_allow_undefined ' $wl-no_fixup_chains'
+          fi
+        ;;
       esac
     ;;
   esac
     if test yes = "$lt_cv_apple_cc_single_mod"; then
       _lt_dar_single_mod='$single_module'
     fi
+    _lt_dar_needs_single_mod=no
+    case $host_os in
+    rhapsody* | darwin1.*)
+      _lt_dar_needs_single_mod=yes ;;
+    darwin*)
+      # When targeting Mac OS X 10.4 (darwin 8) or later,
+      # -single_module is the default and -multi_module is unsupported.
+      # The toolchain on macOS 10.14 (darwin 18) and later cannot
+      # target any OS version that needs -single_module.
+      case ${MACOSX_DEPLOYMENT_TARGET-10.0},$host in
+      10.0,*-darwin[567].*|10.[0-3],*-darwin[5-9].*|10.[0-3],*-darwin1[0-7].*)
+        _lt_dar_needs_single_mod=yes ;;
+      esac
+    ;;
+    esac
     if test yes = "$lt_cv_ld_exported_symbols_list"; then
       _lt_dar_export_syms=' $wl-exported_symbols_list,$output_objdir/$libname-symbols.expsym'
     else
@@ -9067,7 +9067,7 @@ fi
 enable_win32_dll=yes
 
 case $host in
-*-*-cygwin* | *-*-mingw* | *-*-pw32* | *-*-cegcc*)
+*-*-cygwin* | *-*-mingw* | *-*-windows* | *-*-pw32* | *-*-cegcc*)
   if test -n "$ac_tool_prefix"; then
   # Extract the first word of "${ac_tool_prefix}as", so it can be a program name with args.
 set dummy ${ac_tool_prefix}as; ac_word=$2
@@ -9473,31 +9473,54 @@ fi
 
 
 
-
-# Check whether --with-pic was given.
+  # Check whether --enable-pic was given.
+if test ${enable_pic+y}
+then :
+  enableval=$enable_pic; lt_p=${PACKAGE-default}
+     case $enableval in
+     yes|no) pic_mode=$enableval ;;
+     *)
+       pic_mode=default
+       # Look at the argument we got.  We use all the common list separators.
+       lt_save_ifs=$IFS; IFS=$IFS$PATH_SEPARATOR,
+       for lt_pkg in $enableval; do
+	 IFS=$lt_save_ifs
+	 if test "X$lt_pkg" = "X$lt_p"; then
+	   pic_mode=yes
+	 fi
+       done
+       IFS=$lt_save_ifs
+       ;;
+     esac
+else case e in #(
+  e)           # Check whether --with-pic was given.
 if test ${with_pic+y}
 then :
   withval=$with_pic; lt_p=${PACKAGE-default}
-    case $withval in
-    yes|no) pic_mode=$withval ;;
-    *)
-      pic_mode=default
-      # Look at the argument we got.  We use all the common list separators.
-      lt_save_ifs=$IFS; IFS=$IFS$PATH_SEPARATOR,
-      for lt_pkg in $withval; do
-	IFS=$lt_save_ifs
-	if test "X$lt_pkg" = "X$lt_p"; then
-	  pic_mode=yes
-	fi
-      done
-      IFS=$lt_save_ifs
-      ;;
-    esac
+	 case $withval in
+	 yes|no) pic_mode=$withval ;;
+	 *)
+	   pic_mode=default
+	   # Look at the argument we got.  We use all the common list separators.
+	   lt_save_ifs=$IFS; IFS=$IFS$PATH_SEPARATOR,
+	   for lt_pkg in $withval; do
+	     IFS=$lt_save_ifs
+	     if test "X$lt_pkg" = "X$lt_p"; then
+	       pic_mode=yes
+	     fi
+	   done
+	   IFS=$lt_save_ifs
+	   ;;
+	 esac
 else case e in #(
   e) pic_mode=default ;;
 esac
 fi
 
+     ;;
+esac
+fi
+
 
 
 
@@ -9542,18 +9565,29 @@ case $host,$enable_shared in
 power*-*-aix[5-9]*,yes)
   { printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking which variant of shared library versioning to provide" >&5
 printf %s "checking which variant of shared library versioning to provide... " >&6; }
-
-# Check whether --with-aix-soname was given.
+  # Check whether --enable-aix-soname was given.
+if test ${enable_aix_soname+y}
+then :
+  enableval=$enable_aix_soname; case $enableval in
+     aix|svr4|both)
+       ;;
+     *)
+       as_fn_error $? "Unknown argument to --enable-aix-soname" "$LINENO" 5
+       ;;
+     esac
+     lt_cv_with_aix_soname=$enable_aix_soname
+else case e in #(
+  e) # Check whether --with-aix-soname was given.
 if test ${with_aix_soname+y}
 then :
   withval=$with_aix_soname; case $withval in
-    aix|svr4|both)
-      ;;
-    *)
-      as_fn_error $? "Unknown argument to --with-aix-soname" "$LINENO" 5
-      ;;
-    esac
-    lt_cv_with_aix_soname=$with_aix_soname
+         aix|svr4|both)
+           ;;
+         *)
+           as_fn_error $? "Unknown argument to --with-aix-soname" "$LINENO" 5
+           ;;
+         esac
+         lt_cv_with_aix_soname=$with_aix_soname
 else case e in #(
   e) if test ${lt_cv_with_aix_soname+y}
 then :
@@ -9561,12 +9595,16 @@ then :
 else case e in #(
   e) lt_cv_with_aix_soname=aix ;;
 esac
+fi
+ ;;
+esac
 fi
 
-    with_aix_soname=$lt_cv_with_aix_soname ;;
+     enable_aix_soname=$lt_cv_with_aix_soname ;;
 esac
 fi
 
+  with_aix_soname=$enable_aix_soname
   { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $with_aix_soname" >&5
 printf "%s\n" "$with_aix_soname" >&6; }
   if test aix != "$with_aix_soname"; then
@@ -9882,7 +9920,7 @@ objext=$objext
 lt_simple_compile_test_code="int some_variable = 0;"
 
 # Code to be used in simple link tests
-lt_simple_link_test_code='int main(){return(0);}'
+lt_simple_link_test_code='int main(void){return(0);}'
 
 
 
@@ -10024,7 +10062,7 @@ lt_prog_compiler_static=
       # PIC is the default for these OSes.
       ;;
 
-    mingw* | cygwin* | pw32* | os2* | cegcc*)
+    mingw* | windows* | cygwin* | pw32* | os2* | cegcc*)
       # This hack is so that the source file can tell whether it is being
       # built for inclusion in a dll (and should export symbols for example).
       # Although the cygwin gcc ignores -fPIC, still need this for old-style
@@ -10127,7 +10165,7 @@ lt_prog_compiler_static=
       esac
       ;;
 
-    mingw* | cygwin* | pw32* | os2* | cegcc*)
+    mingw* | windows* | cygwin* | pw32* | os2* | cegcc*)
       # This hack is so that the source file can tell whether it is being
       # built for inclusion in a dll (and should export symbols for example).
       lt_prog_compiler_pic='-DDLL_EXPORT'
@@ -10168,6 +10206,12 @@ lt_prog_compiler_static=
 	lt_prog_compiler_pic='-KPIC'
 	lt_prog_compiler_static='-static'
         ;;
+      *flang* | ftn | f18* | f95*)
+        # Flang compiler.
+	lt_prog_compiler_wl='-Wl,'
+	lt_prog_compiler_pic='-fPIC'
+	lt_prog_compiler_static='-static'
+        ;;
       # icc used to be incompatible with GCC.
       # ICC 10 doesn't accept -KPIC any more.
       icc* | ifort*)
@@ -10250,6 +10294,12 @@ lt_prog_compiler_static=
       lt_prog_compiler_static='-Bstatic'
       ;;
 
+    *-mlibc)
+      lt_prog_compiler_wl='-Wl,'
+      lt_prog_compiler_pic='-fPIC'
+      lt_prog_compiler_static='-static'
+      ;;
+
     *nto* | *qnx*)
       # QNX uses GNU C++, but need to define -shared option too, otherwise
       # it will coredump.
@@ -10266,6 +10316,9 @@ lt_prog_compiler_static=
       lt_prog_compiler_static='-non_shared'
       ;;
 
+    serenity*)
+      ;;
+
     solaris*)
       lt_prog_compiler_pic='-KPIC'
       lt_prog_compiler_static='-Bstatic'
@@ -10639,7 +10692,7 @@ printf %s "checking whether the $compiler linker ($LD) supports shared libraries
   extract_expsyms_cmds=
 
   case $host_os in
-  cygwin* | mingw* | pw32* | cegcc*)
+  cygwin* | mingw* | windows* | pw32* | cegcc*)
     # FIXME: the MSVC++ and ICC port hasn't been tested in a loooong time
     # When not using gcc, we currently assume that we are using
     # Microsoft Visual C++ or Intel C++ Compiler.
@@ -10651,9 +10704,6 @@ printf %s "checking whether the $compiler linker ($LD) supports shared libraries
     # we just hope/assume this is gcc and not c89 (= MSVC++ or ICC)
     with_gnu_ld=yes
     ;;
-  openbsd* | bitrig*)
-    with_gnu_ld=no
-    ;;
   esac
 
   ld_shlibs=yes
@@ -10754,7 +10804,7 @@ _LT_EOF
       fi
       ;;
 
-    cygwin* | mingw* | pw32* | cegcc*)
+    cygwin* | mingw* | windows* | pw32* | cegcc*)
       # _LT_TAGVAR(hardcode_libdir_flag_spec, ) is actually meaningless,
       # as there is no search path for DLLs.
       hardcode_libdir_flag_spec='-L$libdir'
@@ -10764,6 +10814,7 @@ _LT_EOF
       enable_shared_with_static_runtimes=yes
       export_symbols_cmds='$NM $libobjs $convenience | $global_symbol_pipe | $SED -e '\''/^[BCDGRS][ ]/s/.*[ ]\([^ ]*\)/\1 DATA/;s/^.*[ ]__nm__\([^ ]*\)[ ][^ ]*/\1 DATA/;/^I[ ]/d;/^[AITW][ ]/s/.* //'\'' | sort | uniq > $export_symbols'
       exclude_expsyms='[_]+GLOBAL_OFFSET_TABLE_|[_]+GLOBAL__[FID]_.*|[_]+head_[A-Za-z0-9_]+_dll|[A-Za-z0-9_]+_dll_iname'
+      file_list_spec='@'
 
       if $LD --help 2>&1 | $GREP 'auto-import' > /dev/null; then
         archive_cmds='$CC -shared $libobjs $deplibs $compiler_flags -o $output_objdir/$soname $wl--enable-auto-image-base -Xlinker --out-implib -Xlinker $lib'
@@ -10783,7 +10834,7 @@ _LT_EOF
 
     haiku*)
       archive_cmds='$CC -shared $libobjs $deplibs $compiler_flags $wl-soname $wl$soname -o $lib'
-      link_all_deplibs=yes
+      link_all_deplibs=no
       ;;
 
     os2*)
@@ -10810,7 +10861,7 @@ _LT_EOF
 	cat $export_symbols | $prefix_cmds >> $output_objdir/$libname.def~
 	$CC -Zdll -Zcrtdll -o $output_objdir/$soname $libobjs $deplibs $compiler_flags $output_objdir/$libname.def~
 	emximp -o $lib $output_objdir/$libname.def'
-      old_archive_From_new_cmds='emximp -o $output_objdir/${libname}_dll.a $output_objdir/$libname.def'
+      old_archive_from_new_cmds='emximp -o $output_objdir/${libname}_dll.a $output_objdir/$libname.def'
       enable_shared_with_static_runtimes=yes
       file_list_spec='@'
       ;;
@@ -10889,6 +10940,7 @@ _LT_EOF
 
 	case $cc_basename in
 	tcc*)
+	  hardcode_libdir_flag_spec='$wl-rpath $wl$libdir'
 	  export_dynamic_flag_spec='-rdynamic'
 	  ;;
 	xlf* | bgf* | bgxlf* | mpixlf*)
@@ -10909,7 +10961,12 @@ _LT_EOF
       fi
       ;;
 
-    netbsd*)
+    *-mlibc)
+	archive_cmds='$CC -shared $pic_flag $libobjs $deplibs $compiler_flags $wl-soname $wl$soname -o $lib'
+	archive_expsym_cmds='$CC -shared $pic_flag $libobjs $deplibs $compiler_flags $wl-soname $wl$soname $wl-retain-symbols-file $wl$export_symbols -o $lib'
+      ;;
+
+    netbsd* | netbsdelf*-gnu)
       if echo __ELF__ | $CC -E - | $GREP __ELF__ >/dev/null; then
 	archive_cmds='$LD -Bshareable $libobjs $deplibs $linker_flags -o $lib'
 	wlarc=
@@ -11301,7 +11358,7 @@ fi
       export_dynamic_flag_spec=-rdynamic
       ;;
 
-    cygwin* | mingw* | pw32* | cegcc*)
+    cygwin* | mingw* | windows* | pw32* | cegcc*)
       # When not using gcc, we currently assume that we are using
       # Microsoft Visual C++ or Intel C++ Compiler.
       # hardcode_libdir_flag_spec is actually meaningless, as there is
@@ -11318,14 +11375,14 @@ fi
 	# Tell ltmain to make .dll files, not .so files.
 	shrext_cmds=.dll
 	# FIXME: Setting linknames here is a bad hack.
-	archive_cmds='$CC -o $output_objdir/$soname $libobjs $compiler_flags $deplibs -Wl,-DLL,-IMPLIB:"$tool_output_objdir$libname.dll.lib"~linknames='
+	archive_cmds='$CC -Fe$output_objdir/$soname $libobjs $compiler_flags $deplibs -Wl,-DLL,-IMPLIB:"$tool_output_objdir$libname.dll.lib"~linknames='
 	archive_expsym_cmds='if   test DEF = "`$SED -n     -e '\''s/^[	 ]*//'\''     -e '\''/^\(;.*\)*$/d'\''     -e '\''s/^\(EXPORTS\|LIBRARY\)\([	 ].*\)*$/DEF/p'\''     -e q     $export_symbols`" ; then
             cp "$export_symbols" "$output_objdir/$soname.def";
             echo "$tool_output_objdir$soname.def" > "$output_objdir/$soname.exp";
           else
             $SED -e '\''s/^/-link -EXPORT:/'\'' < $export_symbols > $output_objdir/$soname.exp;
           fi~
-          $CC -o $tool_output_objdir$soname $libobjs $compiler_flags $deplibs "@$tool_output_objdir$soname.exp" -Wl,-DLL,-IMPLIB:"$tool_output_objdir$libname.dll.lib"~
+          $CC -Fe$tool_output_objdir$soname $libobjs $compiler_flags $deplibs "@$tool_output_objdir$soname.exp" -Wl,-DLL,-IMPLIB:"$tool_output_objdir$libname.dll.lib"~
           linknames='
 	# The linker will not automatically build a static lib if we build a DLL.
 	# _LT_TAGVAR(old_archive_from_new_cmds, )='true'
@@ -11608,11 +11665,15 @@ printf "%s\n" "$lt_cv_irix_exported_symbol" >&6; }
 	# Fabrice Bellard et al's Tiny C Compiler
 	ld_shlibs=yes
 	archive_cmds='$CC -shared $pic_flag -o $lib $libobjs $deplibs $compiler_flags'
+	hardcode_libdir_flag_spec='$wl-rpath $wl$libdir'
 	;;
       esac
       ;;
 
-    netbsd*)
+    *-mlibc)
+      ;;
+
+    netbsd* | netbsdelf*-gnu)
       if echo __ELF__ | $CC -E - | $GREP __ELF__ >/dev/null; then
 	archive_cmds='$LD -Bshareable -o $lib $libobjs $deplibs $linker_flags'  # a.out
       else
@@ -11634,7 +11695,7 @@ printf "%s\n" "$lt_cv_irix_exported_symbol" >&6; }
     *nto* | *qnx*)
       ;;
 
-    openbsd* | bitrig*)
+    openbsd*)
       if test -f /usr/libexec/ld.so; then
 	hardcode_direct=yes
 	hardcode_shlibpath_var=no
@@ -11677,7 +11738,7 @@ printf "%s\n" "$lt_cv_irix_exported_symbol" >&6; }
 	cat $export_symbols | $prefix_cmds >> $output_objdir/$libname.def~
 	$CC -Zdll -Zcrtdll -o $output_objdir/$soname $libobjs $deplibs $compiler_flags $output_objdir/$libname.def~
 	emximp -o $lib $output_objdir/$libname.def'
-      old_archive_From_new_cmds='emximp -o $output_objdir/${libname}_dll.a $output_objdir/$libname.def'
+      old_archive_from_new_cmds='emximp -o $output_objdir/${libname}_dll.a $output_objdir/$libname.def'
       enable_shared_with_static_runtimes=yes
       file_list_spec='@'
       ;;
@@ -11713,6 +11774,9 @@ printf "%s\n" "$lt_cv_irix_exported_symbol" >&6; }
       hardcode_libdir_separator=:
       ;;
 
+    serenity*)
+      ;;
+
     solaris*)
       no_undefined_flag=' -z defs'
       if test yes = "$GCC"; then
@@ -12119,7 +12183,7 @@ if test yes = "$GCC"; then
     *) lt_awk_arg='/^libraries:/' ;;
   esac
   case $host_os in
-    mingw* | cegcc*) lt_sed_strip_eq='s|=\([A-Za-z]:\)|\1|g' ;;
+    mingw* | windows* | cegcc*) lt_sed_strip_eq='s|=\([A-Za-z]:\)|\1|g' ;;
     *) lt_sed_strip_eq='s|=/|/|g' ;;
   esac
   lt_search_path_spec=`$CC -print-search-dirs | awk $lt_awk_arg | $SED -e "s/^libraries://" -e $lt_sed_strip_eq`
@@ -12177,7 +12241,7 @@ BEGIN {RS = " "; FS = "/|\n";} {
   # AWK program above erroneously prepends '/' to C:/dos/paths
   # for these hosts.
   case $host_os in
-    mingw* | cegcc*) lt_search_path_spec=`$ECHO "$lt_search_path_spec" |\
+    mingw* | windows* | cegcc*) lt_search_path_spec=`$ECHO "$lt_search_path_spec" |\
       $SED 's|/\([A-Za-z]:\)|\1|g'` ;;
   esac
   sys_lib_search_path_spec=`$ECHO "$lt_search_path_spec" | $lt_NL2SP`
@@ -12251,7 +12315,7 @@ aix[4-9]*)
     # Unfortunately, runtime linking may impact performance, so we do
     # not want this to be the default eventually. Also, we use the
     # versioned .so libs for executables only if there is the -brtl
-    # linker flag in LDFLAGS as well, or --with-aix-soname=svr4 only.
+    # linker flag in LDFLAGS as well, or --enable-aix-soname=svr4 only.
     # To allow for filename-based versioning support, we need to create
     # libNAME.so.V as an archive file, containing:
     # *) an Import File, referring to the versioned filename of the
@@ -12345,7 +12409,7 @@ bsdi[45]*)
   # libtool to hard-code these into programs
   ;;
 
-cygwin* | mingw* | pw32* | cegcc*)
+cygwin* | mingw* | windows* | pw32* | cegcc*)
   version_type=windows
   shrext_cmds=.dll
   need_version=no
@@ -12356,15 +12420,29 @@ cygwin* | mingw* | pw32* | cegcc*)
     # gcc
     library_names_spec='$libname.dll.a'
     # DLL is installed to $(libdir)/../bin by postinstall_cmds
-    postinstall_cmds='base_file=`basename \$file`~
-      dlpath=`$SHELL 2>&1 -c '\''. $dir/'\''\$base_file'\''i; echo \$dlname'\''`~
-      dldir=$destdir/`dirname \$dlpath`~
-      test -d \$dldir || mkdir -p \$dldir~
-      $install_prog $dir/$dlname \$dldir/$dlname~
-      chmod a+x \$dldir/$dlname~
-      if test -n '\''$stripme'\'' && test -n '\''$striplib'\''; then
-        eval '\''$striplib \$dldir/$dlname'\'' || exit \$?;
-      fi'
+    # If user builds GCC with multilib enabled,
+    # it should just install on $(libdir)
+    # not on $(libdir)/../bin or 32 bits dlls would override 64 bit ones.
+    if test xyes = x"$multilib"; then
+      postinstall_cmds='base_file=`basename \$file`~
+        dlpath=`$SHELL 2>&1 -c '\''. $dir/'\''\$base_file'\''i; echo \$dlname'\''`~
+        dldir=$destdir/`dirname \$dlpath`~
+        $install_prog $dir/$dlname $destdir/$dlname~
+        chmod a+x $destdir/$dlname~
+        if test -n '\''$stripme'\'' && test -n '\''$striplib'\''; then
+          eval '\''$striplib $destdir/$dlname'\'' || exit \$?;
+        fi'
+    else
+      postinstall_cmds='base_file=`basename \$file`~
+        dlpath=`$SHELL 2>&1 -c '\''. $dir/'\''\$base_file'\''i; echo \$dlname'\''`~
+        dldir=$destdir/`dirname \$dlpath`~
+        test -d \$dldir || mkdir -p \$dldir~
+        $install_prog $dir/$dlname \$dldir/$dlname~
+        chmod a+x \$dldir/$dlname~
+        if test -n '\''$stripme'\'' && test -n '\''$striplib'\''; then
+          eval '\''$striplib \$dldir/$dlname'\'' || exit \$?;
+        fi'
+    fi
     postuninstall_cmds='dldll=`$SHELL 2>&1 -c '\''. $file; echo \$dlname'\''`~
       dlpath=$dir/\$dldll~
        $RM \$dlpath'
@@ -12377,7 +12455,7 @@ cygwin* | mingw* | pw32* | cegcc*)
 
       sys_lib_search_path_spec="$sys_lib_search_path_spec /usr/lib/w32api"
       ;;
-    mingw* | cegcc*)
+    mingw* | windows* | cegcc*)
       # MinGW DLLs use traditional 'lib' prefix
       soname_spec='$libname`echo $release | $SED -e 's/[.]/-/g'`$versuffix$shared_ext'
       ;;
@@ -12396,7 +12474,7 @@ cygwin* | mingw* | pw32* | cegcc*)
     library_names_spec='$libname.dll.lib'
 
     case $build_os in
-    mingw*)
+    mingw* | windows*)
       sys_lib_search_path_spec=
       lt_save_ifs=$IFS
       IFS=';'
@@ -12503,7 +12581,28 @@ freebsd* | dragonfly* | midnightbsd*)
       need_version=yes
       ;;
   esac
+  case $host_cpu in
+    powerpc64)
+      # On FreeBSD bi-arch platforms, a different variable is used for 32-bit
+      # binaries.  See <https://man.freebsd.org/cgi/man.cgi?query=ld.so>.
+      cat confdefs.h - <<_ACEOF >conftest.$ac_ext
+/* end confdefs.h.  */
+int test_pointer_size[sizeof (void *) - 5];
+
+_ACEOF
+if ac_fn_c_try_compile "$LINENO"
+then :
   shlibpath_var=LD_LIBRARY_PATH
+else case e in #(
+  e) shlibpath_var=LD_32_LIBRARY_PATH ;;
+esac
+fi
+rm -f core conftest.err conftest.$ac_objext conftest.beam conftest.$ac_ext
+      ;;
+    *)
+      shlibpath_var=LD_LIBRARY_PATH
+      ;;
+  esac
   case $host_os in
   freebsd2.*)
     shlibpath_overrides_runpath=yes
@@ -12533,8 +12632,9 @@ haiku*)
   soname_spec='$libname$release$shared_ext$major'
   shlibpath_var=LIBRARY_PATH
   shlibpath_overrides_runpath=no
-  sys_lib_dlsearch_path_spec='/boot/home/config/lib /boot/common/lib /boot/system/lib'
-  hardcode_into_libs=yes
+  sys_lib_search_path_spec='/boot/system/non-packaged/develop/lib /boot/system/develop/lib'
+  sys_lib_dlsearch_path_spec='/boot/home/config/non-packaged/lib /boot/home/config/lib /boot/system/non-packaged/lib /boot/system/lib'
+  hardcode_into_libs=no
   ;;
 
 hpux9* | hpux10* | hpux11*)
@@ -12644,7 +12744,7 @@ linux*android*)
   version_type=none # Android doesn't support versioned libraries.
   need_lib_prefix=no
   need_version=no
-  library_names_spec='$libname$release$shared_ext'
+  library_names_spec='$libname$release$shared_ext $libname$shared_ext'
   soname_spec='$libname$release$shared_ext'
   finish_cmds=
   shlibpath_var=LD_LIBRARY_PATH
@@ -12656,8 +12756,9 @@ linux*android*)
   hardcode_into_libs=yes
 
   dynamic_linker='Android linker'
-  # Don't embed -rpath directories since the linker doesn't support them.
-  hardcode_libdir_flag_spec='-L$libdir'
+  # -rpath works at least for libraries that are not overridden by
+  # libraries installed in system locations.
+  hardcode_libdir_flag_spec='$wl-rpath $wl$libdir'
   ;;
 
 # This must be glibc/ELF.
@@ -12714,7 +12815,7 @@ fi
   # before this can be enabled.
   hardcode_into_libs=yes
 
-  # Ideally, we could use ldconfig to report *all* directores which are
+  # Ideally, we could use ldconfig to report *all* directories which are
   # searched for libraries, however this is still not possible.  Aside from not
   # being certain /sbin/ldconfig is available, command
   # 'ldconfig -N -X -v | grep ^/' on 64bit Fedora does not report /usr/lib64,
@@ -12734,6 +12835,18 @@ fi
   dynamic_linker='GNU/Linux ld.so'
   ;;
 
+netbsdelf*-gnu)
+  version_type=linux
+  need_lib_prefix=no
+  need_version=no
+  library_names_spec='$libname$release$shared_ext$versuffix $libname$release$shared_ext$major $libname$shared_ext'
+  soname_spec='$libname$release$shared_ext$major'
+  shlibpath_var=LD_LIBRARY_PATH
+  shlibpath_overrides_runpath=no
+  hardcode_into_libs=yes
+  dynamic_linker='NetBSD ld.elf_so'
+  ;;
+
 netbsd*)
   version_type=sunos
   need_lib_prefix=no
@@ -12752,6 +12865,18 @@ netbsd*)
   hardcode_into_libs=yes
   ;;
 
+*-mlibc)
+  version_type=linux # correct to gnu/linux during the next big refactor
+  need_lib_prefix=no
+  need_version=no
+  library_names_spec='$libname$release$shared_ext$versuffix $libname$release$shared_ext$major $libname$shared_ext'
+  soname_spec='$libname$release$shared_ext$major'
+  dynamic_linker='mlibc ld.so'
+  shlibpath_var=LD_LIBRARY_PATH
+  shlibpath_overrides_runpath=no
+  hardcode_into_libs=yes
+  ;;
+
 newsos6)
   version_type=linux # correct to gnu/linux during the next big refactor
   library_names_spec='$libname$release$shared_ext$versuffix $libname$release$shared_ext$major $libname$shared_ext'
@@ -12771,7 +12896,7 @@ newsos6)
   dynamic_linker='ldqnx.so'
   ;;
 
-openbsd* | bitrig*)
+openbsd*)
   version_type=sunos
   sys_lib_dlsearch_path_spec=/usr/lib
   need_lib_prefix=no
@@ -12831,6 +12956,17 @@ rdos*)
   dynamic_linker=no
   ;;
 
+serenity*)
+  version_type=linux # correct to gnu/linux during the next big refactor
+  need_lib_prefix=no
+  need_version=no
+  library_names_spec='$libname$release$shared_ext$versuffix $libname$release$shared_ext$major $libname$shared_ext'
+  soname_spec='$libname$release$shared_ext$major'
+  shlibpath_var=LD_LIBRARY_PATH
+  shlibpath_overrides_runpath=no
+  dynamic_linker='SerenityOS LibELF'
+  ;;
+
 solaris*)
   version_type=linux # correct to gnu/linux during the next big refactor
   need_lib_prefix=no
@@ -12928,6 +13064,496 @@ uts4*)
   shlibpath_var=LD_LIBRARY_PATH
   ;;
 
+emscripten*)
+  version_type=none
+  need_lib_prefix=no
+  need_version=no
+  library_names_spec='$libname$release$shared_ext'
+  soname_spec='$libname$release$shared_ext'
+  finish_cmds=
+  dynamic_linker="Emscripten linker"
+  lt_prog_compiler_wl=
+lt_prog_compiler_pic=
+lt_prog_compiler_static=
+
+
+  if test yes = "$GCC"; then
+    lt_prog_compiler_wl='-Wl,'
+    lt_prog_compiler_static='-static'
+
+    case $host_os in
+      aix*)
+      # All AIX code is PIC.
+      if test ia64 = "$host_cpu"; then
+	# AIX 5 now supports IA64 processor
+	lt_prog_compiler_static='-Bstatic'
+      fi
+      lt_prog_compiler_pic='-fPIC'
+      ;;
+
+    amigaos*)
+      case $host_cpu in
+      powerpc)
+            # see comment about AmigaOS4 .so support
+            lt_prog_compiler_pic='-fPIC'
+        ;;
+      m68k)
+            # FIXME: we need at least 68020 code to build shared libraries, but
+            # adding the '-m68020' flag to GCC prevents building anything better,
+            # like '-m68040'.
+            lt_prog_compiler_pic='-m68020 -resident32 -malways-restore-a4'
+        ;;
+      esac
+      ;;
+
+    beos* | irix5* | irix6* | nonstopux* | osf3* | osf4* | osf5*)
+      # PIC is the default for these OSes.
+      ;;
+
+    mingw* | windows* | cygwin* | pw32* | os2* | cegcc*)
+      # This hack is so that the source file can tell whether it is being
+      # built for inclusion in a dll (and should export symbols for example).
+      # Although the cygwin gcc ignores -fPIC, still need this for old-style
+      # (--disable-auto-import) libraries
+      lt_prog_compiler_pic='-DDLL_EXPORT'
+      case $host_os in
+      os2*)
+	lt_prog_compiler_static='$wl-static'
+	;;
+      esac
+      ;;
+
+    darwin* | rhapsody*)
+      # PIC is the default on this platform
+      # Common symbols not allowed in MH_DYLIB files
+      lt_prog_compiler_pic='-fno-common'
+      ;;
+
+    haiku*)
+      # PIC is the default for Haiku.
+      # The "-static" flag exists, but is broken.
+      lt_prog_compiler_static=
+      ;;
+
+    hpux*)
+      # PIC is the default for 64-bit PA HP-UX, but not for 32-bit
+      # PA HP-UX.  On IA64 HP-UX, PIC is the default but the pic flag
+      # sets the default TLS model and affects inlining.
+      case $host_cpu in
+      hppa*64*)
+	# +Z the default
+	;;
+      *)
+	lt_prog_compiler_pic='-fPIC'
+	;;
+      esac
+      ;;
+
+    interix[3-9]*)
+      # Interix 3.x gcc -fpic/-fPIC options generate broken code.
+      # Instead, we relocate shared libraries at runtime.
+      ;;
+
+    msdosdjgpp*)
+      # Just because we use GCC doesn't mean we suddenly get shared libraries
+      # on systems that don't support them.
+      lt_prog_compiler_can_build_shared=no
+      enable_shared=no
+      ;;
+
+    *nto* | *qnx*)
+      # QNX uses GNU C++, but need to define -shared option too, otherwise
+      # it will coredump.
+      lt_prog_compiler_pic='-fPIC -shared'
+      ;;
+
+    sysv4*MP*)
+      if test -d /usr/nec; then
+	lt_prog_compiler_pic=-Kconform_pic
+      fi
+      ;;
+
+    *)
+      lt_prog_compiler_pic='-fPIC'
+      ;;
+    esac
+
+    case $cc_basename in
+    nvcc*) # Cuda Compiler Driver 2.2
+      lt_prog_compiler_wl='-Xlinker '
+      if test -n "$lt_prog_compiler_pic"; then
+        lt_prog_compiler_pic="-Xcompiler $lt_prog_compiler_pic"
+      fi
+      ;;
+    esac
+  else
+    # PORTME Check for flag to pass linker flags through the system compiler.
+    case $host_os in
+    aix*)
+      lt_prog_compiler_wl='-Wl,'
+      if test ia64 = "$host_cpu"; then
+	# AIX 5 now supports IA64 processor
+	lt_prog_compiler_static='-Bstatic'
+      else
+	lt_prog_compiler_static='-bnso -bI:/lib/syscalls.exp'
+      fi
+      ;;
+
+    darwin* | rhapsody*)
+      # PIC is the default on this platform
+      # Common symbols not allowed in MH_DYLIB files
+      lt_prog_compiler_pic='-fno-common'
+      case $cc_basename in
+      nagfor*)
+        # NAG Fortran compiler
+        lt_prog_compiler_wl='-Wl,-Wl,,'
+        lt_prog_compiler_pic='-PIC'
+        lt_prog_compiler_static='-Bstatic'
+        ;;
+      esac
+      ;;
+
+    mingw* | windows* | cygwin* | pw32* | os2* | cegcc*)
+      # This hack is so that the source file can tell whether it is being
+      # built for inclusion in a dll (and should export symbols for example).
+      lt_prog_compiler_pic='-DDLL_EXPORT'
+      case $host_os in
+      os2*)
+	lt_prog_compiler_static='$wl-static'
+	;;
+      esac
+      ;;
+
+    hpux9* | hpux10* | hpux11*)
+      lt_prog_compiler_wl='-Wl,'
+      # PIC is the default for IA64 HP-UX and 64-bit HP-UX, but
+      # not for PA HP-UX.
+      case $host_cpu in
+      hppa*64*|ia64*)
+	# +Z the default
+	;;
+      *)
+	lt_prog_compiler_pic='+Z'
+	;;
+      esac
+      # Is there a better lt_prog_compiler_static that works with the bundled CC?
+      lt_prog_compiler_static='$wl-a ${wl}archive'
+      ;;
+
+    irix5* | irix6* | nonstopux*)
+      lt_prog_compiler_wl='-Wl,'
+      # PIC (with -KPIC) is the default.
+      lt_prog_compiler_static='-non_shared'
+      ;;
+
+    linux* | k*bsd*-gnu | kopensolaris*-gnu | gnu*)
+      case $cc_basename in
+      # old Intel for x86_64, which still supported -KPIC.
+      ecc*)
+	lt_prog_compiler_wl='-Wl,'
+	lt_prog_compiler_pic='-KPIC'
+	lt_prog_compiler_static='-static'
+        ;;
+      *flang* | ftn | f18* | f95*)
+        # Flang compiler.
+	lt_prog_compiler_wl='-Wl,'
+	lt_prog_compiler_pic='-fPIC'
+	lt_prog_compiler_static='-static'
+        ;;
+      # icc used to be incompatible with GCC.
+      # ICC 10 doesn't accept -KPIC any more.
+      icc* | ifort*)
+	lt_prog_compiler_wl='-Wl,'
+	lt_prog_compiler_pic='-fPIC'
+	lt_prog_compiler_static='-static'
+        ;;
+      # Lahey Fortran 8.1.
+      lf95*)
+	lt_prog_compiler_wl='-Wl,'
+	lt_prog_compiler_pic='--shared'
+	lt_prog_compiler_static='--static'
+	;;
+      nagfor*)
+	# NAG Fortran compiler
+	lt_prog_compiler_wl='-Wl,-Wl,,'
+	lt_prog_compiler_pic='-PIC'
+	lt_prog_compiler_static='-Bstatic'
+	;;
+      tcc*)
+	# Fabrice Bellard et al's Tiny C Compiler
+	lt_prog_compiler_wl='-Wl,'
+	lt_prog_compiler_pic='-fPIC'
+	lt_prog_compiler_static='-static'
+	;;
+      pgcc* | pgf77* | pgf90* | pgf95* | pgfortran*)
+        # Portland Group compilers (*not* the Pentium gcc compiler,
+	# which looks to be a dead project)
+	lt_prog_compiler_wl='-Wl,'
+	lt_prog_compiler_pic='-fpic'
+	lt_prog_compiler_static='-Bstatic'
+        ;;
+      ccc*)
+        lt_prog_compiler_wl='-Wl,'
+        # All Alpha code is PIC.
+        lt_prog_compiler_static='-non_shared'
+        ;;
+      xl* | bgxl* | bgf* | mpixl*)
+	# IBM XL C 8.0/Fortran 10.1, 11.1 on PPC and BlueGene
+	lt_prog_compiler_wl='-Wl,'
+	lt_prog_compiler_pic='-qpic'
+	lt_prog_compiler_static='-qstaticlink'
+	;;
+      *)
+	case `$CC -V 2>&1 | $SED 5q` in
+	*Sun\ Ceres\ Fortran* | *Sun*Fortran*\ [1-7].* | *Sun*Fortran*\ 8.[0-3]*)
+	  # Sun Fortran 8.3 passes all unrecognized flags to the linker
+	  lt_prog_compiler_pic='-KPIC'
+	  lt_prog_compiler_static='-Bstatic'
+	  lt_prog_compiler_wl=''
+	  ;;
+	*Sun\ F* | *Sun*Fortran*)
+	  lt_prog_compiler_pic='-KPIC'
+	  lt_prog_compiler_static='-Bstatic'
+	  lt_prog_compiler_wl='-Qoption ld '
+	  ;;
+	*Sun\ C*)
+	  # Sun C 5.9
+	  lt_prog_compiler_pic='-KPIC'
+	  lt_prog_compiler_static='-Bstatic'
+	  lt_prog_compiler_wl='-Wl,'
+	  ;;
+        *Intel*\ [CF]*Compiler*)
+	  lt_prog_compiler_wl='-Wl,'
+	  lt_prog_compiler_pic='-fPIC'
+	  lt_prog_compiler_static='-static'
+	  ;;
+	*Portland\ Group*)
+	  lt_prog_compiler_wl='-Wl,'
+	  lt_prog_compiler_pic='-fpic'
+	  lt_prog_compiler_static='-Bstatic'
+	  ;;
+	esac
+	;;
+      esac
+      ;;
+
+    newsos6)
+      lt_prog_compiler_pic='-KPIC'
+      lt_prog_compiler_static='-Bstatic'
+      ;;
+
+    *-mlibc)
+      lt_prog_compiler_wl='-Wl,'
+      lt_prog_compiler_pic='-fPIC'
+      lt_prog_compiler_static='-static'
+      ;;
+
+    *nto* | *qnx*)
+      # QNX uses GNU C++, but need to define -shared option too, otherwise
+      # it will coredump.
+      lt_prog_compiler_pic='-fPIC -shared'
+      ;;
+
+    osf3* | osf4* | osf5*)
+      lt_prog_compiler_wl='-Wl,'
+      # All OSF/1 code is PIC.
+      lt_prog_compiler_static='-non_shared'
+      ;;
+
+    rdos*)
+      lt_prog_compiler_static='-non_shared'
+      ;;
+
+    serenity*)
+      ;;
+
+    solaris*)
+      lt_prog_compiler_pic='-KPIC'
+      lt_prog_compiler_static='-Bstatic'
+      case $cc_basename in
+      f77* | f90* | f95* | sunf77* | sunf90* | sunf95*)
+	lt_prog_compiler_wl='-Qoption ld ';;
+      *)
+	lt_prog_compiler_wl='-Wl,';;
+      esac
+      ;;
+
+    sunos4*)
+      lt_prog_compiler_wl='-Qoption ld '
+      lt_prog_compiler_pic='-PIC'
+      lt_prog_compiler_static='-Bstatic'
+      ;;
+
+    sysv4 | sysv4.2uw2* | sysv4.3*)
+      lt_prog_compiler_wl='-Wl,'
+      lt_prog_compiler_pic='-KPIC'
+      lt_prog_compiler_static='-Bstatic'
+      ;;
+
+    sysv4*MP*)
+      if test -d /usr/nec; then
+	lt_prog_compiler_pic='-Kconform_pic'
+	lt_prog_compiler_static='-Bstatic'
+      fi
+      ;;
+
+    sysv5* | unixware* | sco3.2v5* | sco5v6* | OpenUNIX*)
+      lt_prog_compiler_wl='-Wl,'
+      lt_prog_compiler_pic='-KPIC'
+      lt_prog_compiler_static='-Bstatic'
+      ;;
+
+    unicos*)
+      lt_prog_compiler_wl='-Wl,'
+      lt_prog_compiler_can_build_shared=no
+      ;;
+
+    uts4*)
+      lt_prog_compiler_pic='-pic'
+      lt_prog_compiler_static='-Bstatic'
+      ;;
+
+    *)
+      lt_prog_compiler_can_build_shared=no
+      ;;
+    esac
+  fi
+
+case $host_os in
+  # For platforms that do not support PIC, -DPIC is meaningless:
+  *djgpp*)
+    lt_prog_compiler_pic=
+    ;;
+  *)
+    lt_prog_compiler_pic="$lt_prog_compiler_pic -DPIC"
+    ;;
+esac
+
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking for $compiler option to produce PIC" >&5
+printf %s "checking for $compiler option to produce PIC... " >&6; }
+if test ${lt_cv_prog_compiler_pic+y}
+then :
+  printf %s "(cached) " >&6
+else case e in #(
+  e) lt_cv_prog_compiler_pic=$lt_prog_compiler_pic ;;
+esac
+fi
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $lt_cv_prog_compiler_pic" >&5
+printf "%s\n" "$lt_cv_prog_compiler_pic" >&6; }
+lt_prog_compiler_pic=$lt_cv_prog_compiler_pic
+
+#
+# Check to make sure the PIC flag actually works.
+#
+if test -n "$lt_prog_compiler_pic"; then
+  { printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking if $compiler PIC flag $lt_prog_compiler_pic works" >&5
+printf %s "checking if $compiler PIC flag $lt_prog_compiler_pic works... " >&6; }
+if test ${lt_cv_prog_compiler_pic_works+y}
+then :
+  printf %s "(cached) " >&6
+else case e in #(
+  e) lt_cv_prog_compiler_pic_works=no
+   ac_outfile=conftest.$ac_objext
+   echo "$lt_simple_compile_test_code" > conftest.$ac_ext
+   lt_compiler_flag="$lt_prog_compiler_pic -DPIC"  ## exclude from sc_useless_quotes_in_assignment
+   # Insert the option either (1) after the last *FLAGS variable, or
+   # (2) before a word containing "conftest.", or (3) at the end.
+   # Note that $ac_compile itself does not contain backslashes and begins
+   # with a dollar sign (not a hyphen), so the echo should work correctly.
+   # The option is referenced via a variable to avoid confusing sed.
+   lt_compile=`echo "$ac_compile" | $SED \
+   -e 's:.*FLAGS}\{0,1\} :&$lt_compiler_flag :; t' \
+   -e 's: [^ ]*conftest\.: $lt_compiler_flag&:; t' \
+   -e 's:$: $lt_compiler_flag:'`
+   (eval echo "\"\$as_me:$LINENO: $lt_compile\"" >&5)
+   (eval "$lt_compile" 2>conftest.err)
+   ac_status=$?
+   cat conftest.err >&5
+   echo "$as_me:$LINENO: \$? = $ac_status" >&5
+   if (exit $ac_status) && test -s "$ac_outfile"; then
+     # The compiler can only warn and ignore the option if not recognized
+     # So say no if there are warnings other than the usual output.
+     $ECHO "$_lt_compiler_boilerplate" | $SED '/^$/d' >conftest.exp
+     $SED '/^$/d; /^ *+/d' conftest.err >conftest.er2
+     if test ! -s conftest.er2 || diff conftest.exp conftest.er2 >/dev/null; then
+       lt_cv_prog_compiler_pic_works=yes
+     fi
+   fi
+   $RM conftest*
+ ;;
+esac
+fi
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $lt_cv_prog_compiler_pic_works" >&5
+printf "%s\n" "$lt_cv_prog_compiler_pic_works" >&6; }
+
+if test yes = "$lt_cv_prog_compiler_pic_works"; then
+    case $lt_prog_compiler_pic in
+     "" | " "*) ;;
+     *) lt_prog_compiler_pic=" $lt_prog_compiler_pic" ;;
+     esac
+else
+    lt_prog_compiler_pic=
+     lt_prog_compiler_can_build_shared=no
+fi
+
+fi
+
+
+
+
+
+#
+# Check to make sure the static flag actually works.
+#
+wl=$lt_prog_compiler_wl eval lt_tmp_static_flag=\"$lt_prog_compiler_static\"
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking if $compiler static flag $lt_tmp_static_flag works" >&5
+printf %s "checking if $compiler static flag $lt_tmp_static_flag works... " >&6; }
+if test ${lt_cv_prog_compiler_static_works+y}
+then :
+  printf %s "(cached) " >&6
+else case e in #(
+  e) lt_cv_prog_compiler_static_works=no
+   save_LDFLAGS=$LDFLAGS
+   LDFLAGS="$LDFLAGS $lt_tmp_static_flag"
+   echo "$lt_simple_link_test_code" > conftest.$ac_ext
+   if (eval $ac_link 2>conftest.err) && test -s conftest$ac_exeext; then
+     # The linker can only warn and ignore the option if not recognized
+     # So say no if there are warnings
+     if test -s conftest.err; then
+       # Append any errors to the config.log.
+       cat conftest.err 1>&5
+       $ECHO "$_lt_linker_boilerplate" | $SED '/^$/d' > conftest.exp
+       $SED '/^$/d; /^ *+/d' conftest.err >conftest.er2
+       if diff conftest.exp conftest.er2 >/dev/null; then
+         lt_cv_prog_compiler_static_works=yes
+       fi
+     else
+       lt_cv_prog_compiler_static_works=yes
+     fi
+   fi
+   $RM -r conftest*
+   LDFLAGS=$save_LDFLAGS
+ ;;
+esac
+fi
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $lt_cv_prog_compiler_static_works" >&5
+printf "%s\n" "$lt_cv_prog_compiler_static_works" >&6; }
+
+if test yes = "$lt_cv_prog_compiler_static_works"; then
+    :
+else
+    lt_prog_compiler_static=
+fi
+
+
+
+='-fPIC'
+  archive_cmds='$CC -sSIDE_MODULE=2 -shared $libobjs $deplibs $compiler_flags -o $lib'
+  archive_expsym_cmds='$SED "s|^|_|" $export_symbols >$output_objdir/$soname.expsym~$CC -sSIDE_MODULE=2 -shared $libobjs $deplibs $compiler_flags -o $lib -s EXPORTED_FUNCTIONS=@$output_objdir/$soname.expsym'
+  archive_cmds_need_lc=no
+  no_undefined_flag=
+  ;;
+
 *)
   dynamic_linker=no
   ;;
@@ -13112,7 +13738,7 @@ else
     lt_cv_dlopen_self=yes
     ;;
 
-  mingw* | pw32* | cegcc*)
+  mingw* | windows* | pw32* | cegcc*)
     lt_cv_dlopen=LoadLibrary
     lt_cv_dlopen_libs=
     ;;
@@ -13485,11 +14111,11 @@ else
 /* When -fvisibility=hidden is used, assume the code has been annotated
    correspondingly for the symbols needed.  */
 #if defined __GNUC__ && (((__GNUC__ == 3) && (__GNUC_MINOR__ >= 3)) || (__GNUC__ > 3))
-int fnord () __attribute__((visibility("default")));
+int fnord (void) __attribute__((visibility("default")));
 #endif
 
-int fnord () { return 42; }
-int main ()
+int fnord (void) { return 42; }
+int main (void)
 {
   void *self = dlopen (0, LT_DLGLOBAL|LT_DLLAZY_OR_NOW);
   int status = $lt_dlunknown;
@@ -13593,11 +14219,11 @@ else
 /* When -fvisibility=hidden is used, assume the code has been annotated
    correspondingly for the symbols needed.  */
 #if defined __GNUC__ && (((__GNUC__ == 3) && (__GNUC_MINOR__ >= 3)) || (__GNUC__ > 3))
-int fnord () __attribute__((visibility("default")));
+int fnord (void) __attribute__((visibility("default")));
 #endif
 
-int fnord () { return 42; }
-int main ()
+int fnord (void) { return 42; }
+int main (void)
 {
   void *self = dlopen (0, LT_DLGLOBAL|LT_DLLAZY_OR_NOW);
   int status = $lt_dlunknown;
@@ -15539,7 +16165,7 @@ cat >>$CONFIG_STATUS <<\_ACEOF || ac_write_fail=1
 # report actual input values of CONFIG_FILES etc. instead of their
 # values after options handling.
 ac_log="
-This file was extended by libpng $as_me 1.6.44, which was
+This file was extended by libpng $as_me 1.6.47, which was
 generated by GNU Autoconf 2.72.  Invocation command line was
 
   CONFIG_FILES    = $CONFIG_FILES
@@ -15607,7 +16233,7 @@ ac_cs_config_escaped=`printf "%s\n" "$ac_cs_config" | sed "s/^ //; s/'/'\\\\\\\\
 cat >>$CONFIG_STATUS <<_ACEOF || ac_write_fail=1
 ac_cs_config='$ac_cs_config_escaped'
 ac_cs_version="\\
-libpng config.status 1.6.44
+libpng config.status 1.6.47
 configured by $0, generated by GNU Autoconf 2.72,
   with options \\"\$ac_cs_config\\"
 
@@ -16735,19 +17361,18 @@ See 'config.log' for more details" "$LINENO" 5; }
     cat <<_LT_EOF >> "$cfgfile"
 #! $SHELL
 # Generated automatically by $as_me ($PACKAGE) $VERSION
-# Libtool was configured on host `(hostname || uname -n) 2>/dev/null | sed 1q`:
 # NOTE: Changes made to this file will be lost: look at ltmain.sh.
 
 # Provide generalized library-building support services.
 # Written by Gordon Matzigkeit, 1996
 
-# Copyright (C) 2014 Free Software Foundation, Inc.
+# Copyright (C) 2024 Free Software Foundation, Inc.
 # This is free software; see the source for copying conditions.  There is NO
 # warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 
 # GNU Libtool is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
-# the Free Software Foundation; either version 2 of of the License, or
+# the Free Software Foundation; either version 2 of the License, or
 # (at your option) any later version.
 #
 # As a special exception to the GNU General Public License, if you
@@ -17131,7 +17756,7 @@ hardcode_direct=$hardcode_direct
 
 # Set to "yes" if using DIR/libNAME\$shared_ext during linking hardcodes
 # DIR into the resulting binary and the resulting library dependency is
-# "absolute",i.e impossible to change by setting \$shlibpath_var if the
+# "absolute",i.e. impossible to change by setting \$shlibpath_var if the
 # library is relocated.
 hardcode_direct_absolute=$hardcode_direct_absolute
 
diff --git a/configure.ac b/configure.ac
index 22113b265..df48325e0 100644
--- a/configure.ac
+++ b/configure.ac
@@ -25,7 +25,7 @@ AC_PREREQ([2.68])
 
 dnl Version number stuff here:
 
-AC_INIT([libpng],[1.6.44],[png-mng-implement@lists.sourceforge.net])
+AC_INIT([libpng],[1.6.47],[png-mng-implement@lists.sourceforge.net])
 AC_CONFIG_MACRO_DIR([scripts/autoconf])
 
 # libpng does not follow GNU file name conventions (hence 'foreign')
@@ -46,10 +46,10 @@ dnl automake, so the following is not necessary (and is not defined anyway):
 dnl AM_PREREQ([1.11.2])
 dnl stop configure from automagically running automake
 
-PNGLIB_VERSION=1.6.44
+PNGLIB_VERSION=1.6.47
 PNGLIB_MAJOR=1
 PNGLIB_MINOR=6
-PNGLIB_RELEASE=44
+PNGLIB_RELEASE=47
 
 dnl End of version number stuff
 
diff --git a/contrib/.editorconfig b/contrib/.editorconfig
index e1b551df7..8b1466b1d 100644
--- a/contrib/.editorconfig
+++ b/contrib/.editorconfig
@@ -3,5 +3,7 @@
 root = false
 
 [*.[ch]]
+indent_size = unset
+indent_style = unset
 max_doc_length = unset
 max_line_length = unset
diff --git a/contrib/README.txt b/contrib/README.txt
index 97963c6d5..34dfbae4c 100644
--- a/contrib/README.txt
+++ b/contrib/README.txt
@@ -1,3 +1,5 @@
+External contributions to libpng
+--------------------------------
 
 This "contrib" directory contains contributions which are not necessarily under
 the libpng license, although all are open source.  They are not part of
diff --git a/contrib/conftest/fixed.dfa b/contrib/conftest/fixed.dfa
new file mode 100644
index 000000000..cb45f0136
--- /dev/null
+++ b/contrib/conftest/fixed.dfa
@@ -0,0 +1,15 @@
+# fixed.dfa
+#  Build time configuration of libpng
+#
+# Author: John Bowler
+# Copyright: (c) John Bowler, 2025
+# Usage rights:
+#  To the extent possible under law, the author has waived all copyright and
+#  related or neighboring rights to this work.  This work is published from:
+#  United States.
+#
+# Test the standard libpng configuration without floating point (the internal
+# fixed point implementations are used instead).
+#
+option FLOATING_ARITHMETIC off
+option FLOATING_POINT off
diff --git a/contrib/conftest/float-fixed.dfa b/contrib/conftest/float-fixed.dfa
new file mode 100644
index 000000000..c13da3198
--- /dev/null
+++ b/contrib/conftest/float-fixed.dfa
@@ -0,0 +1,14 @@
+# fixed-float.dfa
+#  Build time configuration of libpng
+#
+# Author: John Bowler
+# Copyright: (c) John Bowler, 2025
+# Usage rights:
+#  To the extent possible under law, the author has waived all copyright and
+#  related or neighboring rights to this work.  This work is published from:
+#  United States.
+#
+# Test the standard libpng configuration with the fixed point internal
+# implementation in place of the default floating point
+#
+option FLOATING_ARITHMETIC off
diff --git a/contrib/conftest/nocompile-limits.dfa b/contrib/conftest/nocompile-limits.dfa
new file mode 100644
index 000000000..24e1e2e08
--- /dev/null
+++ b/contrib/conftest/nocompile-limits.dfa
@@ -0,0 +1,21 @@
+# nolimits.dfa
+#  Build time configuration of libpng
+#
+# Author: John Bowler
+# Copyright: (c) John Bowler, 2025
+#
+# Usage rights:
+#  To the extent possible under law, the author has waived all copyright and
+#  related or neighboring rights to this work.  This work is published from:
+#  United States.
+#
+# Build libpng without any limits and without run-time settable limits.  Turning
+# USER_LIMITS off reduces libpng code size by allowing compile-time elimination
+# of some checking code.
+#
+option USER_LIMITS off
+
+@# define PNG_USER_WIDTH_MAX PNG_UINT_31_MAX
+@# define PNG_USER_HEIGHT_MAX PNG_UINT_31_MAX
+@# define PNG_USER_CHUNK_CACHE_MAX 0
+@# define PNG_USER_CHUNK_MALLOC_MAX 0
diff --git a/contrib/conftest/nolimits.dfa b/contrib/conftest/nolimits.dfa
new file mode 100644
index 000000000..5b37fcf72
--- /dev/null
+++ b/contrib/conftest/nolimits.dfa
@@ -0,0 +1,19 @@
+# nolimits.dfa
+#  Build time configuration of libpng
+#
+# Author: John Bowler
+# Copyright: (c) John Bowler, 2025
+#
+# Usage rights:
+#  To the extent possible under law, the author has waived all copyright and
+#  related or neighboring rights to this work.  This work is published from:
+#  United States.
+#
+# Build libpng without any limits.  With these settigs run-time limits are still
+# possible.
+#
+@# define PNG_USER_WIDTH_MAX PNG_UINT_31_MAX
+@# define PNG_USER_HEIGHT_MAX PNG_UINT_31_MAX
+@# define PNG_USER_CHUNK_CACHE_MAX 0
+@# define PNG_USER_CHUNK_MALLOC_MAX 0
+
diff --git a/contrib/examples/README.txt b/contrib/examples/README.txt
index 48dab4f0f..7833d536c 100644
--- a/contrib/examples/README.txt
+++ b/contrib/examples/README.txt
@@ -1,4 +1,3 @@
-
 This directory (contrib/examples) contains examples of libpng usage.
 
 NO COPYRIGHT RIGHTS ARE CLAIMED TO ANY OF THE FILES IN THIS DIRECTORY.
diff --git a/contrib/libtests/pngimage.c b/contrib/libtests/pngimage.c
index be176b2bc..2e2dd0894 100644
--- a/contrib/libtests/pngimage.c
+++ b/contrib/libtests/pngimage.c
@@ -1,4 +1,3 @@
-
 /* pngimage.c
  *
  * Copyright (c) 2021 Cosmin Truta
@@ -543,6 +542,7 @@ typedef enum
 struct display
 {
    jmp_buf        error_return;      /* Where to go to on error */
+   error_level    error_code;        /* Set before longjmp */
 
    const char    *filename;          /* The name of the original file */
    const char    *operation;         /* Operation being performed */
@@ -763,7 +763,10 @@ display_log(struct display *dp, error_level level, const char *fmt, ...)
 
    /* Errors cause this routine to exit to the fail code */
    if (level > APP_FAIL || (level > ERRORS && !(dp->options & CONTINUE)))
+   {
+      dp->error_code = level;
       longjmp(dp->error_return, level);
+    }
 }
 
 /* error handler callbacks for libpng */
@@ -1019,7 +1022,12 @@ compare_read(struct display *dp, int applied_transforms)
    C(height);
    C(bit_depth);
    C(color_type);
-   C(interlace_method);
+#  ifdef PNG_WRITE_INTERLACING_SUPPORTED
+      /* If write interlace has been disabled, the PNG file is still
+       * written correctly, but as a regular (not-interlaced) PNG.
+       */
+      C(interlace_method);
+#  endif
    C(compression_method);
    C(filter_method);
 
@@ -1566,18 +1574,19 @@ static int
 do_test(struct display *dp, const char *file)
    /* Exists solely to isolate the setjmp clobbers */
 {
-   int ret = setjmp(dp->error_return);
+   dp->error_code = VERBOSE; /* The "lowest" level */
 
-   if (ret == 0)
+   if (setjmp(dp->error_return) == 0)
    {
       test_one_file(dp, file);
       return 0;
    }
 
-   else if (ret < ERRORS) /* shouldn't longjmp on warnings */
-      display_log(dp, INTERNAL_ERROR, "unexpected return code %d", ret);
+   else if (dp->error_code < ERRORS) /* shouldn't longjmp on warnings */
+      display_log(dp, INTERNAL_ERROR, "unexpected return code %d",
+                  dp->error_code);
 
-   return ret;
+   return dp->error_code;
 }
 
 int
@@ -1677,7 +1686,11 @@ main(int argc, char **argv)
             int ret = do_test(&d, argv[i]);
 
             if (ret > QUIET) /* abort on user or internal error */
+            {
+               display_clean(&d);
+               display_destroy(&d);
                return 99;
+            }
          }
 
          /* Here on any return, including failures, except user/internal issues
diff --git a/contrib/libtests/pngstest.c b/contrib/libtests/pngstest.c
index 973e60f52..1d15421b5 100644
--- a/contrib/libtests/pngstest.c
+++ b/contrib/libtests/pngstest.c
@@ -1,4 +1,3 @@
-
 /* pngstest.c
  *
  * Copyright (c) 2021 Cosmin Truta
@@ -3500,7 +3499,7 @@ main(int argc, char **argv)
    int retval = 0;
    int c;
 
-#if PNG_LIBPNG_VER >= 10700
+#if PNG_LIBPNG_VER == 10700
       /* This error should not exist in 1.7 or later: */
       opts |= GBG_ERROR;
 #endif
diff --git a/contrib/libtests/pngunknown.c b/contrib/libtests/pngunknown.c
index dfa9d10a1..47a84d984 100644
--- a/contrib/libtests/pngunknown.c
+++ b/contrib/libtests/pngunknown.c
@@ -1,4 +1,3 @@
-
 /* pngunknown.c - test the read side unknown chunk handling
  *
  * Copyright (c) 2021 Cosmin Truta
@@ -114,6 +113,8 @@ typedef png_byte *png_const_bytep;
 #define png_PLTE PNG_U32( 80,  76,  84,  69)
 #define png_bKGD PNG_U32( 98,  75,  71,  68)
 #define png_cHRM PNG_U32( 99,  72,  82,  77)
+#define png_cICP PNG_U32( 99,  73,  67,  80) /* PNGv3 */
+#define png_cLLI PNG_U32( 99,  76,  76,  73) /* PNGv3 */
 #define png_eXIf PNG_U32(101,  88,  73, 102) /* registered July 2017 */
 #define png_fRAc PNG_U32(102,  82,  65,  99) /* registered, not defined */
 #define png_gAMA PNG_U32(103,  65,  77,  65)
@@ -123,6 +124,7 @@ typedef png_byte *png_const_bytep;
 #define png_hIST PNG_U32(104,  73,  83,  84)
 #define png_iCCP PNG_U32(105,  67,  67,  80)
 #define png_iTXt PNG_U32(105,  84,  88, 116)
+#define png_mDCV PNG_U32(109,  68,  67,  86) /* PNGv3 */
 #define png_oFFs PNG_U32(111,  70,  70, 115)
 #define png_pCAL PNG_U32(112,  67,  65,  76)
 #define png_pHYs PNG_U32(112,  72,  89, 115)
@@ -209,6 +211,20 @@ static struct
          0,
 #     else
          1,
+#     endif
+      1,  START, 0 },
+   { "cICP", PNG_INFO_cICP, png_cICP,
+#     ifdef PNG_READ_cICP_SUPPORTED
+         0,
+#     else
+         1,
+#     endif
+      1,  START, 0 },
+   { "cLLI", PNG_INFO_cLLI, png_cLLI,
+#     ifdef PNG_READ_cLLI_SUPPORTED
+         0,
+#     else
+         1,
 #     endif
       1,  START, 0 },
    { "eXIf", PNG_INFO_eXIf, png_eXIf,
@@ -246,6 +262,13 @@ static struct
          1,
 #     endif
       1, ABSENT, 0 },
+   { "mDCV", PNG_INFO_mDCV, png_mDCV,
+#     ifdef PNG_READ_mDCV_SUPPORTED
+         0,
+#     else
+         1,
+#     endif
+      1,  START, 0 },
    { "oFFs", PNG_INFO_oFFs, png_oFFs,
 #     ifdef PNG_READ_oFFs_SUPPORTED
          0,
diff --git a/contrib/libtests/pngvalid.c b/contrib/libtests/pngvalid.c
index 3d66154dd..bddf32141 100644
--- a/contrib/libtests/pngvalid.c
+++ b/contrib/libtests/pngvalid.c
@@ -1,4 +1,3 @@
-
 /* pngvalid.c - validate libpng by constructing then reading png files.
  *
  * Copyright (c) 2021 Cosmin Truta
@@ -304,20 +303,20 @@ make_four_random_bytes(png_uint_32* seed, png_bytep bytes)
 #if defined PNG_READ_SUPPORTED || defined PNG_WRITE_tRNS_SUPPORTED ||\
     defined PNG_WRITE_FILTER_SUPPORTED
 static void
-randomize(void *pv, size_t size)
+randomize_bytes(void *pv, size_t size)
 {
    static png_uint_32 random_seed[2] = {0x56789abc, 0xd};
    make_random_bytes(random_seed, pv, size);
 }
 
-#define R8(this) randomize(&(this), sizeof (this))
+#define R8(this) randomize_bytes(&(this), sizeof (this))
 
 #ifdef PNG_READ_SUPPORTED
 static png_byte
 random_byte(void)
 {
    unsigned char b1[1];
-   randomize(b1, sizeof b1);
+   randomize_bytes(b1, sizeof b1);
    return b1[0];
 }
 #endif /* READ */
@@ -326,7 +325,7 @@ static png_uint_16
 random_u16(void)
 {
    unsigned char b2[2];
-   randomize(b2, sizeof b2);
+   randomize_bytes(b2, sizeof b2);
    return png_get_uint_16(b2);
 }
 
@@ -336,7 +335,7 @@ static png_uint_32
 random_u32(void)
 {
    unsigned char b4[4];
-   randomize(b4, sizeof b4);
+   randomize_bytes(b4, sizeof b4);
    return png_get_uint_32(b4);
 }
 #endif /* READ_FILLER || READ_RGB_TO_GRAY */
@@ -2574,7 +2573,7 @@ modifier_init(png_modifier *pm)
  * in the rgb_to_gray check, replacing it with an exact copy of the libpng 1.5
  * algorithm.
  */
-#define DIGITIZE PNG_LIBPNG_VER < 10700
+#define DIGITIZE PNG_LIBPNG_VER != 10700
 
 /* If pm->calculations_use_input_precision is set then operations will happen
  * with the precision of the input, not the precision of the output depth.
@@ -3986,7 +3985,7 @@ transform_row(png_const_structp pp, png_byte buffer[TRANSFORM_ROWMAX],
 #  define check_interlace_type(type) ((void)(type))
 #  define set_write_interlace_handling(pp,type) png_set_interlace_handling(pp)
 #  define do_own_interlace 0
-#elif PNG_LIBPNG_VER < 10700
+#elif PNG_LIBPNG_VER != 10700
 #  define set_write_interlace_handling(pp,type) (1)
 static void
 check_interlace_type(int const interlace_type)
@@ -4014,7 +4013,7 @@ check_interlace_type(int const interlace_type)
 #  define do_own_interlace 1
 #endif /* WRITE_INTERLACING tests */
 
-#if PNG_LIBPNG_VER >= 10700 || defined PNG_WRITE_INTERLACING_SUPPORTED
+#if PNG_LIBPNG_VER == 10700 || defined PNG_WRITE_INTERLACING_SUPPORTED
 #   define CAN_WRITE_INTERLACE 1
 #else
 #   define CAN_WRITE_INTERLACE 0
@@ -4633,10 +4632,10 @@ static const struct
     {
        /* no warnings makes these errors undetectable prior to 1.7.0 */
        { sBIT0_error_fn, "sBIT(0): failed to detect error",
-         PNG_LIBPNG_VER < 10700 },
+         PNG_LIBPNG_VER != 10700 },
 
        { sBIT_error_fn, "sBIT(too big): failed to detect error",
-         PNG_LIBPNG_VER < 10700 },
+         PNG_LIBPNG_VER != 10700 },
     };
 
 static void
@@ -6236,7 +6235,7 @@ image_pixel_add_alpha(image_pixel *this, const standard_display *display,
    {
       if (this->colour_type == PNG_COLOR_TYPE_GRAY)
       {
-#        if PNG_LIBPNG_VER < 10700
+#        if PNG_LIBPNG_VER != 10700
             if (!for_background && this->bit_depth < 8)
                this->bit_depth = this->sample_depth = 8;
 #        endif
@@ -6246,7 +6245,7 @@ image_pixel_add_alpha(image_pixel *this, const standard_display *display,
             /* After 1.7 the expansion of bit depth only happens if there is a
              * tRNS chunk to expand at this point.
              */
-#           if PNG_LIBPNG_VER >= 10700
+#           if PNG_LIBPNG_VER == 10700
                if (!for_background && this->bit_depth < 8)
                   this->bit_depth = this->sample_depth = 8;
 #           endif
@@ -7127,7 +7126,7 @@ image_transform_png_set_tRNS_to_alpha_mod(const image_transform *this,
    image_pixel *that, png_const_structp pp,
    const transform_display *display)
 {
-#if PNG_LIBPNG_VER < 10700
+#if PNG_LIBPNG_VER != 10700
    /* LIBPNG BUG: this always forces palette images to RGB. */
    if (that->colour_type == PNG_COLOR_TYPE_PALETTE)
       image_pixel_convert_PLTE(that);
@@ -7137,13 +7136,13 @@ image_transform_png_set_tRNS_to_alpha_mod(const image_transform *this,
     * convert to an alpha channel.
     */
    if (that->have_tRNS)
-#     if PNG_LIBPNG_VER >= 10700
+#     if PNG_LIBPNG_VER == 10700
          if (that->colour_type != PNG_COLOR_TYPE_PALETTE &&
              (that->colour_type & PNG_COLOR_MASK_ALPHA) == 0)
 #     endif
       image_pixel_add_alpha(that, &display->this, 0/*!for background*/);
 
-#if PNG_LIBPNG_VER < 10700
+#if PNG_LIBPNG_VER != 10700
    /* LIBPNG BUG: otherwise libpng still expands to 8 bits! */
    else
    {
@@ -7172,7 +7171,7 @@ image_transform_png_set_tRNS_to_alpha_add(image_transform *this,
     * any action on a palette image.
     */
    return
-#  if PNG_LIBPNG_VER >= 10700
+#  if PNG_LIBPNG_VER == 10700
       colour_type != PNG_COLOR_TYPE_PALETTE &&
 #  endif
    (colour_type & PNG_COLOR_MASK_ALPHA) == 0;
@@ -7313,7 +7312,7 @@ image_transform_png_set_expand_gray_1_2_4_to_8_mod(
     const image_transform *this, image_pixel *that, png_const_structp pp,
     const transform_display *display)
 {
-#if PNG_LIBPNG_VER < 10700
+#if PNG_LIBPNG_VER != 10700
    image_transform_png_set_expand_mod(this, that, pp, display);
 #else
    /* Only expand grayscale of bit depth less than 8: */
@@ -7329,7 +7328,7 @@ static int
 image_transform_png_set_expand_gray_1_2_4_to_8_add(image_transform *this,
     const image_transform **that, png_byte colour_type, png_byte bit_depth)
 {
-#if PNG_LIBPNG_VER < 10700
+#if PNG_LIBPNG_VER != 10700
    return image_transform_png_set_expand_add(this, that, colour_type,
       bit_depth);
 #else
@@ -7359,7 +7358,7 @@ image_transform_png_set_expand_16_set(const image_transform *this,
    png_set_expand_16(pp);
 
    /* NOTE: prior to 1.7 libpng does SET_EXPAND as well, so tRNS is expanded. */
-#  if PNG_LIBPNG_VER < 10700
+#  if PNG_LIBPNG_VER != 10700
       if (that->this.has_tRNS)
          that->this.is_transparent = 1;
 #  endif
@@ -7412,7 +7411,7 @@ image_transform_png_set_scale_16_set(const image_transform *this,
     transform_display *that, png_structp pp, png_infop pi)
 {
    png_set_scale_16(pp);
-#  if PNG_LIBPNG_VER < 10700
+#  if PNG_LIBPNG_VER != 10700
       /* libpng will limit the gamma table size: */
       that->max_gamma_8 = PNG_MAX_GAMMA_8;
 #  endif
@@ -7460,7 +7459,7 @@ image_transform_png_set_strip_16_set(const image_transform *this,
     transform_display *that, png_structp pp, png_infop pi)
 {
    png_set_strip_16(pp);
-#  if PNG_LIBPNG_VER < 10700
+#  if PNG_LIBPNG_VER != 10700
       /* libpng will limit the gamma table size: */
       that->max_gamma_8 = PNG_MAX_GAMMA_8;
 #  endif
@@ -7647,7 +7646,7 @@ image_transform_png_set_rgb_to_gray_ini(const image_transform *this,
    else
    {
       /* The default (built in) coefficients, as above: */
-#     if PNG_LIBPNG_VER < 10700
+#     if PNG_LIBPNG_VER != 10700
          data.red_coefficient = 6968 / 32768.;
          data.green_coefficient = 23434 / 32768.;
          data.blue_coefficient = 2366 / 32768.;
@@ -7730,7 +7729,7 @@ image_transform_png_set_rgb_to_gray_ini(const image_transform *this,
           *  conversion adds another +/-2 in the 16-bit case and
           *  +/-(1<<(15-PNG_MAX_GAMMA_8)) in the 8-bit case.
           */
-#        if PNG_LIBPNG_VER < 10700
+#        if PNG_LIBPNG_VER != 10700
             if (that->this.bit_depth < 16)
                that->max_gamma_8 = PNG_MAX_GAMMA_8;
 #        endif
@@ -7907,7 +7906,7 @@ image_transform_png_set_rgb_to_gray_mod(const image_transform *this,
    {
       double gray, err;
 
-#     if PNG_LIBPNG_VER < 10700
+#     if PNG_LIBPNG_VER != 10700
          if (that->colour_type == PNG_COLOR_TYPE_PALETTE)
             image_pixel_convert_PLTE(that);
 #     endif
@@ -8094,7 +8093,7 @@ image_transform_png_set_rgb_to_gray_mod(const image_transform *this,
          double b = that->bluef;
          double be = that->bluee;
 
-#        if PNG_LIBPNG_VER < 10700
+#        if PNG_LIBPNG_VER != 10700
             /* The true gray case involves no math in earlier versions (not
              * true, there was some if gamma correction was happening too.)
              */
@@ -9873,7 +9872,7 @@ gamma_component_validate(const char *name, const validate_info *vi,
              * lost.  This can result in up to a +/-1 error in the presence of
              * an sbit less than the bit depth.
              */
-#           if PNG_LIBPNG_VER < 10700
+#           if PNG_LIBPNG_VER != 10700
 #              define SBIT_ERROR .5
 #           else
 #              define SBIT_ERROR 1.
@@ -10733,7 +10732,7 @@ static void perform_gamma_scale16_tests(png_modifier *pm)
 #  ifndef PNG_MAX_GAMMA_8
 #     define PNG_MAX_GAMMA_8 11
 #  endif
-#  if defined PNG_MAX_GAMMA_8 || PNG_LIBPNG_VER < 10700
+#  if defined PNG_MAX_GAMMA_8 || PNG_LIBPNG_VER != 10700
 #     define SBIT_16_TO_8 PNG_MAX_GAMMA_8
 #  else
 #     define SBIT_16_TO_8 16
@@ -11736,7 +11735,7 @@ int main(int argc, char **argv)
     * code that 16-bit arithmetic is used for 8-bit samples when it would make a
     * difference.
     */
-   pm.assume_16_bit_calculations = PNG_LIBPNG_VER >= 10700;
+   pm.assume_16_bit_calculations = PNG_LIBPNG_VER == 10700;
 
    /* Currently 16 bit expansion happens at the end of the pipeline, so the
     * calculations are done in the input bit depth not the output.
@@ -11760,13 +11759,13 @@ int main(int argc, char **argv)
    pm.test_lbg_gamma_threshold = 1;
    pm.test_lbg_gamma_transform = PNG_LIBPNG_VER >= 10600;
    pm.test_lbg_gamma_sbit = 1;
-   pm.test_lbg_gamma_composition = PNG_LIBPNG_VER >= 10700;
+   pm.test_lbg_gamma_composition = PNG_LIBPNG_VER == 10700;
 
    /* And the test encodings */
    pm.encodings = test_encodings;
    pm.nencodings = ARRAY_SIZE(test_encodings);
 
-#  if PNG_LIBPNG_VER < 10700
+#  if PNG_LIBPNG_VER != 10700
       pm.sbitlow = 8U; /* because libpng doesn't do sBIT below 8! */
 #  else
       pm.sbitlow = 1U;
@@ -11796,7 +11795,7 @@ int main(int argc, char **argv)
    pm.maxout16 = .499;  /* Error in *encoded* value */
    pm.maxabs16 = .00005;/* 1/20000 */
    pm.maxcalc16 =1./65535;/* +/-1 in 16 bits for compose errors */
-#  if PNG_LIBPNG_VER < 10700
+#  if PNG_LIBPNG_VER != 10700
       pm.maxcalcG = 1./((1<<PNG_MAX_GAMMA_8)-1);
 #  else
       pm.maxcalcG = 1./((1<<16)-1);
diff --git a/contrib/libtests/readpng.c b/contrib/libtests/readpng.c
index 7528e90bd..376616a1f 100644
--- a/contrib/libtests/readpng.c
+++ b/contrib/libtests/readpng.c
@@ -1,4 +1,3 @@
-
 /* readpng.c
  *
  * Copyright (c) 2013 John Cunningham Bowler
diff --git a/contrib/libtests/tarith.c b/contrib/libtests/tarith.c
index e35b7ab26..d41b9e177 100644
--- a/contrib/libtests/tarith.c
+++ b/contrib/libtests/tarith.c
@@ -1,4 +1,3 @@
-
 /* tarith.c
  *
  * Copyright (c) 2021 Cosmin Truta
diff --git a/contrib/libtests/timepng.c b/contrib/libtests/timepng.c
index 0093a4548..a66f51345 100644
--- a/contrib/libtests/timepng.c
+++ b/contrib/libtests/timepng.c
@@ -1,4 +1,3 @@
-
 /* timepng.c
  *
  * Copyright (c) 2013,2016 John Cunningham Bowler
diff --git a/contrib/mips-mmi/linux.c b/contrib/mips-mmi/linux.c
index 31525fde9..dc003807c 100644
--- a/contrib/mips-mmi/linux.c
+++ b/contrib/mips-mmi/linux.c
@@ -1,4 +1,3 @@
-
 /* contrib/mips-mmi/linux.c
  *
  * Copyright (c) 2024 Cosmin Truta
diff --git a/contrib/mips-msa/linux.c b/contrib/mips-msa/linux.c
index cae8ca50f..5651df707 100644
--- a/contrib/mips-msa/linux.c
+++ b/contrib/mips-msa/linux.c
@@ -1,4 +1,3 @@
-
 /* contrib/mips-msa/linux.c
  *
  * Copyright (c) 2020-2023 Cosmin Truta
diff --git a/contrib/oss-fuzz/Dockerfile b/contrib/oss-fuzz/Dockerfile
index c9bc4145e..f5bc1a985 100644
--- a/contrib/oss-fuzz/Dockerfile
+++ b/contrib/oss-fuzz/Dockerfile
@@ -1,5 +1,3 @@
-# Copyright 2024 Cosmin Truta
-# Copyright 2017 Glenn Randers-Pehrson
 # Copyright 2016 Google Inc.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
@@ -17,12 +15,11 @@
 ################################################################################
 
 FROM gcr.io/oss-fuzz-base/base-builder
-
+MAINTAINER glennrp@gmail.com
 RUN apt-get update && \
-    apt-get install -y make autoconf automake libtool zlib1g-dev
-
-RUN git clone --depth=1 https://github.com/pnggroup/libpng.git && \
-    git clone --depth=1 https://github.com/madler/zlib.git && \
-    cp libpng/contrib/oss-fuzz/build.sh $SRC
+    apt-get install -y make autoconf automake libtool
 
-WORKDIR /home/libpng
+RUN git clone --depth 1 https://github.com/madler/zlib.git
+RUN git clone --depth 1 https://github.com/glennrp/libpng.git
+RUN cp libpng/contrib/oss-fuzz/build.sh $SRC
+WORKDIR libpng
diff --git a/contrib/oss-fuzz/README.txt b/contrib/oss-fuzz/README.txt
index b01af52ac..66d5242c5 100644
--- a/contrib/oss-fuzz/README.txt
+++ b/contrib/oss-fuzz/README.txt
@@ -1,7 +1,3 @@
-libpng additions to oss-fuzz
-============================
-
-Copyright (c) 2024 Cosmin Truta
 Copyright (c) 2017 Glenn Randers-Pehrson
 
 This code is released under the libpng license.
diff --git a/contrib/oss-fuzz/build.sh b/contrib/oss-fuzz/build.sh
index 1970f9c06..7b8f02639 100755
--- a/contrib/oss-fuzz/build.sh
+++ b/contrib/oss-fuzz/build.sh
@@ -1,8 +1,6 @@
-#!/usr/bin/env bash
-set -eu
+#!/bin/bash -eu
 
-# Copyright 2024 Cosmin Truta
-# Copyright 2017 Glenn Randers-Pehrson
+# Copyright 2017-2018 Glenn Randers-Pehrson
 # Copyright 2016 Google Inc.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
@@ -17,31 +15,36 @@ set -eu
 # See the License for the specific language governing permissions and
 # limitations under the License.
 #
+# Revisions by Glenn Randers-Pehrson, 2017:
+# 1. Build only the library, not the tools (changed "make -j$(nproc) all" to
+#     "make -j$(nproc) libpng16.la").
+# 2. Disabled WARNING and WRITE options in pnglibconf.dfa.
+# 3. Build zlib alongside libpng
 ################################################################################
 
 # Disable logging via library build configuration control.
-sed -e "s/option STDIO/option STDIO disabled/" \
-    -e "s/option WARNING /option WARNING disabled/" \
-    -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
-    scripts/pnglibconf.dfa >scripts/pnglibconf.dfa.tmp
-mv -f scripts/pnglibconf.dfa.tmp scripts/pnglibconf.dfa
+cat scripts/pnglibconf.dfa | \
+  sed -e "s/option STDIO/option STDIO disabled/" \
+      -e "s/option WARNING /option WARNING disabled/" \
+      -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
+> scripts/pnglibconf.dfa.temp
+mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa
 
-# Build the libpng library ("libpng16.la"), excluding the auxiliary tools.
+# build the libpng library.
 autoreconf -f -i
 ./configure --with-libpng-prefix=OSS_FUZZ_
 make -j$(nproc) clean
 make -j$(nproc) libpng16.la
 
-# Build libpng_read_fuzzer.
+# build libpng_read_fuzzer.
 $CXX $CXXFLAGS -std=c++11 -I. \
      $SRC/libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc \
      -o $OUT/libpng_read_fuzzer \
      -lFuzzingEngine .libs/libpng16.a -lz
 
-# Add seed corpus.
+# add seed corpus.
 find $SRC/libpng -name "*.png" | grep -v crashers | \
      xargs zip $OUT/libpng_read_fuzzer_seed_corpus.zip
 
 cp $SRC/libpng/contrib/oss-fuzz/*.dict \
-   $SRC/libpng/contrib/oss-fuzz/*.options \
-   $OUT/
+     $SRC/libpng/contrib/oss-fuzz/*.options $OUT/
diff --git a/contrib/oss-fuzz/libpng_read_fuzzer.cc b/contrib/oss-fuzz/libpng_read_fuzzer.cc
index ad9f9adc6..bfb5d9d3d 100644
--- a/contrib/oss-fuzz/libpng_read_fuzzer.cc
+++ b/contrib/oss-fuzz/libpng_read_fuzzer.cc
@@ -1,4 +1,3 @@
-
 // libpng_read_fuzzer.cc
 // Copyright 2017-2018 Glenn Randers-Pehrson
 // Copyright 2015 The Chromium Authors. All rights reserved.
diff --git a/contrib/pngexif/.editorconfig b/contrib/pngexif/.editorconfig
index ce8fbbfc1..e00082696 100644
--- a/contrib/pngexif/.editorconfig
+++ b/contrib/pngexif/.editorconfig
@@ -4,6 +4,7 @@ root = true
 
 [*]
 charset = utf-8
+indent_size = 4
 indent_style = space
 insert_final_newline = true
 max_doc_length = 79
diff --git a/contrib/pngminim/README b/contrib/pngminim/README
index e17fe35b6..51d5a3c23 100644
--- a/contrib/pngminim/README
+++ b/contrib/pngminim/README
@@ -1,4 +1,3 @@
-
 This demonstrates the use of PNG_USER_CONFIG, pngusr.h and pngusr.dfa
 to build minimal decoder, encoder, and progressive reader applications.
 
diff --git a/contrib/pngminus/.editorconfig b/contrib/pngminus/.editorconfig
new file mode 100644
index 000000000..8504b495e
--- /dev/null
+++ b/contrib/pngminus/.editorconfig
@@ -0,0 +1,29 @@
+# https://editorconfig.org
+
+root = true
+
+[*]
+charset = utf-8
+end_of_line = unset
+indent_size = unset
+indent_style = space
+insert_final_newline = true
+max_doc_length = 79
+max_line_length = 79
+trim_trailing_whitespace = true
+
+[*.[ch]]
+indent_size = 2
+indent_style = space
+
+[CMakeLists.txt]
+indent_size = 4
+indent_style = space
+max_doc_length = 79
+max_line_length = 99
+
+[{Makefile,makevms.com}]
+indent_size = unset
+indent_style = unset
+max_doc_length = 79
+max_line_length = 99
diff --git a/contrib/pngminus/CHANGES.txt b/contrib/pngminus/CHANGES.txt
index 85e590a4a..b4b1a9a8b 100644
--- a/contrib/pngminus/CHANGES.txt
+++ b/contrib/pngminus/CHANGES.txt
@@ -1,4 +1,3 @@
-
 pnm2png / png2pnm --- conversion from PBM/PGM/PPM-file to PNG-file
 copyright (C) 1999-2019 by Willem van Schaik <willem at schaik dot com>
 
@@ -12,3 +11,4 @@ version 1.0 - 1999.10.15 - First version.
         1.6 - 2018.08.05 - Improve portability and fix style (Cosmin Truta)
         1.7 - 2019.01.22 - Change license to MIT (Willem van Schaik)
         1.8 - 2024.01.09 - Fix, improve, modernize (Cosmin Truta)
+        1.9 - 2025.01.10 - Delete conditionally-compiled code (Cosmin Truta)
diff --git a/contrib/pngminus/CMakeLists.txt b/contrib/pngminus/CMakeLists.txt
index d7893648a..8d69b5e7a 100644
--- a/contrib/pngminus/CMakeLists.txt
+++ b/contrib/pngminus/CMakeLists.txt
@@ -1,9 +1,9 @@
-# Copyright (c) 2018-2024 Cosmin Truta
+# Copyright (c) 2018-2025 Cosmin Truta
 #
 # This software is released under the MIT license. For conditions of
 # distribution and use, see the LICENSE file part of this package.
 
-cmake_minimum_required(VERSION 3.5)
+cmake_minimum_required(VERSION 3.14)
 
 project(PNGMINUS C)
 
diff --git a/contrib/pngminus/LICENSE.txt b/contrib/pngminus/LICENSE.txt
index a8d413728..6bdb4f879 100644
--- a/contrib/pngminus/LICENSE.txt
+++ b/contrib/pngminus/LICENSE.txt
@@ -1,4 +1,3 @@
-
 pnm2png / png2pnm --- conversion from PBM/PGM/PPM-file to PNG-file
 
 copyright (C) 1999-2019 by Willem van Schaik <willem at schaik dot com>
diff --git a/contrib/pngminus/png2pnm.c b/contrib/pngminus/png2pnm.c
index f9d5138b7..3c47b91df 100644
--- a/contrib/pngminus/png2pnm.c
+++ b/contrib/pngminus/png2pnm.c
@@ -66,7 +66,7 @@ int main (int argc, char *argv[])
           if ((fp_al = fopen (argv[argi], "wb")) == NULL)
           {
             fname_al = argv[argi];
-            fprintf (stderr, "PNM2PNG\n");
+            fprintf (stderr, "PNG2PNM\n");
             fprintf (stderr, "Error:  cannot create alpha-channel file %s\n",
                      argv[argi]);
             exit (1);
@@ -235,22 +235,6 @@ BOOL do_png2pnm (png_struct *png_ptr, png_info *info_ptr,
   /* set up (if applicable) the expansion of grayscale images to bit-depth 8 */
   png_set_expand_gray_1_2_4_to_8 (png_ptr);
 
-#ifdef NJET
-  /* downgrade 16-bit images to 8-bit */
-  if (bit_depth == 16)
-    png_set_strip_16 (png_ptr);
-  /* transform grayscale images into full-color */
-  if (color_type == PNG_COLOR_TYPE_GRAY ||
-      color_type == PNG_COLOR_TYPE_GRAY_ALPHA)
-    png_set_gray_to_rgb (png_ptr);
-  /* if the PNG image has a gAMA chunk then gamma-correct the output image */
-  {
-    double file_gamma;
-    if (png_get_gAMA (png_ptr, info_ptr, &file_gamma))
-      png_set_gamma (png_ptr, (double) 2.2, file_gamma);
-  }
-#endif
-
   /* read the image file, with all of the above image transforms applied */
   png_read_png (png_ptr, info_ptr, 0, NULL);
 
diff --git a/contrib/pngsuite/README b/contrib/pngsuite/README
index d236b02e7..25f0f54fd 100644
--- a/contrib/pngsuite/README
+++ b/contrib/pngsuite/README
@@ -1,4 +1,3 @@
-
 pngsuite
 --------
 Copyright (c) Willem van Schaik, 1999, 2011, 2012
diff --git a/contrib/pngsuite/interlaced/README b/contrib/pngsuite/interlaced/README
index f171eee01..296fffba6 100644
--- a/contrib/pngsuite/interlaced/README
+++ b/contrib/pngsuite/interlaced/README
@@ -1,2 +1 @@
-
 These images fail the "pngimage-quick" and "pngimage-full" tests.
diff --git a/contrib/testpngs/png-3/cicp-display-p3_reencoded.png b/contrib/testpngs/png-3/cicp-display-p3_reencoded.png
new file mode 100644
index 000000000..91d8e6bc4
Binary files /dev/null and b/contrib/testpngs/png-3/cicp-display-p3_reencoded.png differ
diff --git a/contrib/visupng/.editorconfig b/contrib/visupng/.editorconfig
index d946b1446..d5bcb5312 100644
--- a/contrib/visupng/.editorconfig
+++ b/contrib/visupng/.editorconfig
@@ -5,7 +5,8 @@ root = true
 [*]
 charset = utf-8
 end_of_line = unset
-indent_style = unset
+indent_size = 4
+indent_style = space
 insert_final_newline = true
 max_doc_length = 80
 max_line_length = 100
diff --git a/example.c b/example.c
index 3465fbb37..dd53d8a87 100644
--- a/example.c
+++ b/example.c
@@ -1,4 +1,3 @@
-
 #if 0 /* in case someone actually tries to compile this */
 
 /* example.c - an example of using libpng
diff --git a/intel/filter_sse2_intrinsics.c b/intel/filter_sse2_intrinsics.c
index d3c0fe9e2..2993f650b 100644
--- a/intel/filter_sse2_intrinsics.c
+++ b/intel/filter_sse2_intrinsics.c
@@ -1,4 +1,3 @@
-
 /* filter_sse2_intrinsics.c - SSE2 optimized filter functions
  *
  * Copyright (c) 2018 Cosmin Truta
diff --git a/intel/intel_init.c b/intel/intel_init.c
index 2f8168b7c..9e4610d25 100644
--- a/intel/intel_init.c
+++ b/intel/intel_init.c
@@ -1,4 +1,3 @@
-
 /* intel_init.c - SSE2 optimized filter functions
  *
  * Copyright (c) 2018 Cosmin Truta
diff --git a/libpng-manual.txt b/libpng-manual.txt
index 2ce366d67..862fe2c5d 100644
--- a/libpng-manual.txt
+++ b/libpng-manual.txt
@@ -1,6 +1,6 @@
 libpng-manual.txt - A description on how to use and modify libpng
 
- Copyright (c) 2018-2024 Cosmin Truta
+ Copyright (c) 2018-2025 Cosmin Truta
  Copyright (c) 1998-2018 Glenn Randers-Pehrson
 
  This document is released under the libpng license.
@@ -9,9 +9,9 @@ libpng-manual.txt - A description on how to use and modify libpng
 
  Based on:
 
- libpng version 1.6.36, December 2018, through 1.6.44 - September 2024
+ libpng version 1.6.36, December 2018, through 1.6.47 - February 2025
  Updated and distributed by Cosmin Truta
- Copyright (c) 2018-2024 Cosmin Truta
+ Copyright (c) 2018-2025 Cosmin Truta
 
  libpng versions 0.97, January 1998, through 1.6.35 - July 2018
  Updated and distributed by Glenn Randers-Pehrson
@@ -5173,7 +5173,7 @@ a pre-existing bug where the per-chunk 'keep' setting is ignored, and makes
 it possible to skip IDAT chunks in the sequential reader.
 
 The machine-generated configure files are no longer included in branches
-libpng16 and later of the GIT repository.  They continue to be included
+libpng17 and later of the GIT repository.  They continue to be included
 in the tarball releases, however.
 
 Libpng-1.6.0 through 1.6.2 used the CMF bytes at the beginning of the IDAT
diff --git a/libpng.3 b/libpng.3
index 5a3c89cb9..923b6772e 100644
--- a/libpng.3
+++ b/libpng.3
@@ -1,6 +1,6 @@
-.TH LIBPNG 3 "September 12, 2024"
+.TH LIBPNG 3 "February 18, 2025"
 .SH NAME
-libpng \- Portable Network Graphics (PNG) Reference Library 1.6.44
+libpng \- Portable Network Graphics (PNG) Reference Library 1.6.47
 
 .SH SYNOPSIS
 \fB#include <png.h>\fP
@@ -519,7 +519,7 @@ Following is a copy of the libpng-manual.txt file that accompanies libpng.
 .SH LIBPNG.TXT
 libpng-manual.txt - A description on how to use and modify libpng
 
- Copyright (c) 2018-2024 Cosmin Truta
+ Copyright (c) 2018-2025 Cosmin Truta
  Copyright (c) 1998-2018 Glenn Randers-Pehrson
 
  This document is released under the libpng license.
@@ -528,9 +528,9 @@ libpng-manual.txt - A description on how to use and modify libpng
 
  Based on:
 
- libpng version 1.6.36, December 2018, through 1.6.44 - September 2024
+ libpng version 1.6.36, December 2018, through 1.6.47 - February 2025
  Updated and distributed by Cosmin Truta
- Copyright (c) 2018-2024 Cosmin Truta
+ Copyright (c) 2018-2025 Cosmin Truta
 
  libpng versions 0.97, January 1998, through 1.6.35 - July 2018
  Updated and distributed by Glenn Randers-Pehrson
@@ -5692,7 +5692,7 @@ a pre-existing bug where the per-chunk 'keep' setting is ignored, and makes
 it possible to skip IDAT chunks in the sequential reader.
 
 The machine-generated configure files are no longer included in branches
-libpng16 and later of the GIT repository.  They continue to be included
+libpng17 and later of the GIT repository.  They continue to be included
 in the tarball releases, however.
 
 Libpng-1.6.0 through 1.6.2 used the CMF bytes at the beginning of the IDAT
diff --git a/libpngpf.3 b/libpngpf.3
index b7557ca27..9c4dda2a6 100644
--- a/libpngpf.3
+++ b/libpngpf.3
@@ -1,6 +1,6 @@
-.TH LIBPNGPF 3 "September 12, 2024"
+.TH LIBPNGPF 3 "February 18, 2025"
 .SH NAME
-libpng \- Portable Network Graphics (PNG) Reference Library 1.6.44
+libpng \- Portable Network Graphics (PNG) Reference Library 1.6.47
 (private functions)
 
 .SH SYNOPSIS
diff --git a/ltmain.sh b/ltmain.sh
index 2a50d7f6f..3e6a3db3a 100755
--- a/ltmain.sh
+++ b/ltmain.sh
@@ -2,11 +2,11 @@
 ## DO NOT EDIT - This file generated from ./build-aux/ltmain.in
 ##               by inline-source v2019-02-19.15
 
-# libtool (GNU libtool) 2.4.7
+# libtool (GNU libtool) 2.5.4
 # Provide generalized library-building support services.
 # Written by Gordon Matzigkeit <gord@gnu.ai.mit.edu>, 1996
 
-# Copyright (C) 1996-2019, 2021-2022 Free Software Foundation, Inc.
+# Copyright (C) 1996-2019, 2021-2024 Free Software Foundation, Inc.
 # This is free software; see the source for copying conditions.  There is NO
 # warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 
@@ -31,8 +31,8 @@
 
 PROGRAM=libtool
 PACKAGE=libtool
-VERSION=2.4.7
-package_revision=2.4.7
+VERSION=2.5.4
+package_revision=2.5.4
 
 
 ## ------ ##
@@ -72,11 +72,11 @@ scriptversion=2019-02-19.15; # UTC
 # This is free software.  There is NO warranty; not even for
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 #
-# Copyright (C) 2004-2019, 2021 Bootstrap Authors
+# Copyright (C) 2004-2019, 2021, 2023-2024 Bootstrap Authors
 #
 # This file is dual licensed under the terms of the MIT license
-# <https://opensource.org/license/MIT>, and GPL version 2 or later
-# <http://www.gnu.org/licenses/gpl-2.0.html>.  You must apply one of
+# <https://opensource.org/licenses/MIT>, and GPL version 2 or later
+# <https://www.gnu.org/licenses/gpl-2.0.html>.  You must apply one of
 # these licenses when using or redistributing this software or any of
 # the files within it.  See the URLs above, or the file `LICENSE`
 # included in the Bootstrap distribution for the full license texts.
@@ -143,7 +143,7 @@ nl='
 '
 IFS="$sp	$nl"
 
-# There are apparently some retarded systems that use ';' as a PATH separator!
+# There are apparently some systems that use ';' as a PATH separator!
 if test "${PATH_SEPARATOR+set}" != set; then
   PATH_SEPARATOR=:
   (PATH='/bin;/bin'; FPATH=$PATH; sh -c :) >/dev/null 2>&1 && {
@@ -589,7 +589,7 @@ func_require_term_colors ()
 
   # _G_HAVE_PLUSEQ_OP
   # Can be empty, in which case the shell is probed, "yes" if += is
-  # useable or anything else if it does not work.
+  # usable or anything else if it does not work.
   test -z "$_G_HAVE_PLUSEQ_OP" \
     && (eval 'x=a; x+=" b"; test "a b" = "$x"') 2>/dev/null \
     && _G_HAVE_PLUSEQ_OP=yes
@@ -739,7 +739,7 @@ eval 'func_dirname ()
 #             to NONDIR_REPLACEMENT.
 #             value returned in "$func_dirname_result"
 #   basename: Compute filename of FILE.
-#             value retuned in "$func_basename_result"
+#             value returned in "$func_basename_result"
 # For efficiency, we do not delegate to the functions above but instead
 # duplicate the functionality here.
 eval 'func_dirname_and_basename ()
@@ -897,7 +897,7 @@ func_mkdir_p ()
       # While some portion of DIR does not yet exist...
       while test ! -d "$_G_directory_path"; do
         # ...make a list in topmost first order.  Use a colon delimited
-	# list incase some portion of path contains whitespace.
+	# list in case some portion of path contains whitespace.
         _G_dir_list=$_G_directory_path:$_G_dir_list
 
         # If the last portion added has no slash in it, the list is done
@@ -1536,11 +1536,11 @@ func_lt_ver ()
 # This is free software.  There is NO warranty; not even for
 # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 #
-# Copyright (C) 2010-2019, 2021 Bootstrap Authors
+# Copyright (C) 2010-2019, 2021, 2023-2024 Bootstrap Authors
 #
 # This file is dual licensed under the terms of the MIT license
-# <https://opensource.org/license/MIT>, and GPL version 2 or later
-# <http://www.gnu.org/licenses/gpl-2.0.html>.  You must apply one of
+# <https://opensource.org/licenses/MIT>, and GPL version 2 or later
+# <https://www.gnu.org/licenses/gpl-2.0.html>.  You must apply one of
 # these licenses when using or redistributing this software or any of
 # the files within it.  See the URLs above, or the file `LICENSE`
 # included in the Bootstrap distribution for the full license texts.
@@ -2215,7 +2215,30 @@ func_version ()
 # End:
 
 # Set a version string.
-scriptversion='(GNU libtool) 2.4.7'
+scriptversion='(GNU libtool) 2.5.4'
+
+# func_version
+# ------------
+# Echo version message to standard output and exit.
+func_version ()
+{
+    $debug_cmd
+
+	year=`date +%Y`
+
+	cat <<EOF
+$progname $scriptversion
+Copyright (C) $year Free Software Foundation, Inc.
+License GPLv2+: GNU GPL version 2 or later <https://gnu.org/licenses/gpl.html>
+This is free software: you are free to change and redistribute it.
+There is NO WARRANTY, to the extent permitted by law.
+
+Originally written by Gordon Matzigkeit, 1996
+(See AUTHORS for complete contributor listing)
+EOF
+
+    exit $?
+}
 
 
 # func_echo ARG...
@@ -2238,18 +2261,6 @@ func_echo ()
 }
 
 
-# func_warning ARG...
-# -------------------
-# Libtool warnings are not categorized, so override funclib.sh
-# func_warning with this simpler definition.
-func_warning ()
-{
-    $debug_cmd
-
-    $warning_func ${1+"$@"}
-}
-
-
 ## ---------------- ##
 ## Options parsing. ##
 ## ---------------- ##
@@ -2261,19 +2272,23 @@ usage='$progpath [OPTION]... [MODE-ARG]...'
 
 # Short help message in response to '-h'.
 usage_message="Options:
-       --config             show all configuration variables
-       --debug              enable verbose shell tracing
-   -n, --dry-run            display commands without modifying any files
-       --features           display basic configuration information and exit
-       --mode=MODE          use operation mode MODE
-       --no-warnings        equivalent to '-Wnone'
-       --preserve-dup-deps  don't remove duplicate dependency libraries
-       --quiet, --silent    don't print informational messages
-       --tag=TAG            use configuration variables from tag TAG
-   -v, --verbose            print more informational messages than default
-       --version            print version information
-   -W, --warnings=CATEGORY  report the warnings falling in CATEGORY [all]
-   -h, --help, --help-all   print short, long, or detailed help message
+       --config                 show all configuration variables
+       --debug                  enable verbose shell tracing
+   -n, --dry-run                display commands without modifying any files
+       --features               display basic configuration information
+       --finish                 use operation '--mode=finish'
+       --mode=MODE              use operation mode MODE
+       --no-finish              don't update shared library cache
+       --no-quiet, --no-silent  print default informational messages
+       --no-warnings            equivalent to '-Wnone'
+       --preserve-dup-deps      don't remove duplicate dependency libraries
+       --quiet, --silent        don't print informational messages
+       --reorder-cache=DIRS     reorder shared library cache for preferred DIRS
+       --tag=TAG                use configuration variables from tag TAG
+   -v, --verbose                print more informational messages than default
+       --version                print version information
+   -W, --warnings=CATEGORY      report the warnings falling in CATEGORY [all]
+   -h, --help, --help-all       print short, long, or detailed help message
 "
 
 # Additional text appended to 'usage_message' in response to '--help'.
@@ -2306,13 +2321,13 @@ include the following information:
        compiler:       $LTCC
        compiler flags: $LTCFLAGS
        linker:         $LD (gnu? $with_gnu_ld)
-       version:        $progname (GNU libtool) 2.4.7
+       version:        $progname $scriptversion
        automake:       `($AUTOMAKE --version) 2>/dev/null |$SED 1q`
        autoconf:       `($AUTOCONF --version) 2>/dev/null |$SED 1q`
 
 Report bugs to <bug-libtool@gnu.org>.
-GNU libtool home page: <http://www.gnu.org/software/libtool/>.
-General help using GNU software: <http://www.gnu.org/gethelp/>."
+GNU libtool home page: <https://www.gnu.org/software/libtool/>.
+General help using GNU software: <https://www.gnu.org/gethelp/>."
     exit 0
 }
 
@@ -2502,8 +2517,11 @@ libtool_options_prep ()
     opt_dry_run=false
     opt_help=false
     opt_mode=
+    opt_reorder_cache=false
     opt_preserve_dup_deps=false
     opt_quiet=false
+    opt_finishing=true
+    opt_warning=
 
     nonopt=
     preserve_args=
@@ -2593,14 +2611,18 @@ libtool_parse_options ()
                           clean|compile|execute|finish|install|link|relink|uninstall) ;;
 
                           # Catch anything else as an error
-                          *) func_error "invalid argument for $_G_opt"
+                          *) func_error "invalid argument '$1' for $_G_opt"
                              exit_cmd=exit
-                             break
                              ;;
                         esac
                         shift
                         ;;
 
+        --no-finish)
+                        opt_finishing=false
+                        func_append preserve_args " $_G_opt"
+                        ;;
+
         --no-silent|--no-quiet)
                         opt_quiet=false
                         func_append preserve_args " $_G_opt"
@@ -2616,6 +2638,24 @@ libtool_parse_options ()
                         func_append preserve_args " $_G_opt"
                         ;;
 
+        --reorder-cache)
+                        opt_reorder_cache=true
+                        shared_lib_dirs=$1
+                        if test -n "$shared_lib_dirs"; then
+                          case $1 in
+                            # Must begin with /:
+                            /*) ;;
+
+                            # Catch anything else as an error (relative paths)
+                            *) func_error "invalid argument '$1' for $_G_opt"
+                               func_error "absolute paths are required for $_G_opt"
+                               exit_cmd=exit
+                               ;;
+                          esac
+                        fi
+                        shift
+                        ;;
+
         --silent|--quiet)
                         opt_quiet=:
                         opt_verbose=false
@@ -2652,6 +2692,18 @@ libtool_parse_options ()
 func_add_hook func_parse_options libtool_parse_options
 
 
+# func_warning ARG...
+# -------------------
+# Libtool warnings are not categorized, so override funclib.sh
+# func_warning with this simpler definition.
+func_warning ()
+{
+    if $opt_warning; then
+        $debug_cmd
+        $warning_func ${1+"$@"}
+    fi
+}
+
 
 # libtool_validate_options [ARG]...
 # ---------------------------------
@@ -2668,10 +2720,10 @@ libtool_validate_options ()
     # preserve --debug
     test : = "$debug_cmd" || func_append preserve_args " --debug"
 
-    case $host in
+    case $host_os in
       # Solaris2 added to fix http://debbugs.gnu.org/cgi/bugreport.cgi?bug=16452
       # see also: http://gcc.gnu.org/bugzilla/show_bug.cgi?id=59788
-      *cygwin* | *mingw* | *pw32* | *cegcc* | *solaris2* | *os2*)
+      cygwin* | mingw* | windows* | pw32* | cegcc* | solaris2* | os2*)
         # don't eliminate duplications in $postdeps and $predeps
         opt_duplicate_compiler_generated_deps=:
         ;;
@@ -3003,7 +3055,7 @@ EOF
 
 # func_convert_core_file_wine_to_w32 ARG
 # Helper function used by file name conversion functions when $build is *nix,
-# and $host is mingw, cygwin, or some other w32 environment. Relies on a
+# and $host is mingw, windows, cygwin, or some other w32 environment. Relies on a
 # correctly configured wine environment available, with the winepath program
 # in $build's $PATH.
 #
@@ -3035,9 +3087,10 @@ func_convert_core_file_wine_to_w32 ()
 
 # func_convert_core_path_wine_to_w32 ARG
 # Helper function used by path conversion functions when $build is *nix, and
-# $host is mingw, cygwin, or some other w32 environment. Relies on a correctly
-# configured wine environment available, with the winepath program in $build's
-# $PATH. Assumes ARG has no leading or trailing path separator characters.
+# $host is mingw, windows, cygwin, or some other w32 environment. Relies on a
+# correctly configured wine environment available, with the winepath program
+# in $build's $PATH. Assumes ARG has no leading or trailing path separator
+# characters.
 #
 # ARG is path to be converted from $build format to win32.
 # Result is available in $func_convert_core_path_wine_to_w32_result.
@@ -3180,6 +3233,15 @@ func_convert_path_front_back_pathsep ()
 # end func_convert_path_front_back_pathsep
 
 
+# func_convert_delimited_path PATH ORIG_DELIMITER NEW_DELIMITER
+# Replaces a delimiter for a given path.
+func_convert_delimited_path ()
+{
+	converted_path=`$ECHO "$1" | $SED "s#$2#$3#g"`
+}
+# end func_convert_delimited_path
+
+
 ##################################################
 # $build to $host FILE NAME CONVERSION FUNCTIONS #
 ##################################################
@@ -3514,6 +3576,65 @@ func_dll_def_p ()
 }
 
 
+# func_reorder_shared_lib_cache DIRS
+# Reorder the shared library cache by unconfiguring previous shared library cache
+# and configuring preferred search directories before previous search directories.
+# Previous shared library cache: /usr/lib /usr/local/lib
+# Preferred search directories: /tmp/testing
+# Reordered shared library cache: /tmp/testing /usr/lib /usr/local/lib
+func_reorder_shared_lib_cache ()
+{
+	$debug_cmd
+
+	case $host_os in
+	  openbsd*)
+	    get_search_directories=`PATH="$PATH:/sbin" ldconfig -r | $GREP "search directories" | $SED "s#.*search directories:\ ##g"`
+	    func_convert_delimited_path "$get_search_directories" ':' '\ '
+	    save_search_directories=$converted_path
+	    func_convert_delimited_path "$1" ':' '\ '
+
+	    # Ensure directories exist
+	    for dir in $converted_path; do
+	      # Ensure each directory is an absolute path
+	      case $dir in
+	        /*) ;;
+	        *) func_error "Directory '$dir' is not an absolute path"
+	           exit $EXIT_FAILURE ;;
+	      esac
+	      # Ensure no trailing slashes
+	      func_stripname '' '/' "$dir"
+	      dir=$func_stripname_result
+	      if test -d "$dir"; then
+	        if test -n "$preferred_search_directories"; then
+	          preferred_search_directories="$preferred_search_directories $dir"
+	        else
+	          preferred_search_directories=$dir
+	        fi
+	      else
+	        func_error "Directory '$dir' does not exist"
+	        exit $EXIT_FAILURE
+	      fi
+	    done
+
+	    PATH="$PATH:/sbin" ldconfig -U $save_search_directories
+	    PATH="$PATH:/sbin" ldconfig -m $preferred_search_directories $save_search_directories
+	    get_search_directories=`PATH="$PATH:/sbin" ldconfig -r | $GREP "search directories" | $SED "s#.*search directories:\ ##g"`
+	    func_convert_delimited_path "$get_search_directories" ':' '\ '
+	    reordered_search_directories=$converted_path
+
+	    $ECHO "Original: $save_search_directories"
+	    $ECHO "Reordered: $reordered_search_directories"
+	    exit $EXIT_SUCCESS
+	  ;;
+	  *)
+	    func_error "--reorder-cache is not supported for host_os=$host_os."
+	    exit $EXIT_FAILURE
+	  ;;
+	esac
+}
+# end func_reorder_shared_lib_cache
+
+
 # func_mode_compile arg...
 func_mode_compile ()
 {
@@ -3692,7 +3813,7 @@ func_mode_compile ()
 
     # On Cygwin there's no "real" PIC flag so we must build both object types
     case $host_os in
-    cygwin* | mingw* | pw32* | os2* | cegcc*)
+    cygwin* | mingw* | windows* | pw32* | os2* | cegcc*)
       pic_mode=default
       ;;
     esac
@@ -4086,6 +4207,12 @@ if $opt_help; then
 fi
 
 
+# If option '--reorder-cache', reorder the shared library cache and exit.
+if $opt_reorder_cache; then
+    func_reorder_shared_lib_cache $shared_lib_dirs
+fi
+
+
 # func_mode_execute arg...
 func_mode_execute ()
 {
@@ -4270,7 +4397,7 @@ func_mode_finish ()
       fi
     fi
 
-    if test -n "$finish_cmds$finish_eval" && test -n "$libdirs"; then
+    if test -n "$finish_cmds$finish_eval" && test -n "$libdirs" && $opt_finishing; then
       for libdir in $libdirs; do
 	if test -n "$finish_cmds"; then
 	  # Do each command in the finish commands.
@@ -4295,6 +4422,12 @@ func_mode_finish ()
       for libdir in $libdirs; do
 	$ECHO "   $libdir"
       done
+      if test "false" = "$opt_finishing"; then
+        echo
+        echo "NOTE: finish_cmds were not executed during testing, so you must"
+        echo "manually run ldconfig to add a given test directory, LIBDIR, to"
+        echo "the search path for generated executables."
+      fi
       echo
       echo "If you ever happen to want to link against installed libraries"
       echo "in a given directory, LIBDIR, you must either use libtool, and"
@@ -4531,8 +4664,15 @@ func_mode_install ()
 	func_append dir "$objdir"
 
 	if test -n "$relink_command"; then
+	  # Strip any trailing slash from the destination.
+	  func_stripname '' '/' "$libdir"
+	  destlibdir=$func_stripname_result
+
+	  func_stripname '' '/' "$destdir"
+	  s_destdir=$func_stripname_result
+
 	  # Determine the prefix the user has applied to our future dir.
-	  inst_prefix_dir=`$ECHO "$destdir" | $SED -e "s%$libdir\$%%"`
+	  inst_prefix_dir=`$ECHO "X$s_destdir" | $Xsed -e "s%$destlibdir\$%%"`
 
 	  # Don't allow the user to place us outside of our expected
 	  # location b/c this prevents finding dependent libraries that
@@ -4569,7 +4709,7 @@ func_mode_install ()
 	      'exit $?'
 	  tstripme=$stripme
 	  case $host_os in
-	  cygwin* | mingw* | pw32* | cegcc*)
+	  cygwin* | mingw* | windows* | pw32* | cegcc*)
 	    case $realname in
 	    *.dll.a)
 	      tstripme=
@@ -4682,7 +4822,7 @@ func_mode_install ()
 
 	# Do a test to see if this is really a libtool program.
 	case $host in
-	*cygwin* | *mingw*)
+	*cygwin* | *mingw* | *windows*)
 	    if func_ltwrapper_executable_p "$file"; then
 	      func_ltwrapper_scriptname "$file"
 	      wrapper=$func_ltwrapper_scriptname_result
@@ -4910,7 +5050,7 @@ extern \"C\" {
 	      $RM $export_symbols
 	      eval "$SED -n -e '/^: @PROGRAM@ $/d' -e 's/^.* \(.*\)$/\1/p' "'< "$nlist" > "$export_symbols"'
 	      case $host in
-	      *cygwin* | *mingw* | *cegcc* )
+	      *cygwin* | *mingw* | *windows* | *cegcc* )
                 eval "echo EXPORTS "'> "$output_objdir/$outputname.def"'
                 eval 'cat "$export_symbols" >> "$output_objdir/$outputname.def"'
 	        ;;
@@ -4922,7 +5062,7 @@ extern \"C\" {
 	      eval '$GREP -f "$output_objdir/$outputname.exp" < "$nlist" > "$nlist"T'
 	      eval '$MV "$nlist"T "$nlist"'
 	      case $host in
-	        *cygwin* | *mingw* | *cegcc* )
+	        *cygwin* | *mingw* | *windows* | *cegcc* )
 	          eval "echo EXPORTS "'> "$output_objdir/$outputname.def"'
 	          eval 'cat "$nlist" >> "$output_objdir/$outputname.def"'
 	          ;;
@@ -4936,7 +5076,7 @@ extern \"C\" {
 	  func_basename "$dlprefile"
 	  name=$func_basename_result
           case $host in
-	    *cygwin* | *mingw* | *cegcc* )
+	    *cygwin* | *mingw* | *windows* | *cegcc* )
 	      # if an import library, we need to obtain dlname
 	      if func_win32_import_lib_p "$dlprefile"; then
 	        func_tr_sh "$dlprefile"
@@ -4962,8 +5102,16 @@ extern \"C\" {
 	            eval '$ECHO ": $name " >> "$nlist"'
 	          fi
 	          func_to_tool_file "$dlprefile" func_convert_file_msys_to_w32
-	          eval "$NM \"$func_to_tool_file_result\" 2>/dev/null | $global_symbol_pipe |
-	            $SED -e '/I __imp/d' -e 's/I __nm_/D /;s/_nm__//' >> '$nlist'"
+	          case $host in
+	            i[3456]86-*-mingw32*)
+	              eval "$NM \"$func_to_tool_file_result\" 2>/dev/null | $global_symbol_pipe |
+	                $SED -e '/I __imp/d' -e 's/I __nm_/D /;s/_nm__//' >> '$nlist'"
+	            ;;
+	            *)
+	              eval "$NM \"$func_to_tool_file_result\" 2>/dev/null | $global_symbol_pipe |
+	                $SED -e '/I __imp/d' -e 's/I __nm_/D /;s/__nm_//' >> '$nlist'"
+	            ;;
+	          esac
 	        }
 	      else # not an import lib
 	        $opt_dry_run || {
@@ -5111,7 +5259,7 @@ static const void *lt_preloaded_setup() {
 	# Transform the symbol file into the correct name.
 	symfileobj=$output_objdir/${my_outputname}S.$objext
 	case $host in
-	*cygwin* | *mingw* | *cegcc* )
+	*cygwin* | *mingw* | *windows* | *cegcc* )
 	  if test -f "$output_objdir/$my_outputname.def"; then
 	    compile_command=`$ECHO "$compile_command" | $SED "s%@SYMFILE@%$output_objdir/$my_outputname.def $symfileobj%"`
 	    finalize_command=`$ECHO "$finalize_command" | $SED "s%@SYMFILE@%$output_objdir/$my_outputname.def $symfileobj%"`
@@ -5187,7 +5335,7 @@ func_win32_libid ()
   *ar\ archive*) # could be an import, or static
     # Keep the egrep pattern in sync with the one in _LT_CHECK_MAGIC_METHOD.
     if eval $OBJDUMP -f $1 | $SED -e '10q' 2>/dev/null |
-       $EGREP 'file format (pei*-i386(.*architecture: i386)?|pe-arm-wince|pe-x86-64)' >/dev/null; then
+       $EGREP 'file format (pei*-i386(.*architecture: i386)?|pe-arm-wince|pe-x86-64|pe-aarch64)' >/dev/null; then
       case $nm_interface in
       "MS dumpbin")
 	if func_cygming_ms_implib_p "$1" ||
@@ -5454,7 +5602,7 @@ func_extract_archives ()
 #
 # Emit a libtool wrapper script on stdout.
 # Don't directly open a file because we may want to
-# incorporate the script contents within a cygwin/mingw
+# incorporate the script contents within a cygwin/mingw/windows
 # wrapper executable.  Must ONLY be called from within
 # func_mode_link because it depends on a number of variables
 # set therein.
@@ -5462,7 +5610,7 @@ func_extract_archives ()
 # ARG is the value that the WRAPPER_SCRIPT_BELONGS_IN_OBJDIR
 # variable will take.  If 'yes', then the emitted script
 # will assume that the directory where it is stored is
-# the $objdir directory.  This is a cygwin/mingw-specific
+# the $objdir directory.  This is a cygwin/mingw/windows-specific
 # behavior.
 func_emit_wrapper ()
 {
@@ -5587,7 +5735,7 @@ func_exec_program_core ()
 "
   case $host in
   # Backslashes separate directories on plain windows
-  *-*-mingw | *-*-os2* | *-cegcc*)
+  *-*-mingw* | *-*-windows* | *-*-os2* | *-cegcc*)
     $ECHO "\
       if test -n \"\$lt_option_debug\"; then
         \$ECHO \"$outputname:$output:\$LINENO: newargv[0]: \$progdir\\\\\$program\" 1>&2
@@ -5655,7 +5803,7 @@ func_exec_program ()
     file=\`ls -ld \"\$thisdir/\$file\" | $SED -n 's/.*-> //p'\`
   done
 
-  # Usually 'no', except on cygwin/mingw when embedded into
+  # Usually 'no', except on cygwin/mingw/windows when embedded into
   # the cwrapper.
   WRAPPER_SCRIPT_BELONGS_IN_OBJDIR=$func_emit_wrapper_arg1
   if test \"\$WRAPPER_SCRIPT_BELONGS_IN_OBJDIR\" = \"yes\"; then
@@ -5787,7 +5935,7 @@ EOF
 #endif
 #include <stdio.h>
 #include <stdlib.h>
-#ifdef _MSC_VER
+#if defined _WIN32 && !defined __GNUC__
 # include <direct.h>
 # include <process.h>
 # include <io.h>
@@ -5812,7 +5960,7 @@ EOF
 /* declarations of non-ANSI functions */
 #if defined __MINGW32__
 # ifdef __STRICT_ANSI__
-int _putenv (const char *);
+_CRTIMP int __cdecl _putenv (const char *);
 # endif
 #elif defined __CYGWIN__
 # ifdef __STRICT_ANSI__
@@ -6010,7 +6158,7 @@ main (int argc, char *argv[])
 	{
 EOF
 	    case $host in
-	      *mingw* | *cygwin* )
+	      *mingw* | *windows* | *cygwin* )
 		# make stdout use "unix" line endings
 		echo "          setmode(1,_O_BINARY);"
 		;;
@@ -6029,7 +6177,7 @@ EOF
         {
           /* however, if there is an option in the LTWRAPPER_OPTION_PREFIX
              namespace, but it is not one of the ones we know about and
-             have already dealt with, above (inluding dump-script), then
+             have already dealt with, above (including dump-script), then
              report an error. Otherwise, targets might begin to believe
              they are allowed to use options in the LTWRAPPER_OPTION_PREFIX
              namespace. The first time any user complains about this, we'll
@@ -6113,7 +6261,7 @@ EOF
 EOF
 
 	    case $host_os in
-	      mingw*)
+	      mingw* | windows*)
 	    cat <<"EOF"
   {
     char* p;
@@ -6155,7 +6303,7 @@ EOF
 EOF
 
 	    case $host_os in
-	      mingw*)
+	      mingw* | windows*)
 		cat <<"EOF"
   /* execv doesn't actually work on mingw as expected on unix */
   newargz = prepare_spawn (newargz);
@@ -6574,7 +6722,7 @@ lt_update_lib_path (const char *name, const char *value)
 
 EOF
 	    case $host_os in
-	      mingw*)
+	      mingw* | windows*)
 		cat <<"EOF"
 
 /* Prepares an argument vector before calling spawn().
@@ -6749,7 +6897,7 @@ func_mode_link ()
     $debug_cmd
 
     case $host in
-    *-*-cygwin* | *-*-mingw* | *-*-pw32* | *-*-os2* | *-cegcc*)
+    *-*-cygwin* | *-*-mingw* | *-*-windows* | *-*-pw32* | *-*-os2* | *-cegcc*)
       # It is impossible to link a dll without this setting, and
       # we shouldn't force the makefile maintainer to figure out
       # what system we are compiling for in order to pass an extra
@@ -6773,6 +6921,7 @@ func_mode_link ()
     finalize_command=$nonopt
 
     compile_rpath=
+    compile_rpath_tail=
     finalize_rpath=
     compile_shlibpath=
     finalize_shlibpath=
@@ -6813,10 +6962,12 @@ func_mode_link ()
     xrpath=
     perm_rpath=
     temp_rpath=
+    temp_rpath_tail=
     thread_safe=no
     vinfo=
     vinfo_number=no
     weak_libs=
+    rpath_arg=
     single_module=$wl-single_module
     func_infer_tag $base_compile
 
@@ -7079,7 +7230,7 @@ func_mode_link ()
 	  case $arg in
 	  [\\/]* | [A-Za-z]:[\\/]*) ;;
 	  *)
-	    func_fatal_error "only absolute run-paths are allowed"
+	    func_fatal_error "argument to -rpath is not absolute: $arg"
 	    ;;
 	  esac
 	  if test rpath = "$prev"; then
@@ -7255,7 +7406,7 @@ func_mode_link ()
 	  ;;
 	esac
 	case $host in
-	*-*-cygwin* | *-*-mingw* | *-*-pw32* | *-*-os2* | *-cegcc*)
+	*-*-cygwin* | *-*-mingw* | *-*-windows* | *-*-pw32* | *-*-os2* | *-cegcc*)
 	  testbindir=`$ECHO "$dir" | $SED 's*/lib$*/bin*'`
 	  case :$dllsearchpath: in
 	  *":$dir:"*) ;;
@@ -7275,7 +7426,7 @@ func_mode_link ()
       -l*)
 	if test X-lc = "X$arg" || test X-lm = "X$arg"; then
 	  case $host in
-	  *-*-cygwin* | *-*-mingw* | *-*-pw32* | *-*-beos* | *-cegcc* | *-*-haiku*)
+	  *-*-cygwin* | *-*-mingw* | *-*-windows* | *-*-pw32* | *-*-beos* | *-cegcc* | *-*-haiku*)
 	    # These systems don't actually have a C or math library (as such)
 	    continue
 	    ;;
@@ -7283,7 +7434,7 @@ func_mode_link ()
 	    # These systems don't actually have a C library (as such)
 	    test X-lc = "X$arg" && continue
 	    ;;
-	  *-*-openbsd* | *-*-freebsd* | *-*-dragonfly* | *-*-bitrig* | *-*-midnightbsd*)
+	  *-*-openbsd* | *-*-freebsd* | *-*-dragonfly* | *-*-midnightbsd*)
 	    # Do not include libc due to us having libc/libc_r.
 	    test X-lc = "X$arg" && continue
 	    ;;
@@ -7303,7 +7454,7 @@ func_mode_link ()
 	  esac
 	elif test X-lc_r = "X$arg"; then
 	 case $host in
-	 *-*-openbsd* | *-*-freebsd* | *-*-dragonfly* | *-*-bitrig* | *-*-midnightbsd*)
+	 *-*-openbsd* | *-*-freebsd* | *-*-dragonfly* | *-*-midnightbsd*)
 	   # Do not include libc_r directly, use -pthread flag.
 	   continue
 	   ;;
@@ -7326,7 +7477,8 @@ func_mode_link ()
       # Tru64 UNIX uses -model [arg] to determine the layout of C++
       # classes, name mangling, and exception handling.
       # Darwin uses the -arch flag to determine output architecture.
-      -model|-arch|-isysroot|--sysroot)
+      # -q <option> for IBM XL C/C++ compiler.
+      -model|-arch|-isysroot|--sysroot|-q)
 	func_append compiler_flags " $arg"
 	func_append compile_command " $arg"
 	func_append finalize_command " $arg"
@@ -7347,7 +7499,7 @@ func_mode_link ()
 	continue
 	;;
       -mt|-mthreads|-kthread|-Kthread|-pthreads|--thread-safe \
-      |-threads|-fopenmp|-openmp|-mp|-xopenmp|-omp|-qsmp=*)
+      |-threads|-fopenmp|-fopenmp=*|-openmp|-mp|-xopenmp|-omp|-qsmp=*)
 	func_append compiler_flags " $arg"
 	func_append compile_command " $arg"
 	func_append finalize_command " $arg"
@@ -7370,7 +7522,7 @@ func_mode_link ()
 
       -no-install)
 	case $host in
-	*-*-cygwin* | *-*-mingw* | *-*-pw32* | *-*-os2* | *-*-darwin* | *-cegcc*)
+	*-*-cygwin* | *-*-mingw* | *-*-windows* | *-*-pw32* | *-*-os2* | *-*-darwin* | *-cegcc*)
 	  # The PATH hackery in wrapper scripts is required on Windows
 	  # and Darwin in order for the loader to find any dlls it needs.
 	  func_warning "'-no-install' is ignored for $host"
@@ -7430,7 +7582,7 @@ func_mode_link ()
 	  dir=$lt_sysroot$func_stripname_result
 	  ;;
 	*)
-	  func_fatal_error "only absolute run-paths are allowed"
+	  func_fatal_error "argument ($arg) to '-R' is not an absolute path: $dir"
 	  ;;
 	esac
 	case "$xrpath " in
@@ -7555,13 +7707,29 @@ func_mode_link ()
       # -O*, -g*, -flto*, -fwhopr*, -fuse-linker-plugin GCC link-time optimization
       # -specs=*             GCC specs files
       # -stdlib=*            select c++ std lib with clang
+      # -fdiagnostics-color* simply affects output
+      # -frecord-gcc-switches used to verify flags were respected
       # -fsanitize=*         Clang/GCC memory and address sanitizer
+      # -fno-sanitize*       Clang/GCC memory and address sanitizer
+      # -shared-libsan       Link with shared sanitizer runtimes (Clang)
+      # -static-libsan       Link with static sanitizer runtimes (Clang)
+      # -no-canonical-prefixes Do not expand any symbolic links
       # -fuse-ld=*           Linker select flags for GCC
+      # -static-*            direct GCC to link specific libraries statically
+      # -fcilkplus           Cilk Plus language extension features for C/C++
+      # -rtlib=*             select c runtime lib with clang
+      # --unwindlib=*        select unwinder library with clang
+      # -f{file|debug|macro|profile}-prefix-map=* needed for lto linking
       # -Wa,*                Pass flags directly to the assembler
+      # -Werror, -Werror=*   Report (specified) warnings as errors
       -64|-mips[0-9]|-r[0-9][0-9]*|-xarch=*|-xtarget=*|+DA*|+DD*|-q*|-m*| \
       -t[45]*|-txscale*|-p|-pg|--coverage|-fprofile-*|-F*|@*|-tp=*|--sysroot=*| \
-      -O*|-g*|-flto*|-fwhopr*|-fuse-linker-plugin|-fstack-protector*|-stdlib=*| \
-      -specs=*|-fsanitize=*|-fuse-ld=*|-Wa,*)
+      -O*|-g*|-flto*|-fwhopr*|-fuse-linker-plugin|-fstack-protector*|-no-canonical-prefixes| \
+      -stdlib=*|-rtlib=*|--unwindlib=*| \
+      -specs=*|-fsanitize=*|-fno-sanitize*|-shared-libsan|-static-libsan| \
+      -ffile-prefix-map=*|-fdebug-prefix-map=*|-fmacro-prefix-map=*|-fprofile-prefix-map=*| \
+      -fdiagnostics-color*|-frecord-gcc-switches| \
+      -fuse-ld=*|-static-*|-fcilkplus|-Wa,*|-Werror|-Werror=*)
         func_quote_arg pretty "$arg"
 	arg=$func_quote_arg_result
         func_append compile_command " $arg"
@@ -7719,8 +7887,20 @@ func_mode_link ()
 
       # Now actually substitute the argument into the commands.
       if test -n "$arg"; then
-	func_append compile_command " $arg"
-	func_append finalize_command " $arg"
+	if test -n "$rpath_arg"; then
+          func_append finalize_rpath " ${arg##*,}"
+	  unset rpath_arg
+	else
+	  case $arg in
+          -Wl,-rpath,*)
+	    func_append finalize_rpath " ${arg##*,}";;
+          -Wl,-rpath)
+	    rpath_arg=1;;
+          *)
+            func_append compile_command " $arg"
+	    func_append finalize_command " $arg"
+	  esac
+        fi
       fi
     done # argument parsing loop
 
@@ -7891,7 +8071,7 @@ func_mode_link ()
 	found=false
 	case $deplib in
 	-mt|-mthreads|-kthread|-Kthread|-pthread|-pthreads|--thread-safe \
-        |-threads|-fopenmp|-openmp|-mp|-xopenmp|-omp|-qsmp=*)
+        |-threads|-fopenmp|-fopenmp=*|-openmp|-mp|-xopenmp|-omp|-qsmp=*)
 	  if test prog,link = "$linkmode,$pass"; then
 	    compile_deplibs="$deplib $compile_deplibs"
 	    finalize_deplibs="$deplib $finalize_deplibs"
@@ -8068,18 +8248,15 @@ func_mode_link ()
 		;;
 	      esac
 	      if $valid_a_lib; then
-		echo
-		$ECHO "*** Warning: Linking the shared library $output against the"
-		$ECHO "*** static library $deplib is not portable!"
+		func_warning "Linking the shared library $output against the static library $deplib is not portable!"
 		deplibs="$deplib $deplibs"
 	      else
-		echo
-		$ECHO "*** Warning: Trying to link with static lib archive $deplib."
-		echo "*** I have the capability to make that library automatically link in when"
-		echo "*** you link to this library.  But I can only do this if you have a"
-		echo "*** shared version of the library, which you do not appear to have"
-		echo "*** because the file extensions .$libext of this argument makes me believe"
-		echo "*** that it is just a static archive that I should not use here."
+		func_warning "Trying to link with static lib archive $deplib."
+		func_warning "I have the capability to make that library automatically link in when"
+		func_warning "you link to this library.  But I can only do this if you have a"
+		func_warning "shared version of the library, which you do not appear to have"
+		func_warning "because the file extensions .$libext of this argument makes me believe"
+		func_warning "that it is just a static archive that I should not use here."
 	      fi
 	      ;;
 	    esac
@@ -8274,7 +8451,7 @@ func_mode_link ()
 	  fi
 	  case $host in
 	    # special handling for platforms with PE-DLLs.
-	    *cygwin* | *mingw* | *cegcc* )
+	    *cygwin* | *mingw* | *windows* | *cegcc* )
 	      # Linker will automatically link against shared library if both
 	      # static and shared are present.  Therefore, ensure we extract
 	      # symbols from the import library if a shared library is present
@@ -8374,7 +8551,10 @@ func_mode_link ()
 	      # Make sure the rpath contains only unique directories.
 	      case $temp_rpath: in
 	      *"$absdir:"*) ;;
-	      *) func_append temp_rpath "$absdir:" ;;
+              *) case $absdir in
+                 "$progdir/"*) func_append temp_rpath "$absdir:" ;;
+                 *)            func_append temp_rpath_tail "$absdir:" ;;
+                 esac
 	      esac
 	    fi
 
@@ -8384,9 +8564,12 @@ func_mode_link ()
 	    case " $sys_lib_dlsearch_path " in
 	    *" $absdir "*) ;;
 	    *)
-	      case "$compile_rpath " in
+	      case "$compile_rpath$compile_rpath_tail " in
 	      *" $absdir "*) ;;
-	      *) func_append compile_rpath " $absdir" ;;
+	      *) case $absdir in
+                 "$progdir/"*) func_append compile_rpath " $absdir" ;;
+                 *) func_append compile_rpath_tail " $absdir" ;;
+		 esac
 	      esac
 	      ;;
 	    esac
@@ -8417,8 +8600,8 @@ func_mode_link ()
 	fi
 	if test -n "$library_names" &&
 	   { test no = "$use_static_libs" || test -z "$old_library"; }; then
-	  case $host in
-	  *cygwin* | *mingw* | *cegcc* | *os2*)
+	  case $host_os in
+	  cygwin* | mingw* | windows* | cegcc* | os2*)
 	      # No point in relinking DLLs because paths are not encoded
 	      func_append notinst_deplibs " $lib"
 	      need_relink=no
@@ -8444,11 +8627,11 @@ func_mode_link ()
 	  if test -z "$dlopenmodule" && test yes = "$shouldnotlink" && test link = "$pass"; then
 	    echo
 	    if test prog = "$linkmode"; then
-	      $ECHO "*** Warning: Linking the executable $output against the loadable module"
+	      func_warning "Linking the executable $output against the loadable module"
 	    else
-	      $ECHO "*** Warning: Linking the shared library $output against the loadable module"
+	      func_warning "Linking the shared library $output against the loadable module"
 	    fi
-	    $ECHO "*** $linklib is not portable!"
+	    func_warning "$linklib is not portable!"
 	  fi
 	  if test lib = "$linkmode" &&
 	     test yes = "$hardcode_into_libs"; then
@@ -8458,9 +8641,12 @@ func_mode_link ()
 	    case " $sys_lib_dlsearch_path " in
 	    *" $absdir "*) ;;
 	    *)
-	      case "$compile_rpath " in
+	      case "$compile_rpath$compile_rpath_tail " in
 	      *" $absdir "*) ;;
-	      *) func_append compile_rpath " $absdir" ;;
+	      *) case $absdir in
+                 "$progdir/"*) func_append compile_rpath " $absdir" ;;
+                 *) func_append compile_rpath_tail " $absdir" ;;
+		 esac
 	      esac
 	      ;;
 	    esac
@@ -8487,8 +8673,8 @@ func_mode_link ()
 	      soname=$dlname
 	    elif test -n "$soname_spec"; then
 	      # bleh windows
-	      case $host in
-	      *cygwin* | mingw* | *cegcc* | *os2*)
+	      case $host_os in
+	      cygwin* | mingw* | windows* | cegcc* | os2*)
 	        func_arith $current - $age
 		major=$func_arith_result
 		versuffix=-$major
@@ -8535,6 +8721,7 @@ func_mode_link ()
 		case $host in
 		  *-*-sco3.2v5.0.[024]*) add_dir=-L$dir ;;
 		  *-*-sysv4*uw2*) add_dir=-L$dir ;;
+		  *-*-emscripten*) add_dir=-L$dir ;;
 		  *-*-sysv5OpenUNIX* | *-*-sysv5UnixWare7.[01].[10]* | \
 		    *-*-unixware7*) add_dir=-L$dir ;;
 		  *-*-darwin* )
@@ -8543,11 +8730,10 @@ func_mode_link ()
 		    if /usr/bin/file -L $add 2> /dev/null |
 			 $GREP ": [^:]* bundle" >/dev/null; then
 		      if test "X$dlopenmodule" != "X$lib"; then
-			$ECHO "*** Warning: lib $linklib is a module, not a shared library"
+			func_warning "lib $linklib is a module, not a shared library"
 			if test -z "$old_library"; then
-			  echo
-			  echo "*** And there doesn't seem to be a static archive available"
-			  echo "*** The link will probably fail, sorry"
+			  func_warning "And there doesn't seem to be a static archive available"
+			  func_warning "The link will probably fail, sorry"
 			else
 			  add=$dir/$old_library
 			fi
@@ -8630,7 +8816,7 @@ func_mode_link ()
 	       test no = "$hardcode_direct_absolute"; then
 	      add=$libdir/$linklib
 	    elif test yes = "$hardcode_minus_L"; then
-	      add_dir=-L$libdir
+	      add_dir=-L$lt_sysroot$libdir
 	      add=-l$name
 	    elif test yes = "$hardcode_shlibpath_var"; then
 	      case :$finalize_shlibpath: in
@@ -8647,7 +8833,7 @@ func_mode_link ()
 	      fi
 	    else
 	      # We cannot seem to hardcode it, guess we'll fake it.
-	      add_dir=-L$libdir
+	      add_dir=-L$lt_sysroot$libdir
 	      # Try looking first in the location we're being installed to.
 	      if test -n "$inst_prefix_dir"; then
 		case $libdir in
@@ -8687,21 +8873,19 @@ func_mode_link ()
 
 	    # Just print a warning and add the library to dependency_libs so
 	    # that the program can be linked against the static library.
-	    echo
-	    $ECHO "*** Warning: This system cannot link to static lib archive $lib."
-	    echo "*** I have the capability to make that library automatically link in when"
-	    echo "*** you link to this library.  But I can only do this if you have a"
-	    echo "*** shared version of the library, which you do not appear to have."
+	    func_warning "This system cannot link to static lib archive $lib."
+	    func_warning "I have the capability to make that library automatically link in when"
+	    func_warning "you link to this library.  But I can only do this if you have a"
+	    func_warning "shared version of the library, which you do not appear to have."
 	    if test yes = "$module"; then
-	      echo "*** But as you try to build a module library, libtool will still create "
-	      echo "*** a static module, that should work as long as the dlopening application"
-	      echo "*** is linked with the -dlopen flag to resolve symbols at runtime."
+	      func_warning "But as you try to build a module library, libtool will still create "
+	      func_warning "a static module, that should work as long as the dlopening application"
+	      func_warning "is linked with the -dlopen flag to resolve symbols at runtime."
 	      if test -z "$global_symbol_pipe"; then
-		echo
-		echo "*** However, this would only work if libtool was able to extract symbol"
-		echo "*** lists from a program, using 'nm' or equivalent, but libtool could"
-		echo "*** not find such a program.  So, this module is probably useless."
-		echo "*** 'nm' from GNU binutils and a full rebuild may help."
+		func_warning "However, this would only work if libtool was able to extract symbol"
+		func_warning "lists from a program, using 'nm' or equivalent, but libtool could"
+		func_warning "not find such a program.  So, this module is probably useless."
+		func_warning "'nm' from GNU binutils and a full rebuild may help."
 	      fi
 	      if test no = "$build_old_libs"; then
 		build_libtool_libs=module
@@ -8824,6 +9008,10 @@ func_mode_link ()
 	  fi # link_all_deplibs != no
 	fi # linkmode = lib
       done # for deplib in $libs
+
+      func_append temp_rpath "$temp_rpath_tail"
+      func_append compile_rpath "$compile_rpath_tail"
+
       if test link = "$pass"; then
 	if test prog = "$linkmode"; then
 	  compile_deplibs="$new_inherited_linker_flags $compile_deplibs"
@@ -8861,42 +9049,46 @@ func_mode_link ()
 	  # Add libraries to $var in reverse order
 	  eval tmp_libs=\"\$$var\"
 	  new_libs=
+	  # FIXME: Pedantically, this is the right thing to do, so
+	  #        that some nasty dependency loop isn't accidentally
+	  #        broken: new_libs="$deplib $new_libs"
 	  for deplib in $tmp_libs; do
-	    # FIXME: Pedantically, this is the right thing to do, so
-	    #        that some nasty dependency loop isn't accidentally
-	    #        broken:
-	    #new_libs="$deplib $new_libs"
-	    # Pragmatically, this seems to cause very few problems in
-	    # practice:
-	    case $deplib in
-	    -L*) new_libs="$deplib $new_libs" ;;
-	    -R*) ;;
-	    *)
-	      # And here is the reason: when a library appears more
-	      # than once as an explicit dependence of a library, or
-	      # is implicitly linked in more than once by the
-	      # compiler, it is considered special, and multiple
-	      # occurrences thereof are not removed.  Compare this
-	      # with having the same library being listed as a
-	      # dependency of multiple other libraries: in this case,
-	      # we know (pedantically, we assume) the library does not
-	      # need to be listed more than once, so we keep only the
-	      # last copy.  This is not always right, but it is rare
-	      # enough that we require users that really mean to play
-	      # such unportable linking tricks to link the library
-	      # using -Wl,-lname, so that libtool does not consider it
-	      # for duplicate removal.
-	      case " $specialdeplibs " in
-	      *" $deplib "*) new_libs="$deplib $new_libs" ;;
+	    if $opt_preserve_dup_deps; then
+	      new_libs="$deplib $new_libs"
+	    else
+	      # Pragmatically, this seems to cause very few problems in
+	      # practice:
+	      case $deplib in
+	      -L*) new_libs="$deplib $new_libs" ;;
+	      -R*) ;;
 	      *)
-		case " $new_libs " in
-		*" $deplib "*) ;;
-		*) new_libs="$deplib $new_libs" ;;
-		esac
-		;;
+	        # And here is the reason: when a library appears more
+	        # than once as an explicit dependence of a library, or
+	        # is implicitly linked in more than once by the
+	        # compiler, it is considered special, and multiple
+	        # occurrences thereof are not removed.  Compare this
+	        # with having the same library being listed as a
+	        # dependency of multiple other libraries: in this case,
+	        # we know (pedantically, we assume) the library does not
+	        # need to be listed more than once, so we keep only the
+	        # last copy.  This is not always right, but it is rare
+	        # enough that we require users that really mean to play
+	        # such unportable linking tricks to link the library
+	        # using -Wl,-lname, so that libtool does not consider it
+	        # for duplicate removal.  And if not possible for portability
+	        # reasons, then --preserve-dup-deps should be used.
+	        case " $specialdeplibs " in
+	        *" $deplib "*) new_libs="$deplib $new_libs" ;;
+	        *)
+	          case " $new_libs " in
+	          *" $deplib "*) ;;
+	          *) new_libs="$deplib $new_libs" ;;
+	          esac
+	          ;;
+	        esac
+	        ;;
 	      esac
-	      ;;
-	    esac
+	    fi
 	  done
 	  tmp_libs=
 	  for deplib in $new_libs; do
@@ -9028,9 +9220,7 @@ func_mode_link ()
 	if test pass_all != "$deplibs_check_method"; then
 	  func_fatal_error "cannot build libtool library '$output' from non-libtool objects on this host:$objs"
 	else
-	  echo
-	  $ECHO "*** Warning: Linking the shared library $output against the non-libtool"
-	  $ECHO "*** objects $objs is not portable!"
+	  func_warning "Linking the shared library $output against the non-libtool objects $objs is not portable!"
 	  func_append libobjs " $objs"
 	fi
       fi
@@ -9091,13 +9281,13 @@ func_mode_link ()
 	  #
 	  case $version_type in
 	  # correct linux to gnu/linux during the next big refactor
-	  darwin|freebsd-elf|linux|midnightbsd-elf|osf|windows|none)
+	  darwin|freebsd-elf|linux|midnightbsd-elf|osf|qnx|windows|none)
 	    func_arith $number_major + $number_minor
 	    current=$func_arith_result
 	    age=$number_minor
 	    revision=$number_revision
 	    ;;
-	  freebsd-aout|qnx|sunos)
+	  freebsd-aout|sco|sunos)
 	    current=$number_major
 	    revision=$number_minor
 	    age=0
@@ -9109,6 +9299,9 @@ func_mode_link ()
 	    revision=$number_minor
 	    lt_irix_increment=no
 	    ;;
+	  *)
+	    func_fatal_configuration "$modename: unknown library version type '$version_type'"
+	    ;;
 	  esac
 	  ;;
 	no)
@@ -9244,8 +9437,9 @@ func_mode_link ()
 	  ;;
 
 	qnx)
-	  major=.$current
-	  versuffix=.$current
+	  func_arith $current - $age
+	  major=.$func_arith_result
+	  versuffix=$major.$age.$revision
 	  ;;
 
 	sco)
@@ -9398,7 +9592,7 @@ func_mode_link ()
       if test yes = "$build_libtool_libs"; then
 	if test -n "$rpath"; then
 	  case $host in
-	  *-*-cygwin* | *-*-mingw* | *-*-pw32* | *-*-os2* | *-*-beos* | *-cegcc* | *-*-haiku*)
+	  *-*-cygwin* | *-*-mingw* | *-*-windows* | *-*-pw32* | *-*-os2* | *-*-beos* | *-cegcc* | *-*-haiku*)
 	    # these systems don't actually have a c library (as such)!
 	    ;;
 	  *-*-rhapsody* | *-*-darwin1.[012])
@@ -9449,108 +9643,6 @@ func_mode_link ()
 	  # implementing what was already the behavior.
 	  newdeplibs=$deplibs
 	  ;;
-	test_compile)
-	  # This code stresses the "libraries are programs" paradigm to its
-	  # limits. Maybe even breaks it.  We compile a program, linking it
-	  # against the deplibs as a proxy for the library.  Then we can check
-	  # whether they linked in statically or dynamically with ldd.
-	  $opt_dry_run || $RM conftest.c
-	  cat > conftest.c <<EOF
-	  int main() { return 0; }
-EOF
-	  $opt_dry_run || $RM conftest
-	  if $LTCC $LTCFLAGS -o conftest conftest.c $deplibs; then
-	    ldd_output=`ldd conftest`
-	    for i in $deplibs; do
-	      case $i in
-	      -l*)
-		func_stripname -l '' "$i"
-		name=$func_stripname_result
-		if test yes = "$allow_libtool_libs_with_static_runtimes"; then
-		  case " $predeps $postdeps " in
-		  *" $i "*)
-		    func_append newdeplibs " $i"
-		    i=
-		    ;;
-		  esac
-		fi
-		if test -n "$i"; then
-		  libname=`eval "\\$ECHO \"$libname_spec\""`
-		  deplib_matches=`eval "\\$ECHO \"$library_names_spec\""`
-		  set dummy $deplib_matches; shift
-		  deplib_match=$1
-		  if test `expr "$ldd_output" : ".*$deplib_match"` -ne 0; then
-		    func_append newdeplibs " $i"
-		  else
-		    droppeddeps=yes
-		    echo
-		    $ECHO "*** Warning: dynamic linker does not accept needed library $i."
-		    echo "*** I have the capability to make that library automatically link in when"
-		    echo "*** you link to this library.  But I can only do this if you have a"
-		    echo "*** shared version of the library, which I believe you do not have"
-		    echo "*** because a test_compile did reveal that the linker did not use it for"
-		    echo "*** its dynamic dependency list that programs get resolved with at runtime."
-		  fi
-		fi
-		;;
-	      *)
-		func_append newdeplibs " $i"
-		;;
-	      esac
-	    done
-	  else
-	    # Error occurred in the first compile.  Let's try to salvage
-	    # the situation: Compile a separate program for each library.
-	    for i in $deplibs; do
-	      case $i in
-	      -l*)
-		func_stripname -l '' "$i"
-		name=$func_stripname_result
-		$opt_dry_run || $RM conftest
-		if $LTCC $LTCFLAGS -o conftest conftest.c $i; then
-		  ldd_output=`ldd conftest`
-		  if test yes = "$allow_libtool_libs_with_static_runtimes"; then
-		    case " $predeps $postdeps " in
-		    *" $i "*)
-		      func_append newdeplibs " $i"
-		      i=
-		      ;;
-		    esac
-		  fi
-		  if test -n "$i"; then
-		    libname=`eval "\\$ECHO \"$libname_spec\""`
-		    deplib_matches=`eval "\\$ECHO \"$library_names_spec\""`
-		    set dummy $deplib_matches; shift
-		    deplib_match=$1
-		    if test `expr "$ldd_output" : ".*$deplib_match"` -ne 0; then
-		      func_append newdeplibs " $i"
-		    else
-		      droppeddeps=yes
-		      echo
-		      $ECHO "*** Warning: dynamic linker does not accept needed library $i."
-		      echo "*** I have the capability to make that library automatically link in when"
-		      echo "*** you link to this library.  But I can only do this if you have a"
-		      echo "*** shared version of the library, which you do not appear to have"
-		      echo "*** because a test_compile did reveal that the linker did not use this one"
-		      echo "*** as a dynamic dependency that programs can get resolved with at runtime."
-		    fi
-		  fi
-		else
-		  droppeddeps=yes
-		  echo
-		  $ECHO "*** Warning!  Library $i is needed by this library but I was not able to"
-		  echo "*** make it link in!  You will probably need to install it or some"
-		  echo "*** library that it depends on before this library will be fully"
-		  echo "*** functional.  Installing it before continuing would be even better."
-		fi
-		;;
-	      *)
-		func_append newdeplibs " $i"
-		;;
-	      esac
-	    done
-	  fi
-	  ;;
 	file_magic*)
 	  set dummy $deplibs_check_method; shift
 	  file_magic_regex=`expr "$deplibs_check_method" : "$1 \(.*\)"`
@@ -9614,17 +9706,16 @@ EOF
 	      fi
 	      if test -n "$a_deplib"; then
 		droppeddeps=yes
-		echo
-		$ECHO "*** Warning: linker path does not have real file for library $a_deplib."
-		echo "*** I have the capability to make that library automatically link in when"
-		echo "*** you link to this library.  But I can only do this if you have a"
-		echo "*** shared version of the library, which you do not appear to have"
-		echo "*** because I did check the linker path looking for a file starting"
+		func_warning "Linker path does not have real file for library $a_deplib."
+		func_warning "I have the capability to make that library automatically link in when"
+		func_warning "you link to this library.  But I can only do this if you have a"
+		func_warning "shared version of the library, which you do not appear to have"
+		func_warning "because I did check the linker path looking for a file starting"
 		if test -z "$potlib"; then
-		  $ECHO "*** with $libname but no candidates were found. (...for file magic test)"
+		  func_warning "with $libname but no candidates were found. (...for file magic test)"
 		else
-		  $ECHO "*** with $libname and none of the candidates passed a file format test"
-		  $ECHO "*** using a file magic. Last file checked: $potlib"
+		  func_warning "with $libname and none of the candidates passed a file format test"
+		  func_warning "using a file magic. Last file checked: $potlib"
 		fi
 	      fi
 	      ;;
@@ -9668,17 +9759,16 @@ EOF
 	      fi
 	      if test -n "$a_deplib"; then
 		droppeddeps=yes
-		echo
-		$ECHO "*** Warning: linker path does not have real file for library $a_deplib."
-		echo "*** I have the capability to make that library automatically link in when"
-		echo "*** you link to this library.  But I can only do this if you have a"
-		echo "*** shared version of the library, which you do not appear to have"
-		echo "*** because I did check the linker path looking for a file starting"
+		func_warning "Linker path does not have real file for library $a_deplib."
+		func_warning "I have the capability to make that library automatically link in when"
+		func_warning "you link to this library.  But I can only do this if you have a"
+		func_warning "shared version of the library, which you do not appear to have"
+		func_warning "because I did check the linker path looking for a file starting"
 		if test -z "$potlib"; then
-		  $ECHO "*** with $libname but no candidates were found. (...for regex pattern test)"
+		  func_warning "with $libname but no candidates were found. (...for regex pattern test)"
 		else
-		  $ECHO "*** with $libname and none of the candidates passed a file format test"
-		  $ECHO "*** using a regex pattern. Last file checked: $potlib"
+		  func_warning "with $libname and none of the candidates passed a file format test"
+		  func_warning "using a regex pattern. Last file checked: $potlib"
 		fi
 	      fi
 	      ;;
@@ -9702,11 +9792,11 @@ EOF
 	  *[!\	\ ]*)
 	    echo
 	    if test none = "$deplibs_check_method"; then
-	      echo "*** Warning: inter-library dependencies are not supported in this platform."
+	      func_warning "Inter-library dependencies are not supported in this platform."
 	    else
-	      echo "*** Warning: inter-library dependencies are not known to be supported."
+	      func_warning "Inter-library dependencies are not known to be supported."
 	    fi
-	    echo "*** All declared inter-library dependencies are being dropped."
+	    func_warning "All declared inter-library dependencies are being dropped."
 	    droppeddeps=yes
 	    ;;
 	  esac
@@ -9727,17 +9817,15 @@ EOF
 
 	if test yes = "$droppeddeps"; then
 	  if test yes = "$module"; then
-	    echo
-	    echo "*** Warning: libtool could not satisfy all declared inter-library"
-	    $ECHO "*** dependencies of module $libname.  Therefore, libtool will create"
-	    echo "*** a static module, that should work as long as the dlopening"
-	    echo "*** application is linked with the -dlopen flag."
+	    func_warning "libtool could not satisfy all declared inter-library"
+	    func_warning "dependencies of module $libname.  Therefore, libtool will create"
+	    func_warning "a static module, that should work as long as the dlopening"
+	    func_warning "application is linked with the -dlopen flag."
 	    if test -z "$global_symbol_pipe"; then
-	      echo
-	      echo "*** However, this would only work if libtool was able to extract symbol"
-	      echo "*** lists from a program, using 'nm' or equivalent, but libtool could"
-	      echo "*** not find such a program.  So, this module is probably useless."
-	      echo "*** 'nm' from GNU binutils and a full rebuild may help."
+	      func_warning "However, this would only work if libtool was able to extract symbol"
+	      func_warning "lists from a program, using 'nm' or equivalent, but libtool could"
+	      func_warning "not find such a program.  So, this module is probably useless."
+	      func_warning "'nm' from GNU binutils and a full rebuild may help."
 	    fi
 	    if test no = "$build_old_libs"; then
 	      oldlibs=$output_objdir/$libname.$libext
@@ -9912,7 +10000,7 @@ EOF
 
 	orig_export_symbols=
 	case $host_os in
-	cygwin* | mingw* | cegcc*)
+	cygwin* | mingw* | windows* | cegcc*)
 	  if test -n "$export_symbols" && test -z "$export_symbols_regex"; then
 	    # exporting using user supplied symfile
 	    func_dll_def_p "$export_symbols" || {
@@ -10110,20 +10198,7 @@ EOF
 	  last_robj=
 	  k=1
 
-	  if test -n "$save_libobjs" && test : != "$skipped_export" && test yes = "$with_gnu_ld"; then
-	    output=$output_objdir/$output_la.lnkscript
-	    func_verbose "creating GNU ld script: $output"
-	    echo 'INPUT (' > $output
-	    for obj in $save_libobjs
-	    do
-	      func_to_tool_file "$obj"
-	      $ECHO "$func_to_tool_file_result" >> $output
-	    done
-	    echo ')' >> $output
-	    func_append delfiles " $output"
-	    func_to_tool_file "$output"
-	    output=$func_to_tool_file_result
-	  elif test -n "$save_libobjs" && test : != "$skipped_export" && test -n "$file_list_spec"; then
+	  if test -n "$save_libobjs" && test : != "$skipped_export" && test -n "$file_list_spec"; then
 	    output=$output_objdir/$output_la.lnk
 	    func_verbose "creating linker input file list: $output"
 	    : > $output
@@ -10142,6 +10217,19 @@ EOF
 	    func_append delfiles " $output"
 	    func_to_tool_file "$output"
 	    output=$firstobj\"$file_list_spec$func_to_tool_file_result\"
+	  elif test -n "$save_libobjs" && test : != "$skipped_export" && test yes = "$with_gnu_ld"; then
+	    output=$output_objdir/$output_la.lnkscript
+	    func_verbose "creating GNU ld script: $output"
+	    echo 'INPUT (' > $output
+	    for obj in $save_libobjs
+	    do
+	      func_to_tool_file "$obj"
+	      $ECHO "$func_to_tool_file_result" >> $output
+	    done
+	    echo ')' >> $output
+	    func_append delfiles " $output"
+	    func_to_tool_file "$output"
+	    output=$func_to_tool_file_result
 	  else
 	    if test -n "$save_libobjs"; then
 	      func_verbose "creating reloadable object files..."
@@ -10582,7 +10670,7 @@ EOF
 	  esac
 	fi
 	case $host in
-	*-*-cygwin* | *-*-mingw* | *-*-pw32* | *-*-os2* | *-cegcc*)
+	*-*-cygwin* | *-*-mingw* | *-*-windows* | *-*-pw32* | *-*-os2* | *-cegcc*)
 	  testbindir=`$ECHO "$libdir" | $SED -e 's*/lib$*/bin*'`
 	  case :$dllsearchpath: in
 	  *":$libdir:"*) ;;
@@ -10660,7 +10748,7 @@ EOF
         # Disable wrappers for cegcc and mingw32ce hosts, we are cross compiling anyway.
         wrappers_required=false
         ;;
-      *cygwin* | *mingw* )
+      *cygwin* | *mingw* | *windows* )
         test yes = "$build_libtool_libs" || wrappers_required=false
         ;;
       *)
@@ -10814,7 +10902,7 @@ EOF
 	  *) exeext= ;;
 	esac
 	case $host in
-	  *cygwin* | *mingw* )
+	  *cygwin* | *mingw* | windows* )
 	    func_dirname_and_basename "$output" "" "."
 	    output_name=$func_basename_result
 	    output_path=$func_dirname_result
@@ -11148,7 +11236,7 @@ EOF
 	  # tests/bindir.at for full details.
 	  tdlname=$dlname
 	  case $host,$output,$installed,$module,$dlname in
-	    *cygwin*,*lai,yes,no,*.dll | *mingw*,*lai,yes,no,*.dll | *cegcc*,*lai,yes,no,*.dll)
+	    *cygwin*,*lai,yes,no,*.dll | *mingw*,*lai,yes,no,*.dll | *windows*,*lai,yes,no,*.dll | *cegcc*,*lai,yes,no,*.dll)
 	      # If a -bindir argument was supplied, place the dll there.
 	      if test -n "$bindir"; then
 		func_relative_path "$install_libdir" "$bindir"
diff --git a/mips/filter_msa_intrinsics.c b/mips/filter_msa_intrinsics.c
index 1b734f4d9..a294f5513 100644
--- a/mips/filter_msa_intrinsics.c
+++ b/mips/filter_msa_intrinsics.c
@@ -1,4 +1,3 @@
-
 /* filter_msa_intrinsics.c - MSA optimised filter functions
  *
  * Copyright (c) 2018-2024 Cosmin Truta
@@ -47,7 +46,7 @@
        uint8_t *psrc_lw_m = (uint8_t *) (psrc);  \
        uint32_t val_m;                           \
                                                  \
-       asm volatile (                            \
+       __asm__ volatile (                        \
            "lw  %[val_m],  %[psrc_lw_m]  \n\t"   \
                                                  \
            : [val_m] "=r" (val_m)                \
@@ -62,7 +61,7 @@
        uint8_t *pdst_sh_m = (uint8_t *) (pdst);  \
        uint16_t val_m = (val);                   \
                                                  \
-       asm volatile (                            \
+       __asm__ volatile (                        \
            "sh  %[val_m],  %[pdst_sh_m]  \n\t"   \
                                                  \
            : [pdst_sh_m] "=m" (*pdst_sh_m)       \
@@ -75,7 +74,7 @@
        uint8_t *pdst_sw_m = (uint8_t *) (pdst);  \
        uint32_t val_m = (val);                   \
                                                  \
-       asm volatile (                            \
+       __asm__ volatile (                        \
            "sw  %[val_m],  %[pdst_sw_m]  \n\t"   \
                                                  \
            : [pdst_sw_m] "=m" (*pdst_sw_m)       \
@@ -83,20 +82,20 @@
        );                                        \
    }
 
-       #if (__mips == 64)
+   #if __mips == 64
         #define SD(val, pdst)                         \
         {                                             \
             uint8_t *pdst_sd_m = (uint8_t *) (pdst);  \
             uint64_t val_m = (val);                   \
                                                       \
-            asm volatile (                            \
+            __asm__ volatile (                        \
                 "sd  %[val_m],  %[pdst_sd_m]  \n\t"   \
                                                       \
                 : [pdst_sd_m] "=m" (*pdst_sd_m)       \
                 : [val_m] "r" (val_m)                 \
             );                                        \
         }
-    #else
+   #else
         #define SD(val, pdst)                                          \
         {                                                              \
             uint8_t *pdst_sd_m = (uint8_t *) (pdst);                   \
@@ -108,17 +107,17 @@
             SW(val0_m, pdst_sd_m);                                     \
             SW(val1_m, pdst_sd_m + 4);                                 \
         }
-    #endif
+   #endif /* __mips == 64 */
 #else
    #define MSA_SRLI_B(a, b)   (a >> b)
 
-#if (__mips_isa_rev >= 6)
+#if __mips_isa_rev >= 6
    #define LW(psrc)                              \
    ( {                                           \
        uint8_t *psrc_lw_m = (uint8_t *) (psrc);  \
        uint32_t val_m;                           \
                                                  \
-       asm volatile (                            \
+       __asm__ volatile (                        \
            "lw  %[val_m],  %[psrc_lw_m]  \n\t"   \
                                                  \
            : [val_m] "=r" (val_m)                \
@@ -133,7 +132,7 @@
        uint8_t *pdst_sh_m = (uint8_t *) (pdst);  \
        uint16_t val_m = (val);                   \
                                                  \
-       asm volatile (                            \
+       __asm__ volatile (                        \
            "sh  %[val_m],  %[pdst_sh_m]  \n\t"   \
                                                  \
            : [pdst_sh_m] "=m" (*pdst_sh_m)       \
@@ -146,7 +145,7 @@
        uint8_t *pdst_sw_m = (uint8_t *) (pdst);  \
        uint32_t val_m = (val);                   \
                                                  \
-       asm volatile (                            \
+       __asm__ volatile (                        \
            "sw  %[val_m],  %[pdst_sw_m]  \n\t"   \
                                                  \
            : [pdst_sw_m] "=m" (*pdst_sw_m)       \
@@ -154,20 +153,20 @@
        );                                        \
    }
 
-   #if (__mips == 64)
+   #if __mips == 64
         #define SD(val, pdst)                         \
         {                                             \
             uint8_t *pdst_sd_m = (uint8_t *) (pdst);  \
             uint64_t val_m = (val);                   \
                                                       \
-            asm volatile (                            \
+            __asm__ volatile (                        \
                 "sd  %[val_m],  %[pdst_sd_m]  \n\t"   \
                                                       \
                 : [pdst_sd_m] "=m" (*pdst_sd_m)       \
                 : [val_m] "r" (val_m)                 \
             );                                        \
         }
-    #else
+   #else
         #define SD(val, pdst)                                          \
         {                                                              \
             uint8_t *pdst_sd_m = (uint8_t *) (pdst);                   \
@@ -179,14 +178,14 @@
             SW(val0_m, pdst_sd_m);                                     \
             SW(val1_m, pdst_sd_m + 4);                                 \
         }
-    #endif
-#else  // !(__mips_isa_rev >= 6)
+   #endif /* __mips == 64 */
+#else
    #define LW(psrc)                              \
    ( {                                           \
        uint8_t *psrc_lw_m = (uint8_t *) (psrc);  \
        uint32_t val_m;                           \
                                                  \
-       asm volatile (                            \
+       __asm__ volatile (                        \
            "ulw  %[val_m],  %[psrc_lw_m]  \n\t"  \
                                                  \
            : [val_m] "=r" (val_m)                \
@@ -201,7 +200,7 @@
        uint8_t *pdst_sh_m = (uint8_t *) (pdst);  \
        uint16_t val_m = (val);                   \
                                                  \
-       asm volatile (                            \
+       __asm__ volatile (                        \
            "ush  %[val_m],  %[pdst_sh_m]  \n\t"  \
                                                  \
            : [pdst_sh_m] "=m" (*pdst_sh_m)       \
@@ -214,7 +213,7 @@
        uint8_t *pdst_sw_m = (uint8_t *) (pdst);  \
        uint32_t val_m = (val);                   \
                                                  \
-       asm volatile (                            \
+       __asm__ volatile (                        \
            "usw  %[val_m],  %[pdst_sw_m]  \n\t"  \
                                                  \
            : [pdst_sw_m] "=m" (*pdst_sw_m)       \
@@ -222,7 +221,7 @@
        );                                        \
    }
 
-   #define SD(val, pdst)                                          \
+   #define SD(val, pdst)                                           \
     {                                                              \
         uint8_t *pdst_sd_m = (uint8_t *) (pdst);                   \
         uint32_t val0_m, val1_m;                                   \
@@ -238,14 +237,14 @@
     {                                          \
         uint8_t *pdst_m = (uint8_t *) (pdst);  \
                                                \
-        asm volatile (                         \
+        __asm__ volatile (                     \
             "usw  $0,  %[pdst_m]  \n\t"        \
                                                \
             : [pdst_m] "=m" (*pdst_m)          \
             :                                  \
         );                                     \
     }
-#endif  // (__mips_isa_rev >= 6)
+#endif /* __mips_isa_rev >= 6 */
 #endif
 
 #define LD_B(RTYPE, psrc) *((RTYPE *) (psrc))
diff --git a/mips/mips_init.c b/mips/mips_init.c
index 5c6fa1dbf..143f0a371 100644
--- a/mips/mips_init.c
+++ b/mips/mips_init.c
@@ -1,4 +1,3 @@
-
 /* mips_init.c - MSA optimised filter functions
  *
  * Copyright (c) 2018-2024 Cosmin Truta
diff --git a/png.5 b/png.5
index 14a3c432b..ee4a2b20d 100644
--- a/png.5
+++ b/png.5
@@ -1,4 +1,4 @@
-.TH PNG 5 "September 12, 2024"
+.TH PNG 5 "February 18, 2025"
 .SH NAME
 png \- Portable Network Graphics (PNG) format
 
@@ -20,6 +20,11 @@ matching on heterogeneous platforms.
 .SH "SEE ALSO"
 .BR "libpng"(3), " zlib"(3), " deflate"(5), " " and " zlib"(5)
 .LP
+PNG Specification (Third Edition) Candidate Recommendation Draft, January 2025:
+.IP
+.br
+https://www.w3.org/TR/2025/CRD-png-3-20250121/
+.LP
 PNG Specification (Second Edition), November 2003:
 .IP
 .br
diff --git a/png.c b/png.c
index 9a9fb23d9..6d533ec40 100644
--- a/png.c
+++ b/png.c
@@ -1,7 +1,6 @@
-
 /* png.c - location for general purpose libpng functions
  *
- * Copyright (c) 2018-2024 Cosmin Truta
+ * Copyright (c) 2018-2025 Cosmin Truta
  * Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson
  * Copyright (c) 1996-1997 Andreas Dilger
  * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
@@ -14,7 +13,34 @@
 #include "pngpriv.h"
 
 /* Generate a compiler error if there is an old png.h in the search path. */
-typedef png_libpng_version_1_6_44 Your_png_h_is_not_version_1_6_44;
+typedef png_libpng_version_1_6_47 Your_png_h_is_not_version_1_6_47;
+
+/* Sanity check the chunks definitions - PNG_KNOWN_CHUNKS from pngpriv.h and the
+ * corresponding macro definitions.  This causes a compile time failure if
+ * something is wrong but generates no code.
+ *
+ * (1) The first check is that the PNG_CHUNK(cHNK, index) 'index' values must
+ * increment from 0 to the last value.
+ */
+#define PNG_CHUNK(cHNK, index) != (index) || ((index)+1)
+
+#if 0 PNG_KNOWN_CHUNKS < 0
+#  error PNG_KNOWN_CHUNKS chunk definitions are not in order
+#endif
+
+#undef PNG_CHUNK
+
+/* (2) The chunk name macros, png_cHNK, must all be valid and defined.  Since
+ * this is a preprocessor test undefined pp-tokens come out as zero and will
+ * fail this test.
+ */
+#define PNG_CHUNK(cHNK, index) !PNG_CHUNK_NAME_VALID(png_ ## cHNK) ||
+
+#if PNG_KNOWN_CHUNKS 0
+#  error png_cHNK not defined for some known cHNK
+#endif
+
+#undef PNG_CHUNK
 
 /* Tells libpng that we have already handled the first "num_bytes" bytes
  * of the PNG file signature.  If the PNG data is embedded into another
@@ -242,21 +268,23 @@ png_create_png_struct,(png_const_charp user_png_ver, png_voidp error_ptr,
     */
    memset(&create_struct, 0, (sizeof create_struct));
 
-   /* Added at libpng-1.2.6 */
 #  ifdef PNG_USER_LIMITS_SUPPORTED
       create_struct.user_width_max = PNG_USER_WIDTH_MAX;
       create_struct.user_height_max = PNG_USER_HEIGHT_MAX;
 
 #     ifdef PNG_USER_CHUNK_CACHE_MAX
-      /* Added at libpng-1.2.43 and 1.4.0 */
       create_struct.user_chunk_cache_max = PNG_USER_CHUNK_CACHE_MAX;
 #     endif
 
-#     ifdef PNG_USER_CHUNK_MALLOC_MAX
-      /* Added at libpng-1.2.43 and 1.4.1, required only for read but exists
-       * in png_struct regardless.
-       */
+#     if PNG_USER_CHUNK_MALLOC_MAX > 0 /* default to compile-time limit */
       create_struct.user_chunk_malloc_max = PNG_USER_CHUNK_MALLOC_MAX;
+
+      /* No compile-time limit, so initialize to the system limit: */
+#     elif defined PNG_MAX_MALLOC_64K /* legacy system limit */
+      create_struct.user_chunk_malloc_max = 65536U;
+
+#     else /* modern system limit SIZE_MAX (C99) */
+      create_struct.user_chunk_malloc_max = PNG_SIZE_MAX;
 #     endif
 #  endif
 
@@ -598,13 +626,6 @@ png_free_data(png_const_structrp png_ptr, png_inforp info_ptr, png_uint_32 mask,
    /* Free any eXIf entry */
    if (((mask & PNG_FREE_EXIF) & info_ptr->free_me) != 0)
    {
-# ifdef PNG_READ_eXIf_SUPPORTED
-      if (info_ptr->eXIf_buf)
-      {
-         png_free(png_ptr, info_ptr->eXIf_buf);
-         info_ptr->eXIf_buf = NULL;
-      }
-# endif
       if (info_ptr->exif)
       {
          png_free(png_ptr, info_ptr->exif);
@@ -794,8 +815,8 @@ png_get_copyright(png_const_structrp png_ptr)
    return PNG_STRING_COPYRIGHT
 #else
    return PNG_STRING_NEWLINE \
-      "libpng version 1.6.44" PNG_STRING_NEWLINE \
-      "Copyright (c) 2018-2024 Cosmin Truta" PNG_STRING_NEWLINE \
+      "libpng version 1.6.47" PNG_STRING_NEWLINE \
+      "Copyright (c) 2018-2025 Cosmin Truta" PNG_STRING_NEWLINE \
       "Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson" \
       PNG_STRING_NEWLINE \
       "Copyright (c) 1996-1997 Andreas Dilger" PNG_STRING_NEWLINE \
@@ -1039,186 +1060,67 @@ png_zstream_error(png_structrp png_ptr, int ret)
    }
 }
 
-/* png_convert_size: a PNGAPI but no longer in png.h, so deleted
- * at libpng 1.5.5!
- */
-
-/* Added at libpng version 1.2.34 and 1.4.0 (moved from pngset.c) */
-#ifdef PNG_GAMMA_SUPPORTED /* always set if COLORSPACE */
-static int
-png_colorspace_check_gamma(png_const_structrp png_ptr,
-    png_colorspacerp colorspace, png_fixed_point gAMA, int from)
-   /* This is called to check a new gamma value against an existing one.  The
-    * routine returns false if the new gamma value should not be written.
-    *
-    * 'from' says where the new gamma value comes from:
-    *
-    *    0: the new gamma value is the libpng estimate for an ICC profile
-    *    1: the new gamma value comes from a gAMA chunk
-    *    2: the new gamma value comes from an sRGB chunk
-    */
+#ifdef PNG_COLORSPACE_SUPPORTED
+static png_int_32
+png_fp_add(png_int_32 addend0, png_int_32 addend1, int *error)
 {
-   png_fixed_point gtest;
-
-   if ((colorspace->flags & PNG_COLORSPACE_HAVE_GAMMA) != 0 &&
-       (png_muldiv(&gtest, colorspace->gamma, PNG_FP_1, gAMA) == 0  ||
-      png_gamma_significant(gtest) != 0))
+   /* Safely add two fixed point values setting an error flag and returning 0.5
+    * on overflow.
+    * IMPLEMENTATION NOTE: ANSI requires signed overflow not to occur, therefore
+    * relying on addition of two positive values producing a negative one is not
+    * safe.
+    */
+   if (addend0 > 0)
    {
-      /* Either this is an sRGB image, in which case the calculated gamma
-       * approximation should match, or this is an image with a profile and the
-       * value libpng calculates for the gamma of the profile does not match the
-       * value recorded in the file.  The former, sRGB, case is an error, the
-       * latter is just a warning.
-       */
-      if ((colorspace->flags & PNG_COLORSPACE_FROM_sRGB) != 0 || from == 2)
-      {
-         png_chunk_report(png_ptr, "gamma value does not match sRGB",
-             PNG_CHUNK_ERROR);
-         /* Do not overwrite an sRGB value */
-         return from == 2;
-      }
-
-      else /* sRGB tag not involved */
-      {
-         png_chunk_report(png_ptr, "gamma value does not match libpng estimate",
-             PNG_CHUNK_WARNING);
-         return from == 1;
-      }
+      if (0x7fffffff - addend0 >= addend1)
+         return addend0+addend1;
    }
-
-   return 1;
-}
-
-void /* PRIVATE */
-png_colorspace_set_gamma(png_const_structrp png_ptr,
-    png_colorspacerp colorspace, png_fixed_point gAMA)
-{
-   /* Changed in libpng-1.5.4 to limit the values to ensure overflow can't
-    * occur.  Since the fixed point representation is asymmetrical it is
-    * possible for 1/gamma to overflow the limit of 21474 and this means the
-    * gamma value must be at least 5/100000 and hence at most 20000.0.  For
-    * safety the limits here are a little narrower.  The values are 0.00016 to
-    * 6250.0, which are truly ridiculous gamma values (and will produce
-    * displays that are all black or all white.)
-    *
-    * In 1.6.0 this test replaces the ones in pngrutil.c, in the gAMA chunk
-    * handling code, which only required the value to be >0.
-    */
-   png_const_charp errmsg;
-
-   if (gAMA < 16 || gAMA > 625000000)
-      errmsg = "gamma value out of range";
-
-#  ifdef PNG_READ_gAMA_SUPPORTED
-   /* Allow the application to set the gamma value more than once */
-   else if ((png_ptr->mode & PNG_IS_READ_STRUCT) != 0 &&
-      (colorspace->flags & PNG_COLORSPACE_FROM_gAMA) != 0)
-      errmsg = "duplicate";
-#  endif
-
-   /* Do nothing if the colorspace is already invalid */
-   else if ((colorspace->flags & PNG_COLORSPACE_INVALID) != 0)
-      return;
-
-   else
+   else if (addend0 < 0)
    {
-      if (png_colorspace_check_gamma(png_ptr, colorspace, gAMA,
-          1/*from gAMA*/) != 0)
-      {
-         /* Store this gamma value. */
-         colorspace->gamma = gAMA;
-         colorspace->flags |=
-            (PNG_COLORSPACE_HAVE_GAMMA | PNG_COLORSPACE_FROM_gAMA);
-      }
-
-      /* At present if the check_gamma test fails the gamma of the colorspace is
-       * not updated however the colorspace is not invalidated.  This
-       * corresponds to the case where the existing gamma comes from an sRGB
-       * chunk or profile.  An error message has already been output.
-       */
-      return;
+      if (-0x7fffffff - addend0 <= addend1)
+         return addend0+addend1;
    }
+   else
+      return addend1;
 
-   /* Error exit - errmsg has been set. */
-   colorspace->flags |= PNG_COLORSPACE_INVALID;
-   png_chunk_report(png_ptr, errmsg, PNG_CHUNK_WRITE_ERROR);
+   *error = 1;
+   return PNG_FP_1/2;
 }
 
-void /* PRIVATE */
-png_colorspace_sync_info(png_const_structrp png_ptr, png_inforp info_ptr)
+static png_int_32
+png_fp_sub(png_int_32 addend0, png_int_32 addend1, int *error)
 {
-   if ((info_ptr->colorspace.flags & PNG_COLORSPACE_INVALID) != 0)
+   /* As above but calculate addend0-addend1. */
+   if (addend1 > 0)
    {
-      /* Everything is invalid */
-      info_ptr->valid &= ~(PNG_INFO_gAMA|PNG_INFO_cHRM|PNG_INFO_sRGB|
-         PNG_INFO_iCCP);
-
-#     ifdef PNG_COLORSPACE_SUPPORTED
-      /* Clean up the iCCP profile now if it won't be used. */
-      png_free_data(png_ptr, info_ptr, PNG_FREE_ICCP, -1/*not used*/);
-#     else
-      PNG_UNUSED(png_ptr)
-#     endif
+      if (-0x7fffffff + addend1 <= addend0)
+         return addend0-addend1;
    }
-
-   else
+   else if (addend1 < 0)
    {
-#     ifdef PNG_COLORSPACE_SUPPORTED
-      /* Leave the INFO_iCCP flag set if the pngset.c code has already set
-       * it; this allows a PNG to contain a profile which matches sRGB and
-       * yet still have that profile retrievable by the application.
-       */
-      if ((info_ptr->colorspace.flags & PNG_COLORSPACE_MATCHES_sRGB) != 0)
-         info_ptr->valid |= PNG_INFO_sRGB;
-
-      else
-         info_ptr->valid &= ~PNG_INFO_sRGB;
-
-      if ((info_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_ENDPOINTS) != 0)
-         info_ptr->valid |= PNG_INFO_cHRM;
-
-      else
-         info_ptr->valid &= ~PNG_INFO_cHRM;
-#     endif
-
-      if ((info_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_GAMMA) != 0)
-         info_ptr->valid |= PNG_INFO_gAMA;
-
-      else
-         info_ptr->valid &= ~PNG_INFO_gAMA;
+      if (0x7fffffff + addend1 >= addend0)
+         return addend0-addend1;
    }
-}
-
-#ifdef PNG_READ_SUPPORTED
-void /* PRIVATE */
-png_colorspace_sync(png_const_structrp png_ptr, png_inforp info_ptr)
-{
-   if (info_ptr == NULL) /* reduce code size; check here not in the caller */
-      return;
+   else
+      return addend0;
 
-   info_ptr->colorspace = png_ptr->colorspace;
-   png_colorspace_sync_info(png_ptr, info_ptr);
+   *error = 1;
+   return PNG_FP_1/2;
 }
-#endif
-#endif /* GAMMA */
 
-#ifdef PNG_COLORSPACE_SUPPORTED
 static int
 png_safe_add(png_int_32 *addend0_and_result, png_int_32 addend1,
-      png_int_32 addend2) {
-   /* Safely add three integers.  Returns 0 on success, 1 on overlow.
-    * IMPLEMENTATION NOTE: ANSI requires signed overflow not to occur, therefore
-    * relying on addition of two positive values producing a negative one is not
-    * safe.
+      png_int_32 addend2)
+{
+   /* Safely add three integers.  Returns 0 on success, 1 on overflow.  Does not
+    * set the result on overflow.
     */
-   int addend0 = *addend0_and_result;
-   if (0x7fffffff - addend0 < addend1)
-      return 1;
-   addend0 += addend1;
-   if (0x7fffffff - addend1 < addend2)
-      return 1;
-   *addend0_and_result = addend0 + addend2;
-   return 0;
+   int error = 0;
+   int result = png_fp_add(*addend0_and_result,
+                           png_fp_add(addend1, addend2, &error),
+                           &error);
+   if (!error) *addend0_and_result = result;
+   return error;
 }
 
 /* Added at libpng-1.5.5 to support read and write of true CIEXYZ values for
@@ -1226,10 +1128,11 @@ png_safe_add(png_int_32 *addend0_and_result, png_int_32 addend1,
  * non-zero on a parameter error.  The X, Y and Z values are required to be
  * positive and less than 1.0.
  */
-static int
+int /* PRIVATE */
 png_xy_from_XYZ(png_xy *xy, const png_XYZ *XYZ)
 {
-   png_int_32 d, dred, dgreen, dwhite, whiteX, whiteY;
+   /* NOTE: returns 0 on success, 1 means error. */
+   png_int_32 d, dred, dgreen, dblue, dwhite, whiteX, whiteY;
 
    /* 'd' in each of the blocks below is just X+Y+Z for each component,
     * x, y and z are X,Y,Z/(X+Y+Z).
@@ -1237,44 +1140,52 @@ png_xy_from_XYZ(png_xy *xy, const png_XYZ *XYZ)
    d = XYZ->red_X;
    if (png_safe_add(&d, XYZ->red_Y, XYZ->red_Z))
       return 1;
-   if (png_muldiv(&xy->redx, XYZ->red_X, PNG_FP_1, d) == 0)
+   dred = d;
+   if (png_muldiv(&xy->redx, XYZ->red_X, PNG_FP_1, dred) == 0)
       return 1;
-   if (png_muldiv(&xy->redy, XYZ->red_Y, PNG_FP_1, d) == 0)
+   if (png_muldiv(&xy->redy, XYZ->red_Y, PNG_FP_1, dred) == 0)
       return 1;
-   dred = d;
-   whiteX = XYZ->red_X;
-   whiteY = XYZ->red_Y;
 
    d = XYZ->green_X;
    if (png_safe_add(&d, XYZ->green_Y, XYZ->green_Z))
       return 1;
-   if (png_muldiv(&xy->greenx, XYZ->green_X, PNG_FP_1, d) == 0)
+   dgreen = d;
+   if (png_muldiv(&xy->greenx, XYZ->green_X, PNG_FP_1, dgreen) == 0)
       return 1;
-   if (png_muldiv(&xy->greeny, XYZ->green_Y, PNG_FP_1, d) == 0)
+   if (png_muldiv(&xy->greeny, XYZ->green_Y, PNG_FP_1, dgreen) == 0)
       return 1;
-   dgreen = d;
-   whiteX += XYZ->green_X;
-   whiteY += XYZ->green_Y;
 
    d = XYZ->blue_X;
    if (png_safe_add(&d, XYZ->blue_Y, XYZ->blue_Z))
       return 1;
-   if (png_muldiv(&xy->bluex, XYZ->blue_X, PNG_FP_1, d) == 0)
+   dblue = d;
+   if (png_muldiv(&xy->bluex, XYZ->blue_X, PNG_FP_1, dblue) == 0)
       return 1;
-   if (png_muldiv(&xy->bluey, XYZ->blue_Y, PNG_FP_1, d) == 0)
+   if (png_muldiv(&xy->bluey, XYZ->blue_Y, PNG_FP_1, dblue) == 0)
       return 1;
-   whiteX += XYZ->blue_X;
-   whiteY += XYZ->blue_Y;
 
    /* The reference white is simply the sum of the end-point (X,Y,Z) vectors so
     * the fillowing calculates (X+Y+Z) of the reference white (media white,
     * encoding white) itself:
     */
+   d = dblue;
    if (png_safe_add(&d, dred, dgreen))
       return 1;
-
    dwhite = d;
 
+   /* Find the white X,Y values from the sum of the red, green and blue X,Y
+    * values.
+    */
+   d = XYZ->red_X;
+   if (png_safe_add(&d, XYZ->green_X, XYZ->blue_X))
+      return 1;
+   whiteX = d;
+
+   d = XYZ->red_Y;
+   if (png_safe_add(&d, XYZ->green_Y, XYZ->blue_Y))
+      return 1;
+   whiteY = d;
+
    if (png_muldiv(&xy->whitex, whiteX, PNG_FP_1, dwhite) == 0)
       return 1;
    if (png_muldiv(&xy->whitey, whiteY, PNG_FP_1, dwhite) == 0)
@@ -1283,12 +1194,36 @@ png_xy_from_XYZ(png_xy *xy, const png_XYZ *XYZ)
    return 0;
 }
 
-static int
+int /* PRIVATE */
 png_XYZ_from_xy(png_XYZ *XYZ, const png_xy *xy)
 {
+   /* NOTE: returns 0 on success, 1 means error. */
    png_fixed_point red_inverse, green_inverse, blue_scale;
    png_fixed_point left, right, denominator;
 
+   /* Check xy and, implicitly, z.  Note that wide gamut color spaces typically
+    * have end points with 0 tristimulus values (these are impossible end
+    * points, but they are used to cover the possible colors).  We check
+    * xy->whitey against 5, not 0, to avoid a possible integer overflow.
+    *
+    * The limits here will *not* accept ACES AP0, where bluey is -7700
+    * (-0.0770) because the PNG spec itself requires the xy values to be
+    * unsigned.  whitey is also required to be 5 or more to avoid overflow.
+    *
+    * Instead the upper limits have been relaxed to accomodate ACES AP1 where
+    * redz ends up as -600 (-0.006).  ProPhotoRGB was already "in range."
+    * The new limit accomodates the AP0 and AP1 ranges for z but not AP0 redy.
+    */
+   const png_fixed_point fpLimit = PNG_FP_1+(PNG_FP_1/10);
+   if (xy->redx   < 0 || xy->redx > fpLimit) return 1;
+   if (xy->redy   < 0 || xy->redy > fpLimit-xy->redx) return 1;
+   if (xy->greenx < 0 || xy->greenx > fpLimit) return 1;
+   if (xy->greeny < 0 || xy->greeny > fpLimit-xy->greenx) return 1;
+   if (xy->bluex  < 0 || xy->bluex > fpLimit) return 1;
+   if (xy->bluey  < 0 || xy->bluey > fpLimit-xy->bluex) return 1;
+   if (xy->whitex < 0 || xy->whitex > fpLimit) return 1;
+   if (xy->whitey < 5 || xy->whitey > fpLimit-xy->whitex) return 1;
+
    /* The reverse calculation is more difficult because the original tristimulus
     * value had 9 independent values (red,green,blue)x(X,Y,Z) however only 8
     * derived values were recorded in the cHRM chunk;
@@ -1432,18 +1367,23 @@ png_XYZ_from_xy(png_XYZ *XYZ, const png_xy *xy)
     *  (green-x - blue-x)*(red-y - blue-y)-(green-y - blue-y)*(red-x - blue-x)
     *
     * Accuracy:
-    * The input values have 5 decimal digits of accuracy.  The values are all in
-    * the range 0 < value < 1, so simple products are in the same range but may
-    * need up to 10 decimal digits to preserve the original precision and avoid
-    * underflow.  Because we are using a 32-bit signed representation we cannot
-    * match this; the best is a little over 9 decimal digits, less than 10.
+    * The input values have 5 decimal digits of accuracy.
+    *
+    * In the previous implementation the values were all in the range 0 < value
+    * < 1, so simple products are in the same range but may need up to 10
+    * decimal digits to preserve the original precision and avoid underflow.
+    * Because we are using a 32-bit signed representation we cannot match this;
+    * the best is a little over 9 decimal digits, less than 10.
+    *
+    * This range has now been extended to allow values up to 1.1, or 110,000 in
+    * fixed point.
     *
     * The approach used here is to preserve the maximum precision within the
     * signed representation.  Because the red-scale calculation above uses the
-    * difference between two products of values that must be in the range -1..+1
-    * it is sufficient to divide the product by 7; ceil(100,000/32767*2).  The
-    * factor is irrelevant in the calculation because it is applied to both
-    * numerator and denominator.
+    * difference between two products of values that must be in the range
+    * -1.1..+1.1 it is sufficient to divide the product by 8;
+    * ceil(121,000/32767*2).  The factor is irrelevant in the calculation
+    * because it is applied to both numerator and denominator.
     *
     * Note that the values of the differences of the products of the
     * chromaticities in the above equations tend to be small, for example for
@@ -1465,49 +1405,64 @@ png_XYZ_from_xy(png_XYZ *XYZ, const png_xy *xy)
     *  Adobe Wide Gamut RGB
     *    0.258728243040113 0.724682314948566 0.016589442011321
     */
-   /* By the argument, above overflow should be impossible here. The return
-    * value of 2 indicates an internal error to the caller.
-    */
-   if (png_muldiv(&left, xy->greenx-xy->bluex, xy->redy - xy->bluey, 7) == 0)
-      return 1;
-   if (png_muldiv(&right, xy->greeny-xy->bluey, xy->redx - xy->bluex, 7) == 0)
-      return 1;
-   denominator = left - right;
+   {
+      int error = 0;
 
-   /* Now find the red numerator. */
-   if (png_muldiv(&left, xy->greenx-xy->bluex, xy->whitey-xy->bluey, 7) == 0)
-      return 1;
-   if (png_muldiv(&right, xy->greeny-xy->bluey, xy->whitex-xy->bluex, 7) == 0)
-      return 1;
+      /* By the argument above overflow should be impossible here, however the
+       * code now simply returns a failure code.  The xy subtracts in the
+       * arguments to png_muldiv are *not* checked for overflow because the
+       * checks at the start guarantee they are in the range 0..110000 and
+       * png_fixed_point is a 32-bit signed number.
+       */
+      if (png_muldiv(&left, xy->greenx-xy->bluex, xy->redy - xy->bluey, 8) == 0)
+         return 1;
+      if (png_muldiv(&right, xy->greeny-xy->bluey, xy->redx - xy->bluex, 8) ==
+            0)
+         return 1;
+      denominator = png_fp_sub(left, right, &error);
+      if (error) return 1;
 
-   /* Overflow is possible here and it indicates an extreme set of PNG cHRM
-    * chunk values.  This calculation actually returns the reciprocal of the
-    * scale value because this allows us to delay the multiplication of white-y
-    * into the denominator, which tends to produce a small number.
-    */
-   if (png_muldiv(&red_inverse, xy->whitey, denominator, left-right) == 0 ||
-       red_inverse <= xy->whitey /* r+g+b scales = white scale */)
-      return 1;
+      /* Now find the red numerator. */
+      if (png_muldiv(&left, xy->greenx-xy->bluex, xy->whitey-xy->bluey, 8) == 0)
+         return 1;
+      if (png_muldiv(&right, xy->greeny-xy->bluey, xy->whitex-xy->bluex, 8) ==
+            0)
+         return 1;
 
-   /* Similarly for green_inverse: */
-   if (png_muldiv(&left, xy->redy-xy->bluey, xy->whitex-xy->bluex, 7) == 0)
-      return 1;
-   if (png_muldiv(&right, xy->redx-xy->bluex, xy->whitey-xy->bluey, 7) == 0)
-      return 1;
-   if (png_muldiv(&green_inverse, xy->whitey, denominator, left-right) == 0 ||
-       green_inverse <= xy->whitey)
-      return 1;
+      /* Overflow is possible here and it indicates an extreme set of PNG cHRM
+       * chunk values.  This calculation actually returns the reciprocal of the
+       * scale value because this allows us to delay the multiplication of
+       * white-y into the denominator, which tends to produce a small number.
+       */
+      if (png_muldiv(&red_inverse, xy->whitey, denominator,
+                     png_fp_sub(left, right, &error)) == 0 || error ||
+          red_inverse <= xy->whitey /* r+g+b scales = white scale */)
+         return 1;
 
-   /* And the blue scale, the checks above guarantee this can't overflow but it
-    * can still produce 0 for extreme cHRM values.
-    */
-   blue_scale = png_reciprocal(xy->whitey) - png_reciprocal(red_inverse) -
-       png_reciprocal(green_inverse);
-   if (blue_scale <= 0)
-      return 1;
+      /* Similarly for green_inverse: */
+      if (png_muldiv(&left, xy->redy-xy->bluey, xy->whitex-xy->bluex, 8) == 0)
+         return 1;
+      if (png_muldiv(&right, xy->redx-xy->bluex, xy->whitey-xy->bluey, 8) == 0)
+         return 1;
+      if (png_muldiv(&green_inverse, xy->whitey, denominator,
+                     png_fp_sub(left, right, &error)) == 0 || error ||
+          green_inverse <= xy->whitey)
+         return 1;
 
+      /* And the blue scale, the checks above guarantee this can't overflow but
+       * it can still produce 0 for extreme cHRM values.
+       */
+      blue_scale = png_fp_sub(png_fp_sub(png_reciprocal(xy->whitey),
+                                         png_reciprocal(red_inverse), &error),
+                              png_reciprocal(green_inverse), &error);
+      if (error || blue_scale <= 0)
+         return 1;
+   }
 
-   /* And fill in the png_XYZ: */
+   /* And fill in the png_XYZ.  Again the subtracts are safe because of the
+    * checks on the xy values at the start (the subtracts just calculate the
+    * corresponding z values.)
+    */
    if (png_muldiv(&XYZ->red_X, xy->redx, PNG_FP_1, red_inverse) == 0)
       return 1;
    if (png_muldiv(&XYZ->red_Y, xy->redy, PNG_FP_1, red_inverse) == 0)
@@ -1534,239 +1489,9 @@ png_XYZ_from_xy(png_XYZ *XYZ, const png_xy *xy)
 
    return 0; /*success*/
 }
+#endif /* COLORSPACE */
 
-static int
-png_XYZ_normalize(png_XYZ *XYZ)
-{
-   png_int_32 Y, Ytemp;
-
-   /* Normalize by scaling so the sum of the end-point Y values is PNG_FP_1. */
-   Ytemp = XYZ->red_Y;
-   if (png_safe_add(&Ytemp, XYZ->green_Y, XYZ->blue_Y))
-      return 1;
-
-   Y = Ytemp;
-
-   if (Y != PNG_FP_1)
-   {
-      if (png_muldiv(&XYZ->red_X, XYZ->red_X, PNG_FP_1, Y) == 0)
-         return 1;
-      if (png_muldiv(&XYZ->red_Y, XYZ->red_Y, PNG_FP_1, Y) == 0)
-         return 1;
-      if (png_muldiv(&XYZ->red_Z, XYZ->red_Z, PNG_FP_1, Y) == 0)
-         return 1;
-
-      if (png_muldiv(&XYZ->green_X, XYZ->green_X, PNG_FP_1, Y) == 0)
-         return 1;
-      if (png_muldiv(&XYZ->green_Y, XYZ->green_Y, PNG_FP_1, Y) == 0)
-         return 1;
-      if (png_muldiv(&XYZ->green_Z, XYZ->green_Z, PNG_FP_1, Y) == 0)
-         return 1;
-
-      if (png_muldiv(&XYZ->blue_X, XYZ->blue_X, PNG_FP_1, Y) == 0)
-         return 1;
-      if (png_muldiv(&XYZ->blue_Y, XYZ->blue_Y, PNG_FP_1, Y) == 0)
-         return 1;
-      if (png_muldiv(&XYZ->blue_Z, XYZ->blue_Z, PNG_FP_1, Y) == 0)
-         return 1;
-   }
-
-   return 0;
-}
-
-static int
-png_colorspace_endpoints_match(const png_xy *xy1, const png_xy *xy2, int delta)
-{
-   /* Allow an error of +/-0.01 (absolute value) on each chromaticity */
-   if (PNG_OUT_OF_RANGE(xy1->whitex, xy2->whitex,delta) ||
-       PNG_OUT_OF_RANGE(xy1->whitey, xy2->whitey,delta) ||
-       PNG_OUT_OF_RANGE(xy1->redx,   xy2->redx,  delta) ||
-       PNG_OUT_OF_RANGE(xy1->redy,   xy2->redy,  delta) ||
-       PNG_OUT_OF_RANGE(xy1->greenx, xy2->greenx,delta) ||
-       PNG_OUT_OF_RANGE(xy1->greeny, xy2->greeny,delta) ||
-       PNG_OUT_OF_RANGE(xy1->bluex,  xy2->bluex, delta) ||
-       PNG_OUT_OF_RANGE(xy1->bluey,  xy2->bluey, delta))
-      return 0;
-   return 1;
-}
-
-/* Added in libpng-1.6.0, a different check for the validity of a set of cHRM
- * chunk chromaticities.  Earlier checks used to simply look for the overflow
- * condition (where the determinant of the matrix to solve for XYZ ends up zero
- * because the chromaticity values are not all distinct.)  Despite this it is
- * theoretically possible to produce chromaticities that are apparently valid
- * but that rapidly degrade to invalid, potentially crashing, sets because of
- * arithmetic inaccuracies when calculations are performed on them.  The new
- * check is to round-trip xy -> XYZ -> xy and then check that the result is
- * within a small percentage of the original.
- */
-static int
-png_colorspace_check_xy(png_XYZ *XYZ, const png_xy *xy)
-{
-   int result;
-   png_xy xy_test;
-
-   /* As a side-effect this routine also returns the XYZ endpoints. */
-   result = png_XYZ_from_xy(XYZ, xy);
-   if (result != 0)
-      return result;
-
-   result = png_xy_from_XYZ(&xy_test, XYZ);
-   if (result != 0)
-      return result;
-
-   if (png_colorspace_endpoints_match(xy, &xy_test,
-       5/*actually, the math is pretty accurate*/) != 0)
-      return 0;
-
-   /* Too much slip */
-   return 1;
-}
-
-/* This is the check going the other way.  The XYZ is modified to normalize it
- * (another side-effect) and the xy chromaticities are returned.
- */
-static int
-png_colorspace_check_XYZ(png_xy *xy, png_XYZ *XYZ)
-{
-   int result;
-   png_XYZ XYZtemp;
-
-   result = png_XYZ_normalize(XYZ);
-   if (result != 0)
-      return result;
-
-   result = png_xy_from_XYZ(xy, XYZ);
-   if (result != 0)
-      return result;
-
-   XYZtemp = *XYZ;
-   return png_colorspace_check_xy(&XYZtemp, xy);
-}
-
-/* Used to check for an endpoint match against sRGB */
-static const png_xy sRGB_xy = /* From ITU-R BT.709-3 */
-{
-   /* color      x       y */
-   /* red   */ 64000, 33000,
-   /* green */ 30000, 60000,
-   /* blue  */ 15000,  6000,
-   /* white */ 31270, 32900
-};
-
-static int
-png_colorspace_set_xy_and_XYZ(png_const_structrp png_ptr,
-    png_colorspacerp colorspace, const png_xy *xy, const png_XYZ *XYZ,
-    int preferred)
-{
-   if ((colorspace->flags & PNG_COLORSPACE_INVALID) != 0)
-      return 0;
-
-   /* The consistency check is performed on the chromaticities; this factors out
-    * variations because of the normalization (or not) of the end point Y
-    * values.
-    */
-   if (preferred < 2 &&
-       (colorspace->flags & PNG_COLORSPACE_HAVE_ENDPOINTS) != 0)
-   {
-      /* The end points must be reasonably close to any we already have.  The
-       * following allows an error of up to +/-.001
-       */
-      if (png_colorspace_endpoints_match(xy, &colorspace->end_points_xy,
-          100) == 0)
-      {
-         colorspace->flags |= PNG_COLORSPACE_INVALID;
-         png_benign_error(png_ptr, "inconsistent chromaticities");
-         return 0; /* failed */
-      }
-
-      /* Only overwrite with preferred values */
-      if (preferred == 0)
-         return 1; /* ok, but no change */
-   }
-
-   colorspace->end_points_xy = *xy;
-   colorspace->end_points_XYZ = *XYZ;
-   colorspace->flags |= PNG_COLORSPACE_HAVE_ENDPOINTS;
-
-   /* The end points are normally quoted to two decimal digits, so allow +/-0.01
-    * on this test.
-    */
-   if (png_colorspace_endpoints_match(xy, &sRGB_xy, 1000) != 0)
-      colorspace->flags |= PNG_COLORSPACE_ENDPOINTS_MATCH_sRGB;
-
-   else
-      colorspace->flags &= PNG_COLORSPACE_CANCEL(
-         PNG_COLORSPACE_ENDPOINTS_MATCH_sRGB);
-
-   return 2; /* ok and changed */
-}
-
-int /* PRIVATE */
-png_colorspace_set_chromaticities(png_const_structrp png_ptr,
-    png_colorspacerp colorspace, const png_xy *xy, int preferred)
-{
-   /* We must check the end points to ensure they are reasonable - in the past
-    * color management systems have crashed as a result of getting bogus
-    * colorant values, while this isn't the fault of libpng it is the
-    * responsibility of libpng because PNG carries the bomb and libpng is in a
-    * position to protect against it.
-    */
-   png_XYZ XYZ;
-
-   switch (png_colorspace_check_xy(&XYZ, xy))
-   {
-      case 0: /* success */
-         return png_colorspace_set_xy_and_XYZ(png_ptr, colorspace, xy, &XYZ,
-             preferred);
-
-      case 1:
-         /* We can't invert the chromaticities so we can't produce value XYZ
-          * values.  Likely as not a color management system will fail too.
-          */
-         colorspace->flags |= PNG_COLORSPACE_INVALID;
-         png_benign_error(png_ptr, "invalid chromaticities");
-         break;
-
-      default:
-         /* libpng is broken; this should be a warning but if it happens we
-          * want error reports so for the moment it is an error.
-          */
-         colorspace->flags |= PNG_COLORSPACE_INVALID;
-         png_error(png_ptr, "internal error checking chromaticities");
-   }
-
-   return 0; /* failed */
-}
-
-int /* PRIVATE */
-png_colorspace_set_endpoints(png_const_structrp png_ptr,
-    png_colorspacerp colorspace, const png_XYZ *XYZ_in, int preferred)
-{
-   png_XYZ XYZ = *XYZ_in;
-   png_xy xy;
-
-   switch (png_colorspace_check_XYZ(&xy, &XYZ))
-   {
-      case 0:
-         return png_colorspace_set_xy_and_XYZ(png_ptr, colorspace, &xy, &XYZ,
-             preferred);
-
-      case 1:
-         /* End points are invalid. */
-         colorspace->flags |= PNG_COLORSPACE_INVALID;
-         png_benign_error(png_ptr, "invalid end points");
-         break;
-
-      default:
-         colorspace->flags |= PNG_COLORSPACE_INVALID;
-         png_error(png_ptr, "internal error checking chromaticities");
-   }
-
-   return 0; /* failed */
-}
-
-#if defined(PNG_sRGB_SUPPORTED) || defined(PNG_iCCP_SUPPORTED)
+#ifdef PNG_iCCP_SUPPORTED
 /* Error message generation */
 static char
 png_icc_tag_char(png_uint_32 byte)
@@ -1806,15 +1531,12 @@ is_ICC_signature(png_alloc_size_t it)
 }
 
 static int
-png_icc_profile_error(png_const_structrp png_ptr, png_colorspacerp colorspace,
-    png_const_charp name, png_alloc_size_t value, png_const_charp reason)
+png_icc_profile_error(png_const_structrp png_ptr, png_const_charp name,
+   png_alloc_size_t value, png_const_charp reason)
 {
    size_t pos;
    char message[196]; /* see below for calculation */
 
-   if (colorspace != NULL)
-      colorspace->flags |= PNG_COLORSPACE_INVALID;
-
    pos = png_safecat(message, (sizeof message), 0, "profile '"); /* 9 chars */
    pos = png_safecat(message, pos+79, pos, name); /* Truncate to 79 chars */
    pos = png_safecat(message, (sizeof message), pos, "': "); /* +2 = 90 */
@@ -1841,109 +1563,13 @@ png_icc_profile_error(png_const_structrp png_ptr, png_colorspacerp colorspace,
    pos = png_safecat(message, (sizeof message), pos, reason);
    PNG_UNUSED(pos)
 
-   /* This is recoverable, but make it unconditionally an app_error on write to
-    * avoid writing invalid ICC profiles into PNG files (i.e., we handle them
-    * on read, with a warning, but on write unless the app turns off
-    * application errors the PNG won't be written.)
-    */
-   png_chunk_report(png_ptr, message,
-       (colorspace != NULL) ? PNG_CHUNK_ERROR : PNG_CHUNK_WRITE_ERROR);
+   png_chunk_benign_error(png_ptr, message);
 
    return 0;
 }
-#endif /* sRGB || iCCP */
-
-#ifdef PNG_sRGB_SUPPORTED
-int /* PRIVATE */
-png_colorspace_set_sRGB(png_const_structrp png_ptr, png_colorspacerp colorspace,
-    int intent)
-{
-   /* sRGB sets known gamma, end points and (from the chunk) intent. */
-   /* IMPORTANT: these are not necessarily the values found in an ICC profile
-    * because ICC profiles store values adapted to a D50 environment; it is
-    * expected that the ICC profile mediaWhitePointTag will be D50; see the
-    * checks and code elsewhere to understand this better.
-    *
-    * These XYZ values, which are accurate to 5dp, produce rgb to gray
-    * coefficients of (6968,23435,2366), which are reduced (because they add up
-    * to 32769 not 32768) to (6968,23434,2366).  These are the values that
-    * libpng has traditionally used (and are the best values given the 15bit
-    * algorithm used by the rgb to gray code.)
-    */
-   static const png_XYZ sRGB_XYZ = /* D65 XYZ (*not* the D50 adapted values!) */
-   {
-      /* color      X      Y      Z */
-      /* red   */ 41239, 21264,  1933,
-      /* green */ 35758, 71517, 11919,
-      /* blue  */ 18048,  7219, 95053
-   };
-
-   /* Do nothing if the colorspace is already invalidated. */
-   if ((colorspace->flags & PNG_COLORSPACE_INVALID) != 0)
-      return 0;
-
-   /* Check the intent, then check for existing settings.  It is valid for the
-    * PNG file to have cHRM or gAMA chunks along with sRGB, but the values must
-    * be consistent with the correct values.  If, however, this function is
-    * called below because an iCCP chunk matches sRGB then it is quite
-    * conceivable that an older app recorded incorrect gAMA and cHRM because of
-    * an incorrect calculation based on the values in the profile - this does
-    * *not* invalidate the profile (though it still produces an error, which can
-    * be ignored.)
-    */
-   if (intent < 0 || intent >= PNG_sRGB_INTENT_LAST)
-      return png_icc_profile_error(png_ptr, colorspace, "sRGB",
-          (png_alloc_size_t)intent, "invalid sRGB rendering intent");
-
-   if ((colorspace->flags & PNG_COLORSPACE_HAVE_INTENT) != 0 &&
-       colorspace->rendering_intent != intent)
-      return png_icc_profile_error(png_ptr, colorspace, "sRGB",
-         (png_alloc_size_t)intent, "inconsistent rendering intents");
-
-   if ((colorspace->flags & PNG_COLORSPACE_FROM_sRGB) != 0)
-   {
-      png_benign_error(png_ptr, "duplicate sRGB information ignored");
-      return 0;
-   }
-
-   /* If the standard sRGB cHRM chunk does not match the one from the PNG file
-    * warn but overwrite the value with the correct one.
-    */
-   if ((colorspace->flags & PNG_COLORSPACE_HAVE_ENDPOINTS) != 0 &&
-       !png_colorspace_endpoints_match(&sRGB_xy, &colorspace->end_points_xy,
-       100))
-      png_chunk_report(png_ptr, "cHRM chunk does not match sRGB",
-         PNG_CHUNK_ERROR);
-
-   /* This check is just done for the error reporting - the routine always
-    * returns true when the 'from' argument corresponds to sRGB (2).
-    */
-   (void)png_colorspace_check_gamma(png_ptr, colorspace, PNG_GAMMA_sRGB_INVERSE,
-       2/*from sRGB*/);
-
-   /* intent: bugs in GCC force 'int' to be used as the parameter type. */
-   colorspace->rendering_intent = (png_uint_16)intent;
-   colorspace->flags |= PNG_COLORSPACE_HAVE_INTENT;
-
-   /* endpoints */
-   colorspace->end_points_xy = sRGB_xy;
-   colorspace->end_points_XYZ = sRGB_XYZ;
-   colorspace->flags |=
-      (PNG_COLORSPACE_HAVE_ENDPOINTS|PNG_COLORSPACE_ENDPOINTS_MATCH_sRGB);
-
-   /* gamma */
-   colorspace->gamma = PNG_GAMMA_sRGB_INVERSE;
-   colorspace->flags |= PNG_COLORSPACE_HAVE_GAMMA;
-
-   /* Finally record that we have an sRGB profile */
-   colorspace->flags |=
-      (PNG_COLORSPACE_MATCHES_sRGB|PNG_COLORSPACE_FROM_sRGB);
-
-   return 1; /* set */
-}
-#endif /* sRGB */
+#endif /* iCCP */
 
-#ifdef PNG_iCCP_SUPPORTED
+#ifdef PNG_READ_iCCP_SUPPORTED
 /* Encoded value of D50 as an ICC XYZNumber.  From the ICC 2010 spec the value
  * is XYZ(0.9642,1.0,0.8249), which scales to:
  *
@@ -1953,21 +1579,19 @@ static const png_byte D50_nCIEXYZ[12] =
    { 0x00, 0x00, 0xf6, 0xd6, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xd3, 0x2d };
 
 static int /* bool */
-icc_check_length(png_const_structrp png_ptr, png_colorspacerp colorspace,
-    png_const_charp name, png_uint_32 profile_length)
+icc_check_length(png_const_structrp png_ptr, png_const_charp name,
+   png_uint_32 profile_length)
 {
    if (profile_length < 132)
-      return png_icc_profile_error(png_ptr, colorspace, name, profile_length,
-          "too short");
+      return png_icc_profile_error(png_ptr, name, profile_length, "too short");
    return 1;
 }
 
-#ifdef PNG_READ_iCCP_SUPPORTED
 int /* PRIVATE */
-png_icc_check_length(png_const_structrp png_ptr, png_colorspacerp colorspace,
-    png_const_charp name, png_uint_32 profile_length)
+png_icc_check_length(png_const_structrp png_ptr, png_const_charp name,
+   png_uint_32 profile_length)
 {
-   if (!icc_check_length(png_ptr, colorspace, name, profile_length))
+   if (!icc_check_length(png_ptr, name, profile_length))
       return 0;
 
    /* This needs to be here because the 'normal' check is in
@@ -1976,30 +1600,17 @@ png_icc_check_length(png_const_structrp png_ptr, png_colorspacerp colorspace,
     * the caller supplies the profile buffer so libpng doesn't allocate it.  See
     * the call to icc_check_length below (the write case).
     */
-#  ifdef PNG_SET_USER_LIMITS_SUPPORTED
-      else if (png_ptr->user_chunk_malloc_max > 0 &&
-               png_ptr->user_chunk_malloc_max < profile_length)
-         return png_icc_profile_error(png_ptr, colorspace, name, profile_length,
-             "exceeds application limits");
-#  elif PNG_USER_CHUNK_MALLOC_MAX > 0
-      else if (PNG_USER_CHUNK_MALLOC_MAX < profile_length)
-         return png_icc_profile_error(png_ptr, colorspace, name, profile_length,
-             "exceeds libpng limits");
-#  else /* !SET_USER_LIMITS */
-      /* This will get compiled out on all 32-bit and better systems. */
-      else if (PNG_SIZE_MAX < profile_length)
-         return png_icc_profile_error(png_ptr, colorspace, name, profile_length,
-             "exceeds system limits");
-#  endif /* !SET_USER_LIMITS */
+   if (profile_length > png_chunk_max(png_ptr))
+      return png_icc_profile_error(png_ptr, name, profile_length,
+            "profile too long");
 
    return 1;
 }
-#endif /* READ_iCCP */
 
 int /* PRIVATE */
-png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
-    png_const_charp name, png_uint_32 profile_length,
-    png_const_bytep profile/* first 132 bytes only */, int color_type)
+png_icc_check_header(png_const_structrp png_ptr, png_const_charp name,
+   png_uint_32 profile_length,
+   png_const_bytep profile/* first 132 bytes only */, int color_type)
 {
    png_uint_32 temp;
 
@@ -2010,18 +1621,18 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
     */
    temp = png_get_uint_32(profile);
    if (temp != profile_length)
-      return png_icc_profile_error(png_ptr, colorspace, name, temp,
+      return png_icc_profile_error(png_ptr, name, temp,
           "length does not match profile");
 
    temp = (png_uint_32) (*(profile+8));
    if (temp > 3 && (profile_length & 3))
-      return png_icc_profile_error(png_ptr, colorspace, name, profile_length,
+      return png_icc_profile_error(png_ptr, name, profile_length,
           "invalid length");
 
    temp = png_get_uint_32(profile+128); /* tag count: 12 bytes/tag */
    if (temp > 357913930 || /* (2^32-4-132)/12: maximum possible tag count */
       profile_length < 132+12*temp) /* truncated tag table */
-      return png_icc_profile_error(png_ptr, colorspace, name, temp,
+      return png_icc_profile_error(png_ptr, name, temp,
           "tag count too large");
 
    /* The 'intent' must be valid or we can't store it, ICC limits the intent to
@@ -2029,14 +1640,14 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
     */
    temp = png_get_uint_32(profile+64);
    if (temp >= 0xffff) /* The ICC limit */
-      return png_icc_profile_error(png_ptr, colorspace, name, temp,
+      return png_icc_profile_error(png_ptr, name, temp,
           "invalid rendering intent");
 
    /* This is just a warning because the profile may be valid in future
     * versions.
     */
    if (temp >= PNG_sRGB_INTENT_LAST)
-      (void)png_icc_profile_error(png_ptr, NULL, name, temp,
+      (void)png_icc_profile_error(png_ptr, name, temp,
           "intent outside defined range");
 
    /* At this point the tag table can't be checked because it hasn't necessarily
@@ -2053,7 +1664,7 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
     */
    temp = png_get_uint_32(profile+36); /* signature 'ascp' */
    if (temp != 0x61637370)
-      return png_icc_profile_error(png_ptr, colorspace, name, temp,
+      return png_icc_profile_error(png_ptr, name, temp,
           "invalid signature");
 
    /* Currently the PCS illuminant/adopted white point (the computational
@@ -2064,7 +1675,7 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
     * following is just a warning.
     */
    if (memcmp(profile+68, D50_nCIEXYZ, 12) != 0)
-      (void)png_icc_profile_error(png_ptr, NULL, name, 0/*no tag value*/,
+      (void)png_icc_profile_error(png_ptr, name, 0/*no tag value*/,
           "PCS illuminant is not D50");
 
    /* The PNG spec requires this:
@@ -2092,18 +1703,18 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
    {
       case 0x52474220: /* 'RGB ' */
          if ((color_type & PNG_COLOR_MASK_COLOR) == 0)
-            return png_icc_profile_error(png_ptr, colorspace, name, temp,
+            return png_icc_profile_error(png_ptr, name, temp,
                 "RGB color space not permitted on grayscale PNG");
          break;
 
       case 0x47524159: /* 'GRAY' */
          if ((color_type & PNG_COLOR_MASK_COLOR) != 0)
-            return png_icc_profile_error(png_ptr, colorspace, name, temp,
+            return png_icc_profile_error(png_ptr, name, temp,
                 "Gray color space not permitted on RGB PNG");
          break;
 
       default:
-         return png_icc_profile_error(png_ptr, colorspace, name, temp,
+         return png_icc_profile_error(png_ptr, name, temp,
              "invalid ICC profile color space");
    }
 
@@ -2128,7 +1739,7 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
 
       case 0x61627374: /* 'abst' */
          /* May not be embedded in an image */
-         return png_icc_profile_error(png_ptr, colorspace, name, temp,
+         return png_icc_profile_error(png_ptr, name, temp,
              "invalid embedded Abstract ICC profile");
 
       case 0x6c696e6b: /* 'link' */
@@ -2138,7 +1749,7 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
           * therefore a DeviceLink profile should not be found embedded in a
           * PNG.
           */
-         return png_icc_profile_error(png_ptr, colorspace, name, temp,
+         return png_icc_profile_error(png_ptr, name, temp,
              "unexpected DeviceLink ICC profile class");
 
       case 0x6e6d636c: /* 'nmcl' */
@@ -2146,7 +1757,7 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
           * contain an AToB0 tag that is open to misinterpretation.  Almost
           * certainly it will fail the tests below.
           */
-         (void)png_icc_profile_error(png_ptr, NULL, name, temp,
+         (void)png_icc_profile_error(png_ptr, name, temp,
              "unexpected NamedColor ICC profile class");
          break;
 
@@ -2156,7 +1767,7 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
           * tag content to ensure they are backward compatible with one of the
           * understood profiles.
           */
-         (void)png_icc_profile_error(png_ptr, NULL, name, temp,
+         (void)png_icc_profile_error(png_ptr, name, temp,
              "unrecognized ICC profile class");
          break;
    }
@@ -2172,7 +1783,7 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
          break;
 
       default:
-         return png_icc_profile_error(png_ptr, colorspace, name, temp,
+         return png_icc_profile_error(png_ptr, name, temp,
              "unexpected ICC PCS encoding");
    }
 
@@ -2180,9 +1791,9 @@ png_icc_check_header(png_const_structrp png_ptr, png_colorspacerp colorspace,
 }
 
 int /* PRIVATE */
-png_icc_check_tag_table(png_const_structrp png_ptr, png_colorspacerp colorspace,
-    png_const_charp name, png_uint_32 profile_length,
-    png_const_bytep profile /* header plus whole tag table */)
+png_icc_check_tag_table(png_const_structrp png_ptr, png_const_charp name,
+   png_uint_32 profile_length,
+   png_const_bytep profile /* header plus whole tag table */)
 {
    png_uint_32 tag_count = png_get_uint_32(profile+128);
    png_uint_32 itag;
@@ -2208,7 +1819,7 @@ png_icc_check_tag_table(png_const_structrp png_ptr, png_colorspacerp colorspace,
        * profile.
        */
       if (tag_start > profile_length || tag_length > profile_length - tag_start)
-         return png_icc_profile_error(png_ptr, colorspace, name, tag_id,
+         return png_icc_profile_error(png_ptr, name, tag_id,
              "ICC profile tag outside profile");
 
       if ((tag_start & 3) != 0)
@@ -2217,307 +1828,132 @@ png_icc_check_tag_table(png_const_structrp png_ptr, png_colorspacerp colorspace,
           * only a warning here because libpng does not care about the
           * alignment.
           */
-         (void)png_icc_profile_error(png_ptr, NULL, name, tag_id,
+         (void)png_icc_profile_error(png_ptr, name, tag_id,
              "ICC profile tag start not a multiple of 4");
       }
    }
 
    return 1; /* success, maybe with warnings */
 }
+#endif /* READ_iCCP */
 
-#ifdef PNG_sRGB_SUPPORTED
-#if PNG_sRGB_PROFILE_CHECKS >= 0
-/* Information about the known ICC sRGB profiles */
-static const struct
-{
-   png_uint_32 adler, crc, length;
-   png_uint_32 md5[4];
-   png_byte    have_md5;
-   png_byte    is_broken;
-   png_uint_16 intent;
-
-#  define PNG_MD5(a,b,c,d) { a, b, c, d }, (a!=0)||(b!=0)||(c!=0)||(d!=0)
-#  define PNG_ICC_CHECKSUM(adler, crc, md5, intent, broke, date, length, fname)\
-      { adler, crc, length, md5, broke, intent },
-
-} png_sRGB_checks[] =
-{
-   /* This data comes from contrib/tools/checksum-icc run on downloads of
-    * all four ICC sRGB profiles from www.color.org.
-    */
-   /* adler32, crc32, MD5[4], intent, date, length, file-name */
-   PNG_ICC_CHECKSUM(0x0a3fd9f6, 0x3b8772b9,
-       PNG_MD5(0x29f83dde, 0xaff255ae, 0x7842fae4, 0xca83390d), 0, 0,
-       "2009/03/27 21:36:31", 3048, "sRGB_IEC61966-2-1_black_scaled.icc")
-
-   /* ICC sRGB v2 perceptual no black-compensation: */
-   PNG_ICC_CHECKSUM(0x4909e5e1, 0x427ebb21,
-       PNG_MD5(0xc95bd637, 0xe95d8a3b, 0x0df38f99, 0xc1320389), 1, 0,
-       "2009/03/27 21:37:45", 3052, "sRGB_IEC61966-2-1_no_black_scaling.icc")
-
-   PNG_ICC_CHECKSUM(0xfd2144a1, 0x306fd8ae,
-       PNG_MD5(0xfc663378, 0x37e2886b, 0xfd72e983, 0x8228f1b8), 0, 0,
-       "2009/08/10 17:28:01", 60988, "sRGB_v4_ICC_preference_displayclass.icc")
-
-   /* ICC sRGB v4 perceptual */
-   PNG_ICC_CHECKSUM(0x209c35d2, 0xbbef7812,
-       PNG_MD5(0x34562abf, 0x994ccd06, 0x6d2c5721, 0xd0d68c5d), 0, 0,
-       "2007/07/25 00:05:37", 60960, "sRGB_v4_ICC_preference.icc")
-
-   /* The following profiles have no known MD5 checksum. If there is a match
-    * on the (empty) MD5 the other fields are used to attempt a match and
-    * a warning is produced.  The first two of these profiles have a 'cprt' tag
-    * which suggests that they were also made by Hewlett Packard.
-    */
-   PNG_ICC_CHECKSUM(0xa054d762, 0x5d5129ce,
-       PNG_MD5(0x00000000, 0x00000000, 0x00000000, 0x00000000), 1, 0,
-       "2004/07/21 18:57:42", 3024, "sRGB_IEC61966-2-1_noBPC.icc")
-
-   /* This is a 'mntr' (display) profile with a mediaWhitePointTag that does not
-    * match the D50 PCS illuminant in the header (it is in fact the D65 values,
-    * so the white point is recorded as the un-adapted value.)  The profiles
-    * below only differ in one byte - the intent - and are basically the same as
-    * the previous profile except for the mediaWhitePointTag error and a missing
-    * chromaticAdaptationTag.
-    */
-   PNG_ICC_CHECKSUM(0xf784f3fb, 0x182ea552,
-       PNG_MD5(0x00000000, 0x00000000, 0x00000000, 0x00000000), 0, 1/*broken*/,
-       "1998/02/09 06:49:00", 3144, "HP-Microsoft sRGB v2 perceptual")
-
-   PNG_ICC_CHECKSUM(0x0398f3fc, 0xf29e526d,
-       PNG_MD5(0x00000000, 0x00000000, 0x00000000, 0x00000000), 1, 1/*broken*/,
-       "1998/02/09 06:49:00", 3144, "HP-Microsoft sRGB v2 media-relative")
-};
-
+#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
+#if (defined PNG_READ_mDCV_SUPPORTED) || (defined PNG_READ_cHRM_SUPPORTED)
 static int
-png_compare_ICC_profile_with_sRGB(png_const_structrp png_ptr,
-    png_const_bytep profile, uLong adler)
+have_chromaticities(png_const_structrp png_ptr)
 {
-   /* The quick check is to verify just the MD5 signature and trust the
-    * rest of the data.  Because the profile has already been verified for
-    * correctness this is safe.  png_colorspace_set_sRGB will check the 'intent'
-    * field too, so if the profile has been edited with an intent not defined
-    * by sRGB (but maybe defined by a later ICC specification) the read of
-    * the profile will fail at that point.
+   /* Handle new PNGv3 chunks and the precedence rules to determine whether
+    * png_struct::chromaticities must be processed.  Only required for RGB to
+    * gray.
+    *
+    * mDCV: this is the mastering colour space and it is independent of the
+    *       encoding so it needs to be used regardless of the encoded space.
+    *
+    * cICP: first in priority but not yet implemented - the chromaticities come
+    *       from the 'primaries'.
+    *
+    * iCCP: not supported by libpng (so ignored)
+    *
+    * sRGB: the defaults match sRGB
+    *
+    * cHRM: calculate the coefficients
     */
+#  ifdef PNG_READ_mDCV_SUPPORTED
+      if (png_has_chunk(png_ptr, mDCV))
+         return 1;
+#     define check_chromaticities 1
+#  endif /*mDCV*/
 
-   png_uint_32 length = 0;
-   png_uint_32 intent = 0x10000; /* invalid */
-#if PNG_sRGB_PROFILE_CHECKS > 1
-   uLong crc = 0; /* the value for 0 length data */
-#endif
-   unsigned int i;
-
-#ifdef PNG_SET_OPTION_SUPPORTED
-   /* First see if PNG_SKIP_sRGB_CHECK_PROFILE has been set to "on" */
-   if (((png_ptr->options >> PNG_SKIP_sRGB_CHECK_PROFILE) & 3) ==
-               PNG_OPTION_ON)
-      return 0;
-#endif
-
-   for (i=0; i < (sizeof png_sRGB_checks) / (sizeof png_sRGB_checks[0]); ++i)
-   {
-      if (png_get_uint_32(profile+84) == png_sRGB_checks[i].md5[0] &&
-         png_get_uint_32(profile+88) == png_sRGB_checks[i].md5[1] &&
-         png_get_uint_32(profile+92) == png_sRGB_checks[i].md5[2] &&
-         png_get_uint_32(profile+96) == png_sRGB_checks[i].md5[3])
-      {
-         /* This may be one of the old HP profiles without an MD5, in that
-          * case we can only use the length and Adler32 (note that these
-          * are not used by default if there is an MD5!)
-          */
-#        if PNG_sRGB_PROFILE_CHECKS == 0
-            if (png_sRGB_checks[i].have_md5 != 0)
-               return 1+png_sRGB_checks[i].is_broken;
-#        endif
-
-         /* Profile is unsigned or more checks have been configured in. */
-         if (length == 0)
-         {
-            length = png_get_uint_32(profile);
-            intent = png_get_uint_32(profile+64);
-         }
-
-         /* Length *and* intent must match */
-         if (length == (png_uint_32) png_sRGB_checks[i].length &&
-            intent == (png_uint_32) png_sRGB_checks[i].intent)
-         {
-            /* Now calculate the adler32 if not done already. */
-            if (adler == 0)
-            {
-               adler = adler32(0, NULL, 0);
-               adler = adler32(adler, profile, length);
-            }
-
-            if (adler == png_sRGB_checks[i].adler)
-            {
-               /* These basic checks suggest that the data has not been
-                * modified, but if the check level is more than 1 perform
-                * our own crc32 checksum on the data.
-                */
-#              if PNG_sRGB_PROFILE_CHECKS > 1
-                  if (crc == 0)
-                  {
-                     crc = crc32(0, NULL, 0);
-                     crc = crc32(crc, profile, length);
-                  }
-
-                  /* So this check must pass for the 'return' below to happen.
-                   */
-                  if (crc == png_sRGB_checks[i].crc)
-#              endif
-               {
-                  if (png_sRGB_checks[i].is_broken != 0)
-                  {
-                     /* These profiles are known to have bad data that may cause
-                      * problems if they are used, therefore attempt to
-                      * discourage their use, skip the 'have_md5' warning below,
-                      * which is made irrelevant by this error.
-                      */
-                     png_chunk_report(png_ptr, "known incorrect sRGB profile",
-                         PNG_CHUNK_ERROR);
-                  }
-
-                  /* Warn that this being done; this isn't even an error since
-                   * the profile is perfectly valid, but it would be nice if
-                   * people used the up-to-date ones.
-                   */
-                  else if (png_sRGB_checks[i].have_md5 == 0)
-                  {
-                     png_chunk_report(png_ptr,
-                         "out-of-date sRGB profile with no signature",
-                         PNG_CHUNK_WARNING);
-                  }
-
-                  return 1+png_sRGB_checks[i].is_broken;
-               }
-            }
+#  ifdef PNG_READ_sRGB_SUPPORTED
+      if (png_has_chunk(png_ptr, sRGB))
+         return 0;
+#  endif /*sRGB*/
 
-# if PNG_sRGB_PROFILE_CHECKS > 0
-         /* The signature matched, but the profile had been changed in some
-          * way.  This probably indicates a data error or uninformed hacking.
-          * Fall through to "no match".
-          */
-         png_chunk_report(png_ptr,
-             "Not recognizing known sRGB profile that has been edited",
-             PNG_CHUNK_WARNING);
-         break;
-# endif
-         }
-      }
-   }
+#  ifdef PNG_READ_cHRM_SUPPORTED
+      if (png_has_chunk(png_ptr, cHRM))
+         return 1;
+#     define check_chromaticities 1
+#  endif /*cHRM*/
 
-   return 0; /* no match */
+   return 0; /* sRGB defaults */
 }
+#endif /* READ_mDCV || READ_cHRM */
 
 void /* PRIVATE */
-png_icc_set_sRGB(png_const_structrp png_ptr,
-    png_colorspacerp colorspace, png_const_bytep profile, uLong adler)
+png_set_rgb_coefficients(png_structrp png_ptr)
 {
-   /* Is this profile one of the known ICC sRGB profiles?  If it is, just set
-    * the sRGB information.
+   /* Set the rgb_to_gray coefficients from the colorspace if available.  Note
+    * that '_set' means that png_rgb_to_gray was called **and** it successfully
+    * set up the coefficients.
     */
-   if (png_compare_ICC_profile_with_sRGB(png_ptr, profile, adler) != 0)
-      (void)png_colorspace_set_sRGB(png_ptr, colorspace,
-         (int)/*already checked*/png_get_uint_32(profile+64));
-}
-#endif /* PNG_sRGB_PROFILE_CHECKS >= 0 */
-#endif /* sRGB */
-
-int /* PRIVATE */
-png_colorspace_set_ICC(png_const_structrp png_ptr, png_colorspacerp colorspace,
-    png_const_charp name, png_uint_32 profile_length, png_const_bytep profile,
-    int color_type)
-{
-   if ((colorspace->flags & PNG_COLORSPACE_INVALID) != 0)
-      return 0;
-
-   if (icc_check_length(png_ptr, colorspace, name, profile_length) != 0 &&
-       png_icc_check_header(png_ptr, colorspace, name, profile_length, profile,
-           color_type) != 0 &&
-       png_icc_check_tag_table(png_ptr, colorspace, name, profile_length,
-           profile) != 0)
+   if (png_ptr->rgb_to_gray_coefficients_set == 0)
    {
-#     if defined(PNG_sRGB_SUPPORTED) && PNG_sRGB_PROFILE_CHECKS >= 0
-         /* If no sRGB support, don't try storing sRGB information */
-         png_icc_set_sRGB(png_ptr, colorspace, profile, 0);
-#     endif
-      return 1;
-   }
+#  if check_chromaticities
+      png_XYZ xyz;
 
-   /* Failure case */
-   return 0;
-}
-#endif /* iCCP */
-
-#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
-void /* PRIVATE */
-png_colorspace_set_rgb_coefficients(png_structrp png_ptr)
-{
-   /* Set the rgb_to_gray coefficients from the colorspace. */
-   if (png_ptr->rgb_to_gray_coefficients_set == 0 &&
-      (png_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_ENDPOINTS) != 0)
-   {
-      /* png_set_background has not been called, get the coefficients from the Y
-       * values of the colorspace colorants.
-       */
-      png_fixed_point r = png_ptr->colorspace.end_points_XYZ.red_Y;
-      png_fixed_point g = png_ptr->colorspace.end_points_XYZ.green_Y;
-      png_fixed_point b = png_ptr->colorspace.end_points_XYZ.blue_Y;
-      png_fixed_point total = r+g+b;
-
-      if (total > 0 &&
-         r >= 0 && png_muldiv(&r, r, 32768, total) && r >= 0 && r <= 32768 &&
-         g >= 0 && png_muldiv(&g, g, 32768, total) && g >= 0 && g <= 32768 &&
-         b >= 0 && png_muldiv(&b, b, 32768, total) && b >= 0 && b <= 32768 &&
-         r+g+b <= 32769)
+      if (have_chromaticities(png_ptr) &&
+          png_XYZ_from_xy(&xyz, &png_ptr->chromaticities) == 0)
       {
-         /* We allow 0 coefficients here.  r+g+b may be 32769 if two or
-          * all of the coefficients were rounded up.  Handle this by
-          * reducing the *largest* coefficient by 1; this matches the
-          * approach used for the default coefficients in pngrtran.c
+         /* png_set_rgb_to_gray has not set the coefficients, get them from the
+          * Y * values of the colorspace colorants.
           */
-         int add = 0;
+         png_fixed_point r = xyz.red_Y;
+         png_fixed_point g = xyz.green_Y;
+         png_fixed_point b = xyz.blue_Y;
+         png_fixed_point total = r+g+b;
+
+         if (total > 0 &&
+            r >= 0 && png_muldiv(&r, r, 32768, total) && r >= 0 && r <= 32768 &&
+            g >= 0 && png_muldiv(&g, g, 32768, total) && g >= 0 && g <= 32768 &&
+            b >= 0 && png_muldiv(&b, b, 32768, total) && b >= 0 && b <= 32768 &&
+            r+g+b <= 32769)
+         {
+            /* We allow 0 coefficients here.  r+g+b may be 32769 if two or
+             * all of the coefficients were rounded up.  Handle this by
+             * reducing the *largest* coefficient by 1; this matches the
+             * approach used for the default coefficients in pngrtran.c
+             */
+            int add = 0;
 
-         if (r+g+b > 32768)
-            add = -1;
-         else if (r+g+b < 32768)
-            add = 1;
+            if (r+g+b > 32768)
+               add = -1;
+            else if (r+g+b < 32768)
+               add = 1;
 
-         if (add != 0)
-         {
-            if (g >= r && g >= b)
-               g += add;
-            else if (r >= g && r >= b)
-               r += add;
-            else
-               b += add;
-         }
+            if (add != 0)
+            {
+               if (g >= r && g >= b)
+                  g += add;
+               else if (r >= g && r >= b)
+                  r += add;
+               else
+                  b += add;
+            }
 
-         /* Check for an internal error. */
-         if (r+g+b != 32768)
-            png_error(png_ptr,
-                "internal error handling cHRM coefficients");
+            /* Check for an internal error. */
+            if (r+g+b != 32768)
+               png_error(png_ptr,
+                   "internal error handling cHRM coefficients");
 
-         else
-         {
-            png_ptr->rgb_to_gray_red_coeff   = (png_uint_16)r;
-            png_ptr->rgb_to_gray_green_coeff = (png_uint_16)g;
+            else
+            {
+               png_ptr->rgb_to_gray_red_coeff   = (png_uint_16)r;
+               png_ptr->rgb_to_gray_green_coeff = (png_uint_16)g;
+            }
          }
       }
-
-      /* This is a png_error at present even though it could be ignored -
-       * it should never happen, but it is important that if it does, the
-       * bug is fixed.
-       */
       else
-         png_error(png_ptr, "internal error handling cHRM->XYZ");
+#  endif /* check_chromaticities */
+      {
+         /* Use the historical REC 709 (etc) values: */
+         png_ptr->rgb_to_gray_red_coeff   = 6968;
+         png_ptr->rgb_to_gray_green_coeff = 23434;
+         /* png_ptr->rgb_to_gray_blue_coeff  = 2366; */
+      }
    }
 }
 #endif /* READ_RGB_TO_GRAY */
 
-#endif /* COLORSPACE */
-
 void /* PRIVATE */
 png_check_IHDR(png_const_structrp png_ptr,
     png_uint_32 width, png_uint_32 height, int bit_depth,
@@ -3299,7 +2735,27 @@ png_fixed(png_const_structrp png_ptr, double fp, png_const_charp text)
 }
 #endif
 
-#if defined(PNG_GAMMA_SUPPORTED) || defined(PNG_COLORSPACE_SUPPORTED) ||\
+#if defined(PNG_FLOATING_POINT_SUPPORTED) && \
+   !defined(PNG_FIXED_POINT_MACRO_SUPPORTED) && \
+   (defined(PNG_cLLI_SUPPORTED) || defined(PNG_mDCV_SUPPORTED))
+png_uint_32
+png_fixed_ITU(png_const_structrp png_ptr, double fp, png_const_charp text)
+{
+   double r = floor(10000 * fp + .5);
+
+   if (r > 2147483647. || r < 0)
+      png_fixed_error(png_ptr, text);
+
+#  ifndef PNG_ERROR_TEXT_SUPPORTED
+   PNG_UNUSED(text)
+#  endif
+
+   return (png_uint_32)r;
+}
+#endif
+
+
+#if defined(PNG_READ_GAMMA_SUPPORTED) || defined(PNG_COLORSPACE_SUPPORTED) ||\
     defined(PNG_INCH_CONVERSIONS_SUPPORTED) || defined(PNG_READ_pHYs_SUPPORTED)
 /* muldiv functions */
 /* This API takes signed arguments and rounds the result to the nearest
@@ -3307,7 +2763,7 @@ png_fixed(png_const_structrp png_ptr, double fp, png_const_charp text)
  * the nearest .00001).  Overflow and divide by zero are signalled in
  * the result, a boolean - true on success, false on overflow.
  */
-int
+int /* PRIVATE */
 png_muldiv(png_fixed_point_p res, png_fixed_point a, png_int_32 times,
     png_int_32 divisor)
 {
@@ -3421,27 +2877,7 @@ png_muldiv(png_fixed_point_p res, png_fixed_point a, png_int_32 times,
 
    return 0;
 }
-#endif /* READ_GAMMA || INCH_CONVERSIONS */
-
-#if defined(PNG_READ_GAMMA_SUPPORTED) || defined(PNG_INCH_CONVERSIONS_SUPPORTED)
-/* The following is for when the caller doesn't much care about the
- * result.
- */
-png_fixed_point
-png_muldiv_warn(png_const_structrp png_ptr, png_fixed_point a, png_int_32 times,
-    png_int_32 divisor)
-{
-   png_fixed_point result;
-
-   if (png_muldiv(&result, a, times, divisor) != 0)
-      return result;
-
-   png_warning(png_ptr, "fixed point overflow ignored");
-   return 0;
-}
-#endif
 
-#ifdef PNG_GAMMA_SUPPORTED /* more fixed point functions for gamma */
 /* Calculate a reciprocal, return 0 on div-by-zero or overflow. */
 png_fixed_point
 png_reciprocal(png_fixed_point a)
@@ -3460,26 +2896,38 @@ png_reciprocal(png_fixed_point a)
 
    return 0; /* error/overflow */
 }
+#endif /* READ_GAMMA || COLORSPACE || INCH_CONVERSIONS || READ_pHYS */
 
+#ifdef PNG_READ_GAMMA_SUPPORTED
 /* This is the shared test on whether a gamma value is 'significant' - whether
  * it is worth doing gamma correction.
  */
 int /* PRIVATE */
 png_gamma_significant(png_fixed_point gamma_val)
 {
+   /* sRGB:       1/2.2 == 0.4545(45)
+    * AdobeRGB:   1/(2+51/256) ~= 0.45471 5dp
+    *
+    * So the correction from AdobeRGB to sRGB (output) is:
+    *
+    *    2.2/(2+51/256) == 1.00035524
+    *
+    * I.e. vanishly small (<4E-4) but still detectable in 16-bit linear (+/-
+    * 23).  Note that the Adobe choice seems to be something intended to give an
+    * exact number with 8 binary fractional digits - it is the closest to 2.2
+    * that is possible a base 2 .8p representation.
+    */
    return gamma_val < PNG_FP_1 - PNG_GAMMA_THRESHOLD_FIXED ||
        gamma_val > PNG_FP_1 + PNG_GAMMA_THRESHOLD_FIXED;
 }
-#endif
 
-#ifdef PNG_READ_GAMMA_SUPPORTED
-#ifdef PNG_16BIT_SUPPORTED
+#ifndef PNG_FLOATING_ARITHMETIC_SUPPORTED
 /* A local convenience routine. */
 static png_fixed_point
 png_product2(png_fixed_point a, png_fixed_point b)
 {
-   /* The required result is 1/a * 1/b; the following preserves accuracy. */
-#ifdef PNG_FLOATING_ARITHMETIC_SUPPORTED
+   /* The required result is a * b; the following preserves accuracy. */
+#ifdef PNG_FLOATING_ARITHMETIC_SUPPORTED /* Should now be unused */
    double r = a * 1E-5;
    r *= b;
    r = floor(r+.5);
@@ -3495,9 +2943,8 @@ png_product2(png_fixed_point a, png_fixed_point b)
 
    return 0; /* overflow */
 }
-#endif /* 16BIT */
+#endif /* FLOATING_ARITHMETIC */
 
-/* The inverse of the above. */
 png_fixed_point
 png_reciprocal2(png_fixed_point a, png_fixed_point b)
 {
@@ -4150,10 +3597,27 @@ png_destroy_gamma_table(png_structrp png_ptr)
  * tables, we don't make a full table if we are reducing to 8-bit in
  * the future.  Note also how the gamma_16 tables are segmented so that
  * we don't need to allocate > 64K chunks for a full 16-bit table.
+ *
+ * TODO: move this to pngrtran.c and make it static.  Better yet create
+ * pngcolor.c and put all the PNG_COLORSPACE stuff in there.
  */
+#if defined(PNG_READ_BACKGROUND_SUPPORTED) || \
+   defined(PNG_READ_ALPHA_MODE_SUPPORTED) || \
+   defined(PNG_READ_RGB_TO_GRAY_SUPPORTED)
+#  define GAMMA_TRANSFORMS 1 /* #ifdef CSE */
+#else
+#  define GAMMA_TRANSFORMS 0
+#endif
+
 void /* PRIVATE */
 png_build_gamma_table(png_structrp png_ptr, int bit_depth)
 {
+   png_fixed_point file_gamma, screen_gamma;
+   png_fixed_point correction;
+#  if GAMMA_TRANSFORMS
+      png_fixed_point file_to_linear, linear_to_screen;
+#  endif
+
    png_debug(1, "in png_build_gamma_table");
 
    /* Remove any existing table; this copes with multiple calls to
@@ -4168,27 +3632,44 @@ png_build_gamma_table(png_structrp png_ptr, int bit_depth)
       png_destroy_gamma_table(png_ptr);
    }
 
+   /* The following fields are set, finally, in png_init_read_transformations.
+    * If file_gamma is 0 (unset) nothing can be done otherwise if screen_gamma
+    * is 0 (unset) there is no gamma correction but to/from linear is possible.
+    */
+   file_gamma = png_ptr->file_gamma;
+   screen_gamma = png_ptr->screen_gamma;
+#  if GAMMA_TRANSFORMS
+      file_to_linear = png_reciprocal(file_gamma);
+#  endif
+
+   if (screen_gamma > 0)
+   {
+#     if GAMMA_TRANSFORMS
+         linear_to_screen = png_reciprocal(screen_gamma);
+#     endif
+      correction = png_reciprocal2(screen_gamma, file_gamma);
+   }
+   else /* screen gamma unknown */
+   {
+#     if GAMMA_TRANSFORMS
+         linear_to_screen = file_gamma;
+#     endif
+      correction = PNG_FP_1;
+   }
+
    if (bit_depth <= 8)
    {
-      png_build_8bit_table(png_ptr, &png_ptr->gamma_table,
-          png_ptr->screen_gamma > 0 ?
-          png_reciprocal2(png_ptr->colorspace.gamma,
-          png_ptr->screen_gamma) : PNG_FP_1);
+      png_build_8bit_table(png_ptr, &png_ptr->gamma_table, correction);
 
-#if defined(PNG_READ_BACKGROUND_SUPPORTED) || \
-   defined(PNG_READ_ALPHA_MODE_SUPPORTED) || \
-   defined(PNG_READ_RGB_TO_GRAY_SUPPORTED)
+#if GAMMA_TRANSFORMS
       if ((png_ptr->transformations & (PNG_COMPOSE | PNG_RGB_TO_GRAY)) != 0)
       {
-         png_build_8bit_table(png_ptr, &png_ptr->gamma_to_1,
-             png_reciprocal(png_ptr->colorspace.gamma));
+         png_build_8bit_table(png_ptr, &png_ptr->gamma_to_1, file_to_linear);
 
          png_build_8bit_table(png_ptr, &png_ptr->gamma_from_1,
-             png_ptr->screen_gamma > 0 ?
-             png_reciprocal(png_ptr->screen_gamma) :
-             png_ptr->colorspace.gamma/* Probably doing rgb_to_gray */);
+            linear_to_screen);
       }
-#endif /* READ_BACKGROUND || READ_ALPHA_MODE || RGB_TO_GRAY */
+#endif /* GAMMA_TRANSFORMS */
    }
 #ifdef PNG_16BIT_SUPPORTED
    else
@@ -4254,32 +3735,26 @@ png_build_gamma_table(png_structrp png_ptr, int bit_depth)
        * reduced to 8 bits.
        */
       if ((png_ptr->transformations & (PNG_16_TO_8 | PNG_SCALE_16_TO_8)) != 0)
-          png_build_16to8_table(png_ptr, &png_ptr->gamma_16_table, shift,
-          png_ptr->screen_gamma > 0 ? png_product2(png_ptr->colorspace.gamma,
-          png_ptr->screen_gamma) : PNG_FP_1);
-
+         png_build_16to8_table(png_ptr, &png_ptr->gamma_16_table, shift,
+            png_reciprocal(correction));
       else
-          png_build_16bit_table(png_ptr, &png_ptr->gamma_16_table, shift,
-          png_ptr->screen_gamma > 0 ? png_reciprocal2(png_ptr->colorspace.gamma,
-          png_ptr->screen_gamma) : PNG_FP_1);
+         png_build_16bit_table(png_ptr, &png_ptr->gamma_16_table, shift,
+            correction);
 
-#if defined(PNG_READ_BACKGROUND_SUPPORTED) || \
-   defined(PNG_READ_ALPHA_MODE_SUPPORTED) || \
-   defined(PNG_READ_RGB_TO_GRAY_SUPPORTED)
+#  if GAMMA_TRANSFORMS
       if ((png_ptr->transformations & (PNG_COMPOSE | PNG_RGB_TO_GRAY)) != 0)
       {
          png_build_16bit_table(png_ptr, &png_ptr->gamma_16_to_1, shift,
-             png_reciprocal(png_ptr->colorspace.gamma));
+            file_to_linear);
 
          /* Notice that the '16 from 1' table should be full precision, however
           * the lookup on this table still uses gamma_shift, so it can't be.
           * TODO: fix this.
           */
          png_build_16bit_table(png_ptr, &png_ptr->gamma_16_from_1, shift,
-             png_ptr->screen_gamma > 0 ? png_reciprocal(png_ptr->screen_gamma) :
-             png_ptr->colorspace.gamma/* Probably doing rgb_to_gray */);
+            linear_to_screen);
       }
-#endif /* READ_BACKGROUND || READ_ALPHA_MODE || RGB_TO_GRAY */
+#endif /* GAMMA_TRANSFORMS */
    }
 #endif /* 16BIT */
 }
diff --git a/png.h b/png.h
index 04a233f39..9b069e4ee 100644
--- a/png.h
+++ b/png.h
@@ -1,9 +1,8 @@
-
 /* png.h - header file for PNG reference library
  *
- * libpng version 1.6.44
+ * libpng version 1.6.47
  *
- * Copyright (c) 2018-2024 Cosmin Truta
+ * Copyright (c) 2018-2025 Cosmin Truta
  * Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson
  * Copyright (c) 1996-1997 Andreas Dilger
  * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
@@ -15,7 +14,7 @@
  *   libpng versions 0.89, June 1996, through 0.96, May 1997: Andreas Dilger
  *   libpng versions 0.97, January 1998, through 1.6.35, July 2018:
  *     Glenn Randers-Pehrson
- *   libpng versions 1.6.36, December 2018, through 1.6.44, September 2024:
+ *   libpng versions 1.6.36, December 2018, through 1.6.47, February 2025:
  *     Cosmin Truta
  *   See also "Contributing Authors", below.
  */
@@ -27,8 +26,8 @@
  * PNG Reference Library License version 2
  * ---------------------------------------
  *
- *  * Copyright (c) 1995-2024 The PNG Reference Library Authors.
- *  * Copyright (c) 2018-2024 Cosmin Truta.
+ *  * Copyright (c) 1995-2025 The PNG Reference Library Authors.
+ *  * Copyright (c) 2018-2025 Cosmin Truta.
  *  * Copyright (c) 2000-2002, 2004, 2006-2018 Glenn Randers-Pehrson.
  *  * Copyright (c) 1996-1997 Andreas Dilger.
  *  * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
@@ -239,7 +238,7 @@
  *    ...
  *    1.5.30                  15    10530  15.so.15.30[.0]
  *    ...
- *    1.6.44                  16    10644  16.so.16.44[.0]
+ *    1.6.47                  16    10647  16.so.16.47[.0]
  *
  *    Henceforth the source version will match the shared-library major and
  *    minor numbers; the shared-library major version number will be used for
@@ -275,7 +274,7 @@
  */
 
 /* Version information for png.h - this should match the version in png.c */
-#define PNG_LIBPNG_VER_STRING "1.6.44"
+#define PNG_LIBPNG_VER_STRING "1.6.47"
 #define PNG_HEADER_VERSION_STRING " libpng version " PNG_LIBPNG_VER_STRING "\n"
 
 /* The versions of shared library builds should stay in sync, going forward */
@@ -286,7 +285,7 @@
 /* These should match the first 3 components of PNG_LIBPNG_VER_STRING: */
 #define PNG_LIBPNG_VER_MAJOR   1
 #define PNG_LIBPNG_VER_MINOR   6
-#define PNG_LIBPNG_VER_RELEASE 44
+#define PNG_LIBPNG_VER_RELEASE 47
 
 /* This should be zero for a public release, or non-zero for a
  * development version.
@@ -317,7 +316,7 @@
  * From version 1.0.1 it is:
  * XXYYZZ, where XX=major, YY=minor, ZZ=release
  */
-#define PNG_LIBPNG_VER 10644 /* 1.6.44 */
+#define PNG_LIBPNG_VER 10647 /* 1.6.47 */
 
 /* Library configuration: these options cannot be changed after
  * the library has been built.
@@ -427,7 +426,7 @@ extern "C" {
 /* This triggers a compiler error in png.c, if png.c and png.h
  * do not agree upon the version number.
  */
-typedef char* png_libpng_version_1_6_44;
+typedef char* png_libpng_version_1_6_47;
 
 /* Basic control structions.  Read libpng-manual.txt or libpng.3 for more info.
  *
@@ -745,6 +744,21 @@ typedef png_unknown_chunk * * png_unknown_chunkpp;
 #define PNG_INFO_sCAL 0x4000U  /* ESR, 1.0.6 */
 #define PNG_INFO_IDAT 0x8000U  /* ESR, 1.0.6 */
 #define PNG_INFO_eXIf 0x10000U /* GR-P, 1.6.31 */
+#define PNG_INFO_cICP 0x20000U /* PNGv3: 1.6.45 */
+#define PNG_INFO_cLLI 0x40000U /* PNGv3: 1.6.45 */
+#define PNG_INFO_mDCV 0x80000U /* PNGv3: 1.6.45 */
+/* APNG: these chunks are stored as unknown, these flags are never set
+ * however they are provided as a convenience for implementors of APNG and
+ * avoids any merge conflicts.
+ *
+ * Private chunks: these chunk names violate the chunk name recommendations
+ * because the chunk definitions have no signature and because the private
+ * chunks with these names have been reserved.  Private definitions should
+ * avoid them.
+ */
+#define PNG_INFO_acTL 0x100000U /* PNGv3: 1.6.45: unknown */
+#define PNG_INFO_fcTL 0x200000U /* PNGv3: 1.6.45: unknown */
+#define PNG_INFO_fdAT 0x400000U /* PNGv3: 1.6.45: unknown */
 
 /* This is used for the transformation routines, as some of them
  * change these values for the row.  It also should enable using
@@ -1974,6 +1988,46 @@ PNG_FIXED_EXPORT(233, void, png_set_cHRM_XYZ_fixed, (png_const_structrp png_ptr,
     png_fixed_point int_blue_Z))
 #endif
 
+#ifdef PNG_cICP_SUPPORTED
+PNG_EXPORT(250, png_uint_32, png_get_cICP, (png_const_structrp png_ptr,
+    png_const_inforp info_ptr, png_bytep colour_primaries,
+    png_bytep transfer_function, png_bytep matrix_coefficients,
+    png_bytep video_full_range_flag));
+#endif
+
+#ifdef PNG_cICP_SUPPORTED
+PNG_EXPORT(251, void, png_set_cICP, (png_const_structrp png_ptr,
+    png_inforp info_ptr, png_byte colour_primaries,
+    png_byte transfer_function, png_byte matrix_coefficients,
+    png_byte video_full_range_flag));
+#endif
+
+#ifdef PNG_cLLI_SUPPORTED
+PNG_FP_EXPORT(252, png_uint_32, png_get_cLLI, (png_const_structrp png_ptr,
+         png_const_inforp info_ptr, double *maximum_content_light_level,
+         double *maximum_frame_average_light_level))
+PNG_FIXED_EXPORT(253, png_uint_32, png_get_cLLI_fixed,
+    (png_const_structrp png_ptr, png_const_inforp info_ptr,
+    /* The values below are in cd/m2 (nits) and are scaled by 10,000; not
+     * 100,000 as in the case of png_fixed_point.
+     */
+    png_uint_32p maximum_content_light_level_scaled_by_10000,
+    png_uint_32p maximum_frame_average_light_level_scaled_by_10000))
+#endif
+
+#ifdef PNG_cLLI_SUPPORTED
+PNG_FP_EXPORT(254, void, png_set_cLLI, (png_const_structrp png_ptr,
+         png_inforp info_ptr, double maximum_content_light_level,
+         double maximum_frame_average_light_level))
+PNG_FIXED_EXPORT(255, void, png_set_cLLI_fixed, (png_const_structrp png_ptr,
+    png_inforp info_ptr,
+    /* The values below are in cd/m2 (nits) and are scaled by 10,000; not
+     * 100,000 as in the case of png_fixed_point.
+     */
+    png_uint_32 maximum_content_light_level_scaled_by_10000,
+    png_uint_32 maximum_frame_average_light_level_scaled_by_10000))
+#endif
+
 #ifdef PNG_eXIf_SUPPORTED
 PNG_EXPORT(246, png_uint_32, png_get_eXIf, (png_const_structrp png_ptr,
     png_inforp info_ptr, png_bytep *exif));
@@ -2018,6 +2072,60 @@ PNG_EXPORT(144, void, png_set_IHDR, (png_const_structrp png_ptr,
     int color_type, int interlace_method, int compression_method,
     int filter_method));
 
+#ifdef PNG_mDCV_SUPPORTED
+PNG_FP_EXPORT(256, png_uint_32, png_get_mDCV, (png_const_structrp png_ptr,
+    png_const_inforp info_ptr,
+    /* The chromaticities of the mastering display.  As cHRM, but independent of
+     * the encoding endpoints in cHRM, or cICP, or iCCP.  These values will
+     * always be in the range 0 to 1.3107.
+     */
+    double *white_x, double *white_y, double *red_x, double *red_y,
+    double *green_x, double *green_y, double *blue_x, double *blue_y,
+    /* Mastering display luminance in cd/m2 (nits). */
+    double *mastering_display_maximum_luminance,
+    double *mastering_display_minimum_luminance))
+
+PNG_FIXED_EXPORT(257, png_uint_32, png_get_mDCV_fixed,
+    (png_const_structrp png_ptr, png_const_inforp info_ptr,
+    png_fixed_point *int_white_x, png_fixed_point *int_white_y,
+    png_fixed_point *int_red_x, png_fixed_point *int_red_y,
+    png_fixed_point *int_green_x, png_fixed_point *int_green_y,
+    png_fixed_point *int_blue_x, png_fixed_point *int_blue_y,
+    /* Mastering display luminance in cd/m2 (nits) multiplied (scaled) by
+     * 10,000.
+     */
+    png_uint_32p mastering_display_maximum_luminance_scaled_by_10000,
+    png_uint_32p mastering_display_minimum_luminance_scaled_by_10000))
+#endif
+
+#ifdef PNG_mDCV_SUPPORTED
+PNG_FP_EXPORT(258, void, png_set_mDCV, (png_const_structrp png_ptr,
+    png_inforp info_ptr,
+    /* The chromaticities of the mastering display.  As cHRM, but independent of
+     * the encoding endpoints in cHRM, or cICP, or iCCP.
+     */
+    double white_x, double white_y, double red_x, double red_y, double green_x,
+    double green_y, double blue_x, double blue_y,
+    /* Mastering display luminance in cd/m2 (nits). */
+    double mastering_display_maximum_luminance,
+    double mastering_display_minimum_luminance))
+
+PNG_FIXED_EXPORT(259, void, png_set_mDCV_fixed, (png_const_structrp png_ptr,
+    png_inforp info_ptr,
+    /* The admissible range of these values is not the full range of a PNG
+     * fixed point value.  Negative values cannot be encoded and the maximum
+     * value is about 1.3 */
+    png_fixed_point int_white_x, png_fixed_point int_white_y,
+    png_fixed_point int_red_x, png_fixed_point int_red_y,
+    png_fixed_point int_green_x, png_fixed_point int_green_y,
+    png_fixed_point int_blue_x, png_fixed_point int_blue_y,
+    /* These are PNG unsigned 4 byte values: 31-bit unsigned values.  The MSB
+     * must be zero.
+     */
+    png_uint_32 mastering_display_maximum_luminance_scaled_by_10000,
+    png_uint_32 mastering_display_minimum_luminance_scaled_by_10000))
+#endif
+
 #ifdef PNG_oFFs_SUPPORTED
 PNG_EXPORT(145, png_uint_32, png_get_oFFs, (png_const_structrp png_ptr,
    png_const_inforp info_ptr, png_int_32 *offset_x, png_int_32 *offset_y,
@@ -3238,7 +3346,7 @@ PNG_EXPORT(244, int, png_set_option, (png_structrp png_ptr, int option,
  * one to use is one more than this.)
  */
 #ifdef PNG_EXPORT_LAST_ORDINAL
-  PNG_EXPORT_LAST_ORDINAL(249);
+  PNG_EXPORT_LAST_ORDINAL(259);
 #endif
 
 #ifdef __cplusplus
diff --git a/pngconf.h b/pngconf.h
index 4a4b58ac8..42fa973c2 100644
--- a/pngconf.h
+++ b/pngconf.h
@@ -1,9 +1,8 @@
-
 /* pngconf.h - machine-configurable file for libpng
  *
- * libpng version 1.6.44
+ * libpng version 1.6.47
  *
- * Copyright (c) 2018-2024 Cosmin Truta
+ * Copyright (c) 2018-2025 Cosmin Truta
  * Copyright (c) 1998-2002,2004,2006-2016,2018 Glenn Randers-Pehrson
  * Copyright (c) 1996-1997 Andreas Dilger
  * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
diff --git a/pngdebug.h b/pngdebug.h
index 00d5a4569..ab9ea632d 100644
--- a/pngdebug.h
+++ b/pngdebug.h
@@ -1,4 +1,3 @@
-
 /* pngdebug.h - Debugging macros for libpng, also used in pngtest.c
  *
  * Copyright (c) 2018 Cosmin Truta
diff --git a/pngerror.c b/pngerror.c
index 1babf9f8d..275b188d0 100644
--- a/pngerror.c
+++ b/pngerror.c
@@ -1,4 +1,3 @@
-
 /* pngerror.c - stub functions for i/o and memory allocation
  *
  * Copyright (c) 2018-2024 Cosmin Truta
@@ -936,23 +935,37 @@ png_safe_warning(png_structp png_nonconst_ptr, png_const_charp warning_message)
 int /* PRIVATE */
 png_safe_execute(png_imagep image, int (*function)(png_voidp), png_voidp arg)
 {
-   png_voidp saved_error_buf = image->opaque->error_buf;
+   const png_voidp saved_error_buf = image->opaque->error_buf;
    jmp_buf safe_jmpbuf;
-   int result;
 
    /* Safely execute function(arg), with png_error returning back here. */
    if (setjmp(safe_jmpbuf) == 0)
    {
+      int result;
+
       image->opaque->error_buf = safe_jmpbuf;
       result = function(arg);
       image->opaque->error_buf = saved_error_buf;
-      return result;
+
+      if (result)
+         return 1; /* success */
    }
 
-   /* On png_error, return via longjmp, pop the jmpbuf, and free the image. */
+   /* The function failed either because of a caught png_error and a regular
+    * return of false above or because of an uncaught png_error from the
+    * function itself.  Ensure that the error_buf is always set back to the
+    * value saved above:
+    */
    image->opaque->error_buf = saved_error_buf;
-   png_image_free(image);
-   return 0;
+
+   /* On the final false return, when about to return control to the caller, the
+    * image is freed (png_image_free does this check but it is duplicated here
+    * for clarity:
+    */
+   if (saved_error_buf == NULL)
+      png_image_free(image);
+
+   return 0; /* failure */
 }
 #endif /* SIMPLIFIED READ || SIMPLIFIED_WRITE */
 #endif /* READ || WRITE */
diff --git a/pngget.c b/pngget.c
index 1084b268f..3623c5c7c 100644
--- a/pngget.c
+++ b/pngget.c
@@ -1,4 +1,3 @@
-
 /* pngget.c - retrieval of values from info struct
  *
  * Copyright (c) 2018-2024 Cosmin Truta
@@ -381,7 +380,13 @@ png_fixed_inches_from_microns(png_const_structrp png_ptr, png_int_32 microns)
     * Notice that this can overflow - a warning is output and 0 is
     * returned.
     */
-   return png_muldiv_warn(png_ptr, microns, 500, 127);
+   png_fixed_point result;
+
+   if (png_muldiv(&result, microns, 500, 127) != 0)
+      return result;
+
+   png_warning(png_ptr, "fixed point overflow ignored");
+   return 0;
 }
 
 png_fixed_point PNGAPI
@@ -391,7 +396,7 @@ png_get_x_offset_inches_fixed(png_const_structrp png_ptr,
    return png_fixed_inches_from_microns(png_ptr,
        png_get_x_offset_microns(png_ptr, info_ptr));
 }
-#endif
+#endif /* FIXED_POINT */
 
 #ifdef PNG_FIXED_POINT_SUPPORTED
 png_fixed_point PNGAPI
@@ -519,44 +524,31 @@ png_get_bKGD(png_const_structrp png_ptr, png_inforp info_ptr,
 #  ifdef PNG_FLOATING_POINT_SUPPORTED
 png_uint_32 PNGAPI
 png_get_cHRM(png_const_structrp png_ptr, png_const_inforp info_ptr,
-    double *white_x, double *white_y, double *red_x, double *red_y,
-    double *green_x, double *green_y, double *blue_x, double *blue_y)
+    double *whitex, double *whitey, double *redx, double *redy,
+    double *greenx, double *greeny, double *bluex, double *bluey)
 {
    png_debug1(1, "in %s retrieval function", "cHRM");
 
-   /* Quiet API change: this code used to only return the end points if a cHRM
-    * chunk was present, but the end points can also come from iCCP or sRGB
-    * chunks, so in 1.6.0 the png_get_ APIs return the end points regardless and
-    * the png_set_ APIs merely check that set end points are mutually
-    * consistent.
-    */
+   /* PNGv3: this just returns the values store from the cHRM, if any. */
    if (png_ptr != NULL && info_ptr != NULL &&
-      (info_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_ENDPOINTS) != 0)
+       (info_ptr->valid & PNG_INFO_cHRM) != 0)
    {
-      if (white_x != NULL)
-         *white_x = png_float(png_ptr,
-             info_ptr->colorspace.end_points_xy.whitex, "cHRM white X");
-      if (white_y != NULL)
-         *white_y = png_float(png_ptr,
-             info_ptr->colorspace.end_points_xy.whitey, "cHRM white Y");
-      if (red_x != NULL)
-         *red_x = png_float(png_ptr, info_ptr->colorspace.end_points_xy.redx,
-             "cHRM red X");
-      if (red_y != NULL)
-         *red_y = png_float(png_ptr, info_ptr->colorspace.end_points_xy.redy,
-             "cHRM red Y");
-      if (green_x != NULL)
-         *green_x = png_float(png_ptr,
-             info_ptr->colorspace.end_points_xy.greenx, "cHRM green X");
-      if (green_y != NULL)
-         *green_y = png_float(png_ptr,
-             info_ptr->colorspace.end_points_xy.greeny, "cHRM green Y");
-      if (blue_x != NULL)
-         *blue_x = png_float(png_ptr, info_ptr->colorspace.end_points_xy.bluex,
-             "cHRM blue X");
-      if (blue_y != NULL)
-         *blue_y = png_float(png_ptr, info_ptr->colorspace.end_points_xy.bluey,
-             "cHRM blue Y");
+      if (whitex != NULL)
+         *whitex = png_float(png_ptr, info_ptr->cHRM.whitex, "cHRM wx");
+      if (whitey != NULL)
+         *whitey = png_float(png_ptr, info_ptr->cHRM.whitey, "cHRM wy");
+      if (redx   != NULL)
+         *redx   = png_float(png_ptr, info_ptr->cHRM.redx,   "cHRM rx");
+      if (redy   != NULL)
+         *redy   = png_float(png_ptr, info_ptr->cHRM.redy,   "cHRM ry");
+      if (greenx != NULL)
+         *greenx = png_float(png_ptr, info_ptr->cHRM.greenx, "cHRM gx");
+      if (greeny != NULL)
+         *greeny = png_float(png_ptr, info_ptr->cHRM.greeny, "cHRM gy");
+      if (bluex  != NULL)
+         *bluex  = png_float(png_ptr, info_ptr->cHRM.bluex,  "cHRM bx");
+      if (bluey  != NULL)
+         *bluey  = png_float(png_ptr, info_ptr->cHRM.bluey,  "cHRM by");
       return PNG_INFO_cHRM;
    }
 
@@ -569,38 +561,31 @@ png_get_cHRM_XYZ(png_const_structrp png_ptr, png_const_inforp info_ptr,
     double *green_Y, double *green_Z, double *blue_X, double *blue_Y,
     double *blue_Z)
 {
+   png_XYZ XYZ;
    png_debug1(1, "in %s retrieval function", "cHRM_XYZ(float)");
 
    if (png_ptr != NULL && info_ptr != NULL &&
-       (info_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_ENDPOINTS) != 0)
+       (info_ptr->valid & PNG_INFO_cHRM) != 0 &&
+       png_XYZ_from_xy(&XYZ, &info_ptr->cHRM) == 0)
    {
       if (red_X != NULL)
-         *red_X = png_float(png_ptr, info_ptr->colorspace.end_points_XYZ.red_X,
-             "cHRM red X");
+         *red_X = png_float(png_ptr, XYZ.red_X, "cHRM red X");
       if (red_Y != NULL)
-         *red_Y = png_float(png_ptr, info_ptr->colorspace.end_points_XYZ.red_Y,
-             "cHRM red Y");
+         *red_Y = png_float(png_ptr, XYZ.red_Y, "cHRM red Y");
       if (red_Z != NULL)
-         *red_Z = png_float(png_ptr, info_ptr->colorspace.end_points_XYZ.red_Z,
-             "cHRM red Z");
+         *red_Z = png_float(png_ptr, XYZ.red_Z, "cHRM red Z");
       if (green_X != NULL)
-         *green_X = png_float(png_ptr,
-             info_ptr->colorspace.end_points_XYZ.green_X, "cHRM green X");
+         *green_X = png_float(png_ptr, XYZ.green_X, "cHRM green X");
       if (green_Y != NULL)
-         *green_Y = png_float(png_ptr,
-             info_ptr->colorspace.end_points_XYZ.green_Y, "cHRM green Y");
+         *green_Y = png_float(png_ptr, XYZ.green_Y, "cHRM green Y");
       if (green_Z != NULL)
-         *green_Z = png_float(png_ptr,
-             info_ptr->colorspace.end_points_XYZ.green_Z, "cHRM green Z");
+         *green_Z = png_float(png_ptr, XYZ.green_Z, "cHRM green Z");
       if (blue_X != NULL)
-         *blue_X = png_float(png_ptr,
-             info_ptr->colorspace.end_points_XYZ.blue_X, "cHRM blue X");
+         *blue_X = png_float(png_ptr, XYZ.blue_X, "cHRM blue X");
       if (blue_Y != NULL)
-         *blue_Y = png_float(png_ptr,
-             info_ptr->colorspace.end_points_XYZ.blue_Y, "cHRM blue Y");
+         *blue_Y = png_float(png_ptr, XYZ.blue_Y, "cHRM blue Y");
       if (blue_Z != NULL)
-         *blue_Z = png_float(png_ptr,
-             info_ptr->colorspace.end_points_XYZ.blue_Z, "cHRM blue Z");
+         *blue_Z = png_float(png_ptr, XYZ.blue_Z, "cHRM blue Z");
       return PNG_INFO_cHRM;
    }
 
@@ -617,29 +602,22 @@ png_get_cHRM_XYZ_fixed(png_const_structrp png_ptr, png_const_inforp info_ptr,
     png_fixed_point *int_blue_X, png_fixed_point *int_blue_Y,
     png_fixed_point *int_blue_Z)
 {
+   png_XYZ XYZ;
    png_debug1(1, "in %s retrieval function", "cHRM_XYZ");
 
    if (png_ptr != NULL && info_ptr != NULL &&
-      (info_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_ENDPOINTS) != 0)
+       (info_ptr->valid & PNG_INFO_cHRM) != 0U &&
+       png_XYZ_from_xy(&XYZ, &info_ptr->cHRM) == 0)
    {
-      if (int_red_X != NULL)
-         *int_red_X = info_ptr->colorspace.end_points_XYZ.red_X;
-      if (int_red_Y != NULL)
-         *int_red_Y = info_ptr->colorspace.end_points_XYZ.red_Y;
-      if (int_red_Z != NULL)
-         *int_red_Z = info_ptr->colorspace.end_points_XYZ.red_Z;
-      if (int_green_X != NULL)
-         *int_green_X = info_ptr->colorspace.end_points_XYZ.green_X;
-      if (int_green_Y != NULL)
-         *int_green_Y = info_ptr->colorspace.end_points_XYZ.green_Y;
-      if (int_green_Z != NULL)
-         *int_green_Z = info_ptr->colorspace.end_points_XYZ.green_Z;
-      if (int_blue_X != NULL)
-         *int_blue_X = info_ptr->colorspace.end_points_XYZ.blue_X;
-      if (int_blue_Y != NULL)
-         *int_blue_Y = info_ptr->colorspace.end_points_XYZ.blue_Y;
-      if (int_blue_Z != NULL)
-         *int_blue_Z = info_ptr->colorspace.end_points_XYZ.blue_Z;
+      if (int_red_X != NULL) *int_red_X = XYZ.red_X;
+      if (int_red_Y != NULL) *int_red_Y = XYZ.red_Y;
+      if (int_red_Z != NULL) *int_red_Z = XYZ.red_Z;
+      if (int_green_X != NULL) *int_green_X = XYZ.green_X;
+      if (int_green_Y != NULL) *int_green_Y = XYZ.green_Y;
+      if (int_green_Z != NULL) *int_green_Z = XYZ.green_Z;
+      if (int_blue_X != NULL) *int_blue_X = XYZ.blue_X;
+      if (int_blue_Y != NULL) *int_blue_Y = XYZ.blue_Y;
+      if (int_blue_Z != NULL) *int_blue_Z = XYZ.blue_Z;
       return PNG_INFO_cHRM;
    }
 
@@ -648,31 +626,24 @@ png_get_cHRM_XYZ_fixed(png_const_structrp png_ptr, png_const_inforp info_ptr,
 
 png_uint_32 PNGAPI
 png_get_cHRM_fixed(png_const_structrp png_ptr, png_const_inforp info_ptr,
-    png_fixed_point *white_x, png_fixed_point *white_y, png_fixed_point *red_x,
-    png_fixed_point *red_y, png_fixed_point *green_x, png_fixed_point *green_y,
-    png_fixed_point *blue_x, png_fixed_point *blue_y)
+    png_fixed_point *whitex, png_fixed_point *whitey, png_fixed_point *redx,
+    png_fixed_point *redy, png_fixed_point *greenx, png_fixed_point *greeny,
+    png_fixed_point *bluex, png_fixed_point *bluey)
 {
    png_debug1(1, "in %s retrieval function", "cHRM");
 
+   /* PNGv3: this just returns the values store from the cHRM, if any. */
    if (png_ptr != NULL && info_ptr != NULL &&
-      (info_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_ENDPOINTS) != 0)
+       (info_ptr->valid & PNG_INFO_cHRM) != 0)
    {
-      if (white_x != NULL)
-         *white_x = info_ptr->colorspace.end_points_xy.whitex;
-      if (white_y != NULL)
-         *white_y = info_ptr->colorspace.end_points_xy.whitey;
-      if (red_x != NULL)
-         *red_x = info_ptr->colorspace.end_points_xy.redx;
-      if (red_y != NULL)
-         *red_y = info_ptr->colorspace.end_points_xy.redy;
-      if (green_x != NULL)
-         *green_x = info_ptr->colorspace.end_points_xy.greenx;
-      if (green_y != NULL)
-         *green_y = info_ptr->colorspace.end_points_xy.greeny;
-      if (blue_x != NULL)
-         *blue_x = info_ptr->colorspace.end_points_xy.bluex;
-      if (blue_y != NULL)
-         *blue_y = info_ptr->colorspace.end_points_xy.bluey;
+      if (whitex != NULL) *whitex = info_ptr->cHRM.whitex;
+      if (whitey != NULL) *whitey = info_ptr->cHRM.whitey;
+      if (redx   != NULL) *redx   = info_ptr->cHRM.redx;
+      if (redy   != NULL) *redy   = info_ptr->cHRM.redy;
+      if (greenx != NULL) *greenx = info_ptr->cHRM.greenx;
+      if (greeny != NULL) *greeny = info_ptr->cHRM.greeny;
+      if (bluex  != NULL) *bluex  = info_ptr->cHRM.bluex;
+      if (bluey  != NULL) *bluey  = info_ptr->cHRM.bluey;
       return PNG_INFO_cHRM;
    }
 
@@ -689,11 +660,11 @@ png_get_gAMA_fixed(png_const_structrp png_ptr, png_const_inforp info_ptr,
 {
    png_debug1(1, "in %s retrieval function", "gAMA");
 
+   /* PNGv3 compatibility: only report gAMA if it is really present. */
    if (png_ptr != NULL && info_ptr != NULL &&
-       (info_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_GAMMA) != 0 &&
-       file_gamma != NULL)
+       (info_ptr->valid & PNG_INFO_gAMA) != 0)
    {
-      *file_gamma = info_ptr->colorspace.gamma;
+      if (file_gamma != NULL) *file_gamma = info_ptr->gamma;
       return PNG_INFO_gAMA;
    }
 
@@ -708,12 +679,13 @@ png_get_gAMA(png_const_structrp png_ptr, png_const_inforp info_ptr,
 {
    png_debug1(1, "in %s retrieval function", "gAMA(float)");
 
+   /* PNGv3 compatibility: only report gAMA if it is really present. */
    if (png_ptr != NULL && info_ptr != NULL &&
-      (info_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_GAMMA) != 0 &&
-      file_gamma != NULL)
+       (info_ptr->valid & PNG_INFO_gAMA) != 0)
    {
-      *file_gamma = png_float(png_ptr, info_ptr->colorspace.gamma,
-          "png_get_gAMA");
+      if (file_gamma != NULL)
+         *file_gamma = png_float(png_ptr, info_ptr->gamma, "gAMA");
+
       return PNG_INFO_gAMA;
    }
 
@@ -730,9 +702,10 @@ png_get_sRGB(png_const_structrp png_ptr, png_const_inforp info_ptr,
    png_debug1(1, "in %s retrieval function", "sRGB");
 
    if (png_ptr != NULL && info_ptr != NULL &&
-      (info_ptr->valid & PNG_INFO_sRGB) != 0 && file_srgb_intent != NULL)
+      (info_ptr->valid & PNG_INFO_sRGB) != 0)
    {
-      *file_srgb_intent = info_ptr->colorspace.rendering_intent;
+      if (file_srgb_intent != NULL)
+         *file_srgb_intent = info_ptr->rendering_intent;
       return PNG_INFO_sRGB;
    }
 
@@ -785,6 +758,136 @@ png_get_sPLT(png_const_structrp png_ptr, png_inforp info_ptr,
 }
 #endif
 
+#ifdef PNG_cICP_SUPPORTED
+png_uint_32 PNGAPI
+png_get_cICP(png_const_structrp png_ptr,
+             png_const_inforp info_ptr, png_bytep colour_primaries,
+             png_bytep transfer_function, png_bytep matrix_coefficients,
+             png_bytep video_full_range_flag)
+{
+    png_debug1(1, "in %s retrieval function", "cICP");
+
+    if (png_ptr != NULL && info_ptr != NULL &&
+        (info_ptr->valid & PNG_INFO_cICP) != 0 &&
+        colour_primaries != NULL && transfer_function != NULL &&
+        matrix_coefficients != NULL && video_full_range_flag != NULL)
+    {
+        *colour_primaries = info_ptr->cicp_colour_primaries;
+        *transfer_function = info_ptr->cicp_transfer_function;
+        *matrix_coefficients = info_ptr->cicp_matrix_coefficients;
+        *video_full_range_flag = info_ptr->cicp_video_full_range_flag;
+        return (PNG_INFO_cICP);
+    }
+
+    return 0;
+}
+#endif
+
+#ifdef PNG_cLLI_SUPPORTED
+#  ifdef PNG_FIXED_POINT_SUPPORTED
+png_uint_32 PNGAPI
+png_get_cLLI_fixed(png_const_structrp png_ptr, png_const_inforp info_ptr,
+    png_uint_32p maxCLL,
+    png_uint_32p maxFALL)
+{
+   png_debug1(1, "in %s retrieval function", "cLLI");
+
+   if (png_ptr != NULL && info_ptr != NULL &&
+       (info_ptr->valid & PNG_INFO_cLLI) != 0)
+   {
+      if (maxCLL != NULL) *maxCLL = info_ptr->maxCLL;
+      if (maxFALL != NULL) *maxFALL = info_ptr->maxFALL;
+      return PNG_INFO_cLLI;
+   }
+
+   return 0;
+}
+#  endif
+
+#  ifdef PNG_FLOATING_POINT_SUPPORTED
+png_uint_32 PNGAPI
+png_get_cLLI(png_const_structrp png_ptr, png_const_inforp info_ptr,
+      double *maxCLL, double *maxFALL)
+{
+   png_debug1(1, "in %s retrieval function", "cLLI(float)");
+
+   if (png_ptr != NULL && info_ptr != NULL &&
+       (info_ptr->valid & PNG_INFO_cLLI) != 0)
+   {
+      if (maxCLL != NULL) *maxCLL = info_ptr->maxCLL * .0001;
+      if (maxFALL != NULL) *maxFALL = info_ptr->maxFALL * .0001;
+      return PNG_INFO_cLLI;
+   }
+
+   return 0;
+}
+#  endif
+#endif /* cLLI */
+
+#ifdef PNG_mDCV_SUPPORTED
+#  ifdef PNG_FIXED_POINT_SUPPORTED
+png_uint_32 PNGAPI
+png_get_mDCV_fixed(png_const_structrp png_ptr, png_const_inforp info_ptr,
+    png_fixed_point *white_x, png_fixed_point *white_y,
+    png_fixed_point *red_x, png_fixed_point *red_y,
+    png_fixed_point *green_x, png_fixed_point *green_y,
+    png_fixed_point *blue_x, png_fixed_point *blue_y,
+    png_uint_32p mastering_maxDL, png_uint_32p mastering_minDL)
+{
+   png_debug1(1, "in %s retrieval function", "mDCV");
+
+   if (png_ptr != NULL && info_ptr != NULL &&
+       (info_ptr->valid & PNG_INFO_mDCV) != 0)
+   {
+      if (white_x != NULL) *white_x = info_ptr->mastering_white_x * 2;
+      if (white_y != NULL) *white_y = info_ptr->mastering_white_y * 2;
+      if (red_x != NULL) *red_x = info_ptr->mastering_red_x * 2;
+      if (red_y != NULL) *red_y = info_ptr->mastering_red_y * 2;
+      if (green_x != NULL) *green_x = info_ptr->mastering_green_x * 2;
+      if (green_y != NULL) *green_y = info_ptr->mastering_green_y * 2;
+      if (blue_x != NULL) *blue_x = info_ptr->mastering_blue_x * 2;
+      if (blue_y != NULL) *blue_y = info_ptr->mastering_blue_y * 2;
+      if (mastering_maxDL != NULL) *mastering_maxDL = info_ptr->mastering_maxDL;
+      if (mastering_minDL != NULL) *mastering_minDL = info_ptr->mastering_minDL;
+      return PNG_INFO_mDCV;
+   }
+
+   return 0;
+}
+#  endif
+
+#  ifdef PNG_FLOATING_POINT_SUPPORTED
+png_uint_32 PNGAPI
+png_get_mDCV(png_const_structrp png_ptr, png_const_inforp info_ptr,
+    double *white_x, double *white_y, double *red_x, double *red_y,
+    double *green_x, double *green_y, double *blue_x, double *blue_y,
+    double *mastering_maxDL, double *mastering_minDL)
+{
+   png_debug1(1, "in %s retrieval function", "mDCV(float)");
+
+   if (png_ptr != NULL && info_ptr != NULL &&
+       (info_ptr->valid & PNG_INFO_mDCV) != 0)
+   {
+      if (white_x != NULL) *white_x = info_ptr->mastering_white_x * .00002;
+      if (white_y != NULL) *white_y = info_ptr->mastering_white_y * .00002;
+      if (red_x != NULL) *red_x = info_ptr->mastering_red_x * .00002;
+      if (red_y != NULL) *red_y = info_ptr->mastering_red_y * .00002;
+      if (green_x != NULL) *green_x = info_ptr->mastering_green_x * .00002;
+      if (green_y != NULL) *green_y = info_ptr->mastering_green_y * .00002;
+      if (blue_x != NULL) *blue_x = info_ptr->mastering_blue_x * .00002;
+      if (blue_y != NULL) *blue_y = info_ptr->mastering_blue_y * .00002;
+      if (mastering_maxDL != NULL)
+         *mastering_maxDL = info_ptr->mastering_maxDL * .0001;
+      if (mastering_minDL != NULL)
+         *mastering_minDL = info_ptr->mastering_minDL * .0001;
+      return PNG_INFO_mDCV;
+   }
+
+   return 0;
+}
+#  endif /* FLOATING_POINT */
+#endif /* mDCV */
+
 #ifdef PNG_eXIf_SUPPORTED
 png_uint_32 PNGAPI
 png_get_eXIf(png_const_structrp png_ptr, png_inforp info_ptr,
diff --git a/pnginfo.h b/pnginfo.h
index 1f98dedc4..c2a907bc5 100644
--- a/pnginfo.h
+++ b/pnginfo.h
@@ -1,4 +1,3 @@
-
 /* pnginfo.h - header file for PNG reference library
  *
  * Copyright (c) 2018 Cosmin Truta
@@ -87,18 +86,12 @@ struct png_info_def
     * and initialize the appropriate fields below.
     */
 
-#if defined(PNG_COLORSPACE_SUPPORTED) || defined(PNG_GAMMA_SUPPORTED)
-   /* png_colorspace only contains 'flags' if neither GAMMA or COLORSPACE are
-    * defined.  When COLORSPACE is switched on all the colorspace-defining
-    * chunks should be enabled, when GAMMA is switched on all the gamma-defining
-    * chunks should be enabled.  If this is not done it becomes possible to read
-    * inconsistent PNG files and assign a probably incorrect interpretation to
-    * the information.  (In other words, by carefully choosing which chunks to
-    * recognize the system configuration can select an interpretation for PNG
-    * files containing ambiguous data and this will result in inconsistent
-    * behavior between different libpng builds!)
-    */
-   png_colorspace colorspace;
+#ifdef PNG_cICP_SUPPORTED
+   /* cICP chunk data */
+   png_byte cicp_colour_primaries;
+   png_byte cicp_transfer_function;
+   png_byte cicp_matrix_coefficients;
+   png_byte cicp_video_full_range_flag;
 #endif
 
 #ifdef PNG_iCCP_SUPPORTED
@@ -108,6 +101,24 @@ struct png_info_def
    png_uint_32 iccp_proflen;  /* ICC profile data length */
 #endif
 
+#ifdef PNG_cLLI_SUPPORTED
+   png_uint_32 maxCLL;  /* cd/m2 (nits) * 10,000 */
+   png_uint_32 maxFALL;
+#endif
+
+#ifdef PNG_mDCV_SUPPORTED
+   png_uint_16 mastering_red_x;  /* CIE (xy) x * 50,000 */
+   png_uint_16 mastering_red_y;
+   png_uint_16 mastering_green_x;
+   png_uint_16 mastering_green_y;
+   png_uint_16 mastering_blue_x;
+   png_uint_16 mastering_blue_y;
+   png_uint_16 mastering_white_x;
+   png_uint_16 mastering_white_y;
+   png_uint_32 mastering_maxDL; /* cd/m2 (nits) * 10,000 */
+   png_uint_32 mastering_minDL;
+#endif
+
 #ifdef PNG_TEXT_SUPPORTED
    /* The tEXt, and zTXt chunks contain human-readable textual data in
     * uncompressed, compressed, and optionally compressed forms, respectively.
@@ -186,11 +197,8 @@ defined(PNG_READ_BACKGROUND_SUPPORTED)
 #endif
 
 #ifdef PNG_eXIf_SUPPORTED
-   int num_exif;  /* Added at libpng-1.6.31 */
+   png_uint_32 num_exif;  /* Added at libpng-1.6.31 */
    png_bytep exif;
-# ifdef PNG_READ_eXIf_SUPPORTED
-   png_bytep eXIf_buf;  /* Added at libpng-1.6.32 */
-# endif
 #endif
 
 #ifdef PNG_hIST_SUPPORTED
@@ -263,5 +271,16 @@ defined(PNG_READ_BACKGROUND_SUPPORTED)
    png_bytepp row_pointers;        /* the image bits */
 #endif
 
+#ifdef PNG_cHRM_SUPPORTED
+   png_xy cHRM;
+#endif
+
+#ifdef PNG_gAMA_SUPPORTED
+   png_fixed_point gamma;
+#endif
+
+#ifdef PNG_sRGB_SUPPORTED
+   int rendering_intent;
+#endif
 };
 #endif /* PNGINFO_H */
diff --git a/pngmem.c b/pngmem.c
index 09ed9c1c9..90c13b106 100644
--- a/pngmem.c
+++ b/pngmem.c
@@ -1,4 +1,3 @@
-
 /* pngmem.c - stub functions for memory allocation
  *
  * Copyright (c) 2018 Cosmin Truta
@@ -73,30 +72,29 @@ png_malloc_base,(png_const_structrp png_ptr, png_alloc_size_t size),
     * to implement a user memory handler.  This checks to be sure it isn't
     * called with big numbers.
     */
-#ifndef PNG_USER_MEM_SUPPORTED
-   PNG_UNUSED(png_ptr)
-#endif
+#  ifdef PNG_MAX_MALLOC_64K
+      /* This is support for legacy systems which had segmented addressing
+       * limiting the maximum allocation size to 65536.  It takes precedence
+       * over PNG_SIZE_MAX which is set to 65535 on true 16-bit systems.
+       *
+       * TODO: libpng-1.8: finally remove both cases.
+       */
+      if (size > 65536U) return NULL;
+#  endif
 
-   /* Some compilers complain that this is always true.  However, it
-    * can be false when integer overflow happens.
+   /* This is checked too because the system malloc call below takes a (size_t).
     */
-   if (size > 0 && size <= PNG_SIZE_MAX
-#     ifdef PNG_MAX_MALLOC_64K
-         && size <= 65536U
-#     endif
-      )
-   {
-#ifdef PNG_USER_MEM_SUPPORTED
+   if (size > PNG_SIZE_MAX) return NULL;
+
+#  ifdef PNG_USER_MEM_SUPPORTED
       if (png_ptr != NULL && png_ptr->malloc_fn != NULL)
          return png_ptr->malloc_fn(png_constcast(png_structrp,png_ptr), size);
+#  else
+      PNG_UNUSED(png_ptr)
+#  endif
 
-      else
-#endif
-         return malloc((size_t)size); /* checked for truncation above */
-   }
-
-   else
-      return NULL;
+   /* Use the system malloc */
+   return malloc((size_t)/*SAFE*/size); /* checked for truncation above */
 }
 
 #if defined(PNG_TEXT_SUPPORTED) || defined(PNG_sPLT_SUPPORTED) ||\
diff --git a/pngpread.c b/pngpread.c
index ffab19c08..60d810693 100644
--- a/pngpread.c
+++ b/pngpread.c
@@ -1,4 +1,3 @@
-
 /* pngpread.c - read a png file in push mode
  *
  * Copyright (c) 2018-2024 Cosmin Truta
@@ -32,6 +31,21 @@ if (png_ptr->push_length + 4 > png_ptr->buffer_size) \
 if (png_ptr->buffer_size < N) \
    { png_push_save_buffer(png_ptr); return; }
 
+#ifdef PNG_READ_INTERLACING_SUPPORTED
+/* Arrays to facilitate interlacing - use pass (0 - 6) as index. */
+
+/* Start of interlace block */
+static const png_byte png_pass_start[7] = {0, 4, 0, 2, 0, 1, 0};
+/* Offset to next interlace block */
+static const png_byte png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
+/* Start of interlace block in the y direction */
+static const png_byte png_pass_ystart[7] = {0, 0, 4, 0, 2, 0, 1};
+/* Offset to next interlace block in the y direction */
+static const png_byte png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
+
+/* TODO: Move these arrays to a common utility module to avoid duplication. */
+#endif
+
 void PNGAPI
 png_process_data(png_structrp png_ptr, png_inforp info_ptr,
     png_bytep buffer, size_t buffer_size)
@@ -179,17 +193,8 @@ png_push_read_chunk(png_structrp png_ptr, png_inforp info_ptr)
     */
    if ((png_ptr->mode & PNG_HAVE_CHUNK_HEADER) == 0)
    {
-      png_byte chunk_length[4];
-      png_byte chunk_tag[4];
-
       PNG_PUSH_SAVE_BUFFER_IF_LT(8)
-      png_push_fill_buffer(png_ptr, chunk_length, 4);
-      png_ptr->push_length = png_get_uint_31(png_ptr, chunk_length);
-      png_reset_crc(png_ptr);
-      png_crc_read(png_ptr, chunk_tag, 4);
-      png_ptr->chunk_name = PNG_CHUNK_FROM_STRING(chunk_tag);
-      png_check_chunk_name(png_ptr, png_ptr->chunk_name);
-      png_check_chunk_length(png_ptr, png_ptr->push_length);
+      png_ptr->push_length = png_read_chunk_header(png_ptr);
       png_ptr->mode |= PNG_HAVE_CHUNK_HEADER;
    }
 
@@ -230,13 +235,13 @@ png_push_read_chunk(png_structrp png_ptr, png_inforp info_ptr)
          png_error(png_ptr, "Invalid IHDR length");
 
       PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_IHDR(png_ptr, info_ptr, png_ptr->push_length);
+      png_handle_chunk(png_ptr, info_ptr, png_ptr->push_length);
    }
 
    else if (chunk_name == png_IEND)
    {
       PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_IEND(png_ptr, info_ptr, png_ptr->push_length);
+      png_handle_chunk(png_ptr, info_ptr, png_ptr->push_length);
 
       png_ptr->process_mode = PNG_READ_DONE_MODE;
       png_push_have_end(png_ptr, info_ptr);
@@ -253,12 +258,6 @@ png_push_read_chunk(png_structrp png_ptr, png_inforp info_ptr)
    }
 #endif
 
-   else if (chunk_name == png_PLTE)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_PLTE(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
    else if (chunk_name == png_IDAT)
    {
       png_ptr->idat_size = png_ptr->push_length;
@@ -271,155 +270,10 @@ png_push_read_chunk(png_structrp png_ptr, png_inforp info_ptr)
       return;
    }
 
-#ifdef PNG_READ_gAMA_SUPPORTED
-   else if (png_ptr->chunk_name == png_gAMA)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_gAMA(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_sBIT_SUPPORTED
-   else if (png_ptr->chunk_name == png_sBIT)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_sBIT(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_cHRM_SUPPORTED
-   else if (png_ptr->chunk_name == png_cHRM)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_cHRM(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_eXIf_SUPPORTED
-   else if (png_ptr->chunk_name == png_eXIf)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_eXIf(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_sRGB_SUPPORTED
-   else if (chunk_name == png_sRGB)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_sRGB(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_iCCP_SUPPORTED
-   else if (png_ptr->chunk_name == png_iCCP)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_iCCP(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_sPLT_SUPPORTED
-   else if (chunk_name == png_sPLT)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_sPLT(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_tRNS_SUPPORTED
-   else if (chunk_name == png_tRNS)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_tRNS(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_bKGD_SUPPORTED
-   else if (chunk_name == png_bKGD)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_bKGD(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_hIST_SUPPORTED
-   else if (chunk_name == png_hIST)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_hIST(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_pHYs_SUPPORTED
-   else if (chunk_name == png_pHYs)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_pHYs(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_oFFs_SUPPORTED
-   else if (chunk_name == png_oFFs)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_oFFs(png_ptr, info_ptr, png_ptr->push_length);
-   }
-#endif
-
-#ifdef PNG_READ_pCAL_SUPPORTED
-   else if (chunk_name == png_pCAL)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_pCAL(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_sCAL_SUPPORTED
-   else if (chunk_name == png_sCAL)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_sCAL(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_tIME_SUPPORTED
-   else if (chunk_name == png_tIME)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_tIME(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_tEXt_SUPPORTED
-   else if (chunk_name == png_tEXt)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_tEXt(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_zTXt_SUPPORTED
-   else if (chunk_name == png_zTXt)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_zTXt(png_ptr, info_ptr, png_ptr->push_length);
-   }
-
-#endif
-#ifdef PNG_READ_iTXt_SUPPORTED
-   else if (chunk_name == png_iTXt)
-   {
-      PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_iTXt(png_ptr, info_ptr, png_ptr->push_length);
-   }
-#endif
-
    else
    {
       PNG_PUSH_SAVE_BUFFER_IF_FULL
-      png_handle_unknown(png_ptr, info_ptr, png_ptr->push_length,
-          PNG_HANDLE_CHUNK_AS_DEFAULT);
+      png_handle_chunk(png_ptr, info_ptr, png_ptr->push_length);
    }
 
    png_ptr->mode &= ~PNG_HAVE_CHUNK_HEADER;
@@ -976,27 +830,6 @@ png_push_process_row(png_structrp png_ptr)
 void /* PRIVATE */
 png_read_push_finish_row(png_structrp png_ptr)
 {
-#ifdef PNG_READ_INTERLACING_SUPPORTED
-   /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
-
-   /* Start of interlace block */
-   static const png_byte png_pass_start[] = {0, 4, 0, 2, 0, 1, 0};
-
-   /* Offset to next interlace block */
-   static const png_byte png_pass_inc[] = {8, 8, 4, 4, 2, 2, 1};
-
-   /* Start of interlace block in the y direction */
-   static const png_byte png_pass_ystart[] = {0, 0, 4, 0, 2, 0, 1};
-
-   /* Offset to next interlace block in the y direction */
-   static const png_byte png_pass_yinc[] = {8, 8, 8, 4, 4, 2, 2};
-
-   /* Height of interlace block.  This is not currently used - if you need
-    * it, uncomment it here and in png.h
-   static const png_byte png_pass_height[] = {8, 8, 4, 4, 2, 2, 1};
-   */
-#endif
-
    png_ptr->row_number++;
    if (png_ptr->row_number < png_ptr->num_rows)
       return;
diff --git a/pngpriv.h b/pngpriv.h
index b59084e7e..d514dff5c 100644
--- a/pngpriv.h
+++ b/pngpriv.h
@@ -1,4 +1,3 @@
-
 /* pngpriv.h - private declarations for use inside libpng
  *
  * Copyright (c) 2018-2024 Cosmin Truta
@@ -672,7 +671,7 @@
 #define PNG_FLAG_CRC_ANCILLARY_NOWARN     0x0200U
 #define PNG_FLAG_CRC_CRITICAL_USE         0x0400U
 #define PNG_FLAG_CRC_CRITICAL_IGNORE      0x0800U
-#define PNG_FLAG_ASSUME_sRGB              0x1000U /* Added to libpng-1.5.4 */
+/*      PNG_FLAG_ASSUME_sRGB unused       0x1000U  * Added to libpng-1.5.4 */
 #define PNG_FLAG_OPTIMIZE_ALPHA           0x2000U /* Added to libpng-1.5.4 */
 #define PNG_FLAG_DETECT_UNINITIALIZED     0x4000U /* Added to libpng-1.5.4 */
 /* #define PNG_FLAG_KEEP_UNKNOWN_CHUNKS      0x8000U */
@@ -783,6 +782,8 @@
 #ifdef PNG_FIXED_POINT_MACRO_SUPPORTED
 #define png_fixed(png_ptr, fp, s) ((fp) <= 21474 && (fp) >= -21474 ?\
     ((png_fixed_point)(100000 * (fp))) : (png_fixed_error(png_ptr, s),0))
+#define png_fixed_ITU(png_ptr, fp, s) ((fp) <= 214748 && (fp) >= 0 ?\
+    ((png_uint_32)(10000 * (fp))) : (png_fixed_error(png_ptr, s),0))
 #endif
 /* else the corresponding function is defined below, inside the scope of the
  * cplusplus test.
@@ -801,11 +802,31 @@
  *
  * PNG_32b correctly produces a value shifted by up to 24 bits, even on
  * architectures where (int) is only 16 bits.
+ *
+ * 1.6.47: PNG_32b was made into a preprocessor evaluable macro by replacing the
+ * static_cast with a promoting binary operation using a guaranteed 32-bit
+ * (minimum) unsigned value.
  */
-#define PNG_32b(b,s) ((png_uint_32)(b) << (s))
+#define PNG_32b(b,s) (((0xFFFFFFFFU)&(b)) << (s))
 #define PNG_U32(b1,b2,b3,b4) \
    (PNG_32b(b1,24) | PNG_32b(b2,16) | PNG_32b(b3,8) | PNG_32b(b4,0))
 
+/* Chunk name validation.  When using these macros all the arguments should be
+ * constants, otherwise code bloat may well occur.  The macros are provided
+ * primarily for use in #if checks.
+ *
+ * PNG_32to8 produces a byte value with the right shift; used to extract the
+ * byte value from a chunk name.
+ */
+#define PNG_32to8(cn,s) (((cn) >> (s)) & 0xffU)
+#define PNG_CN_VALID_UPPER(b) ((b) >= 65 && (b) <= 90) /* upper-case ASCII */
+#define PNG_CN_VALID_ASCII(b) PNG_CN_VALID_UPPER((b) & ~32U)
+#define PNG_CHUNK_NAME_VALID(cn) (\
+   PNG_CN_VALID_ASCII(PNG_32to8(cn,24)) && /* critical, !ancillary */\
+   PNG_CN_VALID_ASCII(PNG_32to8(cn,16)) && /* public, !privately defined */\
+   PNG_CN_VALID_UPPER(PNG_32to8(cn, 8)) && /* VALID, !reserved */\
+   PNG_CN_VALID_ASCII(PNG_32to8(cn, 0))   /* data-dependent, !copy ok */)
+
 /* Constants for known chunk types.
  *
  * MAINTAINERS: If you need to add a chunk, define the name here.
@@ -833,9 +854,14 @@
 #define png_IEND PNG_U32( 73,  69,  78,  68)
 #define png_IHDR PNG_U32( 73,  72,  68,  82)
 #define png_PLTE PNG_U32( 80,  76,  84,  69)
+#define png_acTL PNG_U32( 97,  99,  84,  76) /* PNGv3: APNG */
 #define png_bKGD PNG_U32( 98,  75,  71,  68)
 #define png_cHRM PNG_U32( 99,  72,  82,  77)
+#define png_cICP PNG_U32( 99,  73,  67,  80) /* PNGv3 */
+#define png_cLLI PNG_U32( 99,  76,  76,  73) /* PNGv3 */
 #define png_eXIf PNG_U32(101,  88,  73, 102) /* registered July 2017 */
+#define png_fcTL PNG_U32(102,  99,  84,  76) /* PNGv3: APNG */
+#define png_fdAT PNG_U32(102, 100,  65,  84) /* PNGv3: APNG */
 #define png_fRAc PNG_U32(102,  82,  65,  99) /* registered, not defined */
 #define png_gAMA PNG_U32(103,  65,  77,  65)
 #define png_gIFg PNG_U32(103,  73,  70, 103)
@@ -844,6 +870,7 @@
 #define png_hIST PNG_U32(104,  73,  83,  84)
 #define png_iCCP PNG_U32(105,  67,  67,  80)
 #define png_iTXt PNG_U32(105,  84,  88, 116)
+#define png_mDCV PNG_U32(109,  68,  67,  86) /* PNGv3 */
 #define png_oFFs PNG_U32(111,  70,  70, 115)
 #define png_pCAL PNG_U32(112,  67,  65,  76)
 #define png_pHYs PNG_U32(112,  72,  89, 115)
@@ -884,11 +911,74 @@
 #define PNG_CHUNK_RESERVED(c)     (1 & ((c) >> 13))
 #define PNG_CHUNK_SAFE_TO_COPY(c) (1 & ((c) >>  5))
 
+/* Known chunks.  All supported chunks must be listed here.  The macro PNG_CHUNK
+ * contains the four character ASCII name by which the chunk is identified.  The
+ * macro is implemented as required to build tables or switch statements which
+ * require entries for every known chunk.  The macro also contains an index
+ * value which should be in order (this is checked in png.c).
+ *
+ * Notice that "known" does not require "SUPPORTED"; tables should be built in
+ * such a way that chunks unsupported in a build require no more than the table
+ * entry (which should be small.)  In particular function pointers for
+ * unsupported chunks should be NULL.
+ *
+ * At present these index values are not exported (not part of the public API)
+ * so can be changed at will.  For convenience the names are in lexical sort
+ * order but with the critical chunks at the start in the order of occurence in
+ * a PNG.
+ *
+ * PNG_INFO_ values do not exist for every one of these chunk handles; for
+ * example PNG_INFO_{IDAT,IEND,tEXt,iTXt,zTXt} and possibly other chunks in the
+ * future.
+ */
+#define PNG_KNOWN_CHUNKS\
+   PNG_CHUNK(IHDR,  0)\
+   PNG_CHUNK(PLTE,  1)\
+   PNG_CHUNK(IDAT,  2)\
+   PNG_CHUNK(IEND,  3)\
+   PNG_CHUNK(acTL,  4)\
+   PNG_CHUNK(bKGD,  5)\
+   PNG_CHUNK(cHRM,  6)\
+   PNG_CHUNK(cICP,  7)\
+   PNG_CHUNK(cLLI,  8)\
+   PNG_CHUNK(eXIf,  9)\
+   PNG_CHUNK(fcTL, 10)\
+   PNG_CHUNK(fdAT, 11)\
+   PNG_CHUNK(gAMA, 12)\
+   PNG_CHUNK(hIST, 13)\
+   PNG_CHUNK(iCCP, 14)\
+   PNG_CHUNK(iTXt, 15)\
+   PNG_CHUNK(mDCV, 16)\
+   PNG_CHUNK(oFFs, 17)\
+   PNG_CHUNK(pCAL, 18)\
+   PNG_CHUNK(pHYs, 19)\
+   PNG_CHUNK(sBIT, 20)\
+   PNG_CHUNK(sCAL, 21)\
+   PNG_CHUNK(sPLT, 22)\
+   PNG_CHUNK(sRGB, 23)\
+   PNG_CHUNK(tEXt, 24)\
+   PNG_CHUNK(tIME, 25)\
+   PNG_CHUNK(tRNS, 26)\
+   PNG_CHUNK(zTXt, 27)
+
 /* Gamma values (new at libpng-1.5.4): */
 #define PNG_GAMMA_MAC_OLD 151724  /* Assume '1.8' is really 2.2/1.45! */
 #define PNG_GAMMA_MAC_INVERSE 65909
 #define PNG_GAMMA_sRGB_INVERSE 45455
 
+/* gamma sanity check.  libpng cannot implement gamma transforms outside a
+ * certain limit because of its use of 16-bit fixed point intermediate values.
+ * Gamma values that are too large or too small will zap the 16-bit values all
+ * to 0 or 65535 resulting in an obvious 'bad' image.
+ *
+ * In libpng 1.6.0 the limits were changed from 0.07..3 to 0.01..100 to
+ * accommodate the optimal 16-bit gamma of 36 and its reciprocal.
+ *
+ * These are png_fixed_point integral values:
+ */
+#define PNG_LIB_GAMMA_MIN 1000
+#define PNG_LIB_GAMMA_MAX 10000000
+
 /* Almost everything below is C specific; the #defines above can be used in
  * non-C code (so long as it is C-preprocessed) the rest of this stuff cannot.
  */
@@ -952,7 +1042,6 @@ extern "C" {
  *
  * All of these functions must be declared with PNG_INTERNAL_FUNCTION.
  */
-
 /* Zlib support */
 #define PNG_UNEXPECTED_ZLIB_RETURN (-7)
 PNG_INTERNAL_FUNCTION(void, png_zstream_error,(png_structrp png_ptr, int ret),
@@ -971,6 +1060,7 @@ PNG_INTERNAL_FUNCTION(void,png_free_buffer_list,(png_structrp png_ptr,
    !defined(PNG_FIXED_POINT_MACRO_SUPPORTED) && \
    (defined(PNG_gAMA_SUPPORTED) || defined(PNG_cHRM_SUPPORTED) || \
    defined(PNG_sCAL_SUPPORTED) || defined(PNG_READ_BACKGROUND_SUPPORTED) || \
+   defined(PNG_mDCV_SUPPORTED) || \
    defined(PNG_READ_RGB_TO_GRAY_SUPPORTED)) || \
    (defined(PNG_sCAL_SUPPORTED) && \
    defined(PNG_FLOATING_ARITHMETIC_SUPPORTED))
@@ -978,12 +1068,38 @@ PNG_INTERNAL_FUNCTION(png_fixed_point,png_fixed,(png_const_structrp png_ptr,
    double fp, png_const_charp text),PNG_EMPTY);
 #endif
 
+#if defined(PNG_FLOATING_POINT_SUPPORTED) && \
+   !defined(PNG_FIXED_POINT_MACRO_SUPPORTED) && \
+   (defined(PNG_cLLI_SUPPORTED) || defined(PNG_mDCV_SUPPORTED))
+PNG_INTERNAL_FUNCTION(png_uint_32,png_fixed_ITU,(png_const_structrp png_ptr,
+   double fp, png_const_charp text),PNG_EMPTY);
+#endif
+
 /* Check the user version string for compatibility, returns false if the version
  * numbers aren't compatible.
  */
 PNG_INTERNAL_FUNCTION(int,png_user_version_check,(png_structrp png_ptr,
    png_const_charp user_png_ver),PNG_EMPTY);
 
+#ifdef PNG_READ_SUPPORTED /* should only be used on read */
+/* Security: read limits on the largest allocations while reading a PNG.  This
+ * avoids very large allocations caused by PNG files with damaged or altered
+ * chunk 'length' fields.
+ */
+#ifdef PNG_SET_USER_LIMITS_SUPPORTED /* run-time limit */
+#  define png_chunk_max(png_ptr) ((png_ptr)->user_chunk_malloc_max)
+
+#elif PNG_USER_CHUNK_MALLOC_MAX > 0 /* compile-time limit */
+#  define png_chunk_max(png_ptr) ((void)png_ptr, PNG_USER_CHUNK_MALLOC_MAX)
+
+#elif (defined PNG_MAX_MALLOC_64K)  /* legacy system limit */
+#  define png_chunk_max(png_ptr) ((void)png_ptr, 65536U)
+
+#else                               /* modern system limit SIZE_MAX (C99) */
+#  define png_chunk_max(png_ptr) ((void)png_ptr, PNG_SIZE_MAX)
+#endif
+#endif /* READ */
+
 /* Internal base allocator - no messages, NULL on failure to allocate.  This
  * does, however, call the application provided allocator and that could call
  * png_error (although that would be a bug in the application implementation.)
@@ -1083,9 +1199,6 @@ PNG_INTERNAL_FUNCTION(void,png_crc_read,(png_structrp png_ptr, png_bytep buf,
 PNG_INTERNAL_FUNCTION(int,png_crc_finish,(png_structrp png_ptr,
    png_uint_32 skip),PNG_EMPTY);
 
-/* Read the CRC from the file and compare it to the libpng calculated CRC */
-PNG_INTERNAL_FUNCTION(int,png_crc_error,(png_structrp png_ptr),PNG_EMPTY);
-
 /* Calculate the CRC over a section of data.  Note that we are only
  * passing a maximum of 64K on systems that have this as a memory limit,
  * since this is the maximum buffer size we can specify.
@@ -1131,6 +1244,26 @@ PNG_INTERNAL_FUNCTION(void,png_write_cHRM_fixed,(png_structrp png_ptr,
    /* The xy value must have been previously validated */
 #endif
 
+#ifdef PNG_WRITE_cICP_SUPPORTED
+PNG_INTERNAL_FUNCTION(void,png_write_cICP,(png_structrp png_ptr,
+    png_byte colour_primaries, png_byte transfer_function,
+    png_byte matrix_coefficients, png_byte video_full_range_flag), PNG_EMPTY);
+#endif
+
+#ifdef PNG_WRITE_cLLI_SUPPORTED
+PNG_INTERNAL_FUNCTION(void,png_write_cLLI_fixed,(png_structrp png_ptr,
+   png_uint_32 maxCLL, png_uint_32 maxFALL), PNG_EMPTY);
+#endif
+
+#ifdef PNG_WRITE_mDCV_SUPPORTED
+PNG_INTERNAL_FUNCTION(void,png_write_mDCV_fixed,(png_structrp png_ptr,
+   png_uint_16 red_x, png_uint_16 red_y,
+   png_uint_16 green_x, png_uint_16 green_y,
+   png_uint_16 blue_x, png_uint_16 blue_y,
+   png_uint_16 white_x, png_uint_16 white_y,
+   png_uint_32 maxDL, png_uint_32 minDL), PNG_EMPTY);
+#endif
+
 #ifdef PNG_WRITE_sRGB_SUPPORTED
 PNG_INTERNAL_FUNCTION(void,png_write_sRGB,(png_structrp png_ptr,
     int intent),PNG_EMPTY);
@@ -1143,10 +1276,10 @@ PNG_INTERNAL_FUNCTION(void,png_write_eXIf,(png_structrp png_ptr,
 
 #ifdef PNG_WRITE_iCCP_SUPPORTED
 PNG_INTERNAL_FUNCTION(void,png_write_iCCP,(png_structrp png_ptr,
-   png_const_charp name, png_const_bytep profile), PNG_EMPTY);
-   /* The profile must have been previously validated for correctness, the
-    * length comes from the first four bytes.  Only the base, deflate,
-    * compression is supported.
+   png_const_charp name, png_const_bytep profile, png_uint_32 proflen),
+   PNG_EMPTY);
+   /* Writes a previously 'set' profile.  The profile argument is **not**
+    * compressed.
     */
 #endif
 
@@ -1455,119 +1588,36 @@ PNG_INTERNAL_FUNCTION(void,png_do_bgr,(png_row_infop row_info,
 /* The following decodes the appropriate chunks, and does error correction,
  * then calls the appropriate callback for the chunk if it is valid.
  */
-
-/* Decode the IHDR chunk */
-PNG_INTERNAL_FUNCTION(void,png_handle_IHDR,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-PNG_INTERNAL_FUNCTION(void,png_handle_PLTE,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-PNG_INTERNAL_FUNCTION(void,png_handle_IEND,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-
-#ifdef PNG_READ_bKGD_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_bKGD,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_cHRM_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_cHRM,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_eXIf_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_eXIf,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_gAMA_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_gAMA,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_hIST_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_hIST,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_iCCP_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_iCCP,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif /* READ_iCCP */
-
-#ifdef PNG_READ_iTXt_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_iTXt,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_oFFs_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_oFFs,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_pCAL_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_pCAL,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_pHYs_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_pHYs,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_sBIT_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_sBIT,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_sCAL_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_sCAL,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_sPLT_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_sPLT,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif /* READ_sPLT */
-
-#ifdef PNG_READ_sRGB_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_sRGB,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_tEXt_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_tEXt,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_tIME_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_tIME,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_tRNS_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_tRNS,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-#ifdef PNG_READ_zTXt_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_handle_zTXt,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-#endif
-
-PNG_INTERNAL_FUNCTION(void,png_check_chunk_name,(png_const_structrp png_ptr,
-    png_uint_32 chunk_name),PNG_EMPTY);
-
-PNG_INTERNAL_FUNCTION(void,png_check_chunk_length,(png_const_structrp png_ptr,
-    png_uint_32 chunk_length),PNG_EMPTY);
-
-PNG_INTERNAL_FUNCTION(void,png_handle_unknown,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length, int keep),PNG_EMPTY);
+typedef enum
+{
+   /* Result of a call to png_handle_chunk made to handle the current chunk
+    * png_struct::chunk_name on read.  Always informational, either the stream
+    * is read for the next chunk or the routine will call png_error.
+    *
+    * NOTE: order is important internally.  handled_saved and above are regarded
+    * as handling the chunk.
+    */
+   handled_error = 0,  /* bad crc or known and bad format or too long */
+   handled_discarded,  /* not saved in the unknown chunk list */
+   handled_saved,      /* saved in the unknown chunk list */
+   handled_ok          /* known, supported and handled without error */
+} png_handle_result_code;
+
+PNG_INTERNAL_FUNCTION(png_handle_result_code,png_handle_unknown,
+    (png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length, int keep),
+    PNG_EMPTY);
    /* This is the function that gets called for unknown chunks.  The 'keep'
     * argument is either non-zero for a known chunk that has been set to be
     * handled as unknown or zero for an unknown chunk.  By default the function
     * just skips the chunk or errors out if it is critical.
     */
 
+PNG_INTERNAL_FUNCTION(png_handle_result_code,png_handle_chunk,
+    (png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
+   /* This handles the current chunk png_ptr->chunk_name with unread
+    * data[length] and returns one of the above result codes.
+    */
+
 #if defined(PNG_READ_UNKNOWN_CHUNKS_SUPPORTED) ||\
     defined(PNG_HANDLE_AS_UNKNOWN_SUPPORTED)
 PNG_INTERNAL_FUNCTION(int,png_chunk_unknown_handling,
@@ -1607,8 +1657,6 @@ PNG_INTERNAL_FUNCTION(void,png_process_IDAT_data,(png_structrp png_ptr,
     png_bytep buffer, size_t buffer_length),PNG_EMPTY);
 PNG_INTERNAL_FUNCTION(void,png_push_process_row,(png_structrp png_ptr),
     PNG_EMPTY);
-PNG_INTERNAL_FUNCTION(void,png_push_handle_unknown,(png_structrp png_ptr,
-   png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
 PNG_INTERNAL_FUNCTION(void,png_push_have_info,(png_structrp png_ptr,
    png_inforp info_ptr),PNG_EMPTY);
 PNG_INTERNAL_FUNCTION(void,png_push_have_end,(png_structrp png_ptr,
@@ -1621,109 +1669,28 @@ PNG_INTERNAL_FUNCTION(void,png_process_some_data,(png_structrp png_ptr,
     png_inforp info_ptr),PNG_EMPTY);
 PNG_INTERNAL_FUNCTION(void,png_read_push_finish_row,(png_structrp png_ptr),
     PNG_EMPTY);
-#  ifdef PNG_READ_tEXt_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_push_handle_tEXt,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-PNG_INTERNAL_FUNCTION(void,png_push_read_tEXt,(png_structrp png_ptr,
-    png_inforp info_ptr),PNG_EMPTY);
-#  endif
-#  ifdef PNG_READ_zTXt_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_push_handle_zTXt,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-PNG_INTERNAL_FUNCTION(void,png_push_read_zTXt,(png_structrp png_ptr,
-    png_inforp info_ptr),PNG_EMPTY);
-#  endif
-#  ifdef PNG_READ_iTXt_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_push_handle_iTXt,(png_structrp png_ptr,
-    png_inforp info_ptr, png_uint_32 length),PNG_EMPTY);
-PNG_INTERNAL_FUNCTION(void,png_push_read_iTXt,(png_structrp png_ptr,
-    png_inforp info_ptr),PNG_EMPTY);
-#  endif
-
 #endif /* PROGRESSIVE_READ */
 
-/* Added at libpng version 1.6.0 */
-#ifdef PNG_GAMMA_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_colorspace_set_gamma,(png_const_structrp png_ptr,
-    png_colorspacerp colorspace, png_fixed_point gAMA), PNG_EMPTY);
-   /* Set the colorspace gamma with a value provided by the application or by
-    * the gAMA chunk on read.  The value will override anything set by an ICC
-    * profile.
-    */
-
-PNG_INTERNAL_FUNCTION(void,png_colorspace_sync_info,(png_const_structrp png_ptr,
-    png_inforp info_ptr), PNG_EMPTY);
-   /* Synchronize the info 'valid' flags with the colorspace */
-
-PNG_INTERNAL_FUNCTION(void,png_colorspace_sync,(png_const_structrp png_ptr,
-    png_inforp info_ptr), PNG_EMPTY);
-   /* Copy the png_struct colorspace to the info_struct and call the above to
-    * synchronize the flags.  Checks for NULL info_ptr and does nothing.
-    */
-#endif
-
-/* Added at libpng version 1.4.0 */
-#ifdef PNG_COLORSPACE_SUPPORTED
-/* These internal functions are for maintaining the colorspace structure within
- * a png_info or png_struct (or, indeed, both).
- */
-PNG_INTERNAL_FUNCTION(int,png_colorspace_set_chromaticities,
-   (png_const_structrp png_ptr, png_colorspacerp colorspace, const png_xy *xy,
-    int preferred), PNG_EMPTY);
-
-PNG_INTERNAL_FUNCTION(int,png_colorspace_set_endpoints,
-   (png_const_structrp png_ptr, png_colorspacerp colorspace, const png_XYZ *XYZ,
-    int preferred), PNG_EMPTY);
-
-#ifdef PNG_sRGB_SUPPORTED
-PNG_INTERNAL_FUNCTION(int,png_colorspace_set_sRGB,(png_const_structrp png_ptr,
-   png_colorspacerp colorspace, int intent), PNG_EMPTY);
-   /* This does set the colorspace gAMA and cHRM values too, but doesn't set the
-    * flags to write them, if it returns false there was a problem and an error
-    * message has already been output (but the colorspace may still need to be
-    * synced to record the invalid flag).
-    */
-#endif /* sRGB */
-
 #ifdef PNG_iCCP_SUPPORTED
-PNG_INTERNAL_FUNCTION(int,png_colorspace_set_ICC,(png_const_structrp png_ptr,
-   png_colorspacerp colorspace, png_const_charp name,
-   png_uint_32 profile_length, png_const_bytep profile, int color_type),
-   PNG_EMPTY);
-   /* The 'name' is used for information only */
-
 /* Routines for checking parts of an ICC profile. */
 #ifdef PNG_READ_iCCP_SUPPORTED
 PNG_INTERNAL_FUNCTION(int,png_icc_check_length,(png_const_structrp png_ptr,
-   png_colorspacerp colorspace, png_const_charp name,
-   png_uint_32 profile_length), PNG_EMPTY);
+   png_const_charp name, png_uint_32 profile_length), PNG_EMPTY);
 #endif /* READ_iCCP */
 PNG_INTERNAL_FUNCTION(int,png_icc_check_header,(png_const_structrp png_ptr,
-   png_colorspacerp colorspace, png_const_charp name,
-   png_uint_32 profile_length,
+   png_const_charp name, png_uint_32 profile_length,
    png_const_bytep profile /* first 132 bytes only */, int color_type),
    PNG_EMPTY);
 PNG_INTERNAL_FUNCTION(int,png_icc_check_tag_table,(png_const_structrp png_ptr,
-   png_colorspacerp colorspace, png_const_charp name,
-   png_uint_32 profile_length,
+   png_const_charp name, png_uint_32 profile_length,
    png_const_bytep profile /* header plus whole tag table */), PNG_EMPTY);
-#ifdef PNG_sRGB_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_icc_set_sRGB,(
-   png_const_structrp png_ptr, png_colorspacerp colorspace,
-   png_const_bytep profile, uLong adler), PNG_EMPTY);
-   /* 'adler' is the Adler32 checksum of the uncompressed profile data. It may
-    * be zero to indicate that it is not available.  It is used, if provided,
-    * as a fast check on the profile when checking to see if it is sRGB.
-    */
-#endif
 #endif /* iCCP */
 
 #ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
-PNG_INTERNAL_FUNCTION(void,png_colorspace_set_rgb_coefficients,
-   (png_structrp png_ptr), PNG_EMPTY);
-   /* Set the rgb_to_gray coefficients from the colorspace Y values */
+PNG_INTERNAL_FUNCTION(void,png_set_rgb_coefficients, (png_structrp png_ptr),
+   PNG_EMPTY);
+   /* Set the rgb_to_gray coefficients from the cHRM Y values (if unset) */
 #endif /* READ_RGB_TO_GRAY */
-#endif /* COLORSPACE */
 
 /* Added at libpng version 1.4.0 */
 PNG_INTERNAL_FUNCTION(void,png_check_IHDR,(png_const_structrp png_ptr,
@@ -1985,8 +1952,10 @@ PNG_INTERNAL_FUNCTION(int,png_check_fp_string,(png_const_charp string,
    size_t size),PNG_EMPTY);
 #endif /* pCAL || sCAL */
 
-#if defined(PNG_GAMMA_SUPPORTED) ||\
-    defined(PNG_INCH_CONVERSIONS_SUPPORTED) || defined(PNG_READ_pHYs_SUPPORTED)
+#if defined(PNG_READ_GAMMA_SUPPORTED) ||\
+    defined(PNG_COLORSPACE_SUPPORTED) ||\
+    defined(PNG_INCH_CONVERSIONS_SUPPORTED) ||\
+    defined(PNG_READ_pHYs_SUPPORTED)
 /* Added at libpng version 1.5.0 */
 /* This is a utility to provide a*times/div (rounded) and indicate
  * if there is an overflow.  The result is a boolean - false (0)
@@ -1995,22 +1964,14 @@ PNG_INTERNAL_FUNCTION(int,png_check_fp_string,(png_const_charp string,
  */
 PNG_INTERNAL_FUNCTION(int,png_muldiv,(png_fixed_point_p res, png_fixed_point a,
    png_int_32 multiplied_by, png_int_32 divided_by),PNG_EMPTY);
-#endif
 
-#if defined(PNG_READ_GAMMA_SUPPORTED) || defined(PNG_INCH_CONVERSIONS_SUPPORTED)
-/* Same deal, but issue a warning on overflow and return 0. */
-PNG_INTERNAL_FUNCTION(png_fixed_point,png_muldiv_warn,
-   (png_const_structrp png_ptr, png_fixed_point a, png_int_32 multiplied_by,
-   png_int_32 divided_by),PNG_EMPTY);
-#endif
-
-#ifdef PNG_GAMMA_SUPPORTED
 /* Calculate a reciprocal - used for gamma values.  This returns
  * 0 if the argument is 0 in order to maintain an undefined value;
  * there are no warnings.
  */
 PNG_INTERNAL_FUNCTION(png_fixed_point,png_reciprocal,(png_fixed_point a),
    PNG_EMPTY);
+#endif
 
 #ifdef PNG_READ_GAMMA_SUPPORTED
 /* The same but gives a reciprocal of the product of two fixed point
@@ -2019,14 +1980,22 @@ PNG_INTERNAL_FUNCTION(png_fixed_point,png_reciprocal,(png_fixed_point a),
  */
 PNG_INTERNAL_FUNCTION(png_fixed_point,png_reciprocal2,(png_fixed_point a,
    png_fixed_point b),PNG_EMPTY);
-#endif
 
 /* Return true if the gamma value is significantly different from 1.0 */
 PNG_INTERNAL_FUNCTION(int,png_gamma_significant,(png_fixed_point gamma_value),
    PNG_EMPTY);
-#endif
 
-#ifdef PNG_READ_GAMMA_SUPPORTED
+/* PNGv3: 'resolve' the file gamma according to the new PNGv3 rules for colour
+ * space information.
+ *
+ * NOTE: this uses precisely those chunks that libpng supports.  For example it
+ * doesn't use iCCP and it can only use cICP for known and manageable
+ * transforms.  For this reason a gamma specified by png_set_gamma always takes
+ * precedence.
+ */
+PNG_INTERNAL_FUNCTION(png_fixed_point,png_resolve_file_gamma,
+   (png_const_structrp png_ptr),PNG_EMPTY);
+
 /* Internal fixed point gamma correction.  These APIs are called as
  * required to convert single values - they don't need to be fast,
  * they are not used when processing image pixel values.
@@ -2044,6 +2013,22 @@ PNG_INTERNAL_FUNCTION(void,png_destroy_gamma_table,(png_structrp png_ptr),
    PNG_EMPTY);
 PNG_INTERNAL_FUNCTION(void,png_build_gamma_table,(png_structrp png_ptr,
    int bit_depth),PNG_EMPTY);
+#endif /* READ_GAMMA */
+
+#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
+/* Set the RGB coefficients if not already set by png_set_rgb_to_gray */
+PNG_INTERNAL_FUNCTION(void,png_set_rgb_coefficients,(png_structrp png_ptr),
+   PNG_EMPTY);
+#endif
+
+#if defined(PNG_cHRM_SUPPORTED) || defined(PNG_READ_RGB_TO_GRAY_SUPPORTED)
+PNG_INTERNAL_FUNCTION(int,png_XYZ_from_xy,(png_XYZ *XYZ, const png_xy *xy),
+   PNG_EMPTY);
+#endif /* cHRM || READ_RGB_TO_GRAY */
+
+#ifdef PNG_COLORSPACE_SUPPORTED
+PNG_INTERNAL_FUNCTION(int,png_xy_from_XYZ,(png_xy *xy, const png_XYZ *XYZ),
+   PNG_EMPTY);
 #endif
 
 /* SIMPLIFIED READ/WRITE SUPPORT */
diff --git a/pngread.c b/pngread.c
index 07a39df6e..0fd364827 100644
--- a/pngread.c
+++ b/pngread.c
@@ -1,7 +1,6 @@
-
 /* pngread.c - read a PNG file
  *
- * Copyright (c) 2018-2024 Cosmin Truta
+ * Copyright (c) 2018-2025 Cosmin Truta
  * Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson
  * Copyright (c) 1996-1997 Andreas Dilger
  * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
@@ -132,14 +131,11 @@ png_read_info(png_structrp png_ptr, png_inforp info_ptr)
          png_ptr->mode |= PNG_AFTER_IDAT;
       }
 
-      /* This should be a binary subdivision search or a hash for
-       * matching the chunk name rather than a linear search.
-       */
       if (chunk_name == png_IHDR)
-         png_handle_IHDR(png_ptr, info_ptr, length);
+         png_handle_chunk(png_ptr, info_ptr, length);
 
       else if (chunk_name == png_IEND)
-         png_handle_IEND(png_ptr, info_ptr, length);
+         png_handle_chunk(png_ptr, info_ptr, length);
 
 #ifdef PNG_HANDLE_AS_UNKNOWN_SUPPORTED
       else if ((keep = png_chunk_unknown_handling(png_ptr, chunk_name)) != 0)
@@ -156,8 +152,6 @@ png_read_info(png_structrp png_ptr, png_inforp info_ptr)
          }
       }
 #endif
-      else if (chunk_name == png_PLTE)
-         png_handle_PLTE(png_ptr, info_ptr, length);
 
       else if (chunk_name == png_IDAT)
       {
@@ -165,99 +159,8 @@ png_read_info(png_structrp png_ptr, png_inforp info_ptr)
          break;
       }
 
-#ifdef PNG_READ_bKGD_SUPPORTED
-      else if (chunk_name == png_bKGD)
-         png_handle_bKGD(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_cHRM_SUPPORTED
-      else if (chunk_name == png_cHRM)
-         png_handle_cHRM(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_eXIf_SUPPORTED
-      else if (chunk_name == png_eXIf)
-         png_handle_eXIf(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_gAMA_SUPPORTED
-      else if (chunk_name == png_gAMA)
-         png_handle_gAMA(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_hIST_SUPPORTED
-      else if (chunk_name == png_hIST)
-         png_handle_hIST(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_oFFs_SUPPORTED
-      else if (chunk_name == png_oFFs)
-         png_handle_oFFs(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_pCAL_SUPPORTED
-      else if (chunk_name == png_pCAL)
-         png_handle_pCAL(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_sCAL_SUPPORTED
-      else if (chunk_name == png_sCAL)
-         png_handle_sCAL(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_pHYs_SUPPORTED
-      else if (chunk_name == png_pHYs)
-         png_handle_pHYs(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_sBIT_SUPPORTED
-      else if (chunk_name == png_sBIT)
-         png_handle_sBIT(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_sRGB_SUPPORTED
-      else if (chunk_name == png_sRGB)
-         png_handle_sRGB(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_iCCP_SUPPORTED
-      else if (chunk_name == png_iCCP)
-         png_handle_iCCP(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_sPLT_SUPPORTED
-      else if (chunk_name == png_sPLT)
-         png_handle_sPLT(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_tEXt_SUPPORTED
-      else if (chunk_name == png_tEXt)
-         png_handle_tEXt(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_tIME_SUPPORTED
-      else if (chunk_name == png_tIME)
-         png_handle_tIME(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_tRNS_SUPPORTED
-      else if (chunk_name == png_tRNS)
-         png_handle_tRNS(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_zTXt_SUPPORTED
-      else if (chunk_name == png_zTXt)
-         png_handle_zTXt(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_iTXt_SUPPORTED
-      else if (chunk_name == png_iTXt)
-         png_handle_iTXt(png_ptr, info_ptr, length);
-#endif
-
       else
-         png_handle_unknown(png_ptr, info_ptr, length,
-             PNG_HANDLE_CHUNK_AS_DEFAULT);
+         png_handle_chunk(png_ptr, info_ptr, length);
    }
 }
 #endif /* SEQUENTIAL_READ */
@@ -802,10 +705,10 @@ png_read_end(png_structrp png_ptr, png_inforp info_ptr)
          png_ptr->mode |= PNG_HAVE_CHUNK_AFTER_IDAT;
 
       if (chunk_name == png_IEND)
-         png_handle_IEND(png_ptr, info_ptr, length);
+         png_handle_chunk(png_ptr, info_ptr, length);
 
       else if (chunk_name == png_IHDR)
-         png_handle_IHDR(png_ptr, info_ptr, length);
+         png_handle_chunk(png_ptr, info_ptr, length);
 
       else if (info_ptr == NULL)
          png_crc_finish(png_ptr, length);
@@ -839,102 +742,9 @@ png_read_end(png_structrp png_ptr, png_inforp info_ptr)
 
          png_crc_finish(png_ptr, length);
       }
-      else if (chunk_name == png_PLTE)
-         png_handle_PLTE(png_ptr, info_ptr, length);
-
-#ifdef PNG_READ_bKGD_SUPPORTED
-      else if (chunk_name == png_bKGD)
-         png_handle_bKGD(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_cHRM_SUPPORTED
-      else if (chunk_name == png_cHRM)
-         png_handle_cHRM(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_eXIf_SUPPORTED
-      else if (chunk_name == png_eXIf)
-         png_handle_eXIf(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_gAMA_SUPPORTED
-      else if (chunk_name == png_gAMA)
-         png_handle_gAMA(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_hIST_SUPPORTED
-      else if (chunk_name == png_hIST)
-         png_handle_hIST(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_oFFs_SUPPORTED
-      else if (chunk_name == png_oFFs)
-         png_handle_oFFs(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_pCAL_SUPPORTED
-      else if (chunk_name == png_pCAL)
-         png_handle_pCAL(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_sCAL_SUPPORTED
-      else if (chunk_name == png_sCAL)
-         png_handle_sCAL(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_pHYs_SUPPORTED
-      else if (chunk_name == png_pHYs)
-         png_handle_pHYs(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_sBIT_SUPPORTED
-      else if (chunk_name == png_sBIT)
-         png_handle_sBIT(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_sRGB_SUPPORTED
-      else if (chunk_name == png_sRGB)
-         png_handle_sRGB(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_iCCP_SUPPORTED
-      else if (chunk_name == png_iCCP)
-         png_handle_iCCP(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_sPLT_SUPPORTED
-      else if (chunk_name == png_sPLT)
-         png_handle_sPLT(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_tEXt_SUPPORTED
-      else if (chunk_name == png_tEXt)
-         png_handle_tEXt(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_tIME_SUPPORTED
-      else if (chunk_name == png_tIME)
-         png_handle_tIME(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_tRNS_SUPPORTED
-      else if (chunk_name == png_tRNS)
-         png_handle_tRNS(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_zTXt_SUPPORTED
-      else if (chunk_name == png_zTXt)
-         png_handle_zTXt(png_ptr, info_ptr, length);
-#endif
-
-#ifdef PNG_READ_iTXt_SUPPORTED
-      else if (chunk_name == png_iTXt)
-         png_handle_iTXt(png_ptr, info_ptr, length);
-#endif
 
       else
-         png_handle_unknown(png_ptr, info_ptr, length,
-             PNG_HANDLE_CHUNK_AS_DEFAULT);
+         png_handle_chunk(png_ptr, info_ptr, length);
    } while ((png_ptr->mode & PNG_HAVE_IEND) == 0);
 }
 #endif /* SEQUENTIAL_READ */
@@ -1385,6 +1195,31 @@ png_image_format(png_structrp png_ptr)
    return format;
 }
 
+static int
+chromaticities_match_sRGB(const png_xy *xy)
+{
+#  define sRGB_TOLERANCE 1000
+   static const png_xy sRGB_xy = /* From ITU-R BT.709-3 */
+   {
+      /* color      x       y */
+      /* red   */ 64000, 33000,
+      /* green */ 30000, 60000,
+      /* blue  */ 15000,  6000,
+      /* white */ 31270, 32900
+   };
+
+   if (PNG_OUT_OF_RANGE(xy->whitex, sRGB_xy.whitex,sRGB_TOLERANCE) ||
+       PNG_OUT_OF_RANGE(xy->whitey, sRGB_xy.whitey,sRGB_TOLERANCE) ||
+       PNG_OUT_OF_RANGE(xy->redx,   sRGB_xy.redx,  sRGB_TOLERANCE) ||
+       PNG_OUT_OF_RANGE(xy->redy,   sRGB_xy.redy,  sRGB_TOLERANCE) ||
+       PNG_OUT_OF_RANGE(xy->greenx, sRGB_xy.greenx,sRGB_TOLERANCE) ||
+       PNG_OUT_OF_RANGE(xy->greeny, sRGB_xy.greeny,sRGB_TOLERANCE) ||
+       PNG_OUT_OF_RANGE(xy->bluex,  sRGB_xy.bluex, sRGB_TOLERANCE) ||
+       PNG_OUT_OF_RANGE(xy->bluey,  sRGB_xy.bluey, sRGB_TOLERANCE))
+      return 0;
+   return 1;
+}
+
 /* Is the given gamma significantly different from sRGB?  The test is the same
  * one used in pngrtran.c when deciding whether to do gamma correction.  The
  * arithmetic optimizes the division by using the fact that the inverse of the
@@ -1393,22 +1228,44 @@ png_image_format(png_structrp png_ptr)
 static int
 png_gamma_not_sRGB(png_fixed_point g)
 {
-   if (g < PNG_FP_1)
-   {
-      /* An uninitialized gamma is assumed to be sRGB for the simplified API. */
-      if (g == 0)
-         return 0;
-
-      return png_gamma_significant((g * 11 + 2)/5 /* i.e. *2.2, rounded */);
-   }
+   /* 1.6.47: use the same sanity checks as used in pngrtran.c */
+   if (g < PNG_LIB_GAMMA_MIN || g > PNG_LIB_GAMMA_MAX)
+      return 0; /* Includes the uninitialized value 0 */
 
-   return 1;
+   return png_gamma_significant((g * 11 + 2)/5 /* i.e. *2.2, rounded */);
 }
 
 /* Do the main body of a 'png_image_begin_read' function; read the PNG file
  * header and fill in all the information.  This is executed in a safe context,
  * unlike the init routine above.
  */
+static int
+png_image_is_not_sRGB(png_const_structrp png_ptr)
+{
+   /* Does the colorspace **not** match sRGB?  The flag is only set if the
+    * answer can be determined reliably.
+    *
+    * png_struct::chromaticities always exists since the simplified API
+    * requires rgb-to-gray.  The mDCV, cICP and cHRM chunks may all set it to
+    * a non-sRGB value, so it needs to be checked but **only** if one of
+    * those chunks occured in the file.
+    */
+   /* Highest priority: check to be safe. */
+   if (png_has_chunk(png_ptr, cICP) || png_has_chunk(png_ptr, mDCV))
+      return !chromaticities_match_sRGB(&png_ptr->chromaticities);
+
+   /* If the image is marked as sRGB then it is... */
+   if (png_has_chunk(png_ptr, sRGB))
+      return 0;
+
+   /* Last stop: cHRM, must check: */
+   if (png_has_chunk(png_ptr, cHRM))
+      return !chromaticities_match_sRGB(&png_ptr->chromaticities);
+
+   /* Else default to sRGB */
+   return 0;
+}
+
 static int
 png_image_read_header(png_voidp argument)
 {
@@ -1430,17 +1287,13 @@ png_image_read_header(png_voidp argument)
 
       image->format = format;
 
-#ifdef PNG_COLORSPACE_SUPPORTED
-      /* Does the colorspace match sRGB?  If there is no color endpoint
-       * (colorant) information assume yes, otherwise require the
-       * 'ENDPOINTS_MATCHP_sRGB' colorspace flag to have been set.  If the
-       * colorspace has been determined to be invalid ignore it.
+      /* Greyscale images don't (typically) have colour space information and
+       * using it is pretty much impossible, so use sRGB for grayscale (it
+       * doesn't matter r==g==b so the transform is irrelevant.)
        */
-      if ((format & PNG_FORMAT_FLAG_COLOR) != 0 && ((png_ptr->colorspace.flags
-         & (PNG_COLORSPACE_HAVE_ENDPOINTS|PNG_COLORSPACE_ENDPOINTS_MATCH_sRGB|
-            PNG_COLORSPACE_INVALID)) == PNG_COLORSPACE_HAVE_ENDPOINTS))
+      if ((format & PNG_FORMAT_FLAG_COLOR) != 0 &&
+          png_image_is_not_sRGB(png_ptr))
          image->flags |= PNG_IMAGE_FLAG_COLORSPACE_NOT_sRGB;
-#endif
    }
 
    /* We need the maximum number of entries regardless of the format the
@@ -1628,21 +1481,18 @@ png_image_skip_unused_chunks(png_structrp png_ptr)
     * potential vulnerability to security problems in the unused chunks.
     *
     * At present the iCCP chunk data isn't used, so iCCP chunk can be ignored
-    * too.  This allows the simplified API to be compiled without iCCP support,
-    * however if the support is there the chunk is still checked to detect
-    * errors (which are unfortunately quite common.)
+    * too.  This allows the simplified API to be compiled without iCCP support.
     */
    {
          static const png_byte chunks_to_process[] = {
             98,  75,  71,  68, '\0',  /* bKGD */
             99,  72,  82,  77, '\0',  /* cHRM */
+            99,  73,  67,  80, '\0',  /* cICP */
            103,  65,  77,  65, '\0',  /* gAMA */
-#        ifdef PNG_READ_iCCP_SUPPORTED
-           105,  67,  67,  80, '\0',  /* iCCP */
-#        endif
+           109,  68,  67,  86, '\0',  /* mDCV */
            115,  66,  73,  84, '\0',  /* sBIT */
            115,  82,  71,  66, '\0',  /* sRGB */
-           };
+         };
 
        /* Ignore unknown chunks and all other chunks except for the
         * IHDR, PLTE, tRNS, IDAT, and IEND chunks.
@@ -1671,7 +1521,15 @@ png_image_skip_unused_chunks(png_structrp png_ptr)
 static void
 set_file_encoding(png_image_read_control *display)
 {
-   png_fixed_point g = display->image->opaque->png_ptr->colorspace.gamma;
+   png_structrp png_ptr = display->image->opaque->png_ptr;
+   png_fixed_point g = png_resolve_file_gamma(png_ptr);
+
+   /* PNGv3: the result may be 0 however the 'default_gamma' should have been
+    * set before this is called so zero is an error:
+    */
+   if (g == 0)
+      png_error(png_ptr, "internal: default gamma not set");
+
    if (png_gamma_significant(g) != 0)
    {
       if (png_gamma_not_sRGB(g) != 0)
@@ -2159,24 +2017,18 @@ png_image_read_colormap(png_voidp argument)
    /* Default the input file gamma if required - this is necessary because
     * libpng assumes that if no gamma information is present the data is in the
     * output format, but the simplified API deduces the gamma from the input
-    * format.
+    * format.  The 'default' gamma value is also set by png_set_alpha_mode, but
+    * this is happening before any such call, so:
+    *
+    * TODO: should be an internal API and all this code should be copied into a
+    * single common gamma+colorspace file.
     */
-   if ((png_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_GAMMA) == 0)
-   {
-      /* Do this directly, not using the png_colorspace functions, to ensure
-       * that it happens even if the colorspace is invalid (though probably if
-       * it is the setting will be ignored)  Note that the same thing can be
-       * achieved at the application interface with png_set_gAMA.
-       */
-      if (png_ptr->bit_depth == 16 &&
-         (image->flags & PNG_IMAGE_FLAG_16BIT_sRGB) == 0)
-         png_ptr->colorspace.gamma = PNG_GAMMA_LINEAR;
-
-      else
-         png_ptr->colorspace.gamma = PNG_GAMMA_sRGB_INVERSE;
+   if (png_ptr->bit_depth == 16 &&
+      (image->flags & PNG_IMAGE_FLAG_16BIT_sRGB) == 0)
+      png_ptr->default_gamma = PNG_GAMMA_LINEAR;
 
-      png_ptr->colorspace.flags |= PNG_COLORSPACE_HAVE_GAMMA;
-   }
+   else
+      png_ptr->default_gamma = PNG_GAMMA_sRGB_INVERSE;
 
    /* Decide what to do based on the PNG color type of the input data.  The
     * utility function png_create_colormap_entry deals with most aspects of the
@@ -2554,6 +2406,8 @@ png_image_read_colormap(png_voidp argument)
 
             else
             {
+               const png_fixed_point gamma = png_resolve_file_gamma(png_ptr);
+
                /* Either the input or the output has no alpha channel, so there
                 * will be no non-opaque pixels in the color-map; it will just be
                 * grayscale.
@@ -2568,10 +2422,13 @@ png_image_read_colormap(png_voidp argument)
                 * this case and doing it in the palette; this will result in
                 * duplicate palette entries, but that's better than the
                 * alternative of double gamma correction.
+                *
+                * NOTE: PNGv3: check the resolved result of all the potentially
+                * different colour space chunks.
                 */
                if ((png_ptr->color_type == PNG_COLOR_TYPE_RGB_ALPHA ||
                   png_ptr->num_trans > 0) &&
-                  png_gamma_not_sRGB(png_ptr->colorspace.gamma) != 0)
+                  png_gamma_not_sRGB(gamma) != 0)
                {
                   cmap_entries = (unsigned int)make_gray_file_colormap(display);
                   data_encoding = P_FILE;
@@ -2603,8 +2460,8 @@ png_image_read_colormap(png_voidp argument)
                      if (output_encoding == P_sRGB)
                         gray = png_sRGB_table[gray]; /* now P_LINEAR */
 
-                     gray = PNG_DIV257(png_gamma_16bit_correct(gray,
-                         png_ptr->colorspace.gamma)); /* now P_FILE */
+                     gray = PNG_DIV257(png_gamma_16bit_correct(gray, gamma));
+                        /* now P_FILE */
 
                      /* And make sure the corresponding palette entry contains
                       * exactly the required sRGB value.
@@ -3735,6 +3592,12 @@ png_image_read_direct(png_voidp argument)
       /* Set the gamma appropriately, linear for 16-bit input, sRGB otherwise.
        */
       {
+         /* This is safe but should no longer be necessary as
+          * png_ptr->default_gamma should have been set after the
+          * info-before-IDAT was read in png_image_read_header.
+          *
+          * TODO: 1.8: remove this and see what happens.
+          */
          png_fixed_point input_gamma_default;
 
          if ((base_format & PNG_FORMAT_FLAG_LINEAR) != 0 &&
@@ -3790,8 +3653,9 @@ png_image_read_direct(png_voidp argument)
           * yet; it's set below.  png_struct::gamma, however, is set to the
           * final value.
           */
-         if (png_muldiv(&gtest, output_gamma, png_ptr->colorspace.gamma,
-             PNG_FP_1) != 0 && png_gamma_significant(gtest) == 0)
+         if (png_muldiv(&gtest, output_gamma,
+                  png_resolve_file_gamma(png_ptr), PNG_FP_1) != 0 &&
+             png_gamma_significant(gtest) == 0)
             do_local_background = 0;
 
          else if (mode == PNG_ALPHA_STANDARD)
diff --git a/pngrio.c b/pngrio.c
index 794635810..3b137f275 100644
--- a/pngrio.c
+++ b/pngrio.c
@@ -1,4 +1,3 @@
-
 /* pngrio.c - functions for data input
  *
  * Copyright (c) 2018 Cosmin Truta
diff --git a/pngrtran.c b/pngrtran.c
index 1526123e0..a6ce30a52 100644
--- a/pngrtran.c
+++ b/pngrtran.c
@@ -1,4 +1,3 @@
-
 /* pngrtran.c - transforms the data in a row for PNG readers
  *
  * Copyright (c) 2018-2024 Cosmin Truta
@@ -219,9 +218,59 @@ png_set_strip_alpha(png_structrp png_ptr)
 #endif
 
 #if defined(PNG_READ_ALPHA_MODE_SUPPORTED) || defined(PNG_READ_GAMMA_SUPPORTED)
+/* PNGv3 conformance: this private API exists to resolve the now mandatory error
+ * resolution when multiple conflicting sources of gamma or colour space
+ * information are available.
+ *
+ * Terminology (assuming power law, "gamma", encodings):
+ *    "screen" gamma: a power law imposed by the output device when digital
+ *    samples are converted to visible light output.  The EOTF - volage to
+ *    luminance on output.
+ *
+ *    "file" gamma: a power law used to encode luminance levels from the input
+ *    data (the scene or the mastering display system) into digital voltages.
+ *    The OETF - luminance to voltage on input.
+ *
+ *    gamma "correction": a power law matching the **inverse** of the overall
+ *    transfer function from input luminance levels to output levels.  The
+ *    **inverse** of the OOTF; the correction "corrects" for the OOTF by aiming
+ *    to make the overall OOTF (including the correction) linear.
+ *
+ * It is important to understand this terminology because the defined terms are
+ * scattered throughout the libpng code and it is very easy to end up with the
+ * inverse of the power law required.
+ *
+ * Variable and struct::member names:
+ *    file_gamma        OETF  how the PNG data was encoded
+ *
+ *    screen_gamma      EOTF  how the screen will decode digital levels
+ *
+ *    -- not used --    OOTF  the net effect OETF x EOTF
+ *    gamma_correction        the inverse of OOTF to make the result linear
+ *
+ * All versions of libpng require a call to "png_set_gamma" to establish the
+ * "screen" gamma, the power law representing the EOTF.  png_set_gamma may also
+ * set or default the "file" gamma; the OETF.  gamma_correction is calculated
+ * internally.
+ *
+ * The earliest libpng versions required file_gamma to be supplied to set_gamma.
+ * Later versions started allowing png_set_gamma and, later, png_set_alpha_mode,
+ * to cause defaulting from the file data.
+ *
+ * PNGv3 mandated a particular form for this defaulting, one that is compatible
+ * with what libpng did except that if libpng detected inconsistencies it marked
+ * all the chunks as "invalid".  PNGv3 effectively invalidates this prior code.
+ *
+ * Behaviour implemented below:
+ *    translate_gamma_flags(gamma, is_screen)
+ *       The libpng-1.6 API for the gamma parameters to libpng APIs
+ *       (png_set_gamma and png_set_alpha_mode at present).  This allows the
+ *       'gamma' value to be passed as a png_fixed_point number or as one of a
+ *       set of integral values for specific "well known" examples of transfer
+ *       functions.  This is compatible with PNGv3.
+ */
 static png_fixed_point
-translate_gamma_flags(png_structrp png_ptr, png_fixed_point output_gamma,
-    int is_screen)
+translate_gamma_flags(png_fixed_point output_gamma, int is_screen)
 {
    /* Check for flag values.  The main reason for having the old Mac value as a
     * flag is that it is pretty near impossible to work out what the correct
@@ -231,14 +280,6 @@ translate_gamma_flags(png_structrp png_ptr, png_fixed_point output_gamma,
    if (output_gamma == PNG_DEFAULT_sRGB ||
       output_gamma == PNG_FP_1 / PNG_DEFAULT_sRGB)
    {
-      /* If there is no sRGB support this just sets the gamma to the standard
-       * sRGB value.  (This is a side effect of using this function!)
-       */
-#     ifdef PNG_READ_sRGB_SUPPORTED
-         png_ptr->flags |= PNG_FLAG_ASSUME_sRGB;
-#     else
-         PNG_UNUSED(png_ptr)
-#     endif
       if (is_screen != 0)
          output_gamma = PNG_GAMMA_sRGB;
       else
@@ -280,6 +321,33 @@ convert_gamma_value(png_structrp png_ptr, double output_gamma)
    return (png_fixed_point)output_gamma;
 }
 #  endif
+
+static int
+unsupported_gamma(png_structrp png_ptr, png_fixed_point gamma, int warn)
+{
+   /* Validate a gamma value to ensure it is in a reasonable range.  The value
+    * is expected to be 1 or greater, but this range test allows for some
+    * viewing correction values.  The intent is to weed out the API users
+    * who might use the inverse of the gamma value accidentally!
+    *
+    * 1.6.47: apply the test in png_set_gamma as well but only warn and return
+    * false if it fires.
+    *
+    * TODO: 1.8: make this an app_error in png_set_gamma as well.
+    */
+   if (gamma < PNG_LIB_GAMMA_MIN || gamma > PNG_LIB_GAMMA_MAX)
+   {
+#     define msg "gamma out of supported range"
+      if (warn)
+         png_app_warning(png_ptr, msg);
+      else
+         png_app_error(png_ptr, msg);
+      return 1;
+#     undef msg
+   }
+
+   return 0;
+}
 #endif /* READ_ALPHA_MODE || READ_GAMMA */
 
 #ifdef PNG_READ_ALPHA_MODE_SUPPORTED
@@ -287,31 +355,29 @@ void PNGFAPI
 png_set_alpha_mode_fixed(png_structrp png_ptr, int mode,
     png_fixed_point output_gamma)
 {
-   int compose = 0;
    png_fixed_point file_gamma;
+   int compose = 0;
 
    png_debug(1, "in png_set_alpha_mode_fixed");
 
    if (png_rtran_ok(png_ptr, 0) == 0)
       return;
 
-   output_gamma = translate_gamma_flags(png_ptr, output_gamma, 1/*screen*/);
-
-   /* Validate the value to ensure it is in a reasonable range.  The value
-    * is expected to be 1 or greater, but this range test allows for some
-    * viewing correction values.  The intent is to weed out the API users
-    * who might use the inverse of the gamma value accidentally!
-    *
-    * In libpng 1.6.0, we changed from 0.07..3 to 0.01..100, to accommodate
-    * the optimal 16-bit gamma of 36 and its reciprocal.
-    */
-   if (output_gamma < 1000 || output_gamma > 10000000)
-      png_error(png_ptr, "output gamma out of expected range");
+   output_gamma = translate_gamma_flags(output_gamma, 1/*screen*/);
+   if (unsupported_gamma(png_ptr, output_gamma, 0/*error*/))
+      return;
 
    /* The default file gamma is the inverse of the output gamma; the output
-    * gamma may be changed below so get the file value first:
+    * gamma may be changed below so get the file value first.  The default_gamma
+    * is set here and from the simplified API (which uses a different algorithm)
+    * so don't overwrite a set value:
     */
-   file_gamma = png_reciprocal(output_gamma);
+   file_gamma = png_ptr->default_gamma;
+   if (file_gamma == 0)
+   {
+      file_gamma = png_reciprocal(output_gamma);
+      png_ptr->default_gamma = file_gamma;
+   }
 
    /* There are really 8 possibilities here, composed of any combination
     * of:
@@ -362,17 +428,7 @@ png_set_alpha_mode_fixed(png_structrp png_ptr, int mode,
          png_error(png_ptr, "invalid alpha mode");
    }
 
-   /* Only set the default gamma if the file gamma has not been set (this has
-    * the side effect that the gamma in a second call to png_set_alpha_mode will
-    * be ignored.)
-    */
-   if (png_ptr->colorspace.gamma == 0)
-   {
-      png_ptr->colorspace.gamma = file_gamma;
-      png_ptr->colorspace.flags |= PNG_COLORSPACE_HAVE_GAMMA;
-   }
-
-   /* But always set the output gamma: */
+   /* Set the screen gamma values: */
    png_ptr->screen_gamma = output_gamma;
 
    /* Finally, if pre-multiplying, set the background fields to achieve the
@@ -382,7 +438,7 @@ png_set_alpha_mode_fixed(png_structrp png_ptr, int mode,
    {
       /* And obtain alpha pre-multiplication by composing on black: */
       memset(&png_ptr->background, 0, (sizeof png_ptr->background));
-      png_ptr->background_gamma = png_ptr->colorspace.gamma; /* just in case */
+      png_ptr->background_gamma = file_gamma; /* just in case */
       png_ptr->background_gamma_type = PNG_BACKGROUND_GAMMA_FILE;
       png_ptr->transformations &= ~PNG_BACKGROUND_EXPAND;
 
@@ -820,8 +876,8 @@ png_set_gamma_fixed(png_structrp png_ptr, png_fixed_point scrn_gamma,
       return;
 
    /* New in libpng-1.5.4 - reserve particular negative values as flags. */
-   scrn_gamma = translate_gamma_flags(png_ptr, scrn_gamma, 1/*screen*/);
-   file_gamma = translate_gamma_flags(png_ptr, file_gamma, 0/*file*/);
+   scrn_gamma = translate_gamma_flags(scrn_gamma, 1/*screen*/);
+   file_gamma = translate_gamma_flags(file_gamma, 0/*file*/);
 
    /* Checking the gamma values for being >0 was added in 1.5.4 along with the
     * premultiplied alpha support; this actually hides an undocumented feature
@@ -835,17 +891,19 @@ png_set_gamma_fixed(png_structrp png_ptr, png_fixed_point scrn_gamma,
     * libpng-1.6.0.
     */
    if (file_gamma <= 0)
-      png_error(png_ptr, "invalid file gamma in png_set_gamma");
-
+      png_app_error(png_ptr, "invalid file gamma in png_set_gamma");
    if (scrn_gamma <= 0)
-      png_error(png_ptr, "invalid screen gamma in png_set_gamma");
+      png_app_error(png_ptr, "invalid screen gamma in png_set_gamma");
 
-   /* Set the gamma values unconditionally - this overrides the value in the PNG
-    * file if a gAMA chunk was present.  png_set_alpha_mode provides a
-    * different, easier, way to default the file gamma.
+   if (unsupported_gamma(png_ptr, file_gamma, 1/*warn*/) ||
+       unsupported_gamma(png_ptr, scrn_gamma, 1/*warn*/))
+      return;
+
+   /* 1.6.47: png_struct::file_gamma and png_struct::screen_gamma are now only
+    * written by this API.  This removes dependencies on the order of API calls
+    * and allows the complex gamma checks to be delayed until needed.
     */
-   png_ptr->colorspace.gamma = file_gamma;
-   png_ptr->colorspace.flags |= PNG_COLORSPACE_HAVE_GAMMA;
+   png_ptr->file_gamma = file_gamma;
    png_ptr->screen_gamma = scrn_gamma;
 }
 
@@ -1023,26 +1081,9 @@ png_set_rgb_to_gray_fixed(png_structrp png_ptr, int error_action,
          png_ptr->rgb_to_gray_coefficients_set = 1;
       }
 
-      else
-      {
-         if (red >= 0 && green >= 0)
-            png_app_warning(png_ptr,
-                "ignoring out of range rgb_to_gray coefficients");
-
-         /* Use the defaults, from the cHRM chunk if set, else the historical
-          * values which are close to the sRGB/HDTV/ITU-Rec 709 values.  See
-          * png_do_rgb_to_gray for more discussion of the values.  In this case
-          * the coefficients are not marked as 'set' and are not overwritten if
-          * something has already provided a default.
-          */
-         if (png_ptr->rgb_to_gray_red_coeff == 0 &&
-             png_ptr->rgb_to_gray_green_coeff == 0)
-         {
-            png_ptr->rgb_to_gray_red_coeff   = 6968;
-            png_ptr->rgb_to_gray_green_coeff = 23434;
-            /* png_ptr->rgb_to_gray_blue_coeff  = 2366; */
-         }
-      }
+      else if (red >= 0 && green >= 0)
+         png_app_warning(png_ptr,
+               "ignoring out of range rgb_to_gray coefficients");
    }
 }
 
@@ -1283,6 +1324,80 @@ png_init_rgb_transformations(png_structrp png_ptr)
 #endif /* READ_EXPAND && READ_BACKGROUND */
 }
 
+#ifdef PNG_READ_GAMMA_SUPPORTED
+png_fixed_point /* PRIVATE */
+png_resolve_file_gamma(png_const_structrp png_ptr)
+{
+   png_fixed_point file_gamma;
+
+   /* The file gamma is determined by these precedence rules, in this order
+    * (i.e. use the first value found):
+    *
+    *    png_set_gamma; png_struct::file_gammma if not zero, then:
+    *    png_struct::chunk_gamma if not 0 (determined the PNGv3 rules), then:
+    *    png_set_gamma; 1/png_struct::screen_gamma if not zero
+    *
+    *    0 (i.e. do no gamma handling)
+    */
+   file_gamma = png_ptr->file_gamma;
+   if (file_gamma != 0)
+      return file_gamma;
+
+   file_gamma = png_ptr->chunk_gamma;
+   if (file_gamma != 0)
+      return file_gamma;
+
+   file_gamma = png_ptr->default_gamma;
+   if (file_gamma != 0)
+      return file_gamma;
+
+   /* If png_reciprocal oveflows it returns 0 which indicates to the caller that
+    * there is no usable file gamma.  (The checks added to png_set_gamma and
+    * png_set_alpha_mode should prevent a screen_gamma which would overflow.)
+    */
+   if (png_ptr->screen_gamma != 0)
+      file_gamma = png_reciprocal(png_ptr->screen_gamma);
+
+   return file_gamma;
+}
+
+static int
+png_init_gamma_values(png_structrp png_ptr)
+{
+   /* The following temporary indicates if overall gamma correction is
+    * required.
+    */
+   int gamma_correction = 0;
+   png_fixed_point file_gamma, screen_gamma;
+
+   /* Resolve the file_gamma.  See above: if png_ptr::screen_gamma is set
+    * file_gamma will always be set here:
+    */
+   file_gamma = png_resolve_file_gamma(png_ptr);
+   screen_gamma = png_ptr->screen_gamma;
+
+   if (file_gamma > 0) /* file has been set */
+   {
+      if (screen_gamma > 0) /* screen set too */
+         gamma_correction = png_gamma_threshold(file_gamma, screen_gamma);
+
+      else
+         /* Assume the output matches the input; a long time default behavior
+          * of libpng, although the standard has nothing to say about this.
+          */
+         screen_gamma = png_reciprocal(file_gamma);
+   }
+
+   else /* both unset, prevent corrections: */
+      file_gamma = screen_gamma = PNG_FP_1;
+
+   png_ptr->file_gamma = file_gamma;
+   png_ptr->screen_gamma = screen_gamma;
+   return gamma_correction;
+
+}
+#endif /* READ_GAMMA */
+
 void /* PRIVATE */
 png_init_read_transformations(png_structrp png_ptr)
 {
@@ -1302,59 +1417,22 @@ png_init_read_transformations(png_structrp png_ptr)
     * the test needs to be performed later - here.  In addition prior to 1.5.4
     * the tests were repeated for the PALETTE color type here - this is no
     * longer necessary (and doesn't seem to have been necessary before.)
+    *
+    * PNGv3: the new mandatory precedence/priority rules for colour space chunks
+    * are handled here (by calling the above function).
+    *
+    * Turn the gamma transformation on or off as appropriate.  Notice that
+    * PNG_GAMMA just refers to the file->screen correction.  Alpha composition
+    * may independently cause gamma correction because it needs linear data
+    * (e.g. if the file has a gAMA chunk but the screen gamma hasn't been
+    * specified.)  In any case this flag may get turned off in the code
+    * immediately below if the transform can be handled outside the row loop.
     */
-   {
-      /* The following temporary indicates if overall gamma correction is
-       * required.
-       */
-      int gamma_correction = 0;
-
-      if (png_ptr->colorspace.gamma != 0) /* has been set */
-      {
-         if (png_ptr->screen_gamma != 0) /* screen set too */
-            gamma_correction = png_gamma_threshold(png_ptr->colorspace.gamma,
-                png_ptr->screen_gamma);
+   if (png_init_gamma_values(png_ptr) != 0)
+      png_ptr->transformations |= PNG_GAMMA;
 
-         else
-            /* Assume the output matches the input; a long time default behavior
-             * of libpng, although the standard has nothing to say about this.
-             */
-            png_ptr->screen_gamma = png_reciprocal(png_ptr->colorspace.gamma);
-      }
-
-      else if (png_ptr->screen_gamma != 0)
-         /* The converse - assume the file matches the screen, note that this
-          * perhaps undesirable default can (from 1.5.4) be changed by calling
-          * png_set_alpha_mode (even if the alpha handling mode isn't required
-          * or isn't changed from the default.)
-          */
-         png_ptr->colorspace.gamma = png_reciprocal(png_ptr->screen_gamma);
-
-      else /* neither are set */
-         /* Just in case the following prevents any processing - file and screen
-          * are both assumed to be linear and there is no way to introduce a
-          * third gamma value other than png_set_background with 'UNIQUE', and,
-          * prior to 1.5.4
-          */
-         png_ptr->screen_gamma = png_ptr->colorspace.gamma = PNG_FP_1;
-
-      /* We have a gamma value now. */
-      png_ptr->colorspace.flags |= PNG_COLORSPACE_HAVE_GAMMA;
-
-      /* Now turn the gamma transformation on or off as appropriate.  Notice
-       * that PNG_GAMMA just refers to the file->screen correction.  Alpha
-       * composition may independently cause gamma correction because it needs
-       * linear data (e.g. if the file has a gAMA chunk but the screen gamma
-       * hasn't been specified.)  In any case this flag may get turned off in
-       * the code immediately below if the transform can be handled outside the
-       * row loop.
-       */
-      if (gamma_correction != 0)
-         png_ptr->transformations |= PNG_GAMMA;
-
-      else
-         png_ptr->transformations &= ~PNG_GAMMA;
-   }
+   else
+      png_ptr->transformations &= ~PNG_GAMMA;
 #endif
 
    /* Certain transformations have the effect of preventing other
@@ -1426,7 +1504,7 @@ png_init_read_transformations(png_structrp png_ptr)
     * appropriately.
     */
    if ((png_ptr->transformations & PNG_RGB_TO_GRAY) != 0)
-      png_colorspace_set_rgb_coefficients(png_ptr);
+      png_set_rgb_coefficients(png_ptr);
 #endif
 
 #ifdef PNG_READ_GRAY_TO_RGB_SUPPORTED
@@ -1569,10 +1647,10 @@ png_init_read_transformations(png_structrp png_ptr)
     */
    if ((png_ptr->transformations & PNG_GAMMA) != 0 ||
        ((png_ptr->transformations & PNG_RGB_TO_GRAY) != 0 &&
-        (png_gamma_significant(png_ptr->colorspace.gamma) != 0 ||
+        (png_gamma_significant(png_ptr->file_gamma) != 0 ||
          png_gamma_significant(png_ptr->screen_gamma) != 0)) ||
         ((png_ptr->transformations & PNG_COMPOSE) != 0 &&
-         (png_gamma_significant(png_ptr->colorspace.gamma) != 0 ||
+         (png_gamma_significant(png_ptr->file_gamma) != 0 ||
           png_gamma_significant(png_ptr->screen_gamma) != 0
 #  ifdef PNG_READ_BACKGROUND_SUPPORTED
          || (png_ptr->background_gamma_type == PNG_BACKGROUND_GAMMA_UNIQUE &&
@@ -1628,8 +1706,8 @@ png_init_read_transformations(png_structrp png_ptr)
                      break;
 
                   case PNG_BACKGROUND_GAMMA_FILE:
-                     g = png_reciprocal(png_ptr->colorspace.gamma);
-                     gs = png_reciprocal2(png_ptr->colorspace.gamma,
+                     g = png_reciprocal(png_ptr->file_gamma);
+                     gs = png_reciprocal2(png_ptr->file_gamma,
                          png_ptr->screen_gamma);
                      break;
 
@@ -1737,8 +1815,8 @@ png_init_read_transformations(png_structrp png_ptr)
                   break;
 
                case PNG_BACKGROUND_GAMMA_FILE:
-                  g = png_reciprocal(png_ptr->colorspace.gamma);
-                  gs = png_reciprocal2(png_ptr->colorspace.gamma,
+                  g = png_reciprocal(png_ptr->file_gamma);
+                  gs = png_reciprocal2(png_ptr->file_gamma,
                       png_ptr->screen_gamma);
                   break;
 
@@ -1988,11 +2066,11 @@ png_read_transform_info(png_structrp png_ptr, png_inforp info_ptr)
     * been called before this from png_read_update_info->png_read_start_row
     * sometimes does the gamma transform and cancels the flag.
     *
-    * TODO: this looks wrong; the info_ptr should end up with a gamma equal to
-    * the screen_gamma value.  The following probably results in weirdness if
-    * the info_ptr is used by the app after the rows have been read.
+    * TODO: this is confusing.  It only changes the result of png_get_gAMA and,
+    * yes, it does return the value that the transformed data effectively has
+    * but does any app really understand this?
     */
-   info_ptr->colorspace.gamma = png_ptr->colorspace.gamma;
+   info_ptr->gamma = png_ptr->file_gamma;
 #endif
 
    if (info_ptr->bit_depth == 16)
diff --git a/pngrutil.c b/pngrutil.c
index d31dc21da..d0f3ed35d 100644
--- a/pngrutil.c
+++ b/pngrutil.c
@@ -1,4 +1,3 @@
-
 /* pngrutil.c - utilities to read a PNG file
  *
  * Copyright (c) 2018-2024 Cosmin Truta
@@ -18,6 +17,26 @@
 
 #ifdef PNG_READ_SUPPORTED
 
+/* The minimum 'zlib' stream is assumed to be just the 2 byte header, 5 bytes
+ * minimum 'deflate' stream, and the 4 byte checksum.
+ */
+#define LZ77Min  (2U+5U+4U)
+
+#ifdef PNG_READ_INTERLACING_SUPPORTED
+/* Arrays to facilitate interlacing - use pass (0 - 6) as index. */
+
+/* Start of interlace block */
+static const png_byte png_pass_start[7] = {0, 4, 0, 2, 0, 1, 0};
+/* Offset to next interlace block */
+static const png_byte png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
+/* Start of interlace block in the y direction */
+static const png_byte png_pass_ystart[7] = {0, 0, 4, 0, 2, 0, 1};
+/* Offset to next interlace block in the y direction */
+static const png_byte png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
+
+/* TODO: Move these arrays to a common utility module to avoid duplication. */
+#endif
+
 png_uint_32 PNGAPI
 png_get_uint_31(png_const_structrp png_ptr, png_const_bytep buf)
 {
@@ -29,30 +48,6 @@ png_get_uint_31(png_const_structrp png_ptr, png_const_bytep buf)
    return uval;
 }
 
-#if defined(PNG_READ_gAMA_SUPPORTED) || defined(PNG_READ_cHRM_SUPPORTED)
-/* The following is a variation on the above for use with the fixed
- * point values used for gAMA and cHRM.  Instead of png_error it
- * issues a warning and returns (-1) - an invalid value because both
- * gAMA and cHRM use *unsigned* integers for fixed point values.
- */
-#define PNG_FIXED_ERROR (-1)
-
-static png_fixed_point /* PRIVATE */
-png_get_fixed_point(png_structrp png_ptr, png_const_bytep buf)
-{
-   png_uint_32 uval = png_get_uint_32(buf);
-
-   if (uval <= PNG_UINT_31_MAX)
-      return (png_fixed_point)uval; /* known to be in range */
-
-   /* The caller can turn off the warning by passing NULL. */
-   if (png_ptr != NULL)
-      png_warning(png_ptr, "PNG fixed point integer out of range");
-
-   return PNG_FIXED_ERROR;
-}
-#endif
-
 #ifdef PNG_READ_INT_FUNCTIONS_SUPPORTED
 /* NOTE: the read macros will obscure these definitions, so that if
  * PNG_USE_READ_MACROS is set the library will not use them internally,
@@ -149,6 +144,38 @@ png_read_sig(png_structrp png_ptr, png_inforp info_ptr)
       png_ptr->mode |= PNG_HAVE_PNG_SIGNATURE;
 }
 
+/* This function is called to verify that a chunk name is valid.
+ * Do this using the bit-whacking approach from contrib/tools/pngfix.c
+ *
+ * Copied from libpng 1.7.
+ */
+static int
+check_chunk_name(png_uint_32 name)
+{
+   png_uint_32 t;
+
+   /* Remove bit 5 from all but the reserved byte; this means
+    * every 8-bit unit must be in the range 65-90 to be valid.
+    * So bit 5 must be zero, bit 6 must be set and bit 7 zero.
+    */
+   name &= ~PNG_U32(32,32,0,32);
+   t = (name & ~0x1f1f1f1fU) ^ 0x40404040U;
+
+   /* Subtract 65 for each 8-bit quantity, this must not
+    * overflow and each byte must then be in the range 0-25.
+    */
+   name -= PNG_U32(65,65,65,65);
+   t |= name;
+
+   /* Subtract 26, handling the overflow which should set the
+    * top three bits of each byte.
+    */
+   name -= PNG_U32(25,25,25,26);
+   t |= ~name;
+
+   return (t & 0xe0e0e0e0U) == 0U;
+}
+
 /* Read the chunk header (length + type name).
  * Put the type name into png_ptr->chunk_name, and return the length.
  */
@@ -156,33 +183,36 @@ png_uint_32 /* PRIVATE */
 png_read_chunk_header(png_structrp png_ptr)
 {
    png_byte buf[8];
-   png_uint_32 length;
+   png_uint_32 chunk_name, length;
 
 #ifdef PNG_IO_STATE_SUPPORTED
    png_ptr->io_state = PNG_IO_READING | PNG_IO_CHUNK_HDR;
 #endif
 
-   /* Read the length and the chunk name.
-    * This must be performed in a single I/O call.
+   /* Read the length and the chunk name.  png_struct::chunk_name is immediately
+    * updated even if they are detectably wrong.  This aids error message
+    * handling by allowing png_chunk_error to be used.
     */
    png_read_data(png_ptr, buf, 8);
    length = png_get_uint_31(png_ptr, buf);
+   png_ptr->chunk_name = chunk_name = PNG_CHUNK_FROM_STRING(buf+4);
 
-   /* Put the chunk name into png_ptr->chunk_name. */
-   png_ptr->chunk_name = PNG_CHUNK_FROM_STRING(buf+4);
+   /* Reset the crc and run it over the chunk name. */
+   png_reset_crc(png_ptr);
+   png_calculate_crc(png_ptr, buf + 4, 4);
 
    png_debug2(0, "Reading chunk typeid = 0x%lx, length = %lu",
        (unsigned long)png_ptr->chunk_name, (unsigned long)length);
 
-   /* Reset the crc and run it over the chunk name. */
-   png_reset_crc(png_ptr);
-   png_calculate_crc(png_ptr, buf + 4, 4);
+   /* Sanity check the length (first by <= 0x80) and the chunk name.  An error
+    * here indicates a broken stream and libpng has no recovery from this.
+    */
+   if (buf[0] >= 0x80U)
+      png_chunk_error(png_ptr, "bad header (invalid length)");
 
    /* Check to see if chunk name is valid. */
-   png_check_chunk_name(png_ptr, png_ptr->chunk_name);
-
-   /* Check for too-large chunk length */
-   png_check_chunk_length(png_ptr, length);
+   if (!check_chunk_name(chunk_name))
+      png_chunk_error(png_ptr, "bad header (invalid type)");
 
 #ifdef PNG_IO_STATE_SUPPORTED
    png_ptr->io_state = PNG_IO_READING | PNG_IO_CHUNK_DATA;
@@ -202,13 +232,85 @@ png_crc_read(png_structrp png_ptr, png_bytep buf, png_uint_32 length)
    png_calculate_crc(png_ptr, buf, length);
 }
 
+/* Compare the CRC stored in the PNG file with that calculated by libpng from
+ * the data it has read thus far.
+ */
+static int
+png_crc_error(png_structrp png_ptr, int handle_as_ancillary)
+{
+   png_byte crc_bytes[4];
+   png_uint_32 crc;
+   int need_crc = 1;
+
+   /* There are four flags two for ancillary and two for critical chunks.  The
+    * default setting of these flags is all zero.
+    *
+    * PNG_FLAG_CRC_ANCILLARY_USE
+    * PNG_FLAG_CRC_ANCILLARY_NOWARN
+    *  USE+NOWARN: no CRC calculation (implemented here), else;
+    *  NOWARN:     png_chunk_error on error (implemented in png_crc_finish)
+    *  else:       png_chunk_warning on error (implemented in png_crc_finish)
+    *              This is the default.
+    *
+    *    I.e. NOWARN without USE produces png_chunk_error.  The default setting
+    *    where neither are set does the same thing.
+    *
+    * PNG_FLAG_CRC_CRITICAL_USE
+    * PNG_FLAG_CRC_CRITICAL_IGNORE
+    *  IGNORE: no CRC calculation (implemented here), else;
+    *  USE:    png_chunk_warning on error (implemented in png_crc_finish)
+    *  else:   png_chunk_error on error (implemented in png_crc_finish)
+    *          This is the default.
+    *
+    * This arose because of original mis-implementation and has persisted for
+    * compatibility reasons.
+    *
+    * TODO: the flag names are internal so maybe this can be changed to
+    * something comprehensible.
+    */
+   if (handle_as_ancillary || PNG_CHUNK_ANCILLARY(png_ptr->chunk_name) != 0)
+   {
+      if ((png_ptr->flags & PNG_FLAG_CRC_ANCILLARY_MASK) ==
+          (PNG_FLAG_CRC_ANCILLARY_USE | PNG_FLAG_CRC_ANCILLARY_NOWARN))
+         need_crc = 0;
+   }
+
+   else /* critical */
+   {
+      if ((png_ptr->flags & PNG_FLAG_CRC_CRITICAL_IGNORE) != 0)
+         need_crc = 0;
+   }
+
+#ifdef PNG_IO_STATE_SUPPORTED
+   png_ptr->io_state = PNG_IO_READING | PNG_IO_CHUNK_CRC;
+#endif
+
+   /* The chunk CRC must be serialized in a single I/O call. */
+   png_read_data(png_ptr, crc_bytes, 4);
+
+   if (need_crc != 0)
+   {
+      crc = png_get_uint_32(crc_bytes);
+      return crc != png_ptr->crc;
+   }
+
+   else
+      return 0;
+}
+
 /* Optionally skip data and then check the CRC.  Depending on whether we
  * are reading an ancillary or critical chunk, and how the program has set
  * things up, we may calculate the CRC on the data and print a message.
  * Returns '1' if there was a CRC error, '0' otherwise.
+ *
+ * There is one public version which is used in most places and another which
+ * takes the value for the 'critical' flag to check.  This allows PLTE and IEND
+ * handling code to ignore the CRC error and removes some confusing code
+ * duplication.
  */
-int /* PRIVATE */
-png_crc_finish(png_structrp png_ptr, png_uint_32 skip)
+static int
+png_crc_finish_critical(png_structrp png_ptr, png_uint_32 skip,
+      int handle_as_ancillary)
 {
    /* The size of the local buffer for inflate is a good guess as to a
     * reasonable size to use for buffering reads from the application.
@@ -226,14 +328,24 @@ png_crc_finish(png_structrp png_ptr, png_uint_32 skip)
       png_crc_read(png_ptr, tmpbuf, len);
    }
 
-   if (png_crc_error(png_ptr) != 0)
+   /* If 'handle_as_ancillary' has been requested and this is a critical chunk
+    * but PNG_FLAG_CRC_CRITICAL_IGNORE was set then png_read_crc did not, in
+    * fact, calculate the CRC so the ANCILLARY settings should not be used
+    * instead.
+    */
+   if (handle_as_ancillary &&
+       (png_ptr->flags & PNG_FLAG_CRC_CRITICAL_IGNORE) != 0)
+      handle_as_ancillary = 0;
+
+   /* TODO: this might be more comprehensible if png_crc_error was inlined here.
+    */
+   if (png_crc_error(png_ptr, handle_as_ancillary) != 0)
    {
-      if (PNG_CHUNK_ANCILLARY(png_ptr->chunk_name) != 0 ?
+      /* See above for the explanation of how the flags work. */
+      if (handle_as_ancillary || PNG_CHUNK_ANCILLARY(png_ptr->chunk_name) != 0 ?
           (png_ptr->flags & PNG_FLAG_CRC_ANCILLARY_NOWARN) == 0 :
           (png_ptr->flags & PNG_FLAG_CRC_CRITICAL_USE) != 0)
-      {
          png_chunk_warning(png_ptr, "CRC error");
-      }
 
       else
          png_chunk_error(png_ptr, "CRC error");
@@ -244,61 +356,29 @@ png_crc_finish(png_structrp png_ptr, png_uint_32 skip)
    return 0;
 }
 
-/* Compare the CRC stored in the PNG file with that calculated by libpng from
- * the data it has read thus far.
- */
 int /* PRIVATE */
-png_crc_error(png_structrp png_ptr)
+png_crc_finish(png_structrp png_ptr, png_uint_32 skip)
 {
-   png_byte crc_bytes[4];
-   png_uint_32 crc;
-   int need_crc = 1;
-
-   if (PNG_CHUNK_ANCILLARY(png_ptr->chunk_name) != 0)
-   {
-      if ((png_ptr->flags & PNG_FLAG_CRC_ANCILLARY_MASK) ==
-          (PNG_FLAG_CRC_ANCILLARY_USE | PNG_FLAG_CRC_ANCILLARY_NOWARN))
-         need_crc = 0;
-   }
-
-   else /* critical */
-   {
-      if ((png_ptr->flags & PNG_FLAG_CRC_CRITICAL_IGNORE) != 0)
-         need_crc = 0;
-   }
-
-#ifdef PNG_IO_STATE_SUPPORTED
-   png_ptr->io_state = PNG_IO_READING | PNG_IO_CHUNK_CRC;
-#endif
-
-   /* The chunk CRC must be serialized in a single I/O call. */
-   png_read_data(png_ptr, crc_bytes, 4);
-
-   if (need_crc != 0)
-   {
-      crc = png_get_uint_32(crc_bytes);
-      return crc != png_ptr->crc;
-   }
-
-   else
-      return 0;
+   return png_crc_finish_critical(png_ptr, skip, 0/*critical handling*/);
 }
 
 #if defined(PNG_READ_iCCP_SUPPORTED) || defined(PNG_READ_iTXt_SUPPORTED) ||\
     defined(PNG_READ_pCAL_SUPPORTED) || defined(PNG_READ_sCAL_SUPPORTED) ||\
     defined(PNG_READ_sPLT_SUPPORTED) || defined(PNG_READ_tEXt_SUPPORTED) ||\
-    defined(PNG_READ_zTXt_SUPPORTED) || defined(PNG_SEQUENTIAL_READ_SUPPORTED)
+    defined(PNG_READ_zTXt_SUPPORTED) || defined(PNG_READ_eXIf_SUPPORTED) ||\
+    defined(PNG_SEQUENTIAL_READ_SUPPORTED)
 /* Manage the read buffer; this simply reallocates the buffer if it is not small
  * enough (or if it is not allocated).  The routine returns a pointer to the
  * buffer; if an error occurs and 'warn' is set the routine returns NULL, else
- * it will call png_error (via png_malloc) on failure.  (warn == 2 means
- * 'silent').
+ * it will call png_error on failure.
  */
 static png_bytep
-png_read_buffer(png_structrp png_ptr, png_alloc_size_t new_size, int warn)
+png_read_buffer(png_structrp png_ptr, png_alloc_size_t new_size)
 {
    png_bytep buffer = png_ptr->read_buffer;
 
+   if (new_size > png_chunk_max(png_ptr)) return NULL;
+
    if (buffer != NULL && new_size > png_ptr->read_buffer_size)
    {
       png_ptr->read_buffer = NULL;
@@ -313,24 +393,17 @@ png_read_buffer(png_structrp png_ptr, png_alloc_size_t new_size, int warn)
 
       if (buffer != NULL)
       {
-         memset(buffer, 0, new_size); /* just in case */
+#        ifndef PNG_NO_MEMZERO /* for detecting UIM bugs **only** */
+            memset(buffer, 0, new_size); /* just in case */
+#        endif
          png_ptr->read_buffer = buffer;
          png_ptr->read_buffer_size = new_size;
       }
-
-      else if (warn < 2) /* else silent */
-      {
-         if (warn != 0)
-             png_chunk_warning(png_ptr, "insufficient memory to read chunk");
-
-         else
-             png_chunk_error(png_ptr, "insufficient memory to read chunk");
-      }
    }
 
    return buffer;
 }
-#endif /* READ_iCCP|iTXt|pCAL|sCAL|sPLT|tEXt|zTXt|SEQUENTIAL_READ */
+#endif /* READ_iCCP|iTXt|pCAL|sCAL|sPLT|tEXt|zTXt|eXIf|SEQUENTIAL_READ */
 
 /* png_inflate_claim: claim the zstream for some nefarious purpose that involves
  * decompression.  Returns Z_OK on success, else a zlib error code.  It checks
@@ -617,16 +690,7 @@ png_decompress_chunk(png_structrp png_ptr,
     * maybe a '\0' terminator too.  We have to assume that 'prefix_size' is
     * limited only by the maximum chunk size.
     */
-   png_alloc_size_t limit = PNG_SIZE_MAX;
-
-# ifdef PNG_SET_USER_LIMITS_SUPPORTED
-   if (png_ptr->user_chunk_malloc_max > 0 &&
-       png_ptr->user_chunk_malloc_max < limit)
-      limit = png_ptr->user_chunk_malloc_max;
-# elif PNG_USER_CHUNK_MALLOC_MAX > 0
-   if (PNG_USER_CHUNK_MALLOC_MAX < limit)
-      limit = PNG_USER_CHUNK_MALLOC_MAX;
-# endif
+   png_alloc_size_t limit = png_chunk_max(png_ptr);
 
    if (limit >= prefix_size + (terminate != 0))
    {
@@ -831,9 +895,9 @@ png_inflate_read(png_structrp png_ptr, png_bytep read_buffer, uInt read_size,
 }
 #endif /* READ_iCCP */
 
+/* CHUNK HANDLING */
 /* Read and check the IDHR chunk */
-
-void /* PRIVATE */
+static png_handle_result_code
 png_handle_IHDR(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_byte buf[13];
@@ -843,12 +907,7 @@ png_handle_IHDR(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 
    png_debug(1, "in png_handle_IHDR");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) != 0)
-      png_chunk_error(png_ptr, "out of place");
-
-   /* Check the length */
-   if (length != 13)
-      png_chunk_error(png_ptr, "invalid");
+   /* Length and position are checked by the caller. */
 
    png_ptr->mode |= PNG_HAVE_IHDR;
 
@@ -902,257 +961,196 @@ png_handle_IHDR(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    png_debug1(3, "bit_depth = %d", png_ptr->bit_depth);
    png_debug1(3, "channels = %d", png_ptr->channels);
    png_debug1(3, "rowbytes = %lu", (unsigned long)png_ptr->rowbytes);
+
+   /* Rely on png_set_IHDR to completely validate the data and call png_error if
+    * it's wrong.
+    */
    png_set_IHDR(png_ptr, info_ptr, width, height, bit_depth,
        color_type, interlace_type, compression_type, filter_type);
+
+   return handled_ok;
+   PNG_UNUSED(length)
 }
 
 /* Read and check the palette */
-void /* PRIVATE */
+/* TODO: there are several obvious errors in this code when handling
+ * out-of-place chunks and there is much over-complexity caused by trying to
+ * patch up the problems.
+ */
+static png_handle_result_code
 png_handle_PLTE(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
-   png_color palette[PNG_MAX_PALETTE_LENGTH];
-   int max_palette_length, num, i;
-#ifdef PNG_POINTER_INDEXING_SUPPORTED
-   png_colorp pal_ptr;
-#endif
+   png_const_charp errmsg = NULL;
 
    png_debug(1, "in png_handle_PLTE");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   /* Moved to before the 'after IDAT' check below because otherwise duplicate
-    * PLTE chunks are potentially ignored (the spec says there shall not be more
-    * than one PLTE, the error is not treated as benign, so this check trumps
-    * the requirement that PLTE appears before IDAT.)
+   /* 1.6.47: consistency.  This used to be especially treated as a critical
+    * error even in an image which is not colour mapped, there isn't a good
+    * justification for treating some errors here one way and others another so
+    * everything uses the same logic.
     */
-   else if ((png_ptr->mode & PNG_HAVE_PLTE) != 0)
-      png_chunk_error(png_ptr, "duplicate");
+   if ((png_ptr->mode & PNG_HAVE_PLTE) != 0)
+      errmsg = "duplicate";
 
    else if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
-   {
-      /* This is benign because the non-benign error happened before, when an
-       * IDAT was encountered in a color-mapped image with no PLTE.
-       */
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
+      errmsg = "out of place";
 
-   png_ptr->mode |= PNG_HAVE_PLTE;
+   else if ((png_ptr->color_type & PNG_COLOR_MASK_COLOR) == 0)
+      errmsg = "ignored in grayscale PNG";
 
-   if ((png_ptr->color_type & PNG_COLOR_MASK_COLOR) == 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "ignored in grayscale PNG");
-      return;
-   }
+   else if (length > 3*PNG_MAX_PALETTE_LENGTH || (length % 3) != 0)
+      errmsg = "invalid";
 
-#ifndef PNG_READ_OPT_PLTE_SUPPORTED
-   if (png_ptr->color_type != PNG_COLOR_TYPE_PALETTE)
-   {
-      png_crc_finish(png_ptr, length);
-      return;
-   }
-#endif
+   /* This drops PLTE in favour of tRNS or bKGD because both of those chunks
+    * can have an effect on the rendering of the image whereas PLTE only matters
+    * in the case of an 8-bit display with a decoder which controls the palette.
+    *
+    * The alternative here is to ignore the error and store the palette anyway;
+    * destroying the tRNS will definately cause problems.
+    *
+    * NOTE: the case of PNG_COLOR_TYPE_PALETTE need not be considered because
+    * the png_handle_ routines for the three 'after PLTE' chunks tRNS, bKGD and
+    * hIST all check for a preceding PLTE in these cases.
+    */
+   else if (png_ptr->color_type != PNG_COLOR_TYPE_PALETTE &&
+            (png_has_chunk(png_ptr, tRNS) || png_has_chunk(png_ptr, bKGD)))
+      errmsg = "out of place";
 
-   if (length > 3*PNG_MAX_PALETTE_LENGTH || length % 3)
+   else
    {
-      png_crc_finish(png_ptr, length);
-
-      if (png_ptr->color_type != PNG_COLOR_TYPE_PALETTE)
-         png_chunk_benign_error(png_ptr, "invalid");
-
-      else
-         png_chunk_error(png_ptr, "invalid");
+      /* If the palette has 256 or fewer entries but is too large for the bit
+       * depth we don't issue an error to preserve the behavior of previous
+       * libpng versions. We silently truncate the unused extra palette entries
+       * here.
+       */
+      const unsigned max_palette_length =
+         (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE) ?
+            1U << png_ptr->bit_depth : PNG_MAX_PALETTE_LENGTH;
 
-      return;
-   }
+      /* The cast is safe because 'length' is less than
+       * 3*PNG_MAX_PALETTE_LENGTH
+       */
+      const unsigned num = (length > 3U*max_palette_length) ?
+         max_palette_length : (unsigned)length / 3U;
 
-   /* The cast is safe because 'length' is less than 3*PNG_MAX_PALETTE_LENGTH */
-   num = (int)length / 3;
+      unsigned i, j;
+      png_byte buf[3*PNG_MAX_PALETTE_LENGTH];
+      png_color palette[PNG_MAX_PALETTE_LENGTH];
 
-   /* If the palette has 256 or fewer entries but is too large for the bit
-    * depth, we don't issue an error, to preserve the behavior of previous
-    * libpng versions. We silently truncate the unused extra palette entries
-    * here.
-    */
-   if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
-      max_palette_length = (1 << png_ptr->bit_depth);
-   else
-      max_palette_length = PNG_MAX_PALETTE_LENGTH;
+      /* Read the chunk into the buffer then read to the end of the chunk. */
+      png_crc_read(png_ptr, buf, num*3U);
+      png_crc_finish_critical(png_ptr, length - 3U*num,
+            /* Handle as ancillary if PLTE is optional: */
+            png_ptr->color_type != PNG_COLOR_TYPE_PALETTE);
 
-   if (num > max_palette_length)
-      num = max_palette_length;
+      for (i = 0U, j = 0U; i < num; i++)
+      {
+         palette[i].red = buf[j++];
+         palette[i].green = buf[j++];
+         palette[i].blue = buf[j++];
+      }
 
-#ifdef PNG_POINTER_INDEXING_SUPPORTED
-   for (i = 0, pal_ptr = palette; i < num; i++, pal_ptr++)
-   {
-      png_byte buf[3];
+      /* A valid PLTE chunk has been read */
+      png_ptr->mode |= PNG_HAVE_PLTE;
 
-      png_crc_read(png_ptr, buf, 3);
-      pal_ptr->red = buf[0];
-      pal_ptr->green = buf[1];
-      pal_ptr->blue = buf[2];
+      /* TODO: png_set_PLTE has the side effect of setting png_ptr->palette to
+       * its own copy of the palette.  This has the side effect that when
+       * png_start_row is called (this happens after any call to
+       * png_read_update_info) the info_ptr palette gets changed.  This is
+       * extremely unexpected and confusing.
+       *
+       * REVIEW: there have been consistent bugs in the past about gamma and
+       * similar transforms to colour mapped images being useless because the
+       * modified palette cannot be accessed because of the above.
+       *
+       * CONSIDER: Fix this by not sharing the palette in this way.  But does
+       * this completely fix the problem?
+       */
+      png_set_PLTE(png_ptr, info_ptr, palette, num);
+      return handled_ok;
    }
-#else
-   for (i = 0; i < num; i++)
-   {
-      png_byte buf[3];
 
-      png_crc_read(png_ptr, buf, 3);
-      /* Don't depend upon png_color being any order */
-      palette[i].red = buf[0];
-      palette[i].green = buf[1];
-      palette[i].blue = buf[2];
-   }
-#endif
-
-   /* If we actually need the PLTE chunk (ie for a paletted image), we do
-    * whatever the normal CRC configuration tells us.  However, if we
-    * have an RGB image, the PLTE can be considered ancillary, so
-    * we will act as though it is.
-    */
-#ifndef PNG_READ_OPT_PLTE_SUPPORTED
+   /* Here on error: errmsg is non NULL. */
    if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
-#endif
    {
-      png_crc_finish(png_ptr, (png_uint_32) (length - (unsigned int)num * 3));
+      png_crc_finish(png_ptr, length);
+      png_chunk_error(png_ptr, errmsg);
    }
 
-#ifndef PNG_READ_OPT_PLTE_SUPPORTED
-   else if (png_crc_error(png_ptr) != 0)  /* Only if we have a CRC error */
+   else /* not critical to this image */
    {
-      /* If we don't want to use the data from an ancillary chunk,
-       * we have two options: an error abort, or a warning and we
-       * ignore the data in this chunk (which should be OK, since
-       * it's considered ancillary for a RGB or RGBA image).
-       *
-       * IMPLEMENTATION NOTE: this is only here because png_crc_finish uses the
-       * chunk type to determine whether to check the ancillary or the critical
-       * flags.
-       */
-      if ((png_ptr->flags & PNG_FLAG_CRC_ANCILLARY_USE) == 0)
-      {
-         if ((png_ptr->flags & PNG_FLAG_CRC_ANCILLARY_NOWARN) != 0)
-            return;
-
-         else
-            png_chunk_error(png_ptr, "CRC error");
-      }
-
-      /* Otherwise, we (optionally) emit a warning and use the chunk. */
-      else if ((png_ptr->flags & PNG_FLAG_CRC_ANCILLARY_NOWARN) == 0)
-         png_chunk_warning(png_ptr, "CRC error");
+      png_crc_finish_critical(png_ptr, length, 1/*handle as ancillary*/);
+      png_chunk_benign_error(png_ptr, errmsg);
    }
-#endif
 
-   /* TODO: png_set_PLTE has the side effect of setting png_ptr->palette to its
-    * own copy of the palette.  This has the side effect that when png_start_row
-    * is called (this happens after any call to png_read_update_info) the
-    * info_ptr palette gets changed.  This is extremely unexpected and
-    * confusing.
-    *
-    * Fix this by not sharing the palette in this way.
+   /* Because PNG_UNUSED(errmsg) does not work if all the uses are compiled out
+    * (this does happen).
     */
-   png_set_PLTE(png_ptr, info_ptr, palette, num);
-
-   /* The three chunks, bKGD, hIST and tRNS *must* appear after PLTE and before
-    * IDAT.  Prior to 1.6.0 this was not checked; instead the code merely
-    * checked the apparent validity of a tRNS chunk inserted before PLTE on a
-    * palette PNG.  1.6.0 attempts to rigorously follow the standard and
-    * therefore does a benign error if the erroneous condition is detected *and*
-    * cancels the tRNS if the benign error returns.  The alternative is to
-    * amend the standard since it would be rather hypocritical of the standards
-    * maintainers to ignore it.
-    */
-#ifdef PNG_READ_tRNS_SUPPORTED
-   if (png_ptr->num_trans > 0 ||
-       (info_ptr != NULL && (info_ptr->valid & PNG_INFO_tRNS) != 0))
-   {
-      /* Cancel this because otherwise it would be used if the transforms
-       * require it.  Don't cancel the 'valid' flag because this would prevent
-       * detection of duplicate chunks.
-       */
-      png_ptr->num_trans = 0;
-
-      if (info_ptr != NULL)
-         info_ptr->num_trans = 0;
-
-      png_chunk_benign_error(png_ptr, "tRNS must be after");
-   }
-#endif
-
-#ifdef PNG_READ_hIST_SUPPORTED
-   if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_hIST) != 0)
-      png_chunk_benign_error(png_ptr, "hIST must be after");
-#endif
-
-#ifdef PNG_READ_bKGD_SUPPORTED
-   if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_bKGD) != 0)
-      png_chunk_benign_error(png_ptr, "bKGD must be after");
-#endif
+   return errmsg != NULL ? handled_error : handled_error;
 }
 
-void /* PRIVATE */
+/* On read the IDAT chunk is always handled specially, even if marked for
+ * unknown handling (this is allowed), so:
+ */
+#define png_handle_IDAT NULL
+
+static png_handle_result_code
 png_handle_IEND(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_debug(1, "in png_handle_IEND");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0 ||
-       (png_ptr->mode & PNG_HAVE_IDAT) == 0)
-      png_chunk_error(png_ptr, "out of place");
-
    png_ptr->mode |= (PNG_AFTER_IDAT | PNG_HAVE_IEND);
 
-   png_crc_finish(png_ptr, length);
-
    if (length != 0)
       png_chunk_benign_error(png_ptr, "invalid");
 
+   png_crc_finish_critical(png_ptr, length, 1/*handle as ancillary*/);
+
+   return handled_ok;
    PNG_UNUSED(info_ptr)
 }
 
 #ifdef PNG_READ_gAMA_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code
 png_handle_gAMA(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
-   png_fixed_point igamma;
+   png_uint_32 ugamma;
    png_byte buf[4];
 
    png_debug(1, "in png_handle_gAMA");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
+   png_crc_read(png_ptr, buf, 4);
 
-   else if ((png_ptr->mode & (PNG_HAVE_IDAT|PNG_HAVE_PLTE)) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
+   if (png_crc_finish(png_ptr, 0) != 0)
+      return handled_error;
+
+   ugamma = png_get_uint_32(buf);
 
-   if (length != 4)
+   if (ugamma > PNG_UINT_31_MAX)
    {
-      png_crc_finish(png_ptr, length);
       png_chunk_benign_error(png_ptr, "invalid");
-      return;
+      return handled_error;
    }
 
-   png_crc_read(png_ptr, buf, 4);
-
-   if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+   png_set_gAMA_fixed(png_ptr, info_ptr, (png_fixed_point)/*SAFE*/ugamma);
 
-   igamma = png_get_fixed_point(NULL, buf);
+#ifdef PNG_READ_GAMMA_SUPPORTED
+      /* PNGv3: chunk precedence for gamma is cICP, [iCCP], sRGB, gAMA.  gAMA is
+       * at the end of the chain so simply check for an unset value.
+       */
+      if (png_ptr->chunk_gamma == 0)
+         png_ptr->chunk_gamma = (png_fixed_point)/*SAFE*/ugamma;
+#endif /*READ_GAMMA*/
 
-   png_colorspace_set_gamma(png_ptr, &png_ptr->colorspace, igamma);
-   png_colorspace_sync(png_ptr, info_ptr);
+   return handled_ok;
+   PNG_UNUSED(length)
 }
+#else
+#  define png_handle_gAMA NULL
 #endif
 
 #ifdef PNG_READ_sBIT_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_sBIT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    unsigned int truelen, i;
@@ -1161,23 +1159,6 @@ png_handle_sBIT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 
    png_debug(1, "in png_handle_sBIT");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & (PNG_HAVE_IDAT|PNG_HAVE_PLTE)) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-   if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_sBIT) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
-
    if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
    {
       truelen = 3;
@@ -1190,25 +1171,25 @@ png_handle_sBIT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
       sample_depth = png_ptr->bit_depth;
    }
 
-   if (length != truelen || length > 4)
+   if (length != truelen)
    {
-      png_chunk_benign_error(png_ptr, "invalid");
       png_crc_finish(png_ptr, length);
-      return;
+      png_chunk_benign_error(png_ptr, "bad length");
+      return handled_error;
    }
 
    buf[0] = buf[1] = buf[2] = buf[3] = sample_depth;
    png_crc_read(png_ptr, buf, truelen);
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
    for (i=0; i<truelen; ++i)
    {
       if (buf[i] == 0 || buf[i] > sample_depth)
       {
          png_chunk_benign_error(png_ptr, "invalid");
-         return;
+         return handled_error;
       }
    }
 
@@ -1220,7 +1201,7 @@ png_handle_sBIT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
       png_ptr->sig_bit.alpha = buf[3];
    }
 
-   else
+   else /* grayscale */
    {
       png_ptr->sig_bit.gray = buf[0];
       png_ptr->sig_bit.red = buf[0];
@@ -1230,133 +1211,132 @@ png_handle_sBIT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    }
 
    png_set_sBIT(png_ptr, info_ptr, &(png_ptr->sig_bit));
+   return handled_ok;
 }
+#else
+#  define png_handle_sBIT NULL
 #endif
 
 #ifdef PNG_READ_cHRM_SUPPORTED
-void /* PRIVATE */
-png_handle_cHRM(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
+static png_int_32
+png_get_int_32_checked(png_const_bytep buf, int *error)
 {
-   png_byte buf[32];
-   png_xy xy;
+   png_uint_32 uval = png_get_uint_32(buf);
+   if ((uval & 0x80000000) == 0) /* non-negative */
+      return (png_int_32)uval;
 
-   png_debug(1, "in png_handle_cHRM");
+   uval = (uval ^ 0xffffffff) + 1;  /* 2's complement: -x = ~x+1 */
+   if ((uval & 0x80000000) == 0) /* no overflow */
+      return -(png_int_32)uval;
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
+   /* This version of png_get_int_32 has a way of returning the error to the
+    * caller, so:
+    */
+   *error = 1;
+   return 0; /* Safe */
+}
 
-   else if ((png_ptr->mode & (PNG_HAVE_IDAT|PNG_HAVE_PLTE)) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
+static png_handle_result_code /* PRIVATE */
+png_handle_cHRM(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
+{
+   int error = 0;
+   png_xy xy;
+   png_byte buf[32];
 
-   if (length != 32)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "invalid");
-      return;
-   }
+   png_debug(1, "in png_handle_cHRM");
 
    png_crc_read(png_ptr, buf, 32);
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
+
+   xy.whitex = png_get_int_32_checked(buf +  0, &error);
+   xy.whitey = png_get_int_32_checked(buf +  4, &error);
+   xy.redx   = png_get_int_32_checked(buf +  8, &error);
+   xy.redy   = png_get_int_32_checked(buf + 12, &error);
+   xy.greenx = png_get_int_32_checked(buf + 16, &error);
+   xy.greeny = png_get_int_32_checked(buf + 20, &error);
+   xy.bluex  = png_get_int_32_checked(buf + 24, &error);
+   xy.bluey  = png_get_int_32_checked(buf + 28, &error);
 
-   xy.whitex = png_get_fixed_point(NULL, buf);
-   xy.whitey = png_get_fixed_point(NULL, buf + 4);
-   xy.redx   = png_get_fixed_point(NULL, buf + 8);
-   xy.redy   = png_get_fixed_point(NULL, buf + 12);
-   xy.greenx = png_get_fixed_point(NULL, buf + 16);
-   xy.greeny = png_get_fixed_point(NULL, buf + 20);
-   xy.bluex  = png_get_fixed_point(NULL, buf + 24);
-   xy.bluey  = png_get_fixed_point(NULL, buf + 28);
-
-   if (xy.whitex == PNG_FIXED_ERROR ||
-       xy.whitey == PNG_FIXED_ERROR ||
-       xy.redx   == PNG_FIXED_ERROR ||
-       xy.redy   == PNG_FIXED_ERROR ||
-       xy.greenx == PNG_FIXED_ERROR ||
-       xy.greeny == PNG_FIXED_ERROR ||
-       xy.bluex  == PNG_FIXED_ERROR ||
-       xy.bluey  == PNG_FIXED_ERROR)
+   if (error)
    {
-      png_chunk_benign_error(png_ptr, "invalid values");
-      return;
+      png_chunk_benign_error(png_ptr, "invalid");
+      return handled_error;
    }
 
-   /* If a colorspace error has already been output skip this chunk */
-   if ((png_ptr->colorspace.flags & PNG_COLORSPACE_INVALID) != 0)
-      return;
+   /* png_set_cHRM may complain about some of the values but this doesn't matter
+    * because it was a cHRM and it did have vaguely (if, perhaps, ridiculous)
+    * values.  Ridiculousity will be checked if the values are used later.
+    */
+   png_set_cHRM_fixed(png_ptr, info_ptr, xy.whitex, xy.whitey, xy.redx, xy.redy,
+         xy.greenx, xy.greeny, xy.bluex, xy.bluey);
 
-   if ((png_ptr->colorspace.flags & PNG_COLORSPACE_FROM_cHRM) != 0)
-   {
-      png_ptr->colorspace.flags |= PNG_COLORSPACE_INVALID;
-      png_colorspace_sync(png_ptr, info_ptr);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
+   /* We only use 'chromaticities' for RGB to gray */
+#  ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
+      /* There is no need to check sRGB here, cICP is NYI and iCCP is not
+       * supported so just check mDCV.
+       */
+      if (!png_has_chunk(png_ptr, mDCV))
+      {
+         png_ptr->chromaticities = xy;
+      }
+#  endif /* READ_RGB_TO_GRAY */
 
-   png_ptr->colorspace.flags |= PNG_COLORSPACE_FROM_cHRM;
-   (void)png_colorspace_set_chromaticities(png_ptr, &png_ptr->colorspace, &xy,
-       1/*prefer cHRM values*/);
-   png_colorspace_sync(png_ptr, info_ptr);
+   return handled_ok;
+   PNG_UNUSED(length)
 }
+#else
+#  define png_handle_cHRM NULL
 #endif
 
 #ifdef PNG_READ_sRGB_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_sRGB(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_byte intent;
 
    png_debug(1, "in png_handle_sRGB");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & (PNG_HAVE_IDAT|PNG_HAVE_PLTE)) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-   if (length != 1)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "invalid");
-      return;
-   }
-
    png_crc_read(png_ptr, &intent, 1);
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
-   /* If a colorspace error has already been output skip this chunk */
-   if ((png_ptr->colorspace.flags & PNG_COLORSPACE_INVALID) != 0)
-      return;
-
-   /* Only one sRGB or iCCP chunk is allowed, use the HAVE_INTENT flag to detect
-    * this.
+   /* This checks the range of the "rendering intent" because it is specified in
+    * the PNG spec itself; the "reserved" values will result in the chunk not
+    * being accepted, just as they do with the various "reserved" values in
+    * IHDR.
     */
-   if ((png_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_INTENT) != 0)
+   if (intent > 3/*PNGv3 spec*/)
    {
-      png_ptr->colorspace.flags |= PNG_COLORSPACE_INVALID;
-      png_colorspace_sync(png_ptr, info_ptr);
-      png_chunk_benign_error(png_ptr, "too many profiles");
-      return;
+      png_chunk_benign_error(png_ptr, "invalid");
+      return handled_error;
    }
 
-   (void)png_colorspace_set_sRGB(png_ptr, &png_ptr->colorspace, intent);
-   png_colorspace_sync(png_ptr, info_ptr);
+   png_set_sRGB(png_ptr, info_ptr, intent);
+   /* NOTE: png_struct::chromaticities is not set here because the RGB to gray
+    * coefficients are known without a need for the chromaticities.
+    */
+
+#ifdef PNG_READ_GAMMA_SUPPORTED
+      /* PNGv3: chunk precedence for gamma is cICP, [iCCP], sRGB, gAMA.  iCCP is
+       * not supported by libpng so the only requirement is to check for cICP
+       * setting the gamma (this is NYI, but this check is safe.)
+       */
+      if (!png_has_chunk(png_ptr, cICP) || png_ptr->chunk_gamma == 0)
+         png_ptr->chunk_gamma = PNG_GAMMA_sRGB_INVERSE;
+#endif /*READ_GAMMA*/
+
+   return handled_ok;
+   PNG_UNUSED(length)
 }
+#else
+#  define png_handle_sRGB NULL
 #endif /* READ_sRGB */
 
 #ifdef PNG_READ_iCCP_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 /* Note: this does not properly handle profiles that are > 64K under DOS */
 {
@@ -1365,44 +1345,10 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 
    png_debug(1, "in png_handle_iCCP");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & (PNG_HAVE_IDAT|PNG_HAVE_PLTE)) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-   /* Consistent with all the above colorspace handling an obviously *invalid*
-    * chunk is just ignored, so does not invalidate the color space.  An
-    * alternative is to set the 'invalid' flags at the start of this routine
-    * and only clear them in they were not set before and all the tests pass.
+   /* PNGv3: allow PNG files with both sRGB and iCCP because the PNG spec only
+    * ever said that there "should" be only one, not "shall" and the PNGv3
+    * colour chunk precedence rules give a handling for this case anyway.
     */
-
-   /* The keyword must be at least one character and there is a
-    * terminator (0) byte and the compression method byte, and the
-    * 'zlib' datastream is at least 11 bytes.
-    */
-   if (length < 14)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "too short");
-      return;
-   }
-
-   /* If a colorspace error has already been output skip this chunk */
-   if ((png_ptr->colorspace.flags & PNG_COLORSPACE_INVALID) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      return;
-   }
-
-   /* Only one sRGB or iCCP chunk is allowed, use the HAVE_INTENT flag to detect
-    * this.
-    */
-   if ((png_ptr->colorspace.flags & PNG_COLORSPACE_HAVE_INTENT) == 0)
    {
       uInt read_length, keyword_length;
       char keyword[81];
@@ -1412,19 +1358,16 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
        */
       read_length = 81; /* maximum */
       if (read_length > length)
-         read_length = (uInt)length;
+         read_length = (uInt)/*SAFE*/length;
 
       png_crc_read(png_ptr, (png_bytep)keyword, read_length);
       length -= read_length;
 
-      /* The minimum 'zlib' stream is assumed to be just the 2 byte header,
-       * 5 bytes minimum 'deflate' stream, and the 4 byte checksum.
-       */
-      if (length < 11)
+      if (length < LZ77Min)
       {
          png_crc_finish(png_ptr, length);
          png_chunk_benign_error(png_ptr, "too short");
-         return;
+         return handled_error;
       }
 
       keyword_length = 0;
@@ -1461,15 +1404,14 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
                    */
                   png_uint_32 profile_length = png_get_uint_32(profile_header);
 
-                  if (png_icc_check_length(png_ptr, &png_ptr->colorspace,
-                      keyword, profile_length) != 0)
+                  if (png_icc_check_length(png_ptr, keyword, profile_length) !=
+                      0)
                   {
                      /* The length is apparently ok, so we can check the 132
                       * byte header.
                       */
-                     if (png_icc_check_header(png_ptr, &png_ptr->colorspace,
-                         keyword, profile_length, profile_header,
-                         png_ptr->color_type) != 0)
+                     if (png_icc_check_header(png_ptr, keyword, profile_length,
+                              profile_header, png_ptr->color_type) != 0)
                      {
                         /* Now read the tag table; a variable size buffer is
                          * needed at this point, allocate one for the whole
@@ -1479,7 +1421,7 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
                         png_uint_32 tag_count =
                            png_get_uint_32(profile_header + 128);
                         png_bytep profile = png_read_buffer(png_ptr,
-                            profile_length, 2/*silent*/);
+                              profile_length);
 
                         if (profile != NULL)
                         {
@@ -1498,8 +1440,7 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
                            if (size == 0)
                            {
                               if (png_icc_check_tag_table(png_ptr,
-                                  &png_ptr->colorspace, keyword, profile_length,
-                                  profile) != 0)
+                                       keyword, profile_length, profile) != 0)
                               {
                                  /* The profile has been validated for basic
                                   * security issues, so read the whole thing in.
@@ -1531,13 +1472,6 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
                                     png_crc_finish(png_ptr, length);
                                     finished = 1;
 
-# if defined(PNG_sRGB_SUPPORTED) && PNG_sRGB_PROFILE_CHECKS >= 0
-                                    /* Check for a match against sRGB */
-                                    png_icc_set_sRGB(png_ptr,
-                                        &png_ptr->colorspace, profile,
-                                        png_ptr->zstream.adler);
-# endif
-
                                     /* Steal the profile for info_ptr. */
                                     if (info_ptr != NULL)
                                     {
@@ -1560,11 +1494,7 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
                                        }
 
                                        else
-                                       {
-                                          png_ptr->colorspace.flags |=
-                                             PNG_COLORSPACE_INVALID;
                                           errmsg = "out of memory";
-                                       }
                                     }
 
                                     /* else the profile remains in the read
@@ -1572,13 +1502,10 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
                                      * chunks.
                                      */
 
-                                    if (info_ptr != NULL)
-                                       png_colorspace_sync(png_ptr, info_ptr);
-
                                     if (errmsg == NULL)
                                     {
                                        png_ptr->zowner = 0;
-                                       return;
+                                       return handled_ok;
                                     }
                                  }
                                  if (errmsg == NULL)
@@ -1619,22 +1546,21 @@ png_handle_iCCP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
          errmsg = "bad keyword";
    }
 
-   else
-      errmsg = "too many profiles";
-
    /* Failure: the reason is in 'errmsg' */
    if (finished == 0)
       png_crc_finish(png_ptr, length);
 
-   png_ptr->colorspace.flags |= PNG_COLORSPACE_INVALID;
-   png_colorspace_sync(png_ptr, info_ptr);
    if (errmsg != NULL) /* else already output */
       png_chunk_benign_error(png_ptr, errmsg);
+
+   return handled_error;
 }
+#else
+#  define png_handle_iCCP NULL
 #endif /* READ_iCCP */
 
 #ifdef PNG_READ_sPLT_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_sPLT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 /* Note: this does not properly handle chunks that are > 64K under DOS */
 {
@@ -1655,43 +1581,24 @@ png_handle_sPLT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
       if (png_ptr->user_chunk_cache_max == 1)
       {
          png_crc_finish(png_ptr, length);
-         return;
+         return handled_error;
       }
 
       if (--png_ptr->user_chunk_cache_max == 1)
       {
          png_warning(png_ptr, "No space in chunk cache for sPLT");
          png_crc_finish(png_ptr, length);
-         return;
+         return handled_error;
       }
    }
 #endif
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-#ifdef PNG_MAX_MALLOC_64K
-   if (length > 65535U)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "too large to fit in memory");
-      return;
-   }
-#endif
-
-   buffer = png_read_buffer(png_ptr, length+1, 2/*silent*/);
+   buffer = png_read_buffer(png_ptr, length+1);
    if (buffer == NULL)
    {
       png_crc_finish(png_ptr, length);
       png_chunk_benign_error(png_ptr, "out of memory");
-      return;
+      return handled_error;
    }
 
 
@@ -1702,7 +1609,7 @@ png_handle_sPLT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    png_crc_read(png_ptr, buffer, length);
 
    if (png_crc_finish(png_ptr, skip) != 0)
-      return;
+      return handled_error;
 
    buffer[length] = 0;
 
@@ -1715,7 +1622,7 @@ png_handle_sPLT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    if (length < 2U || entry_start > buffer + (length - 2U))
    {
       png_warning(png_ptr, "malformed sPLT chunk");
-      return;
+      return handled_error;
    }
 
    new_palette.depth = *entry_start++;
@@ -1729,7 +1636,7 @@ png_handle_sPLT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    if ((data_length % (unsigned int)entry_size) != 0)
    {
       png_warning(png_ptr, "sPLT chunk has bad length");
-      return;
+      return handled_error;
    }
 
    dl = (png_uint_32)(data_length / (unsigned int)entry_size);
@@ -1738,7 +1645,7 @@ png_handle_sPLT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    if (dl > max_dl)
    {
       png_warning(png_ptr, "sPLT chunk too long");
-      return;
+      return handled_error;
    }
 
    new_palette.nentries = (png_int_32)(data_length / (unsigned int)entry_size);
@@ -1749,10 +1656,9 @@ png_handle_sPLT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    if (new_palette.entries == NULL)
    {
       png_warning(png_ptr, "sPLT chunk requires too much memory");
-      return;
+      return handled_error;
    }
 
-#ifdef PNG_POINTER_INDEXING_SUPPORTED
    for (i = 0; i < new_palette.nentries; i++)
    {
       pp = new_palette.entries + i;
@@ -1775,31 +1681,6 @@ png_handle_sPLT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 
       pp->frequency = png_get_uint_16(entry_start); entry_start += 2;
    }
-#else
-   pp = new_palette.entries;
-
-   for (i = 0; i < new_palette.nentries; i++)
-   {
-
-      if (new_palette.depth == 8)
-      {
-         pp[i].red   = *entry_start++;
-         pp[i].green = *entry_start++;
-         pp[i].blue  = *entry_start++;
-         pp[i].alpha = *entry_start++;
-      }
-
-      else
-      {
-         pp[i].red   = png_get_uint_16(entry_start); entry_start += 2;
-         pp[i].green = png_get_uint_16(entry_start); entry_start += 2;
-         pp[i].blue  = png_get_uint_16(entry_start); entry_start += 2;
-         pp[i].alpha = png_get_uint_16(entry_start); entry_start += 2;
-      }
-
-      pp[i].frequency = png_get_uint_16(entry_start); entry_start += 2;
-   }
-#endif
 
    /* Discard all chunk data except the name and stash that */
    new_palette.name = (png_charp)buffer;
@@ -1807,34 +1688,20 @@ png_handle_sPLT(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    png_set_sPLT(png_ptr, info_ptr, &new_palette, 1);
 
    png_free(png_ptr, new_palette.entries);
+   return handled_ok;
 }
+#else
+#  define png_handle_sPLT NULL
 #endif /* READ_sPLT */
 
 #ifdef PNG_READ_tRNS_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_tRNS(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_byte readbuf[PNG_MAX_PALETTE_LENGTH];
 
    png_debug(1, "in png_handle_tRNS");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-   else if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_tRNS) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
-
    if (png_ptr->color_type == PNG_COLOR_TYPE_GRAY)
    {
       png_byte buf[2];
@@ -1843,7 +1710,7 @@ png_handle_tRNS(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
       {
          png_crc_finish(png_ptr, length);
          png_chunk_benign_error(png_ptr, "invalid");
-         return;
+         return handled_error;
       }
 
       png_crc_read(png_ptr, buf, 2);
@@ -1859,7 +1726,7 @@ png_handle_tRNS(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
       {
          png_crc_finish(png_ptr, length);
          png_chunk_benign_error(png_ptr, "invalid");
-         return;
+         return handled_error;
       }
 
       png_crc_read(png_ptr, buf, length);
@@ -1873,10 +1740,9 @@ png_handle_tRNS(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    {
       if ((png_ptr->mode & PNG_HAVE_PLTE) == 0)
       {
-         /* TODO: is this actually an error in the ISO spec? */
          png_crc_finish(png_ptr, length);
          png_chunk_benign_error(png_ptr, "out of place");
-         return;
+         return handled_error;
       }
 
       if (length > (unsigned int) png_ptr->num_palette ||
@@ -1885,7 +1751,7 @@ png_handle_tRNS(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
       {
          png_crc_finish(png_ptr, length);
          png_chunk_benign_error(png_ptr, "invalid");
-         return;
+         return handled_error;
       }
 
       png_crc_read(png_ptr, readbuf, length);
@@ -1896,13 +1762,13 @@ png_handle_tRNS(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    {
       png_crc_finish(png_ptr, length);
       png_chunk_benign_error(png_ptr, "invalid with alpha channel");
-      return;
+      return handled_error;
    }
 
    if (png_crc_finish(png_ptr, 0) != 0)
    {
       png_ptr->num_trans = 0;
-      return;
+      return handled_error;
    }
 
    /* TODO: this is a horrible side effect in the palette case because the
@@ -1911,11 +1777,14 @@ png_handle_tRNS(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
     */
    png_set_tRNS(png_ptr, info_ptr, readbuf, png_ptr->num_trans,
        &(png_ptr->trans_color));
+   return handled_ok;
 }
+#else
+#  define png_handle_tRNS NULL
 #endif
 
 #ifdef PNG_READ_bKGD_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_bKGD(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    unsigned int truelen;
@@ -1924,27 +1793,17 @@ png_handle_bKGD(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 
    png_debug(1, "in png_handle_bKGD");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & PNG_HAVE_IDAT) != 0 ||
-       (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE &&
-       (png_ptr->mode & PNG_HAVE_PLTE) == 0))
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-   else if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_bKGD) != 0)
+   if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
    {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
+      if ((png_ptr->mode & PNG_HAVE_PLTE) == 0)
+      {
+         png_crc_finish(png_ptr, length);
+         png_chunk_benign_error(png_ptr, "out of place");
+         return handled_error;
+      }
 
-   if (png_ptr->color_type == PNG_COLOR_TYPE_PALETTE)
       truelen = 1;
+   }
 
    else if ((png_ptr->color_type & PNG_COLOR_MASK_COLOR) != 0)
       truelen = 6;
@@ -1956,13 +1815,13 @@ png_handle_bKGD(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    {
       png_crc_finish(png_ptr, length);
       png_chunk_benign_error(png_ptr, "invalid");
-      return;
+      return handled_error;
    }
 
    png_crc_read(png_ptr, buf, truelen);
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
    /* We convert the index value into RGB components so that we can allow
     * arbitrary RGB values for background when we have transparency, and
@@ -1978,7 +1837,7 @@ png_handle_bKGD(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
          if (buf[0] >= info_ptr->num_palette)
          {
             png_chunk_benign_error(png_ptr, "invalid index");
-            return;
+            return handled_error;
          }
 
          background.red = (png_uint_16)png_ptr->palette[buf[0]].red;
@@ -1999,7 +1858,7 @@ png_handle_bKGD(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
          if (buf[0] != 0 || buf[1] >= (unsigned int)(1 << png_ptr->bit_depth))
          {
             png_chunk_benign_error(png_ptr, "invalid gray level");
-            return;
+            return handled_error;
          }
       }
 
@@ -2017,7 +1876,7 @@ png_handle_bKGD(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
          if (buf[0] != 0 || buf[2] != 0 || buf[4] != 0)
          {
             png_chunk_benign_error(png_ptr, "invalid color");
-            return;
+            return handled_error;
          }
       }
 
@@ -2029,75 +1888,174 @@ png_handle_bKGD(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    }
 
    png_set_bKGD(png_ptr, info_ptr, &background);
+   return handled_ok;
 }
+#else
+#  define png_handle_bKGD NULL
 #endif
 
-#ifdef PNG_READ_eXIf_SUPPORTED
-void /* PRIVATE */
-png_handle_eXIf(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
+#ifdef PNG_READ_cICP_SUPPORTED
+static png_handle_result_code /* PRIVATE */
+png_handle_cICP(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
-   unsigned int i;
+   png_byte buf[4];
 
-   png_debug(1, "in png_handle_eXIf");
+   png_debug(1, "in png_handle_cICP");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
+   png_crc_read(png_ptr, buf, 4);
 
-   if (length < 2)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "too short");
-      return;
-   }
+   if (png_crc_finish(png_ptr, 0) != 0)
+      return handled_error;
 
-   else if (info_ptr == NULL || (info_ptr->valid & PNG_INFO_eXIf) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
+   png_set_cICP(png_ptr, info_ptr, buf[0], buf[1],  buf[2], buf[3]);
 
-   info_ptr->free_me |= PNG_FREE_EXIF;
+   /* We only use 'chromaticities' for RGB to gray */
+#  ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
+      if (!png_has_chunk(png_ptr, mDCV))
+      {
+         /* TODO: png_ptr->chromaticities = chromaticities; */
+      }
+#  endif /* READ_RGB_TO_GRAY */
 
-   info_ptr->eXIf_buf = png_voidcast(png_bytep,
-             png_malloc_warn(png_ptr, length));
+#ifdef PNG_READ_GAMMA_SUPPORTED
+      /* PNGv3: chunk precedence for gamma is cICP, [iCCP], sRGB, gAMA.  cICP is
+       * at the head so simply set the gamma if it can be determined.  If not
+       * chunk_gamma remains unchanged; sRGB and gAMA handling check it for
+       * being zero.
+       */
+      /* TODO: set png_struct::chunk_gamma when possible */
+#endif /*READ_GAMMA*/
+
+   return handled_ok;
+   PNG_UNUSED(length)
+}
+#else
+#  define png_handle_cICP NULL
+#endif
+
+#ifdef PNG_READ_cLLI_SUPPORTED
+static png_handle_result_code /* PRIVATE */
+png_handle_cLLI(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
+{
+   png_byte buf[8];
 
-   if (info_ptr->eXIf_buf == NULL)
+   png_debug(1, "in png_handle_cLLI");
+
+   png_crc_read(png_ptr, buf, 8);
+
+   if (png_crc_finish(png_ptr, 0) != 0)
+      return handled_error;
+
+   /* The error checking happens here, this puts it in just one place: */
+   png_set_cLLI_fixed(png_ptr, info_ptr, png_get_uint_32(buf),
+         png_get_uint_32(buf+4));
+   return handled_ok;
+   PNG_UNUSED(length)
+}
+#else
+#  define png_handle_cLLI NULL
+#endif
+
+#ifdef PNG_READ_mDCV_SUPPORTED
+static png_handle_result_code /* PRIVATE */
+png_handle_mDCV(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
+{
+   png_xy chromaticities;
+   png_byte buf[24];
+
+   png_debug(1, "in png_handle_mDCV");
+
+   png_crc_read(png_ptr, buf, 24);
+
+   if (png_crc_finish(png_ptr, 0) != 0)
+      return handled_error;
+
+   /* The error checking happens here, this puts it in just one place.  The
+    * odd /50000 scaling factor makes it more difficult but the (x.y) values are
+    * only two bytes so a <<1 is safe.
+    *
+    * WARNING: the PNG specification defines the cHRM chunk to **start** with
+    * the white point (x,y).  The W3C PNG v3 specification puts the white point
+    * **after* R,G,B.  The x,y values in mDCV are also scaled by 50,000 and
+    * stored in just two bytes, whereas those in cHRM are scaled by 100,000 and
+    * stored in four bytes.  This is very, very confusing.  These APIs remove
+    * the confusion by copying the existing, well established, API.
+    */
+   chromaticities.redx   = png_get_uint_16(buf+ 0U) << 1; /* red x */
+   chromaticities.redy   = png_get_uint_16(buf+ 2U) << 1; /* red y */
+   chromaticities.greenx = png_get_uint_16(buf+ 4U) << 1; /* green x */
+   chromaticities.greeny = png_get_uint_16(buf+ 6U) << 1; /* green y */
+   chromaticities.bluex  = png_get_uint_16(buf+ 8U) << 1; /* blue x */
+   chromaticities.bluey  = png_get_uint_16(buf+10U) << 1; /* blue y */
+   chromaticities.whitex = png_get_uint_16(buf+12U) << 1; /* white x */
+   chromaticities.whitey = png_get_uint_16(buf+14U) << 1; /* white y */
+
+   png_set_mDCV_fixed(png_ptr, info_ptr,
+         chromaticities.whitex, chromaticities.whitey,
+         chromaticities.redx, chromaticities.redy,
+         chromaticities.greenx, chromaticities.greeny,
+         chromaticities.bluex, chromaticities.bluey,
+         png_get_uint_32(buf+16U), /* peak luminance */
+         png_get_uint_32(buf+20U));/* minimum perceivable luminance */
+
+   /* We only use 'chromaticities' for RGB to gray */
+#  ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
+      png_ptr->chromaticities = chromaticities;
+#  endif /* READ_RGB_TO_GRAY */
+
+   return handled_ok;
+   PNG_UNUSED(length)
+}
+#else
+#  define png_handle_mDCV NULL
+#endif
+
+#ifdef PNG_READ_eXIf_SUPPORTED
+static png_handle_result_code /* PRIVATE */
+png_handle_eXIf(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
+{
+   png_bytep buffer = NULL;
+
+   png_debug(1, "in png_handle_eXIf");
+
+   buffer = png_read_buffer(png_ptr, length);
+
+   if (buffer == NULL)
    {
       png_crc_finish(png_ptr, length);
       png_chunk_benign_error(png_ptr, "out of memory");
-      return;
+      return handled_error;
    }
 
-   for (i = 0; i < length; i++)
+   png_crc_read(png_ptr, buffer, length);
+
+   if (png_crc_finish(png_ptr, 0) != 0)
+      return handled_error;
+
+   /* PNGv3: the code used to check the byte order mark at the start for MM or
+    * II, however PNGv3 states that the the first 4 bytes should be checked.
+    * The caller ensures that there are four bytes available.
+    */
    {
-      png_byte buf[1];
-      png_crc_read(png_ptr, buf, 1);
-      info_ptr->eXIf_buf[i] = buf[0];
-      if (i == 1)
+      png_uint_32 header = png_get_uint_32(buffer);
+
+      /* These numbers are copied from the PNGv3 spec: */
+      if (header != 0x49492A00 && header != 0x4D4D002A)
       {
-         if ((buf[0] != 'M' && buf[0] != 'I') ||
-             (info_ptr->eXIf_buf[0] != buf[0]))
-         {
-            png_crc_finish(png_ptr, length - 2);
-            png_chunk_benign_error(png_ptr, "incorrect byte-order specifier");
-            png_free(png_ptr, info_ptr->eXIf_buf);
-            info_ptr->eXIf_buf = NULL;
-            return;
-         }
+         png_chunk_benign_error(png_ptr, "invalid");
+         return handled_error;
       }
    }
 
-   if (png_crc_finish(png_ptr, 0) == 0)
-      png_set_eXIf_1(png_ptr, info_ptr, length, info_ptr->eXIf_buf);
-
-   png_free(png_ptr, info_ptr->eXIf_buf);
-   info_ptr->eXIf_buf = NULL;
+   png_set_eXIf_1(png_ptr, info_ptr, length, buffer);
+   return handled_ok;
 }
+#else
+#  define png_handle_eXIf NULL
 #endif
 
 #ifdef PNG_READ_hIST_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_hIST(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    unsigned int num, i;
@@ -2105,25 +2063,13 @@ png_handle_hIST(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 
    png_debug(1, "in png_handle_hIST");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & PNG_HAVE_IDAT) != 0 ||
-       (png_ptr->mode & PNG_HAVE_PLTE) == 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-   else if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_hIST) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
-
-   num = length / 2 ;
+   /* This cast is safe because the chunk definition limits the length to a
+    * maximum of 1024 bytes.
+    *
+    * TODO: maybe use png_uint_32 anyway, not unsigned int, to reduce the
+    * casts.
+    */
+   num = (unsigned int)length / 2 ;
 
    if (length != num * 2 ||
        num != (unsigned int)png_ptr->num_palette ||
@@ -2131,7 +2077,7 @@ png_handle_hIST(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    {
       png_crc_finish(png_ptr, length);
       png_chunk_benign_error(png_ptr, "invalid");
-      return;
+      return handled_error;
    }
 
    for (i = 0; i < num; i++)
@@ -2143,14 +2089,17 @@ png_handle_hIST(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    }
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
    png_set_hIST(png_ptr, info_ptr, readbuf);
+   return handled_ok;
 }
+#else
+#  define png_handle_hIST NULL
 #endif
 
 #ifdef PNG_READ_pHYs_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_pHYs(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_byte buf[9];
@@ -2159,44 +2108,24 @@ png_handle_pHYs(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 
    png_debug(1, "in png_handle_pHYs");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-   else if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_pHYs) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
-
-   if (length != 9)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "invalid");
-      return;
-   }
-
    png_crc_read(png_ptr, buf, 9);
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
    res_x = png_get_uint_32(buf);
    res_y = png_get_uint_32(buf + 4);
    unit_type = buf[8];
    png_set_pHYs(png_ptr, info_ptr, res_x, res_y, unit_type);
+   return handled_ok;
+   PNG_UNUSED(length)
 }
+#else
+#  define png_handle_pHYs NULL
 #endif
 
 #ifdef PNG_READ_oFFs_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_oFFs(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_byte buf[9];
@@ -2205,45 +2134,25 @@ png_handle_oFFs(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 
    png_debug(1, "in png_handle_oFFs");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-   else if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_oFFs) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
-
-   if (length != 9)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "invalid");
-      return;
-   }
-
    png_crc_read(png_ptr, buf, 9);
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
    offset_x = png_get_int_32(buf);
    offset_y = png_get_int_32(buf + 4);
    unit_type = buf[8];
    png_set_oFFs(png_ptr, info_ptr, offset_x, offset_y, unit_type);
+   return handled_ok;
+   PNG_UNUSED(length)
 }
+#else
+#  define png_handle_oFFs NULL
 #endif
 
 #ifdef PNG_READ_pCAL_SUPPORTED
 /* Read the pCAL chunk (described in the PNG Extensions document) */
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_pCAL(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_int_32 X0, X1;
@@ -2253,40 +2162,22 @@ png_handle_pCAL(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    int i;
 
    png_debug(1, "in png_handle_pCAL");
-
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-   else if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_pCAL) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
-
    png_debug1(2, "Allocating and reading pCAL chunk data (%u bytes)",
        length + 1);
 
-   buffer = png_read_buffer(png_ptr, length+1, 2/*silent*/);
+   buffer = png_read_buffer(png_ptr, length+1);
 
    if (buffer == NULL)
    {
       png_crc_finish(png_ptr, length);
       png_chunk_benign_error(png_ptr, "out of memory");
-      return;
+      return handled_error;
    }
 
    png_crc_read(png_ptr, buffer, length);
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
    buffer[length] = 0; /* Null terminate the last string */
 
@@ -2302,7 +2193,7 @@ png_handle_pCAL(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    if (endptr - buf <= 12)
    {
       png_chunk_benign_error(png_ptr, "invalid");
-      return;
+      return handled_error;
    }
 
    png_debug(3, "Reading pCAL X0, X1, type, nparams, and units");
@@ -2322,7 +2213,7 @@ png_handle_pCAL(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
        (type == PNG_EQUATION_HYPERBOLIC && nparams != 4))
    {
       png_chunk_benign_error(png_ptr, "invalid parameter count");
-      return;
+      return handled_error;
    }
 
    else if (type >= PNG_EQUATION_LAST)
@@ -2341,7 +2232,7 @@ png_handle_pCAL(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    if (params == NULL)
    {
       png_chunk_benign_error(png_ptr, "out of memory");
-      return;
+      return handled_error;
    }
 
    /* Get pointers to the start of each parameter string. */
@@ -2359,20 +2250,29 @@ png_handle_pCAL(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
       {
          png_free(png_ptr, params);
          png_chunk_benign_error(png_ptr, "invalid data");
-         return;
+         return handled_error;
       }
    }
 
    png_set_pCAL(png_ptr, info_ptr, (png_charp)buffer, X0, X1, type, nparams,
        (png_charp)units, params);
 
+   /* TODO: BUG: png_set_pCAL calls png_chunk_report which, in this case, calls
+    * png_benign_error and that can error out.
+    *
+    * png_read_buffer needs to be allocated with space for both nparams and the
+    * parameter strings.  Not hard to do.
+    */
    png_free(png_ptr, params);
+   return handled_ok;
 }
+#else
+#  define png_handle_pCAL NULL
 #endif
 
 #ifdef PNG_READ_sCAL_SUPPORTED
 /* Read the sCAL chunk */
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_sCAL(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_bytep buffer;
@@ -2380,55 +2280,29 @@ png_handle_sCAL(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    int state;
 
    png_debug(1, "in png_handle_sCAL");
-
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "out of place");
-      return;
-   }
-
-   else if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_sCAL) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
-
-   /* Need unit type, width, \0, height: minimum 4 bytes */
-   else if (length < 4)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "invalid");
-      return;
-   }
-
    png_debug1(2, "Allocating and reading sCAL chunk data (%u bytes)",
        length + 1);
 
-   buffer = png_read_buffer(png_ptr, length+1, 2/*silent*/);
+   buffer = png_read_buffer(png_ptr, length+1);
 
    if (buffer == NULL)
    {
-      png_chunk_benign_error(png_ptr, "out of memory");
       png_crc_finish(png_ptr, length);
-      return;
+      png_chunk_benign_error(png_ptr, "out of memory");
+      return handled_error;
    }
 
    png_crc_read(png_ptr, buffer, length);
    buffer[length] = 0; /* Null terminate the last string */
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
    /* Validate the unit. */
    if (buffer[0] != 1 && buffer[0] != 2)
    {
       png_chunk_benign_error(png_ptr, "invalid unit");
-      return;
+      return handled_error;
    }
 
    /* Validate the ASCII numbers, need two ASCII numbers separated by
@@ -2457,15 +2331,22 @@ png_handle_sCAL(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
          png_chunk_benign_error(png_ptr, "non-positive height");
 
       else
+      {
          /* This is the (only) success case. */
          png_set_sCAL_s(png_ptr, info_ptr, buffer[0],
              (png_charp)buffer+1, (png_charp)buffer+heighti);
+         return handled_ok;
+      }
    }
+
+   return handled_error;
 }
+#else
+#  define png_handle_sCAL NULL
 #endif
 
 #ifdef PNG_READ_tIME_SUPPORTED
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_tIME(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_byte buf[7];
@@ -2473,30 +2354,17 @@ png_handle_tIME(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 
    png_debug(1, "in png_handle_tIME");
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
-   else if (info_ptr != NULL && (info_ptr->valid & PNG_INFO_tIME) != 0)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "duplicate");
-      return;
-   }
-
+   /* TODO: what is this doing here?  It should be happened in pngread.c and
+    * pngpread.c, although it could be moved to png_handle_chunk below and
+    * thereby avoid some code duplication.
+    */
    if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
       png_ptr->mode |= PNG_AFTER_IDAT;
 
-   if (length != 7)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "invalid");
-      return;
-   }
-
    png_crc_read(png_ptr, buf, 7);
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
    mod_time.second = buf[6];
    mod_time.minute = buf[5];
@@ -2506,12 +2374,16 @@ png_handle_tIME(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    mod_time.year = png_get_uint_16(buf);
 
    png_set_tIME(png_ptr, info_ptr, &mod_time);
+   return handled_ok;
+   PNG_UNUSED(length)
 }
+#else
+#  define png_handle_tIME NULL
 #endif
 
 #ifdef PNG_READ_tEXt_SUPPORTED
 /* Note: this does not properly handle chunks that are > 64K under DOS */
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_tEXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_text  text_info;
@@ -2528,45 +2400,35 @@ png_handle_tEXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
       if (png_ptr->user_chunk_cache_max == 1)
       {
          png_crc_finish(png_ptr, length);
-         return;
+         return handled_error;
       }
 
       if (--png_ptr->user_chunk_cache_max == 1)
       {
          png_crc_finish(png_ptr, length);
          png_chunk_benign_error(png_ptr, "no space in chunk cache");
-         return;
+         return handled_error;
       }
    }
 #endif
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
+   /* TODO: this doesn't work and shouldn't be necessary. */
    if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
       png_ptr->mode |= PNG_AFTER_IDAT;
 
-#ifdef PNG_MAX_MALLOC_64K
-   if (length > 65535U)
-   {
-      png_crc_finish(png_ptr, length);
-      png_chunk_benign_error(png_ptr, "too large to fit in memory");
-      return;
-   }
-#endif
-
-   buffer = png_read_buffer(png_ptr, length+1, 1/*warn*/);
+   buffer = png_read_buffer(png_ptr, length+1);
 
    if (buffer == NULL)
    {
+      png_crc_finish(png_ptr, length);
       png_chunk_benign_error(png_ptr, "out of memory");
-      return;
+      return handled_error;
    }
 
    png_crc_read(png_ptr, buffer, length);
 
    if (png_crc_finish(png_ptr, skip) != 0)
-      return;
+      return handled_error;
 
    key = (png_charp)buffer;
    key[length] = 0;
@@ -2585,14 +2447,19 @@ png_handle_tEXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
    text_info.text = text;
    text_info.text_length = strlen(text);
 
-   if (png_set_text_2(png_ptr, info_ptr, &text_info, 1) != 0)
-      png_warning(png_ptr, "Insufficient memory to process text chunk");
+   if (png_set_text_2(png_ptr, info_ptr, &text_info, 1) == 0)
+      return handled_ok;
+
+   png_chunk_benign_error(png_ptr, "out of memory");
+   return handled_error;
 }
+#else
+#  define png_handle_tEXt NULL
 #endif
 
 #ifdef PNG_READ_zTXt_SUPPORTED
 /* Note: this does not correctly handle chunks that are > 64K under DOS */
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_zTXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_const_charp errmsg = NULL;
@@ -2607,40 +2474,39 @@ png_handle_zTXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
       if (png_ptr->user_chunk_cache_max == 1)
       {
          png_crc_finish(png_ptr, length);
-         return;
+         return handled_error;
       }
 
       if (--png_ptr->user_chunk_cache_max == 1)
       {
          png_crc_finish(png_ptr, length);
          png_chunk_benign_error(png_ptr, "no space in chunk cache");
-         return;
+         return handled_error;
       }
    }
 #endif
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
+   /* TODO: should not be necessary. */
    if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
       png_ptr->mode |= PNG_AFTER_IDAT;
 
    /* Note, "length" is sufficient here; we won't be adding
-    * a null terminator later.
+    * a null terminator later.  The limit check in png_handle_chunk should be
+    * sufficient.
     */
-   buffer = png_read_buffer(png_ptr, length, 2/*silent*/);
+   buffer = png_read_buffer(png_ptr, length);
 
    if (buffer == NULL)
    {
       png_crc_finish(png_ptr, length);
       png_chunk_benign_error(png_ptr, "out of memory");
-      return;
+      return handled_error;
    }
 
    png_crc_read(png_ptr, buffer, length);
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
    /* TODO: also check that the keyword contents match the spec! */
    for (keyword_length = 0;
@@ -2693,8 +2559,10 @@ png_handle_zTXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
             text.lang = NULL;
             text.lang_key = NULL;
 
-            if (png_set_text_2(png_ptr, info_ptr, &text, 1) != 0)
-               errmsg = "insufficient memory";
+            if (png_set_text_2(png_ptr, info_ptr, &text, 1) == 0)
+               return handled_ok;
+
+            errmsg = "out of memory";
          }
       }
 
@@ -2702,14 +2570,16 @@ png_handle_zTXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
          errmsg = png_ptr->zstream.msg;
    }
 
-   if (errmsg != NULL)
-      png_chunk_benign_error(png_ptr, errmsg);
+   png_chunk_benign_error(png_ptr, errmsg);
+   return handled_error;
 }
+#else
+#  define png_handle_zTXt NULL
 #endif
 
 #ifdef PNG_READ_iTXt_SUPPORTED
 /* Note: this does not correctly handle chunks that are > 64K under DOS */
-void /* PRIVATE */
+static png_handle_result_code /* PRIVATE */
 png_handle_iTXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
    png_const_charp errmsg = NULL;
@@ -2724,37 +2594,35 @@ png_handle_iTXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
       if (png_ptr->user_chunk_cache_max == 1)
       {
          png_crc_finish(png_ptr, length);
-         return;
+         return handled_error;
       }
 
       if (--png_ptr->user_chunk_cache_max == 1)
       {
          png_crc_finish(png_ptr, length);
          png_chunk_benign_error(png_ptr, "no space in chunk cache");
-         return;
+         return handled_error;
       }
    }
 #endif
 
-   if ((png_ptr->mode & PNG_HAVE_IHDR) == 0)
-      png_chunk_error(png_ptr, "missing IHDR");
-
+   /* TODO: should not be necessary. */
    if ((png_ptr->mode & PNG_HAVE_IDAT) != 0)
       png_ptr->mode |= PNG_AFTER_IDAT;
 
-   buffer = png_read_buffer(png_ptr, length+1, 1/*warn*/);
+   buffer = png_read_buffer(png_ptr, length+1);
 
    if (buffer == NULL)
    {
       png_crc_finish(png_ptr, length);
       png_chunk_benign_error(png_ptr, "out of memory");
-      return;
+      return handled_error;
    }
 
    png_crc_read(png_ptr, buffer, length);
 
    if (png_crc_finish(png_ptr, 0) != 0)
-      return;
+      return handled_error;
 
    /* First the keyword. */
    for (prefix_length=0;
@@ -2844,8 +2712,10 @@ png_handle_iTXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
          text.text_length = 0;
          text.itxt_length = uncompressed_length;
 
-         if (png_set_text_2(png_ptr, info_ptr, &text, 1) != 0)
-            errmsg = "insufficient memory";
+         if (png_set_text_2(png_ptr, info_ptr, &text, 1) == 0)
+            return handled_ok;
+
+         errmsg = "out of memory";
       }
    }
 
@@ -2854,7 +2724,10 @@ png_handle_iTXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 
    if (errmsg != NULL)
       png_chunk_benign_error(png_ptr, errmsg);
+   return handled_error;
 }
+#else
+#  define png_handle_iTXt NULL
 #endif
 
 #ifdef PNG_READ_UNKNOWN_CHUNKS_SUPPORTED
@@ -2862,7 +2735,7 @@ png_handle_iTXt(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 static int
 png_cache_unknown_chunk(png_structrp png_ptr, png_uint_32 length)
 {
-   png_alloc_size_t limit = PNG_SIZE_MAX;
+   const png_alloc_size_t limit = png_chunk_max(png_ptr);
 
    if (png_ptr->unknown_chunk.data != NULL)
    {
@@ -2870,16 +2743,6 @@ png_cache_unknown_chunk(png_structrp png_ptr, png_uint_32 length)
       png_ptr->unknown_chunk.data = NULL;
    }
 
-#  ifdef PNG_SET_USER_LIMITS_SUPPORTED
-   if (png_ptr->user_chunk_malloc_max > 0 &&
-       png_ptr->user_chunk_malloc_max < limit)
-      limit = png_ptr->user_chunk_malloc_max;
-
-#  elif PNG_USER_CHUNK_MALLOC_MAX > 0
-   if (PNG_USER_CHUNK_MALLOC_MAX < limit)
-      limit = PNG_USER_CHUNK_MALLOC_MAX;
-#  endif
-
    if (length <= limit)
    {
       PNG_CSTRING_FROM_CHUNK(png_ptr->unknown_chunk.name, png_ptr->chunk_name);
@@ -2918,11 +2781,11 @@ png_cache_unknown_chunk(png_structrp png_ptr, png_uint_32 length)
 #endif /* READ_UNKNOWN_CHUNKS */
 
 /* Handle an unknown, or known but disabled, chunk */
-void /* PRIVATE */
+png_handle_result_code /*PRIVATE*/
 png_handle_unknown(png_structrp png_ptr, png_inforp info_ptr,
     png_uint_32 length, int keep)
 {
-   int handled = 0; /* the chunk was handled */
+   png_handle_result_code handled = handled_discarded; /* the default */
 
    png_debug(1, "in png_handle_unknown");
 
@@ -2969,7 +2832,7 @@ png_handle_unknown(png_structrp png_ptr, png_inforp info_ptr,
           *           error at this point unless it is to be saved.
           * positive: The chunk was handled, libpng will ignore/discard it.
           */
-         if (ret < 0)
+         if (ret < 0) /* handled_error */
             png_chunk_error(png_ptr, "error in user chunk");
 
          else if (ret == 0)
@@ -3003,7 +2866,7 @@ png_handle_unknown(png_structrp png_ptr, png_inforp info_ptr,
 
          else /* chunk was handled */
          {
-            handled = 1;
+            handled = handled_ok;
             /* Critical chunks can be safely discarded at this point. */
             keep = PNG_HANDLE_CHUNK_NEVER;
          }
@@ -3088,7 +2951,7 @@ png_handle_unknown(png_structrp png_ptr, png_inforp info_ptr,
              */
             png_set_unknown_chunks(png_ptr, info_ptr,
                 &png_ptr->unknown_chunk, 1);
-            handled = 1;
+            handled = handled_saved;
 #  ifdef PNG_USER_LIMITS_SUPPORTED
             break;
       }
@@ -3114,79 +2977,267 @@ png_handle_unknown(png_structrp png_ptr, png_inforp info_ptr,
 #endif /* !READ_UNKNOWN_CHUNKS */
 
    /* Check for unhandled critical chunks */
-   if (handled == 0 && PNG_CHUNK_CRITICAL(png_ptr->chunk_name))
+   if (handled < handled_saved && PNG_CHUNK_CRITICAL(png_ptr->chunk_name))
       png_chunk_error(png_ptr, "unhandled critical chunk");
+
+   return handled;
 }
 
-/* This function is called to verify that a chunk name is valid.
- * This function can't have the "critical chunk check" incorporated
- * into it, since in the future we will need to be able to call user
- * functions to handle unknown critical chunks after we check that
- * the chunk name itself is valid.
+/* APNG handling: the minimal implementation of APNG handling in libpng 1.6
+ * requires that those significant applications which already handle APNG not
+ * get hosed.  To do this ensure the code here will have to ensure than APNG
+ * data by default (at least in 1.6) gets stored in the unknown chunk list.
+ * Maybe this can be relaxed in a few years but at present it's just the only
+ * safe way.
+ *
+ * ATM just cause unknown handling for all three chunks:
  */
+#define png_handle_acTL NULL
+#define png_handle_fcTL NULL
+#define png_handle_fdAT NULL
 
-/* Bit hacking: the test for an invalid byte in the 4 byte chunk name is:
+/*
+ * 1.6.47: This is the new table driven interface to all the chunk handling.
  *
- * ((c) < 65 || (c) > 122 || ((c) > 90 && (c) < 97))
+ * The table describes the PNG standard rules for **reading** known chunks -
+ * every chunk which has an entry in PNG_KNOWN_CHUNKS.  The table contains an
+ * entry for each PNG_INDEX_cHNK describing the rules.
+ *
+ * In this initial version the only information in the entry is the
+ * png_handle_cHNK function for the chunk in question.  When chunk support is
+ * compiled out the entry will be NULL.
  */
-
-void /* PRIVATE */
-png_check_chunk_name(png_const_structrp png_ptr, png_uint_32 chunk_name)
+static const struct
 {
-   int i;
-   png_uint_32 cn=chunk_name;
-
-   png_debug(1, "in png_check_chunk_name");
+   png_handle_result_code (*handler)(
+         png_structrp, png_inforp, png_uint_32 length);
+      /* A chunk-specific 'handler', NULL if the chunk is not supported in this
+       * build.
+       */
 
-   for (i=1; i<=4; ++i)
+   /* Crushing these values helps on modern 32-bit architectures because the
+    * pointer and the following bit fields both end up requiring 32 bits.
+    * Typically this will halve the table size.  On 64-bit architectures the
+    * table entries will typically be 8 bytes.
+    */
+   png_uint_32 max_length :12; /* Length min, max in bytes */
+   png_uint_32 min_length :8;
+      /* Length errors on critical chunks have special handling to preserve the
+       * existing behaviour in libpng 1.6.  Anciallary chunks are checked below
+       * and produce a 'benign' error.
+       */
+   png_uint_32 pos_before :4; /* PNG_HAVE_ values chunk must precede */
+   png_uint_32 pos_after  :4; /* PNG_HAVE_ values chunk must follow */
+      /* NOTE: PLTE, tRNS and bKGD require special handling which depends on
+       * the colour type of the base image.
+       */
+   png_uint_32 multiple   :1; /* Multiple occurences permitted */
+      /* This is enabled for PLTE because PLTE may, in practice, be optional */
+}
+read_chunks[PNG_INDEX_unknown] =
+{
+   /* Definitions as above but done indirectly by #define so that
+    * PNG_KNOWN_CHUNKS can be used safely to build the table in order.
+    *
+    * Each CDcHNK definition lists the values for the parameters **after**
+    * the first, 'handler', function.  'handler' is NULL when the chunk has no
+    * compiled in support.
+    */
+#  define NoCheck 0x801U      /* Do not check the maximum length */
+#  define Limit   0x802U      /* Limit to png_chunk_max bytes */
+#  define LKMin   3U+LZ77Min  /* Minimum length of keyword+LZ77 */
+
+#define hIHDR PNG_HAVE_IHDR
+#define hPLTE PNG_HAVE_PLTE
+#define hIDAT PNG_HAVE_IDAT
+   /* For the two chunks, tRNS and bKGD which can occur in PNGs without a PLTE
+    * but must occur after the PLTE use this and put the check in the handler
+    * routine for colour mapped images were PLTE is required.  Also put a check
+    * in PLTE for other image types to drop the PLTE if tRNS or bKGD have been
+    * seen.
+    */
+#define hCOL  (PNG_HAVE_PLTE|PNG_HAVE_IDAT)
+   /* Used for the decoding chunks which must be before PLTE. */
+#define aIDAT PNG_AFTER_IDAT
+
+   /* Chunks from W3C PNG v3: */
+   /*       cHNK  max_len,   min, before, after, multiple */
+#  define CDIHDR      13U,   13U,  hIHDR,     0,        0
+#  define CDPLTE  NoCheck,    0U,      0, hIHDR,        1
+      /* PLTE errors are only critical for colour-map images, consequently the
+       * hander does all the checks.
+       */
+#  define CDIDAT  NoCheck,    0U,  aIDAT, hIHDR,        1
+#  define CDIEND  NoCheck,    0U,      0, aIDAT,        0
+      /* Historically data was allowed in IEND */
+#  define CDtRNS     256U,    0U,  hIDAT, hIHDR,        0
+#  define CDcHRM      32U,   32U,   hCOL, hIHDR,        0
+#  define CDgAMA       4U,    4U,   hCOL, hIHDR,        0
+#  define CDiCCP  NoCheck, LKMin,   hCOL, hIHDR,        0
+#  define CDsBIT       4U,    1U,   hCOL, hIHDR,        0
+#  define CDsRGB       1U,    1U,   hCOL, hIHDR,        0
+#  define CDcICP       4U,    4U,   hCOL, hIHDR,        0
+#  define CDmDCV      24U,   24U,   hCOL, hIHDR,        0
+#  define CDeXIf    Limit,    4U,      0, hIHDR,        0
+#  define CDcLLI       8U,    8U,   hCOL, hIHDR,        0
+#  define CDtEXt  NoCheck,    2U,      0, hIHDR,        1
+      /* Allocates 'length+1'; checked in the handler */
+#  define CDzTXt    Limit, LKMin,      0, hIHDR,        1
+#  define CDiTXt  NoCheck,    6U,      0, hIHDR,        1
+      /* Allocates 'length+1'; checked in the handler */
+#  define CDbKGD       6U,    1U,  hIDAT, hIHDR,        0
+#  define CDhIST    1024U,    0U,  hPLTE, hIHDR,        0
+#  define CDpHYs       9U,    9U,  hIDAT, hIHDR,        0
+#  define CDsPLT  NoCheck,    3U,  hIDAT, hIHDR,        1
+      /* Allocates 'length+1'; checked in the handler */
+#  define CDtIME       7U,    7U,      0, hIHDR,        0
+#  define CDacTL       8U,    8U,  hIDAT, hIHDR,        0
+#  define CDfcTL      25U,   26U,      0, hIHDR,        1
+#  define CDfdAT    Limit,    4U,  hIDAT, hIHDR,        1
+   /* Supported chunks from PNG extensions 1.5.0, NYI so limit */
+#  define CDoFFs       9U,    9U,  hIDAT, hIHDR,        0
+#  define CDpCAL  NoCheck,   14U,  hIDAT, hIHDR,        0
+      /* Allocates 'length+1'; checked in the handler */
+#  define CDsCAL    Limit,    4U,  hIDAT, hIHDR,        0
+      /* Allocates 'length+1'; checked in the handler */
+
+#  define PNG_CHUNK(cHNK, index) { png_handle_ ## cHNK, CD ## cHNK },
+   PNG_KNOWN_CHUNKS
+#  undef PNG_CHUNK
+};
+
+
+static png_index
+png_chunk_index_from_name(png_uint_32 chunk_name)
+{
+   /* For chunk png_cHNK return PNG_INDEX_cHNK.  Return PNG_INDEX_unknown if
+    * chunk_name is not known.  Notice that in a particular build "known" does
+    * not necessarily mean "supported", although the inverse applies.
+    */
+   switch (chunk_name)
    {
-      int c = cn & 0xff;
+#     define PNG_CHUNK(cHNK, index)\
+         case png_ ## cHNK: return PNG_INDEX_ ## cHNK; /* == index */
+
+      PNG_KNOWN_CHUNKS
 
-      if (c < 65 || c > 122 || (c > 90 && c < 97))
-         png_chunk_error(png_ptr, "invalid chunk type");
+#     undef PNG_CHUNK
 
-      cn >>= 8;
+      default: return PNG_INDEX_unknown;
    }
 }
 
-void /* PRIVATE */
-png_check_chunk_length(png_const_structrp png_ptr, png_uint_32 length)
+png_handle_result_code /*PRIVATE*/
+png_handle_chunk(png_structrp png_ptr, png_inforp info_ptr, png_uint_32 length)
 {
-   png_alloc_size_t limit = PNG_UINT_31_MAX;
-
-# ifdef PNG_SET_USER_LIMITS_SUPPORTED
-   if (png_ptr->user_chunk_malloc_max > 0 &&
-       png_ptr->user_chunk_malloc_max < limit)
-      limit = png_ptr->user_chunk_malloc_max;
-# elif PNG_USER_CHUNK_MALLOC_MAX > 0
-   if (PNG_USER_CHUNK_MALLOC_MAX < limit)
-      limit = PNG_USER_CHUNK_MALLOC_MAX;
-# endif
-   if (png_ptr->chunk_name == png_IDAT)
+   /* CSE: these things don't change, these autos are just to save typing and
+    * make the code more clear.
+    */
+   const png_uint_32 chunk_name = png_ptr->chunk_name;
+   const png_index chunk_index = png_chunk_index_from_name(chunk_name);
+
+   png_handle_result_code handled = handled_error;
+   png_const_charp errmsg = NULL;
+
+   /* Is this a known chunk?  If not there are no checks performed here;
+    * png_handle_unknown does the correct checks.  This means that the values
+    * for known but unsupported chunks in the above table are not used here
+    * however the chunks_seen fields in png_struct are still set.
+    */
+   if (chunk_index == PNG_INDEX_unknown ||
+       read_chunks[chunk_index].handler == NULL)
    {
-      png_alloc_size_t idat_limit = PNG_UINT_31_MAX;
-      size_t row_factor =
-         (size_t)png_ptr->width
-         * (size_t)png_ptr->channels
-         * (png_ptr->bit_depth > 8? 2: 1)
-         + 1
-         + (png_ptr->interlaced? 6: 0);
-      if (png_ptr->height > PNG_UINT_32_MAX/row_factor)
-         idat_limit = PNG_UINT_31_MAX;
-      else
-         idat_limit = png_ptr->height * row_factor;
-      row_factor = row_factor > 32566? 32566 : row_factor;
-      idat_limit += 6 + 5*(idat_limit/row_factor+1); /* zlib+deflate overhead */
-      idat_limit=idat_limit < PNG_UINT_31_MAX? idat_limit : PNG_UINT_31_MAX;
-      limit = limit < idat_limit? idat_limit : limit;
+      handled = png_handle_unknown(
+            png_ptr, info_ptr, length, PNG_HANDLE_CHUNK_AS_DEFAULT);
+   }
+
+   /* First check the position.   The first check is historical; the stream must
+    * start with IHDR and anything else causes libpng to give up immediately.
+    */
+   else if (chunk_index != PNG_INDEX_IHDR &&
+            (png_ptr->mode & PNG_HAVE_IHDR) == 0)
+      png_chunk_error(png_ptr, "missing IHDR"); /* NORETURN */
+
+   /* Before all the pos_before chunks, after all the pos_after chunks. */
+   else if (((png_ptr->mode & read_chunks[chunk_index].pos_before) != 0) ||
+            ((png_ptr->mode & read_chunks[chunk_index].pos_after) !=
+             read_chunks[chunk_index].pos_after))
+   {
+      errmsg = "out of place";
+   }
+
+   /* Now check for duplicates: duplicated critical chunks also produce a
+    * full error.
+    */
+   else if (read_chunks[chunk_index].multiple == 0 &&
+            png_file_has_chunk(png_ptr, chunk_index))
+   {
+      errmsg = "duplicate";
+   }
+
+   else if (length < read_chunks[chunk_index].min_length)
+      errmsg = "too short";
+   else
+   {
+      /* NOTE: apart from IHDR the critical chunks (PLTE, IDAT and IEND) are set
+       * up above not to do any length checks.
+       *
+       * The png_chunk_max check ensures that the variable length chunks are
+       * always checked at this point for being within the system allocation
+       * limits.
+       */
+      unsigned max_length = read_chunks[chunk_index].max_length;
+
+      switch (max_length)
+      {
+         case Limit:
+            /* png_read_chunk_header has already png_error'ed chunks with a
+             * length exceeding the 31-bit PNG limit, so just check the memory
+             * limit:
+             */
+            if (length <= png_chunk_max(png_ptr))
+               goto MeetsLimit;
+
+            errmsg = "length exceeds libpng limit";
+            break;
+
+         default:
+            if (length <= max_length)
+               goto MeetsLimit;
+
+            errmsg = "too long";
+            break;
+
+         case NoCheck:
+         MeetsLimit:
+            handled = read_chunks[chunk_index].handler(
+                  png_ptr, info_ptr, length);
+            break;
+      }
+   }
+
+   /* If there was an error or the chunk was simply skipped it is not counted as
+    * 'seen'.
+    */
+   if (errmsg != NULL)
+   {
+      if (PNG_CHUNK_CRITICAL(chunk_name)) /* stop immediately */
+         png_chunk_error(png_ptr, errmsg);
+      else /* ancillary chunk */
+      {
+         /* The chunk data is skipped: */
+         png_crc_finish(png_ptr, length);
+         png_chunk_benign_error(png_ptr, errmsg);
+      }
    }
 
-   if (length > limit)
+   else if (handled >= handled_saved)
    {
-      png_debug2(0," length = %lu, limit = %lu",
-         (unsigned long)length,(unsigned long)limit);
-      png_benign_error(png_ptr, "chunk data is too large");
+      if (chunk_index != PNG_INDEX_unknown)
+         png_file_add_chunk(png_ptr, chunk_index);
    }
+
+   return handled;
 }
 
 /* Combines the row recently read in with the existing pixels in the row.  This
@@ -3684,10 +3735,6 @@ void /* PRIVATE */
 png_do_read_interlace(png_row_infop row_info, png_bytep row, int pass,
     png_uint_32 transformations /* Because these may affect the byte layout */)
 {
-   /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
-   /* Offset to next interlace block */
-   static const unsigned int png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
-
    png_debug(1, "in png_do_read_interlace");
    if (row != NULL && row_info != NULL)
    {
@@ -4180,6 +4227,9 @@ png_read_IDAT_data(png_structrp png_ptr, png_bytep output,
 
          avail_in = png_ptr->IDAT_read_size;
 
+         if (avail_in > png_chunk_max(png_ptr))
+            avail_in = (uInt)/*SAFE*/png_chunk_max(png_ptr);
+
          if (avail_in > png_ptr->idat_size)
             avail_in = (uInt)png_ptr->idat_size;
 
@@ -4187,8 +4237,13 @@ png_read_IDAT_data(png_structrp png_ptr, png_bytep output,
           * to minimize memory usage by causing lots of re-allocs, but
           * realistically doing IDAT_read_size re-allocs is not likely to be a
           * big problem.
+          *
+          * An error here corresponds to the system being out of memory.
           */
-         buffer = png_read_buffer(png_ptr, avail_in, 0/*error*/);
+         buffer = png_read_buffer(png_ptr, avail_in);
+
+         if (buffer == NULL)
+            png_chunk_error(png_ptr, "out of memory");
 
          png_crc_read(png_ptr, buffer, avail_in);
          png_ptr->idat_size -= avail_in;
@@ -4325,20 +4380,6 @@ png_read_finish_IDAT(png_structrp png_ptr)
 void /* PRIVATE */
 png_read_finish_row(png_structrp png_ptr)
 {
-   /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
-
-   /* Start of interlace block */
-   static const png_byte png_pass_start[7] = {0, 4, 0, 2, 0, 1, 0};
-
-   /* Offset to next interlace block */
-   static const png_byte png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
-
-   /* Start of interlace block in the y direction */
-   static const png_byte png_pass_ystart[7] = {0, 0, 4, 0, 2, 0, 1};
-
-   /* Offset to next interlace block in the y direction */
-   static const png_byte png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
-
    png_debug(1, "in png_read_finish_row");
    png_ptr->row_number++;
    if (png_ptr->row_number < png_ptr->num_rows)
@@ -4390,20 +4431,6 @@ png_read_finish_row(png_structrp png_ptr)
 void /* PRIVATE */
 png_read_start_row(png_structrp png_ptr)
 {
-   /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
-
-   /* Start of interlace block */
-   static const png_byte png_pass_start[7] = {0, 4, 0, 2, 0, 1, 0};
-
-   /* Offset to next interlace block */
-   static const png_byte png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
-
-   /* Start of interlace block in the y direction */
-   static const png_byte png_pass_ystart[7] = {0, 0, 4, 0, 2, 0, 1};
-
-   /* Offset to next interlace block in the y direction */
-   static const png_byte png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
-
    unsigned int max_pixel_depth;
    size_t row_bytes;
 
diff --git a/pngset.c b/pngset.c
index eb1c8c7a3..d7f3393c4 100644
--- a/pngset.c
+++ b/pngset.c
@@ -1,7 +1,6 @@
-
 /* pngset.c - storage of image information into info struct
  *
- * Copyright (c) 2018-2024 Cosmin Truta
+ * Copyright (c) 2018-2025 Cosmin Truta
  * Copyright (c) 1998-2018 Glenn Randers-Pehrson
  * Copyright (c) 1996-1997 Andreas Dilger
  * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
@@ -42,27 +41,21 @@ png_set_cHRM_fixed(png_const_structrp png_ptr, png_inforp info_ptr,
     png_fixed_point red_y, png_fixed_point green_x, png_fixed_point green_y,
     png_fixed_point blue_x, png_fixed_point blue_y)
 {
-   png_xy xy;
-
    png_debug1(1, "in %s storage function", "cHRM fixed");
 
    if (png_ptr == NULL || info_ptr == NULL)
       return;
 
-   xy.redx = red_x;
-   xy.redy = red_y;
-   xy.greenx = green_x;
-   xy.greeny = green_y;
-   xy.bluex = blue_x;
-   xy.bluey = blue_y;
-   xy.whitex = white_x;
-   xy.whitey = white_y;
+   info_ptr->cHRM.redx = red_x;
+   info_ptr->cHRM.redy = red_y;
+   info_ptr->cHRM.greenx = green_x;
+   info_ptr->cHRM.greeny = green_y;
+   info_ptr->cHRM.bluex = blue_x;
+   info_ptr->cHRM.bluey = blue_y;
+   info_ptr->cHRM.whitex = white_x;
+   info_ptr->cHRM.whitey = white_y;
 
-   if (png_colorspace_set_chromaticities(png_ptr, &info_ptr->colorspace, &xy,
-       2/* override with app values*/) != 0)
-      info_ptr->colorspace.flags |= PNG_COLORSPACE_FROM_cHRM;
-
-   png_colorspace_sync_info(png_ptr, info_ptr);
+   info_ptr->valid |= PNG_INFO_cHRM;
 }
 
 void PNGFAPI
@@ -74,6 +67,7 @@ png_set_cHRM_XYZ_fixed(png_const_structrp png_ptr, png_inforp info_ptr,
     png_fixed_point int_blue_Z)
 {
    png_XYZ XYZ;
+   png_xy xy;
 
    png_debug1(1, "in %s storage function", "cHRM XYZ fixed");
 
@@ -90,11 +84,14 @@ png_set_cHRM_XYZ_fixed(png_const_structrp png_ptr, png_inforp info_ptr,
    XYZ.blue_Y = int_blue_Y;
    XYZ.blue_Z = int_blue_Z;
 
-   if (png_colorspace_set_endpoints(png_ptr, &info_ptr->colorspace,
-       &XYZ, 2) != 0)
-      info_ptr->colorspace.flags |= PNG_COLORSPACE_FROM_cHRM;
+   if (png_xy_from_XYZ(&xy, &XYZ) == 0)
+   {
+      info_ptr->cHRM = xy;
+      info_ptr->valid |= PNG_INFO_cHRM;
+   }
 
-   png_colorspace_sync_info(png_ptr, info_ptr);
+   else
+      png_app_error(png_ptr, "invalid cHRM XYZ");
 }
 
 #  ifdef PNG_FLOATING_POINT_SUPPORTED
@@ -134,6 +131,192 @@ png_set_cHRM_XYZ(png_const_structrp png_ptr, png_inforp info_ptr, double red_X,
 
 #endif /* cHRM */
 
+#ifdef PNG_cICP_SUPPORTED
+void PNGAPI
+png_set_cICP(png_const_structrp png_ptr, png_inforp info_ptr,
+             png_byte colour_primaries, png_byte transfer_function,
+             png_byte matrix_coefficients, png_byte video_full_range_flag)
+{
+   png_debug1(1, "in %s storage function", "cICP");
+
+   if (png_ptr == NULL || info_ptr == NULL)
+      return;
+
+   info_ptr->cicp_colour_primaries = colour_primaries;
+   info_ptr->cicp_transfer_function = transfer_function;
+   info_ptr->cicp_matrix_coefficients = matrix_coefficients;
+   info_ptr->cicp_video_full_range_flag = video_full_range_flag;
+
+   if (info_ptr->cicp_matrix_coefficients != 0)
+   {
+      png_warning(png_ptr, "Invalid cICP matrix coefficients");
+      return;
+   }
+
+   info_ptr->valid |= PNG_INFO_cICP;
+}
+#endif /* cICP */
+
+#ifdef PNG_cLLI_SUPPORTED
+void PNGFAPI
+png_set_cLLI_fixed(png_const_structrp png_ptr, png_inforp info_ptr,
+    /* The values below are in cd/m2 (nits) and are scaled by 10,000; not
+     * 100,000 as in the case of png_fixed_point.
+     */
+    png_uint_32 maxCLL, png_uint_32 maxFALL)
+{
+   png_debug1(1, "in %s storage function", "cLLI");
+
+   if (png_ptr == NULL || info_ptr == NULL)
+      return;
+
+   /* Check the light level range: */
+   if (maxCLL > 0x7FFFFFFFU || maxFALL > 0x7FFFFFFFU)
+   {
+      /* The limit is 200kcd/m2; somewhat bright but not inconceivable because
+       * human vision is said to run up to 100Mcd/m2.  The sun is about 2Gcd/m2.
+       *
+       * The reference sRGB monitor is 80cd/m2 and the limit of PQ encoding is
+       * 2kcd/m2.
+       */
+      png_chunk_report(png_ptr, "cLLI light level exceeds PNG limit",
+            PNG_CHUNK_WRITE_ERROR);
+      return;
+   }
+
+   info_ptr->maxCLL = maxCLL;
+   info_ptr->maxFALL = maxFALL;
+   info_ptr->valid |= PNG_INFO_cLLI;
+}
+
+#  ifdef PNG_FLOATING_POINT_SUPPORTED
+void PNGAPI
+png_set_cLLI(png_const_structrp png_ptr, png_inforp info_ptr,
+   double maxCLL, double maxFALL)
+{
+   png_set_cLLI_fixed(png_ptr, info_ptr,
+       png_fixed_ITU(png_ptr, maxCLL, "png_set_cLLI(maxCLL)"),
+       png_fixed_ITU(png_ptr, maxFALL, "png_set_cLLI(maxFALL)"));
+}
+#  endif /* FLOATING_POINT */
+#endif /* cLLI */
+
+#ifdef PNG_mDCV_SUPPORTED
+static png_uint_16
+png_ITU_fixed_16(int *error, png_fixed_point v)
+{
+   /* Return a safe uint16_t value scaled according to the ITU H273 rules for
+    * 16-bit display chromaticities.  Functions like the corresponding
+    * png_fixed() internal function with regard to errors: it's an error on
+    * write, a chunk_benign_error on read: See the definition of
+    * png_chunk_report in pngpriv.h.
+    */
+   v /= 2; /* rounds to 0 in C: avoids insignificant arithmetic errors */
+   if (v > 65535 || v < 0)
+   {
+      *error = 1;
+      return 0;
+   }
+
+   return (png_uint_16)/*SAFE*/v;
+}
+
+void PNGAPI
+png_set_mDCV_fixed(png_const_structrp png_ptr, png_inforp info_ptr,
+    png_fixed_point white_x, png_fixed_point white_y,
+    png_fixed_point red_x, png_fixed_point red_y,
+    png_fixed_point green_x, png_fixed_point green_y,
+    png_fixed_point blue_x, png_fixed_point blue_y,
+    png_uint_32 maxDL,
+    png_uint_32 minDL)
+{
+   png_uint_16 rx, ry, gx, gy, bx, by, wx, wy;
+   int error;
+
+   png_debug1(1, "in %s storage function", "mDCV");
+
+   if (png_ptr == NULL || info_ptr == NULL)
+      return;
+
+   /* Check the input values to ensure they are in the expected range: */
+   error = 0;
+   rx = png_ITU_fixed_16(&error, red_x);
+   ry = png_ITU_fixed_16(&error, red_y);
+   gx = png_ITU_fixed_16(&error, green_x);
+   gy = png_ITU_fixed_16(&error, green_y);
+   bx = png_ITU_fixed_16(&error, blue_x);
+   by = png_ITU_fixed_16(&error, blue_y);
+   wx = png_ITU_fixed_16(&error, white_x);
+   wy = png_ITU_fixed_16(&error, white_y);
+
+   if (error)
+   {
+      png_chunk_report(png_ptr,
+         "mDCV chromaticities outside representable range",
+         PNG_CHUNK_WRITE_ERROR);
+      return;
+   }
+
+   /* Check the light level range: */
+   if (maxDL > 0x7FFFFFFFU || minDL > 0x7FFFFFFFU)
+   {
+      /* The limit is 200kcd/m2; somewhat bright but not inconceivable because
+       * human vision is said to run up to 100Mcd/m2.  The sun is about 2Gcd/m2.
+       *
+       * The reference sRGB monitor is 80cd/m2 and the limit of PQ encoding is
+       * 2kcd/m2.
+       */
+      png_chunk_report(png_ptr, "mDCV display light level exceeds PNG limit",
+            PNG_CHUNK_WRITE_ERROR);
+      return;
+   }
+
+   /* All values are safe, the settings are accepted.
+    *
+    * IMPLEMENTATION NOTE: in practice the values can be checked and assigned
+    * but the result is confusing if a writing app calls png_set_mDCV more than
+    * once, the second time with an invalid value.  This approach is more
+    * obviously correct at the cost of typing and a very slight machine
+    * overhead.
+    */
+   info_ptr->mastering_red_x = rx;
+   info_ptr->mastering_red_y = ry;
+   info_ptr->mastering_green_x = gx;
+   info_ptr->mastering_green_y = gy;
+   info_ptr->mastering_blue_x = bx;
+   info_ptr->mastering_blue_y = by;
+   info_ptr->mastering_white_x = wx;
+   info_ptr->mastering_white_y = wy;
+   info_ptr->mastering_maxDL = maxDL;
+   info_ptr->mastering_minDL = minDL;
+   info_ptr->valid |= PNG_INFO_mDCV;
+}
+
+#  ifdef PNG_FLOATING_POINT_SUPPORTED
+void PNGAPI
+png_set_mDCV(png_const_structrp png_ptr, png_inforp info_ptr,
+    double white_x, double white_y, double red_x, double red_y, double green_x,
+    double green_y, double blue_x, double blue_y,
+    double maxDL, double minDL)
+{
+   png_set_mDCV_fixed(png_ptr, info_ptr,
+      /* The ITU approach is to scale by 50,000, not 100,000 so just divide
+       * the input values by 2 and use png_fixed:
+       */
+      png_fixed(png_ptr, white_x / 2, "png_set_mDCV(white(x))"),
+      png_fixed(png_ptr, white_y / 2, "png_set_mDCV(white(y))"),
+      png_fixed(png_ptr, red_x / 2, "png_set_mDCV(red(x))"),
+      png_fixed(png_ptr, red_y / 2, "png_set_mDCV(red(y))"),
+      png_fixed(png_ptr, green_x / 2, "png_set_mDCV(green(x))"),
+      png_fixed(png_ptr, green_y / 2, "png_set_mDCV(green(y))"),
+      png_fixed(png_ptr, blue_x / 2, "png_set_mDCV(blue(x))"),
+      png_fixed(png_ptr, blue_y / 2, "png_set_mDCV(blue(y))"),
+      png_fixed_ITU(png_ptr, maxDL, "png_set_mDCV(maxDL)"),
+      png_fixed_ITU(png_ptr, minDL, "png_set_mDCV(minDL)"));
+}
+#  endif /* FLOATING_POINT */
+#endif /* mDCV */
+
 #ifdef PNG_eXIf_SUPPORTED
 void PNGAPI
 png_set_eXIf(png_const_structrp png_ptr, png_inforp info_ptr,
@@ -185,8 +368,8 @@ png_set_gAMA_fixed(png_const_structrp png_ptr, png_inforp info_ptr,
    if (png_ptr == NULL || info_ptr == NULL)
       return;
 
-   png_colorspace_set_gamma(png_ptr, &info_ptr->colorspace, file_gamma);
-   png_colorspace_sync_info(png_ptr, info_ptr);
+   info_ptr->gamma = file_gamma;
+   info_ptr->valid |= PNG_INFO_gAMA;
 }
 
 #  ifdef PNG_FLOATING_POINT_SUPPORTED
@@ -645,8 +828,8 @@ png_set_sRGB(png_const_structrp png_ptr, png_inforp info_ptr, int srgb_intent)
    if (png_ptr == NULL || info_ptr == NULL)
       return;
 
-   (void)png_colorspace_set_sRGB(png_ptr, &info_ptr->colorspace, srgb_intent);
-   png_colorspace_sync_info(png_ptr, info_ptr);
+   info_ptr->rendering_intent = srgb_intent;
+   info_ptr->valid |= PNG_INFO_sRGB;
 }
 
 void PNGAPI
@@ -658,15 +841,20 @@ png_set_sRGB_gAMA_and_cHRM(png_const_structrp png_ptr, png_inforp info_ptr,
    if (png_ptr == NULL || info_ptr == NULL)
       return;
 
-   if (png_colorspace_set_sRGB(png_ptr, &info_ptr->colorspace,
-       srgb_intent) != 0)
-   {
-      /* This causes the gAMA and cHRM to be written too */
-      info_ptr->colorspace.flags |=
-         PNG_COLORSPACE_FROM_gAMA|PNG_COLORSPACE_FROM_cHRM;
-   }
+   png_set_sRGB(png_ptr, info_ptr, srgb_intent);
+
+#  ifdef PNG_gAMA_SUPPORTED
+      png_set_gAMA_fixed(png_ptr, info_ptr, PNG_GAMMA_sRGB_INVERSE);
+#  endif /* gAMA */
 
-   png_colorspace_sync_info(png_ptr, info_ptr);
+#  ifdef PNG_cHRM_SUPPORTED
+      png_set_cHRM_fixed(png_ptr, info_ptr,
+         /* color      x       y */
+         /* white */ 31270, 32900,
+         /* red   */ 64000, 33000,
+         /* green */ 30000, 60000,
+         /* blue  */ 15000,  6000);
+#  endif /* cHRM */
 }
 #endif /* sRGB */
 
@@ -689,27 +877,6 @@ png_set_iCCP(png_const_structrp png_ptr, png_inforp info_ptr,
    if (compression_type != PNG_COMPRESSION_TYPE_BASE)
       png_app_error(png_ptr, "Invalid iCCP compression method");
 
-   /* Set the colorspace first because this validates the profile; do not
-    * override previously set app cHRM or gAMA here (because likely as not the
-    * application knows better than libpng what the correct values are.)  Pass
-    * the info_ptr color_type field to png_colorspace_set_ICC because in the
-    * write case it has not yet been stored in png_ptr.
-    */
-   {
-      int result = png_colorspace_set_ICC(png_ptr, &info_ptr->colorspace, name,
-          proflen, profile, info_ptr->color_type);
-
-      png_colorspace_sync_info(png_ptr, info_ptr);
-
-      /* Don't do any of the copying if the profile was bad, or inconsistent. */
-      if (result == 0)
-         return;
-
-      /* But do write the gAMA and cHRM chunks from the profile. */
-      info_ptr->colorspace.flags |=
-         PNG_COLORSPACE_FROM_gAMA|PNG_COLORSPACE_FROM_cHRM;
-   }
-
    length = strlen(name)+1;
    new_iccp_name = png_voidcast(png_charp, png_malloc_warn(png_ptr, length));
 
@@ -1395,11 +1562,14 @@ png_set_keep_unknown_chunks(png_structrp png_ptr, int keep,
       static const png_byte chunks_to_ignore[] = {
          98,  75,  71,  68, '\0',  /* bKGD */
          99,  72,  82,  77, '\0',  /* cHRM */
+         99,  73,  67,  80, '\0',  /* cICP */
+         99,  76,  76,  73, '\0',  /* cLLI */
         101,  88,  73, 102, '\0',  /* eXIf */
         103,  65,  77,  65, '\0',  /* gAMA */
         104,  73,  83,  84, '\0',  /* hIST */
         105,  67,  67,  80, '\0',  /* iCCP */
         105,  84,  88, 116, '\0',  /* iTXt */
+        109,  68,  67,  86, '\0',  /* mDCV */
         111,  70,  70, 115, '\0',  /* oFFs */
         112,  67,  65,  76, '\0',  /* pCAL */
         112,  72,  89, 115, '\0',  /* pHYs */
@@ -1661,8 +1831,24 @@ png_set_chunk_malloc_max(png_structrp png_ptr,
 {
    png_debug(1, "in png_set_chunk_malloc_max");
 
+   /* pngstruct::user_chunk_malloc_max is initialized to a non-zero value in
+    * png.c.  This API supports '0' for unlimited, make sure the correct
+    * (unlimited) value is set here to avoid a need to check for 0 everywhere
+    * the parameter is used.
+    */
    if (png_ptr != NULL)
-      png_ptr->user_chunk_malloc_max = user_chunk_malloc_max;
+   {
+      if (user_chunk_malloc_max == 0U) /* unlimited */
+      {
+#        ifdef PNG_MAX_MALLOC_64K
+            png_ptr->user_chunk_malloc_max = 65536U;
+#        else
+            png_ptr->user_chunk_malloc_max = PNG_SIZE_MAX;
+#        endif
+      }
+      else
+         png_ptr->user_chunk_malloc_max = user_chunk_malloc_max;
+   }
 }
 #endif /* ?SET_USER_LIMITS */
 
diff --git a/pngstruct.h b/pngstruct.h
index e591d94d5..324424495 100644
--- a/pngstruct.h
+++ b/pngstruct.h
@@ -1,4 +1,3 @@
-
 /* pngstruct.h - header file for PNG reference library
  *
  * Copyright (c) 2018-2022 Cosmin Truta
@@ -70,13 +69,7 @@ typedef struct png_compression_buffer
 
 /* Colorspace support; structures used in png_struct, png_info and in internal
  * functions to hold and communicate information about the color space.
- *
- * PNG_COLORSPACE_SUPPORTED is only required if the application will perform
- * colorspace corrections, otherwise all the colorspace information can be
- * skipped and the size of libpng can be reduced (significantly) by compiling
- * out the colorspace support.
  */
-#ifdef PNG_COLORSPACE_SUPPORTED
 /* The chromaticities of the red, green and blue colorants and the chromaticity
  * of the corresponding white point (i.e. of rgb(1.0,1.0,1.0)).
  */
@@ -97,48 +90,36 @@ typedef struct png_XYZ
    png_fixed_point green_X, green_Y, green_Z;
    png_fixed_point blue_X, blue_Y, blue_Z;
 } png_XYZ;
-#endif /* COLORSPACE */
 
-#if defined(PNG_COLORSPACE_SUPPORTED) || defined(PNG_GAMMA_SUPPORTED)
-/* A colorspace is all the above plus, potentially, profile information;
- * however at present libpng does not use the profile internally so it is only
- * stored in the png_info struct (if iCCP is supported.)  The rendering intent
- * is retained here and is checked.
- *
- * The file gamma encoding information is also stored here and gamma correction
- * is done by libpng, whereas color correction must currently be done by the
- * application.
+/* Chunk index values as an enum, PNG_INDEX_unknown is also a count of the
+ * number of chunks.
  */
-typedef struct png_colorspace
+#define PNG_CHUNK(cHNK, i) PNG_INDEX_ ## cHNK = (i),
+typedef enum
 {
-#ifdef PNG_GAMMA_SUPPORTED
-   png_fixed_point gamma;        /* File gamma */
-#endif
-
-#ifdef PNG_COLORSPACE_SUPPORTED
-   png_xy      end_points_xy;    /* End points as chromaticities */
-   png_XYZ     end_points_XYZ;   /* End points as CIE XYZ colorant values */
-   png_uint_16 rendering_intent; /* Rendering intent of a profile */
-#endif
+   PNG_KNOWN_CHUNKS
+   PNG_INDEX_unknown
+} png_index;
+#undef PNG_CHUNK
 
-   /* Flags are always defined to simplify the code. */
-   png_uint_16 flags;            /* As defined below */
-} png_colorspace, * PNG_RESTRICT png_colorspacerp;
+/* Chunk flag values.  These are (png_uint_32 values) with exactly one bit set
+ * and can be combined into a flag set with bitwise 'or'.
+ *
+ * TODO: C23: convert these macros to C23 inlines (which are static).
+ */
+#define png_chunk_flag_from_index(i) (0x80000000U >> (31 - (i)))
+   /* The flag coresponding to the given png_index enum value.  This is defined
+    * for png_unknown as well (until it reaches the value 32) but this should
+    * not be relied on.
+    */
 
-typedef const png_colorspace * PNG_RESTRICT png_const_colorspacerp;
+#define png_file_has_chunk(png_ptr, i)\
+   (((png_ptr)->chunks & png_chunk_flag_from_index(i)) != 0)
+   /* The chunk has been recorded in png_struct */
 
-/* General flags for the 'flags' field */
-#define PNG_COLORSPACE_HAVE_GAMMA           0x0001
-#define PNG_COLORSPACE_HAVE_ENDPOINTS       0x0002
-#define PNG_COLORSPACE_HAVE_INTENT          0x0004
-#define PNG_COLORSPACE_FROM_gAMA            0x0008
-#define PNG_COLORSPACE_FROM_cHRM            0x0010
-#define PNG_COLORSPACE_FROM_sRGB            0x0020
-#define PNG_COLORSPACE_ENDPOINTS_MATCH_sRGB 0x0040
-#define PNG_COLORSPACE_MATCHES_sRGB         0x0080 /* exact match on profile */
-#define PNG_COLORSPACE_INVALID              0x8000
-#define PNG_COLORSPACE_CANCEL(flags)        (0xffff ^ (flags))
-#endif /* COLORSPACE || GAMMA */
+#define png_file_add_chunk(pnt_ptr, i)\
+   ((void)((png_ptr)->chunks |= png_chunk_flag_from_index(i)))
+   /* Record the chunk in the png_struct */
 
 struct png_struct_def
 {
@@ -210,6 +191,11 @@ struct png_struct_def
    int zlib_set_strategy;
 #endif
 
+   png_uint_32 chunks; /* PNG_CF_ for every chunk read or (NYI) written */
+#  define png_has_chunk(png_ptr, cHNK)\
+      png_file_has_chunk(png_ptr, PNG_INDEX_ ## cHNK)
+      /* Convenience accessor - use this to check for a known chunk by name */
+
    png_uint_32 width;         /* width of image in pixels */
    png_uint_32 height;        /* height of image in pixels */
    png_uint_32 num_rows;      /* number of rows in current pass */
@@ -286,9 +272,16 @@ struct png_struct_def
    png_uint_32 flush_rows;    /* number of rows written since last flush */
 #endif
 
+#ifdef PNG_READ_RGB_TO_GRAY_SUPPORTED
+   png_xy          chromaticities; /* From mDVC, cICP, [iCCP], sRGB or cHRM */
+#endif
+
 #ifdef PNG_READ_GAMMA_SUPPORTED
    int gamma_shift;      /* number of "insignificant" bits in 16-bit gamma */
-   png_fixed_point screen_gamma; /* screen gamma value (display_exponent) */
+   png_fixed_point screen_gamma; /* screen gamma value (display exponent) */
+   png_fixed_point file_gamma;   /* file gamma value (encoding exponent) */
+   png_fixed_point chunk_gamma;  /* from cICP, iCCP, sRGB or gAMA */
+   png_fixed_point default_gamma;/* from png_set_alpha_mode */
 
    png_bytep gamma_table;     /* gamma table for 8-bit depth files */
    png_uint_16pp gamma_16_table; /* gamma table for 16-bit depth files */
@@ -300,7 +293,7 @@ struct png_struct_def
    png_uint_16pp gamma_16_from_1; /* converts from 1.0 to screen */
    png_uint_16pp gamma_16_to_1; /* converts from file to 1.0 */
 #endif /* READ_BACKGROUND || READ_ALPHA_MODE || RGB_TO_GRAY */
-#endif
+#endif /* READ_GAMMA */
 
 #if defined(PNG_READ_GAMMA_SUPPORTED) || defined(PNG_sBIT_SUPPORTED)
    png_color_8 sig_bit;       /* significant bits in each available channel */
@@ -350,8 +343,8 @@ struct png_struct_def
 /* To do: remove this from libpng-1.7 */
 #ifdef PNG_TIME_RFC1123_SUPPORTED
    char time_buffer[29]; /* String to hold RFC 1123 time text */
-#endif
-#endif
+#endif /* TIME_RFC1123 */
+#endif /* LIBPNG_VER < 10700 */
 
 /* New members added in libpng-1.0.6 */
 
@@ -361,8 +354,8 @@ struct png_struct_def
    png_voidp user_chunk_ptr;
 #ifdef PNG_READ_USER_CHUNKS_SUPPORTED
    png_user_chunk_ptr read_user_chunk_fn; /* user read chunk handler */
-#endif
-#endif
+#endif /* READ_USER_CHUNKS */
+#endif /* USER_CHUNKS */
 
 #ifdef PNG_SET_UNKNOWN_CHUNKS_SUPPORTED
    int          unknown_default; /* As PNG_HANDLE_* */
@@ -469,11 +462,5 @@ struct png_struct_def
 /* New member added in libpng-1.5.7 */
    void (*read_filter[PNG_FILTER_VALUE_LAST-1])(png_row_infop row_info,
       png_bytep row, png_const_bytep prev_row);
-
-#ifdef PNG_READ_SUPPORTED
-#if defined(PNG_COLORSPACE_SUPPORTED) || defined(PNG_GAMMA_SUPPORTED)
-   png_colorspace   colorspace;
-#endif
-#endif
 };
 #endif /* PNGSTRUCT_H */
diff --git a/pngtest.c b/pngtest.c
index 5969f5031..1975b4b68 100644
--- a/pngtest.c
+++ b/pngtest.c
@@ -1,7 +1,6 @@
-
 /* pngtest.c - a test program for libpng
  *
- * Copyright (c) 2018-2024 Cosmin Truta
+ * Copyright (c) 2018-2025 Cosmin Truta
  * Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson
  * Copyright (c) 1996-1997 Andreas Dilger
  * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
@@ -51,7 +50,7 @@
 #define STDERR stdout
 
 /* Generate a compiler error if there is an old png.h in the search path. */
-typedef png_libpng_version_1_6_44 Your_png_h_is_not_version_1_6_44;
+typedef png_libpng_version_1_6_47 Your_png_h_is_not_version_1_6_47;
 
 /* Ensure that all version numbers in png.h are consistent with one another. */
 #if (PNG_LIBPNG_VER != PNG_LIBPNG_VER_MAJOR * 10000 + \
@@ -1143,6 +1142,30 @@ test_one_file(const char *inname, const char *outname)
          png_set_gAMA_fixed(write_ptr, write_info_ptr, gamma);
    }
 #endif
+#ifdef PNG_cLLI_SUPPORTED
+   {
+      png_uint_32 maxCLL;
+      png_uint_32 maxFALL;
+
+      if (png_get_cLLI_fixed(read_ptr, read_info_ptr, &maxCLL, &maxFALL) != 0)
+         png_set_cLLI_fixed(write_ptr, write_info_ptr, maxCLL, maxFALL);
+   }
+#endif
+#ifdef PNG_mDCV_SUPPORTED
+   {
+      png_fixed_point white_x, white_y, red_x, red_y, green_x, green_y, blue_x,
+          blue_y;
+      png_uint_32 maxDL;
+      png_uint_32 minDL;
+
+      if (png_get_mDCV_fixed(read_ptr, read_info_ptr, &white_x, &white_y,
+               &red_x, &red_y, &green_x, &green_y, &blue_x, &blue_y,
+               &maxDL, &minDL) != 0)
+         png_set_mDCV_fixed(write_ptr, write_info_ptr, white_x, white_y,
+               red_x, red_y, green_x, green_y, blue_x, blue_y,
+               maxDL, minDL);
+   }
+#endif
 #else /* Use floating point versions */
 #ifdef PNG_FLOATING_POINT_SUPPORTED
 #ifdef PNG_cHRM_SUPPORTED
@@ -1166,8 +1189,46 @@ test_one_file(const char *inname, const char *outname)
          png_set_gAMA(write_ptr, write_info_ptr, gamma);
    }
 #endif
+#ifdef PNG_cLLI_SUPPORTED
+   {
+      double maxCLL;
+      double maxFALL;
+
+      if (png_get_cLLI(read_ptr, read_info_ptr, &maxCLL, &maxFALL) != 0)
+         png_set_cLLI(write_ptr, write_info_ptr, maxCLL, maxFALL);
+   }
+#endif
+#ifdef PNG_mDCV_SUPPORTED
+   {
+      double white_x, white_y, red_x, red_y, green_x, green_y, blue_x, blue_y;
+      double maxDL;
+      double minDL;
+
+      if (png_get_mDCV(read_ptr, read_info_ptr, &white_x, &white_y,
+               &red_x, &red_y, &green_x, &green_y, &blue_x, &blue_y,
+               &maxDL, &minDL) != 0)
+         png_set_mDCV(write_ptr, write_info_ptr, white_x, white_y,
+               red_x, red_y, green_x, green_y, blue_x, blue_y,
+               maxDL, minDL);
+   }
+#endif
 #endif /* Floating point */
 #endif /* Fixed point */
+#ifdef PNG_cICP_SUPPORTED
+   {
+      png_byte colour_primaries;
+      png_byte transfer_function;
+      png_byte matrix_coefficients;
+      png_byte video_full_range_flag;
+
+      if (png_get_cICP(read_ptr, read_info_ptr,
+                       &colour_primaries, &transfer_function,
+                       &matrix_coefficients, &video_full_range_flag) != 0)
+         png_set_cICP(write_ptr, write_info_ptr,
+                      colour_primaries, transfer_function,
+                      matrix_coefficients, video_full_range_flag);
+   }
+#endif
 #ifdef PNG_iCCP_SUPPORTED
    {
       png_charp name;
@@ -2076,6 +2137,7 @@ main(int argc, char *argv[])
       fprintf(STDERR, " libpng FAILS test\n");
 
    dummy_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
+#ifdef PNG_USER_LIMITS_SUPPORTED
    fprintf(STDERR, " Default limits:\n");
    fprintf(STDERR, "  width_max  = %lu\n",
        (unsigned long) png_get_user_width_max(dummy_ptr));
@@ -2091,6 +2153,7 @@ main(int argc, char *argv[])
    else
       fprintf(STDERR, "  malloc_max = %lu\n",
           (unsigned long) png_get_chunk_malloc_max(dummy_ptr));
+#endif
    png_destroy_read_struct(&dummy_ptr, NULL, NULL);
 
    return (ierror != 0);
diff --git a/pngtest.png b/pngtest.png
index 66df0c4e6..7dc251c1f 100644
Binary files a/pngtest.png and b/pngtest.png differ
diff --git a/pngtrans.c b/pngtrans.c
index 62cb21edf..222b4987f 100644
--- a/pngtrans.c
+++ b/pngtrans.c
@@ -1,4 +1,3 @@
-
 /* pngtrans.c - transforms the data in a row (used by both readers and writers)
  *
  * Copyright (c) 2018-2024 Cosmin Truta
diff --git a/pngwio.c b/pngwio.c
index 10e919dd0..38c9c006c 100644
--- a/pngwio.c
+++ b/pngwio.c
@@ -1,4 +1,3 @@
-
 /* pngwio.c - functions for data output
  *
  * Copyright (c) 2018 Cosmin Truta
diff --git a/pngwrite.c b/pngwrite.c
index 77e412f43..b7aeff4ce 100644
--- a/pngwrite.c
+++ b/pngwrite.c
@@ -1,7 +1,6 @@
-
 /* pngwrite.c - general routines to write a PNG file
  *
- * Copyright (c) 2018-2024 Cosmin Truta
+ * Copyright (c) 2018-2025 Cosmin Truta
  * Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson
  * Copyright (c) 1996-1997 Andreas Dilger
  * Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc.
@@ -128,61 +127,93 @@ png_write_info_before_PLTE(png_structrp png_ptr, png_const_inforp info_ptr)
        * the application continues writing the PNG.  So check the 'invalid'
        * flag here too.
        */
-#ifdef PNG_GAMMA_SUPPORTED
-#  ifdef PNG_WRITE_gAMA_SUPPORTED
-      if ((info_ptr->colorspace.flags & PNG_COLORSPACE_INVALID) == 0 &&
-          (info_ptr->colorspace.flags & PNG_COLORSPACE_FROM_gAMA) != 0 &&
-          (info_ptr->valid & PNG_INFO_gAMA) != 0)
-         png_write_gAMA_fixed(png_ptr, info_ptr->colorspace.gamma);
-#  endif
+#ifdef PNG_WRITE_UNKNOWN_CHUNKS_SUPPORTED
+         /* Write unknown chunks first; PNG v3 establishes a precedence order
+          * for colourspace chunks.  It is certain therefore that new
+          * colourspace chunks will have a precedence and very likely it will be
+          * higher than all known so far.  Writing the unknown chunks here is
+          * most likely to present the chunks in the most convenient order.
+          *
+          * FUTURE: maybe write chunks in the order the app calls png_set_chnk
+          * to give the app control.
+          */
+         write_unknown_chunks(png_ptr, info_ptr, PNG_HAVE_IHDR);
 #endif
 
-#ifdef PNG_COLORSPACE_SUPPORTED
-      /* Write only one of sRGB or an ICC profile.  If a profile was supplied
-       * and it matches one of the known sRGB ones issue a warning.
-       */
-#  ifdef PNG_WRITE_iCCP_SUPPORTED
-         if ((info_ptr->colorspace.flags & PNG_COLORSPACE_INVALID) == 0 &&
-             (info_ptr->valid & PNG_INFO_iCCP) != 0)
-         {
-#    ifdef PNG_WRITE_sRGB_SUPPORTED
-               if ((info_ptr->valid & PNG_INFO_sRGB) != 0)
-                  png_app_warning(png_ptr,
-                      "profile matches sRGB but writing iCCP instead");
-#     endif
+#ifdef PNG_WRITE_sBIT_SUPPORTED
+         /* PNG v3: a streaming app will need to see this before cICP because
+          * the information is helpful in handling HLG encoding (which is
+          * natively 10 bits but gets expanded to 16 in PNG.)
+          *
+          * The app shouldn't care about the order ideally, but it might have
+          * no choice.  In PNG v3, apps are allowed to reject PNGs where the
+          * APNG chunks are out of order so it behooves libpng to be nice here.
+          */
+         if ((info_ptr->valid & PNG_INFO_sBIT) != 0)
+            png_write_sBIT(png_ptr, &(info_ptr->sig_bit), info_ptr->color_type);
+#endif
 
+   /* PNG v3: the July 2004 version of the TR introduced the concept of colour
+    * space priority.  As above it therefore behooves libpng to write the colour
+    * space chunks in the priority order so that a streaming app need not buffer
+    * them.
+    *
+    * PNG v3: Chunks mDCV and cLLI provide ancillary information for the
+    * interpretation of the colourspace chunkgs but do not require support for
+    * those chunks so are outside the "COLORSPACE" check but before the write of
+    * the colourspace chunks themselves.
+    */
+#ifdef PNG_WRITE_cLLI_SUPPORTED
+   if ((info_ptr->valid & PNG_INFO_cLLI) != 0)
+   {
+      png_write_cLLI_fixed(png_ptr, info_ptr->maxCLL, info_ptr->maxFALL);
+   }
+#endif
+#ifdef PNG_WRITE_mDCV_SUPPORTED
+   if ((info_ptr->valid & PNG_INFO_mDCV) != 0)
+   {
+      png_write_mDCV_fixed(png_ptr,
+         info_ptr->mastering_red_x, info_ptr->mastering_red_y,
+         info_ptr->mastering_green_x, info_ptr->mastering_green_y,
+         info_ptr->mastering_blue_x, info_ptr->mastering_blue_y,
+         info_ptr->mastering_white_x, info_ptr->mastering_white_y,
+         info_ptr->mastering_maxDL, info_ptr->mastering_minDL);
+   }
+#endif
+
+#  ifdef PNG_WRITE_cICP_SUPPORTED /* Priority 4 */
+   if ((info_ptr->valid & PNG_INFO_cICP) != 0)
+      {
+         png_write_cICP(png_ptr,
+                        info_ptr->cicp_colour_primaries,
+                        info_ptr->cicp_transfer_function,
+                        info_ptr->cicp_matrix_coefficients,
+                        info_ptr->cicp_video_full_range_flag);
+      }
+#  endif
+
+#  ifdef PNG_WRITE_iCCP_SUPPORTED /* Priority 3 */
+         if ((info_ptr->valid & PNG_INFO_iCCP) != 0)
+         {
             png_write_iCCP(png_ptr, info_ptr->iccp_name,
-                info_ptr->iccp_profile);
+                info_ptr->iccp_profile, info_ptr->iccp_proflen);
          }
-#     ifdef PNG_WRITE_sRGB_SUPPORTED
-         else
-#     endif
 #  endif
 
-#  ifdef PNG_WRITE_sRGB_SUPPORTED
-         if ((info_ptr->colorspace.flags & PNG_COLORSPACE_INVALID) == 0 &&
-             (info_ptr->valid & PNG_INFO_sRGB) != 0)
-            png_write_sRGB(png_ptr, info_ptr->colorspace.rendering_intent);
+#  ifdef PNG_WRITE_sRGB_SUPPORTED /* Priority 2 */
+         if ((info_ptr->valid & PNG_INFO_sRGB) != 0)
+            png_write_sRGB(png_ptr, info_ptr->rendering_intent);
 #  endif /* WRITE_sRGB */
-#endif /* COLORSPACE */
 
-#ifdef PNG_WRITE_sBIT_SUPPORTED
-         if ((info_ptr->valid & PNG_INFO_sBIT) != 0)
-            png_write_sBIT(png_ptr, &(info_ptr->sig_bit), info_ptr->color_type);
-#endif
-
-#ifdef PNG_COLORSPACE_SUPPORTED
-#  ifdef PNG_WRITE_cHRM_SUPPORTED
-         if ((info_ptr->colorspace.flags & PNG_COLORSPACE_INVALID) == 0 &&
-             (info_ptr->colorspace.flags & PNG_COLORSPACE_FROM_cHRM) != 0 &&
-             (info_ptr->valid & PNG_INFO_cHRM) != 0)
-            png_write_cHRM_fixed(png_ptr, &info_ptr->colorspace.end_points_xy);
+#  ifdef PNG_WRITE_gAMA_SUPPORTED /* Priority 1 */
+      if ((info_ptr->valid & PNG_INFO_gAMA) != 0)
+         png_write_gAMA_fixed(png_ptr, info_ptr->gamma);
 #  endif
-#endif
 
-#ifdef PNG_WRITE_UNKNOWN_CHUNKS_SUPPORTED
-         write_unknown_chunks(png_ptr, info_ptr, PNG_HAVE_IHDR);
-#endif
+#  ifdef PNG_WRITE_cHRM_SUPPORTED /* Also priority 1 */
+         if ((info_ptr->valid & PNG_INFO_cHRM) != 0)
+            png_write_cHRM_fixed(png_ptr, &info_ptr->cHRM);
+#  endif
 
       png_ptr->mode |= PNG_WROTE_INFO_BEFORE_PLTE;
    }
diff --git a/pngwtran.c b/pngwtran.c
index 49a13c1e9..a20847023 100644
--- a/pngwtran.c
+++ b/pngwtran.c
@@ -1,4 +1,3 @@
-
 /* pngwtran.c - transforms the data in a row for PNG writers
  *
  * Copyright (c) 2018 Cosmin Truta
diff --git a/pngwutil.c b/pngwutil.c
index 14cc4ce36..be706afe6 100644
--- a/pngwutil.c
+++ b/pngwutil.c
@@ -1,4 +1,3 @@
-
 /* pngwutil.c - utilities to write a PNG file
  *
  * Copyright (c) 2018-2024 Cosmin Truta
@@ -9,12 +8,30 @@
  * This code is released under the libpng license.
  * For conditions of distribution and use, see the disclaimer
  * and license in png.h
+ *
+ * This file contains routines that are only called from within
+ * libpng itself during the course of writing an image.
  */
 
 #include "pngpriv.h"
 
 #ifdef PNG_WRITE_SUPPORTED
 
+#ifdef PNG_WRITE_INTERLACING_SUPPORTED
+/* Arrays to facilitate interlacing - use pass (0 - 6) as index. */
+
+/* Start of interlace block */
+static const png_byte png_pass_start[7] = {0, 4, 0, 2, 0, 1, 0};
+/* Offset to next interlace block */
+static const png_byte png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
+/* Start of interlace block in the y direction */
+static const png_byte png_pass_ystart[7] = {0, 0, 4, 0, 2, 0, 1};
+/* Offset to next interlace block in the y direction */
+static const png_byte png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
+
+/* TODO: Move these arrays to a common utility module to avoid duplication. */
+#endif
+
 #ifdef PNG_WRITE_INT_FUNCTIONS_SUPPORTED
 /* Place a 32-bit number into a buffer in PNG byte order.  We work
  * with unsigned numbers for convenience, although one supported
@@ -1115,10 +1132,9 @@ png_write_sRGB(png_structrp png_ptr, int srgb_intent)
 /* Write an iCCP chunk */
 void /* PRIVATE */
 png_write_iCCP(png_structrp png_ptr, png_const_charp name,
-    png_const_bytep profile)
+    png_const_bytep profile, png_uint_32 profile_len)
 {
    png_uint_32 name_len;
-   png_uint_32 profile_len;
    png_byte new_name[81]; /* 1 byte for the compression byte */
    compression_state comp;
    png_uint_32 temp;
@@ -1131,11 +1147,12 @@ png_write_iCCP(png_structrp png_ptr, png_const_charp name,
    if (profile == NULL)
       png_error(png_ptr, "No profile for iCCP chunk"); /* internal error */
 
-   profile_len = png_get_uint_32(profile);
-
    if (profile_len < 132)
       png_error(png_ptr, "ICC profile too short");
 
+   if (png_get_uint_32(profile) != profile_len)
+      png_error(png_ptr, "Incorrect data in iCCP");
+
    temp = (png_uint_32) (*(profile+8));
    if (temp > 3 && (profile_len & 0x03))
       png_error(png_ptr, "ICC profile length invalid (not a multiple of 4)");
@@ -1471,6 +1488,73 @@ png_write_bKGD(png_structrp png_ptr, png_const_color_16p back, int color_type)
 }
 #endif
 
+#ifdef PNG_WRITE_cICP_SUPPORTED
+/* Write the cICP data */
+void /* PRIVATE */
+png_write_cICP(png_structrp png_ptr,
+               png_byte colour_primaries, png_byte transfer_function,
+               png_byte matrix_coefficients, png_byte video_full_range_flag)
+{
+   png_byte buf[4];
+
+   png_debug(1, "in png_write_cICP");
+
+   png_write_chunk_header(png_ptr, png_cICP, 4);
+
+   buf[0] = colour_primaries;
+   buf[1] = transfer_function;
+   buf[2] = matrix_coefficients;
+   buf[3] = video_full_range_flag;
+   png_write_chunk_data(png_ptr, buf, 4);
+
+   png_write_chunk_end(png_ptr);
+}
+#endif
+
+#ifdef PNG_WRITE_cLLI_SUPPORTED
+void /* PRIVATE */
+png_write_cLLI_fixed(png_structrp png_ptr, png_uint_32 maxCLL,
+   png_uint_32 maxFALL)
+{
+   png_byte buf[8];
+
+   png_debug(1, "in png_write_cLLI_fixed");
+
+   png_save_uint_32(buf, maxCLL);
+   png_save_uint_32(buf + 4, maxFALL);
+
+   png_write_complete_chunk(png_ptr, png_cLLI, buf, 8);
+}
+#endif
+
+#ifdef PNG_WRITE_mDCV_SUPPORTED
+void /* PRIVATE */
+png_write_mDCV_fixed(png_structrp png_ptr,
+   png_uint_16 red_x, png_uint_16 red_y,
+   png_uint_16 green_x, png_uint_16 green_y,
+   png_uint_16 blue_x, png_uint_16 blue_y,
+   png_uint_16 white_x, png_uint_16 white_y,
+   png_uint_32 maxDL, png_uint_32 minDL)
+{
+   png_byte buf[24];
+
+   png_debug(1, "in png_write_mDCV_fixed");
+
+   png_save_uint_16(buf +  0, red_x);
+   png_save_uint_16(buf +  2, red_y);
+   png_save_uint_16(buf +  4, green_x);
+   png_save_uint_16(buf +  6, green_y);
+   png_save_uint_16(buf +  8, blue_x);
+   png_save_uint_16(buf + 10, blue_y);
+   png_save_uint_16(buf + 12, white_x);
+   png_save_uint_16(buf + 14, white_y);
+   png_save_uint_32(buf + 16, maxDL);
+   png_save_uint_32(buf + 20, minDL);
+
+   png_write_complete_chunk(png_ptr, png_mDCV, buf, 24);
+}
+#endif
+
 #ifdef PNG_WRITE_eXIf_SUPPORTED
 /* Write the Exif data */
 void /* PRIVATE */
@@ -1889,22 +1973,6 @@ png_write_tIME(png_structrp png_ptr, png_const_timep mod_time)
 void /* PRIVATE */
 png_write_start_row(png_structrp png_ptr)
 {
-#ifdef PNG_WRITE_INTERLACING_SUPPORTED
-   /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
-
-   /* Start of interlace block */
-   static const png_byte png_pass_start[7] = {0, 4, 0, 2, 0, 1, 0};
-
-   /* Offset to next interlace block */
-   static const png_byte png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
-
-   /* Start of interlace block in the y direction */
-   static const png_byte png_pass_ystart[7] = {0, 0, 4, 0, 2, 0, 1};
-
-   /* Offset to next interlace block in the y direction */
-   static const png_byte png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
-#endif
-
    png_alloc_size_t buf_size;
    int usr_pixel_depth;
 
@@ -2004,22 +2072,6 @@ png_write_start_row(png_structrp png_ptr)
 void /* PRIVATE */
 png_write_finish_row(png_structrp png_ptr)
 {
-#ifdef PNG_WRITE_INTERLACING_SUPPORTED
-   /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
-
-   /* Start of interlace block */
-   static const png_byte png_pass_start[7] = {0, 4, 0, 2, 0, 1, 0};
-
-   /* Offset to next interlace block */
-   static const png_byte png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
-
-   /* Start of interlace block in the y direction */
-   static const png_byte png_pass_ystart[7] = {0, 0, 4, 0, 2, 0, 1};
-
-   /* Offset to next interlace block in the y direction */
-   static const png_byte png_pass_yinc[7] = {8, 8, 8, 4, 4, 2, 2};
-#endif
-
    png_debug(1, "in png_write_finish_row");
 
    /* Next row */
@@ -2095,14 +2147,6 @@ png_write_finish_row(png_structrp png_ptr)
 void /* PRIVATE */
 png_do_write_interlace(png_row_infop row_info, png_bytep row, int pass)
 {
-   /* Arrays to facilitate easy interlacing - use pass (0 - 6) as index */
-
-   /* Start of interlace block */
-   static const png_byte png_pass_start[7] = {0, 4, 0, 2, 0, 1, 0};
-
-   /* Offset to next interlace block */
-   static const png_byte png_pass_inc[7] = {8, 8, 4, 4, 2, 2, 1};
-
    png_debug(1, "in png_do_write_interlace");
 
    /* We don't have to do anything on the last pass (6) */
diff --git a/powerpc/powerpc_init.c b/powerpc/powerpc_init.c
index 54426c558..902748009 100644
--- a/powerpc/powerpc_init.c
+++ b/powerpc/powerpc_init.c
@@ -1,4 +1,3 @@
-
 /* powerpc_init.c - POWERPC optimised filter functions
  *
  * Copyright (c) 2018 Cosmin Truta
diff --git a/projects/vstudio/build.bat b/projects/vstudio/build.bat
new file mode 100644
index 000000000..d129d4b6e
--- /dev/null
+++ b/projects/vstudio/build.bat
@@ -0,0 +1,25 @@
+@echo off
+@setlocal enableextensions
+
+if "%~1" == "/?" goto :help
+if "%~1" == "-?" goto :help
+if "%~1" == "/help" goto :help
+if "%~1" == "-help" goto :help
+if "%~1" == "--help" goto :help
+goto :run
+
+:help
+echo Usage:
+echo   %~nx0 [SOLUTION_CONFIG]
+echo Examples:
+echo   %~nx0 "Release|Win32" (default)
+echo   %~nx0 "Debug|Win32"
+echo   %~nx0 "Release|ARM64"
+echo   %~nx0 "Debug|ARM64"
+echo   etc.
+exit /b 2
+
+:run
+set _SOLUTION_CONFIG="%~1"
+if %_SOLUTION_CONFIG% == "" set _SOLUTION_CONFIG="Release|Win32"
+devenv "%~dp0.\vstudio.sln" /build %_SOLUTION_CONFIG%
diff --git a/projects/vstudio/libpng/libpng.vcxproj b/projects/vstudio/libpng/libpng.vcxproj
index e10f4ff8b..1044fe1d6 100644
--- a/projects/vstudio/libpng/libpng.vcxproj
+++ b/projects/vstudio/libpng/libpng.vcxproj
@@ -158,11 +158,11 @@
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
     <ClCompile>
       <PrecompiledHeader>Use</PrecompiledHeader>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <MinimalRebuild>false</MinimalRebuild>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <IntrinsicFunctions>true</IntrinsicFunctions>
       <FunctionLevelLinking>true</FunctionLevelLinking>
       <FloatingPointExceptions>false</FloatingPointExceptions>
@@ -173,7 +173,7 @@
       <StringPooling>true</StringPooling>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <Optimization>Disabled</Optimization>
       <RuntimeLibrary>MultiThreadedDebugDLL</RuntimeLibrary>
     </ClCompile>
@@ -188,11 +188,11 @@
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|ARM64'">
     <ClCompile>
       <PrecompiledHeader>Use</PrecompiledHeader>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <MinimalRebuild>false</MinimalRebuild>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <IntrinsicFunctions>true</IntrinsicFunctions>
       <FunctionLevelLinking>true</FunctionLevelLinking>
       <FloatingPointExceptions>false</FloatingPointExceptions>
@@ -203,7 +203,7 @@
       <StringPooling>true</StringPooling>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <Optimization>Disabled</Optimization>
       <RuntimeLibrary>MultiThreadedDebugDLL</RuntimeLibrary>
     </ClCompile>
@@ -223,7 +223,7 @@
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <IntrinsicFunctions>true</IntrinsicFunctions>
       <FunctionLevelLinking>true</FunctionLevelLinking>
       <FloatingPointExceptions>false</FloatingPointExceptions>
@@ -250,7 +250,7 @@
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <IntrinsicFunctions>true</IntrinsicFunctions>
       <FunctionLevelLinking>true</FunctionLevelLinking>
       <FloatingPointExceptions>false</FloatingPointExceptions>
@@ -271,12 +271,12 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <PrecompiledHeader>Use</PrecompiledHeader>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <FunctionLevelLinking>true</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <FloatingPointExceptions>false</FloatingPointExceptions>
       <TreatWChar_tAsBuiltInType>false</TreatWChar_tAsBuiltInType>
       <PrecompiledHeaderFile>pngpriv.h</PrecompiledHeaderFile>
@@ -286,7 +286,7 @@
       <MinimalRebuild>false</MinimalRebuild>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <Optimization>Full</Optimization>
     </ClCompile>
     <Link>
@@ -301,12 +301,12 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|ARM64'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <PrecompiledHeader>Use</PrecompiledHeader>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <FunctionLevelLinking>true</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <FloatingPointExceptions>false</FloatingPointExceptions>
       <TreatWChar_tAsBuiltInType>false</TreatWChar_tAsBuiltInType>
       <PrecompiledHeaderFile>pngpriv.h</PrecompiledHeaderFile>
@@ -316,7 +316,7 @@
       <MinimalRebuild>false</MinimalRebuild>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <Optimization>Full</Optimization>
     </ClCompile>
     <Link>
@@ -337,7 +337,7 @@
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <FunctionLevelLinking>true</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <FloatingPointExceptions>false</FloatingPointExceptions>
       <TreatWChar_tAsBuiltInType>false</TreatWChar_tAsBuiltInType>
       <PrecompiledHeaderFile>pngpriv.h</PrecompiledHeaderFile>
@@ -369,7 +369,7 @@
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <FunctionLevelLinking>true</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <FloatingPointExceptions>false</FloatingPointExceptions>
       <TreatWChar_tAsBuiltInType>false</TreatWChar_tAsBuiltInType>
       <PrecompiledHeaderFile>pngpriv.h</PrecompiledHeaderFile>
@@ -396,7 +396,7 @@
   <ItemGroup>
     <ClCompile Include="..\..\..\arm\arm_init.c">
       <DeploymentContent>true</DeploymentContent>
-      <PreprocessorDefinitions Condition="'$(Configuration)|$(Platform)'=='Debug Library|ARM64'">WIN32;_DEBUG;PNG_ARM_NEON_OPT=1;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions Condition="'$(Configuration)|$(Platform)'=='Debug Library|ARM64'">WIN32;_DEBUG;_CRT_SECURE_NO_WARNINGS;PNG_ARM_NEON_OPT=1;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Debug Library|ARM64'">NotUsing</PrecompiledHeader>
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Release Library|Win32'">NotUsing</PrecompiledHeader>
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Debug Library|Win32'">NotUsing</PrecompiledHeader>
@@ -405,7 +405,7 @@
     </ClCompile>
     <ClCompile Include="..\..\..\arm\filter_neon_intrinsics.c">
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Debug Library|ARM64'">NotUsing</PrecompiledHeader>
-      <PreprocessorDefinitions Condition="'$(Configuration)|$(Platform)'=='Debug Library|ARM64'">WIN32;_DEBUG;PNG_ARM_NEON_OPT=1;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions Condition="'$(Configuration)|$(Platform)'=='Debug Library|ARM64'">WIN32;_DEBUG;_CRT_SECURE_NO_WARNINGS;PNG_ARM_NEON_OPT=1;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Release Library|Win32'">NotUsing</PrecompiledHeader>
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Debug Library|Win32'">NotUsing</PrecompiledHeader>
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">NotUsing</PrecompiledHeader>
@@ -413,7 +413,7 @@
     </ClCompile>
     <ClCompile Include="..\..\..\arm\palette_neon_intrinsics.c">
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Debug Library|ARM64'">NotUsing</PrecompiledHeader>
-      <PreprocessorDefinitions Condition="'$(Configuration)|$(Platform)'=='Debug Library|ARM64'">WIN32;_DEBUG;PNG_ARM_NEON_OPT=1;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions Condition="'$(Configuration)|$(Platform)'=='Debug Library|ARM64'">WIN32;_DEBUG;_CRT_SECURE_NO_WARNINGS;PNG_ARM_NEON_OPT=1;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Release Library|Win32'">NotUsing</PrecompiledHeader>
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Debug Library|Win32'">NotUsing</PrecompiledHeader>
       <PrecompiledHeader Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">NotUsing</PrecompiledHeader>
diff --git a/projects/vstudio/pnglibconf/pnglibconf.vcxproj b/projects/vstudio/pnglibconf/pnglibconf.vcxproj
index e0a3887a4..f033f5061 100644
--- a/projects/vstudio/pnglibconf/pnglibconf.vcxproj
+++ b/projects/vstudio/pnglibconf/pnglibconf.vcxproj
@@ -48,7 +48,7 @@
   </PropertyGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <Optimization>MaxSpeed</Optimization>
       <FunctionLevelLinking>true</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
@@ -73,7 +73,7 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|ARM64'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <Optimization>MaxSpeed</Optimization>
       <FunctionLevelLinking>true</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
diff --git a/projects/vstudio/pngstest/pngstest.vcxproj b/projects/vstudio/pngstest/pngstest.vcxproj
index 3937cb41d..e59459818 100644
--- a/projects/vstudio/pngstest/pngstest.vcxproj
+++ b/projects/vstudio/pngstest/pngstest.vcxproj
@@ -149,7 +149,7 @@
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -182,7 +182,7 @@
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -216,7 +216,7 @@
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
       <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -249,7 +249,7 @@
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
       <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -275,17 +275,17 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <PrecompiledHeader>NotUsing</PrecompiledHeader>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Full</Optimization>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <StringPooling>true</StringPooling>
       <MinimalRebuild>false</MinimalRebuild>
       <BrowseInformation>true</BrowseInformation>
@@ -310,17 +310,17 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|ARM64'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <PrecompiledHeader>NotUsing</PrecompiledHeader>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Full</Optimization>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <StringPooling>true</StringPooling>
       <MinimalRebuild>false</MinimalRebuild>
       <BrowseInformation>true</BrowseInformation>
@@ -352,7 +352,7 @@
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -388,7 +388,7 @@
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
diff --git a/projects/vstudio/pngtest/pngtest.vcxproj b/projects/vstudio/pngtest/pngtest.vcxproj
index 72beced2b..58f662fcd 100644
--- a/projects/vstudio/pngtest/pngtest.vcxproj
+++ b/projects/vstudio/pngtest/pngtest.vcxproj
@@ -149,7 +149,7 @@
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -182,7 +182,7 @@
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -216,7 +216,7 @@
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
       <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -249,7 +249,7 @@
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
       <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -275,17 +275,17 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <PrecompiledHeader>NotUsing</PrecompiledHeader>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Full</Optimization>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <StringPooling>true</StringPooling>
       <MinimalRebuild>false</MinimalRebuild>
       <BrowseInformation>true</BrowseInformation>
@@ -310,17 +310,17 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|ARM64'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <PrecompiledHeader>NotUsing</PrecompiledHeader>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Full</Optimization>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <StringPooling>true</StringPooling>
       <MinimalRebuild>false</MinimalRebuild>
       <BrowseInformation>true</BrowseInformation>
@@ -352,7 +352,7 @@
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -389,7 +389,7 @@
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
diff --git a/projects/vstudio/pngunknown/pngunknown.vcxproj b/projects/vstudio/pngunknown/pngunknown.vcxproj
index f4d130d0b..c1568feb6 100644
--- a/projects/vstudio/pngunknown/pngunknown.vcxproj
+++ b/projects/vstudio/pngunknown/pngunknown.vcxproj
@@ -149,7 +149,7 @@
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -182,7 +182,7 @@
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -216,7 +216,7 @@
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
       <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -249,7 +249,7 @@
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
       <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -275,17 +275,17 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <PrecompiledHeader>NotUsing</PrecompiledHeader>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Full</Optimization>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <StringPooling>true</StringPooling>
       <MinimalRebuild>false</MinimalRebuild>
       <BrowseInformation>true</BrowseInformation>
@@ -310,17 +310,17 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|ARM64'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <PrecompiledHeader>NotUsing</PrecompiledHeader>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Full</Optimization>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <StringPooling>true</StringPooling>
       <MinimalRebuild>false</MinimalRebuild>
       <BrowseInformation>true</BrowseInformation>
@@ -352,7 +352,7 @@
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -388,7 +388,7 @@
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
diff --git a/projects/vstudio/pngvalid/pngvalid.vcxproj b/projects/vstudio/pngvalid/pngvalid.vcxproj
index 3726193bf..d016df815 100644
--- a/projects/vstudio/pngvalid/pngvalid.vcxproj
+++ b/projects/vstudio/pngvalid/pngvalid.vcxproj
@@ -149,7 +149,7 @@
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -182,7 +182,7 @@
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -216,7 +216,7 @@
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
       <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -249,7 +249,7 @@
       <Optimization>Disabled</Optimization>
       <BasicRuntimeChecks>EnableFastChecks</BasicRuntimeChecks>
       <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
-      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;_DEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -275,17 +275,17 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|Win32'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <PrecompiledHeader>NotUsing</PrecompiledHeader>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Full</Optimization>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <StringPooling>true</StringPooling>
       <MinimalRebuild>false</MinimalRebuild>
       <BrowseInformation>true</BrowseInformation>
@@ -310,17 +310,17 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|ARM64'">
     <ClCompile>
-      <WarningLevel>$(WarningLevel)</WarningLevel>
+      <WarningLevel>Level3</WarningLevel>
       <PrecompiledHeader>NotUsing</PrecompiledHeader>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Full</Optimization>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;PNG_USE_DLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
-      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
+      <TreatWarningAsError>false</TreatWarningAsError>
       <StringPooling>true</StringPooling>
       <MinimalRebuild>false</MinimalRebuild>
       <BrowseInformation>true</BrowseInformation>
@@ -352,7 +352,7 @@
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
@@ -388,7 +388,7 @@
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <FunctionLevelLinking>false</FunctionLevelLinking>
       <IntrinsicFunctions>true</IntrinsicFunctions>
-      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;%(PreprocessorDefinitions)</PreprocessorDefinitions>
+      <PreprocessorDefinitions>WIN32;NDEBUG;_CONSOLE;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <AdditionalIncludeDirectories>$(ZLibSrcDir);..\..\..\scripts;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
       <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <CompileAsManaged>false</CompileAsManaged>
diff --git a/projects/vstudio/zlib.props b/projects/vstudio/zlib.props
index 878627966..b84a2c0fc 100644
--- a/projects/vstudio/zlib.props
+++ b/projects/vstudio/zlib.props
@@ -2,7 +2,7 @@
 <!--
  * zlib.props - location of zlib source
  *
- * Copyright (c) 2018 Cosmin Truta
+ * Copyright (c) 2018-2024 Cosmin Truta
  * Copyright (c) 1998-2011 Glenn Randers-Pehrson
  *
  * This code is released under the libpng license.
@@ -14,44 +14,43 @@
  -->
 
 <Project ToolsVersion="4.0"
-   xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
+         xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
   <PropertyGroup Label="Globals">
     <!-- Place the name of the directory containing the source of zlib used for
-	 debugging in this property.
+         debugging in this property.
 
          The directory need only contain the '.c' and '.h' files from the
-	 source.
+         source.
 
-	 If you use a relative directory name (as below) then it must be
-	 relative to the project directories; these are one level deeper than
-	 the directories containing this file.
+         If you use a relative directory name (as below) then it must be
+         relative to the project directories; these are one level deeper than
+         the directories containing this file.
 
-	 If the version of zlib you use does not match that used when the
-	 distribution was built you will get warnings from pngtest that the zlib
-	 versions do not match.  The zlib version used in this build is recorded
-	 below:
+         If the version of zlib you use does not match that used when the
+         distribution was built you will get warnings from pngtest that the
+         zlib versions do not match.  The zlib version used in this build is
+         recorded below:
      -->
     <ZLibSrcDir>..\..\..\..\zlib</ZLibSrcDir>
 
     <!-- The following line allows compilation for an ARM target with Visual
          Studio 2012.  Notice that this is not supported by the Visual Studio
          2012 IDE and that the programs that result cannot be run unless they
-         signed by Microsoft.  This is therefore untested; only Microsoft can
-         test it:
+         are signed by Microsoft.  This is therefore untested; only Microsoft
+         can test it:
      -->
     <WindowsSDKDesktopARMSupport>true</WindowsSDKDesktopARMSupport>
 
-    <!-- The following lines provide a global (solution level) control of the
-         warnings issued by the compiler, these are used in the individual
-         project files (*/*.vcxproj) with, for zlib, some extra disables.
+    <!-- The following lines provide a global (solution-level) control of the
+         warnings issued by the compiler.
 
-         Different versions of Visual Studio may require different settings,
-         these settings work with Visual Studio 2013.  Just set
-         TreatWarningAsError to false to check the build without failing on
-         errors.
+         Considering how different versions of Visual Studio sometimes require
+         different settings, and their compilers issue different warnings, we
+         set TreatWarningAsError to false to avoid unforeseen and undesirable
+         build failures for the users who upgrade to a newer Visual Studio that
+         might bring along a more pedantic compiler:
      -->
-   <WarningLevel>EnableAllWarnings</WarningLevel>
-   <TreatWarningAsError>true</TreatWarningAsError>
-   <DisableSpecificWarnings>4255;4668;4710;4711;4746;4820;4996</DisableSpecificWarnings>
+   <WarningLevel>Level3</WarningLevel>
+   <TreatWarningAsError>false</TreatWarningAsError>
   </PropertyGroup>
 </Project>
diff --git a/projects/vstudio/zlib/zlib.vcxproj b/projects/vstudio/zlib/zlib.vcxproj
index 23e606517..7858706ef 100644
--- a/projects/vstudio/zlib/zlib.vcxproj
+++ b/projects/vstudio/zlib/zlib.vcxproj
@@ -154,13 +154,13 @@
     <ClCompile>
       <PreprocessorDefinitions>WIN32;_DEBUG;Z_SOLO;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
-      <WarningLevel>Level3</WarningLevel>
+      <WarningLevel>$(WarningLevel)</WarningLevel>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BrowseInformation>true</BrowseInformation>
       <FunctionLevelLinking>true</FunctionLevelLinking>
-      <DisableSpecificWarnings>$(DisableSpecificWarnings);4127;4131;4242;4244</DisableSpecificWarnings>
-      <TreatWarningAsError>false</TreatWarningAsError>
+      <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
+      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
     </ClCompile>
     <Link>
       <TargetMachine>MachineX86</TargetMachine>
@@ -172,13 +172,13 @@
     <ClCompile>
       <PreprocessorDefinitions>WIN32;_DEBUG;Z_SOLO;%(PreprocessorDefinitions)</PreprocessorDefinitions>
       <RuntimeLibrary>MultiThreadedDebug</RuntimeLibrary>
-      <WarningLevel>Level3</WarningLevel>
+      <WarningLevel>$(WarningLevel)</WarningLevel>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BrowseInformation>true</BrowseInformation>
       <FunctionLevelLinking>true</FunctionLevelLinking>
-      <DisableSpecificWarnings>$(DisableSpecificWarnings);4127;4131;4242;4244</DisableSpecificWarnings>
-      <TreatWarningAsError>false</TreatWarningAsError>
+      <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
+      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
     </ClCompile>
     <Link>
       <GenerateDebugInformation>true</GenerateDebugInformation>
@@ -188,13 +188,13 @@
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|Win32'">
     <ClCompile>
       <PreprocessorDefinitions>WIN32;_DEBUG;Z_SOLO;%(PreprocessorDefinitions)</PreprocessorDefinitions>
-      <WarningLevel>Level3</WarningLevel>
+      <WarningLevel>$(WarningLevel)</WarningLevel>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BrowseInformation>true</BrowseInformation>
       <FunctionLevelLinking>true</FunctionLevelLinking>
-      <DisableSpecificWarnings>$(DisableSpecificWarnings);4127;4131;4242;4244</DisableSpecificWarnings>
-      <TreatWarningAsError>false</TreatWarningAsError>
+      <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
+      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
       <RuntimeLibrary>MultiThreadedDebugDLL</RuntimeLibrary>
     </ClCompile>
     <Link>
@@ -206,13 +206,13 @@
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Debug|ARM64'">
     <ClCompile>
       <PreprocessorDefinitions>WIN32;_DEBUG;Z_SOLO;%(PreprocessorDefinitions)</PreprocessorDefinitions>
-      <WarningLevel>Level3</WarningLevel>
+      <WarningLevel>$(WarningLevel)</WarningLevel>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Disabled</Optimization>
       <BrowseInformation>true</BrowseInformation>
       <FunctionLevelLinking>true</FunctionLevelLinking>
-      <DisableSpecificWarnings>$(DisableSpecificWarnings);4127;4131;4242;4244</DisableSpecificWarnings>
-      <TreatWarningAsError>false</TreatWarningAsError>
+      <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
+      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
       <RuntimeLibrary>MultiThreadedDebugDLL</RuntimeLibrary>
     </ClCompile>
     <Link>
@@ -222,7 +222,7 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release Library|Win32'">
     <ClCompile>
-      <WarningLevel>Level3</WarningLevel>
+      <WarningLevel>$(WarningLevel)</WarningLevel>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Full</Optimization>
       <IntrinsicFunctions>true</IntrinsicFunctions>
@@ -230,8 +230,8 @@
       <BufferSecurityCheck>false</BufferSecurityCheck>
       <BrowseInformation>true</BrowseInformation>
       <FunctionLevelLinking>true</FunctionLevelLinking>
-      <DisableSpecificWarnings>$(DisableSpecificWarnings);4127;4131;4242;4244</DisableSpecificWarnings>
-      <TreatWarningAsError>false</TreatWarningAsError>
+      <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
+      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <PreprocessorDefinitions>WIN32;NDEBUG;Z_SOLO;%(PreprocessorDefinitions)</PreprocessorDefinitions>
     </ClCompile>
@@ -246,7 +246,7 @@
   </ItemDefinitionGroup>
   <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release Library|ARM64'">
     <ClCompile>
-      <WarningLevel>Level3</WarningLevel>
+      <WarningLevel>$(WarningLevel)</WarningLevel>
       <DebugInformationFormat>ProgramDatabase</DebugInformationFormat>
       <Optimization>Full</Optimization>
       <IntrinsicFunctions>true</IntrinsicFunctions>
@@ -254,8 +254,8 @@
       <BufferSecurityCheck>false</BufferSecurityCheck>
       <BrowseInformation>true</BrowseInformation>
       <FunctionLevelLinking>true</FunctionLevelLinking>
-      <DisableSpecificWarnings>$(DisableSpecificWarnings);4127;4131;4242;4244</DisableSpecificWarnings>
-      <TreatWarningAsError>false</TreatWarningAsError>
+      <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
+      <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
       <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
       <PreprocessorDefinitions>WIN32;NDEBUG;Z_SOLO;%(PreprocessorDefinitions)</PreprocessorDefinitions>
     </ClCompile>
@@ -277,7 +277,7 @@
       <BufferSecurityCheck>false</BufferSecurityCheck>
       <BrowseInformation>true</BrowseInformation>
       <FunctionLevelLinking>true</FunctionLevelLinking>
-      <DisableSpecificWarnings>$(DisableSpecificWarnings);4127;4131;4242;4244</DisableSpecificWarnings>
+      <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
       <PreprocessorDefinitions>WIN32;NDEBUG;Z_SOLO;%(PreprocessorDefinitions)</PreprocessorDefinitions>
     </ClCompile>
@@ -302,7 +302,7 @@
       <BufferSecurityCheck>false</BufferSecurityCheck>
       <BrowseInformation>true</BrowseInformation>
       <FunctionLevelLinking>true</FunctionLevelLinking>
-      <DisableSpecificWarnings>$(DisableSpecificWarnings);4127;4131;4242;4244</DisableSpecificWarnings>
+      <DisableSpecificWarnings>$(DisableSpecificWarnings)</DisableSpecificWarnings>
       <TreatWarningAsError>$(TreatWarningAsError)</TreatWarningAsError>
       <PreprocessorDefinitions>WIN32;NDEBUG;Z_SOLO;%(PreprocessorDefinitions)</PreprocessorDefinitions>
     </ClCompile>
diff --git a/scripts/README.txt b/scripts/README.txt
index 326160cbb..332a016cb 100644
--- a/scripts/README.txt
+++ b/scripts/README.txt
@@ -1,79 +1,74 @@
+Scripts and makefiles for libpng
+--------------------------------
 
-Makefiles for libpng
+    pnglibconf.h.prebuilt  =>  Configuration settings
 
-pnglibconf.h.prebuilt  =>  Configuration settings
- makefile.linux    =>  Linux/ELF makefile
-                       (gcc, creates shared libpng16.so.16.1.6.*)
- makefile.linux-opt=>  Linux/ELF makefile with hardware optimizations on
-                       (gcc, creates shared libpng16.so.16.1.6.*)
- makefile.gcc      =>  Generic makefile (gcc, creates static libpng.a)
- makefile.acorn    =>  Acorn makefile
- makefile.aix      =>  AIX/gcc makefile
- makefile.amiga    =>  Amiga makefile
- makefile.atari    =>  Atari makefile
- makefile.bc32     =>  32-bit Borland C++ (all modules compiled in C mode)
- makefile.beos     =>  BeOS makefile
- makefile.clang    =>  Generic clang makefile
- makefile.darwin   =>  Darwin makefile, for macOS (formerly Mac OS X)
- makefile.dec      =>  DEC Alpha UNIX makefile
- makefile.dj2      =>  DJGPP 2 makefile
- makefile.freebsd  =>  FreeBSD makefile
- makefile.gcc      =>  Generic gcc makefile
- makefile.hpgcc    =>  HPUX makefile using gcc
- makefile.hpux     =>  HPUX (10.20 and 11.00) makefile
- makefile.hp64     =>  HPUX (10.20 and 11.00) makefile, 64-bit
- makefile.ibmc     =>  IBM C/C++ version 3.x for Win32 and OS/2 (static)
- makefile.intel    =>  Intel C/C++ version 4.0 and later
- makefile.mips     =>  MIPS makefile
- makefile.netbsd   =>  NetBSD/cc makefile, makes shared libpng.so
- makefile.openbsd  =>  OpenBSD makefile
- makefile.sco      =>  SCO OSr5 ELF and Unixware 7 with Native cc
- makefile.sggcc    =>  Silicon Graphics makefile
-                       (gcc, creates shared libpng16.so.16.1.6.*)
- makefile.sgi      =>  Silicon Graphics IRIX makefile (cc, creates static lib)
- makefile.solaris  =>  Solaris 2.X makefile
-                       (gcc, creates shared libpng16.so.16.1.6.*)
- makefile.so9      =>  Solaris 9 makefile
-                       (gcc, creates shared libpng16.so.16.1.6.*)
- makefile.std      =>  Generic UNIX makefile (cc, creates static libpng.a)
- makefile.sunos    =>  Sun makefile
- makefile.32sunu   =>  Sun Ultra 32-bit makefile
- makefile.64sunu   =>  Sun Ultra 64-bit makefile
- makefile.vcwin32  =>  makefile for Microsoft Visual C++ 4.0 and later
- makevms.com       =>  VMS build script
- smakefile.ppc     =>  AMIGA smakefile for SAS C V6.58/7.00 PPC compiler
-                       (Requires SCOPTIONS, copied from scripts/SCOPTIONS.ppc)
+    makefile.aix      =>  AIX/gcc makefile
+    makefile.amiga    =>  Amiga makefile
+    makefile.atari    =>  Atari makefile
+    makefile.bc32     =>  Borland C makefile, for Win32
+    makefile.beos     =>  BeOS makefile
+    makefile.c89      =>  Generic UNIX makefile for C89 (cc -std=c89)
+    makefile.clang    =>  Generic clang makefile
+    makefile.darwin   =>  Darwin makefile, for macOS (formerly Mac OS X)
+    makefile.dec      =>  DEC Alpha UNIX makefile
+    makefile.dj2      =>  DJGPP 2 makefile
+    makefile.emcc     =>  Emscripten makefile
+    makefile.freebsd  =>  FreeBSD makefile
+    makefile.gcc      =>  Generic gcc makefile
+    makefile.hpgcc    =>  HPUX makefile using gcc
+    makefile.hpux     =>  HPUX (10.20 and 11.00) makefile
+    makefile.hp64     =>  HPUX (10.20 and 11.00) makefile, 64-bit
+    makefile.ibmc     =>  IBM C/C++ version 3.x for Win32 and OS/2 (static lib)
+    makefile.intel    =>  Intel C/C++ version 4.0 and later
+    makefile.linux    =>  Linux/ELF makefile
+                          (gcc, creates shared libpng16.so.16.1.6.*)
+    makefile.mips     =>  MIPS makefile
+    makefile.msys     =>  MSYS (MinGW) makefile
+    makefile.netbsd   =>  NetBSD/cc makefile, makes shared libpng.so
+    makefile.openbsd  =>  OpenBSD makefile
+    makefile.riscos   =>  Acorn RISCOS makefile
+    makefile.sco      =>  SCO OSr5 ELF and Unixware 7 with Native cc
+    makefile.sgi      =>  Silicon Graphics IRIX makefile (cc, static lib)
+    makefile.sggcc    =>  Silicon Graphics makefile
+                          (gcc, creates shared libpng16.so.16.1.6.*)
+    makefile.solaris  =>  Solaris 2.X makefile
+                          (gcc, creates shared libpng16.so.16.1.6.*)
+    makefile.so9      =>  Solaris 9 makefile
+                          (gcc, creates shared libpng16.so.16.1.6.*)
+    makefile.std      =>  Generic UNIX makefile (cc, static lib)
+    makefile.sunos    =>  Sun makefile
+    makefile.32sunu   =>  Sun Ultra 32-bit makefile
+    makefile.64sunu   =>  Sun Ultra 64-bit makefile
+    makefile.vcwin32  =>  makefile for Microsoft Visual C++ 4.0 and later
+    makevms.com       =>  VMS build script
+    smakefile.ppc     =>  AMIGA smakefile for SAS C V6.58/7.00 PPC compiler
+                          (Requires SCOPTIONS, copied from SCOPTIONS.ppc)
 
-Other supporting scripts:
- README.txt        =>  This file
- descrip.mms       =>  VMS makefile for MMS or MMK
- libpng-config-body.in => used by several makefiles to create libpng-config
- libpng-config-head.in => used by several makefiles to create libpng-config
- libpng.pc.in      =>  Used by several makefiles to create libpng.pc
- pngwin.rc         =>  Used by the visualc71 project
- pngwin.def        =>  Used by makefile.os2
- pngwin.dfn        =>  Used to maintain pngwin.def
- SCOPTIONS.ppc     =>  Used with smakefile.ppc
+Other supporting scripts
+------------------------
 
- checksym.awk      =>  Used for maintaining pnglibconf.h
- def.dfn           =>  Used for maintaining pnglibconf.h
- options.awk       =>  Used for maintaining pnglibconf.h
- pnglibconf.dfa    =>  Used for maintaining pnglibconf.h
- pnglibconf.mak    =>  Used for maintaining pnglibconf.h
- sym.dfn           =>  Used for symbol versioning
- symbols.def       =>  Used for symbol versioning
- symbols.dfn       =>  Used for symbol versioning
- vers.dfn          =>  Used for symbol versioning
+    README.txt        =>  This file
+    descrip.mms       =>  VMS makefile for MMS or MMK
+    libpng-config-body.in  =>  used by several makefiles to create libpng-config
+    libpng-config-head.in  =>  used by several makefiles to create libpng-config
+    libpng.pc.in      =>  Used by several makefiles to create libpng.pc
+    macro.lst         =>  Used by GNU Autotools
+    pngwin.rc         =>  Used by the visualc71 project
+    pngwin.def        =>  Used by makefile.os2
+    pngwin.dfn        =>  Used to maintain pngwin.def
+    SCOPTIONS.ppc     =>  Used with smakefile.ppc
 
- libtool.m4        =>  Used by autoconf tools
- ltoptions.m4      =>  Used by autoconf tools
- ltsugar.m4        =>  Used by autoconf tools
- ltversion.m4      =>  Used by autoconf tools
- lt~obsolete.m4    =>  Used by autoconf tools
-
- intprefix.dfn     =>  Used by autoconf tools
- macro.lst         =>  Used by autoconf tools
- prefix.dfn        =>  Used by autoconf tools
+    checksym.awk      =>  Used for maintaining pnglibconf.h
+    dfn.awk           =>  Used for maintaining pnglibconf.h
+    options.awk       =>  Used for maintaining pnglibconf.h
+    pnglibconf.dfa    =>  Used for maintaining pnglibconf.h
+    pnglibconf.mak    =>  Used for maintaining pnglibconf.h
+    intprefix.c       =>  Used for symbol versioning
+    prefix.c          =>  Used for symbol versioning
+    sym.c             =>  Used for symbol versioning
+    symbols.c         =>  Used for symbol versioning
+    vers.c            =>  Used for symbol versioning
 
 Further information can be found in comments in the individual scripts and
 makefiles.
diff --git a/scripts/autoconf/libtool.m4 b/scripts/autoconf/libtool.m4
index 79a2451ef..8d323b3ee 100644
--- a/scripts/autoconf/libtool.m4
+++ b/scripts/autoconf/libtool.m4
@@ -1,6 +1,6 @@
 # libtool.m4 - Configure libtool for the host system. -*-Autoconf-*-
 #
-#   Copyright (C) 1996-2001, 2003-2019, 2021-2022 Free Software
+#   Copyright (C) 1996-2001, 2003-2019, 2021-2024 Free Software
 #   Foundation, Inc.
 #   Written by Gordon Matzigkeit, 1996
 #
@@ -9,13 +9,13 @@
 # modifications, as long as this notice is preserved.
 
 m4_define([_LT_COPYING], [dnl
-# Copyright (C) 2014 Free Software Foundation, Inc.
+# Copyright (C) 2024 Free Software Foundation, Inc.
 # This is free software; see the source for copying conditions.  There is NO
 # warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 
 # GNU Libtool is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
-# the Free Software Foundation; either version 2 of of the License, or
+# the Free Software Foundation; either version 2 of the License, or
 # (at your option) any later version.
 #
 # As a special exception to the GNU General Public License, if you
@@ -32,7 +32,7 @@ m4_define([_LT_COPYING], [dnl
 # along with this program.  If not, see <http://www.gnu.org/licenses/>.
 ])
 
-# serial 59 LT_INIT
+# serial 63 LT_INIT
 
 
 # LT_PREREQ(VERSION)
@@ -60,7 +60,7 @@ esac
 # LT_INIT([OPTIONS])
 # ------------------
 AC_DEFUN([LT_INIT],
-[AC_PREREQ([2.62])dnl We use AC_PATH_PROGS_FEATURE_CHECK
+[AC_PREREQ([2.64])dnl We use AC_PATH_PROGS_FEATURE_CHECK
 AC_REQUIRE([AC_CONFIG_AUX_DIR_DEFAULT])dnl
 AC_BEFORE([$0], [LT_LANG])dnl
 AC_BEFORE([$0], [LT_OUTPUT])dnl
@@ -616,7 +616,7 @@ m4_popdef([AS_MESSAGE_LOG_FD])])])# _LT_GENERATED_FILE_INIT
 # LT_OUTPUT
 # ---------
 # This macro allows early generation of the libtool script (before
-# AC_OUTPUT is called), incase it is used in configure for compilation
+# AC_OUTPUT is called), in case it is used in configure for compilation
 # tests.
 AC_DEFUN([LT_OUTPUT],
 [: ${CONFIG_LT=./config.lt}
@@ -651,9 +651,9 @@ m4_ifset([AC_PACKAGE_NAME], [AC_PACKAGE_NAME ])config.lt[]dnl
 m4_ifset([AC_PACKAGE_VERSION], [ AC_PACKAGE_VERSION])
 configured by $[0], generated by m4_PACKAGE_STRING.
 
-Copyright (C) 2011 Free Software Foundation, Inc.
+Copyright (C) 2024 Free Software Foundation, Inc.
 This config.lt script is free software; the Free Software Foundation
-gives unlimited permision to copy, distribute and modify it."
+gives unlimited permission to copy, distribute and modify it."
 
 while test 0 != $[#]
 do
@@ -730,7 +730,6 @@ _LT_CONFIG_SAVE_COMMANDS([
     cat <<_LT_EOF >> "$cfgfile"
 #! $SHELL
 # Generated automatically by $as_me ($PACKAGE) $VERSION
-# Libtool was configured on host `(hostname || uname -n) 2>/dev/null | sed 1q`:
 # NOTE: Changes made to this file will be lost: look at ltmain.sh.
 
 # Provide generalized library-building support services.
@@ -975,6 +974,7 @@ _lt_linker_boilerplate=`cat conftest.err`
 $RM -r conftest*
 ])# _LT_LINKER_BOILERPLATE
 
+
 # _LT_REQUIRED_DARWIN_CHECKS
 # -------------------------
 m4_defun_once([_LT_REQUIRED_DARWIN_CHECKS],[
@@ -1025,6 +1025,21 @@ m4_defun_once([_LT_REQUIRED_DARWIN_CHECKS],[
 	rm -f conftest.*
       fi])
 
+    # Feature test to disable chained fixups since it is not
+    # compatible with '-undefined dynamic_lookup'
+    AC_CACHE_CHECK([for -no_fixup_chains linker flag],
+      [lt_cv_support_no_fixup_chains],
+      [ save_LDFLAGS=$LDFLAGS
+        LDFLAGS="$LDFLAGS -Wl,-no_fixup_chains"
+        AC_LINK_IFELSE(
+          [AC_LANG_PROGRAM([],[])],
+          lt_cv_support_no_fixup_chains=yes,
+          lt_cv_support_no_fixup_chains=no
+        )
+        LDFLAGS=$save_LDFLAGS
+      ]
+    )
+
     AC_CACHE_CHECK([for -exported_symbols_list linker flag],
       [lt_cv_ld_exported_symbols_list],
       [lt_cv_ld_exported_symbols_list=no
@@ -1049,7 +1064,7 @@ _LT_EOF
       echo "$RANLIB libconftest.a" >&AS_MESSAGE_LOG_FD
       $RANLIB libconftest.a 2>&AS_MESSAGE_LOG_FD
       cat > conftest.c << _LT_EOF
-int main() { return 0;}
+int main(void) { return 0;}
 _LT_EOF
       echo "$LTCC $LTCFLAGS $LDFLAGS -o conftest conftest.c -Wl,-force_load,./libconftest.a" >&AS_MESSAGE_LOG_FD
       $LTCC $LTCFLAGS $LDFLAGS -o conftest conftest.c -Wl,-force_load,./libconftest.a 2>conftest.err
@@ -1074,13 +1089,32 @@ _LT_EOF
         10.[[012]],*|,*powerpc*-darwin[[5-8]]*)
           _lt_dar_allow_undefined='$wl-flat_namespace $wl-undefined ${wl}suppress' ;;
         *)
-          _lt_dar_allow_undefined='$wl-undefined ${wl}dynamic_lookup' ;;
+          _lt_dar_allow_undefined='$wl-undefined ${wl}dynamic_lookup'
+          if test yes = "$lt_cv_support_no_fixup_chains"; then
+            AS_VAR_APPEND([_lt_dar_allow_undefined], [' $wl-no_fixup_chains'])
+          fi
+        ;;
       esac
     ;;
   esac
     if test yes = "$lt_cv_apple_cc_single_mod"; then
       _lt_dar_single_mod='$single_module'
     fi
+    _lt_dar_needs_single_mod=no
+    case $host_os in
+    rhapsody* | darwin1.*)
+      _lt_dar_needs_single_mod=yes ;;
+    darwin*)
+      # When targeting Mac OS X 10.4 (darwin 8) or later,
+      # -single_module is the default and -multi_module is unsupported.
+      # The toolchain on macOS 10.14 (darwin 18) and later cannot
+      # target any OS version that needs -single_module.
+      case ${MACOSX_DEPLOYMENT_TARGET-10.0},$host in
+      10.0,*-darwin[[567]].*|10.[[0-3]],*-darwin[[5-9]].*|10.[[0-3]],*-darwin1[[0-7]].*)
+        _lt_dar_needs_single_mod=yes ;;
+      esac
+    ;;
+    esac
     if test yes = "$lt_cv_ld_exported_symbols_list"; then
       _lt_dar_export_syms=' $wl-exported_symbols_list,$output_objdir/$libname-symbols.expsym'
     else
@@ -1126,7 +1160,7 @@ m4_defun([_LT_DARWIN_LINKER_FEATURES],
     _LT_TAGVAR(archive_expsym_cmds, $1)="$SED 's|^|_|' < \$export_symbols > \$output_objdir/\$libname-symbols.expsym~\$CC -dynamiclib \$allow_undefined_flag -o \$lib \$libobjs \$deplibs \$compiler_flags -install_name \$rpath/\$soname \$verstring $_lt_dar_single_mod$_lt_dar_export_syms$_lt_dsymutil"
     _LT_TAGVAR(module_expsym_cmds, $1)="$SED -e 's|^|_|' < \$export_symbols > \$output_objdir/\$libname-symbols.expsym~\$CC \$allow_undefined_flag -o \$lib -bundle \$libobjs \$deplibs \$compiler_flags$_lt_dar_export_syms$_lt_dsymutil"
     m4_if([$1], [CXX],
-[   if test yes != "$lt_cv_apple_cc_single_mod"; then
+[   if test yes = "$_lt_dar_needs_single_mod" -a yes != "$lt_cv_apple_cc_single_mod"; then
       _LT_TAGVAR(archive_cmds, $1)="\$CC -r -keep_private_externs -nostdlib -o \$lib-master.o \$libobjs~\$CC -dynamiclib \$allow_undefined_flag -o \$lib \$lib-master.o \$deplibs \$compiler_flags -install_name \$rpath/\$soname \$verstring$_lt_dsymutil"
       _LT_TAGVAR(archive_expsym_cmds, $1)="$SED 's|^|_|' < \$export_symbols > \$output_objdir/\$libname-symbols.expsym~\$CC -r -keep_private_externs -nostdlib -o \$lib-master.o \$libobjs~\$CC -dynamiclib \$allow_undefined_flag -o \$lib \$lib-master.o \$deplibs \$compiler_flags -install_name \$rpath/\$soname \$verstring$_lt_dar_export_syms$_lt_dsymutil"
     fi
@@ -1256,7 +1290,9 @@ lt_sysroot=
 case $with_sysroot in #(
  yes)
    if test yes = "$GCC"; then
-     lt_sysroot=`$CC --print-sysroot 2>/dev/null`
+     # Trim trailing / since we'll always append absolute paths and we want
+     # to avoid //, if only for less confusing output for the user.
+     lt_sysroot=`$CC --print-sysroot 2>/dev/null | $SED 's:/\+$::'`
    fi
    ;; #(
  /*)
@@ -1368,7 +1404,7 @@ mips64*-*linux*)
   ;;
 
 x86_64-*kfreebsd*-gnu|x86_64-*linux*|powerpc*-*linux*| \
-s390*-*linux*|s390*-*tpf*|sparc*-*linux*)
+s390*-*linux*|s390*-*tpf*|sparc*-*linux*|x86_64-gnu*)
   # Find out what ABI is being produced by ac_compile, and set linker
   # options accordingly.  Note that the listed cases only cover the
   # situations where additional linker options are needed (such as when
@@ -1383,7 +1419,7 @@ s390*-*linux*|s390*-*tpf*|sparc*-*linux*)
 	  x86_64-*kfreebsd*-gnu)
 	    LD="${LD-ld} -m elf_i386_fbsd"
 	    ;;
-	  x86_64-*linux*)
+	  x86_64-*linux*|x86_64-gnu*)
 	    case `$FILECMD conftest.o` in
 	      *x86-64*)
 		LD="${LD-ld} -m elf32_x86_64"
@@ -1412,7 +1448,7 @@ s390*-*linux*|s390*-*tpf*|sparc*-*linux*)
 	  x86_64-*kfreebsd*-gnu)
 	    LD="${LD-ld} -m elf_x86_64_fbsd"
 	    ;;
-	  x86_64-*linux*)
+	  x86_64-*linux*|x86_64-gnu*)
 	    LD="${LD-ld} -m elf_x86_64"
 	    ;;
 	  powerpcle-*linux*)
@@ -1495,7 +1531,7 @@ _LT_DECL([], [AR], [1], [The archiver])
 
 # Use ARFLAGS variable as AR's operation code to sync the variable naming with
 # Automake.  If both AR_FLAGS and ARFLAGS are specified, AR_FLAGS should have
-# higher priority because thats what people were doing historically (setting
+# higher priority because that's what people were doing historically (setting
 # ARFLAGS for automake and AR_FLAGS for libtool).  FIXME: Make the AR_FLAGS
 # variable obsoleted/removed.
 
@@ -1545,7 +1581,7 @@ AC_CHECK_TOOL(STRIP, strip, :)
 test -z "$STRIP" && STRIP=:
 _LT_DECL([], [STRIP], [1], [A symbol stripping program])
 
-AC_CHECK_TOOL(RANLIB, ranlib, :)
+AC_REQUIRE([AC_PROG_RANLIB])
 test -z "$RANLIB" && RANLIB=:
 _LT_DECL([], [RANLIB], [1],
     [Commands used to install an old-style archive])
@@ -1556,15 +1592,8 @@ old_postinstall_cmds='chmod 644 $oldlib'
 old_postuninstall_cmds=
 
 if test -n "$RANLIB"; then
-  case $host_os in
-  bitrig* | openbsd*)
-    old_postinstall_cmds="$old_postinstall_cmds~\$RANLIB -t \$tool_oldlib"
-    ;;
-  *)
-    old_postinstall_cmds="$old_postinstall_cmds~\$RANLIB \$tool_oldlib"
-    ;;
-  esac
   old_archive_cmds="$old_archive_cmds~\$RANLIB \$tool_oldlib"
+  old_postinstall_cmds="$old_postinstall_cmds~\$RANLIB \$tool_oldlib"
 fi
 
 case $host_os in
@@ -1696,14 +1725,14 @@ AC_CACHE_VAL([lt_cv_sys_max_cmd_len], [dnl
     lt_cv_sys_max_cmd_len=12288;    # 12K is about right
     ;;
 
-  gnu*)
-    # Under GNU Hurd, this test is not required because there is
-    # no limit to the length of command line arguments.
+  gnu* | ironclad*)
+    # Under GNU Hurd and Ironclad, this test is not required because there
+    # is no limit to the length of command line arguments.
     # Libtool will interpret -1 as no limit whatsoever
     lt_cv_sys_max_cmd_len=-1;
     ;;
 
-  cygwin* | mingw* | cegcc*)
+  cygwin* | mingw* | windows* | cegcc*)
     # On Win9x/ME, this test blows up -- it succeeds, but takes
     # about 5 minutes as the teststring grows exponentially.
     # Worse, since 9x/ME are not pre-emptively multitasking,
@@ -1725,7 +1754,7 @@ AC_CACHE_VAL([lt_cv_sys_max_cmd_len], [dnl
     lt_cv_sys_max_cmd_len=8192;
     ;;
 
-  bitrig* | darwin* | dragonfly* | freebsd* | midnightbsd* | netbsd* | openbsd*)
+  darwin* | dragonfly* | freebsd* | midnightbsd* | netbsd* | openbsd*)
     # This has been around since 386BSD, at least.  Likely further.
     if test -x /sbin/sysctl; then
       lt_cv_sys_max_cmd_len=`/sbin/sysctl -n kern.argmax`
@@ -1885,11 +1914,11 @@ else
 /* When -fvisibility=hidden is used, assume the code has been annotated
    correspondingly for the symbols needed.  */
 #if defined __GNUC__ && (((__GNUC__ == 3) && (__GNUC_MINOR__ >= 3)) || (__GNUC__ > 3))
-int fnord () __attribute__((visibility("default")));
+int fnord (void) __attribute__((visibility("default")));
 #endif
 
-int fnord () { return 42; }
-int main ()
+int fnord (void) { return 42; }
+int main (void)
 {
   void *self = dlopen (0, LT_DLGLOBAL|LT_DLLAZY_OR_NOW);
   int status = $lt_dlunknown;
@@ -1946,7 +1975,7 @@ else
     lt_cv_dlopen_self=yes
     ;;
 
-  mingw* | pw32* | cegcc*)
+  mingw* | windows* | pw32* | cegcc*)
     lt_cv_dlopen=LoadLibrary
     lt_cv_dlopen_libs=
     ;;
@@ -2314,7 +2343,7 @@ if test yes = "$GCC"; then
     *) lt_awk_arg='/^libraries:/' ;;
   esac
   case $host_os in
-    mingw* | cegcc*) lt_sed_strip_eq='s|=\([[A-Za-z]]:\)|\1|g' ;;
+    mingw* | windows* | cegcc*) lt_sed_strip_eq='s|=\([[A-Za-z]]:\)|\1|g' ;;
     *) lt_sed_strip_eq='s|=/|/|g' ;;
   esac
   lt_search_path_spec=`$CC -print-search-dirs | awk $lt_awk_arg | $SED -e "s/^libraries://" -e $lt_sed_strip_eq`
@@ -2372,7 +2401,7 @@ BEGIN {RS = " "; FS = "/|\n";} {
   # AWK program above erroneously prepends '/' to C:/dos/paths
   # for these hosts.
   case $host_os in
-    mingw* | cegcc*) lt_search_path_spec=`$ECHO "$lt_search_path_spec" |\
+    mingw* | windows* | cegcc*) lt_search_path_spec=`$ECHO "$lt_search_path_spec" |\
       $SED 's|/\([[A-Za-z]]:\)|\1|g'` ;;
   esac
   sys_lib_search_path_spec=`$ECHO "$lt_search_path_spec" | $lt_NL2SP`
@@ -2447,7 +2476,7 @@ aix[[4-9]]*)
     # Unfortunately, runtime linking may impact performance, so we do
     # not want this to be the default eventually. Also, we use the
     # versioned .so libs for executables only if there is the -brtl
-    # linker flag in LDFLAGS as well, or --with-aix-soname=svr4 only.
+    # linker flag in LDFLAGS as well, or --enable-aix-soname=svr4 only.
     # To allow for filename-based versioning support, we need to create
     # libNAME.so.V as an archive file, containing:
     # *) an Import File, referring to the versioned filename of the
@@ -2541,7 +2570,7 @@ bsdi[[45]]*)
   # libtool to hard-code these into programs
   ;;
 
-cygwin* | mingw* | pw32* | cegcc*)
+cygwin* | mingw* | windows* | pw32* | cegcc*)
   version_type=windows
   shrext_cmds=.dll
   need_version=no
@@ -2552,15 +2581,29 @@ cygwin* | mingw* | pw32* | cegcc*)
     # gcc
     library_names_spec='$libname.dll.a'
     # DLL is installed to $(libdir)/../bin by postinstall_cmds
-    postinstall_cmds='base_file=`basename \$file`~
-      dlpath=`$SHELL 2>&1 -c '\''. $dir/'\''\$base_file'\''i; echo \$dlname'\''`~
-      dldir=$destdir/`dirname \$dlpath`~
-      test -d \$dldir || mkdir -p \$dldir~
-      $install_prog $dir/$dlname \$dldir/$dlname~
-      chmod a+x \$dldir/$dlname~
-      if test -n '\''$stripme'\'' && test -n '\''$striplib'\''; then
-        eval '\''$striplib \$dldir/$dlname'\'' || exit \$?;
-      fi'
+    # If user builds GCC with multilib enabled,
+    # it should just install on $(libdir)
+    # not on $(libdir)/../bin or 32 bits dlls would override 64 bit ones.
+    if test xyes = x"$multilib"; then
+      postinstall_cmds='base_file=`basename \$file`~
+        dlpath=`$SHELL 2>&1 -c '\''. $dir/'\''\$base_file'\''i; echo \$dlname'\''`~
+        dldir=$destdir/`dirname \$dlpath`~
+        $install_prog $dir/$dlname $destdir/$dlname~
+        chmod a+x $destdir/$dlname~
+        if test -n '\''$stripme'\'' && test -n '\''$striplib'\''; then
+          eval '\''$striplib $destdir/$dlname'\'' || exit \$?;
+        fi'
+    else
+      postinstall_cmds='base_file=`basename \$file`~
+        dlpath=`$SHELL 2>&1 -c '\''. $dir/'\''\$base_file'\''i; echo \$dlname'\''`~
+        dldir=$destdir/`dirname \$dlpath`~
+        test -d \$dldir || mkdir -p \$dldir~
+        $install_prog $dir/$dlname \$dldir/$dlname~
+        chmod a+x \$dldir/$dlname~
+        if test -n '\''$stripme'\'' && test -n '\''$striplib'\''; then
+          eval '\''$striplib \$dldir/$dlname'\'' || exit \$?;
+        fi'
+    fi
     postuninstall_cmds='dldll=`$SHELL 2>&1 -c '\''. $file; echo \$dlname'\''`~
       dlpath=$dir/\$dldll~
        $RM \$dlpath'
@@ -2573,7 +2616,7 @@ cygwin* | mingw* | pw32* | cegcc*)
 m4_if([$1], [],[
       sys_lib_search_path_spec="$sys_lib_search_path_spec /usr/lib/w32api"])
       ;;
-    mingw* | cegcc*)
+    mingw* | windows* | cegcc*)
       # MinGW DLLs use traditional 'lib' prefix
       soname_spec='$libname`echo $release | $SED -e 's/[[.]]/-/g'`$versuffix$shared_ext'
       ;;
@@ -2592,7 +2635,7 @@ m4_if([$1], [],[
     library_names_spec='$libname.dll.lib'
 
     case $build_os in
-    mingw*)
+    mingw* | windows*)
       sys_lib_search_path_spec=
       lt_save_ifs=$IFS
       IFS=';'
@@ -2699,7 +2742,21 @@ freebsd* | dragonfly* | midnightbsd*)
       need_version=yes
       ;;
   esac
-  shlibpath_var=LD_LIBRARY_PATH
+  case $host_cpu in
+    powerpc64)
+      # On FreeBSD bi-arch platforms, a different variable is used for 32-bit
+      # binaries.  See <https://man.freebsd.org/cgi/man.cgi?query=ld.so>.
+      AC_COMPILE_IFELSE(
+        [AC_LANG_SOURCE(
+           [[int test_pointer_size[sizeof (void *) - 5];
+           ]])],
+        [shlibpath_var=LD_LIBRARY_PATH],
+        [shlibpath_var=LD_32_LIBRARY_PATH])
+      ;;
+    *)
+      shlibpath_var=LD_LIBRARY_PATH
+      ;;
+  esac
   case $host_os in
   freebsd2.*)
     shlibpath_overrides_runpath=yes
@@ -2729,8 +2786,9 @@ haiku*)
   soname_spec='$libname$release$shared_ext$major'
   shlibpath_var=LIBRARY_PATH
   shlibpath_overrides_runpath=no
-  sys_lib_dlsearch_path_spec='/boot/home/config/lib /boot/common/lib /boot/system/lib'
-  hardcode_into_libs=yes
+  sys_lib_search_path_spec='/boot/system/non-packaged/develop/lib /boot/system/develop/lib'
+  sys_lib_dlsearch_path_spec='/boot/home/config/non-packaged/lib /boot/home/config/lib /boot/system/non-packaged/lib /boot/system/lib'
+  hardcode_into_libs=no
   ;;
 
 hpux9* | hpux10* | hpux11*)
@@ -2840,7 +2898,7 @@ linux*android*)
   version_type=none # Android doesn't support versioned libraries.
   need_lib_prefix=no
   need_version=no
-  library_names_spec='$libname$release$shared_ext'
+  library_names_spec='$libname$release$shared_ext $libname$shared_ext'
   soname_spec='$libname$release$shared_ext'
   finish_cmds=
   shlibpath_var=LD_LIBRARY_PATH
@@ -2852,8 +2910,9 @@ linux*android*)
   hardcode_into_libs=yes
 
   dynamic_linker='Android linker'
-  # Don't embed -rpath directories since the linker doesn't support them.
-  _LT_TAGVAR(hardcode_libdir_flag_spec, $1)='-L$libdir'
+  # -rpath works at least for libraries that are not overridden by
+  # libraries installed in system locations.
+  _LT_TAGVAR(hardcode_libdir_flag_spec, $1)='$wl-rpath $wl$libdir'
   ;;
 
 # This must be glibc/ELF.
@@ -2887,7 +2946,7 @@ linux* | k*bsd*-gnu | kopensolaris*-gnu | gnu*)
   # before this can be enabled.
   hardcode_into_libs=yes
 
-  # Ideally, we could use ldconfig to report *all* directores which are
+  # Ideally, we could use ldconfig to report *all* directories which are
   # searched for libraries, however this is still not possible.  Aside from not
   # being certain /sbin/ldconfig is available, command
   # 'ldconfig -N -X -v | grep ^/' on 64bit Fedora does not report /usr/lib64,
@@ -2907,6 +2966,18 @@ linux* | k*bsd*-gnu | kopensolaris*-gnu | gnu*)
   dynamic_linker='GNU/Linux ld.so'
   ;;
 
+netbsdelf*-gnu)
+  version_type=linux
+  need_lib_prefix=no
+  need_version=no
+  library_names_spec='$libname$release$shared_ext$versuffix $libname$release$shared_ext$major $libname$shared_ext'
+  soname_spec='$libname$release$shared_ext$major'
+  shlibpath_var=LD_LIBRARY_PATH
+  shlibpath_overrides_runpath=no
+  hardcode_into_libs=yes
+  dynamic_linker='NetBSD ld.elf_so'
+  ;;
+
 netbsd*)
   version_type=sunos
   need_lib_prefix=no
@@ -2925,6 +2996,18 @@ netbsd*)
   hardcode_into_libs=yes
   ;;
 
+*-mlibc)
+  version_type=linux # correct to gnu/linux during the next big refactor
+  need_lib_prefix=no
+  need_version=no
+  library_names_spec='$libname$release$shared_ext$versuffix $libname$release$shared_ext$major $libname$shared_ext'
+  soname_spec='$libname$release$shared_ext$major'
+  dynamic_linker='mlibc ld.so'
+  shlibpath_var=LD_LIBRARY_PATH
+  shlibpath_overrides_runpath=no
+  hardcode_into_libs=yes
+  ;;
+
 newsos6)
   version_type=linux # correct to gnu/linux during the next big refactor
   library_names_spec='$libname$release$shared_ext$versuffix $libname$release$shared_ext$major $libname$shared_ext'
@@ -2944,7 +3027,7 @@ newsos6)
   dynamic_linker='ldqnx.so'
   ;;
 
-openbsd* | bitrig*)
+openbsd*)
   version_type=sunos
   sys_lib_dlsearch_path_spec=/usr/lib
   need_lib_prefix=no
@@ -3004,6 +3087,17 @@ rdos*)
   dynamic_linker=no
   ;;
 
+serenity*)
+  version_type=linux # correct to gnu/linux during the next big refactor
+  need_lib_prefix=no
+  need_version=no
+  library_names_spec='$libname$release$shared_ext$versuffix $libname$release$shared_ext$major $libname$shared_ext'
+  soname_spec='$libname$release$shared_ext$major'
+  shlibpath_var=LD_LIBRARY_PATH
+  shlibpath_overrides_runpath=no
+  dynamic_linker='SerenityOS LibELF'
+  ;;
+
 solaris*)
   version_type=linux # correct to gnu/linux during the next big refactor
   need_lib_prefix=no
@@ -3101,6 +3195,21 @@ uts4*)
   shlibpath_var=LD_LIBRARY_PATH
   ;;
 
+emscripten*)
+  version_type=none
+  need_lib_prefix=no
+  need_version=no
+  library_names_spec='$libname$release$shared_ext'
+  soname_spec='$libname$release$shared_ext'
+  finish_cmds=
+  dynamic_linker="Emscripten linker"
+  _LT_COMPILER_PIC($1)='-fPIC'
+  _LT_TAGVAR(archive_cmds, $1)='$CC -sSIDE_MODULE=2 -shared $libobjs $deplibs $compiler_flags -o $lib'
+  _LT_TAGVAR(archive_expsym_cmds, $1)='$SED "s|^|_|" $export_symbols >$output_objdir/$soname.expsym~$CC -sSIDE_MODULE=2 -shared $libobjs $deplibs $compiler_flags -o $lib -s EXPORTED_FUNCTIONS=@$output_objdir/$soname.expsym'
+  _LT_TAGVAR(archive_cmds_need_lc, $1)=no
+  _LT_TAGVAR(no_undefined_flag, $1)=
+  ;;
+
 *)
   dynamic_linker=no
   ;;
@@ -3276,7 +3385,7 @@ if test yes = "$GCC"; then
   # Check if gcc -print-prog-name=ld gives a path.
   AC_MSG_CHECKING([for ld used by $CC])
   case $host in
-  *-*-mingw*)
+  *-*-mingw* | *-*-windows*)
     # gcc leaves a trailing carriage return, which upsets mingw
     ac_prog=`($CC -print-prog-name=ld) 2>&5 | tr -d '\015'` ;;
   *)
@@ -3385,7 +3494,7 @@ case $reload_flag in
 esac
 reload_cmds='$LD$reload_flag -o $output$reload_objs'
 case $host_os in
-  cygwin* | mingw* | pw32* | cegcc*)
+  cygwin* | mingw* | windows* | pw32* | cegcc*)
     if test yes != "$GCC"; then
       reload_cmds=false
     fi
@@ -3457,7 +3566,6 @@ lt_cv_deplibs_check_method='unknown'
 # 'none' -- dependencies not supported.
 # 'unknown' -- same as none, but documents that we really don't know.
 # 'pass_all' -- all dependencies passed with no checks.
-# 'test_compile' -- check by making test program.
 # 'file_magic [[regex]]' -- check by looking for files in library path
 # that responds to the $file_magic_cmd with a given extended regex.
 # If you have 'file' or equivalent on your system and you're not sure
@@ -3484,7 +3592,7 @@ cygwin*)
   lt_cv_file_magic_cmd='func_win32_libid'
   ;;
 
-mingw* | pw32*)
+mingw* | windows* | pw32*)
   # Base MSYS/MinGW do not provide the 'file' command needed by
   # func_win32_libid shell function, so use a weaker test based on 'objdump',
   # unless we find 'file', for example because we are cross-compiling.
@@ -3493,7 +3601,7 @@ mingw* | pw32*)
     lt_cv_file_magic_cmd='func_win32_libid'
   else
     # Keep this pattern in sync with the one in func_win32_libid.
-    lt_cv_deplibs_check_method='file_magic file format (pei*-i386(.*architecture: i386)?|pe-arm-wince|pe-x86-64)'
+    lt_cv_deplibs_check_method='file_magic file format (pei*-i386(.*architecture: i386)?|pe-arm-wince|pe-x86-64|pe-aarch64)'
     lt_cv_file_magic_cmd='$OBJDUMP -f'
   fi
   ;;
@@ -3566,7 +3674,11 @@ linux* | k*bsd*-gnu | kopensolaris*-gnu | gnu*)
   lt_cv_deplibs_check_method=pass_all
   ;;
 
-netbsd*)
+*-mlibc)
+  lt_cv_deplibs_check_method=pass_all
+  ;;
+
+netbsd* | netbsdelf*-gnu)
   if echo __ELF__ | $CC -E - | $GREP __ELF__ > /dev/null; then
     lt_cv_deplibs_check_method='match_pattern /lib[[^/]]+(\.so\.[[0-9]]+\.[[0-9]]+|_pic\.a)$'
   else
@@ -3584,7 +3696,7 @@ newos6*)
   lt_cv_deplibs_check_method=pass_all
   ;;
 
-openbsd* | bitrig*)
+openbsd*)
   if test -z "`echo __ELF__ | $CC -E - | $GREP __ELF__`"; then
     lt_cv_deplibs_check_method='match_pattern /lib[[^/]]+(\.so\.[[0-9]]+\.[[0-9]]+|\.so|_pic\.a)$'
   else
@@ -3600,6 +3712,10 @@ rdos*)
   lt_cv_deplibs_check_method=pass_all
   ;;
 
+serenity*)
+  lt_cv_deplibs_check_method=pass_all
+  ;;
+
 solaris*)
   lt_cv_deplibs_check_method=pass_all
   ;;
@@ -3648,7 +3764,7 @@ file_magic_glob=
 want_nocaseglob=no
 if test "$build" = "$host"; then
   case $host_os in
-  mingw* | pw32*)
+  mingw* | windows* | pw32*)
     if ( shopt | grep nocaseglob ) >/dev/null 2>&1; then
       want_nocaseglob=yes
     else
@@ -3700,7 +3816,7 @@ else
 	# Tru64's nm complains that /dev/null is an invalid object file
 	# MSYS converts /dev/null to NUL, MinGW nm treats NUL as empty
 	case $build_os in
-	mingw*) lt_bad_file=conftest.nm/nofile ;;
+	mingw* | windows*) lt_bad_file=conftest.nm/nofile ;;
 	*) lt_bad_file=/dev/null ;;
 	esac
 	case `"$tmp_nm" -B $lt_bad_file 2>&1 | $SED '1q'` in
@@ -3791,7 +3907,7 @@ lt_cv_sharedlib_from_linklib_cmd,
 [lt_cv_sharedlib_from_linklib_cmd='unknown'
 
 case $host_os in
-cygwin* | mingw* | pw32* | cegcc*)
+cygwin* | mingw* | windows* | pw32* | cegcc*)
   # two different shell functions defined in ltmain.sh;
   # decide which one to use based on capabilities of $DLLTOOL
   case `$DLLTOOL --help 2>&1` in
@@ -3823,16 +3939,16 @@ _LT_DECL([], [sharedlib_from_linklib_cmd], [1],
 m4_defun([_LT_PATH_MANIFEST_TOOL],
 [AC_CHECK_TOOL(MANIFEST_TOOL, mt, :)
 test -z "$MANIFEST_TOOL" && MANIFEST_TOOL=mt
-AC_CACHE_CHECK([if $MANIFEST_TOOL is a manifest tool], [lt_cv_path_mainfest_tool],
-  [lt_cv_path_mainfest_tool=no
+AC_CACHE_CHECK([if $MANIFEST_TOOL is a manifest tool], [lt_cv_path_manifest_tool],
+  [lt_cv_path_manifest_tool=no
   echo "$as_me:$LINENO: $MANIFEST_TOOL '-?'" >&AS_MESSAGE_LOG_FD
   $MANIFEST_TOOL '-?' 2>conftest.err > conftest.out
   cat conftest.err >&AS_MESSAGE_LOG_FD
   if $GREP 'Manifest Tool' conftest.out > /dev/null; then
-    lt_cv_path_mainfest_tool=yes
+    lt_cv_path_manifest_tool=yes
   fi
   rm -f conftest*])
-if test yes != "$lt_cv_path_mainfest_tool"; then
+if test yes != "$lt_cv_path_manifest_tool"; then
   MANIFEST_TOOL=:
 fi
 _LT_DECL([], [MANIFEST_TOOL], [1], [Manifest tool])dnl
@@ -3861,7 +3977,7 @@ AC_DEFUN([LT_LIB_M],
 [AC_REQUIRE([AC_CANONICAL_HOST])dnl
 LIBM=
 case $host in
-*-*-beos* | *-*-cegcc* | *-*-cygwin* | *-*-haiku* | *-*-pw32* | *-*-darwin*)
+*-*-beos* | *-*-cegcc* | *-*-cygwin* | *-*-haiku* | *-*-mingw* | *-*-pw32* | *-*-darwin*)
   # These system don't have libm, or don't need it
   ;;
 *-ncr-sysv4.3*)
@@ -3936,7 +4052,7 @@ case $host_os in
 aix*)
   symcode='[[BCDT]]'
   ;;
-cygwin* | mingw* | pw32* | cegcc*)
+cygwin* | mingw* | windows* | pw32* | cegcc*)
   symcode='[[ABCDGISTW]]'
   ;;
 hpux*)
@@ -3951,7 +4067,7 @@ osf*)
   symcode='[[BCDEGQRST]]'
   ;;
 solaris*)
-  symcode='[[BDRT]]'
+  symcode='[[BCDRT]]'
   ;;
 sco3.2v5*)
   symcode='[[DT]]'
@@ -4015,7 +4131,7 @@ $lt_c_name_lib_hook\
 # Handle CRLF in mingw tool chain
 opt_cr=
 case $build_os in
-mingw*)
+mingw* | windows*)
   opt_cr=`$ECHO 'x\{0,1\}' | tr x '\015'` # option cr in regexp
   ;;
 esac
@@ -4066,13 +4182,14 @@ void nm_test_func(void){}
 #ifdef __cplusplus
 }
 #endif
-int main(){nm_test_var='a';nm_test_func();return(0);}
+int main(void){nm_test_var='a';nm_test_func();return(0);}
 _LT_EOF
 
   if AC_TRY_EVAL(ac_compile); then
     # Now try to grab the symbols.
     nlist=conftest.nm
-    if AC_TRY_EVAL(NM conftest.$ac_objext \| "$lt_cv_sys_global_symbol_pipe" \> $nlist) && test -s "$nlist"; then
+    $ECHO "$as_me:$LINENO: $NM conftest.$ac_objext | $lt_cv_sys_global_symbol_pipe > $nlist" >&AS_MESSAGE_LOG_FD
+    if eval "$NM" conftest.$ac_objext \| "$lt_cv_sys_global_symbol_pipe" \> $nlist 2>&AS_MESSAGE_LOG_FD && test -s "$nlist"; then
       # Try sorting and uniquifying the output.
       if sort "$nlist" | uniq > "$nlist"T; then
 	mv -f "$nlist"T "$nlist"
@@ -4242,7 +4359,7 @@ m4_if([$1], [CXX], [
     beos* | irix5* | irix6* | nonstopux* | osf3* | osf4* | osf5*)
       # PIC is the default for these OSes.
       ;;
-    mingw* | cygwin* | os2* | pw32* | cegcc*)
+    mingw* | windows* | cygwin* | os2* | pw32* | cegcc*)
       # This hack is so that the source file can tell whether it is being
       # built for inclusion in a dll (and should export symbols for example).
       # Although the cygwin gcc ignores -fPIC, still need this for old-style
@@ -4318,7 +4435,7 @@ m4_if([$1], [CXX], [
 	  ;;
 	esac
 	;;
-      mingw* | cygwin* | os2* | pw32* | cegcc*)
+      mingw* | windows* | cygwin* | os2* | pw32* | cegcc*)
 	# This hack is so that the source file can tell whether it is being
 	# built for inclusion in a dll (and should export symbols for example).
 	m4_if([$1], [GCJ], [],
@@ -4444,7 +4561,9 @@ m4_if([$1], [CXX], [
 	    ;;
 	esac
 	;;
-      netbsd*)
+      netbsd* | netbsdelf*-gnu)
+	;;
+      *-mlibc)
 	;;
       *qnx* | *nto*)
         # QNX uses GNU C++, but need to define -shared option too, otherwise
@@ -4474,6 +4593,8 @@ m4_if([$1], [CXX], [
 	;;
       psos*)
 	;;
+      serenity*)
+        ;;
       solaris*)
 	case $cc_basename in
 	  CC* | sunCC*)
@@ -4566,7 +4687,7 @@ m4_if([$1], [CXX], [
       # PIC is the default for these OSes.
       ;;
 
-    mingw* | cygwin* | pw32* | os2* | cegcc*)
+    mingw* | windows* | cygwin* | pw32* | os2* | cegcc*)
       # This hack is so that the source file can tell whether it is being
       # built for inclusion in a dll (and should export symbols for example).
       # Although the cygwin gcc ignores -fPIC, still need this for old-style
@@ -4670,7 +4791,7 @@ m4_if([$1], [CXX], [
       esac
       ;;
 
-    mingw* | cygwin* | pw32* | os2* | cegcc*)
+    mingw* | windows* | cygwin* | pw32* | os2* | cegcc*)
       # This hack is so that the source file can tell whether it is being
       # built for inclusion in a dll (and should export symbols for example).
       m4_if([$1], [GCJ], [],
@@ -4712,6 +4833,12 @@ m4_if([$1], [CXX], [
 	_LT_TAGVAR(lt_prog_compiler_pic, $1)='-KPIC'
 	_LT_TAGVAR(lt_prog_compiler_static, $1)='-static'
         ;;
+      *flang* | ftn | f18* | f95*)
+        # Flang compiler.
+	_LT_TAGVAR(lt_prog_compiler_wl, $1)='-Wl,'
+	_LT_TAGVAR(lt_prog_compiler_pic, $1)='-fPIC'
+	_LT_TAGVAR(lt_prog_compiler_static, $1)='-static'
+        ;;
       # icc used to be incompatible with GCC.
       # ICC 10 doesn't accept -KPIC any more.
       icc* | ifort*)
@@ -4794,6 +4921,12 @@ m4_if([$1], [CXX], [
       _LT_TAGVAR(lt_prog_compiler_static, $1)='-Bstatic'
       ;;
 
+    *-mlibc)
+      _LT_TAGVAR(lt_prog_compiler_wl, $1)='-Wl,'
+      _LT_TAGVAR(lt_prog_compiler_pic, $1)='-fPIC'
+      _LT_TAGVAR(lt_prog_compiler_static, $1)='-static'
+      ;;
+
     *nto* | *qnx*)
       # QNX uses GNU C++, but need to define -shared option too, otherwise
       # it will coredump.
@@ -4810,6 +4943,9 @@ m4_if([$1], [CXX], [
       _LT_TAGVAR(lt_prog_compiler_static, $1)='-non_shared'
       ;;
 
+    serenity*)
+      ;;
+
     solaris*)
       _LT_TAGVAR(lt_prog_compiler_pic, $1)='-KPIC'
       _LT_TAGVAR(lt_prog_compiler_static, $1)='-Bstatic'
@@ -4945,7 +5081,7 @@ m4_if([$1], [CXX], [
   pw32*)
     _LT_TAGVAR(export_symbols_cmds, $1)=$ltdll_cmds
     ;;
-  cygwin* | mingw* | cegcc*)
+  cygwin* | mingw* | windows* | cegcc*)
     case $cc_basename in
     cl* | icl*)
       _LT_TAGVAR(exclude_expsyms, $1)='_NULL_IMPORT_DESCRIPTOR|_IMPORT_DESCRIPTOR_.*'
@@ -5003,7 +5139,7 @@ dnl Note also adjust exclude_expsyms for C++ above.
   extract_expsyms_cmds=
 
   case $host_os in
-  cygwin* | mingw* | pw32* | cegcc*)
+  cygwin* | mingw* | windows* | pw32* | cegcc*)
     # FIXME: the MSVC++ and ICC port hasn't been tested in a loooong time
     # When not using gcc, we currently assume that we are using
     # Microsoft Visual C++ or Intel C++ Compiler.
@@ -5015,9 +5151,6 @@ dnl Note also adjust exclude_expsyms for C++ above.
     # we just hope/assume this is gcc and not c89 (= MSVC++ or ICC)
     with_gnu_ld=yes
     ;;
-  openbsd* | bitrig*)
-    with_gnu_ld=no
-    ;;
   esac
 
   _LT_TAGVAR(ld_shlibs, $1)=yes
@@ -5118,7 +5251,7 @@ _LT_EOF
       fi
       ;;
 
-    cygwin* | mingw* | pw32* | cegcc*)
+    cygwin* | mingw* | windows* | pw32* | cegcc*)
       # _LT_TAGVAR(hardcode_libdir_flag_spec, $1) is actually meaningless,
       # as there is no search path for DLLs.
       _LT_TAGVAR(hardcode_libdir_flag_spec, $1)='-L$libdir'
@@ -5128,6 +5261,7 @@ _LT_EOF
       _LT_TAGVAR(enable_shared_with_static_runtimes, $1)=yes
       _LT_TAGVAR(export_symbols_cmds, $1)='$NM $libobjs $convenience | $global_symbol_pipe | $SED -e '\''/^[[BCDGRS]][[ ]]/s/.*[[ ]]\([[^ ]]*\)/\1 DATA/;s/^.*[[ ]]__nm__\([[^ ]]*\)[[ ]][[^ ]]*/\1 DATA/;/^I[[ ]]/d;/^[[AITW]][[ ]]/s/.* //'\'' | sort | uniq > $export_symbols'
       _LT_TAGVAR(exclude_expsyms, $1)=['[_]+GLOBAL_OFFSET_TABLE_|[_]+GLOBAL__[FID]_.*|[_]+head_[A-Za-z0-9_]+_dll|[A-Za-z0-9_]+_dll_iname']
+      _LT_TAGVAR(file_list_spec, $1)='@'
 
       if $LD --help 2>&1 | $GREP 'auto-import' > /dev/null; then
         _LT_TAGVAR(archive_cmds, $1)='$CC -shared $libobjs $deplibs $compiler_flags -o $output_objdir/$soname $wl--enable-auto-image-base -Xlinker --out-implib -Xlinker $lib'
@@ -5147,7 +5281,7 @@ _LT_EOF
 
     haiku*)
       _LT_TAGVAR(archive_cmds, $1)='$CC -shared $libobjs $deplibs $compiler_flags $wl-soname $wl$soname -o $lib'
-      _LT_TAGVAR(link_all_deplibs, $1)=yes
+      _LT_TAGVAR(link_all_deplibs, $1)=no
       ;;
 
     os2*)
@@ -5174,7 +5308,7 @@ _LT_EOF
 	cat $export_symbols | $prefix_cmds >> $output_objdir/$libname.def~
 	$CC -Zdll -Zcrtdll -o $output_objdir/$soname $libobjs $deplibs $compiler_flags $output_objdir/$libname.def~
 	emximp -o $lib $output_objdir/$libname.def'
-      _LT_TAGVAR(old_archive_From_new_cmds, $1)='emximp -o $output_objdir/${libname}_dll.a $output_objdir/$libname.def'
+      _LT_TAGVAR(old_archive_from_new_cmds, $1)='emximp -o $output_objdir/${libname}_dll.a $output_objdir/$libname.def'
       _LT_TAGVAR(enable_shared_with_static_runtimes, $1)=yes
       _LT_TAGVAR(file_list_spec, $1)='@'
       ;;
@@ -5253,6 +5387,7 @@ _LT_EOF
 
 	case $cc_basename in
 	tcc*)
+	  _LT_TAGVAR(hardcode_libdir_flag_spec, $1)='$wl-rpath $wl$libdir'
 	  _LT_TAGVAR(export_dynamic_flag_spec, $1)='-rdynamic'
 	  ;;
 	xlf* | bgf* | bgxlf* | mpixlf*)
@@ -5273,7 +5408,12 @@ _LT_EOF
       fi
       ;;
 
-    netbsd*)
+    *-mlibc)
+	_LT_TAGVAR(archive_cmds, $1)='$CC -shared $pic_flag $libobjs $deplibs $compiler_flags $wl-soname $wl$soname -o $lib'
+	_LT_TAGVAR(archive_expsym_cmds, $1)='$CC -shared $pic_flag $libobjs $deplibs $compiler_flags $wl-soname $wl$soname $wl-retain-symbols-file $wl$export_symbols -o $lib'
+      ;;
+
+    netbsd* | netbsdelf*-gnu)
       if echo __ELF__ | $CC -E - | $GREP __ELF__ >/dev/null; then
 	_LT_TAGVAR(archive_cmds, $1)='$LD -Bshareable $libobjs $deplibs $linker_flags -o $lib'
 	wlarc=
@@ -5575,7 +5715,7 @@ _LT_EOF
       _LT_TAGVAR(export_dynamic_flag_spec, $1)=-rdynamic
       ;;
 
-    cygwin* | mingw* | pw32* | cegcc*)
+    cygwin* | mingw* | windows* | pw32* | cegcc*)
       # When not using gcc, we currently assume that we are using
       # Microsoft Visual C++ or Intel C++ Compiler.
       # hardcode_libdir_flag_spec is actually meaningless, as there is
@@ -5592,14 +5732,14 @@ _LT_EOF
 	# Tell ltmain to make .dll files, not .so files.
 	shrext_cmds=.dll
 	# FIXME: Setting linknames here is a bad hack.
-	_LT_TAGVAR(archive_cmds, $1)='$CC -o $output_objdir/$soname $libobjs $compiler_flags $deplibs -Wl,-DLL,-IMPLIB:"$tool_output_objdir$libname.dll.lib"~linknames='
+	_LT_TAGVAR(archive_cmds, $1)='$CC -Fe$output_objdir/$soname $libobjs $compiler_flags $deplibs -Wl,-DLL,-IMPLIB:"$tool_output_objdir$libname.dll.lib"~linknames='
 	_LT_TAGVAR(archive_expsym_cmds, $1)='if _LT_DLL_DEF_P([$export_symbols]); then
             cp "$export_symbols" "$output_objdir/$soname.def";
             echo "$tool_output_objdir$soname.def" > "$output_objdir/$soname.exp";
           else
             $SED -e '\''s/^/-link -EXPORT:/'\'' < $export_symbols > $output_objdir/$soname.exp;
           fi~
-          $CC -o $tool_output_objdir$soname $libobjs $compiler_flags $deplibs "@$tool_output_objdir$soname.exp" -Wl,-DLL,-IMPLIB:"$tool_output_objdir$libname.dll.lib"~
+          $CC -Fe$tool_output_objdir$soname $libobjs $compiler_flags $deplibs "@$tool_output_objdir$soname.exp" -Wl,-DLL,-IMPLIB:"$tool_output_objdir$libname.dll.lib"~
           linknames='
 	# The linker will not automatically build a static lib if we build a DLL.
 	# _LT_TAGVAR(old_archive_from_new_cmds, $1)='true'
@@ -5811,11 +5951,15 @@ _LT_EOF
 	# Fabrice Bellard et al's Tiny C Compiler
 	_LT_TAGVAR(ld_shlibs, $1)=yes
 	_LT_TAGVAR(archive_cmds, $1)='$CC -shared $pic_flag -o $lib $libobjs $deplibs $compiler_flags'
+	_LT_TAGVAR(hardcode_libdir_flag_spec, $1)='$wl-rpath $wl$libdir'
 	;;
       esac
       ;;
 
-    netbsd*)
+    *-mlibc)
+      ;;
+
+    netbsd* | netbsdelf*-gnu)
       if echo __ELF__ | $CC -E - | $GREP __ELF__ >/dev/null; then
 	_LT_TAGVAR(archive_cmds, $1)='$LD -Bshareable -o $lib $libobjs $deplibs $linker_flags'  # a.out
       else
@@ -5837,7 +5981,7 @@ _LT_EOF
     *nto* | *qnx*)
       ;;
 
-    openbsd* | bitrig*)
+    openbsd*)
       if test -f /usr/libexec/ld.so; then
 	_LT_TAGVAR(hardcode_direct, $1)=yes
 	_LT_TAGVAR(hardcode_shlibpath_var, $1)=no
@@ -5880,7 +6024,7 @@ _LT_EOF
 	cat $export_symbols | $prefix_cmds >> $output_objdir/$libname.def~
 	$CC -Zdll -Zcrtdll -o $output_objdir/$soname $libobjs $deplibs $compiler_flags $output_objdir/$libname.def~
 	emximp -o $lib $output_objdir/$libname.def'
-      _LT_TAGVAR(old_archive_From_new_cmds, $1)='emximp -o $output_objdir/${libname}_dll.a $output_objdir/$libname.def'
+      _LT_TAGVAR(old_archive_from_new_cmds, $1)='emximp -o $output_objdir/${libname}_dll.a $output_objdir/$libname.def'
       _LT_TAGVAR(enable_shared_with_static_runtimes, $1)=yes
       _LT_TAGVAR(file_list_spec, $1)='@'
       ;;
@@ -5916,6 +6060,9 @@ _LT_EOF
       _LT_TAGVAR(hardcode_libdir_separator, $1)=:
       ;;
 
+    serenity*)
+      ;;
+
     solaris*)
       _LT_TAGVAR(no_undefined_flag, $1)=' -z defs'
       if test yes = "$GCC"; then
@@ -6174,7 +6321,7 @@ _LT_TAGDECL([], [hardcode_direct], [0],
 _LT_TAGDECL([], [hardcode_direct_absolute], [0],
     [Set to "yes" if using DIR/libNAME$shared_ext during linking hardcodes
     DIR into the resulting binary and the resulting library dependency is
-    "absolute", i.e impossible to change by setting $shlibpath_var if the
+    "absolute", i.e. impossible to change by setting $shlibpath_var if the
     library is relocated])
 _LT_TAGDECL([], [hardcode_minus_L], [0],
     [Set to "yes" if using the -LDIR flag during linking hardcodes DIR
@@ -6232,7 +6379,7 @@ _LT_TAGVAR(objext, $1)=$objext
 lt_simple_compile_test_code="int some_variable = 0;"
 
 # Code to be used in simple link tests
-lt_simple_link_test_code='int main(){return(0);}'
+lt_simple_link_test_code='int main(void){return(0);}'
 
 _LT_TAG_COMPILER
 # Save the default compiler, since it gets overwritten when the other
@@ -6421,8 +6568,7 @@ if test yes != "$_lt_caught_CXX_error"; then
         wlarc='$wl'
 
         # ancient GNU ld didn't support --whole-archive et. al.
-        if eval "`$CC -print-prog-name=ld` --help 2>&1" |
-	  $GREP 'no-whole-archive' > /dev/null; then
+        if $LD --help 2>&1 | $GREP 'no-whole-archive' > /dev/null; then
           _LT_TAGVAR(whole_archive_flag_spec, $1)=$wlarc'--whole-archive$convenience '$wlarc'--no-whole-archive'
         else
           _LT_TAGVAR(whole_archive_flag_spec, $1)=
@@ -6442,7 +6588,7 @@ if test yes != "$_lt_caught_CXX_error"; then
       # Commands to make compiler produce verbose output that lists
       # what "hidden" libraries, object files and flags are used when
       # linking a shared library.
-      output_verbose_link_cmd='$CC -shared $CFLAGS -v conftest.$objext 2>&1 | $GREP -v "^Configured with:" | $GREP "\-L"'
+      output_verbose_link_cmd='$CC -shared $CFLAGS -v conftest.$objext 2>&1 | $GREP -v "^Configured with:" | $GREP " [[-]]L"'
 
     else
       GXX=no
@@ -6651,7 +6797,7 @@ if test yes != "$_lt_caught_CXX_error"; then
         esac
         ;;
 
-      cygwin* | mingw* | pw32* | cegcc*)
+      cygwin* | mingw* | windows* | pw32* | cegcc*)
 	case $GXX,$cc_basename in
 	,cl* | no,cl* | ,icl* | no,icl*)
 	  # Native MSVC or ICC
@@ -6704,6 +6850,7 @@ if test yes != "$_lt_caught_CXX_error"; then
 	  _LT_TAGVAR(allow_undefined_flag, $1)=unsupported
 	  _LT_TAGVAR(always_export_symbols, $1)=no
 	  _LT_TAGVAR(enable_shared_with_static_runtimes, $1)=yes
+	  _LT_TAGVAR(file_list_spec, $1)='@'
 
 	  if $LD --help 2>&1 | $GREP 'auto-import' > /dev/null; then
 	    _LT_TAGVAR(archive_cmds, $1)='$CC -shared -nostdlib $predep_objects $libobjs $deplibs $postdep_objects $compiler_flags -o $output_objdir/$soname $wl--enable-auto-image-base -Xlinker --out-implib -Xlinker $lib'
@@ -6750,7 +6897,7 @@ if test yes != "$_lt_caught_CXX_error"; then
 	  cat $export_symbols | $prefix_cmds >> $output_objdir/$libname.def~
 	  $CC -Zdll -Zcrtdll -o $output_objdir/$soname $libobjs $deplibs $compiler_flags $output_objdir/$libname.def~
 	  emximp -o $lib $output_objdir/$libname.def'
-	_LT_TAGVAR(old_archive_From_new_cmds, $1)='emximp -o $output_objdir/${libname}_dll.a $output_objdir/$libname.def'
+	_LT_TAGVAR(old_archive_from_new_cmds, $1)='emximp -o $output_objdir/${libname}_dll.a $output_objdir/$libname.def'
 	_LT_TAGVAR(enable_shared_with_static_runtimes, $1)=yes
 	_LT_TAGVAR(file_list_spec, $1)='@'
 	;;
@@ -6791,7 +6938,7 @@ if test yes != "$_lt_caught_CXX_error"; then
 
       haiku*)
         _LT_TAGVAR(archive_cmds, $1)='$CC -shared $libobjs $deplibs $compiler_flags $wl-soname $wl$soname -o $lib'
-        _LT_TAGVAR(link_all_deplibs, $1)=yes
+        _LT_TAGVAR(link_all_deplibs, $1)=no
         ;;
 
       hpux9*)
@@ -6818,7 +6965,7 @@ if test yes != "$_lt_caught_CXX_error"; then
             # explicitly linking system object files so we need to strip them
             # from the output so that they don't get included in the library
             # dependencies.
-            output_verbose_link_cmd='templist=`($CC -b $CFLAGS -v conftest.$objext 2>&1) | $EGREP "\-L"`; list= ; for z in $templist; do case $z in conftest.$objext) list="$list $z";; *.$objext);; *) list="$list $z";;esac; done; func_echo_all "$list"'
+            output_verbose_link_cmd='templist=`($CC -b $CFLAGS -v conftest.$objext 2>&1) | $EGREP "[[-]]L"`; list= ; for z in $templist; do case $z in conftest.$objext) list="$list $z";; *.$objext);; *) list="$list $z";;esac; done; func_echo_all "$list"'
             ;;
           *)
             if test yes = "$GXX"; then
@@ -6883,7 +7030,7 @@ if test yes != "$_lt_caught_CXX_error"; then
 	    # explicitly linking system object files so we need to strip them
 	    # from the output so that they don't get included in the library
 	    # dependencies.
-	    output_verbose_link_cmd='templist=`($CC -b $CFLAGS -v conftest.$objext 2>&1) | $GREP "\-L"`; list= ; for z in $templist; do case $z in conftest.$objext) list="$list $z";; *.$objext);; *) list="$list $z";;esac; done; func_echo_all "$list"'
+	    output_verbose_link_cmd='templist=`($CC -b $CFLAGS -v conftest.$objext 2>&1) | $GREP " [[-]]L"`; list= ; for z in $templist; do case $z in conftest.$objext) list="$list $z";; *.$objext);; *) list="$list $z";;esac; done; func_echo_all "$list"'
 	    ;;
           *)
 	    if test yes = "$GXX"; then
@@ -7115,6 +7262,10 @@ if test yes != "$_lt_caught_CXX_error"; then
 	esac
 	;;
 
+      *-mlibc)
+        _LT_TAGVAR(ld_shlibs, $1)=yes
+	;;
+
       netbsd*)
         if echo __ELF__ | $CC -E - | $GREP __ELF__ >/dev/null; then
 	  _LT_TAGVAR(archive_cmds, $1)='$LD -Bshareable  -o $lib $predep_objects $libobjs $deplibs $postdep_objects $linker_flags'
@@ -7131,7 +7282,7 @@ if test yes != "$_lt_caught_CXX_error"; then
         _LT_TAGVAR(ld_shlibs, $1)=yes
 	;;
 
-      openbsd* | bitrig*)
+      openbsd*)
 	if test -f /usr/libexec/ld.so; then
 	  _LT_TAGVAR(hardcode_direct, $1)=yes
 	  _LT_TAGVAR(hardcode_shlibpath_var, $1)=no
@@ -7222,7 +7373,7 @@ if test yes != "$_lt_caught_CXX_error"; then
 	      # Commands to make compiler produce verbose output that lists
 	      # what "hidden" libraries, object files and flags are used when
 	      # linking a shared library.
-	      output_verbose_link_cmd='$CC -shared $CFLAGS -v conftest.$objext 2>&1 | $GREP -v "^Configured with:" | $GREP "\-L"'
+	      output_verbose_link_cmd='$CC -shared $CFLAGS -v conftest.$objext 2>&1 | $GREP -v "^Configured with:" | $GREP " [[-]]L"'
 
 	    else
 	      # FIXME: insert proper C++ library support
@@ -7237,6 +7388,9 @@ if test yes != "$_lt_caught_CXX_error"; then
         _LT_TAGVAR(ld_shlibs, $1)=no
         ;;
 
+      serenity*)
+        ;;
+
       sunos4*)
         case $cc_basename in
           CC*)
@@ -7306,7 +7460,7 @@ if test yes != "$_lt_caught_CXX_error"; then
 	        # Commands to make compiler produce verbose output that lists
 	        # what "hidden" libraries, object files and flags are used when
 	        # linking a shared library.
-	        output_verbose_link_cmd='$CC -shared $CFLAGS -v conftest.$objext 2>&1 | $GREP -v "^Configured with:" | $GREP "\-L"'
+	        output_verbose_link_cmd='$CC -shared $CFLAGS -v conftest.$objext 2>&1 | $GREP -v "^Configured with:" | $GREP " [[-]]L"'
 	      else
 	        # g++ 2.7 appears to require '-G' NOT '-shared' on this
 	        # platform.
@@ -7317,7 +7471,7 @@ if test yes != "$_lt_caught_CXX_error"; then
 	        # Commands to make compiler produce verbose output that lists
 	        # what "hidden" libraries, object files and flags are used when
 	        # linking a shared library.
-	        output_verbose_link_cmd='$CC -G $CFLAGS -v conftest.$objext 2>&1 | $GREP -v "^Configured with:" | $GREP "\-L"'
+	        output_verbose_link_cmd='$CC -G $CFLAGS -v conftest.$objext 2>&1 | $GREP -v "^Configured with:" | $GREP " [[-]]L"'
 	      fi
 
 	      _LT_TAGVAR(hardcode_libdir_flag_spec, $1)='$wl-R $wl$libdir'
@@ -7555,10 +7709,11 @@ if AC_TRY_EVAL(ac_compile); then
     case $prev$p in
 
     -L* | -R* | -l*)
-       # Some compilers place space between "-{L,R}" and the path.
+       # Some compilers place space between "-{L,R,l}" and the path.
        # Remove the space.
-       if test x-L = "$p" ||
-          test x-R = "$p"; then
+       if test x-L = x"$p" ||
+          test x-R = x"$p" ||
+          test x-l = x"$p"; then
 	 prev=$p
 	 continue
        fi
@@ -8216,7 +8371,7 @@ AC_SUBST([DLLTOOL])
 # ----------------
 # Check for a file(cmd) program that can be used to detect file type and magic
 m4_defun([_LT_DECL_FILECMD],
-[AC_CHECK_TOOL([FILECMD], [file], [:])
+[AC_CHECK_PROG([FILECMD], [file], [file], [:])
 _LT_DECL([], [FILECMD], [1], [A file(cmd) program that detects file types])
 ])# _LD_DECL_FILECMD
 
@@ -8232,73 +8387,6 @@ _LT_DECL([], [SED], [1], [A sed program that does not truncate output])
 _LT_DECL([], [Xsed], ["\$SED -e 1s/^X//"],
     [Sed that helps us avoid accidentally triggering echo(1) options like -n])
 ])# _LT_DECL_SED
-
-m4_ifndef([AC_PROG_SED], [
-############################################################
-# NOTE: This macro has been submitted for inclusion into   #
-#  GNU Autoconf as AC_PROG_SED.  When it is available in   #
-#  a released version of Autoconf we should remove this    #
-#  macro and use it instead.                               #
-############################################################
-
-m4_defun([AC_PROG_SED],
-[AC_MSG_CHECKING([for a sed that does not truncate output])
-AC_CACHE_VAL(lt_cv_path_SED,
-[# Loop through the user's path and test for sed and gsed.
-# Then use that list of sed's as ones to test for truncation.
-as_save_IFS=$IFS; IFS=$PATH_SEPARATOR
-for as_dir in $PATH
-do
-  IFS=$as_save_IFS
-  test -z "$as_dir" && as_dir=.
-  for lt_ac_prog in sed gsed; do
-    for ac_exec_ext in '' $ac_executable_extensions; do
-      if $as_executable_p "$as_dir/$lt_ac_prog$ac_exec_ext"; then
-        lt_ac_sed_list="$lt_ac_sed_list $as_dir/$lt_ac_prog$ac_exec_ext"
-      fi
-    done
-  done
-done
-IFS=$as_save_IFS
-lt_ac_max=0
-lt_ac_count=0
-# Add /usr/xpg4/bin/sed as it is typically found on Solaris
-# along with /bin/sed that truncates output.
-for lt_ac_sed in $lt_ac_sed_list /usr/xpg4/bin/sed; do
-  test ! -f "$lt_ac_sed" && continue
-  cat /dev/null > conftest.in
-  lt_ac_count=0
-  echo $ECHO_N "0123456789$ECHO_C" >conftest.in
-  # Check for GNU sed and select it if it is found.
-  if "$lt_ac_sed" --version 2>&1 < /dev/null | grep 'GNU' > /dev/null; then
-    lt_cv_path_SED=$lt_ac_sed
-    break
-  fi
-  while true; do
-    cat conftest.in conftest.in >conftest.tmp
-    mv conftest.tmp conftest.in
-    cp conftest.in conftest.nl
-    echo >>conftest.nl
-    $lt_ac_sed -e 's/a$//' < conftest.nl >conftest.out || break
-    cmp -s conftest.out conftest.nl || break
-    # 10000 chars as input seems more than enough
-    test 10 -lt "$lt_ac_count" && break
-    lt_ac_count=`expr $lt_ac_count + 1`
-    if test "$lt_ac_count" -gt "$lt_ac_max"; then
-      lt_ac_max=$lt_ac_count
-      lt_cv_path_SED=$lt_ac_sed
-    fi
-  done
-done
-])
-SED=$lt_cv_path_SED
-AC_SUBST([SED])
-AC_MSG_RESULT([$SED])
-])#AC_PROG_SED
-])#m4_ifndef
-
-# Old name:
-AU_ALIAS([LT_AC_PROG_SED], [AC_PROG_SED])
 dnl aclocal-1.4 backwards compatibility:
 dnl AC_DEFUN([LT_AC_PROG_SED], [])
 
@@ -8345,7 +8433,7 @@ AC_CACHE_VAL(lt_cv_to_host_file_cmd,
 [case $host in
   *-*-mingw* )
     case $build in
-      *-*-mingw* ) # actually msys
+      *-*-mingw* | *-*-windows* ) # actually msys
         lt_cv_to_host_file_cmd=func_convert_file_msys_to_w32
         ;;
       *-*-cygwin* )
@@ -8358,7 +8446,7 @@ AC_CACHE_VAL(lt_cv_to_host_file_cmd,
     ;;
   *-*-cygwin* )
     case $build in
-      *-*-mingw* ) # actually msys
+      *-*-mingw* | *-*-windows* ) # actually msys
         lt_cv_to_host_file_cmd=func_convert_file_msys_to_cygwin
         ;;
       *-*-cygwin* )
@@ -8384,9 +8472,9 @@ AC_CACHE_VAL(lt_cv_to_tool_file_cmd,
 [#assume ordinary cross tools, or native build.
 lt_cv_to_tool_file_cmd=func_convert_file_noop
 case $host in
-  *-*-mingw* )
+  *-*-mingw* | *-*-windows* )
     case $build in
-      *-*-mingw* ) # actually msys
+      *-*-mingw* | *-*-windows* ) # actually msys
         lt_cv_to_tool_file_cmd=func_convert_file_msys_to_w32
         ;;
     esac
diff --git a/scripts/autoconf/ltoptions.m4 b/scripts/autoconf/ltoptions.m4
index b0b5e9c21..25caa8902 100644
--- a/scripts/autoconf/ltoptions.m4
+++ b/scripts/autoconf/ltoptions.m4
@@ -1,6 +1,6 @@
 # Helper functions for option handling.                    -*- Autoconf -*-
 #
-#   Copyright (C) 2004-2005, 2007-2009, 2011-2019, 2021-2022 Free
+#   Copyright (C) 2004-2005, 2007-2009, 2011-2019, 2021-2024 Free
 #   Software Foundation, Inc.
 #   Written by Gary V. Vaughan, 2004
 #
@@ -8,7 +8,7 @@
 # unlimited permission to copy and/or distribute it, with or without
 # modifications, as long as this notice is preserved.
 
-# serial 8 ltoptions.m4
+# serial 10 ltoptions.m4
 
 # This is to help aclocal find these macros, as it can't see m4_define.
 AC_DEFUN([LTOPTIONS_VERSION], [m4_if([1])])
@@ -128,7 +128,7 @@ LT_OPTION_DEFINE([LT_INIT], [win32-dll],
 [enable_win32_dll=yes
 
 case $host in
-*-*-cygwin* | *-*-mingw* | *-*-pw32* | *-*-cegcc*)
+*-*-cygwin* | *-*-mingw* | *-*-windows* | *-*-pw32* | *-*-cegcc*)
   AC_CHECK_TOOL(AS, as, false)
   AC_CHECK_TOOL(DLLTOOL, dlltool, false)
   AC_CHECK_TOOL(OBJDUMP, objdump, false)
@@ -323,29 +323,39 @@ dnl AC_DEFUN([AM_DISABLE_FAST_INSTALL], [])
 
 # _LT_WITH_AIX_SONAME([DEFAULT])
 # ----------------------------------
-# implement the --with-aix-soname flag, and support the `aix-soname=aix'
-# and `aix-soname=both' and `aix-soname=svr4' LT_INIT options. DEFAULT
-# is either `aix', `both' or `svr4'.  If omitted, it defaults to `aix'.
+# implement the --enable-aix-soname configure option, and support the
+# `aix-soname=aix' and `aix-soname=both' and `aix-soname=svr4' LT_INIT options.
+# DEFAULT is either `aix', `both', or `svr4'.  If omitted, it defaults to `aix'.
 m4_define([_LT_WITH_AIX_SONAME],
 [m4_define([_LT_WITH_AIX_SONAME_DEFAULT], [m4_if($1, svr4, svr4, m4_if($1, both, both, aix))])dnl
 shared_archive_member_spec=
 case $host,$enable_shared in
 power*-*-aix[[5-9]]*,yes)
   AC_MSG_CHECKING([which variant of shared library versioning to provide])
-  AC_ARG_WITH([aix-soname],
-    [AS_HELP_STRING([--with-aix-soname=aix|svr4|both],
+  AC_ARG_ENABLE([aix-soname],
+    [AS_HELP_STRING([--enable-aix-soname=aix|svr4|both],
       [shared library versioning (aka "SONAME") variant to provide on AIX, @<:@default=]_LT_WITH_AIX_SONAME_DEFAULT[@:>@.])],
-    [case $withval in
-    aix|svr4|both)
-      ;;
-    *)
-      AC_MSG_ERROR([Unknown argument to --with-aix-soname])
-      ;;
-    esac
-    lt_cv_with_aix_soname=$with_aix_soname],
-    [AC_CACHE_VAL([lt_cv_with_aix_soname],
-      [lt_cv_with_aix_soname=]_LT_WITH_AIX_SONAME_DEFAULT)
-    with_aix_soname=$lt_cv_with_aix_soname])
+    [case $enableval in
+     aix|svr4|both)
+       ;;
+     *)
+       AC_MSG_ERROR([Unknown argument to --enable-aix-soname])
+       ;;
+     esac
+     lt_cv_with_aix_soname=$enable_aix_soname],
+    [_AC_ENABLE_IF([with], [aix-soname],
+        [case $withval in
+         aix|svr4|both)
+           ;;
+         *)
+           AC_MSG_ERROR([Unknown argument to --with-aix-soname])
+           ;;
+         esac
+         lt_cv_with_aix_soname=$with_aix_soname],
+        [AC_CACHE_VAL([lt_cv_with_aix_soname],
+           [lt_cv_with_aix_soname=]_LT_WITH_AIX_SONAME_DEFAULT)])
+     enable_aix_soname=$lt_cv_with_aix_soname])
+  with_aix_soname=$enable_aix_soname
   AC_MSG_RESULT([$with_aix_soname])
   if test aix != "$with_aix_soname"; then
     # For the AIX way of multilib, we name the shared archive member
@@ -376,30 +386,50 @@ LT_OPTION_DEFINE([LT_INIT], [aix-soname=svr4], [_LT_WITH_AIX_SONAME([svr4])])
 
 # _LT_WITH_PIC([MODE])
 # --------------------
-# implement the --with-pic flag, and support the 'pic-only' and 'no-pic'
+# implement the --enable-pic flag, and support the 'pic-only' and 'no-pic'
 # LT_INIT options.
 # MODE is either 'yes' or 'no'.  If omitted, it defaults to 'both'.
 m4_define([_LT_WITH_PIC],
-[AC_ARG_WITH([pic],
-    [AS_HELP_STRING([--with-pic@<:@=PKGS@:>@],
+[AC_ARG_ENABLE([pic],
+    [AS_HELP_STRING([--enable-pic@<:@=PKGS@:>@],
 	[try to use only PIC/non-PIC objects @<:@default=use both@:>@])],
     [lt_p=${PACKAGE-default}
-    case $withval in
-    yes|no) pic_mode=$withval ;;
-    *)
-      pic_mode=default
-      # Look at the argument we got.  We use all the common list separators.
-      lt_save_ifs=$IFS; IFS=$IFS$PATH_SEPARATOR,
-      for lt_pkg in $withval; do
-	IFS=$lt_save_ifs
-	if test "X$lt_pkg" = "X$lt_p"; then
-	  pic_mode=yes
-	fi
-      done
-      IFS=$lt_save_ifs
-      ;;
-    esac],
-    [pic_mode=m4_default([$1], [default])])
+     case $enableval in
+     yes|no) pic_mode=$enableval ;;
+     *)
+       pic_mode=default
+       # Look at the argument we got.  We use all the common list separators.
+       lt_save_ifs=$IFS; IFS=$IFS$PATH_SEPARATOR,
+       for lt_pkg in $enableval; do
+	 IFS=$lt_save_ifs
+	 if test "X$lt_pkg" = "X$lt_p"; then
+	   pic_mode=yes
+	 fi
+       done
+       IFS=$lt_save_ifs
+       ;;
+     esac],
+    [dnl Continue to support --with-pic and --without-pic, for backward
+     dnl compatibility.
+     _AC_ENABLE_IF([with], [pic],
+	[lt_p=${PACKAGE-default}
+	 case $withval in
+	 yes|no) pic_mode=$withval ;;
+	 *)
+	   pic_mode=default
+	   # Look at the argument we got.  We use all the common list separators.
+	   lt_save_ifs=$IFS; IFS=$IFS$PATH_SEPARATOR,
+	   for lt_pkg in $withval; do
+	     IFS=$lt_save_ifs
+	     if test "X$lt_pkg" = "X$lt_p"; then
+	       pic_mode=yes
+	     fi
+	   done
+	   IFS=$lt_save_ifs
+	   ;;
+	 esac],
+	[pic_mode=m4_default([$1], [default])])]
+    )
 
 _LT_DECL([], [pic_mode], [0], [What type of objects to build])dnl
 ])# _LT_WITH_PIC
diff --git a/scripts/autoconf/ltsugar.m4 b/scripts/autoconf/ltsugar.m4
index 902508bd9..5b5c80a3a 100644
--- a/scripts/autoconf/ltsugar.m4
+++ b/scripts/autoconf/ltsugar.m4
@@ -1,6 +1,6 @@
 # ltsugar.m4 -- libtool m4 base layer.                         -*-Autoconf-*-
 #
-# Copyright (C) 2004-2005, 2007-2008, 2011-2019, 2021-2022 Free Software
+# Copyright (C) 2004-2005, 2007-2008, 2011-2019, 2021-2024 Free Software
 # Foundation, Inc.
 # Written by Gary V. Vaughan, 2004
 #
diff --git a/scripts/autoconf/ltversion.m4 b/scripts/autoconf/ltversion.m4
index b155d0ace..228df3f39 100644
--- a/scripts/autoconf/ltversion.m4
+++ b/scripts/autoconf/ltversion.m4
@@ -1,6 +1,6 @@
 # ltversion.m4 -- version numbers			-*- Autoconf -*-
 #
-#   Copyright (C) 2004, 2011-2019, 2021-2022 Free Software Foundation,
+#   Copyright (C) 2004, 2011-2019, 2021-2024 Free Software Foundation,
 #   Inc.
 #   Written by Scott James Remnant, 2004
 #
@@ -10,15 +10,15 @@
 
 # @configure_input@
 
-# serial 4245 ltversion.m4
+# serial 4441 ltversion.m4
 # This file is part of GNU Libtool
 
-m4_define([LT_PACKAGE_VERSION], [2.4.7])
-m4_define([LT_PACKAGE_REVISION], [2.4.7])
+m4_define([LT_PACKAGE_VERSION], [2.5.4])
+m4_define([LT_PACKAGE_REVISION], [2.5.4])
 
 AC_DEFUN([LTVERSION_VERSION],
-[macro_version='2.4.7'
-macro_revision='2.4.7'
+[macro_version='2.5.4'
+macro_revision='2.5.4'
 _LT_DECL(, macro_version, 0, [Which release of libtool.m4 was used?])
 _LT_DECL(, macro_revision, 0)
 ])
diff --git a/scripts/autoconf/lt~obsolete.m4 b/scripts/autoconf/lt~obsolete.m4
index 0f7a8759d..22b534697 100644
--- a/scripts/autoconf/lt~obsolete.m4
+++ b/scripts/autoconf/lt~obsolete.m4
@@ -1,6 +1,6 @@
 # lt~obsolete.m4 -- aclocal satisfying obsolete definitions.    -*-Autoconf-*-
 #
-#   Copyright (C) 2004-2005, 2007, 2009, 2011-2019, 2021-2022 Free
+#   Copyright (C) 2004-2005, 2007, 2009, 2011-2019, 2021-2024 Free
 #   Software Foundation, Inc.
 #   Written by Scott James Remnant, 2004.
 #
diff --git a/scripts/cmake/PNGConfig.cmake b/scripts/cmake/PNGConfig.cmake
index 3b6f646de..b569d4502 100644
--- a/scripts/cmake/PNGConfig.cmake
+++ b/scripts/cmake/PNGConfig.cmake
@@ -1,15 +1,28 @@
-include(CMakeFindDependencyMacro)
-
-find_dependency(ZLIB REQUIRED)
-
-include("${CMAKE_CURRENT_LIST_DIR}/PNGTargets.cmake")
-
-if(NOT TARGET PNG::PNG)
-  if(TARGET PNG::png_shared)
-    add_library(PNG::PNG INTERFACE IMPORTED)
-    target_link_libraries(PNG::PNG INTERFACE PNG::png_shared)
-  elseif(TARGET PNG::png_static)
-    add_library(PNG::PNG INTERFACE IMPORTED)
-    target_link_libraries(PNG::PNG INTERFACE PNG::png_static)
-  endif()
-endif()
+# PNGConfig.cmake
+# CMake config file compatible with the FindPNG module.
+
+# Copyright (c) 2024 Cosmin Truta
+# Written by Benjamin Buch, 2024
+#
+# Use, modification and distribution are subject to
+# the same licensing terms and conditions as libpng.
+# Please see the copyright notice in png.h or visit
+# http://libpng.org/pub/png/src/libpng-LICENSE.txt
+#
+# SPDX-License-Identifier: libpng-2.0
+
+include(CMakeFindDependencyMacro)
+
+find_dependency(ZLIB REQUIRED)
+
+include("${CMAKE_CURRENT_LIST_DIR}/PNGTargets.cmake")
+
+if(NOT TARGET PNG::PNG)
+  if(TARGET PNG::png_shared)
+    add_library(PNG::PNG INTERFACE IMPORTED)
+    target_link_libraries(PNG::PNG INTERFACE PNG::png_shared)
+  elseif(TARGET PNG::png_static)
+    add_library(PNG::PNG INTERFACE IMPORTED)
+    target_link_libraries(PNG::PNG INTERFACE PNG::png_static)
+  endif()
+endif()
diff --git a/scripts/cmake/PNGGenConfig.cmake b/scripts/cmake/PNGGenConfig.cmake
new file mode 100644
index 000000000..4a0030edd
--- /dev/null
+++ b/scripts/cmake/PNGGenConfig.cmake
@@ -0,0 +1,104 @@
+# PNGGenConfig.cmake
+# Utility functions for configuring and building libpng
+
+# Copyright (c) 2018-2025 Cosmin Truta
+# Copyright (c) 2016-2018 Glenn Randers-Pehrson
+# Written by Roger Leigh, 2016
+#
+# Use, modification and distribution are subject to
+# the same licensing terms and conditions as libpng.
+# Please see the copyright notice in png.h or visit
+# http://libpng.org/pub/png/src/libpng-LICENSE.txt
+#
+# SPDX-License-Identifier: libpng-2.0
+
+# Generate .chk from .out with awk, based upon the automake logic:
+# generate_chk(INPUT <file> OUTPUT <file> [DEPENDS <deps>...])
+function(generate_chk)
+  set(options)
+  set(oneValueArgs INPUT OUTPUT)
+  set(multiValueArgs DEPENDS)
+  cmake_parse_arguments(_GC "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
+  if(NOT _GC_INPUT)
+    message(FATAL_ERROR "generate_chk: Missing INPUT argument")
+  endif()
+  if(NOT _GC_OUTPUT)
+    message(FATAL_ERROR "generate_chk: Missing OUTPUT argument")
+  endif()
+
+  # Run genchk.cmake to generate the .chk file.
+  add_custom_command(OUTPUT "${_GC_OUTPUT}"
+                     COMMAND "${CMAKE_COMMAND}"
+                             "-DINPUT=${_GC_INPUT}"
+                             "-DOUTPUT=${_GC_OUTPUT}"
+                             -P "${CMAKE_CURRENT_BINARY_DIR}/scripts/cmake/genchk.cmake"
+                     DEPENDS "${_GC_INPUT}" ${_GC_DEPENDS}
+                     WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
+endfunction()
+
+# Generate .out from C source file with awk:
+# generate_out(INPUT <file> OUTPUT <file> [DEPENDS <deps>...])
+function(generate_out)
+  set(options)
+  set(oneValueArgs INPUT OUTPUT)
+  set(multiValueArgs DEPENDS)
+  cmake_parse_arguments(_GO "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
+  if(NOT _GO_INPUT)
+    message(FATAL_ERROR "generate_out: Missing INPUT argument")
+  endif()
+  if(NOT _GO_OUTPUT)
+    message(FATAL_ERROR "generate_out: Missing OUTPUT argument")
+  endif()
+
+  # Run genout.cmake to generate the .out file.
+  add_custom_command(OUTPUT "${_GO_OUTPUT}"
+                     COMMAND "${CMAKE_COMMAND}"
+                             "-DINPUT=${_GO_INPUT}"
+                             "-DOUTPUT=${_GO_OUTPUT}"
+                             -P "${CMAKE_CURRENT_BINARY_DIR}/scripts/cmake/genout.cmake"
+                     DEPENDS "${_GO_INPUT}" ${_GO_DEPENDS}
+                     WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
+endfunction()
+
+# Generate a source file with awk:
+# generate_source(OUTPUT <file> [DEPENDS <deps>...])
+function(generate_source)
+  set(options)
+  set(oneValueArgs OUTPUT)
+  set(multiValueArgs DEPENDS)
+  cmake_parse_arguments(_GSO "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
+  if(NOT _GSO_OUTPUT)
+    message(FATAL_ERROR "generate_source: Missing OUTPUT argument")
+  endif()
+
+  # Run gensrc.cmake to generate the source file.
+  add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${_GSO_OUTPUT}"
+                     COMMAND "${CMAKE_COMMAND}"
+                             "-DOUTPUT=${_GSO_OUTPUT}"
+                             -P "${CMAKE_CURRENT_BINARY_DIR}/scripts/cmake/gensrc.cmake"
+                     DEPENDS ${_GSO_DEPENDS}
+                     WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
+endfunction()
+
+# Generate an identical file copy:
+# generate_copy(INPUT <file> OUTPUT <file> [DEPENDS <deps>...])
+function(generate_copy)
+  set(options)
+  set(oneValueArgs INPUT OUTPUT)
+  set(multiValueArgs DEPENDS)
+  cmake_parse_arguments(_GCO "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
+  if(NOT _GCO_INPUT)
+    message(FATAL_ERROR "generate_copy: Missing INPUT argument")
+  endif()
+  if(NOT _GCO_OUTPUT)
+    message(FATAL_ERROR "generate_copy: Missing OUTPUT argument")
+  endif()
+
+  # Make a forced file copy, overwriting any pre-existing output file.
+  add_custom_command(OUTPUT "${_GCO_OUTPUT}"
+                     COMMAND "${CMAKE_COMMAND}"
+                             -E remove "${_GCO_OUTPUT}"
+                     COMMAND "${CMAKE_COMMAND}"
+                             -E copy "${_GCO_INPUT}" "${_GCO_OUTPUT}"
+                     DEPENDS "${source}" ${_GCO_DEPENDS})
+endfunction()
diff --git a/scripts/cmake/PNGTest.cmake b/scripts/cmake/PNGTest.cmake
new file mode 100644
index 000000000..184773bc0
--- /dev/null
+++ b/scripts/cmake/PNGTest.cmake
@@ -0,0 +1,42 @@
+# PNGTest.cmake
+# Utility functions for testing libpng
+
+# Copyright (c) 2018-2025 Cosmin Truta
+# Copyright (c) 2016-2018 Glenn Randers-Pehrson
+# Written by Roger Leigh, 2016
+#
+# Use, modification and distribution are subject to
+# the same licensing terms and conditions as libpng.
+# Please see the copyright notice in png.h or visit
+# http://libpng.org/pub/png/src/libpng-LICENSE.txt
+#
+# SPDX-License-Identifier: libpng-2.0
+
+# Add a custom target to run a test:
+# png_add_test(NAME <test> COMMAND <command> [OPTIONS <options>...] [FILES <files>...])
+function(png_add_test)
+  set(options)
+  set(oneValueArgs NAME COMMAND)
+  set(multiValueArgs OPTIONS FILES)
+  cmake_parse_arguments(_PAT "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
+  if(NOT _PAT_NAME)
+    message(FATAL_ERROR "png_add_test: Missing NAME argument")
+  endif()
+  if(NOT _PAT_COMMAND)
+    message(FATAL_ERROR "png_add_test: Missing COMMAND argument")
+  endif()
+
+  # Initialize the global variables used by the "${_PAT_NAME}.cmake" script.
+  set(TEST_OPTIONS "${_PAT_OPTIONS}")
+  set(TEST_FILES "${_PAT_FILES}")
+
+  # Generate and run the "${_PAT_NAME}.cmake" script.
+  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake/test.cmake.in"
+                 "${CMAKE_CURRENT_BINARY_DIR}/tests/${_PAT_NAME}.cmake"
+                 @ONLY)
+  add_test(NAME "${_PAT_NAME}"
+           COMMAND "${CMAKE_COMMAND}"
+                   "-DLIBPNG=$<TARGET_FILE:png_shared>"
+                   "-DTEST_COMMAND=$<TARGET_FILE:${_PAT_COMMAND}>"
+                   -P "${CMAKE_CURRENT_BINARY_DIR}/tests/${_PAT_NAME}.cmake")
+endfunction()
diff --git a/scripts/cmake/test.cmake.in b/scripts/cmake/test.cmake.in
index a1cd30f55..b578da926 100644
--- a/scripts/cmake/test.cmake.in
+++ b/scripts/cmake/test.cmake.in
@@ -26,7 +26,8 @@ if(WIN32)
   set(ENV{PATH} "${LIBPNG_DIR};$ENV{PATH}")
 endif()
 
-message("Running ${TEST_COMMAND}" ${TEST_OPTIONS} ${NATIVE_TEST_FILES})
+string(JOIN " " TEST_COMMAND_STRING "${TEST_COMMAND}" ${TEST_OPTIONS} ${NATIVE_TEST_FILES})
+message(STATUS "Running ${TEST_COMMAND_STRING}")
 execute_process(COMMAND "${TEST_COMMAND}" ${TEST_OPTIONS} ${NATIVE_TEST_FILES}
                 RESULT_VARIABLE TEST_STATUS)
 if(TEST_STATUS)
diff --git a/scripts/descrip.mms b/scripts/descrip.mms
index c440fc350..f0d0b4896 100644
--- a/scripts/descrip.mms
+++ b/scripts/descrip.mms
@@ -1,4 +1,3 @@
-
 cc_defs = /inc=$(ZLIBSRC)
 c_deb =
 
diff --git a/scripts/intprefix.c b/scripts/intprefix.c
index 4085e5401..3c9dc57a5 100644
--- a/scripts/intprefix.c
+++ b/scripts/intprefix.c
@@ -1,4 +1,3 @@
-
 /* intprefix.c - generate an unprefixed internal symbol list
  *
  * Copyright (c) 2013-2014 Glenn Randers-Pehrson
diff --git a/scripts/libpng-config-body.in b/scripts/libpng-config-body.in
index b466432d5..181984b4b 100644
--- a/scripts/libpng-config-body.in
+++ b/scripts/libpng-config-body.in
@@ -1,4 +1,3 @@
-
 usage()
 {
     cat <<EOF
diff --git a/scripts/libpng-config-head.in b/scripts/libpng-config-head.in
index 3d26a0a6a..12574fcab 100644
--- a/scripts/libpng-config-head.in
+++ b/scripts/libpng-config-head.in
@@ -11,7 +11,7 @@
 
 # Modeled after libxml-config.
 
-version=1.6.44
+version=1.6.47
 prefix=""
 libdir=""
 libs=""
diff --git a/scripts/libpng.pc.in b/scripts/libpng.pc.in
index fc3f6f67f..10e29bfbd 100644
--- a/scripts/libpng.pc.in
+++ b/scripts/libpng.pc.in
@@ -5,6 +5,6 @@ includedir=@includedir@/libpng16
 
 Name: libpng
 Description: Loads and saves PNG files
-Version: 1.6.44
+Version: 1.6.47
 Libs: -L${libdir} -lpng16
 Cflags: -I${includedir}
diff --git a/scripts/makefile.32sunu b/scripts/makefile.32sunu
index 822e8a923..2dd8877ed 100644
--- a/scripts/makefile.32sunu
+++ b/scripts/makefile.32sunu
@@ -1,6 +1,6 @@
 # makefile for libpng on Solaris 2.x with cc
 # Contributed by William L. Sebok, based on makefile.linux
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2002, 2006, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 1998 Greg Roelofs
 # Copyright (C) 1996, 1997 Andreas Dilger
@@ -36,13 +36,10 @@ SUN_LD_FLAGS=-fast -xtarget=ultra
 ZLIBLIB=/usr/lib
 ZLIBINC=/usr/include
 
-WARNMORE=-Wwrite-strings -Wpointer-arith -Wshadow \
-	-Wmissing-declarations -Wtraditional -Wcast-align \
-	-Wstrict-prototypes -Wmissing-prototypes # -Wconversion
 CPPFLAGS=-I$(ZLIBINC) # -DPNG_DEBUG=5
-CFLAGS=$(SUN_CC_FLAGS) # $(WARNMORE) -g
+CFLAGS=$(SUN_CC_FLAGS) # -g
 ARFLAGS=rc
-LDFLAGS=$(SUN_LD_FLAGS) -L$(ZLIBLIB) -R$(ZLIBLIB) libpng.a -lz -lm
+LDFLAGS=$(SUN_LD_FLAGS) -L$(ZLIBLIB) -R$(ZLIBLIB) libpng.a -lz -lm # -g
 
 OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
        pngread.o pngrio.o pngrtran.o pngrutil.o pngset.o \
@@ -53,7 +50,7 @@ OBJSDLL = $(OBJS:.o=.pic.o)
 .SUFFIXES:      .c .o .pic.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 .c.pic.o:
 	$(CC) -c $(CPPFLAGS) $(CFLAGS) -KPIC -o $@ $*.c
diff --git a/scripts/makefile.64sunu b/scripts/makefile.64sunu
index 65414b6b5..932db0230 100644
--- a/scripts/makefile.64sunu
+++ b/scripts/makefile.64sunu
@@ -1,6 +1,6 @@
 # makefile for libpng on Solaris 2.x with cc
 # Contributed by William L. Sebok, based on makefile.linux
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2002, 2006, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 1998 Greg Roelofs
 # Copyright (C) 1996, 1997 Andreas Dilger
@@ -36,13 +36,10 @@ SUN_LD_FLAGS=-fast -xtarget=ultra -xarch=v9
 ZLIBLIB=/usr/lib
 ZLIBINC=/usr/include
 
-WARNMORE=-Wwrite-strings -Wpointer-arith -Wshadow \
-	-Wmissing-declarations -Wtraditional -Wcast-align \
-	-Wstrict-prototypes -Wmissing-prototypes # -Wconversion
 CPPFLAGS=-I$(ZLIBINC) # -DPNG_DEBUG=5
-CFLAGS=$(SUN_CC_FLAGS) # $(WARNMORE) -g
+CFLAGS=$(SUN_CC_FLAGS) # -g
 ARFLAGS=rc
-LDFLAGS=-L. -R. $(SUN_LD_FLAGS) -L$(ZLIBLIB) -R$(ZLIBLIB) -lpng16 -lz -lm
+LDFLAGS=-L. -R. $(SUN_LD_FLAGS) -L$(ZLIBLIB) -R$(ZLIBLIB) -lpng16 -lz -lm # -g
 
 OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
        pngread.o pngrio.o pngrtran.o pngrutil.o pngset.o \
@@ -53,7 +50,7 @@ OBJSDLL = $(OBJS:.o=.pic.o)
 .SUFFIXES:      .c .o .pic.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 .c.pic.o:
 	$(CC) -c $(CPPFLAGS) $(CFLAGS) -KPIC -o $@ $*.c
diff --git a/scripts/makefile.aix b/scripts/makefile.aix
index 5b24f54fc..98228693d 100644
--- a/scripts/makefile.aix
+++ b/scripts/makefile.aix
@@ -1,5 +1,5 @@
 # makefile for libpng using gcc (generic, static library)
-# Copyright (C) 2000, 2020-2024 Cosmin Truta
+# Copyright (C) 2000, 2020-2025 Cosmin Truta
 # Copyright (C) 2002, 2006-2009, 2014 Glenn Randers-Pehrson
 # Copyright (C) 2000 Marc O. Gloor (AIX support added, from makefile.gcc)
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
@@ -22,9 +22,8 @@ RM_F = rm -f
 LIBNAME = libpng16
 PNGMAJ = 16
 
-WARNMORE =
 CPPFLAGS = -I$(ZLIBINC) # -DPNG_DEBUG=5
-CFLAGS = -O2 -Wall -Wextra -Wundef # $(WARNMORE) -g
+CFLAGS = -O2 # -g
 ARFLAGS = rc
 LDFLAGS = -L. -L$(ZLIBLIB) -lpng16 -lz -lm # -g
 
@@ -35,7 +34,7 @@ OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
 
 # Targets
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 all: $(LIBNAME).a pngtest
 
diff --git a/scripts/makefile.atari b/scripts/makefile.atari
index 6ed1f7990..02e137ac3 100644
--- a/scripts/makefile.atari
+++ b/scripts/makefile.atari
@@ -1,5 +1,5 @@
 # makefile for libpng
-# Copyright (C) 2022 Cosmin Truta
+# Copyright (C) 2022-2025 Cosmin Truta
 # Copyright (C) 2002, 2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -28,7 +28,7 @@ OBJS = $(LBR)(png.o) $(LBR)(pngerror.o) $(LBR)(pngget.o) $(LBR)(pngmem.o) \
 all: $(LBR) pngtest.ttp
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) $*.c
 
 $(LBR): $(OBJS)
 
diff --git a/scripts/makefile.beos b/scripts/makefile.beos
index fcc7f9cac..13f79cc2c 100644
--- a/scripts/makefile.beos
+++ b/scripts/makefile.beos
@@ -1,6 +1,6 @@
 # makefile for libpng on BeOS x86 ELF with gcc
 # modified from makefile.linux by Sander Stoks
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2020-2025 Cosmin Truta
 # Copyright (C) 2002, 2006, 2008, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 1999 Greg Roelofs
 # Copyright (C) 1996, 1997 Andreas Dilger
@@ -33,14 +33,10 @@ ALIGN=
 # For i386:
 # ALIGN=-malign-loops=2 -malign-functions=2
 
-WARNMORE=-Wwrite-strings -Wpointer-arith -Wshadow \
-	-Wmissing-declarations -Wtraditional -Wcast-align \
-	-Wstrict-prototypes -Wmissing-prototypes # -Wconversion
-
 # On BeOS, -O1 is actually better than -O3.  This is a known bug but it's
 # still here in R4.5
 CPPFLAGS=-I$(ZLIBINC) # -DPNG_DEBUG=5
-CFLAGS=-O1 -funroll-loops $(ALIGN) -Wall -Wextra -Wundef # $(WARNMORE) -g
+CFLAGS=-O1 -funroll-loops $(ALIGN) # -g
 ARFLAGS=rc
 # LDFLAGS=-L. -Wl,-rpath,. -L$(ZLIBLIB) -Wl,-rpath,$(ZLIBLIB) -lpng -lz
 LDFLAGS=-L. -Wl,-soname=$(LIBSOMAJ) -L$(ZLIBLIB) -lz # -g
@@ -58,7 +54,7 @@ OBJSDLL = $(OBJS)
 .SUFFIXES:      .c .o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 all: libpng.a $(LIBSO) pngtest
 
diff --git a/scripts/makefile.c89 b/scripts/makefile.c89
new file mode 100644
index 000000000..1f2fc1d61
--- /dev/null
+++ b/scripts/makefile.c89
@@ -0,0 +1,97 @@
+# makefile for libpng using an ANSI C89 compiler
+# Copyright (C) 2000, 2014, 2019-2025 Cosmin Truta
+# Copyright (C) 2008, 2014 Glenn Randers-Pehrson
+# Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
+#
+# This code is released under the libpng license.
+# For conditions of distribution and use, see the disclaimer
+# and license in png.h
+
+# Location of the zlib library and include files
+ZLIBINC = ../zlib
+ZLIBLIB = ../zlib
+
+# Compiler, linker, lib and other tools
+#CC = c89
+CC = cc
+LD = $(CC)
+AR = ar
+RANLIB = ranlib
+CP = cp
+RM_F = rm -f
+
+# Compiler and linker flags
+NOHWOPT = -DPNG_ARM_NEON_OPT=0 -DPNG_MIPS_MSA_OPT=0 \
+          -DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
+STDC = -pedantic-errors -std=c89
+WARN = -Wall -Wextra -Wundef
+WARNMORE = -Wcast-align -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings \
+           -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes
+LOCAL_CPPFLAGS = $(NOHWOPT)
+CPPFLAGS = -I$(ZLIBINC) # -DPNG_DEBUG=5
+ALL_CPPFLAGS = $(LOCAL_CPPFLAGS) $(CPPFLAGS)
+LOCAL_CFLAGS = $(STDC) $(WARN) # $(WARNMORE)
+CFLAGS = -O2 # -g
+ALL_CFLAGS = $(LOCAL_CFLAGS) $(CFLAGS)
+ARFLAGS = rc
+LDFLAGS = -L$(ZLIBLIB) # -g
+LIBS = -lz -lm
+
+# File extensions
+EXEEXT =
+
+# Pre-built configuration
+# See scripts/pnglibconf.mak for more options
+PNGLIBCONF_H_PREBUILT = scripts/pnglibconf.h.prebuilt
+
+# File lists
+OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
+       pngread.o pngrio.o pngrtran.o pngrutil.o pngset.o \
+       pngtrans.o pngwio.o pngwrite.o pngwtran.o pngwutil.o
+
+# Targets
+all: static
+
+pnglibconf.h: $(PNGLIBCONF_H_PREBUILT)
+	$(CP) $(PNGLIBCONF_H_PREBUILT) $@
+
+.c.o:
+	$(CC) -c $(ALL_CPPFLAGS) $(ALL_CFLAGS) -o $@ $*.c
+
+static: libpng.a pngtest$(EXEEXT)
+
+shared:
+	@echo This is a generic makefile that cannot create shared libraries.
+	@echo Please use a configuration that is specific to your platform.
+	@false
+
+libpng.a: $(OBJS)
+	$(AR) $(ARFLAGS) $@ $(OBJS)
+	$(RANLIB) $@
+
+test: pngtest$(EXEEXT)
+	./pngtest$(EXEEXT)
+
+pngtest$(EXEEXT): pngtest.o libpng.a
+	$(LD) $(LDFLAGS) -o $@ pngtest.o libpng.a $(LIBS)
+
+clean:
+	$(RM_F) *.o libpng.a pngtest$(EXEEXT) pngout.png pnglibconf.h
+
+png.o:      png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngerror.o: png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngget.o:   png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngmem.o:   png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngpread.o: png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngread.o:  png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngrio.o:   png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngrtran.o: png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngrutil.o: png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngset.o:   png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngtrans.o: png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngwio.o:   png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngwrite.o: png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngwtran.o: png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+pngwutil.o: png.h pngconf.h pnglibconf.h pngpriv.h pngstruct.h pnginfo.h pngdebug.h
+
+pngtest.o:  png.h pngconf.h pnglibconf.h
diff --git a/scripts/makefile.clang b/scripts/makefile.clang
index 08aaccf85..52eaa1bad 100644
--- a/scripts/makefile.clang
+++ b/scripts/makefile.clang
@@ -1,5 +1,5 @@
 # makefile for libpng using clang (generic, static library)
-# Copyright (C) 2000, 2014, 2019-2024 Cosmin Truta
+# Copyright (C) 2000, 2014, 2019-2025 Cosmin Truta
 # Copyright (C) 2008, 2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -21,13 +21,17 @@ RM_F = rm -f
 
 # Compiler and linker flags
 NOHWOPT = -DPNG_ARM_NEON_OPT=0 -DPNG_MIPS_MSA_OPT=0 \
-	-DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
-WARNMORE = -Wwrite-strings -Wpointer-arith -Wshadow \
-	-Wmissing-declarations -Wtraditional -Wcast-align \
-	-Wstrict-prototypes -Wmissing-prototypes # -Wconversion
-DEFS = $(NOHWOPT)
-CPPFLAGS = -I$(ZLIBINC) $(DEFS) # -DPNG_DEBUG=5
-CFLAGS = -O2 -Wall -Wextra -Wundef # $(WARNMORE) -g
+          -DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
+STDC = -pedantic-errors # -std=c99
+WARN = -Wall -Wextra -Wundef
+WARNMORE = -Wcast-align -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings \
+           -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes
+LOCAL_CPPFLAGS = $(NOHWOPT)
+CPPFLAGS = -I$(ZLIBINC) # -DPNG_DEBUG=5
+ALL_CPPFLAGS = $(LOCAL_CPPFLAGS) $(CPPFLAGS)
+LOCAL_CFLAGS = $(STDC) $(WARN) # $(WARNMORE)
+CFLAGS = -O2 # -g
+ALL_CFLAGS = $(LOCAL_CFLAGS) $(CFLAGS)
 ARFLAGS = rc
 LDFLAGS = -L$(ZLIBLIB) # -g
 LIBS = -lz -lm
@@ -51,7 +55,7 @@ pnglibconf.h: $(PNGLIBCONF_H_PREBUILT)
 	$(CP) $(PNGLIBCONF_H_PREBUILT) $@
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(ALL_CPPFLAGS) $(ALL_CFLAGS) -o $@ $*.c
 
 static: libpng.a pngtest$(EXEEXT)
 
diff --git a/scripts/makefile.darwin b/scripts/makefile.darwin
index e68797e5e..3e42c5c8e 100644
--- a/scripts/makefile.darwin
+++ b/scripts/makefile.darwin
@@ -1,5 +1,5 @@
 # makefile for libpng on Darwin / macOS
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2014, 2018-2025 Cosmin Truta
 # Copyright (C) 2002, 2004, 2006, 2008, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 2001 Christoph Pfisterer
 # derived from makefile.linux:
@@ -10,10 +10,6 @@
 # For conditions of distribution and use, see the disclaimer
 # and license in png.h
 
-# Where the zlib library and include files are located
-ZLIBLIB=/usr/lib
-ZLIBINC=/usr/include
-
 # Library name:
 LIBNAME=libpng16
 PNGMAJ=16
@@ -30,13 +26,22 @@ LN_SF=ln -sf
 CP=cp
 RM_F=rm -f
 
-NOHWOPT=-DPNG_ARM_NEON_OPT=0 -DPNG_MIPS_MSA_OPT=0 \
-        -DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
-DEFS=$(NOHWOPT)
-CPPFLAGS=-I$(ZLIBINC) $(DEFS)
-CFLAGS=-O3 -funroll-loops -Wall -Wextra -Wundef
-ARFLAGS=rc
-LDFLAGS=-L. -L$(ZLIBLIB) -lpng16 -lz
+# Compiler and linker flags
+NOHWOPT = -DPNG_ARM_NEON_OPT=0 -DPNG_MIPS_MSA_OPT=0 \
+          -DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
+STDC = -pedantic-errors
+WARN = -Wall -Wextra -Wundef
+WARNMORE = -Wcast-align -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings \
+           -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes
+LOCAL_CPPFLAGS = $(NOHWOPT)
+CPPFLAGS = # -DPNG_DEBUG=5
+ALL_CPPFLAGS = $(LOCAL_CPPFLAGS) $(CPPFLAGS)
+LOCAL_CFLAGS = $(STDC) $(WARN) # $(WARNMORE)
+CFLAGS = -O3 -funroll-loops # -g
+ALL_CFLAGS = $(LOCAL_CFLAGS) $(CFLAGS)
+ARFLAGS = rc
+LDFLAGS = -L. -lpng16 -lz # -g
+LDFLAGS_A = libpng.a -lz -lm # -g
 
 # Pre-built configuration
 # See scripts/pnglibconf.mak for more options
@@ -52,12 +57,12 @@ OBJSDLL = $(OBJS:.o=.pic.o)
 .SUFFIXES:      .c .o .pic.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(ALL_CPPFLAGS) $(ALL_CFLAGS) -o $@ $*.c
 
 .c.pic.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -fno-common -o $@ $*.c
+	$(CC) -c $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fno-common -o $@ $*.c
 
-all: libpng.a $(LIBSO) pngtest
+all: libpng.a $(LIBSO) pngtest pngtest-static
 
 pnglibconf.h: $(PNGLIBCONF_H_PREBUILT)
 	$(CP) $(PNGLIBCONF_H_PREBUILT) $@
@@ -71,15 +76,25 @@ $(LIBSO): $(LIBSOMAJ)
 
 $(LIBSOMAJ): $(OBJSDLL)
 	$(CC) -dynamiclib \
-	 -current_version 16 -compatibility_version 16 \
-	 -o $(LIBSOMAJ) \
-	 $(OBJSDLL) -L$(ZLIBLIB) -lz
+	      -current_version 16 -compatibility_version 16 \
+	      -o $(LIBSOMAJ) \
+	      $(OBJSDLL) -lz
 
 pngtest: pngtest.o $(LIBSO)
 	$(CC) -o pngtest $(CFLAGS) pngtest.o $(LDFLAGS)
 
-test: pngtest
+pngtest-static: pngtest.o libpng.a
+	$(CC) -o pngtest-static $(CFLAGS) pngtest.o $(LDFLAGS_A)
+
+test: pngtest pngtest-static
+	@echo ""
+	@echo "   Running pngtest dynamically linked with $(LIBSO):"
+	@echo ""
 	./pngtest
+	@echo ""
+	@echo "   Running pngtest statically linked with libpng.a:"
+	@echo ""
+	./pngtest-static
 
 install:
 	@echo "The $@ target is no longer supported by this makefile."
@@ -94,8 +109,9 @@ install-shared:
 	@false
 
 clean:
-	$(RM_F) *.o libpng.a pngtest pngout.png
+	$(RM_F) $(OBJS) $(OBJSDLL) libpng.a
 	$(RM_F) $(LIBNAME).*dylib pnglibconf.h
+	$(RM_F) pngtest*.o pngtest pngtest-static pngout.png
 
 # DO NOT DELETE THIS LINE -- make depend depends on it.
 
diff --git a/scripts/makefile.dec b/scripts/makefile.dec
index 2cca020df..6be1f65a7 100644
--- a/scripts/makefile.dec
+++ b/scripts/makefile.dec
@@ -1,5 +1,5 @@
 # makefile for libpng on DEC Alpha Unix
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2020-2025 Cosmin Truta
 # Copyright (C) 2000-2002, 2006, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -30,7 +30,7 @@ ZLIBLIB=../zlib
 ZLIBINC=../zlib
 
 CPPFLAGS=-I$(ZLIBINC) # -DPNG_DEBUG=5
-CFLAGS=-std -w1 -O # -g
+CFLAGS=-std -w1 -O
 ARFLAGS=rc
 LDFLAGS=-L$(ZLIBLIB) -rpath $(ZLIBLIB) libpng.a -lz -lm
 
@@ -43,7 +43,7 @@ OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
        pngtrans.o pngwio.o pngwrite.o pngwtran.o pngwutil.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 all: $(LIBSO) libpng.a pngtest
 
diff --git a/scripts/makefile.dj2 b/scripts/makefile.dj2
index 376715097..04a12da08 100644
--- a/scripts/makefile.dj2
+++ b/scripts/makefile.dj2
@@ -1,5 +1,5 @@
 # DJGPP (DOS gcc) makefile for libpng
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2020-2025 Cosmin Truta
 # Copyright (C) 2002, 2006, 2009-2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -11,7 +11,7 @@ CC=gcc
 AR=ar
 RANLIB=ranlib
 CPPFLAGS=-I../zlib -DPNG_NO_SNPRINTF
-CFLAGS=-O
+CFLAGS=-O2 -Wall -Wextra -Wundef
 ARFLAGS=rc
 LDFLAGS=-L. -L../zlib/ -lpng -lz -lm
 
@@ -27,7 +27,7 @@ OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
        pngtrans.o pngwio.o pngwrite.o pngwtran.o pngwutil.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 all: libpng.a pngtest
 
diff --git a/scripts/makefile.emcc b/scripts/makefile.emcc
index 1ab01b8db..861b39750 100644
--- a/scripts/makefile.emcc
+++ b/scripts/makefile.emcc
@@ -1,5 +1,5 @@
 # makefile for libpng using emscripten
-# Copyright (C) 2000, 2014, 2019-2024 Cosmin Truta
+# Copyright (C) 2000, 2014, 2019-2025 Cosmin Truta
 # Copyright (C) 2021 Kirk Roerig
 # Copyright (C) 2008, 2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
@@ -20,8 +20,16 @@ RANLIB = emranlib
 CP = cp
 RM_F = rm -f
 
+STDC = -pedantic-errors # -std=c99
+WARN = -Wall -Wextra -Wundef
+WARNMORE = -Wcast-align -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings \
+           -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes
+LOCAL_CPPFLAGS =
 CPPFLAGS = -I$(ZLIBINC) # -DPNG_DEBUG=5
-CFLAGS = -O2 -Wall -Wextra -Wundef
+ALL_CPPFLAGS = $(LOCAL_CPPFLAGS) $(CPPFLAGS)
+LOCAL_CFLAGS = $(STDC) $(WARN) # $(WARNMORE)
+CFLAGS = -O2
+ALL_CFLAGS = $(LOCAL_CFLAGS) $(CFLAGS)
 ARFLAGS = rc
 LDFLAGS = -L$(ZLIBLIB)
 PNGTEST_LDFLAGS = --preload-file=pngtest.png
@@ -43,7 +51,7 @@ pnglibconf.h: $(PNGLIBCONF_H_PREBUILT)
 	$(CP) $(PNGLIBCONF_H_PREBUILT) $@
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(ALL_CPPFLAGS) $(ALL_CFLAGS) -o $@ $*.c
 
 static: libpng.a pngtest
 
diff --git a/scripts/makefile.freebsd b/scripts/makefile.freebsd
index e4e96a14b..20a147dc3 100644
--- a/scripts/makefile.freebsd
+++ b/scripts/makefile.freebsd
@@ -1,5 +1,5 @@
 # makefile for libpng under FreeBSD
-# Copyright (C) 2020-2022 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2014 Glenn Randers-Pehrson and Andrey A. Chernov
 # Copyright (C) 2002, 2007, 2009 Glenn Randers-Pehrson and Andrey A. Chernov
 #
@@ -35,7 +35,7 @@ SRCS=	png.c pngerror.c pngget.c pngmem.c pngpread.c \
 	pngtrans.c pngwio.c pngwrite.c pngwtran.c pngwutil.c
 
 .c.o:
-	${CC} -c ${CPPFLAGS} ${CFLAGS} -o $@ $<
+	${CC} -c ${CPPFLAGS} ${CFLAGS} -o $@ $*.c
 
 pnglibconf.h:	${PNGLIBCONF_H_PREBUILT}
 	cp ${PNGLIBCONF_H_PREBUILT} $@
diff --git a/scripts/makefile.gcc b/scripts/makefile.gcc
index fc0a1a090..7a11744dc 100644
--- a/scripts/makefile.gcc
+++ b/scripts/makefile.gcc
@@ -1,5 +1,5 @@
 # makefile for libpng using gcc (generic, static library)
-# Copyright (C) 2000, 2014, 2019-2024 Cosmin Truta
+# Copyright (C) 2000, 2014, 2019-2025 Cosmin Truta
 # Copyright (C) 2008, 2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -21,13 +21,17 @@ RM_F = rm -f
 
 # Compiler and linker flags
 NOHWOPT = -DPNG_ARM_NEON_OPT=0 -DPNG_MIPS_MSA_OPT=0 \
-	-DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
-WARNMORE = -Wwrite-strings -Wpointer-arith -Wshadow \
-	-Wmissing-declarations -Wtraditional -Wcast-align \
-	-Wstrict-prototypes -Wmissing-prototypes # -Wconversion
-DEFS = $(NOHWOPT)
-CPPFLAGS = -I$(ZLIBINC) $(DEFS) # -DPNG_DEBUG=5
-CFLAGS = -O2 -Wall -Wextra -Wundef # $(WARNMORE) -g
+          -DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
+STDC = -pedantic-errors # -std=c99
+WARN = -Wall -Wextra -Wundef
+WARNMORE = -Wcast-align -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings \
+           -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes
+LOCAL_CPPFLAGS = $(NOHWOPT)
+CPPFLAGS = -I$(ZLIBINC) # -DPNG_DEBUG=5
+ALL_CPPFLAGS = $(LOCAL_CPPFLAGS) $(CPPFLAGS)
+LOCAL_CFLAGS = $(STDC) $(WARN) # $(WARNMORE)
+CFLAGS = -O2 # -g
+ALL_CFLAGS = $(LOCAL_CFLAGS) $(CFLAGS)
 ARFLAGS = rc
 LDFLAGS = -L$(ZLIBLIB) # -g
 LIBS = -lz -lm
@@ -51,7 +55,7 @@ pnglibconf.h: $(PNGLIBCONF_H_PREBUILT)
 	$(CP) $(PNGLIBCONF_H_PREBUILT) $@
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(ALL_CPPFLAGS) $(ALL_CFLAGS) -o $@ $*.c
 
 static: libpng.a pngtest$(EXEEXT)
 
diff --git a/scripts/makefile.hp64 b/scripts/makefile.hp64
index c974d2f33..971aadc8c 100644
--- a/scripts/makefile.hp64
+++ b/scripts/makefile.hp64
@@ -1,5 +1,5 @@
 # makefile for libpng, HPUX (10.20 and 11.00) using the ANSI/C product.
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 1999-2002, 2006, 2009, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42
 # Contributed by Jim Rice and updated by Chris Schleicher, Hewlett Packard
@@ -56,7 +56,7 @@ OBJSDLL = $(OBJS:.o=.pic.o)
 .SUFFIXES:	.c .o .pic.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 .c.pic.o:
 	$(CC) -c $(CPPFLAGS) $(CFLAGS) +z -o $@ $*.c
diff --git a/scripts/makefile.hpgcc b/scripts/makefile.hpgcc
index a24fb9339..1d00491b8 100644
--- a/scripts/makefile.hpgcc
+++ b/scripts/makefile.hpgcc
@@ -1,5 +1,5 @@
 # makefile for libpng on HP-UX using GCC with the HP ANSI/C linker.
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2002, 2006-2008, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 2001, Laurent faillie
 # Copyright (C) 1998, 1999 Greg Roelofs
@@ -37,12 +37,8 @@ ZLIBINC=/opt/zlib/include
 #   LDSHARED=ld -b
 #   SHAREDLIB=libz.sl
 
-WARNMORE=-Wwrite-strings -Wpointer-arith -Wshadow \
-	-Wmissing-declarations -Wtraditional -Wcast-align \
-	-Wstrict-prototypes -Wmissing-prototypes # -Wconversion
-
 CPPFLAGS=-I$(ZLIBINC) # -DPNG_DEBUG=5
-CFLAGS=-O3 -funroll-loops -Wall -Wextra -Wundef # $(WARNMORE) -g
+CFLAGS=-O3 -funroll-loops # -g
 ARFLAGS=rc
 #LDFLAGS=-L. -Wl,-rpath,. -L$(ZLIBLIB) -Wl,-rpath,$(ZLIBLIB) -lpng16 -lz -lm # -g
 LDFLAGS=-L. -L$(ZLIBLIB) -lpng16 -lz -lm # -g
@@ -56,7 +52,7 @@ OBJSDLL = $(OBJS:.o=.pic.o)
 .SUFFIXES:      .c .o .pic.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 .c.pic.o:
 	$(CC) -c $(CPPFLAGS) $(CFLAGS) -fPIC -o $@ $*.c
diff --git a/scripts/makefile.hpux b/scripts/makefile.hpux
index c3950ae3f..59f433437 100644
--- a/scripts/makefile.hpux
+++ b/scripts/makefile.hpux
@@ -1,5 +1,5 @@
 # makefile for libpng, HPUX (10.20 and 11.00) using the ANSI/C product.
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 1999-2002, 2006, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42
 # Contributed by Jim Rice and updated by Chris Schleicher, Hewlett Packard
@@ -55,7 +55,7 @@ OBJSDLL = $(OBJS:.o=.pic.o)
 .SUFFIXES:	.c .o .pic.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 .c.pic.o:
 	$(CC) -c $(CPPFLAGS) $(CFLAGS) +z -o $@ $*.c
diff --git a/scripts/makefile.ibmc b/scripts/makefile.ibmc
index 95cd0d8b7..1bc95222e 100644
--- a/scripts/makefile.ibmc
+++ b/scripts/makefile.ibmc
@@ -1,7 +1,7 @@
 # Makefile for libpng (static)
 # IBM C version 3.x for Win32 and OS/2
 # Copyright (C) 2006, 2014 Glenn Randers-Pehrson
-# Copyright (C) 2000, 2020 Cosmin Truta
+# Copyright (C) 2000, 2020-2025 Cosmin Truta
 #
 # This code is released under the libpng license.
 # For conditions of distribution and use, see the disclaimer
@@ -46,7 +46,7 @@ LIBS = libpng$(A) $(ZLIBLIB)/zlib$(A)
 
 # Targets
 .c$(O):
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) $*.c
 
 all: libpng$(A) pngtest$(E)
 
diff --git a/scripts/makefile.linux b/scripts/makefile.linux
index c49cdde9d..09bbe2481 100644
--- a/scripts/makefile.linux
+++ b/scripts/makefile.linux
@@ -1,5 +1,5 @@
 # makefile for libpng.a and libpng16.so on Linux ELF with gcc
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 1998, 1999, 2002, 2006, 2008, 2010-2014 Greg Roelofs and
 # Glenn Randers-Pehrson
 # Copyright (C) 1996, 1997 Andreas Dilger
@@ -24,24 +24,22 @@ LN_SF=ln -sf
 CP=cp
 RM_F=rm -f
 
-# Where the zlib library and include files are located.
-#ZLIBLIB=/usr/local/lib
-#ZLIBINC=/usr/local/include
-ZLIBLIB=../zlib
-ZLIBINC=../zlib
-
 # Compiler and linker flags
-NOHWOPT=-DPNG_ARM_NEON_OPT=0 -DPNG_MIPS_MSA_OPT=0 \
-	-DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
-WARNMORE=-Wwrite-strings -Wpointer-arith -Wshadow \
-	-Wmissing-declarations -Wtraditional -Wcast-align \
-	-Wstrict-prototypes -Wmissing-prototypes # -Wconversion
-DEFS=$(NOHWOPT)
-CPPFLAGS=-I$(ZLIBINC) $(DEFS) # -DPNG_DEBUG=5
-CFLAGS=-O3 -funroll-loops -Wall -Wextra -Wundef # $(WARNMORE) -g
-ARFLAGS=rc
-LDFLAGS=-L. -Wl,-rpath,. -L$(ZLIBLIB) -Wl,-rpath,$(ZLIBLIB) -lpng16 -lz -lm # -g
-LDFLAGS_A=-L$(ZLIBLIB) -Wl,-rpath,$(ZLIBLIB) libpng.a -lz -lm # -g
+NOHWOPT = -DPNG_ARM_NEON_OPT=0 -DPNG_MIPS_MSA_OPT=0 \
+          -DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
+STDC = -pedantic-errors
+WARN = -Wall -Wextra -Wundef
+WARNMORE = -Wcast-align -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings \
+           -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes
+LOCAL_CPPFLAGS = $(NOHWOPT)
+CPPFLAGS = # -DPNG_DEBUG=5
+ALL_CPPFLAGS = $(LOCAL_CPPFLAGS) $(CPPFLAGS)
+LOCAL_CFLAGS = $(STDC) $(WARN) # $(WARNMORE)
+CFLAGS = -O3 -funroll-loops # -g
+ALL_CFLAGS = $(LOCAL_CFLAGS) $(CFLAGS)
+ARFLAGS = rc
+LDFLAGS = -L. -Wl,-rpath,. -lpng16 -lz -lm # -g
+LDFLAGS_A = libpng.a -lz -lm # -g
 
 # Pre-built configuration
 # See scripts/pnglibconf.mak for more options
@@ -57,10 +55,10 @@ OBJSDLL = $(OBJS:.o=.pic.o)
 .SUFFIXES:      .c .o .pic.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(ALL_CPPFLAGS) $(ALL_CFLAGS) -o $@ $*.c
 
 .c.pic.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -fPIC -o $@ $*.c
+	$(CC) -c $(ALL_CPPFLAGS) $(ALL_CFLAGS) -fPIC -o $@ $*.c
 
 all: libpng.a $(LIBSO) pngtest pngtest-static
 
diff --git a/scripts/makefile.mips b/scripts/makefile.mips
index 45de36d46..4822a7065 100644
--- a/scripts/makefile.mips
+++ b/scripts/makefile.mips
@@ -1,5 +1,5 @@
 # makefile for libpng
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 1998-2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -26,7 +26,7 @@ OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
        pngtrans.o pngwio.o pngwrite.o pngwtran.o pngwutil.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 all: libpng.a pngtest
 
diff --git a/scripts/makefile.msys b/scripts/makefile.msys
index 8ebcaab99..3951c7467 100644
--- a/scripts/makefile.msys
+++ b/scripts/makefile.msys
@@ -1,5 +1,5 @@
 # makefile for libpng using MSYS/gcc (shared, static library)
-# Copyright (C) 2000, 2019-2024 Cosmin Truta
+# Copyright (C) 2000, 2019-2025 Cosmin Truta
 # Copyright (C) 2012 Glenn Randers-Pehrson and Christopher M. Wheeler
 #
 # Portions taken from makefile.linux and makefile.gcc:
@@ -21,23 +21,28 @@ PNGMAJ=16
 LIBSO=$(LIBNAME).dll
 LIBSOMAJ=$(LIBNAME).dll.$(PNGMAJ)
 
-# Where the zlib library and include files are located.
-#ZLIBLIB=../zlib
-#ZLIBINC=../zlib
-ZLIBLIB=/usr/local/lib
-ZLIBINC=/usr/local/include
-
 # Compiler, linker, lib and other tools
 CC = gcc
 LD = $(CC)
 AR = ar
 RANLIB = ranlib
 CP = cp
-RM_F = rm -rf
+RM_F = rm -f
 LN_SF = ln -sf
 
+# Compiler and linker flags
+NOHWOPT = -DPNG_ARM_NEON_OPT=0 -DPNG_MIPS_MSA_OPT=0 \
+          -DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
+STDC = -pedantic-errors
+WARN = -Wall -Wextra -Wundef
+WARNMORE = -Wcast-align -Wconversion -Wshadow -Wpointer-arith -Wwrite-strings \
+           -Wmissing-declarations -Wmissing-prototypes -Wstrict-prototypes
+LOCAL_CPPFLAGS = $(NOHWOPT)
 CPPFLAGS = # -DPNG_DEBUG=5
-CFLAGS = -O2 -Wall -Wextra -Wundef # -g
+ALL_CPPFLAGS = $(LOCAL_CPPFLAGS) $(CPPFLAGS)
+LOCAL_CFLAGS = $(STDC) $(WARN) # $(WARNMORE)
+CFLAGS = -O2 # -g
+ALL_CFLAGS = $(LOCAL_CFLAGS) $(CFLAGS)
 ARFLAGS = rc
 LDFLAGS = # -g
 LIBS = -lz -lm
@@ -61,7 +66,7 @@ pnglibconf.h: $(PNGLIBCONF_H_PREBUILT)
 	$(CP) $(PNGLIBCONF_H_PREBUILT) $@
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) $<
+	$(CC) -c $(ALL_CPPFLAGS) $(ALL_CFLAGS) -o $@ $*.c
 
 static: libpng.a pngtest$(EXEEXT)
 
diff --git a/scripts/makefile.netbsd b/scripts/makefile.netbsd
index d3419f29b..72643df02 100644
--- a/scripts/makefile.netbsd
+++ b/scripts/makefile.netbsd
@@ -1,5 +1,5 @@
 # makefile for libpng on NetBSD
-# Copyright (C) 2020-2022 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2007-2009, 2014 Glenn Randers-Pehrson
 # Copyright (C) 2002 Patrick R.L. Welche
 #
@@ -32,7 +32,7 @@ PNGLIBCONF_H_PREBUILT= scripts/pnglibconf.h.prebuilt
 # .endif
 
 .c.o:
-	${CC} -c ${CPPFLAGS} ${CFLAGS} -o $@ $<
+	${CC} -c ${CPPFLAGS} ${CFLAGS} -o $@ $*.c
 
 pnglibconf.h:	${PNGLIBCONF_H_PREBUILT}
 	cp ${PNGLIBCONF_H_PREBUILT} $@
diff --git a/scripts/makefile.openbsd b/scripts/makefile.openbsd
index 6bfeab779..1b93f02fe 100644
--- a/scripts/makefile.openbsd
+++ b/scripts/makefile.openbsd
@@ -1,5 +1,5 @@
 # makefile for libpng
-# Copyright (C) 2020-2022 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2007-2009, 2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -26,7 +26,7 @@ CLEANFILES+=	pngtest.o pngtest pnglibconf.h
 PNGLIBCONF_H_PREBUILT= scripts/pnglibconf.h.prebuilt
 
 .c.o:
-	${CC} -c ${CPPFLAGS} ${CFLAGS} -o $@ $<
+	${CC} -c ${CPPFLAGS} ${CFLAGS} -o $@ $*.c
 
 pnglibconf.h:	${PNGLIBCONF_H_PREBUILT}
 	cp ${PNGLIBCONF_H_PREBUILT} $@
diff --git a/scripts/makefile.sco b/scripts/makefile.sco
index 8a8e50ffc..2054c5138 100644
--- a/scripts/makefile.sco
+++ b/scripts/makefile.sco
@@ -1,7 +1,7 @@
 # makefile for SCO OSr5  ELF and Unixware 7 with Native cc
 # Contributed by Mike Hopkirk (hops at sco.com) modified from Makefile.lnx
 #   force ELF build dynamic linking, SONAME setting in lib and RPATH in app
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2002, 2006, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 1998 Greg Roelofs
 # Copyright (C) 1996, 1997 Andreas Dilger
@@ -50,7 +50,7 @@ OBJSDLL = $(OBJS:.o=.pic.o)
 .SUFFIXES:      .c .o .pic.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 .c.pic.o:
 	$(CC) -c $(CPPFLAGS) $(CFLAGS) -KPIC -o $@ $*.c
diff --git a/scripts/makefile.sggcc b/scripts/makefile.sggcc
index f694f6eed..d8a6091ff 100644
--- a/scripts/makefile.sggcc
+++ b/scripts/makefile.sggcc
@@ -1,5 +1,5 @@
 # makefile for libpng.a and libpng16.so, SGI IRIX with 'cc'
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2001-2002, 2006, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -35,9 +35,8 @@ ZLIBINC=../zlib
 # See "man abi".  zlib must be built with the same ABI.
 ABI=
 
-WARNMORE=
 CPPFLAGS=-I$(ZLIBINC) # -DPNG_DEBUG=5
-CFLAGS=$(ABI) -O $(WARNMORE) -fPIC -mabi=n32 # -g
+CFLAGS=$(ABI) -O -fPIC -mabi=n32 # -g
 ARFLAGS=rc
 LDFLAGS=$(ABI) -L. -L$(ZLIBLIB) -lpng -lz -lm # -g
 LDSHARED=cc $(ABI) -shared -soname $(LIBSOMAJ) \
@@ -53,7 +52,7 @@ OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
        pngtrans.o pngwio.o pngwrite.o pngwtran.o pngwutil.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 all: libpng.a pngtest shared
 
diff --git a/scripts/makefile.sgi b/scripts/makefile.sgi
index a60650c25..fb5350957 100644
--- a/scripts/makefile.sgi
+++ b/scripts/makefile.sgi
@@ -1,5 +1,5 @@
 # makefile for libpng.a and libpng16.so, SGI IRIX with 'cc'
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2001-2002, 2006, 2007, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -35,11 +35,10 @@ ZLIBINC=../zlib
 # See "man abi".  zlib must be built with the same ABI.
 ABI=
 
-WARNMORE=-fullwarn
 # Note: -KPIC is the default anyhow
 CPPFLAGS=-I$(ZLIBINC) # -DPNG_DEBUG=5
-#CFLAGS= $(ABI) -O $(WARNMORE) -KPIC # -g
-CFLAGS=$(ABI) -O $(WARNMORE) # -g
+#CFLAGS=$(ABI) -O -fullwarn -KPIC # -g
+CFLAGS=$(ABI) -O -fullwarn # -g
 ARFLAGS=rc
 LDFLAGS_A=$(ABI) -L. -L$(ZLIBLIB) -lpng16 -lz -lm # -g
 LDFLAGS=$(ABI) -L. -L$(ZLIBLIB) -lpng -lz -lm # -g
@@ -56,7 +55,7 @@ OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
        pngtrans.o pngwio.o pngwrite.o pngwtran.o pngwutil.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 all: libpng.a pngtest shared
 
diff --git a/scripts/makefile.so9 b/scripts/makefile.so9
index 5af3ad995..d85670176 100644
--- a/scripts/makefile.so9
+++ b/scripts/makefile.so9
@@ -1,7 +1,7 @@
 # makefile for libpng on Solaris 9 (beta) with Forte cc
 # Updated by Chad Schrock for Solaris 9
 # Contributed by William L. Sebok, based on makefile.linux
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2002, 2006, 2008, 2010-2014 Glenn Randers-Pehrson
 # Copyright (C) 1998-2001 Greg Roelofs
 # Copyright (C) 1996-1997 Andreas Dilger
@@ -19,7 +19,6 @@ LIBSO=$(LIBNAME).so
 LIBSOMAJ=$(LIBNAME).so.$(PNGMAJ)
 
 # Utilities:
-# gcc 2.95 doesn't work.
 CC=cc
 AR=ar
 RANLIB=echo
@@ -56,7 +55,7 @@ OBJSDLL = $(OBJS:.o=.pic.o)
 .SUFFIXES:      .c .o .pic.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 .c.pic.o:
 	$(CC) -c $(CPPFLAGS) $(CFLAGS) -KPIC -o $@ $*.c
diff --git a/scripts/makefile.solaris b/scripts/makefile.solaris
index c4d770978..3274830a9 100644
--- a/scripts/makefile.solaris
+++ b/scripts/makefile.solaris
@@ -1,5 +1,5 @@
 # makefile for libpng on Solaris 2.x with gcc
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2004, 2006-2008, 2010-2014 Glenn Randers-Pehrson
 # Contributed by William L. Sebok, based on makefile.linux
 # Copyright (C) 1998 Greg Roelofs
@@ -34,11 +34,8 @@ RM_F=/bin/rm -f
 ZLIBLIB=/usr/local/lib
 ZLIBINC=/usr/local/include
 
-WARNMORE=-Wwrite-strings -Wpointer-arith -Wshadow \
-	-Wmissing-declarations -Wtraditional -Wcast-align \
-	-Wstrict-prototypes -Wmissing-prototypes # -Wconversion
 CPPFLAGS=-I$(ZLIBINC) # -DPNG_DEBUG=5
-CFLAGS=-O -Wall -Wextra -Wundef # $(WARNMORE) -g
+CFLAGS=-O # -g
 ARFLAGS=rc
 LDFLAGS=-L. -R. -L$(ZLIBLIB) -R$(ZLIBLIB) -lpng16 -lz -lm # -g
 
@@ -55,7 +52,7 @@ OBJSDLL = $(OBJS:.o=.pic.o)
 .SUFFIXES:      .c .o .pic.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 .c.pic.o:
 	$(CC) -c $(CPPFLAGS) $(CFLAGS) -fPIC -o $@ $*.c
diff --git a/scripts/makefile.std b/scripts/makefile.std
index 6d69bf586..5c793eaf2 100644
--- a/scripts/makefile.std
+++ b/scripts/makefile.std
@@ -1,5 +1,5 @@
 # makefile for libpng
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2015, 2018-2025 Cosmin Truta
 # Copyright (C) 2002, 2006, 2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -23,7 +23,7 @@ RM_F = rm -f
 AWK = awk
 
 NOHWOPT = -DPNG_ARM_NEON_OPT=0 -DPNG_MIPS_MSA_OPT=0 \
-	-DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
+          -DPNG_POWERPC_VSX_OPT=0 -DPNG_INTEL_SSE_OPT=0
 DFNFLAGS = # DFNFLAGS contains -D options to use in the libpng build
 DFA_EXTRA = # extra files that can be used to control configuration
 CPPFLAGS = -I$(ZLIBINC) $(NOHWOPT) # -DPNG_DEBUG=5
@@ -41,7 +41,7 @@ OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
        pngtrans.o pngwio.o pngwrite.o pngwtran.o pngwutil.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 all: libpng.a pngtest
 
diff --git a/scripts/makefile.sunos b/scripts/makefile.sunos
index e8c046bb0..2ce8ef42f 100644
--- a/scripts/makefile.sunos
+++ b/scripts/makefile.sunos
@@ -1,5 +1,5 @@
 # makefile for libpng
-# Copyright (C) 2020-2024 Cosmin Truta
+# Copyright (C) 2018-2025 Cosmin Truta
 # Copyright (C) 2002, 2006, 2014 Glenn Randers-Pehrson
 # Copyright (C) 1995 Guy Eric Schalnat, Group 42, Inc.
 #
@@ -33,7 +33,7 @@ OBJS = png.o pngerror.o pngget.o pngmem.o pngpread.o \
        pngtrans.o pngwio.o pngwrite.o pngwtran.o pngwutil.o
 
 .c.o:
-	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<
+	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $*.c
 
 all: libpng.a pngtest
 
diff --git a/scripts/pnglibconf.dfa b/scripts/pnglibconf.dfa
index fe8e48123..f466da1a3 100644
--- a/scripts/pnglibconf.dfa
+++ b/scripts/pnglibconf.dfa
@@ -8,7 +8,7 @@ com pnglibconf.h - library build configuration
 com
 version
 com
-com Copyright (c) 2018-2024 Cosmin Truta
+com Copyright (c) 2018-2025 Cosmin Truta
 com Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson
 com
 com This code is released under the libpng license.
@@ -711,7 +711,7 @@ option WRITE_TEXT requires WRITE_ANCILLARY_CHUNKS enables TEXT
 # processing, it just validates the data in the PNG file.
 
 option GAMMA disabled
-option COLORSPACE enables GAMMA disabled
+option COLORSPACE disabled
 
 # When an ICC profile is read, or png_set, it will be checked for a match
 # against known sRGB profiles if the sRGB handling is enabled.  The
@@ -846,18 +846,21 @@ setting IDAT_READ_SIZE default PNG_ZBUF_SIZE
 # Ancillary chunks
 chunk bKGD
 chunk cHRM enables COLORSPACE
+chunk cICP enables COLORSPACE, GAMMA
+chunk cLLI
 chunk eXIf
 chunk gAMA enables GAMMA
 chunk hIST
-chunk iCCP enables COLORSPACE, GAMMA
+chunk iCCP enables GAMMA
 chunk iTXt enables TEXT
+chunk mDCV enables COLORSPACE
 chunk oFFs
 chunk pCAL
 chunk pHYs
 chunk sBIT
 chunk sCAL
 chunk sPLT
-chunk sRGB enables COLORSPACE, GAMMA, SET_OPTION
+chunk sRGB enables GAMMA, SET_OPTION
 chunk tEXt requires TEXT
 chunk tIME
 chunk tRNS
@@ -992,7 +995,8 @@ option SIMPLIFIED_READ,
       READ_EXPAND, READ_16BIT, READ_EXPAND_16, READ_SCALE_16_TO_8,
       READ_RGB_TO_GRAY, READ_ALPHA_MODE, READ_BACKGROUND, READ_STRIP_ALPHA,
       READ_FILLER, READ_SWAP, READ_PACK, READ_GRAY_TO_RGB, READ_GAMMA,
-      READ_tRNS, READ_bKGD, READ_gAMA, READ_cHRM, READ_sRGB, READ_sBIT
+      READ_tRNS, READ_bKGD, READ_gAMA, READ_cHRM, READ_sRGB, READ_mDCV,
+      READ_cICP, READ_sBIT
 
 # AFIRST and BGR read options:
 #  Prior to libpng 1.6.8 these were disabled but switched on if the low level
diff --git a/scripts/pnglibconf.h.prebuilt b/scripts/pnglibconf.h.prebuilt
index f5ce441ec..748220bfc 100644
--- a/scripts/pnglibconf.h.prebuilt
+++ b/scripts/pnglibconf.h.prebuilt
@@ -1,8 +1,8 @@
 /* pnglibconf.h - library build configuration */
 
-/* libpng version 1.6.44 */
+/* libpng version 1.6.47 */
 
-/* Copyright (c) 2018-2024 Cosmin Truta */
+/* Copyright (c) 2018-2025 Cosmin Truta */
 /* Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson */
 
 /* This code is released under the libpng license. */
@@ -88,11 +88,14 @@
 #define PNG_READ_USER_TRANSFORM_SUPPORTED
 #define PNG_READ_bKGD_SUPPORTED
 #define PNG_READ_cHRM_SUPPORTED
+#define PNG_READ_cICP_SUPPORTED
+#define PNG_READ_cLLI_SUPPORTED
 #define PNG_READ_eXIf_SUPPORTED
 #define PNG_READ_gAMA_SUPPORTED
 #define PNG_READ_hIST_SUPPORTED
 #define PNG_READ_iCCP_SUPPORTED
 #define PNG_READ_iTXt_SUPPORTED
+#define PNG_READ_mDCV_SUPPORTED
 #define PNG_READ_oFFs_SUPPORTED
 #define PNG_READ_pCAL_SUPPORTED
 #define PNG_READ_pHYs_SUPPORTED
@@ -158,11 +161,14 @@
 #define PNG_WRITE_WEIGHTED_FILTER_SUPPORTED
 #define PNG_WRITE_bKGD_SUPPORTED
 #define PNG_WRITE_cHRM_SUPPORTED
+#define PNG_WRITE_cICP_SUPPORTED
+#define PNG_WRITE_cLLI_SUPPORTED
 #define PNG_WRITE_eXIf_SUPPORTED
 #define PNG_WRITE_gAMA_SUPPORTED
 #define PNG_WRITE_hIST_SUPPORTED
 #define PNG_WRITE_iCCP_SUPPORTED
 #define PNG_WRITE_iTXt_SUPPORTED
+#define PNG_WRITE_mDCV_SUPPORTED
 #define PNG_WRITE_oFFs_SUPPORTED
 #define PNG_WRITE_pCAL_SUPPORTED
 #define PNG_WRITE_pHYs_SUPPORTED
@@ -176,11 +182,14 @@
 #define PNG_WRITE_zTXt_SUPPORTED
 #define PNG_bKGD_SUPPORTED
 #define PNG_cHRM_SUPPORTED
+#define PNG_cICP_SUPPORTED
+#define PNG_cLLI_SUPPORTED
 #define PNG_eXIf_SUPPORTED
 #define PNG_gAMA_SUPPORTED
 #define PNG_hIST_SUPPORTED
 #define PNG_iCCP_SUPPORTED
 #define PNG_iTXt_SUPPORTED
+#define PNG_mDCV_SUPPORTED
 #define PNG_oFFs_SUPPORTED
 #define PNG_pCAL_SUPPORTED
 #define PNG_pHYs_SUPPORTED
diff --git a/scripts/prefix.c b/scripts/prefix.c
index 06576ae6a..8a39482b0 100644
--- a/scripts/prefix.c
+++ b/scripts/prefix.c
@@ -1,4 +1,3 @@
-
 /* prefix.c - generate an unprefixed symbol list
  *
  * Copyright (c) 2013-2014 Glenn Randers-Pehrson
diff --git a/scripts/sym.c b/scripts/sym.c
index 7571de2b7..0749449d0 100644
--- a/scripts/sym.c
+++ b/scripts/sym.c
@@ -1,4 +1,3 @@
-
 /* sym.c - define format of libpng.sym
  *
  * Copyright (c) 2011-2014 Glenn Randers-Pehrson
diff --git a/scripts/symbols.c b/scripts/symbols.c
index d51a8303c..d5bb1d0f9 100644
--- a/scripts/symbols.c
+++ b/scripts/symbols.c
@@ -1,4 +1,3 @@
-
 /* symbols.c - find all exported symbols
  *
  * Copyright (c) 2011-2014 Glenn Randers-Pehrson
diff --git a/scripts/symbols.def b/scripts/symbols.def
index 82494bbf9..d17b63067 100644
--- a/scripts/symbols.def
+++ b/scripts/symbols.def
@@ -253,3 +253,13 @@ EXPORTS
  png_set_eXIf @247
  png_get_eXIf_1 @248
  png_set_eXIf_1 @249
+ png_get_cICP @250
+ png_set_cICP @251
+ png_get_cLLI @252
+ png_get_cLLI_fixed @253
+ png_set_cLLI @254
+ png_set_cLLI_fixed @255
+ png_get_mDCV @256
+ png_get_mDCV_fixed @257
+ png_set_mDCV @258
+ png_set_mDCV_fixed @259
diff --git a/scripts/vers.c b/scripts/vers.c
index d74972643..137749c70 100644
--- a/scripts/vers.c
+++ b/scripts/vers.c
@@ -1,4 +1,3 @@
-
 /* vers.c - define format of libpng.vers
  *
  * Copyright (c) 2011-2014 Glenn Randers-Pehrson
diff --git a/tests/pngtest-all b/tests/pngtest-all
index 668d92e9c..0998425a8 100755
--- a/tests/pngtest-all
+++ b/tests/pngtest-all
@@ -24,6 +24,9 @@ TEST(){
 # The "standard" test
 TEST --strict "${srcdir}"/pngtest.png
 
+# PNG-3 tests
+TEST --strict "${srcdir}"/contrib/testpngs/png-3/*.png
+
 # Various crashers
 # Use --relaxed because some come from fuzzers that don't maintain CRCs
 TEST --relaxed "${srcdir}"/contrib/testpngs/crashers/badcrc.png
```

