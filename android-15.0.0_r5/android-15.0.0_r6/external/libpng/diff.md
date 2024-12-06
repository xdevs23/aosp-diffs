```diff
diff --git a/.appveyor.yml b/.appveyor.yml
index ddeb4ecf5..ee3d27ad3 100644
--- a/.appveyor.yml
+++ b/.appveyor.yml
@@ -48,6 +48,7 @@ install:
   - 'if "%TOOLCHAIN%"=="vstudio" C:\tools\vcpkg\vcpkg.exe integrate install'
   - 'if "%TOOLCHAIN%"=="llvm" C:\tools\vcpkg\vcpkg.exe install zlib:%ARCH%-windows'
   - 'if "%TOOLCHAIN%"=="llvm" C:\tools\vcpkg\vcpkg.exe integrate install'
+  - 'if "%TOOLCHAIN%"=="msys2" if "%AUTOMATION%"=="cmake" C:\msys64\usr\bin\pacman.exe -S --noconfirm mingw-w64-%ARCH%-cmake mingw-w64-%ARCH%-ninja'
 
 before_build:
   - 'if "%TOOLCHAIN%"=="vstudio" set CI_CMAKE_GENERATOR=Visual Studio 17 2022'
@@ -58,11 +59,11 @@ before_build:
   - 'if "%TOOLCHAIN%"=="vstudio" if "%ARCH%"=="arm64" set CI_CMAKE_VARS=-DPNG_TESTS=0'
   - 'if "%TOOLCHAIN%"=="llvm" set CI_CMAKE_GENERATOR=Ninja'
   - 'if "%TOOLCHAIN%"=="llvm" set CI_CMAKE_TOOLCHAIN_FILE=C:\tools\vcpkg\scripts\buildsystems\vcpkg.cmake'
-  - 'if "%TOOLCHAIN%"=="llvm" set CI_CC=clang.exe'
-  - 'if "%TOOLCHAIN%"=="msys2" if "%AUTOMATION%"=="cmake" set CI_CMAKE_GENERATOR=Unix Makefiles'
-  - 'if "%TOOLCHAIN%"=="msys2" if "%ARCH%"=="i686" set PATH=C:\msys64\mingw32\bin;%PATH%'
-  - 'if "%TOOLCHAIN%"=="msys2" if "%ARCH%"=="x86_64" set PATH=C:\msys64\mingw64\bin;%PATH%'
-  - 'if "%TOOLCHAIN%"=="msys2" set CI_CC=%ARCH%-w64-mingw32-gcc.exe'
+  - 'if "%TOOLCHAIN%"=="llvm" set CI_CC=clang'
+  - 'if "%TOOLCHAIN%"=="msys2" set CI_CMAKE_GENERATOR=Ninja'
+  - 'if "%TOOLCHAIN%"=="msys2" set CI_CC=gcc'
+  - 'if "%TOOLCHAIN%"=="msys2" if "%ARCH%"=="i686" set MSYSTEM=MINGW32'
+  - 'if "%TOOLCHAIN%"=="msys2" if "%ARCH%"=="x86_64" set MSYSTEM=MINGW64'
   - 'set CI_CMAKE_BUILD_FLAGS=-j2'
   - 'set CI_CTEST_FLAGS=-j2'
   - 'set CI_MAKE_FLAGS=-j2'
@@ -77,3 +78,4 @@ build_script:
 
 cache:
   - C:\tools\vcpkg\installed
+  - C:\msys64\var\cache\pacman
diff --git a/.travis.yml b/.travis.yml
index e8adbbd4a..f14e7c1ca 100644
--- a/.travis.yml
+++ b/.travis.yml
@@ -11,19 +11,13 @@ os:
   - osx
 
 env:
-  - AUTOMATION=cmake CI_CMAKE_VARS="-DPNG_HARDWARE_OPTIMIZATIONS=ON"
-  - AUTOMATION=cmake CI_CMAKE_VARS="-DPNG_HARDWARE_OPTIMIZATIONS=OFF"
-  - AUTOMATION=configure CI_CONFIGURE_FLAGS="--enable-hardware-optimizations"
-  - AUTOMATION=configure CI_CONFIGURE_FLAGS="--disable-hardware-optimizations"
+  - AUTOMATION=cmake
+  - AUTOMATION=configure
   - AUTOMATION=makefiles
 
-matrix:
-  include:
-    - os: osx
-      env: AUTOMATION=cmake CI_CMAKE_GENERATOR=Xcode
-
 before_script:
   - 'if test "$TRAVIS_OS_NAME" = "linux"; then export CI_CC="gcc"; else export CI_CC="clang"; fi'
+  - 'if test "$TRAVIS_OS_NAME" = "osx"; then export CI_CMAKE_GENERATOR="Xcode"; fi'
   - 'if test "$TRAVIS_OS_NAME" != "osx"; then export CI_SANITIZERS="address,undefined"; fi'
   - 'export CI_MAKEFILES="scripts/makefile.$CI_CC scripts/makefile.std"'
   - 'export CI_MAKE_FLAGS=-j2'
diff --git a/ANNOUNCE b/ANNOUNCE
index bc147adb7..a2a7ac363 100644
--- a/ANNOUNCE
+++ b/ANNOUNCE
@@ -1,5 +1,5 @@
-libpng 1.6.43 - February 23, 2024
-=================================
+libpng 1.6.44 - September 12, 2024
+==================================
 
 This is a public release of libpng, intended for use in production code.
 
@@ -9,13 +9,13 @@ Files available for download
 
 Source files with LF line endings (for Unix/Linux):
 
- * libpng-1.6.43.tar.xz (LZMA-compressed, recommended)
- * libpng-1.6.43.tar.gz (deflate-compressed)
+ * libpng-1.6.44.tar.xz (LZMA-compressed, recommended)
+ * libpng-1.6.44.tar.gz (deflate-compressed)
 
 Source files with CRLF line endings (for Windows):
 
- * lpng1643.7z (LZMA-compressed, recommended)
- * lpng1643.zip (deflate-compressed)
+ * lpng1644.7z (LZMA-compressed, recommended)
+ * lpng1644.zip (deflate-compressed)
 
 Other information:
 
@@ -25,36 +25,29 @@ Other information:
  * TRADEMARK.md
 
 
-Changes from version 1.6.42 to version 1.6.43
+Changes from version 1.6.43 to version 1.6.44
 ---------------------------------------------
 
- * Fixed the row width check in png_check_IHDR().
-   This corrected a bug that was specific to the 16-bit platforms,
-   and removed a spurious compiler warning from the 64-bit builds.
-   (Reported by Jacek Caban; fixed by John Bowler)
- * Added eXIf chunk support to the push-mode reader in pngpread.c.
-   (Contributed by Chris Blume)
- * Added contrib/pngexif for the benefit of the users who would like
-   to inspect the content of eXIf chunks.
- * Added contrib/conftest/basic.dfa, a basic build-time configuration.
+ * Hardened calculations in chroma handling to prevent overflows, and
+   relaxed a constraint in cHRM validation to accomodate the standard
+   ACES AP1 set of color primaries.
    (Contributed by John Bowler)
- * Fixed a preprocessor condition in pngread.c that broke build-time
-   configurations like contrib/conftest/pngcp.dfa.
-   (Contributed by John Bowler)
- * Added CMake build support for LoongArch LSX.
-   (Contributed by GuXiWei)
- * Fixed a CMake build error that occurred under a peculiar state of the
-   dependency tree. This was a regression introduced in libpng-1.6.41.
-   (Contributed by Dan Rosser)
- * Marked the installed libpng headers as system headers in CMake.
-   (Contributed by Benjamin Buch)
- * Updated the build support for RISCOS.
-   (Contributed by Cameron Cawley)
- * Updated the makefiles to allow cross-platform builds to initialize
-   conventional make variables like AR and ARFLAGS.
- * Added various improvements to the CI scripts in areas like version
-   consistency verification and text linting.
- * Added version consistency verification to pngtest.c also.
+ * Removed the ASM implementation of ARM Neon optimizations and updated
+   the build accordingly. Only the remaining C implementation shall be
+   used from now on, thus ensuring the support of the PAC/BTI security
+   features on ARM64.
+   (Contributed by Ross Burton and John Bowler)
+ * Fixed the pickup of the PNG_HARDWARE_OPTIMIZATIONS option in the
+   CMake build on FreeBSD/amd64. This is an important performance fix
+   on this platform.
+ * Applied various fixes and improvements to the CMake build.
+   (Contributed by Eric Riff, Benjamin Buch and Erik Scholz)
+ * Added fuzzing targets for the simplified read API.
+   (Contributed by Mikhail Khachayants)
+ * Fixed a build error involving pngtest.c under a custom config.
+   This was a regression introduced in a code cleanup in libpng-1.6.43.
+   (Contributed by Ben Wagner)
+ * Fixed and improved the config files for AppVeyor CI and Travis CI.
 
 
 Send comments/corrections/commendations to png-mng-implement at lists.sf.net.
diff --git a/CHANGES b/CHANGES
index 441b57ecf..724ccca2d 100644
--- a/CHANGES
+++ b/CHANGES
@@ -6196,6 +6196,28 @@ Version 1.6.43 [February 23, 2024]
     consistency verification and text linting.
   Added version consistency verification to pngtest.c also.
 
+Version 1.6.44 [September 12, 2024]
+  Hardened calculations in chroma handling to prevent overflows, and
+    relaxed a constraint in cHRM validation to accomodate the standard
+    ACES AP1 set of color primaries.
+    (Contributed by John Bowler)
+  Removed the ASM implementation of ARM Neon optimizations and updated
+    the build accordingly. Only the remaining C implementation shall be
+    used from now on, thus ensuring the support of the PAC/BTI security
+    features on ARM64.
+    (Contributed by Ross Burton and John Bowler)
+  Fixed the pickup of the PNG_HARDWARE_OPTIMIZATIONS option in the
+    CMake build on FreeBSD/amd64. This is an important performance fix
+    on this platform.
+  Applied various fixes and improvements to the CMake build.
+    (Contributed by Eric Riff, Benjamin Buch and Erik Scholz)
+  Added fuzzing targets for the simplified read API.
+    (Contributed by Mikhail Khachayants)
+  Fixed a build error involving pngtest.c under a custom config.
+    This was a regression introduced in a code cleanup in libpng-1.6.43.
+    (Contributed by Ben Wagner)
+  Fixed and improved the config files for AppVeyor CI and Travis CI.
+
 Send comments/corrections/commendations to png-mng-implement at lists.sf.net.
 Subscription is required; visit
 https://lists.sourceforge.net/lists/listinfo/png-mng-implement
diff --git a/CMakeLists.txt b/CMakeLists.txt
index ad3f2427d..16cc2617d 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -19,7 +19,7 @@ cmake_minimum_required(VERSION 3.6)
 
 set(PNGLIB_MAJOR 1)
 set(PNGLIB_MINOR 6)
-set(PNGLIB_REVISION 43)
+set(PNGLIB_REVISION 44)
 set(PNGLIB_SUBREVISION 0)
 #set(PNGLIB_SUBREVISION "git")
 set(PNGLIB_VERSION ${PNGLIB_MAJOR}.${PNGLIB_MINOR}.${PNGLIB_REVISION})
@@ -90,6 +90,21 @@ endif()
 option(PNG_DEBUG "Enable debug output" OFF)
 option(PNG_HARDWARE_OPTIMIZATIONS "Enable hardware optimizations" ON)
 
+# Initialize and show the target architecture variable PNG_TARGET_ARCHITECTURE.
+#
+# NOTE:
+# On macOS, CMake sets CMAKE_SYSTEM_PROCESSOR to either "x86_64" or "arm64",
+# based upon the OS architecture, not the target architecture. As such, we need
+# to check CMAKE_OSX_ARCHITECTURES to identify which hardware-specific flags to
+# enable. Note that this will fail if you attempt to build a universal binary
+# in a single CMake invocation.
+if (APPLE AND CMAKE_OSX_ARCHITECTURES)
+  string(TOLOWER "${CMAKE_OSX_ARCHITECTURES}" PNG_TARGET_ARCHITECTURE)
+else()
+  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" PNG_TARGET_ARCHITECTURE)
+endif()
+message(STATUS "Building for target architecture: ${PNG_TARGET_ARCHITECTURE}")
+
 # Allow the users to specify a custom location of zlib.
 # This option is deprecated, and no longer needed with CMake 3.12 and newer.
 # Under the CMake policy CMP0074, if zlib is being built alongside libpng as a
@@ -119,22 +134,11 @@ else()
   # libm is not available or not needed.
 endif()
 
-# CMake currently sets CMAKE_SYSTEM_PROCESSOR to one of x86_64 or arm64 on macOS,
-# based upon the OS architecture, not the target architecture. As such, we need
-# to check CMAKE_OSX_ARCHITECTURES to identify which hardware-specific flags to
-# enable. Note that this will fail if you attempt to build a universal binary in
-# a single CMake invocation.
-if (APPLE AND CMAKE_OSX_ARCHITECTURES)
-  set(TARGET_ARCH ${CMAKE_OSX_ARCHITECTURES})
-else()
-  set(TARGET_ARCH ${CMAKE_SYSTEM_PROCESSOR})
-endif()
-
 if(PNG_HARDWARE_OPTIMIZATIONS)
 
 # Set definitions and sources for ARM.
-if(TARGET_ARCH MATCHES "^(ARM|arm|aarch)")
-  if(TARGET_ARCH MATCHES "^(ARM64|arm64|aarch64)")
+if(PNG_TARGET_ARCHITECTURE MATCHES "^(arm|aarch)")
+  if(PNG_TARGET_ARCHITECTURE MATCHES "^(arm64|aarch64)")
     set(PNG_ARM_NEON_POSSIBLE_VALUES on off)
     set(PNG_ARM_NEON "on"
         CACHE STRING "Enable ARM NEON optimizations: on|off; on is default")
@@ -153,9 +157,6 @@ if(TARGET_ARCH MATCHES "^(ARM|arm|aarch)")
         arm/arm_init.c
         arm/filter_neon_intrinsics.c
         arm/palette_neon_intrinsics.c)
-    if(NOT MSVC)
-      list(APPEND libpng_arm_sources arm/filter_neon.S)
-    endif()
     if(PNG_ARM_NEON STREQUAL "on")
       add_definitions(-DPNG_ARM_NEON_OPT=2)
     elseif(PNG_ARM_NEON STREQUAL "check")
@@ -167,7 +168,7 @@ if(TARGET_ARCH MATCHES "^(ARM|arm|aarch)")
 endif()
 
 # Set definitions and sources for PowerPC.
-if(TARGET_ARCH MATCHES "^(powerpc|ppc64)")
+if(PNG_TARGET_ARCHITECTURE MATCHES "^(powerpc|ppc64)")
   set(PNG_POWERPC_VSX_POSSIBLE_VALUES on off)
   set(PNG_POWERPC_VSX "on"
       CACHE STRING "Enable POWERPC VSX optimizations: on|off; on is default")
@@ -189,7 +190,7 @@ if(TARGET_ARCH MATCHES "^(powerpc|ppc64)")
 endif()
 
 # Set definitions and sources for Intel.
-if(TARGET_ARCH MATCHES "^(i[3-6]86|x86|AMD64)")
+if(PNG_TARGET_ARCHITECTURE MATCHES "^(i[3-6]86|x86|amd64)")
   set(PNG_INTEL_SSE_POSSIBLE_VALUES on off)
   set(PNG_INTEL_SSE "on"
       CACHE STRING "Enable INTEL_SSE optimizations: on|off; on is default")
@@ -211,7 +212,7 @@ if(TARGET_ARCH MATCHES "^(i[3-6]86|x86|AMD64)")
 endif()
 
 # Set definitions and sources for MIPS.
-if(TARGET_ARCH MATCHES "^(mipsel|mips64el)")
+if(PNG_TARGET_ARCHITECTURE MATCHES "^(mipsel|mips64el)")
   set(PNG_MIPS_MSA_POSSIBLE_VALUES on off)
   set(PNG_MIPS_MSA "on"
       CACHE STRING "Enable MIPS_MSA optimizations: on|off; on is default")
@@ -258,7 +259,7 @@ if(TARGET_ARCH MATCHES "^(mipsel|mips64el)")
 endif()
 
 # Set definitions and sources for LoongArch.
-if(TARGET_ARCH MATCHES "^(loongarch)")
+if(PNG_TARGET_ARCHITECTURE MATCHES "^(loongarch)")
   include(CheckCCompilerFlag)
   set(PNG_LOONGARCH_LSX_POSSIBLE_VALUES on off)
   set(PNG_LOONGARCH_LSX "on"
@@ -289,27 +290,27 @@ endif()
 else(PNG_HARDWARE_OPTIMIZATIONS)
 
 # Set definitions and sources for ARM.
-if(TARGET_ARCH MATCHES "^(ARM|arm|aarch)")
+if(PNG_TARGET_ARCHITECTURE MATCHES "^(arm|aarch)")
   add_definitions(-DPNG_ARM_NEON_OPT=0)
 endif()
 
 # Set definitions and sources for PowerPC.
-if(TARGET_ARCH MATCHES "^(powerpc|ppc64)")
+if(PNG_TARGET_ARCHITECTURE MATCHES "^(powerpc|ppc64)")
   add_definitions(-DPNG_POWERPC_VSX_OPT=0)
 endif()
 
 # Set definitions and sources for Intel.
-if(TARGET_ARCH MATCHES "^(i[3-6]86|x86|AMD64)")
+if(PNG_TARGET_ARCHITECTURE MATCHES "^(i[3-6]86|x86|amd64)")
   add_definitions(-DPNG_INTEL_SSE_OPT=0)
 endif()
 
 # Set definitions and sources for MIPS.
-if(TARGET_ARCH MATCHES "^(mipsel|mips64el)")
+if(PNG_TARGET_ARCHITECTURE MATCHES "^(mipsel|mips64el)")
   add_definitions(-DPNG_MIPS_MSA_OPT=0)
 endif()
 
 # Set definitions and sources for LoongArch.
-if(TARGET_ARCH MATCHES "^(loongarch)")
+if(PNG_TARGET_ARCHITECTURE MATCHES "^(loongarch)")
   add_definitions(-DPNG_LOONGARCH_LSX_OPT=0)
 endif()
 
@@ -362,8 +363,6 @@ else()
   message(STATUS "Could not find an AWK-compatible program")
 endif()
 
-include_directories(${CMAKE_CURRENT_BINARY_DIR})
-
 if(NOT AWK OR ANDROID OR IOS)
   # No awk available to generate sources; use pre-built pnglibconf.h
   configure_file(${CMAKE_CURRENT_SOURCE_DIR}/scripts/pnglibconf.h.prebuilt
@@ -714,6 +713,8 @@ if(PNG_SHARED)
   endif()
   target_include_directories(png_shared
                              PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
+  target_include_directories(png_shared
+                             PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
   target_include_directories(png_shared SYSTEM
                              INTERFACE $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/libpng${PNGLIB_ABI_VERSION}>)
   target_link_libraries(png_shared PUBLIC ZLIB::ZLIB ${M_LIBRARY})
@@ -728,6 +729,8 @@ if(PNG_STATIC)
                         DEBUG_POSTFIX "${PNG_DEBUG_POSTFIX}")
   target_include_directories(png_static
                              PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
+  target_include_directories(png_static
+                             PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
   target_include_directories(png_static SYSTEM
                              INTERFACE $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/libpng${PNGLIB_ABI_VERSION}>)
   target_link_libraries(png_static PUBLIC ZLIB::ZLIB ${M_LIBRARY})
@@ -757,6 +760,8 @@ if(PNG_FRAMEWORK)
   set_target_properties(png_framework PROPERTIES DEFINE_SYMBOL "")
   target_include_directories(png_framework
                              PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)
+  target_include_directories(png_framework
+                             PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>)
   target_include_directories(png_framework SYSTEM
                              INTERFACE $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/libpng${PNGLIB_ABI_VERSION}>)
   target_link_libraries(png_framework PUBLIC ZLIB::ZLIB ${M_LIBRARY})
@@ -1128,6 +1133,30 @@ if(NOT SKIP_INSTALL_EXPORT AND NOT SKIP_INSTALL_ALL)
           FILE libpng${PNGLIB_ABI_VERSION}.cmake)
 endif()
 
+# Create a CMake Config File that can be used via find_package(PNG CONFIG)
+if(NOT SKIP_INSTALL_CONFIG_FILE AND NOT SKIP_INSTALL_ALL)
+  install(TARGETS ${PNG_LIBRARY_TARGETS}
+          EXPORT PNGTargets
+          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
+          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
+          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
+          FRAMEWORK DESTINATION ${CMAKE_INSTALL_LIBDIR})
+
+  include(CMakePackageConfigHelpers)
+  write_basic_package_version_file(PNGConfigVersion.cmake
+                                   VERSION ${PNGLIB_VERSION}
+                                   COMPATIBILITY SameMinorVersion)
+
+  install(EXPORT PNGTargets
+          FILE PNGTargets.cmake
+          NAMESPACE PNG::
+          DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PNG)
+
+  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake/PNGConfig.cmake
+                ${CMAKE_CURRENT_BINARY_DIR}/PNGConfigVersion.cmake
+          DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PNG)
+endif()
+
 # TODO: Create MSVC import lib for MinGW-compiled shared lib.
 # pexports libpng.dll > libpng.def
 # lib /def:libpng.def /machine:x86
diff --git a/METADATA b/METADATA
index a1ffe529c..a16eb8122 100644
--- a/METADATA
+++ b/METADATA
@@ -1,6 +1,6 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/libpng
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "libpng"
 description: "libpng is a PNG image codec."
@@ -11,12 +11,12 @@ third_party {
   }
   last_upgrade_date {
     year: 2024
-    month: 6
-    day: 13
+    month: 9
+    day: 16
   }
   identifier {
     type: "Git"
     value: "https://github.com/glennrp/libpng.git"
-    version: "v1.6.43"
+    version: "v1.6.44"
   }
 }
diff --git a/Makefile.am b/Makefile.am
index 1f06c703a..eed986c2b 100644
--- a/Makefile.am
+++ b/Makefile.am
@@ -108,7 +108,7 @@ libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@_la_SOURCES = png.c pngerror.c\
 
 if PNG_ARM_NEON
 libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@_la_SOURCES += arm/arm_init.c\
-	arm/filter_neon.S arm/filter_neon_intrinsics.c \
+	arm/filter_neon_intrinsics.c \
 	arm/palette_neon_intrinsics.c
 endif
 
diff --git a/Makefile.in b/Makefile.in
index c9eac7dbc..44b6936b7 100644
--- a/Makefile.in
+++ b/Makefile.in
@@ -1,7 +1,7 @@
-# Makefile.in generated by automake 1.16.5 from Makefile.am.
+# Makefile.in generated by automake 1.17 from Makefile.am.
 # @configure_input@
 
-# Copyright (C) 1994-2021 Free Software Foundation, Inc.
+# Copyright (C) 1994-2024 Free Software Foundation, Inc.
 
 # This Makefile.in is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -83,6 +83,8 @@ am__make_running_with_option = \
   test $$has_opt = yes
 am__make_dryrun = (target_option=n; $(am__make_running_with_option))
 am__make_keepgoing = (target_option=k; $(am__make_running_with_option))
+am__rm_f = rm -f $(am__rm_f_notfound)
+am__rm_rf = rm -rf $(am__rm_f_notfound)
 pkgdatadir = $(datadir)/@PACKAGE@
 pkglibdir = $(libdir)/@PACKAGE@
 pkglibexecdir = $(libexecdir)/@PACKAGE@
@@ -108,7 +110,7 @@ host_triplet = @host@
 @ENABLE_TOOLS_TRUE@bin_PROGRAMS = pngfix$(EXEEXT) \
 @ENABLE_TOOLS_TRUE@	png-fix-itxt$(EXEEXT)
 @PNG_ARM_NEON_TRUE@am__append_2 = arm/arm_init.c\
-@PNG_ARM_NEON_TRUE@	arm/filter_neon.S arm/filter_neon_intrinsics.c \
+@PNG_ARM_NEON_TRUE@	arm/filter_neon_intrinsics.c \
 @PNG_ARM_NEON_TRUE@	arm/palette_neon_intrinsics.c
 
 @PNG_MIPS_MSA_TRUE@am__append_3 = mips/mips_init.c\
@@ -177,10 +179,9 @@ am__base_list = \
   sed '$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;$$!N;s/\n/ /g' | \
   sed '$$!N;$$!N;$$!N;$$!N;s/\n/ /g'
 am__uninstall_files_from_dir = { \
-  test -z "$$files" \
-    || { test ! -d "$$dir" && test ! -f "$$dir" && test ! -r "$$dir"; } \
-    || { echo " ( cd '$$dir' && rm -f" $$files ")"; \
-         $(am__cd) "$$dir" && rm -f $$files; }; \
+  { test ! -d "$$dir" && test ! -f "$$dir" && test ! -r "$$dir"; } \
+  || { echo " ( cd '$$dir' && rm -f" $$files ")"; \
+       $(am__cd) "$$dir" && echo $$files | $(am__xargs_n) 40 $(am__rm_f); }; \
   }
 LTLIBRARIES = $(lib_LTLIBRARIES) $(noinst_LTLIBRARIES)
 am__libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@_la_SOURCES_DIST = png.c \
@@ -188,13 +189,13 @@ am__libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@_la_SOURCES_DIST = png.c \
 	pngrtran.c pngrutil.c pngset.c pngtrans.c pngwio.c pngwrite.c \
 	pngwtran.c pngwutil.c png.h pngconf.h pngdebug.h pnginfo.h \
 	pngpriv.h pngstruct.h pngusr.dfa arm/arm_init.c \
-	arm/filter_neon.S arm/filter_neon_intrinsics.c \
-	arm/palette_neon_intrinsics.c mips/mips_init.c \
-	mips/filter_msa_intrinsics.c mips/filter_mmi_inline_assembly.c \
-	intel/intel_init.c intel/filter_sse2_intrinsics.c \
-	powerpc/powerpc_init.c powerpc/filter_vsx_intrinsics.c
+	arm/filter_neon_intrinsics.c arm/palette_neon_intrinsics.c \
+	mips/mips_init.c mips/filter_msa_intrinsics.c \
+	mips/filter_mmi_inline_assembly.c intel/intel_init.c \
+	intel/filter_sse2_intrinsics.c powerpc/powerpc_init.c \
+	powerpc/filter_vsx_intrinsics.c
 am__dirstamp = $(am__leading_dot)dirstamp
-@PNG_ARM_NEON_TRUE@am__objects_1 = arm/arm_init.lo arm/filter_neon.lo \
+@PNG_ARM_NEON_TRUE@am__objects_1 = arm/arm_init.lo \
 @PNG_ARM_NEON_TRUE@	arm/filter_neon_intrinsics.lo \
 @PNG_ARM_NEON_TRUE@	arm/palette_neon_intrinsics.lo
 @PNG_MIPS_MSA_TRUE@am__objects_2 = mips/mips_init.lo \
@@ -312,7 +313,7 @@ am__depfiles_remade = ./$(DEPDIR)/png.Plo ./$(DEPDIR)/pngerror.Plo \
 	./$(DEPDIR)/pngtest.Po ./$(DEPDIR)/pngtrans.Plo \
 	./$(DEPDIR)/pngwio.Plo ./$(DEPDIR)/pngwrite.Plo \
 	./$(DEPDIR)/pngwtran.Plo ./$(DEPDIR)/pngwutil.Plo \
-	arm/$(DEPDIR)/arm_init.Plo arm/$(DEPDIR)/filter_neon.Plo \
+	arm/$(DEPDIR)/arm_init.Plo \
 	arm/$(DEPDIR)/filter_neon_intrinsics.Plo \
 	arm/$(DEPDIR)/palette_neon_intrinsics.Plo \
 	contrib/libtests/$(DEPDIR)/pngimage.Po \
@@ -333,16 +334,6 @@ am__depfiles_remade = ./$(DEPDIR)/png.Plo ./$(DEPDIR)/pngerror.Plo \
 	powerpc/$(DEPDIR)/filter_vsx_intrinsics.Plo \
 	powerpc/$(DEPDIR)/powerpc_init.Plo
 am__mv = mv -f
-CPPASCOMPILE = $(CCAS) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
-	$(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CCASFLAGS) $(CCASFLAGS)
-LTCPPASCOMPILE = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
-	$(LIBTOOLFLAGS) --mode=compile $(CCAS) $(DEFS) \
-	$(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) \
-	$(AM_CCASFLAGS) $(CCASFLAGS)
-AM_V_CPPAS = $(am__v_CPPAS_@AM_V@)
-am__v_CPPAS_ = $(am__v_CPPAS_@AM_DEFAULT_V@)
-am__v_CPPAS_0 = @echo "  CPPAS   " $@;
-am__v_CPPAS_1 = 
 COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
 	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
 LTCOMPILE = $(LIBTOOL) $(AM_V_lt) --tag=CC $(AM_LIBTOOLFLAGS) \
@@ -513,6 +504,7 @@ am__sh_e_setup = case $$- in *e*) set +e;; esac
 # Default flags passed to test drivers.
 am__common_driver_flags = \
   --color-tests "$$am__color_tests" \
+  $$am__collect_skipped_logs \
   --enable-hard-errors "$$am__enable_hard_errors" \
   --expect-failure "$$am__expect_failure"
 # To be inserted before the command running the test.  Creates the
@@ -537,6 +529,11 @@ if test -f "./$$f"; then dir=./;			\
 elif test -f "$$f"; then dir=;				\
 else dir="$(srcdir)/"; fi;				\
 tst=$$dir$$f; log='$@'; 				\
+if test -n '$(IGNORE_SKIPPED_LOGS)'; then		\
+  am__collect_skipped_logs='--collect-skipped-logs no';	\
+else							\
+  am__collect_skipped_logs='';				\
+fi;							\
 if test -n '$(DISABLE_HARD_ERRORS)'; then		\
   am__enable_hard_errors=no; 				\
 else							\
@@ -592,20 +589,22 @@ distdir = $(PACKAGE)-$(VERSION)
 top_distdir = $(distdir)
 am__remove_distdir = \
   if test -d "$(distdir)"; then \
-    find "$(distdir)" -type d ! -perm -200 -exec chmod u+w {} ';' \
-      && rm -rf "$(distdir)" \
+    find "$(distdir)" -type d ! -perm -700 -exec chmod u+rwx {} ';' \
+      ; rm -rf "$(distdir)" \
       || { sleep 5 && rm -rf "$(distdir)"; }; \
   else :; fi
 am__post_remove_distdir = $(am__remove_distdir)
 DIST_ARCHIVES = $(distdir).tar.gz $(distdir).tar.xz
-GZIP_ENV = --best
+GZIP_ENV = -9
 DIST_TARGETS = dist-xz dist-gzip
 # Exists only to be overridden by the user if desired.
 AM_DISTCHECK_DVI_TARGET = dvi
 distuninstallcheck_listfiles = find . -type f -print
 am__distuninstallcheck_listfiles = $(distuninstallcheck_listfiles) \
   | sed 's|^\./|$(prefix)/|' | grep -v '$(infodir)/dir$$'
-distcleancheck_listfiles = find . -type f -print
+distcleancheck_listfiles = \
+  find . \( -type f -a \! \
+            \( -name .nfs* -o -name .smb* -o -name .__afs* \) \) -print
 
 #distribute headers in /usr/include/libpng/*
 pkgincludedir = $(includedir)/$(PNGLIB_BASENAME)
@@ -709,8 +708,10 @@ ac_ct_DUMPBIN = @ac_ct_DUMPBIN@
 am__include = @am__include@
 am__leading_dot = @am__leading_dot@
 am__quote = @am__quote@
+am__rm_f_notfound = @am__rm_f_notfound@
 am__tar = @am__tar@
 am__untar = @am__untar@
+am__xargs_n = @am__xargs_n@
 
 # generate the -config scripts if required
 binconfigs = libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@-config
@@ -885,7 +886,7 @@ all: $(BUILT_SOURCES) config.h
 	$(MAKE) $(AM_MAKEFLAGS) all-am
 
 .SUFFIXES:
-.SUFFIXES: .chk .out .S .c .lo .log .o .obj .test .test$(EXEEXT) .trs
+.SUFFIXES: .chk .out .c .lo .log .o .obj .test .test$(EXEEXT) .trs
 am--refresh: Makefile
 	@:
 $(srcdir)/Makefile.in: @MAINTAINER_MODE_TRUE@ $(srcdir)/Makefile.am  $(am__configure_deps)
@@ -925,12 +926,12 @@ config.h: stamp-h1
 	@test -f $@ || $(MAKE) $(AM_MAKEFLAGS) stamp-h1
 
 stamp-h1: $(srcdir)/config.h.in $(top_builddir)/config.status
-	@rm -f stamp-h1
-	cd $(top_builddir) && $(SHELL) ./config.status config.h
+	$(AM_V_at)rm -f stamp-h1
+	$(AM_V_GEN)cd $(top_builddir) && $(SHELL) ./config.status config.h
 $(srcdir)/config.h.in: @MAINTAINER_MODE_TRUE@ $(am__configure_deps) 
-	($(am__cd) $(top_srcdir) && $(AUTOHEADER))
-	rm -f stamp-h1
-	touch $@
+	$(AM_V_GEN)($(am__cd) $(top_srcdir) && $(AUTOHEADER))
+	$(AM_V_at)rm -f stamp-h1
+	$(AM_V_at)touch $@
 
 distclean-hdr:
 	-rm -f config.h stamp-h1
@@ -977,25 +978,15 @@ uninstall-binPROGRAMS:
 	`; \
 	test -n "$$list" || exit 0; \
 	echo " ( cd '$(DESTDIR)$(bindir)' && rm -f" $$files ")"; \
-	cd "$(DESTDIR)$(bindir)" && rm -f $$files
+	cd "$(DESTDIR)$(bindir)" && $(am__rm_f) $$files
 
 clean-binPROGRAMS:
-	@list='$(bin_PROGRAMS)'; test -n "$$list" || exit 0; \
-	echo " rm -f" $$list; \
-	rm -f $$list || exit $$?; \
-	test -n "$(EXEEXT)" || exit 0; \
-	list=`for p in $$list; do echo "$$p"; done | sed 's/$(EXEEXT)$$//'`; \
-	echo " rm -f" $$list; \
-	rm -f $$list
+	$(am__rm_f) $(bin_PROGRAMS)
+	test -z "$(EXEEXT)" || $(am__rm_f) $(bin_PROGRAMS:$(EXEEXT)=)
 
 clean-checkPROGRAMS:
-	@list='$(check_PROGRAMS)'; test -n "$$list" || exit 0; \
-	echo " rm -f" $$list; \
-	rm -f $$list || exit $$?; \
-	test -n "$(EXEEXT)" || exit 0; \
-	list=`for p in $$list; do echo "$$p"; done | sed 's/$(EXEEXT)$$//'`; \
-	echo " rm -f" $$list; \
-	rm -f $$list
+	$(am__rm_f) $(check_PROGRAMS)
+	test -z "$(EXEEXT)" || $(am__rm_f) $(check_PROGRAMS:$(EXEEXT)=)
 
 install-libLTLIBRARIES: $(lib_LTLIBRARIES)
 	@$(NORMAL_INSTALL)
@@ -1022,44 +1013,39 @@ uninstall-libLTLIBRARIES:
 	done
 
 clean-libLTLIBRARIES:
-	-test -z "$(lib_LTLIBRARIES)" || rm -f $(lib_LTLIBRARIES)
+	-$(am__rm_f) $(lib_LTLIBRARIES)
 	@list='$(lib_LTLIBRARIES)'; \
 	locs=`for p in $$list; do echo $$p; done | \
 	      sed 's|^[^/]*$$|.|; s|/[^/]*$$||; s|$$|/so_locations|' | \
 	      sort -u`; \
-	test -z "$$locs" || { \
-	  echo rm -f $${locs}; \
-	  rm -f $${locs}; \
-	}
+	echo rm -f $${locs}; \
+	$(am__rm_f) $${locs}
 
 clean-noinstLTLIBRARIES:
-	-test -z "$(noinst_LTLIBRARIES)" || rm -f $(noinst_LTLIBRARIES)
+	-$(am__rm_f) $(noinst_LTLIBRARIES)
 	@list='$(noinst_LTLIBRARIES)'; \
 	locs=`for p in $$list; do echo $$p; done | \
 	      sed 's|^[^/]*$$|.|; s|/[^/]*$$||; s|$$|/so_locations|' | \
 	      sort -u`; \
-	test -z "$$locs" || { \
-	  echo rm -f $${locs}; \
-	  rm -f $${locs}; \
-	}
+	echo rm -f $${locs}; \
+	$(am__rm_f) $${locs}
 arm/$(am__dirstamp):
 	@$(MKDIR_P) arm
-	@: > arm/$(am__dirstamp)
+	@: >>arm/$(am__dirstamp)
 arm/$(DEPDIR)/$(am__dirstamp):
 	@$(MKDIR_P) arm/$(DEPDIR)
-	@: > arm/$(DEPDIR)/$(am__dirstamp)
+	@: >>arm/$(DEPDIR)/$(am__dirstamp)
 arm/arm_init.lo: arm/$(am__dirstamp) arm/$(DEPDIR)/$(am__dirstamp)
-arm/filter_neon.lo: arm/$(am__dirstamp) arm/$(DEPDIR)/$(am__dirstamp)
 arm/filter_neon_intrinsics.lo: arm/$(am__dirstamp) \
 	arm/$(DEPDIR)/$(am__dirstamp)
 arm/palette_neon_intrinsics.lo: arm/$(am__dirstamp) \
 	arm/$(DEPDIR)/$(am__dirstamp)
 mips/$(am__dirstamp):
 	@$(MKDIR_P) mips
-	@: > mips/$(am__dirstamp)
+	@: >>mips/$(am__dirstamp)
 mips/$(DEPDIR)/$(am__dirstamp):
 	@$(MKDIR_P) mips/$(DEPDIR)
-	@: > mips/$(DEPDIR)/$(am__dirstamp)
+	@: >>mips/$(DEPDIR)/$(am__dirstamp)
 mips/mips_init.lo: mips/$(am__dirstamp) mips/$(DEPDIR)/$(am__dirstamp)
 mips/filter_msa_intrinsics.lo: mips/$(am__dirstamp) \
 	mips/$(DEPDIR)/$(am__dirstamp)
@@ -1067,20 +1053,20 @@ mips/filter_mmi_inline_assembly.lo: mips/$(am__dirstamp) \
 	mips/$(DEPDIR)/$(am__dirstamp)
 intel/$(am__dirstamp):
 	@$(MKDIR_P) intel
-	@: > intel/$(am__dirstamp)
+	@: >>intel/$(am__dirstamp)
 intel/$(DEPDIR)/$(am__dirstamp):
 	@$(MKDIR_P) intel/$(DEPDIR)
-	@: > intel/$(DEPDIR)/$(am__dirstamp)
+	@: >>intel/$(DEPDIR)/$(am__dirstamp)
 intel/intel_init.lo: intel/$(am__dirstamp) \
 	intel/$(DEPDIR)/$(am__dirstamp)
 intel/filter_sse2_intrinsics.lo: intel/$(am__dirstamp) \
 	intel/$(DEPDIR)/$(am__dirstamp)
 powerpc/$(am__dirstamp):
 	@$(MKDIR_P) powerpc
-	@: > powerpc/$(am__dirstamp)
+	@: >>powerpc/$(am__dirstamp)
 powerpc/$(DEPDIR)/$(am__dirstamp):
 	@$(MKDIR_P) powerpc/$(DEPDIR)
-	@: > powerpc/$(DEPDIR)/$(am__dirstamp)
+	@: >>powerpc/$(DEPDIR)/$(am__dirstamp)
 powerpc/powerpc_init.lo: powerpc/$(am__dirstamp) \
 	powerpc/$(DEPDIR)/$(am__dirstamp)
 powerpc/filter_vsx_intrinsics.lo: powerpc/$(am__dirstamp) \
@@ -1090,10 +1076,10 @@ libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@.la: $(libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@_la_O
 	$(AM_V_CCLD)$(libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@_la_LINK) -rpath $(libdir) $(libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@_la_OBJECTS) $(libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@_la_LIBADD) $(LIBS)
 loongarch/$(am__dirstamp):
 	@$(MKDIR_P) loongarch
-	@: > loongarch/$(am__dirstamp)
+	@: >>loongarch/$(am__dirstamp)
 loongarch/$(DEPDIR)/$(am__dirstamp):
 	@$(MKDIR_P) loongarch/$(DEPDIR)
-	@: > loongarch/$(DEPDIR)/$(am__dirstamp)
+	@: >>loongarch/$(DEPDIR)/$(am__dirstamp)
 loongarch/libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@lsx_la-loongarch_lsx_init.lo:  \
 	loongarch/$(am__dirstamp) loongarch/$(DEPDIR)/$(am__dirstamp)
 loongarch/libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@lsx_la-filter_lsx_intrinsics.lo:  \
@@ -1103,10 +1089,10 @@ libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@lsx.la: $(libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@ls
 	$(AM_V_CCLD)$(libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@lsx_la_LINK) $(am_libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@lsx_la_rpath) $(libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@lsx_la_OBJECTS) $(libpng@PNGLIB_MAJOR@@PNGLIB_MINOR@lsx_la_LIBADD) $(LIBS)
 contrib/tools/$(am__dirstamp):
 	@$(MKDIR_P) contrib/tools
-	@: > contrib/tools/$(am__dirstamp)
+	@: >>contrib/tools/$(am__dirstamp)
 contrib/tools/$(DEPDIR)/$(am__dirstamp):
 	@$(MKDIR_P) contrib/tools/$(DEPDIR)
-	@: > contrib/tools/$(DEPDIR)/$(am__dirstamp)
+	@: >>contrib/tools/$(DEPDIR)/$(am__dirstamp)
 contrib/tools/png-fix-itxt.$(OBJEXT): contrib/tools/$(am__dirstamp) \
 	contrib/tools/$(DEPDIR)/$(am__dirstamp)
 
@@ -1127,10 +1113,10 @@ pngfix$(EXEEXT): $(pngfix_OBJECTS) $(pngfix_DEPENDENCIES) $(EXTRA_pngfix_DEPENDE
 	$(AM_V_CCLD)$(LINK) $(pngfix_OBJECTS) $(pngfix_LDADD) $(LIBS)
 contrib/libtests/$(am__dirstamp):
 	@$(MKDIR_P) contrib/libtests
-	@: > contrib/libtests/$(am__dirstamp)
+	@: >>contrib/libtests/$(am__dirstamp)
 contrib/libtests/$(DEPDIR)/$(am__dirstamp):
 	@$(MKDIR_P) contrib/libtests/$(DEPDIR)
-	@: > contrib/libtests/$(DEPDIR)/$(am__dirstamp)
+	@: >>contrib/libtests/$(DEPDIR)/$(am__dirstamp)
 contrib/libtests/pngimage.$(OBJEXT): contrib/libtests/$(am__dirstamp) \
 	contrib/libtests/$(DEPDIR)/$(am__dirstamp)
 
@@ -1237,7 +1223,6 @@ distclean-compile:
 @AMDEP_TRUE@@am__include@ @am__quote@./$(DEPDIR)/pngwtran.Plo@am__quote@ # am--include-marker
 @AMDEP_TRUE@@am__include@ @am__quote@./$(DEPDIR)/pngwutil.Plo@am__quote@ # am--include-marker
 @AMDEP_TRUE@@am__include@ @am__quote@arm/$(DEPDIR)/arm_init.Plo@am__quote@ # am--include-marker
-@AMDEP_TRUE@@am__include@ @am__quote@arm/$(DEPDIR)/filter_neon.Plo@am__quote@ # am--include-marker
 @AMDEP_TRUE@@am__include@ @am__quote@arm/$(DEPDIR)/filter_neon_intrinsics.Plo@am__quote@ # am--include-marker
 @AMDEP_TRUE@@am__include@ @am__quote@arm/$(DEPDIR)/palette_neon_intrinsics.Plo@am__quote@ # am--include-marker
 @AMDEP_TRUE@@am__include@ @am__quote@contrib/libtests/$(DEPDIR)/pngimage.Po@am__quote@ # am--include-marker
@@ -1260,34 +1245,10 @@ distclean-compile:
 
 $(am__depfiles_remade):
 	@$(MKDIR_P) $(@D)
-	@echo '# dummy' >$@-t && $(am__mv) $@-t $@
+	@: >>$@
 
 am--depfiles: $(am__depfiles_remade)
 
-.S.o:
-@am__fastdepCCAS_TRUE@	$(AM_V_CPPAS)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.o$$||'`;\
-@am__fastdepCCAS_TRUE@	$(CPPASCOMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -o $@ $< &&\
-@am__fastdepCCAS_TRUE@	$(am__mv) $$depbase.Tpo $$depbase.Po
-@AMDEP_TRUE@@am__fastdepCCAS_FALSE@	$(AM_V_CPPAS)source='$<' object='$@' libtool=no @AMDEPBACKSLASH@
-@AMDEP_TRUE@@am__fastdepCCAS_FALSE@	DEPDIR=$(DEPDIR) $(CCASDEPMODE) $(depcomp) @AMDEPBACKSLASH@
-@am__fastdepCCAS_FALSE@	$(AM_V_CPPAS@am__nodep@)$(CPPASCOMPILE) -c -o $@ $<
-
-.S.obj:
-@am__fastdepCCAS_TRUE@	$(AM_V_CPPAS)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.obj$$||'`;\
-@am__fastdepCCAS_TRUE@	$(CPPASCOMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -o $@ `$(CYGPATH_W) '$<'` &&\
-@am__fastdepCCAS_TRUE@	$(am__mv) $$depbase.Tpo $$depbase.Po
-@AMDEP_TRUE@@am__fastdepCCAS_FALSE@	$(AM_V_CPPAS)source='$<' object='$@' libtool=no @AMDEPBACKSLASH@
-@AMDEP_TRUE@@am__fastdepCCAS_FALSE@	DEPDIR=$(DEPDIR) $(CCASDEPMODE) $(depcomp) @AMDEPBACKSLASH@
-@am__fastdepCCAS_FALSE@	$(AM_V_CPPAS@am__nodep@)$(CPPASCOMPILE) -c -o $@ `$(CYGPATH_W) '$<'`
-
-.S.lo:
-@am__fastdepCCAS_TRUE@	$(AM_V_CPPAS)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.lo$$||'`;\
-@am__fastdepCCAS_TRUE@	$(LTCPPASCOMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -o $@ $< &&\
-@am__fastdepCCAS_TRUE@	$(am__mv) $$depbase.Tpo $$depbase.Plo
-@AMDEP_TRUE@@am__fastdepCCAS_FALSE@	$(AM_V_CPPAS)source='$<' object='$@' libtool=yes @AMDEPBACKSLASH@
-@AMDEP_TRUE@@am__fastdepCCAS_FALSE@	DEPDIR=$(DEPDIR) $(CCASDEPMODE) $(depcomp) @AMDEPBACKSLASH@
-@am__fastdepCCAS_FALSE@	$(AM_V_CPPAS@am__nodep@)$(LTCPPASCOMPILE) -c -o $@ $<
-
 .c.o:
 @am__fastdepCC_TRUE@	$(AM_V_CC)depbase=`echo $@ | sed 's|[^/]*$$|$(DEPDIR)/&|;s|\.o$$||'`;\
 @am__fastdepCC_TRUE@	$(COMPILE) -MT $@ -MD -MP -MF $$depbase.Tpo -c -o $@ $< &&\
@@ -1561,7 +1522,6 @@ distclean-tags:
 am--fnord $(TEST_LOGS) $(TEST_LOGS:.log=.trs): $(am__force_recheck)
 am--force-recheck:
 	@:
-
 $(TEST_SUITE_LOG): $(TEST_LOGS)
 	@$(am__set_TESTS_bases); \
 	am__f_ok () { test -f "$$1" && test -r "$$1"; }; \
@@ -1637,10 +1597,37 @@ $(TEST_SUITE_LOG): $(TEST_LOGS)
 	  result_count $$1 "XPASS:" $$xpass "$$red"; \
 	  result_count $$1 "ERROR:" $$error "$$mgn"; \
 	}; \
+	output_system_information () \
+	{ \
+          echo;                                     \
+	  { uname -a | $(AWK) '{                    \
+  printf "System information (uname -a):";          \
+  for (i = 1; i < NF; ++i)                          \
+    {                                               \
+      if (i != 2)                                   \
+        printf " %s", $$i;                          \
+    }                                               \
+  printf "\n";                                      \
+}'; } 2>&1;                                         \
+	  if test -r /etc/os-release; then          \
+	    echo "Distribution information (/etc/os-release):"; \
+	    sed 8q /etc/os-release;                 \
+	  elif test -r /etc/issue; then             \
+	    echo "Distribution information (/etc/issue):";      \
+	    cat /etc/issue;                         \
+	  fi;                                       \
+	}; \
+	please_report () \
+	{ \
+echo "Some test(s) failed.  Please report this to $(PACKAGE_BUGREPORT),";    \
+echo "together with the test-suite.log file (gzipped) and your system";      \
+echo "information.  Thanks.";                                                \
+	}; \
 	{								\
 	  echo "$(PACKAGE_STRING): $(subdir)/$(TEST_SUITE_LOG)" |	\
 	    $(am__rst_title);						\
 	  create_testsuite_report --no-color;				\
+	  output_system_information;                                    \
 	  echo;								\
 	  echo ".. contents:: :depth: 2";				\
 	  echo;								\
@@ -1660,26 +1647,25 @@ $(TEST_SUITE_LOG): $(TEST_LOGS)
 	create_testsuite_report --maybe-color;				\
 	echo "$$col$$br$$std";						\
 	if $$success; then :; else					\
-	  echo "$${col}See $(subdir)/$(TEST_SUITE_LOG)$${std}";		\
+	  echo "$${col}See $(subdir)/$(TEST_SUITE_LOG) for debugging.$${std}";\
 	  if test -n "$(PACKAGE_BUGREPORT)"; then			\
-	    echo "$${col}Please report to $(PACKAGE_BUGREPORT)$${std}";	\
+	    please_report | sed -e "s/^/$${col}/" -e s/'$$'/"$${std}"/; \
 	  fi;								\
 	  echo "$$col$$br$$std";					\
 	fi;								\
 	$$success || exit 1
 
 check-TESTS: $(check_PROGRAMS)
-	@list='$(RECHECK_LOGS)';           test -z "$$list" || rm -f $$list
-	@list='$(RECHECK_LOGS:.log=.trs)'; test -z "$$list" || rm -f $$list
-	@test -z "$(TEST_SUITE_LOG)" || rm -f $(TEST_SUITE_LOG)
+	@$(am__rm_f) $(RECHECK_LOGS)
+	@$(am__rm_f) $(RECHECK_LOGS:.log=.trs)
+	@$(am__rm_f) $(TEST_SUITE_LOG)
 	@set +e; $(am__set_TESTS_bases); \
 	log_list=`for i in $$bases; do echo $$i.log; done`; \
-	trs_list=`for i in $$bases; do echo $$i.trs; done`; \
-	log_list=`echo $$log_list`; trs_list=`echo $$trs_list`; \
+	log_list=`echo $$log_list`; \
 	$(MAKE) $(AM_MAKEFLAGS) $(TEST_SUITE_LOG) TEST_LOGS="$$log_list"; \
 	exit $$?;
 recheck: all $(check_PROGRAMS)
-	@test -z "$(TEST_SUITE_LOG)" || rm -f $(TEST_SUITE_LOG)
+	@$(am__rm_f) $(TEST_SUITE_LOG)
 	@set +e; $(am__set_TESTS_bases); \
 	bases=`for i in $$bases; do echo $$i; done \
 	         | $(am__list_recheck_tests)` || exit 1; \
@@ -1932,7 +1918,7 @@ distdir: $(BUILT_SOURCES)
 
 distdir-am: $(DISTFILES)
 	$(am__remove_distdir)
-	test -d "$(distdir)" || mkdir "$(distdir)"
+	$(AM_V_at)$(MKDIR_P) "$(distdir)"
 	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
 	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
 	list='$(DISTFILES)'; \
@@ -2020,7 +2006,7 @@ dist dist-all:
 distcheck: dist
 	case '$(DIST_ARCHIVES)' in \
 	*.tar.gz*) \
-	  eval GZIP= gzip $(GZIP_ENV) -dc $(distdir).tar.gz | $(am__untar) ;;\
+	  eval GZIP= gzip -dc $(distdir).tar.gz | $(am__untar) ;;\
 	*.tar.bz2*) \
 	  bzip2 -dc $(distdir).tar.bz2 | $(am__untar) ;;\
 	*.tar.lz*) \
@@ -2030,7 +2016,7 @@ distcheck: dist
 	*.tar.Z*) \
 	  uncompress -c $(distdir).tar.Z | $(am__untar) ;;\
 	*.shar.gz*) \
-	  eval GZIP= gzip $(GZIP_ENV) -dc $(distdir).shar.gz | unshar ;;\
+	  eval GZIP= gzip -dc $(distdir).shar.gz | unshar ;;\
 	*.zip*) \
 	  unzip $(distdir).zip ;;\
 	*.tar.zst*) \
@@ -2138,36 +2124,36 @@ install-strip:
 	    "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'" install; \
 	fi
 mostlyclean-generic:
-	-test -z "$(TEST_LOGS)" || rm -f $(TEST_LOGS)
-	-test -z "$(TEST_LOGS:.log=.trs)" || rm -f $(TEST_LOGS:.log=.trs)
-	-test -z "$(TEST_SUITE_LOG)" || rm -f $(TEST_SUITE_LOG)
+	-$(am__rm_f) $(TEST_LOGS)
+	-$(am__rm_f) $(TEST_LOGS:.log=.trs)
+	-$(am__rm_f) $(TEST_SUITE_LOG)
 
 clean-generic:
-	-test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)
+	-$(am__rm_f) $(CLEANFILES)
 
 distclean-generic:
-	-test -z "$(CONFIG_CLEAN_FILES)" || rm -f $(CONFIG_CLEAN_FILES)
-	-test . = "$(srcdir)" || test -z "$(CONFIG_CLEAN_VPATH_FILES)" || rm -f $(CONFIG_CLEAN_VPATH_FILES)
-	-rm -f arm/$(DEPDIR)/$(am__dirstamp)
-	-rm -f arm/$(am__dirstamp)
-	-rm -f contrib/libtests/$(DEPDIR)/$(am__dirstamp)
-	-rm -f contrib/libtests/$(am__dirstamp)
-	-rm -f contrib/tools/$(DEPDIR)/$(am__dirstamp)
-	-rm -f contrib/tools/$(am__dirstamp)
-	-rm -f intel/$(DEPDIR)/$(am__dirstamp)
-	-rm -f intel/$(am__dirstamp)
-	-rm -f loongarch/$(DEPDIR)/$(am__dirstamp)
-	-rm -f loongarch/$(am__dirstamp)
-	-rm -f mips/$(DEPDIR)/$(am__dirstamp)
-	-rm -f mips/$(am__dirstamp)
-	-rm -f powerpc/$(DEPDIR)/$(am__dirstamp)
-	-rm -f powerpc/$(am__dirstamp)
+	-$(am__rm_f) $(CONFIG_CLEAN_FILES)
+	-test . = "$(srcdir)" || $(am__rm_f) $(CONFIG_CLEAN_VPATH_FILES)
+	-$(am__rm_f) arm/$(DEPDIR)/$(am__dirstamp)
+	-$(am__rm_f) arm/$(am__dirstamp)
+	-$(am__rm_f) contrib/libtests/$(DEPDIR)/$(am__dirstamp)
+	-$(am__rm_f) contrib/libtests/$(am__dirstamp)
+	-$(am__rm_f) contrib/tools/$(DEPDIR)/$(am__dirstamp)
+	-$(am__rm_f) contrib/tools/$(am__dirstamp)
+	-$(am__rm_f) intel/$(DEPDIR)/$(am__dirstamp)
+	-$(am__rm_f) intel/$(am__dirstamp)
+	-$(am__rm_f) loongarch/$(DEPDIR)/$(am__dirstamp)
+	-$(am__rm_f) loongarch/$(am__dirstamp)
+	-$(am__rm_f) mips/$(DEPDIR)/$(am__dirstamp)
+	-$(am__rm_f) mips/$(am__dirstamp)
+	-$(am__rm_f) powerpc/$(DEPDIR)/$(am__dirstamp)
+	-$(am__rm_f) powerpc/$(am__dirstamp)
 
 maintainer-clean-generic:
 	@echo "This command is intended for maintainers to use"
 	@echo "it deletes files that may require special tools to rebuild."
-	-test -z "$(BUILT_SOURCES)" || rm -f $(BUILT_SOURCES)
-	-test -z "$(MAINTAINERCLEANFILES)" || rm -f $(MAINTAINERCLEANFILES)
+	-$(am__rm_f) $(BUILT_SOURCES)
+	-$(am__rm_f) $(MAINTAINERCLEANFILES)
 @DO_INSTALL_LIBPNG_CONFIG_FALSE@@DO_INSTALL_LINKS_FALSE@install-exec-hook:
 @DO_INSTALL_LIBPNG_PC_FALSE@@DO_INSTALL_LINKS_FALSE@install-data-hook:
 @DO_INSTALL_LIBPNG_CONFIG_FALSE@@DO_INSTALL_LIBPNG_PC_FALSE@@DO_INSTALL_LINKS_FALSE@uninstall-hook:
@@ -2179,7 +2165,7 @@ clean-am: clean-binPROGRAMS clean-checkPROGRAMS clean-generic \
 
 distclean: distclean-am
 	-rm -f $(am__CONFIG_DISTCLEAN_FILES)
-		-rm -f ./$(DEPDIR)/png.Plo
+	-rm -f ./$(DEPDIR)/png.Plo
 	-rm -f ./$(DEPDIR)/pngerror.Plo
 	-rm -f ./$(DEPDIR)/pngget.Plo
 	-rm -f ./$(DEPDIR)/pngmem.Plo
@@ -2196,7 +2182,6 @@ distclean: distclean-am
 	-rm -f ./$(DEPDIR)/pngwtran.Plo
 	-rm -f ./$(DEPDIR)/pngwutil.Plo
 	-rm -f arm/$(DEPDIR)/arm_init.Plo
-	-rm -f arm/$(DEPDIR)/filter_neon.Plo
 	-rm -f arm/$(DEPDIR)/filter_neon_intrinsics.Plo
 	-rm -f arm/$(DEPDIR)/palette_neon_intrinsics.Plo
 	-rm -f contrib/libtests/$(DEPDIR)/pngimage.Po
@@ -2267,7 +2252,7 @@ installcheck-am:
 maintainer-clean: maintainer-clean-am
 	-rm -f $(am__CONFIG_DISTCLEAN_FILES)
 	-rm -rf $(top_srcdir)/autom4te.cache
-		-rm -f ./$(DEPDIR)/png.Plo
+	-rm -f ./$(DEPDIR)/png.Plo
 	-rm -f ./$(DEPDIR)/pngerror.Plo
 	-rm -f ./$(DEPDIR)/pngget.Plo
 	-rm -f ./$(DEPDIR)/pngmem.Plo
@@ -2284,7 +2269,6 @@ maintainer-clean: maintainer-clean-am
 	-rm -f ./$(DEPDIR)/pngwtran.Plo
 	-rm -f ./$(DEPDIR)/pngwutil.Plo
 	-rm -f arm/$(DEPDIR)/arm_init.Plo
-	-rm -f arm/$(DEPDIR)/filter_neon.Plo
 	-rm -f arm/$(DEPDIR)/filter_neon_intrinsics.Plo
 	-rm -f arm/$(DEPDIR)/palette_neon_intrinsics.Plo
 	-rm -f contrib/libtests/$(DEPDIR)/pngimage.Po
@@ -2548,3 +2532,10 @@ all-am: $(check_PROGRAMS)
 # Tell versions [3.59,3.63) of GNU make to not export all variables.
 # Otherwise a system limit (for SysV at least) may be exceeded.
 .NOEXPORT:
+
+# Tell GNU make to disable its built-in pattern rules.
+%:: %,v
+%:: RCS/%,v
+%:: RCS/%
+%:: s.%
+%:: SCCS/s.%
diff --git a/README b/README
index a6ca3ae9f..3af606889 100644
--- a/README
+++ b/README
@@ -1,4 +1,4 @@
-README for libpng version 1.6.43
+README for libpng version 1.6.44
 ================================
 
 See the note about version numbers near the top of `png.h`.
diff --git a/aclocal.m4 b/aclocal.m4
index 20850042a..b93b608e4 100644
--- a/aclocal.m4
+++ b/aclocal.m4
@@ -1,6 +1,6 @@
-# generated automatically by aclocal 1.16.5 -*- Autoconf -*-
+# generated automatically by aclocal 1.17 -*- Autoconf -*-
 
-# Copyright (C) 1996-2021 Free Software Foundation, Inc.
+# Copyright (C) 1996-2024 Free Software Foundation, Inc.
 
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -20,7 +20,7 @@ You have another version of autoconf.  It may work, but is not guaranteed to.
 If you have problems, you may need to regenerate the build system entirely.
 To do so, use the procedure documented by the package, typically 'autoreconf'.])])
 
-# Copyright (C) 2002-2021 Free Software Foundation, Inc.
+# Copyright (C) 2002-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -32,10 +32,10 @@ To do so, use the procedure documented by the package, typically 'autoreconf'.])
 # generated from the m4 files accompanying Automake X.Y.
 # (This private macro should not be called outside this file.)
 AC_DEFUN([AM_AUTOMAKE_VERSION],
-[am__api_version='1.16'
+[am__api_version='1.17'
 dnl Some users find AM_AUTOMAKE_VERSION and mistake it for a way to
 dnl require some minimum version.  Point them to the right macro.
-m4_if([$1], [1.16.5], [],
+m4_if([$1], [1.17], [],
       [AC_FATAL([Do not call $0, use AM_INIT_AUTOMAKE([$1]).])])dnl
 ])
 
@@ -51,14 +51,14 @@ m4_define([_AM_AUTOCONF_VERSION], [])
 # Call AM_AUTOMAKE_VERSION and AM_AUTOMAKE_VERSION so they can be traced.
 # This function is AC_REQUIREd by AM_INIT_AUTOMAKE.
 AC_DEFUN([AM_SET_CURRENT_AUTOMAKE_VERSION],
-[AM_AUTOMAKE_VERSION([1.16.5])dnl
+[AM_AUTOMAKE_VERSION([1.17])dnl
 m4_ifndef([AC_AUTOCONF_VERSION],
   [m4_copy([m4_PACKAGE_VERSION], [AC_AUTOCONF_VERSION])])dnl
 _AM_AUTOCONF_VERSION(m4_defn([AC_AUTOCONF_VERSION]))])
 
 # Figure out how to run the assembler.                      -*- Autoconf -*-
 
-# Copyright (C) 2001-2021 Free Software Foundation, Inc.
+# Copyright (C) 2001-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -78,7 +78,7 @@ _AM_IF_OPTION([no-dependencies],, [_AM_DEPENDENCIES([CCAS])])dnl
 
 # AM_AUX_DIR_EXPAND                                         -*- Autoconf -*-
 
-# Copyright (C) 2001-2021 Free Software Foundation, Inc.
+# Copyright (C) 2001-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -130,7 +130,7 @@ am_aux_dir=`cd "$ac_aux_dir" && pwd`
 
 # AM_CONDITIONAL                                            -*- Autoconf -*-
 
-# Copyright (C) 1997-2021 Free Software Foundation, Inc.
+# Copyright (C) 1997-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -161,7 +161,7 @@ AC_CONFIG_COMMANDS_PRE(
 Usually this means the macro was only invoked conditionally.]])
 fi])])
 
-# Copyright (C) 1999-2021 Free Software Foundation, Inc.
+# Copyright (C) 1999-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -293,7 +293,7 @@ AC_CACHE_CHECK([dependency style of $depcc],
       # icc doesn't choke on unknown options, it will just issue warnings
       # or remarks (even with -Werror).  So we grep stderr for any message
       # that says an option was ignored or not supported.
-      # When given -MP, icc 7.0 and 7.1 complain thusly:
+      # When given -MP, icc 7.0 and 7.1 complain thus:
       #   icc: Command line warning: ignoring option '-M'; no argument required
       # The diagnosis changed in icc 8.0:
       #   icc: Command line remark: option '-MP' not supported
@@ -352,7 +352,7 @@ _AM_SUBST_NOTMAKE([am__nodep])dnl
 
 # Generate code to set up dependency tracking.              -*- Autoconf -*-
 
-# Copyright (C) 1999-2021 Free Software Foundation, Inc.
+# Copyright (C) 1999-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -420,7 +420,7 @@ AC_DEFUN([AM_OUTPUT_DEPENDENCY_COMMANDS],
 
 # Do all the work for Automake.                             -*- Autoconf -*-
 
-# Copyright (C) 1996-2021 Free Software Foundation, Inc.
+# Copyright (C) 1996-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -554,7 +554,7 @@ if test -z "$CSCOPE"; then
 fi
 AC_SUBST([CSCOPE])
 
-AC_REQUIRE([AM_SILENT_RULES])dnl
+AC_REQUIRE([_AM_SILENT_RULES])dnl
 dnl The testsuite driver may need to know about EXEEXT, so add the
 dnl 'am__EXEEXT' conditional if _AM_COMPILER_EXEEXT was seen.  This
 dnl macro is hooked onto _AC_COMPILER_EXEEXT early, see below.
@@ -562,47 +562,9 @@ AC_CONFIG_COMMANDS_PRE(dnl
 [m4_provide_if([_AM_COMPILER_EXEEXT],
   [AM_CONDITIONAL([am__EXEEXT], [test -n "$EXEEXT"])])])dnl
 
-# POSIX will say in a future version that running "rm -f" with no argument
-# is OK; and we want to be able to make that assumption in our Makefile
-# recipes.  So use an aggressive probe to check that the usage we want is
-# actually supported "in the wild" to an acceptable degree.
-# See automake bug#10828.
-# To make any issue more visible, cause the running configure to be aborted
-# by default if the 'rm' program in use doesn't match our expectations; the
-# user can still override this though.
-if rm -f && rm -fr && rm -rf; then : OK; else
-  cat >&2 <<'END'
-Oops!
-
-Your 'rm' program seems unable to run without file operands specified
-on the command line, even when the '-f' option is present.  This is contrary
-to the behaviour of most rm programs out there, and not conforming with
-the upcoming POSIX standard: <http://austingroupbugs.net/view.php?id=542>
-
-Please tell bug-automake@gnu.org about your system, including the value
-of your $PATH and any error possibly output before this message.  This
-can help us improve future automake versions.
+AC_REQUIRE([_AM_PROG_RM_F])
+AC_REQUIRE([_AM_PROG_XARGS_N])
 
-END
-  if test x"$ACCEPT_INFERIOR_RM_PROGRAM" = x"yes"; then
-    echo 'Configuration will proceed anyway, since you have set the' >&2
-    echo 'ACCEPT_INFERIOR_RM_PROGRAM variable to "yes"' >&2
-    echo >&2
-  else
-    cat >&2 <<'END'
-Aborting the configuration process, to ensure you take notice of the issue.
-
-You can download and install GNU coreutils to get an 'rm' implementation
-that behaves properly: <https://www.gnu.org/software/coreutils/>.
-
-If you want to complete the configuration process using your problematic
-'rm' anyway, export the environment variable ACCEPT_INFERIOR_RM_PROGRAM
-to "yes", and re-run configure.
-
-END
-    AC_MSG_ERROR([Your 'rm' program is bad, sorry.])
-  fi
-fi
 dnl The trailing newline in this macro's definition is deliberate, for
 dnl backward compatibility and to allow trailing 'dnl'-style comments
 dnl after the AM_INIT_AUTOMAKE invocation. See automake bug#16841.
@@ -635,7 +597,7 @@ for _am_header in $config_headers :; do
 done
 echo "timestamp for $_am_arg" >`AS_DIRNAME(["$_am_arg"])`/stamp-h[]$_am_stamp_count])
 
-# Copyright (C) 2001-2021 Free Software Foundation, Inc.
+# Copyright (C) 2001-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -656,7 +618,7 @@ if test x"${install_sh+set}" != xset; then
 fi
 AC_SUBST([install_sh])])
 
-# Copyright (C) 2003-2021 Free Software Foundation, Inc.
+# Copyright (C) 2003-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -678,7 +640,7 @@ AC_SUBST([am__leading_dot])])
 # Add --enable-maintainer-mode option to configure.         -*- Autoconf -*-
 # From Jim Meyering
 
-# Copyright (C) 1996-2021 Free Software Foundation, Inc.
+# Copyright (C) 1996-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -713,7 +675,7 @@ AC_MSG_CHECKING([whether to enable maintainer-specific portions of Makefiles])
 
 # Check to see how 'make' treats includes.	            -*- Autoconf -*-
 
-# Copyright (C) 2001-2021 Free Software Foundation, Inc.
+# Copyright (C) 2001-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -756,7 +718,7 @@ AC_SUBST([am__quote])])
 
 # Fake the existence of programs that GNU maintainers use.  -*- Autoconf -*-
 
-# Copyright (C) 1997-2021 Free Software Foundation, Inc.
+# Copyright (C) 1997-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -790,7 +752,7 @@ fi
 
 # Helper functions for option handling.                     -*- Autoconf -*-
 
-# Copyright (C) 2001-2021 Free Software Foundation, Inc.
+# Copyright (C) 2001-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -819,7 +781,7 @@ AC_DEFUN([_AM_SET_OPTIONS],
 AC_DEFUN([_AM_IF_OPTION],
 [m4_ifset(_AM_MANGLE_OPTION([$1]), [$2], [$3])])
 
-# Copyright (C) 1999-2021 Free Software Foundation, Inc.
+# Copyright (C) 1999-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -866,7 +828,23 @@ AC_LANG_POP([C])])
 # For backward compatibility.
 AC_DEFUN_ONCE([AM_PROG_CC_C_O], [AC_REQUIRE([AC_PROG_CC])])
 
-# Copyright (C) 2001-2021 Free Software Foundation, Inc.
+# Copyright (C) 2022-2024 Free Software Foundation, Inc.
+#
+# This file is free software; the Free Software Foundation
+# gives unlimited permission to copy and/or distribute it,
+# with or without modifications, as long as this notice is preserved.
+
+# _AM_PROG_RM_F
+# ---------------
+# Check whether 'rm -f' without any arguments works.
+# https://bugs.gnu.org/10828
+AC_DEFUN([_AM_PROG_RM_F],
+[am__rm_f_notfound=
+AS_IF([(rm -f && rm -fr && rm -rf) 2>/dev/null], [], [am__rm_f_notfound='""'])
+AC_SUBST(am__rm_f_notfound)
+])
+
+# Copyright (C) 2001-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -885,16 +863,169 @@ AC_DEFUN([AM_RUN_LOG],
 
 # Check to make sure that the build environment is sane.    -*- Autoconf -*-
 
-# Copyright (C) 1996-2021 Free Software Foundation, Inc.
+# Copyright (C) 1996-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
 # with or without modifications, as long as this notice is preserved.
 
+# _AM_SLEEP_FRACTIONAL_SECONDS
+# ----------------------------
+AC_DEFUN([_AM_SLEEP_FRACTIONAL_SECONDS], [dnl
+AC_CACHE_CHECK([whether sleep supports fractional seconds],
+               am_cv_sleep_fractional_seconds, [dnl
+AS_IF([sleep 0.001 2>/dev/null], [am_cv_sleep_fractional_seconds=yes],
+                                 [am_cv_sleep_fractional_seconds=no])
+])])
+
+# _AM_FILESYSTEM_TIMESTAMP_RESOLUTION
+# -----------------------------------
+# Determine the filesystem's resolution for file modification
+# timestamps.  The coarsest we know of is FAT, with a resolution
+# of only two seconds, even with the most recent "exFAT" extensions.
+# The finest (e.g. ext4 with large inodes, XFS, ZFS) is one
+# nanosecond, matching clock_gettime.  However, it is probably not
+# possible to delay execution of a shell script for less than one
+# millisecond, due to process creation overhead and scheduling
+# granularity, so we don't check for anything finer than that. (See below.)
+AC_DEFUN([_AM_FILESYSTEM_TIMESTAMP_RESOLUTION], [dnl
+AC_REQUIRE([_AM_SLEEP_FRACTIONAL_SECONDS])
+AC_CACHE_CHECK([filesystem timestamp resolution],
+               am_cv_filesystem_timestamp_resolution, [dnl
+# Default to the worst case.
+am_cv_filesystem_timestamp_resolution=2
+
+# Only try to go finer than 1 sec if sleep can do it.
+# Don't try 1 sec, because if 0.01 sec and 0.1 sec don't work,
+# - 1 sec is not much of a win compared to 2 sec, and
+# - it takes 2 seconds to perform the test whether 1 sec works.
+#
+# Instead, just use the default 2s on platforms that have 1s resolution,
+# accept the extra 1s delay when using $sleep in the Automake tests, in
+# exchange for not incurring the 2s delay for running the test for all
+# packages.
+#
+am_try_resolutions=
+if test "$am_cv_sleep_fractional_seconds" = yes; then
+  # Even a millisecond often causes a bunch of false positives,
+  # so just try a hundredth of a second. The time saved between .001 and
+  # .01 is not terribly consequential.
+  am_try_resolutions="0.01 0.1 $am_try_resolutions"
+fi
+
+# In order to catch current-generation FAT out, we must *modify* files
+# that already exist; the *creation* timestamp is finer.  Use names
+# that make ls -t sort them differently when they have equal
+# timestamps than when they have distinct timestamps, keeping
+# in mind that ls -t prints the *newest* file first.
+rm -f conftest.ts?
+: > conftest.ts1
+: > conftest.ts2
+: > conftest.ts3
+
+# Make sure ls -t actually works.  Do 'set' in a subshell so we don't
+# clobber the current shell's arguments. (Outer-level square brackets
+# are removed by m4; they're present so that m4 does not expand
+# <dollar><star>; be careful, easy to get confused.)
+if (
+     set X `[ls -t conftest.ts[12]]` &&
+     {
+       test "$[]*" != "X conftest.ts1 conftest.ts2" ||
+       test "$[]*" != "X conftest.ts2 conftest.ts1";
+     }
+); then :; else
+  # If neither matched, then we have a broken ls.  This can happen
+  # if, for instance, CONFIG_SHELL is bash and it inherits a
+  # broken ls alias from the environment.  This has actually
+  # happened.  Such a system could not be considered "sane".
+  _AS_ECHO_UNQUOTED(
+    ["Bad output from ls -t: \"`[ls -t conftest.ts[12]]`\""],
+    [AS_MESSAGE_LOG_FD])
+  AC_MSG_FAILURE([ls -t produces unexpected output.
+Make sure there is not a broken ls alias in your environment.])
+fi
+
+for am_try_res in $am_try_resolutions; do
+  # Any one fine-grained sleep might happen to cross the boundary
+  # between two values of a coarser actual resolution, but if we do
+  # two fine-grained sleeps in a row, at least one of them will fall
+  # entirely within a coarse interval.
+  echo alpha > conftest.ts1
+  sleep $am_try_res
+  echo beta > conftest.ts2
+  sleep $am_try_res
+  echo gamma > conftest.ts3
+
+  # We assume that 'ls -t' will make use of high-resolution
+  # timestamps if the operating system supports them at all.
+  if (set X `ls -t conftest.ts?` &&
+      test "$[]2" = conftest.ts3 &&
+      test "$[]3" = conftest.ts2 &&
+      test "$[]4" = conftest.ts1); then
+    #
+    # Ok, ls -t worked. If we're at a resolution of 1 second, we're done,
+    # because we don't need to test make.
+    make_ok=true
+    if test $am_try_res != 1; then
+      # But if we've succeeded so far with a subsecond resolution, we
+      # have one more thing to check: make. It can happen that
+      # everything else supports the subsecond mtimes, but make doesn't;
+      # notably on macOS, which ships make 3.81 from 2006 (the last one
+      # released under GPLv2). https://bugs.gnu.org/68808
+      #
+      # We test $MAKE if it is defined in the environment, else "make".
+      # It might get overridden later, but our hope is that in practice
+      # it does not matter: it is the system "make" which is (by far)
+      # the most likely to be broken, whereas if the user overrides it,
+      # probably they did so with a better, or at least not worse, make.
+      # https://lists.gnu.org/archive/html/automake/2024-06/msg00051.html
+      #
+      # Create a Makefile (real tab character here):
+      rm -f conftest.mk
+      echo 'conftest.ts1: conftest.ts2' >conftest.mk
+      echo '	touch conftest.ts2' >>conftest.mk
+      #
+      # Now, running
+      #   touch conftest.ts1; touch conftest.ts2; make
+      # should touch ts1 because ts2 is newer. This could happen by luck,
+      # but most often, it will fail if make's support is insufficient. So
+      # test for several consecutive successes.
+      #
+      # (We reuse conftest.ts[12] because we still want to modify existing
+      # files, not create new ones, per above.)
+      n=0
+      make=${MAKE-make}
+      until test $n -eq 3; do
+        echo one > conftest.ts1
+        sleep $am_try_res
+        echo two > conftest.ts2 # ts2 should now be newer than ts1
+        if $make -f conftest.mk | grep 'up to date' >/dev/null; then
+          make_ok=false
+          break # out of $n loop
+        fi
+        n=`expr $n + 1`
+      done
+    fi
+    #
+    if $make_ok; then
+      # Everything we know to check worked out, so call this resolution good.
+      am_cv_filesystem_timestamp_resolution=$am_try_res
+      break # out of $am_try_res loop
+    fi
+    # Otherwise, we'll go on to check the next resolution.
+  fi
+done
+rm -f conftest.ts?
+# (end _am_filesystem_timestamp_resolution)
+])])
+
 # AM_SANITY_CHECK
 # ---------------
 AC_DEFUN([AM_SANITY_CHECK],
-[AC_MSG_CHECKING([whether build environment is sane])
+[AC_REQUIRE([_AM_FILESYSTEM_TIMESTAMP_RESOLUTION])
+# This check should not be cached, as it may vary across builds of
+# different projects.
+AC_MSG_CHECKING([whether build environment is sane])
 # Reject unsafe characters in $srcdir or the absolute working directory
 # name.  Accept space and tab only in the latter.
 am_lf='
@@ -913,49 +1044,40 @@ esac
 # symlink; some systems play weird games with the mod time of symlinks
 # (eg FreeBSD returns the mod time of the symlink's containing
 # directory).
-if (
-   am_has_slept=no
-   for am_try in 1 2; do
-     echo "timestamp, slept: $am_has_slept" > conftest.file
-     set X `ls -Lt "$srcdir/configure" conftest.file 2> /dev/null`
-     if test "$[*]" = "X"; then
-	# -L didn't work.
-	set X `ls -t "$srcdir/configure" conftest.file`
-     fi
-     if test "$[*]" != "X $srcdir/configure conftest.file" \
-	&& test "$[*]" != "X conftest.file $srcdir/configure"; then
-
-	# If neither matched, then we have a broken ls.  This can happen
-	# if, for instance, CONFIG_SHELL is bash and it inherits a
-	# broken ls alias from the environment.  This has actually
-	# happened.  Such a system could not be considered "sane".
-	AC_MSG_ERROR([ls -t appears to fail.  Make sure there is not a broken
-  alias in your environment])
-     fi
-     if test "$[2]" = conftest.file || test $am_try -eq 2; then
-       break
-     fi
-     # Just in case.
-     sleep 1
-     am_has_slept=yes
-   done
-   test "$[2]" = conftest.file
-   )
-then
-   # Ok.
-   :
-else
-   AC_MSG_ERROR([newly created file is older than distributed files!
+am_build_env_is_sane=no
+am_has_slept=no
+rm -f conftest.file
+for am_try in 1 2; do
+  echo "timestamp, slept: $am_has_slept" > conftest.file
+  if (
+    set X `ls -Lt "$srcdir/configure" conftest.file 2> /dev/null`
+    if test "$[]*" = "X"; then
+      # -L didn't work.
+      set X `ls -t "$srcdir/configure" conftest.file`
+    fi
+    test "$[]2" = conftest.file
+  ); then
+    am_build_env_is_sane=yes
+    break
+  fi
+  # Just in case.
+  sleep "$am_cv_filesystem_timestamp_resolution"
+  am_has_slept=yes
+done
+
+AC_MSG_RESULT([$am_build_env_is_sane])
+if test "$am_build_env_is_sane" = no; then
+  AC_MSG_ERROR([newly created file is older than distributed files!
 Check your system clock])
 fi
-AC_MSG_RESULT([yes])
+
 # If we didn't sleep, we still need to ensure time stamps of config.status and
 # generated files are strictly newer.
 am_sleep_pid=
-if grep 'slept: no' conftest.file >/dev/null 2>&1; then
-  ( sleep 1 ) &
+AS_IF([test -e conftest.file || grep 'slept: no' conftest.file >/dev/null 2>&1],, [dnl
+  ( sleep "$am_cv_filesystem_timestamp_resolution" ) &
   am_sleep_pid=$!
-fi
+])
 AC_CONFIG_COMMANDS_PRE(
   [AC_MSG_CHECKING([that generated files are newer than configure])
    if test -n "$am_sleep_pid"; then
@@ -966,18 +1088,18 @@ AC_CONFIG_COMMANDS_PRE(
 rm -f conftest.file
 ])
 
-# Copyright (C) 2009-2021 Free Software Foundation, Inc.
+# Copyright (C) 2009-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
 # with or without modifications, as long as this notice is preserved.
 
-# AM_SILENT_RULES([DEFAULT])
-# --------------------------
-# Enable less verbose build rules; with the default set to DEFAULT
-# ("yes" being less verbose, "no" or empty being verbose).
-AC_DEFUN([AM_SILENT_RULES],
-[AC_ARG_ENABLE([silent-rules], [dnl
+# _AM_SILENT_RULES
+# ----------------
+# Enable less verbose build rules support.
+AC_DEFUN([_AM_SILENT_RULES],
+[AM_DEFAULT_VERBOSITY=1
+AC_ARG_ENABLE([silent-rules], [dnl
 AS_HELP_STRING(
   [--enable-silent-rules],
   [less verbose build output (undo: "make V=1")])
@@ -985,11 +1107,6 @@ AS_HELP_STRING(
   [--disable-silent-rules],
   [verbose build output (undo: "make V=0")])dnl
 ])
-case $enable_silent_rules in @%:@ (((
-  yes) AM_DEFAULT_VERBOSITY=0;;
-   no) AM_DEFAULT_VERBOSITY=1;;
-    *) AM_DEFAULT_VERBOSITY=m4_if([$1], [yes], [0], [1]);;
-esac
 dnl
 dnl A few 'make' implementations (e.g., NonStop OS and NextStep)
 dnl do not support nested variable expansions.
@@ -1008,14 +1125,6 @@ am__doit:
 else
   am_cv_make_support_nested_variables=no
 fi])
-if test $am_cv_make_support_nested_variables = yes; then
-  dnl Using '$V' instead of '$(V)' breaks IRIX make.
-  AM_V='$(V)'
-  AM_DEFAULT_V='$(AM_DEFAULT_VERBOSITY)'
-else
-  AM_V=$AM_DEFAULT_VERBOSITY
-  AM_DEFAULT_V=$AM_DEFAULT_VERBOSITY
-fi
 AC_SUBST([AM_V])dnl
 AM_SUBST_NOTMAKE([AM_V])dnl
 AC_SUBST([AM_DEFAULT_V])dnl
@@ -1024,9 +1133,33 @@ AC_SUBST([AM_DEFAULT_VERBOSITY])dnl
 AM_BACKSLASH='\'
 AC_SUBST([AM_BACKSLASH])dnl
 _AM_SUBST_NOTMAKE([AM_BACKSLASH])dnl
+dnl Delay evaluation of AM_DEFAULT_VERBOSITY to the end to allow multiple calls
+dnl to AM_SILENT_RULES to change the default value.
+AC_CONFIG_COMMANDS_PRE([dnl
+case $enable_silent_rules in @%:@ (((
+  yes) AM_DEFAULT_VERBOSITY=0;;
+   no) AM_DEFAULT_VERBOSITY=1;;
+esac
+if test $am_cv_make_support_nested_variables = yes; then
+  dnl Using '$V' instead of '$(V)' breaks IRIX make.
+  AM_V='$(V)'
+  AM_DEFAULT_V='$(AM_DEFAULT_VERBOSITY)'
+else
+  AM_V=$AM_DEFAULT_VERBOSITY
+  AM_DEFAULT_V=$AM_DEFAULT_VERBOSITY
+fi
+])dnl
 ])
 
-# Copyright (C) 2001-2021 Free Software Foundation, Inc.
+# AM_SILENT_RULES([DEFAULT])
+# --------------------------
+# Set the default verbosity level to DEFAULT ("yes" being less verbose, "no" or
+# empty being verbose).
+AC_DEFUN([AM_SILENT_RULES],
+[AC_REQUIRE([_AM_SILENT_RULES])
+AM_DEFAULT_VERBOSITY=m4_if([$1], [yes], [0], [1])])
+
+# Copyright (C) 2001-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -1054,7 +1187,7 @@ fi
 INSTALL_STRIP_PROGRAM="\$(install_sh) -c -s"
 AC_SUBST([INSTALL_STRIP_PROGRAM])])
 
-# Copyright (C) 2006-2021 Free Software Foundation, Inc.
+# Copyright (C) 2006-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -1073,7 +1206,7 @@ AC_DEFUN([AM_SUBST_NOTMAKE], [_AM_SUBST_NOTMAKE($@)])
 
 # Check how to create a tarball.                            -*- Autoconf -*-
 
-# Copyright (C) 2004-2021 Free Software Foundation, Inc.
+# Copyright (C) 2004-2024 Free Software Foundation, Inc.
 #
 # This file is free software; the Free Software Foundation
 # gives unlimited permission to copy and/or distribute it,
@@ -1119,15 +1252,19 @@ m4_if([$1], [v7],
       am_uid=`id -u || echo unknown`
       am_gid=`id -g || echo unknown`
       AC_MSG_CHECKING([whether UID '$am_uid' is supported by ustar format])
-      if test $am_uid -le $am_max_uid; then
-         AC_MSG_RESULT([yes])
+      if test x$am_uid = xunknown; then
+        AC_MSG_WARN([ancient id detected; assuming current UID is ok, but dist-ustar might not work])
+      elif test $am_uid -le $am_max_uid; then
+        AC_MSG_RESULT([yes])
       else
-         AC_MSG_RESULT([no])
-         _am_tools=none
+        AC_MSG_RESULT([no])
+        _am_tools=none
       fi
       AC_MSG_CHECKING([whether GID '$am_gid' is supported by ustar format])
-      if test $am_gid -le $am_max_gid; then
-         AC_MSG_RESULT([yes])
+      if test x$gm_gid = xunknown; then
+        AC_MSG_WARN([ancient id detected; assuming current GID is ok, but dist-ustar might not work])
+      elif test $am_gid -le $am_max_gid; then
+        AC_MSG_RESULT([yes])
       else
         AC_MSG_RESULT([no])
         _am_tools=none
@@ -1204,6 +1341,26 @@ AC_SUBST([am__tar])
 AC_SUBST([am__untar])
 ]) # _AM_PROG_TAR
 
+# Copyright (C) 2022-2024 Free Software Foundation, Inc.
+#
+# This file is free software; the Free Software Foundation
+# gives unlimited permission to copy and/or distribute it,
+# with or without modifications, as long as this notice is preserved.
+
+# _AM_PROG_XARGS_N
+# ----------------
+# Check whether 'xargs -n' works.  It should work everywhere, so the fallback
+# is not optimized at all as we never expect to use it.
+AC_DEFUN([_AM_PROG_XARGS_N],
+[AC_CACHE_CHECK([xargs -n works], am_cv_xargs_n_works, [dnl
+AS_IF([test "`echo 1 2 3 | xargs -n2 echo`" = "1 2
+3"], [am_cv_xargs_n_works=yes], [am_cv_xargs_n_works=no])])
+AS_IF([test "$am_cv_xargs_n_works" = yes], [am__xargs_n='xargs -n'], [dnl
+  am__xargs_n='am__xargs_n () { shift; sed "s/ /\\n/g" | while read am__xargs_n_arg; do "$@" "$am__xargs_n_arg"; done; }'
+])dnl
+AC_SUBST(am__xargs_n)
+])
+
 m4_include([scripts/autoconf/libtool.m4])
 m4_include([scripts/autoconf/ltoptions.m4])
 m4_include([scripts/autoconf/ltsugar.m4])
diff --git a/arm/filter_neon.S b/arm/filter_neon.S
index 2308aad13..fc3c7a296 100644
--- a/arm/filter_neon.S
+++ b/arm/filter_neon.S
@@ -1,253 +1,61 @@
 
-/* filter_neon.S - NEON optimised filter functions
+/* filter_neon.S - placeholder file
  *
- * Copyright (c) 2018 Cosmin Truta
- * Copyright (c) 2014,2017 Glenn Randers-Pehrson
- * Written by Mans Rullgard, 2011.
+ * Copyright (c) 2024 Cosmin Truta
  *
  * This code is released under the libpng license.
  * For conditions of distribution and use, see the disclaimer
  * and license in png.h
  */
 
+/* IMPORTANT NOTE:
+ *
+ * Historically, the hand-coded assembler implementation of Neon optimizations
+ * in this module had not been in sync with the intrinsics-based implementation
+ * in filter_neon_intrinsics.c and palette_neon_intrinsics.c, at least since
+ * the introduction of riffled palette optimizations. Moreover, the assembler
+ * code used to work on 32-bit ARM only, and it caused problems, even if empty,
+ * on 64-bit ARM.
+ *
+ * All references to this module from our internal build scripts and projects
+ * have been removed.
+ *
+ * For the external projects that might still expect this module to be present,
+ * we leave this stub in place, for the remaining lifetime of libpng-1.6.x.
+ * Everything should continue to function normally, as long as there are no
+ * deliberate attempts to use the old hand-made assembler code. A build error
+ * will be raised otherwise.
+ */
+
 /* This is required to get the symbol renames, which are #defines, and the
  * definitions (or not) of PNG_ARM_NEON_OPT and PNG_ARM_NEON_IMPLEMENTATION.
  */
 #define PNG_VERSION_INFO_ONLY
 #include "../pngpriv.h"
 
-#if (defined(__linux__) || defined(__FreeBSD__)) && defined(__ELF__)
-.section .note.GNU-stack,"",%progbits /* mark stack as non-executable */
-#endif
-
 #ifdef PNG_READ_SUPPORTED
-
-/* Assembler NEON support - only works for 32-bit ARM (i.e. it does not work for
- * ARM64).  The code in arm/filter_neon_intrinsics.c supports ARM64, however it
- * only works if -mfpu=neon is specified on the GCC command line.  See pngpriv.h
- * for the logic which sets PNG_USE_ARM_NEON_ASM:
- */
 #if PNG_ARM_NEON_IMPLEMENTATION == 2 /* hand-coded assembler */
-
 #if PNG_ARM_NEON_OPT > 0
 
-#ifdef __ELF__
-#   define ELF
+#if defined(__clang__)
+#define GNUC_VERSION 0 /* not gcc, although it might pretend to be */
+#elif defined(__GNUC__)
+#define GNUC_MAJOR (__GNUC__ + 0)
+#define GNUC_MINOR (__GNUC_MINOR__ + 0)
+#define GNUC_PATCHLEVEL (__GNUC_PATCHLEVEL__ + 0)
+#define GNUC_VERSION (GNUC_MAJOR * 10000 + GNUC_MINOR * 100 + GNUC_PATCHLEVEL)
 #else
-#   define ELF @
+#define GNUC_VERSION 0 /* not gcc */
 #endif
 
-        .arch armv7-a
-        .fpu  neon
-
-.macro  func    name, export=0
-    .macro endfunc
-ELF     .size   \name, . - \name
-        .endfunc
-        .purgem endfunc
-    .endm
-        .text
-
-        /* Explicitly specifying alignment here because some versions of
-         * GAS don't align code correctly.  This is harmless in correctly
-         * written versions of GAS.
-         */
-        .align 2
-
-    .if \export
-        .global \name
-    .endif
-ELF     .type   \name, STT_FUNC
-        .func   \name
-\name:
-.endm
-
-func    png_read_filter_row_sub4_neon, export=1
-        ldr             r3,  [r0, #4]           @ rowbytes
-        vmov.i8         d3,  #0
-1:
-        vld4.32         {d4[],d5[],d6[],d7[]},    [r1,:128]
-        vadd.u8         d0,  d3,  d4
-        vadd.u8         d1,  d0,  d5
-        vadd.u8         d2,  d1,  d6
-        vadd.u8         d3,  d2,  d7
-        vst4.32         {d0[0],d1[0],d2[0],d3[0]},[r1,:128]!
-        subs            r3,  r3,  #16
-        bgt             1b
-
-        bx              lr
-endfunc
-
-func    png_read_filter_row_sub3_neon, export=1
-        ldr             r3,  [r0, #4]           @ rowbytes
-        vmov.i8         d3,  #0
-        mov             r0,  r1
-        mov             r2,  #3
-        mov             r12, #12
-        vld1.8          {q11},    [r0], r12
-1:
-        vext.8          d5,  d22, d23, #3
-        vadd.u8         d0,  d3,  d22
-        vext.8          d6,  d22, d23, #6
-        vadd.u8         d1,  d0,  d5
-        vext.8          d7,  d23, d23, #1
-        vld1.8          {q11},    [r0], r12
-        vst1.32         {d0[0]},  [r1,:32], r2
-        vadd.u8         d2,  d1,  d6
-        vst1.32         {d1[0]},  [r1], r2
-        vadd.u8         d3,  d2,  d7
-        vst1.32         {d2[0]},  [r1], r2
-        vst1.32         {d3[0]},  [r1], r2
-        subs            r3,  r3,  #12
-        bgt             1b
-
-        bx              lr
-endfunc
-
-func    png_read_filter_row_up_neon, export=1
-        ldr             r3,  [r0, #4]           @ rowbytes
-1:
-        vld1.8          {q0}, [r1,:128]
-        vld1.8          {q1}, [r2,:128]!
-        vadd.u8         q0,  q0,  q1
-        vst1.8          {q0}, [r1,:128]!
-        subs            r3,  r3,  #16
-        bgt             1b
-
-        bx              lr
-endfunc
-
-func    png_read_filter_row_avg4_neon, export=1
-        ldr             r12, [r0, #4]           @ rowbytes
-        vmov.i8         d3,  #0
-1:
-        vld4.32         {d4[],d5[],d6[],d7[]},    [r1,:128]
-        vld4.32         {d16[],d17[],d18[],d19[]},[r2,:128]!
-        vhadd.u8        d0,  d3,  d16
-        vadd.u8         d0,  d0,  d4
-        vhadd.u8        d1,  d0,  d17
-        vadd.u8         d1,  d1,  d5
-        vhadd.u8        d2,  d1,  d18
-        vadd.u8         d2,  d2,  d6
-        vhadd.u8        d3,  d2,  d19
-        vadd.u8         d3,  d3,  d7
-        vst4.32         {d0[0],d1[0],d2[0],d3[0]},[r1,:128]!
-        subs            r12, r12, #16
-        bgt             1b
-
-        bx              lr
-endfunc
-
-func    png_read_filter_row_avg3_neon, export=1
-        push            {r4,lr}
-        ldr             r12, [r0, #4]           @ rowbytes
-        vmov.i8         d3,  #0
-        mov             r0,  r1
-        mov             r4,  #3
-        mov             lr,  #12
-        vld1.8          {q11},    [r0], lr
-1:
-        vld1.8          {q10},    [r2], lr
-        vext.8          d5,  d22, d23, #3
-        vhadd.u8        d0,  d3,  d20
-        vext.8          d17, d20, d21, #3
-        vadd.u8         d0,  d0,  d22
-        vext.8          d6,  d22, d23, #6
-        vhadd.u8        d1,  d0,  d17
-        vext.8          d18, d20, d21, #6
-        vadd.u8         d1,  d1,  d5
-        vext.8          d7,  d23, d23, #1
-        vld1.8          {q11},    [r0], lr
-        vst1.32         {d0[0]},  [r1,:32], r4
-        vhadd.u8        d2,  d1,  d18
-        vst1.32         {d1[0]},  [r1], r4
-        vext.8          d19, d21, d21, #1
-        vadd.u8         d2,  d2,  d6
-        vhadd.u8        d3,  d2,  d19
-        vst1.32         {d2[0]},  [r1], r4
-        vadd.u8         d3,  d3,  d7
-        vst1.32         {d3[0]},  [r1], r4
-        subs            r12, r12, #12
-        bgt             1b
-
-        pop             {r4,pc}
-endfunc
-
-.macro  paeth           rx,  ra,  rb,  rc
-        vaddl.u8        q12, \ra, \rb           @ a + b
-        vaddl.u8        q15, \rc, \rc           @ 2*c
-        vabdl.u8        q13, \rb, \rc           @ pa
-        vabdl.u8        q14, \ra, \rc           @ pb
-        vabd.u16        q15, q12, q15           @ pc
-        vcle.u16        q12, q13, q14           @ pa <= pb
-        vcle.u16        q13, q13, q15           @ pa <= pc
-        vcle.u16        q14, q14, q15           @ pb <= pc
-        vand            q12, q12, q13           @ pa <= pb && pa <= pc
-        vmovn.u16       d28, q14
-        vmovn.u16       \rx, q12
-        vbsl            d28, \rb, \rc
-        vbsl            \rx, \ra, d28
-.endm
-
-func    png_read_filter_row_paeth4_neon, export=1
-        ldr             r12, [r0, #4]           @ rowbytes
-        vmov.i8         d3,  #0
-        vmov.i8         d20, #0
-1:
-        vld4.32         {d4[],d5[],d6[],d7[]},    [r1,:128]
-        vld4.32         {d16[],d17[],d18[],d19[]},[r2,:128]!
-        paeth           d0,  d3,  d16, d20
-        vadd.u8         d0,  d0,  d4
-        paeth           d1,  d0,  d17, d16
-        vadd.u8         d1,  d1,  d5
-        paeth           d2,  d1,  d18, d17
-        vadd.u8         d2,  d2,  d6
-        paeth           d3,  d2,  d19, d18
-        vmov            d20, d19
-        vadd.u8         d3,  d3,  d7
-        vst4.32         {d0[0],d1[0],d2[0],d3[0]},[r1,:128]!
-        subs            r12, r12, #16
-        bgt             1b
-
-        bx              lr
-endfunc
-
-func    png_read_filter_row_paeth3_neon, export=1
-        push            {r4,lr}
-        ldr             r12, [r0, #4]           @ rowbytes
-        vmov.i8         d3,  #0
-        vmov.i8         d4,  #0
-        mov             r0,  r1
-        mov             r4,  #3
-        mov             lr,  #12
-        vld1.8          {q11},    [r0], lr
-1:
-        vld1.8          {q10},    [r2], lr
-        paeth           d0,  d3,  d20, d4
-        vext.8          d5,  d22, d23, #3
-        vadd.u8         d0,  d0,  d22
-        vext.8          d17, d20, d21, #3
-        paeth           d1,  d0,  d17, d20
-        vst1.32         {d0[0]},  [r1,:32], r4
-        vext.8          d6,  d22, d23, #6
-        vadd.u8         d1,  d1,  d5
-        vext.8          d18, d20, d21, #6
-        paeth           d2,  d1,  d18, d17
-        vext.8          d7,  d23, d23, #1
-        vld1.8          {q11},    [r0], lr
-        vst1.32         {d1[0]},  [r1], r4
-        vadd.u8         d2,  d2,  d6
-        vext.8          d19, d21, d21, #1
-        paeth           d3,  d2,  d19, d18
-        vst1.32         {d2[0]},  [r1], r4
-        vmov            d4,  d19
-        vadd.u8         d3,  d3,  d7
-        vst1.32         {d3[0]},  [r1], r4
-        subs            r12, r12, #12
-        bgt             1b
+#if (GNUC_VERSION > 0) && (GNUC_VERSION < 40300)
+#error "PNG_ARM_NEON is not supported with gcc versions earlier than 4.3.0"
+#elif GNUC_VERSION == 40504
+#error "PNG_ARM_NEON is not supported with gcc version 4.5.4"
+#else
+#error "Please use 'arm/*_neon_intrinsics.c' for PNG_ARM_NEON support"
+#endif
 
-        pop             {r4,pc}
-endfunc
 #endif /* PNG_ARM_NEON_OPT > 0 */
-#endif /* PNG_ARM_NEON_IMPLEMENTATION == 2 (assembler) */
+#endif /* PNG_ARM_NEON_IMPLEMENTATION == 2 */
 #endif /* READ */
diff --git a/ci/targets/android/ci_env.aarch64-linux-android.sh b/ci/targets/android/ci_env.aarch64-linux-android.sh
new file mode 100644
index 000000000..fef0ef138
--- /dev/null
+++ b/ci/targets/android/ci_env.aarch64-linux-android.sh
@@ -0,0 +1,16 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=aarch64
+export CI_TARGET_ARCHVER=aarch64
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=android
+export CI_TARGET_ABIVER=android29
+
+export CI_CC="$CI_TARGET_ARCHVER-$CI_TARGET_SYSTEM-$CI_TARGET_ABIVER-clang"
+export CI_AR="llvm-ar"
+export CI_RANLIB="llvm-ranlib"
diff --git a/ci/targets/android/ci_env.armv7a-linux-androideabi.sh b/ci/targets/android/ci_env.armv7a-linux-androideabi.sh
new file mode 100644
index 000000000..c27bd121e
--- /dev/null
+++ b/ci/targets/android/ci_env.armv7a-linux-androideabi.sh
@@ -0,0 +1,16 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=arm
+export CI_TARGET_ARCHVER=armv7a
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=androideabi
+export CI_TARGET_ABIVER=androideabi29
+
+export CI_CC="$CI_TARGET_ARCHVER-$CI_TARGET_SYSTEM-$CI_TARGET_ABIVER-clang"
+export CI_AR="llvm-ar"
+export CI_RANLIB="llvm-ranlib"
diff --git a/ci/targets/android/ci_env.i686-linux-android.sh b/ci/targets/android/ci_env.i686-linux-android.sh
new file mode 100644
index 000000000..88e369082
--- /dev/null
+++ b/ci/targets/android/ci_env.i686-linux-android.sh
@@ -0,0 +1,16 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=i686
+export CI_TARGET_ARCHVER=i686
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=android
+export CI_TARGET_ABIVER=android29
+
+export CI_CC="$CI_TARGET_ARCHVER-$CI_TARGET_SYSTEM-$CI_TARGET_ABIVER-clang"
+export CI_AR="llvm-ar"
+export CI_RANLIB="llvm-ranlib"
diff --git a/ci/targets/android/ci_env.x86_64-linux-android.sh b/ci/targets/android/ci_env.x86_64-linux-android.sh
new file mode 100644
index 000000000..87460c888
--- /dev/null
+++ b/ci/targets/android/ci_env.x86_64-linux-android.sh
@@ -0,0 +1,16 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=x86_64
+export CI_TARGET_ARCHVER=x86_64
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=android
+export CI_TARGET_ABIVER=android29
+
+export CI_CC="$CI_TARGET_ARCHVER-$CI_TARGET_SYSTEM-$CI_TARGET_ABIVER-clang"
+export CI_AR="llvm-ar"
+export CI_RANLIB="llvm-ranlib"
diff --git a/ci/targets/cygwin/ci_env.i686-pc-cygwin.sh b/ci/targets/cygwin/ci_env.i686-pc-cygwin.sh
new file mode 100644
index 000000000..66b99997b
--- /dev/null
+++ b/ci/targets/cygwin/ci_env.i686-pc-cygwin.sh
@@ -0,0 +1,18 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=i686
+export CI_TARGET_SYSTEM=cygwin
+
+export CI_CC="$CI_TARGET_ARCH-pc-$CI_TARGET_SYSTEM-gcc"
+export CI_AR="$CI_CC-ar"
+export CI_RANLIB="$CI_CC-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=CYGWIN
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/cygwin/ci_env.x86_64-pc-cygwin.sh b/ci/targets/cygwin/ci_env.x86_64-pc-cygwin.sh
new file mode 100644
index 000000000..78f8c25ff
--- /dev/null
+++ b/ci/targets/cygwin/ci_env.x86_64-pc-cygwin.sh
@@ -0,0 +1,18 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=x86_64
+export CI_TARGET_SYSTEM=cygwin
+
+export CI_CC="$CI_TARGET_ARCH-pc-$CI_TARGET_SYSTEM-gcc"
+export CI_AR="$CI_CC-ar"
+export CI_RANLIB="$CI_CC-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=CYGWIN
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/darwin/ci_env.arm64-apple-darwin.sh b/ci/targets/darwin/ci_env.arm64-apple-darwin.sh
new file mode 100644
index 000000000..c54d8c760
--- /dev/null
+++ b/ci/targets/darwin/ci_env.arm64-apple-darwin.sh
@@ -0,0 +1,15 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=arm64
+export CI_TARGET_SYSTEM=darwin
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Darwin
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+    -DCMAKE_OSX_ARCHITECTURES=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/darwin/ci_env.x86_64-apple-darwin.sh b/ci/targets/darwin/ci_env.x86_64-apple-darwin.sh
new file mode 100644
index 000000000..ee87711d5
--- /dev/null
+++ b/ci/targets/darwin/ci_env.x86_64-apple-darwin.sh
@@ -0,0 +1,15 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=x86_64
+export CI_TARGET_SYSTEM=darwin
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Darwin
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+    -DCMAKE_OSX_ARCHITECTURES=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/freebsd/ci_env.aarch64-unknown-freebsd.sh b/ci/targets/freebsd/ci_env.aarch64-unknown-freebsd.sh
new file mode 100644
index 000000000..42235de7d
--- /dev/null
+++ b/ci/targets/freebsd/ci_env.aarch64-unknown-freebsd.sh
@@ -0,0 +1,14 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=aarch64
+export CI_TARGET_SYSTEM=freebsd
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=FreeBSD
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/freebsd/ci_env.i686-unknown-freebsd.sh b/ci/targets/freebsd/ci_env.i686-unknown-freebsd.sh
new file mode 100644
index 000000000..3d188f8da
--- /dev/null
+++ b/ci/targets/freebsd/ci_env.i686-unknown-freebsd.sh
@@ -0,0 +1,14 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=i686
+export CI_TARGET_SYSTEM=freebsd
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=FreeBSD
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/freebsd/ci_env.riscv64-unknown-freebsd.sh b/ci/targets/freebsd/ci_env.riscv64-unknown-freebsd.sh
new file mode 100644
index 000000000..0a02cde4f
--- /dev/null
+++ b/ci/targets/freebsd/ci_env.riscv64-unknown-freebsd.sh
@@ -0,0 +1,14 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=riscv64
+export CI_TARGET_SYSTEM=freebsd
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=FreeBSD
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/freebsd/ci_env.x86_64-unknown-freebsd.sh b/ci/targets/freebsd/ci_env.x86_64-unknown-freebsd.sh
new file mode 100644
index 000000000..c77ace53b
--- /dev/null
+++ b/ci/targets/freebsd/ci_env.x86_64-unknown-freebsd.sh
@@ -0,0 +1,14 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=x86_64
+export CI_TARGET_SYSTEM=freebsd
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=FreeBSD
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.aarch64-linux-gnu.sh b/ci/targets/linux/ci_env.aarch64-linux-gnu.sh
new file mode 100644
index 000000000..cb85bc6d8
--- /dev/null
+++ b/ci/targets/linux/ci_env.aarch64-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=aarch64
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.arm-linux-gnueabi.sh b/ci/targets/linux/ci_env.arm-linux-gnueabi.sh
new file mode 100644
index 000000000..45504dfcd
--- /dev/null
+++ b/ci/targets/linux/ci_env.arm-linux-gnueabi.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=arm
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnueabi
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.arm-linux-gnueabihf.sh b/ci/targets/linux/ci_env.arm-linux-gnueabihf.sh
new file mode 100644
index 000000000..3eb9d1892
--- /dev/null
+++ b/ci/targets/linux/ci_env.arm-linux-gnueabihf.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=arm
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnueabihf
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.i686-linux-gnu.sh b/ci/targets/linux/ci_env.i686-linux-gnu.sh
new file mode 100644
index 000000000..a5efd9f7f
--- /dev/null
+++ b/ci/targets/linux/ci_env.i686-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=i686
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.mips-linux-gnu.sh b/ci/targets/linux/ci_env.mips-linux-gnu.sh
new file mode 100644
index 000000000..532c93c04
--- /dev/null
+++ b/ci/targets/linux/ci_env.mips-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=mips
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.mips64-linux-gnuabi64.sh b/ci/targets/linux/ci_env.mips64-linux-gnuabi64.sh
new file mode 100644
index 000000000..348d2b800
--- /dev/null
+++ b/ci/targets/linux/ci_env.mips64-linux-gnuabi64.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=mips64
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnuabi64
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.mips64el-linux-gnuabi64.sh b/ci/targets/linux/ci_env.mips64el-linux-gnuabi64.sh
new file mode 100644
index 000000000..e264913d8
--- /dev/null
+++ b/ci/targets/linux/ci_env.mips64el-linux-gnuabi64.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=mips64el
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnuabi64
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.mipsel-linux-gnu.sh b/ci/targets/linux/ci_env.mipsel-linux-gnu.sh
new file mode 100644
index 000000000..f99050f10
--- /dev/null
+++ b/ci/targets/linux/ci_env.mipsel-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=mipsel
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.mipsisa32r6-linux-gnu.sh b/ci/targets/linux/ci_env.mipsisa32r6-linux-gnu.sh
new file mode 100644
index 000000000..0a32867f6
--- /dev/null
+++ b/ci/targets/linux/ci_env.mipsisa32r6-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=mipsisa32r6
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.mipsisa32r6el-linux-gnu.sh b/ci/targets/linux/ci_env.mipsisa32r6el-linux-gnu.sh
new file mode 100644
index 000000000..ca0600930
--- /dev/null
+++ b/ci/targets/linux/ci_env.mipsisa32r6el-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=mipsisa32r6el
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.mipsisa64r6-linux-gnuabi64.sh b/ci/targets/linux/ci_env.mipsisa64r6-linux-gnuabi64.sh
new file mode 100644
index 000000000..6c1138fe6
--- /dev/null
+++ b/ci/targets/linux/ci_env.mipsisa64r6-linux-gnuabi64.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=mipsisa64r6
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnuabi64
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.mipsisa64r6el-linux-gnuabi64.sh b/ci/targets/linux/ci_env.mipsisa64r6el-linux-gnuabi64.sh
new file mode 100644
index 000000000..f64f2fcf4
--- /dev/null
+++ b/ci/targets/linux/ci_env.mipsisa64r6el-linux-gnuabi64.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=mipsisa64r6el
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnuabi64
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.powerpc-linux-gnu.sh b/ci/targets/linux/ci_env.powerpc-linux-gnu.sh
new file mode 100644
index 000000000..e50d9b502
--- /dev/null
+++ b/ci/targets/linux/ci_env.powerpc-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=powerpc
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.powerpc64-linux-gnu.sh b/ci/targets/linux/ci_env.powerpc64-linux-gnu.sh
new file mode 100644
index 000000000..15e60adf2
--- /dev/null
+++ b/ci/targets/linux/ci_env.powerpc64-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=powerpc64
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.powerpc64le-linux-gnu.sh b/ci/targets/linux/ci_env.powerpc64le-linux-gnu.sh
new file mode 100644
index 000000000..be0e2ca69
--- /dev/null
+++ b/ci/targets/linux/ci_env.powerpc64le-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=powerpc64le
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.riscv64-linux-gnu.sh b/ci/targets/linux/ci_env.riscv64-linux-gnu.sh
new file mode 100644
index 000000000..d8518d97f
--- /dev/null
+++ b/ci/targets/linux/ci_env.riscv64-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=riscv64
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/linux/ci_env.x86_64-linux-gnu.sh b/ci/targets/linux/ci_env.x86_64-linux-gnu.sh
new file mode 100644
index 000000000..3263fbff8
--- /dev/null
+++ b/ci/targets/linux/ci_env.x86_64-linux-gnu.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=x86_64
+export CI_TARGET_SYSTEM=linux
+export CI_TARGET_ABI=gnu
+
+export CI_GCC="${CI_GCC-gcc}"
+
+export CI_CC="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-$CI_GCC"
+export CI_AR="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ar"
+export CI_RANLIB="$CI_TARGET_ARCH-$CI_TARGET_SYSTEM-$CI_TARGET_ABI-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Linux
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/msdos/ci_env.i386-pc-msdoswatcom.sh b/ci/targets/msdos/ci_env.i386-pc-msdoswatcom.sh
new file mode 100644
index 000000000..59f3bd58f
--- /dev/null
+++ b/ci/targets/msdos/ci_env.i386-pc-msdoswatcom.sh
@@ -0,0 +1,18 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=i386
+export CI_TARGET_SYSTEM=msdoswatcom
+
+export CI_CC="wcl386"
+
+# Open Watcom V2 CMake build
+# https://github.com/open-watcom/open-watcom-v2/discussions/716
+export CI_CMAKE_GENERATOR="Watcom WMake"
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=DOS
+"
diff --git a/ci/targets/msdos/ci_env.i586-pc-msdosdjgpp.sh b/ci/targets/msdos/ci_env.i586-pc-msdosdjgpp.sh
new file mode 100644
index 000000000..63e6d0676
--- /dev/null
+++ b/ci/targets/msdos/ci_env.i586-pc-msdosdjgpp.sh
@@ -0,0 +1,18 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=i586
+export CI_TARGET_SYSTEM=msdosdjgpp
+
+export CI_CC="$CI_TARGET_ARCH-pc-$CI_TARGET_SYSTEM-gcc"
+export CI_AR="$CI_CC-ar"
+export CI_RANLIB="$CI_CC-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Generic
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/msdos/ci_env.i86-pc-msdoswatcom.sh b/ci/targets/msdos/ci_env.i86-pc-msdoswatcom.sh
new file mode 100644
index 000000000..3059f1835
--- /dev/null
+++ b/ci/targets/msdos/ci_env.i86-pc-msdoswatcom.sh
@@ -0,0 +1,19 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=i86
+export CI_TARGET_SYSTEM=msdoswatcom
+
+export CI_CC="wcl"
+
+# Open Watcom V2 CMake build
+# https://github.com/open-watcom/open-watcom-v2/discussions/716
+export CI_CMAKE_GENERATOR="Watcom WMake"
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=DOS
+    -DCMAKE_SYSTEM_PROCESSOR=I86
+"
diff --git a/ci/targets/windows/ci_env.aarch64-windows-llvm.sh b/ci/targets/windows/ci_env.aarch64-windows-llvm.sh
new file mode 100644
index 000000000..80244172a
--- /dev/null
+++ b/ci/targets/windows/ci_env.aarch64-windows-llvm.sh
@@ -0,0 +1,18 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=aarch64
+export CI_TARGET_SYSTEM=windows
+
+export CI_CC="clang"
+export CI_AR="llvm-ar"
+export CI_RANLIB="llvm-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Windows
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/windows/ci_env.i686-w64-mingw32.sh b/ci/targets/windows/ci_env.i686-w64-mingw32.sh
new file mode 100644
index 000000000..8c83d0f2c
--- /dev/null
+++ b/ci/targets/windows/ci_env.i686-w64-mingw32.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=i686
+export CI_TARGET_SYSTEM=mingw32
+
+# The output of `uname -s` on MSYS2 is understandable, and so is
+# CI_TARGET_SYSTEM above, in simplified form. (See also Cygwin.)
+# But aside from that, the Mingw-w64 nomenclature is rather messy.
+export CI_CC="$CI_TARGET_ARCH-w64-mingw32-gcc"
+export CI_AR="$CI_CC-ar"
+export CI_RANLIB="$CI_CC-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Windows
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/windows/ci_env.i686-windows-llvm.sh b/ci/targets/windows/ci_env.i686-windows-llvm.sh
new file mode 100644
index 000000000..3d29f6d55
--- /dev/null
+++ b/ci/targets/windows/ci_env.i686-windows-llvm.sh
@@ -0,0 +1,18 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=i686
+export CI_TARGET_SYSTEM=windows
+
+export CI_CC="clang"
+export CI_AR="llvm-ar"
+export CI_RANLIB="llvm-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Windows
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/windows/ci_env.x86_64-w64-mingw32.sh b/ci/targets/windows/ci_env.x86_64-w64-mingw32.sh
new file mode 100644
index 000000000..67d83557b
--- /dev/null
+++ b/ci/targets/windows/ci_env.x86_64-w64-mingw32.sh
@@ -0,0 +1,21 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=x86_64
+export CI_TARGET_SYSTEM=mingw64
+
+# The output of `uname -s` on MSYS2 is understandable, and so is
+# CI_TARGET_SYSTEM above, in simplified form. (See also Cygwin.)
+# But aside from that, the Mingw-w64 nomenclature is rather messy.
+export CI_CC="$CI_TARGET_ARCH-w64-mingw32-gcc"
+export CI_AR="$CI_CC-ar"
+export CI_RANLIB="$CI_CC-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Windows
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/ci/targets/windows/ci_env.x86_64-windows-llvm.sh b/ci/targets/windows/ci_env.x86_64-windows-llvm.sh
new file mode 100644
index 000000000..747f99b21
--- /dev/null
+++ b/ci/targets/windows/ci_env.x86_64-windows-llvm.sh
@@ -0,0 +1,18 @@
+# Copyright (c) 2023-2024 Cosmin Truta.
+#
+# Use, modification and distribution are subject to the MIT License.
+# Please see the accompanying file LICENSE_MIT.txt
+#
+# SPDX-License-Identifier: MIT
+
+export CI_TARGET_ARCH=x86_64
+export CI_TARGET_SYSTEM=windows
+
+export CI_CC="clang"
+export CI_AR="llvm-ar"
+export CI_RANLIB="llvm-ranlib"
+
+export CI_CMAKE_VARS="
+    -DCMAKE_SYSTEM_NAME=Windows
+    -DCMAKE_SYSTEM_PROCESSOR=$CI_TARGET_ARCH
+"
diff --git a/compile b/compile
index df363c8fb..49b3d05fd 100755
--- a/compile
+++ b/compile
@@ -1,9 +1,9 @@
 #! /bin/sh
 # Wrapper for compilers which do not understand '-c -o'.
 
-scriptversion=2018-03-07.03; # UTC
+scriptversion=2024-06-19.01; # UTC
 
-# Copyright (C) 1999-2021 Free Software Foundation, Inc.
+# Copyright (C) 1999-2024 Free Software Foundation, Inc.
 # Written by Tom Tromey <tromey@cygnus.com>.
 #
 # This program is free software; you can redistribute it and/or modify
@@ -143,7 +143,7 @@ func_cl_wrapper ()
 	  # configure might choose to run compile as 'compile cc -o foo foo.c'.
 	  eat=1
 	  case $2 in
-	    *.o | *.[oO][bB][jJ])
+	    *.o | *.lo | *.[oO][bB][jJ])
 	      func_file_conv "$2"
 	      set x "$@" -Fo"$file"
 	      shift
@@ -248,14 +248,17 @@ If you are trying to build a whole package this is not the
 right script to run: please start by reading the file 'INSTALL'.
 
 Report bugs to <bug-automake@gnu.org>.
+GNU Automake home page: <https://www.gnu.org/software/automake/>.
+General help using GNU software: <https://www.gnu.org/gethelp/>.
 EOF
     exit $?
     ;;
   -v | --v*)
-    echo "compile $scriptversion"
+    echo "compile (GNU Automake) $scriptversion"
     exit $?
     ;;
   cl | *[/\\]cl | cl.exe | *[/\\]cl.exe | \
+  clang-cl | *[/\\]clang-cl | clang-cl.exe | *[/\\]clang-cl.exe | \
   icl | *[/\\]icl | icl.exe | *[/\\]icl.exe )
     func_cl_wrapper "$@"      # Doesn't return...
     ;;
diff --git a/config.guess b/config.guess
index cdfc43920..f6d217a49 100755
--- a/config.guess
+++ b/config.guess
@@ -1,10 +1,10 @@
 #! /bin/sh
 # Attempt to guess a canonical system name.
-#   Copyright 1992-2023 Free Software Foundation, Inc.
+#   Copyright 1992-2024 Free Software Foundation, Inc.
 
 # shellcheck disable=SC2006,SC2268 # see below for rationale
 
-timestamp='2023-08-22'
+timestamp='2024-01-01'
 
 # This file is free software; you can redistribute it and/or modify it
 # under the terms of the GNU General Public License as published by
@@ -60,7 +60,7 @@ version="\
 GNU config.guess ($timestamp)
 
 Originally written by Per Bothner.
-Copyright 1992-2023 Free Software Foundation, Inc.
+Copyright 1992-2024 Free Software Foundation, Inc.
 
 This is free software; see the source for copying conditions.  There is NO
 warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
@@ -165,6 +165,8 @@ Linux|GNU|GNU/*)
 	LIBC=dietlibc
 	#elif defined(__GLIBC__)
 	LIBC=gnu
+	#elif defined(__LLVM_LIBC__)
+	LIBC=llvm
 	#else
 	#include <stdarg.h>
 	/* First heuristic to detect musl libc.  */
@@ -1593,6 +1595,9 @@ EOF
     *:Unleashed:*:*)
 	GUESS=$UNAME_MACHINE-unknown-unleashed$UNAME_RELEASE
 	;;
+    *:Ironclad:*:*)
+	GUESS=$UNAME_MACHINE-unknown-ironclad
+	;;
 esac
 
 # Do we have a guess based on uname results?
diff --git a/config.sub b/config.sub
index defe52c0c..2c6a07ab3 100755
--- a/config.sub
+++ b/config.sub
@@ -1,10 +1,10 @@
 #! /bin/sh
 # Configuration validation subroutine script.
-#   Copyright 1992-2023 Free Software Foundation, Inc.
+#   Copyright 1992-2024 Free Software Foundation, Inc.
 
 # shellcheck disable=SC2006,SC2268 # see below for rationale
 
-timestamp='2023-09-19'
+timestamp='2024-01-01'
 
 # This file is free software; you can redistribute it and/or modify it
 # under the terms of the GNU General Public License as published by
@@ -76,7 +76,7 @@ Report bugs and patches to <config-patches@gnu.org>."
 version="\
 GNU config.sub ($timestamp)
 
-Copyright 1992-2023 Free Software Foundation, Inc.
+Copyright 1992-2024 Free Software Foundation, Inc.
 
 This is free software; see the source for copying conditions.  There is NO
 warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
@@ -1222,6 +1222,7 @@ case $cpu-$vendor in
 			| moxie \
 			| mt \
 			| msp430 \
+			| nanomips* \
 			| nds32 | nds32le | nds32be \
 			| nfp \
 			| nios | nios2 | nios2eb | nios2el \
@@ -1253,6 +1254,7 @@ case $cpu-$vendor in
 			| ubicom32 \
 			| v70 | v850 | v850e | v850e1 | v850es | v850e2 | v850e2v3 \
 			| vax \
+			| vc4 \
 			| visium \
 			| w65 \
 			| wasm32 | wasm64 \
@@ -1597,7 +1599,7 @@ case $cpu-$vendor in
 		os=
 		obj=elf
 		;;
-	mips*-*)
+	mips*-*|nanomips*-*)
 		os=
 		obj=elf
 		;;
@@ -1721,7 +1723,7 @@ fi
 
 case $os in
 	# Sometimes we do "kernel-libc", so those need to count as OSes.
-	musl* | newlib* | relibc* | uclibc*)
+	llvm* | musl* | newlib* | relibc* | uclibc*)
 		;;
 	# Likewise for "kernel-abi"
 	eabi* | gnueabi*)
@@ -1766,12 +1768,19 @@ case $os in
 	     | onefs* | tirtos* | phoenix* | fuchsia* | redox* | bme* \
 	     | midnightbsd* | amdhsa* | unleashed* | emscripten* | wasi* \
 	     | nsk* | powerunix* | genode* | zvmoe* | qnx* | emx* | zephyr* \
-	     | fiwix* | mlibc* | cos* | mbr* )
+	     | fiwix* | mlibc* | cos* | mbr* | ironclad* )
 		;;
 	# This one is extra strict with allowed versions
 	sco3.2v2 | sco3.2v[4-9]* | sco5v6*)
 		# Don't forget version if it is 3.2v4 or newer.
 		;;
+	# This refers to builds using the UEFI calling convention
+	# (which depends on the architecture) and PE file format.
+	# Note that this is both a different calling convention and
+	# different file format than that of GNU-EFI
+	# (x86_64-w64-mingw32).
+	uefi)
+		;;
 	none)
 		;;
 	kernel* | msvc* )
@@ -1818,8 +1827,9 @@ esac
 # As a final step for OS-related things, validate the OS-kernel combination
 # (given a valid OS), if there is a kernel.
 case $kernel-$os-$obj in
-	linux-gnu*- | linux-dietlibc*- | linux-android*- | linux-newlib*- \
-		   | linux-musl*- | linux-relibc*- | linux-uclibc*- | linux-mlibc*- )
+	linux-gnu*- | linux-android*- | linux-dietlibc*- | linux-llvm*- \
+		    | linux-mlibc*- | linux-musl*- | linux-newlib*- \
+		    | linux-relibc*- | linux-uclibc*- )
 		;;
 	uclinux-uclibc*- )
 		;;
@@ -1827,7 +1837,8 @@ case $kernel-$os-$obj in
 		;;
 	windows*-msvc*-)
 		;;
-	-dietlibc*- | -newlib*- | -musl*- | -relibc*- | -uclibc*- | -mlibc*- )
+	-dietlibc*- | -llvm*- | -mlibc*- | -musl*- | -newlib*- | -relibc*- \
+		    | -uclibc*- )
 		# These are just libc implementations, not actual OSes, and thus
 		# require a kernel.
 		echo "Invalid configuration '$1': libc '$os' needs explicit kernel." 1>&2
diff --git a/configure b/configure
index ca475f771..f2048dd7f 100755
--- a/configure
+++ b/configure
@@ -1,6 +1,6 @@
 #! /bin/sh
 # Guess values for system-dependent variables and create Makefiles.
-# Generated by GNU Autoconf 2.72 for libpng 1.6.43.
+# Generated by GNU Autoconf 2.72 for libpng 1.6.44.
 #
 # Report bugs to <png-mng-implement@lists.sourceforge.net>.
 #
@@ -614,8 +614,8 @@ MAKEFLAGS=
 # Identity of this package.
 PACKAGE_NAME='libpng'
 PACKAGE_TARNAME='libpng'
-PACKAGE_VERSION='1.6.43'
-PACKAGE_STRING='libpng 1.6.43'
+PACKAGE_VERSION='1.6.44'
+PACKAGE_STRING='libpng 1.6.44'
 PACKAGE_BUGREPORT='png-mng-implement@lists.sourceforge.net'
 PACKAGE_URL=''
 
@@ -753,6 +753,8 @@ CC
 MAINT
 MAINTAINER_MODE_FALSE
 MAINTAINER_MODE_TRUE
+am__xargs_n
+am__rm_f_notfound
 AM_BACKSLASH
 AM_DEFAULT_VERBOSITY
 AM_DEFAULT_V
@@ -1417,7 +1419,7 @@ if test "$ac_init_help" = "long"; then
   # Omit some internal or obsolete options to make the list less imposing.
   # This message is too long to be a string in the A/UX 3.1 sh.
   cat <<_ACEOF
-'configure' configures libpng 1.6.43 to adapt to many kinds of systems.
+'configure' configures libpng 1.6.44 to adapt to many kinds of systems.
 
 Usage: $0 [OPTION]... [VAR=VALUE]...
 
@@ -1488,7 +1490,7 @@ fi
 
 if test -n "$ac_init_help"; then
   case $ac_init_help in
-     short | recursive ) echo "Configuration of libpng 1.6.43:";;
+     short | recursive ) echo "Configuration of libpng 1.6.44:";;
    esac
   cat <<\_ACEOF
 
@@ -1685,7 +1687,7 @@ fi
 test -n "$ac_init_help" && exit $ac_status
 if $ac_init_version; then
   cat <<\_ACEOF
-libpng configure 1.6.43
+libpng configure 1.6.44
 generated by GNU Autoconf 2.72
 
 Copyright (C) 2023 Free Software Foundation, Inc.
@@ -1948,7 +1950,7 @@ cat >config.log <<_ACEOF
 This file contains any messages produced by compilers while
 running configure, to aid debugging if configure makes a mistake.
 
-It was created by libpng $as_me 1.6.43, which was
+It was created by libpng $as_me 1.6.44, which was
 generated by GNU Autoconf 2.72.  Invocation command line was
 
   $ $0$ac_configure_args_raw
@@ -2729,7 +2731,7 @@ ac_compiler_gnu=$ac_cv_c_compiler_gnu
 # dist-xz requires automake 1.11 or later
 # 1.12.2 fixes a security issue in 1.11.2 and 1.12.1
 # 1.13 is required for parallel tests
-am__api_version='1.16'
+am__api_version='1.17'
 
 
 
@@ -2832,6 +2834,165 @@ test -z "$INSTALL_SCRIPT" && INSTALL_SCRIPT='${INSTALL}'
 
 test -z "$INSTALL_DATA" && INSTALL_DATA='${INSTALL} -m 644'
 
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking whether sleep supports fractional seconds" >&5
+printf %s "checking whether sleep supports fractional seconds... " >&6; }
+if test ${am_cv_sleep_fractional_seconds+y}
+then :
+  printf %s "(cached) " >&6
+else case e in #(
+  e) if sleep 0.001 2>/dev/null
+then :
+  am_cv_sleep_fractional_seconds=yes
+else case e in #(
+  e) am_cv_sleep_fractional_seconds=no ;;
+esac
+fi
+ ;;
+esac
+fi
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $am_cv_sleep_fractional_seconds" >&5
+printf "%s\n" "$am_cv_sleep_fractional_seconds" >&6; }
+
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking filesystem timestamp resolution" >&5
+printf %s "checking filesystem timestamp resolution... " >&6; }
+if test ${am_cv_filesystem_timestamp_resolution+y}
+then :
+  printf %s "(cached) " >&6
+else case e in #(
+  e) # Default to the worst case.
+am_cv_filesystem_timestamp_resolution=2
+
+# Only try to go finer than 1 sec if sleep can do it.
+# Don't try 1 sec, because if 0.01 sec and 0.1 sec don't work,
+# - 1 sec is not much of a win compared to 2 sec, and
+# - it takes 2 seconds to perform the test whether 1 sec works.
+#
+# Instead, just use the default 2s on platforms that have 1s resolution,
+# accept the extra 1s delay when using $sleep in the Automake tests, in
+# exchange for not incurring the 2s delay for running the test for all
+# packages.
+#
+am_try_resolutions=
+if test "$am_cv_sleep_fractional_seconds" = yes; then
+  # Even a millisecond often causes a bunch of false positives,
+  # so just try a hundredth of a second. The time saved between .001 and
+  # .01 is not terribly consequential.
+  am_try_resolutions="0.01 0.1 $am_try_resolutions"
+fi
+
+# In order to catch current-generation FAT out, we must *modify* files
+# that already exist; the *creation* timestamp is finer.  Use names
+# that make ls -t sort them differently when they have equal
+# timestamps than when they have distinct timestamps, keeping
+# in mind that ls -t prints the *newest* file first.
+rm -f conftest.ts?
+: > conftest.ts1
+: > conftest.ts2
+: > conftest.ts3
+
+# Make sure ls -t actually works.  Do 'set' in a subshell so we don't
+# clobber the current shell's arguments. (Outer-level square brackets
+# are removed by m4; they're present so that m4 does not expand
+# <dollar><star>; be careful, easy to get confused.)
+if (
+     set X `ls -t conftest.ts[12]` &&
+     {
+       test "$*" != "X conftest.ts1 conftest.ts2" ||
+       test "$*" != "X conftest.ts2 conftest.ts1";
+     }
+); then :; else
+  # If neither matched, then we have a broken ls.  This can happen
+  # if, for instance, CONFIG_SHELL is bash and it inherits a
+  # broken ls alias from the environment.  This has actually
+  # happened.  Such a system could not be considered "sane".
+  printf "%s\n" ""Bad output from ls -t: \"`ls -t conftest.ts[12]`\""" >&5
+  { { printf "%s\n" "$as_me:${as_lineno-$LINENO}: error: in '$ac_pwd':" >&5
+printf "%s\n" "$as_me: error: in '$ac_pwd':" >&2;}
+as_fn_error $? "ls -t produces unexpected output.
+Make sure there is not a broken ls alias in your environment.
+See 'config.log' for more details" "$LINENO" 5; }
+fi
+
+for am_try_res in $am_try_resolutions; do
+  # Any one fine-grained sleep might happen to cross the boundary
+  # between two values of a coarser actual resolution, but if we do
+  # two fine-grained sleeps in a row, at least one of them will fall
+  # entirely within a coarse interval.
+  echo alpha > conftest.ts1
+  sleep $am_try_res
+  echo beta > conftest.ts2
+  sleep $am_try_res
+  echo gamma > conftest.ts3
+
+  # We assume that 'ls -t' will make use of high-resolution
+  # timestamps if the operating system supports them at all.
+  if (set X `ls -t conftest.ts?` &&
+      test "$2" = conftest.ts3 &&
+      test "$3" = conftest.ts2 &&
+      test "$4" = conftest.ts1); then
+    #
+    # Ok, ls -t worked. If we're at a resolution of 1 second, we're done,
+    # because we don't need to test make.
+    make_ok=true
+    if test $am_try_res != 1; then
+      # But if we've succeeded so far with a subsecond resolution, we
+      # have one more thing to check: make. It can happen that
+      # everything else supports the subsecond mtimes, but make doesn't;
+      # notably on macOS, which ships make 3.81 from 2006 (the last one
+      # released under GPLv2). https://bugs.gnu.org/68808
+      #
+      # We test $MAKE if it is defined in the environment, else "make".
+      # It might get overridden later, but our hope is that in practice
+      # it does not matter: it is the system "make" which is (by far)
+      # the most likely to be broken, whereas if the user overrides it,
+      # probably they did so with a better, or at least not worse, make.
+      # https://lists.gnu.org/archive/html/automake/2024-06/msg00051.html
+      #
+      # Create a Makefile (real tab character here):
+      rm -f conftest.mk
+      echo 'conftest.ts1: conftest.ts2' >conftest.mk
+      echo '	touch conftest.ts2' >>conftest.mk
+      #
+      # Now, running
+      #   touch conftest.ts1; touch conftest.ts2; make
+      # should touch ts1 because ts2 is newer. This could happen by luck,
+      # but most often, it will fail if make's support is insufficient. So
+      # test for several consecutive successes.
+      #
+      # (We reuse conftest.ts[12] because we still want to modify existing
+      # files, not create new ones, per above.)
+      n=0
+      make=${MAKE-make}
+      until test $n -eq 3; do
+        echo one > conftest.ts1
+        sleep $am_try_res
+        echo two > conftest.ts2 # ts2 should now be newer than ts1
+        if $make -f conftest.mk | grep 'up to date' >/dev/null; then
+          make_ok=false
+          break # out of $n loop
+        fi
+        n=`expr $n + 1`
+      done
+    fi
+    #
+    if $make_ok; then
+      # Everything we know to check worked out, so call this resolution good.
+      am_cv_filesystem_timestamp_resolution=$am_try_res
+      break # out of $am_try_res loop
+    fi
+    # Otherwise, we'll go on to check the next resolution.
+  fi
+done
+rm -f conftest.ts?
+# (end _am_filesystem_timestamp_resolution)
+ ;;
+esac
+fi
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $am_cv_filesystem_timestamp_resolution" >&5
+printf "%s\n" "$am_cv_filesystem_timestamp_resolution" >&6; }
+
+# This check should not be cached, as it may vary across builds of
+# different projects.
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking whether build environment is sane" >&5
 printf %s "checking whether build environment is sane... " >&6; }
 # Reject unsafe characters in $srcdir or the absolute working directory
@@ -2852,49 +3013,45 @@ esac
 # symlink; some systems play weird games with the mod time of symlinks
 # (eg FreeBSD returns the mod time of the symlink's containing
 # directory).
-if (
-   am_has_slept=no
-   for am_try in 1 2; do
-     echo "timestamp, slept: $am_has_slept" > conftest.file
-     set X `ls -Lt "$srcdir/configure" conftest.file 2> /dev/null`
-     if test "$*" = "X"; then
-	# -L didn't work.
-	set X `ls -t "$srcdir/configure" conftest.file`
-     fi
-     if test "$*" != "X $srcdir/configure conftest.file" \
-	&& test "$*" != "X conftest.file $srcdir/configure"; then
-
-	# If neither matched, then we have a broken ls.  This can happen
-	# if, for instance, CONFIG_SHELL is bash and it inherits a
-	# broken ls alias from the environment.  This has actually
-	# happened.  Such a system could not be considered "sane".
-	as_fn_error $? "ls -t appears to fail.  Make sure there is not a broken
-  alias in your environment" "$LINENO" 5
-     fi
-     if test "$2" = conftest.file || test $am_try -eq 2; then
-       break
-     fi
-     # Just in case.
-     sleep 1
-     am_has_slept=yes
-   done
-   test "$2" = conftest.file
-   )
-then
-   # Ok.
-   :
-else
-   as_fn_error $? "newly created file is older than distributed files!
+am_build_env_is_sane=no
+am_has_slept=no
+rm -f conftest.file
+for am_try in 1 2; do
+  echo "timestamp, slept: $am_has_slept" > conftest.file
+  if (
+    set X `ls -Lt "$srcdir/configure" conftest.file 2> /dev/null`
+    if test "$*" = "X"; then
+      # -L didn't work.
+      set X `ls -t "$srcdir/configure" conftest.file`
+    fi
+    test "$2" = conftest.file
+  ); then
+    am_build_env_is_sane=yes
+    break
+  fi
+  # Just in case.
+  sleep "$am_cv_filesystem_timestamp_resolution"
+  am_has_slept=yes
+done
+
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $am_build_env_is_sane" >&5
+printf "%s\n" "$am_build_env_is_sane" >&6; }
+if test "$am_build_env_is_sane" = no; then
+  as_fn_error $? "newly created file is older than distributed files!
 Check your system clock" "$LINENO" 5
 fi
-{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: yes" >&5
-printf "%s\n" "yes" >&6; }
+
 # If we didn't sleep, we still need to ensure time stamps of config.status and
 # generated files are strictly newer.
 am_sleep_pid=
-if grep 'slept: no' conftest.file >/dev/null 2>&1; then
-  ( sleep 1 ) &
+if test -e conftest.file || grep 'slept: no' conftest.file >/dev/null 2>&1
+then :
+
+else case e in #(
+  e)   ( sleep "$am_cv_filesystem_timestamp_resolution" ) &
   am_sleep_pid=$!
+ ;;
+esac
 fi
 
 rm -f conftest.file
@@ -3184,17 +3341,13 @@ else
 fi
 rmdir .tst 2>/dev/null
 
+AM_DEFAULT_VERBOSITY=1
 # Check whether --enable-silent-rules was given.
 if test ${enable_silent_rules+y}
 then :
   enableval=$enable_silent_rules;
 fi
 
-case $enable_silent_rules in # (((
-  yes) AM_DEFAULT_VERBOSITY=0;;
-   no) AM_DEFAULT_VERBOSITY=1;;
-    *) AM_DEFAULT_VERBOSITY=1;;
-esac
 am_make=${MAKE-make}
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking whether $am_make supports nested variables" >&5
 printf %s "checking whether $am_make supports nested variables... " >&6; }
@@ -3217,15 +3370,45 @@ esac
 fi
 { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $am_cv_make_support_nested_variables" >&5
 printf "%s\n" "$am_cv_make_support_nested_variables" >&6; }
-if test $am_cv_make_support_nested_variables = yes; then
-    AM_V='$(V)'
-  AM_DEFAULT_V='$(AM_DEFAULT_VERBOSITY)'
-else
-  AM_V=$AM_DEFAULT_VERBOSITY
-  AM_DEFAULT_V=$AM_DEFAULT_VERBOSITY
-fi
 AM_BACKSLASH='\'
 
+am__rm_f_notfound=
+if (rm -f && rm -fr && rm -rf) 2>/dev/null
+then :
+
+else case e in #(
+  e) am__rm_f_notfound='""' ;;
+esac
+fi
+
+
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: checking xargs -n works" >&5
+printf %s "checking xargs -n works... " >&6; }
+if test ${am_cv_xargs_n_works+y}
+then :
+  printf %s "(cached) " >&6
+else case e in #(
+  e) if test "`echo 1 2 3 | xargs -n2 echo`" = "1 2
+3"
+then :
+  am_cv_xargs_n_works=yes
+else case e in #(
+  e) am_cv_xargs_n_works=no ;;
+esac
+fi ;;
+esac
+fi
+{ printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: $am_cv_xargs_n_works" >&5
+printf "%s\n" "$am_cv_xargs_n_works" >&6; }
+if test "$am_cv_xargs_n_works" = yes
+then :
+  am__xargs_n='xargs -n'
+else case e in #(
+  e)   am__xargs_n='am__xargs_n () { shift; sed "s/ /\\n/g" | while read am__xargs_n_arg; do "" "$am__xargs_n_arg"; done; }'
+ ;;
+esac
+fi
+
 if test "`cd $srcdir && pwd`" != "`pwd`"; then
   # Use -I$(srcdir) only when $(srcdir) != ., so that make's output
   # is not polluted with repeated "-I."
@@ -3248,7 +3431,7 @@ fi
 
 # Define the identity of the package.
  PACKAGE='libpng'
- VERSION='1.6.43'
+ VERSION='1.6.44'
 
 
 printf "%s\n" "#define PACKAGE \"$PACKAGE\"" >>confdefs.h
@@ -3309,47 +3492,9 @@ fi
 
 
 
-# POSIX will say in a future version that running "rm -f" with no argument
-# is OK; and we want to be able to make that assumption in our Makefile
-# recipes.  So use an aggressive probe to check that the usage we want is
-# actually supported "in the wild" to an acceptable degree.
-# See automake bug#10828.
-# To make any issue more visible, cause the running configure to be aborted
-# by default if the 'rm' program in use doesn't match our expectations; the
-# user can still override this though.
-if rm -f && rm -fr && rm -rf; then : OK; else
-  cat >&2 <<'END'
-Oops!
 
-Your 'rm' program seems unable to run without file operands specified
-on the command line, even when the '-f' option is present.  This is contrary
-to the behaviour of most rm programs out there, and not conforming with
-the upcoming POSIX standard: <http://austingroupbugs.net/view.php?id=542>
 
-Please tell bug-automake@gnu.org about your system, including the value
-of your $PATH and any error possibly output before this message.  This
-can help us improve future automake versions.
 
-END
-  if test x"$ACCEPT_INFERIOR_RM_PROGRAM" = x"yes"; then
-    echo 'Configuration will proceed anyway, since you have set the' >&2
-    echo 'ACCEPT_INFERIOR_RM_PROGRAM variable to "yes"' >&2
-    echo >&2
-  else
-    cat >&2 <<'END'
-Aborting the configuration process, to ensure you take notice of the issue.
-
-You can download and install GNU coreutils to get an 'rm' implementation
-that behaves properly: <https://www.gnu.org/software/coreutils/>.
-
-If you want to complete the configuration process using your problematic
-'rm' anyway, export the environment variable ACCEPT_INFERIOR_RM_PROGRAM
-to "yes", and re-run configure.
-
-END
-    as_fn_error $? "Your 'rm' program is bad, sorry." "$LINENO" 5
-  fi
-fi
 
 # The following line causes --disable-maintainer-mode to be the default to
 # configure. This is necessary because libpng distributions cannot rely on the
@@ -3381,17 +3526,17 @@ fi
 
 
 
-PNGLIB_VERSION=1.6.43
+PNGLIB_VERSION=1.6.44
 PNGLIB_MAJOR=1
 PNGLIB_MINOR=6
-PNGLIB_RELEASE=43
+PNGLIB_RELEASE=44
 
 
 
 ac_config_headers="$ac_config_headers config.h"
 
 
-# Check for basic programs.
+# Check the basic programs.
 ac_ext=c
 ac_cpp='$CPP $CPPFLAGS'
 ac_compile='$CC -c $CFLAGS $CPPFLAGS conftest.$ac_ext >&5'
@@ -4644,7 +4789,7 @@ else case e in #(
       # icc doesn't choke on unknown options, it will just issue warnings
       # or remarks (even with -Werror).  So we grep stderr for any message
       # that says an option was ignored or not supported.
-      # When given -MP, icc 7.0 and 7.1 complain thusly:
+      # When given -MP, icc 7.0 and 7.1 complain thus:
       #   icc: Command line warning: ignoring option '-M'; no argument required
       # The diagnosis changed in icc 8.0:
       #   icc: Command line remark: option '-MP' not supported
@@ -4779,7 +4924,7 @@ else case e in #(
       # icc doesn't choke on unknown options, it will just issue warnings
       # or remarks (even with -Werror).  So we grep stderr for any message
       # that says an option was ignored or not supported.
-      # When given -MP, icc 7.0 and 7.1 complain thusly:
+      # When given -MP, icc 7.0 and 7.1 complain thus:
       #   icc: Command line warning: ignoring option '-M'; no argument required
       # The diagnosis changed in icc 8.0:
       #   icc: Command line remark: option '-MP' not supported
@@ -14905,6 +15050,18 @@ printf %s "checking that generated files are newer than configure... " >&6; }
    fi
    { printf "%s\n" "$as_me:${as_lineno-$LINENO}: result: done" >&5
 printf "%s\n" "done" >&6; }
+case $enable_silent_rules in # (((
+  yes) AM_DEFAULT_VERBOSITY=0;;
+   no) AM_DEFAULT_VERBOSITY=1;;
+esac
+if test $am_cv_make_support_nested_variables = yes; then
+    AM_V='$(V)'
+  AM_DEFAULT_V='$(AM_DEFAULT_VERBOSITY)'
+else
+  AM_V=$AM_DEFAULT_VERBOSITY
+  AM_DEFAULT_V=$AM_DEFAULT_VERBOSITY
+fi
+
  if test -n "$EXEEXT"; then
   am__EXEEXT_TRUE=
   am__EXEEXT_FALSE='#'
@@ -15382,7 +15539,7 @@ cat >>$CONFIG_STATUS <<\_ACEOF || ac_write_fail=1
 # report actual input values of CONFIG_FILES etc. instead of their
 # values after options handling.
 ac_log="
-This file was extended by libpng $as_me 1.6.43, which was
+This file was extended by libpng $as_me 1.6.44, which was
 generated by GNU Autoconf 2.72.  Invocation command line was
 
   CONFIG_FILES    = $CONFIG_FILES
@@ -15450,7 +15607,7 @@ ac_cs_config_escaped=`printf "%s\n" "$ac_cs_config" | sed "s/^ //; s/'/'\\\\\\\\
 cat >>$CONFIG_STATUS <<_ACEOF || ac_write_fail=1
 ac_cs_config='$ac_cs_config_escaped'
 ac_cs_version="\\
-libpng config.status 1.6.43
+libpng config.status 1.6.44
 configured by $0, generated by GNU Autoconf 2.72,
   with options \\"\$ac_cs_config\\"
 
diff --git a/configure.ac b/configure.ac
index 505d72ff6..22113b265 100644
--- a/configure.ac
+++ b/configure.ac
@@ -25,7 +25,7 @@ AC_PREREQ([2.68])
 
 dnl Version number stuff here:
 
-AC_INIT([libpng],[1.6.43],[png-mng-implement@lists.sourceforge.net])
+AC_INIT([libpng],[1.6.44],[png-mng-implement@lists.sourceforge.net])
 AC_CONFIG_MACRO_DIR([scripts/autoconf])
 
 # libpng does not follow GNU file name conventions (hence 'foreign')
@@ -46,17 +46,17 @@ dnl automake, so the following is not necessary (and is not defined anyway):
 dnl AM_PREREQ([1.11.2])
 dnl stop configure from automagically running automake
 
-PNGLIB_VERSION=1.6.43
+PNGLIB_VERSION=1.6.44
 PNGLIB_MAJOR=1
 PNGLIB_MINOR=6
-PNGLIB_RELEASE=43
+PNGLIB_RELEASE=44
 
 dnl End of version number stuff
 
 AC_CONFIG_SRCDIR([pngget.c])
 AC_CONFIG_HEADERS([config.h])
 
-# Check for basic programs.
+# Check the basic programs.
 AC_LANG([C])
 AC_PROG_CC
 AM_PROG_AS
diff --git a/contrib/oss-fuzz/Dockerfile b/contrib/oss-fuzz/Dockerfile
index f5bc1a985..c9bc4145e 100644
--- a/contrib/oss-fuzz/Dockerfile
+++ b/contrib/oss-fuzz/Dockerfile
@@ -1,3 +1,5 @@
+# Copyright 2024 Cosmin Truta
+# Copyright 2017 Glenn Randers-Pehrson
 # Copyright 2016 Google Inc.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
@@ -15,11 +17,12 @@
 ################################################################################
 
 FROM gcr.io/oss-fuzz-base/base-builder
-MAINTAINER glennrp@gmail.com
+
 RUN apt-get update && \
-    apt-get install -y make autoconf automake libtool
+    apt-get install -y make autoconf automake libtool zlib1g-dev
+
+RUN git clone --depth=1 https://github.com/pnggroup/libpng.git && \
+    git clone --depth=1 https://github.com/madler/zlib.git && \
+    cp libpng/contrib/oss-fuzz/build.sh $SRC
 
-RUN git clone --depth 1 https://github.com/madler/zlib.git
-RUN git clone --depth 1 https://github.com/glennrp/libpng.git
-RUN cp libpng/contrib/oss-fuzz/build.sh $SRC
-WORKDIR libpng
+WORKDIR /home/libpng
diff --git a/contrib/oss-fuzz/README.txt b/contrib/oss-fuzz/README.txt
index 66d5242c5..b01af52ac 100644
--- a/contrib/oss-fuzz/README.txt
+++ b/contrib/oss-fuzz/README.txt
@@ -1,3 +1,7 @@
+libpng additions to oss-fuzz
+============================
+
+Copyright (c) 2024 Cosmin Truta
 Copyright (c) 2017 Glenn Randers-Pehrson
 
 This code is released under the libpng license.
diff --git a/contrib/oss-fuzz/build.sh b/contrib/oss-fuzz/build.sh
index 7b8f02639..1970f9c06 100755
--- a/contrib/oss-fuzz/build.sh
+++ b/contrib/oss-fuzz/build.sh
@@ -1,6 +1,8 @@
-#!/bin/bash -eu
+#!/usr/bin/env bash
+set -eu
 
-# Copyright 2017-2018 Glenn Randers-Pehrson
+# Copyright 2024 Cosmin Truta
+# Copyright 2017 Glenn Randers-Pehrson
 # Copyright 2016 Google Inc.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
@@ -15,36 +17,31 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 #
-# Revisions by Glenn Randers-Pehrson, 2017:
-# 1. Build only the library, not the tools (changed "make -j$(nproc) all" to
-#     "make -j$(nproc) libpng16.la").
-# 2. Disabled WARNING and WRITE options in pnglibconf.dfa.
-# 3. Build zlib alongside libpng
 ################################################################################
 
 # Disable logging via library build configuration control.
-cat scripts/pnglibconf.dfa | \
-  sed -e "s/option STDIO/option STDIO disabled/" \
-      -e "s/option WARNING /option WARNING disabled/" \
-      -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
-> scripts/pnglibconf.dfa.temp
-mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa
+sed -e "s/option STDIO/option STDIO disabled/" \
+    -e "s/option WARNING /option WARNING disabled/" \
+    -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
+    scripts/pnglibconf.dfa >scripts/pnglibconf.dfa.tmp
+mv -f scripts/pnglibconf.dfa.tmp scripts/pnglibconf.dfa
 
-# build the libpng library.
+# Build the libpng library ("libpng16.la"), excluding the auxiliary tools.
 autoreconf -f -i
 ./configure --with-libpng-prefix=OSS_FUZZ_
 make -j$(nproc) clean
 make -j$(nproc) libpng16.la
 
-# build libpng_read_fuzzer.
+# Build libpng_read_fuzzer.
 $CXX $CXXFLAGS -std=c++11 -I. \
      $SRC/libpng/contrib/oss-fuzz/libpng_read_fuzzer.cc \
      -o $OUT/libpng_read_fuzzer \
      -lFuzzingEngine .libs/libpng16.a -lz
 
-# add seed corpus.
+# Add seed corpus.
 find $SRC/libpng -name "*.png" | grep -v crashers | \
      xargs zip $OUT/libpng_read_fuzzer_seed_corpus.zip
 
 cp $SRC/libpng/contrib/oss-fuzz/*.dict \
-     $SRC/libpng/contrib/oss-fuzz/*.options $OUT/
+   $SRC/libpng/contrib/oss-fuzz/*.options \
+   $OUT/
diff --git a/contrib/oss-fuzz/libpng_read_fuzzer.cc b/contrib/oss-fuzz/libpng_read_fuzzer.cc
index 0190cf786..ad9f9adc6 100644
--- a/contrib/oss-fuzz/libpng_read_fuzzer.cc
+++ b/contrib/oss-fuzz/libpng_read_fuzzer.cc
@@ -204,5 +204,21 @@ extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
   png_read_end(png_handler.png_ptr, png_handler.end_info_ptr);
 
   PNG_CLEANUP
+
+#ifdef PNG_SIMPLIFIED_READ_SUPPORTED
+  // Simplified READ API
+  png_image image;
+  memset(&image, 0, (sizeof image));
+  image.version = PNG_IMAGE_VERSION;
+
+  if (!png_image_begin_read_from_memory(&image, data, size)) {
+    return 0;
+  }
+
+  image.format = PNG_FORMAT_RGBA;
+  std::vector<png_byte> buffer(PNG_IMAGE_SIZE(image));
+  png_image_finish_read(&image, NULL, buffer.data(), 0, NULL);
+#endif
+
   return 0;
 }
diff --git a/contrib/tools/chkfmt.sh b/contrib/tools/chkfmt.sh
deleted file mode 100755
index 8810aa7b5..000000000
--- a/contrib/tools/chkfmt.sh
+++ /dev/null
@@ -1,157 +0,0 @@
-#!/bin/sh
-
-# chkfmt.sh
-#
-# COPYRIGHT:
-# Written by John Cunningham Bowler, 2010.
-# Revised by Cosmin Truta, 2022.
-# To the extent possible under law, the author has waived all copyright and
-# related or neighboring rights to this work.  The author published this work
-# from the United States.
-#
-# Check the format of the source files in the current directory:
-#
-#  * The lines should not exceed a predefined maximum length.
-#  * Tab characters should appear only where necessary (e.g. in makefiles).
-#
-# Optionally arguments are files or directories to check.
-#
-#  -v: output the long lines (makes fixing them easier)
-#  -e: spawn an editor for each file that needs a change ($EDITOR must be
-#      defined).  When using -e the script MUST be run from an interactive
-#      command line.
-
-script_name=`basename "$0"`
-
-verbose=
-edit=
-vers=
-test "$1" = "-v" && {
-   shift
-   verbose=yes
-}
-test "$1" = "-e" && {
-   shift
-   if test -n "$EDITOR"
-   then
-      edit=yes
-
-      # Copy the standard streams for the editor
-      exec 3>&0 4>&1 5>&2
-   else
-      echo "$script_name -e: EDITOR must be defined" >&2
-      exit 1
-   fi
-}
-
-# Function to edit a single file - if the file isn't changed ask the user
-# whether or not to continue.  This stuff only works if the script is run
-# from the command line (otherwise, don't specify -e or you will be sorry).
-doed(){
-   cp "$file" "$file".orig
-   "$EDITOR" "$file" 0>&3 1>&4 2>&5 3>&- 4>&- 5>&- || exit 1
-   if cmp -s "$file".orig "$file"
-   then
-      rm "$file".orig
-      echo -n "$file: file not changed, type anything to continue: " >&5
-      read ans 0>&3
-      test -n "$ans" || return 1
-   fi
-   return 0
-}
-
-# In beta versions, the version string which appears in files can be a little
-# long and cause spuriously overlong lines.  To avoid this, substitute the
-# version string with a placeholder string "a.b.cc" before checking for long
-# lines.
-# (Starting from libpng version 1.6.36, we switched to a conventional Git
-# workflow, and we are no longer publishing beta versions.)
-if test -r png.h
-then
-   vers="`sed -n -e \
-   's/^#define PNG_LIBPNG_VER_STRING .\([0-9]\.[0-9]\.[0-9][0-9a-z]*\).$/\1/p' \
-   png.h`"
-   echo "$script_name: checking version $vers"
-fi
-if test -z "$vers"
-then
-   echo "$script_name: png.h not found, ignoring version number" >&2
-fi
-
-test -n "$1" || set -- .
-find "$@" \( -type d \( -name '.git' -o -name '.libs' -o -name 'projects' \) \
-   -prune \) -o \( -type f \
-   ! -name '*.[oa]' ! -name '*.l[oa]' !  -name '*.png' ! -name '*.out' \
-   ! -name '*.jpg' ! -name '*.patch' ! -name '*.obj' ! -name '*.exe' \
-   ! -name '*.com' ! -name '*.tar.*' ! -name '*.zip' ! -name '*.ico' \
-   ! -name '*.res' ! -name '*.rc' ! -name '*.mms' ! -name '*.rej' \
-   ! -name '*.dsp' ! -name '*.orig' ! -name '*.dfn' ! -name '*.swp' \
-   ! -name '~*' ! -name '*.3' \
-   ! -name 'missing' ! -name 'mkinstalldirs' ! -name 'depcomp' \
-   ! -name 'aclocal.m4' ! -name 'install-sh' ! -name 'Makefile.in' \
-   ! -name 'ltmain.sh' ! -name 'config*' -print \) | {
-   st=0
-   while read file
-   do
-      case "$file" in
-      *.mak|*[Mm]akefile.*|*[Mm]akefile)
-         # Makefiles require tabs, dependency lines can be this long.
-         check_tabs=
-         line_length=100;;
-      *.awk)
-         # Allow literal tabs.
-         check_tabs=
-         # Mainframe line printer, anyone?
-         line_length=132;;
-      */ci_*.sh)
-         check_tabs=yes
-         line_length=100;;
-      *contrib/*/*.[ch])
-         check_tabs=yes
-         line_length=100;;
-      *)
-         check_tabs=yes
-         line_length=80;;
-      esac
-
-      # Note that vers can only contain 0-9, . and a-z
-      if test -n "$vers"
-      then
-         sed -e "s/$vers/a.b.cc/g" "$file" >"$file".$$
-      else
-         cp "$file" "$file".$$
-      fi
-      splt="`fold -$line_length "$file".$$ | diff -c "$file".$$ -`"
-      rm "$file".$$
-
-      if test -n "$splt"
-      then
-         echo "$file: lines too long"
-         st=1
-         if test -n "$EDITOR" -a -n "$edit"
-         then
-            doed "$file" || exit 1
-         elif test -n "$verbose"
-         then
-            echo "$splt"
-         fi
-      fi
-      if test -n "$check_tabs"
-      then
-         tab="`tr -c -d '\t' <"$file"`"
-         if test -n "$tab"
-         then
-            echo "$file: file contains tab characters"
-            st=1
-            if test -n "$EDITOR" -a -n "$edit"
-            then
-               doed "$file" || exit 1
-            elif test -n "$verbose"
-            then
-               echo "$splt"
-            fi
-         fi
-      fi
-   done
-   exit $st
-}
diff --git a/depcomp b/depcomp
index 715e34311..1f0aa972c 100755
--- a/depcomp
+++ b/depcomp
@@ -1,9 +1,9 @@
 #! /bin/sh
 # depcomp - compile a program generating dependencies as side-effects
 
-scriptversion=2018-03-07.03; # UTC
+scriptversion=2024-06-19.01; # UTC
 
-# Copyright (C) 1999-2021 Free Software Foundation, Inc.
+# Copyright (C) 1999-2024 Free Software Foundation, Inc.
 
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
@@ -47,11 +47,13 @@ Environment variables:
   libtool     Whether libtool is used (yes/no).
 
 Report bugs to <bug-automake@gnu.org>.
+GNU Automake home page: <https://www.gnu.org/software/automake/>.
+General help using GNU software: <https://www.gnu.org/gethelp/>.
 EOF
     exit $?
     ;;
   -v | --v*)
-    echo "depcomp $scriptversion"
+    echo "depcomp (GNU Automake) $scriptversion"
     exit $?
     ;;
 esac
@@ -113,7 +115,6 @@ nl='
 # These definitions help.
 upper=ABCDEFGHIJKLMNOPQRSTUVWXYZ
 lower=abcdefghijklmnopqrstuvwxyz
-digits=0123456789
 alpha=${upper}${lower}
 
 if test -z "$depmode" || test -z "$source" || test -z "$object"; then
@@ -128,7 +129,7 @@ tmpdepfile=${tmpdepfile-`echo "$depfile" | sed 's/\.\([^.]*\)$/.T\1/'`}
 
 rm -f "$tmpdepfile"
 
-# Avoid interferences from the environment.
+# Avoid interference from the environment.
 gccflag= dashmflag=
 
 # Some modes work just like other modes, but use different flags.  We
@@ -198,8 +199,8 @@ gcc3)
   ;;
 
 gcc)
-## Note that this doesn't just cater to obsosete pre-3.x GCC compilers.
-## but also to in-use compilers like IMB xlc/xlC and the HP C compiler.
+## Note that this doesn't just cater to obsolete pre-3.x GCC compilers.
+## but also to in-use compilers like IBM xlc/xlC and the HP C compiler.
 ## (see the conditional assignment to $gccflag above).
 ## There are various ways to get dependency output from gcc.  Here's
 ## why we pick this rather obscure method:
diff --git a/install-sh b/install-sh
index 7c56c9c01..b1d7a6f67 100755
--- a/install-sh
+++ b/install-sh
@@ -1,7 +1,7 @@
 #!/bin/sh
 # install - install a program, script, or datafile
 
-scriptversion=2023-11-23.18; # UTC
+scriptversion=2024-06-19.01; # UTC
 
 # This originates from X11R5 (mit/util/scripts/install.sh), which was
 # later released in X11R6 (xc/config/util/install.sh) with the
@@ -170,7 +170,7 @@ while test $# -ne 0; do
 
     -T) is_target_a_directory=never;;
 
-    --version) echo "$0 $scriptversion"; exit $?;;
+    --version) echo "$0 (GNU Automake) $scriptversion"; exit $?;;
 
     --) shift
         break;;
@@ -345,7 +345,7 @@ do
 	' 0
 
 	# Because "mkdir -p" follows existing symlinks and we likely work
-	# directly in world-writeable /tmp, make sure that the '$tmpdir'
+	# directly in world-writable /tmp, make sure that the '$tmpdir'
 	# directory is successfully created first before we actually test
 	# 'mkdir -p'.
 	if (umask $mkdir_umask &&
@@ -353,7 +353,7 @@ do
 	    exec $mkdirprog $mkdir_mode -p -- "$tmpdir/a/b") >/dev/null 2>&1
 	then
 	  if test -z "$dir_arg" || {
-	       # Check for POSIX incompatibilities with -m.
+	       # Check for POSIX incompatibility with -m.
 	       # HP-UX 11.23 and IRIX 6.5 mkdir -m -p sets group- or
 	       # other-writable bit of parent directory when it shouldn't.
 	       # FreeBSD 6.1 mkdir -m -p sets mode of existing directory.
diff --git a/libpng-manual.txt b/libpng-manual.txt
index 798805759..2ce366d67 100644
--- a/libpng-manual.txt
+++ b/libpng-manual.txt
@@ -9,7 +9,7 @@ libpng-manual.txt - A description on how to use and modify libpng
 
  Based on:
 
- libpng version 1.6.36, December 2018, through 1.6.43 - February 2024
+ libpng version 1.6.36, December 2018, through 1.6.44 - September 2024
  Updated and distributed by Cosmin Truta
  Copyright (c) 2018-2024 Cosmin Truta
 
diff --git a/libpng.3 b/libpng.3
index 45e76e483..5a3c89cb9 100644
--- a/libpng.3
+++ b/libpng.3
@@ -1,6 +1,6 @@
-.TH LIBPNG 3 "February 23, 2024"
+.TH LIBPNG 3 "September 12, 2024"
 .SH NAME
-libpng \- Portable Network Graphics (PNG) Reference Library 1.6.43
+libpng \- Portable Network Graphics (PNG) Reference Library 1.6.44
 
 .SH SYNOPSIS
 \fB#include <png.h>\fP
@@ -528,7 +528,7 @@ libpng-manual.txt - A description on how to use and modify libpng
 
  Based on:
 
- libpng version 1.6.36, December 2018, through 1.6.43 - February 2024
+ libpng version 1.6.36, December 2018, through 1.6.44 - September 2024
  Updated and distributed by Cosmin Truta
  Copyright (c) 2018-2024 Cosmin Truta
 
diff --git a/libpngpf.3 b/libpngpf.3
index 0abec74a2..b7557ca27 100644
--- a/libpngpf.3
+++ b/libpngpf.3
@@ -1,6 +1,6 @@
-.TH LIBPNGPF 3 "February 23, 2024"
+.TH LIBPNGPF 3 "September 12, 2024"
 .SH NAME
-libpng \- Portable Network Graphics (PNG) Reference Library 1.6.43
+libpng \- Portable Network Graphics (PNG) Reference Library 1.6.44
 (private functions)
 
 .SH SYNOPSIS
diff --git a/missing b/missing
index 1fe1611f1..7e7d78ec5 100755
--- a/missing
+++ b/missing
@@ -1,9 +1,11 @@
 #! /bin/sh
-# Common wrapper for a few potentially missing GNU programs.
+# Common wrapper for a few potentially missing GNU and other programs.
 
-scriptversion=2018-03-07.03; # UTC
+scriptversion=2024-06-07.14; # UTC
 
-# Copyright (C) 1996-2021 Free Software Foundation, Inc.
+# shellcheck disable=SC2006,SC2268 # we must support pre-POSIX shells
+
+# Copyright (C) 1996-2024 Free Software Foundation, Inc.
 # Originally written by Fran,cois Pinard <pinard@iro.umontreal.ca>, 1996.
 
 # This program is free software; you can redistribute it and/or modify
@@ -54,18 +56,20 @@ Options:
   -v, --version   output version information and exit
 
 Supported PROGRAM values:
-  aclocal   autoconf  autoheader   autom4te  automake  makeinfo
-  bison     yacc      flex         lex       help2man
+aclocal autoconf autogen  autoheader autom4te automake autoreconf
+bison   flex     help2man lex        makeinfo perl     yacc
 
 Version suffixes to PROGRAM as well as the prefixes 'gnu-', 'gnu', and
 'g' are ignored when checking the name.
 
-Send bug reports to <bug-automake@gnu.org>."
+Report bugs to <bug-automake@gnu.org>.
+GNU Automake home page: <https://www.gnu.org/software/automake/>.
+General help using GNU software: <https://www.gnu.org/gethelp/>."
     exit $?
     ;;
 
   -v|--v|--ve|--ver|--vers|--versi|--versio|--version)
-    echo "missing $scriptversion (GNU Automake)"
+    echo "missing (GNU Automake) $scriptversion"
     exit $?
     ;;
 
@@ -108,7 +112,7 @@ gnu_software_URL=https://www.gnu.org/software
 program_details ()
 {
   case $1 in
-    aclocal|automake)
+    aclocal|automake|autoreconf)
       echo "The '$1' program is part of the GNU Automake package:"
       echo "<$gnu_software_URL/automake>"
       echo "It also requires GNU Autoconf, GNU m4 and Perl in order to run:"
@@ -123,6 +127,9 @@ program_details ()
       echo "<$gnu_software_URL/m4/>"
       echo "<$perl_URL>"
       ;;
+    *)
+      :
+      ;;
   esac
 }
 
@@ -137,48 +144,55 @@ give_advice ()
   printf '%s\n' "'$1' is $msg."
 
   configure_deps="'configure.ac' or m4 files included by 'configure.ac'"
+  autoheader_deps="'acconfig.h'"
+  automake_deps="'Makefile.am'"
+  aclocal_deps="'acinclude.m4'"
   case $normalized_program in
+    aclocal*)
+      echo "You should only need it if you modified $aclocal_deps or"
+      echo "$configure_deps."
+      ;;
     autoconf*)
-      echo "You should only need it if you modified 'configure.ac',"
-      echo "or m4 files included by it."
-      program_details 'autoconf'
+      echo "You should only need it if you modified $configure_deps."
+      ;;
+    autogen*)
+      echo "You should only need it if you modified a '.def' or '.tpl' file."
+      echo "You may want to install the GNU AutoGen package:"
+      echo "<$gnu_software_URL/autogen/>"
       ;;
     autoheader*)
-      echo "You should only need it if you modified 'acconfig.h' or"
+      echo "You should only need it if you modified $autoheader_deps or"
       echo "$configure_deps."
-      program_details 'autoheader'
       ;;
     automake*)
-      echo "You should only need it if you modified 'Makefile.am' or"
-      echo "$configure_deps."
-      program_details 'automake'
-      ;;
-    aclocal*)
-      echo "You should only need it if you modified 'acinclude.m4' or"
+      echo "You should only need it if you modified $automake_deps or"
       echo "$configure_deps."
-      program_details 'aclocal'
       ;;
-   autom4te*)
+    autom4te*)
       echo "You might have modified some maintainer files that require"
       echo "the 'autom4te' program to be rebuilt."
-      program_details 'autom4te'
+      ;;
+    autoreconf*)
+      echo "You should only need it if you modified $aclocal_deps or"
+      echo "$automake_deps or $autoheader_deps or $automake_deps or"
+      echo "$configure_deps."
       ;;
     bison*|yacc*)
       echo "You should only need it if you modified a '.y' file."
       echo "You may want to install the GNU Bison package:"
       echo "<$gnu_software_URL/bison/>"
       ;;
-    lex*|flex*)
-      echo "You should only need it if you modified a '.l' file."
-      echo "You may want to install the Fast Lexical Analyzer package:"
-      echo "<$flex_URL>"
-      ;;
     help2man*)
       echo "You should only need it if you modified a dependency" \
            "of a man page."
       echo "You may want to install the GNU Help2man package:"
       echo "<$gnu_software_URL/help2man/>"
     ;;
+    lex*|flex*)
+      echo "You should only need it if you modified a '.l' file."
+      echo "You may want to install the Fast Lexical Analyzer package:"
+      echo "<$flex_URL>"
+      ;;
     makeinfo*)
       echo "You should only need it if you modified a '.texi' file, or"
       echo "any other file indirectly affecting the aspect of the manual."
@@ -189,6 +203,12 @@ give_advice ()
       echo "want to install GNU make:"
       echo "<$gnu_software_URL/make/>"
       ;;
+    perl*)
+      echo "You should only need it to run GNU Autoconf, GNU Automake, "
+      echo "  assorted other tools, or if you modified a Perl source file."
+      echo "You may want to install the Perl 5 language interpreter:"
+      echo "<$perl_URL>"
+      ;;
     *)
       echo "You might have modified some files without having the proper"
       echo "tools for further handling them.  Check the 'README' file, it"
@@ -197,6 +217,7 @@ give_advice ()
       echo "case some other package contains this missing '$1' program."
       ;;
   esac
+  program_details "$normalized_program"
 }
 
 give_advice "$1" | sed -e '1s/^/WARNING: /' \
diff --git a/png.5 b/png.5
index a8a681813..14a3c432b 100644
--- a/png.5
+++ b/png.5
@@ -1,4 +1,4 @@
-.TH PNG 5 "February 23, 2024"
+.TH PNG 5 "September 12, 2024"
 .SH NAME
 png \- Portable Network Graphics (PNG) format
 
diff --git a/png.c b/png.c
index 9ed315700..9a9fb23d9 100644
--- a/png.c
+++ b/png.c
@@ -14,7 +14,7 @@
 #include "pngpriv.h"
 
 /* Generate a compiler error if there is an old png.h in the search path. */
-typedef png_libpng_version_1_6_43 Your_png_h_is_not_version_1_6_43;
+typedef png_libpng_version_1_6_44 Your_png_h_is_not_version_1_6_44;
 
 /* Tells libpng that we have already handled the first "num_bytes" bytes
  * of the PNG file signature.  If the PNG data is embedded into another
@@ -794,7 +794,7 @@ png_get_copyright(png_const_structrp png_ptr)
    return PNG_STRING_COPYRIGHT
 #else
    return PNG_STRING_NEWLINE \
-      "libpng version 1.6.43" PNG_STRING_NEWLINE \
+      "libpng version 1.6.44" PNG_STRING_NEWLINE \
       "Copyright (c) 2018-2024 Cosmin Truta" PNG_STRING_NEWLINE \
       "Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson" \
       PNG_STRING_NEWLINE \
@@ -1203,6 +1203,24 @@ png_colorspace_sync(png_const_structrp png_ptr, png_inforp info_ptr)
 #endif /* GAMMA */
 
 #ifdef PNG_COLORSPACE_SUPPORTED
+static int
+png_safe_add(png_int_32 *addend0_and_result, png_int_32 addend1,
+      png_int_32 addend2) {
+   /* Safely add three integers.  Returns 0 on success, 1 on overlow.
+    * IMPLEMENTATION NOTE: ANSI requires signed overflow not to occur, therefore
+    * relying on addition of two positive values producing a negative one is not
+    * safe.
+    */
+   int addend0 = *addend0_and_result;
+   if (0x7fffffff - addend0 < addend1)
+      return 1;
+   addend0 += addend1;
+   if (0x7fffffff - addend1 < addend2)
+      return 1;
+   *addend0_and_result = addend0 + addend2;
+   return 0;
+}
+
 /* Added at libpng-1.5.5 to support read and write of true CIEXYZ values for
  * cHRM, as opposed to using chromaticities.  These internal APIs return
  * non-zero on a parameter error.  The X, Y and Z values are required to be
@@ -1211,38 +1229,52 @@ png_colorspace_sync(png_const_structrp png_ptr, png_inforp info_ptr)
 static int
 png_xy_from_XYZ(png_xy *xy, const png_XYZ *XYZ)
 {
-   png_int_32 d, dwhite, whiteX, whiteY;
+   png_int_32 d, dred, dgreen, dwhite, whiteX, whiteY;
 
-   d = XYZ->red_X + XYZ->red_Y + XYZ->red_Z;
+   /* 'd' in each of the blocks below is just X+Y+Z for each component,
+    * x, y and z are X,Y,Z/(X+Y+Z).
+    */
+   d = XYZ->red_X;
+   if (png_safe_add(&d, XYZ->red_Y, XYZ->red_Z))
+      return 1;
    if (png_muldiv(&xy->redx, XYZ->red_X, PNG_FP_1, d) == 0)
       return 1;
    if (png_muldiv(&xy->redy, XYZ->red_Y, PNG_FP_1, d) == 0)
       return 1;
-   dwhite = d;
+   dred = d;
    whiteX = XYZ->red_X;
    whiteY = XYZ->red_Y;
 
-   d = XYZ->green_X + XYZ->green_Y + XYZ->green_Z;
+   d = XYZ->green_X;
+   if (png_safe_add(&d, XYZ->green_Y, XYZ->green_Z))
+      return 1;
    if (png_muldiv(&xy->greenx, XYZ->green_X, PNG_FP_1, d) == 0)
       return 1;
    if (png_muldiv(&xy->greeny, XYZ->green_Y, PNG_FP_1, d) == 0)
       return 1;
-   dwhite += d;
+   dgreen = d;
    whiteX += XYZ->green_X;
    whiteY += XYZ->green_Y;
 
-   d = XYZ->blue_X + XYZ->blue_Y + XYZ->blue_Z;
+   d = XYZ->blue_X;
+   if (png_safe_add(&d, XYZ->blue_Y, XYZ->blue_Z))
+      return 1;
    if (png_muldiv(&xy->bluex, XYZ->blue_X, PNG_FP_1, d) == 0)
       return 1;
    if (png_muldiv(&xy->bluey, XYZ->blue_Y, PNG_FP_1, d) == 0)
       return 1;
-   dwhite += d;
    whiteX += XYZ->blue_X;
    whiteY += XYZ->blue_Y;
 
-   /* The reference white is simply the sum of the end-point (X,Y,Z) vectors,
-    * thus:
+   /* The reference white is simply the sum of the end-point (X,Y,Z) vectors so
+    * the fillowing calculates (X+Y+Z) of the reference white (media white,
+    * encoding white) itself:
     */
+   if (png_safe_add(&d, dred, dgreen))
+      return 1;
+
+   dwhite = d;
+
    if (png_muldiv(&xy->whitex, whiteX, PNG_FP_1, dwhite) == 0)
       return 1;
    if (png_muldiv(&xy->whitey, whiteY, PNG_FP_1, dwhite) == 0)
@@ -1257,20 +1289,6 @@ png_XYZ_from_xy(png_XYZ *XYZ, const png_xy *xy)
    png_fixed_point red_inverse, green_inverse, blue_scale;
    png_fixed_point left, right, denominator;
 
-   /* Check xy and, implicitly, z.  Note that wide gamut color spaces typically
-    * have end points with 0 tristimulus values (these are impossible end
-    * points, but they are used to cover the possible colors).  We check
-    * xy->whitey against 5, not 0, to avoid a possible integer overflow.
-    */
-   if (xy->redx   < 0 || xy->redx > PNG_FP_1) return 1;
-   if (xy->redy   < 0 || xy->redy > PNG_FP_1-xy->redx) return 1;
-   if (xy->greenx < 0 || xy->greenx > PNG_FP_1) return 1;
-   if (xy->greeny < 0 || xy->greeny > PNG_FP_1-xy->greenx) return 1;
-   if (xy->bluex  < 0 || xy->bluex > PNG_FP_1) return 1;
-   if (xy->bluey  < 0 || xy->bluey > PNG_FP_1-xy->bluex) return 1;
-   if (xy->whitex < 0 || xy->whitex > PNG_FP_1) return 1;
-   if (xy->whitey < 5 || xy->whitey > PNG_FP_1-xy->whitex) return 1;
-
    /* The reverse calculation is more difficult because the original tristimulus
     * value had 9 independent values (red,green,blue)x(X,Y,Z) however only 8
     * derived values were recorded in the cHRM chunk;
@@ -1451,16 +1469,16 @@ png_XYZ_from_xy(png_XYZ *XYZ, const png_xy *xy)
     * value of 2 indicates an internal error to the caller.
     */
    if (png_muldiv(&left, xy->greenx-xy->bluex, xy->redy - xy->bluey, 7) == 0)
-      return 2;
+      return 1;
    if (png_muldiv(&right, xy->greeny-xy->bluey, xy->redx - xy->bluex, 7) == 0)
-      return 2;
+      return 1;
    denominator = left - right;
 
    /* Now find the red numerator. */
    if (png_muldiv(&left, xy->greenx-xy->bluex, xy->whitey-xy->bluey, 7) == 0)
-      return 2;
+      return 1;
    if (png_muldiv(&right, xy->greeny-xy->bluey, xy->whitex-xy->bluex, 7) == 0)
-      return 2;
+      return 1;
 
    /* Overflow is possible here and it indicates an extreme set of PNG cHRM
     * chunk values.  This calculation actually returns the reciprocal of the
@@ -1473,9 +1491,9 @@ png_XYZ_from_xy(png_XYZ *XYZ, const png_xy *xy)
 
    /* Similarly for green_inverse: */
    if (png_muldiv(&left, xy->redy-xy->bluey, xy->whitex-xy->bluex, 7) == 0)
-      return 2;
+      return 1;
    if (png_muldiv(&right, xy->redx-xy->bluex, xy->whitey-xy->bluey, 7) == 0)
-      return 2;
+      return 1;
    if (png_muldiv(&green_inverse, xy->whitey, denominator, left-right) == 0 ||
        green_inverse <= xy->whitey)
       return 1;
@@ -1520,25 +1538,14 @@ png_XYZ_from_xy(png_XYZ *XYZ, const png_xy *xy)
 static int
 png_XYZ_normalize(png_XYZ *XYZ)
 {
-   png_int_32 Y;
+   png_int_32 Y, Ytemp;
 
-   if (XYZ->red_Y < 0 || XYZ->green_Y < 0 || XYZ->blue_Y < 0 ||
-      XYZ->red_X < 0 || XYZ->green_X < 0 || XYZ->blue_X < 0 ||
-      XYZ->red_Z < 0 || XYZ->green_Z < 0 || XYZ->blue_Z < 0)
+   /* Normalize by scaling so the sum of the end-point Y values is PNG_FP_1. */
+   Ytemp = XYZ->red_Y;
+   if (png_safe_add(&Ytemp, XYZ->green_Y, XYZ->blue_Y))
       return 1;
 
-   /* Normalize by scaling so the sum of the end-point Y values is PNG_FP_1.
-    * IMPLEMENTATION NOTE: ANSI requires signed overflow not to occur, therefore
-    * relying on addition of two positive values producing a negative one is not
-    * safe.
-    */
-   Y = XYZ->red_Y;
-   if (0x7fffffff - Y < XYZ->green_X)
-      return 1;
-   Y += XYZ->green_Y;
-   if (0x7fffffff - Y < XYZ->blue_X)
-      return 1;
-   Y += XYZ->blue_Y;
+   Y = Ytemp;
 
    if (Y != PNG_FP_1)
    {
diff --git a/png.h b/png.h
index 83d390312..04a233f39 100644
--- a/png.h
+++ b/png.h
@@ -1,7 +1,7 @@
 
 /* png.h - header file for PNG reference library
  *
- * libpng version 1.6.43
+ * libpng version 1.6.44
  *
  * Copyright (c) 2018-2024 Cosmin Truta
  * Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson
@@ -15,7 +15,7 @@
  *   libpng versions 0.89, June 1996, through 0.96, May 1997: Andreas Dilger
  *   libpng versions 0.97, January 1998, through 1.6.35, July 2018:
  *     Glenn Randers-Pehrson
- *   libpng versions 1.6.36, December 2018, through 1.6.43, February 2024:
+ *   libpng versions 1.6.36, December 2018, through 1.6.44, September 2024:
  *     Cosmin Truta
  *   See also "Contributing Authors", below.
  */
@@ -239,7 +239,7 @@
  *    ...
  *    1.5.30                  15    10530  15.so.15.30[.0]
  *    ...
- *    1.6.43                  16    10643  16.so.16.43[.0]
+ *    1.6.44                  16    10644  16.so.16.44[.0]
  *
  *    Henceforth the source version will match the shared-library major and
  *    minor numbers; the shared-library major version number will be used for
@@ -275,7 +275,7 @@
  */
 
 /* Version information for png.h - this should match the version in png.c */
-#define PNG_LIBPNG_VER_STRING "1.6.43"
+#define PNG_LIBPNG_VER_STRING "1.6.44"
 #define PNG_HEADER_VERSION_STRING " libpng version " PNG_LIBPNG_VER_STRING "\n"
 
 /* The versions of shared library builds should stay in sync, going forward */
@@ -286,18 +286,18 @@
 /* These should match the first 3 components of PNG_LIBPNG_VER_STRING: */
 #define PNG_LIBPNG_VER_MAJOR   1
 #define PNG_LIBPNG_VER_MINOR   6
-#define PNG_LIBPNG_VER_RELEASE 43
+#define PNG_LIBPNG_VER_RELEASE 44
 
 /* This should be zero for a public release, or non-zero for a
  * development version.
  */
-#define PNG_LIBPNG_VER_BUILD  0
+#define PNG_LIBPNG_VER_BUILD 0
 
 /* Release Status */
-#define PNG_LIBPNG_BUILD_ALPHA    1
-#define PNG_LIBPNG_BUILD_BETA     2
-#define PNG_LIBPNG_BUILD_RC       3
-#define PNG_LIBPNG_BUILD_STABLE   4
+#define PNG_LIBPNG_BUILD_ALPHA               1
+#define PNG_LIBPNG_BUILD_BETA                2
+#define PNG_LIBPNG_BUILD_RC                  3
+#define PNG_LIBPNG_BUILD_STABLE              4
 #define PNG_LIBPNG_BUILD_RELEASE_STATUS_MASK 7
 
 /* Release-Specific Flags */
@@ -317,7 +317,7 @@
  * From version 1.0.1 it is:
  * XXYYZZ, where XX=major, YY=minor, ZZ=release
  */
-#define PNG_LIBPNG_VER 10643 /* 1.6.43 */
+#define PNG_LIBPNG_VER 10644 /* 1.6.44 */
 
 /* Library configuration: these options cannot be changed after
  * the library has been built.
@@ -427,7 +427,7 @@ extern "C" {
 /* This triggers a compiler error in png.c, if png.c and png.h
  * do not agree upon the version number.
  */
-typedef char* png_libpng_version_1_6_43;
+typedef char* png_libpng_version_1_6_44;
 
 /* Basic control structions.  Read libpng-manual.txt or libpng.3 for more info.
  *
@@ -824,7 +824,7 @@ typedef PNG_CALLBACK(int, *png_user_chunk_ptr, (png_structp,
  * your compiler.  This may be very difficult - try using a different compiler
  * to build the library!
  */
-PNG_FUNCTION(void, (PNGCAPI *png_longjmp_ptr), PNGARG((jmp_buf, int)), typedef);
+PNG_FUNCTION(void, (PNGCAPI *png_longjmp_ptr), (jmp_buf, int), typedef);
 #endif
 
 /* Transform masks for the high-level interface */
diff --git a/pngconf.h b/pngconf.h
index 000d7b1a8..4a4b58ac8 100644
--- a/pngconf.h
+++ b/pngconf.h
@@ -1,7 +1,7 @@
 
 /* pngconf.h - machine-configurable file for libpng
  *
- * libpng version 1.6.43
+ * libpng version 1.6.44
  *
  * Copyright (c) 2018-2024 Cosmin Truta
  * Copyright (c) 1998-2002,2004,2006-2016,2018 Glenn Randers-Pehrson
@@ -88,7 +88,7 @@
 
 /* The PNGARG macro was used in versions of libpng prior to 1.6.0 to protect
  * against legacy (pre ISOC90) compilers that did not understand function
- * prototypes.  It is not required for modern C compilers.
+ * prototypes.  [Deprecated.]
  */
 #ifndef PNGARG
 #  define PNGARG(arglist) arglist
@@ -298,7 +298,7 @@
 
 #ifndef PNG_EXPORTA
 #  define PNG_EXPORTA(ordinal, type, name, args, attributes) \
-      PNG_FUNCTION(PNG_EXPORT_TYPE(type), (PNGAPI name), PNGARG(args), \
+      PNG_FUNCTION(PNG_EXPORT_TYPE(type), (PNGAPI name), args, \
       PNG_LINKAGE_API attributes)
 #endif
 
@@ -316,7 +316,7 @@
 #endif
 
 #ifndef PNG_CALLBACK
-#  define PNG_CALLBACK(type, name, args) type (PNGCBAPI name) PNGARG(args)
+#  define PNG_CALLBACK(type, name, args) type (PNGCBAPI name) args
 #endif
 
 /* Support for compiler specific function attributes.  These are used
diff --git a/pngerror.c b/pngerror.c
index 29ebda794..1babf9f8d 100644
--- a/pngerror.c
+++ b/pngerror.c
@@ -20,13 +20,14 @@
 
 #if defined(PNG_READ_SUPPORTED) || defined(PNG_WRITE_SUPPORTED)
 
-static PNG_FUNCTION(void, png_default_error,PNGARG((png_const_structrp png_ptr,
-    png_const_charp error_message)),PNG_NORETURN);
+static PNG_FUNCTION(void /* PRIVATE */,
+png_default_error,(png_const_structrp png_ptr, png_const_charp error_message),
+    PNG_NORETURN);
 
 #ifdef PNG_WARNINGS_SUPPORTED
 static void /* PRIVATE */
-png_default_warning PNGARG((png_const_structrp png_ptr,
-    png_const_charp warning_message));
+png_default_warning(png_const_structrp png_ptr,
+    png_const_charp warning_message);
 #endif /* WARNINGS */
 
 /* This function is called whenever there is a fatal error.  This function
diff --git a/pngpriv.h b/pngpriv.h
index 9bfdb7134..b59084e7e 100644
--- a/pngpriv.h
+++ b/pngpriv.h
@@ -140,47 +140,6 @@
     * callbacks to do this.
     */
 #  define PNG_FILTER_OPTIMIZATIONS png_init_filter_functions_neon
-
-   /* By default the 'intrinsics' code in arm/filter_neon_intrinsics.c is used
-    * if possible - if __ARM_NEON__ is set and the compiler version is not known
-    * to be broken.  This is controlled by PNG_ARM_NEON_IMPLEMENTATION which can
-    * be:
-    *
-    *    1  The intrinsics code (the default with __ARM_NEON__)
-    *    2  The hand coded assembler (the default without __ARM_NEON__)
-    *
-    * It is possible to set PNG_ARM_NEON_IMPLEMENTATION in CPPFLAGS, however
-    * this is *NOT* supported and may cease to work even after a minor revision
-    * to libpng.  It *is* valid to do this for testing purposes, e.g. speed
-    * testing or a new compiler, but the results should be communicated to the
-    * libpng implementation list for incorporation in the next minor release.
-    */
-#  ifndef PNG_ARM_NEON_IMPLEMENTATION
-#     if defined(__ARM_NEON__) || defined(__ARM_NEON)
-#        if defined(__clang__)
-            /* At present it is unknown by the libpng developers which versions
-             * of clang support the intrinsics, however some or perhaps all
-             * versions do not work with the assembler so this may be
-             * irrelevant, so just use the default (do nothing here.)
-             */
-#        elif defined(__GNUC__)
-            /* GCC 4.5.4 NEON support is known to be broken.  4.6.3 is known to
-             * work, so if this *is* GCC, or G++, look for a version >4.5
-             */
-#           if __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 6)
-#              define PNG_ARM_NEON_IMPLEMENTATION 2
-#           endif /* no GNUC support */
-#        endif /* __GNUC__ */
-#     else /* !defined __ARM_NEON__ */
-         /* The 'intrinsics' code simply won't compile without this -mfpu=neon:
-          */
-#        if !defined(__aarch64__) && !defined(_M_ARM64)
-            /* The assembler code currently does not work on ARM64 */
-#          define PNG_ARM_NEON_IMPLEMENTATION 2
-#        endif /* __aarch64__ */
-#     endif /* __ARM_NEON__ */
-#  endif /* !PNG_ARM_NEON_IMPLEMENTATION */
-
 #  ifndef PNG_ARM_NEON_IMPLEMENTATION
       /* Use the intrinsics code by default. */
 #     define PNG_ARM_NEON_IMPLEMENTATION 1
diff --git a/pngtest.c b/pngtest.c
index 45ef66a70..5969f5031 100644
--- a/pngtest.c
+++ b/pngtest.c
@@ -45,8 +45,13 @@
 
 #include "png.h"
 
+/* This hack was introduced for historical reasons, and we are
+ * still keeping it in libpng-1.6.x for compatibility reasons.
+ */
+#define STDERR stdout
+
 /* Generate a compiler error if there is an old png.h in the search path. */
-typedef png_libpng_version_1_6_43 Your_png_h_is_not_version_1_6_43;
+typedef png_libpng_version_1_6_44 Your_png_h_is_not_version_1_6_44;
 
 /* Ensure that all version numbers in png.h are consistent with one another. */
 #if (PNG_LIBPNG_VER != PNG_LIBPNG_VER_MAJOR * 10000 + \
@@ -103,11 +108,6 @@ typedef png_libpng_version_1_6_43 Your_png_h_is_not_version_1_6_43;
 typedef FILE * png_FILE_p;
 #endif
 
-/* This hack was introduced for historical reasons, and we are
- * still keeping it in libpng-1.6.x for compatibility reasons.
- */
-#define STDERR stdout
-
 #ifndef PNG_DEBUG
 #  define PNG_DEBUG 0
 #endif
@@ -518,9 +518,9 @@ static int maximum_allocation = 0;
 static int total_allocation = 0;
 static int num_allocations = 0;
 
-png_voidp PNGCBAPI png_debug_malloc PNGARG((png_structp png_ptr,
-    png_alloc_size_t size));
-void PNGCBAPI png_debug_free PNGARG((png_structp png_ptr, png_voidp ptr));
+png_voidp PNGCBAPI png_debug_malloc(png_structp png_ptr,
+    png_alloc_size_t size);
+void PNGCBAPI png_debug_free(png_structp png_ptr, png_voidp ptr);
 
 png_voidp
 PNGCBAPI png_debug_malloc(png_structp png_ptr, png_alloc_size_t size)
diff --git a/scripts/cmake/AUTHORS.md b/scripts/cmake/AUTHORS.md
index 641dde265..c09821786 100644
--- a/scripts/cmake/AUTHORS.md
+++ b/scripts/cmake/AUTHORS.md
@@ -20,6 +20,8 @@ Author List
  * Cosmin Truta
  * Dan Rosser
  * David Callu
+ * Eric Riff
+ * Erik Scholz
  * Gianfranco Costamagna
  * Gleb Mazovetskiy
  * Glenn Randers-Pehrson
diff --git a/scripts/cmake/PNGConfig.cmake b/scripts/cmake/PNGConfig.cmake
new file mode 100644
index 000000000..3b6f646de
--- /dev/null
+++ b/scripts/cmake/PNGConfig.cmake
@@ -0,0 +1,15 @@
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
diff --git a/scripts/cmake/README.md b/scripts/cmake/README.md
index ca418893a..18e710717 100644
--- a/scripts/cmake/README.md
+++ b/scripts/cmake/README.md
@@ -20,6 +20,7 @@ File List
     CMakeLists.txt                 ==>  The main CMake lists file
     scripts/cmake/AUTHORS.md       ==>  The Authors file
     scripts/cmake/README.md        ==>  This file
+    scripts/cmake/PNGConfig.cmake  ==>  Config file for FindPNG
     scripts/cmake/genchk.cmake.in  ==>  Template for genchk.cmake
     scripts/cmake/genout.cmake.in  ==>  Template for genout.cmake
     scripts/cmake/gensrc.cmake.in  ==>  Template for gensrc.cmake
diff --git a/scripts/cmake/genout.cmake.in b/scripts/cmake/genout.cmake.in
index ab8285968..d4a333282 100644
--- a/scripts/cmake/genout.cmake.in
+++ b/scripts/cmake/genout.cmake.in
@@ -19,6 +19,7 @@ set(BINDIR "@CMAKE_CURRENT_BINARY_DIR@")
 set(AWK "@AWK@")
 set(CMAKE_C_COMPILER "@CMAKE_C_COMPILER@")
 set(CMAKE_C_FLAGS @CMAKE_C_FLAGS@)
+set(CMAKE_SYSROOT @CMAKE_SYSROOT@)
 set(INCDIR "@CMAKE_CURRENT_BINARY_DIR@")
 set(PNG_PREFIX "@PNG_PREFIX@")
 set(PNGLIB_MAJOR "@PNGLIB_MAJOR@")
@@ -38,6 +39,10 @@ if(APPLE)
   endif()
 endif()
 
+if(CMAKE_SYSROOT)
+  set(PLATFORM_C_FLAGS ${PLATFORM_C_FLAGS} "--sysroot=${CMAKE_SYSROOT}")
+endif()
+
 get_filename_component(INPUTEXT "${INPUT}" EXT)
 get_filename_component(OUTPUTEXT "${OUTPUT}" EXT)
 get_filename_component(INPUTBASE "${INPUT}" NAME_WE)
diff --git a/scripts/dfn.awk b/scripts/dfn.awk
index 0b25c8a37..0b970e006 100755
--- a/scripts/dfn.awk
+++ b/scripts/dfn.awk
@@ -75,12 +75,12 @@ $1 ~ /^PNG_DFN_END_SORT/{
    if (lineno == "") lineno=NR
 
    if (sub(/^[^"]*PNG_DFN *"/,"",line) != 1) {
-	print "line", lineno ": processing failed:"
-	print orig
-	err=1
-       next
+      print "line", lineno ": processing failed:"
+      print orig
+      err=1
+      next
    } else {
-	++out_count
+      ++out_count
    }
 
    # Now examine quotes within the value:
@@ -94,7 +94,7 @@ $1 ~ /^PNG_DFN_END_SORT/{
    #   #define first_name John
    #   #define last_name Smith
    #
-   #	PNG_DFN"#define name @'@" first_name "@ @" last_name "@@'"
+   #   PNG_DFN"#define name @'@" first_name "@ @" last_name "@@'"
    #
    # Might get C preprocessed to:
    #
@@ -102,7 +102,7 @@ $1 ~ /^PNG_DFN_END_SORT/{
    #
    # Which this script reduces to:
    #
-   #	#define name "John Smith"
+   #   #define name "John Smith"
    #
    while (1) {
       # While there is an @" remove it and the next "@
@@ -195,7 +195,7 @@ $1 ~ /^PNG_DFN_END_SORT/{
 
 END{
    if (out_count > 0 || err > 0)
-	exit err
+      exit err
 
    print "no definition lines found"
    exit 1
diff --git a/scripts/libpng-config-head.in b/scripts/libpng-config-head.in
index 37577f413..3d26a0a6a 100644
--- a/scripts/libpng-config-head.in
+++ b/scripts/libpng-config-head.in
@@ -11,7 +11,7 @@
 
 # Modeled after libxml-config.
 
-version=1.6.43
+version=1.6.44
 prefix=""
 libdir=""
 libs=""
diff --git a/scripts/libpng.pc.in b/scripts/libpng.pc.in
index 6a581d1a4..fc3f6f67f 100644
--- a/scripts/libpng.pc.in
+++ b/scripts/libpng.pc.in
@@ -5,6 +5,6 @@ includedir=@includedir@/libpng16
 
 Name: libpng
 Description: Loads and saves PNG files
-Version: 1.6.43
+Version: 1.6.44
 Libs: -L${libdir} -lpng16
 Cflags: -I${includedir}
diff --git a/scripts/pnglibconf.h.prebuilt b/scripts/pnglibconf.h.prebuilt
index 83f09fbe7..f5ce441ec 100644
--- a/scripts/pnglibconf.h.prebuilt
+++ b/scripts/pnglibconf.h.prebuilt
@@ -1,6 +1,6 @@
 /* pnglibconf.h - library build configuration */
 
-/* libpng version 1.6.43 */
+/* libpng version 1.6.44 */
 
 /* Copyright (c) 2018-2024 Cosmin Truta */
 /* Copyright (c) 1998-2002,2004,2006-2018 Glenn Randers-Pehrson */
diff --git a/test-driver b/test-driver
index be73b80ad..dc38f623f 100755
--- a/test-driver
+++ b/test-driver
@@ -1,9 +1,9 @@
 #! /bin/sh
 # test-driver - basic testsuite driver script.
 
-scriptversion=2018-03-07.03; # UTC
+scriptversion=2024-06-19.01; # UTC
 
-# Copyright (C) 2011-2021 Free Software Foundation, Inc.
+# Copyright (C) 2011-2024 Free Software Foundation, Inc.
 #
 # This program is free software; you can redistribute it and/or modify
 # it under the terms of the GNU General Public License as published by
@@ -44,11 +44,16 @@ print_usage ()
 Usage:
   test-driver --test-name NAME --log-file PATH --trs-file PATH
               [--expect-failure {yes|no}] [--color-tests {yes|no}]
+              [--collect-skipped-logs {yes|no}]
               [--enable-hard-errors {yes|no}] [--]
               TEST-SCRIPT [TEST-SCRIPT-ARGUMENTS]
 
 The '--test-name', '--log-file' and '--trs-file' options are mandatory.
 See the GNU Automake documentation for information.
+
+Report bugs to <bug-automake@gnu.org>.
+GNU Automake home page: <https://www.gnu.org/software/automake/>.
+General help using GNU software: <https://www.gnu.org/gethelp/>.
 END
 }
 
@@ -57,15 +62,17 @@ log_file=  # Where to save the output of the test script.
 trs_file=  # Where to save the metadata of the test run.
 expect_failure=no
 color_tests=no
+collect_skipped_logs=yes
 enable_hard_errors=yes
 while test $# -gt 0; do
   case $1 in
   --help) print_usage; exit $?;;
-  --version) echo "test-driver $scriptversion"; exit $?;;
+  --version) echo "test-driver (GNU Automake) $scriptversion"; exit $?;;
   --test-name) test_name=$2; shift;;
   --log-file) log_file=$2; shift;;
   --trs-file) trs_file=$2; shift;;
   --color-tests) color_tests=$2; shift;;
+  --collect-skipped-logs) collect_skipped_logs=$2; shift;;
   --expect-failure) expect_failure=$2; shift;;
   --enable-hard-errors) enable_hard_errors=$2; shift;;
   --) shift; break;;
@@ -121,7 +128,7 @@ fi
 case $tweaked_estatus:$expect_failure in
   0:yes) col=$red res=XPASS recheck=yes gcopy=yes;;
   0:*)   col=$grn res=PASS  recheck=no  gcopy=no;;
-  77:*)  col=$blu res=SKIP  recheck=no  gcopy=yes;;
+  77:*)  col=$blu res=SKIP  recheck=no  gcopy=$collect_skipped_logs;;
   99:*)  col=$mgn res=ERROR recheck=yes gcopy=yes;;
   *:yes) col=$lgn res=XFAIL recheck=no  gcopy=yes;;
   *:*)   col=$red res=FAIL  recheck=yes gcopy=yes;;
```

