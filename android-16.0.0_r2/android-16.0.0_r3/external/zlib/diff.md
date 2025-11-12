```diff
diff --git a/BUILD.gn b/BUILD.gn
index f97ab45..2a898d2 100644
--- a/BUILD.gn
+++ b/BUILD.gn
@@ -70,7 +70,7 @@ source_set("zlib_common_headers") {
 use_arm_neon_optimizations = false
 if ((current_cpu == "arm" || current_cpu == "arm64") &&
     !(is_win && !is_clang)) {
-  # TODO(richard.townsend@arm.com): Optimizations temporarily disabled for
+  # TODO(ritownsend@google.com): Optimizations temporarily disabled for
   # Windows on Arm MSVC builds, see http://crbug.com/v8/10012.
   if (arm_use_neon) {
     use_arm_neon_optimizations = true
@@ -151,7 +151,13 @@ if (use_arm_neon_optimizations) {
     if (!is_win && !is_clang) {
       assert(!use_thin_lto,
              "ThinLTO fails mixing different module-level targets")
-      cflags_c = [ "-march=armv8-a+aes+crc" ]
+      if (current_cpu == "arm64") {
+        cflags_c = [ "-march=armv8-a+aes+crc" ]
+      } else if (current_cpu == "arm") {
+        cflags_c = [ "-march=armv8-a+crc" ]
+      } else {
+        assert(false, "Unexpected cpu: $current_cpu")
+      }
     }
 
     sources = [
@@ -478,9 +484,7 @@ if (!is_win || target_os != "winuwp") {
     sources = [ "contrib/minizip/minizip.c" ]
 
     if (is_clang) {
-      cflags = [
-        "-Wno-incompatible-pointer-types-discards-qualifiers",
-      ]
+      cflags = [ "-Wno-incompatible-pointer-types-discards-qualifiers" ]
     }
 
     if (!is_debug) {
@@ -500,9 +504,7 @@ if (!is_win || target_os != "winuwp") {
     sources = [ "contrib/minizip/miniunz.c" ]
 
     if (is_clang) {
-      cflags = [
-        "-Wno-incompatible-pointer-types-discards-qualifiers",
-      ]
+      cflags = [ "-Wno-incompatible-pointer-types-discards-qualifiers" ]
     }
 
     if (!is_debug) {
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 66f7d04..b085ab8 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -3,7 +3,7 @@ set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS ON)
 
 project(zlib C)
 
-set(VERSION "1.3.0.1")
+set(VERSION "1.3.1")
 
 set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for executables")
 set(INSTALL_LIB_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Installation directory for libraries")
@@ -24,6 +24,7 @@ check_include_file(stddef.h    HAVE_STDDEF_H)
 option(ENABLE_SIMD_OPTIMIZATIONS "Enable all SIMD optimizations" OFF)
 option(ENABLE_SIMD_AVX512 "Enable SIMD AXV512 optimizations" OFF)
 option(USE_ZLIB_RABIN_KARP_HASH "Enable bitstream compatibility with canonical zlib" OFF)
+option(ENABLE_INTEL_QAT_COMPRESSION "Enable Intel Quick Assist Technology use for compression" OFF)
 option(BUILD_UNITTESTS "Enable standalone unit tests build" OFF)
 option(BUILD_MINIZIP_BIN "Enable building minzip_bin tool" OFF)
 option(BUILD_ZPIPE "Enable building zpipe tool" OFF)
@@ -228,6 +229,22 @@ if (ENABLE_SIMD_OPTIMIZATIONS)
   endif()
 endif()
 
+if (ENABLE_INTEL_QAT_COMPRESSION)
+    list(APPEND ZLIB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/contrib/qat/deflate_qat.cpp)
+    list(APPEND ZLIB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/contrib/qat/qatzpp/io_buffers.cpp)
+    list(APPEND ZLIB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/contrib/qat/qatzpp/memory.cpp)
+    list(APPEND ZLIB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/contrib/qat/qatzpp/qat_buffer_list.cpp)
+    list(APPEND ZLIB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/contrib/qat/qatzpp/qat.cpp)
+    list(APPEND ZLIB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/contrib/qat/qatzpp/qat_instance.cpp)
+    list(APPEND ZLIB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/contrib/qat/qatzpp/session.cpp)
+    list(APPEND ZLIB_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/contrib/qat/qatzpp/qat_task.cpp)
+
+    # TODO(gustavoa): Find a way to include the qatzpp headers without having the
+    # presubmit check throw errors.
+    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/contrib/qat/qatzpp)
+    add_compile_definitions(QAT_COMPRESSION_ENABLED)
+endif()
+
 # parse the full version number from zlib.h and include in ZLIB_FULL_VERSION
 file(READ ${CMAKE_CURRENT_SOURCE_DIR}/zlib.h _zlib_h_contents)
 string(REGEX REPLACE ".*#define[ \t]+ZLIB_VERSION[ \t]+\"([-0-9A-Za-z.]+)\".*"
@@ -250,10 +267,21 @@ if(MINGW)
 endif(MINGW)
 
 add_library(zlib SHARED ${ZLIB_SRCS} ${ZLIB_DLL_SRCS} ${ZLIB_PUBLIC_HDRS} ${ZLIB_PRIVATE_HDRS})
+target_include_directories(zlib PUBLIC ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
 add_library(zlibstatic STATIC ${ZLIB_SRCS} ${ZLIB_PUBLIC_HDRS} ${ZLIB_PRIVATE_HDRS})
+target_include_directories(zlibstatic PUBLIC ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
 set_target_properties(zlib PROPERTIES DEFINE_SYMBOL ZLIB_DLL)
 set_target_properties(zlib PROPERTIES SOVERSION 1)
 
+if (ENABLE_INTEL_QAT_COMPRESSION)
+    target_include_directories(zlib PUBLIC ${QATZPP_INCLUDE_DIRS})
+    target_link_libraries(zlib ${QATZPP_LIBRARY})
+    target_link_libraries(zlib qat)
+    target_include_directories(zlibstatic PUBLIC ${QATZPP_INCLUDE_DIRS})
+    target_link_libraries(zlibstatic ${QATZPP_LIBRARY})
+    target_link_libraries(zlibstatic qat)
+endif()
+
 if(NOT CYGWIN)
     # This property causes shared libraries on Linux to have the full version
     # encoded into their final filename.  We disable this on Cygwin because
@@ -360,6 +388,7 @@ if (BUILD_MINIZIP_BIN)
   add_executable(minizip_bin contrib/minizip/minizip.c contrib/minizip/ioapi.c
     contrib/minizip/ioapi.h contrib/minizip/unzip.c
     contrib/minizip/unzip.h contrib/minizip/zip.c contrib/minizip/zip.h
+    contrib/minizip/ints.h contrib/minizip/skipset.h
     )
   target_link_libraries(minizip_bin zlib)
 endif()
diff --git a/METADATA b/METADATA
index 65435cc..79679b6 100644
--- a/METADATA
+++ b/METADATA
@@ -1,19 +1,19 @@
 # This project was upgraded with external_updater.
 # Usage: tools/external_updater/updater.sh update external/zlib
-# For more info, check https://cs.android.com/android/platform/superproject/+/main:tools/external_updater/README.md
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
 
 name: "zlib"
 description: "The Chromium fork of the zlib compression library."
 third_party {
   license_type: NOTICE
   last_upgrade_date {
-    year: 2024
+    year: 2025
     month: 4
-    day: 10
+    day: 28
   }
   identifier {
     type: "Git"
     value: "https://chromium.googlesource.com/chromium/src/third_party/zlib/"
-    version: "7d77fb7fd66d8a5640618ad32c71fdeb7d3e02df"
+    version: "1e85c01b15363d11fab81c46fe2b5c2179113f70"
   }
 }
diff --git a/README.chromium b/README.chromium
index 31b9d55..1f7c746 100644
--- a/README.chromium
+++ b/README.chromium
@@ -1,8 +1,9 @@
 Name: zlib
 Short Name: zlib
 URL: http://zlib.net/
-Version: 1.3.0.1
-CPEPrefix: cpe:/a:zlib:zlib:1.3.0.1
+Version: 1.3.1
+Revision: 51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf
+CPEPrefix: cpe:/a:zlib:zlib:1.3.1
 Security Critical: yes
 Shipped: yes
 License: Zlib
@@ -20,14 +21,17 @@ also implements the zlib (RFC 1950) and gzip (RFC 1952) wrapper formats.
 Local Modifications:
  - Only source code from the zlib distribution used to build the zlib and
    minizip libraries are present. Many other files have been omitted. Only *.c
-   and *.h files from the upstream root directory and contrib/minizip were
-   imported.
+   and *.h files from the upstream root directory, contrib/minizip and
+   examples/zpipe.c were imported.
+ - The files named '*simd*' are original x86/Arm/RISC-V specific optimizations.
  - The contents of the google directory are original Chromium-specific
    additions.
+ - The contents of the 'contrib' of directory are either Chromium-specific
+   additions or heavily patched zlib files (e.g. inffast_chunk*).
  - Added chromeconf.h
  - Plus the changes in 'patches' folder.
  - Code in contrib/ other than contrib/minizip was added to match zlib's
    contributor layout.
- - In sync with 1.2.13 official release
+ - In sync with 1.3.1 official release
  - ZIP reader modified to allow for progress callbacks during extraction.
  - ZIP reader modified to add detection of AES encrypted content.
diff --git a/contrib/bench/zlib_bench.cc b/contrib/bench/zlib_bench.cc
index b65f929..5d84b8c 100644
--- a/contrib/bench/zlib_bench.cc
+++ b/contrib/bench/zlib_bench.cc
@@ -18,18 +18,19 @@
  *   g++|clang++ -O3 -Wall -std=c++11 zlib_bench.cc -lstdc++ -lz
  */
 
+#include <memory.h>
+#include <stdint.h>
+#include <stdio.h>
+#include <stdlib.h>
+
 #include <algorithm>
 #include <chrono>
 #include <fstream>
 #include <memory>
+#include <new>
 #include <string>
 #include <vector>
 
-#include <memory.h>
-#include <stdint.h>
-#include <stdio.h>
-#include <stdlib.h>
-
 #include "zlib.h"
 
 void error_exit(const char* error, int code) {
@@ -71,10 +72,6 @@ Data read_file_data_or_exit(const char* name) {
   return data;
 }
 
-size_t zlib_estimate_compressed_size(size_t input_size) {
-  return compressBound(input_size);
-}
-
 enum zlib_wrapper {
   kWrapperNONE,
   kWrapperZLIB,
@@ -128,10 +125,6 @@ void zlib_compress(
     std::string* output,
     bool resize_output = false)
 {
-  if (resize_output)
-    output->resize(zlib_estimate_compressed_size(input_size));
-  size_t output_size = output->size();
-
   z_stream stream;
   memset(&stream, 0, sizeof(stream));
 
@@ -140,6 +133,11 @@ void zlib_compress(
   if (result != Z_OK)
     error_exit("deflateInit2 failed", result);
 
+  if (resize_output) {
+    output->resize(deflateBound(&stream, input_size));
+  }
+  size_t output_size = output->size();
+
   stream.next_out = (Bytef*)string_data(output);
   stream.avail_out = (uInt)output_size;
   stream.next_in = (z_const Bytef*)input;
@@ -299,7 +297,7 @@ void zlib_file(const char* name,
 
     // Pre-grow the output buffer so we don't measure string resize time.
     for (int b = 0; b < blocks; ++b)
-      compressed[b].resize(zlib_estimate_compressed_size(block_size));
+      zlib_compress(type, input[b], input_length[b], &compressed[b], true);
 
     auto start = now();
     for (int b = 0; b < blocks; ++b)
@@ -307,11 +305,6 @@ void zlib_file(const char* name,
         zlib_compress(type, input[b], input_length[b], &compressed[b]);
     ctime[run] = std::chrono::duration<double>(now() - start).count();
 
-    // Compress again, resizing compressed, so we don't leave junk at the
-    // end of the compressed string that could confuse zlib_uncompress().
-    for (int b = 0; b < blocks; ++b)
-      zlib_compress(type, input[b], input_length[b], &compressed[b], true);
-
     for (int b = 0; b < blocks; ++b)
       output[b].resize(input_length[b]);
 
diff --git a/contrib/minizip/Makefile b/contrib/minizip/Makefile
index aac76e0..b3e050a 100644
--- a/contrib/minizip/Makefile
+++ b/contrib/minizip/Makefile
@@ -1,5 +1,5 @@
-CC=cc
-CFLAGS := $(CFLAGS) -O -I../..
+CC?=cc
+CFLAGS := -O $(CFLAGS) -I../..
 
 UNZ_OBJS = miniunz.o unzip.o ioapi.o ../../libz.a
 ZIP_OBJS = minizip.o zip.o   ioapi.o ../../libz.a
@@ -9,13 +9,21 @@ ZIP_OBJS = minizip.o zip.o   ioapi.o ../../libz.a
 
 all: miniunz minizip
 
-miniunz:  $(UNZ_OBJS)
+miniunz.o: miniunz.c unzip.h iowin32.h
+minizip.o: minizip.c zip.h iowin32.h ints.h
+unzip.o: unzip.c unzip.h crypt.h
+zip.o: zip.c zip.h crypt.h skipset.h ints.h
+ioapi.o: ioapi.c ioapi.h ints.h
+iowin32.o: iowin32.c iowin32.h ioapi.h
+mztools.o: mztools.c unzip.h
+
+miniunz: $(UNZ_OBJS)
 	$(CC) $(CFLAGS) -o $@ $(UNZ_OBJS)
 
-minizip:  $(ZIP_OBJS)
+minizip: $(ZIP_OBJS)
 	$(CC) $(CFLAGS) -o $@ $(ZIP_OBJS)
 
-test:	miniunz minizip
+test: miniunz minizip
 	@rm -f test.*
 	@echo hello hello hello > test.txt
 	./minizip test test.txt
diff --git a/contrib/minizip/README.chromium b/contrib/minizip/README.chromium
index b5895f2..6728765 100644
--- a/contrib/minizip/README.chromium
+++ b/contrib/minizip/README.chromium
@@ -1,11 +1,12 @@
 Name: ZIP file API for reading file entries in a ZIP archive
 Short Name: minizip
 URL: https://github.com/madler/zlib/tree/master/contrib/minizip
-Version: 1.3.0.1
+Version: 1.3.1.1
+Revision: ef24c4c7502169f016dcd2a26923dbaf3216748c
 License: Zlib
 License File: //third_party/zlib/LICENSE
-Security Critical: yes
 Shipped: yes
+Security Critical: yes
 CPEPrefix: cpe:/a:minizip_project:minizip
 
 Description:
@@ -13,6 +14,13 @@ Minizip provides API on top of zlib that can enumerate and extract ZIP archive
 files. See minizip.md for chromium build instructions.
 
 Local Modifications:
+- OS macro tweaks for Android and Fuchsia
+  0000-build.patch (the contrib/minizip/ parts)
+  0008-minizip-zip-unzip-tools.patch (crrev.com/886990)
+
+- Fix build on UWP. (crrev.com/750639)
+  0004-fix-uwp.patch
+
 - Fixed uncompressing files with wrong uncompressed size set
   crrev.com/268940
   0014-minizip-unzip-with-incorrect-size.patch
diff --git a/contrib/minizip/ints.h b/contrib/minizip/ints.h
new file mode 100644
index 0000000..4c84375
--- /dev/null
+++ b/contrib/minizip/ints.h
@@ -0,0 +1,57 @@
+/* ints.h -- create integer types for 8, 16, 32, and 64 bits
+ * Copyright (C) 2024 Mark Adler
+ * For conditions of distribution and use, see the copyright notice in zlib.h
+ *
+ * There exist compilers with limits.h, but not stdint.h or inttypes.h.
+ */
+
+#ifndef INTS_H
+#define INTS_H
+#include <limits.h>
+#if defined(UCHAR_MAX) && UCHAR_MAX == 0xff
+    typedef signed char i8_t;
+    typedef unsigned char ui8_t;
+#else
+#   error "no 8-bit integer"
+#endif
+#if defined(USHRT_MAX) && USHRT_MAX == 0xffff
+    typedef short i16_t;
+    typedef unsigned short ui16_t;
+#elif defined(UINT_MAX) && UINT_MAX == 0xffff
+    typedef int i16_t;
+    typedef unsigned ui16_t;
+#else
+#   error "no 16-bit integer"
+#endif
+#if defined(UINT_MAX) && UINT_MAX == 0xffffffff
+    typedef int i32_t;
+    typedef unsigned ui32_t;
+#   define PI32 "d"
+#   define PUI32 "u"
+#elif defined(ULONG_MAX) && ULONG_MAX == 0xffffffff
+    typedef long i32_t;
+    typedef unsigned long ui32_t;
+#   define PI32 "ld"
+#   define PUI32 "lu"
+#else
+#   error "no 32-bit integer"
+#endif
+#if defined(ULONG_MAX) && ULONG_MAX == 0xffffffffffffffff
+    typedef long i64_t;
+    typedef unsigned long ui64_t;
+#   define PI64 "ld"
+#   define PUI64 "lu"
+#elif defined(ULLONG_MAX) && ULLONG_MAX == 0xffffffffffffffff
+    typedef long long i64_t;
+    typedef unsigned long long ui64_t;
+#   define PI64 "lld"
+#   define PUI64 "llu"
+#elif defined(ULONG_LONG_MAX) && ULONG_LONG_MAX == 0xffffffffffffffff
+    typedef long long i64_t;
+    typedef unsigned long long ui64_t;
+#   define PI64 "lld"
+#   define PUI64 "llu"
+#else
+#   error "no 64-bit integer"
+#endif
+#endif
diff --git a/contrib/minizip/ioapi.h b/contrib/minizip/ioapi.h
index a2d2e6e..f3b193d 100644
--- a/contrib/minizip/ioapi.h
+++ b/contrib/minizip/ioapi.h
@@ -18,8 +18,8 @@
 
 */
 
-#ifndef _ZLIBIOAPI64_H
-#define _ZLIBIOAPI64_H
+#ifndef ZLIBIOAPI64_H
+#define ZLIBIOAPI64_H
 
 #if (!defined(_WIN32)) && (!defined(WIN32)) && (!defined(__APPLE__))
 
@@ -67,39 +67,12 @@
 #endif
 #endif
 
-/*
-#ifndef ZPOS64_T
-  #ifdef _WIN32
-                #define ZPOS64_T fpos_t
-  #else
-    #include <stdint.h>
-    #define ZPOS64_T uint64_t
-  #endif
-#endif
-*/
-
 #ifdef HAVE_MINIZIP64_CONF_H
 #include "mz64conf.h"
 #endif
 
-/* a type chosen by DEFINE */
-#ifdef HAVE_64BIT_INT_CUSTOM
-typedef  64BIT_INT_CUSTOM_TYPE ZPOS64_T;
-#else
-#ifdef HAS_STDINT_H
-#include "stdint.h"
-typedef uint64_t ZPOS64_T;
-#else
-
-
-
-#if defined(_MSC_VER) || defined(__BORLANDC__)
-typedef unsigned __int64 ZPOS64_T;
-#else
-typedef unsigned long long int ZPOS64_T;
-#endif
-#endif
-#endif
+#include "ints.h"
+typedef ui64_t ZPOS64_T;
 
 /* Maximum unsigned 32-bit value used as placeholder for zip64 */
 #ifndef MAXU32
diff --git a/contrib/minizip/iowin32.c b/contrib/minizip/iowin32.c
index 3f6867f..393c986 100644
--- a/contrib/minizip/iowin32.c
+++ b/contrib/minizip/iowin32.c
@@ -88,7 +88,7 @@ static voidpf win32_build_iowin(HANDLE hFile) {
 }
 
 voidpf ZCALLBACK win32_open64_file_func(voidpf opaque, const void* filename, int mode) {
-    const char* mode_fopen = NULL;
+    (void)opaque;
     DWORD dwDesiredAccess,dwCreationDisposition,dwShareMode,dwFlagsAndAttributes ;
     HANDLE hFile = NULL;
 
@@ -116,7 +116,7 @@ voidpf ZCALLBACK win32_open64_file_func(voidpf opaque, const void* filename, int
 
 
 voidpf ZCALLBACK win32_open64_file_funcA(voidpf opaque, const void* filename, int mode) {
-    const char* mode_fopen = NULL;
+    (void)opaque;
     DWORD dwDesiredAccess,dwCreationDisposition,dwShareMode,dwFlagsAndAttributes ;
     HANDLE hFile = NULL;
 
@@ -139,7 +139,7 @@ voidpf ZCALLBACK win32_open64_file_funcA(voidpf opaque, const void* filename, in
 
 
 voidpf ZCALLBACK win32_open64_file_funcW(voidpf opaque, const void* filename, int mode) {
-    const char* mode_fopen = NULL;
+    (void)opaque;
     DWORD dwDesiredAccess,dwCreationDisposition,dwShareMode,dwFlagsAndAttributes ;
     HANDLE hFile = NULL;
 
@@ -158,7 +158,7 @@ voidpf ZCALLBACK win32_open64_file_funcW(voidpf opaque, const void* filename, in
 
 
 voidpf ZCALLBACK win32_open_file_func(voidpf opaque, const char* filename, int mode) {
-    const char* mode_fopen = NULL;
+    (void)opaque;
     DWORD dwDesiredAccess,dwCreationDisposition,dwShareMode,dwFlagsAndAttributes ;
     HANDLE hFile = NULL;
 
@@ -186,6 +186,7 @@ voidpf ZCALLBACK win32_open_file_func(voidpf opaque, const char* filename, int m
 
 
 uLong ZCALLBACK win32_read_file_func(voidpf opaque, voidpf stream, void* buf,uLong size) {
+    (void)opaque;
     uLong ret=0;
     HANDLE hFile = NULL;
     if (stream!=NULL)
@@ -207,6 +208,7 @@ uLong ZCALLBACK win32_read_file_func(voidpf opaque, voidpf stream, void* buf,uLo
 
 
 uLong ZCALLBACK win32_write_file_func(voidpf opaque, voidpf stream, const void* buf, uLong size) {
+    (void)opaque;
     uLong ret=0;
     HANDLE hFile = NULL;
     if (stream!=NULL)
@@ -246,6 +248,7 @@ static BOOL MySetFilePointerEx(HANDLE hFile, LARGE_INTEGER pos, LARGE_INTEGER *n
 }
 
 long ZCALLBACK win32_tell_file_func(voidpf opaque, voidpf stream) {
+    (void)opaque;
     long ret=-1;
     HANDLE hFile = NULL;
     if (stream!=NULL)
@@ -268,6 +271,7 @@ long ZCALLBACK win32_tell_file_func(voidpf opaque, voidpf stream) {
 }
 
 ZPOS64_T ZCALLBACK win32_tell64_file_func(voidpf opaque, voidpf stream) {
+    (void)opaque;
     ZPOS64_T ret= (ZPOS64_T)-1;
     HANDLE hFile = NULL;
     if (stream!=NULL)
@@ -292,6 +296,7 @@ ZPOS64_T ZCALLBACK win32_tell64_file_func(voidpf opaque, voidpf stream) {
 
 
 long ZCALLBACK win32_seek_file_func(voidpf opaque, voidpf stream, uLong offset, int origin) {
+    (void)opaque;
     DWORD dwMoveMethod=0xFFFFFFFF;
     HANDLE hFile = NULL;
 
@@ -329,6 +334,7 @@ long ZCALLBACK win32_seek_file_func(voidpf opaque, voidpf stream, uLong offset,
 }
 
 long ZCALLBACK win32_seek64_file_func(voidpf opaque, voidpf stream, ZPOS64_T offset, int origin) {
+    (void)opaque;
     DWORD dwMoveMethod=0xFFFFFFFF;
     HANDLE hFile = NULL;
     long ret=-1;
@@ -367,6 +373,7 @@ long ZCALLBACK win32_seek64_file_func(voidpf opaque, voidpf stream, ZPOS64_T off
 }
 
 int ZCALLBACK win32_close_file_func(voidpf opaque, voidpf stream) {
+    (void)opaque;
     int ret=-1;
 
     if (stream!=NULL)
@@ -384,6 +391,7 @@ int ZCALLBACK win32_close_file_func(voidpf opaque, voidpf stream) {
 }
 
 int ZCALLBACK win32_error_file_func(voidpf opaque, voidpf stream) {
+    (void)opaque;
     int ret=-1;
     if (stream!=NULL)
     {
diff --git a/contrib/minizip/miniunz.c b/contrib/minizip/miniunz.c
index 5b4312e..f4ad16b 100644
--- a/contrib/minizip/miniunz.c
+++ b/contrib/minizip/miniunz.c
@@ -39,6 +39,9 @@
 #endif
 
 
+#ifndef _CRT_SECURE_NO_WARNINGS
+#  define _CRT_SECURE_NO_WARNINGS
+#endif
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -79,10 +82,11 @@
 
 /* change_file_date : change the date/time of a file
     filename : the filename of the file where date/time must be modified
-    dosdate : the new date at the MSDos format (4 bytes)
+    dosdate : the new date at the MSDOS format (4 bytes)
     tmu_date : the SAME new date at the tm_unz format */
 static void change_file_date(const char *filename, uLong dosdate, tm_unz tmu_date) {
 #ifdef _WIN32
+  (void)tmu_date;
   HANDLE hFile;
   FILETIME ftm,ftLocal,ftCreate,ftLastAcc,ftLastWrite;
 
@@ -93,8 +97,7 @@ static void change_file_date(const char *filename, uLong dosdate, tm_unz tmu_dat
   LocalFileTimeToFileTime(&ftLocal,&ftm);
   SetFileTime(hFile,&ftm,&ftLastAcc,&ftm);
   CloseHandle(hFile);
-#else
-#if defined(unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
+#elif defined(__unix__) || defined(__unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
   (void)dosdate;
   struct utimbuf ut;
   struct tm newdate;
@@ -116,7 +119,6 @@ static void change_file_date(const char *filename, uLong dosdate, tm_unz tmu_dat
   (void)dosdate;
   (void)tmu_date;
 #endif
-#endif
 }
 
 
@@ -125,9 +127,9 @@ static void change_file_date(const char *filename, uLong dosdate, tm_unz tmu_dat
 
 static int mymkdir(const char* dirname) {
     int ret=0;
-#if defined(_WIN32)
+#ifdef _WIN32
     ret = _mkdir(dirname);
-#elif defined(unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
+#elif defined(__unix__) || defined(__unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
     ret = mkdir (dirname,0775);
 #else
     (void)dirname;
@@ -238,7 +240,7 @@ static int do_list(unzFile uf) {
     printf("  ------  ------     ---- -----   ----    ----   ------     ----\n");
     for (i=0;i<gi.number_entry;i++)
     {
-        char filename_inzip[256];
+        char filename_inzip[65536+1];
         unz_file_info64 file_info;
         uLong ratio=0;
         const char *string_method = "";
@@ -303,7 +305,7 @@ static int do_list(unzFile uf) {
 
 
 static int do_extract_currentfile(unzFile uf, const int* popt_extract_without_path, int* popt_overwrite, const char* password) {
-    char filename_inzip[256];
+    char filename_inzip[65536+1];
     char* filename_withoutpath;
     char* p;
     int err=UNZ_OK;
@@ -354,6 +356,20 @@ static int do_extract_currentfile(unzFile uf, const int* popt_extract_without_pa
         else
             write_filename = filename_withoutpath;
 
+        if (write_filename[0]!='\0')
+        {
+            const char* relative_check = write_filename;
+            while (relative_check[1]!='\0')
+            {
+                if (relative_check[0]=='.' && relative_check[1]=='.')
+                    write_filename = relative_check;
+                relative_check++;
+            }
+        }
+
+        while (write_filename[0]=='/' || write_filename[0]=='.')
+            write_filename++;
+
         err = unzOpenCurrentFilePassword(uf,password);
         if (err!=UNZ_OK)
         {
diff --git a/contrib/minizip/minizip.c b/contrib/minizip/minizip.c
index 9eb3956..53fdd36 100644
--- a/contrib/minizip/minizip.c
+++ b/contrib/minizip/minizip.c
@@ -40,6 +40,9 @@
 
 
 
+#ifndef _CRT_SECURE_NO_WARNINGS
+#  define _CRT_SECURE_NO_WARNINGS
+#endif
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -58,6 +61,7 @@
 #endif
 
 #include "zip.h"
+#include "ints.h"
 
 #ifdef _WIN32
         #define USEWIN32IOAPI
@@ -73,6 +77,7 @@
 /* f: name of file to get info on, tmzip: return value: access,
    modification and creation times, dt: dostime */
 static int filetime(const char *f, tm_zip *tmzip, uLong *dt) {
+  (void)tmzip;
   int ret = 0;
   {
       FILETIME ftLocal;
@@ -90,8 +95,7 @@ static int filetime(const char *f, tm_zip *tmzip, uLong *dt) {
   }
   return ret;
 }
-#else
-#if defined(unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
+#elif defined(__unix__) || defined(__unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
 /* f: name of file to get info on, tmzip: return value: access,
    modification and creation times, dt: dostime */
 static int filetime(const char *f, tm_zip *tmzip, uLong *dt) {
@@ -142,7 +146,6 @@ static int filetime(const char *f, tm_zip *tmzip, uLong *dt) {
     return 0;
 }
 #endif
-#endif
 
 
 
@@ -191,7 +194,7 @@ static int getFileCrc(const char* filenameinzip, void* buf, unsigned long size_b
         do
         {
             err = ZIP_OK;
-            size_read = fread(buf,1,size_buf,fin);
+            size_read = (unsigned long)fread(buf,1,size_buf,fin);
             if (size_read < size_buf)
                 if (feof(fin)==0)
             {
@@ -223,7 +226,7 @@ static int isLargeFile(const char* filename) {
     FSEEKO_FUNC(pFile, 0, SEEK_END);
     pos = (ZPOS64_T)FTELLO_FUNC(pFile);
 
-                printf("File : %s is %llu bytes\n", filename, pos);
+                printf("File : %s is %"PUI64" bytes\n", filename, pos);
 
     if(pos >= 0xffffffff)
      largeFile = 1;
@@ -243,7 +246,7 @@ int main(int argc, char *argv[]) {
     char filename_try[MAXFILENAME+16];
     int zipok;
     int err=0;
-    size_t size_buf=0;
+    unsigned long size_buf=0;
     void* buf=NULL;
     const char* password=NULL;
 
@@ -305,7 +308,7 @@ int main(int argc, char *argv[]) {
     }
     else
     {
-        int i,len;
+        int len;
         int dot_found=0;
 
         zipok = 1 ;
diff --git a/contrib/minizip/mztools.c b/contrib/minizip/mztools.c
index c8d2375..f86c1e7 100644
--- a/contrib/minizip/mztools.c
+++ b/contrib/minizip/mztools.c
@@ -5,6 +5,9 @@
 */
 
 /* Code */
+#ifndef _CRT_SECURE_NO_WARNINGS
+#  define _CRT_SECURE_NO_WARNINGS
+#endif
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -140,28 +143,28 @@ extern int ZEXPORT unzRepair(const char* file, const char* fileOut, const char*
 
         /* Central directory entry */
         {
-          char header[46];
+          char central[46];
           char* comment = "";
           int comsize = (int) strlen(comment);
-          WRITE_32(header, 0x02014b50);
-          WRITE_16(header + 4, version);
-          WRITE_16(header + 6, version);
-          WRITE_16(header + 8, gpflag);
-          WRITE_16(header + 10, method);
-          WRITE_16(header + 12, filetime);
-          WRITE_16(header + 14, filedate);
-          WRITE_32(header + 16, crc);
-          WRITE_32(header + 20, cpsize);
-          WRITE_32(header + 24, uncpsize);
-          WRITE_16(header + 28, fnsize);
-          WRITE_16(header + 30, extsize);
-          WRITE_16(header + 32, comsize);
-          WRITE_16(header + 34, 0);     /* disk # */
-          WRITE_16(header + 36, 0);     /* int attrb */
-          WRITE_32(header + 38, 0);     /* ext attrb */
-          WRITE_32(header + 42, currentOffset);
+          WRITE_32(central, 0x02014b50);
+          WRITE_16(central + 4, version);
+          WRITE_16(central + 6, version);
+          WRITE_16(central + 8, gpflag);
+          WRITE_16(central + 10, method);
+          WRITE_16(central + 12, filetime);
+          WRITE_16(central + 14, filedate);
+          WRITE_32(central + 16, crc);
+          WRITE_32(central + 20, cpsize);
+          WRITE_32(central + 24, uncpsize);
+          WRITE_16(central + 28, fnsize);
+          WRITE_16(central + 30, extsize);
+          WRITE_16(central + 32, comsize);
+          WRITE_16(central + 34, 0);    /* disk # */
+          WRITE_16(central + 36, 0);    /* int attrb */
+          WRITE_32(central + 38, 0);    /* ext attrb */
+          WRITE_32(central + 42, currentOffset);
           /* Header */
-          if (fwrite(header, 1, 46, fpOutCD) == 46) {
+          if (fwrite(central, 1, 46, fpOutCD) == 46) {
             offsetCD += 46;
 
             /* Filename */
@@ -215,23 +218,23 @@ extern int ZEXPORT unzRepair(const char* file, const char* fileOut, const char*
     /* Final central directory  */
     {
       int entriesZip = entries;
-      char header[22];
+      char end[22];
       char* comment = ""; // "ZIP File recovered by zlib/minizip/mztools";
       int comsize = (int) strlen(comment);
       if (entriesZip > 0xffff) {
         entriesZip = 0xffff;
       }
-      WRITE_32(header, 0x06054b50);
-      WRITE_16(header + 4, 0);    /* disk # */
-      WRITE_16(header + 6, 0);    /* disk # */
-      WRITE_16(header + 8, entriesZip);   /* hack */
-      WRITE_16(header + 10, entriesZip);  /* hack */
-      WRITE_32(header + 12, offsetCD);    /* size of CD */
-      WRITE_32(header + 16, offset);      /* offset to CD */
-      WRITE_16(header + 20, comsize);     /* comment */
+      WRITE_32(end, 0x06054b50);
+      WRITE_16(end + 4, 0);         /* disk # */
+      WRITE_16(end + 6, 0);         /* disk # */
+      WRITE_16(end + 8, entriesZip);        /* hack */
+      WRITE_16(end + 10, entriesZip);       /* hack */
+      WRITE_32(end + 12, offsetCD);         /* size of CD */
+      WRITE_32(end + 16, offset);           /* offset to CD */
+      WRITE_16(end + 20, comsize);          /* comment */
 
       /* Header */
-      if (fwrite(header, 1, 22, fpOutCD) == 22) {
+      if (fwrite(end, 1, 22, fpOutCD) == 22) {
 
         /* Comment field */
         if (comsize > 0) {
diff --git a/contrib/minizip/skipset.h b/contrib/minizip/skipset.h
new file mode 100644
index 0000000..5e648b9
--- /dev/null
+++ b/contrib/minizip/skipset.h
@@ -0,0 +1,361 @@
+// skipset.h -- set operations using a skiplist
+// Copyright (C) 2024 Mark Adler
+// See MiniZip_info.txt for the license.
+
+// This implements a skiplist set, i.e. just keys, no data, with ~O(log n) time
+// insert and search operations. The application defines the type of a key, and
+// provides a function to compare two keys.
+
+// This header is not definitions of functions found in another source file --
+// it creates the set functions, with the application's key type, right where
+// the #include is. Before this header is #included, these must be defined:
+//
+// 1. A macro or typedef for set_key_t, the type of a key.
+// 2. A macro or function set_cmp(a, b) to compare two keys. The return values
+//    are < 0 for a < b, 0 for a == b, and > 0 for a > b.
+// 3. A macro or function set_drop(s, k) to release the key k's resources, if
+//    any, when doing a set_end() or set_clear(). s is a pointer to the set
+//    that key is in, for use with set_free() if desired.
+//
+// Example usage:
+//
+//      typedef int set_key_t;
+//      #define set_cmp(a, b) ((a) < (b) ? -1 : (a) == (b) ? 0 : 1)
+//      #define set_drop(s, k)
+//      #include "skipset.h"
+//
+//      int test(void) {        // return 0: good, 1: bad, -1: out of memory
+//          set_t set;
+//          if (setjmp(set.env))
+//              return -1;
+//          set_start(&set);
+//          set_insert(&set, 2);
+//          set_insert(&set, 1);
+//          set_insert(&set, 7);
+//          int bad = !set_found(&set, 2);
+//          bad = bad || set_found(&set, 5);
+//          set_end(&set);
+//          return bad;
+//      }
+//
+// Interface summary (see more details below):
+// - set_t is the type of the set being operated on (a set_t pointer is passed)
+// - set_start() initializes a new, empty set (initialize set.env first)
+// - set_insert() inserts a new key into the set, or not if it's already there
+// - set_found() determines whether or not a key is in the set
+// - set_end() ends the use of the set, freeing all memory
+// - set_clear() empties the set, equivalent to set_end() and then set_start()
+// - set_ok() checks if set appears to be usable, i.e. started and not ended
+//
+// Auxiliary functions available to the application:
+// - set_alloc() allocates memory with optional tracking (#define SET_TRACK)
+// - set_free() deallocates memory allocated by set_alloc()
+// - set_rand() returns 32 random bits (seeded by set_start())
+
+#ifndef SKIPSET_H
+#define SKIPSET_H
+
+#include <stdlib.h>     // realloc(), free(), NULL, size_t
+#include <stddef.h>     // ptrdiff_t
+#include <setjmp.h>     // jmp_buf, longjmp()
+#include <errno.h>      // ENOMEM
+#include <time.h>       // time(), clock()
+#include <assert.h>     // assert.h
+#include "ints.h"       // i16_t, ui32_t, ui64_t
+
+// Structures and functions below noted as "--private--" should not be used by
+// the application. set_t is partially private and partially public -- see the
+// comments there.
+
+// There is no POSIX random() in MSVC, and rand() is awful. For portability, we
+// cannot rely on a library function for random numbers. Instead we use the
+// fast and effective algorithm below, invented by Melissa O'Neill.
+
+// *Really* minimal PCG32 code / (c) 2014 M.E. O'Neill / www.pcg-random.org
+// Licensed under Apache License 2.0 (NO WARRANTY, etc. see website)
+// --private-- Random number generator state.
+typedef struct {
+    ui64_t state;       // 64-bit generator state
+    ui64_t inc;         // 63-bit sequence id
+} set_rand_t;
+// --private-- Initialize the state *gen using seed and seq. seed seeds the
+// advancing 64-bit state. seq is a sequence selection constant.
+void set_seed(set_rand_t *gen, ui64_t seed, ui64_t seq) {
+    gen->inc = (seq << 1) | 1;
+    gen->state = (seed + gen->inc) * 6364136223846793005ULL + gen->inc;
+}
+// Return 32 random bits, advancing the state *gen.
+ui32_t set_rand(set_rand_t *gen) {
+    ui64_t state = gen->state;
+    gen->state = state * 6364136223846793005ULL + gen->inc;
+    ui32_t mix = (ui32_t)(((state >> 18) ^ state) >> 27);
+    int rot = state >> 59;
+    return (mix >> rot) | (mix << ((-rot) & 31));
+}
+// End of PCG32 code.
+
+// --private-- Linked-list node.
+typedef struct set_node_s set_node_t;
+struct set_node_s {
+    set_key_t key;          // the key (not used for head or path)
+    i16_t size;             // number of allocated pointers in right[]
+    i16_t fill;             // number of pointers in right[] filled in
+    set_node_t **right;     // pointer for each level, each to the right
+};
+
+// A set. The application sets env, may use gen with set_rand(), and may read
+// allocs and memory. The remaining variables are --private-- .
+typedef struct set_s {
+    set_node_t *head;       // skiplist head -- no key, just links
+    set_node_t *path;       // right[] is path to key from set_found()
+    set_node_t *node;       // node under construction, in case of longjmp()
+    i16_t depth;            // maximum depth of the skiplist
+    ui64_t ran;             // a precious trove of random bits
+    set_rand_t gen;         // random number generator state
+    jmp_buf env;            // setjmp() environment for allocation errors
+#ifdef SET_TRACK
+    size_t allocs;          // number of allocations
+    size_t memory;          // total amount of allocated memory (>= requests)
+#endif
+} set_t;
+
+// Memory allocation and deallocation. set_alloc(set, ptr, size) returns a
+// pointer to an allocation of size bytes if ptr is NULL, or the previous
+// allocation ptr resized to size bytes. set_alloc() will never return NULL.
+// set_free(set, ptr) frees an allocation created by set_alloc(). These may be
+// used by the application. e.g. if allocation tracking is desired.
+#ifdef SET_TRACK
+// Track the number of allocations and the total backing memory size.
+#  if defined(_WIN32)
+#    include <malloc.h>
+#    define SET_ALLOC_SIZE(ptr) _msize(ptr)
+#  elif defined(__MACH__)
+#    include <malloc/malloc.h>
+#    define SET_ALLOC_SIZE(ptr) malloc_size(ptr)
+#  elif defined(__linux__)
+#    include <malloc.h>
+#    define SET_ALLOC_SIZE(ptr) malloc_usable_size(ptr)
+#  elif defined(__FreeBSD__)
+#    include <malloc_np.h>
+#    define SET_ALLOC_SIZE(ptr) malloc_usable_size(ptr)
+#  elif defined(__NetBSD__)
+#    include <jemalloc/jemalloc.h>
+#    define SET_ALLOC_SIZE(ptr) malloc_usable_size(ptr)
+#  else     // e.g. OpenBSD
+#    define SET_ALLOC_SIZE(ptr) 0
+#  endif
+// With tracking.
+void *set_alloc(set_t *set, void *ptr, size_t size) {
+    size_t had = ptr == NULL ? 0 : SET_ALLOC_SIZE(ptr);
+    void *mem = realloc(ptr, size);
+    if (mem == NULL)
+        longjmp(set->env, ENOMEM);
+    set->allocs += ptr == NULL;
+    set->memory += SET_ALLOC_SIZE(mem) - had;
+    return mem;
+}
+void set_free(set_t *set, void *ptr) {
+    if (ptr != NULL) {
+        set->allocs--;
+        set->memory -= SET_ALLOC_SIZE(ptr);
+        free(ptr);
+    }
+}
+#else
+// Without tracking.
+void *set_alloc(set_t *set, void *ptr, size_t size) {
+    void *mem = realloc(ptr, size);
+    if (mem == NULL)
+        longjmp(set->env, ENOMEM);
+    return mem;
+}
+void set_free(set_t *set, void *ptr) {
+    (void)set;
+    free(ptr);
+}
+#endif
+
+// --private-- Grow node's array right[] as needed to be able to hold at least
+// want links. If fill is true, assure that the first want links are filled in,
+// setting them to set->head if not previously filled in. Otherwise it is
+// assumed that the first want links are about to be filled in.
+void set_grow(set_t *set, set_node_t *node, int want, int fill) {
+    if (node->size < want) {
+        int more = node->size ? node->size : 1;
+        while (more < want)
+            more <<= 1;
+        node->right = set_alloc(set, node->right, more * sizeof(set_node_t *));
+        node->size = (i16_t)more;
+    }
+    int i;
+    if (fill)
+        for (i = node->fill; i < want; i++)
+            node->right[i] = set->head;
+    node->fill = (i16_t)want;
+}
+
+// --private-- Return a new node. key is left uninitialized.
+set_node_t *set_node(set_t *set) {
+    set_node_t *node = set_alloc(set, NULL, sizeof(set_node_t));
+    node->size = 0;
+    node->fill = 0;
+    node->right = NULL;
+    return node;
+}
+
+// --private-- Free the list linked from head, along with the keys.
+void set_sweep(set_t *set) {
+    set_node_t *step = set->head->right[0];
+    while (step != set->head) {
+        set_node_t *next = step->right[0];      // save link to next node
+        set_drop(set, step->key);
+        set_free(set, step->right);
+        set_free(set, step);
+        step = next;
+    }
+}
+
+// Initialize a new set. set->env must be initialized using setjmp() before
+// set_start() is called. A longjmp(set->env, ENOMEM) will be used to handle a
+// memory allocation failure during any of the operations. (See setjmp.h and
+// errno.h.) The set can still be used if this happens, assuming that it didn't
+// happen during set_start(). Whether set_start() completed or not, set_end()
+// can be used to free the set's memory after a longjmp().
+void set_start(set_t *set) {
+#ifdef SET_TRACK
+    set->allocs = 0;
+    set->memory = 0;
+#endif
+    set->head = set->path = set->node = NULL;   // in case set_node() fails
+    set->path = set_node(set);
+    set->head = set_node(set);
+    set_grow(set, set->head, 1, 1); // one link back to head for an empty set
+    *(unsigned char *)&set->head->key = 137;    // set id
+    set->depth = 0;
+    set_seed(&set->gen, ((ui64_t)(ptrdiff_t)set << 32) ^
+                        ((ui64_t)time(NULL) << 12) ^ clock(), 0);
+    set->ran = 1;
+}
+
+// Return true if *set appears to be in a usable state. If *set has been zeroed
+// out, then set_ok(set) will be false and set_end(set) will be safe.
+int set_ok(set_t *set) {
+    return set->head != NULL &&
+           set->head->right != NULL &&
+           *(unsigned char *)&set->head->key == 137;
+}
+
+// Empty the set. This frees the memory used for the previous set contents.
+// After set_clear(), *set is ready for use, as if after a set_start().
+void set_clear(set_t *set) {
+    assert(set_ok(set) && "improper use");
+
+    // Free all the keys and their nodes.
+    set_sweep(set);
+
+    // Leave the head and path allocations as is. Clear their contents, with
+    // head pointing to itself and setting depth to zero, for an empty set.
+    set->head->right[0] = set->head;
+    set->head->fill = 1;
+    set->path->fill = 0;
+    set->depth = 0;
+}
+
+// Done using the set -- free all allocations. The only operation on *set
+// permitted after this is set_start(). Though another set_end() would do no
+// harm. This can be done at any time after a set_start(), or after a longjmp()
+// on any allocation failure, including during a set_start().
+void set_end(set_t *set) {
+    if (set->head != NULL) {
+        // Empty the set and free the head node.
+        if (set->head->right != NULL) {
+            set_sweep(set);
+            set_free(set, set->head->right);
+        }
+        set_free(set, set->head);
+        set->head = NULL;
+    }
+    if (set->path != NULL) {
+        // Free the path work area.
+        set_free(set, set->path->right);
+        set_free(set, set->path);
+        set->path = NULL;
+    }
+    if (set->node != NULL) {
+        // Free the node that was under construction when longjmp() hit.
+        set_drop(set, set->node->key);
+        set_free(set, set->node->right);
+        set_free(set, set->node);
+        set->node = NULL;
+    }
+}
+
+// Look for key. Return 1 if found or 0 if not. This also puts the path to get
+// there in set->path, for use by set_insert().
+int set_found(set_t *set, set_key_t key) {
+    assert(set_ok(set) && "improper use");
+
+    // Start at depth and work down and right as determined by key comparisons.
+    set_node_t *head = set->head, *here = head;
+    int i = set->depth;
+    set_grow(set, set->path, i + 1, 0);
+    do {
+        while (here->right[i] != head &&
+               set_cmp(here->right[i]->key, key) < 0)
+            here = here->right[i];
+        set->path->right[i] = here;
+    } while (i--);
+
+    // See if the key matches.
+    here = here->right[0];
+    return here != head && set_cmp(here->key, key) == 0;
+}
+
+// Insert the key key. Return 0 on success, or 1 if key is already in the set.
+int set_insert(set_t *set, set_key_t key) {
+    assert(set_ok(set) && "improper use");
+
+    if (set_found(set, key))
+        // That key is already in the set.
+        return 1;
+
+    // Randomly generate a new level-- level 0 with probability 1/2, 1 with
+    // probability 1/4, 2 with probability 1/8, etc.
+    int level = 0;
+    for (;;) {
+        if (set->ran == 1)
+            // Ran out. Get another 32 random bits.
+            set->ran = set_rand(&set->gen) | (1ULL << 32);
+        int bit = set->ran & 1;
+        set->ran >>= 1;
+        if (bit)
+            break;
+        assert(level < 32767 &&
+               "Overhead, without any fuss, the stars were going out.");
+        level++;
+    }
+    if (level > set->depth) {
+        // The maximum depth is now deeper. Update the structures.
+        set_grow(set, set->path, level + 1, 1);
+        set_grow(set, set->head, level + 1, 1);
+        set->depth = (i16_t)level;
+    }
+
+    // Make a new node for the provided key, and insert it in the lists up to
+    // and including level.
+    set->node = set_node(set);
+    set->node->key = key;
+    set_grow(set, set->node, level + 1, 0);
+    int i;
+    for (i = 0; i <= level; i++) {
+        set->node->right[i] = set->path->right[i]->right[i];
+        set->path->right[i]->right[i] = set->node;
+    }
+    set->node = NULL;
+    return 0;
+}
+
+#else
+#error ** another skiplist set already created here
+// Would need to implement a prefix in order to support multiple sets.
+#endif
diff --git a/contrib/minizip/unzip.c b/contrib/minizip/unzip.c
index 3576a85..a39e175 100644
--- a/contrib/minizip/unzip.c
+++ b/contrib/minizip/unzip.c
@@ -88,7 +88,7 @@
 
 
 #ifndef CASESENSITIVITYDEFAULT_NO
-#  if !defined(unix) && !defined(CASESENSITIVITYDEFAULT_YES)
+#  if (!defined(__unix__) && !defined(__unix) || defined(__CYGWIN__))  && !defined(CASESENSITIVITYDEFAULT_YES)
 #    define CASESENSITIVITYDEFAULT_NO
 #  endif
 #endif
@@ -113,7 +113,7 @@
 const char unz_copyright[] =
    " unzip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll";
 
-/* unz_file_info_interntal contain internal info about a file in zipfile*/
+/* unz_file_info64_internal contain internal info about a file in zipfile*/
 typedef struct unz_file_info64_internal_s
 {
     ZPOS64_T offset_curfile;/* relative offset of local header 8 bytes */
@@ -336,7 +336,6 @@ extern int ZEXPORT unzStringFileNameCompare (const char*  fileName1,
 #define CENTRALDIRINVALID ((ZPOS64_T)(-1))
 #endif
 
-
 /*
   Locate the Central directory of a zipfile (at the end, just before
     the global comment)
@@ -467,7 +466,7 @@ local ZPOS64_T unz64local_SearchCentralDir64(const zlib_filefunc64_32_def* pzlib
     if (unz64local_getLong(pzlib_filefunc_def,filestream,&uL)!=UNZ_OK)
         return CENTRALDIRINVALID;
 
-    /* number of the disk with the start of the zip64 end of  central directory */
+    /* number of the disk with the start of the zip64 end of central directory */
     if (unz64local_getLong(pzlib_filefunc_def,filestream,&uL)!=UNZ_OK)
         return CENTRALDIRINVALID;
     if (uL != 0)
@@ -514,9 +513,9 @@ local unzFile unzOpenInternal(const void *path,
     ZPOS64_T central_pos;
     uLong   uL;
 
-    uLong number_disk;          /* number of the current dist, used for
+    uLong number_disk;          /* number of the current disk, used for
                                    spanning ZIP, unsupported, always 0*/
-    uLong number_disk_with_CD;  /* number the the disk with central dir, used
+    uLong number_disk_with_CD;  /* number the disk with central dir, used
                                    for spanning ZIP, unsupported, always 0*/
     ZPOS64_T number_entry_CD;      /* total number of entries in
                                    the central dir
@@ -1682,7 +1681,7 @@ extern int ZEXPORT unzReadCurrentFile(unzFile file, voidp buf, unsigned len) {
                 uInt i;
                 for(i=0;i<uReadThis;i++)
                   pfile_in_zip_read_info->read_buffer[i] =
-                      zdecode(s->keys,s->pcrc_32_tab,
+                      (char)zdecode(s->keys,s->pcrc_32_tab,
                               pfile_in_zip_read_info->read_buffer[i]);
             }
 #            endif
diff --git a/contrib/minizip/unzip.h b/contrib/minizip/unzip.h
index 1410584..ceb614e 100644
--- a/contrib/minizip/unzip.h
+++ b/contrib/minizip/unzip.h
@@ -306,13 +306,17 @@ extern int ZEXPORT unzGetCurrentFileInfo(unzFile file,
   Get Info about the current file
   if pfile_info!=NULL, the *pfile_info structure will contain some info about
         the current file
-  if szFileName!=NULL, the filemane string will be copied in szFileName
+  if szFileName!=NULL, the filename string will be copied in szFileName
             (fileNameBufferSize is the size of the buffer)
   if extraField!=NULL, the extra field information will be copied in extraField
             (extraFieldBufferSize is the size of the buffer).
             This is the Central-header version of the extra field
   if szComment!=NULL, the comment string of the file will be copied in szComment
             (commentBufferSize is the size of the buffer)
+  The file name and comment will be zero-terminated if there is room in the
+  provided buffer. Otherwise the buffer will contain as much as will fit. If at
+  least 65537 bytes of room is provided, then the result will always be
+  complete and zero-terminated.
 */
 
 
diff --git a/contrib/minizip/zip.c b/contrib/minizip/zip.c
index e2e9da0..93d2612 100644
--- a/contrib/minizip/zip.c
+++ b/contrib/minizip/zip.c
@@ -25,8 +25,10 @@
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
-#include <stdint.h>
 #include <time.h>
+#ifndef ZLIB_CONST
+#  define ZLIB_CONST
+#endif
 #include "zlib.h"
 #include "zip.h"
 
@@ -123,6 +125,19 @@ typedef struct linkedlist_data_s
 } linkedlist_data;
 
 
+// zipAlreadyThere() set functions for a set of zero-terminated strings, and
+// a block_t type for reading the central directory datablocks.
+typedef char *set_key_t;
+#define set_cmp(a, b) strcmp(a, b)
+#define set_drop(s, k) set_free(s, k)
+#include "skipset.h"
+typedef struct {
+    unsigned char *next;        // next byte in datablock data
+    size_t left;                // number of bytes left in data (at least)
+    linkedlist_datablock_internal *node;    // current datablock
+} block_t;
+
+
 typedef struct
 {
     z_stream stream;            /* zLib stream structure for inflate */
@@ -174,6 +189,10 @@ typedef struct
     char *globalcomment;
 #endif
 
+    // Support for zipAlreadyThere().
+    set_t set;              // set for detecting name collisions
+    block_t block;          // block for reading the central directory
+
 } zip64_internal;
 
 
@@ -264,6 +283,228 @@ local int add_data_in_datablock(linkedlist_data* ll, const void* buf, uLong len)
     return ZIP_OK;
 }
 
+// zipAlreadyThere() operations. "set" in the zip internal structure keeps the
+// set of names that are in the under-construction central directory so far. A
+// skipset provides ~O(log n) time insertion and searching. Central directory
+// records, stored in a linked list of allocated memory datablocks, is read
+// through "block" in the zip internal structure.
+
+// The block_*() functions support extracting the central directory file names
+// from the datablocks. They are designed to support a growing directory by
+// automatically continuing once more data has been appended to the linked
+// datablocks.
+
+// Initialize *block to the head of list. This should only be called once the
+// list has at least some data in it, i.e. list->first_block is not NULL.
+local void block_init(block_t *block, linkedlist_data *list) {
+    block->node = list->first_block;
+    block->next = block->node->data;
+    block->left = block->node->filled_in_this_block;
+}
+
+// Mark *block as bad, with all subsequent reads returning end, even if more
+// data is added to the datablocks. This is invoked if the central directory is
+// invalid, so there is no longer any point in attempting to interpret it.
+local void block_stop(block_t *block) {
+    block->left = 0;
+    block->next = NULL;
+}
+
+// Return true if *block has reached the end of the data in the datablocks.
+local int block_end(block_t *block) {
+    linkedlist_datablock_internal *node = block->node;
+    if (node == NULL)
+        // This block was previously terminated with extreme prejudice.
+        return 1;
+    if (block->next < node->data + node->filled_in_this_block)
+        // There are more bytes to read in the current datablock.
+        return 0;
+    while (node->next_datablock != NULL) {
+        if (node->filled_in_this_block != 0)
+            // There are some bytes in a later datablock.
+            return 0;
+        node = node->next_datablock;
+    }
+    // Reached the end of the list of datablocks. There's nothing.
+    return 1;
+}
+
+// Return one byte from *block, or -1 if the end is reached.
+local int block_get(block_t *block) {
+    while (block->left == 0) {
+        if (block->node == NULL)
+            // We've been marked bad. Return end.
+            return -1;
+        // Update left in case more was filled in since we were last here.
+        block->left = block->node->filled_in_this_block -
+                      (block->next - block->node->data);
+        if (block->left != 0)
+            // There was indeed more data appended in the current datablock.
+            break;
+        if (block->node->next_datablock == NULL)
+            // No more data here, and there is no next datablock. At the end.
+            return -1;
+        // Try the next datablock for more data.
+        block->node = block->node->next_datablock;
+        block->next = block->node->data;
+        block->left = block->node->filled_in_this_block;
+    }
+    // We have a byte to return.
+    block->left--;
+    return *block->next++;
+}
+
+// Return a 16-bit unsigned little-endian value from block, or a negative value
+// if the end is reached.
+local long block_get2(block_t *block) {
+    long got = block_get(block);
+    return got | ((unsigned long)block_get(block) << 8);
+}
+
+// Read up to len bytes from block into buf. Return the number of bytes read.
+local size_t block_read(block_t *block, unsigned char *buf, size_t len) {
+    size_t need = len;
+    while (need) {
+        if (block->left == 0) {
+            // Get a byte to update and step through the linked list as needed.
+            int got = block_get(block);
+            if (got == -1)
+                // Reached the end.
+                break;
+            *buf++ = (unsigned char)got;
+            need--;
+            continue;
+        }
+        size_t take = need > block->left ? block->left : need;
+        memcpy(buf, block->next, take);
+        block->next += take;
+        block->left -= take;
+        buf += take;
+        need -= take;
+    }
+    return len - need;      // return the number of bytes copied
+}
+
+// Skip n bytes in block. Return 0 on success or -1 if there are less than n
+// bytes to the end.
+local int block_skip(block_t *block, size_t n) {
+    while (n > block->left) {
+        n -= block->left;
+        block->next += block->left;
+        block->left = 0;
+        if (block_get(block) == -1)
+            return -1;
+        n--;
+    }
+    block->next += n;
+    block->left -= n;
+    return 0;
+}
+
+// Process the next central directory record at *block. Return the allocated,
+// zero-terminated file name, or NULL for end of input or invalid data. If
+// invalid, *block is marked bad. This uses *set for the allocation of memory.
+local char *block_central_name(block_t *block, set_t *set) {
+    char *name = NULL;
+    for (;;) {
+        if (block_end(block))
+            // At the end of the central directory (so far).
+            return NULL;
+
+        // Check for a central directory record signature.
+        if (block_get2(block) != (CENTRALHEADERMAGIC & 0xffff) ||
+            block_get2(block) != (CENTRALHEADERMAGIC >> 16))
+            // Incorrect signature.
+            break;
+
+        // Go through the remaining fixed-length portion of the record,
+        // extracting the lengths of the three variable-length fields.
+        block_skip(block, 24);
+        unsigned flen = block_get2(block);      // file name length
+        unsigned xlen = block_get2(block);      // extra field length
+        unsigned clen = block_get2(block);      // comment field length
+        if (block_skip(block, 12) == -1)
+            // Premature end of the record.
+            break;
+
+        // Extract the name and skip over the extra and comment fields.
+        name = set_alloc(set, NULL, flen + 1);
+        if (block_read(block, (unsigned char *)name, flen) < flen ||
+            block_skip(block, xlen + clen) == -1)
+            // Premature end of the record.
+            break;
+
+        // Check for embedded nuls in the name.
+        if (memchr(name, 0, flen) != NULL) {
+            // This name can never match the zero-terminated name provided to
+            // zipAlreadyThere(), so we discard it and go back to get another
+            // name. (Who the heck is putting nuls inside their zip file entry
+            // names anyway?)
+            set_free(set, name);
+            continue;
+        }
+
+        // All good. Return the zero-terminated file name.
+        name[flen] = 0;
+        return name;
+    }
+
+    // Invalid signature or premature end of the central directory record.
+    // Abandon trying to process the central directory.
+    set_free(set, name);
+    block_stop(block);
+    return NULL;
+}
+
+// Return 0 if name is not in the central directory so far, 1 if it is, -1 if
+// the central directory is invalid, -2 if out of memory, or ZIP_PARAMERROR if
+// file is NULL.
+extern int ZEXPORT zipAlreadyThere(zipFile file, char const *name) {
+    zip64_internal *zip = file;
+    if (zip == NULL)
+        return ZIP_PARAMERROR;
+    if (zip->central_dir.first_block == NULL)
+        // No central directory yet, so no, name isn't there.
+        return 0;
+    if (setjmp(zip->set.env)) {
+        // Memory allocation failure.
+        set_end(&zip->set);
+        return -2;
+    }
+    if (!set_ok(&zip->set)) {
+        // This is the first time here with some central directory content. We
+        // construct this set of names only on demand. Prepare set and block.
+        set_start(&zip->set);
+        block_init(&zip->block, &zip->central_dir);
+    }
+
+    // Update the set of names from the current central directory contents.
+    // This reads any new central directory records since the last time we were
+    // here.
+    for (;;) {
+        char *there = block_central_name(&zip->block, &zip->set);
+        if (there == NULL) {
+            if (zip->block.next == NULL)
+                // The central directory is invalid.
+                return -1;
+            break;
+        }
+
+        // Add there to the set.
+        if (set_insert(&zip->set, there))
+            // There's already a duplicate in the central directory! We'll just
+            // let this be and carry on.
+            set_free(&zip->set, there);
+    }
+
+    // Return true if name is in the central directory.
+    size_t len = strlen(name);
+    char *copy = set_alloc(&zip->set, NULL, len + 1);
+    strcpy(copy, name);
+    int found = set_found(&zip->set, copy);
+    set_free(&zip->set, copy);
+    return found;
+}
 
 
 /****************************************************************************/
@@ -551,7 +792,7 @@ local ZPOS64_T zip64local_SearchCentralDir64(const zlib_filefunc64_32_def* pzlib
 
     for (i=(int)uReadSize-3; (i--)>0;)
     {
-      // Signature "0x07064b50" Zip64 end of central directory locater
+      // Signature "0x07064b50" Zip64 end of central directory locator
       if (((*(buf+i))==0x50) && ((*(buf+i+1))==0x4b) && ((*(buf+i+2))==0x06) && ((*(buf+i+3))==0x07))
       {
         uPosFound = uReadPos+(unsigned)i;
@@ -575,7 +816,7 @@ local ZPOS64_T zip64local_SearchCentralDir64(const zlib_filefunc64_32_def* pzlib
   if (zip64local_getLong(pzlib_filefunc_def,filestream,&uL)!=ZIP_OK)
     return 0;
 
-  /* number of the disk with the start of the zip64 end of  central directory */
+  /* number of the disk with the start of the zip64 end of central directory */
   if (zip64local_getLong(pzlib_filefunc_def,filestream,&uL)!=ZIP_OK)
     return 0;
   if (uL != 0)
@@ -843,6 +1084,7 @@ extern zipFile ZEXPORT zipOpen3(const void *pathname, int append, zipcharpc* glo
     ziinit.number_entry = 0;
     ziinit.add_position_when_writing_offset = 0;
     init_linkedlist(&(ziinit.central_dir));
+    memset(&ziinit.set, 0, sizeof(set_t));  // make sure set appears dormant
 
 
 
@@ -1027,7 +1269,6 @@ extern int ZEXPORT zipOpenNewFileInZip4_64(zipFile file, const char* filename, c
     int err = ZIP_OK;
 
 #    ifdef NOCRYPT
-    (crcForCrypting);
     if (password != NULL)
         return ZIP_PARAMERROR;
 #    endif
@@ -1412,7 +1653,7 @@ extern int ZEXPORT zipWriteInFileInZip(zipFile file, const void* buf, unsigned i
     else
 #endif
     {
-      zi->ci.stream.next_in = (Bytef*)(uintptr_t)buf;
+      zi->ci.stream.next_in = buf;
       zi->ci.stream.avail_in = len;
 
       while ((err==ZIP_OK) && (zi->ci.stream.avail_in>0))
@@ -1608,7 +1849,7 @@ extern int ZEXPORT zipCloseFileInZipRaw64(zipFile file, ZPOS64_T uncompressed_si
 
       if((uLong)(datasize + 4) > zi->ci.size_centralExtraFree)
       {
-        // we can not write more data to the buffer that we have room for.
+        // we cannot write more data to the buffer that we have room for.
         return ZIP_BADZIPFILE;
       }
 
@@ -1871,6 +2112,8 @@ extern int ZEXPORT zipClose(zipFile file, const char* global_comment) {
     }
     free_linkedlist(&(zi->central_dir));
 
+    set_end(&zi->set);          // set was zeroed, so this is safe
+
     pos = centraldir_pos_inzip - zi->add_position_when_writing_offset;
     if(pos >= 0xffffffff || zi->number_entry >= 0xFFFF)
     {
diff --git a/contrib/minizip/zip.h b/contrib/minizip/zip.h
index 3e230d3..1f7f0b2 100644
--- a/contrib/minizip/zip.h
+++ b/contrib/minizip/zip.h
@@ -35,7 +35,7 @@
 
         See header of zip.h
 
-*/
+ */
 
 #ifndef _zip12_H
 #define _zip12_H
@@ -127,12 +127,12 @@ extern zipFile ZEXPORT zipOpen64(const void *pathname, int append);
      If the zipfile cannot be opened, the return value is NULL.
      Else, the return value is a zipFile Handle, usable with other function
        of this zip package.
-*/
+ */
 
 /* Note : there is no delete function into a zipfile.
    If you want delete file into a zipfile, you must open a zipfile, and create another
    Of course, you can use RAW reading and writing to copy the file you did not want delete
-*/
+ */
 
 extern zipFile ZEXPORT zipOpen2(const char *pathname,
                                 int append,
@@ -186,7 +186,7 @@ extern int ZEXPORT zipOpenNewFileInZip64(zipFile file,
   zip64 is set to 1 if a zip64 extended information block should be added to the local file header.
                     this MUST be '1' if the uncompressed size is >= 0xffffffff.
 
-*/
+ */
 
 
 extern int ZEXPORT zipOpenNewFileInZip2(zipFile file,
@@ -311,12 +311,12 @@ extern int ZEXPORT zipWriteInFileInZip(zipFile file,
                                        unsigned len);
 /*
   Write data in the zipfile
-*/
+ */
 
 extern int ZEXPORT zipCloseFileInZip(zipFile file);
 /*
   Close the current file in the zipfile
-*/
+ */
 
 extern int ZEXPORT zipCloseFileInZipRaw(zipFile file,
                                         uLong uncompressed_size,
@@ -326,17 +326,23 @@ extern int ZEXPORT zipCloseFileInZipRaw64(zipFile file,
                                           ZPOS64_T uncompressed_size,
                                           uLong crc32);
 
+extern int ZEXPORT zipAlreadyThere(zipFile file,
+                                   char const* name);
+/*
+  See if name is already in file's central directory.
+ */
+
 /*
   Close the current file in the zipfile, for file opened with
     parameter raw=1 in zipOpenNewFileInZip2
   uncompressed_size and crc32 are value for the uncompressed size
-*/
+ */
 
 extern int ZEXPORT zipClose(zipFile file,
                             const char* global_comment);
 /*
   Close the zipfile
-*/
+ */
 
 
 extern int ZEXPORT zipRemoveExtraInfoBlock(char* pData, int* dataLen, short sHeader);
@@ -355,7 +361,7 @@ extern int ZEXPORT zipRemoveExtraInfoBlock(char* pData, int* dataLen, short sHea
 
                         Remove ZIP64 Extra information from a Local File Header extra field data
         zipRemoveExtraInfoBlock(pLocalHeaderExtraFieldData, &nLocalHeaderExtraFieldDataLen, 0x0001);
-*/
+ */
 
 #ifdef __cplusplus
 }
diff --git a/contrib/qat/deflate_qat.cpp b/contrib/qat/deflate_qat.cpp
new file mode 100644
index 0000000..bfe4547
--- /dev/null
+++ b/contrib/qat/deflate_qat.cpp
@@ -0,0 +1,312 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#include "deflate_qat.h"
+#include "deflate.h"
+
+#include "session.hpp"
+#include "qat_instance.hpp"
+#include "qat_buffer_list.hpp"
+#include "qat.hpp"
+
+#include <memory>
+
+/*
+*   TODO(gustavoa): Make the input size adjustable from the memlevel
+*   attribute on deflateInit.
+*/
+static constexpr size_t kInputSize = 1024 * 1024;
+
+/* QAT Instances obtained available from the library. */
+static std::vector<std::shared_ptr<qat::Instance>> qat_instances;
+
+/*
+*   TODO(gustavoa): Verify if the ordering of the struct fields won't create
+*   unnecessary holes in the structure that requires extraneous padding.
+*/
+struct qat_deflate {
+    std::unique_ptr<qat::DeflateSession> qat_session;
+
+    /*  QAT requires contiguous physical pages. Cannot be allocated using
+    *   malloc/new.
+    */
+    uint8_t *input_buffer;
+    uint8_t *output_buffer;
+
+    /* Pointer to the next byte in the output buffer. */
+    uint8_t *pending_out;
+
+    unsigned input_buffer_size;
+    unsigned output_buffer_size;
+
+    unsigned pending_in_count;
+    unsigned pending_out_count;
+};
+
+static std::unique_ptr<qat::DeflateSession> qat_create_session(int level, int wrap)
+{
+    CpaDcChecksum checksum = CPA_DC_NONE;
+
+    switch(wrap) {
+    case 1:
+        checksum = CPA_DC_ADLER32;
+        break;
+    case 2:
+        checksum = CPA_DC_CRC32;
+        break;
+    }
+
+    return std::make_unique<qat::DeflateSession>(
+        qat_instances[0],
+        (CpaDcCompLvl)level,
+        checksum,
+        0
+    );
+}
+
+
+int qat_deflate_init()
+{
+    return (qat::Initialize()) ? Z_ERRNO : Z_OK;
+}
+
+struct qat_deflate* qat_deflate_state_init(int level, int wrap)
+{
+    if (qat_instances.empty()) {
+        qat_instances = qat::Instance::Create();
+    }
+    if (qat_instances.empty()) {
+        return nullptr;
+    }
+
+    struct qat_deflate *qat_deflate = new struct qat_deflate;
+    if (!qat_deflate) {
+        return nullptr;
+    }
+
+    /* TODO(gustavoa): Find a way to utilize all the available instances for the same
+     * process.
+     */
+    qat_instances[0]->Start();
+
+    qat_deflate->qat_session = qat_create_session(level, wrap);
+
+    qat_deflate->input_buffer_size = kInputSize;
+    qat_deflate->input_buffer = qat::AllocBlockArray<uint8_t>(kInputSize, 0);
+    qat_deflate->output_buffer_size =
+        qat_deflate->qat_session->GetDeflateBound(qat_deflate->input_buffer_size);
+    qat_deflate->pending_out = qat_deflate->output_buffer =
+        qat::AllocBlockArray<uint8_t>(qat_deflate->output_buffer_size, 0);
+
+    qat_deflate->pending_in_count = qat_deflate->pending_out_count = 0;
+
+    if (!qat_deflate->input_buffer || !qat_deflate->output_buffer) {
+        return nullptr;
+    }
+
+    return qat_deflate;
+}
+
+static unsigned qat_read_buf(z_streamp strm, struct qat_deflate* qat, unsigned size)
+{
+    unsigned len = strm->avail_in;
+
+    if (len > size) {
+        len = size;
+    }
+    if (len == 0) return 0;
+
+    strm->avail_in -= len;
+    strm->total_in += len;
+
+    zmemcpy(
+        qat->input_buffer + qat->pending_in_count,
+        strm->next_in,
+        len
+    );
+
+    strm->next_in += len;
+    qat->pending_in_count += len;
+
+    return len;
+}
+
+void qat_flush_pending(deflate_state* s)
+{
+    unsigned len;
+    z_streamp strm = s->strm;
+    struct qat_deflate* qat = s->qat_s;
+
+    len = qat->pending_out_count;
+    if (len > strm->avail_out) len = strm->avail_out;
+    if (len == 0) return;
+
+    zmemcpy(strm->next_out, qat->pending_out, len);
+
+    qat->pending_out        += len;
+    qat->pending_out_count -= len;
+    strm->next_out          += len;
+    strm->avail_out         -= len;
+    strm->total_out         += len;
+    if (qat->pending_out_count == 0) {
+        qat->pending_out = qat->output_buffer;
+    }
+}
+
+static int qat_compress_pending(deflate_state*s, int flush)
+{
+    struct qat_deflate* qat = s->qat_s;
+    uint32_t metadata_size;
+
+    /* TODO(gustavoa): find a way to make qatzpp setup this number internally. */
+    cpaDcBufferListGetMetaSize(qat->qat_session->getInstance()->GetHandle(), 1, &metadata_size);
+
+    auto job = qat->qat_session->Deflate(
+        std::make_unique<qat::IOBuffers>(
+            std::make_unique<qat::BufferListUser>(
+                qat->input_buffer,
+                qat->pending_in_count,
+                metadata_size
+            ),
+            std::make_unique<qat::BufferListUser>(
+                qat->output_buffer,
+                qat->output_buffer_size,
+                metadata_size
+            )
+        ), (flush == Z_FINISH && s->strm->avail_in == 0)
+    );
+
+    job->WaitCompletion();
+
+    /*
+     *  TODO(gustavoa): make QAT perform the checksum combine.
+     */
+    if (s->wrap == 2) {
+        s->strm->adler = crc32_combine(
+            s->strm->adler,
+            job->GetResults()->checksum,
+            job->GetResults()->consumed
+        );
+    } else if (s->wrap == 1) {
+        s->strm->adler = adler32(
+            s->strm->adler,
+            qat->input_buffer,
+            job->GetResults()->consumed
+        );
+    }
+
+    qat->pending_out_count = job->GetResults()->produced;
+    qat->pending_in_count -= job->GetResults()->consumed;
+
+    if(qat->pending_in_count != 0) {
+        /* Copy any remaining bytes to the beginning of the buffer. */
+        zmemcpy(
+            qat->input_buffer,
+            qat->input_buffer + job->GetResults()->consumed,
+            qat->pending_in_count
+        );
+    }
+
+    return 0;
+}
+
+qat_block_state qat_deflate_step(deflate_state* s, int flush)
+{
+    z_streamp strm = s->strm;
+    struct qat_deflate* qat_state = s->qat_s;
+
+    for (;;) {
+        if (qat_state->pending_in_count < qat_state->input_buffer_size) {
+            qat_read_buf(
+                strm,
+                qat_state,
+                qat_state->input_buffer_size - qat_state->pending_in_count
+            );
+            if (qat_state->pending_in_count < qat_state->input_buffer_size && flush == Z_NO_FLUSH) {
+                return qat_block_need_more;
+            } else {
+                qat_compress_pending(s, flush);
+            }
+            if (strm->avail_in == 0) {
+                break;
+            }
+        } else {
+            qat_compress_pending(s, flush);
+        }
+
+        qat_flush_pending(s);
+        if (strm->avail_out == 0) {
+            return (flush == Z_FINISH) ? qat_block_finish_started : qat_block_need_more;
+        }
+    }
+
+    if (flush == Z_FINISH) {
+        qat_flush_pending(s);
+        if (strm->avail_out == 0) {
+            return qat_block_finish_started;
+        } else {
+            return qat_block_finish_done;
+        }
+    }
+
+    qat_flush_pending(s);
+    if (strm->avail_out == 0) {
+        return qat_block_done;
+    }
+
+    return qat_block_need_more;
+}
+
+int qat_deflate_state_free(deflate_state* s)
+{
+    struct qat_deflate* qat_state = s->qat_s;
+    if (qat_state->input_buffer) {
+        qat::Free(qat_state->input_buffer);
+    }
+    if (qat_state->output_buffer) {
+        qat::Free(qat_state->output_buffer);
+    }
+
+    qat_state->qat_session.reset();
+    delete qat_state;
+    s->qat_s = nullptr;
+
+    return Z_OK;
+}
+
+struct qat_deflate *qat_deflate_copy(deflate_state *ss)
+{
+    struct qat_deflate *sqat = ss->qat_s;
+    struct qat_deflate *dqat = nullptr;
+
+    if (!sqat) {
+        return nullptr;
+    }
+
+    dqat = new struct qat_deflate;
+
+    dqat->qat_session = qat_create_session(ss->level, ss->wrap);
+
+    dqat->input_buffer_size = sqat->input_buffer_size;
+    dqat->input_buffer = qat::AllocBlockArray<uint8_t>(dqat->input_buffer_size, 0);
+
+    dqat->output_buffer_size = sqat->output_buffer_size;
+    dqat->output_buffer = qat::AllocBlockArray<uint8_t>(dqat->output_buffer_size, 0);
+
+    dqat->pending_in_count = sqat->pending_in_count;
+    dqat->pending_out_count = sqat->pending_out_count;
+
+    dqat->pending_out =
+        dqat->output_buffer + (sqat->pending_out - sqat->output_buffer);
+
+    zmemcpy(dqat->input_buffer, sqat->input_buffer, dqat->input_buffer_size);
+    zmemcpy(dqat->output_buffer, sqat->output_buffer, dqat->output_buffer_size);
+
+    return dqat;
+}
+
diff --git a/contrib/qat/deflate_qat.h b/contrib/qat/deflate_qat.h
new file mode 100644
index 0000000..3c7aa11
--- /dev/null
+++ b/contrib/qat/deflate_qat.h
@@ -0,0 +1,54 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#ifndef DEFLATE_QAT_H
+#define DEFLATE_QAT_H
+
+#include "deflate.h"
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/* This is a 1:1 mapping of the block states that deflate_fast, deflate_slow,
+ * deflate_rle, etc.. return.
+ * The added 'qat_failure' value is used for signaling the caller to revert
+ * back into software mode.
+ */
+typedef enum {
+    qat_block_need_more,
+    qat_block_done,
+    qat_block_finish_started,
+    qat_block_finish_done,
+    qat_failure
+} qat_block_state;
+
+/* Initialize QAT for the calling process if it has not been yet initialized. */
+int qat_deflate_init();
+
+/* Initialize a QAT stream state for a deflate_state object. */
+struct qat_deflate *qat_deflate_state_init(int level, int wra);
+
+/* Flush QAT output buffer into the zstream.next_out pointer. */
+void qat_flush_pending(deflate_state*);
+
+/* Compresses/copies/flushes any data in the internal QAT state
+ * input/output buffers.
+*/
+qat_block_state qat_deflate_step(deflate_state*, int flush);
+
+/* Frees all the QAT-related buffers and objects for a given deflate_state. */
+int qat_deflate_state_free(deflate_state*);
+
+struct qat_deflate *qat_deflate_copy(deflate_state *ss);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif
\ No newline at end of file
diff --git a/contrib/qat/qatzpp/io_buffers.cpp b/contrib/qat/qatzpp/io_buffers.cpp
new file mode 100644
index 0000000..2870292
--- /dev/null
+++ b/contrib/qat/qatzpp/io_buffers.cpp
@@ -0,0 +1,31 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#include <fstream>
+#include <iostream>
+
+#include "io_buffers.h"
+#include "qat_instance.hpp"
+
+namespace qat
+{
+
+IOBuffers::IOBuffers()
+{
+}
+
+IOBuffers::IOBuffers(std::unique_ptr<BaseBufferList>&& src_list, std::unique_ptr<BaseBufferList>&& dst_list):
+    src_buffer_list_(std::move(src_list)), dst_buffer_list_(std::move(dst_list))
+{
+}
+
+IOBuffers::~IOBuffers()
+{
+}
+
+}
diff --git a/contrib/qat/qatzpp/io_buffers.h b/contrib/qat/qatzpp/io_buffers.h
new file mode 100644
index 0000000..9fe8bfd
--- /dev/null
+++ b/contrib/qat/qatzpp/io_buffers.h
@@ -0,0 +1,62 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#ifndef QATZPP_IO_BUFFERS_H
+#define QATZPP_IO_BUFFERS_H
+
+#include <qat/cpa_dc.h>
+
+#include <cstring>
+#include <iostream>
+#include <memory>
+#include <string>
+#include <vector>
+
+#include "memory.hpp"
+#include "qat_instance.hpp"
+
+namespace qat
+{
+
+struct BaseBufferList
+{
+    virtual ~BaseBufferList() {}
+
+    CpaBufferList list;
+    std::vector<CpaFlatBuffer> flat_buffers;
+
+protected:
+    BaseBufferList() {}
+};
+
+class IOBuffers
+{
+public:
+    IOBuffers(
+        std::unique_ptr<BaseBufferList> &&src_list,
+        std::unique_ptr<BaseBufferList> &&dst_list
+    );
+    virtual ~IOBuffers();
+
+    BaseBufferList *GetSrc() const {
+        return src_buffer_list_.get();
+    }
+
+    BaseBufferList *GetDst() const {
+        return dst_buffer_list_.get();
+    }
+protected:
+    IOBuffers();
+
+    std::unique_ptr<BaseBufferList> src_buffer_list_;
+    std::unique_ptr<BaseBufferList> dst_buffer_list_;
+};
+
+}
+
+#endif
\ No newline at end of file
diff --git a/contrib/qat/qatzpp/memory.cpp b/contrib/qat/qatzpp/memory.cpp
new file mode 100644
index 0000000..6a97ffe
--- /dev/null
+++ b/contrib/qat/qatzpp/memory.cpp
@@ -0,0 +1,30 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#include <qat/qae_mem.h>
+
+#include <cstdlib>
+#include <iostream>
+
+#include "memory.hpp"
+#include "qat.hpp"
+
+namespace qat
+{
+
+void *Alloc(size_t size_bytes, uint32_t numa_node)
+{
+    return qaeMemAllocNUMA(size_bytes, numa_node, 1);
+}
+
+void Free(void *ptr)
+{
+    qaeMemFreeNUMA(&ptr);
+}
+
+}
\ No newline at end of file
diff --git a/contrib/qat/qatzpp/memory.hpp b/contrib/qat/qatzpp/memory.hpp
new file mode 100644
index 0000000..191516c
--- /dev/null
+++ b/contrib/qat/qatzpp/memory.hpp
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#ifndef QATZPP_MEMORY_HPP
+#define QATZPP_MEMORY_HPP
+
+#include <cstddef>
+#include <cstdint>
+
+namespace qat
+{
+
+void *Alloc(size_t sizeBytes, uint32_t numa_node);
+
+template <typename T>
+T *AllocBlock(int32_t numa_node)
+{
+    return static_cast<T*>(Alloc(sizeof(T), numa_node));
+}
+
+template <typename T>
+T *AllocBlockArray(size_t count, int32_t numa_node)
+{
+    if (count <= 0) {
+        return nullptr;
+    }
+
+    return static_cast<T*>(Alloc(sizeof(T) * count, numa_node));
+}
+
+void Free(void *ptr);
+
+}
+
+#endif
\ No newline at end of file
diff --git a/contrib/qat/qatzpp/qat.cpp b/contrib/qat/qatzpp/qat.cpp
new file mode 100644
index 0000000..80468d3
--- /dev/null
+++ b/contrib/qat/qatzpp/qat.cpp
@@ -0,0 +1,73 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#include "qat.hpp"
+
+#include <qat/cpa.h>
+#include <qat/icp_sal_user.h>
+#include <qat/qae_mem.h>
+
+#include <iostream>
+#include <string>
+#include <memory>
+#include <mutex>
+
+namespace qat
+{
+
+static bool g_qat_not_available = false;
+static bool g_qat_initialized = false;
+static std::mutex g_qat_initialization_mutex;
+
+class QATContext
+{
+public:
+    explicit QATContext() {}
+
+    QATContext(const QATContext &) = delete;
+    QATContext &operator=(const QATContext &) = delete;
+
+    QATContext(QATContext &&) = delete;
+    QATContext &operator=(QATContext &&) = delete;
+
+    ~QATContext()
+    {
+        std::lock_guard<std::mutex> lock(g_qat_initialization_mutex);
+
+        if (g_qat_not_available) return;
+
+        if (g_qat_initialized) {
+            icp_sal_userStop();
+            g_qat_initialized = false;
+        }
+    }
+};
+
+static std::unique_ptr<QATContext> qat_context;
+
+int Initialize()
+{
+    std::lock_guard<std::mutex> lock(g_qat_initialization_mutex);
+    uint32_t cpa_state;
+    if (g_qat_not_available) {
+        return CPA_STATUS_FAIL;
+    }
+    if (g_qat_initialized) {
+        return CPA_STATUS_SUCCESS;
+    }
+
+    cpa_state = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
+
+    g_qat_not_available = (cpa_state != CPA_STATUS_SUCCESS);
+    g_qat_initialized = (cpa_state == CPA_STATUS_SUCCESS);
+
+    qat_context = std::make_unique<QATContext>();
+    return cpa_state;
+}
+
+}
diff --git a/contrib/qat/qatzpp/qat.hpp b/contrib/qat/qatzpp/qat.hpp
new file mode 100644
index 0000000..8ee7746
--- /dev/null
+++ b/contrib/qat/qatzpp/qat.hpp
@@ -0,0 +1,19 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#ifndef QATZPP_QAT_HPP
+#define QATZPP_QAT_HPP
+
+namespace qat
+{
+
+int Initialize();
+
+}
+
+#endif
\ No newline at end of file
diff --git a/contrib/qat/qatzpp/qat_buffer_list.cpp b/contrib/qat/qatzpp/qat_buffer_list.cpp
new file mode 100644
index 0000000..f0eea49
--- /dev/null
+++ b/contrib/qat/qatzpp/qat_buffer_list.cpp
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#include "qat_buffer_list.hpp"
+
+namespace qat
+{
+
+BufferListUser::BufferListUser(
+    uint8_t *data,
+    size_t size,
+    size_t metadata_size)
+{
+    flat_buffers = std::vector<CpaFlatBuffer>(1);
+    flat_buffers[0].pData = data;
+    flat_buffers[0].dataLenInBytes = size;
+    list.pPrivateMetaData = AllocBlockArray<uint8_t>(metadata_size, 0);
+    list.numBuffers = 1;
+    list.pBuffers = flat_buffers.data();
+}
+
+BufferListUser::~BufferListUser()
+{
+    if (list.pPrivateMetaData) {
+        Free(list.pPrivateMetaData);
+    }
+}
+
+}
diff --git a/contrib/qat/qatzpp/qat_buffer_list.hpp b/contrib/qat/qatzpp/qat_buffer_list.hpp
new file mode 100644
index 0000000..2a28175
--- /dev/null
+++ b/contrib/qat/qatzpp/qat_buffer_list.hpp
@@ -0,0 +1,32 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#ifndef QATZPP_QAT_BUFFER_LIST_HPP
+#define QATZPP_QAT_BUFFER_LIST_HPP
+
+#include <qat/cpa.h>
+
+#include "io_buffers.h"
+
+namespace qat
+{
+
+struct BufferListUser final : public BaseBufferList
+{
+    BufferListUser(
+        uint8_t *data,
+        size_t size,
+        size_t metadata_size
+    );
+
+    ~BufferListUser() override;
+};
+
+}
+
+#endif
\ No newline at end of file
diff --git a/contrib/qat/qatzpp/qat_instance.cpp b/contrib/qat/qatzpp/qat_instance.cpp
new file mode 100644
index 0000000..5b833c2
--- /dev/null
+++ b/contrib/qat/qatzpp/qat_instance.cpp
@@ -0,0 +1,135 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#include <qat/qae_mem.h>
+
+#include <iostream>
+#include <vector>
+
+#include "memory.hpp"
+#include "qat_instance.hpp"
+#include "session.hpp"
+
+#define MAX_SAMPLE_BUFFER_SIZE  (4*1024*1024)
+
+namespace qat
+{
+
+static std::mutex g_instance_mutex;
+static std::vector<std::shared_ptr<Instance>> instances;
+
+static CpaPhysicalAddr virt2Phys(void *virt_addr)
+{
+    return (CpaPhysicalAddr)qaeVirtToPhysNUMA(virt_addr);
+}
+
+Instance::Instance(CpaInstanceHandle instance):
+    instance_(instance),
+    num_intermediate_buffer_lists_(0),
+    intermediate_buffer_array_(nullptr),
+    started_(false)
+{
+    CpaDcInstanceCapabilities caps{};
+    cpaDcQueryCapabilities(instance_, &caps);
+
+    if (!caps.statelessDeflateCompression || !caps.statelessDeflateDecompression ||
+        !caps.checksumAdler32 || !caps.dynamicHuffman)
+    {
+        return;
+    }
+
+    if (caps.dynamicHuffmanBufferReq) {
+        uint32_t buffer_metadata_size;
+        cpaDcBufferListGetMetaSize(instance_, 1, &buffer_metadata_size);
+        cpaDcGetNumIntermediateBuffers(instance_, &num_intermediate_buffer_lists_);
+
+        if(num_intermediate_buffer_lists_) {
+            intermediate_buffer_array_ = AllocBlockArray<CpaBufferList*>(num_intermediate_buffer_lists_, 0);
+        }
+        for (int i = 0; i < num_intermediate_buffer_lists_; ++i) {
+            intermediate_buffer_array_[i] = AllocBlock<CpaBufferList>(0);
+            intermediate_buffer_array_[i]->pPrivateMetaData =
+                                                    AllocBlockArray<uint8_t>(buffer_metadata_size, 0);
+            intermediate_buffer_array_[i]->pBuffers = AllocBlock<CpaFlatBuffer>(0);
+            intermediate_buffer_array_[i]->pBuffers->pData =
+                                                    AllocBlockArray<uint8_t>(MAX_SAMPLE_BUFFER_SIZE, 0);
+            intermediate_buffer_array_[i]->pBuffers->dataLenInBytes = MAX_SAMPLE_BUFFER_SIZE;
+        }
+    }
+
+    cpaDcSetAddressTranslation(instance_, virt2Phys);
+}
+
+Instance::~Instance()
+{
+}
+
+CpaDcInstanceCapabilities Instance::GetCapabilities()
+{
+    CpaDcInstanceCapabilities caps{};
+    cpaDcQueryCapabilities(instance_, &caps);
+
+    return caps;
+}
+
+CpaInstanceInfo2 Instance::GetInfo()
+{
+    CpaInstanceInfo2 info{};
+    cpaDcInstanceGetInfo2(instance_, &info);
+
+    return info;
+}
+
+int Instance::Start()
+{
+    std::lock_guard<std::mutex> lock(mutex_);
+
+    if (started_) {
+        return 0;
+    }
+
+    int ret = cpaDcStartInstance
+    (
+        instance_,
+        num_intermediate_buffer_lists_,
+        intermediate_buffer_array_
+    );
+    if (ret) {
+        return -1;
+    }
+    started_ = true;
+    return 0;
+}
+
+std::vector<std::shared_ptr<Instance>> Instance::Create()
+{
+    std::lock_guard<std::mutex> lock(g_instance_mutex);
+    uint16_t num_instances = 0;
+
+    if (!instances.empty()) {
+        return instances;
+    }
+
+    cpaDcGetNumInstances(&num_instances);
+
+    if (!num_instances) {
+        std::cerr << "No instances found\n";
+        return {};
+    }
+
+    std::vector<CpaInstanceHandle> handles(num_instances);
+    cpaDcGetInstances(num_instances, handles.data());
+
+    for(auto& handle: handles) {
+        instances.emplace_back(std::make_shared<Instance>(handle));
+    }
+
+    return instances;
+}
+
+}
diff --git a/contrib/qat/qatzpp/qat_instance.hpp b/contrib/qat/qatzpp/qat_instance.hpp
new file mode 100644
index 0000000..1a2b4af
--- /dev/null
+++ b/contrib/qat/qatzpp/qat_instance.hpp
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#ifndef QATZPP_QAT_INSTANCE_HPP
+#define QATZPP_QAT_INSTANCE_HPP
+
+#include <qat/cpa_dc.h>
+
+#include <memory>
+#include <mutex>
+#include <vector>
+
+namespace qat
+{
+
+class Instance
+{
+public:
+    Instance(CpaInstanceHandle);
+    ~Instance();
+
+    CpaInstanceHandle GetHandle() { return instance_; }
+    CpaDcInstanceCapabilities GetCapabilities();
+    CpaInstanceInfo2 GetInfo();
+
+    int Start(void);
+    static std::vector<std::shared_ptr<Instance>> Create();
+private:
+
+    CpaInstanceHandle instance_;
+    uint16_t num_intermediate_buffer_lists_;
+    CpaBufferList **intermediate_buffer_array_;
+    bool started_;
+
+    std::mutex mutex_;
+};
+
+}
+
+#endif
\ No newline at end of file
diff --git a/contrib/qat/qatzpp/qat_task.cpp b/contrib/qat/qatzpp/qat_task.cpp
new file mode 100644
index 0000000..a53ea94
--- /dev/null
+++ b/contrib/qat/qatzpp/qat_task.cpp
@@ -0,0 +1,58 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#include <qat/cpa.h>
+#include <qat/icp_sal_poll.h>
+
+#include "qat_task.hpp"
+
+namespace qat
+{
+
+QATTask::QATTask(std::shared_ptr<Instance> &qat_instance,
+    std::unique_ptr<IOBuffers> &&buffers,
+    std::unique_ptr<CpaDcRqResults> &&dc_results):
+    qat_instance_(qat_instance),
+    io_buffers_(std::move(buffers)),
+    dc_results_(std::move(dc_results)),
+    completed_(false)
+{
+}
+
+void QATTask::WaitCompletion()
+{
+    if (completed_) {
+        return;
+    }
+
+    while (!completed_) {
+        icp_sal_DcPollInstance(qat_instance_->GetHandle(), 0);
+    }
+}
+
+IOBuffers *QATTask::GetBuffers()
+{
+    return io_buffers_.get();
+}
+
+CpaDcRqResults *QATTask::GetResults()
+{
+    return dc_results_.get();
+}
+
+void dc_callback(void *callback_tag, CpaStatus status)
+{
+    if (!callback_tag) {
+        return;
+    }
+    // Ugly and dangerous
+    QATTask* task = static_cast<QATTask*>(callback_tag);
+    task->completed_ = true;
+}
+
+}
\ No newline at end of file
diff --git a/contrib/qat/qatzpp/qat_task.hpp b/contrib/qat/qatzpp/qat_task.hpp
new file mode 100644
index 0000000..3950502
--- /dev/null
+++ b/contrib/qat/qatzpp/qat_task.hpp
@@ -0,0 +1,54 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#ifndef QATZPP_WORK_HPP
+#define QATZPP_WORK_HPP
+
+#include <qat/cpa.h>
+
+#include <memory>
+
+#include "io_buffers.h"
+
+namespace qat
+{
+
+class QATTask
+{
+public:
+    explicit QATTask(std::shared_ptr<Instance> &qat_instance,
+                std::unique_ptr<IOBuffers> &&,
+                std::unique_ptr<CpaDcRqResults> &&dc_results);
+
+    QATTask(QATTask &&) = delete;
+    QATTask& operator=(QATTask &&) = delete;
+
+    QATTask(const QATTask &) = delete;
+    QATTask &operator=(const QATTask &) = delete;
+
+    void WaitCompletion();
+
+    IOBuffers *GetBuffers();
+    CpaDcRqResults *GetResults();
+
+private:
+    bool completed_;
+
+    std::shared_ptr<Instance> qat_instance_;
+
+    std::unique_ptr<CpaDcRqResults> dc_results_;
+    std::unique_ptr<IOBuffers> io_buffers_;
+
+    friend void dc_callback(void *, CpaStatus);
+};
+
+void dc_callback(void*, CpaStatus);
+
+}
+
+#endif
\ No newline at end of file
diff --git a/contrib/qat/qatzpp/session.cpp b/contrib/qat/qatzpp/session.cpp
new file mode 100644
index 0000000..b4cefb3
--- /dev/null
+++ b/contrib/qat/qatzpp/session.cpp
@@ -0,0 +1,129 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#include <iostream>
+#include <semaphore.h>
+
+#include "memory.hpp"
+#include "session.hpp"
+
+namespace qat
+{
+
+constexpr CpaDcHuffType kHuffType = CPA_DC_HT_FULL_DYNAMIC;
+
+DeflateSession::DeflateSession(
+    std::shared_ptr<Instance> &qat_instance,
+    CpaDcCompLvl comp_level, CpaDcChecksum checksum,
+    uint32_t numa_node):
+    qat_instance_(qat_instance)
+{
+    uint32_t session_size = 0;
+    uint32_t ctx_size = 0;
+
+    CpaDcSessionSetupData sd{};
+    sd.compLevel = comp_level;
+    sd.compType = CPA_DC_DEFLATE;
+    sd.huffType = kHuffType;
+    sd.autoSelectBestHuffmanTree = CPA_DC_ASB_UNCOMP_STATIC_DYNAMIC_WITH_STORED_HDRS;
+    sd.sessDirection = CPA_DC_DIR_COMBINED;
+    sd.sessState = CPA_DC_STATELESS;
+    sd.checksum = checksum;
+
+    cpaDcGetSessionSize(qat_instance_->GetHandle(), &sd, &session_size, &ctx_size);
+    session_ = AllocBlockArray<uint8_t>(session_size, numa_node);
+
+    cpaDcInitSession(
+        qat_instance_->GetHandle(),
+        session_,
+        &sd,
+        nullptr, // No context for stateless operations
+        &dc_callback
+    );
+
+}
+
+DeflateSession::~DeflateSession()
+{
+    if (session_) {
+        cpaDcRemoveSession(qat_instance_->GetHandle(), session_);
+        Free(session_);
+    }
+
+    session_ = nullptr;
+}
+
+std::unique_ptr<QATTask> DeflateSession::Deflate(
+    std::unique_ptr<IOBuffers> &&buffers,
+    bool flush_final)
+{
+    CpaDcOpData op_data{};
+    op_data.flushFlag = (flush_final) ?
+        CPA_DC_FLUSH_FINAL : CPA_DC_FLUSH_FULL;
+    op_data.compressAndVerify = CPA_TRUE;
+    op_data.inputSkipData.skipMode = CPA_DC_SKIP_DISABLED;
+    op_data.outputSkipData.skipMode = CPA_DC_SKIP_DISABLED;
+
+    auto task = std::make_unique<QATTask>(
+        qat_instance_, std::move(buffers),
+        std::make_unique<CpaDcRqResults>()
+    );
+
+    cpaDcCompressData2(
+        qat_instance_->GetHandle(),
+        session_,
+        &task->GetBuffers()->GetSrc()->list,
+        &task->GetBuffers()->GetDst()->list,
+        &op_data,
+        task->GetResults(),
+        static_cast<void*>(task.get())
+    );
+
+    return std::move(task);
+}
+
+std::unique_ptr<QATTask> DeflateSession::Inflate(std::unique_ptr<IOBuffers> &&buffers)
+{
+    CpaDcOpData op_data = {};
+    op_data.flushFlag = CPA_DC_FLUSH_FINAL;
+    op_data.compressAndVerify = CPA_TRUE;
+    op_data.inputSkipData.skipMode = CPA_DC_SKIP_DISABLED;
+    op_data.outputSkipData.skipMode = CPA_DC_SKIP_DISABLED;
+
+    auto task = std::make_unique<QATTask>(
+        qat_instance_, std::move(buffers),
+        std::make_unique<CpaDcRqResults>()
+    );
+
+    cpaDcDecompressData2(
+        qat_instance_->GetHandle(),
+        session_,
+        &task->GetBuffers()->GetSrc()->list,
+        &task->GetBuffers()->GetDst()->list,
+        &op_data,
+        task->GetResults(),
+        static_cast<void*>(task.get())
+    );
+
+    return std::move(task);
+}
+
+uint32_t DeflateSession::GetDeflateBound(uint32_t input_size)
+{
+    uint32_t output_size = 0;
+
+    cpaDcDeflateCompressBound(
+        qat_instance_->GetHandle(),
+        kHuffType,
+        input_size, &output_size
+    );
+
+    return output_size;
+}
+
+}
diff --git a/contrib/qat/qatzpp/session.hpp b/contrib/qat/qatzpp/session.hpp
new file mode 100644
index 0000000..c8af47c
--- /dev/null
+++ b/contrib/qat/qatzpp/session.hpp
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2024 Intel Corporation. All rights reserved.
+ * Authors:
+ *  Gustavo A Espinoza   <gustavo.adolfo.espinoza.quintero@intel.com>
+ *                       <gustavoaespinozaq@hotmail.com>
+ *
+ * For conditions of distribution and use, see copyright notice in zlib.h
+ */
+#ifndef QATZPP_SESSION_HPP
+#define QATZPP_SESSION_HPP
+
+#include <qat/cpa.h>
+#include <qat/cpa_dc.h>
+
+#include <memory>
+
+#include "io_buffers.h"
+#include "qat_task.hpp"
+
+namespace qat
+{
+
+class DeflateSession
+{
+public:
+    DeflateSession(
+        std::shared_ptr<Instance> &, CpaDcCompLvl,
+        CpaDcChecksum, uint32_t numa_node);
+    ~DeflateSession();
+
+    std::unique_ptr<QATTask> Deflate(std::unique_ptr<IOBuffers> &&buffers, bool flush_final);
+    std::unique_ptr<QATTask> Inflate(std::unique_ptr<IOBuffers> &&buffers);
+
+    uint32_t GetDeflateBound(uint32_t input_size);
+
+    std::shared_ptr<Instance> getInstance() { return qat_instance_; }
+
+private:
+    std::shared_ptr<Instance> qat_instance_;
+    CpaDcSessionHandle session_;
+};
+
+}
+
+#endif
\ No newline at end of file
diff --git a/contrib/tests/fuzzers/BUILD.gn b/contrib/tests/fuzzers/BUILD.gn
index 16e918a..d7db4b3 100644
--- a/contrib/tests/fuzzers/BUILD.gn
+++ b/contrib/tests/fuzzers/BUILD.gn
@@ -34,6 +34,11 @@ fuzzer_test("zlib_deflate_set_dictionary_fuzzer") {
   deps = [ "../../../:zlib" ]
 }
 
+fuzzer_test("zlib_compress_fuzzer") {
+  sources = [ "compress_fuzzer.cc" ]
+  deps = [ "../../../:zlib" ]
+}
+
 fuzzer_test("zlib_deflate_fuzzer") {
   sources = [ "deflate_fuzzer.cc" ]
   deps = [ "../../../:zlib" ]
diff --git a/contrib/tests/fuzzers/compress_fuzzer.cc b/contrib/tests/fuzzers/compress_fuzzer.cc
new file mode 100644
index 0000000..3afc781
--- /dev/null
+++ b/contrib/tests/fuzzers/compress_fuzzer.cc
@@ -0,0 +1,46 @@
+// Copyright 2024 The Chromium Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#include <fuzzer/FuzzedDataProvider.h>
+
+#include <vector>
+
+#include "zlib.h"
+
+// Fuzzer builds often have NDEBUG set, so roll our own assert macro.
+#define ASSERT(cond)                                                           \
+  do {                                                                         \
+    if (!(cond)) {                                                             \
+      fprintf(stderr, "%s:%d Assert failed: %s\n", __FILE__, __LINE__, #cond); \
+      exit(1);                                                                 \
+    }                                                                          \
+  } while (0)
+
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
+  FuzzedDataProvider fdp(data, size);
+  const int level = fdp.PickValueInArray({-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
+  const std::vector<uint8_t> src = fdp.ConsumeRemainingBytes<uint8_t>();
+
+  const unsigned long compress_bound = compressBound(src.size());
+  std::vector<uint8_t> compressed;
+  compressed.resize(compress_bound);
+
+  unsigned long compressed_size = compress_bound;
+  int ret = compress2(compressed.data(), &compressed_size, src.data(),
+                      src.size(), level);
+  ASSERT(ret == Z_OK);
+  ASSERT(compressed_size <= compress_bound);
+  compressed.resize(compressed_size);
+
+  std::vector<uint8_t> uncompressed;
+  uncompressed.resize(src.size());
+  unsigned long uncompressed_size = uncompressed.size();
+  ret = uncompress(uncompressed.data(), &uncompressed_size, compressed.data(),
+                   compressed.size());
+  ASSERT(ret == Z_OK);
+  ASSERT(uncompressed_size == src.size());
+  ASSERT(uncompressed == src);
+
+  return 0;
+}
diff --git a/crc32.c b/crc32.c
index 32686f9..204aa1a 100644
--- a/crc32.c
+++ b/crc32.c
@@ -700,24 +700,29 @@ local z_word_t crc_word_big(z_word_t data) {
 /* ========================================================================= */
 unsigned long ZEXPORT crc32_z(unsigned long crc, const unsigned char FAR *buf,
                               z_size_t len) {
+
+    /* If no optimizations are enabled, do it as canonical zlib. */
+#if !defined(CRC32_SIMD_SSE42_PCLMUL) && !defined(CRC32_ARMV8_CRC32) && \
+    !defined(RISCV_RVV) && !defined(CRC32_SIMD_AVX512_PCLMUL)
+    if (buf == Z_NULL) {
+        return 0UL;
+    }
+#else
     /*
      * zlib convention is to call crc32(0, NULL, 0); before making
      * calls to crc32(). So this is a good, early (and infrequent)
      * place to cache CPU features if needed for those later, more
      * interesting crc32() calls.
      */
-#if defined(CRC32_SIMD_SSE42_PCLMUL) || defined(CRC32_ARMV8_CRC32) \
-    || defined(RISCV_RVV)
-    /*
-     * Since this routine can be freely used, check CPU features here.
-     */
     if (buf == Z_NULL) {
-        if (!len) /* Assume user is calling crc32(0, NULL, 0); */
+        if (!len)
             cpu_check_features();
         return 0UL;
     }
-
 #endif
+    /* If AVX-512 is enabled, we will use it for longer inputs and fallback
+     * to SSE4.2 and eventually the portable implementation to handle the tail.
+     */
 #if defined(CRC32_SIMD_AVX512_PCLMUL)
     if (x86_cpu_enable_avx512 && len >= Z_CRC32_AVX512_MINIMUM_LENGTH) {
         /* crc32 64-byte chunks */
@@ -730,7 +735,8 @@ unsigned long ZEXPORT crc32_z(unsigned long crc, const unsigned char FAR *buf,
         /* Fall into the default crc32 for the remaining data. */
         buf += chunk_size;
     }
-#elif defined(CRC32_SIMD_SSE42_PCLMUL)
+#endif
+#if defined(CRC32_SIMD_SSE42_PCLMUL)
     if (x86_cpu_enable_simd && len >= Z_CRC32_SSE42_MINIMUM_LENGTH) {
         /* crc32 16-byte chunks */
         z_size_t chunk_size = len & ~Z_CRC32_SSE42_CHUNKSIZE_MASK;
@@ -758,11 +764,8 @@ unsigned long ZEXPORT crc32_z(unsigned long crc, const unsigned char FAR *buf,
             buf += chunk_size;
         }
 #endif
-        return armv8_crc32_little(buf, len, crc); /* Armv8@32bit or tail. */
-    }
-#else
-    if (buf == Z_NULL) {
-        return 0UL;
+        /* This is scalar and self contained, used on Armv8@32bit or tail. */
+        return armv8_crc32_little(buf, len, crc);
     }
 #endif /* CRC32_SIMD */
 
@@ -1165,6 +1168,11 @@ ZLIB_INTERNAL void crc_reset(deflate_state *const s)
 
 ZLIB_INTERNAL void crc_finalize(deflate_state *const s)
 {
+#ifdef QAT_COMPRESSION_ENABLED
+    if (s->qat_s) {
+        return;
+    }
+#endif
 #ifdef CRC32_SIMD_SSE42_PCLMUL
     if (x86_cpu_enable_simd)
         s->strm->adler = crc_fold_512to32(s);
diff --git a/crc32_simd.c b/crc32_simd.c
index 7428270..1c60ae9 100644
--- a/crc32_simd.c
+++ b/crc32_simd.c
@@ -200,7 +200,8 @@ uint32_t ZLIB_INTERNAL crc32_avx512_simd_(  /* AVX512+PCLMUL */
     return _mm_extract_epi32(a1, 1);
 }
 
-#elif defined(CRC32_SIMD_SSE42_PCLMUL)
+#endif
+#if defined(CRC32_SIMD_SSE42_PCLMUL)
 
 /*
  * crc32_sse42_simd_(): compute the crc32 of the buffer, where the buffer
@@ -386,9 +387,9 @@ uint32_t ZLIB_INTERNAL crc32_sse42_simd_(  /* SSE4.2+PCLMUL */
 #endif
 
 #if defined(__aarch64__)
-#define TARGET_ARMV8_WITH_CRC __attribute__((target("aes,crc")))
+#define TARGET_ARMV8_WITH_CRC __attribute__((target("arch=armv8-a+aes+crc")))
 #else  // !defined(__aarch64__)
-#define TARGET_ARMV8_WITH_CRC __attribute__((target("armv8-a,crc")))
+#define TARGET_ARMV8_WITH_CRC __attribute__((target("crc")))
 #endif  // defined(__aarch64__)
 
 #elif defined(__GNUC__)
@@ -397,7 +398,7 @@ uint32_t ZLIB_INTERNAL crc32_sse42_simd_(  /* SSE4.2+PCLMUL */
  */
 #include <arm_acle.h>
 #include <arm_neon.h>
-#define TARGET_ARMV8_WITH_CRC
+#define TARGET_ARMV8_WITH_CRC __attribute__((target("arch=armv8-a+crc+crypto")))
 #else  // !defined(__GNUC__) && !defined(_aarch64__)
 #error ARM CRC32 SIMD extensions only supported for Clang and GCC
 #endif
diff --git a/deflate.c b/deflate.c
index b9a3120..1d4c688 100644
--- a/deflate.c
+++ b/deflate.c
@@ -1,5 +1,5 @@
 /* deflate.c -- compress data using the deflation algorithm
- * Copyright (C) 1995-2023 Jean-loup Gailly and Mark Adler
+ * Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
  * For conditions of distribution and use, see copyright notice in zlib.h
  */
 
@@ -57,6 +57,10 @@
 #include "slide_hash_simd.h"
 #endif
 
+#if defined(QAT_COMPRESSION_ENABLED)
+#include "contrib/qat/deflate_qat.h"
+#endif
+
 #include "contrib/optimizations/insert_string.h"
 
 #ifdef FASTEST
@@ -65,7 +69,7 @@
 #endif
 
 const char deflate_copyright[] =
-   " deflate 1.3.0.1 Copyright 1995-2023 Jean-loup Gailly and Mark Adler ";
+   " deflate 1.3.1 Copyright 1995-2024 Jean-loup Gailly and Mark Adler ";
 /*
   If you use the zlib library in a product, an acknowledgment is welcome
   in the documentation of your product. If for some reason you cannot
@@ -481,14 +485,7 @@ int ZEXPORT deflateInit2_(z_streamp strm, int level, int method,
     s->window = (Bytef *) ZALLOC(strm,
                                  s->w_size + WINDOW_PADDING,
                                  2*sizeof(Byte));
-    /* Avoid use of unitialized values in the window, see crbug.com/1137613 and
-     * crbug.com/1144420 */
-    zmemzero(s->window, (s->w_size + WINDOW_PADDING) * (2 * sizeof(Byte)));
     s->prev   = (Posf *)  ZALLOC(strm, s->w_size, sizeof(Pos));
-    /* Avoid use of uninitialized value, see:
-     * https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=11360
-     */
-    zmemzero(s->prev, s->w_size * sizeof(Pos));
     s->head   = (Posf *)  ZALLOC(strm, s->hash_size, sizeof(Pos));
 
     s->high_water = 0;      /* nothing written to s->window yet */
@@ -547,6 +544,13 @@ int ZEXPORT deflateInit2_(z_streamp strm, int level, int method,
         deflateEnd (strm);
         return Z_MEM_ERROR;
     }
+    /* Avoid use of unitialized values in the window, see crbug.com/1137613 and
+     * crbug.com/1144420 */
+    zmemzero(s->window, (s->w_size + WINDOW_PADDING) * (2 * sizeof(Byte)));
+    /* Avoid use of uninitialized value, see:
+     * https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=11360
+     */
+    zmemzero(s->prev, s->w_size * sizeof(Pos));
 #ifdef LIT_MEM
     s->d_buf = (ushf *)(s->pending_buf + (s->lit_bufsize << 1));
     s->l_buf = s->pending_buf + (s->lit_bufsize << 2);
@@ -564,6 +568,13 @@ int ZEXPORT deflateInit2_(z_streamp strm, int level, int method,
     s->strategy = strategy;
     s->method = (Byte)method;
 
+#if defined(QAT_COMPRESSION_ENABLED)
+    s->qat_s = NULL;
+    if (s->level && qat_deflate_init() == Z_OK) {
+        s->qat_s = qat_deflate_state_init(s->level, s->wrap);
+    }
+#endif
+
     return deflateReset(strm);
 }
 
@@ -962,6 +973,12 @@ local void flush_pending(z_streamp strm) {
     unsigned len;
     deflate_state *s = strm->state;
 
+#if defined(QAT_COMPRESSION_ENABLED)
+    if (s->qat_s) {
+        qat_flush_pending(s);
+    }
+#endif
+
     _tr_flush_bits(s);
     len = s->pending;
     if (len > strm->avail_out) len = strm->avail_out;
@@ -1315,6 +1332,12 @@ int ZEXPORT deflateEnd(z_streamp strm) {
     TRY_FREE(strm, strm->state->prev);
     TRY_FREE(strm, strm->state->window);
 
+#if defined(QAT_COMPRESSION_ENABLED)
+    if (strm->state->qat_s) {
+        qat_deflate_state_free(strm->state);
+    }
+#endif
+
     ZFREE(strm, strm->state);
     strm->state = Z_NULL;
 
@@ -1389,6 +1412,14 @@ int ZEXPORT deflateCopy(z_streamp dest, z_streamp source) {
     ds->d_desc.dyn_tree = ds->dyn_dtree;
     ds->bl_desc.dyn_tree = ds->bl_tree;
 
+#if defined(QAT_COMPRESSION_ENABLED)
+    if(ss->qat_s) {
+        ds->qat_s = qat_deflate_copy(ss);
+        if (!ds->qat_s)
+            return Z_MEM_ERROR;
+    }
+#endif
+
     return Z_OK;
 #endif /* MAXSEG_64K */
 }
@@ -1632,13 +1663,21 @@ local uInt longest_match(deflate_state *s, IPos cur_match) {
  */
 local void check_match(deflate_state *s, IPos start, IPos match, int length) {
     /* check that the match is indeed a match */
-    if (zmemcmp(s->window + match,
-                s->window + start, length) != EQUAL) {
-        fprintf(stderr, " start %u, match %u, length %d\n",
-                start, match, length);
+    Bytef *back = s->window + (int)match, *here = s->window + start;
+    IPos len = length;
+    if (match == (IPos)-1) {
+        /* match starts one byte before the current window -- just compare the
+           subsequent length-1 bytes */
+        back++;
+        here++;
+        len--;
+    }
+    if (zmemcmp(back, here, len) != EQUAL) {
+        fprintf(stderr, " start %u, match %d, length %d\n",
+                start, (int)match, length);
         do {
-            fprintf(stderr, "%c%c", s->window[match++], s->window[start++]);
-        } while (--length != 0);
+            fprintf(stderr, "(%02x %02x)", *back++, *here++);
+        } while (--len != 0);
         z_error("invalid match");
     }
     if (z_verbose > 1) {
@@ -1880,6 +1919,24 @@ local block_state deflate_fast(deflate_state *s, int flush) {
     IPos hash_head;       /* head of the hash chain */
     int bflush;           /* set if current block must be flushed */
 
+#if defined(QAT_COMPRESSION_ENABLED)
+    if (s->qat_s) {
+        qat_block_state qat_block = qat_deflate_step(s, flush);
+        switch (qat_block) {
+        case qat_block_need_more:
+            return need_more;
+        case qat_block_done:
+            return block_done;
+        case qat_block_finish_started:
+            return finish_started;
+        case qat_block_finish_done:
+            return finish_done;
+        case qat_failure:
+            break;
+        }
+    }
+#endif
+
     for (;;) {
         /* Make sure that we always have enough lookahead, except
          * at the end of the input file. We need MAX_MATCH bytes
@@ -1982,6 +2039,24 @@ local block_state deflate_slow(deflate_state *s, int flush) {
     IPos hash_head;          /* head of hash chain */
     int bflush;              /* set if current block must be flushed */
 
+#if defined(QAT_COMPRESSION_ENABLED)
+    if (s->qat_s) {
+        qat_block_state qat_block = qat_deflate_step(s, flush);
+        switch (qat_block) {
+        case qat_block_need_more:
+            return need_more;
+        case qat_block_done:
+            return block_done;
+        case qat_block_finish_started:
+            return finish_started;
+        case qat_block_finish_done:
+            return finish_done;
+        case qat_failure:
+            break;
+        }
+    }
+#endif
+
     /* Process the input block. */
     for (;;) {
         /* Make sure that we always have enough lookahead, except
diff --git a/deflate.h b/deflate.h
index eb7f072..2d5eaab 100644
--- a/deflate.h
+++ b/deflate.h
@@ -1,5 +1,5 @@
 /* deflate.h -- internal compression state
- * Copyright (C) 1995-2018 Jean-loup Gailly
+ * Copyright (C) 1995-2024 Jean-loup Gailly
  * For conditions of distribution and use, see copyright notice in zlib.h
  */
 
@@ -282,6 +282,13 @@ typedef struct internal_state {
      * hash is enabled.
      */
 
+#if defined(QAT_COMPRESSION_ENABLED)
+    /* Pointer to a struct that contains the current state of the QAT
+     * stream.
+     */
+    struct qat_deflate *qat_s;
+#endif
+
 } FAR deflate_state;
 
 /* Output a byte on the stream.
diff --git a/google/compression_utils.cc b/google/compression_utils.cc
index 0ba3110..d50c969 100644
--- a/google/compression_utils.cc
+++ b/google/compression_utils.cc
@@ -89,19 +89,18 @@ bool GzipUncompress(const std::string& input, std::string* output) {
   return false;
 }
 
-bool GzipUncompress(base::span<const char> input,
-                    base::span<const char> output) {
-  return GzipUncompress(base::as_bytes(input), base::as_bytes(output));
+bool GzipUncompress(base::span<const char> input, base::span<char> output) {
+  return GzipUncompress(base::as_bytes(input), base::as_writable_bytes(output));
 }
 
 bool GzipUncompress(base::span<const uint8_t> input,
-                    base::span<const uint8_t> output) {
+                    base::span<uint8_t> output) {
   uLongf uncompressed_size = GetUncompressedSize(input);
   if (uncompressed_size > output.size())
     return false;
   return zlib_internal::GzipUncompressHelper(
-             reinterpret_cast<Bytef*>(const_cast<uint8_t*>(output.data())),
-             &uncompressed_size, reinterpret_cast<const Bytef*>(input.data()),
+             reinterpret_cast<Bytef*>(output.data()), &uncompressed_size,
+             reinterpret_cast<const Bytef*>(input.data()),
              static_cast<uLongf>(input.size())) == Z_OK;
 }
 
diff --git a/google/compression_utils.h b/google/compression_utils.h
index ea39981..fd81153 100644
--- a/google/compression_utils.h
+++ b/google/compression_utils.h
@@ -43,12 +43,11 @@ bool GzipUncompress(const std::string& input, std::string* output);
 // needed. |output|'s size must be at least as large as the return value from
 // GetUncompressedSize.
 // Returns true for success.
-bool GzipUncompress(base::span<const char> input,
-                    base::span<const char> output);
+bool GzipUncompress(base::span<const char> input, base::span<char> output);
 
 // Like the above method, but using uint8_t instead.
 bool GzipUncompress(base::span<const uint8_t> input,
-                    base::span<const uint8_t> output);
+                    base::span<uint8_t> output);
 
 // Uncompresses the data in |input| using gzip, and writes the results to
 // |output|, which must NOT be the underlying string of |input|, and is resized
diff --git a/google/zip_internal.cc b/google/zip_internal.cc
index 9b20b42..f33da59 100644
--- a/google/zip_internal.cc
+++ b/google/zip_internal.cc
@@ -8,12 +8,12 @@
 #include <string.h>
 
 #include <algorithm>
+#include <string_view>
 
 #include "base/containers/fixed_flat_set.h"
 #include "base/files/file_path.h"
 #include "base/logging.h"
 #include "base/notreached.h"
-#include "base/strings/string_piece.h"
 #include "base/strings/string_util.h"
 #include "base/strings/utf_string_conversions.h"
 
@@ -166,7 +166,6 @@ struct ZipBuffer {
 void* OpenZipBuffer(void* opaque, const void* /*filename*/, int mode) {
   if ((mode & ZLIB_FILEFUNC_MODE_READWRITEFILTER) != ZLIB_FILEFUNC_MODE_READ) {
     NOTREACHED();
-    return NULL;
   }
   ZipBuffer* buffer = static_cast<ZipBuffer*>(opaque);
   if (!buffer || !buffer->data || !buffer->length)
@@ -197,7 +196,6 @@ uLong WriteZipBuffer(void* /*opaque*/,
                      const void* /*buf*/,
                      uLong /*size*/) {
   NOTREACHED();
-  return 0;
 }
 
 // Returns the offset from the beginning of the data.
@@ -229,7 +227,6 @@ long SeekZipBuffer(void* opaque,
     return 0;
   }
   NOTREACHED();
-  return -1;
 }
 
 // Closes the input offset and deletes all resources used for compressing or
@@ -398,64 +395,64 @@ Compression GetCompressionMethod(const base::FilePath& path) {
   if (ext.empty())
     return kDeflated;
 
-  using StringPiece = base::FilePath::StringPieceType;
 
   // Skip the leading dot.
-  StringPiece ext_without_dot = ext;
+  base::FilePath::StringViewType ext_without_dot = ext;
   DCHECK_EQ(ext_without_dot.front(), FILE_PATH_LITERAL('.'));
   ext_without_dot.remove_prefix(1);
 
   // Well known filename extensions of files that a likely to be already
   // compressed. The extensions are in lower case without the leading dot.
-  static constexpr auto kExts = base::MakeFixedFlatSet<StringPiece>({
-      FILE_PATH_LITERAL("3g2"),   //
-      FILE_PATH_LITERAL("3gp"),   //
-      FILE_PATH_LITERAL("7z"),    //
-      FILE_PATH_LITERAL("7zip"),  //
-      FILE_PATH_LITERAL("aac"),   //
-      FILE_PATH_LITERAL("avi"),   //
-      FILE_PATH_LITERAL("bz"),    //
-      FILE_PATH_LITERAL("bz2"),   //
-      FILE_PATH_LITERAL("crx"),   //
-      FILE_PATH_LITERAL("gif"),   //
-      FILE_PATH_LITERAL("gz"),    //
-      FILE_PATH_LITERAL("jar"),   //
-      FILE_PATH_LITERAL("jpeg"),  //
-      FILE_PATH_LITERAL("jpg"),   //
-      FILE_PATH_LITERAL("lz"),    //
-      FILE_PATH_LITERAL("m2v"),   //
-      FILE_PATH_LITERAL("m4p"),   //
-      FILE_PATH_LITERAL("m4v"),   //
-      FILE_PATH_LITERAL("mng"),   //
-      FILE_PATH_LITERAL("mov"),   //
-      FILE_PATH_LITERAL("mp2"),   //
-      FILE_PATH_LITERAL("mp3"),   //
-      FILE_PATH_LITERAL("mp4"),   //
-      FILE_PATH_LITERAL("mpe"),   //
-      FILE_PATH_LITERAL("mpeg"),  //
-      FILE_PATH_LITERAL("mpg"),   //
-      FILE_PATH_LITERAL("mpv"),   //
-      FILE_PATH_LITERAL("ogg"),   //
-      FILE_PATH_LITERAL("ogv"),   //
-      FILE_PATH_LITERAL("png"),   //
-      FILE_PATH_LITERAL("qt"),    //
-      FILE_PATH_LITERAL("rar"),   //
-      FILE_PATH_LITERAL("taz"),   //
-      FILE_PATH_LITERAL("tb2"),   //
-      FILE_PATH_LITERAL("tbz"),   //
-      FILE_PATH_LITERAL("tbz2"),  //
-      FILE_PATH_LITERAL("tgz"),   //
-      FILE_PATH_LITERAL("tlz"),   //
-      FILE_PATH_LITERAL("tz"),    //
-      FILE_PATH_LITERAL("tz2"),   //
-      FILE_PATH_LITERAL("vob"),   //
-      FILE_PATH_LITERAL("webm"),  //
-      FILE_PATH_LITERAL("wma"),   //
-      FILE_PATH_LITERAL("wmv"),   //
-      FILE_PATH_LITERAL("xz"),    //
-      FILE_PATH_LITERAL("z"),     //
-      FILE_PATH_LITERAL("zip"),   //
-  });
+  static constexpr auto kExts =
+      base::MakeFixedFlatSet<base::FilePath::StringViewType>({
+          FILE_PATH_LITERAL("3g2"),   //
+          FILE_PATH_LITERAL("3gp"),   //
+          FILE_PATH_LITERAL("7z"),    //
+          FILE_PATH_LITERAL("7zip"),  //
+          FILE_PATH_LITERAL("aac"),   //
+          FILE_PATH_LITERAL("avi"),   //
+          FILE_PATH_LITERAL("bz"),    //
+          FILE_PATH_LITERAL("bz2"),   //
+          FILE_PATH_LITERAL("crx"),   //
+          FILE_PATH_LITERAL("gif"),   //
+          FILE_PATH_LITERAL("gz"),    //
+          FILE_PATH_LITERAL("jar"),   //
+          FILE_PATH_LITERAL("jpeg"),  //
+          FILE_PATH_LITERAL("jpg"),   //
+          FILE_PATH_LITERAL("lz"),    //
+          FILE_PATH_LITERAL("m2v"),   //
+          FILE_PATH_LITERAL("m4p"),   //
+          FILE_PATH_LITERAL("m4v"),   //
+          FILE_PATH_LITERAL("mng"),   //
+          FILE_PATH_LITERAL("mov"),   //
+          FILE_PATH_LITERAL("mp2"),   //
+          FILE_PATH_LITERAL("mp3"),   //
+          FILE_PATH_LITERAL("mp4"),   //
+          FILE_PATH_LITERAL("mpe"),   //
+          FILE_PATH_LITERAL("mpeg"),  //
+          FILE_PATH_LITERAL("mpg"),   //
+          FILE_PATH_LITERAL("mpv"),   //
+          FILE_PATH_LITERAL("ogg"),   //
+          FILE_PATH_LITERAL("ogv"),   //
+          FILE_PATH_LITERAL("png"),   //
+          FILE_PATH_LITERAL("qt"),    //
+          FILE_PATH_LITERAL("rar"),   //
+          FILE_PATH_LITERAL("taz"),   //
+          FILE_PATH_LITERAL("tb2"),   //
+          FILE_PATH_LITERAL("tbz"),   //
+          FILE_PATH_LITERAL("tbz2"),  //
+          FILE_PATH_LITERAL("tgz"),   //
+          FILE_PATH_LITERAL("tlz"),   //
+          FILE_PATH_LITERAL("tz"),    //
+          FILE_PATH_LITERAL("tz2"),   //
+          FILE_PATH_LITERAL("vob"),   //
+          FILE_PATH_LITERAL("webm"),  //
+          FILE_PATH_LITERAL("wma"),   //
+          FILE_PATH_LITERAL("wmv"),   //
+          FILE_PATH_LITERAL("xz"),    //
+          FILE_PATH_LITERAL("z"),     //
+          FILE_PATH_LITERAL("zip"),   //
+      });
 
   if (kExts.count(ext_without_dot)) {
     return kStored;
diff --git a/google/zip_reader.cc b/google/zip_reader.cc
index 34a815e..182a802 100644
--- a/google/zip_reader.cc
+++ b/google/zip_reader.cc
@@ -5,6 +5,7 @@
 #include "third_party/zlib/google/zip_reader.h"
 
 #include <algorithm>
+#include <string_view>
 #include <utility>
 
 #include "base/check.h"
@@ -15,7 +16,6 @@
 #include "base/logging.h"
 #include "base/numerics/safe_conversions.h"
 #include "base/strings/strcat.h"
-#include "base/strings/string_piece.h"
 #include "base/strings/string_util.h"
 #include "base/strings/utf_string_conversions.h"
 #include "base/task/sequenced_task_runner.h"
@@ -267,7 +267,7 @@ bool ZipReader::OpenEntry() {
   return true;
 }
 
-void ZipReader::Normalize(base::StringPiece16 in) {
+void ZipReader::Normalize(std::u16string_view in) {
   entry_.is_unsafe = true;
 
   // Directory entries in ZIP have a path ending with "/".
@@ -281,15 +281,16 @@ void ZipReader::Normalize(base::StringPiece16 in) {
 
   for (;;) {
     // Consume initial path separators.
-    const base::StringPiece16::size_type i = in.find_first_not_of(u'/');
-    if (i == base::StringPiece16::npos)
+    const std::u16string_view::size_type i = in.find_first_not_of(u'/');
+    if (i == std::u16string_view::npos) {
       break;
+    }
 
     in.remove_prefix(i);
     DCHECK(!in.empty());
 
     // Isolate next path component.
-    const base::StringPiece16 part = in.substr(0, in.find_first_of(u'/'));
+    const std::u16string_view part = in.substr(0, in.find_first_of(u'/'));
     DCHECK(!part.empty());
 
     in.remove_prefix(part.size());
diff --git a/google/zip_reader.h b/google/zip_reader.h
index b7680cc..0dbf50b 100644
--- a/google/zip_reader.h
+++ b/google/zip_reader.h
@@ -10,6 +10,7 @@
 #include <limits>
 #include <memory>
 #include <string>
+#include <string_view>
 
 #include "base/files/file.h"
 #include "base/files/file_path.h"
@@ -281,7 +282,7 @@ class ZipReader {
 
   // Normalizes the given path passed as UTF-16 string piece. Sets entry_.path,
   // entry_.is_directory and entry_.is_unsafe.
-  void Normalize(base::StringPiece16 in);
+  void Normalize(std::u16string_view in);
 
   // Runs the ListenerCallback at a throttled rate.
   void ReportProgress(ListenerCallback listener_callback, uint64_t bytes) const;
diff --git a/google/zip_reader_unittest.cc b/google/zip_reader_unittest.cc
index 9eb7d7d..46c0beb 100644
--- a/google/zip_reader_unittest.cc
+++ b/google/zip_reader_unittest.cc
@@ -9,7 +9,9 @@
 #include <string.h>
 
 #include <iterator>
+#include <optional>
 #include <string>
+#include <string_view>
 #include <vector>
 
 #include "base/check.h"
@@ -22,7 +24,6 @@
 #include "base/i18n/time_formatting.h"
 #include "base/path_service.h"
 #include "base/run_loop.h"
-#include "base/strings/string_piece.h"
 #include "base/strings/stringprintf.h"
 #include "base/strings/utf_string_conversions.h"
 #include "base/test/bind.h"
@@ -172,7 +173,7 @@ class ZipReaderTest : public PlatformTest {
   }
 
   static Paths GetPaths(const base::FilePath& zip_path,
-                        base::StringPiece encoding = {}) {
+                        std::string_view encoding = {}) {
     Paths paths;
 
     if (ZipReader reader; reader.Open(zip_path)) {
@@ -422,7 +423,7 @@ TEST_F(ZipReaderTest, EncryptedFile_WrongPassword) {
     EXPECT_EQ("This is not encrypted.\n", contents);
   }
 
-  for (const base::StringPiece path : {
+  for (const std::string_view path : {
            "Encrypted AES-128.txt",
            "Encrypted AES-192.txt",
            "Encrypted AES-256.txt",
@@ -458,7 +459,7 @@ TEST_F(ZipReaderTest, EncryptedFile_RightPassword) {
   }
 
   // TODO(crbug.com/1296838) Support AES encryption.
-  for (const base::StringPiece path : {
+  for (const std::string_view path : {
            "Encrypted AES-128.txt",
            "Encrypted AES-192.txt",
            "Encrypted AES-256.txt",
@@ -555,10 +556,10 @@ TEST_F(ZipReaderTest, ExtractToFileAsync_RegularFile) {
   const std::string md5 = base::MD5String(output);
   EXPECT_EQ(kQuuxExpectedMD5, md5);
 
-  int64_t file_size = 0;
-  ASSERT_TRUE(base::GetFileSize(target_file, &file_size));
+  std::optional<int64_t> file_size = base::GetFileSize(target_file);
+  ASSERT_TRUE(file_size.has_value());
 
-  EXPECT_EQ(file_size, listener.current_progress());
+  EXPECT_EQ(file_size.value(), listener.current_progress());
 }
 
 TEST_F(ZipReaderTest, ExtractToFileAsync_Encrypted_NoPassword) {
@@ -713,12 +714,12 @@ TEST_F(ZipReaderTest, ExtractCurrentEntryToString) {
     if (i > 0) {
       // Exact byte read limit: must pass.
       EXPECT_TRUE(reader.ExtractCurrentEntryToString(i, &contents));
-      EXPECT_EQ(std::string(base::StringPiece("0123456", i)), contents);
+      EXPECT_EQ(std::string(std::string_view("0123456", i)), contents);
     }
 
     // More than necessary byte read limit: must pass.
     EXPECT_TRUE(reader.ExtractCurrentEntryToString(&contents));
-    EXPECT_EQ(std::string(base::StringPiece("0123456", i)), contents);
+    EXPECT_EQ(std::string(std::string_view("0123456", i)), contents);
   }
   reader.Close();
 }
diff --git a/google/zip_unittest.cc b/google/zip_unittest.cc
index 922d383..2bcfa30 100644
--- a/google/zip_unittest.cc
+++ b/google/zip_unittest.cc
@@ -2,12 +2,15 @@
 // Use of this source code is governed by a BSD-style license that can be
 // found in the LICENSE file.
 
+#include "third_party/zlib/google/zip.h"
+
 #include <stddef.h>
 #include <stdint.h>
 
 #include <iomanip>
 #include <limits>
 #include <string>
+#include <string_view>
 #include <unordered_map>
 #include <unordered_set>
 #include <vector>
@@ -29,7 +32,6 @@
 #include "testing/gmock/include/gmock/gmock.h"
 #include "testing/gtest/include/gtest/gtest.h"
 #include "testing/platform_test.h"
-#include "third_party/zlib/google/zip.h"
 #include "third_party/zlib/google/zip_internal.h"
 #include "third_party/zlib/google/zip_reader.h"
 
@@ -61,8 +63,9 @@ bool CreateFile(const std::string& content,
   if (!base::CreateTemporaryFile(file_path))
     return false;
 
-  if (base::WriteFile(*file_path, content.data(), content.size()) == -1)
+  if (!base::WriteFile(*file_path, content)) {
     return false;
+  }
 
   *file = base::File(
       *file_path, base::File::Flags::FLAG_OPEN | base::File::Flags::FLAG_READ);
@@ -348,7 +351,7 @@ class ZipTest : public PlatformTest {
     base::Time now_time;
     EXPECT_TRUE(base::Time::FromUTCExploded(now_parts, &now_time));
 
-    EXPECT_EQ(1, base::WriteFile(src_file, "1", 1));
+    EXPECT_TRUE(base::WriteFile(src_file, "1"));
     EXPECT_TRUE(base::TouchFile(src_file, base::Time::Now(), test_mtime));
 
     EXPECT_TRUE(zip::Zip(src_dir, zip_file, true));
@@ -746,6 +749,8 @@ TEST_F(ZipTest, UnzipMixedPaths) {
       "Space→",  //
 #else
       " ",                        //
+      "...",                      // Disappears on Windows
+      "....",                     // Disappears on Windows
       "AUX",                      // Disappears on Windows
       "COM1",                     // Disappears on Windows
       "COM2",                     // Disappears on Windows
@@ -1111,9 +1116,9 @@ TEST_F(ZipTest, UnzipFilesWithIncorrectSize) {
     SCOPED_TRACE(base::StringPrintf("Processing %d.txt", i));
     base::FilePath file_path =
         temp_dir.AppendASCII(base::StringPrintf("%d.txt", i));
-    int64_t file_size = -1;
-    EXPECT_TRUE(base::GetFileSize(file_path, &file_size));
-    EXPECT_EQ(static_cast<int64_t>(i), file_size);
+    std::optional<int64_t> file_size = base::GetFileSize(file_path);
+    EXPECT_TRUE(file_size.has_value());
+    EXPECT_EQ(static_cast<int64_t>(i), file_size.value());
   }
 }
 
@@ -1290,7 +1295,7 @@ TEST_F(ZipTest, Compressed) {
   EXPECT_TRUE(base::CreateDirectory(src_dir));
 
   // Create some dummy source files.
-  for (const base::StringPiece s : {"foo", "bar.txt", ".hidden"}) {
+  for (const std::string_view s : {"foo", "bar.txt", ".hidden"}) {
     base::File f(src_dir.AppendASCII(s),
                  base::File::FLAG_CREATE | base::File::FLAG_WRITE);
     ASSERT_TRUE(f.SetLength(5000));
@@ -1304,10 +1309,10 @@ TEST_F(ZipTest, Compressed) {
 
   // Since the source files compress well, the destination ZIP file should be
   // smaller than the source files.
-  int64_t dest_file_size;
-  ASSERT_TRUE(base::GetFileSize(dest_file, &dest_file_size));
-  EXPECT_GT(dest_file_size, 300);
-  EXPECT_LT(dest_file_size, 1000);
+  std::optional<int64_t> dest_file_size = base::GetFileSize(dest_file);
+  ASSERT_TRUE(dest_file_size.has_value());
+  EXPECT_GT(dest_file_size.value(), 300);
+  EXPECT_LT(dest_file_size.value(), 1000);
 }
 
 // Tests that a ZIP put inside a ZIP is simply stored instead of being
@@ -1336,10 +1341,10 @@ TEST_F(ZipTest, NestedZip) {
   // Since the dummy source (inner) ZIP file should simply be stored in the
   // destination (outer) ZIP file, the destination file should be bigger than
   // the source file, but not much bigger.
-  int64_t dest_file_size;
-  ASSERT_TRUE(base::GetFileSize(dest_file, &dest_file_size));
-  EXPECT_GT(dest_file_size, src_size + 100);
-  EXPECT_LT(dest_file_size, src_size + 300);
+  std::optional<int64_t> dest_file_size = base::GetFileSize(dest_file);
+  ASSERT_TRUE(dest_file_size.has_value());
+  EXPECT_GT(dest_file_size.value(), src_size + 100);
+  EXPECT_LT(dest_file_size.value(), src_size + 300);
 }
 
 // Tests that there is no 2GB or 4GB limits. Tests that big files can be zipped
@@ -1400,10 +1405,10 @@ TEST_F(ZipTest, BigFile) {
   // Since the dummy source (inner) ZIP file should simply be stored in the
   // destination (outer) ZIP file, the destination file should be bigger than
   // the source file, but not much bigger.
-  int64_t dest_file_size;
-  ASSERT_TRUE(base::GetFileSize(dest_file, &dest_file_size));
-  EXPECT_GT(dest_file_size, src_size + 100);
-  EXPECT_LT(dest_file_size, src_size + 300);
+  std::optional<int64_t> dest_file_size = base::GetFileSize(dest_file);
+  ASSERT_TRUE(dest_file_size.has_value());
+  EXPECT_GT(dest_file_size.value(), src_size + 100);
+  EXPECT_LT(dest_file_size.value(), src_size + 300);
 
   LOG(INFO) << "Reading big ZIP " << dest_file;
   zip::ZipReader reader;
diff --git a/google/zip_writer.cc b/google/zip_writer.cc
index 31161ae..34ab0ad 100644
--- a/google/zip_writer.cc
+++ b/google/zip_writer.cc
@@ -5,6 +5,7 @@
 #include "third_party/zlib/google/zip_writer.h"
 
 #include <algorithm>
+#include <tuple>
 
 #include "base/files/file.h"
 #include "base/logging.h"
@@ -193,8 +194,8 @@ bool ZipWriter::AddMixedEntries(Paths paths) {
   while (!paths.empty()) {
     // Work with chunks of 50 paths at most.
     const size_t n = std::min<size_t>(paths.size(), 50);
-    const Paths relative_paths = paths.subspan(0, n);
-    paths = paths.subspan(n, paths.size() - n);
+    Paths relative_paths;
+    std::tie(relative_paths, paths) = paths.split_at(n);
 
     files.clear();
     if (!file_accessor_->Open(relative_paths, &files) || files.size() != n)
@@ -233,8 +234,8 @@ bool ZipWriter::AddFileEntries(Paths paths) {
   while (!paths.empty()) {
     // Work with chunks of 50 paths at most.
     const size_t n = std::min<size_t>(paths.size(), 50);
-    const Paths relative_paths = paths.subspan(0, n);
-    paths = paths.subspan(n, paths.size() - n);
+    Paths relative_paths;
+    std::tie(relative_paths, paths) = paths.split_at(n);
 
     DCHECK_EQ(relative_paths.size(), n);
 
diff --git a/gzguts.h b/gzguts.h
index f937504..eba7208 100644
--- a/gzguts.h
+++ b/gzguts.h
@@ -1,5 +1,5 @@
 /* gzguts.h -- zlib internal header definitions for gz* operations
- * Copyright (C) 2004-2019 Mark Adler
+ * Copyright (C) 2004-2024 Mark Adler
  * For conditions of distribution and use, see copyright notice in zlib.h
  */
 
@@ -210,9 +210,5 @@ char ZLIB_INTERNAL *gz_strwinerror(DWORD error);
 /* GT_OFF(x), where x is an unsigned value, is true if x > maximum z_off64_t
    value -- needed when comparing unsigned to z_off64_t, which is signed
    (possible z_off64_t types off_t, off64_t, and long are all signed) */
-#ifdef INT_MAX
-#  define GT_OFF(x) (sizeof(int) == sizeof(z_off64_t) && (x) > INT_MAX)
-#else
 unsigned ZLIB_INTERNAL gz_intmax(void);
-#  define GT_OFF(x) (sizeof(int) == sizeof(z_off64_t) && (x) > gz_intmax())
-#endif
+#define GT_OFF(x) (sizeof(int) == sizeof(z_off64_t) && (x) > gz_intmax())
diff --git a/gzlib.c b/gzlib.c
index 0d3ebf8..7136395 100644
--- a/gzlib.c
+++ b/gzlib.c
@@ -1,5 +1,5 @@
 /* gzlib.c -- zlib functions common to reading and writing gzip files
- * Copyright (C) 2004-2019 Mark Adler
+ * Copyright (C) 2004-2024 Mark Adler
  * For conditions of distribution and use, see copyright notice in zlib.h
  */
 
@@ -566,20 +566,20 @@ void ZLIB_INTERNAL gz_error(gz_statep state, int err, const char *msg) {
 #endif
 }
 
-#ifndef INT_MAX
 /* portably return maximum value for an int (when limits.h presumed not
    available) -- we need to do this to cover cases where 2's complement not
    used, since C standard permits 1's complement and sign-bit representations,
    otherwise we could just use ((unsigned)-1) >> 1 */
 unsigned ZLIB_INTERNAL gz_intmax(void) {
-    unsigned p, q;
-
-    p = 1;
+#ifdef INT_MAX
+    return INT_MAX;
+#else
+    unsigned p = 1, q;
     do {
         q = p;
         p <<= 1;
         p++;
     } while (p > q);
     return q >> 1;
-}
 #endif
+}
diff --git a/inftrees.c b/inftrees.c
index 73d5a77..98cfe16 100644
--- a/inftrees.c
+++ b/inftrees.c
@@ -1,5 +1,5 @@
 /* inftrees.c -- generate Huffman trees for efficient decoding
- * Copyright (C) 1995-2023 Mark Adler
+ * Copyright (C) 1995-2024 Mark Adler
  * For conditions of distribution and use, see copyright notice in zlib.h
  */
 
@@ -9,7 +9,7 @@
 #define MAXBITS 15
 
 const char inflate_copyright[] =
-   " inflate 1.3.0.1 Copyright 1995-2023 Mark Adler ";
+   " inflate 1.3.1 Copyright 1995-2024 Mark Adler ";
 /*
   If you use the zlib library in a product, an acknowledgment is welcome
   in the documentation of your product. If for some reason you cannot
@@ -57,7 +57,7 @@ int ZLIB_INTERNAL inflate_table(codetype type, unsigned short FAR *lens,
         35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258, 0, 0};
     static const unsigned short lext[31] = { /* Length codes 257..285 extra */
         16, 16, 16, 16, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18,
-        19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 16, 70, 200};
+        19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 16, 203, 77};
     static const unsigned short dbase[32] = { /* Distance codes 0..29 base */
         1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
         257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
diff --git a/inftrees.h b/inftrees.h
index f11f29c..6e7f0fa 100644
--- a/inftrees.h
+++ b/inftrees.h
@@ -41,7 +41,7 @@ typedef struct {
    examples/enough.c found in the zlib distribution.  The arguments to that
    program are the number of symbols, the initial root table size, and the
    maximum bit length of a code.  "enough 286 10 15" for literal/length codes
-   returns returns 1332, and "enough 30 9 15" for distance codes returns 592.
+   returns 1332, and "enough 30 9 15" for distance codes returns 592.
    The initial root table size (10 or 9) is found in the fifth argument of the
    inflate_table() calls in inflate.c and infback.c.  If the root table size is
    changed, then these maximum sizes would be need to be recalculated and
diff --git a/libz.map.txt b/libz.map.txt
index 850bbf8..dd41797 100644
--- a/libz.map.txt
+++ b/libz.map.txt
@@ -79,7 +79,7 @@ ZLIB_1.2.5.2 {
     inflateResetKeep;
 } ZLIB_1.2.5.1;
 
-ZLIB_1.2.7.1 { # introduced=19
+ZLIB_1.2.7.1 {
     inflateGetDictionary;
     gzvprintf;
 } ZLIB_1.2.5.2;
@@ -102,7 +102,7 @@ ZLIB_NDK {
     _dist_code;
     _length_code;
     _tr_align;
-    _tr_flush_bits; # introduced=21
+    _tr_flush_bits;
     _tr_flush_block;
     _tr_init;
     _tr_stored_block;
diff --git a/patches/0008-minizip-zip-unzip-tools.patch b/patches/0008-minizip-zip-unzip-tools.patch
index 273a8c9..a359e0f 100644
--- a/patches/0008-minizip-zip-unzip-tools.patch
+++ b/patches/0008-minizip-zip-unzip-tools.patch
@@ -9,7 +9,7 @@ Subject: [PATCH] Build minizip zip and unzip tools
  2 files changed, 9 insertions(+), 11 deletions(-)
 
 diff --git a/third_party/zlib/contrib/minizip/miniunz.c b/third_party/zlib/contrib/minizip/miniunz.c
-index 8ada038dbd4e7..5b4312e5647cd 100644
+index 616c30325e07c..f4ad16bdd377b 100644
 --- a/third_party/zlib/contrib/minizip/miniunz.c
 +++ b/third_party/zlib/contrib/minizip/miniunz.c
 @@ -12,7 +12,7 @@
@@ -30,31 +30,26 @@ index 8ada038dbd4e7..5b4312e5647cd 100644
  // In darwin and perhaps other BSD variants off_t is a 64 bit value, hence no need for specific 64 bit functions
  #define FOPEN_FUNC(filename, mode) fopen(filename, mode)
  #define FTELLO_FUNC(stream) ftello(stream)
-@@ -94,7 +94,7 @@ static void change_file_date(const char *filename, uLong dosdate, tm_unz tmu_dat
+@@ -97,7 +97,7 @@ static void change_file_date(const char *filename, uLong dosdate, tm_unz tmu_dat
+   LocalFileTimeToFileTime(&ftLocal,&ftm);
    SetFileTime(hFile,&ftm,&ftLastAcc,&ftm);
    CloseHandle(hFile);
- #else
--#if defined(unix) || defined(__APPLE__)
-+#if defined(unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
+-#elif defined(__unix__) || defined(__unix) || defined(__APPLE__)
++#elif defined(__unix__) || defined(__unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
    (void)dosdate;
    struct utimbuf ut;
    struct tm newdate;
-@@ -125,11 +125,9 @@ static void change_file_date(const char *filename, uLong dosdate, tm_unz tmu_dat
- 
- static int mymkdir(const char* dirname) {
+@@ -129,7 +129,7 @@ static int mymkdir(const char* dirname) {
      int ret=0;
--#ifdef _WIN32
-+#if defined(_WIN32)
+ #ifdef _WIN32
      ret = _mkdir(dirname);
--#elif unix
--    ret = mkdir (dirname,0775);
--#elif __APPLE__
-+#elif defined(unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
+-#elif defined(__unix__) || defined(__unix) || defined(__APPLE__)
++#elif defined(__unix__) || defined(__unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
      ret = mkdir (dirname,0775);
  #else
      (void)dirname;
 diff --git a/third_party/zlib/contrib/minizip/minizip.c b/third_party/zlib/contrib/minizip/minizip.c
-index 26ee8d029efe6..9eb3956a55e00 100644
+index a44e36a01869d..53fdd363e6222 100644
 --- a/third_party/zlib/contrib/minizip/minizip.c
 +++ b/third_party/zlib/contrib/minizip/minizip.c
 @@ -12,8 +12,7 @@
@@ -76,14 +71,12 @@ index 26ee8d029efe6..9eb3956a55e00 100644
  // In darwin and perhaps other BSD variants off_t is a 64 bit value, hence no need for specific 64 bit functions
  #define FOPEN_FUNC(filename, mode) fopen(filename, mode)
  #define FTELLO_FUNC(stream) ftello(stream)
-@@ -92,7 +91,7 @@ static int filetime(const char *f, tm_zip *tmzip, uLong *dt) {
+@@ -96,7 +95,7 @@ static int filetime(const char *f, tm_zip *tmzip, uLong *dt) {
+   }
    return ret;
  }
- #else
--#if defined(unix) || defined(__APPLE__)
-+#if defined(unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
+-#elif defined(__unix__) || defined(__unix) || defined(__APPLE__)
++#elif defined(__unix__) || defined(__unix) || defined(__APPLE__) || defined(__Fuchsia__) || defined(__ANDROID_API__)
  /* f: name of file to get info on, tmzip: return value: access,
     modification and creation times, dt: dostime */
  static int filetime(const char *f, tm_zip *tmzip, uLong *dt) {
---
-2.31.1.818.g46aad6cb9e-goog
diff --git a/patches/0015-minizip-unzip-enable-decryption.patch b/patches/0015-minizip-unzip-enable-decryption.patch
index 966e83c..feeeb1c 100644
--- a/patches/0015-minizip-unzip-enable-decryption.patch
+++ b/patches/0015-minizip-unzip-enable-decryption.patch
@@ -18,17 +18,6 @@ diff --git a/third_party/zlib/contrib/minizip/unzip.c b/third_party/zlib/contrib
 index 82275d6c1775d..c8a01b23efd42 100644
 --- a/third_party/zlib/contrib/minizip/unzip.c
 +++ b/third_party/zlib/contrib/minizip/unzip.c
-@@ -68,10 +68,6 @@
- #include <stdlib.h>
- #include <string.h>
- 
--#ifndef NOUNCRYPT
--        #define NOUNCRYPT
--#endif
--
- #include "zlib.h"
- #include "unzip.h"
- 
 @@ -1502,6 +1498,7 @@ extern int ZEXPORT unzOpenCurrentFile3(unzFile file, int* method,
              zdecode(s->keys,s->pcrc_32_tab,source[i]);
  
diff --git a/patches/0017-deflate-move-zmemzero-after-null-check.patch b/patches/0017-deflate-move-zmemzero-after-null-check.patch
new file mode 100644
index 0000000..ac8ade5
--- /dev/null
+++ b/patches/0017-deflate-move-zmemzero-after-null-check.patch
@@ -0,0 +1,49 @@
+From 93f86001b67609106c658fe0908a9b7931245b8a Mon Sep 17 00:00:00 2001
+From: pedro martelletto <martelletto@google.com>
+Date: Thu, 3 Apr 2025 16:46:42 +0000
+Subject: [PATCH] [zlib] Deflate: move zmemzero after NULL check
+
+ZALLOC() might fail, in which case dereferencing the returned pointer
+results in undefined behaviour. N.B. These conditions are not reachable
+from Chromium, as Chromium will abort rather than return nullptr from
+malloc. Found by libfido2's fuzz harness.
+---
+ third_party/zlib/deflate.c | 14 +++++++-------
+ 1 file changed, 7 insertions(+), 7 deletions(-)
+
+diff --git a/third_party/zlib/deflate.c b/third_party/zlib/deflate.c
+index 8a5281c2b6cd8..49496bb3b0561 100644
+--- a/third_party/zlib/deflate.c
++++ b/third_party/zlib/deflate.c
+@@ -485,14 +485,7 @@ int ZEXPORT deflateInit2_(z_streamp strm, int level, int method,
+     s->window = (Bytef *) ZALLOC(strm,
+                                  s->w_size + WINDOW_PADDING,
+                                  2*sizeof(Byte));
+-    /* Avoid use of unitialized values in the window, see crbug.com/1137613 and
+-     * crbug.com/1144420 */
+-    zmemzero(s->window, (s->w_size + WINDOW_PADDING) * (2 * sizeof(Byte)));
+     s->prev   = (Posf *)  ZALLOC(strm, s->w_size, sizeof(Pos));
+-    /* Avoid use of uninitialized value, see:
+-     * https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=11360
+-     */
+-    zmemzero(s->prev, s->w_size * sizeof(Pos));
+     s->head   = (Posf *)  ZALLOC(strm, s->hash_size, sizeof(Pos));
+ 
+     s->high_water = 0;      /* nothing written to s->window yet */
+@@ -551,6 +544,13 @@ int ZEXPORT deflateInit2_(z_streamp strm, int level, int method,
+         deflateEnd (strm);
+         return Z_MEM_ERROR;
+     }
++    /* Avoid use of unitialized values in the window, see crbug.com/1137613 and
++     * crbug.com/1144420 */
++    zmemzero(s->window, (s->w_size + WINDOW_PADDING) * (2 * sizeof(Byte)));
++    /* Avoid use of uninitialized value, see:
++     * https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=11360
++     */
++    zmemzero(s->prev, s->w_size * sizeof(Pos));
+ #ifdef LIT_MEM
+     s->d_buf = (ushf *)(s->pending_buf + (s->lit_bufsize << 1));
+     s->l_buf = s->pending_buf + (s->lit_bufsize << 2);
+-- 
+2.49.0.504.g3bcea36a83-goog
+
diff --git a/test/minigzip.c b/test/minigzip.c
index c72356d..134e10e 100644
--- a/test/minigzip.c
+++ b/test/minigzip.c
@@ -303,7 +303,7 @@ static void error(const char *msg) {
 #ifdef USE_MMAP /* MMAP version, Miguel Albrecht <malbrech@eso.org> */
 
 /* Try compressing the input file at once using mmap. Return Z_OK if
- * if success, Z_ERRNO otherwise.
+ * success, Z_ERRNO otherwise.
  */
 static int gz_compress_mmap(FILE *in, gzFile out) {
     int len;
diff --git a/trees.c b/trees.c
index 3813527..62286af 100644
--- a/trees.c
+++ b/trees.c
@@ -1,5 +1,5 @@
 /* trees.c -- output deflated data using Huffman coding
- * Copyright (C) 1995-2021 Jean-loup Gailly
+ * Copyright (C) 1995-2024 Jean-loup Gailly
  * detect_data_type() function provided freely by Cosmin Truta, 2006
  * For conditions of distribution and use, see copyright notice in zlib.h
  */
diff --git a/zconf.h b/zconf.h
index 3df78ad..7f61ba2 100644
--- a/zconf.h
+++ b/zconf.h
@@ -1,5 +1,5 @@
 /* zconf.h -- configuration of the zlib compression library
- * Copyright (C) 1995-2016 Jean-loup Gailly, Mark Adler
+ * Copyright (C) 1995-2024 Jean-loup Gailly, Mark Adler
  * For conditions of distribution and use, see copyright notice in zlib.h
  */
 
@@ -316,14 +316,6 @@
 #  endif
 #endif
 
-#ifndef Z_ARG /* function prototypes for stdarg */
-#  if defined(STDC) || defined(Z_HAVE_STDARG_H)
-#    define Z_ARG(args)  args
-#  else
-#    define Z_ARG(args)  ()
-#  endif
-#endif
-
 /* The following definitions for FAR are needed only for MSDOS mixed
  * model programming (small or medium model with some far allocations).
  * This was tested only with MSC; for other MSDOS compilers you may have
diff --git a/zconf.h.cmakein b/zconf.h.cmakein
index 310c439..0abe3bc 100644
--- a/zconf.h.cmakein
+++ b/zconf.h.cmakein
@@ -1,5 +1,5 @@
 /* zconf.h -- configuration of the zlib compression library
- * Copyright (C) 1995-2016 Jean-loup Gailly, Mark Adler
+ * Copyright (C) 1995-2024 Jean-loup Gailly, Mark Adler
  * For conditions of distribution and use, see copyright notice in zlib.h
  */
 
@@ -302,14 +302,6 @@
 #  endif
 #endif
 
-#ifndef Z_ARG /* function prototypes for stdarg */
-#  if defined(STDC) || defined(Z_HAVE_STDARG_H)
-#    define Z_ARG(args)  args
-#  else
-#    define Z_ARG(args)  ()
-#  endif
-#endif
-
 /* The following definitions for FAR are needed only for MSDOS mixed
  * model programming (small or medium model with some far allocations).
  * This was tested only with MSC; for other MSDOS compilers you may have
diff --git a/zconf.h.in b/zconf.h.in
index fb76ffe..62adc8d 100644
--- a/zconf.h.in
+++ b/zconf.h.in
@@ -1,5 +1,5 @@
 /* zconf.h -- configuration of the zlib compression library
- * Copyright (C) 1995-2016 Jean-loup Gailly, Mark Adler
+ * Copyright (C) 1995-2024 Jean-loup Gailly, Mark Adler
  * For conditions of distribution and use, see copyright notice in zlib.h
  */
 
@@ -300,14 +300,6 @@
 #  endif
 #endif
 
-#ifndef Z_ARG /* function prototypes for stdarg */
-#  if defined(STDC) || defined(Z_HAVE_STDARG_H)
-#    define Z_ARG(args)  args
-#  else
-#    define Z_ARG(args)  ()
-#  endif
-#endif
-
 /* The following definitions for FAR are needed only for MSDOS mixed
  * model programming (small or medium model with some far allocations).
  * This was tested only with MSC; for other MSDOS compilers you may have
diff --git a/zlib.3 b/zlib.3
index adc5b7f..c716020 100644
--- a/zlib.3
+++ b/zlib.3
@@ -1,4 +1,4 @@
-.TH ZLIB 3 "xx Aug 2023"
+.TH ZLIB 3 "22 Jan 2024"
 .SH NAME
 zlib \- compression/decompression library
 .SH SYNOPSIS
@@ -105,9 +105,9 @@ before asking for help.
 Send questions and/or comments to zlib@gzip.org,
 or (for the Windows DLL version) to Gilles Vollant (info@winimage.com).
 .SH AUTHORS AND LICENSE
-Version 1.2.3.0.1
+Version 1.3.1
 .LP
-Copyright (C) 1995-2022 Jean-loup Gailly and Mark Adler
+Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
 .LP
 This software is provided 'as-is', without any express or implied
 warranty.  In no event will the authors be held liable for any damages
diff --git a/zlib.h b/zlib.h
index 7f7c26c..6da4cc1 100644
--- a/zlib.h
+++ b/zlib.h
@@ -1,7 +1,7 @@
 /* zlib.h -- interface of the 'zlib' general purpose compression library
-  version 1.3.0.1, August xxth, 2023
+  version 1.3.1, January 22nd, 2024
 
-  Copyright (C) 1995-2023 Jean-loup Gailly and Mark Adler
+  Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler
 
   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
@@ -37,12 +37,12 @@
 extern "C" {
 #endif
 
-#define ZLIB_VERSION "1.3.0.1-motley"
-#define ZLIB_VERNUM 0x1301
+#define ZLIB_VERSION "1.3.1"
+#define ZLIB_VERNUM 0x1310
 #define ZLIB_VER_MAJOR 1
 #define ZLIB_VER_MINOR 3
-#define ZLIB_VER_REVISION 0
-#define ZLIB_VER_SUBREVISION 1
+#define ZLIB_VER_REVISION 1
+#define ZLIB_VER_SUBREVISION 0
 
 /*
  * In Android's NDK we have one zlib.h for all the versions.
@@ -982,10 +982,10 @@ ZEXTERN int ZEXPORT inflateSync(z_streamp strm);
      inflateSync returns Z_OK if a possible full flush point has been found,
    Z_BUF_ERROR if no more input was provided, Z_DATA_ERROR if no flush point
    has been found, or Z_STREAM_ERROR if the stream structure was inconsistent.
-   In the success case, the application may save the current current value of
-   total_in which indicates where valid compressed data was found.  In the
-   error case, the application may repeatedly call inflateSync, providing more
-   input each time, until success or end of the input data.
+   In the success case, the application may save the current value of total_in
+   which indicates where valid compressed data was found.  In the error case,
+   the application may repeatedly call inflateSync, providing more input each
+   time, until success or end of the input data.
 */
 
 ZEXTERN int ZEXPORT inflateCopy(z_streamp dest,
@@ -1814,14 +1814,14 @@ ZEXTERN uLong ZEXPORT crc32_combine(uLong crc1, uLong crc2, z_off_t len2);
    seq1 and seq2 with lengths len1 and len2, CRC-32 check values were
    calculated for each, crc1 and crc2.  crc32_combine() returns the CRC-32
    check value of seq1 and seq2 concatenated, requiring only crc1, crc2, and
-   len2.
+   len2. len2 must be non-negative.
 */
 
 /*
 ZEXTERN uLong ZEXPORT crc32_combine_gen(z_off_t len2);
 
      Return the operator corresponding to length len2, to be used with
-   crc32_combine_op().
+   crc32_combine_op(). len2 must be non-negative.
 */
 
 ZEXTERN uLong ZEXPORT crc32_combine_op(uLong crc1, uLong crc2, uLong op);
diff --git a/zlib.map b/zlib.map
index b330b60..31544f2 100644
--- a/zlib.map
+++ b/zlib.map
@@ -1,100 +1,100 @@
-ZLIB_1.2.0 {
-  global:
-    compressBound;
-    deflateBound;
-    inflateBack;
-    inflateBackEnd;
-    inflateBackInit_;
-    inflateCopy;
-  local:
-    deflate_copyright;
-    inflate_copyright;
-    inflate_fast;
-    inflate_table;
-    zcalloc;
-    zcfree;
-    z_errmsg;
-    gz_error;
-    gz_intmax;
-    _*;
-};
-
-ZLIB_1.2.0.2 {
-    gzclearerr;
-    gzungetc;
-    zlibCompileFlags;
-} ZLIB_1.2.0;
-
-ZLIB_1.2.0.8 {
-    deflatePrime;
-} ZLIB_1.2.0.2;
-
-ZLIB_1.2.2 {
-    adler32_combine;
-    crc32_combine;
-    deflateSetHeader;
-    inflateGetHeader;
-} ZLIB_1.2.0.8;
-
-ZLIB_1.2.2.3 {
-    deflateTune;
-    gzdirect;
-} ZLIB_1.2.2;
-
-ZLIB_1.2.2.4 {
-    inflatePrime;
-} ZLIB_1.2.2.3;
-
-ZLIB_1.2.3.3 {
-    adler32_combine64;
-    crc32_combine64;
-    gzopen64;
-    gzseek64;
-    gztell64;
-    inflateUndermine;
-} ZLIB_1.2.2.4;
-
-ZLIB_1.2.3.4 {
-    inflateReset2;
-    inflateMark;
-} ZLIB_1.2.3.3;
-
-ZLIB_1.2.3.5 {
-    gzbuffer;
-    gzoffset;
-    gzoffset64;
-    gzclose_r;
-    gzclose_w;
-} ZLIB_1.2.3.4;
-
-ZLIB_1.2.5.1 {
-    deflatePending;
-} ZLIB_1.2.3.5;
-
-ZLIB_1.2.5.2 {
-    deflateResetKeep;
-    gzgetc_;
-    inflateResetKeep;
-} ZLIB_1.2.5.1;
-
-ZLIB_1.2.7.1 {
-    inflateGetDictionary;
-    gzvprintf;
-} ZLIB_1.2.5.2;
-
-ZLIB_1.2.9 {
-    inflateCodesUsed;
-    inflateValidate;
-    uncompress2;
-    gzfread;
-    gzfwrite;
-    deflateGetDictionary;
-    adler32_z;
-    crc32_z;
-} ZLIB_1.2.7.1;
-
-ZLIB_1.2.12 {
-	crc32_combine_gen;
-	crc32_combine_gen64;
-	crc32_combine_op;
-} ZLIB_1.2.9;
+ZLIB_1.2.0 {
+  global:
+    compressBound;
+    deflateBound;
+    inflateBack;
+    inflateBackEnd;
+    inflateBackInit_;
+    inflateCopy;
+  local:
+    deflate_copyright;
+    inflate_copyright;
+    inflate_fast;
+    inflate_table;
+    zcalloc;
+    zcfree;
+    z_errmsg;
+    gz_error;
+    gz_intmax;
+    _*;
+};
+
+ZLIB_1.2.0.2 {
+    gzclearerr;
+    gzungetc;
+    zlibCompileFlags;
+} ZLIB_1.2.0;
+
+ZLIB_1.2.0.8 {
+    deflatePrime;
+} ZLIB_1.2.0.2;
+
+ZLIB_1.2.2 {
+    adler32_combine;
+    crc32_combine;
+    deflateSetHeader;
+    inflateGetHeader;
+} ZLIB_1.2.0.8;
+
+ZLIB_1.2.2.3 {
+    deflateTune;
+    gzdirect;
+} ZLIB_1.2.2;
+
+ZLIB_1.2.2.4 {
+    inflatePrime;
+} ZLIB_1.2.2.3;
+
+ZLIB_1.2.3.3 {
+    adler32_combine64;
+    crc32_combine64;
+    gzopen64;
+    gzseek64;
+    gztell64;
+    inflateUndermine;
+} ZLIB_1.2.2.4;
+
+ZLIB_1.2.3.4 {
+    inflateReset2;
+    inflateMark;
+} ZLIB_1.2.3.3;
+
+ZLIB_1.2.3.5 {
+    gzbuffer;
+    gzoffset;
+    gzoffset64;
+    gzclose_r;
+    gzclose_w;
+} ZLIB_1.2.3.4;
+
+ZLIB_1.2.5.1 {
+    deflatePending;
+} ZLIB_1.2.3.5;
+
+ZLIB_1.2.5.2 {
+    deflateResetKeep;
+    gzgetc_;
+    inflateResetKeep;
+} ZLIB_1.2.5.1;
+
+ZLIB_1.2.7.1 {
+    inflateGetDictionary;
+    gzvprintf;
+} ZLIB_1.2.5.2;
+
+ZLIB_1.2.9 {
+    inflateCodesUsed;
+    inflateValidate;
+    uncompress2;
+    gzfread;
+    gzfwrite;
+    deflateGetDictionary;
+    adler32_z;
+    crc32_z;
+} ZLIB_1.2.7.1;
+
+ZLIB_1.2.12 {
+	crc32_combine_gen;
+	crc32_combine_gen64;
+	crc32_combine_op;
+} ZLIB_1.2.9;
diff --git a/zutil.h b/zutil.h
index 2e2f576..045a35a 100644
--- a/zutil.h
+++ b/zutil.h
@@ -1,5 +1,5 @@
 /* zutil.h -- internal interface and configuration of the compression library
- * Copyright (C) 1995-2022 Jean-loup Gailly, Mark Adler
+ * Copyright (C) 1995-2024 Jean-loup Gailly, Mark Adler
  * For conditions of distribution and use, see copyright notice in zlib.h
  */
 
@@ -71,7 +71,7 @@ typedef unsigned long  ulg;
 extern z_const char * const z_errmsg[10]; /* indexed by 2-zlib_error */
 /* (size given to avoid silly warnings with Visual C++) */
 
-#define ERR_MSG(err) z_errmsg[Z_NEED_DICT-(err)]
+#define ERR_MSG(err) z_errmsg[(err) < -6 || (err) > 2 ? 9 : 2 - (err)]
 
 #define ERR_RETURN(strm,err) \
   return (strm->msg = ERR_MSG(err), (err))
```

