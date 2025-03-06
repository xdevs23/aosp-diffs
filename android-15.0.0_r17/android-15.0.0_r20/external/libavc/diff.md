```diff
diff --git a/.vscode/c_cpp_properties.json b/.vscode/c_cpp_properties.json
new file mode 100644
index 0000000..9e7a00e
--- /dev/null
+++ b/.vscode/c_cpp_properties.json
@@ -0,0 +1,18 @@
+{
+    "configurations": [
+        {
+            "name": "Native",
+            "includePath": [
+                "${workspaceFolder}/**",
+                "${workspaceFolder}/common",
+                "${workspaceFolder}/decoder",
+                "${workspaceFolder}/encoder"
+            ],
+            "defines": [],
+            "cStandard": "c17",
+            "cppStandard": "c++17",
+            "configurationProvider": "ms-vscode.cmake-tools"
+        }
+    ],
+    "version": 4
+}
\ No newline at end of file
diff --git a/.vscode/launch.json b/.vscode/launch.json
new file mode 100644
index 0000000..14da830
--- /dev/null
+++ b/.vscode/launch.json
@@ -0,0 +1,81 @@
+{
+    "version": "0.2.0",
+    "configurations": [
+        {
+            "name": "Run avcenc - Linux",
+            "type": "cppdbg",
+            "request": "launch",
+            "program": "${workspaceFolder}/build/avcenc",
+            "args": ["../examples/avcenc/enc.cfg"],
+            "stopAtEntry": false,
+            "cwd": "${workspaceFolder}/build",
+            "environment": [],
+            "externalConsole": false,
+            "MIMode": "gdb",
+            "setupCommands": [
+                {
+                    "description": "Enable pretty-printing for gdb",
+                    "text": "-enable-pretty-printing",
+                    "ignoreFailures": true
+                }
+            ]
+        },
+        {
+            "name": "Run avcenc - Mac",
+            "type": "cppdbg",
+            "request": "launch",
+            "program": "${workspaceFolder}/build/avcenc",
+            "args": ["../examples/avcenc/enc.cfg"],
+            "stopAtEntry": false,
+            "cwd": "${workspaceFolder}/build",
+            "environment": [],
+            "externalConsole": false,
+            "MIMode": "lldb",
+            "setupCommands": [
+                {
+                    "description": "Enable pretty-printing for lldb",
+                    "text": "-enable-pretty-printing",
+                    "ignoreFailures": true
+                }
+            ]
+        },
+        {
+            "name": "Run avcdec - Linux",
+            "type": "cppdbg",
+            "request": "launch",
+            "program": "${workspaceFolder}/build/avcdec",
+            "args": ["../examples/avcdec/dec.cfg"],
+            "stopAtEntry": false,
+            "cwd": "${workspaceFolder}/build",
+            "environment": [],
+            "externalConsole": false,
+            "MIMode": "gdb",
+            "setupCommands": [
+                {
+                    "description": "Enable pretty-printing for gdb",
+                    "text": "-enable-pretty-printing",
+                    "ignoreFailures": true
+                }
+            ]
+        },
+        {
+            "name": "Run avcdec - Mac",
+            "type": "cppdbg",
+            "request": "launch",
+            "program": "${workspaceFolder}/build/avcdec",
+            "args": ["../examples/avcdec/dec.cfg"],
+            "stopAtEntry": false,
+            "cwd": "${workspaceFolder}/build",
+            "environment": [],
+            "externalConsole": false,
+            "MIMode": "lldb",
+            "setupCommands": [
+                {
+                    "description": "Enable pretty-printing for lldb",
+                    "text": "-enable-pretty-printing",
+                    "ignoreFailures": true
+                }
+            ]
+        }
+    ]
+}
\ No newline at end of file
diff --git a/.vscode/settings.json b/.vscode/settings.json
new file mode 100644
index 0000000..3c4aeea
--- /dev/null
+++ b/.vscode/settings.json
@@ -0,0 +1,19 @@
+{
+    "cmake.buildDirectory": "${workspaceFolder}/build",
+    "cmake.sourceDirectory": "${workspaceFolder}",
+    "cmake.configureArgs": [
+        "-DENABLE_MVC=OFF",
+        "-DENABLE_SVC=OFF",
+        "-DENABLE_TESTS=OFF",
+        "-DCMAKE_C_COMPILER=clang",
+        "-DCMAKE_CXX_COMPILER=clang++"
+    ],
+    "cmake.preferredGenerators": [
+        "Unix Makefiles"
+    ],
+    "cmake.debugConfig": {
+        "avcenc": "avcenc",
+        "avcdec": "avcdec"
+    },
+    "C_Cpp.default.configurationProvider": "ms-vscode.cmake-tools"
+}
\ No newline at end of file
diff --git a/.vscode/tasks.json b/.vscode/tasks.json
new file mode 100644
index 0000000..646fbf8
--- /dev/null
+++ b/.vscode/tasks.json
@@ -0,0 +1,29 @@
+{
+    "version": "2.0.0",
+    "tasks": [
+        {
+            "type": "cmake",
+            "label": "Configure",
+            "command": "configure",
+            "problemMatcher": [
+                "$gcc"
+            ],
+            "group": "build"
+        },
+        {
+            "type": "cmake",
+            "label": "Build",
+            "command": "build",
+            "problemMatcher": [
+                "$gcc"
+            ],
+            "group": {
+                "kind": "build",
+                "isDefault": true
+            },
+            "dependsOn": [
+                "Configure"
+            ]
+        }
+    ]
+}
\ No newline at end of file
diff --git a/CMakeLists.txt b/CMakeLists.txt
index d0c37d3..a32ae8c 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -1,6 +1,17 @@
 cmake_minimum_required(VERSION 3.9.1)
 project(libavc C CXX)
-enable_language(ASM)
+
+if(NOT DEFINED SYSTEM_NAME)
+  set(SYSTEM_NAME ${CMAKE_HOST_SYSTEM_NAME})
+endif()
+
+if(NOT DEFINED SYSTEM_PROCESSOR)
+  set(SYSTEM_PROCESSOR ${CMAKE_HOST_SYSTEM_PROCESSOR})
+endif()
+
+if(NOT "${SYSTEM_NAME}" STREQUAL "Darwin")
+  enable_language(ASM)
+endif()
 
 set(AVC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
 set(AVC_CONFIG_DIR "${CMAKE_CURRENT_BINARY_DIR}")
@@ -19,6 +30,16 @@ if("${AVC_ROOT}" STREQUAL "${AVC_CONFIG_DIR}")
       "And re-run CMake from the build directory.")
 endif()
 
+if("${SYSTEM_NAME}" STREQUAL "Android")
+    find_library(log-lib log QUIET)
+    if(NOT log-lib)
+      message(FATAL_ERROR "Could NOT find log library, retry after installing \
+                           log library at sysroot.")
+    else()
+      message(STATUS "Found log-lib: ${log-lib}")
+    endif()
+endif()
+
 set(THREADS_PREFER_PTHREAD_FLAG TRUE)
 find_package(Threads REQUIRED)
 
diff --git a/METADATA b/METADATA
index cd2d855..d7e98bc 100644
--- a/METADATA
+++ b/METADATA
@@ -8,12 +8,12 @@ third_party {
   license_type: NOTICE
   last_upgrade_date {
     year: 2024
-    month: 8
-    day: 19
+    month: 10
+    day: 30
   }
   identifier {
     type: "Git"
     value: "https://github.com/ittiam-systems/libavc.git"
-    version: "v1.5.0"
+    version: "v1.6.0"
   }
 }
diff --git a/README.md b/README.md
index 5b0663a..84665b8 100644
--- a/README.md
+++ b/README.md
@@ -51,3 +51,29 @@ $ make
 $ cmake .. -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/aarch32_toolchain.cmake
 $ make
 ```
+
+### Building for android
+NOTE: This assumes that you are building on a machine that has
+ [Android NDK](https://developer.android.com/ndk/downloads).
+
+```
+$ cd external/libavc
+$ mkdir build
+$ cd build
+```
+
+#### Armv7 (32-bit)
+
+    cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/android_toolchain.cmake\
+        -DAVC_ANDROID_NDK_PATH=/opt/android-ndk-r26d/\
+        -DANDROID_ABI=armeabi-v7a\
+        -DANDROID_PLATFORM=android-23 ../
+    make
+
+#### Armv8 (64-bit)
+
+    cmake -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/android_toolchain.cmake\
+        -DAVC_ANDROID_NDK_PATH=/opt/android-ndk-r26d/\
+        -DANDROID_ABI=arm64-v8a\
+        -DANDROID_PLATFORM=android-23 ../
+    make
\ No newline at end of file
diff --git a/cmake/toolchains/aarch32_toolchain.cmake b/cmake/toolchains/aarch32_toolchain.cmake
index 5fabde2..a556223 100644
--- a/cmake/toolchains/aarch32_toolchain.cmake
+++ b/cmake/toolchains/aarch32_toolchain.cmake
@@ -1,5 +1,5 @@
-set(CMAKE_SYSTEM_NAME Linux)
-set(CMAKE_SYSTEM_PROCESSOR aarch32)
+set(SYSTEM_NAME Linux)
+set(SYSTEM_PROCESSOR aarch32)
 
 # Modify these variables with paths to appropriate compilers that can produce
 # armv7 targets
diff --git a/cmake/toolchains/aarch64_toolchain.cmake b/cmake/toolchains/aarch64_toolchain.cmake
index 5efbf77..b5dab9d 100644
--- a/cmake/toolchains/aarch64_toolchain.cmake
+++ b/cmake/toolchains/aarch64_toolchain.cmake
@@ -1,5 +1,5 @@
-set(CMAKE_SYSTEM_NAME Linux)
-set(CMAKE_SYSTEM_PROCESSOR aarch64)
+set(SYSTEM_NAME Linux)
+set(SYSTEM_PROCESSOR aarch64)
 
 # Modify these variables with paths to appropriate compilers that can produce
 # armv8 targets
diff --git a/cmake/toolchains/android_toolchain.cmake b/cmake/toolchains/android_toolchain.cmake
new file mode 100644
index 0000000..f725a04
--- /dev/null
+++ b/cmake/toolchains/android_toolchain.cmake
@@ -0,0 +1,34 @@
+set(SYSTEM_NAME Android)
+set(CMAKE_SYSTEM_NAME Android)
+
+if(NOT ANDROID_PLATFORM)
+  set(ANDROID_PLATFORM android-23)
+endif()
+
+# Choose target architecture with:
+# -DANDROID_ABI={armeabi-v7a, arm64-v8a, x86, x86_64}
+if(NOT ANDROID_ABI)
+  set(ANDROID_ABI arm64-v8a)
+endif()
+
+if(ANDROID_ABI MATCHES "^armeabi")
+  set(SYSTEM_PROCESSOR aarch32)
+else()
+  set(SYSTEM_PROCESSOR aarch64)
+endif()
+
+# Toolchain files don't have access to cached variables:
+# https://gitlab.kitware.com/cmake/cmake/issues/16170. Set an intermediate
+# environment variable when loaded the first time.
+if(AVC_ANDROID_NDK_PATH)
+  set(ENV{AVC_ANDROID_NDK_PATH} "${AVC_ANDROID_NDK_PATH}")
+else()
+  set(AVC_ANDROID_NDK_PATH "$ENV{AVC_ANDROID_NDK_PATH}")
+endif()
+
+if(NOT AVC_ANDROID_NDK_PATH)
+  message(FATAL_ERROR "AVC_ANDROID_NDK_PATH not set.")
+  return()
+endif()
+
+include("${AVC_ANDROID_NDK_PATH}/build/cmake/android.toolchain.cmake")
\ No newline at end of file
diff --git a/cmake/utils.cmake b/cmake/utils.cmake
index 468e9d1..85f98ac 100644
--- a/cmake/utils.cmake
+++ b/cmake/utils.cmake
@@ -3,9 +3,9 @@ set(CMAKE_C_STANDARD 90)
 
 # Adds compiler options for all targets
 function(libavc_add_compile_options)
-  if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
+  if("${SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${SYSTEM_PROCESSOR}" STREQUAL "arm64")
     add_compile_options(-march=armv8-a)
-  elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch32")
+  elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_compile_options(-march=armv7-a -mfpu=neon)
   else()
     add_compile_options(-msse4.2 -mno-avx)
@@ -34,9 +34,15 @@ endfunction()
 
 # Adds defintions for all targets
 function(libavc_add_definitions)
-  if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
+  if("${SYSTEM_NAME}" STREQUAL "Darwin")
+    if("${SYSTEM_PROCESSOR}" STREQUAL "arm64")
+      add_definitions(-DARMV8 -DDARWIN -DDEFAULT_ARCH=D_ARCH_ARMV8_GENERIC)
+    else()
+      add_definitions(-DX86 -DDARWIN -DDISABLE_AVX2 -DDEFAULT_ARCH=D_ARCH_X86_GENERIC)
+    endif()
+  elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch64")
     add_definitions(-DARMV8 -DDEFAULT_ARCH=D_ARCH_ARMV8_GENERIC)
-  elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch32")
+  elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
     add_definitions(-DARMV7 -DDEFAULT_ARCH=D_ARCH_ARM_A9Q)
   else()
     add_definitions(-DX86 -DX86_LINUX=1 -DDISABLE_AVX2
@@ -83,6 +89,10 @@ function(libavc_add_executable NAME LIB)
   add_dependencies(${NAME} ${LIB} ${ARG_LIBS})
 
   target_link_libraries(${NAME} ${LIB} ${ARG_LIBS})
+  if("${SYSTEM_NAME}" STREQUAL "Android")
+    target_link_libraries(${NAME} ${log-lib})
+  endif()
+
   if(ARG_FUZZER)
     target_compile_options(${NAME}
                            PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++17>)
diff --git a/common/common.cmake b/common/common.cmake
index 47ca54b..4b3e8bb 100644
--- a/common/common.cmake
+++ b/common/common.cmake
@@ -27,7 +27,7 @@ include_directories(${AVC_ROOT}/common)
 include_directories(${AVC_ROOT}/common/mvc)
 
 # arm/x86 sources
-if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
+if("${SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${SYSTEM_PROCESSOR}" STREQUAL "arm64")
   list(
     APPEND
     LIBAVC_COMMON_ASMS
@@ -59,7 +59,7 @@ if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
 
   include_directories(${AVC_ROOT}/common/arm)
   include_directories(${AVC_ROOT}/common/armv8)
-elseif("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch32")
+elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
   list(
     APPEND
     LIBAVC_COMMON_ASMS
diff --git a/decoder/arm/ih264d_function_selector.c b/decoder/arm/ih264d_function_selector.c
index 925043b..d111973 100644
--- a/decoder/arm/ih264d_function_selector.c
+++ b/decoder/arm/ih264d_function_selector.c
@@ -64,8 +64,13 @@ void ih264d_init_function_ptr(dec_struct_t *ps_codec)
 #if defined(ARMV8)
         case ARCH_ARMV8_GENERIC:
         default:
+#ifdef DARWIN
+            ih264d_init_function_ptr_generic(ps_codec);
+            break;
+#else
             ih264d_init_function_ptr_av8(ps_codec);
             break;
+#endif
 #elif !defined(DISABLE_NEON)
         case ARCH_ARM_A5:
         case ARCH_ARM_A7:
diff --git a/decoder/ih264d_api.c b/decoder/ih264d_api.c
index 16944f4..5d367ed 100644
--- a/decoder/ih264d_api.c
+++ b/decoder/ih264d_api.c
@@ -1628,7 +1628,7 @@ WORD32 ih264d_allocate_static_bufs(iv_obj_t **dec_hdl, void *pv_api_ip, void *pv
             ps_dec->apv_proc_done_mutex[i] =
                             (UWORD8 *)pv_buf + ((2 * i + 1) * mutex_size);
 
-            ret = ithread_mutex_init(ps_dec->apv_proc_start_mutex[0]);
+            ret = ithread_mutex_init(ps_dec->apv_proc_start_mutex[i]);
             RETURN_IF((ret != IV_SUCCESS), ret);
 
             ret = ithread_mutex_init(ps_dec->apv_proc_done_mutex[i]);
diff --git a/decoder/ih264d_dpb_mgr.c b/decoder/ih264d_dpb_mgr.c
index f5974ba..0f3ff66 100644
--- a/decoder/ih264d_dpb_mgr.c
+++ b/decoder/ih264d_dpb_mgr.c
@@ -18,7 +18,7 @@
  * Originally developed and contributed by Ittiam Systems Pvt. Ltd, Bangalore
 */
 #ifdef __ANDROID__
-#include <log/log.h>
+#include <android/log.h>
 #endif
 #include "ih264_typedefs.h"
 #include "ih264_macros.h"
@@ -39,6 +39,17 @@
 #include "ih264_buf_mgr.h"
 #include "assert.h"
 
+#ifdef __ANDROID__
+#ifndef ALOG
+#define ALOG(priority, tag, ...) ((void)__android_log_print(ANDROID_##priority, tag, __VA_ARGS__))
+#define ALOGE(...) ALOG(LOG_ERROR, NULL, __VA_ARGS__)
+inline int android_errorWriteLog(int tag, const char* subTag) {
+    ALOGE("android_errorWriteLog(%x, %s)", tag, subTag);
+    return 0;
+}
+#endif
+#endif
+
 /*!
  ***************************************************************************
  * \file ih264d_dpb_mgr.c
@@ -719,7 +730,7 @@ WORD32 ih264d_ref_idx_reordering(dec_struct_t *ps_dec, UWORD8 uc_lx)
     dpb_manager_t *ps_dpb_mgr = ps_dec->ps_dpb_mgr;
     UWORD16 u4_cur_pic_num = ps_dec->ps_cur_slice->u2_frame_num;
     /*< Maximum Picture Number Minus 1 */
-    UWORD16 ui_max_frame_num =
+    UWORD32 ui_max_frame_num =
                     ps_dec->ps_cur_sps->u2_u4_max_pic_num_minus1 + 1;
 
     WORD32 i, count = 0;
@@ -765,7 +776,7 @@ WORD32 ih264d_ref_idx_reordering(dec_struct_t *ps_dec, UWORD8 uc_lx)
             {
                 // diffPicNum is +ve
                 i_temp = (WORD32)u2_pred_frame_num + (WORD32)ui_nextUev;
-                if(i_temp >= ui_max_frame_num)
+                if(i_temp >= (WORD32)ui_max_frame_num)
                     i_temp -= ui_max_frame_num;
             }
             /* Find the dpb with the matching picNum (picNum==frameNum for framePic) */
diff --git a/decoder/ih264d_parse_headers.c b/decoder/ih264d_parse_headers.c
index a92ad8a..ee161d8 100644
--- a/decoder/ih264d_parse_headers.c
+++ b/decoder/ih264d_parse_headers.c
@@ -584,7 +584,7 @@ WORD32 ih264d_parse_sps(dec_struct_t *ps_dec, dec_bit_stream_t *ps_bitstrm)
     UWORD8 i;
     dec_seq_params_t *ps_seq = NULL;
     UWORD8 u1_profile_idc, u1_level_idc, u1_seq_parameter_set_id, u1_mb_aff_flag = 0;
-    UWORD16 i2_max_frm_num;
+    UWORD32 u4_max_frm_num;
     UWORD32 *pu4_bitstrm_buf = ps_bitstrm->pu4_buffer;
     UWORD32 *pu4_bitstrm_ofst = &ps_bitstrm->u4_ofst;
     UWORD8 u1_frm, uc_constraint_set0_flag, uc_constraint_set1_flag;
@@ -794,8 +794,8 @@ WORD32 ih264d_parse_sps(dec_struct_t *ps_dec, dec_bit_stream_t *ps_bitstrm)
     COPYTHECONTEXT("SPS: log2_max_frame_num_minus4",
                     (ps_seq->u1_bits_in_frm_num - 4));
 
-    i2_max_frm_num = (1 << (ps_seq->u1_bits_in_frm_num));
-    ps_seq->u2_u4_max_pic_num_minus1 = i2_max_frm_num - 1;
+    u4_max_frm_num = (1 << (ps_seq->u1_bits_in_frm_num));
+    ps_seq->u2_u4_max_pic_num_minus1 = u4_max_frm_num - 1;
     /*--------------------------------------------------------------------*/
     /* Decode picture order count and related values                      */
     /*--------------------------------------------------------------------*/
diff --git a/decoder/ih264d_structs.h b/decoder/ih264d_structs.h
index cc8e081..8c10aa9 100644
--- a/decoder/ih264d_structs.h
+++ b/decoder/ih264d_structs.h
@@ -343,7 +343,7 @@ typedef struct
     UWORD8 u1_arbitrary_slice_order_allowed_flag;
     UWORD8 u1_redundant_slices_allowed_flag;
     UWORD8 u1_bits_in_frm_num; /** Number of bits in frame num */
-    UWORD16 u2_u4_max_pic_num_minus1; /** Maximum frame num minus 1 */
+    UWORD32 u2_u4_max_pic_num_minus1; /** Maximum frame num minus 1 */
     UWORD8 u1_pic_order_cnt_type; /** 0 - 2 indicates the method to code picture order count */
     UWORD8 u1_log2_max_pic_order_cnt_lsb_minus;
     WORD32 i4_max_pic_order_cntLsb;
diff --git a/decoder/libavcdec.cmake b/decoder/libavcdec.cmake
index 911c328..1b72dd5 100644
--- a/decoder/libavcdec.cmake
+++ b/decoder/libavcdec.cmake
@@ -36,8 +36,8 @@ list(
 
 include_directories(${AVC_ROOT}/decoder)
 
-if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${CMAKE_SYSTEM_PROCESSOR}"
-                                                     STREQUAL "aarch32")
+if("${SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${SYSTEM_PROCESSOR}" STREQUAL "arm64"
+     OR "${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
   list(
     APPEND LIBAVCDEC_ASMS "${AVC_ROOT}/decoder/arm/ih264d_function_selector.c"
     "${AVC_ROOT}/decoder/arm/ih264d_function_selector_a9q.c"
diff --git a/encoder/arm/ih264e_function_selector.c b/encoder/arm/ih264e_function_selector.c
index 2b155ca..fb57e38 100644
--- a/encoder/arm/ih264e_function_selector.c
+++ b/encoder/arm/ih264e_function_selector.c
@@ -119,8 +119,13 @@ void ih264e_init_function_ptr(void *pv_codec)
         case ARCH_ARM_A57:
         case ARCH_ARM_V8_NEON:
         default:
+#ifdef DARWIN
+            ih264e_init_function_ptr_generic(ps_codec);
+            break;
+#else
             ih264e_init_function_ptr_neon_av8(ps_codec);
             break;
+#endif
 #elif !defined(DISABLE_NEON)
         case ARCH_ARM_A9Q:
         case ARCH_ARM_A9A:
diff --git a/encoder/libavcenc.cmake b/encoder/libavcenc.cmake
index cf7be9c..a8b525c 100644
--- a/encoder/libavcenc.cmake
+++ b/encoder/libavcenc.cmake
@@ -44,7 +44,7 @@ list(
 
 include_directories(${AVC_ROOT}/encoder)
 
-if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
+if("${SYSTEM_PROCESSOR}" STREQUAL "aarch64" OR "${SYSTEM_PROCESSOR}" STREQUAL "arm64")
   list(
     APPEND
     LIBAVCENC_ASMS
@@ -57,7 +57,7 @@ if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
     "${AVC_ROOT}/encoder/armv8/ime_distortion_metrics_av8.s")
 
   include_directories(${AVC_ROOT}/encoder/armv8)
-elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch32")
+elseif("${SYSTEM_PROCESSOR}" STREQUAL "aarch32")
   list(
     APPEND
     LIBAVCENC_ASMS
diff --git a/fuzzer/avc_dec_fuzzer.cmake b/fuzzer/avc_dec_fuzzer.cmake
index c20aaed..2d8fc3c 100644
--- a/fuzzer/avc_dec_fuzzer.cmake
+++ b/fuzzer/avc_dec_fuzzer.cmake
@@ -1,2 +1,4 @@
-libavc_add_fuzzer(avc_dec_fuzzer libavcdec SOURCES
+if(NOT "${SYSTEM_NAME}" STREQUAL "Darwin")
+    libavc_add_fuzzer(avc_dec_fuzzer libavcdec SOURCES
                   ${AVC_ROOT}/fuzzer/avc_dec_fuzzer.cpp)
+endif()
\ No newline at end of file
diff --git a/fuzzer/avc_enc_fuzzer.cmake b/fuzzer/avc_enc_fuzzer.cmake
index d6cb551..89e70fa 100644
--- a/fuzzer/avc_enc_fuzzer.cmake
+++ b/fuzzer/avc_enc_fuzzer.cmake
@@ -1,2 +1,4 @@
-libavc_add_fuzzer(avc_enc_fuzzer libavcenc SOURCES
+if(NOT "${SYSTEM_NAME}" STREQUAL "Darwin")
+    libavc_add_fuzzer(avc_enc_fuzzer libavcenc SOURCES
                   ${AVC_ROOT}/fuzzer/avc_enc_fuzzer.cpp)
+endif()
\ No newline at end of file
```

