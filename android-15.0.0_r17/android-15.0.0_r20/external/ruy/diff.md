```diff
diff --git a/BUILD b/BUILD
index 8c2d62e..342aad7 100644
--- a/BUILD
+++ b/BUILD
@@ -1,7 +1,15 @@
 # Ruy is not BLAS
 
+load("//tools/build_defs/license:license.bzl", "license")
+
 package(
+    default_applicable_licenses = ["//third_party/ruy:license"],
     licenses = ["notice"],  # Apache 2.0
 )
 
+license(
+    name = "license",
+    package_name = "ruy",
+)
+
 exports_files(["LICENSE"])
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 98d480d..f4fe893 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -18,7 +18,7 @@ project(ruy CXX)
 cmake_minimum_required(VERSION 3.13)  # Copied from IREE
 set(CMAKE_CXX_STANDARD 14)
 
-
+include(GNUInstallDirs)
 
 if (PROJECT_NAME STREQUAL CMAKE_PROJECT_NAME)
   set(RUY_IS_TOPLEVEL TRUE)
@@ -35,41 +35,49 @@ endif()
 
 option(RUY_PROFILER "Enable ruy's built-in profiler (harms performance)" OFF)
 
+option(RUY_ENABLE_INSTALL "Enable install rule" ${RUY_IS_TOPLEVEL})
+
 include(cmake/ruy_add_all_subdirs.cmake)
 include(cmake/ruy_cc_library.cmake)
 include(cmake/ruy_cc_binary.cmake)
 include(cmake/ruy_cc_test.cmake)
 
+option(RUY_FIND_CPUINFO "Use find_package to find cpuinfo" OFF)
+
 # Skip cpuinfo if it was already generated, which can happen when ruy is
 # a subdirectory in a wider project that already uses cpuinfo.
-if (NOT TARGET cpuinfo)
-  # Test if the third_party/cpuinfo submodule was checked out before
-  # adding that subdirectory, so we can do more helpful things below in the
-  # else() block when it's not.
-  set(RUY_CPUINFO_CMAKELISTS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/third_party/cpuinfo/CMakeLists.txt")
-  if (EXISTS "${RUY_CPUINFO_CMAKELISTS_FILE}")
-    # Disabling cpuinfo's tests and benchmarks to prevent a copy of its
-    # googletest dependency getting downloaded into a 'deps' directory in the
-    # source tree!
-    set(CPUINFO_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
-    set(CPUINFO_BUILD_UNIT_TESTS OFF CACHE BOOL "" FORCE)
-    set(CPUINFO_BUILD_MOCK_TESTS OFF CACHE BOOL "" FORCE)
-    add_subdirectory("third_party/cpuinfo" EXCLUDE_FROM_ALL)
+if (NOT TARGET cpuinfo::cpuinfo)
+  if (RUY_FIND_CPUINFO)
+    find_package(cpuinfo REQUIRED)
   else()
-    # third_party/cpuinfo is not checked out. That could be intentional when
-    # ruy is a subdirectory in a wider project that is already providing
-    # the cpuinfo target. Maybe that wider project's CMakeLists is ordered
-    # in such a way that cpuinfo gets generated after ruy. In that case,
-    # it's helpful that we continue silently. In the worst case if the cpuinfo
-    # target never gets defined, ruy will fail to compile.
-    # On the other hand, if ruy is the top-level project here (not part of a
-    # wider project) then nothing will define the cpuinfo target for us,
-    # so we will definitely fail to compile, so we may as well fail right here.
-    if (RUY_IS_TOPLEVEL)
-      message(FATAL_ERROR "This file does not exist:\n${RUY_CPUINFO_CMAKELISTS_FILE}\n"
-                    "That typically means that the git submodules of the ruy "
-                    "repository haven't been checked out. Try this in the ruy "
-                    "git directory:\n  git submodule update --init")
+    # Test if the third_party/cpuinfo submodule was checked out before
+    # adding that subdirectory, so we can do more helpful things below in the
+    # else() block when it's not.
+    set(RUY_CPUINFO_CMAKELISTS_FILE "${CMAKE_CURRENT_SOURCE_DIR}/third_party/cpuinfo/CMakeLists.txt")
+    if (EXISTS "${RUY_CPUINFO_CMAKELISTS_FILE}")
+      # Disabling cpuinfo's tests and benchmarks to prevent a copy of its
+      # googletest dependency getting downloaded into a 'deps' directory in the
+      # source tree!
+      set(CPUINFO_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
+      set(CPUINFO_BUILD_UNIT_TESTS OFF CACHE BOOL "" FORCE)
+      set(CPUINFO_BUILD_MOCK_TESTS OFF CACHE BOOL "" FORCE)
+      add_subdirectory("third_party/cpuinfo" EXCLUDE_FROM_ALL)
+    else()
+      # third_party/cpuinfo is not checked out. That could be intentional when
+      # ruy is a subdirectory in a wider project that is already providing
+      # the cpuinfo target. Maybe that wider project's CMakeLists is ordered
+      # in such a way that cpuinfo gets generated after ruy. In that case,
+      # it's helpful that we continue silently. In the worst case if the cpuinfo
+      # target never gets defined, ruy will fail to compile.
+      # On the other hand, if ruy is the top-level project here (not part of a
+      # wider project) then nothing will define the cpuinfo target for us,
+      # so we will definitely fail to compile, so we may as well fail right here.
+      if (RUY_IS_TOPLEVEL)
+        message(FATAL_ERROR "This file does not exist:\n${RUY_CPUINFO_CMAKELISTS_FILE}\n"
+                      "That typically means that the git submodules of the ruy "
+                      "repository haven't been checked out. Try this in the ruy "
+                      "git directory:\n  git submodule update --init")
+      endif()
     endif()
   endif()
 endif()
@@ -88,3 +96,22 @@ add_subdirectory("ruy")
 if (NOT RUY_MINIMAL_BUILD)
   add_subdirectory("example")
 endif()
+
+if (RUY_ENABLE_INSTALL)
+  install(EXPORT ${PROJECT_NAME}Targets
+    NAMESPACE ${PROJECT_NAME}::
+    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
+  )
+
+  include(CMakePackageConfigHelpers)
+
+  configure_package_config_file(
+    "cmake/${PROJECT_NAME}Config.cmake.in"
+    "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
+    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
+  )
+
+  install(FILES "${PROJECT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
+    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
+  )
+endif()
diff --git a/METADATA b/METADATA
index e9e9490..d9eb697 100644
--- a/METADATA
+++ b/METADATA
@@ -1,15 +1,19 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/ruy
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "ruy"
 description: "ruy is a matrix multiplication library."
 third_party {
-  url {
-    type: GIT
-    value: "https://github.com/google/ruy"
-  }
-  version: "9c56af3fce210a8a103eda19bd6f47c08a9e3d90"
   license_type: NOTICE
   last_upgrade_date {
-    year: 2021
-    month: 8
-    day: 11
+    year: 2024
+    month: 11
+    day: 8
+  }
+  identifier {
+    type: "Git"
+    value: "https://github.com/google/ruy"
+    version: "c08ec529fc91722bde519628d9449258082eb847"
   }
 }
diff --git a/OWNERS b/OWNERS
new file mode 100644
index 0000000..7529cb9
--- /dev/null
+++ b/OWNERS
@@ -0,0 +1 @@
+include platform/system/core:/janitors/OWNERS
diff --git a/cmake/bazel_to_cmake.py b/cmake/bazel_to_cmake.py
index 8f972ba..caf9cbf 100755
--- a/cmake/bazel_to_cmake.py
+++ b/cmake/bazel_to_cmake.py
@@ -49,7 +49,7 @@ replacements = [
     ['selects.config_setting_group', 'config_setting_group'],
     ['@com_google_googletest//:gtest', 'gtest'],
     ['@com_google_googletest//:gtest_main', 'gtest_main'],
-    ['@cpuinfo', 'cpuinfo'],
+    ['@cpuinfo', 'cpuinfo::cpuinfo'],
 ]
 
 
diff --git a/cmake/ruyConfig.cmake.in b/cmake/ruyConfig.cmake.in
new file mode 100644
index 0000000..0f3a4f1
--- /dev/null
+++ b/cmake/ruyConfig.cmake.in
@@ -0,0 +1,9 @@
+# ruy CMake configuration file.
+
+include(CMakeFindDependencyMacro)
+
+find_dependency(cpuinfo)
+
+@PACKAGE_INIT@
+
+include("${CMAKE_CURRENT_LIST_DIR}/@PROJECT_NAME@Targets.cmake")
diff --git a/cmake/ruy_cc_library.cmake b/cmake/ruy_cc_library.cmake
index 38accc5..3f3a062 100644
--- a/cmake/ruy_cc_library.cmake
+++ b/cmake/ruy_cc_library.cmake
@@ -42,12 +42,16 @@ function(ruy_cc_library)
     set(_RULE_IS_INTERFACE 0)
   endif()
 
+  file(RELATIVE_PATH _SUBDIR ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_LIST_DIR})
+
   if(_RULE_IS_INTERFACE)
     # Generating a header-only library.
     add_library(${_NAME} INTERFACE)
+    set_target_properties(${_NAME} PROPERTIES PUBLIC_HEADER "${_RULE_HDRS}")
     target_include_directories(${_NAME}
       INTERFACE
-        "${PROJECT_SOURCE_DIR}"
+        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
+        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
     )
     target_link_libraries(${_NAME}
       INTERFACE
@@ -60,12 +64,8 @@ function(ruy_cc_library)
     )
   else()
     # Generating a static binary library.
-    add_library(${_NAME} STATIC "")
-    target_sources(${_NAME}
-      PRIVATE
-        ${_RULE_SRCS}
-        ${_RULE_HDRS}
-    )
+    add_library(${_NAME} STATIC ${_RULE_SRCS} ${_RULE_HDRS})
+    set_target_properties(${_NAME} PROPERTIES PUBLIC_HEADER "${_RULE_HDRS}")
     ruy_include_directories(${_NAME} "${_RULE_DEPS}")
     target_compile_options(${_NAME}
       PRIVATE
@@ -82,4 +82,15 @@ function(ruy_cc_library)
         ${_RULE_DEFINES}
     )
   endif()
+
+  add_library(${PROJECT_NAME}::${_NAME} ALIAS ${_NAME})
+
+  if(NOT _RULE_TESTONLY)
+    install(
+      TARGETS ${_NAME}
+      EXPORT ruyTargets
+      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
+      PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${_SUBDIR}
+    )
+  endif()
 endfunction()
diff --git a/cmake/ruy_include_directories.cmake b/cmake/ruy_include_directories.cmake
index e9b50a9..a90ab61 100644
--- a/cmake/ruy_include_directories.cmake
+++ b/cmake/ruy_include_directories.cmake
@@ -14,20 +14,8 @@
 
 function(ruy_include_directories NAME DEPS)
   target_include_directories(${NAME}
-      PUBLIC
-      "${PROJECT_SOURCE_DIR}"
+    PUBLIC
+      "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>"
+      "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
   )
-  if (cpuinfo IN_LIST DEPS)
-    target_include_directories(${NAME}
-      PRIVATE
-        "${PROJECT_SOURCE_DIR}/third_party/cpuinfo/include"
-    )
-  endif()
-  if ((gtest IN_LIST DEPS) OR
-      (gtest_main IN_LIST DEPS))
-    target_include_directories(${NAME}
-      PRIVATE
-        "${PROJECT_SOURCE_DIR}/third_party/googletest/googletest"
-    )
-  endif()
-endfunction()
\ No newline at end of file
+endfunction()
diff --git a/doc/depgraph.sh b/doc/depgraph.sh
index d66d44f..d1f72af 100755
--- a/doc/depgraph.sh
+++ b/doc/depgraph.sh
@@ -29,7 +29,7 @@ drop=(
     ':validate'
     'profiler:instrumentation'
     '\bclog\b'
-    '\bcpuinfo_impl\b'
+    '\bcpuinfo\b'
     ':apply_multiplier'
     '\blabel='
 )
diff --git a/example/BUILD b/example/BUILD
index 738c33e..912fb2d 100644
--- a/example/BUILD
+++ b/example/BUILD
@@ -1,4 +1,5 @@
 package(
+    default_applicable_licenses = ["//third_party/ruy:license"],
     licenses = ["notice"],  # Apache 2.0
 )
 
diff --git a/example/example.cc b/example/example.cc
index 3bb95f4..6d4fff2 100644
--- a/example/example.cc
+++ b/example/example.cc
@@ -126,6 +126,7 @@ void ExampleMulInt8PerChannelQuantized(ruy::Context *context) {
   std::cout << "RHS:\n" << rhs;
   std::cout << "Result:\n" << dst << "\n";
 }
+
 void ExampleMulInt8GetRawAccumulators(ruy::Context *context) {
   const std::int8_t lhs_data[] = {1, 2, 3, 4};
   const std::int8_t rhs_data[] = {1, 2, 3, 4};
@@ -151,6 +152,35 @@ void ExampleMulInt8GetRawAccumulators(ruy::Context *context) {
   std::cout << "Result:\n" << dst << "\n";
 }
 
+void ExampleMulInt8TimesInt16PerChannelQuantized(ruy::Context *context) {
+  const std::int8_t lhs_data[] = {1, 2, 3, 4};
+  const std::int16_t rhs_data[] = {1000, 2000, 3000, 4000};
+  const std::int32_t multiplier_data[] = {3 << 28, 5 << 28};
+  const int exponent_data[] = {1, -2};
+  std::int16_t dst_data[4];
+
+  ruy::Matrix<std::int8_t> lhs;
+  ruy::MakeSimpleLayout(2, 2, ruy::Order::kRowMajor, lhs.mutable_layout());
+  lhs.set_data(lhs_data);
+  ruy::Matrix<std::int16_t> rhs;
+  ruy::MakeSimpleLayout(2, 2, ruy::Order::kColMajor, rhs.mutable_layout());
+  rhs.set_data(rhs_data);
+  ruy::Matrix<std::int16_t> dst;
+  ruy::MakeSimpleLayout(2, 2, ruy::Order::kColMajor, dst.mutable_layout());
+  dst.set_data(dst_data);
+
+  ruy::MulParams<std::int32_t, std::int16_t> mul_params;
+  mul_params.set_multiplier_fixedpoint_perchannel(multiplier_data);
+  mul_params.set_multiplier_exponent_perchannel(exponent_data);
+  ruy::Mul(lhs, rhs, mul_params, context, &dst);
+
+  std::cout << "Example Mul, int8 times int16 quantized with per-channel "
+               "multipliers\n";
+  std::cout << "LHS:\n" << lhs;
+  std::cout << "RHS:\n" << rhs;
+  std::cout << "Result:\n" << dst << "\n";
+}
+
 int main() {
   ruy::Context context;
   ExampleMulFloat(&context);
@@ -158,4 +188,5 @@ int main() {
   ExampleMulUint8AsymmetricQuantized(&context);
   ExampleMulInt8PerChannelQuantized(&context);
   ExampleMulInt8GetRawAccumulators(&context);
+  ExampleMulInt8TimesInt16PerChannelQuantized(&context);
 }
diff --git a/example/parametrized_example.cc b/example/parametrized_example.cc
index ef6ad23..253d911 100644
--- a/example/parametrized_example.cc
+++ b/example/parametrized_example.cc
@@ -140,7 +140,8 @@ int main(int argc, char* argv[]) {
   }
   Params params;
   const char* allowed_types =
-      "f32xf32->f32, i8xi8->i8, i8xi8->i16, i8xi8->i32, u8xu8->i16, u8xi8->u8";
+      "f32xf32->f32, i8xi8->i8, i8xi8->i16, i8xi8->i32, u8xu8->i16, u8xi8->u8, "
+      "i8xi16->i16, i16xi8->i16";
   const char* allowed_orders = "row-major, column-major";
   read_cmdline_args(help, argc, argv, "--types", "%s", "f32xf32->f32",
                     allowed_types, &params.types);
@@ -172,7 +173,7 @@ int main(int argc, char* argv[]) {
                     allowed_orders, &params.lhs_order);
   read_cmdline_args(help, argc, argv, "--rhs_order", "%s", "row-major",
                     allowed_orders, &params.rhs_order);
-  read_cmdline_args(help, argc, argv, "--rhs_order", "%s", "row-major",
+  read_cmdline_args(help, argc, argv, "--dst_order", "%s", "row-major",
                     allowed_orders, &params.dst_order);
 
   if (help) {
@@ -191,6 +192,10 @@ int main(int argc, char* argv[]) {
     run<std::uint8_t, std::uint8_t, std::int16_t>(params);
   } else if (!strcmp(params.types, "u8xi8->u8")) {
     run<std::uint8_t, std::int8_t, std::uint8_t>(params);
+  } else if (!strcmp(params.types, "i8xi16->i16")) {
+    run<std::int8_t, std::int16_t, std::int16_t>(params);
+  } else if (!strcmp(params.types, "i16xi8->i16")) {
+    run<std::int16_t, std::int8_t, std::int16_t>(params);
   } else {
     fprintf(stderr, "Unknown types: %s\n", params.types);
     exit(1);
diff --git a/ruy/BUILD b/ruy/BUILD
index d04a45d..81d336a 100644
--- a/ruy/BUILD
+++ b/ruy/BUILD
@@ -8,66 +8,55 @@ load(":ruy_test_ext.oss.bzl", "ruy_test_ext_defines", "ruy_test_ext_deps")
 load(":ruy_test.bzl", "ruy_benchmark", "ruy_test")
 
 package(
+    default_applicable_licenses = ["//third_party/ruy:license"],
     licenses = ["notice"],  # Apache 2.0
 )
 
-config_setting(
-    name = "armeabi-v7a",
-    values = {"cpu": "armeabi-v7a"},
-)
-
-config_setting(
-    name = "armv7a",
-    values = {"cpu": "armv7a"},
-)
-
 # Detect ARM 32-bit targets where we are going to just assume NEON support.
-selects.config_setting_group(
+config_setting(
     name = "arm32_assuming_neon",
-    match_any = [
-        ":armeabi-v7a",
-        ":armv7a",
+    constraint_values = [
+        "@platforms//cpu:armv7",
     ],
 )
 
 config_setting(
-    name = "x86_64_k8",
-    values = {"cpu": "k8"},
+    name = "x86_64_and_not_msvc",
+    constraint_values = [
+        "@platforms//cpu:x86_64",
+        "@platforms//os:linux",
+    ],
 )
 
 config_setting(
-    name = "x86_64_haswell",
-    values = {"cpu": "haswell"},
-)
-
-# MSVC toolchains define a different "cpu" value, which helps us as we need
-# to pass different flags on MSVC vs GCC-compatible toolchains to enable
-# x86 SIMD extensions.
-selects.config_setting_group(
-    name = "x86_64_and_not_msvc",
-    match_any = [
-        ":x86_64_k8",
-        ":x86_64_haswell",
+    name = "windows_msvc",
+    constraint_values = [
+        "@platforms//os:windows",
     ],
+    flag_values = {
+        "//tools/cpp:compiler": "msvc",
+    },
 )
 
 config_setting(
     name = "ppc",
-    values = {
-        "cpu": "ppc",
-    },
+    constraint_values = [
+        "@platforms//cpu:ppc",
+    ],
 )
 
 config_setting(
     name = "s390x",
-    values = {
-        "cpu": "s390x",
-    },
+    constraint_values = [
+        "@platforms//cpu:s390x",
+    ],
 )
 
 config_setting(
     name = "fuchsia",
-    values = {"cpu": "fuchsia"},
+    constraint_values = [
+        "@platforms//os:fuchsia",
+    ],
 )
 
 config_setting(
@@ -87,7 +76,7 @@ config_setting(
 selects.config_setting_group(
     name = "do_not_want_O3",
     match_any = [
-        "@bazel_tools//src/conditions:windows_msvc",
+        ":windows_msvc",
         ":dbg_build",
         ":fastbuild_build",
     ],
@@ -380,7 +369,7 @@ cc_library(
     ],
     copts = ruy_copts() +
             select({
-                "@bazel_tools//src/conditions:windows": [],
+                "@platforms//os:windows": [],
                 "//conditions:default": [
                     # ruy_copts contains -Wundef, but cpuinfo's header warns with that.
                     "-Wno-undef",
@@ -397,9 +386,9 @@ cc_library(
         "//conditions:default": ["-DRUY_HAVE_CPUINFO"],
     }),
     deps = [
-        ":platform",
         ":check_macros",
         ":cpu_cache_params",
+        ":platform",
     ] + select({
         # This select must match the similar select in `copts`
         ":ppc": [],
@@ -435,6 +424,13 @@ cc_library(
     visibility = ["//visibility:public"],
 )
 
+cc_library(
+    name = "strategy_controls",
+    hdrs = ["strategy_controls.h"],
+    copts = ruy_copts(),
+    visibility = ["//visibility:public"],
+)
+
 cc_library(
     name = "matrix",
     hdrs = ["matrix.h"],
@@ -859,6 +855,7 @@ cc_library(
         ":performance_advisory",
         ":platform",
         ":prepacked_cache",
+        ":strategy_controls",
         ":thread_pool",
         ":tune",
     ],
@@ -874,6 +871,7 @@ cc_test(
         ":path",
         ":platform",
         ":prepacked_cache",
+        ":strategy_controls",
         ":tune",
     ],
 )
@@ -907,6 +905,7 @@ cc_library(
         ":performance_advisory",
         ":platform",
         ":prepacked_cache",
+        ":strategy_controls",
         ":thread_pool",
         ":trace",
         ":tune",
@@ -937,6 +936,7 @@ cc_test(
         ":gtest_wrapper",
         ":path",
         ":platform",
+        ":strategy_controls",
     ],
 )
 
@@ -972,6 +972,7 @@ cc_library(
         ":opt_set",
         ":side_pair",
         ":size_util",
+        ":strategy_controls",
         ":thread_pool",
         ":trace",
         ":trmul_params",
@@ -1126,24 +1127,24 @@ cc_library(
     # need defines, not copts, because it's controlling a header, test.h
     defines = ruy_test_ext_defines(),
     linkopts = select({
-        "@bazel_tools//src/conditions:windows": [],
+        "@platforms//os:windows": [],
         "//conditions:default": ["-lm"],
     }),
     deps = [
         ":allocator",
-        ":size_util",
-        ":reference_mul",
+        ":context",
+        ":context_get_ctx",
+        ":ctx",
+        ":gtest_wrapper",
         ":matrix",
+        ":mul_params",
+        ":pack_common",
+        ":platform",
         ":pmu",
+        ":reference_mul",
         ":ruy",
-        ":mul_params",
+        ":size_util",
         ":time",
-        ":gtest_wrapper",
-        ":platform",
-        ":context",
-        ":ctx",
-        ":context_get_ctx",
-        ":pack_common",
         "//ruy/profiler",
     ] + ruy_test_ext_deps(),
 )
@@ -1159,6 +1160,8 @@ ruy_benchmark(
         ("i8", "i8", "i32", "i8"),
         ("u8", "u8", "i32", "i16"),
         ("i8", "i8", "i32", "i32"),
+        ("i8", "i16", "i32", "i16"),
+        ("i16", "i8", "i32", "i16"),
     ],
     deps = [
         ":test_lib",
@@ -1180,6 +1183,8 @@ ruy_test(
         ("u8", "u8", "i32", "i16"),
         ("i8", "i8", "i32", "i32"),
         ("i8", "u8", "i32", "i32"),
+        ("i8", "i16", "i32", "i16"),
+        ("i16", "i8", "i32", "i16"),
     ],
     deps = [
         ":test_lib",
@@ -1197,6 +1202,8 @@ ruy_test(
         ("i8", "i8", "i32", "i8"),
         ("u8", "u8", "i32", "i16"),
         ("i8", "i8", "i32", "i32"),
+        ("i8", "i16", "i32", "i16"),
+        ("i16", "i8", "i32", "i16"),
     ],
     tags = ["slow"],
     deps = [
diff --git a/ruy/CMakeLists.txt b/ruy/CMakeLists.txt
index 502ad8a..8e493de 100644
--- a/ruy/CMakeLists.txt
+++ b/ruy/CMakeLists.txt
@@ -3,9 +3,9 @@
 #   cmake/bazel_to_cmake.sh
 
 if(CMAKE_SYSTEM_NAME STREQUAL Windows)
-  set(ruy_0_Wall_Wcxx14_compat_Wextra_Wundef "")
+  set(ruy_0_Wall_Wextra_Wundef "")
 else()
-  set(ruy_0_Wall_Wcxx14_compat_Wextra_Wundef "-Wall;-Wextra;-Wc++14-compat;-Wundef")
+  set(ruy_0_Wall_Wextra_Wundef "-Wall;-Wextra;-Wundef")
 endif()
 
 if(CMAKE_SYSTEM_PROCESSOR STREQUAL arm)
@@ -26,7 +26,7 @@ ruy_cc_library(
   HDRS
     trace.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -43,7 +43,7 @@ ruy_cc_library(
   HDRS
     platform.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
 )
@@ -64,7 +64,7 @@ ruy_cc_library(
   HDRS
     check_macros.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
 )
@@ -75,7 +75,7 @@ ruy_cc_test(
   SRCS
     check_macros_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -89,7 +89,7 @@ ruy_cc_library(
   HDRS
     opt_set.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
 )
@@ -100,7 +100,7 @@ ruy_cc_library(
   HDRS
     time.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
 )
@@ -119,7 +119,7 @@ ruy_cc_library(
   HDRS
     wait.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   LINKOPTS
@@ -134,7 +134,7 @@ ruy_cc_test(
   SRCS
     wait_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   LINKOPTS
@@ -151,7 +151,7 @@ ruy_cc_library(
   HDRS
     size_util.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -164,7 +164,7 @@ ruy_cc_test(
   SRCS
     size_util_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -180,7 +180,7 @@ ruy_cc_library(
   HDRS
     tune.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -199,7 +199,7 @@ ruy_cc_library(
   HDRS
     system_aligned_alloc.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
 )
@@ -212,7 +212,7 @@ ruy_cc_library(
   HDRS
     prepacked_cache.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -227,7 +227,7 @@ ruy_cc_test(
   SRCS
     tune_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -242,7 +242,7 @@ ruy_cc_test(
   SRCS
     prepacked_cache_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -265,7 +265,7 @@ ruy_cc_library(
   HDRS
     allocator.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -280,7 +280,7 @@ ruy_cc_test(
   SRCS
     allocator_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -294,7 +294,7 @@ ruy_cc_library(
   HDRS
     side_pair.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -309,7 +309,7 @@ ruy_cc_library(
   HDRS
     block_map.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -328,7 +328,7 @@ ruy_cc_test(
   SRCS
     block_map_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -348,7 +348,7 @@ ruy_cc_library(
   HDRS
     blocking_counter.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   LINKOPTS
@@ -367,7 +367,7 @@ ruy_cc_library(
   HDRS
     thread_pool.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   LINKOPTS
@@ -388,7 +388,7 @@ ruy_cc_library(
   HDRS
     cpu_cache_params.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
 )
@@ -410,13 +410,13 @@ else()
 endif()
 
 if(CMAKE_SYSTEM_PROCESSOR STREQUAL ppc64 OR CMAKE_SYSTEM_PROCESSOR STREQUAL ppc64le)
-  set(ruy_6_cpuinfo "")
+  set(ruy_6_cpuinfo_cpuinfo "")
 elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL s390 OR CMAKE_SYSTEM_PROCESSOR STREQUAL s390x)
-  set(ruy_6_cpuinfo "")
+  set(ruy_6_cpuinfo_cpuinfo "")
 elseif(CMAKE_SYSTEM_NAME STREQUAL Fuchsia)
-  set(ruy_6_cpuinfo "")
+  set(ruy_6_cpuinfo_cpuinfo "")
 else()
-  set(ruy_6_cpuinfo "cpuinfo")
+  set(ruy_6_cpuinfo_cpuinfo "cpuinfo::cpuinfo")
 endif()
 
 ruy_cc_library(
@@ -427,7 +427,7 @@ ruy_cc_library(
   HDRS
     cpuinfo.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     ${ruy_4_Wno_undef}
@@ -436,7 +436,7 @@ ruy_cc_library(
     ruy_platform
     ruy_check_macros
     ruy_cpu_cache_params
-    ${ruy_6_cpuinfo}
+    ${ruy_6_cpuinfo_cpuinfo}
 )
 
 ruy_cc_library(
@@ -445,7 +445,7 @@ ruy_cc_library(
   HDRS
     path.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   PUBLIC
@@ -462,7 +462,7 @@ ruy_cc_library(
   HDRS
     denormal.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   PUBLIC
@@ -474,7 +474,7 @@ ruy_cc_library(
   HDRS
     performance_advisory.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   PUBLIC
@@ -486,7 +486,7 @@ ruy_cc_library(
   HDRS
     matrix.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   PUBLIC
@@ -500,7 +500,7 @@ ruy_cc_test(
   SRCS
     matrix_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -514,7 +514,7 @@ ruy_cc_library(
   HDRS
     mul_params.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   PUBLIC
@@ -529,7 +529,7 @@ ruy_cc_test(
   SRCS
     mul_params_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -543,7 +543,7 @@ ruy_cc_library(
   HDRS
     mat.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -558,7 +558,7 @@ ruy_cc_library(
   HDRS
     asm_helpers.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -573,7 +573,7 @@ ruy_cc_library(
   HDRS
     apply_multiplier.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -587,7 +587,7 @@ ruy_cc_test(
   SRCS
     apply_multiplier_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -602,7 +602,7 @@ ruy_cc_library(
   HDRS
     kernel_common.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -626,7 +626,7 @@ ruy_cc_library(
   HDRS
     pack_common.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -649,7 +649,7 @@ ruy_cc_library(
   HDRS
     kernel_arm.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -675,7 +675,7 @@ ruy_cc_library(
   HDRS
     pack_arm.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -706,7 +706,7 @@ ruy_cc_library(
   HDRS
     kernel_x86.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     ${ruy_7_mavx512bw_mavx512cd_mavx512dq_mavx512f_mavx512vl_arch_AVX512}
@@ -730,7 +730,7 @@ ruy_cc_library(
   HDRS
     pack_x86.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     ${ruy_7_mavx512bw_mavx512cd_mavx512dq_mavx512f_mavx512vl_arch_AVX512}
@@ -753,7 +753,7 @@ ruy_cc_library(
   HDRS
     have_built_path_for.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     ${ruy_7_mavx512bw_mavx512cd_mavx512dq_mavx512f_mavx512vl_arch_AVX512}
@@ -778,7 +778,7 @@ ruy_cc_library(
   HDRS
     kernel_x86.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     ${ruy_8_mavx2_mfma_arch_AVX2}
@@ -802,7 +802,7 @@ ruy_cc_library(
   HDRS
     pack_x86.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     ${ruy_8_mavx2_mfma_arch_AVX2}
@@ -825,7 +825,7 @@ ruy_cc_library(
   HDRS
     have_built_path_for.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     ${ruy_8_mavx2_mfma_arch_AVX2}
@@ -850,7 +850,7 @@ ruy_cc_library(
   HDRS
     kernel_x86.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     ${ruy_9_mavx_arch_AVX}
@@ -874,7 +874,7 @@ ruy_cc_library(
   HDRS
     pack_x86.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     ${ruy_9_mavx_arch_AVX}
@@ -897,7 +897,7 @@ ruy_cc_library(
   HDRS
     have_built_path_for.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     ${ruy_9_mavx_arch_AVX}
@@ -912,7 +912,7 @@ ruy_cc_library(
   HDRS
     kernel.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -942,7 +942,7 @@ ruy_cc_library(
   HDRS
     pack.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -982,7 +982,7 @@ ruy_cc_library(
   HDRS
     context.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   PUBLIC
@@ -1004,7 +1004,7 @@ ruy_cc_test(
   SRCS
     context_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1033,7 +1033,7 @@ ruy_cc_library(
     ctx.h
     ctx_impl.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1058,7 +1058,7 @@ ruy_cc_library(
   HDRS
     context_get_ctx.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1072,7 +1072,7 @@ ruy_cc_test(
   SRCS
     ctx_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1088,7 +1088,7 @@ ruy_cc_library(
   HDRS
     trmul_params.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1107,7 +1107,7 @@ ruy_cc_library(
   HDRS
     trmul.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1139,7 +1139,7 @@ ruy_cc_library(
   HDRS
     prepare_packed_matrices.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1158,7 +1158,7 @@ ruy_cc_library(
   HDRS
     create_trmul_params.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1183,7 +1183,7 @@ ruy_cc_library(
   HDRS
     validate.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1201,7 +1201,7 @@ ruy_cc_library(
   HDRS
     frontend.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1228,7 +1228,7 @@ ruy_cc_library(
     path.h
     ruy.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   PUBLIC
@@ -1252,7 +1252,7 @@ ruy_cc_test(
   SRCS
     perchannel_buffers_reallocation_test.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1274,7 +1274,7 @@ ruy_cc_library(
   HDRS
     pmu.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
@@ -1287,7 +1287,7 @@ ruy_cc_library(
   HDRS
     reference_mul.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   PUBLIC
@@ -1310,7 +1310,7 @@ ruy_cc_library(
   HDRS
     test.h
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   LINKOPTS
@@ -1340,7 +1340,7 @@ ruy_cc_binary(
   SRCS
     benchmark.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=f32
@@ -1359,7 +1359,7 @@ ruy_cc_binary(
   SRCS
     benchmark.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=u8
@@ -1378,7 +1378,7 @@ ruy_cc_binary(
   SRCS
     benchmark.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=i8
@@ -1397,7 +1397,7 @@ ruy_cc_binary(
   SRCS
     benchmark.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=i8
@@ -1416,7 +1416,7 @@ ruy_cc_binary(
   SRCS
     benchmark.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=u8
@@ -1435,7 +1435,7 @@ ruy_cc_binary(
   SRCS
     benchmark.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=i8
@@ -1447,13 +1447,51 @@ ruy_cc_binary(
     ruy_profiler_instrumentation
 )
 
+ruy_cc_binary(
+  NAME
+    ruy_benchmark_i8_i16_i32_i16
+  TESTONLY
+  SRCS
+    benchmark.cc
+  COPTS
+    ${ruy_0_Wall_Wextra_Wundef}
+    ${ruy_1_mfpu_neon}
+    ${ruy_2_O3}
+    -DRUY_TEST_LHSSCALAR=i8
+    -DRUY_TEST_RHSSCALAR=i16
+    -DRUY_TEST_ACCUMSCALAR=i32
+    -DRUY_TEST_DSTSCALAR=i16
+  DEPS
+    ruy_test_lib
+    ruy_profiler_instrumentation
+)
+
+ruy_cc_binary(
+  NAME
+    ruy_benchmark_i16_i8_i32_i16
+  TESTONLY
+  SRCS
+    benchmark.cc
+  COPTS
+    ${ruy_0_Wall_Wextra_Wundef}
+    ${ruy_1_mfpu_neon}
+    ${ruy_2_O3}
+    -DRUY_TEST_LHSSCALAR=i16
+    -DRUY_TEST_RHSSCALAR=i8
+    -DRUY_TEST_ACCUMSCALAR=i32
+    -DRUY_TEST_DSTSCALAR=i16
+  DEPS
+    ruy_test_lib
+    ruy_profiler_instrumentation
+)
+
 ruy_cc_test(
   NAME
     ruy_test_fast_f32_f32_f32_f32
   SRCS
     test_fast.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=f32
@@ -1471,7 +1509,7 @@ ruy_cc_test(
   SRCS
     test_fast.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=f64
@@ -1489,7 +1527,7 @@ ruy_cc_test(
   SRCS
     test_fast.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=f32
@@ -1507,7 +1545,7 @@ ruy_cc_test(
   SRCS
     test_fast.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=u8
@@ -1525,7 +1563,7 @@ ruy_cc_test(
   SRCS
     test_fast.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=i8
@@ -1543,7 +1581,7 @@ ruy_cc_test(
   SRCS
     test_fast.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=i8
@@ -1561,7 +1599,7 @@ ruy_cc_test(
   SRCS
     test_fast.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=u8
@@ -1579,7 +1617,7 @@ ruy_cc_test(
   SRCS
     test_fast.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=i8
@@ -1597,7 +1635,7 @@ ruy_cc_test(
   SRCS
     test_fast.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=i8
@@ -1609,13 +1647,49 @@ ruy_cc_test(
     gtest_main
 )
 
+ruy_cc_test(
+  NAME
+    ruy_test_fast_i8_i16_i32_i16
+  SRCS
+    test_fast.cc
+  COPTS
+    ${ruy_0_Wall_Wextra_Wundef}
+    ${ruy_1_mfpu_neon}
+    ${ruy_2_O3}
+    -DRUY_TEST_LHSSCALAR=i8
+    -DRUY_TEST_RHSSCALAR=i16
+    -DRUY_TEST_ACCUMSCALAR=i32
+    -DRUY_TEST_DSTSCALAR=i16
+  DEPS
+    ruy_test_lib
+    gtest_main
+)
+
+ruy_cc_test(
+  NAME
+    ruy_test_fast_i16_i8_i32_i16
+  SRCS
+    test_fast.cc
+  COPTS
+    ${ruy_0_Wall_Wextra_Wundef}
+    ${ruy_1_mfpu_neon}
+    ${ruy_2_O3}
+    -DRUY_TEST_LHSSCALAR=i16
+    -DRUY_TEST_RHSSCALAR=i8
+    -DRUY_TEST_ACCUMSCALAR=i32
+    -DRUY_TEST_DSTSCALAR=i16
+  DEPS
+    ruy_test_lib
+    gtest_main
+)
+
 ruy_cc_test(
   NAME
     ruy_test_slow_f32_f32_f32_f32
   SRCS
     test_slow.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=f32
@@ -1635,7 +1709,7 @@ ruy_cc_test(
   SRCS
     test_slow.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=u8
@@ -1655,7 +1729,7 @@ ruy_cc_test(
   SRCS
     test_slow.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=i8
@@ -1675,7 +1749,7 @@ ruy_cc_test(
   SRCS
     test_slow.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=u8
@@ -1695,7 +1769,7 @@ ruy_cc_test(
   SRCS
     test_slow.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
     -DRUY_TEST_LHSSCALAR=i8
@@ -1709,20 +1783,60 @@ ruy_cc_test(
     slow
 )
 
+ruy_cc_test(
+  NAME
+    ruy_test_slow_i8_i16_i32_i16
+  SRCS
+    test_slow.cc
+  COPTS
+    ${ruy_0_Wall_Wextra_Wundef}
+    ${ruy_1_mfpu_neon}
+    ${ruy_2_O3}
+    -DRUY_TEST_LHSSCALAR=i8
+    -DRUY_TEST_RHSSCALAR=i16
+    -DRUY_TEST_ACCUMSCALAR=i32
+    -DRUY_TEST_DSTSCALAR=i16
+  DEPS
+    ruy_test_lib
+    gtest_main
+  TAGS
+    slow
+)
+
+ruy_cc_test(
+  NAME
+    ruy_test_slow_i16_i8_i32_i16
+  SRCS
+    test_slow.cc
+  COPTS
+    ${ruy_0_Wall_Wextra_Wundef}
+    ${ruy_1_mfpu_neon}
+    ${ruy_2_O3}
+    -DRUY_TEST_LHSSCALAR=i16
+    -DRUY_TEST_RHSSCALAR=i8
+    -DRUY_TEST_ACCUMSCALAR=i32
+    -DRUY_TEST_DSTSCALAR=i16
+  DEPS
+    ruy_test_lib
+    gtest_main
+  TAGS
+    slow
+)
+
 ruy_cc_test(
   NAME
     ruy_test_overflow_dst_zero_point
   SRCS
     test_overflow_dst_zero_point.cc
   COPTS
-    ${ruy_0_Wall_Wcxx14_compat_Wextra_Wundef}
+    ${ruy_0_Wall_Wextra_Wundef}
     ${ruy_1_mfpu_neon}
     ${ruy_2_O3}
   DEPS
     ruy_gtest_wrapper
     ruy_matrix
-    ruy
     ruy_path
+    ruy
     ruy_test_lib
     ruy_tune
 )
diff --git a/ruy/allocator.cc b/ruy/allocator.cc
index 64da664..3b9bcf0 100644
--- a/ruy/allocator.cc
+++ b/ruy/allocator.cc
@@ -103,20 +103,24 @@ void Allocator::FreeAll() {
     return;
   }
 
-  // No rounding-up of the size means linear instead of logarithmic
+  // Free all memory before reallocating `ptr_`.
+  // This minimizes the memory high-water-mark.
+  detail::SystemAlignedFree(ptr_);
+  for (void* p : fallback_blocks_) {
+    detail::SystemAlignedFree(p);
+  }
+
+  // We reallocate to the exact new size, rather than growing
+  // exponentially like std::vector. This means linear instead of logarithmic
   // bound on the number of allocation in some worst-case calling patterns.
   // This is considered worth it because minimizing memory usage is important
   // and actual calling patterns in applications that we care about still
   // reach the no-further-allocations steady state in a small finite number
   // of iterations.
   std::ptrdiff_t new_size = size_ + fallback_blocks_total_size_;
-  detail::SystemAlignedFree(ptr_);
   ptr_ = detail::SystemAlignedAlloc(new_size);
   size_ = new_size;
 
-  for (void* p : fallback_blocks_) {
-    detail::SystemAlignedFree(p);
-  }
   fallback_blocks_.clear();
   fallback_blocks_total_size_ = 0;
 }
diff --git a/ruy/benchmark.cc b/ruy/benchmark.cc
index 3c63249..d551852 100644
--- a/ruy/benchmark.cc
+++ b/ruy/benchmark.cc
@@ -103,10 +103,20 @@ std::vector<int> ParseCommaSeparatedInts(
 }
 
 void Benchmark() {
+  // For now, support for int8*int16 cases is limited to the
+  // symmetric case (zero_point==0) because that appears to be
+  // the case in the initial use cases, and that limits complexity
+  // in thinking about accumulator overflows. This would not be a concern
+  // in the future if the accumulator type was int64, but for now its int32.
+  const bool is_int8_times_int16 =
+      (std::is_same<LhsScalar, std::int8_t>::value &&
+       std::is_same<RhsScalar, std::int16_t>::value) ||
+      (std::is_same<LhsScalar, std::int16_t>::value &&
+       std::is_same<RhsScalar, std::int8_t>::value);
   const bool symm_lhs = std::is_floating_point<LhsScalar>::value ||
-                        GetBoolEnvVarOrFalse("SYMM_LHS");
+                        is_int8_times_int16 || GetBoolEnvVarOrFalse("SYMM_LHS");
   const bool symm_rhs = std::is_floating_point<RhsScalar>::value ||
-                        GetBoolEnvVarOrFalse("SYMM_RHS");
+                        is_int8_times_int16 || GetBoolEnvVarOrFalse("SYMM_RHS");
   const bool benchmark_cubic = GetBoolEnvVarOrFalse("RUY_BENCHMARK_CUBIC") ||
                                GetBoolEnvVarOrFalse("RUY_BENCHMARK_CUBIC_LIST");
   const int explicit_rows = GetIntEnvVarOrZero("ROWS");
diff --git a/ruy/build_defs.bzl b/ruy/build_defs.bzl
index 836f47a..d7c6f21 100644
--- a/ruy/build_defs.bzl
+++ b/ruy/build_defs.bzl
@@ -4,7 +4,7 @@
 # Returns warnings flags to use for all ruy code.
 def ruy_copts_warnings():
     return select({
-        "@bazel_tools//src/conditions:windows": [
+        "//tools/cc_target_os:windows": [
             # We run into trouble on Windows toolchains with warning flags,
             # as mentioned in the comments below on each flag.
             # We could be more aggressive in enabling supported warnings on each
@@ -15,9 +15,6 @@ def ruy_copts_warnings():
             "-Wall",
             # Some clang-based Windows toolchains have more warnings in -Wextra.
             "-Wextra",
-            # TensorFlow is C++14 at the moment. This flag ensures that we warn
-            # on any code that isn't C++14, but MSVC does not support it.
-            "-Wc++14-compat",
             # Warn on preprocessor expansion of an undefined token, e.g. catching
             # typos such as `#ifdef __linus__` instead of `#ifdef __linux__`.
             # Not supported by MSVC.
@@ -57,14 +54,14 @@ def ruy_copts():
 def ruy_copts_avx():
     return select({
         "//ruy:x86_64_and_not_msvc": ["-mavx"],
-        "@bazel_tools//src/conditions:windows_msvc": ["/arch:AVX"],
+        "//tools/cc_target_os:windows_msvc": ["/arch:AVX"],
         "//conditions:default": [],
     })
 
 def ruy_copts_avx2_fma():
     return select({
         "//ruy:x86_64_and_not_msvc": ["-mavx2", "-mfma"],
-        "@bazel_tools//src/conditions:windows_msvc": ["/arch:AVX2"],
+        "//tools/cc_target_os:windows_msvc": ["/arch:AVX2"],
         "//conditions:default": [],
     })
 
@@ -74,6 +71,6 @@ def ruy_copts_avx512():
     # in optimized builds (-c opt).
     return select({
         "//ruy:x86_64_and_not_msvc": ["$(STACK_FRAME_UNLIMITED)", "-mavx512f", "-mavx512vl", "-mavx512cd", "-mavx512bw", "-mavx512dq"],
-        "@bazel_tools//src/conditions:windows_msvc": ["/arch:AVX512"],
+        "//tools/cc_target_os:windows_msvc": ["/arch:AVX512"],
         "//conditions:default": [],
     })
diff --git a/ruy/build_defs.oss.bzl b/ruy/build_defs.oss.bzl
index e405b41..6d34ba6 100644
--- a/ruy/build_defs.oss.bzl
+++ b/ruy/build_defs.oss.bzl
@@ -10,6 +10,6 @@ def ruy_linkopts_thread_standard_library():
     # with Bazel. Instead we do the following, which is copied from
     # https://github.com/abseil/abseil-cpp/blob/1112609635037a32435de7aa70a9188dcb591458/absl/base/BUILD.bazel#L155
     return select({
-        "@bazel_tools//src/conditions:windows": [],
+        "//tools/cc_target_os:windows": [],
         "//conditions:default": ["-pthread"],
     })
diff --git a/ruy/context.cc b/ruy/context.cc
index 342ce52..ec651f9 100644
--- a/ruy/context.cc
+++ b/ruy/context.cc
@@ -17,6 +17,7 @@ limitations under the License.
 
 #include "ruy/ctx.h"
 #include "ruy/ctx_impl.h"
+#include "ruy/strategy_controls.h"
 #include "ruy/path.h"
 #include "ruy/performance_advisory.h"
 #include "ruy/prepacked_cache.h"
@@ -44,6 +45,12 @@ int Context::max_num_threads() const { return ctx().max_num_threads(); }
 void Context::set_max_num_threads(int value) {
   mutable_ctx()->set_max_num_threads(value);
 }
+NumThreadsStrategy Context::num_threads_strategy() const {
+  return ctx().num_threads_strategy();
+}
+void Context::set_num_threads_strategy(NumThreadsStrategy strategy) {
+  mutable_ctx()->set_num_threads_strategy(strategy);
+}
 
 void Context::ClearPrepackedCache() { mutable_ctx()->ClearPrepackedCache(); }
 
diff --git a/ruy/context.h b/ruy/context.h
index f148f0f..16f40e7 100644
--- a/ruy/context.h
+++ b/ruy/context.h
@@ -28,6 +28,7 @@ class ThreadPool;
 enum class Path : std::uint8_t;
 enum class Tuning;
 enum class PerformanceAdvisory;
+enum class NumThreadsStrategy : std::uint8_t;
 
 // A Context holds runtime information used by Ruy. It holds runtime resources
 // such as the workers thread pool and the allocator (which holds buffers for
@@ -71,6 +72,10 @@ class Context final {
   int max_num_threads() const;
   void set_max_num_threads(int value);
 
+  // Controls the logic to determine how many threads to use.
+  NumThreadsStrategy num_threads_strategy() const;
+  void set_num_threads_strategy(NumThreadsStrategy strategy);
+
   // Returns true of the last ruy::Mul using this Context flagged the specified
   // `advisory`. This is reset by each ruy::Mul call.
   bool performance_advisory(PerformanceAdvisory advisory) const;
diff --git a/ruy/context_test.cc b/ruy/context_test.cc
index 4e69e65..6497c77 100644
--- a/ruy/context_test.cc
+++ b/ruy/context_test.cc
@@ -16,6 +16,7 @@ limitations under the License.
 #include "ruy/context.h"
 
 #include "ruy/gtest_wrapper.h"
+#include "ruy/strategy_controls.h"
 #include "ruy/path.h"
 #include "ruy/prepacked_cache.h"
 #include "ruy/tune.h"
@@ -30,10 +31,14 @@ TEST(ContextTest, ContextClassSanity) {
   EXPECT_EQ(&context.thread_pool(), context.mutable_thread_pool());
   EXPECT_NE(context.mutable_thread_pool(), nullptr);
   EXPECT_EQ(context.max_num_threads(), 1);
+  EXPECT_EQ(context.num_threads_strategy(), NumThreadsStrategy::kDefault);
   context.set_explicit_tuning(Tuning::kGeneric);
   context.set_max_num_threads(2);
+  context.set_num_threads_strategy(NumThreadsStrategy::kForceMaxNumThreads);
   EXPECT_EQ(context.explicit_tuning(), Tuning::kGeneric);
   EXPECT_EQ(context.max_num_threads(), 2);
+  EXPECT_EQ(context.num_threads_strategy(),
+            NumThreadsStrategy::kForceMaxNumThreads);
 }
 
 }  // namespace
diff --git a/ruy/cpuinfo.cc b/ruy/cpuinfo.cc
index a3e75d7..5daee0b 100644
--- a/ruy/cpuinfo.cc
+++ b/ruy/cpuinfo.cc
@@ -39,7 +39,7 @@ bool CpuInfo::EnsureInitialized() {
 }
 
 namespace {
-void QueryCacheParams(CpuCacheParams* cache_params) {
+bool QueryCacheParams(CpuCacheParams* cache_params) {
   const int processors_count = cpuinfo_get_processors_count();
   RUY_DCHECK_GT(processors_count, 0);
   int overall_local_cache_size = std::numeric_limits<int>::max();
@@ -56,11 +56,19 @@ void QueryCacheParams(CpuCacheParams* cache_params) {
         continue;  // continue, not break, it is possible to have L1+L3 but no
                    // L2.
       }
-      const bool is_local =
-          cpuinfo_get_processor(cache->processor_start)->core ==
-          cpuinfo_get_processor(cache->processor_start +
-                                cache->processor_count - 1)
-              ->core;
+      if (!cache->processor_count) {
+        // This may happen in a sand-boxed process, e.g.: a browser renderer.
+        continue;
+      }
+      const cpuinfo_processor* processor_start =
+          cpuinfo_get_processor(cache->processor_start);
+      const cpuinfo_processor* processor_end = cpuinfo_get_processor(
+          cache->processor_start + cache->processor_count - 1);
+      if (!processor_start || !processor_end) {
+        // This may happen in a sand-boxed process, e.g.: a browser renderer.
+        continue;
+      }
+      const bool is_local = processor_start->core == processor_end->core;
       if (is_local) {
         local_cache_size = cache->size;
       }
@@ -70,8 +78,9 @@ void QueryCacheParams(CpuCacheParams* cache_params) {
     if (!local_cache_size) {
       local_cache_size = last_level_cache_size;
     }
-    RUY_DCHECK_GT(local_cache_size, 0);
-    RUY_DCHECK_GT(last_level_cache_size, 0);
+    if (local_cache_size == 0 || last_level_cache_size == 0) {
+      return false;
+    }
     RUY_DCHECK_GE(last_level_cache_size, local_cache_size);
     overall_local_cache_size =
         std::min(overall_local_cache_size, local_cache_size);
@@ -80,6 +89,7 @@ void QueryCacheParams(CpuCacheParams* cache_params) {
   }
   cache_params->local_cache_size = overall_local_cache_size;
   cache_params->last_level_cache_size = overall_last_level_cache_size;
+  return true;
 }
 }  // end namespace
 
@@ -89,7 +99,10 @@ CpuInfo::InitStatus CpuInfo::Initialize() {
     MakeDummyCacheParams(&cache_params_);
     return InitStatus::kFailed;
   }
-  QueryCacheParams(&cache_params_);
+  if (!QueryCacheParams(&cache_params_)) {
+    MakeDummyCacheParams(&cache_params_);
+    return InitStatus::kFailed;
+  }
   return InitStatus::kInitialized;
 }
 
@@ -123,7 +136,12 @@ bool CpuInfo::CurrentCpuIsA55ish() {
     return false;
   }
 
-  switch (cpuinfo_get_uarch(cpuinfo_get_current_uarch_index())->uarch) {
+  const struct cpuinfo_uarch_info* cpuinfo_uarch =
+      cpuinfo_get_uarch(cpuinfo_get_current_uarch_index());
+  if (!cpuinfo_uarch) {
+    return false;
+  }
+  switch (cpuinfo_uarch->uarch) {
     case cpuinfo_uarch_cortex_a53:
     case cpuinfo_uarch_cortex_a55r0:
     case cpuinfo_uarch_cortex_a55:
@@ -137,8 +155,12 @@ bool CpuInfo::CurrentCpuIsX1() {
   if (!EnsureInitialized()) {
     return false;
   }
-  if (cpuinfo_get_uarch(cpuinfo_get_current_uarch_index())->uarch ==
-      cpuinfo_uarch_cortex_x1) {
+  const struct cpuinfo_uarch_info* cpuinfo_uarch =
+      cpuinfo_get_uarch(cpuinfo_get_current_uarch_index());
+  if (!cpuinfo_uarch) {
+    return false;
+  }
+  if (cpuinfo_uarch->uarch == cpuinfo_uarch_cortex_x1) {
     return true;
   }
   return false;
diff --git a/ruy/ctx.cc b/ruy/ctx.cc
index 0ef098d..5d6afd4 100644
--- a/ruy/ctx.cc
+++ b/ruy/ctx.cc
@@ -26,6 +26,7 @@ limitations under the License.
 #include "ruy/path.h"
 #include "ruy/performance_advisory.h"
 #include "ruy/platform.h"
+#include "ruy/strategy_controls.h"
 #include "ruy/prepacked_cache.h"
 #include "ruy/trace.h"
 
@@ -56,6 +57,12 @@ bool Ctx::performance_advisory(PerformanceAdvisory advisory) const {
   return (impl().performance_advisory_ & advisory) !=
          PerformanceAdvisory::kNone;
 }
+void Ctx::set_num_threads_strategy(NumThreadsStrategy strategy) {
+  mutable_impl()->num_threads_strategy_ = strategy;
+}
+NumThreadsStrategy Ctx::num_threads_strategy() const {
+  return impl().num_threads_strategy_;
+}
 
 void Ctx::SetRuntimeEnabledPaths(Path paths) {
   if (paths == Path::kNone) {
diff --git a/ruy/ctx.h b/ruy/ctx.h
index df9dee2..f576a90 100644
--- a/ruy/ctx.h
+++ b/ruy/ctx.h
@@ -32,6 +32,7 @@ class CpuInfo;
 enum class Path : std::uint8_t;
 enum class Tuning;
 enum class PerformanceAdvisory;
+enum class NumThreadsStrategy : std::uint8_t;
 
 // Ctx is the internal context class used throughout ruy code. Whereas Context
 // is exposed to users, Ctx is internal to ruy. As many of ruy's internal
@@ -53,6 +54,8 @@ class Ctx /* not final, subclassed by CtxImpl */ {
   void clear_performance_advisories();
   void set_performance_advisory(PerformanceAdvisory advisory);
   bool performance_advisory(PerformanceAdvisory advisory) const;
+  void set_num_threads_strategy(NumThreadsStrategy strategy);
+  NumThreadsStrategy num_threads_strategy() const;
 
   // Returns the set of Path's that are available. By default, this is based on
   // runtime detection of CPU features, as well as on which code paths were
diff --git a/ruy/ctx_impl.h b/ruy/ctx_impl.h
index 0a07ef6..be64553 100644
--- a/ruy/ctx_impl.h
+++ b/ruy/ctx_impl.h
@@ -29,6 +29,7 @@ limitations under the License.
 #include "ruy/path.h"
 #include "ruy/performance_advisory.h"
 #include "ruy/prepacked_cache.h"
+#include "ruy/strategy_controls.h"
 #include "ruy/thread_pool.h"
 #include "ruy/tune.h"
 
@@ -63,6 +64,7 @@ class CtxImpl final : public Ctx {
   Tuning explicit_tuning_ = Tuning::kAuto;
   ThreadPool thread_pool_;
   int max_num_threads_ = 1;
+  NumThreadsStrategy num_threads_strategy_ = NumThreadsStrategy::kDefault;
   // Allocator for main thread work before invoking the threadpool.
   // Our simple Allocator does not allow reserving/allocating more blocks
   // while it's already in committed state, so the main thread needs both
diff --git a/ruy/ctx_test.cc b/ruy/ctx_test.cc
index e55dcfc..c40f2d6 100644
--- a/ruy/ctx_test.cc
+++ b/ruy/ctx_test.cc
@@ -15,6 +15,7 @@ limitations under the License.
 
 #include "ruy/ctx_impl.h"
 #include "ruy/gtest_wrapper.h"
+#include "ruy/strategy_controls.h"
 #include "ruy/path.h"
 #include "ruy/platform.h"
 
@@ -67,6 +68,14 @@ TEST(ContextInternalTest, ThreadSpecificResources) {
   }
 }
 
+TEST(ContextInternalTest, SetNumThreadsStrategy) {
+  CtxImpl ctx;
+  EXPECT_EQ(ctx.num_threads_strategy(), NumThreadsStrategy::kDefault);
+  ctx.set_num_threads_strategy(NumThreadsStrategy::kForceMaxNumThreads);
+  EXPECT_EQ(ctx.num_threads_strategy(),
+            NumThreadsStrategy::kForceMaxNumThreads);
+}
+
 }  // namespace
 }  // namespace ruy
 
diff --git a/ruy/kernel_arm32.cc b/ruy/kernel_arm32.cc
index 8782dce..be0c267 100644
--- a/ruy/kernel_arm32.cc
+++ b/ruy/kernel_arm32.cc
@@ -282,16 +282,20 @@ void KernelFloat32Neon(const KernelParamsFloat<8, 4>& params) {
         // Let r8 be stack offset of the row or column variable, whichever
         // is the channel index.
         "tst r4, #" RUY_STR(RUY_ASM_FLAG_CHANNEL_DIMENSION_IS_COL) "\n"
-        "ite eq\n"
-        "moveq r8, #" RUY_STR(RUY_STACK_OFFSET_ROW) "\n"
-        "movne r8, #" RUY_STR(RUY_STACK_OFFSET_COL) "\n"
+        "bne 1000f\n"
+        "mov r8, #" RUY_STR(RUY_STACK_OFFSET_ROW) "\n"
+        "b 1001f\n"
+        "1000:\n"
+        "mov r8, #" RUY_STR(RUY_STACK_OFFSET_COL) "\n"
+        "1001:\n"
         // Let r8 be the channel index.
         "ldr r8, [sp, r8]\n"
         // Compute the bias pointer, by conditionally using the channel index
         // (r8) as offset into bias buffer (r1).
         "tst r4, #" RUY_STR(RUY_ASM_FLAG_HAS_BIAS) "\n"
-        "it ne\n"
-        "addne r1, r1, r8, lsl #2\n"
+        "beq 1002f\n"
+        "add r1, r1, r8, lsl #2\n"
+        "1002:\n"
 
         // Load 4 bias values. When the channel dimension is rows, we will load
         // another 4 bias values just before performing the bias addition below,
@@ -630,7 +634,8 @@ void Kernel8bitNeon(const KernelParams8bit<4, 2>& params) {
   CheckOffsetsInKernelParams8bit(params);
 
   const std::int8_t* lhs_col_ptr = params.lhs_base_ptr;
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   const std::int8_t* lhs_ptr = lhs_col_ptr;
   const std::int8_t* rhs_ptr = rhs_col_ptr;
 
@@ -895,16 +900,21 @@ void Kernel8bitNeon(const KernelParams8bit<4, 2>& params) {
         // Let r8 be stack offset of the row or column variable, whichever
         // is the channel index.
         "tst r4, #" RUY_STR(RUY_ASM_FLAG_CHANNEL_DIMENSION_IS_COL) "\n"
-        "ite eq\n"
-        "moveq r8, #" RUY_STR(RUY_STACK_OFFSET_ROW) "\n"
-        "movne r8, #" RUY_STR(RUY_STACK_OFFSET_COL) "\n"
+        "bne 1000f\n"
+        "mov r8, #" RUY_STR(RUY_STACK_OFFSET_ROW) "\n"
+        "b 1001f\n"
+        "1000:\n"
+        "mov r8, #" RUY_STR(RUY_STACK_OFFSET_COL) "\n"
+        "1001:\n"
+
         // Let r8 be the channel index.
         "ldr r8, [sp, r8]\n"
         // Compute the bias pointer, by conditionally using the channel index
         // (r8) as offset into bias buffer (r1).
         "tst r4, #" RUY_STR(RUY_ASM_FLAG_HAS_BIAS) "\n"
-        "it ne\n"
-        "addne r1, r1, r8, lsl #2\n"
+        "beq 1002f\n"
+        "add r1, r1, r8, lsl #2\n"
+        "1002:\n"
 
         // Load 2 bias values. When the channel dimension is rows, we will load
         // another 2 bias values just before performing the bias addition below,
@@ -1011,10 +1021,10 @@ void Kernel8bitNeon(const KernelParams8bit<4, 2>& params) {
         "ldr r2, [%[params], #" RUY_STR(RUY_OFFSET_MULTIPLIER_FIXEDPOINT) "]\n"
         // r6 has flags, r8 has channel index
         "tst r6, #" RUY_STR(RUY_ASM_FLAG_HAS_PERCHANNEL) "\n"
-        "it ne\n"
-        "addne r1, r1, r8, lsl #2\n"
-        "it ne\n"
-        "addne r2, r2, r8, lsl #2\n"
+        "beq 1003f\n"
+        "add r1, r1, r8, lsl #2\n"
+        "add r2, r2, r8, lsl #2\n"
+        "1003:\n"
 
         // Load the first 2 values of multiplier exponent and fixedpoint data
         // Since this kernel is rectangular 4x2, we will only conditionally load
@@ -1630,7 +1640,8 @@ void Kernel8bitNeon1Col(const KernelParams8bit<4, 2>& params) {
   CheckOffsetsInKernelParams8bit(params);
 
   const std::int8_t* lhs_col_ptr = params.lhs_base_ptr;
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   const std::int8_t* lhs_ptr = lhs_col_ptr;
   const std::int8_t* rhs_ptr = rhs_col_ptr;
 
@@ -1868,8 +1879,9 @@ void Kernel8bitNeon1Col(const KernelParams8bit<4, 2>& params) {
         "ldr r8, [sp, #" RUY_STR(RUY_STACK_OFFSET_ROW) "]\n"
 
         "tst r4, #" RUY_STR(RUY_ASM_FLAG_HAS_BIAS) "\n"
-        "it ne\n"
-        "addne r1, r1, r8, lsl #2\n"
+        "beq 1000f\n"
+        "add r1, r1, r8, lsl #2\n"
+        "1000:\n"
 
         // Load 4 bias values.
         "vld1.32 {d24, d25}, [r1]\n"
@@ -1956,8 +1968,9 @@ void Kernel8bitNeon1Col(const KernelParams8bit<4, 2>& params) {
         "ldr r1, [%[params], #" RUY_STR(RUY_OFFSET_MULTIPLIER_EXPONENT) "]\n"
         "tst r6, #" RUY_STR(RUY_ASM_FLAG_HAS_PERCHANNEL) "\n"
         "ldr r4, [sp, #" RUY_STR(RUY_STACK_OFFSET_ROW) "]\n"
-        "it ne\n"
-        "addne r1, r1, r4, lsl #2\n"
+        "beq 1001f\n"
+        "add r1, r1, r4, lsl #2\n"
+        "1001:\n"
 
         "vld1.32 {q10}, [r1]\n"
 
@@ -1972,8 +1985,9 @@ void Kernel8bitNeon1Col(const KernelParams8bit<4, 2>& params) {
         "ldr r1, [%[params], #" RUY_STR(RUY_OFFSET_MULTIPLIER_FIXEDPOINT) "]\n"
         // r6 has flags, r4 has row
         "tst r6, #" RUY_STR(RUY_ASM_FLAG_HAS_PERCHANNEL) "\n"
-        "it ne\n"
-        "addne r1, r1, r4, lsl #2\n"
+        "beq 1002f\n"
+        "add r1, r1, r4, lsl #2\n"
+        "1002:\n"
         "vld1.32 {q10}, [r1]\n" // multiplier_fixedpoint
 
         // Apply the fixed-point part of the multiplier.
diff --git a/ruy/kernel_arm64.cc b/ruy/kernel_arm64.cc
index 5424107..532138d 100644
--- a/ruy/kernel_arm64.cc
+++ b/ruy/kernel_arm64.cc
@@ -101,7 +101,8 @@ void Kernel8bitNeon(const KernelParams8bit<4, 4>& params) {
   CheckOffsetsInKernelParams8bit(params);
 
   const std::int8_t* lhs_col_ptr = params.lhs_base_ptr;
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   const std::int8_t* lhs_ptr = lhs_col_ptr;
   const std::int8_t* rhs_ptr = rhs_col_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
@@ -1160,7 +1161,8 @@ void Kernel8bitNeon1Col(const KernelParams8bit<4, 4>& params) {
   CheckOffsetsInKernelParams8bit(params);
 
   const std::int8_t* lhs_col_ptr = params.lhs_base_ptr;
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   const std::int8_t* lhs_ptr = lhs_col_ptr;
   const std::int8_t* rhs_ptr = rhs_col_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
@@ -1832,7 +1834,8 @@ void Kernel8bitNeonA55ish(const KernelParams8bit<4, 4>& params) {
   CheckOffsetsInKernelParams8bit(params);
 
   const std::int8_t* lhs_col_ptr = params.lhs_base_ptr;
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   const std::int8_t* lhs_ptr = lhs_col_ptr;
   const std::int8_t* rhs_ptr = rhs_col_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
@@ -2987,7 +2990,8 @@ void Kernel8bitNeonDotprod(const KernelParams8bit<8, 8>& params) {
   CheckOffsetsInKernelParams8bit(params);
 
   const std::int8_t* lhs_col_ptr = params.lhs_base_ptr;
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   const std::int8_t* lhs_ptr = lhs_col_ptr;
   const std::int8_t* rhs_ptr = rhs_col_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
@@ -4413,7 +4417,8 @@ void Kernel8bitNeonDotprodX1(const KernelParams8bit<8, 8>& params) {
   CheckOffsetsInKernelParams8bit(params);
 
   const std::int8_t* lhs_col_ptr = params.lhs_base_ptr;
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   const std::int8_t* lhs_ptr = lhs_col_ptr;
   const std::int8_t* rhs_ptr = rhs_col_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
@@ -5667,7 +5672,8 @@ void Kernel8bitNeonDotprod1Col(const KernelParams8bit<8, 8>& params) {
   CheckOffsetsInKernelParams8bit(params);
 
   const std::int8_t* lhs_col_ptr = params.lhs_base_ptr;
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   const std::int8_t* lhs_ptr = lhs_col_ptr;
   const std::int8_t* rhs_ptr = rhs_col_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
@@ -6362,7 +6368,8 @@ void Kernel8bitNeonDotprodA55ish(const KernelParams8bit<8, 8>& params) {
   CheckOffsetsInKernelParams8bit(params);
 
   const std::int8_t* lhs_col_ptr = params.lhs_base_ptr;
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   const std::int8_t* lhs_ptr = lhs_col_ptr;
   const std::int8_t* rhs_ptr = rhs_col_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
diff --git a/ruy/kernel_avx.cc b/ruy/kernel_avx.cc
index 2405735..0f7e2e3 100644
--- a/ruy/kernel_avx.cc
+++ b/ruy/kernel_avx.cc
@@ -462,7 +462,8 @@ void Kernel8bitAvxImpl(const KernelParams8bit<8, 8>& params) {
     RUY_DCHECK(false);
   }
 
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   void* dst_col_ptr = params.dst_base_ptr;
 
   for (int col = params.start_col; col <= params.last_col;
@@ -1184,7 +1185,8 @@ void Kernel8bitAvxSingleColImpl(const KernelParams8bit<8, 8>& params) {
   int bias_ptr_block_increment =
       params.flags & RUY_ASM_FLAG_HAS_BIAS ? kAvx8bitBlockSize : 0;
 
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const std::int8_t* rhs_col_ptr =
+      static_cast<const int8_t*>(params.rhs_base_ptr);
   void* dst_col_ptr = params.dst_base_ptr;
   const std::int32_t* bias_col_ptr = params.bias;
   if (params.flags & RUY_ASM_FLAG_HAS_BIAS) {
diff --git a/ruy/kernel_avx2_fma.cc b/ruy/kernel_avx2_fma.cc
index eae333c..e725777 100644
--- a/ruy/kernel_avx2_fma.cc
+++ b/ruy/kernel_avx2_fma.cc
@@ -121,7 +121,7 @@ void Kernel8bitAvx2Impl(const KernelParams8bit<8, 8>& params) {
     RUY_DCHECK(false);
   }
 
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const void* rhs_col_ptr = params.rhs_base_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
 
   for (int col = params.start_col; col <= params.last_col;
@@ -251,7 +251,7 @@ void Kernel8bitAvx2Impl(const KernelParams8bit<8, 8>& params) {
       }
 
       const std::int8_t* lhs_ptr = lhs_col_ptr;
-      const std::int8_t* rhs_ptr = rhs_col_ptr;
+      const void* rhs_ptr = rhs_col_ptr;
       for (int d = 0; d < params.depth; d += kAvx8bitInnerSize) {
         const __m256i lhs_data =
             _mm256_load_si256(reinterpret_cast<const __m256i*>(lhs_ptr));
@@ -259,21 +259,29 @@ void Kernel8bitAvx2Impl(const KernelParams8bit<8, 8>& params) {
             _mm256_load_si256(reinterpret_cast<const __m256i*>(rhs_ptr));
 
         // Each "int32" is two 16-bit RHS values, sign extended from 8-bit.
-        std::int32_t rhs_data[16];
-        const __m128i rhs_data_bottom_lane =
-            _mm256_castsi256_si128(rhs_data_8bit);
-        const __m128i rhs_data_top_lane =
-            _mm256_extracti128_si256(rhs_data_8bit, 1);
-        const __m256i rhs_16_bit_dup_low =
-            _mm256_cvtepi8_epi16(rhs_data_bottom_lane);
-        const __m256i rhs_16_bit_dup_high =
-            _mm256_cvtepi8_epi16(rhs_data_top_lane);
-        // Now that we have cast the RHS data, we store it so that each value
-        // can be separately loaded in the accumulation loop.
-        _mm256_storeu_si256(reinterpret_cast<__m256i*>(rhs_data),
-                            rhs_16_bit_dup_low);
-        _mm256_storeu_si256(reinterpret_cast<__m256i*>(rhs_data + 8),
-                            rhs_16_bit_dup_high);
+        std::int32_t rhs_data_buf[16];
+        const std::int32_t* rhs_data =
+            reinterpret_cast<const std::int32_t*>(rhs_ptr);
+
+        if (params.rhs_scalar_size == 1) {
+          rhs_data = rhs_data_buf;
+          const __m128i rhs_data_bottom_lane =
+              _mm256_castsi256_si128(rhs_data_8bit);
+          const __m128i rhs_data_top_lane =
+              _mm256_extracti128_si256(rhs_data_8bit, 1);
+          const __m256i rhs_16_bit_dup_low =
+              _mm256_cvtepi8_epi16(rhs_data_bottom_lane);
+          const __m256i rhs_16_bit_dup_high =
+              _mm256_cvtepi8_epi16(rhs_data_top_lane);
+          // Now that we have cast the RHS data, we store it so that each value
+          // can be separately loaded in the accumulation loop.
+          _mm256_storeu_si256(reinterpret_cast<__m256i*>(rhs_data_buf),
+                              rhs_16_bit_dup_low);
+          _mm256_storeu_si256(reinterpret_cast<__m256i*>(rhs_data_buf + 8),
+                              rhs_16_bit_dup_high);
+        } else {
+          RUY_DCHECK(params.rhs_scalar_size == 2);
+        }
 
         const __m256i lhs_data_split =
             _mm256_shuffle_epi8(lhs_data, splitter_idx);
@@ -339,7 +347,9 @@ void Kernel8bitAvx2Impl(const KernelParams8bit<8, 8>& params) {
         process_column(tmp2, tmp3, accum_data_v7);
 
         lhs_ptr += kAvx8bitBlockSize * kAvx8bitInnerSize;
-        rhs_ptr += kAvx8bitBlockSize * kAvx8bitInnerSize;
+        rhs_ptr = static_cast<const void*>(
+            static_cast<const char*>(rhs_ptr) +
+            kAvx8bitBlockSize * kAvx8bitInnerSize * params.rhs_scalar_size);
       }
 
       if (params.dst_type_id != DstTypeId<std::int32_t>::kValue) {
@@ -717,7 +727,9 @@ void Kernel8bitAvx2Impl(const KernelParams8bit<8, 8>& params) {
 
     dst_col_ptr = static_cast<void*>(static_cast<char*>(dst_col_ptr) +
                                      kAvx8bitBlockSize * params.dst_stride);
-    rhs_col_ptr += kAvx8bitBlockSize * params.rhs_stride;
+    rhs_col_ptr =
+        static_cast<const void*>(static_cast<const char*>(rhs_col_ptr) +
+                                 kAvx8bitBlockSize * params.rhs_stride);
   }  // End col-block loop.
 }  // NOLINT(readability/fn_size)
 
@@ -743,7 +755,7 @@ void Kernel8bitAvx2SingleColImpl(const KernelParams8bit<8, 8>& params) {
   int bias_ptr_block_increment =
       params.flags & RUY_ASM_FLAG_HAS_BIAS ? kAvx8bitBlockSize : 0;
 
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const void* rhs_col_ptr = params.rhs_base_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
   const std::int32_t* bias_col_ptr = params.bias;
   if (params.flags & RUY_ASM_FLAG_HAS_BIAS) {
@@ -807,20 +819,29 @@ void Kernel8bitAvx2SingleColImpl(const KernelParams8bit<8, 8>& params) {
     }
 
     const std::int8_t* lhs_ptr = lhs_col_ptr;
-    const std::int8_t* rhs_ptr = rhs_col_ptr;
+    const void* rhs_ptr = rhs_col_ptr;
     for (int d = 0; d < params.depth; d += kAvx8bitInnerSize) {
       const __m256i lhs_data =
           _mm256_load_si256(reinterpret_cast<const __m256i*>(lhs_ptr));
-      const __m128i rhs_data_8bit = intrin_utils::mm_loadu_si32<path>(rhs_ptr);
+      const std::int32_t* rhs_data =
+          reinterpret_cast<const std::int32_t*>(rhs_ptr);
 
       // Each "int32" is two 16-bit RHS values, sign extended from 8-bit.
       // For simplicity we load 4x the data that we need and process twice the
       // data  that we need  and store only the data we need.
-      std::int32_t rhs_data[2];
-      const __m128i rhs_16_bit_dup = _mm_cvtepi8_epi16(rhs_data_8bit);
-      // Now that we have cast the RHS data, we store it so that each value
-      // can be separately loaded in the accumulation loop.
-      _mm_storeu_si64(reinterpret_cast<__m128i*>(rhs_data), rhs_16_bit_dup);
+      std::int32_t rhs_data_buf[2];
+      if (params.rhs_scalar_size == 1) {
+        rhs_data = rhs_data_buf;
+        const __m128i rhs_data_8bit =
+            intrin_utils::mm_loadu_si32<path>(rhs_ptr);
+        const __m128i rhs_16_bit_dup = _mm_cvtepi8_epi16(rhs_data_8bit);
+        // Now that we have cast the RHS data, we store it so that each value
+        // can be separately loaded in the accumulation loop.
+        _mm_storeu_si64(reinterpret_cast<__m128i*>(rhs_data_buf),
+                        rhs_16_bit_dup);
+      } else {
+        RUY_DCHECK(params.rhs_scalar_size == 2);
+      }
 
       // NOTE: There may be opportunities for permuting the data in the packing
       // code instead of here.
@@ -851,7 +872,9 @@ void Kernel8bitAvx2SingleColImpl(const KernelParams8bit<8, 8>& params) {
           _mm256_madd_epi16(lhs_16_bit_high, rhs_16_bit_dup_high));
 
       lhs_ptr += kAvx8bitBlockSize * kAvx8bitInnerSize;
-      rhs_ptr += kAvx8bitBlockSize * kAvx8bitInnerSize;
+      rhs_ptr = static_cast<const void*>(static_cast<const char*>(rhs_ptr) +
+                                         kAvx8bitBlockSize * kAvx8bitInnerSize *
+                                             params.rhs_scalar_size);
     }
 
     if (params.dst_type_id != DstTypeId<std::int32_t>::kValue) {
@@ -989,7 +1012,8 @@ void Kernel8bitAvx2SingleColImpl(const KernelParams8bit<8, 8>& params) {
 
   dst_col_ptr = static_cast<void*>(static_cast<char*>(dst_col_ptr) +
                                    kAvx8bitBlockSize * params.dst_stride);
-  rhs_col_ptr += kAvx8bitBlockSize * params.rhs_stride;
+  rhs_col_ptr = static_cast<const void*>(static_cast<const char*>(rhs_col_ptr) +
+                                         kAvx8bitBlockSize * params.rhs_stride);
 }  // NOLINT(readability/fn_size)
 
 void Kernel8bitAvx2SingleCol(const KernelParams8bit<8, 8>& params) {
diff --git a/ruy/kernel_avx512.cc b/ruy/kernel_avx512.cc
index 84b9380..654ba27 100644
--- a/ruy/kernel_avx512.cc
+++ b/ruy/kernel_avx512.cc
@@ -67,7 +67,7 @@ void Kernel8bitAvx512(const KernelParams8bit<16, 16>& params) {
     RUY_DCHECK(false);
   }
 
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const void* rhs_col_ptr = params.rhs_base_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
 
   for (int col = params.start_col; col <= params.last_col; col += 16) {
@@ -247,27 +247,34 @@ void Kernel8bitAvx512(const KernelParams8bit<16, 16>& params) {
       }
 
       const std::int8_t* lhs_ptr = lhs_col_ptr;
-      const std::int8_t* rhs_ptr = rhs_col_ptr;
+      const void* rhs_ptr = rhs_col_ptr;
       for (int d = 0; d < params.depth; d += 4) {
         const __m512i lhs_data = _mm512_loadu_si512(lhs_ptr);
         __m512i rhs_data_8bit = _mm512_loadu_si512(rhs_ptr);
 
         // Each "int32" is two 16-bit RHS values, sign extended from 8-bit.
-        std::int32_t rhs_data[32];
-        const __m256i rhs_data_bottom_lane =
-            _mm512_castsi512_si256(rhs_data_8bit);
-        const __m256i rhs_data_top_lane =
-            _mm512_extracti32x8_epi32(rhs_data_8bit, 1);
-        const __m512i rhs_16_bit_dup_low =
-            _mm512_cvtepi8_epi16(rhs_data_bottom_lane);
-        const __m512i rhs_16_bit_dup_high =
-            _mm512_cvtepi8_epi16(rhs_data_top_lane);
-        // Now that we have cast the RHS data, we store it so that each value
-        // can be separately loaded in the accumulation loop.
-        _mm512_storeu_si512(reinterpret_cast<__m256i*>(rhs_data),
-                            rhs_16_bit_dup_low);
-        _mm512_storeu_si512(reinterpret_cast<__m256i*>(rhs_data + 16),
-                            rhs_16_bit_dup_high);
+        std::int32_t rhs_data_buf[32];
+        const std::int32_t* rhs_data =
+            reinterpret_cast<const std::int32_t*>(rhs_ptr);
+        if (params.rhs_scalar_size == 1) {
+          rhs_data = rhs_data_buf;
+          const __m256i rhs_data_bottom_lane =
+              _mm512_castsi512_si256(rhs_data_8bit);
+          const __m256i rhs_data_top_lane =
+              _mm512_extracti32x8_epi32(rhs_data_8bit, 1);
+          const __m512i rhs_16_bit_dup_low =
+              _mm512_cvtepi8_epi16(rhs_data_bottom_lane);
+          const __m512i rhs_16_bit_dup_high =
+              _mm512_cvtepi8_epi16(rhs_data_top_lane);
+          // Now that we have cast the RHS data, we store it so that each value
+          // can be separately loaded in the accumulation loop.
+          _mm512_storeu_si512(reinterpret_cast<__m256i*>(rhs_data_buf),
+                              rhs_16_bit_dup_low);
+          _mm512_storeu_si512(reinterpret_cast<__m256i*>(rhs_data_buf + 16),
+                              rhs_16_bit_dup_high);
+        } else {
+          RUY_DCHECK(params.rhs_scalar_size == 2);
+        }
 
         // Take bytes 0, 1, 4, 5, 8, 9, ... and expand to 16-bit.
         const __m512i lhs_16_bit_low =
@@ -305,7 +312,8 @@ void Kernel8bitAvx512(const KernelParams8bit<16, 16>& params) {
         process_column(15, accum_data_vf);
 
         lhs_ptr += 16 * 4;
-        rhs_ptr += 16 * 4;
+        rhs_ptr = static_cast<const void*>(static_cast<const char*>(rhs_ptr) +
+                                           16 * 4 * params.rhs_scalar_size);
       }
 
       if (params.dst_type_id != DstTypeId<std::int32_t>::kValue) {
@@ -612,7 +620,8 @@ void Kernel8bitAvx512(const KernelParams8bit<16, 16>& params) {
 
     dst_col_ptr = static_cast<void*>(static_cast<char*>(dst_col_ptr) +
                                      16 * params.dst_stride);
-    rhs_col_ptr += 16 * params.rhs_stride;
+    rhs_col_ptr = static_cast<const void*>(
+        static_cast<const char*>(rhs_col_ptr) + 16 * params.rhs_stride);
   }  // End col-block loop.
 }  // NOLINT(readability/fn_size)
 
@@ -625,7 +634,7 @@ void Kernel8bitAvx512SingleCol(const KernelParams8bit<16, 16>& params) {
 
   int bias_ptr_block_increment = params.flags & RUY_ASM_FLAG_HAS_BIAS ? 16 : 0;
 
-  const std::int8_t* rhs_col_ptr = params.rhs_base_ptr;
+  const void* rhs_col_ptr = params.rhs_base_ptr;
   void* dst_col_ptr = params.dst_base_ptr;
   const std::int32_t* bias_col_ptr = params.bias;
   if (params.flags & RUY_ASM_FLAG_HAS_BIAS) {
@@ -684,20 +693,28 @@ void Kernel8bitAvx512SingleCol(const KernelParams8bit<16, 16>& params) {
     }
 
     const std::int8_t* lhs_ptr = lhs_col_ptr;
-    const std::int8_t* rhs_ptr = rhs_col_ptr;
+    const void* rhs_ptr = rhs_col_ptr;
     for (int d = 0; d < params.depth; d += 4) {
       const __m512i lhs_data = _mm512_loadu_si512(lhs_ptr);
-      const __m128i rhs_data_8bit =
-          _mm_loadu_si128(reinterpret_cast<const __m128i*>(rhs_ptr));
+      const std::int32_t* rhs_data =
+          reinterpret_cast<const std::int32_t*>(rhs_ptr);
 
       // Each "int32" is two 16-bit RHS values, sign extended from 8-bit.
       // For simplicity we load 4x the data that we need and process twice the
       // data  that we need  and store only the data we need.
-      std::int32_t rhs_data[2];
-      const __m128i rhs_16_bit_dup = _mm_cvtepi8_epi16(rhs_data_8bit);
-      // Now that we have cast the RHS data, we store it so that each value
-      // can be separately loaded in the accumulation loop.
-      _mm_storeu_si64(reinterpret_cast<__m128i*>(rhs_data), rhs_16_bit_dup);
+      std::int32_t rhs_data_buf[2];
+      if (params.rhs_scalar_size == 1) {
+        rhs_data = rhs_data_buf;
+        const __m128i rhs_data_8bit =
+            _mm_loadu_si128(reinterpret_cast<const __m128i*>(rhs_ptr));
+        const __m128i rhs_16_bit_dup = _mm_cvtepi8_epi16(rhs_data_8bit);
+        // Now that we have cast the RHS data, we store it so that each value
+        // can be separately loaded in the accumulation loop.
+        _mm_storeu_si64(reinterpret_cast<__m128i*>(rhs_data_buf),
+                        rhs_16_bit_dup);
+      } else {
+        RUY_DCHECK(params.rhs_scalar_size == 2);
+      }
 
       // Take bytes 0, 1, 4, 5, 8, 9, ... and expand to 16-bit.
       const __m512i lhs_16_bit_low =
@@ -721,7 +738,8 @@ void Kernel8bitAvx512SingleCol(const KernelParams8bit<16, 16>& params) {
       accum_data_v0 = accum_v;
 
       lhs_ptr += 16 * 4;
-      rhs_ptr += 16 * 4;
+      rhs_ptr = static_cast<const void*>(static_cast<const char*>(rhs_ptr) +
+                                         16 * 4 * params.rhs_scalar_size);
     }
 
     if (params.dst_type_id != DstTypeId<std::int32_t>::kValue) {
diff --git a/ruy/kernel_common.h b/ruy/kernel_common.h
index cff243b..69e819b 100644
--- a/ruy/kernel_common.h
+++ b/ruy/kernel_common.h
@@ -101,7 +101,8 @@ struct KernelParams8bit {
   const std::int8_t* lhs_base_ptr;
   const std::int32_t* multiplier_fixedpoint;
   const std::int32_t* multiplier_exponent;
-  const std::int8_t* rhs_base_ptr;
+  // Make it void* to support 8bit(LHS)x16bit(RHS) case.
+  const void* rhs_base_ptr;
   void* dst_base_ptr;
   std::int32_t lhs_zero_point;
   std::int32_t rhs_zero_point;
@@ -125,11 +126,12 @@ struct KernelParams8bit {
   std::uint8_t dst_tmp_buf[LhsCols * RhsCols * kMaxDstTypeSize];
   std::int32_t multiplier_fixedpoint_buf[LhsCols];
   std::int32_t multiplier_exponent_buf[LhsCols];
+  std::size_t rhs_scalar_size;
 };
 
-template <typename DstScalar, int LhsCols, int RhsCols>
+template <typename RhsScalar, typename DstScalar, int LhsCols, int RhsCols>
 void MakeKernelParams8bit(const PMat<std::int8_t>& lhs,
-                          const PMat<std::int8_t>& rhs,
+                          const PMat<RhsScalar>& rhs,
                           const MulParams<std::int32_t, DstScalar>& mul_params,
                           int start_row, int start_col, int end_row,
                           int end_col, Mat<DstScalar>* dst,
@@ -145,6 +147,7 @@ void MakeKernelParams8bit(const PMat<std::int8_t>& lhs,
   RUY_DCHECK_EQ(end_col % RhsCols, 0);
 
   params->lhs_base_ptr = lhs.data + start_row * lhs.layout.stride;
+  params->rhs_scalar_size = sizeof(RhsScalar);
   params->rhs_base_ptr = rhs.data + start_col * rhs.layout.stride;
   params->flags = 0;
   params->bias = params->zero_data;
@@ -168,7 +171,7 @@ void MakeKernelParams8bit(const PMat<std::int8_t>& lhs,
   params->last_row = end_row - LhsCols;
   params->last_col = end_col - RhsCols;
   params->lhs_stride = lhs.layout.stride;
-  params->rhs_stride = rhs.layout.stride;
+  params->rhs_stride = params->rhs_scalar_size * rhs.layout.stride;
   params->dst_stride = sizeof(DstScalar) * dst->layout.stride;
   params->lhs_zero_point = lhs.zero_point;
   params->rhs_zero_point = rhs.zero_point;
diff --git a/ruy/kernel_x86.h b/ruy/kernel_x86.h
index b716502..51787b9 100644
--- a/ruy/kernel_x86.h
+++ b/ruy/kernel_x86.h
@@ -31,8 +31,8 @@ namespace ruy {
 
 #if RUY_PLATFORM_X86
 
-RUY_INHERIT_KERNEL(Path::kStandardCpp, Path::kAvx2Fma)
 RUY_INHERIT_KERNEL(Path::kStandardCpp, Path::kAvx)
+RUY_INHERIT_KERNEL(Path::kAvx, Path::kAvx2Fma)
 RUY_INHERIT_KERNEL(Path::kAvx2Fma, Path::kAvx512)
 
 void Kernel8bitAvx512(const KernelParams8bit<16, 16>& params);
@@ -60,6 +60,29 @@ struct Kernel<Path::kAvx512, std::int8_t, std::int8_t, std::int32_t, DstScalar>
   }
 };
 
+template <typename DstScalar>
+struct Kernel<Path::kAvx512, std::int8_t, std::int16_t, std::int32_t,
+              DstScalar> {
+  static constexpr Path kPath = Path::kAvx512;
+  Tuning tuning = Tuning::kAuto;
+  using LhsLayout = FixedKernelLayout<Order::kColMajor, 4, 16>;
+  using RhsLayout = FixedKernelLayout<Order::kColMajor, 4, 16>;
+  explicit Kernel(Tuning tuning_) : tuning(tuning_) {}
+  void Run(const PMat<std::int8_t>& lhs, const PMat<std::int16_t>& rhs,
+           const MulParams<std::int32_t, DstScalar>& mul_params, int start_row,
+           int start_col, int end_row, int end_col, Mat<DstScalar>* dst) const {
+    KernelParams8bit<LhsLayout::kCols, RhsLayout::kCols> params;
+    MakeKernelParams8bit(lhs, rhs, mul_params, start_row, start_col, end_row,
+                         end_col, dst, &params);
+    if (dst->layout.cols == 1 &&
+        mul_params.channel_dimension() == ChannelDimension::kRow) {
+      Kernel8bitAvx512SingleCol(params);
+    } else {
+      Kernel8bitAvx512(params);
+    }
+  }
+};
+
 void KernelFloatAvx512(const KernelParamsFloat<16, 16>& params);
 void KernelFloatAvx512SingleCol(const KernelParamsFloat<16, 16>& param);
 
@@ -111,6 +134,29 @@ struct Kernel<Path::kAvx2Fma, std::int8_t, std::int8_t, std::int32_t,
   }
 };
 
+template <typename DstScalar>
+struct Kernel<Path::kAvx2Fma, std::int8_t, std::int16_t, std::int32_t,
+              DstScalar> {
+  static constexpr Path kPath = Path::kAvx2Fma;
+  Tuning tuning = Tuning::kAuto;
+  using LhsLayout = FixedKernelLayout<Order::kColMajor, 4, 8>;
+  using RhsLayout = FixedKernelLayout<Order::kColMajor, 4, 8>;
+  explicit Kernel(Tuning tuning_) : tuning(tuning_) {}
+  void Run(const PMat<std::int8_t>& lhs, const PMat<std::int16_t>& rhs,
+           const MulParams<std::int32_t, DstScalar>& mul_params, int start_row,
+           int start_col, int end_row, int end_col, Mat<DstScalar>* dst) const {
+    KernelParams8bit<LhsLayout::kCols, RhsLayout::kCols> params;
+    MakeKernelParams8bit(lhs, rhs, mul_params, start_row, start_col, end_row,
+                         end_col, dst, &params);
+    if (dst->layout.cols == 1 &&
+        mul_params.channel_dimension() == ChannelDimension::kRow) {
+      Kernel8bitAvx2SingleCol(params);
+    } else {
+      Kernel8bitAvx2(params);
+    }
+  }
+};
+
 void KernelFloatAvx2(const KernelParamsFloat<8, 8>& params);
 void KernelFloatAvx2SingleCol(const KernelParamsFloat<8, 8>& params);
 
diff --git a/ruy/pack_arm.cc b/ruy/pack_arm.cc
index c337986..91f823b 100644
--- a/ruy/pack_arm.cc
+++ b/ruy/pack_arm.cc
@@ -1592,7 +1592,7 @@ void Pack8bitRowMajorForNeonDotprod(const void* src_ptr0, const void* src_ptr1,
                                     int packed_stride, std::int32_t* sums_ptr,
                                     int input_xor) {
   profiler::ScopeLabel label("Pack (kNeonDotprod, from row-major)");
-  asm(
+  asm volatile(
       // clang-format off
           // Prefetch data. This was tuned on Cortex-A55-rev1 cores.
           RUY_PREFETCH_LOAD("prfm pldl1strm, [%[src_ptr0]]\n")
diff --git a/ruy/pack_avx512.cc b/ruy/pack_avx512.cc
index 5281fa8..29a1850 100644
--- a/ruy/pack_avx512.cc
+++ b/ruy/pack_avx512.cc
@@ -38,6 +38,12 @@ void Pack8bitColMajorForAvx512(const std::int8_t*, std::int8_t,
   RUY_DCHECK(false);
 }
 
+void Pack16bitColMajorForAvx512(const std::int16_t*, const std::int16_t*, int,
+                                int, int, std::int16_t*, std::int32_t*) {
+  // CPU-ID-based checks should disable the path that would reach this point.
+  RUY_DCHECK(false);
+}
+
 void PackFloatColMajorForAvx512(const float*, const float*, int, int, int,
                                 float*) {
   // CPU-ID-based checks should disable the path that would reach this point.
@@ -56,20 +62,24 @@ void Pack8bitRowMajorForAvx512(const std::uint8_t*, int, int, std::int8_t*, int,
 using PackImpl8bitAvx512 =
     PackImpl<Path::kAvx512, FixedKernelLayout<Order::kColMajor, 4, 16>,
              std::int8_t, std::int8_t, std::int32_t, Order::kColMajor>;
+using PackImpl16bitAvx512 =
+    PackImpl<Path::kAvx512, FixedKernelLayout<Order::kColMajor, 4, 16>,
+             std::int16_t, std::int16_t, std::int32_t, Order::kColMajor>;
 
 namespace {
 
-inline void ZeroHalf8bitAvx512(int src_rows, std::int8_t packed_zero_point,
-                               std::int8_t* packed_ptr) {
-  using Layout = PackImpl8bitAvx512::Layout;
+template <typename PackImplAvx512, typename Scalar>
+inline void ZeroHalfAvx512(int src_rows, Scalar packed_zero_point,
+                           Scalar* packed_ptr, int chunked_row_mask) {
+  using Layout = typename PackImplAvx512::Layout;
   static constexpr int kHalfLayoutCols =
-      PackImpl8bitAvx512::kHalfLayoutCols;  // Half the number of cols in a
-                                            // block.
+      PackImplAvx512::kHalfLayoutCols;  // Half the number of cols in a
+                                        // block.
   RUY_DCHECK_EQ(kHalfLayoutCols, 8);
   RUY_DCHECK_EQ(Layout::kCols, 16);
   RUY_DCHECK_EQ(Layout::kRows, 4);
 
-  const int non_trailing_blocks = (src_rows & ~31) >> 2;
+  const int non_trailing_blocks = (src_rows & ~chunked_row_mask) >> 2;
   // This routine fills half blocks, and typically fills the second halves.
   // Thus packed_ptr is already offset by 8 * 4.
   for (int k = 0; k < non_trailing_blocks; ++k) {
@@ -79,8 +89,8 @@ inline void ZeroHalf8bitAvx512(int src_rows, std::int8_t packed_zero_point,
   }
 }
 
-inline __m512i LoaduTwo(const std::int8_t* addr_lo,
-                        const std::int8_t* addr_hi) {
+template <typename Scalar>
+inline __m512i LoaduTwo(const Scalar* addr_lo, const Scalar* addr_hi) {
   __m512i lower_filled = _mm512_castsi256_si512(
       _mm256_loadu_si256(reinterpret_cast<const __m256i*>(addr_lo)));
   return _mm512_inserti32x8(
@@ -98,6 +108,16 @@ inline __m512i MaskLoaduTwo(__mmask32 row_mask, const __m256i default_value_v,
       1);
 }
 
+inline __m512i MaskLoaduTwo(__mmask32 row_mask, const __m256i default_value_v,
+                            const std::int16_t* addr_lo,
+                            const std::int16_t* addr_hi) {
+  const __m512i lower_filled = _mm512_castsi256_si512(
+      _mm256_mask_loadu_epi16(default_value_v, row_mask, addr_lo));
+  return _mm512_inserti32x8(
+      lower_filled, _mm256_mask_loadu_epi16(default_value_v, row_mask, addr_hi),
+      1);
+}
+
 inline void HalfPack8bitAvx512(const std::int8_t* src_ptr,
                                std::int8_t input_xor,
                                const std::int8_t* zerobuf, int src_stride,
@@ -454,6 +474,193 @@ inline void HalfPack8bitAvx512(const std::int8_t* src_ptr,
   }
 }
 
+inline void HalfPack16bitAvx512(const std::int16_t* src_ptr,
+                                const std::int16_t* zerobuf, int src_stride,
+                                int remaining_src_cols, int src_rows,
+                                std::int16_t* packed_ptr,
+                                std::int32_t* sums_ptr,
+                                std::int16_t* trailing_buf) {
+  using Layout = PackImpl16bitAvx512::Layout;
+  RUY_DCHECK_EQ(Layout::kCols, 16);
+  RUY_DCHECK_EQ(Layout::kRows, 4);
+  // Each Layout::Rows is 4 contiguous input, contiguous packed elements.
+  // We process 4 of these chunks at a time, padding std::int16_t input chunks.
+  constexpr int kNumRowChunks = 4;
+  constexpr int kNumChunkedSrcRows = kNumRowChunks * Layout::kRows;
+
+  const std::int16_t* src_ptr0 = src_ptr;
+  const std::int16_t* src_ptr1 = src_ptr0 + src_stride;
+  const std::int16_t* src_ptr2 = src_ptr1 + src_stride;
+  const std::int16_t* src_ptr3 = src_ptr2 + src_stride;
+  const std::int16_t* src_ptr4 = src_ptr3 + src_stride;
+  const std::int16_t* src_ptr5 = src_ptr4 + src_stride;
+  const std::int16_t* src_ptr6 = src_ptr5 + src_stride;
+  const std::int16_t* src_ptr7 = src_ptr6 + src_stride;
+  std::int64_t src_inc0 = kNumChunkedSrcRows;
+  std::int64_t src_inc1 = kNumChunkedSrcRows;
+  std::int64_t src_inc2 = kNumChunkedSrcRows;
+  std::int64_t src_inc3 = kNumChunkedSrcRows;
+  std::int64_t src_inc4 = kNumChunkedSrcRows;
+  std::int64_t src_inc5 = kNumChunkedSrcRows;
+  std::int64_t src_inc6 = kNumChunkedSrcRows;
+  std::int64_t src_inc7 = kNumChunkedSrcRows;
+  // Handle cases where source does not have kHalfLayoutCols (8) columns.
+  if (remaining_src_cols < 8) {
+    if (remaining_src_cols <= 0) {
+      src_ptr0 = zerobuf;
+      src_inc0 = 0;
+    }
+    if (remaining_src_cols <= 1) {
+      src_ptr1 = zerobuf;
+      src_inc1 = 0;
+    }
+    if (remaining_src_cols <= 2) {
+      src_ptr2 = zerobuf;
+      src_inc2 = 0;
+    }
+    if (remaining_src_cols <= 3) {
+      src_ptr3 = zerobuf;
+      src_inc3 = 0;
+    }
+    if (remaining_src_cols <= 4) {
+      src_ptr4 = zerobuf;
+      src_inc4 = 0;
+    }
+    if (remaining_src_cols <= 5) {
+      src_ptr5 = zerobuf;
+      src_inc5 = 0;
+    }
+    if (remaining_src_cols <= 6) {
+      src_ptr6 = zerobuf;
+      src_inc6 = 0;
+    }
+    src_ptr7 = zerobuf;
+    src_inc7 = 0;
+  }
+
+  const std::int16_t zero_point = zerobuf[0];
+
+  if (sums_ptr) {
+    // i: kHalfLayoutCols.
+    for (int i = 0; i < 8; ++i) {
+      sums_ptr[i] = 0;
+    }
+  }
+  std::int32_t sums_adjustment = 0;
+  const __m512i ones_16bit = _mm512_set1_epi16(1);
+  __m512i sums_8x2_32bit = _mm512_set1_epi32(0);
+
+  // The overall packing effectively pads the source rows to
+  // (src_rows + 31) & ~31. The iteration over k may skip when m=1, and then we
+  // only pack for (src_rows + 15) & ~15. When there is an incomplete
+  // destination block, this is stored into trailing_buf instead of packed_ptr.
+  for (int k = 0; k < src_rows; k += 2 * kNumChunkedSrcRows) {
+    // m: {0, 1} for 2 chunks of rows.
+    for (int m = 0; m < 2; ++m) {
+      const int available_src_rows = src_rows - k - m * kNumChunkedSrcRows;
+
+      // Available source rows.
+      // If this is less than 0 (for m=1), we skip, having filled trailing
+      // buffer for m=0. Also, if source rows is zero on m=1, then we filled
+      // exactly to the end of the column in the packed buffer.
+      if (available_src_rows > 0) {
+        __m512i t0, t1, t2, t3;
+        __m512i r0, r1, r2, r3;
+        std::int16_t* dst_ptr = packed_ptr;
+
+        if (available_src_rows >= kNumChunkedSrcRows) {
+          t0 = LoaduTwo(src_ptr0, src_ptr4);
+          t1 = LoaduTwo(src_ptr1, src_ptr5);
+          t2 = LoaduTwo(src_ptr2, src_ptr6);
+          t3 = LoaduTwo(src_ptr3, src_ptr7);
+        } else {
+          RUY_DCHECK_LT(available_src_rows >> 2, kNumChunkedSrcRows);
+          // We do not care what goes into the trailing buffer, but we want
+          // in_data[...] == zero_point for irrelevant values in the summation.
+          //
+          // We compensate for padding-with-zero_point by initializing the
+          // summations with the compensating offset.
+          sums_adjustment +=
+              -(zero_point)*4 * (4 - ((available_src_rows + 3) >> 2));
+
+          const __m256i zero_point_v = _mm256_set1_epi16(zero_point);
+          const __mmask32 row_mask =
+              (static_cast<std::uint64_t>(1) << available_src_rows) - 1;
+
+          t0 = MaskLoaduTwo(row_mask, zero_point_v, src_ptr0, src_ptr4);
+          t1 = MaskLoaduTwo(row_mask, zero_point_v, src_ptr1, src_ptr5);
+          t2 = MaskLoaduTwo(row_mask, zero_point_v, src_ptr2, src_ptr6);
+          t3 = MaskLoaduTwo(row_mask, zero_point_v, src_ptr3, src_ptr7);
+          dst_ptr = trailing_buf;
+        }
+
+        r0 = _mm512_unpacklo_epi64(t0, t1);
+        r2 = _mm512_unpackhi_epi64(t0, t1);
+        r1 = _mm512_unpacklo_epi64(t2, t3);
+        r3 = _mm512_unpackhi_epi64(t2, t3);
+
+        r1 = _mm512_permutex_epi64(r1, 0x4e);
+        r3 = _mm512_permutex_epi64(r3, 0x4e);
+
+        t0 = _mm512_mask_blend_epi64(0xcc, r0, r1);
+        t1 = _mm512_mask_blend_epi64(0x33, r0, r1);
+        t2 = _mm512_mask_blend_epi64(0xcc, r2, r3);
+        t3 = _mm512_mask_blend_epi64(0x33, r2, r3);
+
+        t1 = _mm512_permutex_epi64(t1, 0x4e);
+        t3 = _mm512_permutex_epi64(t3, 0x4e);
+
+        _mm512_storeu_si512(reinterpret_cast<__m512i*>(dst_ptr + 0 * 16 * 4),
+                            t0);
+        _mm512_storeu_si512(reinterpret_cast<__m512i*>(dst_ptr + 2 * 16 * 4),
+                            t1);
+        _mm512_storeu_si512(reinterpret_cast<__m512i*>(dst_ptr + 1 * 16 * 4),
+                            t2);
+        _mm512_storeu_si512(reinterpret_cast<__m512i*>(dst_ptr + 3 * 16 * 4),
+                            t3);
+
+        if (sums_ptr) {
+          sums_8x2_32bit = _mm512_add_epi32(sums_8x2_32bit,
+                                            _mm512_madd_epi16(t0, ones_16bit));
+          sums_8x2_32bit = _mm512_add_epi32(sums_8x2_32bit,
+                                            _mm512_madd_epi16(t1, ones_16bit));
+          sums_8x2_32bit = _mm512_add_epi32(sums_8x2_32bit,
+                                            _mm512_madd_epi16(t2, ones_16bit));
+          sums_8x2_32bit = _mm512_add_epi32(sums_8x2_32bit,
+                                            _mm512_madd_epi16(t3, ones_16bit));
+        }
+      }
+
+      packed_ptr += 16 * kNumChunkedSrcRows;
+      src_ptr0 += src_inc0;
+      src_ptr1 += src_inc1;
+      src_ptr2 += src_inc2;
+      src_ptr3 += src_inc3;
+      src_ptr4 += src_inc4;
+      src_ptr5 += src_inc5;
+      src_ptr6 += src_inc6;
+      src_ptr7 += src_inc7;
+    }
+  }
+
+  if (sums_ptr) {
+    const __m256i sums_adjustment_v = _mm256_set1_epi32(sums_adjustment);
+
+    __m256i sums =
+        _mm256_loadu_si256(reinterpret_cast<const __m256i*>(sums_ptr));
+    const __m512i idx =
+        _mm512_set_epi32(15, 13, 11, 9, 7, 5, 3, 1, 14, 12, 10, 8, 6, 4, 2, 0);
+
+    const __m512i sums_2x8_32bit =
+        _mm512_permutexvar_epi32(idx, sums_8x2_32bit);
+    sums = _mm256_add_epi32(sums, sums_adjustment_v);
+    sums = _mm256_add_epi32(sums, _mm512_castsi512_si256(sums_2x8_32bit));
+    sums = _mm256_add_epi32(sums, _mm512_extracti32x8_epi32(sums_2x8_32bit, 1));
+
+    _mm256_storeu_si256(reinterpret_cast<__m256i*>(sums_ptr), sums);
+  }
+}
+
 inline __m512 LoaduTwo(const float* addr_lo, const float* addr_hi) {
   const __m512 lower_filled = _mm512_castps256_ps512(_mm256_loadu_ps(addr_lo));
   return _mm512_insertf32x8(lower_filled, _mm256_loadu_ps(addr_hi), 1);
@@ -658,6 +865,7 @@ void Pack8bitColMajorForAvx512(const std::int8_t* src_ptr,
       kNumRowChunks * Layout::kCols * Layout::kRows;
   std::int8_t trailing_buf[kTrailingBufSize];
   memset(trailing_buf, 0, kTrailingBufSize * sizeof(std::int8_t));
+  constexpr int kChunkedRowMask = kNumRowChunks * Layout::kRows - 1;
 
   std::int32_t* second_sums_ptr =
       sums_ptr ? sums_ptr + kHalfLayoutCols : nullptr;
@@ -674,8 +882,9 @@ void Pack8bitColMajorForAvx512(const std::int8_t* src_ptr,
     HalfPack8bitAvx512(src_ptr, input_xor, zerobuf, src_stride,
                        remaining_src_cols, src_rows, packed_ptr, sums_ptr,
                        trailing_buf);
-    ZeroHalf8bitAvx512(src_rows, zerobuf[0] ^ input_xor,
-                       packed_ptr + kHalfBlockOffset);
+    ZeroHalfAvx512<PackImpl8bitAvx512, std::int8_t>(
+        src_rows, zerobuf[0] ^ input_xor, packed_ptr + kHalfBlockOffset,
+        kChunkedRowMask);
     // The kernel may not need the second half-blocks sums to be set.
     if (second_sums_ptr) {
       for (int i = 0; i < kHalfLayoutCols; ++i) {
@@ -683,7 +892,6 @@ void Pack8bitColMajorForAvx512(const std::int8_t* src_ptr,
       }
     }
   }
-  constexpr int kChunkedRowMask = kNumRowChunks * Layout::kRows - 1;
   const bool trailing_data = (src_rows & kChunkedRowMask) > 0;
   // If the number of source rows is not a multiple of kChunkedRowMask, there
   // will be data in the trailing buffer,
@@ -697,6 +905,68 @@ void Pack8bitColMajorForAvx512(const std::int8_t* src_ptr,
   }
 }
 
+void Pack16bitColMajorForAvx512(const std::int16_t* src_ptr,
+                                const std::int16_t* zerobuf, int src_stride,
+                                int remaining_src_cols, int src_rows,
+                                std::int16_t* packed_ptr,
+                                std::int32_t* sums_ptr) {
+  profiler::ScopeLabel label("Pack kAvx512 16bit");
+
+  using Layout = PackImpl16bitAvx512::Layout;
+  constexpr int kHalfBlockOffset = 32;
+  RUY_DCHECK_EQ(kHalfBlockOffset * 2, Layout::kRows * Layout::kCols);
+  static constexpr int kHalfLayoutCols =
+      PackImpl16bitAvx512::kHalfLayoutCols;  // Half the number of cols in a
+                                             // block.
+  RUY_DCHECK_EQ(kHalfLayoutCols, 8);
+  RUY_DCHECK_EQ(Layout::kCols, 16);
+  RUY_DCHECK_EQ(Layout::kRows, 4);
+
+  // Each Layout::Rows is 4 contiguous input, contiguous packed elements.
+  // We process 8 of these chunks at a time, padding short input chunks.
+  constexpr int kNumRowChunks = 4;
+
+  // Each packed block is 4*16, and there are normally 8. The trailing block is
+  // only slightly shorter.
+  constexpr int kTrailingBufSize =
+      kNumRowChunks * Layout::kCols * Layout::kRows;
+  std::int16_t trailing_buf[kTrailingBufSize] = {0};
+  constexpr int kChunkedRowMask = kNumRowChunks * Layout::kRows - 1;
+
+  std::int32_t* second_sums_ptr =
+      sums_ptr ? sums_ptr + kHalfLayoutCols : nullptr;
+  if (remaining_src_cols > kHalfLayoutCols) {
+    HalfPack16bitAvx512(src_ptr, zerobuf, src_stride, remaining_src_cols,
+                        src_rows, packed_ptr, sums_ptr, trailing_buf);
+    HalfPack16bitAvx512(src_ptr + src_stride * kHalfLayoutCols, zerobuf,
+                        src_stride, remaining_src_cols - kHalfLayoutCols,
+                        src_rows, packed_ptr + kHalfBlockOffset,
+                        second_sums_ptr, trailing_buf + kHalfBlockOffset);
+  } else {
+    HalfPack16bitAvx512(src_ptr, zerobuf, src_stride, remaining_src_cols,
+                        src_rows, packed_ptr, sums_ptr, trailing_buf);
+    ZeroHalfAvx512<PackImpl16bitAvx512, std::int16_t>(
+        src_rows, zerobuf[0], packed_ptr + kHalfBlockOffset, kChunkedRowMask);
+    // The kernel may not need the second half-blocks sums to be set.
+    if (second_sums_ptr) {
+      for (int i = 0; i < kHalfLayoutCols; ++i) {
+        second_sums_ptr[i] = (zerobuf[0]) * ((src_rows + 3) & ~3);
+      }
+    }
+  }
+  const bool trailing_data = (src_rows & kChunkedRowMask) > 0;
+  // If the number of source rows is not a multiple of kChunkedRowMask, there
+  // will be data in the trailing buffer,
+  if (trailing_data) {
+    const int non_trailing_rows = src_rows & ~kChunkedRowMask;
+    // Destination "rows" are padded to next highest multiple of Layout::kRows.
+    const int dst_rows = (src_rows + 3) & ~3;
+    const int trailing_rows = dst_rows - non_trailing_rows;
+    memcpy(packed_ptr + Layout::kCols * non_trailing_rows, trailing_buf,
+           Layout::kCols * trailing_rows * sizeof(std::int16_t));
+  }
+}
+
 void PackFloatColMajorForAvx512(const float* src_ptr, const float* zerobuf,
                                 int src_stride, int remaining_src_cols,
                                 int src_rows, float* packed_ptr) {
diff --git a/ruy/pack_x86.h b/ruy/pack_x86.h
index f3ea54e..a28bbc9 100644
--- a/ruy/pack_x86.h
+++ b/ruy/pack_x86.h
@@ -16,6 +16,7 @@ limitations under the License.
 #ifndef RUY_RUY_PACK_X86_H_
 #define RUY_RUY_PACK_X86_H_
 
+#include <algorithm>
 #include <cstdint>
 #include <cstring>
 #include <type_traits>
@@ -271,6 +272,52 @@ struct PackImpl<Path::kAvx512, FixedKernelLayout<Order::kColMajor, 4, 16>,
   }
 };
 
+void Pack16bitColMajorForAvx512(const std::int16_t* src_ptr,
+                                const std::int16_t* zerobuf, int src_stride,
+                                int remaining_src_cols, int src_rows,
+                                std::int16_t* packed_ptr,
+                                std::int32_t* sums_ptr);
+
+template <>
+struct PackImpl<Path::kAvx512, FixedKernelLayout<Order::kColMajor, 4, 16>,
+                std::int16_t, std::int16_t, std::int32_t, Order::kColMajor> {
+  using Layout = FixedKernelLayout<Order::kColMajor, 4, 16>;
+  static constexpr int kHalfLayoutCols =
+      8;  // Half the number of cols in a block.
+
+  static void Run(Tuning, const Mat<std::int16_t>& src_matrix,
+                  PMat<std::int16_t>* packed_matrix, int start_col,
+                  int end_col) {
+    profiler::ScopeLabel label("Pack (AVX-512 16-bit)");
+
+    RUY_DCHECK(IsColMajor(src_matrix.layout));
+    RUY_DCHECK(IsColMajor(packed_matrix->layout));
+    RUY_DCHECK_EQ((end_col - start_col) % Layout::kCols, 0);
+    RUY_DCHECK_EQ(start_col % Layout::kCols, 0);
+    RUY_DCHECK_EQ(kHalfLayoutCols * 2, Layout::kCols);
+    std::int32_t* sums = packed_matrix->sums;
+    std::int16_t zerobuf[kHalfLayoutCols * Layout::kRows];
+    std::fill(zerobuf, zerobuf + kHalfLayoutCols * Layout::kRows,
+              static_cast<int16_t>(packed_matrix->zero_point));
+    for (int block_col = start_col; block_col < end_col;
+         block_col += Layout::kCols) {
+      std::int32_t* sums_ptr = sums ? sums + block_col : nullptr;
+      int src_stride = src_matrix.layout.stride;
+      const std::int16_t* src_ptr =
+          src_matrix.data.get() + src_stride * block_col;
+      int remaining_src_cols = src_matrix.layout.cols - block_col;
+
+      static constexpr int block_col_mask = ~(Layout::kCols - 1);
+      std::int16_t* packed_ptr =
+          packed_matrix->data +
+          packed_matrix->layout.stride * (block_col & block_col_mask);
+      Pack16bitColMajorForAvx512(src_ptr, zerobuf, src_stride,
+                                 remaining_src_cols, src_matrix.layout.rows,
+                                 packed_ptr, sums_ptr);
+    }
+  }
+};
+
 void PackFloatColMajorForAvx512(const float* src_ptr, const float* zerobuf,
                                 int src_stride, int remaining_src_cols,
                                 int src_rows, float* packed_ptr);
diff --git a/ruy/platform.h b/ruy/platform.h
index eb51931..9b67416 100644
--- a/ruy/platform.h
+++ b/ruy/platform.h
@@ -28,8 +28,11 @@ limitations under the License.
 // Detect APPLE.
 #ifdef __APPLE__
 #define RUY_PLATFORM_APPLE 1
+#include <TargetConditionals.h>
+#define RUY_PLATFORM_APPLE_IPHONE_SIMULATOR TARGET_IPHONE_SIMULATOR
 #else
 #define RUY_PLATFORM_APPLE 0
+#define RUY_PLATFORM_APPLE_IPHONE_SIMULATOR 0
 #endif
 
 // Detect APPLE.
@@ -108,11 +111,11 @@ limitations under the License.
 // Enable on sufficiently recent Android NDK. Earlier versions had broken
 // intrinsics headers.
 #define RUY_PLATFORM_X86_ENHANCEMENTS 1
-#elif defined(__linux__) && defined(__clang__) && (__clang_major__ >= 8)
-// Enable on recent versions of Clang on Linux. Might be possible
+#elif ((RUY_PLATFORM_APPLE && !RUY_PLATFORM_APPLE_IPHONE_SIMULATOR) || \
+       defined(__linux__)) &&                                          \
+    defined(__clang__) && (__clang_major__ >= 8)
+// Enable on recent versions of Clang. Might be possible
 // to relax this version requirement.
-// Not enabling on Apple at the moment because b/138922878, see comment #8, we
-// may only need to disable this on XCode <= 10.2.
 #define RUY_PLATFORM_X86_ENHANCEMENTS 1
 #elif defined(__GNUC__) && (__GNUC__ >= 9)
 // Enable on recent versions of GCC. Might be possible
diff --git a/ruy/profiler/BUILD b/ruy/profiler/BUILD
index 64754bf..7ec8e5f 100644
--- a/ruy/profiler/BUILD
+++ b/ruy/profiler/BUILD
@@ -3,6 +3,7 @@
 load("//ruy:build_defs.oss.bzl", "ruy_linkopts_thread_standard_library")
 
 package(
+    default_applicable_licenses = ["//third_party/ruy:license"],
     licenses = ["notice"],  # Apache 2.0
 )
 
diff --git a/ruy/strategy_controls.h b/ruy/strategy_controls.h
new file mode 100644
index 0000000..629c2b8
--- /dev/null
+++ b/ruy/strategy_controls.h
@@ -0,0 +1,34 @@
+/* Copyright 2022 Google LLC. All Rights Reserved.
+
+Licensed under the Apache License, Version 2.0 (the "License");
+you may not use this file except in compliance with the License.
+You may obtain a copy of the License at
+
+    http://www.apache.org/licenses/LICENSE-2.0
+
+Unless required by applicable law or agreed to in writing, software
+distributed under the License is distributed on an "AS IS" BASIS,
+WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+See the License for the specific language governing permissions and
+limitations under the License.
+==============================================================================*/
+
+#ifndef RUY_RUY_STRATEGY_CONTROLS_H_
+#define RUY_RUY_STRATEGY_CONTROLS_H_
+
+#include <cstdint>
+
+namespace ruy {
+
+enum class NumThreadsStrategy : std::uint8_t {
+  // kDefault means using smart heuristic logic that has been optimized
+  // for cubic ColxRowxDepth matrix multiplication.
+  kDefault,
+  // kForceMaxNumThreads means using ctx->max_num_thread()
+  // for multi-thread computing.
+  kForceMaxNumThreads
+};
+
+}  // namespace ruy
+
+#endif  // RUY_RUY_STRATEGY_CONTROLS_H_
diff --git a/ruy/test.h b/ruy/test.h
index 0b05399..6517519 100644
--- a/ruy/test.h
+++ b/ruy/test.h
@@ -1063,19 +1063,17 @@ void EvalEigenTensor(const Matrix<Scalar>& lhs, const Matrix<Scalar>& rhs,
                                                         : dst->layout().rows());
   using DimPair =
       typename Eigen::Tensor<Scalar, 1, 0, Eigen::Index>::DimensionPair;
-  Eigen::array<DimPair, 1> contract_dims(
+  Eigen::array<DimPair, 1> contract_dims{
       {DimPair((LhsOrder == Order::kColMajor) ? 1 : 0,
-               (RhsOrder == Order::kColMajor) ? 0 : 1)});
-  Eigen::array<int, 2> shuffle(DstOrder == Order::kColMajor ? 0 : 1,
-                               DstOrder == Order::kColMajor ? 1 : 0);
+               (RhsOrder == Order::kColMajor) ? 0 : 1)}};
   static Eigen::ThreadPool pool(max_num_threads ? max_num_threads : 1);
   static Eigen::ThreadPoolDevice device(&pool, pool.NumThreads());
   if (mul_params.bias()) {
     TensorBiasType tensor_bias(mul_params.bias(), dst->layout().rows());
-    Eigen::array<int, 2> bias_2d_shape(tr ? 1 : dst->layout().rows(),
-                                       tr ? dst->layout().rows() : 1);
-    Eigen::array<int, 2> bcast(tr ? dst->layout().cols() : 1,
-                               tr ? 1 : dst->layout().cols());
+    Eigen::array<int, 2> bias_2d_shape{tr ? 1 : dst->layout().rows(),
+                                       tr ? dst->layout().rows() : 1};
+    Eigen::array<int, 2> bcast{tr ? dst->layout().cols() : 1,
+                               tr ? 1 : dst->layout().cols()};
     if (mul_params.clamp_max() == std::numeric_limits<Scalar>::infinity() &&
         mul_params.clamp_min() == -std::numeric_limits<Scalar>::infinity()) {
       tensor_dst.device(device) =
@@ -1715,6 +1713,16 @@ template <typename LhsScalar, typename RhsScalar, typename AccumScalar,
           typename DstScalar>
 void TestSet<LhsScalar, RhsScalar, AccumScalar, DstScalar>::MakeZeroPoints() {
   RUY_CHECK_EQ(life_stage, LifeStage::kInitial);
+  if (std::is_same<LhsScalar, std::int16_t>::value ||
+      std::is_same<RhsScalar, std::int16_t>::value) {
+    // For now, support for int16 source types is limited to the
+    // symmetric case (zero_point==0) because that appears to be
+    // the case in the initial use cases, and that limits complexity
+    // in thinking about accumulator overflows.
+    // Setting use_specified_zero_points causes the default values 0 to be
+    // used unless explicitly overridden.
+    use_specified_zero_points = true;
+  }
   if (!benchmark && !use_specified_zero_points) {
     MakeRandomScalar(RandomRange::kReasonableSrcZeroPoint, &lhs_zero_point);
     MakeRandomScalar(RandomRange::kReasonableSrcZeroPoint, &rhs_zero_point);
@@ -1847,6 +1855,12 @@ void TestSet<LhsScalar, RhsScalar, AccumScalar, DstScalar>::MakeResultPaths() {
     paths_bitfield = get_ctx(&context)->GetRuntimeEnabledPaths();
   }
 
+  // Disable the internal test-only variants of the StandardCpp path in
+  // benchmarks
+  if (benchmark) {
+    paths_bitfield = paths_bitfield & kAllPaths;
+  }
+
   // Disable the internal test-only variants of the StandardCpp path on large
   // tests.
   // This constant be large enough to exercise some interesting BlockMap logic,
diff --git a/ruy/test_overflow_dst_zero_point.cc b/ruy/test_overflow_dst_zero_point.cc
index db1f08d..96ee38c 100644
--- a/ruy/test_overflow_dst_zero_point.cc
+++ b/ruy/test_overflow_dst_zero_point.cc
@@ -58,7 +58,7 @@ void TestOverflowingAdditionOfDestinationZeroPoint(ruy::Context* context,
                                      ? std::numeric_limits<DstScalar>::max()
                                      : std::numeric_limits<DstScalar>::min();
 
-  const std::vector<const std::int8_t> lhs_data(1, 0);
+  const std::vector<std::int8_t> lhs_data(1, 0);
   const std::vector<std::int8_t> rhs_data(cols, 0);
   std::vector<DstScalar> dst_data(cols, 0);
 
diff --git a/ruy/thread_pool.cc b/ruy/thread_pool.cc
index 5f22a13..2e2ca2c 100644
--- a/ruy/thread_pool.cc
+++ b/ruy/thread_pool.cc
@@ -34,135 +34,178 @@ namespace ruy {
 // A worker thread.
 class Thread {
  public:
-  enum class State {
-    Startup,  // The initial state before the thread main loop runs.
-    Ready,    // Is not working, has not yet received new work to do.
-    HasWork,  // Has work to do.
-    ExitAsSoonAsPossible  // Should exit at earliest convenience.
-  };
-
-  explicit Thread(BlockingCounter* counter_to_decrement_when_ready,
-                  Duration spin_duration)
-      : task_(nullptr),
-        state_(State::Startup),
-        counter_to_decrement_when_ready_(counter_to_decrement_when_ready),
+  explicit Thread(BlockingCounter* count_busy_threads, Duration spin_duration)
+      : state_(State::Startup),
+        count_busy_threads_(count_busy_threads),
         spin_duration_(spin_duration) {
     thread_.reset(new std::thread(ThreadFunc, this));
   }
 
+  void RequestExitAsSoonAsPossible() {
+    ChangeStateFromOutsideThread(State::ExitAsSoonAsPossible);
+  }
+
   ~Thread() {
-    ChangeState(State::ExitAsSoonAsPossible);
+    RUY_DCHECK_EQ(state_.load(), State::ExitAsSoonAsPossible);
     thread_->join();
   }
 
-  // Changes State; may be called from either the worker thread
-  // or the master thread; however, not all state transitions are legal,
-  // which is guarded by assertions.
+  // Called by an outside thead to give work to the worker thread.
+  void StartWork(Task* task) {
+    ChangeStateFromOutsideThread(State::HasWork, task);
+  }
+
+ private:
+  enum class State {
+    Startup,  // The initial state before the thread loop runs.
+    Ready,    // Is not working, has not yet received new work to do.
+    HasWork,  // Has work to do.
+    ExitAsSoonAsPossible  // Should exit at earliest convenience.
+  };
+
+  // Implements the state_ change to State::Ready, which is where we consume
+  // task_. Only called on the worker thread.
+  // Reads task_, so assumes ordering past any prior writes to task_.
+  void RevertToReadyState() {
+    RUY_TRACE_SCOPE_NAME("Worker thread task");
+    // See task_ member comment for the ordering of accesses.
+    if (task_) {
+      task_->Run();
+      task_ = nullptr;
+    }
+    // No need to notify state_cond_, since only the worker thread ever waits
+    // on it, and we are that thread.
+    // Relaxed order because ordering is already provided by the
+    // count_busy_threads_->DecrementCount() at the next line, since the next
+    // state_ mutation will be to give new work and that won't happen before
+    // the outside thread has finished the current batch with a
+    // count_busy_threads_->Wait().
+    state_.store(State::Ready, std::memory_order_relaxed);
+    count_busy_threads_->DecrementCount();
+  }
+
+  // Changes State, from outside thread.
   //
   // The Task argument is to be used only with new_state==HasWork.
   // It specifies the Task being handed to this Thread.
-  void ChangeState(State new_state, Task* task = nullptr) {
-    state_mutex_.lock();
-    State old_state = state_.load(std::memory_order_relaxed);
+  //
+  // new_task is only used with State::HasWork.
+  void ChangeStateFromOutsideThread(State new_state, Task* new_task = nullptr) {
+    RUY_DCHECK(new_state == State::ExitAsSoonAsPossible ||
+               new_state == State::HasWork);
+    RUY_DCHECK((new_task != nullptr) == (new_state == State::HasWork));
+
+#ifndef NDEBUG
+    // Debug-only sanity checks based on old_state.
+    State old_state = state_.load();
     RUY_DCHECK_NE(old_state, new_state);
-    switch (old_state) {
-      case State::Startup:
-        RUY_DCHECK_EQ(new_state, State::Ready);
-        break;
-      case State::Ready:
-        RUY_DCHECK(new_state == State::HasWork ||
-                   new_state == State::ExitAsSoonAsPossible);
-        break;
-      case State::HasWork:
-        RUY_DCHECK(new_state == State::Ready ||
-                   new_state == State::ExitAsSoonAsPossible);
-        break;
-      default:
-        abort();
-    }
+    RUY_DCHECK(old_state == State::Ready || old_state == State::HasWork);
+    RUY_DCHECK_NE(old_state, new_state);
+#endif
+
     switch (new_state) {
-      case State::Ready:
-        if (task_) {
-          // Doing work is part of reverting to 'ready' state.
-          task_->Run();
-          task_ = nullptr;
-        }
-        break;
       case State::HasWork:
+        // See task_ member comment for the ordering of accesses.
         RUY_DCHECK(!task_);
-        task_ = task;
+        task_ = new_task;
         break;
-      default:
+      case State::ExitAsSoonAsPossible:
         break;
+      default:
+        abort();
     }
-    state_.store(new_state, std::memory_order_relaxed);
-    state_cond_.notify_all();
-    state_mutex_.unlock();
-    if (new_state == State::Ready) {
-      counter_to_decrement_when_ready_->DecrementCount();
-    }
+    // Release order because the worker thread will read this with acquire
+    // order.
+    state_.store(new_state, std::memory_order_release);
+    state_cond_mutex_.lock();
+    state_cond_.notify_one();  // Only this one worker thread cares.
+    state_cond_mutex_.unlock();
   }
 
   static void ThreadFunc(Thread* arg) { arg->ThreadFuncImpl(); }
 
-  // Called by the master thead to give this thread work to do.
-  void StartWork(Task* task) { ChangeState(State::HasWork, task); }
+  // Waits for state_ to be different from State::Ready, and returns that
+  // new value.
+  State GetNewStateOtherThanReady() {
+    State new_state;
+    const auto& new_state_not_ready = [this, &new_state]() {
+      new_state = state_.load(std::memory_order_acquire);
+      return new_state != State::Ready;
+    };
+    RUY_TRACE_INFO(THREAD_FUNC_IMPL_WAITING);
+    Wait(new_state_not_ready, spin_duration_, &state_cond_, &state_cond_mutex_);
+    return new_state;
+  }
 
- private:
   // Thread entry point.
   void ThreadFuncImpl() {
     RUY_TRACE_SCOPE_NAME("Ruy worker thread function");
-    ChangeState(State::Ready);
+    RevertToReadyState();
 
     // Suppress denormals to avoid computation inefficiency.
     ScopedSuppressDenormals suppress_denormals;
 
-    // Thread main loop
-    while (true) {
-      RUY_TRACE_SCOPE_NAME("Ruy worker thread loop iteration");
-      // In the 'Ready' state, we have nothing to do but to wait until
-      // we switch to another state.
-      const auto& condition = [this]() {
-        return state_.load(std::memory_order_acquire) != State::Ready;
-      };
-      RUY_TRACE_INFO(THREAD_FUNC_IMPL_WAITING);
-      Wait(condition, spin_duration_, &state_cond_, &state_mutex_);
-
-      // Act on new state.
-      switch (state_.load(std::memory_order_acquire)) {
-        case State::HasWork: {
-          RUY_TRACE_SCOPE_NAME("Worker thread task");
-          // Got work to do! So do it, and then revert to 'Ready' state.
-          ChangeState(State::Ready);
-          break;
-        }
-        case State::ExitAsSoonAsPossible:
-          return;
-        default:
-          abort();
-      }
+    // Thread loop
+    while (GetNewStateOtherThanReady() == State::HasWork) {
+      RevertToReadyState();
     }
+
+    // Thread end. We should only get here if we were told to exit.
+    RUY_DCHECK(state_.load() == State::ExitAsSoonAsPossible);
   }
 
-  // The underlying thread.
+  // The underlying thread. Used to join on destruction.
   std::unique_ptr<std::thread> thread_;
 
   // The task to be worked on.
-  Task* task_;
+  //
+  // The ordering of reads and writes to task_ is as follows.
+  //
+  // 1. The outside thread gives new work by calling
+  //      ChangeStateFromOutsideThread(State::HasWork, new_task);
+  //    That does:
+  //    - a. Write task_ = new_task (non-atomic).
+  //    - b. Store state_ = State::HasWork (memory_order_release).
+  // 2. The worker thread picks up the new state by calling
+  //      GetNewStateOtherThanReady()
+  //    That does:
+  //    - c. Load state (memory_order_acquire).
+  //    The worker thread then reads the new task in RevertToReadyState().
+  //    That does:
+  //    - d. Read task_ (non-atomic).
+  // 3. The worker thread, still in RevertToReadyState(), consumes the task_ and
+  //    does:
+  //    - e. Write task_ = nullptr (non-atomic).
+  //    And then calls Call count_busy_threads_->DecrementCount()
+  //    which does
+  //    - f. Store count_busy_threads_ (memory_order_release).
+  // 4. The outside thread, in ThreadPool::ExecuteImpl, finally waits for worker
+  //    threads by calling count_busy_threads_->Wait(), which does:
+  //    - g. Load count_busy_threads_ (memory_order_acquire).
+  //
+  // Thus the non-atomic write-then-read accesses to task_ (a. -> d.) are
+  // ordered by the release-acquire relationship of accesses to state_ (b. ->
+  // c.), and the non-atomic write accesses to task_ (e. -> a.) are ordered by
+  // the release-acquire relationship of accesses to count_busy_threads_ (f. ->
+  // g.).
+  Task* task_ = nullptr;
 
-  // The condition variable and mutex guarding state changes.
+  // Condition variable used by the outside thread to notify the worker thread
+  // of a state change.
   std::condition_variable state_cond_;
-  std::mutex state_mutex_;
+
+  // Mutex used to guard state_cond_
+  std::mutex state_cond_mutex_;
 
   // The state enum tells if we're currently working, waiting for work, etc.
-  // Its concurrent accesses by the thread and main threads are guarded by
-  // state_mutex_, and can thus use memory_order_relaxed. This still needs
-  // to be a std::atomic because we use WaitForVariableChange.
+  // It is written to from either the outside thread or the worker thread,
+  // in the ChangeState method.
+  // It is only ever read by the worker thread.
   std::atomic<State> state_;
 
   // pointer to the master's thread BlockingCounter object, to notify the
   // master thread of when this thread switches to the 'Ready' state.
-  BlockingCounter* const counter_to_decrement_when_ready_;
+  BlockingCounter* const count_busy_threads_;
 
   // See ThreadPool::spin_duration_.
   const Duration spin_duration_;
@@ -180,7 +223,7 @@ void ThreadPool::ExecuteImpl(int task_count, int stride, Task* tasks) {
 
   // Task #0 will be run on the current thread.
   CreateThreads(task_count - 1);
-  counter_to_decrement_when_ready_.Reset(task_count - 1);
+  count_busy_threads_.Reset(task_count - 1);
   for (int i = 1; i < task_count; i++) {
     RUY_TRACE_INFO(THREADPOOL_EXECUTE_STARTING_TASK);
     auto task_address = reinterpret_cast<std::uintptr_t>(tasks) + i * stride;
@@ -193,7 +236,7 @@ void ThreadPool::ExecuteImpl(int task_count, int stride, Task* tasks) {
 
   RUY_TRACE_INFO(THREADPOOL_EXECUTE_WAITING_FOR_THREADS);
   // Wait for the threads submitted above to finish.
-  counter_to_decrement_when_ready_.Wait(spin_duration_);
+  count_busy_threads_.Wait(spin_duration_);
 }
 
 // Ensures that the pool has at least the given count of threads.
@@ -205,15 +248,18 @@ void ThreadPool::CreateThreads(int threads_count) {
   if (threads_.size() >= unsigned_threads_count) {
     return;
   }
-  counter_to_decrement_when_ready_.Reset(threads_count - threads_.size());
+  count_busy_threads_.Reset(threads_count - threads_.size());
   while (threads_.size() < unsigned_threads_count) {
-    threads_.push_back(
-        new Thread(&counter_to_decrement_when_ready_, spin_duration_));
+    threads_.push_back(new Thread(&count_busy_threads_, spin_duration_));
   }
-  counter_to_decrement_when_ready_.Wait(spin_duration_);
+  count_busy_threads_.Wait(spin_duration_);
 }
 
 ThreadPool::~ThreadPool() {
+  // Send all exit requests upfront so threads can work on them in parallel.
+  for (auto w : threads_) {
+    w->RequestExitAsSoonAsPossible();
+  }
   for (auto w : threads_) {
     delete w;
   }
diff --git a/ruy/thread_pool.h b/ruy/thread_pool.h
index e3b6803..946be3d 100644
--- a/ruy/thread_pool.h
+++ b/ruy/thread_pool.h
@@ -98,12 +98,12 @@ class ThreadPool {
   // copy construction disallowed
   ThreadPool(const ThreadPool&) = delete;
 
-  // The threads in this pool. They are owned by the pool:
+  // The worker threads in this pool. They are owned by the pool:
   // the pool creates threads and destroys them in its destructor.
   std::vector<Thread*> threads_;
 
   // The BlockingCounter used to wait for the threads.
-  BlockingCounter counter_to_decrement_when_ready_;
+  BlockingCounter count_busy_threads_;
 
   // This value was empirically derived with some microbenchmark, we don't have
   // high confidence in it.
diff --git a/ruy/trmul.cc b/ruy/trmul.cc
index 602660b..2ff519f 100644
--- a/ruy/trmul.cc
+++ b/ruy/trmul.cc
@@ -21,6 +21,7 @@ limitations under the License.
 #include <atomic>
 #include <cstdint>
 #include <cstring>
+#include <limits>
 #include <memory>
 #include <vector>
 
@@ -34,6 +35,7 @@ limitations under the License.
 #include "ruy/mat.h"
 #include "ruy/matrix.h"
 #include "ruy/mul_params.h"
+#include "ruy/strategy_controls.h"
 #include "ruy/opt_set.h"
 #include "ruy/profiler/instrumentation.h"
 #include "ruy/side_pair.h"
@@ -256,12 +258,28 @@ int GetTentativeThreadCount(Ctx* ctx, int rows, int cols, int depth) {
   // Empirically determined rule for reasonable number of
   // threads to use. This is proportional to the number of arithmetic ops
   // in this Mul (product of the 3 sizes).
-  static constexpr int kDivisorLog2 = 15;
-  const int guess_log2 = std::max(
-      0, ceil_log2(rows) + ceil_log2(cols) + ceil_log2(depth) - kDivisorLog2);
-  int tentative_thread_count =
-      std::min(1 << guess_log2, ctx->max_num_threads());
-  RUY_TRACE_INFO(GET_TENTATIVE_THREAD_COUNT);
+  // Be defensive here by explicitly promoting operands to int64 to avoid the
+  // pitfall of `int64 result = x * y;` overflowing as x and y are still narrow.
+  if (ctx->num_threads_strategy() == NumThreadsStrategy::kForceMaxNumThreads) {
+    return ctx->max_num_threads();
+  }
+  RUY_CHECK_EQ(ctx->num_threads_strategy(), NumThreadsStrategy::kDefault);
+  const std::int64_t rows_i64 = rows;
+  const std::int64_t cols_i64 = cols;
+  const std::int64_t depth_i64 = depth;
+  const std::int64_t problem_size = rows_i64 * cols_i64 * depth_i64;
+  // Division is cheap when the denominator is constant
+  static constexpr std::int64_t kSizePerAdditionalThread = 32768;
+  std::int64_t tentative_thread_count = problem_size / kSizePerAdditionalThread;
+  // tentative_thread_count is still an int64, still not necessarily in the
+  // range of type int. It probably is as long as kSizePerAdditionalThread is
+  // large, but imagine that that constant might change in the future.
+  tentative_thread_count = std::max<std::int64_t>(tentative_thread_count, 1);
+  tentative_thread_count =
+      std::min<std::int64_t>(tentative_thread_count, ctx->max_num_threads());
+  // now tentative_thread_count must be in the range of type int, because
+  // ctx->max_num_threads() is.
+  RUY_DCHECK_LE(tentative_thread_count, std::numeric_limits<int>::max());
   return tentative_thread_count;
 }
 
@@ -377,20 +395,22 @@ void TrMul(Ctx* ctx, TrMulParams* params) {
   // reservation granule.
   std::atomic<int>* atomic_block_id;
   main_allocator->Allocate(1, &atomic_block_id);
-
-  // Create task objects.
-  TrMulTask* tasks;
-  main_allocator->Allocate(thread_count, &tasks);
-
   atomic_block_id->store(thread_count);
 
+  // Create task objects. We allocate a single buffer and then use placement-new
+  // to construct N TrMulTask objects within it. To avoid having the Clang CFI
+  // sanitizer complain about a TrMulTask* pointer temporarily pointing to
+  // garbage, we keep the pointer a plain char* until finished constructing.
+  char* tasks_buf =
+      main_allocator->Allocate<char>(thread_count * sizeof(TrMulTask));
   for (int i = 0; i < thread_count; i++) {
     auto* allocator = ctx->GetThreadSpecificAllocator(i);
     auto* tuning_resolver = ctx->GetThreadSpecificTuningResolver(i);
-    new (tasks + i) TrMulTask(params, block_map, atomic_block_id, i,
-                              need_atomics, packing_status, tuning_resolver,
-                              allocator, ctx->mutable_cpuinfo());
+    new (tasks_buf + i * sizeof(TrMulTask)) TrMulTask(
+        params, block_map, atomic_block_id, i, need_atomics, packing_status,
+        tuning_resolver, allocator, ctx->mutable_cpuinfo());
   }
+  TrMulTask* tasks = reinterpret_cast<TrMulTask*>(tasks_buf);
 
   // Do the computation.
   ctx->mutable_thread_pool()->Execute(thread_count, tasks);
diff --git a/ruy/validate.h b/ruy/validate.h
index b164530..c19cf67 100644
--- a/ruy/validate.h
+++ b/ruy/validate.h
@@ -44,6 +44,18 @@ void ValidateZeroPoints(LhsScalar lhs_zero_point, RhsScalar rhs_zero_point,
   CheckZeroPoint(rhs_zero_point);
   CheckZeroPoint(dst_zero_point);
 
+  // For now, support for int16 source types is limited to the
+  // symmetric case (zero_point==0) because that appears to be
+  // the case in the initial use cases, and that limits complexity
+  // in thinking about accumulator overflows.
+  const bool has_16bit_input = std::is_same<LhsScalar, std::int16_t>::value ||
+                               std::is_same<RhsScalar, std::int16_t>::value;
+  if (has_16bit_input) {
+    RUY_DCHECK(!lhs_zero_point);
+    RUY_DCHECK(!rhs_zero_point);
+    RUY_DCHECK(!dst_zero_point);
+  }
+
   // Guard against the case when both LHS and RHS zero_point's are equal to
   // the minimum representable value. In that case, padding with zero_point
   // values will generate the bad case for fast int8 kernels on NEON
```

