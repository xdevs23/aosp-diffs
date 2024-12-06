```diff
diff --git a/bazel.WORKSPACE b/bazel.WORKSPACE
index 2c666390..b922169c 100644
--- a/bazel.WORKSPACE
+++ b/bazel.WORKSPACE
@@ -17,15 +17,18 @@ load("//build/bazel/rules:api_surfaces_injection.bzl", "api_surfaces_repository"
 # TODO: Once BUILD files for stubs are checked-in, this should be converted to a local_repository.
 api_surfaces_repository(name = "api_surfaces")
 
-load("//build/bazel_common_rules/workspace:external.bzl", "import_external_repositories")
-
-import_external_repositories(
-    bazel_skylib = True,
-    io_abseil_py = True,
+local_repository(
+    name = "bazel_skylib",
+    path = "external/bazel-skylib",
 )
 
 load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")
 
+local_repository(
+    name = "io_abseil_py",
+    path = "external/python/absl-py",
+)
+
 bazel_skylib_workspace()
 
 local_repository(
@@ -139,8 +142,8 @@ local_repository(
 )
 
 register_toolchains(
-    "//prebuilts/jdk/jdk17:runtime_toolchain_definition",
-    "//build/bazel/rules/java:jdk17_host_toolchain_java_definition",
+    "//prebuilts/jdk/jdk21:runtime_toolchain_definition",
+    "//build/bazel/rules/java:jdk21_host_toolchain_java_definition",
 )
 
 local_repository(
diff --git a/bin/bazel b/bin/bazel
index f58bf6ea..d230a196 100755
--- a/bin/bazel
+++ b/bin/bazel
@@ -29,7 +29,7 @@ case $(uname -s) in
     Darwin)
         ANDROID_BAZEL_PATH="${TOP}/prebuilts/bazel/darwin-x86_64/bazel"
         ANDROID_BAZELRC_NAME="darwin.bazelrc"
-        ANDROID_BAZEL_JDK_PATH="${TOP}/prebuilts/jdk/jdk17/darwin-x86"
+        ANDROID_BAZEL_JDK_PATH="${TOP}/prebuilts/jdk/jdk21/darwin-x86"
 
         # Lock down PATH in action execution environment, thereby removing
         # Bazel's default /bin, /usr/bin, /usr/local/bin and ensuring
@@ -52,7 +52,7 @@ case $(uname -s) in
         ANDROID_BAZEL_PATH="${TOP}/prebuilts/bazel/linux-x86_64/bazel"
         ANDROID_BAZELISK_PATH="${TOP}/prebuilts/bazel/linux-x86_64/dev_tools/bazelisk/bazelisk"
         ANDROID_BAZELRC_NAME="linux.bazelrc"
-        ANDROID_BAZEL_JDK_PATH="${TOP}/prebuilts/jdk/jdk17/linux-x86"
+        ANDROID_BAZEL_JDK_PATH="${TOP}/prebuilts/jdk/jdk21/linux-x86"
         RESTRICTED_PATH="${TOP}/prebuilts/build-tools/path/linux-x86:${ABSOLUTE_OUT_DIR}/.path"
         ;;
     *)
diff --git a/common.bazelrc b/common.bazelrc
index 0b2d1d66..a9a9fb14 100644
--- a/common.bazelrc
+++ b/common.bazelrc
@@ -8,8 +8,8 @@ build --experimental_platform_in_output_dir
 build --incompatible_enable_cc_toolchain_resolution
 
 # Ensure that the host_javabase always use the checked-in JDK.
-build --tool_java_runtime_version=jdk17
-build --java_runtime_version=jdk17
+build --tool_java_runtime_version=jdk21
+build --java_runtime_version=jdk21
 
 # Lock down the PATH variable in actions to /usr/bin and /usr/local/bin.
 build --experimental_strict_action_env
diff --git a/rules/java/BUILD b/rules/java/BUILD
index 1433efae..523ba73f 100644
--- a/rules/java/BUILD
+++ b/rules/java/BUILD
@@ -136,14 +136,14 @@ bootclasspath(
 )
 
 default_java_toolchain(
-    name = "jdk17_host_toolchain_java",
+    name = "jdk21_host_toolchain_java",
     bootclasspath = select({
         "host_config_setting_java_7": [":pre_java9_bootclasspath"],
         "host_config_setting_java_8": [":pre_java9_bootclasspath"],
         "//conditions:default": ["@rules_java_builtin//toolchains:platformclasspath"],
     }),
     # TODO(b/218720643): Support switching between multiple JDKs.
-    java_runtime = "//prebuilts/jdk/jdk17:jdk17_runtime",
+    java_runtime = "//prebuilts/jdk/jdk21:jdk21_runtime",
     misc = errorprone_global_flags + DEFAULT_JAVACOPTS + constants.CommonJdkFlags,
     source_version = select(java_version_select_dict),
     target_version = select(java_version_select_dict),
@@ -151,10 +151,10 @@ default_java_toolchain(
 )
 
 toolchain(
-    name = "jdk17_host_toolchain_java_definition",
+    name = "jdk21_host_toolchain_java_definition",
     exec_compatible_with = ["//build/bazel_common_rules/platforms/os:linux"],
     target_compatible_with = ["//build/bazel_common_rules/platforms/os:linux"],
     target_settings = [],
-    toolchain = ":jdk17_host_toolchain_java",
+    toolchain = ":jdk21_host_toolchain_java",
     toolchain_type = "@bazel_tools//tools/jdk:toolchain_type",
 )
diff --git a/rules/java/stub_local_jdk/BUILD.bazel b/rules/java/stub_local_jdk/BUILD.bazel
index 354ef285..6c4857c6 100644
--- a/rules/java/stub_local_jdk/BUILD.bazel
+++ b/rules/java/stub_local_jdk/BUILD.bazel
@@ -21,5 +21,5 @@ toolchain(
 # keep this reference valid.
 alias(
     name = "jar",
-    actual = "@//prebuilts/jdk/jdk17:jar",
+    actual = "@//prebuilts/jdk/jdk21:jar",
 )
diff --git a/rules/tradefed/tradefed.bzl b/rules/tradefed/tradefed.bzl
index ed225993..d866ca66 100644
--- a/rules/tradefed/tradefed.bzl
+++ b/rules/tradefed/tradefed.bzl
@@ -453,7 +453,7 @@ def _tradefed_test_impl(ctx, tradefed_options = []):
     # Append remote device runfiles if using remote execution.
     if _is_remote_device_test(ctx):
         runfiles = runfiles.merge(ctx.runfiles().merge(ctx.attr._run_with[DeviceEnvironment].data))
-        java_home = "/jdk/jdk17/linux-x86"
+        java_home = "/jdk/jdk21/linux-x86"
     else:
         java_runtime = ctx.attr._java_runtime[java_common.JavaRuntimeInfo]
         runfiles = runfiles.merge(ctx.runfiles(java_runtime.files.to_list()))
```

