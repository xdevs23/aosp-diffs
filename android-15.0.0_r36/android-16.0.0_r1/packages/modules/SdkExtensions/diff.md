```diff
diff --git a/Android.bp b/Android.bp
index 857ead7..ab8a357 100644
--- a/Android.bp
+++ b/Android.bp
@@ -65,6 +65,28 @@ sdk {
     ],
 }
 
+module_exports {
+    name: "sdkextensions-host-exports",
+    host_supported: true,
+    target: {
+        host: {
+            compile_multilib: "64",
+            native_binaries: [
+                "derive_classpath",
+            ],
+        },
+        linux_bionic: {
+            enabled: false,
+        },
+        darwin: {
+            enabled: false,
+        },
+        windows: {
+            enabled: false,
+        },
+    },
+}
+
 // Encapsulate the contributions made by the com.android.sdkext to the bootclasspath.
 bootclasspath_fragment {
     name: "com.android.sdkext-bootclasspath-fragment",
@@ -117,18 +139,3 @@ java_test_host {
         "device-tests",
     ],
 }
-
-// TODO: b/316383039 - Remove this module and the script when udc-mainline-prod
-// branch is removed.
-// The options passed to Metalava when generating API signature files and stubs
-// for SDK extension releases.
-genrule {
-    name: "sdkext-released-flagged-apis",
-    visibility: [
-        "//visibility:public",
-    ],
-    tool_files: ["keep-flagged-apis.sh"],
-    srcs: ["released-flagged-apis.txt"],
-    out: ["metalava-keep-flagged-apis.txt"],
-    cmd: "$(location keep-flagged-apis.sh) \"$(in)\" > \"$(out)\"",
-}
diff --git a/derive_classpath/Android.bp b/derive_classpath/Android.bp
index 88af844..9fb245e 100644
--- a/derive_classpath/Android.bp
+++ b/derive_classpath/Android.bp
@@ -19,16 +19,32 @@ package {
 
 cc_defaults {
     name: "derive_classpath-defaults",
+    host_supported: true,
     min_sdk_version: "30",
-    shared_libs: ["liblog"],
     // static c++/libbase for smaller size
     stl: "c++_static",
+    shared_libs: select(os(), {
+        "android": [
+            "liblog",
+        ],
+        default: [],
+    }),
     static_libs: [
         "libbase",
         "libclasspaths_proto",
-        "libmodules-utils-build",
         "libprotobuf-cpp-lite",
-    ],
+    ] + select(os(), {
+        "android": [
+            "libmodules-utils-build",
+        ],
+        default: [
+            "liblog",
+        ],
+    }),
+    cflags: select(os(), {
+        "android": ["-DSDKEXT_ANDROID"],
+        default: [],
+    }),
 }
 
 cc_library {
diff --git a/derive_classpath/derive_classpath.cpp b/derive_classpath/derive_classpath.cpp
index 1de47a7..c1faec2 100644
--- a/derive_classpath/derive_classpath.cpp
+++ b/derive_classpath/derive_classpath.cpp
@@ -17,18 +17,26 @@
 #define LOG_TAG "derive_classpath"
 
 #include "derive_classpath.h"
-#include <android-base/file.h>
-#include <android-base/logging.h>
-#include <android-base/strings.h>
-#include <android-modules-utils/sdk_level.h>
-#include <android-modules-utils/unbounded_sdk_level.h>
+
+#include <ctype.h>
 #include <glob.h>
+
 #include <regex>
 #include <sstream>
 #include <unordered_map>
 
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/parseint.h>
+#include <android-base/strings.h>
+
 #include "packages/modules/common/proto/classpaths.pb.h"
 
+#ifdef SDKEXT_ANDROID
+#include <android-modules-utils/sdk_level.h>
+#include <android-modules-utils/unbounded_sdk_level.h>
+#endif
+
 namespace android {
 namespace derive_classpath {
 
@@ -46,6 +54,62 @@ static const std::string kBootclasspathFragmentLocation = "/etc/classpaths/bootc
 static const std::string kSystemserverclasspathFragmentLocation =
     "/etc/classpaths/systemserverclasspath.pb";
 
+static int GetVersionInt(const std::string& version) {
+  int version_int = 0;
+  if (!android::base::ParseInt(version, &version_int, /*min=*/1, /*max=*/INT_MAX)) {
+    PLOG(FATAL) << "Failed to convert version \"" << version << "\" to int";
+  }
+  return version_int;
+}
+
+static bool IsCodename(const std::string& version) {
+  LOG_IF(FATAL, version.empty()) << "Empty version";
+  return isupper(version[0]);
+}
+
+static bool SdkLevelIsAtLeast(const Args& args, const std::string& version) {
+#ifdef SDKEXT_ANDROID
+  if (args.override_device_sdk_version == 0) {
+    // Most common case: no override.
+    return android::modules::sdklevel::unbounded::IsAtLeast(version.c_str());
+  }
+#endif
+
+  // Mirrors the logic in unbounded_sdk_level.h.
+  if (args.override_device_codename == "REL") {
+    if (IsCodename(version)) {
+      return false;
+    }
+    return args.override_device_sdk_version >= GetVersionInt(version);
+  }
+  if (IsCodename(version)) {
+    return args.override_device_known_codenames.contains(version);
+  }
+  return args.override_device_sdk_version >= GetVersionInt(version);
+}
+
+static bool SdkLevelIsAtMost(const Args& args, const std::string& version) {
+#ifdef SDKEXT_ANDROID
+  if (args.override_device_sdk_version == 0) {
+    // Most common case: no override.
+    return android::modules::sdklevel::unbounded::IsAtMost(version.c_str());
+  }
+#endif
+
+  // Mirrors the logic in unbounded_sdk_level.h.
+  if (args.override_device_codename == "REL") {
+    if (IsCodename(version)) {
+      return true;
+    }
+    return args.override_device_sdk_version <= GetVersionInt(version);
+  }
+  if (IsCodename(version)) {
+    return !args.override_device_known_codenames.contains(version) ||
+        args.override_device_codename == version;
+  }
+  return args.override_device_sdk_version < GetVersionInt(version);
+}
+
 std::vector<std::string> getBootclasspathFragmentGlobPatterns(const Args& args) {
   // Scan only specific directory for fragments if scan_dir is specified
   if (!args.scan_dirs.empty()) {
@@ -237,7 +301,7 @@ bool ParseFragments(const Args& args, Classpaths& classpaths, bool boot_jars) {
 
       if (!jar.min_sdk_version().empty()) {
         const auto& min_sdk_version = jar.min_sdk_version();
-        if (!android::modules::sdklevel::unbounded::IsAtLeast(min_sdk_version.c_str())) {
+        if (!SdkLevelIsAtLeast(args, min_sdk_version)) {
           LOG(INFO) << "not installing " << jar_path << " with min_sdk_version " << min_sdk_version;
           continue;
         }
@@ -245,7 +309,7 @@ bool ParseFragments(const Args& args, Classpaths& classpaths, bool boot_jars) {
 
       if (!jar.max_sdk_version().empty()) {
         const auto& max_sdk_version = jar.max_sdk_version();
-        if (!android::modules::sdklevel::unbounded::IsAtMost(max_sdk_version.c_str())) {
+        if (!SdkLevelIsAtMost(args, max_sdk_version)) {
           LOG(INFO) << "not installing " << jar_path << " with max_sdk_version " << max_sdk_version;
           continue;
         }
@@ -261,9 +325,11 @@ bool ParseFragments(const Args& args, Classpaths& classpaths, bool boot_jars) {
 // classpaths.proto config fragments. The exports file is read by init.rc to setenv *CLASSPATH
 // environ variables at runtime.
 bool GenerateClasspathExports(const Args& args) {
+#ifdef SDKEXT_ANDROID
   // Parse all known classpath fragments
   CHECK(android::modules::sdklevel::IsAtLeastS())
       << "derive_classpath must only be run on Android 12 or above";
+#endif
 
   Classpaths classpaths;
   if (!ParseFragments(args, classpaths, /*boot_jars=*/true)) {
diff --git a/derive_classpath/derive_classpath.h b/derive_classpath/derive_classpath.h
index 0c1678e..88d7f21 100644
--- a/derive_classpath/derive_classpath.h
+++ b/derive_classpath/derive_classpath.h
@@ -18,6 +18,7 @@
 
 #include <string>
 #include <string_view>
+#include <unordered_set>
 #include <vector>
 
 namespace android {
@@ -38,6 +39,13 @@ struct Args {
 
   // Scan specified list of directories instead of using default glob patterns
   std::vector<std::string> scan_dirs;
+
+  // Overrides the value of "ro.build.version.sdk" for SDK version check.
+  int override_device_sdk_version = 0;
+  // Overrides the value of "ro.build.version.codename" for SDK version check.
+  std::string override_device_codename;
+  // Overrides the value of "ro.build.version.known_codenames" for SDK version check.
+  std::unordered_set<std::string> override_device_known_codenames;
 };
 
 bool GenerateClasspathExports(const Args& args);
diff --git a/derive_classpath/derive_classpath_test.cpp b/derive_classpath/derive_classpath_test.cpp
index b233825..4b22e57 100644
--- a/derive_classpath/derive_classpath_test.cpp
+++ b/derive_classpath/derive_classpath_test.cpp
@@ -21,8 +21,6 @@
 #include <android-base/properties.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
-#include <android-modules-utils/sdk_level.h>
-#include <android/api-level.h>
 #include <gtest/gtest.h>
 #include <stdlib.h>
 #include <sys/mman.h>
@@ -34,6 +32,19 @@
 #include "android-base/unique_fd.h"
 #include "packages/modules/common/proto/classpaths.pb.h"
 
+#ifdef SDKEXT_ANDROID
+#include <android-modules-utils/sdk_level.h>
+#include <android/api-level.h>
+#else
+
+#define __ANDROID_API_R__ 30
+#define __NR_memfd_create 319
+
+int memfd_create(const char* name, unsigned int flags) {
+  return syscall(__NR_memfd_create, name, flags);
+}
+#endif
+
 namespace android {
 namespace derive_classpath {
 namespace {
@@ -47,18 +58,18 @@ static const std::string kServicesJarFilepath = "/system/framework/services.jar"
 // The fixture for testing derive_classpath.
 class DeriveClasspathTest : public ::testing::Test {
  protected:
-  ~DeriveClasspathTest() override {
-    // Not really needed, as a test device will re-generate a proper classpath on reboot,
-    // but it's better to leave it in a clean state after a test.
-    GenerateClasspathExports(default_args_);
-  }
-
   const std::string working_dir() { return std::string(temp_dir_.path); }
 
+  const std::string GetOutputPath() { return working_dir() + "/classpath"; }
+
   // Parses the generated classpath exports file and returns each line individually.
-  std::vector<std::string> ParseExportsFile(const char* file = "/data/system/environ/classpath") {
+  std::vector<std::string> ParseExportsFile(const char* file = nullptr) {
+    if (file == nullptr) {
+      file = output_path_.c_str();
+    }
     std::string contents;
-    EXPECT_TRUE(android::base::ReadFileToString(file, &contents, /*follow_symlinks=*/true));
+    EXPECT_TRUE(android::base::ReadFileToString(file, &contents,
+                                                /*follow_symlinks=*/true));
     return android::base::Split(contents, "\n");
   }
 
@@ -121,15 +132,21 @@ class DeriveClasspathTest : public ::testing::Test {
   }
 
   const TemporaryDir temp_dir_;
+  const std::string output_path_ = working_dir() + "/classpath";
 
-  const Args default_args_ = {
-      .output_path = kGeneratedClasspathExportsFilepath,
+#ifdef SDKEXT_ANDROID
+  const Args default_args_with_test_dir_ = {
+      .output_path = output_path_,
+      .glob_pattern_prefix = temp_dir_.path,
   };
-
+#else
   const Args default_args_with_test_dir_ = {
-      .output_path = kGeneratedClasspathExportsFilepath,
+      .output_path = output_path_,
+      .override_device_sdk_version = 35,
+      .override_device_codename = "REL",
       .glob_pattern_prefix = temp_dir_.path,
   };
+#endif
 };
 
 using DeriveClasspathDeathTest = DeriveClasspathTest;
@@ -137,7 +154,7 @@ using DeriveClasspathDeathTest = DeriveClasspathTest;
 // Check only known *CLASSPATH variables are exported.
 TEST_F(DeriveClasspathTest, DefaultNoUnknownClasspaths) {
   // Re-generate default on device classpaths
-  GenerateClasspathExports(default_args_);
+  GenerateClasspathExports(default_args_with_test_dir_);
 
   const std::vector<std::string> exportLines = ParseExportsFile();
   // The first four lines are tested below.
@@ -412,6 +429,9 @@ TEST_F(DeriveClasspathDeathTest, WrongClasspathInFragments) {
 }
 
 TEST_F(DeriveClasspathDeathTest, CurrentSdkVersion) {
+#ifndef SDKEXT_ANDROID
+  GTEST_SKIP();
+#else
   if (android_get_device_api_level() < __ANDROID_API_S__) {
     GTEST_SKIP();
   }
@@ -424,10 +444,14 @@ TEST_F(DeriveClasspathDeathTest, CurrentSdkVersion) {
   WriteConfig(exported_jars, "/apex/com.android.foo/etc/classpaths/systemserverclasspath.pb");
 
   EXPECT_DEATH(GenerateClasspathExports(default_args_with_test_dir_), "no conversion");
+#endif
 }
 
 // Test jars with different sdk versions.
 TEST_F(DeriveClasspathTest, SdkVersionsAreRespected) {
+#ifndef SDKEXT_ANDROID
+  GTEST_SKIP();
+#else
   if (android_get_device_api_level() < __ANDROID_API_S__) {
     GTEST_SKIP();
   }
@@ -532,6 +556,184 @@ TEST_F(DeriveClasspathTest, SdkVersionsAreRespected) {
   const std::vector<std::string> splitExportLine = SplitClasspathExportLine(exportLines[2]);
   const std::string exportValue = splitExportLine[2];
 
+  EXPECT_EQ(android::base::Join(expected_jars, ":"), exportValue);
+#endif
+}
+
+// Test jars with different sdk versions against override device values.
+TEST_F(DeriveClasspathTest, SdkVersionsAreCheckedAgainstOverrideDeviceValuesRelease) {
+  Args args = default_args_with_test_dir_;
+  args.override_device_sdk_version = 35;
+  args.override_device_codename = "REL";
+
+  // List of jars expected to be in SYSTEMSERVERCLASSPATH.
+  std::vector<std::string> expected_jars;
+
+  // Add an unbounded jar.
+  AddJarToClasspath("/system", "/system/framework/unbounded", SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/system/framework/unbounded");
+
+  // Manually create a config with jars that sets sdk versions...
+  ExportedClasspathsJars exported_jars;
+
+  // Known released versions.
+  Jar* jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdk30");
+  jar->set_min_sdk_version(std::to_string(__ANDROID_API_R__));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/minsdk30");
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/maxsdk30");
+  jar->set_max_sdk_version(std::to_string(__ANDROID_API_R__));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+
+  // Provided override device sdk version.
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdklatest");
+  jar->set_min_sdk_version(std::to_string(args.override_device_sdk_version));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/minsdklatest");
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/maxsdklatest");
+  jar->set_max_sdk_version(std::to_string(args.override_device_sdk_version));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/maxsdklatest");
+
+  // Unknown SDK_INT+1 version.
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdk_plus1");
+  jar->set_min_sdk_version(std::to_string(args.override_device_sdk_version + 1));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/maxsdk_plus1");
+  jar->set_max_sdk_version(std::to_string(args.override_device_sdk_version + 1));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/maxsdk_plus1");
+
+  // Known min_sdk_version and future max_sdk_version.
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdk30maxsdk10000");
+  jar->set_min_sdk_version(std::to_string(__ANDROID_API_R__));
+  jar->set_max_sdk_version(std::to_string(args.override_device_sdk_version + 1));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/minsdk30maxsdk10000");
+
+  // Codename.
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdkBaklava");
+  jar->set_min_sdk_version("Baklava");
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/maxsdkBaklava");
+  jar->set_max_sdk_version("Baklava");
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/maxsdkBaklava");
+
+  // ...and write this config to systemserverclasspath.pb.
+  WriteConfig(exported_jars, "/apex/com.android.foo/etc/classpaths/systemserverclasspath.pb");
+
+  // Generate and parse SYSTEMSERVERCLASSPATH.
+  GenerateClasspathExports(args);
+  const std::vector<std::string> exportLines = ParseExportsFile();
+  const std::vector<std::string> splitExportLine = SplitClasspathExportLine(exportLines[2]);
+  const std::string exportValue = splitExportLine[2];
+
+  EXPECT_EQ(android::base::Join(expected_jars, ":"), exportValue);
+}
+
+// Test jars with different sdk versions against override device values.
+TEST_F(DeriveClasspathTest, SdkVersionsAreCheckedAgainstOverrideDeviceValuesDev) {
+  Args args = default_args_with_test_dir_;
+  args.override_device_sdk_version = 35;
+  args.override_device_codename = "Baklava";
+  args.override_device_known_codenames = {
+      "S", "Sv2", "Tiramisu", "UpsideDownCake", "VanillaIceCream", "Baklava"};
+
+  // List of jars expected to be in SYSTEMSERVERCLASSPATH.
+  std::vector<std::string> expected_jars;
+
+  // Add an unbounded jar.
+  AddJarToClasspath("/system", "/system/framework/unbounded", SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/system/framework/unbounded");
+
+  // Manually create a config with jars that sets sdk versions...
+  ExportedClasspathsJars exported_jars;
+
+  // Known released versions.
+  Jar* jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdk30");
+  jar->set_min_sdk_version(std::to_string(__ANDROID_API_R__));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/minsdk30");
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/maxsdk30");
+  jar->set_max_sdk_version(std::to_string(__ANDROID_API_R__));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+
+  // Provided override device sdk version.
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdklatest");
+  jar->set_min_sdk_version(std::to_string(args.override_device_sdk_version));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/minsdklatest");
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/maxsdklatest");
+  jar->set_max_sdk_version(std::to_string(args.override_device_sdk_version));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+
+  // Unknown SDK_INT+1 version.
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdk_plus1");
+  jar->set_min_sdk_version(std::to_string(args.override_device_sdk_version + 1));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/maxsdk_plus1");
+  jar->set_max_sdk_version(std::to_string(args.override_device_sdk_version + 1));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/maxsdk_plus1");
+
+  // Known min_sdk_version and future max_sdk_version.
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdk30maxsdk10000");
+  jar->set_min_sdk_version(std::to_string(__ANDROID_API_R__));
+  jar->set_max_sdk_version(std::to_string(args.override_device_sdk_version + 1));
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/minsdk30maxsdk10000");
+
+  // Codename.
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdkBaklava");
+  jar->set_min_sdk_version("Baklava");
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/minsdkBaklava");
+
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/maxsdkBaklava");
+  jar->set_max_sdk_version("Baklava");
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/maxsdkBaklava");
+
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/minsdkTiramisu");
+  jar->set_min_sdk_version("Tiramisu");
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+  expected_jars.push_back("/apex/com.android.foo/javalib/minsdkTiramisu");
+
+  jar = exported_jars.add_jars();
+  jar->set_path("/apex/com.android.foo/javalib/maxsdkTiramisu");
+  jar->set_max_sdk_version("Tiramisu");
+  jar->set_classpath(SYSTEMSERVERCLASSPATH);
+
+  // ...and write this config to systemserverclasspath.pb.
+  WriteConfig(exported_jars, "/apex/com.android.foo/etc/classpaths/systemserverclasspath.pb");
+
+  // Generate and parse SYSTEMSERVERCLASSPATH.
+  GenerateClasspathExports(args);
+  const std::vector<std::string> exportLines = ParseExportsFile();
+  const std::vector<std::string> splitExportLine = SplitClasspathExportLine(exportLines[2]);
+  const std::string exportValue = splitExportLine[2];
+
   EXPECT_EQ(android::base::Join(expected_jars, ":"), exportValue);
 }
 
diff --git a/derive_classpath/main.cpp b/derive_classpath/main.cpp
index 330f2cc..d8319d3 100644
--- a/derive_classpath/main.cpp
+++ b/derive_classpath/main.cpp
@@ -14,11 +14,13 @@
  * limitations under the License.
  */
 
-#include <android-base/logging.h>
-#include <android-base/strings.h>
 #include <cstdlib>
 #include <string_view>
 
+#include <android-base/logging.h>
+#include <android-base/parseint.h>
+#include <android-base/strings.h>
+
 #include "derive_classpath.h"
 
 bool ArgumentMatches(std::string_view argument, std::string_view prefix, std::string_view* value) {
@@ -57,6 +59,37 @@ bool ParseArgs(android::derive_classpath::Args& args, int argc, char** argv) {
         return false;
       }
       args.scan_dirs = android::base::Split(std::string(value), ",");
+    } else if (ArgumentMatches(arg, "--glob-pattern-prefix=", &value)) {
+      if (!args.glob_pattern_prefix.empty()) {
+        LOG(ERROR) << "Duplicated flag --glob-pattern-prefix is specified";
+        return false;
+      }
+      args.glob_pattern_prefix = value;
+    } else if (ArgumentMatches(arg, "--override-device-sdk-version=", &value)) {
+      if (args.override_device_sdk_version != 0) {
+        LOG(ERROR) << "Duplicated flag --override-device-sdk-version is specified";
+        return false;
+      }
+      if (!android::base::ParseInt(std::string(value), &args.override_device_sdk_version, /*min=*/1,
+                                   /*max=*/INT_MAX)) {
+        PLOG(ERROR) << "Invalid value for --override-device-sdk-version \"" << value << "\"";
+        return false;
+      }
+    } else if (ArgumentMatches(arg, "--override-device-codename=", &value)) {
+      if (!args.override_device_codename.empty()) {
+        LOG(ERROR) << "Duplicated flag --override-device-codename is specified";
+        return false;
+      }
+      args.override_device_codename = value;
+    } else if (ArgumentMatches(arg, "--override-device-known-codenames=", &value)) {
+      if (!args.override_device_known_codenames.empty()) {
+        LOG(ERROR) << "Duplicated flag --override-device-known-codenames is specified";
+        return false;
+      }
+      std::vector<std::string> known_codenames = android::base::Split(std::string(value), ",");
+      std::move(known_codenames.begin(), known_codenames.end(),
+                std::inserter(args.override_device_known_codenames,
+                              args.override_device_known_codenames.end()));
     } else {
       positional_args.emplace_back(arg);
     }
@@ -65,12 +98,58 @@ bool ParseArgs(android::derive_classpath::Args& args, int argc, char** argv) {
   // Validate flag combinations
   if (!args.scan_dirs.empty() && (!args.system_bootclasspath_fragment.empty() ||
                                   !args.system_systemserverclasspath_fragment.empty())) {
-    LOG(ERROR) << "--scan-dirs should not be accompanied by other flags";
+    LOG(ERROR) << "--scan-dirs should not be accompanied by --bootclasspath-fragment or "
+                  "--systemserverclasspath-fragment";
+    return false;
+  }
+
+  if (!args.glob_pattern_prefix.empty() &&
+      (!args.scan_dirs.empty() || !args.system_bootclasspath_fragment.empty() ||
+       !args.system_systemserverclasspath_fragment.empty())) {
+    LOG(ERROR) << "--glob-pattern-prefix should not be accompanied by --scan-dirs, "
+                  "--bootclasspath-fragment or --systemserverclasspath-fragment";
     return false;
   }
 
+  if (args.override_device_sdk_version != 0 && args.override_device_codename.empty()) {
+    LOG(ERROR)
+        << "--override-device-sdk-version should be accompanied by --override-device-codename";
+    return false;
+  }
+
+  if (!args.override_device_codename.empty() && args.override_device_codename != "REL" &&
+      args.override_device_known_codenames.empty()) {
+    LOG(ERROR) << "--override-device-codename should be accompanied by "
+                  "--override-device-known-codenames, unless it is set to \"REL\"";
+    return false;
+  }
+
+  if (args.override_device_sdk_version == 0 &&
+      (!args.override_device_codename.empty() || !args.override_device_known_codenames.empty())) {
+    LOG(ERROR) << "--override-device-codename and --override-device-known-codenames should not "
+                  "be specified without --override-device-sdk-version";
+    return false;
+  }
+
+#ifndef SDKEXT_ANDROID
+  if (args.glob_pattern_prefix.empty() && args.scan_dirs.empty()) {
+    LOG(ERROR) << "Either --glob-pattern-prefix or --scan-dirs must be specified on host";
+    return false;
+  }
+
+  if (args.override_device_sdk_version == 0) {
+    LOG(ERROR)
+        << "--override-device-sdk-version and --override-device-codename must be specified on host";
+    return false;
+  }
+#endif
+
   // Handle positional args
   if (positional_args.size() == 0) {
+#ifndef SDKEXT_ANDROID
+    LOG(ERROR) << "Output path must be specified on host";
+    return false;
+#endif
     args.output_path = android::derive_classpath::kGeneratedClasspathExportsFilepath;
   } else if (positional_args.size() == 1) {
     args.output_path = positional_args[0];
@@ -79,6 +158,7 @@ bool ParseArgs(android::derive_classpath::Args& args, int argc, char** argv) {
                << android::base::Join(positional_args, ' ');
     return false;
   }
+
   return true;
 }
 
diff --git a/derive_sdk/derive_sdk.cpp b/derive_sdk/derive_sdk.cpp
index 9df9309..94964a1 100644
--- a/derive_sdk/derive_sdk.cpp
+++ b/derive_sdk/derive_sdk.cpp
@@ -48,6 +48,7 @@ static const std::unordered_map<std::string, SdkModule> kApexNameToModule = {
     {"com.android.ipsec", SdkModule::IPSEC},
     {"com.android.media", SdkModule::MEDIA},
     {"com.android.mediaprovider", SdkModule::MEDIA_PROVIDER},
+    {"com.android.neuralnetworks", SdkModule::NEURAL_NETWORKS},
     {"com.android.ondevicepersonalization", SdkModule::ON_DEVICE_PERSONALIZATION},
     {"com.android.permission", SdkModule::PERMISSIONS},
     {"com.android.scheduling", SdkModule::SCHEDULING},
@@ -72,12 +73,14 @@ static const std::unordered_set<SdkModule> kUModules = {SdkModule::CONFIG_INFRAS
 
 static const std::unordered_set<SdkModule> kVModules = {};
 
+static const std::unordered_set<SdkModule> kBModules = {SdkModule::NEURAL_NETWORKS};
+
 static const std::string kSystemPropertiesPrefix = "build.version.extensions.";
 
 void ReadSystemProperties(std::map<std::string, std::string>& properties) {
   const std::string default_ = "<not set>";
 
-  for (const auto& dessert : {"r", "s", "t", "ad_services", "u", "v"}) {
+  for (const auto& dessert : {"r", "s", "t", "ad_services", "u", "v", "b"}) {
     properties[kSystemPropertiesPrefix + dessert] =
         android::base::GetProperty(kSystemPropertiesPrefix + dessert, default_);
   }
@@ -227,6 +230,13 @@ bool SetSdkLevels(const std::string& mountpath) {
     }
   }
 
+  relevant_modules.insert(kBModules.begin(), kBModules.end());
+  if (android::modules::sdklevel::IsAtLeastB()) {
+    if (!GetAndSetExtension("b", db, relevant_modules, versions)) {
+      return false;
+    }
+  }
+
   // Consistency check: verify all modules with requirements is included in some dessert
   for (const auto& ext_version : db.versions()) {
     for (const auto& requirement : ext_version.requirements()) {
diff --git a/derive_sdk/derive_sdk_test.cpp b/derive_sdk/derive_sdk_test.cpp
index 4e3cd33..54b8cde 100644
--- a/derive_sdk/derive_sdk_test.cpp
+++ b/derive_sdk/derive_sdk_test.cpp
@@ -38,6 +38,8 @@
     EXPECT_S(n);      \
     EXPECT_T(n);      \
     EXPECT_U(n);      \
+    EXPECT_V(n);      \
+    EXPECT_B(n);      \
   }
 
 #define EXPECT_R(n) EXPECT_EQ(GetR(), (n))
@@ -54,6 +56,9 @@
 // Only expect the V extension level to be set on V+ devices.
 #define EXPECT_V(n) EXPECT_EQ(GetV(), android::modules::sdklevel::IsAtLeastV() ? (n) : -1)
 
+// Only expect the B extension level to be set on B+ devices.
+#define EXPECT_B(n) EXPECT_EQ(GetB(), android::modules::sdklevel::IsAtLeastB() ? (n) : -1)
+
 class DeriveSdkTest : public ::testing::Test {
  protected:
   void TearDown() override { android::derivesdk::SetSdkLevels("/apex"); }
@@ -108,6 +113,8 @@ class DeriveSdkTest : public ::testing::Test {
 
   int GetV() { return android::base::GetIntProperty("build.version.extensions.v", -1); }
 
+  int GetB() { return android::base::GetIntProperty("build.version.extensions.b", -1); }
+
   void EXPECT_ADSERVICES(int n) {
     int actual = android::base::GetIntProperty("build.version.extensions.ad_services", -1);
     // Only expect the AdServices extension level to be set on T+ devices.
@@ -332,6 +339,16 @@ TEST_F(DeriveSdkTest, VanillaIceCream) {
   // Nothing to do: no new modules were added in V
 }
 
+TEST_F(DeriveSdkTest, Baklava) {
+  AddExtensionVersion(1, {
+                             {SdkModule::NEURAL_NETWORKS, 1},
+                         });
+  EXPECT_B(0);
+
+  SetApexVersion("com.android.neuralnetworks", 1);
+  EXPECT_B(1);
+}
+
 int main(int argc, char** argv) {
   ::testing::InitGoogleTest(&argc, argv);
   return RUN_ALL_TESTS();
diff --git a/gen_sdk/Android.bp b/gen_sdk/Android.bp
index e014d5d..cde5935 100644
--- a/gen_sdk/Android.bp
+++ b/gen_sdk/Android.bp
@@ -23,11 +23,6 @@ python_binary_host {
     name: "gen_sdk",
     srcs: ["gen_sdk.py"],
     libs: ["sdk_proto_python"],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 sh_test_host {
diff --git a/gen_sdk/bump_sdk.sh b/gen_sdk/bump_sdk.sh
index 6b4e947..c039ac5 100755
--- a/gen_sdk/bump_sdk.sh
+++ b/gen_sdk/bump_sdk.sh
@@ -23,8 +23,8 @@ bug="$1"
 
 SDKEXT="packages/modules/SdkExtensions/"
 
-TARGET_PRODUCT=aosp_arm64 build/soong/soong_ui.bash --make-mode --soong-only gen_sdk
-out/soong/host/linux-x86/bin/gen_sdk \
+m gen_sdk
+gen_sdk \
     --database ${SDKEXT}/gen_sdk/extensions_db.textpb \
     --action new_sdk \
     --sdk "$sdk" \
@@ -47,7 +47,7 @@ $ gen_sdk --action new_sdk --sdk $sdk
 "
 message+=$(test -z "$bug" || echo "\nBug: $bug")
 message+="\nTest: presubmit"
-message+="\nIgnore-AOSP-first: SDKs are finalized outside of AOSP"
+message+="\nIgnore-AOSP-First: SDKs are finalized outside of AOSP"
 
 message=$(echo -e "$message") # expand '\n' chars
 git -C ${SDKEXT} commit -a -m "$message"
diff --git a/gen_sdk/extensions_db.textpb b/gen_sdk/extensions_db.textpb
index ce3bf2f..390c367 100644
--- a/gen_sdk/extensions_db.textpb
+++ b/gen_sdk/extensions_db.textpb
@@ -1426,3 +1426,108 @@ versions {
     }
   }
 }
+versions {
+  version: 17
+  requirements {
+    module: ART
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: CONSCRYPT
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: IPSEC
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: MEDIA
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: MEDIA_PROVIDER
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: PERMISSIONS
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: SCHEDULING
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: SDK_EXTENSIONS
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: STATSD
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: TETHERING
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: AD_SERVICES
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: APPSEARCH
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: ON_DEVICE_PERSONALIZATION
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: CONFIG_INFRASTRUCTURE
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: HEALTH_FITNESS
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: EXT_SERVICES
+    version {
+      version: 17
+    }
+  }
+  requirements {
+    module: NEURAL_NETWORKS
+    version {
+      version: 17
+    }
+  }
+}
diff --git a/java/android/os/ext/SdkExtensions.java b/java/android/os/ext/SdkExtensions.java
index 6f39439..681ce9b 100644
--- a/java/android/os/ext/SdkExtensions.java
+++ b/java/android/os/ext/SdkExtensions.java
@@ -48,6 +48,7 @@ public class SdkExtensions {
     private static final int T_EXTENSION_INT;
     private static final int U_EXTENSION_INT;
     private static final int V_EXTENSION_INT;
+    private static final int B_EXTENSION_INT;
     private static final int AD_SERVICES_EXTENSION_INT;
     private static final Map<Integer, Integer> ALL_EXTENSION_INTS;
 
@@ -57,6 +58,7 @@ public class SdkExtensions {
         T_EXTENSION_INT = SystemProperties.getInt("build.version.extensions.t", 0);
         U_EXTENSION_INT = SystemProperties.getInt("build.version.extensions.u", 0);
         V_EXTENSION_INT = SystemProperties.getInt("build.version.extensions.v", 0);
+        B_EXTENSION_INT = SystemProperties.getInt("build.version.extensions.b", 0);
         AD_SERVICES_EXTENSION_INT =
                 SystemProperties.getInt("build.version.extensions.ad_services", 0);
         Map<Integer, Integer> extensions = new HashMap<Integer, Integer>();
@@ -74,6 +76,9 @@ public class SdkExtensions {
         if (SdkLevel.isAtLeastV()) {
             extensions.put(VERSION_CODES.VANILLA_ICE_CREAM, V_EXTENSION_INT);
         }
+        if (SdkLevel.isAtLeastB()) {
+            extensions.put(VERSION_CODES.BAKLAVA, B_EXTENSION_INT);
+        }
         ALL_EXTENSION_INTS = Collections.unmodifiableMap(extensions);
     }
 
@@ -89,6 +94,7 @@ public class SdkExtensions {
                 VERSION_CODES.TIRAMISU,
                 VERSION_CODES.UPSIDE_DOWN_CAKE,
                 VERSION_CODES.VANILLA_ICE_CREAM,
+                VERSION_CODES.BAKLAVA,
                 AD_SERVICES,
             })
     @Retention(RetentionPolicy.SOURCE)
@@ -131,6 +137,9 @@ public class SdkExtensions {
         if (extension == VERSION_CODES.VANILLA_ICE_CREAM) {
             return V_EXTENSION_INT;
         }
+        if (extension == VERSION_CODES.BAKLAVA) {
+            return B_EXTENSION_INT;
+        }
         if (extension == AD_SERVICES) {
             return AD_SERVICES_EXTENSION_INT;
         }
diff --git a/javatests/com/android/os/ext/SdkExtensionsTest.java b/javatests/com/android/os/ext/SdkExtensionsTest.java
index bb2172c..b6d3a7b 100644
--- a/javatests/com/android/os/ext/SdkExtensionsTest.java
+++ b/javatests/com/android/os/ext/SdkExtensionsTest.java
@@ -17,6 +17,7 @@
 package com.android.os.ext;
 
 import static android.os.Build.VERSION_CODES;
+import static android.os.Build.VERSION_CODES.BAKLAVA;
 import static android.os.Build.VERSION_CODES.R;
 import static android.os.Build.VERSION_CODES.S;
 import static android.os.Build.VERSION_CODES.TIRAMISU;
@@ -152,7 +153,7 @@ public class SdkExtensionsTest {
     @Test
     public void testZeroValues() throws Exception {
         Set<Integer> assignedCodes =
-                Set.of(R, S, TIRAMISU, UPSIDE_DOWN_CAKE, VANILLA_ICE_CREAM, AD_SERVICES);
+                Set.of(R, S, TIRAMISU, UPSIDE_DOWN_CAKE, VANILLA_ICE_CREAM, BAKLAVA, AD_SERVICES);
         for (int sdk = VERSION_CODES.R; sdk <= 1_000_000; sdk++) {
             if (assignedCodes.contains(sdk)) {
                 continue;
@@ -180,6 +181,9 @@ public class SdkExtensionsTest {
         if (SdkLevel.isAtLeastV()) {
             expectedKeys.add(VANILLA_ICE_CREAM);
         }
+        if (SdkLevel.isAtLeastB()) {
+            expectedKeys.add(BAKLAVA);
+        }
         Set<Integer> actualKeys = SdkExtensions.getAllExtensionVersions().keySet();
         assertThat(actualKeys).containsExactlyElementsIn(expectedKeys);
     }
@@ -214,6 +218,12 @@ public class SdkExtensionsTest {
         assertVersion(expectation, VANILLA_ICE_CREAM, "v");
     }
 
+    @Test
+    public void testExtensionB() throws Exception {
+        Expectation expectation = dessertExpectation(SdkLevel.isAtLeastB());
+        assertVersion(expectation, BAKLAVA, "b");
+    }
+
     @Test
     public void testExtensionAdServices() throws Exception {
         // Go trains do not ship the latest versions of AdServices, though they should. Temporarily
diff --git a/keep-flagged-apis.sh b/keep-flagged-apis.sh
deleted file mode 100755
index efc336c..0000000
--- a/keep-flagged-apis.sh
+++ /dev/null
@@ -1,33 +0,0 @@
-#!/bin/bash -e
-#
-# Copyright 2023 Google Inc. All rights reserved.
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#     http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-# Convert a list of flags in the input file to a list of metalava options
-# that will keep the APIs for those flags will hiding all other flagged
-# APIs.
-
-FLAGS="$1"
-
-FLAGGED="android.annotation.FlaggedApi"
-
-# Convert the list of feature flags in the input file to Metalava options
-# of the form `--revert-annotation !android.annotation.FlaggedApi("<flag>")`
-# to prevent the annotated APIs from being hidden, i.e. include the annotated
-# APIs in the SDK snapshots. This also preserves the line comments, they will
-# be ignored by Metalava but might be useful when debugging.
-sed "s|^[^#].*$|--revert-annotation '!$FLAGGED(\"\\0\")'|" $FLAGS
-
-# Revert all flagged APIs, unless listed above.
-echo "--revert-annotation $FLAGGED"
diff --git a/sdk-extensions-info-test/test.rs b/sdk-extensions-info-test/test.rs
index 9f42f61..6fc10b4 100644
--- a/sdk-extensions-info-test/test.rs
+++ b/sdk-extensions-info-test/test.rs
@@ -139,6 +139,13 @@ mod tests {
                 "{:?}: pattern contains whitespace",
                 symbol
             );
+            if symbol.sdks.contains(&String::from("AD_SERVICES-ext")) {
+                ensure!(
+                    symbol.sdks.len() == 1,
+                    "{:?}: AD_SERVICES-ext is mutually exclusive to all other sdks",
+                    symbol
+                );
+            }
             for id in symbol.sdks.iter() {
                 ensure!(
                     sdk_shortnames.contains(&id),
@@ -219,6 +226,10 @@ mod tests {
             "testdata/whitespace-in-pattern.xml",
             r#"Symbol { jar: "framework-something-else", pattern: "android.app.appsearch.AppSearchSchema.DocumentPropertyConfig.Builder\n                .addIndexableNestedProperties ", sdks: ["bar"] }: pattern contains whitespace"#
         );
+        assert_err!(
+            "testdata/adservices-sdk-mixed-with-other-sdk.xml",
+            r#"Symbol { jar: "framework-something", pattern: "*", sdks: ["AD_SERVICES-ext", "foo"] }: AD_SERVICES-ext is mutually exclusive to all other sdks"#
+        );
     }
 
     #[test]
diff --git a/sdk-extensions-info-test/testdata/adservices-sdk-mixed-with-other-sdk.xml b/sdk-extensions-info-test/testdata/adservices-sdk-mixed-with-other-sdk.xml
new file mode 100644
index 0000000..cf03eaf
--- /dev/null
+++ b/sdk-extensions-info-test/testdata/adservices-sdk-mixed-with-other-sdk.xml
@@ -0,0 +1,17 @@
+<?xml version="1.0" encoding="utf-8"?>
+<sdk-extensions-info>
+    <sdk
+        id="1"
+        shortname="foo"
+        name="The foo extensions"
+        reference="android/os/Build$FOO" />
+    <sdk
+        id="1000000"
+        shortname="AD_SERVICES-ext"
+        name="Ad Services Extensions"
+        reference="android/os/ext/SdkExtensions$AD_SERVICES" />
+    <symbol
+        jar="framework-something"
+        pattern="*"
+        sdks="AD_SERVICES-ext,foo" />
+</sdk-extensions-info>
diff --git a/sdk-extensions-info-test/testdata/correct.xml b/sdk-extensions-info-test/testdata/correct.xml
index 91d756c..b24e8aa 100644
--- a/sdk-extensions-info-test/testdata/correct.xml
+++ b/sdk-extensions-info-test/testdata/correct.xml
@@ -10,6 +10,11 @@
         shortname="bar"
         name="The bar extensions"
         reference="android/os/Build$BAR" />
+    <sdk
+        id="1000000"
+        shortname="AD_SERVICES-ext"
+        name="Ad Services Extensions"
+        reference="android/os/ext/SdkExtensions$AD_SERVICES" />
     <symbol
         jar="framework-something"
         pattern="*"
@@ -22,4 +27,8 @@
         jar="framework-something-else"
         pattern="pkg.b"
         sdks="bar" />
+    <symbol
+        jar="framework-something-else"
+        pattern="pkg.c"
+        sdks="AD_SERVICES-ext" />
 </sdk-extensions-info>
diff --git a/sdk-extensions-info.xml b/sdk-extensions-info.xml
index 3f1eb41..eefefa9 100644
--- a/sdk-extensions-info.xml
+++ b/sdk-extensions-info.xml
@@ -46,6 +46,11 @@
     shortname="V-ext"
     name="V Extensions"
     reference="android/os/Build$VERSION_CODES$VANILLA_ICE_CREAM" />
+  <sdk
+      id="36"
+      shortname="B-ext"
+      name="B Extensions"
+      reference="android/os/Build$VERSION_CODES$BAKLAVA" />
   <sdk
     id="1000000"
     shortname="AD_SERVICES-ext"
@@ -56,165 +61,165 @@
   <symbol
     jar="framework-sdkextensions"
     pattern="*"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
 
   <!-- APPSEARCH -->
   <symbol
     jar="framework-appsearch"
     pattern="android.app.appsearch"
-    sdks="T-ext,U-ext,V-ext" />
+    sdks="T-ext,U-ext,V-ext,B-ext" />
 
   <!-- MEDIA_PROVIDER -->
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.PickerMediaColumns"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.ACTION_PICK_IMAGES"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.ACTION_PICK_IMAGES_SETTINGS"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.EXTRA_PICK_IMAGES_MAX"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
       jar="framework-mediaprovider"
       pattern="android.provider.MediaStore.EXTRA_PICK_IMAGES_IN_ORDER"
-      sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+      sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
       jar="framework-mediaprovider"
       pattern="android.provider.MediaStore.EXTRA_PICK_IMAGES_LAUNCH_TAB"
-      sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+      sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
       jar="framework-mediaprovider"
       pattern="android.provider.MediaStore.EXTRA_PICK_IMAGES_ACCENT_COLOR"
-      sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+      sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
       jar="framework-mediaprovider"
       pattern="android.provider.MediaStore.EXTRA_PICKER_PRE_SELECTION_URIS"
-      sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+      sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
       jar="framework-mediaprovider"
       pattern="android.provider.MediaStore.QUERY_ARG_LATEST_SELECTION_ONLY"
-      sdks="U-ext,V-ext" />
+      sdks="U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.getPickImagesMaxLimit"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.getGeneration"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.getVersion"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.openFileDescriptor"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.openAssetFileDescriptor"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.openTypedAssetFileDescriptor"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.ACCESS_OEM_METADATA_PERMISSION"
-    sdks="T-ext,U-ext,V-ext" />
+    sdks="T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.QUERY_ARG_MEDIA_STANDARD_SORT_ORDER"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.markIsFavoriteStatus"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.VOLUME_EXTERNAL"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.MediaColumns.INFERRED_DATE"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.MediaColumns.OEM_METADATA"
-    sdks="T-ext,U-ext,V-ext" />
+    sdks="T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.Audio.AudioColumns.BITS_PER_SAMPLE"
-    sdks="T-ext,U-ext,V-ext" />
+    sdks="T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.Audio.AudioColumns.SAMPLERATE"
-    sdks="T-ext,U-ext,V-ext" />
+    sdks="T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.OemMetadataService"
-    sdks="T-ext,U-ext,V-ext" />
+    sdks="T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.CloudMediaProvider"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.CloudMediaProviderContract"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.isCurrentCloudMediaProviderAuthority"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.isSupportedCloudMediaProviderAuthority"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-mediaprovider"
     pattern="android.provider.MediaStore.notifyCloudMediaChangedEvent"
-    sdks="R-ext,S-ext,T-ext,U-ext,V-ext" />
+    sdks="R-ext,S-ext,T-ext,U-ext,V-ext,B-ext" />
 
    <!-- PHOTOPICKER -->
    <symbol
     jar="framework-photopicker"
     pattern="android.widget.photopicker"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <!-- CONNECTIVITY -->
   <symbol
     jar="framework-connectivity"
     pattern="android.net.http"
-    sdks="S-ext,T-ext,U-ext,V-ext" />
+    sdks="S-ext,T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-connectivity-t"
     pattern="android.net.nsd"
-    sdks="T-ext,U-ext,V-ext" />
+    sdks="T-ext,U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-connectivity"
     pattern="android.net.thread"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-connectivity"
     pattern="android.net"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
   <symbol
     jar="framework-connectivity-t"
     pattern="android.net.NetworkStats"
-    sdks="T-ext,U-ext,V-ext" />
+    sdks="T-ext,U-ext,V-ext,B-ext" />
 
   <!-- PDF -->
   <symbol
     jar="framework-pdf"
     pattern="android.graphics.pdf"
-    sdks="S-ext,T-ext,U-ext,V-ext" />
+    sdks="S-ext,T-ext,U-ext,V-ext,B-ext" />
 
   <!-- AD_SERVICES -->
   <!--
@@ -238,526 +243,526 @@
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.AggregateRecordsGroupedByDurationResponse.getDataOrigins"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.AggregateRecordsGroupedByPeriodResponse.getDataOrigins"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.BloodPressureRecord.DIASTOLIC_AVG"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.BloodPressureRecord.DIASTOLIC_MAX"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.BloodPressureRecord.DIASTOLIC_MIN"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.BloodPressureRecord.SYSTOLIC_AVG"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.BloodPressureRecord.SYSTOLIC_MIN"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.BloodPressureRecord.SYSTOLIC_MAX"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.CyclingPedalingCadenceRecord.RPM_AVG"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.CyclingPedalingCadenceRecord.RPM_MAX"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.CyclingPedalingCadenceRecord.RPM_MIN"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.NutritionRecord.TRANS_FAT_TOTAL"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.SpeedRecord.SPEED_AVG"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.SpeedRecord.SPEED_MAX"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.SpeedRecord.SPEED_MIN"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.StepsCadenceRecord.STEPS_CADENCE_RATE_AVG"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.StepsCadenceRecord.STEPS_CADENCE_RATE_MAX"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.StepsCadenceRecord.STEPS_CADENCE_RATE_MIN"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.SkinTemperatureRecord"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.SkinTemperatureRecord.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.SkinTemperatureRecord.Delta"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.units.TemperatureDelta"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseCompletionGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseCompletionGoal.ActiveCaloriesBurnedGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseCompletionGoal.DistanceGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseCompletionGoal.DistanceWithVariableRestGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseCompletionGoal.DurationGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseCompletionGoal.RepetitionsGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseCompletionGoal.StepsGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseCompletionGoal.TotalCaloriesBurnedGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseCompletionGoal.UnknownGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseCompletionGoal.UnspecifiedGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExercisePerformanceGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExercisePerformanceGoal.AmrapGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExercisePerformanceGoal.CadenceGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExercisePerformanceGoal.HeartRateGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExercisePerformanceGoal.PowerGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExercisePerformanceGoal.RateOfPerceivedExertionGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExercisePerformanceGoal.SpeedGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExercisePerformanceGoal.UnknownGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExercisePerformanceGoal.WeightGoal"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.PlannedExerciseBlock"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.PlannedExerciseBlock.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.PlannedExerciseSessionRecord"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.PlannedExerciseSessionRecord.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.PlannedExerciseStep"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.PlannedExerciseStep.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_HEALTH_DATA_HISTORY"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_HEALTH_DATA_IN_BACKGROUND"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_PLANNED_EXERCISE"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_SKIN_TEMPERATURE"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.WRITE_PLANNED_EXERCISE"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.WRITE_SKIN_TEMPERATURE"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_EXERCISE_ROUTES"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseSessionRecord.Builder.setPlannedExerciseSessionId"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ExerciseSessionRecord.getPlannedExerciseSessionId"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MINDFULNESS"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.WRITE_MINDFULNESS"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.MindfulnessSessionRecord"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.MindfulnessSessionRecord.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthConnectManager.createMedicalDataSource"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthConnectManager.deleteMedicalDataSourceWithData"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthConnectManager.deleteMedicalResources"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthConnectManager.getMedicalDataSources"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthConnectManager.readMedicalResources"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthConnectManager.upsertMedicalResources"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.CreateMedicalDataSourceRequest"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.CreateMedicalDataSourceRequest.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.DeleteMedicalResourcesRequest"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.DeleteMedicalResourcesRequest.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.GetMedicalDataSourcesRequest"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.GetMedicalDataSourcesRequest.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.MedicalResourceId"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.ReadMedicalResourcesInitialRequest"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.ReadMedicalResourcesInitialRequest.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.ReadMedicalResourcesPageRequest"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.ReadMedicalResourcesPageRequest.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.ReadMedicalResourcesRequest"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.ReadMedicalResourcesResponse"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.UpsertMedicalResourceRequest"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.UpsertMedicalResourceRequest.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.FhirResource"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.FhirResource.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.FhirVersion"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.MedicalDataSource"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.MedicalDataSource.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.MedicalResource"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.MedicalResource.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_ALLERGIES_INTOLERANCES"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_CONDITIONS"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_VACCINES"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_LABORATORY_RESULTS"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_MEDICATIONS"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_PERSONAL_DETAILS"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_PRACTITIONER_DETAILS"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_PREGNANCY"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_PROCEDURES"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_SOCIAL_HISTORY"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_VISITS"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_MEDICAL_DATA_VITAL_SIGNS"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.WRITE_MEDICAL_DATA"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.READ_ACTIVITY_INTENSITY"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.HealthPermissions.WRITE_ACTIVITY_INTENSITY"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ActivityIntensityRecord"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
   <symbol
     jar="framework-healthfitness"
     pattern="android.health.connect.datatypes.ActivityIntensityRecord.Builder"
-    sdks="U-ext,V-ext" />
+    sdks="U-ext,V-ext,B-ext" />
 
 </sdk-extensions-info>
```

