```diff
diff --git a/avb/Android.bp b/avb/Android.bp
index b572968..ee70dfa 100644
--- a/avb/Android.bp
+++ b/avb/Android.bp
@@ -76,10 +76,12 @@ cc_test {
         "vts_gki_compliance_test.cpp",
         "kernel_version_test.cpp",
         "kernel_version_matrix.proto",
+        "ogki_builds_utils.cpp",
     ],
     static_libs: [
         "libgmock",
         "libkver",
+        "libtinyxml2",
         "libvintf",
         "libvts_vintf_test_common",
     ],
@@ -107,5 +109,8 @@ filegroup {
 
 filegroup {
     name: "vts_gki_compliance_test_cpp",
-    srcs: ["vts_gki_compliance_test.cpp"],
+    srcs: [
+        "vts_gki_compliance_test.cpp",
+        "ogki_builds_utils.cpp",
+    ],
 }
diff --git a/avb/ogki_builds_utils.cpp b/avb/ogki_builds_utils.cpp
new file mode 100644
index 0000000..c417cba
--- /dev/null
+++ b/avb/ogki_builds_utils.cpp
@@ -0,0 +1,81 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <string>
+#include <string_view>
+#include <unordered_map>
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/result.h>
+#include <tinyxml2.h>
+#include <utils/Errors.h>
+
+#include "ogki_builds_utils.h"
+
+using android::base::Result;
+using android::base::ResultError;
+
+namespace ogki {
+
+const std::string approved_builds_config_path =
+    "/system/etc/kernel/approved-ogki-builds.xml";
+
+Result<std::unordered_map<std::string, BuildInfo>> GetApprovedBuilds(
+    std::string_view branch_name) {
+  std::string approved_builds_content;
+  if (!android::base::ReadFileToString(approved_builds_config_path,
+                                       &approved_builds_content)) {
+    return ResultError("Failed to read approved OGKI builds config at " +
+                           approved_builds_config_path,
+                       -errno);
+  }
+
+  tinyxml2::XMLDocument approved_builds_xml;
+  if (auto xml_error =
+          approved_builds_xml.Parse(approved_builds_content.c_str());
+      xml_error != tinyxml2::XMLError::XML_SUCCESS) {
+    return ResultError(
+        std::format("Failed to parse approved builds config: {}",
+                    tinyxml2::XMLDocument::ErrorIDToName(xml_error)),
+        android::UNKNOWN_ERROR);
+  }
+
+  tinyxml2::XMLElement* branch_element = nullptr;
+  const auto ogki_element = approved_builds_xml.RootElement();
+  for (auto branch = ogki_element->FirstChildElement("branch"); branch;
+       branch = branch->NextSiblingElement("branch")) {
+    if (branch->Attribute("name", branch_name.data())) {
+      branch_element = branch;
+      break;
+    }
+  }
+  if (!branch_element) {
+    return ResultError(
+        std::format("Branch '{}' not found in approved builds config",
+                    branch_name.data()),
+        android::NAME_NOT_FOUND);
+  }
+
+  std::unordered_map<std::string, BuildInfo> approved_builds;
+  for (auto build = branch_element->FirstChildElement("build"); build;
+       build = build->NextSiblingElement("build")) {
+    approved_builds.emplace(build->Attribute("id"), BuildInfo{});
+  }
+  return approved_builds;
+}
+
+}  // namespace ogki
diff --git a/avb/ogki_builds_utils.h b/avb/ogki_builds_utils.h
new file mode 100644
index 0000000..bd01ca5
--- /dev/null
+++ b/avb/ogki_builds_utils.h
@@ -0,0 +1,30 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <string>
+#include <string_view>
+#include <unordered_map>
+
+#include <android-base/result.h>
+
+namespace ogki {
+
+struct BuildInfo {};
+
+android::base::Result<std::unordered_map<std::string, BuildInfo>>
+GetApprovedBuilds(std::string_view branch_name);
+
+}  // namespace ogki
diff --git a/avb/vts_gki_compliance_test.cpp b/avb/vts_gki_compliance_test.cpp
index f79d992..3ac66a8 100644
--- a/avb/vts_gki_compliance_test.cpp
+++ b/avb/vts_gki_compliance_test.cpp
@@ -14,6 +14,10 @@
  * limitations under the License.
  */
 
+#include <cstdint>
+#include <ranges>
+#include <regex>
+#include <unordered_map>
 #include <vector>
 
 #include <android-base/file.h>
@@ -24,18 +28,33 @@
 #include <bootimg.h>
 #include <fs_avb/fs_avb_util.h>
 #include <gtest/gtest.h>
+#include <kver/kernel_release.h>
 #include <libavb/libavb.h>
+#include <openssl/sha.h>
 #include <storage_literals/storage_literals.h>
 #include <vintf/VintfObject.h>
 #include <vintf/parse_string.h>
 
 #include "gsi_validation_utils.h"
+#include "ogki_builds_utils.h"
 
 using namespace std::literals;
 using namespace android::storage_literals;
 
 namespace {
 
+std::string sha256(const std::string_view content) {
+  unsigned char hash[SHA256_DIGEST_LENGTH];
+  const unsigned char *data = (const unsigned char *)content.data();
+  SHA256(data, content.size(), hash);
+  std::ostringstream os;
+  os << std::hex << std::setfill('0');
+  for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
+    os << std::setw(2) << static_cast<unsigned int>(hash[i]);
+  }
+  return os.str();
+}
+
 std::string GetBlockDevicePath(const std::string &name) {
   return "/dev/block/by-name/" + name + fs_mgr_get_slot_suffix();
 }
@@ -372,6 +391,8 @@ void VerifyImageDescriptor(
 }  // namespace
 
 class GkiComplianceTest : public testing::Test {
+  static const std::regex ogkiUnameRegex;
+
  protected:
   void SetUp() override {
     // Fetch device runtime information.
@@ -391,12 +412,27 @@ class GkiComplianceTest : public testing::Test {
     GTEST_LOG_(INFO) << "Product first API level: " << product_first_api_level;
   }
 
+  bool IsOgkiBuild() const;
   bool ShouldSkipGkiComplianceV2();
 
   std::shared_ptr<const android::vintf::RuntimeInfo> runtime_info;
   int product_first_api_level;
 };
 
+const std::regex GkiComplianceTest::ogkiUnameRegex =
+    std::regex("-abogki[0-9]+(-|$)");
+
+bool GkiComplianceTest::IsOgkiBuild() const {
+  /* Android release version should at least be android14 for OGKI build. */
+  const auto kernel_release = android::kver::KernelRelease::Parse(
+      runtime_info->osRelease(), /* allow_suffix = */ true);
+  if (!kernel_release.has_value() || kernel_release->android_release() < 14) {
+    return false;
+  }
+
+  return std::regex_search(runtime_info->osRelease(), ogkiUnameRegex);
+}
+
 bool GkiComplianceTest::ShouldSkipGkiComplianceV2() {
   /* Skip for devices if the kernel version is not >= 5.10. */
   if (runtime_info->kernelVersion().dropMinor() <
@@ -410,6 +446,11 @@ bool GkiComplianceTest::ShouldSkipGkiComplianceV2() {
     GTEST_LOG_(INFO) << "Exempt from GKI 2.0 test on pre-S launched devices";
     return true;
   }
+  /* Skip for OGKI kernel builds. */
+  if (IsOgkiBuild()) {
+    GTEST_LOG_(INFO) << "Exempt from GKI 2.0 test on OGKI kernel";
+    return true;
+  }
   /*
    * Skip for automotive devices if the kernel version is not >= 5.15 or
    * the device is launched before Android T.
@@ -569,6 +610,32 @@ TEST_F(GkiComplianceTest, GkiComplianceV2_kernel) {
                                                 *generic_kernel_descriptor));
 }
 
+// Verify OGKI build is approved.
+TEST_F(GkiComplianceTest, OgkiCompliance) {
+  if (!IsOgkiBuild()) {
+    GTEST_SKIP() << "OGKI build not detected";
+  }
+
+  const auto kernel_release =
+      android::kver::KernelRelease::Parse(runtime_info->osRelease(),
+                                          /* allow_suffix = */ true);
+  ASSERT_TRUE(kernel_release.has_value())
+      << "Failed to parse the kernel release string: "
+      << runtime_info->osRelease();
+
+  auto branch =
+      std::format("android{}-{}.{}", kernel_release->android_release(),
+                  runtime_info->kernelVersion().version,
+                  runtime_info->kernelVersion().majorRev);
+  auto approved_builds_result = ogki::GetApprovedBuilds(branch);
+  ASSERT_TRUE(approved_builds_result.ok())
+      << "Failed to get approved OGKI builds: "
+      << approved_builds_result.error().message();
+
+  const auto uname_hash = sha256(runtime_info->osRelease());
+  EXPECT_TRUE(approved_builds_result.value().contains(uname_hash));
+}
+
 int main(int argc, char *argv[]) {
   ::testing::InitGoogleTest(&argc, argv);
   android::base::InitLogging(argv, android::base::StderrLogger);
```

