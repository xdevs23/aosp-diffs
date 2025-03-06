```diff
diff --git a/apexd/Android.bp b/apexd/Android.bp
index 261d882c..a402fdc8 100644
--- a/apexd/Android.bp
+++ b/apexd/Android.bp
@@ -85,6 +85,7 @@ cc_defaults {
         "libvintf",
     ],
     static_libs: [
+        "lib_apex_blocklist_proto",
         "lib_microdroid_metadata_proto",
         "libapex",
         "libavb",
@@ -94,8 +95,6 @@ cc_defaults {
         "libtinyxml2",
         "libverity_tree",
         "libvold_binder",
-        "libstatslog_apex",
-        "libstatssocket_lazy",
     ],
     whole_static_libs: ["libcom.android.sysprop.apex"],
 }
@@ -130,15 +129,21 @@ cc_binary {
         "libapex-deps",
         "libapexd-deps",
         "libapexservice-deps",
+        "libapexd_metrics_stats-deps",
     ],
     srcs: [
         "apexd_main.cpp",
     ],
+    shared_libs: [
+        "server_configurable_flags",
+        "brand_new_apex_flag_c_lib",
+    ],
     static_libs: [
         "libapex",
         "libapexd",
         "libapexd_checkpoint_vold",
         "libapexservice",
+        "libapexd_metrics_stats",
     ],
     init_rc: ["apexd.rc"],
     // Just like the init, apexd should be able to run without
@@ -186,9 +191,11 @@ cc_library_static {
         "libapexd-deps",
     ],
     srcs: [
+        "apex_blocklist.cpp",
         "apex_classpath.cpp",
         "apex_database.cpp",
         "apex_file_repository.cpp",
+        "apexd_brand_new_verifier.cpp",
         "apexd.cpp",
         "apexd_dm.cpp",
         "apexd_lifecycle.cpp",
@@ -208,9 +215,11 @@ cc_library_static {
     name: "libapexd_checkpoint_vold",
     defaults: ["apex_flags_defaults"],
     srcs: ["apexd_checkpoint_vold.cpp"],
-    static_libs: [
+    shared_libs: [
         "libbase",
         "libutils",
+    ],
+    static_libs: [
         "libvold_binder",
     ],
     export_include_dirs: ["."],
@@ -287,7 +296,7 @@ cc_library_static {
     export_include_dirs: ["."],
 }
 
-genrule {
+java_genrule {
     // Generates an apex which has a different manifest outside the filesystem
     // image.
     name: "gen_manifest_mismatch_apex",
@@ -307,7 +316,7 @@ genrule {
         "$(genDir)/apex.apexd_test_manifest_mismatch.apex",
 }
 
-genrule {
+java_genrule {
     // Generates an apex with a corrupted filesystem superblock, which should cause
     // Apex::Open to fail
     name: "gen_corrupt_superblock_apex",
@@ -326,7 +335,7 @@ genrule {
         "$(genDir)/apex.apexd_test_corrupt_superblock_apex.apex",
 }
 
-genrule {
+java_genrule {
     // Generates an apex with a corrupted filesystem image, which should cause
     // dm-verity verification to fail
     name: "gen_corrupt_apex",
@@ -345,7 +354,7 @@ genrule {
         "$(genDir)/apex.apexd_test_corrupt_apex.apex",
 }
 
-genrule {
+java_genrule {
     // Extract the root digest with avbtool
     name: "apex.apexd_test_digest",
     out: ["apex.apexd_test_digest.txt"],
@@ -356,7 +365,7 @@ genrule {
         "| cut -c 3-| tee $(out)",
 }
 
-genrule {
+java_genrule {
     // Extract the root digest with avbtool
     name: "apex.apexd_test_f2fs_digest",
     out: ["apex.apexd_test_f2fs_digest.txt"],
@@ -367,7 +376,7 @@ genrule {
         "| cut -c 3-| tee $(out)",
 }
 
-genrule {
+java_genrule {
     // Extract the root digest with avbtool
     name: "apex.apexd_test_erofs_digest",
     out: ["apex.apexd_test_erofs_digest.txt"],
@@ -378,7 +387,7 @@ genrule {
         "| cut -c 3-| tee $(out)",
 }
 
-genrule {
+java_genrule {
     // Generates an apex which has same module name as apex.apexd_test.apex, but
     // is actually signed with a different key.
     name: "gen_key_mismatch_apex",
@@ -398,7 +407,7 @@ genrule {
         "$(genDir)/apex.apexd_test_different_key.apex",
 }
 
-genrule {
+java_genrule {
     // Generates an apex which has same module name as apex.apexd_test.apex, but
     // is actually signed with a different key.
     name: "gen_key_mismatch_apex_v2",
@@ -419,7 +428,7 @@ genrule {
         "$(genDir)/apex.apexd_test_different_key_v2.apex",
 }
 
-genrule {
+java_genrule {
     // Generates an apex which has a different manifest outside the filesystem
     // image.
     name: "gen_manifest_mismatch_rebootless_apex",
@@ -439,7 +448,7 @@ genrule {
         "$(genDir)/test.rebootless_apex_manifest_mismatch.apex",
 }
 
-genrule {
+java_genrule {
     // Generates an apex with a corrupted filesystem image, which should cause
     // dm-verity verification to fail
     name: "gen_corrupt_rebootless_apex",
@@ -471,6 +480,7 @@ cc_test {
         "-Wno-used-but-marked-unused",
     ],
     data: [
+        ":apex.apexd_bootstrap_test",
         ":apex.apexd_test",
         ":apex.apexd_test_erofs",
         ":apex.apexd_test_f2fs",
@@ -495,6 +505,9 @@ cc_test {
         ":gen_capex_without_apex",
         ":gen_capex_with_v2_apex",
         ":gen_key_mismatch_with_original_capex",
+        ":com.android.apex.brand.new",
+        ":com.android.apex.brand.new.v2",
+        ":com.android.apex.brand.new.v2.diffkey",
         ":com.android.apex.cts.shim.v1_prebuilt",
         ":com.android.apex.cts.shim.v2_prebuilt",
         ":com.android.apex.cts.shim.v2_wrong_sha_prebuilt",
@@ -512,6 +525,11 @@ cc_test {
         ":gen_manifest_mismatch_compressed_apex_v2",
         "apexd_testdata/com.android.apex.test_package.avbpubkey",
         "apexd_testdata/com.android.apex.compressed.avbpubkey",
+        "apexd_testdata/com.android.apex.brand.new.avbpubkey",
+        "apexd_testdata/com.android.apex.brand.new.another.avbpubkey",
+        "apexd_testdata/com.android.apex.brand.new.renamed.avbpubkey",
+        "apexd_testdata/blocklist.json",
+        "apexd_testdata/blocklist_invalid.json",
         ":com.android.apex.test.sharedlibs_generated.v1.libvX_prebuilt",
         ":com.android.apex.test.sharedlibs_generated.v2.libvY_prebuilt",
         ":test.rebootless_apex_v1",
@@ -528,13 +546,17 @@ cc_test {
         ":test.rebootless_apex_remove_native_lib",
         ":test.rebootless_apex_app_in_apex",
         ":test.rebootless_apex_priv_app_in_apex",
+        ":com.android.apex.vendor.foo",
+        ":com.android.apex.vendor.foo.with_vintf",
     ],
     srcs: [
+        "apex_blocklist_test.cpp",
         "apex_classpath_test.cpp",
         "apex_database_test.cpp",
         "apex_file_test.cpp",
         "apex_file_repository_test.cpp",
         "apex_manifest_test.cpp",
+        "apexd_brand_new_verifier_test.cpp",
         "apexd_test.cpp",
         "apexd_session_test.cpp",
         "apexd_utils_test.cpp",
@@ -547,13 +569,11 @@ cc_test {
         "libapexd",
         "libfstab",
         "libgmock",
-        "libstatslog_apex",
     ],
     shared_libs: [
         "libbinder",
         "libfs_mgr",
         "libutils",
-        "libstatssocket",
     ],
     generated_sources: ["apex-info-list-tinyxml"],
     test_suites: ["device-tests"],
@@ -672,27 +692,44 @@ xsd_config {
     root_elements: ["apex-info-list"],
 }
 
+cc_defaults {
+    name: "libapexd_metrics_stats-deps",
+    shared_libs: [
+        "libbase",
+        "libbinder",
+        "libutils",
+        "liblog",
+    ],
+    static_libs: [
+        "android.os.statsbootstrap_aidl-cpp",
+        "libstatsbootstrap",
+    ],
+}
+
 cc_library_static {
-    name: "libstatslog_apex",
-    generated_sources: ["statslog_apex.cpp"],
-    generated_headers: ["statslog_apex.h"],
+    name: "libapexd_metrics_stats",
+    defaults: [
+        "libapexd_metrics_stats-deps",
+    ],
+    srcs: [
+        "apexd_metrics_stats.cpp",
+    ],
+    generated_sources: [
+        "statslog_apex.cpp",
+    ],
+    generated_headers: [
+        "statslog_apex.h",
+    ],
     cflags: [
         "-Wall",
         "-Werror",
     ],
-    export_generated_headers: ["statslog_apex.h"],
-    static_libs: [
-        "libcutils",
-        "liblog",
-        "libstatssocket_lazy",
-        "libutils",
-    ],
 }
 
 genrule {
     name: "statslog_apex.h",
     tools: ["stats-log-api-gen"],
-    cmd: "$(location stats-log-api-gen) --header $(genDir)/statslog_apex.h --module apex --namespace stats,apex",
+    cmd: "$(location stats-log-api-gen) --header $(genDir)/statslog_apex.h --module apex --namespace stats,apex --bootstrap",
     out: [
         "statslog_apex.h",
     ],
@@ -701,8 +738,20 @@ genrule {
 genrule {
     name: "statslog_apex.cpp",
     tools: ["stats-log-api-gen"],
-    cmd: "$(location stats-log-api-gen) --cpp $(genDir)/statslog_apex.cpp --module apex --namespace stats,apex --importHeader statslog_apex.h",
+    cmd: "$(location stats-log-api-gen) --cpp $(genDir)/statslog_apex.cpp --module apex --namespace stats,apex --importHeader statslog_apex.h --bootstrap",
     out: [
         "statslog_apex.cpp",
     ],
 }
+
+aconfig_declarations {
+    name: "enable_brand_new_apex",
+    package: "com.android.apex.flags",
+    srcs: ["apexd.aconfig"],
+    container: "system",
+}
+
+cc_aconfig_library {
+    name: "brand_new_apex_flag_c_lib",
+    aconfig_declarations: "enable_brand_new_apex",
+}
diff --git a/apexd/ApexInfoList.xsd b/apexd/ApexInfoList.xsd
index a327fc68..ba6ffce9 100644
--- a/apexd/ApexInfoList.xsd
+++ b/apexd/ApexInfoList.xsd
@@ -23,6 +23,16 @@
     </xs:complexType>
   </xs:element>
 
+  <xs:simpleType name="Partition">
+    <xs:restriction base="xs:string">
+        <xs:pattern value="SYSTEM"/>
+        <xs:pattern value="SYSTEM_EXT"/>
+        <xs:pattern value="PRODUCT"/>
+        <xs:pattern value="VENDOR"/>
+        <xs:pattern value="ODM"/>
+    </xs:restriction>
+  </xs:simpleType>
+
   <xs:element name="apex-info">
     <xs:complexType>
       <xs:attribute name="moduleName" type="xs:string" use="required"/>
@@ -34,6 +44,7 @@
       <xs:attribute name="isActive" type="xs:boolean" use="required"/>
       <xs:attribute name="lastUpdateMillis" type="xs:long"/>
       <xs:attribute name="provideSharedApexLibs" type="xs:boolean" use="required"/>
+      <xs:attribute name="partition" type="Partition" use="required"/>
     </xs:complexType>
   </xs:element>
 </xs:schema>
diff --git a/apexd/aidl/android/apex/ApexInfo.aidl b/apexd/aidl/android/apex/ApexInfo.aidl
index fb590f2a..aa2ae95e 100644
--- a/apexd/aidl/android/apex/ApexInfo.aidl
+++ b/apexd/aidl/android/apex/ApexInfo.aidl
@@ -38,4 +38,18 @@ parcelable ApexInfo {
     // Note: this field can only be set to true during boot, after boot is completed
     //  (sys.boot_completed = 1) value of this field will always be false.
     boolean activeApexChanged;
+
+    /**
+    * The partition that an APEX is pre-installed in or maps to.
+    */
+    enum Partition {
+      SYSTEM,
+      SYSTEM_EXT,
+      PRODUCT,
+      VENDOR,
+      ODM
+    }
+
+    // For pre-installed APEX, this is the partition where it is pre-installed. For brand-new APEX, this is the partition where its credential is pre-installed.
+    Partition partition;
 }
diff --git a/apexd/aidl/android/apex/IApexService.aidl b/apexd/aidl/android/apex/IApexService.aidl
index db2c578e..c65bf7ab 100644
--- a/apexd/aidl/android/apex/IApexService.aidl
+++ b/apexd/aidl/android/apex/IApexService.aidl
@@ -83,39 +83,12 @@ interface IApexService {
     */
    void resumeRevertIfNeeded();
    /**
-    * Forces apexd to remount all active packages.
-    *
-    * This call is mostly useful for speeding up development of APEXes.
-    * Instead of going through a full APEX installation that requires a reboot,
-    * developers can incorporate this method in much faster `adb sync` based
-    * workflow:
-    *
-    * 1. adb shell stop
-    * 2. adb sync
-    * 3. adb shell cmd -w apexservice remountPackages
-    * 4. adb shell start
-    *
-    * Note, that for an APEX package will be successfully remounted only if
-    * there are no alive processes holding a reference to it.
-    *
-    * Not meant for use outside of testing. This call will not be functional
-    * on user builds. Only root is allowed to call this method.
-    */
-   void remountPackages();
-   /**
-    * Forces apexd to recollect pre-installed data from the given |paths|.
-    *
-    * Not meant for use outside of testing. This call will not be functional
-    * on user builds. Only root is allowed to call this method.
-    */
-   void recollectPreinstalledData(in @utf8InCpp List<String> paths);
-   /**
-    * Forces apexd to recollect data apex from the given |path|.
+    * Forces apexd to recollect pre-installed data from all the supported built-in dirs.
     *
     * Not meant for use outside of testing. This call will not be functional
     * on user builds. Only root is allowed to call this method.
     */
-   void recollectDataApex(in @utf8InCpp String path, in@utf8InCpp String decompression_dir);
+   void recollectPreinstalledData();
 
    /**
     * Informs apexd that the boot has completed.
diff --git a/apexd/apex-info-list-api/current.txt b/apexd/apex-info-list-api/current.txt
index 633d2571..a1d9d018 100644
--- a/apexd/apex-info-list-api/current.txt
+++ b/apexd/apex-info-list-api/current.txt
@@ -8,6 +8,7 @@ package com.android.apex {
     method public long getLastUpdateMillis();
     method public String getModuleName();
     method public String getModulePath();
+    method public String getPartition();
     method public String getPreinstalledModulePath();
     method public boolean getProvideSharedApexLibs();
     method public long getVersionCode();
@@ -17,6 +18,7 @@ package com.android.apex {
     method public void setLastUpdateMillis(long);
     method public void setModuleName(String);
     method public void setModulePath(String);
+    method public void setPartition(String);
     method public void setPreinstalledModulePath(String);
     method public void setProvideSharedApexLibs(boolean);
     method public void setVersionCode(long);
diff --git a/apexd/apex_blocklist.cpp b/apexd/apex_blocklist.cpp
new file mode 100644
index 00000000..a319f101
--- /dev/null
+++ b/apexd/apex_blocklist.cpp
@@ -0,0 +1,66 @@
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
+#include "apex_blocklist.h"
+
+#include <android-base/file.h>
+#include <google/protobuf/util/json_util.h>
+
+#include <memory>
+#include <string>
+
+using android::base::Error;
+using android::base::Result;
+using ::apex::proto::ApexBlocklist;
+
+namespace android::apex {
+
+Result<ApexBlocklist> ParseBlocklist(const std::string& content) {
+  ApexBlocklist apex_blocklist;
+  google::protobuf::util::JsonParseOptions options;
+  options.ignore_unknown_fields = true;
+  auto parse_result = google::protobuf::util::JsonStringToMessage(
+      content, &apex_blocklist, options);
+  if (!parse_result.ok()) {
+    return Error() << "Can't parse APEX blocklist: " << parse_result.message();
+  }
+
+  for (const auto& apex : apex_blocklist.blocked_apex()) {
+    // Verifying required fields.
+    // name
+    if (apex.name().empty()) {
+      return Error() << "Missing required field \"name\" from APEX blocklist.";
+    }
+
+    // version
+    if (apex.version() <= 0) {
+      return Error() << "Missing positive value for field \"version\" "
+                        "from APEX blocklist.";
+    }
+  }
+
+  return apex_blocklist;
+}
+
+Result<ApexBlocklist> ReadBlocklist(const std::string& path) {
+  std::string content;
+  if (!android::base::ReadFileToString(path, &content)) {
+    return Error() << "Failed to read blocklist file: " << path;
+  }
+  return ParseBlocklist(content);
+}
+
+}  // namespace android::apex
diff --git a/apexd/apex_blocklist.h b/apexd/apex_blocklist.h
new file mode 100644
index 00000000..60095bae
--- /dev/null
+++ b/apexd/apex_blocklist.h
@@ -0,0 +1,35 @@
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
+#pragma once
+
+#include <android-base/result.h>
+
+#include <string>
+
+#include "apex_blocklist.pb.h"
+
+namespace android::apex {
+// Parses and validates APEX blocklist. The blocklist is used only to block
+// brand-new APEX. A brand-new APEX is blocked when the name exactly matches the
+// block item and the version is smaller than or equal to the configured
+// version.
+android::base::Result<::apex::proto::ApexBlocklist> ParseBlocklist(
+    const std::string& content);
+// Reads and parses APEX blocklist from the file on disk.
+android::base::Result<::apex::proto::ApexBlocklist> ReadBlocklist(
+    const std::string& path);
+}  // namespace android::apex
diff --git a/apexd/apex_blocklist_test.cpp b/apexd/apex_blocklist_test.cpp
new file mode 100644
index 00000000..c26778a3
--- /dev/null
+++ b/apexd/apex_blocklist_test.cpp
@@ -0,0 +1,76 @@
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
+#include "apex_blocklist.h"
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <google/protobuf/util/json_util.h>
+#include <gtest/gtest.h>
+
+#include <algorithm>
+
+using ::apex::proto::ApexBlocklist;
+
+namespace android::apex {
+
+namespace {
+
+std::string ToString(const ApexBlocklist& blocklist) {
+  std::string out;
+  google::protobuf::util::MessageToJsonString(blocklist, &out);
+  return out;
+}
+
+}  // namespace
+
+TEST(ApexBlocklistTest, SimpleValid) {
+  ApexBlocklist blocklist;
+  ApexBlocklist::ApexItem* item = blocklist.add_blocked_apex();
+  item->set_name("com.android.example.apex");
+  item->set_version(1);
+  auto apex_blocklist = ParseBlocklist(ToString(blocklist));
+  ASSERT_RESULT_OK(apex_blocklist);
+  EXPECT_EQ(1, apex_blocklist->blocked_apex().size());
+  EXPECT_EQ("com.android.example.apex", apex_blocklist->blocked_apex(0).name());
+  EXPECT_EQ(1, apex_blocklist->blocked_apex(0).version());
+}
+
+TEST(ApexBlocklistTest, NameMissing) {
+  ApexBlocklist blocklist;
+  ApexBlocklist::ApexItem* item = blocklist.add_blocked_apex();
+  item->set_version(1);
+  auto apex_blocklist = ParseBlocklist(ToString(blocklist));
+  ASSERT_FALSE(apex_blocklist.ok());
+  EXPECT_EQ(apex_blocklist.error().message(),
+            std::string("Missing required field \"name\" from APEX blocklist."))
+      << apex_blocklist.error();
+}
+
+TEST(ApexBlocklistTest, VersionMissing) {
+  ApexBlocklist blocklist;
+  ApexBlocklist::ApexItem* item = blocklist.add_blocked_apex();
+  item->set_name("com.android.example.apex");
+  auto apex_blocklist = ParseBlocklist(ToString(blocklist));
+  ASSERT_FALSE(apex_blocklist.ok());
+  EXPECT_EQ(
+      apex_blocklist.error().message(),
+      std::string(
+          "Missing positive value for field \"version\" from APEX blocklist."))
+      << apex_blocklist.error();
+}
+
+}  // namespace android::apex
diff --git a/apexd/apex_constants.h b/apexd/apex_constants.h
index aea592f3..f2562ca7 100644
--- a/apexd/apex_constants.h
+++ b/apexd/apex_constants.h
@@ -16,13 +16,17 @@
 
 #pragma once
 
+#include <chrono>
 #include <string>
+#include <unordered_map>
 #include <unordered_set>
 #include <vector>
 
 namespace android {
 namespace apex {
 
+enum class ApexPartition { System, SystemExt, Product, Vendor, Odm };
+
 static constexpr const char* kApexDataDir = "/data/apex";
 static constexpr const char* kActiveApexPackagesDataDir = "/data/apex/active";
 static constexpr const char* kApexBackupDir = "/data/apex/backup";
@@ -30,10 +34,19 @@ static constexpr const char* kApexDecompressedDir = "/data/apex/decompressed";
 static constexpr const char* kOtaReservedDir = "/data/apex/ota_reserved";
 static constexpr const char* kApexPackageSystemDir = "/system/apex";
 static constexpr const char* kApexPackageSystemExtDir = "/system_ext/apex";
+static constexpr const char* kApexPackageProductDir = "/product/apex";
 static constexpr const char* kApexPackageVendorDir = "/vendor/apex";
 static constexpr const char* kApexPackageOdmDir = "/odm/apex";
+static const std::unordered_map<ApexPartition, std::string>
+    kBuiltinApexPackageDirs = {
+        {ApexPartition::System, kApexPackageSystemDir},
+        {ApexPartition::SystemExt, kApexPackageSystemExtDir},
+        {ApexPartition::Product, kApexPackageProductDir},
+        {ApexPartition::Vendor, kApexPackageVendorDir},
+        {ApexPartition::Odm, kApexPackageOdmDir},
+};
 static const std::vector<std::string> kApexPackageBuiltinDirs = {
-    kApexPackageSystemDir, kApexPackageSystemExtDir, "/product/apex",
+    kApexPackageSystemDir, kApexPackageSystemExtDir, kApexPackageProductDir,
     kApexPackageVendorDir, kApexPackageOdmDir};
 static constexpr const char* kApexRoot = "/apex";
 static constexpr const char* kStagedSessionsDir = "/data/app-staging";
@@ -82,6 +95,28 @@ static constexpr const char* kApexAllReadyProp = "apex.all.ready";
 static constexpr const char* kCtlApexLoadSysprop = "ctl.apex_load";
 static constexpr const char* kCtlApexUnloadSysprop = "ctl.apex_unload";
 
+// Constants for brand-new APEX
+static constexpr const char* kBrandNewApexPublicKeySuffix = ".avbpubkey";
+static constexpr const char* kBrandNewApexBlocklistFileName = "blocklist.json";
+static constexpr const char* kBrandNewApexConfigSystemDir =
+    "/system/etc/brand_new_apex";
+static constexpr const char* kBrandNewApexConfigSystemExtDir =
+    "/system_ext/etc/brand_new_apex";
+static constexpr const char* kBrandNewApexConfigProductDir =
+    "/product/etc/brand_new_apex";
+static constexpr const char* kBrandNewApexConfigVendorDir =
+    "/vendor/etc/brand_new_apex";
+static constexpr const char* kBrandNewApexConfigOdmDir =
+    "/odm/etc/brand_new_apex";
+static const std::unordered_map<ApexPartition, std::string>
+    kPartitionToBrandNewApexConfigDirs = {
+        {ApexPartition::System, kBrandNewApexConfigSystemDir},
+        {ApexPartition::SystemExt, kBrandNewApexConfigSystemExtDir},
+        {ApexPartition::Product, kBrandNewApexConfigProductDir},
+        {ApexPartition::Vendor, kBrandNewApexConfigVendorDir},
+        {ApexPartition::Odm, kBrandNewApexConfigOdmDir},
+};
+
 // Banned APEX names
 static const std::unordered_set<std::string> kBannedApexName = {
     kApexSharedLibsSubDir,  // To avoid conflicts with predefined
diff --git a/apexd/apex_file.h b/apexd/apex_file.h
index 56077bb5..86d032b1 100644
--- a/apexd/apex_file.h
+++ b/apexd/apex_file.h
@@ -46,6 +46,8 @@ class ApexFile {
   ApexFile() = delete;
   ApexFile(ApexFile&&) = default;
   ApexFile& operator=(ApexFile&&) = default;
+  ApexFile(const ApexFile&) = default;
+  ApexFile& operator=(const ApexFile&) = default;
 
   const std::string& GetPath() const { return apex_path_; }
   const std::optional<uint32_t>& GetImageOffset() const {
diff --git a/apexd/apex_file_repository.cpp b/apexd/apex_file_repository.cpp
index 45b48492..6b98ed7e 100644
--- a/apexd/apex_file_repository.cpp
+++ b/apexd/apex_file_repository.cpp
@@ -23,10 +23,14 @@
 #include <android-base/strings.h>
 #include <microdroid/metadata.h>
 
+#include <cstdint>
+#include <filesystem>
 #include <unordered_map>
 
+#include "apex_blocklist.h"
 #include "apex_constants.h"
 #include "apex_file.h"
+#include "apexd_brand_new_verifier.h"
 #include "apexd_utils.h"
 #include "apexd_vendor_apex.h"
 #include "apexd_verity.h"
@@ -35,6 +39,7 @@ using android::base::EndsWith;
 using android::base::Error;
 using android::base::GetProperty;
 using android::base::Result;
+using ::apex::proto::ApexBlocklist;
 
 namespace android {
 namespace apex {
@@ -57,7 +62,8 @@ std::string GetApexSelectFilenameFromProp(
   return "";
 }
 
-Result<void> ApexFileRepository::ScanBuiltInDir(const std::string& dir) {
+Result<void> ApexFileRepository::ScanBuiltInDir(const std::string& dir,
+                                                ApexPartition partition) {
   LOG(INFO) << "Scanning " << dir << " for pre-installed ApexFiles";
   if (access(dir.c_str(), F_OK) != 0 && errno == ENOENT) {
     LOG(WARNING) << dir << " does not exist. Skipping";
@@ -96,8 +102,9 @@ Result<void> ApexFileRepository::ScanBuiltInDir(const std::string& dir) {
                    << apex_file->GetPath();
         continue;
       }
-      if (enforce_multi_install_partition_ && !InVendorPartition(path) &&
-          !InOdmPartition(path)) {
+      if (enforce_multi_install_partition_ &&
+          partition != ApexPartition::Vendor &&
+          partition != ApexPartition::Odm) {
         LOG(ERROR) << "Multi-install APEX " << path
                    << " can only be preinstalled on /{odm,vendor}/apex/.";
         continue;
@@ -113,6 +120,7 @@ Result<void> ApexFileRepository::ScanBuiltInDir(const std::string& dir) {
         if (auto it = pre_installed_store_.find(name);
             it != pre_installed_store_.end()) {
           pre_installed_store_.erase(it);
+          partition_store_.erase(name);
         }
         continue;
       }
@@ -123,6 +131,7 @@ Result<void> ApexFileRepository::ScanBuiltInDir(const std::string& dir) {
                   << name;
         // Add the APEX file to the store if its filename matches the property.
         pre_installed_store_.emplace(name, std::move(*apex_file));
+        partition_store_.emplace(name, partition);
       } else {
         LOG(INFO) << "Skipping APEX at path " << path
                   << " because it does not match expected multi-install"
@@ -135,22 +144,9 @@ Result<void> ApexFileRepository::ScanBuiltInDir(const std::string& dir) {
     auto it = pre_installed_store_.find(name);
     if (it == pre_installed_store_.end()) {
       pre_installed_store_.emplace(name, std::move(*apex_file));
+      partition_store_.emplace(name, partition);
     } else if (it->second.GetPath() != apex_file->GetPath()) {
-      auto level = base::FATAL;
-      if (ignore_duplicate_apex_definitions_) {
-        level = base::INFO;
-      }
-      // On some development (non-REL) builds the VNDK apex could be in /vendor.
-      // When testing CTS-on-GSI on these builds, there would be two VNDK apexes
-      // in the system, one in /system and one in /vendor.
-      static constexpr char kVndkApexModuleNamePrefix[] = "com.android.vndk.";
-      static constexpr char kPlatformVersionCodenameProperty[] =
-          "ro.build.version.codename";
-      if (android::base::StartsWith(name, kVndkApexModuleNamePrefix) &&
-          GetProperty(kPlatformVersionCodenameProperty, "REL") != "REL") {
-        level = android::base::INFO;
-      }
-      LOG(level) << "Found two apex packages " << it->second.GetPath()
+      LOG(FATAL) << "Found two apex packages " << it->second.GetPath()
                  << " and " << apex_file->GetPath()
                  << " with the same module name " << name;
     } else if (it->second.GetBundledPublicKey() !=
@@ -169,9 +165,10 @@ ApexFileRepository& ApexFileRepository::GetInstance() {
 }
 
 android::base::Result<void> ApexFileRepository::AddPreInstalledApex(
-    const std::vector<std::string>& prebuilt_dirs) {
-  for (const auto& dir : prebuilt_dirs) {
-    if (auto result = ScanBuiltInDir(dir); !result.ok()) {
+    const std::unordered_map<ApexPartition, std::string>&
+        partition_to_prebuilt_dirs) {
+  for (const auto& [partition, dir] : partition_to_prebuilt_dirs) {
+    if (auto result = ScanBuiltInDir(dir, partition); !result.ok()) {
       return result.error();
     }
   }
@@ -305,6 +302,9 @@ Result<int> ApexFileRepository::AddBlockApex(
                      << it->second.GetPath();
     }
     store.emplace(name, std::move(*apex_file));
+    // NOTE: We consider block APEXes are SYSTEM. APEX Config should be extended
+    //       to support non-system block APEXes.
+    partition_store_.emplace(name, ApexPartition::System);
 
     ret++;
   }
@@ -336,7 +336,26 @@ Result<void> ApexFileRepository::AddDataApex(const std::string& data_dir) {
     }
 
     const std::string& name = apex_file->GetManifest().name();
-    if (!HasPreInstalledVersion(name)) {
+    auto preinstalled = pre_installed_store_.find(name);
+    if (preinstalled != pre_installed_store_.end()) {
+      if (preinstalled->second.GetBundledPublicKey() !=
+          apex_file->GetBundledPublicKey()) {
+        // Ignore data apex if public key doesn't match with pre-installed apex
+        LOG(ERROR) << "Skipping " << file
+                   << " : public key doesn't match pre-installed one";
+        continue;
+      }
+    } else if (ApexFileRepository::IsBrandNewApexEnabled()) {
+      auto verified_partition =
+          VerifyBrandNewPackageAgainstPreinstalled(*apex_file);
+      if (!verified_partition.ok()) {
+        LOG(ERROR) << "Skipping " << file << " : "
+                   << verified_partition.error();
+        continue;
+      }
+      // Stores partition for already-verified brand-new APEX.
+      partition_store_.emplace(name, *verified_partition);
+    } else {
       LOG(ERROR) << "Skipping " << file << " : no preinstalled apex";
       // Ignore data apex without corresponding pre-installed apex
       continue;
@@ -350,15 +369,6 @@ Result<void> ApexFileRepository::AddDataApex(const std::string& data_dir) {
                    << " the multi-installed preinstalled version, if possible.";
     }
 
-    auto pre_installed_public_key = GetPublicKey(name);
-    if (!pre_installed_public_key.ok() ||
-        apex_file->GetBundledPublicKey() != *pre_installed_public_key) {
-      // Ignore data apex if public key doesn't match with pre-installed apex
-      LOG(ERROR) << "Skipping " << file
-                 << " : public key doesn't match pre-installed one";
-      continue;
-    }
-
     if (EndsWith(apex_file->GetPath(), kDecompressedApexPackageSuffix)) {
       LOG(WARNING) << "Skipping " << file
                    << " : Non-decompressed APEX should not have "
@@ -384,6 +394,62 @@ Result<void> ApexFileRepository::AddDataApex(const std::string& data_dir) {
   return {};
 }
 
+Result<void> ApexFileRepository::AddBrandNewApexCredentialAndBlocklist(
+    const std::unordered_map<ApexPartition, std::string>&
+        partition_to_dir_map) {
+  for (const auto& [partition, dir] : partition_to_dir_map) {
+    LOG(INFO)
+        << "Scanning " << dir
+        << " for pre-installed public keys and blocklists of brand-new APEX";
+    if (access(dir.c_str(), F_OK) != 0 && errno == ENOENT) {
+      continue;
+    }
+
+    std::vector<std::string> all_credential_files =
+        OR_RETURN(FindFilesBySuffix(dir, {kBrandNewApexPublicKeySuffix}));
+    for (const std::string& credential_path : all_credential_files) {
+      std::string content;
+      CHECK(android::base::ReadFileToString(credential_path, &content));
+      const auto& [it, inserted] =
+          brand_new_apex_pubkeys_.emplace(content, partition);
+      CHECK(inserted || it->second == partition)
+          << "Duplicate public keys are found in different partitions.";
+    }
+
+    const std::string& blocklist_path =
+        std::filesystem::path(dir) / kBrandNewApexBlocklistFileName;
+    const auto blocklist_exists = OR_RETURN(PathExists(blocklist_path));
+    if (!blocklist_exists) {
+      continue;
+    }
+
+    std::unordered_map<std::string, int64_t> apex_name_to_version;
+    ApexBlocklist blocklist = OR_RETURN(ReadBlocklist(blocklist_path));
+    for (const auto& block_item : blocklist.blocked_apex()) {
+      const auto& [it, inserted] =
+          apex_name_to_version.emplace(block_item.name(), block_item.version());
+      CHECK(inserted) << "Duplicate APEX names are found in blocklist.";
+    }
+    brand_new_apex_blocked_version_.emplace(partition, apex_name_to_version);
+  }
+  return {};
+}
+
+Result<ApexPartition> ApexFileRepository::GetPartition(
+    const ApexFile& apex) const {
+  const std::string& name = apex.GetManifest().name();
+  auto it = partition_store_.find(name);
+  if (it != partition_store_.end()) {
+    return it->second;
+  }
+
+  // Supports staged but not-yet-activated brand-new APEX.
+  if (!ApexFileRepository::IsBrandNewApexEnabled()) {
+    return Error() << "No preinstalled data found for package " << name;
+  }
+  return VerifyBrandNewPackageAgainstPreinstalled(apex);
+}
+
 // TODO(b/179497746): remove this method when we add api for fetching ApexFile
 //  by name
 Result<const std::string> ApexFileRepository::GetPublicKey(
@@ -488,6 +554,30 @@ std::vector<ApexFileRef> ApexFileRepository::GetDataApexFiles() const {
   return result;
 }
 
+std::optional<ApexPartition>
+ApexFileRepository::GetBrandNewApexPublicKeyPartition(
+    const std::string& public_key) const {
+  auto it = brand_new_apex_pubkeys_.find(public_key);
+  if (it == brand_new_apex_pubkeys_.end()) {
+    return std::nullopt;
+  }
+  return it->second;
+}
+
+std::optional<int64_t> ApexFileRepository::GetBrandNewApexBlockedVersion(
+    ApexPartition partition, const std::string& apex_name) const {
+  auto it = brand_new_apex_blocked_version_.find(partition);
+  if (it == brand_new_apex_blocked_version_.end()) {
+    return std::nullopt;
+  }
+  const auto& apex_name_to_version = it->second;
+  auto itt = apex_name_to_version.find(apex_name);
+  if (itt == apex_name_to_version.end()) {
+    return std::nullopt;
+  }
+  return itt->second;
+}
+
 // Group pre-installed APEX and data APEX by name
 std::unordered_map<std::string, std::vector<ApexFileRef>>
 ApexFileRepository::AllApexFilesByName() const {
diff --git a/apexd/apex_file_repository.h b/apexd/apex_file_repository.h
index 18ea84c2..b1955229 100644
--- a/apexd/apex_file_repository.h
+++ b/apexd/apex_file_repository.h
@@ -28,8 +28,7 @@
 #include "apex_constants.h"
 #include "apex_file.h"
 
-namespace android {
-namespace apex {
+namespace android::apex {
 
 using ApexFileRef = std::reference_wrapper<const android::apex::ApexFile>;
 
@@ -45,33 +44,24 @@ class ApexFileRepository final {
   // c-tors and d-tor are exposed for testing.
   explicit ApexFileRepository(
       const std::string& decompression_dir = kApexDecompressedDir)
-      : decompression_dir_(decompression_dir){};
+      : decompression_dir_(decompression_dir) {}
   explicit ApexFileRepository(
       bool enforce_multi_install_partition,
       const std::vector<std::string>& multi_install_select_prop_prefixes)
       : multi_install_select_prop_prefixes_(multi_install_select_prop_prefixes),
-        enforce_multi_install_partition_(enforce_multi_install_partition){};
-
-  explicit ApexFileRepository(const std::string& decompression_dir,
-                              bool ignore_duplicate_apex_definitions)
-      : ignore_duplicate_apex_definitions_(ignore_duplicate_apex_definitions),
-        decompression_dir_(decompression_dir){};
-
-  ~ApexFileRepository() {
-    pre_installed_store_.clear();
-    data_store_.clear();
-  };
+        enforce_multi_install_partition_(enforce_multi_install_partition) {}
 
   // Returns a singletone instance of this class.
   static ApexFileRepository& GetInstance();
 
   // Populate instance by collecting pre-installed apex files from the given
-  // |prebuilt_dirs|.
+  // |partition_to_prebuilt_dirs|.
   // Note: this call is **not thread safe** and is expected to be performed in a
   // single thread during initialization of apexd. After initialization is
   // finished, all queries to the instance are thread safe.
   android::base::Result<void> AddPreInstalledApex(
-      const std::vector<std::string>& prebuilt_dirs);
+      const std::unordered_map<ApexPartition, std::string>&
+          partition_to_prebuilt_dirs);
 
   // Populate instance by collecting host-provided apex files via
   // |metadata_partition|. Host can provide its apexes to a VM instance via the
@@ -97,11 +87,30 @@ class ApexFileRepository final {
   // finished, all queries to the instance are thread safe.
   android::base::Result<void> AddDataApex(const std::string& data_dir);
 
+  // Populates instance by collecting pre-installed credential files (.avbpubkey
+  // for now) and blocklist files from the given directories. They are needed
+  // specifically for brand-new APEX.
+  // Note: this call is **not thread safe** and
+  // is expected to be performed in a single thread during initialization of
+  // apexd. After initialization is finished, all queries to the instance are
+  // thread safe.
+  android::base::Result<void> AddBrandNewApexCredentialAndBlocklist(
+      const std::unordered_map<ApexPartition, std::string>&
+          partition_to_dir_map);
+
+  // Returns the mapping partition of a specific apex.
+  // For pre-installed APEX, it is the partition where the pre-installed package
+  // resides. For brand-new APEX, it is the partition where the
+  // credentials to verify the package reside.
+  android::base::Result<ApexPartition> GetPartition(const ApexFile& apex) const;
+
   // Returns trusted public key for an apex with the given |name|.
   android::base::Result<const std::string> GetPublicKey(
       const std::string& name) const;
 
   // Returns path to the pre-installed version of an apex with the given |name|.
+  // For brand-new APEX, returns Error.
+  // For block APEX which is not set as factory, returns Error.
   android::base::Result<const std::string> GetPreinstalledPath(
       const std::string& name) const;
 
@@ -139,6 +148,18 @@ class ApexFileRepository final {
   // Returns reference to all data APEX on device
   std::vector<ApexFileRef> GetDataApexFiles() const;
 
+  // Returns the partition of the pre-installed public key which exactly matches
+  // the |public_key|.
+  std::optional<ApexPartition> GetBrandNewApexPublicKeyPartition(
+      const std::string& public_key) const;
+
+  // Returns the blocked version number of a specific brand-new APEX in a
+  // specific partition. The brand-new APEX is only allowed when its version is
+  // larger than the blocked version.
+  // Returns |std::nullopt| if the |apex_name| is not configured in blocklist.
+  std::optional<int64_t> GetBrandNewApexBlockedVersion(
+      ApexPartition partition, const std::string& apex_name) const;
+
   // Group all ApexFiles on device by their package name
   std::unordered_map<std::string, std::vector<ApexFileRef>> AllApexFilesByName()
       const;
@@ -152,14 +173,24 @@ class ApexFileRepository final {
   // using |HasDataVersion| function.
   ApexFileRef GetDataApex(const std::string& name) const;
 
+  // Returns if installation of brand-new APEX is enabled.
+  static inline bool IsBrandNewApexEnabled() { return enable_brand_new_apex_; };
+
+  // Enables installation of brand-new APEX.
+  static inline void EnableBrandNewApex() { enable_brand_new_apex_ = true; };
+
   // Clears ApexFileRepostiry.
   // Only use in tests.
   void Reset(const std::string& decompression_dir = kApexDecompressedDir) {
     pre_installed_store_.clear();
     data_store_.clear();
+    partition_store_.clear();
+    brand_new_apex_blocked_version_.clear();
+    brand_new_apex_pubkeys_.clear();
     block_apex_overrides_.clear();
     decompression_dir_ = decompression_dir;
     block_disk_path_.reset();
+    enable_brand_new_apex_ = false;
   }
 
  private:
@@ -170,11 +201,24 @@ class ApexFileRepository final {
   ApexFileRepository(ApexFileRepository&&) = delete;
 
   // Scans apexes in the given directory and adds collected data into
-  // |pre_installed_store_|.
-  android::base::Result<void> ScanBuiltInDir(const std::string& dir);
+  // |pre_installed_store_| and |partition_store_|.
+  android::base::Result<void> ScanBuiltInDir(const std::string& dir,
+                                             ApexPartition partition);
 
   std::unordered_map<std::string, ApexFile> pre_installed_store_, data_store_;
 
+  // Map from APEX name to their partition. For pre-installed APEX, this is the
+  // partition where it is pre-installed. For brand-new APEX, this is the
+  // partition where its credential is pre-installed.
+  std::unordered_map<std::string, ApexPartition> partition_store_;
+
+  // Blocked versions for brand-new APEX mapped by their holding partition.
+  std::unordered_map<ApexPartition, std::unordered_map<std::string, int64_t>>
+      brand_new_apex_blocked_version_;
+
+  // Map from trusted public keys for brand-new APEX to their holding partition.
+  std::unordered_map<std::string, ApexPartition> brand_new_apex_pubkeys_;
+
   // Multi-installed APEX name -> all encountered public keys for this APEX.
   std::unordered_map<std::string, std::unordered_set<std::string>>
       multi_install_public_keys_;
@@ -188,9 +232,8 @@ class ApexFileRepository final {
   // Only set false in tests.
   bool enforce_multi_install_partition_ = true;
 
-  // Ignore duplicate vendor APEX definitions, normally a duplicate definition
-  // is considered an error.
-  bool ignore_duplicate_apex_definitions_ = false;
+  // Disallows installation of brand-new APEX by default.
+  inline static bool enable_brand_new_apex_ = false;
 
   // Decompression directory which will be used to determine if apex is
   // decompressed or not
@@ -214,5 +257,4 @@ class ApexFileRepository final {
   std::unordered_map<std::string, BlockApexOverride> block_apex_overrides_;
 };
 
-}  // namespace apex
-}  // namespace android
+}  // namespace android::apex
diff --git a/apexd/apex_file_repository_test.cpp b/apexd/apex_file_repository_test.cpp
index 0166f0dc..067f5d11 100644
--- a/apexd/apex_file_repository_test.cpp
+++ b/apexd/apex_file_repository_test.cpp
@@ -30,7 +30,13 @@
 #include <filesystem>
 #include <string>
 
+#include "apex_blocklist.h"
+#include "apex_constants.h"
 #include "apex_file.h"
+#include "apexd.h"
+#include "apexd_brand_new_verifier.h"
+#include "apexd_metrics.h"
+#include "apexd_private.h"
 #include "apexd_test_utils.h"
 #include "apexd_verity.h"
 
@@ -46,6 +52,7 @@ using android::base::GetExecutableDirectory;
 using android::base::StringPrintf;
 using android::base::testing::Ok;
 using ::testing::ByRef;
+using ::testing::ContainerEq;
 using ::testing::Not;
 using ::testing::UnorderedElementsAre;
 
@@ -80,12 +87,14 @@ TEST(ApexFileRepositoryTest, InitializeSuccess) {
   fs::copy(GetTestFile("apex.apexd_test.apex"), built_in_dir.path);
   fs::copy(GetTestFile("apex.apexd_test_different_app.apex"),
            built_in_dir.path);
+  ApexPartition partition = ApexPartition::System;
 
   fs::copy(GetTestFile("apex.apexd_test.apex"), data_dir.path);
   fs::copy(GetTestFile("apex.apexd_test_different_app.apex"), data_dir.path);
 
   ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({built_in_dir.path}));
+  ASSERT_RESULT_OK(
+      instance.AddPreInstalledApex({{partition, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
   // Now test that apexes were scanned correctly;
@@ -112,6 +121,12 @@ TEST(ApexFileRepositoryTest, InitializeSuccess) {
       ASSERT_EQ(StringPrintf("%s/%s", data_dir.path, apex_name.c_str()), *ret);
     }
 
+    {
+      auto ret = instance.GetPartition(*apex);
+      ASSERT_RESULT_OK(ret);
+      ASSERT_EQ(partition, *ret);
+    }
+
     ASSERT_TRUE(instance.HasPreInstalledVersion(apex->GetManifest().name()));
     ASSERT_TRUE(instance.HasDataVersion(apex->GetManifest().name()));
   };
@@ -120,7 +135,8 @@ TEST(ApexFileRepositoryTest, InitializeSuccess) {
   test_fn("apex.apexd_test_different_app.apex");
 
   // Check that second call will succeed as well.
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({built_in_dir.path}));
+  ASSERT_RESULT_OK(
+      instance.AddPreInstalledApex({{partition, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
   test_fn("apex.apexd_test.apex");
@@ -135,7 +151,8 @@ TEST(ApexFileRepositoryTest, InitializeFailureCorruptApex) {
            td.path);
 
   ApexFileRepository instance;
-  ASSERT_THAT(instance.AddPreInstalledApex({td.path}), Not(Ok()));
+  ASSERT_THAT(instance.AddPreInstalledApex({{ApexPartition::System, td.path}}),
+              Not(Ok()));
 }
 
 TEST(ApexFileRepositoryTest, InitializeCompressedApexWithoutApex) {
@@ -146,7 +163,8 @@ TEST(ApexFileRepositoryTest, InitializeCompressedApexWithoutApex) {
 
   ApexFileRepository instance;
   // Compressed APEX without APEX cannot be opened
-  ASSERT_THAT(instance.AddPreInstalledApex({td.path}), Not(Ok()));
+  ASSERT_THAT(instance.AddPreInstalledApex({{ApexPartition::System, td.path}}),
+              Not(Ok()));
 }
 
 TEST(ApexFileRepositoryTest, InitializeSameNameDifferentPathAborts) {
@@ -159,7 +177,7 @@ TEST(ApexFileRepositoryTest, InitializeSameNameDifferentPathAborts) {
   ASSERT_DEATH(
       {
         ApexFileRepository instance;
-        instance.AddPreInstalledApex({td.path});
+        instance.AddPreInstalledApex({{ApexPartition::System, td.path}});
       },
       "");
 }
@@ -170,7 +188,8 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSuccess) {
   std::string apex_file = GetTestFile("apex.apexd_test.apex");
   fs::copy(apex_file, StringPrintf("%s/version_a.apex", td.path));
   fs::copy(apex_file, StringPrintf("%s/version_b.apex", td.path));
-  std::string apex_name = ApexFile::Open(apex_file)->GetManifest().name();
+  auto apex = ApexFile::Open(apex_file);
+  std::string apex_name = apex->GetManifest().name();
 
   std::string persist_prefix = "debug.apexd.test.persistprefix.";
   std::string bootconfig_prefix = "debug.apexd.test.bootconfigprefix.";
@@ -179,8 +198,9 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSuccess) {
                                   persist_prefix, bootconfig_prefix});
 
   auto test_fn = [&](const std::string& selected_filename) {
-    ASSERT_RESULT_OK(instance.AddPreInstalledApex({td.path}));
-    auto ret = instance.GetPreinstalledPath(apex_name);
+    ASSERT_RESULT_OK(
+        instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
+    auto ret = instance.GetPreinstalledPath(apex->GetManifest().name());
     ASSERT_RESULT_OK(ret);
     ASSERT_EQ(StringPrintf("%s/%s", td.path, selected_filename.c_str()), *ret);
     instance.Reset();
@@ -207,8 +227,8 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSkipsForDifferingKeys) {
            StringPrintf("%s/version_a.apex", td.path));
   fs::copy(GetTestFile("apex.apexd_test_different_key.apex"),
            StringPrintf("%s/version_b.apex", td.path));
-  std::string apex_name =
-      ApexFile::Open(GetTestFile("apex.apexd_test.apex"))->GetManifest().name();
+  auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  std::string apex_name = apex->GetManifest().name();
   std::string prop_prefix = "debug.apexd.test.bootconfigprefix.";
   std::string prop = prop_prefix + apex_name;
   android::base::SetProperty(prop, "version_a.apex");
@@ -216,9 +236,11 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSkipsForDifferingKeys) {
   ApexFileRepository instance(
       /*enforce_multi_install_partition=*/false,
       /*multi_install_select_prop_prefixes=*/{prop_prefix});
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({td.path}));
+  ASSERT_RESULT_OK(
+      instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
   // Neither version should be have been installed.
-  ASSERT_THAT(instance.GetPreinstalledPath(apex_name), Not(Ok()));
+  ASSERT_THAT(instance.GetPreinstalledPath(apex->GetManifest().name()),
+              Not(Ok()));
 
   android::base::SetProperty(prop, "");
 }
@@ -232,8 +254,8 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSkipsForInvalidPartition) {
            StringPrintf("%s/version_a.apex", td.path));
   fs::copy(GetTestFile("apex.apexd_test.apex"),
            StringPrintf("%s/version_b.apex", td.path));
-  std::string apex_name =
-      ApexFile::Open(GetTestFile("apex.apexd_test.apex"))->GetManifest().name();
+  auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  std::string apex_name = apex->GetManifest().name();
   std::string prop_prefix = "debug.apexd.test.bootconfigprefix.";
   std::string prop = prop_prefix + apex_name;
   android::base::SetProperty(prop, "version_a.apex");
@@ -241,9 +263,11 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSkipsForInvalidPartition) {
   ApexFileRepository instance(
       /*enforce_multi_install_partition=*/true,
       /*multi_install_select_prop_prefixes=*/{prop_prefix});
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({td.path}));
+  ASSERT_RESULT_OK(
+      instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
   // Neither version should be have been installed.
-  ASSERT_THAT(instance.GetPreinstalledPath(apex_name), Not(Ok()));
+  ASSERT_THAT(instance.GetPreinstalledPath(apex->GetManifest().name()),
+              Not(Ok()));
 
   android::base::SetProperty(prop, "");
 }
@@ -259,7 +283,7 @@ TEST(ApexFileRepositoryTest,
   ASSERT_DEATH(
       {
         ApexFileRepository instance;
-        instance.AddPreInstalledApex({td.path});
+        instance.AddPreInstalledApex({{ApexPartition::System, td.path}});
       },
       "");
 }
@@ -270,10 +294,13 @@ TEST(ApexFileRepositoryTest, InitializePublicKeyUnexpectdlyChangedAborts) {
   fs::copy(GetTestFile("apex.apexd_test.apex"), td.path);
 
   ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({td.path}));
+  ASSERT_RESULT_OK(
+      instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
+
+  auto apex_file = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
 
   // Check that apex was loaded.
-  auto path = instance.GetPreinstalledPath("com.android.apex.test_package");
+  auto path = instance.GetPreinstalledPath(apex_file->GetManifest().name());
   ASSERT_RESULT_OK(path);
   ASSERT_EQ(StringPrintf("%s/apex.apexd_test.apex", td.path), *path);
 
@@ -294,7 +321,9 @@ TEST(ApexFileRepositoryTest, InitializePublicKeyUnexpectdlyChangedAborts) {
     ASSERT_NE(*public_key, apex->GetBundledPublicKey());
   }
 
-  ASSERT_DEATH({ instance.AddPreInstalledApex({td.path}); }, "");
+  ASSERT_DEATH(
+      { instance.AddPreInstalledApex({{ApexPartition::System, td.path}}); },
+      "");
 }
 
 TEST(ApexFileRepositoryTest,
@@ -304,10 +333,13 @@ TEST(ApexFileRepositoryTest,
   fs::copy(GetTestFile("com.android.apex.compressed.v1.capex"), td.path);
 
   ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({td.path}));
+  ASSERT_RESULT_OK(
+      instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
 
   // Check that apex was loaded.
-  auto path = instance.GetPreinstalledPath("com.android.apex.compressed");
+  auto apex_file =
+      ApexFile::Open(GetTestFile("com.android.apex.compressed.v1.capex"));
+  auto path = instance.GetPreinstalledPath(apex_file->GetManifest().name());
   ASSERT_RESULT_OK(path);
   ASSERT_EQ(StringPrintf("%s/com.android.apex.compressed.v1.capex", td.path),
             *path);
@@ -329,7 +361,9 @@ TEST(ApexFileRepositoryTest,
     ASSERT_NE(*public_key, apex->GetBundledPublicKey());
   }
 
-  ASSERT_DEATH({ instance.AddPreInstalledApex({td.path}); }, "");
+  ASSERT_DEATH(
+      { instance.AddPreInstalledApex({{ApexPartition::System, td.path}}); },
+      "");
 }
 
 TEST(ApexFileRepositoryTest, IsPreInstalledApex) {
@@ -339,7 +373,8 @@ TEST(ApexFileRepositoryTest, IsPreInstalledApex) {
   fs::copy(GetTestFile("com.android.apex.compressed.v1.capex"), td.path);
 
   ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({td.path}));
+  ASSERT_RESULT_OK(
+      instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
 
   auto compressed_apex = ApexFile::Open(
       StringPrintf("%s/com.android.apex.compressed.v1.capex", td.path));
@@ -401,7 +436,8 @@ TEST(ApexFileRepositoryTest, AddAndGetDataApex) {
                         kDecompressedApexPackageSuffix));
 
   ApexFileRepository instance(decompression_dir.path);
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({built_in_dir.path}));
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
   // ApexFileRepository should only deal with APEX in /data/apex/active.
@@ -445,7 +481,8 @@ TEST(ApexFileRepositoryTest, AddDataApexPrioritizeHigherVersionApex) {
   fs::copy(GetTestFile("apex.apexd_test_v2.apex"), data_dir.path);
 
   ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({built_in_dir.path}));
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
   auto data_apexs = instance.GetDataApexFiles();
@@ -462,7 +499,8 @@ TEST(ApexFileRepositoryTest, AddDataApexDoesNotScanDecompressedApex) {
                         built_in_dir.path, decompression_dir.path);
 
   ApexFileRepository instance(decompression_dir.path);
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({built_in_dir.path}));
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
   auto data_apexs = instance.GetDataApexFiles();
@@ -476,7 +514,8 @@ TEST(ApexFileRepositoryTest, AddDataApexIgnoreWrongPublicKey) {
   fs::copy(GetTestFile("apex.apexd_test_different_key.apex"), data_dir.path);
 
   ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({built_in_dir.path}));
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
   auto data_apexs = instance.GetDataApexFiles();
@@ -491,7 +530,8 @@ TEST(ApexFileRepositoryTest, GetPreInstalledApexFiles) {
            built_in_dir.path);
 
   ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({built_in_dir.path}));
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
 
   auto pre_installed_apexs = instance.GetPreInstalledApexFiles();
   auto pre_apex_1 = ApexFile::Open(
@@ -510,7 +550,8 @@ TEST(ApexFileRepositoryTest, AllApexFilesByName) {
   fs::copy(GetTestFile("com.android.apex.compressed.v1.capex"),
            built_in_dir.path);
   ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({built_in_dir.path}));
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
 
   TemporaryDir data_dir;
   fs::copy(GetTestFile("com.android.apex.cts.shim.v2.apex"), data_dir.path);
@@ -545,7 +586,8 @@ TEST(ApexFileRepositoryTest, GetDataApex) {
   fs::copy(GetTestFile("apex.apexd_test_v2.apex"), data_dir.path);
 
   ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({built_in_dir.path}));
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
   auto apex =
@@ -571,7 +613,8 @@ TEST(ApexFileRepositoryTest, GetPreInstalledApex) {
   fs::copy(GetTestFile("apex.apexd_test.apex"), built_in_dir.path);
 
   ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({built_in_dir.path}));
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
 
   auto apex = ApexFile::Open(
       StringPrintf("%s/apex.apexd_test.apex", built_in_dir.path));
@@ -659,15 +702,22 @@ TEST_F(ApexFileRepositoryTestAddBlockApex,
   // block apexes can be identified with IsBlockApex
   ASSERT_TRUE(instance.IsBlockApex(*apex_foo));
 
-  // "block" apexes are treated as "pre-installed"
+  // "block" apexes are treated as "pre-installed" with "is_factory: true"
   auto ret_foo = instance.GetPreInstalledApex("com.android.apex.test_package");
   ASSERT_THAT(ret_foo, ApexFileEq(ByRef(*apex_foo)));
 
+  auto partition_foo = instance.GetPartition(*apex_foo);
+  ASSERT_RESULT_OK(partition_foo);
+  ASSERT_EQ(*partition_foo, ApexPartition::System);
+
   auto apex_bar = ApexFile::Open(apex_bar_path);
   ASSERT_RESULT_OK(apex_bar);
   auto ret_bar =
       instance.GetPreInstalledApex("com.android.apex.test_package_2");
   ASSERT_THAT(ret_bar, ApexFileEq(ByRef(*apex_bar)));
+
+  auto partition_bar = instance.GetPartition(*apex_bar);
+  ASSERT_EQ(*partition_bar, ApexPartition::System);
 }
 
 TEST_F(ApexFileRepositoryTestAddBlockApex,
@@ -695,12 +745,9 @@ TEST_F(ApexFileRepositoryTestAddBlockApex,
   ASSERT_RESULT_OK(status);
 
   // foo is added, but bar is not
-  auto ret_foo = instance.GetPreinstalledPath("com.android.apex.test_package");
-  ASSERT_RESULT_OK(ret_foo);
-  ASSERT_EQ(apex_foo_path, *ret_foo);
-  auto ret_bar =
-      instance.GetPreinstalledPath("com.android.apex.test_package_2");
-  ASSERT_THAT(ret_bar, Not(Ok()));
+  ASSERT_TRUE(instance.HasPreInstalledVersion("com.android.apex.test_package"));
+  ASSERT_FALSE(
+      instance.HasPreInstalledVersion("com.android.apex.test_package_2"));
 }
 
 TEST_F(ApexFileRepositoryTestAddBlockApex, FailsWhenTheresDuplicateNames) {
@@ -909,5 +956,251 @@ TEST_F(ApexFileRepositoryTestAddBlockApex, RespectIsFactoryBitFromMetadata) {
   }
 }
 
+TEST(ApexFileRepositoryTestBrandNewApex, AddAndGetPublicKeyPartition) {
+  TemporaryDir credential_dir_1, credential_dir_2;
+  auto key_path_1 =
+      GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey");
+  fs::copy(key_path_1, credential_dir_1.path);
+  auto key_path_2 = GetTestFile(
+      "apexd_testdata/com.android.apex.brand.new.another.avbpubkey");
+  fs::copy(key_path_2, credential_dir_2.path);
+
+  ApexFileRepository instance;
+  const auto expected_partition_1 = ApexPartition::System;
+  const auto expected_partition_2 = ApexPartition::Odm;
+  auto ret = instance.AddBrandNewApexCredentialAndBlocklist(
+      {{expected_partition_1, credential_dir_1.path},
+       {expected_partition_2, credential_dir_2.path}});
+  ASSERT_RESULT_OK(ret);
+
+  std::string key_1;
+  std::string key_2;
+  const std::string& key_3 = "random key";
+  android::base::ReadFileToString(key_path_1, &key_1);
+  android::base::ReadFileToString(key_path_2, &key_2);
+  auto partition_1 = instance.GetBrandNewApexPublicKeyPartition(key_1);
+  auto partition_2 = instance.GetBrandNewApexPublicKeyPartition(key_2);
+  auto partition_3 = instance.GetBrandNewApexPublicKeyPartition(key_3);
+  ASSERT_EQ(partition_1.value(), expected_partition_1);
+  ASSERT_EQ(partition_2.value(), expected_partition_2);
+  ASSERT_FALSE(partition_3.has_value());
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex,
+     AddPublicKeyFailDuplicateKeyInDiffPartition) {
+  TemporaryDir credential_dir_1, credential_dir_2;
+  auto key_path_1 =
+      GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey");
+  fs::copy(key_path_1, credential_dir_1.path);
+  auto key_path_2 = GetTestFile(
+      "apexd_testdata/com.android.apex.brand.new.renamed.avbpubkey");
+  fs::copy(key_path_2, credential_dir_2.path);
+
+  ApexFileRepository instance;
+  const auto expected_partition_1 = ApexPartition::System;
+  const auto expected_partition_2 = ApexPartition::Odm;
+  ASSERT_DEATH(
+      {
+        instance.AddBrandNewApexCredentialAndBlocklist(
+            {{expected_partition_1, credential_dir_1.path},
+             {expected_partition_2, credential_dir_2.path}});
+      },
+      "Duplicate public keys are found in different partitions.");
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex, AddAndGetBlockedVersion) {
+  TemporaryDir blocklist_dir;
+  auto blocklist_path = GetTestFile("apexd_testdata/blocklist.json");
+  fs::copy(blocklist_path, blocklist_dir.path);
+
+  ApexFileRepository instance;
+  const auto expected_partition = ApexPartition::System;
+  const auto blocked_apex_name = "com.android.apex.brand.new";
+  const auto expected_blocked_version = 1;
+  auto ret = instance.AddBrandNewApexCredentialAndBlocklist(
+      {{expected_partition, blocklist_dir.path}});
+  ASSERT_RESULT_OK(ret);
+
+  const auto non_existent_partition = ApexPartition::Odm;
+  const auto non_existent_apex_name = "randome.apex";
+  auto blocked_version = instance.GetBrandNewApexBlockedVersion(
+      expected_partition, blocked_apex_name);
+  ASSERT_EQ(blocked_version, expected_blocked_version);
+  auto blocked_version_non_existent_apex =
+      instance.GetBrandNewApexBlockedVersion(expected_partition,
+                                             non_existent_apex_name);
+  ASSERT_FALSE(blocked_version_non_existent_apex.has_value());
+  auto blocked_version_non_existent_partition =
+      instance.GetBrandNewApexBlockedVersion(non_existent_partition,
+                                             blocked_apex_name);
+  ASSERT_FALSE(blocked_version_non_existent_partition.has_value());
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex,
+     AddCredentialAndBlocklistSucceedEmptyFile) {
+  TemporaryDir empty_dir;
+
+  ApexFileRepository instance;
+  const auto expected_partition = ApexPartition::System;
+  auto ret = instance.AddBrandNewApexCredentialAndBlocklist(
+      {{expected_partition, empty_dir.path}});
+  ASSERT_RESULT_OK(ret);
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex,
+     AddBlocklistSucceedDuplicateApexNameInDiffPartition) {
+  TemporaryDir blocklist_dir_1, blocklist_dir_2;
+  auto blocklist_path = GetTestFile("apexd_testdata/blocklist.json");
+  fs::copy(blocklist_path, blocklist_dir_1.path);
+  fs::copy(blocklist_path, blocklist_dir_2.path);
+
+  ApexFileRepository instance;
+  const auto expected_partition = ApexPartition::System;
+  const auto other_partition = ApexPartition::Product;
+  auto ret = instance.AddBrandNewApexCredentialAndBlocklist(
+      {{expected_partition, blocklist_dir_1.path},
+       {other_partition, blocklist_dir_2.path}});
+  ASSERT_RESULT_OK(ret);
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex,
+     AddBlocklistFailDuplicateApexNameInSamePartition) {
+  TemporaryDir blocklist_dir;
+  auto blocklist_path = GetTestFile("apexd_testdata/blocklist_invalid.json");
+  fs::copy(blocklist_path, fs::path(blocklist_dir.path) / "blocklist.json");
+
+  ApexFileRepository instance;
+  const auto expected_partition = ApexPartition::System;
+  ASSERT_DEATH(
+      {
+        instance.AddBrandNewApexCredentialAndBlocklist(
+            {{expected_partition, blocklist_dir.path}});
+      },
+      "Duplicate APEX names are found in blocklist.");
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex,
+     AddDataApexSucceedVerifiedBrandNewApex) {
+  // Prepares test data.
+  ApexFileRepository::EnableBrandNewApex();
+  const auto partition = ApexPartition::System;
+  TemporaryDir data_dir, trusted_key_dir;
+  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+
+  ApexFileRepository& instance = ApexFileRepository::GetInstance();
+  instance.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  // Now test that apexes were scanned correctly;
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
+
+  {
+    auto ret = instance.GetDataPath(apex->GetManifest().name());
+    ASSERT_RESULT_OK(ret);
+    ASSERT_EQ(StringPrintf("%s/com.android.apex.brand.new.apex", data_dir.path),
+              *ret);
+  }
+
+  {
+    auto ret = instance.GetPartition(*apex);
+    ASSERT_RESULT_OK(ret);
+    ASSERT_EQ(partition, *ret);
+  }
+
+  ASSERT_THAT(instance.GetPreinstalledPath(apex->GetManifest().name()),
+              Not(Ok()));
+  ASSERT_FALSE(instance.HasPreInstalledVersion(apex->GetManifest().name()));
+  ASSERT_TRUE(instance.HasDataVersion(apex->GetManifest().name()));
+
+  instance.Reset();
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex,
+     AddDataApexFailUnverifiedBrandNewApex) {
+  ApexFileRepository::EnableBrandNewApex();
+  TemporaryDir data_dir;
+  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
+
+  ApexFileRepository& instance = ApexFileRepository::GetInstance();
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+  ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
+
+  ASSERT_THAT(instance.GetDataPath(apex->GetManifest().name()), Not(Ok()));
+  ASSERT_FALSE(instance.HasDataVersion(apex->GetManifest().name()));
+  instance.Reset();
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex, AddDataApexFailBrandNewApexDisabled) {
+  TemporaryDir data_dir;
+  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
+
+  ApexFileRepository& instance = ApexFileRepository::GetInstance();
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+  ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
+
+  ASSERT_THAT(instance.GetDataPath(apex->GetManifest().name()), Not(Ok()));
+  ASSERT_FALSE(instance.HasDataVersion(apex->GetManifest().name()));
+  instance.Reset();
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex,
+     GetPartitionSucceedVerifiedBrandNewApex) {
+  ApexFileRepository::EnableBrandNewApex();
+  TemporaryDir trusted_key_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+
+  ApexFileRepository& instance = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  instance.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = instance.GetPartition(*apex);
+  ASSERT_RESULT_OK(ret);
+  ASSERT_EQ(*ret, partition);
+  instance.Reset();
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex,
+     GetPartitionFailUnverifiedBrandNewApex) {
+  ApexFileRepository::EnableBrandNewApex();
+  ApexFileRepository& instance = ApexFileRepository::GetInstance();
+
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = instance.GetPartition(*apex);
+  ASSERT_THAT(ret, Not(Ok()));
+  instance.Reset();
+}
+
+TEST(ApexFileRepositoryTestBrandNewApex, GetPartitionFailBrandNewApexDisabled) {
+  TemporaryDir trusted_key_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+
+  ApexFileRepository& instance = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  instance.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = instance.GetPartition(*apex);
+  ASSERT_THAT(ret, Not(Ok()));
+  instance.Reset();
+}
+
 }  // namespace apex
 }  // namespace android
diff --git a/apexd/apexd.aconfig b/apexd/apexd.aconfig
new file mode 100644
index 00000000..89e848fd
--- /dev/null
+++ b/apexd/apexd.aconfig
@@ -0,0 +1,10 @@
+package: "com.android.apex.flags"
+container: "system"
+
+flag {
+  name: "enable_brand_new_apex"
+  namespace: "aaos_sdv"
+  description: "This flag controls if allowing installation of brand-new APEX"
+  bug: "361500273"
+  is_fixed_read_only: true
+}
diff --git a/apexd/apexd.cpp b/apexd/apexd.cpp
index b1c16acb..ed4cbafd 100644
--- a/apexd/apexd.cpp
+++ b/apexd/apexd.cpp
@@ -39,7 +39,6 @@
 #include <linux/f2fs.h>
 #include <linux/loop.h>
 #include <selinux/android.h>
-#include <statssocket_lazy.h>
 #include <stdlib.h>
 #include <sys/inotify.h>
 #include <sys/ioctl.h>
@@ -49,7 +48,6 @@
 #include <sys/types.h>
 #include <unistd.h>
 #include <utils/Trace.h>
-#include <vintf/VintfObject.h>
 
 #include <algorithm>
 #include <array>
@@ -64,6 +62,7 @@
 #include <mutex>
 #include <optional>
 #include <queue>
+#include <ranges>
 #include <sstream>
 #include <string>
 #include <string_view>
@@ -79,6 +78,7 @@
 #include "apex_manifest.h"
 #include "apex_sha.h"
 #include "apex_shim.h"
+#include "apexd_brand_new_verifier.h"
 #include "apexd_checkpoint.h"
 #include "apexd_dm.h"
 #include "apexd_lifecycle.h"
@@ -91,7 +91,6 @@
 #include "apexd_vendor_apex.h"
 #include "apexd_verity.h"
 #include "com_android_apex.h"
-#include "statslog_apex.h"
 
 using android::base::boot_clock;
 using android::base::ConsumePrefix;
@@ -118,6 +117,8 @@ namespace android {
 namespace apex {
 
 using MountedApexData = MountedApexDatabase::MountedApexData;
+Result<std::vector<ApexFile>> OpenSessionApexFiles(
+    int session_id, const std::vector<int>& child_session_ids);
 
 namespace {
 
@@ -184,9 +185,10 @@ bool IsBootstrapApex(const ApexFile& apex) {
     return ret;
   }();
 
-  if (IsVendorApex(apex) && apex.GetManifest().vendorbootstrap()) {
+  if (apex.GetManifest().vendorbootstrap() || apex.GetManifest().bootstrap()) {
     return true;
   }
+
   return std::find(kBootstrapApexes.begin(), kBootstrapApexes.end(),
                    apex.GetManifest().name()) != kBootstrapApexes.end() ||
          std::find(additional.begin(), additional.end(),
@@ -401,18 +403,13 @@ Result<MountedApexData> MountPackageImpl(const ApexFile& apex,
   }
   LOG(VERBOSE) << "Loopback device created: " << loopback_device.name;
 
-  auto& instance = ApexFileRepository::GetInstance();
-
-  auto public_key = instance.GetPublicKey(apex.GetManifest().name());
-  if (!public_key.ok()) {
-    return public_key.error();
-  }
-
-  auto verity_data = apex.VerifyApexVerity(*public_key);
+  auto verity_data = apex.VerifyApexVerity(apex.GetBundledPublicKey());
   if (!verity_data.ok()) {
     return Error() << "Failed to verify Apex Verity data for " << full_path
                    << ": " << verity_data.error();
   }
+
+  auto& instance = ApexFileRepository::GetInstance();
   if (instance.IsBlockApex(apex)) {
     auto root_digest = instance.GetBlockApexRootDigest(apex.GetPath());
     if (root_digest.has_value() &&
@@ -503,15 +500,6 @@ Result<MountedApexData> MountPackageImpl(const ApexFile& apex,
   }
 }
 
-Result<MountedApexData> VerifyAndTempMountPackage(
-    const ApexFile& apex, const std::string& mount_point) {
-  const std::string& package_id = GetPackageId(apex.GetManifest());
-  LOG(DEBUG) << "Temp mounting " << package_id << " to " << mount_point;
-  const std::string& temp_device_name = package_id + ".tmp";
-  return MountPackageImpl(apex, mount_point, temp_device_name,
-                          /* verify_image = */ true, /* reuse_device= */ false);
-}
-
 }  // namespace
 
 Result<void> Unmount(const MountedApexData& data, bool deferred) {
@@ -556,32 +544,48 @@ Result<void> Unmount(const MountedApexData& data, bool deferred) {
 
 namespace {
 
-template <typename VerifyFn>
-Result<void> RunVerifyFnInsideTempMount(const ApexFile& apex,
-                                        const VerifyFn& verify_fn) {
-  // Temp mount image of this apex to validate it was properly signed;
-  // this will also read the entire block device through dm-verity, so
-  // we can be sure there is no corruption.
-  const std::string& temp_mount_point =
-      apexd_private::GetPackageTempMountPoint(apex.GetManifest());
-
-  Result<MountedApexData> mount_status =
-      VerifyAndTempMountPackage(apex, temp_mount_point);
-  if (!mount_status.ok()) {
-    LOG(ERROR) << "Failed to temp mount to " << temp_mount_point << " : "
-               << mount_status.error();
-    return mount_status.error();
-  }
-  auto cleaner = [&]() {
-    LOG(DEBUG) << "Unmounting " << temp_mount_point;
-    Result<void> result = Unmount(*mount_status, /* deferred= */ false);
-    if (!result.ok()) {
-      LOG(WARNING) << "Failed to unmount " << temp_mount_point << " : "
-                   << result.error();
+auto RunVerifyFnInsideTempMounts(std::span<const ApexFile> apex_files,
+                                 auto verify_fn)
+    -> decltype(verify_fn(std::vector<std::string>{})) {
+  // Temp mounts will be cleaned up on exit.
+  std::vector<MountedApexData> mounted_data;
+  auto guard = android::base::make_scope_guard([&]() {
+    for (const auto& data : mounted_data) {
+      if (auto result = Unmount(data, /*deferred=*/false); !result.ok()) {
+        LOG(WARNING) << "Failed to unmount " << data.mount_point << ": "
+                     << result.error();
+      }
     }
-  };
-  auto scope_guard = android::base::make_scope_guard(cleaner);
-  return verify_fn(temp_mount_point);
+  });
+
+  // Temp mounts all apexes.
+  // This will also read the entire block device for each apex,
+  // so we can be sure there is no corruption.
+  std::vector<std::string> mount_points;
+  for (const auto& apex : apex_files) {
+    auto mount_point =
+        apexd_private::GetPackageTempMountPoint(apex.GetManifest());
+    auto package_id = GetPackageId(apex.GetManifest());
+    auto device_name = package_id + ".tmp";
+
+    LOG(DEBUG) << "Temp mounting " << package_id << " to " << mount_point;
+    auto data = OR_RETURN(MountPackageImpl(apex, mount_point, device_name,
+                                           /*verify_image=*/true,
+                                           /*reuse_device=*/false));
+    mount_points.push_back(mount_point);
+    mounted_data.push_back(data);
+  }
+
+  // Invoke fn with mount_points.
+  return verify_fn(mount_points);
+}
+
+// Singluar variant of RunVerifyFnInsideTempMounts for convenience
+auto RunVerifyFnInsideTempMount(const ApexFile& apex, auto verify_fn)
+    -> decltype(verify_fn(std::string{})) {
+  return RunVerifyFnInsideTempMounts(
+      Single(apex),
+      [&](const auto& mount_points) { return verify_fn(mount_points[0]); });
 }
 
 // Converts a list of apex file paths into a list of ApexFile objects
@@ -627,10 +631,8 @@ Result<void> VerifyVndkVersion(const ApexFile& apex_file) {
       GetProperty("ro.product.vndk.version", "");
 
   const auto& instance = ApexFileRepository::GetInstance();
-  const auto& preinstalled =
-      instance.GetPreInstalledApex(apex_file.GetManifest().name());
-  const auto& path = preinstalled.get().GetPath();
-  if (InVendorPartition(path) || InOdmPartition(path)) {
+  const auto& partition = OR_RETURN(instance.GetPartition(apex_file));
+  if (partition == ApexPartition::Vendor || partition == ApexPartition::Odm) {
     if (vndk_version != vendor_vndk_version) {
       return Error() << "vndkVersion(" << vndk_version
                      << ") doesn't match with device VNDK version("
@@ -638,8 +640,7 @@ Result<void> VerifyVndkVersion(const ApexFile& apex_file) {
     }
     return {};
   }
-  if (StartsWith(path, "/product/apex/") ||
-      StartsWith(path, "/system/product/apex/")) {
+  if (partition == ApexPartition::Product) {
     if (vndk_version != product_vndk_version) {
       return Error() << "vndkVersion(" << vndk_version
                      << ") doesn't match with device VNDK version("
@@ -655,12 +656,9 @@ Result<void> VerifyVndkVersion(const ApexFile& apex_file) {
 // each boot. Try to avoid putting expensive checks inside this function.
 Result<void> VerifyPackageBoot(const ApexFile& apex_file) {
   // TODO(ioffe): why do we need this here?
-  auto& instance = ApexFileRepository::GetInstance();
-  auto public_key = instance.GetPublicKey(apex_file.GetManifest().name());
-  if (!public_key.ok()) {
-    return public_key.error();
-  }
-  Result<ApexVerityData> verity_or = apex_file.VerifyApexVerity(*public_key);
+  const auto& public_key =
+      OR_RETURN(apexd_private::GetVerifiedPublicKey(apex_file));
+  Result<ApexVerityData> verity_or = apex_file.VerifyApexVerity(public_key);
   if (!verity_or.ok()) {
     return verity_or.error();
   }
@@ -682,80 +680,57 @@ Result<void> VerifyPackageBoot(const ApexFile& apex_file) {
   return {};
 }
 
+struct VerificationResult {
+  std::map<std::string, std::vector<std::string>> apex_hals;
+};
+
 // A version of apex verification that happens on SubmitStagedSession.
 // This function contains checks that might be expensive to perform, e.g. temp
 // mounting a package and reading entire dm-verity device, and shouldn't be run
 // during boot.
-Result<void> VerifyPackageStagedInstall(const ApexFile& apex_file) {
-  const auto& verify_package_boot_status = VerifyPackageBoot(apex_file);
-  if (!verify_package_boot_status.ok()) {
-    return verify_package_boot_status;
-  }
+Result<VerificationResult> VerifyPackagesStagedInstall(
+    const std::vector<ApexFile>& apex_files) {
+  for (const auto& apex_file : apex_files) {
+    OR_RETURN(VerifyPackageBoot(apex_file));
 
-  const auto validate_fn = [&apex_file](const std::string& mount_point) {
-    if (IsVendorApex(apex_file)) {
-      return CheckVendorApexUpdate(apex_file, mount_point);
+    // Extra verification for brand-new APEX. The case that brand-new APEX is
+    // not enabled when there is install request for brand-new APEX is already
+    // covered in |VerifyPackageBoot|.
+    if (ApexFileRepository::IsBrandNewApexEnabled()) {
+      OR_RETURN(VerifyBrandNewPackageAgainstActive(apex_file));
     }
-    return Result<void>{};
-  };
-  return RunVerifyFnInsideTempMount(apex_file, validate_fn);
-}
-
-template <typename VerifyApexFn>
-Result<std::vector<ApexFile>> VerifyPackages(
-    const std::vector<std::string>& paths, const VerifyApexFn& verify_apex_fn) {
-  Result<std::vector<ApexFile>> apex_files = OpenApexFiles(paths);
-  if (!apex_files.ok()) {
-    return apex_files.error();
   }
 
-  LOG(DEBUG) << "VerifyPackages() for " << Join(paths, ',');
-
-  for (const ApexFile& apex_file : *apex_files) {
-    Result<void> result = verify_apex_fn(apex_file);
-    if (!result.ok()) {
-      return result.error();
+  // Since there can be multiple staged sessions, let's verify incoming APEXes
+  // with all staged apexes mounted.
+  std::vector<ApexFile> all_apex_files;
+  for (const auto& session :
+       gSessionManager->GetSessionsInState(SessionState::STAGED)) {
+    auto session_id = session.GetId();
+    auto child_session_ids = session.GetChildSessionIds();
+    auto staged_apex_files = OpenSessionApexFiles(
+        session_id, {child_session_ids.begin(), child_session_ids.end()});
+    if (staged_apex_files.ok()) {
+      std::ranges::move(*staged_apex_files, std::back_inserter(all_apex_files));
+    } else {
+      // Let's not abort with a previously staged session
+      LOG(ERROR) << "Failed to open previously staged APEX files: "
+                 << staged_apex_files.error();
     }
   }
-  return std::move(*apex_files);
-}
-
-// VerifySessionDir verifies and returns the apex file in a session
-Result<ApexFile> VerifySessionDir(int session_id, const bool is_rollback) {
-  std::string session_dir_path =
-      StringPrintf("%s/session_%d", gConfig->staged_session_dir, session_id);
-  LOG(INFO) << "Scanning " << session_dir_path
-            << " looking for packages to be validated";
-  Result<std::vector<std::string>> scan =
-      FindFilesBySuffix(session_dir_path, {kApexPackageSuffix});
-  if (!scan.ok()) {
-    LOG(WARNING) << scan.error();
-    return scan.error();
-  }
 
-  if (scan->size() > 1) {
-    return Errorf(
-        "More than one APEX package found in the same session directory.");
+  // + incoming APEXes at the end.
+  for (const auto& apex_file : apex_files) {
+    all_apex_files.push_back(apex_file);
   }
 
-  // Report ApexInstallRequests here, so we can track apexes that
-  // do not pass the VerifyPackages() and thus won't return for tracking.
-  // SubmitStagedSession() performs the remaining apex metrics with valid
-  // instances. VerifySessionDir is only called by SubmitStagedSession(), so we
-  // can surmise that a staged apex installation is occurring.
-  SendApexInstallationRequestedAtom(
-      (*scan)[0], is_rollback,
-      stats::apex::APEX_INSTALLATION_REQUESTED__INSTALLATION_TYPE__STAGED);
-
-  auto verified = VerifyPackages(*scan, VerifyPackageStagedInstall);
-  if (!verified.ok()) {
-    SendApexInstallationEndedAtom(
-        (*scan)[0],
-        stats::apex::
-            APEX_INSTALLATION_ENDED__INSTALLATION_RESULT__INSTALL_FAILURE_APEX_INSTALLATION);
-    return verified.error();
-  }
-  return std::move((*verified)[0]);
+  auto check_fn = [&](const std::vector<std::string>& mount_points)
+      -> Result<VerificationResult> {
+    VerificationResult result;
+    result.apex_hals = OR_RETURN(CheckVintf(all_apex_files, mount_points));
+    return result;
+  };
+  return RunVerifyFnInsideTempMounts(all_apex_files, check_fn);
 }
 
 Result<void> DeleteBackup() {
@@ -942,6 +917,19 @@ Result<void> MountPackage(const ApexFile& apex, const std::string& mount_point,
 
 namespace apexd_private {
 
+Result<std::string> GetVerifiedPublicKey(const ApexFile& apex) {
+  auto preinstalled_public_key =
+      ApexFileRepository::GetInstance().GetPublicKey(apex.GetManifest().name());
+  if (preinstalled_public_key.ok()) {
+    return *preinstalled_public_key;
+  } else if (ApexFileRepository::IsBrandNewApexEnabled() &&
+             VerifyBrandNewPackageAgainstPreinstalled(apex).ok()) {
+    return apex.GetBundledPublicKey();
+  }
+  return Error() << "No preinstalled apex found for unverified package "
+                 << apex.GetManifest().name();
+}
+
 bool IsMounted(const std::string& full_path) {
   bool found_mounted = false;
   gMountedApexes.ForallMountedApexes([&](const std::string&,
@@ -1208,18 +1196,8 @@ Result<void> DeactivatePackage(const std::string& full_path) {
                         /* deferred= */ false, /* detach_mount_point= */ false);
 }
 
-Result<std::vector<ApexFile>> GetStagedApexFiles(
+Result<std::vector<ApexFile>> OpenSessionApexFiles(
     int session_id, const std::vector<int>& child_session_ids) {
-  auto session = gSessionManager->GetSession(session_id);
-  if (!session.ok()) {
-    return session.error();
-  }
-  // We should only accept sessions in SessionState::STAGED state
-  auto session_state = (*session).GetState();
-  if (session_state != SessionState::STAGED) {
-    return Error() << "Session " << session_id << " is not in state STAGED";
-  }
-
   std::vector<int> ids_to_scan;
   if (!child_session_ids.empty()) {
     ids_to_scan = child_session_ids;
@@ -1248,30 +1226,23 @@ Result<std::vector<ApexFile>> GetStagedApexFiles(
   return OpenApexFiles(apex_file_paths);
 }
 
-Result<ClassPath> MountAndDeriveClassPath(
-    const std::vector<ApexFile>& apex_files) {
-  std::vector<MountedApexData> mounted_data;
-  auto guard = android::base::make_scope_guard([&]() {
-    for (const auto& data : mounted_data) {
-      Unmount(data, /*deferred=*/false);
-    }
-  });
-
-  // Mount the staged apex files
-  std::vector<std::string> temp_mounted_apex_paths;
-  for (const auto& apex : apex_files) {
-    const std::string& temp_mount_point =
-        apexd_private::GetPackageTempMountPoint(apex.GetManifest());
-    auto mount_status = VerifyAndTempMountPackage(apex, temp_mount_point);
-    if (!mount_status.ok()) {
-      return mount_status.error();
-    }
-    temp_mounted_apex_paths.push_back(temp_mount_point);
-    mounted_data.push_back(*mount_status);
+Result<std::vector<ApexFile>> GetStagedApexFiles(
+    int session_id, const std::vector<int>& child_session_ids) {
+  // We should only accept sessions in SessionState::STAGED state
+  auto session = OR_RETURN(gSessionManager->GetSession(session_id));
+  if (session.GetState() != SessionState::STAGED) {
+    return Error() << "Session " << session_id << " is not in state STAGED";
   }
 
+  return OpenSessionApexFiles(session_id, child_session_ids);
+}
+
+Result<ClassPath> MountAndDeriveClassPath(
+    const std::vector<ApexFile>& apex_files) {
   // Calculate classpaths of temp mounted staged apexs
-  return ClassPath::DeriveClassPath(temp_mounted_apex_paths);
+  return RunVerifyFnInsideTempMounts(apex_files, [](const auto& mount_points) {
+    return ClassPath::DeriveClassPath(mount_points);
+  });
 }
 
 std::vector<ApexFile> GetActivePackages() {
@@ -1491,15 +1462,6 @@ Result<void> ActivateApexPackages(const std::vector<ApexFileRef>& apexes,
   }
   worker_num = std::min(apex_queue.size(), worker_num);
 
-  // On -eng builds there might be two different pre-installed art apexes.
-  // Attempting to activate them in parallel will result in UB (e.g.
-  // apexd-bootstrap might crash). In order to avoid this, for the time being on
-  // -eng builds activate apexes sequentially.
-  // TODO(b/176497601): remove this.
-  if (GetProperty("ro.build.type", "") == "eng") {
-    worker_num = 1;
-  }
-
   std::vector<std::future<std::vector<Result<const ApexFile*>>>> futures;
   futures.reserve(worker_num);
   for (size_t i = 0; i < worker_num; i++) {
@@ -1970,19 +1932,6 @@ void ScanStagedSessionsDirAndStage() {
         continue;
       }
       staged_apex_names.push_back(apex_file->GetManifest().name());
-
-      // Collect apex's file hash now to assist sending metrics later. With
-      // successful installs, when we want to send the metric message, we are
-      // unable to read the session's apex to compute the sha for the message
-      Result<std::string> apex_file_sha256_str =
-          CalculateSha256(apex_file->GetPath());
-      if (!apex_file_sha256_str.ok()) {
-        LOG(WARNING) << "Unable to get sha256 of ApexFile "
-                     << apex_file->GetPath() << " : "
-                     << apex_file_sha256_str.error();
-      } else {
-        RegisterSessionApexSha(session_id, *apex_file_sha256_str);
-      }
     }
 
     const Result<void> result = StagePackages(apexes);
@@ -2253,8 +2202,7 @@ int OnBootstrap() {
   auto time_started = boot_clock::now();
 
   ApexFileRepository& instance = ApexFileRepository::GetInstance();
-  Result<void> status =
-      instance.AddPreInstalledApex(gConfig->apex_built_in_dirs);
+  Result<void> status = instance.AddPreInstalledApex(gConfig->builtin_dirs);
   if (!status.ok()) {
     LOG(ERROR) << "Failed to collect APEX keys : " << status.error();
     return 1;
@@ -2284,17 +2232,6 @@ int OnBootstrap() {
   LOG(INFO) << "Need to pre-allocate " << loop_device_cnt
             << " loop devices for " << pre_installed_apexes.size()
             << " APEX packages";
-  // TODO(b/209491448) Remove this.
-  auto block_count = AddBlockApex(instance);
-  if (!block_count.ok()) {
-    LOG(ERROR) << status.error();
-    return 1;
-  }
-  if (*block_count > 0) {
-    LOG(INFO) << "Also need to pre-allocate " << *block_count
-              << " loop devices for block APEXes";
-    loop_device_cnt += *block_count;
-  }
   if (auto res = loop::PreAllocateLoopDevices(loop_device_cnt); !res.ok()) {
     LOG(ERROR) << "Failed to pre-allocate loop devices : " << res.error();
   }
@@ -2315,13 +2252,6 @@ int OnBootstrap() {
     }
   }
 
-  // Create directories for APEX shared libraries.
-  auto sharedlibs_apex_dir = CreateSharedLibsApexDir();
-  if (!sharedlibs_apex_dir.ok()) {
-    LOG(ERROR) << sharedlibs_apex_dir.error();
-    return 1;
-  }
-
   // Now activate bootstrap apexes.
   auto ret =
       ActivateApexPackages(bootstrap_apexes, ActivationMode::kBootstrapMode);
@@ -2338,13 +2268,6 @@ int OnBootstrap() {
   return 0;
 }
 
-Result<void> RemountApexFile(const std::string& path) {
-  if (auto ret = DeactivatePackage(path); !ret.ok()) {
-    return ret;
-  }
-  return ActivatePackage(path);
-}
-
 void InitializeVold(CheckpointInterface* checkpoint_service) {
   if (checkpoint_service != nullptr) {
     gVoldService = checkpoint_service;
@@ -2375,17 +2298,18 @@ void InitializeSessionManager(ApexSessionManager* session_manager) {
 void Initialize(CheckpointInterface* checkpoint_service) {
   InitializeVold(checkpoint_service);
   ApexFileRepository& instance = ApexFileRepository::GetInstance();
-  Result<void> status = instance.AddPreInstalledApex(kApexPackageBuiltinDirs);
+  Result<void> status = instance.AddPreInstalledApex(gConfig->builtin_dirs);
   if (!status.ok()) {
     LOG(ERROR) << "Failed to collect pre-installed APEX files : "
                << status.error();
     return;
   }
 
-  // TODO(b/209491448) Remove this.
-  if (auto block_status = AddBlockApex(instance); !block_status.ok()) {
-    LOG(ERROR) << status.error();
-    return;
+  if (ApexFileRepository::IsBrandNewApexEnabled()) {
+    Result<void> result = instance.AddBrandNewApexCredentialAndBlocklist(
+        kPartitionToBrandNewApexConfigDirs);
+    CHECK(result.ok()) << "Failed to collect pre-installed public keys and "
+                          "blocklists for brand-new APEX";
   }
 
   gMountedApexes.PopulateFromMounts(
@@ -2436,13 +2360,6 @@ std::vector<ApexFileRef> SelectApexForActivation(
       continue;
     }
 
-    // The package must have a pre-installed version before we consider it for
-    // activation
-    if (!instance.HasPreInstalledVersion(package_name)) {
-      LOG(INFO) << "Package " << package_name << " is not pre-installed";
-      continue;
-    }
-
     if (apex_files.size() == 1) {
       LOG(DEBUG) << "Selecting the only APEX: " << package_name << " "
                  << apex_files[0].get().GetPath();
@@ -2852,9 +2769,15 @@ Result<std::vector<ApexFile>> SubmitStagedSession(
     const int session_id, const std::vector<int>& child_session_ids,
     const bool has_rollback_enabled, const bool is_rollback,
     const int rollback_id) {
+  auto event = InstallRequestedEvent(InstallType::Staged, is_rollback);
+
   if (session_id == 0) {
     return Error() << "Session id was not provided.";
   }
+  if (has_rollback_enabled && is_rollback) {
+    return Error() << "Cannot set session " << session_id << " as both a"
+                   << " rollback and enabled for rollback.";
+  }
 
   if (!gSupportsFsCheckpoints) {
     Result<void> backup_status = BackupActivePackages();
@@ -2864,35 +2787,11 @@ Result<std::vector<ApexFile>> SubmitStagedSession(
     }
   }
 
-  std::vector<int> ids_to_scan;
-  if (!child_session_ids.empty()) {
-    ids_to_scan = child_session_ids;
-  } else {
-    ids_to_scan = {session_id};
-  }
-
-  std::vector<ApexFile> ret;
-  auto guard = android::base::make_scope_guard([&]() {
-    for (const auto& apex : ret) {
-      SendApexInstallationEndedAtom(
-          apex.GetPath(),
-          stats::apex::
-              APEX_INSTALLATION_ENDED__INSTALLATION_RESULT__INSTALL_FAILURE_APEX_INSTALLATION);
-    }
-  });
-  for (int id_to_scan : ids_to_scan) {
-    auto verified = VerifySessionDir(id_to_scan, is_rollback);
-    if (!verified.ok()) {
-      return verified.error();
-    }
-    LOG(DEBUG) << verified->GetPath() << " is verified";
-    ret.push_back(std::move(*verified));
-  }
+  auto ret = OR_RETURN(OpenSessionApexFiles(session_id, child_session_ids));
+  event.AddFiles(ret);
 
-  if (has_rollback_enabled && is_rollback) {
-    return Error() << "Cannot set session " << session_id << " as both a"
-                   << " rollback and enabled for rollback.";
-  }
+  auto result = OR_RETURN(VerifyPackagesStagedInstall(ret));
+  event.AddHals(result.apex_hals);
 
   auto session = gSessionManager->CreateSession(session_id);
   if (!session.ok()) {
@@ -2907,6 +2806,7 @@ Result<std::vector<ApexFile>> SubmitStagedSession(
   for (const auto& apex_file : ret) {
     session->AddApexName(apex_file.GetManifest().name());
   }
+  session->SetApexFileHashes(event.GetFileHashes());
   Result<void> commit_status =
       (*session).UpdateStateAndCommit(SessionState::VERIFIED);
   if (!commit_status.ok()) {
@@ -2918,8 +2818,7 @@ Result<std::vector<ApexFile>> SubmitStagedSession(
     ReleaseF2fsCompressedBlocks(apex.GetPath());
   }
 
-  // Disabling scope guard to stop Failure atoms from being sent
-  guard.Disable();
+  event.MarkSucceeded();
 
   return ret;
 }
@@ -2956,10 +2855,7 @@ Result<void> MarkStagedSessionSuccessful(const int session_id) {
     // TODO: Handle activated apexes still unavailable to apexd at this time.
     // This is because apexd is started before this activation with a linker
     // configuration which doesn't know about statsd
-    SendSessionApexInstallationEndedAtom(
-        session_id,
-        stats::apex::
-            APEX_INSTALLATION_ENDED__INSTALLATION_RESULT__INSTALL_SUCCESSFUL);
+    SendSessionApexInstallationEndedAtom(*session, InstallResult::Success);
     auto cleanup_status = DeleteBackup();
     if (!cleanup_status.ok()) {
       return Error() << "Failed to mark session " << *session
@@ -3090,37 +2986,6 @@ int UnmountAll(bool also_include_staged_apexes) {
   return ret;
 }
 
-Result<void> RemountPackages() {
-  std::vector<std::string> apexes;
-  gMountedApexes.ForallMountedApexes([&apexes](const std::string& /*package*/,
-                                               const MountedApexData& data,
-                                               bool latest) {
-    if (latest) {
-      LOG(DEBUG) << "Found active APEX " << data.full_path;
-      apexes.push_back(data.full_path);
-    }
-  });
-  std::vector<std::string> failed;
-  for (const std::string& apex : apexes) {
-    // Since this is only used during development workflow, we are trying to
-    // remount as many apexes as possible instead of failing fast.
-    if (auto ret = RemountApexFile(apex); !ret.ok()) {
-      LOG(WARNING) << "Failed to remount " << apex << " : " << ret.error();
-      failed.emplace_back(apex);
-    }
-  }
-  static constexpr const char* kErrorMessage =
-      "Failed to remount following APEX packages, hence previous versions of "
-      "them are still active. If APEX you are developing is in this list, it "
-      "means that there still are alive processes holding a reference to the "
-      "previous version of your APEX.\n";
-  if (!failed.empty()) {
-    return Error() << kErrorMessage << "Failed (" << failed.size() << ") "
-                   << "APEX packages: [" << Join(failed, ',') << "]";
-  }
-  return {};
-}
-
 // Given a single new APEX incoming via OTA, should we allocate space for it?
 bool ShouldAllocateSpaceForDecompression(const std::string& new_apex_name,
                                          const int64_t new_apex_version,
@@ -3181,6 +3046,21 @@ int64_t CalculateSizeForCompressedApex(
   return result;
 }
 
+std::string CastPartition(ApexPartition in) {
+  switch (in) {
+    case ApexPartition::System:
+      return "SYSTEM";
+    case ApexPartition::SystemExt:
+      return "SYSTEM_EXT";
+    case ApexPartition::Product:
+      return "PRODUCT";
+    case ApexPartition::Vendor:
+      return "VENDOR";
+    case ApexPartition::Odm:
+      return "ODM";
+  }
+}
+
 void CollectApexInfoList(std::ostream& os,
                          const std::vector<ApexFile>& active_apexs,
                          const std::vector<ApexFile>& inactive_apexs) {
@@ -3197,6 +3077,8 @@ void CollectApexInfoList(std::ostream& os,
       preinstalled_module_path = *preinstalled_path;
     }
 
+    auto partition = CastPartition(OR_FATAL(instance.GetPartition(apex)));
+
     std::optional<int64_t> mtime =
         instance.GetBlockApexLastUpdateSeconds(apex.GetPath());
     if (!mtime.has_value()) {
@@ -3211,7 +3093,7 @@ void CollectApexInfoList(std::ostream& os,
         apex.GetManifest().name(), apex.GetPath(), preinstalled_module_path,
         apex.GetManifest().version(), apex.GetManifest().versionname(),
         instance.IsPreInstalledApex(apex), is_active, mtime,
-        apex.GetManifest().providesharedapexlibs());
+        apex.GetManifest().providesharedapexlibs(), partition);
     apex_infos.emplace_back(std::move(apex_info));
   };
   for (const auto& apex : active_apexs) {
@@ -3320,7 +3202,7 @@ int OnStartInVmMode() {
   auto& instance = ApexFileRepository::GetInstance();
 
   // Scan pre-installed apexes
-  if (auto status = instance.AddPreInstalledApex(gConfig->apex_built_in_dirs);
+  if (auto status = instance.AddPreInstalledApex(gConfig->builtin_dirs);
       !status.ok()) {
     LOG(ERROR) << "Failed to scan pre-installed APEX files: " << status.error();
     return 1;
@@ -3353,10 +3235,10 @@ int OnStartInVmMode() {
 
 int OnOtaChrootBootstrap(bool also_include_staged_apexes) {
   auto& instance = ApexFileRepository::GetInstance();
-  if (auto status = instance.AddPreInstalledApex(gConfig->apex_built_in_dirs);
+  if (auto status = instance.AddPreInstalledApex(gConfig->builtin_dirs);
       !status.ok()) {
     LOG(ERROR) << "Failed to scan pre-installed apexes from "
-               << Join(gConfig->apex_built_in_dirs, ',');
+               << std::format("{}", gConfig->builtin_dirs | std::views::values);
     return 1;
   }
   if (also_include_staged_apexes) {
@@ -3480,28 +3362,26 @@ android::apex::MountedApexDatabase& GetApexDatabaseForTesting() {
 
 // A version of apex verification that happens during non-staged APEX
 // installation.
-Result<void> VerifyPackageNonStagedInstall(const ApexFile& apex_file,
-                                           bool force) {
-  const auto& verify_package_boot_status = VerifyPackageBoot(apex_file);
-  if (!verify_package_boot_status.ok()) {
-    return verify_package_boot_status;
-  }
+Result<VerificationResult> VerifyPackageNonStagedInstall(
+    const ApexFile& apex_file, bool force) {
+  OR_RETURN(VerifyPackageBoot(apex_file));
 
-  auto check_fn = [&apex_file,
-                   &force](const std::string& mount_point) -> Result<void> {
+  auto check_fn =
+      [&apex_file,
+       &force](const std::string& mount_point) -> Result<VerificationResult> {
     if (force) {
-      return Result<void>{};
+      return {};
     }
+    VerificationResult result;
     if (access((mount_point + "/app").c_str(), F_OK) == 0) {
       return Error() << apex_file.GetPath() << " contains app inside";
     }
     if (access((mount_point + "/priv-app").c_str(), F_OK) == 0) {
       return Error() << apex_file.GetPath() << " contains priv-app inside";
     }
-    if (IsVendorApex(apex_file)) {
-      return CheckVendorApexUpdate(apex_file, mount_point);
-    }
-    return Result<void>{};
+    result.apex_hals =
+        OR_RETURN(CheckVintf(Single(apex_file), Single(mount_point)));
+    return result;
   };
   return RunVerifyFnInsideTempMount(apex_file, check_fn);
 }
@@ -3644,13 +3524,17 @@ Result<void> LoadApexFromInit(const std::string& apex_name) {
   return {};
 }
 
-Result<ApexFile> InstallPackageImpl(const std::string& package_path,
-                                    bool force) {
+Result<ApexFile> InstallPackage(const std::string& package_path, bool force) {
+  auto event = InstallRequestedEvent(InstallType::NonStaged,
+                                     /*is_rollback=*/false);
+
   auto temp_apex = ApexFile::Open(package_path);
   if (!temp_apex.ok()) {
     return temp_apex.error();
   }
 
+  event.AddFiles(Single(*temp_apex));
+
   const std::string& module_name = temp_apex->GetManifest().name();
   // Don't allow non-staged update if there are no active versions of this APEX.
   auto cur_mounted_data = gMountedApexes.GetLatestMountedApex(module_name);
@@ -3673,9 +3557,8 @@ Result<ApexFile> InstallPackageImpl(const std::string& package_path,
   // 1. Verify that APEX is correct. This is a heavy check that involves
   // mounting an APEX on a temporary mount point and reading the entire
   // dm-verity block device.
-  if (auto res = VerifyPackageNonStagedInstall(*temp_apex, force); !res.ok()) {
-    return res.error();
-  }
+  auto result = OR_RETURN(VerifyPackageNonStagedInstall(*temp_apex, force));
+  event.AddHals(result.apex_hals);
 
   // 2. Compute params for mounting new apex.
   auto new_id_minor = ComputePackageIdMinor(*temp_apex);
@@ -3765,24 +3648,9 @@ Result<ApexFile> InstallPackageImpl(const std::string& package_path,
   // filesystem.
   ReleaseF2fsCompressedBlocks(target_file);
 
-  return new_apex;
-}
+  event.MarkSucceeded();
 
-Result<ApexFile> InstallPackage(const std::string& package_path, bool force) {
-  LOG(INFO) << "Installing " << package_path;
-  SendApexInstallationRequestedAtom(
-      package_path, /* is_rollback */ false,
-      stats::apex::APEX_INSTALLATION_REQUESTED__INSTALLATION_TYPE__REBOOTLESS);
-  // TODO: Add error-enums
-  Result<ApexFile> ret = InstallPackageImpl(package_path, force);
-  SendApexInstallationEndedAtom(
-      package_path,
-      ret.ok()
-          ? stats::apex::
-                APEX_INSTALLATION_ENDED__INSTALLATION_RESULT__INSTALL_SUCCESSFUL
-          : stats::apex::
-                APEX_INSTALLATION_ENDED__INSTALLATION_RESULT__INSTALL_FAILURE_APEX_INSTALLATION);
-  return ret;
+  return new_apex;
 }
 
 bool IsActiveApexChanged(const ApexFile& apex) {
diff --git a/apexd/apexd.h b/apexd/apexd.h
index 8d5dbdf4..8ccb59c2 100644
--- a/apexd/apexd.h
+++ b/apexd/apexd.h
@@ -42,7 +42,7 @@ namespace apex {
 // this config should do the trick.
 struct ApexdConfig {
   const char* apex_status_sysprop;
-  std::vector<std::string> apex_built_in_dirs;
+  std::unordered_map<ApexPartition, std::string> builtin_dirs;
   const char* active_apex_data_dir;
   const char* decompression_dir;
   const char* ota_reserved_dir;
@@ -58,7 +58,7 @@ struct ApexdConfig {
 
 static const ApexdConfig kDefaultConfig = {
     kApexStatusSysprop,
-    kApexPackageBuiltinDirs,
+    kBuiltinApexPackageDirs,
     kActiveApexPackagesDataDir,
     kApexDecompressedDir,
     kOtaReservedDir,
@@ -186,10 +186,6 @@ int UnmountAll(bool also_include_staged_apexes);
 android::base::Result<MountedApexDatabase::MountedApexData>
 GetTempMountedApexData(const std::string& package);
 
-// Optimistically tries to remount as many APEX packages as possible.
-// For more documentation see corresponding binder call in IApexService.aidl.
-android::base::Result<void> RemountPackages();
-
 // Exposed for unit tests
 bool ShouldAllocateSpaceForDecompression(const std::string& new_apex_name,
                                          int64_t new_apex_version,
@@ -200,6 +196,8 @@ int64_t CalculateSizeForCompressedApex(
         compressed_apexes,
     const ApexFileRepository& instance);
 
+// Casts |ApexPartition| to partition string used in XSD.
+std::string CastPartition(ApexPartition partition);
 void CollectApexInfoList(std::ostream& os,
                          const std::vector<ApexFile>& active_apexs,
                          const std::vector<ApexFile>& inactive_apexs);
@@ -222,9 +220,6 @@ android::apex::MountedApexDatabase& GetApexDatabaseForTesting();
 android::base::Result<ApexFile> InstallPackage(const std::string& package_path,
                                                bool force);
 
-// Exposed for testing.
-android::base::Result<int> AddBlockApex(ApexFileRepository& instance);
-
 bool IsActiveApexChanged(const ApexFile& apex);
 
 // Shouldn't be used outside of apexd_test.cpp
diff --git a/apexd/apexd_brand_new_verifier.cpp b/apexd/apexd_brand_new_verifier.cpp
new file mode 100644
index 00000000..aa9b120c
--- /dev/null
+++ b/apexd/apexd_brand_new_verifier.cpp
@@ -0,0 +1,76 @@
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
+#include "apexd_brand_new_verifier.h"
+
+#include <optional>
+#include <string>
+
+#include "android-base/logging.h"
+#include "apex_constants.h"
+#include "apex_file_repository.h"
+
+using android::base::Error;
+using android::base::Result;
+
+namespace android::apex {
+
+Result<ApexPartition> VerifyBrandNewPackageAgainstPreinstalled(
+    const ApexFile& apex) {
+  CHECK(ApexFileRepository::IsBrandNewApexEnabled())
+      << "Brand-new APEX must be enabled in order to do verification.";
+
+  const std::string& name = apex.GetManifest().name();
+  const auto& file_repository = ApexFileRepository::GetInstance();
+  auto partition = file_repository.GetBrandNewApexPublicKeyPartition(
+      apex.GetBundledPublicKey());
+  if (!partition.has_value()) {
+    return Error()
+           << "No pre-installed public key found for the brand-new APEX: "
+           << name;
+  }
+
+  if (apex.GetManifest().version() <=
+      file_repository.GetBrandNewApexBlockedVersion(partition.value(), name)) {
+    return Error() << "Brand-new APEX is blocked: " << name;
+  }
+
+  return partition.value();
+}
+
+Result<void> VerifyBrandNewPackageAgainstActive(const ApexFile& apex) {
+  CHECK(ApexFileRepository::IsBrandNewApexEnabled())
+      << "Brand-new APEX must be enabled in order to do verification.";
+
+  const std::string& name = apex.GetManifest().name();
+  const auto& file_repository = ApexFileRepository::GetInstance();
+
+  if (file_repository.HasPreInstalledVersion(name)) {
+    return {};
+  }
+
+  if (file_repository.HasDataVersion(name)) {
+    auto existing_package = file_repository.GetDataApex(name).get();
+    if (apex.GetBundledPublicKey() != existing_package.GetBundledPublicKey()) {
+      return Error()
+             << "Brand-new APEX public key doesn't match existing active APEX: "
+             << name;
+    }
+  }
+  return {};
+}
+
+}  // namespace android::apex
diff --git a/apexd/apexd_brand_new_verifier.h b/apexd/apexd_brand_new_verifier.h
new file mode 100644
index 00000000..fb1738cd
--- /dev/null
+++ b/apexd/apexd_brand_new_verifier.h
@@ -0,0 +1,53 @@
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
+#pragma once
+
+#include <android-base/result.h>
+
+#include <string>
+
+#include "apex_constants.h"
+#include "apex_file.h"
+
+namespace android::apex {
+
+// Verifies a specific brand-new package against the
+// pre-installed public keys and blocklists. The housing partition of the public
+// key and blocklist is returned if the verification succeeds. Verifies a
+// brand-new APEX in that
+// 1. brand-new APEX is enabled
+// 2. it matches exactly one certificate in one of the built-in partitions
+// 3. its name and version are not blocked by the blocklist in the matching
+// partition
+//
+// The function is called in
+// |SubmitStagedSession| (brand-new apex becomes 'staged')
+// |ScanStagedSessionsDirAndStage| ('staged' apex becomes 'active')
+// |ApexFileRepository::AddDataApex| (add 'active' apex to repository)
+android::base::Result<ApexPartition> VerifyBrandNewPackageAgainstPreinstalled(
+    const ApexFile& apex);
+
+// Returns the verification result of a specific brand-new package.
+// Verifies a brand-new APEX in that its public key is the same as the existing
+// active version if any. Pre-installed APEX is skipped.
+//
+// The function is called in
+// |SubmitStagedSession| (brand-new apex becomes 'staged')
+android::base::Result<void> VerifyBrandNewPackageAgainstActive(
+    const ApexFile& apex);
+
+}  // namespace android::apex
diff --git a/apexd/apexd_brand_new_verifier_test.cpp b/apexd/apexd_brand_new_verifier_test.cpp
new file mode 100644
index 00000000..78d4675f
--- /dev/null
+++ b/apexd/apexd_brand_new_verifier_test.cpp
@@ -0,0 +1,223 @@
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
+#include "apexd_brand_new_verifier.h"
+
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/properties.h>
+#include <android-base/result-gmock.h>
+#include <android-base/stringprintf.h>
+#include <gtest/gtest.h>
+#include <sys/stat.h>
+
+#include <filesystem>
+#include <string>
+
+#include "apex_constants.h"
+#include "apex_file_repository.h"
+#include "apexd_test_utils.h"
+
+namespace android::apex {
+
+namespace fs = std::filesystem;
+
+using android::base::GetExecutableDirectory;
+using android::base::testing::Ok;
+using android::base::testing::WithMessage;
+using ::testing::Not;
+
+static std::string GetTestDataDir() { return GetExecutableDirectory(); }
+static std::string GetTestFile(const std::string& name) {
+  return GetTestDataDir() + "/" + name;
+}
+
+TEST(BrandNewApexVerifierTest, SucceedPublicKeyMatch) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = VerifyBrandNewPackageAgainstPreinstalled(*apex);
+  ASSERT_RESULT_OK(ret);
+  ASSERT_EQ(*ret, partition);
+
+  file_repository.Reset();
+}
+
+TEST(BrandNewApexVerifierTest, SucceedVersionBiggerThanBlocked) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir config_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           config_dir.path);
+  fs::copy(GetTestFile("apexd_testdata/blocklist.json"), config_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, config_dir.path}});
+
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.v2.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = VerifyBrandNewPackageAgainstPreinstalled(*apex);
+  ASSERT_RESULT_OK(ret);
+  ASSERT_EQ(*ret, partition);
+
+  file_repository.Reset();
+}
+
+TEST(BrandNewApexVerifierTest, SucceedMatchActive) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  TemporaryDir trusted_key_dir, data_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{ApexPartition::System, trusted_key_dir.path}});
+  file_repository.AddDataApex(data_dir.path);
+
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.v2.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = VerifyBrandNewPackageAgainstActive(*apex);
+  ASSERT_RESULT_OK(ret);
+
+  file_repository.Reset();
+}
+
+TEST(BrandNewApexVerifierTest, SucceedSkipPreinstalled) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  TemporaryDir built_in_dir;
+  fs::copy(GetTestFile("apex.apexd_test.apex"), built_in_dir.path);
+  file_repository.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}});
+
+  auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = VerifyBrandNewPackageAgainstActive(*apex);
+  ASSERT_RESULT_OK(ret);
+
+  file_repository.Reset();
+}
+
+TEST(BrandNewApexVerifierTest, SucceedSkipWithoutDataVersion) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = VerifyBrandNewPackageAgainstActive(*apex);
+  ASSERT_RESULT_OK(ret);
+
+  file_repository.Reset();
+}
+
+TEST(BrandNewApexVerifierTest, FailBrandNewApexDisabled) {
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  ASSERT_DEATH(
+      { VerifyBrandNewPackageAgainstPreinstalled(*apex); },
+      "Brand-new APEX must be enabled in order to do verification.");
+  ASSERT_DEATH(
+      { VerifyBrandNewPackageAgainstActive(*apex); },
+      "Brand-new APEX must be enabled in order to do verification.");
+
+  file_repository.Reset();
+}
+
+TEST(BrandNewApexVerifierTest, FailNoMatchingPublicKey) {
+  ApexFileRepository::EnableBrandNewApex();
+
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = VerifyBrandNewPackageAgainstPreinstalled(*apex);
+  ASSERT_THAT(
+      ret,
+      HasError(WithMessage(("No pre-installed public key found for the "
+                            "brand-new APEX: com.android.apex.brand.new"))));
+}
+
+TEST(BrandNewApexVerifierTest, FailBlockedByVersion) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir config_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           config_dir.path);
+  fs::copy(GetTestFile("apexd_testdata/blocklist.json"), config_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, config_dir.path}});
+
+  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = VerifyBrandNewPackageAgainstPreinstalled(*apex);
+  ASSERT_THAT(ret,
+              HasError(WithMessage(
+                  ("Brand-new APEX is blocked: com.android.apex.brand.new"))));
+
+  file_repository.Reset();
+}
+
+TEST(BrandNewApexVerifierTest, FailPublicKeyNotMatchActive) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  TemporaryDir trusted_key_dir, data_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  fs::copy(GetTestFile(
+               "apexd_testdata/com.android.apex.brand.new.another.avbpubkey"),
+           trusted_key_dir.path);
+  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{ApexPartition::System, trusted_key_dir.path}});
+  file_repository.AddDataApex(data_dir.path);
+
+  auto apex =
+      ApexFile::Open(GetTestFile("com.android.apex.brand.new.v2.diffkey.apex"));
+  ASSERT_RESULT_OK(apex);
+
+  auto ret = VerifyBrandNewPackageAgainstActive(*apex);
+  ASSERT_THAT(
+      ret,
+      HasError(WithMessage(("Brand-new APEX public key doesn't match existing "
+                            "active APEX: com.android.apex.brand.new"))));
+
+  file_repository.Reset();
+}
+
+}  // namespace android::apex
diff --git a/apexd/apexd_loop.cpp b/apexd/apexd_loop.cpp
index 49f32869..a8155cd1 100644
--- a/apexd/apexd_loop.cpp
+++ b/apexd/apexd_loop.cpp
@@ -325,11 +325,20 @@ Result<void> PreAllocateLoopDevices(size_t num) {
   return {};
 }
 
-Result<void> ConfigureLoopDevice(const int device_fd, const std::string& target,
-                                 const uint32_t image_offset,
-                                 const size_t image_size) {
+// This is a temporary/empty object for a loop device before the backing file is
+// set.
+struct EmptyLoopDevice {
+  unique_fd fd;
+  std::string name;
+  LoopbackDeviceUniqueFd ToOwned() { return {std::move(fd), std::move(name)}; }
+};
+
+static Result<LoopbackDeviceUniqueFd> ConfigureLoopDevice(
+    EmptyLoopDevice&& inner, const std::string& target,
+    const uint32_t image_offset, const size_t image_size) {
   static bool use_loop_configure;
   static std::once_flag once_flag;
+  auto device_fd = inner.fd.get();
   std::call_once(once_flag, [&]() {
     // LOOP_CONFIGURE is a new ioctl in Linux 5.8 (and backported in Android
     // common) that allows atomically configuring a loop device. It is a lot
@@ -396,11 +405,13 @@ Result<void> ConfigureLoopDevice(const int device_fd, const std::string& target,
       return ErrnoError() << "Failed to LOOP_CONFIGURE";
     }
 
-    return {};
+    return inner.ToOwned();
   } else {
     if (ioctl(device_fd, LOOP_SET_FD, target_fd.get()) == -1) {
       return ErrnoError() << "Failed to LOOP_SET_FD";
     }
+    // Now, we have a fully-owned loop device.
+    LoopbackDeviceUniqueFd loop_device = inner.ToOwned();
 
     if (ioctl(device_fd, LOOP_SET_STATUS64, &li) == -1) {
       return ErrnoError() << "Failed to LOOP_SET_STATUS64";
@@ -433,12 +444,12 @@ Result<void> ConfigureLoopDevice(const int device_fd, const std::string& target,
     if (ioctl(device_fd, LOOP_SET_BLOCK_SIZE, 4096) == -1) {
       PLOG(WARNING) << "Failed to LOOP_SET_BLOCK_SIZE";
     }
+    return loop_device;
   }
-  return {};
 }
 
-Result<LoopbackDeviceUniqueFd> WaitForDevice(int num) {
-  const std::vector<std::string> candidate_devices = {
+static Result<EmptyLoopDevice> WaitForLoopDevice(int num) {
+  std::vector<std::string> candidate_devices = {
       StringPrintf("/dev/block/loop%d", num),
       StringPrintf("/dev/loop%d", num),
   };
@@ -462,7 +473,7 @@ Result<LoopbackDeviceUniqueFd> WaitForDevice(int num) {
     for (const auto& device : candidate_devices) {
       unique_fd sysfs_fd(open(device.c_str(), O_RDWR | O_CLOEXEC));
       if (sysfs_fd.get() != -1) {
-        return LoopbackDeviceUniqueFd(std::move(sysfs_fd), device);
+        return EmptyLoopDevice{std::move(sysfs_fd), std::move(device)};
       }
     }
     PLOG(WARNING) << "Loopback device " << num << " not ready. Waiting 50ms...";
@@ -476,9 +487,8 @@ Result<LoopbackDeviceUniqueFd> WaitForDevice(int num) {
   return Error() << "Failed to open loopback device " << num;
 }
 
-Result<LoopbackDeviceUniqueFd> CreateLoopDevice(const std::string& target,
-                                                uint32_t image_offset,
-                                                size_t image_size) {
+static Result<LoopbackDeviceUniqueFd> CreateLoopDevice(
+    const std::string& target, uint32_t image_offset, size_t image_size) {
   ATRACE_NAME("CreateLoopDevice");
 
   unique_fd ctl_fd(open("/dev/loop-control", O_RDWR | O_CLOEXEC));
@@ -493,24 +503,11 @@ Result<LoopbackDeviceUniqueFd> CreateLoopDevice(const std::string& target,
     return ErrnoError() << "Failed LOOP_CTL_GET_FREE";
   }
 
-  Result<LoopbackDeviceUniqueFd> loop_device = WaitForDevice(num);
-  if (!loop_device.ok()) {
-    return loop_device.error();
-  }
-  CHECK_NE(loop_device->device_fd.get(), -1);
-
-  Result<void> configure_status = ConfigureLoopDevice(
-      loop_device->device_fd.get(), target, image_offset, image_size);
-  if (!configure_status.ok() && configure_status.error().code() == EBUSY) {
-    // EBUSY means that loop device was bound to a different process. We need to call
-    // CloseGood() here to ensure that when destroying LoopbackDeviceUniqueFd we
-    // don't call LOOP_CLR_FD ioctl on this loop device, essentially clearing the
-    // loop device while other process is using it.
-    loop_device->CloseGood();
-    return configure_status.error();
-  }
+  auto loop_device = OR_RETURN(WaitForLoopDevice(num));
+  CHECK_NE(loop_device.fd.get(), -1);
 
-  return loop_device;
+  return ConfigureLoopDevice(std::move(loop_device), target, image_offset,
+                             image_size);
 }
 
 Result<LoopbackDeviceUniqueFd> CreateAndConfigureLoopDevice(
diff --git a/apexd/apexd_loop.h b/apexd/apexd_loop.h
index 3c356d94..14ff8a3f 100644
--- a/apexd/apexd_loop.h
+++ b/apexd/apexd_loop.h
@@ -55,8 +55,6 @@ struct LoopbackDeviceUniqueFd {
   int Get() { return device_fd.get(); }
 };
 
-android::base::Result<LoopbackDeviceUniqueFd> WaitForDevice(int num);
-
 android::base::Result<void> ConfigureQueueDepth(
     const std::string& loop_device_path, const std::string& file_path);
 
diff --git a/apexd/apexd_main.cpp b/apexd/apexd_main.cpp
index d216bc8d..91cbfb88 100644
--- a/apexd/apexd_main.cpp
+++ b/apexd/apexd_main.cpp
@@ -24,10 +24,15 @@
 
 #include <memory>
 
+#include "apex_file_repository.h"
 #include "apexd.h"
 #include "apexd_checkpoint_vold.h"
 #include "apexd_lifecycle.h"
+#include "apexd_metrics_stats.h"
 #include "apexservice.h"
+#include "com_android_apex_flags.h"
+
+namespace flags = com::android::apex::flags;
 
 namespace {
 
@@ -132,6 +137,19 @@ int main(int argc, char** argv) {
   // TODO(b/158468454): add a -v flag or an external setting to change severity.
   android::base::SetMinimumLogSeverity(android::base::INFO);
 
+  // Two flags are used here:
+  // CLI flag `--enable-brand-new-apex`: used to control the feature usage in
+  // individual targets
+  // AConfig flag `enable_brand_new_apex`: used to advance
+  // the feature to different release stages, and applies to all targets
+  if (flags::enable_brand_new_apex()) {
+    if (argv[1] != nullptr && strcmp("--enable-brand-new-apex", argv[1]) == 0) {
+      android::apex::ApexFileRepository::EnableBrandNewApex();
+      argc--;
+      argv++;
+    }
+  }
+
   const bool has_subcommand = argv[1] != nullptr;
   LOG(INFO) << "Started. subcommand = "
             << (has_subcommand ? argv[1] : "(null)");
@@ -174,6 +192,7 @@ int main(int argc, char** argv) {
     vold_service = &*vold_service_st;
   }
   android::apex::Initialize(vold_service);
+  android::apex::InitMetrics(std::make_unique<android::apex::StatsLog>());
 
   if (booting) {
     auto res = session_manager->MigrateFromOldSessionsDir(
diff --git a/apexd/apexd_metrics.cpp b/apexd/apexd_metrics.cpp
index 4922091f..fde6f9d3 100644
--- a/apexd/apexd_metrics.cpp
+++ b/apexd/apexd_metrics.cpp
@@ -14,139 +14,135 @@
  * limitations under the License.
  */
 
-#include <statssocket_lazy.h>
+#include "apexd_metrics.h"
+
+#include <android-base/logging.h>
+#include <android-base/result.h>
+#include <android-base/strings.h>
 #include <sys/stat.h>
 
+#include <utility>
+
+#include "apex_constants.h"
+#include "apex_file.h"
+#include "apex_file_repository.h"
 #include "apex_sha.h"
-#include "apexd.h"
+#include "apexd_session.h"
 #include "apexd_vendor_apex.h"
-#include "statslog_apex.h"
 
 using android::base::Result;
+using android::base::StartsWith;
 
 namespace android::apex {
 
-// Ties sessions to their apex file, assists reporting installation metrics
-std::unordered_map<int, std::vector<std::string>> gSessionApexSha;
+namespace {
 
-void SendApexInstallationRequestedAtom(const std::string& package_path,
-                                       bool is_rollback,
-                                       unsigned int install_type) {
-  if (!statssocket::lazy::IsAvailable()) {
-    LOG(WARNING) << "Unable to send Apex Install Atom for " << package_path
-                 << " ; libstatssocket is not available";
-    return;
-  }
-  auto apex_file = ApexFile::Open(package_path);
-  if (!apex_file.ok()) {
-    LOG(WARNING) << "Unable to send Apex Atom; Failed to open ApexFile "
-                 << package_path << ": " << apex_file.error();
-    return;
-  }
-  const std::string& module_name = apex_file->GetManifest().name();
-  struct stat stat_buf;
-  intmax_t apex_file_size;
-  if (stat(package_path.c_str(), &stat_buf) == 0) {
-    apex_file_size = stat_buf.st_size;
-  } else {
-    PLOG(WARNING) << "Failed to stat " << package_path;
-    apex_file_size = 0;
-  }
-  Result<std::string> apex_file_sha256_str = CalculateSha256(package_path);
-  if (!apex_file_sha256_str.ok()) {
-    LOG(WARNING) << "Unable to get sha256 of ApexFile: "
-                 << apex_file_sha256_str.error();
-    return;
-  }
-  const std::vector<const char*>
-      hal_cstr_list;  // TODO(b/366217822): Populate HAL information
-  int ret = stats::apex::stats_write(
-      stats::apex::APEX_INSTALLATION_REQUESTED, module_name.c_str(),
-      apex_file->GetManifest().version(), apex_file_size,
-      apex_file_sha256_str->c_str(), GetPreinstallPartitionEnum(*apex_file),
-      install_type, is_rollback,
-      apex_file->GetManifest().providesharedapexlibs(), hal_cstr_list);
-  if (ret < 0) {
-    LOG(WARNING) << "Failed to report apex_installation_requested stats";
-  }
+std::unique_ptr<Metrics> gMetrics;
+
+}  // namespace
+
+std::unique_ptr<Metrics> InitMetrics(std::unique_ptr<Metrics> metrics) {
+  std::swap(gMetrics, metrics);
+  return metrics;
 }
 
-void SendApexInstallationStagedAtom(const std::string& package_path) {
-  if (!statssocket::lazy::IsAvailable()) {
-    LOG(WARNING) << "Unable to send Apex Staged Atom for " << package_path
-                 << " ; libstatssocket is not available";
+void SendApexInstallationEndedAtom(const std::string& package_path,
+                                   InstallResult install_result) {
+  if (!gMetrics) {
     return;
   }
-  Result<std::string> apex_file_sha256_str = CalculateSha256(package_path);
-  if (!apex_file_sha256_str.ok()) {
-    LOG(WARNING) << "Unable to get sha256 of ApexFile: "
-                 << apex_file_sha256_str.error();
+  Result<std::string> hash = CalculateSha256(package_path);
+  if (!hash.ok()) {
+    LOG(WARNING) << "Unable to get sha256 of ApexFile: " << hash.error();
     return;
   }
-  int ret = stats::apex::stats_write(stats::apex::APEX_INSTALLATION_STAGED,
-                                     apex_file_sha256_str->c_str());
-  if (ret < 0) {
-    LOG(WARNING) << "Failed to report apex_installation_staged stats";
-  }
+  gMetrics->SendInstallationEnded(*hash, install_result);
 }
 
-void SendApexInstallationEndedAtom(const std::string& package_path,
-                                   int install_result) {
-  if (!statssocket::lazy::IsAvailable()) {
-    LOG(WARNING) << "Unable to send Apex Ended Atom for " << package_path
-                 << " ; libstatssocket is not available";
+void SendSessionApexInstallationEndedAtom(const ApexSession& session,
+                                          InstallResult install_result) {
+  if (!gMetrics) {
     return;
   }
-  Result<std::string> apex_file_sha256_str = CalculateSha256(package_path);
-  if (!apex_file_sha256_str.ok()) {
-    LOG(WARNING) << "Unable to get sha256 of ApexFile: "
-                 << apex_file_sha256_str.error();
-    return;
-  }
-  int ret =
-      stats::apex::stats_write(stats::apex::APEX_INSTALLATION_ENDED,
-                               apex_file_sha256_str->c_str(), install_result);
-  if (ret < 0) {
-    LOG(WARNING) << "Failed to report apex_installation_ended stats";
+
+  for (const auto& hash : session.GetApexFileHashes()) {
+    gMetrics->SendInstallationEnded(hash, install_result);
   }
 }
 
-void SendSessionApexInstallationEndedAtom(int session_id, int install_result) {
-  if (!statssocket::lazy::IsAvailable()) {
-    LOG(WARNING) << "Unable to send Apex Ended Atom for session " << session_id
-                 << " ; libstatssocket is not available";
+InstallRequestedEvent::~InstallRequestedEvent() {
+  if (!gMetrics) {
     return;
   }
-  if (gSessionApexSha.find(session_id) == gSessionApexSha.end()) {
-    LOG(WARNING) << "Unable to send Apex Ended Atom for session " << session_id
-                 << " ; apex_sha for session was not found";
+  for (const auto& info : files_) {
+    gMetrics->SendInstallationRequested(install_type_, is_rollback_, info);
+  }
+  // Staged installation ends later. No need to send "end" event now.
+  if (succeeded_ && install_type_ == InstallType::Staged) {
     return;
   }
-  for (const auto& apex_sha : gSessionApexSha[session_id]) {
-    int ret = stats::apex::stats_write(stats::apex::APEX_INSTALLATION_ENDED,
-                                       apex_sha.c_str(), install_result);
-    if (ret < 0) {
-      LOG(WARNING) << "Failed to report apex_installation_ended stats";
-    }
+  auto result = succeeded_ ? InstallResult::Success : InstallResult::Failure;
+  for (const auto& info : files_) {
+    gMetrics->SendInstallationEnded(info.file_hash, result);
   }
 }
 
-void SendApexInstallationStagedAtoms(
-    const std::vector<std::string>& package_paths) {
-  for (const std::string& path : package_paths) {
-    SendApexInstallationStagedAtom(path);
+void InstallRequestedEvent::MarkSucceeded() { succeeded_ = true; }
+
+void InstallRequestedEvent::AddFiles(std::span<const ApexFile> files) {
+  auto& repo = ApexFileRepository::GetInstance();
+  files_.reserve(files.size());
+  for (const auto& file : files) {
+    Metrics::ApexFileInfo info;
+    info.name = file.GetManifest().name();
+    info.version = file.GetManifest().version();
+    info.shared_libs = file.GetManifest().providesharedapexlibs();
+
+    const auto& file_path = file.GetPath();
+    struct stat stat_buf;
+    if (stat(file_path.c_str(), &stat_buf) == 0) {
+      info.file_size = stat_buf.st_size;
+    } else {
+      PLOG(WARNING) << "Failed to stat " << file_path;
+      continue;
+    }
+
+    if (auto result = CalculateSha256(file_path); result.ok()) {
+      info.file_hash = result.value();
+    } else {
+      LOG(WARNING) << "Unable to get sha256 of " << file_path << ": "
+                   << result.error();
+      continue;
+    }
+
+    if (auto result = repo.GetPartition(file); result.ok()) {
+      info.partition = result.value();
+    } else {
+      LOG(WARNING) << "Failed to get partition of " << file_path << ": "
+                   << result.error();
+      continue;
+    }
+
+    files_.push_back(std::move(info));
   }
 }
 
-void SendApexInstallationEndedAtoms(
-    const std::vector<std::string>& package_paths, int install_result) {
-  for (const std::string& path : package_paths) {
-    SendApexInstallationEndedAtom(path, install_result);
+void InstallRequestedEvent::AddHals(
+    const std::map<std::string, std::vector<std::string>>& hals) {
+  for (auto& info : files_) {
+    if (auto it = hals.find(info.name); it != hals.end()) {
+      info.hals = it->second;
+    }
   }
 }
 
-void RegisterSessionApexSha(int session_id, const std::string apex_file_sha) {
-  gSessionApexSha[session_id].push_back(apex_file_sha);
+std::vector<std::string> InstallRequestedEvent::GetFileHashes() const {
+  std::vector<std::string> hashes;
+  hashes.reserve(files_.size());
+  for (const auto& info : files_) {
+    hashes.push_back(info.file_hash);
+  }
+  return hashes;
 }
 
 }  // namespace android::apex
diff --git a/apexd/apexd_metrics.h b/apexd/apexd_metrics.h
index e46f9a8b..dce8c3d6 100644
--- a/apexd/apexd_metrics.h
+++ b/apexd/apexd_metrics.h
@@ -16,26 +16,82 @@
 
 #pragma once
 
+#include <map>
+#include <memory>
+#include <span>
+#include <string>
+#include <vector>
+
+#include "apex_constants.h"
+
 namespace android::apex {
 
-void RegisterSessionApexSha(int session_id, const std::string apex_file_sha);
+class ApexFile;
+class ApexSession;
+
+enum class InstallType {
+  Staged,
+  NonStaged,
+};
+
+enum class InstallResult {
+  Success,
+  Failure,
+};
+
+class Metrics {
+ public:
+  struct ApexFileInfo {
+    std::string name;
+    int64_t version;
+    bool shared_libs;
+    int64_t file_size;
+    std::string file_hash;
+    ApexPartition partition;
+    std::vector<std::string> hals;
+  };
+
+  virtual ~Metrics() = default;
+  virtual void SendInstallationRequested(InstallType install_type,
+                                         bool is_rollback,
+                                         const ApexFileInfo& info) = 0;
+  virtual void SendInstallationEnded(const std::string& file_hash,
+                                     InstallResult result) = 0;
+};
+
+std::unique_ptr<Metrics> InitMetrics(std::unique_ptr<Metrics> metrics);
+
+void SendSessionApexInstallationEndedAtom(const ApexSession& session,
+                                          InstallResult install_result);
 
-void SendApexInstallationRequestedAtom(const std::string& package_path,
-                                       bool is_rollback,
-                                       unsigned int install_type);
+// Helper class to send "installation_requested" event. Events are
+// sent in its destructor using Metrics::Send* methods.
+class InstallRequestedEvent {
+ public:
+  InstallRequestedEvent(InstallType install_type, bool is_rollback)
+      : install_type_(install_type), is_rollback_(is_rollback) {}
+  // Sends the "requested" event.
+  // Sends the "end" event if it's non-staged or failed.
+  ~InstallRequestedEvent();
 
-void SendApexInstallationStagedAtom(const std::string& package_path);
+  void AddFiles(std::span<const ApexFile> files);
 
-void SendApexInstallationEndedAtom(const std::string& package_path,
-                                   int install_result);
+  // Adds HAL Information for each APEX.
+  // Since the event can contain multiple APEX files, HAL information is
+  // passed as a map of APEX name to a list of HAL names.
+  void AddHals(const std::map<std::string, std::vector<std::string>>& hals);
 
-void SendSessionApexInstallationEndedAtom(int session_id, int install_result);
+  // Marks the current installation request has succeeded.
+  void MarkSucceeded();
 
-void SendApexInstallationStagedAtoms(
-    const std::vector<std::string>& package_paths);
-void SendApexInstallationEndedAtoms(
-    const std::vector<std::string>& package_paths, int install_result);
+  // Returns file hashes for APEX files added by AddFile()
+  std::vector<std::string> GetFileHashes() const;
 
-void SendApexInstallationFailedAtoms(const std::vector<ApexFile>& apexes);
+ private:
+  InstallType install_type_;
+  bool is_rollback_;
+  std::vector<Metrics::ApexFileInfo> files_;
+  bool succeeded_ = false;
+};
 
 }  // namespace android::apex
diff --git a/apexd/apexd_metrics_stats.cpp b/apexd/apexd_metrics_stats.cpp
new file mode 100644
index 00000000..39bb8108
--- /dev/null
+++ b/apexd/apexd_metrics_stats.cpp
@@ -0,0 +1,111 @@
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
+#include "apexd_metrics_stats.h"
+
+#include <android-base/logging.h>
+#include <unistd.h>
+
+#include "apex_constants.h"
+#include "apexd_metrics.h"
+#include "statslog_apex.h"
+
+namespace android::apex {
+
+namespace {
+
+int Cast(InstallType install_type) {
+  switch (install_type) {
+    case InstallType::Staged:
+      return stats::apex::
+          APEX_INSTALLATION_REQUESTED__INSTALLATION_TYPE__STAGED;
+    case InstallType::NonStaged:
+      return stats::apex::
+          APEX_INSTALLATION_REQUESTED__INSTALLATION_TYPE__REBOOTLESS;
+  }
+}
+
+int Cast(InstallResult install_result) {
+  switch (install_result) {
+    case InstallResult::Success:
+      return stats::apex::
+          APEX_INSTALLATION_ENDED__INSTALLATION_RESULT__INSTALL_SUCCESSFUL;
+    case InstallResult::Failure:
+      return stats::apex::
+          APEX_INSTALLATION_ENDED__INSTALLATION_RESULT__INSTALL_FAILURE_APEX_INSTALLATION;
+  }
+}
+
+int Cast(ApexPartition partition) {
+  switch (partition) {
+    case ApexPartition::System:
+      return stats::apex::
+          APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_SYSTEM;
+    case ApexPartition::SystemExt:
+      return stats::apex::
+          APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_SYSTEM_EXT;
+    case ApexPartition::Product:
+      return stats::apex::
+          APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_PRODUCT;
+    case ApexPartition::Vendor:
+      return stats::apex::
+          APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_VENDOR;
+    case ApexPartition::Odm:
+      return stats::apex::
+          APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_ODM;
+  }
+}
+
+}  // namespace
+
+void StatsLog::SendInstallationRequested(InstallType install_type,
+                                         bool is_rollback,
+                                         const ApexFileInfo& info) {
+  if (!IsAvailable()) {
+    LOG(WARNING) << "Unable to send atom: libstatssocket is not available";
+    return;
+  }
+  std::vector<const char*> hals_cstr;
+  for (const auto& hal : info.hals) {
+    hals_cstr.push_back(hal.c_str());
+  }
+  int ret = stats::apex::stats_write(
+      stats::apex::APEX_INSTALLATION_REQUESTED, info.name.c_str(), info.version,
+      info.file_size, info.file_hash.c_str(), Cast(info.partition),
+      Cast(install_type), is_rollback, info.shared_libs, hals_cstr);
+  if (ret < 0) {
+    LOG(WARNING) << "Failed to report apex_installation_requested stats";
+  }
+}
+
+void StatsLog::SendInstallationEnded(const std::string& file_hash,
+                                     InstallResult result) {
+  if (!IsAvailable()) {
+    LOG(WARNING) << "Unable to send atom: libstatssocket is not available";
+    return;
+  }
+  int ret = stats::apex::stats_write(stats::apex::APEX_INSTALLATION_ENDED,
+                                     file_hash.c_str(), Cast(result));
+  if (ret < 0) {
+    LOG(WARNING) << "Failed to report apex_installation_ended stats";
+  }
+}
+
+bool StatsLog::IsAvailable() {
+  return access("/apex/com.android.os.statsd", F_OK) == 0;
+}
+
+}  // namespace android::apex
diff --git a/apexd/apexd_metrics_stats.h b/apexd/apexd_metrics_stats.h
new file mode 100644
index 00000000..4e675b10
--- /dev/null
+++ b/apexd/apexd_metrics_stats.h
@@ -0,0 +1,40 @@
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
+#pragma once
+
+#include <string>
+
+#include "apex_constants.h"
+#include "apexd_metrics.h"
+
+namespace android::apex {
+
+class StatsLog : public Metrics {
+ public:
+  StatsLog() = default;
+  ~StatsLog() override = default;
+
+  void SendInstallationRequested(InstallType install_type, bool is_rollback,
+                                 const ApexFileInfo& info) override;
+  void SendInstallationEnded(const std::string& file_hash,
+                             InstallResult result) override;
+
+ private:
+  bool IsAvailable();
+};
+
+}  // namespace android::apex
diff --git a/apexd/apexd_microdroid.cpp b/apexd/apexd_microdroid.cpp
index 15b540e3..41f20f05 100644
--- a/apexd/apexd_microdroid.cpp
+++ b/apexd/apexd_microdroid.cpp
@@ -17,6 +17,7 @@
 // Entry for microdroid-specific apexd. This should be kept as minimal as
 // possible.
 
+#include "apex_constants.h"
 #define LOG_TAG "apexd-vm"
 
 #include <android-base/logging.h>
@@ -26,7 +27,8 @@
 
 static const android::apex::ApexdConfig kMicrodroidConfig = {
     android::apex::kApexStatusSysprop,
-    {android::apex::kApexPackageSystemDir},
+    {{android::apex::ApexPartition::System,
+      android::apex::kApexPackageSystemDir}},
     // A bunch of things are not used in Microdroid, hence we use nullptr
     // instead of an actual value.
     nullptr, /* active_apex_data_dir */
diff --git a/apexd/apexd_private.h b/apexd/apexd_private.h
index ea8d1504..9d66f143 100644
--- a/apexd/apexd_private.h
+++ b/apexd/apexd_private.h
@@ -17,9 +17,10 @@
 #ifndef ANDROID_APEXD_APEXD_PRIVATE_H_
 #define ANDROID_APEXD_APEXD_PRIVATE_H_
 
+#include <android-base/result.h>
+
 #include <string>
 
-#include <android-base/result.h>
 #include "apex_database.h"
 #include "apex_file.h"
 #include "apex_manifest.h"
@@ -33,6 +34,8 @@ static constexpr int kMkdirMode = 0755;
 
 namespace apexd_private {
 
+android::base::Result<std::string> GetVerifiedPublicKey(const ApexFile& apex);
+
 std::string GetPackageMountPoint(const ::apex::proto::ApexManifest& manifest);
 std::string GetPackageTempMountPoint(
     const ::apex::proto::ApexManifest& manifest);
diff --git a/apexd/apexd_session.cpp b/apexd/apexd_session.cpp
index 69ac1d93..db772ee2 100644
--- a/apexd/apexd_session.cpp
+++ b/apexd/apexd_session.cpp
@@ -129,6 +129,11 @@ ApexSession::GetApexNames() const {
   return state_.apex_names();
 }
 
+const google::protobuf::RepeatedPtrField<std::string>
+ApexSession::GetApexFileHashes() const {
+  return state_.apex_file_hashes();
+}
+
 const std::string& ApexSession::GetSessionDir() const { return session_dir_; }
 
 void ApexSession::SetBuildFingerprint(const std::string& fingerprint) {
@@ -160,6 +165,10 @@ void ApexSession::AddApexName(const std::string& apex_name) {
   state_.add_apex_names(apex_name);
 }
 
+void ApexSession::SetApexFileHashes(const std::vector<std::string>& hashes) {
+  *(state_.mutable_apex_file_hashes()) = {hashes.begin(), hashes.end()};
+}
+
 Result<void> ApexSession::UpdateStateAndCommit(
     const SessionState::State& session_state) {
   state_.set_state(session_state);
diff --git a/apexd/apexd_session.h b/apexd/apexd_session.h
index d95ab7eb..97411a84 100644
--- a/apexd/apexd_session.h
+++ b/apexd/apexd_session.h
@@ -57,6 +57,8 @@ class ApexSession {
   bool IsRollback() const;
   int GetRollbackId() const;
   const google::protobuf::RepeatedPtrField<std::string> GetApexNames() const;
+  const google::protobuf::RepeatedPtrField<std::string> GetApexFileHashes()
+      const;
   const std::string& GetSessionDir() const;
 
   void SetChildSessionIds(const std::vector<int>& child_session_ids);
@@ -67,6 +69,7 @@ class ApexSession {
   void SetCrashingNativeProcess(const std::string& crashing_process);
   void SetErrorMessage(const std::string& error_message);
   void AddApexName(const std::string& apex_name);
+  void SetApexFileHashes(const std::vector<std::string>& hashes);
 
   android::base::Result<void> UpdateStateAndCommit(
       const ::apex::proto::SessionState::State& state);
diff --git a/apexd/apexd_test.cpp b/apexd/apexd_test.cpp
index 0c4919f0..a0c95a4b 100644
--- a/apexd/apexd_test.cpp
+++ b/apexd/apexd_test.cpp
@@ -39,12 +39,14 @@
 #include <unordered_set>
 #include <vector>
 
+#include "apex_constants.h"
 #include "apex_database.h"
 #include "apex_file.h"
 #include "apex_file_repository.h"
 #include "apex_manifest.pb.h"
 #include "apexd_checkpoint.h"
 #include "apexd_loop.h"
+#include "apexd_metrics.h"
 #include "apexd_session.h"
 #include "apexd_test_utils.h"
 #include "apexd_utils.h"
@@ -54,6 +56,7 @@
 namespace android {
 namespace apex {
 
+using namespace std::literals;
 namespace fs = std::filesystem;
 
 using MountedApexData = MountedApexDatabase::MountedApexData;
@@ -151,6 +154,9 @@ class ApexdUnitTest : public ::testing::Test {
  public:
   ApexdUnitTest() {
     built_in_dir_ = StringPrintf("%s/pre-installed-apex", td_.path);
+    partition_ = ApexPartition::System;
+    partition_string_ = "SYSTEM";
+    block_partition_string_ = "SYSTEM";
     data_dir_ = StringPrintf("%s/data-apex", td_.path);
     decompression_dir_ = StringPrintf("%s/decompressed-apex", td_.path);
     ota_reserved_dir_ = StringPrintf("%s/ota-reserved", td_.path);
@@ -161,7 +167,7 @@ class ApexdUnitTest : public ::testing::Test {
     session_manager_ = ApexSessionManager::Create(sessions_metadata_dir_);
 
     config_ = {kTestApexdStatusSysprop,
-               {built_in_dir_},
+               {{partition_, built_in_dir_}},
                data_dir_.c_str(),
                decompression_dir_.c_str(),
                ota_reserved_dir_.c_str(),
@@ -171,6 +177,11 @@ class ApexdUnitTest : public ::testing::Test {
   }
 
   const std::string& GetBuiltInDir() { return built_in_dir_; }
+  ApexPartition GetPartition() { return partition_; }
+  const std::string& GetPartitionString() { return partition_string_; }
+  const std::string& GetBlockPartitionString() {
+    return block_partition_string_;
+  }
   const std::string& GetDataDir() { return data_dir_; }
   const std::string& GetDecompressionDir() { return decompression_dir_; }
   const std::string& GetOtaReservedDir() { return ota_reserved_dir_; }
@@ -277,6 +288,9 @@ class ApexdUnitTest : public ::testing::Test {
  protected:
   TemporaryDir td_;
   std::string built_in_dir_;
+  ApexPartition partition_;
+  std::string partition_string_;
+  std::string block_partition_string_;
   std::string data_dir_;
   std::string decompression_dir_;
   std::string ota_reserved_dir_;
@@ -288,15 +302,15 @@ class ApexdUnitTest : public ::testing::Test {
   ApexdConfig config_;
 };
 
-// Apex that does not have pre-installed version, does not get selected
-TEST_F(ApexdUnitTest, ApexMustHavePreInstalledVersionForSelection) {
+TEST_F(ApexdUnitTest, SelectApexForActivationSuccess) {
   AddPreInstalledApex("apex.apexd_test.apex");
   AddPreInstalledApex("com.android.apex.cts.shim.apex");
   auto shared_lib_1 = ApexFile::Open(AddPreInstalledApex(
       "com.android.apex.test.sharedlibs_generated.v1.libvX.apex"));
   auto& instance = ApexFileRepository::GetInstance();
   // Pre-installed data needs to be present so that we can add data apex
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   auto apexd_test_file = ApexFile::Open(AddDataApex("apex.apexd_test.apex"));
   auto shim_v1 = ApexFile::Open(AddDataApex("com.android.apex.cts.shim.apex"));
@@ -307,11 +321,11 @@ TEST_F(ApexdUnitTest, ApexMustHavePreInstalledVersionForSelection) {
   ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
 
   const auto all_apex = instance.AllApexFilesByName();
-  // Pass a blank instance so that the data apex files are not considered
+  // Pass a blank instance so that no apex file is considered
   // pre-installed
   const ApexFileRepository instance_blank;
   auto result = SelectApexForActivation(all_apex, instance_blank);
-  ASSERT_EQ(result.size(), 0u);
+  ASSERT_EQ(result.size(), 6u);
   // When passed proper instance they should get selected
   result = SelectApexForActivation(all_apex, instance);
   ASSERT_EQ(result.size(), 3u);
@@ -326,7 +340,8 @@ TEST_F(ApexdUnitTest, HigherVersionOfApexIsSelected) {
       ApexFile::Open(AddPreInstalledApex("apex.apexd_test_v2.apex"));
   AddPreInstalledApex("com.android.apex.cts.shim.apex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   TemporaryDir data_dir;
   AddDataApex("apex.apexd_test.apex");
@@ -349,7 +364,8 @@ TEST_F(ApexdUnitTest, DataApexGetsPriorityForSameVersions) {
   AddPreInstalledApex("com.android.apex.cts.shim.apex");
   // Initialize pre-installed APEX information
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   auto apexd_test_file = ApexFile::Open(AddDataApex("apex.apexd_test.apex"));
   auto shim_v1 = ApexFile::Open(AddDataApex("com.android.apex.cts.shim.apex"));
@@ -371,7 +387,8 @@ TEST_F(ApexdUnitTest, SharedLibsCanHaveBothVersionSelected) {
       "com.android.apex.test.sharedlibs_generated.v1.libvX.apex"));
   // Initialize pre-installed APEX information
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   auto shared_lib_v2 = ApexFile::Open(
       AddDataApex("com.android.apex.test.sharedlibs_generated.v2.libvY.apex"));
@@ -393,7 +410,8 @@ TEST_F(ApexdUnitTest, SharedLibsDataVersionDeletedIfLower) {
       "com.android.apex.test.sharedlibs_generated.v2.libvY.apex"));
   // Initialize pre-installed APEX information
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   auto shared_lib_v1 = ApexFile::Open(
       AddDataApex("com.android.apex.test.sharedlibs_generated.v1.libvX.apex"));
@@ -577,7 +595,8 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexReuseOtaApex) {
 
 TEST_F(ApexdUnitTest, ShouldAllocateSpaceForDecompressionNewApex) {
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   // A brand new compressed APEX is being introduced: selected
   bool result =
@@ -590,7 +609,8 @@ TEST_F(ApexdUnitTest,
   // Prepare fake pre-installed apex
   AddPreInstalledApex("apex.apexd_test.apex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   // An existing pre-installed APEX is now compressed in the OTA: selected
   {
@@ -621,7 +641,8 @@ TEST_F(ApexdUnitTest, ShouldAllocateSpaceForDecompressionVersionCompare) {
   // Prepare fake pre-installed apex
   PrepareCompressedApex("com.android.apex.compressed.v1.capex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
   ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
 
   {
@@ -654,7 +675,9 @@ TEST_F(ApexdUnitTest, ShouldAllocateSpaceForDecompressionVersionCompare) {
 
   // Replace decompressed data apex with a higher version
   ApexFileRepository instance_new(GetDecompressionDir());
-  ASSERT_THAT(instance_new.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(
+      instance_new.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+      Ok());
   TemporaryDir data_dir_new;
   fs::copy(GetTestFile("com.android.apex.compressed.v2_original.apex"),
            data_dir_new.path);
@@ -691,7 +714,8 @@ TEST_F(ApexdUnitTest, CalculateSizeForCompressedApexEmptyList) {
 TEST_F(ApexdUnitTest, CalculateSizeForCompressedApex) {
   ApexFileRepository instance;
   AddPreInstalledApex("com.android.apex.compressed.v1.capex");
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   std::vector<std::tuple<std::string, int64_t, int64_t>> input = {
       std::make_tuple("new_apex", 1, 1),
@@ -903,6 +927,7 @@ class ApexdMountTest : public ApexdUnitTest {
         LOG(ERROR) << "Failed to unmount " << apex << " : " << status.error();
       }
     }
+    InitMetrics({});  // reset
   }
 
   void SetBlockApexEnabled(bool enabled) {
@@ -965,7 +990,8 @@ class ApexdMountTest : public ApexdUnitTest {
 // TODO(b/187864524): cover other negative scenarios.
 TEST_F(ApexdMountTest, InstallPackageRejectsApexWithoutRebootlessSupport) {
   std::string file_path = AddPreInstalledApex("apex.apexd_test.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -987,7 +1013,8 @@ TEST_F(ApexdMountTest, InstallPackageRejectsNoPreInstalledApex) {
 
 TEST_F(ApexdMountTest, InstallPackageRejectsNoActiveApex) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_v2.apex"),
                             /* force= */ false);
@@ -998,7 +1025,8 @@ TEST_F(ApexdMountTest, InstallPackageRejectsNoActiveApex) {
 
 TEST_F(ApexdMountTest, InstallPackageRejectsManifestMismatch) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1014,7 +1042,8 @@ TEST_F(ApexdMountTest, InstallPackageRejectsManifestMismatch) {
 
 TEST_F(ApexdMountTest, InstallPackageRejectsCorrupted) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1027,7 +1056,8 @@ TEST_F(ApexdMountTest, InstallPackageRejectsCorrupted) {
 
 TEST_F(ApexdMountTest, InstallPackageRejectsProvidesSharedLibs) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1040,7 +1070,8 @@ TEST_F(ApexdMountTest, InstallPackageRejectsProvidesSharedLibs) {
 
 TEST_F(ApexdMountTest, InstallPackageRejectsProvidesNativeLibs) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1053,7 +1084,8 @@ TEST_F(ApexdMountTest, InstallPackageRejectsProvidesNativeLibs) {
 
 TEST_F(ApexdMountTest, InstallPackageRejectsRequiresSharedApexLibs) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1067,7 +1099,8 @@ TEST_F(ApexdMountTest, InstallPackageRejectsRequiresSharedApexLibs) {
 
 TEST_F(ApexdMountTest, InstallPackageRejectsJniLibs) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1079,7 +1112,8 @@ TEST_F(ApexdMountTest, InstallPackageRejectsJniLibs) {
 
 TEST_F(ApexdMountTest, InstallPackageAcceptsAddRequiredNativeLib) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1093,7 +1127,8 @@ TEST_F(ApexdMountTest, InstallPackageAcceptsAddRequiredNativeLib) {
 
 TEST_F(ApexdMountTest, InstallPackageAcceptsRemoveRequiredNativeLib) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1107,7 +1142,8 @@ TEST_F(ApexdMountTest, InstallPackageAcceptsRemoveRequiredNativeLib) {
 
 TEST_F(ApexdMountTest, InstallPackageRejectsAppInApex) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1119,7 +1155,8 @@ TEST_F(ApexdMountTest, InstallPackageRejectsAppInApex) {
 
 TEST_F(ApexdMountTest, InstallPackageRejectsPrivAppInApex) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1133,7 +1170,8 @@ TEST_F(ApexdMountTest, InstallPackageRejectsPrivAppInApex) {
 
 TEST_F(ApexdMountTest, InstallPackagePreInstallVersionActive) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1181,7 +1219,8 @@ TEST_F(ApexdMountTest, InstallPackagePreInstallVersionActive) {
 
 TEST_F(ApexdMountTest, InstallPackagePreInstallVersionActiveSamegrade) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1223,7 +1262,8 @@ TEST_F(ApexdMountTest, InstallPackagePreInstallVersionActiveSamegrade) {
 
 TEST_F(ApexdMountTest, InstallPackageUnloadOldApex) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   bool unloaded = false;
   bool loaded = false;
@@ -1248,7 +1288,8 @@ TEST_F(ApexdMountTest, InstallPackageUnloadOldApex) {
 
 TEST_F(ApexdMountTest, InstallPackageWithService) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_service_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1264,7 +1305,8 @@ TEST_F(ApexdMountTest, InstallPackageWithService) {
 
 TEST_F(ApexdMountTest, InstallPackageDataVersionActive) {
   AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   std::string file_path = AddDataApex("test.rebootless_apex_v1.apex");
   ASSERT_THAT(ActivatePackage(file_path), Ok());
@@ -1313,7 +1355,8 @@ TEST_F(ApexdMountTest, InstallPackageDataVersionActive) {
 
 TEST_F(ApexdMountTest, InstallPackageResolvesPathCollision) {
   AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   std::string file_path = AddDataApex("test.rebootless_apex_v1.apex",
                                       "test.apex.rebootless@1_1.apex");
@@ -1367,7 +1410,8 @@ TEST_F(ApexdMountTest, InstallPackageResolvesPathCollision) {
 
 TEST_F(ApexdMountTest, InstallPackageDataVersionActiveSamegrade) {
   AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   std::string file_path = AddDataApex("test.rebootless_apex_v2.apex");
   ASSERT_THAT(ActivatePackage(file_path), Ok());
@@ -1416,7 +1460,8 @@ TEST_F(ApexdMountTest, InstallPackageDataVersionActiveSamegrade) {
 
 TEST_F(ApexdMountTest, InstallPackageUnmountFailsPreInstalledApexActive) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1460,7 +1505,8 @@ TEST_F(ApexdMountTest, InstallPackageUnmountFailsPreInstalledApexActive) {
 
 TEST_F(ApexdMountTest, InstallPackageUnmountFailedUpdatedApexActive) {
   AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   std::string file_path = AddDataApex("test.rebootless_apex_v1.apex");
 
@@ -1507,7 +1553,8 @@ TEST_F(ApexdMountTest, InstallPackageUnmountFailedUpdatedApexActive) {
 TEST_F(ApexdMountTest, InstallPackageUpdatesApexInfoList) {
   auto apex_1 = AddPreInstalledApex("test.rebootless_apex_v1.apex");
   auto apex_2 = AddPreInstalledApex("apex.apexd_test.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   UnmountOnTearDown(apex_1);
   UnmountOnTearDown(apex_2);
@@ -1534,20 +1581,23 @@ TEST_F(ApexdMountTest, InstallPackageUpdatesApexInfoList) {
       /* preinstalledModulePath= */ apex_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package",
       /* modulePath= */ apex_2, /* preinstalledModulePath= */ apex_2,
       /* versionCode= */ 1, /* versionName= */ "1", /* isFactory= */ true,
       /* isActive= */ true, GetMTime(apex_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_3 = com::android::apex::ApexInfo(
       /* moduleName= */ "test.apex.rebootless",
       /* modulePath= */ ret->GetPath(),
       /* preinstalledModulePath= */ apex_1,
       /* versionCode= */ 2, /* versionName= */ "2",
       /* isFactory= */ false, /* isActive= */ true, GetMTime(ret->GetPath()),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
                                    ApexInfoXmlEq(apex_info_xml_2),
@@ -1562,7 +1612,8 @@ TEST_F(ApexdMountTest, ActivatePackageBannedName) {
 
 TEST_F(ApexdMountTest, ActivatePackageNoCode) {
   std::string file_path = AddPreInstalledApex("apex.apexd_test_nocode.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1590,7 +1641,8 @@ TEST_F(ApexdMountTest, ActivatePackageNoCode) {
 TEST_F(ApexdMountTest, ActivatePackageManifestMissmatch) {
   std::string file_path =
       AddPreInstalledApex("apex.apexd_test_manifest_mismatch.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   auto status = ActivatePackage(file_path);
   ASSERT_THAT(
@@ -1601,7 +1653,8 @@ TEST_F(ApexdMountTest, ActivatePackageManifestMissmatch) {
 
 TEST_F(ApexdMountTest, ActivatePackage) {
   std::string file_path = AddPreInstalledApex("apex.apexd_test.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1624,7 +1677,8 @@ TEST_F(ApexdMountTest, ActivatePackage) {
 
 TEST_F(ApexdMountTest, ActivatePackageShowsUpInMountedApexDatabase) {
   std::string file_path = AddPreInstalledApex("apex.apexd_test.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
   UnmountOnTearDown(file_path);
@@ -1654,7 +1708,8 @@ TEST_F(ApexdMountTest, ActivatePackageShowsUpInMountedApexDatabase) {
 
 TEST_F(ApexdMountTest, DeactivePackageFreesLoopDevices) {
   AddPreInstalledApex("apex.apexd_test.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   std::string file_path = AddDataApex("apex.apexd_test_v2.apex");
   ASSERT_THAT(ActivatePackage(file_path), Ok());
@@ -1680,7 +1735,8 @@ TEST_F(ApexdMountTest, DeactivePackageFreesLoopDevices) {
 
 TEST_F(ApexdMountTest, DeactivePackageTearsDownVerityDevice) {
   AddPreInstalledApex("apex.apexd_test.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   std::string file_path = AddDataApex("apex.apexd_test_v2.apex");
   ASSERT_THAT(ActivatePackage(file_path), Ok());
@@ -1706,7 +1762,8 @@ TEST_F(ApexdMountTest, ActivateDeactivateSharedLibsApex) {
 
   std::string file_path = AddPreInstalledApex(
       "com.android.apex.test.sharedlibs_generated.v1.libvX.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   UnmountOnTearDown(file_path);
   ASSERT_THAT(ActivatePackage(file_path), Ok());
@@ -1753,7 +1810,8 @@ TEST_F(ApexdMountTest, RemoveInactiveDataApex) {
   auto active_data_apex = AddDataApex("apex.apexd_test_v2.apex");
 
   // Activate some of the apex
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
   UnmountOnTearDown(active_decompressed_apex);
   UnmountOnTearDown(active_data_apex);
   ASSERT_THAT(ActivatePackage(active_decompressed_apex), Ok());
@@ -1795,13 +1853,15 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapOnlyPreInstalledApexes) {
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package_2",
       /* modulePath= */ apex_path_2, /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 1, /* versionName= */ "1", /* isFactory= */ true,
       /* isActive= */ true, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
                                    ApexInfoXmlEq(apex_info_xml_2)));
@@ -1842,20 +1902,23 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHasHigherVersion) {
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package_2",
       /* modulePath= */ apex_path_2, /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 1, /* versionName= */ "1", /* isFactory= */ true,
       /* isActive= */ true, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_3 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package",
       /* modulePath= */ apex_path_3,
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 2, /* versionName= */ "2",
       /* isFactory= */ false, /* isActive= */ true, GetMTime(apex_path_3),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
                                    ApexInfoXmlEq(apex_info_xml_2),
@@ -1890,20 +1953,23 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHasSameVersion) {
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package_2",
       /* modulePath= */ apex_path_2, /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 1, /* versionName= */ "1", /* isFactory= */ true,
       /* isActive= */ true, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_3 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package",
       /* modulePath= */ apex_path_3,
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ false, /* isActive= */ true, GetMTime(apex_path_3),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
                                    ApexInfoXmlEq(apex_info_xml_2),
@@ -1938,13 +2004,15 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSystemHasHigherVersion) {
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 2, /* versionName= */ "2",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package_2",
       /* modulePath= */ apex_path_2, /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 1, /* versionName= */ "1", /* isFactory= */ true,
       /* isActive= */ true, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
 
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
@@ -1979,13 +2047,15 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHasSameVersionButDifferentKey) {
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package_2",
       /* modulePath= */ apex_path_2, /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 1, /* versionName= */ "1", /* isFactory= */ true,
       /* isActive= */ true, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
 
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
@@ -2028,13 +2098,15 @@ TEST_F(ApexdMountTest,
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package_2",
       /* modulePath= */ apex_path_2, /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 1, /* versionName= */ "1", /* isFactory= */ true,
       /* isActive= */ true, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
 
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
@@ -2064,7 +2136,8 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataApexWithoutPreInstalledApex) {
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
 
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1)));
@@ -2097,21 +2170,24 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapPreInstalledSharedLibsApex) {
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test.sharedlibs",
       /* modulePath= */ apex_path_2,
       /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_3 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package",
       /* modulePath= */ apex_path_3,
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 2, /* versionName= */ "2",
       /* isFactory= */ false, /* isActive= */ true, GetMTime(apex_path_3),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
 
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
@@ -2181,28 +2257,32 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSharedLibsApexBothVersions) {
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test.sharedlibs",
       /* modulePath= */ apex_path_2,
       /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_3 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package",
       /* modulePath= */ apex_path_3,
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 2, /* versionName= */ "2",
       /* isFactory= */ false, /* isActive= */ true, GetMTime(apex_path_3),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_4 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test.sharedlibs",
       /* modulePath= */ apex_path_4,
       /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 2, /* versionName= */ "2",
       /* isFactory= */ false, /* isActive= */ true, GetMTime(apex_path_4),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
 
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
@@ -2278,7 +2358,8 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapOnlyCompressedApexes) {
       /* preinstalledModulePath= */ apex_path,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(decompressed_apex),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_decompressed)));
   auto& db = GetApexDatabaseForTesting();
@@ -2358,7 +2439,8 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapUpgradeCapex) {
       /* versionCode= */ 2, /* versionName= */ "2",
       /* isFactory= */ true, /* isActive= */ true,
       GetMTime(decompressed_active_apex),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_decompressed)));
   auto& db = GetApexDatabaseForTesting();
@@ -2407,7 +2489,8 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapex) {
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true,
       GetMTime(decompressed_active_apex),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_decompressed)));
   auto& db = GetApexDatabaseForTesting();
@@ -2456,7 +2539,8 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapexDifferentDigest) {
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true,
       GetMTime(decompressed_ota_apex),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_decompressed)));
   auto& db = GetApexDatabaseForTesting();
@@ -2521,7 +2605,8 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapexDifferentKey) {
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true,
       GetMTime(decompressed_active_apex),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_decompressed)));
   auto& db = GetApexDatabaseForTesting();
@@ -2565,7 +2650,8 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapCapexToApex) {
       /* preinstalledModulePath= */ apex_path,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(apex_path),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_uncompressed)));
 }
@@ -2606,7 +2692,8 @@ TEST_F(ApexdMountTest,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true,
       GetMTime(decompressed_active_apex),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_decompressed)));
 }
@@ -2638,14 +2725,16 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHigherThanCapex) {
       /* preinstalledModulePath= */ system_apex_path,
       /* versionCode= */ 2, /* versionName= */ "2",
       /* isFactory= */ false, /* isActive= */ true, GetMTime(data_apex_path),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_system = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.compressed",
       /* modulePath= */ system_apex_path,
       /* preinstalledModulePath= */ system_apex_path,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ false, GetMTime(system_apex_path),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_data),
                                    ApexInfoXmlEq(apex_info_xml_system)));
@@ -2690,7 +2779,8 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataLowerThanCapex) {
       /* versionCode= */ 2, /* versionName= */ "2",
       /* isFactory= */ true, /* isActive= */ true,
       GetMTime(decompressed_active_apex),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml)));
   auto& db = GetApexDatabaseForTesting();
@@ -2731,14 +2821,16 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataSameAsCapex) {
       /* preinstalledModulePath= */ system_apex_path,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ false, /* isActive= */ true, GetMTime(data_apex_path),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_system = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.compressed",
       /* modulePath= */ system_apex_path,
       /* preinstalledModulePath= */ system_apex_path,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ false, GetMTime(system_apex_path),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_data),
                                    ApexInfoXmlEq(apex_info_xml_system)));
@@ -2783,7 +2875,8 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHasDifferentKeyThanCapex) {
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true,
       GetMTime(decompressed_active_apex),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_decompressed)));
   auto& db = GetApexDatabaseForTesting();
@@ -2827,13 +2920,15 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSystemDataStagedInSameVersion) {
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package",
       /* modulePath= */ apex_path_3, /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1", /* isFactory= */ false,
       /* isActive= */ true, GetMTime(apex_path_3),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
 
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
@@ -2867,7 +2962,8 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSystemNewerThanDataStaged) {
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 2, /* versionName= */ "2",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
 
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml)));
@@ -2960,13 +3056,15 @@ TEST_F(ApexdMountTest,
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 137, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package_2",
       /* modulePath= */ apex_path_2, /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 1, /* versionName= */ "1", /* isFactory= */ true,
       /* isActive= */ true, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
 
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
@@ -3002,13 +3100,15 @@ TEST_F(ApexdMountTest,
       /* preinstalledModulePath= */ apex_path_1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
   auto apex_info_xml_2 = com::android::apex::ApexInfo(
       /* moduleName= */ "com.android.apex.test_package_2",
       /* modulePath= */ apex_path_2, /* preinstalledModulePath= */ apex_path_2,
       /* versionCode= */ 1, /* versionName= */ "1", /* isFactory= */ true,
       /* isActive= */ true, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetPartitionString());
 
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
@@ -3024,9 +3124,9 @@ TEST_F(ApexdMountTest, OnStartOnlyPreInstalledApexes) {
   std::string apex_path_2 =
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3052,9 +3152,9 @@ TEST_F(ApexdMountTest, OnStartDataHasHigherVersion) {
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
   std::string apex_path_3 = AddDataApex("apex.apexd_test_v2.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3078,9 +3178,9 @@ TEST_F(ApexdMountTest, OnStartDataHasWrongSHA) {
   std::string apex_path = AddPreInstalledApex("com.android.apex.cts.shim.apex");
   AddDataApex("com.android.apex.cts.shim.v2_wrong_sha.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   UnmountOnTearDown(apex_path);
   OnStart();
@@ -3102,9 +3202,9 @@ TEST_F(ApexdMountTest, OnStartDataHasSameVersion) {
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
   std::string apex_path_3 = AddDataApex("apex.apexd_test.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3138,9 +3238,9 @@ TEST_F(ApexdMountTest, OnStartSystemHasHigherVersion) {
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
   AddDataApex("apex.apexd_test.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3174,9 +3274,9 @@ TEST_F(ApexdMountTest, OnStartFailsToActivateApexOnDataFallsBackToBuiltIn) {
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
   AddDataApex("apex.apexd_test_manifest_mismatch.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3217,9 +3317,9 @@ TEST_F(ApexdMountTest, OnStartApexOnDataHasWrongKeyFallsBackToBuiltIn) {
     ASSERT_EQ(static_cast<uint64_t>(apex->GetManifest().version()), 2ULL);
   }
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3251,9 +3351,9 @@ TEST_F(ApexdMountTest, OnStartOnlyPreInstalledCapexes) {
   std::string apex_path_1 =
       AddPreInstalledApex("com.android.apex.compressed.v1.capex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3288,9 +3388,9 @@ TEST_F(ApexdMountTest, OnStartDataHasHigherVersionThanCapex) {
   std::string apex_path_2 =
       AddDataApex("com.android.apex.compressed.v2_original.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3320,9 +3420,9 @@ TEST_F(ApexdMountTest, OnStartDataHasSameVersionAsCapex) {
   AddPreInstalledApex("com.android.apex.compressed.v1.capex");
   std::string apex_path_2 = AddDataApex("com.android.apex.compressed.v1.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3355,9 +3455,9 @@ TEST_F(ApexdMountTest, OnStartSystemHasHigherVersionCapexThanData) {
       AddPreInstalledApex("com.android.apex.compressed.v2.capex");
   AddDataApex("com.android.apex.compressed.v1.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3392,9 +3492,9 @@ TEST_F(ApexdMountTest, OnStartFailsToActivateApexOnDataFallsBackToCapex) {
   AddPreInstalledApex("com.android.apex.compressed.v1.capex");
   AddDataApex("com.android.apex.compressed.v2_manifest_mismatch.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3431,9 +3531,9 @@ TEST_F(ApexdMountTest, OnStartFallbackToAlreadyDecompressedCapex) {
   PrepareCompressedApex("com.android.apex.compressed.v1.capex");
   AddDataApex("com.android.apex.compressed.v2_manifest_mismatch.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3472,9 +3572,9 @@ TEST_F(ApexdMountTest, OnStartFallbackToCapexSameVersion) {
   fs::copy(GetTestFile("com.android.apex.compressed.v2_manifest_mismatch.apex"),
            GetDataDir() + "/com.android.apex.compressed@2.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3510,9 +3610,9 @@ TEST_F(ApexdMountTest, OnStartCapexToApex) {
                         previous_built_in_dir.path);
   auto apex_path = AddPreInstalledApex("com.android.apex.compressed.v1.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3550,9 +3650,9 @@ TEST_F(ApexdMountTest, OnStartOrphanedDecompressedApexInActiveDirectory) {
            decompressed_apex_in_active_dir);
   auto apex_path = AddPreInstalledApex("com.android.apex.compressed.v1.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3580,9 +3680,9 @@ TEST_F(ApexdMountTest, OnStartDecompressedApexVersionDifferentThanCapex) {
                         previous_built_in_dir.path);
   auto apex_path = AddPreInstalledApex("com.android.apex.compressed.v1.capex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3623,9 +3723,9 @@ TEST_F(ApexdMountTest, OnStartOtaApexKeptUntilSlotSwitch) {
   fs::copy(GetTestFile("com.android.apex.compressed.v2_original.apex"),
            ota_apex_path.c_str());
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   // When we call OnStart for the first time, it will decompress v1 capex and
   // activate it, while after second call it will decompress v2 capex and
@@ -3651,9 +3751,9 @@ TEST_F(ApexdMountTest, OnStartOtaApexKeptUntilSlotSwitch) {
   RemoveFileIfExists(old_capex);
   AddPreInstalledApex("com.android.apex.compressed.v2.capex");
   ApexFileRepository::GetInstance().Reset(GetDecompressionDir());
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
   OnStart();
   path_exists = PathExists(ota_apex_path);
   ASSERT_FALSE(*path_exists);
@@ -3683,9 +3783,9 @@ TEST_F(ApexdMountTest,
       pre_installed_apex->GetManifest().capexmetadata().originalapexdigest(),
       different_digest);
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3714,9 +3814,9 @@ TEST_F(ApexdMountTest, OnStartDecompressedApexVersionSameAsCapexDifferentKey) {
   // Place a same version capex in current built_in_dir, which has different key
   auto apex_path = AddPreInstalledApex("com.android.apex.compressed.v1.capex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -3757,7 +3857,8 @@ TEST_F(ApexdMountTest, PopulateFromMountsChecksPathPrefix) {
       StringPrintf("%s/apex.apexd_test_different_app.apex", td.path);
 
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   ASSERT_THAT(ActivatePackage(apex_path), Ok());
   ASSERT_THAT(ActivatePackage(decompressed_apex), Ok());
@@ -3831,7 +3932,8 @@ TEST_F(ApexdMountTest, UnmountAll) {
                    GetDecompressionDir().c_str());
 
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   ASSERT_THAT(ActivatePackage(apex_path_2), Ok());
   ASSERT_THAT(ActivatePackage(apex_path_3), Ok());
@@ -3877,7 +3979,8 @@ TEST_F(ApexdMountTest, UnmountAllSharedLibsApex) {
       AddDataApex("com.android.apex.test.sharedlibs_generated.v2.libvY.apex");
 
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   ASSERT_THAT(ActivatePackage(apex_path_1), Ok());
   ASSERT_THAT(ActivatePackage(apex_path_2), Ok());
@@ -3906,7 +4009,8 @@ TEST_F(ApexdMountTest, UnmountAllDeferred) {
   std::string apex_path_3 = AddDataApex("apex.apexd_test_v2.apex");
 
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   ASSERT_THAT(ActivatePackage(apex_path_2), Ok());
   ASSERT_THAT(ActivatePackage(apex_path_3), Ok());
@@ -3971,7 +4075,8 @@ TEST_F(ApexdMountTest, UnmountAllStaged) {
       GetStagedDir(apex_session->GetId()) + "/" + "apex.apexd_test_v2.apex";
 
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   ASSERT_THAT(ActivatePackage(apex_path_2), Ok());
   ASSERT_THAT(ActivatePackage(apex_path_3), Ok());
@@ -4060,7 +4165,8 @@ TEST_F(ApexdMountTest, OnStartInVmModeActivatesBlockDevicesAsWell) {
       /* preinstalledModulePath= */ path1,
       /* versionCode= */ 1, /* versionName= */ "1",
       /* isFactory= */ true, /* isActive= */ true, GetMTime(path1),
-      /* provideSharedApexLibs= */ false);
+      /* provideSharedApexLibs= */ false,
+      /* partition= */ GetBlockPartitionString());
   ASSERT_THAT(info_list->getApexInfo(),
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1)));
 }
@@ -4183,201 +4289,6 @@ TEST_F(ApexdMountTest, OnStartInVmModeFailsWithWrongRootDigest) {
   ASSERT_EQ(1, OnStartInVmMode());
 }
 
-// Test that OnStart works with only block devices
-TEST_F(ApexdMountTest, OnStartOnlyBlockDevices) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
-  // Set system property to enable block apexes
-  SetBlockApexEnabled(true);
-
-  auto path1 = AddBlockApex("apex.apexd_test.apex");
-
-  ASSERT_THAT(android::apex::AddBlockApex(ApexFileRepository::GetInstance()),
-              Ok());
-
-  OnStart();
-  UnmountOnTearDown(path1);
-
-  ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
-  auto apex_mounts = GetApexMounts();
-
-  ASSERT_THAT(apex_mounts,
-              UnorderedElementsAre("/apex/com.android.apex.test_package",
-                                   "/apex/com.android.apex.test_package@1"));
-}
-
-// Test that we can have a mix of both block and system apexes
-TEST_F(ApexdMountTest, OnStartBlockAndSystemInstalled) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
-  // Set system property to enable block apexes
-  SetBlockApexEnabled(true);
-
-  auto path1 = AddPreInstalledApex("apex.apexd_test.apex");
-  auto path2 = AddBlockApex("apex.apexd_test_different_app.apex");
-
-  auto& instance = ApexFileRepository::GetInstance();
-
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
-  ASSERT_THAT(android::apex::AddBlockApex(instance), Ok());
-
-  OnStart();
-  UnmountOnTearDown(path1);
-  UnmountOnTearDown(path2);
-
-  ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
-  auto apex_mounts = GetApexMounts();
-
-  ASSERT_THAT(apex_mounts,
-              UnorderedElementsAre("/apex/com.android.apex.test_package",
-                                   "/apex/com.android.apex.test_package@1",
-                                   "/apex/com.android.apex.test_package_2",
-                                   "/apex/com.android.apex.test_package_2@1"));
-}
-
-TEST_F(ApexdMountTest, OnStartBlockAndCompressedInstalled) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
-  // Set system property to enable block apexes
-  SetBlockApexEnabled(true);
-
-  auto path1 = AddPreInstalledApex("com.android.apex.compressed.v1.capex");
-  auto path2 = AddBlockApex("apex.apexd_test.apex");
-
-  auto& instance = ApexFileRepository::GetInstance();
-
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
-  ASSERT_THAT(android::apex::AddBlockApex(instance), Ok());
-
-  OnStart();
-  UnmountOnTearDown(path1);
-  UnmountOnTearDown(path2);
-
-  // Decompressed APEX should be mounted
-  std::string decompressed_active_apex = StringPrintf(
-      "%s/com.android.apex.compressed@1%s", GetDecompressionDir().c_str(),
-      kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
-
-  ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
-  auto apex_mounts = GetApexMounts();
-  ASSERT_THAT(apex_mounts,
-              UnorderedElementsAre("/apex/com.android.apex.compressed",
-                                   "/apex/com.android.apex.compressed@1",
-                                   "/apex/com.android.apex.test_package",
-                                   "/apex/com.android.apex.test_package@1"));
-}
-
-// Test that data version of apex is used if newer
-TEST_F(ApexdMountTest, BlockAndNewerData) {
-  // MockCheckpointInterface checkpoint_interface;
-  //// Need to call InitializeVold before calling OnStart
-  // InitializeVold(&checkpoint_interface);
-
-  // Set system property to enable block apexes
-  SetBlockApexEnabled(true);
-
-  auto& instance = ApexFileRepository::GetInstance();
-  AddBlockApex("apex.apexd_test.apex");
-  ASSERT_THAT(android::apex::AddBlockApex(instance), Ok());
-
-  TemporaryDir data_dir;
-  auto apexd_test_file_v2 =
-      ApexFile::Open(AddDataApex("apex.apexd_test_v2.apex"));
-  ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
-
-  auto all_apex = instance.AllApexFilesByName();
-  auto result = SelectApexForActivation(all_apex, instance);
-  ASSERT_EQ(result.size(), 1u);
-
-  ASSERT_THAT(result,
-              UnorderedElementsAre(ApexFileEq(ByRef(*apexd_test_file_v2))));
-}
-
-// Test that data version of apex not is used if older
-TEST_F(ApexdMountTest, BlockApexAndOlderData) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
-  // Set system property to enable block apexes
-  SetBlockApexEnabled(true);
-
-  auto& instance = ApexFileRepository::GetInstance();
-  auto apexd_test_file_v2 =
-      ApexFile::Open(AddBlockApex("apex.apexd_test_v2.apex"));
-  ASSERT_THAT(android::apex::AddBlockApex(instance), Ok());
-
-  TemporaryDir data_dir;
-  AddDataApex("apex.apexd_test.apex");
-  ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
-
-  auto all_apex = instance.AllApexFilesByName();
-  auto result = SelectApexForActivation(all_apex, instance);
-  ASSERT_EQ(result.size(), 1u);
-
-  ASSERT_THAT(result,
-              UnorderedElementsAre(ApexFileEq(ByRef(*apexd_test_file_v2))));
-}
-
-// Test that AddBlockApex does nothing if system property not set.
-TEST_F(ApexdMountTest, AddBlockApexWithoutSystemProp) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
-  auto& instance = ApexFileRepository::GetInstance();
-  AddBlockApex("apex.apexd_test.apex");
-  ASSERT_THAT(android::apex::AddBlockApex(instance), Ok());
-  ASSERT_EQ(instance.AllApexFilesByName().size(), 0ul);
-}
-
-// Test that adding block apex fails if preinstalled version exists
-TEST_F(ApexdMountTest, AddBlockApexFailsWithDuplicate) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
-  // Set system property to enable block apexes
-  SetBlockApexEnabled(true);
-
-  AddPreInstalledApex("apex.apexd_test.apex");
-  AddBlockApex("apex.apexd_test_v2.apex");
-
-  auto& instance = ApexFileRepository::GetInstance();
-
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
-  ASSERT_THAT(android::apex::AddBlockApex(instance),
-              HasError(WithMessage(HasSubstr(
-                  "duplicate of com.android.apex.test_package found"))));
-}
-
-// Test that adding block apex fails if preinstalled compressed version exists
-TEST_F(ApexdMountTest, AddBlockApexFailsWithCompressedDuplicate) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
-  // Set system property to enable block apexes
-  SetBlockApexEnabled(true);
-
-  auto path1 = AddPreInstalledApex("com.android.apex.compressed.v1.capex");
-  auto path2 = AddBlockApex("com.android.apex.compressed.v1.apex");
-
-  auto& instance = ApexFileRepository::GetInstance();
-
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
-  ASSERT_THAT(android::apex::AddBlockApex(instance),
-              HasError(WithMessage(HasSubstr(
-                  "duplicate of com.android.apex.compressed found"))));
-}
-
 class ApexActivationFailureTests : public ApexdMountTest {};
 
 TEST_F(ApexActivationFailureTests, BuildFingerprintDifferent) {
@@ -4477,7 +4388,8 @@ TEST_F(ApexActivationFailureTests, ActivatePackageImplFails) {
 
   auto shim_path = AddPreInstalledApex("com.android.apex.cts.shim.apex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({GetBuiltInDir()}));
+  ASSERT_RESULT_OK(
+      instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}));
 
   auto apex_session =
       CreateStagedSession("com.android.apex.cts.shim.v2_wrong_sha.apex", 123);
@@ -4504,7 +4416,8 @@ TEST_F(ApexActivationFailureTests,
 
   auto pre_installed_apex = AddPreInstalledApex("apex.apexd_test.apex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({GetBuiltInDir()}));
+  ASSERT_RESULT_OK(
+      instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}));
 
   auto apex_session = CreateStagedSession("apex.apexd_test.apex", 123);
   ASSERT_RESULT_OK(apex_session);
@@ -4530,7 +4443,8 @@ TEST_F(ApexActivationFailureTests, StagedSessionRevertsWhenInFsRollbackMode) {
 
   auto pre_installed_apex = AddPreInstalledApex("apex.apexd_test.apex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_RESULT_OK(instance.AddPreInstalledApex({GetBuiltInDir()}));
+  ASSERT_RESULT_OK(
+      instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}));
 
   auto apex_session = CreateStagedSession("apex.apexd_test.apex", 123);
   ASSERT_RESULT_OK(apex_session);
@@ -4563,20 +4477,35 @@ TEST_F(ApexdMountTest, OnBootstrapCreatesEmptyDmDevices) {
             dm.GetState("com.android.apex.compressed"));
 }
 
+TEST_F(ApexdMountTest, OnBootstrapLoadBootstrapApexOnly) {
+  AddPreInstalledApex("apex.apexd_test.apex");
+  AddPreInstalledApex("apex.apexd_bootstrap_test.apex");
+
+  ASSERT_EQ(0, OnBootstrap());
+
+  // Check bootstrap apex was loaded
+  auto active_bootstrap_apex =
+      GetActivePackage("com.android.apex.bootstrap_test_package");
+  ASSERT_THAT(active_bootstrap_apex, Ok());
+  // Check that non-bootstrap apex was not loaded
+  ASSERT_THAT(GetActivePackage("com.android.apex.test_package"), Not(Ok()));
+}
+
 TEST_F(ApexdUnitTest, StagePackagesFailKey) {
   auto status =
       StagePackages({GetTestFile("apex.apexd_test_no_inst_key.apex")});
 
   ASSERT_THAT(
       status,
-      HasError(WithMessage(("No preinstalled apex found for package "
+      HasError(WithMessage(("No preinstalled apex found for unverified package "
                             "com.android.apex.test_package.no_inst_key"))));
 }
 
 TEST_F(ApexdUnitTest, StagePackagesSuccess) {
   AddPreInstalledApex("apex.apexd_test.apex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   auto status = StagePackages({GetTestFile("apex.apexd_test.apex")});
   ASSERT_THAT(status, Ok());
@@ -4589,7 +4518,8 @@ TEST_F(ApexdUnitTest, StagePackagesSuccess) {
 TEST_F(ApexdUnitTest, StagePackagesClearsPreviouslyActivePackage) {
   AddPreInstalledApex("apex.apexd_test.apex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   auto current_apex = AddDataApex("apex.apexd_test.apex");
   ASSERT_EQ(0, access(current_apex.c_str(), F_OK));
@@ -4607,7 +4537,8 @@ TEST_F(ApexdUnitTest, StagePackagesClearsPreviouslyActivePackage) {
 TEST_F(ApexdUnitTest, StagePackagesClearsPreviouslyActivePackageDowngrade) {
   AddPreInstalledApex("apex.apexd_test.apex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   auto current_apex = AddDataApex("apex.apexd_test_v2.apex");
   ASSERT_EQ(0, access(current_apex.c_str(), F_OK));
@@ -4625,7 +4556,8 @@ TEST_F(ApexdUnitTest, StagePackagesClearsPreviouslyActivePackageDowngrade) {
 TEST_F(ApexdUnitTest, StagePackagesAlreadyStagedPackage) {
   AddPreInstalledApex("apex.apexd_test.apex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   auto status = StagePackages({GetTestFile("apex.apexd_test.apex")});
   ASSERT_THAT(status, Ok());
@@ -4662,7 +4594,8 @@ TEST_F(ApexdUnitTest, StagePackagesMultiplePackages) {
   AddPreInstalledApex("apex.apexd_test.apex");
   AddPreInstalledApex("apex.apexd_test_different_app.apex");
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   auto status =
       StagePackages({GetTestFile("apex.apexd_test_v2.apex"),
@@ -4710,7 +4643,8 @@ TEST_F(ApexdUnitTest, UnstagePackagesFailPreInstalledApex) {
   auto file_path2 = AddDataApex("apex.apexd_test_different_app.apex");
 
   auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({GetBuiltInDir()}), Ok());
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   ASSERT_THAT(UnstagePackages({file_path1, file_path2}),
               HasError(WithMessage("Can't uninstall pre-installed apex " +
@@ -4737,7 +4671,8 @@ TEST_F(ApexdUnitTest, RevertStoresCrashingNativeProcess) {
 
 TEST_F(ApexdUnitTest, MountAndDeriveClasspathNoJar) {
   AddPreInstalledApex("apex.apexd_test_classpath.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   // Call MountAndDeriveClassPath
   auto apex_file = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
@@ -4751,7 +4686,8 @@ TEST_F(ApexdUnitTest, MountAndDeriveClasspathNoJar) {
 
 TEST_F(ApexdUnitTest, MountAndDeriveClassPathJarsPresent) {
   AddPreInstalledApex("apex.apexd_test_classpath.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()});
+  ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}});
 
   // Call MountAndDeriveClassPath
   auto apex_file =
@@ -4808,9 +4744,9 @@ TEST_F(ApexdMountTest, OnStartNoApexUpdated) {
   std::string apex_path_4 =
       AddDecompressedApex("com.android.apex.compressed.v1.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -4837,9 +4773,9 @@ TEST_F(ApexdMountTest, OnStartDecompressingConsideredApexUpdate) {
       kDecompressedApexPackageSuffix);
   UnmountOnTearDown(decompressed_active_apex);
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   OnStart();
 
@@ -4862,9 +4798,9 @@ TEST_F(ApexdMountTest, ActivatesStagedSession) {
   auto apex_session = CreateStagedSession("apex.apexd_test_v2.apex", 37);
   apex_session->UpdateStateAndCommit(SessionState::STAGED);
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   std::string active_apex =
       GetDataDir() + "/" + "com.android.apex.test_package@2.apex";
@@ -4897,9 +4833,9 @@ TEST_F(ApexdMountTest, FailsToActivateStagedSession) {
       CreateStagedSession("apex.apexd_test_manifest_mismatch.apex", 73);
   apex_session->UpdateStateAndCommit(SessionState::STAGED);
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   UnmountOnTearDown(preinstalled_apex);
   OnStart();
@@ -4927,9 +4863,9 @@ TEST_F(ApexdMountTest, FailsToActivateApexFallbacksToSystemOne) {
   std::string preinstalled_apex = AddPreInstalledApex("apex.apexd_test.apex");
   AddDataApex("apex.apexd_test_manifest_mismatch.apex");
 
-  ASSERT_THAT(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}),
-      Ok());
+  ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
+                  {{GetPartition(), GetBuiltInDir()}}),
+              Ok());
 
   UnmountOnTearDown(preinstalled_apex);
   OnStart();
@@ -4949,8 +4885,8 @@ TEST_F(ApexdMountTest, SubmitSingleStagedSessionKeepsPreviousSessions) {
 
   std::string preinstalled_apex = AddPreInstalledApex("apex.apexd_test.apex");
 
-  ASSERT_RESULT_OK(
-      ApexFileRepository::GetInstance().AddPreInstalledApex({GetBuiltInDir()}));
+  ASSERT_RESULT_OK(ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{GetPartition(), GetBuiltInDir()}}));
 
   UnmountOnTearDown(preinstalled_apex);
 
@@ -4990,6 +4926,304 @@ TEST_F(ApexdMountTest, SubmitSingleStagedSessionKeepsPreviousSessions) {
   ASSERT_EQ(SessionState::VERIFIED, sessions[3].GetState());
 }
 
+struct SpyMetrics : Metrics {
+  std::vector<std::tuple<InstallType, bool, ApexFileInfo>> requested;
+  std::vector<std::tuple<std::string, InstallResult>> ended;
+
+  void SendInstallationRequested(InstallType install_type, bool is_rollback,
+                                 const ApexFileInfo& info) override {
+    requested.emplace_back(install_type, is_rollback, info);
+  }
+  void SendInstallationEnded(const std::string& file_hash,
+                             InstallResult result) override {
+    ended.emplace_back(file_hash, result);
+  }
+};
+
+TEST_F(ApexdMountTest, SendEventOnSubmitStagedSession) {
+  MockCheckpointInterface checkpoint_interface;
+  checkpoint_interface.SetSupportsCheckpoint(true);
+  InitializeVold(&checkpoint_interface);
+
+  InitMetrics(std::make_unique<SpyMetrics>());
+
+  std::string preinstalled_apex =
+      AddPreInstalledApex("com.android.apex.vendor.foo.apex");
+
+  // Test APEX is a "vendor" APEX. Preinstalled partition should be vendor.
+  ASSERT_RESULT_OK(ApexFileRepository::GetInstance().AddPreInstalledApex(
+      {{ApexPartition::Vendor, GetBuiltInDir()}}));
+
+  UnmountOnTearDown(preinstalled_apex);
+  OnStart();
+  // checkvintf needs apex-info-list.xml to identify vendor APEXes.
+  // OnAllPackagesActivated() generates it.
+  OnAllPackagesActivated(/*bootstrap*/ false);
+
+  PrepareStagedSession("com.android.apex.vendor.foo.with_vintf.apex", 239);
+  ASSERT_RESULT_OK(SubmitStagedSession(239, {}, false, false, -1));
+
+  auto spy = std::unique_ptr<SpyMetrics>(
+      static_cast<SpyMetrics*>(InitMetrics(nullptr).release()));
+  ASSERT_NE(nullptr, spy.get());
+
+  ASSERT_EQ(1u, spy->requested.size());
+  const auto& requested = spy->requested[0];
+  ASSERT_EQ(InstallType::Staged, std::get<0>(requested));
+  ASSERT_EQ("com.android.apex.vendor.foo"s, std::get<2>(requested).name);
+  ASSERT_THAT(std::get<2>(requested).hals, ElementsAre("android.apex.foo@1"s));
+
+  ASSERT_EQ(0u, spy->ended.size());
+}
+
+TEST(Loop, CreateWithApexFile) {
+  auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  ASSERT_THAT(apex, Ok());
+  ASSERT_TRUE(apex->GetImageOffset().has_value());
+  ASSERT_TRUE(apex->GetImageSize().has_value());
+
+  auto loop = loop::CreateAndConfigureLoopDevice(apex->GetPath(),
+                                                 apex->GetImageOffset().value(),
+                                                 apex->GetImageSize().value());
+  ASSERT_THAT(loop, Ok());
+}
+
+TEST(Loop, NoSuchFile) {
+  CaptureStderr();
+  {
+    auto loop = loop::CreateAndConfigureLoopDevice("invalid_path", 0, 0);
+    ASSERT_THAT(loop, Not(Ok()));
+  }
+  ASSERT_EQ(GetCapturedStderr(), "");
+}
+
+TEST_F(ApexdMountTest, SubmitStagedSessionSucceedVerifiedBrandNewApex) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  PrepareStagedSession("com.android.apex.brand.new.apex", 239);
+  ASSERT_RESULT_OK(SubmitStagedSession(239, {}, false, false, -1));
+
+  auto sessions = GetSessionManager()->GetSessions();
+  ASSERT_EQ(1u, sessions.size());
+  ASSERT_EQ(239, sessions[0].GetId());
+  ASSERT_EQ(SessionState::VERIFIED, sessions[0].GetState());
+  file_repository.Reset();
+}
+
+TEST_F(ApexdMountTest,
+       SubmitStagedSessionSucceedVerifiedBrandNewApexWithActiveVersion) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir, data_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+  ASSERT_RESULT_OK(file_repository.AddDataApex(data_dir.path));
+
+  PrepareStagedSession("com.android.apex.brand.new.v2.apex", 239);
+  ASSERT_RESULT_OK(SubmitStagedSession(239, {}, false, false, -1));
+
+  auto sessions = GetSessionManager()->GetSessions();
+  ASSERT_EQ(1u, sessions.size());
+  ASSERT_EQ(239, sessions[0].GetId());
+  ASSERT_EQ(SessionState::VERIFIED, sessions[0].GetState());
+  file_repository.Reset();
+}
+
+TEST_F(ApexdMountTest,
+       SubmitStagedSessionFailBrandNewApexMismatchActiveVersion) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir, data_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  fs::copy(GetTestFile(
+               "apexd_testdata/com.android.apex.brand.new.another.avbpubkey"),
+           trusted_key_dir.path);
+  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+  ASSERT_RESULT_OK(file_repository.AddDataApex(data_dir.path));
+
+  PrepareStagedSession("com.android.apex.brand.new.v2.diffkey.apex", 239);
+  auto ret = SubmitStagedSession(239, {}, false, false, -1);
+
+  ASSERT_THAT(
+      ret,
+      HasError(WithMessage(("Brand-new APEX public key doesn't match existing "
+                            "active APEX: com.android.apex.brand.new"))));
+  file_repository.Reset();
+}
+
+TEST_F(ApexdMountTest, SubmitStagedSessionFailBrandNewApexDisabled) {
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  PrepareStagedSession("com.android.apex.brand.new.apex", 239);
+  auto ret = SubmitStagedSession(239, {}, false, false, -1);
+
+  ASSERT_THAT(ret,
+              HasError(WithMessage(("No preinstalled apex found for unverified "
+                                    "package com.android.apex.brand.new"))));
+  file_repository.Reset();
+}
+
+TEST_F(ApexdUnitTest, StagePackagesSucceedVerifiedBrandNewApex) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  auto status = StagePackages({GetTestFile("com.android.apex.brand.new.apex")});
+
+  ASSERT_RESULT_OK(status);
+  auto staged_path = StringPrintf("%s/com.android.apex.brand.new@1.apex",
+                                  GetDataDir().c_str());
+  ASSERT_EQ(0, access(staged_path.c_str(), F_OK));
+  file_repository.Reset();
+}
+
+TEST_F(ApexdUnitTest, StagePackagesFailUnverifiedBrandNewApex) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir;
+  fs::copy(GetTestFile(
+               "apexd_testdata/com.android.apex.brand.new.another.avbpubkey"),
+           trusted_key_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  auto status = StagePackages({GetTestFile("com.android.apex.brand.new.apex")});
+
+  ASSERT_THAT(status,
+              HasError(WithMessage(("No preinstalled apex found for unverified "
+                                    "package com.android.apex.brand.new"))));
+
+  file_repository.Reset();
+}
+
+TEST_F(ApexdMountTest, ActivatesStagedSessionSucceedVerifiedBrandNewApex) {
+  MockCheckpointInterface checkpoint_interface;
+  // Need to call InitializeVold before calling OnStart
+  InitializeVold(&checkpoint_interface);
+
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  auto apex_session =
+      CreateStagedSession("com.android.apex.brand.new.apex", 37);
+  apex_session->UpdateStateAndCommit(SessionState::STAGED);
+
+  std::string active_apex =
+      GetDataDir() + "/" + "com.android.apex.brand.new@1.apex";
+
+  UnmountOnTearDown(active_apex);
+  OnStart();
+
+  // Quick check that session was activated
+  {
+    auto session = GetSessionManager()->GetSession(37);
+    ASSERT_THAT(session, Ok());
+    ASSERT_EQ(session->GetState(), SessionState::ACTIVATED);
+  }
+
+  auto updated_apexes = GetChangedActiveApexesForTesting();
+  ASSERT_EQ(updated_apexes.size(), 1u);
+  auto apex_file = ApexFile::Open(active_apex);
+  ASSERT_THAT(apex_file, Ok());
+  ASSERT_TRUE(IsActiveApexChanged(*apex_file));
+
+  file_repository.Reset();
+}
+
+TEST_F(ApexdMountTest, ActivatesStagedSessionFailUnverifiedBrandNewApex) {
+  MockCheckpointInterface checkpoint_interface;
+  // Need to call InitializeVold before calling OnStart
+  InitializeVold(&checkpoint_interface);
+
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir;
+  fs::copy(GetTestFile(
+               "apexd_testdata/com.android.apex.brand.new.another.avbpubkey"),
+           trusted_key_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+
+  auto apex_session =
+      CreateStagedSession("com.android.apex.brand.new.apex", 37);
+  apex_session->UpdateStateAndCommit(SessionState::STAGED);
+
+  std::string active_apex =
+      GetDataDir() + "/" + "com.android.apex.brand.new@1.apex";
+
+  UnmountOnTearDown(active_apex);
+  OnStart();
+
+  // Quick check that session was activated
+  {
+    auto session = GetSessionManager()->GetSession(37);
+    ASSERT_THAT(session, Ok());
+    ASSERT_EQ(session->GetState(), SessionState::ACTIVATION_FAILED);
+  }
+
+  auto updated_apexes = GetChangedActiveApexesForTesting();
+  ASSERT_EQ(updated_apexes.size(), 0u);
+
+  file_repository.Reset();
+}
+
+TEST_F(ApexdMountTest, NonStagedUpdateFailVerifiedBrandNewApex) {
+  ApexFileRepository::EnableBrandNewApex();
+  auto& file_repository = ApexFileRepository::GetInstance();
+  const auto partition = ApexPartition::System;
+  TemporaryDir trusted_key_dir, data_dir;
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           trusted_key_dir.path);
+  file_repository.AddBrandNewApexCredentialAndBlocklist(
+      {{partition, trusted_key_dir.path}});
+  auto file_path = AddDataApex("com.android.apex.brand.new.apex");
+  ASSERT_THAT(ActivatePackage(file_path), Ok());
+  UnmountOnTearDown(file_path);
+
+  auto ret = InstallPackage(GetTestFile("com.android.apex.brand.new.apex"),
+                            /* force= */ false);
+  ASSERT_THAT(
+      ret,
+      HasError(WithMessage(HasSubstr("No preinstalled apex found for package "
+                                     "com.android.apex.brand.new"))));
+
+  file_repository.Reset();
+}
+
 class LogTestToLogcat : public ::testing::EmptyTestEventListener {
   void OnTestStart(const ::testing::TestInfo& test_info) override {
 #ifdef __ANDROID__
diff --git a/apexd/apexd_test_utils.h b/apexd/apexd_test_utils.h
index 517080cb..693af923 100644
--- a/apexd/apexd_test_utils.h
+++ b/apexd/apexd_test_utils.h
@@ -95,7 +95,8 @@ MATCHER_P(ApexInfoEq, other, "") {
                   Eq(other.preinstalledModulePath)),
             Field("versionCode", &ApexInfo::versionCode, Eq(other.versionCode)),
             Field("isFactory", &ApexInfo::isFactory, Eq(other.isFactory)),
-            Field("isActive", &ApexInfo::isActive, Eq(other.isActive))),
+            Field("isActive", &ApexInfo::isActive, Eq(other.isActive)),
+            Field("partition", &ApexInfo::partition, Eq(other.partition))),
       arg, result_listener);
 }
 
@@ -159,6 +160,7 @@ inline void PrintTo(const ApexInfo& apex, std::ostream* os) {
   *os << "  versionCode : " << apex.versionCode << "\n";
   *os << "  isFactory : " << apex.isFactory << "\n";
   *os << "  isActive : " << apex.isActive << "\n";
+  *os << "  partition : " << toString(apex.partition) << "\n";
   *os << "}";
 }
 
@@ -305,42 +307,9 @@ inline android::base::Result<void> SetUpApexTestEnvironment() {
   return {};
 }
 
-// Simpler version of loop::CreateLoopDevice. Uses LOOP_SET_FD/LOOP_SET_STATUS64
-// instead of LOOP_CONFIGURE.
-// TODO(b/191244059) use loop::CreateLoopDevice
-inline base::Result<loop::LoopbackDeviceUniqueFd> CreateLoopDeviceForTest(
-    const std::string& filepath) {
-  base::unique_fd ctl_fd(open("/dev/loop-control", O_RDWR | O_CLOEXEC));
-  if (ctl_fd.get() == -1) {
-    return base::ErrnoError() << "Failed to open loop-control";
-  }
-  int num = ioctl(ctl_fd.get(), LOOP_CTL_GET_FREE);
-  if (num == -1) {
-    return base::ErrnoError() << "Failed LOOP_CTL_GET_FREE";
-  }
-  auto loop_device = loop::WaitForDevice(num);
-  if (!loop_device.ok()) {
-    return loop_device.error();
-  }
-  base::unique_fd target_fd(open(filepath.c_str(), O_RDONLY | O_CLOEXEC));
-  if (target_fd.get() == -1) {
-    return base::ErrnoError() << "Failed to open " << filepath;
-  }
-  struct loop_info64 li = {};
-  strlcpy((char*)li.lo_crypt_name, filepath.c_str(), LO_NAME_SIZE);
-  li.lo_flags |= LO_FLAGS_AUTOCLEAR;
-  if (ioctl(loop_device->device_fd.get(), LOOP_SET_FD, target_fd.get()) == -1) {
-    return base::ErrnoError() << "Failed to LOOP_SET_FD";
-  }
-  if (ioctl(loop_device->device_fd.get(), LOOP_SET_STATUS64, &li) == -1) {
-    return base::ErrnoError() << "Failed to LOOP_SET_STATUS64";
-  }
-  return loop_device;
-}
-
 inline base::Result<loop::LoopbackDeviceUniqueFd> MountViaLoopDevice(
     const std::string& filepath, const std::string& mount_point) {
-  auto loop_device = CreateLoopDeviceForTest(filepath);
+  auto loop_device = loop::CreateAndConfigureLoopDevice(filepath, 0, 0);
   if (loop_device.ok()) {
     close(open(mount_point.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                0644));
@@ -519,7 +488,9 @@ MATCHER_P(ApexInfoXmlEq, other, "") {
                    Eq(other.getIsFactory())),
           Property("isActive", &ApexInfo::getIsActive, Eq(other.getIsActive())),
           Property("lastUpdateMillis", &ApexInfo::getLastUpdateMillis,
-                   Eq(other.getLastUpdateMillis()))),
+                   Eq(other.getLastUpdateMillis())),
+          Property("partition", &ApexInfo::getPartition,
+                   Eq(other.getPartition()))),
       arg, result_listener);
 }
 
@@ -537,6 +508,7 @@ inline void PrintTo(const ApexInfo& apex, std::ostream* os) {
   *os << "  versionCode : " << apex.getVersionCode() << "\n";
   *os << "  isFactory : " << apex.getIsFactory() << "\n";
   *os << "  isActive : " << apex.getIsActive() << "\n";
+  *os << "  partition : " << apex.getPartition() << "\n";
   *os << "}";
 }
 
diff --git a/apexd/apexd_testdata/Android.bp b/apexd/apexd_testdata/Android.bp
index c90d943c..caf65ec5 100644
--- a/apexd/apexd_testdata/Android.bp
+++ b/apexd/apexd_testdata/Android.bp
@@ -26,6 +26,20 @@ apex_key {
     installable: false,
 }
 
+apex_key {
+    name: "com.android.apex.brand.new.key",
+    public_key: "com.android.apex.brand.new.avbpubkey",
+    private_key: "com.android.apex.brand.new.pem",
+    installable: false,
+}
+
+apex_key {
+    name: "com.android.apex.brand.new.another.key",
+    public_key: "com.android.apex.brand.new.another.avbpubkey",
+    private_key: "com.android.apex.brand.new.another.pem",
+    installable: false,
+}
+
 apex_key {
     name: "com.android.apex.compressed.key",
     public_key: "com.android.apex.compressed.avbpubkey",
@@ -43,6 +57,16 @@ apex {
     min_sdk_version: "29", // test requires hashtree to be present.
 }
 
+apex {
+    name: "apex.apexd_bootstrap_test",
+    manifest: "manifest_bootstrap.json",
+    file_contexts: ":apex.test-file_contexts",
+    prebuilts: ["sample_prebuilt_file"],
+    key: "com.android.apex.test_package.key",
+    installable: false,
+    min_sdk_version: "29", // test requires hashtree to be present.
+}
+
 apex {
     name: "com.android.apex.compressed.v1",
     manifest: "manifest_compressed.json",
@@ -65,7 +89,37 @@ apex {
     updatable: false,
 }
 
-genrule {
+apex {
+    name: "com.android.apex.brand.new",
+    manifest: "manifest_brand_new.json",
+    file_contexts: ":apex.test-file_contexts",
+    prebuilts: ["sample_prebuilt_file"],
+    key: "com.android.apex.brand.new.key",
+    installable: false,
+    min_sdk_version: "34",
+}
+
+apex {
+    name: "com.android.apex.brand.new.v2",
+    manifest: "manifest_brand_new_v2.json",
+    file_contexts: ":apex.test-file_contexts",
+    prebuilts: ["sample_prebuilt_file"],
+    key: "com.android.apex.brand.new.key",
+    installable: false,
+    min_sdk_version: "34",
+}
+
+apex {
+    name: "com.android.apex.brand.new.v2.diffkey",
+    manifest: "manifest_brand_new_v2.json",
+    file_contexts: ":apex.test-file_contexts",
+    prebuilts: ["sample_prebuilt_file"],
+    key: "com.android.apex.brand.new.another.key",
+    installable: false,
+    min_sdk_version: "34",
+}
+
+java_genrule {
     // Generates an apex which has a different public key outside the filesystem image
     name: "gen_key_mismatch_with_image_apex",
     out: ["apex.apexd_test_wrong_public_key.apex"],
@@ -83,7 +137,7 @@ genrule {
         "$(genDir)/apex.apexd_test_wrong_public_key.apex",
 }
 
-genrule {
+java_genrule {
     // Generates a compressed apex which doesn't have an original_apex file in it
     name: "gen_capex_without_apex",
     out: ["com.android.apex.compressed.v1_without_apex.capex"],
@@ -94,7 +148,7 @@ genrule {
         "-o $(genDir)/com.android.apex.compressed.v1_without_apex.capex",
 }
 
-genrule {
+java_genrule {
     // Generates a compressed apex which has different version of original_apex in it
     name: "gen_capex_with_v2_apex",
     out: ["com.android.apex.compressed.v1_with_v2_apex.capex"],
@@ -109,7 +163,7 @@ genrule {
         "-o $(genDir)/com.android.apex.compressed.v1_with_v2_apex.capex",
 }
 
-genrule {
+java_genrule {
     // Generates a compressed apex which can be opened but not decompressed
     name: "gen_capex_not_decompressible",
     out: ["com.android.apex.compressed.v1_not_decompressible.capex"],
@@ -123,7 +177,7 @@ genrule {
         "-o $(genDir)/com.android.apex.compressed.v1_not_decompressible.capex",
 }
 
-genrule {
+java_genrule {
     // Generates a capex which has same module name as com.android.apex.compressed, but
     // is contains a different public key.
     name: "gen_key_mismatch_capex",
@@ -150,7 +204,7 @@ genrule {
         "--output=$(genDir)/com.android.apex.compressed_different_key.capex",
 }
 
-genrule {
+java_genrule {
     // Generates a capex which has a different public key than original_apex
     name: "gen_key_mismatch_with_original_capex",
     out: ["com.android.apex.compressed_key_mismatch_with_original.capex"],
@@ -162,7 +216,7 @@ genrule {
         "-o $(genDir)/com.android.apex.compressed_key_mismatch_with_original.capex",
 }
 
-genrule {
+java_genrule {
     // Generates an apex which has a different manifest outside the filesystem
     // image.
     name: "gen_manifest_mismatch_compressed_apex_v2",
@@ -259,7 +313,7 @@ apex {
     min_sdk_version: "29", // add apex_manifest.json as well
 }
 
-genrule {
+java_genrule {
     name: "apex.apexd_test_v2_no_pb",
     srcs: [":apex.apexd_test_v2_legacy"],
     out: ["apex.apexd_test_v2_no_pb.apex"],
diff --git a/apexd/apexd_testdata/blocklist.json b/apexd/apexd_testdata/blocklist.json
new file mode 100644
index 00000000..4729c496
--- /dev/null
+++ b/apexd/apexd_testdata/blocklist.json
@@ -0,0 +1,8 @@
+{
+  "blocked_apex": [
+    {
+      "name": "com.android.apex.brand.new",
+      "version": 1
+    }
+  ]
+}
diff --git a/apexd/apexd_testdata/blocklist_invalid.json b/apexd/apexd_testdata/blocklist_invalid.json
new file mode 100644
index 00000000..26d3715d
--- /dev/null
+++ b/apexd/apexd_testdata/blocklist_invalid.json
@@ -0,0 +1,12 @@
+{
+  "blocked_apex": [
+    {
+      "name": "com.android.apex.brand.new",
+      "version": 1
+    },
+    {
+      "name": "com.android.apex.brand.new",
+      "version": 9
+    }
+  ]
+}
diff --git a/apexd/apexd_testdata/com.android.apex.brand.new.another.avbpubkey b/apexd/apexd_testdata/com.android.apex.brand.new.another.avbpubkey
new file mode 100644
index 00000000..e3e5f232
Binary files /dev/null and b/apexd/apexd_testdata/com.android.apex.brand.new.another.avbpubkey differ
diff --git a/apexd/apexd_testdata/com.android.apex.brand.new.another.pem b/apexd/apexd_testdata/com.android.apex.brand.new.another.pem
new file mode 100644
index 00000000..ed2202f8
--- /dev/null
+++ b/apexd/apexd_testdata/com.android.apex.brand.new.another.pem
@@ -0,0 +1,52 @@
+-----BEGIN PRIVATE KEY-----
+MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQD8hmO4TpeG/VIv
+/AC/806rjtOZrcHH+5kpPRlB9sB6Hs1PlXo4sXHw7ySy1u7I+hUydNPpg+XyL5tm
+G0q7gwLwln+sah1pkVGRFd+yHWoJYDFGNPuOskmrBJwOw8S/7VWl9bj5OqAEq6kG
+DnmdvnsuANwHIxbdSRvYe7dpQ8kGL9OuSu2jxrTlYA6DEdoqJSHcqfyPrV5XSxWi
+OgADxDVQVVqkhDh0rSv1Z+IBsSJsguII/NKJXpA3pRNb4jRWW10m6jtcHaKEwsSS
+aNa/plJA3+QhzF9baAKZOTsrx9+tR8e34gpNNoJD7D3YyC5s9FTZsWlLC6u/lIKZ
+fqub7HVOUD+HuZnpOd399Np0GuI7e1PS1HDHO0ZjW+iIN7uWG5gScNZsBaQjDUgJ
+pdwp7YQ7kmOZxesctWDpUK3Ak3bmT26MGANVpQLHTuG8Ntbj0hwSH+LTEgO1EN98
+R/fppLzl4fLNNAcI7E213tOPHrA7St8/HzUNav3vzFv+IUpX0qA8vj6jGuponPrN
+RjfTN2nK/uT0FmMnzo0AWGVZ4+Bk1py3QSPYlGzJqTyqWU8SXkqtmeA+PVVvxHAu
+U4CSYYD2J08KhBc5vAXowIJPVGe1u0VoPCAnm5RFIoRdqjhpMihi7/bzQo+WxXur
+btcSJifKfUgYDblltZor5UVvbexe4QIDAQABAoICABBFnKFgtxTkt+oNpAK6a+RU
+JMBvWOBJDxqALGN6wfZci8BIEoMatAvhbQz1GpfqvXjt3EXc0PFlLe9LbOpeS88y
+83EpuVF3Irllnm98w7ts7l/mxBry1BpoBqJQ7Rms8mrqRYwRwgPrB84zGpUWlBtn
+xMXU9gE2V8wAVNY8nvR+GnbNrzhxcnChWu4JNXSnxeHRNkwP0NdxKCi28g9MEl9l
+0JxvRLAIBKAgnIidYGl7mZMYr3xYkpRzV6cBEXxLENqUF1UdN760SjRg+w2Iax5x
+DuM6px5dumUjMfPlQj2JNY5cy2skSwqTa3zPkWZF7D3G19EVJHEI4c2AQxCeEQTl
+FGV3mW72JgHoOR/6baP8pvrDqcrPbGMZopgG3EUJ4LvoSp1banDb27PzBgqpvR1/
+YOiP5H70sCZ2Wal88KPlAhH6sijVVGUa1DMPTaPJi77soXmFhqMhX7dCviQipRc2
+9k2NZlCAS3Cqvbbf3JeVEwTL1LO122fP3LJcIGyGi9AxJ013LSbmOySKdxC8RKJa
+G0V0jZ+eSnDSlyWLVHI1XHr/wmzPNJExz2EGRMMDRhrFGZma5//ycc34oIIup2dL
+O5fXtFgKbGyOfqmaWVIncnSb+b7/b04ebUMnktKRr9y6iCRDgCI8+qzFgfGfdW9R
+ChPwEmSRPiBnKLPH57FBAoIBAQD+qNXRI5kbAQPF2vuyJpqGgXYGGWW1HUgBvksG
+rrxzqZnbMvW5rNG6/Dfnwot9QAlRuLQtymTRgCKNCPlV+vE/vjF5fkoTpb7As+OQ
+0KR+DDvWEj51Z/iJJoQR29vRkXjxIgvTKOs/ZkxHbdzepmg+bUFBUuDQczQN+lxJ
+N6KCrmbNE8YW2Fn2lS+Kd4HX9imDWBRY1fwU+uQD4/xkMYO8a6K/wUPj/nEuGOGR
+4XAqz7zYRXwOcqiHIDDtsSNzjfIljuyQPv84gEZDxQmzejAA6x0Ivg/pMv69IMad
+aodObqdWd7mzEUk519/gkUzl17jolcO53o4UAs4vIOIXNzD5AoIBAQD92q2LLGH3
+4tqloVCMR5N7GRTPhR7joBKuoLY5GEDDKfPiiL/y3ceiZv0p0rZGkq925fHaBMgQ
+jIFDTX6kG1ae7+KLWvFKHt8ET1DEiOD941AsVD0i7v02IwROwfq+D13nU8kYX6rx
+1TqJ+h5NKis1/pQIWSOomU1l90phJiC7xJFxaQW5ScNGjbM3gFnmblG4zLvdIUGN
+rZCZIScIYfrgrorh7X0CTm9fZsemChPsPn/O26PnIp7W4Qd+wb6irxA2rc4Y7tr9
+dkyITfeMgNwvzFE8k3BvIjI5x6Obv6DAmaOw9wXvAc3uwmxuZ0kjB5SNhPyZym+g
+8WiqnleXmn8pAoIBACKNTdV+evuK+7QQri3Rxw2Q6y6Qq5gTTP3Pj+ZsNu2KiXGQ
+TH7Qz/QK3Jr5bmukEJ+h6/B6kYtLU2THXu0niywW5ieR1wMrbeI/hhTT+j2P815s
+Q0Uywin5q9mwdvbMQhiVgf04hBKqEpdudJVRBrvRnxT55b7ioqFy4qqcfdQ1TYVt
+tWbMHAi03SpwZJGkuKU1gi07e2RtVhqhCFGf1jvubrqNwmRg1YJnpdNhPxLP9NNz
+Og3LyMnsuDbH3gODsuMdrUM1CPPlk6MGTPapEXJOdDYHc6k0XhPTKp+ZIJqnsNSu
+keeV5NWQULPrgv98cX49M704URat+sOyNnrn5iECggEAWZy7jJizUM1tP/DtPUf7
+IQZemU8180bLsYecLBWKrxp9NKfvkq2FzqeqkPwISmt3s3JC6SKs+WKQMxEFNqtL
+7bli8Ky+5tp1AdF6ApcLTbTT1YI7Pry8+EJuP9ssR7GnBYVHROporwwFqTV5QuYy
+8NGYskW9V8QeVXNxd0/9WCtw6GcZlSob3CkjbeFKWxTwllr3qn0V5gyyMcxJOiVU
+acJT1qN+cLT9jeD7c3q1Q71gYsaYWnyXM+WmPrHoOQexoovCaHzRI46CP8++JoRK
+tjjbKJYnp6ObtVfrQozoE3VpGoxpNNEfQDy0CFk/sTT41OhwP13+AAOYXjqdUzA/
+2QKCAQEAnUxnOZjAOpZ+x1D4RpBG8PseWR4bL29izBU32p6uuQIr0sodpke3L0dV
+G415p0FY0vC7OH+NICXX5uhS/AsFPKGjwYev+6OBQBJAxmNSc6UQLIVConNVrjYk
+4ZS+CO7JTKLp/GlqX/mZTWmJ6ilCSgrWLl6UFkc6wAeqlsSajTyqFkV3eTqSEVnd
+LDt6ioT2qZvn2NeubCpqvUfMqJk+RnaG76DMzEv4Y4jAvrxiia0ytzmMLkogc4Fn
+rsI22MHeZMMstBNYchF2D7ABXFaVN0XGqJi1cD/delHNpMndamxcsCTKbquZSLYy
+VT7TFitme9cTVbK0PkJ52qMGqrJ+aA==
+-----END PRIVATE KEY-----
diff --git a/apexd/apexd_testdata/com.android.apex.brand.new.avbpubkey b/apexd/apexd_testdata/com.android.apex.brand.new.avbpubkey
new file mode 100644
index 00000000..bb19cf90
Binary files /dev/null and b/apexd/apexd_testdata/com.android.apex.brand.new.avbpubkey differ
diff --git a/apexd/apexd_testdata/com.android.apex.brand.new.pem b/apexd/apexd_testdata/com.android.apex.brand.new.pem
new file mode 100644
index 00000000..4e44206d
--- /dev/null
+++ b/apexd/apexd_testdata/com.android.apex.brand.new.pem
@@ -0,0 +1,52 @@
+-----BEGIN PRIVATE KEY-----
+MIIJRAIBADANBgkqhkiG9w0BAQEFAASCCS4wggkqAgEAAoICAQC/WUnfI8dHk60m
+6ZZHRGJAXcP9XiG9sfxAawZwzbdt7ewVP2eJZZCNXDngRQLOjai8Ik0bnZlX5QmQ
+FKzqFJYmiv0G2yZJApxSsDqknYKwnRrQD27JScyGZj6PCpeR6pkq9iWgYQwaMC2y
+R6A5yAppm0XJX2xr2P04N0jIIa+BtvTmAdWKVP0cuqFYM1WJXBTQBp2x/i6G689G
+/l3rbH5EE9JQsRVjza1I26wW5W1tkiuPXq+4MFvFnoL9EHRGijeBhgkARyZTFEMo
+dhYijvYUpmc93iYxrNskwtyzLatTkGlL5qfVn7QQ8147/ENq9YKHXRi+kjuxcuOX
+PmIGD/5xkT/ANWkh02BrSmYgEDeqFo24f5CqRxWVj1YjPxBkGyoR52bhXNa1Mo6H
+wZEv2d5cAeFgg9tE+h/HgzsCmOdrSyuNttpMacEXavBEg9JjcJzKClUw+CYg0Bk0
+Ludp+vUAdoTgoSNklpy4ZeiOJRVN/rf1i0yilvVzxf0Low4kVlJLQLV06i+cGvzg
+SKFri50L/mg8l32oTZ6rh8xt37Dh30FLMK0VlFWh9o7EQCSspVYLS5KWsKBOCvpd
+hTDRPxYIsV8pWo3pXOUK9RKuSkKIFeGAim7f/A+aRUsu47dADJkfzLFNaYSUcLUV
+3KRiillGRzUG36HJrurwMCx4Jf0taQIDAQABAoICABTyurxfz52FrI9lw7K+KQ54
+ZXA7ybBZh67quJwJXXM+uJmT5Ssc0CA1sE1d6MKBri8Yhz4GeSbu92bLaKnAwrZq
+AWzqeYzFKSWBTw4+AzSAIpMUGXIWbvpov6ELzQ+nsgiKxZBDB57nVt1da4xf2sn4
+eoGi/XzqFsC8hq6IR41JIRL8MOtRxhsK0IaWKh9dUhb7HnEBzYiuULUqPFB9gm5E
+CEKWvGt+dSHUkMi56cq01al+uXiN7MIcCiWX0070q0J2EM6zu12dioOnt+ElKwoU
+NJnIlABctuoVnjFMhuThWrG5SPcBYqZ3akHhamUPhzB4D/EvE7Nny0Q/y130Cswl
+8bkD3x3Kcp9y6q6hVwRYocQ3UiTUjcptmAqxgEYVZEGunjpCR64OEJQJRfE8mVG1
+/ZNHO5vjud5vv46zshQAosfYioCOIM9NDyn5/4FDrSK8gjcTefiAsEjSdo/XarDI
+7+aFE3Dx8JPZmWjhzQdw5F634lFrnESBWs/hOkCmXUw5/Kdnt6ugXhg5pzPxF+YS
+Gx3VZuzqDhPtt1xYQ2qX5KTPzQM18JYYozzgmn1Xuj2jpx2RwzNnhy+8nOgjU8gf
+XpqsUHnQUZ0po9srVX9XtfHyYsbls2bv9u6oYUQfBI+RPCfRvheGwlOswQPzNaDH
+Y6retALXu48rQHHsq07hAoIBAQDxKnm7L4Uh7r0yaHJCvSCvaZkQjQx6pbg8AvsG
+ojlalCrxM4pzjTUV2DdwM3gRwSo1KKltxXQjxlPm2pfMpHqFKGMVgTlUCbBSM0Yc
+sFM97CoFMl0gwkV1TGT2/FbSbnsFJYpb0VSp/QPqIdlRIkM9ZnraSCrSfDJLozk9
+d26BkjkFD7Kb5rp5UUUaBuqFfFf1MCep5v/grSmHaIinCtq9g3ocjM0ajbC+0kvs
+xjN2VvKy7ARJYIPclbPGWHOvexz7BRLzzLiVNOvMnVj7r7vEkq4HC3DdkH57OECo
+2cof9xJfKPNwRcjrysL4sfAIdb/Ln72oMdYk36ALNbGVtPW5AoIBAQDLHl3M4jKR
+TIEkwEMJTQ4YE93ilr/N3CEa5ZtujNlwY9btf2f79Y8AB3Bos7eHzDA1s6XZtWb1
+9AqSV3aN+IoKiTOgzypO7SGmGzvtrTn29stUzceRvVzTRkixg2TL5bOC0EtvAYMm
+gYtkEOeu6DaVMCG4ttn7KlpMZEkomMZ0PqwGQXAMbuwsfvmqIfQTHL7rH+kFt52W
+l4ogUGlcOw/xW+I+NXWNEJPzB7F7nNhao8/SBmlEkRvomTqm469lKnT/TUkY/gDy
+z4fBffvSaFmB8HfRp6nL+7EQcygzLblsDRmzTFo6Ha7ByGuq8wUTWywIFjDp6Ez2
+1EUrn46Mvc0xAoIBAQCoUdoGkIMeDM/WF9nvxKrEYzJmv9s+2t08XWQw3BalppZW
+JH/0aFDtvyvqTrH1ylkYIxoluFN4CJtUm6qpNP8iYu7M+pU1l1GN/aVorpRaurMV
+T3J6Q71QwhIR5EsAsgWAsRPhQ7gQsLwDtL5Fh2FgwF7sbMQehnpgGjsAMJRbMOBF
+LRCfCSmLNPLC2KLkqcWGJqb4SXa7rIA4tvfxhnznGpWmyYr5hn0eog5F4ovWg5b+
+1AWl5QwDcCS6Qc/0YTv34zG4IWGPGhGdjRCnEZ8+8pUt64lJyujMPZW7g840AzC6
+ZA2MhdhW4fy0sRR0AyLrDsHDW403zTCZwk8Ayv1ZAoIBAQCLEMFb80p33I9W4COF
+jLInngJ+joPHp/0qcyWV7O06W8DdXiuNgDRl6rH1nYX8fbpMKjFU+zQBFRLf2u4a
+iZ3JVOJ6KRxoaUZueZrwQXe8NIBGEZWfnKyfIjHHB5TNXPkoiP/8gmaOyIbs/f4B
+7I7iWc/craRUqEymnMrR9rd5Aye4KLlUaeVdGZpJ93EqXLYCORjLh0lnv10cfrGE
+KhPiReyCdwuCh2UkMZI8dchTVnCE9UrBXTBkcfSMKrr9YrIz0XBIoi94Dsp9mYn+
+Jt+RbVg7vLUuKaazAoT1dUrMRbPg5FeqDoSFvHiq1DQXaoadCsR2gUugevjYwydQ
+COshAoIBAQCkCrWoK+L5OXcx0slz0i1iXXeuAIGaHXolIj6v3MvMipHNwD84wCS4
+vpu5IjqqfzP//sLQOxafjsWKhwahAOAAC/CfhLNXQPi3hNhE2kvDf9spMb+mTRpJ
+Yy+XI2jL5SQUPUlb7AFU4Gpe+sxDidldzuS2Z8bthyt3IqayzBPkGVjAk2MjrEIX
++gEa/InOCkqrJeulBL8AoCQUuCjPIZj8/OLNsgoYg8hWsq8OjLNWfoXv+9fdyCgP
+bpA2vLPXRakxd22K+IekZYY3Bbn85L+JPEqWNkuNugqAUWbLQUOdepG2tkjJftYr
+AziB6Uc3374Ysm7gyMqgHH0+dHkqOUDq
+-----END PRIVATE KEY-----
diff --git a/apexd/apexd_testdata/com.android.apex.brand.new.renamed.avbpubkey b/apexd/apexd_testdata/com.android.apex.brand.new.renamed.avbpubkey
new file mode 100644
index 00000000..bb19cf90
Binary files /dev/null and b/apexd/apexd_testdata/com.android.apex.brand.new.renamed.avbpubkey differ
diff --git a/apexd/apexd_testdata/manifest_bootstrap.json b/apexd/apexd_testdata/manifest_bootstrap.json
new file mode 100644
index 00000000..febbe352
--- /dev/null
+++ b/apexd/apexd_testdata/manifest_bootstrap.json
@@ -0,0 +1,5 @@
+{
+  "name": "com.android.apex.bootstrap_test_package",
+  "version": 1,
+  "bootstrap": true
+}
diff --git a/apexd/apexd_testdata/manifest_brand_new.json b/apexd/apexd_testdata/manifest_brand_new.json
new file mode 100644
index 00000000..1c743c82
--- /dev/null
+++ b/apexd/apexd_testdata/manifest_brand_new.json
@@ -0,0 +1,5 @@
+{
+  "name": "com.android.apex.brand.new",
+  "version": 1,
+  "supportsRebootlessUpdate": true
+}
diff --git a/apexd/apexd_testdata/manifest_brand_new_v2.json b/apexd/apexd_testdata/manifest_brand_new_v2.json
new file mode 100644
index 00000000..72d07a7a
--- /dev/null
+++ b/apexd/apexd_testdata/manifest_brand_new_v2.json
@@ -0,0 +1,4 @@
+{
+  "name": "com.android.apex.brand.new",
+  "version": 2
+}
diff --git a/apexd/apexd_utils.h b/apexd/apexd_utils.h
index d2d6566e..32262774 100644
--- a/apexd/apexd_utils.h
+++ b/apexd/apexd_utils.h
@@ -17,19 +17,6 @@
 #ifndef ANDROID_APEXD_APEXD_UTILS_H_
 #define ANDROID_APEXD_APEXD_UTILS_H_
 
-#include <chrono>
-#include <cstdint>
-#include <filesystem>
-#include <string>
-#include <thread>
-#include <type_traits>
-#include <vector>
-
-#include <dirent.h>
-#include <sys/stat.h>
-#include <sys/types.h>
-#include <sys/wait.h>
-
 #include <android-base/chrono_utils.h>
 #include <android-base/logging.h>
 #include <android-base/properties.h>
@@ -37,7 +24,20 @@
 #include <android-base/scopeguard.h>
 #include <android-base/strings.h>
 #include <cutils/android_reboot.h>
+#include <dirent.h>
 #include <selinux/android.h>
+#include <sys/stat.h>
+#include <sys/types.h>
+#include <sys/wait.h>
+
+#include <chrono>
+#include <cstdint>
+#include <filesystem>
+#include <span>
+#include <string>
+#include <thread>
+#include <type_traits>
+#include <vector>
 
 #include "apex_constants.h"
 
@@ -325,6 +325,12 @@ inline android::base::Result<std::string> GetfileconPath(
   return ret;
 }
 
+// Adapter for a single-valued span
+template <typename T>
+std::span<const T> Single(const T& t) {
+  return std::span{&t, 1};
+}
+
 }  // namespace apex
 }  // namespace android
 
diff --git a/apexd/apexd_vendor_apex.cpp b/apexd/apexd_vendor_apex.cpp
index 1e0a7820..88943c8b 100644
--- a/apexd/apexd_vendor_apex.cpp
+++ b/apexd/apexd_vendor_apex.cpp
@@ -18,63 +18,63 @@
 
 #include "apexd_vendor_apex.h"
 
+#include <android-base/logging.h>
 #include <android-base/strings.h>
 #include <vintf/VintfObject.h>
 
 #include "apex_file_repository.h"
 #include "apexd_private.h"
-#include "statslog_apex.h"
+#include "apexd_utils.h"
 
 using android::base::Error;
+using android::base::Result;
 using android::base::StartsWith;
 
-namespace android {
-namespace apex {
+namespace android::apex {
 
-bool InVendorPartition(const std::string& path) {
-  return StartsWith(path, "/vendor/apex/") ||
-         StartsWith(path, "/system/vendor/apex/");
-}
-
-bool InOdmPartition(const std::string& path) {
-  return StartsWith(path, "/odm/apex/") ||
-         StartsWith(path, "/vendor/odm/apex/") ||
-         StartsWith(path, "/system/vendor/odm/apex/");
-}
+using apexd_private::GetActiveMountPoint;
 
-// Returns if apex is a vendor apex, works by testing path of its preinstalled
-// version.
-bool IsVendorApex(const ApexFile& apex_file) {
-  const auto& instance = ApexFileRepository::GetInstance();
-  const auto& preinstalled =
-      instance.GetPreInstalledApex(apex_file.GetManifest().name());
-  const auto& path = preinstalled.get().GetPath();
-  return InVendorPartition(path) || InOdmPartition(path);
+static Result<bool> HasVintfIn(std::span<const std::string> apex_mounts) {
+  for (const auto& mount : apex_mounts) {
+    if (OR_RETURN(PathExists(mount + "/etc/vintf"))) return true;
+  }
+  return false;
 }
 
-// Checks Compatibility for incoming vendor apex.
+// Checks Compatibility for incoming APEXes.
 //    Adds the data from apex's vintf_fragment(s) and tests compatibility.
-base::Result<void> CheckVendorApexUpdate(const ApexFile& apex_file,
-                                         const std::string& apex_mount_point) {
+Result<std::map<std::string, std::vector<std::string>>> CheckVintf(
+    std::span<const ApexFile> apex_files,
+    std::span<const std::string> mount_points) {
   std::string error;
 
-  const std::string apex_name = apex_file.GetManifest().name();
+  std::vector<std::string> current_mounts;
+  for (const auto& apex : apex_files) {
+    current_mounts.push_back(GetActiveMountPoint(apex.GetManifest()));
+  }
 
-  std::string path_to_replace =
-      apexd_private::GetActiveMountPoint(apex_file.GetManifest());
+  // Skip the check unless any of the current/incoming APEXes has etc/vintf.
+  if (!OR_RETURN(HasVintfIn(current_mounts)) &&
+      !OR_RETURN(HasVintfIn(mount_points))) {
+    return {};
+  }
 
   // Create PathReplacingFileSystem instance containing caller's path
-  // substitution
+  // substitutions
+  std::map<std::string, std::string> replacements;
+  CHECK(apex_files.size() == mount_points.size()) << "size mismatch";
+  for (size_t i = 0; i < current_mounts.size(); i++) {
+    replacements.emplace(current_mounts[i], mount_points[i]);
+  }
   std::unique_ptr<vintf::FileSystem> path_replaced_fs =
       std::make_unique<vintf::details::PathReplacingFileSystem>(
-          std::move(path_to_replace), apex_mount_point,
-          std::make_unique<vintf::details::FileSystemImpl>());
+          std::make_unique<vintf::details::FileSystemImpl>(),
+          std::move(replacements));
 
   // Create a new VintfObject that uses our path-replacing FileSystem instance
-  auto vintf_with_replaced_path =
-      vintf::VintfObject::Builder()
-          .setFileSystem(std::move(path_replaced_fs))
-          .build();
+  auto vintf_object = vintf::VintfObject::Builder()
+                          .setFileSystem(std::move(path_replaced_fs))
+                          .build();
 
   // Disable RuntimeInfo components. Allows callers to run check
   // without requiring read permission of restricted resources
@@ -82,55 +82,30 @@ base::Result<void> CheckVendorApexUpdate(const ApexFile& apex_file,
   flags = flags.disableRuntimeInfo();
 
   // checkCompatibility on vintfObj using the replacement vintf directory
-  int ret = vintf_with_replaced_path->checkCompatibility(&error, flags);
-  LOG(DEBUG) << "CheckVendorApexUpdate: check on vendor apex " << apex_name
-             << " returned " << ret << " (want " << vintf::COMPATIBLE
-             << " == COMPATIBLE)";
+  int ret = vintf_object->checkCompatibility(&error, flags);
   if (ret == vintf::INCOMPATIBLE) {
-    return Error() << "vendor apex is not compatible, error=" << error;
-  } else if (ret != vintf::COMPATIBLE) {
-    return Error() << "Check of vendor apex failed, error=" << error;
-  }
-
-  return {};
-}
-
-// GetPreinstallPartitionEnum returns the enumeration value of the preinstall-
-//    partition of the passed apex_file
-int GetPreinstallPartitionEnum(const ApexFile& apex_file) {
-  const auto& instance = ApexFileRepository::GetInstance();
-  // We must test if this apex has a pre-installed version before calling
-  // GetPreInstalledApex() - throws an exception if apex doesn't have one
-  if (!instance.IsPreInstalledApex(apex_file)) {
-    return stats::apex::
-        APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_OTHER;
-  }
-  const auto& preinstalled =
-      instance.GetPreInstalledApex(apex_file.GetManifest().name());
-  const auto& preinstalled_path = preinstalled.get().GetPath();
-  if (InVendorPartition(preinstalled_path)) {
-    return stats::apex::
-        APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_VENDOR;
+    return Error() << "CheckVintf failed: not compatible. error=" << error;
   }
-  if (InOdmPartition(preinstalled_path)) {
-    return stats::apex::
-        APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_ODM;
+  if (ret != vintf::COMPATIBLE) {
+    return Error() << "CheckVintf failed: error=" << error;
   }
-  if (StartsWith(preinstalled_path, "/system_ext/apex/")) {
-    return stats::apex::
-        APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_SYSTEM_EXT;
-  }
-  if (StartsWith(preinstalled_path, "/system/apex/")) {
-    return stats::apex::
-        APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_SYSTEM;
-  }
-  if (StartsWith(preinstalled_path, "/product/apex/")) {
-    return stats::apex::
-        APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_PRODUCT;
-  }
-  return stats::apex::
-      APEX_INSTALLATION_REQUESTED__APEX_PREINSTALL_PARTITION__PARTITION_OTHER;
+
+  // Compat check passed.
+  // Collect HAL information from incoming APEXes for metrics.
+  std::map<std::string, std::vector<std::string>> apex_hals;
+  auto collect_hals = [&](auto manifest) {
+    manifest->forEachInstance([&](const auto& instance) {
+      if (instance.updatableViaApex().has_value()) {
+        apex_hals[instance.updatableViaApex().value()].push_back(
+            instance.nameWithVersion());
+      }
+      return true;  // continue
+    });
+  };
+  collect_hals(vintf_object->getFrameworkHalManifest());
+  collect_hals(vintf_object->getDeviceHalManifest());
+
+  return apex_hals;
 }
 
-}  // namespace apex
-}  // namespace android
+}  // namespace android::apex
diff --git a/apexd/apexd_vendor_apex.h b/apexd/apexd_vendor_apex.h
index 313a303b..d5865709 100644
--- a/apexd/apexd_vendor_apex.h
+++ b/apexd/apexd_vendor_apex.h
@@ -14,37 +14,23 @@
  * limitations under the License.
  */
 
-#ifndef ANDROID_APEXD_VENDOR_APEX_H_
-#define ANDROID_APEXD_VENDOR_APEX_H_
+#pragma once
 
 #include <android-base/result.h>
 
+#include <map>
+#include <span>
 #include <string>
+#include <vector>
 
 #include "apex_file.h"
 
-using android::base::Result;
+namespace android::apex {
 
-namespace android {
-namespace apex {
+// Checks VINTF for incoming apex updates.
+// Returns a map with APEX name and its HAL list.
+base::Result<std::map<std::string, std::vector<std::string>>> CheckVintf(
+    std::span<const ApexFile> apex_files,
+    std::span<const std::string> mount_points);
 
-bool InVendorPartition(const std::string& path);
-
-bool InOdmPartition(const std::string& path);
-
-// Determines if an incoming apex is a vendor apex
-bool IsVendorApex(const ApexFile& apex_file);
-
-// For incoming vendor apex updates.  Adds the data from its
-//   vintf_fragment(s) and tests compatibility.
-Result<void> CheckVendorApexUpdate(const ApexFile& apex_file,
-                                   const std::string& apex_mount_point);
-
-// GetPreinstallPartitionEnum returns an enumeration value of the
-//   preinstall partition of the passed apex_file
-int GetPreinstallPartitionEnum(const ApexFile& apex_file);
-
-}  // namespace apex
-}  // namespace android
-
-#endif  // ANDROID_APEXD_VENDOR_APEX_H_
+}  // namespace android::apex
diff --git a/apexd/apexservice.cpp b/apexd/apexservice.cpp
index 1dd59589..89685471 100644
--- a/apexd/apexservice.cpp
+++ b/apexd/apexservice.cpp
@@ -16,33 +16,33 @@
 
 #include "apexservice.h"
 
-#include <dirent.h>
-#include <stdio.h>
-#include <stdlib.h>
-
 #include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/properties.h>
 #include <android-base/result.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
+#include <android/apex/BnApexService.h>
 #include <binder/IPCThreadState.h>
 #include <binder/IResultReceiver.h>
 #include <binder/IServiceManager.h>
 #include <binder/LazyServiceRegistrar.h>
 #include <binder/ProcessState.h>
 #include <binder/Status.h>
+#include <dirent.h>
 #include <private/android_filesystem_config.h>
+#include <stdio.h>
+#include <stdlib.h>
 #include <utils/String16.h>
 
+#include "apex_constants.h"
 #include "apex_file.h"
 #include "apex_file_repository.h"
 #include "apexd.h"
+#include "apexd_metrics.h"
 #include "apexd_session.h"
 #include "string_log.h"
 
-#include <android/apex/BnApexService.h>
-
 using android::base::Join;
 using android::base::Result;
 
@@ -106,11 +106,7 @@ class ApexService : public BnApexService {
   BinderStatus destroyCeSnapshots(int user_id, int rollback_id) override;
   BinderStatus destroyCeSnapshotsNotSpecified(
       int user_id, const std::vector<int>& retain_rollback_ids) override;
-  BinderStatus remountPackages() override;
-  BinderStatus recollectPreinstalledData(
-      const std::vector<std::string>& paths) override;
-  BinderStatus recollectDataApex(const std::string& path,
-                                 const std::string& decompression_dir) override;
+  BinderStatus recollectPreinstalledData() override;
   BinderStatus markBootCompleted() override;
   BinderStatus calculateSizeForCompressedApex(
       const CompressedApexInfoList& compressed_apex_info_list,
@@ -355,6 +351,21 @@ void ConvertToApexSessionInfo(const ApexSession& session,
   }
 }
 
+static ::android::apex::ApexInfo::Partition Cast(ApexPartition in) {
+  switch (in) {
+    case ApexPartition::System:
+      return ::android::apex::ApexInfo::Partition::SYSTEM;
+    case ApexPartition::SystemExt:
+      return ::android::apex::ApexInfo::Partition::SYSTEM_EXT;
+    case ApexPartition::Product:
+      return ::android::apex::ApexInfo::Partition::PRODUCT;
+    case ApexPartition::Vendor:
+      return ::android::apex::ApexInfo::Partition::VENDOR;
+    case ApexPartition::Odm:
+      return ::android::apex::ApexInfo::Partition::ODM;
+  }
+}
+
 static ApexInfo GetApexInfo(const ApexFile& package) {
   auto& instance = ApexFileRepository::GetInstance();
   ApexInfo out;
@@ -367,31 +378,22 @@ static ApexInfo GetApexInfo(const ApexFile& package) {
   Result<std::string> preinstalled_path =
       instance.GetPreinstalledPath(package.GetManifest().name());
   if (preinstalled_path.ok()) {
-    // We replace the preinstalled paths for block devices to /system/apex
-    // because PackageManager will not resolve them if they aren't in one of
-    // the SYSTEM_PARTITIONS defined in PackagePartitions.java.
-    // b/195363518 for more context.
-    const std::string block_path = "/dev/block/";
-    const std::string sys_apex_path =
-        std::string(kApexPackageSystemDir) + "/" +
-        preinstalled_path->substr(block_path.length());
-    out.preinstalledModulePath = preinstalled_path->starts_with(block_path)
-                                     ? sys_apex_path
-                                     : *preinstalled_path;
+    out.preinstalledModulePath = *preinstalled_path;
   }
   out.activeApexChanged = ::android::apex::IsActiveApexChanged(package);
+  out.partition = Cast(OR_FATAL(instance.GetPartition(package)));
   return out;
 }
 
 static std::string ToString(const ApexInfo& package) {
-  std::string msg = StringLog()
-                    << "Module: " << package.moduleName
-                    << " Version: " << package.versionCode
-                    << " VersionName: " << package.versionName
-                    << " Path: " << package.modulePath
-                    << " IsActive: " << std::boolalpha << package.isActive
-                    << " IsFactory: " << std::boolalpha << package.isFactory
-                    << std::endl;
+  std::string msg =
+      StringLog() << "Module: " << package.moduleName
+                  << " Version: " << package.versionCode
+                  << " VersionName: " << package.versionName
+                  << " Path: " << package.modulePath
+                  << " IsActive: " << std::boolalpha << package.isActive
+                  << " IsFactory: " << std::boolalpha << package.isFactory
+                  << " Partition: " << toString(package.partition) << std::endl;
   return msg;
 }
 
@@ -726,27 +728,8 @@ BinderStatus ApexService::destroyCeSnapshotsNotSpecified(
   return BinderStatus::ok();
 }
 
-BinderStatus ApexService::remountPackages() {
-  LOG(INFO) << "remountPackages() received by ApexService";
-
-  if (auto debug = CheckDebuggable("remountPackages"); !debug.isOk()) {
-    return debug;
-  }
-  if (auto root = CheckCallerIsRoot("remountPackages"); !root.isOk()) {
-    return root;
-  }
-  if (auto res = ::android::apex::RemountPackages(); !res.ok()) {
-    return BinderStatus::fromExceptionCode(
-        BinderStatus::EX_SERVICE_SPECIFIC,
-        String8(res.error().message().c_str()));
-  }
-  return BinderStatus::ok();
-}
-
-BinderStatus ApexService::recollectPreinstalledData(
-    const std::vector<std::string>& paths) {
-  LOG(INFO) << "recollectPreinstalledData() received by ApexService, paths: "
-            << Join(paths, ',');
+BinderStatus ApexService::recollectPreinstalledData() {
+  LOG(INFO) << "recollectPreinstalledData() received by ApexService";
 
   if (auto debug = CheckDebuggable("recollectPreinstalledData");
       !debug.isOk()) {
@@ -756,28 +739,10 @@ BinderStatus ApexService::recollectPreinstalledData(
       !root.isOk()) {
     return root;
   }
-  ApexFileRepository& instance = ApexFileRepository::GetInstance();
-  if (auto res = instance.AddPreInstalledApex(paths); !res.ok()) {
-    return BinderStatus::fromExceptionCode(
-        BinderStatus::EX_SERVICE_SPECIFIC,
-        String8(res.error().message().c_str()));
-  }
-  return BinderStatus::ok();
-}
-
-BinderStatus ApexService::recollectDataApex(
-    const std::string& path, const std::string& decompression_dir) {
-  LOG(INFO) << "recollectDataApex() received by ApexService, paths " << path
-            << " and " << decompression_dir;
 
-  if (auto debug = CheckDebuggable("recollectDataApex"); !debug.isOk()) {
-    return debug;
-  }
-  if (auto root = CheckCallerIsRoot("recollectDataApex"); !root.isOk()) {
-    return root;
-  }
   ApexFileRepository& instance = ApexFileRepository::GetInstance();
-  if (auto res = instance.AddDataApex(path); !res.ok()) {
+  if (auto res = instance.AddPreInstalledApex(kBuiltinApexPackageDirs);
+      !res.ok()) {
     return BinderStatus::fromExceptionCode(
         BinderStatus::EX_SERVICE_SPECIFIC,
         String8(res.error().message().c_str()));
@@ -876,37 +841,14 @@ status_t ApexService::shellCommand(int in, int out, int err,
     }
     log << "ApexService:" << std::endl
         << "  help - display this help" << std::endl
-        << "  stagePackages [package_path1] ([package_path2]...) - stage "
-           "multiple packages from the given path"
-        << std::endl
         << "  getActivePackage [package_name] - return info for active package "
            "with given name, if present"
         << std::endl
         << "  getAllPackages - return the list of all packages" << std::endl
         << "  getActivePackages - return the list of active packages"
         << std::endl
-        << "  activatePackage [package_path] - activate package from the "
-           "given path"
-        << std::endl
-        << "  deactivatePackage [package_path] - deactivate package from the "
-           "given path"
-        << std::endl
         << "  getStagedSessionInfo [sessionId] - displays information about a "
            "given session previously submitted"
-        << std::endl
-        << "  submitStagedSession [sessionId] - attempts to submit the "
-           "installer session with given id"
-        << std::endl
-        << "  remountPackages - Force apexd to remount active packages. This "
-           "call can be used to speed up development workflow of an APEX "
-           "package. Example of usage:\n"
-           "    1. adb shell stop\n"
-           "    2. adb sync\n"
-           "    3. adb shell cmd -w apexservice remountPackages\n"
-           "    4. adb shell start\n"
-           "\n"
-           "Note: APEX package will be successfully remounted only if there "
-           "are no alive processes holding a reference to it"
         << std::endl;
     dprintf(fd, "%s", log.operator std::string().c_str());
   };
@@ -918,25 +860,6 @@ status_t ApexService::shellCommand(int in, int out, int err,
 
   const String16& cmd = args[0];
 
-  if (cmd == String16("stagePackages")) {
-    if (args.size() < 2) {
-      print_help(err, "stagePackages requires at least one package_path");
-      return BAD_VALUE;
-    }
-    std::vector<std::string> pkgs;
-    pkgs.reserve(args.size() - 1);
-    for (size_t i = 1; i != args.size(); ++i) {
-      pkgs.emplace_back(String8(args[i]).c_str());
-    }
-    BinderStatus status = stagePackages(pkgs);
-    if (status.isOk()) {
-      return OK;
-    }
-    std::string msg = StringLog() << "Failed to stage package(s): "
-                                  << status.toString8().c_str() << std::endl;
-    dprintf(err, "%s", msg.c_str());
-    return BAD_VALUE;
-  }
   if (cmd == String16("getAllPackages")) {
     if (args.size() != 1) {
       print_help(err, "Unrecognized options");
@@ -999,38 +922,6 @@ status_t ApexService::shellCommand(int in, int out, int err,
     return BAD_VALUE;
   }
 
-  if (cmd == String16("activatePackage")) {
-    if (args.size() != 2) {
-      print_help(err, "activatePackage requires one package_path");
-      return BAD_VALUE;
-    }
-    std::string path = String8(args[1]).c_str();
-    auto status = ::android::apex::ActivatePackage(path);
-    if (status.ok()) {
-      return OK;
-    }
-    std::string msg = StringLog() << "Failed to activate package: "
-                                  << status.error().message() << std::endl;
-    dprintf(err, "%s", msg.c_str());
-    return BAD_VALUE;
-  }
-
-  if (cmd == String16("deactivatePackage")) {
-    if (args.size() != 2) {
-      print_help(err, "deactivatePackage requires one package_path");
-      return BAD_VALUE;
-    }
-    std::string path = String8(args[1]).c_str();
-    auto status = ::android::apex::DeactivatePackage(path);
-    if (status.ok()) {
-      return OK;
-    }
-    std::string msg = StringLog() << "Failed to deactivate package: "
-                                  << status.error().message() << std::endl;
-    dprintf(err, "%s", msg.c_str());
-    return BAD_VALUE;
-  }
-
   if (cmd == String16("getStagedSessionInfo")) {
     if (args.size() != 2) {
       print_help(err, "getStagedSessionInfo requires one session id");
@@ -1070,49 +961,6 @@ status_t ApexService::shellCommand(int in, int out, int err,
     return BAD_VALUE;
   }
 
-  if (cmd == String16("submitStagedSession")) {
-    if (args.size() != 2) {
-      print_help(err, "submitStagedSession requires one session id");
-      return BAD_VALUE;
-    }
-    int session_id = strtol(String8(args[1]).c_str(), nullptr, 10);
-    if (session_id < 0) {
-      std::string msg = StringLog()
-                        << "Failed to parse session id. Must be an integer.";
-      dprintf(err, "%s", msg.c_str());
-      return BAD_VALUE;
-    }
-
-    ApexInfoList list;
-    std::vector<int> empty_child_session_ids;
-    ApexSessionParams params;
-    params.sessionId = session_id;
-    params.childSessionIds = empty_child_session_ids;
-    BinderStatus status = submitStagedSession(params, &list);
-    if (status.isOk()) {
-        for (const auto& item : list.apexInfos) {
-          std::string msg = ToString(item);
-          dprintf(out, "%s", msg.c_str());
-        }
-      return OK;
-    }
-    std::string msg = StringLog() << "Failed to submit session: "
-                                  << status.toString8().c_str() << std::endl;
-    dprintf(err, "%s", msg.c_str());
-    return BAD_VALUE;
-  }
-
-  if (cmd == String16("remountPackages")) {
-    BinderStatus status = remountPackages();
-    if (status.isOk()) {
-      return OK;
-    }
-    std::string msg = StringLog() << "remountPackages failed: "
-                                  << status.toString8().c_str() << std::endl;
-    dprintf(err, "%s", msg.c_str());
-    return BAD_VALUE;
-  }
-
   if (cmd == String16("help")) {
     if (args.size() != 1) {
       print_help(err, "Help has no options");
diff --git a/apexd/apexservice_test.cpp b/apexd/apexservice_test.cpp
index 51adef06..97eee063 100644
--- a/apexd/apexservice_test.cpp
+++ b/apexd/apexservice_test.cpp
@@ -122,7 +122,7 @@ class ApexServiceTest : public ::testing::Test {
         vold_service_->supportsCheckpoint(&supports_fs_checkpointing_);
     ASSERT_TRUE(IsOk(status));
     CleanUp();
-    service_->recollectPreinstalledData(kApexPackageBuiltinDirs);
+    service_->recollectPreinstalledData();
 
     session_manager_ = ApexSessionManager::Create(GetSessionsDir());
   }
diff --git a/apexer/Android.bp b/apexer/Android.bp
index 780730b1..d41a53bb 100644
--- a/apexer/Android.bp
+++ b/apexer/Android.bp
@@ -104,10 +104,6 @@ python_test_host {
         "apexer_test.py",
     ],
     data: [
-        ":com.android.example.apex",
-        ":com.android.example-legacy.apex",
-        ":com.android.example-logging_parent.apex",
-        ":com.android.example-overridden_package_name.apex",
         ":apexer_test_host_tools",
         "testdata/com.android.example.apex.avbpubkey",
         "testdata/com.android.example.apex.pem",
@@ -115,6 +111,12 @@ python_test_host {
         "testdata/com.android.example.apex.x509.pem",
         "testdata/manifest.json",
     ],
+    device_common_data: [
+        ":com.android.example.apex",
+        ":com.android.example-legacy.apex",
+        ":com.android.example-logging_parent.apex",
+        ":com.android.example-overridden_package_name.apex",
+    ],
     test_suites: ["general-tests"],
     libs: [
         "apex_manifest",
diff --git a/apexer/apexer.py b/apexer/apexer.py
index 88541545..d57fafdf 100644
--- a/apexer/apexer.py
+++ b/apexer/apexer.py
@@ -108,7 +108,6 @@ def ParseArgs(argv):
       '--payload_fs_type',
       metavar='FS_TYPE',
       required=False,
-      default='ext4',
       choices=['ext4', 'f2fs', 'erofs'],
       help='type of filesystem being used for payload image "ext4", "f2fs" or "erofs"')
   parser.add_argument(
@@ -379,6 +378,12 @@ def ValidateArgs(args):
       if build_info.logging_parent:
         args.logging_parent = build_info.logging_parent
 
+  if not args.payload_fs_type:
+    if build_info and build_info.payload_fs_type:
+      args.payload_fs_type = build_info.payload_fs_type
+    else:
+      args.payload_fs_type = 'ext4'
+
   return True
 
 
diff --git a/apexer/apexer_test.py b/apexer/apexer_test.py
index 48d4a957..18b003fa 100644
--- a/apexer/apexer_test.py
+++ b/apexer/apexer_test.py
@@ -180,11 +180,11 @@ class ApexerRebuildTest(unittest.TestCase):
 
         files = {}
         for i in ["apexer", "deapexer", "avbtool", "mke2fs", "sefcontext_compile", "e2fsdroid",
-            "resize2fs", "soong_zip", "aapt2", "merge_zips", "zipalign", "debugfs_static",
-                  "signapk.jar", "android.jar", "blkid", "fsck.erofs", "conv_apex_manifest"]:
+                  "resize2fs", "soong_zip", "aapt2", "merge_zips", "zipalign", "debugfs_static",
+                  "signapk.jar", "android.jar", "make_erofs", "fsck.erofs", "conv_apex_manifest"]:
             file_path = os.path.join(dir_name, "bin", i)
             if os.path.exists(file_path):
-                os.chmod(file_path, stat.S_IRUSR | stat.S_IXUSR);
+                os.chmod(file_path, stat.S_IRUSR | stat.S_IXUSR)
                 files[i] = file_path
             else:
                 files[i] = i
@@ -255,8 +255,8 @@ class ApexerRebuildTest(unittest.TestCase):
         dir_name = tempfile.mkdtemp(prefix=self._testMethodName+"_extracted_payload_")
         self._to_cleanup.append(dir_name)
         cmd = ["deapexer", "--debugfs_path", self.host_tools["debugfs_static"],
-               "--blkid_path",self.host_tools["blkid"], "--fsckerofs_path",
-               self.host_tools["fsck.erofs"], "extract", apex_file_path, dir_name]
+               "--fsckerofs_path", self.host_tools["fsck.erofs"], "extract",
+               apex_file_path, dir_name]
         run_host_command(cmd)
 
         # Remove payload files added by apexer and e2fs tools.
@@ -420,14 +420,6 @@ class ApexerRebuildTest(unittest.TestCase):
         self.assertEqual(get_sha1sum(signed_payload),
                          get_sha1sum(container_files["apex_payload"]))
 
-        # Now assert that given an unsigned image and the original container
-        # files, we can produce an identical unsigned image.
-        unsigned_payload_dir = self._extract_payload_from_img(unsigned_payload_only_file_path)
-        unsigned_payload_only_2_file_path = self._run_apexer(container_files, unsigned_payload_dir,
-                                                             ["--unsigned_payload_only"])
-        self.assertEqual(get_sha1sum(unsigned_payload_only_file_path),
-                         get_sha1sum(unsigned_payload_only_2_file_path))
-
     def test_apex_with_logging_parent(self):
       self._run_build_test(TEST_APEX_WITH_LOGGING_PARENT)
 
diff --git a/docs/howto.md b/docs/howto.md
index 853f9760..3df8f047 100644
--- a/docs/howto.md
+++ b/docs/howto.md
@@ -343,22 +343,25 @@ implicit.
 Use
 
 ```
-adb sync && adb shell cmd -w apexservice remountPackages
+adb install --force-non-staged <path_to_apex>
 ```
 
-Note that for this command to remount your APEX, you must ensure that all
-processes that have reference to your APEX are killed. E.g. if you are
-developing an APEX that contributes to system\_server, you can use the
-following:
+This is a development only feature that only works on debuggable builds.
+It can be used to speed up development workflow for teams that have
+their code packaged in an APEX.
 
-```
-adb root
-adb remount
-adb shell stop
-adb sync
-adb shell cmd -w apexservice remountPackages
-adb shell start
-```
+Example of how this feature can be used:
+
+1. Iterate on code in an APEX
+2. Build APEX
+3. `adb install --force-non-staged out/dist/your.apex`
+4. Restart the processes that depend on this APEX
+   (e.g. `adb shell stop && adb shell start`).
+5. ???
+6. Profit
+
+Behind the scenes the force non-staged APEX update is implemented by
+unmounting the /apex/ mount point with `MNT_DETACH` flag.
 
 ## Using an APEX
 
diff --git a/libs/libapexsupport/.clang-format b/libs/libapexsupport/.clang-format
new file mode 120000
index 00000000..037a768d
--- /dev/null
+++ b/libs/libapexsupport/.clang-format
@@ -0,0 +1 @@
+../../apexd/.clang-format
\ No newline at end of file
diff --git a/libs/libapexsupport/Android.bp b/libs/libapexsupport/Android.bp
index a3d128cf..e7743d88 100644
--- a/libs/libapexsupport/Android.bp
+++ b/libs/libapexsupport/Android.bp
@@ -40,7 +40,6 @@ cc_library {
     llndk: {
         symbol_file: "libapexsupport.map.txt",
         unversioned: true,
-        export_llndk_headers: ["libvendorsupport_llndk_headers"],
     },
     export_include_dirs: [
         "include",
@@ -48,10 +47,4 @@ cc_library {
     local_include_dirs: [
         "include",
     ],
-    header_libs: [
-        "libvendorsupport_llndk_headers",
-    ],
-    export_header_lib_headers: [
-        "libvendorsupport_llndk_headers",
-    ],
 }
diff --git a/libs/libapexsupport/include/android/apexsupport.h b/libs/libapexsupport/include/android/apexsupport.h
index 63dd86b4..9c11b3ae 100644
--- a/libs/libapexsupport/include/android/apexsupport.h
+++ b/libs/libapexsupport/include/android/apexsupport.h
@@ -44,6 +44,9 @@ typedef enum AApexInfoError : int32_t {
   AAPEXINFO_INVALID_APEX,
 } AApexInfoError;
 
+// Defining #llndk symbols
+#if defined(__ANDROID_VNDK__) || !defined(__ANDROID_APEX__)
+
 /**
  * Creates an AApexInfo object from the current calling executable. For example,
  * when called by a binary from /apex/com.android.foo/bin/foo, this will set an
@@ -56,15 +59,16 @@ typedef enum AApexInfoError : int32_t {
  *
  * \returns AApexInfoError
  */
-__attribute__((warn_unused_result)) AApexInfoError
-AApexInfo_create(AApexInfo *_Nullable *_Nonnull info);
+__attribute__((warn_unused_result)) AApexInfoError AApexInfo_create(
+    AApexInfo *_Nullable *_Nonnull info) __INTRODUCED_IN(__ANDROID_API_V__);
 
 /**
  * Destroys an AApexInfo object created by AApexInfo_create().
  *
  * \param info pointer to the AApexInfo object created by AApexInfo_create()
  */
-void AApexInfo_destroy(AApexInfo *_Nonnull info);
+void AApexInfo_destroy(AApexInfo *_Nonnull info)
+    __INTRODUCED_IN(__ANDROID_API_V__);
 
 /**
  * Returns a C-string for the APEX name.
@@ -78,7 +82,8 @@ void AApexInfo_destroy(AApexInfo *_Nonnull info);
  * \return the APEX name.
  */
 __attribute__((warn_unused_result))
-const char *_Nonnull AApexInfo_getName(const AApexInfo *_Nonnull info);
+const char *_Nonnull AApexInfo_getName(const AApexInfo *_Nonnull info)
+    __INTRODUCED_IN(__ANDROID_API_V__);
 
 /**
  * Returns the APEX version.
@@ -87,10 +92,13 @@ const char *_Nonnull AApexInfo_getName(const AApexInfo *_Nonnull info);
  *
  * \return the APEX version.
  */
-int64_t AApexInfo_getVersion(const AApexInfo *_Nonnull info);
+int64_t AApexInfo_getVersion(const AApexInfo *_Nonnull info)
+    __INTRODUCED_IN(__ANDROID_API_V__);
+
+#endif
 
 // AApexSupport_loadLibrary is private to platform yet.
-#if !defined(__ANDROID_VENDOR__) && !defined(__ANDROID_PRODUCT__)
+#if !defined(__ANDROID_VNDK__) && !defined(__ANDROID_APEX__)
 /**
  * Opens a library from a given apex and returns its handle.
  *
diff --git a/libs/libapexsupport/tests/Android.bp b/libs/libapexsupport/tests/Android.bp
index 1e53a7b0..da7aed38 100644
--- a/libs/libapexsupport/tests/Android.bp
+++ b/libs/libapexsupport/tests/Android.bp
@@ -43,7 +43,7 @@ sh_test_host {
     test_options: {
         unit_test: false,
     },
-    data: [
+    device_common_data: [
         ":com.android.libapexsupport.tests",
     ],
 }
diff --git a/proto/Android.bp b/proto/Android.bp
index 24619bf7..bb505ee2 100644
--- a/proto/Android.bp
+++ b/proto/Android.bp
@@ -90,6 +90,15 @@ cc_library_static {
     srcs: ["session_state.proto"],
 }
 
+cc_library_static {
+    name: "lib_apex_blocklist_proto",
+    host_supported: true,
+    proto: {
+        export_proto_headers: true,
+    },
+    srcs: ["apex_blocklist.proto"],
+}
+
 genrule {
     name: "apex-protos",
     tools: ["soong_zip"],
diff --git a/proto/apex_blocklist.proto b/proto/apex_blocklist.proto
new file mode 100644
index 00000000..cba331ab
--- /dev/null
+++ b/proto/apex_blocklist.proto
@@ -0,0 +1,38 @@
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
+syntax = "proto3";
+
+package apex.proto;
+
+option java_package = "com.android.apex";
+option java_outer_classname = "Protos";
+
+message ApexBlocklist {
+  message ApexItem {
+    // Required.
+    // APEX name defined in manifest.
+    string name = 1;
+
+    // Required.
+    // Version number. Must be positive. Any version that is equal to or lower
+    // than the specified version is blocked.
+    int64 version = 2;
+  }
+
+  // The list of APEX that should be blocked from installation.
+  repeated ApexItem blocked_apex = 1;
+}
diff --git a/proto/apex_manifest.proto b/proto/apex_manifest.proto
index cc3bd43a..09bbf38d 100644
--- a/proto/apex_manifest.proto
+++ b/proto/apex_manifest.proto
@@ -87,6 +87,13 @@ message ApexManifest {
   // VNDK version for apexes depending on a specific version of VNDK libs.
   string vndkVersion = 14;
 
+  // Deprecated.
   // Whether this vendor APEX needs to be activated in bootstrap phase.
-  bool vendorBootstrap = 15;
+  // For new APEX, please use `bootstrap` instead.
+  // Vendor APEX become bootstrap APEX if either `vendorBootstrap`
+  // or `bootstrap` is set to true.
+  bool vendorBootstrap = 15 [ deprecated = true ];
+
+  // Whether this APEX needs to be activated in bootstrap phase.
+  bool bootstrap = 16;
 }
diff --git a/proto/session_state.proto b/proto/session_state.proto
index cebf0adb..ad49ef40 100644
--- a/proto/session_state.proto
+++ b/proto/session_state.proto
@@ -61,4 +61,7 @@ message SessionState {
 
   // Populated with error details when session fails to activate
   string error_message = 10;
+
+  // The list of sha256 hashes of apexes within this session.
+  repeated string apex_file_hashes = 11;
 }
diff --git a/pylintrc b/pylintrc
index 88750048..8cc06f47 100644
--- a/pylintrc
+++ b/pylintrc
@@ -161,12 +161,6 @@ disable=abstract-method,
 # mypackage.mymodule.MyReporterClass.
 output-format=text
 
-# Put messages in a separate file for each module / package specified on the
-# command line instead of printing them on stdout. Reports (if any) will be
-# written in a file name "pylint_global.[txt|html]". This option is deprecated
-# and it will be removed in Pylint 2.0.
-files-output=no
-
 # Tells whether to display a full report or only the messages
 reports=no
 
@@ -271,7 +265,7 @@ generated-members=
 [FORMAT]
 
 # Maximum number of characters on a single line.
-max-line-length=80
+max-line-length=100
 
 # TODO(https://github.com/PyCQA/pylint/issues/3352): Direct pylint to exempt
 # lines made too long by directives to pytype.
@@ -285,12 +279,6 @@ ignore-long-lines=(?x)(
 # else.
 single-line-if-stmt=yes
 
-# List of optional constructs for which whitespace checking is disabled. `dict-
-# separator` is used to allow tabulation in dicts, etc.: {1  : 1,\n222: 2}.
-# `trailing-comma` allows a space between comma and closing bracket: (a, ).
-# `empty-line` allows space-only lines.
-no-space-check=
-
 # Maximum number of lines in a module
 max-module-lines=99999
 
@@ -442,6 +430,6 @@ valid-metaclass-classmethod-first-arg=mcs
 
 # Exceptions that will emit a warning when being caught. Defaults to
 # "Exception"
-overgeneral-exceptions=StandardError,
-                       Exception,
-                       BaseException
+overgeneral-exceptions=builtins.StandardError,
+                       builtins.Exception,
+                       builtins.BaseException
diff --git a/shim/build/Android.bp b/shim/build/Android.bp
index 36d12fd7..1838eb6d 100644
--- a/shim/build/Android.bp
+++ b/shim/build/Android.bp
@@ -249,7 +249,7 @@ apex {
     updatable: false,
 }
 
-genrule {
+java_genrule {
     name: "generate_hash_v1",
     srcs: [
         ":com.android.apex.cts.shim.v2",
@@ -422,7 +422,7 @@ genrule {
 }
 
 // v2 cts shim package signed by bob, without lineage
-genrule {
+java_genrule {
     name: "com.android.apex.cts.shim.v2_signed_bob",
     out: ["com.android.apex.cts.shim.v2_signed_bob"],
     tools: [":apksigner"],
@@ -439,7 +439,7 @@ genrule {
 }
 
 // v2 cts shim package signed by bob + lineage
-genrule {
+java_genrule {
     name: "com.android.apex.cts.shim.v2_signed_bob_rot",
     out: ["com.android.apex.cts.shim.v2_signed_bob_rot"],
     tools: [":apksigner"],
@@ -457,7 +457,7 @@ genrule {
 }
 
 // v2 cts shim package signed by bob + lineage + rollback capability
-genrule {
+java_genrule {
     name: "com.android.apex.cts.shim.v2_signed_bob_rot_rollback",
     out: ["com.android.apex.cts.shim.v2_signed_bob_rot_rollback"],
     tools: [":apksigner"],
@@ -475,7 +475,7 @@ genrule {
 }
 
 // v3 cts shim package signed by bob
-genrule {
+java_genrule {
     name: "com.android.apex.cts.shim.v3_signed_bob",
     out: ["com.android.apex.cts.shim.v3_signed_bob"],
     tools: [":apksigner"],
@@ -492,7 +492,7 @@ genrule {
 }
 
 // v3 cts shim package signed by bob + lineage
-genrule {
+java_genrule {
     name: "com.android.apex.cts.shim.v3_signed_bob_rot",
     out: ["com.android.apex.cts.shim.v3_signed_bob_rot"],
     tools: [":apksigner"],
@@ -527,7 +527,7 @@ apex {
     updatable: false,
 }
 
-genrule {
+java_genrule {
     name: "com.android.apex.cts.shim.v2_no_pb",
     srcs: [":com.android.apex.cts.shim.v2_legacy"],
     out: ["com.android.apex.cts.shim.v2_no_pb.apex"],
@@ -566,7 +566,7 @@ apex {
 }
 
 // Apex shim with unsigned apk
-genrule {
+java_genrule {
     name: "com.android.apex.cts.shim.v2_unsigned_apk_container",
     // Use shim.v2_rebootless to re-use same APEX in the rebootless update test case.
     srcs: [":com.android.apex.cts.shim.v2_rebootless"],
diff --git a/tests/native/.clang-format b/tests/.clang-format
similarity index 100%
rename from tests/native/.clang-format
rename to tests/.clang-format
diff --git a/tests/Android.bp b/tests/Android.bp
index 46d7cb03..25da3e01 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -34,7 +34,7 @@ java_test_host {
     static_libs: [
         "platformprotos",
     ],
-    data: [
+    device_common_data: [
         ":test1_com.android.tzdata",
     ],
     test_config: "timezone-data-e2e-tests.xml",
@@ -45,7 +45,7 @@ java_test_host {
     name: "media_e2e_tests",
     srcs: ["src/**/MediaHostTest.java"],
     defaults: ["apex_e2e_test_defaults"],
-    data: [
+    device_common_data: [
         ":test_com.android.media",
     ],
     test_config: "media-e2e-tests.xml",
@@ -56,7 +56,7 @@ java_test_host {
     name: "media_swcodec_e2e_tests",
     srcs: ["src/**/MediaSwCodecHostTest.java"],
     defaults: ["apex_e2e_test_defaults"],
-    data: [
+    device_common_data: [
         ":test_com.android.media.swcodec",
     ],
     test_config: "media-swcodec-e2e-tests.xml",
@@ -67,7 +67,7 @@ java_test_host {
     name: "apex_targetprep_tests",
     libs: ["tradefed"],
     srcs: ["src/**/ApexTargetPrepTest.java"],
-    data: [":StagedInstallTestApexV2"],
+    device_common_data: [":StagedInstallTestApexV2"],
     test_config: "apex-targetprep-tests.xml",
     test_suites: ["general-tests"],
 }
@@ -145,6 +145,8 @@ java_test_host {
         "testdata/trigger_watchdog.rc",
         "testdata/trigger_watchdog.sh",
         "testdata/trigger_reboot.sh",
+    ],
+    device_common_data: [
         ":apex.apexd_test_v2",
         ":com.android.apex.cts.shim.v2_prebuilt",
     ],
@@ -165,7 +167,7 @@ java_test_host {
     ],
     test_config: "apexd-host-tests.xml",
     test_suites: ["general-tests"],
-    data: [
+    device_common_data: [
         ":apex.apexd_test",
         ":apex.apexd_test_v2",
         ":apex.apexd_test_v2_no_pb",
@@ -176,7 +178,6 @@ java_test_host {
         ":test.good1.com.android.hardware.wifi",
         ":test.bad1.com.android.hardware.wifi",
         ":test.bad2.com.android.hardware.wifi",
-        ":test.bad3.com.android.hardware.wifi",
     ],
 }
 
@@ -199,13 +200,14 @@ java_test_host {
         "frameworks-base-hostutils",
         "testng",
     ],
-    data: [
+    device_common_data: [
         ":VendorApexTestsApp",
         ":com.android.apex.vendor.foo",
         ":com.android.apex.vendor.foo",
         ":com.android.apex.vendor.foo.apex.all.ready",
         ":com.android.apex.vendor.foo.bootstrap",
         ":com.android.apex.vendor.foo.v1_with_service",
+        ":com.android.apex.vendor.bar",
     ],
     test_config: "vendor-apex-tests.xml",
     test_suites: [
@@ -230,6 +232,8 @@ android_test_helper_app {
         ":com.android.apex.vendor.foo.v2_with_requireNativeLibs",
         ":com.android.apex.vendor.foo.v2_with_service",
         ":com.android.apex.vendor.foo.v2_with_wrong_vndk_version",
+        ":com.android.apex.vendor.foo.with_vintf", // v2
+        ":com.android.apex.vendor.bar.v2_with_vintf",
     ],
     test_suites: [
         "general-tests",
@@ -242,7 +246,7 @@ java_test_host {
         "src/**/SharedLibsApexTest.java",
     ],
     libs: ["tradefed"],
-    java_resources: [
+    device_common_java_resources: [
         ":com.android.apex.test.bar_stripped.v1.libvX_prebuilt",
         ":com.android.apex.test.bar_stripped.v2.libvY_prebuilt",
         ":com.android.apex.test.bar.v1.libvX_prebuilt",
@@ -281,7 +285,7 @@ java_test_host {
     ],
     test_config: "apex_compression_platform_tests.xml",
     test_suites: ["general-tests"],
-    data: [
+    device_common_data: [
         ":com.android.apex.compressed.v1",
         ":com.android.apex.compressed.v1{.apex}",
         ":com.android.apex.compressed.v1_different_digest",
@@ -322,10 +326,10 @@ java_test_host {
     ],
     test_config: "apk-in-apex-tests.xml",
     test_suites: ["general-tests"],
-    data: [
+    device_common_data: [
         ":apex_apkinapex_tests_app",
     ],
-    java_resources: [
+    device_common_java_resources: [
         ":com.android.apex.product.test",
         ":com.android.apex.product.app.test.xml",
         ":com.android.apex.system.test",
@@ -368,11 +372,11 @@ java_test_host {
     ],
     test_config: "max-sdk-tests.xml",
     test_suites: ["general-tests"],
-    data: [
+    device_common_data: [
         ":apex_maxsdk_tests_app",
         ":apex_maxsdk_regular_app_tests",
     ],
-    java_resources: [
+    device_common_java_resources: [
         ":com.android.apex.maxsdk.test",
     ],
 }
diff --git a/tests/TEST_MAPPING b/tests/TEST_MAPPING
index 391ee898..759190f0 100644
--- a/tests/TEST_MAPPING
+++ b/tests/TEST_MAPPING
@@ -42,6 +42,9 @@
     },
     {
       "name": "VendorApexHostTestCases"
+    },
+    {
+      "name": "apexd_host_tests"
     }
   ],
   "imports": [
diff --git a/tests/app/src/com/android/tests/apex/app/VendorApexTests.java b/tests/app/src/com/android/tests/apex/app/VendorApexTests.java
index 3cd53cf8..aa473ed8 100644
--- a/tests/app/src/com/android/tests/apex/app/VendorApexTests.java
+++ b/tests/app/src/com/android/tests/apex/app/VendorApexTests.java
@@ -52,6 +52,7 @@ public class VendorApexTests {
     private static final String TAG = "VendorApexTests";
 
     private static final String APEX_PACKAGE_NAME = "com.android.apex.vendor.foo";
+    private static final String APEX_PACKAGE_NAME_BAR = "com.android.apex.vendor.bar";
     private static final TestApp Apex2Rebootless = new TestApp(
             "com.android.apex.vendor.foo.v2", APEX_PACKAGE_NAME, 2,
             /*isApex*/true, "com.android.apex.vendor.foo.v2.apex");
@@ -64,6 +65,12 @@ public class VendorApexTests {
     private static final TestApp Apex2WrongVndkVersion = new TestApp(
             "com.android.apex.vendor.foo.v2_with_wrong_vndk_version", APEX_PACKAGE_NAME, 2,
             /*isApex*/true, "com.android.apex.vendor.foo.v2_with_wrong_vndk_version.apex");
+    private static final TestApp ApexFooV2WithVintf = new TestApp(
+            "com.android.apex.vendor.foo.with_vintf", APEX_PACKAGE_NAME, 2,
+            /*isApex*/true, "com.android.apex.vendor.foo.with_vintf.apex");
+    private static final TestApp ApexBarV2WithVintf = new TestApp(
+            "com.android.apex.vendor.bar.v2_with_vintf", APEX_PACKAGE_NAME_BAR, 2,
+            /*isApex*/true, "com.android.apex.vendor.bar.v2_with_vintf.apex");
 
     /* parameter passed from host-side VendorApexTests: [vendor, odm] */
     private String mPartition;
@@ -72,6 +79,7 @@ public class VendorApexTests {
     public void setUp() {
         InstallUtils.dropShellPermissionIdentity();
         InstallUtils.adoptShellPermissionIdentity(
+                Manifest.permission.INSTALL_PACKAGES,
                 Manifest.permission.INSTALL_PACKAGE_UPDATES,
                 Manifest.permission.INSTALL_TEST_ONLY_PACKAGE);
         Bundle bundle = InstrumentationRegistry.getArguments();
@@ -156,6 +164,23 @@ public class VendorApexTests {
                 Install.single(Apex2WrongVndkVersion).setStaged());
     }
 
+    @Test
+    public void testCheckVintfWithAllStagedApexes_MultiPackage() throws Exception {
+        InstallUtils.commitExpectingFailure(
+                AssertionError.class,
+                "CheckVintf failed",
+                Install.multi(ApexFooV2WithVintf, ApexBarV2WithVintf).setStaged());
+    }
+
+    @Test
+    public void testCheckVintfWithAllStagedApexes_MultiSession() throws Exception {
+        Install.single(ApexFooV2WithVintf).setStaged().commit();
+        InstallUtils.commitExpectingFailure(
+                AssertionError.class,
+                "CheckVintf failed",
+                Install.single(ApexBarV2WithVintf).setStaged());
+    }
+
     private static void assertAwait(Supplier<Boolean> test, long millis, String failMessage)
             throws Exception {
         long start = System.currentTimeMillis();
diff --git a/tests/src/com/android/tests/apex/ApexdHostTest.java b/tests/src/com/android/tests/apex/ApexdHostTest.java
index 60184047..f4121469 100644
--- a/tests/src/com/android/tests/apex/ApexdHostTest.java
+++ b/tests/src/com/android/tests/apex/ApexdHostTest.java
@@ -122,36 +122,6 @@ public class ApexdHostTest extends BaseHostJUnit4Test  {
         }
     }
 
-    @Test
-    public void testRemountApex() throws Exception {
-        assumeTrue("Device does not support updating APEX", mHostUtils.isApexUpdateSupported());
-        assumeTrue("Device requires root", getDevice().isAdbRoot());
-        final File oldFile = getDevice().pullFile(SHIM_APEX_PATH);
-        try {
-            getDevice().remountSystemWritable();
-            // In case remount requires a reboot, wait for boot to complete.
-            getDevice().waitForBootComplete(Duration.ofMinutes(3).toMillis());
-            final File newFile = mHostUtils.getTestFile("com.android.apex.cts.shim.v2.apex");
-            // Stop framework
-            getDevice().executeShellV2Command("stop");
-            // Push new shim APEX. This simulates adb sync.
-            getDevice().pushFile(newFile, SHIM_APEX_PATH);
-            // Ask apexd to remount packages
-            getDevice().executeShellV2Command("cmd -w apexservice remountPackages");
-            // Start framework
-            getDevice().executeShellV2Command("start");
-            // Give enough time for system_server to boot.
-            Thread.sleep(Duration.ofSeconds(15).toMillis());
-            final Set<ITestDevice.ApexInfo> activeApexes = getDevice().getActiveApexes();
-            ITestDevice.ApexInfo testApex = new ITestDevice.ApexInfo(
-                    "com.android.apex.cts.shim", 2L);
-            assertThat(activeApexes).contains(testApex);
-        } finally {
-            getDevice().pushFile(oldFile, SHIM_APEX_PATH);
-            getDevice().reboot();
-        }
-    }
-
     @Test
     public void testApexWithoutPbIsNotActivated_ProductPartitionHasOlderVersion()
             throws Exception {
@@ -395,30 +365,6 @@ public class ApexdHostTest extends BaseHostJUnit4Test  {
         assertThat(error).contains("No device manifest");
     }
 
-    /**
-     * Test to verify that apexd will reject a vendor apex that tries to
-     *     update an unrelated hardware interface.  Staged installation.
-     */
-    @Test
-    public void testRejectsStagedApexThatUpdatesUnrelatedHardware() throws Exception {
-        assumeTrue("Device does not support updating APEX", mHostUtils.isApexUpdateSupported());
-        assumeTrue("Device requires root", getDevice().isAdbRoot());
-        assumeTrue("Device test requires wifi hardware",
-                getDevice().hasFeature("android.hardware.wifi"));
-        assumeTrue("Device test requires an active wifi apex",
-                deviceHasActiveApex("com.android.hardware.wifi"));
-
-        String apex_filename = "test.bad3.com.android.hardware.wifi.apex";
-
-        File apexFile = mHostUtils.getTestFile(apex_filename);
-
-        // Try to install it, we should get a manifest/matix compatibility error
-        String error = mHostUtils.installStagedPackage(apexFile);
-        assertThat(error).isNotNull();
-        assertThat(error).contains(
-                "Device manifest and framework compatibility matrix are incompatible");
-    }
-
     /**
      * Test to verify that apexd will accept a good vendor apex update
      *     Install method is immediate (rebootless) (non-staged) installation.
@@ -490,28 +436,4 @@ public class ApexdHostTest extends BaseHostJUnit4Test  {
         assertThat(error).isNotNull();
         assertThat(error).contains("No device manifest");
     }
-
-    /**
-     * Test to verify that apexd will reject a vendor apex tries to
-     *     update an unrelated hardware interface.
-     */
-    @Test
-    public void testRejectsRebootlessApexThatUpdatesUnrelatedHardware() throws Exception {
-        assumeTrue("Device does not support updating APEX", mHostUtils.isApexUpdateSupported());
-        assumeTrue("Device requires root", getDevice().isAdbRoot());
-        assumeTrue("Device test requires wifi hardware",
-                getDevice().hasFeature("android.hardware.wifi"));
-        assumeTrue("Device test requires an active wifi apex",
-                deviceHasActiveApex("com.android.hardware.wifi"));
-
-        String apex_filename = "test.bad3.com.android.hardware.wifi.apex";
-
-        File apexFile = mHostUtils.getTestFile(apex_filename);
-
-        // Try to install it, we should get a manifest/matix compatibility error
-        String error = mHostUtils.installRebootlessPackage(apexFile);
-        assertThat(error).isNotNull();
-        assertThat(error).contains(
-                "Device manifest and framework compatibility matrix are incompatible");
-    }
 }
diff --git a/tests/src/com/android/tests/apex/host/VendorApexTests.java b/tests/src/com/android/tests/apex/host/VendorApexTests.java
index 508230e8..5f951ca2 100644
--- a/tests/src/com/android/tests/apex/host/VendorApexTests.java
+++ b/tests/src/com/android/tests/apex/host/VendorApexTests.java
@@ -92,8 +92,8 @@ public class VendorApexTests extends BaseHostJUnit4Test {
 
     @After
     public void tearDown() throws Exception {
-        deleteFiles("/" + mPartition + "/apex/" + APEX_PACKAGE_NAME + "*apex",
-                "/data/apex/active/" + APEX_PACKAGE_NAME + "*apex");
+        deleteFiles("/" + mPartition + "/apex/com.android.apex.vendor.*apex",
+                "/data/apex/active/com.android.apex.vendor.*apex");
     }
 
     @Test
@@ -156,6 +156,32 @@ public class VendorApexTests extends BaseHostJUnit4Test {
             .isEqualTo(getMountNamespaceFor("$(pidof vold)"));
     }
 
+    @Test
+    @LargeTest
+    public void testCheckVintfWithAllStagedApexes_MultiPackage() throws Exception {
+        // CheckVintf should be invoked with all staged APEXes mounted.
+        // For example, two conflicting APEXes in a session may pass the check
+        // when CheckVintf is performed with a single incoming APEX separately.
+        // In this test, installing two conflicting APEXes in the same session should
+        // fail with CheckVintf error.
+        pushPreinstalledApex("com.android.apex.vendor.foo.apex",
+                "com.android.apex.vendor.bar.apex");
+        runPhase("testCheckVintfWithAllStagedApexes_MultiPackage");
+    }
+
+    @Test
+    @LargeTest
+    public void testCheckVintfWithAllStagedApexes_MultiSession() throws Exception {
+        // CheckVintf should be invoked with all staged APEXes mounted.
+        // For example, two conflicting APEXes in different sessions may pass the check
+        // when CheckVintf is performed for each session separately.
+        // In this test, installing two APEXes in two separate sessions should
+        // fail with CheckVintfError.
+        pushPreinstalledApex("com.android.apex.vendor.foo.apex",
+                "com.android.apex.vendor.bar.apex");
+        runPhase("testCheckVintfWithAllStagedApexes_MultiSession");
+    }
+
     private String getMountNamespaceFor(String proc) throws Exception {
         CommandResult result =
                 getDevice().executeShellV2Command("readlink /proc/" + proc + "/ns/mnt");
@@ -165,11 +191,14 @@ public class VendorApexTests extends BaseHostJUnit4Test {
         return result.getStdout().trim();
     }
 
-    private void pushPreinstalledApex(String fileName) throws Exception {
+    private void pushPreinstalledApex(String... fileNames) throws Exception {
+        assertThat(fileNames).isNotEmpty();
         CompatibilityBuildHelper buildHelper = new CompatibilityBuildHelper(getBuild());
-        final File apex = buildHelper.getTestFile(fileName);
-        Path path = Paths.get("/", mPartition, "apex", fileName);
-        assertTrue(getDevice().pushFile(apex, path.toString()));
+        for (String fileName : fileNames) {
+            final File apex = buildHelper.getTestFile(fileName);
+            Path path = Paths.get("/", mPartition, "apex", fileName);
+            assertTrue(getDevice().pushFile(apex, path.toString()));
+        }
         getDevice().reboot();
     }
 
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.bar/Android.bp
index 3fec14ba..9f1f1b67 100644
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/Android.bp
+++ b/tests/testdata/sharedlibs/build/com.android.apex.test.bar/Android.bp
@@ -45,6 +45,8 @@ apex {
             ],
         },
     },
+    // This test apex is used by shared_libs_repack, which works with only ext4.
+    payload_fs_type: "ext4",
 }
 
 cc_binary {
@@ -67,7 +69,7 @@ cc_binary {
     apex_available: ["com.android.apex.test.bar"],
 }
 
-genrule {
+java_genrule {
     name: "com.android.apex.test.bar_stripped",
     out: ["com.android.apex.test.bar_stripped.apex"],
     defaults: ["apexer_test_host_tools_list"],
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.baz/Android.bp
index b32a6b97..0af35523 100644
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/Android.bp
+++ b/tests/testdata/sharedlibs/build/com.android.apex.test.baz/Android.bp
@@ -37,6 +37,8 @@ apex {
         targets: ["sharedlibs_test"],
     },
     updatable: false,
+    // This test apex is used by shared_libs_repack, which works with only ext4.
+    payload_fs_type: "ext4",
 }
 
 cc_binary {
@@ -48,7 +50,7 @@ cc_binary {
     apex_available: ["com.android.apex.test.baz"],
 }
 
-genrule {
+java_genrule {
     name: "com.android.apex.test.baz_stripped",
     out: ["com.android.apex.test.baz_stripped.apex"],
     defaults: ["apexer_test_host_tools_list"],
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.foo/Android.bp
index 0c4e9522..368bee8c 100644
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/Android.bp
+++ b/tests/testdata/sharedlibs/build/com.android.apex.test.foo/Android.bp
@@ -37,6 +37,8 @@ apex {
         targets: ["sharedlibs_test"],
     },
     updatable: false,
+    // This test apex is used by shared_libs_repack, which works with only ext4.
+    payload_fs_type: "ext4",
 }
 
 cc_binary {
@@ -48,7 +50,7 @@ cc_binary {
     apex_available: ["com.android.apex.test.foo"],
 }
 
-genrule {
+java_genrule {
     name: "com.android.apex.test.foo_stripped",
     out: ["com.android.apex.test.foo_stripped.apex"],
     defaults: ["apexer_test_host_tools_list"],
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.pony/Android.bp
index 14b15ead..f20aee33 100644
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/Android.bp
+++ b/tests/testdata/sharedlibs/build/com.android.apex.test.pony/Android.bp
@@ -37,6 +37,8 @@ apex {
         targets: ["sharedlibs_test"],
     },
     updatable: false,
+    // This test apex is used by shared_libs_repack, which works with only ext4.
+    payload_fs_type: "ext4",
 }
 
 cc_binary {
@@ -48,7 +50,7 @@ cc_binary {
     apex_available: ["com.android.apex.test.pony"],
 }
 
-genrule {
+java_genrule {
     name: "com.android.apex.test.pony_stripped",
     out: ["com.android.apex.test.pony_stripped.apex"],
     defaults: ["apexer_test_host_tools_list"],
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/Android.bp
index efea81f6..183cbeb3 100644
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/Android.bp
+++ b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/Android.bp
@@ -43,9 +43,11 @@ apex {
             ],
         },
     },
+    // This test apex is used by shared_libs_repack, which works with only ext4.
+    payload_fs_type: "ext4",
 }
 
-genrule {
+java_genrule {
     name: "com.android.apex.test.sharedlibs_generated",
     out: ["com.android.apex.test.sharedlibs_generated.apex"],
     defaults: ["apexer_test_host_tools_list"],
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/Android.bp
index 0098a334..d8f59614 100644
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/Android.bp
+++ b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/Android.bp
@@ -35,9 +35,11 @@ apex {
     // We want to force libc++.so to be available in this stub APEX, so put an empty binary.
     binaries: ["noop"],
     updatable: false,
+    // This test apex is used by shared_libs_repack, which works with only ext4.
+    payload_fs_type: "ext4",
 }
 
-genrule {
+java_genrule {
     name: "com.android.apex.test.sharedlibs_secondary_generated",
     out: ["com.android.apex.test.sharedlibs_secondary_generated.apex"],
     defaults: ["apexer_test_host_tools_list"],
diff --git a/tests/testdata/vendorapex/Android.bp b/tests/testdata/vendorapex/Android.bp
index 6ac7bff4..c3bee5cd 100644
--- a/tests/testdata/vendorapex/Android.bp
+++ b/tests/testdata/vendorapex/Android.bp
@@ -45,6 +45,14 @@ apex_test {
     ],
 }
 
+apex_test {
+    name: "com.android.apex.vendor.bar",
+    defaults: [
+        "com.android.apex.vendor.foo.defaults",
+    ],
+    manifest: "manifest_bar_v1.json",
+}
+
 apex_test {
     name: "com.android.apex.vendor.foo.v2",
     defaults: [
@@ -62,6 +70,9 @@ apex_test {
     binaries: [
         "apex_vendor_foo_test_binary",
     ],
+    skip_validations: {
+        apex_sepolicy_tests: true, // we don't have a valid label for the test binary
+    },
 }
 
 cc_binary {
@@ -112,9 +123,9 @@ prebuilt_etc {
 }
 
 prebuilt_etc {
-    name: "apex_vendor_foo_v2_vintf",
+    name: "apex_vendor_foo_v2.xml",
     src: "apex_vendor_foo_v2.xml",
-    relative_install_path: "vintf",
+    sub_dir: "vintf",
     installable: false,
 }
 
@@ -173,7 +184,19 @@ apex_test {
     ],
     prebuilts: [
         "apex_vendor_foo_v2.rc",
-        "apex_vendor_foo_v2_vintf",
+        "apex_vendor_foo_v2.xml",
+    ],
+}
+
+// Test apex conflicting with com.android.apex.vendor.foo.v2_with_vintf
+apex_test {
+    name: "com.android.apex.vendor.bar.v2_with_vintf",
+    defaults: [
+        "com.android.apex.vendor.foo.defaults",
+    ],
+    manifest: "manifest_bar_v2.json",
+    prebuilts: [
+        "apex_vendor_foo_v2.xml",
     ],
 }
 
@@ -225,31 +248,6 @@ prebuilt_etc {
     sub_dir: "vintf",
 }
 
-// Creates wifi test apex that is updating interface for other hardware
-//    (picked an HAL that exists elsewhere, and for hardware that has
-//     updatable-via-apex="true", and still gets caught - good!)
-apex_test {
-    name: "test.bad3.com.android.hardware.wifi",
-    manifest: "wifi_manifest_rebootless.json",
-    key: "com.android.hardware.key",
-    certificate: ":com.android.hardware.certificate",
-    file_contexts: "wifi_file_contexts",
-    updatable: false,
-    soc_specific: true,
-    installable: false,
-    prebuilts: [
-        "vintf_fragment_wifi_bad3.xml",
-        "com.android.hardware.wifi.rc",
-    ],
-}
-
-prebuilt_etc {
-    name: "vintf_fragment_wifi_bad3.xml",
-    src: "vintf_fragment_wifi_bad3.xml",
-    installable: false,
-    sub_dir: "vintf",
-}
-
 // Test apex for updating com.android.hardware.wifi, with a
 //    good apex
 apex_test {
diff --git a/tests/testdata/vendorapex/manifest_bar_v1.json b/tests/testdata/vendorapex/manifest_bar_v1.json
new file mode 100644
index 00000000..259b6824
--- /dev/null
+++ b/tests/testdata/vendorapex/manifest_bar_v1.json
@@ -0,0 +1,4 @@
+{
+    "name": "com.android.apex.vendor.bar",
+    "version": 1
+}
diff --git a/tests/testdata/vendorapex/manifest_bar_v2.json b/tests/testdata/vendorapex/manifest_bar_v2.json
new file mode 100644
index 00000000..93f4cd86
--- /dev/null
+++ b/tests/testdata/vendorapex/manifest_bar_v2.json
@@ -0,0 +1,4 @@
+{
+    "name": "com.android.apex.vendor.bar",
+    "version": 2
+}
diff --git a/tests/testdata/vendorapex/vintf_fragment_wifi_bad3.xml b/tests/testdata/vendorapex/vintf_fragment_wifi_bad3.xml
deleted file mode 100644
index 1a5a1bac..00000000
--- a/tests/testdata/vendorapex/vintf_fragment_wifi_bad3.xml
+++ /dev/null
@@ -1,16 +0,0 @@
-<!--
-This file is a copy of hardware/interfaces/wifi/1.6/default/android.hardware.wifi@1.0-service.xml,
-modified to have a different valid interface name, but which is not related to the wifi hal interface.
-Attempts to install a vendor apex that includes this file as a vintf fragment should fail.
--->
-<manifest version="1.0" type="device">
-    <hal format="hidl">
-        <name>android.hardware.wifi</name>
-        <transport>hwbinder</transport>
-        <version>1.6</version>
-        <interface>
-            <name>ICameraProvider</name>
-            <instance>default</instance>
-        </interface>
-    </hal>
-</manifest>
diff --git a/tests/vts/Android.bp b/tests/vts/Android.bp
new file mode 100644
index 00000000..9d33d564
--- /dev/null
+++ b/tests/vts/Android.bp
@@ -0,0 +1,37 @@
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_test {
+    name: "vts_apex_test",
+    srcs: [
+        "VtsApexTest.cpp",
+    ],
+    shared_libs: [
+        "libbase",
+        "liblog",
+    ],
+    static_libs: [
+        "libapex",
+    ],
+    test_suites: [
+        "general-tests",
+        "vts",
+    ],
+    require_root: true,
+    auto_gen_config: true,
+}
diff --git a/tests/vts/VtsApexTest.cpp b/tests/vts/VtsApexTest.cpp
new file mode 100644
index 00000000..86566533
--- /dev/null
+++ b/tests/vts/VtsApexTest.cpp
@@ -0,0 +1,65 @@
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
+#define LOG_TAG "VtsApexTest"
+
+#include <android-base/file.h>
+#include <fcntl.h>
+#include <gtest/gtest.h>
+
+#include <filesystem>
+
+#include "apex_constants.h"
+
+using android::base::unique_fd;
+
+namespace android::apex {
+
+static void ForEachPreinstalledApex(auto fn) {
+  namespace fs = std::filesystem;
+  std::error_code ec;
+  for (const auto &dir : kApexPackageBuiltinDirs) {
+    if (!fs::exists(dir, ec)) {
+      if (ec) {
+        FAIL() << "Can't to access " << dir << ": " << ec.message();
+      }
+      continue;
+    }
+    auto it = fs::directory_iterator(dir, ec);
+    auto end = fs::directory_iterator();
+    for (; !ec && it != end; it.increment(ec)) {
+      fs::path path = *it;
+      if (path.extension() != kApexPackageSuffix) {
+        continue;
+      }
+      fn(path);
+    }
+    if (ec) {
+      FAIL() << "Can't read " << dir << ": " << ec.message();
+    }
+  }
+}
+
+// Preinstalled APEX files (.apex) should be okay when opening with O_DIRECT
+TEST(VtsApexTest, OpenPreinstalledApex) {
+  ForEachPreinstalledApex([](auto path) {
+    unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECT));
+    ASSERT_NE(fd.get(), -1)
+        << "Can't open an APEX file " << path << ": " << strerror(errno);
+  });
+}
+
+}  // namespace android::apex
diff --git a/tools/Android.bp b/tools/Android.bp
index 7acf7ebf..6975698c 100644
--- a/tools/Android.bp
+++ b/tools/Android.bp
@@ -81,12 +81,14 @@ python_test_host {
     ],
     data: [
         ":avbtool",
-        ":com.android.example.apex",
         ":conv_apex_manifest",
         ":apex_compression_tool",
         ":deapexer",
         ":soong_zip",
     ],
+    device_common_data: [
+        ":com.android.example.apex",
+    ],
     libs: [
         "apex_manifest_proto",
     ],
@@ -134,7 +136,6 @@ sh_test_host {
     data_libs: [
         "libbase",
         "libc++",
-        "libcgrouprc",
         "libcrypto",
         "libcutils",
         "liblog",
@@ -180,9 +181,11 @@ python_test_host {
     data: [
         ":apexer_test_host_tools",
         ":apexer_with_DCLA_preprocessing",
-        ":com.android.example.apex",
         "testdata/com.android.example.apex.pem",
     ],
+    device_common_data: [
+        ":com.android.example.apex",
+    ],
     test_suites: ["general-tests"],
     test_options: {
         unit_test: true,
diff --git a/tools/apexer_with_DCLA_preprocessing_test.py b/tools/apexer_with_DCLA_preprocessing_test.py
index 1396cf52..5b41c92b 100644
--- a/tools/apexer_with_DCLA_preprocessing_test.py
+++ b/tools/apexer_with_DCLA_preprocessing_test.py
@@ -22,7 +22,7 @@ import shutil
 import stat
 import subprocess
 import tempfile
-from typing import List, BinaryIO
+from typing import List
 import unittest
 import zipfile
 
@@ -91,15 +91,15 @@ class ApexerWithDCLAPreprocessingTest(unittest.TestCase):
     self._to_cleanup.append(tmp_dir)
     return tmp_dir
 
-  def expand_apex(self, apex_file: str | BinaryIO) -> None:
+  def expand_apex(self, apex_file) -> None:
     """expand an apex file include apex_payload."""
     apex_dir = self.create_temp_dir()
     with zipfile.ZipFile(apex_file, 'r') as apex_zip:
       apex_zip.extractall(apex_dir)
-    payload_img = os.path.join(apex_dir, 'apex_payload.img')
     extract_dir = os.path.join(apex_dir, 'payload_extract')
-    os.mkdir(extract_dir)
-    run_command([self.debugfs_static, payload_img, '-R', f'rdump / {extract_dir}'])
+    run_command([self.deapexer, '--debugfs_path', self.debugfs_static,
+                 '--fsckerofs_path', self.fsck_erofs,
+                 'extract', apex_file, extract_dir])
 
     # remove /etc and /lost+found and /payload_extract/apex_manifest.pb
     lost_and_found = os.path.join(extract_dir, 'lost+found')
@@ -132,13 +132,15 @@ class ApexerWithDCLAPreprocessingTest(unittest.TestCase):
     self.apexer_tool_path = os.path.join(host_tools_dir, 'bin')
     self.apexer_wrapper = apexer_wrapper
     self.key_file = key_file
+    self.deapexer = os.path.join(host_tools_dir, 'bin/deapexer')
     self.debugfs_static = os.path.join(host_tools_dir, 'bin/debugfs_static')
+    self.fsck_erofs = os.path.join(host_tools_dir, 'bin/fsck.erofs')
     self.android_jar = os.path.join(host_tools_dir, 'bin/android.jar')
     self.apexer = os.path.join(host_tools_dir, 'bin/apexer')
     os.chmod(apexer_wrapper, stat.S_IRUSR | stat.S_IXUSR);
     for i in ['apexer', 'deapexer', 'avbtool', 'mke2fs', 'sefcontext_compile', 'e2fsdroid',
       'resize2fs', 'soong_zip', 'aapt2', 'merge_zips', 'zipalign', 'debugfs_static',
-      'signapk.jar', 'android.jar']:
+      'signapk.jar', 'android.jar', 'fsck.erofs']:
       file_path = os.path.join(host_tools_dir, 'bin', i)
       if os.path.exists(file_path):
         os.chmod(file_path, stat.S_IRUSR | stat.S_IXUSR);
@@ -146,8 +148,12 @@ class ApexerWithDCLAPreprocessingTest(unittest.TestCase):
 
   def test_DCLA_preprocessing(self):
     """test DCLA preprocessing done properly."""
-    with resources().joinpath(TEST_APEX + '.apex').open(mode='rb') as apex_file:
-      apex_dir = self.expand_apex(apex_file)
+    with resources().joinpath(TEST_APEX + '.apex').open(mode='rb') as apex_file_obj:
+      tmp_dir = self.create_temp_dir()
+      apex_file = os.path.join(tmp_dir, TEST_APEX + '.apex')
+      with open(apex_file, 'wb') as f:
+        shutil.copyfileobj(apex_file_obj, f)
+    apex_dir = self.expand_apex(apex_file)
 
     # create apex canned_fs_config file, TEST_APEX does not come with one
     canned_fs_config_file = os.path.join(apex_dir, 'canned_fs_config')
diff --git a/tools/deapexer.py b/tools/deapexer.py
index e547ad90..ade5945e 100755
--- a/tools/deapexer.py
+++ b/tools/deapexer.py
@@ -27,6 +27,7 @@ import argparse
 import apex_manifest
 import enum
 import os
+import re
 import shutil
 import sys
 import subprocess
@@ -46,17 +47,17 @@ FS_TYPES = [
 def RetrieveFileSystemType(file):
   """Returns filesystem type with magic"""
   with open(file, 'rb') as f:
-    for type, offset, magic in FS_TYPES:
+    for fs_type, offset, magic in FS_TYPES:
       buf = bytearray(len(magic))
       f.seek(offset, os.SEEK_SET)
       f.readinto(buf)
       if buf == magic:
-        return type
+        return fs_type
   raise ValueError('Failed to retrieve filesystem type')
 
 class ApexImageEntry(object):
-
-  def __init__(self, name, base_dir, permissions, size, ino, extents,
+  """Represents an entry in APEX payload"""
+  def __init__(self, name, *, base_dir, permissions, size, ino, extents,
                is_directory, is_symlink, security_context):
     self._name = name
     self._base_dir = base_dir
@@ -67,6 +68,7 @@ class ApexImageEntry(object):
     self._ino = ino
     self._extents = extents
     self._security_context = security_context
+    self._entries = []
 
   @property
   def name(self):
@@ -109,6 +111,10 @@ class ApexImageEntry(object):
   def ino(self):
     return self._ino
 
+  @property
+  def entries(self):
+    return self._entries
+
   @property
   def extents(self):
     return self._extents
@@ -126,39 +132,21 @@ class ApexImageEntry(object):
     else:
       ret += '-'
 
-    def mask_as_string(m):
+    def MaskAsString(m):
       ret = 'r' if m & 4 == 4 else '-'
       ret += 'w' if m & 2 == 2 else '-'
       ret += 'x' if m & 1 == 1 else '-'
       return ret
 
-    ret += mask_as_string(self._permissions >> 6)
-    ret += mask_as_string((self._permissions >> 3) & 7)
-    ret += mask_as_string(self._permissions & 7)
+    ret += MaskAsString(self._permissions >> 6)
+    ret += MaskAsString((self._permissions >> 3) & 7)
+    ret += MaskAsString(self._permissions & 7)
 
     return ret + ' ' + self._size + ' ' + self._name
 
 
-class ApexImageDirectory(object):
-
-  def __init__(self, path, entries, apex):
-    self._path = path
-    self._entries = sorted(entries, key=lambda e: e.name)
-    self._apex = apex
-
-  def list(self, is_recursive=False):
-    for e in self._entries:
-      yield e
-      if e.is_directory and e.name != '.' and e.name != '..':
-        for ce in self.enter_subdir(e).list(is_recursive):
-          yield ce
-
-  def enter_subdir(self, entry):
-    return self._apex._list(self._path + entry.name + '/')
-
-
 class Apex(object):
-
+  """Represents an APEX file"""
   def __init__(self, args):
     self._debugfs = args.debugfs_path
     self._fsckerofs = args.fsckerofs_path
@@ -167,7 +155,6 @@ class Apex(object):
     with zipfile.ZipFile(self._apex, 'r') as zip_ref:
       self._payload = zip_ref.extract('apex_payload.img', path=self._tempdir)
     self._payload_fs_type = RetrieveFileSystemType(self._payload)
-    self._cache = {}
 
   def __del__(self):
     shutil.rmtree(self._tempdir)
@@ -175,21 +162,22 @@ class Apex(object):
   def __enter__(self):
     return self
 
-  def __exit__(self, type, value, traceback):
+  def __exit__(self, ex_type, value, traceback):
     pass
 
-  def list(self, is_recursive=False):
+  def list(self):
     if self._payload_fs_type not in ['ext4']:
-      sys.exit(f"{self._payload_fs_type} is not supported for `list`.")
+      sys.exit(f'{self._payload_fs_type} is not supported for `list`.')
+
+    yield from self.entries()
 
-    root = self._list('./')
-    return root.list(is_recursive)
+  def read_dir(self, path) -> ApexImageEntry:
+    assert path.endswith('/')
+    assert self.payload_fs_type == 'ext4'
 
-  def _list(self, path):
-    if path in self._cache:
-      return self._cache[path]
-    res = subprocess.check_output([self._debugfs, '-R', 'ls -l -p %s' % path, self._payload],
+    res = subprocess.check_output([self._debugfs, '-R', f'ls -l -p {path}', self._payload],
                                   text=True, stderr=subprocess.DEVNULL)
+    dir_entry = None
     entries = []
     for line in res.split('\n'):
       if not line:
@@ -200,6 +188,10 @@ class Apex(object):
       name = parts[5]
       if not name:
         continue
+      if name == '..':
+        continue
+      if name == 'lost+found' and path == './':
+        continue
       ino = parts[1]
       bits = parts[2]
       size = parts[6]
@@ -208,7 +200,7 @@ class Apex(object):
       is_directory=bits[1]=='4'
 
       if not is_symlink and not is_directory:
-        stdout = subprocess.check_output([self._debugfs, '-R', 'dump_extents <%s>' % ino,
+        stdout = subprocess.check_output([self._debugfs, '-R', f'dump_extents <{ino}>',
                                           self._payload], text=True, stderr=subprocess.DEVNULL)
         # Output of dump_extents for an inode fragmented in 3 blocks (length and addresses represent
         # block-sized sections):
@@ -226,9 +218,9 @@ class Apex(object):
             length = min(int(tokens[-1]) * BLOCK_SIZE, left_length)
             left_length -= length
             extents.append((offset, length))
-          if (left_length != 0): # dump_extents sometimes fails to display "hole" blocks
+          if left_length != 0: # dump_extents sometimes fails to display "hole" blocks
             raise ValueError
-        except:
+        except: # pylint: disable=bare-except
           extents = [] # [] means that we failed to retrieve the file location successfully
 
       # get 'security.selinux' attribute
@@ -241,49 +233,101 @@ class Apex(object):
       ], text=True, stderr=subprocess.DEVNULL)
       security_context = stdout.rstrip('\n\x00')
 
-      entries.append(ApexImageEntry(name,
-                                    base_dir=path,
-                                    permissions=int(bits[3:], 8),
-                                    size=size,
-                                    is_directory=is_directory,
-                                    is_symlink=is_symlink,
-                                    ino=ino,
-                                    extents=extents,
-                                    security_context=security_context))
-
-    return ApexImageDirectory(path, entries, self)
+      entry = ApexImageEntry(name,
+                             base_dir=path,
+                             permissions=int(bits[3:], 8),
+                             size=size,
+                             is_directory=is_directory,
+                             is_symlink=is_symlink,
+                             ino=ino,
+                             extents=extents,
+                             security_context=security_context)
+      if name == '.':
+        dir_entry = entry
+      elif is_directory:
+        sub_dir_entry = self.read_dir(path + name + '/')
+        # sub_dir_entry should be the same inode
+        assert entry.ino == sub_dir_entry.ino
+        entry.entries.extend(sub_dir_entry.entries)
+        entries.append(entry)
+      else:
+        entries.append(entry)
+
+    assert dir_entry
+    dir_entry.entries.extend(sorted(entries, key=lambda e: e.name))
+    return dir_entry
 
   def extract(self, dest):
+    """Recursively dumps contents of the payload with retaining mode bits, but not owner/group"""
     if self._payload_fs_type == 'erofs':
-      subprocess.run([self._fsckerofs, '--extract=%s' % (dest), '--overwrite', self._payload],
-                     stdout=subprocess.DEVNULL, check=True)
+      subprocess.run([self._fsckerofs, f'--extract={dest}', '--overwrite',
+                     '--no-preserve-owner', self._payload], stdout=subprocess.DEVNULL, check=True)
     elif self._payload_fs_type == 'ext4':
-      # Suppress stderr without failure
-      try:
-        subprocess.run([self._debugfs, '-R', 'rdump ./ %s' % (dest), self._payload],
-                       capture_output=True, check=True)
-      except subprocess.CalledProcessError as e:
-        sys.exit(e.stderr)
+      # Extract entries one by one using `dump` because `rdump` doesn't support
+      # "no-perserve" mode
+      for entry in self.entries():
+        self.write_entry(entry, dest)
     else:
       # TODO(b/279688635) f2fs is not supported yet.
-      sys.exit(f"{self._payload_fs_type} is not supported for `extract`.")
+      sys.exit(f'{self._payload_fs_type} is not supported for `extract`.')
+
+  @property
+  def payload_fs_type(self) -> str:
+    return self._payload_fs_type
+
+  def entries(self):
+    """Generator to visit all entries in the payload starting from root(./)"""
+
+    def TopDown(entry):
+      yield entry
+      for child in entry.entries:
+        yield from TopDown(child)
+
+    root = self.read_dir('./')
+    yield from TopDown(root)
+
+  def read_symlink(self, entry):
+    assert entry.is_symlink
+    assert self.payload_fs_type == 'ext4'
+
+    stdout = subprocess.check_output([self._debugfs, '-R', f'stat {entry.full_path}',
+                                      self._payload], text=True, stderr=subprocess.DEVNULL)
+    # Output of stat for a symlink should have the following line:
+    #   Fast link dest: \"%.*s\"
+    m = re.search(r'\bFast link dest: \"(.+)\"\n', stdout)
+    if not m:
+      sys.exit('failed to read symlink target')
+    return m.group(1)
+
+  def write_entry(self, entry, out_dir):
+    dest = os.path.normpath(os.path.join(out_dir, entry.full_path))
+    if entry.is_directory:
+      if not os.path.exists(dest):
+        os.makedirs(dest, mode=0o755)
+    elif entry.is_symlink:
+      os.symlink(self.read_symlink(entry), dest)
+    else:
+      subprocess.check_output([self._debugfs, '-R', f'dump {entry.full_path} {dest}',
+        self._payload], text=True, stderr=subprocess.DEVNULL)
+      # retain mode bits
+      os.chmod(dest, entry.permissions)
 
 
 def RunList(args):
   if GetType(args.apex) == ApexType.COMPRESSED:
     with tempfile.TemporaryDirectory() as temp:
       decompressed_apex = os.path.join(temp, 'temp.apex')
-      decompress(args.apex, decompressed_apex)
+      Decompress(args.apex, decompressed_apex)
       args.apex = decompressed_apex
 
       RunList(args)
       return
 
   with Apex(args) as apex:
-    for e in apex.list(is_recursive=True):
+    for e in apex.list():
       # dot(., ..) directories
       if not e.root and e.name in ('.', '..'):
-          continue
+        continue
       res = ''
       if args.size:
         res += e.size + ' '
@@ -298,8 +342,8 @@ def RunList(args):
 def RunExtract(args):
   if GetType(args.apex) == ApexType.COMPRESSED:
     with tempfile.TemporaryDirectory() as temp:
-      decompressed_apex = os.path.join(temp, "temp.apex")
-      decompress(args.apex, decompressed_apex)
+      decompressed_apex = os.path.join(temp, 'temp.apex')
+      Decompress(args.apex, decompressed_apex)
       args.apex = decompressed_apex
 
       RunExtract(args)
@@ -309,8 +353,8 @@ def RunExtract(args):
     if not os.path.exists(args.dest):
       os.makedirs(args.dest, mode=0o755)
     apex.extract(args.dest)
-    if os.path.isdir(os.path.join(args.dest, "lost+found")):
-      shutil.rmtree(os.path.join(args.dest, "lost+found"))
+    if os.path.isdir(os.path.join(args.dest, 'lost+found')):
+      shutil.rmtree(os.path.join(args.dest, 'lost+found'))
 
 class ApexType(enum.Enum):
   INVALID = 0
@@ -339,6 +383,8 @@ def RunInfo(args):
       print(args.apex + ' is not a valid apex')
       sys.exit(1)
     print(res.name)
+  elif args.print_payload_type:
+    print(Apex(args).payload_fs_type)
   else:
     manifest = apex_manifest.fromApex(args.apex)
     print(apex_manifest.toJsonString(manifest))
@@ -361,9 +407,10 @@ def RunDecompress(args):
 
   compressed_apex_fp = args.input
   decompressed_apex_fp = args.output
-  return decompress(compressed_apex_fp, decompressed_apex_fp)
+  return Decompress(compressed_apex_fp, decompressed_apex_fp)
 
-def decompress(compressed_apex_fp, decompressed_apex_fp):
+
+def Decompress(compressed_apex_fp, decompressed_apex_fp):
   if os.path.exists(decompressed_apex_fp):
     print("Output path '" + decompressed_apex_fp + "' already exists")
     sys.exit(1)
@@ -387,19 +434,24 @@ def main(argv):
   debugfs_default = None
   fsckerofs_default = None
   if 'ANDROID_HOST_OUT' in os.environ:
-    debugfs_default = '%s/bin/debugfs_static' % os.environ['ANDROID_HOST_OUT']
-    fsckerofs_default = '%s/bin/fsck.erofs' % os.environ['ANDROID_HOST_OUT']
-  parser.add_argument('--debugfs_path', help='The path to debugfs binary', default=debugfs_default)
-  parser.add_argument('--fsckerofs_path', help='The path to fsck.erofs binary', default=fsckerofs_default)
+    debugfs_default = os.path.join(os.environ['ANDROID_HOST_OUT'], 'bin/debugfs_static')
+    fsckerofs_default = os.path.join(os.environ['ANDROID_HOST_OUT'], 'bin/fsck.erofs')
+  parser.add_argument(
+      '--debugfs_path', help='The path to debugfs binary', default=debugfs_default)
+  parser.add_argument(
+      '--fsckerofs_path', help='The path to fsck.erofs binary', default=fsckerofs_default)
   # TODO(b/279858383) remove the argument
   parser.add_argument('--blkid_path', help='NOT USED')
 
   subparsers = parser.add_subparsers(required=True, dest='cmd')
 
-  parser_list = subparsers.add_parser('list', help='prints content of an APEX to stdout')
+  parser_list = subparsers.add_parser(
+      'list', help='prints content of an APEX to stdout')
   parser_list.add_argument('apex', type=str, help='APEX file')
-  parser_list.add_argument('--size', help='also show the size of the files', action="store_true")
-  parser_list.add_argument('--extents', help='also show the location of the files', action="store_true")
+  parser_list.add_argument(
+      '--size', help='also show the size of the files', action='store_true')
+  parser_list.add_argument(
+      '--extents', help='also show the location of the files', action='store_true')
   parser_list.add_argument('-Z', '--contexts',
                            help='also show the security context of the files',
                            action='store_true')
@@ -416,6 +468,9 @@ def main(argv):
   parser_info.add_argument('--print-type',
                            help='Prints type of the apex (COMPRESSED or UNCOMPRESSED)',
                            action='store_true')
+  parser_info.add_argument('--print-payload-type',
+                           help='Prints filesystem type of the apex payload',
+                           action='store_true')
   parser_info.set_defaults(func=RunInfo)
 
   # Handle sub-command "decompress"
diff --git a/tools/host_apex_verifier.cc b/tools/host_apex_verifier.cc
index 2cd670c9..1c6704ca 100644
--- a/tools/host_apex_verifier.cc
+++ b/tools/host_apex_verifier.cc
@@ -56,7 +56,10 @@ namespace {
 static const std::vector<std::string> partitions = {"system", "system_ext",
                                                     "product", "vendor", "odm"};
 
-void PrintUsage() {
+void PrintUsage(const std::string& msg = "") {
+  if (msg != "") {
+    std::cerr << "Error: " << msg << "\n";
+  }
   printf(R"(usage: host_apex_verifier [options]
 
 Tests APEX file(s) for correctness.
@@ -76,21 +79,44 @@ for checking all APEXes:
 
 for checking a single APEX:
   --apex=PATH                 Path to the target APEX.
+  --partition_tag=[system|vendor|...] Partition for the target APEX.
 )");
 }
 
+// Use this for better error message when unavailable keyword is used.
+class NotAvailableParser : public init::SectionParser {
+ public:
+  NotAvailableParser(const std::string& keyword) : keyword_(keyword) {}
+  base::Result<void> ParseSection(std::vector<std::string>&&,
+                                  const std::string&, int) override {
+    return base::Error() << "'" << keyword_ << "' is not available.";
+  }
+
+ private:
+  std::string keyword_;
+};
+
 // Validate any init rc files inside the APEX.
 void CheckInitRc(const std::string& apex_dir, const ApexManifest& manifest,
-                 int sdk_version) {
+                 int sdk_version, bool is_vendor) {
   init::Parser parser;
+  if (is_vendor) {
+    init::InitializeHostSubcontext({apex_dir});
+  }
   init::ServiceList service_list = init::ServiceList();
-  parser.AddSectionParser(
-      "service", std::make_unique<init::ServiceParser>(&service_list, nullptr));
+  parser.AddSectionParser("service", std::make_unique<init::ServiceParser>(
+                                         &service_list, init::GetSubcontext()));
   const init::BuiltinFunctionMap& function_map = init::GetBuiltinFunctionMap();
   init::Action::set_function_map(&function_map);
   init::ActionManager action_manager = init::ActionManager();
-  parser.AddSectionParser(
-      "on", std::make_unique<init::ActionParser>(&action_manager, nullptr));
+  if (is_vendor) {
+    parser.AddSectionParser("on", std::make_unique<init::ActionParser>(
+                                      &action_manager, init::GetSubcontext()));
+  } else {
+    // "on" keyword is not available in non-vendor APEXes.
+    parser.AddSectionParser("on", std::make_unique<NotAvailableParser>("on"));
+  }
+
   std::string init_dir_path = apex_dir + "/etc";
   std::vector<std::string> init_configs;
   std::unique_ptr<DIR, decltype(&closedir)> init_dir(
@@ -132,7 +158,7 @@ void CheckInitRc(const std::string& apex_dir, const ApexManifest& manifest,
 
 // Extract and validate a single APEX.
 void ScanApex(const std::string& deapexer, int sdk_version,
-              const std::string& apex_path) {
+              const std::string& apex_path, const std::string& partition_tag) {
   LOG(INFO) << "Checking APEX " << apex_path;
 
   auto apex = OR_FATAL(ApexFile::Open(apex_path));
@@ -147,8 +173,8 @@ void ScanApex(const std::string& deapexer, int sdk_version,
     LOG(FATAL) << "Error running deapexer command \"" << deapexer_command
                << "\": " << code;
   }
-
-  CheckInitRc(extracted_apex_dir, manifest, sdk_version);
+  bool is_vendor = partition_tag == "vendor" || partition_tag == "odm";
+  CheckInitRc(extracted_apex_dir, manifest, sdk_version, is_vendor);
 }
 
 // Scan the factory APEX files in the partition apex dir.
@@ -160,8 +186,10 @@ void ScanApex(const std::string& deapexer, int sdk_version,
 //   - Extracted target_files archives which may not contain
 //     flattened <PARTITON>/apex/ directories.
 void ScanPartitionApexes(const std::string& deapexer, int sdk_version,
-                         const std::string& partition_dir) {
-  LOG(INFO) << "Scanning partition factory APEX dir " << partition_dir;
+                         const std::string& partition_dir,
+                         const std::string& partition_tag) {
+  LOG(INFO) << "Scanning " << partition_dir << " for factory APEXes in "
+            << partition_tag;
 
   std::unique_ptr<DIR, decltype(&closedir)> apex_dir(
       opendir(partition_dir.c_str()), closedir);
@@ -174,7 +202,8 @@ void ScanPartitionApexes(const std::string& deapexer, int sdk_version,
   while ((entry = readdir(apex_dir.get()))) {
     if (base::EndsWith(entry->d_name, ".apex") ||
         base::EndsWith(entry->d_name, ".capex")) {
-      ScanApex(deapexer, sdk_version, partition_dir + "/" + entry->d_name);
+      ScanApex(deapexer, sdk_version, partition_dir + "/" + entry->d_name,
+               partition_tag);
     }
   }
 }
@@ -196,6 +225,7 @@ int main(int argc, char** argv) {
   int sdk_version = INT_MAX;
   std::map<std::string, std::string> partition_map;
   std::string apex;
+  std::string partition_tag;
 
   while (true) {
     static const struct option long_options[] = {
@@ -210,6 +240,7 @@ int main(int argc, char** argv) {
         {"out_vendor", required_argument, nullptr, 0},
         {"out_odm", required_argument, nullptr, 0},
         {"apex", required_argument, nullptr, 0},
+        {"partition_tag", required_argument, nullptr, 0},
         {nullptr, 0, nullptr, 0},
     };
 
@@ -241,6 +272,9 @@ int main(int argc, char** argv) {
         if (name == "apex") {
           apex = optarg;
         }
+        if (name == "partition_tag") {
+          partition_tag = optarg;
+        }
         for (const auto& p : partitions) {
           if (name == "out_" + p) {
             partition_map[p] = optarg;
@@ -272,16 +306,25 @@ int main(int argc, char** argv) {
   deapexer += " --fsckerofs_path " + fsckerofs;
 
   if (!!apex.empty() + !!partition_map.empty() != 1) {
-    PrintUsage();
+    PrintUsage("use either --apex or --out_<partition>.\n");
     return EXIT_FAILURE;
   }
+  if (!apex.empty()) {
+    if (std::find(partitions.begin(), partitions.end(), partition_tag) ==
+        partitions.end()) {
+      PrintUsage(
+          "--apex should come with "
+          "--partition_tag=[system|system_ext|product|vendor|odm].\n");
+      return EXIT_FAILURE;
+    }
+  }
 
   if (!partition_map.empty()) {
-    for (const auto& p : partition_map) {
-      ScanPartitionApexes(deapexer, sdk_version, p.second);
+    for (const auto& [partition, dir] : partition_map) {
+      ScanPartitionApexes(deapexer, sdk_version, dir, partition);
     }
   } else {
-    ScanApex(deapexer, sdk_version, apex);
+    ScanApex(deapexer, sdk_version, apex, partition_tag);
   }
   return EXIT_SUCCESS;
 }
```

