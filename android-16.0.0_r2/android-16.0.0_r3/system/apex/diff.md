```diff
diff --git a/apexd/Android.bp b/apexd/Android.bp
index 12bbfb32..4a30bb78 100644
--- a/apexd/Android.bp
+++ b/apexd/Android.bp
@@ -18,6 +18,7 @@ tidy_errors = [
     "bugprone-undelegated-constructor",
     // "bugprone-unhandled-self-assignment", // found in apex_manifest.proto
     "bugprone-unused-raii",
+    "bugprone-use-after-move",
     "cert-err34-c",
     "google-default-arguments",
     // "google-explicit-constructor", // found in com_android_apex.h
@@ -87,8 +88,10 @@ cc_defaults {
     ],
     static_libs: [
         "lib_apex_blocklist_proto",
+        "lib_apex_image_list_proto",
         "lib_microdroid_metadata_proto",
         "libapex",
+        "libapexd_flags",
         "libavb",
         "libdm",
         "libext2_uuid",
@@ -138,16 +141,12 @@ cc_binary {
     srcs: [
         "apexd_main.cpp",
     ],
-    shared_libs: [
-        "server_configurable_flags",
-        "apexd_flags_c_lib",
-    ],
     static_libs: [
         "libapex",
-        "libapexd",
         "libapexd_checkpoint_vold",
-        "libapexservice",
         "libapexd_metrics_stats",
+        "libapexd",
+        "libapexservice",
     ],
     init_rc: ["apexd.rc"],
     // Just like the init, apexd should be able to run without
@@ -285,7 +284,6 @@ cc_library_static {
         "apex_manifest.cpp",
         "apex_sha.cpp",
         "apex_shim.cpp",
-        "apexd_verity.cpp",
     ],
     host_supported: true,
     target: {
@@ -500,7 +498,6 @@ cc_test {
         ":apex.apexd_test_nocode",
         ":apex.apexd_test_v2",
         ":apex.corrupted_b146895998",
-        ":apex.banned_name",
         ":gen_key_mismatch_apex",
         ":gen_key_mismatch_apex_v2",
         ":gen_key_mismatch_capex",
@@ -521,7 +518,6 @@ cc_test {
         ":com.android.apex.cts.shim.v2_additional_folder_prebuilt",
         ":com.android.apex.cts.shim.v2_with_pre_install_hook_prebuilt",
         ":com.android.apex.cts.shim.v2_with_post_install_hook_prebuilt",
-        ":com.android.apex.compressed_sharedlibs",
         ":com.android.apex.compressed.v1",
         ":com.android.apex.compressed.v1_different_digest",
         ":com.android.apex.compressed.v1_different_digest_original",
@@ -536,17 +532,13 @@ cc_test {
         "apexd_testdata/com.android.apex.brand.new.renamed.avbpubkey",
         "apexd_testdata/blocklist.json",
         "apexd_testdata/blocklist_invalid.json",
-        ":com.android.apex.test.sharedlibs_generated.v1.libvX_prebuilt",
-        ":com.android.apex.test.sharedlibs_generated.v2.libvY_prebuilt",
         ":test.rebootless_apex_v1",
         ":test.rebootless_apex_v2",
         ":test.rebootless_apex_service_v1",
         ":test.rebootless_apex_service_v2",
         ":gen_manifest_mismatch_rebootless_apex",
         ":gen_corrupt_rebootless_apex",
-        ":test.rebootless_apex_provides_sharedlibs",
         ":test.rebootless_apex_provides_native_libs",
-        ":test.rebootless_apex_requires_shared_apex_libs",
         ":test.rebootless_apex_jni_libs",
         ":test.rebootless_apex_add_native_lib",
         ":test.rebootless_apex_remove_native_lib",
@@ -564,6 +556,7 @@ cc_test {
         "apex_manifest_test.cpp",
         "apexd_brand_new_verifier_test.cpp",
         "apexd_image_manager_test.cpp",
+        "apexd_loop_test.cpp",
         "apexd_test.cpp",
         "apexd_session_test.cpp",
         "apexd_utils_test.cpp",
@@ -608,7 +601,6 @@ cc_test {
         ":apex.apexd_test_nocode",
         ":apex.apexd_test_v2",
         ":apex.corrupted_b146895998",
-        ":apex.banned_name",
         ":gen_key_mismatch_apex",
         ":gen_key_mismatch_apex_v2",
         ":gen_key_mismatch_capex",
@@ -626,7 +618,6 @@ cc_test {
         ":com.android.apex.cts.shim.v2_additional_folder_prebuilt",
         ":com.android.apex.cts.shim.v2_with_pre_install_hook_prebuilt",
         ":com.android.apex.cts.shim.v2_with_post_install_hook_prebuilt",
-        ":com.android.apex.compressed_sharedlibs",
         ":com.android.apex.compressed.v1",
         ":com.android.apex.compressed.v1_different_digest",
         ":com.android.apex.compressed.v1_different_digest_original",
@@ -636,17 +627,13 @@ cc_test {
         ":gen_manifest_mismatch_compressed_apex_v2",
         "apexd_testdata/com.android.apex.test_package.avbpubkey",
         "apexd_testdata/com.android.apex.compressed.avbpubkey",
-        ":com.android.apex.test.sharedlibs_generated.v1.libvX_prebuilt",
-        ":com.android.apex.test.sharedlibs_generated.v2.libvY_prebuilt",
         ":test.rebootless_apex_v1",
         ":test.rebootless_apex_v2",
         ":test.rebootless_apex_service_v1",
         ":test.rebootless_apex_service_v2",
         ":gen_manifest_mismatch_rebootless_apex",
         ":gen_corrupt_rebootless_apex",
-        ":test.rebootless_apex_provides_sharedlibs",
         ":test.rebootless_apex_provides_native_libs",
-        ":test.rebootless_apex_requires_shared_apex_libs",
         ":test.rebootless_apex_jni_libs",
         ":test.rebootless_apex_add_native_lib",
         ":test.rebootless_apex_remove_native_lib",
@@ -675,6 +662,28 @@ cc_test {
     test_config: "ApexServiceTestCases.xml",
 }
 
+cc_benchmark {
+    name: "ApexBenchmark",
+    defaults: [
+        "apex_flags_defaults",
+        "libapex-deps",
+        "libapexd-deps",
+    ],
+    srcs: [
+        "apexd_benchmark.cpp",
+    ],
+    static_libs: [
+        "libapex",
+        "libapexd",
+    ],
+    shared_libs: [
+        "libfs_mgr",
+        "libutils",
+    ],
+    test_suites: ["general-tests"],
+    require_root: true,
+}
+
 xsd_config {
     name: "apex-info-list",
     srcs: ["ApexInfoList.xsd"],
@@ -703,7 +712,6 @@ cc_defaults {
         "liblog",
     ],
     static_libs: [
-        "android.os.statsbootstrap_aidl-cpp",
         "libstatsbootstrap",
     ],
 }
@@ -754,6 +762,6 @@ aconfig_declarations {
 }
 
 cc_aconfig_library {
-    name: "apexd_flags_c_lib",
+    name: "libapexd_flags",
     aconfig_declarations: "apexd_flags",
 }
diff --git a/apexd/apex_constants.h b/apexd/apex_constants.h
index 0cecee8c..561851b6 100644
--- a/apexd/apex_constants.h
+++ b/apexd/apex_constants.h
@@ -33,6 +33,7 @@ static constexpr const char* kApexBackupDir = "/data/apex/backup";
 static constexpr const char* kApexDecompressedDir = "/data/apex/decompressed";
 static constexpr const char* kOtaReservedDir = "/data/apex/ota_reserved";
 static constexpr const char* kMetadataImagesDir = "/metadata/apex/images";
+static constexpr const char* kMetadataConfigDir = "/metadata/apex/config";
 static constexpr const char* kDataImagesDir = "/data/apex/images";
 static constexpr const char* kApexPackageSystemDir = "/system/apex";
 static constexpr const char* kApexPackageSystemExtDir = "/system_ext/apex";
@@ -54,7 +55,6 @@ static constexpr const char* kApexRoot = "/apex";
 static constexpr const char* kStagedSessionsDir = "/data/app-staging";
 
 static constexpr const char* kApexDataSubDir = "apexdata";
-static constexpr const char* kApexSharedLibsSubDir = "sharedlibs";
 static constexpr const char* kApexSnapshotSubDir = "apexrollback";
 static constexpr const char* kPreRestoreSuffix = "-prerestore";
 
@@ -68,6 +68,9 @@ static constexpr const char* kDecompressedApexPackageSuffix =
     ".decompressed.apex";
 static constexpr const char* kOtaApexPackageSuffix = ".ota.apex";
 
+static constexpr const char* kDmLinearApexSuffix = ".apex";
+static constexpr const char* kDmLinearPayloadSuffix = ".payload";
+
 static constexpr const char* kManifestFilenameJson = "apex_manifest.json";
 static constexpr const char* kManifestFilenamePb = "apex_manifest.pb";
 
@@ -79,14 +82,13 @@ static constexpr const char* kApexStatusStarting = "starting";
 static constexpr const char* kApexStatusActivated = "activated";
 static constexpr const char* kApexStatusReady = "ready";
 
-static constexpr const char* kMultiApexSelectPersistPrefix =
-    "persist.vendor.apex.";
-static constexpr const char* kMultiApexSelectBootconfigPrefix =
+static constexpr const char* kApexSelectPersistPrefix = "persist.vendor.apex.";
+static constexpr const char* kApexSelectBootconfigPrefix =
     "ro.boot.vendor.apex.";
-static const std::vector<std::string> kMultiApexSelectPrefix = {
+static const std::vector<std::string> kApexSelectPrefix = {
     // Check persist props first, to allow users to override bootconfig.
-    kMultiApexSelectPersistPrefix,
-    kMultiApexSelectBootconfigPrefix,
+    kApexSelectPersistPrefix,
+    kApexSelectBootconfigPrefix,
 };
 
 static constexpr const char* kVmPayloadMetadataPartitionProp =
@@ -111,7 +113,7 @@ static constexpr const char* kBrandNewApexConfigVendorDir =
 static constexpr const char* kBrandNewApexConfigOdmDir =
     "/odm/etc/brand_new_apex";
 static const std::unordered_map<ApexPartition, std::string>
-    kPartitionToBrandNewApexConfigDirs = {
+    kBrandNewApexConfigDirs = {
         {ApexPartition::System, kBrandNewApexConfigSystemDir},
         {ApexPartition::SystemExt, kBrandNewApexConfigSystemExtDir},
         {ApexPartition::Product, kBrandNewApexConfigProductDir},
@@ -119,10 +121,5 @@ static const std::unordered_map<ApexPartition, std::string>
         {ApexPartition::Odm, kBrandNewApexConfigOdmDir},
 };
 
-// Banned APEX names
-static const std::unordered_set<std::string> kBannedApexName = {
-    kApexSharedLibsSubDir,  // To avoid conflicts with predefined
-                            // /apex/sharedlibs directory
-};
 }  // namespace apex
 }  // namespace android
diff --git a/apexd/apex_database.cpp b/apexd/apex_database.cpp
index bee8fc6f..e1b4e029 100644
--- a/apexd/apex_database.cpp
+++ b/apexd/apex_database.cpp
@@ -15,16 +15,13 @@
  */
 
 #include "apex_database.h"
-#include "apex_constants.h"
-#include "apex_file.h"
-#include "apexd_utils.h"
-#include "string_log.h"
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/parseint.h>
 #include <android-base/result.h>
 #include <android-base/strings.h>
+#include <libdm/dm.h>
 
 #include <filesystem>
 #include <fstream>
@@ -32,6 +29,11 @@
 #include <unordered_map>
 #include <utility>
 
+#include "apex_constants.h"
+#include "apex_file.h"
+#include "apexd_utils.h"
+#include "string_log.h"
+
 using android::base::ConsumeSuffix;
 using android::base::EndsWith;
 using android::base::ErrnoError;
@@ -42,6 +44,7 @@ using android::base::Result;
 using android::base::Split;
 using android::base::StartsWith;
 using android::base::Trim;
+using android::dm::DeviceMapper;
 
 namespace fs = std::filesystem;
 
@@ -130,29 +133,35 @@ bool IsTempMountPoint(const std::string& mount_point) {
   return EndsWith(mount_point, ".tmp");
 }
 
-Result<void> PopulateLoopInfo(const BlockDevice& top_device,
-                              const std::vector<std::string>& data_dirs,
-                              MountedApexData* apex_data) {
+Result<BlockDevice> GetUnderlying(const BlockDevice& top_device) {
   std::vector<BlockDevice> slaves = top_device.GetSlaves();
   if (slaves.size() != 1) {
     return Error() << "dm device " << top_device.DevPath()
                    << " has unexpected number of slaves (should be 1) : "
                    << slaves.size();
   }
-  if (slaves[0].GetType() != LoopDevice) {
-    return Error() << slaves[0].DevPath() << " is not a loop device";
+  return std::move(slaves[0]);
+}
+
+static Result<void> ValidateDm(const std::string& device_name,
+                               const std::string& expected_type) {
+  auto& dm = DeviceMapper::Instance();
+  std::vector<DeviceMapper::TargetInfo> table;
+  if (!dm.GetTableInfo(device_name, &table)) {
+    return Error() << "Could not read device-mapper table for DM device: "
+                   << device_name;
   }
-  std::string backing_file =
-      OR_RETURN(slaves[0].GetProperty("loop/backing_file"));
-  bool is_data_loop_device = std::any_of(
-      data_dirs.begin(), data_dirs.end(),
-      [&](const std::string& dir) { return StartsWith(backing_file, dir); });
-  if (!is_data_loop_device) {
-    return Error() << "Data loop device " << slaves[0].DevPath()
-                   << " has unexpected backing file " << backing_file;
+  if (table.size() != 1) {
+    return Error() << "Unexpected table info(size=" << table.size()
+                   << ", expected=1) for DM device: " << device_name;
+  }
+  const auto& entry = table[0].spec;
+  auto target_type = DeviceMapper::GetTargetType(entry);
+  if (expected_type != target_type) {
+    return Error() << "Unexpected table type (" << target_type
+                   << ") for DM device: " << device_name
+                   << " (expected: " << expected_type << ")";
   }
-  apex_data->loop_name = slaves[0].DevPath();
-  apex_data->full_path = backing_file;
   return {};
 }
 
@@ -178,60 +187,70 @@ void NormalizeIfDeleted(MountedApexData* apex_data) {
 Result<MountedApexData> ResolveMountInfo(
     const BlockDevice& block, const std::string& mount_point,
     const std::vector<std::string>& data_dirs) {
+  MountedApexData result;
+  result.mount_point = mount_point;
+
   // Now, see if it is dm-verity or loop mounted
   switch (block.GetType()) {
     case LoopDevice: {
-      auto backing_file = block.GetProperty("loop/backing_file");
-      if (!backing_file.ok()) {
-        return backing_file.error();
-      }
-      MountedApexData result;
       result.loop_name = block.DevPath();
-      result.full_path = *backing_file;
-      result.mount_point = mount_point;
-      NormalizeIfDeleted(&result);
-      return result;
-    }
+      result.full_path = OR_RETURN(block.GetProperty("loop/backing_file"));
+    } break;
     case DeviceMapperDevice: {
-      auto name = block.GetProperty("dm/name");
-      if (!name.ok()) {
-        return name.error();
-      }
-      MountedApexData result;
-      result.mount_point = mount_point;
-      result.device_name = *name;
-      auto status = PopulateLoopInfo(block, data_dirs, &result);
-      if (!status.ok()) {
-        return status.error();
+      result.verity_name = OR_RETURN(block.GetProperty("dm/name"));
+      OR_RETURN(ValidateDm(result.verity_name, "verity"));
+      auto underlying = OR_RETURN(GetUnderlying(block));
+      switch (underlying.GetType()) {
+        case LoopDevice: {
+          result.loop_name = underlying.DevPath();
+          result.full_path =
+              OR_RETURN(underlying.GetProperty("loop/backing_file"));
+        } break;
+        case DeviceMapperDevice: {
+          result.linear_name = OR_RETURN(underlying.GetProperty("dm/name"));
+          OR_RETURN(ValidateDm(result.linear_name, "linear"));
+          result.full_path = OR_RETURN(GetUnderlying(underlying)).DevPath();
+        } break;
+        default:
+          return Error() << "Unknown underlying device type for dm-verity:"
+                         << underlying.DevPath();
       }
-      NormalizeIfDeleted(&result);
-      return result;
-    }
+    } break;
     case UnknownDevice: {
       return Errorf("Can't resolve {}", block.DevPath().string());
     }
   }
+
+  // Check if a mount with dm-verity + loop is backed by a data apex
+  if (!result.verity_name.empty() && !result.loop_name.empty()) {
+    bool is_data_loop_device = std::any_of(
+        data_dirs.begin(), data_dirs.end(), [&](const std::string& dir) {
+          return StartsWith(result.full_path, dir);
+        });
+    if (!is_data_loop_device) {
+      return Error() << "Data loop device " << result.loop_name
+                     << " has unexpected backing file " << result.full_path;
+    }
+  }
+
+  NormalizeIfDeleted(&result);
+  return result;
 }
 
 }  // namespace
 
 // On startup, APEX database is populated from /proc/mounts.
-
+//
 // /apex/<package-id> can be mounted from
 // - /dev/block/loopX : loop device
 // - /dev/block/dm-X : dm-verity
-
+//
 // In case of loop device, the original APEX file can be tracked
 // by /sys/block/loopX/loop/backing_file.
-
-// In case of dm-verity, it is mapped to a loop device.
-// This mapped loop device can be traced by
-// /sys/block/dm-X/slaves/ directory which contains
-// a symlink to /sys/block/loopY, which leads to
-// the original APEX file.
-// Device name can be retrieved from
-// /sys/block/dm-Y/dm/name.
-
+//
+// In case of dm-verity, its underlying block device can be
+// either a loop device or a dm-linear device.
+//
 // Need to read /proc/mounts on startup since apexd can start
 // at any time (It's a lazy service).
 void MountedApexDatabase::PopulateFromMounts(
@@ -263,13 +282,11 @@ void MountedApexDatabase::PopulateFromMounts(
 
     auto [package, version] = ParseMountPoint(mount_point);
     mount_data->version = version;
-    AddMountedApexLocked(package, *mount_data);
-
     LOG(INFO) << "Found " << mount_point << " backed by"
               << (mount_data->deleted ? " deleted " : " ") << "file "
               << mount_data->full_path;
+    AddMountedApexLocked(package, std::move(*mount_data));
   }
-
   LOG(INFO) << mounted_apexes_.size() << " packages restored.";
 }
 
diff --git a/apexd/apex_database.h b/apexd/apex_database.h
index c963a38c..c6eadcff 100644
--- a/apexd/apex_database.h
+++ b/apexd/apex_database.h
@@ -36,24 +36,27 @@ class MountedApexDatabase {
   // Stores associated low-level data for a mounted APEX. To conserve memory,
   // the APEX file isn't stored, but must be opened to retrieve specific data.
   struct MountedApexData {
-    int version = 0;        // APEX version for this mount
-    std::string loop_name;  // Loop device used (fs path).
-    std::string full_path;  // Full path to the apex file.
-    std::string mount_point;  // Path this apex is mounted on.
-    std::string device_name;  // Name of the dm verity device.
+    int64_t version = 0;      // APEX version for this mount
+    std::string loop_name;    // Loop device used (fs path)
+    std::string full_path;    // Full path to the apex file
+    std::string mount_point;  // Path this apex is mounted on
+    std::string verity_name;  // Name of the dm-verity device
+    std::string linear_name;  // Name of the dm-linear device
     // Whenever apex file specified in full_path was deleted.
     bool deleted = false;
 
     MountedApexData() = default;
-    MountedApexData(int version, const std::string& loop_name,
+    MountedApexData(int64_t version, const std::string& loop_name,
                     const std::string& full_path,
                     const std::string& mount_point,
-                    const std::string& device_name)
+                    const std::string& verity_name,
+                    const std::string& linear_name)
         : version(version),
           loop_name(loop_name),
           full_path(full_path),
           mount_point(mount_point),
-          device_name(device_name),
+          verity_name(verity_name),
+          linear_name(linear_name),
           deleted(false) {}
 
     inline auto operator<=>(const MountedApexData& rhs) const = default;
diff --git a/apexd/apex_database_test.cpp b/apexd/apex_database_test.cpp
index 682810f3..c4f4cbd3 100644
--- a/apexd/apex_database_test.cpp
+++ b/apexd/apex_database_test.cpp
@@ -70,15 +70,13 @@ bool ContainsPackage(const MountedApexDatabase& db, const std::string& package,
 
 TEST(ApexDatabaseTest, AddRemovedMountedApex) {
   constexpr const char* kPackage = "package";
-  constexpr const char* kLoopName = "loop";
   constexpr const char* kPath = "path";
-  constexpr const char* kMountPoint = "mount";
-  constexpr const char* kDeviceName = "dev";
 
   MountedApexDatabase db;
   ASSERT_EQ(CountPackages(db), 0u);
 
-  MountedApexData data(0, kLoopName, kPath, kMountPoint, kDeviceName);
+  MountedApexData data;
+  data.full_path = kPath;
   db.AddMountedApex(kPackage, data);
   ASSERT_TRUE(Contains(db, kPackage, data));
   ASSERT_TRUE(ContainsPackage(db, kPackage, data));
@@ -102,7 +100,7 @@ TEST(ApexDatabaseTest, MountMultiple) {
   MountedApexData data[arraysize(kPackage)];
   for (size_t i = 0; i < arraysize(kPackage); ++i) {
     data[i] = MountedApexData(0, kLoopName[i], kPath[i], kMountPoint[i],
-                              kDeviceName[i]);
+                              kDeviceName[i], "");
     db.AddMountedApex(kPackage[i], data[i]);
   }
 
@@ -131,28 +129,34 @@ TEST(ApexDatabaseTest, DoIfLatest) {
   MountedApexDatabase db;
 
   // With apex: [{version=0,path=path}]
-  db.AddMountedApex("package", 0, "loop", "path", "mount", "dev");
+  MountedApexData apex;
+  apex.version = 0;
+  apex.full_path = "path";
+  db.AddMountedApex("package", apex);
+  // Check if path is the latest
   ASSERT_THAT(db.DoIfLatest("package", "path", returnError),
               HasError(WithMessage("expected")));
 
   // With apexes: [{version=0,path=path}, {version=5,path=path5}]
-  db.AddMountedApex("package", 5, "loop5", "path5", "mount5", "dev5");
+  MountedApexData apex5;
+  apex5.version = 5;
+  apex5.full_path = "path5";
+  db.AddMountedApex("package", apex5);
+  // Check if path is NOT the latest
   ASSERT_THAT(db.DoIfLatest("package", "path", returnError), Ok());
+  // Check if path5 is the latest
   ASSERT_THAT(db.DoIfLatest("package", "path5", returnError),
               HasError(WithMessage("expected")));
 }
 
 TEST(ApexDatabaseTest, GetLatestMountedApex) {
   constexpr const char* kPackage = "package";
-  constexpr const char* kLoopName = "loop";
-  constexpr const char* kPath = "path";
-  constexpr const char* kMountPoint = "mount";
-  constexpr const char* kDeviceName = "dev";
 
   MountedApexDatabase db;
   ASSERT_EQ(CountPackages(db), 0u);
 
-  MountedApexData data(0, kLoopName, kPath, kMountPoint, kDeviceName);
+  MountedApexData data;
+  data.version = 42;
   db.AddMountedApex(kPackage, data);
 
   auto ret = db.GetLatestMountedApex(kPackage);
diff --git a/apexd/apex_file.cpp b/apexd/apex_file.cpp
index 1ca6cfeb..c5e29634 100644
--- a/apexd/apex_file.cpp
+++ b/apexd/apex_file.cpp
@@ -34,7 +34,6 @@
 
 #include "apex_constants.h"
 #include "apexd_utils.h"
-#include "apexd_verity.h"
 
 using android::base::borrowed_fd;
 using android::base::ErrnoError;
@@ -161,10 +160,6 @@ Result<ApexFile> ApexFile::Open(const std::string& path) {
     return manifest.error();
   }
 
-  if (is_compressed && manifest->providesharedapexlibs()) {
-    return Error() << "Apex providing sharedlibs shouldn't be compressed";
-  }
-
   // b/179211712 the stored path should be the realpath, otherwise the path we
   // get by scanning the directory would be different from the path we get
   // by reading /proc/mounts, if the apex file is on a symlink dir.
@@ -173,8 +168,9 @@ Result<ApexFile> ApexFile::Open(const std::string& path) {
     return ErrnoError() << "can't get realpath of " << path;
   }
 
-  return ApexFile(realpath, image_offset, image_size, std::move(*manifest),
-                  pubkey, fs_type, is_compressed);
+  return ApexFile(std::move(realpath), image_offset, image_size,
+                  std::move(*manifest), std::move(pubkey), std::move(fs_type),
+                  is_compressed);
 }
 
 // AVB-related code.
@@ -454,5 +450,15 @@ Result<void> ApexFile::Decompress(const std::string& dest_path) const {
   return {};
 }
 
+std::string BytesToHex(const uint8_t* bytes, size_t bytes_len) {
+  std::ostringstream s;
+
+  s << std::hex << std::setfill('0');
+  for (size_t i = 0; i < bytes_len; i++) {
+    s << std::setw(2) << static_cast<int>(bytes[i]);
+  }
+  return s.str();
+}
+
 }  // namespace apex
 }  // namespace android
diff --git a/apexd/apex_file.h b/apexd/apex_file.h
index 86d032b1..4f78554c 100644
--- a/apexd/apex_file.h
+++ b/apexd/apex_file.h
@@ -17,13 +17,13 @@
 #ifndef ANDROID_APEXD_APEX_FILE_H_
 #define ANDROID_APEXD_APEX_FILE_H_
 
+#include <android-base/result.h>
+#include <libavb/libavb.h>
+
 #include <memory>
 #include <string>
 #include <vector>
 
-#include <android-base/result.h>
-#include <libavb/libavb.h>
-
 #include "apex_manifest.h"
 
 namespace android {
@@ -63,17 +63,16 @@ class ApexFile {
   android::base::Result<void> Decompress(const std::string& output_path) const;
 
  private:
-  ApexFile(const std::string& apex_path,
-           const std::optional<uint32_t>& image_offset,
+  ApexFile(std::string&& apex_path, const std::optional<uint32_t>& image_offset,
            const std::optional<size_t>& image_size,
-           ::apex::proto::ApexManifest manifest, const std::string& apex_pubkey,
-           const std::optional<std::string>& fs_type, bool is_compressed)
-      : apex_path_(apex_path),
+           ::apex::proto::ApexManifest&& manifest, std::string&& apex_pubkey,
+           std::optional<std::string>&& fs_type, bool is_compressed)
+      : apex_path_(std::move(apex_path)),
         image_offset_(image_offset),
         image_size_(image_size),
         manifest_(std::move(manifest)),
-        apex_pubkey_(apex_pubkey),
-        fs_type_(fs_type),
+        apex_pubkey_(std::move(apex_pubkey)),
+        fs_type_(std::move(fs_type)),
         is_compressed_(is_compressed) {}
 
   std::string apex_path_;
@@ -85,6 +84,8 @@ class ApexFile {
   bool is_compressed_;
 };
 
+std::string BytesToHex(const uint8_t* bytes, size_t len);
+
 }  // namespace apex
 }  // namespace android
 
diff --git a/apexd/apex_file_repository.cpp b/apexd/apex_file_repository.cpp
index b6c8d5d3..ec77f2dd 100644
--- a/apexd/apex_file_repository.cpp
+++ b/apexd/apex_file_repository.cpp
@@ -36,7 +36,6 @@
 #include "apexd_brand_new_verifier.h"
 #include "apexd_utils.h"
 #include "apexd_vendor_apex.h"
-#include "apexd_verity.h"
 
 using android::base::EndsWith;
 using android::base::Error;
@@ -47,6 +46,7 @@ using ::apex::proto::ApexBlocklist;
 namespace android {
 namespace apex {
 
+namespace {
 std::string ConsumeApexPackageSuffix(const std::string& path) {
   std::string_view path_view(path);
   android::base::ConsumeSuffix(&path_view, kApexPackageSuffix);
@@ -64,21 +64,22 @@ std::string GetApexSelectFilenameFromProp(
   }
   return "";
 }
+}  // namespace
 
 void ApexFileRepository::StorePreInstalledApex(ApexFile&& apex_file,
                                                ApexPartition partition) {
   const std::string& name = apex_file.GetManifest().name();
 
-  // Check if this APEX name is treated as a multi-install APEX.
+  // Check if this APEX name is selected or not.
   //
   // Note: apexd is a oneshot service which runs at boot, but can be
   // restarted when needed (such as staging an APEX update). If a
-  // multi-install select property changes between boot and when apexd
+  // APEX select property changes between boot and when apexd
   // restarts, the LOG messages below will report the version that will be
   // activated on next reboot, which may differ from the currently-active
   // version.
   std::string select_filename =
-      GetApexSelectFilenameFromProp(multi_install_select_prop_prefixes_, name);
+      GetApexSelectFilenameFromProp(apex_select_prop_prefixes_, name);
   if (!select_filename.empty()) {
     std::string path;
     if (!android::base::Realpath(apex_file.GetPath(), &path)) {
@@ -86,10 +87,9 @@ void ApexFileRepository::StorePreInstalledApex(ApexFile&& apex_file,
                  << apex_file.GetPath();
       return;
     }
-    if (enforce_multi_install_partition_ &&
-        partition != ApexPartition::Vendor && partition != ApexPartition::Odm) {
-      LOG(ERROR) << "Multi-install APEX " << path
-                 << " can only be preinstalled on /{odm,vendor}/apex/.";
+    if (partition != ApexPartition::Vendor && partition != ApexPartition::Odm) {
+      LOG(ERROR) << "APEX-select property is supported on /{odm,vendor}/apex/ :"
+                 << path;
       return;
     }
 
@@ -108,23 +108,19 @@ void ApexFileRepository::StorePreInstalledApex(ApexFile&& apex_file,
       return;
     }
 
-    if (ConsumeApexPackageSuffix(android::base::Basename(path)) ==
+    if (select_filename == "none") {
+      LOG(INFO) << "Skipping APEX at path " << apex_file.GetPath()
+                << " because it's disabled via sysprop.";
+      return;
+    }
+
+    if (ConsumeApexPackageSuffix(android::base::Basename(path)) !=
         select_filename) {
-      LOG(INFO) << "Found APEX at path " << path << " for multi-install APEX "
-                << name;
-      // A copy is needed because apex_file is moved here
-      const std::string apex_name = name;
-      // Add the APEX file to the store if its filename matches the
-      // property.
-      pre_installed_store_.emplace(apex_name, std::move(apex_file));
-      partition_store_.emplace(apex_name, partition);
-    } else {
       LOG(INFO) << "Skipping APEX at path " << path
                 << " because it does not match expected multi-install"
                 << " APEX property for " << name;
+      return;
     }
-
-    return;
   }
 
   auto it = pre_installed_store_.find(name);
@@ -239,31 +235,11 @@ android::base::Result<void> ApexFileRepository::AddPreInstalledApex(
   auto all_apex_paths =
       OR_RETURN(CollectPreInstalledApex(partition_to_prebuilt_dirs));
 
-  for (const auto& apex_path : all_apex_paths) {
-    Result<ApexFile> apex_file = ApexFile::Open(apex_path.path);
-    if (!apex_file.ok()) {
-      return Error() << "Failed to open " << apex_path.path << " : "
-                     << apex_file.error();
-    }
-
-    StorePreInstalledApex(std::move(*apex_file), apex_path.partition);
-  }
-  multi_install_public_keys_.clear();
-  return {};
-}
-
-android::base::Result<void> ApexFileRepository::AddPreInstalledApexParallel(
-    const std::unordered_map<ApexPartition, std::string>&
-        partition_to_prebuilt_dirs) {
-  auto all_apex_paths =
-      OR_RETURN(CollectPreInstalledApex(partition_to_prebuilt_dirs));
-
   auto apex_file_and_partition = OR_RETURN(OpenApexFiles(all_apex_paths));
 
   for (auto&& [apex_file, partition] : apex_file_and_partition) {
     StorePreInstalledApex(std::move(apex_file), partition);
   }
-  multi_install_public_keys_.clear();
   return {};
 }
 
@@ -404,8 +380,6 @@ Result<int> ApexFileRepository::AddBlockApex(
   return {ret};
 }
 
-// TODO(b/179497746): AddDataApex should not concern with filtering out invalid
-//   apex.
 Result<void> ApexFileRepository::AddDataApex(const std::string& data_dir) {
   LOG(INFO) << "Scanning " << data_dir << " for data ApexFiles";
   if (access(data_dir.c_str(), F_OK) != 0 && errno == ENOENT) {
@@ -420,6 +394,8 @@ Result<void> ApexFileRepository::AddDataApex(const std::string& data_dir) {
   }
 
   // TODO(b/179248390): scan parallelly if possible
+  std::vector<ApexFile> apex_files;
+  apex_files.reserve(active_apex->size());
   for (const auto& file : *active_apex) {
     LOG(INFO) << "Found updated apex " << file;
     Result<ApexFile> apex_file = ApexFile::Open(file);
@@ -427,20 +403,37 @@ Result<void> ApexFileRepository::AddDataApex(const std::string& data_dir) {
       LOG(ERROR) << "Failed to open " << file << " : " << apex_file.error();
       continue;
     }
+    apex_files.push_back(std::move(*apex_file));
+  }
 
-    const std::string& name = apex_file->GetManifest().name();
+  AddDataApexFiles(std::move(apex_files));
+  return {};
+}
+
+void ApexFileRepository::AddDataApexFiles(std::vector<ApexFile>&& apex_files) {
+  for (auto& apex_file : apex_files) {
+    const std::string& file = apex_file.GetPath();
+    const std::string& name = apex_file.GetManifest().name();
     auto preinstalled = pre_installed_store_.find(name);
     if (preinstalled != pre_installed_store_.end()) {
       if (preinstalled->second.GetBundledPublicKey() !=
-          apex_file->GetBundledPublicKey()) {
+          apex_file.GetBundledPublicKey()) {
         // Ignore data apex if public key doesn't match with pre-installed apex
         LOG(ERROR) << "Skipping " << file
                    << " : public key doesn't match pre-installed one";
         continue;
       }
+      if (preinstalled->second.GetManifest().version() >
+          apex_file.GetManifest().version()) {
+        LOG(ERROR) << "Skipping " << file << " : version("
+                   << apex_file.GetManifest().version()
+                   << ") is lower than pre-installed one("
+                   << preinstalled->second.GetManifest().version() << ")";
+        continue;
+      }
     } else if (ApexFileRepository::IsBrandNewApexEnabled()) {
       auto verified_partition =
-          VerifyBrandNewPackageAgainstPreinstalled(*apex_file);
+          VerifyBrandNewPackageAgainstPreinstalled(apex_file);
       if (!verified_partition.ok()) {
         LOG(ERROR) << "Skipping " << file << " : "
                    << verified_partition.error();
@@ -454,37 +447,35 @@ Result<void> ApexFileRepository::AddDataApex(const std::string& data_dir) {
       continue;
     }
 
-    std::string select_filename = GetApexSelectFilenameFromProp(
-        multi_install_select_prop_prefixes_, name);
-    if (!select_filename.empty()) {
-      LOG(WARNING) << "APEX " << name << " is a multi-installed APEX."
-                   << " Any updated version in /data will always overwrite"
-                   << " the multi-installed preinstalled version, if possible.";
+    if (apex_file.IsCompressed()) {
+      LOG(ERROR) << "Skipping " << file
+                 << " : Compressed APEX in data is not supported";
+      continue;
     }
-
-    if (EndsWith(apex_file->GetPath(), kDecompressedApexPackageSuffix)) {
-      LOG(WARNING) << "Skipping " << file
-                   << " : Non-decompressed APEX should not have "
-                   << kDecompressedApexPackageSuffix << " suffix";
+    if (EndsWith(file, kDecompressedApexPackageSuffix)) {
+      LOG(ERROR) << "Skipping " << file
+                 << " : Non-decompressed APEX should not have "
+                 << kDecompressedApexPackageSuffix << " suffix";
       continue;
     }
 
     auto it = data_store_.find(name);
     if (it == data_store_.end()) {
-      data_store_.emplace(name, std::move(*apex_file));
+      data_store_.emplace(name, std::move(apex_file));
       continue;
     }
 
-    const auto& existing_version = it->second.GetManifest().version();
-    const auto new_version = apex_file->GetManifest().version();
-    // If multiple data apexs are preset, select the one with highest version
-    bool prioritize_higher_version = new_version > existing_version;
-    // For same version, non-decompressed apex gets priority
-    if (prioritize_higher_version) {
-      it->second = std::move(*apex_file);
+    auto existing_version = it->second.GetManifest().version();
+    auto new_version = apex_file.GetManifest().version();
+    if (new_version > existing_version) {
+      it->second = std::move(apex_file);
+    } else {
+      LOG(ERROR) << "Skipping " << file << " : version(" << new_version
+                 << ") is lower than or same as "
+                 << " the other (" << existing_version << ")";
+      continue;
     }
   }
-  return {};
 }
 
 Result<void> ApexFileRepository::AddBrandNewApexCredentialAndBlocklist(
@@ -543,25 +534,6 @@ Result<ApexPartition> ApexFileRepository::GetPartition(
   return VerifyBrandNewPackageAgainstPreinstalled(apex);
 }
 
-// TODO(b/179497746): remove this method when we add api for fetching ApexFile
-//  by name
-Result<const std::string> ApexFileRepository::GetPublicKey(
-    const std::string& name) const {
-  auto it = pre_installed_store_.find(name);
-  if (it == pre_installed_store_.end()) {
-    // Special casing for APEXes backed by block devices, i.e. APEXes in VM.
-    // Inside a VM, we fall back to find the key from data_store_. This is
-    // because an APEX is put to either pre_installed_store_ or data_store,
-    // depending on whether it was a factory APEX or not in the host.
-    it = data_store_.find(name);
-    if (it != data_store_.end() && IsBlockApex(it->second)) {
-      return it->second.GetBundledPublicKey();
-    }
-    return Error() << "No preinstalled apex found for package " << name;
-  }
-  return it->second.GetBundledPublicKey();
-}
-
 Result<const std::string> ApexFileRepository::GetPreinstalledPath(
     const std::string& name) const {
   auto it = pre_installed_store_.find(name);
@@ -593,10 +565,6 @@ bool ApexFileRepository::HasPreInstalledVersion(const std::string& name) const {
   return pre_installed_store_.find(name) != pre_installed_store_.end();
 }
 
-bool ApexFileRepository::HasDataVersion(const std::string& name) const {
-  return data_store_.find(name) != data_store_.end();
-}
-
 // ApexFile is considered a decompressed APEX if it is located in decompression
 // dir
 bool ApexFileRepository::IsDecompressedApex(const ApexFile& apex) const {
@@ -625,15 +593,6 @@ std::vector<ApexFileRef> ApexFileRepository::GetPreInstalledApexFiles() const {
   return result;
 }
 
-std::vector<ApexFileRef> ApexFileRepository::GetDataApexFiles() const {
-  std::vector<ApexFileRef> result;
-  result.reserve(data_store_.size());
-  for (const auto& it : data_store_) {
-    result.emplace_back(std::cref(it.second));
-  }
-  return result;
-}
-
 std::optional<ApexPartition>
 ApexFileRepository::GetBrandNewApexPublicKeyPartition(
     const std::string& public_key) const {
@@ -658,30 +617,38 @@ std::optional<int64_t> ApexFileRepository::GetBrandNewApexBlockedVersion(
   return itt->second;
 }
 
-// Group pre-installed APEX and data APEX by name
-std::unordered_map<std::string, std::vector<ApexFileRef>>
-ApexFileRepository::AllApexFilesByName() const {
-  // Group them by name
-  std::unordered_map<std::string, std::vector<ApexFileRef>> result;
-  for (const auto* store : {&pre_installed_store_, &data_store_}) {
-    for (const auto& [name, apex] : *store) {
-      result[name].emplace_back(std::cref(apex));
+// For every package X, there can be at most two APEX, pre-installed vs
+// installed on data. Prefer data apexes and fallback to preinstalled. Note that
+// when adding data apexes, only same/higher version will be added to
+// data_store_.
+std::vector<ApexFileRef> ApexFileRepository::SelectApexForActivation() const {
+  std::vector<ApexFileRef> result;
+  result.reserve(partition_store_.size());
+  // partition_store_ has a collective set of apex names. Note that there can be
+  // data-only apexes without pre-installed: block apex or brand-new apex.
+  for (const auto& [apex_name, _] : partition_store_) {
+    if (auto it = data_store_.find(apex_name); it != data_store_.end()) {
+      result.emplace_back(std::cref(it->second));
+      continue;
+    }
+    if (auto it = pre_installed_store_.find(apex_name);
+        it != pre_installed_store_.end()) {
+      result.emplace_back(std::cref(it->second));
+      continue;
     }
+    LOG(FATAL) << "APEX " << apex_name << " found in partition_store_,"
+               << " but not found in pre_installed_store_ or data_store_";
   }
   return result;
 }
 
-ApexFileRef ApexFileRepository::GetDataApex(const std::string& name) const {
-  auto it = data_store_.find(name);
-  CHECK(it != data_store_.end());
-  return std::cref(it->second);
-}
-
-ApexFileRef ApexFileRepository::GetPreInstalledApex(
+std::optional<ApexFileRef> ApexFileRepository::GetPreInstalledApex(
     const std::string& name) const {
   auto it = pre_installed_store_.find(name);
-  CHECK(it != pre_installed_store_.end());
-  return std::cref(it->second);
+  if (it != pre_installed_store_.end()) {
+    return std::cref(it->second);
+  }
+  return std::nullopt;
 }
 
 }  // namespace apex
diff --git a/apexd/apex_file_repository.h b/apexd/apex_file_repository.h
index 8229b2d6..4d9b0872 100644
--- a/apexd/apex_file_repository.h
+++ b/apexd/apex_file_repository.h
@@ -53,13 +53,11 @@ class ApexFileRepository final {
  public:
   // c-tors and d-tor are exposed for testing.
   explicit ApexFileRepository(
-      const std::string& decompression_dir = kApexDecompressedDir)
-      : decompression_dir_(decompression_dir) {}
-  explicit ApexFileRepository(
-      bool enforce_multi_install_partition,
-      const std::vector<std::string>& multi_install_select_prop_prefixes)
-      : multi_install_select_prop_prefixes_(multi_install_select_prop_prefixes),
-        enforce_multi_install_partition_(enforce_multi_install_partition) {}
+      const std::string& decompression_dir = kApexDecompressedDir,
+      const std::vector<std::string>& apex_select_prop_prefixes =
+          kApexSelectPrefix)
+      : decompression_dir_(decompression_dir),
+        apex_select_prop_prefixes_(apex_select_prop_prefixes) {}
 
   // Returns a singletone instance of this class.
   static ApexFileRepository& GetInstance();
@@ -73,17 +71,6 @@ class ApexFileRepository final {
       const std::unordered_map<ApexPartition, std::string>&
           partition_to_prebuilt_dirs);
 
-  // Populate instance by collecting pre-installed apex files from the given
-  // |partition_to_prebuilt_dirs|.
-  // The difference between this function and |AddPreInstalledApex| is that this
-  // function opens pre-installed apex files in parallel. Note: this call is
-  // **not thread safe** and is expected to be performed in a single thread
-  // during initialization of apexd. After initialization is finished, all
-  // queries to the instance are thread safe.
-  android::base::Result<void> AddPreInstalledApexParallel(
-      const std::unordered_map<ApexPartition, std::string>&
-          partition_to_prebuilt_dirs);
-
   // Populate instance by collecting host-provided apex files via
   // |metadata_partition|. Host can provide its apexes to a VM instance via the
   // virtual disk image which has partitions: (see
@@ -108,6 +95,14 @@ class ApexFileRepository final {
   // finished, all queries to the instance are thread safe.
   android::base::Result<void> AddDataApex(const std::string& data_dir);
 
+  // Populate instance by adding data apex files. Note that files can be
+  // skipped when
+  // - its bundled pubkey doesn't match the preinstalled
+  // - its version is lower than the preinstalled
+  // - it's a compressed one
+  // - its filename ends with .decompressed.apex (for historical reason)
+  void AddDataApexFiles(std::vector<ApexFile>&& files);
+
   // Populates instance by collecting pre-installed credential files (.avbpubkey
   // for now) and blocklist files from the given directories. They are needed
   // specifically for brand-new APEX.
@@ -125,10 +120,6 @@ class ApexFileRepository final {
   // credentials to verify the package reside.
   android::base::Result<ApexPartition> GetPartition(const ApexFile& apex) const;
 
-  // Returns trusted public key for an apex with the given |name|.
-  android::base::Result<const std::string> GetPublicKey(
-      const std::string& name) const;
-
   // Returns path to the pre-installed version of an apex with the given |name|.
   // For brand-new APEX, returns Error.
   // For block APEX which is not set as factory, returns Error.
@@ -147,9 +138,6 @@ class ApexFileRepository final {
   // |name|.
   bool HasPreInstalledVersion(const std::string& name) const;
 
-  // Checks whether there is a data version of an apex with the given |name|.
-  bool HasDataVersion(const std::string& name) const;
-
   // Checks if given |apex| is pre-installed.
   bool IsPreInstalledApex(const ApexFile& apex) const;
 
@@ -162,9 +150,6 @@ class ApexFileRepository final {
   // Returns reference to all pre-installed APEX on device
   std::vector<ApexFileRef> GetPreInstalledApexFiles() const;
 
-  // Returns reference to all data APEX on device
-  std::vector<ApexFileRef> GetDataApexFiles() const;
-
   // Returns the partition of the pre-installed public key which exactly matches
   // the |public_key|.
   std::optional<ApexPartition> GetBrandNewApexPublicKeyPartition(
@@ -177,18 +162,11 @@ class ApexFileRepository final {
   std::optional<int64_t> GetBrandNewApexBlockedVersion(
       ApexPartition partition, const std::string& apex_name) const;
 
-  // Group all ApexFiles on device by their package name
-  std::unordered_map<std::string, std::vector<ApexFileRef>> AllApexFilesByName()
-      const;
+  // Select all apexes for activation
+  std::vector<ApexFileRef> SelectApexForActivation() const;
 
-  // Returns a pre-installed version of apex with the given name. Caller is
-  // expected to check if there is a pre-installed apex with the given name
-  // using |HasPreinstalledVersion| function.
-  ApexFileRef GetPreInstalledApex(const std::string& name) const;
-  // Returns a data version of apex with the given name. Caller is
-  // expected to check if there is a data apex with the given name
-  // using |HasDataVersion| function.
-  ApexFileRef GetDataApex(const std::string& name) const;
+  // Returns a pre-installed version of apex with the given name.
+  std::optional<ApexFileRef> GetPreInstalledApex(const std::string& name) const;
 
   // Returns if installation of brand-new APEX is enabled.
   static inline bool IsBrandNewApexEnabled() { return enable_brand_new_apex_; };
@@ -222,12 +200,12 @@ class ApexFileRepository final {
   void StorePreInstalledApex(ApexFile&& apex_file, ApexPartition partition);
 
   // Scans and returns apexes in the given directories.
-  android::base::Result<std::vector<ApexPath>> CollectPreInstalledApex(
+  static base::Result<std::vector<ApexPath>> CollectPreInstalledApex(
       const std::unordered_map<ApexPartition, std::string>&
           partition_to_prebuilt_dirs);
 
   // Opens and returns the apexes in the given paths.
-  android::base::Result<std::vector<ApexFileAndPartition>> OpenApexFiles(
+  static base::Result<std::vector<ApexFileAndPartition>> OpenApexFiles(
       const std::vector<ApexPath>& apex_paths);
 
   std::unordered_map<std::string, ApexFile> pre_installed_store_, data_store_;
@@ -244,19 +222,6 @@ class ApexFileRepository final {
   // Map from trusted public keys for brand-new APEX to their holding partition.
   std::unordered_map<std::string, ApexPartition> brand_new_apex_pubkeys_;
 
-  // Multi-installed APEX name -> all encountered public keys for this APEX.
-  std::unordered_map<std::string, std::unordered_set<std::string>>
-      multi_install_public_keys_;
-
-  // Prefixes used when looking for multi-installed APEX sysprops.
-  // Order matters: the first non-empty prop value is returned.
-  std::vector<std::string> multi_install_select_prop_prefixes_ =
-      kMultiApexSelectPrefix;
-
-  // Allows multi-install APEXes outside of expected partitions.
-  // Only set false in tests.
-  bool enforce_multi_install_partition_ = true;
-
   // Disallows installation of brand-new APEX by default.
   inline static bool enable_brand_new_apex_ = false;
 
@@ -280,6 +245,21 @@ class ApexFileRepository final {
   // Use "path" as key instead of APEX name because there can be multiple
   // versions of sharedlibs APEXes.
   std::unordered_map<std::string, BlockApexOverride> block_apex_overrides_;
+
+  // Prefixes used when looking for APEX select sysprops. APEX select sysprop
+  // can be used to install multiple instances of the same package, and select
+  // only one of them. Order matters: the first non-empty prop value is
+  // returned.
+  std::vector<std::string> apex_select_prop_prefixes_;
+
+  // When there are multiple instances of the same package, they should share
+  // the same public key. To ensure that, keep the map of package name to all
+  // encountered public keys for this APEX.
+  std::unordered_map<std::string, std::unordered_set<std::string>>
+      multi_install_public_keys_;
+
+  // for tests to access ApexFileRepository's private data
+  friend class ApexFileRepositoryAccessor;
 };
 
 }  // namespace android::apex
diff --git a/apexd/apex_file_repository_test.cpp b/apexd/apex_file_repository_test.cpp
index 2c22864f..f8ba47ff 100644
--- a/apexd/apex_file_repository_test.cpp
+++ b/apexd/apex_file_repository_test.cpp
@@ -20,6 +20,7 @@
 #include <android-base/logging.h>
 #include <android-base/properties.h>
 #include <android-base/result-gmock.h>
+#include <android-base/scopeguard.h>
 #include <android-base/stringprintf.h>
 #include <errno.h>
 #include <gmock/gmock.h>
@@ -38,7 +39,6 @@
 #include "apexd_metrics.h"
 #include "apexd_private.h"
 #include "apexd_test_utils.h"
-#include "apexd_verity.h"
 
 namespace android {
 namespace apex {
@@ -50,11 +50,28 @@ namespace fs = std::filesystem;
 using android::apex::testing::ApexFileEq;
 using android::base::StringPrintf;
 using android::base::testing::Ok;
-using ::testing::ByRef;
+using ::testing::_;
 using ::testing::ContainerEq;
+using ::testing::Contains;
+using ::testing::Eq;
+using ::testing::IsEmpty;
 using ::testing::Not;
+using ::testing::Optional;
+using ::testing::Pair;
 using ::testing::UnorderedElementsAre;
 
+class ApexFileRepositoryAccessor {
+ public:
+  static std::vector<ApexFileRef> GetDataApexFiles(
+      const ApexFileRepository& repository) {
+    std::vector<ApexFileRef> result;
+    for (const auto& it : repository.data_store_) {
+      result.emplace_back(std::cref(it.second));
+    }
+    return result;
+  }
+};
+
 namespace {
 // Copies the compressed apex to |built_in_dir| and decompresses it to
 // |decompression_dir
@@ -83,25 +100,15 @@ TEST(ApexFileRepositoryTest, InitializeSuccess) {
            built_in_dir.path);
   ApexPartition partition = ApexPartition::System;
 
-  fs::copy(GetTestFile("apex.apexd_test.apex"), data_dir.path);
-  fs::copy(GetTestFile("apex.apexd_test_different_app.apex"), data_dir.path);
-
   ApexFileRepository instance;
   ASSERT_RESULT_OK(
       instance.AddPreInstalledApex({{partition, built_in_dir.path}}));
-  ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
   // Now test that apexes were scanned correctly;
   auto test_fn = [&](const std::string& apex_name) {
     auto apex = ApexFile::Open(GetTestFile(apex_name));
     ASSERT_RESULT_OK(apex);
 
-    {
-      auto ret = instance.GetPublicKey(apex->GetManifest().name());
-      ASSERT_RESULT_OK(ret);
-      ASSERT_EQ(apex->GetBundledPublicKey(), *ret);
-    }
-
     {
       auto ret = instance.GetPreinstalledPath(apex->GetManifest().name());
       ASSERT_RESULT_OK(ret);
@@ -116,41 +123,10 @@ TEST(ApexFileRepositoryTest, InitializeSuccess) {
     }
 
     ASSERT_TRUE(instance.HasPreInstalledVersion(apex->GetManifest().name()));
-    ASSERT_TRUE(instance.HasDataVersion(apex->GetManifest().name()));
   };
 
   test_fn("apex.apexd_test.apex");
   test_fn("apex.apexd_test_different_app.apex");
-
-  // Check that second call will succeed as well.
-  ASSERT_RESULT_OK(
-      instance.AddPreInstalledApex({{partition, built_in_dir.path}}));
-  ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
-
-  test_fn("apex.apexd_test.apex");
-  test_fn("apex.apexd_test_different_app.apex");
-}
-
-TEST(ApexFileRepositoryTest, AddPreInstalledApexParallel) {
-  TemporaryDir built_in_dir;
-  fs::copy(GetTestFile("apex.apexd_test.apex"), built_in_dir.path);
-  fs::copy(GetTestFile("apex.apexd_test_different_app.apex"),
-           built_in_dir.path);
-  ApexPartition partition = ApexPartition::System;
-  std::unordered_map<ApexPartition, std::string> apex_dir = {
-      {partition, built_in_dir.path}};
-
-  ApexFileRepository instance0;
-  instance0.AddPreInstalledApex(apex_dir);
-  auto expected = instance0.GetPreInstalledApexFiles();
-
-  ApexFileRepository instance;
-  ASSERT_RESULT_OK(instance.AddPreInstalledApexParallel(apex_dir));
-  auto actual = instance.GetPreInstalledApexFiles();
-  ASSERT_EQ(actual.size(), expected.size());
-  for (size_t i = 0; i < actual.size(); ++i) {
-    ASSERT_THAT(actual[i], ApexFileEq(expected[i]));
-  }
 }
 
 TEST(ApexFileRepositoryTest, InitializeFailureCorruptApex) {
@@ -192,7 +168,7 @@ TEST(ApexFileRepositoryTest, InitializeSameNameDifferentPathAborts) {
       "");
 }
 
-TEST(ApexFileRepositoryTest, InitializeMultiInstalledSuccess) {
+TEST(ApexFileRepositoryTest, ApexSelectWithMultiApexSuccess) {
   // Prepare test data.
   TemporaryDir td;
   std::string apex_file = GetTestFile("apex.apexd_test.apex");
@@ -203,13 +179,13 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSuccess) {
 
   std::string persist_prefix = "debug.apexd.test.persistprefix.";
   std::string bootconfig_prefix = "debug.apexd.test.bootconfigprefix.";
-  ApexFileRepository instance(/*enforce_multi_install_partition=*/false,
-                              /*multi_install_select_prop_prefixes=*/{
-                                  persist_prefix, bootconfig_prefix});
+  ApexFileRepository instance(
+      kApexDecompressedDir,
+      /*apex_select_prop_prefixes=*/{persist_prefix, bootconfig_prefix});
 
   auto test_fn = [&](const std::string& selected_filename) {
     ASSERT_RESULT_OK(
-        instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
+        instance.AddPreInstalledApex({{ApexPartition::Vendor, td.path}}));
     auto ret = instance.GetPreinstalledPath(apex->GetManifest().name());
     ASSERT_RESULT_OK(ret);
     ASSERT_EQ(StringPrintf("%s/%s", td.path, selected_filename.c_str()), *ret);
@@ -230,7 +206,38 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSuccess) {
   android::base::SetProperty(bootconfig_prefix + apex_name, "");
 }
 
-TEST(ApexFileRepositoryTest, InitializeMultiInstalledSkipsForDifferingKeys) {
+TEST(ApexFileRepositoryTest, IgnoreNoneForApexSelect) {
+  // Prepare test data.
+  TemporaryDir td;
+  fs::copy(GetTestFile("apex.apexd_test.apex"), td.path);
+  auto apex_name =
+      ApexFile::Open(GetTestFile("apex.apexd_test.apex"))->GetManifest().name();
+
+  auto apex_select_prop_prefix = "debug.apexd.select."s;
+  auto reset_prop = base::make_scope_guard(
+      [&] { base::SetProperty(apex_select_prop_prefix + apex_name, ""); });
+
+  {
+    ApexFileRepository instance(
+        kApexDecompressedDir,
+        /*apex_select_prop_prefixes=*/{apex_select_prop_prefix});
+    ASSERT_THAT(
+        instance.AddPreInstalledApex({{ApexPartition::Vendor, td.path}}), Ok());
+    ASSERT_THAT(instance.GetPreInstalledApex(apex_name), Optional(_));
+  }
+  // With select prop is set to "none", the apex is skipped.
+  {
+    android::base::SetProperty(apex_select_prop_prefix + apex_name, "none");
+    ApexFileRepository instance(
+        kApexDecompressedDir,
+        /*apex_select_prop_prefixes=*/{apex_select_prop_prefix});
+    ASSERT_THAT(
+        instance.AddPreInstalledApex({{ApexPartition::Vendor, td.path}}), Ok());
+    ASSERT_THAT(instance.GetPreInstalledApex(apex_name), Eq(std::nullopt));
+  }
+}
+
+TEST(ApexFileRepositoryTest, ApexSelectSkipsForDifferingKeys) {
   // Prepare test data.
   TemporaryDir td;
   fs::copy(GetTestFile("apex.apexd_test.apex"),
@@ -243,11 +250,10 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSkipsForDifferingKeys) {
   std::string prop = prop_prefix + apex_name;
   android::base::SetProperty(prop, "version_a.apex");
 
-  ApexFileRepository instance(
-      /*enforce_multi_install_partition=*/false,
-      /*multi_install_select_prop_prefixes=*/{prop_prefix});
+  ApexFileRepository instance(kApexDecompressedDir,
+                              /*apex_select_prop_prefixes=*/{prop_prefix});
   ASSERT_RESULT_OK(
-      instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
+      instance.AddPreInstalledApex({{ApexPartition::Vendor, td.path}}));
   // Neither version should be have been installed.
   ASSERT_THAT(instance.GetPreinstalledPath(apex->GetManifest().name()),
               Not(Ok()));
@@ -255,7 +261,7 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSkipsForDifferingKeys) {
   android::base::SetProperty(prop, "");
 }
 
-TEST(ApexFileRepositoryTest, InitializeMultiInstalledSkipsForInvalidPartition) {
+TEST(ApexFileRepositoryTest, ApexSelectSkipsForInvalidPartition) {
   // Prepare test data.
   TemporaryDir td;
   // Note: These test files are on /data, which is not a valid partition for
@@ -270,9 +276,8 @@ TEST(ApexFileRepositoryTest, InitializeMultiInstalledSkipsForInvalidPartition) {
   std::string prop = prop_prefix + apex_name;
   android::base::SetProperty(prop, "version_a.apex");
 
-  ApexFileRepository instance(
-      /*enforce_multi_install_partition=*/true,
-      /*multi_install_select_prop_prefixes=*/{prop_prefix});
+  ApexFileRepository instance(kApexDecompressedDir,
+                              /*apex_select_prop_prefixes=*/{prop_prefix});
   ASSERT_RESULT_OK(
       instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
   // Neither version should be have been installed.
@@ -301,36 +306,18 @@ TEST(ApexFileRepositoryTest,
 TEST(ApexFileRepositoryTest, InitializePublicKeyUnexpectdlyChangedAborts) {
   // Prepare test data.
   TemporaryDir td;
-  fs::copy(GetTestFile("apex.apexd_test.apex"), td.path);
+  auto apex_path = std::string(td.path) + "/test.apex";
+  fs::copy(GetTestFile("apex.apexd_test.apex"), apex_path);
 
   ApexFileRepository instance;
   ASSERT_RESULT_OK(
       instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
 
-  auto apex_file = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
-
-  // Check that apex was loaded.
-  auto path = instance.GetPreinstalledPath(apex_file->GetManifest().name());
-  ASSERT_RESULT_OK(path);
-  ASSERT_EQ(StringPrintf("%s/apex.apexd_test.apex", td.path), *path);
-
-  auto public_key = instance.GetPublicKey("com.android.apex.test_package");
-  ASSERT_RESULT_OK(public_key);
+  fs::copy(GetTestFile("apex.apexd_test_different_key.apex"), apex_path,
+           fs::copy_options::overwrite_existing);
 
   // Substitute it with another apex with the same name, but different public
   // key.
-  fs::copy(GetTestFile("apex.apexd_test_different_key.apex"), *path,
-           fs::copy_options::overwrite_existing);
-
-  {
-    auto apex = ApexFile::Open(*path);
-    ASSERT_RESULT_OK(apex);
-    // Check module name hasn't changed.
-    ASSERT_EQ("com.android.apex.test_package", apex->GetManifest().name());
-    // Check public key has changed.
-    ASSERT_NE(*public_key, apex->GetBundledPublicKey());
-  }
-
   ASSERT_DEATH(
       { instance.AddPreInstalledApex({{ApexPartition::System, td.path}}); },
       "");
@@ -340,36 +327,17 @@ TEST(ApexFileRepositoryTest,
      InitializePublicKeyUnexpectdlyChangedAbortsCompressedApex) {
   // Prepare test data.
   TemporaryDir td;
-  fs::copy(GetTestFile("com.android.apex.compressed.v1.capex"), td.path);
+  auto apex_path = std::string(td.path) + "/test.apex";
+  fs::copy(GetTestFile("com.android.apex.compressed.v1.capex"), apex_path);
 
   ApexFileRepository instance;
   ASSERT_RESULT_OK(
       instance.AddPreInstalledApex({{ApexPartition::System, td.path}}));
 
-  // Check that apex was loaded.
-  auto apex_file =
-      ApexFile::Open(GetTestFile("com.android.apex.compressed.v1.capex"));
-  auto path = instance.GetPreinstalledPath(apex_file->GetManifest().name());
-  ASSERT_RESULT_OK(path);
-  ASSERT_EQ(StringPrintf("%s/com.android.apex.compressed.v1.capex", td.path),
-            *path);
-
-  auto public_key = instance.GetPublicKey("com.android.apex.compressed");
-  ASSERT_RESULT_OK(public_key);
-
   // Substitute it with another apex with the same name, but different public
   // key.
   fs::copy(GetTestFile("com.android.apex.compressed_different_key.capex"),
-           *path, fs::copy_options::overwrite_existing);
-
-  {
-    auto apex = ApexFile::Open(*path);
-    ASSERT_RESULT_OK(apex);
-    // Check module name hasn't changed.
-    ASSERT_EQ("com.android.apex.compressed", apex->GetManifest().name());
-    // Check public key has changed.
-    ASSERT_NE(*public_key, apex->GetBundledPublicKey());
-  }
+           apex_path, fs::copy_options::overwrite_existing);
 
   ASSERT_DEATH(
       { instance.AddPreInstalledApex({{ApexPartition::System, td.path}}); },
@@ -452,23 +420,43 @@ TEST(ApexFileRepositoryTest, AddAndGetDataApex) {
 
   // ApexFileRepository should only deal with APEX in /data/apex/active.
   // Decompressed APEX should not be included
-  auto data_apexs = instance.GetDataApexFiles();
+  auto data_apexs = ApexFileRepositoryAccessor::GetDataApexFiles(instance);
   auto normal_apex =
       ApexFile::Open(StringPrintf("%s/apex.apexd_test_v2.apex", data_dir.path));
-  ASSERT_THAT(data_apexs,
-              UnorderedElementsAre(ApexFileEq(ByRef(*normal_apex))));
+  ASSERT_THAT(data_apexs, UnorderedElementsAre(ApexFileEq(*normal_apex)));
 }
 
 TEST(ApexFileRepositoryTest, AddDataApexIgnoreCompressedApex) {
   // Prepare test data.
-  TemporaryDir data_dir, decompression_dir;
+  TemporaryDir preinstalled_dir, data_dir;
+  fs::copy(GetTestFile("com.android.apex.compressed.v1.capex"),
+           preinstalled_dir.path);
   fs::copy(GetTestFile("com.android.apex.compressed.v1.capex"), data_dir.path);
 
   ApexFileRepository instance;
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, preinstalled_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
-  auto data_apexs = instance.GetDataApexFiles();
-  ASSERT_EQ(data_apexs.size(), 0u);
+  auto data_apexs = ApexFileRepositoryAccessor::GetDataApexFiles(instance);
+  ASSERT_THAT(data_apexs, IsEmpty());
+}
+
+TEST(ApexFileRepositoryTest, AddDataApexIgnoreCompressedApexWithApexExtension) {
+  // Prepare test data.
+  TemporaryDir preinstalled_dir, data_dir;
+  fs::copy(GetTestFile("com.android.apex.compressed.v1.capex"),
+           preinstalled_dir.path);
+  fs::copy(GetTestFile("com.android.apex.compressed.v1.capex"),
+           std::string(data_dir.path) + "/com.android.apex.compressed.apex");
+
+  ApexFileRepository instance;
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, preinstalled_dir.path}}));
+  ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
+
+  auto data_apexs = ApexFileRepositoryAccessor::GetDataApexFiles(instance);
+  ASSERT_THAT(data_apexs, IsEmpty());
 }
 
 TEST(ApexFileRepositoryTest, AddDataApexIgnoreIfNotPreInstalled) {
@@ -479,7 +467,7 @@ TEST(ApexFileRepositoryTest, AddDataApexIgnoreIfNotPreInstalled) {
   ApexFileRepository instance;
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
-  auto data_apexs = instance.GetDataApexFiles();
+  auto data_apexs = ApexFileRepositoryAccessor::GetDataApexFiles(instance);
   ASSERT_EQ(data_apexs.size(), 0u);
 }
 
@@ -495,11 +483,25 @@ TEST(ApexFileRepositoryTest, AddDataApexPrioritizeHigherVersionApex) {
       {{ApexPartition::System, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
-  auto data_apexs = instance.GetDataApexFiles();
+  auto data_apexs = ApexFileRepositoryAccessor::GetDataApexFiles(instance);
   auto normal_apex =
       ApexFile::Open(StringPrintf("%s/apex.apexd_test_v2.apex", data_dir.path));
-  ASSERT_THAT(data_apexs,
-              UnorderedElementsAre(ApexFileEq(ByRef(*normal_apex))));
+  ASSERT_THAT(data_apexs, UnorderedElementsAre(ApexFileEq(*normal_apex)));
+}
+
+TEST(ApexFileRepositoryTest, AddDataApexIgnoreIfLowerThanPreinstalled) {
+  // Prepare test data.
+  TemporaryDir built_in_dir, data_dir;
+  fs::copy(GetTestFile("apex.apexd_test_v2.apex"), built_in_dir.path);
+  fs::copy(GetTestFile("apex.apexd_test.apex"), data_dir.path);
+
+  ApexFileRepository instance;
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
+  ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
+
+  auto data_apexs = ApexFileRepositoryAccessor::GetDataApexFiles(instance);
+  ASSERT_THAT(data_apexs, IsEmpty());
 }
 
 TEST(ApexFileRepositoryTest, AddDataApexDoesNotScanDecompressedApex) {
@@ -513,7 +515,7 @@ TEST(ApexFileRepositoryTest, AddDataApexDoesNotScanDecompressedApex) {
       {{ApexPartition::System, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
-  auto data_apexs = instance.GetDataApexFiles();
+  auto data_apexs = ApexFileRepositoryAccessor::GetDataApexFiles(instance);
   ASSERT_EQ(data_apexs.size(), 0u);
 }
 
@@ -528,7 +530,7 @@ TEST(ApexFileRepositoryTest, AddDataApexIgnoreWrongPublicKey) {
       {{ApexPartition::System, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
-  auto data_apexs = instance.GetDataApexFiles();
+  auto data_apexs = ApexFileRepositoryAccessor::GetDataApexFiles(instance);
   ASSERT_EQ(data_apexs.size(), 0u);
 }
 
@@ -548,73 +550,90 @@ TEST(ApexFileRepositoryTest, GetPreInstalledApexFiles) {
       StringPrintf("%s/apex.apexd_test.apex", built_in_dir.path));
   auto pre_apex_2 = ApexFile::Open(StringPrintf(
       "%s/com.android.apex.compressed.v1.capex", built_in_dir.path));
-  ASSERT_THAT(pre_installed_apexs,
-              UnorderedElementsAre(ApexFileEq(ByRef(*pre_apex_1)),
-                                   ApexFileEq(ByRef(*pre_apex_2))));
+  ASSERT_THAT(
+      pre_installed_apexs,
+      UnorderedElementsAre(ApexFileEq(*pre_apex_1), ApexFileEq(*pre_apex_2)));
 }
 
-TEST(ApexFileRepositoryTest, AllApexFilesByName) {
-  TemporaryDir built_in_dir, decompression_dir;
-  fs::copy(GetTestFile("apex.apexd_test.apex"), built_in_dir.path);
-  fs::copy(GetTestFile("com.android.apex.cts.shim.apex"), built_in_dir.path);
-  fs::copy(GetTestFile("com.android.apex.compressed.v1.capex"),
-           built_in_dir.path);
+ApexFile CopyTestApex(const std::string& test_filename,
+                      const std::string& dest_dir) {
+  fs::copy(GetTestFile(test_filename), dest_dir);
+  auto apex_path = dest_dir + "/" + test_filename;
+  auto apex = ApexFile::Open(apex_path);
+  CHECK(apex.ok()) << apex.error();
+  return *apex;
+}
+
+TEST(ApexFileRepositoryTest, SelectApexForActivation_NoData) {
+  TemporaryDir built_in_dir;
+  auto test_apex = CopyTestApex("apex.apexd_test.apex", built_in_dir.path);
+  auto shim_v1 =
+      CopyTestApex("com.android.apex.cts.shim.apex", built_in_dir.path);
+
   ApexFileRepository instance;
   ASSERT_RESULT_OK(instance.AddPreInstalledApex(
       {{ApexPartition::System, built_in_dir.path}}));
+  auto result = instance.SelectApexForActivation();
 
-  TemporaryDir data_dir;
-  fs::copy(GetTestFile("com.android.apex.cts.shim.v2.apex"), data_dir.path);
-  ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
+  ASSERT_THAT(result,
+              UnorderedElementsAre(ApexFileEq(test_apex), ApexFileEq(shim_v1)));
+}
 
-  auto result = instance.AllApexFilesByName();
+TEST(ApexFileRepositoryTest, SelectApexForActivation_HigherDataApex) {
+  TemporaryDir built_in_dir, data_dir;
+  auto test_apex = CopyTestApex("apex.apexd_test.apex", built_in_dir.path);
+  auto shim_v1 =
+      CopyTestApex("com.android.apex.cts.shim.apex", built_in_dir.path);
+  auto capex =
+      CopyTestApex("com.android.apex.compressed.v1.capex", built_in_dir.path);
+  auto shim_v2 =
+      CopyTestApex("com.android.apex.cts.shim.v2.apex", data_dir.path);
 
-  // Verify the contents of result
-  auto apexd_test_file = ApexFile::Open(
-      StringPrintf("%s/apex.apexd_test.apex", built_in_dir.path));
-  auto shim_v1 = ApexFile::Open(
-      StringPrintf("%s/com.android.apex.cts.shim.apex", built_in_dir.path));
-  auto compressed_apex = ApexFile::Open(StringPrintf(
-      "%s/com.android.apex.compressed.v1.capex", built_in_dir.path));
-  auto shim_v2 = ApexFile::Open(
-      StringPrintf("%s/com.android.apex.cts.shim.v2.apex", data_dir.path));
-
-  ASSERT_EQ(result.size(), 3u);
-  ASSERT_THAT(result[apexd_test_file->GetManifest().name()],
-              UnorderedElementsAre(ApexFileEq(ByRef(*apexd_test_file))));
-  ASSERT_THAT(result[shim_v1->GetManifest().name()],
-              UnorderedElementsAre(ApexFileEq(ByRef(*shim_v1)),
-                                   ApexFileEq(ByRef(*shim_v2))));
-  ASSERT_THAT(result[compressed_apex->GetManifest().name()],
-              UnorderedElementsAre(ApexFileEq(ByRef(*compressed_apex))));
+  ApexFileRepository instance;
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
+  ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
+  auto result = instance.SelectApexForActivation();
+
+  // shim_v2 is selected because it's higher
+  ASSERT_THAT(result,
+              UnorderedElementsAre(ApexFileEq(test_apex), ApexFileEq(capex),
+                                   ApexFileEq(shim_v2)));
 }
 
-TEST(ApexFileRepositoryTest, GetDataApex) {
-  // Prepare test data.
+// When versions are equal, non-pre-installed version gets priority
+TEST(ApexFileRepositoryTest, SelectApexForActivation_SameDataApex) {
   TemporaryDir built_in_dir, data_dir;
-  fs::copy(GetTestFile("apex.apexd_test.apex"), built_in_dir.path);
-  fs::copy(GetTestFile("apex.apexd_test_v2.apex"), data_dir.path);
+  auto test_apex = CopyTestApex("apex.apexd_test.apex", built_in_dir.path);
+  auto shim_v1 =
+      CopyTestApex("com.android.apex.cts.shim.apex", built_in_dir.path);
+  auto test_apex_in_data = CopyTestApex("apex.apexd_test.apex", data_dir.path);
+  auto shim_v1_in_data =
+      CopyTestApex("com.android.apex.cts.shim.apex", data_dir.path);
 
   ApexFileRepository instance;
   ASSERT_RESULT_OK(instance.AddPreInstalledApex(
       {{ApexPartition::System, built_in_dir.path}}));
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
+  auto result = instance.SelectApexForActivation();
 
-  auto apex =
-      ApexFile::Open(StringPrintf("%s/apex.apexd_test_v2.apex", data_dir.path));
-  ASSERT_RESULT_OK(apex);
-
-  auto ret = instance.GetDataApex("com.android.apex.test_package");
-  ASSERT_THAT(ret, ApexFileEq(ByRef(*apex)));
+  ASSERT_THAT(result, UnorderedElementsAre(ApexFileEq(test_apex_in_data),
+                                           ApexFileEq(shim_v1_in_data)));
 }
 
-TEST(ApexFileRepositoryTest, GetDataApexNoSuchApexAborts) {
-  ASSERT_DEATH(
-      {
-        ApexFileRepository instance;
-        instance.GetDataApex("whatever");
-      },
-      "");
+TEST(ApexFileRepositoryTest, SelectApexForActivation_LowerDataApex) {
+  TemporaryDir built_in_dir, data_dir;
+  auto shim_v2 =
+      CopyTestApex("com.android.apex.cts.shim.v2.apex", built_in_dir.path);
+  auto shim_v1 = CopyTestApex("com.android.apex.cts.shim.apex", data_dir.path);
+
+  ApexFileRepository instance;
+  ASSERT_RESULT_OK(instance.AddPreInstalledApex(
+      {{ApexPartition::System, built_in_dir.path}}));
+  ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
+  auto result = instance.SelectApexForActivation();
+
+  ASSERT_THAT(result, UnorderedElementsAre(ApexFileEq(shim_v2)));
 }
 
 TEST(ApexFileRepositoryTest, GetPreInstalledApex) {
@@ -631,16 +650,12 @@ TEST(ApexFileRepositoryTest, GetPreInstalledApex) {
   ASSERT_RESULT_OK(apex);
 
   auto ret = instance.GetPreInstalledApex("com.android.apex.test_package");
-  ASSERT_THAT(ret, ApexFileEq(ByRef(*apex)));
+  ASSERT_THAT(ret, Optional(ApexFileEq(*apex)));
 }
 
-TEST(ApexFileRepositoryTest, GetPreInstalledApexNoSuchApexAborts) {
-  ASSERT_DEATH(
-      {
-        ApexFileRepository instance;
-        instance.GetPreInstalledApex("whatever");
-      },
-      "");
+TEST(ApexFileRepositoryTest, GetPreInstalledApexNoSuchApex) {
+  ApexFileRepository instance;
+  ASSERT_EQ(instance.GetPreInstalledApex("whatever"), std::nullopt);
 }
 
 struct ApexFileRepositoryTestAddBlockApex : public ::testing::Test {
@@ -714,7 +729,7 @@ TEST_F(ApexFileRepositoryTestAddBlockApex,
 
   // "block" apexes are treated as "pre-installed" with "is_factory: true"
   auto ret_foo = instance.GetPreInstalledApex("com.android.apex.test_package");
-  ASSERT_THAT(ret_foo, ApexFileEq(ByRef(*apex_foo)));
+  ASSERT_THAT(ret_foo, Optional(ApexFileEq(*apex_foo)));
 
   auto partition_foo = instance.GetPartition(*apex_foo);
   ASSERT_RESULT_OK(partition_foo);
@@ -724,7 +739,7 @@ TEST_F(ApexFileRepositoryTestAddBlockApex,
   ASSERT_RESULT_OK(apex_bar);
   auto ret_bar =
       instance.GetPreInstalledApex("com.android.apex.test_package_2");
-  ASSERT_THAT(ret_bar, ApexFileEq(ByRef(*apex_bar)));
+  ASSERT_THAT(ret_bar, Optional(ApexFileEq(*apex_bar)));
 
   auto partition_bar = instance.GetPartition(*apex_bar);
   ASSERT_EQ(*partition_bar, ApexPartition::System);
@@ -1095,7 +1110,7 @@ TEST(ApexFileRepositoryTestBrandNewApex,
   ApexFileRepository::EnableBrandNewApex();
   const auto partition = ApexPartition::System;
   TemporaryDir data_dir, trusted_key_dir;
-  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
+  auto apex = CopyTestApex("com.android.apex.brand.new.apex", data_dir.path);
   fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
            trusted_key_dir.path);
 
@@ -1104,22 +1119,19 @@ TEST(ApexFileRepositoryTestBrandNewApex,
       {{partition, trusted_key_dir.path}});
 
   // Now test that apexes were scanned correctly;
-  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
-  ASSERT_RESULT_OK(apex);
-
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
   {
-    auto ret = instance.GetPartition(*apex);
+    auto ret = instance.GetPartition(apex);
     ASSERT_RESULT_OK(ret);
     ASSERT_EQ(partition, *ret);
   }
 
-  ASSERT_THAT(instance.GetPreinstalledPath(apex->GetManifest().name()),
+  ASSERT_THAT(instance.GetPreinstalledPath(apex.GetManifest().name()),
               Not(Ok()));
-  ASSERT_FALSE(instance.HasPreInstalledVersion(apex->GetManifest().name()));
-  ASSERT_TRUE(instance.HasDataVersion(apex->GetManifest().name()));
-
+  ASSERT_FALSE(instance.HasPreInstalledVersion(apex.GetManifest().name()));
+  ASSERT_THAT(instance.SelectApexForActivation(),
+              UnorderedElementsAre(ApexFileEq(apex)));
   instance.Reset();
 }
 
@@ -1127,27 +1139,21 @@ TEST(ApexFileRepositoryTestBrandNewApex,
      AddDataApexFailUnverifiedBrandNewApex) {
   ApexFileRepository::EnableBrandNewApex();
   TemporaryDir data_dir;
-  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
+  auto apex = CopyTestApex("com.android.apex.brand.new.apex", data_dir.path);
 
   ApexFileRepository& instance = ApexFileRepository::GetInstance();
-  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
-  ASSERT_RESULT_OK(apex);
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
-
-  ASSERT_FALSE(instance.HasDataVersion(apex->GetManifest().name()));
+  ASSERT_THAT(instance.SelectApexForActivation(), IsEmpty());
   instance.Reset();
 }
 
 TEST(ApexFileRepositoryTestBrandNewApex, AddDataApexFailBrandNewApexDisabled) {
   TemporaryDir data_dir;
-  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
+  auto apex = CopyTestApex("com.android.apex.brand.new.apex", data_dir.path);
 
   ApexFileRepository& instance = ApexFileRepository::GetInstance();
-  auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
-  ASSERT_RESULT_OK(apex);
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
-
-  ASSERT_FALSE(instance.HasDataVersion(apex->GetManifest().name()));
+  ASSERT_THAT(instance.SelectApexForActivation(), IsEmpty());
   instance.Reset();
 }
 
diff --git a/apexd/apex_file_test.cpp b/apexd/apex_file_test.cpp
index 4d8642c4..dd50f9d0 100644
--- a/apexd/apex_file_test.cpp
+++ b/apexd/apex_file_test.cpp
@@ -326,17 +326,6 @@ TEST(ApexFileTest, GetPathReturnsRealpath) {
   ASSERT_EQ(real_path, apex_file->GetPath());
 }
 
-TEST(ApexFileTest, CompressedSharedLibsApexIsRejected) {
-  const std::string file_path =
-      kTestDataDir + "com.android.apex.compressed_sharedlibs.capex";
-  Result<ApexFile> apex_file = ApexFile::Open(file_path);
-
-  ASSERT_FALSE(apex_file.ok());
-  ASSERT_THAT(apex_file.error().message(),
-              ::testing::HasSubstr("Apex providing sharedlibs shouldn't "
-                                   "be compressed"));
-}
-
 // Check if CAPEX contains originalApexDigest in its manifest
 TEST(ApexFileTest, OriginalApexDigest) {
   const std::string capex_path =
diff --git a/apexd/apexd.cpp b/apexd/apexd.cpp
index 9e3c915a..203d4e6c 100644
--- a/apexd/apexd.cpp
+++ b/apexd/apexd.cpp
@@ -37,7 +37,6 @@
 #include <libdm/dm.h>
 #include <libdm/dm_table.h>
 #include <libdm/dm_target.h>
-#include <linux/f2fs.h>
 #include <linux/loop.h>
 #include <selinux/android.h>
 #include <stdlib.h>
@@ -93,6 +92,10 @@
 #include "apexd_vendor_apex.h"
 #include "apexd_verity.h"
 #include "com_android_apex.h"
+#include "com_android_apex_flags.h"
+
+namespace flags = com::android::apex::flags;
+namespace fs = std::filesystem;
 
 using android::base::boot_clock;
 using android::base::ConsumePrefix;
@@ -107,6 +110,7 @@ using android::base::SetProperty;
 using android::base::StartsWith;
 using android::base::StringPrintf;
 using android::base::unique_fd;
+using android::base::WriteStringToFile;
 using android::dm::DeviceMapper;
 using android::dm::DmDeviceState;
 using android::dm::DmTable;
@@ -201,9 +205,12 @@ bool IsBootstrapApex(const ApexFile& apex) {
     return ret;
   }();
 
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
   if (apex.GetManifest().vendorbootstrap() || apex.GetManifest().bootstrap()) {
     return true;
   }
+#pragma clang diagnostic pop
 
   return std::find(kBootstrapApexes.begin(), kBootstrapApexes.end(),
                    apex.GetManifest().name()) != kBootstrapApexes.end() ||
@@ -211,31 +218,6 @@ bool IsBootstrapApex(const ApexFile& apex) {
                    apex.GetManifest().name()) != additional.end();
 }
 
-void ReleaseF2fsCompressedBlocks(const std::string& file_path) {
-  unique_fd fd(
-      TEMP_FAILURE_RETRY(open(file_path.c_str(), O_RDONLY | O_CLOEXEC, 0)));
-  if (fd.get() == -1) {
-    PLOG(ERROR) << "Failed to open " << file_path;
-    return;
-  }
-  unsigned int flags;
-  if (ioctl(fd, FS_IOC_GETFLAGS, &flags) == -1) {
-    PLOG(ERROR) << "Failed to call FS_IOC_GETFLAGS on " << file_path;
-    return;
-  }
-  if ((flags & FS_COMPR_FL) == 0) {
-    // Doesn't support f2fs-compression.
-    return;
-  }
-  uint64_t blk_cnt;
-  if (ioctl(fd, F2FS_IOC_RELEASE_COMPRESS_BLOCKS, &blk_cnt) == -1) {
-    PLOG(ERROR) << "Failed to call F2FS_IOC_RELEASE_COMPRESS_BLOCKS on "
-                << file_path;
-  }
-  LOG(INFO) << "Released " << blk_cnt << " compressed blocks from "
-            << file_path;
-}
-
 std::unique_ptr<DmTable> CreateVerityTable(const ApexVerityData& verity_data,
                                            const std::string& block_device,
                                            bool restart_on_corruption) {
@@ -358,8 +340,78 @@ Result<void> VerifyMountedImage(const ApexFile& apex,
   return {};
 }
 
+Result<loop::LoopbackDeviceUniqueFd> CreateLoopForApex(const ApexFile& apex,
+                                                       int32_t loop_id) {
+  if (!apex.GetImageOffset() || !apex.GetImageSize()) {
+    return Error() << "Cannot create mount point without image offset and size";
+  }
+  const std::string& full_path = apex.GetPath();
+  loop::LoopbackDeviceUniqueFd loopback_device;
+  for (size_t attempts = 1;; ++attempts) {
+    Result<loop::LoopbackDeviceUniqueFd> ret =
+        loop::CreateAndConfigureLoopDevice(
+            full_path, apex.GetImageOffset().value(),
+            apex.GetImageSize().value(), loop_id);
+    if (ret.ok()) {
+      loopback_device = std::move(*ret);
+      break;
+    }
+    if (attempts >= kLoopDeviceSetupAttempts) {
+      return Error() << "Could not create loop device for " << full_path << ": "
+                     << ret.error();
+    }
+  }
+  LOG(VERBOSE) << "Loopback device created: " << loopback_device.name;
+  return std::move(loopback_device);
+}
+
+bool IsMountBeforeDataEnabled() { return gConfig->mount_before_data; }
+
+[[maybe_unused]] bool CanMountBeforeDataOnNextBoot() {
+  // If there's no data apex files in /data/apex/active and no capex files, then
+  // apexd-bootstrap can mount ALL apexes (preinstalled and pinned data apexes).
+  if (!IsEmptyDirectory(gConfig->active_apex_data_dir)) {
+    return false;
+  }
+  auto& repo = ApexFileRepository::GetInstance();
+  if (std::ranges::any_of(
+          repo.GetPreInstalledApexFiles(),
+          [](const ApexFile& apex) { return apex.IsCompressed(); })) {
+    return false;
+  }
+  return true;
+}
+
+[[maybe_unused]] void CreateMetadataConfigFile(const std::string& filename) {
+  auto config_file = fs::path(gConfig->metadata_config_dir) / filename;
+  if (!WriteStringToFile("", config_file)) {
+    PLOG(ERROR) << "Failed to create " << config_file;
+  }
+}
+
+Result<DmDevice> CreateDmLinearForPayload(const ApexFile& apex,
+                                          const std::string& device_name) {
+  if (!apex.GetImageOffset() || !apex.GetImageSize()) {
+    return Error() << "Cannot create mount point without image offset and size";
+  }
+  // TODO(b/405904883) measure the IO performance and reduce # of layers if
+  // necessary
+  DmTable table;
+  constexpr auto kBytesInSector = 512;
+  table.Emplace<dm::DmTargetLinear>(0, *apex.GetImageSize() / kBytesInSector,
+                                    apex.GetPath(),
+                                    *apex.GetImageOffset() / kBytesInSector);
+  table.set_readonly(true);
+  auto dev =
+      OR_RETURN(CreateDmDevice(device_name, table, /* reuse device */ false));
+
+  OR_RETURN(loop::ConfigureReadAhead(dev.GetDevPath()));
+  return std::move(dev);
+}
+
 Result<MountedApexData> MountPackageImpl(const ApexFile& apex,
                                          const std::string& mount_point,
+                                         int32_t loop_id,
                                          const std::string& device_name,
                                          bool verify_image, bool reuse_device) {
   auto tag = "MountPackageImpl: " + apex.GetManifest().name();
@@ -369,6 +421,17 @@ Result<MountedApexData> MountPackageImpl(const ApexFile& apex,
                    << apex.GetPath();
   }
 
+  // Steps to mount an APEX file:
+  //
+  // 1. create a mount point (directory)
+  // 2. create a block device for the payload part of the APEX
+  // 3. wrap it with a dm-verity device if the APEX is not on top of verity
+  //    device
+  // 4. mount the payload filesystm
+  // 5. verify the mount
+
+  // Step 1. Create a directory for the mount point
+
   LOG(VERBOSE) << "Creating mount point: " << mount_point;
   auto time_started = boot_clock::now();
   // Note: the mount point could exist in case when the APEX was activated
@@ -398,25 +461,22 @@ Result<MountedApexData> MountPackageImpl(const ApexFile& apex,
 
   const std::string& full_path = apex.GetPath();
 
-  if (!apex.GetImageOffset() || !apex.GetImageSize()) {
-    return Error() << "Cannot create mount point without image offset and size";
-  }
-  loop::LoopbackDeviceUniqueFd loopback_device;
-  for (size_t attempts = 1;; ++attempts) {
-    Result<loop::LoopbackDeviceUniqueFd> ret =
-        loop::CreateAndConfigureLoopDevice(full_path,
-                                           apex.GetImageOffset().value(),
-                                           apex.GetImageSize().value());
-    if (ret.ok()) {
-      loopback_device = std::move(*ret);
-      break;
-    }
-    if (attempts >= kLoopDeviceSetupAttempts) {
-      return Error() << "Could not create loop device for " << full_path << ": "
-                     << ret.error();
-    }
+  // Step 2. Create a block device for the payload
+
+  std::string block_device;
+  loop::LoopbackDeviceUniqueFd loop;
+  DmDevice linear_dev;
+
+  if (IsMountBeforeDataEnabled() && GetImageManager()->IsPinnedApex(apex)) {
+    linear_dev = OR_RETURN(
+        CreateDmLinearForPayload(apex, device_name + kDmLinearPayloadSuffix));
+    block_device = linear_dev.GetDevPath();
+  } else {
+    loop = OR_RETURN(CreateLoopForApex(apex, loop_id));
+    block_device = loop.name;
   }
-  LOG(VERBOSE) << "Loopback device created: " << loopback_device.name;
+
+  // Step 3. Wrap the block device with dm-verity (optional)
 
   auto verity_data = apex.VerifyApexVerity(apex.GetBundledPublicKey());
   if (!verity_data.ok()) {
@@ -436,11 +496,6 @@ Result<MountedApexData> MountPackageImpl(const ApexFile& apex,
     }
   }
 
-  std::string block_device = loopback_device.name;
-  MountedApexData apex_data(apex.GetManifest().version(), loopback_device.name,
-                            apex.GetPath(), mount_point,
-                            /* device_name = */ "");
-
   // for APEXes in immutable partitions, we don't need to mount them on
   // dm-verity because they are already in the dm-verity protected partition;
   // system. However, note that we don't skip verification to ensure that APEXes
@@ -454,33 +509,35 @@ Result<MountedApexData> MountPackageImpl(const ApexFile& apex,
   DmDevice verity_dev;
   if (mount_on_verity) {
     auto verity_table =
-        CreateVerityTable(*verity_data, loopback_device.name,
+        CreateVerityTable(*verity_data, block_device,
                           /* restart_on_corruption = */ !verify_image);
     Result<DmDevice> verity_dev_res =
         CreateDmDevice(device_name, *verity_table, reuse_device);
     if (!verity_dev_res.ok()) {
-      return Error() << "Failed to create Apex Verity device " << full_path
-                     << ": " << verity_dev_res.error();
+      // verify root digest for better debugging
+      if (auto st = VerifyVerityRootDigest(apex); !st.ok()) {
+        LOG(ERROR) << "Failed to verify root digest with " << full_path << ": "
+                   << st.error();
+      }
+      return Error() << "Failed to create dm-verity for path=" << full_path
+                     << " block=" << block_device << ": "
+                     << verity_dev_res.error();
     }
     verity_dev = std::move(*verity_dev_res);
-    apex_data.device_name = device_name;
-    block_device = verity_dev.GetDevPath();
+    OR_RETURN(loop::ConfigureReadAhead(verity_dev.GetDevPath()));
 
-    Result<void> read_ahead_status =
-        loop::ConfigureReadAhead(verity_dev.GetDevPath());
-    if (!read_ahead_status.ok()) {
-      return read_ahead_status.error();
-    }
-  }
-  // TODO(b/158467418): consider moving this inside RunVerifyFnInsideTempMount.
-  if (mount_on_verity && verify_image) {
-    Result<void> verity_status =
-        ReadVerityDevice(block_device, (*verity_data).desc->image_size);
-    if (!verity_status.ok()) {
-      return verity_status.error();
+    // TODO(b/158467418): consider moving this inside
+    // RunVerifyFnInsideTempMount.
+    if (verify_image) {
+      OR_RETURN(ReadVerityDevice(verity_dev.GetDevPath(),
+                                 (*verity_data).desc->image_size));
     }
+
+    block_device = verity_dev.GetDevPath();
   }
 
+  // Step 4. Mount the payload filesystem at the mount point
+
   uint32_t mount_flags = MS_NOATIME | MS_NODEV | MS_DIRSYNC | MS_RDONLY;
   if (apex.GetManifest().nocode()) {
     mount_flags |= MS_NOEXEC;
@@ -490,32 +547,38 @@ Result<MountedApexData> MountPackageImpl(const ApexFile& apex,
     return Error() << "Cannot mount package without FsType";
   }
   if (mount(block_device.c_str(), mount_point.c_str(),
-            apex.GetFsType().value().c_str(), mount_flags, nullptr) == 0) {
-    auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
-                            boot_clock::now() - time_started)
-                            .count();
-    LOG(INFO) << "Successfully mounted package " << full_path << " on "
-              << mount_point << " duration=" << time_elapsed;
-    auto status = VerifyMountedImage(apex, mount_point);
-    if (!status.ok()) {
-      if (umount2(mount_point.c_str(), UMOUNT_NOFOLLOW) != 0) {
-        PLOG(ERROR) << "Failed to umount " << mount_point;
-      }
-      return Error() << "Failed to verify " << full_path << ": "
-                     << status.error();
-    }
-    // Time to accept the temporaries as good.
-    verity_dev.Release();
-    loopback_device.CloseGood();
-
-    scope_guard.Disable();  // Accept the mount.
-    return apex_data;
-  } else {
+            apex.GetFsType().value().c_str(), mount_flags, nullptr) != 0) {
     return ErrnoError() << "Mounting failed for package " << full_path;
   }
-}
 
-bool IsMountBeforeDataEnabled() { return gConfig->mount_before_data; }
+  // Step 5. After mounting, verify the mounted image
+
+  auto status = VerifyMountedImage(apex, mount_point);
+  if (!status.ok()) {
+    if (umount2(mount_point.c_str(), UMOUNT_NOFOLLOW) != 0) {
+      PLOG(ERROR) << "Failed to umount " << mount_point;
+    }
+    return Error() << "Failed to verify " << full_path << ": "
+                   << status.error();
+  }
+
+  MountedApexData apex_data(apex.GetManifest().version(), loop.name,
+                            apex.GetPath(), mount_point, verity_dev.GetName(),
+                            linear_dev.GetName());
+
+  // Time to accept the temporaries as good.
+  linear_dev.Release();
+  verity_dev.Release();
+  loop.CloseGood();
+  scope_guard.Disable();
+
+  auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
+                          boot_clock::now() - time_started)
+                          .count();
+  LOG(VERBOSE) << "Successfully mounted package " << full_path << " on "
+               << mount_point << " duration=" << time_elapsed;
+  return apex_data;
+}
 
 }  // namespace
 
@@ -534,28 +597,16 @@ Result<void> Unmount(const MountedApexData& data, bool deferred) {
     }
   }
 
-  // Try to free up the device-mapper device.
-  if (!data.device_name.empty()) {
-    const auto& result = DeleteDmDevice(data.device_name, deferred);
-    if (!result.ok()) {
-      return result;
-    }
+  // Try to free up the device-mapper devices.
+  if (!data.verity_name.empty()) {
+    OR_RETURN(DeleteDmDevice(data.verity_name, deferred));
   }
-
-  // Try to free up the loop device.
-  auto log_fn = [](const std::string& path, const std::string& /*id*/) {
-    LOG(VERBOSE) << "Freeing loop device " << path << " for unmount.";
-  };
-
-  // Since we now use LO_FLAGS_AUTOCLEAR when configuring loop devices, in
-  // theory we don't need to manually call DestroyLoopDevice here even if
-  // |deferred| is false. However we prefer to call it to ensure the invariant
-  // of SubmitStagedSession (after it's done, loop devices created for temp
-  // mount are freed).
-  if (!data.loop_name.empty() && !deferred) {
-    loop::DestroyLoopDevice(data.loop_name, log_fn);
+  if (!data.linear_name.empty()) {
+    OR_RETURN(DeleteDmDevice(data.linear_name, deferred));
   }
 
+  // Since we now use LO_FLAGS_AUTOCLEAR when configuring loop devices, we don't
+  // need to manually clear the loop here. (umount2 above will clear the loop.)
   return {};
 }
 
@@ -586,7 +637,8 @@ auto RunVerifyFnInsideTempMounts(std::span<const ApexFile> apex_files,
     auto device_name = package_id + ".tmp";
 
     LOG(DEBUG) << "Temp mounting " << package_id << " to " << mount_point;
-    auto data = OR_RETURN(MountPackageImpl(apex, mount_point, device_name,
+    auto data = OR_RETURN(MountPackageImpl(apex, mount_point, loop::kFreeLoopId,
+                                           device_name,
                                            /*verify_image=*/true,
                                            /*reuse_device=*/false));
     mount_points.push_back(mount_point);
@@ -672,13 +724,10 @@ Result<void> VerifyVndkVersion(const ApexFile& apex_file) {
 // This function should only verification checks that are necessary to run on
 // each boot. Try to avoid putting expensive checks inside this function.
 Result<void> VerifyPackageBoot(const ApexFile& apex_file) {
-  // TODO(ioffe): why do we need this here?
-  const auto& public_key =
-      OR_RETURN(apexd_private::GetVerifiedPublicKey(apex_file));
-  Result<ApexVerityData> verity_or = apex_file.VerifyApexVerity(public_key);
-  if (!verity_or.ok()) {
-    return verity_or.error();
-  }
+  // Verify bundled key against preinstalled data
+  OR_RETURN(apexd_private::CheckBundledPublicKeyMatchesPreinstalled(apex_file));
+  // Verify bundled key against apex itself
+  OR_RETURN(apex_file.VerifyApexVerity(apex_file.GetBundledPublicKey()));
 
   if (shim::IsShimApex(apex_file)) {
     // Validating shim is not a very cheap operation, but it's fine to perform
@@ -700,11 +749,6 @@ Result<void> VerifyPackageBoot(const ApexFile& apex_file) {
 Result<void> VerifyNoOverlapInSessions(std::span<const ApexFile> apex_files,
                                        std::span<const ApexSession> sessions) {
   for (const auto& session : sessions) {
-    // We don't want to install/stage while another session is being staged.
-    if (session.GetState() == SessionState::VERIFIED) {
-      return Error() << "Session " << session.GetId() << " is being staged.";
-    }
-
     // We don't want to install/stage if the same package is already staged.
     if (session.GetState() == SessionState::STAGED) {
       for (const auto& apex : apex_files) {
@@ -732,19 +776,20 @@ Result<VerificationResult> VerifyPackagesStagedInstall(
     const std::vector<ApexFile>& apex_files) {
   for (const auto& apex_file : apex_files) {
     OR_RETURN(VerifyPackageBoot(apex_file));
+  }
 
-    // Extra verification for brand-new APEX. The case that brand-new APEX is
-    // not enabled when there is install request for brand-new APEX is already
-    // covered in |VerifyPackageBoot|.
-    if (ApexFileRepository::IsBrandNewApexEnabled()) {
-      OR_RETURN(VerifyBrandNewPackageAgainstActive(apex_file));
+  // Extra verification for brand-new APEX. The case that brand-new APEX is
+  // not enabled when there is install request for brand-new APEX is already
+  // covered in |VerifyPackageBoot|.
+  if (ApexFileRepository::IsBrandNewApexEnabled()) {
+    for (const auto& apex_file : apex_files) {
+      OR_RETURN(VerifyBrandNewPackageAgainstActive(apex_file, gMountedApexes));
     }
   }
 
   auto sessions = gSessionManager->GetSessions();
 
   // Check overlapping: reject if the same package is already staged
-  // or if there's a session being staged.
   OR_RETURN(VerifyNoOverlapInSessions(apex_files, sessions));
 
   // Since there can be multiple staged sessions, let's verify incoming APEXes
@@ -919,9 +964,7 @@ Result<void> UnmountPackage(const ApexFile& apex, bool allow_latest,
     return Error() << "Did not find " << apex.GetPath();
   }
 
-  // Concept of latest sharedlibs apex is somewhat blurred. Since this is only
-  // used in testing, it is ok to always allow unmounting sharedlibs apex.
-  if (latest && !manifest.providesharedapexlibs()) {
+  if (latest) {
     if (!allow_latest) {
       return Error() << "Package " << apex.GetPath() << " is active";
     }
@@ -952,8 +995,9 @@ Result<void> UnmountPackage(const ApexFile& apex, bool allow_latest,
 void SetConfig(const ApexdConfig& config) { gConfig = config; }
 
 Result<void> MountPackage(const ApexFile& apex, const std::string& mount_point,
-                          const std::string& device_name, bool reuse_device) {
-  auto ret = MountPackageImpl(apex, mount_point, device_name,
+                          int32_t loop_id, const std::string& device_name,
+                          bool reuse_device) {
+  auto ret = MountPackageImpl(apex, mount_point, loop_id, device_name,
                               /* verify_image = */ false, reuse_device);
   if (!ret.ok()) {
     return ret.error();
@@ -965,17 +1009,25 @@ Result<void> MountPackage(const ApexFile& apex, const std::string& mount_point,
 
 namespace apexd_private {
 
-Result<std::string> GetVerifiedPublicKey(const ApexFile& apex) {
-  auto preinstalled_public_key =
-      ApexFileRepository::GetInstance().GetPublicKey(apex.GetManifest().name());
-  if (preinstalled_public_key.ok()) {
-    return *preinstalled_public_key;
-  } else if (ApexFileRepository::IsBrandNewApexEnabled() &&
-             VerifyBrandNewPackageAgainstPreinstalled(apex).ok()) {
-    return apex.GetBundledPublicKey();
+Result<void> CheckBundledPublicKeyMatchesPreinstalled(const ApexFile& apex) {
+  const auto& name = apex.GetManifest().name();
+  // Check if the bundled key matches the preinstalled one.
+  auto preinstalled =
+      ApexFileRepository::GetInstance().GetPreInstalledApex(name);
+  if (preinstalled.has_value()) {
+    if (preinstalled->get().GetBundledPublicKey() ==
+        apex.GetBundledPublicKey()) {
+      return {};
+    }
+    return Error() << "public key doesn't match the pre-installed one";
+  }
+  if (ApexFileRepository::IsBrandNewApexEnabled()) {
+    if (VerifyBrandNewPackageAgainstPreinstalled(apex).ok()) {
+      return {};
+    }
   }
   return Error() << "No preinstalled apex found for unverified package "
-                 << apex.GetManifest().name();
+                 << name;
 }
 
 bool IsMounted(const std::string& full_path) {
@@ -1013,111 +1065,6 @@ Result<void> ResumeRevertIfNeeded() {
   return RevertActiveSessions("", "");
 }
 
-Result<void> ContributeToSharedLibs(const std::string& mount_point) {
-  for (const auto& lib_path : {"lib", "lib64"}) {
-    std::string apex_lib_path = mount_point + "/" + lib_path;
-    auto lib_dir = PathExists(apex_lib_path);
-    if (!lib_dir.ok() || !*lib_dir) {
-      continue;
-    }
-
-    auto iter = std::filesystem::directory_iterator(apex_lib_path);
-    std::error_code ec;
-
-    while (iter != std::filesystem::end(iter)) {
-      const auto& lib_entry = *iter;
-      if (!lib_entry.is_directory()) {
-        iter = iter.increment(ec);
-        if (ec) {
-          return Error() << "Failed to scan " << apex_lib_path << " : "
-                         << ec.message();
-        }
-        continue;
-      }
-
-      const auto library_name = lib_entry.path().filename();
-      const std::string library_symlink_dir =
-          StringPrintf("%s/%s/%s/%s", kApexRoot, kApexSharedLibsSubDir,
-                       lib_path, library_name.c_str());
-
-      auto symlink_dir = PathExists(library_symlink_dir);
-      if (!symlink_dir.ok() || !*symlink_dir) {
-        std::filesystem::create_directory(library_symlink_dir, ec);
-        if (ec) {
-          return Error() << "Failed to create directory " << library_symlink_dir
-                         << ": " << ec.message();
-        }
-      }
-
-      auto inner_iter =
-          std::filesystem::directory_iterator(lib_entry.path().string());
-
-      while (inner_iter != std::filesystem::end(inner_iter)) {
-        const auto& lib_items = *inner_iter;
-        const auto hash_value = lib_items.path().filename();
-        const std::string library_symlink_hash = StringPrintf(
-            "%s/%s", library_symlink_dir.c_str(), hash_value.c_str());
-
-        auto hash_dir = PathExists(library_symlink_hash);
-        if (hash_dir.ok() && *hash_dir) {
-          // Compare file size for two library files with same name and hash
-          // value
-          auto existing_file_path =
-              library_symlink_hash + "/" + library_name.string();
-          auto existing_file_size = GetFileSize(existing_file_path);
-          if (!existing_file_size.ok()) {
-            return existing_file_size.error();
-          }
-
-          auto new_file_path =
-              lib_items.path().string() + "/" + library_name.string();
-          auto new_file_size = GetFileSize(new_file_path);
-          if (!new_file_size.ok()) {
-            return new_file_size.error();
-          }
-
-          if (*existing_file_size != *new_file_size) {
-            return Error() << "There are two libraries with same hash and "
-                              "different file size : "
-                           << existing_file_path << " and " << new_file_path;
-          }
-
-          inner_iter = inner_iter.increment(ec);
-          if (ec) {
-            return Error() << "Failed to scan " << lib_entry.path().string()
-                           << " : " << ec.message();
-          }
-          continue;
-        }
-        std::filesystem::create_directory_symlink(lib_items.path(),
-                                                  library_symlink_hash, ec);
-        if (ec) {
-          return Error() << "Failed to create symlink from " << lib_items.path()
-                         << " to " << library_symlink_hash << ec.message();
-        }
-
-        inner_iter = inner_iter.increment(ec);
-        if (ec) {
-          return Error() << "Failed to scan " << lib_entry.path().string()
-                         << " : " << ec.message();
-        }
-      }
-
-      iter = iter.increment(ec);
-      if (ec) {
-        return Error() << "Failed to scan " << apex_lib_path << " : "
-                       << ec.message();
-      }
-    }
-  }
-
-  return {};
-}
-
-bool IsValidPackageName(const std::string& package_name) {
-  return kBannedApexName.count(package_name) == 0;
-}
-
 // Activates given APEX file.
 //
 // In a nutshel activation of an APEX consist of the following steps:
@@ -1128,21 +1075,11 @@ bool IsValidPackageName(const std::string& package_name) {
 //   4. Mount the dm-verity device on that mount point.
 //     4.1 In case APEX file comes from a partition that is already
 //       dm-verity protected (e.g. /system) then we mount the loop device.
-//
-//
-// Note: this function only does the job to activate this single APEX.
-// In case this APEX file contributes to the /apex/sharedlibs mount point, then
-// you must also call ContributeToSharedLibs after finishing activating all
-// APEXes. See ActivateApexPackages for more context.
-Result<void> ActivatePackageImpl(const ApexFile& apex_file,
+
+Result<void> ActivatePackageImpl(const ApexFile& apex_file, int32_t loop_id,
                                  const std::string& device_name,
                                  bool reuse_device) {
   ATRACE_NAME("ActivatePackageImpl");
-  const ApexManifest& manifest = apex_file.GetManifest();
-
-  if (!IsValidPackageName(manifest.name())) {
-    return Errorf("Package name {} is not allowed.", manifest.name());
-  }
 
   // Validate upgraded shim apex
   if (shim::IsShimApex(apex_file) &&
@@ -1159,28 +1096,19 @@ Result<void> ActivatePackageImpl(const ApexFile& apex_file,
   // See whether we think it's active, and do not allow to activate the same
   // version. Also detect whether this is the highest version.
   // We roll this into a single check.
+  const ApexManifest& manifest = apex_file.GetManifest();
   bool version_found_mounted = false;
   {
-    uint64_t new_version = manifest.version();
+    int64_t new_version = manifest.version();
     bool version_found_active = false;
     gMountedApexes.ForallMountedApexes(
         manifest.name(), [&](const MountedApexData& data, bool latest) {
-          Result<ApexFile> other_apex = ApexFile::Open(data.full_path);
-          if (!other_apex.ok()) {
-            return;
-          }
-          if (static_cast<uint64_t>(other_apex->GetManifest().version()) ==
-              new_version) {
+          if (data.version == new_version) {
             version_found_mounted = true;
             version_found_active = latest;
           }
         });
-    // If the package provides shared libraries to other APEXs, we need to
-    // activate all versions available (i.e. preloaded on /system/apex and
-    // available on /data/apex/active). The reason is that there might be some
-    // APEXs loaded from /system/apex that reference the libraries contained on
-    // the preloaded version of the apex providing shared libraries.
-    if (version_found_active && !manifest.providesharedapexlibs()) {
+    if (version_found_active) {
       LOG(DEBUG) << "Package " << manifest.name() << " with version "
                  << manifest.version() << " already active";
       return {};
@@ -1191,26 +1119,23 @@ Result<void> ActivatePackageImpl(const ApexFile& apex_file,
       apexd_private::GetPackageMountPoint(manifest);
 
   if (!version_found_mounted) {
-    auto mount_status =
-        MountPackage(apex_file, mount_point, device_name, reuse_device);
+    auto mount_status = MountPackage(apex_file, mount_point, loop_id,
+                                     device_name, reuse_device);
     if (!mount_status.ok()) {
       return mount_status;
     }
   }
 
-  // Bind mount the latest version to /apex/<package_name>, unless the
-  // package provides shared libraries to other APEXs.
-  if (!manifest.providesharedapexlibs()) {
-    auto st = gMountedApexes.DoIfLatest(
-        manifest.name(), apex_file.GetPath(), [&]() -> Result<void> {
-          return apexd_private::BindMount(
-              apexd_private::GetActiveMountPoint(manifest), mount_point);
-        });
-    if (!st.ok()) {
-      return Error() << "Failed to update package " << manifest.name()
-                     << " to version " << manifest.version() << " : "
-                     << st.error();
-    }
+  // Bind mount the latest version to /apex/<package_name>.
+  auto st = gMountedApexes.DoIfLatest(
+      manifest.name(), apex_file.GetPath(), [&]() -> Result<void> {
+        return apexd_private::BindMount(
+            apexd_private::GetActiveMountPoint(manifest), mount_point);
+      });
+  if (!st.ok()) {
+    return Error() << "Failed to update package " << manifest.name()
+                   << " to version " << manifest.version() << " : "
+                   << st.error();
   }
 
   LOG(DEBUG) << "Successfully activated " << apex_file.GetPath()
@@ -1228,7 +1153,8 @@ Result<void> ActivatePackage(const std::string& full_path) {
   if (!apex_file.ok()) {
     return apex_file.error();
   }
-  return ActivatePackageImpl(*apex_file, GetPackageId(apex_file->GetManifest()),
+  return ActivatePackageImpl(*apex_file, loop::kFreeLoopId,
+                             GetPackageId(apex_file->GetManifest()),
                              /* reuse_device= */ false);
 }
 
@@ -1324,27 +1250,31 @@ std::vector<ApexFile> GetActivePackages() {
   return ret;
 }
 
-std::vector<ApexFile> CalculateInactivePackages(
-    const std::vector<ApexFile>& active) {
-  std::vector<ApexFile> inactive = GetFactoryPackages();
+std::vector<ApexFileRef> CalculateInactivePackages(
+    const std::vector<ApexFileRef>& active_apexes) {
+  std::set<std::string> active_preinstalled_names;
+  auto& repo = ApexFileRepository::GetInstance();
+  for (const auto& apex : active_apexes) {
+    if (repo.IsPreInstalledApex(apex)) {
+      active_preinstalled_names.insert(apex.get().GetManifest().name());
+    }
+  }
+
+  std::vector<ApexFileRef> inactive = repo.GetPreInstalledApexFiles();
   auto new_end = std::remove_if(
-      inactive.begin(), inactive.end(), [&active](const ApexFile& apex) {
-        return std::any_of(active.begin(), active.end(),
-                           [&apex](const ApexFile& active_apex) {
-                             return apex.GetPath() == active_apex.GetPath();
-                           });
+      inactive.begin(), inactive.end(), [&](const ApexFile& apex) {
+        return active_preinstalled_names.contains(apex.GetManifest().name());
       });
   inactive.erase(new_end, inactive.end());
   return inactive;
 }
 
-Result<void> EmitApexInfoList(bool is_bootstrap) {
-  std::vector<ApexFile> active{GetActivePackages()};
-
-  std::vector<ApexFile> inactive;
+void EmitApexInfoList(const std::vector<ApexFileRef>& active,
+                      bool is_bootstrap) {
+  std::vector<ApexFileRef> inactive;
   // we skip for non-activated built-in apexes in bootstrap mode
   // in order to avoid boottime increase
-  if (!is_bootstrap) {
+  if (IsMountBeforeDataEnabled() || !is_bootstrap) {
     inactive = CalculateInactivePackages(active);
   }
 
@@ -1354,29 +1284,14 @@ Result<void> EmitApexInfoList(bool is_bootstrap) {
   unique_fd fd(TEMP_FAILURE_RETRY(
       open(kApexInfoList, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)));
   if (fd.get() == -1) {
-    return ErrnoErrorf("Can't open {}", kApexInfoList);
+    PLOG(ERROR) << "Can't open " << kApexInfoList;
+    return;
   }
   if (!android::base::WriteStringToFd(xml.str(), fd)) {
-    return ErrnoErrorf("Can't write to {}", kApexInfoList);
-  }
-
-  fd.reset();
-  return RestoreconPath(kApexInfoList);
-}
-
-namespace {
-std::unordered_map<std::string, uint64_t> GetActivePackagesMap() {
-  std::vector<ApexFile> active_packages = GetActivePackages();
-  std::unordered_map<std::string, uint64_t> ret;
-  for (const auto& package : active_packages) {
-    const ApexManifest& manifest = package.GetManifest();
-    ret.insert({manifest.name(), manifest.version()});
+    PLOG(ERROR) << "Can't write to " << kApexInfoList;
   }
-  return ret;
 }
 
-}  // namespace
-
 std::vector<ApexFile> GetFactoryPackages() {
   std::vector<ApexFile> ret;
 
@@ -1447,182 +1362,140 @@ namespace {
 
 enum ActivationMode { kBootstrapMode = 0, kBootMode, kOtaChrootMode, kVmMode };
 
-std::vector<Result<const ApexFile*>> ActivateApexWorker(
-    ActivationMode mode, std::queue<const ApexFile*>& apex_queue,
-    std::mutex& mutex) {
-  ATRACE_NAME("ActivateApexWorker");
-  std::vector<Result<const ApexFile*>> ret;
+Result<void> ActivateApex(const ApexFile& apex, ActivationMode mode,
+                          size_t index) {
+  ATRACE_NAME("ActivateApex");
+  int32_t loop_id = loop::kFreeLoopId;
+  if (mode == ActivationMode::kBootstrapMode) {
+    // Bootstrap mode needs to be very fast in a normal situation (no errors).
+    // Creating a loop device can be faster by specifying an ID. Since this is a
+    // bootstrap mode, we can assume that the range of indexes [0..) are free.
+    loop_id = static_cast<int32_t>(index);
+  }
+  std::string device_name;
+  if (mode == ActivationMode::kBootMode) {
+    device_name = apex.GetManifest().name();
+  } else {
+    device_name = GetPackageId(apex.GetManifest());
+  }
+  if (mode == ActivationMode::kOtaChrootMode) {
+    device_name += ".chroot";
+  }
+  bool reuse_device = mode == ActivationMode::kBootMode;
+  return ActivatePackageImpl(apex, loop_id, device_name, reuse_device);
+}
 
-  while (true) {
-    const ApexFile* apex;
-    {
-      std::lock_guard lock(mutex);
-      if (apex_queue.empty()) break;
-      apex = apex_queue.front();
-      apex_queue.pop();
-    }
-
-    std::string device_name;
-    if (mode == ActivationMode::kBootMode) {
-      device_name = apex->GetManifest().name();
-    } else {
-      device_name = GetPackageId(apex->GetManifest());
-    }
-    if (mode == ActivationMode::kOtaChrootMode) {
-      device_name += ".chroot";
-    }
-    bool reuse_device = mode == ActivationMode::kBootMode;
-    auto res = ActivatePackageImpl(*apex, device_name, reuse_device);
-    if (!res.ok()) {
-      ret.push_back(Error() << "Failed to activate " << apex->GetPath() << "("
-                            << device_name << "): " << res.error());
-    } else {
-      ret.push_back({apex});
+struct ActivationContext {
+  std::unordered_map<std::string, ApexFile> decompressed_apex_store;
+  // Wrapper to ProcessCompressedApex to keep the ApexFile object in the store
+  Result<ApexFileRef> DecompressApex(const ApexFile& capex,
+                                     bool is_ota_chroot) {
+    auto name = capex.GetManifest().name();
+    auto it = decompressed_apex_store.find(name);
+    if (it != decompressed_apex_store.end()) {
+      return std::cref(it->second);
     }
+    auto decompressed = OR_RETURN(ProcessCompressedApex(capex, is_ota_chroot));
+    auto pair = decompressed_apex_store.emplace(name, std::move(decompressed));
+    return std::cref(pair.first->second);
   }
+};
 
-  return ret;
-}
+// Custom result type for ActivateApexPackages()
+struct ActivationResult {
+  std::vector<ApexFileRef> activated;
+  std::vector<ApexFileRef> failed;
+  std::string error_message;
 
-Result<void> ActivateApexPackages(const std::vector<ApexFileRef>& apexes,
-                                  ActivationMode mode) {
-  ATRACE_NAME("ActivateApexPackages");
-  std::queue<const ApexFile*> apex_queue;
-  std::mutex apex_queue_mutex;
+  bool ok() const { return failed.empty(); }
+  const std::string& error() const { return error_message; }
+};
 
-  for (const ApexFile& apex : apexes) {
-    apex_queue.emplace(&apex);
+ActivationResult ActivateApexPackages(ActivationContext& ctx,
+                                      const std::vector<ApexFileRef>& apexes,
+                                      ActivationMode mode) {
+  ATRACE_NAME("ActivateApexPackages");
+  size_t apex_cnt = apexes.size();
+  std::vector<Result<ApexFileRef>> results;
+  results.reserve(apex_cnt);
+
+  // Decompress compressed apexes, if any, only in supported modes.
+  // TODO(b/179248390) do this in parallel
+  bool compressed_apex_supported = mode == ActivationMode::kBootMode ||
+                                   mode == ActivationMode::kOtaChrootMode;
+  bool is_ota_chroot = mode == ActivationMode::kOtaChrootMode;
+  for (const auto& apex : apexes) {
+    if (apex.get().IsCompressed() && compressed_apex_supported) {
+      results.push_back(ctx.DecompressApex(apex, is_ota_chroot));
+    } else {
+      results.push_back(apex);
+    }
   }
 
   size_t worker_num =
       android::sysprop::ApexProperties::boot_activation_threads().value_or(0);
-
   // Setting number of workers to the number of packages to load
   // This seems to provide the best performance
   if (worker_num == 0) {
-    worker_num = apex_queue.size();
-  }
-  worker_num = std::min(apex_queue.size(), worker_num);
-
-  std::vector<std::future<std::vector<Result<const ApexFile*>>>> futures;
-  futures.reserve(worker_num);
-  for (size_t i = 0; i < worker_num; i++) {
-    futures.push_back(std::async(std::launch::async, ActivateApexWorker,
-                                 std::ref(mode), std::ref(apex_queue),
-                                 std::ref(apex_queue_mutex)));
+    worker_num = apex_cnt;
+  } else {
+    worker_num = std::min(apex_cnt, worker_num);
   }
 
-  size_t activated_cnt = 0;
-  size_t failed_cnt = 0;
-  std::string error_message;
-  std::vector<const ApexFile*> activated_sharedlibs_apexes;
-  for (size_t i = 0; i < futures.size(); i++) {
-    for (const auto& res : futures[i].get()) {
-      if (res.ok()) {
-        ++activated_cnt;
-        if (res.value()->GetManifest().providesharedapexlibs()) {
-          activated_sharedlibs_apexes.push_back(res.value());
-        }
-      } else {
-        ++failed_cnt;
-        LOG(ERROR) << res.error();
-        if (failed_cnt == 1) {
-          error_message = res.error().message();
-        }
+  ForEachParallel(worker_num, 0uz, apex_cnt, [&](size_t index) {
+    if (results[index].ok()) {
+      auto status = ActivateApex(*results[index], mode, index);
+      if (!status.ok()) {
+        results[index] = status.error();
       }
     }
-  }
+  });
 
-  // We finished activation of APEX packages and now are ready to populate the
-  // /apex/sharedlibs mount point. Since there can be multiple different APEXes
-  // contributing to shared libs (at the point of writing this comment there can
-  // be up 2 APEXes: pre-installed sharedlibs APEX and its updated counterpart)
-  // we need to call ContributeToSharedLibs sequentially to avoid potential race
-  // conditions. See b/240291921
-  const auto& apex_repo = ApexFileRepository::GetInstance();
-  // To make things simpler we also provide an order in which APEXes contribute
-  // to sharedlibs.
-  auto cmp = [&apex_repo](const auto& apex_a, const auto& apex_b) {
-    // An APEX with higher version should contribute first
-    if (apex_a->GetManifest().version() != apex_b->GetManifest().version()) {
-      return apex_a->GetManifest().version() > apex_b->GetManifest().version();
-    }
-    // If they have the same version, then we pick the updated APEX first.
-    return !apex_repo.IsPreInstalledApex(*apex_a);
-  };
-  std::sort(activated_sharedlibs_apexes.begin(),
-            activated_sharedlibs_apexes.end(), cmp);
-  for (const auto& sharedlibs_apex : activated_sharedlibs_apexes) {
-    LOG(DEBUG) << "Populating sharedlibs with APEX "
-               << sharedlibs_apex->GetPath() << " ( "
-               << sharedlibs_apex->GetManifest().name()
-               << " ) version : " << sharedlibs_apex->GetManifest().version();
-    auto mount_point =
-        apexd_private::GetPackageMountPoint(sharedlibs_apex->GetManifest());
-    if (auto ret = ContributeToSharedLibs(mount_point); !ret.ok()) {
-      LOG(ERROR) << "Failed to populate sharedlibs with APEX package "
-                 << sharedlibs_apex->GetPath() << " : " << ret.error();
-      ++failed_cnt;
-      if (failed_cnt == 1) {
-        error_message = ret.error().message();
+  ActivationResult activation_result;
+  for (size_t i = 0; i < apex_cnt; ++i) {
+    auto& res = results[i];
+    if (res.ok()) {
+      activation_result.activated.push_back(*res);
+    } else {
+      LOG(ERROR) << res.error();
+      activation_result.failed.push_back(apexes[i]);
+      if (activation_result.failed.size() == 1) {
+        activation_result.error_message = res.error().message();
       }
     }
   }
-
-  if (failed_cnt > 0) {
-    return Error() << "Failed to activate " << failed_cnt
-                   << " APEX packages. One of the errors: " << error_message;
-  }
-  LOG(INFO) << "Activated " << activated_cnt << " packages.";
-  return {};
+  LOG(INFO) << "Activated " << activation_result.activated.size()
+            << " packages.";
+  return activation_result;
 }
 
 // A fallback function in case some of the apexes failed to activate. For all
 // such apexes that were coming from /data partition we will attempt to activate
 // their corresponding pre-installed copies.
-Result<void> ActivateMissingApexes(const std::vector<ApexFileRef>& apexes,
-                                   ActivationMode mode) {
+ActivationResult ActivateMissingApexes(ActivationContext& ctx,
+                                       const std::vector<ApexFileRef>& failed,
+                                       ActivationMode mode) {
   LOG(INFO) << "Trying to activate pre-installed versions of missing apexes";
   const auto& file_repository = ApexFileRepository::GetInstance();
-  const auto& activated_apexes = GetActivePackagesMap();
   std::vector<ApexFileRef> fallback_apexes;
-  for (const auto& apex_ref : apexes) {
-    const auto& apex = apex_ref.get();
-    if (apex.GetManifest().providesharedapexlibs()) {
-      // We must mount both versions of sharedlibs apex anyway. Not much we can
-      // do here.
-      continue;
-    }
+  for (const auto& apex : failed) {
     if (file_repository.IsPreInstalledApex(apex)) {
       // We tried to activate pre-installed apex in the first place. No need to
       // try again.
       continue;
     }
-    const std::string& name = apex.GetManifest().name();
-    if (activated_apexes.find(name) == activated_apexes.end()) {
-      fallback_apexes.push_back(file_repository.GetPreInstalledApex(name));
+    const std::string& name = apex.get().GetManifest().name();
+    auto preinstalled = file_repository.GetPreInstalledApex(name);
+    if (!preinstalled.has_value()) {
+      // Not every apex has preinstalled.
+      CHECK(ApexFileRepository::IsBrandNewApexEnabled() ||
+            file_repository.IsBlockApex(apex))
+          << "No preinstalled APEX found for " << name;
+      continue;
     }
+    fallback_apexes.push_back(preinstalled.value());
   }
 
-  // Process compressed APEX, if any
-  std::vector<ApexFileRef> compressed_apex;
-  for (auto it = fallback_apexes.begin(); it != fallback_apexes.end();) {
-    if (it->get().IsCompressed()) {
-      compressed_apex.emplace_back(*it);
-      it = fallback_apexes.erase(it);
-    } else {
-      it++;
-    }
-  }
-  std::vector<ApexFile> decompressed_apex;
-  if (!compressed_apex.empty()) {
-    decompressed_apex = ProcessCompressedApex(
-        compressed_apex,
-        /* is_ota_chroot= */ mode == ActivationMode::kOtaChrootMode);
-    for (const ApexFile& apex_file : decompressed_apex) {
-      fallback_apexes.emplace_back(std::cref(apex_file));
-    }
-  }
   if (mode == kBootMode) {
     // Treat fallback to pre-installed APEXes as a change of the acitve APEX,
     // since we are already in a pretty dire situation, so it's better if we
@@ -1631,7 +1504,7 @@ Result<void> ActivateMissingApexes(const std::vector<ApexFileRef>& apexes,
       gChangedActiveApexes.insert(apex.get().GetManifest().name());
     }
   }
-  return ActivateApexPackages(fallback_apexes, mode);
+  return ActivateApexPackages(ctx, fallback_apexes, mode);
 }
 
 }  // namespace
@@ -1870,7 +1743,77 @@ void DeleteDePreRestoreSnapshots(const ApexSession& session) {
   }
 }
 
-void OnBootCompleted() { ApexdLifecycle::GetInstance().MarkBootCompleted(); }
+void MarkBootCompleted() { ApexdLifecycle::GetInstance().MarkBootCompleted(); }
+
+// Moves all apexes in the session to "active" state in a transactional manner.
+// Returns the name list of the apexes in the session on success.
+Result<std::vector<std::string>> TryActivateStagedSession(
+    const ApexSession& session) {
+  std::string build_fingerprint = GetProperty(kBuildFingerprintSysprop, "");
+  if (session.GetBuildFingerprint().compare(build_fingerprint) != 0) {
+    return Error() << "APEX build fingerprint has changed";
+  }
+
+  // If device supports fs-checkpoint, then apex session should only be
+  // installed when in checkpoint-mode. Otherwise, we will not be able to
+  // revert /data on error.
+  if (gSupportsFsCheckpoints && !gInFsCheckpointMode) {
+    return Error()
+           << "Cannot install apex session if not in fs-checkpoint mode";
+  }
+
+  if (IsMountBeforeDataEnabled()) {
+    if (session.GetApexImages().empty()) {
+      return Error() << "No apex found in session";
+    }
+    auto image_manager = GetImageManager();
+    std::vector<std::string> images{std::from_range, session.GetApexImages()};
+
+    auto unmap_devices = base::make_scope_guard([&]() {
+      for (const auto& image : images) {
+        auto unmap = image_manager->UnmapImageIfExists(image);
+        if (!unmap.ok()) {
+          LOG(ERROR) << unmap.error();
+        }
+      }
+    });
+
+    std::vector<std::string> apex_names_in_session;
+    apex_names_in_session.reserve(images.size());
+    for (const auto& image : images) {
+      auto dm_device = OR_RETURN(image_manager->MapImage(image));
+      auto apex_file = OR_RETURN(ApexFile::Open(dm_device));
+      OR_RETURN(VerifyPackageBoot(apex_file));
+
+      apex_names_in_session.push_back(apex_file.GetManifest().name());
+    }
+
+    std::vector<ApexListEntry> new_entries;
+    new_entries.reserve(images.size());
+    for (size_t i = 0; i < images.size(); i++) {
+      new_entries.emplace_back(images[i], apex_names_in_session[i]);
+    }
+    // Now, update "active" list
+    auto active_list =
+        OR_RETURN(image_manager->GetApexList(ApexListType::ACTIVE));
+    OR_RETURN(image_manager->UpdateApexList(
+        ApexListType::ACTIVE,
+        UpdateApexListWithNewEntries(std::move(active_list), new_entries)));
+
+    // Let's keep mapped devices because they needs to be mapped as "active" in
+    // ScanDataApexFiles().
+    unmap_devices.Disable();
+    return apex_names_in_session;
+  } else {
+    auto apexes = OR_RETURN(ScanSessionApexFiles(session));
+    auto packages = StagePackagesImpl(apexes);
+    if (!packages.ok()) {
+      return Error() << "Activation failed for packages "
+                     << base::Join(apexes, ", ") << ": " << packages.error();
+    }
+    return std::move(*packages);
+  }
+}
 
 // Scans all STAGED sessions and activate them so that APEXes in those sessions
 // become available for activation. Sessions are updated to be ACTIVATED state,
@@ -1878,76 +1821,45 @@ void OnBootCompleted() { ApexdLifecycle::GetInstance().MarkBootCompleted(); }
 // Note that this doesn't abort with failed sessions. Apexd just marks them as
 // failed and continues activation process. It's higher level component (e.g.
 // system_server) that needs to handle the failures.
-void ActivateStagedSessions() {
-  LOG(INFO) << "Scanning " << GetSessionsDir()
-            << " looking for sessions to be activated.";
-
-  auto sessions_to_activate =
-      gSessionManager->GetSessionsInState(SessionState::STAGED);
+void ActivateStagedSessions(std::vector<ApexSession>&& sessions) {
+  std::vector<std::reference_wrapper<ApexSession>> sessions_to_activate;
+  for (auto& session : sessions) {
+    if (session.GetState() == SessionState::STAGED) {
+      sessions_to_activate.push_back(std::ref(session));
+    }
+  }
   if (gSupportsFsCheckpoints) {
     // A session that is in the ACTIVATED state should still be re-activated if
     // fs checkpointing is supported. In this case, a session may be in the
     // ACTIVATED state yet the data/apex/active directory may have been
     // reverted. The session should be reverted in this scenario.
-    auto activated_sessions =
-        gSessionManager->GetSessionsInState(SessionState::ACTIVATED);
-    sessions_to_activate.insert(sessions_to_activate.end(),
-                                activated_sessions.begin(),
-                                activated_sessions.end());
+    for (auto& session : sessions) {
+      if (session.GetState() == SessionState::ACTIVATED) {
+        sessions_to_activate.push_back(std::ref(session));
+      }
+    }
   }
 
-  for (auto& session : sessions_to_activate) {
-    auto session_id = session.GetId();
+  LOG(INFO) << "Found " << sessions_to_activate.size()
+            << " sessions to activate";
 
-    auto session_failed_fn = [&]() {
+  for (ApexSession& session : sessions_to_activate) {
+    auto session_id = session.GetId();
+    auto packages = TryActivateStagedSession(session);
+    if (!packages.ok()) {
+      LOG(ERROR) << packages.error();
+      session.SetErrorMessage(packages.error().message());
       LOG(WARNING) << "Marking session " << session_id << " as failed.";
       auto st = session.UpdateStateAndCommit(SessionState::ACTIVATION_FAILED);
       if (!st.ok()) {
         LOG(WARNING) << "Failed to mark session " << session_id
                      << " as failed : " << st.error();
       }
-    };
-    auto scope_guard = android::base::make_scope_guard(session_failed_fn);
-
-    std::string build_fingerprint = GetProperty(kBuildFingerprintSysprop, "");
-    if (session.GetBuildFingerprint().compare(build_fingerprint) != 0) {
-      auto error_message = "APEX build fingerprint has changed";
-      LOG(ERROR) << error_message;
-      session.SetErrorMessage(error_message);
       continue;
     }
 
-    // If device supports fs-checkpoint, then apex session should only be
-    // installed when in checkpoint-mode. Otherwise, we will not be able to
-    // revert /data on error.
-    if (gSupportsFsCheckpoints && !gInFsCheckpointMode) {
-      auto error_message =
-          "Cannot install apex session if not in fs-checkpoint mode";
-      LOG(ERROR) << error_message;
-      session.SetErrorMessage(error_message);
-      continue;
-    }
-
-    auto apexes = ScanSessionApexFiles(session);
-    if (!apexes.ok()) {
-      LOG(WARNING) << apexes.error();
-      session.SetErrorMessage(apexes.error().message());
-      continue;
-    }
-
-    auto packages = StagePackagesImpl(*apexes);
-    if (!packages.ok()) {
-      std::string error_message =
-          std::format("Activation failed for packages {} : {}", *apexes,
-                      packages.error().message());
-      LOG(ERROR) << error_message;
-      session.SetErrorMessage(error_message);
-      continue;
-    }
-
-    // Session was OK, release scopeguard.
-    scope_guard.Disable();
-
+    LOG(INFO) << "Session(" << session_id
+              << ") is successfully activated: " << base::Join(*packages, ", ");
     gChangedActiveApexes.insert_range(*packages);
 
     auto st = session.UpdateStateAndCommit(SessionState::ACTIVATED);
@@ -1974,7 +1886,8 @@ Result<std::vector<std::string>> StagePackagesImpl(
   }
   LOG(DEBUG) << "StagePackagesImpl() for " << Join(tmp_paths, ',');
 
-  // Note: this function is temporary. As such the code is not optimized, e.g.,
+  // Note: this function is temporary. As such the code is not optimized,
+  // e.g.,
   //       it will open ApexFiles multiple times.
 
   // 1) Verify all packages.
@@ -2073,10 +1986,10 @@ Result<void> UnstagePackages(const std::vector<std::string>& paths) {
 }
 
 /**
- * During apex installation, staged sessions located in /metadata/apex/sessions
- * mutate the active sessions in /data/apex/active. If some error occurs during
- * installation of apex, we need to revert /data/apex/active to its original
- * state and reboot.
+ * During apex installation, staged sessions located in
+ * /metadata/apex/sessions mutate the active sessions in /data/apex/active. If
+ * some error occurs during installation of apex, we need to revert
+ * /data/apex/active to its original state and reboot.
  *
  * Also, we need to put staged sessions in /metadata/apex/sessions in
  * REVERTED state so that they do not get activated on next reboot.
@@ -2166,36 +2079,6 @@ Result<void> RevertActiveSessionsAndReboot(
   return {};
 }
 
-Result<void> CreateSharedLibsApexDir() {
-  // Creates /apex/sharedlibs/lib{,64} for SharedLibs APEXes.
-  std::string shared_libs_sub_dir =
-      StringPrintf("%s/%s", kApexRoot, kApexSharedLibsSubDir);
-  auto dir_exists = PathExists(shared_libs_sub_dir);
-  if (!dir_exists.ok() || !*dir_exists) {
-    std::error_code error_code;
-    std::filesystem::create_directory(shared_libs_sub_dir, error_code);
-    if (error_code) {
-      return Error() << "Failed to create directory " << shared_libs_sub_dir
-                     << ": " << error_code.message();
-    }
-  }
-  for (const auto& lib_path : {"lib", "lib64"}) {
-    std::string apex_lib_path =
-        StringPrintf("%s/%s", shared_libs_sub_dir.c_str(), lib_path);
-    auto lib_dir_exists = PathExists(apex_lib_path);
-    if (!lib_dir_exists.ok() || !*lib_dir_exists) {
-      std::error_code error_code;
-      std::filesystem::create_directory(apex_lib_path, error_code);
-      if (error_code) {
-        return Error() << "Failed to create directory " << apex_lib_path << ": "
-                       << error_code.message();
-      }
-    }
-  }
-
-  return {};
-}
-
 void PrepareResources(size_t loop_device_cnt,
                       const std::vector<std::string>& apex_names) {
   LOG(INFO) << "Need to pre-allocate " << loop_device_cnt << " loop devices";
@@ -2205,8 +2088,8 @@ void PrepareResources(size_t loop_device_cnt,
 
   DeviceMapper& dm = DeviceMapper::Instance();
   // Create empty dm device for each found APEX.
-  // This is a boot time optimization that makes use of the fact that user space
-  // paths will be created by ueventd before apexd is started, and hence
+  // This is a boot time optimization that makes use of the fact that user
+  // space paths will be created by ueventd before apexd is started, and hence
   // reducing the time to activate APEXEs on /data.
   // Note: since at this point we don't know which APEXes are updated, we are
   // optimistically creating a verity device for all of them. Once boot
@@ -2219,22 +2102,108 @@ void PrepareResources(size_t loop_device_cnt,
   }
 }
 
+// Note that this needs to be called before scanning data apexes because
+// revert or activation may change the active set of data apexes. For example,
+// revert restores the active apexes from the last backup.
+void ProcessSessions() {
+  auto sessions = gSessionManager->GetSessions();
+
+  if (sessions.empty()) {
+    LOG(INFO) << "No sessions to revert/activate.";
+    return;
+  }
+
+  // If there's any pending revert, revert active sessions.
+  if (std::ranges::any_of(sessions, [](const auto& session) {
+        return session.GetState() == SessionState::REVERT_IN_PROGRESS;
+      })) {
+    if (auto status = RevertActiveSessions("", ""); !status.ok()) {
+      LOG(ERROR) << "Failed to resume revert : " << status.error();
+    }
+  } else {
+    // Otherwise, activate STAGED sessions.
+    ActivateStagedSessions(std::move(sessions));
+  }
+}
+
+std::vector<ApexFile> ScanDataApexFiles(ApexImageManager* manager) {
+  CHECK(IsMountBeforeDataEnabled());
+  auto image_list = manager->GetApexList(ApexListType::ACTIVE);
+  if (!image_list.ok()) {
+    LOG(ERROR) << "Failed to get active image list : " << image_list.error();
+    return {};
+  }
+  std::vector<ApexFile> apex_files;
+  apex_files.reserve(image_list->size());
+  for (const auto& entry : *image_list) {
+    auto path = manager->MapImage(entry.image_name);
+    // Log error and keep searching for active apexes
+    if (!path.ok()) {
+      LOG(ERROR) << "Skip " << entry.image_name << ": " << path.error();
+      continue;
+    }
+    auto apex_file = ApexFile::Open(*path);
+    if (!apex_file.ok()) {
+      manager->UnmapImage(entry.image_name);
+      LOG(ERROR) << "Skip " << entry.image_name << ": " << apex_file.error();
+      continue;
+    }
+    apex_files.push_back(std::move(*apex_file));
+  }
+  return apex_files;
+}
+
+Result<void> AddPreinstalledData(ApexFileRepository& instance) {
+  if (auto status = instance.AddPreInstalledApex(gConfig->builtin_dirs);
+      !status.ok()) {
+    return Error() << "Failed to collect pre-installed APEX files: "
+                   << status.error();
+  }
+
+  if (ApexFileRepository::IsBrandNewApexEnabled()) {
+    if (auto status = instance.AddBrandNewApexCredentialAndBlocklist(
+            gConfig->brand_new_apex_config_dirs);
+        !status.ok()) {
+      return Error() << "Failed to collect pre-installed public keys and "
+                        "blocklists for brand-new APEX: "
+                     << status.error();
+    }
+  }
+  return {};
+}
+
 int OnBootstrap() {
   ATRACE_NAME("OnBootstrap");
   auto time_started = boot_clock::now();
 
   ApexFileRepository& instance = ApexFileRepository::GetInstance();
-  Result<void> status =
-      instance.AddPreInstalledApexParallel(gConfig->builtin_dirs);
-  if (!status.ok()) {
-    LOG(ERROR) << "Failed to collect APEX keys : " << status.error();
+  if (auto st = AddPreinstalledData(instance); !st.ok()) {
+    LOG(ERROR) << st.error();
     return 1;
   }
 
   std::vector<ApexFileRef> activation_list;
 
   if (IsMountBeforeDataEnabled()) {
-    activation_list = SelectApexForActivation();
+    // Wait until coldboot is done. This is to avoid unnecessary polling when
+    // using/creating loop or device-mapper devices. Note that apexd relies on
+    // devices created by init process for faster activation. Their nodes are
+    // created by ueventd's coldboot. Hence, accessing them before coldboot is
+    // done causes polling, which can be much slower than waiting for coldboot.
+    // Similarly, before coldboot is done, ueventd can't handle a device
+    // creation. This will also cause polling the userspace node creation.
+    // Instead of racing with ueventd, let's wait until it finishes coldboot.
+    base::WaitForProperty("ro.cold_boot_done", "true",
+                          std::chrono::seconds(10));
+
+    // Process sessions before scanning "active" data apexes because sessions
+    // can change the list of active data apexes:
+    // - if there's a pending revert, then reverts all active sessions.
+    // - if there's staged sessions, then activate them first.
+    ProcessSessions();
+    auto data_apexes = ScanDataApexFiles(GetImageManager());
+    instance.AddDataApexFiles(std::move(data_apexes));
+    activation_list = instance.SelectApexForActivation();
   } else {
     const auto& pre_installed_apexes = instance.GetPreInstalledApexFiles();
     size_t loop_device_cnt = pre_installed_apexes.size();
@@ -2248,28 +2217,19 @@ int OnBootstrap() {
         activation_list.push_back(apex);
         loop_device_cnt++;
       }
-      if (apex.get().GetManifest().providesharedapexlibs()) {
-        LOG(INFO) << "Found sharedlibs APEX " << apex.get().GetPath();
-        // Sharedlis APEX might be mounted 2 times:
-        //   * Pre-installed sharedlibs APEX will be mounted in OnStart
-        //   * Updated sharedlibs APEX (if it exists) will be mounted in OnStart
-        //
-        // We already counted a loop device for one of these 2 mounts, need to
-        // add 1 more.
-        loop_device_cnt++;
-      }
     }
     PrepareResources(loop_device_cnt, apex_names);
   }
 
-  auto ret =
-      ActivateApexPackages(activation_list, ActivationMode::kBootstrapMode);
-  if (!ret.ok()) {
-    LOG(ERROR) << "Failed to activate apexes: " << ret.error();
+  ActivationContext ctx;
+  auto result = ActivateApexPackages(ctx, activation_list,
+                                     ActivationMode::kBootstrapMode);
+  if (!result.ok()) {
+    LOG(ERROR) << "Failed to activate apexes: " << result.error();
     return 1;
   }
+  EmitApexInfoList(result.activated, /*is_bootstrap=*/true);
 
-  OnAllPackagesActivated(/*is_bootstrap=*/true);
   auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           boot_clock::now() - time_started)
                           .count();
@@ -2311,136 +2271,17 @@ void InitializeSessionManager(ApexSessionManager* session_manager) {
 
 void Initialize(CheckpointInterface* checkpoint_service) {
   InitializeVold(checkpoint_service);
+
   ApexFileRepository& instance = ApexFileRepository::GetInstance();
-  Result<void> status = instance.AddPreInstalledApex(gConfig->builtin_dirs);
-  if (!status.ok()) {
-    LOG(ERROR) << "Failed to collect pre-installed APEX files : "
-               << status.error();
+  if (auto status = AddPreinstalledData(instance); !status.ok()) {
+    LOG(ERROR) << "Failed to collect preinstalled data: " << status.error();
     return;
   }
 
-  if (ApexFileRepository::IsBrandNewApexEnabled()) {
-    Result<void> result = instance.AddBrandNewApexCredentialAndBlocklist(
-        kPartitionToBrandNewApexConfigDirs);
-    CHECK(result.ok()) << "Failed to collect pre-installed public keys and "
-                          "blocklists for brand-new APEX";
-  }
-
   gMountedApexes.PopulateFromMounts(
       {gConfig->active_apex_data_dir, gConfig->decompression_dir});
 }
 
-// Note: Pre-installed apex are initialized in Initialize(CheckpointInterface*)
-// TODO(b/172911822): Consolidate this with Initialize() when
-//  ApexFileRepository can act as cache and re-scanning is not expensive
-void InitializeDataApex() {
-  ApexFileRepository& instance = ApexFileRepository::GetInstance();
-  Result<void> status = instance.AddDataApex(kActiveApexPackagesDataDir);
-  if (!status.ok()) {
-    LOG(ERROR) << "Failed to collect data APEX files : " << status.error();
-    return;
-  }
-}
-
-/**
- * For every package X, there can be at most two APEX, pre-installed vs
- * installed on data. We usually select only one of these APEX for each package
- * based on the following conditions:
- *   - Package X must be pre-installed on one of the built-in directories.
- *   - If there are multiple APEX, we select the one with highest version.
- *   - If there are multiple with same version, we give priority to APEX on
- * /data partition.
- *
- * Typically, only one APEX is activated for each package, but APEX that provide
- * shared libs are exceptions. We have to activate both APEX for them.
- *
- * @return list of ApexFile that needs to be activated
- */
-std::vector<ApexFileRef> SelectApexForActivation() {
-  LOG(INFO) << "Selecting APEX for activation";
-  std::vector<ApexFileRef> activation_list;
-  const auto& instance = ApexFileRepository::GetInstance();
-  const auto& all_apex = instance.AllApexFilesByName();
-  activation_list.reserve(all_apex.size());
-  // For every package X, select which APEX to activate
-  for (auto& apex_it : all_apex) {
-    const std::string& package_name = apex_it.first;
-    const std::vector<ApexFileRef>& apex_files = apex_it.second;
-
-    if (apex_files.size() > 2 || apex_files.size() == 0) {
-      LOG(FATAL) << "Unexpectedly found more than two versions or none for "
-                    "APEX package "
-                 << package_name;
-      continue;
-    }
-
-    if (apex_files.size() == 1) {
-      LOG(DEBUG) << "Selecting the only APEX: " << package_name << " "
-                 << apex_files[0].get().GetPath();
-      activation_list.emplace_back(apex_files[0]);
-      continue;
-    }
-
-    // TODO(b/179497746): Now that we are dealing with list of reference, this
-    //  selection process can be simplified by sorting the vector.
-
-    // Given an APEX A and the version of the other APEX B, should we activate
-    // it?
-    auto select_apex = [&instance, &activation_list](
-                           const ApexFileRef& a_ref,
-                           const int version_b) mutable {
-      const ApexFile& a = a_ref.get();
-      // If A has higher version than B, then it should be activated
-      const bool higher_version = a.GetManifest().version() > version_b;
-      // If A has same version as B, then data version should get activated
-      const bool same_version_priority_to_data =
-          a.GetManifest().version() == version_b &&
-          !instance.IsPreInstalledApex(a);
-
-      // APEX that provides shared library are special:
-      //  - if preinstalled version is lower than data version, both versions
-      //    are activated.
-      //  - if preinstalled version is equal to data version, data version only
-      //    is activated.
-      //  - if preinstalled version is higher than data version, preinstalled
-      //    version only is activated.
-      const bool provides_shared_apex_libs =
-          a.GetManifest().providesharedapexlibs();
-      bool activate = false;
-      if (provides_shared_apex_libs) {
-        // preinstalled version gets activated in all cases except when same
-        // version as data.
-        if (instance.IsPreInstalledApex(a) &&
-            (a.GetManifest().version() != version_b)) {
-          LOG(DEBUG) << "Activating preinstalled shared libs APEX: "
-                     << a.GetManifest().name() << " " << a.GetPath();
-          activate = true;
-        }
-        // data version gets activated in all cases except when its version
-        // is lower than preinstalled version.
-        if (!instance.IsPreInstalledApex(a) &&
-            (a.GetManifest().version() >= version_b)) {
-          LOG(DEBUG) << "Activating shared libs APEX: "
-                     << a.GetManifest().name() << " " << a.GetPath();
-          activate = true;
-        }
-      } else if (higher_version || same_version_priority_to_data) {
-        LOG(DEBUG) << "Selecting between two APEX: " << a.GetManifest().name()
-                   << " " << a.GetPath();
-        activate = true;
-      }
-      if (activate) {
-        activation_list.emplace_back(a_ref);
-      }
-    };
-    const int version_0 = apex_files[0].get().GetManifest().version();
-    const int version_1 = apex_files[1].get().GetManifest().version();
-    select_apex(apex_files[0].get(), version_1);
-    select_apex(apex_files[1].get(), version_0);
-  }
-  return activation_list;
-}
-
 namespace {
 
 Result<ApexFile> OpenAndValidateDecompressedApex(const ApexFile& capex,
@@ -2463,6 +2304,8 @@ Result<ApexFile> OpenAndValidateDecompressedApex(const ApexFile& capex,
   return std::move(*apex);
 }
 
+}  // namespace
+
 // Process a single compressed APEX. Returns the decompressed APEX if
 // successful.
 Result<ApexFile> ProcessCompressedApex(const ApexFile& capex,
@@ -2571,41 +2414,10 @@ Result<ApexFile> ProcessCompressedApex(const ApexFile& capex,
   }
 
   gChangedActiveApexes.insert(return_apex->GetManifest().name());
-  /// Release compressed blocks in case decompression_dest is on f2fs-compressed
-  // filesystem.
-  ReleaseF2fsCompressedBlocks(decompression_dest);
 
   scope_guard.Disable();
   return return_apex;
 }
-}  // namespace
-
-/**
- * For each compressed APEX, decompress it to kApexDecompressedDir
- * and return the decompressed APEX.
- *
- * Returns list of decompressed APEX.
- */
-std::vector<ApexFile> ProcessCompressedApex(
-    const std::vector<ApexFileRef>& compressed_apex, bool is_ota_chroot) {
-  LOG(INFO) << "Processing compressed APEX";
-
-  std::vector<ApexFile> decompressed_apex_list;
-  for (const ApexFile& capex : compressed_apex) {
-    if (!capex.IsCompressed()) {
-      continue;
-    }
-
-    auto decompressed_apex = ProcessCompressedApex(capex, is_ota_chroot);
-    if (decompressed_apex.ok()) {
-      decompressed_apex_list.emplace_back(std::move(*decompressed_apex));
-      continue;
-    }
-    LOG(ERROR) << "Failed to process compressed APEX: "
-               << decompressed_apex.error();
-  }
-  return decompressed_apex_list;
-}
 
 Result<void> ValidateDecompressedApex(const ApexFile& capex,
                                       const ApexFile& apex) {
@@ -2633,6 +2445,42 @@ Result<void> ValidateDecompressedApex(const ApexFile& capex,
   return {};
 }
 
+void ActivateApexesOnStart() {
+  // Process sessions before adding data apexes.
+  // If there is any new apex to be installed on /data/app-staging, hardlink
+  // them to /data/apex/active first.
+  ProcessSessions();
+
+  auto& instance = ApexFileRepository::GetInstance();
+  if (auto status = instance.AddDataApex(gConfig->active_apex_data_dir);
+      !status.ok()) {
+    LOG(ERROR) << "Failed to collect data APEX files : " << status.error();
+  }
+
+  // Group every ApexFile on device by name
+  ActivationContext ctx;
+  auto activate_status = ActivateApexPackages(
+      ctx, instance.SelectApexForActivation(), ActivationMode::kBootMode);
+  if (!activate_status.ok()) {
+    std::string error_message = StringPrintf("Failed to activate packages: %s",
+                                             activate_status.error().c_str());
+    LOG(ERROR) << error_message;
+    Result<void> revert_status =
+        RevertActiveSessionsAndReboot("", error_message);
+    if (!revert_status.ok()) {
+      LOG(ERROR) << "Failed to revert : " << revert_status.error();
+    }
+    auto retry_status = ActivateMissingApexes(ctx, activate_status.failed,
+                                              ActivationMode::kBootMode);
+    if (!retry_status.ok()) {
+      LOG(ERROR) << retry_status.error();
+    }
+    // Collect activated apex files
+    activate_status.activated.append_range(retry_status.activated);
+  }
+  EmitApexInfoList(activate_status.activated, /*is_bootstrap=*/false);
+}
+
 void OnStart() {
   ATRACE_NAME("OnStart");
   LOG(INFO) << "Marking APEXd as starting";
@@ -2641,6 +2489,14 @@ void OnStart() {
     PLOG(ERROR) << "Failed to set " << gConfig->apex_status_sysprop << " to "
                 << kApexStatusStarting;
   }
+  if constexpr (flags::mount_before_data()) {
+    // When started with the feature(mount-before-data) enabled, make sure that
+    // the device never goes back to the migration state even if OnStart() fails
+    // to complete.
+    if (IsMountBeforeDataEnabled()) {
+      CreateMetadataConfigFile("mount_before_data");
+    }
+  }
 
   // Ask whether we should revert any active sessions; this can happen if
   // we've exceeded the retry count on a device that supports filesystem
@@ -2658,71 +2514,12 @@ void OnStart() {
     }
   }
 
-  // Create directories for APEX shared libraries.
-  auto sharedlibs_apex_dir = CreateSharedLibsApexDir();
-  if (!sharedlibs_apex_dir.ok()) {
-    LOG(ERROR) << sharedlibs_apex_dir.error();
-  }
-
-  // If there is any new apex to be installed on /data/app-staging, hardlink
-  // them to /data/apex/active first.
-  ActivateStagedSessions();
-  if (auto status = ApexFileRepository::GetInstance().AddDataApex(
-          gConfig->active_apex_data_dir);
-      !status.ok()) {
-    LOG(ERROR) << "Failed to collect data APEX files : " << status.error();
-  }
-
-  auto status = ResumeRevertIfNeeded();
-  if (!status.ok()) {
-    LOG(ERROR) << "Failed to resume revert : " << status.error();
-  }
-
-  // Group every ApexFile on device by name
-  auto activation_list = SelectApexForActivation();
-
-  // Process compressed APEX, if any
-  std::vector<ApexFileRef> compressed_apex;
-  for (auto it = activation_list.begin(); it != activation_list.end();) {
-    if (it->get().IsCompressed()) {
-      compressed_apex.emplace_back(*it);
-      it = activation_list.erase(it);
-    } else {
-      it++;
-    }
-  }
-  std::vector<ApexFile> decompressed_apex;
-  if (!compressed_apex.empty()) {
-    decompressed_apex =
-        ProcessCompressedApex(compressed_apex, /* is_ota_chroot= */ false);
-    for (const ApexFile& apex_file : decompressed_apex) {
-      activation_list.emplace_back(std::cref(apex_file));
-    }
-  }
-
-  // TODO(b/179248390): activate parallelly if possible
-  auto activate_status =
-      ActivateApexPackages(activation_list, ActivationMode::kBootMode);
-  if (!activate_status.ok()) {
-    std::string error_message =
-        StringPrintf("Failed to activate packages: %s",
-                     activate_status.error().message().c_str());
-    LOG(ERROR) << error_message;
-    Result<void> revert_status =
-        RevertActiveSessionsAndReboot("", error_message);
-    if (!revert_status.ok()) {
-      LOG(ERROR) << "Failed to revert : " << revert_status.error();
-    }
-    auto retry_status =
-        ActivateMissingApexes(activation_list, ActivationMode::kBootMode);
-    if (!retry_status.ok()) {
-      LOG(ERROR) << retry_status.error();
-    }
+  // TODO(b/381175707) until migration is finished, OnStart should activate both
+  // locations: /data/apex/active + pinned apexes
+  if (!IsMountBeforeDataEnabled()) {
+    ActivateApexesOnStart();
   }
 
-  // Clean up inactive APEXes on /data. We don't need them anyway.
-  RemoveInactiveDataApex();
-
   // Now that APEXes are mounted, snapshot or restore DE_sys data.
   SnapshotOrRestoreDeSysData();
 
@@ -2732,18 +2529,7 @@ void OnStart() {
   LOG(INFO) << "OnStart done, duration=" << time_elapsed;
 }
 
-void OnAllPackagesActivated(bool is_bootstrap) {
-  auto result = EmitApexInfoList(is_bootstrap);
-  if (!result.ok()) {
-    LOG(ERROR) << "cannot emit apex info list: " << result.error();
-  }
-
-  // Because apexd in bootstrap mode runs in blocking mode
-  // we don't have to set as activated.
-  if (is_bootstrap) {
-    return;
-  }
-
+void OnAllPackagesActivated() {
   // Set a system property to let other components know that APEXs are
   // activated, but are not yet ready to be used. init is expected to wait
   // for this status before performing configuration based on activated
@@ -2768,8 +2554,8 @@ void OnAllPackagesReady() {
                 << kApexStatusReady;
   }
   // Since apexd.status property is a system property, we expose yet another
-  // property as system_restricted_prop so that, for example, vendor can rely on
-  // the "ready" event.
+  // property as system_restricted_prop so that, for example, vendor can rely
+  // on the "ready" event.
   if (!SetProperty(kApexAllReadyProp, "true")) {
     PLOG(ERROR) << "Failed to set " << kApexAllReadyProp << " to true";
   }
@@ -2810,8 +2596,8 @@ Result<std::vector<ApexFile>> SubmitStagedSession(
     apex_images = OR_RETURN(GetImageManager()->PinApexFiles(ret));
   }
 
-  // The incoming session is now verified by apexd. From now on, apexd keeps its
-  // own session data. The session should be marked as "ready" so that it
+  // The incoming session is now verified by apexd. From now on, apexd keeps
+  // its own session data. The session should be marked as "ready" so that it
   // becomes STAGED. On next reboot, STAGED sessions become ACTIVATED, which
   // means the APEXes in those sessions are in "active" state and to be
   // activated.
@@ -2819,11 +2605,11 @@ Result<std::vector<ApexFile>> SubmitStagedSession(
   //    SubmitStagedSession     MarkStagedSessionReady
   //           |                          |
   //           V                          V
-  //         VERIFIED (created) ---------------> STAGED
-  //                                               |
-  //                                               | <-- ActivateStagedSessions
-  //                                               V
-  //                                             ACTIVATED
+  //         VERIFIED (created) ------------> STAGED
+  //                                            |
+  //                                            | <--ActivateStagedSessions
+  //                                            V
+  //                                        ACTIVATED
   //
 
   auto session = gSessionManager->CreateSession(session_id);
@@ -2847,11 +2633,6 @@ Result<std::vector<ApexFile>> SubmitStagedSession(
     return commit_status.error();
   }
 
-  for (const auto& apex : ret) {
-    // Release compressed blocks in case /data is f2fs-compressed filesystem.
-    ReleaseF2fsCompressedBlocks(apex.GetPath());
-  }
-
   event.MarkSucceeded();
 
   return ret;
@@ -2883,8 +2664,8 @@ Result<void> MarkStagedSessionSuccessful(const int session_id) {
   if (!session.ok()) {
     return session.error();
   }
-  // Only SessionState::ACTIVATED or SessionState::SUCCESS states are accepted.
-  // In the SessionState::SUCCESS state, this function is a no-op.
+  // Only SessionState::ACTIVATED or SessionState::SUCCESS states are
+  // accepted. In the SessionState::SUCCESS state, this function is a no-op.
   if (session->GetState() == SessionState::SUCCESS) {
     return {};
   } else if (session->GetState() == SessionState::ACTIVATED) {
@@ -2938,6 +2719,56 @@ void RemoveInactiveDataApex() {
       }
     }
   }
+
+  // Update the active list first and remove unused pinned images. Note that
+  // not every apex in active list is activated in case the preinstalled
+  // APEXes may have changed due to OTA.
+
+  auto image_manager = GetImageManager();
+  std::vector<ApexListEntry> active_list;
+  if (auto st = image_manager->GetApexList(ApexListType::ACTIVE); st.ok()) {
+    active_list = std::move(*st);
+  } else {
+    LOG(ERROR) << "Failed to get active apex list: " << st.error();
+    return;
+  }
+  // Remove skipped entries from ACTIVE list.
+  std::erase_if(active_list, [&](const auto& entry) {
+    auto path = image_manager->GetMappedPath(entry.image_name);
+    return !path || !apexd_private::IsMounted(path.value());
+  });
+  // Then, update the list
+  if (auto st =
+          image_manager->UpdateApexList(ApexListType::ACTIVE, active_list);
+      !st.ok()) {
+    LOG(ERROR) << "Failed to update active apex list: " << st.error();
+  }
+
+  // Now, remove unused pinned images.
+
+  // We've already checked that active_list contains what's actually activated.
+  std::unordered_set<std::string> images_in_use;
+  for (const auto& entry : active_list) {
+    images_in_use.insert(entry.image_name);
+  }
+
+  // If there are sessions not yet deleted, apex images referenced by them are
+  // also considered as being in use.
+  // TODO(b/409309264) clarify if there IS non-finalized session at this point.
+  for (const auto& session : gSessionManager->GetSessions()) {
+    images_in_use.insert_range(session.GetApexImages());
+  }
+
+  for (const auto& image : image_manager->GetAllImages()) {
+    if (images_in_use.contains(image)) {
+      continue;
+    }
+    LOG(INFO) << "Removing inactive pinned APEX image: " << image;
+    if (auto st = image_manager->UnmapAndDeleteImage(image); !st.ok()) {
+      LOG(ERROR) << "Failed to remove pinned APEX image: " << image << ": "
+                 << st.error();
+    }
+  }
 }
 
 bool IsApexDevice(const std::string& dev_name) {
@@ -2970,9 +2801,18 @@ void DeleteUnusedVerityDevices() {
   }
 }
 
-void BootCompletedCleanup() {
+void BootCompletedCleanup() REQUIRES(!gInstallLock) {
+  auto install_guard = std::scoped_lock{gInstallLock};
   gSessionManager->DeleteFinalizedSessions();
+  RemoveInactiveDataApex();
   DeleteUnusedVerityDevices();
+
+  if constexpr (flags::mount_before_data()) {
+    // Mark "migration done" by creating /metadata/apex/config/mount_before_data
+    if (IsMountBeforeDataEnabled() || CanMountBeforeDataOnNextBoot()) {
+      CreateMetadataConfigFile("mount_before_data");
+    }
+  }
 }
 
 int UnmountAll(bool also_include_staged_apexes) {
@@ -3003,7 +2843,7 @@ int UnmountAll(bool also_include_staged_apexes) {
       ret = 1;
       return;
     }
-    if (latest && !apex->GetManifest().providesharedapexlibs()) {
+    if (latest) {
       auto pos = data.mount_point.find('@');
       CHECK(pos != std::string::npos);
       std::string bind_mount = data.mount_point.substr(0, pos);
@@ -3095,14 +2935,10 @@ std::string CastPartition(ApexPartition in) {
 }
 
 void CollectApexInfoList(std::ostream& os,
-                         const std::vector<ApexFile>& active_apexs,
-                         const std::vector<ApexFile>& inactive_apexs) {
-  std::vector<com::android::apex::ApexInfo> apex_infos;
-
-  auto convert_to_autogen = [&apex_infos](const ApexFile& apex,
-                                          bool is_active) {
-    auto& instance = ApexFileRepository::GetInstance();
-
+                         const std::vector<ApexFileRef>& active_apexs,
+                         const std::vector<ApexFileRef>& inactive_apexs) {
+  auto& instance = ApexFileRepository::GetInstance();
+  auto convert = [&](const ApexFile& apex, bool is_active) {
     auto preinstalled_path =
         instance.GetPreinstalledPath(apex.GetManifest().name());
     std::optional<std::string> preinstalled_module_path;
@@ -3127,16 +2963,21 @@ void CollectApexInfoList(std::ostream& os,
         apex.GetManifest().version(), apex.GetManifest().versionname(),
         instance.IsPreInstalledApex(apex), is_active, mtime,
         apex.GetManifest().providesharedapexlibs(), partition);
-    apex_infos.emplace_back(std::move(apex_info));
+    return apex_info;
   };
+  // Note: xsdc-generated writer needs to construct the object structure, which
+  // is a bit inefficient. Here the root element is manually handled for better
+  // performance. Tests will ensure the output is well-formed.
+  // TODO: extend xsdc for streaming writer
+  os << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
+  os << "<apex-info-list>\n";
   for (const auto& apex : active_apexs) {
-    convert_to_autogen(apex, /* is_active= */ true);
+    convert(apex, /* is_active= */ true).write(os, "apex-info");
   }
   for (const auto& apex : inactive_apexs) {
-    convert_to_autogen(apex, /* is_active= */ false);
+    convert(apex, /* is_active= */ false).write(os, "apex-info");
   }
-  com::android::apex::ApexInfoList apex_info_list(apex_infos);
-  com::android::apex::write(os, apex_info_list);
+  os << "</apex-info-list>";
 }
 
 // Reserve |size| bytes in |dest_dir| by creating a zero-filled file.
@@ -3215,8 +3056,7 @@ Result<int> AddBlockApex(ApexFileRepository& instance) {
 }
 
 // When running in the VM mode, we follow the minimal start-up operations.
-// - CreateSharedLibsApexDir
-// - AddPreInstalledApex: note that CAPEXes are not supported in the VM mode
+// - AddPreInstalledData: note that CAPEXes are not supported in the VM mode
 // - AddBlockApex
 // - ActivateApexPackages
 // - setprop apexd.status: activated/ready
@@ -3226,18 +3066,10 @@ int OnStartInVmMode() {
     LOG(ERROR) << loop_ready.error();
   }
 
-  // Create directories for APEX shared libraries.
-  if (auto status = CreateSharedLibsApexDir(); !status.ok()) {
-    LOG(ERROR) << "Failed to create /apex/sharedlibs : " << status.ok();
-    return 1;
-  }
-
   auto& instance = ApexFileRepository::GetInstance();
 
-  // Scan pre-installed apexes
-  if (auto status = instance.AddPreInstalledApex(gConfig->builtin_dirs);
-      !status.ok()) {
-    LOG(ERROR) << "Failed to scan pre-installed APEX files: " << status.error();
+  if (auto status = AddPreinstalledData(instance); !status.ok()) {
+    LOG(ERROR) << "Failed collect preinstalled data: " << status.error();
     return 1;
   }
 
@@ -3246,14 +3078,16 @@ int OnStartInVmMode() {
     return 1;
   }
 
-  if (auto status = ActivateApexPackages(SelectApexForActivation(),
-                                         ActivationMode::kVmMode);
-      !status.ok()) {
-    LOG(ERROR) << "Failed to activate apex packages : " << status.error();
+  ActivationContext ctx;
+  auto result = ActivateApexPackages(ctx, instance.SelectApexForActivation(),
+                                     ActivationMode::kVmMode);
+  if (!result.ok()) {
+    LOG(ERROR) << "Failed to activate apex packages : " << result.error();
     return 1;
   }
+  EmitApexInfoList(result.activated, /*is_bootstrap=*/false);
 
-  OnAllPackagesActivated(false);
+  OnAllPackagesActivated();
   // In VM mode, we don't run a separate --snapshotde mode.
   // Instead, we mark apexd.status "ready" right now.
   OnAllPackagesReady();
@@ -3262,20 +3096,19 @@ int OnStartInVmMode() {
 
 int OnOtaChrootBootstrap(bool also_include_staged_apexes) {
   auto& instance = ApexFileRepository::GetInstance();
-  if (auto status = instance.AddPreInstalledApex(gConfig->builtin_dirs);
-      !status.ok()) {
-    LOG(ERROR) << "Failed to scan pre-installed apexes from "
-               << std::format("{}", gConfig->builtin_dirs | std::views::values);
+  if (auto status = AddPreinstalledData(instance); !status.ok()) {
+    LOG(ERROR) << "Failed to scan preinstalled data: " << status.error();
     return 1;
   }
   if (also_include_staged_apexes) {
-    // Scan staged dirs, and then scan the active dir. If a module is in both a
-    // staged dir and the active dir, the APEX with a higher version will be
-    // picked. If the versions are equal, the APEX in staged dir will be picked.
+    // Scan staged dirs, and then scan the active dir. If a module is in both
+    // a staged dir and the active dir, the APEX with a higher version will be
+    // picked. If the versions are equal, the APEX in staged dir will be
+    // picked.
     //
-    // The result is an approximation of what the active dir will actually have
-    // after the reboot. In case of a downgrade install, it differs from the
-    // actual, but this is not a supported case.
+    // The result is an approximation of what the active dir will actually
+    // have after the reboot. In case of a downgrade install, it differs from
+    // the actual, but this is not a supported case.
     for (const ApexSession& session :
          gSessionManager->GetSessionsInState(SessionState::STAGED)) {
       std::vector<std::string> dirs_to_scan =
@@ -3297,55 +3130,25 @@ int OnOtaChrootBootstrap(bool also_include_staged_apexes) {
     return 1;
   }
 
-  // Create directories for APEX shared libraries.
-  if (auto status = CreateSharedLibsApexDir(); !status.ok()) {
-    LOG(ERROR) << "Failed to create /apex/sharedlibs : " << status.ok();
-    return 1;
-  }
-
-  auto activation_list = SelectApexForActivation();
-
-  // TODO(b/179497746): This is the third time we are duplicating this code
-  // block. This will be easier to dedup once we start opening ApexFiles via
-  // ApexFileRepository. That way, ProcessCompressedApex can return list of
-  // ApexFileRef, instead of ApexFile.
-
-  // Process compressed APEX, if any
-  std::vector<ApexFileRef> compressed_apex;
-  for (auto it = activation_list.begin(); it != activation_list.end();) {
-    if (it->get().IsCompressed()) {
-      compressed_apex.emplace_back(*it);
-      it = activation_list.erase(it);
-    } else {
-      it++;
-    }
-  }
-  std::vector<ApexFile> decompressed_apex;
-  if (!compressed_apex.empty()) {
-    decompressed_apex =
-        ProcessCompressedApex(compressed_apex, /* is_ota_chroot= */ true);
-
-    for (const ApexFile& apex_file : decompressed_apex) {
-      activation_list.emplace_back(std::cref(apex_file));
-    }
-  }
-
-  auto activate_status =
-      ActivateApexPackages(activation_list, ActivationMode::kOtaChrootMode);
+  ActivationContext ctx;
+  auto activate_status = ActivateApexPackages(
+      ctx, instance.SelectApexForActivation(), ActivationMode::kOtaChrootMode);
   if (!activate_status.ok()) {
     LOG(ERROR) << "Failed to activate apex packages : "
                << activate_status.error();
-    auto retry_status =
-        ActivateMissingApexes(activation_list, ActivationMode::kOtaChrootMode);
+    auto retry_status = ActivateMissingApexes(ctx, activate_status.failed,
+                                              ActivationMode::kOtaChrootMode);
     if (!retry_status.ok()) {
       LOG(ERROR) << retry_status.error();
     }
+    // Collect activated apex files
+    activate_status.activated.append_range(retry_status.activated);
   }
-
-  if (auto status = EmitApexInfoList(/*is_bootstrap*/ false); !status.ok()) {
-    LOG(ERROR) << status.error();
+  EmitApexInfoList(activate_status.activated, /*is_bootstrap=*/false);
+  if (auto status = RestoreconPath(kApexInfoList); !status.ok()) {
+    LOG(ERROR) << "Can't restorecon " << kApexInfoList << ": "
+               << status.error();
   }
-
   return 0;
 }
 
@@ -3362,7 +3165,6 @@ Result<VerificationResult> VerifyPackageNonStagedInstall(
   auto sessions = gSessionManager->GetSessions();
 
   // Check overlapping: reject if the same package is already staged
-  // or if there's a session being staged.
   OR_RETURN(VerifyNoOverlapInSessions(Single(apex_file), sessions));
 
   auto check_fn =
@@ -3397,37 +3199,27 @@ Result<void> CheckSupportsNonStagedInstall(const ApexFile& new_apex,
 
     // Check if update will impact linkerconfig.
 
-    // Updates to shared libs APEXes must be done via staged install flow.
-    if (new_manifest.providesharedapexlibs()) {
-      return Error() << new_apex.GetPath() << " is a shared libs APEX";
-    }
-
     // This APEX provides native libs to other parts of the platform. It can
     // only be updated via staged install flow.
     if (new_manifest.providenativelibs_size() > 0) {
       return Error() << new_apex.GetPath() << " provides native libs";
     }
 
-    // This APEX requires libs provided by dynamic common library APEX, hence it
-    // can only be installed using staged install flow.
-    if (new_manifest.requiresharedapexlibs_size() > 0) {
-      return Error() << new_apex.GetPath() << " requires shared apex libs";
-    }
-
     // We don't allow non-staged updates of APEXES that have java libs inside.
     if (new_manifest.jnilibs_size() > 0) {
       return Error() << new_apex.GetPath() << " requires JNI libs";
     }
   }
 
-  auto expected_public_key =
-      ApexFileRepository::GetInstance().GetPublicKey(new_manifest.name());
-  if (!expected_public_key.ok()) {
-    return expected_public_key.error();
-  }
-  auto verity_data = new_apex.VerifyApexVerity(*expected_public_key);
-  if (!verity_data.ok()) {
-    return verity_data.error();
+  // Brand-new apexes are not supported.
+  if (ApexFileRepository::IsBrandNewApexEnabled()) {
+    // Make sure that the new apex has the preinstall one.
+    auto preinstalled = ApexFileRepository::GetInstance().GetPreInstalledApex(
+        new_manifest.name());
+    if (!preinstalled.has_value()) {
+      return Error() << "No preinstalled apex found for package "
+                     << new_manifest.name();
+    }
   }
   return {};
 }
@@ -3443,6 +3235,11 @@ Result<size_t> ComputePackageIdMinor(const ApexFile& apex) {
   size_t next_minor = 1;
   for (const auto& dm_device : dm_devices) {
     std::string_view dm_name(dm_device.name());
+    // Skip .payload and .apex dm-linear devices
+    if (dm_name.ends_with(kDmLinearPayloadSuffix) ||
+        dm_name.ends_with(kDmLinearApexSuffix)) {
+      continue;
+    }
     // Format is <module_name>@<version_code>[_<minor>]
     if (!ConsumePrefix(&dm_name, apex.GetManifest().name())) {
       continue;
@@ -3517,7 +3314,8 @@ Result<ApexFile> InstallPackage(const std::string& package_path, bool force)
   event.AddFiles(Single(*temp_apex));
 
   const std::string& module_name = temp_apex->GetManifest().name();
-  // Don't allow non-staged update if there are no active versions of this APEX.
+  // Don't allow non-staged update if there are no active versions of this
+  // APEX.
   auto cur_mounted_data = gMountedApexes.GetLatestMountedApex(module_name);
   if (!cur_mounted_data.has_value()) {
     return Error() << "No active version found for package " << module_name;
@@ -3563,71 +3361,119 @@ Result<ApexFile> InstallPackage(const std::string& package_path, bool force)
     }
   });
 
-  // 2. Unmount currently active APEX.
-  if (auto res =
-          UnmountPackage(*cur_apex, /* allow_latest= */ true,
-                         /* deferred= */ true, /* detach_mount_point= */ force);
-      !res.ok()) {
-    return res.error();
-  }
-
-  // 3. Hard link to final destination.
-  std::string target_file =
-      StringPrintf("%s/%s.apex", gConfig->active_apex_data_dir, new_id.c_str());
+  // We need a few ScopeGuards to recover the current state when something goes
+  // wrong. Note that std::vector destroys elements from the end.
+  std::vector<base::ScopeGuard<std::function<void()>>> guards;
 
-  auto guard = android::base::make_scope_guard([&]() {
-    if (unlink(target_file.c_str()) != 0 && errno != ENOENT) {
-      PLOG(ERROR) << "Failed to unlink " << target_file;
-    }
+  // 3. Unmount currently active APEX.
+  OR_RETURN(UnmountPackage(*cur_apex, /* allow_latest= */ true,
+                           /* deferred= */ true,
+                           /* detach_mount_point= */ force));
+  // Re-activate the current apex on error.
+  guards.emplace_back(base::make_scope_guard([&]() {
     // We can't really rely on the fact that dm-verity device backing up
     // previously active APEX is still around. We need to create a new one.
     std::string old_new_id = GetPackageId(temp_apex->GetManifest()) + "_" +
                              std::to_string(*new_id_minor + 1);
-    auto res = ActivatePackageImpl(*cur_apex, old_new_id,
+    auto res = ActivatePackageImpl(*cur_apex, loop::kFreeLoopId, old_new_id,
                                    /* reuse_device= */ false);
     if (!res.ok()) {
       // At this point not much we can do... :(
       LOG(ERROR) << res.error();
     }
-  });
+  }));
+
+  // 4. Put the new file in "active" as |target_file|
+  std::string target_file;
+  if (IsMountBeforeDataEnabled()) {
+    auto image_manager = GetImageManager();
+    // Pin the new file first.
+    auto image = OR_RETURN(image_manager->PinApexFiles(Single(*temp_apex)))[0];
+    guards.emplace_back(base::make_scope_guard([=]() {
+      if (auto st = image_manager->DeleteImage(image); !st.ok()) {
+        LOG(ERROR) << st.error();
+      }
+    }));
+
+    // Update "active" list with the new image.
+    auto active_list =
+        OR_RETURN(image_manager->GetApexList(ApexListType::ACTIVE));
+    OR_RETURN(image_manager->UpdateApexList(
+        ApexListType::ACTIVE,
+        UpdateApexListWithNewEntries(
+            active_list, std::vector{ApexListEntry{image, module_name}})));
+    guards.emplace_back(base::make_scope_guard([=]() {
+      if (auto st =
+              image_manager->UpdateApexList(ApexListType::ACTIVE, active_list);
+          !st.ok()) {
+        LOG(ERROR) << st.error();
+      }
+    }));
 
-  // At this point it should be safe to hard link |temp_apex| to
-  // |params->target_file|. In case reboot happens during one of the stages
-  // below, then on next boot apexd will pick up the new verified APEX.
-  if (link(package_path.c_str(), target_file.c_str()) != 0) {
-    return ErrnoError() << "Failed to link " << package_path << " to "
-                        << target_file;
+    // Map the image so that we can access the pinned APEX
+    target_file = OR_RETURN(image_manager->MapImage(image));
+    guards.emplace_back(base::make_scope_guard([=]() {
+      if (auto st = image_manager->UnmapImage(image); !st.ok()) {
+        LOG(ERROR) << st.error();
+      }
+    }));
+  } else {
+    // Hard-link to final destination
+    target_file = StringPrintf("%s/%s.apex", gConfig->active_apex_data_dir,
+                               new_id.c_str());
+    // At this point it should be safe to hard link |temp_apex| to
+    // |params->target_file|. In case reboot happens during one of the stages
+    // below, then on next boot apexd will pick up the new verified APEX.
+    if (link(package_path.c_str(), target_file.c_str()) != 0) {
+      return ErrnoError() << "Failed to link " << package_path << " to "
+                          << target_file;
+    }
+    // Remove the target file on error
+    guards.emplace_back(base::make_scope_guard([=]() {
+      if (unlink(target_file.c_str()) != 0 && errno != ENOENT) {
+        PLOG(ERROR) << "Failed to unlink " << target_file;
+      }
+    }));
   }
 
+  // Reopen ApexFile from the new location
   auto new_apex = ApexFile::Open(target_file);
   if (!new_apex.ok()) {
     return new_apex.error();
   }
 
-  // 4. And activate new one.
-  auto activate_status = ActivatePackageImpl(*new_apex, new_id,
-                                             /* reuse_device= */ false);
+  // 5. And activate new one.
+  auto activate_status =
+      ActivatePackageImpl(*new_apex, loop::kFreeLoopId, new_id,
+                          /* reuse_device= */ false);
   if (!activate_status.ok()) {
     return activate_status.error();
   }
 
-  // Accept the install.
-  guard.Disable();
+  // Accept the install. Disable all ScopeGuards.
+  for (auto& guard : guards) guard.Disable();
 
-  // 4. Now we can unlink old APEX if it's not pre-installed.
+  // 6. Now we can unlink old APEX if it's not pre-installed.
   if (!ApexFileRepository::GetInstance().IsPreInstalledApex(*cur_apex)) {
-    if (unlink(cur_mounted_data->full_path.c_str()) != 0) {
-      PLOG(ERROR) << "Failed to unlink " << cur_mounted_data->full_path;
+    if (auto image = GetImageManager()->FindPinnedApex(*cur_apex); image) {
+      if (auto st = GetImageManager()->UnmapAndDeleteImage(*image); !st.ok()) {
+        LOG(ERROR) << st.error();
+      }
+    } else {
+      if (unlink(cur_mounted_data->full_path.c_str()) != 0) {
+        PLOG(ERROR) << "Failed to unlink " << cur_mounted_data->full_path;
+      }
     }
   }
 
-  if (auto res = EmitApexInfoList(/*is_bootstrap*/ false); !res.ok()) {
-    LOG(ERROR) << res.error();
+  // 7. Update apex-info-list.xml
+  auto active = GetActivePackages();
+  std::vector<ApexFileRef> active_references;
+  active_references.reserve(active.size());
+  for (const auto& apex : active) {
+    active_references.push_back(std::cref(apex));
   }
-
-  // Release compressed blocks in case target_file is on f2fs-compressed
-  // filesystem.
-  ReleaseF2fsCompressedBlocks(target_file);
+  EmitApexInfoList(active_references, /*is_bootstrap=*/false);
 
   event.MarkSucceeded();
 
diff --git a/apexd/apexd.h b/apexd/apexd.h
index 8cbf0f69..0f190612 100644
--- a/apexd/apexd.h
+++ b/apexd/apexd.h
@@ -55,10 +55,13 @@ struct ApexdConfig {
   const char* vm_payload_metadata_partition_prop;
   const char* active_apex_selinux_ctx;
 
+  std::unordered_map<ApexPartition, std::string> brand_new_apex_config_dirs;
+
   // TODO(b/381173074) True in tests for now. Will be configured as true if
   // - new device (ro.vendor.api_level >= 202504 (TBD))
   // - or, upgrading device with migration done (e.g. flag in /metadata/apex)
   bool mount_before_data;
+  const char* metadata_config_dir;
 };
 
 static const ApexdConfig kDefaultConfig = {
@@ -70,7 +73,9 @@ static const ApexdConfig kDefaultConfig = {
     kStagedSessionsDir,
     kVmPayloadMetadataPartitionProp,
     "u:object_r:staging_data_file",
+    kBrandNewApexConfigDirs,
     false, /* mount_before_data */
+    kMetadataConfigDir,
 };
 
 class CheckpointInterface;
@@ -83,9 +88,6 @@ android::base::Result<void> Unmount(
 
 android::base::Result<void> ResumeRevertIfNeeded();
 
-android::base::Result<void> PreinstallPackages(
-    const std::vector<std::string>& paths) WARN_UNUSED;
-
 android::base::Result<void> StagePackages(
     const std::vector<std::string>& tmpPaths) WARN_UNUSED;
 android::base::Result<void> UnstagePackages(
@@ -145,19 +147,13 @@ void InitializeSessionManager(ApexSessionManager* session_manager);
 // Initializes in-memory state (e.g. pre-installed data, activated apexes).
 // Must be called first before calling any other boot sequence related function.
 void Initialize(CheckpointInterface* checkpoint_service);
-// Initializes data apex as in-memory state. Should be called only if we are
-// not booting, since initialization timing is different when booting
-void InitializeDataApex();
 // Apex activation logic. Scans staged apex sessions and activates apexes.
 // Must only be called during boot (i.e apexd.status is not "ready" or
 // "activated").
 void OnStart();
-// For every package X, there can be at most two APEX, pre-installed vs
-// installed on data. We decide which ones should be activated and return them
-// as a list
-std::vector<ApexFileRef> SelectApexForActivation();
-std::vector<ApexFile> ProcessCompressedApex(
-    const std::vector<ApexFileRef>& compressed_apex, bool is_ota_chroot);
+
+android::base::Result<ApexFile> ProcessCompressedApex(const ApexFile& capex,
+                                                      bool is_ota_chroot);
 // Validate |apex| is same as |capex|
 android::base::Result<void> ValidateDecompressedApex(const ApexFile& capex,
                                                      const ApexFile& apex);
@@ -165,13 +161,13 @@ android::base::Result<void> ValidateDecompressedApex(const ApexFile& capex,
 // "activated".
 // Must only be called during boot (i.e. apexd.status is not "ready" or
 // "activated").
-void OnAllPackagesActivated(bool is_bootstrap);
+void OnAllPackagesActivated();
 // Notifies system that apexes are ready by setting apexd.status property to
 // "ready".
 // Must only be called during boot (i.e. apexd.status is not "ready" or
 // "activated").
 void OnAllPackagesReady();
-void OnBootCompleted();
+void MarkBootCompleted();
 
 // Removes inactivate apexes on /data after activation.
 // This can happen when prebuilt APEXes are newer than /data apexes with OTA.
@@ -185,9 +181,6 @@ int SnapshotOrRestoreDeUserData();
 // If `also_include_staged_apexes` is true, it's for Pre-reboot Dexopt.
 int UnmountAll(bool also_include_staged_apexes);
 
-android::base::Result<MountedApexDatabase::MountedApexData>
-GetTempMountedApexData(const std::string& package);
-
 // Exposed for unit tests
 bool ShouldAllocateSpaceForDecompression(const std::string& new_apex_name,
                                          int64_t new_apex_version,
@@ -198,11 +191,12 @@ int64_t CalculateSizeForCompressedApex(
     const std::vector<std::tuple<std::string, int64_t, int64_t>>&
         compressed_apexes);
 
-// Casts |ApexPartition| to partition string used in XSD.
-std::string CastPartition(ApexPartition partition);
+// Exposed for benchmark
+void EmitApexInfoList(const std::vector<ApexFileRef>& active,
+                      bool is_bootstrap);
 void CollectApexInfoList(std::ostream& os,
-                         const std::vector<ApexFile>& active_apexs,
-                         const std::vector<ApexFile>& inactive_apexs);
+                         const std::vector<ApexFileRef>& active_apexs,
+                         const std::vector<ApexFileRef>& inactive_apexs);
 
 // Reserve |size| bytes in |dest_dir| by creating a zero-filled file
 android::base::Result<void> ReserveSpaceForCompressedApex(
diff --git a/apexd/apexd_benchmark.cpp b/apexd/apexd_benchmark.cpp
new file mode 100644
index 00000000..b93d8e65
--- /dev/null
+++ b/apexd/apexd_benchmark.cpp
@@ -0,0 +1,63 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include <android-base/properties.h>
+#include <benchmark/benchmark.h>
+
+#include "apex_file.h"
+#include "apex_file_repository.h"
+#include "apexd.h"
+
+using android::apex::ApexFile;
+using android::apex::ApexFileRepository;
+using android::apex::kBuiltinApexPackageDirs;
+using android::base::SetProperty;
+
+static void BM_ApexFile_Open(benchmark::State& state) {
+  for (auto _ : state) {
+    ApexFile::Open("/system/apex/com.android.apex.cts.shim.apex");
+  }
+}
+BENCHMARK(BM_ApexFile_Open);
+
+static void BM_ApexFileRepository_AddPreInstalledApex(benchmark::State& state) {
+  for (auto _ : state) {
+    ApexFileRepository instance;
+    instance.AddPreInstalledApex(kBuiltinApexPackageDirs);
+  }
+}
+BENCHMARK(BM_ApexFileRepository_AddPreInstalledApex);
+
+static void BM_ApexFileRepository_GetPreInstalledApex(benchmark::State& state) {
+  ApexFileRepository instance;
+  instance.AddPreInstalledApex(kBuiltinApexPackageDirs);
+  for (auto _ : state) {
+    instance.GetPreInstalledApexFiles();
+  }
+}
+BENCHMARK(BM_ApexFileRepository_GetPreInstalledApex);
+
+static void BM_EmitApexInfoList(benchmark::State& state) {
+  auto& instance = ApexFileRepository::GetInstance();
+  instance.AddPreInstalledApex(kBuiltinApexPackageDirs);
+  auto preinstalled = instance.GetPreInstalledApexFiles();
+  for (auto _ : state) {
+    android::apex::EmitApexInfoList(preinstalled, false);
+  }
+}
+BENCHMARK(BM_EmitApexInfoList);
+
+BENCHMARK_MAIN();
\ No newline at end of file
diff --git a/apexd/apexd_brand_new_verifier.cpp b/apexd/apexd_brand_new_verifier.cpp
index aa9b120c..f785eeec 100644
--- a/apexd/apexd_brand_new_verifier.cpp
+++ b/apexd/apexd_brand_new_verifier.cpp
@@ -51,7 +51,8 @@ Result<ApexPartition> VerifyBrandNewPackageAgainstPreinstalled(
   return partition.value();
 }
 
-Result<void> VerifyBrandNewPackageAgainstActive(const ApexFile& apex) {
+Result<void> VerifyBrandNewPackageAgainstActive(const ApexFile& apex,
+                                                const MountedApexDatabase& db) {
   CHECK(ApexFileRepository::IsBrandNewApexEnabled())
       << "Brand-new APEX must be enabled in order to do verification.";
 
@@ -61,10 +62,12 @@ Result<void> VerifyBrandNewPackageAgainstActive(const ApexFile& apex) {
   if (file_repository.HasPreInstalledVersion(name)) {
     return {};
   }
-
-  if (file_repository.HasDataVersion(name)) {
-    auto existing_package = file_repository.GetDataApex(name).get();
-    if (apex.GetBundledPublicKey() != existing_package.GetBundledPublicKey()) {
+  // This is a brand-new apex being staged. It should have the same public key
+  // as any currently active version.
+  auto active = db.GetLatestMountedApex(name);
+  if (active) {
+    auto active_apex_file = OR_RETURN(ApexFile::Open(active->full_path));
+    if (apex.GetBundledPublicKey() != active_apex_file.GetBundledPublicKey()) {
       return Error()
              << "Brand-new APEX public key doesn't match existing active APEX: "
              << name;
diff --git a/apexd/apexd_brand_new_verifier.h b/apexd/apexd_brand_new_verifier.h
index db38e250..1719460f 100644
--- a/apexd/apexd_brand_new_verifier.h
+++ b/apexd/apexd_brand_new_verifier.h
@@ -21,6 +21,7 @@
 #include <string>
 
 #include "apex_constants.h"
+#include "apex_database.h"
 #include "apex_file.h"
 
 namespace android::apex {
@@ -43,11 +44,11 @@ android::base::Result<ApexPartition> VerifyBrandNewPackageAgainstPreinstalled(
 
 // Returns the verification result of a specific brand-new package.
 // Verifies a brand-new APEX in that its public key is the same as the existing
-// active version if any. Pre-installed APEX is skipped.
+// active version if any.
 //
 // The function is called in
 // |SubmitStagedSession| (brand-new apex becomes 'staged')
 android::base::Result<void> VerifyBrandNewPackageAgainstActive(
-    const ApexFile& apex);
+    const ApexFile& apex, const MountedApexDatabase& db);
 
 }  // namespace android::apex
diff --git a/apexd/apexd_brand_new_verifier_test.cpp b/apexd/apexd_brand_new_verifier_test.cpp
index efc2bb2c..75239465 100644
--- a/apexd/apexd_brand_new_verifier_test.cpp
+++ b/apexd/apexd_brand_new_verifier_test.cpp
@@ -39,11 +39,33 @@ using android::base::testing::Ok;
 using android::base::testing::WithMessage;
 using ::testing::Not;
 
-TEST(BrandNewApexVerifierTest, SucceedPublicKeyMatch) {
-  ApexFileRepository::EnableBrandNewApex();
+class BrandNewApexVerifierTest : public ::testing::Test {
+ protected:
+  void SetUp() override { ApexFileRepository::EnableBrandNewApex(); }
+  void TearDown() override { ApexFileRepository::GetInstance().Reset(); }
+
+  // Copy test file to the data dir and populate db with fake mount info
+  void PrepareDataApex(const std::string& test_file) {
+    fs::copy(GetTestFile(test_file), data_dir.path);
+    auto data_apex_path = std::string(data_dir.path) + "/" + test_file;
+    auto apex_file = ApexFile::Open(data_apex_path);
+    ASSERT_THAT(apex_file, Ok());
+    MountedApexDatabase::MountedApexData data;
+    data.version = apex_file->GetManifest().version();
+    data.full_path = data_apex_path;
+    db.AddMountedApex(apex_file->GetManifest().name(), data);
+  }
+
+  TemporaryDir trusted_key_dir;
+  TemporaryDir config_dir;
+  TemporaryDir data_dir;
+  TemporaryDir built_in_dir;
+  MountedApexDatabase db;
+};
+
+TEST_F(BrandNewApexVerifierTest, SucceedPublicKeyMatch) {
   auto& file_repository = ApexFileRepository::GetInstance();
   const auto partition = ApexPartition::System;
-  TemporaryDir trusted_key_dir;
   fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
            trusted_key_dir.path);
   file_repository.AddBrandNewApexCredentialAndBlocklist(
@@ -55,15 +77,11 @@ TEST(BrandNewApexVerifierTest, SucceedPublicKeyMatch) {
   auto ret = VerifyBrandNewPackageAgainstPreinstalled(*apex);
   ASSERT_RESULT_OK(ret);
   ASSERT_EQ(*ret, partition);
-
-  file_repository.Reset();
 }
 
-TEST(BrandNewApexVerifierTest, SucceedVersionBiggerThanBlocked) {
-  ApexFileRepository::EnableBrandNewApex();
+TEST_F(BrandNewApexVerifierTest, SucceedVersionBiggerThanBlocked) {
   auto& file_repository = ApexFileRepository::GetInstance();
   const auto partition = ApexPartition::System;
-  TemporaryDir config_dir;
   fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
            config_dir.path);
   fs::copy(GetTestFile("apexd_testdata/blocklist.json"), config_dir.path);
@@ -76,34 +94,25 @@ TEST(BrandNewApexVerifierTest, SucceedVersionBiggerThanBlocked) {
   auto ret = VerifyBrandNewPackageAgainstPreinstalled(*apex);
   ASSERT_RESULT_OK(ret);
   ASSERT_EQ(*ret, partition);
-
-  file_repository.Reset();
 }
 
-TEST(BrandNewApexVerifierTest, SucceedMatchActive) {
-  ApexFileRepository::EnableBrandNewApex();
+TEST_F(BrandNewApexVerifierTest, SucceedMatchActive) {
   auto& file_repository = ApexFileRepository::GetInstance();
-  TemporaryDir trusted_key_dir, data_dir;
   fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
            trusted_key_dir.path);
-  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
   file_repository.AddBrandNewApexCredentialAndBlocklist(
       {{ApexPartition::System, trusted_key_dir.path}});
-  file_repository.AddDataApex(data_dir.path);
+  PrepareDataApex("com.android.apex.brand.new.apex");
 
   auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.v2.apex"));
   ASSERT_RESULT_OK(apex);
 
-  auto ret = VerifyBrandNewPackageAgainstActive(*apex);
+  auto ret = VerifyBrandNewPackageAgainstActive(*apex, db);
   ASSERT_RESULT_OK(ret);
-
-  file_repository.Reset();
 }
 
-TEST(BrandNewApexVerifierTest, SucceedSkipPreinstalled) {
-  ApexFileRepository::EnableBrandNewApex();
+TEST_F(BrandNewApexVerifierTest, SucceedSkipPreinstalled) {
   auto& file_repository = ApexFileRepository::GetInstance();
-  TemporaryDir built_in_dir;
   fs::copy(GetTestFile("apex.apexd_test.apex"), built_in_dir.path);
   file_repository.AddPreInstalledApex(
       {{ApexPartition::System, built_in_dir.path}});
@@ -111,29 +120,23 @@ TEST(BrandNewApexVerifierTest, SucceedSkipPreinstalled) {
   auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
   ASSERT_RESULT_OK(apex);
 
-  auto ret = VerifyBrandNewPackageAgainstActive(*apex);
+  auto ret = VerifyBrandNewPackageAgainstActive(*apex, db);
   ASSERT_RESULT_OK(ret);
-
-  file_repository.Reset();
 }
 
-TEST(BrandNewApexVerifierTest, SucceedSkipWithoutDataVersion) {
-  ApexFileRepository::EnableBrandNewApex();
+TEST_F(BrandNewApexVerifierTest, SucceedSkipWithoutDataVersion) {
   auto& file_repository = ApexFileRepository::GetInstance();
-
   auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
   ASSERT_RESULT_OK(apex);
 
-  auto ret = VerifyBrandNewPackageAgainstActive(*apex);
+  auto ret = VerifyBrandNewPackageAgainstActive(*apex, db);
   ASSERT_RESULT_OK(ret);
-
-  file_repository.Reset();
 }
 
-TEST(BrandNewApexVerifierTest, FailBrandNewApexDisabled) {
+TEST_F(BrandNewApexVerifierTest, FailBrandNewApexDisabled) {
   auto& file_repository = ApexFileRepository::GetInstance();
+  file_repository.Reset();  // Disable brand-new-apex
   const auto partition = ApexPartition::System;
-  TemporaryDir trusted_key_dir;
   fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
            trusted_key_dir.path);
   file_repository.AddBrandNewApexCredentialAndBlocklist(
@@ -146,15 +149,11 @@ TEST(BrandNewApexVerifierTest, FailBrandNewApexDisabled) {
       { VerifyBrandNewPackageAgainstPreinstalled(*apex); },
       "Brand-new APEX must be enabled in order to do verification.");
   ASSERT_DEATH(
-      { VerifyBrandNewPackageAgainstActive(*apex); },
+      { VerifyBrandNewPackageAgainstActive(*apex, db); },
       "Brand-new APEX must be enabled in order to do verification.");
-
-  file_repository.Reset();
 }
 
-TEST(BrandNewApexVerifierTest, FailNoMatchingPublicKey) {
-  ApexFileRepository::EnableBrandNewApex();
-
+TEST_F(BrandNewApexVerifierTest, FailNoMatchingPublicKey) {
   auto apex = ApexFile::Open(GetTestFile("com.android.apex.brand.new.apex"));
   ASSERT_RESULT_OK(apex);
 
@@ -165,11 +164,9 @@ TEST(BrandNewApexVerifierTest, FailNoMatchingPublicKey) {
                             "brand-new APEX: com.android.apex.brand.new"))));
 }
 
-TEST(BrandNewApexVerifierTest, FailBlockedByVersion) {
-  ApexFileRepository::EnableBrandNewApex();
+TEST_F(BrandNewApexVerifierTest, FailBlockedByVersion) {
   auto& file_repository = ApexFileRepository::GetInstance();
   const auto partition = ApexPartition::System;
-  TemporaryDir config_dir;
   fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
            config_dir.path);
   fs::copy(GetTestFile("apexd_testdata/blocklist.json"), config_dir.path);
@@ -183,35 +180,28 @@ TEST(BrandNewApexVerifierTest, FailBlockedByVersion) {
   ASSERT_THAT(ret,
               HasError(WithMessage(
                   ("Brand-new APEX is blocked: com.android.apex.brand.new"))));
-
-  file_repository.Reset();
 }
 
-TEST(BrandNewApexVerifierTest, FailPublicKeyNotMatchActive) {
-  ApexFileRepository::EnableBrandNewApex();
+TEST_F(BrandNewApexVerifierTest, FailPublicKeyNotMatchActive) {
   auto& file_repository = ApexFileRepository::GetInstance();
-  TemporaryDir trusted_key_dir, data_dir;
   fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
            trusted_key_dir.path);
   fs::copy(GetTestFile(
                "apexd_testdata/com.android.apex.brand.new.another.avbpubkey"),
            trusted_key_dir.path);
-  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
   file_repository.AddBrandNewApexCredentialAndBlocklist(
       {{ApexPartition::System, trusted_key_dir.path}});
-  file_repository.AddDataApex(data_dir.path);
+  PrepareDataApex("com.android.apex.brand.new.apex");
 
   auto apex =
       ApexFile::Open(GetTestFile("com.android.apex.brand.new.v2.diffkey.apex"));
   ASSERT_RESULT_OK(apex);
 
-  auto ret = VerifyBrandNewPackageAgainstActive(*apex);
+  auto ret = VerifyBrandNewPackageAgainstActive(*apex, db);
   ASSERT_THAT(
       ret,
       HasError(WithMessage(("Brand-new APEX public key doesn't match existing "
                             "active APEX: com.android.apex.brand.new"))));
-
-  file_repository.Reset();
 }
 
 }  // namespace android::apex
diff --git a/apexd/apexd_dm.cpp b/apexd/apexd_dm.cpp
index 0d2e8358..4a995b59 100644
--- a/apexd/apexd_dm.cpp
+++ b/apexd/apexd_dm.cpp
@@ -43,7 +43,7 @@ static Result<DmDevice> CreateDmDeviceInternal(
     const std::chrono::milliseconds& timeout) {
   std::string dev_path;
   if (!dm.CreateDevice(name, table, &dev_path, timeout)) {
-    return Error() << "Couldn't create dm-device.";
+    return Error() << "Couldn't create dm-device for name=" << name;
   }
   return DmDevice(name, dev_path);
 }
diff --git a/apexd/apexd_image_manager.cpp b/apexd/apexd_image_manager.cpp
index d45a2663..6845c18f 100644
--- a/apexd/apexd_image_manager.cpp
+++ b/apexd/apexd_image_manager.cpp
@@ -16,21 +16,28 @@
 
 #include "apexd_image_manager.h"
 
+#include <android-base/file.h>
 #include <android-base/result.h>
 #include <android-base/unique_fd.h>
+#include <libdm/dm.h>
 #include <sys/sendfile.h>
+#include <unistd.h>
 
 #include <algorithm>
+#include <cerrno>
 #include <chrono>
 
+#include "apex_image_list.pb.h"
 #include "apexd.h"
 #include "apexd_utils.h"
 
 using android::base::borrowed_fd;
 using android::base::ErrnoError;
 using android::base::Error;
+using android::base::RemoveFileIfExists;
 using android::base::Result;
 using android::base::unique_fd;
+using android::dm::DeviceMapper;
 using namespace std::chrono_literals;
 
 namespace android::apex {
@@ -64,16 +71,88 @@ std::string AllocateNewName(const std::vector<std::string>& known_names,
   });
   // Find free slot for the "base_name"
   for (auto i = 0; i < count; i++) {
-    std::string new_name = base_name + "_" + std::to_string(i) + ".apex";
+    std::string new_name =
+        base_name + "_" + std::to_string(i) + kDmLinearApexSuffix;
     if (std::ranges::find(known_names, new_name) == known_names.end()) {
       return new_name;
     }
   }
-  return base_name + "_" + std::to_string(count) + ".apex";
+  return base_name + "_" + std::to_string(count) + kDmLinearApexSuffix;
+}
+
+Result<void> WriteImageList(const std::vector<ApexListEntry>& list,
+                            const std::string& filename) {
+  unique_fd fd(
+      open(filename.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC | O_TRUNC, 0660));
+  if (fd < 0) {
+    return ErrnoError() << "Failed to open " << filename;
+  }
+
+  // Serialize using proto
+  using ::apex::proto::ApexImageList;
+
+  ApexImageList pb_list;
+  pb_list.mutable_entries()->Reserve(list.size());
+  for (const auto& entry : list) {
+    ApexImageList::Entry pb_entry;
+    pb_entry.set_image_name(entry.image_name);
+    pb_entry.set_apex_name(entry.apex_name);
+    *pb_list.add_entries() = std::move(pb_entry);
+  }
+  if (!pb_list.SerializeToFileDescriptor(fd.get())) {
+    return Error() << "Failed to save APEX image list to " << filename;
+  }
+
+  fsync(fd.get());
+  return {};
+}
+
+Result<std::vector<ApexListEntry>> ReadImageList(const std::string& filename) {
+  unique_fd fd(open(filename.c_str(), O_RDONLY | O_CLOEXEC));
+  if (fd < 0) {
+    if (errno == ENOENT) {
+      return {};
+    }
+    return ErrnoError() << "Failed to open " << filename;
+  }
+
+  std::vector<ApexListEntry> list;
+
+  // Deserialize using proto
+  using ::apex::proto::ApexImageList;
+
+  ApexImageList pb_list;
+  if (!pb_list.ParseFromFileDescriptor(fd.get())) {
+    return Error() << "Failed to parse APEX image list from " << filename;
+  }
+  list.reserve(pb_list.entries_size());
+  for (const auto& entry : pb_list.entries()) {
+    list.emplace_back(entry.image_name(), entry.apex_name());
+  }
+
+  return list;
 }
 
 }  // namespace
 
+std::vector<ApexListEntry> UpdateApexListWithNewEntries(
+    std::vector<ApexListEntry> list,
+    const std::vector<ApexListEntry>& new_entries) {
+  // Collect updated apex names
+  std::vector<std::string> updated_names;
+  updated_names.reserve(new_entries.size());
+  for (const auto& entry : new_entries) {
+    updated_names.push_back(entry.apex_name);
+  }
+  // Remove updated apexes from existing list first.
+  std::erase_if(list, [&](const auto& entry) {
+    return std::ranges::contains(updated_names, entry.apex_name);
+  });
+  // Add new entries to the list
+  list.append_range(new_entries);
+  return list;
+}
+
 ApexImageManager::ApexImageManager(const std::string& metadata_dir,
                                    const std::string& data_dir)
     : metadata_dir_(metadata_dir),
@@ -153,10 +232,104 @@ Result<void> ApexImageManager::DeleteImage(const std::string& image) {
   return {};
 }
 
+Result<void> ApexImageManager::UnmapAndDeleteImage(const std::string& image) {
+  OR_RETURN(UnmapImageIfExists(image));
+  return DeleteImage(image);
+}
+
 std::vector<std::string> ApexImageManager::GetAllImages() {
   return fsmgr_->GetAllBackingImages();
 }
 
+std::optional<std::string> ApexImageManager::FindPinnedApex(
+    const ApexFile& apex) const {
+  DeviceMapper& dm = DeviceMapper::Instance();
+  if (!dm.IsDmBlockDevice(apex.GetPath())) {
+    return std::nullopt;
+  }
+  auto name = dm.GetDmDeviceNameByPath(apex.GetPath());
+  if (!name) {
+    return std::nullopt;
+  }
+  // TODO(405903373): Cache lp_metadata for faster lookup
+  if (fsmgr_->BackingImageExists(name.value())) {
+    return name.value();
+  }
+  return std::nullopt;
+}
+
+std::optional<std::string> ApexImageManager::GetMappedPath(
+    const std::string& image) {
+  std::string path;
+  if (fsmgr_->GetMappedImageDevice(image, &path)) {
+    return path;
+  }
+  return std::nullopt;
+}
+
+Result<std::string> ApexImageManager::MapImage(const std::string& image) {
+  std::string path;
+  if (fsmgr_->GetMappedImageDevice(image, &path)) {
+    return path;
+  }
+  if (!fsmgr_->MapImageDevice(image, 10s, &path)) {
+    return Error() << "Failed to create dm-linear device for " << image;
+  }
+  return path;
+}
+
+Result<void> ApexImageManager::UnmapImage(const std::string& image) {
+  if (!fsmgr_->UnmapImageDevice(image)) {
+    return Error() << "Failed to unmap dm-linear device for " << image;
+  }
+  return {};
+}
+
+Result<void> ApexImageManager::UnmapImageIfExists(const std::string& image) {
+  if (fsmgr_->IsImageMapped(image)) {
+    return UnmapImage(image);
+  }
+  return {};
+}
+
+std::string ApexImageManager::GetApexListFile(ApexListType list_type) const {
+  switch (list_type) {
+    case ApexListType::ACTIVE:
+      return metadata_dir_ + "/active";
+    case ApexListType::BACKUP:
+      return metadata_dir_ + "/backup";
+  }
+}
+
+Result<void> ApexImageManager::UpdateApexList(
+    ApexListType list_type, const std::vector<ApexListEntry>& list) {
+  auto listfile = GetApexListFile(list_type);
+
+  // Write to a tempfile first and then rename it to target name to avoid
+  // losing an existing file or half-written file.
+
+  auto tempfile = listfile + ".tmp";
+  OR_RETURN(WriteImageList(list, tempfile));
+
+  auto cleanup = base::make_scope_guard([&]() {
+    if (auto rc = unlink(tempfile.c_str()); rc == -1 && errno != ENOENT) {
+      PLOG(ERROR) << "Fail to delete " << tempfile;
+    }
+  });
+
+  // rename() replaces an existing file if there's any.
+  if (auto rc = rename(tempfile.c_str(), listfile.c_str()); rc == -1) {
+    return ErrnoError() << "Fail to create " << listfile;
+  }
+  return {};
+}
+
+Result<std::vector<ApexListEntry>> ApexImageManager::GetApexList(
+    ApexListType list_type) {
+  auto list_file = GetApexListFile(list_type);
+  return ReadImageList(list_file);
+}
+
 ApexImageManager* GetImageManager() { return gImageManager; }
 
 void InitializeImageManager(ApexImageManager* image_manager) {
diff --git a/apexd/apexd_image_manager.h b/apexd/apexd_image_manager.h
index e0f2047e..cb882f62 100644
--- a/apexd/apexd_image_manager.h
+++ b/apexd/apexd_image_manager.h
@@ -28,27 +28,77 @@
 
 namespace android::apex {
 
+// ApexImageManager manages two lists of APEX files (or image names).
+// - ACTIVE: the list of "active" apexes. Candidates for activation.
+// - BACKUP: a copy of the last ACTIVE list that was successful.
+//
+// The lists are stored in /metadata/apex/images directory.
+enum ApexListType {
+  ACTIVE,
+  BACKUP,
+};
+
+struct ApexListEntry {
+  std::string image_name;
+  std::string apex_name;
+
+  inline auto operator<=>(const ApexListEntry&) const = default;
+};
+
+// Returns an updated list. A new entry replaces any existing entries with the
+// same apex name.
+std::vector<ApexListEntry> UpdateApexListWithNewEntries(
+    std::vector<ApexListEntry> list,
+    const std::vector<ApexListEntry>& new_entries);
+
 class ApexImageManager {
  public:
-  ~ApexImageManager() = default;
+  virtual ~ApexImageManager() = default;
 
   // Pin APEX files in /data/apex/images and save their metadata(e.g. FIEMAP
   // extents) in /metadata/apex/images so that they are available before /data
   // partition is mounted.
   // Returns names which correspond to pinned APEX files.
-  base::Result<std::vector<std::string>> PinApexFiles(
+  virtual base::Result<std::vector<std::string>> PinApexFiles(
       std::span<const ApexFile> apex_files);
   base::Result<void> DeleteImage(const std::string& image);
+  base::Result<void> UnmapAndDeleteImage(const std::string& image);
   std::vector<std::string> GetAllImages();
 
+  // True if the apex is backed by a dm-linear device created by
+  // ApexImageManager
+  bool IsPinnedApex(const ApexFile& file) const {
+    return FindPinnedApex(file).has_value();
+  }
+
+  // Returns the image name if the apex is backed by a dm-linear device created
+  // by ApexImageManager
+  std::optional<std::string> FindPinnedApex(const ApexFile& file) const;
+
+  // Returns the path of the block device if mapped. Similar to MapImage(), but
+  // this doesn't create a block device if not mapped already.
+  std::optional<std::string> GetMappedPath(const std::string& image);
+
+  // Creates a dm-linear block device for a pinned apex and returns the path of
+  // the created block device.
+  virtual base::Result<std::string> MapImage(const std::string& image);
+  base::Result<void> UnmapImage(const std::string& image);
+  base::Result<void> UnmapImageIfExists(const std::string& image);
+
+  base::Result<void> UpdateApexList(ApexListType list_type,
+                                    const std::vector<ApexListEntry>& entries);
+  base::Result<std::vector<ApexListEntry>> GetApexList(ApexListType list_type);
+
   static std::unique_ptr<ApexImageManager> Create(
       const std::string& metadata_images_dir,
       const std::string& data_images_dir);
 
- private:
+ protected:
   ApexImageManager(const std::string& metadata_dir,
                    const std::string& data_dir);
 
+  std::string GetApexListFile(ApexListType list_type) const;
+
   std::string metadata_dir_;
   std::string data_dir_;
   std::unique_ptr<fiemap::IImageManager> fsmgr_;
diff --git a/apexd/apexd_image_manager_test.cpp b/apexd/apexd_image_manager_test.cpp
index f9bc2bbb..7ad9d19d 100644
--- a/apexd/apexd_image_manager_test.cpp
+++ b/apexd/apexd_image_manager_test.cpp
@@ -17,6 +17,7 @@
 #include "apexd_image_manager.h"
 
 #include <android-base/result-gmock.h>
+#include <android-base/scopeguard.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 
@@ -24,9 +25,13 @@
 
 using namespace std::literals;
 
+using android::base::make_scope_guard;
 using android::base::testing::HasValue;
 using android::base::testing::Ok;
+using testing::Eq;
 using testing::IsEmpty;
+using testing::Optional;
+using testing::SizeIs;
 
 namespace android::apex {
 
@@ -54,4 +59,137 @@ TEST(ApexImageManagerTest, PinApexFiles) {
                                    "com.android.apex.test_pack_1.apex"s}));
 }
 
+TEST(ApexImageManagerTest, FindPinnedApex) {
+  TemporaryDir metadata_dir;
+  TemporaryDir data_dir;
+  auto image_manager =
+      ApexImageManager::Create(metadata_dir.path, data_dir.path);
+
+  auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  ASSERT_THAT(apex, Ok());
+  auto images = image_manager->PinApexFiles(std::vector{*apex});
+  ASSERT_THAT(images, HasValue(SizeIs(1)));
+  auto image = images->at(0);
+
+  auto dev = image_manager->MapImage(image);
+  ASSERT_THAT(dev, Ok());
+  auto guard = make_scope_guard(
+      [&]() { ASSERT_THAT(image_manager->UnmapImage(image), Ok()); });
+
+  auto apex_from_mapped = ApexFile::Open(dev.value());
+  ASSERT_THAT(apex_from_mapped, Ok());
+
+  // Find() works with ApexFile opened from the mapped image.
+  ASSERT_THAT(image_manager->FindPinnedApex(*apex), Eq(std::nullopt));
+  ASSERT_THAT(image_manager->FindPinnedApex(*apex_from_mapped),
+              Optional(image));
+}
+
+TEST(ApexImageManagerTest, GetMappedPath) {
+  TemporaryDir metadata_dir;
+  TemporaryDir data_dir;
+  auto image_manager =
+      ApexImageManager::Create(metadata_dir.path, data_dir.path);
+
+  auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  ASSERT_THAT(apex, Ok());
+  auto images = image_manager->PinApexFiles(std::vector{*apex});
+  ASSERT_THAT(images, HasValue(SizeIs(1)));
+  auto image = images->at(0);
+
+  ASSERT_THAT(image_manager->GetMappedPath(image), Eq(std::nullopt));
+
+  auto dev = image_manager->MapImage(image);
+  ASSERT_THAT(dev, Ok());
+  auto guard = make_scope_guard(
+      [&]() { ASSERT_THAT(image_manager->UnmapImage(image), Ok()); });
+
+  ASSERT_THAT(image_manager->GetMappedPath(image), Optional(dev.value()));
+}
+
+TEST(ApexImageManagerTest, ManageApexList) {
+  TemporaryDir metadata_dir;
+  TemporaryDir data_dir;
+  auto image_manager =
+      ApexImageManager::Create(metadata_dir.path, data_dir.path);
+
+  ASSERT_THAT(image_manager->GetApexList(ApexListType::ACTIVE),
+              HasValue(IsEmpty()));
+
+  std::vector<ApexListEntry> list;
+  list.emplace_back("image1", "package1");
+  list.emplace_back("image2", "package2");
+  ASSERT_THAT(image_manager->UpdateApexList(ApexListType::ACTIVE, list), Ok());
+  ASSERT_THAT(image_manager->GetApexList(ApexListType::ACTIVE), HasValue(list));
+}
+
+TEST(ApexImageManagerTest, UpdateApexListMultipleTimes) {
+  TemporaryDir metadata_dir;
+  TemporaryDir data_dir;
+  auto image_manager =
+      ApexImageManager::Create(metadata_dir.path, data_dir.path);
+
+  // Write/read empty list
+  ASSERT_THAT(image_manager->UpdateApexList(ApexListType::ACTIVE, {}), Ok());
+  ASSERT_THAT(image_manager->GetApexList(ApexListType::ACTIVE),
+              HasValue(IsEmpty()));
+
+  // Update should overwrite the list
+  auto list =
+      std::vector<ApexListEntry>{{"image", "apex"}, {"image2", "apex2"}};
+  ASSERT_THAT(image_manager->UpdateApexList(ApexListType::ACTIVE, list), Ok());
+  ASSERT_THAT(image_manager->GetApexList(ApexListType::ACTIVE), HasValue(list));
+
+  // Update the list again with empty list
+  ASSERT_THAT(image_manager->UpdateApexList(ApexListType::ACTIVE, {}), Ok());
+  ASSERT_THAT(image_manager->GetApexList(ApexListType::ACTIVE),
+              HasValue(IsEmpty()));
+}
+
+TEST(UpdateApexListWithNewEntries, AddNew) {
+  auto list = std::vector<ApexListEntry>{};
+  auto new_entries = std::vector<ApexListEntry>{
+      {"image1", "apex1"},
+      {"image2", "apex2"},
+  };
+  auto updated = std::vector<ApexListEntry>{
+      {"image1", "apex1"},
+      {"image2", "apex2"},
+  };
+  ASSERT_EQ(UpdateApexListWithNewEntries(list, new_entries), updated);
+}
+
+TEST(UpdateApexListWithNewEntries, ReplaceAndAddNew) {
+  auto list = std::vector<ApexListEntry>{
+      {"image1", "apex1"},
+      {"image2", "apex2"},
+  };
+  auto new_entries = std::vector<ApexListEntry>{
+      {"image2_1", "apex2"},
+      {"image3", "apex3"},
+  };
+  auto updated = std::vector<ApexListEntry>{
+      {"image1", "apex1"},
+      {"image2_1", "apex2"},
+      {"image3", "apex3"},
+  };
+  ASSERT_EQ(UpdateApexListWithNewEntries(list, new_entries), updated);
+}
+
+TEST(UpdateApexListWithNewEntries, ReplaceAll) {
+  auto list = std::vector<ApexListEntry>{
+      {"image1", "apex1"},
+      {"image2", "apex2"},
+  };
+  auto new_entries = std::vector<ApexListEntry>{
+      {"image1_1", "apex1"},
+      {"image2_1", "apex2"},
+  };
+  auto updated = std::vector<ApexListEntry>{
+      {"image1_1", "apex1"},
+      {"image2_1", "apex2"},
+  };
+  ASSERT_EQ(UpdateApexListWithNewEntries(list, new_entries), updated);
+}
+
 }  // namespace android::apex
\ No newline at end of file
diff --git a/apexd/apexd_lifecycle.cpp b/apexd/apexd_lifecycle.cpp
index f18b3822..f472313a 100644
--- a/apexd/apexd_lifecycle.cpp
+++ b/apexd/apexd_lifecycle.cpp
@@ -36,6 +36,11 @@ static const char* BOOT_TIMEOUT = "BootTimeout"; // NOLINT
 namespace android {
 namespace apex {
 
+ApexdLifecycle& ApexdLifecycle::GetInstance() {
+  static ApexdLifecycle instance;
+  return instance;
+}
+
 bool ApexdLifecycle::IsBooting() {
   auto status = GetProperty(kApexStatusSysprop, "");
   return status != kApexStatusReady && status != kApexStatusActivated;
diff --git a/apexd/apexd_lifecycle.h b/apexd/apexd_lifecycle.h
index 75dc7612..e444161d 100644
--- a/apexd/apexd_lifecycle.h
+++ b/apexd/apexd_lifecycle.h
@@ -35,10 +35,7 @@ class ApexdLifecycle {
   void RevertActiveSessions(const std::string& process,
                             const std::string& error);
  public:
-  static ApexdLifecycle& GetInstance() {
-    static ApexdLifecycle instance;
-    return instance;
-  }
+  static ApexdLifecycle& GetInstance();
   bool IsBooting();
   void MarkBootCompleted();
   void WaitForBootStatus(const bool has_active_session);
diff --git a/apexd/apexd_loop.cpp b/apexd/apexd_loop.cpp
index 44a2f226..c31c5dc3 100644
--- a/apexd/apexd_loop.cpp
+++ b/apexd/apexd_loop.cpp
@@ -47,6 +47,7 @@
 #include "apexd_utils.h"
 
 using android::base::Basename;
+using android::base::borrowed_fd;
 using android::base::Dirname;
 using android::base::ErrnoError;
 using android::base::Error;
@@ -63,8 +64,6 @@ namespace android {
 namespace apex {
 namespace loop {
 
-static constexpr const char* kApexLoopIdPrefix = "apex:";
-
 // 128 kB read-ahead, which we currently use for /system as well
 static constexpr const unsigned int kReadAheadKb = 128;
 
@@ -364,7 +363,7 @@ struct EmptyLoopDevice {
 };
 
 static Result<LoopbackDeviceUniqueFd> ConfigureLoopDevice(
-    EmptyLoopDevice&& inner, const std::string& target,
+    EmptyLoopDevice&& inner, borrowed_fd target_fd, bool use_buffered_io,
     const uint32_t image_offset, const size_t image_size) {
   static bool use_loop_configure;
   static std::once_flag once_flag;
@@ -384,38 +383,8 @@ static Result<LoopbackDeviceUniqueFd> ConfigureLoopDevice(
     }
   });
 
-  /*
-   * Using O_DIRECT will tell the kernel that we want to use Direct I/O
-   * on the underlying file, which we want to do to avoid double caching.
-   * Note that Direct I/O won't be enabled immediately, because the block
-   * size of the underlying block device may not match the default loop
-   * device block size (512); when we call LOOP_SET_BLOCK_SIZE below, the
-   * kernel driver will automatically enable Direct I/O when it sees that
-   * condition is now met.
-   */
-  bool use_buffered_io = false;
-  unique_fd target_fd(open(target.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECT));
-  if (target_fd.get() == -1) {
-    struct statfs stbuf;
-    int saved_errno = errno;
-    // let's give another try with buffered I/O for EROFS and squashfs
-    if (statfs(target.c_str(), &stbuf) != 0 ||
-        (stbuf.f_type != EROFS_SUPER_MAGIC_V1 &&
-         stbuf.f_type != SQUASHFS_MAGIC &&
-         stbuf.f_type != OVERLAYFS_SUPER_MAGIC)) {
-      return Error(saved_errno) << "Failed to open " << target;
-    }
-    LOG(WARNING) << "Fallback to buffered I/O for " << target;
-    use_buffered_io = true;
-    target_fd.reset(open(target.c_str(), O_RDONLY | O_CLOEXEC));
-    if (target_fd.get() == -1) {
-      return ErrnoError() << "Failed to open " << target;
-    }
-  }
-
   struct loop_info64 li;
   memset(&li, 0, sizeof(li));
-  strlcpy((char*)li.lo_crypt_name, kApexLoopIdPrefix, LO_NAME_SIZE);
   li.lo_offset = image_offset;
   li.lo_sizelimit = image_size;
   // Automatically free loop device on last close.
@@ -479,10 +448,7 @@ static Result<LoopbackDeviceUniqueFd> ConfigureLoopDevice(
 }
 
 static Result<EmptyLoopDevice> WaitForLoopDevice(int num) {
-  std::vector<std::string> candidate_devices = {
-      StringPrintf("/dev/block/loop%d", num),
-      StringPrintf("/dev/loop%d", num),
-  };
+  std::string device = StringPrintf("/dev/block/loop%d", num);
 
   // apexd-bootstrap runs in parallel with ueventd to optimize boot time. In
   // rare cases apexd would try attempt to mount an apex before ueventd created
@@ -494,31 +460,32 @@ static Result<EmptyLoopDevice> WaitForLoopDevice(int num) {
   // ueventd to run to actually create the device node in userspace. To solve
   // this properly we should listen on the netlink socket for uevents, or use
   // inotify. For now, this will have to do.
-  size_t attempts =
-      android::sysprop::ApexProperties::loop_wait_attempts().value_or(3u);
+  size_t attempts = sysprop::ApexProperties::loop_wait_attempts().value_or(0u);
+  if (attempts == 0) {
+    attempts = 3u;
+  }
   for (size_t i = 0; i != attempts; ++i) {
-    if (!cold_boot_done) {
-      cold_boot_done = GetBoolProperty("ro.cold_boot_done", false);
+    unique_fd sysfs_fd(open(device.c_str(), O_RDWR | O_CLOEXEC));
+    if (sysfs_fd.get() != -1) {
+      return EmptyLoopDevice{std::move(sysfs_fd), std::move(device)};
     }
-    for (const auto& device : candidate_devices) {
-      unique_fd sysfs_fd(open(device.c_str(), O_RDWR | O_CLOEXEC));
-      if (sysfs_fd.get() != -1) {
-        return EmptyLoopDevice{std::move(sysfs_fd), std::move(device)};
-      }
-    }
-    PLOG(WARNING) << "Loopback device " << num << " not ready. Waiting 50ms...";
+    PLOG(WARNING) << "Loop device " << num << " not ready. Waiting 50ms...";
     usleep(50000);
     if (!cold_boot_done) {
       // ueventd hasn't finished cold boot yet, keep trying.
       i = 0;
+      cold_boot_done = GetBoolProperty("ro.cold_boot_done", false);
     }
   }
 
-  return Error() << "Failed to open loopback device " << num;
+  return Error() << "Failed to open loop device " << num;
 }
 
-static Result<LoopbackDeviceUniqueFd> CreateLoopDevice(
-    const std::string& target, uint32_t image_offset, size_t image_size) {
+static Result<LoopbackDeviceUniqueFd> CreateLoopDevice(borrowed_fd target_fd,
+                                                       bool use_buffered_io,
+                                                       uint32_t image_offset,
+                                                       size_t image_size,
+                                                       int32_t loop_id) {
   ATRACE_NAME("CreateLoopDevice");
 
   unique_fd ctl_fd(open("/dev/loop-control", O_RDWR | O_CLOEXEC));
@@ -526,23 +493,73 @@ static Result<LoopbackDeviceUniqueFd> CreateLoopDevice(
     return ErrnoError() << "Failed to open loop-control";
   }
 
-  static std::mutex mtx;
-  std::lock_guard lock(mtx);
-  int num = ioctl(ctl_fd.get(), LOOP_CTL_GET_FREE);
-  if (num == -1) {
-    return ErrnoError() << "Failed LOOP_CTL_GET_FREE";
+  if (loop_id == kFreeLoopId) {
+    // Getting a new free slot and configuring it should be done together with a
+    // mutex. Otherwise, parallel activation will cause huge contention and
+    // unnecessary retries.
+    //
+    // However, using a mutex isn't enought because there'll
+    // be other processes that might try to get a free loop. Then either of
+    // processes will fail when it tries to configure it because it's already
+    // being in use by the other process. This is handled in
+    // CreateAndConfigureLoopDevice() by retrying for 1s.
+    static std::mutex mtx;
+    std::lock_guard lock(mtx);
+    int num = ioctl(ctl_fd.get(), LOOP_CTL_GET_FREE);
+    if (num == -1) {
+      return ErrnoError() << "Failed LOOP_CTL_GET_FREE";
+    }
+    auto loop_device = OR_RETURN(WaitForLoopDevice(num));
+    return ConfigureLoopDevice(std::move(loop_device), target_fd,
+                               use_buffered_io, image_offset, image_size);
+  } else {
+    // When creating a loop with the id specified, no need to guard the scope
+    // with a mutex. If it fails to configure for some reasons (e.g. used by
+    // other threads or processes), just return error.
+    int num = ioctl(ctl_fd.get(), LOOP_CTL_ADD, loop_id);
+    if (num != loop_id && errno != EEXIST) {
+      return ErrnoError() << "Failed LOOP_CTL_ADD " << loop_id;
+    }
+    auto loop_device = OR_RETURN(WaitForLoopDevice(loop_id));
+    return ConfigureLoopDevice(std::move(loop_device), target_fd,
+                               use_buffered_io, image_offset, image_size);
   }
-
-  auto loop_device = OR_RETURN(WaitForLoopDevice(num));
-  CHECK_NE(loop_device.fd.get(), -1);
-
-  return ConfigureLoopDevice(std::move(loop_device), target, image_offset,
-                             image_size);
 }
 
 Result<LoopbackDeviceUniqueFd> CreateAndConfigureLoopDevice(
-    const std::string& target, uint32_t image_offset, size_t image_size) {
+    const std::string& target, uint32_t image_offset, size_t image_size,
+    int32_t loop_id) {
   ATRACE_NAME("CreateAndConfigureLoopDevice");
+
+  /*
+   * Using O_DIRECT will tell the kernel that we want to use Direct I/O
+   * on the underlying file, which we want to do to avoid double caching.
+   * Note that Direct I/O won't be enabled immediately, because the block
+   * size of the underlying block device may not match the default loop
+   * device block size (512); when we call LOOP_SET_BLOCK_SIZE below, the
+   * kernel driver will automatically enable Direct I/O when it sees that
+   * condition is now met.
+   */
+  bool use_buffered_io = false;
+  unique_fd target_fd(open(target.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECT));
+  if (target_fd.get() == -1) {
+    struct statfs stbuf;
+    int saved_errno = errno;
+    // let's give another try with buffered I/O for EROFS and squashfs
+    if (statfs(target.c_str(), &stbuf) != 0 ||
+        (stbuf.f_type != EROFS_SUPER_MAGIC_V1 &&
+         stbuf.f_type != SQUASHFS_MAGIC &&
+         stbuf.f_type != OVERLAYFS_SUPER_MAGIC)) {
+      return Error(saved_errno) << "Failed to open " << target;
+    }
+    LOG(WARNING) << "Fallback to buffered I/O for " << target;
+    use_buffered_io = true;
+    target_fd.reset(open(target.c_str(), O_RDONLY | O_CLOEXEC));
+    if (target_fd.get() == -1) {
+      return ErrnoError() << "Failed to open " << target;
+    }
+  }
+
   // Do minimal amount of work while holding a mutex. We need it because
   // acquiring + configuring a loop device is not atomic. Ideally we should
   // pre-acquire all the loop devices in advance, so that when we run APEX
@@ -552,18 +569,22 @@ Result<LoopbackDeviceUniqueFd> CreateAndConfigureLoopDevice(
   // we just limit the scope that requires locking.
   android::base::Timer timer;
   Result<LoopbackDeviceUniqueFd> loop_device;
-  while (timer.duration() < 1s) {
-    loop_device = CreateLoopDevice(target, image_offset, image_size);
+  while (true) {
+    loop_device = CreateLoopDevice(target_fd, use_buffered_io, image_offset,
+                                   image_size, loop_id);
     if (loop_device.ok()) {
       break;
     }
+    if (timer.duration() >= 1s) {
+      return loop_device.error();
+    }
+    LOG(WARNING) << "Failed to create a new loop device. Retrying...: "
+                 << loop_device.error();
+    // The loop_id might be in use. Let's retry with -1 to get a new free slot.
+    loop_id = kFreeLoopId;
     std::this_thread::sleep_for(5ms);
   }
 
-  if (!loop_device.ok()) {
-    return loop_device.error();
-  }
-
   Result<void> sched_status = ConfigureScheduler(loop_device->name);
   if (!sched_status.ok()) {
     LOG(WARNING) << "Configuring I/O scheduler failed: "
@@ -583,33 +604,6 @@ Result<LoopbackDeviceUniqueFd> CreateAndConfigureLoopDevice(
   return loop_device;
 }
 
-void DestroyLoopDevice(const std::string& path, const DestroyLoopFn& extra) {
-  unique_fd fd(open(path.c_str(), O_RDWR | O_CLOEXEC));
-  if (fd.get() == -1) {
-    if (errno != ENOENT) {
-      PLOG(WARNING) << "Failed to open " << path;
-    }
-    return;
-  }
-
-  struct loop_info64 li;
-  if (ioctl(fd.get(), LOOP_GET_STATUS64, &li) < 0) {
-    if (errno != ENXIO) {
-      PLOG(WARNING) << "Failed to LOOP_GET_STATUS64 " << path;
-    }
-    return;
-  }
-
-  auto id = std::string((char*)li.lo_crypt_name);
-  if (StartsWith(id, kApexLoopIdPrefix)) {
-    extra(path, id);
-
-    if (ioctl(fd.get(), LOOP_CLR_FD, 0) < 0) {
-      PLOG(WARNING) << "Failed to LOOP_CLR_FD " << path;
-    }
-  }
-}
-
 }  // namespace loop
 }  // namespace apex
 }  // namespace android
diff --git a/apexd/apexd_loop.h b/apexd/apexd_loop.h
index 14ff8a3f..18e70b1b 100644
--- a/apexd/apexd_loop.h
+++ b/apexd/apexd_loop.h
@@ -29,6 +29,8 @@ namespace loop {
 
 using android::base::unique_fd;
 
+constexpr int32_t kFreeLoopId = -1;
+
 struct LoopbackDeviceUniqueFd {
   unique_fd device_fd;
   std::string name;
@@ -63,11 +65,8 @@ android::base::Result<void> ConfigureReadAhead(const std::string& device_path);
 android::base::Result<void> PreAllocateLoopDevices(size_t num);
 
 android::base::Result<LoopbackDeviceUniqueFd> CreateAndConfigureLoopDevice(
-    const std::string& target, uint32_t image_offset, size_t image_size);
-
-using DestroyLoopFn =
-    std::function<void(const std::string&, const std::string&)>;
-void DestroyLoopDevice(const std::string& path, const DestroyLoopFn& extra);
+    const std::string& target, uint32_t image_offset, size_t image_size,
+    int32_t loop_id = kFreeLoopId);
 
 }  // namespace loop
 }  // namespace apex
diff --git a/apexd/apexd_loop_test.cpp b/apexd/apexd_loop_test.cpp
new file mode 100644
index 00000000..5bce75dd
--- /dev/null
+++ b/apexd/apexd_loop_test.cpp
@@ -0,0 +1,133 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "apexd_loop.h"
+
+#include <android-base/file.h>
+#include <android-base/result-gmock.h>
+#include <android-base/scopeguard.h>
+#include <android-base/unique_fd.h>
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+#include <linux/loop.h>
+#include <sys/mount.h>
+#include <sys/stat.h>
+#include <unistd.h>
+
+#include <string>
+
+#include "apex_file.h"
+#include "apexd_test_utils.h"
+
+using android::base::unique_fd;
+using android::base::testing::Ok;
+using ::testing::Not;
+using ::testing::internal::CaptureStderr;
+using ::testing::internal::GetCapturedStderr;
+
+namespace android::apex {
+
+static void AssertLoopIsCleared(const std::string& path) {
+  unique_fd fd(open(path.c_str(), O_RDWR | O_CLOEXEC));
+  ASSERT_TRUE(fd.ok());
+  ASSERT_EQ(ioctl(fd, LOOP_CLR_FD, 0), -1);
+  ASSERT_EQ(errno, ENXIO);
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
+TEST(Loop, ClearedOnExit) {
+  auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  std::string loop_name;
+  {
+    auto loop = loop::CreateAndConfigureLoopDevice(
+        apex->GetPath(), apex->GetImageOffset().value(),
+        apex->GetImageSize().value());
+    ASSERT_THAT(loop, Ok());
+    loop_name = loop->name;
+  }
+  AssertLoopIsCleared(loop_name);
+}
+
+TEST(Loop, ClearedOnCloseGood) {
+  auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  std::string loop_name;
+  {
+    auto loop = loop::CreateAndConfigureLoopDevice(
+        apex->GetPath(), apex->GetImageOffset().value(),
+        apex->GetImageSize().value());
+    ASSERT_THAT(loop, Ok());
+    loop_name = loop->name;
+    loop->CloseGood();
+  }
+  AssertLoopIsCleared(loop_name);
+}
+
+TEST(Loop, AliveWhileMounted) {
+  auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  TemporaryDir temp_dir;
+  auto umount = base::make_scope_guard(
+      [&]() { umount2(temp_dir.path, UMOUNT_NOFOLLOW); });
+  std::string loop_name;
+  {
+    // Create a loop for apex paylaod
+    auto loop = loop::CreateAndConfigureLoopDevice(
+        apex->GetPath(), apex->GetImageOffset().value(),
+        apex->GetImageSize().value());
+    ASSERT_THAT(loop, Ok());
+    loop_name = loop->name;
+
+    // Mount the payload filesystem
+    uint32_t mount_flags = MS_NOATIME | MS_NODEV | MS_DIRSYNC | MS_RDONLY;
+    auto rc = mount(loop_name.c_str(), temp_dir.path,
+                    apex->GetFsType().value().c_str(), mount_flags, nullptr);
+    ASSERT_EQ(rc, 0) << strerror(errno);
+
+    // CloseGood() prevents LOOP_CLR_FD on exit(dtor)
+    loop->CloseGood();
+  }
+
+  std::string manifest_path = std::string(temp_dir.path) + "/apex_manifest.pb";
+  ASSERT_EQ(access(manifest_path.c_str(), F_OK), 0);
+  ASSERT_EQ(access(loop_name.c_str(), F_OK), 0);
+
+  ASSERT_EQ(umount2(temp_dir.path, UMOUNT_NOFOLLOW), 0);
+  umount.Disable();
+
+  // loop is cleaned up automatically after unmount.
+  ASSERT_NE(access(manifest_path.c_str(), F_OK), 0);
+  AssertLoopIsCleared(loop_name);
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
+}  // namespace android::apex
\ No newline at end of file
diff --git a/apexd/apexd_main.cpp b/apexd/apexd_main.cpp
index c0c8e9a8..c07b1a29 100644
--- a/apexd/apexd_main.cpp
+++ b/apexd/apexd_main.cpp
@@ -49,12 +49,6 @@ int HandleSubcommand(int argc, char** argv) {
     SetDefaultTag("apexd-unmount-all");
     bool also_include_staged_apexes =
         argc >= 3 && strcmp("--also-include-staged-apexes", argv[2]) == 0;
-    std::unique_ptr<android::apex::ApexSessionManager> session_manager;
-    if (also_include_staged_apexes) {
-      session_manager = android::apex::ApexSessionManager::Create(
-          android::apex::GetSessionsDir());
-      android::apex::InitializeSessionManager(session_manager.get());
-    }
     return android::apex::UnmountAll(also_include_staged_apexes);
   }
 
@@ -62,12 +56,6 @@ int HandleSubcommand(int argc, char** argv) {
     SetDefaultTag("apexd-otachroot");
     bool also_include_staged_apexes =
         argc >= 3 && strcmp("--also-include-staged-apexes", argv[2]) == 0;
-    std::unique_ptr<android::apex::ApexSessionManager> session_manager;
-    if (also_include_staged_apexes) {
-      session_manager = android::apex::ApexSessionManager::Create(
-          android::apex::GetSessionsDir());
-      android::apex::InitializeSessionManager(session_manager.get());
-    }
     return android::apex::OnOtaChrootBootstrap(also_include_staged_apexes);
   }
 
@@ -84,10 +72,6 @@ int HandleSubcommand(int argc, char** argv) {
       android::apex::InitializeVold(&*vold_service_st);
     }
 
-    auto session_manager = android::apex::ApexSessionManager::Create(
-        android::apex::GetSessionsDir());
-    android::apex::InitializeSessionManager(session_manager.get());
-
     int result = android::apex::SnapshotOrRestoreDeUserData();
 
     if (result == 0) {
@@ -135,19 +119,6 @@ int main(int argc, char** argv) {
   // TODO(b/158468454): add a -v flag or an external setting to change severity.
   android::base::SetMinimumLogSeverity(android::base::INFO);
 
-  // Two flags are used here:
-  // CLI flag `--enable-brand-new-apex`: used to control the feature usage in
-  // individual targets
-  // AConfig flag `enable_brand_new_apex`: used to advance
-  // the feature to different release stages, and applies to all targets
-  if (flags::enable_brand_new_apex()) {
-    if (argv[1] != nullptr && strcmp("--enable-brand-new-apex", argv[1]) == 0) {
-      android::apex::ApexFileRepository::EnableBrandNewApex();
-      argc--;
-      argv++;
-    }
-  }
-
   const bool has_subcommand = argv[1] != nullptr;
   LOG(INFO) << "Started. subcommand = "
             << (has_subcommand ? argv[1] : "(null)");
@@ -163,7 +134,24 @@ int main(int argc, char** argv) {
 
   InstallSigtermSignalHandler();
 
-  android::apex::SetConfig(android::apex::kDefaultConfig);
+  auto config = android::apex::kDefaultConfig;
+  if constexpr (flags::mount_before_data()) {
+    if (android::base::GetIntProperty("ro.init.mnt_ns.count", 2) == 1) {
+      config.mount_before_data = true;
+    }
+  }
+  android::apex::SetConfig(config);
+
+  // Two flags are used here:
+  // * sysprop flag `apexd.config.brand_new_apex`: used to control the feature
+  //   usage in individual targets
+  // * AConfig flag `enable_brand_new_apex`: used to advance the feature to
+  //   different release stages, and applies to all targets.
+  if constexpr (flags::enable_brand_new_apex()) {
+    if (android::base::GetBoolProperty("apexd.config.brand_new_apex", false)) {
+      android::apex::ApexFileRepository::EnableBrandNewApex();
+    }
+  }
 
   android::apex::ApexdLifecycle& lifecycle =
       android::apex::ApexdLifecycle::GetInstance();
@@ -173,14 +161,14 @@ int main(int argc, char** argv) {
       android::apex::kMetadataImagesDir, android::apex::kDataImagesDir);
   android::apex::InitializeImageManager(image_manager.get());
 
-  if (has_subcommand) {
-    return HandleSubcommand(argc, argv);
-  }
-
   auto session_manager = android::apex::ApexSessionManager::Create(
       android::apex::GetSessionsDir());
   android::apex::InitializeSessionManager(session_manager.get());
 
+  if (has_subcommand) {
+    return HandleSubcommand(argc, argv);
+  }
+
   android::base::Result<android::apex::VoldCheckpointInterface>
       vold_service_st = android::apex::VoldCheckpointInterface::Create();
   android::apex::VoldCheckpointInterface* vold_service = nullptr;
@@ -195,13 +183,6 @@ int main(int argc, char** argv) {
 
   if (booting) {
     android::apex::OnStart();
-  } else {
-    // TODO(b/172911822): Trying to use data apex related ApexFileRepository
-    //  apis without initializing it should throw error. Also, unit tests should
-    //  not pass without initialization.
-    // TODO(b/172911822): Consolidate this with Initialize() when
-    //  ApexFileRepository can act as cache and re-scanning is not expensive
-    android::apex::InitializeDataApex();
   }
   // start apexservice before ApexdLifecycle::WaitForBootStatus which waits for
   // IApexService::markBootComplete().
@@ -215,7 +196,7 @@ int main(int argc, char** argv) {
     // themselves should wait for the ready status instead, which is set when
     // the "--snapshotde" subcommand is received and snapshot/restore is
     // complete.
-    android::apex::OnAllPackagesActivated(/*is_bootstrap=*/false);
+    android::apex::OnAllPackagesActivated();
     lifecycle.WaitForBootStatus(session_manager->HasActiveSession());
     // Run cleanup routine on boot complete.
     // This should run before AllowServiceShutdown() to prevent
diff --git a/apexd/apexd_microdroid.cpp b/apexd/apexd_microdroid.cpp
index d78b2c57..f68792e4 100644
--- a/apexd/apexd_microdroid.cpp
+++ b/apexd/apexd_microdroid.cpp
@@ -37,7 +37,9 @@ static const android::apex::ApexdConfig kMicrodroidConfig = {
     nullptr, /* staged_session_dir */
     android::apex::kVmPayloadMetadataPartitionProp,
     nullptr, /* active_apex_selinux_ctx */
+    {},      /* brand_new_apex_config_dirs */
     false,   /* mount_before_data */
+    nullptr, /* metadata_config_dir */
 };
 
 int main(int /*argc*/, char** argv) {
diff --git a/apexd/apexd_private.h b/apexd/apexd_private.h
index 9d66f143..a15e0b3c 100644
--- a/apexd/apexd_private.h
+++ b/apexd/apexd_private.h
@@ -34,7 +34,8 @@ static constexpr int kMkdirMode = 0755;
 
 namespace apexd_private {
 
-android::base::Result<std::string> GetVerifiedPublicKey(const ApexFile& apex);
+base::Result<void> CheckBundledPublicKeyMatchesPreinstalled(
+    const ApexFile& apex);
 
 std::string GetPackageMountPoint(const ::apex::proto::ApexManifest& manifest);
 std::string GetPackageTempMountPoint(
diff --git a/apexd/apexd_session.cpp b/apexd/apexd_session.cpp
index 025caa20..b3e0e5dd 100644
--- a/apexd/apexd_session.cpp
+++ b/apexd/apexd_session.cpp
@@ -247,6 +247,11 @@ Result<ApexSession> ApexSessionManager::GetSession(int session_id) const {
 std::vector<ApexSession> ApexSessionManager::GetSessions() const {
   std::vector<ApexSession> sessions;
 
+  // Return successfully without warning if the directory doesn't exist yet.
+  if (access(sessions_base_dir_.c_str(), F_OK) != 0) {
+    return sessions;
+  }
+
   auto walk_status = WalkDir(sessions_base_dir_, [&](const auto& entry) {
     if (!entry.is_directory()) {
       return;
@@ -265,7 +270,6 @@ std::vector<ApexSession> ApexSessionManager::GetSessions() const {
 
   if (!walk_status.ok()) {
     LOG(WARNING) << walk_status.error();
-    return sessions;
   }
 
   return sessions;
diff --git a/apexd/apexd_test.cpp b/apexd/apexd_test.cpp
index f0b87aa4..4d85fc95 100644
--- a/apexd/apexd_test.cpp
+++ b/apexd/apexd_test.cpp
@@ -22,6 +22,7 @@
 #include <android-base/scopeguard.h>
 #include <android-base/stringprintf.h>
 #include <android-base/unique_fd.h>
+#include <gmock/gmock-matchers.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 #include <libdm/dm.h>
@@ -51,17 +52,20 @@
 #include "apexd_session.h"
 #include "apexd_test_utils.h"
 #include "apexd_utils.h"
+#include "apexd_verity.h"
 #include "com_android_apex.h"
-#include "gmock/gmock-matchers.h"
+#include "com_android_apex_flags.h"
 
 namespace android {
 namespace apex {
 
 using namespace std::literals;
 namespace fs = std::filesystem;
+namespace flags = com::android::apex::flags;
 
 using MountedApexData = MountedApexDatabase::MountedApexData;
 using android::apex::testing::ApexFileEq;
+using android::base::Error;
 using android::base::GetExecutableDirectory;
 using android::base::GetProperty;
 using android::base::Join;
@@ -82,16 +86,18 @@ using android::base::testing::WithMessage;
 using android::dm::DeviceMapper;
 using ::apex::proto::SessionState;
 using com::android::apex::testing::ApexInfoXmlEq;
-using ::testing::ByRef;
 using ::testing::Contains;
 using ::testing::ElementsAre;
 using ::testing::EndsWith;
 using ::testing::Eq;
+using ::testing::Field;
 using ::testing::HasSubstr;
 using ::testing::IsEmpty;
 using ::testing::Not;
+using ::testing::Optional;
 using ::testing::Pointwise;
 using ::testing::Property;
+using ::testing::SizeIs;
 using ::testing::StartsWith;
 using ::testing::UnorderedElementsAre;
 using ::testing::UnorderedElementsAreArray;
@@ -181,6 +187,8 @@ class ApexdUnitTest : public ::testing::Test {
     data_images_dir_ = StringPrintf("%s/data-images", td_.path);
     image_manager_ =
         ApexImageManager::Create(metadata_images_dir_, data_images_dir_);
+    metadata_config_dir_ = StringPrintf("%s/metadata-config", td_.path);
+    brand_new_config_dir_ = StringPrintf("%s/brand-new-config", td_.path);
 
     config_ = ApexdConfig{
         kTestApexdStatusSysprop,
@@ -191,7 +199,9 @@ class ApexdUnitTest : public ::testing::Test {
         staged_session_dir_.c_str(),
         kTestVmPayloadMetadataPartitionProp,
         kTestActiveApexSelinuxCtx,
-        false, /*mount_before_data*/
+        {{partition_, brand_new_config_dir_}}, /* brand_new_apex_config_dirs */
+        false,                                 /*mount_before_data*/
+        metadata_config_dir_.c_str(),
     };
   }
 
@@ -257,12 +267,10 @@ class ApexdUnitTest : public ::testing::Test {
     auto compressed_file_path =
         StringPrintf("%s/%s", built_in_dir.c_str(), name.c_str());
     auto compressed_apex = ApexFile::Open(compressed_file_path);
-    std::vector<ApexFileRef> compressed_apex_list;
-    compressed_apex_list.emplace_back(std::cref(*compressed_apex));
     auto decompressed =
-        ProcessCompressedApex(compressed_apex_list, /*is_ota_chroot*/ false);
-    CHECK(decompressed.size() == 1);
-    return std::make_tuple(compressed_file_path, decompressed[0].GetPath());
+        ProcessCompressedApex(*compressed_apex, /*is_ota_chroot*/ false);
+    CHECK(decompressed.ok());
+    return std::make_tuple(compressed_file_path, decompressed->GetPath());
   }
 
   std::tuple<std::string, std::string> PrepareCompressedApex(
@@ -300,7 +308,9 @@ class ApexdUnitTest : public ::testing::Test {
     ASSERT_EQ(mkdir(staged_session_dir_.c_str(), 0755), 0);
     ASSERT_EQ(mkdir(sessions_metadata_dir_.c_str(), 0755), 0);
     ASSERT_EQ(mkdir(metadata_images_dir_.c_str(), 0755), 0);
+    ASSERT_EQ(mkdir(metadata_config_dir_.c_str(), 0755), 0);
     ASSERT_EQ(mkdir(data_images_dir_.c_str(), 0755), 0);
+    ASSERT_EQ(mkdir(brand_new_config_dir_.c_str(), 0755), 0);
 
     // We don't really need for all the test cases, but until we refactor apexd
     // to use dependency injection instead of this SetConfig approach, it is not
@@ -336,129 +346,29 @@ class ApexdUnitTest : public ::testing::Test {
   std::string data_images_dir_;
   std::unique_ptr<ApexImageManager> image_manager_;
 
+  std::string metadata_config_dir_;
+  std::string brand_new_config_dir_;
+
   ApexdConfig config_;
 };
 
-TEST_F(ApexdUnitTest, SelectApexForActivationSuccess) {
-  AddPreInstalledApex("apex.apexd_test.apex");
-  AddPreInstalledApex("com.android.apex.cts.shim.apex");
-  auto shared_lib_1 = ApexFile::Open(AddPreInstalledApex(
-      "com.android.apex.test.sharedlibs_generated.v1.libvX.apex"));
-  auto& instance = ApexFileRepository::GetInstance();
-  // Pre-installed data needs to be present so that we can add data apex
-  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
-              Ok());
-
-  auto apexd_test_file = ApexFile::Open(AddDataApex("apex.apexd_test.apex"));
-  auto shim_v1 = ApexFile::Open(AddDataApex("com.android.apex.cts.shim.apex"));
-  // Normally both pre-installed and data apex would be activated for a shared
-  // libs apex, but if they are the same version only the data apex will be.
-  auto shared_lib_2 = ApexFile::Open(
-      AddDataApex("com.android.apex.test.sharedlibs_generated.v1.libvX.apex"));
-  ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
-
-  auto result = SelectApexForActivation();
-  ASSERT_EQ(result.size(), 3u);
-  ASSERT_THAT(result, UnorderedElementsAre(ApexFileEq(ByRef(*apexd_test_file)),
-                                           ApexFileEq(ByRef(*shim_v1)),
-                                           ApexFileEq(ByRef(*shared_lib_2))));
-}
-
-// Higher version gets priority when selecting for activation
-TEST_F(ApexdUnitTest, HigherVersionOfApexIsSelected) {
-  auto apexd_test_file_v2 =
-      ApexFile::Open(AddPreInstalledApex("apex.apexd_test_v2.apex"));
-  AddPreInstalledApex("com.android.apex.cts.shim.apex");
-  auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
-              Ok());
-
-  TemporaryDir data_dir;
-  AddDataApex("apex.apexd_test.apex");
-  auto shim_v2 =
-      ApexFile::Open(AddDataApex("com.android.apex.cts.shim.v2.apex"));
-  ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
-
-  auto result = SelectApexForActivation();
-  ASSERT_EQ(result.size(), 2u);
-
-  ASSERT_THAT(result,
-              UnorderedElementsAre(ApexFileEq(ByRef(*apexd_test_file_v2)),
-                                   ApexFileEq(ByRef(*shim_v2))));
-}
-
-// When versions are equal, non-pre-installed version gets priority
-TEST_F(ApexdUnitTest, DataApexGetsPriorityForSameVersions) {
-  AddPreInstalledApex("apex.apexd_test.apex");
-  AddPreInstalledApex("com.android.apex.cts.shim.apex");
-  // Initialize pre-installed APEX information
-  auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
-              Ok());
-
-  auto apexd_test_file = ApexFile::Open(AddDataApex("apex.apexd_test.apex"));
-  auto shim_v1 = ApexFile::Open(AddDataApex("com.android.apex.cts.shim.apex"));
-  // Initialize ApexFile repo
-  ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
-
-  auto result = SelectApexForActivation();
-  ASSERT_EQ(result.size(), 2u);
+TEST_F(ApexdUnitTest, VerifyVerityRootDigest) {
+  auto apex_ok = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  ASSERT_THAT(apex_ok, Ok());
+  ASSERT_THAT(VerifyVerityRootDigest(*apex_ok), Ok());
 
-  ASSERT_THAT(result, UnorderedElementsAre(ApexFileEq(ByRef(*apexd_test_file)),
-                                           ApexFileEq(ByRef(*shim_v1))));
-}
-
-// Both versions of shared libs can be selected when preinstalled version is
-// lower than data version
-TEST_F(ApexdUnitTest, SharedLibsCanHaveBothVersionSelected) {
-  auto shared_lib_v1 = ApexFile::Open(AddPreInstalledApex(
-      "com.android.apex.test.sharedlibs_generated.v1.libvX.apex"));
-  // Initialize pre-installed APEX information
-  auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
-              Ok());
-
-  auto shared_lib_v2 = ApexFile::Open(
-      AddDataApex("com.android.apex.test.sharedlibs_generated.v2.libvY.apex"));
-  // Initialize data APEX information
-  ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
-
-  auto result = SelectApexForActivation();
-  ASSERT_EQ(result.size(), 2u);
-
-  ASSERT_THAT(result, UnorderedElementsAre(ApexFileEq(ByRef(*shared_lib_v1)),
-                                           ApexFileEq(ByRef(*shared_lib_v2))));
-}
-
-// Data version of shared libs should not be selected if lower than
-// preinstalled version
-TEST_F(ApexdUnitTest, SharedLibsDataVersionDeletedIfLower) {
-  auto shared_lib_v2 = ApexFile::Open(AddPreInstalledApex(
-      "com.android.apex.test.sharedlibs_generated.v2.libvY.apex"));
-  // Initialize pre-installed APEX information
-  auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
-              Ok());
-
-  auto shared_lib_v1 = ApexFile::Open(
-      AddDataApex("com.android.apex.test.sharedlibs_generated.v1.libvX.apex"));
-  // Initialize data APEX information
-  ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
-
-  auto result = SelectApexForActivation();
-  ASSERT_EQ(result.size(), 1u);
-
-  ASSERT_THAT(result, UnorderedElementsAre(ApexFileEq(ByRef(*shared_lib_v2))));
+  auto apex_bad =
+      ApexFile::Open(GetTestFile("apex.apexd_test_corrupt_apex.apex"));
+  ASSERT_THAT(apex_bad, Ok());
+  ASSERT_THAT(VerifyVerityRootDigest(*apex_bad),
+              HasError(WithMessage(HasSubstr("root digest mismatch"))));
 }
 
 TEST_F(ApexdUnitTest, ProcessCompressedApex) {
   auto compressed_apex = ApexFile::Open(
       AddPreInstalledApex("com.android.apex.compressed.v1.capex"));
 
-  std::vector<ApexFileRef> compressed_apex_list;
-  compressed_apex_list.emplace_back(std::cref(*compressed_apex));
-  auto return_value =
-      ProcessCompressedApex(compressed_apex_list, /* is_ota_chroot= */ false);
+  auto return_value = ProcessCompressedApex(*compressed_apex, false);
 
   std::string decompressed_file_path = StringPrintf(
       "%s/com.android.apex.compressed@1%s", GetDecompressionDir().c_str(),
@@ -469,8 +379,7 @@ TEST_F(ApexdUnitTest, ProcessCompressedApex) {
 
   // Assert that return value contains decompressed APEX
   auto decompressed_apex = ApexFile::Open(decompressed_file_path);
-  ASSERT_THAT(return_value,
-              UnorderedElementsAre(ApexFileEq(ByRef(*decompressed_apex))));
+  ASSERT_THAT(return_value, HasValue(ApexFileEq(*decompressed_apex)));
 }
 
 TEST_F(ApexdUnitTest, ProcessCompressedApexRunsVerification) {
@@ -478,14 +387,10 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexRunsVerification) {
       "com.android.apex.compressed_key_mismatch_with_original.capex"));
   auto compressed_apex_version_mismatch = ApexFile::Open(
       AddPreInstalledApex("com.android.apex.compressed.v1_with_v2_apex.capex"));
-
-  std::vector<ApexFileRef> compressed_apex_list;
-  compressed_apex_list.emplace_back(std::cref(*compressed_apex_mismatch_key));
-  compressed_apex_list.emplace_back(
-      std::cref(*compressed_apex_version_mismatch));
-  auto return_value =
-      ProcessCompressedApex(compressed_apex_list, /* is_ota_chroot= */ false);
-  ASSERT_EQ(return_value.size(), 0u);
+  ASSERT_THAT(ProcessCompressedApex(*compressed_apex_mismatch_key, false),
+              Not(Ok()));
+  ASSERT_THAT(ProcessCompressedApex(*compressed_apex_version_mismatch, false),
+              Not(Ok()));
 }
 
 TEST_F(ApexdUnitTest, ValidateDecompressedApex) {
@@ -531,11 +436,9 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexCanBeCalledMultipleTimes) {
   auto compressed_apex = ApexFile::Open(
       AddPreInstalledApex("com.android.apex.compressed.v1.capex"));
 
-  std::vector<ApexFileRef> compressed_apex_list;
-  compressed_apex_list.emplace_back(std::cref(*compressed_apex));
   auto return_value =
-      ProcessCompressedApex(compressed_apex_list, /* is_ota_chroot= */ false);
-  ASSERT_EQ(return_value.size(), 1u);
+      ProcessCompressedApex(*compressed_apex, /* is_ota_chroot= */ false);
+  ASSERT_THAT(return_value, Ok());
 
   // Capture the creation time of the decompressed APEX
   std::error_code ec;
@@ -548,8 +451,8 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexCanBeCalledMultipleTimes) {
 
   // Now try to decompress the same capex again. It should not fail.
   return_value =
-      ProcessCompressedApex(compressed_apex_list, /* is_ota_chroot= */ false);
-  ASSERT_EQ(return_value.size(), 1u);
+      ProcessCompressedApex(*compressed_apex, /* is_ota_chroot= */ false);
+  ASSERT_THAT(return_value, Ok());
 
   // Ensure the decompressed APEX file did not change
   auto last_write_time_2 = fs::last_write_time(decompressed_apex_path, ec);
@@ -563,11 +466,9 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexOnOtaChroot) {
   auto compressed_apex = ApexFile::Open(
       AddPreInstalledApex("com.android.apex.compressed.v1.capex"));
 
-  std::vector<ApexFileRef> compressed_apex_list;
-  compressed_apex_list.emplace_back(std::cref(*compressed_apex));
   auto return_value =
-      ProcessCompressedApex(compressed_apex_list, /* is_ota_chroot= */ true);
-  ASSERT_EQ(return_value.size(), 1u);
+      ProcessCompressedApex(*compressed_apex, /* is_ota_chroot= */ true);
+  ASSERT_THAT(return_value, Ok());
 
   // Decompressed APEX should be located in decompression_dir
   std::string decompressed_file_path =
@@ -580,8 +481,7 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexOnOtaChroot) {
 
   // Assert that return value contains the decompressed APEX
   auto apex_file = ApexFile::Open(decompressed_file_path);
-  ASSERT_THAT(return_value,
-              UnorderedElementsAre(ApexFileEq(ByRef(*apex_file))));
+  ASSERT_THAT(return_value, HasValue(ApexFileEq(*apex_file)));
 }
 
 // When decompressing APEX, reuse existing OTA APEX
@@ -590,14 +490,11 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexReuseOtaApex) {
   auto compressed_apex = ApexFile::Open(AddPreInstalledApex(
       "com.android.apex.compressed.v1_not_decompressible.capex"));
 
-  std::vector<ApexFileRef> compressed_apex_list;
-  compressed_apex_list.emplace_back(std::cref(*compressed_apex));
-
   // If we try to decompress capex directly, it should fail since the capex
   // pushed is faulty and cannot be decompressed
   auto return_value =
-      ProcessCompressedApex(compressed_apex_list, /* is_ota_chroot= */ false);
-  ASSERT_EQ(return_value.size(), 0u);
+      ProcessCompressedApex(*compressed_apex, /* is_ota_chroot= */ false);
+  ASSERT_THAT(return_value, Not(Ok()));
 
   // But, if there is an ota_apex present for reuse, it should reuse that
   // and avoid decompressing the faulty capex
@@ -608,12 +505,12 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexReuseOtaApex) {
                    GetDecompressionDir().c_str(), kOtaApexPackageSuffix);
   fs::copy(GetTestFile("com.android.apex.compressed.v1.apex"), ota_apex_path);
   return_value =
-      ProcessCompressedApex(compressed_apex_list, /* is_ota_chroot= */ false);
-  ASSERT_EQ(return_value.size(), 1u);
+      ProcessCompressedApex(*compressed_apex, /* is_ota_chroot= */ false);
+  ASSERT_THAT(return_value, Ok());
 
   // Ota Apex should be cleaned up
   ASSERT_THAT(PathExists(ota_apex_path), HasValue(false));
-  ASSERT_EQ(return_value[0].GetPath(),
+  ASSERT_EQ(return_value->GetPath(),
             StringPrintf("%s/com.android.apex.compressed@1%s",
                          GetDecompressionDir().c_str(),
                          kDecompressedApexPackageSuffix));
@@ -640,7 +537,7 @@ TEST_F(ApexdUnitTest,
   {
     MountedApexDatabase db;
     db.AddMountedApex("com.android.apex.test_package", 1, "", preinstalled_path,
-                      "mount_point", "device_name");
+                      "mount_point", "device_name", "");
     bool result = ShouldAllocateSpaceForDecompression(
         "com.android.apex.test_package", 1, instance, db);
     ASSERT_TRUE(result);
@@ -653,7 +550,7 @@ TEST_F(ApexdUnitTest,
   {
     MountedApexDatabase db;
     db.AddMountedApex("com.android.apex.test_package", 2, "", data_path,
-                      "mount_point", "device_name");
+                      "mount_point", "device_name", "");
     bool result = ShouldAllocateSpaceForDecompression(
         "com.android.apex.test_package", 3, instance, db);
     ASSERT_TRUE(result);
@@ -663,7 +560,7 @@ TEST_F(ApexdUnitTest,
   {
     MountedApexDatabase db;
     db.AddMountedApex("com.android.apex.test_package", 2, "", data_path,
-                      "mount_point", "device_name");
+                      "mount_point", "device_name", "");
     bool result = ShouldAllocateSpaceForDecompression(
         "com.android.apex.test_package", 2, instance, db);
     ASSERT_FALSE(result);
@@ -680,7 +577,7 @@ TEST_F(ApexdUnitTest, ShouldAllocateSpaceForDecompression_VersionCompare) {
   // Fake mount
   MountedApexDatabase db;
   db.AddMountedApex("com.android.apex.compressed", 1, "", decompressed_path,
-                    "mount_point", "device_name");
+                    "mount_point", "device_name", "");
 
   {
     // New Compressed apex has higher version than decompressed data apex:
@@ -715,7 +612,7 @@ TEST_F(ApexdUnitTest, ShouldAllocateSpaceForDecompression_VersionCompare) {
   ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
   db.Reset();
   db.AddMountedApex("com.android.apex.compressed", 2, "", data_path,
-                    "mount_point", "device_name");
+                    "mount_point", "device_name", "");
   {
     // New Compressed apex has higher version as data apex: selected
     bool result = ShouldAllocateSpaceForDecompression(
@@ -844,8 +741,7 @@ TEST_F(ApexdUnitTest, GetStagedApexFilesNoChild) {
 
   auto apex_file = ApexFile::Open(
       StringPrintf("%s/apex.apexd_test.apex", GetStagedDir(123).c_str()));
-  ASSERT_THAT(result,
-              HasValue(UnorderedElementsAre(ApexFileEq(ByRef(*apex_file)))));
+  ASSERT_THAT(result, HasValue(UnorderedElementsAre(ApexFileEq(*apex_file))));
 }
 
 TEST_F(ApexdUnitTest, GetStagedApexFilesOnlyStaged) {
@@ -905,9 +801,8 @@ TEST_F(ApexdUnitTest, GetStagedApexFilesWithChildren) {
       StringPrintf("%s/apex.apexd_test.apex", GetStagedDir(124).c_str()));
   auto child_apex_file_2 = ApexFile::Open(
       StringPrintf("%s/apex.apexd_test.apex", GetStagedDir(125).c_str()));
-  ASSERT_THAT(*result,
-              UnorderedElementsAre(ApexFileEq(ByRef(*child_apex_file_1)),
-                                   ApexFileEq(ByRef(*child_apex_file_2))));
+  ASSERT_THAT(*result, UnorderedElementsAre(ApexFileEq(*child_apex_file_1),
+                                            ApexFileEq(*child_apex_file_2)));
 }
 
 // A test fixture to use for tests that mount/unmount apexes.
@@ -928,6 +823,12 @@ class ApexdMountTest : public ApexdUnitTest {
 
   void TearDown() override {
     SetBlockApexEnabled(false);
+    DeactivateAllPackages();
+    InitMetrics({});  // reset
+    ApexdUnitTest::TearDown();
+  }
+
+  void DeactivateAllPackages() {
     auto activated = std::vector<std::string>{};
     GetApexDatabaseForTesting().ForallMountedApexes(
         [&](auto pkg, auto data, auto latest) {
@@ -938,8 +839,6 @@ class ApexdMountTest : public ApexdUnitTest {
         LOG(ERROR) << "Failed to unmount " << apex << " : " << status.error();
       }
     }
-    InitMetrics({});  // reset
-    ApexdUnitTest::TearDown();
   }
 
   void SetBlockApexEnabled(bool enabled) {
@@ -1104,19 +1003,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsCorrupted) {
               HasError(WithMessage(HasSubstr("Can't verify /dev/block/dm-"))));
 }
 
-TEST_F(ApexdMountTest, InstallPackageRejectsProvidesSharedLibs) {
-  std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex(
-      {{GetPartition(), GetBuiltInDir()}});
-
-  ASSERT_THAT(ActivatePackage(file_path), Ok());
-
-  auto ret = InstallPackage(
-      GetTestFile("test.rebootless_apex_provides_sharedlibs.apex"),
-      /* force= */ false);
-  ASSERT_THAT(ret, HasError(WithMessage(HasSubstr(" is a shared libs APEX"))));
-}
-
 TEST_F(ApexdMountTest, InstallPackageRejectsProvidesNativeLibs) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
   ApexFileRepository::GetInstance().AddPreInstalledApex(
@@ -1130,20 +1016,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsProvidesNativeLibs) {
   ASSERT_THAT(ret, HasError(WithMessage(HasSubstr(" provides native libs"))));
 }
 
-TEST_F(ApexdMountTest, InstallPackageRejectsRequiresSharedApexLibs) {
-  std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex(
-      {{GetPartition(), GetBuiltInDir()}});
-
-  ASSERT_THAT(ActivatePackage(file_path), Ok());
-
-  auto ret = InstallPackage(
-      GetTestFile("test.rebootless_apex_requires_shared_apex_libs.apex"),
-      /* force= */ false);
-  ASSERT_THAT(ret,
-              HasError(WithMessage(HasSubstr(" requires shared apex libs"))));
-}
-
 TEST_F(ApexdMountTest, InstallPackageRejectsJniLibs) {
   std::string file_path = AddPreInstalledApex("test.rebootless_apex_v1.apex");
   ApexFileRepository::GetInstance().AddPreInstalledApex(
@@ -1251,7 +1123,7 @@ TEST_F(ApexdMountTest, InstallPackagePreInstallVersionActive) {
       "test.apex.rebootless", [&](const MountedApexData& data, bool latest) {
         ASSERT_TRUE(latest);
         ASSERT_EQ(data.full_path, ret->GetPath());
-        ASSERT_EQ(data.device_name, "test.apex.rebootless@2_1");
+        ASSERT_EQ(data.verity_name, "test.apex.rebootless@2_1");
       });
 }
 
@@ -1292,7 +1164,7 @@ TEST_F(ApexdMountTest, InstallPackagePreInstallVersionActiveSamegrade) {
       "test.apex.rebootless", [&](const MountedApexData& data, bool latest) {
         ASSERT_TRUE(latest);
         ASSERT_EQ(data.full_path, ret->GetPath());
-        ASSERT_EQ(data.device_name, "test.apex.rebootless@1_1");
+        ASSERT_EQ(data.verity_name, "test.apex.rebootless@1_1");
       });
 }
 
@@ -1379,7 +1251,7 @@ TEST_F(ApexdMountTest, InstallPackageDataVersionActive) {
       "test.apex.rebootless", [&](const MountedApexData& data, bool latest) {
         ASSERT_TRUE(latest);
         ASSERT_EQ(data.full_path, ret->GetPath());
-        ASSERT_EQ(data.device_name, "test.apex.rebootless@2_1");
+        ASSERT_EQ(data.verity_name, "test.apex.rebootless@2_1");
       });
 }
 
@@ -1432,7 +1304,7 @@ TEST_F(ApexdMountTest, InstallPackageResolvesPathCollision) {
       "test.apex.rebootless", [&](const MountedApexData& data, bool latest) {
         ASSERT_TRUE(latest);
         ASSERT_EQ(data.full_path, ret->GetPath());
-        ASSERT_EQ(data.device_name, "test.apex.rebootless@1_2");
+        ASSERT_EQ(data.verity_name, "test.apex.rebootless@1_2");
       });
 }
 
@@ -1480,7 +1352,7 @@ TEST_F(ApexdMountTest, InstallPackageDataVersionActiveSamegrade) {
       "test.apex.rebootless", [&](const MountedApexData& data, bool latest) {
         ASSERT_TRUE(latest);
         ASSERT_EQ(data.full_path, ret->GetPath());
-        ASSERT_EQ(data.device_name, "test.apex.rebootless@2_1");
+        ASSERT_EQ(data.verity_name, "test.apex.rebootless@2_1");
       });
 }
 
@@ -1570,7 +1442,7 @@ TEST_F(ApexdMountTest, InstallPackageUnmountFailedUpdatedApexActive) {
       "test.apex.rebootless", [&](const MountedApexData& data, bool latest) {
         ASSERT_TRUE(latest);
         ASSERT_EQ(data.full_path, file_path);
-        ASSERT_EQ(data.device_name, "test.apex.rebootless@1");
+        ASSERT_EQ(data.verity_name, "test.apex.rebootless@1");
       });
 }
 
@@ -1580,12 +1452,7 @@ TEST_F(ApexdMountTest, InstallPackageUpdatesApexInfoList) {
   ApexFileRepository::GetInstance().AddPreInstalledApex(
       {{GetPartition(), GetBuiltInDir()}});
 
-  ASSERT_THAT(ActivatePackage(apex_1), Ok());
-  ASSERT_THAT(ActivatePackage(apex_2), Ok());
-
-  // Call OnAllPackagesActivated to create /apex/apex-info-list.xml.
-  OnAllPackagesActivated(/* is_bootstrap= */ false);
-  // Check /apex/apex-info-list.xml was created.
+  OnStart();
   ASSERT_EQ(0, access("/apex/apex-info-list.xml", F_OK));
 
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_v2.apex"),
@@ -1625,12 +1492,6 @@ TEST_F(ApexdMountTest, InstallPackageUpdatesApexInfoList) {
                                    ApexInfoXmlEq(apex_info_xml_3)));
 }
 
-TEST_F(ApexdMountTest, ActivatePackageBannedName) {
-  auto status = ActivatePackage(GetTestFile("sharedlibs.apex"));
-  ASSERT_THAT(status,
-              HasError(WithMessage("Package name sharedlibs is not allowed.")));
-}
-
 TEST_F(ApexdMountTest, ActivatePackageNoCode) {
   std::string file_path = AddPreInstalledApex("apex.apexd_test_nocode.apex");
   ApexFileRepository::GetInstance().AddPreInstalledApex(
@@ -1764,40 +1625,6 @@ TEST_F(ApexdMountTest, DeactivePackageTearsDownVerityDevice) {
             dm.GetState("com.android.apex.test_package@2"));
 }
 
-TEST_F(ApexdMountTest, ActivateDeactivateSharedLibsApex) {
-  ASSERT_EQ(mkdir("/apex/sharedlibs", 0755), 0);
-  ASSERT_EQ(mkdir("/apex/sharedlibs/lib", 0755), 0);
-  ASSERT_EQ(mkdir("/apex/sharedlibs/lib64", 0755), 0);
-  auto deleter = make_scope_guard([]() {
-    std::error_code ec;
-    fs::remove_all("/apex/sharedlibs", ec);
-    if (ec) {
-      LOG(ERROR) << "Failed to delete /apex/sharedlibs : " << ec;
-    }
-  });
-
-  std::string file_path = AddPreInstalledApex(
-      "com.android.apex.test.sharedlibs_generated.v1.libvX.apex");
-  ApexFileRepository::GetInstance().AddPreInstalledApex(
-      {{GetPartition(), GetBuiltInDir()}});
-
-  ASSERT_THAT(ActivatePackage(file_path), Ok());
-
-  auto active_apex = GetActivePackage("com.android.apex.test.sharedlibs");
-  ASSERT_THAT(active_apex, Ok());
-  ASSERT_EQ(active_apex->GetPath(), file_path);
-
-  auto apex_mounts = GetApexMounts();
-  ASSERT_THAT(apex_mounts,
-              UnorderedElementsAre("/apex/com.android.apex.test.sharedlibs@1"));
-
-  ASSERT_THAT(DeactivatePackage(file_path), Ok());
-  ASSERT_THAT(GetActivePackage("com.android.apex.test.sharedlibs"), Not(Ok()));
-
-  auto new_apex_mounts = GetApexMounts();
-  ASSERT_EQ(new_apex_mounts.size(), 0u);
-}
-
 TEST_F(ApexdMountTest, RemoveInactiveDataApex) {
   AddPreInstalledApex("com.android.apex.compressed.v2.capex");
   // Add a decompressed apex that will not be mounted, so should be removed
@@ -2137,185 +1964,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataApexWithoutPreInstalledApex) {
               UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1)));
 }
 
-TEST_F(ApexdMountTest, OnOtaChrootBootstrapPreInstalledSharedLibsApex) {
-  std::string apex_path_1 = AddPreInstalledApex("apex.apexd_test.apex");
-  std::string apex_path_2 = AddPreInstalledApex(
-      "com.android.apex.test.sharedlibs_generated.v1.libvX.apex");
-  std::string apex_path_3 = AddDataApex("apex.apexd_test_v2.apex");
-
-  ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
-
-  auto apex_mounts = GetApexMounts();
-  ASSERT_THAT(apex_mounts,
-              UnorderedElementsAre("/apex/com.android.apex.test_package",
-                                   "/apex/com.android.apex.test_package@2",
-                                   "/apex/com.android.apex.test.sharedlibs@1"));
-
-  ASSERT_EQ(access("/apex/apex-info-list.xml", F_OK), 0);
-  auto info_list =
-      com::android::apex::readApexInfoList("/apex/apex-info-list.xml");
-  ASSERT_TRUE(info_list.has_value());
-  auto apex_info_xml_1 = com::android::apex::ApexInfo(
-      /* moduleName= */ "com.android.apex.test_package",
-      /* modulePath= */ apex_path_1,
-      /* preinstalledModulePath= */ apex_path_1,
-      /* versionCode= */ 1, /* versionName= */ "1",
-      /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false,
-      /* partition= */ GetPartitionString());
-  auto apex_info_xml_2 = com::android::apex::ApexInfo(
-      /* moduleName= */ "com.android.apex.test.sharedlibs",
-      /* modulePath= */ apex_path_2,
-      /* preinstalledModulePath= */ apex_path_2,
-      /* versionCode= */ 1, /* versionName= */ "1",
-      /* isFactory= */ true, /* isActive= */ true, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false,
-      /* partition= */ GetPartitionString());
-  auto apex_info_xml_3 = com::android::apex::ApexInfo(
-      /* moduleName= */ "com.android.apex.test_package",
-      /* modulePath= */ apex_path_3,
-      /* preinstalledModulePath= */ apex_path_1,
-      /* versionCode= */ 2, /* versionName= */ "2",
-      /* isFactory= */ false, /* isActive= */ true, GetMTime(apex_path_3),
-      /* provideSharedApexLibs= */ false,
-      /* partition= */ GetPartitionString());
-
-  ASSERT_THAT(info_list->getApexInfo(),
-              UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
-                                   ApexInfoXmlEq(apex_info_xml_2),
-                                   ApexInfoXmlEq(apex_info_xml_3)));
-
-  ASSERT_EQ(access("/apex/sharedlibs", F_OK), 0);
-
-  // Check /apex/sharedlibs is populated properly.
-  std::vector<std::string> sharedlibs;
-  for (const auto& p : fs::recursive_directory_iterator("/apex/sharedlibs")) {
-    if (fs::is_symlink(p)) {
-      auto src = fs::read_symlink(p.path());
-      ASSERT_EQ(p.path().filename(), src.filename());
-      sharedlibs.push_back(p.path().parent_path().string() + "->" +
-                           src.parent_path().string());
-    }
-  }
-
-  std::vector<std::string> expected = {
-      "/apex/sharedlibs/lib/libsharedlibtest.so->"
-      "/apex/com.android.apex.test.sharedlibs@1/lib/libsharedlibtest.so",
-      "/apex/sharedlibs/lib/libc++.so->"
-      "/apex/com.android.apex.test.sharedlibs@1/lib/libc++.so",
-  };
-
-  // On 64bit devices we also have lib64.
-  if (!GetProperty("ro.product.cpu.abilist64", "").empty()) {
-    expected.push_back(
-        "/apex/sharedlibs/lib64/libsharedlibtest.so->"
-        "/apex/com.android.apex.test.sharedlibs@1/lib64/libsharedlibtest.so");
-    expected.push_back(
-        "/apex/sharedlibs/lib64/libc++.so->"
-        "/apex/com.android.apex.test.sharedlibs@1/lib64/libc++.so");
-  }
-  ASSERT_THAT(sharedlibs, UnorderedElementsAreArray(expected));
-}
-
-TEST_F(ApexdMountTest, OnOtaChrootBootstrapSharedLibsApexBothVersions) {
-  std::string apex_path_1 = AddPreInstalledApex("apex.apexd_test.apex");
-  std::string apex_path_2 = AddPreInstalledApex(
-      "com.android.apex.test.sharedlibs_generated.v1.libvX.apex");
-  std::string apex_path_3 = AddDataApex("apex.apexd_test_v2.apex");
-  std::string apex_path_4 =
-      AddDataApex("com.android.apex.test.sharedlibs_generated.v2.libvY.apex");
-
-  ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
-
-  auto apex_mounts = GetApexMounts();
-  ASSERT_THAT(apex_mounts,
-              UnorderedElementsAre("/apex/com.android.apex.test_package",
-                                   "/apex/com.android.apex.test_package@2",
-                                   "/apex/com.android.apex.test.sharedlibs@1",
-                                   "/apex/com.android.apex.test.sharedlibs@2"));
-
-  ASSERT_EQ(access("/apex/apex-info-list.xml", F_OK), 0);
-  auto info_list =
-      com::android::apex::readApexInfoList("/apex/apex-info-list.xml");
-  ASSERT_TRUE(info_list.has_value());
-  auto apex_info_xml_1 = com::android::apex::ApexInfo(
-      /* moduleName= */ "com.android.apex.test_package",
-      /* modulePath= */ apex_path_1,
-      /* preinstalledModulePath= */ apex_path_1,
-      /* versionCode= */ 1, /* versionName= */ "1",
-      /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_path_1),
-      /* provideSharedApexLibs= */ false,
-      /* partition= */ GetPartitionString());
-  auto apex_info_xml_2 = com::android::apex::ApexInfo(
-      /* moduleName= */ "com.android.apex.test.sharedlibs",
-      /* modulePath= */ apex_path_2,
-      /* preinstalledModulePath= */ apex_path_2,
-      /* versionCode= */ 1, /* versionName= */ "1",
-      /* isFactory= */ true, /* isActive= */ false, GetMTime(apex_path_2),
-      /* provideSharedApexLibs= */ false,
-      /* partition= */ GetPartitionString());
-  auto apex_info_xml_3 = com::android::apex::ApexInfo(
-      /* moduleName= */ "com.android.apex.test_package",
-      /* modulePath= */ apex_path_3,
-      /* preinstalledModulePath= */ apex_path_1,
-      /* versionCode= */ 2, /* versionName= */ "2",
-      /* isFactory= */ false, /* isActive= */ true, GetMTime(apex_path_3),
-      /* provideSharedApexLibs= */ false,
-      /* partition= */ GetPartitionString());
-  auto apex_info_xml_4 = com::android::apex::ApexInfo(
-      /* moduleName= */ "com.android.apex.test.sharedlibs",
-      /* modulePath= */ apex_path_4,
-      /* preinstalledModulePath= */ apex_path_2,
-      /* versionCode= */ 2, /* versionName= */ "2",
-      /* isFactory= */ false, /* isActive= */ true, GetMTime(apex_path_4),
-      /* provideSharedApexLibs= */ false,
-      /* partition= */ GetPartitionString());
-
-  ASSERT_THAT(info_list->getApexInfo(),
-              UnorderedElementsAre(ApexInfoXmlEq(apex_info_xml_1),
-                                   ApexInfoXmlEq(apex_info_xml_2),
-                                   ApexInfoXmlEq(apex_info_xml_3),
-                                   ApexInfoXmlEq(apex_info_xml_4)));
-
-  ASSERT_EQ(access("/apex/sharedlibs", F_OK), 0);
-
-  // Check /apex/sharedlibs is populated properly.
-  // Because we don't want to hardcode full paths (they are pretty long and have
-  // a hash in them which might change if new prebuilts are dropped in), the
-  // assertion logic is a little bit clunky.
-  std::vector<std::string> sharedlibs;
-  for (const auto& p : fs::recursive_directory_iterator("/apex/sharedlibs")) {
-    if (fs::is_symlink(p)) {
-      auto src = fs::read_symlink(p.path());
-      ASSERT_EQ(p.path().filename(), src.filename());
-      sharedlibs.push_back(p.path().parent_path().string() + "->" +
-                           src.parent_path().string());
-    }
-  }
-
-  std::vector<std::string> expected = {
-      "/apex/sharedlibs/lib/libsharedlibtest.so->"
-      "/apex/com.android.apex.test.sharedlibs@2/lib/libsharedlibtest.so",
-      "/apex/sharedlibs/lib/libsharedlibtest.so->"
-      "/apex/com.android.apex.test.sharedlibs@1/lib/libsharedlibtest.so",
-      "/apex/sharedlibs/lib/libc++.so->"
-      "/apex/com.android.apex.test.sharedlibs@2/lib/libc++.so",
-  };
-  // On 64bit devices we also have lib64.
-  if (!GetProperty("ro.product.cpu.abilist64", "").empty()) {
-    expected.push_back(
-        "/apex/sharedlibs/lib64/libsharedlibtest.so->"
-        "/apex/com.android.apex.test.sharedlibs@2/lib64/libsharedlibtest.so");
-    expected.push_back(
-        "/apex/sharedlibs/lib64/libsharedlibtest.so->"
-        "/apex/com.android.apex.test.sharedlibs@1/lib64/libsharedlibtest.so");
-    expected.push_back(
-        "/apex/sharedlibs/lib64/libc++.so->"
-        "/apex/com.android.apex.test.sharedlibs@2/lib64/libc++.so");
-  }
-
-  ASSERT_THAT(sharedlibs, UnorderedElementsAreArray(expected));
-}
 
 // Test when we move from uncompressed APEX to CAPEX via ota
 TEST_F(ApexdMountTest, OnOtaChrootBootstrapOnlyCompressedApexes) {
@@ -2355,7 +2003,7 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapOnlyCompressedApexes) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed@1.chroot");
                          });
 }
@@ -2434,7 +2082,7 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapUpgradeCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed@2.chroot");
                          });
 }
@@ -2483,7 +2131,7 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed@1.chroot");
                          });
 }
@@ -2532,7 +2180,7 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapexDifferentDigest) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_ota_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed@1.chroot");
                          });
 
@@ -2597,7 +2245,7 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapexDifferentKey) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed@1.chroot");
                          });
 }
@@ -2723,7 +2371,7 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHigherThanCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, data_apex_path);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed@2.chroot");
                          });
 }
@@ -2767,7 +2415,7 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataLowerThanCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed@2.chroot");
                          });
 }
@@ -2817,7 +2465,7 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataSameAsCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, data_apex_path);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed@1.chroot");
                          });
 }
@@ -2861,7 +2509,7 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHasDifferentKeyThanCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed@1.chroot");
                          });
 }
@@ -2953,18 +2601,13 @@ static std::string GetSelinuxContext(const std::string& file) {
 
 TEST_F(ApexdMountTest, OnOtaChrootBootstrapSelinuxLabelsAreCorrect) {
   std::string apex_path_1 = AddPreInstalledApex("apex.apexd_test.apex");
-  std::string apex_path_2 = AddPreInstalledApex(
-      "com.android.apex.test.sharedlibs_generated.v1.libvX.apex");
-  std::string apex_path_3 = AddDataApex("apex.apexd_test_v2.apex");
+  std::string apex_path_2 = AddDataApex("apex.apexd_test_v2.apex");
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
   EXPECT_EQ(GetSelinuxContext("/apex/apex-info-list.xml"),
             "u:object_r:apex_info_file:s0");
 
-  EXPECT_EQ(GetSelinuxContext("/apex/sharedlibs"),
-            "u:object_r:apex_mnt_dir:s0");
-
   EXPECT_EQ(GetSelinuxContext("/apex/com.android.apex.test_package"),
             "u:object_r:system_file:s0");
   EXPECT_EQ(GetSelinuxContext("/apex/com.android.apex.test_package@2"),
@@ -2985,14 +2628,14 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDmDevicesHaveCorrectName) {
   db.ForallMountedApexes("com.android.apex.test_package_2",
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
-                           ASSERT_THAT(data.device_name, IsEmpty());
+                           ASSERT_THAT(data.verity_name, IsEmpty());
                            ASSERT_THAT(data.loop_name, StartsWith("/dev"));
                          });
   // com.android.apex.test_package should be mounted on top of dm-verity device.
   db.ForallMountedApexes("com.android.apex.test_package",
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.test_package@2.chroot");
                            ASSERT_THAT(data.loop_name, StartsWith("/dev"));
                          });
@@ -3286,7 +2929,7 @@ TEST_F(ApexdMountTest, OnStartOnlyPreInstalledCapexes) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed");
                          });
 }
@@ -3313,7 +2956,7 @@ TEST_F(ApexdMountTest, OnStartDataHasHigherVersionThanCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, apex_path_2);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed");
                          });
 }
@@ -3342,7 +2985,7 @@ TEST_F(ApexdMountTest, OnStartDataHasSameVersionAsCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, apex_path_2);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed");
                          });
 }
@@ -3375,7 +3018,7 @@ TEST_F(ApexdMountTest, OnStartSystemHasHigherVersionCapexThanData) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed");
                          });
 }
@@ -3407,7 +3050,7 @@ TEST_F(ApexdMountTest, OnStartFailsToActivateApexOnDataFallsBackToCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed");
                          });
 }
@@ -3440,7 +3083,7 @@ TEST_F(ApexdMountTest, OnStartFallbackToAlreadyDecompressedCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed");
                          });
 }
@@ -3476,7 +3119,7 @@ TEST_F(ApexdMountTest, OnStartFallbackToCapexSameVersion) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed");
                          });
 }
@@ -3506,7 +3149,7 @@ TEST_F(ApexdMountTest, OnStartCapexToApex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, apex_path);
-                           ASSERT_THAT(data.device_name, IsEmpty());
+                           ASSERT_THAT(data.verity_name, IsEmpty());
                          });
 }
 
@@ -3535,7 +3178,7 @@ TEST_F(ApexdMountTest, OnStartOrphanedDecompressedApexInActiveDirectory) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, apex_path);
-                           ASSERT_THAT(data.device_name, IsEmpty());
+                           ASSERT_THAT(data.verity_name, IsEmpty());
                          });
 }
 
@@ -3570,7 +3213,7 @@ TEST_F(ApexdMountTest, OnStartDecompressedApexVersionDifferentThanCapex) {
                          [&](const MountedApexData& data, bool latest) {
                            ASSERT_TRUE(latest);
                            ASSERT_EQ(data.full_path, decompressed_active_apex);
-                           ASSERT_EQ(data.device_name,
+                           ASSERT_EQ(data.verity_name,
                                      "com.android.apex.compressed");
                          });
 }
@@ -3806,45 +3449,6 @@ TEST_F(ApexdMountTest, UnmountAll) {
   ASSERT_EQ(new_apex_mounts.size(), 0u);
 }
 
-TEST_F(ApexdMountTest, UnmountAllSharedLibsApex) {
-  ASSERT_EQ(mkdir("/apex/sharedlibs", 0755), 0);
-  ASSERT_EQ(mkdir("/apex/sharedlibs/lib", 0755), 0);
-  ASSERT_EQ(mkdir("/apex/sharedlibs/lib64", 0755), 0);
-  auto deleter = make_scope_guard([]() {
-    std::error_code ec;
-    fs::remove_all("/apex/sharedlibs", ec);
-    if (ec) {
-      LOG(ERROR) << "Failed to delete /apex/sharedlibs : " << ec;
-    }
-  });
-
-  std::string apex_path_1 = AddPreInstalledApex(
-      "com.android.apex.test.sharedlibs_generated.v1.libvX.apex");
-  std::string apex_path_2 =
-      AddDataApex("com.android.apex.test.sharedlibs_generated.v2.libvY.apex");
-
-  auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
-              Ok());
-
-  ASSERT_THAT(ActivatePackage(apex_path_1), Ok());
-  ASSERT_THAT(ActivatePackage(apex_path_2), Ok());
-
-  auto apex_mounts = GetApexMounts();
-  ASSERT_THAT(apex_mounts,
-              UnorderedElementsAre("/apex/com.android.apex.test.sharedlibs@1",
-                                   "/apex/com.android.apex.test.sharedlibs@2"));
-
-  auto& db = GetApexDatabaseForTesting();
-  // UnmountAll expects apex database to empty, hence this reset.
-  db.Reset();
-
-  ASSERT_EQ(0, UnmountAll(/*also_include_staged_apexes=*/false));
-
-  auto new_apex_mounts = GetApexMounts();
-  ASSERT_EQ(new_apex_mounts.size(), 0u);
-}
-
 TEST_F(ApexdMountTest, UnmountAllDeferred) {
   AddPreInstalledApex("apex.apexd_test.apex");
   std::string apex_path_2 =
@@ -4001,57 +3605,6 @@ TEST_F(ApexdMountTest, OnStartInVmModeFailsWithDuplicateNames) {
   ASSERT_EQ(1, OnStartInVmMode());
 }
 
-TEST_F(ApexdMountTest, OnStartInVmSupportsMultipleSharedLibsApexes) {
-  MockCheckpointInterface checkpoint_interface;
-  InitializeVold(&checkpoint_interface);
-  SetBlockApexEnabled(true);
-
-  auto path1 =
-      AddBlockApex("com.android.apex.test.sharedlibs_generated.v1.libvX.apex",
-                   /*public_key=*/"", /*root_digest=*/"", /*is_factory=*/true);
-  auto path2 =
-      AddBlockApex("com.android.apex.test.sharedlibs_generated.v2.libvY.apex",
-                   /*public_key=*/"", /*root_digest=*/"", /*is_factory=*/false);
-
-  ASSERT_EQ(0, OnStartInVmMode());
-
-  // Btw, in case duplicates are sharedlibs apexes, both should be activated
-  auto apex_mounts = GetApexMounts();
-  ASSERT_THAT(apex_mounts,
-              UnorderedElementsAre("/apex/com.android.apex.test.sharedlibs@1",
-                                   "/apex/com.android.apex.test.sharedlibs@2"));
-}
-
-TEST_F(ApexdMountTest, OnStartInVmShouldRejectInDuplicateFactoryApexes) {
-  MockCheckpointInterface checkpoint_interface;
-  InitializeVold(&checkpoint_interface);
-  SetBlockApexEnabled(true);
-
-  auto path1 =
-      AddBlockApex("com.android.apex.test.sharedlibs_generated.v1.libvX.apex",
-                   /*public_key=*/"", /*root_digest=*/"", /*is_factory=*/true);
-  auto path2 =
-      AddBlockApex("com.android.apex.test.sharedlibs_generated.v2.libvY.apex",
-                   /*public_key=*/"", /*root_digest=*/"", /*is_factory=*/true);
-
-  ASSERT_EQ(1, OnStartInVmMode());
-}
-
-TEST_F(ApexdMountTest, OnStartInVmShouldRejectInDuplicateNonFactoryApexes) {
-  MockCheckpointInterface checkpoint_interface;
-  InitializeVold(&checkpoint_interface);
-  SetBlockApexEnabled(true);
-
-  auto path1 =
-      AddBlockApex("com.android.apex.test.sharedlibs_generated.v1.libvX.apex",
-                   /*public_key=*/"", /*root_digest=*/"", /*is_factory=*/false);
-  auto path2 =
-      AddBlockApex("com.android.apex.test.sharedlibs_generated.v2.libvY.apex",
-                   /*public_key=*/"", /*root_digest=*/"", /*is_factory=*/false);
-
-  ASSERT_EQ(1, OnStartInVmMode());
-}
-
 TEST_F(ApexdMountTest, OnStartInVmModeFailsWithWrongPubkey) {
   // Set system property to enable block apexes
   SetBlockApexEnabled(true);
@@ -4476,11 +4029,9 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexWrongSELinuxContext) {
   auto compressed_apex = ApexFile::Open(
       AddPreInstalledApex("com.android.apex.compressed.v1.capex"));
 
-  std::vector<ApexFileRef> compressed_apex_list;
-  compressed_apex_list.emplace_back(std::cref(*compressed_apex));
   auto return_value =
-      ProcessCompressedApex(compressed_apex_list, /* is_ota_chroot= */ false);
-  ASSERT_EQ(return_value.size(), 1u);
+      ProcessCompressedApex(*compressed_apex, /* is_ota_chroot= */ false);
+  ASSERT_THAT(return_value, Ok());
 
   auto decompressed_apex_path = StringPrintf(
       "%s/com.android.apex.compressed@1%s", GetDecompressionDir().c_str(),
@@ -4496,8 +4047,8 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexWrongSELinuxContext) {
             GetSelinuxContext(decompressed_apex_path));
 
   auto attempt_2 =
-      ProcessCompressedApex(compressed_apex_list, /* is_ota_chroot= */ false);
-  ASSERT_EQ(attempt_2.size(), 1u);
+      ProcessCompressedApex(*compressed_apex, /* is_ota_chroot= */ false);
+  ASSERT_THAT(attempt_2, Ok());
   // Verify that it again has correct context.
   ASSERT_EQ(kTestActiveApexSelinuxCtx,
             GetSelinuxContext(decompressed_apex_path));
@@ -4693,9 +4244,6 @@ TEST_F(ApexdMountTest, SendEventOnSubmitStagedSession) {
       {{ApexPartition::Vendor, GetBuiltInDir()}}));
 
   OnStart();
-  // checkvintf needs apex-info-list.xml to identify vendor APEXes.
-  // OnAllPackagesActivated() generates it.
-  OnAllPackagesActivated(/*bootstrap*/ false);
 
   PrepareStagedSession("com.android.apex.vendor.foo.with_vintf.apex", 239);
   ASSERT_RESULT_OK(SubmitStagedSession(239, {}, false, false, -1));
@@ -4713,27 +4261,6 @@ TEST_F(ApexdMountTest, SendEventOnSubmitStagedSession) {
   ASSERT_EQ(0u, spy->ended.size());
 }
 
-TEST(Loop, CreateWithApexFile) {
-  auto apex = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
-  ASSERT_THAT(apex, Ok());
-  ASSERT_TRUE(apex->GetImageOffset().has_value());
-  ASSERT_TRUE(apex->GetImageSize().has_value());
-
-  auto loop = loop::CreateAndConfigureLoopDevice(apex->GetPath(),
-                                                 apex->GetImageOffset().value(),
-                                                 apex->GetImageSize().value());
-  ASSERT_THAT(loop, Ok());
-}
-
-TEST(Loop, NoSuchFile) {
-  CaptureStderr();
-  {
-    auto loop = loop::CreateAndConfigureLoopDevice("invalid_path", 0, 0);
-    ASSERT_THAT(loop, Not(Ok()));
-  }
-  ASSERT_EQ(GetCapturedStderr(), "");
-}
-
 TEST_F(ApexdMountTest, SubmitStagedSessionSucceedVerifiedBrandNewApex) {
   ApexFileRepository::EnableBrandNewApex();
   auto& file_repository = ApexFileRepository::GetInstance();
@@ -4759,13 +4286,13 @@ TEST_F(ApexdMountTest,
   ApexFileRepository::EnableBrandNewApex();
   auto& file_repository = ApexFileRepository::GetInstance();
   const auto partition = ApexPartition::System;
-  TemporaryDir trusted_key_dir, data_dir;
+  TemporaryDir trusted_key_dir;
   fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
            trusted_key_dir.path);
-  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
   file_repository.AddBrandNewApexCredentialAndBlocklist(
       {{partition, trusted_key_dir.path}});
-  ASSERT_RESULT_OK(file_repository.AddDataApex(data_dir.path));
+  auto data_apex = AddDataApex("com.android.apex.brand.new.apex");
+  ASSERT_THAT(ActivatePackage(data_apex), Ok());
 
   PrepareStagedSession("com.android.apex.brand.new.v2.apex", 239);
   ASSERT_RESULT_OK(SubmitStagedSession(239, {}, false, false, -1));
@@ -4782,16 +4309,16 @@ TEST_F(ApexdMountTest,
   ApexFileRepository::EnableBrandNewApex();
   auto& file_repository = ApexFileRepository::GetInstance();
   const auto partition = ApexPartition::System;
-  TemporaryDir trusted_key_dir, data_dir;
+  TemporaryDir trusted_key_dir;
   fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
            trusted_key_dir.path);
   fs::copy(GetTestFile(
                "apexd_testdata/com.android.apex.brand.new.another.avbpubkey"),
            trusted_key_dir.path);
-  fs::copy(GetTestFile("com.android.apex.brand.new.apex"), data_dir.path);
   file_repository.AddBrandNewApexCredentialAndBlocklist(
       {{partition, trusted_key_dir.path}});
-  ASSERT_RESULT_OK(file_repository.AddDataApex(data_dir.path));
+  auto data_apex = AddDataApex("com.android.apex.brand.new.apex");
+  ASSERT_THAT(ActivatePackage(data_apex), Ok());
 
   PrepareStagedSession("com.android.apex.brand.new.v2.diffkey.apex", 239);
   auto ret = SubmitStagedSession(239, {}, false, false, -1);
@@ -4950,6 +4477,25 @@ TEST_F(ApexdMountTest, NonStagedUpdateFailVerifiedBrandNewApex) {
   file_repository.Reset();
 }
 
+TEST_F(ApexdMountTest, BootCompletedCleanup_CleanupInactiveApexes) {
+  AddPreInstalledApex("apex.apexd_test.apex");
+  auto selected = AddDataApex("apex.apexd_test_v2.apex");
+  auto ignored1 = AddDataApex("apex.apexd_test.apex");
+  auto ignored2 = AddDataApex("apex.apexd_test_different_app.apex");
+
+  auto& instance = ApexFileRepository::GetInstance();
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
+  OnStart();
+  ASSERT_THAT(FindFilesBySuffix(data_dir_, {kApexPackageSuffix}),
+              HasValue(UnorderedElementsAre(selected, ignored1, ignored2)));
+
+  // Inactive data apexes are removed on boot completion.
+  BootCompletedCleanup();
+  ASSERT_THAT(FindFilesBySuffix(data_dir_, {kApexPackageSuffix}),
+              HasValue(UnorderedElementsAre(selected)));
+}
+
 class SubmitStagedSessionTest : public ApexdMountTest {
  protected:
   void SetUp() override {
@@ -5025,18 +4571,6 @@ TEST_F(SubmitStagedSessionTest,
               HasError(WithMessage(HasSubstr("already staged"))));
 }
 
-TEST_F(SubmitStagedSessionTest, RejectStagingIfAnotherSessionIsBeingStaged) {
-  auto session_id = 42;
-  PrepareStagedSession("apex.apexd_test.apex", session_id);
-  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
-
-  // MarkStagedSessionReady is not called yet.
-  auto session_id2 = 43;
-  PrepareStagedSession("apex.apexd_test_different_app.apex", session_id2);
-  ASSERT_THAT(SubmitStagedSession(session_id2, {}, false, false, -1),
-              HasError(WithMessage(HasSubstr("being staged"))));
-}
-
 TEST_F(SubmitStagedSessionTest, RejectInstallPackageForStagedPackage) {
   auto session_id = 42;
   PrepareStagedSession("apex.apexd_test.apex", session_id);
@@ -5048,17 +4582,6 @@ TEST_F(SubmitStagedSessionTest, RejectInstallPackageForStagedPackage) {
       HasError(WithMessage(HasSubstr("already staged"))));
 }
 
-TEST_F(SubmitStagedSessionTest, RejectInstallIfAnotherSessionIsBeingStaged) {
-  auto session_id = 42;
-  PrepareStagedSession("apex.apexd_test.apex", session_id);
-  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
-
-  // MarkStagedSessionReady is not called yet.
-  ASSERT_THAT(InstallPackage(GetTestFile("apex.apexd_test_different_app.apex"),
-                             /* force= */ true),
-              HasError(WithMessage(HasSubstr("being staged"))));
-}
-
 TEST_F(SubmitStagedSessionTest, AbortedSessionDoesNotBlockNewStagingOrInstall) {
   auto session_id = 42;
   PrepareStagedSession("apex.apexd_test.apex", session_id);
@@ -5141,8 +4664,151 @@ class MountBeforeDataTest : public ApexdMountTest {
     AddPreInstalledApex("apex.apexd_test.apex");
     AddPreInstalledApex("apex.apexd_test_different_app.apex");
   }
+
+  void TearDown() override {
+    ApexdMountTest::TearDown();
+    // Unmap dm-linear devices mapped by ApexImageManager
+    for (const auto& image : image_manager_->GetAllImages()) {
+      image_manager_->UnmapImageIfExists(image);
+    }
+  }
+
+  void SimulateReboot() {
+    DeactivateAllPackages();
+    ApexFileRepository::GetInstance().Reset();
+    // Staged apexes in /data/app-staging are not accessible
+    DeleteDirContent(staged_session_dir_);
+    InitializeVold(nullptr);
+  }
 };
 
+TEST_F(MountBeforeDataTest, ActivatePinnedApex) {
+  ASSERT_EQ(0, OnBootstrap());
+
+  auto orig = ApexFile::Open(GetTestFile("apex.apexd_test_v2.apex"));
+  ASSERT_THAT(orig, Ok());
+  auto name = orig->GetManifest().name();
+
+  auto pinned = image_manager_->PinApexFiles(Single(*orig));
+  ASSERT_THAT(pinned, Ok());
+
+  auto image = pinned->at(0);
+  auto block_dev_path = image_manager_->MapImage(image);
+  ASSERT_THAT(block_dev_path, Ok());
+  auto unmap =
+      base::make_scope_guard([&]() { image_manager_->UnmapImage(image); });
+
+  ASSERT_THAT(ActivatePackage(*block_dev_path), Ok());
+  auto deactivate = base::make_scope_guard(
+      [&]() { ASSERT_THAT(DeactivatePackage(*block_dev_path), Ok()); });
+
+  // Checks if PopulateFromMounts() works okay with dm-linear device
+  MountedApexDatabase db;
+  db.PopulateFromMounts({});
+  auto linear_name = GetPackageId(orig->GetManifest()) + kDmLinearPayloadSuffix;
+  ASSERT_THAT(db.GetLatestMountedApex(name),
+              Optional(Field(&MountedApexData::linear_name, linear_name)));
+}
+
+TEST_F(MountBeforeDataTest, NonStagedInstall_SucceedAgainstPreinstalled) {
+  ASSERT_EQ(0, OnBootstrap());
+
+  // Install succeeds.
+  const auto apex_name = "com.android.apex.test_package"s;
+  ASSERT_THAT(InstallPackage(GetTestFile("apex.apexd_test_v2.apex"),
+                             /* force= */ true),
+              Ok());
+
+  // Active list is updated with new install.
+  auto active_list = image_manager_->GetApexList(ApexListType::ACTIVE);
+  ASSERT_THAT(active_list, HasValue(SizeIs(1)));
+  auto entry = active_list->at(0);
+  ASSERT_EQ(entry.apex_name, apex_name);
+
+  // Active mount is backed by the mapped device.
+  auto mount_data = GetApexDatabaseForTesting().GetLatestMountedApex(apex_name);
+  ASSERT_TRUE(mount_data.has_value());
+  ASSERT_THAT(image_manager_->MapImage(entry.image_name),
+              HasValue(mount_data->full_path));
+}
+
+TEST_F(MountBeforeDataTest, NonStagedInstall_SucceedAgainstData) {
+  ASSERT_EQ(0, OnBootstrap());
+
+  const auto apex_name = "com.android.apex.test_package"s;
+  ASSERT_THAT(InstallPackage(GetTestFile("apex.apexd_test.apex"),
+                             /* force= */ true),
+              Ok());
+  // Keep the path of the newly installed apex
+  auto mount_data = GetApexDatabaseForTesting().GetLatestMountedApex(apex_name);
+  ASSERT_TRUE(mount_data.has_value());
+  auto data_apex = ApexFile::Open(mount_data->full_path);
+
+  // Second installation replaces the previous one.
+  ASSERT_THAT(InstallPackage(GetTestFile("apex.apexd_test_v2.apex"),
+                             /* force= */ true),
+              Ok());
+
+  // and the previous apex is removed.
+  ASSERT_THAT(PathExists(data_apex->GetPath()), HasValue(false));
+  ASSERT_THAT(GetImageManager()->FindPinnedApex(*data_apex), Eq(std::nullopt));
+}
+
+TEST_F(MountBeforeDataTest, NonStagedInstall_FailToCreateBackingImage) {
+  // Setup failing image manager
+  struct MockApexImageManager : public ApexImageManager {
+    MockApexImageManager(std::string metadata_dir, std::string data_dir)
+        : ApexImageManager(metadata_dir, data_dir) {}
+    Result<std::vector<std::string>> PinApexFiles(
+        std::span<const ApexFile>) override {
+      return Error() << "Can't pin apex";
+    }
+  } test_im{metadata_images_dir_, data_images_dir_};
+  InitializeImageManager(&test_im);
+  auto guard =
+      make_scope_guard([&] { InitializeImageManager(image_manager_.get()); });
+
+  ASSERT_EQ(0, OnBootstrap());
+  auto mounts = GetApexMounts();
+  auto active_list = GetImageManager()->GetApexList(ApexListType::ACTIVE);
+
+  ASSERT_THAT(InstallPackage(GetTestFile("apex.apexd_test_v2.apex"),
+                             /* force= */ true),
+              HasError(WithMessage("Can't pin apex")));
+
+  // Others remain the same
+  ASSERT_THAT(GetApexMounts(), UnorderedElementsAreArray(mounts));
+  ASSERT_EQ(GetImageManager()->GetApexList(ApexListType::ACTIVE), active_list);
+}
+
+TEST_F(MountBeforeDataTest, NonStagedInstall_FailToMapImage) {
+  // Setup failing image manager
+  struct MockApexImageManager : public ApexImageManager {
+    MockApexImageManager(std::string metadata_dir, std::string data_dir)
+        : ApexImageManager(metadata_dir, data_dir) {}
+    Result<std::string> MapImage(const std::string&) override {
+      return Error() << "Can't map image";
+    }
+  } test_im{metadata_images_dir_, data_images_dir_};
+  InitializeImageManager(&test_im);
+  auto guard =
+      make_scope_guard([&] { InitializeImageManager(image_manager_.get()); });
+
+  ASSERT_EQ(0, OnBootstrap());
+  auto mounts = GetApexMounts();
+  auto active_list = GetImageManager()->GetApexList(ApexListType::ACTIVE);
+
+  ASSERT_THAT(InstallPackage(GetTestFile("apex.apexd_test_v2.apex"),
+                             /* force= */ true),
+              HasError(WithMessage("Can't map image")));
+
+  // Others remain the same
+  ASSERT_THAT(GetApexMounts(), UnorderedElementsAreArray(mounts));
+  ASSERT_EQ(GetImageManager()->GetApexList(ApexListType::ACTIVE), active_list);
+  // Pinned apex is deleted on error.
+  ASSERT_THAT(GetImageManager()->GetAllImages(), IsEmpty());
+}
+
 TEST_F(MountBeforeDataTest, StagingCreatesBackingImages) {
   ASSERT_EQ(0, OnBootstrap());
 
@@ -5176,6 +4842,135 @@ TEST_F(MountBeforeDataTest, OnBootstrapActivatesAllApexes) {
                                    "/apex/com.android.apex.test_package@1"s));
 }
 
+TEST_F(MountBeforeDataTest, OnBootstrapActivatesAllApexes_ActivateData) {
+  // Prepare pinned data apex before onBootstrap()
+  auto data_apex = ApexFile::Open(GetTestFile("apex.apexd_test_v2.apex"));
+  auto pinned = image_manager_->PinApexFiles(Single(*data_apex));
+  ASSERT_THAT(pinned, Ok());
+  // Prepare the active list
+  std::vector<ApexListEntry> list;
+  list.emplace_back(pinned->at(0), data_apex->GetManifest().name());
+  ASSERT_THAT(image_manager_->UpdateApexList(ApexListType::ACTIVE, list), Ok());
+
+  ASSERT_EQ(0, OnBootstrap());
+
+  // Pinned apex (com.android.apex.test_package@2) is activated.
+  ASSERT_THAT(GetApexMounts(),
+              Contains("/apex/com.android.apex.test_package@2"));
+}
+
+TEST_F(MountBeforeDataTest, OnBootstrapActivatesAllApexes_IgnoreInvalidImage) {
+  // Prepare pinned data apex before onBootstrap()
+  auto data_apex = ApexFile::Open(GetTestFile("apex.apexd_test_v2.apex"));
+  auto pinned = image_manager_->PinApexFiles(Single(*data_apex));
+  ASSERT_THAT(pinned, Ok());
+  // Prepare the active list
+  std::vector<ApexListEntry> list;
+  list.emplace_back("invalid", "invalid");                            // invalid
+  list.emplace_back(pinned->at(0), data_apex->GetManifest().name());  // valid
+  ASSERT_THAT(image_manager_->UpdateApexList(ApexListType::ACTIVE, list), Ok());
+
+  // OnBootstrap() should succeed with valid ones.
+  ASSERT_EQ(0, OnBootstrap());
+  ASSERT_THAT(GetApexMounts(),
+              Contains("/apex/com.android.apex.test_package@2"));
+}
+
+TEST_F(MountBeforeDataTest, OnBootstrapActivatesStagedSessions) {
+  // Given that com.android.apex.test_package@1 is preinstalled
+  ASSERT_EQ(0, OnBootstrap());
+  auto mounts = GetApexMounts();
+
+  // Stage com.android.apex.test_package@2
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test_v2.apex", session_id);
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+  ASSERT_THAT(MarkStagedSessionReady(session_id), Ok());
+
+  SimulateReboot();
+
+  ASSERT_THAT(OnBootstrap(), Eq(0));
+
+  // Staged session should be activated.
+  auto session = GetSessionManager()->GetSession(session_id);
+  ASSERT_THAT(session, Ok());
+  ASSERT_EQ(session->GetState(), SessionState::ACTIVATED);
+
+  // The apex in the session should be activated.
+  std::ranges::replace(mounts, "/apex/com.android.apex.test_package@1"s,
+                       "/apex/com.android.apex.test_package@2"s);
+  ASSERT_THAT(GetApexMounts(), UnorderedElementsAreArray(mounts));
+}
+
+TEST_F(MountBeforeDataTest, OnStartSkipsActivation) {
+  ASSERT_EQ(0, OnBootstrap());
+  auto mounts = GetApexMounts();
+
+  // Apexes in /data/apex/active should be ignored.
+  AddDataApex("apex.apexd_test_v2.apex");
+  OnStart();
+
+  // Mounts remain unchanged.
+  ASSERT_THAT(GetApexMounts(), Eq(mounts));
+}
+
+TEST_F(MountBeforeDataTest, BootCompletedCleanup_RemovesInactiveDataApexes) {
+  // apex0 is valid and apex1 is unknown.
+  auto apex0 = ApexFile::Open(GetTestFile("apex.apexd_test_v2.apex"));
+  auto apex1 = ApexFile::Open(GetTestFile("test.rebootless_apex_v1.apex"));
+  auto pinned = image_manager_->PinApexFiles(std::vector{*apex0, *apex1});
+  ASSERT_THAT(pinned, HasValue(SizeIs(2)));
+  std::vector<ApexListEntry> active_list{
+      {pinned->at(0), apex0->GetManifest().name()},
+      {pinned->at(1), apex1->GetManifest().name()},
+  };
+  ASSERT_THAT(image_manager_->UpdateApexList(ApexListType::ACTIVE, active_list),
+              Ok());
+
+  // APEX files in /data/apex/active should be skipped and removed.
+  auto data_apex = AddDataApex("apex.apexd_test_v2.apex");
+
+  ASSERT_EQ(0, OnBootstrap());
+  BootCompletedCleanup();
+
+  ASSERT_THAT(PathExists(data_apex), HasValue(false));
+  ASSERT_THAT(image_manager_->GetAllImages(),
+              UnorderedElementsAre(pinned->at(0)));
+}
+
+TEST_F(MountBeforeDataTest, BootCompletedCleanup_CreatesConfigFile) {
+  if (!flags::mount_before_data()) {
+    GTEST_SKIP() << "mount_before_data is off";
+  }
+  ASSERT_EQ(0, OnBootstrap());
+  BootCompletedCleanup();
+  auto config_file = metadata_config_dir_ + "/mount_before_data";
+  ASSERT_EQ(0, access(config_file.c_str(), F_OK));
+}
+
+TEST_F(MountBeforeDataTest, BrandNewApex) {
+  fs::copy(GetTestFile("apexd_testdata/com.android.apex.brand.new.avbpubkey"),
+           brand_new_config_dir_);
+  ApexFileRepository::EnableBrandNewApex();
+  ASSERT_EQ(0, OnBootstrap());
+
+  // Prepare brand-new apex installation
+  auto session_id = 42;
+  PrepareStagedSession("com.android.apex.brand.new.apex", session_id);
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+  ASSERT_THAT(MarkStagedSessionReady(session_id), Ok());
+
+  SimulateReboot();
+  ApexFileRepository::EnableBrandNewApex();
+  ASSERT_EQ(0, OnBootstrap());
+
+  // Staged session should be activated.
+  auto session = GetSessionManager()->GetSession(session_id);
+  ASSERT_THAT(session, Ok());
+  ASSERT_EQ(session->GetState(), SessionState::ACTIVATED);
+  ApexFileRepository::GetInstance().Reset();
+}
+
 class LogTestToLogcat : public ::testing::EmptyTestEventListener {
   void OnTestStart(const ::testing::TestInfo& test_info) override {
 #ifdef __ANDROID__
diff --git a/apexd/apexd_test_utils.h b/apexd/apexd_test_utils.h
index bd76dd52..4e075e92 100644
--- a/apexd/apexd_test_utils.h
+++ b/apexd/apexd_test_utils.h
@@ -105,17 +105,16 @@ MATCHER_P(ApexFileEq, other, "") {
   using ::testing::Property;
 
   return ExplainMatchResult(
-      AllOf(Property("path", &ApexFile::GetPath, Eq(other.get().GetPath())),
+      AllOf(Property("path", &ApexFile::GetPath, Eq(other.GetPath())),
             Property("image_offset", &ApexFile::GetImageOffset,
-                     Eq(other.get().GetImageOffset())),
+                     Eq(other.GetImageOffset())),
             Property("image_size", &ApexFile::GetImageSize,
-                     Eq(other.get().GetImageSize())),
-            Property("fs_type", &ApexFile::GetFsType,
-                     Eq(other.get().GetFsType())),
+                     Eq(other.GetImageSize())),
+            Property("fs_type", &ApexFile::GetFsType, Eq(other.GetFsType())),
             Property("public_key", &ApexFile::GetBundledPublicKey,
-                     Eq(other.get().GetBundledPublicKey())),
+                     Eq(other.GetBundledPublicKey())),
             Property("is_compressed", &ApexFile::IsCompressed,
-                     Eq(other.get().IsCompressed()))),
+                     Eq(other.IsCompressed()))),
       arg, result_listener);
 }
 
diff --git a/apexd/apexd_testdata/Android.bp b/apexd/apexd_testdata/Android.bp
index 18e48be7..f4cf286a 100644
--- a/apexd/apexd_testdata/Android.bp
+++ b/apexd/apexd_testdata/Android.bp
@@ -343,6 +343,16 @@ apex {
     updatable: false,
 }
 
+apex_test {
+    name: "apex.apexd_test_v_long",
+    manifest: "manifest_v_long.json",
+    file_contexts: ":apex.test-file_contexts",
+    prebuilts: ["sample_prebuilt_file"],
+    key: "com.android.apex.test_package.key",
+    installable: false,
+    updatable: false,
+}
+
 apex_key {
     name: "com.android.apex.test_package.no_inst_key.key",
     public_key: "com.android.apex.test_package.no_inst_key.avbpubkey",
@@ -421,30 +431,6 @@ prebuilt_apex {
     installable: false,
 }
 
-// APEX for banned name test cannot be generated at build time.
-// This file can be generated manually by creating new apex target
-// with manifest name 'sharedlibs', and modify aapt2 to skip validating
-// package name from aapt::util::IsAndroidPackageName().
-prebuilt_apex {
-    name: "apex.banned_name",
-    src: "sharedlibs.apex",
-    filename: "sharedlibs.apex",
-    installable: false,
-}
-
-// A compressed apex that also provides shared libs.
-// Should be declined by ApexFile::Open.
-apex {
-    name: "com.android.apex.compressed_sharedlibs",
-    manifest: "manifest_compressed_sharedlibs.json",
-    file_contexts: ":apex.test-file_contexts",
-    prebuilts: ["sample_prebuilt_file"],
-    key: "com.android.apex.compressed.key",
-    installable: false,
-    test_only_force_compression: true,
-    updatable: false,
-}
-
 prebuilt_etc {
     name: "sample_big_prebuilt_file",
     // Generated by:
@@ -500,15 +486,6 @@ apex {
     updatable: false,
 }
 
-apex {
-    name: "test.rebootless_apex_provides_sharedlibs",
-    manifest: "manifest_rebootless_provides_sharedlibs.json",
-    file_contexts: ":apex.test-file_contexts",
-    key: "com.android.apex.test_package.key",
-    installable: false,
-    updatable: false,
-}
-
 apex {
     name: "test.rebootless_apex_provides_native_libs",
     manifest: "manifest_rebootless_provides_native_libs.json",
@@ -518,15 +495,6 @@ apex {
     updatable: false,
 }
 
-apex {
-    name: "test.rebootless_apex_requires_shared_apex_libs",
-    manifest: "manifest_rebootless_requires_shared_apex_libs.json",
-    file_contexts: ":apex.test-file_contexts",
-    key: "com.android.apex.test_package.key",
-    installable: false,
-    updatable: false,
-}
-
 apex {
     name: "test.rebootless_apex_jni_libs",
     manifest: "manifest_rebootless_jni_libs.json",
diff --git a/apexd/apexd_testdata/manifest_compressed_sharedlibs.json b/apexd/apexd_testdata/manifest_compressed_sharedlibs.json
deleted file mode 100644
index 30d2835f..00000000
--- a/apexd/apexd_testdata/manifest_compressed_sharedlibs.json
+++ /dev/null
@@ -1,5 +0,0 @@
-{
-  "name": "com.android.apex.compressed",
-  "version": 1,
-  "provideSharedApexLibs": true
-}
diff --git a/apexd/apexd_testdata/manifest_rebootless_provides_sharedlibs.json b/apexd/apexd_testdata/manifest_rebootless_provides_sharedlibs.json
deleted file mode 100644
index d91c21e4..00000000
--- a/apexd/apexd_testdata/manifest_rebootless_provides_sharedlibs.json
+++ /dev/null
@@ -1,10 +0,0 @@
-{
-  "name": "test.apex.rebootless",
-  "version": 1,
-  "supportsRebootlessUpdate": true,
-  "requireNativeLibs": [
-    "libfoo",
-    "libbar"
-  ],
-  "provideSharedApexLibs": true
-}
diff --git a/apexd/apexd_testdata/manifest_rebootless_requires_shared_apex_libs.json b/apexd/apexd_testdata/manifest_rebootless_requires_shared_apex_libs.json
deleted file mode 100644
index faaadfda..00000000
--- a/apexd/apexd_testdata/manifest_rebootless_requires_shared_apex_libs.json
+++ /dev/null
@@ -1,12 +0,0 @@
-{
-  "name": "test.apex.rebootless",
-  "version": 1,
-  "supportsRebootlessUpdate": true,
-  "requireNativeLibs": [
-    "libfoo",
-    "libbar"
-  ],
-  "requireSharedApexLibs": [
-    "libabc"
-  ]
-}
diff --git a/apexd/apexd_testdata/manifest_v_long.json b/apexd/apexd_testdata/manifest_v_long.json
new file mode 100644
index 00000000..0746a427
--- /dev/null
+++ b/apexd/apexd_testdata/manifest_v_long.json
@@ -0,0 +1,4 @@
+{
+  "name": "com.android.apex.test_package",
+  "version": 8589934592
+}
diff --git a/apexd/apexd_utils.h b/apexd/apexd_utils.h
index 32262774..6aa12745 100644
--- a/apexd/apexd_utils.h
+++ b/apexd/apexd_utils.h
@@ -331,6 +331,22 @@ std::span<const T> Single(const T& t) {
   return std::span{&t, 1};
 }
 
+template <typename Idx, typename Op>
+void ForEachParallel(size_t num_threads, Idx first, Idx last, Op op) {
+  std::atomic<Idx> shared_index{first};
+  std::vector<std::thread> threads;
+  threads.reserve(num_threads);
+  for (size_t i = 0; i < num_threads; i++) {
+    threads.emplace_back([&]() {
+      Idx index;
+      while ((index = shared_index++) < last) {
+        op(index);
+      }
+    });
+  }
+  for (auto& t : threads) t.join();
+}
+
 }  // namespace apex
 }  // namespace android
 
diff --git a/apexd/apexd_verity.cpp b/apexd/apexd_verity.cpp
index d0c4b2d5..fd65588b 100644
--- a/apexd/apexd_verity.cpp
+++ b/apexd/apexd_verity.cpp
@@ -16,21 +16,100 @@
 
 #include "apexd_verity.h"
 
+#include <android-base/file.h>
+#include <android-base/result.h>
+#include <android-base/unique_fd.h>
+#include <verity/hash_tree_builder.h>
+
+#include <filesystem>
 #include <iomanip>
 #include <sstream>
 #include <string>
+#include <vector>
+
+#include "apex_constants.h"
+#include "apex_file.h"
+#include "apexd_utils.h"
+
+using android::base::Dirname;
+using android::base::ErrnoError;
+using android::base::Error;
+using android::base::ReadFully;
+using android::base::Result;
+using android::base::unique_fd;
 
 namespace android {
 namespace apex {
 
-std::string BytesToHex(const uint8_t* bytes, size_t bytes_len) {
-  std::ostringstream s;
+namespace {
+
+uint8_t HexToBin(char h) {
+  if (h >= 'A' && h <= 'H') return h - 'A' + 10;
+  if (h >= 'a' && h <= 'h') return h - 'a' + 10;
+  return h - '0';
+}
+
+std::vector<uint8_t> HexToBin(const std::string& hex) {
+  std::vector<uint8_t> bin;
+  bin.reserve(hex.size() / 2);
+  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
+    uint8_t c = (HexToBin(hex[i]) << 4) + HexToBin(hex[i + 1]);
+    bin.push_back(c);
+  }
+  return bin;
+}
+
+}  // namespace
+
+Result<void> VerifyVerityRootDigest(const ApexFile& apex) {
+  CHECK(apex.GetImageOffset().has_value());
+  CHECK(!apex.IsCompressed());
+
+  unique_fd fd(
+      TEMP_FAILURE_RETRY(open(apex.GetPath().c_str(), O_RDONLY | O_CLOEXEC)));
+  if (fd.get() == -1) {
+    return ErrnoError() << "Failed to open " << apex.GetPath();
+  }
+  auto verity_data =
+      OR_RETURN(apex.VerifyApexVerity(apex.GetBundledPublicKey()));
+
+  auto block_size = verity_data.desc->hash_block_size;
+  auto image_size = verity_data.desc->image_size;
+  auto hash_fn = HashTreeBuilder::HashFunction(verity_data.hash_algorithm);
+  if (hash_fn == nullptr) {
+    return Error() << "Unsupported hash algorithm "
+                   << verity_data.hash_algorithm;
+  }
+  auto builder = std::make_unique<HashTreeBuilder>(block_size, hash_fn);
+  if (!builder->Initialize(image_size, HexToBin(verity_data.salt))) {
+    return Error() << "Invalid image size " << image_size;
+  }
+  if (lseek(fd, apex.GetImageOffset().value(), SEEK_SET) == -1) {
+    return ErrnoError() << "Failed to seek";
+  }
+  auto block_count = image_size / block_size;
+  auto buf = std::vector<uint8_t>(block_size);
+  while (block_count-- > 0) {
+    if (!ReadFully(fd, buf.data(), block_size)) {
+      return Error() << "Failed to read";
+    }
+    if (!builder->Update(buf.data(), block_size)) {
+      return Error() << "Failed to build hashtree: Update";
+    }
+  }
+  if (!builder->BuildHashTree()) {
+    return Error() << "Failed to build hashtree: incomplete data";
+  }
 
-  s << std::hex << std::setfill('0');
-  for (size_t i = 0; i < bytes_len; i++) {
-    s << std::setw(2) << static_cast<int>(bytes[i]);
+  auto golden_digest = HexToBin(verity_data.root_digest);
+  auto digest = builder->root_hash();
+  // This returns zero-padded digest.
+  // resize() it to compare with golden digest,
+  digest.resize(golden_digest.size());
+  if (digest != golden_digest) {
+    return Error() << "root digest mismatch";
   }
-  return s.str();
+  return {};
 }
 
 }  // namespace apex
diff --git a/apexd/apexd_verity.h b/apexd/apexd_verity.h
index aeedf5ec..a160a986 100644
--- a/apexd/apexd_verity.h
+++ b/apexd/apexd_verity.h
@@ -23,7 +23,7 @@
 namespace android {
 namespace apex {
 
-std::string BytesToHex(const uint8_t* bytes, size_t len);
+base::Result<void> VerifyVerityRootDigest(const ApexFile& apex);
 
 }  // namespace apex
 }  // namespace android
diff --git a/apexd/apexservice.cpp b/apexd/apexservice.cpp
index b74796fe..dde54611 100644
--- a/apexd/apexservice.cpp
+++ b/apexd/apexservice.cpp
@@ -270,7 +270,7 @@ BinderStatus ApexService::markBootCompleted() {
     return check;
   }
 
-  ::android::apex::OnBootCompleted();
+  ::android::apex::MarkBootCompleted();
   return BinderStatus::ok();
 }
 
diff --git a/apexd/apexservice_test.cpp b/apexd/apexservice_test.cpp
index 8544044d..33949c8c 100644
--- a/apexd/apexservice_test.cpp
+++ b/apexd/apexservice_test.cpp
@@ -74,6 +74,7 @@ using android::apex::testing::IsOk;
 using android::apex::testing::SessionInfoEq;
 using android::base::EndsWith;
 using android::base::Error;
+using android::base::GetIntProperty;
 using android::base::Join;
 using android::base::Result;
 using android::base::SetProperty;
@@ -1473,6 +1474,9 @@ static const std::vector<std::string> kEarlyProcesses = {
 // This test case is part of the ApexServiceTest suite to ensure that apexd is
 // running when this test is executed.
 TEST_F(ApexServiceTest, EarlyProcessesAreInDifferentMountNamespace) {
+  if (GetIntProperty("ro.init.mnt_ns.count", 2) == 1) {
+    GTEST_SKIP() << "A device is using a single mount namespace";
+  }
   std::string ns_apexd;
 
   ExecInMountNamespaceOf(GetPidOf("apexd"), [&](pid_t /*pid*/) {
@@ -1516,6 +1520,9 @@ static const std::vector<std::string> kEarlyApexes = {
 };
 
 TEST(ApexdTest, ApexesAreActivatedForEarlyProcesses) {
+  if (GetIntProperty("ro.init.mnt_ns.count", 2) == 1) {
+    GTEST_SKIP() << "A device is using a single mount namespace";
+  }
   for (const auto& name : kEarlyProcesses) {
     pid_t pid = GetPidOf(name);
     const std::string path =
diff --git a/apexer/apexer.py b/apexer/apexer.py
index 184cbb7d..8b20ad72 100644
--- a/apexer/apexer.py
+++ b/apexer/apexer.py
@@ -235,7 +235,7 @@ def GetDirSize(dir_name):
 
 def GetFilesAndDirsCount(dir_name):
   count = 0
-  for root, dirs, files in os.walk(dir_name):
+  for _, dirs, files in os.walk(dir_name):
     count += (len(dirs) + len(files))
   return count
 
@@ -245,18 +245,35 @@ def RoundUp(size, unit):
   return (size + unit - 1) & (~(unit - 1))
 
 
+def FormatVersionCode(version):
+  version_str = str(version)
+  version_major_str = ''
+  if version >= 2**31:
+    version_str = hex(version & 0xFFFFFFFF)
+    version_major = version >> 32
+    if version_major > 0:
+      version_major_str = hex(version_major)
+  return version_str, version_major_str
+
+
 def PrepareAndroidManifest(package, version, test_only):
   template = """\
 <?xml version="1.0" encoding="utf-8"?>
 <manifest xmlns:android="http://schemas.android.com/apk/res/android"
-  package="{package}" android:versionCode="{version}">
+  package="{package}" android:versionCode="{version}"{version_major_attr}>
   <!-- APEX does not have classes.dex -->
   <application android:hasCode="false" {test_only_attribute}/>
 </manifest>
 """
+  version_str, version_major_str = FormatVersionCode(version)
+  version_major_attr = ''
+  if version_major_str != '':
+    version_major_attr = f' android:versionMajor="{version_major_str}"'
 
   test_only_attribute = 'android:testOnly="true"' if test_only else ''
-  return template.format(package=package, version=version,
+  return template.format(package=package,
+                         version=version_str,
+                         version_major_attr=version_major_attr,
                          test_only_attribute=test_only_attribute)
 
 
@@ -288,9 +305,9 @@ def ValidateArgs(args):
     if not os.path.exists(args.build_info):
       print("Build info file '" + args.build_info + "' does not exist")
       return False
-    with open(args.build_info, 'rb') as buildInfoFile:
+    with open(args.build_info, 'rb') as build_info_file:
       build_info = apex_build_info_pb2.ApexBuildInfo()
-      build_info.ParseFromString(buildInfoFile.read())
+      build_info.ParseFromString(build_info_file.read())
 
   if not os.path.exists(args.manifest):
     print("Manifest file '" + args.manifest + "' does not exist")
@@ -328,8 +345,8 @@ def ValidateArgs(args):
     return False
 
   if args.unsigned_payload_only:
-    args.payload_only = True;
-    args.unsigned_payload = True;
+    args.payload_only = True
+    args.unsigned_payload = True
 
   if not args.key and not args.unsigned_payload:
     print('Missing --key {keyfile} argument!')
@@ -389,7 +406,7 @@ def ValidateArgs(args):
 
 def GenerateBuildInfo(args):
   build_info = apex_build_info_pb2.ApexBuildInfo()
-  if (args.include_cmd_line_in_build_info):
+  if args.include_cmd_line_in_build_info:
     build_info.apexer_command_line = str(sys.argv)
 
   with open(args.file_contexts, 'rb') as f:
@@ -684,8 +701,8 @@ def SignImage(args, manifest_apex, img_file):
   # TODO(b/113320014) eliminate this step
   info, _ = RunCommand(['avbtool', 'info_image', '--image', img_file],
                        args.verbose)
-  vbmeta_offset = int(re.search('VBMeta\ offset:\ *([0-9]+)', info).group(1))
-  vbmeta_size = int(re.search('VBMeta\ size:\ *([0-9]+)', info).group(1))
+  vbmeta_offset = int(re.search('VBMeta offset: *([0-9]+)', info).group(1))
+  vbmeta_size = int(re.search('VBMeta size: *([0-9]+)', info).group(1))
   partition_size = RoundUp(vbmeta_offset + vbmeta_size,
                            BLOCK_SIZE) + BLOCK_SIZE
 
@@ -825,9 +842,14 @@ def CreateApex(args, work_dir):
   cmd.extend(['--manifest', android_manifest_file])
   if args.override_apk_package_name:
     cmd.extend(['--rename-manifest-package', args.override_apk_package_name])
+
   # This version from apex_manifest.json is used when versionCode isn't
   # specified in AndroidManifest.xml
-  cmd.extend(['--version-code', str(manifest_apex.version)])
+  version_str, version_major_str = FormatVersionCode(manifest_apex.version)
+  cmd.extend(['--version-code', version_str])
+  if version_major_str != '':
+    cmd.extend(['--version-code-major', version_major_str])
+
   if manifest_apex.versionName:
     cmd.extend(['--version-name', manifest_apex.versionName])
   if args.target_sdk_version:
@@ -857,8 +879,8 @@ def CreateApexManifest(manifest_path):
     manifest_apex = ParseApexManifest(manifest_path)
     ValidateApexManifest(manifest_apex)
     return manifest_apex
-  except IOError:
-    raise ApexManifestError("Cannot read manifest file: '" + manifest_path + "'")
+  except IOError as exc:
+    raise ApexManifestError("Cannot read manifest file: '" + manifest_path + "'") from exc
 
 class TempDirectory(object):
 
diff --git a/libs/libapexsupport/include/android/apexsupport.h b/libs/libapexsupport/include/android/apexsupport.h
index 9c11b3ae..71a04539 100644
--- a/libs/libapexsupport/include/android/apexsupport.h
+++ b/libs/libapexsupport/include/android/apexsupport.h
@@ -42,6 +42,8 @@ typedef enum AApexInfoError : int32_t {
    * See the log for details.
    */
   AAPEXINFO_INVALID_APEX,
+  /* The APEX name is invalid. */
+  AAPEXINFO_INVALID_APEX_NAME,
 } AApexInfoError;
 
 // Defining #llndk symbols
@@ -62,6 +64,20 @@ typedef enum AApexInfoError : int32_t {
 __attribute__((warn_unused_result)) AApexInfoError AApexInfo_create(
     AApexInfo *_Nullable *_Nonnull info) __INTRODUCED_IN(__ANDROID_API_V__);
 
+/**
+ * Creates an AApexInfo object from the APEX name. The allocated AApexInfo
+ * object has to be deallocated using AApexInfo_destroy().
+ *
+ * \param name the APEX name (encoding: utf8)
+ * \param info out parameter for an AApexInfo object for the APEX. Null
+ *    when failed to read the APEX manifest.
+ *
+ * \return AApexInfoError
+ */
+__attribute__((warn_unused_result)) AApexInfoError AApexInfo_createWithName(
+    const char *_Nonnull name, AApexInfo *_Nullable *_Nonnull info)
+    __INTRODUCED_IN(37);
+
 /**
  * Destroys an AApexInfo object created by AApexInfo_create().
  *
diff --git a/libs/libapexsupport/libapexsupport.map.txt b/libs/libapexsupport/libapexsupport.map.txt
index 24dd082e..b180a521 100644
--- a/libs/libapexsupport/libapexsupport.map.txt
+++ b/libs/libapexsupport/libapexsupport.map.txt
@@ -20,6 +20,7 @@ LIBAPEXSUPPORT {
     AApexInfo_destroy; # llndk
     AApexInfo_getName; # llndk
     AApexInfo_getVersion; # llndk
+    AApexInfo_createWithName; # llndk introduced=37
   local:
     *;
 };
diff --git a/libs/libapexsupport/src/apexinfo.rs b/libs/libapexsupport/src/apexinfo.rs
index 95a30a65..cc900edb 100644
--- a/libs/libapexsupport/src/apexinfo.rs
+++ b/libs/libapexsupport/src/apexinfo.rs
@@ -56,9 +56,19 @@ impl AApexInfo {
             version: manifest.version,
         })
     }
+
+    pub fn create_with_name(name: &str) -> Result<Self, AApexInfoError> {
+        let manifest_path = Path::new("/apex").join(name).join("apex_manifest.pb");
+        let manifest = parse_apex_manifest(manifest_path)?;
+        Ok(AApexInfo {
+            name: CString::new(manifest.name)
+                .map_err(|err| AApexInfoError::InvalidApex(format!("{err:?}")))?,
+            version: manifest.version,
+        })
+    }
 }
 
-/// Returns the apex_manifest.pb path when a given path belongs to an apex.
+/// Returns the APEX name when a given path belongs to an apex.
 fn get_apex_manifest_path<P: AsRef<Path>>(path: P) -> Result<PathBuf, AApexInfoError> {
     let remain = path
         .as_ref()
@@ -74,7 +84,8 @@ fn get_apex_manifest_path<P: AsRef<Path>>(path: P) -> Result<PathBuf, AApexInfoE
 /// Parses the apex_manifest.pb protobuf message from a given path.
 fn parse_apex_manifest<P: AsRef<Path>>(path: P) -> Result<ApexManifest, AApexInfoError> {
     let mut f = File::open(path).map_err(|err| AApexInfoError::InvalidApex(format!("{err:?}")))?;
-    Message::parse_from_reader(&mut f).map_err(|err| AApexInfoError::InvalidApex(format!("{err:?}")))
+    Message::parse_from_reader(&mut f)
+        .map_err(|err| AApexInfoError::InvalidApex(format!("{err:?}")))
 }
 
 #[cfg(test)]
diff --git a/libs/libapexsupport/src/lib.rs b/libs/libapexsupport/src/lib.rs
index f1ee61eb..f2029c84 100644
--- a/libs/libapexsupport/src/lib.rs
+++ b/libs/libapexsupport/src/lib.rs
@@ -19,19 +19,20 @@
 mod apexinfo;
 
 use apexinfo::{AApexInfo, AApexInfoError};
-use std::ffi::c_char;
+use std::ffi::{c_char, CStr};
 
 /// NOTE: Keep these constants in sync with apexsupport.h
 const AAPEXINFO_OK: i32 = 0;
 const AAPEXINFO_NO_APEX: i32 = 1;
 const AAPEXINFO_ERROR_GET_EXECUTABLE_PATH: i32 = 2;
-const AAPEXINFO_INALID_APEX: i32 = 3;
+const AAPEXINFO_INVALID_APEX: i32 = 3;
+const AAPEXINFO_INVALID_APEX_NAME: i32 = 4;
 
 fn as_error_code(err: &AApexInfoError) -> i32 {
     match err {
         AApexInfoError::PathNotFromApex(_) => AAPEXINFO_NO_APEX,
         AApexInfoError::ExePathUnavailable(_) => AAPEXINFO_ERROR_GET_EXECUTABLE_PATH,
-        AApexInfoError::InvalidApex(_) => AAPEXINFO_INALID_APEX,
+        AApexInfoError::InvalidApex(_) => AAPEXINFO_INVALID_APEX,
     }
 }
 
@@ -58,6 +59,37 @@ pub unsafe extern "C" fn AApexInfo_create(out: *mut *mut AApexInfo) -> i32 {
     }
 }
 
+#[no_mangle]
+/// Creates AApexInfo object with the given APEX name
+///
+/// # Safety
+///
+/// The provided pointer must be valid and have no aliases for the duration of the call.
+pub unsafe extern "C" fn AApexInfo_createWithName(
+    name: *const c_char,
+    out: *mut *mut AApexInfo,
+) -> i32 {
+    // SAFETY: The pointer is not null, so the caller guarantees that it is valid.
+    let name = unsafe { CStr::from_ptr(name) }.to_str();
+    if name.is_err() {
+        return AAPEXINFO_INVALID_APEX_NAME;
+    }
+    match AApexInfo::create_with_name(name.unwrap()) {
+        Ok(info) => {
+            let ptr = Box::into_raw(Box::new(info));
+            // SAFETY: We have checked that `out` is not null, so the caller guarantees that it is
+            // valid and unaliased.
+            unsafe { *out = ptr };
+            AAPEXINFO_OK
+        }
+        Err(err) => {
+            // TODO(b/271488212): Use Rust logger.
+            eprintln!("AApexInfo_createWithName(): {err:?}");
+            as_error_code(&err)
+        }
+    }
+}
+
 #[no_mangle]
 /// Destroys AApexInfo object created by AApexInfo_create().
 ///
diff --git a/libs/libapexsupport/tests/libapexsupport-tests.cpp b/libs/libapexsupport/tests/libapexsupport-tests.cpp
index e412598a..23c012c0 100644
--- a/libs/libapexsupport/tests/libapexsupport-tests.cpp
+++ b/libs/libapexsupport/tests/libapexsupport-tests.cpp
@@ -14,11 +14,10 @@
  * limitations under the License.
  */
 
+#include <android/apexsupport.h>
 #include <dlfcn.h>
 #include <gtest/gtest.h>
 
-#include <android/apexsupport.h>
-
 #ifdef __ANDROID_APEX__
 
 TEST(LibApexSupportTest, AApexInfo) {
@@ -34,14 +33,39 @@ TEST(LibApexSupportTest, AApexInfo) {
   AApexInfo_destroy(info);
 }
 
-#else // __ANDROID_APEX__
+TEST(LibApexSupportTest, AApexInfo_createWithName) {
+  if (__builtin_available(android 37, *)) {
+    AApexInfo *info;
+    EXPECT_EQ(
+        AApexInfo_createWithName("com.android.libapexsupport.tests", &info),
+        AAPEXINFO_OK);
+    ASSERT_NE(info, nullptr);
+
+    // Version should match with the values in manifest.json
+    EXPECT_EQ(42, AApexInfo_getVersion(info));
+
+    AApexInfo_destroy(info);
+  }
+}
+
+TEST(LibApexSupportTest, AApexInfo_createWithName_Failure) {
+  if (__builtin_available(android 37, *)) {
+    AApexInfo *info;
+    EXPECT_EQ(AApexInfo_createWithName(
+                  "com.android.libapexsupport.tests.non_existent", &info),
+              AAPEXINFO_INVALID_APEX);
+    ASSERT_EQ(info, nullptr);
+  }
+}
+
+#else  // __ANDROID_APEX__
 
 TEST(LibApexSupportTest, AApexInfo) {
   AApexInfo *info;
   EXPECT_EQ(AApexInfo_create(&info), AAPEXINFO_NO_APEX);
 }
 
-#endif // __ANDROID_APEX__
+#endif  // __ANDROID_APEX__
 
 int main(int argc, char **argv) {
   ::testing::InitGoogleTest(&argc, argv);
diff --git a/patchlevel/Android.bp b/patchlevel/Android.bp
new file mode 100644
index 00000000..99d43233
--- /dev/null
+++ b/patchlevel/Android.bp
@@ -0,0 +1,21 @@
+//
+// Copyright (C) 2025 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+prebuilt_etc {
+    name: "apexd.mainline_patch_level_2",
+    src: "com.google.android.mainline.patchlevel.2.xml",
+    filename_from_src: true,
+}
diff --git a/tests/shared-libs-apex-tests.xml b/patchlevel/com.google.android.mainline.patchlevel.2.xml
similarity index 55%
rename from tests/shared-libs-apex-tests.xml
rename to patchlevel/com.google.android.mainline.patchlevel.2.xml
index d41b8916..1bb3b2cc 100644
--- a/tests/shared-libs-apex-tests.xml
+++ b/patchlevel/com.google.android.mainline.patchlevel.2.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2020 The Android Open Source Project
+<!-- Copyright (C) 2025 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,11 +13,11 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<configuration description="Runs the shared libs apex host side test cases">
-    <option name="test-suite-tag" value="sharedlibs_host_tests" />
-    <option name="test-suite-tag" value="apct" />
-    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
-    <test class="com.android.tradefed.testtype.HostTest" >
-        <option name="jar" value="sharedlibs_host_tests.jar" />
-    </test>
-</configuration>
+
+<config>
+    <!-- Mainline platform patch level 2
+         Android 16 and above. 1 patches
+         1) https://docs.partner.android.com/partners/announcements/general/general2025#gpsu-jul-25
+    -->
+    <feature name="com.google.android.mainline.patchlevel.2" />
+</config>
\ No newline at end of file
diff --git a/proto/Android.bp b/proto/Android.bp
index 74b59767..160a334b 100644
--- a/proto/Android.bp
+++ b/proto/Android.bp
@@ -109,6 +109,15 @@ cc_library_static {
     srcs: ["apex_blocklist.proto"],
 }
 
+cc_library_static {
+    name: "lib_apex_image_list_proto",
+    host_supported: true,
+    proto: {
+        export_proto_headers: true,
+    },
+    srcs: ["apex_image_list.proto"],
+}
+
 genrule {
     name: "apex-protos",
     tools: ["soong_zip"],
diff --git a/tests/testdata/sharedlibs/build/sharedlibstest.cpp b/proto/apex_image_list.proto
similarity index 54%
rename from tests/testdata/sharedlibs/build/sharedlibstest.cpp
rename to proto/apex_image_list.proto
index bac580ef..28e0a752 100644
--- a/tests/testdata/sharedlibs/build/sharedlibstest.cpp
+++ b/proto/apex_image_list.proto
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2020 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,17 +14,22 @@
  * limitations under the License.
  */
 
-#include "sharedlibstest.h"
+syntax = "proto3";
 
-#include <string>
+package apex.proto;
 
-namespace sharedlibstest {
+option java_package = "com.android.apex";
+option java_outer_classname = "Protos";
 
-// This parameter gets modified by the build_artifacts.sh script.
-#define FINGERPRINT "VERSION_XXX"
+message ApexImageList {
+  message Entry {
+    // The name of apex image, managed by ApexImageManager. Not same as the apex name.
+    string image_name = 1;
 
-std::string getSharedLibsTestFingerprint() {
-  return std::string("SHARED_LIB_") + FINGERPRINT;
-}
+    // the name of apex, declared in apex_manifest.
+    string apex_name = 2;
+  }
 
-} // namespace sharedlibstest
+  // the list of apex images
+  repeated Entry entries = 1;
+}
diff --git a/proto/apex_manifest.proto b/proto/apex_manifest.proto
index 09bbf38d..9e5d5b53 100644
--- a/proto/apex_manifest.proto
+++ b/proto/apex_manifest.proto
@@ -58,18 +58,20 @@ message ApexManifest {
   // marked as "is_jni: true" from the list of "native_shared_libs".
   repeated string jniLibs = 9;
 
+  // Deprecated.
   // List of libs required that are located in a shared libraries APEX.  The
   // Android platform only checks whether this list is non-empty, and by default
   // the Android build system never sets this. This field can be used when
   // producing or processing an APEX using libraries in /apex/sharedlibs (see
   // `provideSharedApexLibs` field) to store some information about the
   // libraries.
-  repeated string requireSharedApexLibs = 10;
+  repeated string requireSharedApexLibs = 10 [ deprecated = true ];
 
+  // Deprecated.
   // Whether this APEX provides libraries to be shared with other APEXs. This
   // causes libraries contained in the APEX to be made available under
   // /apex/sharedlibs .
-  bool provideSharedApexLibs = 11;
+  bool provideSharedApexLibs = 11 [ deprecated = true ];
 
   message CompressedApexMetadata {
 
diff --git a/tests/Android.bp b/tests/Android.bp
index 25da3e01..fd645c24 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -240,38 +240,6 @@ android_test_helper_app {
     ],
 }
 
-java_test_host {
-    name: "sharedlibs_host_tests",
-    srcs: [
-        "src/**/SharedLibsApexTest.java",
-    ],
-    libs: ["tradefed"],
-    device_common_java_resources: [
-        ":com.android.apex.test.bar_stripped.v1.libvX_prebuilt",
-        ":com.android.apex.test.bar_stripped.v2.libvY_prebuilt",
-        ":com.android.apex.test.bar.v1.libvX_prebuilt",
-        ":com.android.apex.test.bar.v2.libvY_prebuilt",
-        ":com.android.apex.test.baz_stripped.v1.libvX_prebuilt",
-        ":com.android.apex.test.foo_stripped.v1.libvX_prebuilt",
-        ":com.android.apex.test.foo_stripped.v2.libvY_prebuilt",
-        ":com.android.apex.test.foo.v1.libvX_prebuilt",
-        ":com.android.apex.test.foo.v2.libvY_prebuilt",
-        ":com.android.apex.test.pony_stripped.v1.libvZ_prebuilt",
-        ":com.android.apex.test.pony.v1.libvZ_prebuilt",
-        ":com.android.apex.test.sharedlibs_generated.v1.libvX_prebuilt",
-        ":com.android.apex.test.sharedlibs_generated.v2.libvY_prebuilt",
-        ":com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ_prebuilt",
-    ],
-    static_libs: [
-        "compatibility-host-util",
-        "cts-install-lib-host",
-        "frameworks-base-hostutils",
-        "truth",
-    ],
-    test_config: "shared-libs-apex-tests.xml",
-    test_suites: ["general-tests"],
-}
-
 java_test_host {
     name: "apex_compression_platform_tests",
     srcs: ["src/**/ApexCompressionTests.java"],
diff --git a/tests/TEST_MAPPING b/tests/TEST_MAPPING
index 759190f0..b698721d 100644
--- a/tests/TEST_MAPPING
+++ b/tests/TEST_MAPPING
@@ -8,9 +8,6 @@
     },
     {
       "name": "apex_apkinapex_tests"
-    },
-    {
-      "name": "CtsApexSharedLibrariesTestCases"
     }
   ],
   "presubmit-large": [
@@ -20,9 +17,6 @@
     //},
     {
       "name": "sdkextensions_e2e_tests"
-    },
-    {
-      "name": "sharedlibs_host_tests"
     }
   ],
   "postsubmit": [
diff --git a/tests/native/Android.bp b/tests/native/Android.bp
deleted file mode 100644
index 59d470d7..00000000
--- a/tests/native/Android.bp
+++ /dev/null
@@ -1,56 +0,0 @@
-// Copyright (C) 2021 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-    default_team: "trendy_team_treble",
-}
-
-cc_test {
-    name: "CtsApexSharedLibrariesTestCases",
-    test_suites: [
-        "cts",
-        "device-tests",
-        "mts",
-    ],
-    compile_multilib: "both",
-    multilib: {
-        lib32: {
-            suffix: "32",
-        },
-        lib64: {
-            suffix: "64",
-        },
-    },
-
-    shared_libs: [
-        "liblog",
-        "libdl_android",
-    ],
-
-    static_libs: [
-        "libbase",
-        "libfs_mgr",
-    ],
-
-    srcs: [
-        "apex_shared_libraries_test.cpp",
-    ],
-
-    cflags: [
-        "-Wall",
-        "-Wextra",
-        "-Werror",
-    ],
-}
diff --git a/tests/native/AndroidTest.xml b/tests/native/AndroidTest.xml
deleted file mode 100644
index be00cdad..00000000
--- a/tests/native/AndroidTest.xml
+++ /dev/null
@@ -1,32 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2021 The Android Open Source Project
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-          http://www.apache.org/licenses/LICENSE-2.0
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-<configuration description="Config for CTS apex_shared_libraries test cases">
-    <option name="test-suite-tag" value="cts" />
-    <option name="config-descriptor:metadata" key="component" value="systems" />
-    <option name="config-descriptor:metadata" key="parameter" value="not_instant_app" />
-    <option name="config-descriptor:metadata" key="parameter" value="multi_abi" />
-    <option name="config-descriptor:metadata" key="parameter" value="secondary_user" />
-    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.FilePusher">
-        <option name="cleanup" value="true" />
-        <option name="push" value="CtsApexSharedLibrariesTestCases->/data/local/tmp/CtsApexSharedLibrariesTestCases" />
-        <option name="append-bitness" value="true" />
-    </target_preparer>
-    <test class="com.android.tradefed.testtype.GTest" >
-        <option name="native-test-device-path" value="/data/local/tmp" />
-        <option name="module-name" value="CtsApexSharedLibrariesTestCases" />
-        <option name="runtime-hint" value="65s" />
-    </test>
-    <!-- Controller that will skip the module if a native bridge situation is detected -->
-    <!-- For example: module wants to run arm32 and device is x86 -->
-    <object type="module_controller" class="com.android.tradefed.testtype.suite.module.NativeBridgeModuleController" />
-</configuration>
diff --git a/tests/native/apex_shared_libraries_test.cpp b/tests/native/apex_shared_libraries_test.cpp
deleted file mode 100644
index 1c67aab6..00000000
--- a/tests/native/apex_shared_libraries_test.cpp
+++ /dev/null
@@ -1,219 +0,0 @@
-/*
- * Copyright (C) 2021 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-#define LOG_TAG "apex_shared_libraries_test"
-
-#include <android-base/logging.h>
-#include <android-base/properties.h>
-#include <android-base/scopeguard.h>
-#include <android-base/strings.h>
-#include <android/dlext.h>
-#include <dlfcn.h>
-#include <fstab/fstab.h>
-#include <gtest/gtest.h>
-#include <link.h>
-
-#include <filesystem>
-#include <fstream>
-#include <regex>
-#include <sstream>
-#include <string>
-
-using android::base::GetBoolProperty;
-using android::base::Split;
-using android::base::StartsWith;
-using android::fs_mgr::Fstab;
-using android::fs_mgr::ReadFstabFromFile;
-
-namespace fs = std::filesystem;
-
-// No header available for these symbols
-extern "C" struct android_namespace_t* android_get_exported_namespace(
-    const char* name);
-
-extern "C" struct android_namespace_t* android_create_namespace(
-    const char* name, const char* ld_library_path,
-    const char* default_library_path, uint64_t type,
-    const char* permitted_when_isolated_path,
-    struct android_namespace_t* parent);
-
-#if !defined(__LP64__)
-static constexpr const char LIB[] = "lib";
-#else   // !__LP64__
-static constexpr const char LIB[] = "lib64";
-#endif  // !__LP64_
-
-static constexpr const char kApexSharedLibsRoot[] = "/apex/sharedlibs";
-
-// Before running the test, make sure that certain libraries are not pre-loaded
-// in the test process.
-void check_preloaded_libraries() {
-  static constexpr const char* unwanted[] = {
-      "libbase.so",
-      "libcrypto.so",
-  };
-
-  std::ifstream f("/proc/self/maps");
-  std::string line;
-  while (std::getline(f, line)) {
-    for (const char* lib : unwanted) {
-      EXPECT_TRUE(line.find(lib) == std::string::npos)
-          << "Library " << lib << " seems preloaded in the test process. "
-          << "This is a potential error. Please remove direct or transitive "
-          << "dependency to this library. You may debug this by running this "
-          << "test with `export LD_DEBUG=1` and "
-          << "`setprop debug.ld.all dlopen,dlerror`.";
-    }
-  }
-}
-
-TEST(apex_shared_libraries, symlink_libraries_loadable) {
-  check_preloaded_libraries();
-
-  Fstab fstab;
-  ASSERT_TRUE(ReadFstabFromFile("/proc/mounts", &fstab));
-
-  // Regex to use when checking if a mount is for an active APEX or not. Note
-  // that non-active APEX mounts don't have the @<number> marker.
-  std::regex active_apex_pattern(R"(/apex/(.*)@\d+)");
-
-  // Traverse mount points to identify apexs.
-  for (auto& entry : fstab) {
-    std::cmatch m;
-    if (!std::regex_match(entry.mount_point.c_str(), m, active_apex_pattern)) {
-      continue;
-    }
-    // Linker namespace name of the apex com.android.foo is com_android_foo.
-    std::string apex_namespace_name = m[1];
-    std::replace(apex_namespace_name.begin(), apex_namespace_name.end(), '.',
-                 '_');
-
-    // Filter out any mount irrelevant (e.g. tmpfs)
-    std::string dev_file = fs::path(entry.blk_device).filename();
-    if (!StartsWith(dev_file, "loop") && !StartsWith(dev_file, "dm-")) {
-      continue;
-    }
-
-    auto lib = fs::path(entry.mount_point) / LIB;
-    if (!fs::is_directory(lib)) {
-      continue;
-    }
-
-    for (auto& p : fs::directory_iterator(lib)) {
-      std::error_code ec;
-      if (!fs::is_symlink(p, ec)) {
-        continue;
-      }
-
-      // We are only checking libraries pointing at a location inside
-      // /apex/sharedlibs.
-      auto target = fs::read_symlink(p.path(), ec);
-      if (ec || !StartsWith(target.string(), kApexSharedLibsRoot)) {
-        continue;
-      }
-
-      LOG(INFO) << "Checking " << p.path();
-
-      // Symlink validity check.
-      auto dest = fs::canonical(p.path(), ec);
-      EXPECT_FALSE(ec) << "Failed to resolve " << p.path() << " (symlink to "
-                       << target << "): " << ec;
-      if (ec) {
-        continue;
-      }
-
-      // Library loading validity check.
-      dlerror();  // Clear any pending errors.
-      android_namespace_t* ns =
-          android_get_exported_namespace(apex_namespace_name.c_str());
-      if (ns == nullptr) {
-        LOG(INFO) << "Creating linker namespace " << apex_namespace_name;
-        // In case the apex namespace doesn't exist (actually not accessible),
-        // create a new one that can search libraries from the apex directory
-        // and can load (but not search) from the shared lib APEX.
-        std::string search_paths = lib;
-        search_paths.push_back(':');
-        // Adding "/system/lib[64]" is not ideal; we need to link to the
-        // namespace that is capable of loading libs from the directory.
-        // However, since the namespace (the `system` namespace) is not
-        // exported, we can't make a link. Instead, we allow this new namespace
-        // to search/load libraries from the directory.
-        search_paths.append(std::string("/system/") + LIB);
-        std::string permitted_paths = "/apex";
-        ns = android_create_namespace(
-            apex_namespace_name.c_str(),
-            /* ld_library_path=*/nullptr,
-            /* default_library_path=*/search_paths.c_str(),
-            /* type=*/3,  // ISOLATED and SHARED
-            /* permitted_when_isolated_path=*/permitted_paths.c_str(),
-            /* parent=*/nullptr);
-      }
-
-      EXPECT_TRUE(ns != nullptr)
-          << "Cannot find or create namespace " << apex_namespace_name;
-      const android_dlextinfo dlextinfo = {
-          .flags = ANDROID_DLEXT_USE_NAMESPACE,
-          .library_namespace = ns,
-      };
-
-      void* handle = android_dlopen_ext(p.path().c_str(), RTLD_NOW, &dlextinfo);
-      EXPECT_TRUE(handle != nullptr)
-          << "Failed to load " << p.path() << " which is a symlink to "
-          << target << ".\n"
-          << "Reason: " << dlerror() << "\n"
-          << "Make sure that the library is accessible.";
-      if (handle == nullptr) {
-        continue;
-      }
-      auto guard = android::base::make_scope_guard([&]() { dlclose(handle); });
-
-      // Check that library is loaded and pointing to the realpath of the
-      // library.
-      auto dl_callback = [](dl_phdr_info* info, size_t /* size */, void* data) {
-        auto dest = *static_cast<fs::path*>(data);
-        if (info->dlpi_name == nullptr) {
-          // This is linker imposing as libdl.so - skip it
-          return 0;
-        }
-        int j;
-        for (j = 0; j < info->dlpi_phnum; j++) {
-          void* addr = (void*)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
-          Dl_info dl_info;
-          int rc = dladdr(addr, &dl_info);
-          if (rc == 0) {
-            continue;
-          }
-          if (dl_info.dli_fname) {
-            auto libpath = fs::path(dl_info.dli_fname);
-            if (libpath == dest) {
-              // Library found!
-              return 1;
-            }
-          }
-        }
-
-        return 0;
-      };
-      bool found = (dl_iterate_phdr(dl_callback, &dest) == 1);
-      EXPECT_TRUE(found) << "Error verifying library symlink " << p.path()
-                         << " which points to " << target
-                         << " which resolves to file " << dest;
-      if (found) {
-        LOG(INFO) << "Verified that " << p.path()
-                  << " correctly loads as library " << dest;
-      }
-    }
-  }
-}
diff --git a/tests/src/com/android/tests/apex/ApexdHostTest.java b/tests/src/com/android/tests/apex/ApexdHostTest.java
index 264ebbac..9f4a18d9 100644
--- a/tests/src/com/android/tests/apex/ApexdHostTest.java
+++ b/tests/src/com/android/tests/apex/ApexdHostTest.java
@@ -95,7 +95,7 @@ public class ApexdHostTest extends BaseHostJUnit4Test  {
                     "com.android.apex.test_package", 2L);
             assertThat(activeApexes).doesNotContain(testApex);
             mHostUtils.waitForFileDeleted("/data/apex/active/apexd_test_v2.apex",
-                    Duration.ofMinutes(3));
+                    Duration.ofMinutes(1));
         } finally {
             getDevice().executeShellV2Command("rm /data/apex/active/apexd_test_v2.apex");
         }
@@ -278,10 +278,8 @@ public class ApexdHostTest extends BaseHostJUnit4Test  {
             ITestDevice.ApexInfo testApex = new ITestDevice.ApexInfo(
                     "com.android.apex.cts.shim", 1L);
             assertThat(activeApexes).contains(testApex);
-            assertThat(
-                    getDevice()
-                            .doesFileExist("/data/apex/active/com.android.apex.cts.shim@2.apex"))
-                    .isFalse();
+            mHostUtils.waitForFileDeleted("/data/apex/active/com.android.apex.cts.shim@2.apex",
+                    Duration.ofMinutes(3));
         } finally {
             getDevice().deleteFile("/data/apex/active/com.android.apex.cts.shim@2.apex");
         }
diff --git a/tests/src/com/android/tests/apex/SharedLibsApexTest.java b/tests/src/com/android/tests/apex/SharedLibsApexTest.java
deleted file mode 100644
index 797a71b1..00000000
--- a/tests/src/com/android/tests/apex/SharedLibsApexTest.java
+++ /dev/null
@@ -1,554 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-package com.android.tests.apex;
-
-import static com.google.common.truth.Truth.assertThat;
-
-import static org.junit.Assume.assumeTrue;
-
-import android.cts.install.lib.host.InstallUtilsHost;
-
-import com.android.compatibility.common.util.CpuFeatures;
-import com.android.internal.util.test.SystemPreparer;
-import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
-import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
-
-import org.junit.Rule;
-import org.junit.Test;
-import org.junit.rules.RuleChain;
-import org.junit.rules.TemporaryFolder;
-import org.junit.runner.RunWith;
-
-import java.time.Duration;
-
-@RunWith(DeviceJUnit4ClassRunner.class)
-public class SharedLibsApexTest extends BaseHostJUnit4Test {
-
-    private final InstallUtilsHost mHostUtils = new InstallUtilsHost(this);
-    private final TemporaryFolder mTemporaryFolder = new TemporaryFolder();
-    private final SystemPreparer mPreparer = new SystemPreparer(mTemporaryFolder,
-            this::getDevice);
-
-    @Rule
-    public final RuleChain ruleChain = RuleChain.outerRule(mTemporaryFolder).around(mPreparer);
-
-    enum ApexName {
-        FOO,
-        BAR,
-        BAZ,
-        PONY,
-        SHAREDLIBS,
-        SHAREDLIBS_SECONDARY
-    }
-
-    enum ApexVersion {
-        ONE,
-        TWO
-    }
-
-    enum ApexType {
-        DEFAULT,
-        STRIPPED
-    }
-
-    enum SharedLibsVersion {
-        X,
-        Y,
-        Z
-    }
-
-    /**
-     * Utility function to generate test apex names in the form e.g.:
-     *   "com.android.apex.test.bar.v1.libvX.apex"
-     */
-    private String getTestApex(ApexName apexName, ApexType apexType, ApexVersion apexVersion,
-            SharedLibsVersion sharedLibsVersion) {
-        StringBuilder ret = new StringBuilder();
-        ret.append("com.android.apex.test.");
-        switch(apexName) {
-            case FOO:
-                ret.append("foo");
-                break;
-            case BAR:
-                ret.append("bar");
-                break;
-            case BAZ:
-                ret.append("baz");
-                break;
-            case PONY:
-                ret.append("pony");
-                break;
-            case SHAREDLIBS:
-                ret.append("sharedlibs_generated");
-                break;
-            case SHAREDLIBS_SECONDARY:
-                ret.append("sharedlibs_secondary_generated");
-                break;
-        }
-
-        switch(apexType) {
-            case STRIPPED:
-                ret.append("_stripped");
-                break;
-            case DEFAULT:
-                break;
-        }
-
-        switch(apexVersion) {
-            case ONE:
-                ret.append(".v1");
-                break;
-            case TWO:
-                ret.append(".v2");
-                break;
-        }
-
-        switch(sharedLibsVersion) {
-            case X:
-                ret.append(".libvX.apex");
-                break;
-            case Y:
-                ret.append(".libvY.apex");
-                break;
-            case Z:
-                ret.append(".libvZ.apex");
-                break;
-        }
-
-        return ret.toString();
-    }
-
-    /**
-     * Utility function to generate the file name of an installed package as per
-     * apexd convention e.g.: "com.android.apex.test.bar@1.apex"
-     */
-    private String getInstalledApexFileName(ApexName apexName, ApexVersion apexVersion) {
-        StringBuilder ret = new StringBuilder();
-        ret.append("com.android.apex.test.");
-        switch(apexName) {
-            case FOO:
-                ret.append("foo");
-                break;
-            case BAR:
-                ret.append("bar");
-                break;
-            case BAZ:
-                ret.append("baz");
-                break;
-            case PONY:
-                ret.append("pony");
-                break;
-            case SHAREDLIBS:
-                ret.append("sharedlibs");
-                break;
-            case SHAREDLIBS_SECONDARY:
-                ret.append("sharedlibs_secondary");
-                break;
-        }
-        ret.append("@");
-        switch(apexVersion) {
-            case ONE:
-                ret.append("1");
-                break;
-            case TWO:
-                ret.append("2");
-                break;
-        }
-        ret.append(".apex");
-        return ret.toString();
-    }
-
-    /**
-     * Tests basic functionality of two apex packages being force-installed and the C++ binaries
-     * contained in them being executed correctly.
-     */
-    @Test
-    public void testInstallAndRunDefaultApexs() throws Exception {
-        assumeTrue("Device does not support updating APEX", mHostUtils.isApexUpdateSupported());
-        assumeTrue("Device requires root", getDevice().isAdbRoot());
-
-        for (String apex : new String[]{
-                getTestApex(ApexName.BAR, ApexType.DEFAULT, ApexVersion.ONE, SharedLibsVersion.X),
-                getTestApex(ApexName.FOO, ApexType.DEFAULT, ApexVersion.ONE, SharedLibsVersion.X),
-                getTestApex(ApexName.PONY, ApexType.DEFAULT, ApexVersion.ONE, SharedLibsVersion.Z),
-        }) {
-            mPreparer.pushResourceFile(apex,
-                    "/system/apex/" + apex);
-        }
-        mPreparer.reboot();
-
-        getDevice().disableAdbRoot();
-        String runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.foo/bin/foo_test");
-        assertThat(runAsResult).isEqualTo("FOO_VERSION_1 SHARED_LIB_VERSION_X");
-        if (CpuFeatures.isX86_32(getDevice()) || CpuFeatures.isArm32(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                    "/apex/com.android.apex.test.bar/bin/bar_test32");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_1 SHARED_LIB_VERSION_X");
-        }
-        if (CpuFeatures.isX86_64(getDevice()) || CpuFeatures.isArm64(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                    "/apex/com.android.apex.test.bar/bin/bar_test64");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_1 SHARED_LIB_VERSION_X");
-        }
-        runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.pony/bin/pony_test");
-        assertThat(runAsResult).isEqualTo("PONY_VERSION_1 SHARED_LIB_VERSION_Z");
-
-        mPreparer.stageMultiplePackages(
-            new String[]{
-                getTestApex(ApexName.BAR, ApexType.DEFAULT, ApexVersion.TWO, SharedLibsVersion.Y),
-                getTestApex(ApexName.FOO, ApexType.DEFAULT, ApexVersion.TWO, SharedLibsVersion.Y),
-            },
-            new String[] {
-                "com.android.apex.test.bar",
-                "com.android.apex.test.foo",
-            }).reboot();
-
-        runAsResult = getDevice().executeShellCommand(
-            "/apex/com.android.apex.test.foo/bin/foo_test");
-        assertThat(runAsResult).isEqualTo("FOO_VERSION_2 SHARED_LIB_VERSION_Y");
-        if (CpuFeatures.isX86_32(getDevice()) || CpuFeatures.isArm32(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.bar/bin/bar_test32");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_2 SHARED_LIB_VERSION_Y");
-        }
-        if (CpuFeatures.isX86_64(getDevice()) || CpuFeatures.isArm64(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.bar/bin/bar_test64");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_2 SHARED_LIB_VERSION_Y");
-        }
-    }
-
-    /**
-     * Tests functionality of shared libraries apex: installs two apexs "stripped" of libc++.so and
-     * one apex containing it and verifies that C++ binaries can run.
-     */
-    @Test
-    public void testInstallAndRunOptimizedApexs() throws Exception {
-        assumeTrue("Device does not support updating APEX", mHostUtils.isApexUpdateSupported());
-        assumeTrue("Device requires root", getDevice().isAdbRoot());
-
-        // Base case:
-        //
-        // Pre-installed on /system:
-        //   package bar version 1 using library version X
-        //   package foo version 1 using library version X
-        //   package sharedlibs version 1 exporting library version X
-        //
-        //   package pony version 1 using library version Z
-        //   package sharedlibs_secondary version 1 exporting library version Z
-
-        for (String apex : new String[]{
-                getTestApex(ApexName.BAR, ApexType.STRIPPED, ApexVersion.ONE, SharedLibsVersion.X),
-                getTestApex(ApexName.FOO, ApexType.STRIPPED, ApexVersion.ONE, SharedLibsVersion.X),
-                getTestApex(ApexName.PONY, ApexType.STRIPPED, ApexVersion.ONE, SharedLibsVersion.Z),
-                getTestApex(ApexName.SHAREDLIBS, ApexType.DEFAULT, ApexVersion.ONE,
-                    SharedLibsVersion.X),
-                getTestApex(ApexName.SHAREDLIBS_SECONDARY, ApexType.DEFAULT, ApexVersion.ONE,
-                    SharedLibsVersion.Z),
-        }) {
-            mPreparer.pushResourceFile(apex,
-                    "/system/apex/" + apex);
-        }
-        mPreparer.reboot();
-
-        getDevice().disableAdbRoot();
-        String runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.foo/bin/foo_test");
-        assertThat(runAsResult).isEqualTo("FOO_VERSION_1 SHARED_LIB_VERSION_X");
-        if (CpuFeatures.isX86_32(getDevice()) || CpuFeatures.isArm32(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                    "/apex/com.android.apex.test.bar/bin/bar_test32");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_1 SHARED_LIB_VERSION_X");
-        }
-        if (CpuFeatures.isX86_64(getDevice()) || CpuFeatures.isArm64(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                    "/apex/com.android.apex.test.bar/bin/bar_test64");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_1 SHARED_LIB_VERSION_X");
-        }
-        runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.pony/bin/pony_test");
-        assertThat(runAsResult).isEqualTo("PONY_VERSION_1 SHARED_LIB_VERSION_Z");
-
-        // Edge case: sharedlibs updated with a same version apex.
-        //
-        // Updated packages (installed on /data/apex/active):
-        //   package sharedlibs version 1 exporting library version X            <-- new
-        //   package sharedlibs_secondary version 1 exporting library version Z  <-- new
-        //
-        // Pre-installed:
-        //   package bar version 1 using library version X
-        //   package foo version 1 using library version X
-        //   (inactive) package sharedlibs version 1 exporting library version X
-        //
-        //   package pony version 1 using library version Z
-        //   (inactive) package sharedlibs_secondary version 1 exporting library version Z
-
-        mPreparer.stageMultiplePackages(
-            new String[]{
-                getTestApex(ApexName.SHAREDLIBS, ApexType.DEFAULT, ApexVersion.ONE,
-                    SharedLibsVersion.X),
-                getTestApex(ApexName.SHAREDLIBS_SECONDARY, ApexType.DEFAULT, ApexVersion.ONE,
-                    SharedLibsVersion.Z),
-            },
-            new String[]{
-                "com.android.apex.test.sharedlibs",
-                "com.android.apex.test.sharedlibs_secondary",
-            }).reboot();
-
-        runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.foo/bin/foo_test");
-        assertThat(runAsResult).isEqualTo("FOO_VERSION_1 SHARED_LIB_VERSION_X");
-        if (CpuFeatures.isX86_32(getDevice()) || CpuFeatures.isArm32(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                    "/apex/com.android.apex.test.bar/bin/bar_test32");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_1 SHARED_LIB_VERSION_X");
-        }
-        if (CpuFeatures.isX86_64(getDevice()) || CpuFeatures.isArm64(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                    "/apex/com.android.apex.test.bar/bin/bar_test64");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_1 SHARED_LIB_VERSION_X");
-        }
-        runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.pony/bin/pony_test");
-        assertThat(runAsResult).isEqualTo("PONY_VERSION_1 SHARED_LIB_VERSION_Z");
-
-        // Updated packages (installed on /data/apex/active):
-        //   package bar version 2 using library version Y               <-- new
-        //   package foo version 2 using library version Y               <-- new
-        //   package sharedlibs version 2 exporting library version Y    <-- new
-        //   package sharedlibs_secondary version 1 exporting library version Z
-        //
-        // Pre-installed:
-        //   (inactive) package bar version 1 using library version X
-        //   (inactive) package foo version 1 using library version X
-        //   package sharedlibs version 1 exporting library version X
-        //
-        //   package pony version 1 using library version Z
-        //   (inactive) package sharedlibs_secondary version 1 exporting library version Z
-
-        mPreparer.stageMultiplePackages(
-            new String[]{
-                getTestApex(ApexName.BAR, ApexType.STRIPPED, ApexVersion.TWO, SharedLibsVersion.Y),
-                getTestApex(ApexName.FOO, ApexType.STRIPPED, ApexVersion.TWO, SharedLibsVersion.Y),
-                getTestApex(ApexName.SHAREDLIBS, ApexType.DEFAULT, ApexVersion.TWO,
-                    SharedLibsVersion.Y),
-            },
-            new String[]{
-                "com.android.apex.test.bar",
-                "com.android.apex.test.foo",
-                "com.android.apex.test.sharedlibs",
-            }).reboot();
-
-        runAsResult = getDevice().executeShellCommand(
-            "/apex/com.android.apex.test.foo/bin/foo_test");
-        assertThat(runAsResult).isEqualTo("FOO_VERSION_2 SHARED_LIB_VERSION_Y");
-        if (CpuFeatures.isX86_32(getDevice()) || CpuFeatures.isArm32(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.bar/bin/bar_test32");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_2 SHARED_LIB_VERSION_Y");
-        }
-        if (CpuFeatures.isX86_64(getDevice()) || CpuFeatures.isArm64(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.bar/bin/bar_test64");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_2 SHARED_LIB_VERSION_Y");
-        }
-        runAsResult = getDevice().executeShellCommand(
-            "/apex/com.android.apex.test.pony/bin/pony_test");
-        assertThat(runAsResult).isEqualTo("PONY_VERSION_1 SHARED_LIB_VERSION_Z");
-
-        // Assume that an OTA now adds a package baz on /system needing libraries installed on
-        // /system:
-        //
-        // Updated packages (installed on /data/apex/active):
-        //   package bar version 2 using library version Y
-        //   package foo version 2 using library version Y
-        //   package sharedlibs version 2 exporting library version Y
-        //
-        // Pre-installed:
-        //   (inactive) package bar version 1 using library version X
-        //   package baz version 1 using library version X               <-- new
-        //   (inactive) package foo version 1 using library version X
-        //   package sharedlibs version 1 exporting library version X
-        //   package pony version 1 using library version Z
-        //   package sharedlibs_secondary version 1 exporting library version Z
-
-        String baz_apex =
-                getTestApex(ApexName.BAZ, ApexType.STRIPPED, ApexVersion.ONE, SharedLibsVersion.X);
-        mPreparer.pushResourceFile(baz_apex, "/system/apex/" + baz_apex);
-        mPreparer.reboot();
-
-        runAsResult = getDevice().executeShellCommand(
-            "/apex/com.android.apex.test.foo/bin/foo_test");
-        assertThat(runAsResult).isEqualTo("FOO_VERSION_2 SHARED_LIB_VERSION_Y");
-        if (CpuFeatures.isX86_32(getDevice()) || CpuFeatures.isArm32(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.bar/bin/bar_test32");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_2 SHARED_LIB_VERSION_Y");
-        }
-        if (CpuFeatures.isX86_64(getDevice()) || CpuFeatures.isArm64(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.bar/bin/bar_test64");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_2 SHARED_LIB_VERSION_Y");
-        }
-        runAsResult = getDevice().executeShellCommand(
-            "/apex/com.android.apex.test.baz/bin/baz_test");
-        assertThat(runAsResult).isEqualTo("BAZ_VERSION_1 SHARED_LIB_VERSION_X");
-        runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.pony/bin/pony_test");
-        assertThat(runAsResult).isEqualTo("PONY_VERSION_1 SHARED_LIB_VERSION_Z");
-    }
-
-    /**
-     * Tests that when a shared library apex is updated via OTA the previously
-     * downloaded version is remoted.
-     */
-    @Test
-    public void testHigherVersionOnSystemDeletesDataVersion() throws Exception {
-        assumeTrue("Device does not support updating APEX", mHostUtils.isApexUpdateSupported());
-        assumeTrue("Device requires root", getDevice().isAdbRoot());
-
-        // Base case:
-        //
-        // Pre-installed on /system:
-        //   package bar version 1 using library version X
-        //   package foo version 1 using library version X
-        //   package sharedlibs version 1 exporting library version X
-        for (String apex : new String[]{
-                getTestApex(ApexName.BAR, ApexType.STRIPPED, ApexVersion.ONE, SharedLibsVersion.X),
-                getTestApex(ApexName.FOO, ApexType.STRIPPED, ApexVersion.ONE, SharedLibsVersion.X),
-                getTestApex(ApexName.SHAREDLIBS, ApexType.DEFAULT, ApexVersion.ONE,
-                    SharedLibsVersion.X),
-        }) {
-            mPreparer.pushResourceFile(apex,
-                    "/system/apex/" + apex);
-        }
-        mPreparer.reboot();
-        String runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.foo/bin/foo_test");
-        assertThat(runAsResult).isEqualTo("FOO_VERSION_1 SHARED_LIB_VERSION_X");
-        if (CpuFeatures.isX86_32(getDevice()) || CpuFeatures.isArm32(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                    "/apex/com.android.apex.test.bar/bin/bar_test32");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_1 SHARED_LIB_VERSION_X");
-        }
-        if (CpuFeatures.isX86_64(getDevice()) || CpuFeatures.isArm64(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                    "/apex/com.android.apex.test.bar/bin/bar_test64");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_1 SHARED_LIB_VERSION_X");
-        }
-
-        // Same-grade case:
-        //
-        // Pre-installed on /system:
-        //   package bar version 1 using library version X
-        //   package foo version 1 using library version X
-        //   package sharedlibs version 1 exporting library version X
-        // Updated packages (installed on /data/apex/active):
-        //   package bar version 1 using library version X
-        //   package foo version 1 using library version X
-        //   package sharedlibs version 1 exporting library version X
-        mPreparer.stageMultiplePackages(
-            new String[]{
-                getTestApex(ApexName.BAR, ApexType.STRIPPED, ApexVersion.ONE, SharedLibsVersion.X),
-                getTestApex(ApexName.FOO, ApexType.STRIPPED, ApexVersion.ONE, SharedLibsVersion.X),
-                getTestApex(ApexName.SHAREDLIBS, ApexType.DEFAULT, ApexVersion.ONE,
-                    SharedLibsVersion.X),
-            },
-            new String[]{
-                "com.android.apex.test.bar",
-                "com.android.apex.test.foo",
-                "com.android.apex.test.sharedlibs",
-            }).reboot();
-
-        runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.foo/bin/foo_test");
-        assertThat(runAsResult).isEqualTo("FOO_VERSION_1 SHARED_LIB_VERSION_X");
-        if (CpuFeatures.isX86_32(getDevice()) || CpuFeatures.isArm32(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                    "/apex/com.android.apex.test.bar/bin/bar_test32");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_1 SHARED_LIB_VERSION_X");
-        }
-        if (CpuFeatures.isX86_64(getDevice()) || CpuFeatures.isArm64(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                    "/apex/com.android.apex.test.bar/bin/bar_test64");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_1 SHARED_LIB_VERSION_X");
-        }
-
-        // Simulate OTA upgrading pre-installed modules:
-        //
-        // Pre-installed on /system:
-        //   package bar version 2 using library version Y
-        //   package foo version 2 using library version Y
-        //   package sharedlibs version 2 exporting library version Y
-        //
-        // Updated packages (installed on /data/apex/active):
-        //   package bar version 1 using library version X (deleted)
-        //   package foo version 1 using library version X (deleted)
-        //   package sharedlibs version 1 exporting library version X (deleted)
-        //
-        for (String apex : new String[]{
-                getTestApex(ApexName.BAR, ApexType.STRIPPED, ApexVersion.ONE, SharedLibsVersion.X),
-                getTestApex(ApexName.FOO, ApexType.STRIPPED, ApexVersion.ONE, SharedLibsVersion.X),
-                getTestApex(ApexName.SHAREDLIBS, ApexType.DEFAULT, ApexVersion.ONE,
-                    SharedLibsVersion.X),
-        }) {
-            mPreparer.deleteFile("/system/apex/" + apex);
-        }
-        for (String apex : new String[]{
-                getTestApex(ApexName.BAR, ApexType.STRIPPED, ApexVersion.TWO, SharedLibsVersion.Y),
-                getTestApex(ApexName.FOO, ApexType.STRIPPED, ApexVersion.TWO, SharedLibsVersion.Y),
-                getTestApex(ApexName.SHAREDLIBS, ApexType.DEFAULT, ApexVersion.TWO,
-                    SharedLibsVersion.Y),
-        }) {
-            mPreparer.pushResourceFile(apex,
-                    "/system/apex/" + apex);
-        }
-
-        // Check that files in /data are deleted on first boot.
-        assertThat(getDevice().doesFileExist("/data/apex/active/"
-                + getInstalledApexFileName(ApexName.BAR, ApexVersion.ONE))).isTrue();
-        assertThat(getDevice().doesFileExist("/data/apex/active/"
-                + getInstalledApexFileName(ApexName.FOO, ApexVersion.ONE))).isTrue();
-        assertThat(getDevice().doesFileExist("/data/apex/active/"
-                + getInstalledApexFileName(ApexName.SHAREDLIBS, ApexVersion.ONE))).isTrue();
-        mPreparer.reboot();
-        mHostUtils.waitForFileDeleted("/data/apex/active/"
-                + getInstalledApexFileName(ApexName.BAR, ApexVersion.ONE), Duration.ofMinutes(3));
-        mHostUtils.waitForFileDeleted("/data/apex/active/"
-                + getInstalledApexFileName(ApexName.FOO, ApexVersion.ONE), Duration.ofMinutes(3));
-        mHostUtils.waitForFileDeleted("/data/apex/active/"
-                + getInstalledApexFileName(ApexName.SHAREDLIBS, ApexVersion.ONE),
-                Duration.ofMinutes(3));
-
-        getDevice().disableAdbRoot();
-        runAsResult = getDevice().executeShellCommand(
-            "/apex/com.android.apex.test.foo/bin/foo_test");
-        assertThat(runAsResult).isEqualTo("FOO_VERSION_2 SHARED_LIB_VERSION_Y");
-        if (CpuFeatures.isX86_32(getDevice()) || CpuFeatures.isArm32(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.bar/bin/bar_test32");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_2 SHARED_LIB_VERSION_Y");
-        }
-        if (CpuFeatures.isX86_64(getDevice()) || CpuFeatures.isArm64(getDevice())) {
-            runAsResult = getDevice().executeShellCommand(
-                "/apex/com.android.apex.test.bar/bin/bar_test64");
-            assertThat(runAsResult).isEqualTo("BAR_VERSION_2 SHARED_LIB_VERSION_Y");
-        }
-    }
-}
diff --git a/tests/src/com/android/tests/apex/host/ApexCompressionTests.java b/tests/src/com/android/tests/apex/host/ApexCompressionTests.java
index ed4957a8..af10fd52 100644
--- a/tests/src/com/android/tests/apex/host/ApexCompressionTests.java
+++ b/tests/src/com/android/tests/apex/host/ApexCompressionTests.java
@@ -343,7 +343,8 @@ public class ApexCompressionTests extends BaseHostJUnit4Test {
         // Push a data apex that will fail to activate
         final File file =
                 mHostUtils.getTestFile("com.android.apex.compressed.v2_manifest_mismatch.apex");
-        getDevice().pushFile(file, APEX_ACTIVE_DIR + COMPRESSED_APEX_PACKAGE_NAME + "@2.apex");
+        final String corrupt_apex = APEX_ACTIVE_DIR + COMPRESSED_APEX_PACKAGE_NAME + "@2.apex";
+        getDevice().pushFile(file, corrupt_apex);
         // Push a CAPEX which should act as the fallback
         // Note that this reboots the device.
         pushTestApex(COMPRESSED_APEX_PACKAGE_NAME + ".v2.capex");
@@ -358,11 +359,7 @@ public class ApexCompressionTests extends BaseHostJUnit4Test {
         assertThat(getDevice().doesFileExist(
                 DECOMPRESSED_DIR_PATH + COMPRESSED_APEX_PACKAGE_NAME + "@2"
                 + DECOMPRESSED_APEX_SUFFIX)).isTrue();
-        assertThat(getDevice().doesFileExist(
-                APEX_ACTIVE_DIR + COMPRESSED_APEX_PACKAGE_NAME + "@2"
-                + DECOMPRESSED_APEX_SUFFIX)).isFalse();
-        assertThat(getDevice().doesFileExist(
-                APEX_ACTIVE_DIR + COMPRESSED_APEX_PACKAGE_NAME + "@2.apex")).isFalse();
+        mHostUtils.waitForFileDeleted(corrupt_apex, Duration.ofMinutes(1));
     }
 
     @Test
diff --git a/tests/src/com/android/tests/apex/host/ApkInApexTests.java b/tests/src/com/android/tests/apex/host/ApkInApexTests.java
index 8452e413..53732d81 100644
--- a/tests/src/com/android/tests/apex/host/ApkInApexTests.java
+++ b/tests/src/com/android/tests/apex/host/ApkInApexTests.java
@@ -78,6 +78,7 @@ public class ApkInApexTests extends BaseHostJUnit4Test {
 
     @After
     public void tearDown() throws Exception {
+        mPreparer.after();
         getDevice().disableAdbRoot();
     }
 
diff --git a/tests/testdata/sharedlibs/README.md b/tests/testdata/sharedlibs/README.md
deleted file mode 100644
index a59686da..00000000
--- a/tests/testdata/sharedlibs/README.md
+++ /dev/null
@@ -1,13 +0,0 @@
-### Test artifacts for shared libraries APEX support
-
-This directory contains APEX packages used for testing the platform support for
-moving shared libraries used by binaries within an APEX package into another
-APEX package.
-
-Due to the peculiarity of the build needs, this directory contains prebuilt
-artifacts used by tests. In order to regenerate these artifacts, run from the
-root of the tree:
-
-```shell script
-./system/apex/tests/testdata/sharedlibs/build/build_artifacts.sh
-```
\ No newline at end of file
diff --git a/tests/testdata/sharedlibs/build/Android.bp b/tests/testdata/sharedlibs/build/Android.bp
deleted file mode 100644
index 41601cbb..00000000
--- a/tests/testdata/sharedlibs/build/Android.bp
+++ /dev/null
@@ -1,76 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-cc_binary {
-    name: "noop",
-    srcs: ["noop.cc"],
-    shared_libs: [
-        "libsharedlibtest",
-    ],
-    multilib: {
-        lib32: {
-            suffix: "32",
-        },
-        lib64: {
-            suffix: "64",
-        },
-    },
-
-    compile_multilib: "both",
-
-    apex_available: [
-        "com.android.apex.test.sharedlibs_stub",
-        "com.android.apex.test.sharedlibs_secondary_stub",
-    ],
-}
-
-python_binary_host {
-    name: "shared_libs_repack",
-    srcs: [
-        "shared_libs_repack.py",
-    ],
-    libs: [
-        "apex_build_info_proto",
-        "apex_manifest_proto",
-    ],
-    required: [
-        "apexer",
-        "signapk",
-    ],
-}
-
-cc_library_shared {
-    name: "libsharedlibtest",
-    srcs: ["sharedlibstest.cpp"],
-
-    local_include_dirs: [
-        "include",
-    ],
-
-    export_include_dirs: [
-        "include",
-    ],
-    apex_available: [
-        "com.android.apex.test.bar",
-        "com.android.apex.test.baz",
-        "com.android.apex.test.foo",
-        "com.android.apex.test.pony",
-        "com.android.apex.test.sharedlibs_stub",
-        "com.android.apex.test.sharedlibs_secondary_stub",
-    ],
-}
diff --git a/tests/testdata/sharedlibs/build/build_artifacts.sh b/tests/testdata/sharedlibs/build/build_artifacts.sh
deleted file mode 100755
index 8dbc64f5..00000000
--- a/tests/testdata/sharedlibs/build/build_artifacts.sh
+++ /dev/null
@@ -1,206 +0,0 @@
-#!/bin/bash -e
-
-# List of files required in output. Every other file generated will be skipped.
-OUTFILES=(
-  com.android.apex.test.bar_stripped.v1.libvX.apex
-  com.android.apex.test.bar_stripped.v2.libvY.apex
-  com.android.apex.test.bar.v1.libvX.apex
-  com.android.apex.test.bar.v2.libvY.apex
-  com.android.apex.test.baz_stripped.v1.libvX.apex
-  com.android.apex.test.foo_stripped.v1.libvX.apex
-  com.android.apex.test.foo_stripped.v2.libvY.apex
-  com.android.apex.test.foo.v1.libvX.apex
-  com.android.apex.test.foo.v2.libvY.apex
-  com.android.apex.test.pony_stripped.v1.libvZ.apex
-  com.android.apex.test.pony.v1.libvZ.apex
-  com.android.apex.test.sharedlibs_generated.v1.libvX.apex
-  com.android.apex.test.sharedlibs_generated.v2.libvY.apex
-  com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex
-)
-
-# "apex" type build targets to build.
-APEX_TARGETS=(
-  system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.bar:com.android.apex.test.bar
-  system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.foo:com.android.apex.test.foo
-  system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.pony:com.android.apex.test.pony
-)
-
-# "genrule" type build targets to build, and directory they are built from.
-GENRULE_TARGETS=(
-  system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.bar:com.android.apex.test.bar_stripped
-  system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.baz:com.android.apex.test.baz_stripped
-  system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.foo:com.android.apex.test.foo_stripped
-  system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.pony:com.android.apex.test.pony_stripped
-  system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs:com.android.apex.test.sharedlibs_generated
-  system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary:com.android.apex.test.sharedlibs_secondary_generated
-)
-
-if [ ! -e "build/make/core/Makefile" ]; then
-    echo "$0 must be run from the top of the tree"
-    exit 1
-fi
-
-OUT_DIR=$(source build/envsetup.sh > /dev/null; TARGET_PRODUCT= get_build_var OUT_DIR)
-DIST_DIR=$(source build/envsetup.sh > /dev/null; TARGET_PRODUCT= get_build_var DIST_DIR)
-TMPDIR=$(source build/envsetup.sh > /dev/null; TARGET_PRODUCT= get_build_var TMPDIR)
-
-manifestdirs=()
-
-for t in "${APEX_TARGETS[@]}" "${GENRULE_TARGETS[@]}"; do
-    IFS=: read -a ar <<< "${t}"
-    manifestdirs+=( ${ar[0]})
-done
-
-manifestdirs=($(printf "%s\n" "${manifestdirs[@]}" | sort -u))
-
-generated_artifacts=()
-
-archs=(
-  arm
-  arm64
-  x86
-  x86_64
-)
-
-apexversions=(
-  1
-  2
-)
-
-libversions=(
-  X
-  Y
-  Z
-)
-
-for arch in "${archs[@]}"; do
-    for apexversion in "${apexversions[@]}"; do
-        apexfingerprint="VERSION_${apexversion}"
-        sed -i "s/#define FINGERPRINT .*/#define FINGERPRINT \"${apexfingerprint}\"/g" \
-        system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.bar/bar_test.cc \
-        system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.baz/baz_test.cc \
-        system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.foo/foo_test.cc \
-        system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.pony/pony_test.cc
-
-        for d in "${manifestdirs[@]}"; do
-            sed -i "s/  \"version\": .*/  \"version\": ${apexversion}/g" \
-            ${d}/manifest.json
-        done
-        for libversion in "${libversions[@]}"; do
-            # Check if we need to build this combination of versions.
-            found=n
-            for t in "${APEX_TARGETS[@]}" "${GENRULE_TARGETS[@]}"; do
-                IFS=: read -a ar <<< "${t}"
-                outfile=${ar[1]}.v${apexversion}.libv${libversion}.apex
-                if printf '%s\n' "${OUTFILES[@]}" | grep -q -F "${outfile}"; then
-                    found=y
-                    break
-                fi
-            done
-            if [ "${found}" != "y" ]; then
-                # Skipping this combination.
-                continue
-            fi
-
-            echo "Building combination arch: ${arch}, apexversion: ${apexversion}, libversion: ${libversion}"
-            libfingerprint="VERSION_${libversion}"
-            sed -i "s/#define FINGERPRINT .*/#define FINGERPRINT \"${libfingerprint}\"/g" \
-            system/apex/tests/testdata/sharedlibs/build/sharedlibstest.cpp
-
-            build/soong/soong_ui.bash \
-                --make-mode \
-                TARGET_PRODUCT=aosp_${arch} \
-                dist sharedlibs_test
-
-            for t in "${APEX_TARGETS[@]}" "${GENRULE_TARGETS[@]}"; do
-                IFS=: read -a ar <<< "${t}"
-                outfile=${ar[1]}.v${apexversion}.libv${libversion}.apex
-                if printf '%s\n' "${OUTFILES[@]}" | grep -q -P "^${outfile}\$"; then
-                    cp -v \
-                    "${DIST_DIR}"/"${ar[1]}".apex \
-                    system/apex/tests/testdata/sharedlibs/prebuilts/${arch}/${outfile}
-                    generated_artifacts+=(system/apex/tests/testdata/sharedlibs/prebuilts/${arch}/${outfile})
-                fi
-            done
-        done
-    done
-done
-
-# Generate the Android.bp file for the prebuilts.
-tmpfile=$(mktemp)
-
-cat > "${tmpfile}" << EOF
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-// This file is auto-generated by
-// ./system/apex/tests/testdata/sharedlibs/build/build_artifacts.sh
-// Do NOT edit manually.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-EOF
-
-artifacts_filenames=()
-for artifact in "${generated_artifacts[@]}"; do
-    artifacts_filenames+=($(basename ${artifact}))
-done
-
-artifacts_filenames=($(printf '%s\n' "${artifacts_filenames[@]}" | sort -u))
-
-for artifact in "${artifacts_filenames[@]}"; do
-    outfile=$(basename "${artifact}")
-    # remove .apex suffix
-    rulename=${outfile%.apex}
-
-    cat >> "${tmpfile}" << EOF
-
-prebuilt_apex {
-  name: "${rulename}_prebuilt",
-  arch: {
-EOF
-
-    for arch in "${archs[@]}"; do
-        cat >> "${tmpfile}" << EOF
-    ${arch}: {
-      src: "${arch}/${outfile}",
-    },
-EOF
-    done
-
-    cat >> "${tmpfile}" << EOF
-  },
-  filename: "${outfile}",
-  installable: false,
-}
-EOF
-done
-
-mv "${tmpfile}" system/apex/tests/testdata/sharedlibs/prebuilts/Android.bp
-
-# Restore the default version string to avoid bogus diffs.
-sed -i "s/#define FINGERPRINT .*/#define FINGERPRINT \"VERSION_XXX\"/g" \
-system/apex/tests/testdata/sharedlibs/build/sharedlibstest.cpp \
-system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.bar/bar_test.cc \
-system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.baz/baz_test.cc \
-system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.foo/foo_test.cc \
-system/apex/tests/testdata/sharedlibs/build/com.android.apex.test.pony/pony_test.cc
-
-for d in "${manifestdirs[@]}"; do
-    sed -i "s/  \"version\": .*/  \"version\": 1/g" \
-    ${d}/manifest.json
-done
-
-ls -l "${generated_artifacts[@]}"
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.bar/Android.bp
deleted file mode 100644
index 9f1f1b67..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/Android.bp
+++ /dev/null
@@ -1,98 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-apex_key {
-    name: "com.android.apex.test.bar.key",
-    public_key: "com.android.apex.test.bar.avbpubkey",
-    private_key: "com.android.apex.test.bar.pem",
-}
-
-android_app_certificate {
-    name: "com.android.apex.test.bar.certificate",
-    certificate: "com.android.apex.test.bar",
-}
-
-apex {
-    name: "com.android.apex.test.bar",
-    manifest: "manifest.json",
-    file_contexts: ":apex.test-file_contexts",
-    key: "com.android.apex.test.bar.key",
-    installable: false,
-    binaries: ["bar_test"],
-    dist: {
-        targets: ["sharedlibs_test"],
-    },
-    updatable: false,
-    compile_multilib: "both",
-    multilib: {
-        both: {
-            binaries: [
-                "bar_test",
-            ],
-        },
-    },
-    // This test apex is used by shared_libs_repack, which works with only ext4.
-    payload_fs_type: "ext4",
-}
-
-cc_binary {
-    name: "bar_test",
-    srcs: ["bar_test.cc"],
-    shared_libs: [
-        "libsharedlibtest",
-    ],
-    multilib: {
-        lib32: {
-            suffix: "32",
-        },
-        lib64: {
-            suffix: "64",
-        },
-    },
-
-    compile_multilib: "both",
-
-    apex_available: ["com.android.apex.test.bar"],
-}
-
-java_genrule {
-    name: "com.android.apex.test.bar_stripped",
-    out: ["com.android.apex.test.bar_stripped.apex"],
-    defaults: ["apexer_test_host_tools_list"],
-    dist: {
-        targets: ["sharedlibs_test"],
-    },
-    srcs: [
-        ":com.android.apex.test.bar",
-        "com.android.apex.test.bar.avbpubkey",
-        "com.android.apex.test.bar.pem",
-        "com.android.apex.test.bar.pk8",
-        "com.android.apex.test.bar.x509.pem",
-    ],
-    tools: [
-        "shared_libs_repack",
-    ],
-    cmd: "$(location shared_libs_repack) " +
-        " --mode strip" +
-        " --key $(location com.android.apex.test.bar.pem)" +
-        " --input $(location :com.android.apex.test.bar)" +
-        " --output $(genDir)/com.android.apex.test.bar_stripped.apex" +
-        " --pk8key $(location com.android.apex.test.bar.pk8)" +
-        " --pubkey $(location com.android.apex.test.bar.avbpubkey)" +
-        " --x509key $(location com.android.apex.test.bar.x509.pem)" +
-        " --tmpdir $(genDir)",
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/bar_test.cc b/tests/testdata/sharedlibs/build/com.android.apex.test.bar/bar_test.cc
deleted file mode 100644
index 9b397de2..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/bar_test.cc
+++ /dev/null
@@ -1,13 +0,0 @@
-#include <iostream>
-#include <string>
-
-#include "sharedlibstest.h"
-
-// This parameter gets modified by the build_artifacts.sh script.
-#define FINGERPRINT "VERSION_XXX"
-
-int main() {
-  std::cout << "BAR_" << FINGERPRINT << " "
-            << sharedlibstest::getSharedLibsTestFingerprint();
-  return 0;
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.avbpubkey b/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.avbpubkey
deleted file mode 100644
index 931a477a..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.avbpubkey and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.pem
deleted file mode 100644
index 9363cda9..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.pem
+++ /dev/null
@@ -1,51 +0,0 @@
------BEGIN RSA PRIVATE KEY-----
-MIIJKAIBAAKCAgEAp/bgVatvywj6wEKD0ldJ+RxfFOv/67norL43z55gd/K/u1W4
-GoFHm0e5T1PV0j5zMi7EraIWy5g9eTmtU9DTwJoIKHw/agrVimxBsd5Los/zHAGJ
-JoRy5Wo7cenpp2QpNzfY3HdN88PMZ3FiRooa/GepoOI7IBs3IEmGJTC3N5CZYsh7
-b3yzZn4cuWuQZ+oD+G/z1AjK9Q1po3auz5lqSu1VD8GoswwfrC7G/MvH/5Jytu/o
-XKESeGIri8YDMqsVX7hHTGbQ8MBpy5RtFfIGND+XulZvTl87bXAhJVbJjD3GlZyM
-i/eZL4pUdxKjv/ZOT5bI1/NTJ6Qtr6yMgJuVbL7VHYFPISxdwXYY/fkr0AvZw+hL
-KopDrb3Jn+79elZqOuZ6l1muCpkXRs4QS4fRSh4Lnk2782p+y070WhdA+zgzDLhX
-4ytyhAGNi9wWNCjGDT3C8AOoRzn8PhG8sHsAHL6sFYpJx3LRyv/nO1jFGHDd3cgj
-Vql0NTyVPlj8JiSQ1aQvXMtf1M7pwp6igjKPf37tVrZ4gDpjQm26VSy8lcgKgR8w
-Ej4Ti4NbkcZuoJNjIfJZJAUDtr+aXJA2bWRO0ggTnuvC3sHCMH4o6i2FdNzsahYn
-z2QY7h7hiuCdXJdoFWBhSOQ9cUcBroymuSNWhliSxj7XObql2hK+u3Bzp3MCAwEA
-AQKCAgAdQrPYGNKT40+TmMLQLOa1IA0sXuSpkyyGk2izoZqaqs5d+1PkQitQUNFm
-kWtJghmdX2ph+T/RXgcvjC220UViYzMSonqFpbeHss5LBzfT+DgY4+eZry846iXK
-9X3/7EIF3ZPI7HvHAJAmYSlGsp565DA319GHCVa0KDrXVcJFSsp93AEs7eNu8n9c
-ifGROMJSUGaAxLter2R81psjjU1oGipcYVdbQbxuyYNe3L1Nt5yGZArtwB2wnSGK
-6wb5l7ZUg4zgMXUqy8pibcwHK6+LAJ0VGCOx2oNG0Gbl01WvOb/Tpn8RjyO/lXCb
-gcLHGUiRMupwPHJ7EG3pEb00VmZUUCd5bBv76A8WyS9hrGZbcHy26nS/9HkadT5Q
-IZVjWSbjZA13Tm0OmSKgwV3UC5yRZnRj4vNoku9bhWhZ+n7GCAYbSBiAVBrlIgM6
-yxw66Sbxq7jLEZEUDWLTGl00W07hvF44FHYIATsOMzHyLPbKAeozimP/sZVw+dFN
-KcNVKJtvxf/xoZIvM32BevrwqlfgQRr6G+sILzP60NlLMqQTsXlqsqZlyZ6ROrWp
-0q1T1NQBqiyNjk5Iq+nfQl0wVK1F8Xj/IrZ4udddKKunWtDIADcdx3HshkmiVVwp
-3lTadEEEA64Jwu9GyoYK78+xINkIm8/GK4LPgo4a5eRO5JaAqQKCAQEA1/DzERsj
-FqmrF3SVKt15ZqAV71YkVmlVTcE62Gr93kE0YEhkK9HrxcddkiPgkaKP/VUXpzwL
-zVsvdIlPaCdLQVoZt/c2weDvNO+8DKtb3v4AYgc8fltSCvPMzdc3VezL1Y0mZmMV
-sZndsw2ZpZnRrtHllqPQR8mC3mLgvhUyQw2yIcWPuI1L3VBTjd/9z6MDgDTZ3gKq
-h5odK5gu+KIT5hUsnxCb1Z7D3WAw/uprwpW4IFIFWbMeXPwVGuwKQ0/ueqSWQPoC
-mO5sVLd43auO9pAtp0BT8shdPkxuJiI7FNckdh8QJJOu2JkvN9O9/GZEDK2NuPZN
-ONo0hAkczxUkjQKCAQEAxx+BeFsY7H2ai55QR8TkEaK4jVuqiJZFjMipQWkM8vyM
-kYXUG/sV61gex5TZEdagxGdGyGsm58kq9cySY75CGPjCm9bPJ2qsKnKEkw4PK6BM
-eqHres2x7XjE64tF4AIYLPNVmMQKc/5Ke7uTsA2W4YYHSwDKODRFGKhgc4oI5G+w
-j5TtnqeOQ+WxseFEQEp9RgUIssO6m0K4lE9lrwTFsu95USrpJQXs6J/nZct/xXAO
-fRuv/nB7GMSj+Ay7TEfFbAw0D8NKEYzpF1/oUjPW8aihXh3Eq6HySBjRbAH8YCjC
-WZYSm7f7TLunIonRL+dqCHB3WFDsvta2nwdPdUb7/wKCAQAZquxZhi4/jV9m5Fau
-x7CcgD7bOhQLqW2YVnWWL/GJL5r4LuKpSsSJt87phhY1eWtAI5MyL7L/b+1OHtwv
-dyw80mboNRxvIzuLwUtK/jtnYC3PeSi5pEU2RBB+Dyzmq8T211ZPKUv01mNB20X+
-JzCDZTOzGjmxrsQ9hudL8N0Ol1wrI36X40O3RMsJvCxBOBE8dgvHle2LPMhm3CoJ
-J8rRuIabSbAcTkjd0YdBZb/1WzKNtPIp3V6oktY3YwM9SQ0ByvqJMq6IWx7JWx2k
-y7WsnSqwDLdtzl82/oLBSaRYL9KHr92NW3iXCm5QZnzYuZcxIpgL+krnjRhc8XBZ
-NRwpAoIBAQCntCU61J6dLvwmcuNyTqU3JTEB/R4Xg1h4RdgnOu6pB4LsXSZTmpjP
-aZwiw34+w+ELCWBYE8bkmE0ST4VLdEX++iQNVFGMBQ+TgHef0st8FrnS3uSQvQUJ
-2BkhuF7VV249DYQd8Z5MKvNYWpb8Q7W7o0IpLTUjOQKozcbOCIeMvXSauPeYE86B
-6MZL5kmxTAtOGZdF2AsmEH+ciXI+gWpwVbh7YASUJfVtxp8A4O9vvfy16cfEJ7/F
-EHh4xWBJ0ni3k1+Vlwie12rJQQFNmlOBnGCr/65QT0ja5+wZZ2LDKhDlmrt5Yu7H
-pZQSRrhj/CcVjIM3YpDB+dw8+880GuDJAoIBAD/3oFK1uG++uU/Mo+3YtZj5YWuE
-Z5FNE7tJGeyKUvKXTLUO1NTG+HEmSGkOyeiXrQNJssFOjgVzNx1kke5Pi4qv4+QL
-087gFnhDnrMHBSwcWIpkEe5zQEYrS/yRJlD63WM72ivLDNTXe/BQfuCIdX9qBHbG
-qQQzjaLdj0xtKQsidL2Cy/PlqfqGzp90I6uXbRiOrC4rsNjr9mX82atNswua0tcD
-mMGi0eJXtKOS2aaJPU9yofd4sBW+n94Ff5ue1cwfjdW/lKaAPDBGNRCgvvcyM39Q
-DWK6NSHzz7pVO5+tb54vMZK4TySPrS1qlin4AALo4tHIBuIDkaIHTmDsF8c=
------END RSA PRIVATE KEY-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.pk8 b/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.pk8
deleted file mode 100644
index 6119c7f2..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.pk8 and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.x509.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.x509.pem
deleted file mode 100644
index e687fc56..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/com.android.apex.test.bar.x509.pem
+++ /dev/null
@@ -1,34 +0,0 @@
------BEGIN CERTIFICATE-----
-MIIF1zCCA78CFEnLOBRbjwndwo8AjZVTyorFhju2MA0GCSqGSIb3DQEBCwUAMIGm
-MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91
-bnRhaW4gVmlldzEQMA4GA1UECgwHQW5kcm9pZDEQMA4GA1UECwwHQW5kcm9pZDEi
-MCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTEiMCAGA1UEAwwZY29t
-LmFuZHJvaWQuYXBleC50ZXN0LmJhcjAgFw0yMDEwMDUxNjMzMDVaGA80NzU4MDkw
-MTE2MzMwNVowgaYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYw
-FAYDVQQHDA1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKDAdBbmRyb2lkMRAwDgYDVQQL
-DAdBbmRyb2lkMSIwIAYJKoZIhvcNAQkBFhNhbmRyb2lkQGFuZHJvaWQuY29tMSIw
-IAYDVQQDDBljb20uYW5kcm9pZC5hcGV4LnRlc3QuYmFyMIICIjANBgkqhkiG9w0B
-AQEFAAOCAg8AMIICCgKCAgEA42Gi4Y3vNA1zQh+IDY/mQbRfvy5ikmWFTP4PwKcO
-XSg21BiTx7o7k+cKbuHjCWp3eh2O1fRXB9WXLQ3//8BNLZLUuaGWM7+fcsN5V+aK
-yPxzt/6fYBOzb4BkYnMgJjmOHBo9TL1g35IPM6O5Y3oSvCBhQuMdvZYbBDBAZ4Zn
-+0PoP7fWPPUne4PGL5KF48ttpKbXeFhUjWcVnh440Amfs4+dHrblf4/f1iKUIrT8
-hNWgOBhUrHAKyKAyE/FYydVm6smLZN39m/5ac7LDwYzRBP5IDVKbLxfmwSOfj0n9
-1YvEyl/BSwY0V29AbCbsl9eVQkE2Jy1UqS7we8rK+V+Z3b/dTOh7skdAwMHGDi6v
-qIxjNr9tAX1Pxhj1PbqYM7nIa7hLmNfJk6N/k72VjJdiWyp2WcQFIJQduSbtgMS3
-CA+LzCJqEbqz5SyaFHh89KsqHPGOxcsVHI5mIRWhBioCKlCbsqvcZg+ChzdY7Hbk
-ViBhqmZr7cAXyZEqUXApSmX3E1yKCXry1WF9hl8homsG0rO1C+seS+R3OiWRNdrK
-o9Aik1gtwpoxbJH+Hxc0usS4yW3b3YyFN2tPUN2NoTFrkKNSRfDwqlWCJH8wd1Og
-4dTxyYesVLCKW0/YfPKBCPFlAqx+yDBOe7lxP/1kuWdKeIHxdhlGpjqUoaeqi+46
-+xMCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAlGQyBIzKvdstBN/6uASKOHcWuqfD
-COyBXnUmMHEWawtS0C4aL0rJmvILQaVrFp3dPkjI3RpN8TZqVnQfawOewOBe/2Vk
-cpzGxsIJQpjmFmMJr730LX/RDELnTnz3VKwIbCoZBZ3qktiAI5+rGmmP4FrU8MVl
-m+VnShyxFSmLakhcyezOos3+ibJDgFsoNFDQ9b8aTUFKy4Xsa5OMSYeAJc4L2IWY
-dowDHu5wnRTfy0uCXn095GdgSiYAAvSp58M/bXuVaHXm/Qg0upWdEaouSMecAYwz
-PTF2sEpmoAUVIHOusm1Chqopa4kQtQCcVB3b/1YDZTeodjKHI7w9WLqjEeq7+fYl
-msvxlYtyL3r6JpQXyYhy1643zmI8/P1TYTi1AbsVNwz/87xmHyrldLKH+jmWMspx
-hiynKOTZahtO48WhkRGLa+iJk14ztUdD3MxAJwZiMUMFhLth/zYLGSyBwqR1smrs
-J5k7BL67b07JApjoPL1OHn9ypBrV5L2CKwSfEGEzp65BtfGIGDYyoNxEv8zky8KY
-XHxZaSWor6RQRp1QX6VRcXYk7XQHWuIevlW5W2APRXCAC05+rlVvi98swJQUcR3/
-oZCgxdr9mSV01fRZMkXv5exkhu/KR8c1ZstqRcSswRv4vrFFTFRahrTWGk0DQXU3
-EH5MwrfZ9sUq7Iw=
------END CERTIFICATE-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/manifest.json b/tests/testdata/sharedlibs/build/com.android.apex.test.bar/manifest.json
deleted file mode 100644
index da13d6d8..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.bar/manifest.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-  "name": "com.android.apex.test.bar",
-  "version": 1
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.baz/Android.bp
deleted file mode 100644
index 0af35523..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/Android.bp
+++ /dev/null
@@ -1,79 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-apex_key {
-    name: "com.android.apex.test.baz.key",
-    public_key: "com.android.apex.test.baz.avbpubkey",
-    private_key: "com.android.apex.test.baz.pem",
-}
-
-android_app_certificate {
-    name: "com.android.apex.test.baz.certificate",
-    certificate: "com.android.apex.test.baz",
-}
-
-apex {
-    name: "com.android.apex.test.baz",
-    manifest: "manifest.json",
-    file_contexts: ":apex.test-file_contexts",
-    key: "com.android.apex.test.baz.key",
-    installable: false,
-    binaries: ["baz_test"],
-    dist: {
-        targets: ["sharedlibs_test"],
-    },
-    updatable: false,
-    // This test apex is used by shared_libs_repack, which works with only ext4.
-    payload_fs_type: "ext4",
-}
-
-cc_binary {
-    name: "baz_test",
-    srcs: ["baz_test.cc"],
-    shared_libs: [
-        "libsharedlibtest",
-    ],
-    apex_available: ["com.android.apex.test.baz"],
-}
-
-java_genrule {
-    name: "com.android.apex.test.baz_stripped",
-    out: ["com.android.apex.test.baz_stripped.apex"],
-    defaults: ["apexer_test_host_tools_list"],
-    dist: {
-        targets: ["sharedlibs_test"],
-    },
-    srcs: [
-        ":com.android.apex.test.baz",
-        "com.android.apex.test.baz.avbpubkey",
-        "com.android.apex.test.baz.pem",
-        "com.android.apex.test.baz.pk8",
-        "com.android.apex.test.baz.x509.pem",
-    ],
-    tools: [
-        "shared_libs_repack",
-    ],
-    cmd: "$(location shared_libs_repack) " +
-        " --mode strip" +
-        " --key $(location com.android.apex.test.baz.pem)" +
-        " --input $(location :com.android.apex.test.baz)" +
-        " --output $(genDir)/com.android.apex.test.baz_stripped.apex" +
-        " --pk8key $(location com.android.apex.test.baz.pk8)" +
-        " --pubkey $(location com.android.apex.test.baz.avbpubkey)" +
-        " --x509key $(location com.android.apex.test.baz.x509.pem)" +
-        " --tmpdir $(genDir)",
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/baz_test.cc b/tests/testdata/sharedlibs/build/com.android.apex.test.baz/baz_test.cc
deleted file mode 100644
index ea5b341a..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/baz_test.cc
+++ /dev/null
@@ -1,13 +0,0 @@
-#include <iostream>
-#include <string>
-
-#include "sharedlibstest.h"
-
-// This parameter gets modified by the build_artifacts.sh script.
-#define FINGERPRINT "VERSION_XXX"
-
-int main() {
-  std::cout << "BAZ_" << FINGERPRINT << " "
-            << sharedlibstest::getSharedLibsTestFingerprint();
-  return 0;
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.avbpubkey b/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.avbpubkey
deleted file mode 100644
index ef865d7a..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.avbpubkey and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.pem
deleted file mode 100644
index ee8b8a66..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.pem
+++ /dev/null
@@ -1,51 +0,0 @@
------BEGIN RSA PRIVATE KEY-----
-MIIJKQIBAAKCAgEAu48tcVfIiZ9syLm4CqkRE5/MOhfzro4epTGV0VrkOc8JYQic
-YjRAN02/7QfGk/aei3xRuVKqAqDxnZ5IE5ii6/HT9TOInMK08/vr7jc6N7dfQCSW
-nyvG3WBC2HWEmuVCGJrY1j/lmIzKuUcMgpF0ZaqB1Qm/viI/ppXZiEm234SFAg0y
-RZbiiGRy5K388xkTA0nbIAi3iRq8RSfDN4kFzIH/Y7AsNF/tzI2K+4PziGmReH/e
-ekgPhC7XUUySNrjctl7naDgvuihu18QwsC+WNCop7aHLe/ByOrOFq5R/mGsPCP6q
-JyUJ0P9YotI28y+h7rd88W6IsTQMz9jw1JENx2YGJHkjRYIy97vDDbeeyBm5qI3I
-Suy8IgzG/JW0w4pvUB6pWzfDuw+Hr4sqU7Bjb/CFeFUfzSGTg7efDN8W3L/O/wtH
-+hR1t0B0BZBtW9TOFCo4z30C1u2OltT5Vr8GgsODMdR6tQCNpu4WmWfImriETuKQ
-OzPYo2eKCbsoLEQxda+EUu4h5FDH703JYWvrxCCmHeW624iXy1LavEc9YYOe0oRT
-DslIvYSHimH9jvgXRU7HLz0obljwwYRM+7aHWmTClrIC+aSEq1x0COHt8fWtbJ3f
-gBCdNSBcd0GEX55V6Ez1lytGWLzwPqedYbQnoKdIJPu5Ge7GMm75de0lgR8CAwEA
-AQKCAgBoV2e1dVt3zHwtUrxjGdkJLM3lx6tmAWRlDCfHlyP+UQJru+mb7GuJGLTb
-/YZojDt5Z8jjK2yvF7AyunpohHKmhhsffvLSGrOmRBDlrk2x706LFY/Brw3r3AB0
-ATSrIz1ZCNP2pQdqjXC+EBuSi67QXEHsLYdBFDaKyzSAUFnvEP8ZvBOqiR0vOYp9
-U5mz99AO9Uh1EsRf/sKcSlmdDJpwQiW85KZC4NcfA+M8txSFYA1wltpC9tHC/HgG
-n218Ce2nezaLUS6kBphbaqaXbXHHRWmb7HWSVpqFs5d6c5tkRLLRkzM/oahLX7KE
-qiOtuGMCtYtJmO9sfYNfIdYguy2JOylBQU1HLT2eTp/be29aUfblGpvG+4WM49+e
-da33R65viP6uvwcTuiQIZdfouJLgADutfmLAX4XGk110k/AOzSFCeIvX0oeoc/Nv
-IZDgGQjELBuyKdCEnheo3UkngXZg2hbVSoI+EQE900wm8s3vi8GoKq32VuZAiNGi
-mW6ebs1A3fOLCPrK9GdbLu6A2uXyeeQH7NMiyK9o5jWPIU7NJ3KUgGQmbNz0/aqi
-jN93DdRjeoYXUdD2oYC8S9XMqtdiUubVEMqDeGg2jhLxYDk9EfKD9KZnmFSBM7a0
-WlZlixTXi77ktJS7+1YlRWluPIhD0MXdEkHeRmgGZoc0w9ayoQKCAQEA6IrCf8U6
-SUG2QaLrIjAVcR76UETGR4gE5s5E1qvZB3/yGzou9QeBOGFz5lRQbrGD9nrNFuqq
-Z/VJmsL2aia4dPDjjJLPW3budcq8GjR/ZdGCkE+VWc3D/CUf8ja4Lx3MxDjym0cw
-i+pMysym/6QNo/sAltzQYehtQlGNUisII+p1FbHKQAZwLgczvglZObgynegSUyKT
-xrXcUyqOozU933YPkPE1X3cKyF2JFoK/YzxMCfDlYIs4SfwlFnFELbz5ug4Zx2WU
-Ouc9JWhAELYzHnbHP0OkP6mUTjSJC52XCdHg8b2Qtrof/PEuJ3Xoyz8PFBQIeRjD
-HzTJ4i0Pzwd/rwKCAQEAznrE11R6IbsAznmE5d2nmrph8n0qnpXi9Ryd5c4W6VNm
-+hnelTnhAkGtNHJCloL24zPlAlb9CAGKJM7U1I21PqgZpIJ7hHTU1FLiwc83dkal
-IQ5yVbAPoa4O/qn0Omo+MQ+tYCygDHiAJFQFah+pX1Jj+6djn7kKNCzpVeN6aVFu
-hblHAOgwhDlt+l461wjYsI39osPfgInO/z/oY0WuIFEYCA5kWXEuNImqZi7GTcs3
-EQVR+OxTxwt9IUJVeTAusv8V5DFqlojF9jZVBB60VcfMAEyjsAF0/ZsweuBU3jnD
-mAln3pIS4AON0zGM/eZFKKkHZT+ZVqIUOVCFoyGBkQKCAQEAwmX10SCM6F7hwR80
-WCFAW4/dDCtiYrwn9NctHxUMWsOwHujWBosekIaPgFat4svNmMjyGJ1WlY+t143y
-t6zk+QXEBGlapYjYMmqoM3P9qJ2r+348SZXFqE1U1oS+Fs1fuA4vanXp9J2LUuIh
-HYcEzDfyNywjnCXU6OMKNE27AWNoPBmkDUAUmbX1oIFqMOF2lyFB6HP4e97ecDwc
-f/3rWpr0ymOLDeKThgsDpmjpHEl0+76B0uKvzNHYI1nO+DmJvus4y8N0VoWnTVVI
-cXAPbgE38gBXF81pKLOseaRldpUY6p5hkxAn26m3vs9ILFjr/wn8R1fXDohv2P94
-vsbzCwKCAQAkXsu9gkvhFSeXNyCJvPmA78PBCvsu5AgOVPQbPqoaf25sL5Jdhsxz
-sU3pJxdDm94RN1rnhpsbhenngedLaYq7drDNoY5QTqQOomr+6JlEZD1CDWFmZpTa
-TeamRRmYEI7T5YcMoc+vYqpvu70YbGtRNxoVge6ye82oUyDm2CL/2jA1reUr67pg
-EB2nNGH47r38m4ZJ3WbJJX0oyQEOO3/ogWBSSvayKpWQ+47gYOzdVyZkASPnTPmU
-3hk0epLDvhD7xqL8hxfXXFBChl+DUkVBtufgRZ+vqRIKegOYIVvRqSsi5MU/F0vr
-2bRptxi2wJD+EIgU9Zb1A6e8UMq5aXWBAoIBAQDS8w0TG4R8SLHXOs9JagC53zAx
-qVV8mrL9BEYzeuM6vNpyZIO75O94q2ifGvzsISxLf2xom99BxpcWo9UAyHFgubL3
-+P0spdJSeP0OWJgldEqwWGMrzQbYZomzi/QUlFpXNZfHgHZLaCK7qKu9RDQLVtug
-5i+yVjSKl6RcaCCG9E2u68yxKlI246RNK1HZXQgxsnz6BnP/cqAn9G+yzT9p6nmK
-tt2d2s35MS1zV9YzACi2idsZBeio7bghC1maj/TJvq9gRwIRN4UpbPRsflpdejFY
-nEEW+tEbNzFrepkw08+9dRGnPU1G1NYvyQqMhc98lVBiMoDiH8X18gVWafhR
------END RSA PRIVATE KEY-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.pk8 b/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.pk8
deleted file mode 100644
index 37948c1a..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.pk8 and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.x509.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.x509.pem
deleted file mode 100644
index d41d86c7..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/com.android.apex.test.baz.x509.pem
+++ /dev/null
@@ -1,34 +0,0 @@
------BEGIN CERTIFICATE-----
-MIIF1zCCA78CFAgqiNJewYXPYz+41LOIDLe9lXnzMA0GCSqGSIb3DQEBCwUAMIGm
-MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91
-bnRhaW4gVmlldzEQMA4GA1UECgwHQW5kcm9pZDEQMA4GA1UECwwHQW5kcm9pZDEi
-MCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTEiMCAGA1UEAwwZY29t
-LmFuZHJvaWQuYXBleC50ZXN0LmJhejAgFw0yMDExMTAwOTIzNTJaGA80NzU4MTAw
-NzA5MjM1MlowgaYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYw
-FAYDVQQHDA1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKDAdBbmRyb2lkMRAwDgYDVQQL
-DAdBbmRyb2lkMSIwIAYJKoZIhvcNAQkBFhNhbmRyb2lkQGFuZHJvaWQuY29tMSIw
-IAYDVQQDDBljb20uYW5kcm9pZC5hcGV4LnRlc3QuYmF6MIICIjANBgkqhkiG9w0B
-AQEFAAOCAg8AMIICCgKCAgEAtm4cczWBEzR+kzRPHsBh61ihAQNtWN2mKLhZZKRS
-YrNZ59+M53menjsc1Bs5fYvKTMGj2u2a/yvq0QiSAlgVMY+1aZ40FN22tBTmy4yr
-6iTMi9Q+uUbQJlHLWSy8n3oFuxEHAP96ZPDJyqPHSJpKeSPKIgwyw3I+nXb/fmB4
-HvBmjHbFnwvKqHFyoEm5p/wGZn2vMtxZqlignNtUZr2zYTJW9YCuL80L/o1jdAFk
-5sHH1tBEcp1ZTXRgKm2XFfp7fqfOWkS9XL3VUF0LVWMgyv0u2fr7n8TPZb8iz5PA
-naCUN9hCoPrj4vg29eVYy2IoeSrLOAUiK986mZDToKbhxuLSHVV+IRNnqIQV0+mu
-rR8OCqDlWbD+fU29cacAjGFt72unLAIEE49GHZFS2pTZ0cDXX1bBUrBVTMlcnCjn
-YiU7XtPaJGelBkJEu/ErjHE9TrsQGKkzMwd2ySTOsk3K4OtWl+E9i50TW8Vu7gR+
-Qr4lZvY90OmXw+k02pkCo5g1GU8uXoTPjd0JQsmiEk01dMIPyWxXBYiuiRUxu3mc
-vYJJGKZSMX3VKKYmtFN9lTuf/OyjztHjRQPit9sWVcYgKuy0kw1LQSJxtyNQIeFm
-ipZVzh8Wo2TMm8argWMPHxyIfjEiVbNhXirC4My0Z02agyyB4Edxg2jkiKQBss3y
-/IECAwEAATANBgkqhkiG9w0BAQsFAAOCAgEArOMz9Hn03yy2ano628v0wXMFixVA
-/XzSpb8GWi4GzJxV96c9t6QQPVdo/XS0uBuEa2Uc0/W5icU9+iKzBvQHM3MI1jI6
-/oj8/mGAzvyvIA0pdKP1XOvugsgi2UDNr5QNgZ1UPIpVkzeBQpLgTiWL70Pl/znE
-b7Q1nKEFeNWxBaMk6u6n6gNh6sMLv1doSCi0FM1cnWHv/0qxPizGjTHKmGs4TbMZ
-zWnBoH8XSMxruAEbucl1E7vYXgYthOW0I+SCFpyP53e9VdoNNYWMeNKCm3EoIY86
-XWLArBBQcCCrsLas45670ouQ/H9Yn498MwFinuWcsfROghXQwhn7fPaDQ2oVlftj
-4LQS2vD20mJV15wa/1n/VDzRAxIZwPdtbJX6JZO8E7Oc0+WSehwhaU+x7k9GYyBv
-tiEGS297qZC0/WvoE3VtRHZjOzphxt6PLelCEoqhdZy+q0uGxj8TmPRXo9xtmBLH
-6GPgZe3dR2SJ4uMqBjt6/6/Rki3du3btAn2O4b0Zf6h3wftqK6INbsJ7fRpIgLaU
-GvCZiCUZaxkNcCO94RnZJrTTVO1rJ1ZBkcqyMHvrSRhPCAyH2zVtHcNDCiR06GNA
-+7P5SuyntvmnZKteKc2HdTnm42ewIXyDIwTs1crc8/luevw81s+SJqWumSGTxpfU
-IAM423xlNZfBXZA=
------END CERTIFICATE-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/manifest.json b/tests/testdata/sharedlibs/build/com.android.apex.test.baz/manifest.json
deleted file mode 100644
index 1c57f3af..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.baz/manifest.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-  "name": "com.android.apex.test.baz",
-  "version": 1
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.foo/Android.bp
deleted file mode 100644
index 368bee8c..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/Android.bp
+++ /dev/null
@@ -1,79 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-apex_key {
-    name: "com.android.apex.test.foo.key",
-    public_key: "com.android.apex.test.foo.avbpubkey",
-    private_key: "com.android.apex.test.foo.pem",
-}
-
-android_app_certificate {
-    name: "com.android.apex.test.foo.certificate",
-    certificate: "com.android.apex.test.foo",
-}
-
-apex {
-    name: "com.android.apex.test.foo",
-    manifest: "manifest.json",
-    file_contexts: ":apex.test-file_contexts",
-    key: "com.android.apex.test.foo.key",
-    installable: false,
-    binaries: ["foo_test"],
-    dist: {
-        targets: ["sharedlibs_test"],
-    },
-    updatable: false,
-    // This test apex is used by shared_libs_repack, which works with only ext4.
-    payload_fs_type: "ext4",
-}
-
-cc_binary {
-    name: "foo_test",
-    srcs: ["foo_test.cc"],
-    shared_libs: [
-        "libsharedlibtest",
-    ],
-    apex_available: ["com.android.apex.test.foo"],
-}
-
-java_genrule {
-    name: "com.android.apex.test.foo_stripped",
-    out: ["com.android.apex.test.foo_stripped.apex"],
-    defaults: ["apexer_test_host_tools_list"],
-    dist: {
-        targets: ["sharedlibs_test"],
-    },
-    srcs: [
-        ":com.android.apex.test.foo",
-        "com.android.apex.test.foo.avbpubkey",
-        "com.android.apex.test.foo.pem",
-        "com.android.apex.test.foo.pk8",
-        "com.android.apex.test.foo.x509.pem",
-    ],
-    tools: [
-        "shared_libs_repack",
-    ],
-    cmd: "$(location shared_libs_repack) " +
-        " --mode strip" +
-        " --key $(location com.android.apex.test.foo.pem)" +
-        " --input $(location :com.android.apex.test.foo)" +
-        " --output $(genDir)/com.android.apex.test.foo_stripped.apex" +
-        " --pk8key $(location com.android.apex.test.foo.pk8)" +
-        " --pubkey $(location com.android.apex.test.foo.avbpubkey)" +
-        " --x509key $(location com.android.apex.test.foo.x509.pem)" +
-        " --tmpdir $(genDir)",
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.avbpubkey b/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.avbpubkey
deleted file mode 100644
index 575ba511..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.avbpubkey and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.pem
deleted file mode 100644
index 1d651b58..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.pem
+++ /dev/null
@@ -1,51 +0,0 @@
------BEGIN RSA PRIVATE KEY-----
-MIIJKAIBAAKCAgEAz2ykMX5GHx1z+1BpFcNwnZv/8AladKxjG962kBuZrxSpu3pb
-8JKTqajY1TNmM7Hs0P8RjDY0M2ryNWodNu7GZKSOz7L+LztHeJFuZByCHjh4em79
-sYivhJKqlX0EVCnxW+IPQPQqxJKDoFBGWo/HfbhXiZJR5OT/XrNhl9KfpFL1NHfU
-dmZHIqFJHCrcQ4jQNxAh9XIvw0bwEwWe/q3Hdxs7UC4mH4m0Hz3cmKe73H0al3FW
-2L3xgy5vmc93SgzO0Csrmcrsp84B3qtNd6B0Xna52AEmBMuhWMRiFlIpV/Pf9utS
-PYoxU3IRjUJ0FacMbhgQOZdtXZGW+G3FLnH2XHX9rUNnrlMmgTmoCGH/JD4ZwXvF
-KoEUZ8wlGVZksNz8i79yPMxR/QyEppf56YSD72FrfCBMVdBDi0vYk7/nhqJU97ws
-VFwhFDTxp0//rca8UOnn0pP9HKylxT6sff/w2U+zzzn1MLsu/Tx6JEbDj+464RnK
-zxBL0wyzUUkwOodgctW8UFPSrttbQD5+7G+kQUl3q1854bX1EdW5jGF3l/OxE9P6
-mbsZlHPOjd4nFOtju7cgKpDbFtVwyDZRBtoPBIbBqS9bf7Y3oaesVeFkDfeC5SkC
-bUIDlri8Sysuse9uoNtaGzvYu5Wnuv3FE1V4X9Ak92S8VyUT2a2miW6Hj9sCAwEA
-AQKCAgAefqdpC1p9ypO5l+nLJE+TLFMlVAqzaoCroUOPzi76+Xu2r1eC99mzsLoo
-JgVZhkf9tfI7feCQyqFPTwl6gQIz26mPSY5rHTj1tdPX7gUHMmAsB9NOXX0IbZOc
-pKOVSBFO495AO2VqPuwRDpw5Rjga+JYOCK/3id8tagvoCTQlMXkRPKjEu2ar5bBc
-7sQxPZT28206q43wFKbI9SOZ56ySizNeJ1q9ej479ZlP7CEHWnElYKlW9h3inloT
-79dm0Jk7K42eb6H5TaUiumaKNtHE7YmHAyw2ukU/SqftBilD3/vGTnRpzb5QuU1x
-ShrM8CE4slr4TJXskrHyVhkOKf0A+RNKcZ6YICrEK1GGOTItNMcAGbHSTQBqVr5I
-MApXfiEQfZetgSv0e9s+DGecB016QG/uJis6OyABV0hYBcnrNPNgpUhmDfy+IN6A
-dpdjeSD/7iOXTEnCe9jrY5+0ot4rKZbl00GoZpb+3pYoBcpDiIVJvPxrWUZeC6lc
-aZjgmjkg2IDXE7swevsStLqSRY3cusMTnRS1Ay37/gobE+f2rJZArY4GAobckT3R
-im6q8cfzTH46wAZBuO6wHlmNfbDVZlvXx6zFhkqpefxRQ1V6Fa9LvkICcGmuhn1O
-9p3DBphflcbHtMGwJpmmr0A3T/aakw2aMT9Qzda91SItlqxy+QKCAQEA8pE4vt3R
-a9PEABO3rF5oWT8UaHfGBTDhoZnG1KDofDvoKrw2R09mz5nhROIDnVaQMtkWChhi
-YhChOHZANp1K2xaCXqDRzbFVq1e/HB9Ag6mTZkT5R9Z088/vOWRIA9H3rk74GB+y
-9iaCusk8NiIqlubvc7XaoTO4ChQ9X+p9QDAmvZVaDfsJGSXYvqfVfMy179mIlzCN
-DSTePQsn1qEiPKltRNBysuluDJqa/PhcsGd7Oeo8SJuLFVOHk9rTuemvIbkxI8v8
-PZ6LD4ORCDsEKst5giqvVBl3yZ2ntuLlouxQGAg0F+VGxSvDYz81zwUHUmsSXDFo
-gw22tWGCQpeFvQKCAQEA2uk2jzEnMvhklfh+3mAUNpPRUyAC7KHIB0vSgvkRTK1w
-aqWF5jCx0onz9sW7lGYcM6RRXBJNi7z8NxouY2Bdw7ijGd7ZuL2ybpbsIetfMV16
-xGZCEL1JEHOnglEochGzspwKmADqWpV/suXKcOlrAZeH1y28TNOgaprTG8zr02DJ
-CQrV8uJnE3HArEHtQdtjsPv/OhDEjEA3Gl2k3hRuhsf0rfeMby0QvvqyVb0Y4SEM
-iIq8MP/dZPgNrDi4r3s0aps10ciAHyHtyuLv2PRkc5ddsBh5V2uEc+S0TTFRRW5N
-uuM6E7uiuCbNrdd/1dfl55ojIYgI4TgR6lH5kmPJdwKCAQBPAK9rstE/fkRLBiD/
-WexAjQP3lnL/Q9FpEa2pmRK/S7+tE4nWJe1FVkgBaF9nAkeK2BuOhCye5e2sdw8o
-+ofj3WvuqBBNHyHY4YZUAXXArB1e5L4QALAsrJ+soJW38M3rjrrNGJ3v/9D6Rwp+
-Uxht958rn6IqeK7LUZY/xB6xJj2n55niDc4Dy8jRJ9anhAEJsl8DZwO5sTVUympa
-RDbjbQcyr3V8Af0ey8gI9lcx+TIwRbMGrupYstDofhARcCPjJu7zSr/HzfhawC4f
-cSFFUuorU/2wtW7HUrrKHRJPwwm/GgTld35aP4uuqmq7F1cwJ8FeF5WDgZbtcmm7
-iKA9AoIBAHaOWSsBns4e8jK6atM6S5gnQ/V137+R+ofhC3g9NZ5GTByl2jeJZbS1
-W7fo7Kb5Cgr50cpAa1jjl+CrwDW3yfAmvcZUB6viqJD2EZppI5vTmZpmGx9/s+NC
-D5UnKPVmGuD/W0lpLYKzdn5HrvSppXcuPrZNoa4l6rnxcaWbvJg00YuhH6+z58kD
-ESr5ZWoGTB5cy6QB0sB2QqF318MiY52BC0VwTNElIe2cThrbF29Ne8EzCaqr15ZI
-NPdxnKwE2KVnu6UKpkC2GleHwgfIi+KCNo4ZIxYyN4CgevlXXUFx9IzjZN+s/fon
-obqlfCkvDOb6dk5BozV+LU2u6a/bdQ8CggEBAK/n4ELmvMRbkB4lr9BEN5GyWwvq
-Zkd3e1EcefMpR/dXv+2YD95BlUa2kOhvGVNb2TtnTGcodtYgmWgkSCNwYGO15YX+
-f1OdqWJdJs/FEgMWyAElLHcrwFUJIDuBBLCZrYYKSgNoUM/Ddk/CaAGWT4lsq1U7
-X+GC8SVGkxyqV4GzI4uQ9/vxgbxP9zIbHQqa4BUUM4kzaWxTtJuaF+fHsafgTsDb
-BDmOR/vVAhbM02Bw6xCqWNB337dIC2LJNmvmbTz/4lxe9mZIvN56UzcXAHSB8Xkj
-fbn4ipVY7l/NC4LBLzRvEItTdNr7zAC4QpsU2/upw5PPhv5R4Q2FKV96zM8=
------END RSA PRIVATE KEY-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.pk8 b/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.pk8
deleted file mode 100644
index fa38e322..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.pk8 and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.x509.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.x509.pem
deleted file mode 100644
index 145a6560..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/com.android.apex.test.foo.x509.pem
+++ /dev/null
@@ -1,34 +0,0 @@
------BEGIN CERTIFICATE-----
-MIIF1zCCA78CFGuWfjBtDvTQFqx0afFbqDDoozbTMA0GCSqGSIb3DQEBCwUAMIGm
-MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91
-bnRhaW4gVmlldzEQMA4GA1UECgwHQW5kcm9pZDEQMA4GA1UECwwHQW5kcm9pZDEi
-MCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTEiMCAGA1UEAwwZY29t
-LmFuZHJvaWQuYXBleC50ZXN0LmZvbzAgFw0yMDEwMDUxNDU2NTJaGA80NzU4MDkw
-MTE0NTY1MlowgaYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYw
-FAYDVQQHDA1Nb3VudGFpbiBWaWV3MRAwDgYDVQQKDAdBbmRyb2lkMRAwDgYDVQQL
-DAdBbmRyb2lkMSIwIAYJKoZIhvcNAQkBFhNhbmRyb2lkQGFuZHJvaWQuY29tMSIw
-IAYDVQQDDBljb20uYW5kcm9pZC5hcGV4LnRlc3QuZm9vMIICIjANBgkqhkiG9w0B
-AQEFAAOCAg8AMIICCgKCAgEAuB+RzoO8K96g3xYQng3cToQGYfCFVA47S3qUBlpj
-Qr4IIw/R/Mo/0/LoK3OMBbjrpwYm0mBRrBttoX0jqlANDOrsk0T6jrWsIiz0iDar
-5PEJjZpnfQILN76shJ/YgW4GQdLvjrZMtksBxKXLbID1uxBBD7KZzIpb7euiV06w
-gaNJZyZg+2J0Isj8qI4H34x2GtjQxd2rN8KTLYOgatekkQCauHH/LLCxVA0K62v5
-+NPmrhBTQNO8TSMLmqci13jYcvs9Oj2qkwQKD9i4SMn1VoHrswjulXMibWEyu5xB
-72vjwd9+xpLDcLxHDCQW8uFS7z/omhIE/DTC4QnmGmfz3gyi8O3sekLAdrP5YMz6
-+GrrNN8dwKr470g02oMtdpvTIC+4CcIMUuNBPvzsLUnCAxYTWo2QM8hcHx7Bs3XA
-gRaeC2pEIcz9oWoTr/G/5ipdmLSDUVtBQAiNa3KouY9OAO7RtqmweLiXaBfPQSBM
-lBWnyNhfEnhp++4Ef3LFDRpFfyo12XUysdmdreVjlZJ8MykJD5AU0EZ3gQbjcmWX
-vnIWJTc3045dMCDn/1pOss8//q8doIhwVoTCRK0UAofZEajbtfDQTtggWyjMTPtR
-pDtAJA1kmBLnCpjcrnj995pkz6rbMU76zDE7SzoVHE0zRnjDIiLCvNNScJ6oxY/R
-/wcCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAp5kVSkIcuFWMl2X7yTyC3AuOfsOS
-nqnEGs5ns1ij1SjSsogwt4apnjfgXdc3sye2eX3s1SWnxkIBwBQVOIrvSWgN1Wda
-9UQ5uKcrbiz2yT1QMBD1VYsv/zzRPWNP7rzcR7szfaNQOje3BoCaQOkWutgDKi3O
-kN8mz7VtfQniKvw/bbrSQMyVkQpy40XQTyJckfizomTVXlI79AoOVayER/Osgjp9
-8qwjtKVp/o3f3Nd5g2yS9GwsGBbXST0KhSB7bmsLHxPGyF1Zw8i6kKMuS9PX0E8r
-lBGGMZceKDp0eGDXeEUdVIn7labsS2UpMKRuDurpsvol8s3lVBFhAD8yT3yLRNhM
-c573H1ttrE/tlDOj6pdE/uz24WG+M11iKNuqW+/XnUiUjZpK+2Bt6ev4Yg9cDknn
-ih9dr+/YEvCopBCgwaURhTOxDKNNDQCQbu10NnT+apnomWVgWIAmu9SJRE0dFHj/
-46TIUnmmnjg1tTq90yJYoZyXLib6r9PUIXtUEGtBbbjg0axhUqP1jr6FKYnnK3TP
-NkxrkUVDUuI76qDhPIfqECymJz8fx97AJcPGT4qwOJKcCgft86RHOJIFr1AGVGSw
-b+Vw2IWKNwyAqixjN/hhmNH2nlUdhuPPDk1GuTwlODuAvC/GTfOms7yacSeEO0wk
-Sw6cwZWCm3nMiiE=
------END CERTIFICATE-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/foo_test.cc b/tests/testdata/sharedlibs/build/com.android.apex.test.foo/foo_test.cc
deleted file mode 100644
index 34d44d4f..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/foo_test.cc
+++ /dev/null
@@ -1,13 +0,0 @@
-#include <iostream>
-#include <string>
-
-#include "sharedlibstest.h"
-
-// This parameter gets modified by the build_artifacts.sh script.
-#define FINGERPRINT "VERSION_XXX"
-
-int main() {
-  std::cout << "FOO_" << FINGERPRINT << " "
-            << sharedlibstest::getSharedLibsTestFingerprint();
-  return 0;
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/manifest.json b/tests/testdata/sharedlibs/build/com.android.apex.test.foo/manifest.json
deleted file mode 100644
index c986f711..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.foo/manifest.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-  "name": "com.android.apex.test.foo",
-  "version": 1
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.pony/Android.bp
deleted file mode 100644
index f20aee33..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/Android.bp
+++ /dev/null
@@ -1,79 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-apex_key {
-    name: "com.android.apex.test.pony.key",
-    public_key: "com.android.apex.test.pony.avbpubkey",
-    private_key: "com.android.apex.test.pony.pem",
-}
-
-android_app_certificate {
-    name: "com.android.apex.test.pony.certificate",
-    certificate: "com.android.apex.test.pony",
-}
-
-apex {
-    name: "com.android.apex.test.pony",
-    manifest: "manifest.json",
-    file_contexts: ":apex.test-file_contexts",
-    key: "com.android.apex.test.pony.key",
-    installable: false,
-    binaries: ["pony_test"],
-    dist: {
-        targets: ["sharedlibs_test"],
-    },
-    updatable: false,
-    // This test apex is used by shared_libs_repack, which works with only ext4.
-    payload_fs_type: "ext4",
-}
-
-cc_binary {
-    name: "pony_test",
-    srcs: ["pony_test.cc"],
-    shared_libs: [
-        "libsharedlibtest",
-    ],
-    apex_available: ["com.android.apex.test.pony"],
-}
-
-java_genrule {
-    name: "com.android.apex.test.pony_stripped",
-    out: ["com.android.apex.test.pony_stripped.apex"],
-    defaults: ["apexer_test_host_tools_list"],
-    dist: {
-        targets: ["sharedlibs_test"],
-    },
-    srcs: [
-        ":com.android.apex.test.pony",
-        "com.android.apex.test.pony.avbpubkey",
-        "com.android.apex.test.pony.pem",
-        "com.android.apex.test.pony.pk8",
-        "com.android.apex.test.pony.x509.pem",
-    ],
-    tools: [
-        "shared_libs_repack",
-    ],
-    cmd: "$(location shared_libs_repack) " +
-        " --mode strip" +
-        " --key $(location com.android.apex.test.pony.pem)" +
-        " --input $(location :com.android.apex.test.pony)" +
-        " --output $(genDir)/com.android.apex.test.pony_stripped.apex" +
-        " --pk8key $(location com.android.apex.test.pony.pk8)" +
-        " --pubkey $(location com.android.apex.test.pony.avbpubkey)" +
-        " --x509key $(location com.android.apex.test.pony.x509.pem)" +
-        " --tmpdir $(genDir)",
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.avbpubkey b/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.avbpubkey
deleted file mode 100644
index f7af6e90..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.avbpubkey and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.pem
deleted file mode 100644
index c0e2965d..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.pem
+++ /dev/null
@@ -1,51 +0,0 @@
------BEGIN RSA PRIVATE KEY-----
-MIIJKQIBAAKCAgEAu5za6xUAaREb/RXJGh0QOi+tPLjtmDkYL3COBcZ6dTsBYZuE
-TkBwNgsvfk713Ddk6iOirjcakRLdj1K9lJdyBHMocNz8TjizO/3uRhLA34Fgog6Y
-h0xwpDfb5gPyb18OvCVFuRLIremGa68zPnXl+p0kxzqafKICGjAp3x3ugNcSMXlN
-0nKm4MSDiqZbTlAYutW+jTFr+e2VABbbCY6ijgQJMFDHNkA4QgW2rwEK63OaTImT
-OKT44JnQ5VJpl8VN7HRaAyg5MUjVfuo/HSIkFpYZ5rxgWOZioqvJw+lFV6/TSrxk
-P2JWQuu9mBDmuAoaEHE/yyLPLDKtQUquc6IwGBFG2/dn1WKoTB1X0TsCaIwTBGVV
-n23foz/+uE2FJuh0mNaGWMHN4cOekbYhti1xIvOnHFlOIWdpmRRkIvUwjZYVkCu9
-UnPDHmhbA+3cr8scqc66JTESc1A/uoIGBtK10aY5jUyg4Tvdjc+PlwapeIAseYzK
-x4eW1ujaTP+DEMBaamQLOwhvewxXubTyhjIN4epQma11pVfLwfuM7GAGqlyzTMXE
-BQLkm17TIPEkb+wpU9zP4Xn5FshE8mb6k71fVXwWeBaHtF+tx4Ml5Jv2XUe23EDJ
-5pnIB0sXyJcEjDlqbNCzfZn/LMJQHSd5h+wfwLoeL3U5TigpFSQp9MypSX0CAwEA
-AQKCAgB7LdhaYrabRT2AJI6eE5j06xqt9KkiudHUS+0jg5YhZDVa9bWffxVtllh/
-cK5iAQjD5dPI2Ksbtyw7DtMkPW8B1u4ldCI/5WBgsi+AWI3D8XkVzcl9g8WtPHOn
-iM3jK6FMDJjDk76o2NuF1kkp6FSv//8Gw8ZssB37PcYwFMHkW9E5JHDhDJ/ekYfg
-P6tRNquV+AKdR2aieMfMgDUeCEVYQvQZgd/aEb4eMwwnyOJ3hrY3LFi55y70oGkU
-N9DWchfgeOAklINAhZaPNpNruF/DaJfm86W6mMEIFwxpEb6SfQGYXyrept0GISuh
-LO+exBsq0oBVCizF0xwH81Wo3EMAWnjAGMNxzKOdtJhP0VCL5asgMb6/QbKecko3
-2kZNAeW0aC8wFajCOarQQ5JgMcPdC2gGqjUakqHj+1QlbvG/KI1Xav0ET/OIFOuY
-RAneqIaWVkU76tldm3mnp6b4vS6lsT/v/56sHtCUWGDmVF8zNkZ94LF6XcbEt6ZJ
-p0Ssq0e35Z60ikAPuxNXNA0kgJBpq/V6j0Iqf9otGuEFLCy9AEtCKSYHVQvwRmMC
-wLGr0L47p7RSKyMqWwJFZmMPfbAUz+IlYtxqzQ316L2NSCRnTHPV+thh9W/HIXvu
-pciYkbjk2m4cpjiYEZRS6wLadfPGqMosNJX42G1INM2wEzfeQQKCAQEA35iBH9P+
-hWGYl1rmZBQfv2uYJPo6TDyM7kOrIctmPek8XPWNI9jnayE0Mmpf/eA1sTZpOzg2
-hVVc2QK8Baqxaq6JwNz/WVIvvD8kuCnsBLVYfAxEXgS5aF6NYbSg2oZf0CaMAFtM
-xf0SIyhol9Xl9d48CrmumNZnkvpa7AzOvb9PRn8TXFJFkmkyDmDWvQVaBZbbkKMC
-Ak3UA2nB8ypXfujLc2aBAeoSSw2d/EdoZW4TI/v5sFI+FM9Eg8KG3MP7rhaemptl
-6DNh5PpFYl6smqE87Cb+0jmR3ek9jkjxXJxE4VrkBrDT4BYogb4TnNP7wdux5GJ7
-NqBAGQ8Mjj4ezQKCAQEA1s1dt/VxbOBPCRWlmIlWnmiY4pf3dkl1HOClNOwtviG7
-gCRmeIwtt4O2uwZOMd/JyYLBg4yieT8cCDbXSPXVop765bftBz/Ce5xU9sadLzI5
-sUdHRJkBtHsC12vXZrlrcnVauKAoArDcz5AgndqZ6i7lw5wsB2fQhITGJ1fYMW0L
-RRugKU+wuAgur5GOoTPmryrf8WAbKYh9eeyoBHvK2u8JxsiUXUuJIPvOPjArmHLe
-fxsoN8G3o4Rud9ugPEjsfT3RU8oA+9+LUMVbNl6q8RF9qherxKqmXwukh4C4iuVn
-MyJ3FBAq4Z4BSbyirl4APC4Q41z//ZTYrAuFx9J1cQKCAQBY99ihLnw+3GeYCe5U
-cgFz7D78r6hUv18gS0Kjzsge6FhBcN85HUxvvyWCzfrmDLmwisLyclqXUTEBlGn2
-I0Y2+b4MRKNCCka+M63Lrbqg4PuVWFg3xM91bPH6p6G9cexb6YqZdbqlqR33aVO8
-3rqCy2u+pMWJQP6zZ/SXqjz1GVNU7Klqeb3/FOZ6/CNV0PRR9wXklkftXMR4mzM2
-K2nnMIALqgS5G0cuH/v17v/mJBdvoQpoE0FqjFJpzxRUcZMKYSu4vw6chx1zu/Wx
-v5QUbwXLvXR1d7zHvM/mdrW7MN7jgIPs+Z1Es+xoO5aYN20cZOtywZDfWoJGtks7
-qhIdAoIBAQCqntwXmH2tRwtgovIzlLvZ/imaq61kJvtAoex4ejXndfHy2ncOwAI8
-aAJI0rxf/2vQhe1iqd4QwyFoIO+mw6cbkn6m5A8CGBJKj6YpkyAd8h5Dg+PHSGZD
-Twa1yLKDpTsE4tTaHFVLteLfeJN/77kcfH4Df9S1WTAXY0Pm0m8m63/tOAFjbypn
-NBCpYsxRneFaOItDttw8hG9u3p2jWhWLDB7O6Fp5NNvK+FkdqrOmV3AGtLKgf154
-I2SADlNcL2yyGt1gWe+oIiwOT4WhTVcpP4R7DGxjPk4C50OcYpGzun7b7j96D1GQ
-fyp0wMLUEFTNeKXvg9rPOWFWX5y3WaPxAoIBAQCiWoixjIhHK0f2yMvcYAzqb3A3
-AZs8IjU7phUxAa8LB4R2V5NOYsUl8xIZqZgoPjyJvlI0S82IjEuLqnsmh8GgtJxa
-vOL8JLUX27kr/eOTkz6EnzYVtViFM+D2re7QvakGSh+D43sC29S+dUSMrB6XvFdP
-pBbD6paLmefvgRyP8kxMTujsqVS9TSAqZLirxGSC28wgrRx9CRTy93MxUfw9spCO
-V4/TO384iLZBlj6bDJc4g7YL1KYvZ6ZCCLWoq2TXyBHAOjfThttOoGFj1B4KqdZP
-rO7xAyJCS3t++Nm1AWqmnA7wmNEhMruEZchqGOP7A5f/xcxdsjY0m5LTth50
------END RSA PRIVATE KEY-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.pk8 b/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.pk8
deleted file mode 100644
index 104a5830..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.pk8 and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.x509.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.x509.pem
deleted file mode 100644
index 2f96a293..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/com.android.apex.test.pony.x509.pem
+++ /dev/null
@@ -1,34 +0,0 @@
------BEGIN CERTIFICATE-----
-MIIF2TCCA8ECFBuIrFu5kQxwNJM09/WyY4JaskQLMA0GCSqGSIb3DQEBCwUAMIGn
-MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91
-bnRhaW4gVmlldzEQMA4GA1UECgwHQW5kcm9pZDEQMA4GA1UECwwHQW5kcm9pZDEi
-MCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTEjMCEGA1UEAwwaY29t
-LmFuZHJvaWQuYXBleC50ZXN0LnBvbnkwIBcNMjAxMTI3MTA1MTI1WhgPNDc1ODEw
-MjQxMDUxMjVaMIGnMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEW
-MBQGA1UEBwwNTW91bnRhaW4gVmlldzEQMA4GA1UECgwHQW5kcm9pZDEQMA4GA1UE
-CwwHQW5kcm9pZDEiMCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTEj
-MCEGA1UEAwwaY29tLmFuZHJvaWQuYXBleC50ZXN0LnBvbnkwggIiMA0GCSqGSIb3
-DQEBAQUAA4ICDwAwggIKAoICAQCrNP9VtH73dqoDIKN9GQ/XTizM2y79KgiUah8J
-4w2FLn3Q/TKxH/NRJVhunAbNLbu8bqfOhETFFWWr8FD2CNq7j5ZSN/xZHHgo40F+
-U1+SisPErTVa9oma4fn62qrzwOZ/uDqwCwzv2Qx7SAYE52M4JAwMI16sV7KZGXBI
-3MZApfRWcuk9FcH0SPCQReY+P4nRqpNqSdsDw0u6BFnPmc2oymkUy7VV7KLjpNo1
-si5M43U3QyLhx6abVdeeIdcC1ycNYEyYKWigBqWOWHIxj2FWUA/vF1OLJm6AR5Z/
-VYh9/7EPvPW+QsMwaM/YRgoCXAnbWA1T7XDJx6aksy6CHt53FjufNwqKC9npthYl
-rdy7rv8XBfrp6/ZXzRhsEWXMHliGrDQF0vyHPgs9CsfdPQtR3H+7tV5nXfa4vj2S
-WbkmZyOyDLTQku7luh2dDcn4Jw9yOoAc2cD7ql6H/Hd4MKrPX/SKahpK7ypZebgY
-RRovxgwxrgFkP9J8/xW1GCY767a9E/sjVaFdQb1rAUWkNG2NBUDtFKdu7mg1KFyE
-c1dTY4cpLiahWLyD845bLnunWaYqutRm3ufu10lBstqF1RkBHcqvoxfoa2IeNB23
-MPqKGaovQuFj+cRHsetC5W3VmROcvAvIJzhcvy3CK5JhvXdvGTkFaoA+6hifY2WU
-Chli5wIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCKEncgnGCwsHkC9UGg/HDwU97Q
-ZH2kqNXdFRYURp8BmQbtNYuYSs9CYDpGugOjW7RILmr954KO+KNCo1OX6c4RWwQ0
-5LAh5+/FmBHiTJlWHRFGhL9WR8Mn1iwEsrANMyhoeoLwlKDVORM2/rS7APBM1pQl
-gQfQHLt0cWoFpoL+pHElyuoVVKGB8sf06atcB/U8HND/xSY8fa7YjBOPYIMoUEvQ
-aeN4JbxYNStqGDEz7+FoguXudQAvq8JFECsFwjWZd0/I5AjqcHiAG9ZaOrUiVRl2
-MdZSf2fjeSHXV3TH7i9f5vmcPUNERZxo/dutOTTVxlS42qrUaVwuSJzDG/MfXZWB
-A6IB3P2qe5lzGl8mmvGKbX3ZXakf0OJaGb/Wn7GpsTynS3P6Zqa02oz89kquERey
-PoHrR3tzNbUbDnjc/px2h2esG7E7E4bRc1PE6ndpvhs2vKypTpYO2v0cXWSk+xiR
-eUZGPIXS7yMHSu4yHxoWUnWoEfzhKJ87gpk87wkSieL73zC/uMkjjyksmngN59VU
-ODkUALrflWdHHynYiaA09zsDCjDuWDBXl17DNPV9lb4L0wLjJSklhuGsHo+wtW9k
-HJx+H972Qk79C4/ZuNiRx83xt8hruqlky2wkZKB9cxYTiizoD9CXwpBl+KGo5oFX
-ZjsDT4tnAHMa69yUoA==
------END CERTIFICATE-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/manifest.json b/tests/testdata/sharedlibs/build/com.android.apex.test.pony/manifest.json
deleted file mode 100644
index d1b5a60d..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/manifest.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-  "name": "com.android.apex.test.pony",
-  "version": 1
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/pony_test.cc b/tests/testdata/sharedlibs/build/com.android.apex.test.pony/pony_test.cc
deleted file mode 100644
index 761d2410..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.pony/pony_test.cc
+++ /dev/null
@@ -1,13 +0,0 @@
-#include <iostream>
-#include <string>
-
-#include "sharedlibstest.h"
-
-// This parameter gets modified by the build_artifacts.sh script.
-#define FINGERPRINT "VERSION_XXX"
-
-int main() {
-  std::cout << "PONY_" << FINGERPRINT << " "
-            << sharedlibstest::getSharedLibsTestFingerprint();
-  return 0;
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/Android.bp
deleted file mode 100644
index 183cbeb3..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/Android.bp
+++ /dev/null
@@ -1,76 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-apex_key {
-    name: "com.android.apex.test.sharedlibs.key",
-    public_key: "com.android.apex.test.sharedlibs.avbpubkey",
-    private_key: "com.android.apex.test.sharedlibs.pem",
-}
-
-android_app_certificate {
-    name: "com.android.apex.test.sharedlibs.certificate",
-    certificate: "com.android.apex.test.sharedlibs",
-}
-
-apex {
-    name: "com.android.apex.test.sharedlibs_stub",
-    manifest: "manifest.json",
-    file_contexts: ":apex.test-file_contexts",
-    key: "com.android.apex.test.sharedlibs.key",
-    installable: false,
-    // We want to force libc++.so to be available in this stub APEX, so put an empty binary.
-    binaries: ["noop"],
-    updatable: false,
-    compile_multilib: "both",
-    multilib: {
-        both: {
-            binaries: [
-                "noop",
-            ],
-        },
-    },
-    // This test apex is used by shared_libs_repack, which works with only ext4.
-    payload_fs_type: "ext4",
-}
-
-java_genrule {
-    name: "com.android.apex.test.sharedlibs_generated",
-    out: ["com.android.apex.test.sharedlibs_generated.apex"],
-    defaults: ["apexer_test_host_tools_list"],
-    dist: {
-        targets: ["sharedlibs_test"],
-    },
-    srcs: [
-        ":com.android.apex.test.sharedlibs_stub",
-        "com.android.apex.test.sharedlibs.avbpubkey",
-        "com.android.apex.test.sharedlibs.pem",
-        "com.android.apex.test.sharedlibs.pk8",
-        "com.android.apex.test.sharedlibs.x509.pem",
-    ],
-    tools: [
-        "shared_libs_repack",
-    ],
-    cmd: "$(location shared_libs_repack) " +
-        " --mode sharedlibs" +
-        " --key $(location com.android.apex.test.sharedlibs.pem)" +
-        " --input $(location :com.android.apex.test.sharedlibs_stub)" +
-        " --output $(genDir)/com.android.apex.test.sharedlibs_generated.apex" +
-        " --pk8key $(location com.android.apex.test.sharedlibs.pk8)" +
-        " --pubkey $(location com.android.apex.test.sharedlibs.avbpubkey)" +
-        " --x509key $(location com.android.apex.test.sharedlibs.x509.pem)" +
-        " --tmpdir $(genDir)",
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.avbpubkey b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.avbpubkey
deleted file mode 100644
index b9a268d9..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.avbpubkey and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.pem
deleted file mode 100644
index ce939dcc..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.pem
+++ /dev/null
@@ -1,51 +0,0 @@
------BEGIN RSA PRIVATE KEY-----
-MIIJKgIBAAKCAgEA2EG+ZcurX/nUUNhpbARwgQGgLTQkXU3yNYRk6t5WoXI6t3D2
-/bePE27RRzUhplvs5SZthRl3pgkzhZtajObm31VaUX5cXGveux1bQdtfTeMmEfPl
-TZ5bjM2aWV8QOpPQxUbL3tjCr2NB6sRX864nxl6RvFSgbVACBDVDBbdiHfq4UTGM
-oL0APyO9PCfPueFXwOJyW+gtMc50m+s46E/7Je0hmCfx5xlTjnue0CzF9oDPvat6
-72hX5JFOxefHPIVW2/IFnjzMsyCwjF4WyB2eZjmH3Mtx44Xn5hH/a+1wMvvcJmjx
-W4rexJVdDSr+RZTQC0Wr2eObk/6ib4gjXcjCr8cAdTB5g9IbKmGdOlHM3VavlkL9
-CMzNy+/w5UnqWrLJanC9nJba6PmwxG7n5doFODwB1ZypX3crrxjyT5saKN0KnSF3
-Ux3yt8SPnAr5QZ01ta4H26I65YwQi+Bqf/MOy+DgEDv3GEUTGLvK5YK2sDSWdIr4
-s3NRpkkUpAo/RZsqlxYCkYXtrdngP5r1ej0+uuzXt8cqXytcTqMpJzwDtNvlJiRG
-iqYzQZE+p3JrLgUTnT+clezOU4SbbaK17z+gLFoy9rs15ChF+VM0GFeuWh0pTOv8
-UfpsOZrI4Cwgr1q8oUGhcXwj6cgqdxzlrRFqb7no6L0rajk2dQLBoCFIV4ECAwEA
-AQKCAgAgHQMtEqWMRwkkSD6/b5lVTux+SfPsdxq0n8hsqD+tEc1uWDQVUSDJ/fbN
-4DHzBkuTa7VvwmxmF4+zE3LK4a7/EymqWF1WzB3zI1Td3rm0UzrgB5vRfuaRbiax
-htBeIn0qDm1P1lhyuwaa2jVFVmNJrdluYhLAqNTj0xT00FqdoRGl3PnJFMfomGIN
-gMv0CmaBmh7pTv0HHGVske2NcfMVmrUWZzgg3T3vNqRKvZtYE6DFxaUn0BLdOka8
-VMLdVd+kIbh72wN6xivxbDdt2BghjgGC5CMxaj0ZiSqo2EWFDKmQepz8vw59msCK
-qAvCQWrzgZEXdhkwTOvKLCk0UA+4zJoZ1hF3tZWStftqHB+zl1nsz3H8vBHzUaGJ
-1ufJqBZrmKqJvMEMlxoV+A8ftV/SZTmdXrEb/CNLGAfNdf8mhjc5hU58HLQPHQxA
-3IAj1Jyllc5hZHYXKAvu89ift0ZxZel8Nim+STmzpXiTvhia8+NEJlbOIp7JJf9L
-OOhj33PUiIR9e2iPOrhPOkV4o3HVW/Dpwu2P1DSqOIoGxB0zFE+eZGGf9HVNOyy9
-xUUGRpzdD8M09gnI3Yszabo2HjKdKYQdmoSc7jzMMwvQGd9Zt08KvpsWj8mry7l9
-VVy8h4rWlxmJtC8aXOHI5thV/4jmwfRYbDEzh4Qt2XxVQCyvUQKCAQEA9uviNj0Q
-FWtpeYULYMksz63JryaPeI3wAJtz6efYTcJ025qobTiHhoIER3TInsBBUQ3/YRYy
-ZBtCeKpLxYA81IabIX9lO757RMslEb5KeD3Da2HqNnrh3hyRXgXXcUMbed8JunlC
-5FRCRafikkj5ABvLHB9AYgAhS/vnTGQ7+XgpFsYi1kUGbJw+t4ly/ydWLjs5XoY7
-JdAuwnI/T8z31yYGG8T3oMSQV+BXT1doGNalKGupGMrUyvvqJQvScvxsVSWS8cRS
-A1Xu91R0oMYhwnUkMZc7qYEVdGqcXFagSbnXufT4J7Bw+H7wbY17fYOC3cGkh3AK
-FCa1d74Zd/3aswKCAQEA4DU7vukSOSDAf1hChkYXPzUJdrk31AVfeISYZmKqYah6
-65I2kzOnaszDQRg11wHXHSRhU0oVQxA77VTQBNQzOy+F7oB3o0cuQ+n6X5U8QQy4
-2dmgiYp3rkrqoH9KVn5VsYdwyYQHmE1IVMazo2YByv2N7aq4KN0MEgYUzizF38jX
-hf7ubQA7mGr9I0Wm1keQJ1m9VZ06mPKLfG70LViJAAvCYzSLY/31FBGVNq4JlreP
-EI4hgrYv7tzU6BqzrIdAmFOYOOsdRnUUW9+OhVzreU2EBAAmjK1jWa6FFAXGJEhi
-/qyO2suvNdWsIGxfqt5yhPMevMqjyEPmvwpLF+5u+wKCAQEAj9ShZVS2bLOvsdB0
-60DkMGkcBUGh6uhK+B+VKpgZYFo4Nb9mApEeKJTNp034mriEk5FixAvo+HUEiEMy
-de4YAPgTnzSVJHL1XQI0Kpy8xkO79G4JvwhfT0E20Bz4/QnJFHl+Mjf2ZghKvkZn
-7SxClvSZoFz35N4MhzVJ6y6r3MpIrPJnUobMkjGFOuX+rXAdfDqVVWE9TO5yfmOM
-S5CqgZGtlzlpwSUeq4GLejUA9w75D41+52knAMIzBrdXNBGjjQmhCeGAoF7LHxj8
-ArbG7X3MwnJEl50QgUqkoAj5v1hYuAJhFsVpWOagaEA0wcz8Su5ER3xU8p4FsKV0
-MngVjwKCAQEAqVuMpcioWz7CKW8h0Qtgw/3sCCIgaaclVoPSGoSs7te1AfyP/OEn
-tSS22JTRFnftZbX1TlTHesDog31tJDil+i8Lm/yuYkeCSwqSdWDlAr35Y5VgDoTp
-ol40nMeJ/4uub0s/hviURBcca+0sBGEpOYwNiVlLgpJ2a6bsUFDBpyiupCjNMMjc
-O2WVkO8r9vBXk2HWArWhbabIdlXZW+dklQRM8WLfZ8iNN3uQmp0b4R0GlBrIdVPp
-ISTuLeT9k3UW9fkvIs92baJCnqNfpJ1rwVUsQ1lZxSmzwipxm45A/WcwX+84eU0i
-LCgavOMf4JHnL0X2EeV/kea4hdXgo1MXwQKCAQEApKpBnJ2DPxN/I0cHbOFLH1rS
-A3lZvx0iOz7AFVK9laJ/794s5RdugXQ0MO4D0u+QrYN/Q3GnMpuNmHM8FRRNRIte
-jdpPmFLyPOrqOCaeISmMnwZl1GZtOjZwOWRWP/7pK8cv6bI4H8tDyYq9T3b0K+TK
-mqhqoHyN4aNrLCxggmhFS8wlK5UmuwJRfbAx4KGbfYk7fy4THkGjn5ZL3q9PO9Fa
-1jWsiBFdnmRQvD4svnTswPEts/rJ9o1P5+AnWtVKK7Npq9eOFhPRJ3R3hruHJath
-Cw999aol+hd093kcd7RzRmRjxUZ6oKxs1yRF7o9QQxnsmHRUT79Yy9LBOprvVA==
------END RSA PRIVATE KEY-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.pk8 b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.pk8
deleted file mode 100644
index 933eb474..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.pk8 and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.x509.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.x509.pem
deleted file mode 100644
index 95f96af8..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/com.android.apex.test.sharedlibs.x509.pem
+++ /dev/null
@@ -1,34 +0,0 @@
------BEGIN CERTIFICATE-----
-MIIF5TCCA80CFBhOpuxTEQRD+MtXkeI8yP5rnPrwMA0GCSqGSIb3DQEBCwUAMIGt
-MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91
-bnRhaW4gVmlldzEQMA4GA1UECgwHQW5kcm9pZDEQMA4GA1UECwwHQW5kcm9pZDEi
-MCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTEpMCcGA1UEAwwgY29t
-LmFuZHJvaWQuYXBleC50ZXN0LnNoYXJlZGxpYnMwIBcNMjAxMDA1MTYzMzIwWhgP
-NDc1ODA5MDExNjMzMjBaMIGtMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZv
-cm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEQMA4GA1UECgwHQW5kcm9pZDEQ
-MA4GA1UECwwHQW5kcm9pZDEiMCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lk
-LmNvbTEpMCcGA1UEAwwgY29tLmFuZHJvaWQuYXBleC50ZXN0LnNoYXJlZGxpYnMw
-ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDjKxHP9SI0nMgAqYsSueNU
-042arnj7pjdzhqHhRWr8Ub0mwMXx0ulkgZcnhCbdg52670T2wPhl/xi4/HL7PybU
-sjt1QsjOaYcDdSrdxnsPe4RXZG4aE/+z06pm7TJ2jMGjJzS9x4AXbFNBxLsLp+gk
-fuxhpGQklgymRUojtUFMWhnXURQz5wyYJGUrV32FpOo5JKtO4A42pNhcHNBzeQp0
-LVAwcQalmxra1maf0PXTg6L4yukyNzfLYcukjkQilzrkWGPqGexCzLF+WXiuznNj
-BqPguKXvdsmSUIqAKGw6QHnuD6cAm3d2CuMzd4fjdOwzxFtfDEXS8f8ai/K+UEvx
-eqf8eXV0cpKROrbf0CafcUli/3CKIc3UXoQr5kx4LSp0eJHOyaoGEF3Dex/k0dgJ
-O80nNGTydhwvfMoZ4MOm+4yzDTqKu/Hw2ebM9po3vsfF3oy/hjEX0CaS4DnKDugg
-WUwAbTHG5k/lbzy6mkjRDxwSzn6sDrhHM1rs45thiQF9hfZuDwUbaGmxFAq8+Gtu
-xcr6bhryxaiO10MdMHI5KP1ZfZT49c+K8oVlTOsHxxxSK3eiQOs4k8A0jef7gfTP
-rnDKbdq7JHr73bHXv495UtgZMCKtS3p4kvHs5PYblWvJmYImMrLjqdtuckYOeEIO
-2N+79Rm8YAItX+SigohnZwIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQAiJdApc590
-zoYl2w6NOj1xMljzta5Ld92lbJ3O4r1IoFQ6p+bSuV5RlPEC/kzR1G2WrZf66IrW
-UOSxtDjY6Bt1GKO949BKTp4/gdrnanst7ai5VnPeGWstUIEJ5SmF7C9QBhWnGnFT
-9zGdtbKnkcreZ81yabbNwAAwZWgX5hfkLSuMu7SzgLnzVDQOvbg96esWCbbBNPAl
-KhZb5Bzc42TDlUxWfqIC0Of3GjcLu1Ukn4fwFphMD4wGoHIgpGD6975BVWESpmnV
-tPDwiI+02Nha1aySZr/TiTId0AUucb6fqySqjCbOowv3DimKt+anwZjk1k/12TLb
-Uro5nOPbWwQkQws7tnfNb8VBWoGNc+SJbh260rhv7gpwsvXOdbKbyR7mSqXylreh
-DBUd/UL2eR1IrMuixK4bvmfVd7y+lxYKutEk+ifwSEuAubcbZ/dKH4PzjRnu1evv
-4M/1sLH4LRd+qHoR4ylopX8dWn3xh2Xq9KFrnTXRk1nd1YeGqcyTz+H7bBhYZKLO
-vPYTUb8ZYc/h0VGaABVywnb8wWZH4Op7ytKDybV2PGjhdLWaA3Y758ySkEab80ye
-XSuSPevgTDc7ZV3/Ijs7cW6+XVKnWWl4H7DQxG4B9vWrKl0YejNJBUNaXoE5t1hN
-TG2GM5D9sA/8HiW1JygwH0CBXMT5drYYjA==
------END CERTIFICATE-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/manifest.json b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/manifest.json
deleted file mode 100644
index abdb7c42..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs/manifest.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-  "name": "com.android.apex.test.sharedlibs",
-  "version": 1
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/Android.bp b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/Android.bp
deleted file mode 100644
index d8f59614..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/Android.bp
+++ /dev/null
@@ -1,68 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-apex_key {
-    name: "com.android.apex.test.sharedlibs_secondary.key",
-    public_key: "com.android.apex.test.sharedlibs_secondary.avbpubkey",
-    private_key: "com.android.apex.test.sharedlibs_secondary.pem",
-}
-
-android_app_certificate {
-    name: "com.android.apex.test.sharedlibs_secondary.certificate",
-    certificate: "com.android.apex.test.sharedlibs_secondary",
-}
-
-apex {
-    name: "com.android.apex.test.sharedlibs_secondary_stub",
-    manifest: "manifest.json",
-    file_contexts: ":apex.test-file_contexts",
-    key: "com.android.apex.test.sharedlibs_secondary.key",
-    installable: false,
-    // We want to force libc++.so to be available in this stub APEX, so put an empty binary.
-    binaries: ["noop"],
-    updatable: false,
-    // This test apex is used by shared_libs_repack, which works with only ext4.
-    payload_fs_type: "ext4",
-}
-
-java_genrule {
-    name: "com.android.apex.test.sharedlibs_secondary_generated",
-    out: ["com.android.apex.test.sharedlibs_secondary_generated.apex"],
-    defaults: ["apexer_test_host_tools_list"],
-    dist: {
-        targets: ["sharedlibs_test"],
-    },
-    srcs: [
-        ":com.android.apex.test.sharedlibs_secondary_stub",
-        "com.android.apex.test.sharedlibs_secondary.avbpubkey",
-        "com.android.apex.test.sharedlibs_secondary.pem",
-        "com.android.apex.test.sharedlibs_secondary.pk8",
-        "com.android.apex.test.sharedlibs_secondary.x509.pem",
-    ],
-    tools: [
-        "shared_libs_repack",
-    ],
-    cmd: "$(location shared_libs_repack) " +
-        " --mode sharedlibs" +
-        " --key $(location com.android.apex.test.sharedlibs_secondary.pem)" +
-        " --input $(location :com.android.apex.test.sharedlibs_secondary_stub)" +
-        " --output $(genDir)/com.android.apex.test.sharedlibs_secondary_generated.apex" +
-        " --pk8key $(location com.android.apex.test.sharedlibs_secondary.pk8)" +
-        " --pubkey $(location com.android.apex.test.sharedlibs_secondary.avbpubkey)" +
-        " --x509key $(location com.android.apex.test.sharedlibs_secondary.x509.pem)" +
-        " --tmpdir $(genDir)",
-}
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.avbpubkey b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.avbpubkey
deleted file mode 100644
index 3ccad0fa..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.avbpubkey and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.pem
deleted file mode 100644
index 5d4e1e1d..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.pem
+++ /dev/null
@@ -1,51 +0,0 @@
------BEGIN RSA PRIVATE KEY-----
-MIIJKgIBAAKCAgEA2U7XN6RmrgLci4ZK2Osai9MqNIfx0gBX43DeIt6/1mQ5T590
-016wrGN6Oux0+LcdPU4PmpcyHw8+JVgdZjxG5c4icfWEuuc3Y+Pb6/FhvNwNrN5U
-wx7/DFGyEWaRZEe3pk6oDETSYvY5CzQjrFz+mDDwNnho0zxsRD74GWumQOkdAg0W
-7ihUq4/gCnjx+SeijTJAZcN0+oSldRa8+yN5zYdtO9gt9PGZLr87pvIFbcKp8QIT
-sReN9eFoLHYYktq5y4YXIhhV7W0imsPzAq6gtzHC6+qgDPCvwD6/GTvGHgF+DEUl
-/NuQgqgeVrFOEnHZ5qsawRwVeVq6sRd2ZQUdj+ix5KTS9/iKpg/cyLHCaXzEWWcZ
-DtKnZKxdFTyXa4w+UshQkKDHPYOKfOXLaTTywz9oAZNDBQsLjUUIDZhyxRq7a5Zk
-gUi5zG+Wx6r46pdSmMb76Qa2vasMQUYFoRINRfrsU6EJp55fjWCDzFXMIdm8nSkz
-4DY6T+XLu76zAMrZZPHrQle2D5zi/mu2yvbHi0sbujUCFBFrPpLkaD8TE1gqxqfh
-p5+xXD8tal6Mj7exLvRCadNaQ1R8CtcZhVxtUPmGVwlUZ6aF1QpARQtfZuVBEiut
-kyfTb9ns8r3xmxsUOSwJA6SgRuN0gvXIfDnNumDaP9dkuGE98uQpTu8kZbsCAwEA
-AQKCAgEAg0oR1yk5bAqIirdxAwtP94h16FT18eWJM/2eB71Cc9oLkiKJp6Z+4Tgc
-wfrYVOf0/3PpE4IjowZHirJo2Lq0LuVShD1MmstU+MHSvgMRBNSCYp3U4ioY961o
-AwFP+CEoQI8nEnqGDYorPqyanOl2XCa9CnvHAVBxLO5KYLlcMb1lbDbSUsMFHL4J
-IuqdbuXWXK4uoAzt4OlBObOqK6TsUxNuGIjsgx9waADbnmp8gyroF5ckpIrRlus/
-UBVtlVQWinMSCORhDdgw3wZiDI3KxcOHu5b+abMEzAZc2Hb3pGtMZ0djwxg4f+fo
-pIHs5FHqz2Uy/dbk1nPNdW7ydegYShuQmsvbOT6R8Qi25c9SiirXKOtdCM50JTW7
-SRaReqhiy828m9DOrwSXXiHrmyNevpwGQtRELGi14rgPqnpuUNaOmMEGAstQ+xcU
-Hl0DVuxWXN37iEKa4zv/LKwRzBVxlrSC1M3ufiOi2tVl5btMrdz5jZwDLYQxI7TX
-Nu0l/tEWD98/sJyOk4bmGUFrD5+oBpPGw/MrK6k7DmJjp8W1NRiiIACI/flzRWcA
-la7lPk23kG0/lmrWY87NQhEaPR9RMqmizlnF3VzWyDxXgZcn4ucjRmH7qhQLsZCC
-VIEI3oPoQSd7w+pHghLTA4R0KqW2ur/d05mkOmLfGnL27wPqaJECggEBAPX2tgHr
-DLIapja0HtxYNx0I5H/lHi3bzBI426h7317oIQpASKsqaIu/jOSDt5gLC0g+qSJi
-gT/l454bkdN4lTAMvY+3vJg3cN4U8J9GAejZi2X23Hed1QVuBSckz3CrHanqVBMN
-Nj9FsfQpqLJpewVqqdKR9rK+1ZNyMWfEO9M3pxlpZyWhPHg7KtbqBo0hS5Stlqpy
-xOo4nF4WC+OGNUo02R12ETJM4AmMs28Z5oNYZZ6K4cqKReNcDqt891ryXrow6aq9
-JBYz8sCeBQSTnPNnhbLJH/YOVMlhdAJhBcxEDbNKM6vmFQOuBEp12tjQoXsiv54C
-uBou7aRft8uGeHMCggEBAOIszCN1ZvD+xbaLDtKgPrAuDVRaZuZ9vb2TVB7Gcpto
-hCXU5GoapqQgjGplsXOQ1FMRozeRL4lQWfPfiueLAV3AeIHm0qjD2aanhJPvPrnb
-UCOdWRID99q9/s6bP98XiDseZiTHNlWitwpbWPAvmW2/08otmf4TgeLrA8p75CtK
-qJXU7o7fWTBFHF238rusK3N9t0Vikb0Cx1xDui6b5PeWtqAREV1/swP0J0av1fwK
-OuvZ8VdUjb5KMUMtGgMEWA277kYuryalu+oQH+bfe3XXUJS7fAI7GlokVqhJ8CLZ
-eSSZDtdqHib968cA4wr55nt1rEiDWzG7f2GeZra6s5kCggEAN53QrABdP4ydFvOF
-oudjlvIi0PSa7V2s+FXY/XD9IjW0+t9sTx/owejPUACkrAGbTHu2vOqvNSajYGX1
-hG7YtSO8XVn7kCPBJsZvXmRzHBbM2YKHeZi7yV2GVsKREXXv4DL3TdOH96inw4ED
-/0uwoJnsyots0CAspQmGOGN775e+9hUKWMzrongmiLAkSRdFQto5nlMTSa8BVJkB
-mTIIrL3kdi/zVX9ijWY+UJn3sK11VPMseSLpCK8RNh+swujZGJrky1G3bjnS41EX
-62ABdlxrM/EchAPbkimyFLOhnv2oZ2kY4/7Ds7BOkhOyJ6KNUQ2bbHxK6si/vZJT
-OfcvFwKCAQEA0nnVzvmmPocY/vMRbDjrnZB9nw4xzDUfqZe9JJaQeMcekwY3OfZr
-NTmE8k6IgH8618MGHOPjVOmNjEFvRmI5d0Fx45EmYR9BILGr0u9FdDf/r+Txyq4e
-rVU6FpKrMbT4deuoKnmourCdnem8LmhdY6CsOu2M7MDCkqUZ9gitIQxtLmHlTtfS
-a/UknKJeJP/nv6YyM0OzVC2N0PLGBDHXNgDvGq5HdrcrpHZFRqbDf7UVd/5tdVOe
-RINOrLEAD+au+rj02CMBo/l/kiZHSdaXUeZ5eq+ui3Ts5Q4EBsAn1IaFEeXNxfFe
-9fI+xAazQrekISg0l5aF+xX9SJ7b/xhnoQKCAQEA7vvi5zUalTNRreeExX0wiKRj
-sCvUhQoykimKpWzSUg6DpdF+DhK59/ERVSkA4C2WwHEYqZdrgEKnmqOZQkqgtq1B
-O5xxioRtn6VsZRYjaRw5Cq/Ej1AeDgQr+SH29kBtym81mMBbkPnFoBxKCjuuVn9u
-4Kjg910wxErzipjDB2alfkuFCqNz9IZd2XSmpmGhpE/hBlZP4slJXTX77nIxRTHB
-Vq5gehJoEhLNsFAu34BgrXRIhzSBALdalbepNrHh2br87rJpjxeRASbuyyNdgZyl
-wk+aJxHo6RpMD7xHxsxv5kmRcLITPICk+ysLZ5ZHMaEuGIVFxDdOoFGylRV4wQ==
------END RSA PRIVATE KEY-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.pk8 b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.pk8
deleted file mode 100644
index 2eee60f0..00000000
Binary files a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.pk8 and /dev/null differ
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.x509.pem b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.x509.pem
deleted file mode 100644
index 74dd144f..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/com.android.apex.test.sharedlibs_secondary.x509.pem
+++ /dev/null
@@ -1,34 +0,0 @@
------BEGIN CERTIFICATE-----
-MIIF+TCCA+ECFGnrAltwoToH4tPw7aN36oFBb8zxMA0GCSqGSIb3DQEBCwUAMIG3
-MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91
-bnRhaW4gVmlldzEQMA4GA1UECgwHQW5kcm9pZDEQMA4GA1UECwwHQW5kcm9pZDEi
-MCAGCSqGSIb3DQEJARYTYW5kcm9pZEBhbmRyb2lkLmNvbTEzMDEGA1UEAwwqY29t
-LmFuZHJvaWQuYXBleC50ZXN0LnNoYXJlZGxpYnNfc2Vjb25kYXJ5MCAXDTIwMTEy
-NzEwNTE0N1oYDzQ3NTgxMDI0MTA1MTQ3WjCBtzELMAkGA1UEBhMCVVMxEzARBgNV
-BAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEDAOBgNVBAoM
-B0FuZHJvaWQxEDAOBgNVBAsMB0FuZHJvaWQxIjAgBgkqhkiG9w0BCQEWE2FuZHJv
-aWRAYW5kcm9pZC5jb20xMzAxBgNVBAMMKmNvbS5hbmRyb2lkLmFwZXgudGVzdC5z
-aGFyZWRsaWJzX3NlY29uZGFyeTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
-ggIBANLZWZWEtzYdHL+yio1j16r4aDCtRMdTFT8dWhXi/khEodZ9PZHV73eAWl7o
-5AHO2h/4To6hqxKlzl5lbNWT/Xu7OFvhaqy1gD2XiOyZxqNITba3SV4qDnWYAMHc
-JdcYKv/F5UMeiXQueBJ2HaWcWoZPOmHwfJbMxSvr+LOwtI1vvR38G68uIFyR0Rlb
-jQggv/WsudLlB++0c+jOtPLmD65h7dXXXlqGvu+7Rt5GWYxtN/sIZ0KPqtLk1JQD
-nIa5E05UDcqfGnyo5mz7t9Tj+4dyH/B+fY9JMXJMNMcy47CfdhR4NfnsUTmLqXRc
-fOwSRfuodMbCd4WAgA6e6KHjlBO89NOA3QamQDyhT3XURrMCMeRQvb155dEoHCs5
-FDBu138hku5aylLfiHkEHfwEDu9wsWAd3CWsBfqOMAEQG7AB+4lCaGVhYKMxKWjM
-Pdqzfy47ODHrMEprfrYlOkdJ+9Fu9HJZvEMQXh7tleoOSIuvqmL1ksRSUXsE2JHJ
-KC/hoBCcVsMsujxn7tQilB0e+TLDml08dIrrGLV1UiqU/80q0MC2Bwinne21KAtY
-UMJd2pImZr3H4z7J6wQmuevvcZksaEwWXtQzIoXenmaSW9bwqVy6k+DushOghGy/
-CAeeJAc35sUFsa8ysp0aPARZIqCYiesGdiO/wW+UVibo2JyLAgMBAAEwDQYJKoZI
-hvcNAQELBQADggIBAFE7g7ZTGqSDpJ/PyLKLp+oItJ+JNJVd5UbLvLMiA4t7QTtE
-0aPCxMGybJGeYbs16OB3ZqWZlVyjirEXAmSH2HZxO1uIeDcCjndSCfz+oxmBs27j
-C8t5BzExaelpP/J9nyKObzaZ1EJ+KdTqPVmrhgN8uUU82mRt5oJZuxGbHNdbzxGh
-zXHi+q5oecWaiBFDSF9pvKFp7nvbW4MIaGcm9Flx9JdYhgzRfXeJV7EsKE2Kxflj
-nojgyUzjvkNTa/wRASgwr/hgpPL0mpD9gSejxOA5wRGLknDlIfsfEh5cJTFiBO5b
-MZiSHe7Ds+8GWyKk8y8G2YtB0Z5HxD91rzPA2W/JEDHhoI8jT47I3JuOyJMjC9DV
-kAu4nhReBilOmU+oS1Iv+TheslPGLEZ7JOHsmyQh5X5H0D+YH7H9L8BOWEBlNBhy
-zPlMKNWsvMZmem/fhuXK1xUUWZuqoj2tF2fMmiYf6fSNRb7dQI10uBslxX7myNyj
-pqZNSk/E9V650UC5JixpOtPxrSsPXifOLwB7OEkT5v7v/MoBqlSfqve9/62Ktnuc
-NC9Rt3fqU+VOs6tVUPGnSJRDc2uhvU8rJZN86e1xX8d7lhHZwO8sJtaxZ2KYduM1
-ncEODTAxK7wQ041CS7H/kULG6CEPnIg0a1ZjASWhQRbQ1Rj/Y40CmHxThnyx
------END CERTIFICATE-----
diff --git a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/manifest.json b/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/manifest.json
deleted file mode 100644
index 80da6f14..00000000
--- a/tests/testdata/sharedlibs/build/com.android.apex.test.sharedlibs_secondary/manifest.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-  "name": "com.android.apex.test.sharedlibs_secondary",
-  "version": 1
-}
diff --git a/tests/testdata/sharedlibs/build/include/sharedlibstest.h b/tests/testdata/sharedlibs/build/include/sharedlibstest.h
deleted file mode 100644
index a2f0cdc9..00000000
--- a/tests/testdata/sharedlibs/build/include/sharedlibstest.h
+++ /dev/null
@@ -1,28 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef SHAREDLIBSTEST_H_
-#define SHAREDLIBSTEST_H_
-
-#include <string>
-
-namespace sharedlibstest {
-
-std::string getSharedLibsTestFingerprint();
-
-} // namespace sharedlibstest
-
-#endif // SHAREDLIBSTEST_H_
diff --git a/tests/testdata/sharedlibs/build/noop.cc b/tests/testdata/sharedlibs/build/noop.cc
deleted file mode 100644
index cfd2ef57..00000000
--- a/tests/testdata/sharedlibs/build/noop.cc
+++ /dev/null
@@ -1,9 +0,0 @@
-#include <iostream>
-
-#include "sharedlibstest.h"
-
-int main() {
-  std::cout << "This binary should never be executed";
-  std::cout << sharedlibstest::getSharedLibsTestFingerprint();
-  return 1;
-}
\ No newline at end of file
diff --git a/tests/testdata/sharedlibs/build/shared_libs_repack.py b/tests/testdata/sharedlibs/build/shared_libs_repack.py
deleted file mode 100644
index f5f78286..00000000
--- a/tests/testdata/sharedlibs/build/shared_libs_repack.py
+++ /dev/null
@@ -1,421 +0,0 @@
-#  Copyright (C) 2020 The Android Open Source Project
-#
-#  Licensed under the Apache License, Version 2.0 (the "License");
-#  you may not use this file except in compliance with the License.
-#  You may obtain a copy of the License at
-#
-#       http://www.apache.org/licenses/LICENSE-2.0
-#
-#  Unless required by applicable law or agreed to in writing, software
-#  distributed under the License is distributed on an "AS IS" BASIS,
-#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-#  See the License for the specific language governing permissions and
-#  limitations under the License.
-#
-#  Licensed under the Apache License, Version 2.0 (the "License");
-#  you may not use this file except in compliance with the License.
-#  You may obtain a copy of the License at
-#
-#       http://www.apache.org/licenses/LICENSE-2.0
-#
-#  Unless required by applicable law or agreed to in writing, software
-#  distributed under the License is distributed on an "AS IS" BASIS,
-#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-#  See the License for the specific language governing permissions and
-#  limitations under the License.
-"""Repacking tool for Shared Libs APEX testing."""
-
-import argparse
-import hashlib
-import logging
-import os
-import shutil
-import subprocess
-import sys
-import tempfile
-from zipfile import ZipFile
-
-import apex_build_info_pb2
-import apex_manifest_pb2
-
-logger = logging.getLogger(__name__)
-
-def comma_separated_list(arg):
-  return arg.split(',')
-
-
-def parse_args(argv):
-  parser = argparse.ArgumentParser(
-      description='Repacking tool for Shared Libs APEX testing')
-
-  parser.add_argument('--input', required=True, help='Input file')
-  parser.add_argument('--output', required=True, help='Output file')
-  parser.add_argument(
-      '--key', required=True, help='Path to the private avb key file')
-  parser.add_argument(
-      '--pk8key',
-      required=True,
-      help='Path to the private apk key file in pk8 format')
-  parser.add_argument(
-      '--pubkey', required=True, help='Path to the public avb key file')
-  parser.add_argument(
-      '--tmpdir', required=True, help='Temporary directory to use')
-  parser.add_argument(
-      '--x509key',
-      required=True,
-      help='Path to the public apk key file in x509 format')
-  parser.add_argument(
-      '--mode', default='strip', choices=['strip', 'sharedlibs'])
-  parser.add_argument(
-      '--libs',
-      default='libc++.so,libsharedlibtest.so',
-      type=comma_separated_list,
-      help='Libraries to strip/repack. Expects comma separated values.')
-  return parser.parse_args(argv)
-
-
-def run(args, verbose=None, **kwargs):
-  """Creates and returns a subprocess.Popen object.
-
-  Args:
-    args: The command represented as a list of strings.
-    verbose: Whether the commands should be shown. Default to the global
-      verbosity if unspecified.
-    kwargs: Any additional args to be passed to subprocess.Popen(), such as env,
-      stdin, etc. stdout and stderr will default to subprocess.PIPE and
-      subprocess.STDOUT respectively unless caller specifies any of them.
-      universal_newlines will default to True, as most of the users in
-      releasetools expect string output.
-
-  Returns:
-    A subprocess.Popen object.
-  """
-  if 'stdout' not in kwargs and 'stderr' not in kwargs:
-    kwargs['stdout'] = subprocess.PIPE
-    kwargs['stderr'] = subprocess.STDOUT
-  if 'universal_newlines' not in kwargs:
-    kwargs['universal_newlines'] = True
-  if verbose:
-    logger.info('  Running: \"%s\"', ' '.join(args))
-  return subprocess.Popen(args, **kwargs)
-
-
-def run_and_check_output(args, verbose=None, **kwargs):
-  """Runs the given command and returns the output.
-
-  Args:
-    args: The command represented as a list of strings.
-    verbose: Whether the commands should be shown. Default to the global
-      verbosity if unspecified.
-    kwargs: Any additional args to be passed to subprocess.Popen(), such as env,
-      stdin, etc. stdout and stderr will default to subprocess.PIPE and
-      subprocess.STDOUT respectively unless caller specifies any of them.
-
-  Returns:
-    The output string.
-
-  Raises:
-    ExternalError: On non-zero exit from the command.
-  """
-  proc = run(args, verbose=verbose, **kwargs)
-  output, _ = proc.communicate()
-  if output is None:
-    output = ''
-  # Don't log any if caller explicitly says so.
-  if verbose:
-    logger.info('%s', output.rstrip())
-  if proc.returncode != 0:
-    raise RuntimeError(
-        'Failed to run command \'{}\' (exit code {}):\n{}'.format(
-            args, proc.returncode, output))
-  return output
-
-
-def get_container_files(apex_file_path, tmpdir):
-  dir_name = tempfile.mkdtemp(prefix='container_files_', dir=tmpdir)
-  with ZipFile(apex_file_path, 'r') as zip_obj:
-    zip_obj.extractall(path=dir_name)
-  files = {}
-  for i in [
-      'apex_manifest.json', 'apex_manifest.pb', 'apex_build_info.pb', 'assets',
-      'apex_payload.img', 'apex_payload.zip'
-  ]:
-    file_path = os.path.join(dir_name, i)
-    if os.path.exists(file_path):
-      files[i] = file_path
-
-  image_file = files.get('apex_payload.img')
-  if image_file is None:
-    image_file = files.get('apex_payload.zip')
-
-  files['apex_payload'] = image_file
-
-  return files
-
-
-def extract_payload_from_img(img_file_path, tmpdir):
-  dir_name = tempfile.mkdtemp(prefix='extracted_payload_', dir=tmpdir)
-  cmd = [
-      _get_host_tools_path('debugfs_static'), '-R',
-      'rdump ./ %s' % dir_name, img_file_path
-  ]
-  run_and_check_output(cmd)
-
-  # Remove payload files added by apexer and e2fs tools.
-  for i in ['apex_manifest.json', 'apex_manifest.pb']:
-    if os.path.exists(os.path.join(dir_name, i)):
-      os.remove(os.path.join(dir_name, i))
-  if os.path.isdir(os.path.join(dir_name, 'lost+found')):
-    shutil.rmtree(os.path.join(dir_name, 'lost+found'))
-  return dir_name
-
-
-def run_apexer(container_files, payload_dir, key_path, pubkey_path, tmpdir):
-  apexer_cmd = _get_host_tools_path('apexer')
-  cmd = [
-      apexer_cmd, '--force', '--include_build_info', '--do_not_check_keyname'
-  ]
-  cmd.extend([
-      '--apexer_tool_path',
-      os.path.dirname(apexer_cmd) + ':prebuilts/sdk/tools/linux/bin'
-  ])
-  cmd.extend(['--manifest', container_files['apex_manifest.pb']])
-  if 'apex_manifest.json' in container_files:
-    cmd.extend(['--manifest_json', container_files['apex_manifest.json']])
-  cmd.extend(['--build_info', container_files['apex_build_info.pb']])
-  if 'assets' in container_files:
-    cmd.extend(['--assets_dir', container_files['assets']])
-  cmd.extend(['--key', key_path])
-  cmd.extend(['--pubkey', pubkey_path])
-
-  # Decide on output file name
-  apex_suffix = '.apex.unsigned'
-  fd, fn = tempfile.mkstemp(prefix='repacked_', suffix=apex_suffix, dir=tmpdir)
-  os.close(fd)
-  cmd.extend([payload_dir, fn])
-
-  run_and_check_output(cmd)
-  return fn
-
-
-def _get_java_toolchain():
-  java_toolchain = 'java'
-  if os.path.isfile('prebuilts/jdk/jdk21/linux-x86/bin/java'):
-    java_toolchain = 'prebuilts/jdk/jdk21/linux-x86/bin/java'
-
-  java_dep_lib = (
-      os.path.join(os.path.dirname(_get_host_tools_path()), 'lib64') + ':' +
-      os.path.join(os.path.dirname(_get_host_tools_path()), 'lib'))
-
-  return [java_toolchain, java_dep_lib]
-
-
-def _get_host_tools_path(tool_name=None):
-  # This script is located at e.g.
-  # out/host/linux-x86/bin/shared_libs_repack/shared_libs_repack.py.
-  # Find the host tools dir by going up two directories.
-  dirname = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
-  if tool_name:
-    return os.path.join(dirname, tool_name)
-  return dirname
-
-
-def sign_apk_container(unsigned_apex, x509key_path, pk8key_path, tmpdir):
-  fd, fn = tempfile.mkstemp(prefix='repacked_', suffix='.apex', dir=tmpdir)
-  os.close(fd)
-  java_toolchain, java_dep_lib = _get_java_toolchain()
-
-  cmd = [
-      java_toolchain, '-Djava.library.path=' + java_dep_lib, '-jar',
-      os.path.join(
-          os.path.dirname(_get_host_tools_path()), 'framework', 'signapk.jar'),
-      '-a', '4096', '--align-file-size', x509key_path, pk8key_path, unsigned_apex, fn
-  ]
-  run_and_check_output(cmd)
-  return fn
-
-
-def compute_sha512(file_path):
-  block_size = 65536
-  hashbuf = hashlib.sha512()
-  with open(file_path, 'rb') as f:
-    fb = f.read(block_size)
-    while len(fb) > 0:
-      hashbuf.update(fb)
-      fb = f.read(block_size)
-  return hashbuf.hexdigest()
-
-
-def parse_fs_config(fs_config):
-  configs = fs_config.splitlines()
-  # Result is set of configurations.
-  # Each configuration is set of items as [file path, uid, gid, mode].
-  # All items are stored as string.
-  result = []
-  for config in configs:
-    result.append(config.split())
-  return result
-
-
-def config_to_str(configs):
-  result = ''
-  for config in configs:
-    result += ' '.join(config) + '\n'
-  return result
-
-
-def _extract_lib_or_lib64(payload_dir, lib_full_path):
-  # Figure out if this is lib or lib64:
-  # Strip out the payload_dir and split by /
-  libpath = lib_full_path[len(payload_dir):].lstrip('/').split('/')
-  return libpath[0]
-
-
-def main(argv):
-  args = parse_args(argv)
-  apex_file_path = args.input
-
-  container_files = get_container_files(apex_file_path, args.tmpdir)
-  payload_dir = extract_payload_from_img(container_files['apex_payload.img'],
-                                         args.tmpdir)
-  libs = args.libs
-  assert len(libs)> 0
-
-  lib_paths = [os.path.join(payload_dir, lib_dir, lib)
-               for lib_dir in ['lib', 'lib64']
-               for lib in libs
-               if os.path.exists(os.path.join(payload_dir, lib_dir, lib))]
-
-  assert len(lib_paths) > 0
-
-  lib_paths_hashes = [(lib, compute_sha512(lib)) for lib in lib_paths]
-
-  if args.mode == 'strip':
-    # Stripping mode. Add a reference to the version of libc++.so to the
-    # requireSharedApexLibs entry in the manifest, and remove lib64/libc++.so
-    # from the payload.
-    pb = apex_manifest_pb2.ApexManifest()
-    with open(container_files['apex_manifest.pb'], 'rb') as f:
-      pb.ParseFromString(f.read())
-      for lib_path_hash in lib_paths_hashes:
-        basename = os.path.basename(lib_path_hash[0])
-        libpath = _extract_lib_or_lib64(payload_dir, lib_path_hash[0])
-        assert libpath in ('lib', 'lib64')
-        pb.requireSharedApexLibs.append(os.path.join(libpath, basename) + ':'
-                                        + lib_path_hash[1])
-        # Replace existing library with symlink
-        symlink_dst = os.path.join('/', 'apex', 'sharedlibs',
-                                   libpath, basename, lib_path_hash[1],
-                                   basename)
-        os.remove(lib_path_hash[0])
-        os.system('ln -s {0} {1}'.format(symlink_dst, lib_path_hash[0]))
-      #
-      # Example of resulting manifest:
-      # ---
-      # name: "com.android.apex.test.foo"
-      # version: 1
-      # requireNativeLibs: "libc.so"
-      # requireNativeLibs: "libdl.so"
-      # requireNativeLibs: "libm.so"
-      # requireSharedApexLibs: "lib/libc++.so:23c5dd..."
-      # requireSharedApexLibs: "lib/libsharedlibtest.so:870f38..."
-      # requireSharedApexLibs: "lib64/libc++.so:72a584..."
-      # requireSharedApexLibs: "lib64/libsharedlibtest.so:109015..."
-      # --
-      # To print uncomment the following:
-      # from google.protobuf import text_format
-      # print(text_format.MessageToString(pb))
-    with open(container_files['apex_manifest.pb'], 'wb') as f:
-      f.write(pb.SerializeToString())
-
-  if args.mode == 'sharedlibs':
-    # Sharedlibs mode. Mark in the APEX manifest that this package contains
-    # shared libraries.
-    pb = apex_manifest_pb2.ApexManifest()
-    with open(container_files['apex_manifest.pb'], 'rb') as f:
-      pb.ParseFromString(f.read())
-      del pb.requireNativeLibs[:]
-      pb.provideSharedApexLibs = True
-    with open(container_files['apex_manifest.pb'], 'wb') as f:
-      f.write(pb.SerializeToString())
-
-    pb = apex_build_info_pb2.ApexBuildInfo()
-    with open(container_files['apex_build_info.pb'], 'rb') as f:
-      pb.ParseFromString(f.read())
-
-    canned_fs_config = parse_fs_config(pb.canned_fs_config.decode('utf-8'))
-
-    # Remove the bin directory from payload dir and from the canned_fs_config.
-    shutil.rmtree(os.path.join(payload_dir, 'bin'))
-    canned_fs_config = [config for config in canned_fs_config
-                        if not config[0].startswith('/bin')]
-
-    # Remove from the canned_fs_config the entries we are about to relocate in
-    # different dirs.
-    source_lib_paths = [os.path.join('/', libpath, lib)
-                        for libpath in ['lib', 'lib64']
-                        for lib in libs]
-    # We backup the fs config lines for the libraries we are going to relocate,
-    # so we can set the same permissions later.
-    canned_fs_config_original_lib = {config[0] : config
-                                     for config in canned_fs_config
-                                     if config[0] in source_lib_paths}
-
-    canned_fs_config = [config for config in canned_fs_config
-                        if config[0] not in source_lib_paths]
-
-    # We move any targeted library in lib64/ or lib/ to a directory named
-    # /lib64/libNAME.so/${SHA512_OF_LIBCPP}/ or
-    # /lib/libNAME.so/${SHA512_OF_LIBCPP}/
-    #
-    for lib_path_hash in lib_paths_hashes:
-      basename = os.path.basename(lib_path_hash[0])
-      libpath = _extract_lib_or_lib64(payload_dir, lib_path_hash[0])
-      tmp_lib = os.path.join(payload_dir, libpath, basename + '.bak')
-      shutil.move(lib_path_hash[0], tmp_lib)
-      destdir = os.path.join(payload_dir, libpath, basename, lib_path_hash[1])
-      os.makedirs(destdir)
-      shutil.move(tmp_lib, os.path.join(destdir, basename))
-
-      canned_fs_config.append(
-          ['/' + libpath + '/' + basename, '0', '2000', '0755'])
-      canned_fs_config.append(
-          ['/' + libpath + '/' + basename + '/' + lib_path_hash[1],
-           '0', '2000', '0755'])
-
-      if os.path.join('/', libpath, basename) in canned_fs_config_original_lib:
-        config = canned_fs_config_original_lib[os.path.join(
-                                                   '/',
-                                                   libpath,
-                                                   basename)]
-        canned_fs_config.append([os.path.join('/', libpath, basename,
-                                              lib_path_hash[1], basename),
-                                config[1], config[2], config[3]])
-      else:
-        canned_fs_config.append([os.path.join('/', libpath, basename,
-                                              lib_path_hash[1], basename),
-                                '1000', '1000', '0644'])
-
-    pb.canned_fs_config = config_to_str(canned_fs_config).encode('utf-8')
-    with open(container_files['apex_build_info.pb'], 'wb') as f:
-      f.write(pb.SerializeToString())
-
-  try:
-    for lib in lib_paths:
-      os.rmdir(os.path.dirname(lib))
-  except OSError:
-    # Directory not empty, that's OK.
-    pass
-
-  repack_apex_file_path = run_apexer(container_files, payload_dir, args.key,
-                                     args.pubkey, args.tmpdir)
-
-  resigned_apex_file_path = sign_apk_container(repack_apex_file_path,
-                                               args.x509key, args.pk8key,
-                                               args.tmpdir)
-
-  shutil.copyfile(resigned_apex_file_path, args.output)
-
-
-if __name__ == '__main__':
-  main(sys.argv[1:])
diff --git a/tests/testdata/sharedlibs/prebuilts/Android.bp b/tests/testdata/sharedlibs/prebuilts/Android.bp
deleted file mode 100644
index 55fc9523..00000000
--- a/tests/testdata/sharedlibs/prebuilts/Android.bp
+++ /dev/null
@@ -1,301 +0,0 @@
-// Copyright (C) 2020 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-// This file is auto-generated by
-// ./system/apex/tests/testdata/sharedlibs/build/build_artifacts.sh
-// Do NOT edit manually.
-
-package {
-    default_applicable_licenses: ["Android-Apache-2.0"],
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.bar_stripped.v1.libvX_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.bar_stripped.v1.libvX.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.bar_stripped.v1.libvX.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.bar_stripped.v1.libvX.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.bar_stripped.v1.libvX.apex",
-        },
-    },
-    filename: "com.android.apex.test.bar_stripped.v1.libvX.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.bar_stripped.v2.libvY_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.bar_stripped.v2.libvY.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.bar_stripped.v2.libvY.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.bar_stripped.v2.libvY.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.bar_stripped.v2.libvY.apex",
-        },
-    },
-    filename: "com.android.apex.test.bar_stripped.v2.libvY.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.bar.v1.libvX_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.bar.v1.libvX.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.bar.v1.libvX.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.bar.v1.libvX.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.bar.v1.libvX.apex",
-        },
-    },
-    filename: "com.android.apex.test.bar.v1.libvX.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.bar.v2.libvY_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.bar.v2.libvY.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.bar.v2.libvY.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.bar.v2.libvY.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.bar.v2.libvY.apex",
-        },
-    },
-    filename: "com.android.apex.test.bar.v2.libvY.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.baz_stripped.v1.libvX_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.baz_stripped.v1.libvX.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.baz_stripped.v1.libvX.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.baz_stripped.v1.libvX.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.baz_stripped.v1.libvX.apex",
-        },
-    },
-    filename: "com.android.apex.test.baz_stripped.v1.libvX.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.foo_stripped.v1.libvX_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.foo_stripped.v1.libvX.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.foo_stripped.v1.libvX.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.foo_stripped.v1.libvX.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.foo_stripped.v1.libvX.apex",
-        },
-    },
-    filename: "com.android.apex.test.foo_stripped.v1.libvX.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.foo_stripped.v2.libvY_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.foo_stripped.v2.libvY.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.foo_stripped.v2.libvY.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.foo_stripped.v2.libvY.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.foo_stripped.v2.libvY.apex",
-        },
-    },
-    filename: "com.android.apex.test.foo_stripped.v2.libvY.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.foo.v1.libvX_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.foo.v1.libvX.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.foo.v1.libvX.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.foo.v1.libvX.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.foo.v1.libvX.apex",
-        },
-    },
-    filename: "com.android.apex.test.foo.v1.libvX.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.foo.v2.libvY_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.foo.v2.libvY.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.foo.v2.libvY.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.foo.v2.libvY.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.foo.v2.libvY.apex",
-        },
-    },
-    filename: "com.android.apex.test.foo.v2.libvY.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.pony_stripped.v1.libvZ_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.pony_stripped.v1.libvZ.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.pony_stripped.v1.libvZ.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.pony_stripped.v1.libvZ.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.pony_stripped.v1.libvZ.apex",
-        },
-    },
-    filename: "com.android.apex.test.pony_stripped.v1.libvZ.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.pony.v1.libvZ_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.pony.v1.libvZ.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.pony.v1.libvZ.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.pony.v1.libvZ.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.pony.v1.libvZ.apex",
-        },
-    },
-    filename: "com.android.apex.test.pony.v1.libvZ.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.sharedlibs_generated.v1.libvX_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.sharedlibs_generated.v1.libvX.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.sharedlibs_generated.v1.libvX.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.sharedlibs_generated.v1.libvX.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.sharedlibs_generated.v1.libvX.apex",
-        },
-    },
-    filename: "com.android.apex.test.sharedlibs_generated.v1.libvX.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.sharedlibs_generated.v2.libvY_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.sharedlibs_generated.v2.libvY.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.sharedlibs_generated.v2.libvY.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.sharedlibs_generated.v2.libvY.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.sharedlibs_generated.v2.libvY.apex",
-        },
-    },
-    filename: "com.android.apex.test.sharedlibs_generated.v2.libvY.apex",
-    installable: false,
-}
-
-prebuilt_apex {
-    name: "com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ_prebuilt",
-    arch: {
-        arm: {
-            src: "arm/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex",
-        },
-        arm64: {
-            src: "arm64/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex",
-        },
-        x86: {
-            src: "x86/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex",
-        },
-        x86_64: {
-            src: "x86_64/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex",
-        },
-    },
-    filename: "com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex",
-    installable: false,
-}
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar.v1.libvX.apex
deleted file mode 100644
index f5a0ef38..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar.v2.libvY.apex
deleted file mode 100644
index 3657dfe8..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar_stripped.v1.libvX.apex
deleted file mode 100644
index d45abc92..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar_stripped.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar_stripped.v2.libvY.apex
deleted file mode 100644
index 8f0bcb65..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.bar_stripped.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.baz_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.baz_stripped.v1.libvX.apex
deleted file mode 100644
index 8437d413..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.baz_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo.v1.libvX.apex
deleted file mode 100644
index cdc9881c..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo.v2.libvY.apex
deleted file mode 100644
index 2a642b26..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo_stripped.v1.libvX.apex
deleted file mode 100644
index 45cf6214..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo_stripped.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo_stripped.v2.libvY.apex
deleted file mode 100644
index 1bacacf3..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.foo_stripped.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.pony.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.pony.v1.libvZ.apex
deleted file mode 100644
index 5d900488..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.pony.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.pony_stripped.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.pony_stripped.v1.libvZ.apex
deleted file mode 100644
index b1e23e7d..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.pony_stripped.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.sharedlibs_generated.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.sharedlibs_generated.v1.libvX.apex
deleted file mode 100644
index 277bcb0a..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.sharedlibs_generated.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.sharedlibs_generated.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.sharedlibs_generated.v2.libvY.apex
deleted file mode 100644
index adc8dcf8..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.sharedlibs_generated.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex
deleted file mode 100644
index 11a5fb7c..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar.v1.libvX.apex
deleted file mode 100644
index e42a5835..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar.v2.libvY.apex
deleted file mode 100644
index 994e4a81..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar_stripped.v1.libvX.apex
deleted file mode 100644
index 0e5ff7a9..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar_stripped.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar_stripped.v2.libvY.apex
deleted file mode 100644
index a0f7019a..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.bar_stripped.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.baz_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.baz_stripped.v1.libvX.apex
deleted file mode 100644
index b4f38ef2..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.baz_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo.v1.libvX.apex
deleted file mode 100644
index e8a4284f..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo.v2.libvY.apex
deleted file mode 100644
index df09b069..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo_stripped.v1.libvX.apex
deleted file mode 100644
index c00c1688..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo_stripped.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo_stripped.v2.libvY.apex
deleted file mode 100644
index 82d9b232..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.foo_stripped.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.pony.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.pony.v1.libvZ.apex
deleted file mode 100644
index ad50152f..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.pony.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.pony_stripped.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.pony_stripped.v1.libvZ.apex
deleted file mode 100644
index 9e51a661..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.pony_stripped.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.sharedlibs_generated.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.sharedlibs_generated.v1.libvX.apex
deleted file mode 100644
index 8a586f9f..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.sharedlibs_generated.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.sharedlibs_generated.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.sharedlibs_generated.v2.libvY.apex
deleted file mode 100644
index 556506a5..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.sharedlibs_generated.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex
deleted file mode 100644
index ac3d9b0e..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/arm64/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar.v1.libvX.apex
deleted file mode 100644
index 60e274ee..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar.v2.libvY.apex
deleted file mode 100644
index 26f4daa2..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar_stripped.v1.libvX.apex
deleted file mode 100644
index 3b322336..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar_stripped.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar_stripped.v2.libvY.apex
deleted file mode 100644
index 032315e9..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.bar_stripped.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.baz_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.baz_stripped.v1.libvX.apex
deleted file mode 100644
index 75a3f3a1..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.baz_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo.v1.libvX.apex
deleted file mode 100644
index 332eeacf..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo.v2.libvY.apex
deleted file mode 100644
index 07b1cbcb..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo_stripped.v1.libvX.apex
deleted file mode 100644
index a43011a4..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo_stripped.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo_stripped.v2.libvY.apex
deleted file mode 100644
index 8abff001..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.foo_stripped.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.pony.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.pony.v1.libvZ.apex
deleted file mode 100644
index 206ef9f8..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.pony.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.pony_stripped.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.pony_stripped.v1.libvZ.apex
deleted file mode 100644
index 32ca7f6d..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.pony_stripped.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.sharedlibs_generated.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.sharedlibs_generated.v1.libvX.apex
deleted file mode 100644
index 5924af18..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.sharedlibs_generated.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.sharedlibs_generated.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.sharedlibs_generated.v2.libvY.apex
deleted file mode 100644
index fd009cc2..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.sharedlibs_generated.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex
deleted file mode 100644
index e0e3ea01..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar.v1.libvX.apex
deleted file mode 100644
index d81b476d..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar.v2.libvY.apex
deleted file mode 100644
index 4edbe0ed..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar_stripped.v1.libvX.apex
deleted file mode 100644
index a3b7d5c9..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar_stripped.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar_stripped.v2.libvY.apex
deleted file mode 100644
index cfd741b1..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.bar_stripped.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.baz_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.baz_stripped.v1.libvX.apex
deleted file mode 100644
index d1efac0d..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.baz_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo.v1.libvX.apex
deleted file mode 100644
index d935dd26..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo.v2.libvY.apex
deleted file mode 100644
index 213488c0..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo_stripped.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo_stripped.v1.libvX.apex
deleted file mode 100644
index 1f3bcc24..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo_stripped.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo_stripped.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo_stripped.v2.libvY.apex
deleted file mode 100644
index 73d22c12..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.foo_stripped.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.pony.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.pony.v1.libvZ.apex
deleted file mode 100644
index aef13f97..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.pony.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.pony_stripped.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.pony_stripped.v1.libvZ.apex
deleted file mode 100644
index e25d1289..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.pony_stripped.v1.libvZ.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.sharedlibs_generated.v1.libvX.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.sharedlibs_generated.v1.libvX.apex
deleted file mode 100644
index ac6fcca6..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.sharedlibs_generated.v1.libvX.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.sharedlibs_generated.v2.libvY.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.sharedlibs_generated.v2.libvY.apex
deleted file mode 100644
index c9948e89..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.sharedlibs_generated.v2.libvY.apex and /dev/null differ
diff --git a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex b/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex
deleted file mode 100644
index 9df0c53f..00000000
Binary files a/tests/testdata/sharedlibs/prebuilts/x86_64/com.android.apex.test.sharedlibs_secondary_generated.v1.libvZ.apex and /dev/null differ
diff --git a/tests/vts/Android.bp b/tests/vts/Android.bp
index 9d33d564..659a4597 100644
--- a/tests/vts/Android.bp
+++ b/tests/vts/Android.bp
@@ -30,7 +30,8 @@ cc_test {
     ],
     test_suites: [
         "general-tests",
-        "vts",
+        // TODO(b/418125620) re-enable this test
+        // "vts",
     ],
     require_root: true,
     auto_gen_config: true,
diff --git a/tools/Android.bp b/tools/Android.bp
index 813307af..5b626256 100644
--- a/tools/Android.bp
+++ b/tools/Android.bp
@@ -25,8 +25,7 @@ python_binary_host {
         "apex_manifest",
     ],
     required: [
-        "blkid_static",
-        "debugfs_static",
+        "debugfs_static", // "debugfs" fails with BUILD_HOST_static=1
         "fsck.erofs",
     ],
 }
@@ -37,9 +36,7 @@ python_binary_host {
         "apex_elf_checker.py",
     ],
     required: [
-        "blkid_static",
-        "debugfs_static",
-        "fsck.erofs",
+        "deapexer",
     ],
 }
 
@@ -94,34 +91,14 @@ cc_binary_host {
         "libapex",
         "libinit_host",
     ],
-}
-
-sh_test_host {
-    name: "host-apex-verifier",
-    src: "host-apex-verifier.sh",
-    test_suites: ["device-tests"],
-    test_config: "host-apex-verifier.xml",
-    test_options: {
-        unit_test: false,
-    },
-    data_bins: [
+    // Choose one protobuf library to avoid ODR:
+    // - libapex-deps brings "full" as shared
+    // - init_host_defaults brings "lite" as shared
+    exclude_shared_libs: [
+        "libprotobuf-cpp-lite",
+    ],
+    required: [
         "deapexer",
-        "debugfs_static",
-        "fsck.erofs",
-        "host_apex_verifier",
-    ],
-    data_libs: [
-        "libbase",
-        "libc++",
-        "libcrypto",
-        "libcutils",
-        "liblog",
-        "libpcre2", // used by libselinux
-        "libprotobuf-cpp-full", // used by libapex
-        "libprotobuf-cpp-lite", // used by libinit_host
-        "libselinux", // used by libapex
-        "libz",
-        "libziparchive",
     ],
 }
 
@@ -130,39 +107,6 @@ python_library_host {
     srcs: ["apexer_wrapper_utils.py"],
 }
 
-python_binary_host {
-    name: "apexer_with_DCLA_preprocessing",
-    srcs: [
-        "apexer_with_DCLA_preprocessing.py",
-    ],
-    libs: [
-        "apexer_wrapper_utils",
-    ],
-}
-
-python_test_host {
-    name: "apexer_with_DCLA_preprocessing_test",
-    main: "apexer_with_DCLA_preprocessing_test.py",
-    srcs: [
-        "apexer_with_DCLA_preprocessing_test.py",
-    ],
-    // Need to add a pkg_path because importlib.resources
-    // cannot load resources from the root package.
-    pkg_path: "apexer_with_DCLA_preprocessing_test",
-    data: [
-        ":apexer_test_host_tools",
-        ":apexer_with_DCLA_preprocessing",
-        "testdata/com.android.example.apex.pem",
-    ],
-    device_common_data: [
-        ":com.android.example.apex",
-    ],
-    test_suites: ["general-tests"],
-    test_options: {
-        unit_test: true,
-    },
-}
-
 python_binary_host {
     name: "apexer_with_trim_preprocessing",
     srcs: [
diff --git a/tools/TEST_MAPPING b/tools/TEST_MAPPING
deleted file mode 100644
index a840033a..00000000
--- a/tools/TEST_MAPPING
+++ /dev/null
@@ -1,7 +0,0 @@
-{
-  "postsubmit": [
-    {
-      "name": "host-apex-verifier"
-    }
-  ]
-}
diff --git a/tools/apex-ls/Android.bp b/tools/apex-ls/Android.bp
index d80ffd17..5cb3682d 100644
--- a/tools/apex-ls/Android.bp
+++ b/tools/apex-ls/Android.bp
@@ -19,7 +19,6 @@ package {
 cc_binary_host {
     name: "apex-ls",
     defaults: [
-        "libapex-deps",
         // we need this to get the feature flags
         // used to build liberofs.
         "erofs-utils_export_defaults",
@@ -30,11 +29,16 @@ cc_binary_host {
         "main.cpp",
     ],
     static_libs: [
+        // apex
+        "lib_apex_manifest_proto",
         "libapex",
+
+        "libavb",
         "libbase",
         "libcrypto",
         "libcutils",
         "liberofs",
+        "liblog",
         "liblz4",
         "libprotobuf-cpp-full",
         "libselinux",
@@ -52,5 +56,5 @@ cc_binary_host {
         "libext2_e2p",
         "libext2_support",
     ],
-    static_executable: true,
+    stl: "c++_static",
 }
diff --git a/tools/apex-ls/erofs.cpp b/tools/apex-ls/erofs.cpp
index 9758461b..2d518916 100644
--- a/tools/apex-ls/erofs.cpp
+++ b/tools/apex-ls/erofs.cpp
@@ -98,6 +98,11 @@ Result<Entry> ReadEntry(struct erofs_sb_info* sbi, const fs::path& path) {
                    << erofs_strerror(err);
   }
 
+  // free memory allocated by erofs_getxattr
+  if (inode.xattr_shared_xattrs) {
+    free(inode.xattr_shared_xattrs);
+    inode.xattr_shared_xattrs = nullptr;
+  }
   return Entry{mode, entry_path, security_context};
 }
 
diff --git a/tools/apex_elf_checker.py b/tools/apex_elf_checker.py
index 8f51b0ec..e3c55ecc 100644
--- a/tools/apex_elf_checker.py
+++ b/tools/apex_elf_checker.py
@@ -73,7 +73,7 @@ def InitTools(tool_path):
       tool: ToolPath(tool)
       for tool in [
           'deapexer',
-          'debugfs_static',
+          'debugfs',
           'fsck.erofs',
           'llvm-readelf',
       ]
@@ -119,7 +119,7 @@ def CheckElfFiles(args, tools):
         [
             tools['deapexer'],
             '--debugfs_path',
-            tools['debugfs_static'],
+            tools['debugfs'],
             '--fsckerofs_path',
             tools['fsck.erofs'],
             'extract',
@@ -137,7 +137,7 @@ def CheckElfFiles(args, tools):
         if unwanted & needed:
           sys.exit(
               f'{os.path.relpath(file, work_dir)} has unwanted NEEDED:'
-              f' {",".join(unwanted & needed)}'
+              f' {','.join(unwanted & needed)}'
           )
 
 
diff --git a/tools/apexer_with_DCLA_preprocessing.py b/tools/apexer_with_DCLA_preprocessing.py
deleted file mode 100644
index ea4049dd..00000000
--- a/tools/apexer_with_DCLA_preprocessing.py
+++ /dev/null
@@ -1,98 +0,0 @@
-#!/usr/bin/env python3
-
-"""This is a wrapper function of apexer. It provides opportunity to do
-some artifact preprocessing before calling into apexer. Some of these
-artifact preprocessing are difficult or impossible to do in soong or
-bazel such as placing native shared libs in DCLA. It is better to do
-these in a binary so that the DCLA preprocessing logic can be reused
-regardless of the build system
-"""
-
-import argparse
-from glob import glob
-import os
-import shutil
-import sys
-import tempfile
-
-import apexer_wrapper_utils
-
-def ParseArgs(argv):
-  parser = argparse.ArgumentParser(
-      description='wrapper to run apexer for DCLA')
-  parser.add_argument(
-      '--apexer',
-      help='path to apexer binary')
-  parser.add_argument(
-      '--canned_fs_config',
-      help='path to canned_fs_config file')
-  parser.add_argument(
-      'input_dir',
-      metavar='INPUT_DIR',
-      help='the directory having files to be packaged')
-  parser.add_argument(
-      'output',
-      metavar='OUTPUT',
-      help='name of the APEX file')
-  parser.add_argument(
-      'rest_args',
-      nargs='*',
-      help='remaining flags that will be passed as-is to apexer')
-  return parser.parse_args(argv)
-
-def PlaceDCLANativeSharedLibs(image_dir: str, canned_fs_config: str) -> str:
-  """Place native shared libs for DCLA in a special way.
-
-  Traditional apex has native shared libs placed under /lib(64)? inside
-  the apex. However, for DCLA, it needs to be placed in a special way:
-
-  /lib(64)?/foo.so/<sha512 foo.so>/foo.so
-
-  This function moves the shared libs to desired location and update
-  canned_fs_config file accordingly
-  """
-
-  # remove all .so entries from canned_fs_config
-  parent_dir = os.path.dirname(canned_fs_config)
-  updated_canned_fs_config = os.path.join(parent_dir, 'updated_canned_fs_config')
-  with open(canned_fs_config, 'r') as f:
-    lines = f.readlines()
-  with open(updated_canned_fs_config, 'w') as f:
-    for line in lines:
-      segs = line.split(' ')
-      if not segs[0].endswith('.so'):
-        f.write(line)
-      else:
-        with tempfile.TemporaryDirectory() as tmp_dir:
-          # move native libs
-          lib_file = os.path.join(image_dir, segs[0][1:])
-          digest = apexer_wrapper_utils.GetDigest(lib_file)
-          lib_name = os.path.basename(lib_file)
-          dest_dir = os.path.join(lib_file, digest)
-
-          shutil.move(lib_file, os.path.join(tmp_dir, lib_name))
-          os.makedirs(dest_dir, exist_ok=True)
-          shutil.move(os.path.join(tmp_dir, lib_name),
-                      os.path.join(dest_dir, lib_name))
-
-          # add canned_fs_config entries
-          f.write(f'{segs[0]} 0 2000 0755\n')
-          f.write(f'{os.path.join(segs[0], digest)} 0 2000 0755\n')
-          f.write(f'{os.path.join(segs[0], digest, lib_name)} 1000 1000 0644\n')
-
-  # return the modified canned_fs_config
-  return updated_canned_fs_config
-
-def main(argv):
-  args = ParseArgs(argv)
-  args.canned_fs_config = PlaceDCLANativeSharedLibs(
-      args.input_dir, args.canned_fs_config)
-
-  cmd = [args.apexer, '--canned_fs_config', args.canned_fs_config]
-  cmd.extend(args.rest_args)
-  cmd.extend([args.input_dir, args.output])
-
-  apexer_wrapper_utils.RunCommand(cmd)
-
-if __name__ == "__main__":
- main(sys.argv[1:])
diff --git a/tools/apexer_with_DCLA_preprocessing_test.py b/tools/apexer_with_DCLA_preprocessing_test.py
deleted file mode 100644
index 5b41c92b..00000000
--- a/tools/apexer_with_DCLA_preprocessing_test.py
+++ /dev/null
@@ -1,229 +0,0 @@
-#!/usr/bin/env python3
-#
-# Copyright (C) 2020 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-"""Unit tests for apexer_with_DCLA_preprocessing."""
-import hashlib
-import importlib.resources
-import os
-import shutil
-import stat
-import subprocess
-import tempfile
-from typing import List
-import unittest
-import zipfile
-
-TEST_PRIVATE_KEY = os.path.join('testdata', 'com.android.example.apex.pem')
-TEST_APEX = 'com.android.example.apex'
-
-# In order to debug test failures, set DEBUG_TEST to True and run the test from
-# local workstation bypassing atest, e.g.:
-# $ m apexer_with_DCLA_preprocessing_test && \
-#   out/host/linux-x86/nativetest64/apexer_with_DCLA_preprocessing_test/\
-#   apexer_with_DCLA_preprocessing_test
-#
-# the test will print out the command used, and the temporary files used by the
-# test.
-DEBUG_TEST = False
-
-def resources():
-  return importlib.resources.files('apexer_with_DCLA_preprocessing_test')
-
-# TODO: consolidate these common test utilities into a common python_library_host
-# to be shared across tests under system/apex
-def run_command(cmd: List[str]) -> None:
-  """Run a command."""
-  try:
-    if DEBUG_TEST:
-      cmd_str = ' '.join(cmd)
-      print(f'\nRunning: \n{cmd_str}\n')
-    subprocess.run(
-        cmd,
-        check=True,
-        text=True,
-        stdout=subprocess.PIPE,
-        stderr=subprocess.PIPE)
-  except subprocess.CalledProcessError as err:
-    print(err.stderr)
-    print(err.output)
-    raise err
-
-def get_digest(file_path: str) -> str:
-  """Get sha512 digest of a file """
-  digester = hashlib.sha512()
-  with open(file_path, 'rb') as f:
-    bytes_to_digest = f.read()
-    digester.update(bytes_to_digest)
-    return digester.hexdigest()
-
-class ApexerWithDCLAPreprocessingTest(unittest.TestCase):
-
-  def setUp(self):
-    self._to_cleanup = []
-    self.unzip_host_tools()
-
-  def tearDown(self):
-    if not DEBUG_TEST:
-      for i in self._to_cleanup:
-        if os.path.isdir(i):
-          shutil.rmtree(i, ignore_errors=True)
-        else:
-          os.remove(i)
-      del self._to_cleanup[:]
-    else:
-      print('Cleanup: ' + str(self._to_cleanup))
-
-  def create_temp_dir(self) -> str:
-    tmp_dir = tempfile.mkdtemp()
-    self._to_cleanup.append(tmp_dir)
-    return tmp_dir
-
-  def expand_apex(self, apex_file) -> None:
-    """expand an apex file include apex_payload."""
-    apex_dir = self.create_temp_dir()
-    with zipfile.ZipFile(apex_file, 'r') as apex_zip:
-      apex_zip.extractall(apex_dir)
-    extract_dir = os.path.join(apex_dir, 'payload_extract')
-    run_command([self.deapexer, '--debugfs_path', self.debugfs_static,
-                 '--fsckerofs_path', self.fsck_erofs,
-                 'extract', apex_file, extract_dir])
-
-    # remove /etc and /lost+found and /payload_extract/apex_manifest.pb
-    lost_and_found = os.path.join(extract_dir, 'lost+found')
-    etc_dir = os.path.join(extract_dir, 'etc')
-    os.remove(os.path.join(extract_dir, 'apex_manifest.pb'))
-    if os.path.isdir(lost_and_found):
-      shutil.rmtree(lost_and_found)
-    if os.path.isdir(etc_dir):
-      shutil.rmtree(etc_dir)
-
-    return apex_dir
-
-  def unzip_host_tools(self) -> None:
-    host_tools_dir = self.create_temp_dir()
-    with (
-      resources().joinpath('apexer_test_host_tools.zip').open(mode='rb') as host_tools_zip_resource,
-      resources().joinpath(TEST_PRIVATE_KEY).open(mode='rb') as key_file_resource,
-      resources().joinpath('apexer_with_DCLA_preprocessing').open(mode='rb') as apexer_wrapper_resource,
-    ):
-      with zipfile.ZipFile(host_tools_zip_resource, 'r') as zip_obj:
-        zip_obj.extractall(host_tools_dir)
-      apexer_wrapper = os.path.join(host_tools_dir, 'apexer_with_DCLA_preprocessing')
-      with open(apexer_wrapper, 'wb') as f:
-        shutil.copyfileobj(apexer_wrapper_resource, f)
-      key_file = os.path.join(host_tools_dir, 'key.pem')
-      with open(key_file, 'wb') as f:
-        shutil.copyfileobj(key_file_resource, f)
-
-
-    self.apexer_tool_path = os.path.join(host_tools_dir, 'bin')
-    self.apexer_wrapper = apexer_wrapper
-    self.key_file = key_file
-    self.deapexer = os.path.join(host_tools_dir, 'bin/deapexer')
-    self.debugfs_static = os.path.join(host_tools_dir, 'bin/debugfs_static')
-    self.fsck_erofs = os.path.join(host_tools_dir, 'bin/fsck.erofs')
-    self.android_jar = os.path.join(host_tools_dir, 'bin/android.jar')
-    self.apexer = os.path.join(host_tools_dir, 'bin/apexer')
-    os.chmod(apexer_wrapper, stat.S_IRUSR | stat.S_IXUSR);
-    for i in ['apexer', 'deapexer', 'avbtool', 'mke2fs', 'sefcontext_compile', 'e2fsdroid',
-      'resize2fs', 'soong_zip', 'aapt2', 'merge_zips', 'zipalign', 'debugfs_static',
-      'signapk.jar', 'android.jar', 'fsck.erofs']:
-      file_path = os.path.join(host_tools_dir, 'bin', i)
-      if os.path.exists(file_path):
-        os.chmod(file_path, stat.S_IRUSR | stat.S_IXUSR);
-
-
-  def test_DCLA_preprocessing(self):
-    """test DCLA preprocessing done properly."""
-    with resources().joinpath(TEST_APEX + '.apex').open(mode='rb') as apex_file_obj:
-      tmp_dir = self.create_temp_dir()
-      apex_file = os.path.join(tmp_dir, TEST_APEX + '.apex')
-      with open(apex_file, 'wb') as f:
-        shutil.copyfileobj(apex_file_obj, f)
-    apex_dir = self.expand_apex(apex_file)
-
-    # create apex canned_fs_config file, TEST_APEX does not come with one
-    canned_fs_config_file = os.path.join(apex_dir, 'canned_fs_config')
-    with open(canned_fs_config_file, 'w') as f:
-      # add /lib/foo.so file
-      lib_dir = os.path.join(apex_dir, 'payload_extract', 'lib')
-      os.makedirs(lib_dir)
-      foo_file = os.path.join(lib_dir, 'foo.so')
-      with open(foo_file, 'w') as lib_file:
-        lib_file.write('This is a placeholder lib file.')
-      foo_digest = get_digest(foo_file)
-
-      # add /lib dir and /lib/foo.so in canned_fs_config
-      f.write('/lib 0 2000 0755\n')
-      f.write('/lib/foo.so 1000 1000 0644\n')
-
-      # add /lib/bar.so file
-      lib_dir = os.path.join(apex_dir, 'payload_extract', 'lib64')
-      os.makedirs(lib_dir)
-      bar_file = os.path.join(lib_dir, 'bar.so')
-      with open(bar_file, 'w') as lib_file:
-        lib_file.write('This is another placeholder lib file.')
-      bar_digest = get_digest(bar_file)
-
-      # add /lib dir and /lib/foo.so in canned_fs_config
-      f.write('/lib64 0 2000 0755\n')
-      f.write('/lib64/bar.so 1000 1000 0644\n')
-
-      f.write('/ 0 2000 0755\n')
-      f.write('/apex_manifest.pb 1000 1000 0644\n')
-
-    # call apexer_with_DCLA_preprocessing
-    manifest_file = os.path.join(apex_dir, 'apex_manifest.pb')
-    build_info_file = os.path.join(apex_dir, 'apex_build_info.pb')
-    apex_out = os.path.join(apex_dir, 'DCLA_preprocessed_output.apex')
-    run_command([self.apexer_wrapper,
-                 '--apexer', self.apexer,
-                 '--canned_fs_config', canned_fs_config_file,
-                 os.path.join(apex_dir, 'payload_extract'),
-                 apex_out,
-                 '--',
-                 '--android_jar_path', self.android_jar,
-                 '--apexer_tool_path', self.apexer_tool_path,
-                 '--key', self.key_file,
-                 '--manifest', manifest_file,
-                 '--build_info', build_info_file,
-                 '--payload_fs_type', 'ext4',
-                 '--payload_type', 'image',
-                 '--force'
-                 ])
-
-    # check the existence of updated canned_fs_config
-    updated_canned_fs_config = os.path.join(apex_dir, 'updated_canned_fs_config')
-    self.assertTrue(
-        os.path.isfile(updated_canned_fs_config),
-        'missing updated canned_fs_config file named updated_canned_fs_config')
-
-    # check the resulting apex, it should have /lib/foo.so/<hash>/foo.so and
-    # /lib64/bar.so/<hash>/bar.so
-    result_apex_dir = self.expand_apex(apex_out)
-    replaced_foo = os.path.join(
-        result_apex_dir, f'payload_extract/lib/foo.so/{foo_digest}/foo.so')
-    replaced_bar = os.path.join(
-        result_apex_dir, f'payload_extract/lib64/bar.so/{bar_digest}/bar.so')
-    self.assertTrue(
-        os.path.isfile(replaced_foo),
-        f'expecting /lib/foo.so/{foo_digest}/foo.so')
-    self.assertTrue(
-        os.path.isfile(replaced_bar),
-        f'expecting /lib64/bar.so/{bar_digest}/bar.so')
-
-if __name__ == '__main__':
-  unittest.main(verbosity=2)
diff --git a/tools/host-apex-verifier.sh b/tools/host-apex-verifier.sh
deleted file mode 100755
index 125c9b73..00000000
--- a/tools/host-apex-verifier.sh
+++ /dev/null
@@ -1,32 +0,0 @@
-#!/bin/bash
-set -x
-
-echo "Pulling APEXes from the device factory APEX directories."
-TEMP_DIR="`mktemp -d`"
-adb pull /system/apex/ $TEMP_DIR/system
-adb pull /system_ext/apex/ $TEMP_DIR/system_ext
-adb pull /product/apex/ $TEMP_DIR/product
-adb pull /vendor/apex/ $TEMP_DIR/vendor
-adb pull /odm/apex/ $TEMP_DIR/odm
-
-set -e
-
-echo "Running host_apex_verifier."
-SDK_VERSION="`adb shell getprop ro.build.version.sdk`"
-TEST_DIR=$(dirname $0)
-HOST_APEX_VERIFIER=$TEST_DIR/host_apex_verifier
-DEBUGFS=$TEST_DIR/debugfs_static
-DEAPEXER=$TEST_DIR/deapexer
-FSCKEROFS=$TEST_DIR/fsck.erofs
-$HOST_APEX_VERIFIER \
-  --deapexer $DEAPEXER \
-  --debugfs $DEBUGFS \
-  --fsckerofs $FSCKEROFS \
-  --sdk_version $SDK_VERSION \
-  --out_system $TEMP_DIR/system \
-  --out_system_ext $TEMP_DIR/system_ext \
-  --out_product $TEMP_DIR/product \
-  --out_vendor $TEMP_DIR/vendor \
-  --out_odm $TEMP_DIR/odm
-
-rm -rf $TEMP_DIR
diff --git a/tools/host-apex-verifier.xml b/tools/host-apex-verifier.xml
deleted file mode 100644
index 46ac96c6..00000000
--- a/tools/host-apex-verifier.xml
+++ /dev/null
@@ -1,22 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2022 The Android Open Source Project
-
-    Licensed under the Apache License, Version 2.0 (the "License");
-    you may not use this file except in compliance with the License.
-    You may obtain a copy of the License at
-
-        http://www.apache.org/licenses/LICENSE-2.0
-
-    Unless required by applicable law or agreed to in writing, software
-    distributed under the License is distributed on an "AS IS" BASIS,
-    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-    See the License for the specific language governing permissions and
-    limitations under the License.
--->
-<configuration description="Config for host_apex_verifier test">
-    <option name="test-suite-tag" value="host-apex-verifier" />
-    <!-- This test requires a device, so it's not annotated with a null-device -->
-    <test class="com.android.tradefed.testtype.binary.ExecutableHostTest" >
-        <option name="binary" value="host-apex-verifier" />
-    </test>
-</configuration>
diff --git a/tools/host_apex_verifier.cc b/tools/host_apex_verifier.cc
index 1c6704ca..81667e3f 100644
--- a/tools/host_apex_verifier.cc
+++ b/tools/host_apex_verifier.cc
@@ -41,10 +41,11 @@ passwd* getpwnam(const char*) {
   static char fake_buf[] = "fake";
   static passwd fake_passwd = {
       .pw_name = fake_buf,
-      .pw_dir = fake_buf,
-      .pw_shell = fake_buf,
+      .pw_passwd = nullptr,
       .pw_uid = 123,
       .pw_gid = 123,
+      .pw_dir = fake_buf,
+      .pw_shell = fake_buf,
   };
   return &fake_passwd;
 }
@@ -62,22 +63,14 @@ void PrintUsage(const std::string& msg = "") {
   }
   printf(R"(usage: host_apex_verifier [options]
 
-Tests APEX file(s) for correctness.
+Tests APEX file for correctness.
 
 Options:
-  --deapexer=PATH             Use the deapexer binary at this path when extracting APEXes.
-  --debugfs=PATH              Use the debugfs binary at this path when extracting APEXes.
-  --fsckerofs=PATH            Use the fsck.erofs binary at this path when extracting APEXes.
+  --deapexer=PATH             Use the deapexer binary at this path when extracting APEX.
+  --debugfs=PATH              Use the debugfs binary at this path when extracting APEX.
+  --fsckerofs=PATH            Use the fsck.erofs binary at this path when extracting APEX.
   --sdk_version=INT           The active system SDK version used when filtering versioned
                               init.rc files.
-for checking all APEXes:
-  --out_system=DIR            Path to the factory APEX directory for the system partition.
-  --out_system_ext=DIR        Path to the factory APEX directory for the system_ext partition.
-  --out_product=DIR           Path to the factory APEX directory for the product partition.
-  --out_vendor=DIR            Path to the factory APEX directory for the vendor partition.
-  --out_odm=DIR               Path to the factory APEX directory for the odm partition.
-
-for checking a single APEX:
   --apex=PATH                 Path to the target APEX.
   --partition_tag=[system|vendor|...] Partition for the target APEX.
 )");
@@ -177,37 +170,6 @@ void ScanApex(const std::string& deapexer, int sdk_version,
   CheckInitRc(extracted_apex_dir, manifest, sdk_version, is_vendor);
 }
 
-// Scan the factory APEX files in the partition apex dir.
-// Scans APEX files directly, rather than flattened ${PRODUCT_OUT}/apex/
-// directories. This allows us to check:
-//   - Prebuilt APEXes which do not flatten to that path.
-//   - Multi-installed APEXes, where only the default
-//     APEX may flatten to that path.
-//   - Extracted target_files archives which may not contain
-//     flattened <PARTITON>/apex/ directories.
-void ScanPartitionApexes(const std::string& deapexer, int sdk_version,
-                         const std::string& partition_dir,
-                         const std::string& partition_tag) {
-  LOG(INFO) << "Scanning " << partition_dir << " for factory APEXes in "
-            << partition_tag;
-
-  std::unique_ptr<DIR, decltype(&closedir)> apex_dir(
-      opendir(partition_dir.c_str()), closedir);
-  if (!apex_dir) {
-    LOG(WARNING) << "Unable to open dir " << partition_dir;
-    return;
-  }
-
-  dirent* entry;
-  while ((entry = readdir(apex_dir.get()))) {
-    if (base::EndsWith(entry->d_name, ".apex") ||
-        base::EndsWith(entry->d_name, ".capex")) {
-      ScanApex(deapexer, sdk_version, partition_dir + "/" + entry->d_name,
-               partition_tag);
-    }
-  }
-}
-
 }  // namespace
 
 int main(int argc, char** argv) {
@@ -219,11 +181,10 @@ int main(int argc, char** argv) {
   const char* host_out = getenv("ANDROID_HOST_OUT");
   if (host_out) {
     deapexer = std::string(host_out) + "/bin/deapexer";
-    debugfs = std::string(host_out) + "/bin/debugfs_static";
+    debugfs = std::string(host_out) + "/bin/debugfs";
     fsckerofs = std::string(host_out) + "/bin/fsck.erofs";
   }
   int sdk_version = INT_MAX;
-  std::map<std::string, std::string> partition_map;
   std::string apex;
   std::string partition_tag;
 
@@ -234,11 +195,6 @@ int main(int argc, char** argv) {
         {"debugfs", required_argument, nullptr, 0},
         {"fsckerofs", required_argument, nullptr, 0},
         {"sdk_version", required_argument, nullptr, 0},
-        {"out_system", required_argument, nullptr, 0},
-        {"out_system_ext", required_argument, nullptr, 0},
-        {"out_product", required_argument, nullptr, 0},
-        {"out_vendor", required_argument, nullptr, 0},
-        {"out_odm", required_argument, nullptr, 0},
         {"apex", required_argument, nullptr, 0},
         {"partition_tag", required_argument, nullptr, 0},
         {nullptr, 0, nullptr, 0},
@@ -273,12 +229,11 @@ int main(int argc, char** argv) {
           apex = optarg;
         }
         if (name == "partition_tag") {
-          partition_tag = optarg;
-        }
-        for (const auto& p : partitions) {
-          if (name == "out_" + p) {
-            partition_map[p] = optarg;
+          if (std::ranges::count(partitions, optarg) == 0) {
+            PrintUsage();
+            return EXIT_FAILURE;
           }
+          partition_tag = optarg;
         }
         break;
       }
@@ -298,34 +253,15 @@ int main(int argc, char** argv) {
     PrintUsage();
     return EXIT_FAILURE;
   }
-  if (deapexer.empty() || debugfs.empty() || fsckerofs.empty()) {
+  if (deapexer.empty() || debugfs.empty() || fsckerofs.empty() ||
+      apex.empty() || partition_tag.empty()) {
     PrintUsage();
     return EXIT_FAILURE;
   }
   deapexer += " --debugfs_path " + debugfs;
   deapexer += " --fsckerofs_path " + fsckerofs;
 
-  if (!!apex.empty() + !!partition_map.empty() != 1) {
-    PrintUsage("use either --apex or --out_<partition>.\n");
-    return EXIT_FAILURE;
-  }
-  if (!apex.empty()) {
-    if (std::find(partitions.begin(), partitions.end(), partition_tag) ==
-        partitions.end()) {
-      PrintUsage(
-          "--apex should come with "
-          "--partition_tag=[system|system_ext|product|vendor|odm].\n");
-      return EXIT_FAILURE;
-    }
-  }
-
-  if (!partition_map.empty()) {
-    for (const auto& [partition, dir] : partition_map) {
-      ScanPartitionApexes(deapexer, sdk_version, dir, partition);
-    }
-  } else {
-    ScanApex(deapexer, sdk_version, apex, partition_tag);
-  }
+  ScanApex(deapexer, sdk_version, apex, partition_tag);
   return EXIT_SUCCESS;
 }
 
```

