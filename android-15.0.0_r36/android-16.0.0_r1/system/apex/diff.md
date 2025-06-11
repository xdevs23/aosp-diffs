```diff
diff --git a/apexd/Android.bp b/apexd/Android.bp
index a402fdc8..12bbfb32 100644
--- a/apexd/Android.bp
+++ b/apexd/Android.bp
@@ -80,6 +80,7 @@ cc_defaults {
     name: "libapexd-deps",
     defaults: ["libapex-deps"],
     shared_libs: [
+        "libfs_mgr",
         "liblog",
         "liblogwrap",
         "libvintf",
@@ -119,6 +120,9 @@ aidl_interface {
         ndk: {
             enabled: false,
         },
+        rust: {
+            enabled: true,
+        },
     },
 }
 
@@ -136,7 +140,7 @@ cc_binary {
     ],
     shared_libs: [
         "server_configurable_flags",
-        "brand_new_apex_flag_c_lib",
+        "apexd_flags_c_lib",
     ],
     static_libs: [
         "libapex",
@@ -171,6 +175,7 @@ cc_binary {
         "libprotobuf-cpp-full-ndk",
     ],
     exclude_shared_libs: [
+        "libfs_mgr",
         "libprotobuf-cpp-full",
         "libvintf",
     ],
@@ -198,6 +203,7 @@ cc_library_static {
         "apexd_brand_new_verifier.cpp",
         "apexd.cpp",
         "apexd_dm.cpp",
+        "apexd_image_manager.cpp",
         "apexd_lifecycle.cpp",
         "apexd_loop.cpp",
         "apexd_metrics.cpp",
@@ -340,7 +346,7 @@ java_genrule {
     // dm-verity verification to fail
     name: "gen_corrupt_apex",
     out: ["apex.apexd_test_corrupt_apex.apex"],
-    srcs: [":apex.apexd_test"],
+    srcs: [":apex.apexd_test_for_corruption"],
     tools: [
         "soong_zip",
         "zipalign",
@@ -557,6 +563,7 @@ cc_test {
         "apex_file_repository_test.cpp",
         "apex_manifest_test.cpp",
         "apexd_brand_new_verifier_test.cpp",
+        "apexd_image_manager_test.cpp",
         "apexd_test.cpp",
         "apexd_session_test.cpp",
         "apexd_utils_test.cpp",
@@ -594,11 +601,6 @@ cc_test {
     ],
     data: [
         ":apex.apexd_test",
-        ":apex.apexd_test_erofs",
-        ":apex.apexd_test_f2fs",
-        ":apex.apexd_test_digest",
-        ":apex.apexd_test_erofs_digest",
-        ":apex.apexd_test_f2fs_digest",
         ":apex.apexd_test_classpath",
         ":apex.apexd_test_different_app",
         ":apex.apexd_test_no_inst_key",
@@ -745,13 +747,13 @@ genrule {
 }
 
 aconfig_declarations {
-    name: "enable_brand_new_apex",
+    name: "apexd_flags",
     package: "com.android.apex.flags",
     srcs: ["apexd.aconfig"],
     container: "system",
 }
 
 cc_aconfig_library {
-    name: "brand_new_apex_flag_c_lib",
-    aconfig_declarations: "enable_brand_new_apex",
+    name: "apexd_flags_c_lib",
+    aconfig_declarations: "apexd_flags",
 }
diff --git a/apexd/aidl/android/apex/IApexService.aidl b/apexd/aidl/android/apex/IApexService.aidl
index c65bf7ab..32be9ec7 100644
--- a/apexd/aidl/android/apex/IApexService.aidl
+++ b/apexd/aidl/android/apex/IApexService.aidl
@@ -66,12 +66,6 @@ interface IApexService {
 
    void unstagePackages(in @utf8InCpp List<String> active_package_paths);
 
-   /**
-    * Returns the active package corresponding to |package_name| and null
-    * if none exists.
-    */
-   ApexInfo getActivePackage(in @utf8InCpp String package_name);
-
    /**
     * Not meant for use outside of testing. The call will not be
     * functional on user builds.
diff --git a/apexd/apex_constants.h b/apexd/apex_constants.h
index f2562ca7..0cecee8c 100644
--- a/apexd/apex_constants.h
+++ b/apexd/apex_constants.h
@@ -32,6 +32,8 @@ static constexpr const char* kActiveApexPackagesDataDir = "/data/apex/active";
 static constexpr const char* kApexBackupDir = "/data/apex/backup";
 static constexpr const char* kApexDecompressedDir = "/data/apex/decompressed";
 static constexpr const char* kOtaReservedDir = "/data/apex/ota_reserved";
+static constexpr const char* kMetadataImagesDir = "/metadata/apex/images";
+static constexpr const char* kDataImagesDir = "/data/apex/images";
 static constexpr const char* kApexPackageSystemDir = "/system/apex";
 static constexpr const char* kApexPackageSystemExtDir = "/system_ext/apex";
 static constexpr const char* kApexPackageProductDir = "/product/apex";
@@ -69,7 +71,7 @@ static constexpr const char* kOtaApexPackageSuffix = ".ota.apex";
 static constexpr const char* kManifestFilenameJson = "apex_manifest.json";
 static constexpr const char* kManifestFilenamePb = "apex_manifest.pb";
 
-static constexpr const char* kApexInfoList = "apex-info-list.xml";
+static constexpr const char* kApexInfoList = "/apex/apex-info-list.xml";
 
 // These should be in-sync with system/sepolicy/private/property_contexts
 static constexpr const char* kApexStatusSysprop = "apexd.status";
diff --git a/apexd/apex_database.h b/apexd/apex_database.h
index 8277c4f8..c963a38c 100644
--- a/apexd/apex_database.h
+++ b/apexd/apex_database.h
@@ -62,26 +62,16 @@ class MountedApexDatabase {
   template <typename... Args>
   inline void AddMountedApexLocked(const std::string& package, Args&&... args)
       REQUIRES(mounted_apexes_mutex_) {
-    auto it = mounted_apexes_.find(package);
-    if (it == mounted_apexes_.end()) {
-      auto insert_it =
-          mounted_apexes_.emplace(package, std::set<MountedApexData>());
-      CHECK(insert_it.second);
-      it = insert_it.first;
-    }
-
-    auto check_it =
-        it->second.emplace(MountedApexData(std::forward<Args>(args)...));
-    CHECK(check_it.second);
-
-    CheckUniqueLoopDm();
+    auto [_, inserted] =
+        mounted_apexes_[package].emplace(std::forward<Args>(args)...);
+    CHECK(inserted);
   }
 
   template <typename... Args>
   inline void AddMountedApex(const std::string& package, Args&&... args)
       REQUIRES(!mounted_apexes_mutex_) {
     std::lock_guard lock(mounted_apexes_mutex_);
-    AddMountedApexLocked(package, args...);
+    AddMountedApexLocked(package, std::forward<Args>(args)...);
   }
 
   inline void RemoveMountedApex(const std::string& package,
@@ -150,7 +140,7 @@ class MountedApexDatabase {
   }
 
   inline std::optional<MountedApexData> GetLatestMountedApex(
-      const std::string& package) REQUIRES(!mounted_apexes_mutex_) {
+      const std::string& package) const REQUIRES(!mounted_apexes_mutex_) {
     std::optional<MountedApexData> ret;
     ForallMountedApexes(package,
                         [&ret](const MountedApexData& data, bool latest) {
@@ -186,23 +176,6 @@ class MountedApexDatabase {
     const Mutex& operator!() const { return *this; }
   };
   mutable Mutex mounted_apexes_mutex_;
-
-  inline void CheckUniqueLoopDm() REQUIRES(mounted_apexes_mutex_) {
-    std::unordered_set<std::string> loop_devices;
-    std::unordered_set<std::string> dm_devices;
-    for (const auto& apex_set : mounted_apexes_) {
-      for (const auto& mount : apex_set.second) {
-        if (mount.loop_name != "") {
-          CHECK(loop_devices.insert(mount.loop_name).second)
-              << "Duplicate loop device: " << mount.loop_name;
-        }
-        if (mount.device_name != "") {
-          CHECK(dm_devices.insert(mount.device_name).second)
-              << "Duplicate dm device: " << mount.device_name;
-        }
-      }
-    }
-  }
 };
 
 }  // namespace apex
diff --git a/apexd/apex_database_test.cpp b/apexd/apex_database_test.cpp
index 9af9a646..682810f3 100644
--- a/apexd/apex_database_test.cpp
+++ b/apexd/apex_database_test.cpp
@@ -166,33 +166,6 @@ TEST(ApexDatabaseTest, GetLatestMountedApexReturnsNullopt) {
   ASSERT_FALSE(ret.has_value());
 }
 
-#pragma clang diagnostic push
-// error: 'ReturnSentinel' was marked unused but was used
-// [-Werror,-Wused-but-marked-unused]
-#pragma clang diagnostic ignored "-Wused-but-marked-unused"
-
-TEST(MountedApexDataTest, NoDuplicateLoopDataLoopDevices) {
-  ASSERT_DEATH(
-      {
-        MountedApexDatabase db;
-        db.AddMountedApex("package", 0, "loop", "path", "mount", "dm");
-        db.AddMountedApex("package2", 0, "loop", "path2", "mount2", "dm2");
-      },
-      "Duplicate loop device: loop");
-}
-
-TEST(MountedApexDataTest, NoDuplicateDm) {
-  ASSERT_DEATH(
-      {
-        MountedApexDatabase db;
-        db.AddMountedApex("package", 0, "loop", "path", "mount", "dm");
-        db.AddMountedApex("package2", 0, "loop2", "path2", "mount2", "dm");
-      },
-      "Duplicate dm device: dm");
-}
-
-#pragma clang diagnostic pop
-
 }  // namespace
 }  // namespace apex
 }  // namespace android
diff --git a/apexd/apex_file.cpp b/apexd/apex_file.cpp
index 9ed48aa1..1ca6cfeb 100644
--- a/apexd/apex_file.cpp
+++ b/apexd/apex_file.cpp
@@ -430,7 +430,7 @@ Result<void> ApexFile::Decompress(const std::string& dest_path) const {
 
   // Open destination file descriptor
   unique_fd dest_fd(
-      open(dest_path.c_str(), O_WRONLY | O_CLOEXEC | O_CREAT | O_EXCL, 0644));
+      open(dest_path.c_str(), O_WRONLY | O_CLOEXEC | O_CREAT | O_EXCL | O_SYNC, 0644));
   if (dest_fd.get() == -1) {
     return ErrnoError() << "Failed to open decompression destination "
                         << dest_path.c_str();
diff --git a/apexd/apex_file_repository.cpp b/apexd/apex_file_repository.cpp
index 6b98ed7e..b6c8d5d3 100644
--- a/apexd/apex_file_repository.cpp
+++ b/apexd/apex_file_repository.cpp
@@ -16,6 +16,7 @@
 
 #include "apex_file_repository.h"
 
+#include <ApexProperties.sysprop.h>
 #include <android-base/file.h>
 #include <android-base/properties.h>
 #include <android-base/result.h>
@@ -25,6 +26,8 @@
 
 #include <cstdint>
 #include <filesystem>
+#include <future>
+#include <queue>
 #include <unordered_map>
 
 #include "apex_blocklist.h"
@@ -62,101 +65,167 @@ std::string GetApexSelectFilenameFromProp(
   return "";
 }
 
-Result<void> ApexFileRepository::ScanBuiltInDir(const std::string& dir,
-                                                ApexPartition partition) {
-  LOG(INFO) << "Scanning " << dir << " for pre-installed ApexFiles";
-  if (access(dir.c_str(), F_OK) != 0 && errno == ENOENT) {
-    LOG(WARNING) << dir << " does not exist. Skipping";
-    return {};
+void ApexFileRepository::StorePreInstalledApex(ApexFile&& apex_file,
+                                               ApexPartition partition) {
+  const std::string& name = apex_file.GetManifest().name();
+
+  // Check if this APEX name is treated as a multi-install APEX.
+  //
+  // Note: apexd is a oneshot service which runs at boot, but can be
+  // restarted when needed (such as staging an APEX update). If a
+  // multi-install select property changes between boot and when apexd
+  // restarts, the LOG messages below will report the version that will be
+  // activated on next reboot, which may differ from the currently-active
+  // version.
+  std::string select_filename =
+      GetApexSelectFilenameFromProp(multi_install_select_prop_prefixes_, name);
+  if (!select_filename.empty()) {
+    std::string path;
+    if (!android::base::Realpath(apex_file.GetPath(), &path)) {
+      LOG(ERROR) << "Unable to resolve realpath of APEX with path "
+                 << apex_file.GetPath();
+      return;
+    }
+    if (enforce_multi_install_partition_ &&
+        partition != ApexPartition::Vendor && partition != ApexPartition::Odm) {
+      LOG(ERROR) << "Multi-install APEX " << path
+                 << " can only be preinstalled on /{odm,vendor}/apex/.";
+      return;
+    }
+
+    auto& keys = multi_install_public_keys_[name];
+    keys.insert(apex_file.GetBundledPublicKey());
+    if (keys.size() > 1) {
+      LOG(ERROR) << "Multi-install APEXes for " << name
+                 << " have different public keys.";
+      // If any versions of a multi-installed APEX differ in public key,
+      // then no version should be installed.
+      if (auto it = pre_installed_store_.find(name);
+          it != pre_installed_store_.end()) {
+        pre_installed_store_.erase(it);
+        partition_store_.erase(name);
+      }
+      return;
+    }
+
+    if (ConsumeApexPackageSuffix(android::base::Basename(path)) ==
+        select_filename) {
+      LOG(INFO) << "Found APEX at path " << path << " for multi-install APEX "
+                << name;
+      // A copy is needed because apex_file is moved here
+      const std::string apex_name = name;
+      // Add the APEX file to the store if its filename matches the
+      // property.
+      pre_installed_store_.emplace(apex_name, std::move(apex_file));
+      partition_store_.emplace(apex_name, partition);
+    } else {
+      LOG(INFO) << "Skipping APEX at path " << path
+                << " because it does not match expected multi-install"
+                << " APEX property for " << name;
+    }
+
+    return;
   }
 
-  Result<std::vector<std::string>> all_apex_files = FindFilesBySuffix(
-      dir, {kApexPackageSuffix, kCompressedApexPackageSuffix});
-  if (!all_apex_files.ok()) {
-    return all_apex_files.error();
+  auto it = pre_installed_store_.find(name);
+  if (it == pre_installed_store_.end()) {
+    // A copy is needed because apex_file is moved here
+    const std::string apex_name = name;
+    pre_installed_store_.emplace(apex_name, std::move(apex_file));
+    partition_store_.emplace(apex_name, partition);
+  } else if (it->second.GetPath() != apex_file.GetPath()) {
+    LOG(FATAL) << "Found two apex packages " << it->second.GetPath() << " and "
+               << apex_file.GetPath() << " with the same module name " << name;
+  } else if (it->second.GetBundledPublicKey() !=
+             apex_file.GetBundledPublicKey()) {
+    LOG(FATAL) << "Public key of apex package " << it->second.GetPath() << " ("
+               << name << ") has unexpectedly changed";
   }
+}
 
-  // TODO(b/179248390): scan parallelly if possible
-  for (const auto& file : *all_apex_files) {
-    LOG(INFO) << "Found pre-installed APEX " << file;
-    Result<ApexFile> apex_file = ApexFile::Open(file);
-    if (!apex_file.ok()) {
-      return Error() << "Failed to open " << file << " : " << apex_file.error();
+Result<std::vector<ApexPath>> ApexFileRepository::CollectPreInstalledApex(
+    const std::unordered_map<ApexPartition, std::string>&
+        partition_to_prebuilt_dirs) {
+  std::vector<ApexPath> all_apex_paths;
+  for (const auto& [partition, dir] : partition_to_prebuilt_dirs) {
+    LOG(INFO) << "Scanning " << dir << " for pre-installed ApexFiles";
+    if (access(dir.c_str(), F_OK) != 0 && errno == ENOENT) {
+      LOG(WARNING) << dir << " does not exist. Skipping";
+      continue;
     }
 
-    const std::string& name = apex_file->GetManifest().name();
-
-    // Check if this APEX name is treated as a multi-install APEX.
-    //
-    // Note: apexd is a oneshot service which runs at boot, but can be restarted
-    // when needed (such as staging an APEX update). If a multi-install select
-    // property changes between boot and when apexd restarts, the LOG messages
-    // below will report the version that will be activated on next reboot,
-    // which may differ from the currently-active version.
-    std::string select_filename = GetApexSelectFilenameFromProp(
-        multi_install_select_prop_prefixes_, name);
-    if (!select_filename.empty()) {
-      std::string path;
-      if (!android::base::Realpath(apex_file->GetPath(), &path)) {
-        LOG(ERROR) << "Unable to resolve realpath of APEX with path "
-                   << apex_file->GetPath();
-        continue;
-      }
-      if (enforce_multi_install_partition_ &&
-          partition != ApexPartition::Vendor &&
-          partition != ApexPartition::Odm) {
-        LOG(ERROR) << "Multi-install APEX " << path
-                   << " can only be preinstalled on /{odm,vendor}/apex/.";
-        continue;
-      }
+    std::vector<std::string> apex_paths = OR_RETURN(FindFilesBySuffix(
+        dir, {kApexPackageSuffix, kCompressedApexPackageSuffix}));
+    for (auto&& path : apex_paths) {
+      LOG(INFO) << "Found pre-installed APEX " << path;
+      all_apex_paths.emplace_back(std::move(path), partition);
+    }
+  }
+  return all_apex_paths;
+}
 
-      auto& keys = multi_install_public_keys_[name];
-      keys.insert(apex_file->GetBundledPublicKey());
-      if (keys.size() > 1) {
-        LOG(ERROR) << "Multi-install APEXes for " << name
-                   << " have different public keys.";
-        // If any versions of a multi-installed APEX differ in public key,
-        // then no version should be installed.
-        if (auto it = pre_installed_store_.find(name);
-            it != pre_installed_store_.end()) {
-          pre_installed_store_.erase(it);
-          partition_store_.erase(name);
-        }
-        continue;
-      }
+Result<std::vector<ApexFileAndPartition>> ApexFileRepository::OpenApexFiles(
+    const std::vector<ApexPath>& apex_paths) {
+  std::atomic_size_t shared_index{0};
+  size_t apex_count = apex_paths.size();
+
+  size_t worker_num =
+      android::sysprop::ApexProperties::apex_file_open_threads().value_or(0);
+  if (worker_num == 0) {
+    worker_num = apex_count;
+  } else {
+    worker_num = std::min(apex_count, worker_num);
+  }
 
-      if (ConsumeApexPackageSuffix(android::base::Basename(path)) ==
-          select_filename) {
-        LOG(INFO) << "Found APEX at path " << path << " for multi-install APEX "
-                  << name;
-        // Add the APEX file to the store if its filename matches the property.
-        pre_installed_store_.emplace(name, std::move(*apex_file));
-        partition_store_.emplace(name, partition);
-      } else {
-        LOG(INFO) << "Skipping APEX at path " << path
-                  << " because it does not match expected multi-install"
-                  << " APEX property for " << name;
-      }
+  struct IndexedApexFile {
+    ApexFileAndPartition apex_file;
+    size_t index;
+  };
+  std::vector<std::future<Result<std::vector<IndexedApexFile>>>> futures;
+  futures.reserve(worker_num);
+
+  for (size_t i = 0; i < worker_num; i++) {
+    futures.push_back(std::async(
+        std::launch::async,
+        [&shared_index, apex_paths,
+         apex_count]() -> Result<std::vector<IndexedApexFile>> {
+          std::vector<IndexedApexFile> ret;
+          size_t current_index;
+          while ((current_index = shared_index.fetch_add(
+                      1, std::memory_order_relaxed)) < apex_count) {
+            const ApexPath& apex_path = apex_paths[current_index];
+            Result<ApexFile> apex_file = ApexFile::Open(apex_path.path);
+            if (apex_file.ok()) {
+              ret.emplace_back(ApexFileAndPartition(std::move(*apex_file),
+                                                    apex_path.partition),
+                               current_index);
+            } else {
+              return Error() << "Failed to open apex file " << apex_path.path
+                             << " : " << apex_file.error();
+            }
+          }
+          return {ret};
+        }));
+  }
 
-      continue;
+  std::vector<std::optional<ApexFileAndPartition>> optional_apex_files;
+  optional_apex_files.resize(apex_count);
+  for (auto& future : futures) {
+    auto res = OR_RETURN(future.get());
+    for (auto&& indexed_apex_file : res) {
+      optional_apex_files[indexed_apex_file.index] =
+          std::move(indexed_apex_file.apex_file);
     }
+  }
 
-    auto it = pre_installed_store_.find(name);
-    if (it == pre_installed_store_.end()) {
-      pre_installed_store_.emplace(name, std::move(*apex_file));
-      partition_store_.emplace(name, partition);
-    } else if (it->second.GetPath() != apex_file->GetPath()) {
-      LOG(FATAL) << "Found two apex packages " << it->second.GetPath()
-                 << " and " << apex_file->GetPath()
-                 << " with the same module name " << name;
-    } else if (it->second.GetBundledPublicKey() !=
-               apex_file->GetBundledPublicKey()) {
-      LOG(FATAL) << "Public key of apex package " << it->second.GetPath()
-                 << " (" << name << ") has unexpectedly changed";
+  std::vector<ApexFileAndPartition> apex_files;
+  apex_files.reserve(apex_count);
+  for (auto&& optional_apex_file : optional_apex_files) {
+    if (optional_apex_file.has_value()) {
+      apex_files.push_back(optional_apex_file.value());
     }
   }
-  multi_install_public_keys_.clear();
-  return {};
+  return apex_files;
 }
 
 ApexFileRepository& ApexFileRepository::GetInstance() {
@@ -167,11 +236,34 @@ ApexFileRepository& ApexFileRepository::GetInstance() {
 android::base::Result<void> ApexFileRepository::AddPreInstalledApex(
     const std::unordered_map<ApexPartition, std::string>&
         partition_to_prebuilt_dirs) {
-  for (const auto& [partition, dir] : partition_to_prebuilt_dirs) {
-    if (auto result = ScanBuiltInDir(dir, partition); !result.ok()) {
-      return result.error();
+  auto all_apex_paths =
+      OR_RETURN(CollectPreInstalledApex(partition_to_prebuilt_dirs));
+
+  for (const auto& apex_path : all_apex_paths) {
+    Result<ApexFile> apex_file = ApexFile::Open(apex_path.path);
+    if (!apex_file.ok()) {
+      return Error() << "Failed to open " << apex_path.path << " : "
+                     << apex_file.error();
     }
+
+    StorePreInstalledApex(std::move(*apex_file), apex_path.partition);
+  }
+  multi_install_public_keys_.clear();
+  return {};
+}
+
+android::base::Result<void> ApexFileRepository::AddPreInstalledApexParallel(
+    const std::unordered_map<ApexPartition, std::string>&
+        partition_to_prebuilt_dirs) {
+  auto all_apex_paths =
+      OR_RETURN(CollectPreInstalledApex(partition_to_prebuilt_dirs));
+
+  auto apex_file_and_partition = OR_RETURN(OpenApexFiles(all_apex_paths));
+
+  for (auto&& [apex_file, partition] : apex_file_and_partition) {
+    StorePreInstalledApex(std::move(apex_file), partition);
   }
+  multi_install_public_keys_.clear();
   return {};
 }
 
@@ -250,6 +342,9 @@ Result<int> ApexFileRepository::AddBlockApex(
                      << apex_file.error();
     }
 
+    const std::string& name = apex_file->GetManifest().name();
+    LOG(INFO) << "Found host apex " << name << " at " << apex_path;
+
     // When metadata specifies the public key of the apex, it should match the
     // bundled key. Otherwise we accept it.
     if (apex_config.public_key() != "" &&
@@ -257,8 +352,6 @@ Result<int> ApexFileRepository::AddBlockApex(
       return Error() << "public key doesn't match: " << apex_path;
     }
 
-    const std::string& name = apex_file->GetManifest().name();
-
     // When metadata specifies the manifest name and version of the apex, it
     // should match what we see in the manifest.
     if (apex_config.manifest_name() != "" &&
@@ -469,8 +562,6 @@ Result<const std::string> ApexFileRepository::GetPublicKey(
   return it->second.GetBundledPublicKey();
 }
 
-// TODO(b/179497746): remove this method when we add api for fetching ApexFile
-//  by name
 Result<const std::string> ApexFileRepository::GetPreinstalledPath(
     const std::string& name) const {
   auto it = pre_installed_store_.find(name);
@@ -480,17 +571,6 @@ Result<const std::string> ApexFileRepository::GetPreinstalledPath(
   return it->second.GetPath();
 }
 
-// TODO(b/179497746): remove this method when we add api for fetching ApexFile
-//  by name
-Result<const std::string> ApexFileRepository::GetDataPath(
-    const std::string& name) const {
-  auto it = data_store_.find(name);
-  if (it == data_store_.end()) {
-    return Error() << "No data apex found for package " << name;
-  }
-  return it->second.GetPath();
-}
-
 std::optional<std::string> ApexFileRepository::GetBlockApexRootDigest(
     const std::string& path) const {
   auto it = block_apex_overrides_.find(path);
@@ -581,26 +661,13 @@ std::optional<int64_t> ApexFileRepository::GetBrandNewApexBlockedVersion(
 // Group pre-installed APEX and data APEX by name
 std::unordered_map<std::string, std::vector<ApexFileRef>>
 ApexFileRepository::AllApexFilesByName() const {
-  // Collect all apex files
-  std::vector<ApexFileRef> all_apex_files;
-  auto pre_installed_apexs = GetPreInstalledApexFiles();
-  auto data_apexs = GetDataApexFiles();
-  std::move(pre_installed_apexs.begin(), pre_installed_apexs.end(),
-            std::back_inserter(all_apex_files));
-  std::move(data_apexs.begin(), data_apexs.end(),
-            std::back_inserter(all_apex_files));
-
   // Group them by name
   std::unordered_map<std::string, std::vector<ApexFileRef>> result;
-  for (const auto& apex_file_ref : all_apex_files) {
-    const ApexFile& apex_file = apex_file_ref.get();
-    const std::string& package_name = apex_file.GetManifest().name();
-    if (result.find(package_name) == result.end()) {
-      result[package_name] = std::vector<ApexFileRef>{};
+  for (const auto* store : {&pre_installed_store_, &data_store_}) {
+    for (const auto& [name, apex] : *store) {
+      result[name].emplace_back(std::cref(apex));
     }
-    result[package_name].emplace_back(apex_file_ref);
   }
-
   return result;
 }
 
diff --git a/apexd/apex_file_repository.h b/apexd/apex_file_repository.h
index b1955229..8229b2d6 100644
--- a/apexd/apex_file_repository.h
+++ b/apexd/apex_file_repository.h
@@ -32,6 +32,16 @@ namespace android::apex {
 
 using ApexFileRef = std::reference_wrapper<const android::apex::ApexFile>;
 
+struct ApexPath {
+  std::string path;
+  ApexPartition partition;
+};
+
+struct ApexFileAndPartition {
+  ApexFile apex_file;
+  ApexPartition partition;
+};
+
 // This class serves as a ApexFile repository for all apexes on device. It also
 // provides information about the ApexFiles it hosts, such as which are
 // pre-installed and which are data. Such information can be used, for example,
@@ -63,6 +73,17 @@ class ApexFileRepository final {
       const std::unordered_map<ApexPartition, std::string>&
           partition_to_prebuilt_dirs);
 
+  // Populate instance by collecting pre-installed apex files from the given
+  // |partition_to_prebuilt_dirs|.
+  // The difference between this function and |AddPreInstalledApex| is that this
+  // function opens pre-installed apex files in parallel. Note: this call is
+  // **not thread safe** and is expected to be performed in a single thread
+  // during initialization of apexd. After initialization is finished, all
+  // queries to the instance are thread safe.
+  android::base::Result<void> AddPreInstalledApexParallel(
+      const std::unordered_map<ApexPartition, std::string>&
+          partition_to_prebuilt_dirs);
+
   // Populate instance by collecting host-provided apex files via
   // |metadata_partition|. Host can provide its apexes to a VM instance via the
   // virtual disk image which has partitions: (see
@@ -114,10 +135,6 @@ class ApexFileRepository final {
   android::base::Result<const std::string> GetPreinstalledPath(
       const std::string& name) const;
 
-  // Returns path to the data version of an apex with the given |name|.
-  android::base::Result<const std::string> GetDataPath(
-      const std::string& name) const;
-
   // Returns root digest of an apex with the given |path| for block apexes.
   std::optional<std::string> GetBlockApexRootDigest(
       const std::string& path) const;
@@ -200,10 +217,18 @@ class ApexFileRepository final {
   ApexFileRepository& operator=(ApexFileRepository&&) = delete;
   ApexFileRepository(ApexFileRepository&&) = delete;
 
-  // Scans apexes in the given directory and adds collected data into
-  // |pre_installed_store_| and |partition_store_|.
-  android::base::Result<void> ScanBuiltInDir(const std::string& dir,
-                                             ApexPartition partition);
+  // Stores the given single apex data into |pre_installed_store_| and
+  // |partition_store_|.
+  void StorePreInstalledApex(ApexFile&& apex_file, ApexPartition partition);
+
+  // Scans and returns apexes in the given directories.
+  android::base::Result<std::vector<ApexPath>> CollectPreInstalledApex(
+      const std::unordered_map<ApexPartition, std::string>&
+          partition_to_prebuilt_dirs);
+
+  // Opens and returns the apexes in the given paths.
+  android::base::Result<std::vector<ApexFileAndPartition>> OpenApexFiles(
+      const std::vector<ApexPath>& apex_paths);
 
   std::unordered_map<std::string, ApexFile> pre_installed_store_, data_store_;
 
diff --git a/apexd/apex_file_repository_test.cpp b/apexd/apex_file_repository_test.cpp
index 067f5d11..2c22864f 100644
--- a/apexd/apex_file_repository_test.cpp
+++ b/apexd/apex_file_repository_test.cpp
@@ -48,7 +48,6 @@ using namespace std::literals;
 namespace fs = std::filesystem;
 
 using android::apex::testing::ApexFileEq;
-using android::base::GetExecutableDirectory;
 using android::base::StringPrintf;
 using android::base::testing::Ok;
 using ::testing::ByRef;
@@ -56,11 +55,6 @@ using ::testing::ContainerEq;
 using ::testing::Not;
 using ::testing::UnorderedElementsAre;
 
-static std::string GetTestDataDir() { return GetExecutableDirectory(); }
-static std::string GetTestFile(const std::string& name) {
-  return GetTestDataDir() + "/" + name;
-}
-
 namespace {
 // Copies the compressed apex to |built_in_dir| and decompresses it to
 // |decompression_dir
@@ -115,12 +109,6 @@ TEST(ApexFileRepositoryTest, InitializeSuccess) {
                 *ret);
     }
 
-    {
-      auto ret = instance.GetDataPath(apex->GetManifest().name());
-      ASSERT_RESULT_OK(ret);
-      ASSERT_EQ(StringPrintf("%s/%s", data_dir.path, apex_name.c_str()), *ret);
-    }
-
     {
       auto ret = instance.GetPartition(*apex);
       ASSERT_RESULT_OK(ret);
@@ -143,6 +131,28 @@ TEST(ApexFileRepositoryTest, InitializeSuccess) {
   test_fn("apex.apexd_test_different_app.apex");
 }
 
+TEST(ApexFileRepositoryTest, AddPreInstalledApexParallel) {
+  TemporaryDir built_in_dir;
+  fs::copy(GetTestFile("apex.apexd_test.apex"), built_in_dir.path);
+  fs::copy(GetTestFile("apex.apexd_test_different_app.apex"),
+           built_in_dir.path);
+  ApexPartition partition = ApexPartition::System;
+  std::unordered_map<ApexPartition, std::string> apex_dir = {
+      {partition, built_in_dir.path}};
+
+  ApexFileRepository instance0;
+  instance0.AddPreInstalledApex(apex_dir);
+  auto expected = instance0.GetPreInstalledApexFiles();
+
+  ApexFileRepository instance;
+  ASSERT_RESULT_OK(instance.AddPreInstalledApexParallel(apex_dir));
+  auto actual = instance.GetPreInstalledApexFiles();
+  ASSERT_EQ(actual.size(), expected.size());
+  for (size_t i = 0; i < actual.size(); ++i) {
+    ASSERT_THAT(actual[i], ApexFileEq(expected[i]));
+  }
+}
+
 TEST(ApexFileRepositoryTest, InitializeFailureCorruptApex) {
   // Prepare test data.
   TemporaryDir td;
@@ -1099,13 +1109,6 @@ TEST(ApexFileRepositoryTestBrandNewApex,
 
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
-  {
-    auto ret = instance.GetDataPath(apex->GetManifest().name());
-    ASSERT_RESULT_OK(ret);
-    ASSERT_EQ(StringPrintf("%s/com.android.apex.brand.new.apex", data_dir.path),
-              *ret);
-  }
-
   {
     auto ret = instance.GetPartition(*apex);
     ASSERT_RESULT_OK(ret);
@@ -1131,7 +1134,6 @@ TEST(ApexFileRepositoryTestBrandNewApex,
   ASSERT_RESULT_OK(apex);
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
-  ASSERT_THAT(instance.GetDataPath(apex->GetManifest().name()), Not(Ok()));
   ASSERT_FALSE(instance.HasDataVersion(apex->GetManifest().name()));
   instance.Reset();
 }
@@ -1145,7 +1147,6 @@ TEST(ApexFileRepositoryTestBrandNewApex, AddDataApexFailBrandNewApexDisabled) {
   ASSERT_RESULT_OK(apex);
   ASSERT_RESULT_OK(instance.AddDataApex(data_dir.path));
 
-  ASSERT_THAT(instance.GetDataPath(apex->GetManifest().name()), Not(Ok()));
   ASSERT_FALSE(instance.HasDataVersion(apex->GetManifest().name()));
   instance.Reset();
 }
diff --git a/apexd/apexd.aconfig b/apexd/apexd.aconfig
index 89e848fd..0039422f 100644
--- a/apexd/apexd.aconfig
+++ b/apexd/apexd.aconfig
@@ -8,3 +8,11 @@ flag {
   bug: "361500273"
   is_fixed_read_only: true
 }
+
+flag {
+  name: "mount_before_data"
+  namespace: "treble"
+  description: "This flag controls if allowing mounting APEXes before the data partition"
+  bug: "361701397"
+  is_fixed_read_only: true
+}
diff --git a/apexd/apexd.cpp b/apexd/apexd.cpp
index ed4cbafd..9e3c915a 100644
--- a/apexd/apexd.cpp
+++ b/apexd/apexd.cpp
@@ -28,6 +28,7 @@
 #include <android-base/scopeguard.h>
 #include <android-base/stringprintf.h>
 #include <android-base/strings.h>
+#include <android-base/thread_annotations.h>
 #include <android-base/unique_fd.h>
 #include <dirent.h>
 #include <fcntl.h>
@@ -81,6 +82,7 @@
 #include "apexd_brand_new_verifier.h"
 #include "apexd_checkpoint.h"
 #include "apexd_dm.h"
+#include "apexd_image_manager.h"
 #include "apexd_lifecycle.h"
 #include "apexd_loop.h"
 #include "apexd_metrics.h"
@@ -117,9 +119,12 @@ namespace android {
 namespace apex {
 
 using MountedApexData = MountedApexDatabase::MountedApexData;
-Result<std::vector<ApexFile>> OpenSessionApexFiles(
+Result<std::vector<ApexFile>> OpenApexFilesInSessionDirs(
     int session_id, const std::vector<int>& child_session_ids);
 
+Result<std::vector<std::string>> StagePackagesImpl(
+    const std::vector<std::string>& tmp_paths);
+
 namespace {
 
 static constexpr const char* kBuildFingerprintSysprop = "ro.build.fingerprint";
@@ -140,6 +145,17 @@ CheckpointInterface* gVoldService;
 bool gSupportsFsCheckpoints = false;
 bool gInFsCheckpointMode = false;
 
+// Process-wise global mutex to serialize install/staging functions:
+// - submitStagedSession
+// - markStagedSessionReady
+// - installAndActivatePackage
+// This is to ensure that there's no overlapping between install/staging.
+// To be specific, we don't want to perform verification when there's a
+// VERIFIED session, which is not yet fully staged.
+struct Mutex : std::mutex {
+  const Mutex& operator!() const { return *this; }  // for negative capability
+} gInstallLock;
+
 // APEXEs for which a different version was activated than in the previous boot.
 // This can happen in the following scenarios:
 //  1. This APEX is part of the staged session that was applied during this
@@ -263,8 +279,8 @@ std::unique_ptr<DmTable> CreateVerityTable(const ApexVerityData& verity_data,
  * kActiveApexPackagesDataDir
  */
 Result<void> RemovePreviouslyActiveApexFiles(
-    const std::unordered_set<std::string>& affected_packages,
-    const std::unordered_set<std::string>& files_to_keep) {
+    const std::vector<std::string>& affected_packages,
+    const std::vector<std::string>& files_to_keep) {
   auto all_active_apex_files =
       FindFilesBySuffix(gConfig->active_apex_data_dir, {kApexPackageSuffix});
 
@@ -273,23 +289,22 @@ Result<void> RemovePreviouslyActiveApexFiles(
   }
 
   for (const std::string& path : *all_active_apex_files) {
+    if (std::ranges::contains(files_to_keep, path)) {
+      // This is a path that was staged and should be kept.
+      continue;
+    }
+
     Result<ApexFile> apex_file = ApexFile::Open(path);
     if (!apex_file.ok()) {
       return apex_file.error();
     }
-
     const std::string& package_name = apex_file->GetManifest().name();
-    if (affected_packages.find(package_name) == affected_packages.end()) {
+    if (!std::ranges::contains(affected_packages, package_name)) {
       // This apex belongs to a package that wasn't part of this stage sessions,
       // hence it should be kept.
       continue;
     }
 
-    if (files_to_keep.find(apex_file->GetPath()) != files_to_keep.end()) {
-      // This is a path that was staged and should be kept.
-      continue;
-    }
-
     LOG(DEBUG) << "Deleting previously active apex " << apex_file->GetPath();
     if (unlink(apex_file->GetPath().c_str()) != 0) {
       return ErrnoError() << "Failed to unlink " << apex_file->GetPath();
@@ -500,6 +515,8 @@ Result<MountedApexData> MountPackageImpl(const ApexFile& apex,
   }
 }
 
+bool IsMountBeforeDataEnabled() { return gConfig->mount_before_data; }
+
 }  // namespace
 
 Result<void> Unmount(const MountedApexData& data, bool deferred) {
@@ -680,6 +697,29 @@ Result<void> VerifyPackageBoot(const ApexFile& apex_file) {
   return {};
 }
 
+Result<void> VerifyNoOverlapInSessions(std::span<const ApexFile> apex_files,
+                                       std::span<const ApexSession> sessions) {
+  for (const auto& session : sessions) {
+    // We don't want to install/stage while another session is being staged.
+    if (session.GetState() == SessionState::VERIFIED) {
+      return Error() << "Session " << session.GetId() << " is being staged.";
+    }
+
+    // We don't want to install/stage if the same package is already staged.
+    if (session.GetState() == SessionState::STAGED) {
+      for (const auto& apex : apex_files) {
+        if (std::ranges::contains(session.GetApexNames(),
+                                  apex.GetManifest().name())) {
+          return Error() << "APEX " << apex.GetManifest().name()
+                         << " is already staged by session " << session.GetId()
+                         << ".";
+        }
+      }
+    }
+  }
+  return {};  // okay
+}
+
 struct VerificationResult {
   std::map<std::string, std::vector<std::string>> apex_hals;
 };
@@ -701,14 +741,22 @@ Result<VerificationResult> VerifyPackagesStagedInstall(
     }
   }
 
+  auto sessions = gSessionManager->GetSessions();
+
+  // Check overlapping: reject if the same package is already staged
+  // or if there's a session being staged.
+  OR_RETURN(VerifyNoOverlapInSessions(apex_files, sessions));
+
   // Since there can be multiple staged sessions, let's verify incoming APEXes
   // with all staged apexes mounted.
   std::vector<ApexFile> all_apex_files;
-  for (const auto& session :
-       gSessionManager->GetSessionsInState(SessionState::STAGED)) {
+  for (const auto& session : sessions) {
+    if (session.GetState() != SessionState::STAGED) {
+      continue;
+    }
     auto session_id = session.GetId();
     auto child_session_ids = session.GetChildSessionIds();
-    auto staged_apex_files = OpenSessionApexFiles(
+    auto staged_apex_files = OpenApexFilesInSessionDirs(
         session_id, {child_session_ids.begin(), child_session_ids.end()});
     if (staged_apex_files.ok()) {
       std::ranges::move(*staged_apex_files, std::back_inserter(all_apex_files));
@@ -1196,7 +1244,7 @@ Result<void> DeactivatePackage(const std::string& full_path) {
                         /* deferred= */ false, /* detach_mount_point= */ false);
 }
 
-Result<std::vector<ApexFile>> OpenSessionApexFiles(
+Result<std::vector<std::string>> ScanApexFilesInSessionDirs(
     int session_id, const std::vector<int>& child_session_ids) {
   std::vector<int> ids_to_scan;
   if (!child_session_ids.empty()) {
@@ -1222,7 +1270,20 @@ Result<std::vector<ApexFile>> OpenSessionApexFiles(
     std::string& apex_file_path = (*scan)[0];
     apex_file_paths.push_back(std::move(apex_file_path));
   }
+  return apex_file_paths;
+}
 
+Result<std::vector<std::string>> ScanSessionApexFiles(
+    const ApexSession& session) {
+  auto child_session_ids =
+      std::vector{std::from_range, session.GetChildSessionIds()};
+  return ScanApexFilesInSessionDirs(session.GetId(), child_session_ids);
+}
+
+Result<std::vector<ApexFile>> OpenApexFilesInSessionDirs(
+    int session_id, const std::vector<int>& child_session_ids) {
+  auto apex_file_paths =
+      OR_RETURN(ScanApexFilesInSessionDirs(session_id, child_session_ids));
   return OpenApexFiles(apex_file_paths);
 }
 
@@ -1234,7 +1295,7 @@ Result<std::vector<ApexFile>> GetStagedApexFiles(
     return Error() << "Session " << session_id << " is not in state STAGED";
   }
 
-  return OpenSessionApexFiles(session_id, child_session_ids);
+  return OpenApexFilesInSessionDirs(session_id, child_session_ids);
 }
 
 Result<ClassPath> MountAndDeriveClassPath(
@@ -1278,21 +1339,7 @@ std::vector<ApexFile> CalculateInactivePackages(
 }
 
 Result<void> EmitApexInfoList(bool is_bootstrap) {
-  // Apexd runs both in "bootstrap" and "default" mount namespace.
-  // To expose /apex/apex-info-list.xml separately in each mount namespaces,
-  // we write /apex/.<namespace>-apex-info-list .xml file first and then
-  // bind mount it to the canonical file (/apex/apex-info-list.xml).
-  const std::string file_name =
-      fmt::format("{}/.{}-{}", kApexRoot,
-                  is_bootstrap ? "bootstrap" : "default", kApexInfoList);
-
-  unique_fd fd(TEMP_FAILURE_RETRY(
-      open(file_name.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)));
-  if (fd.get() == -1) {
-    return ErrnoErrorf("Can't open {}", file_name);
-  }
-
-  const std::vector<ApexFile> active(GetActivePackages());
+  std::vector<ApexFile> active{GetActivePackages()};
 
   std::vector<ApexFile> inactive;
   // we skip for non-activated built-in apexes in bootstrap mode
@@ -1304,23 +1351,17 @@ Result<void> EmitApexInfoList(bool is_bootstrap) {
   std::stringstream xml;
   CollectApexInfoList(xml, active, inactive);
 
+  unique_fd fd(TEMP_FAILURE_RETRY(
+      open(kApexInfoList, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)));
+  if (fd.get() == -1) {
+    return ErrnoErrorf("Can't open {}", kApexInfoList);
+  }
   if (!android::base::WriteStringToFd(xml.str(), fd)) {
-    return ErrnoErrorf("Can't write to {}", file_name);
+    return ErrnoErrorf("Can't write to {}", kApexInfoList);
   }
 
   fd.reset();
-
-  const std::string mount_point =
-      fmt::format("{}/{}", kApexRoot, kApexInfoList);
-  if (access(mount_point.c_str(), F_OK) != 0) {
-    close(open(mount_point.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
-               0644));
-  }
-  if (mount(file_name.c_str(), mount_point.c_str(), nullptr, MS_BIND,
-            nullptr) == -1) {
-    return ErrnoErrorf("Can't bind mount {} to {}", file_name, mount_point);
-  }
-  return RestoreconPath(file_name);
+  return RestoreconPath(kApexInfoList);
 }
 
 namespace {
@@ -1369,23 +1410,13 @@ std::vector<ApexFile> GetFactoryPackages() {
   return ret;
 }
 
-Result<ApexFile> GetActivePackage(const std::string& packageName) {
-  std::vector<ApexFile> packages = GetActivePackages();
-  for (ApexFile& apex : packages) {
-    if (apex.GetManifest().name() == packageName) {
-      return std::move(apex);
-    }
-  }
-
-  return ErrnoError() << "Cannot find matching package for: " << packageName;
-}
-
 /**
  * Abort individual staged session.
  *
  * Returns without error only if session was successfully aborted.
  **/
-Result<void> AbortStagedSession(int session_id) {
+Result<void> AbortStagedSession(int session_id) REQUIRES(!gInstallLock) {
+  auto install_guard = std::scoped_lock{gInstallLock};
   auto session = gSessionManager->GetSession(session_id);
   if (!session.ok()) {
     return Error() << "No session found with id " << session_id;
@@ -1393,8 +1424,19 @@ Result<void> AbortStagedSession(int session_id) {
 
   switch (session->GetState()) {
     case SessionState::VERIFIED:
-      [[clang::fallthrough]];
+      [[fallthrough]];
     case SessionState::STAGED:
+      if (IsMountBeforeDataEnabled()) {
+        for (const auto& image : session->GetApexImages()) {
+          auto result = GetImageManager()->DeleteImage(image);
+          if (!result.ok()) {
+            // There's not much we can do with error. Let's log it. On boot
+            // completion, dangling images (not referenced by any) will be
+            // deleted anyway.
+            LOG(ERROR) << result.error();
+          }
+        }
+      }
       return session->DeleteSession();
     default:
       return Error() << "Session " << *session << " can't be aborted";
@@ -1830,8 +1872,13 @@ void DeleteDePreRestoreSnapshots(const ApexSession& session) {
 
 void OnBootCompleted() { ApexdLifecycle::GetInstance().MarkBootCompleted(); }
 
-// Returns true if any session gets staged
-void ScanStagedSessionsDirAndStage() {
+// Scans all STAGED sessions and activate them so that APEXes in those sessions
+// become available for activation. Sessions are updated to be ACTIVATED state,
+// or ACTIVATION_FAILED if something goes wrong.
+// Note that this doesn't abort with failed sessions. Apexd just marks them as
+// failed and continues activation process. It's higher level component (e.g.
+// system_server) that needs to handle the failures.
+void ActivateStagedSessions() {
   LOG(INFO) << "Scanning " << GetSessionsDir()
             << " looking for sessions to be activated.";
 
@@ -1881,64 +1928,18 @@ void ScanStagedSessionsDirAndStage() {
       continue;
     }
 
-    std::vector<std::string> dirs_to_scan =
-        session.GetStagedApexDirs(gConfig->staged_session_dir);
-
-    std::vector<std::string> apexes;
-    bool scan_successful = true;
-    for (const auto& dir_to_scan : dirs_to_scan) {
-      Result<std::vector<std::string>> scan =
-          FindFilesBySuffix(dir_to_scan, {kApexPackageSuffix});
-      if (!scan.ok()) {
-        LOG(WARNING) << scan.error();
-        session.SetErrorMessage(scan.error().message());
-        scan_successful = false;
-        break;
-      }
-
-      if (scan->size() > 1) {
-        std::string error_message = StringPrintf(
-            "More than one APEX package found in the same session directory %s "
-            ", skipping activation",
-            dir_to_scan.c_str());
-        LOG(WARNING) << error_message;
-        session.SetErrorMessage(error_message);
-        scan_successful = false;
-        break;
-      }
-
-      if (scan->empty()) {
-        std::string error_message = StringPrintf(
-            "No APEX packages found while scanning %s session id: %d.",
-            dir_to_scan.c_str(), session_id);
-        LOG(WARNING) << error_message;
-        session.SetErrorMessage(error_message);
-        scan_successful = false;
-        break;
-      }
-      apexes.push_back(std::move((*scan)[0]));
-    }
-
-    if (!scan_successful) {
+    auto apexes = ScanSessionApexFiles(session);
+    if (!apexes.ok()) {
+      LOG(WARNING) << apexes.error();
+      session.SetErrorMessage(apexes.error().message());
       continue;
     }
 
-    std::vector<std::string> staged_apex_names;
-    for (const auto& apex : apexes) {
-      // TODO(b/158470836): Avoid opening ApexFile repeatedly.
-      Result<ApexFile> apex_file = ApexFile::Open(apex);
-      if (!apex_file.ok()) {
-        LOG(ERROR) << "Cannot open apex file during staging: " << apex;
-        continue;
-      }
-      staged_apex_names.push_back(apex_file->GetManifest().name());
-    }
-
-    const Result<void> result = StagePackages(apexes);
-    if (!result.ok()) {
-      std::string error_message = StringPrintf(
-          "Activation failed for packages %s : %s", Join(apexes, ',').c_str(),
-          result.error().message().c_str());
+    auto packages = StagePackagesImpl(*apexes);
+    if (!packages.ok()) {
+      std::string error_message =
+          std::format("Activation failed for packages {} : {}", *apexes,
+                      packages.error().message());
       LOG(ERROR) << error_message;
       session.SetErrorMessage(error_message);
       continue;
@@ -1947,9 +1948,7 @@ void ScanStagedSessionsDirAndStage() {
     // Session was OK, release scopeguard.
     scope_guard.Disable();
 
-    for (const std::string& apex : staged_apex_names) {
-      gChangedActiveApexes.insert(apex);
-    }
+    gChangedActiveApexes.insert_range(*packages);
 
     auto st = session.UpdateStateAndCommit(SessionState::ACTIVATED);
     if (!st.ok()) {
@@ -1968,9 +1967,10 @@ std::string StageDestPath(const ApexFile& apex_file) {
 
 }  // namespace
 
-Result<void> StagePackagesImpl(const std::vector<std::string>& tmp_paths) {
+Result<std::vector<std::string>> StagePackagesImpl(
+    const std::vector<std::string>& tmp_paths) {
   if (tmp_paths.empty()) {
-    return Errorf("Empty set of inputs");
+    return Error() << "Empty set of inputs";
   }
   LOG(DEBUG) << "StagePackagesImpl() for " << Join(tmp_paths, ',');
 
@@ -2003,7 +2003,7 @@ Result<void> StagePackagesImpl(const std::vector<std::string>& tmp_paths) {
   // 2) Now stage all of them.
 
   // Ensure the APEX gets removed on failure.
-  std::unordered_set<std::string> staged_files;
+  std::vector<std::string> staged_files;
   auto deleter = [&staged_files]() {
     for (const std::string& staged_path : staged_files) {
       if (TEMP_FAILURE_RETRY(unlink(staged_path.c_str())) != 0) {
@@ -2013,7 +2013,7 @@ Result<void> StagePackagesImpl(const std::vector<std::string>& tmp_paths) {
   };
   auto scope_guard = android::base::make_scope_guard(deleter);
 
-  std::unordered_set<std::string> staged_packages;
+  std::vector<std::string> staged_packages;
   for (const ApexFile& apex_file : *apex_files) {
     // move apex to /data/apex/active.
     std::string dest_path = StageDestPath(apex_file);
@@ -2028,8 +2028,8 @@ Result<void> StagePackagesImpl(const std::vector<std::string>& tmp_paths) {
       return ErrnoError() << "Unable to link " << apex_file.GetPath() << " to "
                           << dest_path;
     }
-    staged_files.insert(dest_path);
-    staged_packages.insert(apex_file.GetManifest().name());
+    staged_files.push_back(dest_path);
+    staged_packages.push_back(apex_file.GetManifest().name());
 
     LOG(DEBUG) << "Success linking " << apex_file.GetPath() << " to "
                << dest_path;
@@ -2037,15 +2037,14 @@ Result<void> StagePackagesImpl(const std::vector<std::string>& tmp_paths) {
 
   scope_guard.Disable();  // Accept the state.
 
-  return RemovePreviouslyActiveApexFiles(staged_packages, staged_files);
+  OR_RETURN(RemovePreviouslyActiveApexFiles(staged_packages, staged_files));
+
+  return staged_packages;
 }
 
 Result<void> StagePackages(const std::vector<std::string>& tmp_paths) {
-  Result<void> ret = StagePackagesImpl(tmp_paths);
-  if (!ret.ok()) {
-    ;  // TODO(b/366068337, Queue atoms)
-  }
-  return ret;
+  OR_RETURN(StagePackagesImpl(tmp_paths));
+  return {};
 }
 
 Result<void> UnstagePackages(const std::vector<std::string>& paths) {
@@ -2074,13 +2073,13 @@ Result<void> UnstagePackages(const std::vector<std::string>& paths) {
 }
 
 /**
- * During apex installation, staged sessions located in /data/apex/sessions
+ * During apex installation, staged sessions located in /metadata/apex/sessions
  * mutate the active sessions in /data/apex/active. If some error occurs during
  * installation of apex, we need to revert /data/apex/active to its original
  * state and reboot.
  *
- * Also, we need to put staged sessions in /data/apex/sessions in REVERTED state
- * so that they do not get activated on next reboot.
+ * Also, we need to put staged sessions in /metadata/apex/sessions in
+ * REVERTED state so that they do not get activated on next reboot.
  */
 Result<void> RevertActiveSessions(const std::string& crashing_native_process,
                                   const std::string& error_message) {
@@ -2197,41 +2196,9 @@ Result<void> CreateSharedLibsApexDir() {
   return {};
 }
 
-int OnBootstrap() {
-  ATRACE_NAME("OnBootstrap");
-  auto time_started = boot_clock::now();
-
-  ApexFileRepository& instance = ApexFileRepository::GetInstance();
-  Result<void> status = instance.AddPreInstalledApex(gConfig->builtin_dirs);
-  if (!status.ok()) {
-    LOG(ERROR) << "Failed to collect APEX keys : " << status.error();
-    return 1;
-  }
-
-  const auto& pre_installed_apexes = instance.GetPreInstalledApexFiles();
-  int loop_device_cnt = pre_installed_apexes.size();
-  // Find all bootstrap apexes
-  std::vector<ApexFileRef> bootstrap_apexes;
-  for (const auto& apex : pre_installed_apexes) {
-    if (IsBootstrapApex(apex.get())) {
-      LOG(INFO) << "Found bootstrap APEX " << apex.get().GetPath();
-      bootstrap_apexes.push_back(apex);
-      loop_device_cnt++;
-    }
-    if (apex.get().GetManifest().providesharedapexlibs()) {
-      LOG(INFO) << "Found sharedlibs APEX " << apex.get().GetPath();
-      // Sharedlis APEX might be mounted 2 times:
-      //   * Pre-installed sharedlibs APEX will be mounted in OnStart
-      //   * Updated sharedlibs APEX (if it exists) will be mounted in OnStart
-      //
-      // We already counted a loop device for one of these 2 mounts, need to add
-      // 1 more.
-      loop_device_cnt++;
-    }
-  }
-  LOG(INFO) << "Need to pre-allocate " << loop_device_cnt
-            << " loop devices for " << pre_installed_apexes.size()
-            << " APEX packages";
+void PrepareResources(size_t loop_device_cnt,
+                      const std::vector<std::string>& apex_names) {
+  LOG(INFO) << "Need to pre-allocate " << loop_device_cnt << " loop devices";
   if (auto res = loop::PreAllocateLoopDevices(loop_device_cnt); !res.ok()) {
     LOG(ERROR) << "Failed to pre-allocate loop devices : " << res.error();
   }
@@ -2245,18 +2212,60 @@ int OnBootstrap() {
   // optimistically creating a verity device for all of them. Once boot
   // finishes, apexd will clean up unused devices.
   // TODO(b/192241176): move to apexd_verity.{h,cpp}
-  for (const auto& apex : pre_installed_apexes) {
-    const std::string& name = apex.get().GetManifest().name();
+  for (const auto& name : apex_names) {
     if (!dm.CreatePlaceholderDevice(name)) {
       LOG(ERROR) << "Failed to create empty device " << name;
     }
   }
+}
+
+int OnBootstrap() {
+  ATRACE_NAME("OnBootstrap");
+  auto time_started = boot_clock::now();
+
+  ApexFileRepository& instance = ApexFileRepository::GetInstance();
+  Result<void> status =
+      instance.AddPreInstalledApexParallel(gConfig->builtin_dirs);
+  if (!status.ok()) {
+    LOG(ERROR) << "Failed to collect APEX keys : " << status.error();
+    return 1;
+  }
+
+  std::vector<ApexFileRef> activation_list;
+
+  if (IsMountBeforeDataEnabled()) {
+    activation_list = SelectApexForActivation();
+  } else {
+    const auto& pre_installed_apexes = instance.GetPreInstalledApexFiles();
+    size_t loop_device_cnt = pre_installed_apexes.size();
+    std::vector<std::string> apex_names;
+    apex_names.reserve(loop_device_cnt);
+    // Find all bootstrap apexes
+    for (const auto& apex : pre_installed_apexes) {
+      apex_names.push_back(apex.get().GetManifest().name());
+      if (IsBootstrapApex(apex.get())) {
+        LOG(INFO) << "Found bootstrap APEX " << apex.get().GetPath();
+        activation_list.push_back(apex);
+        loop_device_cnt++;
+      }
+      if (apex.get().GetManifest().providesharedapexlibs()) {
+        LOG(INFO) << "Found sharedlibs APEX " << apex.get().GetPath();
+        // Sharedlis APEX might be mounted 2 times:
+        //   * Pre-installed sharedlibs APEX will be mounted in OnStart
+        //   * Updated sharedlibs APEX (if it exists) will be mounted in OnStart
+        //
+        // We already counted a loop device for one of these 2 mounts, need to
+        // add 1 more.
+        loop_device_cnt++;
+      }
+    }
+    PrepareResources(loop_device_cnt, apex_names);
+  }
 
-  // Now activate bootstrap apexes.
   auto ret =
-      ActivateApexPackages(bootstrap_apexes, ActivationMode::kBootstrapMode);
+      ActivateApexPackages(activation_list, ActivationMode::kBootstrapMode);
   if (!ret.ok()) {
-    LOG(ERROR) << "Failed to activate bootstrap apex files : " << ret.error();
+    LOG(ERROR) << "Failed to activate apexes: " << ret.error();
     return 1;
   }
 
@@ -2269,24 +2278,29 @@ int OnBootstrap() {
 }
 
 void InitializeVold(CheckpointInterface* checkpoint_service) {
-  if (checkpoint_service != nullptr) {
-    gVoldService = checkpoint_service;
-    Result<bool> supports_fs_checkpoints =
-        gVoldService->SupportsFsCheckpoints();
-    if (supports_fs_checkpoints.ok()) {
-      gSupportsFsCheckpoints = *supports_fs_checkpoints;
+  if (checkpoint_service == nullptr) {
+    // For tests to reset global states because tests that change global states
+    // may affect other tests.
+    gVoldService = nullptr;
+    gSupportsFsCheckpoints = false;
+    gInFsCheckpointMode = false;
+    return;
+  }
+  gVoldService = checkpoint_service;
+  Result<bool> supports_fs_checkpoints = gVoldService->SupportsFsCheckpoints();
+  if (supports_fs_checkpoints.ok()) {
+    gSupportsFsCheckpoints = *supports_fs_checkpoints;
+  } else {
+    LOG(ERROR) << "Failed to check if filesystem checkpoints are supported: "
+               << supports_fs_checkpoints.error();
+  }
+  if (gSupportsFsCheckpoints) {
+    Result<bool> needs_checkpoint = gVoldService->NeedsCheckpoint();
+    if (needs_checkpoint.ok()) {
+      gInFsCheckpointMode = *needs_checkpoint;
     } else {
-      LOG(ERROR) << "Failed to check if filesystem checkpoints are supported: "
-                 << supports_fs_checkpoints.error();
-    }
-    if (gSupportsFsCheckpoints) {
-      Result<bool> needs_checkpoint = gVoldService->NeedsCheckpoint();
-      if (needs_checkpoint.ok()) {
-        gInFsCheckpointMode = *needs_checkpoint;
-      } else {
-        LOG(ERROR) << "Failed to check if we're in filesystem checkpoint mode: "
-                   << needs_checkpoint.error();
-      }
+      LOG(ERROR) << "Failed to check if we're in filesystem checkpoint mode: "
+                 << needs_checkpoint.error();
     }
   }
 }
@@ -2340,14 +2354,14 @@ void InitializeDataApex() {
  * Typically, only one APEX is activated for each package, but APEX that provide
  * shared libs are exceptions. We have to activate both APEX for them.
  *
- * @param all_apex all the APEX grouped by their package name
  * @return list of ApexFile that needs to be activated
  */
-std::vector<ApexFileRef> SelectApexForActivation(
-    const std::unordered_map<std::string, std::vector<ApexFileRef>>& all_apex,
-    const ApexFileRepository& instance) {
+std::vector<ApexFileRef> SelectApexForActivation() {
   LOG(INFO) << "Selecting APEX for activation";
   std::vector<ApexFileRef> activation_list;
+  const auto& instance = ApexFileRepository::GetInstance();
+  const auto& all_apex = instance.AllApexFilesByName();
+  activation_list.reserve(all_apex.size());
   // For every package X, select which APEX to activate
   for (auto& apex_it : all_apex) {
     const std::string& package_name = apex_it.first;
@@ -2652,7 +2666,7 @@ void OnStart() {
 
   // If there is any new apex to be installed on /data/app-staging, hardlink
   // them to /data/apex/active first.
-  ScanStagedSessionsDirAndStage();
+  ActivateStagedSessions();
   if (auto status = ApexFileRepository::GetInstance().AddDataApex(
           gConfig->active_apex_data_dir);
       !status.ok()) {
@@ -2665,11 +2679,7 @@ void OnStart() {
   }
 
   // Group every ApexFile on device by name
-  const auto& instance = ApexFileRepository::GetInstance();
-  const auto& all_apex = instance.AllApexFilesByName();
-  // There can be multiple APEX packages with package name X. Determine which
-  // one to activate.
-  auto activation_list = SelectApexForActivation(all_apex, instance);
+  auto activation_list = SelectApexForActivation();
 
   // Process compressed APEX, if any
   std::vector<ApexFileRef> compressed_apex;
@@ -2768,7 +2778,8 @@ void OnAllPackagesReady() {
 Result<std::vector<ApexFile>> SubmitStagedSession(
     const int session_id, const std::vector<int>& child_session_ids,
     const bool has_rollback_enabled, const bool is_rollback,
-    const int rollback_id) {
+    const int rollback_id) REQUIRES(!gInstallLock) {
+  auto install_guard = std::scoped_lock{gInstallLock};
   auto event = InstallRequestedEvent(InstallType::Staged, is_rollback);
 
   if (session_id == 0) {
@@ -2787,12 +2798,34 @@ Result<std::vector<ApexFile>> SubmitStagedSession(
     }
   }
 
-  auto ret = OR_RETURN(OpenSessionApexFiles(session_id, child_session_ids));
+  auto ret =
+      OR_RETURN(OpenApexFilesInSessionDirs(session_id, child_session_ids));
   event.AddFiles(ret);
 
   auto result = OR_RETURN(VerifyPackagesStagedInstall(ret));
   event.AddHals(result.apex_hals);
 
+  std::vector<std::string> apex_images;
+  if (IsMountBeforeDataEnabled()) {
+    apex_images = OR_RETURN(GetImageManager()->PinApexFiles(ret));
+  }
+
+  // The incoming session is now verified by apexd. From now on, apexd keeps its
+  // own session data. The session should be marked as "ready" so that it
+  // becomes STAGED. On next reboot, STAGED sessions become ACTIVATED, which
+  // means the APEXes in those sessions are in "active" state and to be
+  // activated.
+  //
+  //    SubmitStagedSession     MarkStagedSessionReady
+  //           |                          |
+  //           V                          V
+  //         VERIFIED (created) ---------------> STAGED
+  //                                               |
+  //                                               | <-- ActivateStagedSessions
+  //                                               V
+  //                                             ACTIVATED
+  //
+
   auto session = gSessionManager->CreateSession(session_id);
   if (!session.ok()) {
     return session.error();
@@ -2807,6 +2840,7 @@ Result<std::vector<ApexFile>> SubmitStagedSession(
     session->AddApexName(apex_file.GetManifest().name());
   }
   session->SetApexFileHashes(event.GetFileHashes());
+  session->SetApexImages(apex_images);
   Result<void> commit_status =
       (*session).UpdateStateAndCommit(SessionState::VERIFIED);
   if (!commit_status.ok()) {
@@ -2823,7 +2857,9 @@ Result<std::vector<ApexFile>> SubmitStagedSession(
   return ret;
 }
 
-Result<void> MarkStagedSessionReady(const int session_id) {
+Result<void> MarkStagedSessionReady(const int session_id)
+    REQUIRES(!gInstallLock) {
+  auto install_guard = std::scoped_lock{gInstallLock};
   auto session = gSessionManager->GetSession(session_id);
   if (!session.ok()) {
     return session.error();
@@ -2989,7 +3025,8 @@ int UnmountAll(bool also_include_staged_apexes) {
 // Given a single new APEX incoming via OTA, should we allocate space for it?
 bool ShouldAllocateSpaceForDecompression(const std::string& new_apex_name,
                                          const int64_t new_apex_version,
-                                         const ApexFileRepository& instance) {
+                                         const ApexFileRepository& instance,
+                                         const MountedApexDatabase& db) {
   // An apex at most will have two versions on device: pre-installed and data.
 
   // Check if there is a pre-installed version for the new apex.
@@ -2999,47 +3036,43 @@ bool ShouldAllocateSpaceForDecompression(const std::string& new_apex_name,
   }
 
   // Check if there is a data apex
-  if (!instance.HasDataVersion(new_apex_name)) {
-    // Data apex doesn't exist. Compare against pre-installed APEX
-    auto pre_installed_apex = instance.GetPreInstalledApex(new_apex_name);
-    if (!pre_installed_apex.get().IsCompressed()) {
-      // Compressing an existing uncompressed system APEX.
-      return true;
-    }
-    // Since there is no data apex, it means device is using the compressed
-    // pre-installed version. If new apex has higher version, we are upgrading
-    // the pre-install version and if new apex has lower version, we are
-    // downgrading it. So the current decompressed apex should be replaced
-    // with the new decompressed apex to reflect that.
-    const int64_t pre_installed_version =
-        instance.GetPreInstalledApex(new_apex_name)
-            .get()
-            .GetManifest()
-            .version();
-    return new_apex_version != pre_installed_version;
+  // If the current active apex is preinstalled, then it means no data apex.
+  auto current_active = db.GetLatestMountedApex(new_apex_name);
+  if (!current_active) {
+    LOG(ERROR) << "Failed to get mount data for : " << new_apex_name
+               << " is preinstalled, but not activated.";
+    return true;
+  }
+  auto current_active_apex_file = ApexFile::Open(current_active->full_path);
+  if (!current_active_apex_file.ok()) {
+    LOG(ERROR) << "Failed to open " << current_active->full_path << " : "
+               << current_active_apex_file.error();
+    return true;
+  }
+  if (instance.IsPreInstalledApex(*current_active_apex_file)) {
+    return true;
   }
 
   // From here on, data apex exists. So we should compare directly against data
   // apex.
-  auto data_apex = instance.GetDataApex(new_apex_name);
-  // Compare the data apex version with new apex
-  const int64_t data_version = data_apex.get().GetManifest().version();
+  const int64_t data_version =
+      current_active_apex_file->GetManifest().version();
   // We only decompress the new_apex if it has higher version than data apex.
   return new_apex_version > data_version;
 }
 
 int64_t CalculateSizeForCompressedApex(
     const std::vector<std::tuple<std::string, int64_t, int64_t>>&
-        compressed_apexes,
-    const ApexFileRepository& instance) {
+        compressed_apexes) {
+  const auto& instance = ApexFileRepository::GetInstance();
   int64_t result = 0;
   for (const auto& compressed_apex : compressed_apexes) {
     std::string module_name;
     int64_t version_code;
     int64_t decompressed_size;
     std::tie(module_name, version_code, decompressed_size) = compressed_apex;
-    if (ShouldAllocateSpaceForDecompression(module_name, version_code,
-                                            instance)) {
+    if (ShouldAllocateSpaceForDecompression(module_name, version_code, instance,
+                                            gMountedApexes)) {
       result += decompressed_size;
     }
   }
@@ -3209,17 +3242,11 @@ int OnStartInVmMode() {
   }
 
   if (auto status = AddBlockApex(instance); !status.ok()) {
-    LOG(ERROR) << status.error();
+    LOG(ERROR) << "Failed to scan host APEX files: " << status.error();
     return 1;
   }
 
-  if (auto status = ActivateApexPackages(instance.GetPreInstalledApexFiles(),
-                                         ActivationMode::kVmMode);
-      !status.ok()) {
-    LOG(ERROR) << "Failed to activate apex packages : " << status.error();
-    return 1;
-  }
-  if (auto status = ActivateApexPackages(instance.GetDataApexFiles(),
+  if (auto status = ActivateApexPackages(SelectApexForActivation(),
                                          ActivationMode::kVmMode);
       !status.ok()) {
     LOG(ERROR) << "Failed to activate apex packages : " << status.error();
@@ -3276,8 +3303,7 @@ int OnOtaChrootBootstrap(bool also_include_staged_apexes) {
     return 1;
   }
 
-  auto activation_list =
-      SelectApexForActivation(instance.AllApexFilesByName(), instance);
+  auto activation_list = SelectApexForActivation();
 
   // TODO(b/179497746): This is the third time we are duplicating this code
   // block. This will be easier to dedup once we start opening ApexFiles via
@@ -3316,41 +3342,8 @@ int OnOtaChrootBootstrap(bool also_include_staged_apexes) {
     }
   }
 
-  // There are a bunch of places that are producing apex-info.xml file.
-  // We should consolidate the logic in one function and make all other places
-  // use it.
-  auto active_apexes = GetActivePackages();
-  std::vector<ApexFile> inactive_apexes = GetFactoryPackages();
-  auto new_end = std::remove_if(
-      inactive_apexes.begin(), inactive_apexes.end(),
-      [&active_apexes](const ApexFile& apex) {
-        return std::any_of(active_apexes.begin(), active_apexes.end(),
-                           [&apex](const ApexFile& active_apex) {
-                             return apex.GetPath() == active_apex.GetPath();
-                           });
-      });
-  inactive_apexes.erase(new_end, inactive_apexes.end());
-  std::stringstream xml;
-  CollectApexInfoList(xml, active_apexes, inactive_apexes);
-  std::string file_name = StringPrintf("%s/%s", kApexRoot, kApexInfoList);
-  unique_fd fd(TEMP_FAILURE_RETRY(
-      open(file_name.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)));
-  if (fd.get() == -1) {
-    PLOG(ERROR) << "Can't open " << file_name;
-    return 1;
-  }
-
-  if (!android::base::WriteStringToFd(xml.str(), fd)) {
-    PLOG(ERROR) << "Can't write to " << file_name;
-    return 1;
-  }
-
-  fd.reset();
-
-  if (auto status = RestoreconPath(file_name); !status.ok()) {
-    LOG(ERROR) << "Failed to restorecon " << file_name << " : "
-               << status.error();
-    return 1;
+  if (auto status = EmitApexInfoList(/*is_bootstrap*/ false); !status.ok()) {
+    LOG(ERROR) << status.error();
   }
 
   return 0;
@@ -3366,6 +3359,12 @@ Result<VerificationResult> VerifyPackageNonStagedInstall(
     const ApexFile& apex_file, bool force) {
   OR_RETURN(VerifyPackageBoot(apex_file));
 
+  auto sessions = gSessionManager->GetSessions();
+
+  // Check overlapping: reject if the same package is already staged
+  // or if there's a session being staged.
+  OR_RETURN(VerifyNoOverlapInSessions(Single(apex_file), sessions));
+
   auto check_fn =
       [&apex_file,
        &force](const std::string& mount_point) -> Result<VerificationResult> {
@@ -3480,26 +3479,6 @@ Result<size_t> ComputePackageIdMinor(const ApexFile& apex) {
   return next_minor;
 }
 
-Result<void> UpdateApexInfoList() {
-  std::vector<ApexFile> active(GetActivePackages());
-  std::vector<ApexFile> inactive = CalculateInactivePackages(active);
-
-  std::stringstream xml;
-  CollectApexInfoList(xml, active, inactive);
-
-  std::string name = StringPrintf("%s/.default-%s", kApexRoot, kApexInfoList);
-  unique_fd fd(TEMP_FAILURE_RETRY(
-      open(name.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)));
-  if (fd.get() == -1) {
-    return ErrnoError() << "Can't open " << name;
-  }
-  if (!WriteStringToFd(xml.str(), fd)) {
-    return ErrnoError() << "Failed to write to " << name;
-  }
-
-  return {};
-}
-
 // TODO(b/238820991) Handle failures
 Result<void> UnloadApexFromInit(const std::string& apex_name) {
   if (!SetProperty(kCtlApexUnloadSysprop, apex_name)) {
@@ -3524,7 +3503,9 @@ Result<void> LoadApexFromInit(const std::string& apex_name) {
   return {};
 }
 
-Result<ApexFile> InstallPackage(const std::string& package_path, bool force) {
+Result<ApexFile> InstallPackage(const std::string& package_path, bool force)
+    REQUIRES(!gInstallLock) {
+  auto install_guard = std::scoped_lock{gInstallLock};
   auto event = InstallRequestedEvent(InstallType::NonStaged,
                                      /*is_rollback=*/false);
 
@@ -3640,7 +3621,7 @@ Result<ApexFile> InstallPackage(const std::string& package_path, bool force) {
     }
   }
 
-  if (auto res = UpdateApexInfoList(); !res.ok()) {
+  if (auto res = EmitApexInfoList(/*is_bootstrap*/ false); !res.ok()) {
     LOG(ERROR) << res.error();
   }
 
diff --git a/apexd/apexd.h b/apexd/apexd.h
index 8ccb59c2..8cbf0f69 100644
--- a/apexd/apexd.h
+++ b/apexd/apexd.h
@@ -54,6 +54,11 @@ struct ApexdConfig {
   // and the subsequent numbers should point APEX files.
   const char* vm_payload_metadata_partition_prop;
   const char* active_apex_selinux_ctx;
+
+  // TODO(b/381173074) True in tests for now. Will be configured as true if
+  // - new device (ro.vendor.api_level >= 202504 (TBD))
+  // - or, upgrading device with migration done (e.g. flag in /metadata/apex)
+  bool mount_before_data;
 };
 
 static const ApexdConfig kDefaultConfig = {
@@ -65,6 +70,7 @@ static const ApexdConfig kDefaultConfig = {
     kStagedSessionsDir,
     kVmPayloadMetadataPartitionProp,
     "u:object_r:staging_data_file",
+    false, /* mount_before_data */
 };
 
 class CheckpointInterface;
@@ -113,8 +119,6 @@ android::base::Result<void> DeactivatePackage(const std::string& full_path)
     WARN_UNUSED;
 
 std::vector<ApexFile> GetActivePackages();
-android::base::Result<ApexFile> GetActivePackage(
-    const std::string& package_name);
 
 std::vector<ApexFile> GetFactoryPackages();
 
@@ -151,9 +155,7 @@ void OnStart();
 // For every package X, there can be at most two APEX, pre-installed vs
 // installed on data. We decide which ones should be activated and return them
 // as a list
-std::vector<ApexFileRef> SelectApexForActivation(
-    const std::unordered_map<std::string, std::vector<ApexFileRef>>& all_apex,
-    const ApexFileRepository& instance);
+std::vector<ApexFileRef> SelectApexForActivation();
 std::vector<ApexFile> ProcessCompressedApex(
     const std::vector<ApexFileRef>& compressed_apex, bool is_ota_chroot);
 // Validate |apex| is same as |capex|
@@ -189,12 +191,12 @@ GetTempMountedApexData(const std::string& package);
 // Exposed for unit tests
 bool ShouldAllocateSpaceForDecompression(const std::string& new_apex_name,
                                          int64_t new_apex_version,
-                                         const ApexFileRepository& instance);
+                                         const ApexFileRepository& instance,
+                                         const MountedApexDatabase& db);
 
 int64_t CalculateSizeForCompressedApex(
     const std::vector<std::tuple<std::string, int64_t, int64_t>>&
-        compressed_apexes,
-    const ApexFileRepository& instance);
+        compressed_apexes);
 
 // Casts |ApexPartition| to partition string used in XSD.
 std::string CastPartition(ApexPartition partition);
diff --git a/apexd/apexd_brand_new_verifier.h b/apexd/apexd_brand_new_verifier.h
index fb1738cd..db38e250 100644
--- a/apexd/apexd_brand_new_verifier.h
+++ b/apexd/apexd_brand_new_verifier.h
@@ -36,7 +36,7 @@ namespace android::apex {
 //
 // The function is called in
 // |SubmitStagedSession| (brand-new apex becomes 'staged')
-// |ScanStagedSessionsDirAndStage| ('staged' apex becomes 'active')
+// |ActivateStagedSessions| ('staged' apex becomes 'active')
 // |ApexFileRepository::AddDataApex| (add 'active' apex to repository)
 android::base::Result<ApexPartition> VerifyBrandNewPackageAgainstPreinstalled(
     const ApexFile& apex);
diff --git a/apexd/apexd_brand_new_verifier_test.cpp b/apexd/apexd_brand_new_verifier_test.cpp
index 78d4675f..efc2bb2c 100644
--- a/apexd/apexd_brand_new_verifier_test.cpp
+++ b/apexd/apexd_brand_new_verifier_test.cpp
@@ -35,16 +35,10 @@ namespace android::apex {
 
 namespace fs = std::filesystem;
 
-using android::base::GetExecutableDirectory;
 using android::base::testing::Ok;
 using android::base::testing::WithMessage;
 using ::testing::Not;
 
-static std::string GetTestDataDir() { return GetExecutableDirectory(); }
-static std::string GetTestFile(const std::string& name) {
-  return GetTestDataDir() + "/" + name;
-}
-
 TEST(BrandNewApexVerifierTest, SucceedPublicKeyMatch) {
   ApexFileRepository::EnableBrandNewApex();
   auto& file_repository = ApexFileRepository::GetInstance();
diff --git a/apexd/apexd_image_manager.cpp b/apexd/apexd_image_manager.cpp
new file mode 100644
index 00000000..d45a2663
--- /dev/null
+++ b/apexd/apexd_image_manager.cpp
@@ -0,0 +1,173 @@
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
+#include "apexd_image_manager.h"
+
+#include <android-base/result.h>
+#include <android-base/unique_fd.h>
+#include <sys/sendfile.h>
+
+#include <algorithm>
+#include <chrono>
+
+#include "apexd.h"
+#include "apexd_utils.h"
+
+using android::base::borrowed_fd;
+using android::base::ErrnoError;
+using android::base::Error;
+using android::base::Result;
+using android::base::unique_fd;
+using namespace std::chrono_literals;
+
+namespace android::apex {
+
+namespace {
+
+ApexImageManager* gImageManager;
+
+Result<void> SendFile(borrowed_fd dest_fd, const std::string& src_path,
+                      size_t size) {
+  unique_fd src_fd(open(src_path.c_str(), O_RDONLY));
+  if (!src_fd.ok()) {
+    return Error() << "Failed to open " << src_path;
+  }
+  int rc = sendfile(dest_fd.get(), src_fd, nullptr, size);
+  if (rc == -1) {
+    return ErrnoError() << "Failed to sendfile from " << src_path;
+  }
+  return {};
+}
+
+// Find a unique "image" name for the apex name: e.g. com.android.foo_2.apex
+std::string AllocateNewName(const std::vector<std::string>& known_names,
+                            const std::string& apex_name) {
+  // Note that because fsmgr's ImageManager uses the name as partition name,
+  // the name can't be longer than 36. Let's limit the name up to 26 and reserve
+  // the suffix (e.g "_0000.apex")
+  auto base_name = apex_name.substr(0, 26);
+  auto count = std::ranges::count_if(known_names, [&](const auto& name) {
+    return name.starts_with(base_name);
+  });
+  // Find free slot for the "base_name"
+  for (auto i = 0; i < count; i++) {
+    std::string new_name = base_name + "_" + std::to_string(i) + ".apex";
+    if (std::ranges::find(known_names, new_name) == known_names.end()) {
+      return new_name;
+    }
+  }
+  return base_name + "_" + std::to_string(count) + ".apex";
+}
+
+}  // namespace
+
+ApexImageManager::ApexImageManager(const std::string& metadata_dir,
+                                   const std::string& data_dir)
+    : metadata_dir_(metadata_dir),
+      data_dir_(data_dir),
+      fsmgr_(fiemap::ImageManager::Open(metadata_dir, data_dir)) {}
+
+// PinApexFiles makes apex_files accessible even before /data is mounted. At a
+// high-level, it pins those apex files, extract their extents, and save the
+// extents in metadata_dir_. Later on, regardless of whether /data is mounted or
+// not, one can use the extents to build dm-liner block devices which will give
+// direct access to the apex files content, effectively bypassing the filesystem
+// layer.
+//
+// However, in reality, it's slightly more complex than this. Any data stored in
+// /data is encrypted via dm-default-key. This means that if you construct the
+// dm-liner block devices directly from the extents of the apex files, you will
+// get encrypted data when reading the block devices.
+//
+// To work around this problem, for each apex file, this function creates a new
+// file in data_dir_/<name>.img that has the size >= size of the apex
+// file. That new file is then pinned, and its extents are saved to
+// metadata_dir_/. Then the function constructs a temporary dm-linear block
+// device using the extents and copy the content of apex file to the block
+// device. By doing so, the block device have unencrypted copy of the apex file.
+//
+// This comes with a size overhead of extra copies of APEX files and wasted
+// space due to the file-system specific granularity of pinned files.
+// (TODO/402256229)
+Result<std::vector<std::string>> ApexImageManager::PinApexFiles(
+    std::span<const ApexFile> apex_files) {
+  std::vector<std::string> new_images;
+  // On error, clean up new backing files
+  auto guard = base::make_scope_guard([&]() {
+    for (const auto& image : new_images) {
+      fsmgr_->DeleteBackingImage(image);
+    }
+  });
+
+  for (const auto& apex_file : apex_files) {
+    // Get a unique "image" name from the apex name
+    auto image_name = AllocateNewName(fsmgr_->GetAllBackingImages(),
+                                      apex_file.GetManifest().name());
+
+    auto apex_path = apex_file.GetPath();
+    auto file_size = OR_RETURN(GetFileSize(apex_path));
+
+    // Create a pinned file for the apex file using
+    // fiemap::ImageManager::CreateBackingImage() which creates
+    // /data/apex/images/{image_name}.img and saves its extents in
+    // /metadata/apex/images/lp_metadata.
+    auto status = fsmgr_->CreateBackingImage(image_name, file_size, 0);
+    if (!status.is_ok()) {
+      return Error() << "Failed to create a pinned backing file for "
+                     << apex_path;
+    }
+    new_images.emplace_back(image_name);
+
+    // Now, copy the apex file to the pinned file thru the block device which
+    // bypasseses the filesystem (/data) and encyryption layer (dm-default-key).
+    // MappedDevice::Open() constructs a dm-linear device from the extents of
+    // the pinned file.
+    auto device = fiemap::MappedDevice::Open(fsmgr_.get(), 10s, image_name);
+    if (!device) {
+      return Error() << "Failed to map the image: " << image_name;
+    }
+    OR_RETURN(SendFile(device->fd(), apex_path, file_size));
+  }
+
+  guard.Disable();
+  return new_images;
+}
+
+Result<void> ApexImageManager::DeleteImage(const std::string& image) {
+  if (!fsmgr_->DeleteBackingImage(image)) {
+    return Error() << "Failed to delete backing image: " << image;
+  }
+  return {};
+}
+
+std::vector<std::string> ApexImageManager::GetAllImages() {
+  return fsmgr_->GetAllBackingImages();
+}
+
+ApexImageManager* GetImageManager() { return gImageManager; }
+
+void InitializeImageManager(ApexImageManager* image_manager) {
+  gImageManager = image_manager;
+}
+
+std::unique_ptr<ApexImageManager> ApexImageManager::Create(
+    const std::string& metadata_images_dir,
+    const std::string& data_images_dir) {
+  return std::unique_ptr<ApexImageManager>(
+      new ApexImageManager(metadata_images_dir, data_images_dir));
+}
+
+}  // namespace android::apex
\ No newline at end of file
diff --git a/apexd/apexd_image_manager.h b/apexd/apexd_image_manager.h
new file mode 100644
index 00000000..e0f2047e
--- /dev/null
+++ b/apexd/apexd_image_manager.h
@@ -0,0 +1,60 @@
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
+#pragma once
+
+#include <android-base/result.h>
+#include <libfiemap/image_manager.h>
+
+#include <memory>
+#include <span>
+#include <string>
+#include <vector>
+
+#include "apex_file.h"
+
+namespace android::apex {
+
+class ApexImageManager {
+ public:
+  ~ApexImageManager() = default;
+
+  // Pin APEX files in /data/apex/images and save their metadata(e.g. FIEMAP
+  // extents) in /metadata/apex/images so that they are available before /data
+  // partition is mounted.
+  // Returns names which correspond to pinned APEX files.
+  base::Result<std::vector<std::string>> PinApexFiles(
+      std::span<const ApexFile> apex_files);
+  base::Result<void> DeleteImage(const std::string& image);
+  std::vector<std::string> GetAllImages();
+
+  static std::unique_ptr<ApexImageManager> Create(
+      const std::string& metadata_images_dir,
+      const std::string& data_images_dir);
+
+ private:
+  ApexImageManager(const std::string& metadata_dir,
+                   const std::string& data_dir);
+
+  std::string metadata_dir_;
+  std::string data_dir_;
+  std::unique_ptr<fiemap::IImageManager> fsmgr_;
+};
+
+void InitializeImageManager(ApexImageManager* image_manager);
+ApexImageManager* GetImageManager();
+
+}  // namespace android::apex
\ No newline at end of file
diff --git a/apexd/apexd_image_manager_test.cpp b/apexd/apexd_image_manager_test.cpp
new file mode 100644
index 00000000..f9bc2bbb
--- /dev/null
+++ b/apexd/apexd_image_manager_test.cpp
@@ -0,0 +1,57 @@
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
+#include "apexd_image_manager.h"
+
+#include <android-base/result-gmock.h>
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+#include "apexd_test_utils.h"
+
+using namespace std::literals;
+
+using android::base::testing::HasValue;
+using android::base::testing::Ok;
+using testing::IsEmpty;
+
+namespace android::apex {
+
+TEST(ApexImageManagerTest, EmptyWhenDirectoriesAreNotReady) {
+  // For the first boot, apexd-bootstrap starts without /data or /metadata
+  // directories.
+  auto image_manager =
+      ApexImageManager::Create("/no-metadata-images", "/no-data-images");
+  ASSERT_THAT(image_manager->GetAllImages(), IsEmpty());
+}
+
+TEST(ApexImageManagerTest, PinApexFiles) {
+  TemporaryDir metadata_dir;
+  TemporaryDir data_dir;
+  auto image_manager =
+      ApexImageManager::Create(metadata_dir.path, data_dir.path);
+
+  auto apex1 = ApexFile::Open(GetTestFile("apex.apexd_test.apex"));
+  ASSERT_THAT(apex1, Ok());
+  auto apex2 =
+      ApexFile::Open(GetTestFile("apex.apexd_test_different_app.apex"));
+  ASSERT_THAT(apex2, Ok());
+  ASSERT_THAT(image_manager->PinApexFiles(std::vector{*apex1, *apex2}),
+              HasValue(std::vector{"com.android.apex.test_pack_0.apex"s,
+                                   "com.android.apex.test_pack_1.apex"s}));
+}
+
+}  // namespace android::apex
\ No newline at end of file
diff --git a/apexd/apexd_loop.cpp b/apexd/apexd_loop.cpp
index a8155cd1..44a2f226 100644
--- a/apexd/apexd_loop.cpp
+++ b/apexd/apexd_loop.cpp
@@ -47,6 +47,7 @@
 #include "apexd_utils.h"
 
 using android::base::Basename;
+using android::base::Dirname;
 using android::base::ErrnoError;
 using android::base::Error;
 using android::base::GetBoolProperty;
@@ -125,32 +126,40 @@ static Result<std::string> PartitionParent(const std::string& blockdev) {
   if (blockdev.find('/') != std::string::npos) {
     return Error() << "Invalid argument " << blockdev;
   }
-  std::error_code ec;
-  for (const auto& entry :
-       std::filesystem::directory_iterator("/sys/class/block", ec)) {
-    const std::string path = entry.path().string();
-    if (std::filesystem::exists(
-            StringPrintf("%s/%s", path.c_str(), blockdev.c_str()))) {
-      return Basename(path);
-    }
+
+  std::string link_path;
+  std::string path = "/sys/class/block/" + blockdev;
+  if (!android::base::Readlink(path, &link_path)) {
+    PLOG(ERROR) << "readlink('" << path << "') failed";
+    return blockdev;
   }
-  return blockdev;
+
+  if (Basename(link_path) != blockdev) {
+    LOG(ERROR) << "readlink('" << path << "') returned '" << link_path
+               << "' but it doesn't end with '" << blockdev << "'";
+    return blockdev;
+  }
+
+  // for parent devices like "sda", link_path looks like ".../block/sda"
+  // for child devices like "sda26", link_path looks like ".../block/sda/sda26"
+  std::string parent_path = Dirname(link_path);
+  std::string parent = Basename(parent_path);
+  if (parent != "block")
+    return parent;
+  else
+    return blockdev;
 }
 
 // Convert a major:minor pair into a block device name.
-static std::string BlockdevName(dev_t dev) {
-  std::error_code ec;
-  for (const auto& entry :
-       std::filesystem::directory_iterator("/dev/block", ec)) {
-    struct stat statbuf;
-    if (stat(entry.path().string().c_str(), &statbuf) < 0) {
-      continue;
-    }
-    if (dev == statbuf.st_rdev) {
-      return Basename(entry.path().string());
-    }
+static Result<std::string> BlockdevName(dev_t dev) {
+  std::string link_path;
+  std::string path = "/sys/dev/block/" + std::to_string(major(dev)) + ":" +
+                     std::to_string(minor(dev));
+  if (!android::base::Readlink(path, &link_path)) {
+    return ErrnoErrorf("readlink('{}') failed", path.c_str());
   }
-  return {};
+
+  return Basename(link_path);
 }
 
 // For file `file_path`, retrieve the block device backing the filesystem on
@@ -160,17 +169,32 @@ static std::string BlockdevName(dev_t dev) {
 // -> /dev/block/dm-1 (system_b; dm-linear)
 // -> /dev/sda26
 static Result<uint32_t> BlockDeviceQueueDepth(const std::string& file_path) {
+  static std::unordered_map<std::string, uint32_t> cache;
+  static std::mutex cache_mutex;
+
   struct stat statbuf;
   int res = stat(file_path.c_str(), &statbuf);
   if (res < 0) {
     return ErrnoErrorf("stat({})", file_path.c_str());
   }
-  std::string blockdev = "/dev/block/" + BlockdevName(statbuf.st_dev);
-  LOG(VERBOSE) << file_path << " -> " << blockdev;
-  if (blockdev.empty()) {
-    return Errorf("Failed to convert {}:{} (path {})", major(statbuf.st_dev),
-                  minor(statbuf.st_dev), file_path.c_str());
+  std::string blockdev;
+  if (auto blockdev_name = BlockdevName(statbuf.st_dev); blockdev_name.ok()) {
+    blockdev = "/dev/block/" + *blockdev_name;
+    LOG(VERBOSE) << file_path << " -> " << blockdev;
+  } else {
+    return Error() << "Failed to convert " << major(statbuf.st_dev) << ":"
+                   << minor(statbuf.st_dev)
+                   << "to block device name: " << blockdev_name.error();
+  }
+
+  {
+    std::lock_guard<std::mutex> lock(cache_mutex);
+    auto it = cache.find(blockdev);
+    if (it != cache.end()) {
+      return it->second;
+    }
   }
+
   auto& dm = DeviceMapper::Instance();
   for (;;) {
     std::optional<std::string> child = dm.GetParentBlockDeviceByPath(blockdev);
@@ -200,7 +224,13 @@ static Result<uint32_t> BlockDeviceQueueDepth(const std::string& file_path) {
   nr_tags = android::base::Trim(nr_tags);
   LOG(VERBOSE) << file_path << " is backed by /dev/" << blockdev
                << " and that block device supports queue depth " << nr_tags;
-  return strtol(nr_tags.c_str(), NULL, 0);
+  uint32_t result = strtol(nr_tags.c_str(), NULL, 0);
+
+  {
+    std::lock_guard<std::mutex> lock(cache_mutex);
+    cache[blockdev] = result;
+  }
+  return result;
 }
 
 // Set 'nr_requests' of `loop_device_path` equal to the queue depth of
diff --git a/apexd/apexd_main.cpp b/apexd/apexd_main.cpp
index 91cbfb88..c0c8e9a8 100644
--- a/apexd/apexd_main.cpp
+++ b/apexd/apexd_main.cpp
@@ -27,6 +27,7 @@
 #include "apex_file_repository.h"
 #include "apexd.h"
 #include "apexd_checkpoint_vold.h"
+#include "apexd_image_manager.h"
 #include "apexd_lifecycle.h"
 #include "apexd_metrics_stats.h"
 #include "apexservice.h"
@@ -83,9 +84,6 @@ int HandleSubcommand(int argc, char** argv) {
       android::apex::InitializeVold(&*vold_service_st);
     }
 
-    // We are running regular apexd, which starts after /metadata/apex/sessions
-    // and /data/apex/sessions have been created by init. It is safe to create
-    // ApexSessionManager.
     auto session_manager = android::apex::ApexSessionManager::Create(
         android::apex::GetSessionsDir());
     android::apex::InitializeSessionManager(session_manager.get());
@@ -171,13 +169,14 @@ int main(int argc, char** argv) {
       android::apex::ApexdLifecycle::GetInstance();
   bool booting = lifecycle.IsBooting();
 
+  auto image_manager = android::apex::ApexImageManager::Create(
+      android::apex::kMetadataImagesDir, android::apex::kDataImagesDir);
+  android::apex::InitializeImageManager(image_manager.get());
+
   if (has_subcommand) {
     return HandleSubcommand(argc, argv);
   }
 
-  // We are running regular apexd, which starts after /metadata/apex/sessions
-  // and /data/apex/sessions have been created by init. It is safe to create
-  // ApexSessionManager.
   auto session_manager = android::apex::ApexSessionManager::Create(
       android::apex::GetSessionsDir());
   android::apex::InitializeSessionManager(session_manager.get());
@@ -195,12 +194,6 @@ int main(int argc, char** argv) {
   android::apex::InitMetrics(std::make_unique<android::apex::StatsLog>());
 
   if (booting) {
-    auto res = session_manager->MigrateFromOldSessionsDir(
-        android::apex::kOldApexSessionsDir);
-    if (!res.ok()) {
-      LOG(ERROR) << "Failed to migrate sessions to /metadata partition : "
-                 << res.error();
-    }
     android::apex::OnStart();
   } else {
     // TODO(b/172911822): Trying to use data apex related ApexFileRepository
diff --git a/apexd/apexd_microdroid.cpp b/apexd/apexd_microdroid.cpp
index 41f20f05..d78b2c57 100644
--- a/apexd/apexd_microdroid.cpp
+++ b/apexd/apexd_microdroid.cpp
@@ -37,6 +37,7 @@ static const android::apex::ApexdConfig kMicrodroidConfig = {
     nullptr, /* staged_session_dir */
     android::apex::kVmPayloadMetadataPartitionProp,
     nullptr, /* active_apex_selinux_ctx */
+    false,   /* mount_before_data */
 };
 
 int main(int /*argc*/, char** argv) {
diff --git a/apexd/apexd_session.cpp b/apexd/apexd_session.cpp
index db772ee2..025caa20 100644
--- a/apexd/apexd_session.cpp
+++ b/apexd/apexd_session.cpp
@@ -60,19 +60,7 @@ static Result<SessionState> ParseSessionState(const std::string& session_dir) {
 
 }  // namespace
 
-std::string GetSessionsDir() {
-  static std::string result;
-  static std::once_flag once_flag;
-  std::call_once(once_flag, [&]() {
-    auto status =
-        FindFirstExistingDirectory(kNewApexSessionsDir, kOldApexSessionsDir);
-    if (!status.ok()) {
-      LOG(FATAL) << status.error();
-    }
-    result = std::move(*status);
-  });
-  return result;
-}
+std::string GetSessionsDir() { return kApexSessionsDir; }
 
 ApexSession::ApexSession(SessionState state, std::string session_dir)
     : state_(std::move(state)), session_dir_(std::move(session_dir)) {}
@@ -134,6 +122,11 @@ ApexSession::GetApexFileHashes() const {
   return state_.apex_file_hashes();
 }
 
+const google::protobuf::RepeatedPtrField<std::string>
+ApexSession::GetApexImages() const {
+  return state_.apex_images();
+}
+
 const std::string& ApexSession::GetSessionDir() const { return session_dir_; }
 
 void ApexSession::SetBuildFingerprint(const std::string& fingerprint) {
@@ -169,6 +162,10 @@ void ApexSession::SetApexFileHashes(const std::vector<std::string>& hashes) {
   *(state_.mutable_apex_file_hashes()) = {hashes.begin(), hashes.end()};
 }
 
+void ApexSession::SetApexImages(const std::vector<std::string>& images) {
+  *(state_.mutable_apex_images()) = {images.begin(), images.end()};
+}
+
 Result<void> ApexSession::UpdateStateAndCommit(
     const SessionState::State& session_state) {
   state_.set_state(session_state);
@@ -222,15 +219,6 @@ std::vector<std::string> ApexSession::GetStagedApexDirs(
 ApexSessionManager::ApexSessionManager(std::string sessions_base_dir)
     : sessions_base_dir_(std::move(sessions_base_dir)) {}
 
-ApexSessionManager::ApexSessionManager(ApexSessionManager&& other) noexcept
-    : sessions_base_dir_(std::move(other.sessions_base_dir_)) {}
-
-ApexSessionManager& ApexSessionManager::operator=(
-    ApexSessionManager&& other) noexcept {
-  sessions_base_dir_ = std::move(other.sessions_base_dir_);
-  return *this;
-}
-
 std::unique_ptr<ApexSessionManager> ApexSessionManager::Create(
     std::string sessions_base_dir) {
   return std::unique_ptr<ApexSessionManager>(
@@ -295,18 +283,6 @@ std::vector<ApexSession> ApexSessionManager::GetSessionsInState(
   return sessions;
 }
 
-Result<void> ApexSessionManager::MigrateFromOldSessionsDir(
-    const std::string& old_sessions_base_dir) {
-  if (old_sessions_base_dir == sessions_base_dir_) {
-    LOG(INFO)
-        << old_sessions_base_dir
-        << " is the same as the current session directory. Nothing to migrate";
-    return {};
-  }
-
-  return MoveDir(old_sessions_base_dir, sessions_base_dir_);
-}
-
 bool ApexSessionManager::HasActiveSession() {
   for (auto& s : GetSessions()) {
     if (!s.IsFinalized() &&
diff --git a/apexd/apexd_session.h b/apexd/apexd_session.h
index 97411a84..1978a0bb 100644
--- a/apexd/apexd_session.h
+++ b/apexd/apexd_session.h
@@ -28,17 +28,11 @@
 namespace android {
 namespace apex {
 
-// Starting from R, apexd prefers /metadata partition (kNewApexSessionsDir) as
-// location for sessions-related information. For devices that don't have
-// /metadata partition, apexd will fallback to the /data one
-// (kOldApexSessionsDir).
-static constexpr const char* kOldApexSessionsDir = "/data/apex/sessions";
-static constexpr const char* kNewApexSessionsDir = "/metadata/apex/sessions";
+// apexd uses the /metadata partition (kApexSessionsDir) as
+// location for sessions-related information.
+static constexpr const char* kApexSessionsDir = "/metadata/apex/sessions";
 
 // Returns top-level directory to store sessions metadata in.
-// If device has /metadata partition, this will return
-// /metadata/apex/sessions, on all other devices it will return
-// /data/apex/sessions.
 std::string GetSessionsDir();
 
 // TODO(b/288309411): remove static functions in this class.
@@ -59,6 +53,7 @@ class ApexSession {
   const google::protobuf::RepeatedPtrField<std::string> GetApexNames() const;
   const google::protobuf::RepeatedPtrField<std::string> GetApexFileHashes()
       const;
+  const google::protobuf::RepeatedPtrField<std::string> GetApexImages() const;
   const std::string& GetSessionDir() const;
 
   void SetChildSessionIds(const std::vector<int>& child_session_ids);
@@ -70,6 +65,7 @@ class ApexSession {
   void SetErrorMessage(const std::string& error_message);
   void AddApexName(const std::string& apex_name);
   void SetApexFileHashes(const std::vector<std::string>& hashes);
+  void SetApexImages(const std::vector<std::string>& images);
 
   android::base::Result<void> UpdateStateAndCommit(
       const ::apex::proto::SessionState::State& state);
@@ -90,9 +86,6 @@ class ApexSession {
 
 class ApexSessionManager {
  public:
-  ApexSessionManager(ApexSessionManager&&) noexcept;
-  ApexSessionManager& operator=(ApexSessionManager&&) noexcept;
-
   static std::unique_ptr<ApexSessionManager> Create(
       std::string sessions_base_dir);
 
@@ -102,9 +95,6 @@ class ApexSessionManager {
   std::vector<ApexSession> GetSessionsInState(
       const ::apex::proto::SessionState::State& state) const;
 
-  android::base::Result<void> MigrateFromOldSessionsDir(
-      const std::string& old_sessions_base_dir);
-
   bool HasActiveSession();
   void DeleteFinalizedSessions();
 
@@ -112,6 +102,8 @@ class ApexSessionManager {
   explicit ApexSessionManager(std::string sessions_base_dir);
   ApexSessionManager(const ApexSessionManager&) = delete;
   ApexSessionManager& operator=(const ApexSessionManager&) = delete;
+  ApexSessionManager(ApexSessionManager&&) = delete;
+  ApexSessionManager& operator=(ApexSessionManager&&) = delete;
 
   std::string sessions_base_dir_;
 };
diff --git a/apexd/apexd_session_test.cpp b/apexd/apexd_session_test.cpp
index 233bbc11..3ec36485 100644
--- a/apexd/apexd_session_test.cpp
+++ b/apexd/apexd_session_test.cpp
@@ -48,24 +48,6 @@ using ::testing::UnorderedElementsAre;
 
 // TODO(b/170329726): add unit tests for apexd_sessions.h
 
-TEST(ApexdSessionTest, GetSessionsDirSessionsStoredInMetadata) {
-  if (access("/metadata", F_OK) != 0) {
-    GTEST_SKIP() << "Device doesn't have /metadata partition";
-  }
-
-  std::string result = GetSessionsDir();
-  ASSERT_EQ(result, "/metadata/apex/sessions");
-}
-
-TEST(ApexdSessionTest, GetSessionsDirNoMetadataPartitionFallbackToData) {
-  if (access("/metadata", F_OK) == 0) {
-    GTEST_SKIP() << "Device has /metadata partition";
-  }
-
-  std::string result = GetSessionsDir();
-  ASSERT_EQ(result, "/data/apex/sessions");
-}
-
 TEST(ApexSessionManagerTest, CreateSession) {
   TemporaryDir td;
   auto manager = ApexSessionManager::Create(std::string(td.path));
@@ -178,104 +160,6 @@ TEST(ApexSessionManager, GetSessionsInState) {
   ASSERT_EQ(SessionState::SUCCESS, sessions[1].GetState());
 }
 
-TEST(ApexSessionManager, MigrateFromOldSessionsDir) {
-  TemporaryDir td;
-  auto old_manager = ApexSessionManager::Create(std::string(td.path));
-
-  auto session1 = old_manager->CreateSession(239);
-  ASSERT_RESULT_OK(session1);
-  ASSERT_RESULT_OK(session1->UpdateStateAndCommit(SessionState::STAGED));
-
-  auto session2 = old_manager->CreateSession(13);
-  ASSERT_RESULT_OK(session2);
-  ASSERT_RESULT_OK(session2->UpdateStateAndCommit(SessionState::SUCCESS));
-
-  auto session3 = old_manager->CreateSession(31);
-  ASSERT_RESULT_OK(session3);
-  ASSERT_RESULT_OK(session3->UpdateStateAndCommit(SessionState::ACTIVATED));
-
-  TemporaryDir td2;
-  auto new_manager = ApexSessionManager::Create(std::string(td2.path));
-
-  ASSERT_RESULT_OK(
-      new_manager->MigrateFromOldSessionsDir(std::string(td.path)));
-
-  auto sessions = new_manager->GetSessions();
-  std::sort(
-      sessions.begin(), sessions.end(),
-      [](const auto& s1, const auto& s2) { return s1.GetId() < s2.GetId(); });
-
-  ASSERT_EQ(3u, sessions.size());
-
-  ASSERT_EQ(13, sessions[0].GetId());
-  ASSERT_EQ(SessionState::SUCCESS, sessions[0].GetState());
-
-  ASSERT_EQ(31, sessions[1].GetId());
-  ASSERT_EQ(SessionState::ACTIVATED, sessions[1].GetState());
-
-  ASSERT_EQ(239, sessions[2].GetId());
-  ASSERT_EQ(SessionState::STAGED, sessions[2].GetState());
-
-  // Check that old manager directory doesn't have anything
-  auto old_sessions = old_manager->GetSessions();
-  ASSERT_TRUE(old_sessions.empty());
-}
-
-TEST(ApexSessionManager, MigrateFromOldSessionsDirSameDir) {
-  TemporaryDir td;
-  auto old_manager = ApexSessionManager::Create(std::string(td.path));
-
-  auto session1 = old_manager->CreateSession(239);
-  ASSERT_RESULT_OK(session1);
-  ASSERT_RESULT_OK(session1->UpdateStateAndCommit(SessionState::STAGED));
-
-  auto session2 = old_manager->CreateSession(13);
-  ASSERT_RESULT_OK(session2);
-  ASSERT_RESULT_OK(session2->UpdateStateAndCommit(SessionState::SUCCESS));
-
-  auto session3 = old_manager->CreateSession(31);
-  ASSERT_RESULT_OK(session3);
-  ASSERT_RESULT_OK(session3->UpdateStateAndCommit(SessionState::ACTIVATED));
-
-  auto new_manager = ApexSessionManager::Create(std::string(td.path));
-
-  ASSERT_RESULT_OK(
-      new_manager->MigrateFromOldSessionsDir(std::string(td.path)));
-
-  auto sessions = new_manager->GetSessions();
-  std::sort(
-      sessions.begin(), sessions.end(),
-      [](const auto& s1, const auto& s2) { return s1.GetId() < s2.GetId(); });
-
-  ASSERT_EQ(3u, sessions.size());
-
-  ASSERT_EQ(13, sessions[0].GetId());
-  ASSERT_EQ(SessionState::SUCCESS, sessions[0].GetState());
-
-  ASSERT_EQ(31, sessions[1].GetId());
-  ASSERT_EQ(SessionState::ACTIVATED, sessions[1].GetState());
-
-  ASSERT_EQ(239, sessions[2].GetId());
-  ASSERT_EQ(SessionState::STAGED, sessions[2].GetState());
-
-  // Directory is the same, so using old_manager should also work.
-  auto old_sessions = old_manager->GetSessions();
-  std::sort(
-      old_sessions.begin(), old_sessions.end(),
-      [](const auto& s1, const auto& s2) { return s1.GetId() < s2.GetId(); });
-
-  ASSERT_EQ(3u, old_sessions.size());
-
-  ASSERT_EQ(13, old_sessions[0].GetId());
-  ASSERT_EQ(SessionState::SUCCESS, old_sessions[0].GetState());
-
-  ASSERT_EQ(31, old_sessions[1].GetId());
-  ASSERT_EQ(SessionState::ACTIVATED, old_sessions[1].GetState());
-
-  ASSERT_EQ(239, old_sessions[2].GetId());
-  ASSERT_EQ(SessionState::STAGED, old_sessions[2].GetState());
-}
-
 TEST(ApexSessionManagerTest, GetStagedApexDirsSelf) {
   TemporaryDir td;
   auto manager = ApexSessionManager::Create(std::string(td.path));
diff --git a/apexd/apexd_test.cpp b/apexd/apexd_test.cpp
index a0c95a4b..f0b87aa4 100644
--- a/apexd/apexd_test.cpp
+++ b/apexd/apexd_test.cpp
@@ -45,6 +45,7 @@
 #include "apex_file_repository.h"
 #include "apex_manifest.pb.h"
 #include "apexd_checkpoint.h"
+#include "apexd_image_manager.h"
 #include "apexd_loop.h"
 #include "apexd_metrics.h"
 #include "apexd_session.h"
@@ -85,20 +86,18 @@ using ::testing::ByRef;
 using ::testing::Contains;
 using ::testing::ElementsAre;
 using ::testing::EndsWith;
+using ::testing::Eq;
 using ::testing::HasSubstr;
 using ::testing::IsEmpty;
 using ::testing::Not;
+using ::testing::Pointwise;
+using ::testing::Property;
 using ::testing::StartsWith;
 using ::testing::UnorderedElementsAre;
 using ::testing::UnorderedElementsAreArray;
 using ::testing::internal::CaptureStderr;
 using ::testing::internal::GetCapturedStderr;
 
-static std::string GetTestDataDir() { return GetExecutableDirectory(); }
-static std::string GetTestFile(const std::string& name) {
-  return GetTestDataDir() + "/" + name;
-}
-
 static int64_t GetMTime(const std::string& path) {
   struct stat st_buf;
   if (stat(path.c_str(), &st_buf) != 0) {
@@ -117,6 +116,18 @@ static int64_t GetSizeByBlocks(const std::string& path) {
   return st_buf.st_blocks * st_buf.st_blksize;
 }
 
+static Result<ApexFile> GetActivePackage(const std::string& packageName) {
+  std::vector<ApexFile> packages = GetActivePackages();
+  for (ApexFile& apex : packages) {
+    if (apex.GetManifest().name() == packageName) {
+      return std::move(apex);
+    }
+  }
+
+  return base::ErrnoError()
+         << "Cannot find matching package for: " << packageName;
+}
+
 // A very basic mock of CheckpointInterface.
 class MockCheckpointInterface : public CheckpointInterface {
  public:
@@ -166,14 +177,22 @@ class ApexdUnitTest : public ::testing::Test {
         StringPrintf("%s/metadata-staged-session-dir", td_.path);
     session_manager_ = ApexSessionManager::Create(sessions_metadata_dir_);
 
-    config_ = {kTestApexdStatusSysprop,
-               {{partition_, built_in_dir_}},
-               data_dir_.c_str(),
-               decompression_dir_.c_str(),
-               ota_reserved_dir_.c_str(),
-               staged_session_dir_.c_str(),
-               kTestVmPayloadMetadataPartitionProp,
-               kTestActiveApexSelinuxCtx};
+    metadata_images_dir_ = StringPrintf("%s/metadata-images", td_.path);
+    data_images_dir_ = StringPrintf("%s/data-images", td_.path);
+    image_manager_ =
+        ApexImageManager::Create(metadata_images_dir_, data_images_dir_);
+
+    config_ = ApexdConfig{
+        kTestApexdStatusSysprop,
+        {{partition_, built_in_dir_}},
+        data_dir_.c_str(),
+        decompression_dir_.c_str(),
+        ota_reserved_dir_.c_str(),
+        staged_session_dir_.c_str(),
+        kTestVmPayloadMetadataPartitionProp,
+        kTestActiveApexSelinuxCtx,
+        false, /*mount_before_data*/
+    };
   }
 
   const std::string& GetBuiltInDir() { return built_in_dir_; }
@@ -231,26 +250,32 @@ class ApexdUnitTest : public ::testing::Test {
   }
 
   // Copies the compressed apex to |built_in_dir| and decompresses it to
-  // |decompressed_dir| and then hard links to |target_dir|
-  std::string PrepareCompressedApex(const std::string& name,
-                                    const std::string& built_in_dir) {
+  // |decompressed_dir| and returns both paths as tuple.
+  std::tuple<std::string, std::string> PrepareCompressedApex(
+      const std::string& name, const std::string& built_in_dir) {
     fs::copy(GetTestFile(name), built_in_dir);
-    auto compressed_apex = ApexFile::Open(
-        StringPrintf("%s/%s", built_in_dir.c_str(), name.c_str()));
+    auto compressed_file_path =
+        StringPrintf("%s/%s", built_in_dir.c_str(), name.c_str());
+    auto compressed_apex = ApexFile::Open(compressed_file_path);
     std::vector<ApexFileRef> compressed_apex_list;
     compressed_apex_list.emplace_back(std::cref(*compressed_apex));
-    auto return_value =
+    auto decompressed =
         ProcessCompressedApex(compressed_apex_list, /*is_ota_chroot*/ false);
-    return StringPrintf("%s/%s", built_in_dir.c_str(), name.c_str());
+    CHECK(decompressed.size() == 1);
+    return std::make_tuple(compressed_file_path, decompressed[0].GetPath());
   }
 
-  std::string PrepareCompressedApex(const std::string& name) {
+  std::tuple<std::string, std::string> PrepareCompressedApex(
+      const std::string& name) {
     return PrepareCompressedApex(name, built_in_dir_);
   }
 
-  void PrepareStagedSession(const std::string& apex_name, int session_id) {
-    CreateDirIfNeeded(GetStagedDir(session_id), 0755);
-    fs::copy(GetTestFile(apex_name), GetStagedDir(session_id));
+  std::string PrepareStagedSession(const std::string& apex_name,
+                                   int session_id) {
+    auto session_dir = GetStagedDir(session_id);
+    CreateDirIfNeeded(session_dir, 0755);
+    fs::copy(GetTestFile(apex_name), session_dir);
+    return session_dir + "/" + apex_name;
   }
 
   Result<ApexSession> CreateStagedSession(const std::string& apex_name,
@@ -274,6 +299,8 @@ class ApexdUnitTest : public ::testing::Test {
     ASSERT_EQ(mkdir(ota_reserved_dir_.c_str(), 0755), 0);
     ASSERT_EQ(mkdir(staged_session_dir_.c_str(), 0755), 0);
     ASSERT_EQ(mkdir(sessions_metadata_dir_.c_str(), 0755), 0);
+    ASSERT_EQ(mkdir(metadata_images_dir_.c_str(), 0755), 0);
+    ASSERT_EQ(mkdir(data_images_dir_.c_str(), 0755), 0);
 
     // We don't really need for all the test cases, but until we refactor apexd
     // to use dependency injection instead of this SetConfig approach, it is not
@@ -281,9 +308,15 @@ class ApexdUnitTest : public ::testing::Test {
     // initialize it for all of them.
     InitializeSessionManager(GetSessionManager());
     DeleteDirContent(GetSessionsDir());
+
+    InitializeImageManager(image_manager_.get());
   }
 
-  void TearDown() override { DeleteDirContent(GetSessionsDir()); }
+  void TearDown() override {
+    DeleteDirContent(GetSessionsDir());
+    // Reset vold; some tests changing this might affect other tests.
+    InitializeVold(nullptr);
+  }
 
  protected:
   TemporaryDir td_;
@@ -299,6 +332,10 @@ class ApexdUnitTest : public ::testing::Test {
   std::string sessions_metadata_dir_;
   std::unique_ptr<ApexSessionManager> session_manager_;
 
+  std::string metadata_images_dir_;
+  std::string data_images_dir_;
+  std::unique_ptr<ApexImageManager> image_manager_;
+
   ApexdConfig config_;
 };
 
@@ -320,14 +357,7 @@ TEST_F(ApexdUnitTest, SelectApexForActivationSuccess) {
       AddDataApex("com.android.apex.test.sharedlibs_generated.v1.libvX.apex"));
   ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
 
-  const auto all_apex = instance.AllApexFilesByName();
-  // Pass a blank instance so that no apex file is considered
-  // pre-installed
-  const ApexFileRepository instance_blank;
-  auto result = SelectApexForActivation(all_apex, instance_blank);
-  ASSERT_EQ(result.size(), 6u);
-  // When passed proper instance they should get selected
-  result = SelectApexForActivation(all_apex, instance);
+  auto result = SelectApexForActivation();
   ASSERT_EQ(result.size(), 3u);
   ASSERT_THAT(result, UnorderedElementsAre(ApexFileEq(ByRef(*apexd_test_file)),
                                            ApexFileEq(ByRef(*shim_v1)),
@@ -349,8 +379,7 @@ TEST_F(ApexdUnitTest, HigherVersionOfApexIsSelected) {
       ApexFile::Open(AddDataApex("com.android.apex.cts.shim.v2.apex"));
   ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
 
-  auto all_apex = instance.AllApexFilesByName();
-  auto result = SelectApexForActivation(all_apex, instance);
+  auto result = SelectApexForActivation();
   ASSERT_EQ(result.size(), 2u);
 
   ASSERT_THAT(result,
@@ -372,8 +401,7 @@ TEST_F(ApexdUnitTest, DataApexGetsPriorityForSameVersions) {
   // Initialize ApexFile repo
   ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
 
-  auto all_apex = instance.AllApexFilesByName();
-  auto result = SelectApexForActivation(all_apex, instance);
+  auto result = SelectApexForActivation();
   ASSERT_EQ(result.size(), 2u);
 
   ASSERT_THAT(result, UnorderedElementsAre(ApexFileEq(ByRef(*apexd_test_file)),
@@ -395,8 +423,7 @@ TEST_F(ApexdUnitTest, SharedLibsCanHaveBothVersionSelected) {
   // Initialize data APEX information
   ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
 
-  auto all_apex = instance.AllApexFilesByName();
-  auto result = SelectApexForActivation(all_apex, instance);
+  auto result = SelectApexForActivation();
   ASSERT_EQ(result.size(), 2u);
 
   ASSERT_THAT(result, UnorderedElementsAre(ApexFileEq(ByRef(*shared_lib_v1)),
@@ -418,8 +445,7 @@ TEST_F(ApexdUnitTest, SharedLibsDataVersionDeletedIfLower) {
   // Initialize data APEX information
   ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
 
-  auto all_apex = instance.AllApexFilesByName();
-  auto result = SelectApexForActivation(all_apex, instance);
+  auto result = SelectApexForActivation();
   ASSERT_EQ(result.size(), 1u);
 
   ASSERT_THAT(result, UnorderedElementsAre(ApexFileEq(ByRef(*shared_lib_v2))));
@@ -593,140 +619,125 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexReuseOtaApex) {
                          kDecompressedApexPackageSuffix));
 }
 
-TEST_F(ApexdUnitTest, ShouldAllocateSpaceForDecompressionNewApex) {
-  auto& instance = ApexFileRepository::GetInstance();
-  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
-              Ok());
+TEST_F(ApexdUnitTest, ShouldAllocateSpaceForDecompression_NewApex) {
+  ApexFileRepository instance;
+  MountedApexDatabase db;
 
   // A brand new compressed APEX is being introduced: selected
-  bool result =
-      ShouldAllocateSpaceForDecompression("com.android.brand.new", 1, instance);
+  bool result = ShouldAllocateSpaceForDecompression("com.android.brand.new", 1,
+                                                    instance, db);
   ASSERT_TRUE(result);
 }
 
 TEST_F(ApexdUnitTest,
-       ShouldAllocateSpaceForDecompressionWasNotCompressedBefore) {
-  // Prepare fake pre-installed apex
-  AddPreInstalledApex("apex.apexd_test.apex");
-  auto& instance = ApexFileRepository::GetInstance();
+       ShouldAllocateSpaceForDecompression_WasNotCompressedBefore) {
+  ApexFileRepository instance;
+  auto preinstalled_path = AddPreInstalledApex("apex.apexd_test.apex");
   ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
               Ok());
 
   // An existing pre-installed APEX is now compressed in the OTA: selected
   {
+    MountedApexDatabase db;
+    db.AddMountedApex("com.android.apex.test_package", 1, "", preinstalled_path,
+                      "mount_point", "device_name");
     bool result = ShouldAllocateSpaceForDecompression(
-        "com.android.apex.test_package", 1, instance);
+        "com.android.apex.test_package", 1, instance, db);
     ASSERT_TRUE(result);
   }
 
   // Even if there is a data apex (lower version)
   // Include data apex within calculation now
-  AddDataApex("apex.apexd_test_v2.apex");
+  auto data_path = AddDataApex("apex.apexd_test_v2.apex");
   ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
   {
+    MountedApexDatabase db;
+    db.AddMountedApex("com.android.apex.test_package", 2, "", data_path,
+                      "mount_point", "device_name");
     bool result = ShouldAllocateSpaceForDecompression(
-        "com.android.apex.test_package", 3, instance);
+        "com.android.apex.test_package", 3, instance, db);
     ASSERT_TRUE(result);
   }
 
   // But not if data apex has equal or higher version
   {
+    MountedApexDatabase db;
+    db.AddMountedApex("com.android.apex.test_package", 2, "", data_path,
+                      "mount_point", "device_name");
     bool result = ShouldAllocateSpaceForDecompression(
-        "com.android.apex.test_package", 2, instance);
+        "com.android.apex.test_package", 2, instance, db);
     ASSERT_FALSE(result);
   }
 }
 
-TEST_F(ApexdUnitTest, ShouldAllocateSpaceForDecompressionVersionCompare) {
+TEST_F(ApexdUnitTest, ShouldAllocateSpaceForDecompression_VersionCompare) {
   // Prepare fake pre-installed apex
-  PrepareCompressedApex("com.android.apex.compressed.v1.capex");
-  auto& instance = ApexFileRepository::GetInstance();
+  ApexFileRepository instance(decompression_dir_);
+  auto [_, decompressed_path] =
+      PrepareCompressedApex("com.android.apex.compressed.v1.capex");
   ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
               Ok());
-  ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
+  // Fake mount
+  MountedApexDatabase db;
+  db.AddMountedApex("com.android.apex.compressed", 1, "", decompressed_path,
+                    "mount_point", "device_name");
 
   {
     // New Compressed apex has higher version than decompressed data apex:
     // selected
+
     bool result = ShouldAllocateSpaceForDecompression(
-        "com.android.apex.compressed", 2, instance);
+        "com.android.apex.compressed", 2, instance, db);
     ASSERT_TRUE(result)
         << "Higher version test with decompressed data returned false";
   }
 
   // Compare against decompressed data apex
   {
-    // New Compressed apex has same version as decompressed data apex: not
-    // selected
+    // New Compressed apex has same version as decompressed data apex: selected
     bool result = ShouldAllocateSpaceForDecompression(
-        "com.android.apex.compressed", 1, instance);
-    ASSERT_FALSE(result)
-        << "Same version test with decompressed data returned true";
+        "com.android.apex.compressed", 1, instance, db);
+    ASSERT_TRUE(result) << "Even with same version, the incoming apex may have "
+                           "a different size. Need to decompress";
   }
 
   {
     // New Compressed apex has lower version than decompressed data apex:
     // selected
     bool result = ShouldAllocateSpaceForDecompression(
-        "com.android.apex.compressed", 0, instance);
+        "com.android.apex.compressed", 0, instance, db);
     ASSERT_TRUE(result)
         << "lower version test with decompressed data returned false";
   }
 
   // Replace decompressed data apex with a higher version
-  ApexFileRepository instance_new(GetDecompressionDir());
-  ASSERT_THAT(
-      instance_new.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
-      Ok());
-  TemporaryDir data_dir_new;
-  fs::copy(GetTestFile("com.android.apex.compressed.v2_original.apex"),
-           data_dir_new.path);
-  ASSERT_THAT(instance_new.AddDataApex(data_dir_new.path), Ok());
-
+  auto data_path = AddDataApex("com.android.apex.compressed.v2_original.apex");
+  ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
+  db.Reset();
+  db.AddMountedApex("com.android.apex.compressed", 2, "", data_path,
+                    "mount_point", "device_name");
   {
     // New Compressed apex has higher version as data apex: selected
     bool result = ShouldAllocateSpaceForDecompression(
-        "com.android.apex.compressed", 3, instance_new);
+        "com.android.apex.compressed", 3, instance, db);
     ASSERT_TRUE(result) << "Higher version test with new data returned false";
   }
 
   {
     // New Compressed apex has same version as data apex: not selected
     bool result = ShouldAllocateSpaceForDecompression(
-        "com.android.apex.compressed", 2, instance_new);
+        "com.android.apex.compressed", 2, instance, db);
     ASSERT_FALSE(result) << "Same version test with new data returned true";
   }
 
   {
     // New Compressed apex has lower version than data apex: not selected
     bool result = ShouldAllocateSpaceForDecompression(
-        "com.android.apex.compressed", 1, instance_new);
+        "com.android.apex.compressed", 1, instance, db);
     ASSERT_FALSE(result) << "lower version test with new data returned true";
   }
 }
 
-TEST_F(ApexdUnitTest, CalculateSizeForCompressedApexEmptyList) {
-  ApexFileRepository instance;
-  int64_t result = CalculateSizeForCompressedApex({}, instance);
-  ASSERT_EQ(0LL, result);
-}
-
-TEST_F(ApexdUnitTest, CalculateSizeForCompressedApex) {
-  ApexFileRepository instance;
-  AddPreInstalledApex("com.android.apex.compressed.v1.capex");
-  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
-              Ok());
-
-  std::vector<std::tuple<std::string, int64_t, int64_t>> input = {
-      std::make_tuple("new_apex", 1, 1),
-      std::make_tuple("new_apex_2", 1, 2),
-      std::make_tuple("com.android.apex.compressed", 1, 4),  // will be ignored
-      std::make_tuple("com.android.apex.compressed", 2, 8),
-  };
-  int64_t result = CalculateSizeForCompressedApex(input, instance);
-  ASSERT_EQ(1 + 2 + 8LL, result);
-}
-
 TEST_F(ApexdUnitTest, ReserveSpaceForCompressedApexCreatesSingleFile) {
   TemporaryDir dest_dir;
   // Reserving space should create a single file in dest_dir with exact size
@@ -907,27 +918,28 @@ class ApexdMountTest : public ApexdUnitTest {
     vm_payload_disk_ = StringPrintf("%s/vm-payload", td_.path);
   }
 
-  void UnmountOnTearDown(const std::string& apex_file) {
-    to_unmount_.push_back(apex_file);
-  }
-
  protected:
-  void SetUp() final {
+  void SetUp() override {
     ApexdUnitTest::SetUp();
     GetApexDatabaseForTesting().Reset();
     GetChangedActiveApexesForTesting().clear();
     ASSERT_THAT(SetUpApexTestEnvironment(), Ok());
   }
 
-  void TearDown() final {
-    ApexdUnitTest::TearDown();
+  void TearDown() override {
     SetBlockApexEnabled(false);
-    for (const auto& apex : to_unmount_) {
+    auto activated = std::vector<std::string>{};
+    GetApexDatabaseForTesting().ForallMountedApexes(
+        [&](auto pkg, auto data, auto latest) {
+          activated.push_back(data.full_path);
+        });
+    for (const auto& apex : activated) {
       if (auto status = DeactivatePackage(apex); !status.ok()) {
         LOG(ERROR) << "Failed to unmount " << apex << " : " << status.error();
       }
     }
     InitMetrics({});  // reset
+    ApexdUnitTest::TearDown();
   }
 
   void SetBlockApexEnabled(bool enabled) {
@@ -976,7 +988,6 @@ class ApexdMountTest : public ApexdUnitTest {
 
  private:
   MountNamespaceRestorer restorer_;
-  std::vector<std::string> to_unmount_;
 
   // Block APEX specific stuff.
   std::string vm_payload_disk_;
@@ -987,6 +998,48 @@ class ApexdMountTest : public ApexdUnitTest {
   std::vector<BlockApex> block_apexes_;
 };
 
+TEST_F(ApexdMountTest, CalculateSizeForCompressedApexEmptyList) {
+  int64_t result = CalculateSizeForCompressedApex({});
+  ASSERT_EQ(0LL, result);
+}
+
+TEST_F(ApexdMountTest, CalculateSizeForCompressedApex) {
+  auto& instance = ApexFileRepository::GetInstance();
+  AddPreInstalledApex("com.android.apex.compressed.v1.capex");
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
+
+  OnStart();
+
+  std::vector<std::tuple<std::string, int64_t, int64_t>> input = {
+      std::make_tuple("new_apex", 1, 1),
+      std::make_tuple("new_apex_2", 1, 2),
+      std::make_tuple("com.android.apex.compressed", 1, 8),
+  };
+  int64_t result = CalculateSizeForCompressedApex(input);
+  ASSERT_EQ(1 + 2 + 8LL, result);
+}
+
+TEST_F(
+    ApexdMountTest,
+    CalculateSizeForCompressedApex_SkipIfDataApexIsNewerThanOrEqualToPreInstalledApex) {
+  auto& instance = ApexFileRepository::GetInstance();
+  AddPreInstalledApex("com.android.apex.compressed.v1.capex");
+  AddDataApex("com.android.apex.compressed.v2_original.apex");
+  ASSERT_THAT(instance.AddPreInstalledApex({{GetPartition(), GetBuiltInDir()}}),
+              Ok());
+  ASSERT_THAT(instance.AddDataApex(GetDataDir()), Ok());
+
+  OnStart();
+
+  std::vector<std::tuple<std::string, int64_t, int64_t>> input = {
+      std::make_tuple("new_apex", 1, 1),
+      std::make_tuple("com.android.apex.compressed", 2, 8),  // ignored
+  };
+  int64_t result = CalculateSizeForCompressedApex(input);
+  ASSERT_EQ(1LL, result);
+}
+
 // TODO(b/187864524): cover other negative scenarios.
 TEST_F(ApexdMountTest, InstallPackageRejectsApexWithoutRebootlessSupport) {
   std::string file_path = AddPreInstalledApex("apex.apexd_test.apex");
@@ -994,7 +1047,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsApexWithoutRebootlessSupport) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret =
       InstallPackage(GetTestFile("apex.apexd_test.apex"), /* force= */ false);
@@ -1029,7 +1081,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsManifestMismatch) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret =
       InstallPackage(GetTestFile("test.rebootless_apex_manifest_mismatch.apex"),
@@ -1046,7 +1097,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsCorrupted) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_corrupted.apex"),
                             /* force= */ false);
@@ -1060,7 +1110,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsProvidesSharedLibs) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret = InstallPackage(
       GetTestFile("test.rebootless_apex_provides_sharedlibs.apex"),
@@ -1074,7 +1123,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsProvidesNativeLibs) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret = InstallPackage(
       GetTestFile("test.rebootless_apex_provides_native_libs.apex"),
@@ -1088,7 +1136,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsRequiresSharedApexLibs) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret = InstallPackage(
       GetTestFile("test.rebootless_apex_requires_shared_apex_libs.apex"),
@@ -1103,7 +1150,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsJniLibs) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_jni_libs.apex"),
                             /* force= */ false);
@@ -1116,13 +1162,11 @@ TEST_F(ApexdMountTest, InstallPackageAcceptsAddRequiredNativeLib) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret =
       InstallPackage(GetTestFile("test.rebootless_apex_add_native_lib.apex"),
                      /* force= */ false);
   ASSERT_THAT(ret, Ok());
-  UnmountOnTearDown(ret->GetPath());
 }
 
 TEST_F(ApexdMountTest, InstallPackageAcceptsRemoveRequiredNativeLib) {
@@ -1131,13 +1175,11 @@ TEST_F(ApexdMountTest, InstallPackageAcceptsRemoveRequiredNativeLib) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret =
       InstallPackage(GetTestFile("test.rebootless_apex_remove_native_lib.apex"),
                      /* force= */ false);
   ASSERT_THAT(ret, Ok());
-  UnmountOnTearDown(ret->GetPath());
 }
 
 TEST_F(ApexdMountTest, InstallPackageRejectsAppInApex) {
@@ -1146,7 +1188,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsAppInApex) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret = InstallPackage(
       GetTestFile("test.rebootless_apex_app_in_apex.apex"), /* force= */ false);
@@ -1159,7 +1200,6 @@ TEST_F(ApexdMountTest, InstallPackageRejectsPrivAppInApex) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret =
       InstallPackage(GetTestFile("test.rebootless_apex_priv_app_in_apex.apex"),
@@ -1174,7 +1214,6 @@ TEST_F(ApexdMountTest, InstallPackagePreInstallVersionActive) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   {
     auto active_apex = GetActivePackage("test.apex.rebootless");
@@ -1185,7 +1224,6 @@ TEST_F(ApexdMountTest, InstallPackagePreInstallVersionActive) {
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_v2.apex"),
                             /* force= */ false);
   ASSERT_THAT(ret, Ok());
-  UnmountOnTearDown(ret->GetPath());
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -1223,7 +1261,6 @@ TEST_F(ApexdMountTest, InstallPackagePreInstallVersionActiveSamegrade) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   {
     auto active_apex = GetActivePackage("test.apex.rebootless");
@@ -1234,7 +1271,6 @@ TEST_F(ApexdMountTest, InstallPackagePreInstallVersionActiveSamegrade) {
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_v1.apex"),
                             /* force= */ false);
   ASSERT_THAT(ret, Ok());
-  UnmountOnTearDown(ret->GetPath());
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -1274,12 +1310,10 @@ TEST_F(ApexdMountTest, InstallPackageUnloadOldApex) {
   });
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_v2.apex"),
                             /* force= */ false);
   ASSERT_THAT(ret, Ok());
-  UnmountOnTearDown(ret->GetPath());
 
   monitor_apex_ready_prop.join();
   ASSERT_TRUE(unloaded);
@@ -1292,7 +1326,6 @@ TEST_F(ApexdMountTest, InstallPackageWithService) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_service_v2.apex"),
                             /* force= */ false);
@@ -1300,7 +1333,6 @@ TEST_F(ApexdMountTest, InstallPackageWithService) {
   auto manifest = ReadManifest("/apex/test.apex.rebootless/apex_manifest.pb");
   ASSERT_THAT(manifest, Ok());
   ASSERT_EQ(2u, manifest->version());
-  UnmountOnTearDown(ret->GetPath());
 }
 
 TEST_F(ApexdMountTest, InstallPackageDataVersionActive) {
@@ -1310,7 +1342,6 @@ TEST_F(ApexdMountTest, InstallPackageDataVersionActive) {
 
   std::string file_path = AddDataApex("test.rebootless_apex_v1.apex");
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   {
     auto active_apex = GetActivePackage("test.apex.rebootless");
@@ -1321,7 +1352,6 @@ TEST_F(ApexdMountTest, InstallPackageDataVersionActive) {
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_v2.apex"),
                             /* force= */ false);
   ASSERT_THAT(ret, Ok());
-  UnmountOnTearDown(ret->GetPath());
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -1361,7 +1391,6 @@ TEST_F(ApexdMountTest, InstallPackageResolvesPathCollision) {
   std::string file_path = AddDataApex("test.rebootless_apex_v1.apex",
                                       "test.apex.rebootless@1_1.apex");
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   {
     auto active_apex = GetActivePackage("test.apex.rebootless");
@@ -1372,7 +1401,6 @@ TEST_F(ApexdMountTest, InstallPackageResolvesPathCollision) {
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_v1.apex"),
                             /* force= */ false);
   ASSERT_THAT(ret, Ok());
-  UnmountOnTearDown(ret->GetPath());
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -1415,7 +1443,6 @@ TEST_F(ApexdMountTest, InstallPackageDataVersionActiveSamegrade) {
 
   std::string file_path = AddDataApex("test.rebootless_apex_v2.apex");
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   {
     auto active_apex = GetActivePackage("test.apex.rebootless");
@@ -1426,7 +1453,6 @@ TEST_F(ApexdMountTest, InstallPackageDataVersionActiveSamegrade) {
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_v2.apex"),
                             /* force= */ false);
   ASSERT_THAT(ret, Ok());
-  UnmountOnTearDown(ret->GetPath());
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -1464,7 +1490,6 @@ TEST_F(ApexdMountTest, InstallPackageUnmountFailsPreInstalledApexActive) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   {
     auto active_apex = GetActivePackage("test.apex.rebootless");
@@ -1511,7 +1536,6 @@ TEST_F(ApexdMountTest, InstallPackageUnmountFailedUpdatedApexActive) {
   std::string file_path = AddDataApex("test.rebootless_apex_v1.apex");
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   {
     auto active_apex = GetActivePackage("test.apex.rebootless");
@@ -1556,8 +1580,6 @@ TEST_F(ApexdMountTest, InstallPackageUpdatesApexInfoList) {
   ApexFileRepository::GetInstance().AddPreInstalledApex(
       {{GetPartition(), GetBuiltInDir()}});
 
-  UnmountOnTearDown(apex_1);
-  UnmountOnTearDown(apex_2);
   ASSERT_THAT(ActivatePackage(apex_1), Ok());
   ASSERT_THAT(ActivatePackage(apex_2), Ok());
 
@@ -1569,7 +1591,6 @@ TEST_F(ApexdMountTest, InstallPackageUpdatesApexInfoList) {
   auto ret = InstallPackage(GetTestFile("test.rebootless_apex_v2.apex"),
                             /* force= */ false);
   ASSERT_THAT(ret, Ok());
-  UnmountOnTearDown(ret->GetPath());
 
   ASSERT_EQ(access("/apex/apex-info-list.xml", F_OK), 0);
   auto info_list =
@@ -1616,7 +1637,6 @@ TEST_F(ApexdMountTest, ActivatePackageNoCode) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   std::string mountinfo;
   ASSERT_TRUE(ReadFileToString("/proc/self/mountinfo", &mountinfo));
@@ -1657,7 +1677,6 @@ TEST_F(ApexdMountTest, ActivatePackage) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto active_apex = GetActivePackage("com.android.apex.test_package");
   ASSERT_THAT(active_apex, Ok());
@@ -1681,7 +1700,6 @@ TEST_F(ApexdMountTest, ActivatePackageShowsUpInMountedApexDatabase) {
       {{GetPartition(), GetBuiltInDir()}});
 
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto active_apex = GetActivePackage("com.android.apex.test_package");
   ASSERT_THAT(active_apex, Ok());
@@ -1713,7 +1731,6 @@ TEST_F(ApexdMountTest, DeactivePackageFreesLoopDevices) {
 
   std::string file_path = AddDataApex("apex.apexd_test_v2.apex");
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   // Get loop devices that were used to mount APEX.
   auto children = ListChildLoopDevices("com.android.apex.test_package@2");
@@ -1740,7 +1757,6 @@ TEST_F(ApexdMountTest, DeactivePackageTearsDownVerityDevice) {
 
   std::string file_path = AddDataApex("apex.apexd_test_v2.apex");
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   ASSERT_THAT(DeactivatePackage(file_path), Ok());
   auto& dm = DeviceMapper::Instance();
@@ -1765,7 +1781,6 @@ TEST_F(ApexdMountTest, ActivateDeactivateSharedLibsApex) {
   ApexFileRepository::GetInstance().AddPreInstalledApex(
       {{GetPartition(), GetBuiltInDir()}});
 
-  UnmountOnTearDown(file_path);
   ASSERT_THAT(ActivatePackage(file_path), Ok());
 
   auto active_apex = GetActivePackage("com.android.apex.test.sharedlibs");
@@ -1812,8 +1827,6 @@ TEST_F(ApexdMountTest, RemoveInactiveDataApex) {
   // Activate some of the apex
   ApexFileRepository::GetInstance().AddPreInstalledApex(
       {{GetPartition(), GetBuiltInDir()}});
-  UnmountOnTearDown(active_decompressed_apex);
-  UnmountOnTearDown(active_data_apex);
   ASSERT_THAT(ActivatePackage(active_decompressed_apex), Ok());
   ASSERT_THAT(ActivatePackage(active_data_apex), Ok());
   // Clean up inactive apex packages
@@ -1833,8 +1846,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapOnlyPreInstalledApexes) {
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(apex_path_2);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -1882,9 +1893,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHasHigherVersion) {
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
-
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -1933,9 +1941,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHasSameVersion) {
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
-
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -1984,9 +1989,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSystemHasHigherVersion) {
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(apex_path_2);
-
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -2027,9 +2029,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHasSameVersionButDifferentKey) {
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(apex_path_2);
-
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -2078,9 +2077,6 @@ TEST_F(ApexdMountTest,
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(apex_path_2);
-
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -2119,8 +2115,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataApexWithoutPreInstalledApex) {
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
-  UnmountOnTearDown(apex_path_1);
-
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -2151,9 +2145,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapPreInstalledSharedLibsApex) {
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
-
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -2236,10 +2227,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSharedLibsApexBothVersions) {
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
-  UnmountOnTearDown(apex_path_4);
-
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -2341,7 +2328,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapOnlyCompressedApexes) {
   std::string decompressed_apex =
       StringPrintf("%s/com.android.apex.compressed@1%s",
                    GetDecompressionDir().c_str(), kOtaApexPackageSuffix);
-  UnmountOnTearDown(decompressed_apex);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2386,7 +2372,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDecompressOnlyOnceMultipleCalls) {
   std::string decompressed_ota_apex =
       StringPrintf("%s/com.android.apex.compressed@1%s",
                    GetDecompressionDir().c_str(), kOtaApexPackageSuffix);
-  UnmountOnTearDown(decompressed_ota_apex);
 
   // Capture the creation time of the OTA APEX
   std::error_code ec;
@@ -2421,7 +2406,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapUpgradeCapex) {
   std::string decompressed_active_apex =
       StringPrintf("%s/com.android.apex.compressed@2%s",
                    GetDecompressionDir().c_str(), kOtaApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2471,7 +2455,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapex) {
   std::string decompressed_active_apex = StringPrintf(
       "%s/com.android.apex.compressed@1%s", GetDecompressionDir().c_str(),
       kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2508,7 +2491,7 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapex) {
 // Test when we update existing CAPEX to same version, but different digest
 TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapexDifferentDigest) {
   TemporaryDir previous_built_in_dir;
-  auto different_digest_apex_path = PrepareCompressedApex(
+  auto [different_digest_apex_path, _] = PrepareCompressedApex(
       "com.android.apex.compressed.v1_different_digest.capex",
       previous_built_in_dir.path);
   // Place a same version capex in current built_in_dir, which has different
@@ -2521,7 +2504,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapexDifferentDigest) {
   std::string decompressed_ota_apex =
       StringPrintf("%s/com.android.apex.compressed@1%s",
                    GetDecompressionDir().c_str(), kOtaApexPackageSuffix);
-  UnmountOnTearDown(decompressed_ota_apex);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2587,7 +2569,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSamegradeCapexDifferentKey) {
   std::string decompressed_active_apex =
       StringPrintf("%s/com.android.apex.compressed@1%s",
                    GetDecompressionDir().c_str(), kOtaApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2633,7 +2614,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapCapexToApex) {
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
   // New uncompressed APEX should be mounted
-  UnmountOnTearDown(apex_path);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2674,7 +2654,6 @@ TEST_F(ApexdMountTest,
   std::string decompressed_active_apex =
       StringPrintf("%s/com.android.apex.compressed@1%s",
                    GetDecompressionDir().c_str(), kOtaApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2700,7 +2679,7 @@ TEST_F(ApexdMountTest,
 
 // Test when we update CAPEX and there is a higher version present in data
 TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHigherThanCapex) {
-  auto system_apex_path =
+  auto [system_apex_path, _] =
       PrepareCompressedApex("com.android.apex.compressed.v1.capex");
   auto data_apex_path =
       AddDataApex("com.android.apex.compressed.v2_original.apex");
@@ -2708,7 +2687,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHigherThanCapex) {
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
   // Data APEX should be mounted
-  UnmountOnTearDown(data_apex_path);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2761,7 +2739,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataLowerThanCapex) {
   std::string decompressed_active_apex =
       StringPrintf("%s/com.android.apex.compressed@2%s",
                    GetDecompressionDir().c_str(), kOtaApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2797,14 +2774,13 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataLowerThanCapex) {
 
 // Test when we update CAPEX and there is a same version present in data
 TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataSameAsCapex) {
-  auto system_apex_path =
+  auto [system_apex_path, _] =
       PrepareCompressedApex("com.android.apex.compressed.v1.capex");
   auto data_apex_path = AddDataApex("com.android.apex.compressed.v1.apex");
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
   // Data APEX should be mounted
-  UnmountOnTearDown(data_apex_path);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2857,7 +2833,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDataHasDifferentKeyThanCapex) {
   std::string decompressed_active_apex =
       StringPrintf("%s/com.android.apex.compressed@1%s",
                    GetDecompressionDir().c_str(), kOtaApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -2903,8 +2878,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSystemDataStagedInSameVersion) {
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/true), 0);
 
-  UnmountOnTearDown(apex_path_3);
-
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -2945,8 +2918,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSystemNewerThanDataStaged) {
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/true), 0);
 
-  UnmountOnTearDown(apex_path_1);
-
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -2986,8 +2957,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapSelinuxLabelsAreCorrect) {
       "com.android.apex.test.sharedlibs_generated.v1.libvX.apex");
   std::string apex_path_3 = AddDataApex("apex.apexd_test_v2.apex");
 
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
 
   EXPECT_EQ(GetSelinuxContext("/apex/apex-info-list.xml"),
@@ -3009,8 +2978,6 @@ TEST_F(ApexdMountTest, OnOtaChrootBootstrapDmDevicesHaveCorrectName) {
   std::string apex_path_3 = AddDataApex("apex.apexd_test_v2.apex");
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
 
   MountedApexDatabase& db = GetApexDatabaseForTesting();
   // com.android.apex.test_package_2 should be mounted directly on top of loop
@@ -3039,7 +3006,6 @@ TEST_F(ApexdMountTest,
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
-  UnmountOnTearDown(apex_path_2);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -3080,8 +3046,6 @@ TEST_F(ApexdMountTest,
       AddDataApex("apex.apexd_test_manifest_mismatch.apex");
 
   ASSERT_EQ(OnOtaChrootBootstrap(/*also_include_staged_apexes=*/false), 0);
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(apex_path_2);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -3116,10 +3080,6 @@ TEST_F(ApexdMountTest,
 }
 
 TEST_F(ApexdMountTest, OnStartOnlyPreInstalledApexes) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   std::string apex_path_1 = AddPreInstalledApex("apex.apexd_test.apex");
   std::string apex_path_2 =
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
@@ -3130,9 +3090,6 @@ TEST_F(ApexdMountTest, OnStartOnlyPreInstalledApexes) {
 
   OnStart();
 
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(apex_path_2);
-
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -3143,10 +3100,6 @@ TEST_F(ApexdMountTest, OnStartOnlyPreInstalledApexes) {
 }
 
 TEST_F(ApexdMountTest, OnStartDataHasHigherVersion) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   AddPreInstalledApex("apex.apexd_test.apex");
   std::string apex_path_2 =
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
@@ -3158,9 +3111,6 @@ TEST_F(ApexdMountTest, OnStartDataHasHigherVersion) {
 
   OnStart();
 
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
-
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -3171,10 +3121,6 @@ TEST_F(ApexdMountTest, OnStartDataHasHigherVersion) {
 }
 
 TEST_F(ApexdMountTest, OnStartDataHasWrongSHA) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   std::string apex_path = AddPreInstalledApex("com.android.apex.cts.shim.apex");
   AddDataApex("com.android.apex.cts.shim.v2_wrong_sha.apex");
 
@@ -3182,7 +3128,6 @@ TEST_F(ApexdMountTest, OnStartDataHasWrongSHA) {
                   {{GetPartition(), GetBuiltInDir()}}),
               Ok());
 
-  UnmountOnTearDown(apex_path);
   OnStart();
 
   // Check system shim apex is activated instead of the data one.
@@ -3193,10 +3138,6 @@ TEST_F(ApexdMountTest, OnStartDataHasWrongSHA) {
 }
 
 TEST_F(ApexdMountTest, OnStartDataHasSameVersion) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   AddPreInstalledApex("apex.apexd_test.apex");
   std::string apex_path_2 =
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
@@ -3208,9 +3149,6 @@ TEST_F(ApexdMountTest, OnStartDataHasSameVersion) {
 
   OnStart();
 
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
-
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -3229,10 +3167,6 @@ TEST_F(ApexdMountTest, OnStartDataHasSameVersion) {
 }
 
 TEST_F(ApexdMountTest, OnStartSystemHasHigherVersion) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   std::string apex_path_1 = AddPreInstalledApex("apex.apexd_test_v2.apex");
   std::string apex_path_2 =
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
@@ -3244,9 +3178,6 @@ TEST_F(ApexdMountTest, OnStartSystemHasHigherVersion) {
 
   OnStart();
 
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(apex_path_2);
-
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -3265,10 +3196,6 @@ TEST_F(ApexdMountTest, OnStartSystemHasHigherVersion) {
 }
 
 TEST_F(ApexdMountTest, OnStartFailsToActivateApexOnDataFallsBackToBuiltIn) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   std::string apex_path_1 = AddPreInstalledApex("apex.apexd_test.apex");
   std::string apex_path_2 =
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
@@ -3280,9 +3207,6 @@ TEST_F(ApexdMountTest, OnStartFailsToActivateApexOnDataFallsBackToBuiltIn) {
 
   OnStart();
 
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(apex_path_2);
-
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -3301,10 +3225,6 @@ TEST_F(ApexdMountTest, OnStartFailsToActivateApexOnDataFallsBackToBuiltIn) {
 }
 
 TEST_F(ApexdMountTest, OnStartApexOnDataHasWrongKeyFallsBackToBuiltIn) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   std::string apex_path_1 = AddPreInstalledApex("apex.apexd_test.apex");
   std::string apex_path_2 =
       AddPreInstalledApex("apex.apexd_test_different_app.apex");
@@ -3323,9 +3243,6 @@ TEST_F(ApexdMountTest, OnStartApexOnDataHasWrongKeyFallsBackToBuiltIn) {
 
   OnStart();
 
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(apex_path_2);
-
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -3344,10 +3261,6 @@ TEST_F(ApexdMountTest, OnStartApexOnDataHasWrongKeyFallsBackToBuiltIn) {
 }
 
 TEST_F(ApexdMountTest, OnStartOnlyPreInstalledCapexes) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   std::string apex_path_1 =
       AddPreInstalledApex("com.android.apex.compressed.v1.capex");
 
@@ -3361,7 +3274,6 @@ TEST_F(ApexdMountTest, OnStartOnlyPreInstalledCapexes) {
   std::string decompressed_active_apex = StringPrintf(
       "%s/com.android.apex.compressed@1%s", GetDecompressionDir().c_str(),
       kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
@@ -3380,10 +3292,6 @@ TEST_F(ApexdMountTest, OnStartOnlyPreInstalledCapexes) {
 }
 
 TEST_F(ApexdMountTest, OnStartDataHasHigherVersionThanCapex) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   AddPreInstalledApex("com.android.apex.compressed.v1.capex");
   std::string apex_path_2 =
       AddDataApex("com.android.apex.compressed.v2_original.apex");
@@ -3394,8 +3302,6 @@ TEST_F(ApexdMountTest, OnStartDataHasHigherVersionThanCapex) {
 
   OnStart();
 
-  UnmountOnTearDown(apex_path_2);
-
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -3413,10 +3319,6 @@ TEST_F(ApexdMountTest, OnStartDataHasHigherVersionThanCapex) {
 }
 
 TEST_F(ApexdMountTest, OnStartDataHasSameVersionAsCapex) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   AddPreInstalledApex("com.android.apex.compressed.v1.capex");
   std::string apex_path_2 = AddDataApex("com.android.apex.compressed.v1.apex");
 
@@ -3427,7 +3329,6 @@ TEST_F(ApexdMountTest, OnStartDataHasSameVersionAsCapex) {
   OnStart();
 
   // Data APEX should be mounted
-  UnmountOnTearDown(apex_path_2);
 
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
@@ -3447,10 +3348,6 @@ TEST_F(ApexdMountTest, OnStartDataHasSameVersionAsCapex) {
 }
 
 TEST_F(ApexdMountTest, OnStartSystemHasHigherVersionCapexThanData) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   std::string apex_path_1 =
       AddPreInstalledApex("com.android.apex.compressed.v2.capex");
   AddDataApex("com.android.apex.compressed.v1.apex");
@@ -3465,7 +3362,6 @@ TEST_F(ApexdMountTest, OnStartSystemHasHigherVersionCapexThanData) {
   std::string decompressed_active_apex = StringPrintf(
       "%s/com.android.apex.compressed@2%s", GetDecompressionDir().c_str(),
       kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
@@ -3485,10 +3381,6 @@ TEST_F(ApexdMountTest, OnStartSystemHasHigherVersionCapexThanData) {
 }
 
 TEST_F(ApexdMountTest, OnStartFailsToActivateApexOnDataFallsBackToCapex) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   AddPreInstalledApex("com.android.apex.compressed.v1.capex");
   AddDataApex("com.android.apex.compressed.v2_manifest_mismatch.apex");
 
@@ -3502,7 +3394,6 @@ TEST_F(ApexdMountTest, OnStartFailsToActivateApexOnDataFallsBackToCapex) {
   std::string decompressed_active_apex = StringPrintf(
       "%s/com.android.apex.compressed@1%s", GetDecompressionDir().c_str(),
       kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
@@ -3524,10 +3415,6 @@ TEST_F(ApexdMountTest, OnStartFailsToActivateApexOnDataFallsBackToCapex) {
 // Test scenario when we fallback to capex but it already has a decompressed
 // version on data
 TEST_F(ApexdMountTest, OnStartFallbackToAlreadyDecompressedCapex) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   PrepareCompressedApex("com.android.apex.compressed.v1.capex");
   AddDataApex("com.android.apex.compressed.v2_manifest_mismatch.apex");
 
@@ -3541,7 +3428,6 @@ TEST_F(ApexdMountTest, OnStartFallbackToAlreadyDecompressedCapex) {
   std::string decompressed_active_apex = StringPrintf(
       "%s/com.android.apex.compressed@1%s", GetDecompressionDir().c_str(),
       kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
@@ -3562,10 +3448,6 @@ TEST_F(ApexdMountTest, OnStartFallbackToAlreadyDecompressedCapex) {
 // Test scenario when we fallback to capex but it has same version as corrupt
 // data apex
 TEST_F(ApexdMountTest, OnStartFallbackToCapexSameVersion) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   AddPreInstalledApex("com.android.apex.compressed.v2.capex");
   // Add data apex using the common naming convention for /data/apex/active
   // directory
@@ -3582,7 +3464,6 @@ TEST_F(ApexdMountTest, OnStartFallbackToCapexSameVersion) {
   std::string decompressed_active_apex = StringPrintf(
       "%s/com.android.apex.compressed@2%s", GetDecompressionDir().c_str(),
       kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
@@ -3601,10 +3482,6 @@ TEST_F(ApexdMountTest, OnStartFallbackToCapexSameVersion) {
 }
 
 TEST_F(ApexdMountTest, OnStartCapexToApex) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   TemporaryDir previous_built_in_dir;
   PrepareCompressedApex("com.android.apex.compressed.v1.capex",
                         previous_built_in_dir.path);
@@ -3617,7 +3494,6 @@ TEST_F(ApexdMountTest, OnStartCapexToApex) {
   OnStart();
 
   // Uncompressed APEX should be mounted
-  UnmountOnTearDown(apex_path);
 
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
@@ -3636,10 +3512,6 @@ TEST_F(ApexdMountTest, OnStartCapexToApex) {
 
 // Test to ensure we do not mount decompressed APEX from /data/apex/active
 TEST_F(ApexdMountTest, OnStartOrphanedDecompressedApexInActiveDirectory) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   // Place a decompressed APEX in /data/apex/active. This apex should not
   // be mounted since it's not in correct location. Instead, the
   // pre-installed APEX should be mounted.
@@ -3657,7 +3529,6 @@ TEST_F(ApexdMountTest, OnStartOrphanedDecompressedApexInActiveDirectory) {
   OnStart();
 
   // Pre-installed APEX should be mounted
-  UnmountOnTearDown(apex_path);
   auto& db = GetApexDatabaseForTesting();
   // Check that pre-installed APEX has been activated
   db.ForallMountedApexes("com.android.apex.compressed",
@@ -3671,10 +3542,6 @@ TEST_F(ApexdMountTest, OnStartOrphanedDecompressedApexInActiveDirectory) {
 // Test scenario when decompressed version has different version than
 // pre-installed CAPEX
 TEST_F(ApexdMountTest, OnStartDecompressedApexVersionDifferentThanCapex) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   TemporaryDir previous_built_in_dir;
   PrepareCompressedApex("com.android.apex.compressed.v2.capex",
                         previous_built_in_dir.path);
@@ -3691,7 +3558,6 @@ TEST_F(ApexdMountTest, OnStartDecompressedApexVersionDifferentThanCapex) {
   std::string decompressed_active_apex = StringPrintf(
       "%s/com.android.apex.compressed@1%s", GetDecompressionDir().c_str(),
       kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "starting");
   auto apex_mounts = GetApexMounts();
@@ -3711,10 +3577,6 @@ TEST_F(ApexdMountTest, OnStartDecompressedApexVersionDifferentThanCapex) {
 
 // Test that ota_apex is persisted until slot switch
 TEST_F(ApexdMountTest, OnStartOtaApexKeptUntilSlotSwitch) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   // Imagine current system has v1 capex and we have v2 incoming via ota
   auto old_capex = AddPreInstalledApex("com.android.apex.compressed.v1.capex");
   auto ota_apex_path =
@@ -3737,8 +3599,6 @@ TEST_F(ApexdMountTest, OnStartOtaApexKeptUntilSlotSwitch) {
   auto new_decompressed_apex = StringPrintf(
       "%s/com.android.apex.compressed@2%s", GetDecompressionDir().c_str(),
       kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(old_decompressed_apex);
-  UnmountOnTearDown(new_decompressed_apex);
 
   // First try starting without slot switch. Since we are booting with
   // old pre-installed capex, ota_apex should not be deleted
@@ -3763,10 +3623,6 @@ TEST_F(ApexdMountTest, OnStartOtaApexKeptUntilSlotSwitch) {
 // digest
 TEST_F(ApexdMountTest,
        OnStartDecompressedApexVersionSameAsCapexDifferentDigest) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   // Push a CAPEX to system without decompressing it
   auto apex_path = AddPreInstalledApex("com.android.apex.compressed.v1.capex");
   auto pre_installed_apex = ApexFile::Open(apex_path);
@@ -3791,7 +3647,6 @@ TEST_F(ApexdMountTest,
 
   // Existing same version decompressed APEX with different root digest should
   // be ignored and the pre-installed CAPEX should be decompressed again.
-  UnmountOnTearDown(decompressed_apex_path);
 
   // Ensure decompressed apex has same digest as pre-installed
   auto decompressed_apex = ApexFile::Open(decompressed_apex_path);
@@ -3803,12 +3658,8 @@ TEST_F(ApexdMountTest,
 
 // Test when decompressed APEX has different key than CAPEX
 TEST_F(ApexdMountTest, OnStartDecompressedApexVersionSameAsCapexDifferentKey) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   TemporaryDir previous_built_in_dir;
-  auto different_key_apex_path =
+  auto [different_key_apex_path, _] =
       PrepareCompressedApex("com.android.apex.compressed_different_key.capex",
                             previous_built_in_dir.path);
   // Place a same version capex in current built_in_dir, which has different key
@@ -3825,7 +3676,6 @@ TEST_F(ApexdMountTest, OnStartDecompressedApexVersionSameAsCapexDifferentKey) {
   std::string decompressed_active_apex = StringPrintf(
       "%s/com.android.apex.compressed@1%s", GetDecompressionDir().c_str(),
       kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   // Ensure decompressed apex has same digest as pre-installed
   auto pre_installed_apex = ApexFile::Open(apex_path);
@@ -3875,8 +3725,6 @@ TEST_F(ApexdMountTest, PopulateFromMountsChecksPathPrefix) {
           other_apex_mount_data.emplace(data);
         }
       });
-  UnmountOnTearDown(apex_path);
-  UnmountOnTearDown(decompressed_apex);
   ASSERT_TRUE(other_apex_mount_data.has_value());
   auto deleter = make_scope_guard([&other_apex_mount_data]() {
     if (!other_apex_mount_data.has_value()) {
@@ -3938,9 +3786,6 @@ TEST_F(ApexdMountTest, UnmountAll) {
   ASSERT_THAT(ActivatePackage(apex_path_2), Ok());
   ASSERT_THAT(ActivatePackage(apex_path_3), Ok());
   ASSERT_THAT(ActivatePackage(decompressed_apex), Ok());
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
-  UnmountOnTearDown(decompressed_apex);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -3984,8 +3829,6 @@ TEST_F(ApexdMountTest, UnmountAllSharedLibsApex) {
 
   ASSERT_THAT(ActivatePackage(apex_path_1), Ok());
   ASSERT_THAT(ActivatePackage(apex_path_2), Ok());
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(apex_path_2);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -4014,8 +3857,6 @@ TEST_F(ApexdMountTest, UnmountAllDeferred) {
 
   ASSERT_THAT(ActivatePackage(apex_path_2), Ok());
   ASSERT_THAT(ActivatePackage(apex_path_3), Ok());
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
 
   ASSERT_THAT(GetApexMounts(),
               UnorderedElementsAre("/apex/com.android.apex.test_package",
@@ -4080,8 +3921,6 @@ TEST_F(ApexdMountTest, UnmountAllStaged) {
 
   ASSERT_THAT(ActivatePackage(apex_path_2), Ok());
   ASSERT_THAT(ActivatePackage(apex_path_3), Ok());
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
@@ -4100,60 +3939,41 @@ TEST_F(ApexdMountTest, UnmountAllStaged) {
 }
 
 TEST_F(ApexdMountTest, OnStartInVmModeActivatesPreInstalled) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   auto path1 = AddPreInstalledApex("apex.apexd_test.apex");
   auto path2 = AddPreInstalledApex("apex.apexd_test_different_app.apex");
   // In VM mode, we don't scan /data/apex
   AddDataApex("apex.apexd_test_v2.apex");
 
   ASSERT_EQ(0, OnStartInVmMode());
-  UnmountOnTearDown(path1);
-  UnmountOnTearDown(path2);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
                                    "/apex/com.android.apex.test_package@1",
                                    "/apex/com.android.apex.test_package_2",
-                                   "/apex/com.android.apex.test_package_2@1",
-                                   // Emits apex-info-list as well
-                                   "/apex/apex-info-list.xml"));
+                                   "/apex/com.android.apex.test_package_2@1"));
 
   ASSERT_EQ(GetProperty(kTestApexdStatusSysprop, ""), "ready");
 }
 
 TEST_F(ApexdMountTest, OnStartInVmModeFailsWithCapex) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   AddPreInstalledApex("com.android.apex.compressed.v2.capex");
 
   ASSERT_EQ(1, OnStartInVmMode());
 }
 
 TEST_F(ApexdMountTest, OnStartInVmModeActivatesBlockDevicesAsWell) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   // Set system property to enable block apexes
   SetBlockApexEnabled(true);
 
   auto path1 = AddBlockApex("apex.apexd_test.apex");
 
   ASSERT_EQ(0, OnStartInVmMode());
-  UnmountOnTearDown(path1);
 
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test_package",
-                                   "/apex/com.android.apex.test_package@1",
-                                   // Emits apex-info-list as well
-                                   "/apex/apex-info-list.xml"));
+                                   "/apex/com.android.apex.test_package@1"));
 
   ASSERT_EQ(access("/apex/apex-info-list.xml", F_OK), 0);
   auto info_list =
@@ -4172,10 +3992,6 @@ TEST_F(ApexdMountTest, OnStartInVmModeActivatesBlockDevicesAsWell) {
 }
 
 TEST_F(ApexdMountTest, OnStartInVmModeFailsWithDuplicateNames) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   // Set system property to enable block apexes
   SetBlockApexEnabled(true);
 
@@ -4198,16 +4014,12 @@ TEST_F(ApexdMountTest, OnStartInVmSupportsMultipleSharedLibsApexes) {
                    /*public_key=*/"", /*root_digest=*/"", /*is_factory=*/false);
 
   ASSERT_EQ(0, OnStartInVmMode());
-  UnmountOnTearDown(path1);
-  UnmountOnTearDown(path2);
 
   // Btw, in case duplicates are sharedlibs apexes, both should be activated
   auto apex_mounts = GetApexMounts();
   ASSERT_THAT(apex_mounts,
               UnorderedElementsAre("/apex/com.android.apex.test.sharedlibs@1",
-                                   "/apex/com.android.apex.test.sharedlibs@2",
-                                   // Emits apex-info-list as well
-                                   "/apex/apex-info-list.xml"));
+                                   "/apex/com.android.apex.test.sharedlibs@2"));
 }
 
 TEST_F(ApexdMountTest, OnStartInVmShouldRejectInDuplicateFactoryApexes) {
@@ -4223,8 +4035,6 @@ TEST_F(ApexdMountTest, OnStartInVmShouldRejectInDuplicateFactoryApexes) {
                    /*public_key=*/"", /*root_digest=*/"", /*is_factory=*/true);
 
   ASSERT_EQ(1, OnStartInVmMode());
-  UnmountOnTearDown(path1);
-  UnmountOnTearDown(path2);
 }
 
 TEST_F(ApexdMountTest, OnStartInVmShouldRejectInDuplicateNonFactoryApexes) {
@@ -4240,15 +4050,9 @@ TEST_F(ApexdMountTest, OnStartInVmShouldRejectInDuplicateNonFactoryApexes) {
                    /*public_key=*/"", /*root_digest=*/"", /*is_factory=*/false);
 
   ASSERT_EQ(1, OnStartInVmMode());
-  UnmountOnTearDown(path1);
-  UnmountOnTearDown(path2);
 }
 
 TEST_F(ApexdMountTest, OnStartInVmModeFailsWithWrongPubkey) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   // Set system property to enable block apexes
   SetBlockApexEnabled(true);
 
@@ -4258,17 +4062,12 @@ TEST_F(ApexdMountTest, OnStartInVmModeFailsWithWrongPubkey) {
 }
 
 TEST_F(ApexdMountTest, GetActivePackagesReturningBlockApexesAsWell) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   // Set system property to enable block apexes
   SetBlockApexEnabled(true);
 
   auto path1 = AddBlockApex("apex.apexd_test.apex");
 
   ASSERT_EQ(0, OnStartInVmMode());
-  UnmountOnTearDown(path1);
 
   auto active_apexes = GetActivePackages();
   ASSERT_EQ(1u, active_apexes.size());
@@ -4276,10 +4075,6 @@ TEST_F(ApexdMountTest, GetActivePackagesReturningBlockApexesAsWell) {
 }
 
 TEST_F(ApexdMountTest, OnStartInVmModeFailsWithWrongRootDigest) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   // Set system property to enable block apexes
   SetBlockApexEnabled(true);
 
@@ -4292,10 +4087,6 @@ TEST_F(ApexdMountTest, OnStartInVmModeFailsWithWrongRootDigest) {
 class ApexActivationFailureTests : public ApexdMountTest {};
 
 TEST_F(ApexActivationFailureTests, BuildFingerprintDifferent) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   auto apex_session = CreateStagedSession("apex.apexd_test.apex", 123);
   ASSERT_RESULT_OK(apex_session);
   apex_session->SetBuildFingerprint("wrong fingerprint");
@@ -4310,10 +4101,6 @@ TEST_F(ApexActivationFailureTests, BuildFingerprintDifferent) {
 }
 
 TEST_F(ApexActivationFailureTests, ApexFileMissingInStagingDirectory) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   auto apex_session = CreateStagedSession("apex.apexd_test.apex", 123);
   ASSERT_RESULT_OK(apex_session);
   apex_session->UpdateStateAndCommit(SessionState::STAGED);
@@ -4324,15 +4111,10 @@ TEST_F(ApexActivationFailureTests, ApexFileMissingInStagingDirectory) {
 
   apex_session = GetSessionManager()->GetSession(123);
   ASSERT_RESULT_OK(apex_session);
-  ASSERT_THAT(apex_session->GetErrorMessage(),
-              HasSubstr("No APEX packages found"));
+  ASSERT_THAT(apex_session->GetErrorMessage(), HasSubstr("Found: 0"));
 }
 
 TEST_F(ApexActivationFailureTests, MultipleApexFileInStagingDirectory) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   auto apex_session = CreateStagedSession("apex.apexd_test.apex", 123);
   ASSERT_RESULT_OK(apex_session);
   CreateStagedSession("com.android.apex.compressed.v1.apex", 123);
@@ -4342,15 +4124,10 @@ TEST_F(ApexActivationFailureTests, MultipleApexFileInStagingDirectory) {
 
   apex_session = GetSessionManager()->GetSession(123);
   ASSERT_RESULT_OK(apex_session);
-  ASSERT_THAT(apex_session->GetErrorMessage(),
-              HasSubstr("More than one APEX package found"));
+  ASSERT_THAT(apex_session->GetErrorMessage(), HasSubstr("Found: 2"));
 }
 
 TEST_F(ApexActivationFailureTests, CorruptedSuperblockApexCannotBeStaged) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   auto apex_session =
       CreateStagedSession("apex.apexd_test_corrupt_superblock_apex.apex", 123);
   apex_session->UpdateStateAndCommit(SessionState::STAGED);
@@ -4365,10 +4142,6 @@ TEST_F(ApexActivationFailureTests, CorruptedSuperblockApexCannotBeStaged) {
 }
 
 TEST_F(ApexActivationFailureTests, CorruptedApexCannotBeStaged) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   auto apex_session = CreateStagedSession("corrupted_b146895998.apex", 123);
   ASSERT_RESULT_OK(apex_session);
   apex_session->UpdateStateAndCommit(SessionState::STAGED);
@@ -4382,10 +4155,6 @@ TEST_F(ApexActivationFailureTests, CorruptedApexCannotBeStaged) {
 }
 
 TEST_F(ApexActivationFailureTests, ActivatePackageImplFails) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   auto shim_path = AddPreInstalledApex("com.android.apex.cts.shim.apex");
   auto& instance = ApexFileRepository::GetInstance();
   ASSERT_RESULT_OK(
@@ -4396,7 +4165,6 @@ TEST_F(ApexActivationFailureTests, ActivatePackageImplFails) {
   ASSERT_RESULT_OK(apex_session);
   apex_session->UpdateStateAndCommit(SessionState::STAGED);
 
-  UnmountOnTearDown(shim_path);
   OnStart();
 
   apex_session = GetSessionManager()->GetSession(123);
@@ -4423,7 +4191,6 @@ TEST_F(ApexActivationFailureTests,
   ASSERT_RESULT_OK(apex_session);
   apex_session->UpdateStateAndCommit(SessionState::STAGED);
 
-  UnmountOnTearDown(pre_installed_apex);
   OnStart();
 
   apex_session = GetSessionManager()->GetSession(123);
@@ -4450,7 +4217,6 @@ TEST_F(ApexActivationFailureTests, StagedSessionRevertsWhenInFsRollbackMode) {
   ASSERT_RESULT_OK(apex_session);
   apex_session->UpdateStateAndCommit(SessionState::STAGED);
 
-  UnmountOnTearDown(pre_installed_apex);
   OnStart();
 
   apex_session = GetSessionManager()->GetSession(123);
@@ -4481,6 +4247,12 @@ TEST_F(ApexdMountTest, OnBootstrapLoadBootstrapApexOnly) {
   AddPreInstalledApex("apex.apexd_test.apex");
   AddPreInstalledApex("apex.apexd_bootstrap_test.apex");
 
+  DeviceMapper& dm = DeviceMapper::Instance();
+  auto cleaner = make_scope_guard([&]() {
+    dm.DeleteDeviceIfExists("com.android.apex.test_package", 1s);
+    dm.DeleteDeviceIfExists("com.android.apex.bootstrap_test_package", 1s);
+  });
+
   ASSERT_EQ(0, OnBootstrap());
 
   // Check bootstrap apex was loaded
@@ -4732,10 +4504,6 @@ TEST_F(ApexdUnitTest, ProcessCompressedApexWrongSELinuxContext) {
 }
 
 TEST_F(ApexdMountTest, OnStartNoApexUpdated) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   AddPreInstalledApex("com.android.apex.compressed.v1.capex");
   std::string apex_path_1 = AddPreInstalledApex("apex.apexd_test.apex");
   std::string apex_path_2 =
@@ -4750,10 +4518,6 @@ TEST_F(ApexdMountTest, OnStartNoApexUpdated) {
 
   OnStart();
 
-  UnmountOnTearDown(apex_path_2);
-  UnmountOnTearDown(apex_path_3);
-  UnmountOnTearDown(apex_path_4);
-
   auto updated_apexes = GetChangedActiveApexesForTesting();
   ASSERT_EQ(updated_apexes.size(), 0u);
   // Quick check that all apexes were mounted
@@ -4762,16 +4526,11 @@ TEST_F(ApexdMountTest, OnStartNoApexUpdated) {
 }
 
 TEST_F(ApexdMountTest, OnStartDecompressingConsideredApexUpdate) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   AddPreInstalledApex("com.android.apex.compressed.v1.capex");
   std::string apex_path_1 = AddPreInstalledApex("apex.apexd_test.apex");
   std::string decompressed_active_apex = StringPrintf(
       "%s/com.android.apex.compressed@1%s", GetDecompressionDir().c_str(),
       kDecompressedApexPackageSuffix);
-  UnmountOnTearDown(decompressed_active_apex);
 
   ASSERT_THAT(ApexFileRepository::GetInstance().AddPreInstalledApex(
                   {{GetPartition(), GetBuiltInDir()}}),
@@ -4779,9 +4538,6 @@ TEST_F(ApexdMountTest, OnStartDecompressingConsideredApexUpdate) {
 
   OnStart();
 
-  UnmountOnTearDown(apex_path_1);
-  UnmountOnTearDown(decompressed_active_apex);
-
   auto updated_apexes = GetChangedActiveApexesForTesting();
   ASSERT_EQ(updated_apexes.size(), 1u);
   auto apex_file = ApexFile::Open(decompressed_active_apex);
@@ -4790,10 +4546,6 @@ TEST_F(ApexdMountTest, OnStartDecompressingConsideredApexUpdate) {
 }
 
 TEST_F(ApexdMountTest, ActivatesStagedSession) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   std::string preinstalled_apex = AddPreInstalledApex("apex.apexd_test.apex");
   auto apex_session = CreateStagedSession("apex.apexd_test_v2.apex", 37);
   apex_session->UpdateStateAndCommit(SessionState::STAGED);
@@ -4805,8 +4557,6 @@ TEST_F(ApexdMountTest, ActivatesStagedSession) {
   std::string active_apex =
       GetDataDir() + "/" + "com.android.apex.test_package@2.apex";
 
-  UnmountOnTearDown(preinstalled_apex);
-  UnmountOnTearDown(active_apex);
   OnStart();
 
   // Quick check that session was activated
@@ -4824,10 +4574,6 @@ TEST_F(ApexdMountTest, ActivatesStagedSession) {
 }
 
 TEST_F(ApexdMountTest, FailsToActivateStagedSession) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   std::string preinstalled_apex = AddPreInstalledApex("apex.apexd_test.apex");
   auto apex_session =
       CreateStagedSession("apex.apexd_test_manifest_mismatch.apex", 73);
@@ -4837,7 +4583,6 @@ TEST_F(ApexdMountTest, FailsToActivateStagedSession) {
                   {{GetPartition(), GetBuiltInDir()}}),
               Ok());
 
-  UnmountOnTearDown(preinstalled_apex);
   OnStart();
 
   // Quick check that session was activated
@@ -4856,10 +4601,6 @@ TEST_F(ApexdMountTest, FailsToActivateStagedSession) {
 }
 
 TEST_F(ApexdMountTest, FailsToActivateApexFallbacksToSystemOne) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   std::string preinstalled_apex = AddPreInstalledApex("apex.apexd_test.apex");
   AddDataApex("apex.apexd_test_manifest_mismatch.apex");
 
@@ -4867,7 +4608,6 @@ TEST_F(ApexdMountTest, FailsToActivateApexFallbacksToSystemOne) {
                   {{GetPartition(), GetBuiltInDir()}}),
               Ok());
 
-  UnmountOnTearDown(preinstalled_apex);
   OnStart();
 
   auto updated_apexes = GetChangedActiveApexesForTesting();
@@ -4888,12 +4628,10 @@ TEST_F(ApexdMountTest, SubmitSingleStagedSessionKeepsPreviousSessions) {
   ASSERT_RESULT_OK(ApexFileRepository::GetInstance().AddPreInstalledApex(
       {{GetPartition(), GetBuiltInDir()}}));
 
-  UnmountOnTearDown(preinstalled_apex);
-
   // First simulate existence of a bunch of sessions.
   auto session1 = GetSessionManager()->CreateSession(37);
   ASSERT_RESULT_OK(session1);
-  ASSERT_RESULT_OK(session1->UpdateStateAndCommit(SessionState::VERIFIED));
+  ASSERT_RESULT_OK(session1->UpdateStateAndCommit(SessionState::STAGED));
 
   auto session2 = GetSessionManager()->CreateSession(57);
   ASSERT_RESULT_OK(session2);
@@ -4914,7 +4652,7 @@ TEST_F(ApexdMountTest, SubmitSingleStagedSessionKeepsPreviousSessions) {
   ASSERT_EQ(4u, sessions.size());
 
   ASSERT_EQ(37, sessions[0].GetId());
-  ASSERT_EQ(SessionState::VERIFIED, sessions[0].GetState());
+  ASSERT_EQ(SessionState::STAGED, sessions[0].GetState());
 
   ASSERT_EQ(57, sessions[1].GetId());
   ASSERT_EQ(SessionState::STAGED, sessions[1].GetState());
@@ -4954,7 +4692,6 @@ TEST_F(ApexdMountTest, SendEventOnSubmitStagedSession) {
   ASSERT_RESULT_OK(ApexFileRepository::GetInstance().AddPreInstalledApex(
       {{ApexPartition::Vendor, GetBuiltInDir()}}));
 
-  UnmountOnTearDown(preinstalled_apex);
   OnStart();
   // checkvintf needs apex-info-list.xml to identify vendor APEXes.
   // OnAllPackagesActivated() generates it.
@@ -5124,10 +4861,6 @@ TEST_F(ApexdUnitTest, StagePackagesFailUnverifiedBrandNewApex) {
 }
 
 TEST_F(ApexdMountTest, ActivatesStagedSessionSucceedVerifiedBrandNewApex) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   ApexFileRepository::EnableBrandNewApex();
   auto& file_repository = ApexFileRepository::GetInstance();
   const auto partition = ApexPartition::System;
@@ -5144,7 +4877,6 @@ TEST_F(ApexdMountTest, ActivatesStagedSessionSucceedVerifiedBrandNewApex) {
   std::string active_apex =
       GetDataDir() + "/" + "com.android.apex.brand.new@1.apex";
 
-  UnmountOnTearDown(active_apex);
   OnStart();
 
   // Quick check that session was activated
@@ -5164,10 +4896,6 @@ TEST_F(ApexdMountTest, ActivatesStagedSessionSucceedVerifiedBrandNewApex) {
 }
 
 TEST_F(ApexdMountTest, ActivatesStagedSessionFailUnverifiedBrandNewApex) {
-  MockCheckpointInterface checkpoint_interface;
-  // Need to call InitializeVold before calling OnStart
-  InitializeVold(&checkpoint_interface);
-
   ApexFileRepository::EnableBrandNewApex();
   auto& file_repository = ApexFileRepository::GetInstance();
   const auto partition = ApexPartition::System;
@@ -5185,7 +4913,6 @@ TEST_F(ApexdMountTest, ActivatesStagedSessionFailUnverifiedBrandNewApex) {
   std::string active_apex =
       GetDataDir() + "/" + "com.android.apex.brand.new@1.apex";
 
-  UnmountOnTearDown(active_apex);
   OnStart();
 
   // Quick check that session was activated
@@ -5212,7 +4939,6 @@ TEST_F(ApexdMountTest, NonStagedUpdateFailVerifiedBrandNewApex) {
       {{partition, trusted_key_dir.path}});
   auto file_path = AddDataApex("com.android.apex.brand.new.apex");
   ASSERT_THAT(ActivatePackage(file_path), Ok());
-  UnmountOnTearDown(file_path);
 
   auto ret = InstallPackage(GetTestFile("com.android.apex.brand.new.apex"),
                             /* force= */ false);
@@ -5224,6 +4950,232 @@ TEST_F(ApexdMountTest, NonStagedUpdateFailVerifiedBrandNewApex) {
   file_repository.Reset();
 }
 
+class SubmitStagedSessionTest : public ApexdMountTest {
+ protected:
+  void SetUp() override {
+    ApexdMountTest::SetUp();
+
+    MockCheckpointInterface checkpoint_interface;
+    checkpoint_interface.SetSupportsCheckpoint(true);
+    InitializeVold(&checkpoint_interface);
+
+    // Has two preinstalled APEXes (for testing multi-APEX session)
+    AddPreInstalledApex("apex.apexd_test.apex");
+    AddPreInstalledApex("apex.apexd_test_different_app.apex");
+    ApexFileRepository::GetInstance().AddPreInstalledApex(
+        {{GetPartition(), GetBuiltInDir()}});
+
+    OnStart();
+  }
+
+  void TearDown() override {
+    // Should not leak temporary verity devices regardless of success.
+    // Why EXPECT? Needs to call TearDown() for unmounting even when something
+    // goes wrong with the test.
+    std::vector<DeviceMapper::DmBlockDevice> devices;
+    EXPECT_TRUE(DeviceMapper::Instance().GetAvailableDevices(&devices));
+    for (const auto& device : devices) {
+      EXPECT_THAT(device.name(), Not(EndsWith(".tmp")));
+    }
+
+    ApexdMountTest::TearDown();
+  }
+};
+
+TEST_F(SubmitStagedSessionTest, SimpleSuccess) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+}
+
+TEST_F(SubmitStagedSessionTest, SuccessStoresBuildFingerprint) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+
+  auto session = GetSessionManager()->GetSession(session_id);
+  ASSERT_NE(session->GetBuildFingerprint(), ""s);
+}
+
+TEST_F(SubmitStagedSessionTest,
+       RejectIfSamePackageIsAlreadyStaged_SameVersion) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+  ASSERT_THAT(MarkStagedSessionReady(session_id), Ok());
+
+  auto session_id2 = 43;
+  PrepareStagedSession("apex.apexd_test.apex", session_id2);
+  ASSERT_THAT(SubmitStagedSession(session_id2, {}, false, false, -1),
+              HasError(WithMessage(HasSubstr("already staged"))));
+}
+
+TEST_F(SubmitStagedSessionTest,
+       RejectIfSamePackageIsAlreadyStaged_DifferentVersion) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+  ASSERT_THAT(MarkStagedSessionReady(session_id), Ok());
+
+  auto session_id2 = 43;
+  PrepareStagedSession("apex.apexd_test_v2.apex", session_id2);
+  ASSERT_THAT(SubmitStagedSession(session_id2, {}, false, false, -1),
+              HasError(WithMessage(HasSubstr("already staged"))));
+}
+
+TEST_F(SubmitStagedSessionTest, RejectStagingIfAnotherSessionIsBeingStaged) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+
+  // MarkStagedSessionReady is not called yet.
+  auto session_id2 = 43;
+  PrepareStagedSession("apex.apexd_test_different_app.apex", session_id2);
+  ASSERT_THAT(SubmitStagedSession(session_id2, {}, false, false, -1),
+              HasError(WithMessage(HasSubstr("being staged"))));
+}
+
+TEST_F(SubmitStagedSessionTest, RejectInstallPackageForStagedPackage) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+  ASSERT_THAT(MarkStagedSessionReady(session_id), Ok());
+
+  ASSERT_THAT(
+      InstallPackage(GetTestFile("apex.apexd_test.apex"), /* force= */ true),
+      HasError(WithMessage(HasSubstr("already staged"))));
+}
+
+TEST_F(SubmitStagedSessionTest, RejectInstallIfAnotherSessionIsBeingStaged) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+
+  // MarkStagedSessionReady is not called yet.
+  ASSERT_THAT(InstallPackage(GetTestFile("apex.apexd_test_different_app.apex"),
+                             /* force= */ true),
+              HasError(WithMessage(HasSubstr("being staged"))));
+}
+
+TEST_F(SubmitStagedSessionTest, AbortedSessionDoesNotBlockNewStagingOrInstall) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+  ASSERT_THAT(AbortStagedSession(session_id), Ok());
+
+  auto session_id2 = 43;
+  PrepareStagedSession("apex.apexd_test.apex", session_id2);
+  ASSERT_THAT(SubmitStagedSession(session_id2, {}, false, false, -1), Ok());
+  ASSERT_THAT(AbortStagedSession(session_id2), Ok());
+
+  ASSERT_THAT(InstallPackage(GetTestFile("apex.apexd_test.apex"),
+                             /* force= */ true),
+              Ok());
+}
+
+TEST_F(SubmitStagedSessionTest, FailWithManifestMismatch) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test_manifest_mismatch.apex", session_id);
+
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1),
+              HasError(WithMessage(HasSubstr("does not match manifest"))));
+}
+
+TEST_F(SubmitStagedSessionTest, FailedSessionNotPersisted) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test_manifest_mismatch.apex", session_id);
+
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Not(Ok()));
+
+  auto session = GetSessionManager()->GetSession(session_id);
+  ASSERT_THAT(session, Not(Ok()));
+}
+
+TEST_F(SubmitStagedSessionTest, CannotBeRollbackAndHaveRollbackEnabled) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, /*has_rollback=*/true,
+                                  /*is_rollback*/ true, -1),
+              HasError(WithMessage(
+                  HasSubstr("both a rollback and enabled for rollback"))));
+}
+
+TEST_F(SubmitStagedSessionTest, FailWithCorruptApex) {
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test_corrupt_apex.apex", session_id);
+
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1),
+              HasError(WithMessage(HasSubstr("corrupted?"))));
+}
+
+TEST_F(SubmitStagedSessionTest, SuccessWithMultiSession) {
+  auto parent_session_id = 42;
+  auto child_session1_id = 43;
+  auto child_session2_id = 44;
+  auto file1 = PrepareStagedSession("apex.apexd_test.apex", child_session1_id);
+  auto file2 = PrepareStagedSession("apex.apexd_test_different_app.apex",
+                                    child_session2_id);
+
+  auto ret = SubmitStagedSession(parent_session_id,
+                                 {child_session1_id, child_session2_id}, false,
+                                 false, -1);
+  ASSERT_THAT(ret, HasValue(ElementsAre(Property(&ApexFile::GetPath, file1),
+                                        Property(&ApexFile::GetPath, file2))));
+
+  auto session = GetSessionManager()->GetSession(parent_session_id);
+  ASSERT_THAT(session->GetChildSessionIds(),
+              ElementsAre(child_session1_id, child_session2_id));
+}
+
+// Temporary test cases until the feature is fully enabled/implemented
+class MountBeforeDataTest : public ApexdMountTest {
+ protected:
+  void SetUp() override {
+    config_.mount_before_data = true;
+    ApexdMountTest::SetUp();
+
+    // preinstalled APEXes
+    AddPreInstalledApex("apex.apexd_test.apex");
+    AddPreInstalledApex("apex.apexd_test_different_app.apex");
+  }
+};
+
+TEST_F(MountBeforeDataTest, StagingCreatesBackingImages) {
+  ASSERT_EQ(0, OnBootstrap());
+
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+
+  auto session = GetSessionManager()->GetSession(session_id);
+  ASSERT_THAT(session->GetApexImages(),
+              Pointwise(Eq(), image_manager_->GetAllImages()));
+}
+
+TEST_F(MountBeforeDataTest, AbortSessionRemovesBackingImages) {
+  ASSERT_EQ(0, OnBootstrap());
+
+  auto session_id = 42;
+  PrepareStagedSession("apex.apexd_test.apex", session_id);
+  ASSERT_THAT(SubmitStagedSession(session_id, {}, false, false, -1), Ok());
+  ASSERT_THAT(AbortStagedSession(session_id), Ok());
+
+  ASSERT_THAT(image_manager_->GetAllImages(), IsEmpty());
+}
+
+TEST_F(MountBeforeDataTest, OnBootstrapActivatesAllApexes) {
+  ASSERT_EQ(0, OnBootstrap());
+
+  ASSERT_THAT(GetApexMounts(),
+              UnorderedElementsAre("/apex/com.android.apex.test_package_2"s,
+                                   "/apex/com.android.apex.test_package_2@1"s,
+                                   "/apex/com.android.apex.test_package"s,
+                                   "/apex/com.android.apex.test_package@1"s));
+}
+
 class LogTestToLogcat : public ::testing::EmptyTestEventListener {
   void OnTestStart(const ::testing::TestInfo& test_info) override {
 #ifdef __ANDROID__
diff --git a/apexd/apexd_test_utils.h b/apexd/apexd_test_utils.h
index 693af923..bd76dd52 100644
--- a/apexd/apexd_test_utils.h
+++ b/apexd/apexd_test_utils.h
@@ -14,16 +14,8 @@
  * limitations under the License.
  */
 
-#include <filesystem>
-#include <fstream>
-
-#include <gmock/gmock.h>
-#include <gtest/gtest.h>
-#include <linux/loop.h>
-#include <sched.h>
-#include <sys/mount.h>
-
 #include <android-base/errors.h>
+#include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/macros.h>
 #include <android-base/result.h>
@@ -34,15 +26,22 @@
 #include <android/apex/ApexSessionInfo.h>
 #include <binder/IServiceManager.h>
 #include <fstab/fstab.h>
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
 #include <libdm/dm.h>
+#include <linux/loop.h>
+#include <sched.h>
 #include <selinux/android.h>
+#include <sys/mount.h>
+
+#include <filesystem>
+#include <fstream>
 
 #include "apex_file.h"
 #include "apexd_loop.h"
 #include "apexd_utils.h"
-#include "session_state.pb.h"
-
 #include "com_android_apex.h"
+#include "session_state.pb.h"
 
 namespace android {
 namespace apex {
@@ -446,6 +445,12 @@ inline android::base::Result<struct loop_info64> GetLoopDeviceStatus(
   return loop_info;
 }
 
+inline std::string GetTestDataDir() { return base::GetExecutableDirectory(); }
+
+inline std::string GetTestFile(const std::string& name) {
+  return GetTestDataDir() + "/" + name;
+}
+
 }  // namespace apex
 }  // namespace android
 
diff --git a/apexd/apexd_testdata/Android.bp b/apexd/apexd_testdata/Android.bp
index caf65ec5..18e48be7 100644
--- a/apexd/apexd_testdata/Android.bp
+++ b/apexd/apexd_testdata/Android.bp
@@ -54,9 +54,21 @@ apex {
     prebuilts: ["sample_prebuilt_file"],
     key: "com.android.apex.test_package.key",
     installable: false,
+    payload_fs_type: "ext4", // many tests rely on this to be 'ext4'
     min_sdk_version: "29", // test requires hashtree to be present.
 }
 
+apex {
+    name: "apex.apexd_test_for_corruption",
+    manifest: "manifest.json",
+    file_contexts: ":apex.test-file_contexts",
+    // For corruption to be effective, the file should be big enough and random.
+    prebuilts: ["sample_big_prebuilt_file"],
+    key: "com.android.apex.test_package.key",
+    installable: false,
+    updatable: false,
+}
+
 apex {
     name: "apex.apexd_bootstrap_test",
     manifest: "manifest_bootstrap.json",
@@ -433,6 +445,15 @@ apex {
     updatable: false,
 }
 
+prebuilt_etc {
+    name: "sample_big_prebuilt_file",
+    // Generated by:
+    //   $ head -c 1M /dev/urandom > sample_big_prebuilt_file
+    // NOTE: avoid genrule for deterministc builds.
+    src: "sample_big_prebuilt_file",
+    installable: false,
+}
+
 apex {
     name: "test.rebootless_apex_v1",
     manifest: "manifest_rebootless.json",
@@ -440,6 +461,10 @@ apex {
     key: "com.android.apex.test_package.key",
     installable: false,
     updatable: false,
+    prebuilts: [
+        // Add a random file (1M) for corruption to be effective
+        "sample_big_prebuilt_file",
+    ],
     // TODO(ioffe): we should have a separate field to hashtree presence.
     min_sdk_version: "29", // test requires hashtree to be present.
 }
diff --git a/apexd/apexd_testdata/sample_big_prebuilt_file b/apexd/apexd_testdata/sample_big_prebuilt_file
new file mode 100644
index 00000000..97909541
Binary files /dev/null and b/apexd/apexd_testdata/sample_big_prebuilt_file differ
diff --git a/apexd/apexservice.cpp b/apexd/apexservice.cpp
index 89685471..b74796fe 100644
--- a/apexd/apexservice.cpp
+++ b/apexd/apexservice.cpp
@@ -73,6 +73,17 @@ BinderStatus CheckCallerSystemOrRoot(const std::string& name) {
   return BinderStatus::ok();
 }
 
+BinderStatus CheckCallerSystemKsOrRoot(const std::string& name) {
+  uid_t uid = IPCThreadState::self()->getCallingUid();
+  if (uid != AID_ROOT && uid != AID_SYSTEM && uid != AID_KEYSTORE) {
+    std::string msg =
+        "Only root, keystore, and system_server are allowed to call " + name;
+    return BinderStatus::fromExceptionCode(BinderStatus::EX_SECURITY,
+                                           String8(msg.c_str()));
+  }
+  return BinderStatus::ok();
+}
+
 class ApexService : public BnApexService {
  public:
   using BinderStatus = ::android::binder::Status;
@@ -92,8 +103,6 @@ class ApexService : public BnApexService {
   BinderStatus getStagedApexInfos(const ApexSessionParams& params,
                                   std::vector<ApexInfo>* aidl_return) override;
   BinderStatus getActivePackages(std::vector<ApexInfo>* aidl_return) override;
-  BinderStatus getActivePackage(const std::string& package_name,
-                                ApexInfo* aidl_return) override;
   BinderStatus getAllPackages(std::vector<ApexInfo>* aidl_return) override;
   BinderStatus abortStagedSession(int session_id) override;
   BinderStatus revertActiveSessions() override;
@@ -274,9 +283,8 @@ BinderStatus ApexService::calculateSizeForCompressedApex(
     compressed_apexes.emplace_back(apex_info.moduleName, apex_info.versionCode,
                                    apex_info.decompressedSize);
   }
-  const auto& instance = ApexFileRepository::GetInstance();
-  *required_size = ::android::apex::CalculateSizeForCompressedApex(
-      compressed_apexes, instance);
+  *required_size =
+      ::android::apex::CalculateSizeForCompressedApex(compressed_apexes);
   return BinderStatus::ok();
 }
 
@@ -484,7 +492,7 @@ BinderStatus ApexService::getActivePackages(
     std::vector<ApexInfo>* aidl_return) {
   LOG(INFO) << "getActivePackages received by ApexService";
 
-  auto check = CheckCallerSystemOrRoot("getActivePackages");
+  auto check = CheckCallerSystemKsOrRoot("getActivePackages");
   if (!check.isOk()) {
     return check;
   }
@@ -499,24 +507,6 @@ BinderStatus ApexService::getActivePackages(
   return BinderStatus::ok();
 }
 
-BinderStatus ApexService::getActivePackage(const std::string& package_name,
-                                           ApexInfo* aidl_return) {
-  LOG(INFO) << "getActivePackage received by ApexService package_name : "
-            << package_name;
-
-  auto check = CheckCallerSystemOrRoot("getActivePackage");
-  if (!check.isOk()) {
-    return check;
-  }
-
-  Result<ApexFile> apex = ::android::apex::GetActivePackage(package_name);
-  if (apex.ok()) {
-    *aidl_return = GetApexInfo(*apex);
-    aidl_return->isActive = true;
-  }
-  return BinderStatus::ok();
-}
-
 BinderStatus ApexService::getAllPackages(std::vector<ApexInfo>* aidl_return) {
   LOG(INFO) << "getAllPackages received by ApexService";
 
@@ -841,9 +831,6 @@ status_t ApexService::shellCommand(int in, int out, int err,
     }
     log << "ApexService:" << std::endl
         << "  help - display this help" << std::endl
-        << "  getActivePackage [package_name] - return info for active package "
-           "with given name, if present"
-        << std::endl
         << "  getAllPackages - return the list of all packages" << std::endl
         << "  getActivePackages - return the list of active packages"
         << std::endl
@@ -900,28 +887,6 @@ status_t ApexService::shellCommand(int in, int out, int err,
     return BAD_VALUE;
   }
 
-  if (cmd == String16("getActivePackage")) {
-    if (args.size() != 2) {
-      print_help(err, "Unrecognized options");
-      return BAD_VALUE;
-    }
-
-    ApexInfo package;
-    BinderStatus status = getActivePackage(String8(args[1]).c_str(), &package);
-    if (status.isOk()) {
-      std::string msg = ToString(package);
-      dprintf(out, "%s", msg.c_str());
-      return OK;
-    }
-
-    std::string msg = StringLog()
-                      << "Failed to fetch active package: "
-                      << String8(args[1]).c_str()
-                      << ", error: " << status.toString8().c_str() << std::endl;
-    dprintf(err, "%s", msg.c_str());
-    return BAD_VALUE;
-  }
-
   if (cmd == String16("getStagedSessionInfo")) {
     if (args.size() != 2) {
       print_help(err, "getStagedSessionInfo requires one session id");
diff --git a/apexd/apexservice_test.cpp b/apexd/apexservice_test.cpp
index 97eee063..8544044d 100644
--- a/apexd/apexservice_test.cpp
+++ b/apexd/apexservice_test.cpp
@@ -498,83 +498,6 @@ TEST_F(ApexServiceTest, DISABLED_EnforceSelinux) {
   EXPECT_TRUE(IsSelinuxEnforced() || kIsX86);
 }
 
-TEST_F(ApexServiceTest,
-       SubmitStagegSessionSuccessDoesNotLeakTempVerityDevices) {
-  PrepareTestApexForInstall installer(GetTestFile("apex.apexd_test.apex"),
-                                      "/data/app-staging/session_1543",
-                                      "staging_data_file");
-  if (!installer.Prepare()) {
-    return;
-  }
-
-  ApexInfoList list;
-  ApexSessionParams params;
-  params.sessionId = 1543;
-  ASSERT_TRUE(IsOk(service_->submitStagedSession(params, &list)));
-
-  std::vector<DeviceMapper::DmBlockDevice> devices;
-  DeviceMapper& dm = DeviceMapper::Instance();
-  ASSERT_TRUE(dm.GetAvailableDevices(&devices));
-
-  for (const auto& device : devices) {
-    ASSERT_THAT(device.name(), Not(EndsWith(".tmp")));
-  }
-}
-
-TEST_F(ApexServiceTest, SubmitStagedSessionStoresBuildFingerprint) {
-  PrepareTestApexForInstall installer(GetTestFile("apex.apexd_test.apex"),
-                                      "/data/app-staging/session_1547",
-                                      "staging_data_file");
-  if (!installer.Prepare()) {
-    return;
-  }
-  ApexInfoList list;
-  ApexSessionParams params;
-  params.sessionId = 1547;
-  ASSERT_TRUE(IsOk(service_->submitStagedSession(params, &list)));
-
-  auto session = GetSession(1547);
-  ASSERT_FALSE(session->GetBuildFingerprint().empty());
-}
-
-TEST_F(ApexServiceTest, SubmitStagedSessionFailDoesNotLeakTempVerityDevices) {
-  PrepareTestApexForInstall installer(
-      GetTestFile("apex.apexd_test_manifest_mismatch.apex"),
-      "/data/app-staging/session_239", "staging_data_file");
-  if (!installer.Prepare()) {
-    return;
-  }
-
-  ApexInfoList list;
-  ApexSessionParams params;
-  params.sessionId = 239;
-  ASSERT_FALSE(IsOk(service_->submitStagedSession(params, &list)));
-
-  std::vector<DeviceMapper::DmBlockDevice> devices;
-  DeviceMapper& dm = DeviceMapper::Instance();
-  ASSERT_TRUE(dm.GetAvailableDevices(&devices));
-
-  for (const auto& device : devices) {
-    ASSERT_THAT(device.name(), Not(EndsWith(".tmp")));
-  }
-}
-
-TEST_F(ApexServiceTest, CannotBeRollbackAndHaveRollbackEnabled) {
-  PrepareTestApexForInstall installer(GetTestFile("apex.apexd_test.apex"),
-                                      "/data/app-staging/session_1543",
-                                      "staging_data_file");
-  if (!installer.Prepare()) {
-    return;
-  }
-
-  ApexInfoList list;
-  ApexSessionParams params;
-  params.sessionId = 1543;
-  params.isRollback = true;
-  params.hasRollbackEnabled = true;
-  ASSERT_FALSE(IsOk(service_->submitStagedSession(params, &list)));
-}
-
 TEST_F(ApexServiceTest, SessionParamDefaults) {
   PrepareTestApexForInstall installer(GetTestFile("apex.apexd_test.apex"),
                                       "/data/app-staging/session_1547",
@@ -880,28 +803,6 @@ TEST_F(ApexServiceTest, SubmitSingleSessionTestSuccess) {
   ASSERT_THAT(sessions, UnorderedElementsAre(SessionInfoEq(expected)));
 }
 
-TEST_F(ApexServiceTest, SubmitSingleSessionTestFail) {
-  PrepareTestApexForInstall installer(
-      GetTestFile("apex.apexd_test_corrupt_apex.apex"),
-      "/data/app-staging/session_456", "staging_data_file");
-  if (!installer.Prepare()) {
-    FAIL() << GetDebugStr(&installer);
-  }
-
-  ApexInfoList list;
-  ApexSessionParams params;
-  params.sessionId = 456;
-  ASSERT_FALSE(IsOk(service_->submitStagedSession(params, &list)))
-      << GetDebugStr(&installer);
-
-  ApexSessionInfo session;
-  ASSERT_TRUE(IsOk(service_->getStagedSessionInfo(456, &session)))
-      << GetDebugStr(&installer);
-  ApexSessionInfo expected = CreateSessionInfo(-1);
-  expected.isUnknown = true;
-  EXPECT_THAT(session, SessionInfoEq(expected));
-}
-
 TEST_F(ApexServiceTest, SubmitMultiSessionTestSuccess) {
   // Parent session id: 10
   // Children session ids: 20 30
diff --git a/apexd/sysprop/ApexProperties.sysprop b/apexd/sysprop/ApexProperties.sysprop
index 7e204023..88a7277e 100644
--- a/apexd/sysprop/ApexProperties.sysprop
+++ b/apexd/sysprop/ApexProperties.sysprop
@@ -66,3 +66,15 @@ prop {
     access: Readonly
     prop_name: "apexd.config.loopback.readahead"
 }
+
+# This sysprop allows adjusting the number of threads that are used
+# to open APEX files during bootstrap. If this sysprop is not set or set to 0,
+# the total number of threads equal the number of pre-installed packages.
+# The maximum number of threads is capped to the number of pre-installed packages.
+prop {
+    api_name: "apex_file_open_threads"
+    type: UInt
+    scope: Internal
+    access: Readonly
+    prop_name: "apexd.config.apex_file_open.threads"
+}
diff --git a/apexer/Android.bp b/apexer/Android.bp
index d41a53bb..030dd86e 100644
--- a/apexer/Android.bp
+++ b/apexer/Android.bp
@@ -27,7 +27,7 @@ apexer_tools = [
     "zipalign",
     "make_f2fs",
     "sload_f2fs",
-    "make_erofs",
+    "mkfs.erofs",
     // TODO(b/124476339) apex doesn't follow 'required' dependencies so we need to include this
     // manually for 'avbtool'.
     "fec",
@@ -67,11 +67,6 @@ python_binary_host {
     data: [
         ":mke2fs_conf_for_apexer",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "apex_manifest",
         "apex_build_info_proto",
@@ -85,11 +80,6 @@ python_binary_host {
     srcs: [
         "conv_apex_manifest.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "apex_manifest_proto",
     ],
@@ -121,11 +111,6 @@ python_test_host {
     libs: [
         "apex_manifest",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 apexer_deps_minus_go_tools = apexer_tools + [
@@ -177,7 +162,7 @@ genrule {
         "cp $(location avbtool) $$BIN && " +
         "cp $(location aapt2) $$BIN && " +
         "cp $(location e2fsdroid) $$BIN && " +
-        "cp $(location make_erofs) $$BIN && " +
+        "cp $(location mkfs.erofs) $$BIN && " +
         "cp $(location merge_zips) $$BIN && " +
         "cp $(location mke2fs) $$BIN && " +
         "cp $(location resize2fs) $$BIN && " +
diff --git a/apexer/apexer.py b/apexer/apexer.py
index d57fafdf..184cbb7d 100644
--- a/apexer/apexer.py
+++ b/apexer/apexer.py
@@ -617,7 +617,7 @@ def CreateImageErofs(args, work_dir, manifests_dir, img_file):
   cmd.append(tmp_input_dir)
   RunCommand(cmd, args.verbose)
 
-  cmd = ['make_erofs']
+  cmd = ['mkfs.erofs']
   cmd.extend(['-z', 'lz4hc'])
   cmd.extend(['--fs-config-file', args.canned_fs_config])
   cmd.extend(['--file-contexts', args.file_contexts])
diff --git a/apexer/apexer_test.py b/apexer/apexer_test.py
index 18b003fa..8eaf8758 100644
--- a/apexer/apexer_test.py
+++ b/apexer/apexer_test.py
@@ -181,7 +181,7 @@ class ApexerRebuildTest(unittest.TestCase):
         files = {}
         for i in ["apexer", "deapexer", "avbtool", "mke2fs", "sefcontext_compile", "e2fsdroid",
                   "resize2fs", "soong_zip", "aapt2", "merge_zips", "zipalign", "debugfs_static",
-                  "signapk.jar", "android.jar", "make_erofs", "fsck.erofs", "conv_apex_manifest"]:
+                  "signapk.jar", "android.jar", "mkfs.erofs", "fsck.erofs", "conv_apex_manifest"]:
             file_path = os.path.join(dir_name, "bin", i)
             if os.path.exists(file_path):
                 os.chmod(file_path, stat.S_IRUSR | stat.S_IXUSR)
diff --git a/libs/libapexsupport/apexsupport.cpp b/libs/libapexsupport/apexsupport.cpp
index 307cd829..2a01422b 100644
--- a/libs/libapexsupport/apexsupport.cpp
+++ b/libs/libapexsupport/apexsupport.cpp
@@ -19,6 +19,7 @@
 
 #include <dlfcn.h>
 
+#include <algorithm>
 #include <string>
 
 #include <android/dlext.h>
diff --git a/libs/libapexutil/Android.bp b/libs/libapexutil/Android.bp
index db0ec88c..a37a5a7c 100644
--- a/libs/libapexutil/Android.bp
+++ b/libs/libapexutil/Android.bp
@@ -40,7 +40,10 @@ cc_library_static {
         "//apex_available:platform",
         "com.android.runtime",
     ],
-    visibility: ["//system/linkerconfig"],
+    visibility: [
+        "//system/linkerconfig",
+        "//packages/modules/Virtualization/guest/microdroid_launcher",
+    ],
 }
 
 cc_test {
diff --git a/proto/Android.bp b/proto/Android.bp
index bb505ee2..74b59767 100644
--- a/proto/Android.bp
+++ b/proto/Android.bp
@@ -60,6 +60,16 @@ python_library_host {
     },
 }
 
+python_library_host {
+    name: "apex_blocklist_proto",
+    srcs: [
+        "apex_blocklist.proto",
+    ],
+    proto: {
+        canonical_path_from_root: false,
+    },
+}
+
 python_library_host {
     name: "apex_build_info_proto",
     srcs: [
diff --git a/proto/session_state.proto b/proto/session_state.proto
index ad49ef40..d5b3f45b 100644
--- a/proto/session_state.proto
+++ b/proto/session_state.proto
@@ -64,4 +64,7 @@ message SessionState {
 
   // The list of sha256 hashes of apexes within this session.
   repeated string apex_file_hashes = 11;
+
+  // The name list of apex images within this session.
+  repeated string apex_images = 12;
 }
diff --git a/shim/Android.bp b/shim/Android.bp
index 7ec17b56..b35f1d31 100644
--- a/shim/Android.bp
+++ b/shim/Android.bp
@@ -41,6 +41,12 @@ prebuilt_apex {
     },
     filename: "com.android.apex.cts.shim.apex",
     installable: true,
+    // Declare the apps included in the prebuilt apex so that they can be
+    // signed using apkcerts.txt
+    apps: [
+        "CtsShim",
+        "CtsShimPriv",
+    ],
 }
 
 prebuilt_apex {
@@ -64,6 +70,12 @@ prebuilt_apex {
     },
     filename: "com.android.apex.cts.shim.v2.apex",
     installable: false,
+    // Declare the apps included in the prebuilt apex so that they can be
+    // signed using apkcerts.txt
+    apps: [
+        "CtsShim",
+        "CtsShimPriv",
+    ],
 }
 
 prebuilt_apex {
@@ -202,6 +214,12 @@ prebuilt_apex {
     },
     filename: "com.android.apex.cts.shim.v3.apex",
     installable: false,
+    // Declare the apps included in the prebuilt apex so that they can be
+    // signed using apkcerts.txt
+    apps: [
+        "CtsShim",
+        "CtsShimPriv",
+    ],
 }
 
 prebuilt_apex {
diff --git a/tests/OWNERS b/tests/OWNERS
index 71f225ae..880c9457 100644
--- a/tests/OWNERS
+++ b/tests/OWNERS
@@ -2,4 +2,3 @@
 chenzhu@google.com
 jiyong@google.com
 robertogil@google.com
-yuwu@google.com
diff --git a/tests/src/com/android/tests/apex/ApexdHostTest.java b/tests/src/com/android/tests/apex/ApexdHostTest.java
index f4121469..264ebbac 100644
--- a/tests/src/com/android/tests/apex/ApexdHostTest.java
+++ b/tests/src/com/android/tests/apex/ApexdHostTest.java
@@ -258,34 +258,6 @@ public class ApexdHostTest extends BaseHostJUnit4Test  {
         assertThat(updatedState).isEqualTo(initialState);
     }
 
-    /**
-     * Verifies that content of {@code /data/apex/sessions/} is migrated to the {@code
-     * /metadata/apex/sessions}.
-     */
-    @Test
-    public void testSessionsDirMigrationToMetadata() throws Exception {
-        assumeTrue("Device does not support updating APEX", mHostUtils.isApexUpdateSupported());
-        assumeTrue("Device requires root", getDevice().isAdbRoot());
-
-        try {
-            getDevice().executeShellV2Command("mkdir -p /data/apex/sessions/1543");
-            File file = File.createTempFile("foo", "bar");
-            getDevice().pushFile(file, "/data/apex/sessions/1543/file");
-
-            // During boot sequence apexd will move /data/apex/sessions/1543/file to
-            // /metadata/apex/sessions/1543/file.
-            getDevice().reboot();
-            assertWithMessage("Timed out waiting for device to boot").that(
-                    getDevice().waitForBootComplete(Duration.ofMinutes(2).toMillis())).isTrue();
-
-            assertThat(getDevice().doesFileExist("/metadata/apex/sessions/1543/file")).isTrue();
-            assertThat(getDevice().doesFileExist("/data/apex/sessions/1543/file")).isFalse();
-        } finally {
-            getDevice().executeShellV2Command("rm -R /data/apex/sessions/1543");
-            getDevice().executeShellV2Command("rm -R /metadata/apex/sessions/1543");
-        }
-    }
-
     @Test
     public void testFailsToActivateApexOnDataFallbacksToPreInstalled() throws Exception {
         assumeTrue("Device does not support updating APEX", mHostUtils.isApexUpdateSupported());
diff --git a/tests/testdata/sharedlibs/build/Android.bp b/tests/testdata/sharedlibs/build/Android.bp
index f8fa184a..41601cbb 100644
--- a/tests/testdata/sharedlibs/build/Android.bp
+++ b/tests/testdata/sharedlibs/build/Android.bp
@@ -44,11 +44,6 @@ python_binary_host {
     srcs: [
         "shared_libs_repack.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "apex_build_info_proto",
         "apex_manifest_proto",
diff --git a/tests/vts/VtsApexTest.cpp b/tests/vts/VtsApexTest.cpp
index 86566533..49114d78 100644
--- a/tests/vts/VtsApexTest.cpp
+++ b/tests/vts/VtsApexTest.cpp
@@ -17,6 +17,7 @@
 #define LOG_TAG "VtsApexTest"
 
 #include <android-base/file.h>
+#include <android-base/properties.h>
 #include <fcntl.h>
 #include <gtest/gtest.h>
 
@@ -24,6 +25,7 @@
 
 #include "apex_constants.h"
 
+using android::base::GetIntProperty;
 using android::base::unique_fd;
 
 namespace android::apex {
@@ -31,7 +33,7 @@ namespace android::apex {
 static void ForEachPreinstalledApex(auto fn) {
   namespace fs = std::filesystem;
   std::error_code ec;
-  for (const auto &dir : kApexPackageBuiltinDirs) {
+  for (const auto& [partition, dir] : kBuiltinApexPackageDirs) {
     if (!fs::exists(dir, ec)) {
       if (ec) {
         FAIL() << "Can't to access " << dir << ": " << ec.message();
@@ -45,7 +47,7 @@ static void ForEachPreinstalledApex(auto fn) {
       if (path.extension() != kApexPackageSuffix) {
         continue;
       }
-      fn(path);
+      fn(partition, path);
     }
     if (ec) {
       FAIL() << "Can't read " << dir << ": " << ec.message();
@@ -55,10 +57,36 @@ static void ForEachPreinstalledApex(auto fn) {
 
 // Preinstalled APEX files (.apex) should be okay when opening with O_DIRECT
 TEST(VtsApexTest, OpenPreinstalledApex) {
-  ForEachPreinstalledApex([](auto path) {
+  // The requirement was added in Android V (for system) and 202404 (for
+  // vendor).
+  bool skip_system = android_get_device_api_level() < 35;
+  bool skip_vendor = GetIntProperty("ro.board.api_level", 0) < 202404;
+
+  ForEachPreinstalledApex([=](auto partition, auto path) {
+    switch (partition) {
+      case ApexPartition::System:
+        [[fallthrough]];
+      case ApexPartition::SystemExt:
+        [[fallthrough]];
+      case ApexPartition::Product: {
+        if (skip_system) {
+          return;
+        }
+        break;
+      }
+      case ApexPartition::Vendor:
+        [[fallthrough]];
+      case ApexPartition::Odm: {
+        if (skip_vendor) {
+          return;
+        }
+        break;
+      }
+    }
+
     unique_fd fd(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECT));
-    ASSERT_NE(fd.get(), -1)
-        << "Can't open an APEX file " << path << ": " << strerror(errno);
+    ASSERT_NE(fd.get(), -1) << "Can't open an APEX file " << path
+                            << " with O_DIRECT: " << strerror(errno);
   });
 }
 
diff --git a/tools/Android.bp b/tools/Android.bp
index 6975698c..813307af 100644
--- a/tools/Android.bp
+++ b/tools/Android.bp
@@ -21,11 +21,6 @@ python_binary_host {
     srcs: [
         "deapexer.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "apex_manifest",
     ],
@@ -41,11 +36,6 @@ python_binary_host {
     srcs: [
         "apex_elf_checker.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     required: [
         "blkid_static",
         "debugfs_static",
@@ -58,11 +48,6 @@ python_binary_host {
     srcs: [
         "apex_compression_tool.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "apex_manifest_proto",
     ],
@@ -96,11 +81,6 @@ python_test_host {
     test_options: {
         unit_test: true,
     },
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 cc_binary_host {
@@ -110,9 +90,6 @@ cc_binary_host {
         "init_host_defaults",
         "libapex-deps",
     ],
-    shared_libs: [
-        "libprocessgroup",
-    ],
     static_libs: [
         "libapex",
         "libinit_host",
@@ -140,7 +117,6 @@ sh_test_host {
         "libcutils",
         "liblog",
         "libpcre2", // used by libselinux
-        "libprocessgroup",
         "libprotobuf-cpp-full", // used by libapex
         "libprotobuf-cpp-lite", // used by libinit_host
         "libselinux", // used by libapex
@@ -159,11 +135,6 @@ python_binary_host {
     srcs: [
         "apexer_with_DCLA_preprocessing.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "apexer_wrapper_utils",
     ],
@@ -190,11 +161,6 @@ python_test_host {
     test_options: {
         unit_test: true,
     },
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
 python_binary_host {
@@ -202,11 +168,6 @@ python_binary_host {
     srcs: [
         "apexer_with_trim_preprocessing.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "apex_manifest_proto",
         "apexer_wrapper_utils",
@@ -216,17 +177,25 @@ python_binary_host {
 python_binary_host {
     name: "apexd_host",
     srcs: ["apexd_host.py"],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "apex_manifest",
     ],
     required: [
         "deapexer",
-        "debugfs_static",
+        "debugfs",
         "fsck.erofs",
     ],
 }
+
+python_binary_host {
+    name: "brand_new_apex_verifier",
+    srcs: ["brand_new_apex_verifier.py"],
+    version: {
+        py3: {
+            embedded_launcher: true,
+        },
+    },
+    libs: [
+        "apex_blocklist_proto",
+    ],
+}
diff --git a/tools/apex-ls/Android.bp b/tools/apex-ls/Android.bp
new file mode 100644
index 00000000..d80ffd17
--- /dev/null
+++ b/tools/apex-ls/Android.bp
@@ -0,0 +1,56 @@
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
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_binary_host {
+    name: "apex-ls",
+    defaults: [
+        "libapex-deps",
+        // we need this to get the feature flags
+        // used to build liberofs.
+        "erofs-utils_export_defaults",
+    ],
+    srcs: [
+        "erofs.cpp",
+        "ext4.cpp",
+        "main.cpp",
+    ],
+    static_libs: [
+        "libapex",
+        "libbase",
+        "libcrypto",
+        "libcutils",
+        "liberofs",
+        "liblz4",
+        "libprotobuf-cpp-full",
+        "libselinux",
+        "libz",
+        "libziparchive",
+
+        // ext4
+        "libext2_misc",
+        "libext2fs",
+        "libext2_blkid",
+        "libext2_uuid",
+        "libext2_ss",
+        "libext2_quota",
+        "libext2_com_err",
+        "libext2_e2p",
+        "libext2_support",
+    ],
+    static_executable: true,
+}
diff --git a/tools/apex-ls/erofs.cpp b/tools/apex-ls/erofs.cpp
new file mode 100644
index 00000000..9758461b
--- /dev/null
+++ b/tools/apex-ls/erofs.cpp
@@ -0,0 +1,126 @@
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
+#include "erofs.h"
+
+#include <android-base/result.h>
+#include <android-base/scopeguard.h>
+// ignore unused-parameter in headers
+#pragma GCC diagnostic push
+#pragma GCC diagnostic ignored "-Wunused-parameter"
+#include <erofs/config.h>
+#include <erofs/dir.h>
+#include <erofs/inode.h>
+#pragma GCC diagnostic pop
+
+#include <filesystem>
+#include <functional>
+#include <string>
+#include <vector>
+
+using android::base::Error;
+using android::base::make_scope_guard;
+using android::base::Result;
+namespace fs = std::filesystem;
+using namespace std::placeholders;
+
+namespace {
+
+struct ReadDirContext {
+  struct erofs_dir_context ctx;
+  std::vector<std::string> names;
+};
+
+int ReadDirIter(struct erofs_dir_context* ctx) {
+  std::string name{ctx->dname, ctx->dname + ctx->de_namelen};
+  ((ReadDirContext*)ctx)->names.push_back(name);
+  return 0;
+}
+
+Result<std::vector<std::string>> ReadDir(struct erofs_sb_info* sbi,
+                                         const fs::path& path) {
+  struct erofs_inode dir = {.sbi = sbi};
+  auto err = erofs_ilookup(path.string().c_str(), &dir);
+  if (err) {
+    return Error(err) << "failed to read inode for " << path;
+  }
+  if (!S_ISDIR(dir.i_mode)) {
+    return Error() << "failed to read dir: " << path << " is not a directory";
+  }
+  ReadDirContext ctx = {
+      {
+          .dir = &dir,
+          .cb = ReadDirIter,
+          .flags = EROFS_READDIR_VALID_PNID,
+      },
+  };
+  err = erofs_iterate_dir(&ctx.ctx, false);
+  if (err) {
+    return Error(err) << "failed to read dir";
+  }
+  return ctx.names;
+}
+
+Result<Entry> ReadEntry(struct erofs_sb_info* sbi, const fs::path& path) {
+  struct erofs_inode inode = {.sbi = sbi};
+  auto err = erofs_ilookup(path.string().c_str(), &inode);
+  if (err) {
+    return Error(err) << "failed to read inode for " << path;
+  }
+
+  mode_t mode = inode.i_mode;
+
+  std::string entry_path = path.string();
+  // make sure dir path ends with '/'
+  if (S_ISDIR(mode)) {
+    entry_path += '/';
+  }
+
+  // read security context
+  char security_context[256];
+  err = erofs_getxattr(&inode, "security.selinux", security_context,
+                       sizeof(security_context));
+  if (err < 0) {
+    return Error() << "failed to get security context of " << path << ": "
+                   << erofs_strerror(err);
+  }
+
+  return Entry{mode, entry_path, security_context};
+}
+
+}  // namespace
+
+Result<std::vector<Entry>> ErofsList(const std::string& image_path) {
+  erofs_init_configure();
+  auto configure = make_scope_guard(&erofs_exit_configure);
+
+  // open image
+  struct erofs_sb_info sbi;
+  auto err = erofs_dev_open(&sbi, image_path.c_str(), O_RDONLY | O_TRUNC);
+  if (err) {
+    return Error(err) << "failed to open image file";
+  }
+  auto dev = make_scope_guard([&] { erofs_dev_close(&sbi); });
+
+  // read superblock
+  err = erofs_read_superblock(&sbi);
+  if (err) {
+    return Error(err) << "failed to read superblock";
+  }
+  auto superblock = make_scope_guard([&] { erofs_put_super(&sbi); });
+
+  return List(std::bind(&ReadEntry, &sbi, _1), std::bind(&ReadDir, &sbi, _1));
+}
\ No newline at end of file
diff --git a/tools/apex-ls/erofs.h b/tools/apex-ls/erofs.h
new file mode 100644
index 00000000..183cfb7b
--- /dev/null
+++ b/tools/apex-ls/erofs.h
@@ -0,0 +1,24 @@
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
+#pragma once
+
+#include <android-base/result.h>
+
+#include "list.h"
+
+android::base::Result<std::vector<Entry>> ErofsList(
+    const std::string& image_file);
diff --git a/tools/apex-ls/ext4.cpp b/tools/apex-ls/ext4.cpp
new file mode 100644
index 00000000..08aea1a5
--- /dev/null
+++ b/tools/apex-ls/ext4.cpp
@@ -0,0 +1,160 @@
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
+#include "ext4.h"
+
+#include <android-base/result.h>
+#include <android-base/scopeguard.h>
+extern "C" {
+#include <et/com_err.h>
+#include <ext2fs/ext2_io.h>
+#include <ext2fs/ext2fs.h>
+}
+#include <sys/stat.h>
+
+#include <filesystem>
+#include <functional>
+#include <string>
+#include <vector>
+
+using android::base::Error;
+using android::base::make_scope_guard;
+using android::base::Result;
+namespace fs = std::filesystem;
+using namespace std::placeholders;
+
+namespace {
+
+Result<ext2_ino_t> PathToIno(ext2_filsys fs, const fs::path& path) {
+  ext2_ino_t ino;
+  auto err = ext2fs_namei(fs, EXT2_ROOT_INO, EXT2_ROOT_INO,
+                          path.string().c_str(), &ino);
+  if (err) {
+    return Error() << "failed to resolve path" << path << ": "
+                   << error_message(err);
+  }
+  return ino;
+}
+
+Result<std::string> GetXattr(ext2_filsys fs, ext2_ino_t ino,
+                             const std::string& key) {
+  struct ext2_xattr_handle* h;
+
+  auto err = ext2fs_xattrs_open(fs, ino, &h);
+  if (err) {
+    return Error() << "failed to open xattr: " << error_message(err);
+  }
+  auto close = make_scope_guard([&] { ext2fs_xattrs_close(&h); });
+
+  err = ext2fs_xattrs_read(h);
+  if (err) {
+    return Error() << "failed to read xattr: " << error_message(err);
+  }
+
+  char* buf = nullptr;
+  size_t buflen;
+  err = ext2fs_xattr_get(h, key.c_str(), (void**)&buf, &buflen);
+  if (err) {
+    return Error() << "failed to get xattr " << key << ": "
+                   << error_message(err);
+  }
+  std::string value = buf;
+  ext2fs_free_mem(&buf);
+
+  return value;
+}
+
+struct ReadDirContext {
+  fs::path dir;
+  std::vector<std::string> names;
+};
+
+int ReadDirIter(ext2_ino_t dir, int entry, struct ext2_dir_entry* dirent,
+                int offset, int blocksize, char* buf, void* priv_data) {
+  (void)dir;
+  (void)entry;
+  (void)offset;
+  (void)blocksize;
+  (void)buf;
+
+  ReadDirContext* ctx = (ReadDirContext*)priv_data;
+
+  auto len = ext2fs_dirent_name_len(dirent);
+  std::string name(dirent->name, dirent->name + len);
+  // ignore ./lost+found
+  if (ctx->dir == "." && name == "lost+found") {
+    return 0;
+  }
+  ctx->names.push_back(name);
+  return 0;
+}
+
+Result<std::vector<std::string>> ReadDir(ext2_filsys fs, const fs::path& path) {
+  ext2_ino_t ino = OR_RETURN(PathToIno(fs, path));
+
+  ReadDirContext ctx = {.dir = path};
+  auto err = ext2fs_dir_iterate2(fs, ino, /*flag*/ 0,
+                                 /*block_buf*/ nullptr, &ReadDirIter,
+                                 /*priv_data*/ &ctx);
+  if (err) {
+    return Error() << "failed to read dir " << path << ": "
+                   << error_message(err);
+  }
+  return ctx.names;
+}
+
+Result<Entry> ReadEntry(ext2_filsys fs, const fs::path& path) {
+  ext2_ino_t ino = OR_RETURN(PathToIno(fs, path));
+
+  struct ext2_inode inode;
+  auto err = ext2fs_read_inode(fs, ino, &inode);
+  if (err) {
+    return Error() << "failed to read inode for " << path << ": "
+                   << error_message(err);
+  }
+
+  mode_t mode = inode.i_mode;
+
+  std::string entry_path = path.string();
+  // make sure dir path ends with '/'
+  if (S_ISDIR(mode)) {
+    entry_path += '/';
+  }
+
+  // read security context
+  auto security_context = OR_RETURN(GetXattr(fs, ino, "security.selinux"));
+
+  return Entry{mode, entry_path, security_context};
+}
+
+}  // namespace
+
+Result<std::vector<Entry>> Ext4List(const std::string& image_path) {
+  // open image
+  ext2_filsys fs;
+  io_manager io_ptr = unix_io_manager;
+  auto err = ext2fs_open(
+      image_path.c_str(),
+      EXT2_FLAG_SOFTSUPP_FEATURES | EXT2_FLAG_64BITS | EXT2_FLAG_THREADS,
+      /* superblock */ 0, /* blocksize */ 0, io_ptr, &fs);
+  if (err) {
+    return Error() << "failed to open " << image_path << ": "
+                   << error_message(err);
+  }
+  auto close = make_scope_guard([&] { ext2fs_close_free(&fs); });
+
+  return List(std::bind(&ReadEntry, fs, _1), std::bind(&ReadDir, fs, _1));
+}
\ No newline at end of file
diff --git a/tools/apex-ls/ext4.h b/tools/apex-ls/ext4.h
new file mode 100644
index 00000000..b6834651
--- /dev/null
+++ b/tools/apex-ls/ext4.h
@@ -0,0 +1,24 @@
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
+#pragma once
+
+#include <android-base/result.h>
+
+#include "list.h"
+
+android::base::Result<std::vector<Entry>> Ext4List(
+    const std::string& image_file);
diff --git a/tools/apex-ls/list.h b/tools/apex-ls/list.h
new file mode 100644
index 00000000..ac8b4493
--- /dev/null
+++ b/tools/apex-ls/list.h
@@ -0,0 +1,70 @@
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
+#pragma once
+
+#include <android-base/result.h>
+#include <fcntl.h>
+#include <sys/stat.h>
+
+#include <functional>
+#include <string>
+#include <vector>
+
+struct Entry {
+  // file mode
+  mode_t mode;
+
+  // path to this entry.
+  // - each entry should start with './'
+  // - directory entry should end with '/'
+  std::string path;
+
+  std::string security_context;
+};
+
+// Generic lister
+template <typename ReadEntry, typename ReadDir>
+android::base::Result<std::vector<Entry>> List(ReadEntry read_entry,
+                                               ReadDir read_dir) {
+  namespace fs = std::filesystem;
+  using namespace android::base;
+
+  std::vector<Entry> entries;
+
+  // Recursive visitor
+  std::function<Result<void>(const fs::path& path)> visit =
+      [&](const fs::path& path) -> Result<void> {
+    auto entry = OR_RETURN(read_entry(path));
+    entries.push_back(entry);
+
+    if (S_ISDIR(entry.mode)) {
+      auto names = OR_RETURN(read_dir(path));
+      std::ranges::sort(names);
+      for (auto name : names) {
+        // Skip . and ..
+        if (name == "." || name == "..") continue;
+        OR_RETURN(visit(path / name));
+      }
+    }
+    return {};
+  };
+
+  // Visit each path entry recursively starting from root
+  OR_RETURN(visit("."));
+
+  return entries;
+}
\ No newline at end of file
diff --git a/tools/apex-ls/main.cpp b/tools/apex-ls/main.cpp
new file mode 100644
index 00000000..291486a3
--- /dev/null
+++ b/tools/apex-ls/main.cpp
@@ -0,0 +1,127 @@
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
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/result.h>
+#include <android-base/unique_fd.h>
+#include <apex_file.h>
+#include <fcntl.h>
+#include <sys/sendfile.h>
+
+#include <iostream>
+#include <map>
+#include <string>
+#include <vector>
+
+#include "erofs.h"
+#include "ext4.h"
+#include "list.h"
+
+using android::apex::ApexFile;
+using android::base::ErrnoError;
+using android::base::Error;
+using android::base::Result;
+using android::base::unique_fd;
+
+using namespace std::string_literals;
+
+struct Args {
+  std::string apex_file;
+  bool show_security_context;
+};
+
+Result<void> PrintList(Args args) {
+  auto apex_file = OR_RETURN(ApexFile::Open(args.apex_file));
+
+  // If the apex is .capex, decompress it first.
+  TemporaryDir temp_dir;
+  if (apex_file.IsCompressed()) {
+    auto original_apex_path = std::string(temp_dir.path) + "/original.apex";
+    OR_RETURN(apex_file.Decompress(original_apex_path));
+    apex_file = OR_RETURN(ApexFile::Open(original_apex_path));
+  }
+
+  if (!apex_file.GetFsType().has_value())
+    return Error() << "Invalid apex: no fs type";
+  if (!apex_file.GetImageSize().has_value())
+    return Error() << "Invalid apex: no image size";
+  if (!apex_file.GetImageOffset().has_value())
+    return Error() << "Invalid apex: no image offset";
+
+  std::map lister = {
+      std::pair{"ext4"s, &Ext4List},
+      std::pair{"erofs"s, &ErofsList},
+  };
+  auto fs_type = *apex_file.GetFsType();
+  if (!lister.contains(fs_type)) {
+    return Error() << "Invalid filesystem type: " << fs_type;
+  }
+
+  // Extract apex_payload.img
+  TemporaryFile temp_file;
+  {
+    unique_fd src(open(apex_file.GetPath().c_str(), O_RDONLY | O_CLOEXEC));
+    off_t offset = *apex_file.GetImageOffset();
+    size_t size = *apex_file.GetImageSize();
+    if (sendfile(temp_file.fd, src, &offset, size) < 0) {
+      return ErrnoError()
+             << "Failed to create a temporary file for apex payload";
+    }
+  }
+
+  for (const auto& entry : OR_RETURN(lister[fs_type](temp_file.path))) {
+    std::cout << entry.path;
+    if (args.show_security_context) {
+      std::cout << " " << entry.security_context;
+    }
+    std::cout << "\n";
+  }
+  return {};
+}
+
+Result<Args> ParseArgs(std::vector<std::string> args) {
+  if (args.size() == 2) {
+    return Args{
+        .apex_file = args[1],
+        .show_security_context = false,
+    };
+  }
+  if (args.size() == 3 && args[1] == "-Z") {
+    return Args{
+        .apex_file = args[2],
+        .show_security_context = true,
+    };
+  }
+  return Error() << "Invalid args\n"
+                 << "usage: " << args[0] << " [-Z] APEX_FILE\n";
+}
+
+Result<void> TryMain(std::vector<std::string> args) {
+  auto parse_args = OR_RETURN(ParseArgs(args));
+  OR_RETURN(PrintList(parse_args));
+  return {};
+}
+
+int main(int argc, char** argv) {
+  android::base::SetMinimumLogSeverity(android::base::ERROR);
+  if (auto st = TryMain(std::vector<std::string>{argv, argv + argc});
+      !st.ok()) {
+    std::cerr << st.error() << "\n";
+    return 1;
+  }
+  return 0;
+}
diff --git a/tools/apexd_host.py b/tools/apexd_host.py
index 0e163c33..2c796348 100644
--- a/tools/apexd_host.py
+++ b/tools/apexd_host.py
@@ -80,10 +80,11 @@ def ParseArgs():
 class ApexFile(object):
   """Represents an APEX file."""
 
-  def __init__(self, path_on_host, path_on_device):
+  def __init__(self, path_on_host, path_on_device, partition):
     self._path_on_host = path_on_host
     self._path_on_device = path_on_device
     self._manifest = apex_manifest.fromApex(path_on_host)
+    self._partition = partition
 
   @property
   def name(self):
@@ -97,12 +98,17 @@ class ApexFile(object):
   def path_on_device(self):
     return self._path_on_device
 
+  @property
+  def partition(self):
+    return self._partition
+
   # Helper to create apex-info element
   @property
   def attrs(self):
     return {
         'moduleName': self.name,
         'modulePath': self.path_on_device,
+        'partition': self.partition.upper(),
         'preinstalledModulePath': self.path_on_device,
         'versionCode': str(self._manifest.version),
         'versionName': self._manifest.versionName,
@@ -124,19 +130,21 @@ def InitTools(tool_path):
       )
     tool_path = os.path.dirname(os.path.dirname(exec_path))
 
-  def ToolPath(name):
-    path = os.path.join(tool_path, 'bin', name)
-    if not os.path.exists(path):
-      sys.exit(f'Required tool({name}) not found in {tool_path}')
-    return path
-
+  def ToolPath(name, candidates):
+    for candidate in candidates:
+      path = os.path.join(tool_path, 'bin', candidate)
+      if os.path.exists(path):
+        return path
+    sys.exit(f'Required tool({name}) not found in {tool_path}')
+
+  tools = {
+    'deapexer': ['deapexer'],
+    'debugfs': ['debugfs', 'debugfs_static'],
+    'fsckerofs': ['fsck.erofs'],
+  }
   return {
-      tool: ToolPath(tool)
-      for tool in [
-          'deapexer',
-          'debugfs_static',
-          'fsck.erofs',
-      ]
+      tool: ToolPath(tool, candidates)
+      for tool, candidates in tools.items()
   }
 
 
@@ -146,7 +154,7 @@ def ScanApexes(partition, real_path) -> list[ApexFile]:
       os.path.join(real_path, 'apex/*.apex')
   ) + glob.glob(os.path.join(real_path, 'apex/*.capex')):
     path_on_device = f'/{partition}/apex/' + os.path.basename(path_on_host)
-    apexes.append(ApexFile(path_on_host, path_on_device))
+    apexes.append(ApexFile(path_on_host, path_on_device, partition))
   # sort list for stability
   return sorted(apexes, key=lambda apex: apex.path_on_device)
 
@@ -168,8 +176,8 @@ def ActivateApexes(partitions, apex_dir, tools):
         continue
 
       cmd = [tools['deapexer']]
-      cmd += ['--debugfs_path', tools['debugfs_static']]
-      cmd += ['--fsckerofs_path', tools['fsck.erofs']]
+      cmd += ['--debugfs_path', tools['debugfs']]
+      cmd += ['--fsckerofs_path', tools['fsckerofs']]
       cmd += [
           'extract',
           apex_file.path_on_host,
diff --git a/tools/brand_new_apex_verifier.py b/tools/brand_new_apex_verifier.py
new file mode 100644
index 00000000..2551c8c0
--- /dev/null
+++ b/tools/brand_new_apex_verifier.py
@@ -0,0 +1,123 @@
+#!/usr/bin/env python
+#
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+"""brand_new_apex_verifier verifies blocklist files and public keys for brand-new APEX.
+
+Verifies the integrity of blocklist files and public keys associated with brand-new APEX modules.
+Specifically, it checks for duplicate entries in blocklist files and duplicate public key content.
+
+Example:
+    $ brand_new_apex_verifier --pubkey_paths path1 path2 --blocklist_paths --output_path output
+"""
+import argparse
+import os
+
+import apex_blocklist_pb2
+from google.protobuf import json_format
+
+
+def ParseArgs():
+  parser = argparse.ArgumentParser()
+  parser.add_argument('--pubkey_paths', nargs='*', help='List of paths to the .avbpubkey files.')
+  parser.add_argument(
+      '--blocklist_paths', nargs='*', help='List of paths to the blocklist.json files.',
+  )
+  parser.add_argument(
+      '--output_path', help='Output file path.',
+  )
+  return parser.parse_args()
+
+
+def ParseBlocklistFile(file):
+  """Parses a blocklist JSON file into an ApexBlocklist protobuf object.
+
+  Args:
+    file: The path to the blocklist JSON file.
+
+  Returns:
+    An ApexBlocklist protobuf object.
+
+  Raises:
+    Exception: If parsing fails due to JSON format errors.
+  """
+  try:
+    with open(file, 'rb') as f:
+      return json_format.Parse(f.read(), apex_blocklist_pb2.ApexBlocklist())
+  except json_format.ParseError as err:
+    raise ValueError(err) from err
+
+
+def VerifyBlocklistFile(blocklist_paths):
+  """Verifies the provided blocklist files.
+
+  Checks for duplicate apex names within each blocklist file.
+
+  Args:
+    blocklist_paths: The paths to the blocklist files.
+
+  Raises:
+    Exception: If duplicate apex names are found in any blocklist file.
+  """
+  for blocklist_path in blocklist_paths:
+    if not os.path.exists(blocklist_path):
+      continue
+    apex_blocklist = ParseBlocklistFile(blocklist_path)
+    blocked_apex = set()
+    for apex_item in apex_blocklist.blocked_apex:
+      if apex_item.name in blocked_apex:
+        raise ValueError(f'Duplicate apex name found in blocklist file: {blocklist_path}')
+      blocked_apex.add(apex_item.name)
+
+
+def VerifyPublicKey(pubkey_paths):
+  """Verifies the provided public key files.
+
+  Checks for duplicate public key file content.
+
+  Args:
+    pubkey_paths: Paths to the public key files.
+
+  Raises:
+    Exception: If duplicate public key content is found.
+  """
+  pubkeys = {}
+  for file_path in pubkey_paths:
+    if not os.path.exists(file_path):
+      continue
+    try:
+      with open(file_path, 'rb') as f:
+        file_content = f.read()
+        if file_content in pubkeys:
+          raise ValueError(
+            f'Duplicate key material found: {pubkeys[file_content]} and '
+            f'{file_path}.')
+        pubkeys[file_content] = file_path
+    except OSError as e:
+      raise ValueError(f'Error reading public key file {file_path}: {e}') from e
+
+
+def main():
+  args = ParseArgs()
+
+  with open(args.output_path, 'w', encoding='utf-8') as f:
+    try:
+      VerifyBlocklistFile(args.blocklist_paths)
+      VerifyPublicKey(args.pubkey_paths)
+      f.write('Verification successful.')
+    except ValueError as e:
+      f.write(f'Verification failed: {e}')
+
+if __name__ == '__main__':
+  main()
diff --git a/tools/deapexer.py b/tools/deapexer.py
index ade5945e..c42724c0 100755
--- a/tools/deapexer.py
+++ b/tools/deapexer.py
@@ -295,9 +295,16 @@ class Apex(object):
     # Output of stat for a symlink should have the following line:
     #   Fast link dest: \"%.*s\"
     m = re.search(r'\bFast link dest: \"(.+)\"\n', stdout)
-    if not m:
+    if m:
+      return m.group(1)
+
+    # if above match fails, it means it's a slow link. Use cat.
+    output = subprocess.check_output([self._debugfs, '-R', f'cat {entry.full_path}',
+                                      self._payload], text=True, stderr=subprocess.DEVNULL)
+
+    if not output:
       sys.exit('failed to read symlink target')
-    return m.group(1)
+    return output
 
   def write_entry(self, entry, out_dir):
     dest = os.path.normpath(os.path.join(out_dir, entry.full_path))
```

