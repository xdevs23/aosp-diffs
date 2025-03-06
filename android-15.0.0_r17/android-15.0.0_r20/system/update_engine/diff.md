```diff
diff --git a/Android.bp b/Android.bp
index 0cbf2863..dd9b02e4 100644
--- a/Android.bp
+++ b/Android.bp
@@ -80,6 +80,9 @@ cc_defaults {
             cflags: [
                 "-DUSE_FEC=1",
             ],
+            shared_libs: [
+                "libbase",
+            ],
         },
         host: {
             cflags: [
@@ -182,7 +185,7 @@ python_library_host {
 // The payload application component and common dependencies.
 cc_defaults {
     name: "libpayload_consumer_exports_defaults",
-    defaults: ["update_metadata-protos_exports",],
+    defaults: ["update_metadata-protos_exports"],
 
     static_libs: [
         "libxz",
@@ -214,17 +217,17 @@ cc_defaults {
 cc_defaults {
     name: "libpayload_consumer_exports",
     defaults: [
-        "libpayload_consumer_exports_defaults"
+        "libpayload_consumer_exports_defaults",
     ],
-    static_libs: ["update_metadata-protos",],
+    static_libs: ["update_metadata-protos"],
 }
 
 cc_defaults {
     name: "libpayload_consumer_exports_proto-full",
     defaults: [
-        "libpayload_consumer_exports_defaults"
+        "libpayload_consumer_exports_defaults",
     ],
-    static_libs: ["update_metadata-protos-full",],
+    static_libs: ["update_metadata-protos-full"],
 }
 
 cc_defaults {
@@ -309,7 +312,7 @@ cc_library_static {
     export_generated_headers: ["statslog_ue.h"],
     shared_libs: [
         "libstatssocket",
-    ]
+    ],
 }
 
 genrule {
@@ -335,7 +338,7 @@ genrule {
 // A BootControl class implementation using Android's HIDL boot_control HAL.
 cc_defaults {
     name: "libupdate_engine_boot_control_exports_defaults",
-    defaults: ["update_metadata-protos_exports",],
+    defaults: ["update_metadata-protos_exports"],
 
     static_libs: [
         "libcutils",
@@ -368,7 +371,7 @@ cc_defaults {
             exclude_static_libs: [
                 "libfs_mgr_binder",
                 "libsnapshot_static",
-                "libstatslog_ue"
+                "libstatslog_ue",
             ],
         },
     },
@@ -382,7 +385,7 @@ cc_defaults {
     static_libs: [
         "libpayload_consumer",
         "update_metadata-protos",
-    ]
+    ],
 }
 
 cc_defaults {
@@ -393,7 +396,7 @@ cc_defaults {
     static_libs: [
         "libpayload_consumer_proto-full",
         "update_metadata-protos-full",
-    ]
+    ],
 }
 
 cc_defaults {
@@ -466,7 +469,7 @@ cc_defaults {
         "libbrillo-binder",
         "libcurl",
         "libcutils",
-        "libupdate_engine_stable-V2-cpp",
+        "libupdate_engine_stable-V3-cpp",
         "liblog",
         "libssl",
         "libstatssocket",
@@ -503,6 +506,29 @@ cc_defaults {
     ],
 }
 
+aidl_interface {
+    name: "libupdate_engine_aidl_interface",
+    srcs: [
+        ":libupdate_engine_aidl",
+    ],
+    backend: {
+        cpp: {
+            enabled: false,
+        },
+        java: {
+            enabled: false,
+        },
+        ndk: {
+            enabled: false,
+        },
+        rust: {
+            enabled: true,
+        },
+    },
+    frozen: false,
+    unstable: true,
+}
+
 cc_defaults {
     name: "libupdate_engine_android_defaults",
     defaults: [
@@ -539,7 +565,7 @@ cc_library_static {
     defaults: [
         "libupdate_engine_android_defaults",
         "libupdate_engine_android_exports",
-    ]
+    ],
 }
 
 cc_library_static {
@@ -547,7 +573,7 @@ cc_library_static {
     defaults: [
         "libupdate_engine_android_defaults",
         "libupdate_engine_android_exports_proto-full",
-    ]
+    ],
 }
 
 // update_engine (type: executable)
@@ -569,7 +595,10 @@ cc_binary {
         "otacerts",
     ],
 
-    srcs: ["main.cc", "aosp/metrics_reporter_android.cc"],
+    srcs: [
+        "main.cc",
+        "aosp/metrics_reporter_android.cc",
+    ],
     init_rc: ["update_engine.rc"],
 }
 
@@ -595,7 +624,7 @@ cc_binary {
 
     exclude_static_libs: [
         "libstatslog_ue",
-        "libupdate_engine_boot_control"
+        "libupdate_engine_boot_control",
     ],
 
     exclude_shared_libs: [
@@ -774,7 +803,7 @@ cc_library_static {
     name: "libcow_size_estimator",
     defaults: [
         "ue_defaults",
-        "update_metadata-protos_exports"
+        "update_metadata-protos_exports",
     ],
     host_supported: true,
     recovery_available: true,
@@ -806,7 +835,10 @@ cc_defaults {
 cc_library_static {
     name: "liblz4diff",
     host_supported: true,
-    defaults: ["ue_defaults", "liblz4diff_defaults"],
+    defaults: [
+        "ue_defaults",
+        "liblz4diff_defaults",
+    ],
     srcs: [
         "lz4diff/lz4diff.cc",
         "lz4diff/lz4diff_compress.cc",
@@ -995,8 +1027,8 @@ genrule {
 genrule {
     name: "ue_unittest_erofs_imgs",
     cmd: "$(in) $(location mkfs.erofs) $(location gen/erofs_empty.img) && " +
-         "$(in) $(location mkfs.erofs) $(location gen/erofs.img) $(location delta_generator) && " +
-         "$(in) $(location mkfs.erofs) $(location gen/erofs_new.img) $(location delta_generator) lz4hc,7",
+        "$(in) $(location mkfs.erofs) $(location gen/erofs.img) $(location delta_generator) && " +
+        "$(in) $(location mkfs.erofs) $(location gen/erofs_new.img) $(location delta_generator) lz4hc,7",
     srcs: ["sample_images/generate_test_erofs_images.sh"],
     out: [
         "gen/erofs.img",
@@ -1298,7 +1330,7 @@ cc_library_headers {
         darwin: {
             enabled: false,
         },
-    }
+    },
 }
 
 cc_binary_host {
@@ -1410,6 +1442,6 @@ cc_fuzz {
         cc: [
             "elsk@google.com",
             "zhangkelvin@google.com",
-        ]
+        ],
     },
 }
diff --git a/OWNERS b/OWNERS
index 58ecfe1a..1900cf4f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -2,9 +2,7 @@ set noparent
 
 # Android et. al. maintainers:
 deymo@google.com
-elsk@google.com
 senj@google.com
-xunchang@google.com
 zhangkelvin@google.com
 
 # Chromium OS maintainers:
diff --git a/aosp/binder_service_android.cc b/aosp/binder_service_android.cc
index 37df9a56..ec9ea6e8 100644
--- a/aosp/binder_service_android.cc
+++ b/aosp/binder_service_android.cc
@@ -24,6 +24,7 @@
 #include <utils/String8.h>
 
 #include "update_engine/aosp/binder_service_android_common.h"
+#include "update_engine/common/error_code.h"
 
 using android::binder::Status;
 using android::os::IUpdateEngineCallback;
@@ -254,4 +255,14 @@ Status BinderUpdateEngineAndroidService::cleanupSuccessfulUpdate(
   return Status::ok();
 }
 
+Status BinderUpdateEngineAndroidService::triggerPostinstall(
+    const ::android::String16& partition) {
+  Error error;
+  service_delegate_->TriggerPostinstall(android::String8(partition).c_str(),
+                                        &error);
+  if (error.error_code != ErrorCode::kSuccess)
+    return ErrorPtrToStatus(error);
+  return Status::ok();
+}
+
 }  // namespace chromeos_update_engine
diff --git a/aosp/binder_service_android.h b/aosp/binder_service_android.h
index f1ce6b5d..25d3c4bb 100644
--- a/aosp/binder_service_android.h
+++ b/aosp/binder_service_android.h
@@ -33,8 +33,9 @@
 
 namespace chromeos_update_engine {
 
-class BinderUpdateEngineAndroidService : public android::os::BnUpdateEngine,
-                                         public ServiceObserverInterface {
+class BinderUpdateEngineAndroidService final
+    : public android::os::BnUpdateEngine,
+      public ServiceObserverInterface {
  public:
   explicit BinderUpdateEngineAndroidService(
       ServiceDelegateAndroidInterface* service_delegate);
@@ -79,6 +80,8 @@ class BinderUpdateEngineAndroidService : public android::os::BnUpdateEngine,
       int64_t* return_value) override;
   android::binder::Status cleanupSuccessfulUpdate(
       const android::sp<android::os::IUpdateEngineCallback>& callback) override;
+  ::android::binder::Status triggerPostinstall(
+      const ::android::String16& partition) override;
 
  private:
   // Remove the passed |callback| from the list of registered callbacks. Called
diff --git a/aosp/binder_service_stable_android.cc b/aosp/binder_service_stable_android.cc
index 3bc7f6c4..069f3ba6 100644
--- a/aosp/binder_service_stable_android.cc
+++ b/aosp/binder_service_stable_android.cc
@@ -16,8 +16,6 @@
 
 #include "update_engine/aosp/binder_service_stable_android.h"
 
-#include <memory>
-
 #include <base/bind.h>
 #include <base/logging.h>
 #include <binderwrapper/binder_wrapper.h>
@@ -125,4 +123,15 @@ bool BinderUpdateEngineAndroidStableService::UnbindCallback(
   return true;
 }
 
+android::binder::Status
+BinderUpdateEngineAndroidStableService::triggerPostinstall(
+    const ::android::String16& partition) {
+  Error error;
+  if (!service_delegate_->TriggerPostinstall(
+          android::String8{partition}.c_str(), &error)) {
+    return ErrorPtrToStatus(error);
+  }
+  return Status::ok();
+}
+
 }  // namespace chromeos_update_engine
diff --git a/aosp/binder_service_stable_android.h b/aosp/binder_service_stable_android.h
index 212afaa6..2f3fa7e8 100644
--- a/aosp/binder_service_stable_android.h
+++ b/aosp/binder_service_stable_android.h
@@ -19,7 +19,6 @@
 
 #include <stdint.h>
 
-#include <string>
 #include <vector>
 
 #include <utils/Errors.h>
@@ -33,7 +32,7 @@
 
 namespace chromeos_update_engine {
 
-class BinderUpdateEngineAndroidStableService
+class BinderUpdateEngineAndroidStableService final
     : public android::os::BnUpdateEngineStable,
       public ServiceObserverInterface {
  public:
@@ -62,6 +61,8 @@ class BinderUpdateEngineAndroidStableService
   android::binder::Status unbind(
       const android::sp<android::os::IUpdateEngineStableCallback>& callback,
       bool* return_value) override;
+  android::binder::Status triggerPostinstall(
+      const ::android::String16& partition) override;
 
  private:
   // Remove the passed |callback| from the list of registered callbacks. Called
diff --git a/aosp/dynamic_partition_control_android.cc b/aosp/dynamic_partition_control_android.cc
index af46b35b..d1c3bf26 100644
--- a/aosp/dynamic_partition_control_android.cc
+++ b/aosp/dynamic_partition_control_android.cc
@@ -19,6 +19,7 @@
 #include <algorithm>
 #include <chrono>  // NOLINT(build/c++11) - using libsnapshot / liblp API
 #include <cstdint>
+#include <iterator>
 #include <map>
 #include <memory>
 #include <set>
@@ -31,8 +32,7 @@
 #include <android-base/strings.h>
 #include <base/files/file_util.h>
 #include <base/logging.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <bootloader_message/bootloader_message.h>
 #include <fs_mgr.h>
 #include <fs_mgr_dm_linear.h>
@@ -57,6 +57,7 @@
 using android::base::GetBoolProperty;
 using android::base::GetProperty;
 using android::base::Join;
+using android::base::StringPrintf;
 using android::dm::DeviceMapper;
 using android::dm::DmDeviceState;
 using android::fs_mgr::CreateLogicalPartition;
@@ -72,7 +73,6 @@ using android::snapshot::Return;
 using android::snapshot::SnapshotManager;
 using android::snapshot::SnapshotManagerStub;
 using android::snapshot::UpdateState;
-using base::StringPrintf;
 
 namespace chromeos_update_engine {
 
@@ -101,7 +101,11 @@ constexpr std::chrono::milliseconds kMapTimeout{1000};
 constexpr std::chrono::milliseconds kMapSnapshotTimeout{10000};
 
 DynamicPartitionControlAndroid::~DynamicPartitionControlAndroid() {
-  UnmapAllPartitions();
+  std::set<std::string> mapped = mapped_devices_;
+  LOG(INFO) << "Destroying [" << Join(mapped, ", ") << "] from device mapper";
+  for (const auto& device_name : mapped) {
+    ignore_result(UnmapPartitionOnDeviceMapper(device_name));
+  }
   metadata_device_.reset();
 }
 
@@ -185,18 +189,34 @@ bool DynamicPartitionControlAndroid::OptimizeOperation(
   return false;
 }
 
+constexpr auto&& kRWSourcePartitionSuffix = "_ota";
+std::string DynamicPartitionControlAndroid::GetDeviceName(
+    std::string partition_name, uint32_t slot) const {
+  if (partition_name.ends_with(kRWSourcePartitionSuffix)) {
+    return partition_name;
+  }
+  if (!partition_name.ends_with("_a") && !partition_name.ends_with("_b")) {
+    partition_name += slot ? "_b" : "_a";
+  }
+  if (slot == source_slot_) {
+    return partition_name + kRWSourcePartitionSuffix;
+  }
+  return partition_name;
+}
+
 bool DynamicPartitionControlAndroid::MapPartitionInternal(
     const std::string& super_device,
     const std::string& target_partition_name,
     uint32_t slot,
     bool force_writable,
     std::string* path) {
+  auto device_name = GetDeviceName(target_partition_name, slot);
   CreateLogicalPartitionParams params = {
       .block_device = super_device,
       .metadata_slot = slot,
       .partition_name = target_partition_name,
       .force_writable = force_writable,
-  };
+      .device_name = device_name};
   bool success = false;
   if (GetVirtualAbFeatureFlag().IsEnabled() && target_supports_snapshot_ &&
       slot != source_slot_ && force_writable && ExpectMetadataMounted()) {
@@ -220,7 +240,7 @@ bool DynamicPartitionControlAndroid::MapPartitionInternal(
   LOG(INFO) << "Succesfully mapped " << target_partition_name
             << " to device mapper (force_writable = " << force_writable
             << "); device path at " << *path;
-  mapped_devices_.insert(target_partition_name);
+  mapped_devices_.insert(params.device_name);
   return true;
 }
 
@@ -230,9 +250,10 @@ bool DynamicPartitionControlAndroid::MapPartitionOnDeviceMapper(
     uint32_t slot,
     bool force_writable,
     std::string* path) {
-  DmDeviceState state = GetState(target_partition_name);
+  auto device_name = GetDeviceName(target_partition_name, slot);
+  DmDeviceState state = GetState(device_name);
   if (state == DmDeviceState::ACTIVE) {
-    if (mapped_devices_.find(target_partition_name) != mapped_devices_.end()) {
+    if (mapped_devices_.find(device_name) != mapped_devices_.end()) {
       if (GetDmDevicePathByName(target_partition_name, path)) {
         LOG(INFO) << target_partition_name
                   << " is mapped on device mapper: " << *path;
@@ -246,12 +267,13 @@ bool DynamicPartitionControlAndroid::MapPartitionOnDeviceMapper(
     // Note that for source partitions, if GetState() == ACTIVE, callers (e.g.
     // BootControlAndroid) should not call MapPartitionOnDeviceMapper, but
     // should directly call GetDmDevicePathByName.
-    if (!UnmapPartitionOnDeviceMapper(target_partition_name)) {
+    LOG(INFO) << "Destroying `" << device_name << "` from device mapper";
+    if (!UnmapPartitionOnDeviceMapper(device_name)) {
       LOG(ERROR) << target_partition_name
                  << " is mapped before the update, and it cannot be unmapped.";
       return false;
     }
-    state = GetState(target_partition_name);
+    state = GetState(device_name);
     if (state != DmDeviceState::INVALID) {
       LOG(ERROR) << target_partition_name << " is unmapped but state is "
                  << static_cast<std::underlying_type_t<DmDeviceState>>(state);
@@ -271,32 +293,37 @@ bool DynamicPartitionControlAndroid::MapPartitionOnDeviceMapper(
 
 bool DynamicPartitionControlAndroid::UnmapPartitionOnDeviceMapper(
     const std::string& target_partition_name) {
-  if (DeviceMapper::Instance().GetState(target_partition_name) !=
+  auto device_name = target_partition_name;
+  if (target_partition_name.ends_with("_a") ||
+      target_partition_name.ends_with("_b")) {
+    auto slot = target_partition_name.ends_with("_a") ? 0 : 1;
+    device_name = GetDeviceName(target_partition_name, slot);
+  }
+  if (DeviceMapper::Instance().GetState(device_name) !=
       DmDeviceState::INVALID) {
     // Partitions at target slot on non-Virtual A/B devices are mapped as
     // dm-linear. Also, on Virtual A/B devices, system_other may be mapped for
     // preopt apps as dm-linear.
     // Call DestroyLogicalPartition to handle these cases.
-    bool success = DestroyLogicalPartition(target_partition_name);
+    bool success = DestroyLogicalPartition(device_name);
 
     // On a Virtual A/B device, |target_partition_name| may be a leftover from
     // a paused update. Clean up any underlying devices.
-    if (ExpectMetadataMounted()) {
-      success &= snapshot_->UnmapUpdateSnapshot(target_partition_name);
+    if (ExpectMetadataMounted() &&
+        !device_name.ends_with(kRWSourcePartitionSuffix)) {
+      success &= snapshot_->UnmapUpdateSnapshot(device_name);
     } else {
-      LOG(INFO) << "Skip UnmapUpdateSnapshot(" << target_partition_name
-                << ") because metadata is not mounted";
+      LOG(INFO) << "Skip UnmapUpdateSnapshot(" << device_name << ")";
     }
 
     if (!success) {
-      LOG(ERROR) << "Cannot unmap " << target_partition_name
-                 << " from device mapper.";
+      LOG(ERROR) << "Cannot unmap " << device_name << " from device mapper.";
       return false;
     }
-    LOG(INFO) << "Successfully unmapped " << target_partition_name
+    LOG(INFO) << "Successfully unmapped " << device_name
               << " from device mapper.";
   }
-  mapped_devices_.erase(target_partition_name);
+  mapped_devices_.erase(device_name);
   return true;
 }
 
@@ -307,16 +334,27 @@ bool DynamicPartitionControlAndroid::UnmapAllPartitions() {
   }
   // UnmapPartitionOnDeviceMapper removes objects from mapped_devices_, hence
   // a copy is needed for the loop.
-  std::set<std::string> mapped = mapped_devices_;
+  std::set<std::string> mapped;
+  std::copy_if(mapped_devices_.begin(),
+               mapped_devices_.end(),
+               std::inserter(mapped, mapped.end()),
+               [](auto&& device_name) {
+                 return !std::string_view(device_name)
+                             .ends_with(kRWSourcePartitionSuffix);
+               });
   LOG(INFO) << "Destroying [" << Join(mapped, ", ") << "] from device mapper";
-  for (const auto& partition_name : mapped) {
-    ignore_result(UnmapPartitionOnDeviceMapper(partition_name));
+  for (const auto& device_name : mapped) {
+    ignore_result(UnmapPartitionOnDeviceMapper(device_name));
   }
   return true;
 }
 
 void DynamicPartitionControlAndroid::Cleanup() {
-  UnmapAllPartitions();
+  std::set<std::string> mapped = mapped_devices_;
+  LOG(INFO) << "Destroying [" << Join(mapped, ", ") << "] from device mapper";
+  for (const auto& device_name : mapped) {
+    ignore_result(UnmapPartitionOnDeviceMapper(device_name));
+  }
   LOG(INFO) << "UnmapAllPartitions done";
   metadata_device_.reset();
   if (GetVirtualAbFeatureFlag().IsEnabled()) {
@@ -773,6 +811,8 @@ bool DynamicPartitionControlAndroid::GetSystemOtherPath(
   // In recovery, metadata might not be mounted, and
   // UnmapPartitionOnDeviceMapper might fail. However,
   // it is unusual that system_other has already been mapped. Hence, just skip.
+  LOG(INFO) << "Destroying `" << partition_name_suffix
+            << "` from device mapper";
   TEST_AND_RETURN_FALSE(UnmapPartitionOnDeviceMapper(partition_name_suffix));
   // Use CreateLogicalPartition directly to avoid mapping with existing
   // snapshots.
@@ -814,6 +854,8 @@ bool DynamicPartitionControlAndroid::EraseSystemOtherAvbFooter(
   // should be called. If DestroyLogicalPartition does fail, it is still okay
   // to skip the error here and let Prepare*() fail later.
   if (should_unmap) {
+    LOG(INFO) << "Destroying `" << partition_name_suffix
+              << "` from device mapper";
     TEST_AND_RETURN_FALSE(UnmapPartitionOnDeviceMapper(partition_name_suffix));
   }
 
@@ -943,7 +985,8 @@ bool DynamicPartitionControlAndroid::CheckSuperPartitionAllocatableSpace(
     }
     case SpaceLimit::ERROR_IF_EXCEEDED_SUPER: {
       if (sum_groups > full_space) {
-        LOG(ERROR) << base::StringPrintf(fmt, sum_groups, "", full_space);
+        LOG(ERROR) << android::base::StringPrintf(
+            fmt, sum_groups, "", full_space);
         return false;
       }
       break;
@@ -1161,12 +1204,13 @@ DynamicPartitionControlAndroid::GetPartitionDevice(
   std::string device;
   if (GetDynamicPartitionsFeatureFlag().IsEnabled() &&
       (slot == current_slot || is_target_dynamic_)) {
-    switch (GetDynamicPartitionDevice(device_dir,
-                                      partition_name_suffix,
-                                      slot,
-                                      current_slot,
-                                      not_in_payload,
-                                      &device)) {
+    auto status = GetDynamicPartitionDevice(device_dir,
+                                            partition_name_suffix,
+                                            slot,
+                                            current_slot,
+                                            not_in_payload,
+                                            &device);
+    switch (status) {
       case DynamicPartitionDeviceStatus::SUCCESS:
         return {{.rw_device_path = device,
                  .readonly_device_path = device,
@@ -1176,6 +1220,7 @@ DynamicPartitionControlAndroid::GetPartitionDevice(
         break;
       case DynamicPartitionDeviceStatus::ERROR:  // fallthrough
       default:
+        LOG(ERROR) << "Unhandled dynamic partition status " << (int)status;
         return {};
     }
   }
@@ -1211,6 +1256,7 @@ DynamicPartitionControlAndroid::GetDynamicPartitionDevice(
     std::string* device) {
   std::string super_device =
       device_dir.Append(GetSuperPartitionName(slot)).value();
+  auto device_name = GetDeviceName(partition_name_suffix, slot);
 
   auto builder = LoadMetadataBuilder(super_device, slot);
   if (builder == nullptr) {
@@ -1233,13 +1279,12 @@ DynamicPartitionControlAndroid::GetDynamicPartitionDevice(
   }
 
   if (slot == current_slot) {
-    if (GetState(partition_name_suffix) != DmDeviceState::ACTIVE) {
-      LOG(WARNING) << partition_name_suffix << " is at current slot but it is "
+    if (GetState(device_name) != DmDeviceState::ACTIVE) {
+      LOG(WARNING) << device_name << " is at current slot but it is "
                    << "not mapped. Now try to map it.";
     } else {
-      if (GetDmDevicePathByName(partition_name_suffix, device)) {
-        LOG(INFO) << partition_name_suffix
-                  << " is mapped on device mapper: " << *device;
+      if (GetDmDevicePathByName(device_name, device)) {
+        LOG(INFO) << device_name << " is mapped on device mapper: " << *device;
         return DynamicPartitionDeviceStatus::SUCCESS;
       }
       LOG(ERROR) << partition_name_suffix << "is mapped but path is unknown.";
diff --git a/aosp/dynamic_partition_control_android.h b/aosp/dynamic_partition_control_android.h
index 176cf504..1f70184f 100644
--- a/aosp/dynamic_partition_control_android.h
+++ b/aosp/dynamic_partition_control_android.h
@@ -338,6 +338,8 @@ class DynamicPartitionControlAndroid : public DynamicPartitionControlInterface {
   // target_supports_snapshot_ and is_target_dynamic_.
   bool SetTargetBuildVars(const DeltaArchiveManifest& manifest);
 
+  std::string GetDeviceName(std::string partition_name, uint32_t slot) const;
+
   std::set<std::string> mapped_devices_;
   const FeatureFlag dynamic_partitions_;
   const FeatureFlag virtual_ab_;
diff --git a/aosp/dynamic_partition_control_android_unittest.cc b/aosp/dynamic_partition_control_android_unittest.cc
index 30780f0a..68223948 100644
--- a/aosp/dynamic_partition_control_android_unittest.cc
+++ b/aosp/dynamic_partition_control_android_unittest.cc
@@ -16,17 +16,15 @@
 
 #include "update_engine/aosp/dynamic_partition_control_android.h"
 
-#include <algorithm>
 #include <set>
-#include <vector>
 
 #include <base/logging.h>
-#include <base/strings/string_util.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 #include <libavb/libavb.h>
 #include <libsnapshot/mock_snapshot.h>
 
+#include "update_engine/aosp/boot_control_android.h"
 #include "update_engine/aosp/dynamic_partition_test_utils.h"
 #include "update_engine/aosp/mock_dynamic_partition_control_android.h"
 #include "update_engine/common/mock_prefs.h"
@@ -213,7 +211,7 @@ class DynamicPartitionControlAndroidTest : public ::testing::Test {
   }
 
   std::unique_ptr<DynamicPartitionControlAndroid> module_;
-  TestParam slots_;
+  TestParam slots_{};
 };
 
 class DynamicPartitionControlAndroidTestP
@@ -241,7 +239,7 @@ TEST_P(DynamicPartitionControlAndroidTestP,
                                 {T("system"), 3_GiB},
                                 {T("vendor"), 1_GiB}};
   PartitionSizes update_metadata{{"system", 3_GiB}, {"vendor", 1_GiB}};
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_metadata, update_metadata, expected));
 }
 
@@ -258,7 +256,7 @@ TEST_P(DynamicPartitionControlAndroidTestP,
                                 {T("system"), 2_GiB},
                                 {T("vendor"), 150_MiB}};
   PartitionSizes update_metadata{{"system", 2_GiB}, {"vendor", 150_MiB}};
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_metadata, update_metadata, expected));
 }
 
@@ -267,7 +265,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, AddPartitionToEmptyMetadata) {
   PartitionSuffixSizes source_metadata{};
   PartitionSuffixSizes expected{{T("system"), 2_GiB}, {T("vendor"), 1_GiB}};
   PartitionSizes update_metadata{{"system", 2_GiB}, {"vendor", 1_GiB}};
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_metadata, update_metadata, expected));
 }
 
@@ -278,7 +276,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, AddAdditionalPartition) {
   PartitionSuffixSizes expected{
       {S("system"), 2_GiB}, {T("system"), 2_GiB}, {T("vendor"), 1_GiB}};
   PartitionSizes update_metadata{{"system", 2_GiB}, {"vendor", 1_GiB}};
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_metadata, update_metadata, expected));
 }
 
@@ -292,7 +290,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, DeletePartition) {
   PartitionSuffixSizes expected{
       {S("system"), 2_GiB}, {S("vendor"), 1_GiB}, {T("system"), 2_GiB}};
   PartitionSizes update_metadata{{"system", 2_GiB}};
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_metadata, update_metadata, expected));
 }
 
@@ -304,7 +302,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, DeleteAll) {
                                        {T("vendor"), 1_GiB}};
   PartitionSuffixSizes expected{{S("system"), 2_GiB}, {S("vendor"), 1_GiB}};
   PartitionSizes update_metadata{};
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_metadata, update_metadata, expected));
 }
 
@@ -315,7 +313,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, CorruptedSourceMetadata) {
       .WillOnce(Invoke([](auto, auto, auto) { return nullptr; }));
   ExpectUnmap({T("system")});
 
-  EXPECT_FALSE(PreparePartitionsForUpdate({{"system", 1_GiB}}))
+  ASSERT_FALSE(PreparePartitionsForUpdate({{"system", 1_GiB}}))
       << "Should not be able to continue with corrupt source metadata";
 }
 
@@ -328,7 +326,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, NotEnoughSpace) {
                                        {T("vendor"), 0}};
   PartitionSizes update_metadata{{"system", 3_GiB}, {"vendor", 3_GiB}};
 
-  EXPECT_FALSE(UpdatePartitionMetadata(source_metadata, update_metadata, {}))
+  ASSERT_FALSE(UpdatePartitionMetadata(source_metadata, update_metadata, {}))
       << "Should not be able to fit 11GiB data into 10GiB space";
 }
 
@@ -338,7 +336,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, NotEnoughSpaceForSlot) {
                                        {T("system"), 0},
                                        {T("vendor"), 0}};
   PartitionSizes update_metadata{{"system", 3_GiB}, {"vendor", 3_GiB}};
-  EXPECT_FALSE(UpdatePartitionMetadata(source_metadata, update_metadata, {}))
+  ASSERT_FALSE(UpdatePartitionMetadata(source_metadata, update_metadata, {}))
       << "Should not be able to grow over size of super / 2";
 }
 
@@ -363,35 +361,35 @@ TEST_P(DynamicPartitionControlAndroidTestP,
   // Not calling through
   // DynamicPartitionControlAndroidTest::PreparePartitionsForUpdate(), since we
   // don't want any default group in the PartitionMetadata.
-  EXPECT_TRUE(dynamicControl().PreparePartitionsForUpdate(
+  ASSERT_TRUE(dynamicControl().PreparePartitionsForUpdate(
       source(), target(), {}, true, nullptr, nullptr));
 
   // Should use dynamic source partitions.
-  EXPECT_CALL(dynamicControl(), GetState(S("system")))
+  EXPECT_CALL(dynamicControl(), GetState(S("system") + "_ota"))
       .Times(1)
       .WillOnce(Return(DmDeviceState::ACTIVE));
   string system_device;
-  EXPECT_TRUE(dynamicControl().GetPartitionDevice(
+  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "system", source(), source(), &system_device));
-  EXPECT_EQ(GetDmDevice(S("system")), system_device);
+  ASSERT_EQ(GetDmDevice(S("system") + "_ota"), system_device);
 
   // Should use static target partitions without querying dynamic control.
   EXPECT_CALL(dynamicControl(), GetState(T("system"))).Times(0);
-  EXPECT_TRUE(dynamicControl().GetPartitionDevice(
+  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "system", target(), source(), &system_device));
-  EXPECT_EQ(GetDevice(T("system")), system_device);
+  ASSERT_EQ(GetDevice(T("system")), system_device);
 
   // Static partition "bar".
   EXPECT_CALL(dynamicControl(), GetState(S("bar"))).Times(0);
   std::string bar_device;
-  EXPECT_TRUE(dynamicControl().GetPartitionDevice(
+  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "bar", source(), source(), &bar_device));
-  EXPECT_EQ(GetDevice(S("bar")), bar_device);
+  ASSERT_EQ(GetDevice(S("bar")), bar_device);
 
   EXPECT_CALL(dynamicControl(), GetState(T("bar"))).Times(0);
-  EXPECT_TRUE(dynamicControl().GetPartitionDevice(
+  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "bar", target(), source(), &bar_device));
-  EXPECT_EQ(GetDevice(T("bar")), bar_device);
+  ASSERT_EQ(GetDevice(T("bar")), bar_device);
 }
 
 TEST_P(DynamicPartitionControlAndroidTestP, GetMountableDevicePath) {
@@ -412,9 +410,9 @@ TEST_P(DynamicPartitionControlAndroidTestP, GetMountableDevicePath) {
                                  GetDevice(S("system")),
                                  GetDevice(T("system")))))
       .WillRepeatedly(Return(true));
-  EXPECT_CALL(
-      dynamicControl(),
-      GetState(AnyOf(S("vendor"), T("vendor"), S("system"), T("system"))))
+  EXPECT_CALL(dynamicControl(),
+              GetState(AnyOf(
+                  S("vendor"), T("vendor"), S("system") + "_ota", T("system"))))
       .WillRepeatedly(Return(DmDeviceState::ACTIVE));
 
   SetMetadata(source(), {{S("system"), 2_GiB}, {S("vendor"), 1_GiB}});
@@ -422,7 +420,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, GetMountableDevicePath) {
   std::string device;
   ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "system", source(), source(), &device));
-  ASSERT_EQ(GetDmDevice(S("system")), device);
+  ASSERT_EQ(GetDmDevice(S("system") + "_ota"), device);
 
   ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "system", target(), source(), &device));
@@ -454,9 +452,9 @@ TEST_P(DynamicPartitionControlAndroidTestP, GetMountableDevicePathVABC) {
                                  GetDevice(S("system")),
                                  GetDevice(T("system")))))
       .WillRepeatedly(Return(true));
-  EXPECT_CALL(
-      dynamicControl(),
-      GetState(AnyOf(S("vendor"), T("vendor"), S("system"), T("system"))))
+  EXPECT_CALL(dynamicControl(),
+              GetState(AnyOf(
+                  S("vendor"), T("vendor"), S("system") + "_ota", T("system"))))
       .WillRepeatedly(Return(DmDeviceState::ACTIVE));
 
   SetMetadata(source(), {{S("system"), 2_GiB}, {S("vendor"), 1_GiB}});
@@ -465,7 +463,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, GetMountableDevicePathVABC) {
   std::string device;
   ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "system", source(), source(), &device));
-  ASSERT_EQ(GetDmDevice(S("system")), device);
+  ASSERT_EQ(GetDmDevice(S("system") + "_ota"), device);
 
   ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "system", target(), source(), &device));
@@ -500,7 +498,7 @@ TEST_P(DynamicPartitionControlAndroidTestP,
                {T("system"), 2_GiB},
                {T("vendor"), 1_GiB}});
 
-  EXPECT_TRUE(dynamicControl().PreparePartitionsForUpdate(
+  ASSERT_TRUE(dynamicControl().PreparePartitionsForUpdate(
       source(),
       target(),
       PartitionSizesToManifest({{"system", 2_GiB}, {"vendor", 1_GiB}}),
@@ -509,13 +507,13 @@ TEST_P(DynamicPartitionControlAndroidTestP,
       nullptr));
 
   // Dynamic partition "system".
-  EXPECT_CALL(dynamicControl(), GetState(S("system")))
+  EXPECT_CALL(dynamicControl(), GetState(S("system") + "_ota"))
       .Times(1)
       .WillOnce(Return(DmDeviceState::ACTIVE));
   string system_device;
-  EXPECT_TRUE(dynamicControl().GetPartitionDevice(
+  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "system", source(), source(), &system_device));
-  EXPECT_EQ(GetDmDevice(S("system")), system_device);
+  ASSERT_EQ(GetDmDevice(S("system") + "_ota"), system_device);
 
   EXPECT_CALL(dynamicControl(), GetState(T("system")))
       .Times(AnyNumber())
@@ -529,21 +527,21 @@ TEST_P(DynamicPartitionControlAndroidTestP,
             *device = "/fake/remapped/" + name;
             return true;
           }));
-  EXPECT_TRUE(dynamicControl().GetPartitionDevice(
+  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "system", target(), source(), &system_device));
-  EXPECT_EQ("/fake/remapped/" + T("system"), system_device);
+  ASSERT_EQ("/fake/remapped/" + T("system"), system_device);
 
   // Static partition "bar".
   EXPECT_CALL(dynamicControl(), GetState(S("bar"))).Times(0);
   std::string bar_device;
-  EXPECT_TRUE(dynamicControl().GetPartitionDevice(
+  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "bar", source(), source(), &bar_device));
-  EXPECT_EQ(GetDevice(S("bar")), bar_device);
+  ASSERT_EQ(GetDevice(S("bar")), bar_device);
 
   EXPECT_CALL(dynamicControl(), GetState(T("bar"))).Times(0);
-  EXPECT_TRUE(dynamicControl().GetPartitionDevice(
+  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
       "bar", target(), source(), &bar_device));
-  EXPECT_EQ(GetDevice(T("bar")), bar_device);
+  ASSERT_EQ(GetDevice(T("bar")), bar_device);
 }
 
 INSTANTIATE_TEST_CASE_P(DynamicPartitionControlAndroidTest,
@@ -583,7 +581,7 @@ TEST_P(DynamicPartitionControlAndroidGroupTestP, ResizeWithinGroup) {
   AddGroupAndPartition(&update_manifest, "android", 3_GiB, "system", 3_GiB);
   AddGroupAndPartition(&update_manifest, "oem", 2_GiB, "vendor", 2_GiB);
 
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_manifest, update_manifest, expected));
 }
 
@@ -591,7 +589,7 @@ TEST_P(DynamicPartitionControlAndroidGroupTestP, NotEnoughSpaceForGroup) {
   DeltaArchiveManifest update_manifest;
   AddGroupAndPartition(&update_manifest, "android", 3_GiB, "system", 1_GiB),
       AddGroupAndPartition(&update_manifest, "oem", 2_GiB, "vendor", 3_GiB);
-  EXPECT_FALSE(UpdatePartitionMetadata(source_manifest, update_manifest, {}))
+  ASSERT_FALSE(UpdatePartitionMetadata(source_manifest, update_manifest, {}))
       << "Should not be able to grow over maximum size of group";
 }
 
@@ -599,7 +597,7 @@ TEST_P(DynamicPartitionControlAndroidGroupTestP, GroupTooBig) {
   DeltaArchiveManifest update_manifest;
   AddGroup(&update_manifest, "android", 3_GiB);
   AddGroup(&update_manifest, "oem", 3_GiB);
-  EXPECT_FALSE(UpdatePartitionMetadata(source_manifest, update_manifest, {}))
+  ASSERT_FALSE(UpdatePartitionMetadata(source_manifest, update_manifest, {}))
       << "Should not be able to grow over size of super / 2";
 }
 
@@ -615,7 +613,7 @@ TEST_P(DynamicPartitionControlAndroidGroupTestP, AddPartitionToGroup) {
   AddPartition(&update_manifest, g, "system_ext", 1_GiB);
   AddGroupAndPartition(&update_manifest, "oem", 2_GiB, "vendor", 2_GiB);
 
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_manifest, update_manifest, expected));
 }
 
@@ -627,7 +625,7 @@ TEST_P(DynamicPartitionControlAndroidGroupTestP, RemovePartitionFromGroup) {
   AddGroup(&update_manifest, "android", 3_GiB);
   AddGroupAndPartition(&update_manifest, "oem", 2_GiB, "vendor", 2_GiB);
 
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_manifest, update_manifest, expected));
 }
 
@@ -641,7 +639,7 @@ TEST_P(DynamicPartitionControlAndroidGroupTestP, AddGroup) {
   AddGroupAndPartition(&update_manifest, "oem", 1_GiB, "vendor", 1_GiB);
   AddGroupAndPartition(
       &update_manifest, "new_group", 2_GiB, "new_partition", 2_GiB);
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_manifest, update_manifest, expected));
 }
 
@@ -649,7 +647,7 @@ TEST_P(DynamicPartitionControlAndroidGroupTestP, RemoveGroup) {
   DeltaArchiveManifest update_manifest;
   AddGroupAndPartition(&update_manifest, "android", 2_GiB, "system", 2_GiB);
 
-  EXPECT_TRUE(UpdatePartitionMetadata(
+  ASSERT_TRUE(UpdatePartitionMetadata(
       source_manifest, update_manifest, Not(HasGroup(T("oem")))));
 }
 
@@ -660,7 +658,7 @@ TEST_P(DynamicPartitionControlAndroidGroupTestP, ResizeGroup) {
   DeltaArchiveManifest update_manifest;
   AddGroupAndPartition(&update_manifest, "android", 2_GiB, "system", 2_GiB),
       AddGroupAndPartition(&update_manifest, "oem", 3_GiB, "vendor", 3_GiB);
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       UpdatePartitionMetadata(source_manifest, update_manifest, expected));
 }
 
@@ -726,7 +724,7 @@ TEST_F(DynamicPartitionControlAndroidTest, SimulatedFirstUpdate) {
   ExpectStoreMetadata(update_sizes_1());
   ExpectUnmap({"grown_b", "shrunk_b", "same_b", "added_b"});
 
-  EXPECT_TRUE(PreparePartitionsForUpdate({{"grown", 3_GiB},
+  ASSERT_TRUE(PreparePartitionsForUpdate({{"grown", 3_GiB},
                                           {"shrunk", 150_MiB},
                                           {"same", 100_MiB},
                                           {"added", 150_MiB}}));
@@ -743,7 +741,7 @@ TEST_F(DynamicPartitionControlAndroidTest, SimulatedSecondUpdate) {
   ExpectStoreMetadata(update_sizes_2());
   ExpectUnmap({"grown_a", "shrunk_a", "same_a", "deleted_a"});
 
-  EXPECT_TRUE(PreparePartitionsForUpdate({{"grown", 4_GiB},
+  ASSERT_TRUE(PreparePartitionsForUpdate({{"grown", 4_GiB},
                                           {"shrunk", 100_MiB},
                                           {"same", 100_MiB},
                                           {"deleted", 64_MiB}}));
@@ -751,7 +749,7 @@ TEST_F(DynamicPartitionControlAndroidTest, SimulatedSecondUpdate) {
 
 TEST_F(DynamicPartitionControlAndroidTest, ApplyingToCurrentSlot) {
   SetSlots({1, 1});
-  EXPECT_FALSE(PreparePartitionsForUpdate({}))
+  ASSERT_FALSE(PreparePartitionsForUpdate({}))
       << "Should not be able to apply to current slot.";
 }
 
@@ -767,16 +765,16 @@ TEST_P(DynamicPartitionControlAndroidTestP, OptimizeOperationTest) {
 
   InstallOperation iop;
   InstallOperation optimized;
-  Extent *se, *de;
+  Extent *se{}, *de{};
 
   // Not a SOURCE_COPY operation, cannot skip.
   iop.set_type(InstallOperation::REPLACE);
-  EXPECT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
 
   iop.set_type(InstallOperation::SOURCE_COPY);
 
   // By default GetVirtualAbFeatureFlag is disabled. Cannot skip operation.
-  EXPECT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
 
   // Enable GetVirtualAbFeatureFlag in the mock interface.
   ON_CALL(dynamicControl(), GetVirtualAbFeatureFlag())
@@ -784,21 +782,21 @@ TEST_P(DynamicPartitionControlAndroidTestP, OptimizeOperationTest) {
 
   // By default target_supports_snapshot_ is set to false. Cannot skip
   // operation.
-  EXPECT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
 
   SetSnapshotEnabled(true);
 
   // Empty source and destination. Skip.
-  EXPECT_TRUE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
-  EXPECT_TRUE(optimized.src_extents().empty());
-  EXPECT_TRUE(optimized.dst_extents().empty());
+  ASSERT_TRUE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_TRUE(optimized.src_extents().empty());
+  ASSERT_TRUE(optimized.dst_extents().empty());
 
   se = iop.add_src_extents();
   se->set_start_block(0);
   se->set_num_blocks(1);
 
   // There is something in sources, but destinations are empty. Cannot skip.
-  EXPECT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
 
   InstallOperation iop2;
 
@@ -807,48 +805,48 @@ TEST_P(DynamicPartitionControlAndroidTestP, OptimizeOperationTest) {
   de->set_num_blocks(1);
 
   // There is something in destinations, but sources are empty. Cannot skip.
-  EXPECT_FALSE(dynamicControl().OptimizeOperation("foo", iop2, &optimized));
+  ASSERT_FALSE(dynamicControl().OptimizeOperation("foo", iop2, &optimized));
 
   de = iop.add_dst_extents();
   de->set_start_block(0);
   de->set_num_blocks(1);
 
   // Sources and destinations are identical. Skip.
-  EXPECT_TRUE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
-  EXPECT_TRUE(optimized.src_extents().empty());
-  EXPECT_TRUE(optimized.dst_extents().empty());
+  ASSERT_TRUE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_TRUE(optimized.src_extents().empty());
+  ASSERT_TRUE(optimized.dst_extents().empty());
 
   se = iop.add_src_extents();
   se->set_start_block(1);
   se->set_num_blocks(5);
 
   // There is something in source, but not in destination. Cannot skip.
-  EXPECT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
 
   de = iop.add_dst_extents();
   de->set_start_block(1);
   de->set_num_blocks(5);
 
   // There is source and destination are equal. Skip.
-  EXPECT_TRUE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
-  EXPECT_TRUE(optimized.src_extents().empty());
-  EXPECT_TRUE(optimized.dst_extents().empty());
+  ASSERT_TRUE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_TRUE(optimized.src_extents().empty());
+  ASSERT_TRUE(optimized.dst_extents().empty());
 
   de = iop.add_dst_extents();
   de->set_start_block(6);
   de->set_num_blocks(5);
 
   // There is something extra in dest. Cannot skip.
-  EXPECT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_FALSE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
 
   se = iop.add_src_extents();
   se->set_start_block(6);
   se->set_num_blocks(5);
 
   // Source and dest are identical again. Skip.
-  EXPECT_TRUE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
-  EXPECT_TRUE(optimized.src_extents().empty());
-  EXPECT_TRUE(optimized.dst_extents().empty());
+  ASSERT_TRUE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_TRUE(optimized.src_extents().empty());
+  ASSERT_TRUE(optimized.dst_extents().empty());
 
   iop.Clear();
   iop.set_type(InstallOperation::SOURCE_COPY);
@@ -866,20 +864,20 @@ TEST_P(DynamicPartitionControlAndroidTestP, OptimizeOperationTest) {
   de->set_num_blocks(5);
 
   // [1, 3, 4, 7, 8] -> [2, 3, 4, 5, 6] should return [1, 7, 8] -> [2, 5, 6]
-  EXPECT_TRUE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
+  ASSERT_TRUE(dynamicControl().OptimizeOperation("foo", iop, &optimized));
   ASSERT_EQ(2, optimized.src_extents_size());
   ASSERT_EQ(2, optimized.dst_extents_size());
-  EXPECT_EQ(1u, optimized.src_extents(0).start_block());
-  EXPECT_EQ(1u, optimized.src_extents(0).num_blocks());
-  EXPECT_EQ(2u, optimized.dst_extents(0).start_block());
-  EXPECT_EQ(1u, optimized.dst_extents(0).num_blocks());
-  EXPECT_EQ(7u, optimized.src_extents(1).start_block());
-  EXPECT_EQ(2u, optimized.src_extents(1).num_blocks());
-  EXPECT_EQ(5u, optimized.dst_extents(1).start_block());
-  EXPECT_EQ(2u, optimized.dst_extents(1).num_blocks());
+  ASSERT_EQ(1u, optimized.src_extents(0).start_block());
+  ASSERT_EQ(1u, optimized.src_extents(0).num_blocks());
+  ASSERT_EQ(2u, optimized.dst_extents(0).start_block());
+  ASSERT_EQ(1u, optimized.dst_extents(0).num_blocks());
+  ASSERT_EQ(7u, optimized.src_extents(1).start_block());
+  ASSERT_EQ(2u, optimized.src_extents(1).num_blocks());
+  ASSERT_EQ(5u, optimized.dst_extents(1).start_block());
+  ASSERT_EQ(2u, optimized.dst_extents(1).num_blocks());
 
   // Don't skip for static partitions.
-  EXPECT_FALSE(dynamicControl().OptimizeOperation("bar", iop, &optimized));
+  ASSERT_FALSE(dynamicControl().OptimizeOperation("bar", iop, &optimized));
 }
 
 TEST_F(DynamicPartitionControlAndroidTest, ResetUpdate) {
@@ -921,7 +919,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, AvbNotEnabledOnSystemOther) {
       }));
   ON_CALL(dynamicControl(), IsAvbEnabledOnSystemOther())
       .WillByDefault(Return(false));
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       dynamicControl().RealEraseSystemOtherAvbFooter(source(), target()));
 }
 
@@ -930,7 +928,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, NoSystemOtherToErase) {
   ON_CALL(dynamicControl(), IsAvbEnabledOnSystemOther())
       .WillByDefault(Return(true));
   std::string path;
-  bool should_unmap;
+  bool should_unmap{};
   ASSERT_TRUE(dynamicControl().RealGetSystemOtherPath(
       source(), target(), T("system"), &path, &should_unmap));
   ASSERT_TRUE(path.empty()) << path;
@@ -944,7 +942,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, NoSystemOtherToErase) {
         return dynamicControl().RealGetSystemOtherPath(
             source_slot, target_slot, name, path, should_unmap);
       }));
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       dynamicControl().RealEraseSystemOtherAvbFooter(source(), target()));
 }
 
@@ -954,7 +952,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, SkipEraseUpdatedSystemOther) {
   ON_CALL(dynamicControl(), IsAvbEnabledOnSystemOther())
       .WillByDefault(Return(true));
   std::string path;
-  bool should_unmap;
+  bool should_unmap{};
   ASSERT_TRUE(dynamicControl().RealGetSystemOtherPath(
       source(), target(), T("system"), &path, &should_unmap));
   ASSERT_TRUE(path.empty()) << path;
@@ -968,7 +966,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, SkipEraseUpdatedSystemOther) {
         return dynamicControl().RealGetSystemOtherPath(
             source_slot, target_slot, name, path, should_unmap);
       }));
-  EXPECT_TRUE(
+  ASSERT_TRUE(
       dynamicControl().RealEraseSystemOtherAvbFooter(source(), target()));
 }
 
@@ -1060,8 +1058,8 @@ TEST_P(SnapshotPartitionTestP, PreparePartitions) {
   ExpectCreateUpdateSnapshots(android::snapshot::Return::Ok());
   SetMetadata(source(), {});
   uint64_t required_size = 0;
-  EXPECT_TRUE(PreparePartitionsForUpdate(&required_size));
-  EXPECT_EQ(0u, required_size);
+  ASSERT_TRUE(PreparePartitionsForUpdate(&required_size));
+  ASSERT_EQ(0u, required_size);
 }
 
 // Test that if not enough space, required size returned by SnapshotManager is
@@ -1071,8 +1069,8 @@ TEST_P(SnapshotPartitionTestP, PreparePartitionsNoSpace) {
   uint64_t required_size = 0;
 
   SetMetadata(source(), {});
-  EXPECT_FALSE(PreparePartitionsForUpdate(&required_size));
-  EXPECT_EQ(1_GiB, required_size);
+  ASSERT_FALSE(PreparePartitionsForUpdate(&required_size));
+  ASSERT_EQ(1_GiB, required_size);
 }
 
 // Test that in recovery, use empty space in super partition for a snapshot
@@ -1089,8 +1087,8 @@ TEST_P(SnapshotPartitionTestP, RecoveryUseSuperEmpty) {
   EXPECT_CALL(dynamicControl(), PrepareDynamicPartitionsForUpdate(_, _, _, _))
       .Times(0);
   uint64_t required_size = 0;
-  EXPECT_TRUE(PreparePartitionsForUpdate(&required_size));
-  EXPECT_EQ(0u, required_size);
+  ASSERT_TRUE(PreparePartitionsForUpdate(&required_size));
+  ASSERT_EQ(0u, required_size);
 }
 
 // Test that in recovery, if CreateUpdateSnapshots throws an error, try
@@ -1125,12 +1123,32 @@ TEST_P(SnapshotPartitionTestP, RecoveryErrorShouldDeleteSource) {
   ExpectStoreMetadata({{T("system"), 3_GiB}, {T("vendor"), 1_GiB}});
 
   uint64_t required_size = 0;
-  EXPECT_TRUE(PreparePartitionsForUpdate(&required_size));
-  EXPECT_EQ(0u, required_size);
+  ASSERT_TRUE(PreparePartitionsForUpdate(&required_size));
+  ASSERT_EQ(0u, required_size);
 }
 
 INSTANTIATE_TEST_CASE_P(DynamicPartitionControlAndroidTest,
                         SnapshotPartitionTestP,
                         testing::Values(TestParam{0, 1}, TestParam{1, 0}));
 
+TEST(SourcePartitionTest, MapSourceWritable) {
+  BootControlAndroid boot_control;
+  ASSERT_TRUE(boot_control.Init());
+  auto source_slot = boot_control.GetCurrentSlot();
+  DynamicPartitionControlAndroid dynamic_control(source_slot);
+  std::string device;
+  ASSERT_TRUE(dynamic_control.GetPartitionDevice(
+      "system", source_slot, source_slot, &device));
+  android::base::unique_fd fd(open(device.c_str(), O_RDWR | O_CLOEXEC));
+  ASSERT_TRUE(utils::SetBlockDeviceReadOnly(device, false));
+  ASSERT_GE(fd, 0) << android::base::ErrnoNumberAsString(errno);
+  std::array<char, 512> block{};
+  ASSERT_EQ(pread(fd.get(), block.data(), block.size(), 0),
+            (ssize_t)block.size())
+      << android::base::ErrnoNumberAsString(errno);
+  ASSERT_EQ(pwrite(fd.get(), block.data(), block.size(), 0),
+            (ssize_t)block.size())
+      << android::base::ErrnoNumberAsString(errno);
+}
+
 }  // namespace chromeos_update_engine
diff --git a/aosp/dynamic_partition_test_utils.h b/aosp/dynamic_partition_test_utils.h
index c5183823..07bb3862 100644
--- a/aosp/dynamic_partition_test_utils.h
+++ b/aosp/dynamic_partition_test_utils.h
@@ -23,14 +23,13 @@
 #include <map>
 #include <memory>
 #include <string>
-#include <vector>
 
-#include <base/strings/string_util.h>
 #include <fs_mgr.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 #include <liblp/builder.h>
 #include <storage_literals/storage_literals.h>
+#include <android-base/strings.h>
 
 #include "update_engine/common/boot_control_interface.h"
 #include "update_engine/update_metadata.pb.h"
@@ -148,9 +147,7 @@ inline DeltaArchiveManifest PartitionSuffixSizesToManifest(
   }
   for (const auto& pair : partition_sizes) {
     for (size_t suffix_idx = 0; suffix_idx < kMaxNumSlots; ++suffix_idx) {
-      if (base::EndsWith(pair.first,
-                         kSlotSuffixes[suffix_idx],
-                         base::CompareCase::SENSITIVE)) {
+      if (android::base::EndsWith(pair.first, kSlotSuffixes[suffix_idx])) {
         AddPartition(
             &manifest,
             manifest.mutable_dynamic_partition_metadata()->mutable_groups(
diff --git a/aosp/dynamic_partition_utils.cc b/aosp/dynamic_partition_utils.cc
index 6b77a45c..b62b4359 100644
--- a/aosp/dynamic_partition_utils.cc
+++ b/aosp/dynamic_partition_utils.cc
@@ -18,8 +18,8 @@
 
 #include <vector>
 
+#include <android-base/strings.h>
 #include <base/logging.h>
-#include <base/strings/string_util.h>
 
 using android::fs_mgr::MetadataBuilder;
 
@@ -29,7 +29,7 @@ void DeleteGroupsWithSuffix(MetadataBuilder* builder,
                             const std::string& suffix) {
   std::vector<std::string> groups = builder->ListGroups();
   for (const auto& group_name : groups) {
-    if (base::EndsWith(group_name, suffix, base::CompareCase::SENSITIVE)) {
+    if (android::base::EndsWith(group_name, suffix)) {
       LOG(INFO) << "Removing group " << group_name;
       builder->RemoveGroupAndPartitions(group_name);
     }
diff --git a/aosp/hardware_android.cc b/aosp/hardware_android.cc
index f8732abd..dd39fdd8 100644
--- a/aosp/hardware_android.cc
+++ b/aosp/hardware_android.cc
@@ -26,7 +26,6 @@
 #include <android-base/properties.h>
 #include <base/files/file_util.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
 #include <bootloader_message/bootloader_message.h>
 #include <fstab/fstab.h>
 #include <libavb/libavb.h>
@@ -108,7 +107,7 @@ std::string CalculateVbmetaDigestForInactiveSlot() {
   const std::string encoded_digest =
       base::HexEncode(vbmeta_digest, AVB_SHA256_DIGEST_SIZE);
   LOG(INFO) << "vbmeta digest for target slot: " << encoded_digest;
-  return base::ToLowerASCII(encoded_digest);
+  return ToLower(encoded_digest);
 }
 
 }  // namespace
@@ -214,10 +213,8 @@ int HardwareAndroid::GetPowerwashCount() const {
   return 0;
 }
 
-bool HardwareAndroid::SchedulePowerwash(bool save_rollback_data) {
+bool HardwareAndroid::SchedulePowerwash() {
   LOG(INFO) << "Scheduling a powerwash to BCB.";
-  LOG_IF(WARNING, save_rollback_data) << "save_rollback_data was true but "
-                                      << "isn't supported.";
   string err;
   if (!update_bootloader_message({"--wipe_data", "--reason=wipe_data_from_ota"},
                                  &err)) {
diff --git a/aosp/hardware_android.h b/aosp/hardware_android.h
index d20e8df3..b071e060 100644
--- a/aosp/hardware_android.h
+++ b/aosp/hardware_android.h
@@ -18,13 +18,11 @@
 #define UPDATE_ENGINE_AOSP_HARDWARE_ANDROID_H_
 
 #include <string>
-#include <string_view>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <base/time/time.h>
 
 #include "update_engine/common/error_code.h"
-#include "update_engine/common/hardware.h"
 #include "update_engine/common/hardware_interface.h"
 
 namespace chromeos_update_engine {
@@ -49,7 +47,7 @@ class HardwareAndroid : public HardwareInterface {
   bool SetMaxFirmwareKeyRollforward(int firmware_max_rollforward) override;
   bool SetMaxKernelKeyRollforward(int kernel_max_rollforward) override;
   int GetPowerwashCount() const override;
-  bool SchedulePowerwash(bool save_rollback_data) override;
+  bool SchedulePowerwash() override;
   bool CancelPowerwash() override;
   bool GetNonVolatileDirectory(base::FilePath* path) const override;
   bool GetPowerwashSafeDirectory(base::FilePath* path) const override;
diff --git a/aosp/logging_android.cc b/aosp/logging_android.cc
index 1a0fa9a6..d4e20159 100644
--- a/aosp/logging_android.cc
+++ b/aosp/logging_android.cc
@@ -32,8 +32,7 @@
 #include <android-base/unique_fd.h>
 #include <base/files/dir_reader_posix.h>
 #include <base/logging.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <log/log.h>
 
 #include "android/log.h"
@@ -93,9 +92,10 @@ void DeleteOldLogs(const string& kLogsRoot) {
 string SetupLogFile(const string& kLogsRoot) {
   DeleteOldLogs(kLogsRoot);
 
-  return base::StringPrintf("%s/update_engine.%s",
-                            kLogsRoot.c_str(),
-                            utils::GetTimeAsString(::time(nullptr)).c_str());
+  return android::base::StringPrintf(
+      "%s/update_engine.%s",
+      kLogsRoot.c_str(),
+      utils::GetTimeAsString(::time(nullptr)).c_str());
 }
 
 const char* LogPriorityToCString(int priority) {
diff --git a/aosp/metrics_reporter_android.cc b/aosp/metrics_reporter_android.cc
index d9746163..6b832311 100644
--- a/aosp/metrics_reporter_android.cc
+++ b/aosp/metrics_reporter_android.cc
@@ -19,12 +19,11 @@
 #include <stdint.h>
 
 #include <algorithm>
-#include <any>
 #include <memory>
 #include <string>
 
 #include <android-base/properties.h>
-#include <base/strings/string_util.h>
+#include <android-base/strings.h>
 #include <fs_mgr.h>
 #include <libdm/dm.h>
 #include <liblp/builder.h>
@@ -34,12 +33,12 @@
 #include "update_engine/common/constants.h"
 #include "update_engine/payload_consumer/install_plan.h"
 
+using android::base::EndsWith;
 using android::fs_mgr::GetPartitionGroupName;
 using android::fs_mgr::LpMetadata;
 using android::fs_mgr::MetadataBuilder;
 using android::fs_mgr::ReadMetadata;
 using android::fs_mgr::SlotNumberForSlotSuffix;
-using base::EndsWith;
 
 namespace {
 // A number offset adds on top of the enum value. e.g. ErrorCode::SUCCESS will
@@ -104,9 +103,7 @@ void MetricsReporterAndroid::ReportUpdateAttemptMetrics(
       super_partition_size_bytes = GetTotalSuperPartitionSize(*metadata);
 
       for (const auto& group : metadata->groups) {
-        if (EndsWith(GetPartitionGroupName(group),
-                     fs_mgr_get_slot_suffix(),
-                     base::CompareCase::SENSITIVE)) {
+        if (EndsWith(GetPartitionGroupName(group), fs_mgr_get_slot_suffix())) {
           slot_size_bytes += group.maximum_size;
         }
       }
diff --git a/aosp/network_selector_android.h b/aosp/network_selector_android.h
index b79d1b36..2a3cb2ec 100644
--- a/aosp/network_selector_android.h
+++ b/aosp/network_selector_android.h
@@ -17,7 +17,7 @@
 #ifndef UPDATE_ENGINE_AOSP_NETWORK_SELECTOR_ANDROID_H_
 #define UPDATE_ENGINE_AOSP_NETWORK_SELECTOR_ANDROID_H_
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "update_engine/common/network_selector_interface.h"
 
diff --git a/aosp/ota_extractor.cc b/aosp/ota_extractor.cc
index 42270f4b..29ba44c1 100644
--- a/aosp/ota_extractor.cc
+++ b/aosp/ota_extractor.cc
@@ -206,6 +206,10 @@ bool ExtractImagesFromOTA(const DeltaArchiveManifest& manifest,
 
   if (FLAGS_single_thread) {
     for (const auto& partition : manifest.partitions()) {
+      if (!partitions.empty() &&
+          partitions.count(partition.partition_name()) == 0) {
+        continue;
+      }
       if (!ExtractImageFromPartition(manifest,
                                      partition,
                                      data_begin,
@@ -221,6 +225,10 @@ bool ExtractImagesFromOTA(const DeltaArchiveManifest& manifest,
   } else {
     std::vector<std::pair<std::future<bool>, std::string>> futures;
     for (const auto& partition : manifest.partitions()) {
+      if (!partitions.empty() &&
+          partitions.count(partition.partition_name()) == 0) {
+        continue;
+      }
       futures.push_back(std::make_pair(std::async(std::launch::async,
                                                   ExtractImageFromPartition,
                                                   manifest,
diff --git a/aosp/service_delegate_android_interface.h b/aosp/service_delegate_android_interface.h
index 45c0274c..c73c6de1 100644
--- a/aosp/service_delegate_android_interface.h
+++ b/aosp/service_delegate_android_interface.h
@@ -68,6 +68,9 @@ class ServiceDelegateAndroidInterface {
       const std::vector<std::string>& key_value_pair_headers,
       Error* error) = 0;
 
+  virtual bool TriggerPostinstall(const std::string& partition,
+                                  Error* error) = 0;
+
   // Suspend an ongoing update. Returns true if there was an update ongoing and
   // it was suspended. In case of failure, it returns false and sets |error|
   // accordingly.
diff --git a/aosp/sideload_main.cc b/aosp/sideload_main.cc
index bf015c94..4a92ca74 100644
--- a/aosp/sideload_main.cc
+++ b/aosp/sideload_main.cc
@@ -21,7 +21,7 @@
 
 #include <base/command_line.h>
 #include <base/strings/string_split.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <brillo/asynchronous_signal_handler.h>
 #include <brillo/flag_helper.h>
 #include <brillo/message_loops/base_message_loop.h>
@@ -73,12 +73,12 @@ class SideloadDaemonState : public DaemonStateInterface,
                               status == UpdateStatus::FINALIZING)) {
       // Split the progress bar in two parts for the two stages DOWNLOADING and
       // FINALIZING.
-      ReportStatus(base::StringPrintf(
+      ReportStatus(android::base::StringPrintf(
           "ui_print Step %d/2", status == UpdateStatus::DOWNLOADING ? 1 : 2));
-      ReportStatus(base::StringPrintf("progress 0.5 0"));
+      ReportStatus(android::base::StringPrintf("progress 0.5 0"));
     }
     if (status_ != status || fabs(progress - progress_) > 0.005) {
-      ReportStatus(base::StringPrintf("set_progress %.lf", progress));
+      ReportStatus(android::base::StringPrintf("set_progress %.lf", progress));
     }
     progress_ = progress;
     status_ = status;
@@ -86,10 +86,10 @@ class SideloadDaemonState : public DaemonStateInterface,
 
   void SendPayloadApplicationComplete(ErrorCode error_code) override {
     if (error_code != ErrorCode::kSuccess) {
-      ReportStatus(
-          base::StringPrintf("ui_print Error applying update: %d (%s)",
-                             error_code,
-                             utils::ErrorCodeToString(error_code).c_str()));
+      ReportStatus(android::base::StringPrintf(
+          "ui_print Error applying update: %d (%s)",
+          error_code,
+          utils::ErrorCodeToString(error_code).c_str()));
     }
     error_code_ = error_code;
     brillo::MessageLoop::current()->BreakLoop();
diff --git a/aosp/update_attempter_android.cc b/aosp/update_attempter_android.cc
index 857685f8..f29383a8 100644
--- a/aosp/update_attempter_android.cc
+++ b/aosp/update_attempter_android.cc
@@ -24,11 +24,11 @@
 #include <vector>
 
 #include <android-base/parsebool.h>
+#include <android-base/parseint.h>
 #include <android-base/properties.h>
 #include <android-base/unique_fd.h>
 #include <base/bind.h>
 #include <base/logging.h>
-#include <base/strings/string_number_conversions.h>
 #include <brillo/data_encoding.h>
 #include <brillo/message_loops/message_loop.h>
 #include <brillo/strings/string_utils.h>
@@ -113,7 +113,7 @@ bool LogAndSetError(Error* error,
 
 bool GetHeaderAsBool(const string& header, bool default_value) {
   int value = 0;
-  if (base::StringToInt(header, &value) && (value == 0 || value == 1))
+  if (android::base::ParseInt(header, &value) && (value == 0 || value == 1))
     return value == 1;
   return default_value;
 }
@@ -274,8 +274,8 @@ bool UpdateAttempterAndroid::ApplyPayload(
   InstallPlan::Payload payload;
   payload.size = payload_size;
   if (!payload.size) {
-    if (!base::StringToUint64(headers[kPayloadPropertyFileSize],
-                              &payload.size)) {
+    if (!android::base::ParseUint<uint64_t>(headers[kPayloadPropertyFileSize],
+                                            &payload.size)) {
       payload.size = 0;
     }
   }
@@ -284,8 +284,8 @@ bool UpdateAttempterAndroid::ApplyPayload(
     LOG(WARNING) << "Unable to decode base64 file hash: "
                  << headers[kPayloadPropertyFileHash];
   }
-  if (!base::StringToUint64(headers[kPayloadPropertyMetadataSize],
-                            &payload.metadata_size)) {
+  if (!android::base::ParseUint<uint64_t>(headers[kPayloadPropertyMetadataSize],
+                                          &payload.metadata_size)) {
     payload.metadata_size = 0;
   }
   // The |payload.type| is not used anymore since minor_version 3.
@@ -340,8 +340,8 @@ bool UpdateAttempterAndroid::ApplyPayload(
 
   NetworkId network_id = kDefaultNetworkId;
   if (!headers[kPayloadPropertyNetworkId].empty()) {
-    if (!base::StringToUint64(headers[kPayloadPropertyNetworkId],
-                              &network_id)) {
+    if (!android::base::ParseUint<uint64_t>(headers[kPayloadPropertyNetworkId],
+                                            &network_id)) {
       return LogAndSetGenericError(
           error,
           __LINE__,
@@ -711,7 +711,6 @@ void UpdateAttempterAndroid::ProcessingDone(const ActionProcessor* processor,
   LOG(INFO) << "Processing Done.";
   metric_bytes_downloaded_.Flush(true);
   metric_total_bytes_downloaded_.Flush(true);
-  last_error_ = code;
   if (status_ == UpdateStatus::CLEANUP_PREVIOUS_UPDATE) {
     TerminateUpdateAndNotify(code);
     return;
@@ -1339,6 +1338,9 @@ bool UpdateAttempterAndroid::setShouldSwitchSlotOnReboot(
   // Don't run postinstall, we just need PostinstallAction to switch the slots.
   install_plan_.run_post_install = false;
   install_plan_.is_resume = true;
+  // previous ApplyPayload() call may have requested powerwash, these
+  // settings would be saved in `this->install_plan_`. Inherit that setting.
+  install_plan_.powerwash_required = this->install_plan_.powerwash_required;
 
   CHECK_NE(install_plan_.source_slot, UINT32_MAX);
   CHECK_NE(install_plan_.target_slot, UINT32_MAX);
@@ -1347,11 +1349,13 @@ bool UpdateAttempterAndroid::setShouldSwitchSlotOnReboot(
       std::make_unique<PostinstallRunnerAction>(boot_control_, hardware_);
   postinstall_runner_action->set_delegate(this);
 
-  // If last error code is kUpdatedButNotActive, we know that we reached this
-  // state by calling applyPayload() with switch_slot=false. That applyPayload()
-  // call would have already performed filesystem verification, therefore, we
+  // If |kPrefsPostInstallSucceeded| is set, we know that we reached this
+  // state by calling applyPayload() That applyPayload() call would have
+  // already performed filesystem verification, therefore, we
   // can safely skip the verification to save time.
-  if (last_error_ == ErrorCode::kUpdatedButNotActive) {
+  bool postinstall_succeeded = false;
+  if (prefs_->GetBoolean(kPrefsPostInstallSucceeded, &postinstall_succeeded) &&
+      postinstall_succeeded) {
     auto install_plan_action =
         std::make_unique<InstallPlanAction>(install_plan_);
     BondActions(install_plan_action.get(), postinstall_runner_action.get());
@@ -1450,6 +1454,18 @@ void UpdateAttempterAndroid::ScheduleCleanupPreviousUpdate() {
   processor_->StartProcessing();
 }
 
+bool UpdateAttempterAndroid::TriggerPostinstall(const std::string& partition,
+                                                Error* error) {
+  if (error) {
+    return LogAndSetGenericError(
+        error,
+        __LINE__,
+        __FILE__,
+        __FUNCTION__ + std::string(" is not implemented"));
+  }
+  return false;
+}
+
 void UpdateAttempterAndroid::OnCleanupProgressUpdate(double progress) {
   for (auto&& callback : cleanup_previous_update_callbacks_) {
     callback->OnCleanupProgressUpdate(progress);
diff --git a/aosp/update_attempter_android.h b/aosp/update_attempter_android.h
index b7851f19..ac0cc518 100644
--- a/aosp/update_attempter_android.h
+++ b/aosp/update_attempter_android.h
@@ -52,7 +52,7 @@ enum class OTAResult {
   OTA_SUCCESSFUL,
 };
 
-class UpdateAttempterAndroid
+class UpdateAttempterAndroid final
     : public ServiceDelegateAndroidInterface,
       public ActionProcessorDelegate,
       public DownloadActionDelegate,
@@ -99,6 +99,7 @@ class UpdateAttempterAndroid
   bool setShouldSwitchSlotOnReboot(const std::string& metadata_filename,
                                    Error* error) override;
   bool resetShouldSwitchSlotOnReboot(Error* error) override;
+  bool TriggerPostinstall(const std::string& partition, Error* error) override;
 
   // ActionProcessorDelegate methods:
   void ProcessingDone(const ActionProcessor* processor,
@@ -286,7 +287,6 @@ class UpdateAttempterAndroid
 
   // The path to the zip file with X509 certificates.
   std::string update_certificates_path_{constants::kUpdateCertificatesPath};
-  ErrorCode last_error_{ErrorCode::kSuccess};
 
   metrics_utils::PersistedValue<int64_t> metric_bytes_downloaded_;
   metrics_utils::PersistedValue<int64_t> metric_total_bytes_downloaded_;
diff --git a/aosp/update_engine_client_android.cc b/aosp/update_engine_client_android.cc
index 4f42a59a..4d01ea67 100644
--- a/aosp/update_engine_client_android.cc
+++ b/aosp/update_engine_client_android.cc
@@ -157,6 +157,11 @@ int UpdateEngineClientAndroid::OnInit() {
                 "Perform just the slow switching part of OTA. "
                 "Used to revert a slot switch or re-do slot switch. Valid "
                 "values are 'true' and 'false'");
+  DEFINE_string(
+      trigger_postinstall,
+      UNSPECIFIED_FLAG,
+      "Only run postinstall sciprts. And only run postinstall script for the "
+      "specified partition. Example: \"system\", \"product\"");
   DEFINE_bool(suspend, false, "Suspend an ongoing update and exit.");
   DEFINE_bool(resume, false, "Resume a suspended update.");
   DEFINE_bool(cancel, false, "Cancel the ongoing update and exit.");
@@ -231,6 +236,11 @@ int UpdateEngineClientAndroid::OnInit() {
     return ExitWhenIdle(service_->resetStatus());
   }
 
+  if (FLAGS_trigger_postinstall != UNSPECIFIED_FLAG) {
+    return ExitWhenIdle(service_->triggerPostinstall(
+        android::String16(FLAGS_trigger_postinstall.c_str())));
+  }
+
   if (FLAGS_switch_slot != UNSPECIFIED_FLAG) {
     if (FLAGS_switch_slot != "true" && FLAGS_switch_slot != "false") {
       LOG(ERROR) << "--switch_slot should be either true or false, got "
diff --git a/binder_bindings/android/os/IUpdateEngine.aidl b/binder_bindings/android/os/IUpdateEngine.aidl
index 4043b1a5..7291391f 100644
--- a/binder_bindings/android/os/IUpdateEngine.aidl
+++ b/binder_bindings/android/os/IUpdateEngine.aidl
@@ -76,4 +76,23 @@ interface IUpdateEngine {
    * but needs reboot). DEVICE_CORRUPTED for permanent errors.
    */
   void cleanupSuccessfulUpdate(IUpdateEngineCallback callback);
+  /**
+   * Run postinstall scripts for the given |partition|
+   * This allows developers to run postinstall for a partition at
+   * a time they see fit. For example, they may wish to run postinstall
+   * script when device is IDLE and charging. This method would return
+   * immediately if |partition| is empty or does not correspond to any
+   * partitions on device. |partition| is expected to be unsuffixed, for
+   * example system,product,system_ext, etc.
+   * It is allowed to call this function multiple times with the same
+   * partition. Postinstall script for that partition would get run more
+   * than once. Owners of postinstall scripts should be designed to work
+   * correctly in such cases(idempotent). Note this expectation holds even
+   * without this API, and it has been so for years.
+   * @param Name of thje partition to run postinstall scripts. Should not
+   * contain slot suffix.(e.g. system,product,system_ext)
+   *
+   * @hide
+   */
+  void triggerPostinstall(in String partition);
 }
diff --git a/certificate_checker.cc b/certificate_checker.cc
index 938c66fd..8ffa596b 100644
--- a/certificate_checker.cc
+++ b/certificate_checker.cc
@@ -20,8 +20,7 @@
 
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <curl/curl.h>
 #include <openssl/evp.h>
 #include <openssl/ssl.h>
@@ -160,10 +159,11 @@ bool CertificateChecker::CheckCertificateChange(int preverify_ok,
   // prefs.
   string digest_string = base::HexEncode(digest, digest_length);
 
-  string storage_key = base::StringPrintf("%s-%d-%d",
-                                          kPrefsUpdateServerCertificate,
-                                          static_cast<int>(server_to_check),
-                                          depth);
+  string storage_key =
+      android::base::StringPrintf("%s-%d-%d",
+                                  kPrefsUpdateServerCertificate,
+                                  static_cast<int>(server_to_check),
+                                  depth);
   string stored_digest;
   // If there's no stored certificate, we just store the current one and return.
   if (!prefs_->GetString(storage_key, &stored_digest)) {
diff --git a/certificate_checker.h b/certificate_checker.h
index 5d0b5ba3..0dc61b2c 100644
--- a/certificate_checker.h
+++ b/certificate_checker.h
@@ -22,7 +22,7 @@
 
 #include <string>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <gtest/gtest_prod.h>  // for FRIEND_TEST
 
 namespace chromeos_update_engine {
diff --git a/certificate_checker_unittest.cc b/certificate_checker_unittest.cc
index 15d65552..62b2152b 100644
--- a/certificate_checker_unittest.cc
+++ b/certificate_checker_unittest.cc
@@ -18,8 +18,7 @@
 
 #include <string>
 
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 
@@ -46,10 +45,10 @@ class MockCertificateCheckObserver : public CertificateChecker::Observer {
 class CertificateCheckerTest : public testing::Test {
  protected:
   void SetUp() override {
-    cert_key_ = base::StringPrintf("%s-%d-%d",
-                                   cert_key_prefix_.c_str(),
-                                   static_cast<int>(server_to_check_),
-                                   depth_);
+    cert_key_ = android::base::StringPrintf("%s-%d-%d",
+                                            cert_key_prefix_.c_str(),
+                                            static_cast<int>(server_to_check_),
+                                            depth_);
     cert_checker.Init();
     cert_checker.SetObserver(&observer_);
   }
diff --git a/common/action.h b/common/action.h
index d32322c3..e9b5bd47 100644
--- a/common/action.h
+++ b/common/action.h
@@ -23,7 +23,7 @@
 #include <string>
 
 #include <base/logging.h>
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "update_engine/common/action_pipe.h"
 #include "update_engine/common/action_processor.h"
diff --git a/common/action_pipe.h b/common/action_pipe.h
index 4c568126..f1498b16 100644
--- a/common/action_pipe.h
+++ b/common/action_pipe.h
@@ -24,7 +24,7 @@
 #include <string>
 
 #include <base/logging.h>
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 // The structure of these classes (Action, ActionPipe, ActionProcessor, etc.)
 // is based on the KSAction* classes from the Google Update Engine code at
diff --git a/common/action_processor.h b/common/action_processor.h
index 5a4286fd..ee7e51cc 100644
--- a/common/action_processor.h
+++ b/common/action_processor.h
@@ -21,7 +21,7 @@
 #include <memory>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "update_engine/common/error_code.h"
 
diff --git a/common/boot_control_interface.h b/common/boot_control_interface.h
index 2de21a16..045236a7 100644
--- a/common/boot_control_interface.h
+++ b/common/boot_control_interface.h
@@ -23,7 +23,7 @@
 #include <vector>
 
 #include <base/callback.h>
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "update_engine/common/dynamic_partition_control_interface.h"
 #include "update_engine/update_metadata.pb.h"
diff --git a/common/cpu_limiter.cc b/common/cpu_limiter.cc
index 5f1ae6f0..32263900 100644
--- a/common/cpu_limiter.cc
+++ b/common/cpu_limiter.cc
@@ -20,7 +20,6 @@
 
 #include <base/bind.h>
 #include <base/logging.h>
-#include <base/strings/string_number_conversions.h>
 #include <base/time/time.h>
 
 #include "update_engine/common/utils.h"
@@ -67,7 +66,7 @@ bool CPULimiter::SetCpuShares(CpuShares shares) {
   if (shares_ == shares)
     return true;
 
-  std::string string_shares = base::NumberToString(static_cast<int>(shares));
+  std::string string_shares = std::format("{}", static_cast<int>(shares));
   LOG(INFO) << "Setting cgroup cpu shares to  " << string_shares;
   if (!utils::WriteFile(
           kCGroupSharesPath, string_shares.c_str(), string_shares.size())) {
diff --git a/common/dlcservice_interface.h b/common/dlcservice_interface.h
index 7b577104..a075092d 100644
--- a/common/dlcservice_interface.h
+++ b/common/dlcservice_interface.h
@@ -21,7 +21,7 @@
 #include <string>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 namespace chromeos_update_engine {
 
diff --git a/common/error_code_utils.cc b/common/error_code_utils.cc
index 421e1249..dc2d7cb0 100644
--- a/common/error_code_utils.cc
+++ b/common/error_code_utils.cc
@@ -16,8 +16,6 @@
 
 #include "update_engine/common/error_code_utils.h"
 
-#include <base/strings/string_number_conversions.h>
-
 using std::string;
 
 namespace chromeos_update_engine {
@@ -185,7 +183,7 @@ string ErrorCodeToString(ErrorCode code) {
       // error codes which should be added here.
   }
 
-  return "Unknown error: " + base::NumberToString(static_cast<unsigned>(code));
+  return "Unknown error: " + std::format("{}", static_cast<unsigned>(code));
 }
 
 }  // namespace utils
diff --git a/common/excluder_interface.h b/common/excluder_interface.h
index 1dfd227c..81a0c378 100644
--- a/common/excluder_interface.h
+++ b/common/excluder_interface.h
@@ -20,7 +20,7 @@
 #include <memory>
 #include <string>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 namespace chromeos_update_engine {
 
diff --git a/common/fake_hardware.h b/common/fake_hardware.h
index 6c25183a..3b68958c 100644
--- a/common/fake_hardware.h
+++ b/common/fake_hardware.h
@@ -107,15 +107,13 @@ class FakeHardware : public HardwareInterface {
 
   int GetPowerwashCount() const override { return powerwash_count_; }
 
-  bool SchedulePowerwash(bool save_rollback_data) override {
+  bool SchedulePowerwash() override {
     powerwash_scheduled_ = true;
-    save_rollback_data_ = save_rollback_data;
     return true;
   }
 
   bool CancelPowerwash() override {
     powerwash_scheduled_ = false;
-    save_rollback_data_ = false;
     return true;
   }
 
diff --git a/common/fake_prefs.h b/common/fake_prefs.h
index 721cf246..c87c57c9 100644
--- a/common/fake_prefs.h
+++ b/common/fake_prefs.h
@@ -23,7 +23,7 @@
 #include <string_view>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "update_engine/common/prefs_interface.h"
 
diff --git a/common/file_fetcher.cc b/common/file_fetcher.cc
index 7134fd69..cb8e89a4 100644
--- a/common/file_fetcher.cc
+++ b/common/file_fetcher.cc
@@ -23,12 +23,10 @@
 #include <base/format_macros.h>
 #include <base/location.h>
 #include <base/logging.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <brillo/streams/file_stream.h>
 
-#include "update_engine/common/hardware_interface.h"
-#include "update_engine/common/platform_constants.h"
+#include "update_engine/common/utils.h"
 
 using std::string;
 
@@ -43,9 +41,8 @@ namespace chromeos_update_engine {
 // static
 bool FileFetcher::SupportedUrl(const string& url) {
   // Note that we require the file path to start with a "/".
-  return (
-      base::StartsWith(url, "file:///", base::CompareCase::INSENSITIVE_ASCII) ||
-      base::StartsWith(url, "fd://", base::CompareCase::INSENSITIVE_ASCII));
+  return (android::base::StartsWith(ToLower(url), "file:///") ||
+          android::base::StartsWith(ToLower(url), "fd://"));
 }
 
 FileFetcher::~FileFetcher() {
@@ -70,7 +67,7 @@ void FileFetcher::BeginTransfer(const string& url) {
 
   string file_path;
 
-  if (base::StartsWith(url, "fd://", base::CompareCase::INSENSITIVE_ASCII)) {
+  if (android::base::StartsWith(ToLower(url), "fd://")) {
     int fd = std::stoi(url.substr(strlen("fd://")));
     file_path = url;
     stream_ = brillo::FileStream::FromFileDescriptor(fd, false, nullptr);
diff --git a/common/file_fetcher.h b/common/file_fetcher.h
index cc0e8806..997d4874 100644
--- a/common/file_fetcher.h
+++ b/common/file_fetcher.h
@@ -22,7 +22,7 @@
 #include <utility>
 
 #include <base/logging.h>
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <brillo/streams/stream.h>
 
 #include "update_engine/common/http_fetcher.h"
diff --git a/common/hardware_interface.h b/common/hardware_interface.h
index 4e820f1a..1b146d1b 100644
--- a/common/hardware_interface.h
+++ b/common/hardware_interface.h
@@ -100,9 +100,8 @@ class HardwareInterface {
   virtual int GetPowerwashCount() const = 0;
 
   // Signals that a powerwash (stateful partition wipe) should be performed
-  // after reboot. If |save_rollback_data| is true additional state is
-  // preserved during shutdown that can be restored after the powerwash.
-  virtual bool SchedulePowerwash(bool save_rollback_data) = 0;
+  // after reboot.
+  virtual bool SchedulePowerwash() = 0;
 
   // Cancel the powerwash operation scheduled to be performed on next boot.
   virtual bool CancelPowerwash() = 0;
diff --git a/common/hash_calculator.h b/common/hash_calculator.h
index 36bfcc8b..e0a08e35 100644
--- a/common/hash_calculator.h
+++ b/common/hash_calculator.h
@@ -24,7 +24,7 @@
 #include <vector>
 
 #include <base/logging.h>
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <brillo/secure_blob.h>
 
 // This class provides a simple wrapper around OpenSSL providing a hash of data
diff --git a/common/http_common.cc b/common/http_common.cc
index c8bac477..f05c5943 100644
--- a/common/http_common.cc
+++ b/common/http_common.cc
@@ -20,7 +20,7 @@
 
 #include <cstdlib>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <base/stl_util.h>
 
 namespace chromeos_update_engine {
diff --git a/common/http_fetcher.h b/common/http_fetcher.h
index f32c01d9..58ee99e1 100644
--- a/common/http_fetcher.h
+++ b/common/http_fetcher.h
@@ -24,7 +24,7 @@
 
 #include <base/callback.h>
 #include <base/logging.h>
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <brillo/message_loops/message_loop.h>
 #include <brillo/secure_blob.h>
 
@@ -47,7 +47,7 @@ class HttpFetcher {
   // |proxy_resolver| is the resolver that will be consulted for proxy
   // settings. It may be null, in which case direct connections will
   // be used. Does not take ownership of the resolver.
-  explicit HttpFetcher()
+  HttpFetcher()
       : post_data_set_(false),
         http_response_code_(0),
         delegate_(nullptr),
diff --git a/common/http_fetcher_unittest.cc b/common/http_fetcher_unittest.cc
index b2296602..7821f4c4 100644
--- a/common/http_fetcher_unittest.cc
+++ b/common/http_fetcher_unittest.cc
@@ -26,6 +26,7 @@
 #include <utility>
 #include <vector>
 
+#include <android-base/stringprintf.h>
 #include <base/bind.h>
 #include <base/location.h>
 #include <base/logging.h>
@@ -34,8 +35,7 @@
 #endif  // BASE_VER < 780000
 #include <base/stl_util.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #if BASE_VER >= 780000  // CrOS
 #include <base/task/single_thread_task_executor.h>
 #endif  // BASE_VER >= 780000
@@ -88,8 +88,8 @@ namespace chromeos_update_engine {
 static const char* kUnusedUrl = "unused://unused";
 
 static inline string LocalServerUrlForPath(in_port_t port, const string& path) {
-  string port_str = (port ? base::StringPrintf(":%hu", port) : "");
-  return base::StringPrintf(
+  string port_str = (port ? android::base::StringPrintf(":%hu", port) : "");
+  return android::base::StringPrintf(
       "http://127.0.0.1%s%s", port_str.c_str(), path.c_str());
 }
 
@@ -272,7 +272,7 @@ class LibcurlHttpFetcherFactory : public AnyHttpFetcherFactory {
 
   string BigUrl(in_port_t port) const override {
     return LocalServerUrlForPath(
-        port, base::StringPrintf("/download/%d", kBigLength));
+        port, android::base::StringPrintf("/download/%d", kBigLength));
   }
   string SmallUrl(in_port_t port) const override {
     return LocalServerUrlForPath(port, "/foo");
@@ -768,16 +768,17 @@ TYPED_TEST(HttpFetcherTest, FlakyTest) {
     unique_ptr<HttpServer> server(this->test_.CreateServer());
     ASSERT_TRUE(server->started_);
 
-    this->loop_.PostTask(FROM_HERE,
-                         base::Bind(&StartTransfer,
-                                    fetcher.get(),
-                                    LocalServerUrlForPath(
-                                        server->GetPort(),
-                                        base::StringPrintf("/flaky/%d/%d/%d/%d",
-                                                           kBigLength,
-                                                           kFlakyTruncateLength,
-                                                           kFlakySleepEvery,
-                                                           kFlakySleepSecs))));
+    this->loop_.PostTask(
+        FROM_HERE,
+        base::Bind(&StartTransfer,
+                   fetcher.get(),
+                   LocalServerUrlForPath(
+                       server->GetPort(),
+                       android::base::StringPrintf("/flaky/%d/%d/%d/%d",
+                                                   kBigLength,
+                                                   kFlakyTruncateLength,
+                                                   kFlakySleepEvery,
+                                                   kFlakySleepSecs))));
     this->loop_.Run();
 
     // verify the data we get back
@@ -908,12 +909,13 @@ TYPED_TEST(HttpFetcherTest, ServerDiesTest) {
       FROM_HERE,
       base::Bind(StartTransfer,
                  fetcher.get(),
-                 LocalServerUrlForPath(port,
-                                       base::StringPrintf("/flaky/%d/%d/%d/%d",
-                                                          kBigLength,
-                                                          kFlakyTruncateLength,
-                                                          kFlakySleepEvery,
-                                                          kFlakySleepSecs))));
+                 LocalServerUrlForPath(
+                     port,
+                     android::base::StringPrintf("/flaky/%d/%d/%d/%d",
+                                                 kBigLength,
+                                                 kFlakyTruncateLength,
+                                                 kFlakySleepEvery,
+                                                 kFlakySleepSecs))));
   this->loop_.Run();
   EXPECT_EQ(1, delegate.times_transfer_complete_called_);
   EXPECT_EQ(0, delegate.times_transfer_terminated_called_);
@@ -940,12 +942,13 @@ TYPED_TEST(HttpFetcherTest, TerminateTransferWhenServerDiedTest) {
       FROM_HERE,
       base::Bind(StartTransfer,
                  fetcher.get(),
-                 LocalServerUrlForPath(port,
-                                       base::StringPrintf("/flaky/%d/%d/%d/%d",
-                                                          kBigLength,
-                                                          kFlakyTruncateLength,
-                                                          kFlakySleepEvery,
-                                                          kFlakySleepSecs))));
+                 LocalServerUrlForPath(
+                     port,
+                     android::base::StringPrintf("/flaky/%d/%d/%d/%d",
+                                                 kBigLength,
+                                                 kFlakyTruncateLength,
+                                                 kFlakySleepEvery,
+                                                 kFlakySleepSecs))));
   // Terminating the transfer after 3 seconds gives it a chance to contact the
   // server and enter the retry loop.
   this->loop_.PostDelayedTask(FROM_HERE,
@@ -1032,7 +1035,7 @@ TYPED_TEST(HttpFetcherTest, SimpleRedirectTest) {
   ASSERT_TRUE(server->started_);
 
   for (size_t c = 0; c < base::size(kRedirectCodes); ++c) {
-    const string url = base::StringPrintf(
+    const string url = android::base::StringPrintf(
         "/redirect/%d/download/%d", kRedirectCodes[c], kMediumLength);
     RedirectTest(server.get(), true, url, this->test_.NewLargeFetcher());
   }
@@ -1047,10 +1050,10 @@ TYPED_TEST(HttpFetcherTest, MaxRedirectTest) {
 
   string url;
   for (int r = 0; r < kDownloadMaxRedirects; r++) {
-    url += base::StringPrintf("/redirect/%d",
-                              kRedirectCodes[r % base::size(kRedirectCodes)]);
+    url += android::base::StringPrintf(
+        "/redirect/%d", kRedirectCodes[r % base::size(kRedirectCodes)]);
   }
-  url += base::StringPrintf("/download/%d", kMediumLength);
+  url += android::base::StringPrintf("/download/%d", kMediumLength);
   RedirectTest(server.get(), true, url, this->test_.NewLargeFetcher());
 }
 
@@ -1063,10 +1066,10 @@ TYPED_TEST(HttpFetcherTest, BeyondMaxRedirectTest) {
 
   string url;
   for (int r = 0; r < kDownloadMaxRedirects + 1; r++) {
-    url += base::StringPrintf("/redirect/%d",
-                              kRedirectCodes[r % base::size(kRedirectCodes)]);
+    url += android::base::StringPrintf(
+        "/redirect/%d", kRedirectCodes[r % base::size(kRedirectCodes)]);
   }
-  url += base::StringPrintf("/download/%d", kMediumLength);
+  url += android::base::StringPrintf("/download/%d", kMediumLength);
   RedirectTest(server.get(), false, url, this->test_.NewLargeFetcher());
 }
 
@@ -1118,12 +1121,12 @@ void MultiTest(HttpFetcher* fetcher_in,
                                                   e = ranges.end();
        it != e;
        ++it) {
-    string tmp_str = base::StringPrintf("%jd+", it->first);
+    string tmp_str = android::base::StringPrintf("%jd+", it->first);
     if (it->second > 0) {
-      base::StringAppendF(&tmp_str, "%jd", it->second);
+      android::base::StringAppendF(&tmp_str, "%jd", it->second);
       multi_fetcher->AddRange(it->first, it->second);
     } else {
-      base::StringAppendF(&tmp_str, "?");
+      android::base::StringAppendF(&tmp_str, "?");
       multi_fetcher->AddRange(it->first);
     }
     LOG(INFO) << "added range: " << tmp_str;
@@ -1256,9 +1259,9 @@ TYPED_TEST(HttpFetcherTest, MultiHttpFetcherErrorIfOffsetRecoverableTest) {
   ranges.push_back(make_pair(99, 0));
   MultiTest(this->test_.NewLargeFetcher(3),
             this->test_.fake_hardware(),
-            LocalServerUrlForPath(
-                server->GetPort(),
-                base::StringPrintf("/error-if-offset/%d/2", kBigLength)),
+            LocalServerUrlForPath(server->GetPort(),
+                                  android::base::StringPrintf(
+                                      "/error-if-offset/%d/2", kBigLength)),
             ranges,
             "abcdefghijabcdefghijabcdejabcdefghijabcdef",
             kBigLength - (99 - 25),
@@ -1279,9 +1282,9 @@ TYPED_TEST(HttpFetcherTest, MultiHttpFetcherErrorIfOffsetUnrecoverableTest) {
   ranges.push_back(make_pair(99, 0));
   MultiTest(this->test_.NewLargeFetcher(),
             this->test_.fake_hardware(),
-            LocalServerUrlForPath(
-                server->GetPort(),
-                base::StringPrintf("/error-if-offset/%d/3", kBigLength)),
+            LocalServerUrlForPath(server->GetPort(),
+                                  android::base::StringPrintf(
+                                      "/error-if-offset/%d/3", kBigLength)),
             ranges,
             "abcdefghijabcdefghijabcde",  // only received the first chunk
             25,
diff --git a/common/hwid_override.h b/common/hwid_override.h
index d39b5726..438993a4 100644
--- a/common/hwid_override.h
+++ b/common/hwid_override.h
@@ -21,7 +21,7 @@
 #include <string>
 
 #include <base/files/file_path.h>
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 namespace chromeos_update_engine {
 
diff --git a/common/mock_http_fetcher.cc b/common/mock_http_fetcher.cc
index 1b3cd7d7..668d249a 100644
--- a/common/mock_http_fetcher.cc
+++ b/common/mock_http_fetcher.cc
@@ -20,11 +20,12 @@
 
 #include <base/bind.h>
 #include <base/logging.h>
-#include <base/strings/string_util.h>
 #include <base/time/time.h>
 #include <brillo/message_loops/message_loop.h>
 #include <gtest/gtest.h>
 
+#include "update_engine/common/utils.h"
+
 // This is a mock implementation of HttpFetcher which is useful for testing.
 
 using brillo::MessageLoop;
@@ -107,11 +108,11 @@ void MockHttpFetcher::TerminateTransfer() {
 
 void MockHttpFetcher::SetHeader(const std::string& header_name,
                                 const std::string& header_value) {
-  extra_headers_[base::ToLowerASCII(header_name)] = header_value;
+  extra_headers_[ToLower(header_name)] = header_value;
 }
 
 std::string MockHttpFetcher::GetHeader(const std::string& header_name) const {
-  const auto it = extra_headers_.find(base::ToLowerASCII(header_name));
+  const auto it = extra_headers_.find(ToLower(header_name));
   if (it == extra_headers_.end())
     return "";
   return it->second;
diff --git a/common/multi_range_http_fetcher.cc b/common/multi_range_http_fetcher.cc
index b5bf923d..a7d339b5 100644
--- a/common/multi_range_http_fetcher.cc
+++ b/common/multi_range_http_fetcher.cc
@@ -16,7 +16,7 @@
 
 #include "update_engine/common/multi_range_http_fetcher.h"
 
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
 #include <algorithm>
 #include <string>
@@ -183,7 +183,7 @@ void MultiRangeHttpFetcher::Reset() {
 }
 
 std::string MultiRangeHttpFetcher::Range::ToString() const {
-  std::string range_str = base::StringPrintf("%jd+", offset());
+  std::string range_str = android::base::StringPrintf("%jd+", offset());
   if (HasLength())
     range_str += std::to_string(length());
   else
diff --git a/common/network_selector_stub.h b/common/network_selector_stub.h
index b32df919..668a66cd 100644
--- a/common/network_selector_stub.h
+++ b/common/network_selector_stub.h
@@ -17,7 +17,7 @@
 #ifndef UPDATE_ENGINE_COMMON_NETWORK_SELECTOR_STUB_H_
 #define UPDATE_ENGINE_COMMON_NETWORK_SELECTOR_STUB_H_
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "update_engine/common/network_selector_interface.h"
 
diff --git a/common/prefs.cc b/common/prefs.cc
index 77078cf0..3d692386 100644
--- a/common/prefs.cc
+++ b/common/prefs.cc
@@ -21,13 +21,13 @@
 #include <unistd.h>
 
 #include <android-base/file.h>
+#include <android-base/parseint.h>
 #include <base/files/file_enumerator.h>
 #include <base/files/file_util.h>
 #include <base/logging.h>
-#include <base/strings/string_number_conversions.h>
 #include <base/strings/string_split.h>
-#include <base/strings/string_util.h>
 
+#include "android-base/strings.h"
 #include "update_engine/common/utils.h"
 
 using std::string;
@@ -73,13 +73,13 @@ bool PrefsBase::GetInt64(const std::string_view key, int64_t* value) const {
   string str_value;
   if (!GetString(key, &str_value))
     return false;
-  base::TrimWhitespaceASCII(str_value, base::TRIM_ALL, &str_value);
+  str_value = android::base::Trim(str_value);
   if (str_value.empty()) {
     LOG(ERROR) << "When reading pref " << key
                << ", got an empty value after trim";
     return false;
   }
-  if (!base::StringToInt64(str_value, value)) {
+  if (!android::base::ParseInt<int64_t>(str_value, value)) {
     LOG(ERROR) << "When reading pref " << key << ", failed to convert value "
                << str_value << " to integer";
     return false;
@@ -88,14 +88,14 @@ bool PrefsBase::GetInt64(const std::string_view key, int64_t* value) const {
 }
 
 bool PrefsBase::SetInt64(std::string_view key, const int64_t value) {
-  return SetString(key, base::NumberToString(value));
+  return SetString(key, std::format("{}", value));
 }
 
 bool PrefsBase::GetBoolean(std::string_view key, bool* value) const {
   string str_value;
   if (!GetString(key, &str_value))
     return false;
-  base::TrimWhitespaceASCII(str_value, base::TRIM_ALL, &str_value);
+  str_value = android::base::Trim(str_value);
   if (str_value == "false") {
     *value = false;
     return true;
@@ -163,7 +163,7 @@ void PrefsBase::RemoveObserver(std::string_view key,
 }
 
 string PrefsInterface::CreateSubKey(const vector<string>& ns_and_key) {
-  return base::JoinString(ns_and_key, string(1, kKeySeparator));
+  return android::base::Join(ns_and_key, string(1, kKeySeparator));
 }
 
 // Prefs
@@ -326,7 +326,7 @@ bool Prefs::FileStorage::GetFileNameForKey(std::string_view key,
   // Allows only non-empty keys containing [A-Za-z0-9_-/].
   TEST_AND_RETURN_FALSE(!key.empty());
   for (char c : key)
-    TEST_AND_RETURN_FALSE(base::IsAsciiAlpha(c) || base::IsAsciiDigit(c) ||
+    TEST_AND_RETURN_FALSE(isalpha(c) || isdigit(c) ||
                           c == '_' || c == '-' || c == kKeySeparator);
   if (std::filesystem::exists(GetTemporaryDir())) {
     *filename =
diff --git a/common/prefs_unittest.cc b/common/prefs_unittest.cc
index cef6d441..f0d620ff 100644
--- a/common/prefs_unittest.cc
+++ b/common/prefs_unittest.cc
@@ -24,9 +24,8 @@
 
 #include <base/files/file_util.h>
 #include <base/files/scoped_temp_dir.h>
-#include <base/macros.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/macros.h>
+#include <android-base/stringprintf.h>
 #include <gmock/gmock.h>
 #include <gtest/gtest.h>
 
@@ -282,18 +281,18 @@ TEST_F(PrefsTest, GetInt64BadValue) {
 }
 
 TEST_F(PrefsTest, GetInt64Max) {
-  ASSERT_TRUE(SetValue(
-      kKey,
-      base::StringPrintf("%" PRIi64, std::numeric_limits<int64_t>::max())));
+  ASSERT_TRUE(SetValue(kKey,
+                       android::base::StringPrintf(
+                           "%" PRIi64, std::numeric_limits<int64_t>::max())));
   int64_t value;
   EXPECT_TRUE(prefs_.GetInt64(kKey, &value));
   EXPECT_EQ(std::numeric_limits<int64_t>::max(), value);
 }
 
 TEST_F(PrefsTest, GetInt64Min) {
-  ASSERT_TRUE(SetValue(
-      kKey,
-      base::StringPrintf("%" PRIi64, std::numeric_limits<int64_t>::min())));
+  ASSERT_TRUE(SetValue(kKey,
+                       android::base::StringPrintf(
+                           "%" PRIi64, std::numeric_limits<int64_t>::min())));
   int64_t value;
   EXPECT_TRUE(prefs_.GetInt64(kKey, &value));
   EXPECT_EQ(std::numeric_limits<int64_t>::min(), value);
@@ -328,7 +327,8 @@ TEST_F(PrefsTest, SetInt64Max) {
   EXPECT_TRUE(prefs_.SetInt64(kKey, std::numeric_limits<int64_t>::max()));
   string value;
   EXPECT_TRUE(base::ReadFileToString(prefs_dir_.Append(kKey), &value));
-  EXPECT_EQ(base::StringPrintf("%" PRIi64, std::numeric_limits<int64_t>::max()),
+  EXPECT_EQ(android::base::StringPrintf("%" PRIi64,
+                                        std::numeric_limits<int64_t>::max()),
             value);
 }
 
@@ -336,7 +336,8 @@ TEST_F(PrefsTest, SetInt64Min) {
   EXPECT_TRUE(prefs_.SetInt64(kKey, std::numeric_limits<int64_t>::min()));
   string value;
   EXPECT_TRUE(base::ReadFileToString(prefs_dir_.Append(kKey), &value));
-  EXPECT_EQ(base::StringPrintf("%" PRIi64, std::numeric_limits<int64_t>::min()),
+  EXPECT_EQ(android::base::StringPrintf("%" PRIi64,
+                                        std::numeric_limits<int64_t>::min()),
             value);
 }
 
diff --git a/common/subprocess.cc b/common/subprocess.cc
index 9e53d6db..dfc1c5c4 100644
--- a/common/subprocess.cc
+++ b/common/subprocess.cc
@@ -30,9 +30,7 @@
 #include <base/bind.h>
 #include <base/logging.h>
 #include <base/posix/eintr_wrapper.h>
-#include <base/stl_util.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <brillo/secure_blob.h>
 
 #include "update_engine/common/utils.h"
@@ -100,7 +98,7 @@ bool LaunchProcess(const vector<string>& cmd,
   proc->RedirectUsingPipe(STDOUT_FILENO, false);
   proc->SetPreExecCallback(base::Bind(&SetupChild, env, flags));
 
-  LOG(INFO) << "Running \"" << base::JoinString(cmd, " ") << "\"";
+  LOG(INFO) << "Running \"" << android::base::Join(cmd, " ") << "\"";
   return proc->Start();
 }
 
@@ -128,7 +126,7 @@ void Subprocess::OnStdoutReady(SubprocessRecord* record) {
     bytes_read = 0;
     bool eof;
     bool ok = utils::ReadAll(
-        record->stdout_fd, buf, base::size(buf), &bytes_read, &eof);
+        record->stdout_fd, buf, std::size(buf), &bytes_read, &eof);
     record->stdout_str.append(buf, bytes_read);
     if (!ok || eof) {
       // There was either an error or an EOF condition, so we are done watching
diff --git a/common/subprocess.h b/common/subprocess.h
index e59776a2..d4edcc97 100644
--- a/common/subprocess.h
+++ b/common/subprocess.h
@@ -27,7 +27,7 @@
 #include <base/callback.h>
 #include <base/files/file_descriptor_watcher_posix.h>
 #include <base/logging.h>
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <brillo/asynchronous_signal_handler_interface.h>
 #include <brillo/message_loops/message_loop.h>
 #ifdef __CHROMEOS__
diff --git a/common/subprocess_unittest.cc b/common/subprocess_unittest.cc
index 0cb7b377..2a8be94a 100644
--- a/common/subprocess_unittest.cc
+++ b/common/subprocess_unittest.cc
@@ -31,8 +31,7 @@
 #if BASE_VER < 780000  // Android
 #include <base/message_loop/message_loop.h>
 #endif  // BASE_VER < 780000
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #if BASE_VER >= 780000  // Chrome OS
 #include <base/task/single_thread_task_executor.h>
 #endif  // BASE_VER >= 780000
@@ -247,7 +246,7 @@ TEST_F(SubprocessTest, CancelTest) {
   vector<string> cmd = {
       kBinPath "/sh",
       "-c",
-      base::StringPrintf(
+      android::base::StringPrintf(
           // The 'sleep' launched below could be left behind as an orphaned
           // process when the 'sh' process is terminated by SIGTERM. As a
           // remedy, trap SIGTERM and kill the 'sleep' process, which requires
diff --git a/common/test_utils.h b/common/test_utils.h
index b85f80da..2a582b16 100644
--- a/common/test_utils.h
+++ b/common/test_utils.h
@@ -175,7 +175,7 @@ class ActionTraits<ObjectFeederAction<T>> {
 // This is a simple Action class for testing. It feeds an object into
 // another action.
 template <typename T>
-class ObjectFeederAction : public Action<ObjectFeederAction<T>> {
+class ObjectFeederAction final : public Action<ObjectFeederAction<T>> {
  public:
   typedef NoneType InputObjectType;
   typedef T OutputObjectType;
diff --git a/common/utils.cc b/common/utils.cc
index 53ef8d00..bd33ecaf 100644
--- a/common/utils.cc
+++ b/common/utils.cc
@@ -39,6 +39,7 @@
 #include <utility>
 #include <vector>
 
+#include <android-base/stringprintf.h>
 #include <android-base/strings.h>
 #include <base/callback.h>
 #include <base/files/file_path.h>
@@ -51,8 +52,7 @@
 #include <base/rand_util.h>
 #include <base/strings/string_number_conversions.h>
 #include <base/strings/string_split.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <brillo/data_encoding.h>
 
 #include "update_engine/common/constants.h"
@@ -370,7 +370,7 @@ off_t BlockDevSize(int fd) {
 }
 
 off_t FileSize(int fd) {
-  struct stat stbuf{};
+  struct stat stbuf {};
   int rc = fstat(fd, &stbuf);
   CHECK_EQ(rc, 0);
   if (rc < 0) {
@@ -587,17 +587,17 @@ string MakePartitionName(const string& disk_name, int partition_num) {
 }
 
 bool FileExists(const char* path) {
-  struct stat stbuf{};
+  struct stat stbuf {};
   return 0 == lstat(path, &stbuf);
 }
 
 bool IsSymlink(const char* path) {
-  struct stat stbuf{};
+  struct stat stbuf {};
   return lstat(path, &stbuf) == 0 && S_ISLNK(stbuf.st_mode) != 0;
 }
 
 bool IsRegFile(const char* path) {
-  struct stat stbuf{};
+  struct stat stbuf {};
   return lstat(path, &stbuf) == 0 && S_ISREG(stbuf.st_mode) != 0;
 }
 
@@ -752,7 +752,8 @@ bool UnmountFilesystem(const string& mountpoint) {
 }
 
 bool IsMountpoint(const std::string& mountpoint) {
-  struct stat stdir{}, stparent{};
+  struct stat stdir {
+  }, stparent{};
 
   // Check whether the passed mountpoint is a directory and the /.. is in the
   // same device or not. If mountpoint/.. is in a different device it means that
@@ -892,34 +893,34 @@ string FormatTimeDelta(TimeDelta delta) {
   unsigned usecs = delta.InMicroseconds();
 
   if (days)
-    base::StringAppendF(&str, "%ud", days);
+    android::base::StringAppendF(&str, "%ud", days);
   if (days || hours)
-    base::StringAppendF(&str, "%uh", hours);
+    android::base::StringAppendF(&str, "%uh", hours);
   if (days || hours || mins)
-    base::StringAppendF(&str, "%um", mins);
-  base::StringAppendF(&str, "%u", secs);
+    android::base::StringAppendF(&str, "%um", mins);
+  android::base::StringAppendF(&str, "%u", secs);
   if (usecs) {
     int width = 6;
     while ((usecs / 10) * 10 == usecs) {
       usecs /= 10;
       width--;
     }
-    base::StringAppendF(&str, ".%0*u", width, usecs);
+    android::base::StringAppendF(&str, ".%0*u", width, usecs);
   }
-  base::StringAppendF(&str, "s");
+  android::base::StringAppendF(&str, "s");
   return str;
 }
 
 string ToString(const Time utc_time) {
   Time::Exploded exp_time{};
   utc_time.UTCExplode(&exp_time);
-  return base::StringPrintf("%d/%d/%d %d:%02d:%02d GMT",
-                            exp_time.month,
-                            exp_time.day_of_month,
-                            exp_time.year,
-                            exp_time.hour,
-                            exp_time.minute,
-                            exp_time.second);
+  return android::base::StringPrintf("%d/%d/%d %d:%02d:%02d GMT",
+                                     exp_time.month,
+                                     exp_time.day_of_month,
+                                     exp_time.year,
+                                     exp_time.hour,
+                                     exp_time.minute,
+                                     exp_time.second);
 }
 
 string ToString(bool b) {
@@ -1005,9 +1006,9 @@ string CalculateP2PFileId(const brillo::Blob& payload_hash,
                           size_t payload_size) {
   string encoded_hash = brillo::data_encoding::Base64Encode(
       brillo::data_encoding::Base64Encode(payload_hash));
-  return base::StringPrintf("cros_update_size_%" PRIuS "_hash_%s",
-                            payload_size,
-                            encoded_hash.c_str());
+  return android::base::StringPrintf("cros_update_size_%" PRIuS "_hash_%s",
+                                     payload_size,
+                                     encoded_hash.c_str());
 }
 
 bool ConvertToOmahaInstallDate(Time time, int* out_num_days) {
@@ -1196,7 +1197,7 @@ string GetFilePath(int fd) {
 }
 
 string GetTimeAsString(time_t utime) {
-  struct tm tm{};
+  struct tm tm {};
   CHECK_EQ(localtime_r(&utime, &tm), &tm);
   char str[16];
   CHECK_EQ(strftime(str, sizeof(str), "%Y%m%d-%H%M%S", &tm), 15u);
@@ -1204,7 +1205,7 @@ string GetTimeAsString(time_t utime) {
 }
 
 string GetExclusionName(const string& str_to_convert) {
-  return base::NumberToString(base::StringPieceHash()(str_to_convert));
+  return std::format("{}", base::StringPieceHash()(str_to_convert));
 }
 
 static bool ParseTimestamp(std::string_view str, int64_t* out) {
diff --git a/common/utils.h b/common/utils.h
index 1d8de851..52665d32 100644
--- a/common/utils.h
+++ b/common/utils.h
@@ -562,6 +562,15 @@ constexpr std::string_view ToStringView(
 
 bool GetTempName(const std::string& path, base::FilePath* template_path);
 
+template <typename String>
+std::string ToLower(const String& str) {
+  auto copy = std::string(str);
+  std::transform(str.begin(), str.end(), copy.begin(), [](unsigned char c) {
+    return std::tolower(c);
+  });
+  return copy;
+}
+
 }  // namespace chromeos_update_engine
 
 #define TEST_AND_RETURN_FALSE_ERRNO(_x)                             \
diff --git a/download_action.cc b/download_action.cc
index 566fad91..9a8c8706 100644
--- a/download_action.cc
+++ b/download_action.cc
@@ -16,14 +16,11 @@
 
 #include "update_engine/common/download_action.h"
 
-#include <errno.h>
-
-#include <algorithm>
 #include <string>
 
 #include <base/files/file_path.h>
 #include <base/metrics/statistics_recorder.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
 #include "update_engine/common/boot_control_interface.h"
 #include "update_engine/common/error_code_utils.h"
diff --git a/fake_file_writer.h b/fake_file_writer.h
index 75507ea5..68765d89 100644
--- a/fake_file_writer.h
+++ b/fake_file_writer.h
@@ -19,7 +19,7 @@
 
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <brillo/secure_blob.h>
 
 #include "update_engine/payload_consumer/file_writer.h"
diff --git a/libcurl_http_fetcher.cc b/libcurl_http_fetcher.cc
index b8d11f5a..08c8a672 100644
--- a/libcurl_http_fetcher.cc
+++ b/libcurl_http_fetcher.cc
@@ -29,8 +29,7 @@
 #include <base/location.h>
 #include <base/logging.h>
 #include <base/strings/string_split.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <base/threading/thread_task_runner_handle.h>
 
 #ifdef __ANDROID__
@@ -83,7 +82,7 @@ int LibcurlHttpFetcher::LibcurlCloseSocketCallback(void* clientp,
 
   LibcurlHttpFetcher* fetcher = static_cast<LibcurlHttpFetcher*>(clientp);
   // Stop watching the socket before closing it.
-  for (size_t t = 0; t < base::size(fetcher->fd_controller_maps_); ++t) {
+  for (size_t t = 0; t < std::size(fetcher->fd_controller_maps_); ++t) {
     fetcher->fd_controller_maps_[t].erase(item);
   }
 
@@ -109,28 +108,24 @@ LibcurlHttpFetcher::~LibcurlHttpFetcher() {
   CleanUp();
 }
 
-bool LibcurlHttpFetcher::GetProxyType(const string& proxy,
+bool LibcurlHttpFetcher::GetProxyType(const string& proxy_str,
                                       curl_proxytype* out_type) {
-  if (base::StartsWith(
-          proxy, "socks5://", base::CompareCase::INSENSITIVE_ASCII) ||
-      base::StartsWith(
-          proxy, "socks://", base::CompareCase::INSENSITIVE_ASCII)) {
+  auto proxy = ToLower(proxy_str);
+  if (android::base::StartsWith(proxy, "socks5://") ||
+      android::base::StartsWith(proxy, "socks://")) {
     *out_type = CURLPROXY_SOCKS5_HOSTNAME;
     return true;
   }
-  if (base::StartsWith(
-          proxy, "socks4://", base::CompareCase::INSENSITIVE_ASCII)) {
+  if (android::base::StartsWith(proxy, "socks4://")) {
     *out_type = CURLPROXY_SOCKS4A;
     return true;
   }
-  if (base::StartsWith(
-          proxy, "http://", base::CompareCase::INSENSITIVE_ASCII) ||
-      base::StartsWith(
-          proxy, "https://", base::CompareCase::INSENSITIVE_ASCII)) {
+  if (android::base::StartsWith(proxy, "http://") ||
+      android::base::StartsWith(proxy, "https://")) {
     *out_type = CURLPROXY_HTTP;
     return true;
   }
-  if (base::StartsWith(proxy, kNoProxy, base::CompareCase::INSENSITIVE_ASCII)) {
+  if (android::base::StartsWith(proxy, kNoProxy)) {
     // known failure case. don't log.
     return false;
   }
@@ -196,7 +191,7 @@ void LibcurlHttpFetcher::ResumeTransfer(const string& url) {
   if (post_data_set_) {
     // Set the Content-Type HTTP header, if one was specifically set.
     if (post_content_type_ != kHttpContentTypeUnspecified) {
-      const string content_type_attr = base::StringPrintf(
+      const string content_type_attr = android::base::StringPrintf(
           "Content-Type: %s", GetHttpContentTypeString(post_content_type_));
       curl_http_headers_ =
           curl_slist_append(curl_http_headers_, content_type_attr.c_str());
@@ -222,7 +217,7 @@ void LibcurlHttpFetcher::ResumeTransfer(const string& url) {
     }
 
     // Create a string representation of the desired range.
-    string range_str = base::StringPrintf(
+    string range_str = android::base::StringPrintf(
         "%" PRIu64 "-", static_cast<uint64_t>(resume_offset_));
     if (end_offset)
       range_str += std::to_string(end_offset);
@@ -259,15 +254,12 @@ void LibcurlHttpFetcher::ResumeTransfer(const string& url) {
   // Lock down the appropriate curl options for HTTP or HTTPS depending on
   // the url.
   if (hardware_->IsOfficialBuild()) {
-    if (base::StartsWith(
-            url_, "http://", base::CompareCase::INSENSITIVE_ASCII)) {
+    if (android::base::StartsWith(ToLower(url_), "http://")) {
       SetCurlOptionsForHttp();
-    } else if (base::StartsWith(
-                   url_, "https://", base::CompareCase::INSENSITIVE_ASCII)) {
+    } else if (android::base::StartsWith(ToLower(url_), "https://")) {
       SetCurlOptionsForHttps();
 #ifdef __ANDROID__
-    } else if (base::StartsWith(
-                   url_, "file://", base::CompareCase::INSENSITIVE_ASCII)) {
+    } else if (android::base::StartsWith(ToLower(url_), "file://")) {
       SetCurlOptionsForFile();
 #endif  // __ANDROID__
     } else {
@@ -379,7 +371,7 @@ void LibcurlHttpFetcher::SetHeader(const string& header_name,
     header_line = header_name + ":";
   TEST_AND_RETURN(header_line.find('\n') == string::npos);
   TEST_AND_RETURN(header_name.find(':') == string::npos);
-  extra_headers_[base::ToLowerASCII(header_name)] = header_line;
+  extra_headers_[ToLower(header_name)] = header_line;
 }
 
 // Inputs: header_name, header_value
@@ -397,7 +389,7 @@ bool LibcurlHttpFetcher::GetHeader(const string& header_name,
   // Initially clear |header_value| to handle both success and failures without
   // leaving |header_value| in a unclear state.
   header_value->clear();
-  auto header_key = base::ToLowerASCII(header_name);
+  auto header_key = ToLower(header_name);
   auto header_line_itr = extra_headers_.find(header_key);
   // If the |header_name| was never set, indicate so by returning false.
   if (header_line_itr == extra_headers_.end())
@@ -683,7 +675,7 @@ void LibcurlHttpFetcher::SetupMessageLoopSources() {
 
   // We should iterate through all file descriptors up to libcurl's fd_max or
   // the highest one we're tracking, whichever is larger.
-  for (size_t t = 0; t < base::size(fd_controller_maps_); ++t) {
+  for (size_t t = 0; t < std::size(fd_controller_maps_); ++t) {
     if (!fd_controller_maps_[t].empty())
       fd_max = max(fd_max, fd_controller_maps_[t].rbegin()->first);
   }
@@ -701,7 +693,7 @@ void LibcurlHttpFetcher::SetupMessageLoopSources() {
         is_exc || (FD_ISSET(fd, &fd_write) != 0)  // track 1 -- write
     };
 
-    for (size_t t = 0; t < base::size(fd_controller_maps_); ++t) {
+    for (size_t t = 0; t < std::size(fd_controller_maps_); ++t) {
       bool tracked =
           fd_controller_maps_[t].find(fd) != fd_controller_maps_[t].end();
 
@@ -782,7 +774,7 @@ void LibcurlHttpFetcher::CleanUp() {
   MessageLoop::current()->CancelTask(timeout_id_);
   timeout_id_ = MessageLoop::kTaskIdNull;
 
-  for (size_t t = 0; t < base::size(fd_controller_maps_); ++t) {
+  for (size_t t = 0; t < std::size(fd_controller_maps_); ++t) {
     fd_controller_maps_[t].clear();
   }
 
@@ -809,7 +801,7 @@ void LibcurlHttpFetcher::CleanUp() {
 
 void LibcurlHttpFetcher::GetHttpResponseCode() {
   long http_response_code = 0;  // NOLINT(runtime/int) - curl needs long.
-  if (base::StartsWith(url_, "file://", base::CompareCase::INSENSITIVE_ASCII)) {
+  if (android::base::StartsWith(ToLower(url_), "file://")) {
     // Fake out a valid response code for file:// URLs.
     http_response_code_ = 299;
   } else if (curl_easy_getinfo(curl_handle_,
diff --git a/libcurl_http_fetcher.h b/libcurl_http_fetcher.h
index 0e34f9d2..b21cdca8 100644
--- a/libcurl_http_fetcher.h
+++ b/libcurl_http_fetcher.h
@@ -26,7 +26,7 @@
 
 #include <base/files/file_descriptor_watcher_posix.h>
 #include <base/logging.h>
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <brillo/message_loops/message_loop.h>
 
 #include "update_engine/certificate_checker.h"
diff --git a/liburing_cpp/Android.bp b/liburing_cpp/Android.bp
index 0daa48d5..e17f0808 100644
--- a/liburing_cpp/Android.bp
+++ b/liburing_cpp/Android.bp
@@ -19,7 +19,6 @@ cc_library {
 	static_libs: [
 		"liburing",
 	],
-	include_dirs: ["bionic/libc/kernel"],
 	export_include_dirs: [
 		"include",
 	],
diff --git a/liburing_cpp/src/IoUring.cpp b/liburing_cpp/src/IoUring.cpp
index f561d257..cf102723 100644
--- a/liburing_cpp/src/IoUring.cpp
+++ b/liburing_cpp/src/IoUring.cpp
@@ -14,7 +14,7 @@
 // limitations under the License.
 //
 
-#include <asm-generic/errno-base.h>
+#include <errno.h>
 #include <liburing_cpp/IoUring.h>
 #include <string.h>
 
diff --git a/lz4diff/lz4diff_compress_unittest.cc b/lz4diff/lz4diff_compress_unittest.cc
index 9caa9a31..b00a1081 100644
--- a/lz4diff/lz4diff_compress_unittest.cc
+++ b/lz4diff/lz4diff_compress_unittest.cc
@@ -21,11 +21,9 @@
 #include <string>
 #include <vector>
 
-#include <base/format_macros.h>
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <gtest/gtest.h>
 #include <erofs/internal.h>
 #include <erofs/io.h>
@@ -35,7 +33,6 @@
 #include "update_engine/lz4diff/lz4diff_compress.h"
 #include "update_engine/payload_generator/delta_diff_generator.h"
 #include "update_engine/payload_generator/erofs_filesystem.h"
-#include "update_engine/payload_generator/extent_utils.h"
 
 using std::string;
 using std::vector;
diff --git a/lz4diff/lz4diff_unittest.cc b/lz4diff/lz4diff_unittest.cc
index aabff994..f5ae7965 100644
--- a/lz4diff/lz4diff_unittest.cc
+++ b/lz4diff/lz4diff_unittest.cc
@@ -24,8 +24,7 @@
 #include <base/format_macros.h>
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <gtest/gtest.h>
 #include <erofs/internal.h>
 #include <erofs/io.h>
diff --git a/payload_consumer/certificate_parser_android.h b/payload_consumer/certificate_parser_android.h
index ccb92936..e2a3921f 100644
--- a/payload_consumer/certificate_parser_android.h
+++ b/payload_consumer/certificate_parser_android.h
@@ -21,7 +21,7 @@
 #include <string>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "payload_consumer/certificate_parser_interface.h"
 
diff --git a/payload_consumer/certificate_parser_stub.h b/payload_consumer/certificate_parser_stub.h
index a51c2c67..4f78efe6 100644
--- a/payload_consumer/certificate_parser_stub.h
+++ b/payload_consumer/certificate_parser_stub.h
@@ -21,7 +21,7 @@
 #include <string>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "update_engine/payload_consumer/certificate_parser_interface.h"
 
diff --git a/payload_consumer/delta_performer.cc b/payload_consumer/delta_performer.cc
index 519ec716..0b4a13e6 100644
--- a/payload_consumer/delta_performer.cc
+++ b/payload_consumer/delta_performer.cc
@@ -33,7 +33,7 @@
 #include <base/format_macros.h>
 #include <base/metrics/histogram_macros.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <base/time/time.h>
 #include <brillo/data_encoding.h>
 #include <bsdiff/bspatch.h>
@@ -89,7 +89,7 @@ void DeltaPerformer::LogProgress(const char* message_prefix) {
   if (num_total_operations_) {
     total_operations_str = std::to_string(num_total_operations_);
     // Upcasting to 64-bit to avoid overflow, back to size_t for formatting.
-    completed_percentage_str = base::StringPrintf(
+    completed_percentage_str = android::base::StringPrintf(
         " (%" PRIu64 "%%)",
         IntRatio(next_operation_num_, num_total_operations_, 100));
   }
@@ -101,7 +101,7 @@ void DeltaPerformer::LogProgress(const char* message_prefix) {
   if (payload_size) {
     payload_size_str = std::to_string(payload_size);
     // Upcasting to 64-bit to avoid overflow, back to size_t for formatting.
-    downloaded_percentage_str = base::StringPrintf(
+    downloaded_percentage_str = android::base::StringPrintf(
         " (%" PRIu64 "%%)", IntRatio(total_bytes_received_, payload_size, 100));
   }
 
@@ -998,7 +998,8 @@ bool DeltaPerformer::ExtentsToBsdiffPositionsString(
     uint64_t this_length =
         min(full_length - length,
             static_cast<uint64_t>(extent.num_blocks()) * block_size);
-    ret += base::StringPrintf("%" PRIi64 ":%" PRIu64 ",", start, this_length);
+    ret += android::base::StringPrintf(
+        "%" PRIi64 ":%" PRIu64 ",", start, this_length);
     length += this_length;
   }
   TEST_AND_RETURN_FALSE(length == full_length);
diff --git a/payload_consumer/delta_performer_integration_test.cc b/payload_consumer/delta_performer_integration_test.cc
index bffee8df..fe3121bc 100644
--- a/payload_consumer/delta_performer_integration_test.cc
+++ b/payload_consumer/delta_performer_integration_test.cc
@@ -16,18 +16,16 @@
 
 #include "update_engine/payload_consumer/delta_performer.h"
 
-#include <inttypes.h>
 #include <sys/mount.h>
 
 #include <algorithm>
+#include <list>
 #include <string>
 #include <vector>
 
 #include <base/files/file_path.h>
 #include <base/files/file_util.h>
-#include <base/stl_util.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <gmock/gmock-matchers.h>
 #include <google/protobuf/repeated_field.h>
 #include <gtest/gtest.h>
@@ -37,7 +35,6 @@
 #include "update_engine/common/fake_boot_control.h"
 #include "update_engine/common/fake_hardware.h"
 #include "update_engine/common/fake_prefs.h"
-#include "update_engine/common/hardware_interface.h"
 #include "update_engine/common/mock_download_action.h"
 #include "update_engine/common/mock_prefs.h"
 #include "update_engine/common/test_utils.h"
@@ -251,14 +248,16 @@ static void SignGeneratedShellPayloadWithKeys(
     size_t signature_size{};
     ASSERT_TRUE(
         PayloadSigner::GetMaximumSignatureSize(key_path, &signature_size));
-    signature_size_strings.push_back(base::StringPrintf("%zu", signature_size));
+    signature_size_strings.push_back(
+        android::base::StringPrintf("%zu", signature_size));
   }
-  string signature_size_string = base::JoinString(signature_size_strings, ":");
+  string signature_size_string =
+      android::base::Join(signature_size_strings, ":");
 
   ScopedTempFile hash_file("hash.XXXXXX"), metadata_hash_file("hash.XXXXXX");
   string delta_generator_path = GetBuildArtifactsPath("delta_generator");
   ASSERT_EQ(0,
-            System(base::StringPrintf(
+            System(android::base::StringPrintf(
                 "%s -in_file=%s -signature_size=%s -out_hash_file=%s "
                 "-out_metadata_hash_file=%s",
                 delta_generator_path.c_str(),
@@ -290,27 +289,29 @@ static void SignGeneratedShellPayloadWithKeys(
                                             metadata_signature));
     metadata_sig_file_paths.push_back(metadata_sig_files.back().path());
   }
-  string sig_files_string = base::JoinString(sig_file_paths, ":");
+  string sig_files_string = android::base::Join(sig_file_paths, ":");
   string metadata_sig_files_string =
-      base::JoinString(metadata_sig_file_paths, ":");
+      android::base::Join(metadata_sig_file_paths, ":");
 
   // Add the signature to the payload.
-  ASSERT_EQ(0,
-            System(base::StringPrintf("%s --signature_size=%s -in_file=%s "
-                                      "-payload_signature_file=%s "
-                                      "-metadata_signature_file=%s "
-                                      "-out_file=%s",
-                                      delta_generator_path.c_str(),
-                                      signature_size_string.c_str(),
-                                      payload_path.c_str(),
-                                      sig_files_string.c_str(),
-                                      metadata_sig_files_string.c_str(),
-                                      payload_path.c_str())));
-
-  int verify_result = System(base::StringPrintf("%s -in_file=%s -public_key=%s",
-                                                delta_generator_path.c_str(),
-                                                payload_path.c_str(),
-                                                public_key_path.c_str()));
+  ASSERT_EQ(
+      0,
+      System(android::base::StringPrintf("%s --signature_size=%s -in_file=%s "
+                                         "-payload_signature_file=%s "
+                                         "-metadata_signature_file=%s "
+                                         "-out_file=%s",
+                                         delta_generator_path.c_str(),
+                                         signature_size_string.c_str(),
+                                         payload_path.c_str(),
+                                         sig_files_string.c_str(),
+                                         metadata_sig_files_string.c_str(),
+                                         payload_path.c_str())));
+
+  int verify_result =
+      System(android::base::StringPrintf("%s -in_file=%s -public_key=%s",
+                                         delta_generator_path.c_str(),
+                                         payload_path.c_str(),
+                                         public_key_path.c_str()));
 
   if (verification_success) {
     ASSERT_EQ(0, verify_result);
@@ -415,30 +416,32 @@ static void GenerateDeltaFile(bool full_kernel,
                             std::end(kRandomString));
     }
     ASSERT_TRUE(utils::WriteFile(
-        base::StringPrintf("%s/hardtocompress", a_mnt.c_str()).c_str(),
+        android::base::StringPrintf("%s/hardtocompress", a_mnt.c_str()).c_str(),
         hardtocompress.data(),
         hardtocompress.size()));
 
     brillo::Blob zeros(16 * 1024, 0);
     ASSERT_EQ(static_cast<int>(zeros.size()),
-              base::WriteFile(base::FilePath(base::StringPrintf(
+              base::WriteFile(base::FilePath(android::base::StringPrintf(
                                   "%s/move-to-sparse", a_mnt.c_str())),
                               reinterpret_cast<const char*>(zeros.data()),
                               zeros.size()));
 
     ASSERT_TRUE(WriteSparseFile(
-        base::StringPrintf("%s/move-from-sparse", a_mnt.c_str()), 16 * 1024));
+        android::base::StringPrintf("%s/move-from-sparse", a_mnt.c_str()),
+        16 * 1024));
 
     ASSERT_TRUE(WriteByteAtOffset(
-        base::StringPrintf("%s/move-semi-sparse", a_mnt.c_str()), 4096));
+        android::base::StringPrintf("%s/move-semi-sparse", a_mnt.c_str()),
+        4096));
 
     // Write 1 MiB of 0xff to try to catch the case where writing a bsdiff
     // patch fails to zero out the final block.
     brillo::Blob ones(1024 * 1024, 0xff);
-    ASSERT_TRUE(
-        utils::WriteFile(base::StringPrintf("%s/ones", a_mnt.c_str()).c_str(),
-                         ones.data(),
-                         ones.size()));
+    ASSERT_TRUE(utils::WriteFile(
+        android::base::StringPrintf("%s/ones", a_mnt.c_str()).c_str(),
+        ones.data(),
+        ones.size()));
   }
 
   // Create a result image with image_size bytes of garbage.
@@ -505,7 +508,7 @@ static void GenerateDeltaFile(bool full_kernel,
                             std::end(kRandomString));
     }
     ASSERT_TRUE(utils::WriteFile(
-        base::StringPrintf("%s/hardtocompress", b_mnt.c_str()).c_str(),
+        android::base::StringPrintf("%s/hardtocompress", b_mnt.c_str()).c_str(),
         hardtocompress.data(),
         hardtocompress.size()));
   }
@@ -904,17 +907,16 @@ void VerifyPayloadResult(DeltaPerformer* performer,
     // no need to verify new partition if VerifyPayload failed.
     return;
   }
-
-  CompareFilesByBlock(state->result_kernel->path(),
-                      state->new_kernel->path(),
-                      state->kernel_size);
-  CompareFilesByBlock(
-      state->result_img->path(), state->b_img->path(), state->image_size);
+  ASSERT_NO_FATAL_FAILURE(CompareFilesByBlock(state->result_kernel->path(),
+                                              state->new_kernel->path(),
+                                              state->kernel_size));
+  ASSERT_NO_FATAL_FAILURE(CompareFilesByBlock(
+      state->result_img->path(), state->b_img->path(), state->image_size));
 
   brillo::Blob updated_kernel_partition;
   ASSERT_TRUE(
       utils::ReadFile(state->result_kernel->path(), &updated_kernel_partition));
-  ASSERT_GE(updated_kernel_partition.size(), base::size(kNewData));
+  ASSERT_GE(updated_kernel_partition.size(), std::size(kNewData));
   ASSERT_TRUE(std::equal(std::begin(kNewData),
                          std::end(kNewData),
                          updated_kernel_partition.begin()));
@@ -955,7 +957,8 @@ void VerifyPayload(DeltaPerformer* performer,
       break;  // appease gcc
   }
 
-  VerifyPayloadResult(performer, state, expected_result, minor_version);
+  ASSERT_NO_FATAL_FAILURE(
+      VerifyPayloadResult(performer, state, expected_result, minor_version));
 }
 
 void DoSmallImageTest(bool full_kernel,
@@ -966,22 +969,23 @@ void DoSmallImageTest(bool full_kernel,
                       uint32_t minor_version) {
   DeltaState state;
   DeltaPerformer* performer = nullptr;
-  GenerateDeltaFile(full_kernel,
-                    full_rootfs,
-                    chunk_size,
-                    signature_test,
-                    &state,
-                    minor_version);
-
-  ApplyDeltaFile(full_kernel,
-                 full_rootfs,
-                 signature_test,
-                 &state,
-                 hash_checks_mandatory,
-                 kValidOperationData,
-                 &performer,
-                 minor_version);
-  VerifyPayload(performer, &state, signature_test, minor_version);
+  ASSERT_NO_FATAL_FAILURE(GenerateDeltaFile(full_kernel,
+                                            full_rootfs,
+                                            chunk_size,
+                                            signature_test,
+                                            &state,
+                                            minor_version));
+
+  ASSERT_NO_FATAL_FAILURE(ApplyDeltaFile(full_kernel,
+                                         full_rootfs,
+                                         signature_test,
+                                         &state,
+                                         hash_checks_mandatory,
+                                         kValidOperationData,
+                                         &performer,
+                                         minor_version));
+  ASSERT_NO_FATAL_FAILURE(
+      VerifyPayload(performer, &state, signature_test, minor_version));
   delete performer;
 }
 
@@ -991,14 +995,14 @@ void DoOperationHashMismatchTest(OperationHashTest op_hash_test,
   uint64_t minor_version = kFullPayloadMinorVersion;
   GenerateDeltaFile(true, true, -1, kSignatureGenerated, &state, minor_version);
   DeltaPerformer* performer = nullptr;
-  ApplyDeltaFile(true,
-                 true,
-                 kSignatureGenerated,
-                 &state,
-                 hash_checks_mandatory,
-                 op_hash_test,
-                 &performer,
-                 minor_version);
+  ASSERT_NO_FATAL_FAILURE(ApplyDeltaFile(true,
+                                         true,
+                                         kSignatureGenerated,
+                                         &state,
+                                         hash_checks_mandatory,
+                                         op_hash_test,
+                                         &performer,
+                                         minor_version));
   delete performer;
 }
 
diff --git a/payload_consumer/delta_performer_unittest.cc b/payload_consumer/delta_performer_unittest.cc
index 04cfaadc..d2b8bcdf 100644
--- a/payload_consumer/delta_performer_unittest.cc
+++ b/payload_consumer/delta_performer_unittest.cc
@@ -25,13 +25,11 @@
 #include <string>
 #include <vector>
 
+#include <android-base/parseint.h>
 #include <base/files/file_path.h>
 #include <base/files/file_util.h>
 #include <base/files/scoped_temp_dir.h>
-#include <base/stl_util.h>
-#include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <brillo/secure_blob.h>
 #include <gmock/gmock.h>
 #include <google/protobuf/repeated_field.h>
@@ -657,12 +655,12 @@ TEST_F(DeltaPerformerTest, SourceHashMismatchTest) {
 
 TEST_F(DeltaPerformerTest, ExtentsToByteStringTest) {
   uint64_t test[] = {1, 1, 4, 2, 0, 1};
-  static_assert(base::size(test) % 2 == 0, "Array size uneven");
+  static_assert(std::size(test) % 2 == 0, "Array size uneven");
   const uint64_t block_size = 4096;
   const uint64_t file_length = 4 * block_size - 13;
 
   google::protobuf::RepeatedPtrField<Extent> extents;
-  for (size_t i = 0; i < base::size(test); i += 2) {
+  for (size_t i = 0; i < std::size(test); i += 2) {
     *(extents.Add()) = ExtentForRange(test[i], test[i + 1]);
   }
 
@@ -1079,7 +1077,8 @@ TEST(DISABLED_ConfVersionTest, ConfVersionsMatch) {
   string major_version_str;
   uint64_t major_version{};
   EXPECT_TRUE(store.GetString("PAYLOAD_MAJOR_VERSION", &major_version_str));
-  EXPECT_TRUE(base::StringToUint64(major_version_str, &major_version));
+  EXPECT_TRUE(
+      android::base::ParseUint<uint64_t>(major_version_str, &major_version));
   EXPECT_EQ(kMaxSupportedMajorPayloadVersion, major_version);
 }
 
diff --git a/payload_consumer/filesystem_verifier_action.cc b/payload_consumer/filesystem_verifier_action.cc
index 2e2f6b96..8c21673a 100644
--- a/payload_consumer/filesystem_verifier_action.cc
+++ b/payload_consumer/filesystem_verifier_action.cc
@@ -31,7 +31,6 @@
 #include <utility>
 
 #include <base/bind.h>
-#include <base/strings/string_util.h>
 #include <brillo/data_encoding.h>
 #include <brillo/message_loops/message_loop.h>
 #include <brillo/secure_blob.h>
@@ -112,7 +111,7 @@ void FilesystemVerifierAction::PerformAction() {
   std::partial_sum(partition_weight_.begin(),
                    partition_weight_.end(),
                    partition_weight_.begin(),
-                   std::plus<size_t>());
+                   std::plus<uint64_t>());
 
   install_plan_.Dump();
   // If we are not writing verity, just map all partitions once at the
@@ -357,8 +356,8 @@ void FilesystemVerifierAction::StartPartitionHashing() {
   if (partition_index_ == install_plan_.partitions.size()) {
     if (!install_plan_.untouched_dynamic_partitions.empty()) {
       LOG(INFO) << "Verifying extents of untouched dynamic partitions ["
-                << base::JoinString(install_plan_.untouched_dynamic_partitions,
-                                    ", ")
+                << android::base::Join(
+                       install_plan_.untouched_dynamic_partitions, ", ")
                 << "]";
       if (!dynamic_control_->VerifyExtentsForUntouchedPartitions(
               install_plan_.source_slot,
diff --git a/payload_consumer/filesystem_verifier_action.h b/payload_consumer/filesystem_verifier_action.h
index d8cb9025..2adf62ef 100644
--- a/payload_consumer/filesystem_verifier_action.h
+++ b/payload_consumer/filesystem_verifier_action.h
@@ -176,7 +176,7 @@ class FilesystemVerifierAction : public InstallPlanAction {
   // Cumulative sum of partition sizes. Used for progress report.
   // This vector will always start with 0, and end with total size of all
   // partitions.
-  std::vector<size_t> partition_weight_;
+  std::vector<uint64_t> partition_weight_;
 
   DISALLOW_COPY_AND_ASSIGN(FilesystemVerifierAction);
 };
diff --git a/payload_consumer/install_plan.cc b/payload_consumer/install_plan.cc
index 9c3934d5..8916af55 100644
--- a/payload_consumer/install_plan.cc
+++ b/payload_consumer/install_plan.cc
@@ -22,8 +22,7 @@
 #include <base/format_macros.h>
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
 #include "update_engine/common/utils.h"
 #include "update_engine/update_metadata.pb.h"
@@ -36,7 +35,7 @@ namespace chromeos_update_engine {
 namespace {
 string PayloadUrlsToString(
     const decltype(InstallPlan::Payload::payload_urls)& payload_urls) {
-  return "(" + base::JoinString(payload_urls, ",") + ")";
+  return "(" + android::base::Join(payload_urls, ",") + ")";
 }
 
 string VectorToString(const vector<std::pair<string, string>>& input,
@@ -46,9 +45,10 @@ string VectorToString(const vector<std::pair<string, string>>& input,
                  input.end(),
                  std::back_inserter(vec),
                  [](const auto& pair) {
-                   return base::JoinString({pair.first, pair.second}, ": ");
+                   return android::base::Join(vector{pair.first, pair.second},
+                                              ": ");
                  });
-  return base::JoinString(vec, separator);
+  return android::base::Join(vec, separator);
 }
 }  // namespace
 
@@ -81,8 +81,7 @@ void InstallPlan::Dump() const {
 
 string InstallPlan::ToString() const {
   string url_str = download_url;
-  if (base::StartsWith(
-          url_str, "fd://", base::CompareCase::INSENSITIVE_ASCII)) {
+  if (android::base::StartsWith(ToLower(url_str), "fd://")) {
     int fd = std::stoi(url_str.substr(strlen("fd://")));
     url_str = utils::GetFilePath(fd);
   }
@@ -99,8 +98,6 @@ string InstallPlan::ToString() const {
           {"powerwash_required", utils::ToString(powerwash_required)},
           {"switch_slot_on_reboot", utils::ToString(switch_slot_on_reboot)},
           {"run_post_install", utils::ToString(run_post_install)},
-          {"rollback_data_save_requested",
-           utils::ToString(rollback_data_save_requested)},
           {"write_verity", utils::ToString(write_verity)},
       },
       "\n"));
@@ -109,12 +106,12 @@ string InstallPlan::ToString() const {
     result_str.emplace_back(VectorToString(
         {
             {"Partition", partition.name},
-            {"source_size", base::NumberToString(partition.source_size)},
+            {"source_size", std::format("{}", partition.source_size)},
             {"source_path", partition.source_path},
             {"source_hash",
              base::HexEncode(partition.source_hash.data(),
                              partition.source_hash.size())},
-            {"target_size", base::NumberToString(partition.target_size)},
+            {"target_size", std::format("{}", partition.target_size)},
             {"target_path", partition.target_path},
             {"target_hash",
              base::HexEncode(partition.target_hash.data(),
@@ -131,10 +128,10 @@ string InstallPlan::ToString() const {
     const auto& payload = payloads[i];
     result_str.emplace_back(VectorToString(
         {
-            {"Payload", base::NumberToString(i)},
+            {"Payload", std::format("{}", i)},
             {"urls", PayloadUrlsToString(payload.payload_urls)},
-            {"size", base::NumberToString(payload.size)},
-            {"metadata_size", base::NumberToString(payload.metadata_size)},
+            {"size", std::format("{}", payload.size)},
+            {"metadata_size", std::format("{}", payload.metadata_size)},
             {"metadata_signature", payload.metadata_signature},
             {"hash", base::HexEncode(payload.hash.data(), payload.hash.size())},
             {"type", InstallPayloadTypeToString(payload.type)},
@@ -145,7 +142,7 @@ string InstallPlan::ToString() const {
         "\n  "));
   }
 
-  return base::JoinString(result_str, "\n");
+  return android::base::Join(result_str, "\n");
 }
 
 bool InstallPlan::LoadPartitionsFromSlots(BootControlInterface* boot_control) {
diff --git a/payload_consumer/install_plan.h b/payload_consumer/install_plan.h
index 097c6cef..e1c2c34a 100644
--- a/payload_consumer/install_plan.h
+++ b/payload_consumer/install_plan.h
@@ -20,7 +20,7 @@
 #include <string>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <brillo/secure_blob.h>
 
 #include "update_engine/common/action.h"
@@ -182,9 +182,6 @@ struct InstallPlan {
   // False otherwise.
   bool run_post_install{true};
 
-  // True if this rollback should preserve some system data.
-  bool rollback_data_save_requested{false};
-
   // True if the update should write verity.
   // False otherwise.
   bool write_verity{true};
diff --git a/payload_consumer/install_plan_unittest.cc b/payload_consumer/install_plan_unittest.cc
index d2a3f5f5..ca543609 100644
--- a/payload_consumer/install_plan_unittest.cc
+++ b/payload_consumer/install_plan_unittest.cc
@@ -54,7 +54,6 @@ hash_checks_mandatory: false
 powerwash_required: false
 switch_slot_on_reboot: true
 run_post_install: true
-rollback_data_save_requested: false
 write_verity: true
 Partition: foo-partition_name
   source_size: 0
diff --git a/payload_consumer/partition_writer.cc b/payload_consumer/partition_writer.cc
index e55722c0..17763eab 100644
--- a/payload_consumer/partition_writer.cc
+++ b/payload_consumer/partition_writer.cc
@@ -29,8 +29,7 @@
 #include <vector>
 
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
 #include "update_engine/common/error_code.h"
 #include "update_engine/common/utils.h"
@@ -328,12 +327,12 @@ bool PartitionWriter::ValidateSourceHash(const brillo::Blob& calculated_hash,
     vector<string> source_extents;
     for (const Extent& ext : operation.src_extents()) {
       source_extents.push_back(
-          base::StringPrintf("%" PRIu64 ":%" PRIu64,
-                             static_cast<uint64_t>(ext.start_block()),
-                             static_cast<uint64_t>(ext.num_blocks())));
+          android::base::StringPrintf("%" PRIu64 ":%" PRIu64,
+                                      static_cast<uint64_t>(ext.start_block()),
+                                      static_cast<uint64_t>(ext.num_blocks())));
     }
     LOG(ERROR) << "Operation source (offset:size) in blocks: "
-               << base::JoinString(source_extents, ",");
+               << android::base::Join(source_extents, ",");
 
     // Log remount history if this device is an ext4 partition.
     LogMountHistory(source_fd);
diff --git a/payload_consumer/partition_writer_unittest.cc b/payload_consumer/partition_writer_unittest.cc
index 32324b6d..ef2690fc 100644
--- a/payload_consumer/partition_writer_unittest.cc
+++ b/payload_consumer/partition_writer_unittest.cc
@@ -128,7 +128,7 @@ class PartitionWriterTest : public testing::Test {
   PartitionWriter writer_{
       partition_update_, install_part_, &dynamic_control_, kBlockSize, false};
 };
-// Test that the error-corrected file descriptor is used to read a partition
+// Test that the plain file descriptor is used to read a partition
 // when no hash is available for SOURCE_COPY but it falls back to the normal
 // file descriptor when the size of the error corrected one is too small.
 TEST_F(PartitionWriterTest, ErrorCorrectionSourceCopyWhenNoHashFallbackTest) {
@@ -153,13 +153,8 @@ TEST_F(PartitionWriterTest, ErrorCorrectionSourceCopyWhenNoHashFallbackTest) {
   ASSERT_NO_FATAL_FAILURE();
   ASSERT_EQ(output_data, expected_data);
 
-  // Verify that the fake_fec was attempted to be used. Since the file
-  // descriptor is shorter it can actually do more than one read to realize it
-  // reached the EOF.
-  ASSERT_LE(1U, fake_fec->GetReadOps().size());
-  // This fallback doesn't count as an error-corrected operation since the
-  // operation hash was not available.
-  ASSERT_EQ(0U, GetSourceEccRecoveredFailures());
+  // Verify that the fake_fec was not used
+  ASSERT_LE(0U, fake_fec->GetReadOps().size());
 }
 
 // Test that the error-corrected file descriptor is used to read the partition
diff --git a/payload_consumer/payload_metadata.cc b/payload_consumer/payload_metadata.cc
index f797723c..d2e42f02 100644
--- a/payload_consumer/payload_metadata.cc
+++ b/payload_consumer/payload_metadata.cc
@@ -18,7 +18,7 @@
 
 #include <endian.h>
 
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <brillo/data_encoding.h>
 
 #include "update_engine/common/constants.h"
@@ -62,17 +62,17 @@ MetadataParseResult PayloadMetadata::ParsePayloadHeader(
   // Validate the magic string.
   if (memcmp(payload, kDeltaMagic, sizeof(kDeltaMagic)) != 0) {
     LOG(ERROR) << "Bad payload format -- invalid delta magic: "
-               << base::StringPrintf("%02x%02x%02x%02x",
-                                     payload[0],
-                                     payload[1],
-                                     payload[2],
-                                     payload[3])
+               << android::base::StringPrintf("%02x%02x%02x%02x",
+                                              payload[0],
+                                              payload[1],
+                                              payload[2],
+                                              payload[3])
                << " Expected: "
-               << base::StringPrintf("%02x%02x%02x%02x",
-                                     kDeltaMagic[0],
-                                     kDeltaMagic[1],
-                                     kDeltaMagic[2],
-                                     kDeltaMagic[3]);
+               << android::base::StringPrintf("%02x%02x%02x%02x",
+                                              kDeltaMagic[0],
+                                              kDeltaMagic[1],
+                                              kDeltaMagic[2],
+                                              kDeltaMagic[3]);
     *error = ErrorCode::kDownloadInvalidMetadataMagicString;
     return MetadataParseResult::kError;
   }
diff --git a/payload_consumer/payload_metadata.h b/payload_consumer/payload_metadata.h
index a38405d1..4d2d5b07 100644
--- a/payload_consumer/payload_metadata.h
+++ b/payload_consumer/payload_metadata.h
@@ -22,7 +22,7 @@
 #include <string>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <brillo/secure_blob.h>
 
 #include "update_engine/common/error_code.h"
diff --git a/payload_consumer/postinstall_runner_action.cc b/payload_consumer/postinstall_runner_action.cc
index 4de75aa7..5a6eeab3 100644
--- a/payload_consumer/postinstall_runner_action.cc
+++ b/payload_consumer/postinstall_runner_action.cc
@@ -30,9 +30,7 @@
 #include <base/files/file_path.h>
 #include <base/files/file_util.h>
 #include <base/logging.h>
-#include <base/stl_util.h>
 #include <base/strings/string_split.h>
-#include <base/strings/string_util.h>
 
 #include "update_engine/common/action_processor.h"
 #include "update_engine/common/boot_control_interface.h"
@@ -129,8 +127,7 @@ void PostinstallRunnerAction::PerformAction() {
   // that retains a small amount of system state such as enrollment and
   // network configuration. In both cases all user accounts are deleted.
   if (install_plan_.powerwash_required) {
-    if (hardware_->SchedulePowerwash(
-            install_plan_.rollback_data_save_requested)) {
+    if (hardware_->SchedulePowerwash()) {
       powerwash_scheduled_ = true;
     } else {
       return CompletePostinstall(ErrorCode::kPostinstallPowerwashError);
@@ -327,7 +324,7 @@ void PostinstallRunnerAction::OnProgressFdReady() {
     bytes_read = 0;
     bool eof;
     bool ok =
-        utils::ReadAll(progress_fd_, buf, base::size(buf), &bytes_read, &eof);
+        utils::ReadAll(progress_fd_, buf, std::size(buf), &bytes_read, &eof);
     progress_buffer_.append(buf, bytes_read);
     // Process every line.
     vector<string> lines = base::SplitString(
diff --git a/payload_consumer/postinstall_runner_action.h b/payload_consumer/postinstall_runner_action.h
index 60170697..1a3cdf6d 100644
--- a/payload_consumer/postinstall_runner_action.h
+++ b/payload_consumer/postinstall_runner_action.h
@@ -26,7 +26,6 @@
 #include <brillo/message_loops/message_loop.h>
 #include <gtest/gtest_prod.h>
 
-#include "update_engine/common/action.h"
 #include "update_engine/common/boot_control_interface.h"
 #include "update_engine/common/hardware_interface.h"
 #include "update_engine/payload_consumer/install_plan.h"
diff --git a/payload_consumer/postinstall_runner_action_unittest.cc b/payload_consumer/postinstall_runner_action_unittest.cc
index c899599c..028402a5 100644
--- a/payload_consumer/postinstall_runner_action_unittest.cc
+++ b/payload_consumer/postinstall_runner_action_unittest.cc
@@ -29,8 +29,7 @@
 #if BASE_VER < 780000  // Android
 #include <base/message_loop/message_loop.h>
 #endif  // BASE_VER < 780000
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #if BASE_VER >= 780000  // CrOS
 #include <base/task/single_thread_task_executor.h>
 #endif  // BASE_VER >= 780000
@@ -116,7 +115,7 @@ class PostinstallRunnerActionTest : public ::testing::Test {
 
   void SuspendRunningAction() {
     if (!postinstall_action_ || !postinstall_action_->current_command_ ||
-        test_utils::Readlink(base::StringPrintf(
+        test_utils::Readlink(android::base::StringPrintf(
             "/proc/%d/fd/0", postinstall_action_->current_command_)) !=
             "/dev/zero") {
       // We need to wait for the postinstall command to start and flag that it
@@ -199,7 +198,6 @@ void PostinstallRunnerActionTest::RunPostinstallAction(
   install_plan.partitions = {part};
   install_plan.download_url = "http://127.0.0.1:8080/update";
   install_plan.powerwash_required = powerwash_required;
-  install_plan.rollback_data_save_requested = save_rollback_data;
   RunPostinstallActionWithInstallPlan(install_plan);
 }
 
diff --git a/payload_consumer/verified_source_fd.cc b/payload_consumer/verified_source_fd.cc
index d760d1ff..131f2fb6 100644
--- a/payload_consumer/verified_source_fd.cc
+++ b/payload_consumer/verified_source_fd.cc
@@ -19,12 +19,10 @@
 #include <sys/stat.h>
 
 #include <memory>
-#include <utility>
 #include <vector>
 
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
 #include "update_engine/common/error_code.h"
 #include "update_engine/common/hash_calculator.h"
@@ -91,6 +89,16 @@ FileDescriptorPtr VerifiedSourceFd::ChooseSourceFD(
     *error = ErrorCode::kSuccess;
   }
   if (!operation.has_src_sha256_hash()) {
+    if (operation.type() == InstallOperation::SOURCE_COPY) {
+      // delta_generator always adds SHA256 hash for source data. If hash is
+      // missing, the only possibility is we are doing a partial update, and
+      // currently processing a partition that's not in the payload. Data on
+      // this partition would be copied to the new slot as is. So, if the
+      // current partition boots fine(either no corruption, or with FEC), the
+      // new partition would boot fine as well. Hence, just return |source_fd_|
+      // to save time.
+      return source_fd_;
+    }
     // When the operation doesn't include a source hash, we attempt the error
     // corrected device first since we can't verify the block in the raw device
     // at this point, but we first need to make sure all extents are readable
diff --git a/payload_consumer/verity_writer_interface.h b/payload_consumer/verity_writer_interface.h
index 3ebe768c..fee31eec 100644
--- a/payload_consumer/verity_writer_interface.h
+++ b/payload_consumer/verity_writer_interface.h
@@ -20,7 +20,7 @@
 #include <cstdint>
 #include <memory>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "common/utils.h"
 #include "payload_consumer/file_descriptor.h"
diff --git a/payload_consumer/xor_extent_writer.cc b/payload_consumer/xor_extent_writer.cc
index fe7eca7b..d4f62524 100644
--- a/payload_consumer/xor_extent_writer.cc
+++ b/payload_consumer/xor_extent_writer.cc
@@ -28,7 +28,7 @@ namespace chromeos_update_engine {
 bool XORExtentWriter::WriteXorCowOp(const uint8_t* bytes,
                                     const size_t size,
                                     const Extent& xor_ext,
-                                    const size_t src_offset) {
+                                    const uint64_t src_offset) {
   xor_block_data.resize(BlockSize() * xor_ext.num_blocks());
   const auto src_block = src_offset / BlockSize();
   ssize_t bytes_read = 0;
diff --git a/payload_consumer/xor_extent_writer.h b/payload_consumer/xor_extent_writer.h
index 2074ee28..d965aba0 100644
--- a/payload_consumer/xor_extent_writer.h
+++ b/payload_consumer/xor_extent_writer.h
@@ -36,7 +36,7 @@ class XORExtentWriter : public BlockExtentWriter {
                   FileDescriptorPtr source_fd,
                   android::snapshot::ICowWriter* cow_writer,
                   const ExtentMap<const CowMergeOperation*>& xor_map,
-                  size_t partition_size)
+                  uint64_t partition_size)
       : src_extents_(op.src_extents()),
         source_fd_(source_fd),
         xor_map_(xor_map),
@@ -63,13 +63,13 @@ class XORExtentWriter : public BlockExtentWriter {
   bool WriteXorCowOp(const uint8_t* bytes,
                      const size_t size,
                      const Extent& xor_ext,
-                     size_t src_offset);
+                     uint64_t src_offset);
   const google::protobuf::RepeatedPtrField<Extent>& src_extents_;
   const FileDescriptorPtr source_fd_;
   const ExtentMap<const CowMergeOperation*>& xor_map_;
   android::snapshot::ICowWriter* cow_writer_;
   std::vector<uint8_t> xor_block_data;
-  const size_t partition_size_;
+  const uint64_t partition_size_;
 };
 
 }  // namespace chromeos_update_engine
diff --git a/payload_generator/ab_generator.cc b/payload_generator/ab_generator.cc
index 570ce458..62d608a3 100644
--- a/payload_generator/ab_generator.cc
+++ b/payload_generator/ab_generator.cc
@@ -19,7 +19,7 @@
 #include <algorithm>
 #include <utility>
 
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
 #include "update_engine/common/hash_calculator.h"
 #include "update_engine/common/utils.h"
@@ -147,7 +147,8 @@ bool ABGenerator::SplitSourceCopy(const AnnotatedOperation& original_aop,
 
     AnnotatedOperation new_aop;
     new_aop.op = new_op;
-    new_aop.name = base::StringPrintf("%s:%d", original_aop.name.c_str(), i);
+    new_aop.name =
+        android::base::StringPrintf("%s:%d", original_aop.name.c_str(), i);
     result_aops->push_back(new_aop);
   }
   if (curr_src_ext_index != original_op.src_extents().size() - 1) {
@@ -183,7 +184,8 @@ bool ABGenerator::SplitAReplaceOp(const PayloadVersion& version,
 
     AnnotatedOperation new_aop;
     new_aop.op = new_op;
-    new_aop.name = base::StringPrintf("%s:%d", original_aop.name.c_str(), i);
+    new_aop.name =
+        android::base::StringPrintf("%s:%d", original_aop.name.c_str(), i);
     TEST_AND_RETURN_FALSE(
         AddDataAndSetType(&new_aop, version, target_part_path, blob_file));
 
@@ -230,7 +232,7 @@ bool ABGenerator::MergeOperations(vector<AnnotatedOperation>* aops,
       // merge), are contiguous, are fragmented to have one destination extent,
       // and their combined block count would be less than chunk size, merge
       // them.
-      last_aop.name = base::StringPrintf(
+      last_aop.name = android::base::StringPrintf(
           "%s,%s", last_aop.name.c_str(), curr_aop.name.c_str());
 
       if (is_delta_op) {
diff --git a/payload_generator/ab_generator.h b/payload_generator/ab_generator.h
index 2accf1ef..63a40e92 100644
--- a/payload_generator/ab_generator.h
+++ b/payload_generator/ab_generator.h
@@ -20,7 +20,7 @@
 #include <string>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <brillo/secure_blob.h>
 
 #include "update_engine/payload_consumer/payload_constants.h"
diff --git a/payload_generator/annotated_operation.cc b/payload_generator/annotated_operation.cc
index 5637cb12..18924e4a 100644
--- a/payload_generator/annotated_operation.cc
+++ b/payload_generator/annotated_operation.cc
@@ -18,7 +18,7 @@
 
 #include <base/format_macros.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
 #include "update_engine/common/utils.h"
 #include "update_engine/payload_consumer/payload_constants.h"
diff --git a/payload_generator/blob_file_writer.h b/payload_generator/blob_file_writer.h
index bdd4c08c..cd33df68 100644
--- a/payload_generator/blob_file_writer.h
+++ b/payload_generator/blob_file_writer.h
@@ -17,7 +17,7 @@
 #ifndef UPDATE_ENGINE_PAYLOAD_GENERATOR_BLOB_FILE_WRITER_H_
 #define UPDATE_ENGINE_PAYLOAD_GENERATOR_BLOB_FILE_WRITER_H_
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include <base/synchronization/lock.h>
 #include <brillo/secure_blob.h>
diff --git a/payload_generator/deflate_utils.cc b/payload_generator/deflate_utils.cc
index d1967991..edd6fe13 100644
--- a/payload_generator/deflate_utils.cc
+++ b/payload_generator/deflate_utils.cc
@@ -22,7 +22,6 @@
 
 #include <base/files/file_util.h>
 #include <base/logging.h>
-#include <base/strings/string_util.h>
 
 #include "update_engine/common/utils.h"
 #include "update_engine/payload_generator/delta_diff_generator.h"
@@ -66,7 +65,7 @@ bool CopyExtentsToFile(const string& in_path,
 bool IsSquashfsImage(const string& part_path,
                      const FilesystemInterface::File& file) {
   // Only check for files with img postfix.
-  if (base::EndsWith(file.name, ".img", base::CompareCase::SENSITIVE) &&
+  if (android::base::EndsWith(file.name, ".img") &&
       utils::BlocksInExtents(file.extents) >=
           kMinimumSquashfsImageSize / kBlockSize) {
     brillo::Blob super_block;
@@ -132,9 +131,7 @@ bool IsFileExtensions(
   return any_of(extensions.begin(),
                 extensions.end(),
                 [name = ToStringPiece(name)](const auto& ext) {
-                  return base::EndsWith(name,
-                                        ToStringPiece(ext),
-                                        base::CompareCase::INSENSITIVE_ASCII);
+                  return android::base::EndsWith(ToLower(name), ToLower(ext));
                 });
 }
 
diff --git a/payload_generator/delta_diff_generator.cc b/payload_generator/delta_diff_generator.cc
index 4abff92f..eb4e5941 100644
--- a/payload_generator/delta_diff_generator.cc
+++ b/payload_generator/delta_diff_generator.cc
@@ -16,9 +16,7 @@
 
 #include "update_engine/payload_generator/delta_diff_generator.h"
 
-#include <errno.h>
 #include <fcntl.h>
-#include <inttypes.h>
 #include <sys/stat.h>
 #include <sys/types.h>
 
@@ -32,9 +30,7 @@
 #include <base/threading/simple_thread.h>
 
 #include "update_engine/common/utils.h"
-#include "update_engine/payload_consumer/delta_performer.h"
 #include "update_engine/payload_consumer/file_descriptor.h"
-#include "update_engine/payload_consumer/payload_constants.h"
 #include "update_engine/payload_generator/ab_generator.h"
 #include "update_engine/payload_generator/annotated_operation.h"
 #include "update_engine/payload_generator/blob_file_writer.h"
@@ -186,8 +182,7 @@ bool GenerateUpdatePayloadFile(const PayloadGenerationConfig& config,
     off_t data_file_size = 0;
     BlobFileWriter blob_file(data_file.fd(), &data_file_size);
     if (config.is_delta) {
-      TEST_AND_RETURN_FALSE(config.source.partitions.size() ==
-                            config.target.partitions.size());
+      TEST_EQ(config.source.partitions.size(), config.target.partitions.size());
     }
     PartitionConfig empty_part("");
     std::vector<std::vector<AnnotatedOperation>> all_aops;
@@ -200,10 +195,18 @@ bool GenerateUpdatePayloadFile(const PayloadGenerationConfig& config,
         config.target.partitions.size());
 
     std::vector<PartitionProcessor> partition_tasks{};
-    auto thread_count = std::min<int>(diff_utils::GetMaxThreads(),
-                                      config.target.partitions.size());
+    auto thread_count = std::min<size_t>(diff_utils::GetMaxThreads(),
+                                         config.target.partitions.size());
+    if (thread_count > config.max_threads && config.max_threads > 0) {
+      thread_count = config.max_threads;
+    }
+    if (thread_count < 1) {
+      thread_count = 1;
+    }
     base::DelegateSimpleThreadPool thread_pool{"partition-thread-pool",
-                                               thread_count};
+                                               static_cast<int>(thread_count)};
+    LOG(INFO) << "Using " << thread_count << " threads to process "
+              << config.target.partitions.size() << " partitions";
     for (size_t i = 0; i < config.target.partitions.size(); i++) {
       const PartitionConfig& old_part =
           config.is_delta ? config.source.partitions[i] : empty_part;
diff --git a/payload_generator/delta_diff_utils.cc b/payload_generator/delta_diff_utils.cc
index 152da4d2..033d879c 100644
--- a/payload_generator/delta_diff_utils.cc
+++ b/payload_generator/delta_diff_utils.cc
@@ -41,8 +41,7 @@
 
 #include <base/files/file_util.h>
 #include <base/format_macros.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <base/threading/simple_thread.h>
 #include <brillo/data_encoding.h>
 #include <bsdiff/bsdiff.h>
@@ -677,9 +676,12 @@ bool DeltaReadPartition(vector<AnnotatedOperation>* aops,
 
   size_t max_threads = GetMaxThreads();
 
-  if (config.max_threads > 0) {
+  if (config.max_threads > 0 && config.max_threads < max_threads) {
     max_threads = config.max_threads;
   }
+  LOG(INFO) << "Using " << max_threads << " threads to process "
+            << file_delta_processors.size() << " files on partition "
+            << old_part.name;
 
   // Sort the files in descending order based on number of new blocks to make
   // sure we start the largest ones first.
@@ -907,7 +909,7 @@ bool DeltaReadFile(std::vector<AnnotatedOperation>* aops,
     }
 
     if (static_cast<uint64_t>(chunk_blocks) < total_blocks) {
-      aop.name = base::StringPrintf(
+      aop.name = android::base::StringPrintf(
           "%s:%" PRIu64, name.c_str(), block_offset / chunk_blocks);
     }
 
@@ -1208,9 +1210,9 @@ bool IsExtFilesystem(const string& device) {
   return true;
 }
 
-// Return the number of CPUs on the machine, and 4 threads in minimum.
+// Return the number of CPUs on the machine, and 1 threads in minimum.
 size_t GetMaxThreads() {
-  return std::max(sysconf(_SC_NPROCESSORS_ONLN), 4L);
+  return std::max(sysconf(_SC_NPROCESSORS_ONLN), 1L);
 }
 
 }  // namespace diff_utils
diff --git a/payload_generator/delta_diff_utils_unittest.cc b/payload_generator/delta_diff_utils_unittest.cc
index 53bbeaad..ca6578ce 100644
--- a/payload_generator/delta_diff_utils_unittest.cc
+++ b/payload_generator/delta_diff_utils_unittest.cc
@@ -23,7 +23,7 @@
 
 #include <base/files/scoped_file.h>
 #include <base/format_macros.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <bsdiff/patch_writer.h>
 #include <gtest/gtest.h>
 #include <puffin/common.h>
@@ -95,7 +95,7 @@ bool InitializePartitionWithUniqueBlocks(const PartitionConfig& part,
   size_t num_blocks = part.size / block_size;
   brillo::Blob file_data(part.size);
   for (size_t i = 0; i < num_blocks; ++i) {
-    string prefix = base::StringPrintf(
+    string prefix = android::base::StringPrintf(
         "block tag 0x%.16" PRIx64 ", block number %16" PRIuS " ", tag, i);
     brillo::Blob block_data(prefix.begin(), prefix.end());
     TEST_AND_RETURN_FALSE(prefix.size() <= block_size);
@@ -531,7 +531,8 @@ TEST_F(DeltaDiffUtilsTest, IdenticalBlocksAreCopiedFromSource) {
 
   ASSERT_EQ(expected_op_extents.size(), aops_.size());
   for (size_t i = 0; i < aops_.size() && i < expected_op_extents.size(); ++i) {
-    SCOPED_TRACE(base::StringPrintf("Failed on operation number %" PRIuS, i));
+    SCOPED_TRACE(
+        android::base::StringPrintf("Failed on operation number %" PRIuS, i));
     const AnnotatedOperation& aop = aops_[i];
     ASSERT_EQ(InstallOperation::SOURCE_COPY, aop.op.type());
     ASSERT_EQ(1, aop.op.src_extents_size());
@@ -628,7 +629,8 @@ TEST_F(DeltaDiffUtilsTest, ZeroBlocksUseReplaceBz) {
 
   ASSERT_EQ(expected_op_extents.size(), aops_.size());
   for (size_t i = 0; i < aops_.size() && i < expected_op_extents.size(); ++i) {
-    SCOPED_TRACE(base::StringPrintf("Failed on operation number %" PRIuS, i));
+    SCOPED_TRACE(
+        android::base::StringPrintf("Failed on operation number %" PRIuS, i));
     const AnnotatedOperation& aop = aops_[i];
     ASSERT_EQ(InstallOperation::REPLACE_BZ, aop.op.type());
     ASSERT_EQ(0, aop.op.src_extents_size());
diff --git a/payload_generator/erofs_filesystem_unittest.cc b/payload_generator/erofs_filesystem_unittest.cc
index 58686c3d..43a38ece 100644
--- a/payload_generator/erofs_filesystem_unittest.cc
+++ b/payload_generator/erofs_filesystem_unittest.cc
@@ -24,8 +24,7 @@
 #include <base/format_macros.h>
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <gtest/gtest.h>
 
 #include "payload_generator/delta_diff_generator.h"
diff --git a/payload_generator/ext2_filesystem.cc b/payload_generator/ext2_filesystem.cc
index 535d8ada..062ccfed 100644
--- a/payload_generator/ext2_filesystem.cc
+++ b/payload_generator/ext2_filesystem.cc
@@ -32,7 +32,7 @@
 #include <set>
 
 #include <base/logging.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
 #include "update_engine/common/utils.h"
 #include "update_engine/payload_generator/extent_ranges.h"
@@ -196,7 +196,7 @@ bool Ext2Filesystem::GetFiles(vector<File>* files) const {
     if (it_ino == EXT2_RESIZE_INO) {
       file.name = "<group-descriptors>";
     } else {
-      file.name = base::StringPrintf("<inode-%u>", it_ino);
+      file.name = android::base::StringPrintf("<inode-%u>", it_ino);
     }
 
     memset(&file.file_stat, 0, sizeof(file.file_stat));
@@ -266,7 +266,7 @@ bool Ext2Filesystem::GetFiles(vector<File>* files) const {
       // just skiped.
       LOG(WARNING) << "Reading directory name on inode " << dir_ino
                    << " (error " << error << ")";
-      inodes[dir_ino].name = base::StringPrintf("<dir-%u>", dir_ino);
+      inodes[dir_ino].name = android::base::StringPrintf("<dir-%u>", dir_ino);
     } else {
       inodes[dir_ino].name = dir_name;
       files->push_back(inodes[dir_ino]);
diff --git a/payload_generator/ext2_filesystem_unittest.cc b/payload_generator/ext2_filesystem_unittest.cc
index 4ac72994..28f14c6f 100644
--- a/payload_generator/ext2_filesystem_unittest.cc
+++ b/payload_generator/ext2_filesystem_unittest.cc
@@ -26,8 +26,7 @@
 #include <base/format_macros.h>
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <gtest/gtest.h>
 
 #include "update_engine/common/test_utils.h"
diff --git a/payload_generator/extent_ranges.h b/payload_generator/extent_ranges.h
index bd468a11..61a4167c 100644
--- a/payload_generator/extent_ranges.h
+++ b/payload_generator/extent_ranges.h
@@ -20,7 +20,7 @@
 #include <set>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "update_engine/common/utils.h"
 #include "update_engine/payload_generator/extent_utils.h"
diff --git a/payload_generator/extent_ranges_unittest.cc b/payload_generator/extent_ranges_unittest.cc
index 5f36aa3d..28a9d93b 100644
--- a/payload_generator/extent_ranges_unittest.cc
+++ b/payload_generator/extent_ranges_unittest.cc
@@ -18,11 +18,10 @@
 
 #include <vector>
 
-#include <base/stl_util.h>
 #include <gtest/gtest.h>
 
-#include "update_engine/payload_generator/extent_utils.h"
 #include "update_engine/payload_consumer/payload_constants.h"
+#include "update_engine/payload_generator/extent_utils.h"
 
 using std::vector;
 using chromeos_update_engine::operator==;
@@ -53,7 +52,7 @@ void ExpectRangeEq(const ExtentRanges& ranges,
 }
 
 #define ASSERT_RANGE_EQ(ranges, var) \
-  ASSERT_NO_FATAL_FAILURE(ExpectRangeEq(ranges, var, base::size(var), __LINE__))
+  ASSERT_NO_FATAL_FAILURE(ExpectRangeEq(ranges, var, std::size(var), __LINE__))
 
 void ExpectRangesOverlapOrTouch(uint64_t a_start,
                                 uint64_t a_num,
diff --git a/payload_generator/extent_utils.cc b/payload_generator/extent_utils.cc
index 851db8a2..782f95b6 100644
--- a/payload_generator/extent_utils.cc
+++ b/payload_generator/extent_utils.cc
@@ -18,12 +18,13 @@
 
 #include <inttypes.h>
 
+#include <set>
 #include <string>
 #include <vector>
 
 #include <base/logging.h>
 #include <base/macros.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
 #include "update_engine/payload_consumer/payload_constants.h"
 #include "update_engine/payload_generator/extent_ranges.h"
@@ -89,9 +90,10 @@ template <typename Container>
 string ExtentsToStringTemplate(const Container& extents) {
   string ext_str;
   for (const Extent& e : extents)
-    ext_str += base::StringPrintf("[%" PRIu64 ", %" PRIu64 "] ",
-                                  static_cast<uint64_t>(e.start_block()),
-                                  static_cast<uint64_t>(e.num_blocks()));
+    ext_str +=
+        android::base::StringPrintf("[%" PRIu64 ", %" PRIu64 "] ",
+                                    static_cast<uint64_t>(e.start_block()),
+                                    static_cast<uint64_t>(e.num_blocks()));
   return ext_str;
 }
 
diff --git a/payload_generator/full_update_generator.cc b/payload_generator/full_update_generator.cc
index 4a5f63a9..2491f76b 100644
--- a/payload_generator/full_update_generator.cc
+++ b/payload_generator/full_update_generator.cc
@@ -24,8 +24,7 @@
 #include <memory>
 
 #include <base/format_macros.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <base/synchronization/lock.h>
 #include <base/threading/simple_thread.h>
 #include <brillo/secure_blob.h>
@@ -164,7 +163,7 @@ bool FullUpdateGenerator::GenerateOperations(
     // Preset all the static information about the operations. The
     // ChunkProcessor will set the rest.
     AnnotatedOperation* aop = aops->data() + i;
-    aop->name = base::StringPrintf(
+    aop->name = android::base::StringPrintf(
         "<%s-operation-%" PRIuS ">", new_part.name.c_str(), i);
     Extent* dst_extent = aop->op.add_dst_extents();
     dst_extent->set_start_block(start_block);
diff --git a/payload_generator/full_update_generator.h b/payload_generator/full_update_generator.h
index e17dd379..b6d2c965 100644
--- a/payload_generator/full_update_generator.h
+++ b/payload_generator/full_update_generator.h
@@ -20,7 +20,7 @@
 #include <string>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "update_engine/payload_generator/blob_file_writer.h"
 #include "update_engine/payload_generator/operations_generator.h"
diff --git a/payload_generator/generate_delta_main.cc b/payload_generator/generate_delta_main.cc
index 5ffd05e0..635d8011 100644
--- a/payload_generator/generate_delta_main.cc
+++ b/payload_generator/generate_delta_main.cc
@@ -26,7 +26,6 @@
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
 #include <base/strings/string_split.h>
-#include <base/strings/string_util.h>
 #include <brillo/key_value_store.h>
 #include <brillo/message_loops/base_message_loop.h>
 #include <unistd.h>
@@ -280,7 +279,7 @@ string ToString(const map<Key, Val>& map) {
   for (const auto& it : map) {
     result.emplace_back(it.first + ": " + it.second);
   }
-  return "{" + base::JoinString(result, ",") + "}";
+  return "{" + android::base::Join(result, ",") + "}";
 }
 
 bool ParsePerPartitionTimestamps(const string& partition_timestamps,
@@ -764,7 +763,9 @@ int Main(int argc, char** argv) {
 
   payload_config.security_patch_level = FLAGS_security_patch_level;
 
-  payload_config.max_threads = FLAGS_max_threads;
+  if (FLAGS_max_threads > 0) {
+    payload_config.max_threads = FLAGS_max_threads;
+  }
 
   if (!FLAGS_partition_timestamps.empty()) {
     CHECK(ParsePerPartitionTimestamps(FLAGS_partition_timestamps,
diff --git a/payload_generator/mapfile_filesystem.cc b/payload_generator/mapfile_filesystem.cc
index 5bca5770..c9b4cd50 100644
--- a/payload_generator/mapfile_filesystem.cc
+++ b/payload_generator/mapfile_filesystem.cc
@@ -19,10 +19,10 @@
 #include <algorithm>
 #include <map>
 
+#include <android-base/parseint.h>
 #include <base/files/file_util.h>
 #include <base/logging.h>
 #include <base/memory/ptr_util.h>
-#include <base/strings/string_number_conversions.h>
 #include <base/strings/string_split.h>
 
 #include "update_engine/common/utils.h"
@@ -98,11 +98,14 @@ bool MapfileFilesystem::GetFiles(vector<File>* files) const {
           line.substr(delim + 1, last_delim - (delim + 1)).as_string();
       size_t dash = blocks.find('-', 0);
       uint64_t block_start, block_end;
-      if (dash == string::npos && base::StringToUint64(blocks, &block_start)) {
+      if (dash == string::npos &&
+          android::base::ParseUint<uint64_t>(blocks, &block_start)) {
         mapped_file.extents.push_back(ExtentForRange(block_start, 1));
       } else if (dash != string::npos &&
-                 base::StringToUint64(blocks.substr(0, dash), &block_start) &&
-                 base::StringToUint64(blocks.substr(dash + 1), &block_end)) {
+                 android::base::ParseUint<uint64_t>(blocks.substr(0, dash),
+                                                    &block_start) &&
+                 android::base::ParseUint<uint64_t>(blocks.substr(dash + 1),
+                                                    &block_end)) {
         if (block_end < block_start) {
           LOG(ERROR) << "End block " << block_end
                      << " is smaller than start block " << block_start
diff --git a/payload_generator/mapfile_filesystem_unittest.cc b/payload_generator/mapfile_filesystem_unittest.cc
index 57b672b5..e3291aa6 100644
--- a/payload_generator/mapfile_filesystem_unittest.cc
+++ b/payload_generator/mapfile_filesystem_unittest.cc
@@ -25,8 +25,7 @@
 #include <base/format_macros.h>
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <gtest/gtest.h>
 
 #include "update_engine/common/test_utils.h"
diff --git a/payload_generator/operations_generator.h b/payload_generator/operations_generator.h
index 4d7322b3..c25173fa 100644
--- a/payload_generator/operations_generator.h
+++ b/payload_generator/operations_generator.h
@@ -19,7 +19,7 @@
 
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 
 #include "update_engine/payload_generator/annotated_operation.h"
 #include "update_engine/payload_generator/blob_file_writer.h"
diff --git a/payload_generator/payload_file.cc b/payload_generator/payload_file.cc
index 8f5b826b..c0362e19 100644
--- a/payload_generator/payload_file.cc
+++ b/payload_generator/payload_file.cc
@@ -18,11 +18,10 @@
 
 #include <endian.h>
 
-#include <algorithm>
 #include <map>
 #include <utility>
 
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
 #include "update_engine/common/hash_calculator.h"
 #include "update_engine/common/utils.h"
diff --git a/payload_generator/payload_generation_config.cc b/payload_generator/payload_generation_config.cc
index 839960ee..20c5e042 100644
--- a/payload_generator/payload_generation_config.cc
+++ b/payload_generator/payload_generation_config.cc
@@ -22,7 +22,6 @@
 
 #include <android-base/parseint.h>
 #include <base/logging.h>
-#include <base/strings/string_number_conversions.h>
 #include <brillo/strings/string_utils.h>
 #include <libsnapshot/cow_format.h>
 
@@ -176,7 +175,7 @@ bool ImageConfig::LoadDynamicPartitionMetadata(
     }
 
     uint64_t max_size{};
-    if (!base::StringToUint64(buf, &max_size)) {
+    if (!android::base::ParseUint<uint64_t>(buf, &max_size)) {
       LOG(ERROR) << "Group size for " << group_name << " = " << buf
                  << " is not an integer.";
       return false;
diff --git a/payload_generator/payload_generation_config.h b/payload_generator/payload_generation_config.h
index 0256a9db..7f107bb5 100644
--- a/payload_generator/payload_generation_config.h
+++ b/payload_generator/payload_generation_config.h
@@ -266,7 +266,9 @@ struct PayloadGenerationConfig {
 
   std::string security_patch_level;
 
-  uint32_t max_threads = 0;
+  // This doesn't mean we will use 256 threads, we still upper bound thread
+  // count by number of CPU cores
+  uint32_t max_threads = 256;
 
   std::vector<bsdiff::CompressorType> compressors{
       bsdiff::CompressorType::kBZ2, bsdiff::CompressorType::kBrotli};
diff --git a/payload_generator/payload_generation_config_android.cc b/payload_generator/payload_generation_config_android.cc
index d950092b..1abdd55b 100644
--- a/payload_generator/payload_generation_config_android.cc
+++ b/payload_generator/payload_generation_config_android.cc
@@ -16,6 +16,7 @@
 
 #include "update_engine/payload_generator/payload_generation_config.h"
 
+#include <android-base/parseint.h>
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
 #include <base/strings/string_split.h>
@@ -187,13 +188,13 @@ bool ImageConfig::LoadVerityConfig() {
               base::StringToSizeT(verity_table[4], &hash_block_size));
           TEST_AND_RETURN_FALSE(block_size == hash_block_size);
           uint64_t num_data_blocks = 0;
-          TEST_AND_RETURN_FALSE(
-              base::StringToUint64(verity_table[5], &num_data_blocks));
+          TEST_AND_RETURN_FALSE(android::base::ParseUint<uint64_t>(
+              verity_table[5], &num_data_blocks));
           part.verity.hash_tree_data_extent =
               ExtentForRange(0, num_data_blocks);
           uint64_t hash_start_block = 0;
-          TEST_AND_RETURN_FALSE(
-              base::StringToUint64(verity_table[6], &hash_start_block));
+          TEST_AND_RETURN_FALSE(android::base::ParseUint<uint64_t>(
+              verity_table[6], &hash_start_block));
           part.verity.hash_tree_algorithm = verity_table[7];
           TEST_AND_RETURN_FALSE(base::HexStringToBytes(
               verity_table[9], &part.verity.hash_tree_salt));
diff --git a/payload_generator/payload_properties.cc b/payload_generator/payload_properties.cc
index d47c0599..60c682a6 100644
--- a/payload_generator/payload_properties.cc
+++ b/payload_generator/payload_properties.cc
@@ -22,7 +22,6 @@
 #include <vector>
 
 #include <base/json/json_writer.h>
-#include <base/strings/string_util.h>
 #include <base/values.h>
 #include <brillo/data_encoding.h>
 
@@ -118,7 +117,7 @@ bool PayloadProperties::LoadFromPayload() {
       base64_signatures.push_back(
           brillo::data_encoding::Base64Encode(sig.data()));
     }
-    metadata_signatures_ = base::JoinString(base64_signatures, ":");
+    metadata_signatures_ = android::base::Join(base64_signatures, ":");
   }
 
   is_delta_ = std::any_of(manifest.partitions().begin(),
diff --git a/payload_generator/payload_properties_unittest.cc b/payload_generator/payload_properties_unittest.cc
index b4bfb810..1545d4c0 100644
--- a/payload_generator/payload_properties_unittest.cc
+++ b/payload_generator/payload_properties_unittest.cc
@@ -24,7 +24,7 @@
 #include <base/files/scoped_file.h>
 #include <base/files/scoped_temp_dir.h>
 #include <base/rand_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <brillo/data_encoding.h>
 
 #include <gtest/gtest.h>
diff --git a/payload_generator/payload_signer.cc b/payload_generator/payload_signer.cc
index 11e136fb..b661a92c 100644
--- a/payload_generator/payload_signer.cc
+++ b/payload_generator/payload_signer.cc
@@ -23,8 +23,6 @@
 
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_split.h>
-#include <base/strings/string_util.h>
 #include <brillo/data_encoding.h>
 #include <openssl/err.h>
 #include <openssl/pem.h>
diff --git a/payload_generator/payload_signer.h b/payload_generator/payload_signer.h
index 9676b718..297a54e1 100644
--- a/payload_generator/payload_signer.h
+++ b/payload_generator/payload_signer.h
@@ -20,7 +20,7 @@
 #include <string>
 #include <vector>
 
-#include <base/macros.h>
+#include <android-base/macros.h>
 #include <brillo/key_value_store.h>
 #include <brillo/secure_blob.h>
 
diff --git a/payload_generator/payload_signer_unittest.cc b/payload_generator/payload_signer_unittest.cc
index 96e44317..ac11fcfd 100644
--- a/payload_generator/payload_signer_unittest.cc
+++ b/payload_generator/payload_signer_unittest.cc
@@ -20,7 +20,6 @@
 #include <vector>
 
 #include <base/logging.h>
-#include <base/stl_util.h>
 #include <gtest/gtest.h>
 
 #include "update_engine/common/hash_calculator.h"
@@ -111,8 +110,8 @@ TEST_F(PayloadSignerTest, SignSimpleTextTest) {
   EXPECT_EQ(1, signatures.signatures_size());
   const Signatures::Signature& sig = signatures.signatures(0);
   const string& sig_data = sig.data();
-  ASSERT_EQ(base::size(kDataSignature), sig_data.size());
-  for (size_t i = 0; i < base::size(kDataSignature); i++) {
+  ASSERT_EQ(std::size(kDataSignature), sig_data.size());
+  for (size_t i = 0; i < std::size(kDataSignature); i++) {
     EXPECT_EQ(kDataSignature[i], static_cast<uint8_t>(sig_data[i]));
   }
 }
diff --git a/payload_generator/squashfs_filesystem_unittest.cc b/payload_generator/squashfs_filesystem_unittest.cc
index 68ca9df2..87eacf2c 100644
--- a/payload_generator/squashfs_filesystem_unittest.cc
+++ b/payload_generator/squashfs_filesystem_unittest.cc
@@ -27,8 +27,7 @@
 #include <base/format_macros.h>
 #include <base/logging.h>
 #include <base/strings/string_number_conversions.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 #include <gtest/gtest.h>
 
 #include "update_engine/common/test_utils.h"
diff --git a/payload_generator/xz_android.cc b/payload_generator/xz_android.cc
index 97e2c32a..1c93a6b2 100644
--- a/payload_generator/xz_android.cc
+++ b/payload_generator/xz_android.cc
@@ -18,10 +18,10 @@
 
 #include <algorithm>
 
+#include <android-base/logging.h>
 #include <7zCrc.h>
 #include <Xz.h>
 #include <XzEnc.h>
-#include <base/logging.h>
 
 namespace {
 
diff --git a/payload_generator/xz_chromeos.cc b/payload_generator/xz_chromeos.cc
deleted file mode 100644
index 2ff9458b..00000000
--- a/payload_generator/xz_chromeos.cc
+++ /dev/null
@@ -1,54 +0,0 @@
-//
-// Copyright (C) 2016 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-
-#include "update_engine/payload_generator/xz.h"
-
-#include <base/logging.h>
-#include <lzma.h>
-
-namespace chromeos_update_engine {
-
-void XzCompressInit() {}
-
-bool XzCompress(const brillo::Blob& in, brillo::Blob* out) {
-  out->clear();
-  if (in.empty())
-    return true;
-
-  // Resize the output buffer to get enough memory for writing the compressed
-  // data.
-  out->resize(lzma_stream_buffer_bound(in.size()));
-
-  const uint32_t kLzmaPreset = 6;
-  size_t out_pos = 0;
-  int rc = lzma_easy_buffer_encode(kLzmaPreset,
-                                   LZMA_CHECK_NONE,  // We do not need CRC.
-                                   nullptr,
-                                   in.data(),
-                                   in.size(),
-                                   out->data(),
-                                   &out_pos,
-                                   out->size());
-  if (rc != LZMA_OK) {
-    LOG(ERROR) << "Failed to compress data to LZMA stream with return code: "
-               << rc;
-    return false;
-  }
-  out->resize(out_pos);
-  return true;
-}
-
-}  // namespace chromeos_update_engine
diff --git a/stable/Android.bp b/stable/Android.bp
index 59165a71..2e7bab6a 100644
--- a/stable/Android.bp
+++ b/stable/Android.bp
@@ -58,6 +58,11 @@ aidl_interface {
             version: "2",
             imports: [],
         },
+        {
+            version: "3",
+            imports: [],
+        },
+
     ],
     frozen: true,
 
diff --git a/stable/aidl_api/libupdate_engine_stable/3/.hash b/stable/aidl_api/libupdate_engine_stable/3/.hash
new file mode 100644
index 00000000..df3180c9
--- /dev/null
+++ b/stable/aidl_api/libupdate_engine_stable/3/.hash
@@ -0,0 +1 @@
+9563bb511840955a304b5eb06c39710c56e81559
diff --git a/stable/aidl_api/libupdate_engine_stable/3/android/os/IUpdateEngineStable.aidl b/stable/aidl_api/libupdate_engine_stable/3/android/os/IUpdateEngineStable.aidl
new file mode 100644
index 00000000..2e7b23a0
--- /dev/null
+++ b/stable/aidl_api/libupdate_engine_stable/3/android/os/IUpdateEngineStable.aidl
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.os;
+/* @hide */
+interface IUpdateEngineStable {
+  /* @hide */
+  void applyPayloadFd(in ParcelFileDescriptor pfd, in long payload_offset, in long payload_size, in String[] headerKeyValuePairs);
+  /* @hide */
+  boolean bind(android.os.IUpdateEngineStableCallback callback);
+  /* @hide */
+  boolean unbind(android.os.IUpdateEngineStableCallback callback);
+  /* @hide */
+  void triggerPostinstall(in String partition);
+}
diff --git a/stable/aidl_api/libupdate_engine_stable/3/android/os/IUpdateEngineStableCallback.aidl b/stable/aidl_api/libupdate_engine_stable/3/android/os/IUpdateEngineStableCallback.aidl
new file mode 100644
index 00000000..c09fa43b
--- /dev/null
+++ b/stable/aidl_api/libupdate_engine_stable/3/android/os/IUpdateEngineStableCallback.aidl
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+///////////////////////////////////////////////////////////////////////////////
+// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
+///////////////////////////////////////////////////////////////////////////////
+
+// This file is a snapshot of an AIDL file. Do not edit it manually. There are
+// two cases:
+// 1). this is a frozen version file - do not edit this in any case.
+// 2). this is a 'current' file. If you make a backwards compatible change to
+//     the interface (from the latest frozen version), the build system will
+//     prompt you to update this file with `m <name>-update-api`.
+//
+// You must not make a backward incompatible change to any AIDL file built
+// with the aidl_interface module type with versions property set. The module
+// type is used to build AIDL files in a way that they can be used across
+// independently updatable components of the system. If a device is shipped
+// with such a backward incompatible change, it has a high risk of breaking
+// later when a module using the interface is updated, e.g., Mainline modules.
+
+package android.os;
+/* @hide */
+interface IUpdateEngineStableCallback {
+  /* @hide */
+  oneway void onStatusUpdate(int status_code, float percentage);
+  /* @hide */
+  oneway void onPayloadApplicationComplete(int error_code);
+}
diff --git a/stable/aidl_api/libupdate_engine_stable/current/android/os/IUpdateEngineStable.aidl b/stable/aidl_api/libupdate_engine_stable/current/android/os/IUpdateEngineStable.aidl
index 43e8dd01..2e7b23a0 100644
--- a/stable/aidl_api/libupdate_engine_stable/current/android/os/IUpdateEngineStable.aidl
+++ b/stable/aidl_api/libupdate_engine_stable/current/android/os/IUpdateEngineStable.aidl
@@ -40,4 +40,6 @@ interface IUpdateEngineStable {
   boolean bind(android.os.IUpdateEngineStableCallback callback);
   /* @hide */
   boolean unbind(android.os.IUpdateEngineStableCallback callback);
+  /* @hide */
+  void triggerPostinstall(in String partition);
 }
diff --git a/stable/android/os/IUpdateEngineStable.aidl b/stable/android/os/IUpdateEngineStable.aidl
index a38ba896..f9ddd39e 100644
--- a/stable/android/os/IUpdateEngineStable.aidl
+++ b/stable/android/os/IUpdateEngineStable.aidl
@@ -80,4 +80,25 @@ interface IUpdateEngineStable {
    * @hide
    */
   boolean unbind(IUpdateEngineStableCallback callback);
+
+
+  /**
+   * Run postinstall scripts for the given |partition|
+   * This allows developers to run postinstall for a partition at
+   * a time they see fit. For example, they may wish to run postinstall
+   * script when device is IDLE and charging. This method would return
+   * immediately if |partition| is empty or does not correspond to any
+   * partitions on device. |partition| is expected to be unsuffixed, for
+   * example system,product,system_ext, etc.
+   * It is allowed to call this function multiple times with the same
+   * partition. Postinstall script for that partition would get run more
+   * than once. Owners of postinstall scripts should be designed to work
+   * correctly in such cases(idempotent). Note this expectation holds even
+   * without this API, and it has been so for years.
+   * @param Name of thje partition to run postinstall scripts. Should not
+   * contain slot suffix.(e.g. system,product,system_ext)
+   *
+   * @hide
+   */
+  void triggerPostinstall(in String partition);
 }
diff --git a/test_http_server.cc b/test_http_server.cc
index ba5e9acf..2e07a23c 100644
--- a/test_http_server.cc
+++ b/test_http_server.cc
@@ -23,7 +23,6 @@
 // GET a url.
 
 #include <err.h>
-#include <errno.h>
 #include <fcntl.h>
 #include <inttypes.h>
 #include <netinet/in.h>
@@ -36,16 +35,15 @@
 #include <sys/types.h>
 #include <unistd.h>
 
-#include <algorithm>
 #include <string>
 #include <vector>
 
 #include <base/logging.h>
 #include <base/posix/eintr_wrapper.h>
 #include <base/strings/string_split.h>
-#include <base/strings/string_util.h>
-#include <base/strings/stringprintf.h>
+#include <android-base/stringprintf.h>
 
+#include "android-base/strings.h"
 #include "update_engine/common/http_common.h"
 
 // HTTP end-of-line delimiter; sorry, this needs to be a macro.
@@ -88,7 +86,7 @@ bool ParseRequest(int fd, HttpRequest* request) {
       exit(RC_ERR_READ);
     }
     headers.append(buf, r);
-  } while (!base::EndsWith(headers, EOL EOL, base::CompareCase::SENSITIVE));
+  } while (!android::base::EndsWith(headers, EOL EOL));
 
   LOG(INFO) << "got headers:\n--8<------8<------8<------8<----\n"
             << headers << "\n--8<------8<------8<------8<----";
@@ -102,10 +100,7 @@ bool ParseRequest(int fd, HttpRequest* request) {
       base::SPLIT_WANT_ALL);
 
   // Decode URL line.
-  vector<string> terms = base::SplitString(lines[0],
-                                           base::kWhitespaceASCII,
-                                           base::KEEP_WHITESPACE,
-                                           base::SPLIT_WANT_NONEMPTY);
+  vector<string> terms = android::base::Tokenize(lines[0], " ");
   CHECK_EQ(terms.size(), static_cast<vector<string>::size_type>(3));
   CHECK_EQ(terms[0], "GET");
   request->url = terms[1];
@@ -114,31 +109,28 @@ bool ParseRequest(int fd, HttpRequest* request) {
   // Decode remaining lines.
   size_t i{};
   for (i = 1; i < lines.size(); i++) {
-    terms = base::SplitString(lines[i],
-                              base::kWhitespaceASCII,
-                              base::KEEP_WHITESPACE,
-                              base::SPLIT_WANT_NONEMPTY);
+    terms = android::base::Tokenize(lines[i], " ");
 
     if (terms[0] == "Range:") {
       CHECK_EQ(terms.size(), static_cast<vector<string>::size_type>(2));
       string& range = terms[1];
       LOG(INFO) << "range attribute: " << range;
-      CHECK(base::StartsWith(range, "bytes=", base::CompareCase::SENSITIVE) &&
+      CHECK(android::base::StartsWith(range, "bytes=") &&
             range.find('-') != string::npos);
       request->start_offset = atoll(range.c_str() + strlen("bytes="));
       // Decode end offset and increment it by one (so it is non-inclusive).
       if (range.find('-') < range.length() - 1)
         request->end_offset = atoll(range.c_str() + range.find('-') + 1) + 1;
       request->return_code = kHttpResponsePartialContent;
-      string tmp_str = base::StringPrintf(
+      string tmp_str = android::base::StringPrintf(
           "decoded range offsets: "
           "start=%jd end=",
           (intmax_t)request->start_offset);
       if (request->end_offset > 0)
-        base::StringAppendF(
+        android::base::StringAppendF(
             &tmp_str, "%jd (non-inclusive)", (intmax_t)request->end_offset);
       else
-        base::StringAppendF(&tmp_str, "unspecified");
+        android::base::StringAppendF(&tmp_str, "unspecified");
       LOG(INFO) << tmp_str;
     } else if (terms[0] == "Host:") {
       CHECK_EQ(terms.size(), static_cast<vector<string>::size_type>(2));
@@ -531,11 +523,10 @@ void HandleConnection(int fd) {
   LOG(INFO) << "pid(" << getpid() << "): handling url " << url;
   if (url == "/quitquitquit") {
     HandleQuit(fd);
-  } else if (base::StartsWith(
-                 url, "/download/", base::CompareCase::SENSITIVE)) {
+  } else if (android::base::StartsWith(url, "/download/")) {
     const UrlTerms terms(url, 2);
     HandleGet(fd, request, terms.GetSizeT(1));
-  } else if (base::StartsWith(url, "/flaky/", base::CompareCase::SENSITIVE)) {
+  } else if (android::base::StartsWith(url, "/flaky/")) {
     const UrlTerms terms(url, 5);
     HandleGet(fd,
               request,
@@ -547,8 +538,7 @@ void HandleConnection(int fd) {
     HandleRedirect(fd, request);
   } else if (url == "/error") {
     HandleError(fd, request);
-  } else if (base::StartsWith(
-                 url, "/error-if-offset/", base::CompareCase::SENSITIVE)) {
+  } else if (android::base::StartsWith(url, "/error-if-offset/")) {
     const UrlTerms terms(url, 3);
     HandleErrorIfOffset(fd, request, terms.GetSizeT(1), terms.GetInt(2));
   } else if (url == "/echo-headers") {
@@ -642,7 +632,8 @@ int main(int argc, char** argv) {
   // unit tests, avoid unilateral changes; (b) it is necessary to flush/sync the
   // file to prevent the spawning process from waiting indefinitely for this
   // message.
-  string listening_msg = base::StringPrintf("%s%hu", kListeningMsgPrefix, port);
+  string listening_msg =
+      android::base::StringPrintf("%s%hu", kListeningMsgPrefix, port);
   LOG(INFO) << listening_msg;
   CHECK_EQ(write(report_fd, listening_msg.c_str(), listening_msg.length()),
            static_cast<int>(listening_msg.length()));
diff --git a/update_status_utils.cc b/update_status_utils.cc
index 6b96dda6..6b23d4fe 100644
--- a/update_status_utils.cc
+++ b/update_status_utils.cc
@@ -16,7 +16,6 @@
 #include "update_engine/update_status_utils.h"
 
 #include <base/logging.h>
-#include <base/strings/string_number_conversions.h>
 #include <brillo/key_value_store.h>
 
 using brillo::KeyValueStore;
@@ -98,10 +97,9 @@ string UpdateEngineStatusToString(const UpdateEngineStatus& status) {
   KeyValueStore key_value_store;
 
   key_value_store.SetString(kLastCheckedTime,
-                            base::NumberToString(status.last_checked_time));
-  key_value_store.SetString(kProgress, base::NumberToString(status.progress));
-  key_value_store.SetString(kNewSize,
-                            base::NumberToString(status.new_size_bytes));
+                            std::format("{}", status.last_checked_time));
+  key_value_store.SetString(kProgress, std::format("{}", status.progress));
+  key_value_store.SetString(kNewSize, std::format("{}", status.new_size_bytes));
   key_value_store.SetString(kCurrentOp, UpdateStatusToString(status.status));
   key_value_store.SetString(kNewVersion, status.new_version);
   key_value_store.SetBoolean(kIsEnterpriseRollback,
```

