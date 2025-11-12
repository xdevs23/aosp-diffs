```diff
diff --git a/README.md b/README.md
index fad6eaa4..4e9f13e7 100644
--- a/README.md
+++ b/README.md
@@ -50,6 +50,7 @@ with source and destination builds. This script requires target_file.zip to work
 image files are not sufficient.
 
 ### Distribution/Configuration
+
 Once the OTA packages are generated, they are signed with specific keys
 and stored in a location known to an update server (GOTA).
 GOTA will then make this OTA package accessible via a public URL. Optionally,
@@ -57,6 +58,7 @@ operators an choose to make this OTA update available only to a specific
 subset of devices.
 
 ### Installation
+
 When the device's updater client initiates an update (either periodically or user
 initiated), it first consults different device policies to see if the update
 check is allowed. For example, device policies can prevent an update check
@@ -67,8 +69,8 @@ Once policies allow for the update check, the updater client sends a request to
 the update server (all this communication happens over HTTPS) and identifies its
 parameters like its Application ID, hardware ID, version, board, etc.
 
-Some policities on the server might prevent the device from getting specific
-OTA updates, these server side policities are often set by operators. For
+Some policies on the server might prevent the device from getting specific
+OTA updates, these server side policies are often set by operators. For
 example, the operator might want to deliver a beta version of software to only
 a subset of devices.
 
@@ -81,7 +83,9 @@ the update, or reports that the update failed with specific error codes, etc.
 
 The device will then proceed to actually installing the OTA update. This consists
 of roughly 3 steps.
+
 #### Download & Install
+
 Each payload consists of two main sections: metadata and extra data. The
 metadata is basically a list of operations that should be performed for an
 update. The extra data contains the data blobs needed by some or all of these
@@ -111,7 +115,7 @@ payload). If the signature cannot be verified, the update is rejected.
 
 After the inactive partition is updated, the updater client will compute
 Forward-Error-Correction(also known as FEC, Verity) code for each partition,
-and wriee the computed verity data to inactive partitions. In some updates,
+and write the computed verity data to inactive partitions. In some updates,
 verity data is included in the extra data, so this step will be skipped.
 
 Then, the entire partition is re-read, hashed and compared to a hash value
diff --git a/aosp/cleanup_previous_update_action.cc b/aosp/cleanup_previous_update_action.cc
index 9c0843cc..bd41630a 100644
--- a/aosp/cleanup_previous_update_action.cc
+++ b/aosp/cleanup_previous_update_action.cc
@@ -518,9 +518,6 @@ void CleanupPreviousUpdateAction::ReportMergeStats() {
   auto passed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
       result->merge_time());
 
-  bool vab_retrofit = boot_control_->GetDynamicPartitionControl()
-                          ->GetVirtualAbFeatureFlag()
-                          .IsRetrofit();
   bool vab_compression_enabled = boot_control_->GetDynamicPartitionControl()
                                      ->GetVirtualAbCompressionFeatureFlag()
                                      .IsEnabled();
@@ -551,7 +548,7 @@ void CleanupPreviousUpdateAction::ReportMergeStats() {
                       static_cast<int32_t>(report.state()),
                       static_cast<int64_t>(passed_ms.count()),
                       static_cast<int32_t>(report.resume_count()),
-                      vab_retrofit,
+                      false, /* vab retrofit */
                       static_cast<int64_t>(report.cow_file_size()),
                       vab_compression_enabled,
                       vab_compression_used,
diff --git a/aosp/dynamic_partition_control_android.cc b/aosp/dynamic_partition_control_android.cc
index b10be762..d736b3b2 100644
--- a/aosp/dynamic_partition_control_android.cc
+++ b/aosp/dynamic_partition_control_android.cc
@@ -77,10 +77,7 @@ using android::snapshot::UpdateState;
 namespace chromeos_update_engine {
 
 constexpr char kUseDynamicPartitions[] = "ro.boot.dynamic_partitions";
-constexpr char kRetrfoitDynamicPartitions[] =
-    "ro.boot.dynamic_partitions_retrofit";
 constexpr char kVirtualAbEnabled[] = "ro.virtual_ab.enabled";
-constexpr char kVirtualAbRetrofit[] = "ro.virtual_ab.retrofit";
 constexpr char kVirtualAbCompressionEnabled[] =
     "ro.virtual_ab.compression.enabled";
 constexpr auto&& kVirtualAbCompressionXorEnabled =
@@ -131,9 +128,8 @@ static FeatureFlag GetFeatureFlag(const char* enable_prop,
 
 DynamicPartitionControlAndroid::DynamicPartitionControlAndroid(
     uint32_t source_slot)
-    : dynamic_partitions_(
-          GetFeatureFlag(kUseDynamicPartitions, kRetrfoitDynamicPartitions)),
-      virtual_ab_(GetFeatureFlag(kVirtualAbEnabled, kVirtualAbRetrofit)),
+    : dynamic_partitions_(GetFeatureFlag(kUseDynamicPartitions, nullptr)),
+      virtual_ab_(GetFeatureFlag(kVirtualAbEnabled, nullptr)),
       virtual_ab_compression_(GetFeatureFlag(kVirtualAbCompressionEnabled,
                                              kVirtualAbCompressionRetrofit)),
       virtual_ab_compression_xor_(
@@ -426,24 +422,15 @@ bool DynamicPartitionControlAndroid::StoreMetadata(
     return false;
   }
 
-  if (GetDynamicPartitionsFeatureFlag().IsRetrofit()) {
-    if (!FlashPartitionTable(super_device, *metadata)) {
-      LOG(ERROR) << "Cannot write metadata to " << super_device;
-      return false;
-    }
-    LOG(INFO) << "Written metadata to " << super_device;
-  } else {
-    if (!UpdatePartitionTable(super_device, *metadata, target_slot)) {
-      LOG(ERROR) << "Cannot write metadata to slot "
-                 << BootControlInterface::SlotName(target_slot) << " in "
-                 << super_device;
-      return false;
-    }
-    LOG(INFO) << "Copied metadata to slot "
-              << BootControlInterface::SlotName(target_slot) << " in "
-              << super_device;
+  if (!UpdatePartitionTable(super_device, *metadata, target_slot)) {
+    LOG(ERROR) << "Cannot write metadata to slot "
+               << BootControlInterface::SlotName(target_slot) << " in "
+               << super_device;
+    return false;
   }
-
+  LOG(INFO) << "Copied metadata to slot "
+            << BootControlInterface::SlotName(target_slot) << " in "
+            << super_device;
   return true;
 }
 
@@ -730,19 +717,6 @@ bool DynamicPartitionControlAndroid::GetSystemOtherPath(
     return true;
   }
 
-  if (!IsRecovery()) {
-    // Found unexpected avb_keys for system_other on devices retrofitting
-    // dynamic partitions. Previous crash in update_engine may leave logical
-    // partitions mapped on physical system_other partition. It is difficult to
-    // handle these cases. Just fail.
-    if (GetDynamicPartitionsFeatureFlag().IsRetrofit()) {
-      LOG(ERROR) << "Cannot erase AVB footer on system_other on devices with "
-                 << "retrofit dynamic partitions. They should not have AVB "
-                 << "enabled on system_other.";
-      return false;
-    }
-  }
-
   std::string device_dir_str;
   TEST_AND_RETURN_FALSE(GetDeviceDir(&device_dir_str));
   base::FilePath device_dir(device_dir_str);
@@ -754,8 +728,7 @@ bool DynamicPartitionControlAndroid::GetSystemOtherPath(
     return true;
   }
 
-  auto source_super_device =
-      device_dir.Append(GetSuperPartitionName(source_slot)).value();
+  auto source_super_device = device_dir.Append(GetSuperPartitionName()).value();
 
   auto builder = LoadMetadataBuilder(source_super_device, source_slot);
   if (builder == nullptr) {
@@ -879,8 +852,7 @@ bool DynamicPartitionControlAndroid::PrepareDynamicPartitionsForUpdate(
   std::string device_dir_str;
   TEST_AND_RETURN_FALSE(GetDeviceDir(&device_dir_str));
   base::FilePath device_dir(device_dir_str);
-  auto source_device =
-      device_dir.Append(GetSuperPartitionName(source_slot)).value();
+  auto source_device = device_dir.Append(GetSuperPartitionName()).value();
 
   auto builder = LoadMetadataBuilder(source_device, source_slot, target_slot);
   if (builder == nullptr) {
@@ -897,21 +869,13 @@ bool DynamicPartitionControlAndroid::PrepareDynamicPartitionsForUpdate(
   TEST_AND_RETURN_FALSE(
       UpdatePartitionMetadata(builder.get(), target_slot, manifest));
 
-  auto target_device =
-      device_dir.Append(GetSuperPartitionName(target_slot)).value();
+  auto target_device = device_dir.Append(GetSuperPartitionName()).value();
 
   return StoreMetadata(target_device, builder.get(), target_slot);
 }
 
 DynamicPartitionControlAndroid::SpaceLimit
 DynamicPartitionControlAndroid::GetSpaceLimit(bool use_snapshot) {
-  // On device retrofitting dynamic partitions, allocatable_space = "super",
-  // where "super" is the sum of all block devices for that slot. Since block
-  // devices are dedicated for the corresponding slot, there's no need to halve
-  // the allocatable space.
-  if (GetDynamicPartitionsFeatureFlag().IsRetrofit())
-    return SpaceLimit::ERROR_IF_EXCEEDED_SUPER;
-
   // On device launching dynamic partitions w/o VAB, regardless of recovery
   // sideload, super partition must be big enough to hold both A and B slots of
   // groups. Hence,
@@ -919,33 +883,7 @@ DynamicPartitionControlAndroid::GetSpaceLimit(bool use_snapshot) {
   if (!GetVirtualAbFeatureFlag().IsEnabled())
     return SpaceLimit::ERROR_IF_EXCEEDED_HALF_OF_SUPER;
 
-  // Source build supports VAB. Super partition must be big enough to hold
-  // one slot of groups (ERROR_IF_EXCEEDED_SUPER). However, there are cases
-  // where additional warning messages needs to be written.
-
-  // If using snapshot updates, implying that target build also uses VAB,
-  // allocatable_space = super
-  if (use_snapshot)
-    return SpaceLimit::ERROR_IF_EXCEEDED_SUPER;
-
-  // Source build supports VAB but not using snapshot updates. There are
-  // several cases, as listed below.
-  // Sideloading: allocatable_space = super.
-  if (IsRecovery())
-    return SpaceLimit::ERROR_IF_EXCEEDED_SUPER;
-
-  // On launch VAB device, this implies secondary payload.
-  // Technically, we don't have to check anything, but sum(groups) < super
-  // still applies.
-  if (!GetVirtualAbFeatureFlag().IsRetrofit())
-    return SpaceLimit::ERROR_IF_EXCEEDED_SUPER;
-
-  // On retrofit VAB device, either of the following:
-  // - downgrading: allocatable_space = super / 2
-  // - secondary payload: don't check anything
-  // These two cases are indistinguishable,
-  // hence emit warning if sum(groups) > super / 2
-  return SpaceLimit::WARN_IF_EXCEEDED_HALF_OF_SUPER;
+  return SpaceLimit::ERROR_IF_EXCEEDED_SUPER;
 }
 
 bool DynamicPartitionControlAndroid::CheckSuperPartitionAllocatableSpace(
@@ -1017,8 +955,7 @@ bool DynamicPartitionControlAndroid::PrepareSnapshotPartitionsForUpdate(
   std::string device_dir_str;
   TEST_AND_RETURN_FALSE(GetDeviceDir(&device_dir_str));
   base::FilePath device_dir(device_dir_str);
-  auto super_device =
-      device_dir.Append(GetSuperPartitionName(source_slot)).value();
+  auto super_device = device_dir.Append(GetSuperPartitionName()).value();
   auto builder = LoadMetadataBuilder(super_device, source_slot);
   if (builder == nullptr) {
     LOG(ERROR) << "No metadata at "
@@ -1045,9 +982,8 @@ bool DynamicPartitionControlAndroid::PrepareSnapshotPartitionsForUpdate(
   return true;
 }
 
-std::string DynamicPartitionControlAndroid::GetSuperPartitionName(
-    uint32_t slot) {
-  return fs_mgr_get_super_partition_name(slot);
+std::string DynamicPartitionControlAndroid::GetSuperPartitionName() {
+  return fs_mgr_get_super_partition_name();
 }
 
 bool DynamicPartitionControlAndroid::UpdatePartitionMetadata(
@@ -1252,7 +1188,7 @@ bool DynamicPartitionControlAndroid::IsSuperBlockDevice(
     uint32_t current_slot,
     const std::string& partition_name_suffix) {
   std::string source_device =
-      device_dir.Append(GetSuperPartitionName(current_slot)).value();
+      device_dir.Append(GetSuperPartitionName()).value();
   auto source_metadata = LoadMetadataBuilder(source_device, current_slot);
   return source_metadata->HasBlockDevice(partition_name_suffix);
 }
@@ -1265,8 +1201,7 @@ DynamicPartitionControlAndroid::GetDynamicPartitionDevice(
     uint32_t current_slot,
     bool not_in_payload,
     std::string* device) {
-  std::string super_device =
-      device_dir.Append(GetSuperPartitionName(slot)).value();
+  std::string super_device = device_dir.Append(GetSuperPartitionName()).value();
   auto device_name = GetDeviceName(partition_name_suffix, slot);
 
   auto builder = LoadMetadataBuilder(super_device, slot);
@@ -1421,7 +1356,7 @@ bool DynamicPartitionControlAndroid::ListDynamicPartitionsForSlot(
   std::string device_dir_str;
   TEST_AND_RETURN_FALSE(GetDeviceDir(&device_dir_str));
   base::FilePath device_dir(device_dir_str);
-  auto super_device = device_dir.Append(GetSuperPartitionName(slot)).value();
+  auto super_device = device_dir.Append(GetSuperPartitionName()).value();
   auto builder = LoadMetadataBuilder(super_device, slot);
   TEST_AND_RETURN_FALSE(builder != nullptr);
 
@@ -1448,13 +1383,11 @@ bool DynamicPartitionControlAndroid::VerifyExtentsForUntouchedPartitions(
   TEST_AND_RETURN_FALSE(GetDeviceDir(&device_dir_str));
   base::FilePath device_dir(device_dir_str);
 
-  auto source_super_device =
-      device_dir.Append(GetSuperPartitionName(source_slot)).value();
+  auto source_super_device = device_dir.Append(GetSuperPartitionName()).value();
   auto source_builder = LoadMetadataBuilder(source_super_device, source_slot);
   TEST_AND_RETURN_FALSE(source_builder != nullptr);
 
-  auto target_super_device =
-      device_dir.Append(GetSuperPartitionName(target_slot)).value();
+  auto target_super_device = device_dir.Append(GetSuperPartitionName()).value();
   auto target_builder = LoadMetadataBuilder(target_super_device, target_slot);
   TEST_AND_RETURN_FALSE(target_builder != nullptr);
 
@@ -1537,7 +1470,7 @@ std::optional<base::FilePath> DynamicPartitionControlAndroid::GetSuperDevice() {
     return {};
   }
   base::FilePath device_dir(device_dir_str);
-  auto super_device = device_dir.Append(GetSuperPartitionName(target_slot_));
+  auto super_device = device_dir.Append(GetSuperPartitionName());
   return super_device;
 }
 
diff --git a/aosp/dynamic_partition_control_android.h b/aosp/dynamic_partition_control_android.h
index e5ba86a3..15642448 100644
--- a/aosp/dynamic_partition_control_android.h
+++ b/aosp/dynamic_partition_control_android.h
@@ -136,8 +136,7 @@ class DynamicPartitionControlAndroid : public DynamicPartitionControlInterface {
 
   // Retrieves metadata from |super_device| at slot |source_slot|. And
   // modifies the metadata so that during updates, the metadata can be written
-  // to |target_slot|. In particular, on retrofit devices, the returned
-  // metadata automatically includes block devices at |target_slot|.
+  // to |target_slot|.
   virtual std::unique_ptr<android::fs_mgr::MetadataBuilder> LoadMetadataBuilder(
       const std::string& super_device,
       uint32_t source_slot,
@@ -178,7 +177,7 @@ class DynamicPartitionControlAndroid : public DynamicPartitionControlInterface {
 
   // Return the name of the super partition (which stores super partition
   // metadata) for a given slot.
-  virtual std::string GetSuperPartitionName(uint32_t slot);
+  virtual std::string GetSuperPartitionName();
 
   virtual void set_fake_mapped_devices(const std::set<std::string>& fake);
 
diff --git a/aosp/dynamic_partition_control_android_unittest.cc b/aosp/dynamic_partition_control_android_unittest.cc
index 68223948..3d741ac1 100644
--- a/aosp/dynamic_partition_control_android_unittest.cc
+++ b/aosp/dynamic_partition_control_android_unittest.cc
@@ -65,7 +65,7 @@ class DynamicPartitionControlAndroidTest : public ::testing::Test {
           return true;
         }));
 
-    ON_CALL(dynamicControl(), GetSuperPartitionName(_))
+    ON_CALL(dynamicControl(), GetSuperPartitionName())
         .WillByDefault(Return(kFakeSuper));
 
     ON_CALL(dynamicControl(), GetDmDevicePathByName(_, _))
@@ -94,8 +94,8 @@ class DynamicPartitionControlAndroidTest : public ::testing::Test {
     return static_cast<NiceMock<MockDynamicPartitionControlAndroid>&>(*module_);
   }
 
-  std::string GetSuperDevice(uint32_t slot) {
-    return GetDevice(dynamicControl().GetSuperPartitionName(slot));
+  std::string GetSuperDevice() {
+    return GetDevice(dynamicControl().GetSuperPartitionName());
   }
 
   uint32_t source() { return slots_.source; }
@@ -117,8 +117,7 @@ class DynamicPartitionControlAndroidTest : public ::testing::Test {
                    const PartitionSuffixSizes& sizes,
                    uint32_t partition_attr = 0,
                    uint64_t super_size = kDefaultSuperSize) {
-    EXPECT_CALL(dynamicControl(),
-                LoadMetadataBuilder(GetSuperDevice(slot), slot))
+    EXPECT_CALL(dynamicControl(), LoadMetadataBuilder(GetSuperDevice(), slot))
         .Times(AnyNumber())
         .WillRepeatedly(Invoke([=](auto, auto) {
           return NewFakeMetadata(PartitionSuffixSizesToManifest(sizes),
@@ -127,7 +126,7 @@ class DynamicPartitionControlAndroidTest : public ::testing::Test {
         }));
 
     EXPECT_CALL(dynamicControl(),
-                LoadMetadataBuilder(GetSuperDevice(slot), slot, _))
+                LoadMetadataBuilder(GetSuperDevice(), slot, _))
         .Times(AnyNumber())
         .WillRepeatedly(Invoke([=](auto, auto, auto) {
           return NewFakeMetadata(PartitionSuffixSizesToManifest(sizes),
@@ -137,10 +136,10 @@ class DynamicPartitionControlAndroidTest : public ::testing::Test {
   }
 
   void ExpectStoreMetadata(const PartitionSuffixSizes& partition_sizes) {
-    EXPECT_CALL(dynamicControl(),
-                StoreMetadata(GetSuperDevice(target()),
-                              MetadataMatches(partition_sizes),
-                              target()))
+    EXPECT_CALL(
+        dynamicControl(),
+        StoreMetadata(
+            GetSuperDevice(), MetadataMatches(partition_sizes), target()))
         .WillOnce(Return(true));
   }
 
@@ -309,7 +308,7 @@ TEST_P(DynamicPartitionControlAndroidTestP, DeleteAll) {
 // Test corrupt source metadata case.
 TEST_P(DynamicPartitionControlAndroidTestP, CorruptedSourceMetadata) {
   EXPECT_CALL(dynamicControl(),
-              LoadMetadataBuilder(GetSuperDevice(source()), source(), _))
+              LoadMetadataBuilder(GetSuperDevice(), source(), _))
       .WillOnce(Invoke([](auto, auto, auto) { return nullptr; }));
   ExpectUnmap({T("system")});
 
@@ -340,58 +339,6 @@ TEST_P(DynamicPartitionControlAndroidTestP, NotEnoughSpaceForSlot) {
       << "Should not be able to grow over size of super / 2";
 }
 
-TEST_P(DynamicPartitionControlAndroidTestP,
-       ApplyRetrofitUpdateOnDynamicPartitionsEnabledBuild) {
-  ON_CALL(dynamicControl(), GetDynamicPartitionsFeatureFlag())
-      .WillByDefault(Return(FeatureFlag(FeatureFlag::Value::RETROFIT)));
-  // Static partition {system,bar}_{a,b} exists.
-  EXPECT_CALL(dynamicControl(),
-              DeviceExists(AnyOf(GetDevice(S("bar")),
-                                 GetDevice(T("bar")),
-                                 GetDevice(S("system")),
-                                 GetDevice(T("system")))))
-      .WillRepeatedly(Return(true));
-
-  SetMetadata(source(),
-              {{S("system"), 2_GiB},
-               {S("vendor"), 1_GiB},
-               {T("system"), 2_GiB},
-               {T("vendor"), 1_GiB}});
-
-  // Not calling through
-  // DynamicPartitionControlAndroidTest::PreparePartitionsForUpdate(), since we
-  // don't want any default group in the PartitionMetadata.
-  ASSERT_TRUE(dynamicControl().PreparePartitionsForUpdate(
-      source(), target(), {}, true, nullptr, nullptr));
-
-  // Should use dynamic source partitions.
-  EXPECT_CALL(dynamicControl(), GetState(S("system") + "_ota"))
-      .Times(1)
-      .WillOnce(Return(DmDeviceState::ACTIVE));
-  string system_device;
-  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
-      "system", source(), source(), &system_device));
-  ASSERT_EQ(GetDmDevice(S("system") + "_ota"), system_device);
-
-  // Should use static target partitions without querying dynamic control.
-  EXPECT_CALL(dynamicControl(), GetState(T("system"))).Times(0);
-  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
-      "system", target(), source(), &system_device));
-  ASSERT_EQ(GetDevice(T("system")), system_device);
-
-  // Static partition "bar".
-  EXPECT_CALL(dynamicControl(), GetState(S("bar"))).Times(0);
-  std::string bar_device;
-  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
-      "bar", source(), source(), &bar_device));
-  ASSERT_EQ(GetDevice(S("bar")), bar_device);
-
-  EXPECT_CALL(dynamicControl(), GetState(T("bar"))).Times(0);
-  ASSERT_TRUE(dynamicControl().GetPartitionDevice(
-      "bar", target(), source(), &bar_device));
-  ASSERT_EQ(GetDevice(T("bar")), bar_device);
-}
-
 TEST_P(DynamicPartitionControlAndroidTestP, GetMountableDevicePath) {
   ON_CALL(dynamicControl(), GetDynamicPartitionsFeatureFlag())
       .WillByDefault(Return(FeatureFlag(FeatureFlag::Value::LAUNCH)));
@@ -518,9 +465,9 @@ TEST_P(DynamicPartitionControlAndroidTestP,
   EXPECT_CALL(dynamicControl(), GetState(T("system")))
       .Times(AnyNumber())
       .WillOnce(Return(DmDeviceState::ACTIVE));
-  EXPECT_CALL(dynamicControl(),
-              MapPartitionOnDeviceMapper(
-                  GetSuperDevice(target()), T("system"), target(), _, _))
+  EXPECT_CALL(
+      dynamicControl(),
+      MapPartitionOnDeviceMapper(GetSuperDevice(), T("system"), target(), _, _))
       .Times(AnyNumber())
       .WillRepeatedly(
           Invoke([](const auto&, const auto& name, auto, auto, auto* device) {
diff --git a/aosp/mock_dynamic_partition_control_android.h b/aosp/mock_dynamic_partition_control_android.h
index cc6ebf34..2d14770b 100644
--- a/aosp/mock_dynamic_partition_control_android.h
+++ b/aosp/mock_dynamic_partition_control_android.h
@@ -70,7 +70,7 @@ class MockDynamicPartitionControlAndroid
               (override));
   MOCK_METHOD(bool, GetDeviceDir, (std::string*), (override));
   MOCK_METHOD(FeatureFlag, GetDynamicPartitionsFeatureFlag, (), (override));
-  MOCK_METHOD(std::string, GetSuperPartitionName, (uint32_t), (override));
+  MOCK_METHOD(std::string, GetSuperPartitionName, (), (override));
   MOCK_METHOD(FeatureFlag, GetVirtualAbFeatureFlag, (), (override));
   MOCK_METHOD(FeatureFlag, GetVirtualAbCompressionFeatureFlag, (), (override));
   MOCK_METHOD(FeatureFlag,
diff --git a/aosp/service_delegate_android_interface.h b/aosp/service_delegate_android_interface.h
index 5e139d79..3aca2c52 100644
--- a/aosp/service_delegate_android_interface.h
+++ b/aosp/service_delegate_android_interface.h
@@ -17,6 +17,7 @@
 #ifndef UPDATE_ENGINE_AOSP_SERVICE_DELEGATE_ANDROID_INTERFACE_H_
 #define UPDATE_ENGINE_AOSP_SERVICE_DELEGATE_ANDROID_INTERFACE_H_
 
+#include <functional>
 #include <memory>
 #include <string>
 #include <vector>
diff --git a/aosp/update_attempter_android.cc b/aosp/update_attempter_android.cc
index 461cece9..c44e0ccd 100644
--- a/aosp/update_attempter_android.cc
+++ b/aosp/update_attempter_android.cc
@@ -1178,7 +1178,7 @@ void UpdateAttempterAndroid::UpdateStateAfterReboot(const OTAResult result) {
       // return the space to user. Any subsequent attempt to install OTA will
       // allocate space again anyway.
       LOG(INFO) << "Detected a rollback, releasing space allocated for apex "
-                   "deompression.";
+                   "decompression.";
       apex_handler_android_->AllocateSpace({});
       DeltaPerformer::ResetUpdateProgress(prefs_, false);
     }
diff --git a/flags/Android.bp b/flags/Android.bp
index 30194c2c..8814383f 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -5,6 +5,7 @@ aconfig_declarations {
     srcs: [
         "update_engine_flags.aconfig",
     ],
+    exportable: true,
 }
 
 java_aconfig_library {
@@ -14,6 +15,14 @@ java_aconfig_library {
     libs: ["fake_device_config"],
 }
 
+java_aconfig_library {
+    name: "update_engine_exported_flags_java_lib",
+    aconfig_declarations: "update_engine_aconfig_declarations",
+    sdk_version: "core_platform",
+    libs: ["fake_device_config"],
+    mode: "exported",
+}
+
 cc_aconfig_library {
     name: "update_engine_flags_cc_lib",
     aconfig_declarations: "update_engine_aconfig_declarations",
diff --git a/lz4diff/lz4diff_compress.h b/lz4diff/lz4diff_compress.h
index a1ac8fa9..75b3bcd4 100644
--- a/lz4diff/lz4diff_compress.h
+++ b/lz4diff/lz4diff_compress.h
@@ -18,6 +18,7 @@
 #define UPDATE_ENGINE_LZ4DIFF_LZ4DIFF_COMPRESS_H_
 
 #include "lz4diff_format.h"
+#include <functional>
 #include <string_view>
 
 namespace chromeos_update_engine {
diff --git a/payload_generator/deflate_utils.cc b/payload_generator/deflate_utils.cc
index edd6fe13..4ba4b6c0 100644
--- a/payload_generator/deflate_utils.cc
+++ b/payload_generator/deflate_utils.cc
@@ -115,12 +115,10 @@ bool IsBitExtentInExtent(const Extent& extent, const BitExtent& bit_extent) {
          ((bit_extent.offset + bit_extent.length + 7) / 8) <=
              ((extent.start_block() + extent.num_blocks()) * kBlockSize);
 }
+}  // namespace
 
 // Returns whether the given file |name| has an extension listed in
 // |extensions|.
-
-}  // namespace
-
 constexpr base::StringPiece ToStringPiece(std::string_view s) {
   return base::StringPiece(s.data(), s.length());
 }
@@ -244,13 +242,22 @@ bool CompactDeflates(const vector<Extent>& extents,
                      const vector<BitExtent>& in_deflates,
                      vector<BitExtent>* out_deflates) {
   size_t bytes_passed = 0;
+  size_t expected_deflates_size = in_deflates.size();
+
   out_deflates->reserve(in_deflates.size());
+
+  std::vector<bool> bitmask(in_deflates.size(), false);
   for (const auto& extent : extents) {
     size_t gap_bytes = extent.start_block() * kBlockSize - bytes_passed;
-    for (const auto& deflate : in_deflates) {
+    for (size_t i = 0; i < in_deflates.size(); i++) {
+      if (bitmask[i]) {
+        continue;
+      }
+      auto deflate = in_deflates[i];
       if (IsBitExtentInExtent(extent, deflate)) {
         out_deflates->emplace_back(deflate.offset - (gap_bytes * 8),
                                    deflate.length);
+        bitmask[i] = true;
       }
     }
     bytes_passed += extent.num_blocks() * kBlockSize;
diff --git a/payload_generator/deflate_utils.h b/payload_generator/deflate_utils.h
index 517fc4eb..aba19a8e 100644
--- a/payload_generator/deflate_utils.h
+++ b/payload_generator/deflate_utils.h
@@ -87,7 +87,7 @@ bool CompactDeflates(const std::vector<Extent>& extents,
                      const std::vector<puffin::BitExtent>& in_deflates,
                      std::vector<puffin::BitExtent>* out_deflates);
 
-// Combines |FindDeflates| and |CompcatDeflates| for ease of use.
+// Combines |FindDeflates| and |CompactDeflates| for ease of use.
 bool FindAndCompactDeflates(const std::vector<Extent>& extents,
                             const std::vector<puffin::BitExtent>& in_deflates,
                             std::vector<puffin::BitExtent>* out_deflates);
diff --git a/payload_generator/delta_diff_utils_unittest.cc b/payload_generator/delta_diff_utils_unittest.cc
index ca6578ce..44483daa 100644
--- a/payload_generator/delta_diff_utils_unittest.cc
+++ b/payload_generator/delta_diff_utils_unittest.cc
@@ -864,4 +864,16 @@ TEST_F(DeltaDiffUtilsTest, FindAndCompactDeflates) {
       extents, bit_extents, &out_deflates));
 }
 
+TEST_F(DeltaDiffUtilsTest, FindAndCompactDeflatesOverlappingExtents) {
+  std::vector<puffin::BitExtent> bit_extents{{5000 * 8, 10}};
+
+  std::vector<Extent> extents = {
+      ExtentForRange(0, 5),
+      ExtentForRange(1, 10),
+  };
+  std::vector<puffin::BitExtent> out_deflates;
+  ASSERT_TRUE(deflate_utils::FindAndCompactDeflates(
+      extents, bit_extents, &out_deflates));
+}
+
 }  // namespace chromeos_update_engine
diff --git a/test_config.xml b/test_config.xml
index fe3cbfda..a2400f25 100644
--- a/test_config.xml
+++ b/test_config.xml
@@ -21,6 +21,11 @@
         <option name="cleanup" value="true" />
         <option name="push" value="update_engine_unittests->/data/nativetest/update_engine_unittests" />
     </target_preparer>
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="throw-if-cmd-fail" value="true" />
+        <option name="run-command" value="enable-verity" />
+    </target_preparer>
+    <target_preparer class="com.android.tradefed.targetprep.RebootTargetPreparer" />
 
     <test class="com.android.tradefed.testtype.GTest" >
         <option name="native-test-device-path" value="/data/nativetest" />
diff --git a/update_status_utils.cc b/update_status_utils.cc
index 6b23d4fe..635d2291 100644
--- a/update_status_utils.cc
+++ b/update_status_utils.cc
@@ -15,6 +15,7 @@
 //
 #include "update_engine/update_status_utils.h"
 
+#include <format>
 #include <base/logging.h>
 #include <brillo/key_value_store.h>
 
```

