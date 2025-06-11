```diff
diff --git a/Android.bp b/Android.bp
index dd9b02e4..628d55be 100644
--- a/Android.bp
+++ b/Android.bp
@@ -1288,6 +1288,47 @@ cc_test {
     ],
 }
 
+// update_engine_unittests (type: executable)
+// ========================================================
+// Main unittest file.
+cc_test {
+    name: "update_engine_recovery_unittests",
+    defaults: [
+        "ue_defaults",
+        "update_metadata-protos_exports",
+    ],
+    cflags: [
+        "-D__ANDROID_RECOVERY__",
+    ],
+
+    static_libs: [
+        "libbrillo-test-helpers",
+        "libbase",
+        "liblog",
+        "libgmock",
+        "libchrome_test_helpers",
+        "libupdate_engine_android",
+        "update_metadata-protos",
+        "libsnapshot_cow",
+        "libdm",
+    ],
+
+    header_libs: [
+        "libstorage_literals_headers",
+    ],
+    test_suites: ["device-tests"],
+    srcs: [
+        "payload_consumer/postinstall_runner_action_recovery_unittest.cc",
+        "payload_consumer/postinstall_runner_action.cc",
+        "common/subprocess.cc",
+        "common/test_utils.cc",
+        "common/utils.cc",
+        "common/dynamic_partition_control_stub.cc",
+        "common/action_processor.cc",
+        "common/error_code_utils.cc",
+    ],
+}
+
 // Brillo update payload generation script
 // ========================================================
 sh_binary {
diff --git a/METADATA b/METADATA
deleted file mode 100644
index d97975ca..00000000
--- a/METADATA
+++ /dev/null
@@ -1,3 +0,0 @@
-third_party {
-  license_type: NOTICE
-}
diff --git a/OWNERS b/OWNERS
index 1900cf4f..7495e15b 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,7 +1,6 @@
 set noparent
 
 # Android et. al. maintainers:
-deymo@google.com
 senj@google.com
 zhangkelvin@google.com
 
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 85fd5ece..e79b4c1d 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -2,6 +2,7 @@
 clang_format = true
 cpplint = true
 pylint = true
+bpfmt = true
 
 [Hook Scripts]
 protobuflint = ./protobuflint.py ${PREUPLOAD_COMMIT} ${PREUPLOAD_FILES}
diff --git a/aosp/boot_control_android.cc b/aosp/boot_control_android.cc
index 0a1d3deb..343be9f0 100644
--- a/aosp/boot_control_android.cc
+++ b/aosp/boot_control_android.cc
@@ -18,13 +18,13 @@
 
 #include <memory>
 #include <utility>
-#include <vector>
 
 #include <base/bind.h>
 #include <base/logging.h>
 #include <bootloader_message/bootloader_message.h>
 #include <brillo/message_loops/message_loop.h>
 
+
 #include "update_engine/aosp/dynamic_partition_control_android.h"
 
 using std::string;
diff --git a/aosp/boot_control_android.h b/aosp/boot_control_android.h
index 51923e25..57bf5de6 100644
--- a/aosp/boot_control_android.h
+++ b/aosp/boot_control_android.h
@@ -17,7 +17,6 @@
 #ifndef UPDATE_ENGINE_AOSP_BOOT_CONTROL_ANDROID_H_
 #define UPDATE_ENGINE_AOSP_BOOT_CONTROL_ANDROID_H_
 
-#include <map>
 #include <memory>
 #include <string>
 
diff --git a/aosp/dynamic_partition_control_android.cc b/aosp/dynamic_partition_control_android.cc
index d1c3bf26..b10be762 100644
--- a/aosp/dynamic_partition_control_android.cc
+++ b/aosp/dynamic_partition_control_android.cc
@@ -226,7 +226,7 @@ bool DynamicPartitionControlAndroid::MapPartitionInternal(
     // One exception is when /metadata is not mounted. Fallback to
     // CreateLogicalPartition as snapshots are not created in the first place.
     params.timeout_ms = kMapSnapshotTimeout;
-    success = snapshot_->MapUpdateSnapshot(params, path);
+    success = GetSnapshotManager()->MapUpdateSnapshot(params, path);
   } else {
     params.timeout_ms = kMapTimeout;
     success = CreateLogicalPartition(params, path);
@@ -311,7 +311,7 @@ bool DynamicPartitionControlAndroid::UnmapPartitionOnDeviceMapper(
     // a paused update. Clean up any underlying devices.
     if (ExpectMetadataMounted() &&
         !device_name.ends_with(kRWSourcePartitionSuffix)) {
-      success &= snapshot_->UnmapUpdateSnapshot(device_name);
+      success &= GetSnapshotManager()->UnmapUpdateSnapshot(device_name);
     } else {
       LOG(INFO) << "Skip UnmapUpdateSnapshot(" << device_name << ")";
     }
@@ -328,7 +328,7 @@ bool DynamicPartitionControlAndroid::UnmapPartitionOnDeviceMapper(
 }
 
 bool DynamicPartitionControlAndroid::UnmapAllPartitions() {
-  snapshot_->UnmapAllSnapshots();
+  GetSnapshotManager()->UnmapAllSnapshots();
   if (mapped_devices_.empty()) {
     return false;
   }
@@ -358,12 +358,9 @@ void DynamicPartitionControlAndroid::Cleanup() {
   LOG(INFO) << "UnmapAllPartitions done";
   metadata_device_.reset();
   if (GetVirtualAbFeatureFlag().IsEnabled()) {
-    snapshot_ = SnapshotManager::New();
-  } else {
-    snapshot_ = SnapshotManagerStub::New();
+    // Release ISnapshotManager instance so GSID can be gracefully shutdown
+    snapshot_ = nullptr;
   }
-  CHECK(snapshot_ != nullptr) << "Cannot initialize SnapshotManager.";
-  LOG(INFO) << "SnapshotManager initialized.";
 }
 
 bool DynamicPartitionControlAndroid::DeviceExists(const std::string& path) {
@@ -585,7 +582,7 @@ bool DynamicPartitionControlAndroid::PreparePartitionsForUpdate(
     // should not proceed because during next boot, snapshots will overlay on
     // the devices incorrectly.
     if (ExpectMetadataMounted()) {
-      TEST_AND_RETURN_FALSE(snapshot_->CancelUpdate());
+      TEST_AND_RETURN_FALSE(GetSnapshotManager()->CancelUpdate());
     } else {
       LOG(INFO) << "Skip canceling previous update because metadata is not "
                 << "mounted";
@@ -996,6 +993,20 @@ bool DynamicPartitionControlAndroid::CheckSuperPartitionAllocatableSpace(
   return true;
 }
 
+android::snapshot::ISnapshotManager*
+DynamicPartitionControlAndroid::GetSnapshotManager() {
+  if (snapshot_ == nullptr) {
+    if (GetVirtualAbFeatureFlag().IsEnabled()) {
+      snapshot_ = SnapshotManager::New();
+    } else {
+      snapshot_ = SnapshotManagerStub::New();
+    }
+  }
+  CHECK(snapshot_ != nullptr) << "Cannot initialize SnapshotManager.";
+  LOG(INFO) << "SnapshotManager initialized.";
+  return snapshot_.get();
+}
+
 bool DynamicPartitionControlAndroid::PrepareSnapshotPartitionsForUpdate(
     uint32_t source_slot,
     uint32_t target_slot,
@@ -1018,11 +1029,11 @@ bool DynamicPartitionControlAndroid::PrepareSnapshotPartitionsForUpdate(
   TEST_AND_RETURN_FALSE(
       CheckSuperPartitionAllocatableSpace(builder.get(), manifest, true));
 
-  if (!snapshot_->BeginUpdate()) {
+  if (!GetSnapshotManager()->BeginUpdate()) {
     LOG(ERROR) << "Cannot begin new update.";
     return false;
   }
-  auto ret = snapshot_->CreateUpdateSnapshots(manifest);
+  auto ret = GetSnapshotManager()->CreateUpdateSnapshots(manifest);
   if (!ret) {
     LOG(ERROR) << "Cannot create update snapshots: " << ret.string();
     if (required_size != nullptr &&
@@ -1124,9 +1135,9 @@ bool DynamicPartitionControlAndroid::UpdatePartitionMetadata(
 
 bool DynamicPartitionControlAndroid::FinishUpdate(bool powerwash_required) {
   if (ExpectMetadataMounted()) {
-    if (snapshot_->GetUpdateState() == UpdateState::Initiated) {
+    if (GetSnapshotManager()->GetUpdateState() == UpdateState::Initiated) {
       LOG(INFO) << "Snapshot writes are done.";
-      return snapshot_->FinishedSnapshotWrites(powerwash_required);
+      return GetSnapshotManager()->FinishedSnapshotWrites(powerwash_required);
     }
   } else {
     LOG(INFO) << "Skip FinishedSnapshotWrites() because /metadata is not "
@@ -1350,7 +1361,7 @@ DynamicPartitionControlAndroid::GetCleanupPreviousUpdateAction(
     return std::make_unique<NoOpAction>();
   }
   return std::make_unique<CleanupPreviousUpdateAction>(
-      prefs, boot_control, snapshot_.get(), delegate);
+      prefs, boot_control, GetSnapshotManager(), delegate);
 }
 
 bool DynamicPartitionControlAndroid::ResetUpdate(PrefsInterface* prefs) {
@@ -1372,7 +1383,7 @@ bool DynamicPartitionControlAndroid::ResetUpdate(PrefsInterface* prefs) {
       prefs, false /* quick */, false /* skip dynamic partitions metadata */));
 
   if (ExpectMetadataMounted()) {
-    TEST_AND_RETURN_FALSE(snapshot_->CancelUpdate());
+    TEST_AND_RETURN_FALSE(GetSnapshotManager()->CancelUpdate());
   } else {
     LOG(INFO) << "Skip cancelling update in ResetUpdate because /metadata is "
               << "not mounted";
@@ -1473,7 +1484,7 @@ bool DynamicPartitionControlAndroid::EnsureMetadataMounted() {
   }
 
   if (metadata_device_ == nullptr) {
-    metadata_device_ = snapshot_->EnsureMetadataMounted();
+    metadata_device_ = GetSnapshotManager()->EnsureMetadataMounted();
   }
   return metadata_device_ != nullptr;
 }
@@ -1497,7 +1508,7 @@ DynamicPartitionControlAndroid::OpenCowWriter(
       .timeout_ms = kMapSnapshotTimeout};
   // TODO(zhangkelvin) Open an APPEND mode CowWriter once there's an API to do
   // it.
-  return snapshot_->OpenSnapshotWriter(params, label);
+  return GetSnapshotManager()->OpenSnapshotWriter(params, label);
 }  // namespace chromeos_update_engine
 
 std::unique_ptr<FileDescriptor> DynamicPartitionControlAndroid::OpenCowFd(
@@ -1531,7 +1542,13 @@ std::optional<base::FilePath> DynamicPartitionControlAndroid::GetSuperDevice() {
 }
 
 bool DynamicPartitionControlAndroid::MapAllPartitions() {
-  return snapshot_->MapAllSnapshots(kMapSnapshotTimeout);
+  // This flag tells us if VAB is enabled. In the case it's not (e.g. for
+  // secondary payloads) we are falling back on A/B and MapAllPartitions should
+  // just be a no-op
+  if (!target_supports_snapshot_) {
+    return true;
+  }
+  return GetSnapshotManager()->MapAllSnapshots(kMapSnapshotTimeout);
 }
 
 bool DynamicPartitionControlAndroid::IsDynamicPartition(
@@ -1555,7 +1572,7 @@ bool DynamicPartitionControlAndroid::IsDynamicPartition(
 
 bool DynamicPartitionControlAndroid::UpdateUsesSnapshotCompression() {
   return GetVirtualAbFeatureFlag().IsEnabled() &&
-         snapshot_->UpdateUsesCompression();
+         GetSnapshotManager()->UpdateUsesCompression();
 }
 
 FeatureFlag
diff --git a/aosp/dynamic_partition_control_android.h b/aosp/dynamic_partition_control_android.h
index 1f70184f..e5ba86a3 100644
--- a/aosp/dynamic_partition_control_android.h
+++ b/aosp/dynamic_partition_control_android.h
@@ -339,6 +339,7 @@ class DynamicPartitionControlAndroid : public DynamicPartitionControlInterface {
   bool SetTargetBuildVars(const DeltaArchiveManifest& manifest);
 
   std::string GetDeviceName(std::string partition_name, uint32_t slot) const;
+  android::snapshot::ISnapshotManager* GetSnapshotManager();
 
   std::set<std::string> mapped_devices_;
   const FeatureFlag dynamic_partitions_;
diff --git a/aosp/service_delegate_android_interface.h b/aosp/service_delegate_android_interface.h
index c73c6de1..5e139d79 100644
--- a/aosp/service_delegate_android_interface.h
+++ b/aosp/service_delegate_android_interface.h
@@ -17,8 +17,6 @@
 #ifndef UPDATE_ENGINE_AOSP_SERVICE_DELEGATE_ANDROID_INTERFACE_H_
 #define UPDATE_ENGINE_AOSP_SERVICE_DELEGATE_ANDROID_INTERFACE_H_
 
-#include <inttypes.h>
-
 #include <memory>
 #include <string>
 #include <vector>
diff --git a/aosp/sideload_main.cc b/aosp/sideload_main.cc
index 4a92ca74..9e7512ee 100644
--- a/aosp/sideload_main.cc
+++ b/aosp/sideload_main.cc
@@ -120,7 +120,7 @@ class SideloadDaemonState : public DaemonStateInterface,
 };
 
 // Apply an update payload directly from the given payload URI.
-bool ApplyUpdatePayload(const string& payload,
+ErrorCode ApplyUpdatePayload(const string& payload,
                         int64_t payload_offset,
                         int64_t payload_size,
                         const vector<string>& headers,
@@ -145,13 +145,13 @@ bool ApplyUpdatePayload(const string& payload,
       boot_control::CreateBootControl();
   if (!boot_control) {
     LOG(ERROR) << "Error initializing the BootControlInterface.";
-    return false;
+    return ErrorCode::kError;
   }
 
   std::unique_ptr<HardwareInterface> hardware = hardware::CreateHardware();
   if (!hardware) {
     LOG(ERROR) << "Error initializing the HardwareInterface.";
-    return false;
+    return ErrorCode::kError;
   }
 
   UpdateAttempterAndroid update_attempter(&sideload_daemon_state,
@@ -161,11 +161,13 @@ bool ApplyUpdatePayload(const string& payload,
                                           nullptr);
   update_attempter.Init();
 
-  TEST_AND_RETURN_FALSE(update_attempter.ApplyPayload(
-      payload, payload_offset, payload_size, headers, nullptr));
+  if (!update_attempter.ApplyPayload(
+          payload, payload_offset, payload_size, headers, nullptr)) {
+    LOG(ERROR) << "Error attempting the ApplyPayload.";
+  }
 
   loop.Run();
-  return sideload_daemon_state.status() == UpdateStatus::UPDATED_NEED_REBOOT;
+  return sideload_daemon_state.error_code();
 }
 
 }  // namespace
@@ -198,9 +200,6 @@ int main(int argc, char** argv) {
   vector<string> headers = base::SplitString(
       FLAGS_headers, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
 
-  if (!chromeos_update_engine::ApplyUpdatePayload(
-          FLAGS_payload, FLAGS_offset, FLAGS_size, headers, FLAGS_status_fd))
-    return 1;
-
-  return 0;
+  return static_cast<int>(chromeos_update_engine::ApplyUpdatePayload(
+      FLAGS_payload, FLAGS_offset, FLAGS_size, headers, FLAGS_status_fd));
 }
diff --git a/aosp/update_attempter_android.cc b/aosp/update_attempter_android.cc
index f29383a8..461cece9 100644
--- a/aosp/update_attempter_android.cc
+++ b/aosp/update_attempter_android.cc
@@ -17,6 +17,7 @@
 #include "update_engine/aosp/update_attempter_android.h"
 
 #include <algorithm>
+#include <iterator>
 #include <map>
 #include <memory>
 #include <ostream>
@@ -56,6 +57,7 @@
 #include "update_engine/payload_consumer/payload_verifier.h"
 #include "update_engine/payload_consumer/postinstall_runner_action.h"
 #include "update_engine/update_boot_flags_action.h"
+#include "update_engine/update_metadata.pb.h"
 #include "update_engine/update_status.h"
 #include "update_engine/update_status_utils.h"
 
@@ -480,6 +482,18 @@ bool UpdateAttempterAndroid::ResumeUpdate(Error* error) {
 }
 
 bool UpdateAttempterAndroid::CancelUpdate(Error* error) {
+  auto action = processor_->current_action();
+  if (action != nullptr &&
+      action->Type() == CleanupPreviousUpdateAction::StaticType()) {
+    return LogAndSetError(
+        error,
+        __LINE__,
+        __FILE__,
+        "CleanupPreviousUpdateAction is running, this action cannot be "
+        "canceled. As it often performs critical merge operations after "
+        "reboot.",
+        ErrorCode::kRollbackNotPossible);
+  }
   if (!processor_->IsRunning())
     return LogAndSetGenericError(
         error, __LINE__, __FILE__, "No ongoing update to cancel.");
@@ -546,6 +560,32 @@ bool operator!=(const std::vector<unsigned char>& a, std::string_view b) {
   return !(a == b);
 }
 
+bool VerifyPayloadMetadata(Error* error,
+                           std::string_view metadata,
+                           const PayloadMetadata& payload_metadata) {
+  auto payload_verifier = PayloadVerifier::CreateInstanceFromZipPath(
+      constants::kUpdateCertificatesPath);
+  if (!payload_verifier) {
+    return LogAndSetError(error,
+                          __LINE__,
+                          __FILE__,
+                          "Failed to create the payload verifier from " +
+                              std::string(constants::kUpdateCertificatesPath),
+                          ErrorCode::kDownloadManifestParseError);
+  }
+  auto errorcode = payload_metadata.ValidateMetadataSignature(
+      metadata, "", *payload_verifier);
+  if (errorcode != ErrorCode::kSuccess) {
+    return LogAndSetError(error,
+                          __LINE__,
+                          __FILE__,
+                          "Failed to validate metadata signature: " +
+                              utils::ErrorCodeToString(errorcode),
+                          errorcode);
+  }
+  return true;
+}
+
 bool UpdateAttempterAndroid::VerifyPayloadParseManifest(
     const std::string& metadata_filename,
     std::string_view expected_metadata_hash,
@@ -619,27 +659,9 @@ bool UpdateAttempterAndroid::VerifyPayloadParseManifest(
                 << HexEncode(metadata_hash);
     }
   }
+  TEST_AND_RETURN_FALSE(
+      VerifyPayloadMetadata(error, ToStringView(metadata), payload_metadata));
 
-  auto payload_verifier = PayloadVerifier::CreateInstanceFromZipPath(
-      constants::kUpdateCertificatesPath);
-  if (!payload_verifier) {
-    return LogAndSetError(error,
-                          __LINE__,
-                          __FILE__,
-                          "Failed to create the payload verifier from " +
-                              std::string(constants::kUpdateCertificatesPath),
-                          ErrorCode::kDownloadManifestParseError);
-  }
-  errorcode = payload_metadata.ValidateMetadataSignature(
-      metadata, "", *payload_verifier);
-  if (errorcode != ErrorCode::kSuccess) {
-    return LogAndSetError(error,
-                          __LINE__,
-                          __FILE__,
-                          "Failed to validate metadata signature: " +
-                              utils::ErrorCodeToString(errorcode),
-                          errorcode);
-  }
   if (!payload_metadata.GetManifest(metadata, manifest)) {
     return LogAndSetError(error,
                           __LINE__,
@@ -853,6 +875,8 @@ void UpdateAttempterAndroid::TerminateUpdateAndNotify(ErrorCode error_code) {
     return;
   }
 
+  boot_control_->GetDynamicPartitionControl()->Cleanup();
+
   if (status_ == UpdateStatus::CLEANUP_PREVIOUS_UPDATE) {
     ClearUpdateCompletedMarker();
     LOG(INFO) << "Terminating cleanup previous update.";
@@ -862,8 +886,6 @@ void UpdateAttempterAndroid::TerminateUpdateAndNotify(ErrorCode error_code) {
     return;
   }
 
-  boot_control_->GetDynamicPartitionControl()->Cleanup();
-
   for (auto observer : daemon_state_->service_observers())
     observer->SendPayloadApplicationComplete(error_code);
 
@@ -1341,6 +1363,7 @@ bool UpdateAttempterAndroid::setShouldSwitchSlotOnReboot(
   // previous ApplyPayload() call may have requested powerwash, these
   // settings would be saved in `this->install_plan_`. Inherit that setting.
   install_plan_.powerwash_required = this->install_plan_.powerwash_required;
+  install_plan_.switch_slot_on_reboot = true;
 
   CHECK_NE(install_plan_.source_slot, UINT32_MAX);
   CHECK_NE(install_plan_.target_slot, UINT32_MAX);
@@ -1454,16 +1477,162 @@ void UpdateAttempterAndroid::ScheduleCleanupPreviousUpdate() {
   processor_->StartProcessing();
 }
 
+bool ParsePayloadMetadata(Error* error,
+                          std::string_view manifest_bytes,
+                          DeltaArchiveManifest* manifest) {
+  PayloadMetadata payload_metadata;
+  ErrorCode errorcode{};
+  if (payload_metadata.ParsePayloadHeader(manifest_bytes, &errorcode) !=
+      MetadataParseResult::kSuccess) {
+    return LogAndSetError(error,
+                          __LINE__,
+                          __FILE__,
+                          "Failed to parse payload header: " +
+                              utils::ErrorCodeToString(errorcode),
+                          errorcode);
+  }
+  uint64_t metadata_size = payload_metadata.GetMetadataSize() +
+                           payload_metadata.GetMetadataSignatureSize();
+  if (metadata_size < kMaxPayloadHeaderSize ||
+      metadata_size > manifest_bytes.size()) {
+    return LogAndSetError(error,
+                          __LINE__,
+                          __FILE__,
+                          "Invalid metadata size on cached manifest: " +
+                              std::to_string(metadata_size),
+                          ErrorCode::kDownloadManifestParseError);
+  }
+  TEST_AND_RETURN_FALSE(
+      VerifyPayloadMetadata(error, manifest_bytes, payload_metadata));
+
+  if (!payload_metadata.GetManifest(manifest_bytes, manifest)) {
+    return LogAndSetError(error,
+                          __LINE__,
+                          __FILE__,
+                          "Failed to parse manifest. Might need to install "
+                          "OTA first and re-try this API",
+                          ErrorCode::kDownloadManifestParseError);
+  }
+  return true;
+}
+
 bool UpdateAttempterAndroid::TriggerPostinstall(const std::string& partition,
                                                 Error* error) {
-  if (error) {
-    return LogAndSetGenericError(
+  if (processor_->IsRunning()) {
+    return LogAndSetError(error,
+                          __LINE__,
+                          __FILE__,
+                          "Already processing an update, cancel it first.",
+                          ErrorCode::kUpdateProcessing);
+  }
+  bool postinstall_succeeded = false;
+  if (!prefs_->GetBoolean(kPrefsPostInstallSucceeded, &postinstall_succeeded)) {
+    return LogAndSetError(
         error,
         __LINE__,
         __FILE__,
-        __FUNCTION__ + std::string(" is not implemented"));
+        "Postinstall action did not run. "
+        "OTA update must first reach the "
+        "Postinstall phase(which verfies that all partitions can be mounted) "
+        "before calling TriggerPostinstall",
+        ErrorCode::kPostinstallRunnerError);
   }
-  return false;
+  if (!postinstall_succeeded) {
+    return LogAndSetError(
+        error,
+        __LINE__,
+        __FILE__,
+        "Postinstall action did not complete successfully. "
+        "OTA update must first reach the "
+        "Postinstall phase(which verfies that all partitions can be mounted) "
+        "before calling TriggerPostinstall",
+        ErrorCode::kPostinstallRunnerError);
+  }
+
+  InstallPlan install_plan;
+  install_plan.source_slot = GetCurrentSlot();
+  install_plan.target_slot = GetTargetSlot();
+  install_plan.switch_slot_on_reboot = false;
+  install_plan.run_post_install = true;
+  install_plan.download_url =
+      std::string(kPrefsManifestBytes) + ":" + install_plan_.download_url;
+
+  std::string manifest_bytes;
+  // kPrefsManifestBytes is set during DownloadAction
+  if (!prefs_->GetString(kPrefsManifestBytes, &manifest_bytes)) {
+    return LogAndSetError(
+        error,
+        __LINE__,
+        __FILE__,
+        "Cached manifest not found. TriggerPostinstall can only be called "
+        "after OTA get past at least FilesystemVerification stage",
+        ErrorCode::kDownloadStateInitializationError);
+  }
+  DeltaArchiveManifest manifest;
+  TEST_AND_RETURN_FALSE(ParsePayloadMetadata(error, manifest_bytes, &manifest));
+  ErrorCode errorcode{};
+  if (!boot_control_->GetDynamicPartitionControl()->PreparePartitionsForUpdate(
+          GetCurrentSlot(),
+          GetTargetSlot(),
+          manifest,
+          false /* should update */,
+          nullptr,
+          &errorcode)) {
+    return LogAndSetError(error,
+                          __LINE__,
+                          __FILE__,
+                          "Failed to PreparePartitionsForUpdate",
+                          errorcode);
+  }
+  std::vector<PartitionUpdate> partitions;
+  std::copy_if(manifest.partitions().begin(),
+               manifest.partitions().end(),
+               std::back_inserter(partitions),
+               [&partition](const PartitionUpdate& part) {
+                 return part.partition_name() == partition;
+               });
+  if (partitions.empty()) {
+    return LogAndSetError(error,
+                          __LINE__,
+                          __FILE__,
+                          "Partition " + partition + " not found",
+                          ErrorCode::kDownloadStateInitializationError);
+  }
+  // We only want to trigger postinstall for a specific partition,
+  // and since we already checked partitions array is non-empty, reading just
+  // the first partition is enough.
+  if (!partitions[0].has_postinstall_path() ||
+      partitions[0].postinstall_path().empty()) {
+    return LogAndSetError(error,
+                          __LINE__,
+                          __FILE__,
+                          "Partition " + partition +
+                              " does not have a postinstall script defined",
+                          ErrorCode::kDownloadStateInitializationError);
+  }
+  if (!install_plan.ParsePartitions(
+          partitions, boot_control_, manifest.block_size(), &errorcode)) {
+    return LogAndSetError(error,
+                          __LINE__,
+                          __FILE__,
+                          "Failed to parse manifest partitions. Might need "
+                          "to install OTA first and re-try this API",
+                          ErrorCode::kDownloadManifestParseError);
+  }
+  LOG(INFO) << "Trigger postinstall with this install plan: "
+            << install_plan.ToString();
+
+  auto postinstall_runner_action =
+      std::make_unique<PostinstallRunnerAction>(boot_control_, hardware_);
+  postinstall_runner_action->set_delegate(this);
+
+  auto install_plan_action = std::make_unique<InstallPlanAction>(install_plan);
+  BondActions(install_plan_action.get(), postinstall_runner_action.get());
+  processor_->EnqueueAction(std::move(install_plan_action));
+  processor_->EnqueueAction(std::move(postinstall_runner_action));
+  SetStatusAndNotify(UpdateStatus::FINALIZING);
+  ScheduleProcessingStart();
+  return true;
 }
 
 void UpdateAttempterAndroid::OnCleanupProgressUpdate(double progress) {
diff --git a/common/boot_control_interface.h b/common/boot_control_interface.h
index 045236a7..1a451d3a 100644
--- a/common/boot_control_interface.h
+++ b/common/boot_control_interface.h
@@ -18,15 +18,12 @@
 #define UPDATE_ENGINE_COMMON_BOOT_CONTROL_INTERFACE_H_
 
 #include <climits>
-#include <map>
 #include <string>
-#include <vector>
 
 #include <base/callback.h>
 #include <android-base/macros.h>
 
 #include "update_engine/common/dynamic_partition_control_interface.h"
-#include "update_engine/update_metadata.pb.h"
 
 namespace chromeos_update_engine {
 
diff --git a/common/fake_boot_control.h b/common/fake_boot_control.h
index 8a685016..82d4827d 100644
--- a/common/fake_boot_control.h
+++ b/common/fake_boot_control.h
@@ -40,6 +40,11 @@ class FakeBootControl : public BootControlInterface {
     dynamic_partition_control_.reset(new DynamicPartitionControlStub());
   }
 
+  void SetDynamicPartitionControl(
+      std::unique_ptr<DynamicPartitionControlInterface> dynamic_control) {
+    dynamic_partition_control_ = std::move(dynamic_control);
+  }
+
   // BootControlInterface overrides.
   unsigned int GetNumSlots() const override { return num_slots_; }
   BootControlInterface::Slot GetCurrentSlot() const override {
diff --git a/flags/Android.bp b/flags/Android.bp
new file mode 100644
index 00000000..30194c2c
--- /dev/null
+++ b/flags/Android.bp
@@ -0,0 +1,20 @@
+aconfig_declarations {
+    name: "update_engine_aconfig_declarations",
+    package: "com.android.update_engine",
+    container: "system",
+    srcs: [
+        "update_engine_flags.aconfig",
+    ],
+}
+
+java_aconfig_library {
+    name: "update_engine_flags_java_lib",
+    aconfig_declarations: "update_engine_aconfig_declarations",
+    sdk_version: "core_platform",
+    libs: ["fake_device_config"],
+}
+
+cc_aconfig_library {
+    name: "update_engine_flags_cc_lib",
+    aconfig_declarations: "update_engine_aconfig_declarations",
+}
diff --git a/flags/update_engine_flags.aconfig b/flags/update_engine_flags.aconfig
new file mode 100644
index 00000000..a7c286e3
--- /dev/null
+++ b/flags/update_engine_flags.aconfig
@@ -0,0 +1,11 @@
+package: "com.android.update_engine"
+container: "system"
+
+flag {
+  name: "minor_changes_2025q4"
+  is_exported: true
+  namespace: "phoenix"
+  description: "Enable 2025Q4 minor changes"
+  bug: "396669769"
+  is_fixed_read_only: true
+}
diff --git a/libcurl_http_fetcher.cc b/libcurl_http_fetcher.cc
index 08c8a672..db94a6fe 100644
--- a/libcurl_http_fetcher.cc
+++ b/libcurl_http_fetcher.cc
@@ -648,11 +648,17 @@ void LibcurlHttpFetcher::Unpause() {
     return;
   }
   CHECK(curl_handle_);
-  CHECK_EQ(curl_easy_pause(curl_handle_, CURLPAUSE_CONT), CURLE_OK);
-  // Since the transfer is in progress, we need to dispatch a CurlPerformOnce()
-  // now to let the connection continue, otherwise it would be called by the
-  // TimeoutCallback but with a delay.
-  CurlPerformOnce();
+  auto ret = curl_easy_pause(curl_handle_, CURLPAUSE_CONT);
+  if (ret != CURLE_OK) {
+    LOG(ERROR) << "Failed to unpause connection, reason: " << ret
+               << ". Terminating transfer.";
+    TerminateTransfer();
+  } else {
+    // Since the transfer is in progress, we need to dispatch a
+    // CurlPerformOnce() now to let the connection continue, otherwise it would
+    // be called by the TimeoutCallback but with a delay.
+    CurlPerformOnce();
+  }
 }
 
 // This method sets up callbacks with the MessageLoop.
diff --git a/liburing_cpp/Android.bp b/liburing_cpp/Android.bp
index e17f0808..8566bc22 100644
--- a/liburing_cpp/Android.bp
+++ b/liburing_cpp/Android.bp
@@ -1,4 +1,3 @@
-
 package {
     // See: http://go/android-license-faq
     // A large-scale-change added 'default_applicable_licenses' to import
@@ -9,31 +8,32 @@ package {
 }
 
 cc_library {
-	name: "liburing_cpp",
-	host_supported: true,
-	recovery_available: true,
-	srcs: [
-		"src/IoUring.cpp",
-		"src/IoUringSQE.cpp",
-	],
-	static_libs: [
-		"liburing",
-	],
-	export_include_dirs: [
-		"include",
-	],
+    name: "liburing_cpp",
+    host_supported: true,
+    recovery_available: true,
+    ramdisk_available: true,
+    vendor_ramdisk_available: true,
+    srcs: [
+        "src/IoUring.cpp",
+        "src/IoUringSQE.cpp",
+    ],
+    static_libs: [
+        "liburing",
+    ],
+    export_include_dirs: [
+        "include",
+    ],
 }
 
-
 cc_test_host {
-	name: "liburing_cpp_tests",
-	srcs: [
-		"tests/BasicTests.cpp",
-		"tests/main.cpp",
-	],
-	static_libs: [
-		"libgtest",
-		"liburing",
-		"liburing_cpp",
-	],
+    name: "liburing_cpp_tests",
+    srcs: [
+        "tests/BasicTests.cpp",
+        "tests/main.cpp",
+    ],
+    static_libs: [
+        "libgtest",
+        "liburing",
+        "liburing_cpp",
+    ],
 }
diff --git a/liburing_cpp/include/liburing_cpp/IoUring.h b/liburing_cpp/include/liburing_cpp/IoUring.h
index 09ed5ccc..b3826305 100644
--- a/liburing_cpp/include/liburing_cpp/IoUring.h
+++ b/liburing_cpp/include/liburing_cpp/IoUring.h
@@ -53,6 +53,12 @@ class IoUringInterface {
   // Register a set of file descriptors to kernel.
   virtual Errno RegisterFiles(const int* files, size_t files_size) = 0;
   virtual Errno UnregisterFiles() = 0;
+
+  // Prepare read to a registered buffer. This does not submit the operation
+  // to the kernel. For that, call |IoUringInterface::Submit()|
+  virtual IoUringSQE PrepReadFixed(
+      int fd, void* buf, unsigned nbytes, uint64_t offset, int buf_index) = 0;
+
   // Append a submission entry into this io_uring. This does not submit the
   // operation to the kernel. For that, call |IoUringInterface::Submit()|
   virtual IoUringSQE PrepRead(int fd, void *buf, unsigned nbytes,
diff --git a/liburing_cpp/src/IoUring.cpp b/liburing_cpp/src/IoUring.cpp
index cf102723..85892204 100644
--- a/liburing_cpp/src/IoUring.cpp
+++ b/liburing_cpp/src/IoUring.cpp
@@ -82,6 +82,19 @@ class IoUring final : public IoUringInterface {
     return ret;
   }
 
+  IoUringSQE PrepReadFixed(int fd,
+                           void* buf,
+                           unsigned nbytes,
+                           uint64_t offset,
+                           int buf_index) override {
+    auto sqe = io_uring_get_sqe(&ring);
+    if (sqe == nullptr) {
+      return IoUringSQE{nullptr};
+    }
+    io_uring_prep_read_fixed(sqe, fd, buf, nbytes, offset, buf_index);
+    return IoUringSQE{static_cast<void*>(sqe)};
+  }
+
   IoUringSQE PrepRead(int fd, void* buf, unsigned nbytes,
                       uint64_t offset) override {
     auto sqe = io_uring_get_sqe(&ring);
diff --git a/liburing_cpp/tests/BasicTests.cpp b/liburing_cpp/tests/BasicTests.cpp
index 81288f6b..680fb646 100644
--- a/liburing_cpp/tests/BasicTests.cpp
+++ b/liburing_cpp/tests/BasicTests.cpp
@@ -191,4 +191,51 @@ TEST_F(IoUringTest, ExtentRead) {
   for (int i = 0; i < data.size(); ++i) {
     ASSERT_EQ(data[i], i % 256);
   }
-}
\ No newline at end of file
+}
+
+TEST_F(IoUringTest, ExtentReadFixedBuffers) {
+  const int fd = fileno(fp);
+  ASSERT_NO_FATAL_FAILURE(WriteTestData(fd, kBlockSize * 3, kBlockSize));
+  ASSERT_NO_FATAL_FAILURE(WriteTestData(fd, kBlockSize * 5, kBlockSize));
+  ASSERT_NO_FATAL_FAILURE(WriteTestData(fd, kBlockSize * 8, kBlockSize));
+  ASSERT_NO_FATAL_FAILURE(WriteTestData(fd, kBlockSize * 13, kBlockSize));
+  fsync(fd);
+
+  std::vector<unsigned char> data;
+  data.resize(kBlockSize * 4);
+  std::unique_ptr<struct iovec[]> vecs = std::make_unique<struct iovec[]>(4);
+  for (int i = 0; i < 4; i++) {
+    vecs[i].iov_base = data.data() + i * kBlockSize;
+    vecs[i].iov_len = kBlockSize;
+  }
+
+  ASSERT_TRUE(ring->RegisterBuffers(vecs.get(), 4).IsOk());
+
+  ASSERT_TRUE(
+      ring->PrepReadFixed(fd, data.data(), kBlockSize, 3 * kBlockSize, 0)
+          .IsOk());
+  ASSERT_TRUE(
+      ring->PrepReadFixed(
+              fd, data.data() + kBlockSize, kBlockSize, 5 * kBlockSize, 1)
+          .IsOk());
+  ASSERT_TRUE(
+      ring->PrepReadFixed(
+              fd, data.data() + kBlockSize * 2, kBlockSize, 8 * kBlockSize, 2)
+          .IsOk());
+  ASSERT_TRUE(
+      ring->PrepReadFixed(
+              fd, data.data() + kBlockSize * 3, kBlockSize, 13 * kBlockSize, 3)
+          .IsOk());
+  ring->SubmitAndWait(4);
+  const auto cqes = ring->PopCQE(4);
+  if (cqes.IsErr()) {
+    FAIL() << cqes.GetError().ErrMsg();
+    return;
+  }
+  for (const auto& cqe : cqes.GetResult()) {
+    ASSERT_GT(cqe.res, 0);
+  }
+  for (int i = 0; i < data.size(); ++i) {
+    ASSERT_EQ(data[i], i % 256);
+  }
+}
diff --git a/payload_consumer/delta_performer.cc b/payload_consumer/delta_performer.cc
index 0b4a13e6..14a707fb 100644
--- a/payload_consumer/delta_performer.cc
+++ b/payload_consumer/delta_performer.cc
@@ -598,6 +598,15 @@ bool DeltaPerformer::ParseManifest(const char** c_bytes,
   // new_cow_size per partition = partition_size - (#blocks in Copy
   // operations part of the partition)
   if (install_plan_->vabc_none) {
+    size_t cowOpsize = android::snapshot::GetCowOpSize(
+        manifest_.dynamic_partition_metadata().cow_version());
+    if (cowOpsize == 0) {
+      cowOpsize = sizeof(android::snapshot::CowOperationV2);
+      LOG(WARNING) << "Failed to determine cow op size for COW version "
+                   << manifest_.dynamic_partition_metadata().cow_version()
+                   << ", defaulting to " << cowOpsize;
+    }
+
     LOG(INFO) << "Setting Virtual AB Compression algorithm to none. This "
                  "would also disable VABC XOR as XOR only saves space if "
                  "compression is enabled.";
@@ -628,13 +637,11 @@ bool DeltaPerformer::ParseManifest(const char** c_bytes,
       // Every block written to COW device will come with a header which
       // stores src/dst block info along with other data.
       const auto cow_metadata_size = partition.new_partition_info().size() /
-                                     manifest_.block_size() *
-                                     sizeof(android::snapshot::CowOperation);
+                                     manifest_.block_size() * cowOpsize;
       // update_engine will emit a label op every op or every two seconds,
       // whichever one is longer. In the worst case, we add 1 label per
       // InstallOp. So take size of label ops into account.
-      const auto label_ops_size =
-          partition.operations_size() * sizeof(android::snapshot::CowOperation);
+      const auto label_ops_size = partition.operations_size() * cowOpsize;
       // Adding extra 2MB headroom just for any unexpected space usage.
       // If we overrun reserved COW size, entire OTA will fail
       // and no way for user to retry OTA
diff --git a/payload_consumer/filesystem_verifier_action.cc b/payload_consumer/filesystem_verifier_action.cc
index 8c21673a..956f90b0 100644
--- a/payload_consumer/filesystem_verifier_action.cc
+++ b/payload_consumer/filesystem_verifier_action.cc
@@ -16,7 +16,6 @@
 
 #include "update_engine/payload_consumer/filesystem_verifier_action.h"
 
-#include <errno.h>
 #include <fcntl.h>
 #include <sys/stat.h>
 #include <sys/types.h>
@@ -28,7 +27,6 @@
 #include <memory>
 #include <numeric>
 #include <string>
-#include <utility>
 
 #include <base/bind.h>
 #include <brillo/data_encoding.h>
diff --git a/payload_consumer/payload_metadata.cc b/payload_consumer/payload_metadata.cc
index d2e42f02..649d9bed 100644
--- a/payload_consumer/payload_metadata.cc
+++ b/payload_consumer/payload_metadata.cc
@@ -154,7 +154,7 @@ bool PayloadMetadata::GetManifest(const unsigned char* payload,
 }
 
 ErrorCode PayloadMetadata::ValidateMetadataSignature(
-    const brillo::Blob& payload,
+    const std::string_view payload,
     const string& metadata_signature,
     const PayloadVerifier& payload_verifier) const {
   if (payload.size() < metadata_size_ + metadata_signature_size_)
diff --git a/payload_consumer/payload_metadata.h b/payload_consumer/payload_metadata.h
index 4d2d5b07..fd24f204 100644
--- a/payload_consumer/payload_metadata.h
+++ b/payload_consumer/payload_metadata.h
@@ -17,14 +17,12 @@
 #ifndef UPDATE_ENGINE_PAYLOAD_CONSUMER_PAYLOAD_METADATA_H_
 #define UPDATE_ENGINE_PAYLOAD_CONSUMER_PAYLOAD_METADATA_H_
 
-#include <inttypes.h>
-
 #include <string>
-#include <vector>
 
 #include <android-base/macros.h>
 #include <brillo/secure_blob.h>
 
+#include "update_engine/common/utils.h"
 #include "update_engine/common/error_code.h"
 #include "update_engine/payload_consumer/payload_verifier.h"
 #include "update_engine/update_metadata.pb.h"
@@ -55,6 +53,12 @@ class PayloadMetadata {
   // the payload.
   MetadataParseResult ParsePayloadHeader(const brillo::Blob& payload,
                                          ErrorCode* error);
+  MetadataParseResult ParsePayloadHeader(std::string_view payload,
+                                         ErrorCode* error) {
+    return ParsePayloadHeader(reinterpret_cast<const uint8_t*>(payload.data()),
+                              payload.size(),
+                              error);
+  }
   MetadataParseResult ParsePayloadHeader(const unsigned char* payload,
                                          size_t size,
                                          ErrorCode* error);
@@ -69,9 +73,16 @@ class PayloadMetadata {
   // to the payload server doesn't exploit any vulnerability in the code that
   // parses the protocol buffer.
   ErrorCode ValidateMetadataSignature(
-      const brillo::Blob& payload,
+      std::string_view payload,
       const std::string& metadata_signature,
       const PayloadVerifier& payload_verifier) const;
+  ErrorCode ValidateMetadataSignature(
+      const std::vector<uint8_t>& payload,
+      const std::string& metadata_signature,
+      const PayloadVerifier& payload_verifier) const {
+    return ValidateMetadataSignature(
+        ToStringView(payload), metadata_signature, payload_verifier);
+  }
 
   // Returns the major payload version. If the version was not yet parsed,
   // returns zero.
@@ -93,6 +104,12 @@ class PayloadMetadata {
   bool GetManifest(const unsigned char* payload,
                    size_t size,
                    DeltaArchiveManifest* out_manifest) const;
+  bool GetManifest(std::string_view payload,
+                   DeltaArchiveManifest* out_manifest) const {
+    return GetManifest(reinterpret_cast<const uint8_t*>(payload.data()),
+                       payload.size(),
+                       out_manifest);
+  }
 
   // Parses a payload file |payload_path| and prepares the metadata properties,
   // manifest and metadata signatures. Can be used as an easy to use utility to
diff --git a/payload_consumer/postinstall_runner_action.cc b/payload_consumer/postinstall_runner_action.cc
index 5a6eeab3..3b099166 100644
--- a/payload_consumer/postinstall_runner_action.cc
+++ b/payload_consumer/postinstall_runner_action.cc
@@ -109,14 +109,17 @@ void PostinstallRunnerAction::PerformAction() {
   auto dynamic_control = boot_control_->GetDynamicPartitionControl();
   CHECK(dynamic_control);
 
-  // Mount snapshot partitions for Virtual AB Compression Compression.
-  if (dynamic_control->UpdateUsesSnapshotCompression()) {
-    // If we are switching slots, then we are required to MapAllPartitions,
-    // as FinishUpdate() requires all partitions to be mapped.
-    // And switching slots requires FinishUpdate() to be called first
+  // Mount snapshot partitions for Virtual AB updates.
+  // If we are switching slots, then we are required to MapAllPartitions,
+  // as FinishUpdate() requires all partitions to be mapped.
+  // And switching slots requires FinishUpdate() to be called first
+  if (dynamic_control->GetVirtualAbFeatureFlag().IsEnabled() &&
+      !constants::kIsRecovery) {
     if (!install_plan_.partitions.empty() ||
         install_plan_.switch_slot_on_reboot) {
       if (!dynamic_control->MapAllPartitions()) {
+        LOG(ERROR) << "Failed to map all partitions, this would cause "
+                      "FinishUpdate to fail. Abort early.";
         return CompletePostinstall(ErrorCode::kPostInstallMountError);
       }
     }
@@ -280,14 +283,20 @@ void PostinstallRunnerAction::PerformPartitionPostinstall() {
   // Runs the postinstall script asynchronously to free up the main loop while
   // it's running.
   vector<string> command = {abs_path};
-#ifdef __ANDROID__
   // In Brillo and Android, we pass the slot number and status fd.
   command.push_back(std::to_string(install_plan_.target_slot));
   command.push_back(std::to_string(kPostinstallStatusFd));
-#else
-  // Chrome OS postinstall expects the target rootfs as the first parameter.
-  command.push_back(partition.target_path);
-#endif  // __ANDROID__
+  // If install plan only contains one partition, notify the script. Most likely
+  // we are scheduled by `triggerPostinstall` API. Certain scripts might want
+  // different behaviors when triggered by `triggerPostinstall` API. For
+  // example, call scheduler API to schedule a postinstall run during
+  // applyPayload(), and only run actual postinstall work if scheduled by
+  // external async scheduler.
+  if (install_plan_.partitions.size() == 1 &&
+      !install_plan_.switch_slot_on_reboot &&
+      install_plan_.download_url.starts_with(kPrefsManifestBytes)) {
+    command.push_back("1");
+  }
 
   current_command_ = Subprocess::Get().ExecFlags(
       command,
diff --git a/payload_consumer/postinstall_runner_action_recovery_unittest.cc b/payload_consumer/postinstall_runner_action_recovery_unittest.cc
new file mode 100644
index 00000000..3a869c90
--- /dev/null
+++ b/payload_consumer/postinstall_runner_action_recovery_unittest.cc
@@ -0,0 +1,202 @@
+//
+// Copyright (C) 2012 The Android Open Source Project
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
+#include "gmock/gmock.h"
+#include "update_engine/payload_consumer/postinstall_runner_action.h"
+
+#include <sys/stat.h>
+#include <sys/types.h>
+#include <unistd.h>
+
+#include <memory>
+#include <string>
+#include <utility>
+#include "common/dynamic_partition_control_interface.h"
+
+#include <base/bind.h>
+#include <base/files/file_util.h>
+#include <base/message_loop/message_loop.h>
+#include <android-base/stringprintf.h>
+#include <brillo/message_loops/base_message_loop.h>
+#include <brillo/message_loops/message_loop_utils.h>
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+#include "update_engine/common/fake_boot_control.h"
+#include "update_engine/common/fake_hardware.h"
+#include "update_engine/common/test_utils.h"
+#include "update_engine/common/utils.h"
+#include "update_engine/common/mock_dynamic_partition_control.h"
+
+using brillo::MessageLoop;
+using chromeos_update_engine::test_utils::ScopedLoopbackDeviceBinder;
+using std::string;
+using testing::_;
+using testing::AtLeast;
+using testing::Return;
+
+namespace chromeos_update_engine {
+
+class PostinstActionProcessorDelegate : public ActionProcessorDelegate {
+ public:
+  PostinstActionProcessorDelegate() = default;
+  void ProcessingDone(const ActionProcessor* processor,
+                      ErrorCode code) override {
+    MessageLoop::current()->BreakLoop();
+    processing_done_called_ = true;
+  }
+  void ProcessingStopped(const ActionProcessor* processor) override {
+    MessageLoop::current()->BreakLoop();
+    processing_stopped_called_ = true;
+  }
+
+  void ActionCompleted(ActionProcessor* processor,
+                       AbstractAction* action,
+                       ErrorCode code) override {
+    if (action->Type() == PostinstallRunnerAction::StaticType()) {
+      code_ = code;
+      code_set_ = true;
+    }
+  }
+
+  ErrorCode code_{ErrorCode::kError};
+  bool code_set_{false};
+  bool processing_done_called_{false};
+  bool processing_stopped_called_{false};
+};
+
+class MockPostinstallRunnerActionDelegate
+    : public PostinstallRunnerAction::DelegateInterface {
+ public:
+  MOCK_METHOD1(ProgressUpdate, void(double progress));
+};
+
+class PostinstallRunnerActionTest : public ::testing::Test {
+ protected:
+  void SetUp() override {
+    loop_.SetAsCurrent();
+    {
+      auto mock_dynamic_control =
+          std::make_unique<MockDynamicPartitionControl>();
+      mock_dynamic_control_ = mock_dynamic_control.get();
+      fake_boot_control_.SetDynamicPartitionControl(
+          std::move(mock_dynamic_control));
+    }
+    ON_CALL(*mock_dynamic_control_, FinishUpdate(_))
+        .WillByDefault(Return(true));
+    ON_CALL(*mock_dynamic_control_, GetVirtualAbFeatureFlag())
+        .WillByDefault(Return(FeatureFlag(FeatureFlag::Value::LAUNCH)));
+  }
+
+  // Setup an action processor and run the PostinstallRunnerAction with a single
+  // partition |device_path|, running the |postinstall_program| command from
+  // there.
+  void RunPostinstallAction(bool powerwash_required, bool save_rollback_data);
+
+  void RunPostinstallActionWithInstallPlan(const InstallPlan& install_plan);
+
+ public:
+  void ResumeRunningAction() {
+    ASSERT_NE(nullptr, postinstall_action_);
+    postinstall_action_->ResumeAction();
+  }
+
+ protected:
+  base::MessageLoopForIO base_loop_;
+  brillo::BaseMessageLoop loop_{&base_loop_};
+
+  FakeBootControl fake_boot_control_;
+  FakeHardware fake_hardware_;
+  MockDynamicPartitionControl* mock_dynamic_control_;
+  PostinstActionProcessorDelegate processor_delegate_;
+
+  // The PostinstallRunnerAction delegate receiving the progress updates.
+  PostinstallRunnerAction::DelegateInterface* setup_action_delegate_{nullptr};
+
+  // A pointer to the posinstall_runner action and the processor.
+  PostinstallRunnerAction* postinstall_action_{nullptr};
+  ActionProcessor* processor_{nullptr};
+};
+
+void PostinstallRunnerActionTest::RunPostinstallAction(
+    bool powerwash_required, bool save_rollback_data) {
+  InstallPlan::Partition part;
+  part.name = "part";
+  part.target_path = "/dev/invalid";
+  part.readonly_target_path = "/dev/invalid";
+  part.run_postinstall = false;
+  part.postinstall_path.clear();
+  InstallPlan install_plan;
+  install_plan.partitions = {part};
+  install_plan.download_url = "http://127.0.0.1:8080/update";
+  install_plan.powerwash_required = powerwash_required;
+  RunPostinstallActionWithInstallPlan(install_plan);
+}
+
+void PostinstallRunnerActionTest::RunPostinstallActionWithInstallPlan(
+    const chromeos_update_engine::InstallPlan& install_plan) {
+  ActionProcessor processor;
+  processor_ = &processor;
+  auto feeder_action = std::make_unique<ObjectFeederAction<InstallPlan>>();
+  feeder_action->set_obj(install_plan);
+  auto runner_action = std::make_unique<PostinstallRunnerAction>(
+      &fake_boot_control_, &fake_hardware_);
+  postinstall_action_ = runner_action.get();
+  base::FilePath temp_dir;
+  TEST_AND_RETURN(base::CreateNewTempDirectory("postinstall", &temp_dir));
+  postinstall_action_->SetMountDir(temp_dir.value());
+  runner_action->set_delegate(setup_action_delegate_);
+  BondActions(feeder_action.get(), runner_action.get());
+  auto collector_action =
+      std::make_unique<ObjectCollectorAction<InstallPlan>>();
+  BondActions(runner_action.get(), collector_action.get());
+  processor.EnqueueAction(std::move(feeder_action));
+  processor.EnqueueAction(std::move(runner_action));
+  processor.EnqueueAction(std::move(collector_action));
+  processor.set_delegate(&processor_delegate_);
+
+  loop_.PostTask(
+      FROM_HERE,
+      base::Bind(
+          [](ActionProcessor* processor) { processor->StartProcessing(); },
+          base::Unretained(&processor)));
+  loop_.Run();
+  ASSERT_FALSE(processor.IsRunning());
+  postinstall_action_ = nullptr;
+  processor_ = nullptr;
+  ASSERT_TRUE(processor_delegate_.processing_stopped_called_ ||
+              processor_delegate_.processing_done_called_);
+  if (processor_delegate_.processing_done_called_) {
+    // Validation check that the code was set when the processor finishes.
+    ASSERT_TRUE(processor_delegate_.code_set_);
+  }
+}
+
+// Test that postinstall succeeds in the simple case of running the default
+// /postinst command which only exits 0.
+TEST_F(PostinstallRunnerActionTest, RunAsRootSimpleTest) {
+  EXPECT_CALL(*mock_dynamic_control_, GetVirtualAbFeatureFlag())
+      .WillOnce(Return(FeatureFlag(FeatureFlag::Value::LAUNCH)));
+  RunPostinstallAction(false, false);
+  ASSERT_EQ(ErrorCode::kSuccess, processor_delegate_.code_);
+  ASSERT_TRUE(processor_delegate_.processing_done_called_);
+
+  // Since powerwash_required was false, this should not trigger a powerwash.
+  ASSERT_FALSE(fake_hardware_.IsPowerwashScheduled());
+  ASSERT_FALSE(fake_hardware_.GetIsRollbackPowerwashScheduled());
+}
+
+}  // namespace chromeos_update_engine
diff --git a/payload_consumer/postinstall_runner_action_unittest.cc b/payload_consumer/postinstall_runner_action_unittest.cc
index 028402a5..85791443 100644
--- a/payload_consumer/postinstall_runner_action_unittest.cc
+++ b/payload_consumer/postinstall_runner_action_unittest.cc
@@ -23,6 +23,7 @@
 #include <memory>
 #include <string>
 #include <utility>
+#include "common/dynamic_partition_control_interface.h"
 
 #include <base/bind.h>
 #include <base/files/file_util.h>
@@ -44,10 +45,14 @@
 #include "update_engine/common/subprocess.h"
 #include "update_engine/common/test_utils.h"
 #include "update_engine/common/utils.h"
+#include "update_engine/common/mock_dynamic_partition_control.h"
 
 using brillo::MessageLoop;
 using chromeos_update_engine::test_utils::ScopedLoopbackDeviceBinder;
 using std::string;
+using testing::_;
+using testing::AtLeast;
+using testing::Return;
 
 namespace chromeos_update_engine {
 
@@ -95,6 +100,21 @@ class PostinstallRunnerActionTest : public ::testing::Test {
     // stored in the "disk_ext2_unittest.img" image.
     postinstall_image_ =
         test_utils::GetBuildArtifactsPath("gen/disk_ext2_unittest.img");
+    {
+      auto mock_dynamic_control =
+          std::make_unique<MockDynamicPartitionControl>();
+      mock_dynamic_control_ = mock_dynamic_control.get();
+      fake_boot_control_.SetDynamicPartitionControl(
+          std::move(mock_dynamic_control));
+    }
+    ON_CALL(*mock_dynamic_control_, FinishUpdate(_))
+        .WillByDefault(Return(true));
+    ON_CALL(*mock_dynamic_control_, MapAllPartitions())
+        .WillByDefault(Return(true));
+    ON_CALL(*mock_dynamic_control_, UnmapAllPartitions())
+        .WillByDefault(Return(true));
+    ON_CALL(*mock_dynamic_control_, GetVirtualAbFeatureFlag())
+        .WillByDefault(Return(FeatureFlag(FeatureFlag::Value::LAUNCH)));
   }
 
   // Setup an action processor and run the PostinstallRunnerAction with a single
@@ -173,6 +193,7 @@ class PostinstallRunnerActionTest : public ::testing::Test {
 
   FakeBootControl fake_boot_control_;
   FakeHardware fake_hardware_;
+  MockDynamicPartitionControl* mock_dynamic_control_;
   PostinstActionProcessorDelegate processor_delegate_;
 
   // The PostinstallRunnerAction delegate receiving the progress updates.
@@ -398,6 +419,7 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootSuspendResumeActionTest) {
 // Test that we can cancel a postinstall action while it is running.
 TEST_F(PostinstallRunnerActionTest, RunAsRootCancelPostinstallActionTest) {
   ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
+  EXPECT_CALL(*mock_dynamic_control_, MapAllPartitions()).Times(AtLeast(1));
 
   // Wait for the action to start and then cancel it.
   CancelWhenStarted();
@@ -411,6 +433,10 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootCancelPostinstallActionTest) {
 // Test that we parse and process the progress reports from the progress
 // file descriptor.
 TEST_F(PostinstallRunnerActionTest, RunAsRootProgressUpdatesTest) {
+  EXPECT_CALL(*mock_dynamic_control_, MapAllPartitions())
+      .Times(AtLeast(1))
+      .WillRepeatedly(Return(true));
+  EXPECT_CALL(*mock_dynamic_control_, FinishUpdate(_)).Times(AtLeast(1));
   testing::StrictMock<MockPostinstallRunnerActionDelegate> mock_delegate_;
   testing::InSequence s;
   EXPECT_CALL(mock_delegate_, ProgressUpdate(0));
diff --git a/payload_generator/full_update_generator.cc b/payload_generator/full_update_generator.cc
index 2491f76b..5362525d 100644
--- a/payload_generator/full_update_generator.cc
+++ b/payload_generator/full_update_generator.cc
@@ -17,11 +17,8 @@
 #include "update_engine/payload_generator/full_update_generator.h"
 
 #include <fcntl.h>
-#include <inttypes.h>
 
 #include <algorithm>
-#include <deque>
-#include <memory>
 
 #include <base/format_macros.h>
 #include <android-base/stringprintf.h>
@@ -98,7 +95,7 @@ bool ChunkProcessor::ProcessChunk() {
       fd_, buffer_in_.data(), buffer_in_.size(), offset_, &bytes_read));
   TEST_AND_RETURN_FALSE(bytes_read == static_cast<ssize_t>(size_));
 
-  InstallOperation::Type op_type;
+  InstallOperation::Type op_type{};
   TEST_AND_RETURN_FALSE(diff_utils::GenerateBestFullOperation(
       buffer_in_, version_, &op_blob, &op_type));
 
@@ -122,7 +119,7 @@ bool FullUpdateGenerator::GenerateOperations(
   // For performance reasons, we force a small default hard limit of 1 MiB. This
   // limit can be changed in the config, and we will use the smaller of the two
   // soft/hard limits.
-  size_t full_chunk_size;
+  size_t full_chunk_size{};
   if (config.hard_chunk_size >= 0) {
     full_chunk_size = std::min(static_cast<size_t>(config.hard_chunk_size),
                                config.soft_chunk_size);
diff --git a/scripts/Android.bp b/scripts/Android.bp
index e86a9f20..b4d85390 100644
--- a/scripts/Android.bp
+++ b/scripts/Android.bp
@@ -68,12 +68,4 @@ python_binary_host {
     libs: [
         "update_payload",
     ],
-    version: {
-        py2: {
-            enabled: false,
-        },
-        py3: {
-            enabled: true,
-        },
-    },
 }
```

