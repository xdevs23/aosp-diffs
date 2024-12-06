```diff
diff --git a/aosp/dynamic_partition_control_android.cc b/aosp/dynamic_partition_control_android.cc
index d8df5206..af46b35b 100644
--- a/aosp/dynamic_partition_control_android.cc
+++ b/aosp/dynamic_partition_control_android.cc
@@ -199,7 +199,7 @@ bool DynamicPartitionControlAndroid::MapPartitionInternal(
   };
   bool success = false;
   if (GetVirtualAbFeatureFlag().IsEnabled() && target_supports_snapshot_ &&
-      force_writable && ExpectMetadataMounted()) {
+      slot != source_slot_ && force_writable && ExpectMetadataMounted()) {
     // Only target partitions are mapped with force_writable. On Virtual
     // A/B devices, target partitions may overlap with source partitions, so
     // they must be mapped with snapshot.
@@ -317,6 +317,7 @@ bool DynamicPartitionControlAndroid::UnmapAllPartitions() {
 
 void DynamicPartitionControlAndroid::Cleanup() {
   UnmapAllPartitions();
+  LOG(INFO) << "UnmapAllPartitions done";
   metadata_device_.reset();
   if (GetVirtualAbFeatureFlag().IsEnabled()) {
     snapshot_ = SnapshotManager::New();
@@ -324,6 +325,7 @@ void DynamicPartitionControlAndroid::Cleanup() {
     snapshot_ = SnapshotManagerStub::New();
   }
   CHECK(snapshot_ != nullptr) << "Cannot initialize SnapshotManager.";
+  LOG(INFO) << "SnapshotManager initialized.";
 }
 
 bool DynamicPartitionControlAndroid::DeviceExists(const std::string& path) {
@@ -1245,7 +1247,7 @@ DynamicPartitionControlAndroid::GetDynamicPartitionDevice(
     }
   }
 
-  bool force_writable = (slot != current_slot) && !not_in_payload;
+  const bool force_writable = !not_in_payload;
   if (MapPartitionOnDeviceMapper(
           super_device, partition_name_suffix, slot, force_writable, device)) {
     return DynamicPartitionDeviceStatus::SUCCESS;
diff --git a/aosp/ota_extractor.cc b/aosp/ota_extractor.cc
index 713cfc35..42270f4b 100644
--- a/aosp/ota_extractor.cc
+++ b/aosp/ota_extractor.cc
@@ -17,6 +17,7 @@
 #include <array>
 #include <cstdint>
 #include <cstdio>
+#include <future>
 #include <iterator>
 #include <memory>
 
@@ -53,6 +54,7 @@ DEFINE_string(partitions,
               "",
               "Comma separated list of partitions to extract, leave empty for "
               "extracting all partitions");
+DEFINE_bool(single_thread, false, "Limit extraction to a single thread");
 
 using chromeos_update_engine::DeltaArchiveManifest;
 using chromeos_update_engine::PayloadMetadata;
@@ -93,6 +95,103 @@ void WriteVerity(const PartitionUpdate& partition,
   return;
 }
 
+bool ExtractImageFromPartition(const DeltaArchiveManifest& manifest,
+                               const PartitionUpdate& partition,
+                               const size_t data_begin,
+                               int payload_fd,
+                               std::string_view input_dir,
+                               std::string_view output_dir) {
+  InstallOperationExecutor executor(manifest.block_size());
+  const base::FilePath output_dir_path(
+      base::StringPiece(output_dir.data(), output_dir.size()));
+  const base::FilePath input_dir_path(
+      base::StringPiece(input_dir.data(), input_dir.size()));
+  std::vector<unsigned char> blob;
+
+  LOG(INFO) << "Extracting partition " << partition.partition_name()
+            << " size: " << partition.new_partition_info().size();
+  const auto output_path =
+      output_dir_path.Append(partition.partition_name() + ".img").value();
+  auto out_fd =
+      std::make_shared<chromeos_update_engine::EintrSafeFileDescriptor>();
+  TEST_AND_RETURN_FALSE_ERRNO(
+      out_fd->Open(output_path.c_str(), O_RDWR | O_CREAT, 0644));
+  auto in_fd =
+      std::make_shared<chromeos_update_engine::EintrSafeFileDescriptor>();
+  if (partition.has_old_partition_info()) {
+    const auto input_path =
+        input_dir_path.Append(partition.partition_name() + ".img").value();
+    LOG(INFO) << "Incremental OTA detected for partition "
+              << partition.partition_name() << " opening source image "
+              << input_path;
+    CHECK(in_fd->Open(input_path.c_str(), O_RDONLY))
+        << " failed to open " << input_path;
+  }
+
+  for (const auto& op : partition.operations()) {
+    if (op.has_src_sha256_hash()) {
+      brillo::Blob actual_hash;
+      TEST_AND_RETURN_FALSE(fd_utils::ReadAndHashExtents(
+          in_fd, op.src_extents(), manifest.block_size(), &actual_hash));
+      CHECK_EQ(HexEncode(ToStringView(actual_hash)),
+               HexEncode(op.src_sha256_hash()))
+          << ", failed partition: " << partition.partition_name();
+    }
+
+    blob.resize(op.data_length());
+    const auto op_data_offset = data_begin + op.data_offset();
+    ssize_t bytes_read = 0;
+    TEST_AND_RETURN_FALSE(utils::PReadAll(
+        payload_fd, blob.data(), blob.size(), op_data_offset, &bytes_read));
+    if (op.has_data_sha256_hash()) {
+      brillo::Blob actual_hash;
+      TEST_AND_RETURN_FALSE(HashCalculator::RawHashOfData(blob, &actual_hash));
+      CHECK_EQ(HexEncode(ToStringView(actual_hash)),
+               HexEncode(op.data_sha256_hash()))
+          << ", failed partition: " << partition.partition_name();
+    }
+    auto direct_writer = std::make_unique<DirectExtentWriter>(out_fd);
+    if (op.type() == InstallOperation::ZERO) {
+      TEST_AND_RETURN_FALSE(
+          executor.ExecuteZeroOrDiscardOperation(op, std::move(direct_writer)));
+    } else if (op.type() == InstallOperation::REPLACE ||
+               op.type() == InstallOperation::REPLACE_BZ ||
+               op.type() == InstallOperation::REPLACE_XZ) {
+      TEST_AND_RETURN_FALSE(executor.ExecuteReplaceOperation(
+          op, std::move(direct_writer), blob.data()));
+    } else if (op.type() == InstallOperation::SOURCE_COPY) {
+      CHECK(in_fd->IsOpen())
+          << ", failed partition: " << partition.partition_name();
+      TEST_AND_RETURN_FALSE(executor.ExecuteSourceCopyOperation(
+          op, std::move(direct_writer), in_fd));
+    } else {
+      CHECK(in_fd->IsOpen())
+          << ", failed partition: " << partition.partition_name();
+      TEST_AND_RETURN_FALSE(executor.ExecuteDiffOperation(
+          op, std::move(direct_writer), in_fd, blob.data(), blob.size()));
+    }
+  }
+  WriteVerity(partition, out_fd, manifest.block_size());
+  int err =
+      truncate64(output_path.c_str(), partition.new_partition_info().size());
+  if (err) {
+    PLOG(ERROR) << "Failed to truncate " << output_path << " to "
+                << partition.new_partition_info().size();
+  }
+  brillo::Blob actual_hash;
+  TEST_AND_RETURN_FALSE(
+      HashCalculator::RawHashOfFile(output_path, &actual_hash));
+  CHECK_EQ(HexEncode(ToStringView(actual_hash)),
+           HexEncode(partition.new_partition_info().hash()))
+      << " Partition " << partition.partition_name()
+      << " hash mismatches. Either the source image or OTA package is "
+         "corrupted.";
+
+  LOG(INFO) << "Extracted partition " << partition.partition_name();
+
+  return true;
+}
+
 bool ExtractImagesFromOTA(const DeltaArchiveManifest& manifest,
                           const PayloadMetadata& metadata,
                           int payload_fd,
@@ -100,97 +199,46 @@ bool ExtractImagesFromOTA(const DeltaArchiveManifest& manifest,
                           std::string_view input_dir,
                           std::string_view output_dir,
                           const std::set<std::string>& partitions) {
-  InstallOperationExecutor executor(manifest.block_size());
   const size_t data_begin = metadata.GetMetadataSize() +
                             metadata.GetMetadataSignatureSize() +
                             payload_offset;
-  const base::FilePath output_dir_path(
-      base::StringPiece(output_dir.data(), output_dir.size()));
-  const base::FilePath input_dir_path(
-      base::StringPiece(input_dir.data(), input_dir.size()));
-  std::vector<unsigned char> blob;
-  for (const auto& partition : manifest.partitions()) {
-    if (!partitions.empty() &&
-        partitions.count(partition.partition_name()) == 0) {
-      continue;
-    }
-    LOG(INFO) << "Extracting partition " << partition.partition_name()
-              << " size: " << partition.new_partition_info().size();
-    const auto output_path =
-        output_dir_path.Append(partition.partition_name() + ".img").value();
-    auto out_fd =
-        std::make_shared<chromeos_update_engine::EintrSafeFileDescriptor>();
-    TEST_AND_RETURN_FALSE_ERRNO(
-        out_fd->Open(output_path.c_str(), O_RDWR | O_CREAT, 0644));
-    auto in_fd =
-        std::make_shared<chromeos_update_engine::EintrSafeFileDescriptor>();
-    if (partition.has_old_partition_info()) {
-      const auto input_path =
-          input_dir_path.Append(partition.partition_name() + ".img").value();
-      LOG(INFO) << "Incremental OTA detected for partition "
-                << partition.partition_name() << " opening source image "
-                << input_path;
-      CHECK(in_fd->Open(input_path.c_str(), O_RDONLY))
-          << " failed to open " << input_path;
-    }
-
-    for (const auto& op : partition.operations()) {
-      if (op.has_src_sha256_hash()) {
-        brillo::Blob actual_hash;
-        TEST_AND_RETURN_FALSE(fd_utils::ReadAndHashExtents(
-            in_fd, op.src_extents(), manifest.block_size(), &actual_hash));
-        CHECK_EQ(HexEncode(ToStringView(actual_hash)),
-                 HexEncode(op.src_sha256_hash()));
-      }
+  bool ret = true;
 
-      blob.resize(op.data_length());
-      const auto op_data_offset = data_begin + op.data_offset();
-      ssize_t bytes_read = 0;
-      TEST_AND_RETURN_FALSE(utils::PReadAll(
-          payload_fd, blob.data(), blob.size(), op_data_offset, &bytes_read));
-      if (op.has_data_sha256_hash()) {
-        brillo::Blob actual_hash;
-        TEST_AND_RETURN_FALSE(
-            HashCalculator::RawHashOfData(blob, &actual_hash));
-        CHECK_EQ(HexEncode(ToStringView(actual_hash)),
-                 HexEncode(op.data_sha256_hash()));
-      }
-      auto direct_writer = std::make_unique<DirectExtentWriter>(out_fd);
-      if (op.type() == InstallOperation::ZERO) {
-        TEST_AND_RETURN_FALSE(executor.ExecuteZeroOrDiscardOperation(
-            op, std::move(direct_writer)));
-      } else if (op.type() == InstallOperation::REPLACE ||
-                 op.type() == InstallOperation::REPLACE_BZ ||
-                 op.type() == InstallOperation::REPLACE_XZ) {
-        TEST_AND_RETURN_FALSE(executor.ExecuteReplaceOperation(
-            op, std::move(direct_writer), blob.data()));
-      } else if (op.type() == InstallOperation::SOURCE_COPY) {
-        CHECK(in_fd->IsOpen());
-        TEST_AND_RETURN_FALSE(executor.ExecuteSourceCopyOperation(
-            op, std::move(direct_writer), in_fd));
-      } else {
-        CHECK(in_fd->IsOpen());
-        TEST_AND_RETURN_FALSE(executor.ExecuteDiffOperation(
-            op, std::move(direct_writer), in_fd, blob.data(), blob.size()));
+  if (FLAGS_single_thread) {
+    for (const auto& partition : manifest.partitions()) {
+      if (!ExtractImageFromPartition(manifest,
+                                     partition,
+                                     data_begin,
+                                     payload_fd,
+                                     input_dir,
+                                     output_dir)) {
+        ret = false;
+        LOG(ERROR) << "Extraction of partition " << partition.partition_name()
+                   << " failed";
+        break;
       }
     }
-    WriteVerity(partition, out_fd, manifest.block_size());
-    int err =
-        truncate64(output_path.c_str(), partition.new_partition_info().size());
-    if (err) {
-      PLOG(ERROR) << "Failed to truncate " << output_path << " to "
-                  << partition.new_partition_info().size();
+  } else {
+    std::vector<std::pair<std::future<bool>, std::string>> futures;
+    for (const auto& partition : manifest.partitions()) {
+      futures.push_back(std::make_pair(std::async(std::launch::async,
+                                                  ExtractImageFromPartition,
+                                                  manifest,
+                                                  partition,
+                                                  data_begin,
+                                                  payload_fd,
+                                                  input_dir,
+                                                  output_dir),
+                                       partition.partition_name()));
+    }
+    for (auto& future : futures) {
+      if (!future.first.get()) {
+        ret = false;
+        LOG(ERROR) << "Extraction of partition " << future.second << " failed";
+      }
     }
-    brillo::Blob actual_hash;
-    TEST_AND_RETURN_FALSE(
-        HashCalculator::RawHashOfFile(output_path, &actual_hash));
-    CHECK_EQ(HexEncode(ToStringView(actual_hash)),
-             HexEncode(partition.new_partition_info().hash()))
-        << " Partition " << partition.partition_name()
-        << " hash mismatches. Either the source image or OTA package is "
-           "corrupted.";
   }
-  return true;
+  return ret;
 }
 
 }  // namespace chromeos_update_engine
diff --git a/aosp/update_attempter_android.cc b/aosp/update_attempter_android.cc
index 0f6fc5ce..857685f8 100644
--- a/aosp/update_attempter_android.cc
+++ b/aosp/update_attempter_android.cc
@@ -299,6 +299,8 @@ bool UpdateAttempterAndroid::ApplyPayload(
   install_plan_.is_resume = !payload_id.empty() &&
                             DeltaPerformer::CanResumeUpdate(prefs_, payload_id);
   if (!install_plan_.is_resume) {
+    LOG(INFO) << "Starting a new update " << payload_url
+              << " size: " << payload_size << " offset: " << payload_offset;
     boot_control_->GetDynamicPartitionControl()->Cleanup();
     boot_control_->GetDynamicPartitionControl()->ResetUpdate(prefs_);
 
@@ -379,11 +381,26 @@ bool UpdateAttempterAndroid::ApplyPayload(
 #endif  // _UE_SIDELOAD
   }
   // Setup extra headers.
-  if (!headers[kPayloadPropertyAuthorization].empty())
+  if (!headers[kPayloadPropertyAuthorization].empty()) {
     fetcher->SetHeader("Authorization", headers[kPayloadPropertyAuthorization]);
-  if (!headers[kPayloadPropertyUserAgent].empty())
+  }
+  if (!headers[kPayloadPropertyUserAgent].empty()) {
     fetcher->SetHeader("User-Agent", headers[kPayloadPropertyUserAgent]);
-
+  }
+  if (!headers[kPayloadPropertyHTTPExtras].empty()) {
+    auto entries =
+        android::base::Split(headers[kPayloadPropertyHTTPExtras], " ");
+    for (auto& entry : entries) {
+      auto parts = android::base::Split(entry, ";");
+      if (parts.size() != 2) {
+        LOG(ERROR)
+            << "HTTP headers are not in expected format. "
+               "headers[kPayloadPropertyHTTPExtras] = key1;val1 key2;val2";
+        continue;
+      }
+      fetcher->SetHeader(parts[0], parts[1]);
+    }
+  }
   if (!headers[kPayloadPropertyNetworkProxy].empty()) {
     LOG(INFO) << "Using proxy url from payload headers: "
               << headers[kPayloadPropertyNetworkProxy];
@@ -848,6 +865,9 @@ void UpdateAttempterAndroid::TerminateUpdateAndNotify(ErrorCode error_code) {
 
   boot_control_->GetDynamicPartitionControl()->Cleanup();
 
+  for (auto observer : daemon_state_->service_observers())
+    observer->SendPayloadApplicationComplete(error_code);
+
   download_progress_ = 0;
   UpdateStatus new_status =
       (error_code == ErrorCode::kSuccess ? UpdateStatus::UPDATED_NEED_REBOOT
@@ -861,9 +881,6 @@ void UpdateAttempterAndroid::TerminateUpdateAndNotify(ErrorCode error_code) {
     LOG(WARNING) << "Unable to unbind network.";
   }
 
-  for (auto observer : daemon_state_->service_observers())
-    observer->SendPayloadApplicationComplete(error_code);
-
   CollectAndReportUpdateMetricsOnUpdateFinished(error_code);
   ClearMetricsPrefs();
   if (error_code == ErrorCode::kSuccess) {
diff --git a/common/constants.h b/common/constants.h
index 3fcf1f14..dcd181f8 100644
--- a/common/constants.h
+++ b/common/constants.h
@@ -163,6 +163,8 @@ static constexpr const auto& kPayloadPropertyMetadataSize = "METADATA_SIZE";
 static constexpr const auto& kPayloadPropertyMetadataHash = "METADATA_HASH";
 // The Authorization: HTTP header to be sent when downloading the payload.
 static constexpr const auto& kPayloadPropertyAuthorization = "AUTHORIZATION";
+// HTTP headers extra entries in the format of key1;val1 key2;val2 key3;val3
+static constexpr const auto& kPayloadPropertyHTTPExtras = "HTTP_EXTRAS";
 // The User-Agent HTTP header to be sent when downloading the payload.
 static constexpr const auto& kPayloadPropertyUserAgent = "USER_AGENT";
 // Set "POWERWASH=1" to powerwash (factory data reset) the device after
diff --git a/common/http_fetcher_unittest.cc b/common/http_fetcher_unittest.cc
index 06f3e151..b2296602 100644
--- a/common/http_fetcher_unittest.cc
+++ b/common/http_fetcher_unittest.cc
@@ -548,6 +548,8 @@ TYPED_TEST(HttpFetcherTest, ExtraHeadersInRequestTest) {
   fetcher->SetHeader("User-Agent", "MyTest");
   fetcher->SetHeader("user-agent", "Override that header");
   fetcher->SetHeader("Authorization", "Basic user:passwd");
+  fetcher->SetHeader("Cache-Control", "testControl");
+  fetcher->SetHeader("Connection", "testConnection");
 
   // Invalid headers.
   fetcher->SetHeader("X-Foo", "Invalid\nHeader\nIgnored");
@@ -571,6 +573,8 @@ TYPED_TEST(HttpFetcherTest, ExtraHeadersInRequestTest) {
             delegate.data.find("user-agent: Override that header\r\n"));
   EXPECT_NE(string::npos,
             delegate.data.find("Authorization: Basic user:passwd\r\n"));
+  EXPECT_NE(string::npos, delegate.data.find("Cache-Control: testControl\r\n"));
+  EXPECT_NE(string::npos, delegate.data.find("Connection: testConnection\r\n"));
 
   EXPECT_EQ(string::npos, delegate.data.find("\nAccept:"));
   EXPECT_EQ(string::npos, delegate.data.find("X-Foo: Invalid"));
diff --git a/common/prefs.cc b/common/prefs.cc
index 79d622f4..77078cf0 100644
--- a/common/prefs.cc
+++ b/common/prefs.cc
@@ -200,7 +200,12 @@ bool Prefs::FileStorage::CreateTemporaryPrefs() {
     return false;
   }
   // Copy the directory.
-  std::filesystem::copy(source_directory, destination_directory);
+  std::error_code e;
+  std::filesystem::copy(source_directory, destination_directory, e);
+  if (e) {
+    LOG(ERROR) << "failed to copy prefs to prefs_tmp: " << e.message();
+    return false;
+  }
 
   return true;
 }
@@ -209,7 +214,12 @@ bool Prefs::FileStorage::DeleteTemporaryPrefs() {
   std::filesystem::path destination_directory(GetTemporaryDir());
 
   if (std::filesystem::exists(destination_directory)) {
-    return std::filesystem::remove_all(destination_directory);
+    std::error_code e;
+    std::filesystem::remove_all(destination_directory, e);
+    if (e) {
+      LOG(ERROR) << "failed to remove directory: " << e.message();
+      return false;
+    }
   }
   return true;
 }
diff --git a/lz4diff/lz4diff_compress_unittest.cc b/lz4diff/lz4diff_compress_unittest.cc
index d05c6bec..9caa9a31 100644
--- a/lz4diff/lz4diff_compress_unittest.cc
+++ b/lz4diff/lz4diff_compress_unittest.cc
@@ -14,10 +14,10 @@
 // limitations under the License.
 //
 
+#include <fcntl.h>
 #include <unistd.h>
 
 #include <algorithm>
-#include <mutex>
 #include <string>
 #include <vector>
 
@@ -48,10 +48,10 @@ static void ExtractErofsImage(const char* erofs_image,
                               const char* inode_path,
                               Blob* output) {
   struct erofs_sb_info sbi {};
-  auto err = dev_open_ro(&sbi, erofs_image);
+  auto err = erofs_dev_open(&sbi, erofs_image, O_RDONLY);
   ASSERT_EQ(err, 0);
   DEFER {
-    dev_close(&sbi);
+    erofs_dev_close(&sbi);
   };
 
   err = erofs_read_superblock(&sbi);
diff --git a/payload_consumer/filesystem_verifier_action.cc b/payload_consumer/filesystem_verifier_action.cc
index 5345085c..2e2f6b96 100644
--- a/payload_consumer/filesystem_verifier_action.cc
+++ b/payload_consumer/filesystem_verifier_action.cc
@@ -273,7 +273,7 @@ void FilesystemVerifierAction::WriteVerityAndHashPartition(
     return;
   }
   const auto read_size =
-      std::min<size_t>(buffer_size, end_offset - start_offset);
+      std::min<uint64_t>(buffer_size, end_offset - start_offset);
   const auto bytes_read = fd->Read(buffer, read_size);
   if (bytes_read < 0 || static_cast<size_t>(bytes_read) != read_size) {
     PLOG(ERROR) << "Failed to read offset " << start_offset << " expected "
@@ -319,7 +319,7 @@ void FilesystemVerifierAction::HashPartition(const off64_t start_offset,
     return;
   }
   const auto read_size =
-      std::min<size_t>(buffer_size, end_offset - start_offset);
+      std::min<uint64_t>(buffer_size, end_offset - start_offset);
   const auto bytes_read = fd->Read(buffer, read_size);
   if (bytes_read < 0 || static_cast<size_t>(bytes_read) != read_size) {
     PLOG(ERROR) << "Failed to read offset " << start_offset << " expected "
@@ -406,7 +406,6 @@ void FilesystemVerifierAction::StartPartitionHashing() {
   buffer_.resize(kReadFileBufferSize);
   hasher_ = std::make_unique<HashCalculator>();
 
-  offset_ = 0;
   filesystem_data_end_ = partition_size_;
   if (partition.fec_offset > 0) {
     CHECK_LE(partition.hash_tree_offset, partition.fec_offset)
@@ -456,7 +455,7 @@ const std::string& FilesystemVerifierAction::GetPartitionPath() const {
   }
 }
 
-size_t FilesystemVerifierAction::GetPartitionSize() const {
+uint64_t FilesystemVerifierAction::GetPartitionSize() const {
   const InstallPlan::Partition& partition =
       install_plan_.partitions[partition_index_];
   switch (verifier_step_) {
diff --git a/payload_consumer/filesystem_verifier_action.h b/payload_consumer/filesystem_verifier_action.h
index 5bc44b1f..d8cb9025 100644
--- a/payload_consumer/filesystem_verifier_action.h
+++ b/payload_consumer/filesystem_verifier_action.h
@@ -109,7 +109,7 @@ class FilesystemVerifierAction : public InstallPlanAction {
 
   bool IsVABC(const InstallPlan::Partition& partition) const;
 
-  size_t GetPartitionSize() const;
+  uint64_t GetPartitionSize() const;
 
   // When the read is done, finalize the hash checking of the current partition
   // and continue checking the next one.
@@ -163,9 +163,6 @@ class FilesystemVerifierAction : public InstallPlanAction {
   // partition in gpt.
   uint64_t partition_size_{0};
 
-  // The byte offset that we are reading in the current partition.
-  uint64_t offset_{0};
-
   // The end offset of filesystem data, first byte position of hashtree.
   uint64_t filesystem_data_end_{0};
 
diff --git a/payload_consumer/install_plan.cc b/payload_consumer/install_plan.cc
index cea8e5a9..9c3934d5 100644
--- a/payload_consumer/install_plan.cc
+++ b/payload_consumer/install_plan.cc
@@ -99,7 +99,6 @@ string InstallPlan::ToString() const {
           {"powerwash_required", utils::ToString(powerwash_required)},
           {"switch_slot_on_reboot", utils::ToString(switch_slot_on_reboot)},
           {"run_post_install", utils::ToString(run_post_install)},
-          {"is_rollback", utils::ToString(is_rollback)},
           {"rollback_data_save_requested",
            utils::ToString(rollback_data_save_requested)},
           {"write_verity", utils::ToString(write_verity)},
diff --git a/payload_consumer/install_plan.h b/payload_consumer/install_plan.h
index dbbe4b25..097c6cef 100644
--- a/payload_consumer/install_plan.h
+++ b/payload_consumer/install_plan.h
@@ -182,9 +182,6 @@ struct InstallPlan {
   // False otherwise.
   bool run_post_install{true};
 
-  // True if this update is a rollback.
-  bool is_rollback{false};
-
   // True if this rollback should preserve some system data.
   bool rollback_data_save_requested{false};
 
diff --git a/payload_consumer/install_plan_unittest.cc b/payload_consumer/install_plan_unittest.cc
index 193d9366..d2a3f5f5 100644
--- a/payload_consumer/install_plan_unittest.cc
+++ b/payload_consumer/install_plan_unittest.cc
@@ -54,7 +54,6 @@ hash_checks_mandatory: false
 powerwash_required: false
 switch_slot_on_reboot: true
 run_post_install: true
-is_rollback: false
 rollback_data_save_requested: false
 write_verity: true
 Partition: foo-partition_name
diff --git a/payload_consumer/postinstall_runner_action.cc b/payload_consumer/postinstall_runner_action.cc
index bfdd39e3..4de75aa7 100644
--- a/payload_consumer/postinstall_runner_action.cc
+++ b/payload_consumer/postinstall_runner_action.cc
@@ -113,9 +113,11 @@ void PostinstallRunnerAction::PerformAction() {
 
   // Mount snapshot partitions for Virtual AB Compression Compression.
   if (dynamic_control->UpdateUsesSnapshotCompression()) {
-    // Before calling MapAllPartitions to map snapshot devices, all CowWriters
-    // must be closed, and MapAllPartitions() should be called.
-    if (!install_plan_.partitions.empty()) {
+    // If we are switching slots, then we are required to MapAllPartitions,
+    // as FinishUpdate() requires all partitions to be mapped.
+    // And switching slots requires FinishUpdate() to be called first
+    if (!install_plan_.partitions.empty() ||
+        install_plan_.switch_slot_on_reboot) {
       if (!dynamic_control->MapAllPartitions()) {
         return CompletePostinstall(ErrorCode::kPostInstallMountError);
       }
@@ -126,7 +128,7 @@ void PostinstallRunnerAction::PerformAction() {
   // if this is a full/normal powerwash, or a special rollback powerwash
   // that retains a small amount of system state such as enrollment and
   // network configuration. In both cases all user accounts are deleted.
-  if (install_plan_.powerwash_required || install_plan_.is_rollback) {
+  if (install_plan_.powerwash_required) {
     if (hardware_->SchedulePowerwash(
             install_plan_.rollback_data_save_requested)) {
       powerwash_scheduled_ = true;
@@ -456,14 +458,6 @@ void PostinstallRunnerAction::CompletePostinstall(ErrorCode error_code) {
   };
   if (error_code == ErrorCode::kSuccess) {
     if (install_plan_.switch_slot_on_reboot) {
-      if constexpr (!constants::kIsRecovery) {
-        if (!boot_control_->GetDynamicPartitionControl()->MapAllPartitions()) {
-          LOG(WARNING)
-              << "Failed to map all partitions before marking snapshot as "
-                 "ready for slot switch. Subsequent FinishUpdate() call may or "
-                 "may not work";
-        }
-      }
       if (!boot_control_->GetDynamicPartitionControl()->FinishUpdate(
               install_plan_.powerwash_required) ||
           !boot_control_->SetActiveBootSlot(install_plan_.target_slot)) {
diff --git a/payload_consumer/postinstall_runner_action_unittest.cc b/payload_consumer/postinstall_runner_action_unittest.cc
index 75d93dc7..c899599c 100644
--- a/payload_consumer/postinstall_runner_action_unittest.cc
+++ b/payload_consumer/postinstall_runner_action_unittest.cc
@@ -104,7 +104,6 @@ class PostinstallRunnerActionTest : public ::testing::Test {
   void RunPostinstallAction(const string& device_path,
                             const string& postinstall_program,
                             bool powerwash_required,
-                            bool is_rollback,
                             bool save_rollback_data);
 
   void RunPostinstallActionWithInstallPlan(const InstallPlan& install_plan);
@@ -189,7 +188,6 @@ void PostinstallRunnerActionTest::RunPostinstallAction(
     const string& device_path,
     const string& postinstall_program,
     bool powerwash_required,
-    bool is_rollback,
     bool save_rollback_data) {
   InstallPlan::Partition part;
   part.name = "part";
@@ -201,7 +199,6 @@ void PostinstallRunnerActionTest::RunPostinstallAction(
   install_plan.partitions = {part};
   install_plan.download_url = "http://127.0.0.1:8080/update";
   install_plan.powerwash_required = powerwash_required;
-  install_plan.is_rollback = is_rollback;
   install_plan.rollback_data_save_requested = save_rollback_data;
   RunPostinstallActionWithInstallPlan(install_plan);
 }
@@ -279,8 +276,7 @@ TEST_F(PostinstallRunnerActionTest, ProcessProgressLineTest) {
 TEST_F(PostinstallRunnerActionTest, RunAsRootSimpleTest) {
   ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
 
-  RunPostinstallAction(
-      loop.dev(), kPostinstallDefaultScript, false, false, false);
+  RunPostinstallAction(loop.dev(), kPostinstallDefaultScript, false, false);
   EXPECT_EQ(ErrorCode::kSuccess, processor_delegate_.code_);
   EXPECT_TRUE(processor_delegate_.processing_done_called_);
 
@@ -291,7 +287,7 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootSimpleTest) {
 
 TEST_F(PostinstallRunnerActionTest, RunAsRootRunSymlinkFileTest) {
   ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
-  RunPostinstallAction(loop.dev(), "bin/postinst_link", false, false, false);
+  RunPostinstallAction(loop.dev(), "bin/postinst_link", false, false);
   EXPECT_EQ(ErrorCode::kSuccess, processor_delegate_.code_);
 }
 
@@ -301,7 +297,6 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootPowerwashRequiredTest) {
   RunPostinstallAction(loop.dev(),
                        "bin/postinst_example",
                        /*powerwash_required=*/true,
-                       false,
                        false);
   EXPECT_EQ(ErrorCode::kSuccess, processor_delegate_.code_);
 
@@ -310,43 +305,10 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootPowerwashRequiredTest) {
   EXPECT_FALSE(fake_hardware_.GetIsRollbackPowerwashScheduled());
 }
 
-TEST_F(PostinstallRunnerActionTest, RunAsRootRollbackTestNoDataSave) {
-  ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
-
-  // Run a simple postinstall program, rollback happened.
-  RunPostinstallAction(loop.dev(),
-                       "bin/postinst_example",
-                       false,
-                       /*is_rollback=*/true,
-                       /*save_rollback_data=*/false);
-  EXPECT_EQ(ErrorCode::kSuccess, processor_delegate_.code_);
-
-  // Check that powerwash was scheduled and that it's NOT a rollback powerwash.
-  EXPECT_TRUE(fake_hardware_.IsPowerwashScheduled());
-  EXPECT_FALSE(fake_hardware_.GetIsRollbackPowerwashScheduled());
-}
-
-TEST_F(PostinstallRunnerActionTest, RunAsRootRollbackTestWithDataSave) {
-  ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
-
-  // Run a simple postinstall program, rollback happened.
-  RunPostinstallAction(loop.dev(),
-                       "bin/postinst_example",
-                       false,
-                       /*is_rollback=*/true,
-                       /*save_rollback_data=*/true);
-  EXPECT_EQ(ErrorCode::kSuccess, processor_delegate_.code_);
-
-  // Check that powerwash was scheduled and that it's a rollback powerwash.
-  EXPECT_TRUE(fake_hardware_.IsPowerwashScheduled());
-  EXPECT_TRUE(fake_hardware_.GetIsRollbackPowerwashScheduled());
-}
-
 // Runs postinstall from a partition file that doesn't mount, so it should
 // fail.
 TEST_F(PostinstallRunnerActionTest, RunAsRootCantMountTest) {
-  RunPostinstallAction(
-      "/dev/null", kPostinstallDefaultScript, false, false, false);
+  RunPostinstallAction("/dev/null", kPostinstallDefaultScript, false, false);
   EXPECT_EQ(ErrorCode::kPostInstallMountError, processor_delegate_.code_);
 
   // In case of failure, Postinstall should not signal a powerwash even if it
@@ -382,7 +344,7 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootSkipOptionalPostinstallTest) {
 // fail.
 TEST_F(PostinstallRunnerActionTest, RunAsRootErrScriptTest) {
   ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
-  RunPostinstallAction(loop.dev(), "bin/postinst_fail1", false, false, false);
+  RunPostinstallAction(loop.dev(), "bin/postinst_fail1", false, false);
   EXPECT_EQ(ErrorCode::kPostinstallRunnerError, processor_delegate_.code_);
 }
 
@@ -390,7 +352,7 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootErrScriptTest) {
 // UMA with a different error code. Test those cases are properly detected.
 TEST_F(PostinstallRunnerActionTest, RunAsRootFirmwareBErrScriptTest) {
   ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
-  RunPostinstallAction(loop.dev(), "bin/postinst_fail3", false, false, false);
+  RunPostinstallAction(loop.dev(), "bin/postinst_fail3", false, false);
   EXPECT_EQ(ErrorCode::kPostinstallBootedFromFirmwareB,
             processor_delegate_.code_);
 }
@@ -398,7 +360,7 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootFirmwareBErrScriptTest) {
 // Check that you can't specify an absolute path.
 TEST_F(PostinstallRunnerActionTest, RunAsRootAbsolutePathNotAllowedTest) {
   ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
-  RunPostinstallAction(loop.dev(), "/etc/../bin/sh", false, false, false);
+  RunPostinstallAction(loop.dev(), "/etc/../bin/sh", false, false);
   EXPECT_EQ(ErrorCode::kPostinstallRunnerError, processor_delegate_.code_);
 }
 
@@ -407,8 +369,7 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootAbsolutePathNotAllowedTest) {
 // SElinux labels are only set on Android.
 TEST_F(PostinstallRunnerActionTest, RunAsRootCheckFileContextsTest) {
   ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
-  RunPostinstallAction(
-      loop.dev(), "bin/self_check_context", false, false, false);
+  RunPostinstallAction(loop.dev(), "bin/self_check_context", false, false);
   EXPECT_EQ(ErrorCode::kSuccess, processor_delegate_.code_);
 }
 
@@ -417,7 +378,7 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootCheckFileContextsTest) {
 TEST_F(PostinstallRunnerActionTest, RunAsRootCheckDefaultFileContextsTest) {
   ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
   RunPostinstallAction(
-      loop.dev(), "bin/self_check_default_context", false, false, false);
+      loop.dev(), "bin/self_check_default_context", false, false);
   EXPECT_EQ(ErrorCode::kSuccess, processor_delegate_.code_);
 }
 #endif  // __ANDROID__
@@ -430,7 +391,7 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootSuspendResumeActionTest) {
   loop_.PostTask(FROM_HERE,
                  base::Bind(&PostinstallRunnerActionTest::SuspendRunningAction,
                             base::Unretained(this)));
-  RunPostinstallAction(loop.dev(), "bin/postinst_suspend", false, false, false);
+  RunPostinstallAction(loop.dev(), "bin/postinst_suspend", false, false);
   // postinst_suspend returns 0 only if it was suspended at some point.
   EXPECT_EQ(ErrorCode::kSuccess, processor_delegate_.code_);
   EXPECT_TRUE(processor_delegate_.processing_done_called_);
@@ -442,7 +403,7 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootCancelPostinstallActionTest) {
 
   // Wait for the action to start and then cancel it.
   CancelWhenStarted();
-  RunPostinstallAction(loop.dev(), "bin/postinst_suspend", false, false, false);
+  RunPostinstallAction(loop.dev(), "bin/postinst_suspend", false, false);
   // When canceling the action, the action never finished and therefore we had
   // a ProcessingStopped call instead.
   EXPECT_FALSE(processor_delegate_.code_set_);
@@ -465,8 +426,7 @@ TEST_F(PostinstallRunnerActionTest, RunAsRootProgressUpdatesTest) {
 
   ScopedLoopbackDeviceBinder loop(postinstall_image_, false, nullptr);
   setup_action_delegate_ = &mock_delegate_;
-  RunPostinstallAction(
-      loop.dev(), "bin/postinst_progress", false, false, false);
+  RunPostinstallAction(loop.dev(), "bin/postinst_progress", false, false);
   EXPECT_EQ(ErrorCode::kSuccess, processor_delegate_.code_);
 }
 
diff --git a/payload_consumer/verified_source_fd.cc b/payload_consumer/verified_source_fd.cc
index 3f17ad71..d760d1ff 100644
--- a/payload_consumer/verified_source_fd.cc
+++ b/payload_consumer/verified_source_fd.cc
@@ -109,9 +109,16 @@ FileDescriptorPtr VerifiedSourceFd::ChooseSourceFD(
   brillo::Blob source_hash;
   brillo::Blob expected_source_hash(operation.src_sha256_hash().begin(),
                                     operation.src_sha256_hash().end());
-  if (fd_utils::ReadAndHashExtents(
-          source_fd_, operation.src_extents(), block_size_, &source_hash) &&
-      source_hash == expected_source_hash) {
+  if (!fd_utils::ReadAndHashExtents(
+          source_fd_, operation.src_extents(), block_size_, &source_hash)) {
+    LOG(ERROR) << "Failed to compute hash for operation " << operation.type()
+               << " data offset: " << operation.data_offset();
+    if (error) {
+      *error = ErrorCode::kDownloadOperationHashVerificationError;
+    }
+    return nullptr;
+  }
+  if (source_hash == expected_source_hash) {
     return source_fd_;
   }
   if (error) {
diff --git a/payload_consumer/verity_writer_android.cc b/payload_consumer/verity_writer_android.cc
index 4a476d20..d808dd54 100644
--- a/payload_consumer/verity_writer_android.cc
+++ b/payload_consumer/verity_writer_android.cc
@@ -78,7 +78,7 @@ bool IncrementalEncodeFEC::Compute(FileDescriptor* _read_fd,
     // Encodes |block_size| number of rs blocks each round so that we can read
     // one block each time instead of 1 byte to increase random read
     // performance. This uses about 1 MiB memory for 4K block size.
-    for (size_t j = 0; j < rs_n_; j++) {
+    for (uint64_t j = 0; j < rs_n_; j++) {
       uint64_t offset = fec_ecc_interleave(
           current_round_ * rs_n_ * block_size_ + j, rs_n_, num_rounds_);
       // Don't read past |data_size|, treat them as 0.
@@ -95,11 +95,11 @@ bool IncrementalEncodeFEC::Compute(FileDescriptor* _read_fd,
         TEST_AND_RETURN_FALSE(static_cast<size_t>(bytes_read) ==
                               buffer_.size());
       }
-      for (size_t k = 0; k < buffer_.size(); k++) {
+      for (uint64_t k = 0; k < buffer_.size(); k++) {
         rs_blocks_[k * rs_n_ + j] = buffer_[k];
       }
     }
-    for (size_t j = 0; j < block_size_; j++) {
+    for (uint64_t j = 0; j < block_size_; j++) {
       // Encode [j * rs_n_ : (j + 1) * rs_n_) in |rs_blocks| and write
       // |fec_roots| number of parity bytes to |j * fec_roots| in |fec|.
       encode_rs_char(rs_char_.get(),
diff --git a/payload_consumer/verity_writer_android.h b/payload_consumer/verity_writer_android.h
index 1aaafd5b..99269885 100644
--- a/payload_consumer/verity_writer_android.h
+++ b/payload_consumer/verity_writer_android.h
@@ -63,8 +63,8 @@ class IncrementalEncodeFEC {
   brillo::Blob fec_;
   brillo::Blob fec_read_;
   EncodeFECStep current_step_;
-  size_t current_round_;
-  size_t num_rounds_;
+  uint64_t current_round_;
+  uint64_t num_rounds_;
   FileDescriptor* read_fd_;
   FileDescriptor* write_fd_;
   uint64_t data_offset_;
@@ -73,7 +73,7 @@ class IncrementalEncodeFEC {
   uint64_t fec_size_;
   uint64_t fec_roots_;
   uint64_t block_size_;
-  size_t rs_n_;
+  uint64_t rs_n_;
   bool verify_mode_;
   std::unique_ptr<void, decltype(&free_rs_char)> rs_char_;
   UnownedCachedFileDescriptor cache_fd_;
diff --git a/payload_generator/erofs_filesystem.cc b/payload_generator/erofs_filesystem.cc
index 32a5fc57..2835dea3 100644
--- a/payload_generator/erofs_filesystem.cc
+++ b/payload_generator/erofs_filesystem.cc
@@ -175,12 +175,12 @@ std::unique_ptr<ErofsFilesystem> ErofsFilesystem::CreateFromFile(
   }
   struct erofs_sb_info sbi {};
 
-  if (const auto err = dev_open_ro(&sbi, filename.c_str()); err) {
+  if (const auto err = erofs_dev_open(&sbi, filename.c_str(), O_RDONLY); err) {
     PLOG(INFO) << "Failed to open " << filename;
     return nullptr;
   }
   DEFER {
-    dev_close(&sbi);
+    erofs_dev_close(&sbi);
   };
 
   if (const auto err = erofs_read_superblock(&sbi); err) {
@@ -189,7 +189,7 @@ std::unique_ptr<ErofsFilesystem> ErofsFilesystem::CreateFromFile(
   }
   const auto block_size = 1UL << sbi.blkszbits;
   struct stat st {};
-  if (const auto err = fstat(sbi.devfd, &st); err) {
+  if (const auto err = stat(filename.c_str(), &st); err) {
     PLOG(ERROR) << "Failed to stat() " << filename;
     return nullptr;
   }
```

