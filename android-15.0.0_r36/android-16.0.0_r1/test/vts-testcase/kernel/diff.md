```diff
diff --git a/api/TEST_MAPPING b/api/TEST_MAPPING
index aba9301..e99f678 100644
--- a/api/TEST_MAPPING
+++ b/api/TEST_MAPPING
@@ -1,8 +1,5 @@
 {
   "kernel-presubmit": [
-    {
-      "name": "bpf_module_test"
-    },
     {
       "name": "drop_caches_test"
     },
diff --git a/api/tun/OWNERS b/api/tun/OWNERS
index 237452c..4b02e39 100644
--- a/api/tun/OWNERS
+++ b/api/tun/OWNERS
@@ -1,4 +1,2 @@
 # Bug component: 31808
-lorenzo@google.com
-maze@google.com
-satk@google.com
+file:platform/packages/modules/Connectivity:main:/OWNERS_core_networking_xts
diff --git a/checkpoint/Android.bp b/checkpoint/Android.bp
index 7097bed..9fe1b5f 100644
--- a/checkpoint/Android.bp
+++ b/checkpoint/Android.bp
@@ -31,15 +31,11 @@ python_test_host {
         "vts_vndk_utils",
     ],
     test_suites: [
+        "automotive-sdv-tests",
         "vts",
     ],
     test_options: {
         unit_test: false,
     },
     test_config: "vts_kernel_checkpoint_test.xml",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        }
-    }
 }
diff --git a/encryption/file_based_encryption_tests.cpp b/encryption/file_based_encryption_tests.cpp
index b485440..95d891d 100644
--- a/encryption/file_based_encryption_tests.cpp
+++ b/encryption/file_based_encryption_tests.cpp
@@ -25,20 +25,28 @@
 // The correctness tests cover the following settings:
 //
 //    fileencryption=aes-256-xts:aes-256-cts:v2
+//    fileencryption=aes-256-xts:aes-256-cts:v2+dusize_4k
 //    fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized
+//    fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+dusize_4k
 //    fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0
+//    fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0+dusize_4k
 //    fileencryption=aes-256-xts:aes-256-cts:v2+emmc_optimized
 //    fileencryption=aes-256-xts:aes-256-cts:v2+emmc_optimized+wrappedkey_v0
 //    fileencryption=adiantum:adiantum:v2
+//    fileencryption=adiantum:adiantum:v2+dusize_4k
 //
 // On devices launching with R or higher those are equivalent to simply:
 //
 //    fileencryption=
+//    fileencryption=::dusize_4k
 //    fileencryption=::inlinecrypt_optimized
+//    fileencryption=::inlinecrypt_optimized+dusize_4k
 //    fileencryption=::inlinecrypt_optimized+wrappedkey_v0
+//    fileencryption=::inlinecrypt_optimized+wrappedkey_v0+dusize_4k
 //    fileencryption=::emmc_optimized
 //    fileencryption=::emmc_optimized+wrappedkey_v0
 //    fileencryption=adiantum
+//    fileencryption=adiantum+dusize_4k
 //
 // The tests don't check which one of those settings, if any, the device is
 // actually using; they just try to test everything they can.
@@ -103,14 +111,8 @@ constexpr const char *kUnencryptedDir = "/data/unencrypted";
 // encryption settings that Android is configured to use.
 constexpr const char *kTmpDir = "/data/local/tmp";
 
-// Assumed size of filesystem blocks, in bytes
-constexpr int kFilesystemBlockSize = 4096;
-
-// Size of the test file in filesystem blocks
-constexpr int kTestFileBlocks = 256;
-
-// Size of the test file in bytes
-constexpr int kTestFileBytes = kFilesystemBlockSize * kTestFileBlocks;
+// Test file size in bytes.  Must be a multiple of the filesystem block size.
+constexpr int kTestFileSize = 1 << 20;
 
 // fscrypt master key size in bytes
 constexpr int kFscryptMasterKeySize = 64;
@@ -139,7 +141,7 @@ struct FscryptFileNonce {
 // Format of the initialization vector
 union FscryptIV {
   struct {
-    __le32 lblk_num;      // file logical block number, starts at 0
+    __le32 du_index;  // zero-based index of the data unit number in the file
     __le32 inode_number;  // only used for IV_INO_LBLK_64
     uint8_t file_nonce[kFscryptFileNonceSize];  // only used for DIRECT_KEY
   };
@@ -263,15 +265,15 @@ class ScopedFsFreezer {
 
 // Reads the raw data of a file specified by |fd|. The file is located on the
 // filesystem specified by |fs_info|. The file has |expected_data_size| bytes of
-// initialized data; this must be a multiple of the filesystem block size
-// kFilesystemBlockSize.  The file may contain holes, in which case only the
-// non-holes are read; the holes are not counted in |expected_data_size|.
+// initialized data; this must be a multiple of the filesystem block size.  The
+// file may contain holes, in which case only the non-holes are read; the holes
+// are not counted in |expected_data_size|.
 static bool ReadRawDataOfFile(int fd, const FilesystemInfo &fs_info,
                               int expected_data_size,
                               std::vector<uint8_t> *raw_data) {
-  int max_extents = expected_data_size / kFilesystemBlockSize;
+  int max_extents = expected_data_size / fs_info.block_size;
 
-  EXPECT_TRUE(expected_data_size % kFilesystemBlockSize == 0);
+  EXPECT_TRUE(expected_data_size % fs_info.block_size == 0);
 
   if (fsync(fd) != 0) {
     ADD_FAILURE() << "Failed to sync file" << Errno();
@@ -298,7 +300,7 @@ static bool ReadRawDataOfFile(int fd, const FilesystemInfo &fs_info,
   // Direct I/O requires using a block size aligned buffer.
 
   std::unique_ptr<void, void (*)(void *)> buf_mem(
-      aligned_alloc(kFilesystemBlockSize, expected_data_size), free);
+      aligned_alloc(fs_info.block_size, expected_data_size), free);
   if (buf_mem == nullptr) {
     ADD_FAILURE() << "Out of memory";
     return false;
@@ -320,12 +322,12 @@ static bool ReadRawDataOfFile(int fd, const FilesystemInfo &fs_info,
                     << extent.fe_flags << std::dec;
       return false;
     }
-    if (extent.fe_length % kFilesystemBlockSize != 0) {
+    if (extent.fe_length % fs_info.block_size != 0) {
       ADD_FAILURE()
           << "Extent (length) is not aligned to filesystem block size";
       return false;
     }
-    if (extent.fe_physical % kFilesystemBlockSize != 0) {
+    if (extent.fe_physical % fs_info.block_size != 0) {
       ADD_FAILURE() << "Extent (physical address) is not aligned to filesystem "
                        "block size";
       return false;
@@ -337,14 +339,14 @@ static bool ReadRawDataOfFile(int fd, const FilesystemInfo &fs_info,
     // Find the raw block device and remap the physical offset.
     std::string raw_blk_device;
     for (const DiskMapEntry &map_entry : fs_info.disk_map) {
-      if (extent.fe_physical / kFilesystemBlockSize <= map_entry.end_blkaddr) {
-        if ((extent.fe_physical + extent.fe_length) / kFilesystemBlockSize >
+      if (extent.fe_physical / fs_info.block_size <= map_entry.end_blkaddr) {
+        if ((extent.fe_physical + extent.fe_length) / fs_info.block_size >
             (map_entry.end_blkaddr + 1)) {
           ADD_FAILURE() << "Extent spans multiple block devices";
           return false;
         }
         raw_blk_device = map_entry.raw_blk_device;
-        extent.fe_physical -= map_entry.start_blkaddr * kFilesystemBlockSize;
+        extent.fe_physical -= map_entry.start_blkaddr * fs_info.block_size;
         break;
       }
     }
@@ -438,9 +440,10 @@ static bool IsCompressibleCluster(int cluster_num) {
 // test that the encryption works correctly with both.  We also don't make the
 // data *too* compressible, since we want to have enough compressed blocks in
 // each cluster to see the IVs being incremented.
-static bool MakeSomeCompressibleClusters(std::vector<uint8_t> &bytes,
-                                         int log_cluster_size) {
-  int cluster_bytes = kFilesystemBlockSize << log_cluster_size;
+static bool MakeSomeCompressibleClusters(const FilesystemInfo &fs_info,
+                                         int log_cluster_size,
+                                         std::vector<uint8_t> &bytes) {
+  int cluster_bytes = fs_info.block_size << log_cluster_size;
   if (bytes.size() % cluster_bytes != 0) {
     ADD_FAILURE() << "Test file size (" << bytes.size()
                   << " bytes) is not divisible by compression cluster size ("
@@ -450,7 +453,7 @@ static bool MakeSomeCompressibleClusters(std::vector<uint8_t> &bytes,
   int num_clusters = bytes.size() / cluster_bytes;
   for (int i = 0; i < num_clusters; i++) {
     if (IsCompressibleCluster(i)) {
-      memset(&bytes[i * cluster_bytes], 0, 2 * kFilesystemBlockSize);
+      memset(&bytes[i * cluster_bytes], 0, 2 * fs_info.block_size);
     }
   }
   return true;
@@ -464,12 +467,12 @@ struct f2fs_compressed_cluster {
 } __attribute__((packed));
 
 static bool DecompressLZ4Cluster(const uint8_t *in, uint8_t *out,
-                                 int cluster_bytes) {
+                                 int block_size, int cluster_bytes) {
   const struct f2fs_compressed_cluster *cluster =
       reinterpret_cast<const struct f2fs_compressed_cluster *>(in);
   uint32_t clen = __le32_to_cpu(cluster->clen);
 
-  if (clen > cluster_bytes - kFilesystemBlockSize - sizeof(*cluster)) {
+  if (clen > cluster_bytes - block_size - sizeof(*cluster)) {
     ADD_FAILURE() << "Invalid compressed cluster (bad compressed size)";
     return false;
   }
@@ -484,9 +487,8 @@ static bool DecompressLZ4Cluster(const uint8_t *in, uint8_t *out,
   // ("f2fs: fix leaking uninitialized memory in compressed clusters").
   // Note that if this fails, we can still continue with the rest of the test.
   size_t full_clen = offsetof(struct f2fs_compressed_cluster, cdata[clen]);
-  if (full_clen % kFilesystemBlockSize != 0) {
-    size_t remainder =
-        kFilesystemBlockSize - (full_clen % kFilesystemBlockSize);
+  if (full_clen % block_size != 0) {
+    size_t remainder = block_size - (full_clen % block_size);
     std::vector<uint8_t> zeroes(remainder, 0);
     std::vector<uint8_t> actual(&cluster->cdata[clen],
                                 &cluster->cdata[clen + remainder]);
@@ -504,8 +506,9 @@ class FBEPolicyTest : public ::testing::Test {
   bool CreateAndSetHwWrappedKey(std::vector<uint8_t> *enc_key,
                                 std::vector<uint8_t> *sw_secret);
   int GetSkipFlagsForInoBasedEncryption();
-  bool SetEncryptionPolicy(int contents_mode, int filenames_mode, int flags,
-                           int skip_flags);
+  int GetSkipFlagsForDataUnitSize(int data_unit_size);
+  bool SetEncryptionPolicy(int contents_mode, int filenames_mode,
+                           int data_unit_size, int flags, int skip_flags);
   bool GenerateTestFile(
       TestFileInfo *info,
       const struct f2fs_comp_option *compress_options = nullptr);
@@ -518,9 +521,13 @@ class FBEPolicyTest : public ::testing::Test {
                                   std::vector<uint8_t> &enc_key);
   void VerifyCiphertext(const std::vector<uint8_t> &enc_key,
                         const FscryptIV &starting_iv, const Cipher &cipher,
-                        const TestFileInfo &file_info);
+                        const TestFileInfo &file_info, int data_unit_size);
   void TestEmmcOptimizedDunWraparound(const std::vector<uint8_t> &master_key,
                                       const std::vector<uint8_t> &enc_key);
+  void TestAesPerFileKeysPolicy(int data_unit_size);
+  void TestAesInlineCryptOptimizedPolicy(int data_unit_size);
+  void TestAesInlineCryptOptimizedHwWrappedKeyPolicy(int data_unit_size);
+  void TestAdiantumPolicy(int data_unit_size);
   bool EnableF2fsCompressionOnTestDir();
   bool F2fsCompressOptionsSupported(const struct f2fs_comp_option &opts);
   std::string test_dir_;
@@ -666,16 +673,33 @@ int FBEPolicyTest::GetSkipFlagsForInoBasedEncryption() {
   return 0;
 }
 
+int FBEPolicyTest::GetSkipFlagsForDataUnitSize(int data_unit_size) {
+  // The log2_data_unit_size field in struct fscrypt_policy_v2 is only supported
+  // by the android14-5.15 and later kernels.
+  if (data_unit_size != 0) return kSkipIfNoPolicySupport;
+  return 0;
+}
+
 // Sets a v2 encryption policy on the test directory.  The policy will use the
-// test key and the specified encryption modes and flags.  If the kernel doesn't
-// support setting or using the encryption policy, then a failure will be added,
-// unless the reason is covered by a bit set in |skip_flags|.
+// test key and the specified encryption modes, data unit size, and flags.  If
+// the kernel doesn't support setting or using the encryption policy, then a
+// failure will be added, unless the reason is covered by a bit set in
+// |skip_flags|.
 bool FBEPolicyTest::SetEncryptionPolicy(int contents_mode, int filenames_mode,
-                                        int flags, int skip_flags) {
+                                        int data_unit_size, int flags,
+                                        int skip_flags) {
   if (!key_added_) {
     ADD_FAILURE() << "SetEncryptionPolicy called but no key added";
     return false;
   }
+  uint8_t log2_data_unit_size = 0;
+  if (data_unit_size != 0) {
+    log2_data_unit_size = log2(data_unit_size);
+    if (data_unit_size != 1 << log2_data_unit_size) {
+      ADD_FAILURE() << "Requested data unit size is not a power of 2";
+      return false;
+    }
+  }
 
   struct fscrypt_policy_v2 policy;
   memset(&policy, 0, sizeof(policy));
@@ -685,6 +709,7 @@ bool FBEPolicyTest::SetEncryptionPolicy(int contents_mode, int filenames_mode,
   // Always give PAD_16, to match the policies that Android sets for real.
   // It doesn't affect contents encryption, though.
   policy.flags = flags | FSCRYPT_POLICY_FLAGS_PAD_16;
+  policy.log2_data_unit_size = log2_data_unit_size;
   memcpy(policy.master_key_identifier, master_key_specifier_.u.identifier,
          FSCRYPT_KEY_IDENTIFIER_SIZE);
 
@@ -730,6 +755,9 @@ bool FBEPolicyTest::SetEncryptionPolicy(int contents_mode, int filenames_mode,
       //   - The device's inline encryption hardware doesn't support the number
       //     of DUN bytes needed for file contents encryption.
       //
+      //   - The device's inline encryption hardware doesn't support the data
+      //     unit size needed for file contents encryption.
+      //
       //   - The policy uses the IV_INO_LBLK_32 flag, and the filesystem block
       //     size differs from the page size.  (Kernel limitation.)
       if (errno == EINVAL && (skip_flags & kSkipIfInlineEncryptionNotUsable)) {
@@ -750,12 +778,12 @@ bool FBEPolicyTest::SetEncryptionPolicy(int contents_mode, int filenames_mode,
 // disk, and other information about the file.
 bool FBEPolicyTest::GenerateTestFile(
     TestFileInfo *info, const struct f2fs_comp_option *compress_options) {
-  info->plaintext.resize(kTestFileBytes);
+  info->plaintext.resize(kTestFileSize);
   RandomBytesForTesting(info->plaintext);
 
   if (compress_options != nullptr &&
-      !MakeSomeCompressibleClusters(info->plaintext,
-                                    compress_options->log_cluster_size))
+      !MakeSomeCompressibleClusters(
+          fs_info_, compress_options->log_cluster_size, info->plaintext))
     return false;
 
   if (!WriteTestFile(info->plaintext, test_file_, fs_info_, compress_options,
@@ -879,25 +907,33 @@ static bool HashInodeNumber(const std::vector<uint8_t> &master_key,
 void FBEPolicyTest::VerifyCiphertext(const std::vector<uint8_t> &enc_key,
                                      const FscryptIV &starting_iv,
                                      const Cipher &cipher,
-                                     const TestFileInfo &file_info) {
+                                     const TestFileInfo &file_info,
+                                     int data_unit_size) {
   const std::vector<uint8_t> &plaintext = file_info.plaintext;
 
-  GTEST_LOG_(INFO) << "Verifying correctness of encrypted data";
+  if (data_unit_size == 0) {
+    data_unit_size = fs_info_.block_size;
+  }
+
+  if (plaintext.size() % data_unit_size != 0) {
+    ADD_FAILURE() << "File size is not a multiple of the data unit size";
+    return;
+  }
+
+  GTEST_LOG_(INFO) << "Verifying correctness of encrypted data; data_unit_size="
+                   << data_unit_size;
   FscryptIV iv = starting_iv;
 
   std::vector<uint8_t> computed_ciphertext(plaintext.size());
 
-  // Encrypt each filesystem block of file contents.
-  for (size_t i = 0; i < plaintext.size(); i += kFilesystemBlockSize) {
-    int block_size =
-        std::min<size_t>(kFilesystemBlockSize, plaintext.size() - i);
-
+  // Encrypt each data unit of file contents.
+  for (size_t i = 0; i < plaintext.size(); i += data_unit_size) {
     ASSERT_GE(sizeof(iv.bytes), cipher.ivsize());
     ASSERT_TRUE(cipher.Encrypt(enc_key, iv.bytes, &plaintext[i],
-                               &computed_ciphertext[i], block_size));
+                               &computed_ciphertext[i], data_unit_size));
 
-    // Update the IV by incrementing the file logical block number.
-    iv.lblk_num = __cpu_to_le32(__le32_to_cpu(iv.lblk_num) + 1);
+    // Update the IV by incrementing the data unit index.
+    iv.du_index = __cpu_to_le32(__le32_to_cpu(iv.du_index) + 1);
   }
 
   ASSERT_EQ(file_info.actual_ciphertext, computed_ciphertext);
@@ -929,20 +965,19 @@ static bool InitIVForInoLblk32(const std::vector<uint8_t> &master_key,
   uint32_t hash;
   if (!HashInodeNumber(master_key, inode_number, &hash)) return false;
   memset(iv, 0, kFscryptMaxIVSize);
-  iv->lblk_num = __cpu_to_le32(hash);
+  iv->du_index = __cpu_to_le32(hash);
   return true;
 }
 
-// Tests a policy matching "fileencryption=aes-256-xts:aes-256-cts:v2"
-// (or simply "fileencryption=" on devices launched with R or higher)
-TEST_F(FBEPolicyTest, TestAesPerFileKeysPolicy) {
+void FBEPolicyTest::TestAesPerFileKeysPolicy(int data_unit_size) {
   if (skip_test_) return;
 
   auto master_key = GenerateTestKey(kFscryptMasterKeySize);
   ASSERT_TRUE(SetMasterKey(master_key));
 
   if (!SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS,
-                           0, 0))
+                           data_unit_size, 0,
+                           GetSkipFlagsForDataUnitSize(data_unit_size)))
     return;
 
   TestFileInfo file_info;
@@ -953,22 +988,30 @@ TEST_F(FBEPolicyTest, TestAesPerFileKeysPolicy) {
 
   FscryptIV iv;
   ASSERT_TRUE(InitIVForPerFileKey(&iv));
-  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
+  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info, data_unit_size);
 }
 
-// Tests a policy matching
-// "fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized"
-// (or simply "fileencryption=::inlinecrypt_optimized" on devices launched with
-// R or higher)
-TEST_F(FBEPolicyTest, TestAesInlineCryptOptimizedPolicy) {
+// Tests a policy matching "fileencryption=aes-256-xts:aes-256-cts:v2"
+// (or simply "fileencryption=" on devices launched with R or higher)
+TEST_F(FBEPolicyTest, TestAesPerFileKeysPolicy_DefaultDataUnitSize) {
+  TestAesPerFileKeysPolicy(0);
+}
+
+// Same as above, but adds the dusize_4k option.
+TEST_F(FBEPolicyTest, TestAesPerFileKeysPolicy_4KDataUnitSize) {
+  TestAesPerFileKeysPolicy(4096);
+}
+
+void FBEPolicyTest::TestAesInlineCryptOptimizedPolicy(int data_unit_size) {
   if (skip_test_) return;
 
   auto master_key = GenerateTestKey(kFscryptMasterKeySize);
   ASSERT_TRUE(SetMasterKey(master_key));
 
   if (!SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS,
-                           FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
-                           GetSkipFlagsForInoBasedEncryption()))
+                           data_unit_size, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
+                           GetSkipFlagsForInoBasedEncryption() |
+                               GetSkipFlagsForDataUnitSize(data_unit_size)))
     return;
 
   TestFileInfo file_info;
@@ -981,24 +1024,35 @@ TEST_F(FBEPolicyTest, TestAesInlineCryptOptimizedPolicy) {
 
   FscryptIV iv;
   ASSERT_TRUE(InitIVForInoLblk64(file_info.inode_number, &iv));
-  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
+  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info, data_unit_size);
 }
 
 // Tests a policy matching
-// "fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0"
-// (or simply "fileencryption=::inlinecrypt_optimized+wrappedkey_v0" on devices
-// launched with R or higher)
-TEST_F(FBEPolicyTest, TestAesInlineCryptOptimizedHwWrappedKeyPolicy) {
+// "fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized"
+// (or simply "fileencryption=::inlinecrypt_optimized" on devices launched with
+// R or higher)
+TEST_F(FBEPolicyTest, TestAesInlineCryptOptimizedPolicy_DefaultDataUnitSize) {
+  TestAesInlineCryptOptimizedPolicy(0);
+}
+
+// Same as above, but adds the dusize_4k option.
+TEST_F(FBEPolicyTest, TestAesInlineCryptOptimizedPolicy_4KDataUnitSize) {
+  TestAesInlineCryptOptimizedPolicy(4096);
+}
+
+void FBEPolicyTest::TestAesInlineCryptOptimizedHwWrappedKeyPolicy(
+    int data_unit_size) {
   if (skip_test_) return;
 
   std::vector<uint8_t> enc_key, sw_secret;
   if (!CreateAndSetHwWrappedKey(&enc_key, &sw_secret)) return;
 
   if (!SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS,
-                           FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
+                           data_unit_size, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
                            // 64-bit DUN support is not guaranteed.
                            kSkipIfInlineEncryptionNotUsable |
-                               GetSkipFlagsForInoBasedEncryption()))
+                               GetSkipFlagsForInoBasedEncryption() |
+                               GetSkipFlagsForDataUnitSize(data_unit_size)))
     return;
 
   TestFileInfo file_info;
@@ -1006,13 +1060,30 @@ TEST_F(FBEPolicyTest, TestAesInlineCryptOptimizedHwWrappedKeyPolicy) {
 
   FscryptIV iv;
   ASSERT_TRUE(InitIVForInoLblk64(file_info.inode_number, &iv));
-  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
+  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info, data_unit_size);
+}
+
+// Tests a policy matching
+// "fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0"
+// (or simply "fileencryption=::inlinecrypt_optimized+wrappedkey_v0" on devices
+// launched with R or higher)
+TEST_F(FBEPolicyTest,
+       TestAesInlineCryptOptimizedHwWrappedKeyPolicy_DefaultDataUnitSize) {
+  TestAesInlineCryptOptimizedHwWrappedKeyPolicy(0);
+}
+
+// Same as above, but adds the dusize_4k option.
+TEST_F(FBEPolicyTest,
+       TestAesInlineCryptOptimizedHwWrappedKeyPolicy_4KDataUnitSize) {
+  TestAesInlineCryptOptimizedHwWrappedKeyPolicy(4096);
 }
 
 // With IV_INO_LBLK_32, the DUN (IV) can wrap from UINT32_MAX to 0 in the middle
 // of the file.  This method tests that this case appears to be handled
 // correctly, by doing I/O across the place where the DUN wraps around.  Assumes
 // that test_dir_ has already been set up with an IV_INO_LBLK_32 policy.
+//
+// Assumes that the data unit size and filesystem block size are the same.
 void FBEPolicyTest::TestEmmcOptimizedDunWraparound(
     const std::vector<uint8_t> &master_key,
     const std::vector<uint8_t> &enc_key) {
@@ -1022,13 +1093,13 @@ void FBEPolicyTest::TestEmmcOptimizedDunWraparound(
   constexpr uint32_t block_count_1 = 3;
   constexpr uint32_t block_count_2 = 7;
   constexpr uint32_t block_count = block_count_1 + block_count_2;
-  constexpr size_t data_size = block_count * kFilesystemBlockSize;
+  const size_t data_size = block_count * fs_info_.block_size;
 
   // Assumed maximum file size.  Unfortunately there isn't a syscall to get
   // this.  ext4 allows ~16TB and f2fs allows ~4TB.  However, an underestimate
   // works fine for our purposes, so just go with 1TB.
   constexpr off_t max_file_size = 1000000000000;
-  constexpr off_t max_file_blocks = max_file_size / kFilesystemBlockSize;
+  const off_t max_file_blocks = max_file_size / fs_info_.block_size;
 
   // Repeatedly create empty files until we find one that can be used for DUN
   // wraparound testing, due to SipHash(inode_number) being almost UINT32_MAX.
@@ -1079,11 +1150,11 @@ void FBEPolicyTest::TestEmmcOptimizedDunWraparound(
 
     // Write the test data.  To support O_DIRECT, use a block-aligned buffer.
     std::unique_ptr<void, void (*)(void *)> buf_mem(
-        aligned_alloc(kFilesystemBlockSize, data_size), free);
+        aligned_alloc(fs_info_.block_size, data_size), free);
     ASSERT_TRUE(buf_mem != nullptr);
     memcpy(buf_mem.get(), &file_info.plaintext[0], data_size);
     off_t pos = static_cast<off_t>(lblk_with_dun_0 - block_count_1) *
-                kFilesystemBlockSize;
+                fs_info_.block_size;
     ASSERT_EQ(data_size, pwrite(fd, buf_mem.get(), data_size, pos))
         << "Error writing data to " << path << Errno();
 
@@ -1092,14 +1163,17 @@ void FBEPolicyTest::TestEmmcOptimizedDunWraparound(
                                   &file_info.actual_ciphertext));
     FscryptIV iv;
     memset(&iv, 0, sizeof(iv));
-    iv.lblk_num = __cpu_to_le32(-block_count_1);
-    VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
+    iv.du_index = __cpu_to_le32(-block_count_1);
+    VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info, 0);
   }
 }
 
 // Tests a policy matching
 // "fileencryption=aes-256-xts:aes-256-cts:v2+emmc_optimized" (or simply
 // "fileencryption=::emmc_optimized" on devices launched with R or higher)
+//
+// Note: we do not test emmc_optimized+dusize_4k, since the kernel does not
+// support this combination yet.
 TEST_F(FBEPolicyTest, TestAesEmmcOptimizedPolicy) {
   if (skip_test_) return;
 
@@ -1107,7 +1181,7 @@ TEST_F(FBEPolicyTest, TestAesEmmcOptimizedPolicy) {
   ASSERT_TRUE(SetMasterKey(master_key));
 
   if (!SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS,
-                           FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
+                           0, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
                            GetSkipFlagsForInoBasedEncryption()))
     return;
 
@@ -1121,7 +1195,7 @@ TEST_F(FBEPolicyTest, TestAesEmmcOptimizedPolicy) {
 
   FscryptIV iv;
   ASSERT_TRUE(InitIVForInoLblk32(master_key, file_info.inode_number, &iv));
-  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
+  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info, 0);
 
   TestEmmcOptimizedDunWraparound(master_key, enc_key);
 }
@@ -1130,18 +1204,19 @@ TEST_F(FBEPolicyTest, TestAesEmmcOptimizedPolicy) {
 // "fileencryption=aes-256-xts:aes-256-cts:v2+emmc_optimized+wrappedkey_v0"
 // (or simply "fileencryption=::emmc_optimized+wrappedkey_v0" on devices
 // launched with R or higher)
+//
+// Note: we do not test emmc_optimized+dusize_4k, since the kernel does not
+// support this combination yet.
 TEST_F(FBEPolicyTest, TestAesEmmcOptimizedHwWrappedKeyPolicy) {
   if (skip_test_) return;
 
   std::vector<uint8_t> enc_key, sw_secret;
   if (!CreateAndSetHwWrappedKey(&enc_key, &sw_secret)) return;
 
-  int skip_flags = GetSkipFlagsForInoBasedEncryption();
-  if (kFilesystemBlockSize != getpagesize())
-    skip_flags |= kSkipIfInlineEncryptionNotUsable;
-
   if (!SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS,
-                           FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32, skip_flags))
+                           0, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_32,
+                           kSkipIfInlineEncryptionNotUsable |
+                               GetSkipFlagsForInoBasedEncryption()))
     return;
 
   TestFileInfo file_info;
@@ -1149,14 +1224,12 @@ TEST_F(FBEPolicyTest, TestAesEmmcOptimizedHwWrappedKeyPolicy) {
 
   FscryptIV iv;
   ASSERT_TRUE(InitIVForInoLblk32(sw_secret, file_info.inode_number, &iv));
-  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
+  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info, 0);
 
   TestEmmcOptimizedDunWraparound(sw_secret, enc_key);
 }
 
-// Tests a policy matching "fileencryption=adiantum:adiantum:v2" (or simply
-// "fileencryption=adiantum" on devices launched with R or higher)
-TEST_F(FBEPolicyTest, TestAdiantumPolicy) {
+void FBEPolicyTest::TestAdiantumPolicy(int data_unit_size) {
   if (skip_test_) return;
 
   auto master_key = GenerateTestKey(kFscryptMasterKeySize);
@@ -1168,8 +1241,9 @@ TEST_F(FBEPolicyTest, TestAdiantumPolicy) {
   // We don't need to use GetSkipFlagsForInoBasedEncryption() here, since the
   // "DIRECT_KEY" IV generation method doesn't include inode numbers in the IVs.
   if (!SetEncryptionPolicy(FSCRYPT_MODE_ADIANTUM, FSCRYPT_MODE_ADIANTUM,
-                           FSCRYPT_POLICY_FLAG_DIRECT_KEY,
-                           kSkipIfNoCryptoAPISupport))
+                           data_unit_size, FSCRYPT_POLICY_FLAG_DIRECT_KEY,
+                           kSkipIfNoCryptoAPISupport |
+                               GetSkipFlagsForDataUnitSize(data_unit_size)))
     return;
 
   TestFileInfo file_info;
@@ -1181,7 +1255,18 @@ TEST_F(FBEPolicyTest, TestAdiantumPolicy) {
 
   FscryptIV iv;
   ASSERT_TRUE(InitIVForDirectKey(file_info.nonce, &iv));
-  VerifyCiphertext(enc_key, iv, AdiantumCipher(), file_info);
+  VerifyCiphertext(enc_key, iv, AdiantumCipher(), file_info, data_unit_size);
+}
+
+// Tests a policy matching "fileencryption=adiantum:adiantum:v2" (or simply
+// "fileencryption=adiantum" on devices launched with R or higher)
+TEST_F(FBEPolicyTest, TestAdiantumPolicy_DefaultDataUnitSize) {
+  TestAdiantumPolicy(0);
+}
+
+// Same as above, but adds the dusize_4k option.
+TEST_F(FBEPolicyTest, TestAdiantumPolicy_4KDataUnitSize) {
+  TestAdiantumPolicy(4096);
 }
 
 // Tests adding a corrupted wrapped key to fscrypt keyring.
@@ -1334,7 +1419,7 @@ TEST_F(FBEPolicyTest, DISABLED_TestF2fsCompression) {
   auto master_key = GenerateTestKey(kFscryptMasterKeySize);
   ASSERT_TRUE(SetMasterKey(master_key));
   ASSERT_TRUE(SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS,
-                                  FSCRYPT_MODE_AES_256_CTS, 0, 0));
+                                  FSCRYPT_MODE_AES_256_CTS, 0, 0, 0));
 
   // This test will use LZ4 compression with a cluster size of 2^2 = 4 blocks.
   // Check that this setting is supported.
@@ -1343,7 +1428,7 @@ TEST_F(FBEPolicyTest, DISABLED_TestF2fsCompression) {
   // important for this test.  We just (somewhat arbitrarily) chose a setting
   // which is commonly used and for which a decompression library is available.
   const int log_cluster_size = 2;
-  const int cluster_bytes = kFilesystemBlockSize << log_cluster_size;
+  const int cluster_bytes = fs_info_.block_size << log_cluster_size;
   struct f2fs_comp_option comp_opt;
   memset(&comp_opt, 0, sizeof(comp_opt));
   comp_opt.algorithm = F2FS_COMPRESS_LZ4;
@@ -1351,45 +1436,46 @@ TEST_F(FBEPolicyTest, DISABLED_TestF2fsCompression) {
   if (!F2fsCompressOptionsSupported(comp_opt)) return;
 
   // Generate the test file and retrieve its on-disk data.  Note: despite being
-  // compressed, the on-disk data here will still be |kTestFileBytes| long.
-  // This is because FS_IOC_FIEMAP doesn't natively support compression, and the
-  // way that f2fs handles it on compressed files results in us reading extra
-  // blocks appended to the compressed clusters.  It works out in the end
-  // though, since these extra blocks get ignored during decompression.
+  // compressed, the on-disk data here will still be |kTestFileSize| long.  This
+  // is because FS_IOC_FIEMAP doesn't natively support compression, and the way
+  // that f2fs handles it on compressed files results in us reading extra blocks
+  // appended to the compressed clusters.  It works out in the end though, since
+  // these extra blocks get ignored during decompression.
   TestFileInfo file_info;
   ASSERT_TRUE(GenerateTestFile(&file_info, &comp_opt));
 
   GTEST_LOG_(INFO) << "Decrypting the blocks of the compressed file";
   std::vector<uint8_t> enc_key(kAes256XtsKeySize);
   ASSERT_TRUE(DerivePerFileEncryptionKey(master_key, file_info.nonce, enc_key));
-  std::vector<uint8_t> decrypted_data(kTestFileBytes);
+  std::vector<uint8_t> decrypted_data(kTestFileSize);
   FscryptIV iv;
   memset(&iv, 0, sizeof(iv));
-  ASSERT_EQ(0, kTestFileBytes % kFilesystemBlockSize);
-  for (int i = 0; i < kTestFileBytes; i += kFilesystemBlockSize) {
-    int block_num = i / kFilesystemBlockSize;
+  ASSERT_EQ(0, kTestFileSize % fs_info_.block_size);
+  for (int i = 0; i < kTestFileSize; i += fs_info_.block_size) {
+    int block_num = i / fs_info_.block_size;
     int cluster_num = i / cluster_bytes;
 
     // In compressed clusters, IVs start at 1 higher than the expected value.
     // Fortunately, due to the compression there is no overlap...
     if (IsCompressibleCluster(cluster_num)) block_num++;
 
-    iv.lblk_num = __cpu_to_le32(block_num);
+    iv.du_index = __cpu_to_le32(block_num);
     ASSERT_TRUE(Aes256XtsCipher().Decrypt(
         enc_key, iv.bytes, &file_info.actual_ciphertext[i], &decrypted_data[i],
-        kFilesystemBlockSize));
+        fs_info_.block_size));
   }
 
   GTEST_LOG_(INFO) << "Decompressing the decrypted blocks of the file";
-  std::vector<uint8_t> decompressed_data(kTestFileBytes);
-  ASSERT_EQ(0, kTestFileBytes % cluster_bytes);
-  for (int i = 0; i < kTestFileBytes; i += cluster_bytes) {
+  std::vector<uint8_t> decompressed_data(kTestFileSize);
+  ASSERT_EQ(0, kTestFileSize % cluster_bytes);
+  for (int i = 0; i < kTestFileSize; i += cluster_bytes) {
     int cluster_num = i / cluster_bytes;
     if (IsCompressibleCluster(cluster_num)) {
       // We had filled this cluster with compressible data, so it should have
       // been stored compressed.
       ASSERT_TRUE(DecompressLZ4Cluster(&decrypted_data[i],
-                                       &decompressed_data[i], cluster_bytes));
+                                       &decompressed_data[i],
+                                       fs_info_.block_size, cluster_bytes));
     } else {
       // We had filled this cluster with random data, so it should have been
       // incompressible and thus stored uncompressed.
@@ -1473,7 +1559,7 @@ TEST(FBETest, TestFileContentsRandomness) {
   FilesystemInfo fs_info;
   ASSERT_TRUE(GetFilesystemInfo(kTestMountpoint, &fs_info));
 
-  std::vector<uint8_t> zeroes(kTestFileBytes, 0);
+  std::vector<uint8_t> zeroes(kTestFileSize, 0);
   std::vector<uint8_t> ciphertext_1;
   std::vector<uint8_t> ciphertext_2;
   ASSERT_TRUE(WriteTestFile(zeroes, path_1, fs_info, nullptr, &ciphertext_1));
diff --git a/encryption/metadata_encryption_tests.cpp b/encryption/metadata_encryption_tests.cpp
index 91fa06f..5ac7464 100644
--- a/encryption/metadata_encryption_tests.cpp
+++ b/encryption/metadata_encryption_tests.cpp
@@ -74,9 +74,6 @@ namespace kernel {
 // Alignment to use for direct I/O reads of block devices
 static constexpr int kDirectIOAlignment = 4096;
 
-// Assumed size of filesystem blocks, in bytes
-static constexpr int kFilesystemBlockSize = 4096;
-
 // Checks whether the kernel supports version 2 or higher of dm-default-key.
 static bool IsDmDefaultKeyV2Supported(DeviceMapper &dm) {
   DmTargetTypeInfo info;
@@ -290,11 +287,11 @@ TEST_F(DmDefaultKeyTest, TestHwWrappedKey) {
   VerifyDecryption(enc_key, Aes256XtsCipher());
 }
 
-// Tests that if the device uses metadata encryption, then the first
-// kFilesystemBlockSize bytes of the userdata partition appear random.  For ext4
-// and f2fs, this block should contain the filesystem superblock; it therefore
-// should be initialized and metadata-encrypted.  Ideally we'd check additional
-// blocks too, but that would require awareness of the filesystem structure.
+// Tests that if the device uses metadata encryption, then the first filesystem
+// block of the userdata partition appears random.  For ext4 and f2fs, this
+// block should contain the filesystem superblock; it therefore should be
+// initialized and metadata-encrypted.  Ideally we'd check additional blocks
+// too, but that would require awareness of the filesystem structure.
 //
 // This isn't as strong a test as the correctness tests, but it's useful because
 // it applies regardless of the encryption format and key.  Thus it runs even on
@@ -324,7 +321,7 @@ TEST(MetadataEncryptionTest, TestRandomness) {
   // The first block of the filesystem's main block device should always be
   // metadata-encrypted.
   ASSERT_TRUE(ReadBlockDevice(fs_info.disk_map[0].raw_blk_device,
-                              kFilesystemBlockSize, &raw_data));
+                              fs_info.block_size, &raw_data));
   ASSERT_TRUE(VerifyDataRandomness(raw_data));
 }
 
diff --git a/encryption/utils.cpp b/encryption/utils.cpp
index e47aac2..e6585e0 100644
--- a/encryption/utils.cpp
+++ b/encryption/utils.cpp
@@ -33,6 +33,7 @@
 #include <linux/magic.h>
 #include <mntent.h>
 #include <openssl/cmac.h>
+#include <sys/statvfs.h>
 #include <unistd.h>
 
 #include "Keymaster.h"
@@ -435,10 +436,17 @@ bool GetFilesystemInfo(const std::string &mountpoint, FilesystemInfo *fs_info) {
                          &fs_info->uuid))
     return false;
 
-  GTEST_LOG_(INFO) << " Filesystem mounted on " << mountpoint
-                   << " has type: " << fs_info->type << ", UUID is "
-                   << BytesToHex(fs_info->uuid.bytes);
+  struct statvfs stbuf;
+  if (statvfs(mountpoint.c_str(), &stbuf) != 0) {
+    ADD_FAILURE() << "Failed to statvfs " << mountpoint << Errno();
+    return false;
+  }
+  fs_info->block_size = stbuf.f_bsize;
 
+  GTEST_LOG_(INFO) << "Filesystem mounted on " << mountpoint
+                   << " has type: " << fs_info->type
+                   << ", block_size: " << fs_info->block_size
+                   << ", uuid: " << BytesToHex(fs_info->uuid.bytes);
   for (const DiskMapEntry &map_entry : fs_info->disk_map) {
     GTEST_LOG_(INFO) << "Block device: " << map_entry.fs_blk_device << " ("
                      << map_entry.raw_blk_device << ") ranging from "
diff --git a/encryption/vts_kernel_encryption.h b/encryption/vts_kernel_encryption.h
index bd3b620..908d2e1 100644
--- a/encryption/vts_kernel_encryption.h
+++ b/encryption/vts_kernel_encryption.h
@@ -120,6 +120,7 @@ struct DiskMapEntry {
 struct FilesystemInfo {
   std::string type;
   FilesystemUuid uuid;
+  int block_size;  // block size in bytes, typically 4096 or 16384
 
   // The filesystem's block devices in sorted order of filesystem block address.
   // The covered addresses are guaranteed to be contiguous and non-overlapping.
diff --git a/f2fs/Android.bp b/f2fs/Android.bp
index 662520d..b30e9cd 100644
--- a/f2fs/Android.bp
+++ b/f2fs/Android.bp
@@ -44,6 +44,7 @@ cc_test {
     test_config: "f2fs_test.xml",
     test_suites: [
         "general-tests",
+        "vts",
     ],
 }
 
diff --git a/f2fs/F2fsTest.cpp b/f2fs/F2fsTest.cpp
index 19f2981..82ef11c 100644
--- a/f2fs/F2fsTest.cpp
+++ b/f2fs/F2fsTest.cpp
@@ -54,17 +54,11 @@ class F2fsTest : public testing::Test {
     close(fd);
 
     const char* make_fs_argv[] = {
-        kMkfsPath,
-        "-f",
-        "-O",
-        "extra_attr",
-        "-O",
-        "project_quota",
-        "-O",
-        "compression",
-        "-g",
-        "android",
-        "/data/local/tmp/img",
+        kMkfsPath,    "-f",          "-O",
+        "extra_attr", "-O",          "project_quota",
+        "-O",         "compression", "-O",
+        "casefold",   "-C",          "utf8",
+        "-g",         "android",     "/data/local/tmp/img",
     };
     res = logwrap_fork_execvp(arraysize(make_fs_argv), make_fs_argv, nullptr,
                               false, LOG_KLOG, true, nullptr);
@@ -214,4 +208,33 @@ TEST_F(F2fsTest, test_sparse_decompress) {
   close(fd);
 }
 
+TEST_F(F2fsTest, test_casefolding_ignorable_codepoint) {
+  const char* kTestFolder = "/data/local/tmp/mnt/cf/";
+  const char* kTestFileCase1Path = "/data/local/tmp/mnt/cf/❤";  // u2764
+  const char* kTestFileCase2Path = "/data/local/tmp/mnt/cf/❤️";  // u2764 + ufe0f
+  struct stat stat1;
+  struct stat stat2;
+
+  ASSERT_EQ(mkdir(kTestFolder, (S_IRWXU | S_IRGRP | S_IROTH)), 0);
+  int fd = open(kTestFolder, O_RDONLY | O_DIRECTORY);
+  ASSERT_NE(fd, -1);
+  int flag = FS_CASEFOLD_FL;
+  ASSERT_EQ(ioctl(fd, FS_IOC_SETFLAGS, &flag), 0);
+  close(fd);
+
+  fd = open(kTestFileCase1Path, O_RDWR | O_TRUNC | O_CREAT,
+            (S_IRWXU | S_IRGRP | S_IROTH));
+  ASSERT_NE(fd, -1);
+  ASSERT_NE(fstat(fd, &stat1), -1);
+  close(fd);
+
+  fd = open(kTestFileCase2Path, O_RDWR | O_TRUNC | O_CREAT,
+            (S_IRWXU | S_IRGRP | S_IROTH));
+  ASSERT_NE(fd, -1);
+  ASSERT_NE(fstat(fd, &stat2), -1);
+  close(fd);
+
+  ASSERT_EQ(stat1.st_ino, stat2.st_ino);
+}
+
 }  // namespace android
diff --git a/f2fs/TEST_MAPPING b/f2fs/TEST_MAPPING
new file mode 100644
index 0000000..000f374
--- /dev/null
+++ b/f2fs/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "postsubmit": [
+    {
+      "name": "f2fs_test"
+    }
+  ]
+}
diff --git a/fuse_bpf/Android.bp b/fuse_bpf/Android.bp
index 8a6936a..f913c07 100644
--- a/fuse_bpf/Android.bp
+++ b/fuse_bpf/Android.bp
@@ -37,9 +37,4 @@ python_test_host {
         unit_test: false,
     },
     test_config: "vts_kernel_fuse_bpf_test.xml",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        }
-    }
 }
diff --git a/gki/Android.bp b/gki/Android.bp
index 9390ea7..36de940 100644
--- a/gki/Android.bp
+++ b/gki/Android.bp
@@ -124,6 +124,32 @@ cc_test {
     ],
 }
 
+cc_library {
+    name: "vts_boot_test_utils_lib",
+    srcs: [
+        "cpio.cpp",
+        "lz4_legacy.cpp",
+        "ramdisk_utils.cpp",
+    ],
+    export_include_dirs: ["."],
+    defaults: [
+        "libvintf_static_user_defaults",
+    ],
+    static_libs: [
+        "libbase",
+        "liblz4",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    header_libs: [
+        "bootimg_headers",
+        "libstorage_literals_headers",
+    ],
+    test_only: true,
+}
+
 filegroup {
     name: "WtsDlkmPartitionTestCasesSrc",
     srcs: ["vts_dlkm_partition_test.cpp"],
diff --git a/gki/generic_boot_image_test.cpp b/gki/generic_boot_image_test.cpp
index 76abfa0..f41c5a1 100644
--- a/gki/generic_boot_image_test.cpp
+++ b/gki/generic_boot_image_test.cpp
@@ -146,6 +146,18 @@ std::set<std::string> GetAllowListBySdkLevel(uint32_t target_sdk_level) {
   static const std::map<uint32_t, std::set<std::string>> allow_by_level = {
       {__ANDROID_API_T__, {"system/bin/snapuserd_ramdisk"}},
       {__ANDROID_API_U__, {"dev/console", "dev/null", "dev/urandom"}},
+      {
+          __ANDROID_API_V__,
+          {
+              "system/bin/toolbox_ramdisk",
+              "system/bin/modprobe",
+              "system/bin/start",
+              "system/bin/stop",
+              "system/bin/setprop",
+              "system/bin/getprop",
+              "system/bin/getevent",
+          },
+      },
   };
   auto res = GetRequirementBySdkLevel(target_sdk_level);
   for (const auto& [level, requirements] : allow_by_level) {
diff --git a/gki/ramdisk_utils.cpp b/gki/ramdisk_utils.cpp
index a133edf..1c4182a 100644
--- a/gki/ramdisk_utils.cpp
+++ b/gki/ramdisk_utils.cpp
@@ -36,7 +36,7 @@ namespace {
 android::base::Result<std::unique_ptr<TemporaryFile>> ExtractRamdiskRaw(
     std::string_view boot_path) {
   android::base::unique_fd bootimg(
-      TEMP_FAILURE_RETRY(open(boot_path.data(), O_RDONLY)));
+      TEMP_FAILURE_RETRY(open(std::string(boot_path).c_str(), O_RDONLY)));
   if (!bootimg.ok()) return ErrnoError() << "open(" << boot_path << ")";
   boot_img_hdr_v3 hdr{};
   if (!ReadFullyAtOffset(bootimg.get(), &hdr, sizeof(hdr), 0))
@@ -63,18 +63,55 @@ android::base::Result<std::unique_ptr<TemporaryFile>> ExtractRamdiskRaw(
   auto ramdisk_content_file = std::make_unique<TemporaryFile>();
   if (!WriteStringToFd(ramdisk_content, ramdisk_content_file->fd))
     return ErrnoError() << "write ramdisk section to file";
-  fsync(ramdisk_content_file->fd);
+  if (fsync(ramdisk_content_file->fd) != 0)
+    return ErrnoError() << "fsync ramdisk section file";
 
   return ramdisk_content_file;
 }
 
+android::base::Result<std::unique_ptr<TemporaryFile>> ExtractVendorRamdiskRaw(
+    const std::string &vendor_boot_path) {
+  android::base::unique_fd bootimg(
+      TEMP_FAILURE_RETRY(open(vendor_boot_path.c_str(), O_RDONLY)));
+  if (!bootimg.ok()) return ErrnoError() << "open(" << vendor_boot_path << ")";
+  vendor_boot_img_hdr_v3 hdr{};
+  if (!ReadFullyAtOffset(bootimg.get(), &hdr, sizeof(hdr), 0))
+    return ErrnoError() << "read header";
+  if (0 != memcmp(hdr.magic, VENDOR_BOOT_MAGIC, VENDOR_BOOT_MAGIC_SIZE))
+    return Error() << "Boot magic mismatch";
+
+  if (hdr.header_version < 3)
+    return Error() << "Unsupported header version V" << hdr.header_version;
+
+  // See bootimg.h
+  const auto num_boot_header_pages =
+      (hdr.header_size + hdr.page_size - 1) / hdr.page_size;
+  const auto ramdisk_offset_base = hdr.page_size * num_boot_header_pages;
+
+  // Ignore the vendor ramdisk table and load the entire vendor ramdisk section.
+  // This has the same effect as does loading all of the vendor ramdisk
+  //  fragments in the vendor_boot partition.
+  // https://source.android.com/docs/core/architecture/partitions/vendor-boot-partitions#vendor-boot-header
+  std::string vendor_ramdisk_content(hdr.vendor_ramdisk_size, '\0');
+  auto vendor_ramdisk_content_file = std::make_unique<TemporaryFile>();
+
+  if (!ReadFullyAtOffset(bootimg.get(), vendor_ramdisk_content.data(),
+                         hdr.vendor_ramdisk_size, ramdisk_offset_base))
+    return ErrnoError() << "read ramdisk section";
+  if (!WriteStringToFd(vendor_ramdisk_content, vendor_ramdisk_content_file->fd))
+    return ErrnoError() << "write ramdisk section to file";
+  if (fsync(vendor_ramdisk_content_file->fd) != 0)
+    return ErrnoError() << "fsync ramdisk section file";
+  return vendor_ramdisk_content_file;
+}
+
 }  // namespace
 
 // From the boot image / partition, extract the ramdisk section, decompress it,
 // and extract from the cpio archive.
 android::base::Result<std::unique_ptr<TemporaryDir>> ExtractRamdiskToDirectory(
     std::string_view boot_path) {
-  auto raw_ramdisk_file = ExtractRamdiskRaw(boot_path);
+  const auto raw_ramdisk_file = ExtractRamdiskRaw(boot_path);
   if (!raw_ramdisk_file.ok()) return raw_ramdisk_file.error();
 
   TemporaryFile decompressed;
@@ -85,4 +122,21 @@ android::base::Result<std::unique_ptr<TemporaryDir>> ExtractRamdiskToDirectory(
   return android::CpioExtract(decompressed.path);
 }
 
+// From the vendor_boot image / partition, extract the vendor_ramdisk section,
+//  decompress it, and extract from the cpio archive.
+android::base::Result<std::unique_ptr<TemporaryDir>>
+ExtractVendorRamdiskToDirectory(const std::string &vendor_boot_path) {
+  const auto vendor_raw_ramdisk_file =
+      ExtractVendorRamdiskRaw(vendor_boot_path);
+  if (!vendor_raw_ramdisk_file.ok()) return vendor_raw_ramdisk_file.error();
+
+  TemporaryFile decompressed;
+  // TODO: b/374932907 -- Verify if this assumption is correct,
+  //   if not add logic to support Gzip, or uncompressed ramdisks.
+  auto decompress_res = android::Lz4DecompressLegacy(
+      (*vendor_raw_ramdisk_file)->path, decompressed.path);
+  if (!decompress_res.ok()) return decompress_res.error();
+
+  return android::CpioExtract(decompressed.path);
+}
 }  // namespace android
diff --git a/gki/ramdisk_utils.h b/gki/ramdisk_utils.h
index 69e49ea..3d26574 100644
--- a/gki/ramdisk_utils.h
+++ b/gki/ramdisk_utils.h
@@ -28,4 +28,9 @@ namespace android {
 android::base::Result<std::unique_ptr<TemporaryDir>> ExtractRamdiskToDirectory(
     std::string_view boot_path);
 
+// From the vendor_boot image / partition, extract the vendor_ramdisk section,
+//  decompress it, and extract from the cpio archive.
+android::base::Result<std::unique_ptr<TemporaryDir>>
+ExtractVendorRamdiskToDirectory(const std::string &vendor_boot_path);
+
 }  // namespace android
diff --git a/gki/vts_dlkm_partition_test.cpp b/gki/vts_dlkm_partition_test.cpp
index f1c832e..e91d4b1 100644
--- a/gki/vts_dlkm_partition_test.cpp
+++ b/gki/vts_dlkm_partition_test.cpp
@@ -139,29 +139,6 @@ class DlkmPartitionTest : public testing::Test {
   int product_first_api_level;
 };
 
-TEST_F(DlkmPartitionTest, VendorDlkmPartition) {
-  if (vendor_api_level < __ANDROID_API_S__) {
-    GTEST_SKIP()
-        << "Exempt from vendor_dlkm partition test. ro.vendor.api_level ("
-        << vendor_api_level << ") < " << __ANDROID_API_S__;
-  }
-  // Only enforce this test on products launched with Android T and later.
-  if (product_first_api_level < __ANDROID_API_T__) {
-    GTEST_SKIP() << "Exempt from vendor_dlkm partition test. "
-                    "ro.product.first_api_level ("
-                 << product_first_api_level << ") < " << __ANDROID_API_T__;
-  }
-  if (runtime_info->kernelVersion().dropMinor() !=
-          android::vintf::Version{5, 4} &&
-      runtime_info->kernelVersion().dropMinor() <
-          android::vintf::Version{5, 10}) {
-    GTEST_SKIP() << "Exempt from vendor_dlkm partition test. kernel: "
-                 << runtime_info->kernelVersion();
-  }
-  ASSERT_NO_FATAL_FAILURE(VerifyDlkmPartition("vendor"));
-  ASSERT_NO_FATAL_FAILURE(VerifyDlkmPartition("odm"));
-}
-
 TEST_F(DlkmPartitionTest, SystemDlkmPartition) {
   if (vendor_api_level < __ANDROID_API_T__) {
     GTEST_SKIP()
diff --git a/ltp/OWNERS b/ltp/OWNERS
index 66f12c4..6ef51ba 100644
--- a/ltp/OWNERS
+++ b/ltp/OWNERS
@@ -1,5 +1,5 @@
 # Bug component: 391836
-vmartensson@google.com
-balsini@google.com
 edliaw@google.com
 bettyzhou@google.com
+vmartensson@google.com
+balsini@google.com
diff --git a/ltp/testcase/tools/Android.bp b/ltp/testcase/tools/Android.bp
index c467b71..4b18230 100644
--- a/ltp/testcase/tools/Android.bp
+++ b/ltp/testcase/tools/Android.bp
@@ -27,11 +27,6 @@ python_test_host {
         "configs/stable_tests.py",
         "test_launcher.py",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        }
-    },
 }
 
 python_binary_host {
@@ -46,9 +41,4 @@ python_binary_host {
         ":ltp_disabled_tests",
         ":ltp_runtests",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        }
-    },
 }
diff --git a/ltp/testcase/tools/configs/disabled_tests.py b/ltp/testcase/tools/configs/disabled_tests.py
index aeae9b3..1699004 100644
--- a/ltp/testcase/tools/configs/disabled_tests.py
+++ b/ltp/testcase/tools/configs/disabled_tests.py
@@ -42,6 +42,8 @@ DISABLED_TESTS = {
     'kernel_misc.zram01_64bit',  # b/191226875
     'kernel_misc.zram02_32bit',  # b/191227531
     'kernel_misc.zram02_64bit',  # b/191227531
+    'sched.sched_football_32bit',  # b/339128703
+    'sched.sched_football_64bit',  # b/339128703
     'sched.sched_getattr01_32bit',  # b/200686092
     'sched.sched_setattr01_32bit',  # b/200686092
     'syscalls.bpf_prog02_32bit',  # b/191867447
@@ -79,6 +81,8 @@ DISABLED_TESTS = {
     'syscalls.mount03_64bit',  # b/275747273
     'syscalls.mount07_32bit',  # b/309808883
     'syscalls.mount07_64bit',  # b/309808883
+    'syscalls.mseal01_32bit',  # b/400564968 mseal not supported on 32 bit
+    'syscalls.mseal02_32bit',  # b/400564968 mseal not supported on 32 bit
     'syscalls.openat04_32bit',  # b/277806579
     'syscalls.openat04_64bit',  # b/277806579
     'syscalls.rt_sigprocmask01_32bit',  # b/191248975
@@ -93,6 +97,8 @@ DISABLED_TESTS = {
     'syscalls.splice07_64bit',  # b/328315662
     'syscalls.statx07_32bit',  # b/191236106
     'syscalls.statx07_64bit',  # b/191236106
+    'syscalls.unlink09_32bit',
+    'syscalls.unlink09_64bit',
 }
 
 # These tests are only disabled for hwasan
diff --git a/ltp/testcase/tools/configs/stable_tests.py b/ltp/testcase/tools/configs/stable_tests.py
index 21199c7..6ecbd37 100644
--- a/ltp/testcase/tools/configs/stable_tests.py
+++ b/ltp/testcase/tools/configs/stable_tests.py
@@ -604,6 +604,16 @@ STABLE_TESTS = {
     'pty.hangup01_64bit': False,
     'pty.ptem01_32bit': False,
     'pty.ptem01_64bit': False,
+    'pty.ptem02_32bit': False,
+    'pty.ptem02_64bit': False,
+    'pty.ptem03_32bit': False,
+    'pty.ptem03_64bit': False,
+    'pty.ptem04_32bit': False,
+    'pty.ptem04_64bit': False,
+    'pty.ptem05_32bit': False,
+    'pty.ptem05_64bit': False,
+    'pty.ptem06_32bit': False,
+    'pty.ptem06_64bit': False,
     'pty.pty01_32bit': False,
     'pty.pty01_64bit': False,
     'pty.pty02_32bit': False,
@@ -612,6 +622,10 @@ STABLE_TESTS = {
     'pty.pty06_64bit': False,
     'pty.pty07_32bit': False,
     'pty.pty07_64bit': False,
+    'pty.pty08_32bit': False,
+    'pty.pty08_64bit': False,
+    'pty.pty09_32bit': False,
+    'pty.pty09_64bit': False,
     'sched.autogroup01_32bit': False,
     'sched.autogroup01_64bit': False,
     'sched.hackbench01_32bit': False,
@@ -634,8 +648,8 @@ STABLE_TESTS = {
     'sched.sched_setattr01_64bit': False,
     'sched.sched_stress_32bit': False,
     'sched.sched_stress_64bit': False,
-    'sched.starvation_32bit': True,
-    'sched.starvation_64bit': True,
+    'sched.starvation_32bit': False,
+    'sched.starvation_64bit': False,
     'sched.time-schedule01_32bit': False,
     'sched.time-schedule01_64bit': False,
     'securebits.check_keepcaps01_32bit': False,
@@ -718,6 +732,10 @@ STABLE_TESTS = {
     'syscalls.brk02_64bit': True,
     'syscalls.cacheflush01_32bit': False,
     'syscalls.cacheflush01_64bit': False,
+    'syscalls.cachestat01_32bit': False,
+    'syscalls.cachestat01_64bit': False,
+    'syscalls.cachestat04_32bit': False,
+    'syscalls.cachestat04_64bit': False,
     'syscalls.capget01_32bit': True,
     'syscalls.capget01_64bit': True,
     'syscalls.capget02_32bit': True,
@@ -746,6 +764,10 @@ STABLE_TESTS = {
     'syscalls.chmod05_64bit': True,
     'syscalls.chmod07_32bit': True,
     'syscalls.chmod07_64bit': True,
+    'syscalls.chmod08_32bit': True,
+    'syscalls.chmod08_64bit': True,
+    'syscalls.chmod09_32bit': False,
+    'syscalls.chmod09_64bit': False,
     'syscalls.chown01_16_32bit': False,
     'syscalls.chown01_16_64bit': False,
     'syscalls.chown01_32bit': True,
@@ -1060,6 +1082,10 @@ STABLE_TESTS = {
     'syscalls.fchmodat01_64bit': True,
     'syscalls.fchmodat02_32bit': True,
     'syscalls.fchmodat02_64bit': True,
+    'syscalls.fchmodat2_01_32bit': False,
+    'syscalls.fchmodat2_01_64bit': False,
+    'syscalls.fchmodat2_02_32bit': False,
+    'syscalls.fchmodat2_02_64bit': False,
     'syscalls.fchown01_16_32bit': False,
     'syscalls.fchown01_16_64bit': False,
     'syscalls.fchown01_32bit': True,
@@ -1368,6 +1394,8 @@ STABLE_TESTS = {
     'syscalls.get_robust_list01_64bit': True,
     'syscalls.getcpu01_32bit': True,
     'syscalls.getcpu01_64bit': True,
+    'syscalls.getcpu02_32bit': True,
+    'syscalls.getcpu02_64bit': True,
     'syscalls.getcwd01_32bit': True,
     'syscalls.getcwd01_64bit': True,
     'syscalls.getcwd02_32bit': True,
@@ -1600,6 +1628,16 @@ STABLE_TESTS = {
     'syscalls.ioctl08_64bit': False,
     'syscalls.ioctl09_32bit': False,
     'syscalls.ioctl09_64bit': False,
+    'syscalls.ioctl_ficlone01_32bit': False,
+    'syscalls.ioctl_ficlone01_64bit': False,
+    'syscalls.ioctl_ficlone02_32bit': False,
+    'syscalls.ioctl_ficlone02_64bit': False,
+    'syscalls.ioctl_ficlone03_32bit': False,
+    'syscalls.ioctl_ficlone03_64bit': False,
+    'syscalls.ioctl_ficlonerange01_32bit': False,
+    'syscalls.ioctl_ficlonerange01_64bit': False,
+    'syscalls.ioctl_ficlonerange02_32bit': False,
+    'syscalls.ioctl_ficlonerange02_64bit': False,
     'syscalls.ioctl_loop03_32bit': True,
     'syscalls.ioctl_loop03_64bit': True,
     'syscalls.ioctl_loop04_32bit': True,
@@ -1688,6 +1726,14 @@ STABLE_TESTS = {
     'syscalls.linkat02_64bit': True,
     'syscalls.listen01_32bit': True,
     'syscalls.listen01_64bit': True,
+    'syscalls.listmount01_32bit': False,
+    'syscalls.listmount01_64bit': False,
+    'syscalls.listmount02_32bit': False,
+    'syscalls.listmount02_64bit': False,
+    'syscalls.listmount03_32bit': False,
+    'syscalls.listmount03_64bit': False,
+    'syscalls.listmount04_32bit': False,
+    'syscalls.listmount04_64bit': False,
     'syscalls.listxattr01_32bit': True,
     'syscalls.listxattr01_64bit': True,
     'syscalls.listxattr02_32bit': True,
@@ -1716,10 +1762,6 @@ STABLE_TESTS = {
     'syscalls.lseek07_64bit': True,
     'syscalls.lseek11_32bit': False,  # b/145105382
     'syscalls.lseek11_64bit': False,  # b/145105382
-    'syscalls.lstat01A_32bit': True,
-    'syscalls.lstat01A_64_32bit': True,
-    'syscalls.lstat01A_64_64bit': True,
-    'syscalls.lstat01A_64bit': True,
     'syscalls.lstat01_32bit': True,
     'syscalls.lstat01_64_32bit': True,
     'syscalls.lstat01_64_64bit': True,
@@ -1728,6 +1770,10 @@ STABLE_TESTS = {
     'syscalls.lstat02_64_32bit': True,
     'syscalls.lstat02_64_64bit': True,
     'syscalls.lstat02_64bit': True,
+    'syscalls.lstat03_32bit': True,
+    'syscalls.lstat03_64_32bit': True,
+    'syscalls.lstat03_64_64bit': True,
+    'syscalls.lstat03_64bit': True,
     'syscalls.madvise01_32bit': True,
     'syscalls.madvise01_64bit': True,
     'syscalls.madvise02_32bit': True,
@@ -1744,6 +1790,8 @@ STABLE_TESTS = {
     'syscalls.madvise10_64bit': True,
     'syscalls.madvise11_32bit': False,
     'syscalls.madvise11_64bit': False,
+    'syscalls.madvise12_32bit': False,
+    'syscalls.madvise12_64bit': False,
     'syscalls.mallinfo02_32bit': False,
     'syscalls.mallinfo02_64bit': False,
     'syscalls.mbind01_32bit': False,
@@ -1912,6 +1960,8 @@ STABLE_TESTS = {
     'syscalls.mremap05_64bit': True,
     'syscalls.mremap06_32bit': True,
     'syscalls.mremap06_64bit': True,
+    'syscalls.mseal01_64bit': False,
+    'syscalls.mseal02_64bit': False,
     'syscalls.msgget05_32bit': False,
     'syscalls.msgget05_64bit': False,
     'syscalls.msync01_32bit': True,
@@ -1920,8 +1970,8 @@ STABLE_TESTS = {
     'syscalls.msync02_64bit': True,
     'syscalls.msync03_32bit': True,
     'syscalls.msync03_64bit': True,
-    'syscalls.msync04_32bit': True,
-    'syscalls.msync04_64bit': True,
+    'syscalls.msync04_32bit': False,
+    'syscalls.msync04_64bit': False,
     'syscalls.munlock01_32bit': True,
     'syscalls.munlock01_64bit': True,
     'syscalls.munlock02_32bit': True,
@@ -1956,8 +2006,6 @@ STABLE_TESTS = {
     'syscalls.nice03_64bit': True,
     'syscalls.nice05_32bit': True,
     'syscalls.nice05_64bit': True,
-    'syscalls.open01A_32bit': True,
-    'syscalls.open01A_64bit': True,
     'syscalls.open01_32bit': True,
     'syscalls.open01_64bit': True,
     'syscalls.open02_32bit': True,
@@ -1980,6 +2028,8 @@ STABLE_TESTS = {
     'syscalls.open11_64bit': True,
     'syscalls.open14_32bit': True,
     'syscalls.open14_64bit': True,
+    'syscalls.open15_32bit': True,
+    'syscalls.open15_64bit': True,
     'syscalls.open_by_handle_at01_32bit': False,
     'syscalls.open_by_handle_at01_64bit': False,
     'syscalls.open_by_handle_at02_32bit': False,
@@ -2096,8 +2146,6 @@ STABLE_TESTS = {
     'syscalls.prctl02_64bit': True,
     'syscalls.prctl03_32bit': True,
     'syscalls.prctl03_64bit': True,
-    'syscalls.prctl04_32bit': True,
-    'syscalls.prctl04_64bit': True,
     'syscalls.prctl05_32bit': True,
     'syscalls.prctl05_64bit': True,
     'syscalls.prctl06_32bit': True,
@@ -2310,6 +2358,8 @@ STABLE_TESTS = {
     'syscalls.rename13_64bit': True,
     'syscalls.rename14_32bit': True,
     'syscalls.rename14_64bit': True,
+    'syscalls.rename15_32bit': True,
+    'syscalls.rename15_64bit': True,
     'syscalls.renameat01_32bit': True,
     'syscalls.renameat01_64bit': True,
     'syscalls.renameat201_32bit': True,
@@ -2322,6 +2372,12 @@ STABLE_TESTS = {
     'syscalls.request_key02_64bit': True,
     'syscalls.request_key03_32bit': True,
     'syscalls.request_key03_64bit': True,
+    'syscalls.request_key04_32bit': True,
+    'syscalls.request_key04_64bit': True,
+    'syscalls.request_key05_32bit': True,
+    'syscalls.request_key05_64bit': True,
+    'syscalls.request_key06_32bit': True,
+    'syscalls.request_key06_64bit': True,
     'syscalls.rmdir01_32bit': True,
     'syscalls.rmdir01_64bit': True,
     'syscalls.rmdir02_32bit': True,
@@ -2404,6 +2460,8 @@ STABLE_TESTS = {
     'syscalls.sched_setscheduler04_64bit': True,
     'syscalls.sched_yield01_32bit': True,
     'syscalls.sched_yield01_64bit': True,
+    'syscalls.seccomp01_32bit': True,
+    'syscalls.seccomp01_64bit': True,
     'syscalls.select01_32bit': True,
     'syscalls.select01_64bit': True,
     'syscalls.select01_SYS__newselect_32bit': False,
@@ -2651,8 +2709,8 @@ STABLE_TESTS = {
     'syscalls.setreuid07_16_64bit': False,
     'syscalls.setreuid07_32bit': True,
     'syscalls.setreuid07_64bit': True,
-    'syscalls.setrlimit01_32bit': True,
-    'syscalls.setrlimit01_64bit': True,
+    'syscalls.setrlimit01_32bit': False,
+    'syscalls.setrlimit01_64bit': False,
     'syscalls.setrlimit02_32bit': True,
     'syscalls.setrlimit02_64bit': True,
     'syscalls.setrlimit03_32bit': True,
@@ -2691,6 +2749,10 @@ STABLE_TESTS = {
     'syscalls.setxattr03_64bit': True,
     'syscalls.sgetmask01_32bit': False,
     'syscalls.sgetmask01_64bit': False,
+    'syscalls.shutdown01_32bit': True,
+    'syscalls.shutdown01_64bit': True,
+    'syscalls.shutdown02_32bit': True,
+    'syscalls.shutdown02_64bit': True,
     'syscalls.sigaction01_32bit': True,
     'syscalls.sigaction01_64bit': True,
     'syscalls.sigaction02_32bit': True,
@@ -2715,6 +2777,8 @@ STABLE_TESTS = {
     'syscalls.signal06_64bit': False,
     'syscalls.signalfd01_32bit': True,
     'syscalls.signalfd01_64bit': True,
+    'syscalls.signalfd02_32bit': True,
+    'syscalls.signalfd02_64bit': True,
     'syscalls.signalfd4_01_32bit': True,
     'syscalls.signalfd4_01_64bit': True,
     'syscalls.signalfd4_02_32bit': True,
@@ -2801,6 +2865,22 @@ STABLE_TESTS = {
     'syscalls.statfs03_64_32bit': True,
     'syscalls.statfs03_64_64bit': True,
     'syscalls.statfs03_64bit': True,
+    'syscalls.statmount01_32bit': False,
+    'syscalls.statmount01_64bit': False,
+    'syscalls.statmount02_32bit': False,
+    'syscalls.statmount02_64bit': False,
+    'syscalls.statmount03_32bit': False,
+    'syscalls.statmount03_64bit': False,
+    'syscalls.statmount04_32bit': False,
+    'syscalls.statmount04_64bit': False,
+    'syscalls.statmount05_32bit': False,
+    'syscalls.statmount05_64bit': False,
+    'syscalls.statmount06_32bit': False,
+    'syscalls.statmount06_64bit': False,
+    'syscalls.statmount07_32bit': False,
+    'syscalls.statmount07_64bit': False,
+    'syscalls.statmount08_32bit': False,
+    'syscalls.statmount08_64bit': False,
     'syscalls.statvfs01_32bit': False,
     'syscalls.statvfs01_64bit': False,
     'syscalls.statvfs02_32bit': False,
@@ -2979,8 +3059,8 @@ STABLE_TESTS = {
     'syscalls.unlink07_64bit': True,
     'syscalls.unlink08_32bit': True,
     'syscalls.unlink08_64bit': True,
-    'syscalls.unlink09_32bit': True,
-    'syscalls.unlink09_64bit': True,
+    'syscalls.unlink10_32bit': True,
+    'syscalls.unlink10_64bit': True,
     'syscalls.unlinkat01_32bit': True,
     'syscalls.unlinkat01_64bit': True,
     'syscalls.unshare01_32bit': True,
diff --git a/ltp/testcase/tools/template/template.xml b/ltp/testcase/tools/template/template.xml
index bf3f06b..f59b99e 100644
--- a/ltp/testcase/tools/template/template.xml
+++ b/ltp/testcase/tools/template/template.xml
@@ -36,7 +36,6 @@
     <!-- Mandatory tests (must pass and cannot skip). -->
     <test class="com.android.tradefed.testtype.binary.KernelTargetTest">
         <option name="skip-binary-check" value="true" />
-        <option name="abort-if-device-lost" value="true" />
         <option name="abort-if-root-lost" value="true" />
         <!-- Set binary timeout to be 18 min which is greater than the default 5 min timeout. Otherwise TF will retry to the command and attempt to do device recovery. -->
         <option name="per-binary-timeout" value="1080000" />
@@ -47,7 +46,6 @@
         <!-- Identify LTP's TCONF code (incompatible configuration) as a skip. -->
         <option name="exit-code-skip" value="32" />
         <option name="skip-binary-check" value="true" />
-        <option name="abort-if-device-lost" value="true" />
         <option name="abort-if-root-lost" value="true" />
         <!-- Set binary timeout to be 18 min which is greater than the default 5 min timeout. Otherwise TF will retry to the command and attempt to do device recovery. -->
         <option name="per-binary-timeout" value="1080000" />
diff --git a/pagesize_16kb/Vts16KPageSizeTest.cpp b/pagesize_16kb/Vts16KPageSizeTest.cpp
index 6c98bdd..69b2d1e 100644
--- a/pagesize_16kb/Vts16KPageSizeTest.cpp
+++ b/pagesize_16kb/Vts16KPageSizeTest.cpp
@@ -213,3 +213,37 @@ TEST_F(Vts16KPageSizeTest, CanReadProcessFileMappedContents) {
                 << "Failed to read maps: " << map.name;
     }
 }
+
+void setUnsetProp(const std::string& prop) {
+    // save and set the default
+    bool defaultValue = android::base::GetBoolProperty(prop, false);
+    // set and verify property.
+    ASSERT_EQ(android::base::SetProperty(prop, "true"), true);
+    ASSERT_EQ(android::base::GetBoolProperty(prop, false), true);
+
+    // reset
+    ASSERT_EQ(android::base::SetProperty(prop, std::to_string(defaultValue)), true);
+}
+
+TEST_F(Vts16KPageSizeTest, BackCompatSupport) {
+    // Backcompat support is added in Android B
+    int apiLevel = VendorApiLevel();
+    if (apiLevel < 36 /* Android B */) {
+        GTEST_SKIP() << "16 KB backcompat support is only required on Android B and later release";
+    }
+
+    std::string prop = "bionic.linker.16kb.app_compat.enabled";
+    setUnsetProp(prop);
+}
+
+TEST_F(Vts16KPageSizeTest, PackageManagerDisableBackCompat) {
+    // Package manager support for backcompat is added in Android B
+    int apiLevel = VendorApiLevel();
+    if (apiLevel < 36 /* Android B */) {
+        GTEST_SKIP() << "16 KB backcompat support in package manager is only required on Android B "
+                        "and later release";
+    }
+
+    std::string prop = "pm.16kb.app_compat.disabled";
+    setUnsetProp(prop);
+}
diff --git a/zram/ZramTest.cpp b/zram/ZramTest.cpp
index 317d733..f791e61 100644
--- a/zram/ZramTest.cpp
+++ b/zram/ZramTest.cpp
@@ -40,6 +40,7 @@ TEST(ZramTest, hasZramSwap) {
   const char* procSwapsPath = "/proc/swaps";
   const char* swapFilename = "/dev/block/zram0";
   int64_t swapSize;
+  bool fileFound = false;
   std::string delimiters = "\t ";
   std::ifstream ifs(procSwapsPath);
   std::string line;
@@ -48,8 +49,16 @@ TEST(ZramTest, hasZramSwap) {
   if (!std::getline(ifs, line)) {
     FAIL() << "Failed to read /proc/swaps.";
   }
-
-  if (!std::getline(ifs, line)) {
+  // Read all lines in the file and checks each line if it contains the string
+  // "zram0"
+  while (std::getline(ifs, line)) {
+    if (line.find(swapFilename) != std::string::npos) {
+      // zram device found
+      fileFound = true;
+      break;
+    }
+  }
+  if (!fileFound) {
     FAIL() << "No swaps found.";
   }
 
```

