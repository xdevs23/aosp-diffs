```diff
diff --git a/api/bpf_native_test/Android.bp b/api/bpf_native_test/Android.bp
index 8cc6668..94f07dd 100644
--- a/api/bpf_native_test/Android.bp
+++ b/api/bpf_native_test/Android.bp
@@ -23,7 +23,6 @@ cc_defaults {
     name: "binary_bpf_defaults",
     srcs: ["BpfTest.cpp"],
     shared_libs: [
-        "libcgrouprc",
         "libcutils",
         "libutils",
         "liblog",
@@ -50,12 +49,8 @@ cc_defaults {
 
 bpf {
     name: "kern.o",
-    include_dirs: ["packages/modules/Connectivity/bpf_progs"],
+    include_dirs: ["packages/modules/Connectivity/bpf/progs"],
     srcs: ["kern.c"],
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
 }
 
 cc_test {
@@ -63,12 +58,7 @@ cc_test {
     defaults: ["binary_bpf_defaults"],
     test_config: "bpf_module_test.xml",
     test_suites: [
-        "device-tests",
+        "general-tests",
         "vts",
     ],
 }
-
-cc_test {
-    name: "vts_test_binary_bpf_module",
-    defaults: ["binary_bpf_defaults"],
-}
diff --git a/api/bpf_native_test/kern.c b/api/bpf_native_test/kern.c
index 83f0719..81c3a98 100644
--- a/api/bpf_native_test/kern.c
+++ b/api/bpf_native_test/kern.c
@@ -14,11 +14,8 @@
  * limitations under the License.
  */
 
-#include "kern.h"
-#include <linux/bpf.h>
-#include <stdint.h>
-#include "bpf_helpers.h"
 #include "bpf_net_helpers.h"
+#include "kern.h"
 
 DEFINE_BPF_MAP(test_configuration_map, HASH, uint32_t, uint32_t, 1)
 DEFINE_BPF_MAP(test_stats_map_A, HASH, uint64_t, stats_value, MAX_NUM_SOCKETS)
diff --git a/encryption/OWNERS b/encryption/OWNERS
index 8ae729d..925aa18 100644
--- a/encryption/OWNERS
+++ b/encryption/OWNERS
@@ -1,2 +1,3 @@
+# Bug component: 49763
 ebiggers@google.com
 paulcrowley@google.com
diff --git a/encryption/file_based_encryption_tests.cpp b/encryption/file_based_encryption_tests.cpp
index b7717fa..b485440 100644
--- a/encryption/file_based_encryption_tests.cpp
+++ b/encryption/file_based_encryption_tests.cpp
@@ -261,12 +261,12 @@ class ScopedFsFreezer {
   int fd_ = -1;
 };
 
-// Reads the raw data of the file specified by |fd| from its underlying block
-// device |blk_device|.  The file has |expected_data_size| bytes of initialized
-// data; this must be a multiple of the filesystem block size
+// Reads the raw data of a file specified by |fd|. The file is located on the
+// filesystem specified by |fs_info|. The file has |expected_data_size| bytes of
+// initialized data; this must be a multiple of the filesystem block size
 // kFilesystemBlockSize.  The file may contain holes, in which case only the
 // non-holes are read; the holes are not counted in |expected_data_size|.
-static bool ReadRawDataOfFile(int fd, const std::string &blk_device,
+static bool ReadRawDataOfFile(int fd, const FilesystemInfo &fs_info,
                               int expected_data_size,
                               std::vector<uint8_t> *raw_data) {
   int max_extents = expected_data_size / kFilesystemBlockSize;
@@ -306,16 +306,8 @@ static bool ReadRawDataOfFile(int fd, const std::string &blk_device,
   uint8_t *buf = static_cast<uint8_t *>(buf_mem.get());
   int offset = 0;
 
-  android::base::unique_fd blk_fd(
-      open(blk_device.c_str(), O_RDONLY | O_DIRECT | O_CLOEXEC));
-  if (blk_fd < 0) {
-    ADD_FAILURE() << "Failed to open raw block device " << blk_device
-                  << Errno();
-    return false;
-  }
-
   for (int i = 0; i < map->fm_mapped_extents; i++) {
-    const struct fiemap_extent &extent = map->fm_extents[i];
+    struct fiemap_extent &extent = map->fm_extents[i];
 
     GTEST_LOG_(INFO) << "Extent " << i + 1 << " of " << map->fm_mapped_extents
                      << " is logical offset " << extent.fe_logical
@@ -329,13 +321,46 @@ static bool ReadRawDataOfFile(int fd, const std::string &blk_device,
       return false;
     }
     if (extent.fe_length % kFilesystemBlockSize != 0) {
-      ADD_FAILURE() << "Extent is not aligned to filesystem block size";
+      ADD_FAILURE()
+          << "Extent (length) is not aligned to filesystem block size";
+      return false;
+    }
+    if (extent.fe_physical % kFilesystemBlockSize != 0) {
+      ADD_FAILURE() << "Extent (physical address) is not aligned to filesystem "
+                       "block size";
       return false;
     }
     if (extent.fe_length > expected_data_size - offset) {
       ADD_FAILURE() << "File is longer than expected";
       return false;
     }
+    // Find the raw block device and remap the physical offset.
+    std::string raw_blk_device;
+    for (const DiskMapEntry &map_entry : fs_info.disk_map) {
+      if (extent.fe_physical / kFilesystemBlockSize <= map_entry.end_blkaddr) {
+        if ((extent.fe_physical + extent.fe_length) / kFilesystemBlockSize >
+            (map_entry.end_blkaddr + 1)) {
+          ADD_FAILURE() << "Extent spans multiple block devices";
+          return false;
+        }
+        raw_blk_device = map_entry.raw_blk_device;
+        extent.fe_physical -= map_entry.start_blkaddr * kFilesystemBlockSize;
+        break;
+      }
+    }
+    if (raw_blk_device.empty()) {
+      ADD_FAILURE()
+          << "Failed to find a raw block device in the block device list";
+      return false;
+    }
+    // Open the raw block device and read out the data.
+    android::base::unique_fd blk_fd(
+        open(raw_blk_device.c_str(), O_RDONLY | O_DIRECT | O_CLOEXEC));
+    if (blk_fd < 0) {
+      ADD_FAILURE() << "Failed to open raw block device " << raw_blk_device
+                    << Errno();
+      return false;
+    }
     if (pread(blk_fd, &buf[offset], extent.fe_length, extent.fe_physical) !=
         extent.fe_length) {
       ADD_FAILURE() << "Error reading raw data from block device" << Errno();
@@ -351,11 +376,11 @@ static bool ReadRawDataOfFile(int fd, const std::string &blk_device,
   return true;
 }
 
-// Writes |plaintext| to a file |path| located on the block device |blk_device|.
-// Returns in |ciphertext| the file's raw ciphertext read from |blk_device|.
+// Writes |plaintext| to a file |path| on the filesystem |fs_info|.
+// Returns in |ciphertext| the file's raw ciphertext read from disk.
 static bool WriteTestFile(const std::vector<uint8_t> &plaintext,
                           const std::string &path,
-                          const std::string &blk_device,
+                          const FilesystemInfo &fs_info,
                           const struct f2fs_comp_option *compress_options,
                           std::vector<uint8_t> *ciphertext) {
   GTEST_LOG_(INFO) << "Creating test file " << path << " containing "
@@ -393,7 +418,7 @@ static bool WriteTestFile(const std::vector<uint8_t> &plaintext,
   }
 
   GTEST_LOG_(INFO) << "Reading the raw ciphertext of " << path << " from disk";
-  if (!ReadRawDataOfFile(fd, blk_device, plaintext.size(), ciphertext)) {
+  if (!ReadRawDataOfFile(fd, fs_info, plaintext.size(), ciphertext)) {
     ADD_FAILURE() << "Failed to read the raw ciphertext of " << path;
     return false;
   }
@@ -733,8 +758,8 @@ bool FBEPolicyTest::GenerateTestFile(
                                     compress_options->log_cluster_size))
     return false;
 
-  if (!WriteTestFile(info->plaintext, test_file_, fs_info_.raw_blk_device,
-                     compress_options, &info->actual_ciphertext))
+  if (!WriteTestFile(info->plaintext, test_file_, fs_info_, compress_options,
+                     &info->actual_ciphertext))
     return false;
 
   android::base::unique_fd fd(open(test_file_.c_str(), O_RDONLY | O_CLOEXEC));
@@ -1063,7 +1088,7 @@ void FBEPolicyTest::TestEmmcOptimizedDunWraparound(
         << "Error writing data to " << path << Errno();
 
     // Verify the ciphertext.
-    ASSERT_TRUE(ReadRawDataOfFile(fd, fs_info_.raw_blk_device, data_size,
+    ASSERT_TRUE(ReadRawDataOfFile(fd, fs_info_, data_size,
                                   &file_info.actual_ciphertext));
     FscryptIV iv;
     memset(&iv, 0, sizeof(iv));
@@ -1451,10 +1476,8 @@ TEST(FBETest, TestFileContentsRandomness) {
   std::vector<uint8_t> zeroes(kTestFileBytes, 0);
   std::vector<uint8_t> ciphertext_1;
   std::vector<uint8_t> ciphertext_2;
-  ASSERT_TRUE(WriteTestFile(zeroes, path_1, fs_info.raw_blk_device, nullptr,
-                            &ciphertext_1));
-  ASSERT_TRUE(WriteTestFile(zeroes, path_2, fs_info.raw_blk_device, nullptr,
-                            &ciphertext_2));
+  ASSERT_TRUE(WriteTestFile(zeroes, path_1, fs_info, nullptr, &ciphertext_1));
+  ASSERT_TRUE(WriteTestFile(zeroes, path_2, fs_info, nullptr, &ciphertext_2));
 
   GTEST_LOG_(INFO) << "Verifying randomness of ciphertext";
 
diff --git a/encryption/metadata_encryption_tests.cpp b/encryption/metadata_encryption_tests.cpp
index 74db200..91fa06f 100644
--- a/encryption/metadata_encryption_tests.cpp
+++ b/encryption/metadata_encryption_tests.cpp
@@ -175,7 +175,7 @@ void DmDefaultKeyTest::SetUp() {
 
   FilesystemInfo fs_info;
   ASSERT_TRUE(GetFilesystemInfo(kTestMountpoint, &fs_info));
-  raw_blk_device_ = fs_info.raw_blk_device;
+  raw_blk_device_ = fs_info.disk_map[0].raw_blk_device;
 
   dm_->DeleteDevice(test_dm_device_name_.c_str());
 }
@@ -321,8 +321,10 @@ TEST(MetadataEncryptionTest, TestRandomness) {
   std::vector<uint8_t> raw_data;
   FilesystemInfo fs_info;
   ASSERT_TRUE(GetFilesystemInfo(mountpoint, &fs_info));
-  ASSERT_TRUE(
-      ReadBlockDevice(fs_info.raw_blk_device, kFilesystemBlockSize, &raw_data));
+  // The first block of the filesystem's main block device should always be
+  // metadata-encrypted.
+  ASSERT_TRUE(ReadBlockDevice(fs_info.disk_map[0].raw_blk_device,
+                              kFilesystemBlockSize, &raw_data));
   ASSERT_TRUE(VerifyDataRandomness(raw_data));
 }
 
diff --git a/encryption/utils.cpp b/encryption/utils.cpp
index b7a0b57..41430f3 100644
--- a/encryption/utils.cpp
+++ b/encryption/utils.cpp
@@ -16,8 +16,12 @@
 
 // Utility functions for VtsKernelEncryptionTest.
 
+#include <fstream>
+
 #include <LzmaLib.h>
+#include <android-base/parseint.h>
 #include <android-base/properties.h>
+#include <android-base/strings.h>
 #include <android-base/unique_fd.h>
 #include <errno.h>
 #include <ext4_utils/ext4.h>
@@ -33,6 +37,9 @@
 #include "Keymaster.h"
 #include "vts_kernel_encryption.h"
 
+using android::base::ParseInt;
+using android::base::Split;
+using android::base::StartsWith;
 using namespace android::dm;
 
 namespace android {
@@ -137,33 +144,8 @@ bool GetFirstApiLevel(int *first_api_level) {
   return true;
 }
 
-// Gets the block device and type of the filesystem mounted on |mountpoint|.
-// This block device is the one on which the filesystem is directly located.  In
-// the case of device-mapper that means something like /dev/mapper/dm-5, not the
-// underlying device like /dev/block/by-name/userdata.
-static bool GetFsBlockDeviceAndType(const std::string &mountpoint,
-                                    std::string *fs_blk_device,
-                                    std::string *fs_type) {
-  std::unique_ptr<FILE, int (*)(FILE *)> mnts(setmntent("/proc/mounts", "re"),
-                                              endmntent);
-  if (!mnts) {
-    ADD_FAILURE() << "Failed to open /proc/mounts" << Errno();
-    return false;
-  }
-  struct mntent *mnt;
-  while ((mnt = getmntent(mnts.get())) != nullptr) {
-    if (mnt->mnt_dir == mountpoint) {
-      *fs_blk_device = mnt->mnt_fsname;
-      *fs_type = mnt->mnt_type;
-      return true;
-    }
-  }
-  ADD_FAILURE() << "No /proc/mounts entry found for " << mountpoint;
-  return false;
-}
-
-// Gets the UUID of the filesystem of type |fs_type| that's located on
-// |fs_blk_device|.
+// Gets the UUID of the filesystem that uses |fs_blk_device| as its main block
+// device. |fs_type| gives the filesystem type.
 //
 // Unfortunately there's no kernel API to get the UUID; instead we have to read
 // it from the filesystem superblock.
@@ -219,12 +201,13 @@ static bool GetFilesystemUuid(const std::string &fs_blk_device,
   return true;
 }
 
-// Gets the raw block device of the filesystem that is mounted from
-// |fs_blk_device|.  By "raw block device" we mean a block device from which we
-// can read the encrypted file contents and filesystem metadata.  When metadata
-// encryption is disabled, this is simply |fs_blk_device|.  When metadata
-// encryption is enabled, then |fs_blk_device| is a dm-default-key device and
-// the "raw block device" is the parent of this dm-default-key device.
+// Gets the raw block device corresponding to |fs_blk_device| that is one of a
+// filesystem's mounted block devices. By "raw block device" we mean a block
+// device from which we can read the encrypted file contents and filesystem
+// metadata.  When metadata encryption is disabled, this is simply
+// |fs_blk_device|.  When metadata encryption is enabled, then |fs_blk_device|
+// is a dm-default-key device and the "raw block device" is the parent of this
+// dm-default-key device.
 //
 // We don't just use the block device listed in the fstab, because (a) it can be
 // a logical partition name which needs extra code to map to a block device, and
@@ -281,21 +264,109 @@ static bool GetRawBlockDevice(const std::string &fs_blk_device,
   return true;
 }
 
-// Gets information about the filesystem mounted on |mountpoint|.
-bool GetFilesystemInfo(const std::string &mountpoint, FilesystemInfo *info) {
-  if (!GetFsBlockDeviceAndType(mountpoint, &info->fs_blk_device, &info->type))
+// Gets information about a filesystem's block devices
+static bool GetFsBlockDeviceList(FilesystemInfo *fs_info,
+                                 const std::string &mnt_fsname) {
+  // Add a default block device
+  DiskMapEntry map_entry;
+  map_entry.start_blkaddr = 0;
+  map_entry.end_blkaddr = INT64_MAX - 1;
+  map_entry.fs_blk_device = mnt_fsname;
+
+  if (!GetRawBlockDevice(map_entry.fs_blk_device, &map_entry.raw_blk_device)) {
+    ADD_FAILURE() << "Broken block device path of the default disk";
     return false;
+  }
+  fs_info->disk_map.push_back(map_entry);
+
+  if (fs_info->type != "f2fs") return true;
+
+  // This requires a kernel patch, f238eff95f48 ("f2fs: add a proc entry show
+  // disk layout"), merged in v6.9
+  static constexpr std::string_view kDevBlockPrefix("/dev/block/");
+  const std::string proc_path = "/proc/fs/f2fs/" +
+                                mnt_fsname.substr(kDevBlockPrefix.length()) +
+                                "/disk_map";
+  std::ifstream proc_fs(proc_path.c_str());
+  if (!proc_fs.is_open()) {
+    GTEST_LOG_(INFO) << proc_path
+                     << " does not exist (expected on pre-6.9 kernels)";
+    return true;
+  }
 
-  if (!GetFilesystemUuid(info->fs_blk_device, info->type, &info->uuid))
+  std::string line;
+  bool first_device = true;
+  while (std::getline(proc_fs, line)) {
+    if (!android::base::StartsWith(line, "Disk: ")) {
+      continue;
+    }
+    if (first_device) {
+      fs_info->disk_map.erase(fs_info->disk_map.begin());
+      first_device = false;
+    }
+    DiskMapEntry map_entry;
+    std::vector<std::string> data = Split(line, "\t ");
+    if (!ParseInt(data[3], &map_entry.start_blkaddr)) {
+      ADD_FAILURE() << "Broken first block address in the address range";
+      return false;
+    }
+    if (!ParseInt(data[5], &map_entry.end_blkaddr)) {
+      ADD_FAILURE() << "Broken last block address in the address range";
+      return false;
+    }
+    map_entry.fs_blk_device = data[7];
+    if (!GetRawBlockDevice(map_entry.fs_blk_device,
+                           &map_entry.raw_blk_device)) {
+      ADD_FAILURE() << "Broken block device path in the disk map entry";
+      return false;
+    }
+    fs_info->disk_map.push_back(map_entry);
+  }
+  return true;
+}
+
+// Gets the block device list and type of the filesystem mounted on
+// |mountpoint|. The block device list has all the block device information
+// along with the address space ranges configured by the mounted filesystem.
+static bool GetFsBlockDeviceListAndType(const std::string &mountpoint,
+                                        FilesystemInfo *fs_info) {
+  std::unique_ptr<FILE, int (*)(FILE *)> mnts(setmntent("/proc/mounts", "re"),
+                                              endmntent);
+  if (!mnts) {
+    ADD_FAILURE() << "Failed to open /proc/mounts" << Errno();
     return false;
+  }
+  struct mntent *mnt;
+  while ((mnt = getmntent(mnts.get())) != nullptr) {
+    if (mnt->mnt_dir == mountpoint) {
+      fs_info->type = mnt->mnt_type;
+      return GetFsBlockDeviceList(fs_info, mnt->mnt_fsname);
+    }
+  }
+  ADD_FAILURE() << "No /proc/mounts entry found for " << mountpoint;
+  return false;
+}
+
+// Gets information about the filesystem mounted on |mountpoint|.
+bool GetFilesystemInfo(const std::string &mountpoint, FilesystemInfo *fs_info) {
+  if (!GetFsBlockDeviceListAndType(mountpoint, fs_info)) return false;
 
-  if (!GetRawBlockDevice(info->fs_blk_device, &info->raw_blk_device))
+  // This disk_map[0] always indicates the main block device which the
+  // filesystem contains its superblock.
+  if (!GetFilesystemUuid(fs_info->disk_map[0].fs_blk_device, fs_info->type,
+                         &fs_info->uuid))
     return false;
 
-  GTEST_LOG_(INFO) << info->fs_blk_device << " is mounted on " << mountpoint
-                   << " with type " << info->type << "; UUID is "
-                   << BytesToHex(info->uuid.bytes) << ", raw block device is "
-                   << info->raw_blk_device;
+  GTEST_LOG_(INFO) << " Filesystem mounted on " << mountpoint
+                   << " has type: " << fs_info->type << ", UUID is "
+                   << BytesToHex(fs_info->uuid.bytes);
+
+  for (const DiskMapEntry &map_entry : fs_info->disk_map) {
+    GTEST_LOG_(INFO) << "Block device: " << map_entry.fs_blk_device << " ("
+                     << map_entry.raw_blk_device << ") ranging from "
+                     << map_entry.start_blkaddr << " to "
+                     << map_entry.end_blkaddr;
+  }
   return true;
 }
 
diff --git a/encryption/vts_kernel_encryption.h b/encryption/vts_kernel_encryption.h
index bf45719..bd3b620 100644
--- a/encryption/vts_kernel_encryption.h
+++ b/encryption/vts_kernel_encryption.h
@@ -110,11 +110,27 @@ struct FilesystemUuid {
   uint8_t bytes[kFilesystemUuidSize];
 };
 
-struct FilesystemInfo {
+struct DiskMapEntry {
   std::string fs_blk_device;
+  std::string raw_blk_device;
+  int64_t start_blkaddr;
+  int64_t end_blkaddr;
+};
+
+struct FilesystemInfo {
   std::string type;
   FilesystemUuid uuid;
-  std::string raw_blk_device;
+
+  // The filesystem's block devices in sorted order of filesystem block address.
+  // The covered addresses are guaranteed to be contiguous and non-overlapping.
+  // The first device, starting at address 0, is the filesystem's "main" block
+  // device.
+  // Note, the disk_map's end_blkaddr is inclusive like below:
+  // [disk number]   [start_blkaddr]   [end_blkaddr]
+  // 0               0                 X - 1
+  // 1               X                 Y - 1
+  // 2               Y                 Z
+  std::vector<DiskMapEntry> disk_map;
 };
 
 bool GetFilesystemInfo(const std::string &mountpoint, FilesystemInfo *info);
diff --git a/fuse_bpf/vts_kernel_fuse_bpf_test.py b/fuse_bpf/vts_kernel_fuse_bpf_test.py
index 0f6a911..53ee771 100644
--- a/fuse_bpf/vts_kernel_fuse_bpf_test.py
+++ b/fuse_bpf/vts_kernel_fuse_bpf_test.py
@@ -38,7 +38,9 @@ class VtsKernelFuseBpfTest(unittest.TestCase):
         except:
             pass
         out_running, err, return_code = self.dut.Execute("getprop ro.fuse.bpf.is_running")
-        self.assertTrue(first_api_level < 34 or out_running.strip() == "true",
+        # Devices that are grandfathered into using sdcardfs are unable to simply swap to fuse-bpf
+        out_sdcardfs, err, return_code = self.dut.Execute("mount | grep \"type sdcardfs\"")
+        self.assertTrue(first_api_level < 34 or out_sdcardfs.strip() != "" or out_running.strip() == "true",
                            "fuse-bpf is disabled")
 
 
diff --git a/gki/Android.bp b/gki/Android.bp
index 296ab1c..5e803c3 100644
--- a/gki/Android.bp
+++ b/gki/Android.bp
@@ -49,6 +49,31 @@ cc_test {
     ],
 }
 
+cc_test {
+    name: "vts_eol_enforcement_test",
+    test_suites: [
+        "device-tests",
+        "vts",
+    ],
+    srcs: [
+        "eol_enforcement_test.cpp",
+    ],
+    defaults: [
+        "libvintf_static_user_defaults",
+    ],
+    static_libs: [
+        "libbase",
+        "libkver",
+        "libtinyxml2",
+        "libvintf",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+    test_config: "eol_enforcement_test.xml",
+}
+
 cc_test {
     name: "vts_generic_boot_image_test",
     require_root: true,
diff --git a/gki/eol_enforcement_test.cpp b/gki/eol_enforcement_test.cpp
new file mode 100644
index 0000000..dd01d95
--- /dev/null
+++ b/gki/eol_enforcement_test.cpp
@@ -0,0 +1,192 @@
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
+#include <chrono>
+#include <cstdint>
+#include <format>
+#include <limits>
+#include <regex>
+#include <sstream>
+
+#include <android-base/file.h>
+#include <android-base/parseint.h>
+#include <gtest/gtest.h>
+#include <kver/kernel_release.h>
+#include <tinyxml2.h>
+#include <vintf/Version.h>
+#include <vintf/VintfObject.h>
+
+using android::vintf::KernelVersion;
+using android::vintf::RuntimeInfo;
+using android::vintf::Version;
+using android::vintf::VintfObject;
+
+namespace {
+
+const std::string kernel_lifetimes_config_path =
+    "/system/etc/kernel/kernel-lifetimes.xml";
+
+bool parseDate(std::string_view date_string,
+               std::chrono::year_month_day& date) {
+  const std::regex date_regex("(\\d\\d\\d\\d)-(\\d\\d)-(\\d\\d)");
+  std::cmatch date_match;
+  if (!std::regex_match(date_string.data(), date_match, date_regex)) {
+    return false;
+  }
+
+  uint32_t year, month, day;
+  android::base::ParseUint(date_match[1].str(), &year);
+  android::base::ParseUint(date_match[2].str(), &month);
+  android::base::ParseUint(date_match[3].str(), &day);
+  date = std::chrono::year_month_day(std::chrono::year(year),
+                                     std::chrono::month(month),
+                                     std::chrono::day(day));
+  return true;
+}
+
+KernelVersion parseKernelVersion(std::string_view kernel_version_string) {
+  const std::regex kernel_version_regex("(\\d+)\\.(\\d+)\\.(\\d+)");
+  std::cmatch kernel_version_match;
+  if (!std::regex_match(kernel_version_string.data(), kernel_version_match,
+                        kernel_version_regex)) {
+    return {};
+  }
+
+  uint32_t v, mj, mi;
+  android::base::ParseUint(kernel_version_match[1].str(), &v);
+  android::base::ParseUint(kernel_version_match[2].str(), &mj);
+  android::base::ParseUint(kernel_version_match[3].str(), &mi);
+  return KernelVersion(v, mj, mi);
+}
+
+}  // namespace
+
+class EolEnforcementTest : public testing::Test {
+ public:
+  virtual void SetUp() override {
+    // Get current date.
+    today = std::chrono::year_month_day(std::chrono::floor<std::chrono::days>(
+        std::chrono::system_clock::now()));
+
+    // Get runtime info.
+    auto vintf = VintfObject::GetInstance();
+    ASSERT_NE(vintf, nullptr);
+    runtime_info = vintf->getRuntimeInfo(RuntimeInfo::FetchFlag::CPU_VERSION |
+                                         RuntimeInfo::FetchFlag::CONFIG_GZ);
+    ASSERT_NE(runtime_info, nullptr);
+  }
+
+  bool isReleaseEol(std::string_view date) const;
+
+  std::chrono::year_month_day today;
+  std::shared_ptr<const RuntimeInfo> runtime_info;
+};
+
+bool EolEnforcementTest::isReleaseEol(std::string_view date_string) const {
+  std::chrono::year_month_day date;
+  if (!parseDate(date_string, date)) {
+    ADD_FAILURE() << "Failed to parse date string: " << date_string;
+  }
+  return today > date;
+}
+
+TEST_F(EolEnforcementTest, KernelNotEol) {
+  ASSERT_GE(runtime_info->kernelVersion().dropMinor(), (Version{4, 14}))
+      << "Kernel versions below 4.14 are EOL";
+
+  std::string kernel_lifetimes_content;
+  ASSERT_TRUE(android::base::ReadFileToString(kernel_lifetimes_config_path,
+                                              &kernel_lifetimes_content))
+      << "Failed to read approved OGKI builds config at "
+      << kernel_lifetimes_config_path;
+
+  tinyxml2::XMLDocument kernel_lifetimes_xml;
+  const auto xml_error =
+      kernel_lifetimes_xml.Parse(kernel_lifetimes_content.c_str());
+  ASSERT_EQ(xml_error, tinyxml2::XMLError::XML_SUCCESS)
+      << "Failed to parse approved builds config: "
+      << tinyxml2::XMLDocument::ErrorIDToName(xml_error);
+
+  const auto kernel_version = runtime_info->kernelVersion();
+  std::string branch_name;
+  if (kernel_version.dropMinor() < Version{5, 4}) {
+    branch_name = std::format("android-{}.{}", kernel_version.version,
+                              kernel_version.majorRev);
+  } else {
+    const auto kernel_release = android::kver::KernelRelease::Parse(
+        android::vintf::VintfObject::GetRuntimeInfo()->osRelease(),
+        /* allow_suffix = */ true);
+    ASSERT_TRUE(kernel_release.has_value())
+        << "Failed to parse the kernel release string";
+    branch_name =
+        std::format("android{}-{}.{}", kernel_release->android_release(),
+                    kernel_version.version, kernel_version.majorRev);
+  }
+
+  tinyxml2::XMLElement* branch_element = nullptr;
+  const auto kernels_element = kernel_lifetimes_xml.RootElement();
+  for (auto branch = kernels_element->FirstChildElement("branch"); branch;
+       branch = branch->NextSiblingElement("branch")) {
+    if (branch->Attribute("name", branch_name.c_str())) {
+      branch_element = branch;
+      break;
+    }
+  }
+  ASSERT_NE(branch_element, nullptr)
+      << "Branch '" << branch_name << "' not found in approved builds config";
+
+  // Test against branch EOL is there are no releases for the branch.
+  if (const auto no_releases = branch_element->FirstChildElement("no-releases");
+      no_releases != nullptr) {
+    std::chrono::year_month_day eol;
+    ASSERT_TRUE(parseDate(branch_element->Attribute("eol"), eol))
+        << "Failed to parse branch '" << branch_name
+        << "' EOL date: " << branch_element->Attribute("eol");
+    EXPECT_GE(eol, today);
+    return;
+  }
+
+  // Test against kernel release EOL.
+  const auto lts_versions = branch_element->FirstChildElement("lts-versions");
+  const auto release_version =
+      std::format("{}.{}.{}", kernel_version.version, kernel_version.majorRev,
+                  kernel_version.minorRev);
+  tinyxml2::XMLElement* latest_release = nullptr;
+  KernelVersion latest_kernel_version;
+  for (auto release = lts_versions->FirstChildElement("release"); release;
+       release = release->NextSiblingElement("release")) {
+    if (release->Attribute("version", release_version.c_str())) {
+      EXPECT_FALSE(isReleaseEol(release->Attribute("eol")));
+      return;
+    } else if (auto kernel_version =
+                   parseKernelVersion(release->Attribute("version"));
+               latest_release == nullptr ||
+               kernel_version > latest_kernel_version) {
+      latest_release = release;
+      latest_kernel_version = kernel_version;
+    }
+  }
+
+  // If current kernel version is newer than the latest kernel version found in
+  // the config, then this might be a kernel release which is yet to get a
+  // release config. Test against the latest kernel release version if this is
+  // the case.
+  if (kernel_version > latest_kernel_version) {
+    EXPECT_FALSE(isReleaseEol(latest_release->Attribute("eol")));
+  } else {
+    FAIL() << "Kernel release '" << release_version << "' is not recognised";
+  }
+}
diff --git a/gki/eol_enforcement_test.xml b/gki/eol_enforcement_test.xml
new file mode 100644
index 0000000..54a252c
--- /dev/null
+++ b/gki/eol_enforcement_test.xml
@@ -0,0 +1,27 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+<configuration description="Config for vts_eol_enforcement_test">
+    <target_preparer class="com.android.tradefed.targetprep.WaitForDeviceDatetimePreparer"/>
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
+    <target_preparer class="com.android.tradefed.targetprep.PushFilePreparer">
+        <option name="cleanup" value="true"/>
+        <option name="push" value="vts_eol_enforcement_test->/data/local/tmp/vts_eol_enforcement_test"/>
+    </target_preparer>
+    <test class="com.android.tradefed.testtype.GTest">
+        <option name="native-test-device-path" value="/data/local/tmp"/>
+        <option name="module-name" value="vts_eol_enforcement_test"/>
+    </test>
+</configuration>
diff --git a/gki/generic_boot_image_test.cpp b/gki/generic_boot_image_test.cpp
index c9af3ef..76abfa0 100644
--- a/gki/generic_boot_image_test.cpp
+++ b/gki/generic_boot_image_test.cpp
@@ -178,8 +178,10 @@ TEST_F(GenericBootImageTest, GenericRamdisk) {
   ASSERT_NE(Level::UNSPECIFIED, kernel_level) << error_msg;
   std::string boot_path;
   if (kernel_level >= Level::T) {
-    if (std::stoi(android::base::GetProperty("ro.vendor.api_level", "0")) >=
-        __ANDROID_API_T__) {
+    int first_api_level = android::base::GetIntProperty(
+        "ro.board.first_api_level",
+        android::base::GetIntProperty("ro.vendor.api_level", 1000000));
+    if (first_api_level >= __ANDROID_API_T__) {
       boot_path = "/dev/block/by-name/init_boot" + slot_suffix;
     } else {
       // This is the case of a device launched before Android 13 that is
diff --git a/ltp/testcase/tools/configs/stable_tests.py b/ltp/testcase/tools/configs/stable_tests.py
index ef0ffff..627e509 100644
--- a/ltp/testcase/tools/configs/stable_tests.py
+++ b/ltp/testcase/tools/configs/stable_tests.py
@@ -838,8 +838,8 @@ STABLE_TESTS = {
     'syscalls.creat04_64bit': True,
     'syscalls.creat05_32bit': True,
     'syscalls.creat05_64bit': True,
-    'syscalls.creat07_32bit': True,
-    'syscalls.creat07_64bit': True,
+    'syscalls.creat07_32bit': False,
+    'syscalls.creat07_64bit': False,
     'syscalls.creat08_32bit': True,
     'syscalls.creat08_64bit': True,
     'syscalls.delete_module01_32bit': False,
@@ -952,8 +952,8 @@ STABLE_TESTS = {
     'syscalls.execve02_64bit': True,
     'syscalls.execve03_32bit': True,
     'syscalls.execve03_64bit': True,
-    'syscalls.execve04_32bit': True,
-    'syscalls.execve04_64bit': True,
+    'syscalls.execve04_32bit': False,
+    'syscalls.execve04_64bit': False,
     'syscalls.execve05_32bit': True,
     'syscalls.execve05_64bit': True,
     'syscalls.execveat01_32bit': False,  # b/122888513
diff --git a/pagesize_16kb/Vts16KPageSizeTest.cpp b/pagesize_16kb/Vts16KPageSizeTest.cpp
index f839299..589964c 100644
--- a/pagesize_16kb/Vts16KPageSizeTest.cpp
+++ b/pagesize_16kb/Vts16KPageSizeTest.cpp
@@ -28,6 +28,14 @@ class Vts16KPageSizeTest : public ::testing::Test {
         return android::base::GetIntProperty("ro.vendor.api_level", __ANDROID_API_S__);
     }
 
+    static int ProductPageSize() {
+        return android::base::GetIntProperty("ro.product.page_size", 0);
+    }
+
+    static int BootPageSize() {
+        return android::base::GetIntProperty("ro.boot.hardware.cpu.pagesize", 0);
+    }
+
     static bool NoBionicPageSizeMacroProperty() {
         // "ro.product.build.no_bionic_page_size_macro" was added in Android V and is
         // set to true when Android is build with PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO := true.
@@ -41,6 +49,11 @@ class Vts16KPageSizeTest : public ::testing::Test {
 
         android::elf64::Elf64Binary elf;
 
+        // 32bit ELFs only need to support a max-page-size of 4KiB
+        if (!android::elf64::Elf64Parser::IsElf64(filepath)) {
+            return 4096;
+        }
+
         if (!android::elf64::Elf64Parser::ParseElfFile(filepath, elf)) {
             return -1;
         }
@@ -60,8 +73,9 @@ class Vts16KPageSizeTest : public ::testing::Test {
     }
 
     static void SetUpTestSuite() {
-        if (VendorApiLevel() < __ANDROID_API_V__) {
-            GTEST_SKIP() << "16kB support is only required on V and later releases.";
+        if (VendorApiLevel() < 202404 && ProductPageSize() != 16384) {
+            GTEST_SKIP() << "16kB support is only required on V and later releases as well as on "
+                            "products directly booting with 16kB kernels.";
         }
     }
 
@@ -117,3 +131,25 @@ TEST_F(Vts16KPageSizeTest, NoBionicPageSizeMacro) {
     if (!NoBionicPageSizeMacroProperty())
         GTEST_SKIP() << "Device was not built with: PRODUCT_NO_BIONIC_PAGE_SIZE_MACRO := true";
 }
+
+/**
+ * Checks if the device has page size which was set using TARGET_BOOTS_16K
+ */
+TEST_F(Vts16KPageSizeTest, ProductPageSize) {
+    // We can't set the default value to be 4096 since device which will have 16KB page size and
+    // doesn't set TARGET_BOOTS_16K, won't have this property and will fail the test.
+    int requiredPageSize = ProductPageSize();
+    if (requiredPageSize != 0) {
+        int currentPageSize = getpagesize();
+        ASSERT_EQ(requiredPageSize, currentPageSize);
+    } else {
+        GTEST_SKIP() << "Device was not built with option TARGET_BOOTS_16K = true";
+    }
+}
+
+/**
+ * Check boot reported or CPU reported page size that is currently being used.
+ */
+TEST_F(Vts16KPageSizeTest, BootPageSize) {
+    ASSERT_EQ(BootPageSize(), getpagesize());
+}
```

