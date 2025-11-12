```diff
diff --git a/OWNERS b/OWNERS
index c85600b..b4237f8 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,7 +1,6 @@
 # Bug component: 391836
 
 bettyzhou@google.com
-vmartensson@google.com
 sspatil@google.com
 tkjos@google.com
 adelva@google.com
diff --git a/abi/src/com/android/tests/abi/KernelAbilistTest.java b/abi/src/com/android/tests/abi/KernelAbilistTest.java
index 418bab8..849fdf3 100644
--- a/abi/src/com/android/tests/abi/KernelAbilistTest.java
+++ b/abi/src/com/android/tests/abi/KernelAbilistTest.java
@@ -30,6 +30,7 @@ import org.junit.runner.RunWith;
 public class KernelAbilistTest extends BaseHostJUnit4Test {
     private static final String FEATURE_LEANBACK = "android.software.leanback";
     private static final String FEATURE_TV = "android.hardware.type.television";
+    private static final String FEATURE_WATCH = "android.hardware.type.watch";
 
     @VsrTest(requirements = {"VSR-3.12-002"})
     @RequiresDevice
@@ -46,6 +47,11 @@ public class KernelAbilistTest extends BaseHostJUnit4Test {
             return;
         }
 
+        // Exclude VSR-3.12 for Wear
+        if (hasDeviceFeature(FEATURE_WATCH)) {
+            return;
+        }
+
         // Allow OEMs to keep shipping 32/64 mixed systems if they update their
         // vendor partition to a newer API level, as long as the device was
         // first launched before this VSR requirement was added in API 34.
diff --git a/api/sysfs/OWNERS b/api/sysfs/OWNERS
index 85b9a12..44830f3 100644
--- a/api/sysfs/OWNERS
+++ b/api/sysfs/OWNERS
@@ -1,3 +1,2 @@
 # Bug component: 391836
-vmartensson@google.com
-edliaw@google.com
+tkjos@google.com
\ No newline at end of file
diff --git a/encryption/OWNERS b/encryption/OWNERS
index 925aa18..d82ea84 100644
--- a/encryption/OWNERS
+++ b/encryption/OWNERS
@@ -1,3 +1,2 @@
 # Bug component: 49763
 ebiggers@google.com
-paulcrowley@google.com
diff --git a/f2fs/Android.bp b/f2fs/Android.bp
index b30e9cd..250c423 100644
--- a/f2fs/Android.bp
+++ b/f2fs/Android.bp
@@ -47,8 +47,3 @@ cc_test {
         "vts",
     ],
 }
-
-cc_test {
-    name: "vts_test_binary_f2fs",
-    defaults: ["binary_f2fs_defaults"],
-}
diff --git a/f2fs/F2fsTest.cpp b/f2fs/F2fsTest.cpp
index 82ef11c..b9afde8 100644
--- a/f2fs/F2fsTest.cpp
+++ b/f2fs/F2fsTest.cpp
@@ -48,19 +48,25 @@ class F2fsTest : public testing::Test {
     int flags = FS_COMPR_FL;
     int res;
 
+    page_size = getpagesize();
+    std::string block_size = std::to_string(page_size);
     ASSERT_NE(fd, -1);
     res = ftruncate(fd, 100 << 20);  // 100 MB
     ASSERT_EQ(res, 0);
     close(fd);
 
-    const char* make_fs_argv[] = {
-        kMkfsPath,    "-f",          "-O",
-        "extra_attr", "-O",          "project_quota",
-        "-O",         "compression", "-O",
-        "casefold",   "-C",          "utf8",
-        "-g",         "android",     "/data/local/tmp/img",
+    std::vector<const char*> make_fs_argv = {
+        kMkfsPath, "-f",          "-O", "extra_attr", "-O", "project_quota",
+        "-O",      "compression", "-O", "casefold",   "-C", "utf8",
+        "-g",      "android",
     };
-    res = logwrap_fork_execvp(arraysize(make_fs_argv), make_fs_argv, nullptr,
+    make_fs_argv.push_back("-w");
+    make_fs_argv.push_back(block_size.c_str());
+    make_fs_argv.push_back("-b");
+    make_fs_argv.push_back(block_size.c_str());
+    make_fs_argv.push_back("/data/local/tmp/img");
+
+    res = logwrap_fork_execvp(make_fs_argv.size(), make_fs_argv.data(), nullptr,
                               false, LOG_KLOG, true, nullptr);
     ASSERT_EQ(res, 0);
     mkdir("/data/local/tmp/mnt", (S_IRWXU | S_IRGRP | S_IROTH));
@@ -71,12 +77,12 @@ class F2fsTest : public testing::Test {
     ASSERT_EQ(mount(loop_dev.device().c_str(), "data/local/tmp/mnt", "f2fs", 0,
                     "compress_mode=user"),
               0);
-    test_data1 = malloc(4096);
+    test_data1 = malloc(page_size);
     ASSERT_NE(test_data1, nullptr);
-    memset(test_data1, 0x41, 4096);
-    test_data2 = malloc(4096);
+    memset(test_data1, 0x41, page_size);
+    test_data2 = malloc(page_size);
     ASSERT_NE(test_data2, nullptr);
-    memset(test_data2, 0x61, 4096);
+    memset(test_data2, 0x61, page_size);
   }
   void TearDown() override {
     ASSERT_EQ(umount2("/data/local/tmp/mnt", MNT_DETACH), 0);
@@ -89,32 +95,33 @@ class F2fsTest : public testing::Test {
  protected:
   void* test_data1;
   void* test_data2;
+  int page_size;
 };
 
 TEST_F(F2fsTest, test_normal_lseek) {
-  char buf[4096];
+  char buf[page_size];
   int fd = open(kTestFilePath, O_RDWR | O_TRUNC | O_CREAT,
                 (S_IRWXU | S_IRGRP | S_IROTH));
   ASSERT_NE(fd, -1);
 
-  ASSERT_EQ(lseek(fd, 1024 * 4096, SEEK_SET), 1024 * 4096);
+  ASSERT_EQ(lseek(fd, 1024 * page_size, SEEK_SET), 1024 * page_size);
   for (int i = 0; i < 1024; i++) {
-    ASSERT_EQ(write(fd, test_data1, 4096), 4096);
+    ASSERT_EQ(write(fd, test_data1, page_size), page_size);
   }
   fsync(fd);
   ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), 0);
-  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 1024 * 4096);
+  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 1024 * page_size);
   lseek(fd, 0, SEEK_SET);
-  write(fd, test_data2, 4096);
+  write(fd, test_data2, page_size);
   fsync(fd);
   ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 0);
 
-  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), 4096);
-  ASSERT_EQ(lseek(fd, 5000, SEEK_DATA), 1024 * 4096);
+  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), page_size);
+  ASSERT_EQ(lseek(fd, page_size + 904, SEEK_DATA), 1024 * page_size);
 }
 
 TEST_F(F2fsTest, test_compressed_lseek) {
-  char buf[4096];
+  char buf[page_size];
 
   int fd = open(kTestFilePath, O_RDWR | O_TRUNC | O_CREAT,
                 (S_IRWXU | S_IRGRP | S_IROTH));
@@ -122,24 +129,24 @@ TEST_F(F2fsTest, test_compressed_lseek) {
 
   int flags = FS_COMPR_FL;
   ASSERT_NE(ioctl(fd, FS_IOC_SETFLAGS, &flags), -1);
-  ASSERT_EQ(lseek(fd, 1024 * 4096, SEEK_SET), 1024 * 4096);
+  ASSERT_EQ(lseek(fd, 1024 * page_size, SEEK_SET), 1024 * page_size);
   for (int i = 0; i < 1024; i++) {
-    ASSERT_EQ(write(fd, test_data1, 4096), 4096);
+    ASSERT_EQ(write(fd, test_data1, page_size), page_size);
   }
   fsync(fd);
   ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), 0);
-  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 1024 * 4096);
+  ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 1024 * page_size);
   ASSERT_NE(ioctl(fd, F2FS_IOC_COMPRESS_FILE), -1);
   lseek(fd, 0, SEEK_SET);
-  write(fd, test_data2, 4096);
+  write(fd, test_data2, page_size);
   fsync(fd);
   ASSERT_EQ(lseek(fd, 0, SEEK_DATA), 0);
-  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), 4096);
-  ASSERT_EQ(lseek(fd, 5000, SEEK_DATA), 1024 * 4096);
+  ASSERT_EQ(lseek(fd, 0, SEEK_HOLE), page_size);
+  ASSERT_EQ(lseek(fd, page_size + 904, SEEK_DATA), 1024 * page_size);
 }
 
 TEST_F(F2fsTest, test_sparse_decompress) {
-  char buf[4096];
+  char buf[page_size];
   int res;
 
   int fd = open(kTestFilePath, O_RDWR | O_TRUNC | O_CREAT,
@@ -150,16 +157,16 @@ TEST_F(F2fsTest, test_sparse_decompress) {
   ASSERT_NE(fd, -1);
 
   ASSERT_NE(ioctl(fd, FS_IOC_SETFLAGS, &flags), -1);
-  res = lseek(fd, 1024 * 4096, SEEK_SET);
-  ASSERT_EQ(res, 1024 * 4096);
+  res = lseek(fd, 1024 * page_size, SEEK_SET);
+  ASSERT_EQ(res, 1024 * page_size);
   for (int i = 0; i < 1024; i++) {
-    res = write(fd, test_data1, 4096);
-    ASSERT_EQ(res, 4096);
+    res = write(fd, test_data1, page_size);
+    ASSERT_EQ(res, page_size);
   }
   fsync(fd);
   ASSERT_NE(ioctl(fd, F2FS_IOC_COMPRESS_FILE), -1);
   lseek(fd, 0, SEEK_SET);
-  write(fd, test_data2, 4096);
+  write(fd, test_data2, page_size);
   fsync(fd);
   int pid = fork();
   if (pid == 0) {
@@ -189,21 +196,21 @@ TEST_F(F2fsTest, test_sparse_decompress) {
   // Check for corruption
   fd = open(kTestFilePath, O_RDONLY);
   ASSERT_NE(fd, -1);
-  res = read(fd, buf, 4096);
-  ASSERT_EQ(res, 4096);
-  ASSERT_EQ(memcmp(buf, test_data2, 4096), 0);
+  res = read(fd, buf, page_size);
+  ASSERT_EQ(res, page_size);
+  ASSERT_EQ(memcmp(buf, test_data2, page_size), 0);
 
-  char empty_buf[4096];
-  memset(empty_buf, 0, 4096);
+  char empty_buf[page_size];
+  memset(empty_buf, 0, page_size);
   for (int i = 1; i < 1024; i++) {
-    res = read(fd, buf, 4096);
-    ASSERT_EQ(res, 4096);
-    ASSERT_EQ(memcmp(buf, empty_buf, 4096), 0);
+    res = read(fd, buf, page_size);
+    ASSERT_EQ(res, page_size);
+    ASSERT_EQ(memcmp(buf, empty_buf, page_size), 0);
   }
   for (int i = 0; i < 1024; i++) {
-    res = read(fd, buf, 4096);
-    ASSERT_EQ(res, 4096);
-    ASSERT_EQ(memcmp(buf, test_data1, 4096), 0);
+    res = read(fd, buf, page_size);
+    ASSERT_EQ(res, page_size);
+    ASSERT_EQ(memcmp(buf, test_data1, page_size), 0);
   }
   close(fd);
 }
diff --git a/gki/generic_boot_image_test.cpp b/gki/generic_boot_image_test.cpp
index f41c5a1..4d7b593 100644
--- a/gki/generic_boot_image_test.cpp
+++ b/gki/generic_boot_image_test.cpp
@@ -93,12 +93,14 @@ class GenericBootImageTest : public testing::Test {
     // device targets, and we don't have any requests to skip this test
     // on x86 / x86_64 as of 2022-06-07.
 
-    int firstApiLevel = std::stoi(android::base::GetProperty("ro.product.first_api_level", "0"));
-    if (isTV() && firstApiLevel <= __ANDROID_API_T__) {
+    first_api_level_ = std::stoi(
+        android::base::GetProperty("ro.product.first_api_level", "0"));
+    if (isTV() && first_api_level_ <= __ANDROID_API_T__) {
       GTEST_SKIP() << "Skipping on TV devices";
     }
   }
   std::shared_ptr<const RuntimeInfo> runtime_info;
+  int first_api_level_ = -1;
 };
 
 TEST_F(GenericBootImageTest, KernelReleaseFormat) {
@@ -157,7 +159,7 @@ std::set<std::string> GetAllowListBySdkLevel(uint32_t target_sdk_level) {
               "system/bin/getprop",
               "system/bin/getevent",
           },
-      },
+      }, {36, { "dev/kmsg" }}
   };
   auto res = GetRequirementBySdkLevel(target_sdk_level);
   for (const auto& [level, requirements] : allow_by_level) {
@@ -235,6 +237,20 @@ TEST_F(GenericBootImageTest, GenericRamdisk) {
   std::set<std::string> generic_ramdisk_allow_list =
       GetAllowListBySdkLevel(sdk_level);
 
+  // init_boot was considered a system partition since its introduction,
+  // however, many devices accidentally shipped it under vendor freeze. As of
+  // 2025Q2 we are now validating the requirement.
+  if (first_api_level_ > __ANDROID_API_V__) {
+    const auto system_sdk_level =
+        android::base::GetIntProperty("ro.system.build.version.sdk", 0);
+    ASSERT_EQ(sdk_level, system_sdk_level)
+        << "The generic ramdisk must be updated along with the system image "
+           "and be built from the same source code. The current system level "
+           "is "
+        << system_sdk_level << " and the ramdisk was built at level "
+        << sdk_level;
+  }
+
   const bool is_debuggable = GetBoolProperty("ro.debuggable", false);
   if (is_debuggable) {
     const std::set<std::string> debuggable_allowlist{
diff --git a/gki/lz4_legacy.cpp b/gki/lz4_legacy.cpp
index 423687c..a04d668 100644
--- a/gki/lz4_legacy.cpp
+++ b/gki/lz4_legacy.cpp
@@ -42,7 +42,7 @@ android::base::Result<void> Lz4DecompressLegacy(const char* input,
   constexpr uint32_t lz4_legacy_magic = 0x184C2102;
   constexpr auto lz4_legacy_block_size = 8_MiB;
 
-  struct stat st_buf {};
+  struct stat st_buf{};
   if (stat(input, &st_buf) != 0) {
     return ErrnoError() << "stat(" << input << ")";
   }
@@ -85,7 +85,8 @@ android::base::Result<void> Lz4DecompressLegacy(const char* input,
 
     // Android is little-endian. No need to convert block_size.
     if (block_size == lz4_legacy_magic) {
-      return Error() << "Found another lz4 compressed stream";
+      // If there are more streams keep reading.
+      continue;
     }
     if (block_size > ibuf.size()) {
       return Error() << "Block size is " << block_size
diff --git a/gki/ramdisk_utils.cpp b/gki/ramdisk_utils.cpp
index 1c4182a..f645675 100644
--- a/gki/ramdisk_utils.cpp
+++ b/gki/ramdisk_utils.cpp
@@ -26,6 +26,7 @@
 using android::base::ErrnoError;
 using android::base::Error;
 using android::base::ReadFullyAtOffset;
+using android::base::WriteFully;
 using android::base::WriteStringToFd;
 
 namespace android {
@@ -69,8 +70,8 @@ android::base::Result<std::unique_ptr<TemporaryFile>> ExtractRamdiskRaw(
   return ramdisk_content_file;
 }
 
-android::base::Result<std::unique_ptr<TemporaryFile>> ExtractVendorRamdiskRaw(
-    const std::string &vendor_boot_path) {
+android::base::Result<std::vector<std::unique_ptr<TemporaryFile>>>
+ExtractVendorRamdisksRaw(const std::string &vendor_boot_path) {
   android::base::unique_fd bootimg(
       TEMP_FAILURE_RETRY(open(vendor_boot_path.c_str(), O_RDONLY)));
   if (!bootimg.ok()) return ErrnoError() << "open(" << vendor_boot_path << ")";
@@ -83,26 +84,69 @@ android::base::Result<std::unique_ptr<TemporaryFile>> ExtractVendorRamdiskRaw(
   if (hdr.header_version < 3)
     return Error() << "Unsupported header version V" << hdr.header_version;
 
+  std::vector<std::unique_ptr<TemporaryFile>> vendor_ramdisk_content_files;
   // See bootimg.h
   const auto num_boot_header_pages =
       (hdr.header_size + hdr.page_size - 1) / hdr.page_size;
+  const auto num_boot_ramdisk_pages =
+      (hdr.vendor_ramdisk_size + hdr.page_size - 1) / hdr.page_size;
+  const auto num_boot_dtb_pages =
+      (hdr.dtb_size + hdr.page_size - 1) / hdr.page_size;
   const auto ramdisk_offset_base = hdr.page_size * num_boot_header_pages;
 
-  // Ignore the vendor ramdisk table and load the entire vendor ramdisk section.
-  // This has the same effect as does loading all of the vendor ramdisk
-  //  fragments in the vendor_boot partition.
-  // https://source.android.com/docs/core/architecture/partitions/vendor-boot-partitions#vendor-boot-header
-  std::string vendor_ramdisk_content(hdr.vendor_ramdisk_size, '\0');
-  auto vendor_ramdisk_content_file = std::make_unique<TemporaryFile>();
-
-  if (!ReadFullyAtOffset(bootimg.get(), vendor_ramdisk_content.data(),
-                         hdr.vendor_ramdisk_size, ramdisk_offset_base))
-    return ErrnoError() << "read ramdisk section";
-  if (!WriteStringToFd(vendor_ramdisk_content, vendor_ramdisk_content_file->fd))
-    return ErrnoError() << "write ramdisk section to file";
-  if (fsync(vendor_ramdisk_content_file->fd) != 0)
-    return ErrnoError() << "fsync ramdisk section file";
-  return vendor_ramdisk_content_file;
+  auto read_and_write_ramdisk = [&](uint32_t ramdisk_size,
+                                    uint32_t bootconfig_offset)
+      -> android::base::Result<std::unique_ptr<TemporaryFile>> {
+    std::vector<uint8_t> ramdisk_content(ramdisk_size, '\0');
+    auto ramdisk_content_file = std::make_unique<TemporaryFile>();
+    if (!ReadFullyAtOffset(bootimg.get(), ramdisk_content.data(),
+                           ramdisk_content.size(), bootconfig_offset))
+      return ErrnoError() << "read ramdisk section";
+    if (!WriteFully(ramdisk_content_file->fd, ramdisk_content.data(),
+                    ramdisk_content.size()))
+      return ErrnoError() << "write ramdisk section to file";
+    if (fsync(ramdisk_content_file->fd) != 0)
+      return ErrnoError() << "fsync ramdisk section file";
+    return ramdisk_content_file;
+  };
+
+  // For V4 it's possible to have multiple ramdisks so handle it sepparately.
+  if (hdr.header_version > 3) {
+    vendor_boot_img_hdr_v4 hdr_4{};
+    if (!ReadFullyAtOffset(bootimg.get(), &hdr_4, sizeof(hdr_4), 0))
+      return ErrnoError() << "read header";
+
+    const auto num_vendor_ramdisk_table_pages =
+        (hdr_4.vendor_ramdisk_table_size + hdr_4.page_size - 1) /
+        hdr_4.page_size;
+    const auto vendor_ramdisk_table_offset =
+        hdr_4.page_size *
+        (num_boot_header_pages + num_boot_ramdisk_pages + num_boot_dtb_pages);
+
+    for (uint32_t idx = 0; idx < hdr_4.vendor_ramdisk_table_entry_num; ++idx) {
+      vendor_ramdisk_table_entry_v4 entry;
+      const auto entry_offset = vendor_ramdisk_table_offset +
+                                (hdr_4.vendor_ramdisk_table_entry_size * idx);
+      if (!ReadFullyAtOffset(bootimg.get(), &entry, sizeof(entry),
+                             entry_offset))
+        return ErrnoError() << "reading ramdisk table entry index " << idx;
+
+      auto vendor_ramdisk_content_file = read_and_write_ramdisk(
+          entry.ramdisk_size, ramdisk_offset_base + entry.ramdisk_offset);
+      if (!vendor_ramdisk_content_file.ok())
+        return vendor_ramdisk_content_file.error();
+      vendor_ramdisk_content_files.emplace_back(
+          std::move(*vendor_ramdisk_content_file));
+    }
+  } else {
+    auto vendor_ramdisk_content_file =
+        read_and_write_ramdisk(hdr.vendor_ramdisk_size, ramdisk_offset_base);
+    if (!vendor_ramdisk_content_file.ok())
+      return vendor_ramdisk_content_file.error();
+    vendor_ramdisk_content_files.emplace_back(
+        std::move(*vendor_ramdisk_content_file));
+  }
+  return vendor_ramdisk_content_files;
 }
 
 }  // namespace
@@ -122,21 +166,26 @@ android::base::Result<std::unique_ptr<TemporaryDir>> ExtractRamdiskToDirectory(
   return android::CpioExtract(decompressed.path);
 }
 
-// From the vendor_boot image / partition, extract the vendor_ramdisk section,
-//  decompress it, and extract from the cpio archive.
-android::base::Result<std::unique_ptr<TemporaryDir>>
-ExtractVendorRamdiskToDirectory(const std::string &vendor_boot_path) {
-  const auto vendor_raw_ramdisk_file =
-      ExtractVendorRamdiskRaw(vendor_boot_path);
-  if (!vendor_raw_ramdisk_file.ok()) return vendor_raw_ramdisk_file.error();
-
-  TemporaryFile decompressed;
-  // TODO: b/374932907 -- Verify if this assumption is correct,
-  //   if not add logic to support Gzip, or uncompressed ramdisks.
-  auto decompress_res = android::Lz4DecompressLegacy(
-      (*vendor_raw_ramdisk_file)->path, decompressed.path);
-  if (!decompress_res.ok()) return decompress_res.error();
-
-  return android::CpioExtract(decompressed.path);
+// From the vendor_boot image / partition, extract all vendor_ramdisk
+// sections, decompress all ramdisks, and extract from the cpio archives.
+android::base::Result<std::vector<std::unique_ptr<TemporaryDir>>>
+ExtractVendorRamdisks(const std::string &vendor_boot_path) {
+  const auto vendor_raw_ramdisk_files =
+      ExtractVendorRamdisksRaw(vendor_boot_path);
+  if (!vendor_raw_ramdisk_files.ok()) return vendor_raw_ramdisk_files.error();
+
+  std::vector<std::unique_ptr<TemporaryDir>> extracted_ramdisks;
+  for (const auto &vendor_raw_ramdisk_file : *vendor_raw_ramdisk_files) {
+    TemporaryFile decompressed;
+    // TODO: b/374932907 -- Verify if this assumption is correct,
+    //   if not add logic to support Gzip, or uncompressed ramdisks.
+    auto decompress_res = android::Lz4DecompressLegacy(
+        vendor_raw_ramdisk_file->path, decompressed.path);
+    if (!decompress_res.ok()) return decompress_res.error();
+    auto cpio_extract_res = android::CpioExtract(decompressed.path);
+    if (!cpio_extract_res.ok()) return decompress_res.error();
+    extracted_ramdisks.emplace_back(std::move(*cpio_extract_res));
+  }
+  return extracted_ramdisks;
 }
 }  // namespace android
diff --git a/gki/ramdisk_utils.h b/gki/ramdisk_utils.h
index 3d26574..5354532 100644
--- a/gki/ramdisk_utils.h
+++ b/gki/ramdisk_utils.h
@@ -28,9 +28,9 @@ namespace android {
 android::base::Result<std::unique_ptr<TemporaryDir>> ExtractRamdiskToDirectory(
     std::string_view boot_path);
 
-// From the vendor_boot image / partition, extract the vendor_ramdisk section,
-//  decompress it, and extract from the cpio archive.
-android::base::Result<std::unique_ptr<TemporaryDir>>
-ExtractVendorRamdiskToDirectory(const std::string &vendor_boot_path);
+// From the vendor_boot image / partition, extract all vendor_ramdisk
+// sections, decompress all ramdisks, and extract from the cpio archives.
+android::base::Result<std::vector<std::unique_ptr<TemporaryDir>>>
+ExtractVendorRamdisks(const std::string &vendor_boot_path);
 
 }  // namespace android
diff --git a/ltp/OWNERS b/ltp/OWNERS
index 6ef51ba..902849d 100644
--- a/ltp/OWNERS
+++ b/ltp/OWNERS
@@ -1,5 +1,3 @@
 # Bug component: 391836
-edliaw@google.com
 bettyzhou@google.com
-vmartensson@google.com
 balsini@google.com
diff --git a/ltp/testcase/OWNERS b/ltp/testcase/OWNERS
index 4088918..b9c310d 100644
--- a/ltp/testcase/OWNERS
+++ b/ltp/testcase/OWNERS
@@ -1,4 +1,2 @@
 # Bug component: 391836
-vmartensson@google.com
-balsini@google.com
-edliaw@google.com
+balsini@google.com
\ No newline at end of file
diff --git a/ltp/testcase/tools/template/template.xml b/ltp/testcase/tools/template/template.xml
index f59b99e..9fd3555 100644
--- a/ltp/testcase/tools/template/template.xml
+++ b/ltp/testcase/tools/template/template.xml
@@ -12,7 +12,7 @@
 -->
 <!DOCTYPE configuration [
 <!ENTITY ltp_dir "/data/local/tmp/{MODULE}">
-<!ENTITY ltp_env "export LTPROOT=/data/local/tmp/{MODULE}/{target} LTP_DEV_FS_TYPE=ext4; export PATH=/system/bin:$LTPROOT TMP=$LTPROOT/tmp; export TMPBASE=$TMP/tmpbase LTPTMP=$TMP/ltptemp TMPDIR=$TMP/tmpdir">
+<!ENTITY ltp_env "export LTPROOT=/data/local/tmp/{MODULE}/{target} LTP_DEV_FS_TYPE=ext4; export PATH=/system/bin:$LTPROOT TMP=$LTPROOT/tmp; export TMPBASE=$TMP/tmpbase LTPTMP=$TMP/ltptemp TMPDIR=$TMP/tmpdir; export LTP_TIMEOUT_MUL=2">
 ]>
 <configuration description="Runs vts_ltp_test.">
     <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
```

