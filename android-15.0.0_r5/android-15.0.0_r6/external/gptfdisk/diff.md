```diff
diff --git a/diskio-heap.cc b/diskio-heap.cc
index 3129113..72ea8fa 100644
--- a/diskio-heap.cc
+++ b/diskio-heap.cc
@@ -11,7 +11,9 @@
  * GNU General Public License for more details.
  */
 
-#include <algorithm>
+#include <fcntl.h>
+#include <sys/stat.h>
+#include <unistd.h>
 
 #include "diskio.h"
 
@@ -26,19 +28,54 @@ int DiskIO::OpenForRead(const unsigned char* data, size_t size) {
     return 1;
 }
 
-void DiskIO::MakeRealName(void) {
-    realFilename = userFilename;
-}
+void DiskIO::MakeRealName(void) { this->realFilename = this->userFilename; }
 
 int DiskIO::OpenForRead(void) {
-    return 1;
+  struct stat64 st;
+
+  if (this->isOpen) {
+    if (this->openForWrite) {
+      Close();
+    } else {
+      return 1;
+    }
+  }
+
+  this->fd = open(realFilename.c_str(), O_RDONLY | O_CREAT, S_IRUSR | S_IRGRP | S_IROTH);
+  if (this->fd == -1) {
+    this->realFilename = this->userFilename = "";
+  } else {
+    if (fstat64(fd, &st) == 0) {
+      if (!(S_ISDIR(st.st_mode) || S_ISFIFO(st.st_mode) ||
+            S_ISSOCK(st.st_mode))) {
+        this->isOpen = 1;
+      }
+    }
+  }
+  return this->isOpen;
 }
 
 int DiskIO::OpenForWrite(void) {
+  if ((this->isOpen) && (this->openForWrite)) {
     return 1;
+  }
+
+  Close();
+  this->fd = open(realFilename.c_str(), O_WRONLY | O_CREAT,
+                  S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
+  if (fd >= 0) {
+    this->isOpen = 1;
+    this->openForWrite = 1;
+  }
+  return this->isOpen;
 }
 
 void DiskIO::Close(void) {
+  if (this->isOpen) {
+    close(this->fd);
+  }
+  this->isOpen = 0;
+  this->openForWrite = 0;
 }
 
 int DiskIO::GetBlockSize(void) {
@@ -62,23 +99,73 @@ int DiskIO::DiskSync(void) {
 }
 
 int DiskIO::Seek(uint64_t sector) {
-    off_t off = sector * GetBlockSize();
-    if (off >= this->size) {
-        return 0;
-    } else {
-        this->off = off;
-        return 1;
+  int retval = 1;
+  off_t seekTo = sector * static_cast<uint64_t>(GetBlockSize());
+
+  if (!isOpen) {
+    if (OpenForRead() != 1) {
+      retval = 0;
+    }
+  }
+
+  if (isOpen && seekTo < this->size) {
+    off_t sought = lseek64(fd, seekTo, SEEK_SET);
+    if (sought != seekTo) {
+      retval = 0;
     }
+  }
+
+  if (retval) {
+    this->off = seekTo;
+  }
+
+  return retval;
 }
 
 int DiskIO::Read(void* buffer, int numBytes) {
-    int actualBytes = std::min(static_cast<int>(this->size - this->off), numBytes);
+  int actualBytes = 0;
+  if (this->size > this->off) {
+    actualBytes = std::min(static_cast<int>(this->size - this->off), numBytes);
     memcpy(buffer, this->data + this->off, actualBytes);
+  }
     return actualBytes;
 }
 
-int DiskIO::Write(void*, int) {
-    return 0;
+int DiskIO::Write(void *buffer, int numBytes) {
+  int blockSize, i, numBlocks, retval = 0;
+  char *tempSpace;
+
+  if ((!this->isOpen) || (!this->openForWrite)) {
+    OpenForWrite();
+  }
+
+  if (this->isOpen) {
+    blockSize = GetBlockSize();
+    if (numBytes <= blockSize) {
+      numBlocks = 1;
+      tempSpace = new char[blockSize];
+    } else {
+      numBlocks = numBytes / blockSize;
+      if ((numBytes % blockSize) != 0)
+        numBlocks++;
+      tempSpace = new char[numBlocks * blockSize];
+    }
+    if (tempSpace == NULL) {
+      return 0;
+    }
+
+    memcpy(tempSpace, buffer, numBytes);
+    for (i = numBytes; i < numBlocks * blockSize; i++) {
+      tempSpace[i] = 0;
+    }
+    retval = write(fd, tempSpace, numBlocks * blockSize);
+
+    if (((numBlocks * blockSize) != numBytes) && (retval > 0))
+      retval = numBytes;
+
+    delete[] tempSpace;
+  }
+  return retval;
 }
 
 uint64_t DiskIO::DiskSize(int *) {
diff --git a/fuzzer/Android.bp b/fuzzer/Android.bp
index 5f4a18b..bdeb9c0 100644
--- a/fuzzer/Android.bp
+++ b/fuzzer/Android.bp
@@ -5,11 +5,11 @@ package {
     // to get the below license kinds:
     //   SPDX-license-identifier-GPL-2.0
     default_applicable_licenses: ["external_gptfdisk_license"],
+    default_team: "trendy_team_android_kernel",
 }
 
-cc_fuzz {
-    name: "libgptf_fuzzer",
-    srcs: ["libgptf_fuzzer.cc"],
+cc_defaults {
+    name: "libgptf_fuzz_defaults",
     cflags: ["-DENABLE_HEAP_DISKIO"],
     host_supported: true,
     corpus: ["corpus/*"],
@@ -29,3 +29,15 @@ cc_fuzz {
         },
     },
 }
+
+cc_fuzz {
+    name: "libgptf_fuzzer",
+    srcs: ["libgptf_fuzzer.cc"],
+    defaults: ["libgptf_fuzz_defaults"],
+}
+
+cc_fuzz {
+    name: "basicmbr_fuzzer",
+    srcs: ["basicmbr_fuzzer.cc"],
+    defaults: ["libgptf_fuzz_defaults"],
+}
diff --git a/fuzzer/basicmbr_fuzzer.cc b/fuzzer/basicmbr_fuzzer.cc
new file mode 100644
index 0000000..6341f02
--- /dev/null
+++ b/fuzzer/basicmbr_fuzzer.cc
@@ -0,0 +1,102 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * This software is licensed under the terms of the GNU General Public
+ * License version 2, as published by the Free Software Foundation, and
+ * may be copied, distributed, and modified under those terms.
+ *
+ * This program is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
+ * GNU General Public License for more details.
+ */
+
+#include <fstream>
+#include <iostream>
+#include <functional>
+#include "diskio.h"
+#include "mbr.h"
+
+#include <fuzzer/FuzzedDataProvider.h>
+
+const std::string kTempFile = "/dev/tempfile";
+const std::string kNull = "/dev/null";
+
+std::ofstream silence(kNull);
+
+class BasicMBRFuzzer {
+public:
+  BasicMBRFuzzer(const uint8_t *data, size_t size) : mFdp(data, size) {
+    mDisk.OpenForRead(static_cast<const unsigned char *>(data), size);
+  }
+
+  ~BasicMBRFuzzer() { mDisk.Close(); }
+
+  void process();
+
+private:
+  DiskIO mDisk;
+  FuzzedDataProvider mFdp;
+};
+
+void BasicMBRFuzzer::process() {
+  BasicMBRData mbrData;
+  if (mFdp.ConsumeBool()) {
+    BasicMBRData mbrDataFile(kTempFile);
+    mbrData = mbrDataFile;
+  }
+
+  bool isLegal = false;
+
+  while (mFdp.remaining_bytes()) {
+    auto invokeMBRAPI = mFdp.PickValueInArray<const std::function<void()>>({
+        [&]() {
+          mbrData.SetDisk(&mDisk);
+        },
+        [&]() {
+          if (mDisk.OpenForWrite(kTempFile)) {
+            mbrData.WriteMBRData(kTempFile);
+          }
+          mbrData.ReadMBRData(&mDisk);
+        },
+        [&]() {
+          uint32_t low, high;
+          mbrData.GetPartRange(&low, &high);
+        },
+        [&]() {
+          mbrData.MakeBiggestPart(mFdp.ConsumeIntegral<uint8_t>() /* index */,
+                                  mFdp.ConsumeIntegral<uint8_t>() /* type */);
+        },
+        [&]() {
+          mbrData.SetPartType(mFdp.ConsumeIntegral<uint8_t>() /* num */,
+                              mFdp.ConsumeIntegral<uint8_t>() /* type */);
+        },
+        [&]() {
+          mbrData.FindFirstInFree(mFdp.ConsumeIntegral<uint64_t>() /* start */);
+        },
+        [&]() {
+          mbrData.GetFirstSector(mFdp.ConsumeIntegral<uint8_t>() /* index */);
+        },
+        [&]() {
+          if (!isLegal) {
+            mbrData.MakeItLegal();
+            isLegal = true;
+          }
+        },
+    });
+    invokeMBRAPI();
+  }
+  mbrData.BlankGPTData();
+}
+
+extern "C" int LLVMFuzzerInitialize(int *, char ***) {
+  std::cout.rdbuf(silence.rdbuf());
+  std::cerr.rdbuf(silence.rdbuf());
+  return 0;
+}
+
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
+  BasicMBRFuzzer basicMBRFuzzer(data, size);
+  basicMBRFuzzer.process();
+  return 0;
+}
diff --git a/fuzzer/libgptf_fuzzer.cc b/fuzzer/libgptf_fuzzer.cc
index 688167a..be7f101 100644
--- a/fuzzer/libgptf_fuzzer.cc
+++ b/fuzzer/libgptf_fuzzer.cc
@@ -13,31 +13,161 @@
 
 #include <fstream>
 #include <iostream>
-
+#include <functional>
 #include "diskio.h"
-#include "mbr.h"
 #include "gpt.h"
+#include "parttypes.h"
 
 #include <fuzzer/FuzzedDataProvider.h>
 
-std::ofstream silence("/dev/null");
+const int8_t kQuiet = 1;
+const int8_t kMinRuns = 1;
+const int8_t kGPTMaxRuns = 24;
+const int16_t kMaxByte = 256;
+const std::string kShowCommand = "show";
+const std::string kGetCommand = "get";
+const std::string kTempFile = "/dev/tempfile";
+const std::string kNull = "/dev/null";
+const std::string kBackup = "/dev/gptbackup";
+const std::string kDoesNotExist = "/dev/does_not_exist";
 
-extern "C" int LLVMFuzzerInitialize(int *, char ***) {
-    std::cout.rdbuf(silence.rdbuf());
-    std::cerr.rdbuf(silence.rdbuf());
-    return 0;
+std::ofstream silence(kNull);
+
+class GptfFuzzer {
+public:
+  GptfFuzzer(const uint8_t *data, size_t size) : mFdp(data, size) {
+    mDisk.OpenForRead(static_cast<const unsigned char *>(data), size);
+  }
+
+  ~GptfFuzzer() { mDisk.Close(); }
+
+  void process();
+
+private:
+  void init();
+  FuzzedDataProvider mFdp;
+  DiskIO mDisk;
+  GPTData mGptData;
+};
+
+void GptfFuzzer::init() {
+  if (mFdp.ConsumeBool()) {
+    mGptData.SetDisk(mDisk);
+  } else {
+    mGptData.SetDisk(kTempFile);
+  }
+
+  uint64_t startSector = mFdp.ConsumeIntegral<uint64_t>();
+  uint64_t endSector =
+      mFdp.ConsumeIntegralInRange<uint64_t>(startSector, UINT64_MAX);
+  mGptData.CreatePartition(mFdp.ConsumeIntegral<uint8_t>() /* partNum */,
+                           startSector, endSector);
+
+  const UnicodeString name = mFdp.ConsumeRandomLengthString(NAME_SIZE);
+  uint8_t partNum = mFdp.ConsumeIntegral<uint8_t>();
+  if (mGptData.SetName(partNum, name)) {
+    PartType pType;
+    mGptData.ChangePartType(partNum, pType);
+  }
+
+  if (mFdp.ConsumeBool()) {
+    mGptData.SetAlignment(mFdp.ConsumeIntegral<uint32_t>() /* n */);
+  }
+
+  if (mFdp.ConsumeBool()) {
+    GUIDData gData(mFdp.ConsumeRandomLengthString(kMaxByte));
+    gData.Randomize();
+    mGptData.SetDiskGUID(gData);
+    mGptData.SaveGPTBackup(kBackup);
+    mGptData.SetPartitionGUID(mFdp.ConsumeIntegral<uint8_t>() /* pn */, gData);
+  }
+
+  if (mFdp.ConsumeBool()) {
+    mGptData.RandomizeGUIDs();
+  }
+
+  if (mFdp.ConsumeBool()) {
+    mGptData.LoadGPTBackup(kBackup);
+  }
+
+  if (mFdp.ConsumeBool()) {
+    mGptData.SaveGPTData(kQuiet);
+  }
+
+  if (mFdp.ConsumeBool()) {
+    mGptData.SaveMBR();
+  }
 }
 
-extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
-    DiskIO disk;
-    disk.OpenForRead(static_cast<const unsigned char*>(data), size);
+void GptfFuzzer::process() {
+  init();
+  int8_t runs = mFdp.ConsumeIntegralInRange<int32_t>(kMinRuns, kGPTMaxRuns);
 
-    BasicMBRData mbrData;
-    mbrData.ReadMBRData(&disk);
+  while (--runs && mFdp.remaining_bytes()) {
+    auto invokeGPTAPI = mFdp.PickValueInArray<const std::function<void()>>({
+        [&]() {
+          mGptData.XFormDisklabel(
+              mFdp.ConsumeIntegral<uint8_t>() /* partNum */);
+        },
+        [&]() {
+          mGptData.OnePartToMBR(mFdp.ConsumeIntegral<uint8_t>() /* gptPart */,
+                                mFdp.ConsumeIntegral<uint8_t>() /* mbrPart */);
+        },
+        [&]() {
+          uint32_t numSegments;
+          uint64_t largestSegment;
+          mGptData.FindFreeBlocks(&numSegments, &largestSegment);
+        },
+        [&]() {
+          mGptData.FindFirstInLargest();
+        },
+        [&]() {
+          mGptData.FindLastAvailable();
+        },
+        [&]() {
+          mGptData.FindFirstFreePart();
+        },
+        [&]() {
+          mGptData.MoveMainTable(
+              mFdp.ConsumeIntegral<uint64_t>() /* pteSector */);
+        },
+        [&]() {
+          mGptData.Verify();
+        },
+        [&]() {
+          mGptData.SortGPT();
+        },
+        [&]() {
+          std::string command = mFdp.ConsumeBool() ? kShowCommand : kGetCommand;
+          std::string randomCommand = mFdp.ConsumeRandomLengthString(kMaxByte);
+          mGptData.ManageAttributes(
+              mFdp.ConsumeIntegral<uint8_t>() /* partNum */,
+              mFdp.ConsumeBool() ? command : randomCommand,
+              mFdp.ConsumeRandomLengthString(kMaxByte) /* bits */);
+        },
+    });
+    invokeGPTAPI();
+  }
+  if (mFdp.ConsumeBool()) {
+    mGptData.LoadPartitions(kDoesNotExist);
+  }
+  if (mFdp.ConsumeBool()) {
+    mGptData.SwapPartitions(mFdp.ConsumeIntegral<uint8_t>() /* partNum1 */,
+                            mFdp.ConsumeIntegral<uint8_t>() /* partNum2 */);
+  }
+  mGptData.DeletePartition(mFdp.ConsumeIntegral<uint8_t>() /* partNum */);
+  mGptData.DestroyMBR();
+  mGptData.DestroyGPT();
+}
 
-    GPTData gptData;
-    gptData.SetDisk(disk);
-    gptData.LoadPartitions("/dev/does_not_exist");
+extern "C" int LLVMFuzzerInitialize(int *, char ***) {
+  std::cout.rdbuf(silence.rdbuf());
+  std::cerr.rdbuf(silence.rdbuf());
+  return 0;
+}
 
-    return 0;
+extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
+  GptfFuzzer gptfFuzzer(data, size);
+  gptfFuzzer.process();
+  return 0;
 }
```

