```diff
diff --git a/libunwindstack/Android.bp b/libunwindstack/Android.bp
index 1568a4e..59a854e 100644
--- a/libunwindstack/Android.bp
+++ b/libunwindstack/Android.bp
@@ -233,12 +233,26 @@ cc_library {
 }
 
 // Make sure that the code can be compiled without Android Logging.
-cc_library {
+cc_library_static {
     name: "libunwindstack_stdout_log",
     defaults: ["libunwindstack_defaults"],
     srcs: [
         "LogStdout.cpp",
     ],
+    target: {
+        android: {
+            srcs: [
+                "AndroidLogStdout.cpp",
+                "DexFile.cpp",
+            ],
+            cflags: ["-DDEXFILE_SUPPORT"],
+            whole_static_libs: ["libdexfile_support"],
+        },
+    },
+    whole_static_libs: [
+        "liblzma",
+        "libz",
+    ],
 }
 
 // Static library without DEX support to avoid dependencies on the ART APEX.
@@ -509,6 +523,8 @@ cc_defaults {
     shared_libs: [
         "libbase",
         "liblzma",
+    ],
+    static_libs: [
         "libunwindstack_stdout_log",
     ],
     target: {
diff --git a/libunwindstack/AndroidLogStdout.cpp b/libunwindstack/AndroidLogStdout.cpp
new file mode 100644
index 0000000..5a40fc8
--- /dev/null
+++ b/libunwindstack/AndroidLogStdout.cpp
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+#include <stdarg.h>
+#include <stdio.h>
+#include <stdlib.h>
+
+// This file contains only the log functions necessary to compile the unwinder
+// tools using libdexfile for android targets.
+
+extern "C" void __android_log_assert(const char* cond, const char*, const char* fmt, ...) {
+  if (fmt) {
+    va_list ap;
+    va_start(ap, fmt);
+    vprintf(fmt, ap);
+    va_end(ap);
+    printf("\n");
+  } else {
+    if (cond) {
+      printf("Assertion failed: %s\n", cond);
+    } else {
+      printf("Unspecified assertion failed.\n");
+    }
+  }
+  abort();
+}
diff --git a/libunwindstack/Demangle.cpp b/libunwindstack/Demangle.cpp
index 8d0bfd6..29b58b4 100644
--- a/libunwindstack/Demangle.cpp
+++ b/libunwindstack/Demangle.cpp
@@ -25,18 +25,18 @@
 
 namespace unwindstack {
 
-std::string DemangleNameIfNeeded(const std::string& name) {
-  if (name.length() < 2 || name[0] != '_') {
+static std::string Demangle(const char* name, size_t length) {
+  if (length < 2 || name[0] != '_') {
     return name;
   }
 
   char* demangled_str = nullptr;
   if (name[1] == 'Z') {
     // Try to demangle C++ name.
-    demangled_str = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, nullptr);
+    demangled_str = abi::__cxa_demangle(name, nullptr, nullptr, nullptr);
   } else if (name[1] == 'R') {
     // Try to demangle rust name.
-    demangled_str = rustc_demangle(name.c_str(), nullptr, nullptr, nullptr);
+    demangled_str = rustc_demangle(name, nullptr, nullptr, nullptr);
   }
 
   if (demangled_str == nullptr) {
@@ -48,4 +48,15 @@ std::string DemangleNameIfNeeded(const std::string& name) {
   return demangled_name;
 }
 
+std::string DemangleNameIfNeeded(const std::string& name) {
+  // This is special, the Android linker has functions of the form __dl_XXX,
+  // where the XX might be a mangled name. Try to demangle that part and
+  // add the __dl_ back.
+  if (name.starts_with("__dl_")) {
+    return "__dl_" + Demangle(&name[5], name.length() - 5);
+  }
+
+  return Demangle(name.c_str(), name.length());
+}
+
 }  // namespace unwindstack
diff --git a/libunwindstack/DwarfEhFrameWithHdr.cpp b/libunwindstack/DwarfEhFrameWithHdr.cpp
index 8e4bfee..31ce172 100644
--- a/libunwindstack/DwarfEhFrameWithHdr.cpp
+++ b/libunwindstack/DwarfEhFrameWithHdr.cpp
@@ -139,7 +139,7 @@ const typename DwarfEhFrameWithHdr<AddressType>::FdeInfo*
 DwarfEhFrameWithHdr<AddressType>::GetFdeInfoFromIndex(size_t index) {
   auto entry = fde_info_.find(index);
   if (entry != fde_info_.end()) {
-    return &fde_info_[index];
+    return &entry->second;
   }
   FdeInfo* info = &fde_info_[index];
 
diff --git a/libunwindstack/DwarfSection.cpp b/libunwindstack/DwarfSection.cpp
index 728390c..99cfadc 100644
--- a/libunwindstack/DwarfSection.cpp
+++ b/libunwindstack/DwarfSection.cpp
@@ -600,9 +600,12 @@ bool DwarfSectionImpl<AddressType>::GetCfaLocationInfo(uint64_t pc, const DwarfF
       last_error_ = cfa.last_error();
       return false;
     }
-    cie_loc_regs_[fde->cie_offset] = *loc_regs;
+    DwarfLocations* cie_loc_regs = &cie_loc_regs_[fde->cie_offset];
+    *cie_loc_regs = *loc_regs;
+    cfa.set_cie_loc_regs(cie_loc_regs);
+  } else {
+    cfa.set_cie_loc_regs(&reg_entry->second);
   }
-  cfa.set_cie_loc_regs(&cie_loc_regs_[fde->cie_offset]);
   if (!cfa.GetLocationInfo(pc, fde->cfa_instructions_offset, fde->cfa_instructions_end, loc_regs)) {
     last_error_ = cfa.last_error();
     return false;
@@ -706,8 +709,7 @@ bool DwarfSectionImpl<AddressType>::GetNextCieOrFde(uint64_t& next_entries_offse
   }
 
   if (entry_is_cie) {
-    auto entry = cie_entries_.find(start_offset);
-    if (entry == cie_entries_.end()) {
+    if (!cie_entries_.contains(start_offset)) {
       DwarfCie* cie = &cie_entries_[start_offset];
       cie->lsda_encoding = DW_EH_PE_omit;
       cie->cfa_instructions_end = next_entries_offset;
diff --git a/libunwindstack/Global.cpp b/libunwindstack/Global.cpp
index 0183bd3..0463832 100644
--- a/libunwindstack/Global.cpp
+++ b/libunwindstack/Global.cpp
@@ -77,8 +77,17 @@ void Global::FindAndReadVariable(Maps* maps, const char* var_str) {
   //   f1000-f2000 0 ---
   //   f2000-f3000 1000 r-x /system/lib/libc.so
   //   f3000-f4000 2000 rw- /system/lib/libc.so
+  // It is also possible to see page size compat maps after the read-only like so:
+  //   f0000-f1000 0 r-- /system/lib/libc.so
+  //   f1000-f2000 0 --- [page size compat]
+  //   f2000-f3000 1000 r-x /system/lib/libc.so
+  //   f3000-f4000 2000 rw- /system/lib/libc.so
+  // [page size compat] was introduced in the Android kernel in commit:
+  // https://android-review.googlesource.com/c/kernel/common/+/3052547
+  // This will be needed in Android kernels as long as 4kB-page-sized
+  // devices are supported.
   MapInfo* map_zero = nullptr;
-  for (const auto& info : *maps) {
+  maps->ForEachMapInfo([&map_zero, &variable, this](MapInfo* info) -> bool {
     if ((info->flags() & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE) &&
         map_zero != nullptr && Searchable(info->name()) && info->name() == map_zero->name()) {
       Elf* elf = map_zero->GetElf(memory_, arch());
@@ -88,14 +97,15 @@ void Global::FindAndReadVariable(Maps* maps, const char* var_str) {
         if (ptr >= info->offset() && ptr < offset_end) {
           ptr = info->start() + ptr - info->offset();
           if (ReadVariableData(ptr)) {
-            break;
+            return false;
           }
         }
       }
-    } else if (info->offset() == 0 && !info->name().empty()) {
-      map_zero = info.get();
+    } else if (info->offset() == 0 && !info->IsBlank()) {
+      map_zero = info;
     }
-  }
+    return true;
+  });
 }
 
 }  // namespace unwindstack
diff --git a/libunwindstack/GlobalDebugImpl.h b/libunwindstack/GlobalDebugImpl.h
index a4d13ac..7cbfa95 100644
--- a/libunwindstack/GlobalDebugImpl.h
+++ b/libunwindstack/GlobalDebugImpl.h
@@ -241,7 +241,7 @@ class GlobalDebugImpl : public GlobalDebugInterface<Symfile>, public Global {
     // Follow the linked list.
     while (uid.address != 0) {
       // Check if we have reached an already cached entry (we restart from head repeatedly).
-      if (entries->count(uid) != 0) {
+      if (entries->contains(uid)) {
         return true;
       }
 
diff --git a/libunwindstack/Maps.cpp b/libunwindstack/Maps.cpp
index 36f9d4c..a467a8b 100644
--- a/libunwindstack/Maps.cpp
+++ b/libunwindstack/Maps.cpp
@@ -167,6 +167,14 @@ bool LocalUpdatableMaps::Parse() {
   return parsed;
 }
 
+void LocalUpdatableMaps::ForEachMapInfo(std::function<bool(MapInfo*)> const& find_var) {
+  pthread_rwlock_rdlock(&maps_rwlock_);
+  for (const auto& info : maps_) {
+    if (!find_var(info.get())) break;
+  }
+  pthread_rwlock_unlock(&maps_rwlock_);
+}
+
 bool LocalUpdatableMaps::Reparse(/*out*/ bool* any_changed) {
   // New maps will be added at the end without deleting the old ones.
   size_t last_map_idx = maps_.size();
diff --git a/libunwindstack/Memory.cpp b/libunwindstack/Memory.cpp
index 0594a7a..6912f1e 100644
--- a/libunwindstack/Memory.cpp
+++ b/libunwindstack/Memory.cpp
@@ -267,6 +267,7 @@ void MemoryFileAtOffset::Clear() {
   if (data_) {
     munmap(&data_[-offset_], size_ + offset_);
     data_ = nullptr;
+    size_ = 0;
   }
 }
 
diff --git a/libunwindstack/include/unwindstack/MapInfo.h b/libunwindstack/include/unwindstack/MapInfo.h
index 9f025ff..3881f73 100644
--- a/libunwindstack/include/unwindstack/MapInfo.h
+++ b/libunwindstack/include/unwindstack/MapInfo.h
@@ -203,7 +203,11 @@ class MapInfo {
   // Returns the printable version of the build id (hex dump of raw data).
   std::string GetPrintableBuildID();
 
-  inline bool IsBlank() { return offset() == 0 && flags() == 0 && name().empty(); }
+  // A blank map can have no name, or be a kernel named map [page size compat]
+  // that should be skipped.
+  inline bool IsBlank() {
+    return offset() == 0 && flags() == 0 && (name().empty() || name() == "[page size compat]");
+  }
 
   // Returns elf_fields_. It will create the object if it is null.
   ElfFields& GetElfFields();
diff --git a/libunwindstack/include/unwindstack/Maps.h b/libunwindstack/include/unwindstack/Maps.h
index d9e1383..a90dc0d 100644
--- a/libunwindstack/include/unwindstack/Maps.h
+++ b/libunwindstack/include/unwindstack/Maps.h
@@ -55,6 +55,12 @@ class Maps {
 
   virtual const std::string GetMapsFile() const { return ""; }
 
+  virtual void ForEachMapInfo(std::function<bool(MapInfo*)> const& find_var) {
+    for (const auto& info : maps_) {
+      if (!find_var(info.get())) break;
+    }
+  }
+
   void Add(uint64_t start, uint64_t end, uint64_t offset, uint64_t flags, const std::string& name);
   void Add(uint64_t start, uint64_t end, uint64_t offset, uint64_t flags, const std::string& name,
            uint64_t load_bias);
@@ -108,6 +114,8 @@ class LocalUpdatableMaps : public Maps {
 
   const std::string GetMapsFile() const override;
 
+  virtual void ForEachMapInfo(std::function<bool(MapInfo*)> const& find_var) override;
+
   bool Reparse(/*out*/ bool* any_changed = nullptr);
 
  private:
diff --git a/libunwindstack/offline_files/load_bias_different_section_bias_arm64/output.txt b/libunwindstack/offline_files/load_bias_different_section_bias_arm64/output.txt
index d34c97e..71be4b6 100644
--- a/libunwindstack/offline_files/load_bias_different_section_bias_arm64/output.txt
+++ b/libunwindstack/offline_files/load_bias_different_section_bias_arm64/output.txt
@@ -1,5 +1,5 @@
   #00 pc 00000000000d59bc  linker64 (__dl_syscall+28)
-  #01 pc 00000000000554e8  linker64 (__dl__ZL24debuggerd_signal_handleriP7siginfoPv+1148)
+  #01 pc 00000000000554e8  linker64 (__dl_debuggerd_signal_handler(int, siginfo*, void*)+1148)
   #02 pc 00000000000008c0  vdso (__kernel_rt_sigreturn)
   #03 pc 000000000007f3e8  libc.so (abort+168)
   #04 pc 00000000000459fc  test (std::__ndk1::__throw_bad_cast()+4)
diff --git a/libunwindstack/offline_files/shared_lib_in_apk_arm64/output.txt b/libunwindstack/offline_files/shared_lib_in_apk_arm64/output.txt
index d7bbf39..203adf3 100644
--- a/libunwindstack/offline_files/shared_lib_in_apk_arm64/output.txt
+++ b/libunwindstack/offline_files/shared_lib_in_apk_arm64/output.txt
@@ -1,5 +1,5 @@
   #00 pc 000000000014ccbc  linker64 (__dl_syscall+28)
-  #01 pc 000000000005426c  linker64 (__dl__ZL24debuggerd_signal_handleriP7siginfoPv+1128)
+  #01 pc 000000000005426c  linker64 (__dl_debuggerd_signal_handler(int, siginfo*, void*)+1128)
   #02 pc 00000000000008c0  vdso.so (__kernel_rt_sigreturn)
   #03 pc 00000000000846f4  libc.so (abort+172)
   #04 pc 0000000000084ad4  libc.so (__assert2+36)
diff --git a/libunwindstack/offline_files/shared_lib_in_apk_memory_only_arm64/output.txt b/libunwindstack/offline_files/shared_lib_in_apk_memory_only_arm64/output.txt
index c733893..80cef47 100644
--- a/libunwindstack/offline_files/shared_lib_in_apk_memory_only_arm64/output.txt
+++ b/libunwindstack/offline_files/shared_lib_in_apk_memory_only_arm64/output.txt
@@ -1,5 +1,5 @@
   #00 pc 000000000014ccbc  linker64 (__dl_syscall+28)
-  #01 pc 000000000005426c  linker64 (__dl__ZL24debuggerd_signal_handleriP7siginfoPv+1128)
+  #01 pc 000000000005426c  linker64 (__dl_debuggerd_signal_handler(int, siginfo*, void*)+1128)
   #02 pc 00000000000008c0  vdso.so (__kernel_rt_sigreturn)
   #03 pc 00000000000846f4  libc.so (abort+172)
   #04 pc 0000000000084ad4  libc.so (__assert2+36)
diff --git a/libunwindstack/offline_files/zlib_compress_arm/output.txt b/libunwindstack/offline_files/zlib_compress_arm/output.txt
index 38eaa7c..6530719 100644
--- a/libunwindstack/offline_files/zlib_compress_arm/output.txt
+++ b/libunwindstack/offline_files/zlib_compress_arm/output.txt
@@ -1,5 +1,5 @@
   #00 pc 000c1324  linker (__dl_syscall+28)
-  #01 pc 000361f5  linker (__dl__ZL24debuggerd_signal_handleriP7siginfoPv+1048)
+  #01 pc 000361f5  linker (__dl_debuggerd_signal_handler(int, siginfo*, void*)+1048)
   #02 pc 000c6c40  linker (__dl___restore_rt)
   #03 pc 0003ceae  libc.so (abort+134)
   #04 pc 00003f4f  crasher (maybe_abort+42)
diff --git a/libunwindstack/offline_files/zstd_compress_arm/output.txt b/libunwindstack/offline_files/zstd_compress_arm/output.txt
index efccfc2..d2416c5 100644
--- a/libunwindstack/offline_files/zstd_compress_arm/output.txt
+++ b/libunwindstack/offline_files/zstd_compress_arm/output.txt
@@ -1,5 +1,5 @@
   #00 pc 000c1324  linker (__dl_syscall+28)
-  #01 pc 000361e3  linker (__dl__ZL24debuggerd_signal_handleriP7siginfoPv+1030)
+  #01 pc 000361e3  linker (__dl_debuggerd_signal_handler(int, siginfo*, void*)+1030)
   #02 pc 000c6c40  linker (__dl___restore_rt)
   #03 pc 0003ceae  libc.so (abort+134)
   #04 pc 00003f4f  crasher (maybe_abort+42)
diff --git a/libunwindstack/tests/DemangleTest.cpp b/libunwindstack/tests/DemangleTest.cpp
index 3047b6e..45f120c 100644
--- a/libunwindstack/tests/DemangleTest.cpp
+++ b/libunwindstack/tests/DemangleTest.cpp
@@ -43,4 +43,13 @@ TEST(DemangleTest, rust_names) {
   EXPECT_EQ("profcollectd::main", DemangleNameIfNeeded("_RNvCs4VPobU5SDH_12profcollectd4main"));
 }
 
+TEST(DemangleTest, linker_names) {
+  EXPECT_EQ("__dl_", DemangleNameIfNeeded("__dl_"));
+  EXPECT_EQ("__dl_abort", DemangleNameIfNeeded("__dl_abort"));
+  EXPECT_EQ("__dl__Z", DemangleNameIfNeeded("__dl__Z"));
+  EXPECT_EQ("__dl__Z", DemangleNameIfNeeded("__dl__Z"));
+  EXPECT_EQ("__dl_fake(bool)", DemangleNameIfNeeded("__dl__Z4fakeb"));
+  EXPECT_EQ("__dl_demangle(int)", DemangleNameIfNeeded("__dl__Z8demanglei"));
+}
+
 }  // namespace unwindstack
diff --git a/libunwindstack/tests/DexFilesTest.cpp b/libunwindstack/tests/DexFilesTest.cpp
index 500f00d..1cad442 100644
--- a/libunwindstack/tests/DexFilesTest.cpp
+++ b/libunwindstack/tests/DexFilesTest.cpp
@@ -68,7 +68,10 @@ class DexFilesTest : public ::testing::Test {
                        "500000-501000 r--p 0000000 00:00 0 /fake/elf4\n"
                        "501000-502000 ---p 0000000 00:00 0\n"
                        "503000-510000 rw-p 0003000 00:00 0 /fake/elf4\n"
-                       "510000-520000 rw-p 0010000 00:00 0 /fake/elf4\n"));
+                       "510000-520000 rw-p 0010000 00:00 0 /fake/elf4\n"
+                       "600000-601000 r--p 0000000 00:00 0 /fake/elf5\n"
+                       "601000-602000 ---p 0000000 00:00 0 [page size compat]\n"
+                       "603000-610000 rw-p 0003000 00:00 0 /fake/elf5\n"));
     ASSERT_TRUE(maps_->Parse());
 
     // Global variable in a section that is not readable.
@@ -90,6 +93,11 @@ class DexFilesTest : public ::testing::Test {
     map_info = maps_->Get(kMapGlobalAfterEmpty).get();
     ASSERT_TRUE(map_info != nullptr);
     CreateFakeElf(map_info, 0x3800, 0x3000, 0x3000, 0xd000);
+
+    // Global variable set in this map, but there is a page size compat map before rw map.
+    map_info = maps_->Get(kMapGlobalAfterPageSizeCompat).get();
+    ASSERT_TRUE(map_info != nullptr);
+    CreateFakeElf(map_info, 0x3800, 0x3000, 0x3000, 0xd000);
   }
 
   void SetUp() override {
@@ -115,6 +123,7 @@ class DexFilesTest : public ::testing::Test {
   static constexpr size_t kMapDexFiles = 8;
   static constexpr size_t kMapGlobalAfterEmpty = 9;
   static constexpr size_t kMapDexFilesAfterEmpty = 12;
+  static constexpr size_t kMapGlobalAfterPageSizeCompat = 13;
 
   std::shared_ptr<Memory> process_memory_;
   MemoryFake* memory_;
@@ -358,6 +367,19 @@ TEST_F(DexFilesTest, get_method_information_with_empty_map) {
   EXPECT_EQ(0U, method_offset);
 }
 
+TEST_F(DexFilesTest, get_method_information_with_page_size_compat_map) {
+  SharedString method_name = "nothing";
+  uint64_t method_offset = 0x124;
+
+  WriteDescriptor32(0x603800, 0x606000);
+  WriteEntry32(0x606000, 0, 0, 0x610000, sizeof(kDexData));
+  WriteDex(0x610000);
+
+  dex_files_->GetFunctionName(maps_.get(), 0x610100, &method_name, &method_offset);
+  EXPECT_EQ("Main.<init>", method_name);
+  EXPECT_EQ(0U, method_offset);
+}
+
 TEST_F(DexFilesTest, get_method_information_tagged_descriptor_entry_addr_arm64) {
   Init(ARCH_ARM64);
 
diff --git a/libunwindstack/tests/DwarfCfaTest.cpp b/libunwindstack/tests/DwarfCfaTest.cpp
index 937d50b..c76a8d5 100644
--- a/libunwindstack/tests/DwarfCfaTest.cpp
+++ b/libunwindstack/tests/DwarfCfaTest.cpp
@@ -379,7 +379,7 @@ TYPED_TEST_P(DwarfCfaTest, cfa_same) {
   ASSERT_TRUE(this->cfa_->GetLocationInfo(this->fde_.pc_start, 0x100, 0x102, &loc_regs));
   ASSERT_EQ(0x102U, this->dmem_->cur_offset());
   ASSERT_EQ(0U, loc_regs.size());
-  ASSERT_EQ(0U, loc_regs.count(127));
+  ASSERT_FALSE(loc_regs.contains(127));
 
   ASSERT_EQ("", GetFakeLogPrint());
   ASSERT_EQ("", GetFakeLogBuf());
@@ -392,7 +392,7 @@ TYPED_TEST_P(DwarfCfaTest, cfa_same) {
   ASSERT_TRUE(this->cfa_->GetLocationInfo(this->fde_.pc_start, 0x2100, 0x2103, &loc_regs));
   ASSERT_EQ(0x2103U, this->dmem_->cur_offset());
   ASSERT_EQ(0U, loc_regs.size());
-  ASSERT_EQ(0U, loc_regs.count(255));
+  ASSERT_FALSE(loc_regs.contains(255));
 
   ASSERT_EQ("", GetFakeLogPrint());
   ASSERT_EQ("", GetFakeLogBuf());
@@ -458,14 +458,14 @@ TYPED_TEST_P(DwarfCfaTest, cfa_state) {
   ASSERT_TRUE(this->cfa_->GetLocationInfo(this->fde_.pc_start, 0x2000, 0x2005, &loc_regs));
   ASSERT_EQ(0x2005U, this->dmem_->cur_offset());
   ASSERT_EQ(2U, loc_regs.size());
-  ASSERT_NE(loc_regs.end(), loc_regs.find(5));
-  ASSERT_NE(loc_regs.end(), loc_regs.find(6));
+  ASSERT_TRUE(loc_regs.contains(5));
+  ASSERT_TRUE(loc_regs.contains(6));
 
   loc_regs.clear();
   ASSERT_TRUE(this->cfa_->GetLocationInfo(this->fde_.pc_start, 0x2000, 0x2006, &loc_regs));
   ASSERT_EQ(0x2006U, this->dmem_->cur_offset());
   ASSERT_EQ(1U, loc_regs.size());
-  ASSERT_NE(loc_regs.end(), loc_regs.find(5));
+  ASSERT_TRUE(loc_regs.contains(5));
 
   ResetLogs();
   this->fake_memory_->SetMemory(
@@ -476,31 +476,31 @@ TYPED_TEST_P(DwarfCfaTest, cfa_state) {
   ASSERT_TRUE(this->cfa_->GetLocationInfo(this->fde_.pc_start, 0x6000, 0x600c, &loc_regs));
   ASSERT_EQ(0x600cU, this->dmem_->cur_offset());
   ASSERT_EQ(4U, loc_regs.size());
-  ASSERT_NE(loc_regs.end(), loc_regs.find(5));
-  ASSERT_NE(loc_regs.end(), loc_regs.find(6));
-  ASSERT_NE(loc_regs.end(), loc_regs.find(7));
-  ASSERT_NE(loc_regs.end(), loc_regs.find(9));
+  ASSERT_TRUE(loc_regs.contains(5));
+  ASSERT_TRUE(loc_regs.contains(6));
+  ASSERT_TRUE(loc_regs.contains(7));
+  ASSERT_TRUE(loc_regs.contains(9));
 
   loc_regs.clear();
   ASSERT_TRUE(this->cfa_->GetLocationInfo(this->fde_.pc_start, 0x6000, 0x600d, &loc_regs));
   ASSERT_EQ(0x600dU, this->dmem_->cur_offset());
   ASSERT_EQ(3U, loc_regs.size());
-  ASSERT_NE(loc_regs.end(), loc_regs.find(5));
-  ASSERT_NE(loc_regs.end(), loc_regs.find(6));
-  ASSERT_NE(loc_regs.end(), loc_regs.find(7));
+  ASSERT_TRUE(loc_regs.contains(5));
+  ASSERT_TRUE(loc_regs.contains(6));
+  ASSERT_TRUE(loc_regs.contains(7));
 
   loc_regs.clear();
   ASSERT_TRUE(this->cfa_->GetLocationInfo(this->fde_.pc_start, 0x6000, 0x600e, &loc_regs));
   ASSERT_EQ(0x600eU, this->dmem_->cur_offset());
   ASSERT_EQ(2U, loc_regs.size());
-  ASSERT_NE(loc_regs.end(), loc_regs.find(5));
-  ASSERT_NE(loc_regs.end(), loc_regs.find(6));
+  ASSERT_TRUE(loc_regs.contains(5));
+  ASSERT_TRUE(loc_regs.contains(6));
 
   loc_regs.clear();
   ASSERT_TRUE(this->cfa_->GetLocationInfo(this->fde_.pc_start, 0x6000, 0x600f, &loc_regs));
   ASSERT_EQ(0x600fU, this->dmem_->cur_offset());
   ASSERT_EQ(1U, loc_regs.size());
-  ASSERT_NE(loc_regs.end(), loc_regs.find(5));
+  ASSERT_TRUE(loc_regs.contains(5));
 
   loc_regs.clear();
   ASSERT_TRUE(this->cfa_->GetLocationInfo(this->fde_.pc_start, 0x6000, 0x6010, &loc_regs));
diff --git a/libunwindstack/tests/ElfCacheTest.cpp b/libunwindstack/tests/ElfCacheTest.cpp
index 1687a4c..7ebdff2 100644
--- a/libunwindstack/tests/ElfCacheTest.cpp
+++ b/libunwindstack/tests/ElfCacheTest.cpp
@@ -99,7 +99,7 @@ class ElfCacheTest : public ::testing::Test {
 
     for (auto& map_info : *maps_) {
       if (!map_info->name().empty()) {
-        if (renames.count(map_info->name()) != 0) {
+        if (renames.contains(map_info->name())) {
           // Replace the name with the temporary file name.
           map_info->name() = renames.at(map_info->name());
         }
diff --git a/libunwindstack/tests/MapInfoTest.cpp b/libunwindstack/tests/MapInfoTest.cpp
index d578976..0050fe7 100644
--- a/libunwindstack/tests/MapInfoTest.cpp
+++ b/libunwindstack/tests/MapInfoTest.cpp
@@ -105,6 +105,15 @@ TEST(MapInfoTest, real_map_check) {
   map2->set_name("");
   EXPECT_EQ(map3, map1->GetNextRealMap());
 
+  // Verify if the map has the name [page size compat] it's still considered blank.
+  map2->set_name("[page size compat]");
+  EXPECT_EQ(nullptr, map1->GetPrevRealMap());
+  EXPECT_EQ(map3, map1->GetNextRealMap());
+  EXPECT_EQ(map1, map3->GetPrevRealMap());
+  EXPECT_EQ(nullptr, map3->GetNextRealMap());
+  map2->set_name("");
+  EXPECT_EQ(map3, map1->GetNextRealMap());
+
   // Verify that if the Get{Next,Prev}RealMap names must match.
   map1->set_name("another");
   EXPECT_EQ(nullptr, map1->GetPrevRealMap());
diff --git a/libunwindstack/tests/MemoryFileTest.cpp b/libunwindstack/tests/MemoryFileTest.cpp
index 4124a49..5fcfee8 100644
--- a/libunwindstack/tests/MemoryFileTest.cpp
+++ b/libunwindstack/tests/MemoryFileTest.cpp
@@ -273,4 +273,18 @@ TEST_F(MemoryFileTest, init_reinit) {
   }
 }
 
+// Verify that if the init fails, that a subsequent read does not crash.
+TEST_F(MemoryFileTest, init_fail_read_fail) {
+  WriteTestData();
+
+  ASSERT_TRUE(memory_.Init(tf_->path, 0));
+
+  // Now force init to fail.
+  ASSERT_FALSE(memory_.Init("/does/not/exist", 0));
+
+  // Read should not crash.
+  uint64_t data;
+  ASSERT_FALSE(memory_.ReadFully(0, &data, sizeof(data)));
+}
+
 }  // namespace unwindstack
diff --git a/libunwindstack/tools/unwind.cpp b/libunwindstack/tools/unwind.cpp
index 6bed226..f3624e3 100644
--- a/libunwindstack/tools/unwind.cpp
+++ b/libunwindstack/tools/unwind.cpp
@@ -26,13 +26,8 @@
 #include <sys/types.h>
 #include <unistd.h>
 
-#include <unwindstack/DexFiles.h>
-#include <unwindstack/Elf.h>
-#include <unwindstack/JitDebug.h>
-#include <unwindstack/Maps.h>
-#include <unwindstack/Memory.h>
+#include <unwindstack/AndroidUnwinder.h>
 #include <unwindstack/Regs.h>
-#include <unwindstack/Unwinder.h>
 
 static bool Attach(pid_t pid) {
   if (ptrace(PTRACE_SEIZE, pid, 0, 0) == -1) {
@@ -86,13 +81,17 @@ void DoUnwind(pid_t pid) {
   }
   printf("\n");
 
-  unwindstack::UnwinderFromPid unwinder(1024, pid);
-  unwinder.SetRegs(regs);
-  unwinder.Unwind();
+  unwindstack::AndroidRemoteUnwinder unwinder(pid);
+  unwindstack::AndroidUnwinderData data;
+  if (!unwinder.Unwind(regs, data)) {
+    printf("Unable to unwind pid %d: %s\n", pid, data.GetErrorString().c_str());
+    return;
+  }
+  data.DemangleFunctionNames();
 
   // Print the frames.
-  for (size_t i = 0; i < unwinder.NumFrames(); i++) {
-    printf("%s\n", unwinder.FormatFrame(i).c_str());
+  for (const auto& frame : data.frames) {
+    printf("%s\n", unwinder.FormatFrame(frame).c_str());
   }
 }
 
diff --git a/libunwindstack/tools/unwind_for_offline.cpp b/libunwindstack/tools/unwind_for_offline.cpp
index 9184665..e01d4d3 100644
--- a/libunwindstack/tools/unwind_for_offline.cpp
+++ b/libunwindstack/tools/unwind_for_offline.cpp
@@ -14,28 +14,28 @@
  * limitations under the License.
  */
 
-#include <cstdio>
-#define _GNU_SOURCE 1
+#include <ctype.h>
 #include <inttypes.h>
+#include <stdint.h>
 #include <stdio.h>
+#include <stdlib.h>
 #include <sys/mman.h>
+#include <unistd.h>
 
 #include <algorithm>
-#include <cstdlib>
 #include <filesystem>
+#include <limits>
 #include <memory>
 #include <string>
 #include <unordered_map>
 #include <utility>
 #include <vector>
 
-#include <unwindstack/Elf.h>
-#include <unwindstack/JitDebug.h>
+#include <unwindstack/AndroidUnwinder.h>
 #include <unwindstack/MapInfo.h>
 #include <unwindstack/Maps.h>
 #include <unwindstack/Memory.h>
 #include <unwindstack/Regs.h>
-#include <unwindstack/Unwinder.h>
 #include "utils/ProcessTracer.h"
 
 #include <android-base/file.h>
@@ -289,13 +289,17 @@ bool SaveData(pid_t tid, const std::filesystem::path& cwd, bool is_main_thread,
   if (!SaveRegs(regs)) {
     return false;
   }
+  uint64_t sp = regs->sp();
 
   // Do an unwind so we know how much of the stack to save, and what
   // elf files are involved.
-  unwindstack::UnwinderFromPid unwinder(1024, tid);
-  unwinder.SetRegs(regs);
-  uint64_t sp = regs->sp();
-  unwinder.Unwind();
+  unwindstack::AndroidRemoteUnwinder unwinder(tid);
+  unwindstack::AndroidUnwinderData data;
+  if (!unwinder.Unwind(regs, data)) {
+    fprintf(stderr, "Unable to unwind tid %d: %s\n", tid, data.GetErrorString().c_str());
+    return false;
+  }
+  data.DemangleFunctionNames();
 
   std::vector<std::pair<uint64_t, uint64_t>> stacks;
   unwindstack::Maps* maps = unwinder.GetMaps();
@@ -307,7 +311,7 @@ bool SaveData(pid_t tid, const std::filesystem::path& cwd, bool is_main_thread,
   }
 
   std::unordered_map<uintptr_t, unwindstack::MapInfo*> map_infos;
-  for (const auto& frame : unwinder.frames()) {
+  for (const auto& frame : data.frames) {
     auto map_info = maps->Find(frame.sp);
     if (map_info != nullptr && sp_map_start != map_info->start()) {
       stacks.emplace_back(std::make_pair(frame.sp, map_info->end()));
@@ -316,8 +320,8 @@ bool SaveData(pid_t tid, const std::filesystem::path& cwd, bool is_main_thread,
     map_infos[reinterpret_cast<uintptr_t>(frame.map_info.get())] = frame.map_info.get();
   }
 
-  for (size_t i = 0; i < unwinder.NumFrames(); i++) {
-    fprintf(output_fp, "%s\n", unwinder.FormatFrame(i).c_str());
+  for (const auto& frame : data.frames) {
+    fprintf(output_fp, "%s\n", unwinder.FormatFrame(frame).c_str());
   }
 
   if (!SaveStack(tid, stacks, output_fp)) {
diff --git a/libunwindstack/tools/unwind_info.cpp b/libunwindstack/tools/unwind_info.cpp
index 668dc56..c5bdc1c 100644
--- a/libunwindstack/tools/unwind_info.cpp
+++ b/libunwindstack/tools/unwind_info.cpp
@@ -28,6 +28,7 @@
 
 #include <string>
 
+#include <unwindstack/Demangle.h>
 #include <unwindstack/DwarfSection.h>
 #include <unwindstack/DwarfStructs.h>
 #include <unwindstack/Elf.h>
@@ -56,7 +57,7 @@ void DumpArm(Elf* elf, ElfInterfaceArm* interface) {
       printf("  PC 0x%" PRIx64, pc + load_bias);
       uint64_t func_offset;
       if (elf->GetFunctionName(pc + load_bias, &name, &func_offset) && !name.empty()) {
-        printf(" <%s>", name.c_str());
+        printf(" <%s>", DemangleNameIfNeeded(name).c_str());
       }
       printf("\n");
       uint64_t entry;
@@ -95,7 +96,7 @@ void DumpDwarfSection(Elf* elf, DwarfSection* section, uint64_t) {
     SharedString name;
     uint64_t func_offset;
     if (elf->GetFunctionName(fde->pc_start, &name, &func_offset) && !name.empty()) {
-      printf(" <%s>", name.c_str());
+      printf(" <%s>", DemangleNameIfNeeded(name).c_str());
     }
     printf("\n");
     if (!section->Log(2, UINT64_MAX, fde, elf->arch())) {
diff --git a/libunwindstack/tools/unwind_reg_info.cpp b/libunwindstack/tools/unwind_reg_info.cpp
index b483759..0ad0552 100644
--- a/libunwindstack/tools/unwind_reg_info.cpp
+++ b/libunwindstack/tools/unwind_reg_info.cpp
@@ -32,6 +32,7 @@
 #include <utility>
 #include <vector>
 
+#include <unwindstack/Demangle.h>
 #include <unwindstack/DwarfLocation.h>
 #include <unwindstack/DwarfMemory.h>
 #include <unwindstack/DwarfSection.h>
@@ -201,7 +202,7 @@ int GetInfo(const char* file, uint64_t offset, uint64_t pc) {
   SharedString function_name;
   uint64_t function_offset;
   if (elf.GetFunctionName(pc, &function_name, &function_offset)) {
-    printf(" (%s)", function_name.c_str());
+    printf(" (%s)", DemangleNameIfNeeded(function_name).c_str());
   }
   printf(":\n");
 
diff --git a/libunwindstack/tools/unwind_symbols.cpp b/libunwindstack/tools/unwind_symbols.cpp
index aca8939..c26de03 100644
--- a/libunwindstack/tools/unwind_symbols.cpp
+++ b/libunwindstack/tools/unwind_symbols.cpp
@@ -25,6 +25,7 @@
 
 #include <string>
 
+#include <unwindstack/Demangle.h>
 #include <unwindstack/Elf.h>
 #include <unwindstack/Log.h>
 #include <unwindstack/Memory.h>
@@ -103,7 +104,7 @@ int main(int argc, char** argv) {
     if (func_offset != 0) {
       printf("+%" PRId64, func_offset);
     }
-    printf(": %s\n", cur_name.c_str());
+    printf(": %s\n", DemangleNameIfNeeded(cur_name).c_str());
     return 0;
   }
 
@@ -116,7 +117,8 @@ int main(int argc, char** argv) {
       uint64_t func_offset;
       if (elf.GetFunctionName(addr, &cur_name, &func_offset)) {
         if (cur_name != name) {
-          printf("<0x%" PRIx64 "> Function: %s\n", addr - func_offset, cur_name.c_str());
+          printf("<0x%" PRIx64 "> Function: %s\n", addr - func_offset,
+                 DemangleNameIfNeeded(cur_name).c_str());
         }
         name = cur_name;
       }
diff --git a/libunwindstack/utils/OfflineUnwindUtils.cpp b/libunwindstack/utils/OfflineUnwindUtils.cpp
index 0d5e15c..fe06914 100644
--- a/libunwindstack/utils/OfflineUnwindUtils.cpp
+++ b/libunwindstack/utils/OfflineUnwindUtils.cpp
@@ -463,7 +463,7 @@ const std::string& OfflineUnwindUtils::GetAdjustedSampleName(
 
 bool OfflineUnwindUtils::IsValidUnwindSample(const std::string& sample_name,
                                              std::string* error_msg) const {
-  if (samples_.find(sample_name) == samples_.end()) {
+  if (!samples_.contains(sample_name)) {
     std::stringstream err_stream;
     err_stream << "Invalid sample name (offline file directory) '" << sample_name << "'.";
     if (sample_name == kSingleSample) {
diff --git a/libunwindstack/utils/ProcessTracer.cpp b/libunwindstack/utils/ProcessTracer.cpp
index 7f60ca0..d5638d8 100644
--- a/libunwindstack/utils/ProcessTracer.cpp
+++ b/libunwindstack/utils/ProcessTracer.cpp
@@ -98,7 +98,7 @@ bool ProcessTracer::Resume() {
 }
 
 bool ProcessTracer::Detach(pid_t tid) {
-  if (tid != pid_ && tids_.find(tid) == tids_.end()) {
+  if (tid != pid_ && !tids_.contains(tid)) {
     fprintf(stderr, "Tid %d does not belong to proc %d.\n", tid, pid_);
     return false;
   }
@@ -119,7 +119,7 @@ bool ProcessTracer::Detach(pid_t tid) {
 }
 
 bool ProcessTracer::Attach(pid_t tid) {
-  if (tid != pid_ && tids_.find(tid) == tids_.end()) {
+  if (tid != pid_ && !tids_.contains(tid)) {
     fprintf(stderr, "Tid %d does not belong to proc %d.\n", tid, pid_);
     return false;
   }
```

