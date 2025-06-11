```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index dcf92be..cfa5095 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -5,4 +5,3 @@ clang_format = true
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/libunwindstack/LogAndroid.cpp b/libunwindstack/LogAndroid.cpp
index 2f5b00e..e6ed025 100644
--- a/libunwindstack/LogAndroid.cpp
+++ b/libunwindstack/LogAndroid.cpp
@@ -17,6 +17,7 @@
 #include <stdarg.h>
 #include <stdint.h>
 #include <stdio.h>
+#include <stdlib.h>
 
 #include <string>
 
diff --git a/libunwindstack/Unwinder.cpp b/libunwindstack/Unwinder.cpp
index 115a265..c4d656f 100644
--- a/libunwindstack/Unwinder.cpp
+++ b/libunwindstack/Unwinder.cpp
@@ -61,17 +61,22 @@ void Unwinder::FillInDexFrame() {
   frame->sp = regs_->sp();
 
   frame->map_info = maps_->Find(dex_pc);
-  if (frame->map_info != nullptr) {
-    frame->rel_pc = dex_pc - frame->map_info->start();
-    // Initialize the load bias for this map so subsequent calls
-    // to GetLoadBias() will always return data.
-    frame->map_info->set_load_bias(0);
-  } else {
+  if (frame->map_info == nullptr) {
     frame->rel_pc = dex_pc;
     warnings_ |= WARNING_DEX_PC_NOT_IN_MAP;
     return;
   }
 
+  auto& map_info = frame->map_info;
+  frame->rel_pc = dex_pc - map_info->start();
+  if (!map_info->LoadBiasInitialized()) {
+    // Only do this once per MapInfo object used for a dex pc frame. If
+    // multiple threads happen to do this at the same time, this action
+    // is idempotent and will set the same values.
+    map_info->set_elf_start_offset(map_info->offset());
+    map_info->set_load_bias(0);
+  }
+
   if (!resolve_names_) {
     return;
   }
diff --git a/libunwindstack/include/unwindstack/Arch.h b/libunwindstack/include/unwindstack/Arch.h
index 975053f..b1f0b0f 100644
--- a/libunwindstack/include/unwindstack/Arch.h
+++ b/libunwindstack/include/unwindstack/Arch.h
@@ -17,6 +17,7 @@
 #pragma once
 
 #include <stddef.h>
+#include <stdint.h>
 
 namespace unwindstack {
 
diff --git a/libunwindstack/include/unwindstack/MapInfo.h b/libunwindstack/include/unwindstack/MapInfo.h
index 3881f73..25424c9 100644
--- a/libunwindstack/include/unwindstack/MapInfo.h
+++ b/libunwindstack/include/unwindstack/MapInfo.h
@@ -133,6 +133,8 @@ class MapInfo {
     return elf().get();
   }
 
+  bool LoadBiasInitialized() { return load_bias() != UINT64_MAX; }
+
   inline uint64_t start() const { return start_; }
   inline void set_start(uint64_t value) { start_ = value; }
 
diff --git a/libunwindstack/include/unwindstack/Maps.h b/libunwindstack/include/unwindstack/Maps.h
index a90dc0d..deddb4b 100644
--- a/libunwindstack/include/unwindstack/Maps.h
+++ b/libunwindstack/include/unwindstack/Maps.h
@@ -20,6 +20,7 @@
 #include <sys/types.h>
 #include <unistd.h>
 
+#include <functional>
 #include <memory>
 #include <string>
 #include <vector>
diff --git a/libunwindstack/include/unwindstack/RegsGetLocal.h b/libunwindstack/include/unwindstack/RegsGetLocal.h
index 86aab97..e3c1092 100644
--- a/libunwindstack/include/unwindstack/RegsGetLocal.h
+++ b/libunwindstack/include/unwindstack/RegsGetLocal.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <unwindstack/Regs.h>
+
 namespace unwindstack {
 
 #if defined(__arm__)
diff --git a/libunwindstack/include/unwindstack/UcontextRiscv64.h b/libunwindstack/include/unwindstack/UcontextRiscv64.h
index fe0264a..9da4350 100644
--- a/libunwindstack/include/unwindstack/UcontextRiscv64.h
+++ b/libunwindstack/include/unwindstack/UcontextRiscv64.h
@@ -28,10 +28,11 @@
 
 #pragma once
 
-namespace unwindstack {
-
+#include <stdint.h>
 #include <sys/cdefs.h>
 
+namespace unwindstack {
+
 typedef uint64_t __riscv_mc_gp_state[32];  // unsigned long
 
 struct __riscv_mc_f_ext_state {
diff --git a/libunwindstack/include/unwindstack/UserArm.h b/libunwindstack/include/unwindstack/UserArm.h
index 725a35b..8ae8451 100644
--- a/libunwindstack/include/unwindstack/UserArm.h
+++ b/libunwindstack/include/unwindstack/UserArm.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <stdint.h>
+
 namespace unwindstack {
 
 struct arm_user_regs {
diff --git a/libunwindstack/include/unwindstack/UserArm64.h b/libunwindstack/include/unwindstack/UserArm64.h
index 0e16cd6..0ae0874 100644
--- a/libunwindstack/include/unwindstack/UserArm64.h
+++ b/libunwindstack/include/unwindstack/UserArm64.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <stdint.h>
+
 namespace unwindstack {
 
 struct arm64_user_regs {
diff --git a/libunwindstack/include/unwindstack/UserRiscv64.h b/libunwindstack/include/unwindstack/UserRiscv64.h
index c7ad198..55e024d 100644
--- a/libunwindstack/include/unwindstack/UserRiscv64.h
+++ b/libunwindstack/include/unwindstack/UserRiscv64.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <stdint.h>
+
 namespace unwindstack {
 
 struct riscv64_user_regs {
diff --git a/libunwindstack/include/unwindstack/UserX86.h b/libunwindstack/include/unwindstack/UserX86.h
index 9508010..6e78f8b 100644
--- a/libunwindstack/include/unwindstack/UserX86.h
+++ b/libunwindstack/include/unwindstack/UserX86.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <stdint.h>
+
 namespace unwindstack {
 
 struct x86_user_regs {
diff --git a/libunwindstack/include/unwindstack/UserX86_64.h b/libunwindstack/include/unwindstack/UserX86_64.h
index d7ff2e2..102cf56 100644
--- a/libunwindstack/include/unwindstack/UserX86_64.h
+++ b/libunwindstack/include/unwindstack/UserX86_64.h
@@ -28,6 +28,8 @@
 
 #pragma once
 
+#include <stdint.h>
+
 namespace unwindstack {
 
 struct x86_64_user_regs {
diff --git a/libunwindstack/tests/UnwinderTest.cpp b/libunwindstack/tests/UnwinderTest.cpp
index 598afcc..141ffa6 100644
--- a/libunwindstack/tests/UnwinderTest.cpp
+++ b/libunwindstack/tests/UnwinderTest.cpp
@@ -115,6 +115,8 @@ class UnwinderTest : public ::testing::Test {
                           "/fake/fake_offset.oat", elf);
     map_info->set_elf_offset(0x8000);
 
+    AddMapInfo(0xa8000, 0xa9000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, "/fake/fake_vdex.apk");
+
     elf = new ElfFake(elf_memory);
     elf->FakeSetInterface(new ElfInterfaceFake(empty));
     map_info = AddMapInfo(0xc0000, 0xc1000, 0, PROT_READ | PROT_WRITE | PROT_EXEC,
@@ -1311,6 +1313,54 @@ TEST_F(UnwinderTest, dex_pc_max_frames) {
   EXPECT_EQ(PROT_READ | PROT_WRITE | PROT_EXEC, frame->map_info->flags());
 }
 
+TEST_F(UnwinderTest, dex_pc_vdex_in_apk) {
+  ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
+  regs_.set_pc(0x1000);
+  regs_.set_sp(0x10000);
+  regs_.FakeSetDexPc(0xa8400);
+
+  Unwinder unwinder(64, maps_.get(), &regs_, process_memory_);
+  unwinder.Unwind();
+  EXPECT_EQ(ERROR_NONE, unwinder.LastErrorCode());
+  EXPECT_EQ(WARNING_NONE, unwinder.warnings());
+
+  ASSERT_EQ(2U, unwinder.NumFrames());
+
+  auto* frame = &unwinder.frames()[0];
+  EXPECT_EQ(0U, frame->num);
+  EXPECT_EQ(0x400U, frame->rel_pc);
+  EXPECT_EQ(0xa8400U, frame->pc);
+  EXPECT_EQ(0x10000U, frame->sp);
+  EXPECT_EQ("", frame->function_name);
+  EXPECT_EQ(0U, frame->function_offset);
+  ASSERT_TRUE(frame->map_info != nullptr);
+  EXPECT_EQ("/fake/fake_vdex.apk", frame->map_info->name());
+  EXPECT_EQ("/fake/fake_vdex.apk", frame->map_info->GetFullName());
+  EXPECT_EQ(0x1000U, frame->map_info->elf_start_offset());
+  EXPECT_EQ(0x1000U, frame->map_info->offset());
+  EXPECT_EQ(0xa8000U, frame->map_info->start());
+  EXPECT_EQ(0xa9000U, frame->map_info->end());
+  EXPECT_EQ(0U, frame->map_info->GetLoadBias());
+  EXPECT_EQ(PROT_READ | PROT_WRITE | PROT_EXEC, frame->map_info->flags());
+
+  frame = &unwinder.frames()[1];
+  EXPECT_EQ(1U, frame->num);
+  EXPECT_EQ(0U, frame->rel_pc);
+  EXPECT_EQ(0x1000U, frame->pc);
+  EXPECT_EQ(0x10000U, frame->sp);
+  EXPECT_EQ("Frame0", frame->function_name);
+  EXPECT_EQ(0U, frame->function_offset);
+  ASSERT_TRUE(frame->map_info != nullptr);
+  EXPECT_EQ("/system/fake/libc.so", frame->map_info->name());
+  EXPECT_EQ("/system/fake/libc.so", frame->map_info->GetFullName());
+  EXPECT_EQ(0U, frame->map_info->elf_start_offset());
+  EXPECT_EQ(0U, frame->map_info->offset());
+  EXPECT_EQ(0x1000U, frame->map_info->start());
+  EXPECT_EQ(0x8000U, frame->map_info->end());
+  EXPECT_EQ(0U, frame->map_info->GetLoadBias());
+  EXPECT_EQ(PROT_READ | PROT_WRITE, frame->map_info->flags());
+}
+
 TEST_F(UnwinderTest, elf_file_not_readable) {
   ElfInterfaceFake::FakePushFunctionData(FunctionData("Frame0", 0));
 
```

