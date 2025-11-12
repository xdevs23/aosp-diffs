```diff
diff --git a/libunwindstack/Android.bp b/libunwindstack/Android.bp
index 59a854e..192ede6 100644
--- a/libunwindstack/Android.bp
+++ b/libunwindstack/Android.bp
@@ -525,6 +525,7 @@ cc_defaults {
         "liblzma",
     ],
     static_libs: [
+        "libprocinfo",
         "libunwindstack_stdout_log",
     ],
     target: {
diff --git a/libunwindstack/LogStdout.cpp b/libunwindstack/LogStdout.cpp
index e54bd11..220ab8a 100644
--- a/libunwindstack/LogStdout.cpp
+++ b/libunwindstack/LogStdout.cpp
@@ -17,6 +17,7 @@
 #include <stdarg.h>
 #include <stdint.h>
 #include <stdio.h>
+#include <stdlib.h>
 
 #include <string>
 
diff --git a/libunwindstack/RegsArm.cpp b/libunwindstack/RegsArm.cpp
index 7258058..bf38616 100644
--- a/libunwindstack/RegsArm.cpp
+++ b/libunwindstack/RegsArm.cpp
@@ -29,7 +29,9 @@
 
 namespace unwindstack {
 
-RegsArm::RegsArm() : RegsImpl<uint32_t>(ARM_REG_LAST, Location(LOCATION_REGISTER, ARM_REG_LR)) {}
+RegsArm::RegsArm()
+    : RegsImpl<uint32_t>(ARM_REG_LAST, ARM_EXTRA_REG_LAST,
+                         Location(LOCATION_REGISTER, ARM_REG_LR)) {}
 
 ArchEnum RegsArm::Arch() {
   return ARCH_ARM;
@@ -93,6 +95,7 @@ Regs* RegsArm::CreateFromUcontext(void* ucontext) {
 
   RegsArm* regs = new RegsArm();
   memcpy(regs->RawData(), &arm_ucontext->uc_mcontext.regs[0], ARM_REG_LAST * sizeof(uint32_t));
+  regs->SetExtraRegister(ARM_EXTRA_REG_ERROR_CODE, arm_ucontext->uc_mcontext.error_code);
   return regs;
 }
 
diff --git a/libunwindstack/RegsArm64.cpp b/libunwindstack/RegsArm64.cpp
index 85da806..549a41e 100644
--- a/libunwindstack/RegsArm64.cpp
+++ b/libunwindstack/RegsArm64.cpp
@@ -34,10 +34,8 @@
 namespace unwindstack {
 
 RegsArm64::RegsArm64()
-    : RegsImpl<uint64_t>(ARM64_REG_LAST, Location(LOCATION_REGISTER, ARM64_REG_LR)) {
-  ResetPseudoRegisters();
-  pac_mask_ = 0;
-}
+    : RegsImpl<uint64_t>(ARM64_REG_LAST, ARM64_EXTRA_REG_LAST,
+                         Location(LOCATION_REGISTER, ARM64_REG_LR)) {}
 
 ArchEnum RegsArm64::Arch() {
   return ARCH_ARM64;
@@ -144,10 +142,25 @@ Regs* RegsArm64::Read(const void* remote_data) {
 }
 
 Regs* RegsArm64::CreateFromUcontext(void* ucontext) {
+  // Get the normal aarch64 registers.
   arm64_ucontext_t* arm64_ucontext = reinterpret_cast<arm64_ucontext_t*>(ucontext);
-
   RegsArm64* regs = new RegsArm64();
   memcpy(regs->RawData(), &arm64_ucontext->uc_mcontext.regs[0], ARM64_REG_LAST * sizeof(uint64_t));
+
+  // The reserved part of the mcontext contains extra information.
+  uint64_t ctx = reinterpret_cast<uint64_t>(arm64_ucontext->uc_mcontext.reserved);
+  uint64_t max_ctx_value = ctx + sizeof(arm64_ucontext->uc_mcontext.reserved);
+  while ((ctx + sizeof(arm64_ctx)) <= max_ctx_value) {
+    arm64_ctx* ctx_ptr = reinterpret_cast<arm64_ctx*>(ctx);
+    if (ctx_ptr->size == 0) {
+      break;
+    }
+    if (ctx_ptr->magic == kArm64EsrMagic && (ctx + sizeof(arm64_esr_ctx)) <= max_ctx_value) {
+      regs->SetExtraRegister(ARM64_EXTRA_REG_ESR, reinterpret_cast<arm64_esr_ctx*>(ctx_ptr)->esr);
+      break;
+    }
+    ctx += ctx_ptr->size;
+  }
   return regs;
 }
 
@@ -177,20 +190,20 @@ bool RegsArm64::StepIfSignalHandler(uint64_t elf_offset, Elf* elf, Memory* proce
 
 void RegsArm64::ResetPseudoRegisters(void) {
   // DWARF for AArch64 says RA_SIGN_STATE should be initialized to 0.
-  this->SetPseudoRegister(Arm64Reg::ARM64_PREG_RA_SIGN_STATE, 0);
+  memset(pseudo_regs_, 0, sizeof(pseudo_regs_));
 }
 
 bool RegsArm64::SetPseudoRegister(uint16_t id, uint64_t value) {
-  if ((id >= Arm64Reg::ARM64_PREG_FIRST) && (id < Arm64Reg::ARM64_PREG_LAST)) {
-    pseudo_regs_[id - Arm64Reg::ARM64_PREG_FIRST] = value;
+  if ((id >= ARM64_PREG_FIRST) && (id < ARM64_PREG_LAST)) {
+    pseudo_regs_[id - ARM64_PREG_FIRST] = value;
     return true;
   }
   return false;
 }
 
 bool RegsArm64::GetPseudoRegister(uint16_t id, uint64_t* value) {
-  if ((id >= Arm64Reg::ARM64_PREG_FIRST) && (id < Arm64Reg::ARM64_PREG_LAST)) {
-    *value = pseudo_regs_[id - Arm64Reg::ARM64_PREG_FIRST];
+  if ((id >= ARM64_PREG_FIRST) && (id < ARM64_PREG_LAST)) {
+    *value = pseudo_regs_[id - ARM64_PREG_FIRST];
     return true;
   }
   return false;
@@ -198,7 +211,7 @@ bool RegsArm64::GetPseudoRegister(uint16_t id, uint64_t* value) {
 
 bool RegsArm64::IsRASigned() {
   uint64_t value;
-  auto result = this->GetPseudoRegister(Arm64Reg::ARM64_PREG_RA_SIGN_STATE, &value);
+  auto result = this->GetPseudoRegister(ARM64_PREG_RA_SIGN_STATE, &value);
   return (result && (value != 0));
 }
 
diff --git a/libunwindstack/RegsRiscv64.cpp b/libunwindstack/RegsRiscv64.cpp
index 532b3b1..ef63884 100644
--- a/libunwindstack/RegsRiscv64.cpp
+++ b/libunwindstack/RegsRiscv64.cpp
@@ -70,7 +70,7 @@ uint64_t RegsRiscv64::GetVlenbFromRemote(pid_t pid) {
 #endif
 
 RegsRiscv64::RegsRiscv64()
-    : RegsImpl<uint64_t>(RISCV64_REG_COUNT, Location(LOCATION_REGISTER, RISCV64_REG_RA)) {}
+    : RegsImpl<uint64_t>(RISCV64_REG_COUNT, 0, Location(LOCATION_REGISTER, RISCV64_REG_RA)) {}
 
 ArchEnum RegsRiscv64::Arch() {
   return ARCH_RISCV64;
diff --git a/libunwindstack/RegsX86.cpp b/libunwindstack/RegsX86.cpp
index 4452699..d233506 100644
--- a/libunwindstack/RegsX86.cpp
+++ b/libunwindstack/RegsX86.cpp
@@ -28,7 +28,8 @@
 
 namespace unwindstack {
 
-RegsX86::RegsX86() : RegsImpl<uint32_t>(X86_REG_LAST, Location(LOCATION_SP_OFFSET, -4)) {}
+RegsX86::RegsX86()
+    : RegsImpl<uint32_t>(X86_REG_LAST, X86_EXTRA_REG_LAST, Location(LOCATION_SP_OFFSET, -4)) {}
 
 ArchEnum RegsX86::Arch() {
   return ARCH_X86;
@@ -109,6 +110,7 @@ Regs* RegsX86::CreateFromUcontext(void* ucontext) {
 
   RegsX86* regs = new RegsX86();
   regs->SetFromUcontext(x86_ucontext);
+  regs->SetExtraRegister(X86_EXTRA_REG_ERR, x86_ucontext->uc_mcontext.err);
   return regs;
 }
 
diff --git a/libunwindstack/RegsX86_64.cpp b/libunwindstack/RegsX86_64.cpp
index ac29302..5e5b315 100644
--- a/libunwindstack/RegsX86_64.cpp
+++ b/libunwindstack/RegsX86_64.cpp
@@ -29,7 +29,9 @@
 
 namespace unwindstack {
 
-RegsX86_64::RegsX86_64() : RegsImpl<uint64_t>(X86_64_REG_LAST, Location(LOCATION_SP_OFFSET, -8)) {}
+RegsX86_64::RegsX86_64()
+    : RegsImpl<uint64_t>(X86_64_REG_LAST, X86_64_EXTRA_REG_LAST, Location(LOCATION_SP_OFFSET, -8)) {
+}
 
 ArchEnum RegsX86_64::Arch() {
   return ARCH_X86_64;
@@ -129,6 +131,8 @@ Regs* RegsX86_64::CreateFromUcontext(void* ucontext) {
 
   RegsX86_64* regs = new RegsX86_64();
   regs->SetFromUcontext(x86_64_ucontext);
+
+  regs->SetExtraRegister(X86_64_EXTRA_REG_ERR, x86_64_ucontext->uc_mcontext.err);
   return regs;
 }
 
diff --git a/libunwindstack/include/unwindstack/MachineArm.h b/libunwindstack/include/unwindstack/MachineArm.h
index 6b8198e..0cd4c6e 100644
--- a/libunwindstack/include/unwindstack/MachineArm.h
+++ b/libunwindstack/include/unwindstack/MachineArm.h
@@ -42,6 +42,10 @@ enum ArmReg : uint16_t {
   ARM_REG_SP = ARM_REG_R13,
   ARM_REG_LR = ARM_REG_R14,
   ARM_REG_PC = ARM_REG_R15,
+
+  // Extra registers, usually only found in ucontext data.
+  ARM_EXTRA_REG_ERROR_CODE = 0,
+  ARM_EXTRA_REG_LAST,
 };
 
 }  // namespace unwindstack
diff --git a/libunwindstack/include/unwindstack/MachineArm64.h b/libunwindstack/include/unwindstack/MachineArm64.h
index f1b7c1d..1e37024 100644
--- a/libunwindstack/include/unwindstack/MachineArm64.h
+++ b/libunwindstack/include/unwindstack/MachineArm64.h
@@ -64,8 +64,12 @@ enum Arm64Reg : uint16_t {
 
   // AARCH64 Return address signed state pseudo-register
   ARM64_PREG_RA_SIGN_STATE = 34,
-  ARM64_PREG_FIRST = ARM64_PREG_RA_SIGN_STATE,
   ARM64_PREG_LAST,
+  ARM64_PREG_FIRST = ARM64_PREG_RA_SIGN_STATE,
+
+  // Extra registers, usually only found in ucontext data.
+  ARM64_EXTRA_REG_ESR = 0,
+  ARM64_EXTRA_REG_LAST,
 };
 
 }  // namespace unwindstack
diff --git a/libunwindstack/include/unwindstack/MachineX86.h b/libunwindstack/include/unwindstack/MachineX86.h
index ff4fd4b..9f8d900 100644
--- a/libunwindstack/include/unwindstack/MachineX86.h
+++ b/libunwindstack/include/unwindstack/MachineX86.h
@@ -43,6 +43,10 @@ enum X86Reg : uint16_t {
 
   X86_REG_SP = X86_REG_ESP,
   X86_REG_PC = X86_REG_EIP,
+
+  // Extra registers, usually only found in ucontext data.
+  X86_EXTRA_REG_ERR = 0,
+  X86_EXTRA_REG_LAST,
 };
 
 }  // namespace unwindstack
diff --git a/libunwindstack/include/unwindstack/MachineX86_64.h b/libunwindstack/include/unwindstack/MachineX86_64.h
index 66670e3..6174bcc 100644
--- a/libunwindstack/include/unwindstack/MachineX86_64.h
+++ b/libunwindstack/include/unwindstack/MachineX86_64.h
@@ -44,6 +44,10 @@ enum X86_64Reg : uint16_t {
 
   X86_64_REG_SP = X86_64_REG_RSP,
   X86_64_REG_PC = X86_64_REG_RIP,
+
+  // Extra registers, usually only found in ucontext data.
+  X86_64_EXTRA_REG_ERR = 0,
+  X86_64_EXTRA_REG_LAST,
 };
 
 }  // namespace unwindstack
diff --git a/libunwindstack/include/unwindstack/Regs.h b/libunwindstack/include/unwindstack/Regs.h
index 5d3224c..24536c0 100644
--- a/libunwindstack/include/unwindstack/Regs.h
+++ b/libunwindstack/include/unwindstack/Regs.h
@@ -71,6 +71,9 @@ class Regs {
   virtual bool SetPseudoRegister(uint16_t, uint64_t) { return false; }
   virtual bool GetPseudoRegister(uint16_t, uint64_t*) { return false; }
 
+  virtual void SetExtraRegister(uint16_t, uint64_t) {}
+  virtual uint64_t GetExtraRegister(uint16_t) { return 0; }
+
   virtual bool StepIfSignalHandler(uint64_t elf_offset, Elf* elf, Memory* process_memory) = 0;
 
   virtual bool SetPcFromReturnAddress(Memory* process_memory) = 0;
@@ -98,14 +101,27 @@ class Regs {
 template <typename AddressType>
 class RegsImpl : public Regs {
  public:
-  RegsImpl(uint16_t total_regs, Location return_loc)
-      : Regs(total_regs, return_loc), regs_(total_regs) {}
+  RegsImpl(uint16_t total_regs, uint16_t total_extra_regs, Location return_loc)
+      : Regs(total_regs, return_loc), regs_(total_regs), extra_regs_(total_extra_regs) {}
   virtual ~RegsImpl() = default;
 
   inline AddressType& operator[](size_t reg) { return regs_[reg]; }
 
   void* RawData() override { return regs_.data(); }
 
+  void SetExtraRegister(uint16_t reg, uint64_t value) override {
+    if (reg >= extra_regs_.size()) {
+      return;
+    }
+    extra_regs_[reg] = value;
+  }
+  uint64_t GetExtraRegister(uint16_t reg) override {
+    if (reg >= extra_regs_.size()) {
+      return 0;
+    }
+    return extra_regs_[reg];
+  }
+
   virtual void IterateRegisters(std::function<void(const char*, uint64_t)> fn) override {
     for (size_t i = 0; i < regs_.size(); ++i) {
       fn(std::to_string(i).c_str(), regs_[i]);
@@ -114,6 +130,7 @@ class RegsImpl : public Regs {
 
  protected:
   std::vector<AddressType> regs_;
+  std::vector<uint64_t> extra_regs_;
 };
 
 uint64_t GetPcAdjustment(uint64_t rel_pc, Elf* elf, ArchEnum arch);
diff --git a/libunwindstack/include/unwindstack/RegsArm64.h b/libunwindstack/include/unwindstack/RegsArm64.h
index 71b3605..d4179b3 100644
--- a/libunwindstack/include/unwindstack/RegsArm64.h
+++ b/libunwindstack/include/unwindstack/RegsArm64.h
@@ -67,8 +67,8 @@ class RegsArm64 : public RegsImpl<uint64_t> {
   static Regs* CreateFromUcontext(void* ucontext);
 
  protected:
-  uint64_t pseudo_regs_[Arm64Reg::ARM64_PREG_LAST - Arm64Reg::ARM64_PREG_FIRST];
-  uint64_t pac_mask_;
+  uint64_t pseudo_regs_[Arm64Reg::ARM64_PREG_LAST - Arm64Reg::ARM64_PREG_FIRST] = {};
+  uint64_t pac_mask_ = 0;
 };
 
 }  // namespace unwindstack
diff --git a/libunwindstack/include/unwindstack/UcontextArm64.h b/libunwindstack/include/unwindstack/UcontextArm64.h
index 49278b3..02daccb 100644
--- a/libunwindstack/include/unwindstack/UcontextArm64.h
+++ b/libunwindstack/include/unwindstack/UcontextArm64.h
@@ -44,11 +44,23 @@ struct arm64_sigset_t {
   uint64_t sig;  // unsigned long
 };
 
+constexpr uint32_t kArm64EsrMagic = 0x45535201U;
+
+struct arm64_ctx {
+  uint32_t magic;
+  uint32_t size;
+};
+
+struct arm64_esr_ctx {
+  struct arm64_ctx head;
+  uint64_t esr;
+};
+
 struct arm64_mcontext_t {
   uint64_t fault_address;         // __u64
   uint64_t regs[ARM64_REG_LAST];  // __u64
   uint64_t pstate;                // __u64
-  // Nothing else is used, so don't define it.
+  uint8_t reserved[4096] __attribute__((__aligned__(16)));
 };
 
 struct arm64_ucontext_t {
diff --git a/libunwindstack/tests/RegsTest.cpp b/libunwindstack/tests/RegsTest.cpp
index 10605ab..4f26400 100644
--- a/libunwindstack/tests/RegsTest.cpp
+++ b/libunwindstack/tests/RegsTest.cpp
@@ -23,13 +23,18 @@
 
 #include <unwindstack/Elf.h>
 #include <unwindstack/ElfInterface.h>
+#include <unwindstack/MachineArm.h>
+#include <unwindstack/MachineArm64.h>
 #include <unwindstack/MachineRiscv64.h>
+#include <unwindstack/MachineX86.h>
+#include <unwindstack/MachineX86_64.h>
 #include <unwindstack/MapInfo.h>
 #include <unwindstack/RegsArm.h>
 #include <unwindstack/RegsArm64.h>
 #include <unwindstack/RegsRiscv64.h>
 #include <unwindstack/RegsX86.h>
 #include <unwindstack/RegsX86_64.h>
+#include <unwindstack/UcontextArm64.h>
 
 #include "ElfFake.h"
 #include "RegsFake.h"
@@ -263,9 +268,87 @@ TEST_F(RegsTest, x86_64_verify_sp_pc) {
   EXPECT_EQ(0x4900000000U, x86_64.pc());
 }
 
+TEST_F(RegsTest, arm_error_code) {
+  RegsArm arm;
+  arm.SetExtraRegister(ARM_EXTRA_REG_ERROR_CODE, 0x8769U);
+  EXPECT_EQ(0x8769U, arm.GetExtraRegister(ARM_EXTRA_REG_ERROR_CODE));
+}
+
+TEST_F(RegsTest, arm64_esr) {
+  RegsArm64 arm64;
+  arm64.SetExtraRegister(Arm64Reg::ARM64_EXTRA_REG_ESR, 0x1000U);
+  EXPECT_EQ(0x1000U, arm64.GetExtraRegister(Arm64Reg::ARM64_EXTRA_REG_ESR));
+}
+
+TEST_F(RegsTest, arm64_esr_from_ucontext) {
+  arm64_ucontext_t ucontext;
+  arm64_esr_ctx* ctx = reinterpret_cast<arm64_esr_ctx*>(ucontext.uc_mcontext.reserved);
+  ctx->head.magic = 0x45535201U;
+  ctx->head.size = sizeof(arm64_esr_ctx);
+  ctx->esr = 0x1200adefU;
+
+  std::unique_ptr<Regs> regs(RegsArm64::CreateFromUcontext(&ucontext));
+  ASSERT_TRUE(regs.get() != nullptr);
+
+  EXPECT_EQ(0x1200adefU, regs->GetExtraRegister(ARM64_EXTRA_REG_ESR));
+}
+
+TEST_F(RegsTest, arm64_esr_from_ucontext_edges) {
+  arm64_ucontext_t ucontext;
+  arm64_ctx* ctx = reinterpret_cast<arm64_ctx*>(ucontext.uc_mcontext.reserved);
+  ctx->magic = 0xdeadbeef;
+  // Choose a size that should be outside the structure.
+  ctx->size = sizeof(ucontext.uc_mcontext.reserved);
+
+  std::unique_ptr<Regs> regs(RegsArm64::CreateFromUcontext(&ucontext));
+  ASSERT_TRUE(regs.get() != nullptr);
+
+  EXPECT_EQ(0U, regs->GetExtraRegister(ARM64_EXTRA_REG_ESR));
+
+  // Put the esr context at the end of the ucontext section but with the esr
+  // value past the end, so the value should not be set.
+  ctx->size = sizeof(ucontext.uc_mcontext.reserved) - sizeof(arm64_ctx);
+  arm64_ctx* last_ctx = reinterpret_cast<arm64_ctx*>(reinterpret_cast<uint8_t*>(ctx) + ctx->size);
+  last_ctx->magic = 0x45535201U;
+  last_ctx->size = sizeof(arm64_esr_ctx);
+
+  regs.reset(RegsArm64::CreateFromUcontext(&ucontext));
+  ASSERT_TRUE(regs.get() != nullptr);
+
+  EXPECT_EQ(0U, regs->GetExtraRegister(ARM64_EXTRA_REG_ESR));
+
+  // Now move the esr context data at the absolute end of the section.
+  last_ctx->magic = 0;
+  last_ctx->size = 0;
+
+  ctx->size = sizeof(ucontext.uc_mcontext.reserved) - sizeof(arm64_esr_ctx);
+  arm64_esr_ctx* esr_ctx =
+      reinterpret_cast<arm64_esr_ctx*>(reinterpret_cast<uint8_t*>(ctx) + ctx->size);
+  esr_ctx->head.magic = 0x45535201U;
+  esr_ctx->head.size = sizeof(arm64_esr_ctx);
+  esr_ctx->esr = 0xdead1234U;
+
+  regs.reset(RegsArm64::CreateFromUcontext(&ucontext));
+  ASSERT_TRUE(regs.get() != nullptr);
+
+  EXPECT_EQ(0xdead1234U, regs->GetExtraRegister(ARM64_EXTRA_REG_ESR));
+}
+
+TEST_F(RegsTest, x86_err) {
+  RegsX86 x86;
+  x86.SetExtraRegister(X86_EXTRA_REG_ERR, 0x1234U);
+  EXPECT_EQ(0x1234U, x86.GetExtraRegister(X86_EXTRA_REG_ERR));
+}
+
+TEST_F(RegsTest, x86_64_err) {
+  RegsX86_64 x86_64;
+  x86_64.SetExtraRegister(X86_64_EXTRA_REG_ERR, 0x2000U);
+  EXPECT_EQ(0x2000U, x86_64.GetExtraRegister(X86_64_EXTRA_REG_ERR));
+}
+
 TEST_F(RegsTest, arm64_strip_pac_mask) {
   RegsArm64 arm64;
-  arm64.SetPseudoRegister(Arm64Reg::ARM64_PREG_RA_SIGN_STATE, 1);
+  EXPECT_TRUE(arm64.SetPseudoRegister(Arm64Reg::ARM64_PREG_RA_SIGN_STATE, 1));
   arm64.SetPACMask(0x007fff8000000000ULL);
   arm64.set_pc(0x0020007214bb3a04ULL);
   EXPECT_EQ(0x0000007214bb3a04ULL, arm64.pc());
diff --git a/libunwindstack/tests/VerifyBionicTerminationTest.cpp b/libunwindstack/tests/VerifyBionicTerminationTest.cpp
index 680d7c2..c03fc6f 100644
--- a/libunwindstack/tests/VerifyBionicTerminationTest.cpp
+++ b/libunwindstack/tests/VerifyBionicTerminationTest.cpp
@@ -48,48 +48,62 @@ static std::string DumpFrames(const AndroidUnwinderData& data, AndroidUnwinder&
   return unwind;
 }
 
-static DwarfLocationEnum GetReturnAddressLocation(uint64_t rel_pc, DwarfSection* section) {
+static bool ReturnAddressLocationIsUndefined(ArchEnum arch, DwarfSection* section,
+                                             uint64_t rel_pc) {
   if (section == nullptr) {
-    return DWARF_LOCATION_INVALID;
+    return false;
   }
 
   const DwarfFde* fde = section->GetFdeFromPc(rel_pc);
   if (fde == nullptr || fde->cie == nullptr) {
-    return DWARF_LOCATION_INVALID;
+    return false;
   }
   DwarfLocations regs;
-  if (!section->GetCfaLocationInfo(rel_pc, fde, &regs, ARCH_UNKNOWN)) {
-    return DWARF_LOCATION_INVALID;
+  if (!section->GetCfaLocationInfo(rel_pc, fde, &regs, arch)) {
+    return false;
   }
 
   auto reg_entry = regs.find(fde->cie->return_address_register);
   if (reg_entry == regs.end()) {
-    return DWARF_LOCATION_INVALID;
+    return false;
   }
-  return reg_entry->second.type;
+  return reg_entry->second.type == DWARF_LOCATION_UNDEFINED;
 }
 
 static void VerifyReturnAddress(const FrameData& frame) {
-  // Now go and find information about the register data and verify that the relative pc results in
-  // an undefined register.
-  auto file_memory = Memory::CreateFileMemory(frame.map_info->name(), 0);
-  Elf elf(file_memory);
-  ASSERT_TRUE(frame.map_info != nullptr);
-  ASSERT_TRUE(elf.Init()) << "Failed to init elf object from " << frame.map_info->name().c_str();
-  ASSERT_TRUE(elf.valid()) << "Elf " << frame.map_info->name().c_str() << " is not valid.";
-  ElfInterface* interface = elf.interface();
-
-  // Only check the eh_frame and the debug_frame since the undefined register
-  // is set using a cfi directive.
-  // Check debug_frame first, then eh_frame since debug_frame always
-  // contains the most specific data.
-  DwarfLocationEnum location = GetReturnAddressLocation(frame.rel_pc, interface->debug_frame());
-  if (location == DWARF_LOCATION_UNDEFINED) {
+  Elf* elf = frame.map_info->GetElfObj();
+  ASSERT_NE(nullptr, elf) << "No elf object in map info frame";
+  ASSERT_TRUE(elf->valid()) << "No valid elf object in map info for frame";
+  ElfInterface* interface = elf->interface();
+  ASSERT_NE(nullptr, interface) << "Cannot find elf interface in elf object";
+
+  // The undefined register comes from a cfi directive set in __libc__init
+  // using the BIONIC_STOP_UNWIND macro.
+  // Look for this definition in these DwarfSections in this order:
+  //   debug_frame
+  //   eh_frame
+  //   gnu_debugdata debug_frame
+  //   gnu_debugdata eh_frame
+  // Always check debug_frame first since it usually conatins the most
+  // specific data.
+  if (ReturnAddressLocationIsUndefined(elf->arch(), interface->debug_frame(), frame.rel_pc)) {
+    return;
+  }
+  if (ReturnAddressLocationIsUndefined(elf->arch(), interface->eh_frame(), frame.rel_pc)) {
     return;
   }
 
-  location = GetReturnAddressLocation(frame.rel_pc, interface->eh_frame());
-  ASSERT_EQ(DWARF_LOCATION_UNDEFINED, location);
+  ElfInterface* gnu_debugdata = elf->gnu_debugdata_interface();
+  ASSERT_TRUE(gnu_debugdata != nullptr)
+      << "Could not find undefined return register in debug_frame or eh_frame";
+  if (ReturnAddressLocationIsUndefined(elf->arch(), gnu_debugdata->debug_frame(), frame.rel_pc)) {
+    return;
+  }
+  if (ReturnAddressLocationIsUndefined(elf->arch(), gnu_debugdata->eh_frame(), frame.rel_pc)) {
+    return;
+  }
+  FAIL() << "Could not find undefined return register in debug_frame, eh_frame, gnu_debugdata "
+            "debug_frame or gnu_debugdata eh_frame";
 }
 
 // This assumes that the function starts from the main thread, and that the
diff --git a/libunwindstack/tools/unwind.cpp b/libunwindstack/tools/unwind.cpp
index f3624e3..c4c9523 100644
--- a/libunwindstack/tools/unwind.cpp
+++ b/libunwindstack/tools/unwind.cpp
@@ -26,6 +26,14 @@
 #include <sys/types.h>
 #include <unistd.h>
 
+#include <algorithm>
+#include <string>
+#include <vector>
+
+#include <android-base/file.h>
+#include <android-base/stringprintf.h>
+#include <android-base/strings.h>
+#include <procinfo/process.h>
 #include <unwindstack/AndroidUnwinder.h>
 #include <unwindstack/Regs.h>
 
@@ -51,35 +59,37 @@ static bool Attach(pid_t pid) {
   return false;
 }
 
-void DoUnwind(pid_t pid) {
+void DoUnwind(pid_t pid, bool print_abi = false) {
   unwindstack::Regs* regs = unwindstack::Regs::RemoteGet(pid);
   if (regs == nullptr) {
     printf("Unable to get remote reg data\n");
     return;
   }
 
-  printf("ABI: ");
-  switch (regs->Arch()) {
-    case unwindstack::ARCH_ARM:
-      printf("arm");
-      break;
-    case unwindstack::ARCH_X86:
-      printf("x86");
-      break;
-    case unwindstack::ARCH_ARM64:
-      printf("arm64");
-      break;
-    case unwindstack::ARCH_X86_64:
-      printf("x86_64");
-      break;
-    case unwindstack::ARCH_RISCV64:
-      printf("riscv64");
-      break;
-    default:
-      printf("unknown\n");
-      return;
+  if (print_abi) {
+    printf("ABI: ");
+    switch (regs->Arch()) {
+      case unwindstack::ARCH_ARM:
+        printf("arm");
+        break;
+      case unwindstack::ARCH_X86:
+        printf("x86");
+        break;
+      case unwindstack::ARCH_ARM64:
+        printf("arm64");
+        break;
+      case unwindstack::ARCH_X86_64:
+        printf("x86_64");
+        break;
+      case unwindstack::ARCH_RISCV64:
+        printf("riscv64");
+        break;
+      default:
+        printf("unknown\n");
+        return;
+    }
+    printf("\n");
   }
-  printf("\n");
 
   unwindstack::AndroidRemoteUnwinder unwinder(pid);
   unwindstack::AndroidUnwinderData data;
@@ -107,9 +117,51 @@ int main(int argc, char** argv) {
     return 1;
   }
 
-  DoUnwind(pid);
+  std::string proc(android::base::StringPrintf("/proc/%d/", pid));
+  printf("Pid: %d\n", pid);
+  std::string executable;
+  android::base::Readlink(proc + "exe", &executable);
+  if (executable.empty()) {
+    executable = "Unknown";
+  }
+  printf("Executable: %s\n", executable.c_str());
+  std::string cmdline;
+  android::base::ReadFileToString(proc + "cmdline", &cmdline);
+  if (cmdline.empty()) {
+    cmdline = "Unknown";
+  }
+  printf("Command Line: %s\n", cmdline.c_str());
+
+  DoUnwind(pid, /*print_abi*/ true);
 
   ptrace(PTRACE_DETACH, pid, 0, 0);
 
+  std::vector<pid_t> tids;
+  android::procinfo::GetProcessTids(pid, &tids);
+  std::sort(tids.begin(), tids.end());
+  for (const auto& tid : tids) {
+    if (tid == pid) {
+      // Main thread has already been unwound.
+      continue;
+    }
+    if (!Attach(tid)) {
+      printf("Failed to attach to pid %d: %s\n", tid, strerror(errno));
+      return 1;
+    }
+
+    std::string thread_name;
+    android::base::ReadFileToString(android::base::StringPrintf("/proc/%d/comm", tid),
+                                    &thread_name);
+    thread_name = android::base::Trim(thread_name);
+    if (thread_name.empty()) {
+      thread_name = "Unknown Thread";
+    }
+    printf("\nTid: %d Thread name: %s\n", tid, thread_name.c_str());
+
+    DoUnwind(tid);
+
+    ptrace(PTRACE_DETACH, tid, 0, 0);
+  }
+
   return 0;
 }
diff --git a/libunwindstack/utils/RegsFake.h b/libunwindstack/utils/RegsFake.h
index 634afe6..de87591 100644
--- a/libunwindstack/utils/RegsFake.h
+++ b/libunwindstack/utils/RegsFake.h
@@ -46,6 +46,9 @@ class RegsFake : public Regs {
     return true;
   }
 
+  void SetExtraRegister(uint16_t, uint64_t) override {}
+  uint64_t GetExtraRegister(uint16_t) override { return 0; }
+
   void IterateRegisters(std::function<void(const char*, uint64_t)>) override {}
 
   bool Is32Bit() {
@@ -74,7 +77,10 @@ template <typename TypeParam>
 class RegsImplFake : public RegsImpl<TypeParam> {
  public:
   RegsImplFake(uint16_t total_regs)
-      : RegsImpl<TypeParam>(total_regs, Regs::Location(Regs::LOCATION_UNKNOWN, 0)) {}
+      : RegsImpl<TypeParam>(total_regs, 0, Regs::Location(Regs::LOCATION_UNKNOWN, 0)) {}
+  RegsImplFake(uint16_t total_regs, uint16_t total_extra_regs)
+      : RegsImpl<TypeParam>(total_regs, total_extra_regs,
+                            Regs::Location(Regs::LOCATION_UNKNOWN, 0)) {}
   virtual ~RegsImplFake() = default;
 
   ArchEnum Arch() override { return ARCH_UNKNOWN; }
```

