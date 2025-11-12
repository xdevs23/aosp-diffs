```diff
diff --git a/Android.bp b/Android.bp
index 9f8065d6..aa1f83b8 100644
--- a/Android.bp
+++ b/Android.bp
@@ -300,6 +300,20 @@ cc_test_host {
     },
 }
 
+filegroup {
+    name: "berberis_host_tests_data_32",
+    srcs: [
+        "tiny_loader/tests/files/32/*",
+    ],
+}
+
+filegroup {
+    name: "berberis_host_tests_data_64",
+    srcs: [
+        "tiny_loader/tests/files/64/*",
+    ],
+}
+
 // Clang violates psABI: https://groups.google.com/g/x86-64-abi/c/BjOOyihHuqg
 // We want to esnrue that possible fix of this bug wouldn't be unnoticed: b/382703210
 cc_test_host {
@@ -349,22 +363,84 @@ cc_test_host {
     },
 }
 
+// This module is used as a workaround to define those deps of berberis_all_deps_defaults which are native_bridge only.
+ndk_translation_package {
+    name: "berberis_all_deps_intermediate_package",
+    compile_multilib: "both",
+    native_bridge_supported: true,
+    native_bridge_deps: [
+        "berberis_hello_world",
+        "berberis_hello_world_static",
+        "berberis_ndk_program_tests",
+        "berberis_perf_tests_static",
+    ],
+    generate_build_files: false,
+}
+
 phony_rule_defaults {
     name: "berberis_all_deps_defaults",
     phony_deps: [
-        "berberis_hello_world.native_bridge",
-        "berberis_hello_world_static.native_bridge",
         "berberis_host_tests",
         "berberis_host_tests_avx",
         "berberis_host_tests_no_avx",
         "berberis_ndk_program_tests",
-        "berberis_ndk_program_tests.native_bridge",
-        "berberis_perf_tests_static.native_bridge",
         "dwarf_reader",
         "libberberis_emulated_libcamera2ndk_api_checker",
         "nogrod_unit_tests",
         "gen_intrinsics_tests",
+        // The intermediate packages to declare those deps which are native_bridge variant.
+        "berberis_all_deps_intermediate_package",
+    ],
+}
+
+// This module is used as a workaround to define those deps of berberis_all_deps_defaults which are native_bridge only.
+ndk_translation_package {
+    name: "berberis_all_riscv64_to_x86_64_intermediate_package",
+    compile_multilib: "both",
+    native_bridge_supported: true,
+    native_bridge_deps: [
+        // NATIVE_BRIDGE_PRODUCT_PACKAGES
+        "libnative_bridge_vdso",
+        "native_bridge_guest_app_process",
+        "native_bridge_guest_linker",
+        "libandroidicu",
+        "libcompiler_rt",
+        "libcrypto",
+        "libcutils",
+        "libdl",
+        "libdl_android",
+        "libicu",
+        "liblog",
+        "libm",
+        "libsqlite",
+        "libssl",
+        "libstdc++",
+        "libsync",
+        "libutils",
+        "libz",
+        // NATIVE_BRIDGE_MODIFIED_GUEST_LIBS
+        "libnative_bridge_guest_libaaudio",
+        "libnative_bridge_guest_libamidi",
+        "libnative_bridge_guest_libandroid",
+        "libnative_bridge_guest_libandroid_runtime",
+        "libnative_bridge_guest_libbinder_ndk",
+        "//frameworks/libs/native_bridge_support/android_api/libc:libnative_bridge_guest_libc",
+        "libnative_bridge_guest_libcamera2ndk",
+        "libnative_bridge_guest_libEGL",
+        "libnative_bridge_guest_libGLESv1_CM",
+        "libnative_bridge_guest_libGLESv2",
+        "libnative_bridge_guest_libGLESv3",
+        "libnative_bridge_guest_libjnigraphics",
+        "libnative_bridge_guest_libmediandk",
+        "libnative_bridge_guest_libnativehelper",
+        "libnative_bridge_guest_libnativewindow",
+        "libnative_bridge_guest_libneuralnetworks",
+        "libnative_bridge_guest_libOpenMAXAL",
+        "libnative_bridge_guest_libOpenSLES",
+        "libnative_bridge_guest_libvulkan",
+        "libnative_bridge_guest_libwebviewchromium_plat_support",
     ],
+    generate_build_files: false,
 }
 
 // Note: Keep in sync with variables from `berberis_config.mk` and
@@ -397,47 +473,8 @@ phony_rule_defaults {
         "berberis_program_runner_binfmt_misc_riscv64",
         "berberis_program_runner_riscv64",
         "libberberis_riscv64",
-        // NATIVE_BRIDGE_PRODUCT_PACKAGES
-        "libnative_bridge_vdso.native_bridge",
-        "native_bridge_guest_app_process.native_bridge",
-        "native_bridge_guest_linker.native_bridge",
-        // $(addsuffix .native_bridge,$(NATIVE_BRIDGE_ORIG_GUEST_LIBS))
-        "libandroidicu.bootstrap.native_bridge",
-        "libcompiler_rt.native_bridge",
-        "libcrypto.native_bridge",
-        "libcutils.native_bridge",
-        "libdl.bootstrap.native_bridge",
-        "libdl_android.bootstrap.native_bridge",
-        "libicu.bootstrap.native_bridge",
-        "liblog.native_bridge",
-        "libm.bootstrap.native_bridge",
-        "libsqlite.native_bridge",
-        "libssl.native_bridge",
-        "libstdc++.native_bridge",
-        "libsync.native_bridge",
-        "libutils.native_bridge",
-        "libz.native_bridge",
-        // NATIVE_BRIDGE_MODIFIED_GUEST_LIBS
-        "libnative_bridge_guest_libaaudio.native_bridge",
-        "libnative_bridge_guest_libamidi.native_bridge",
-        "libnative_bridge_guest_libandroid.native_bridge",
-        "libnative_bridge_guest_libandroid_runtime.native_bridge",
-        "libnative_bridge_guest_libbinder_ndk.native_bridge",
-        "libnative_bridge_guest_libc.native_bridge",
-        "libnative_bridge_guest_libcamera2ndk.native_bridge",
-        "libnative_bridge_guest_libEGL.native_bridge",
-        "libnative_bridge_guest_libGLESv1_CM.native_bridge",
-        "libnative_bridge_guest_libGLESv2.native_bridge",
-        "libnative_bridge_guest_libGLESv3.native_bridge",
-        "libnative_bridge_guest_libjnigraphics.native_bridge",
-        "libnative_bridge_guest_libmediandk.native_bridge",
-        "libnative_bridge_guest_libnativehelper.native_bridge",
-        "libnative_bridge_guest_libnativewindow.native_bridge",
-        "libnative_bridge_guest_libneuralnetworks.native_bridge",
-        "libnative_bridge_guest_libOpenMAXAL.native_bridge",
-        "libnative_bridge_guest_libOpenSLES.native_bridge",
-        "libnative_bridge_guest_libvulkan.native_bridge",
-        "libnative_bridge_guest_libwebviewchromium_plat_support.native_bridge",
+        // The intermediate packages to declare those deps which are native_bridge variant.
+        "berberis_all_riscv64_to_x86_64_intermediate_package",
         // Everything else.
         "berberis_guest_loader_riscv64_tests",
     ],
@@ -479,3 +516,9 @@ berberis_phony_rule {
         },
     },
 }
+
+python_binary_host {
+    name: "berberis_gen_gtest_failure_template",
+    main: "tests/gen_gtest_failure_template.py",
+    srcs: ["tests/gen_gtest_failure_template.py"],
+}
diff --git a/assembler/Android.bp b/assembler/Android.bp
index 3e5af686..fd7d6145 100644
--- a/assembler/Android.bp
+++ b/assembler/Android.bp
@@ -43,7 +43,7 @@ filegroup {
     name: "libberberis_assembler_gen_inputs_riscv32",
     srcs: [
         "instructions/insn_def_riscv.json",
-        "instructions/insn_def_rv32.json",
+        "instructions/insn_def_riscv32.json",
     ],
 }
 
@@ -51,7 +51,7 @@ filegroup {
     name: "libberberis_assembler_gen_inputs_riscv64",
     srcs: [
         "instructions/insn_def_riscv.json",
-        "instructions/insn_def_rv64.json",
+        "instructions/insn_def_riscv64.json",
     ],
 }
 
@@ -85,7 +85,7 @@ genrule {
     name: "libberberis_assembler_gen_public_headers_riscv32",
     out: [
         "berberis/assembler/gen_assembler_common_riscv-inl.h",
-        "berberis/assembler/gen_assembler_rv32-inl.h",
+        "berberis/assembler/gen_assembler_riscv32-inl.h",
     ],
     srcs: [":libberberis_assembler_gen_inputs_riscv32"],
     tools: ["gen_asm"],
@@ -94,7 +94,7 @@ genrule {
 
 genrule {
     name: "libberberis_assembler_gen_public_headers_using_riscv32",
-    out: ["berberis/assembler/gen_assembler_rv32-using-inl.h"],
+    out: ["berberis/assembler/gen_assembler_riscv32-using-inl.h"],
     srcs: [":libberberis_assembler_gen_inputs_riscv32"],
     tools: ["gen_asm"],
     cmd: "$(location gen_asm) --using $(out) $(in)",
@@ -104,7 +104,7 @@ genrule {
     name: "libberberis_assembler_gen_public_headers_riscv64",
     out: [
         "berberis/assembler/gen_assembler_common_riscv-inl.h",
-        "berberis/assembler/gen_assembler_rv64-inl.h",
+        "berberis/assembler/gen_assembler_riscv64-inl.h",
     ],
     srcs: [":libberberis_assembler_gen_inputs_riscv64"],
     tools: ["gen_asm"],
@@ -113,7 +113,7 @@ genrule {
 
 genrule {
     name: "libberberis_assembler_gen_public_headers_using_riscv64",
-    out: ["berberis/assembler/gen_assembler_rv64-using-inl.h"],
+    out: ["berberis/assembler/gen_assembler_riscv64-using-inl.h"],
     srcs: [":libberberis_assembler_gen_inputs_riscv64"],
     tools: ["gen_asm"],
     cmd: "$(location gen_asm) --using $(out) $(in)",
@@ -130,7 +130,7 @@ genrule {
 genrule {
     name: "libberberis_assembler_gen_public_headers_x86_32",
     out: [
-        "berberis/assembler/gen_assembler_x86_32_and_x86_64-inl.h",
+        "berberis/assembler/gen_assembler_x86_32_or_x86_64-inl.h",
         "berberis/assembler/gen_assembler_x86_32-inl.h",
     ],
     srcs: [":libberberis_assembler_gen_inputs_x86_32"],
@@ -149,7 +149,7 @@ genrule {
 genrule {
     name: "libberberis_assembler_gen_public_headers_x86_64",
     out: [
-        "berberis/assembler/gen_assembler_x86_32_and_x86_64-inl.h",
+        "berberis/assembler/gen_assembler_x86_32_or_x86_64-inl.h",
         "berberis/assembler/gen_assembler_x86_64-inl.h",
     ],
     srcs: [":libberberis_assembler_gen_inputs_x86_64"],
diff --git a/assembler/assembler_test.cc b/assembler/assembler_test.cc
index 6dc2e9bc..7f327504 100644
--- a/assembler/assembler_test.cc
+++ b/assembler/assembler_test.cc
@@ -37,7 +37,7 @@ using CodeEmitter = berberis::x86_32::Assembler;
 #elif defined(__amd64__)
 using CodeEmitter = berberis::x86_64::Assembler;
 #elif defined(__riscv)
-using CodeEmitter = berberis::rv64::Assembler;
+using CodeEmitter = berberis::riscv64::Assembler;
 #else
 #error "Unsupported platform"
 #endif
@@ -115,7 +115,7 @@ inline bool CompareCode(const ParcelInt* code_template_begin,
   return true;
 }
 
-namespace rv32 {
+namespace riscv32 {
 
 bool AssemblerTest() {
   MachineCode code;
@@ -311,9 +311,9 @@ bool AssemblerTest() {
   return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code, CPUArch::kRiscv64);
 }
 
-}  // namespace rv32
+}  // namespace riscv32
 
-namespace rv64 {
+namespace riscv64 {
 
 bool AssemblerTest() {
   MachineCode code;
@@ -507,7 +507,7 @@ bool AssemblerTest() {
   return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code, CPUArch::kRiscv64);
 }
 
-}  // namespace rv64
+}  // namespace riscv64
 
 namespace x86_32 {
 
@@ -1309,8 +1309,8 @@ bool MixedAssembler() {
 }  // namespace berberis
 
 TEST(Assembler, AssemblerTest) {
-  EXPECT_TRUE(berberis::rv32::AssemblerTest());
-  EXPECT_TRUE(berberis::rv64::AssemblerTest());
+  EXPECT_TRUE(berberis::riscv32::AssemblerTest());
+  EXPECT_TRUE(berberis::riscv64::AssemblerTest());
   EXPECT_TRUE(berberis::x86_32::AssemblerTest());
   EXPECT_TRUE(berberis::x86_64::AssemblerTest());
 #if defined(__i386__)
diff --git a/assembler/gen_asm.py b/assembler/gen_asm.py
index be960188..556af574 100644
--- a/assembler/gen_asm.py
+++ b/assembler/gen_asm.py
@@ -204,7 +204,10 @@ def _gen_register_read_write_info(insn, arch):
       if (_get_arg_type_name(arg, insn.get('type', None)) in register_types_to_gen
           and 'x86' in arch):
         if arg.get('usage') == usage or arg.get('usage') == "use_def":
-          yield '  Register%s(arg%d);' % (usage.capitalize(), arg_count)
+          if usage == 'def' and arg.get('class') == "GeneralReg32":
+            yield '  Register%s(arg%d, true);' % (usage.capitalize(), arg_count)
+          else:
+            yield '  Register%s(arg%d);' % (usage.capitalize(), arg_count)
       arg_count += 1
 
 def _check_insn_uses_xmm(insn, arch):
@@ -526,7 +529,7 @@ def _gen_emit_instruction(f, insn, arch, rip_operand=False, dyn_rm=False):
       continue
     # Note: in RISC-V there is never any ambiguity about whether full register or its part is used.
     # Instead size of operand is always encoded in the name, e.g. addw vs add or fadd.s vs fadd.d
-    if arch in ['common_riscv', 'rv32', 'rv64']:
+    if arch in ['riscv', 'riscv32', 'riscv64']:
       if dyn_rm and arg['class'] == 'Rm':
         result.append('Rounding::kDyn')
       else:
diff --git a/assembler/immediates_test.cc b/assembler/immediates_test.cc
index 228dcb1a..15efb280 100644
--- a/assembler/immediates_test.cc
+++ b/assembler/immediates_test.cc
@@ -20,8 +20,8 @@
 #include <optional>
 #include <tuple>
 
-#include "berberis/assembler/rv32.h"
-#include "berberis/assembler/rv64.h"
+#include "berberis/assembler/riscv32.h"
+#include "berberis/assembler/riscv64.h"
 
 namespace berberis {
 
@@ -73,10 +73,10 @@ class Riscv64ImmediatesTest : public ::testing::Test {
               uint32_t raw_immediate_value = result->EncodedValue();
               // RISC-V I-ImmediateType and S-Immediate support the same set of values and could be
               // converted from one to another, but other types of immediates are unique.
-              if constexpr (std::is_same_v<ImmediateType, rv64::Assembler::Immediate>) {
-                EXPECT_EQ(ImmediateType(rv64::Assembler::SImmediate(typed_source)), *result);
-              } else if constexpr (std::is_same_v<ImmediateType, rv64::Assembler::SImmediate>) {
-                EXPECT_EQ(ImmediateType(rv64::Assembler::Immediate(typed_source)), *result);
+              if constexpr (std::is_same_v<ImmediateType, riscv64::Assembler::Immediate>) {
+                EXPECT_EQ(ImmediateType(riscv64::Assembler::SImmediate(typed_source)), *result);
+              } else if constexpr (std::is_same_v<ImmediateType, riscv64::Assembler::SImmediate>) {
+                EXPECT_EQ(ImmediateType(riscv64::Assembler::Immediate(typed_source)), *result);
               }
               EXPECT_EQ(raw_immediate_value, *expected_result);
               ImmediateType result = ImmediateType(source);
@@ -503,15 +503,15 @@ TEST_F(Riscv64ImmediatesTest, TestPImmediate) {
 
 TEST_F(Riscv64ImmediatesTest, TestShiftImmediate) {
   using T = std::tuple<uint32_t, std::optional<uint32_t>>;
-  TestConversion<rv32::Assembler::ShiftImmediate,
-                 rv32::Assembler::MakeShiftImmediate,
-                 rv32::Assembler::MakeShiftImmediate,
-                 rv32::Assembler::MakeShiftImmediate,
-                 rv32::Assembler::MakeShiftImmediate,
-                 rv32::Assembler::MakeShiftImmediate,
-                 rv32::Assembler::MakeShiftImmediate,
-                 rv32::Assembler::MakeShiftImmediate,
-                 rv32::Assembler::MakeShiftImmediate>(std::array{
+  TestConversion<riscv32::Assembler::ShiftImmediate,
+                 riscv32::Assembler::MakeShiftImmediate,
+                 riscv32::Assembler::MakeShiftImmediate,
+                 riscv32::Assembler::MakeShiftImmediate,
+                 riscv32::Assembler::MakeShiftImmediate,
+                 riscv32::Assembler::MakeShiftImmediate,
+                 riscv32::Assembler::MakeShiftImmediate,
+                 riscv32::Assembler::MakeShiftImmediate,
+                 riscv32::Assembler::MakeShiftImmediate>(std::array{
       T{0b000000000000000000000'000000'0000'0, 0b0'00000000000'00000'000'00000'0000000},
       //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
       T{0b000000000000000000000'000000'0000'1, 0b0'00000000001'00000'000'00000'0000000},
@@ -580,15 +580,15 @@ TEST_F(Riscv64ImmediatesTest, TestShiftImmediate) {
       T{0b110000000000000000000'000000'0000'0, {}},
       T{0b100000000000000000000'000000'0000'0, {}},
   });
-  TestConversion<rv64::Assembler::ShiftImmediate,
-                 rv64::Assembler::MakeShiftImmediate,
-                 rv64::Assembler::MakeShiftImmediate,
-                 rv64::Assembler::MakeShiftImmediate,
-                 rv64::Assembler::MakeShiftImmediate,
-                 rv64::Assembler::MakeShiftImmediate,
-                 rv64::Assembler::MakeShiftImmediate,
-                 rv64::Assembler::MakeShiftImmediate,
-                 rv64::Assembler::MakeShiftImmediate>(std::array{
+  TestConversion<riscv64::Assembler::ShiftImmediate,
+                 riscv64::Assembler::MakeShiftImmediate,
+                 riscv64::Assembler::MakeShiftImmediate,
+                 riscv64::Assembler::MakeShiftImmediate,
+                 riscv64::Assembler::MakeShiftImmediate,
+                 riscv64::Assembler::MakeShiftImmediate,
+                 riscv64::Assembler::MakeShiftImmediate,
+                 riscv64::Assembler::MakeShiftImmediate,
+                 riscv64::Assembler::MakeShiftImmediate>(std::array{
       T{0b000000000000000000000'000000'0000'0, 0b0'00000000000'00000'000'00000'0000000},
       //  31                 11 10   5 4  1 0   31 30       20 19 15     11  7 6     0
       T{0b000000000000000000000'000000'0000'1, 0b0'00000000001'00000'000'00000'0000000},
diff --git a/assembler/include/berberis/assembler/rv32.h b/assembler/include/berberis/assembler/riscv32.h
similarity index 88%
rename from assembler/include/berberis/assembler/rv32.h
rename to assembler/include/berberis/assembler/riscv32.h
index be8af904..3edc366a 100644
--- a/assembler/include/berberis/assembler/rv32.h
+++ b/assembler/include/berberis/assembler/riscv32.h
@@ -16,14 +16,14 @@
 
 // Assembler to produce RV32 instructions (no ABI version). Somewhat influenced by V8 assembler.
 
-#ifndef BERBERIS_ASSEMBLER_RV32_H_
-#define BERBERIS_ASSEMBLER_RV32_H_
+#ifndef BERBERIS_ASSEMBLER_RISCV32_H_
+#define BERBERIS_ASSEMBLER_RISCV32_H_
 
 #include <type_traits>  // std::is_same
 
 #include "berberis/assembler/riscv.h"
 
-namespace berberis::rv32 {
+namespace berberis::riscv32 {
 
 class Assembler : public riscv::Assembler<Assembler> {
  public:
@@ -52,7 +52,7 @@ class Assembler : public riscv::Assembler<Assembler> {
   friend BaseAssembler;
 
 // Instructions.
-#include "berberis/assembler/gen_assembler_rv32-inl.h"  // NOLINT generated file!
+#include "berberis/assembler/gen_assembler_riscv32-inl.h"  // NOLINT generated file!
 
  private:
   Assembler() = delete;
@@ -63,6 +63,6 @@ class Assembler : public riscv::Assembler<Assembler> {
   friend BaseAssembler;
 };
 
-}  // namespace berberis::rv32
+}  // namespace berberis::riscv32
 
-#endif  // BERBERIS_ASSEMBLER_RV32_H_
+#endif  // BERBERIS_ASSEMBLER_RISCV32_H_
diff --git a/assembler/include/berberis/assembler/rv64.h b/assembler/include/berberis/assembler/riscv64.h
similarity index 94%
rename from assembler/include/berberis/assembler/rv64.h
rename to assembler/include/berberis/assembler/riscv64.h
index 02200cc9..6bcb62fc 100644
--- a/assembler/include/berberis/assembler/rv64.h
+++ b/assembler/include/berberis/assembler/riscv64.h
@@ -16,15 +16,15 @@
 
 // Assembler to produce RV64 instructions (no ABI version). Somewhat influenced by V8 assembler.
 
-#ifndef BERBERIS_ASSEMBLER_RV64_H_
-#define BERBERIS_ASSEMBLER_RV64_H_
+#ifndef BERBERIS_ASSEMBLER_RISCV64_H_
+#define BERBERIS_ASSEMBLER_RISCV64_H_
 
 #include <bit>          // std::countr_zero
 #include <type_traits>  // std::is_same
 
 #include "berberis/assembler/riscv.h"
 
-namespace berberis::rv64 {
+namespace berberis::riscv64 {
 
 class Assembler : public riscv::Assembler<Assembler> {
  public:
@@ -53,7 +53,7 @@ class Assembler : public riscv::Assembler<Assembler> {
   friend BaseAssembler;
 
 // Instructions.
-#include "berberis/assembler/gen_assembler_rv64-inl.h"  // NOLINT generated file!
+#include "berberis/assembler/gen_assembler_riscv64-inl.h"  // NOLINT generated file!
 
  private:
   Assembler() = delete;
@@ -130,6 +130,6 @@ constexpr inline void Assembler::Negw(Register arg0, Register arg1) {
   Subw(arg0, zero, arg1);
 }
 
-}  // namespace berberis::rv64
+}  // namespace berberis::riscv64
 
-#endif  // BERBERIS_ASSEMBLER_RV64_H_
+#endif  // BERBERIS_ASSEMBLER_RISCV64_H_
diff --git a/assembler/include/berberis/assembler/rv32e.h b/assembler/include/berberis/assembler/rv32e.h
index da000079..aa78656a 100644
--- a/assembler/include/berberis/assembler/rv32e.h
+++ b/assembler/include/berberis/assembler/rv32e.h
@@ -21,16 +21,16 @@
 
 #include <type_traits>  // std::is_same
 
-#include "berberis/assembler/rv32.h"
+#include "berberis/assembler/riscv32.h"
 
 namespace berberis::rv32e {
 
-class Assembler : public ::berberis::rv32::Assembler {
+class Assembler : public ::berberis::riscv32::Assembler {
  public:
-  using BaseAssembler = riscv::Assembler<::berberis::rv32::Assembler>;
-  using FinalAssembler = berberis::rv32::Assembler;
+  using BaseAssembler = riscv::Assembler<::berberis::riscv32::Assembler>;
+  using FinalAssembler = berberis::riscv32::Assembler;
 
-  explicit Assembler(MachineCode* code) : berberis::rv32::Assembler(code) {}
+  explicit Assembler(MachineCode* code) : berberis::riscv32::Assembler(code) {}
 
   // Registers available used on “small” CPUs (with 16 general purpose registers) and “big” CPUs (32
   // general purpose registers).
diff --git a/assembler/include/berberis/assembler/rv32i.h b/assembler/include/berberis/assembler/rv32i.h
index e671aee5..eada72d9 100644
--- a/assembler/include/berberis/assembler/rv32i.h
+++ b/assembler/include/berberis/assembler/rv32i.h
@@ -21,18 +21,18 @@
 
 #include <type_traits>  // std::is_same
 
-#include "berberis/assembler/rv32.h"
+#include "berberis/assembler/riscv32.h"
 
 namespace berberis {
 
 namespace rv32i {
 
-class Assembler : public ::berberis::rv32::Assembler {
+class Assembler : public ::berberis::riscv32::Assembler {
  public:
-  using BaseAssembler = riscv::Assembler<::berberis::rv32::Assembler>;
-  using FinalAssembler = ::berberis::rv32::Assembler;
+  using BaseAssembler = riscv::Assembler<::berberis::riscv32::Assembler>;
+  using FinalAssembler = ::berberis::riscv32::Assembler;
 
-  explicit Assembler(MachineCode* code) : berberis::rv32::Assembler(code) {}
+  explicit Assembler(MachineCode* code) : berberis::riscv32::Assembler(code) {}
 
   static constexpr Register ra{1};
   static constexpr Register sp{2};
diff --git a/assembler/include/berberis/assembler/rv64i.h b/assembler/include/berberis/assembler/rv64i.h
index 8bd818ab..c86a4da9 100644
--- a/assembler/include/berberis/assembler/rv64i.h
+++ b/assembler/include/berberis/assembler/rv64i.h
@@ -21,18 +21,18 @@
 
 #include <type_traits>  // std::is_same
 
-#include "berberis/assembler/rv64.h"
+#include "berberis/assembler/riscv64.h"
 
 namespace berberis {
 
 namespace rv64i {
 
-class Assembler : public ::berberis::rv64::Assembler {
+class Assembler : public ::berberis::riscv64::Assembler {
  public:
-  using BaseAssembler = riscv::Assembler<::berberis::rv64::Assembler>;
-  using FinalAssembler = ::berberis::rv64::Assembler;
+  using BaseAssembler = riscv::Assembler<::berberis::riscv64::Assembler>;
+  using FinalAssembler = ::berberis::riscv64::Assembler;
 
-  explicit Assembler(MachineCode* code) : berberis::rv64::Assembler(code) {}
+  explicit Assembler(MachineCode* code) : berberis::riscv64::Assembler(code) {}
 
   static constexpr Register ra{1};
   static constexpr Register sp{2};
diff --git a/assembler/include/berberis/assembler/x86_32.h b/assembler/include/berberis/assembler/x86_32.h
index 35bdf4aa..48ab4e50 100644
--- a/assembler/include/berberis/assembler/x86_32.h
+++ b/assembler/include/berberis/assembler/x86_32.h
@@ -21,15 +21,15 @@
 
 #include <type_traits>  // std::is_same
 
-#include "berberis/assembler/x86_32_and_x86_64.h"
+#include "berberis/assembler/x86_32_or_x86_64.h"
 
 namespace berberis {
 
 namespace x86_32 {
 
-class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
+class Assembler : public x86_32_or_x86_64::Assembler<Assembler> {
  public:
-  using BaseAssembler = x86_32_and_x86_64::Assembler<Assembler>;
+  using BaseAssembler = x86_32_or_x86_64::Assembler<Assembler>;
   using FinalAssembler = Assembler;
 
   explicit Assembler(MachineCode* code) : BaseAssembler(code) {}
diff --git a/assembler/include/berberis/assembler/x86_32_and_x86_64.h b/assembler/include/berberis/assembler/x86_32_or_x86_64.h
similarity index 99%
rename from assembler/include/berberis/assembler/x86_32_and_x86_64.h
rename to assembler/include/berberis/assembler/x86_32_or_x86_64.h
index 32f65d46..72d91de6 100644
--- a/assembler/include/berberis/assembler/x86_32_and_x86_64.h
+++ b/assembler/include/berberis/assembler/x86_32_or_x86_64.h
@@ -14,8 +14,8 @@
  * limitations under the License.
  */
 
-#ifndef BERBERIS_ASSEMBLER_X86_32_AND_X86_64_H_
-#define BERBERIS_ASSEMBLER_X86_32_AND_X86_64_H_
+#ifndef BERBERIS_ASSEMBLER_X86_32_OR_X86_64_H_
+#define BERBERIS_ASSEMBLER_X86_32_OR_X86_64_H_
 
 #include <cstddef>  // std::size_t
 #include <cstdint>
@@ -52,7 +52,7 @@ class Assembler;
 
 }  // namespace x86_64
 
-namespace x86_32_and_x86_64 {
+namespace x86_32_or_x86_64 {
 
 template <typename DerivedAssemblerType>
 class Assembler : public AssemblerBase {
@@ -283,7 +283,7 @@ class Assembler : public AssemblerBase {
   }
 
 // Instructions.
-#include "berberis/assembler/gen_assembler_x86_32_and_x86_64-inl.h"  // NOLINT generated file
+#include "berberis/assembler/gen_assembler_x86_32_or_x86_64-inl.h"  // NOLINT generated file
 
   // Flow control.
   void JmpRel(int32_t offset) {
@@ -938,8 +938,8 @@ constexpr inline void Assembler<DerivedAssemblerType>::Xchgl(Register dest, Regi
   }
 }
 
-}  // namespace x86_32_and_x86_64
+}  // namespace x86_32_or_x86_64
 
 }  // namespace berberis
 
-#endif  // BERBERIS_ASSEMBLER_X86_32_AND_X86_64_H_
+#endif  // BERBERIS_ASSEMBLER_X86_32_OR_X86_64_H_
diff --git a/assembler/include/berberis/assembler/x86_64.h b/assembler/include/berberis/assembler/x86_64.h
index 786ae76b..bc1b0d09 100644
--- a/assembler/include/berberis/assembler/x86_64.h
+++ b/assembler/include/berberis/assembler/x86_64.h
@@ -21,7 +21,7 @@
 
 #include <type_traits>  // std::is_same
 
-#include "berberis/assembler/x86_32_and_x86_64.h"
+#include "berberis/assembler/x86_32_or_x86_64.h"
 #include "berberis/base/logging.h"
 
 namespace berberis {
@@ -30,9 +30,9 @@ class MachindeCode;
 
 namespace x86_64 {
 
-class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
+class Assembler : public x86_32_or_x86_64::Assembler<Assembler> {
  public:
-  using BaseAssembler = x86_32_and_x86_64::Assembler<Assembler>;
+  using BaseAssembler = x86_32_or_x86_64::Assembler<Assembler>;
   using FinalAssembler = Assembler;
 
   explicit Assembler(MachineCode* code) : BaseAssembler(code) {}
diff --git a/assembler/instructions/insn_def_riscv.json b/assembler/instructions/insn_def_riscv.json
index d5ce3a42..9742ddcc 100644
--- a/assembler/instructions/insn_def_riscv.json
+++ b/assembler/instructions/insn_def_riscv.json
@@ -14,7 +14,7 @@
     "See the License for the specific language governing permissions and",
     "limitations under the License."
   ],
-  "arch": "common_riscv",
+  "arch": "riscv",
   "insns": [
     {
       "encodings": {
diff --git a/assembler/instructions/insn_def_rv32.json b/assembler/instructions/insn_def_riscv32.json
similarity index 98%
rename from assembler/instructions/insn_def_rv32.json
rename to assembler/instructions/insn_def_riscv32.json
index 4ac7697c..bfc9c97d 100644
--- a/assembler/instructions/insn_def_rv32.json
+++ b/assembler/instructions/insn_def_riscv32.json
@@ -14,7 +14,7 @@
     "See the License for the specific language governing permissions and",
     "limitations under the License."
   ],
-  "arch": "rv32",
+  "arch": "riscv32",
   "insns": [
     {
       "encodings": {
diff --git a/assembler/instructions/insn_def_rv64.json b/assembler/instructions/insn_def_riscv64.json
similarity index 99%
rename from assembler/instructions/insn_def_rv64.json
rename to assembler/instructions/insn_def_riscv64.json
index ab544a0c..f6217a40 100644
--- a/assembler/instructions/insn_def_rv64.json
+++ b/assembler/instructions/insn_def_riscv64.json
@@ -14,7 +14,7 @@
     "See the License for the specific language governing permissions and",
     "limitations under the License."
   ],
-  "arch": "rv64",
+  "arch": "riscv64",
   "insns": [
     {
       "encodings": {
diff --git a/backend/Android.bp b/backend/Android.bp
index 8a0aef2a..6cca87c0 100644
--- a/backend/Android.bp
+++ b/backend/Android.bp
@@ -30,28 +30,11 @@ python_library_host {
     libs: ["asm_defs_lib"],
 }
 
-python_binary_host {
-    name: "berberis_gen_reg_class",
-    main: "gen_reg_class.py",
-    srcs: ["gen_reg_class.py"],
-    libs: ["gen_reg_class_lib"],
-}
-
-python_library_host {
-    name: "gen_reg_class_lib",
-    srcs: ["gen_reg_class_lib.py"],
-}
-
 filegroup {
     name: "libberberis_backend_machine_ir_gen_inputs_x86_64",
     srcs: ["x86_64/lir_instructions.json"],
 }
 
-filegroup {
-    name: "libberberis_backend_reg_class_gen_inputs_x86_64",
-    srcs: ["x86_64/reg_class_def.json"],
-}
-
 filegroup {
     name: "libberberis_backend_gen_inputs_riscv64_to_x86_64",
     srcs: [
@@ -116,20 +99,6 @@ genrule_defaults {
     // ],
 }
 
-genrule {
-    name: "libberberis_backend_machine_ir_gen_sources_riscv64_to_x86_64",
-    defaults: ["libberberis_backend_machine_ir_gen_sources_x86_64_defaults"],
-    srcs: [":libberberis_backend_gen_inputs_riscv64_to_x86_64"],
-}
-
-genrule {
-    name: "libberberis_backend_reg_class_gen_headers_x86_64",
-    out: ["machine_reg_class_x86_64-inl.h"],
-    srcs: [":libberberis_backend_reg_class_gen_inputs_x86_64"],
-    tools: ["berberis_gen_reg_class"],
-    cmd: "$(location berberis_gen_reg_class) $(out) $(in)",
-}
-
 cc_library_headers {
     name: "libberberis_backend_headers",
     defaults: ["berberis_defaults"],
@@ -138,10 +107,12 @@ cc_library_headers {
     header_libs: [
         "libberberis_assembler_headers",
         "libberberis_base_headers",
+        "libberberis_device_arch_info_headers",
     ],
     export_header_lib_headers: [
         "libberberis_assembler_headers",
         "libberberis_base_headers",
+        "libberberis_device_arch_info_headers",
     ],
 }
 
@@ -149,7 +120,6 @@ cc_library_headers {
     name: "libberberis_backend_headers_riscv64_to_x86_64",
     defaults: ["berberis_defaults_64"],
     host_supported: true,
-    export_include_dirs: ["riscv64_to_x86_64/include"],
     header_libs: [
         "libberberis_backend_headers",
         "libberberis_guest_state_riscv64_headers",
@@ -160,14 +130,8 @@ cc_library_headers {
         "libberberis_guest_state_riscv64_headers",
         "libberberis_macro_assembler_headers_riscv64_to_x86_64",
     ],
-    generated_headers: [
-        "libberberis_backend_machine_ir_gen_headers_riscv64_to_x86_64",
-        "libberberis_backend_reg_class_gen_headers_x86_64",
-    ],
-    export_generated_headers: [
-        "libberberis_backend_machine_ir_gen_headers_riscv64_to_x86_64",
-        "libberberis_backend_reg_class_gen_headers_x86_64",
-    ],
+    generated_headers: ["libberberis_backend_machine_ir_gen_headers_riscv64_to_x86_64"],
+    export_generated_headers: ["libberberis_backend_machine_ir_gen_headers_riscv64_to_x86_64"],
 }
 
 filegroup {
@@ -215,9 +179,6 @@ cc_library_static {
         "berberis_backend_defaults",
     ],
     host_supported: true,
-    generated_sources: [
-        "libberberis_backend_machine_ir_gen_sources_riscv64_to_x86_64",
-    ],
     header_libs: [
         "libberberis_backend_headers_riscv64_to_x86_64",
     ],
@@ -241,7 +202,6 @@ filegroup {
         "x86_64/loop_guest_context_optimizer_test.cc",
         "x86_64/machine_ir_analysis_test.cc",
         "x86_64/machine_ir_check_test.cc",
-        "x86_64/machine_insn_intrinsics_tests.cc",
         "x86_64/machine_ir_exec_test.cc",
         "x86_64/machine_ir_opt_test.cc",
         "x86_64/machine_ir_test.cc",
diff --git a/backend/gen_lir.py b/backend/gen_lir.py
index b59ca252..f947ab51 100755
--- a/backend/gen_lir.py
+++ b/backend/gen_lir.py
@@ -52,6 +52,7 @@ are usually written before all input operands are read, so it makes sense to
 describe scratch operands as output-only-early-clobber.
 """
 
+import asm_defs
 import gen_lir_lib
 import sys
 
@@ -92,7 +93,14 @@ def main(argv):
       argv[arch_def_files_end:])
     gen_lir_lib.gen_code_2_cc(argv[2], arch, insns)
     gen_lir_lib.gen_machine_info_h(argv[3], arch, insns)
-    gen_lir_lib.gen_machine_opcode_h(argv[4], arch, insns)
+    # Produce opcodes for all instructions, even the ones not supported as
+    # instruction in backend, since they could be generated as intrinsics,
+    # instead.
+    insns4opcodes = []
+    for def_file in argv[arch_def_files_end:]:
+      _, asm_insns = asm_defs.load_asm_defs(def_file)
+      insns4opcodes.extend(asm_insns)
+    gen_lir_lib.gen_machine_opcode_h(argv[4], arch, insns4opcodes)
     gen_lir_lib.gen_machine_ir_h(argv[5], arch, insns)
   elif mode == '--sources':
     arch, insns = gen_lir_lib.load_all_lir_defs(
diff --git a/backend/gen_lir_lib.py b/backend/gen_lir_lib.py
index 5ff15032..47e8b6c7 100755
--- a/backend/gen_lir_lib.py
+++ b/backend/gen_lir_lib.py
@@ -69,14 +69,15 @@ class Operand(object):
 
 
 def _get_reg_operand_info(usage, kind):
+  kind = 'kRegisterClass<device_arch_info::%s>' % kind
   if usage == 'use':
-    return '{ &k%s, MachineRegKind::kUse }' % (kind)
+    return '{ &%s, MachineRegKind::kUse }' % (kind)
   if usage == 'def':
-    return '{ &k%s, MachineRegKind::kDef }' % (kind)
+    return '{ &%s, MachineRegKind::kDef }' % (kind)
   if usage == 'use_def':
-    return '{ &k%s, MachineRegKind::kUseDef }' % (kind)
+    return '{ &%s, MachineRegKind::kUseDef }' % (kind)
   if usage == 'def_early_clobber':
-    return '{ &k%s, MachineRegKind::kDefEarlyClobber }' % (kind)
+    return '{ &%s, MachineRegKind::kDefEarlyClobber }' % (kind)
   assert False, 'unknown operand usage %s' % (usage)
 
 
@@ -111,11 +112,11 @@ def _make_imm_operand(bits):
 
 def _make_scale_operand():
   op = Operand()
-  op.type = 'MachineMemOperandScale'
+  op.type = 'Assembler::ScaleFactor'
   op.name = 'scale'
   op.reg_operand_info = None
   op.initializer = 'set_scale(scale)'
-  op.asm_arg = 'ToScaleFactor(scale())'
+  op.asm_arg = 'scale()'
   return op
 
 
@@ -318,6 +319,9 @@ def _gen_insn_emit(f, insn):
   operands, _ = _get_insn_operands(insn)
   asm_args = [op.asm_arg for op in operands if op.asm_arg]
   print('void %s::Emit(CodeEmitter* as) const {' % (name), file=f)
+  for float in ['Float16', 'Float32', 'Float64']:
+    if float in asm:
+      print('  using intrinsics::%s;' % float, file=f)
   print('%sas->%s(%s);' % (INDENT, asm, ', '.join(asm_args)), file=f)
   print('}', file=f)
 
@@ -334,6 +338,10 @@ def _gen_insn_class(f, insn):
   print('class %s : public MachineInsnForArch {' % (name), file=f)
   print(' public:', file=f)
   print('  explicit %s(%s);' % (name, ', '.join(params)), file=f)
+  print('  template <typename MachineIRBuilder>', file=f)
+  print('  static constexpr %s* (MachineIRBuilder::*kGenFunc)(%s) =' %
+     (name, ', '.join(params)), file=f)
+  print('      &MachineIRBuilder::template Gen<%s>;' % name, file=f)
   print('  static constexpr MachineInsnInfo kInfo =', file=f)
   print('      MachineInsnInfo({kMachineOp%s,' % (name), file=f)
   print('                       %d,' % (len(regs)), file=f)
@@ -408,44 +416,30 @@ def gen_machine_opcode_h(out, arch, insns):
     for insn in insns:
       name = insn.get('name')
       print('kMachineOp%s,' % (name), file=f)
-
-
-def _gen_mem_insn_groups(f, insns):
-  # Build a dictionary to map a memory insn group name to another dictionary,
-  # which in turn maps an addressing mode to an individual memory insn.
-  groups = {}
-  for i in insns:
-    group_name = i.get('mem_group_name')
-    if group_name:
-      groups.setdefault(group_name, {})[i.get('addr_mode')] = i.get('name')
-
-  for group_name in sorted(groups):
-    # The order of the addressing modes here is important.  It must
-    # match what MemInsns expects.
-    mem_insns = [groups[group_name][addr_mode]
-                 for addr_mode in ('Absolute', 'BaseDisp', 'IndexDisp', 'BaseIndexDisp')]
-    print('using %s = MemInsns<%s>;' % (group_name, ', '.join(mem_insns)), file=f)
+    for insn in _expand_mem_insns(insns):
+      name = insn.get('name')
+      opcode = insn.get('opcode_name')
+      print('kMachineOp%s = kMachineOp%s ,' % (name, opcode), file=f)
 
 
 def gen_machine_ir_h(out, arch, insns):
   with open(out, 'w') as f:
     for insn in insns:
       _gen_insn_class(f, insn)
-    print('', file=f)
-    _gen_mem_insn_groups(f, insns)
 
 
 def _contains_mem(insn):
   return any(asm_defs.is_mem_op(arg['class']) for arg in insn.get('args'))
 
 
-def _create_mem_insn(insn, addr_mode):
+def _create_mem_insn(insn, addr_index, addr_mode):
   new_insn = insn.copy()
   macro_name = asm_defs.get_mem_macro_name(insn, addr_mode)
   new_insn['name'] = macro_name
   new_insn['addr_mode'] = addr_mode
   new_insn['asm'] = macro_name
   new_insn['mem_group_name'] = asm_defs.get_mem_macro_name(insn, '') + 'Insns'
+  new_insn['opcode_name'] = insn['name'] + ' | (%s << kLowMachineOpcodeBits)' % addr_index
   return new_insn
 
 
@@ -453,20 +447,21 @@ def _expand_mem_insns(insns):
   result = []
   for insn in insns:
     if _contains_mem(insn):
-      result.extend([_create_mem_insn(insn, addr_mode)
-                     for addr_mode in ('Absolute', 'BaseDisp', 'IndexDisp', 'BaseIndexDisp')])
-    result.append(insn)
+      result.extend([
+          _create_mem_insn(insn, addr_index, addr_mode)
+          for addr_index, addr_mode in
+              enumerate(('Absolute', 'BaseDisp', 'IndexDisp', 'BaseIndexDisp'))])
   return result
 
 
-def _load_lir_def(allowlist_looked, allowlist_found, asm_def):
+def _load_lir_def(allowlist_referenced, allowlist_defined, asm_def):
   arch, insns = asm_defs.load_asm_defs(asm_def)
-  insns = _expand_mem_insns(insns)
+  insns.extend(_expand_mem_insns(insns))
   # Mark all instructions to remove and remember instructions we kept
   for insn in insns:
     insn_name = insn.get('mem_group_name', insn['name'])
-    if insn_name in allowlist_looked:
-      allowlist_found.add(insn_name)
+    if insn_name in allowlist_referenced:
+      allowlist_defined.add(insn_name)
     else:
       insn['skip_lir'] = 1
   # Filter out disabled instructions.
@@ -493,14 +488,14 @@ def _allowlist_instructions(allowlist_files, machine_ir_intrinsic_binding_files)
 
 
 def load_all_lir_defs(allowlist_files, machine_ir_intrinsic_binding_files, lir_defs):
-  allowlist_looked = _allowlist_instructions(
+  allowlist_referenced = _allowlist_instructions(
       allowlist_files, machine_ir_intrinsic_binding_files)
-  allowlist_found = set()
+  allowlist_defined = set()
   arch = None
   insns = []
   macro_insns = []
   for lir_def in lir_defs:
-    def_arch, def_insns = _load_lir_def(allowlist_looked, allowlist_found, lir_def)
+    def_arch, def_insns = _load_lir_def(allowlist_referenced, allowlist_defined, lir_def)
     if arch and not arch.startswith('common_'):
       assert def_arch is None or arch == def_arch
     else:
@@ -513,5 +508,7 @@ def load_all_lir_defs(allowlist_files, machine_ir_intrinsic_binding_files, lir_d
     _check_insn_defs(insn)
   # Some macroinstructions can only be used in Lite translator for now. Ignore them here.
   insns.extend(insn for insn in macro_insns if _check_insn_defs(insn, True))
-  assert allowlist_looked == allowlist_found
+  assert allowlist_referenced == allowlist_defined, \
+      "Intrinsics referenced in bindings and not defined: " + \
+      string(allowlist_referenced - allowlist_defined)
   return arch, insns
diff --git a/backend/gen_reg_class_lib.py b/backend/gen_reg_class_lib.py
deleted file mode 100644
index aaa1ac26..00000000
--- a/backend/gen_reg_class_lib.py
+++ /dev/null
@@ -1,46 +0,0 @@
-#!/usr/bin/python3
-#
-# Copyright (C) 2023 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-"""Generate machine IR register class definitions from data file."""
-
-def gen_machine_reg_class_inc(f, reg_classes):
-  for reg_class in reg_classes:
-    name = reg_class.get('name')
-    regs = reg_class.get('regs')
-    print('inline constexpr uint64_t k%sMask =' % (name), file=f)
-    for r in regs[: -1]:
-      print('    (1ULL << kMachineReg%s.reg()) |' % (r), file=f)
-    print('    (1ULL << kMachineReg%s.reg());' % (regs[-1]), file=f)
-    print('inline constexpr MachineRegClass k%s = {' % (name), file=f)
-    print('    "%s",' % (name), file=f)
-    print('    %d,' % (reg_class.get('size')), file=f)
-    print('    k%sMask,' % (name), file=f)
-    print('    %d,' % (len(regs)), file=f)
-    print('    {', file=f)
-    for r in regs:
-      print('      kMachineReg%s,' % (r), file=f)
-    print('    }', file=f)
-    print('};', file=f)
-
-
-def expand_aliases(reg_classes):
-  expanded = {}
-  for reg_class in reg_classes:
-    expanded_regs = []
-    for r in reg_class.get('regs'):
-      expanded_regs.extend(expanded.get(r, [r]))
-    reg_class['regs'] = expanded_regs
-    expanded[reg_class.get('name')] = expanded_regs
diff --git a/backend/include/berberis/backend/common/machine_ir.h b/backend/include/berberis/backend/common/machine_ir.h
index b18d59c2..b2d14895 100644
--- a/backend/include/berberis/backend/common/machine_ir.h
+++ b/backend/include/berberis/backend/common/machine_ir.h
@@ -81,6 +81,10 @@ class MachineReg {
 
   constexpr friend bool operator!=(MachineReg left, MachineReg right) { return !(left == right); }
 
+  constexpr friend bool operator<(MachineReg left, MachineReg right) {
+    return left.reg_ < right.reg_;
+  }
+
   [[nodiscard]] static constexpr MachineReg CreateVRegFromIndex(uint32_t index) {
     CHECK_LE(index, std::numeric_limits<int>::max() - kFirstVRegNumber);
     return MachineReg{kFirstVRegNumber + static_cast<int>(index)};
diff --git a/backend/include/berberis/backend/x86_64/code_debug.h b/backend/include/berberis/backend/x86_64/code_debug.h
index 8080acd9..b6064b9e 100644
--- a/backend/include/berberis/backend/x86_64/code_debug.h
+++ b/backend/include/berberis/backend/x86_64/code_debug.h
@@ -27,6 +27,8 @@ namespace berberis {
 
 namespace x86_64 {
 
+class MachineInsnX86_64;
+
 std::string GetImplicitRegOperandDebugString(const MachineInsnX86_64* insn, int i);
 std::string GetAbsoluteMemOperandDebugString(const MachineInsnX86_64* insn);
 std::string GetBaseDispMemOperandDebugString(const MachineInsnX86_64* insn, int i);
diff --git a/backend/include/berberis/backend/x86_64/code_emit.h b/backend/include/berberis/backend/x86_64/code_emit.h
index 451322e0..df8e722a 100644
--- a/backend/include/berberis/backend/x86_64/code_emit.h
+++ b/backend/include/berberis/backend/x86_64/code_emit.h
@@ -29,7 +29,6 @@ namespace berberis::x86_64 {
 Assembler::Register GetGReg(MachineReg r);
 Assembler::XMMRegister GetXReg(MachineReg r);
 Assembler::YMMRegister GetYReg(MachineReg r);
-Assembler::ScaleFactor ToScaleFactor(MachineMemOperandScale scale);
 
 }  // namespace berberis::x86_64
 
diff --git a/backend/include/berberis/backend/x86_64/insn_folding.h b/backend/include/berberis/backend/x86_64/insn_folding.h
index 3b81aaf1..73c62cc0 100644
--- a/backend/include/berberis/backend/x86_64/insn_folding.h
+++ b/backend/include/berberis/backend/x86_64/insn_folding.h
@@ -24,38 +24,45 @@
 
 namespace berberis::x86_64 {
 
+enum class FoldingType { kImpossible, kReplaceInsn, kInsertInsn, kRemoveInsn };
+
 // The DefMap class stores a map between registers and their latest definitions and positions.
 class DefMap {
  public:
   DefMap(size_t size, Arena* arena)
-      : def_map_(size, {nullptr, 0}, arena), flags_reg_(kInvalidMachineReg), index_(0) {}
-  [[nodiscard]] std::pair<const MachineInsn*, int> Get(MachineReg reg) const {
+      : def_map_(size, {std::nullopt, 0}, arena), flags_reg_(kInvalidMachineReg), index_(0) {}
+  [[nodiscard]] std::pair<std::optional<MachineInsnList::iterator>, int> Get(MachineReg reg) const {
     if (!reg.IsVReg()) {
-      return {nullptr, 0};
+      return {std::nullopt, 0};
+    }
+    auto [def_insn, def_insn_index] = def_map_.at(reg.GetVRegIndex());
+    if (!def_insn) {
+      return {std::nullopt, 0};
     }
-    return def_map_.at(reg.GetVRegIndex());
+    return {def_insn, def_insn_index};
   }
-  [[nodiscard]] std::pair<const MachineInsn*, int> Get(MachineReg reg, int use_index) const {
+  [[nodiscard]] std::pair<std::optional<MachineInsnList::iterator>, int> Get(MachineReg reg,
+                                                                             int use_index) const {
     if (!reg.IsVReg()) {
-      return {nullptr, 0};
+      return {std::nullopt, 0};
     }
     auto [def_insn, def_insn_index] = def_map_.at(reg.GetVRegIndex());
-    if (!def_insn || def_insn_index > use_index) {
-      return {nullptr, 0};
+    if (!def_insn || def_insn_index >= use_index) {
+      return {std::nullopt, 0};
     }
     return {def_insn, def_insn_index};
   }
-  void ProcessInsn(const MachineInsn* insn);
+  void ProcessInsn(MachineInsnList::iterator insn_it);
   void Initialize();
 
  private:
-  void Set(MachineReg reg, const MachineInsn* insn) {
+  void Set(MachineReg reg, MachineInsnList::iterator insn_it) {
     if (reg.IsVReg()) {
-      def_map_.at(reg.GetVRegIndex()) = std::pair(insn, index_);
+      def_map_.at(reg.GetVRegIndex()) = std::pair(insn_it, index_);
     }
   }
-  void MapDefRegs(const MachineInsn* insn);
-  ArenaVector<std::pair<const MachineInsn*, int>> def_map_;
+  void MapDefRegs(MachineInsnList::iterator insn_it);
+  ArenaVector<std::pair<std::optional<MachineInsnList::iterator>, int>> def_map_;
   MachineReg flags_reg_;
   int index_;
 };
@@ -65,17 +72,31 @@ class InsnFolding {
   explicit InsnFolding(DefMap& def_map, MachineIR* machine_ir)
       : def_map_(def_map), machine_ir_(machine_ir) {}
 
-  std::tuple<bool, MachineInsn*> TryFoldInsn(const MachineInsn* insn);
+  std::tuple<FoldingType, berberis::MachineInsn*> TryFoldInsn(const MachineInsnList::iterator insn,
+                                                              const MachineBasicBlock* bb);
 
  private:
   DefMap& def_map_;
   MachineIR* machine_ir_;
-  bool IsRegImm(MachineReg reg, uint64_t* imm) const;
-  bool IsWritingSameFlagsValue(const MachineInsn* insn) const;
-  template <bool is_input_64bit>
-  std::tuple<bool, MachineInsn*> TryFoldImmediateInput(const MachineInsn* insn);
-  std::tuple<bool, MachineInsn*> TryFoldRedundantMovl(const MachineInsn* insn);
-  MachineInsn* NewImmInsnFromRegInsn(const MachineInsn* insn, int32_t imm);
+  std::optional<uint64_t> GetImmValueIfPossible(MachineReg reg) const;
+  bool IsWritingSameFlagsValue(MachineInsnList::iterator insn_it) const;
+  std::tuple<std::optional<MachineInsnList::iterator>, int> FindNonPseudoCopyDef(
+      MachineReg src_reg) const;
+  template <bool kIsInput64Bit>
+  std::tuple<FoldingType, berberis::MachineInsn*> TryFoldImmediateInput(
+      MachineInsnList::iterator insn_it);
+  std::tuple<FoldingType, berberis::MachineInsn*> TryFoldTwoImmediates(
+      MachineInsnList::iterator insn_it);
+  std::tuple<FoldingType, berberis::MachineInsn*> TryFoldRedundantMovl(
+      MachineInsnList::iterator insn_it);
+  template <bool kBMI, bool kIsInput64Bit>
+  std::tuple<FoldingType, berberis::MachineInsn*> TryFoldCountLeadingZeros(
+      MachineInsnList::iterator insn_it,
+      const MachineBasicBlock* bb);
+  berberis::MachineInsn* NewImmInsnFromRegInsn(const berberis::MachineInsn* insn, int32_t imm);
+  berberis::MachineInsn* NewInsnFromTwoImmediatesOperation(const berberis::MachineInsn* insn,
+                                                           uint64_t imm1,
+                                                           uint64_t imm2);
 };
 
 void FoldInsns(MachineIR* machine_ir);
diff --git a/backend/include/berberis/backend/x86_64/local_guest_context_optimizer.h b/backend/include/berberis/backend/x86_64/local_guest_context_optimizer.h
index cb85536a..cfd86571 100644
--- a/backend/include/berberis/backend/x86_64/local_guest_context_optimizer.h
+++ b/backend/include/berberis/backend/x86_64/local_guest_context_optimizer.h
@@ -21,7 +21,13 @@
 
 namespace berberis::x86_64 {
 
-void RemoveLocalGuestContextAccesses(x86_64::MachineIR* machine_ir);
+struct OptimizeLocalParams {
+  size_t general_reg_limit = 12;
+  size_t simd_reg_limit = 12;
+};
+
+void RemoveLocalGuestContextAccesses(x86_64::MachineIR* machine_ir,
+                                     const OptimizeLocalParams& params = OptimizeLocalParams());
 
 }  // namespace berberis::x86_64
 
diff --git a/backend/include/berberis/backend/x86_64/machine_insn_intrinsics.h b/backend/include/berberis/backend/x86_64/machine_insn_intrinsics.h
deleted file mode 100644
index bd2bcc72..00000000
--- a/backend/include/berberis/backend/x86_64/machine_insn_intrinsics.h
+++ /dev/null
@@ -1,330 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef BERBERIS_BACKEND_X86_64_MACHINE_INSN_INTRINSICS_H_
-#define BERBERIS_BACKEND_X86_64_MACHINE_INSN_INTRINSICS_H_
-
-#include <string>
-#include <tuple>
-#include <type_traits>
-#include <variant>
-
-#include "berberis/backend/code_emitter.h"
-#include "berberis/backend/common/machine_ir.h"
-#include "berberis/backend/x86_64/code_debug.h"
-#include "berberis/backend/x86_64/code_emit.h"
-#include "berberis/backend/x86_64/machine_ir.h"
-#include "berberis/backend/x86_64/machine_ir_builder.h"
-#include "berberis/base/dependent_false.h"
-#include "berberis/base/stringprintf.h"
-#include "berberis/intrinsics/intrinsics_args.h"
-#include "berberis/intrinsics/intrinsics_bindings.h"
-
-namespace berberis::x86_64 {
-
-// tuple_cat for types, to help remove filtered out types below.
-template <typename... Ts>
-using tuple_cat_t = decltype(std::tuple_cat(std::declval<Ts>()...));
-
-// Predicate to determine whether type T has a RegisterClass alias.
-template <class, class = void>
-struct has_reg_class_impl : std::false_type {};
-template <class T>
-struct has_reg_class_impl<T, std::void_t<typename T::RegisterClass>> : std::true_type {};
-template <typename T>
-using has_reg_class_t = has_reg_class_impl<T>;
-
-// Filter out types from Ts... that do not satisfy the predicate, collect them
-// into a tuple.
-template <template <typename> typename Predicate, typename... Ts>
-using filter_t =
-    tuple_cat_t<std::conditional_t<Predicate<Ts>::value, std::tuple<Ts>, std::tuple<>>...>;
-
-// Convert Binding into constructor argument(s).
-template <typename T, typename = void>
-struct ConstructorArg;
-
-// Immediates expand into their class type.
-template <typename T>
-struct ConstructorArg<ArgTraits<T>, std::enable_if_t<ArgTraits<T>::Class::kIsImmediate, void>> {
-  using type = std::tuple<typename ArgTraits<T>::Class::Type>;
-};
-
-// Mem ops expand into base register and disp.
-template <typename T>
-struct ConstructorArg<ArgTraits<T>,
-                      std::enable_if_t<!ArgTraits<T>::Class::kIsImmediate &&
-                                           ArgTraits<T>::RegisterClass::kAsRegister == 'm',
-                                       void>> {
-  static_assert(
-      std::is_same_v<typename ArgTraits<T>::Usage, intrinsics::bindings::DefEarlyClobber>);
-  // Need to emit base register AND disp.
-  using type = std::tuple<MachineReg, int32_t>;
-};
-
-// Everything else expands into a MachineReg.
-template <typename T>
-struct ConstructorArg<ArgTraits<T>,
-                      std::enable_if_t<!ArgTraits<T>::Class::kIsImmediate &&
-                                           ArgTraits<T>::RegisterClass::kAsRegister != 'm',
-                                       void>> {
-  using type = std::tuple<MachineReg>;
-};
-
-template <typename T>
-using constructor_one_arg_t = typename ConstructorArg<ArgTraits<T>>::type;
-
-// Use this alias to generate constructor Args from bindings via the AsmCallInfo::MachineInsn
-// alias. The tuple args will be extracted by the tuple specialization on MachineInsn below.
-template <typename... T>
-using constructor_args_t = tuple_cat_t<constructor_one_arg_t<T>...>;
-
-// Predicate to determine whether type T is a memory access arg.
-template <class, class = void>
-struct is_mem_impl : std::false_type {};
-template <class T>
-struct is_mem_impl<
-    T,
-    std::enable_if_t<!T::Class::kIsImmediate && T::RegisterClass::kAsRegister == 'm', void>>
-    : std::true_type {};
-template <typename T>
-using is_mem_t = is_mem_impl<T>;
-
-template <typename... Bindings>
-constexpr size_t mem_count_v = std::tuple_size_v<filter_t<is_mem_t, ArgTraits<Bindings>...>>;
-
-template <size_t N, typename... Bindings>
-constexpr bool has_n_mem_v = mem_count_v<Bindings...> > (N - 1);
-
-template <typename AsmCallInfo, auto kMnemo, auto kOpcode, typename Args, typename... Bindings>
-class MachineInsn;
-
-// Use specialization to extract the tuple parameter pack generated from constructor_args_t above.
-template <typename AsmCallInfo,
-          auto kMnemo,
-          auto kOpcode,
-          typename... CtorArgs,
-          typename... Bindings>
-class MachineInsn<AsmCallInfo, kMnemo, kOpcode, std::tuple<CtorArgs...>, Bindings...> final
-    : public MachineInsnX86_64 {
- private:
-  template <typename>
-  struct GenMachineInsnInfoT;
-  // We want to filter out any bindings that are not used for Register args.
-  using RegBindings = filter_t<has_reg_class_t, ArgTraits<Bindings>...>;
-
- public:
-  // This static simplifies constructing this MachineInsn in intrinsic implementations.
-  static constexpr MachineInsn* (MachineIRBuilder::*kGenFunc)(CtorArgs...) =
-      &MachineIRBuilder::template Gen<MachineInsn>;
-
-  explicit MachineInsn(CtorArgs... args) : MachineInsnX86_64(&kInfo) {
-    ProcessArgs<0 /* reg_idx */, 0 /* disp_idx */, Bindings...>(args...);
-  }
-
-  static constexpr MachineInsnInfo kInfo = GenMachineInsnInfoT<RegBindings>::value;
-
-  static constexpr int NumRegOperands() { return kInfo.num_reg_operands; }
-  static constexpr const MachineRegKind& RegKindAt(int i) { return kInfo.reg_kinds[i]; }
-
-  std::string GetDebugString() const override {
-    std::string s(kMnemo);
-    ProcessDebugString<Bindings...>(&s);
-    return s;
-  }
-
-  void Emit(CodeEmitter* as) const override {
-    std::apply(AsmCallInfo::kMacroInstruction,
-               std::tuple_cat(std::tuple<CodeEmitter&>{*as},
-                              EmitArgs<0 /* reg_idx */, 0 /* disp_idx */, Bindings...>()));
-  }
-
-  int32_t disp2() const { return disp2_; }
-  void set_disp2(int32_t val) { disp2_ = val; }
-
- private:
-  int32_t disp2_;
-
-  template <size_t, size_t, typename...>
-  void ProcessArgs() {}
-
-  template <size_t reg_idx,
-            size_t disp_idx,
-            typename B,
-            typename... BindingsRest,
-            typename T,
-            typename... Args>
-  auto ProcessArgs(T arg, Args... args) -> std::enable_if_t<ArgTraits<B>::Class::kIsImmediate> {
-    this->set_imm(arg);
-    ProcessArgs<reg_idx, disp_idx, BindingsRest...>(args...);
-  }
-
-  template <size_t reg_idx,
-            size_t disp_idx,
-            typename B,
-            typename... BindingsRest,
-            typename T,
-            typename... Args>
-  auto ProcessArgs(T arg, Args... args)
-      -> std::enable_if_t<ArgTraits<B>::RegisterClass::kAsRegister != 'm'> {
-    static_assert(std::is_same_v<MachineReg, T>);
-    this->SetRegAt(reg_idx, arg);
-    ProcessArgs<reg_idx + 1, disp_idx, BindingsRest...>(args...);
-  }
-
-  template <size_t reg_idx,
-            size_t disp_idx,
-            typename B,
-            typename... BindingsRest,
-            typename T1,
-            typename T2,
-            typename... Args>
-  auto ProcessArgs(T1 base, T2 disp, Args... args)
-      -> std::enable_if_t<ArgTraits<B>::RegisterClass::kAsRegister == 'm'> {
-    // Only tmp memory args are supported.
-    static_assert(ArgTraits<B>::arg_info.arg_type == ArgInfo::TMP_ARG);
-    this->SetRegAt(reg_idx, base);
-    if constexpr (disp_idx == 0) {
-      this->set_disp(disp);
-    } else if constexpr (disp_idx == 1) {
-      this->set_disp2(disp);
-    } else {
-      static_assert(kDependentValueFalse<disp_idx>);
-    }
-    ProcessArgs<reg_idx + 1, disp_idx + 1, BindingsRest...>(args...);
-  }
-
-  static constexpr auto GetInsnKind() {
-    if constexpr (AsmCallInfo::kSideEffects) {
-      return kMachineInsnSideEffects;
-    } else {
-      return kMachineInsnDefault;
-    }
-  }
-
-  template <typename T, typename = void>
-  struct RegInfo;
-  template <typename T>
-  struct RegInfo<T, std::enable_if_t<T::RegisterClass::kAsRegister != 'm', void>> {
-    static constexpr auto kRegClass = &T::RegisterClass::template kRegClass<MachineInsnX86_64>;
-    static constexpr auto kRegKind =
-        intrinsics::bindings::kRegKind<typename T::Usage, berberis::MachineRegKind>;
-  };
-  template <typename T>
-  struct RegInfo<T, std::enable_if_t<T::RegisterClass::kAsRegister == 'm', void>> {
-    static_assert(std::is_same_v<typename T::Usage, intrinsics::bindings::DefEarlyClobber>);
-    static constexpr auto kRegClass = &kGeneralReg32;
-    static constexpr auto kRegKind = MachineRegKind::kUse;
-  };
-
-  template <typename... T>
-  struct GenMachineInsnInfoT<std::tuple<T...>> {
-    static constexpr MachineInsnInfo value = MachineInsnInfo(
-        {kOpcode, sizeof...(T), {{RegInfo<T>::kRegClass, RegInfo<T>::kRegKind}...}, GetInsnKind()});
-  };
-
-  template <typename... Args>
-  void ProcessDebugString(std::string* s) const {
-    *s +=
-        " " + ProcessDebugStringArgs<0 /* arg_idx */, 0 /* reg_idx */, 0 /* disp_idx */, Args...>();
-    if (this->recovery_pc()) {
-      *s += StringPrintf(" <0x%" PRIxPTR ">", this->recovery_pc());
-    }
-  }
-
-  // TODO(b/260725458): Use inline template lambda instead after C++20 becomes available.
-  template <>
-  void ProcessDebugString<>(std::string*) const {}
-
-  template <size_t arg_idx, size_t reg_idx, size_t disp_idx, typename T, typename... Args>
-  std::string ProcessDebugStringArgs() const {
-    std::string prefix;
-    if constexpr (arg_idx > 0) {
-      prefix = ", ";
-    }
-    if constexpr (ArgTraits<T>::Class::kIsImmediate) {
-      return prefix + GetImmOperandDebugString(this) +
-             ProcessDebugStringArgs<arg_idx + 1, reg_idx, disp_idx, Args...>();
-    } else if constexpr (ArgTraits<T>::Class::kAsRegister == 'm') {
-      if constexpr (disp_idx == 0) {
-        return prefix + GetBaseDispMemOperandDebugString(this, reg_idx) +
-               ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, disp_idx + 1, Args...>();
-      } else if constexpr (disp_idx == 1) {
-        return prefix +
-               StringPrintf(
-                   "[%s + 0x%x]", GetRegOperandDebugString(this, reg_idx).c_str(), disp2()) +
-               ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, disp_idx + 1, Args...>();
-      } else {
-        static_assert(kDependentValueFalse<disp_idx>);
-      }
-    } else if constexpr (ArgTraits<T>::RegisterClass::kIsImplicitReg) {
-      return prefix + GetImplicitRegOperandDebugString(this, reg_idx) +
-             ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, disp_idx, Args...>();
-    } else {
-      return prefix + GetRegOperandDebugString(this, reg_idx) +
-             ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, disp_idx, Args...>();
-    }
-  }
-
-  template <size_t, size_t, size_t>
-  std::string ProcessDebugStringArgs() const {
-    return "";
-  }
-
-  // TODO(b/260725458): Use inline template lambda instead after C++20 becomes available.
-  template <size_t, size_t>
-  auto EmitArgs() const {
-    return std::tuple{};
-  }
-
-  template <size_t reg_idx, size_t disp_idx, typename T, typename... Args>
-  auto EmitArgs() const {
-    if constexpr (ArgTraits<T>::Class::kIsImmediate) {
-      return std::tuple_cat(
-          std::tuple{static_cast<constructor_one_arg_t<T>>(MachineInsnX86_64::imm())},
-          EmitArgs<reg_idx, disp_idx, Args...>());
-    } else if constexpr (ArgTraits<T>::RegisterClass::kAsRegister == 'x') {
-      return std::tuple_cat(std::tuple{GetXReg(this->RegAt(reg_idx))},
-                            EmitArgs<reg_idx + 1, disp_idx, Args...>());
-    } else if constexpr (ArgTraits<T>::RegisterClass::kAsRegister == 'r' ||
-                         ArgTraits<T>::RegisterClass::kAsRegister == 'q') {
-      return std::tuple_cat(std::tuple{GetGReg(this->RegAt(reg_idx))},
-                            EmitArgs<reg_idx + 1, disp_idx, Args...>());
-    } else if constexpr (ArgTraits<T>::RegisterClass::kAsRegister == 'm' &&
-                         std::is_same_v<typename ArgTraits<T>::Usage,
-                                        intrinsics::bindings::DefEarlyClobber>) {
-      if constexpr (disp_idx == 0) {
-        return std::tuple_cat(std::tuple{Assembler::Operand{.base = GetGReg(this->RegAt(reg_idx)),
-                                                            .disp = static_cast<int32_t>(disp())}},
-                              EmitArgs<reg_idx + 1, disp_idx + 1, Args...>());
-      } else if constexpr (disp_idx == 1) {
-        return std::tuple_cat(std::tuple{Assembler::Operand{.base = GetGReg(this->RegAt(reg_idx)),
-                                                            .disp = static_cast<int32_t>(disp2())}},
-                              EmitArgs<reg_idx + 1, disp_idx + 1, Args...>());
-      } else {
-        static_assert(kDependentTypeFalse<T>);
-      }
-    } else if constexpr (ArgTraits<T>::RegisterClass::kIsImplicitReg) {
-      return EmitArgs<reg_idx, disp_idx, Args...>();
-    } else {
-      static_assert(kDependentTypeFalse<T>);
-    }
-  }
-};
-
-}  // namespace berberis::x86_64
-
-#endif  // BERBERIS_BACKEND_X86_64_MACHINE_INSN_INTRINSICS_H_
diff --git a/backend/include/berberis/backend/x86_64/machine_ir.h b/backend/include/berberis/backend/x86_64/machine_ir.h
index ca31588d..37034d76 100644
--- a/backend/include/berberis/backend/x86_64/machine_ir.h
+++ b/backend/include/berberis/backend/x86_64/machine_ir.h
@@ -19,17 +19,28 @@
 #ifndef BERBERIS_BACKEND_X86_64_MACHINE_IR_H_
 #define BERBERIS_BACKEND_X86_64_MACHINE_IR_H_
 
+#include <array>
 #include <cstdint>
 #include <string>
 
 #include "berberis/assembler/x86_64.h"
 #include "berberis/backend/code_emitter.h"
-#include "berberis/backend/common/machine_ir.h"
+#include "berberis/backend/common/machine_ir.h"  // IWYU pragma: export.
+#include "berberis/backend/x86_64/code_debug.h"
+#include "berberis/backend/x86_64/code_emit.h"
 #include "berberis/base/arena_alloc.h"
+#include "berberis/base/stringprintf.h"
+#include "berberis/device_arch_info/x86_64/device_arch_info.h"
 #include "berberis/guest_state/guest_state_arch.h"
 
 namespace berberis {
 
+// Some instructions form groups. E.g. memory-accesses typically have 4 versions: Absolute, Base,
+// Index Base+Index.
+//
+// To ensure that there enough bits to separate these versions we reserve top 8 bits.
+inline constexpr int kLowMachineOpcodeBits = 24;
+
 enum MachineOpcode : int {
   kMachineOpUndefined = 0,
   kMachineOpCallImm,
@@ -43,110 +54,126 @@ enum MachineOpcode : int {
   kMachineOpPseudoJump,
   kMachineOpPseudoReadFlags,
   kMachineOpPseudoWriteFlags,
-// Some frontends may need additional opcodes currently.
-// Ideally we may want to separate froentend and backend, but for now only include
-// berberis/backend/x86_64/machine_opcode_guest-inl.h if it exists.
-#if __has_include("berberis/backend/x86_64/machine_opcode_guest-inl.h")
-#include "berberis/backend/x86_64/machine_opcode_guest-inl.h"
-#endif  // __has_include("berberis/backend/x86_64/machine_opcode_guest-inl.h")
 #include "machine_opcode_x86_64-inl.h"  // NOLINT generated file!
 };
 
 namespace x86_64 {
 
-constexpr const MachineReg kMachineRegR8{1};
-constexpr const MachineReg kMachineRegR9{2};
-constexpr const MachineReg kMachineRegR10{3};
-constexpr const MachineReg kMachineRegR11{4};
-constexpr const MachineReg kMachineRegRSI{5};
-constexpr const MachineReg kMachineRegRDI{6};
-constexpr const MachineReg kMachineRegRAX{7};
-constexpr const MachineReg kMachineRegRBX{8};
-constexpr const MachineReg kMachineRegRCX{9};
-constexpr const MachineReg kMachineRegRDX{10};
-constexpr const MachineReg kMachineRegRBP{11};
-constexpr const MachineReg kMachineRegRSP{12};
-constexpr const MachineReg kMachineRegR12{13};
-constexpr const MachineReg kMachineRegR13{14};
-constexpr const MachineReg kMachineRegR14{15};
-constexpr const MachineReg kMachineRegR15{16};
-constexpr const MachineReg kMachineRegFLAGS{19};
-constexpr const MachineReg kMachineRegXMM0{20};
-constexpr const MachineReg kMachineRegXMM1{21};
-constexpr const MachineReg kMachineRegXMM2{22};
-constexpr const MachineReg kMachineRegXMM3{23};
-constexpr const MachineReg kMachineRegXMM4{24};
-constexpr const MachineReg kMachineRegXMM5{25};
-constexpr const MachineReg kMachineRegXMM6{26};
-constexpr const MachineReg kMachineRegXMM7{27};
-constexpr const MachineReg kMachineRegXMM8{28};
-constexpr const MachineReg kMachineRegXMM9{29};
-constexpr const MachineReg kMachineRegXMM10{30};
-constexpr const MachineReg kMachineRegXMM11{31};
-constexpr const MachineReg kMachineRegXMM12{32};
-constexpr const MachineReg kMachineRegXMM13{33};
-constexpr const MachineReg kMachineRegXMM14{34};
-constexpr const MachineReg kMachineRegXMM15{35};
+class MachineRegs {
+ public:
+  static constexpr MachineReg kR8{1};
+  static constexpr MachineReg kR9{2};
+  static constexpr MachineReg kR10{3};
+  static constexpr MachineReg kR11{4};
+  static constexpr MachineReg kRSI{5};
+  static constexpr MachineReg kRDI{6};
+  static constexpr MachineReg kRAX{7};
+  static constexpr MachineReg kRBX{8};
+  static constexpr MachineReg kRCX{9};
+  static constexpr MachineReg kRDX{10};
+  static constexpr MachineReg kRBP{11};
+  static constexpr MachineReg kRSP{12};
+  static constexpr MachineReg kR12{13};
+  static constexpr MachineReg kR13{14};
+  static constexpr MachineReg kR14{15};
+  static constexpr MachineReg kR15{16};
+  static constexpr MachineReg kFLAGS{19};
+  static constexpr MachineReg kXMM0{20};
+  static constexpr MachineReg kXMM1{21};
+  static constexpr MachineReg kXMM2{22};
+  static constexpr MachineReg kXMM3{23};
+  static constexpr MachineReg kXMM4{24};
+  static constexpr MachineReg kXMM5{25};
+  static constexpr MachineReg kXMM6{26};
+  static constexpr MachineReg kXMM7{27};
+  static constexpr MachineReg kXMM8{28};
+  static constexpr MachineReg kXMM9{29};
+  static constexpr MachineReg kXMM10{30};
+  static constexpr MachineReg kXMM11{31};
+  static constexpr MachineReg kXMM12{32};
+  static constexpr MachineReg kXMM13{33};
+  static constexpr MachineReg kXMM14{34};
+  static constexpr MachineReg kXMM15{35};
+};
+
+inline constexpr auto kMachineRegFLAGS = MachineRegs::kFLAGS;
+inline constexpr auto kMachineRegRBP = MachineRegs::kRBP;
+inline constexpr auto kMachineRegRSP = MachineRegs::kRSP;
 
 inline bool IsGReg(MachineReg r) {
-  return r.reg() >= kMachineRegR8.reg() && r.reg() <= kMachineRegR15.reg();
+  return r.reg() >= MachineRegs::kR8.reg() && r.reg() <= MachineRegs::kR15.reg();
 }
 
 inline bool IsXReg(MachineReg r) {
-  return r.reg() >= kMachineRegXMM0.reg() && r.reg() <= kMachineRegXMM15.reg();
+  return r.reg() >= MachineRegs::kXMM0.reg() && r.reg() <= MachineRegs::kXMM15.reg();
 }
 
 // rax, rdi, rsi, rdx, rcx, r8-r11, xmm0-xmm15, flags
 const int kMaxMachineRegOperands = 26;
 
 // Context loads and stores use rbp as base.
-const MachineReg kCPUStatePointer = kMachineRegRBP;
+inline constexpr auto kCPUStatePointer = MachineRegs::kRBP;
 
 struct MachineInsnInfo {
   MachineOpcode opcode;
   int num_reg_operands;
   MachineRegKind reg_kinds[kMaxMachineRegOperands];
   MachineInsnKind kind;
+  constexpr int InputRegistersCount() const {
+    int result = 0;
+    for (int index = 0; index < num_reg_operands; ++index) {
+      if (reg_kinds[index].IsInput()) {
+        result++;
+      }
+    }
+    return result;
+  }
+  constexpr int OutputRegistersCount() const {
+    int result = 0;
+    for (int index = 0; index < num_reg_operands; ++index) {
+      if (reg_kinds[index].IsDef()) {
+        result++;
+      }
+    }
+    return result;
+  }
 };
 
-enum class MachineMemOperandScale {
-  kOne,
-  kTwo,
-  kFour,
-  kEight,
-};
+template <typename MachineInsnInfoClass>
+constexpr MachineRegClass MachineRegClassFromMachineInsnInfoClass() {
+  return []<typename... RegisterClass>(const std::tuple<RegisterClass...>&) -> MachineRegClass {
+    return {
+        .debug_name = MachineInsnInfoClass::kName,
+        .reg_size = MachineInsnInfoClass::kSizeInBits / 8,
+        .reg_mask = ((1ULL << RegisterClass::template kMachineRegId<MachineRegs>.reg()) | ...),
+        .num_regs = sizeof...(RegisterClass),
+        .regs = {RegisterClass::template kMachineRegId<MachineRegs>...},
+    };
+  }(typename MachineInsnInfoClass::RegistersList());
+}
 
-#include "machine_reg_class_x86_64-inl.h"  // NOLINT generated file!
+template <typename MachineInsnInfoClass>
+inline constexpr MachineRegClass kRegisterClass =
+    MachineRegClassFromMachineInsnInfoClass<MachineInsnInfoClass>();
+
+inline constexpr auto& kRAX = kRegisterClass<device_arch_info::RAX>;
+inline constexpr auto& kGeneralReg32 = kRegisterClass<device_arch_info::GeneralReg32>;
+inline constexpr auto& kGeneralReg64 = kRegisterClass<device_arch_info::GeneralReg64>;
+inline constexpr auto& kReg32 = kRegisterClass<device_arch_info::Reg32>;
+inline constexpr auto& kReg64 = kRegisterClass<device_arch_info::Reg64>;
+inline constexpr auto& kXmmReg = kRegisterClass<device_arch_info::XmmReg>;
+inline constexpr auto& kFLAGS = kRegisterClass<device_arch_info::FLAGS>;
 
 class MachineInsnX86_64 : public MachineInsn {
  public:
-  static constexpr const auto kEAX = x86_64::kEAX;
-  static constexpr const auto kRAX = x86_64::kRAX;
-  static constexpr const auto kAL = x86_64::kAL;
-  static constexpr const auto kAX = x86_64::kAX;
-  static constexpr const auto kEBX = x86_64::kEBX;
-  static constexpr const auto kRBX = x86_64::kRBX;
-  static constexpr const auto kCL = x86_64::kCL;
-  static constexpr const auto kECX = x86_64::kECX;
-  static constexpr const auto kRCX = x86_64::kRCX;
-  static constexpr const auto kEDX = x86_64::kEDX;
-  static constexpr const auto kRDX = x86_64::kRDX;
-  static constexpr const auto kGeneralReg8 = x86_64::kGeneralReg8;
-  static constexpr const auto kGeneralReg16 = x86_64::kGeneralReg16;
-  static constexpr const auto kGeneralReg32 = x86_64::kGeneralReg32;
-  static constexpr const auto kGeneralReg64 = x86_64::kGeneralReg64;
-  static constexpr const auto kFpReg32 = x86_64::kFpReg32;
-  static constexpr const auto kFpReg64 = x86_64::kFpReg64;
-  static constexpr const auto kVecReg128 = x86_64::kVecReg128;
-  static constexpr const auto kXmmReg = x86_64::kXmmReg;
-  static constexpr const auto kFLAGS = x86_64::kFLAGS;
-
   MachineInsnX86_64(const MachineInsnX86_64& other) : MachineInsn(other) {
     for (int i = 0; i < kMaxMachineRegOperands; i++) {
       regs_[i] = other.regs_[i];
     }
     scale_ = other.scale_;
+    scale2_ = other.scale2_;
     disp_ = other.disp_;
+    disp2_ = other.disp2_;
     imm_ = other.imm_;
     cond_ = other.cond_;
 
@@ -157,10 +184,14 @@ class MachineInsnX86_64 : public MachineInsn {
     // No code here - will never be called!
   }
 
-  MachineMemOperandScale scale() const { return scale_; }
+  Assembler::ScaleFactor scale() const { return scale_; }
+
+  Assembler::ScaleFactor scale2() const { return scale2_; }
 
   uint32_t disp() const { return disp_; }
 
+  uint32_t disp2() const { return disp2_; }
+
   Assembler::Condition cond() const { return cond_; }
 
   uint64_t imm() const { return imm_; }
@@ -214,22 +245,28 @@ class MachineInsnX86_64 : public MachineInsn {
  protected:
   explicit MachineInsnX86_64(const MachineInsnInfo* info)
       : MachineInsn(info->opcode, info->num_reg_operands, info->reg_kinds, regs_, info->kind),
-        scale_(MachineMemOperandScale::kOne) {}
+        scale_(Assembler::kTimesOne) {}
+
+  void set_scale(Assembler::ScaleFactor scale) { scale_ = scale; }
 
-  void set_scale(MachineMemOperandScale scale) { scale_ = scale; }
+  void set_scale2(Assembler::ScaleFactor scale2) { scale2_ = scale2; }
 
   void set_disp(uint32_t disp) { disp_ = disp; }
 
+  void set_disp2(uint32_t disp2) { disp2_ = disp2; }
+
   void set_cond(Assembler::Condition cond) { cond_ = cond; }
 
   void set_imm(uint64_t imm) { imm_ = imm; }
 
  private:
   MachineReg regs_[kMaxMachineRegOperands];
-  MachineMemOperandScale scale_;
   uint32_t disp_;
-  uint64_t imm_;
+  Assembler::ScaleFactor scale_;
+  Assembler::ScaleFactor scale2_;
   Assembler::Condition cond_;
+  uint32_t disp2_;
+  uint64_t imm_;
 };
 
 // Syntax sugar.
@@ -289,26 +326,432 @@ class CallImmArg : public MachineInsnX86_64 {
   };
 };
 
-// This template is syntax sugar to group memory instructions with
-// different addressing modes.
-template <typename Absolute_, typename BaseDisp_, typename IndexDisp_, typename BaseIndexDisp_>
-class MemInsns {
- public:
-  using Absolute = Absolute_;
-  using BaseDisp = BaseDisp_;
-  using IndexDisp = IndexDisp_;
-  using BaseIndexDisp = BaseIndexDisp_;
+using MachineInsnForArch = MachineInsnX86_64;
+
+struct MemoryOperand {
+  MachineReg base = kInvalidMachineReg;
+  MachineReg index = kInvalidMachineReg;
+  Assembler::ScaleFactor scale = Assembler::kTimesOne;
+  // Note: x86-64 only supports 64bit offset in one instruction: movabs – and that one may only be
+  // be used to move a value to or from RAX. We don't use it in our code anywhere and it would be
+  // better to treat it as a special case, rather than pretend that other instruction may support
+  // 64bit offset.
+  int32_t disp = 0;
 };
 
-using MachineInsnForArch = MachineInsnX86_64;
+template <typename IntrinsicBindingInfo>
+class MachineInsnOperandsHelper;
+
+template <auto kEmitInsnFunc,
+          auto kMnemo,
+          auto GetOpcode,
+          typename CPUIDRestriction,
+          typename... Operands,
+          bool kSideEffects>
+class MachineInsnOperandsHelper<device_arch_info::DeviceInsnInfo<kEmitInsnFunc,
+                                                                 kMnemo,
+                                                                 kSideEffects,
+                                                                 GetOpcode,
+                                                                 CPUIDRestriction,
+                                                                 std::tuple<Operands...>>>
+    final {
+ public:
+  // We want to filter out any operands that are not used for Register args.
+  // Note: memory operands accept register and offset, thus they are included.
+  using RegOperandsTuple = decltype(std::tuple_cat(
+      std::declval<std::conditional_t<device_arch_info::kIsRegister<Operands> ||
+                                          device_arch_info::kIsMemoryOperand<Operands>,
+                                      std::tuple<Operands>,
+                                      std::tuple<>>>()...));
+  // Note: immediates accept appropriate type, register operands includes only register while memory
+  // operand needs both base register and offset.
+  using ConstructorArgsTuple = decltype(std::tuple_cat(
+      std::declval<std::conditional_t<device_arch_info::kIsCondition<Operands> ||
+                                          device_arch_info::kIsImmediate<Operands>,
+                                      std::tuple<typename Operands::Class::Type>,
+                                      std::conditional_t<device_arch_info::kIsRegister<Operands>,
+                                                         std::tuple<MachineReg>,
+                                                         std::tuple<const MemoryOperand&>>>>()...));
+};
 
-#include "gen_machine_ir_x86_64-inl.h"  // NOLINT generated file!
+template <typename IntrinsicBindingInfo,
+          typename = typename MachineInsnOperandsHelper<IntrinsicBindingInfo>::RegOperandsTuple,
+          typename = typename MachineInsnOperandsHelper<IntrinsicBindingInfo>::ConstructorArgsTuple>
+class MachineInsn;
+
+template <auto kEmitInsnFunc,
+          auto kMnemo,
+          auto GetOpcode,
+          typename CPUIDRestriction,
+          typename... Operands,
+          typename... RegOperands,
+          typename... ConstructorArgs,
+          bool kSideEffects>
+class MachineInsn<device_arch_info::DeviceInsnInfo<kEmitInsnFunc,
+                                                   kMnemo,
+                                                   kSideEffects,
+                                                   GetOpcode,
+                                                   CPUIDRestriction,
+                                                   std::tuple<Operands...>>,
+                  std::tuple<RegOperands...>,
+                  std::tuple<ConstructorArgs...>>
+    final : public MachineInsnX86_64 {
+ private:
+  template <auto>
+  static constexpr MachineInsnInfo GenMachineInsnInfo();
+  static constexpr std::array<MachineInsnInfo,
+                              1 << (2 * (device_arch_info::kIsMemoryOperand<Operands> + ... + 0))>
+  GenMachineInsnInfos();
 
-class MachineInfo {
  public:
-#include "machine_info_x86_64-inl.h"  // NOLINT generated file!
+  // This static simplifies constructing this MachineInsn in intrinsic implementations.
+  template <typename MachineIRBuilder>
+  static constexpr MachineInsn* (MachineIRBuilder::*kGenFunc)(ConstructorArgs...) =
+      &MachineIRBuilder::template Gen<MachineInsn>;
+
+  using DeviceInsnInfo = device_arch_info::DeviceInsnInfo<kEmitInsnFunc,
+                                                          kMnemo,
+                                                          kSideEffects,
+                                                          GetOpcode,
+                                                          CPUIDRestriction,
+                                                          std::tuple<Operands...>>;
+
+  explicit MachineInsn(ConstructorArgs... args) : MachineInsnX86_64(&GenMachineInsnInfo(args...)) {
+    constexpr int kConditionalsOperandsCount = (device_arch_info::kIsCondition<Operands> + ... + 0);
+    static_assert(kConditionalsOperandsCount <= 1);
+    constexpr int kImmediateOperandsCount = (device_arch_info::kIsImmediate<Operands> + ... + 0);
+    static_assert(kImmediateOperandsCount <= 1);
+    constexpr int kMemoryOperandsCount = (device_arch_info::kIsMemoryOperand<Operands> + ... + 0);
+    static_assert(kMemoryOperandsCount <= 2);
+    size_t reg_idx{}, mem_idx{};
+    (
+        [&reg_idx, &mem_idx, this]<typename Operand, typename ConstructorArg>(ConstructorArg arg) {
+          if constexpr (device_arch_info::kIsCondition<Operand>) {
+            MachineInsnX86_64::set_cond(arg);
+          } else if constexpr (device_arch_info::kIsImmediate<Operand>) {
+            MachineInsnX86_64::set_imm(arg);
+          } else if constexpr (device_arch_info::kIsRegister<Operand>) {
+            static_assert(std::is_same_v<MachineReg, ConstructorArg>);
+            MachineInsnX86_64::SetRegAt(reg_idx++, arg);
+          } else if constexpr (device_arch_info::kIsMemoryOperand<Operand>) {
+            static_assert(std::is_same_v<const MemoryOperand&, ConstructorArg>);
+            if (arg.base != kInvalidMachineReg) {
+              MachineInsnX86_64::SetRegAt(reg_idx++, arg.base);
+            }
+            if (arg.index != kInvalidMachineReg) {
+              MachineInsnX86_64::SetRegAt(reg_idx++, arg.index);
+            }
+            if (++mem_idx == 1) {
+              MachineInsnX86_64::set_disp(arg.disp);
+              MachineInsnX86_64::set_scale(arg.scale);
+            } else if (mem_idx == 2) {
+              MachineInsnX86_64::set_disp2(arg.disp);
+              MachineInsnX86_64::set_scale2(arg.scale);
+            }
+          }
+        }.template operator()<Operands, ConstructorArgs>(args),
+        ...);
+  }
+
+  static constexpr std::array<MachineInsnInfo,
+                              1 << (2 * (device_arch_info::kIsMemoryOperand<Operands> + ... + 0))>
+      kInfos = GenMachineInsnInfos();
+  // Note: kInfo has well-defined meaning – it's information about intrinsic with all MemoryOperand
+  // types ignored.
+  // This is useful not only for instructions without operands, but also for SSA form: since these
+  // registers that are passed into MemoryOperand are always kUse and never kDef or kUseDef we may
+  // ignore them in our analysis.
+  static constexpr const MachineInsnInfo& kInfo = kInfos[0];
+
+  int NumRegOperands() {
+    constexpr int kMemoryOperandsCount = (device_arch_info::kIsMemoryOperand<Operands> + ... + 0);
+    constexpr int kMemoryOperandsCountMask = (1 << (2 * kMemoryOperandsCount)) - 1;
+    return kInfos[(opcode() >> kLowMachineOpcodeBits) & kMemoryOperandsCountMask].num_reg_operands;
+  }
+
+  const MachineRegKind& RegKindAt(int i) {
+    constexpr int kMemoryOperandsCount = (device_arch_info::kIsMemoryOperand<Operands> + ... + 0);
+    constexpr int kMemoryOperandsCountMask = (1 << (2 * kMemoryOperandsCount)) - 1;
+    return kInfos[(opcode() >> kLowMachineOpcodeBits) & kMemoryOperandsCountMask].reg_kinds[i];
+  }
+
+  std::string GetDebugString() const override {
+    std::string s(kMnemo);
+    // Code below assumes that we have at most two memory operands.
+    static_assert((device_arch_info::kIsMemoryOperand<Operands> + ... + 0) <= 2);
+    size_t arg_idx{}, reg_idx{}, mem_idx{};
+    (
+        [&s, &arg_idx, &reg_idx, &mem_idx, this]<typename Operand> {
+          s += " ";
+          if (arg_idx > 0) {
+            s += ", ";
+          }
+          if constexpr (device_arch_info::kIsCondition<Operand>) {
+            s += GetCondOperandDebugString(this);
+          } else if constexpr (device_arch_info::kIsImmediate<Operand>) {
+            s += GetImmOperandDebugString(this);
+          } else if constexpr (device_arch_info::kIsMemoryOperand<Operand>) {
+            auto [has_base, has_index] = OpcodeHasMemoryBaseIndex(mem_idx++);
+            if (mem_idx == 1) {
+              if (has_base) {
+                if (has_index) {
+                  s += GetBaseIndexDispMemOperandDebugString(this, reg_idx);
+                  reg_idx += 2;
+                } else {
+                  s += GetBaseDispMemOperandDebugString(this, reg_idx++);
+                }
+              } else if (has_index) {
+                s += GetIndexDispMemOperandDebugString(this, reg_idx++);
+              } else {
+                s += GetAbsoluteMemOperandDebugString(this);
+              }
+            } else /* mem_idx == 2 */ {
+              if (has_base) {
+                if (has_index) {
+                  s += StringPrintf("[%s + %s * %d + 0x%x]",
+                                    GetRegOperandDebugString(this, reg_idx).c_str(),
+                                    GetRegOperandDebugString(this, reg_idx + 1).c_str(),
+                                    1 << MachineInsnX86_64::scale2(),
+                                    MachineInsnX86_64::disp2());
+                  reg_idx += 2;
+                } else {
+                  s += StringPrintf(
+                      "[%s + 0x%x]", GetRegOperandDebugString(this, reg_idx++).c_str(), disp2());
+                }
+              } else if (has_index) {
+                s += StringPrintf("[%s * %d + 0x%x]",
+                                  GetRegOperandDebugString(this, reg_idx++).c_str(),
+                                  1 << MachineInsnX86_64::scale2(),
+                                  MachineInsnX86_64::disp2());
+              } else {
+                s += StringPrintf("[0x%x]", MachineInsnX86_64::disp2());
+              }
+            }
+          } else if constexpr (device_arch_info::kIsImplicitReg<Operand>) {
+            s += GetImplicitRegOperandDebugString(this, reg_idx++);
+          } else {
+            s += GetRegOperandDebugString(this, reg_idx++);
+          }
+          arg_idx++;
+        }.template operator()<Operands>(),
+        ...);
+
+    if (MachineInsnX86_64::recovery_pc()) {
+      s += StringPrintf(" <0x%" PRIxPTR ">", MachineInsnX86_64::recovery_pc());
+    }
+    return s;
+  }
+
+  void Emit(CodeEmitter* as) const override {
+    // Code below assumes that we have at most two memory operands.
+    static_assert((device_arch_info::kIsMemoryOperand<Operands> + ... + 0) <= 2);
+    size_t reg_idx{}, mem_idx{};
+    std::apply(
+        kEmitInsnFunc,
+        std::tuple_cat(std::tuple<CodeEmitter&>{*as}, [&reg_idx, &mem_idx, this]<typename Operand> {
+          // Suppress spurious warnings.
+          // See https://github.com/llvm/llvm-project/issues/34798#issuecomment-980989495
+          (void)reg_idx;
+          (void)mem_idx;
+          if constexpr (device_arch_info::kIsCondition<Operands>) {
+            return std::tuple{MachineInsnX86_64::cond()};
+          } else if constexpr (device_arch_info::kIsImmediate<Operands>) {
+            return std::tuple{MachineInsnX86_64::imm()};
+          } else if constexpr (device_arch_info::kIsMemoryOperand<Operands>) {
+            auto [has_base, has_index] = OpcodeHasMemoryBaseIndex(mem_idx++);
+            Assembler::Operand operand;
+            if (has_base) {
+              operand.base = GetGReg(MachineInsnX86_64::RegAt(reg_idx++));
+            }
+            if (has_index) {
+              operand.index = GetGReg(MachineInsnX86_64::RegAt(reg_idx++));
+            }
+            if (mem_idx == 1) {
+              if (has_index) {
+                operand.scale = scale();
+              }
+              operand.disp = static_cast<int32_t>(disp());
+            } else /* mem_idx == 2 */ {
+              if (has_index) {
+                operand.scale = scale2();
+              }
+              operand.disp = static_cast<int32_t>(disp2());
+            }
+            return std::tuple{operand};
+          } else if constexpr (device_arch_info::kIsImplicitReg<Operand>) {
+            return reg_idx++, std::tuple{};
+          } else if constexpr (Operand::Class::kAsRegister == 'x') {
+            return std::tuple{GetXReg(MachineInsnX86_64::RegAt(reg_idx++))};
+          } else if constexpr (Operand::Class::kAsRegister == 'r' ||
+                               Operand::Class::kAsRegister == 'q') {
+            return std::tuple{GetGReg(MachineInsnX86_64::RegAt(reg_idx++))};
+          } else {
+            static_assert(kDependentTypeFalse<Operand>);
+          }
+        }.template operator()<Operands>()...));
+  }
+
+ private:
+  // Ensure that bits that we are using to split opcodes are not used by opcode already.
+  // Note: we need to do that with all opcodes, including opcodes without memory operands,
+  // to guarantee that memory-using opcodes don't clash with memory non-using opcodes.
+  static_assert(!(static_cast<int>(GetOpcode.template operator()<MachineOpcode>()) &
+                  ((~0) << kLowMachineOpcodeBits)));
+
+  static constexpr auto GetInsnKind() {
+    if constexpr (kSideEffects) {
+      return kMachineInsnSideEffects;
+    } else {
+      return kMachineInsnDefault;
+    }
+  }
+
+  constexpr std::pair<bool, bool> OpcodeHasMemoryBaseIndex(size_t mem_operand_idx) const {
+    int base_index_info = opcode() >> (kLowMachineOpcodeBits + mem_operand_idx * 2);
+    return {base_index_info & 1, base_index_info & 2};
+  }
+
+  static const MachineInsnInfo& GenMachineInsnInfo(ConstructorArgs... args) {
+    constexpr int kMemoryOperandsCount =
+        (std::is_same_v<ConstructorArgs, const MemoryOperand&> + ... + 0);
+    static_assert(kMemoryOperandsCount <= 2);
+    if constexpr (kMemoryOperandsCount == 0) {
+      return kInfos[0];
+    } else {
+      size_t index = 0;
+      size_t current_bit = 1;
+      (
+          [&index, &current_bit]<typename ConstructorArg>(ConstructorArg arg) {
+            if constexpr (std::is_same_v<ConstructorArg, const MemoryOperand&>) {
+              if (arg.base != kInvalidMachineReg) {
+                index |= current_bit;
+              }
+              current_bit <<= 1;
+              if (arg.index != kInvalidMachineReg) {
+                index |= current_bit;
+              }
+              current_bit <<= 1;
+            }
+          }.template operator()<ConstructorArgs>(args),
+          ...);
+      return kInfos[index];
+    }
+  }
 };
 
+template <auto kEmitInsnFunc,
+          auto kMnemo,
+          auto GetOpcode,
+          typename CPUIDRestriction,
+          typename... Operands,
+          typename... RegOperands,
+          typename... ConstructorArgs,
+          bool kSideEffects>
+template <auto BaseIndexRegistersUsed>
+constexpr MachineInsnInfo MachineInsn<device_arch_info::DeviceInsnInfo<kEmitInsnFunc,
+                                                                       kMnemo,
+                                                                       kSideEffects,
+                                                                       GetOpcode,
+                                                                       CPUIDRestriction,
+                                                                       std::tuple<Operands...>>,
+                                      std::tuple<RegOperands...>,
+                                      std::tuple<ConstructorArgs...>>::GenMachineInsnInfo() {
+  MachineInsnInfo result = {
+    .opcode = GetOpcode.template operator()<MachineOpcode>(),
+    .kind = GetInsnKind()
+  };
+  size_t mem_operand_bit_pos = 0;
+  (
+      [&opcode = result.opcode,
+       &mem_operand_bit_pos,
+       &num_reg_operands = result.num_reg_operands,
+       &reg_kinds = result.reg_kinds]<typename Operand> {
+        if constexpr (device_arch_info::kIsRegister<Operand>) {
+          static_assert(MachineRegKind::kDef ==
+                        static_cast<MachineRegKind::StandardAccess>(device_arch_info::kDef));
+          static_assert(
+              MachineRegKind::kDefEarlyClobber ==
+              static_cast<MachineRegKind::StandardAccess>(device_arch_info::kDefEarlyClobber));
+          static_assert(MachineRegKind::kUse ==
+                        static_cast<MachineRegKind::StandardAccess>(device_arch_info::kUse));
+          static_assert(MachineRegKind::kUseDef ==
+                        static_cast<MachineRegKind::StandardAccess>(device_arch_info::kUseDef));
+          reg_kinds[num_reg_operands++] = {
+              &kRegisterClass<typename Operand::Class>,
+              static_cast<MachineRegKind::StandardAccess>(Operand::kUsage)};
+        } else {
+          static_assert(device_arch_info::kIsMemoryOperand<Operand>);
+          // Note: normally size of array should match number of memory operands, but that's not
+          // true for kInfo where it's zero.
+          // TODO(399130034): remove std::size when kInfo is removed.
+          if (std::size(BaseIndexRegistersUsed) > mem_operand_bit_pos &&
+              BaseIndexRegistersUsed[mem_operand_bit_pos]) {
+            reg_kinds[num_reg_operands++] = {&kGeneralReg64, MachineRegKind::kUse};
+            opcode = static_cast<MachineOpcode>(
+                opcode | (1 << (kLowMachineOpcodeBits + mem_operand_bit_pos)));
+          }
+          mem_operand_bit_pos++;
+          if (std::size(BaseIndexRegistersUsed) > mem_operand_bit_pos &&
+              BaseIndexRegistersUsed[mem_operand_bit_pos]) {
+            reg_kinds[num_reg_operands++] = {&kGeneralReg64, MachineRegKind::kUse};
+            opcode = static_cast<MachineOpcode>(
+                opcode | (1 << (kLowMachineOpcodeBits + mem_operand_bit_pos)));
+          }
+          mem_operand_bit_pos++;
+        }
+      }.template operator()<RegOperands>(),
+      ...);
+  return result;
+}
+
+template <auto kEmitInsnFunc,
+          auto kMnemo,
+          auto GetOpcode,
+          typename CPUIDRestriction,
+          typename... Operands,
+          typename... RegOperands,
+          typename... ConstructorArgs,
+          bool kSideEffects>
+constexpr std::array<MachineInsnInfo,
+                     1 << (2 * (device_arch_info::kIsMemoryOperand<Operands> + ... + 0))>
+MachineInsn<device_arch_info::DeviceInsnInfo<kEmitInsnFunc,
+                                             kMnemo,
+                                             kSideEffects,
+                                             GetOpcode,
+                                             CPUIDRestriction,
+                                             std::tuple<Operands...>>,
+            std::tuple<RegOperands...>,
+            std::tuple<ConstructorArgs...>>::GenMachineInsnInfos() {
+  constexpr int kMemoryOperandsCount = (device_arch_info::kIsMemoryOperand<Operands> + ... + 0);
+  if constexpr (kMemoryOperandsCount == 0) {
+    return {GenMachineInsnInfo<std::array<bool, 0>{}>()};
+  } else if constexpr (kMemoryOperandsCount == 1) {
+    return {GenMachineInsnInfo<std::array{false, false}>(),
+            GenMachineInsnInfo<std::array{true, false}>(),
+            GenMachineInsnInfo<std::array{false, true}>(),
+            GenMachineInsnInfo<std::array{true, true}>()};
+  } else if constexpr (kMemoryOperandsCount == 2) {
+    return {GenMachineInsnInfo<std::array{false, false, false, false}>(),
+            GenMachineInsnInfo<std::array{true, false, false, false}>(),
+            GenMachineInsnInfo<std::array{false, true, false, false}>(),
+            GenMachineInsnInfo<std::array{true, true, false, false}>(),
+            GenMachineInsnInfo<std::array{false, false, true, false}>(),
+            GenMachineInsnInfo<std::array{true, false, true, false}>(),
+            GenMachineInsnInfo<std::array{false, true, true, false}>(),
+            GenMachineInsnInfo<std::array{true, true, true, false}>(),
+            GenMachineInsnInfo<std::array{false, false, false, true}>(),
+            GenMachineInsnInfo<std::array{true, false, false, true}>(),
+            GenMachineInsnInfo<std::array{false, true, false, true}>(),
+            GenMachineInsnInfo<std::array{true, true, false, true}>(),
+            GenMachineInsnInfo<std::array{false, false, true, true}>(),
+            GenMachineInsnInfo<std::array{true, false, true, true}>(),
+            GenMachineInsnInfo<std::array{false, true, true, true}>(),
+            GenMachineInsnInfo<std::array{true, true, true, true}>()};
+  } else {
+    static_assert(kDependentTypeFalse<std::tuple<Operands...>>);
+  }
+}
+
 class MachineIR : public berberis::MachineIR {
  public:
   enum class BasicBlockOrder {
@@ -326,6 +769,60 @@ class MachineIR : public berberis::MachineIR {
     bb_order_ = BasicBlockOrder::kUnordered;
   }
 
+  [[nodiscard]] bool IsCPUStateGet(berberis::MachineInsn* insn) const {
+    if (insn->opcode() != kMachineOpMovqRegMemBaseDisp &&
+        insn->opcode() != kMachineOpMovdqaXRegMemBaseDisp &&
+        insn->opcode() != kMachineOpMovwRegMemBaseDisp &&
+        insn->opcode() != kMachineOpMovsdXRegMemBaseDisp) {
+      return false;
+    }
+
+    auto x86_insn = AsMachineInsnX86_64(insn);
+
+    // Check that it is not for ThreadState fields outside of CPUState.
+    if (x86_insn->disp() >= sizeof(CPUState)) {
+      return false;
+    }
+
+    // reservation_value is loaded in HeavyOptimizerFrontend::AtomicLoad and written
+    // in HeavyOptimizerFrontend::AtomicStore partially (for performance
+    // reasons), which is not supported by our context optimizer.
+    auto reservation_value_offset = offsetof(ThreadState, cpu.reservation_value);
+    if (x86_insn->disp() >= reservation_value_offset &&
+        x86_insn->disp() < reservation_value_offset + sizeof(Reservation)) {
+      return false;
+    }
+
+    return x86_insn->RegAt(1) == kCPUStatePointer;
+  }
+
+  [[nodiscard]] bool IsCPUStatePut(berberis::MachineInsn* insn) const {
+    if (insn->opcode() != kMachineOpMovqMemBaseDispReg &&
+        insn->opcode() != kMachineOpMovdqaMemBaseDispXReg &&
+        insn->opcode() != kMachineOpMovwMemBaseDispReg &&
+        insn->opcode() != kMachineOpMovsdMemBaseDispXReg) {
+      return false;
+    }
+
+    auto x86_insn = AsMachineInsnX86_64(insn);
+
+    // Check that it is not for ThreadState fields outside of CPUState.
+    if (x86_insn->disp() >= sizeof(CPUState)) {
+      return false;
+    }
+
+    // reservation_value is loaded in HeavyOptimizerFrontend::AtomicLoad and written
+    // in HeavyOptimizerFrontend::AtomicStore partially (for performance
+    // reasons), which is not supported by our context optimizer.
+    auto reservation_value_offset = offsetof(ThreadState, cpu.reservation_value);
+    if (x86_insn->disp() >= reservation_value_offset &&
+        x86_insn->disp() < reservation_value_offset + sizeof(Reservation)) {
+      return false;
+    }
+
+    return x86_insn->RegAt(0) == kCPUStatePointer;
+  }
+
   [[nodiscard]] MachineBasicBlock* NewBasicBlock() {
     return NewInArena<MachineBasicBlock>(arena(), arena(), ReserveBasicBlockId());
   }
@@ -351,7 +848,7 @@ class MachineIR : public berberis::MachineIR {
     return new_bb;
   }
 
-  [[nodiscard]] static bool IsControlTransfer(MachineInsn* insn) {
+  [[nodiscard]] static bool IsControlTransfer(berberis::MachineInsn* insn) {
     return insn->opcode() == kMachineOpPseudoBranch ||
            insn->opcode() == kMachineOpPseudoCondBranch ||
            insn->opcode() == kMachineOpPseudoIndirectJump || insn->opcode() == kMachineOpPseudoJump;
@@ -361,6 +858,123 @@ class MachineIR : public berberis::MachineIR {
 
   void set_bb_order(BasicBlockOrder order) { bb_order_ = order; }
 
+  using berberis::MachineIR::NewInsn;
+
+  template <typename T, typename... Args>
+  [[nodiscard]] T* NewInsn(Args... args) {
+    return berberis::MachineIR::template NewInsn<T, Args...>(args...);
+  }
+
+  template <template <typename> typename InsnType>
+  using MachineInsnType =
+      MachineInsn<typename InsnType<typename CodeEmitter::Assemblers>::DeviceInsnInfo>;
+
+  template <template <typename> typename InsnType, size_t N>
+  using GenArg = std::tuple_element_t<
+      N,
+      typename MachineInsnOperandsHelper<typename InsnType<
+          typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple>;
+
+  template <template <typename> typename InsnType>
+  [[nodiscard]] auto NewInsn()
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 0,
+          MachineInsnType<InsnType>*> {
+    return NewInsn<MachineInsnType<InsnType>>();
+  }
+
+  template <template <typename> typename InsnType>
+  [[nodiscard]] auto NewInsn(GenArg<InsnType, 0> arg0)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 1,
+          MachineInsnType<InsnType>*> {
+    return NewInsn<MachineInsnType<InsnType>, GenArg<InsnType, 0>>(arg0);
+  }
+
+  template <template <typename> typename InsnType>
+  [[nodiscard]] auto NewInsn(GenArg<InsnType, 0> arg0, GenArg<InsnType, 1> arg1)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 2,
+          MachineInsnType<InsnType>*> {
+    return NewInsn<MachineInsnType<InsnType>, GenArg<InsnType, 0>, GenArg<InsnType, 1>>(arg0, arg1);
+  }
+
+  template <template <typename> typename InsnType>
+  [[nodiscard]] auto NewInsn(GenArg<InsnType, 0> arg0,
+                             GenArg<InsnType, 1> arg1,
+                             GenArg<InsnType, 2> arg2)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 3,
+          MachineInsnType<InsnType>*> {
+    return NewInsn<MachineInsnType<InsnType>,
+                   GenArg<InsnType, 0>,
+                   GenArg<InsnType, 1>,
+                   GenArg<InsnType, 2>>(arg0, arg1, arg2);
+  }
+
+  template <template <typename> typename InsnType>
+  [[nodiscard]] auto NewInsn(GenArg<InsnType, 0> arg0,
+                             GenArg<InsnType, 1> arg1,
+                             GenArg<InsnType, 2> arg2,
+                             GenArg<InsnType, 3> arg3)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 4,
+          MachineInsnType<InsnType>*> {
+    return NewInsn<MachineInsnType<InsnType>,
+                   GenArg<InsnType, 0>,
+                   GenArg<InsnType, 1>,
+                   GenArg<InsnType, 2>,
+                   GenArg<InsnType, 3>>(arg0, arg1, arg2, arg3);
+  }
+
+  template <template <typename> typename InsnType>
+  [[nodiscard]] auto NewInsn(GenArg<InsnType, 0> arg0,
+                             GenArg<InsnType, 1> arg1,
+                             GenArg<InsnType, 2> arg2,
+                             GenArg<InsnType, 3> arg3,
+                             GenArg<InsnType, 4> arg4)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 5,
+          MachineInsnType<InsnType>*> {
+    return NewInsn<MachineInsnType<InsnType>,
+                   GenArg<InsnType, 0>,
+                   GenArg<InsnType, 1>,
+                   GenArg<InsnType, 2>,
+                   GenArg<InsnType, 3>,
+                   GenArg<InsnType, 4>>(arg0, arg1, arg2, arg3, arg4);
+  }
+
+  template <template <typename> typename InsnType>
+  [[nodiscard]] auto NewInsn(GenArg<InsnType, 0> arg0,
+                             GenArg<InsnType, 1> arg1,
+                             GenArg<InsnType, 2> arg2,
+                             GenArg<InsnType, 3> arg3,
+                             GenArg<InsnType, 4> arg4,
+                             GenArg<InsnType, 5> arg5)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 6,
+          MachineInsnType<InsnType>*> {
+    return NewInsn<MachineInsnType<InsnType>,
+                   GenArg<InsnType, 0>,
+                   GenArg<InsnType, 1>,
+                   GenArg<InsnType, 2>,
+                   GenArg<InsnType, 3>,
+                   GenArg<InsnType, 4>,
+                   GenArg<InsnType, 5>>(arg0, arg1, arg2, arg3, arg4, arg5);
+  }
+
+  template <template <typename> typename InsnType, typename... Args>
+  [[nodiscard]] MachineInsnType<InsnType>* NewInsn(Args... args) {
+    return NewInsn<MachineInsnType<InsnType>, Args...>(args...);
+  }
+
  private:
   BasicBlockOrder bb_order_;
 };
diff --git a/backend/include/berberis/backend/x86_64/machine_ir_builder.h b/backend/include/berberis/backend/x86_64/machine_ir_builder.h
index cff67232..cfaeccad 100644
--- a/backend/include/berberis/backend/x86_64/machine_ir_builder.h
+++ b/backend/include/berberis/backend/x86_64/machine_ir_builder.h
@@ -28,6 +28,61 @@
 
 namespace berberis::x86_64 {
 
+template <auto kFunc, typename InoutTuple1, typename InputTuple2>
+class TupleMergePlan;
+
+template <typename MachineInsn,
+          typename MachineIRBuilder,
+          typename... OutputArgs,
+          MachineInsn* (MachineIRBuilder::*kFunc)(OutputArgs...),
+          typename... InputArgs1,
+          typename... InputArgs2>
+class TupleMergePlan<kFunc, std::tuple<InputArgs1...>, std::tuple<InputArgs2...>> {
+  static_assert(sizeof...(OutputArgs) == sizeof...(InputArgs1) + sizeof...(InputArgs2));
+  template <size_t index1, size_t index2>
+  void static constexpr GenTupleMergePlan(std::array<size_t, sizeof...(OutputArgs)>& result) {
+    if constexpr (sizeof...(InputArgs1) == index1) {
+      static_assert(std::is_same_v<
+                    decltype(std::get<index1 + index2>(std::declval<std::tuple<OutputArgs...>>())),
+                    decltype(std::get<index2>(std::declval<std::tuple<InputArgs2...>>()))>);
+      result[index1 + index2] = sizeof...(InputArgs1) + index2;
+      if constexpr (index2 + 1 < sizeof...(InputArgs2)) {
+        return GenTupleMergePlan<index1, index2 + 1>(result);
+      }
+    } else if constexpr (sizeof...(InputArgs2) == index2) {
+      static_assert(std::is_same_v<
+                    decltype(std::get<index1 + index2>(std::declval<std::tuple<OutputArgs...>>())),
+                    decltype(std::get<index1>(std::declval<std::tuple<InputArgs1...>>()))>);
+      result[index1 + index2] = index1;
+      if constexpr (index1 + 1 < sizeof...(InputArgs1)) {
+        return GenTupleMergePlan<index1 + 1, index2>(result);
+      }
+    } else if constexpr (std::is_same_v<decltype(std::get<index1 + index2>(
+                                            std::declval<std::tuple<OutputArgs...>>())),
+                                        decltype(std::get<index1>(
+                                            std::declval<std::tuple<InputArgs1...>>()))>) {
+      result[index1 + index2] = index1;
+      return GenTupleMergePlan<index1 + 1, index2>(result);
+    } else {
+      result[index1 + index2] = sizeof...(InputArgs1) + index2;
+      return GenTupleMergePlan<index1, index2 + 1>(result);
+    }
+  }
+  static constexpr std::array<size_t, sizeof...(OutputArgs)> GenTupleMergePlan() {
+    std::array<size_t, sizeof...(OutputArgs)> result;
+    if constexpr (sizeof...(InputArgs1) > 0 || sizeof...(InputArgs2) > 0) {
+      GenTupleMergePlan<0, 0>(result);
+    }
+    return result;
+  }
+
+ public:
+  static constexpr std::array<size_t, sizeof...(OutputArgs)> kPlan = GenTupleMergePlan();
+};
+
+template <auto kFunc, typename InoutTuple1, typename InputTuple2>
+inline constexpr auto& kTupleMergePlan = TupleMergePlan<kFunc, InoutTuple1, InputTuple2>::kPlan;
+
 // Syntax sugar for building machine IR.
 class MachineIRBuilder : public MachineIRBuilderBase<MachineIR> {
  public:
@@ -44,20 +99,147 @@ class MachineIRBuilder : public MachineIRBuilderBase<MachineIR> {
     return MachineIRBuilderBase::Gen<InsnType, Args...>(args...);
   }
 
+  template <template <typename> typename InsnType>
+  using MachineInsnType =
+      MachineInsn<typename InsnType<typename CodeEmitter::Assemblers>::DeviceInsnInfo>;
+
+  template <template <typename> typename InsnType, size_t N>
+  using GenArg = std::tuple_element_t<
+      N,
+      typename MachineInsnOperandsHelper<typename InsnType<
+          typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple>;
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen()
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 0,
+          MachineInsnType<InsnType>*> {
+    return MachineIRBuilderBase::Gen<MachineInsnType<InsnType>>();
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 1,
+          MachineInsnType<InsnType>*> {
+    return MachineIRBuilderBase::Gen<MachineInsnType<InsnType>, GenArg<InsnType, 0>>(arg0);
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0, GenArg<InsnType, 1> arg1)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 2,
+          MachineInsnType<InsnType>*> {
+    return MachineIRBuilderBase::
+        Gen<MachineInsnType<InsnType>, GenArg<InsnType, 0>, GenArg<InsnType, 1>>(arg0, arg1);
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0,
+                           GenArg<InsnType, 1> arg1,
+                           GenArg<InsnType, 2> arg2)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 3,
+          MachineInsnType<InsnType>*> {
+    return MachineIRBuilderBase::Gen<MachineInsnType<InsnType>,
+                                     GenArg<InsnType, 0>,
+                                     GenArg<InsnType, 1>,
+                                     GenArg<InsnType, 2>>(arg0, arg1, arg2);
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0,
+                           GenArg<InsnType, 1> arg1,
+                           GenArg<InsnType, 2> arg2,
+                           GenArg<InsnType, 3> arg3)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 4,
+          MachineInsnType<InsnType>*> {
+    return MachineIRBuilderBase::Gen<MachineInsnType<InsnType>,
+                                     GenArg<InsnType, 0>,
+                                     GenArg<InsnType, 1>,
+                                     GenArg<InsnType, 2>,
+                                     GenArg<InsnType, 3>>(arg0, arg1, arg2, arg3);
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0,
+                           GenArg<InsnType, 1> arg1,
+                           GenArg<InsnType, 2> arg2,
+                           GenArg<InsnType, 3> arg3,
+                           GenArg<InsnType, 4> arg4)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 5,
+          MachineInsnType<InsnType>*> {
+    return MachineIRBuilderBase::Gen<MachineInsnType<InsnType>,
+                                     GenArg<InsnType, 0>,
+                                     GenArg<InsnType, 1>,
+                                     GenArg<InsnType, 2>,
+                                     GenArg<InsnType, 3>,
+                                     GenArg<InsnType, 4>>(arg0, arg1, arg2, arg3, arg4);
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0,
+                           GenArg<InsnType, 1> arg1,
+                           GenArg<InsnType, 2> arg2,
+                           GenArg<InsnType, 3> arg3,
+                           GenArg<InsnType, 4> arg4,
+                           GenArg<InsnType, 5> arg5)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 6,
+          MachineInsnType<InsnType>*> {
+    return MachineIRBuilderBase::Gen<MachineInsnType<InsnType>,
+                                     GenArg<InsnType, 0>,
+                                     GenArg<InsnType, 1>,
+                                     GenArg<InsnType, 2>,
+                                     GenArg<InsnType, 3>,
+                                     GenArg<InsnType, 4>,
+                                     GenArg<InsnType, 5>>(arg0, arg1, arg2, arg3, arg4, arg5);
+  }
+
+  template <auto kFunc, auto kTupleMergePlan, typename... Args, std::size_t... kIndex>
+  auto Gen(std::tuple<Args...> args, std::index_sequence<kIndex...>) {
+    return std::apply(
+        kFunc,
+        std::tuple_cat(std::tuple{this}, std::tuple{std::get<kTupleMergePlan[kIndex]>(args)}...));
+  }
+
+  template <auto kFunc,
+            auto kTupleMergePlan,
+            typename... Args,
+            typename kIndexes = std::make_index_sequence<sizeof...(Args)>>
+  auto Gen(std::tuple<Args...> args) {
+    return Gen<kFunc, kTupleMergePlan>(args, kIndexes{});
+  }
+
+  template <auto kFunc, typename... InputArgs1, typename... InputArgs2>
+  auto Gen(std::tuple<InputArgs1...> args1, std::tuple<InputArgs2...> args2) {
+    return Gen<kFunc, kTupleMergePlan<kFunc, std::tuple<InputArgs1...>, std::tuple<InputArgs2...>>>(
+        std::tuple_cat(args1, args2));
+  }
+
   void GenGet(MachineReg dst_reg, int32_t offset) {
-    Gen<x86_64::MovqRegMemBaseDisp>(dst_reg, x86_64::kMachineRegRBP, offset);
+    Gen<x86_64::MovqRegOp>(dst_reg, {.base = x86_64::kMachineRegRBP, .disp = offset});
   }
 
   void GenPut(int32_t offset, MachineReg src_reg) {
-    Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, offset, src_reg);
+    Gen<x86_64::MovqOpReg>({.base = x86_64::kMachineRegRBP, .disp = offset}, src_reg);
   }
 
   template <size_t kSize>
   void GenGetSimd(MachineReg dst_reg, int32_t offset) {
     if constexpr (kSize == 8) {
-      Gen<x86_64::MovsdXRegMemBaseDisp>(dst_reg, x86_64::kMachineRegRBP, offset);
+      Gen<x86_64::MovsdXRegOp>(dst_reg, {.base = x86_64::kMachineRegRBP, .disp = offset});
     } else if constexpr (kSize == 16) {
-      Gen<x86_64::MovdqaXRegMemBaseDisp>(dst_reg, x86_64::kMachineRegRBP, offset);
+      Gen<x86_64::MovdqaXRegOp>(dst_reg, {.base = x86_64::kMachineRegRBP, .disp = offset});
     } else {
       static_assert(kDependentValueFalse<kSize>);
     }
@@ -66,9 +248,9 @@ class MachineIRBuilder : public MachineIRBuilderBase<MachineIR> {
   template <size_t kSize>
   void GenSetSimd(int32_t offset, MachineReg src_reg) {
     if constexpr (kSize == 8) {
-      Gen<x86_64::MovsdMemBaseDispXReg>(x86_64::kMachineRegRBP, offset, src_reg);
+      Gen<x86_64::MovsdOpXReg>({.base = x86_64::kMachineRegRBP, .disp = offset}, src_reg);
     } else if constexpr (kSize == 16) {
-      Gen<x86_64::MovdqaMemBaseDispXReg>(x86_64::kMachineRegRBP, offset, src_reg);
+      Gen<x86_64::MovdqaOpXReg>({.base = x86_64::kMachineRegRBP, .disp = offset}, src_reg);
     } else {
       static_assert(kDependentValueFalse<kSize>);
     }
diff --git a/backend/include/berberis/backend/x86_64/read_flags_optimizer.h b/backend/include/berberis/backend/x86_64/read_flags_optimizer.h
index c43f67bf..c2870f07 100644
--- a/backend/include/berberis/backend/x86_64/read_flags_optimizer.h
+++ b/backend/include/berberis/backend/x86_64/read_flags_optimizer.h
@@ -17,25 +17,63 @@
 #ifndef BERBERIS_BACKEND_X86_64_READ_FLAGS_OPTIMIZER_H_
 #define BERBERIS_BACKEND_X86_64_READ_FLAGS_OPTIMIZER_H_
 
-#include "berberis/backend/common/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir_analysis.h"
+#include "berberis/base/arena_map.h"
 #include "berberis/base/arena_vector.h"
 
 namespace berberis::x86_64 {
 
-using InsnGenerator = MachineInsn* (*)(MachineIR*, MachineInsn*);
+using InsnGenerator = berberis::MachineInsn* (*)(MachineIR*, berberis::MachineInsn*);
+
+struct FlagSettingInsn {
+  MachineInsnList::iterator insn;
+  bool cmc;
+};
+
+struct ReadFlagsOptContext {
+  MachineBasicBlock* bb;
+  // Original readflag instruction.
+  MachineInsnList::iterator readflags_insn;
+  // Original instruction that set flag register.
+  FlagSettingInsn flag_set_insn;
+};
 
 bool CheckRegsUnusedWithinInsnRange(MachineInsnList::iterator insn_it,
                                     MachineInsnList::iterator end,
-                                    ArenaVector<MachineReg>& regs);
-bool CheckPostLoopNode(MachineBasicBlock* block, const ArenaVector<MachineReg>& regs);
-bool CheckSuccessorNode(Loop* loop, MachineBasicBlock* block, ArenaVector<MachineReg>& regs);
+                                    MachineRegVector& regs);
+bool CheckPostLoopNode(MachineBasicBlock* block, const MachineRegVector& regs);
+bool CheckSuccessorNode(Loop* loop, MachineBasicBlock* block, MachineRegVector& regs);
 std::optional<InsnGenerator> GetInsnGen(MachineOpcode opcode);
-bool RegsLiveInBasicBlock(MachineBasicBlock* bb, const ArenaVector<MachineReg>& regs);
-std::optional<MachineInsnList::iterator> FindFlagSettingInsn(MachineInsnList::iterator insn_it,
-                                                             MachineInsnList::iterator begin,
-                                                             MachineReg reg);
+std::optional<FlagSettingInsn> FindFlagSettingInsn(MachineInsnList::iterator insn_it,
+                                                   MachineInsnList::iterator begin,
+                                                   MachineReg reg);
+void InsertFlagGenInstructions(MachineIR* machine_ir,
+                               ReadFlagsOptContext& context,
+                               MachineInsnList::iterator insn_it,
+                               const ArenaMap<MachineReg, MachineReg>& reg_map,
+                               MachineReg reg);
+std::optional<FlagSettingInsn> IsEligibleReadFlag(MachineIR* machine_ir,
+                                                  Loop* loop,
+                                                  MachineBasicBlock* bb,
+                                                  MachineInsnList::iterator insn_it);
+std::optional<MachineReg> NeedsToSaveFlags(MachineBasicBlock* bb,
+                                           MachineInsnList::iterator insn_it);
+void OptimizeReadFlags(MachineIR* machine_ir);
+bool RegsLiveInBasicBlock(MachineBasicBlock* bb, const MachineRegVector& regs);
+void RemoveEligibleReadFlagsInLoopTree(MachineIR* machine_ir, LoopTreeNode* loop_tree_node);
+void RemoveReadFlags(MachineIR* machine_ir, ReadFlagsOptContext context);
+bool RemoveRegs(MachineRegVector& remove_from_regs, const MachineRegVector& regs_to_remove);
+// Note flags_regs must not be a reference because we update it with new flag
+// registers based on our current basic block, but they are only applicable to
+// the current and future basic blocks.
+void ReplaceFlagRegisters(MachineIR* machine_ir,
+                          ReadFlagsOptContext context,
+                          MachineInsnList::iterator insn_it,
+                          MachineRegVector flags_regs,
+                          const ArenaMap<MachineReg, MachineReg>& reg_map,
+                          berberis::MachineInsn* insn);
+
 }  // namespace berberis::x86_64
 
 #endif  // BERBERIS_BACKEND_X86_64_READ_FLAGS_OPTIMIZER_H_
diff --git a/backend/include/berberis/backend/x86_64/rename_copy_uses.h b/backend/include/berberis/backend/x86_64/rename_copy_uses.h
index ad289078..db12886d 100644
--- a/backend/include/berberis/backend/x86_64/rename_copy_uses.h
+++ b/backend/include/berberis/backend/x86_64/rename_copy_uses.h
@@ -19,7 +19,6 @@
 
 #include <stdint.h>
 
-#include "berberis/backend/common/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/base/algorithm.h"
 #include "berberis/base/arena_vector.h"
@@ -31,9 +30,9 @@ class RenameCopyUsesMap {
   explicit RenameCopyUsesMap(MachineIR* machine_ir)
       : map_(machine_ir->NumVReg(), {kInvalidMachineReg, 0, 0}, machine_ir->arena()) {}
 
-  void RenameUseIfMapped(MachineInsn* insn, int i);
-  void ProcessDef(MachineInsn* insn, int i);
-  void ProcessCopy(MachineInsn* copy);
+  void RenameUseIfMapped(berberis::MachineInsn* insn, int i);
+  void ProcessDef(berberis::MachineInsn* insn, int i);
+  void ProcessCopy(berberis::MachineInsn* copy);
   void Tick() { time_++; }
   void StartBasicBlock(MachineBasicBlock* bb);
 
diff --git a/backend/riscv64_to_x86_64/include/berberis/backend/x86_64/machine_opcode_guest-inl.h b/backend/riscv64_to_x86_64/include/berberis/backend/x86_64/machine_opcode_guest-inl.h
deleted file mode 100644
index 77079724..00000000
--- a/backend/riscv64_to_x86_64/include/berberis/backend/x86_64/machine_opcode_guest-inl.h
+++ /dev/null
@@ -1,7 +0,0 @@
-
-kMachineOpMacroFeGetExceptionsTranslateMemBaseDispReg,
-    kMachineOpMacroFeSetExceptionsAndRoundImmTranslateMemBaseDispImm,
-    kMachineOpMacroFeSetExceptionsAndRoundTranslateRegMemBaseDispRegReg,
-    kMachineOpMacroFeSetExceptionsImmTranslateMemBaseDispImm,
-    kMachineOpMacroFeSetExceptionsTranslateRegMemBaseDispReg,
-    kMachineOpMacroFeSetRoundImmTranslateMemBaseDispMemBaseDispImm,
diff --git a/backend/testing/include/x86_64/loop_guest_context_optimizer_test_checks.h b/backend/testing/include/x86_64/loop_guest_context_optimizer_test_checks.h
index e77abb55..f7c9b665 100644
--- a/backend/testing/include/x86_64/loop_guest_context_optimizer_test_checks.h
+++ b/backend/testing/include/x86_64/loop_guest_context_optimizer_test_checks.h
@@ -25,14 +25,14 @@
 
 namespace berberis::x86_64 {
 
-inline MachineReg CheckCopyGetInsnAndObtainMappedReg(MachineInsn* get_insn,
+inline MachineReg CheckCopyGetInsnAndObtainMappedReg(berberis::MachineInsn* get_insn,
                                                      MachineReg expected_dst) {
   EXPECT_EQ(get_insn->opcode(), kMachineOpPseudoCopy);
   EXPECT_EQ(get_insn->RegAt(0), expected_dst);
   return get_insn->RegAt(1);
 }
 
-inline MachineReg CheckCopyPutInsnAndObtainMappedReg(MachineInsn* put_insn,
+inline MachineReg CheckCopyPutInsnAndObtainMappedReg(berberis::MachineInsn* put_insn,
                                                      MachineReg expected_src) {
   EXPECT_EQ(put_insn->opcode(), kMachineOpPseudoCopy);
   EXPECT_EQ(put_insn->RegAt(1), expected_src);
@@ -50,7 +50,10 @@ inline void CheckMemRegMap(MemRegMap mem_reg_map,
   EXPECT_EQ(mem_reg_map[offset].value().is_modified, is_modified);
 }
 
-inline void CheckGetInsn(MachineInsn* insn, MachineOpcode opcode, MachineReg reg, size_t disp) {
+inline void CheckGetInsn(berberis::MachineInsn* insn,
+                         MachineOpcode opcode,
+                         MachineReg reg,
+                         size_t disp) {
   auto get_insn = AsMachineInsnX86_64(insn);
   EXPECT_TRUE(get_insn->IsCPUStateGet());
   EXPECT_EQ(get_insn->opcode(), opcode);
@@ -58,7 +61,10 @@ inline void CheckGetInsn(MachineInsn* insn, MachineOpcode opcode, MachineReg reg
   EXPECT_EQ(get_insn->disp(), disp);
 }
 
-inline void CheckPutInsn(MachineInsn* insn, MachineOpcode opcode, MachineReg reg, size_t disp) {
+inline void CheckPutInsn(berberis::MachineInsn* insn,
+                         MachineOpcode opcode,
+                         MachineReg reg,
+                         size_t disp) {
   auto put_insn = AsMachineInsnX86_64(insn);
   EXPECT_TRUE(put_insn->IsCPUStatePut());
   EXPECT_EQ(put_insn->opcode(), opcode);
diff --git a/backend/testing/include/x86_64/mem_operand.h b/backend/testing/include/x86_64/mem_operand.h
deleted file mode 100644
index a6d21d05..00000000
--- a/backend/testing/include/x86_64/mem_operand.h
+++ /dev/null
@@ -1,149 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef BERBERIS_BACKEND_X86_64_MEM_OPERAND_H_
-#define BERBERIS_BACKEND_X86_64_MEM_OPERAND_H_
-
-#include <cstdint>
-
-#include "berberis/backend/x86_64/machine_ir.h"
-#include "berberis/backend/x86_64/machine_ir_builder.h"
-#include "berberis/base/logging.h"
-
-namespace berberis {
-
-namespace x86_64 {
-
-class MemOperand {
- public:
-  enum AddrMode { kAddrModeInvalid, kAddrModeBaseDisp, kAddrModeIndexDisp, kAddrModeBaseIndexDisp };
-
-  MemOperand() : addr_mode_(kAddrModeInvalid), scale_(MachineMemOperandScale::kOne), disp_(0) {}
-
-  static MemOperand MakeBaseDisp(MachineReg base, int32_t disp) {
-    return MemOperand(
-        kAddrModeBaseDisp, base, kInvalidMachineReg, MachineMemOperandScale::kOne, disp);
-  }
-
-  template <MachineMemOperandScale scale>
-  static MemOperand MakeIndexDisp(MachineReg index, int32_t disp) {
-    // We do not accept kOne here.  BaseDisp has
-    // better encoding than IndexDisp with kOne.
-    // Also, we do not want to have two ways to express reg + disp.
-    static_assert(scale != MachineMemOperandScale::kOne, "ScaleOne not allowed");
-    return MemOperand(kAddrModeIndexDisp, kInvalidMachineReg, index, scale, disp);
-  }
-
-  template <MachineMemOperandScale scale>
-  static MemOperand MakeBaseIndexDisp(MachineReg base, MachineReg index, int32_t disp) {
-    return MemOperand(kAddrModeBaseIndexDisp, base, index, scale, disp);
-  }
-
-  AddrMode addr_mode() const { return addr_mode_; }
-
-  MachineReg base() const {
-    CHECK(addr_mode_ == kAddrModeBaseDisp || addr_mode_ == kAddrModeBaseIndexDisp);
-    return base_;
-  }
-
-  MachineReg index() const {
-    CHECK(addr_mode_ == kAddrModeIndexDisp || addr_mode_ == kAddrModeBaseIndexDisp);
-    return index_;
-  }
-
-  MachineMemOperandScale scale() const {
-    CHECK(addr_mode_ == kAddrModeIndexDisp || addr_mode_ == kAddrModeBaseIndexDisp);
-    return scale_;
-  }
-
-  int32_t disp() const {
-    CHECK_NE(addr_mode_, kAddrModeInvalid);
-    return disp_;
-  }
-
-  bool IsValid() const { return addr_mode_ != kAddrModeInvalid; }
-
- private:
-  // We keep this general constructor private. Users must call
-  // MakeBaseDisp, MakeIndexDisp etc. This way, it's obvious to callers
-  // what addressing mode is being requested because the method names
-  // contain addressing modes.
-  MemOperand(AddrMode addr_mode,
-             MachineReg base,
-             MachineReg index,
-             MachineMemOperandScale scale,
-             int32_t disp)
-      : addr_mode_(addr_mode), base_(base), index_(index), scale_(scale), disp_(disp) {}
-
-  const AddrMode addr_mode_;
-  const MachineReg base_;
-  const MachineReg index_;
-  const MachineMemOperandScale scale_;
-  // The hardware sign-extends disp to 64-bit.
-  const int32_t disp_;
-};
-
-template <typename MachineInsnMemInsns, typename... Args>
-void GenArgsMem(MachineIRBuilder* builder, const MemOperand& mem_operand, Args... args) {
-  switch (mem_operand.addr_mode()) {
-    case MemOperand::kAddrModeBaseDisp:
-      builder->Gen<typename MachineInsnMemInsns::BaseDisp>(
-          args..., mem_operand.base(), mem_operand.disp());
-      break;
-    case MemOperand::kAddrModeIndexDisp:
-      builder->Gen<typename MachineInsnMemInsns::IndexDisp>(
-          args..., mem_operand.index(), mem_operand.scale(), mem_operand.disp());
-      break;
-    case MemOperand::kAddrModeBaseIndexDisp:
-      builder->Gen<typename MachineInsnMemInsns::BaseIndexDisp>(args...,
-                                                                mem_operand.base(),
-                                                                mem_operand.index(),
-                                                                mem_operand.scale(),
-                                                                mem_operand.disp());
-      break;
-    default:
-      FATAL("Impossible addressing mode");
-  }
-}
-
-template <typename MachineInsnMemInsns, typename... Args>
-void GenMemArgs(MachineIRBuilder* builder, const MemOperand& mem_operand, Args... args) {
-  switch (mem_operand.addr_mode()) {
-    case MemOperand::kAddrModeBaseDisp:
-      builder->Gen<typename MachineInsnMemInsns::BaseDisp>(
-          mem_operand.base(), mem_operand.disp(), args...);
-      break;
-    case MemOperand::kAddrModeIndexDisp:
-      builder->Gen<typename MachineInsnMemInsns::IndexDisp>(
-          mem_operand.index(), mem_operand.scale(), mem_operand.disp(), args...);
-      break;
-    case MemOperand::kAddrModeBaseIndexDisp:
-      builder->Gen<typename MachineInsnMemInsns::BaseIndexDisp>(mem_operand.base(),
-                                                                mem_operand.index(),
-                                                                mem_operand.scale(),
-                                                                mem_operand.disp(),
-                                                                args...);
-      break;
-    default:
-      FATAL("Impossible addressing mode");
-  }
-}
-
-}  // namespace x86_64
-
-}  // namespace berberis
-
-#endif  // BERBERIS_BACKEND_X86_64_MEM_OPERAND_H_
diff --git a/backend/x86_64/code.cc b/backend/x86_64/code.cc
index 6489dcd2..de282e17 100644
--- a/backend/x86_64/code.cc
+++ b/backend/x86_64/code.cc
@@ -30,19 +30,32 @@ constexpr MachineInsnInfo kCallImmInfo = {
     kMachineOpCallImm,
     26,
     {
-        {&kRAX, MachineRegKind::kDef},   {&kRDI, MachineRegKind::kDef},
-        {&kRSI, MachineRegKind::kDef},   {&kRDX, MachineRegKind::kDef},
-        {&kRCX, MachineRegKind::kDef},   {&kR8, MachineRegKind::kDef},
-        {&kR9, MachineRegKind::kDef},    {&kR10, MachineRegKind::kDef},
-        {&kR11, MachineRegKind::kDef},   {&kXMM0, MachineRegKind::kDef},
-        {&kXMM1, MachineRegKind::kDef},  {&kXMM2, MachineRegKind::kDef},
-        {&kXMM3, MachineRegKind::kDef},  {&kXMM4, MachineRegKind::kDef},
-        {&kXMM5, MachineRegKind::kDef},  {&kXMM6, MachineRegKind::kDef},
-        {&kXMM7, MachineRegKind::kDef},  {&kXMM8, MachineRegKind::kDef},
-        {&kXMM9, MachineRegKind::kDef},  {&kXMM10, MachineRegKind::kDef},
-        {&kXMM11, MachineRegKind::kDef}, {&kXMM12, MachineRegKind::kDef},
-        {&kXMM13, MachineRegKind::kDef}, {&kXMM14, MachineRegKind::kDef},
-        {&kXMM15, MachineRegKind::kDef}, {&kFLAGS, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::RAX>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::RDI>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::RSI>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::RDX>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::RCX>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::R8>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::R9>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::R10>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::R11>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM0>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM1>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM2>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM3>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM4>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM5>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM6>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM7>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM8>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM9>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM10>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM11>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM12>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM13>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM14>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::XMM15>, MachineRegKind::kDef},
+        {&kRegisterClass<device_arch_info::FLAGS>, MachineRegKind::kDef},
     },
     kMachineInsnSideEffects};
 
@@ -147,8 +160,6 @@ CallImmArg::CallImmArg(MachineReg arg, CallImm::RegType reg_type)
   SetRegAt(0, arg);
 }
 
-#include "insn-inl_x86_64.h"  // NOLINT generated file!
-
 }  // namespace x86_64
 
 const MachineOpcode PseudoBranch::kOpcode = kMachineOpPseudoBranch;
diff --git a/backend/x86_64/code_debug.cc b/backend/x86_64/code_debug.cc
index ec62133a..f25d71cc 100644
--- a/backend/x86_64/code_debug.cc
+++ b/backend/x86_64/code_debug.cc
@@ -45,17 +45,8 @@ namespace x86_64 {
 
 namespace {
 
-int ScaleToInt(MachineMemOperandScale scale) {
-  switch (scale) {
-    case MachineMemOperandScale::kOne:
-      return 1;
-    case MachineMemOperandScale::kTwo:
-      return 2;
-    case MachineMemOperandScale::kFour:
-      return 4;
-    case MachineMemOperandScale::kEight:
-      return 8;
-  }
+int ScaleToInt(Assembler::ScaleFactor scale) {
+  return 1 << scale;
 }
 
 }  // namespace
diff --git a/backend/x86_64/code_emit.cc b/backend/x86_64/code_emit.cc
index cb093af2..44327710 100644
--- a/backend/x86_64/code_emit.cc
+++ b/backend/x86_64/code_emit.cc
@@ -201,28 +201,15 @@ Assembler::XMMRegister GetXReg(MachineReg r) {
       Assembler::xmm14,
       Assembler::xmm15,
   };
-  CHECK_GE(r.reg(), kMachineRegXMM0.reg());
-  CHECK_LT(static_cast<unsigned>(r.reg() - kMachineRegXMM0.reg()), std::size(kHardRegs));
-  return kHardRegs[r.reg() - kMachineRegXMM0.reg()];
+  CHECK_GE(r.reg(), MachineRegs::kXMM0.reg());
+  CHECK_LT(static_cast<unsigned>(r.reg() - MachineRegs::kXMM0.reg()), std::size(kHardRegs));
+  return kHardRegs[r.reg() - MachineRegs::kXMM0.reg()];
 }
 
 Assembler::YMMRegister GetYReg(MachineReg r) {
   return GetXReg(r).To256Bit();
 }
 
-Assembler::ScaleFactor ToScaleFactor(MachineMemOperandScale scale) {
-  switch (scale) {
-    case MachineMemOperandScale::kOne:
-      return Assembler::kTimesOne;
-    case MachineMemOperandScale::kTwo:
-      return Assembler::kTimesTwo;
-    case MachineMemOperandScale::kFour:
-      return Assembler::kTimesFour;
-    case MachineMemOperandScale::kEight:
-      return Assembler::kTimesEight;
-  }
-}
-
 void CallImm::Emit(CodeEmitter* as) const {
   as->Call(AsHostCode(imm()));
   if (custom_avx256_abi_) {
diff --git a/backend/x86_64/code_gen.cc b/backend/x86_64/code_gen.cc
index 0f18339a..90727b5a 100644
--- a/backend/x86_64/code_gen.cc
+++ b/backend/x86_64/code_gen.cc
@@ -26,6 +26,7 @@
 #include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir_check.h"
 #include "berberis/backend/x86_64/machine_ir_opt.h"
+#include "berberis/backend/x86_64/read_flags_optimizer.h"
 #include "berberis/backend/x86_64/rename_copy_uses.h"
 #include "berberis/backend/x86_64/rename_vregs.h"
 #include "berberis/base/checks.h"
@@ -57,6 +58,7 @@ void GenCode(MachineIR* machine_ir, MachineCode* machine_code, const GenCodePara
   RemoveDeadCode(machine_ir);
 
   FoldWriteFlags(machine_ir);
+  OptimizeReadFlags(machine_ir);
 
   AllocRegs(machine_ir);
 
diff --git a/backend/x86_64/insn_folding.cc b/backend/x86_64/insn_folding.cc
index 497a6829..7b5286b7 100644
--- a/backend/x86_64/insn_folding.cc
+++ b/backend/x86_64/insn_folding.cc
@@ -19,7 +19,6 @@
 #include <cstdint>
 #include <tuple>
 
-#include "berberis/backend/common/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir.h"
 
 #include "berberis/backend/code_emitter.h"  // for CodeEmitter::Condition
@@ -29,7 +28,8 @@
 
 namespace berberis::x86_64 {
 
-void DefMap::MapDefRegs(const MachineInsn* insn) {
+void DefMap::MapDefRegs(MachineInsnList::iterator insn_it) {
+  const berberis::MachineInsn* insn = *insn_it;
   for (int op = 0; op < insn->NumRegOperands(); ++op) {
     MachineReg reg = insn->RegAt(op);
     if (insn->RegKindAt(op).RegClass()->IsSubsetOf(&x86_64::kFLAGS)) {
@@ -40,41 +40,41 @@ void DefMap::MapDefRegs(const MachineInsn* insn) {
       CHECK(reg == flags_reg_);
     }
     if (insn->RegKindAt(op).IsDef()) {
-      Set(reg, insn);
+      Set(reg, insn_it);
     }
   }
 }
 
-void DefMap::ProcessInsn(const MachineInsn* insn) {
-  MapDefRegs(insn);
+void DefMap::ProcessInsn(MachineInsnList::iterator insn_it) {
+  MapDefRegs(insn_it);
   ++index_;
 }
 
 void DefMap::Initialize() {
-  std::fill(def_map_.begin(), def_map_.end(), std::pair(nullptr, 0));
+  std::fill(def_map_.begin(), def_map_.end(), std::pair(std::nullopt, 0));
   flags_reg_ = kInvalidMachineReg;
   index_ = 0;
 }
 
-bool InsnFolding::IsRegImm(MachineReg reg, uint64_t* imm) const {
-  auto [general_insn, _] = def_map_.Get(reg);
-  if (!general_insn) {
-    return false;
+std::optional<uint64_t> InsnFolding::GetImmValueIfPossible(MachineReg reg) const {
+  auto [general_insn_it, _] = FindNonPseudoCopyDef(reg);
+  if (!general_insn_it.has_value()) {
+    return std::nullopt;
   }
+  const berberis::MachineInsn* general_insn = *general_insn_it.value();
   const auto* insn = AsMachineInsnX86_64(general_insn);
   if (insn->opcode() == kMachineOpMovqRegImm) {
-    *imm = insn->imm();
-    return true;
+    return insn->imm();
   } else if (insn->opcode() == kMachineOpMovlRegImm) {
     // Take into account zero-extension by MOVL.
-    *imm = static_cast<uint64_t>(static_cast<uint32_t>(insn->imm()));
-    return true;
+    return static_cast<uint64_t>(static_cast<uint32_t>(insn->imm()));
   }
-  return false;
+  return std::nullopt;
 }
 
-MachineInsn* InsnFolding::NewImmInsnFromRegInsn(const MachineInsn* insn, int32_t imm32) {
-  MachineInsn* folded_insn;
+berberis::MachineInsn* InsnFolding::NewImmInsnFromRegInsn(const berberis::MachineInsn* insn,
+                                                          int32_t imm32) {
+  berberis::MachineInsn* folded_insn;
   switch (insn->opcode()) {
     case kMachineOpAddqRegReg:
       folded_insn = machine_ir_->NewInsn<AddqRegImm>(insn->RegAt(0), imm32, insn->RegAt(2));
@@ -97,6 +97,12 @@ MachineInsn* InsnFolding::NewImmInsnFromRegInsn(const MachineInsn* insn, int32_t
     case kMachineOpTestqRegReg:
       folded_insn = machine_ir_->NewInsn<TestqRegImm>(insn->RegAt(0), imm32, insn->RegAt(2));
       break;
+    case kMachineOpShlqRegReg:
+      folded_insn = machine_ir_->NewInsn<ShlqRegImm>(insn->RegAt(0), imm32, insn->RegAt(2));
+      break;
+    case kMachineOpShrqRegReg:
+      folded_insn = machine_ir_->NewInsn<ShrqRegImm>(insn->RegAt(0), imm32, insn->RegAt(2));
+      break;
     case kMachineOpMovlRegReg:
       folded_insn = machine_ir_->NewInsn<MovlRegImm>(insn->RegAt(0), imm32);
       break;
@@ -121,13 +127,21 @@ MachineInsn* InsnFolding::NewImmInsnFromRegInsn(const MachineInsn* insn, int32_t
     case kMachineOpTestlRegReg:
       folded_insn = machine_ir_->NewInsn<TestlRegImm>(insn->RegAt(0), imm32, insn->RegAt(2));
       break;
+    case kMachineOpShllRegReg:
+      folded_insn = machine_ir_->NewInsn<ShllRegImm>(insn->RegAt(0), imm32, insn->RegAt(2));
+      break;
+    case kMachineOpShrlRegReg:
+      folded_insn = machine_ir_->NewInsn<ShrlRegImm>(insn->RegAt(0), imm32, insn->RegAt(2));
+      break;
     case kMachineOpMovlMemBaseDispReg:
-      folded_insn = machine_ir_->NewInsn<MovlMemBaseDispImm>(
-          insn->RegAt(0), AsMachineInsnX86_64(insn)->disp(), imm32);
+      folded_insn = machine_ir_->NewInsn<MovlOpImm>(
+          {.base = insn->RegAt(0), .disp = static_cast<int32_t>(AsMachineInsnX86_64(insn)->disp())},
+          imm32);
       break;
     case kMachineOpMovqMemBaseDispReg:
-      folded_insn = machine_ir_->NewInsn<MovqMemBaseDispImm>(
-          insn->RegAt(0), AsMachineInsnX86_64(insn)->disp(), imm32);
+      folded_insn = machine_ir_->NewInsn<MovqOpImm>(
+          {.base = insn->RegAt(0), .disp = static_cast<int32_t>(AsMachineInsnX86_64(insn)->disp())},
+          imm32);
       break;
     default:
       LOG_ALWAYS_FATAL("unexpected opcode");
@@ -138,89 +152,260 @@ MachineInsn* InsnFolding::NewImmInsnFromRegInsn(const MachineInsn* insn, int32_t
   return folded_insn;
 }
 
-bool InsnFolding::IsWritingSameFlagsValue(const MachineInsn* write_flags_insn) const {
-  CHECK(write_flags_insn && write_flags_insn->opcode() == kMachineOpPseudoWriteFlags);
-  MachineReg src_reg = write_flags_insn->RegAt(0);
-  auto [def_insn, def_insn_pos] = def_map_.Get(src_reg);
-  // Warning: We are assuming that all flags writes in IR happen to the same virtual register.
-  while (true) {
-    if (!def_insn) {
-      return false;
+std::tuple<std::optional<MachineInsnList::iterator>, int> InsnFolding::FindNonPseudoCopyDef(
+    MachineReg src_reg) const {
+  auto [def_insn_it, def_insn_pos] = def_map_.Get(src_reg);
+  while (def_insn_it.has_value()) {
+    const berberis::MachineInsn* def_insn = *def_insn_it.value();
+    if (def_insn->opcode() != kMachineOpPseudoCopy) {
+      return {def_insn_it, def_insn_pos};
     }
+    std::tie(def_insn_it, def_insn_pos) = def_map_.Get(def_insn->RegAt(1), def_insn_pos);
+  }
+  return {std::nullopt, 0};
+}
 
-    int opcode = def_insn->opcode();
-    if (opcode == kMachineOpPseudoCopy) {
-      src_reg = def_insn->RegAt(1);
-      std::tie(def_insn, def_insn_pos) = def_map_.Get(src_reg, def_insn_pos);
-      continue;
-    } else if (opcode == kMachineOpPseudoReadFlags) {
-      break;
-    }
+bool InsnFolding::IsWritingSameFlagsValue(MachineInsnList::iterator write_flags_insn_it) const {
+  const berberis::MachineInsn* write_flags_insn = *write_flags_insn_it;
+  CHECK(write_flags_insn && write_flags_insn->opcode() == kMachineOpPseudoWriteFlags);
+  MachineReg src_reg = write_flags_insn->RegAt(0);
+  auto [def_insn_it, def_insn_pos] = FindNonPseudoCopyDef(src_reg);
+  if (!def_insn_it.has_value()) {
+    return false;
+  }
+  const berberis::MachineInsn* def_insn = *def_insn_it.value();
+  if (def_insn->opcode() != kMachineOpPseudoReadFlags) {
     return false;
   }
-
   // Instruction is PseudoReadFlags.
   if (write_flags_insn->RegAt(1) != def_insn->RegAt(1)) {
     return false;
   }
   auto [flag_def_insn, _] = def_map_.Get(write_flags_insn->RegAt(1), def_insn_pos);
-  return flag_def_insn != nullptr;
+  return flag_def_insn.has_value();
 }
 
-template <bool is_input_64bit>
-std::tuple<bool, MachineInsn*> InsnFolding::TryFoldImmediateInput(const MachineInsn* insn) {
-  auto src = insn->RegAt(1);
-  uint64_t imm64;
-  if (!IsRegImm(src, &imm64)) {
-    return {false, nullptr};
+template <bool kIsInput64Bit>
+std::tuple<FoldingType, berberis::MachineInsn*> InsnFolding::TryFoldImmediateInput(
+    MachineInsnList::iterator insn_it) {
+  const berberis::MachineInsn* insn = *insn_it;
+  auto src1 = insn->RegAt(1);
+  std::optional<uint64_t> imm64_1 = GetImmValueIfPossible(src1);
+  if (!imm64_1.has_value()) {
+    return {FoldingType::kImpossible, nullptr};
+  }
+
+  auto src0 = insn->RegAt(0);
+  std::optional<uint64_t> imm64_0 = GetImmValueIfPossible(src0);
+  if (imm64_0.has_value()) {
+    // Both operands are immediates. This insn can be folded into one Movq.
+    if (insn->opcode() == kMachineOpAndqRegReg || insn->opcode() == kMachineOpAndlRegReg ||
+        insn->opcode() == kMachineOpOrqRegReg || insn->opcode() == kMachineOpOrlRegReg ||
+        insn->opcode() == kMachineOpXorqRegReg || insn->opcode() == kMachineOpXorlRegReg ||
+        insn->opcode() == kMachineOpAddqRegReg || insn->opcode() == kMachineOpAddlRegReg ||
+        insn->opcode() == kMachineOpSubqRegReg || insn->opcode() == kMachineOpSublRegReg ||
+        insn->opcode() == kMachineOpShlqRegReg || insn->opcode() == kMachineOpShllRegReg ||
+        insn->opcode() == kMachineOpShrqRegReg || insn->opcode() == kMachineOpShrlRegReg) {
+      return {FoldingType::kInsertInsn,
+              NewInsnFromTwoImmediatesOperation(insn, imm64_0.value(), imm64_1.value())};
+    }
   }
 
   // MovqRegReg is the only instruction that can encode full 64-bit immediate.
   if (insn->opcode() == kMachineOpMovqRegReg) {
-    return {true, machine_ir_->NewInsn<MovqRegImm>(insn->RegAt(0), imm64)};
+    return {FoldingType::kReplaceInsn,
+            machine_ir_->NewInsn<MovqRegImm>(insn->RegAt(0), imm64_1.value())};
   }
 
-  int64_t signed_imm = bit_cast<int64_t>(imm64);
+  int64_t signed_imm = bit_cast<int64_t>(imm64_1.value());
   int32_t signed_imm32 = static_cast<int32_t>(signed_imm);
-  if (!is_input_64bit) {
+  if (!kIsInput64Bit) {
     // Use the lower half of the register as the immediate operand.
-    return {true, NewImmInsnFromRegInsn(insn, signed_imm32)};
+    return {FoldingType::kReplaceInsn, NewImmInsnFromRegInsn(insn, signed_imm32)};
   }
 
   // Except for MOVQ x86 doesn't allow to encode 64-bit immediates. That said,
   // we can encode 32-bit immediates that are sign-extended by hardware to
   // 64-bit during instruction execution.
   if (signed_imm == static_cast<int64_t>(signed_imm32)) {
-    return {true, NewImmInsnFromRegInsn(insn, signed_imm32)};
+    return {FoldingType::kReplaceInsn, NewImmInsnFromRegInsn(insn, signed_imm32)};
+  }
+
+  return {FoldingType::kImpossible, nullptr};
+}
+
+berberis::MachineInsn* InsnFolding::NewInsnFromTwoImmediatesOperation(
+    const berberis::MachineInsn* insn,
+    uint64_t imm1,
+    uint64_t imm2) {
+  switch (insn->opcode()) {
+    case kMachineOpShllRegImm:
+    case kMachineOpShllRegReg:
+      // In 32 bit shift operations, count operand is masked to size 5 bits.
+      return machine_ir_->NewInsn<MovlRegImm>(insn->RegAt(0),
+                                              static_cast<uint32_t>(imm1 << (imm2 % 32)));
+    case kMachineOpShlqRegImm:
+    case kMachineOpShlqRegReg:
+      // In 64 bit shift operations, count operand is masked to size 6 bits.
+      return machine_ir_->NewInsn<MovqRegImm>(insn->RegAt(0), imm1 << (imm2 % 64));
+    case kMachineOpShrlRegImm:
+    case kMachineOpShrlRegReg:
+      // In 32 bit shift operations, count operand is masked to size 5 bits.
+      return machine_ir_->NewInsn<MovlRegImm>(insn->RegAt(0),
+                                              static_cast<uint32_t>(imm1 >> (imm2 % 32)));
+    case kMachineOpShrqRegImm:
+    case kMachineOpShrqRegReg:
+      // In 64 bit shift operations, count operand is masked to size 6 bits.
+      return machine_ir_->NewInsn<MovqRegImm>(insn->RegAt(0), imm1 >> (imm2 % 64));
+    case kMachineOpAndlRegImm:
+    case kMachineOpAndlRegReg:
+      return machine_ir_->NewInsn<MovlRegImm>(insn->RegAt(0), static_cast<uint32_t>(imm1 & imm2));
+    case kMachineOpAndqRegImm:
+    case kMachineOpAndqRegReg:
+      return machine_ir_->NewInsn<MovqRegImm>(insn->RegAt(0), imm1 & imm2);
+    case kMachineOpOrlRegImm:
+    case kMachineOpOrlRegReg:
+      return machine_ir_->NewInsn<MovlRegImm>(insn->RegAt(0), static_cast<uint32_t>(imm1 | imm2));
+    case kMachineOpOrqRegImm:
+    case kMachineOpOrqRegReg:
+      return machine_ir_->NewInsn<MovqRegImm>(insn->RegAt(0), imm1 | imm2);
+    case kMachineOpXorlRegImm:
+    case kMachineOpXorlRegReg:
+      return machine_ir_->NewInsn<MovlRegImm>(insn->RegAt(0), static_cast<uint32_t>(imm1 ^ imm2));
+    case kMachineOpXorqRegImm:
+    case kMachineOpXorqRegReg:
+      return machine_ir_->NewInsn<MovqRegImm>(insn->RegAt(0), imm1 ^ imm2);
+    case kMachineOpAddlRegImm:
+    case kMachineOpAddlRegReg:
+      return machine_ir_->NewInsn<MovlRegImm>(insn->RegAt(0), static_cast<uint32_t>(imm1 + imm2));
+    case kMachineOpAddqRegImm:
+    case kMachineOpAddqRegReg:
+      return machine_ir_->NewInsn<MovqRegImm>(insn->RegAt(0), imm1 + imm2);
+    case kMachineOpSublRegImm:
+    case kMachineOpSublRegReg:
+      return machine_ir_->NewInsn<MovlRegImm>(insn->RegAt(0), static_cast<uint32_t>(imm1 - imm2));
+    case kMachineOpSubqRegImm:
+    case kMachineOpSubqRegReg:
+      return machine_ir_->NewInsn<MovqRegImm>(insn->RegAt(0), imm1 - imm2);
+    default:
+      LOG_ALWAYS_FATAL("unexpected opcode");
+      return nullptr;
   }
+}
 
-  return {false, nullptr};
+std::tuple<FoldingType, berberis::MachineInsn*> InsnFolding::TryFoldTwoImmediates(
+    MachineInsnList::iterator insn_it) {
+  const berberis::MachineInsn* insn = *insn_it;
+  CHECK_GE(insn->NumRegOperands(), 2);
+  MachineReg imm1_reg = insn->RegAt(0);
+  std::optional<uint64_t> imm1 = GetImmValueIfPossible(imm1_reg);
+  if (!imm1.has_value()) {
+    return {FoldingType::kImpossible, nullptr};
+  }
+  uint64_t imm2 = AsMachineInsnX86_64(insn)->imm();
+  // Check no value loss when imm2 is represented using 32 bits.
+  CHECK(imm2 == static_cast<uint64_t>(static_cast<int32_t>(imm2)));
+  // Rest of IR may use the value of flags set by current insn. Therefore, we don't remove
+  // current insn, rather simply insert the folded insn. The dead code eliminator will
+  // remove the current insn if possible.
+  return {FoldingType::kInsertInsn, NewInsnFromTwoImmediatesOperation(insn, imm1.value(), imm2)};
 }
 
-std::tuple<bool, MachineInsn*> InsnFolding::TryFoldRedundantMovl(const MachineInsn* insn) {
+std::tuple<FoldingType, berberis::MachineInsn*> InsnFolding::TryFoldRedundantMovl(
+    MachineInsnList::iterator insn_it) {
+  const berberis::MachineInsn* insn = *insn_it;
   CHECK_EQ(insn->opcode(), kMachineOpMovlRegReg);
   auto src = insn->RegAt(1);
-  auto [def_insn, _] = def_map_.Get(src);
-
-  if (!def_insn) {
-    return {false, nullptr};
+  auto [def_insn_it, _] = FindNonPseudoCopyDef(src);
+  if (!def_insn_it.has_value()) {
+    return {FoldingType::kImpossible, nullptr};
   }
+  const berberis::MachineInsn* def_insn = *def_insn_it.value();
 
   // If the definition of src clears its upper half, then we can replace MOVL with PseudoCopy.
   switch (def_insn->opcode()) {
     case kMachineOpMovlRegReg:
+    case kMachineOpMovlRegMemAbsolute:
+    case kMachineOpMovlRegMemBaseDisp:
+    case kMachineOpMovlRegMemIndexDisp:
+    case kMachineOpMovlRegMemBaseIndexDisp:
     case kMachineOpAndlRegReg:
     case kMachineOpXorlRegReg:
     case kMachineOpOrlRegReg:
     case kMachineOpSublRegReg:
     case kMachineOpAddlRegReg:
-      return {true, machine_ir_->NewInsn<PseudoCopy>(insn->RegAt(0), src, 4)};
+    case kMachineOpShrdlRegRegImm:
+      return {FoldingType::kReplaceInsn, machine_ir_->NewInsn<PseudoCopy>(insn->RegAt(0), src, 4)};
     default:
-      return {false, nullptr};
+      return {FoldingType::kImpossible, nullptr};
   }
 }
 
-std::tuple<bool, MachineInsn*> InsnFolding::TryFoldInsn(const MachineInsn* insn) {
+template <bool kBMI, bool kIsInput64Bit>
+std::tuple<FoldingType, berberis::MachineInsn*> InsnFolding::TryFoldCountLeadingZeros(
+    MachineInsnList::iterator insn_it,
+    const MachineBasicBlock* bb) {
+  const berberis::MachineInsn* insn = *insn_it;
+  const MachineOpcode clz_insn_opcode =
+      kBMI            ? kIsInput64Bit ? kMachineOpLzcntqRegReg : kMachineOpLzcntlRegReg
+      : kIsInput64Bit ? kMachineOpCountLeadingZerosU64
+                      : kMachineOpCountLeadingZerosU32;
+  CHECK_EQ(insn->opcode(), clz_insn_opcode);
+  MachineReg clz_src_reg = insn->RegAt(1);
+  auto [def_insn_it, def_insn_pos] = FindNonPseudoCopyDef(clz_src_reg);
+  if (!def_insn_it.has_value()) {
+    return {FoldingType::kImpossible, nullptr};
+  }
+  if (def_insn_it == bb->insn_list().begin()) {
+    return {FoldingType::kImpossible, nullptr};
+  }
+  const berberis::MachineInsn* def_insn = *def_insn_it.value();
+  const MachineOpcode reverse_bits_insn_opcode =
+      kIsInput64Bit ? kMachineOpReverseBitsU64 : kMachineOpReverseBitsU32;
+  if (def_insn->opcode() != reverse_bits_insn_opcode) {
+    return {FoldingType::kImpossible, nullptr};
+  }
+  const berberis::MachineInsn* reverse_bits_insn = def_insn;
+  MachineInsnList::iterator insn_before_reverse_bits_it = std::prev(def_insn_it.value());
+  const berberis::MachineInsn* insn_before_reverse_bits = *insn_before_reverse_bits_it;
+  if (insn_before_reverse_bits->opcode() != kMachineOpPseudoCopy) {
+    return {FoldingType::kImpossible, nullptr};
+  }
+  const berberis::MachineInsn* pseudo_copy = insn_before_reverse_bits;
+  if (pseudo_copy->RegAt(0) != reverse_bits_insn->RegAt(1) ||
+      pseudo_copy->RegAt(0) == pseudo_copy->RegAt(1)) {
+    return {FoldingType::kImpossible, nullptr};
+  }
+  // If ReverseBits insn or any insn after overwrites pseudo_copy->RegAt(1), this will return
+  // std::nullopt.
+  if (std::get<0>(def_map_.Get(pseudo_copy->RegAt(1), def_insn_pos)) == std::nullopt) {
+    return {FoldingType::kImpossible, nullptr};
+  }
+  berberis::MachineInsn* new_insn;
+  if (kBMI) {
+    if (kIsInput64Bit) {
+      new_insn =
+          machine_ir_->NewInsn<TzcntqRegReg>(insn->RegAt(0), pseudo_copy->RegAt(1), insn->RegAt(2));
+    } else {
+      new_insn =
+          machine_ir_->NewInsn<TzcntlRegReg>(insn->RegAt(0), pseudo_copy->RegAt(1), insn->RegAt(2));
+    }
+  } else {
+    if (kIsInput64Bit) {
+      new_insn = machine_ir_->NewInsn<CountTrailingZerosU64>(
+          insn->RegAt(0), pseudo_copy->RegAt(1), insn->RegAt(2));
+    } else {
+      new_insn = machine_ir_->NewInsn<CountTrailingZerosU32>(
+          insn->RegAt(0), pseudo_copy->RegAt(1), insn->RegAt(2));
+    }
+  }
+  return {FoldingType::kReplaceInsn, new_insn};
+}
+
+std::tuple<FoldingType, berberis::MachineInsn*> InsnFolding::TryFoldInsn(
+    const MachineInsnList::iterator insn_it,
+    const MachineBasicBlock* bb) {
+  const berberis::MachineInsn* insn = *insn_it;
   switch (insn->opcode()) {
     case kMachineOpMovqMemBaseDispReg:
     case kMachineOpMovqRegReg:
@@ -231,14 +416,15 @@ std::tuple<bool, MachineInsn*> InsnFolding::TryFoldInsn(const MachineInsn* insn)
     case kMachineOpSubqRegReg:
     case kMachineOpCmpqRegReg:
     case kMachineOpAddqRegReg:
-      return TryFoldImmediateInput<true>(insn);
+    case kMachineOpShlqRegReg:
+    case kMachineOpShrqRegReg:
+      return TryFoldImmediateInput<true>(insn_it);
     case kMachineOpMovlRegReg: {
-      auto [is_folded, folded_insn] = TryFoldImmediateInput<false>(insn);
-      if (is_folded) {
-        return {is_folded, folded_insn};
+      auto [folding_type, folded_insn] = TryFoldImmediateInput<false>(insn_it);
+      if (folding_type != FoldingType::kImpossible) {
+        return {folding_type, folded_insn};
       }
-
-      return TryFoldRedundantMovl(insn);
+      return TryFoldRedundantMovl(insn_it);
     }
     case kMachineOpMovlMemBaseDispReg:
     case kMachineOpAndlRegReg:
@@ -248,17 +434,42 @@ std::tuple<bool, MachineInsn*> InsnFolding::TryFoldInsn(const MachineInsn* insn)
     case kMachineOpSublRegReg:
     case kMachineOpCmplRegReg:
     case kMachineOpAddlRegReg:
-      return TryFoldImmediateInput<false>(insn);
+    case kMachineOpShllRegReg:
+    case kMachineOpShrlRegReg:
+      return TryFoldImmediateInput<false>(insn_it);
     case kMachineOpPseudoWriteFlags: {
-      if (IsWritingSameFlagsValue(insn)) {
-        return {true, nullptr};
+      if (IsWritingSameFlagsValue(insn_it)) {
+        return {FoldingType::kRemoveInsn, nullptr};
       }
       break;
     }
+    case kMachineOpShlqRegImm:
+    case kMachineOpShrqRegImm:
+    case kMachineOpAndqRegImm:
+    case kMachineOpOrqRegImm:
+    case kMachineOpXorqRegImm:
+    case kMachineOpAddqRegImm:
+    case kMachineOpSubqRegImm:
+    case kMachineOpShllRegImm:
+    case kMachineOpShrlRegImm:
+    case kMachineOpAndlRegImm:
+    case kMachineOpOrlRegImm:
+    case kMachineOpXorlRegImm:
+    case kMachineOpAddlRegImm:
+    case kMachineOpSublRegImm:
+      return TryFoldTwoImmediates(insn_it);
+    case kMachineOpLzcntlRegReg:
+      return TryFoldCountLeadingZeros<true, false>(insn_it, bb);
+    case kMachineOpLzcntqRegReg:
+      return TryFoldCountLeadingZeros<true, true>(insn_it, bb);
+    case kMachineOpCountLeadingZerosU32:
+      return TryFoldCountLeadingZeros<false, false>(insn_it, bb);
+    case kMachineOpCountLeadingZerosU64:
+      return TryFoldCountLeadingZeros<false, true>(insn_it, bb);
     default:
-      return {false, nullptr};
+      return {FoldingType::kImpossible, nullptr};
   }
-  return {false, nullptr};
+  return {FoldingType::kImpossible, nullptr};
 }
 
 void FoldInsns(MachineIR* machine_ir) {
@@ -267,20 +478,24 @@ void FoldInsns(MachineIR* machine_ir) {
     def_map.Initialize();
     InsnFolding insn_folding(def_map, machine_ir);
     MachineInsnList& insn_list = bb->insn_list();
-
     for (auto insn_it = insn_list.begin(); insn_it != insn_list.end();) {
-      auto [is_folded, new_insn] = insn_folding.TryFoldInsn(*insn_it);
-
-      if (is_folded) {
+      auto [folding_type, new_insn] = insn_folding.TryFoldInsn(insn_it, bb);
+      if (folding_type == FoldingType::kRemoveInsn) {
         insn_it = insn_list.erase(insn_it);
-        if (new_insn) {
-          insn_list.insert(insn_it, new_insn);
-          def_map.ProcessInsn(new_insn);
-        }
+        continue;
+      }
+
+      if (folding_type == FoldingType::kReplaceInsn) {
+        CHECK(new_insn);
+        *insn_it = new_insn;
+      } else if (folding_type == FoldingType::kInsertInsn) {
+        CHECK(new_insn);
+        insn_list.insert(std::next(insn_it), new_insn);
       } else {
-        def_map.ProcessInsn(*insn_it);
-        ++insn_it;
+        CHECK(folding_type == FoldingType::kImpossible);
       }
+      def_map.ProcessInsn(insn_it);
+      ++insn_it;
     }
   }
 }
@@ -354,7 +569,7 @@ void FoldWriteFlags(MachineIR* machine_ir) {
     }
 
     MachineReg flags_src = write_flags->RegAt(0);
-    MachineInsn* new_write_flags =
+    berberis::MachineInsn* new_write_flags =
         machine_ir->NewInsn<x86_64::TestwRegImm>(flags_src, flags_mask, flags);
     insn_it = bb->insn_list().erase(insn_it);
     bb->insn_list().insert(insn_it, new_write_flags);
diff --git a/backend/x86_64/insn_folding_test.cc b/backend/x86_64/insn_folding_test.cc
index 226ae0d1..ba207c9c 100644
--- a/backend/x86_64/insn_folding_test.cc
+++ b/backend/x86_64/insn_folding_test.cc
@@ -30,9 +30,19 @@ namespace berberis::x86_64 {
 
 namespace {
 
+constexpr auto kMachineRegRAX = MachineRegs::kRAX;
+constexpr auto kMachineRegRDI = MachineRegs::kRDI;
+
+MachineInsnList::iterator FoldInsnsAndGetLastInsnIt(MachineIR* machine_ir, MachineBasicBlock* bb) {
+  FoldInsns(machine_ir);
+  return std::prev(bb->insn_list().end());
+}
+
 // By default for the successful folding the immediate must be sign-extended from 32-bit to the same
 // 64-bit integer number.
-template <typename InsnTypeRegReg, typename InsnTypeRegImm, bool kExpectSuccess = true>
+template <template <typename> typename InsnTypeRegReg,
+          template <typename> typename InsnTypeRegImm,
+          bool kExpectSuccess = true>
 void TryRegRegInsnFolding(bool is_64bit_mov_imm, uint64_t imm = 0x7777ffffULL) {
   Arena arena;
   MachineIR machine_ir(&arena);
@@ -51,37 +61,21 @@ void TryRegRegInsnFolding(bool is_64bit_mov_imm, uint64_t imm = 0x7777ffffULL) {
     builder.Gen<MovlRegImm>(vreg1, imm);
   }
   builder.Gen<InsnTypeRegReg>(vreg2, vreg1, flags);
-  builder.Gen<PseudoJump>(kNullGuestAddr);
 
-  bb->live_out().push_back(vreg2);
-
-  DefMap def_map(machine_ir.NumVReg(), machine_ir.arena());
-  for (const auto* insn : bb->insn_list()) {
-    def_map.ProcessInsn(insn);
-  }
-
-  InsnFolding insn_folding(def_map, &machine_ir);
-
-  auto insn_it = bb->insn_list().begin();
-  insn_it++;
-  const MachineInsn* insn = *insn_it;
-
-  auto [is_folded, folded_insn] = insn_folding.TryFoldInsn(insn);
-
-  if (!is_folded) {
-    EXPECT_FALSE(kExpectSuccess);
+  berberis::MachineInsn* folded_insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  if (!kExpectSuccess) {
+    EXPECT_EQ(MachineIR::MachineInsnType<InsnTypeRegReg>::kInfo.opcode, folded_insn->opcode());
     return;
   }
-  EXPECT_TRUE(kExpectSuccess);
-  EXPECT_EQ(InsnTypeRegImm::kInfo.opcode, folded_insn->opcode());
+  EXPECT_EQ(MachineIR::MachineInsnType<InsnTypeRegImm>::kInfo.opcode, folded_insn->opcode());
   EXPECT_EQ(vreg2, folded_insn->RegAt(0));
   EXPECT_EQ(flags, folded_insn->RegAt(1));
   EXPECT_EQ(static_cast<uint64_t>(static_cast<int32_t>(imm)),
             AsMachineInsnX86_64(folded_insn)->imm());
 }
 
-template <typename InsnTypeRegReg, typename InsnTypeRegImm>
-void TryMovInsnFolding(bool is_64bit_mov_imm, uint64_t imm) {
+template <template <typename> typename InsnTypeRegReg, template <typename> typename InsnTypeRegImm>
+void TryRegRegInsnFoldingExtraPseudoCopy(bool is_64bit_mov_imm, uint64_t imm = 0x7777ffffULL) {
   Arena arena;
   MachineIR machine_ir(&arena);
   auto* bb = machine_ir.NewBasicBlock();
@@ -90,6 +84,8 @@ void TryMovInsnFolding(bool is_64bit_mov_imm, uint64_t imm) {
 
   MachineReg vreg1 = machine_ir.AllocVReg();
   MachineReg vreg2 = machine_ir.AllocVReg();
+  MachineReg vreg3 = machine_ir.AllocVReg();
+  MachineReg flags = machine_ir.AllocVReg();
 
   builder.StartBasicBlock(bb);
   if (is_64bit_mov_imm) {
@@ -97,29 +93,47 @@ void TryMovInsnFolding(bool is_64bit_mov_imm, uint64_t imm) {
   } else {
     builder.Gen<MovlRegImm>(vreg1, imm);
   }
-  builder.Gen<InsnTypeRegReg>(vreg2, vreg1);
-  builder.Gen<PseudoJump>(kNullGuestAddr);
+  builder.Gen<PseudoCopy>(vreg2, vreg1, 8);
+  builder.Gen<InsnTypeRegReg>(vreg3, vreg2, flags);
 
-  bb->live_out().push_back(vreg2);
+  MachineInsnList::iterator folded_insn_it = FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  berberis::MachineInsn* folded_insn = *folded_insn_it;
+  EXPECT_EQ(MachineIR::MachineInsnType<InsnTypeRegImm>::kInfo.opcode, folded_insn->opcode());
+  EXPECT_EQ(vreg3, folded_insn->RegAt(0));
+  EXPECT_EQ(flags, folded_insn->RegAt(1));
+  EXPECT_EQ(static_cast<uint64_t>(static_cast<int32_t>(imm)),
+            AsMachineInsnX86_64(folded_insn)->imm());
 
-  DefMap def_map(machine_ir.NumVReg(), machine_ir.arena());
-  for (const auto* insn : bb->insn_list()) {
-    def_map.ProcessInsn(insn);
-  }
+  auto prev_insn_it = std::prev(folded_insn_it);
+  berberis::MachineInsn* prev_insn = *prev_insn_it;
+  EXPECT_EQ(prev_insn->opcode(), kMachineOpPseudoCopy);
+}
 
-  InsnFolding insn_folding(def_map, &machine_ir);
+template <template <typename> typename InsnTypeRegReg, template <typename> typename InsnTypeRegImm>
+void TryMovInsnFolding(bool is_64bit_mov_imm, uint64_t imm) {
+  Arena arena;
+  MachineIR machine_ir(&arena);
+  auto* bb = machine_ir.NewBasicBlock();
 
-  auto insn_it = bb->insn_list().begin();
-  insn_it++;
-  const MachineInsn* insn = *insn_it;
+  MachineIRBuilder builder(&machine_ir);
 
-  auto [is_folded, folded_insn] = insn_folding.TryFoldInsn(insn);
+  MachineReg vreg1 = machine_ir.AllocVReg();
+  MachineReg vreg2 = machine_ir.AllocVReg();
 
-  EXPECT_TRUE(is_folded);
-  EXPECT_EQ(InsnTypeRegImm::kInfo.opcode, folded_insn->opcode());
+  builder.StartBasicBlock(bb);
+  if (is_64bit_mov_imm) {
+    builder.Gen<MovqRegImm>(vreg1, imm);
+  } else {
+    builder.Gen<MovlRegImm>(vreg1, imm);
+  }
+  builder.Gen<InsnTypeRegReg>(vreg2, vreg1);
+
+  berberis::MachineInsn* folded_insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  EXPECT_EQ(MachineIR::MachineInsnType<InsnTypeRegImm>::kInfo.opcode, folded_insn->opcode());
   EXPECT_EQ(vreg2, folded_insn->RegAt(0));
   // MovqRegReg is the only instruction that can take full 64-bit imm.
-  if (InsnTypeRegReg::kInfo.opcode == MovqRegReg::kInfo.opcode) {
+  if (MachineIR::MachineInsnType<InsnTypeRegReg>::kInfo.opcode ==
+      MachineIR::MachineInsnType<MovqRegReg>::kInfo.opcode) {
     // Take into account zero-extension when MOVL.
     EXPECT_EQ(is_64bit_mov_imm ? imm : static_cast<uint32_t>(imm),
               AsMachineInsnX86_64(folded_insn)->imm());
@@ -129,6 +143,81 @@ void TryMovInsnFolding(bool is_64bit_mov_imm, uint64_t imm) {
   }
 }
 
+template <template <typename> typename InsnTypeRegImm, bool kInsnIs64Bit>
+void TryTwoImmediatesRegImmInsnFolding(uint64_t imm1, int32_t imm2, uint64_t expected_op_result) {
+  Arena arena;
+  MachineIR machine_ir(&arena);
+
+  MachineIRBuilder builder(&machine_ir);
+
+  auto* bb = machine_ir.NewBasicBlock();
+
+  MachineReg vreg1 = machine_ir.AllocVReg();
+  MachineReg vreg2 = machine_ir.AllocVReg();
+  MachineReg flags = machine_ir.AllocVReg();
+
+  builder.StartBasicBlock(bb);
+  if (kInsnIs64Bit) {
+    builder.Gen<MovqRegImm>(vreg1, imm1);
+  } else {
+    builder.Gen<MovlRegImm>(vreg1, static_cast<uint32_t>(imm1));
+  }
+  builder.Gen<PseudoCopy>(vreg2, vreg1, 8);
+  builder.Gen<InsnTypeRegImm>(vreg2, imm2, flags);
+
+  MachineInsnList::iterator insn_it = FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  berberis::MachineInsn* insn = *insn_it;
+  if (kInsnIs64Bit) {
+    EXPECT_EQ(insn->opcode(), kMachineOpMovqRegImm);
+    EXPECT_EQ(AsMachineInsnX86_64(insn)->imm(), expected_op_result);
+  } else {
+    EXPECT_EQ(insn->opcode(), kMachineOpMovlRegImm);
+    EXPECT_EQ(static_cast<uint32_t>(AsMachineInsnX86_64(insn)->imm()),
+              static_cast<uint32_t>(expected_op_result));
+  }
+  auto prev_insn_it = std::prev(insn_it);
+  berberis::MachineInsn* prev_insn = *prev_insn_it;
+  EXPECT_EQ(prev_insn->opcode(), MachineIR::MachineInsnType<InsnTypeRegImm>::kInfo.opcode);
+}
+
+template <template <typename> typename InsnTypeRegReg, bool kInsnIs64Bit>
+void TryTwoImmediatesRegRegInsnFolding(uint64_t imm1, uint64_t imm2, uint64_t expected_op_result) {
+  Arena arena;
+  MachineIR machine_ir(&arena);
+
+  MachineIRBuilder builder(&machine_ir);
+
+  auto* bb = machine_ir.NewBasicBlock();
+
+  MachineReg vreg1 = machine_ir.AllocVReg();
+  MachineReg vreg2 = machine_ir.AllocVReg();
+  MachineReg flags = machine_ir.AllocVReg();
+
+  builder.StartBasicBlock(bb);
+  if (kInsnIs64Bit) {
+    builder.Gen<MovqRegImm>(vreg1, imm1);
+    builder.Gen<MovqRegImm>(vreg2, imm2);
+  } else {
+    builder.Gen<MovlRegImm>(vreg1, static_cast<uint32_t>(imm1));
+    builder.Gen<MovlRegImm>(vreg2, static_cast<uint32_t>(imm2));
+  }
+  builder.Gen<InsnTypeRegReg>(vreg1, vreg2, flags);
+
+  MachineInsnList::iterator insn_it = FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  berberis::MachineInsn* insn = *insn_it;
+  if (kInsnIs64Bit) {
+    EXPECT_EQ(insn->opcode(), kMachineOpMovqRegImm);
+    EXPECT_EQ(AsMachineInsnX86_64(insn)->imm(), expected_op_result);
+  } else {
+    EXPECT_EQ(insn->opcode(), kMachineOpMovlRegImm);
+    EXPECT_EQ(static_cast<uint32_t>(AsMachineInsnX86_64(insn)->imm()),
+              static_cast<uint32_t>(expected_op_result));
+  }
+  auto prev_insn_it = std::prev(insn_it);
+  berberis::MachineInsn* prev_insn = *prev_insn_it;
+  EXPECT_EQ(prev_insn->opcode(), MachineIR::MachineInsnType<InsnTypeRegReg>::kInfo.opcode);
+}
+
 TEST(InsnFoldingTest, DefMapGetsLatestDef) {
   Arena arena;
   MachineIR machine_ir(&arena);
@@ -151,21 +240,57 @@ TEST(InsnFoldingTest, DefMapGetsLatestDef) {
   bb->live_out().push_back(vreg2);
 
   DefMap def_map(machine_ir.NumVReg(), machine_ir.arena());
-  for (const auto* insn : bb->insn_list()) {
-    def_map.ProcessInsn(insn);
+  for (auto insn_it = bb->insn_list().begin(); insn_it != bb->insn_list().end(); ++insn_it) {
+    def_map.ProcessInsn(insn_it);
   }
 
-  auto [vreg1_def, index1] = def_map.Get(vreg1);
+  auto [vreg1_def_it, index1] = def_map.Get(vreg1);
+  ASSERT_TRUE(vreg1_def_it.has_value());
+  const berberis::MachineInsn* vreg1_def = *vreg1_def_it.value();
   EXPECT_EQ(kMachineOpMovqRegImm, vreg1_def->opcode());
   EXPECT_EQ(vreg1, vreg1_def->RegAt(0));
   EXPECT_EQ(index1, 0);
 
-  auto [vreg2_def, index2] = def_map.Get(vreg2);
+  auto [vreg2_def_it, index2] = def_map.Get(vreg2);
+  ASSERT_TRUE(vreg2_def_it.has_value());
+  const berberis::MachineInsn* vreg2_def = *vreg2_def_it.value();
   EXPECT_EQ(kMachineOpAddqRegReg, vreg2_def->opcode());
   EXPECT_EQ(vreg2, vreg2_def->RegAt(0));
   EXPECT_EQ(index2, 2);
 }
 
+TEST(InsnFoldingTest, DefMapReturnsNoDefIfVRegIsOverwrittenByInsn) {
+  Arena arena;
+  MachineIR machine_ir(&arena);
+
+  auto* bb = machine_ir.NewBasicBlock();
+
+  MachineIRBuilder builder(&machine_ir);
+
+  MachineReg vreg1 = machine_ir.AllocVReg();
+  MachineReg vreg2 = machine_ir.AllocVReg();
+  MachineReg flags = machine_ir.AllocVReg();
+
+  builder.StartBasicBlock(bb);
+  builder.Gen<MovqRegImm>(vreg1, 0);
+  builder.Gen<MovqRegImm>(vreg2, 0);
+  builder.Gen<AddqRegReg>(vreg1, vreg2, flags);
+  builder.Gen<AddqRegReg>(vreg2, vreg1, flags);
+
+  DefMap def_map(machine_ir.NumVReg(), machine_ir.arena());
+  for (auto insn_it = bb->insn_list().begin(); insn_it != bb->insn_list().end(); ++insn_it) {
+    def_map.ProcessInsn(insn_it);
+  }
+
+  auto [vreg1_def_insn_it, vreg_def_insn_pos] = def_map.Get(vreg1);
+  ASSERT_TRUE(vreg1_def_insn_it.has_value());
+  EXPECT_EQ(kMachineOpAddqRegReg, (*vreg1_def_insn_it.value())->opcode());
+
+  // Checking def_map for vreg1 at the position of an instruction that overwrites it.
+  auto [vreg1_overwritten_def_it, _] = def_map.Get(vreg1, vreg_def_insn_pos);
+  EXPECT_FALSE(vreg1_overwritten_def_it.has_value());
+}
+
 TEST(InsnFoldingTest, MovFolding) {
   constexpr uint64_t kSignExtendableImm = 0xffff'ffff'8000'0000ULL;
   constexpr uint64_t kNotSignExtendableImm = 0xffff'ffff'0000'0000ULL;
@@ -192,23 +317,11 @@ TEST(InsnFoldingTest, SingleMovqMemBaseDispImm32Folding) {
 
   builder.StartBasicBlock(bb);
   builder.Gen<MovlRegImm>(vreg1, 2);
-  builder.Gen<MovqMemBaseDispReg>(kMachineRegRAX, 4, vreg1);
+  builder.Gen<MovqOpReg>({.base = kMachineRegRAX, .disp = 4}, vreg1);
   builder.SetRecoveryPointAtLastInsn(recovery_bb);
   builder.SetRecoveryWithGuestPCAtLastInsn(42);
-  builder.Gen<PseudoJump>(kNullGuestAddr);
-
-  DefMap def_map(machine_ir.NumVReg(), machine_ir.arena());
-  for (const auto* insn : bb->insn_list()) {
-    def_map.ProcessInsn(insn);
-  }
-
-  InsnFolding insn_folding(def_map, &machine_ir);
 
-  auto insn_it = bb->insn_list().begin();
-  insn_it++;
-  const MachineInsn* insn = *insn_it;
-
-  auto [_, folded_insn] = insn_folding.TryFoldInsn(insn);
+  berberis::MachineInsn* folded_insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
   EXPECT_EQ(kMachineOpMovqMemBaseDispImm, folded_insn->opcode());
   EXPECT_EQ(kMachineRegRAX, folded_insn->RegAt(0));
   EXPECT_EQ(2UL, AsMachineInsnX86_64(folded_insn)->imm());
@@ -230,23 +343,11 @@ TEST(InsnFoldingTest, SingleMovlMemBaseDispImm32Folding) {
 
   builder.StartBasicBlock(bb);
   builder.Gen<MovqRegImm>(vreg1, 0x3'0000'0003);
-  builder.Gen<MovlMemBaseDispReg>(kMachineRegRAX, 4, vreg1);
+  builder.Gen<MovlOpReg>({.base = kMachineRegRAX, .disp = 4}, vreg1);
   builder.SetRecoveryPointAtLastInsn(recovery_bb);
   builder.SetRecoveryWithGuestPCAtLastInsn(42);
-  builder.Gen<PseudoJump>(kNullGuestAddr);
-
-  DefMap def_map(machine_ir.NumVReg(), machine_ir.arena());
-  for (const auto* insn : bb->insn_list()) {
-    def_map.ProcessInsn(insn);
-  }
-
-  InsnFolding insn_folding(def_map, &machine_ir);
 
-  auto insn_it = bb->insn_list().begin();
-  insn_it++;
-  const MachineInsn* insn = *insn_it;
-
-  auto [_, folded_insn] = insn_folding.TryFoldInsn(insn);
+  berberis::MachineInsn* folded_insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
   EXPECT_EQ(kMachineOpMovlMemBaseDispImm, folded_insn->opcode());
   EXPECT_EQ(kMachineRegRAX, folded_insn->RegAt(0));
   EXPECT_EQ(3UL, AsMachineInsnX86_64(folded_insn)->imm());
@@ -271,19 +372,33 @@ TEST(InsnFoldingTest, RedundantMovlFolding) {
   builder.StartBasicBlock(bb);
   builder.Gen<AddlRegReg>(vreg2, vreg3, flags);
   builder.Gen<MovlRegReg>(vreg1, vreg2);
-  builder.Gen<PseudoJump>(kNullGuestAddr);
 
-  DefMap def_map(machine_ir.NumVReg(), machine_ir.arena());
-  for (const auto* insn : bb->insn_list()) {
-    def_map.ProcessInsn(insn);
-  }
+  berberis::MachineInsn* folded_insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  EXPECT_EQ(kMachineOpPseudoCopy, folded_insn->opcode());
+  EXPECT_EQ(vreg1, folded_insn->RegAt(0));
+  EXPECT_EQ(vreg2, folded_insn->RegAt(1));
+}
+
+TEST(InsnFoldingTest, RedundantMovlFoldingExtraPseudoCopy) {
+  Arena arena;
+  MachineIR machine_ir(&arena);
 
-  InsnFolding insn_folding(def_map, &machine_ir);
+  MachineIRBuilder builder(&machine_ir);
 
-  auto insn_it = bb->insn_list().begin();
-  const MachineInsn* insn = *std::next(insn_it);
+  auto* bb = machine_ir.NewBasicBlock();
+
+  MachineReg vreg1 = machine_ir.AllocVReg();
+  MachineReg vreg2 = machine_ir.AllocVReg();
+  MachineReg vreg3 = machine_ir.AllocVReg();
+  MachineReg vreg4 = machine_ir.AllocVReg();
+  MachineReg flags = machine_ir.AllocVReg();
+
+  builder.StartBasicBlock(bb);
+  builder.Gen<XorlRegReg>(vreg3, vreg4, flags);
+  builder.Gen<PseudoCopy>(vreg2, vreg3, 8);
+  builder.Gen<MovlRegReg>(vreg1, vreg2);
 
-  auto [_, folded_insn] = insn_folding.TryFoldInsn(insn);
+  berberis::MachineInsn* folded_insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
   EXPECT_EQ(kMachineOpPseudoCopy, folded_insn->opcode());
   EXPECT_EQ(vreg1, folded_insn->RegAt(0));
   EXPECT_EQ(vreg2, folded_insn->RegAt(1));
@@ -304,19 +419,11 @@ TEST(InsnFoldingTest, GracefulHandlingOfVRegDefinedInPreviousBasicBlock) {
 
   builder.StartBasicBlock(bb);
   builder.Gen<MovlRegReg>(vreg1, vreg2);
-  builder.Gen<PseudoJump>(kNullGuestAddr);
-
-  DefMap def_map(machine_ir.NumVReg(), machine_ir.arena());
-  for (const auto* insn : bb->insn_list()) {
-    def_map.ProcessInsn(insn);
-  }
-
-  InsnFolding insn_folding(def_map, &machine_ir);
-
-  const MachineInsn* insn = *(bb->insn_list().begin());
 
-  auto [success, _] = insn_folding.TryFoldInsn(insn);
-  EXPECT_FALSE(success);
+  berberis::MachineInsn* folded_insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  EXPECT_EQ(folded_insn->opcode(), kMachineOpMovlRegReg);
+  EXPECT_EQ(vreg1, folded_insn->RegAt(0));
+  EXPECT_EQ(vreg2, folded_insn->RegAt(1));
 }
 
 TEST(InsnFoldingTest, RegRegInsnTypeFolding) {
@@ -328,6 +435,8 @@ TEST(InsnFoldingTest, RegRegInsnTypeFolding) {
     TryRegRegInsnFolding<XorqRegReg, XorqRegImm>(is_64bit_mov_imm);
     TryRegRegInsnFolding<AndqRegReg, AndqRegImm>(is_64bit_mov_imm);
     TryRegRegInsnFolding<TestqRegReg, TestqRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFolding<ShlqRegReg, ShlqRegImm>(is_64bit_mov_imm, 10);
+    TryRegRegInsnFolding<ShrqRegReg, ShrqRegImm>(is_64bit_mov_imm, 11);
 
     TryRegRegInsnFolding<AddlRegReg, AddlRegImm>(is_64bit_mov_imm);
     TryRegRegInsnFolding<SublRegReg, SublRegImm>(is_64bit_mov_imm);
@@ -336,6 +445,24 @@ TEST(InsnFoldingTest, RegRegInsnTypeFolding) {
     TryRegRegInsnFolding<XorlRegReg, XorlRegImm>(is_64bit_mov_imm);
     TryRegRegInsnFolding<AndlRegReg, AndlRegImm>(is_64bit_mov_imm);
     TryRegRegInsnFolding<TestlRegReg, TestlRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFolding<ShllRegReg, ShllRegImm>(is_64bit_mov_imm, 10);
+    TryRegRegInsnFolding<ShrlRegReg, ShrlRegImm>(is_64bit_mov_imm, 11);
+
+    TryRegRegInsnFoldingExtraPseudoCopy<AddqRegReg, AddqRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<SubqRegReg, SubqRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<CmpqRegReg, CmpqRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<OrqRegReg, OrqRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<XorqRegReg, XorqRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<AndqRegReg, AndqRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<TestqRegReg, TestqRegImm>(is_64bit_mov_imm);
+
+    TryRegRegInsnFoldingExtraPseudoCopy<AddlRegReg, AddlRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<SublRegReg, SublRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<CmplRegReg, CmplRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<OrlRegReg, OrlRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<XorlRegReg, XorlRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<AndlRegReg, AndlRegImm>(is_64bit_mov_imm);
+    TryRegRegInsnFoldingExtraPseudoCopy<TestlRegReg, TestlRegImm>(is_64bit_mov_imm);
   }
 }
 
@@ -422,8 +549,8 @@ TEST(InsnFoldingTest, PseudoWriteFlagsErased) {
   EXPECT_EQ(bb->insn_list().size(), 4UL);
 
   auto insn_it = bb->insn_list().rbegin();
-  insn_it++;
-  const MachineInsn* insn = *insn_it;
+  ++insn_it;
+  const berberis::MachineInsn* insn = *insn_it;
 
   EXPECT_EQ(kMachineOpPseudoCopy, insn->opcode());
 }
@@ -503,8 +630,8 @@ TEST(InsnFoldingTest, FoldInsnsSmoke) {
   EXPECT_EQ(bb->insn_list().size(), 3UL);
 
   auto insn_it = bb->insn_list().begin();
-  insn_it++;
-  MachineInsn* insn = *insn_it;
+  ++insn_it;
+  berberis::MachineInsn* insn = *insn_it;
 
   EXPECT_EQ(insn->opcode(), kMachineOpAddqRegImm);
   EXPECT_EQ(vreg2, insn->RegAt(0));
@@ -554,6 +681,204 @@ TEST(InsnFoldingTest, FoldWriteFlags) {
   TestFoldCond(Cond::kNoOverflow, Cond::kEqual, PseudoWriteFlags::Flags::kOverflow);
 }
 
+TEST(InsnFoldingTest, CountTrailingZeroesFolding64) {
+  Arena arena;
+  MachineIR machine_ir(&arena);
+
+  MachineIRBuilder builder(&machine_ir);
+
+  auto* bb = machine_ir.NewBasicBlock();
+
+  MachineReg vreg1 = machine_ir.AllocVReg();
+  MachineReg vreg2 = machine_ir.AllocVReg();
+  MachineReg vreg3 = machine_ir.AllocVReg();
+  MachineReg vreg4 = machine_ir.AllocVReg();
+  MachineReg vreg5 = machine_ir.AllocVReg();
+  MachineReg vreg6 = machine_ir.AllocVReg();
+  MachineReg flags = machine_ir.AllocVReg();
+
+  builder.StartBasicBlock(bb);
+  builder.Gen<MovqRegImm>(vreg1, 3);
+  builder.Gen<PseudoCopy>(vreg2, vreg1, 8);
+  builder.Gen<ReverseBitsU64>(vreg3, vreg2, vreg4, flags);
+  builder.Gen<PseudoCopy>(vreg5, vreg3, 8);
+  builder.Gen<CountLeadingZerosU64>(vreg6, vreg5, flags);
+
+  berberis::MachineInsn* insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  EXPECT_EQ(insn->opcode(), kMachineOpCountTrailingZerosU64);
+  EXPECT_EQ(insn->RegAt(0), vreg6);
+  EXPECT_EQ(insn->RegAt(1), vreg1);
+}
+
+TEST(InsnFoldingTest, CountTrailingZeroesFolding64MBI) {
+  Arena arena;
+  MachineIR machine_ir(&arena);
+
+  MachineIRBuilder builder(&machine_ir);
+
+  auto* bb = machine_ir.NewBasicBlock();
+
+  MachineReg vreg1 = machine_ir.AllocVReg();
+  MachineReg vreg2 = machine_ir.AllocVReg();
+  MachineReg vreg3 = machine_ir.AllocVReg();
+  MachineReg vreg4 = machine_ir.AllocVReg();
+  MachineReg vreg5 = machine_ir.AllocVReg();
+  MachineReg vreg6 = machine_ir.AllocVReg();
+  MachineReg flags = machine_ir.AllocVReg();
+
+  builder.StartBasicBlock(bb);
+  builder.Gen<MovqRegImm>(vreg1, 3);
+  builder.Gen<PseudoCopy>(vreg2, vreg1, 8);
+  builder.Gen<ReverseBitsU64>(vreg3, vreg2, vreg4, flags);
+  builder.Gen<PseudoCopy>(vreg5, vreg3, 8);
+  builder.Gen<LzcntqRegReg>(vreg6, vreg5, flags);
+
+  berberis::MachineInsn* insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  EXPECT_EQ(insn->opcode(), kMachineOpTzcntqRegReg);
+  EXPECT_EQ(insn->RegAt(0), vreg6);
+  EXPECT_EQ(insn->RegAt(1), vreg1);
+}
+
+TEST(InsnFoldingTest, CountTrailingZeroesFolding32) {
+  Arena arena;
+  MachineIR machine_ir(&arena);
+
+  MachineIRBuilder builder(&machine_ir);
+
+  auto* bb = machine_ir.NewBasicBlock();
+
+  MachineReg vreg1 = machine_ir.AllocVReg();
+  MachineReg vreg2 = machine_ir.AllocVReg();
+  MachineReg vreg3 = machine_ir.AllocVReg();
+  MachineReg vreg4 = machine_ir.AllocVReg();
+  MachineReg vreg5 = machine_ir.AllocVReg();
+  MachineReg flags = machine_ir.AllocVReg();
+
+  builder.StartBasicBlock(bb);
+  builder.Gen<MovqRegImm>(vreg1, 3);
+  builder.Gen<PseudoCopy>(vreg2, vreg1, 8);
+  builder.Gen<ReverseBitsU32>(vreg3, vreg2, flags);
+  builder.Gen<PseudoCopy>(vreg4, vreg3, 8);
+  builder.Gen<CountLeadingZerosU32>(vreg5, vreg4, flags);
+
+  berberis::MachineInsn* insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  EXPECT_EQ(insn->opcode(), kMachineOpCountTrailingZerosU32);
+  EXPECT_EQ(insn->RegAt(0), vreg5);
+  EXPECT_EQ(insn->RegAt(1), vreg1);
+}
+
+TEST(InsnFoldingTest, CountTrailingZeroesFolding32BMI) {
+  Arena arena;
+  MachineIR machine_ir(&arena);
+
+  MachineIRBuilder builder(&machine_ir);
+
+  auto* bb = machine_ir.NewBasicBlock();
+
+  MachineReg vreg1 = machine_ir.AllocVReg();
+  MachineReg vreg2 = machine_ir.AllocVReg();
+  MachineReg vreg3 = machine_ir.AllocVReg();
+  MachineReg vreg4 = machine_ir.AllocVReg();
+  MachineReg vreg5 = machine_ir.AllocVReg();
+  MachineReg flags = machine_ir.AllocVReg();
+
+  builder.StartBasicBlock(bb);
+  builder.Gen<MovqRegImm>(vreg1, 3);
+  builder.Gen<PseudoCopy>(vreg2, vreg1, 8);
+  builder.Gen<ReverseBitsU32>(vreg3, vreg2, flags);
+  builder.Gen<PseudoCopy>(vreg4, vreg3, 8);
+  builder.Gen<LzcntlRegReg>(vreg5, vreg4, flags);
+
+  berberis::MachineInsn* insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  EXPECT_EQ(insn->opcode(), kMachineOpTzcntlRegReg);
+  EXPECT_EQ(insn->RegAt(0), vreg5);
+  EXPECT_EQ(insn->RegAt(1), vreg1);
+}
+
+TEST(InsnFoldingTest, CountTrailingZeroesFoldingCancelledIfArgNotAlive) {
+  Arena arena;
+  MachineIR machine_ir(&arena);
+
+  MachineIRBuilder builder(&machine_ir);
+
+  auto* bb = machine_ir.NewBasicBlock();
+
+  MachineReg vreg1 = machine_ir.AllocVReg();
+  MachineReg vreg2 = machine_ir.AllocVReg();
+  MachineReg vreg3 = machine_ir.AllocVReg();
+  MachineReg vreg4 = machine_ir.AllocVReg();
+  MachineReg vreg5 = machine_ir.AllocVReg();
+  MachineReg vreg6 = machine_ir.AllocVReg();
+  MachineReg flags = machine_ir.AllocVReg();
+
+  builder.StartBasicBlock(bb);
+  builder.Gen<MovqRegImm>(vreg1, 3);
+  builder.Gen<PseudoCopy>(vreg2, vreg1, 8);
+  builder.Gen<ReverseBitsU64>(vreg3, vreg2, vreg4, flags);
+  builder.Gen<MovqRegImm>(vreg1, 4);  // invalidates vreg1
+  builder.Gen<PseudoCopy>(vreg5, vreg3, 8);
+  builder.Gen<LzcntqRegReg>(vreg6, vreg5, flags);
+
+  berberis::MachineInsn* insn = *FoldInsnsAndGetLastInsnIt(&machine_ir, bb);
+  EXPECT_EQ(insn->opcode(), kMachineOpLzcntqRegReg);
+}
+
+TEST(InsnFoldingTest, FoldTwoImmediatesRegImmInsn32) {
+  uint32_t imm = 0x1234'5678;
+  TryTwoImmediatesRegImmInsnFolding<AndlRegImm, false>(
+      imm, static_cast<int32_t>(0xf0f0'f0f0), imm & uint32_t{0xf0f0'f0f0});
+  TryTwoImmediatesRegImmInsnFolding<OrlRegImm, false>(
+      imm, static_cast<int32_t>(0xf0f0'f0f0), imm | uint32_t{0xf0f0'f0f0});
+  TryTwoImmediatesRegImmInsnFolding<XorlRegImm, false>(
+      imm, static_cast<int32_t>(0xf0f0'f0f0), imm ^ uint32_t{0xf0f0'f0f0});
+  TryTwoImmediatesRegImmInsnFolding<AddlRegImm, false>(
+      imm, static_cast<int32_t>(0xf0f0'f0f0), imm + uint32_t{0xf0f0'f0f0});
+  TryTwoImmediatesRegImmInsnFolding<SublRegImm, false>(
+      imm, static_cast<int32_t>(0xf0f0'f0f0), imm - uint32_t{0xf0f0'f0f0});
+  TryTwoImmediatesRegImmInsnFolding<ShllRegImm, false>(imm, 10, imm << 10);
+  TryTwoImmediatesRegImmInsnFolding<ShrlRegImm, false>(imm, 11, imm >> 11);
+}
+
+TEST(InsnFoldingTest, FoldTwoImmediatesRegImmInsn64) {
+  uint64_t imm = 0x1234'5678'9abc'def0;
+  TryTwoImmediatesRegImmInsnFolding<AndqRegImm, true>(
+      imm, static_cast<int32_t>(0xf0f0'f0f0), imm & uint64_t{0xffff'ffff'f0f0'f0f0});
+  TryTwoImmediatesRegImmInsnFolding<OrqRegImm, true>(
+      imm, static_cast<int32_t>(0xf0f0'f0f0), imm | uint64_t{0xffff'ffff'f0f0'f0f0});
+  TryTwoImmediatesRegImmInsnFolding<XorqRegImm, true>(
+      imm, static_cast<int32_t>(0xf0f0'f0f0), imm ^ uint64_t{0xffff'ffff'f0f0'f0f0});
+  TryTwoImmediatesRegImmInsnFolding<AddqRegImm, true>(
+      imm, static_cast<int32_t>(0xf0f0'f0f0), imm + uint64_t{0xffff'ffff'f0f0'f0f0});
+  TryTwoImmediatesRegImmInsnFolding<SubqRegImm, true>(
+      imm, static_cast<int32_t>(0xf0f0'f0f0), imm - uint64_t{0xffff'ffff'f0f0'f0f0});
+  TryTwoImmediatesRegImmInsnFolding<ShlqRegImm, true>(imm, 10, imm << 10);
+  TryTwoImmediatesRegImmInsnFolding<ShrqRegImm, true>(imm, 11, imm >> 11);
+}
+
+TEST(InsnFoldingTest, FoldTwoImmediatesRegRegInsn32) {
+  uint32_t imm1 = 0x1234'5678;
+  uint32_t imm2 = 0xf0f0'f0f0;
+  TryTwoImmediatesRegRegInsnFolding<AndlRegReg, false>(imm1, imm2, imm1 & imm2);
+  TryTwoImmediatesRegRegInsnFolding<OrlRegReg, false>(imm1, imm2, imm1 | imm2);
+  TryTwoImmediatesRegRegInsnFolding<XorlRegReg, false>(imm1, imm2, imm1 ^ imm2);
+  TryTwoImmediatesRegRegInsnFolding<AddlRegReg, false>(imm1, imm2, imm1 + imm2);
+  TryTwoImmediatesRegRegInsnFolding<SublRegReg, false>(imm1, imm2, imm1 - imm2);
+  TryTwoImmediatesRegRegInsnFolding<ShllRegReg, false>(imm1, 10, imm1 << 10);
+  TryTwoImmediatesRegRegInsnFolding<ShrlRegReg, false>(imm1, 11, imm1 >> 11);
+}
+
+TEST(InsnFoldingTest, FoldTwoImmediatesRegRegInsn64) {
+  uint64_t imm1 = 0x1234'5678'9abc'def0;
+  uint64_t imm2 = 0xf0f0'f0f0'f0f0'f0f0;
+  TryTwoImmediatesRegRegInsnFolding<AndqRegReg, true>(imm1, imm2, imm1 & imm2);
+  TryTwoImmediatesRegRegInsnFolding<OrqRegReg, true>(imm1, imm2, imm1 | imm2);
+  TryTwoImmediatesRegRegInsnFolding<XorqRegReg, true>(imm1, imm2, imm1 ^ imm2);
+  TryTwoImmediatesRegRegInsnFolding<AddqRegReg, true>(imm1, imm2, imm1 + imm2);
+  TryTwoImmediatesRegRegInsnFolding<SubqRegReg, true>(imm1, imm2, imm1 - imm2);
+  TryTwoImmediatesRegRegInsnFolding<ShlqRegReg, true>(imm1, 10, imm1 << 10);
+  TryTwoImmediatesRegRegInsnFolding<ShrqRegReg, true>(imm1, 11, imm1 >> 11);
+}
+
 }  // namespace
 
 }  // namespace berberis::x86_64
diff --git a/backend/x86_64/lir_instructions.json b/backend/x86_64/lir_instructions.json
index 713c0642..d8160026 100644
--- a/backend/x86_64/lir_instructions.json
+++ b/backend/x86_64/lir_instructions.json
@@ -76,6 +76,7 @@
         "ShlqRegImm",
         "ShlqRegReg",
         "ShrbRegImm",
+        "ShrdlRegRegImm",
         "ShrlRegImm",
         "ShrlRegReg",
         "ShrqRegImm",
@@ -96,6 +97,8 @@
         "LockCmpXchgqRegMemRegInsns",
         "LockCmpXchg8bRegRegRegRegMemInsns",
         "LockCmpXchg16bRegRegRegRegMemInsns",
+        "LzcntlRegReg",
+        "LzcntqRegReg",
         "Mfence",
         "MovbMemImmInsns",
         "MovbMemRegInsns",
@@ -199,6 +202,8 @@
         "SublRegReg",
         "SubqRegImm",
         "SubqRegReg",
+        "TzcntlRegReg",
+        "TzcntqRegReg",
         "Vfmadd231pdXRegXRegXReg",
         "Vfmadd231psXRegXRegXReg",
         "Vfmadd231sdXRegXRegXReg",
diff --git a/backend/x86_64/liveness_analyzer.cc b/backend/x86_64/liveness_analyzer.cc
index 3a0f7790..64636b7c 100644
--- a/backend/x86_64/liveness_analyzer.cc
+++ b/backend/x86_64/liveness_analyzer.cc
@@ -63,7 +63,7 @@ bool LivenessAnalyzer::VisitBasicBlock(const MachineBasicBlock* bb) {
 
   // Traverse instructions backward, updating liveness.
   for (auto insn_it = bb->insn_list().rbegin(); insn_it != bb->insn_list().rend(); ++insn_it) {
-    const MachineInsn* insn = *insn_it;
+    const berberis::MachineInsn* insn = *insn_it;
     // Same reg can be def and use, so process all defs first.
     for (int i = 0; i < insn->NumRegOperands(); ++i) {
       if (insn->RegAt(i).IsVReg() && insn->RegKindAt(i).IsDef()) {
diff --git a/backend/x86_64/liveness_analyzer_test.cc b/backend/x86_64/liveness_analyzer_test.cc
index f2986107..e7ed6f2d 100644
--- a/backend/x86_64/liveness_analyzer_test.cc
+++ b/backend/x86_64/liveness_analyzer_test.cc
@@ -28,6 +28,8 @@ namespace berberis {
 
 namespace {
 
+constexpr auto kMachineRegRAX = x86_64::MachineRegs::kRAX;
+
 template <typename... VRegs>
 void ExpectNoLiveIns(const x86_64::LivenessAnalyzer* liveness,
                      const MachineBasicBlock* bb,
@@ -72,7 +74,7 @@ TEST(MachineLivenessAnalyzerTest, UseProducesLiveIn) {
   auto* bb = machine_ir.NewBasicBlock();
 
   builder.StartBasicBlock(bb);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   x86_64::LivenessAnalyzer liveness(&machine_ir);
@@ -85,6 +87,12 @@ class FakeInsnWithDefEarlyClobber : public MachineInsn {
  public:
   explicit FakeInsnWithDefEarlyClobber(MachineReg reg)
       : MachineInsn(kMachineOpUndefined, 1, &reg_kind_, &reg_, kMachineInsnDefault), reg_{reg} {}
+  static constexpr x86_64::MachineInsnInfo kInfo =
+      x86_64::MachineInsnInfo({MachineOpcode{0},
+                               1,
+                               {{&x86_64::kRegisterClass<x86_64::device_arch_info::GeneralReg32>,
+                                 MachineRegKind::kDefEarlyClobber}},
+                               kMachineInsnDefault});
   [[nodiscard]] std::string GetDebugString() const override {
     return "FakeInsnWithDefEarlyClobber";
   }
@@ -128,7 +136,7 @@ TEST(MachineLivenessAnalyzerTest, DefKillsUse) {
 
   builder.StartBasicBlock(bb);
   builder.Gen<x86_64::MovqRegImm>(vreg, 0);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   x86_64::LivenessAnalyzer liveness(&machine_ir);
@@ -168,7 +176,7 @@ TEST(MachineLivenessAnalyzerTest, DefDoesNotKillAnotherVReg) {
 
   builder.StartBasicBlock(bb);
   builder.Gen<x86_64::MovqRegImm>(vreg1, 0);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg2);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg2);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   x86_64::LivenessAnalyzer liveness(&machine_ir);
diff --git a/backend/x86_64/local_guest_context_optimizer.cc b/backend/x86_64/local_guest_context_optimizer.cc
index 3c93e03f..51f322c0 100644
--- a/backend/x86_64/local_guest_context_optimizer.cc
+++ b/backend/x86_64/local_guest_context_optimizer.cc
@@ -24,13 +24,15 @@ namespace berberis::x86_64 {
 
 namespace {
 
+using OffsetCounterMap = ArenaVector<std::pair<size_t, int>>;
+
 class LocalGuestContextOptimizer {
  public:
   explicit LocalGuestContextOptimizer(x86_64::MachineIR* machine_ir)
       : machine_ir_(machine_ir),
         mem_reg_map_(sizeof(CPUState), std::nullopt, machine_ir->arena()) {}
 
-  void RemoveLocalGuestContextAccesses();
+  void RemoveLocalGuestContextAccesses(const OptimizeLocalParams& params);
 
  private:
   struct MappedRegUsage {
@@ -45,11 +47,70 @@ class LocalGuestContextOptimizer {
   ArenaVector<std::optional<MappedRegUsage>> mem_reg_map_;
 };
 
-void LocalGuestContextOptimizer::RemoveLocalGuestContextAccesses() {
+ArenaVector<int> CountGuestRegAccesses(const MachineIR* ir, MachineBasicBlock* bb) {
+  ArenaVector<int> guest_access_count(sizeof(CPUState), 0, ir->arena());
+  for (auto* base_insn : bb->insn_list()) {
+    if (ir->IsCPUStateGet(base_insn) || ir->IsCPUStatePut(base_insn)) {
+      auto insn = AsMachineInsnX86_64(base_insn);
+      guest_access_count.at(insn->disp())++;
+    }
+  }
+  return guest_access_count;
+}
+
+OffsetCounterMap GetSortedOffsetCounters(MachineIR* ir, MachineBasicBlock* bb) {
+  auto guest_access_count = CountGuestRegAccesses(ir, bb);
+
+  OffsetCounterMap offset_counter_map(ir->arena());
+  for (size_t offset = 0; offset < sizeof(CPUState); offset++) {
+    int cnt = guest_access_count.at(offset);
+    if (cnt > 0) {
+      offset_counter_map.push_back({offset, cnt});
+    }
+  }
+
+  std::sort(offset_counter_map.begin(), offset_counter_map.end(), [](auto pair1, auto pair2) {
+    return std::get<1>(pair1) > std::get<1>(pair2);
+  });
+
+  return offset_counter_map;
+}
+
+void LocalGuestContextOptimizer::RemoveLocalGuestContextAccesses(
+    const OptimizeLocalParams& params) {
   for (auto* bb : machine_ir_->bb_list()) {
     std::fill(mem_reg_map_.begin(), mem_reg_map_.end(), std::nullopt);
+
+    auto sorted_offsets = GetSortedOffsetCounters(machine_ir_, bb);
+    ArenaVector<bool> optimized_offsets(sizeof(CPUState), false, machine_ir_->arena());
+
+    size_t general_reg_count = 0;
+    size_t simd_reg_count = 0;
+    for (auto [offset, unused_counter] : sorted_offsets) {
+      // TODO(b/232598137): Account for f and v register classes.
+      // Simd regs.
+      if (IsSimdOffset(offset)) {
+        if (simd_reg_count++ < params.simd_reg_limit) {
+          optimized_offsets[offset] = true;
+        }
+        continue;
+      }
+      // General regs and flags.
+      if (general_reg_count++ < params.general_reg_limit) {
+        optimized_offsets[offset] = true;
+      }
+    }
+
     for (auto insn_it = bb->insn_list().begin(); insn_it != bb->insn_list().end(); insn_it++) {
       auto* insn = AsMachineInsnX86_64(*insn_it);
+
+      // Skip insn if it accesses regs with low priority
+      if (insn->IsCPUStateGet() || insn->IsCPUStatePut()) {
+        if (!optimized_offsets.at(insn->disp())) {
+          continue;
+        }
+      }
+
       if (insn->IsCPUStateGet()) {
         ReplaceGetAndUpdateMap(insn_it);
       } else if (insn->IsCPUStatePut()) {
@@ -92,9 +153,10 @@ void LocalGuestContextOptimizer::ReplacePutAndUpdateMap(MachineInsnList& insn_li
 
 }  // namespace
 
-void RemoveLocalGuestContextAccesses(x86_64::MachineIR* machine_ir) {
+void RemoveLocalGuestContextAccesses(x86_64::MachineIR* machine_ir,
+                                     const OptimizeLocalParams& params) {
   LocalGuestContextOptimizer optimizer(machine_ir);
-  optimizer.RemoveLocalGuestContextAccesses();
+  optimizer.RemoveLocalGuestContextAccesses(params);
 }
 
 }  // namespace berberis::x86_64
diff --git a/backend/x86_64/local_guest_context_optimizer_test.cc b/backend/x86_64/local_guest_context_optimizer_test.cc
index ad984c75..9ea03565 100644
--- a/backend/x86_64/local_guest_context_optimizer_test.cc
+++ b/backend/x86_64/local_guest_context_optimizer_test.cc
@@ -126,9 +126,9 @@ TEST(MachineIRLocalGuestContextOptimizer, DoNotRemoveAccessToMonitorValue) {
   builder.StartBasicBlock(bb);
   auto reg1 = machine_ir.AllocVReg();
   auto reg2 = machine_ir.AllocVReg();
-  auto offset = offsetof(ProcessState, cpu.reservation_value);
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, offset, reg1);
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, offset, reg2);
+  constexpr auto offset = offsetof(ProcessState, cpu.reservation_value);
+  builder.Gen<x86_64::MovqOpReg>({.base = x86_64::kMachineRegRBP, .disp = offset}, reg1);
+  builder.Gen<x86_64::MovqOpReg>({.base = x86_64::kMachineRegRBP, .disp = offset}, reg2);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   x86_64::RemoveLocalGuestContextAccesses(&machine_ir);
@@ -144,6 +144,68 @@ TEST(MachineIRLocalGuestContextOptimizer, DoNotRemoveAccessToMonitorValue) {
   ASSERT_EQ(x86_64::AsMachineInsnX86_64(store_insn_2)->disp(), offset);
 }
 
+TEST(MachineIRLocalGuestContextOptimizer, LimitRegisters) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  auto bb = machine_ir.NewBasicBlock();
+  builder.StartBasicBlock(bb);
+  builder.GenGet(machine_ir.AllocVReg(), GetThreadStateRegOffset(1));
+  builder.GenGet(machine_ir.AllocVReg(), GetThreadStateRegOffset(1));
+  builder.GenGet(machine_ir.AllocVReg(), GetThreadStateRegOffset(0));
+  builder.GenGet(machine_ir.AllocVReg(), GetThreadStateRegOffset(0));
+  builder.GenGet(machine_ir.AllocVReg(), GetThreadStateRegOffset(0));
+
+  if (DoesCpuStateHaveDedicatedSimdRegs()) {
+    builder.GenGet(machine_ir.AllocVReg(), GetThreadStateSimdRegOffset(5));
+    builder.GenGet(machine_ir.AllocVReg(), GetThreadStateSimdRegOffset(2));
+    builder.GenGet(machine_ir.AllocVReg(), GetThreadStateSimdRegOffset(5));
+    builder.GenGet(machine_ir.AllocVReg(), GetThreadStateSimdRegOffset(2));
+    builder.GenGet(machine_ir.AllocVReg(), GetThreadStateSimdRegOffset(0));
+    builder.GenGet(machine_ir.AllocVReg(), GetThreadStateSimdRegOffset(5));
+  }
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  x86_64::RemoveLocalGuestContextAccesses(&machine_ir,
+                                          x86_64::OptimizeLocalParams{
+                                              .general_reg_limit = 1,
+                                              .simd_reg_limit = 2,
+                                          });
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  // Check instructions with general regs replaced.
+  auto insn_it = bb->insn_list().begin();
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpMovqRegMemBaseDisp);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpMovqRegMemBaseDisp);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpMovqRegMemBaseDisp);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  insn_it++;
+
+  // Check instructions with simd regs replaced.
+  if (DoesCpuStateHaveDedicatedSimdRegs()) {
+    ASSERT_EQ((*insn_it)->opcode(), kMachineOpMovqRegMemBaseDisp);
+    insn_it++;
+    ASSERT_EQ((*insn_it)->opcode(), kMachineOpMovqRegMemBaseDisp);
+    insn_it++;
+    ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+    insn_it++;
+    ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+    insn_it++;
+    ASSERT_EQ((*insn_it)->opcode(), kMachineOpMovqRegMemBaseDisp);
+    insn_it++;
+    ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+    insn_it++;
+    ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoJump);
+  }
+}
+
 }  // namespace
 
 }  // namespace berberis
diff --git a/backend/x86_64/loop_guest_context_optimizer.cc b/backend/x86_64/loop_guest_context_optimizer.cc
index 2d498ed8..8796c03c 100644
--- a/backend/x86_64/loop_guest_context_optimizer.cc
+++ b/backend/x86_64/loop_guest_context_optimizer.cc
@@ -95,7 +95,7 @@ void ReplacePutAndUpdateMap(MachineIR* ir,
 
   auto src = insn->RegAt(1);
   auto copy_size = insn->opcode() == kMachineOpMovdqaMemBaseDispXReg ? 16 : 8;
-  auto* new_insn = static_cast<MachineInsn*>(
+  auto* new_insn = static_cast<berberis::MachineInsn*>(
       ir->NewInsn<PseudoCopy>(mem_reg_map[disp].value().reg, src, copy_size));
   *insn_it = new_insn;
 }
@@ -105,7 +105,8 @@ void GenerateGetInsns(MachineIR* ir, MachineBasicBlock* bb, const MemRegMap& mem
   CHECK_EQ(bb->out_edges().size(), 1);
 
   auto insert_it = std::prev(bb->insn_list().end());
-  for (unsigned long disp = 0; disp < mem_reg_map.size(); disp++) {
+  CHECK(mem_reg_map.size() <= std::numeric_limits<int32_t>::max());
+  for (int32_t disp = 0; disp < static_cast<int32_t>(mem_reg_map.size()); disp++) {
     if (!mem_reg_map[disp].has_value()) {
       continue;
     }
@@ -118,19 +119,19 @@ void GenerateGetInsns(MachineIR* ir, MachineBasicBlock* bb, const MemRegMap& mem
     // TODO(b/203826752) Do not generate the Get insn if the initialization of the mapped
     // register is not needed.
     auto reg_info = mem_reg_map[disp].value();
-    MachineInsn* get_insn;
+    berberis::MachineInsn* get_insn;
     switch (reg_info.mov_type) {
       case MovType::kMovq:
-        get_insn = ir->NewInsn<MovqRegMemBaseDisp>(reg_info.reg, kMachineRegRBP, disp);
+        get_insn = ir->NewInsn<MovqRegOp>(reg_info.reg, {.base = kMachineRegRBP, .disp = disp});
         break;
       case MovType::kMovdqa:
-        get_insn = ir->NewInsn<MovdqaXRegMemBaseDisp>(reg_info.reg, kMachineRegRBP, disp);
+        get_insn = ir->NewInsn<MovdqaXRegOp>(reg_info.reg, {.base = kMachineRegRBP, .disp = disp});
         break;
       case MovType::kMovw:
-        get_insn = ir->NewInsn<MovwRegMemBaseDisp>(reg_info.reg, kMachineRegRBP, disp);
+        get_insn = ir->NewInsn<MovwRegOp>(reg_info.reg, {.base = kMachineRegRBP, .disp = disp});
         break;
       case MovType::kMovsd:
-        get_insn = ir->NewInsn<MovsdXRegMemBaseDisp>(reg_info.reg, kMachineRegRBP, disp);
+        get_insn = ir->NewInsn<MovsdXRegOp>(reg_info.reg, {.base = kMachineRegRBP, .disp = disp});
         break;
     }
 
@@ -143,7 +144,8 @@ void GeneratePutInsns(MachineIR* ir, MachineBasicBlock* bb, const MemRegMap& mem
   CHECK_EQ(bb->in_edges().size(), 1);
 
   auto insert_it = bb->insn_list().begin();
-  for (unsigned long disp = 0; disp < mem_reg_map.size(); disp++) {
+  CHECK(static_cast<size_t>(static_cast<int32_t>(mem_reg_map.size())) == mem_reg_map.size());
+  for (int32_t disp = 0; disp < static_cast<int32_t>(mem_reg_map.size()); disp++) {
     if (!mem_reg_map[disp].has_value()) {
       continue;
     }
@@ -153,19 +155,19 @@ void GeneratePutInsns(MachineIR* ir, MachineBasicBlock* bb, const MemRegMap& mem
       continue;
     }
 
-    MachineInsn* put_insn;
+    berberis::MachineInsn* put_insn;
     switch (reg_info.mov_type) {
       case MovType::kMovq:
-        put_insn = ir->NewInsn<MovqMemBaseDispReg>(kMachineRegRBP, disp, reg_info.reg);
+        put_insn = ir->NewInsn<MovqOpReg>({.base = kMachineRegRBP, .disp = disp}, reg_info.reg);
         break;
       case MovType::kMovdqa:
-        put_insn = ir->NewInsn<MovdqaMemBaseDispXReg>(kMachineRegRBP, disp, reg_info.reg);
+        put_insn = ir->NewInsn<MovdqaOpXReg>({.base = kMachineRegRBP, .disp = disp}, reg_info.reg);
         break;
       case MovType::kMovw:
-        put_insn = ir->NewInsn<MovwMemBaseDispReg>(kMachineRegRBP, disp, reg_info.reg);
+        put_insn = ir->NewInsn<MovwOpReg>({.base = kMachineRegRBP, .disp = disp}, reg_info.reg);
         break;
       case MovType::kMovsd:
-        put_insn = ir->NewInsn<MovsdMemBaseDispXReg>(kMachineRegRBP, disp, reg_info.reg);
+        put_insn = ir->NewInsn<MovsdOpXReg>({.base = kMachineRegRBP, .disp = disp}, reg_info.reg);
         break;
     }
 
diff --git a/backend/x86_64/loop_guest_context_optimizer_test.cc b/backend/x86_64/loop_guest_context_optimizer_test.cc
index 663f276a..148de693 100644
--- a/backend/x86_64/loop_guest_context_optimizer_test.cc
+++ b/backend/x86_64/loop_guest_context_optimizer_test.cc
@@ -291,7 +291,7 @@ TEST(MachineIRLoopGuestContextOptimizerRiscv64, ReplaceGetMovwAndUpdateMap) {
   builder.StartBasicBlock(bb);
   auto reg1 = machine_ir.AllocVReg();
   auto offset = 0;
-  builder.Gen<MovwRegMemBaseDisp>(reg1, kMachineRegRBP, offset);
+  builder.Gen<MovwRegOp>(reg1, {.base = kMachineRegRBP, .disp = offset});
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   auto insn_it = bb->insn_list().begin();
@@ -315,7 +315,7 @@ TEST(MachineIRLoopGuestContextOptimizerRiscv64, ReplacePutMovwAndUpdateMap) {
   builder.StartBasicBlock(bb);
   auto reg1 = machine_ir.AllocVReg();
   auto offset = 0;
-  builder.Gen<MovwMemBaseDispReg>(kMachineRegRBP, offset, reg1);
+  builder.Gen<MovwOpReg>({.base = kMachineRegRBP, .disp = offset}, reg1);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   auto insn_it = bb->insn_list().begin();
@@ -1077,7 +1077,7 @@ TEST(MachineIRLoopGuestContextOptimizer, ReplaceGetFlagsAndUpdateMap) {
   builder.StartBasicBlock(bb);
   auto reg1 = machine_ir.AllocVReg();
   auto offset = GetThreadStateFlagOffset();
-  builder.Gen<MovwRegMemBaseDisp>(reg1, kMachineRegRBP, offset);
+  builder.Gen<MovwRegOp>(reg1, {.base = kMachineRegRBP, .disp = static_cast<int32_t>(offset)});
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   auto insn_it = bb->insn_list().begin();
@@ -1104,7 +1104,7 @@ TEST(MachineIRLoopGuestContextOptimizer, ReplacePutFlagsAndUpdateMap) {
   builder.StartBasicBlock(bb);
   auto reg1 = machine_ir.AllocVReg();
   auto offset = GetThreadStateFlagOffset();
-  builder.Gen<MovwMemBaseDispReg>(kMachineRegRBP, offset, reg1);
+  builder.Gen<MovwOpReg>({.base = kMachineRegRBP, .disp = static_cast<int32_t>(offset)}, reg1);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   auto insn_it = bb->insn_list().begin();
diff --git a/backend/x86_64/machine_insn_intrinsics_tests.cc b/backend/x86_64/machine_insn_intrinsics_tests.cc
deleted file mode 100644
index 5388c8b4..00000000
--- a/backend/x86_64/machine_insn_intrinsics_tests.cc
+++ /dev/null
@@ -1,64 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#include "gtest/gtest.h"
-
-#include "berberis/backend/x86_64/machine_insn_intrinsics.h"
-#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h"
-#include "berberis/intrinsics/intrinsics_args.h"
-
-namespace berberis {
-
-namespace {
-
-// TEST(MachineInsnIntrinsicsTest, HasNMem)
-static_assert(x86_64::has_n_mem_v<
-              1,
-              TmpArg<intrinsics::bindings::Mem32, intrinsics::bindings::DefEarlyClobber>>);
-static_assert(!x86_64::has_n_mem_v<1>);
-static_assert(!x86_64::has_n_mem_v<
-              1,
-              TmpArg<intrinsics::bindings::GeneralReg32, intrinsics::bindings::DefEarlyClobber>>);
-static_assert(x86_64::has_n_mem_v<2,
-                                  TmpArg<intrinsics::bindings::Mem32, intrinsics::bindings::Use>,
-                                  TmpArg<intrinsics::bindings::Mem32, intrinsics::bindings::Def>>);
-static_assert(!x86_64::has_n_mem_v<
-              2,
-              TmpArg<intrinsics::bindings::Mem32, intrinsics::bindings::DefEarlyClobber>>);
-
-// TEST(MachineInsnIntrinsicsTest, ConstructorArgs)
-static_assert(
-    std::is_same_v<x86_64::constructor_args_t<
-                       TmpArg<intrinsics::bindings::Mem64, intrinsics::bindings::DefEarlyClobber>>,
-                   std::tuple<MachineReg, int32_t>>);
-static_assert(
-    std::is_same_v<x86_64::constructor_args_t<TmpArg<intrinsics::bindings::GeneralReg64,
-                                                     intrinsics::bindings::DefEarlyClobber>>,
-                   std::tuple<MachineReg>>);
-static_assert(std::is_same_v<x86_64::constructor_args_t<
-                                 InArg<0, intrinsics::bindings::Imm32, intrinsics::bindings::Use>>,
-                             std::tuple<int32_t>>);
-static_assert(
-    std::is_same_v<
-        x86_64::constructor_args_t<
-            InArg<0, intrinsics::bindings::Imm16, intrinsics::bindings::Use>,
-            TmpArg<intrinsics::bindings::Mem64, intrinsics::bindings::DefEarlyClobber>,
-            TmpArg<intrinsics::bindings::GeneralReg64, intrinsics::bindings::DefEarlyClobber>>,
-        std::tuple<int16_t, MachineReg, int32_t, MachineReg>>);
-
-}  // namespace
-
-}  // namespace berberis
diff --git a/backend/x86_64/machine_ir_analysis.cc b/backend/x86_64/machine_ir_analysis.cc
index e2f03ec9..e53c40af 100644
--- a/backend/x86_64/machine_ir_analysis.cc
+++ b/backend/x86_64/machine_ir_analysis.cc
@@ -18,7 +18,6 @@
 
 #include <algorithm>
 
-#include "berberis/backend/common/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/base/algorithm.h"
 #include "berberis/base/arena_alloc.h"
diff --git a/backend/x86_64/machine_ir_check_test.cc b/backend/x86_64/machine_ir_check_test.cc
index 92f580bf..55e48049 100644
--- a/backend/x86_64/machine_ir_check_test.cc
+++ b/backend/x86_64/machine_ir_check_test.cc
@@ -29,6 +29,8 @@ namespace berberis {
 
 namespace {
 
+constexpr auto kMachineRegRAX = x86_64::MachineRegs::kRAX;
+
 TEST(MachineIRCheckTest, BasicBlockNotDstOfInEdgeLists) {
   Arena arena;
   x86_64::MachineIR machine_ir(&arena);
@@ -190,7 +192,7 @@ TEST(MachineIRCheckTest, MisplacedJump) {
 
   builder.StartBasicBlock(bb);
   builder.Gen<PseudoJump>(kNullGuestAddr);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
 
   EXPECT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckFail);
 }
@@ -206,7 +208,7 @@ TEST(MachineIRCheckTest, MisplacedIndirectJump) {
 
   builder.StartBasicBlock(bb);
   builder.Gen<PseudoIndirectJump>(vreg);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
 
   EXPECT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckFail);
 }
@@ -228,7 +230,7 @@ TEST(MachineIRCheckTest, MisplacedPseudoBranch) {
   builder.Gen<x86_64::MovqRegImm>(vreg, 0);
 
   builder.StartBasicBlock(bb2);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   EXPECT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckFail);
@@ -253,7 +255,7 @@ TEST(MachineIRCheckTest, MisplacedPseudoCondBranch) {
   builder.Gen<x86_64::MovqRegImm>(vreg, 0);
 
   builder.StartBasicBlock(bb2);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   builder.StartBasicBlock(bb3);
@@ -278,7 +280,7 @@ TEST(MachineIRCheckTest, NoThenEdgePseudoBranch) {
   builder.Gen<PseudoBranch>(bb2);
 
   builder.StartBasicBlock(bb2);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   EXPECT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckDanglingBasicBlock);
@@ -302,7 +304,7 @@ TEST(MachineIRCheckTest, NoThenEdgePseudoCondBranch) {
   builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb2, bb3, x86_64::kMachineRegFLAGS);
 
   builder.StartBasicBlock(bb2);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   builder.StartBasicBlock(bb3);
@@ -330,7 +332,7 @@ TEST(MachineIRCheckTest, NoElseEdgePseudoCondBranch) {
   builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb2, bb3, x86_64::kMachineRegFLAGS);
 
   builder.StartBasicBlock(bb2);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   builder.StartBasicBlock(bb3);
diff --git a/backend/x86_64/machine_ir_exec_test.cc b/backend/x86_64/machine_ir_exec_test.cc
index f9555e3e..cee46f2f 100644
--- a/backend/x86_64/machine_ir_exec_test.cc
+++ b/backend/x86_64/machine_ir_exec_test.cc
@@ -31,12 +31,15 @@
 #include "berberis/code_gen_lib/code_gen_lib.h"  // EmitFreeStackFrame
 #include "berberis/test_utils/scoped_exec_region.h"
 
-#include "x86_64/mem_operand.h"
-
 namespace berberis {
 
 namespace {
 
+constexpr auto kMachineRegRAX = x86_64::MachineRegs::kRAX;
+constexpr auto kMachineRegRBP = x86_64::MachineRegs::kRBP;
+constexpr auto kMachineRegRDI = x86_64::MachineRegs::kRDI;
+constexpr auto kMachineRegXMM0 = x86_64::MachineRegs::kXMM0;
+
 // TODO(b/232598137): Maybe share with
 // heavy_optimizer/<guest>_to_<host>/call_intrinsic_tests.cc.
 class ExecTest {
@@ -127,13 +130,13 @@ TEST(ExecMachineIR, Smoke) {
   builder.StartBasicBlock(machine_ir.NewBasicBlock());
 
   // Let RBP point to 'data'.
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, reinterpret_cast<uintptr_t>(&data));
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, reinterpret_cast<uintptr_t>(&data));
 
   // data.y = data.x;
-  builder.Gen<x86_64::MovqRegMemBaseDisp>(
-      x86_64::kMachineRegRAX, x86_64::kMachineRegRBP, offsetof(Data, x));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(
-      x86_64::kMachineRegRBP, offsetof(Data, y), x86_64::kMachineRegRAX);
+  builder.Gen<x86_64::MovqRegOp>(kMachineRegRAX,
+                                 {.base = kMachineRegRBP, .disp = offsetof(Data, x)});
+  builder.Gen<x86_64::MovqOpReg>({.base = kMachineRegRBP, .disp = offsetof(Data, y)},
+                                 kMachineRegRAX);
 
   ExecTest test;
   test.Init(machine_ir);
@@ -153,15 +156,15 @@ TEST(ExecMachineIR, CallImm) {
   builder.StartBasicBlock(machine_ir.NewBasicBlock());
 
   uint64_t data = 0xfeedf00d'feedf00dULL;
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRDI, data);
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRDI, data);
   auto* invert_func_ptr = +[](uint64_t arg) { return ~arg; };
 
   MachineReg flag_register = machine_ir.AllocVReg();
   builder.GenCallImm(bit_cast<uintptr_t>(invert_func_ptr), flag_register);
 
   uint64_t result = 0;
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, reinterpret_cast<uintptr_t>(&result));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, 0, x86_64::kMachineRegRAX);
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, reinterpret_cast<uintptr_t>(&result));
+  builder.Gen<x86_64::MovqOpReg>({.base = kMachineRegRBP}, kMachineRegRAX);
 
   ExecTest test;
   test.Init(machine_ir);
@@ -203,9 +206,9 @@ TEST(ExecMachineIR, CallImmAllocIntOperands) {
       {data_reg, x86_64::CallImm::kIntRegType},
   }};
   auto* call = builder.GenCallImm(bit_cast<uintptr_t>(func_ptr), flag_register, args);
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, bit_cast<uintptr_t>(&result));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, 0, call->IntResultAt(0));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, 8, call->IntResultAt(1));
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, bit_cast<uintptr_t>(&result));
+  builder.Gen<x86_64::MovqOpReg>({.base = kMachineRegRBP}, call->IntResultAt(0));
+  builder.Gen<x86_64::MovqOpReg>({.base = kMachineRegRBP, .disp = 8}, call->IntResultAt(1));
 
   AllocRegs(&machine_ir);
 
@@ -299,11 +302,11 @@ TEST(ExecMachineIR, CallImmAllocXmmOperands) {
       {data_xreg, x86_64::CallImm::kXmmRegType},
   }};
   auto* call = builder.GenCallImm(bit_cast<uintptr_t>(func_ptr), flag_register, args);
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, bit_cast<uintptr_t>(&result));
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, bit_cast<uintptr_t>(&result));
   builder.Gen<x86_64::MovqRegXReg>(data_reg, call->XmmResultAt(0));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, 0, data_reg);
+  builder.Gen<x86_64::MovqOpReg>({.base = kMachineRegRBP}, data_reg);
   builder.Gen<x86_64::MovqRegXReg>(data_reg, call->XmmResultAt(1));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, 8, data_reg);
+  builder.Gen<x86_64::MovqOpReg>({.base = kMachineRegRBP, .disp = 8}, data_reg);
 
   AllocRegs(&machine_ir);
 
@@ -387,7 +390,7 @@ void TestRegAlloc() {
   builder.StartBasicBlock(machine_ir.NewBasicBlock());
 
   // Let rbp point to 'data'.
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, reinterpret_cast<uintptr_t>(&data));
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, reinterpret_cast<uintptr_t>(&data));
 
   // Read data.in_array into vregs, xor and write to data.out.
 
@@ -397,8 +400,10 @@ void TestRegAlloc() {
   for (int i = 0; i < N; ++i) {
     MachineReg v = machine_ir.AllocVReg();
     vregs[i] = v;
-    builder.Gen<x86_64::MovqRegMemBaseDisp>(
-        v, x86_64::kMachineRegRBP, offsetof(Data, in_array) + i * sizeof(data.in_array[0]));
+    builder.Gen<x86_64::MovqRegOp>(
+        v,
+        {.base = kMachineRegRBP,
+         .disp = static_cast<int32_t>(offsetof(Data, in_array) + i * sizeof(data.in_array[0]))});
     MachineReg vx = machine_ir.AllocVReg();
     xmm_vregs[i] = vx;
     builder.Gen<x86_64::MovqXRegReg>(vx, v);
@@ -428,7 +433,7 @@ void TestRegAlloc() {
   builder.Gen<x86_64::MovqRegXReg>(v1, vx0);
   MachineReg vflags = machine_ir.AllocVReg();
   builder.Gen<x86_64::AddqRegReg>(v1, v0, vflags);
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, offsetof(Data, out), v1);
+  builder.Gen<x86_64::MovqOpReg>({.base = kMachineRegRBP, .disp = offsetof(Data, out)}, v1);
 
   AllocRegs(&machine_ir);
 
@@ -455,7 +460,7 @@ TEST(ExecMachineIR, RegAllocWithCallImm) {
   TestRegAlloc<true>();
 }
 
-TEST(ExecMachineIR, MemOperand) {
+TEST(ExecMachineIR, MemoryOperand) {
   struct Data {
     uint64_t in_base_disp;
     uint64_t in_index_disp;
@@ -483,22 +488,22 @@ TEST(ExecMachineIR, MemOperand) {
   MachineReg data_reg;
 
   // BaseDisp
-  x86_64::MemOperand mem_base_disp =
-      x86_64::MemOperand::MakeBaseDisp(base_reg, offsetof(Data, in_base_disp));
+  x86_64::MemoryOperand mem_base_disp{.base = base_reg, .disp = offsetof(Data, in_base_disp)};
   data_reg = machine_ir.AllocVReg();
-  x86_64::GenArgsMem<x86_64::MovzxblRegMemInsns>(&builder, mem_base_disp, data_reg);
-  builder.Gen<x86_64::MovqMemBaseDispReg>(base_reg, offsetof(Data, out_base_disp), data_reg);
+  builder.Gen<x86_64::MovzxblRegOp>(data_reg, mem_base_disp);
+  builder.Gen<x86_64::MovqOpReg>({.base = base_reg, .disp = offsetof(Data, out_base_disp)},
+                                 data_reg);
 
   // IndexDisp
   MachineReg index_reg = machine_ir.AllocVReg();
   static_assert(alignof(struct Data) >= 2);
   builder.Gen<x86_64::MovqRegImm>(index_reg, reinterpret_cast<uintptr_t>(&data) / 2);
-  x86_64::MemOperand mem_index_disp =
-      x86_64::MemOperand::MakeIndexDisp<x86_64::MachineMemOperandScale::kTwo>(
-          index_reg, offsetof(Data, in_index_disp));
+  x86_64::MemoryOperand mem_index_disp = {
+      .index = index_reg, .scale = CodeEmitter::kTimesTwo, offsetof(Data, in_index_disp)};
   data_reg = machine_ir.AllocVReg();
-  x86_64::GenArgsMem<x86_64::MovzxblRegMemInsns>(&builder, mem_index_disp, data_reg);
-  builder.Gen<x86_64::MovqMemBaseDispReg>(base_reg, offsetof(Data, out_index_disp), data_reg);
+  builder.Gen<x86_64::MovzxblRegOp>(data_reg, mem_index_disp);
+  builder.Gen<x86_64::MovqOpReg>({.base = base_reg, .disp = offsetof(Data, out_index_disp)},
+                                 data_reg);
 
   // BaseIndexDisp
   MachineReg tmp_base_reg = machine_ir.AllocVReg();
@@ -506,12 +511,12 @@ TEST(ExecMachineIR, MemOperand) {
                                   reinterpret_cast<uintptr_t>(&data.in_base_index_disp[0]));
   MachineReg tmp_index_reg = machine_ir.AllocVReg();
   builder.Gen<x86_64::MovqRegImm>(tmp_index_reg, 2);
-  x86_64::MemOperand mem_base_index_disp =
-      x86_64::MemOperand::MakeBaseIndexDisp<x86_64::MachineMemOperandScale::kFour>(
-          tmp_base_reg, tmp_index_reg, 8);
+  x86_64::MemoryOperand mem_base_index_disp = {
+      .base = tmp_base_reg, .index = tmp_index_reg, .scale = CodeEmitter::kTimesFour, .disp = 8};
   data_reg = machine_ir.AllocVReg();
-  x86_64::GenArgsMem<x86_64::MovzxblRegMemInsns>(&builder, mem_base_index_disp, data_reg);
-  builder.Gen<x86_64::MovqMemBaseDispReg>(base_reg, offsetof(Data, out_base_index_disp), data_reg);
+  builder.Gen<x86_64::MovzxblRegOp>(data_reg, mem_base_index_disp);
+  builder.Gen<x86_64::MovqOpReg>({.base = base_reg, .disp = offsetof(Data, out_base_index_disp)},
+                                 data_reg);
 
   AllocRegs(&machine_ir);
 
@@ -525,39 +530,39 @@ TEST(ExecMachineIR, MemOperand) {
 }
 
 const MachineReg kGRegs[]{
-    x86_64::kMachineRegR8,
-    x86_64::kMachineRegR9,
-    x86_64::kMachineRegR10,
-    x86_64::kMachineRegR11,
-    x86_64::kMachineRegRSI,
-    x86_64::kMachineRegRDI,
-    x86_64::kMachineRegRAX,
-    x86_64::kMachineRegRBX,
-    x86_64::kMachineRegRCX,
-    x86_64::kMachineRegRDX,
-    x86_64::kMachineRegR12,
-    x86_64::kMachineRegR13,
-    x86_64::kMachineRegR14,
-    x86_64::kMachineRegR15,
+    x86_64::MachineRegs::kR8,
+    x86_64::MachineRegs::kR9,
+    x86_64::MachineRegs::kR10,
+    x86_64::MachineRegs::kR11,
+    x86_64::MachineRegs::kRSI,
+    x86_64::MachineRegs::kRDI,
+    x86_64::MachineRegs::kRAX,
+    x86_64::MachineRegs::kRBX,
+    x86_64::MachineRegs::kRCX,
+    x86_64::MachineRegs::kRDX,
+    x86_64::MachineRegs::kR12,
+    x86_64::MachineRegs::kR13,
+    x86_64::MachineRegs::kR14,
+    x86_64::MachineRegs::kR15,
 };
 
 const MachineReg kXmms[]{
-    x86_64::kMachineRegXMM0,
-    x86_64::kMachineRegXMM1,
-    x86_64::kMachineRegXMM2,
-    x86_64::kMachineRegXMM3,
-    x86_64::kMachineRegXMM4,
-    x86_64::kMachineRegXMM5,
-    x86_64::kMachineRegXMM6,
-    x86_64::kMachineRegXMM7,
-    x86_64::kMachineRegXMM8,
-    x86_64::kMachineRegXMM9,
-    x86_64::kMachineRegXMM10,
-    x86_64::kMachineRegXMM11,
-    x86_64::kMachineRegXMM12,
-    x86_64::kMachineRegXMM13,
-    x86_64::kMachineRegXMM14,
-    x86_64::kMachineRegXMM15,
+    x86_64::MachineRegs::kXMM0,
+    x86_64::MachineRegs::kXMM1,
+    x86_64::MachineRegs::kXMM2,
+    x86_64::MachineRegs::kXMM3,
+    x86_64::MachineRegs::kXMM4,
+    x86_64::MachineRegs::kXMM5,
+    x86_64::MachineRegs::kXMM6,
+    x86_64::MachineRegs::kXMM7,
+    x86_64::MachineRegs::kXMM8,
+    x86_64::MachineRegs::kXMM9,
+    x86_64::MachineRegs::kXMM10,
+    x86_64::MachineRegs::kXMM11,
+    x86_64::MachineRegs::kXMM12,
+    x86_64::MachineRegs::kXMM13,
+    x86_64::MachineRegs::kXMM14,
+    x86_64::MachineRegs::kXMM15,
 };
 
 class ExecMachineIRTest : public ::testing::Test {
@@ -606,47 +611,55 @@ class ExecMachineIRTest : public ::testing::Test {
     builder_.StartBasicBlock(bb_);
 
     // Let rbp point to 'data'.
-    builder_.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, reinterpret_cast<uintptr_t>(&data_));
+    builder_.Gen<x86_64::MovqRegImm>(kMachineRegRBP, reinterpret_cast<uintptr_t>(&data_));
 
     for (size_t i = 0; i < std::size(data_.slots); ++i) {
       slots_[i] = MachineReg::CreateSpilledRegFromIndex(
           machine_ir_.SpillSlotOffset(machine_ir_.AllocSpill()));
 
-      builder_.Gen<x86_64::MovdquXRegMemBaseDisp>(
-          x86_64::kMachineRegXMM0,
-          x86_64::kMachineRegRBP,
-          offsetof(Data, slots) + i * sizeof(data_.slots[0]));
-      builder_.Gen<PseudoCopy>(slots_[i], x86_64::kMachineRegXMM0, 16);
+      builder_.Gen<x86_64::MovdquXRegOp>(
+          kMachineRegXMM0,
+          {.base = kMachineRegRBP,
+           .disp = static_cast<int32_t>(offsetof(Data, slots) + i * sizeof(data_.slots[0]))});
+      builder_.Gen<PseudoCopy>(slots_[i], kMachineRegXMM0, 16);
     }
 
     for (size_t i = 0; i < std::size(kXmms); ++i) {
-      builder_.Gen<x86_64::MovdquXRegMemBaseDisp>(
-          kXmms[i], x86_64::kMachineRegRBP, offsetof(Data, xmms) + i * sizeof(data_.xmms[0]));
+      builder_.Gen<x86_64::MovdquXRegOp>(
+          kXmms[i],
+          {.base = kMachineRegRBP,
+           .disp = static_cast<int32_t>(offsetof(Data, xmms) + i * sizeof(data_.xmms[0]))});
     }
 
     for (size_t i = 0; i < std::size(kGRegs); ++i) {
-      builder_.Gen<x86_64::MovqRegMemBaseDisp>(
-          kGRegs[i], x86_64::kMachineRegRBP, offsetof(Data, gregs) + i * sizeof(data_.gregs[0]));
+      builder_.Gen<x86_64::MovqRegOp>(
+          kGRegs[i],
+          {.base = kMachineRegRBP,
+           .disp = static_cast<int32_t>(offsetof(Data, gregs) + i * sizeof(data_.gregs[0]))});
     }
   }
 
   void Finalize() {
     for (size_t i = 0; i < std::size(kGRegs); ++i) {
-      builder_.Gen<x86_64::MovqMemBaseDispReg>(
-          x86_64::kMachineRegRBP, offsetof(Data, gregs) + i * sizeof(data_.gregs[0]), kGRegs[i]);
+      builder_.Gen<x86_64::MovqOpReg>(
+          {.base = kMachineRegRBP,
+           .disp = static_cast<int32_t>(offsetof(Data, gregs) + i * sizeof(data_.gregs[0]))},
+          kGRegs[i]);
     }
 
     for (size_t i = 0; i < std::size(kXmms); ++i) {
-      builder_.Gen<x86_64::MovdquMemBaseDispXReg>(
-          x86_64::kMachineRegRBP, offsetof(Data, xmms) + i * sizeof(data_.xmms[0]), kXmms[i]);
+      builder_.Gen<x86_64::MovdquOpXReg>(
+          {.base = kMachineRegRBP,
+           .disp = static_cast<int32_t>(offsetof(Data, xmms) + i * sizeof(data_.xmms[0]))},
+          kXmms[i]);
     }
 
     for (size_t i = 0; i < std::size(data_.slots); ++i) {
-      builder_.Gen<PseudoCopy>(x86_64::kMachineRegXMM0, slots_[i], 16);
-      builder_.Gen<x86_64::MovdquMemBaseDispXReg>(
-          x86_64::kMachineRegRBP,
-          offsetof(Data, slots) + i * sizeof(data_.slots[0]),
-          x86_64::kMachineRegXMM0);
+      builder_.Gen<PseudoCopy>(kMachineRegXMM0, slots_[i], 16);
+      builder_.Gen<x86_64::MovdquOpXReg>(
+          {.base = kMachineRegRBP,
+           .disp = static_cast<int32_t>(offsetof(Data, slots) + i * sizeof(data_.slots[0]))},
+          kMachineRegXMM0);
     }
 
     test_.Init(machine_ir_);
@@ -725,7 +738,7 @@ TEST(ExecMachineIR, RecoveryBlock) {
 
   Arena arena;
   x86_64::MachineIR machine_ir(&arena);
-  constexpr auto kScratchReg = x86_64::kMachineRegRBP;
+  constexpr auto kScratchReg = kMachineRegRBP;
   auto* main_bb = machine_ir.NewBasicBlock();
   auto* recovery_bb = machine_ir.NewBasicBlock();
 
@@ -733,7 +746,7 @@ TEST(ExecMachineIR, RecoveryBlock) {
   builder.StartBasicBlock(main_bb);
   // Cause a SIGSEGV.
   builder.Gen<x86_64::XorqRegReg>(kScratchReg, kScratchReg, x86_64::kMachineRegFLAGS);
-  builder.Gen<x86_64::MovqMemBaseDispReg>(kScratchReg, 0, kScratchReg);
+  builder.Gen<x86_64::MovqOpReg>({.base = kScratchReg}, kScratchReg);
   builder.SetRecoveryPointAtLastInsn(recovery_bb);
   builder.Gen<PseudoJump>(21ULL);
 
@@ -757,13 +770,13 @@ TEST(ExecMachineIR, RecoveryWithGuestPC) {
 
   Arena arena;
   x86_64::MachineIR machine_ir(&arena);
-  constexpr auto kScratchReg = x86_64::kMachineRegRBP;
+  constexpr auto kScratchReg = kMachineRegRBP;
 
   x86_64::MachineIRBuilder builder(&machine_ir);
   builder.StartBasicBlock(machine_ir.NewBasicBlock());
   // Cause a SIGSEGV.
   builder.Gen<x86_64::XorqRegReg>(kScratchReg, kScratchReg, x86_64::kMachineRegFLAGS);
-  builder.Gen<x86_64::MovqMemBaseDispReg>(kScratchReg, 0, kScratchReg);
+  builder.Gen<x86_64::MovqOpReg>({.base = kScratchReg}, kScratchReg);
   builder.SetRecoveryWithGuestPCAtLastInsn(42ULL);
 
   ExecTest test;
@@ -790,15 +803,16 @@ TEST(ExecMachineIR, PseudoReadFlags) {
   builder.StartBasicBlock(machine_ir.NewBasicBlock());
 
   // Let RBP point to 'data'.
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, reinterpret_cast<uintptr_t>(&data));
-  builder.Gen<x86_64::MovqRegMemBaseDisp>(
-      x86_64::kMachineRegRAX, x86_64::kMachineRegRBP, offsetof(Data, x));
-  builder.Gen<x86_64::AddqRegMemBaseDisp>(
-      x86_64::kMachineRegRAX, x86_64::kMachineRegRBP, offsetof(Data, y), x86_64::kMachineRegFLAGS);
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, reinterpret_cast<uintptr_t>(&data));
+  builder.Gen<x86_64::MovqRegOp>(kMachineRegRAX,
+                                 {.base = kMachineRegRBP, .disp = offsetof(Data, x)});
+  builder.Gen<x86_64::AddqRegOp>(kMachineRegRAX,
+                                 {.base = kMachineRegRBP, .disp = offsetof(Data, y)},
+                                 x86_64::kMachineRegFLAGS);
   builder.Gen<PseudoReadFlags>(
-      PseudoReadFlags::kWithOverflow, x86_64::kMachineRegRAX, x86_64::kMachineRegFLAGS);
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, reinterpret_cast<uintptr_t>(&res_flags));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, 0, x86_64::kMachineRegRAX);
+      PseudoReadFlags::kWithOverflow, kMachineRegRAX, x86_64::kMachineRegFLAGS);
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, reinterpret_cast<uintptr_t>(&res_flags));
+  builder.Gen<x86_64::MovqOpReg>({.base = kMachineRegRBP}, kMachineRegRAX);
 
   ExecTest test;
   test.Init(machine_ir);
@@ -833,17 +847,18 @@ TEST(ExecMachineIR, PseudoReadFlagsWithoutOverflow) {
   builder.StartBasicBlock(machine_ir.NewBasicBlock());
 
   // Let RBP point to 'data'.
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, reinterpret_cast<uintptr_t>(&data));
-  builder.Gen<x86_64::MovqRegMemBaseDisp>(
-      x86_64::kMachineRegRAX, x86_64::kMachineRegRBP, offsetof(Data, x));
-  builder.Gen<x86_64::AddqRegMemBaseDisp>(
-      x86_64::kMachineRegRAX, x86_64::kMachineRegRBP, offsetof(Data, y), x86_64::kMachineRegFLAGS);
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, reinterpret_cast<uintptr_t>(&data));
+  builder.Gen<x86_64::MovqRegOp>(kMachineRegRAX,
+                                 {.base = kMachineRegRBP, .disp = offsetof(Data, x)});
+  builder.Gen<x86_64::AddqRegOp>(kMachineRegRAX,
+                                 {.base = kMachineRegRBP, .disp = offsetof(Data, y)},
+                                 x86_64::kMachineRegFLAGS);
   // ReadFlags must reset overflow to zero, even if it's set in RAX.
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRAX, MakeFlags(0b0001));
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRAX, MakeFlags(0b0001));
   builder.Gen<PseudoReadFlags>(
-      PseudoReadFlags::kWithoutOverflow, x86_64::kMachineRegRAX, x86_64::kMachineRegFLAGS);
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, reinterpret_cast<uintptr_t>(&res_flags));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, 0, x86_64::kMachineRegRAX);
+      PseudoReadFlags::kWithoutOverflow, kMachineRegRAX, x86_64::kMachineRegFLAGS);
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, reinterpret_cast<uintptr_t>(&res_flags));
+  builder.Gen<x86_64::MovqOpReg>({.base = kMachineRegRBP}, kMachineRegRAX);
 
   ExecTest test;
   test.Init(machine_ir);
@@ -865,14 +880,14 @@ TEST(ExecMachineIR, PseudoWriteFlags) {
   x86_64::MachineIRBuilder builder(&machine_ir);
   builder.StartBasicBlock(machine_ir.NewBasicBlock());
 
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, reinterpret_cast<uintptr_t>(&arg_flags));
-  builder.Gen<x86_64::MovqRegMemBaseDisp>(x86_64::kMachineRegRAX, x86_64::kMachineRegRBP, 0);
-  builder.Gen<PseudoWriteFlags>(x86_64::kMachineRegRAX, x86_64::kMachineRegFLAGS);
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, reinterpret_cast<uintptr_t>(&arg_flags));
+  builder.Gen<x86_64::MovqRegOp>(kMachineRegRAX, {.base = kMachineRegRBP});
+  builder.Gen<PseudoWriteFlags>(kMachineRegRAX, x86_64::kMachineRegFLAGS);
   // Assume PseudoReadFlags is verified by another test.
   builder.Gen<PseudoReadFlags>(
-      PseudoReadFlags::kWithOverflow, x86_64::kMachineRegRAX, x86_64::kMachineRegFLAGS);
-  builder.Gen<x86_64::MovqRegImm>(x86_64::kMachineRegRBP, reinterpret_cast<uintptr_t>(&res_flags));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, 0, x86_64::kMachineRegRAX);
+      PseudoReadFlags::kWithOverflow, kMachineRegRAX, x86_64::kMachineRegFLAGS);
+  builder.Gen<x86_64::MovqRegImm>(kMachineRegRBP, reinterpret_cast<uintptr_t>(&res_flags));
+  builder.Gen<x86_64::MovqOpReg>({.base = kMachineRegRBP}, kMachineRegRAX);
 
   ExecTest test;
   test.Init(machine_ir);
diff --git a/backend/x86_64/machine_ir_opt.cc b/backend/x86_64/machine_ir_opt.cc
index c587f3bd..9cc3fa8b 100644
--- a/backend/x86_64/machine_ir_opt.cc
+++ b/backend/x86_64/machine_ir_opt.cc
@@ -63,7 +63,7 @@ class RegUsageBitSet {
   VRegBitSet reg_set_;
 };
 
-bool AreResultsUsed(const MachineInsn* insn, const RegUsageBitSet& is_reg_used) {
+bool AreResultsUsed(const berberis::MachineInsn* insn, const RegUsageBitSet& is_reg_used) {
   for (int i = 0; i < insn->NumRegOperands(); ++i) {
     if (insn->RegKindAt(i).IsDef() && is_reg_used[insn->RegAt(i)]) {
       return true;
@@ -72,7 +72,7 @@ bool AreResultsUsed(const MachineInsn* insn, const RegUsageBitSet& is_reg_used)
   return false;
 }
 
-void SetInsnResultsUnused(const MachineInsn* insn, RegUsageBitSet& is_reg_used) {
+void SetInsnResultsUnused(const berberis::MachineInsn* insn, RegUsageBitSet& is_reg_used) {
   for (int i = 0; i < insn->NumRegOperands(); ++i) {
     if (insn->RegKindAt(i).IsDef()) {
       is_reg_used.Reset(insn->RegAt(i));
@@ -80,7 +80,7 @@ void SetInsnResultsUnused(const MachineInsn* insn, RegUsageBitSet& is_reg_used)
   }
 }
 
-void SetInsnArgumentsUsed(const MachineInsn* insn, RegUsageBitSet& is_reg_used) {
+void SetInsnArgumentsUsed(const berberis::MachineInsn* insn, RegUsageBitSet& is_reg_used) {
   for (int i = 0; i < insn->NumRegOperands(); ++i) {
     if (insn->RegKindAt(i).IsUse()) {
       is_reg_used.Set(insn->RegAt(i));
@@ -102,7 +102,7 @@ void RemoveDeadCode(MachineIR* machine_ir) {
 
     // Go from end to begin removing all unused instructions.
     for (auto insn_it = bb->insn_list().rbegin(); insn_it != bb->insn_list().rend();) {
-      MachineInsn* insn = *insn_it++;
+      berberis::MachineInsn* insn = *insn_it++;
 
       if (!insn->has_side_effects() && !AreResultsUsed(insn, is_reg_used)) {
         // Note non trivial way in which reverse_iterator is erased.
@@ -247,7 +247,7 @@ bool IsForwarderBlock(MachineBasicBlock* bb) {
     return false;
   }
 
-  const MachineInsn* last_insn = bb->insn_list().back();
+  const berberis::MachineInsn* last_insn = bb->insn_list().back();
   return last_insn->opcode() == PseudoBranch::kOpcode;
 }
 
diff --git a/backend/x86_64/machine_ir_opt_test.cc b/backend/x86_64/machine_ir_opt_test.cc
index 351df6a3..19e40b06 100644
--- a/backend/x86_64/machine_ir_opt_test.cc
+++ b/backend/x86_64/machine_ir_opt_test.cc
@@ -31,6 +31,10 @@ namespace berberis {
 
 namespace {
 
+constexpr auto kMachineRegRAX = x86_64::MachineRegs::kRAX;
+constexpr auto kMachineRegRCX = x86_64::MachineRegs::kRCX;
+constexpr auto kMachineRegRBX = x86_64::MachineRegs::kRBX;
+
 TEST(MachineIRRemoveDeadCodeTest, DefKilledByAnotherDef) {
   Arena arena;
   x86_64::MachineIR machine_ir(&arena);
@@ -73,7 +77,7 @@ TEST(MachineIRRemoveDeadCodeTest, RegUsedInSameBasicBlockNotErased) {
 
   builder.StartBasicBlock(bb);
   builder.Gen<x86_64::MovqRegImm>(vreg1, 4);
-  builder.Gen<x86_64::MovqMemBaseDispReg>(vreg2, 0, vreg1);
+  builder.Gen<x86_64::MovqOpReg>({.base = vreg2}, vreg1);
   builder.Gen<PseudoBranch>(bb);
 
   bb->live_out().push_back(vreg1);
@@ -213,7 +217,7 @@ TEST(MachineIRRemoveDeadCodeTest, HardRegisterAccess) {
   x86_64::MachineIRBuilder builder(&machine_ir);
 
   builder.StartBasicBlock(bb);
-  builder.Gen<x86_64::AddbRegImm>(x86_64::kMachineRegRAX, 3, x86_64::kMachineRegFLAGS);
+  builder.Gen<x86_64::AddbRegImm>(kMachineRegRAX, 3, x86_64::kMachineRegFLAGS);
   builder.Gen<PseudoBranch>(bb);
 
   x86_64::RemoveDeadCode(&machine_ir);
@@ -545,7 +549,7 @@ TEST(MachineIR, ForwardingPseudoBranch) {
   machine_ir.AddEdge(bb1, bb2);
 
   builder.StartBasicBlock(bb0);
-  builder.Gen<x86_64::MovlRegImm>(x86_64::kMachineRegRAX, 23);
+  builder.Gen<x86_64::MovlRegImm>(kMachineRegRAX, 23);
   builder.Gen<PseudoBranch>(bb1);
 
   // Create a forwarder block
@@ -611,7 +615,7 @@ TEST(MachineIR, ForwardingPseudoCondBranchThen) {
   builder.Gen<PseudoBranch>(bb2);
 
   builder.StartBasicBlock(bb2);
-  builder.Gen<x86_64::MovlRegImm>(x86_64::kMachineRegRAX, 23);
+  builder.Gen<x86_64::MovlRegImm>(kMachineRegRAX, 23);
   builder.Gen<PseudoBranch>(bb3);
 
   builder.StartBasicBlock(bb3);
@@ -672,7 +676,7 @@ TEST(MachineIR, ForwardingPseudoCondBranchElse) {
   builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb1, bb2, x86_64::kMachineRegFLAGS);
 
   builder.StartBasicBlock(bb1);
-  builder.Gen<x86_64::MovlRegImm>(x86_64::kMachineRegRAX, 23);
+  builder.Gen<x86_64::MovlRegImm>(kMachineRegRAX, 23);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   // Create a forwarder block
@@ -731,7 +735,7 @@ TEST(MachineIR, EntryForwarderIsNotRemoved) {
 
   // Create a forwarder block
   builder.StartBasicBlock(bb1);
-  builder.Gen<x86_64::MovlRegImm>(x86_64::kMachineRegRAX, 29);
+  builder.Gen<x86_64::MovlRegImm>(kMachineRegRAX, 29);
   builder.Gen<PseudoBranch>(bb2);
 
   builder.StartBasicBlock(bb2);
@@ -876,13 +880,13 @@ TEST(MachineIR, RemoveConsecutiveForwarderBlocks) {
   builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb1, bb3, x86_64::kMachineRegFLAGS);
 
   builder.StartBasicBlock(bb1);
-  builder.Gen<x86_64::MovlRegImm>(x86_64::kMachineRegRAX, 23);
+  builder.Gen<x86_64::MovlRegImm>(kMachineRegRAX, 23);
   builder.Gen<PseudoBranch>(bb2);
 
   // Create a forwarder block.
   builder.StartBasicBlock(bb2);
-  builder.Gen<PseudoCopy>(x86_64::kMachineRegRAX, x86_64::kMachineRegRAX, 4);
-  builder.Gen<PseudoCopy>(x86_64::kMachineRegRBX, x86_64::kMachineRegRBX, 4);
+  builder.Gen<PseudoCopy>(kMachineRegRAX, kMachineRegRAX, 4);
+  builder.Gen<PseudoCopy>(kMachineRegRBX, kMachineRegRBX, 4);
   builder.Gen<PseudoBranch>(bb3);
 
   // Create another forwarder block.
@@ -890,7 +894,7 @@ TEST(MachineIR, RemoveConsecutiveForwarderBlocks) {
   builder.Gen<PseudoBranch>(bb4);
 
   builder.StartBasicBlock(bb4);
-  builder.Gen<x86_64::MovlRegImm>(x86_64::kMachineRegRBX, 7);
+  builder.Gen<x86_64::MovlRegImm>(kMachineRegRBX, 7);
   builder.Gen<PseudoBranch>(bb5);
 
   builder.StartBasicBlock(bb5);
@@ -946,8 +950,8 @@ TEST(MachineIR, RemoveNopPseudoCopy) {
   x86_64::MachineIRBuilder builder(&machine_ir);
 
   builder.StartBasicBlock(bb0);
-  builder.Gen<PseudoCopy>(x86_64::kMachineRegRAX, x86_64::kMachineRegRAX, 4);
-  builder.Gen<PseudoCopy>(x86_64::kMachineRegRBX, x86_64::kMachineRegRCX, 4);
+  builder.Gen<PseudoCopy>(kMachineRegRAX, kMachineRegRAX, 4);
+  builder.Gen<PseudoCopy>(kMachineRegRBX, kMachineRegRCX, 4);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   EXPECT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
@@ -967,8 +971,8 @@ TEST(MachineIR, RemoveNopPseudoCopy) {
   // to EBX.
   MachineInsn* insn0 = *insn_it;
   EXPECT_EQ(kMachineOpPseudoCopy, insn0->opcode());
-  EXPECT_EQ(x86_64::kMachineRegRBX, insn0->RegAt(0));
-  EXPECT_EQ(x86_64::kMachineRegRCX, insn0->RegAt(1));
+  EXPECT_EQ(kMachineRegRBX, insn0->RegAt(0));
+  EXPECT_EQ(kMachineRegRCX, insn0->RegAt(1));
 
   // Verify that the next instruction is PseudoJump.
   MachineInsn* insn1 = *(++insn_it);
diff --git a/backend/x86_64/machine_ir_test_corpus.cc b/backend/x86_64/machine_ir_test_corpus.cc
index dbf445fc..3c6a162f 100644
--- a/backend/x86_64/machine_ir_test_corpus.cc
+++ b/backend/x86_64/machine_ir_test_corpus.cc
@@ -19,13 +19,14 @@
 #include <tuple>
 
 #include "berberis/backend/code_emitter.h"
-#include "berberis/backend/common/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir_builder.h"
 #include "berberis/guest_state/guest_addr.h"
 
 namespace berberis {
 
+constexpr auto kMachineRegRAX = x86_64::MachineRegs::kRAX;
+
 std::tuple<const MachineBasicBlock*,
            const MachineBasicBlock*,
            const MachineBasicBlock*,
@@ -49,11 +50,11 @@ BuildDataFlowAcrossBasicBlocks(x86_64::MachineIR* machine_ir) {
   builder.Gen<PseudoBranch>(bb2);
 
   builder.StartBasicBlock(bb2);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg2);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg2);
   builder.Gen<PseudoBranch>(bb3);
 
   builder.StartBasicBlock(bb3);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg1);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg1);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   return {bb1, bb2, bb3, vreg1, vreg2};
@@ -84,7 +85,7 @@ BuildDataFlowFromTwoPreds(x86_64::MachineIR* machine_ir) {
   builder.Gen<PseudoBranch>(bb3);
 
   builder.StartBasicBlock(bb3);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   return {bb1, bb2, bb3, vreg};
@@ -111,11 +112,11 @@ BuildDataFlowToTwoSuccs(x86_64::MachineIR* machine_ir) {
   builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb2, bb3, x86_64::kMachineRegFLAGS);
 
   builder.StartBasicBlock(bb2);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   builder.StartBasicBlock(bb3);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   return {bb1, bb2, bb3, vreg};
@@ -199,7 +200,7 @@ BuildDataFlowAcrossEmptyLoop(x86_64::MachineIR* machine_ir) {
   builder.Gen<PseudoBranch>(bb2);
 
   builder.StartBasicBlock(bb4);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   return {bb1, bb2, bb3, bb4, vreg};
diff --git a/backend/x86_64/read_flags_optimizer.cc b/backend/x86_64/read_flags_optimizer.cc
index 9196c105..0b0b956e 100644
--- a/backend/x86_64/read_flags_optimizer.cc
+++ b/backend/x86_64/read_flags_optimizer.cc
@@ -16,11 +16,12 @@
 
 #include "berberis/backend/x86_64/read_flags_optimizer.h"
 
+#include <iterator>
 #include <optional>
 
-#include "berberis/backend/common/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/base/algorithm.h"
+#include "berberis/base/arena_set.h"
 #include "berberis/base/arena_vector.h"
 
 namespace berberis::x86_64 {
@@ -30,7 +31,7 @@ namespace berberis::x86_64 {
 // Returns true iff we reach the end without encountering any uses of regs.
 bool CheckRegsUnusedWithinInsnRange(MachineInsnList::iterator insn_it,
                                     MachineInsnList::iterator end,
-                                    ArenaVector<MachineReg>& regs) {
+                                    MachineRegVector& regs) {
   for (; insn_it != end; ++insn_it) {
     for (auto i = 0; i < (*insn_it)->NumRegOperands(); i++) {
       if (Contains(regs, (*insn_it)->RegAt(i))) {
@@ -54,7 +55,7 @@ bool CheckRegsUnusedWithinInsnRange(MachineInsnList::iterator insn_it,
 //   original node with readflags instruction
 //
 // Returns true iff this node doesn't stop us from using the optimization.
-bool CheckSuccessorNode(Loop* loop, MachineBasicBlock* bb, ArenaVector<MachineReg>& regs) {
+bool CheckSuccessorNode(Loop* loop, MachineBasicBlock* bb, MachineRegVector& regs) {
   // If the node doesn't actually use any of regs we can just skip it.
   if (!RegsLiveInBasicBlock(bb, regs)) {
     return true;
@@ -103,7 +104,9 @@ bool CheckSuccessorNode(Loop* loop, MachineBasicBlock* bb, ArenaVector<MachineRe
 // * the node must have only one in_edge - this guarantees the register is coming
 // from the readflags
 // * nothing in regs should be in live_out
-bool CheckPostLoopNode(MachineBasicBlock* bb, const ArenaVector<MachineReg>& regs) {
+// * does not redefine registers in regs - this simplifies the logic of figuring out when to
+// insert instructions (see b/417321580 for more context)
+bool CheckPostLoopNode(MachineBasicBlock* bb, const MachineRegVector& regs) {
   // If the node doesn't actually use any of regs we can just skip it.
   if (!RegsLiveInBasicBlock(bb, regs)) {
     return true;
@@ -119,11 +122,20 @@ bool CheckPostLoopNode(MachineBasicBlock* bb, const ArenaVector<MachineReg>& reg
       return false;
     }
   }
+
+  for (auto insn : bb->insn_list()) {
+    for (int i = 0; i < insn->NumRegOperands(); i++) {
+      if (Contains(regs, insn->RegAt(i)) && insn->RegKindAt(i).IsDef()) {
+        return false;
+      }
+    }
+  }
+
   return true;
 }
 
 // Checks if anything in regs is in bb->live_in().
-bool RegsLiveInBasicBlock(MachineBasicBlock* bb, const ArenaVector<MachineReg>& regs) {
+bool RegsLiveInBasicBlock(MachineBasicBlock* bb, const MachineRegVector& regs) {
   for (auto r : bb->live_in()) {
     if (Contains(regs, r)) {
       return true;
@@ -133,10 +145,15 @@ bool RegsLiveInBasicBlock(MachineBasicBlock* bb, const ArenaVector<MachineReg>&
 }
 
 template <typename T>
-MachineInsn* CopyInstruction(MachineIR* machine_ir, MachineInsn* insn) {
+berberis::MachineInsn* CopyInstruction(MachineIR* machine_ir, berberis::MachineInsn* insn) {
   return machine_ir->NewInsn<T>(*static_cast<T*>(insn));
 }
 
+template <template <typename> typename T>
+berberis::MachineInsn* CopyInstruction(MachineIR* machine_ir, berberis::MachineInsn* insn) {
+  return machine_ir->NewInsn<T>(*static_cast<MachineIR::MachineInsnType<T>*>(insn));
+}
+
 std::optional<InsnGenerator> GetInsnGen(MachineOpcode opcode) {
   switch (opcode) {
     case kMachineOpAddqRegReg:
@@ -164,21 +181,338 @@ std::optional<InsnGenerator> GetInsnGen(MachineOpcode opcode) {
   }
 }
 
+// Finds all read flags we can optimize away and removes them.
+void RemoveEligibleReadFlagsInLoopTree(MachineIR* machine_ir, LoopTreeNode* loop_tree_node) {
+  if (loop_tree_node->NumInnerloops() > 0) {
+    // Remove from inner loops first.
+    for (size_t i = 0; i < loop_tree_node->NumInnerloops(); i++) {
+      RemoveEligibleReadFlagsInLoopTree(machine_ir, loop_tree_node->GetInnerloopNode(i));
+    }
+  }
+  auto loop = loop_tree_node->loop();
+  if (loop == nullptr) {
+    return;
+  }
+  // TODO(b/417284998): We could skip the nodes which were already scanned in inner loops.
+  for (auto* bb : *loop) {
+    for (auto insn_it = bb->insn_list().begin(); insn_it != bb->insn_list().end(); insn_it++) {
+      if (AsMachineInsnX86_64(*insn_it)->opcode() == kMachineOpPseudoReadFlags) {
+        auto flag_set_opt = IsEligibleReadFlag(machine_ir, loop, bb, insn_it);
+        if (flag_set_opt.has_value()) {
+          RemoveReadFlags(machine_ir, ReadFlagsOptContext{bb, insn_it, flag_set_opt.value()});
+        }
+      }
+    }
+  }
+}
+
 // Finds the instruction which sets a flag register.
 // insn_it should point to one past the element we first want to check
 // (typically it should point to the readflags instruction).
-std::optional<MachineInsnList::iterator> FindFlagSettingInsn(MachineInsnList::iterator insn_it,
-                                                             MachineInsnList::iterator begin,
-                                                             MachineReg reg) {
+std::optional<FlagSettingInsn> FindFlagSettingInsn(MachineInsnList::iterator insn_it,
+                                                   MachineInsnList::iterator begin,
+                                                   MachineReg reg) {
+  bool cmc = false;
   while (insn_it != begin) {
     insn_it--;
     for (int i = 0; i < (*insn_it)->NumRegOperands(); i++) {
       if ((*insn_it)->RegAt(i) == reg && (*insn_it)->RegKindAt(i).IsDef()) {
-        return insn_it;
+        if ((*insn_it)->opcode() == kMachineOpCmc) {
+          // CMC just inverts the carry flag so we still need to find what sets the original EFLAGS.
+          cmc = true;
+          // We need to go to the previous instruction, but since we know that CMC has just one
+          // operand simple "continue" here immediately exits the loop over operands.
+          continue;
+        }
+        return FlagSettingInsn{insn_it, cmc};
+      }
+    }
+  }
+  return std::nullopt;
+}
+
+void InsertFlagGenInstructions(MachineIR* machine_ir,
+                               ReadFlagsOptContext& context,
+                               MachineInsnList::iterator insn_it,
+                               const ArenaMap<MachineReg, MachineReg>& reg_map,
+                               MachineReg reg) {
+  auto flag_reg_used = NeedsToSaveFlags(context.bb, insn_it);
+  MachineReg flag_copy;
+  if (flag_reg_used.has_value()) {
+    flag_copy = machine_ir->AllocVReg();
+    context.bb->insn_list().insert(
+        insn_it,
+        machine_ir->NewInsn<PseudoReadFlags>(
+            PseudoReadFlags::kWithOverflow, flag_copy, flag_reg_used.value()));
+  }
+  MachineReg flag_reg;
+  // First add instruction that sets flags register.
+  auto insn_opt = GetInsnGen((*context.flag_set_insn.insn)->opcode());
+  CHECK(insn_opt.has_value());
+  auto insn = insn_opt.value()(machine_ir, *context.flag_set_insn.insn);
+  for (int i = 0; i < insn->NumRegOperands(); i++) {
+    if (insn->RegKindAt(i).IsInput()) {
+      CHECK(reg_map.contains(insn->RegAt(i)));
+      MachineReg input_reg;
+      if (insn->RegKindAt(i).IsDef()) {
+        // If it gets overwritten by the instruction, we need to make a new copy.
+        input_reg = machine_ir->AllocVReg();
+        context.bb->insn_list().insert(
+            insn_it, machine_ir->NewInsn<PseudoCopy>(input_reg, reg_map.at(insn->RegAt(i)), 8));
+      } else {
+        // if it's not def we can just reuse the copy from before.
+        input_reg = reg_map.at(insn->RegAt(i));
+      }
+      insn->SetRegAt(i, input_reg);
+    } else {
+      // Allocate new registers for non-input as original ones are
+      // probably not in scope.
+      insn->SetRegAt(i, machine_ir->AllocVReg());
+      if (insn->RegKindAt(i).RegClass()->IsSubsetOf(&kFLAGS)) {
+        // Save the flag register to set PSEUDO_READFLAGS.
+        flag_reg = insn->RegAt(i);
+      }
+    }
+  }
+  CHECK(!flag_reg.IsInvalidReg());
+  context.bb->insn_list().insert(insn_it, insn);
+  if (context.flag_set_insn.cmc) {
+    context.bb->insn_list().insert(insn_it, machine_ir->NewInsn<Cmc>(flag_reg));
+  }
+
+  // Now add readflags instruction.
+  insn =
+      GetInsnGen((*context.readflags_insn)->opcode()).value()(machine_ir, *context.readflags_insn);
+  insn->SetRegAt(0, reg);
+  insn->SetRegAt(1, flag_reg);
+  context.bb->insn_list().insert(insn_it, insn);
+
+  if (flag_reg_used.has_value()) {
+    context.bb->insn_list().insert(
+        insn_it, machine_ir->NewInsn<PseudoWriteFlags>(flag_copy, flag_reg_used.value()));
+  }
+}
+
+// Given an iterator that points to a READFLAGS instruction, checks if the
+// instruction can be optimized away.
+//
+// In the case we can't optimize it, we return std::nullopt. If we can optimize
+// it, we return an optional containing a pointer to the MachineInsn which set
+// the flag register which we would be reading.
+//
+// For now we only consider the common special case.
+// READFLAG is eligible to be removed if
+// * in loop
+// * register must not be used elsewhere in the loop
+// * lifetime of register should be limited to an exit node,
+//   post loop node, neighboring exit nodes, and post loop nodes of those
+//   neighbors
+//   * We can guarantee this via live_in and live_out properties
+//   * For post loop, neighbor exit nodes, and post loop nodes of
+//     those neighbors, only one in_edges
+//   * Register must not be live_in besides in the aforementioned nodes.
+//
+// As example of the allowed configuration
+//   (LOOP NODE) -> (READFLAG NODE) -> (POST LOOP NODE)
+//         ^             |
+//         |             v
+//   (LOOP NODE) <-  (EXIT NODE) ---> (NEIGHBOR'S POST LOOP NODE)
+std::optional<FlagSettingInsn> IsEligibleReadFlag(MachineIR* machine_ir,
+                                                  Loop* loop,
+                                                  MachineBasicBlock* bb,
+                                                  MachineInsnList::iterator insn_it) {
+  CHECK_EQ(AsMachineInsnX86_64(*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  auto flag_register = (*insn_it)->RegAt(1);
+  // We use a set here because the original register will be pseudocopy'd when
+  // used as live_out. So long as these new registers adhere to the same
+  // constraints this is fine.
+  MachineRegVector regs({(*insn_it)->RegAt(0)}, machine_ir->arena());
+  insn_it++;
+  if (!CheckRegsUnusedWithinInsnRange(insn_it, bb->insn_list().end(), regs)) {
+    return std::nullopt;
+  }
+
+  bool is_exit_node = false;
+  // Reached end of basic block, check neighbors.
+  for (auto edge : bb->out_edges()) {
+    if (Contains(*loop, edge->dst())) {
+      // Check if it's a neighbor exit node.
+      if (!CheckSuccessorNode(loop, edge->dst(), regs)) {
+        return std::nullopt;
+      }
+    } else {
+      is_exit_node = true;
+      // Check if it satisifes post loop node requirements.
+      if (!CheckPostLoopNode(edge->dst(), regs)) {
+        return std::nullopt;
+      }
+    }
+  }
+  if (!is_exit_node) {
+    return std::nullopt;
+  }
+
+  // Make sure we know how to copy this instruction.
+  auto flag_setter = FindFlagSettingInsn(insn_it, bb->insn_list().begin(), flag_register);
+  if (flag_setter.has_value() && GetInsnGen((*flag_setter.value().insn)->opcode()).has_value()) {
+    return flag_setter.value();
+  }
+  return std::nullopt;
+}
+
+// Check if we need to save the flag register because a later instruction uses it. If so, returns
+// the flag MachineReg that's used.
+std::optional<MachineReg> NeedsToSaveFlags(MachineBasicBlock* bb,
+                                           MachineInsnList::iterator insn_it) {
+  for (; insn_it != bb->insn_list().end(); ++insn_it) {
+    for (int i = 0; i < (*insn_it)->NumRegOperands(); i++) {
+      auto reg_kind = (*insn_it)->RegKindAt(i);
+      if (!reg_kind.RegClass()->IsSubsetOf(&kFLAGS)) {
+        continue;
+      }
+      if (reg_kind.IsInput()) {
+        return (*insn_it)->RegAt(i);
       }
+      // Instruction clobbers it so we don't need to worry about rest of instructions.
+      return std::nullopt;
     }
   }
+  // Host flags should never be live_out across basic blocks.
+  // It would be better to do a CHECK but currently there's no way to know
+  // whether a virtual register is a flag or not.
   return std::nullopt;
 }
 
+void OptimizeReadFlags(MachineIR* machine_ir) {
+  auto loop_tree = BuildLoopTree(machine_ir);
+  RemoveEligibleReadFlagsInLoopTree(machine_ir, loop_tree.root());
+}
+
+// Removes all elements of regs_to_remove from remove_from_regs. Returns true if anything was
+// removed.
+//
+// Note this ideally only be used for small vectors as it's O(n^2).
+bool RemoveRegs(MachineRegVector& remove_from_regs, const MachineRegVector& regs_to_remove) {
+  auto orig_size = remove_from_regs.size();
+  for (auto rit = remove_from_regs.rbegin(); rit != remove_from_regs.rend();
+       /* Incremented in loop */) {
+    if (Contains(regs_to_remove, *rit)) {
+      // erase only takes forward iterator so we create one from rit.
+      rit = EraseFromReverseIterator(remove_from_regs, rit);
+    } else {
+      rit++;
+    }
+  }
+  return orig_size != remove_from_regs.size();
+}
+
+// Removes the READFLAGS instruction, finds the instruction which generated the
+// flags, and creates copies of the registers.
+void RemoveReadFlags(MachineIR* machine_ir, ReadFlagsOptContext context) {
+  auto insn_it = context.readflags_insn;
+  auto flags_reg = (*insn_it)->RegAt(0);
+  MachineReg flags_register = (*insn_it)->RegAt(1);
+  // Delete READFLAGS instruction
+  context.bb->insn_list().erase(insn_it);
+
+  insn_it = context.flag_set_insn.insn;
+
+  berberis::MachineInsn* insn = *insn_it;
+
+  // Create copies of input registers.
+  ArenaMap<MachineReg, MachineReg> reg_map(machine_ir->arena());
+  for (int i = 0; i < insn->NumRegOperands(); i++) {
+    if (insn->RegKindAt(i).IsInput()) {
+      MachineReg copy = machine_ir->AllocVReg();
+      reg_map[insn->RegAt(i)] = copy;
+      context.bb->insn_list().insert(insn_it,
+                                     machine_ir->NewInsn<PseudoCopy>(copy, insn->RegAt(i), 8));
+    }
+  }
+
+  ArenaVector<MachineReg> reg_vec({flags_reg}, machine_ir->arena());
+  ReplaceFlagRegisters(
+      machine_ir, context, std::next(context.flag_set_insn.insn), reg_vec, reg_map, insn);
+}
+
+// Propagates the copied input registers, and regenerates the EFLAGs register if
+// we find an instruction that uses it. Updates live_in/live_out of blocks to
+// include copied input registers.
+//
+// Params:
+// * context - ReadFlagsOptContext generated from where the readflags
+// instruction was found.
+// * insn_it - iterator for MachineInsn in block for where we should begin
+// reading instructions. Should be begin() except when called from
+// RemoveReadFlags
+// * flags_regs - set of flags register and its PSEUDOCOPY's
+// * reg_map - the mapping from the original input registers to their copies
+// * insn - Original instruction which created the EFLAGS register.
+void ReplaceFlagRegisters(MachineIR* machine_ir,
+                          ReadFlagsOptContext context,
+                          MachineInsnList::iterator insn_it,
+                          MachineRegVector flags_regs,
+                          const ArenaMap<MachineReg, MachineReg>& reg_map,
+                          berberis::MachineInsn* insn) {
+  ArenaSet<MachineReg> used_flags{machine_ir->arena()};
+  while (insn_it != context.bb->insn_list().end()) {
+    if (AsMachineInsnX86_64(*insn_it)->opcode() == kMachineOpPseudoCopy &&
+        Contains(flags_regs, (*insn_it)->RegAt(1))) {
+      // If flags register was copied we add the copy to flags_regs and delete instruction.
+      flags_regs.push_back((*insn_it)->RegAt(0));
+      insn_it = context.bb->insn_list().erase(insn_it);
+      continue;
+    }
+    // Check if we use the register.
+    used_flags.clear();
+    for (int i = 0; i < (*insn_it)->NumRegOperands(); i++) {
+      if (Contains(flags_regs, (*insn_it)->RegAt(i))) {
+        used_flags.insert((*insn_it)->RegAt(i));
+      }
+    }
+    // Insert instructions for any flags we used.
+    for (auto reg : used_flags) {
+      InsertFlagGenInstructions(machine_ir, context, insn_it, reg_map, reg);
+    }
+    insn_it++;
+  }
+
+  // Add copied registers to live_in if needed.
+  for (auto reg : context.bb->live_in()) {
+    if (Contains(flags_regs, reg)) {
+      for (auto mapping : reg_map) {
+        context.bb->live_in().push_back(mapping.second);
+      }
+      break;
+    }
+  }
+
+  // Remove flags_regs from live_in and live_out.
+  RemoveRegs(context.bb->live_in(), flags_regs);
+  auto was_live_out = RemoveRegs(context.bb->live_out(), flags_regs);
+  // Update live_out with our copied input registers if flags_regs was in
+  // live_out.
+  if (was_live_out) {
+    for (auto mapping : reg_map) {
+      context.bb->live_out().push_back(mapping.second);
+    }
+  }
+
+  // Recurse on neighbors where flags registers are live_in.
+  for (auto* out_edge : context.bb->out_edges()) {
+    for (auto live_in_reg : out_edge->dst()->live_in()) {
+      if (Contains(flags_regs, live_in_reg)) {
+        ReplaceFlagRegisters(
+            machine_ir,
+            ReadFlagsOptContext{out_edge->dst(), context.readflags_insn, context.flag_set_insn},
+            out_edge->dst()->insn_list().begin(),
+            flags_regs,
+            reg_map,
+            insn);
+        break;
+      }
+    }
+  }
+}
+
 }  // namespace berberis::x86_64
diff --git a/backend/x86_64/read_flags_optimizer_test.cc b/backend/x86_64/read_flags_optimizer_test.cc
index 2b56e5ac..7f04aaa5 100644
--- a/backend/x86_64/read_flags_optimizer_test.cc
+++ b/backend/x86_64/read_flags_optimizer_test.cc
@@ -16,14 +16,15 @@
 
 #include "gtest/gtest.h"
 
-#include <tuple>
+#include <algorithm>
 
 #include "berberis/backend/x86_64/read_flags_optimizer.h"
 
-#include "berberis/backend/common/machine_ir.h"
+#include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir_analysis.h"
 #include "berberis/backend/x86_64/machine_ir_builder.h"
 #include "berberis/backend/x86_64/machine_ir_check.h"
+#include "berberis/base/algorithm.h"
 #include "berberis/base/arena_alloc.h"
 #include "berberis/base/arena_vector.h"
 
@@ -31,18 +32,39 @@ namespace berberis::x86_64 {
 
 namespace {
 
-std::tuple<MachineBasicBlock*, MachineBasicBlock*, MachineBasicBlock*, MachineBasicBlock*>
-BuildBasicLoop(MachineIR* machine_ir) {
+struct TestLoop {
+  MachineBasicBlock* preloop;
+  MachineBasicBlock* loop_head;
+  MachineBasicBlock* loop_exit;
+  MachineBasicBlock* postloop;
+  MachineBasicBlock* successor;
+  MachineBasicBlock* succ_postloop;
+  MachineReg flags_reg;
+  // Iterator which points to the READFLAGS instruction.
+  MachineInsnList::iterator readflags_it;
+};
+
+TestLoop BuildBasicLoop(MachineIR* machine_ir) {
   x86_64::MachineIRBuilder builder(machine_ir);
 
+  // bb0 -> bb1 -> bb2 -> bb3
+  //         ^       |
+  //         |----- bb4 -> bb5
   auto bb0 = machine_ir->NewBasicBlock();
   auto bb1 = machine_ir->NewBasicBlock();
   auto bb2 = machine_ir->NewBasicBlock();
   auto bb3 = machine_ir->NewBasicBlock();
+  auto bb4 = machine_ir->NewBasicBlock();
+  auto bb5 = machine_ir->NewBasicBlock();
   machine_ir->AddEdge(bb0, bb1);
   machine_ir->AddEdge(bb1, bb2);
-  machine_ir->AddEdge(bb2, bb1);
   machine_ir->AddEdge(bb2, bb3);
+  machine_ir->AddEdge(bb2, bb4);
+  machine_ir->AddEdge(bb4, bb1);
+  machine_ir->AddEdge(bb4, bb5);
+
+  auto flags0 = machine_ir->AllocVReg();
+  auto flags1 = machine_ir->AllocVReg();
 
   builder.StartBasicBlock(bb0);
   builder.Gen<PseudoBranch>(bb1);
@@ -50,12 +72,25 @@ BuildBasicLoop(MachineIR* machine_ir) {
   builder.Gen<PseudoBranch>(bb2);
 
   builder.StartBasicBlock(bb2);
-  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb1, bb3, kMachineRegFLAGS);
+  builder.Gen<AddqRegReg>(machine_ir->AllocVReg(), machine_ir->AllocVReg(), kMachineRegFLAGS);
+  builder.Gen<PseudoReadFlags>(PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS);
+  builder.Gen<PseudoCopy>(flags1, flags0, 8);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb3, bb4, kMachineRegFLAGS);
+  bb2->live_out().push_back(flags1);
 
   builder.StartBasicBlock(bb3);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
-  return {bb0, bb1, bb2, bb3};
+  builder.StartBasicBlock(bb4);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb1, bb5, kMachineRegFLAGS);
+
+  builder.StartBasicBlock(bb5);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  auto insn_it = std::next(bb2->insn_list().begin());
+  CHECK_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+
+  return {bb0, bb1, bb2, bb3, bb4, bb5, flags1, insn_it};
 }
 
 TEST(MachineIRReadFlagsOptimizer, CheckRegsUnusedWithinInsnRangeAddsReg) {
@@ -65,7 +100,7 @@ TEST(MachineIRReadFlagsOptimizer, CheckRegsUnusedWithinInsnRangeAddsReg) {
 
   MachineReg flags0 = machine_ir.AllocVReg();
   MachineReg flags1 = machine_ir.AllocVReg();
-  ArenaVector<MachineReg> regs({flags0}, machine_ir.arena());
+  MachineRegVector regs({flags0}, machine_ir.arena());
 
   auto bb0 = machine_ir.NewBasicBlock();
   auto bb1 = machine_ir.NewBasicBlock();
@@ -99,8 +134,8 @@ TEST(MachineIRReadFlagsOptimizer, CheckRegsUnusedWithinInsnRange) {
 
   MachineReg flags0 = machine_ir.AllocVReg();
   MachineReg flags1 = machine_ir.AllocVReg();
-  ArenaVector<MachineReg> regs0({flags0}, machine_ir.arena());
-  ArenaVector<MachineReg> regs1({flags1}, machine_ir.arena());
+  MachineRegVector regs0({flags0}, machine_ir.arena());
+  MachineRegVector regs1({flags1}, machine_ir.arena());
 
   auto bb0 = machine_ir.NewBasicBlock();
 
@@ -115,6 +150,26 @@ TEST(MachineIRReadFlagsOptimizer, CheckRegsUnusedWithinInsnRange) {
   ASSERT_EQ(regs0.size(), 1UL);
 }
 
+TEST(MachineIRReadFlagsOptimizer, CheckPostLoopChecksRedefines) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags = machine_ir.AllocVReg();
+  MachineRegVector regs({flags}, machine_ir.arena());
+
+  auto bb0 = machine_ir.NewBasicBlock();
+
+  bb0->live_in().push_back(flags);
+  builder.StartBasicBlock(bb0);
+  builder.Gen<x86_64::AddqRegReg>(flags, flags, kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  ASSERT_FALSE(CheckPostLoopNode(bb0, regs));
+}
+
 TEST(MachineIRReadFlagsOptimizer, CheckPostLoopNodeLifetime) {
   Arena arena;
   x86_64::MachineIR machine_ir(&arena);
@@ -122,7 +177,7 @@ TEST(MachineIRReadFlagsOptimizer, CheckPostLoopNodeLifetime) {
 
   MachineReg flags = machine_ir.AllocVReg();
   MachineReg flags_copy = machine_ir.AllocVReg();
-  ArenaVector<MachineReg> regs({flags, flags_copy}, machine_ir.arena());
+  MachineRegVector regs({flags, flags_copy}, machine_ir.arena());
 
   auto bb0 = machine_ir.NewBasicBlock();
   auto bb1 = machine_ir.NewBasicBlock();
@@ -134,7 +189,7 @@ TEST(MachineIRReadFlagsOptimizer, CheckPostLoopNodeLifetime) {
   builder.Gen<PseudoBranch>(bb1);
 
   builder.StartBasicBlock(bb1);
-  builder.Gen<x86_64::AddqRegReg>(flags_copy, flags_copy, kMachineRegFLAGS);
+  builder.Gen<x86_64::AddqRegReg>(machine_ir.AllocVReg(), flags_copy, kMachineRegFLAGS);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
@@ -154,7 +209,7 @@ TEST(MachineIRReadFlagsOptimizer, CheckPostLoopNodeLiveIn) {
   x86_64::MachineIRBuilder builder(&machine_ir);
 
   MachineReg flags = machine_ir.AllocVReg();
-  ArenaVector<MachineReg> regs({flags}, machine_ir.arena());
+  MachineRegVector regs({flags}, machine_ir.arena());
 
   auto bb0 = machine_ir.NewBasicBlock();
   auto bb1 = machine_ir.NewBasicBlock();
@@ -178,7 +233,7 @@ TEST(MachineIRReadFlagsOptimizer, CheckPostLoopNodeInEdges) {
   x86_64::MachineIRBuilder builder(&machine_ir);
 
   MachineReg flags = machine_ir.AllocVReg();
-  ArenaVector<MachineReg> regs({flags}, machine_ir.arena());
+  MachineRegVector regs({flags}, machine_ir.arena());
 
   auto bb0 = machine_ir.NewBasicBlock();
   auto bb1 = machine_ir.NewBasicBlock();
@@ -199,18 +254,18 @@ TEST(MachineIRReadFlagsOptimizer, CheckSuccessorNodeFailsIfUsingRegisters) {
   x86_64::MachineIRBuilder builder(&machine_ir);
 
   MachineReg flags = machine_ir.AllocVReg();
-  ArenaVector<MachineReg> regs({flags}, machine_ir.arena());
+  MachineRegVector regs({flags}, machine_ir.arena());
 
-  auto [preloop, loop_head, loop_exit, postloop] = BuildBasicLoop(&machine_ir);
-  loop_exit->live_in().push_back(flags);
-  loop_exit->insn_list().insert(loop_exit->insn_list().begin(),
-                                machine_ir.NewInsn<MovqRegImm>(flags, 123));
+  auto testloop = BuildBasicLoop(&machine_ir);
+  testloop.loop_exit->live_in().push_back(flags);
+  testloop.loop_exit->insn_list().insert(testloop.loop_exit->insn_list().begin(),
+                                         machine_ir.NewInsn<MovqRegImm>(flags, 123));
 
   ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
 
   auto loop_tree = BuildLoopTree(&machine_ir);
   auto loop = loop_tree.root()->GetInnerloopNode(0)->loop();
-  ASSERT_FALSE(CheckSuccessorNode(loop, loop_exit, regs));
+  ASSERT_FALSE(CheckSuccessorNode(loop, testloop.loop_exit, regs));
 }
 
 TEST(MachineIRReadFlagsOptimizer, CheckSuccessorNodeFailsIfNotExit) {
@@ -219,7 +274,7 @@ TEST(MachineIRReadFlagsOptimizer, CheckSuccessorNodeFailsIfNotExit) {
   x86_64::MachineIRBuilder builder(&machine_ir);
 
   MachineReg flags = machine_ir.AllocVReg();
-  ArenaVector<MachineReg> regs({flags}, machine_ir.arena());
+  MachineRegVector regs({flags}, machine_ir.arena());
 
   auto bb0 = machine_ir.NewBasicBlock();
   auto bb1 = machine_ir.NewBasicBlock();
@@ -240,6 +295,7 @@ TEST(MachineIRReadFlagsOptimizer, CheckSuccessorNodeFailsIfNotExit) {
 
   auto loop_tree = BuildLoopTree(&machine_ir);
   auto loop = loop_tree.root()->GetInnerloopNode(0)->loop();
+
   // Should fail because not an exit node.
   ASSERT_FALSE(CheckSuccessorNode(loop, bb2, regs));
 }
@@ -250,20 +306,17 @@ TEST(MachineIRReadFlagsOptimizer, CheckSuccessorNodeInEdges) {
   x86_64::MachineIR machine_ir(&arena);
   x86_64::MachineIRBuilder builder(&machine_ir);
 
-  MachineReg flags = machine_ir.AllocVReg();
-  ArenaVector<MachineReg> regs({flags}, machine_ir.arena());
-
-  auto [preloop, loop_head, loop_exit, postloop] = BuildBasicLoop(&machine_ir);
-
+  auto testloop = BuildBasicLoop(&machine_ir);
   auto loop_tree = BuildLoopTree(&machine_ir);
   auto loop = loop_tree.root()->GetInnerloopNode(0)->loop();
+  MachineRegVector regs({testloop.flags_reg}, machine_ir.arena());
 
   ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
 
-  loop_exit->live_in().push_back(flags);
-  ASSERT_TRUE(CheckSuccessorNode(loop, loop_exit, regs));
-  machine_ir.AddEdge(preloop, loop_exit);
-  ASSERT_FALSE(CheckSuccessorNode(loop, loop_exit, regs));
+  testloop.successor->live_in().push_back(testloop.flags_reg);
+  ASSERT_TRUE(CheckSuccessorNode(loop, testloop.successor, regs));
+  machine_ir.AddEdge(testloop.preloop, testloop.successor);
+  ASSERT_FALSE(CheckSuccessorNode(loop, testloop.successor, regs));
 }
 
 // regs should not be live_in to other loop nodes.
@@ -274,41 +327,39 @@ TEST(MachineIRReadFlagsOptimizer, CheckSuccessorNodeLiveIn) {
 
   MachineReg flags0 = machine_ir.AllocVReg();
   MachineReg flags1 = machine_ir.AllocVReg();
-  ArenaVector<MachineReg> regs({flags0}, machine_ir.arena());
-
-  auto [preloop, loop_head, loop_exit, postloop] = BuildBasicLoop(&machine_ir);
-
-  loop_exit->live_in().push_back(flags0);
+  MachineRegVector regs({flags0}, machine_ir.arena());
 
-  loop_exit->insn_list().insert(loop_exit->insn_list().begin(),
-                                machine_ir.NewInsn<PseudoCopy>(flags1, flags0, 8));
+  auto testloop = BuildBasicLoop(&machine_ir);
 
-  postloop->live_in().push_back(flags1);
+  testloop.loop_exit->live_in().push_back(flags0);
+  testloop.loop_exit->insn_list().insert(testloop.loop_exit->insn_list().begin(),
+                                         machine_ir.NewInsn<PseudoCopy>(flags1, flags0, 8));
 
+  testloop.postloop->live_in().push_back(flags1);
   ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
 
   auto loop_tree = BuildLoopTree(&machine_ir);
   auto loop = loop_tree.root()->GetInnerloopNode(0)->loop();
 
-  ASSERT_TRUE(CheckSuccessorNode(loop, loop_exit, regs));
+  ASSERT_TRUE(CheckSuccessorNode(loop, testloop.loop_exit, regs));
   // Remove flags1.
   regs.pop_back();
 
   // Make sure we fail if flags0 is live_in of another loop node.
-  loop_head->live_in().push_back(flags0);
-  ASSERT_FALSE(CheckSuccessorNode(loop, loop_exit, regs));
+  testloop.successor->live_in().push_back(flags0);
+  ASSERT_FALSE(CheckSuccessorNode(loop, testloop.loop_exit, regs));
 
   // Reset state.
-  loop_head->live_in().pop_back();
+  testloop.successor->live_in().pop_back();
   regs.pop_back();
 
   // Make sure that we check live_in after CheckRegsUnusedWithinInsnRange.
-  loop_head->live_in().push_back(flags1);
-  ASSERT_FALSE(CheckSuccessorNode(loop, loop_exit, regs));
+  testloop.successor->live_in().push_back(flags1);
+  ASSERT_FALSE(CheckSuccessorNode(loop, testloop.loop_exit, regs));
 }
 
 // Helper function to check that two instructions are the same.
-void TestCopiedInstruction(MachineIR* machine_ir, MachineInsn* insn) {
+void TestCopiedInstruction(MachineIR* machine_ir, berberis::MachineInsn* insn) {
   MachineReg reg = machine_ir->AllocVReg();
 
   auto gen = GetInsnGen(insn->opcode());
@@ -343,6 +394,223 @@ TEST(MachineIRReadFlagsOptimizer, GetInsnGen) {
           PseudoReadFlags::kWithOverflow, machine_ir.AllocVReg(), kMachineRegFLAGS));
 }
 
+TEST(MachineIRReadFlagsOptimizer, InsertFlagGenInstructionsAddsCmc) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  auto flags0 = machine_ir.AllocVReg();
+  auto input0 = machine_ir.AllocVReg();
+  auto input1 = machine_ir.AllocVReg();
+
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<AddqRegReg>(input0, input1, kMachineRegFLAGS);
+  builder.Gen<Cmc>(kMachineRegFLAGS);
+  builder.Gen<PseudoReadFlags>(PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS);
+  builder.Gen<PseudoBranch>(bb1);
+
+  builder.StartBasicBlock(bb1);
+  builder.Gen<MovqRegReg>(flags0, flags0);
+
+  auto context = ReadFlagsOptContext{
+      bb1, std::next(bb0->insn_list().begin(), 2), FlagSettingInsn{bb0->insn_list().begin(), true}};
+  InsertFlagGenInstructions(
+      &machine_ir,
+      context,
+      bb1->insn_list().begin(),
+      ArenaMap<MachineReg, MachineReg>({{input0, input0}, {input1, input1}}, machine_ir.arena()),
+      flags0);
+
+  auto insn_it = bb1->insn_list().begin();
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+  auto flags_reg = (*insn_it)->RegAt(2);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpCmc);
+  ASSERT_EQ((*insn_it)->RegAt(0), flags_reg);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  ASSERT_EQ((*insn_it)->RegAt(1), flags_reg);
+  insn_it++;
+}
+
+TEST(MachineIRReadFlagsOptimizer, InsertFlagGenInstructionsSavesFlagReg) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  auto testloop = BuildBasicLoop(&machine_ir);
+
+  // register we save flags to in BuildBasicLoop.
+  auto flags = (*std::next(testloop.loop_exit->insn_list().begin()))->RegAt(0);
+  auto input0 = (*testloop.loop_exit->insn_list().begin())->RegAt(0);
+  auto input1 = (*testloop.loop_exit->insn_list().begin())->RegAt(1);
+
+  // Note the instructions are inserted in reverse order.
+  testloop.postloop->insn_list().push_front(machine_ir.NewInsn<PseudoReadFlags>(
+      PseudoReadFlags::kWithOverflow, machine_ir.AllocVReg(), kMachineRegFLAGS));
+  testloop.postloop->insn_list().push_front(machine_ir.NewInsn<MovqRegReg>(flags, flags));
+
+  auto context =
+      ReadFlagsOptContext{testloop.postloop,
+                          std::next(testloop.loop_exit->insn_list().begin()),
+                          FlagSettingInsn{testloop.loop_exit->insn_list().begin(), false}};
+  InsertFlagGenInstructions(
+      &machine_ir,
+      context,
+      testloop.postloop->insn_list().begin(),
+      ArenaMap<MachineReg, MachineReg>({{input0, input0}, {input1, input1}}, machine_ir.arena()),
+      flags);
+
+  // Check that read and write flags instructions inserted.
+  ASSERT_EQ((*testloop.postloop->insn_list().begin())->opcode(), kMachineOpPseudoReadFlags);
+  ASSERT_EQ((*std::next(testloop.postloop->insn_list().begin(), 4))->opcode(),
+            kMachineOpPseudoWriteFlags);
+
+  // Now test that we don't insert read/write flags when we don't need to.
+  testloop.postloop->insn_list().clear();
+  testloop.postloop->insn_list().push_front(machine_ir.NewInsn<PseudoJump>(kNullGuestAddr));
+  testloop.postloop->insn_list().push_front(machine_ir.NewInsn<MovqRegReg>(flags, flags));
+
+  InsertFlagGenInstructions(
+      &machine_ir,
+      context,
+      testloop.postloop->insn_list().begin(),
+      ArenaMap<MachineReg, MachineReg>({{input0, input0}, {input1, input1}}, machine_ir.arena()),
+      flags);
+
+  ASSERT_EQ((*testloop.postloop->insn_list().begin())->opcode(), kMachineOpPseudoCopy);
+}
+
+// Tests that IsEligibleReadFlags makes sure the flag register isn't used in the
+// exit node.
+TEST(MachineIRReadFlagsOptimizer, IsEligibleReadFlagChecksFlagsNotUsedInExitNode) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  auto testloop = BuildBasicLoop(&machine_ir);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+  auto loop_tree = BuildLoopTree(&machine_ir);
+  auto res = IsEligibleReadFlag(&machine_ir,
+                                loop_tree.root()->GetInnerloopNode(0)->loop(),
+                                testloop.loop_exit,
+                                testloop.readflags_it);
+  ASSERT_TRUE(res.has_value());
+
+  testloop.loop_exit->insn_list().push_back(
+      machine_ir.NewInsn<PseudoWriteFlags>(testloop.flags_reg, kMachineRegFLAGS));
+  res = IsEligibleReadFlag(&machine_ir,
+                           loop_tree.root()->GetInnerloopNode(0)->loop(),
+                           testloop.loop_exit,
+                           testloop.readflags_it);
+  ASSERT_FALSE(res.has_value());
+}
+
+// Tests that IsEligibleReadFlags checks post loop node.
+TEST(MachineIRReadFlagsOptimizer, IsEligibleReadFlagChecksPostloopNode) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  auto testloop = BuildBasicLoop(&machine_ir);
+  MachineReg flags_copy = machine_ir.AllocVReg();
+
+  testloop.postloop->live_in().push_back(testloop.flags_reg);
+  testloop.postloop->insn_list().push_front(
+      machine_ir.NewInsn<PseudoCopy>(flags_copy, testloop.flags_reg, 8));
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+  auto loop_tree = BuildLoopTree(&machine_ir);
+  auto res = IsEligibleReadFlag(&machine_ir,
+                                loop_tree.root()->GetInnerloopNode(0)->loop(),
+                                testloop.loop_exit,
+                                testloop.readflags_it);
+  ASSERT_TRUE(res.has_value());
+
+  // Make postloop node fail by having the copy be live_out.
+  testloop.postloop->live_out().push_back(testloop.flags_reg);
+  res = IsEligibleReadFlag(&machine_ir,
+                           loop_tree.root()->GetInnerloopNode(0)->loop(),
+                           testloop.loop_exit,
+                           testloop.readflags_it);
+  ASSERT_FALSE(res.has_value());
+}
+
+// Tests that IsEligibleReadFlags checks loop successor node.
+TEST(MachineIRReadFlagsOptimizer, IsEligibleReadFlagChecksSuccessorNode) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  auto testloop = BuildBasicLoop(&machine_ir);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+  auto loop_tree = BuildLoopTree(&machine_ir);
+  auto res = IsEligibleReadFlag(&machine_ir,
+                                loop_tree.root()->GetInnerloopNode(0)->loop(),
+                                testloop.loop_exit,
+                                testloop.readflags_it);
+  ASSERT_TRUE(res.has_value());
+
+  // Make successor fail by accessing the register.
+  testloop.successor->live_in().push_back(testloop.flags_reg);
+  testloop.successor->insn_list().push_front(
+      machine_ir.NewInsn<PseudoWriteFlags>(machine_ir.AllocVReg(), testloop.flags_reg));
+  res = IsEligibleReadFlag(&machine_ir,
+                           loop_tree.root()->GetInnerloopNode(0)->loop(),
+                           testloop.loop_exit,
+                           testloop.readflags_it);
+  ASSERT_FALSE(res.has_value());
+}
+
+// Tests that IsEligibleReadFlags checks successor's postloop node.
+TEST(MachineIRReadFlagsOptimizer, IsEligibleReadFlagChecksSuccPostLoopNode) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  auto testloop = BuildBasicLoop(&machine_ir);
+  MachineReg flags_copy = machine_ir.AllocVReg();
+
+  testloop.successor->live_in().push_back(testloop.flags_reg);
+  testloop.successor->insn_list().push_front(
+      machine_ir.NewInsn<PseudoCopy>(flags_copy, testloop.flags_reg, 8));
+  testloop.successor->live_out().push_back(flags_copy);
+  testloop.succ_postloop->live_in().push_back(flags_copy);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+  auto loop_tree = BuildLoopTree(&machine_ir);
+  auto res = IsEligibleReadFlag(&machine_ir,
+                                loop_tree.root()->GetInnerloopNode(0)->loop(),
+                                testloop.loop_exit,
+                                testloop.readflags_it);
+  ASSERT_TRUE(res.has_value());
+
+  // succ_postloop should fail if it lets flags_copy be live_out.
+  testloop.succ_postloop->live_out().push_back(flags_copy);
+  res = IsEligibleReadFlag(&machine_ir,
+                           loop_tree.root()->GetInnerloopNode(0)->loop(),
+                           testloop.loop_exit,
+                           testloop.readflags_it);
+  ASSERT_FALSE(res.has_value());
+}
+
+// Tests that IsEligibleReadFlags returns the right instruction.
+TEST(MachineIRReadFlagsOptimizer, IsEligibleReadFlagReturnsSetter) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  auto testloop = BuildBasicLoop(&machine_ir);
+  testloop.loop_exit->insn_list().push_front(
+      machine_ir.NewInsn<SubqRegImm>(machine_ir.AllocVReg(), 121, testloop.flags_reg));
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+  auto loop_tree = BuildLoopTree(&machine_ir);
+
+  auto insn_it = std::next(testloop.loop_exit->insn_list().begin(), 2);
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  auto res = IsEligibleReadFlag(
+      &machine_ir, loop_tree.root()->GetInnerloopNode(0)->loop(), testloop.loop_exit, insn_it);
+  ASSERT_TRUE(res.has_value());
+  ASSERT_EQ((*res.value().insn)->opcode(), kMachineOpAddqRegReg);
+}
+
 TEST(MachineIRReadFlagsOptimizer, FindFlagSettingInsn) {
   Arena arena;
   x86_64::MachineIR machine_ir(&arena);
@@ -370,7 +638,7 @@ TEST(MachineIRReadFlagsOptimizer, FindFlagSettingInsn) {
 
   auto flag_setter = FindFlagSettingInsn(insn_it, bb->insn_list().begin(), flags0);
   ASSERT_TRUE(flag_setter.has_value());
-  ASSERT_EQ((*flag_setter.value())->opcode(), kMachineOpSubqRegImm);
+  ASSERT_EQ((*flag_setter.value().insn)->opcode(), kMachineOpSubqRegImm);
 
   // Test that we exit properly when we can't find the instruction.
   // Move to second AddqRegReg.
@@ -379,6 +647,716 @@ TEST(MachineIRReadFlagsOptimizer, FindFlagSettingInsn) {
   ASSERT_FALSE(flag_setter.has_value());
 }
 
+TEST(MachineIRReadFlagsOptimizer, FindFlagSettingInsnSetsCmc) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  auto bb = machine_ir.NewBasicBlock();
+  builder.StartBasicBlock(bb);
+  builder.Gen<AddqRegReg>(machine_ir.AllocVReg(), machine_ir.AllocVReg(), kMachineRegFLAGS);
+  builder.Gen<Cmc>(kMachineRegFLAGS);
+  builder.Gen<PseudoReadFlags>(
+      PseudoReadFlags::kWithOverflow, machine_ir.AllocVReg(), kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  auto flag_setter = FindFlagSettingInsn(
+      std::next(bb->insn_list().begin(), 2), bb->insn_list().begin(), kMachineRegFLAGS);
+  ASSERT_TRUE(flag_setter.has_value());
+  ASSERT_TRUE(flag_setter.value().cmc);
+}
+
+TEST(MachineIRReadFlagsOptimizer, NeedsToSaveFlags) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  // Not used so shouldn't need to save.
+  auto bb0 = machine_ir.NewBasicBlock();
+  builder.StartBasicBlock(bb0);
+  builder.Gen<MovqRegReg>(machine_ir.AllocVReg(), machine_ir.AllocVReg());
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+  ASSERT_FALSE(NeedsToSaveFlags(bb0, bb0->insn_list().begin()).has_value());
+
+  // Flags are read so should be saved.
+  auto bb1 = machine_ir.NewBasicBlock();
+  builder.StartBasicBlock(bb1);
+  builder.Gen<MovqRegReg>(machine_ir.AllocVReg(), machine_ir.AllocVReg());
+  builder.Gen<PseudoReadFlags>(
+      PseudoReadFlags::kWithOverflow, machine_ir.AllocVReg(), kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+  ASSERT_EQ(NeedsToSaveFlags(bb1, bb1->insn_list().begin()).value(), kMachineRegFLAGS);
+
+  // Flags used but clobbered beforehand so shouldn't need to be saved.
+  auto bb2 = machine_ir.NewBasicBlock();
+  builder.StartBasicBlock(bb2);
+  builder.Gen<MovqRegReg>(machine_ir.AllocVReg(), machine_ir.AllocVReg());
+  builder.Gen<SubqRegImm>(machine_ir.AllocVReg(), 1, kMachineRegFLAGS);
+  builder.Gen<PseudoReadFlags>(
+      PseudoReadFlags::kWithOverflow, machine_ir.AllocVReg(), kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+  ASSERT_FALSE(NeedsToSaveFlags(bb2, bb2->insn_list().begin()).has_value());
+}
+
+TEST(MachineIRReadFlagsOptimizer, RemoveEligibleReadFlagsInLoopTree) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg scratch = machine_ir.AllocVReg();
+  // flags0 used to test whether we remove from outer loops.
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags00 = machine_ir.AllocVReg();
+  // flags1 used to test whether we remove from inner loop.
+  MachineReg flags1 = machine_ir.AllocVReg();
+  MachineReg flags11 = machine_ir.AllocVReg();
+
+  //         |-------|
+  // bb0 -> bb1 --> bb2 <-> bb3 -> bb4
+  //         |
+  //        bb5
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  auto bb2 = machine_ir.NewBasicBlock();
+  auto bb3 = machine_ir.NewBasicBlock();
+  auto bb4 = machine_ir.NewBasicBlock();
+  auto bb5 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+  machine_ir.AddEdge(bb1, bb2);
+  machine_ir.AddEdge(bb1, bb5);
+  machine_ir.AddEdge(bb2, bb1);
+  machine_ir.AddEdge(bb2, bb3);
+  machine_ir.AddEdge(bb3, bb2);
+  machine_ir.AddEdge(bb3, bb4);
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<PseudoBranch>(bb1);
+
+  builder.StartBasicBlock(bb1);
+  builder.Gen<x86_64::AddqRegReg>(scratch, scratch, kMachineRegFLAGS);
+  builder.Gen<PseudoReadFlags>(PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS);
+  builder.Gen<PseudoCopy>(flags00, flags0, 8);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb2, bb5, kMachineRegFLAGS);
+  bb1->live_out().push_back(flags00);
+
+  builder.StartBasicBlock(bb2);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb1, bb3, kMachineRegFLAGS);
+
+  builder.StartBasicBlock(bb3);
+  builder.Gen<x86_64::AddqRegReg>(scratch, scratch, kMachineRegFLAGS);
+  builder.Gen<PseudoReadFlags>(PseudoReadFlags::kWithOverflow, flags1, kMachineRegFLAGS);
+  builder.Gen<PseudoCopy>(flags11, flags1, 8);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb2, bb4, kMachineRegFLAGS);
+  bb3->live_out().push_back(flags11);
+
+  builder.StartBasicBlock(bb4);
+  builder.Gen<x86_64::AddqRegReg>(machine_ir.AllocVReg(), flags11, kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+  bb4->live_in().push_back(flags11);
+
+  builder.StartBasicBlock(bb5);
+  builder.Gen<x86_64::AddqRegReg>(machine_ir.AllocVReg(), flags00, kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+  bb5->live_in().push_back(flags00);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+  auto loop_tree = BuildLoopTree(&machine_ir);
+  RemoveEligibleReadFlagsInLoopTree(&machine_ir, loop_tree.root());
+
+  // flags0 should be removed if we correctly optimize outer loops.
+  auto insn_it = std::next(bb1->insn_list().begin());
+  ASSERT_NE((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+
+  // pseudoreadflags flags1 should be removed.
+  insn_it = std::next(bb3->insn_list().begin());
+  ASSERT_NE((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+
+  // Check that bb4 and bb5 have the correct instructions added.
+  insn_it = bb4->insn_list().begin();
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+
+  insn_it = bb5->insn_list().begin();
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+}
+
+TEST(MachineIRReadFlagsOptimizer, RemoveEligibleReadFlagsExitsToOuterLoop) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg scratch = machine_ir.AllocVReg();
+  // flags0 used to test whether we remove from outer loops.
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags00 = machine_ir.AllocVReg();
+
+  //         |-------------|
+  // bb0 -> bb1 -> bb2 -> bb3 -> bb4
+  //                ^--|
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  auto bb2 = machine_ir.NewBasicBlock();
+  auto bb3 = machine_ir.NewBasicBlock();
+  auto bb4 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+  machine_ir.AddEdge(bb1, bb2);
+  machine_ir.AddEdge(bb2, bb2);
+  machine_ir.AddEdge(bb2, bb3);
+  machine_ir.AddEdge(bb3, bb1);
+  machine_ir.AddEdge(bb3, bb4);
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<PseudoBranch>(bb1);
+
+  builder.StartBasicBlock(bb1);
+  builder.Gen<PseudoBranch>(bb2);
+
+  builder.StartBasicBlock(bb2);
+  builder.Gen<x86_64::SubqRegReg>(scratch, scratch, kMachineRegFLAGS);
+  builder.Gen<PseudoReadFlags>(PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS);
+  builder.Gen<PseudoCopy>(flags00, flags0, 8);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb2, bb3, kMachineRegFLAGS);
+  bb2->live_out().push_back(flags00);
+
+  bb3->live_in().push_back(flags00);
+  builder.StartBasicBlock(bb3);
+  builder.Gen<x86_64::MovqRegReg>(machine_ir.AllocVReg(), flags00);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb1, bb4, machine_ir.AllocVReg());
+
+  builder.StartBasicBlock(bb4);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+  auto loop_tree = BuildLoopTree(&machine_ir);
+  RemoveEligibleReadFlagsInLoopTree(&machine_ir, loop_tree.root());
+
+  // flags0 should be removed if we correctly optimize outer loops.
+  auto insn_it = std::next(bb2->insn_list().begin());
+  ASSERT_NE((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+
+  // Check that bb3 has instructions added.
+  insn_it = bb3->insn_list().begin();
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpSubqRegReg);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoWriteFlags);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpMovqRegReg);
+}
+
+TEST(MachineIRReadFlagsOptimizer, OptimizeReadFlags) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  auto testloop = BuildBasicLoop(&machine_ir);
+
+  MachineReg flags_copy = machine_ir.AllocVReg();
+
+  testloop.postloop->live_in().push_back(testloop.flags_reg);
+  testloop.postloop->insn_list().push_front(
+      machine_ir.NewInsn<MovqRegReg>(machine_ir.AllocVReg(), testloop.flags_reg));
+
+  testloop.successor->live_in().push_back(testloop.flags_reg);
+  testloop.successor->insn_list().push_front(
+      machine_ir.NewInsn<PseudoCopy>(flags_copy, testloop.flags_reg, 8));
+  testloop.successor->live_out().push_back(flags_copy);
+
+  testloop.succ_postloop->live_in().push_back(flags_copy);
+  testloop.succ_postloop->insn_list().push_front(
+      machine_ir.NewInsn<MovqRegReg>(machine_ir.AllocVReg(), flags_copy));
+
+  OptimizeReadFlags(&machine_ir);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  // Check that original PSEUDOREADFLAGS instruction is gone.
+  ASSERT_TRUE(std::none_of(
+      testloop.loop_exit->insn_list().begin(),
+      testloop.loop_exit->insn_list().end(),
+      [](berberis::MachineInsn* insn) { return insn->opcode() == kMachineOpPseudoReadFlags; }));
+
+  // Check that postloop inserted the original instruction.
+  auto insn_it = testloop.postloop->insn_list().begin();
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+
+  // Check that successor removes pseudocopy.
+  insn_it = testloop.successor->insn_list().begin();
+  ASSERT_NE((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+
+  // Check that succ_postloop also has original instruction.
+  insn_it = testloop.succ_postloop->insn_list().begin();
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+}
+
+TEST(MachineIRReadFlagsOptimizer, RemoveRegs) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags1 = machine_ir.AllocVReg();
+  MachineReg flags2 = machine_ir.AllocVReg();
+  MachineReg flags3 = machine_ir.AllocVReg();
+  MachineReg flags4 = machine_ir.AllocVReg();
+
+  MachineRegVector disallowed({flags0, flags1, flags3}, machine_ir.arena());
+  MachineRegVector regs({flags0, flags1, flags2, flags3, flags4}, machine_ir.arena());
+
+  ASSERT_TRUE(RemoveRegs(regs, disallowed));
+  ASSERT_EQ(regs.size(), 2UL);
+  ASSERT_TRUE(Contains(regs, flags2));
+  ASSERT_TRUE(Contains(regs, flags4));
+  ASSERT_FALSE(RemoveRegs(regs, disallowed));
+}
+
+TEST(MachineIRReadFlagsOptimizer, RemoveReadFlags) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags00 = machine_ir.AllocVReg();
+  MachineReg flags000 = machine_ir.AllocVReg();
+  MachineReg flags1 = machine_ir.AllocVReg();
+  MachineReg input_flag0 = machine_ir.AllocVReg();
+  MachineReg input_flag1 = machine_ir.AllocVReg();
+
+  // bb0 --> bb1 --> bb2 --> bb3
+  //          ^       |
+  //          |       v
+  //          -------bb4 --> bb5
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  auto bb2 = machine_ir.NewBasicBlock();
+  auto bb3 = machine_ir.NewBasicBlock();
+  auto bb4 = machine_ir.NewBasicBlock();
+  auto bb5 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+  machine_ir.AddEdge(bb1, bb2);
+  machine_ir.AddEdge(bb2, bb3);
+  machine_ir.AddEdge(bb2, bb4);
+  machine_ir.AddEdge(bb4, bb1);
+  machine_ir.AddEdge(bb4, bb5);
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<PseudoBranch>(bb1);
+
+  builder.StartBasicBlock(bb1);
+  builder.Gen<PseudoBranch>(bb2);
+
+  builder.StartBasicBlock(bb2);
+  builder.Gen<AddqRegReg>(input_flag0, input_flag1, kMachineRegFLAGS);
+  auto* readflag_insn =
+      builder.Gen<PseudoReadFlags>(PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS);
+  builder.Gen<PseudoCopy>(flags00, flags0, 8);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb3, bb4, kMachineRegFLAGS);
+  bb2->live_out().push_back(flags00);
+
+  builder.StartBasicBlock(bb3);
+  builder.Gen<MovqRegReg>(flags1, flags00);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+  bb3->live_in().push_back(flags00);
+
+  builder.StartBasicBlock(bb4);
+  builder.Gen<PseudoCopy>(flags000, flags00, 8);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb1, bb5, kMachineRegFLAGS);
+  bb4->live_in().push_back(flags00);
+  bb4->live_out().push_back(flags000);
+
+  builder.StartBasicBlock(bb5);
+  builder.Gen<MovqRegReg>(flags1, flags000);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+  bb5->live_in().push_back(flags000);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  RemoveReadFlags(&machine_ir,
+                  ReadFlagsOptContext{
+                      bb2,
+                      std::find(bb2->insn_list().begin(), bb2->insn_list().end(), readflag_insn),
+                      FlagSettingInsn{bb2->insn_list().begin(), false}});
+
+  // Check ReadFlags gone.
+  ASSERT_TRUE(std::none_of(
+      bb2->insn_list().begin(), bb2->insn_list().end(), [](berberis::MachineInsn* insn) {
+        return insn->opcode() == kMachineOpPseudoReadFlags;
+      }));
+  // Check that we created copies of input flags.
+  auto insn_it = bb2->insn_list().begin();
+  ASSERT_TRUE((*insn_it)->opcode() == kMachineOpPseudoCopy && (*insn_it)->RegAt(1) == input_flag0);
+  insn_it++;
+  ASSERT_TRUE((*insn_it)->opcode() == kMachineOpPseudoCopy && (*insn_it)->RegAt(1) == input_flag1);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+
+  // Check live_in/live_out.
+  ASSERT_EQ(bb2->live_out().size(), 2UL);
+  ASSERT_EQ(std::find(bb2->live_out().begin(), bb2->live_out().end(), flags0),
+            bb2->live_out().end());
+  ASSERT_EQ(bb3->live_in().size(), 2UL);
+  ASSERT_EQ(bb4->live_in().size(), 2UL);
+  ASSERT_EQ(bb4->live_out().size(), 2UL);
+  ASSERT_EQ(bb5->live_in().size(), 2UL);
+  ASSERT_EQ(bb1->live_in().size(), 0UL);
+
+  // Check that we create the instruction to set flags.
+  insn_it = bb3->insn_list().begin();
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  ASSERT_TRUE(Contains(bb3->live_in(), (*insn_it)->RegAt(1)));
+  auto input_copy = (*insn_it)->RegAt(0);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+  ASSERT_FALSE(Contains(bb3->live_in(), (*insn_it)->RegAt(0)));
+  ASSERT_EQ(input_copy, (*insn_it)->RegAt(0));
+  ASSERT_TRUE(Contains(bb3->live_in(), (*insn_it)->RegAt(1)));
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  ASSERT_EQ((*insn_it)->RegAt(0), flags00);
+
+  insn_it = bb5->insn_list().begin();
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  ASSERT_TRUE(Contains(bb5->live_in(), (*insn_it)->RegAt(1)));
+  input_copy = (*insn_it)->RegAt(0);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+  ASSERT_FALSE(Contains(bb5->live_in(), (*insn_it)->RegAt(0)));
+  ASSERT_EQ(input_copy, (*insn_it)->RegAt(0));
+  ASSERT_TRUE(Contains(bb5->live_in(), (*insn_it)->RegAt(1)));
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  ASSERT_EQ((*insn_it)->RegAt(0), flags000);
+}
+
+TEST(MachineIRReadFlagsOptimizer, ReplaceFlagRegistersRecursesOnNeighbors) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg input0 = machine_ir.AllocVReg();
+  MachineReg input00 = machine_ir.AllocVReg();
+
+  // bb0 <-> bb2
+  //  |-> bb1
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  auto bb2 = machine_ir.NewBasicBlock();
+  auto bb3 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+  machine_ir.AddEdge(bb0, bb2);
+  machine_ir.AddEdge(bb2, bb0);
+
+  builder.StartBasicBlock(bb0);
+  auto* flag_set_insn = builder.Gen<SubqRegImm>(input0, 12, kMachineRegFLAGS);
+  builder.Gen<PseudoCopy>(input00, input0, 8);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb1, bb2, kMachineRegFLAGS);
+
+  bb1->live_in().push_back(flags0);
+  builder.StartBasicBlock(bb1);
+  builder.Gen<PseudoWriteFlags>(flags0, kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  bb2->live_in().push_back(flags0);
+  builder.StartBasicBlock(bb2);
+  builder.Gen<PseudoWriteFlags>(flags0, kMachineRegFLAGS);
+  builder.Gen<PseudoBranch>(bb0);
+
+  ReplaceFlagRegisters(
+      &machine_ir,
+      ReadFlagsOptContext{
+          bb0,
+          MachineInsnList{{machine_ir.NewInsn<PseudoReadFlags>(
+                              PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS)},
+                          machine_ir.arena()}
+              .begin(),
+          FlagSettingInsn{bb0->insn_list().begin(), false},
+      },
+      bb0->insn_list().begin(),
+      MachineRegVector({flags0}, machine_ir.arena()),
+      ArenaMap<MachineReg, MachineReg>({{input0, input00}}, machine_ir.arena()),
+      flag_set_insn);
+
+  // Make sure that ReplaceFlagRegisters modifies bb1 and bb2.
+  ASSERT_EQ((*std::next(bb1->insn_list().begin()))->opcode(), kMachineOpSubqRegImm);
+  ASSERT_EQ((*std::next(bb2->insn_list().begin()))->opcode(), kMachineOpSubqRegImm);
+}
+
+TEST(MachineIRReadFlagsOptimizer, ReplaceFlagRegistersReplacesInstructions) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags00 = machine_ir.AllocVReg();
+  MachineReg input0 = machine_ir.AllocVReg();
+  MachineReg input00 = machine_ir.AllocVReg();
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+
+  builder.StartBasicBlock(bb0);
+  auto* flag_set_insn = builder.Gen<SubqRegImm>(input0, 12, kMachineRegFLAGS);
+  builder.Gen<PseudoCopy>(input00, input0, 8);
+  builder.Gen<PseudoBranch>(bb1);
+
+  bb1->live_in().push_back(flags0);
+  builder.StartBasicBlock(bb1);
+  builder.Gen<PseudoCopy>(flags00, flags0, 8);
+  builder.Gen<PseudoWriteFlags>(flags00, kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ReplaceFlagRegisters(
+      &machine_ir,
+      ReadFlagsOptContext{
+          bb0,
+          MachineInsnList{{machine_ir.NewInsn<PseudoReadFlags>(
+                              PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS)},
+                          machine_ir.arena()}
+              .begin(),
+          FlagSettingInsn{bb0->insn_list().begin(), false},
+      },
+      bb0->insn_list().begin(),
+      MachineRegVector({flags0}, machine_ir.arena()),
+      ArenaMap<MachineReg, MachineReg>({{input0, input00}}, machine_ir.arena()),
+      flag_set_insn);
+
+  auto insns = bb1->insn_list().begin();
+  ASSERT_EQ((*insns)->opcode(), kMachineOpPseudoCopy);
+  ASSERT_EQ((*insns)->RegAt(1), input00);
+  insns++;
+  auto input000 = (*insns)->RegAt(0);
+  ASSERT_EQ((*insns)->opcode(), kMachineOpSubqRegImm);
+  ASSERT_EQ((*insns)->RegAt(0), input000);
+  auto sub_flag_reg = (*insns)->RegAt(1);
+  insns++;
+  ASSERT_EQ((*insns)->opcode(), kMachineOpPseudoReadFlags);
+  ASSERT_EQ((*insns)->RegAt(0).reg(), flags00.reg());
+  ASSERT_EQ((*insns)->RegAt(1), sub_flag_reg);
+}
+
+TEST(MachineIRReadFlagsOptimizer, ReplaceFlagRegistersUpdatesLiveInOut) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags00 = machine_ir.AllocVReg();
+  MachineReg input0 = machine_ir.AllocVReg();
+  MachineReg input00 = machine_ir.AllocVReg();
+  MachineReg input1 = machine_ir.AllocVReg();
+  MachineReg input11 = machine_ir.AllocVReg();
+
+  auto bb0 = machine_ir.NewBasicBlock();
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<PseudoCopy>(flags00, flags0, 8);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+  bb0->live_in().push_back(flags0);
+  bb0->live_out().push_back(flags00);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  ReplaceFlagRegisters(
+      &machine_ir,
+      ReadFlagsOptContext{
+          bb0,
+          MachineInsnList{{machine_ir.NewInsn<PseudoReadFlags>(
+                              PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS)},
+                          machine_ir.arena()}
+              .begin(),
+          FlagSettingInsn{
+              MachineInsnList{{machine_ir.NewInsn<AddqRegReg>(input0, input1, kMachineRegFLAGS)},
+                              machine_ir.arena()}
+                  .begin(),
+              false},
+      },
+      bb0->insn_list().begin(),
+      MachineRegVector({flags0}, machine_ir.arena()),
+      ArenaMap<MachineReg, MachineReg>({{input0, input00}, {input1, input11}}, machine_ir.arena()),
+      nullptr);
+
+  ASSERT_EQ(bb0->live_in().size(), 2UL);
+  ASSERT_TRUE(Contains(bb0->live_in(), input00));
+  ASSERT_TRUE(Contains(bb0->live_in(), input11));
+}
+
+TEST(MachineIRReadFlagsOptimizer, ReplaceFlagRegistersDeletesCopies) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags00 = machine_ir.AllocVReg();
+  MachineReg flags000 = machine_ir.AllocVReg();
+  MachineReg flags1 = machine_ir.AllocVReg();
+
+  auto bb0 = machine_ir.NewBasicBlock();
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<PseudoCopy>(flags00, flags0, 8);
+  builder.Gen<PseudoCopy>(flags000, flags00, 8);
+  builder.Gen<PseudoReadFlags>(PseudoReadFlags::kWithOverflow, flags1, kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  ReplaceFlagRegisters(
+      &machine_ir,
+      ReadFlagsOptContext{
+          bb0,
+          MachineInsnList{{machine_ir.NewInsn<PseudoReadFlags>(
+                              PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS)},
+                          machine_ir.arena()}
+              .begin(),
+          FlagSettingInsn{
+              MachineInsnList{{machine_ir.NewInsn<AddqRegReg>(flags0, flags0, kMachineRegFLAGS)},
+                              machine_ir.arena()}
+                  .begin(),
+              false},
+      },
+      bb0->insn_list().begin(),
+      MachineRegVector({flags0}, machine_ir.arena()),
+      ArenaMap<MachineReg, MachineReg>(machine_ir.arena()),
+      nullptr);
+  ASSERT_TRUE(std::none_of(
+      bb0->insn_list().begin(), bb0->insn_list().end(), [](berberis::MachineInsn* insn) {
+        return insn->opcode() == kMachineOpPseudoCopy;
+      }));
+  ASSERT_TRUE(std::any_of(
+      bb0->insn_list().begin(), bb0->insn_list().end(), [](berberis::MachineInsn* insn) {
+        return insn->opcode() == kMachineOpPseudoReadFlags;
+      }));
+}
+
+// Make sure we make copies of any registers which are written to.
+TEST(MachineIRReadFlagsOptimizer, ReplaceFlagRegistersCopiesDefRegisters) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg input0 = machine_ir.AllocVReg();
+  MachineReg input00 = machine_ir.AllocVReg();
+  MachineReg input1 = machine_ir.AllocVReg();
+  MachineReg input11 = machine_ir.AllocVReg();
+
+  auto bb0 = machine_ir.NewBasicBlock();
+  builder.StartBasicBlock(bb0);
+  builder.Gen<PseudoWriteFlags>(flags0, kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  ReplaceFlagRegisters(
+      &machine_ir,
+      ReadFlagsOptContext{
+          bb0,
+          MachineInsnList{{machine_ir.NewInsn<PseudoReadFlags>(
+                              PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS)},
+                          machine_ir.arena()}
+              .begin(),
+          FlagSettingInsn{
+              MachineInsnList{{machine_ir.NewInsn<AddqRegReg>(input0, input1, kMachineRegFLAGS)},
+                              machine_ir.arena()}
+                  .begin(),
+              false},
+      },
+      bb0->insn_list().begin(),
+      MachineRegVector({flags0}, machine_ir.arena()),
+      ArenaMap<MachineReg, MachineReg>(
+          {
+              {input0, input00},
+              {input1, input11},
+          },
+          machine_ir.arena()),
+      nullptr);
+
+  auto insns = bb0->insn_list().begin();
+  ASSERT_EQ((*insns)->opcode(), kMachineOpPseudoCopy);
+  ASSERT_EQ((*insns)->RegAt(1), input00);
+  auto input000 = (*insns)->RegAt(0);
+  insns++;
+  ASSERT_EQ((*insns)->opcode(), kMachineOpAddqRegReg);
+  ASSERT_EQ((*insns)->RegAt(0), input000);
+  ASSERT_NE((*insns)->RegAt(1), input1);
+}
+
+// Test that ReplaceFlagRegisters won't insert instructions multiple times for
+// the same register.
+TEST(MachineIRReadFlagsOptimizer, ReplaceFlagRegistersWithDuplicates) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg input0 = machine_ir.AllocVReg();
+
+  auto bb0 = machine_ir.NewBasicBlock();
+  builder.StartBasicBlock(bb0);
+  builder.Gen<SubqRegReg>(flags0, flags0, kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  ReplaceFlagRegisters(
+      &machine_ir,
+      ReadFlagsOptContext{
+          bb0,
+          MachineInsnList{{machine_ir.NewInsn<PseudoReadFlags>(
+                              PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS)},
+                          machine_ir.arena()}
+              .begin(),
+          FlagSettingInsn{
+              MachineInsnList{{machine_ir.NewInsn<AddqRegReg>(input0, input0, kMachineRegFLAGS)},
+                              machine_ir.arena()}
+                  .begin(),
+              false},
+      },
+      bb0->insn_list().begin(),
+      MachineRegVector({flags0}, machine_ir.arena()),
+      ArenaMap<MachineReg, MachineReg>(
+          {
+              {input0, input0},
+          },
+          machine_ir.arena()),
+      nullptr);
+
+  auto insn_it = bb0->insn_list().begin();
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoCopy);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpAddqRegReg);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpSubqRegReg);
+  insn_it++;
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoJump);
+}
+
 }  // namespace
 
 }  // namespace berberis::x86_64
diff --git a/backend/x86_64/rename_copy_uses.cc b/backend/x86_64/rename_copy_uses.cc
index 73a108e2..0410bd83 100644
--- a/backend/x86_64/rename_copy_uses.cc
+++ b/backend/x86_64/rename_copy_uses.cc
@@ -16,7 +16,6 @@
 
 #include "berberis/backend/x86_64/rename_copy_uses.h"
 
-#include "berberis/backend/common/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir.h"
 
 namespace berberis::x86_64 {
@@ -32,7 +31,7 @@ MachineReg RenameCopyUsesMap::Get(MachineReg reg) {
   return renamed;
 }
 
-void RenameCopyUsesMap::RenameUseIfMapped(MachineInsn* insn, int i) {
+void RenameCopyUsesMap::RenameUseIfMapped(berberis::MachineInsn* insn, int i) {
   // Narrow type uses may require a copy for register allocator to successfully handle them.
   // TODO(b/200327919): It'd better to make CallImmArg specify the exact narrow class for
   // the corresponding call argument. Then we wouldn't need to special case it.
@@ -50,7 +49,7 @@ void RenameCopyUsesMap::RenameUseIfMapped(MachineInsn* insn, int i) {
   }
 }
 
-void RenameCopyUsesMap::ProcessDef(MachineInsn* insn, int i) {
+void RenameCopyUsesMap::ProcessDef(berberis::MachineInsn* insn, int i) {
   MachineReg reg = insn->RegAt(i);
 
   if (!reg.IsVReg()) {
@@ -60,7 +59,7 @@ void RenameCopyUsesMap::ProcessDef(MachineInsn* insn, int i) {
   RenameDataForReg(reg) = {kInvalidMachineReg, 0, time_};
 }
 
-void RenameCopyUsesMap::ProcessCopy(MachineInsn* copy) {
+void RenameCopyUsesMap::ProcessCopy(berberis::MachineInsn* copy) {
   auto dst = copy->RegAt(0);
   auto src = copy->RegAt(1);
   if (!dst.IsVReg() || !src.IsVReg()) {
@@ -91,7 +90,7 @@ void RenameCopyUses(MachineIR* machine_ir) {
   for (auto* bb : machine_ir->bb_list()) {
     map.StartBasicBlock(bb);
 
-    for (MachineInsn* insn : bb->insn_list()) {
+    for (berberis::MachineInsn* insn : bb->insn_list()) {
       for (int i = 0; i < insn->NumRegOperands(); ++i) {
         // Note that Def-Use operands cannot be renamed, so we handle them as Defs.
         if (insn->RegKindAt(i).IsDef()) {
diff --git a/backend/x86_64/rename_copy_uses_test.cc b/backend/x86_64/rename_copy_uses_test.cc
index 3646ed79..becaee11 100644
--- a/backend/x86_64/rename_copy_uses_test.cc
+++ b/backend/x86_64/rename_copy_uses_test.cc
@@ -25,6 +25,10 @@
 
 namespace berberis::x86_64 {
 
+constexpr auto kMachineRegRAX = MachineRegs::kRAX;
+constexpr auto kMachineRegRCX = MachineRegs::kRCX;
+constexpr auto kMachineRegRBX = MachineRegs::kRBX;
+
 namespace {
 
 TEST(MachineIRRenameCopyUsesMapTest, Basic) {
diff --git a/backend/x86_64/rename_vregs_local.cc b/backend/x86_64/rename_vregs_local.cc
index a93f1a66..023384aa 100644
--- a/backend/x86_64/rename_vregs_local.cc
+++ b/backend/x86_64/rename_vregs_local.cc
@@ -52,7 +52,7 @@ void TryRenameRegOperand(int operand_index,
                          MachineInsnList::const_iterator insn_it,
                          MachineIR* machine_ir,
                          MachineInsnList& insn_list) {
-  MachineInsn* insn = *insn_it;
+  berberis::MachineInsn* insn = *insn_it;
   MachineReg reg = insn->RegAt(operand_index);
 
   if (!reg.IsVReg()) {
@@ -87,7 +87,7 @@ void TryRenameRegOperand(int operand_index,
 
 void RenameInsnListRegs(VRegMap& vreg_map, MachineInsnList& insn_list, MachineIR* machine_ir) {
   for (auto insn_it = insn_list.begin(); insn_it != insn_list.end(); ++insn_it) {
-    MachineInsn* insn = *insn_it;
+    berberis::MachineInsn* insn = *insn_it;
     for (int i = 0; i < insn->NumRegOperands(); ++i) {
       // Renames current register, if necessary - has various criteria depending on the type of the
       // register (i.e., register is a USE and/or DEF).
diff --git a/backend/x86_64/rename_vregs_test.cc b/backend/x86_64/rename_vregs_test.cc
index bc57abde..7490e716 100644
--- a/backend/x86_64/rename_vregs_test.cc
+++ b/backend/x86_64/rename_vregs_test.cc
@@ -28,6 +28,8 @@ namespace berberis {
 
 namespace {
 
+constexpr auto kMachineRegRAX = x86_64::MachineRegs::kRAX;
+
 TEST(MachineRenameVRegsTest, AssignNewVRegsInSameBasicBlock) {
   Arena arena;
   x86_64::MachineIR machine_ir(&arena);
@@ -39,7 +41,7 @@ TEST(MachineRenameVRegsTest, AssignNewVRegsInSameBasicBlock) {
 
   builder.StartBasicBlock(bb);
   builder.Gen<x86_64::MovqRegImm>(vreg, 0);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   x86_64::VRegMap vreg_map(&machine_ir);
@@ -52,7 +54,7 @@ TEST(MachineRenameVRegsTest, AssignNewVRegsInSameBasicBlock) {
   it++;
   EXPECT_EQ(new_vreg, (*it)->RegAt(1));
   // Hard regs remain unrenamed.
-  EXPECT_EQ(x86_64::kMachineRegRAX, (*it)->RegAt(0));
+  EXPECT_EQ(kMachineRegRAX, (*it)->RegAt(0));
 }
 
 TEST(MachineRenameVRegsTest, AssignNewVRegsAcrossBasicBlocks) {
@@ -72,7 +74,7 @@ TEST(MachineRenameVRegsTest, AssignNewVRegsAcrossBasicBlocks) {
   builder.Gen<PseudoBranch>(bb2);
 
   builder.StartBasicBlock(bb2);
-  builder.Gen<x86_64::MovqRegReg>(x86_64::kMachineRegRAX, vreg);
+  builder.Gen<x86_64::MovqRegReg>(kMachineRegRAX, vreg);
   builder.Gen<PseudoJump>(kNullGuestAddr);
 
   x86_64::VRegMap vreg_map(&machine_ir);
@@ -89,7 +91,7 @@ TEST(MachineRenameVRegsTest, AssignNewVRegsAcrossBasicBlocks) {
   EXPECT_NE(vreg, vreg_in_bb2);
   EXPECT_NE(vreg_in_bb1, vreg_in_bb2);
   // Hard regs remain unrenamed.
-  EXPECT_EQ(x86_64::kMachineRegRAX, (*it)->RegAt(0));
+  EXPECT_EQ(kMachineRegRAX, (*it)->RegAt(0));
 }
 
 TEST(MachineRenameVRegsTest, DataFlowAcrossBasicBlocks) {
diff --git a/base/config_globals.cc b/base/config_globals.cc
index 74f2679a..0c3fd470 100644
--- a/base/config_globals.cc
+++ b/base/config_globals.cc
@@ -103,6 +103,10 @@ const char* GetMainExecutableRealPath() {
   return g_main_executable_real_path;
 }
 
+const char** GetMainExecutableRealPathPointer() {
+  return &g_main_executable_real_path;
+}
+
 void SetAppPackageName(std::string_view name) {
   CHECK(!name.empty());
   g_app_package_name = MakeForeverCStr(name);
diff --git a/base/config_globals_custom.cc b/base/config_globals_custom.cc
index f2eacfb3..4be2e861 100644
--- a/base/config_globals_custom.cc
+++ b/base/config_globals_custom.cc
@@ -39,8 +39,8 @@ std::string ToString(ConfigFlag flag) {
       return "top-byte-ignore";
     case kDisableRegMap:
       return "disable-reg-map";
-    case kEnableDisjointRegionsTranslation:
-      return "enable-disjoint-regions-translation";
+    case kDisableAdjacentRegionsTranslation:
+      return "disable-adjacent-regions-translation";
     case kDisableIntrinsicInlining:
       return "disable-intrinsic-inlining";
     case kMergeProfilesForSameModeRegions:
diff --git a/base/include/berberis/base/algorithm.h b/base/include/berberis/base/algorithm.h
index c28e9576..41c195f0 100644
--- a/base/include/berberis/base/algorithm.h
+++ b/base/include/berberis/base/algorithm.h
@@ -18,6 +18,7 @@
 #define BERBERIS_BASE_ALGORITHM_H_
 
 #include <algorithm>
+#include <iterator>
 
 namespace berberis {
 
@@ -25,6 +26,11 @@ namespace berberis {
 // Non-const container versions.
 //
 
+template <class Container>
+auto EraseFromReverseIterator(Container& container, typename Container::reverse_iterator rit) {
+  return std::reverse_iterator(container.erase(std::prev(rit.base())));
+}
+
 template <class Container, class Value>
 auto Find(Container& container, const Value& value) {
   return std::find(container.begin(), container.end(), value);
diff --git a/base/include/berberis/base/config.h b/base/include/berberis/base/config.h
index 308c2e4a..7fc28a09 100644
--- a/base/include/berberis/base/config.h
+++ b/base/include/berberis/base/config.h
@@ -20,8 +20,13 @@
 #include <cstddef>
 #include <cstdint>
 
+#include "berberis/base/page_size.h"
+
 namespace berberis::config {
 
+// Guest page size
+inline const size_t kGuestPageSize = berberis::kPageSize;
+
 // Size of the stack frame allocated in translated code prologue.
 // As translated code ('slow') prologue executes much less frequently than
 // region ('fast') prologue, it makes sense to allocate a frame there that
@@ -47,8 +52,6 @@ inline constexpr bool kLinkJumpsBetweenRegions = !kAllJumpsExitGeneratedCode;
 // Generate local jumps if jump's target address falls within the
 // current region. If false dispatch to another region instead.
 inline constexpr bool kLinkJumpsWithinRegion = !kAllJumpsExitGeneratedCode;
-// Guest page size. Always 4K for now.
-inline constexpr size_t kGuestPageSize = 4096;
 // Number of hard registers assumed by the register allocator.
 inline constexpr uint32_t kMaxHardRegs = 64u;
 // Threshold for switching between gears
diff --git a/base/include/berberis/base/config_globals.h b/base/include/berberis/base/config_globals.h
index 9e282573..b92035ec 100644
--- a/base/include/berberis/base/config_globals.h
+++ b/base/include/berberis/base/config_globals.h
@@ -33,6 +33,7 @@ class ConfigStr {
 
 void SetMainExecutableRealPath(std::string_view path);
 const char* GetMainExecutableRealPath();
+const char** GetMainExecutableRealPathPointer();
 
 void SetAppPackageName(std::string_view name);
 const char* GetAppPackageName();
@@ -51,7 +52,7 @@ uintptr_t GetEntryPointOverride();
 enum ConfigFlag {
   kTopByteIgnore,
   kDisableRegMap,
-  kEnableDisjointRegionsTranslation,
+  kDisableAdjacentRegionsTranslation,
   kVerboseTranslation,
   kAccurateSigsegv,
   kDisableIntrinsicInlining,
diff --git a/base/include/berberis/base/page_size.h b/base/include/berberis/base/page_size.h
index 6b19847f..6ff32888 100644
--- a/base/include/berberis/base/page_size.h
+++ b/base/include/berberis/base/page_size.h
@@ -17,8 +17,6 @@
 #ifndef BERBERIS_BASE_PAGESIZE_H_
 #define BERBERIS_BASE_PAGESIZE_H_
 
-#include "berberis/base/checks.h"
-
 #include <unistd.h>
 
 namespace berberis {
@@ -37,7 +35,6 @@ struct PageSize {
     if (value_ == 0) {
       return getpagesize();
     }
-    CHECK((value_ & (value_ - 1)) == 0);  // Power of 2
     return value_;
   }
 
diff --git a/base/include/berberis/base/string_literal.h b/base/include/berberis/base/string_literal.h
new file mode 100644
index 00000000..a0eed868
--- /dev/null
+++ b/base/include/berberis/base/string_literal.h
@@ -0,0 +1,37 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_BASE_STRING_LITERAL_H_
+#define BERBERIS_BASE_STRING_LITERAL_H_
+
+#include <algorithm>
+#include <cstddef>
+
+namespace berberis {
+
+// Note: we use that type as argument of template which means that “all base classes and non-static
+// data members should be public and non-mutable”.
+template <size_t N>
+struct StringLiteral {
+  constexpr StringLiteral(const char (&str)[N]) { std::copy_n(str, N, value); }
+  constexpr operator const char*() const { return value; }
+
+  char value[N];
+};
+
+}  // namespace berberis
+
+#endif  // BERBERIS_BASE_STRING_LITERAL_H_
diff --git a/code_gen_lib/riscv64_to_x86_64/gen_wrapper.cc b/code_gen_lib/riscv64_to_x86_64/gen_wrapper.cc
index 5a65c991..d4c13ce5 100644
--- a/code_gen_lib/riscv64_to_x86_64/gen_wrapper.cc
+++ b/code_gen_lib/riscv64_to_x86_64/gen_wrapper.cc
@@ -152,9 +152,9 @@ void GenWrapGuestFunction(MachineCode* mc,
         if (signature[i] == 'f') {
           // LP64D requires 32-bit floats to be NaN boxed.
           if (host_platform::kHasAVX) {
-            as.MacroNanBoxAVX<intrinsics::Float32>(kFpParamRegs[fp_argc], kFpParamRegs[fp_argc]);
+            as.NanBoxAVX<intrinsics::Float32>(kFpParamRegs[fp_argc], kFpParamRegs[fp_argc]);
           } else {
-            as.MacroNanBox<intrinsics::Float32>(kFpParamRegs[fp_argc]);
+            as.NanBox<intrinsics::Float32>(kFpParamRegs[fp_argc]);
           }
         }
         if (host_platform::kHasAVX) {
diff --git a/decoder/include/berberis/decoder/riscv64/semantics_player.h b/decoder/include/berberis/decoder/riscv64/semantics_player.h
index 67a9d8df..ab344d7b 100644
--- a/decoder/include/berberis/decoder/riscv64/semantics_player.h
+++ b/decoder/include/berberis/decoder/riscv64/semantics_player.h
@@ -36,6 +36,24 @@ class SemanticsPlayer {
   using FpRegister = typename SemanticsListener::FpRegister;
   static constexpr FpRegister no_fp_register = SemanticsListener::no_fp_register;
 
+  // Note: this is part of the machinery that makes it possible to pick between High demultiplexer
+  // and Low demultiplexer approach.  More info on go/berberis-intrinsic-demultiplexing
+  using TemplateTypeId = SemanticsListener::TemplateTypeId;
+  template <typename TypeName>
+  using Type = SemanticsListener::template Value<SemanticsListener::template kIdFromType<TypeName>>;
+  // Syntax sugar to eliminate {} from type conversion.
+  template <typename TypeName>
+  static constexpr Type<TypeName> kType{};
+  template <auto kEnumValue>
+  using TypeFromId = SemanticsListener::template TypeFromId<kEnumValue>;
+  template <auto ValueParam>
+  using Value = SemanticsListener::template Value<ValueParam>;
+  // Syntax sugar to eliminate {} from value conversion.
+  template <auto ValueParam>
+  static constexpr Value<ValueParam> kValue{};
+  template <typename TypeName>
+  static constexpr Value<static_cast<int>(sizeof(TypeName))> kSize{};
+
   explicit SemanticsPlayer(SemanticsListener* listener) : listener_(listener) {}
 
   // Decoder's InsnConsumer implementation.
@@ -79,27 +97,27 @@ class SemanticsPlayer {
   Register Amo(typename Decoder::AmoOpcode opcode, Register arg1, Register arg2) {
     switch (opcode) {
       case Decoder::AmoOpcode::kLr:
-        return listener_->template Lr<IntType, aq, rl>(arg1);
+        return listener_->Lr(arg1, kType<IntType>, kValue<aq>, kValue<rl>);
       case Decoder::AmoOpcode::kSc:
-        return listener_->template Sc<IntType, aq, rl>(arg1, arg2);
+        return listener_->Sc(arg1, arg2, kType<IntType>, kValue<aq>, kValue<rl>);
       case Decoder::AmoOpcode::kAmoswap:
-        return listener_->template AmoSwap<IntType, aq, rl>(arg1, arg2);
+        return listener_->AmoSwap(arg1, arg2, kType<IntType>, kValue<aq>, kValue<rl>);
       case Decoder::AmoOpcode::kAmoadd:
-        return listener_->template AmoAdd<IntType, aq, rl>(arg1, arg2);
+        return listener_->AmoAdd(arg1, arg2, kType<IntType>, kValue<aq>, kValue<rl>);
       case Decoder::AmoOpcode::kAmoxor:
-        return listener_->template AmoXor<IntType, aq, rl>(arg1, arg2);
+        return listener_->AmoXor(arg1, arg2, kType<IntType>, kValue<aq>, kValue<rl>);
       case Decoder::AmoOpcode::kAmoand:
-        return listener_->template AmoAnd<IntType, aq, rl>(arg1, arg2);
+        return listener_->AmoAnd(arg1, arg2, kType<IntType>, kValue<aq>, kValue<rl>);
       case Decoder::AmoOpcode::kAmoor:
-        return listener_->template AmoOr<IntType, aq, rl>(arg1, arg2);
+        return listener_->AmoOr(arg1, arg2, kType<IntType>, kValue<aq>, kValue<rl>);
       case Decoder::AmoOpcode::kAmomin:
-        return listener_->template AmoMin<std::make_signed_t<IntType>, aq, rl>(arg1, arg2);
+        return listener_->AmoMin(arg1, arg2, ToSigned(kType<IntType>), kValue<aq>, kValue<rl>);
       case Decoder::AmoOpcode::kAmomax:
-        return listener_->template AmoMax<std::make_signed_t<IntType>, aq, rl>(arg1, arg2);
+        return listener_->AmoMax(arg1, arg2, ToSigned(kType<IntType>), kValue<aq>, kValue<rl>);
       case Decoder::AmoOpcode::kAmominu:
-        return listener_->template AmoMin<std::make_unsigned_t<IntType>, aq, rl>(arg1, arg2);
+        return listener_->AmoMin(arg1, arg2, ToUnsigned(kType<IntType>), kValue<aq>, kValue<rl>);
       case Decoder::AmoOpcode::kAmomaxu:
-        return listener_->template AmoMax<std::make_unsigned_t<IntType>, aq, rl>(arg1, arg2);
+        return listener_->AmoMax(arg1, arg2, ToUnsigned(kType<IntType>), kValue<aq>, kValue<rl>);
       default:
         Undefined();
         return no_register;
@@ -181,13 +199,15 @@ class SemanticsPlayer {
         args.src_type == Decoder::FloatOperandType::kDouble) {
       FpRegister arg = GetFRegAndUnboxNan<Float64>(args.src);
       Register frm = listener_->template GetCsr<CsrName::kFrm>();
-      FpRegister result = listener_->template FCvtFloatToFloat<Float32, Float64>(args.rm, frm, arg);
+      FpRegister result =
+          listener_->FCvtFloatToFloat(args.rm, frm, arg, kType<Float32>, kType<Float64>);
       NanBoxAndSetFpReg<Float32>(args.dst, result);
     } else if (args.dst_type == Decoder::FloatOperandType::kDouble &&
                args.src_type == Decoder::FloatOperandType::kFloat) {
       FpRegister arg = GetFRegAndUnboxNan<Float32>(args.src);
       Register frm = listener_->template GetCsr<CsrName::kFrm>();
-      FpRegister result = listener_->template FCvtFloatToFloat<Float64, Float32>(args.rm, frm, arg);
+      FpRegister result =
+          listener_->FCvtFloatToFloat(args.rm, frm, arg, kType<Float64>, kType<Float32>);
       NanBoxAndSetFpReg<Float64>(args.dst, result);
     } else {
       Undefined();
@@ -216,16 +236,16 @@ class SemanticsPlayer {
     Register result = no_register;
     switch (dst_type) {
       case Decoder::FcvtOperandType::k32bitSigned:
-        result = listener_->template FCvtFloatToInteger<int32_t, FLoatType>(rm, frm, arg);
+        result = listener_->FCvtFloatToInteger(rm, frm, arg, kType<int32_t>, kType<FLoatType>);
         break;
       case Decoder::FcvtOperandType::k32bitUnsigned:
-        result = listener_->template FCvtFloatToInteger<uint32_t, FLoatType>(rm, frm, arg);
+        result = listener_->FCvtFloatToInteger(rm, frm, arg, kType<uint32_t>, kType<FLoatType>);
         break;
       case Decoder::FcvtOperandType::k64bitSigned:
-        result = listener_->template FCvtFloatToInteger<int64_t, FLoatType>(rm, frm, arg);
+        result = listener_->FCvtFloatToInteger(rm, frm, arg, kType<int64_t>, kType<FLoatType>);
         break;
       case Decoder::FcvtOperandType::k64bitUnsigned:
-        result = listener_->template FCvtFloatToInteger<uint64_t, FLoatType>(rm, frm, arg);
+        result = listener_->FCvtFloatToInteger(rm, frm, arg, kType<uint64_t>, kType<FLoatType>);
         break;
       default:
         return Undefined();
@@ -254,16 +274,16 @@ class SemanticsPlayer {
     FpRegister result = no_fp_register;
     switch (src_type) {
       case Decoder::FcvtOperandType::k32bitSigned:
-        result = listener_->template FCvtIntegerToFloat<FloatType, int32_t>(rm, frm, arg);
+        result = listener_->FCvtIntegerToFloat(rm, frm, arg, kType<FloatType>, kType<int32_t>);
         break;
       case Decoder::FcvtOperandType::k32bitUnsigned:
-        result = listener_->template FCvtIntegerToFloat<FloatType, uint32_t>(rm, frm, arg);
+        result = listener_->FCvtIntegerToFloat(rm, frm, arg, kType<FloatType>, kType<uint32_t>);
         break;
       case Decoder::FcvtOperandType::k64bitSigned:
-        result = listener_->template FCvtIntegerToFloat<FloatType, int64_t>(rm, frm, arg);
+        result = listener_->FCvtIntegerToFloat(rm, frm, arg, kType<FloatType>, kType<int64_t>);
         break;
       case Decoder::FcvtOperandType::k64bitUnsigned:
-        result = listener_->template FCvtIntegerToFloat<FloatType, uint64_t>(rm, frm, arg);
+        result = listener_->FCvtIntegerToFloat(rm, frm, arg, kType<FloatType>, kType<uint64_t>);
         break;
       default:
         Undefined();
@@ -299,10 +319,10 @@ class SemanticsPlayer {
     FpRegister result = no_fp_register;
     switch (opcode) {
       case Decoder::FmaOpcode::kFmadd:
-        result = listener_->template FMAdd<FloatType>(rm, frm, arg1, arg2, arg3);
+        result = listener_->FMAdd(rm, frm, arg1, arg2, arg3, kType<FloatType>);
         break;
       case Decoder::FmaOpcode::kFmsub:
-        result = listener_->template FMSub<FloatType>(rm, frm, arg1, arg2, arg3);
+        result = listener_->FMSub(rm, frm, arg1, arg2, arg3, kType<FloatType>);
         break;
       // Note (from RISC-V manual): The FNMSUB and FNMADD instructions are counterintuitively named,
       // owing to the naming of the corresponding instructions in MIPS-IV. The MIPS instructions
@@ -315,10 +335,10 @@ class SemanticsPlayer {
       // Since even official documentation calls the names “counterintuitive” it's better to use x86
       // ones for intrinsics.
       case Decoder::FmaOpcode::kFnmsub:
-        result = listener_->template FNMAdd<FloatType>(rm, frm, arg1, arg2, arg3);
+        result = listener_->FNMAdd(rm, frm, arg1, arg2, arg3, kType<FloatType>);
         break;
       case Decoder::FmaOpcode::kFnmadd:
-        result = listener_->template FNMSub<FloatType>(rm, frm, arg1, arg2, arg3);
+        result = listener_->FNMSub(rm, frm, arg1, arg2, arg3, kType<FloatType>);
         break;
       default:
         return Undefined();
@@ -414,25 +434,25 @@ class SemanticsPlayer {
     Register result = Overloaded{[&](const typename Decoder::OpArgs& args) {
                                    switch (args.opcode) {
                                      case Decoder::OpOpcode::kDiv:
-                                       return listener_->template Div<int64_t>(arg1, arg2);
+                                       return listener_->DivRiscV(arg1, arg2, kType<int64_t>);
                                      case Decoder::OpOpcode::kDivu:
-                                       return listener_->template Div<uint64_t>(arg1, arg2);
+                                       return listener_->DivRiscV(arg1, arg2, kType<uint64_t>);
                                      case Decoder::OpOpcode::kRem:
-                                       return listener_->template Rem<int64_t>(arg1, arg2);
+                                       return listener_->RemRiscV(arg1, arg2, kType<int64_t>);
                                      case Decoder::OpOpcode::kRemu:
-                                       return listener_->template Rem<uint64_t>(arg1, arg2);
+                                       return listener_->RemRiscV(arg1, arg2, kType<uint64_t>);
                                      case Decoder::OpOpcode::kMax:
-                                       return listener_->template Max<int64_t>(arg1, arg2);
+                                       return listener_->Max(arg1, arg2, kType<int64_t>);
                                      case Decoder::OpOpcode::kMaxu:
-                                       return listener_->template Max<uint64_t>(arg1, arg2);
+                                       return listener_->Max(arg1, arg2, kType<uint64_t>);
                                      case Decoder::OpOpcode::kMin:
-                                       return listener_->template Min<int64_t>(arg1, arg2);
+                                       return listener_->Min(arg1, arg2, kType<int64_t>);
                                      case Decoder::OpOpcode::kMinu:
-                                       return listener_->template Min<uint64_t>(arg1, arg2);
+                                       return listener_->Min(arg1, arg2, kType<uint64_t>);
                                      case Decoder::OpOpcode::kRol:
-                                       return listener_->template Rol<int64_t>(arg1, arg2);
+                                       return listener_->Rol(arg1, arg2, kType<int64_t>);
                                      case Decoder::OpOpcode::kRor:
-                                       return listener_->template Ror<int64_t>(arg1, arg2);
+                                       return listener_->Ror(arg1, arg2, kType<int64_t>);
                                      case Decoder::OpOpcode::kSh1add:
                                        return listener_->Sh1add(arg1, arg2);
                                      case Decoder::OpOpcode::kSh2add:
@@ -456,17 +476,17 @@ class SemanticsPlayer {
                                      case Decoder::Op32Opcode::kAdduw:
                                        return listener_->Adduw(arg1, arg2);
                                      case Decoder::Op32Opcode::kDivw:
-                                       return listener_->template Div<int32_t>(arg1, arg2);
+                                       return listener_->DivRiscV(arg1, arg2, kType<int32_t>);
                                      case Decoder::Op32Opcode::kDivuw:
-                                       return listener_->template Div<uint32_t>(arg1, arg2);
+                                       return listener_->DivRiscV(arg1, arg2, kType<uint32_t>);
                                      case Decoder::Op32Opcode::kRemw:
-                                       return listener_->template Rem<int32_t>(arg1, arg2);
+                                       return listener_->RemRiscV(arg1, arg2, kType<int32_t>);
                                      case Decoder::Op32Opcode::kRemuw:
-                                       return listener_->template Rem<uint32_t>(arg1, arg2);
+                                       return listener_->RemRiscV(arg1, arg2, kType<uint32_t>);
                                      case Decoder::Op32Opcode::kRolw:
-                                       return listener_->template Rol<int32_t>(arg1, arg2);
+                                       return listener_->Rol(arg1, arg2, kType<int32_t>);
                                      case Decoder::Op32Opcode::kRorw:
-                                       return listener_->template Ror<int32_t>(arg1, arg2);
+                                       return listener_->Ror(arg1, arg2, kType<int32_t>);
                                      case Decoder::Op32Opcode::kSh1adduw:
                                        return listener_->Sh1adduw(arg1, arg2);
                                      case Decoder::Op32Opcode::kSh2adduw:
@@ -485,19 +505,19 @@ class SemanticsPlayer {
     Register result = no_register;
     switch (args.opcode) {
       case Decoder::OpSingleInputOpcode::kZextb:
-        result = listener_->template Zext<uint8_t>(arg);
+        result = listener_->Zext(arg, kType<uint8_t>);
         break;
       case Decoder::OpSingleInputOpcode::kZexth:
-        result = listener_->template Zext<uint16_t>(arg);
+        result = listener_->Zext(arg, kType<uint16_t>);
         break;
       case Decoder::OpSingleInputOpcode::kZextw:
-        result = listener_->template Zext<uint32_t>(arg);
+        result = listener_->Zext(arg, kType<uint32_t>);
         break;
       case Decoder::OpSingleInputOpcode::kSextb:
-        result = listener_->template Sext<int8_t>(arg);
+        result = listener_->Sext(arg, kType<int8_t>);
         break;
       case Decoder::OpSingleInputOpcode::kSexth:
-        result = listener_->template Sext<int16_t>(arg);
+        result = listener_->Sext(arg, kType<int16_t>);
         break;
       default:
         Undefined();
@@ -525,16 +545,16 @@ class SemanticsPlayer {
     FpRegister result = no_fp_register;
     switch (opcode) {
       case Decoder::OpFpOpcode::kFAdd:
-        result = listener_->template FAdd<FloatType>(rm, frm, arg1, arg2);
+        result = listener_->FAdd(rm, frm, arg1, arg2, kType<FloatType>);
         break;
       case Decoder::OpFpOpcode::kFSub:
-        result = listener_->template FSub<FloatType>(rm, frm, arg1, arg2);
+        result = listener_->FSub(rm, frm, arg1, arg2, kType<FloatType>);
         break;
       case Decoder::OpFpOpcode::kFMul:
-        result = listener_->template FMul<FloatType>(rm, frm, arg1, arg2);
+        result = listener_->FMul(rm, frm, arg1, arg2, kType<FloatType>);
         break;
       case Decoder::OpFpOpcode::kFDiv:
-        result = listener_->template FDiv<FloatType>(rm, frm, arg1, arg2);
+        result = listener_->FDiv(rm, frm, arg1, arg2, kType<FloatType>);
         break;
       default:
         return Undefined();
@@ -565,13 +585,13 @@ class SemanticsPlayer {
     Register result = no_register;
     switch (opcode) {
       case Decoder::OpFpGpRegisterTargetNoRoundingOpcode::kFle:
-        result = listener_->template Fle<FloatType>(arg1, arg2);
+        result = listener_->Fle(arg1, arg2, kType<FloatType>);
         break;
       case Decoder::OpFpGpRegisterTargetNoRoundingOpcode::kFlt:
-        result = listener_->template Flt<FloatType>(arg1, arg2);
+        result = listener_->Flt(arg1, arg2, kType<FloatType>);
         break;
       case Decoder::OpFpGpRegisterTargetNoRoundingOpcode::kFeq:
-        result = listener_->template Feq<FloatType>(arg1, arg2);
+        result = listener_->Feq(arg1, arg2, kType<FloatType>);
         break;
       default:
         return Undefined();
@@ -600,7 +620,7 @@ class SemanticsPlayer {
     Register result = no_register;
     switch (opcode) {
       case Decoder::OpFpGpRegisterTargetSingleInputNoRoundingOpcode::kFclass:
-        result = listener_->template FClass<FloatType>(arg);
+        result = listener_->FClass(arg, kType<FloatType>);
         break;
       default:
         return Undefined();
@@ -645,19 +665,19 @@ class SemanticsPlayer {
     }
     switch (opcode) {
       case Decoder::OpFpNoRoundingOpcode::kFSgnj:
-        result = listener_->template FSgnj<FloatType>(arg1, arg2);
+        result = listener_->FSgnj(arg1, arg2, kType<FloatType>);
         break;
       case Decoder::OpFpNoRoundingOpcode::kFSgnjn:
-        result = listener_->template FSgnjn<FloatType>(arg1, arg2);
+        result = listener_->FSgnjn(arg1, arg2, kType<FloatType>);
         break;
       case Decoder::OpFpNoRoundingOpcode::kFSgnjx:
-        result = listener_->template FSgnjx<FloatType>(arg1, arg2);
+        result = listener_->FSgnjx(arg1, arg2, kType<FloatType>);
         break;
       case Decoder::OpFpNoRoundingOpcode::kFMin:
-        result = listener_->template FMin<FloatType>(arg1, arg2);
+        result = listener_->FMin(arg1, arg2, kType<FloatType>);
         break;
       case Decoder::OpFpNoRoundingOpcode::kFMax:
-        result = listener_->template FMax<FloatType>(arg1, arg2);
+        result = listener_->FMax(arg1, arg2, kType<FloatType>);
         break;
       default:
         Undefined();
@@ -674,10 +694,10 @@ class SemanticsPlayer {
     Register result = no_register;
     switch (args.operand_type) {
       case Decoder::FloatOperandType::kFloat:
-        result = listener_->template FmvFloatToInteger<int32_t, Float32>(arg);
+        result = listener_->FmvFloatToInteger(arg, kType<int32_t>, kType<Float32>);
         break;
       case Decoder::FloatOperandType::kDouble:
-        result = listener_->template FmvFloatToInteger<int64_t, Float64>(arg);
+        result = listener_->FmvFloatToInteger(arg, kType<int64_t>, kType<Float64>);
         break;
       default:
         Undefined();
@@ -691,11 +711,11 @@ class SemanticsPlayer {
     FpRegister result = no_fp_register;
     switch (args.operand_type) {
       case Decoder::FloatOperandType::kFloat:
-        result = listener_->template FmvIntegerToFloat<Float32, int32_t>(arg);
+        result = listener_->FmvIntegerToFloat(arg, kType<Float32>, kType<int32_t>);
         NanBoxAndSetFpReg<Float32>(args.dst, result);
         break;
       case Decoder::FloatOperandType::kDouble:
-        result = listener_->template FmvIntegerToFloat<Float64, int64_t>(arg);
+        result = listener_->FmvIntegerToFloat(arg, kType<Float64>, kType<int64_t>);
         NanBoxAndSetFpReg<Float64>(args.dst, result);
         break;
       default:
@@ -725,7 +745,7 @@ class SemanticsPlayer {
     Register frm = listener_->template GetCsr<CsrName::kFrm>();
     switch (opcode) {
       case Decoder::OpFpSingleInputOpcode::kFSqrt:
-        result = listener_->template FSqrt<FloatType>(rm, frm, arg);
+        result = listener_->FSqrt(rm, frm, arg, kType<FloatType>);
         break;
       default:
         return Undefined();
@@ -791,15 +811,15 @@ class SemanticsPlayer {
                                  [&](const typename Decoder::BitmanipImmArgs& args) {
                                    switch (args.opcode) {
                                      case Decoder::BitmanipImmOpcode::kClz:
-                                       return listener_->template Clz<int64_t>(arg);
+                                       return listener_->Clz(arg, kType<int64_t>);
                                      case Decoder::BitmanipImmOpcode::kCpop:
-                                       return listener_->template Cpop<int64_t>(arg);
+                                       return listener_->Cpop(arg, kType<int64_t>);
                                      case Decoder::BitmanipImmOpcode::kCtz:
-                                       return listener_->template Ctz<int64_t>(arg);
+                                       return listener_->Ctz(arg, kType<int64_t>);
                                      case Decoder::BitmanipImmOpcode::kSextb:
-                                       return listener_->template Sext<int8_t>(arg);
+                                       return listener_->Sext(arg, kType<int8_t>);
                                      case Decoder::BitmanipImmOpcode::kSexth:
-                                       return listener_->template Sext<int16_t>(arg);
+                                       return listener_->Sext(arg, kType<int16_t>);
                                      case Decoder::BitmanipImmOpcode::kOrcb:
                                        return listener_->Orcb(arg);
                                      case Decoder::BitmanipImmOpcode::kRev8:
@@ -822,11 +842,11 @@ class SemanticsPlayer {
                                  [&](const typename Decoder::BitmanipImm32Args& args) {
                                    switch (args.opcode) {
                                      case Decoder::BitmanipImm32Opcode::kClzw:
-                                       return listener_->template Clz<int32_t>(arg);
+                                       return listener_->Clz(arg, kType<int32_t>);
                                      case Decoder::BitmanipImm32Opcode::kCpopw:
-                                       return listener_->template Cpop<int32_t>(arg);
+                                       return listener_->Cpop(arg, kType<int32_t>);
                                      case Decoder::BitmanipImm32Opcode::kCtzw:
-                                       return listener_->template Ctz<int32_t>(arg);
+                                       return listener_->Ctz(arg, kType<int32_t>);
                                      case Decoder::BitmanipImm32Opcode::kRoriw:
                                        return listener_->Roriw(arg, args.shamt);
                                      case Decoder::BitmanipImm32Opcode::kSlliuw:
@@ -969,6 +989,35 @@ class SemanticsPlayer {
 
   void Undefined() { listener_->Undefined(); };
 
+  template <typename ValueType>
+  static constexpr auto ToFloat(ValueType value) {
+    return TemplateTypeIdToFloat(value);
+  }
+  template <typename ValueType>
+  static constexpr auto ToInt(ValueType value) {
+    return TemplateTypeIdToInt(value);
+  }
+  template <typename ValueType>
+  static constexpr auto ToNarrow(ValueType value) {
+    return TemplateTypeIdToNarrow(value);
+  }
+  template <typename ValueType>
+  static constexpr auto ToSigned(ValueType value) {
+    return TemplateTypeIdToSigned(value);
+  }
+  template <typename ValueType>
+  static constexpr auto SizeOf(ValueType value) {
+    return TemplateTypeIdSizeOf(value);
+  }
+  template <typename ValueType>
+  static constexpr auto ToUnsigned(ValueType value) {
+    return TemplateTypeIdToUnsigned(value);
+  }
+  template <typename ValueType>
+  static constexpr auto ToWide(ValueType value) {
+    return TemplateTypeIdToWide(value);
+  }
+
  private:
   Register GetRegOrZero(uint8_t reg) {
     return reg == 0 ? listener_->GetImm(0) : listener_->GetReg(reg);
@@ -980,74 +1029,26 @@ class SemanticsPlayer {
     }
   }
 
-  // TODO(b/260725458): stop using GetCsrProcessor helper class and define lambda in GetCsr instead.
-  // We need C++20 (https://wg21.link/P0428R2) for that.
-  class GetCsrProcessor {
-   public:
-    GetCsrProcessor(Register& reg, SemanticsListener* listener) : reg_(reg), listener_(listener) {}
-    template <CsrName kName>
-    void operator()() {
-      reg_ = listener_->template GetCsr<kName>();
-    }
-
-   private:
-    Register& reg_;
-    SemanticsListener* listener_;
-  };
-
   std::tuple<bool, Register> GetCsr(CsrName csr) {
     Register reg = no_register;
-    GetCsrProcessor get_csr(reg, listener_);
-    return {ProcessCsrNameAsTemplateParameter(csr, get_csr), reg};
+    bool success = ProcessCsrNameAsTemplateParameter(
+        csr, [&reg, this]<CsrName kName> { reg = listener_->template GetCsr<kName>(); });
+    return {success, reg};
   }
 
-  // TODO(b/260725458): stop using SetCsrProcessor helper class and define lambda in SetCsr instead.
-  // We need C++20 (https://wg21.link/P0428R2) for that.
-  class SetCsrImmProcessor {
-   public:
-    SetCsrImmProcessor(uint8_t imm, SemanticsListener* listener) : imm_(imm), listener_(listener) {}
-    template <CsrName kName>
-    void operator()() {
-      // Csr registers with two top bits set are read-only.
-      // Attempts to write into such register raise illegal instruction exceptions.
-      if constexpr (CsrWritable(kName)) {
-        listener_->template SetCsr<kName>(imm_);
-      }
-    }
-
-   private:
-    uint8_t imm_;
-    SemanticsListener* listener_;
-  };
-
   bool SetCsr(CsrName csr, uint8_t imm) {
     // Csr registers with two top bits set are read-only.
     // Attempts to write into such register raise illegal instruction exceptions.
     if (!CsrWritable(csr)) {
       return false;
     }
-    SetCsrImmProcessor set_csr(imm, listener_);
-    return ProcessCsrNameAsTemplateParameter(csr, set_csr);
-  }
-
-  // TODO(b/260725458): stop using SetCsrProcessor helper class and define lambda in SetCsr instead.
-  // We need C++20 (https://wg21.link/P0428R2) for that.
-  class SetCsrProcessor {
-   public:
-    SetCsrProcessor(Register reg, SemanticsListener* listener) : reg_(reg), listener_(listener) {}
-    template <CsrName kName>
-    void operator()() {
-      // Csr registers with two top bits set are read-only.
-      // Attempts to write into such register raise illegal instruction exceptions.
+    // SetCsrImmProcessor set_csr(imm, listener_);
+    return ProcessCsrNameAsTemplateParameter(csr, [imm, this]<CsrName kName> {
       if constexpr (CsrWritable(kName)) {
-        listener_->template SetCsr<kName>(reg_);
+        listener_->template SetCsr<kName>(imm);
       }
-    }
-
-   private:
-    Register reg_;
-    SemanticsListener* listener_;
-  };
+    });
+  }
 
   bool SetCsr(CsrName csr, Register reg) {
     // Csr registers with two top bits set are read-only.
@@ -1055,8 +1056,11 @@ class SemanticsPlayer {
     if (!CsrWritable(csr)) {
       return false;
     }
-    SetCsrProcessor set_csr(reg, listener_);
-    return ProcessCsrNameAsTemplateParameter(csr, set_csr);
+    return ProcessCsrNameAsTemplateParameter(csr, [&reg, this]<CsrName kName> {
+      if constexpr (CsrWritable(kName)) {
+        listener_->template SetCsr<kName>(reg);
+      }
+    });
   }
 
   // Floating point instructions in RISC-V are encoded in a way where you may find out size of
@@ -1085,7 +1089,7 @@ class SemanticsPlayer {
   // Step #3.
   template <typename FloatType>
   FpRegister CanonicalizeNan(FpRegister value) {
-    return listener_->template CanonicalizeNan<FloatType>(value);
+    return listener_->CanonicalizeNan(value, kType<FloatType>);
   }
 
   // Step #4. Note the assymetry: step #1 may skip the NaN unboxing (would use GetFpReg if so),
diff --git a/device_arch_info/Android.bp b/device_arch_info/Android.bp
new file mode 100644
index 00000000..f24803b6
--- /dev/null
+++ b/device_arch_info/Android.bp
@@ -0,0 +1,142 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+python_binary_host {
+    name: "gen_device_insn_info",
+    main: "gen_device_insn_info.py",
+    srcs: ["gen_device_insn_info.py"],
+    libs: ["gen_device_insn_info_lib"],
+}
+
+python_library_host {
+    name: "gen_device_insn_info_lib",
+    srcs: ["gen_device_insn_info_lib.py"],
+    libs: ["asm_defs_lib"],
+}
+
+python_binary_host {
+    name: "gen_reg_class",
+    main: "gen_reg_class.py",
+    srcs: ["gen_reg_class.py"],
+    libs: ["gen_reg_class_lib"],
+}
+
+python_library_host {
+    name: "gen_reg_class_lib",
+    srcs: ["gen_reg_class_lib.py"],
+}
+
+filegroup {
+    name: "libberberis_device_arch_info_reg_class_gen_inputs_riscv64",
+    srcs: ["riscv64/reg_class_def.json"],
+}
+
+filegroup {
+    name: "libberberis_device_arch_info_reg_class_gen_inputs_x86_32",
+    srcs: ["x86_32/reg_class_def.json"],
+}
+
+filegroup {
+    name: "libberberis_device_arch_info_reg_class_gen_inputs_x86_64",
+    srcs: ["x86_64/reg_class_def.json"],
+}
+
+genrule {
+    name: "libberberis_device_arch_info_device_insn_info_gen_headers_x86_32",
+    out: [
+        "berberis/device_arch_info/x86_32_or_x86_64/device_insn_info-inl.h",
+        "berberis/device_arch_info/x86_32/device_insn_info-inl.h",
+        "berberis/device_arch_info/all_to_x86_32_or_x86_64/device_insn_info-inl.h",
+    ],
+    srcs: [
+        ":libberberis_assembler_gen_inputs_x86_32",
+        ":libberberis_macro_assembler_gen_inputs_all_to_x86_32_or_x86_64",
+    ],
+    tools: ["gen_device_insn_info"],
+    cmd: "$(location gen_device_insn_info) $(out) $(in)",
+}
+
+genrule {
+    name: "libberberis_device_arch_info_device_insn_info_gen_headers_x86_64",
+    out: [
+        "berberis/device_arch_info/x86_32_or_x86_64/device_insn_info-inl.h",
+        "berberis/device_arch_info/x86_64/device_insn_info-inl.h",
+        "berberis/device_arch_info/all_to_x86_32_or_x86_64/device_insn_info-inl.h",
+        "berberis/device_arch_info/all_to_x86_64/device_insn_info-inl.h",
+    ],
+    srcs: [
+        ":libberberis_assembler_gen_inputs_x86_64",
+        ":libberberis_macro_assembler_gen_inputs_all_to_x86_64",
+    ],
+    tools: ["gen_device_insn_info"],
+    cmd: "$(location gen_device_insn_info) $(out) $(in)",
+}
+
+genrule {
+    name: "libberberis_device_arch_info_reg_class_gen_headers_riscv64",
+    out: ["berberis/device_arch_info/riscv64/machine_reg_class-inl.h"],
+    srcs: [":libberberis_device_arch_info_reg_class_gen_inputs_riscv64"],
+    tools: ["gen_reg_class"],
+    cmd: "$(location gen_reg_class) $(out) $(in)",
+}
+
+genrule {
+    name: "libberberis_device_arch_info_reg_class_gen_headers_x86_32",
+    out: ["berberis/device_arch_info/x86_32/machine_reg_class-inl.h"],
+    srcs: [":libberberis_device_arch_info_reg_class_gen_inputs_x86_32"],
+    tools: ["gen_reg_class"],
+    cmd: "$(location gen_reg_class) $(out) $(in)",
+}
+
+genrule {
+    name: "libberberis_device_arch_info_reg_class_gen_headers_x86_64",
+    out: ["berberis/device_arch_info/x86_64/machine_reg_class-inl.h"],
+    srcs: [":libberberis_device_arch_info_reg_class_gen_inputs_x86_64"],
+    tools: ["gen_reg_class"],
+    cmd: "$(location gen_reg_class) $(out) $(in)",
+}
+
+cc_library_headers {
+    name: "libberberis_device_arch_info_headers",
+    defaults: ["berberis_all_hosts_defaults"],
+    host_supported: true,
+    export_include_dirs: ["include"],
+    header_libs: [
+        "libberberis_assembler_headers",
+        "libberberis_base_headers",
+    ],
+    generated_headers: [
+        "libberberis_device_arch_info_device_insn_info_gen_headers_x86_32",
+        "libberberis_device_arch_info_device_insn_info_gen_headers_x86_64",
+        "libberberis_device_arch_info_reg_class_gen_headers_riscv64",
+        "libberberis_device_arch_info_reg_class_gen_headers_x86_32",
+        "libberberis_device_arch_info_reg_class_gen_headers_x86_64",
+    ],
+    export_header_lib_headers: [
+        "libberberis_assembler_headers",
+        "libberberis_base_headers",
+    ],
+    export_generated_headers: [
+        "libberberis_device_arch_info_device_insn_info_gen_headers_x86_32",
+        "libberberis_device_arch_info_device_insn_info_gen_headers_x86_64",
+        "libberberis_device_arch_info_reg_class_gen_headers_riscv64",
+        "libberberis_device_arch_info_reg_class_gen_headers_x86_32",
+        "libberberis_device_arch_info_reg_class_gen_headers_x86_64",
+    ],
+}
diff --git a/device_arch_info/gen_device_insn_info.py b/device_arch_info/gen_device_insn_info.py
new file mode 100644
index 00000000..825d162e
--- /dev/null
+++ b/device_arch_info/gen_device_insn_info.py
@@ -0,0 +1,60 @@
+#!/usr/bin/python
+#
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Generate device_insn_info files out of the definition file.
+
+See the full description of format in gen_device_insn_info_lib.py
+
+"""
+
+import gen_device_insn_info_lib
+import sys
+
+
+INDENT = '  '
+AUTOGEN = """\
+// This file automatically generated by gen_device_insn_info.py
+// DO NOT EDIT!
+"""
+
+
+def main(argv):
+  # Usage:
+  #   gen_device_insn_info.py <device_insn_info-inl.h>
+  #                           ...
+  #                           <def>
+  #                           ...
+  #        Note: there should be equal number of inputs and outputes,
+  #              one file on input is translated to one file in output.
+
+  assert len(argv) % 2 == 1
+  filenames = argv[1:]
+  filename_pairs = ((filenames[i], filenames[len(filenames)//2 + i])
+                    for i in range(0, len(filenames)//2))
+
+  assemblers = 0
+  for out_filename, input_filename in filename_pairs:
+    with open(out_filename, 'w') as out_file:
+      print(AUTOGEN, file=out_file)
+      insns = gen_device_insn_info_lib._load_lir_def(input_filename, assemblers)
+      gen_device_insn_info_lib._gen_device_insn_info(out_file, insns)
+    assemblers += 1
+
+  return 0
+
+
+if __name__ == '__main__':
+  sys.exit(main(sys.argv))
diff --git a/device_arch_info/gen_device_insn_info_lib.py b/device_arch_info/gen_device_insn_info_lib.py
new file mode 100644
index 00000000..7cd7bcc9
--- /dev/null
+++ b/device_arch_info/gen_device_insn_info_lib.py
@@ -0,0 +1,174 @@
+#!/usr/bin/python
+#
+# Copyright (C) 2025 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Generate device_insn_info files out of the definition file.
+
+* Operand usage
+
+Register allocator needs operand usage to learn which operands can share the
+same register.
+
+To understand register sharing options, register allocator assumes insn works
+in these steps:
+- read input operands
+- do the job
+- write output operands
+
+So, input-output operands should have dedicated registers, while input-only
+operands can share registers with output-only operands.
+
+There might be an exception when output-only operand is written before all
+input-only operands are read, so its register can't be shared. Such operands
+are usually referred as output-only-early-clobber operands.
+
+For register sharing, output-only-early-clobber operand is the same as
+input-output operand, but it is unnatural to describe output-only as
+input-output, so we use a special keyword for it.
+
+Finally, keywords are:
+use - input-only
+def - output-only
+def_early_clobber - output-only-early-clobber
+use_def - input-output
+
+* Scratch operands
+
+Scratch operands are actually output operands - indeed, their original value
+is not used and they get some new value after the insn is done. However, they
+are usually written before all input operands are read, so it makes sense to
+describe scratch operands as output-only-early-clobber.
+"""
+
+import asm_defs
+import json
+import sys
+
+
+def _gen_device_insn_info(f, insns):
+  for insn in insns:
+    print ("""
+template <typename MacroAssemblers>
+class %s {
+ public:
+  using DeviceInsnInfo = device_arch_info::DeviceInsnInfo<%s>;
+};""" % (
+      insn['name'],
+      ',\n                  '.join(
+        [_get_asm_reference(insn),
+       '"%s"' % insn['mnemo'],
+       # Int3, Lfence, Mfence, Sfence, and UD2 have side effects not related to arguments.
+       # TODO: decide if we still need it (currently MachineIR treats all instructions without
+       # operands as volatile).
+       'true' if insn['name'] in ('Int3', 'Lfence', 'Mfence', 'Sfence', 'UD2') or
+                 any(asm_defs.is_mem_op(arg['class']) and arg['usage'] != 'use'
+                     for arg in insn['args']) else 'false',
+       _get_opcode_reference(insn),
+       _get_cpuid_restriction(insn),
+       _get_reg_operands_info(insn['args'])])),  file=f)
+
+
+def _get_asm_type(asm, prefix):
+  args = filter(
+    lambda arg: not asm_defs.is_implicit_reg(arg['class']), asm['args'])
+  return ', '.join(_get_asm_operand_type(arg, prefix) for arg in args)
+
+
+def _get_asm_operand_type(arg, prefix):
+  cls = arg.get('class')
+  if asm_defs.is_cond(cls):
+    return prefix + 'Condition'
+  if asm_defs.is_label(cls):
+    return prefix + 'Label'
+  if asm_defs.is_x87reg(cls):
+    return prefix + 'X87Register'
+  if asm_defs.is_greg(cls):
+    return prefix + 'Register'
+  if asm_defs.is_xreg(cls):
+    return prefix + 'XMMRegister'
+  if asm_defs.is_yreg(cls):
+    return prefix + 'YMMRegister'
+  if asm_defs.is_mem_op(cls):
+    return 'const ' + prefix + 'Operand&'
+  if asm_defs.is_imm(cls):
+    if cls == 'Imm2':
+      return 'int8_t'
+    return 'int' + cls[3:] + '_t'
+  assert False, f"Unknown asm operand type: {arg}"
+
+
+def _get_asm_reference(asm):
+  # Because of misfeature of Itanium C++ ABI we couldn't just use MacroAssembler
+  # to static cast these references if we want to use them as template argument:
+  # https://ibob.bg/blog/2018/08/18/a-bug-in-the-cpp-standard/
+
+  # Thankfully there are usually no need to use the same trick for MacroInstructions
+  # since we may always rename these, except when immediates are involved.
+
+  # But for assembler we need to use actual type from where these
+  # instructions come from!
+  #
+  # E.g. LZCNT have to be processed like this:
+  #   static_cast<void (Assembler_common_x86::*)(
+  #     typename Assembler_common_x86::Register,
+  #     typename Assembler_common_x86::Register)>(
+  #       &Assembler_common_x86::Lzcntl)
+  assembler = 'std::tuple_element_t<%s, MacroAssemblers>' % asm['macroassembler']
+  return 'static_cast<void (%s::*)(%s)>(%s&%s::%s%s)' % (
+      assembler,
+      _get_asm_type(asm, 'typename %s::' % assembler),
+      '\n                  ',
+      assembler,
+      'template ' if '<' in asm['asm'] else '',
+      asm['asm'])
+
+
+def _get_cpuid_restriction(asm):
+  cpuid_restriction = 'device_arch_info::NoCPUIDRestriction'
+  if 'feature' in asm:
+    if asm['feature'] == 'AuthenticAMD':
+      cpuid_restriction = 'device_arch_info::IsAuthenticAMD'
+    else:
+      cpuid_restriction = 'device_arch_info::Has%s' % asm['feature']
+  return cpuid_restriction
+
+
+def _get_opcode_reference(asm):
+  return f"[]<typename Opcode>{{ return Opcode::kMachineOp{asm['name']}; }}"
+
+
+def _get_reg_operands_info(args):
+  return 'std::tuple<%s>' % ', '.join(_get_reg_operand_info(arg) for arg in args)
+
+
+def _get_reg_operand_info(arg):
+  class_info = 'device_arch_info::%s' % arg['class']
+  if arg['class'] in ('Cond', 'Imm2', 'Imm8', 'Imm16', 'Imm32', 'Imm64', 'Label'):
+    return 'device_arch_info::OperandInfo<%s, device_arch_info::kUse>' % class_info
+  assert 'usage' in arg, f"Unknown asm operand without 'usage'"
+  using_info = 'device_arch_info::%s' % {
+      'def': 'kDef',
+      'def_early_clobber': 'kDefEarlyClobber',
+      'use': 'kUse',
+      'use_def': 'kUseDef'
+  }[arg['usage']]
+  return 'device_arch_info::OperandInfo<%s, %s>' % (class_info, using_info)
+
+
+def _load_lir_def(asm_def, macroassembler):
+  _, insns = asm_defs.load_asm_defs(asm_def)
+  for insn in insns:
+    insn['macroassembler'] = macroassembler
+  return insns
diff --git a/backend/gen_reg_class.py b/device_arch_info/gen_reg_class.py
old mode 100755
new mode 100644
similarity index 100%
rename from backend/gen_reg_class.py
rename to device_arch_info/gen_reg_class.py
diff --git a/device_arch_info/gen_reg_class_lib.py b/device_arch_info/gen_reg_class_lib.py
new file mode 100644
index 00000000..44734d6c
--- /dev/null
+++ b/device_arch_info/gen_reg_class_lib.py
@@ -0,0 +1,67 @@
+#!/usr/bin/python3
+#
+# Copyright (C) 2023 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Generate machine IR register class definitions from data file."""
+
+def gen_machine_reg_class_inc(f, reg_classes):
+  for reg_class in reg_classes:
+    print(f'class {reg_class.get('name')};', file=f)
+  for reg_class in reg_classes:
+    name = reg_class.get('name')
+    regs = reg_class.get('regs')
+    size = reg_class.get('size') * 8
+    print(f'class {name} {{', file=f)
+    print(' public:', file=f)
+    print(f'  static constexpr const char* kName = "{name}";', file=f)
+    print('  static constexpr size_t kSizeInBits = %d;' % size, file=f)
+    print('  using RegistersList = std::tuple<%s>;' % ', '.join(regs), file=f)
+    if 'gcc_asm_name' in reg_class:
+      if 'type' in reg_class:
+        print('  using Type = %s;' % reg_class['type'], file=f)
+      elif size == 128:
+        print('  using Type = __m128;', file=f)
+      elif size == 256:
+        print('#ifdef __AVX__', file=f)
+        print('  using Type = __m256;', file=f)
+        print('#endif', file=f)
+      else:
+        print('  using Type = uint%d_t;' % size, file=f)
+      gcc_asm_name = reg_class.get('gcc_asm_name')
+      print(f'  static constexpr char kAsRegister = \'{gcc_asm_name}\';', file=f)
+    else:
+      # std::conditional_t requires type even for branch that wouldn't be taken.
+      # Use of `void` as type here means it would be compatible with that logic,
+      # but would exclude most accidental uses of it because `void` can not be used
+      # to declare arguments of functions, or local variables.
+      print('  using Type = void;', file=f)
+    if len(regs) == 1:
+      print('  template <typename Assembler>', file=f)
+      print('  static constexpr auto kAssemblerRegisterPointer = '
+            f'&Assembler::gpr_{gcc_asm_name};', file=f)
+    print('  template <typename MachineRegDefinitions>', file=f)
+    print('  static constexpr auto kMachineRegId = '
+          f'MachineRegDefinitions::k{name};', file=f)
+    print('};', file=f)
+
+
+def expand_aliases(reg_classes):
+  expanded = {}
+  for reg_class in reg_classes:
+    expanded_regs = []
+    for r in reg_class.get('regs'):
+      expanded_regs.extend(expanded.get(r, [r]))
+    reg_class['regs'] = expanded_regs
+    expanded[reg_class.get('name')] = expanded_regs
diff --git a/device_arch_info/include/berberis/device_arch_info/common/device_arch_info.h b/device_arch_info/include/berberis/device_arch_info/common/device_arch_info.h
new file mode 100644
index 00000000..66b3d0be
--- /dev/null
+++ b/device_arch_info/include/berberis/device_arch_info/common/device_arch_info.h
@@ -0,0 +1,183 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_DEVICE_ARCH_INFO_COMMON_DEVICE_ARCH_INFO_H_
+#define BERBERIS_DEVICE_ARCH_INFO_COMMON_DEVICE_ARCH_INFO_H_
+
+#include <cstdint>
+
+#include "berberis/base/string_literal.h"
+
+namespace berberis::device_arch_info {
+
+class Mem8 {
+ public:
+  using Type = uint8_t;
+  static constexpr char kAsRegister = 'm';
+};
+
+class Mem16 {
+ public:
+  using Type = uint16_t;
+  static constexpr char kAsRegister = 'm';
+};
+
+class Mem32 {
+ public:
+  using Type = uint32_t;
+  static constexpr char kAsRegister = 'm';
+};
+
+class Mem64 {
+ public:
+  using Type = uint64_t;
+  static constexpr char kAsRegister = 'm';
+};
+
+template <typename OperandClass, typename = void>
+inline constexpr bool kIsCondition = false;
+
+template <typename OperandClass, typename = void>
+inline constexpr bool kIsFLAGS = false;
+
+template <typename OperandClass, typename = void>
+inline constexpr bool kIsGeneralReg32 = false;
+
+template <typename OperandClass, typename = void>
+inline constexpr bool kIsImmediate = false;
+
+template <typename OperandClass, typename = void>
+inline constexpr bool kIsMemoryOperand = false;
+
+template <typename OperandClass, typename = void>
+inline constexpr bool kIsRegister =
+    !kIsCondition<OperandClass> && !kIsImmediate<OperandClass> && !kIsMemoryOperand<OperandClass>;
+
+template <typename OperandClass, typename = void>
+inline constexpr bool kIsImplicitReg = false;
+
+template <typename OperandClass>
+inline constexpr bool
+    kIsCondition<OperandClass, std::enable_if_t<sizeof(typename OperandClass::Class) >= 1>> =
+        kIsCondition<typename OperandClass::Class>;
+
+template <typename OperandClass>
+inline constexpr bool
+    kIsFLAGS<OperandClass, std::enable_if_t<sizeof(typename OperandClass::Class) >= 1>> =
+        kIsFLAGS<typename OperandClass::Class>;
+
+template <typename OperandClass>
+inline constexpr bool
+    kIsGeneralReg32<OperandClass, std::enable_if_t<sizeof(typename OperandClass::Class) >= 1>> =
+        kIsGeneralReg32<typename OperandClass::Class>;
+
+template <typename OperandClass>
+inline constexpr bool
+    kIsImmediate<OperandClass, std::enable_if_t<sizeof(typename OperandClass::Class) >= 1>> =
+        kIsImmediate<typename OperandClass::Class>;
+
+template <typename RegisterClass>
+inline constexpr bool kIsImplicitReg<
+    RegisterClass,
+    std::enable_if_t<kIsRegister<RegisterClass> &&
+                     std::tuple_size_v<typename RegisterClass::RegistersList> == 1>> = true;
+
+template <typename OperandClass>
+inline constexpr bool
+    kIsImplicitReg<OperandClass, std::enable_if_t<sizeof(typename OperandClass::Class) >= 1>> =
+        kIsImplicitReg<typename OperandClass::Class>;
+
+template <typename OperandClass>
+inline constexpr bool
+    kIsMemoryOperand<OperandClass, std::enable_if_t<sizeof(typename OperandClass::Class) >= 1>> =
+        kIsMemoryOperand<typename OperandClass::Class>;
+
+template <>
+inline constexpr bool kIsMemoryOperand<Mem8> = true;
+
+template <>
+inline constexpr bool kIsMemoryOperand<Mem16> = true;
+
+template <>
+inline constexpr bool kIsMemoryOperand<Mem32> = true;
+
+template <>
+inline constexpr bool kIsMemoryOperand<Mem64> = true;
+
+// Note: value of RegBindingKind and MachineRegKind have to be the same since we convert one to
+// another with a static_cast in berberis/backend/x86_64/machine_insn_intrinsics.h. We don't care
+// about these values in intrinsics module, but for optimizations it's important to have LSB set
+// when an instruction uses the value (which is true for kDefEarlyClobber: in that case the
+// instruction sets the value and then uses it), the next bit is set when register is output and MSB
+// bit is set when register is input. We have static_assert in the aforemetioned header that ensures
+// that an attempt to change these two enums and make them different would lead to a compile-time
+// error.
+enum RegBindingKind { kDef = 2, kDefEarlyClobber = 3, kUse = 5, kUseDef = 7 };
+
+template <typename OperandClass, RegBindingKind kUsageTemplateName>
+class OperandInfo {
+ public:
+  using Class = OperandClass;
+  static constexpr RegBindingKind kUsage = kUsageTemplateName;
+  static_assert(!kIsImmediate<Class> || kUsage == kUse);
+};
+
+// Tag classes. They are never instantioned, only used as tags to pass information about
+// bindings.
+class NoCPUIDRestriction;  // All CPUs have at least “no CPUID restriction” mode.
+
+template <auto kEmitInsnFunc,
+          StringLiteral kMnemo,
+          bool kSideEffects,
+          auto GetOpcode,
+          typename... Types>
+class DeviceInsnInfo;
+
+template <auto kEmitInsnFunc_,
+          StringLiteral kMnemo,
+          bool kSideEffects_,
+          auto GetOpcode,
+          typename CPUIDRestriction_,
+          typename... Operands_>
+class DeviceInsnInfo<kEmitInsnFunc_,
+                     kMnemo,
+                     kSideEffects_,
+                     GetOpcode,
+                     CPUIDRestriction_,
+                     std::tuple<Operands_...>>
+    final {
+ public:
+  static constexpr auto kEmitInsnFunc = kEmitInsnFunc_;
+  static constexpr bool kSideEffects = kSideEffects_;
+  using CPUIDRestriction = CPUIDRestriction_;
+  template <typename Callback, typename... Args>
+  constexpr static void ProcessOperands(Callback&& callback, Args&&... args) {
+    (callback(Operands_{}, std::forward<Args>(args)...), ...);
+  }
+  template <typename Callback, typename... Args>
+  constexpr static bool VerifyOperands(Callback&& callback, Args&&... args) {
+    return (callback(Operands_{}, std::forward<Args>(args)...) && ...);
+  }
+  template <typename Callback, typename... Args>
+  constexpr static auto MakeTuplefromOperands(Callback&& callback, Args&&... args) {
+    return std::tuple_cat(callback(Operands_{}, std::forward<Args>(args)...)...);
+  }
+  using Operands = std::tuple<Operands_...>;
+};
+
+}  // namespace berberis::device_arch_info
+
+#endif  // BERBERIS_DEVICE_ARCH_INFO_COMMON_DEVICE_ARCH_INFO_H_
diff --git a/device_arch_info/include/berberis/device_arch_info/riscv64/device_arch_info.h b/device_arch_info/include/berberis/device_arch_info/riscv64/device_arch_info.h
new file mode 100644
index 00000000..c14662ba
--- /dev/null
+++ b/device_arch_info/include/berberis/device_arch_info/riscv64/device_arch_info.h
@@ -0,0 +1,116 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_DEVICE_ARCH_INFO_RISCV64_DEVICE_ARCH_INFO_H_
+#define BERBERIS_DEVICE_ARCH_INFO_RISCV64_DEVICE_ARCH_INFO_H_
+
+#include <cstdint>
+
+#include "berberis/assembler/riscv.h"
+#include "berberis/device_arch_info/common/device_arch_info.h"
+
+namespace berberis {
+
+namespace riscv64::device_arch_info {
+
+// Note: normally using namespace is forbidden in headers, but these two namespaces literally
+// only exist to be imported here (and in other device CPU-specific headers).
+
+using namespace berberis::device_arch_info;
+
+class BImm {
+ public:
+  using Type = riscv::BImmediate;
+};
+
+class CsrImm {
+ public:
+  using Type = riscv::CsrImmediate;
+};
+
+class IImm {
+ public:
+  using Type = riscv::IImmediate;
+};
+
+class JImm {
+ public:
+  using Type = riscv::JImmediate;
+};
+
+class PImm {
+ public:
+  using Type = riscv::PImmediate;
+};
+
+class SImm {
+ public:
+  using Type = riscv::SImmediate;
+};
+
+class Shift32Imm {
+ public:
+  using Type = riscv::Shift32Immediate;
+};
+
+class Shift64Imm {
+ public:
+  using Type = riscv::Shift64Immediate;
+};
+
+class UImm {
+ public:
+  using Type = riscv::UImmediate;
+};
+
+#include "berberis/device_arch_info/riscv64/machine_reg_class-inl.h"
+
+}  // namespace riscv64::device_arch_info
+
+namespace device_arch_info {
+
+template <>
+inline constexpr bool kIsImmediate<riscv64::device_arch_info::BImm> = true;
+
+template <>
+inline constexpr bool kIsImmediate<riscv64::device_arch_info::CsrImm> = true;
+
+template <>
+inline constexpr bool kIsImmediate<riscv64::device_arch_info::IImm> = true;
+
+template <>
+inline constexpr bool kIsImmediate<riscv64::device_arch_info::JImm> = true;
+
+template <>
+inline constexpr bool kIsImmediate<riscv64::device_arch_info::PImm> = true;
+
+template <>
+inline constexpr bool kIsImmediate<riscv64::device_arch_info::SImm> = true;
+
+template <>
+inline constexpr bool kIsImmediate<riscv64::device_arch_info::Shift32Imm> = true;
+
+template <>
+inline constexpr bool kIsImmediate<riscv64::device_arch_info::Shift64Imm> = true;
+
+template <>
+inline constexpr bool kIsImmediate<riscv64::device_arch_info::UImm> = true;
+
+}  // namespace device_arch_info
+
+}  // namespace berberis
+
+#endif  // BERBERIS_DEVICE_ARCH_INFO_RISCV64_DEVICE_ARCH_INFO_H_
diff --git a/device_arch_info/include/berberis/device_arch_info/x86_32/device_arch_info.h b/device_arch_info/include/berberis/device_arch_info/x86_32/device_arch_info.h
new file mode 100644
index 00000000..bb1650d6
--- /dev/null
+++ b/device_arch_info/include/berberis/device_arch_info/x86_32/device_arch_info.h
@@ -0,0 +1,77 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_DEVICE_ARCH_INFO_X86_32_DEVICE_ARCH_INFO_H_
+#define BERBERIS_DEVICE_ARCH_INFO_X86_32_DEVICE_ARCH_INFO_H_
+
+#include <x86intrin.h>
+
+#include <cstdint>
+
+#include "berberis/assembler/x86_32.h"
+#include "berberis/device_arch_info/x86_32_or_x86_64/device_arch_info.h"
+
+namespace berberis {
+
+namespace x86_32 {
+
+namespace device_arch_info {
+
+// Note: normally using namespace is forbidden in headers, but these two namespaces literally
+// only exist to be imported here (and in other device CPU-specific headers).
+
+using namespace berberis::x86_32_or_x86_64::device_arch_info;
+
+class Cond {
+ public:
+  using Type = x86_32_or_x86_64::Assembler<x86_64::Assembler>::Condition;
+};
+
+// We don't currently have use-cases where call may be embedded into MachineIR and we don't know how
+// to properly handle it.
+// We would need to make this class “real” to be able to do that, but also would probably need
+// other changes.
+class ESP;
+
+#include "berberis/device_arch_info/x86_32/machine_reg_class-inl.h"
+
+}  // namespace device_arch_info
+
+#include "berberis/device_arch_info/all_to_x86_32_or_x86_64/device_insn_info-inl.h"
+#include "berberis/device_arch_info/x86_32/device_insn_info-inl.h"
+#include "berberis/device_arch_info/x86_32_or_x86_64/device_insn_info-inl.h"
+
+}  // namespace x86_32
+
+namespace device_arch_info {
+
+template <>
+inline constexpr bool kIsCondition<x86_32::device_arch_info::Cond> = true;
+
+template <>
+inline constexpr bool kIsGeneralReg32<x86_32::device_arch_info::GeneralReg32> = true;
+
+template <>
+inline constexpr bool kIsFLAGS<x86_32::device_arch_info::FLAGS> = true;
+
+template <>
+inline constexpr bool kIsRegister<x86_32::device_arch_info::FLAGS> = true;
+
+}  // namespace device_arch_info
+
+}  // namespace berberis
+
+#endif  // BERBERIS_DEVICE_ARCH_INFO_X86_32_DEVICE_ARCH_INFO_H_
diff --git a/device_arch_info/include/berberis/device_arch_info/x86_32_or_x86_64/device_arch_info.h b/device_arch_info/include/berberis/device_arch_info/x86_32_or_x86_64/device_arch_info.h
new file mode 100644
index 00000000..69e3f52f
--- /dev/null
+++ b/device_arch_info/include/berberis/device_arch_info/x86_32_or_x86_64/device_arch_info.h
@@ -0,0 +1,215 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_DEVICE_ARCH_INFO_ALL_TO_X86_32_OR_x86_64_DEVICE_ARCH_INFO_H_
+#define BERBERIS_DEVICE_ARCH_INFO_ALL_TO_X86_32_OR_x86_64_DEVICE_ARCH_INFO_H_
+
+#include <x86intrin.h>
+
+#include <cstdint>
+
+#include "berberis/device_arch_info/common/device_arch_info.h"
+
+// Note: normally using namespace is forbidden in headers, but these two namespaces literally
+// only exist to be imported here (and in other device CPU-specific headers).
+
+namespace berberis {
+
+namespace x86_32_or_x86_64::device_arch_info {
+
+using namespace berberis::device_arch_info;
+
+class Imm2 {
+ public:
+  using Type = int8_t;
+};
+
+class Imm8 {
+ public:
+  using Type = int8_t;
+};
+
+class Imm16 {
+ public:
+  using Type = int16_t;
+};
+
+class Imm32 {
+ public:
+  using Type = int32_t;
+};
+
+class Imm64 {
+ public:
+  using Type = int64_t;
+};
+
+class MemX87 {
+ public:
+  // MemX87 can only be used as temporary argument, but having type here simplifies metaprogramming:
+  // it can not be used as actual type of variable or parameter, but can be used with
+  // std::conditional_t to pick some other type.
+  using Type = void;
+  static constexpr bool kIsImmediate = false;
+  static constexpr char kAsRegister = 'm';
+};
+
+class VecMem32 {
+ public:
+  using Type = uint32_t;
+  static constexpr char kAsRegister = 'm';
+};
+
+class VecMem64 {
+ public:
+  using Type = uint64_t;
+  static constexpr char kAsRegister = 'm';
+};
+
+class VecMem128 {
+ public:
+  using Type = __m128;
+  static constexpr char kAsRegister = 'm';
+};
+
+class VecMem256 {
+ public:
+#ifdef __AVX__
+  using Type = __m256;
+#endif
+  static constexpr char kAsRegister = 'm';
+};
+
+// We don't currently have use-cases where instructions that use these register classes can be used
+// with MachineIR.
+// We would need to make this classes “real” to be able to do that, but also would probably need
+// other changes.
+class CC;
+class GeneralReg;
+class Label;
+class Mem;
+class MemX8716;
+class MemX8732;
+class MemX8764;
+class MemX8780;
+class RSP;
+class RegX87;
+class SW;
+class ST;
+class ST1;
+
+// Tag classes. They are never instantioned, only used as tags to pass information about
+// bindings.
+class Has3DNOW;
+class Has3DNOWP;
+class HasADX;
+class HasAES;
+class HasAESAVX;
+class HasAMXBF16;
+class HasAMXFP16;
+class HasAMXINT8;
+class HasAMXTILE;
+class HasAVX;
+class HasAVX2;
+class HasAVX5124FMAPS;
+class HasAVX5124VNNIW;
+class HasAVX512BF16;
+class HasAVX512BITALG;
+class HasAVX512BW;
+class HasAVX512CD;
+class HasAVX512DQ;
+class HasAVX512ER;
+class HasAVX512F;
+class HasAVX512FP16;
+class HasAVX512IFMA;
+class HasAVX512PF;
+class HasAVX512VBMI;
+class HasAVX512VBMI2;
+class HasAVX512VL;
+class HasAVX512VNNI;
+class HasAVX512VPOPCNTDQ;
+class HasBMI;
+class HasBMI2;
+class HasCLMUL;
+class HasCLMULAVX;
+class HasCMOV;
+class HasCMPXCHG16B;
+class HasCMPXCHG8B;
+class HasF16C;
+class HasFMA;
+class HasFMA4;
+class HasFXSAVE;
+class HasLZCNT;
+// BMI2 is set and PDEP/PEXT are ok to use. See more here:
+//   https://twitter.com/instlatx64/status/1322503571288559617
+class HashPDEP;
+class HasPOPCNT;
+class HasRDSEED;
+class HasSERIALIZE;
+class HasSHA;
+class HasSSE;
+class HasSSE2;
+class HasSSE3;
+class HasSSE4_1;
+class HasSSE4_2;
+class HasSSE4a;
+class HasSSSE3;
+class HasTBM;
+class HasVAES;
+class HasVPCLMULQD;
+class HasX87;
+class HasCustomCapability;
+class IsAuthenticAMD;
+
+}  // namespace x86_32_or_x86_64::device_arch_info
+
+namespace device_arch_info {
+
+template <>
+inline constexpr bool kIsImmediate<x86_32_or_x86_64::device_arch_info::Imm2> = true;
+
+template <>
+inline constexpr bool kIsImmediate<x86_32_or_x86_64::device_arch_info::Imm8> = true;
+
+template <>
+inline constexpr bool kIsImmediate<x86_32_or_x86_64::device_arch_info::Imm16> = true;
+
+template <>
+inline constexpr bool kIsImmediate<x86_32_or_x86_64::device_arch_info::Imm32> = true;
+
+template <>
+inline constexpr bool kIsImmediate<x86_32_or_x86_64::device_arch_info::Imm64> = true;
+
+template <>
+inline constexpr bool kIsMemoryOperand<x86_32_or_x86_64::device_arch_info::MemX87> = true;
+
+template <>
+inline constexpr bool kIsMemoryOperand<x86_32_or_x86_64::device_arch_info::VecMem32> = true;
+
+template <>
+inline constexpr bool kIsMemoryOperand<x86_32_or_x86_64::device_arch_info::VecMem64> = true;
+
+template <>
+inline constexpr bool kIsMemoryOperand<x86_32_or_x86_64::device_arch_info::VecMem128> = true;
+
+template <>
+inline constexpr bool kIsMemoryOperand<x86_32_or_x86_64::device_arch_info::VecMem256> = true;
+
+}  // namespace device_arch_info
+
+}  // namespace berberis
+
+#endif  // BERBERIS_DEVICE_ARCH_INFO_ALL_TO_X86_32_OR_x86_64_DEVICE_ARCH_INFO_H_
diff --git a/device_arch_info/include/berberis/device_arch_info/x86_64/device_arch_info.h b/device_arch_info/include/berberis/device_arch_info/x86_64/device_arch_info.h
new file mode 100644
index 00000000..570c150f
--- /dev/null
+++ b/device_arch_info/include/berberis/device_arch_info/x86_64/device_arch_info.h
@@ -0,0 +1,83 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_DEVICE_ARCH_INFO_X86_64_DEVICE_ARCH_INFO_H_
+#define BERBERIS_DEVICE_ARCH_INFO_X86_64_DEVICE_ARCH_INFO_H_
+
+#include <x86intrin.h>
+
+#include <cstdint>
+
+#include "berberis/assembler/x86_64.h"
+#include "berberis/device_arch_info/x86_32_or_x86_64/device_arch_info.h"
+
+namespace berberis {
+
+namespace x86_64 {
+
+namespace device_arch_info {
+
+// Note: normally using namespace is forbidden in headers, but these two namespaces literally
+// only exist to be imported here (and in other device CPU-specific headers).
+
+using namespace berberis::x86_32_or_x86_64::device_arch_info;
+
+class Cond {
+ public:
+  using Type = x86_32_or_x86_64::Assembler<x86_64::Assembler>::Condition;
+};
+
+class Mem128 {
+ public:
+#if defined(__LP64__)
+  using Type = __uint128_t;
+#endif
+  static constexpr char kAsRegister = 'm';
+};
+
+#include "berberis/device_arch_info/x86_64/machine_reg_class-inl.h"
+
+}  // namespace device_arch_info
+
+#include "berberis/device_arch_info/all_to_x86_32_or_x86_64/device_insn_info-inl.h"
+#include "berberis/device_arch_info/all_to_x86_64/device_insn_info-inl.h"
+#include "berberis/device_arch_info/x86_32_or_x86_64/device_insn_info-inl.h"
+#include "berberis/device_arch_info/x86_64/device_insn_info-inl.h"
+
+}  // namespace x86_64
+
+namespace device_arch_info {
+
+template <>
+inline constexpr bool kIsCondition<x86_64::device_arch_info::Cond> = true;
+
+template <>
+inline constexpr bool kIsGeneralReg32<x86_64::device_arch_info::GeneralReg32> = true;
+
+template <>
+inline constexpr bool kIsFLAGS<x86_64::device_arch_info::FLAGS> = true;
+
+template <>
+inline constexpr bool kIsRegister<x86_64::device_arch_info::FLAGS> = true;
+
+template <>
+inline constexpr bool kIsMemoryOperand<x86_64::device_arch_info::Mem128> = true;
+
+}  // namespace device_arch_info
+
+}  // namespace berberis
+
+#endif  // BERBERIS_DEVICE_ARCH_INFO_X86_64_DEVICE_ARCH_INFO_H_
diff --git a/device_arch_info/riscv64/reg_class_def.json b/device_arch_info/riscv64/reg_class_def.json
new file mode 100644
index 00000000..c7deb9f7
--- /dev/null
+++ b/device_arch_info/riscv64/reg_class_def.json
@@ -0,0 +1,537 @@
+{
+  "License": [
+    "Copyright (C) 2025 The Android Open Source Project",
+    "",
+    "Licensed under the Apache License, Version 2.0 (the “License”);",
+    "you may not use this file except in compliance with the License.",
+    "You may obtain a copy of the License at",
+    "",
+    "     http://www.apache.org/licenses/LICENSE-2.0",
+    "",
+    "Unless required by applicable law or agreed to in writing, software",
+    "distributed under the License is distributed on an “AS IS” BASIS,",
+    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
+    "See the License for the specific language governing permissions and",
+    "limitations under the License."
+  ],
+  "reg_classes": [
+    {
+      "name": "GeneralReg",
+      "size": 8,
+      "regs": [
+        "X1",
+        "X2",
+        "X3",
+        "X4",
+        "X5",
+        "X6",
+        "X7",
+        "X8",
+        "X9",
+        "X10",
+        "X11",
+        "X12",
+        "X13",
+        "X14",
+        "X15",
+        "X16",
+        "X17",
+        "X18",
+        "X19",
+        "X20",
+        "X21",
+        "X22",
+        "X23",
+        "X24",
+        "X25",
+        "X26",
+        "X27",
+        "X28",
+        "X29",
+        "X30",
+        "X31"
+      ],
+      "gcc_asm_name": "r"
+    },
+    {
+      "name": "FpReg",
+      "size": 8,
+      "regs": [
+        "F0",
+        "F1",
+        "F2",
+        "F3",
+        "F4",
+        "F5",
+        "F6",
+        "F7",
+        "F8",
+        "F9",
+        "F10",
+        "F11",
+        "F12",
+        "F13",
+        "F14",
+        "F15",
+        "F16",
+        "F17",
+        "F18",
+        "F19",
+        "F20",
+        "F21",
+        "F22",
+        "F23",
+        "F24",
+        "F25",
+        "F26",
+        "F27",
+        "F29",
+        "F29",
+        "F30",
+        "F31"
+      ],
+      "gcc_asm_name": "f"
+    },
+    {
+      "name": "X1",
+      "size": 8,
+      "regs": [
+        "X1"
+      ]
+    },
+    {
+      "name": "X2",
+      "size": 8,
+      "regs": [
+        "X2"
+      ]
+    },
+    {
+      "name": "X3",
+      "size": 8,
+      "regs": [
+        "X3"
+      ]
+    },
+    {
+      "name": "X4",
+      "size": 8,
+      "regs": [
+        "X4"
+      ]
+    },
+    {
+      "name": "X5",
+      "size": 8,
+      "regs": [
+        "X5"
+      ]
+    },
+    {
+      "name": "X6",
+      "size": 8,
+      "regs": [
+        "X6"
+      ]
+    },
+    {
+      "name": "X7",
+      "size": 8,
+      "regs": [
+        "X7"
+      ]
+    },
+    {
+      "name": "X8",
+      "size": 8,
+      "regs": [
+        "X8"
+      ]
+    },
+    {
+      "name": "X9",
+      "size": 8,
+      "regs": [
+        "X9"
+      ]
+    },
+    {
+      "name": "X10",
+      "size": 8,
+      "regs": [
+        "X10"
+      ]
+    },
+    {
+      "name": "X11",
+      "size": 8,
+      "regs": [
+        "X11"
+      ]
+    },
+    {
+      "name": "X12",
+      "size": 8,
+      "regs": [
+        "X12"
+      ]
+    },
+    {
+      "name": "X13",
+      "size": 8,
+      "regs": [
+        "X13"
+      ]
+    },
+    {
+      "name": "X14",
+      "size": 8,
+      "regs": [
+        "X14"
+      ]
+    },
+    {
+      "name": "X15",
+      "size": 8,
+      "regs": [
+        "X15"
+      ]
+    },
+    {
+      "name": "X16",
+      "size": 8,
+      "regs": [
+        "X16"
+      ]
+    },
+    {
+      "name": "X17",
+      "size": 8,
+      "regs": [
+        "X17"
+      ]
+    },
+    {
+      "name": "X18",
+      "size": 8,
+      "regs": [
+        "X18"
+      ]
+    },
+    {
+      "name": "X19",
+      "size": 8,
+      "regs": [
+        "X19"
+      ]
+    },
+    {
+      "name": "X20",
+      "size": 8,
+      "regs": [
+        "X20"
+      ]
+    },
+    {
+      "name": "X21",
+      "size": 8,
+      "regs": [
+        "X21"
+      ]
+    },
+    {
+      "name": "X22",
+      "size": 8,
+      "regs": [
+        "X22"
+      ]
+    },
+    {
+      "name": "X23",
+      "size": 8,
+      "regs": [
+        "X23"
+      ]
+    },
+    {
+      "name": "X24",
+      "size": 8,
+      "regs": [
+        "X24"
+      ]
+    },
+    {
+      "name": "X25",
+      "size": 8,
+      "regs": [
+        "X25"
+      ]
+    },
+    {
+      "name": "X26",
+      "size": 8,
+      "regs": [
+        "X26"
+      ]
+    },
+    {
+      "name": "X27",
+      "size": 8,
+      "regs": [
+        "X27"
+      ]
+    },
+    {
+      "name": "X28",
+      "size": 8,
+      "regs": [
+        "X28"
+      ]
+    },
+    {
+      "name": "X29",
+      "size": 8,
+      "regs": [
+        "X29"
+      ]
+    },
+    {
+      "name": "X30",
+      "size": 8,
+      "regs": [
+        "X30"
+      ]
+    },
+    {
+      "name": "X31",
+      "size": 8,
+      "regs": [
+        "X31"
+      ]
+    },
+    {
+      "name": "F0",
+      "size": 8,
+      "regs": [
+        "F0"
+      ]
+    },
+    {
+      "name": "F1",
+      "size": 8,
+      "regs": [
+        "F1"
+      ]
+    },
+    {
+      "name": "F2",
+      "size": 8,
+      "regs": [
+        "F2"
+      ]
+    },
+    {
+      "name": "F3",
+      "size": 8,
+      "regs": [
+        "F3"
+      ]
+    },
+    {
+      "name": "F4",
+      "size": 8,
+      "regs": [
+        "F4"
+      ]
+    },
+    {
+      "name": "F5",
+      "size": 8,
+      "regs": [
+        "F5"
+      ]
+    },
+    {
+      "name": "F6",
+      "size": 8,
+      "regs": [
+        "F6"
+      ]
+    },
+    {
+      "name": "F7",
+      "size": 8,
+      "regs": [
+        "F7"
+      ]
+    },
+    {
+      "name": "F8",
+      "size": 8,
+      "regs": [
+        "F8"
+      ]
+    },
+    {
+      "name": "F9",
+      "size": 8,
+      "regs": [
+        "F9"
+      ]
+    },
+    {
+      "name": "F10",
+      "size": 8,
+      "regs": [
+        "F10"
+      ]
+    },
+    {
+      "name": "F11",
+      "size": 8,
+      "regs": [
+        "F11"
+      ]
+    },
+    {
+      "name": "F12",
+      "size": 8,
+      "regs": [
+        "F12"
+      ]
+    },
+    {
+      "name": "F13",
+      "size": 8,
+      "regs": [
+        "F13"
+      ]
+    },
+    {
+      "name": "F14",
+      "size": 8,
+      "regs": [
+        "F14"
+      ]
+    },
+    {
+      "name": "F15",
+      "size": 8,
+      "regs": [
+        "F15"
+      ]
+    },
+    {
+      "name": "F16",
+      "size": 8,
+      "regs": [
+        "F16"
+      ]
+    },
+    {
+      "name": "F17",
+      "size": 8,
+      "regs": [
+        "F17"
+      ]
+    },
+    {
+      "name": "F18",
+      "size": 8,
+      "regs": [
+        "F18"
+      ]
+    },
+    {
+      "name": "F19",
+      "size": 8,
+      "regs": [
+        "F19"
+      ]
+    },
+    {
+      "name": "F20",
+      "size": 8,
+      "regs": [
+        "F20"
+      ]
+    },
+    {
+      "name": "F21",
+      "size": 8,
+      "regs": [
+        "F21"
+      ]
+    },
+    {
+      "name": "F22",
+      "size": 8,
+      "regs": [
+        "F22"
+      ]
+    },
+    {
+      "name": "F23",
+      "size": 8,
+      "regs": [
+        "F23"
+      ]
+    },
+    {
+      "name": "F24",
+      "size": 8,
+      "regs": [
+        "F24"
+      ]
+    },
+    {
+      "name": "F25",
+      "size": 8,
+      "regs": [
+        "F25"
+      ]
+    },
+    {
+      "name": "F26",
+      "size": 8,
+      "regs": [
+        "F26"
+      ]
+    },
+    {
+      "name": "F27",
+      "size": 8,
+      "regs": [
+        "F27"
+      ]
+    },
+    {
+      "name": "F28",
+      "size": 8,
+      "regs": [
+        "F28"
+      ]
+    },
+    {
+      "name": "F29",
+      "size": 8,
+      "regs": [
+        "F29"
+      ]
+    },
+    {
+      "name": "F30",
+      "size": 8,
+      "regs": [
+        "F30"
+      ]
+    },
+    {
+      "name": "F31",
+      "size": 8,
+      "regs": [
+        "F31"
+      ]
+    }
+  ]
+}
diff --git a/device_arch_info/x86_32/reg_class_def.json b/device_arch_info/x86_32/reg_class_def.json
new file mode 100644
index 00000000..33953ab0
--- /dev/null
+++ b/device_arch_info/x86_32/reg_class_def.json
@@ -0,0 +1,261 @@
+{
+  "License": [
+    "Copyright (C) 2023 The Android Open Source Project",
+    "",
+    "Licensed under the Apache License, Version 2.0 (the “License”);",
+    "you may not use this file except in compliance with the License.",
+    "You may obtain a copy of the License at",
+    "",
+    "     http://www.apache.org/licenses/LICENSE-2.0",
+    "",
+    "Unless required by applicable law or agreed to in writing, software",
+    "distributed under the License is distributed on an “AS IS” BASIS,",
+    "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
+    "See the License for the specific language governing permissions and",
+    "limitations under the License."
+  ],
+  "reg_classes": [
+    {
+      "name": "GeneralReg32",
+      "size": 4,
+      "comment": ["EAX, ECX and EDX are often implicit operands, allocate them at the end"],
+      "regs": [
+        "EDI",
+        "ESI",
+        "EBX",
+        "EDX",
+        "ECX",
+        "EAX"
+      ],
+      "gcc_asm_name": "r"
+    },
+    {
+      "name": "XmmReg",
+      "size": 16,
+      "comment": ["XMM0 can be an implicit operand in some instructions, allocate it at the end"],
+      "regs": [
+        "XMM1",
+        "XMM2",
+        "XMM3",
+        "XMM4",
+        "XMM5",
+        "XMM6",
+        "XMM7",
+        "XMM0"
+      ],
+      "gcc_asm_name": "x"
+    },
+    {
+      "name": "YmmReg",
+      "size": 32,
+      "regs": [
+        "XmmReg"
+      ],
+      "gcc_asm_name": "x"
+    },
+    {
+      "name": "Reg32",
+      "size": 4,
+      "regs": [
+        "GeneralReg32",
+        "XmmReg"
+      ]
+    },
+    {
+      "name": "GeneralReg16",
+      "size": 2,
+      "regs": [
+        "GeneralReg32"
+      ],
+      "gcc_asm_name": "r"
+    },
+    {
+      "name": "GeneralReg8",
+      "size": 1,
+      "regs": [
+        "EBX",
+        "EDX",
+        "ECX",
+        "EAX"
+      ],
+      "gcc_asm_name": "q"
+    },
+    {
+      "name": "FpReg64",
+      "size": 8,
+      "type": "__m128",
+      "regs": [
+        "XmmReg"
+      ],
+      "gcc_asm_name": "x"
+    },
+    {
+      "name": "FpReg32",
+      "size": 4,
+      "type": "__m128",
+      "regs": [
+        "XmmReg"
+      ],
+      "gcc_asm_name": "x"
+    },
+    {
+      "name": "VecReg128",
+      "size": 16,
+      "regs": [
+        "XmmReg"
+      ],
+      "gcc_asm_name": "x"
+    },
+    {
+      "name": "VecReg256",
+      "size": 32,
+      "regs": [
+        "XmmReg"
+      ],
+      "gcc_asm_name": "x"
+    },
+    {
+      "name": "EAX",
+      "size": 4,
+      "regs": [
+        "EAX"
+      ],
+      "gcc_asm_name": "a"
+    },
+    {
+      "name": "AX",
+      "size": 2,
+      "regs": [
+        "EAX"
+      ],
+      "gcc_asm_name": "a"
+    },
+    {
+      "name": "AL",
+      "size": 1,
+      "regs": [
+        "EAX"
+      ],
+      "gcc_asm_name": "a"
+    },
+    {
+      "name": "EBX",
+      "size": 4,
+      "regs": [
+        "EBX"
+      ],
+      "gcc_asm_name": "b"
+    },
+    {
+      "name": "ECX",
+      "size": 4,
+      "regs": [
+        "ECX"
+      ],
+      "gcc_asm_name": "c"
+    },
+    {
+      "name": "CL",
+      "size": 1,
+      "regs": [
+        "ECX"
+      ],
+      "gcc_asm_name": "c"
+    },
+    {
+      "name": "EDX",
+      "size": 4,
+      "regs": [
+        "EDX"
+      ],
+      "gcc_asm_name": "d"
+    },
+    {
+      "name": "DX",
+      "size": 2,
+      "regs": [
+        "EDX"
+      ],
+      "gcc_asm_name": "d"
+    },
+    {
+      "name": "ESI",
+      "size": 4,
+      "regs": [
+        "ESI"
+      ],
+      "gcc_asm_name": "S"
+    },
+    {
+      "name": "EDI",
+      "size": 4,
+      "regs": [
+        "EDI"
+      ],
+      "gcc_asm_name": "D"
+    },
+    {
+      "name": "XMM0",
+      "size": 16,
+      "regs": [
+        "XMM0"
+      ]
+    },
+    {
+      "name": "XMM1",
+      "size": 16,
+      "regs": [
+        "XMM1"
+      ]
+    },
+    {
+      "name": "XMM2",
+      "size": 16,
+      "regs": [
+        "XMM2"
+      ]
+    },
+    {
+      "name": "XMM3",
+      "size": 16,
+      "regs": [
+        "XMM3"
+      ]
+    },
+    {
+      "name": "XMM4",
+      "size": 16,
+      "regs": [
+        "XMM4"
+      ]
+    },
+    {
+      "name": "XMM5",
+      "size": 16,
+      "regs": [
+        "XMM5"
+      ]
+    },
+    {
+      "name": "XMM6",
+      "size": 16,
+      "regs": [
+        "XMM6"
+      ]
+    },
+    {
+      "name": "XMM7",
+      "size": 16,
+      "regs": [
+        "XMM7"
+      ]
+    },
+    {
+      "name": "FLAGS",
+      "size": 0,
+      "regs": [
+        "FLAGS"
+      ]
+    }
+  ]
+}
diff --git a/backend/x86_64/reg_class_def.json b/device_arch_info/x86_64/reg_class_def.json
similarity index 82%
rename from backend/x86_64/reg_class_def.json
rename to device_arch_info/x86_64/reg_class_def.json
index 204c8254..5a2473e2 100644
--- a/backend/x86_64/reg_class_def.json
+++ b/device_arch_info/x86_64/reg_class_def.json
@@ -35,7 +35,8 @@
         "R12",
         "RCX",
         "RAX"
-      ]
+      ],
+      "gcc_asm_name": "r"
     },
     {
       "name": "XmmReg",
@@ -59,14 +60,16 @@
         "XMM14",
         "XMM15",
         "XMM0"
-      ]
+      ],
+      "gcc_asm_name": "x"
     },
     {
       "name": "YmmReg",
       "size": 32,
       "regs": [
         "XmmReg"
-      ]
+      ],
+      "gcc_asm_name": "x"
     },
     {
       "name": "Reg64",
@@ -88,147 +91,170 @@
       "size": 4,
       "regs": [
         "GeneralReg64"
-      ]
+      ],
+      "gcc_asm_name": "r"
     },
     {
       "name": "GeneralReg16",
       "size": 2,
       "regs": [
         "GeneralReg64"
-      ]
+      ],
+      "gcc_asm_name": "r"
     },
     {
       "name": "GeneralReg8",
       "size": 1,
       "regs": [
         "GeneralReg64"
-      ]
+      ],
+      "gcc_asm_name": "r"
     },
     {
       "name": "FpReg64",
       "size": 8,
+      "type": "__m128",
       "regs": [
         "XmmReg"
-      ]
+      ],
+      "gcc_asm_name": "x"
     },
     {
       "name": "FpReg32",
       "size": 4,
+      "type": "__m128",
       "regs": [
         "XmmReg"
-      ]
+      ],
+      "gcc_asm_name": "x"
     },
     {
       "name": "VecReg128",
       "size": 16,
       "regs": [
         "XmmReg"
-      ]
+      ],
+      "gcc_asm_name": "x"
     },
     {
       "name": "VecReg256",
       "size": 32,
       "regs": [
         "XmmReg"
-      ]
+      ],
+      "gcc_asm_name": "x"
     },
     {
       "name": "RAX",
       "size": 8,
       "regs": [
         "RAX"
-      ]
+      ],
+      "gcc_asm_name": "a"
     },
     {
       "name": "EAX",
       "size": 4,
       "regs": [
         "RAX"
-      ]
+      ],
+      "gcc_asm_name": "a"
     },
     {
       "name": "AX",
       "size": 2,
       "regs": [
         "RAX"
-      ]
+      ],
+      "gcc_asm_name": "a"
     },
     {
       "name": "AL",
       "size": 1,
       "regs": [
         "RAX"
-      ]
+      ],
+      "gcc_asm_name": "a"
     },
     {
       "name": "RBX",
       "size": 8,
       "regs": [
         "RBX"
-      ]
+      ],
+      "gcc_asm_name": "b"
     },
     {
       "name": "EBX",
       "size": 4,
       "regs": [
         "RBX"
-      ]
+      ],
+      "gcc_asm_name": "b"
     },
     {
       "name": "RCX",
       "size": 8,
       "regs": [
         "RCX"
-      ]
+      ],
+      "gcc_asm_name": "c"
     },
     {
       "name": "ECX",
       "size": 4,
       "regs": [
         "RCX"
-      ]
+      ],
+      "gcc_asm_name": "c"
     },
     {
       "name": "CL",
       "size": 1,
       "regs": [
         "RCX"
-      ]
+      ],
+      "gcc_asm_name": "c"
     },
     {
       "name": "RDX",
       "size": 8,
       "regs": [
         "RDX"
-      ]
+      ],
+      "gcc_asm_name": "d"
     },
     {
       "name": "EDX",
       "size": 4,
       "regs": [
         "RDX"
-      ]
+      ],
+      "gcc_asm_name": "d"
     },
     {
       "name": "DX",
       "size": 2,
       "regs": [
         "RDX"
-      ]
+      ],
+      "gcc_asm_name": "d"
     },
     {
       "name": "RSI",
       "size": 8,
       "regs": [
         "RSI"
-      ]
+      ],
+      "gcc_asm_name": "S"
     },
     {
       "name": "RDI",
       "size": 8,
       "regs": [
         "RDI"
-      ]
+      ],
+      "gcc_asm_name": "D"
     },
     {
       "name": "R8",
@@ -258,6 +284,34 @@
         "R11"
       ]
     },
+    {
+      "name": "R12",
+      "size": 8,
+      "regs": [
+        "R12"
+      ]
+    },
+    {
+      "name": "R13",
+      "size": 8,
+      "regs": [
+        "R13"
+      ]
+    },
+    {
+      "name": "R14",
+      "size": 8,
+      "regs": [
+        "R14"
+      ]
+    },
+    {
+      "name": "R15",
+      "size": 8,
+      "regs": [
+        "R15"
+      ]
+    },
     {
       "name": "XMM0",
       "size": 16,
diff --git a/guest_loader/guest_loader.cc b/guest_loader/guest_loader.cc
index 83f8dc38..87b5dd5d 100644
--- a/guest_loader/guest_loader.cc
+++ b/guest_loader/guest_loader.cc
@@ -21,6 +21,7 @@
 #include <climits>     // CHAR_BIT
 #include <cstdint>
 #include <cstdlib>
+#include <filesystem>
 #include <functional>  // std::ref
 #include <random>
 #include <thread>
@@ -288,7 +289,6 @@ GuestLoader* GuestLoader::CreateInstance(const char* main_executable_path,
   // For readlink(/proc/self/exe).
   SetMainExecutableRealPath(main_executable_path);
 
-  instance->main_executable_path_ = main_executable_path;
   // Initialize caller_addr_ to executable entry point.
   instance->caller_addr_ = instance->executable_elf_file_.entry_point();
 
@@ -348,7 +348,7 @@ GuestLoader* GuestLoader::GetInstance() {
 void GuestLoader::StartGuestMainThread() {
   std::thread t(StartGuestExecutableImpl,
                 1,
-                &main_executable_path_,
+                GetMainExecutableRealPathPointer(),
                 environ,
                 &linker_elf_file_,
                 &executable_elf_file_,
@@ -357,13 +357,42 @@ void GuestLoader::StartGuestMainThread() {
   WaitForAppProcess();
 }
 
+std::filesystem::path GetSystemPath(const char* subdir, const char* relative_path) {
+  std::filesystem::path result("/system");
+  result.append(subdir);
+  // Prefer alternative location if exists.
+  std::filesystem::path alt_result = result / "berberis";
+  if (std::filesystem::exists(alt_result) && std::filesystem::is_directory(alt_result)) {
+    return alt_result / relative_path;
+  }
+  return result / relative_path;
+}
+
+std::string GetPtInterpPath() {
+  return GetSystemPath("bin", kPtInterpRelativePath).string();
+}
+
+std::string GetAppProcessPath() {
+  return GetSystemPath("bin", kAppProcessRelativePath).string();
+}
+
+std::string GetVdsoPath() {
+#if defined(BERBERIS_GUEST_LP64)
+  const char* lib_dir = "lib64";
+#else
+  const char* lib_dir = "lib";
+#endif
+  return GetSystemPath(lib_dir, kVdsoRelativePath).string();
+}
+
 void GuestLoader::StartGuestExecutable(size_t argc, const char* argv[], char* envp[]) {
   StartGuestExecutableImpl(
       argc, argv, envp, &linker_elf_file_, &executable_elf_file_, &vdso_elf_file_);
 }
 
 GuestLoader* GuestLoader::StartAppProcessInNewThread(std::string* error_msg) {
-  GuestLoader* instance = CreateInstance(kAppProcessPath, kVdsoPath, kPtInterpPath, error_msg);
+  GuestLoader* instance = CreateInstance(
+      GetAppProcessPath().c_str(), GetVdsoPath().c_str(), GetPtInterpPath().c_str(), error_msg);
   if (instance) {
     instance->StartGuestMainThread();
   }
@@ -378,8 +407,8 @@ void GuestLoader::StartExecutable(const char* main_executable_path,
                                   char* envp[],
                                   std::string* error_msg) {
   GuestLoader* instance = CreateInstance(main_executable_path,
-                                         vdso_path ? vdso_path : kVdsoPath,
-                                         loader_path ? loader_path : kPtInterpPath,
+                                         vdso_path ? vdso_path : GetVdsoPath().c_str(),
+                                         loader_path ? loader_path : GetPtInterpPath().c_str(),
                                          error_msg);
   if (instance) {
     instance->StartGuestExecutable(argc, argv, envp);
diff --git a/guest_loader/guest_loader_impl.h b/guest_loader/guest_loader_impl.h
index 4233923a..5ff8870b 100644
--- a/guest_loader/guest_loader_impl.h
+++ b/guest_loader/guest_loader_impl.h
@@ -33,9 +33,9 @@ namespace berberis {
 
 // TODO(b/280544942): Consider moving these paths to native_bridge_support.
 // Define these path constants for the target guest architecture.
-extern const char* kAppProcessPath;
-extern const char* kPtInterpPath;
-extern const char* kVdsoPath;
+extern const char* kAppProcessRelativePath;
+extern const char* kPtInterpRelativePath;
+extern const char* kVdsoRelativePath;
 extern const char* kProxyPrefix;
 
 GuestAddr InitKernelArgs(GuestAddr guest_sp,
diff --git a/guest_loader/include/berberis/guest_loader/guest_loader.h b/guest_loader/include/berberis/guest_loader/guest_loader.h
index 807cdf61..cef57b67 100644
--- a/guest_loader/include/berberis/guest_loader/guest_loader.h
+++ b/guest_loader/include/berberis/guest_loader/guest_loader.h
@@ -147,7 +147,6 @@ class GuestLoader {
   std::string dl_error_holder_;
   const char* dl_error_;
 
-  const char* main_executable_path_;
   LoadedElfFile executable_elf_file_;
   LoadedElfFile linker_elf_file_;
   LoadedElfFile vdso_elf_file_;
diff --git a/guest_loader/riscv64/guest_loader_arch.cc b/guest_loader/riscv64/guest_loader_arch.cc
index f40a6672..2a325c8b 100644
--- a/guest_loader/riscv64/guest_loader_arch.cc
+++ b/guest_loader/riscv64/guest_loader_arch.cc
@@ -28,9 +28,9 @@ namespace berberis {
 
 // TODO(b/279068747): Ensure these paths are correct.
 // Paths required by guest_loader_impl.h.
-const char* kAppProcessPath = "/system/bin/riscv64/app_process64";
-const char* kPtInterpPath = "/system/bin/riscv64/linker64";
-const char* kVdsoPath = "/system/lib64/riscv64/libnative_bridge_vdso.so";
+const char* kAppProcessRelativePath = "riscv64/app_process64";
+const char* kPtInterpRelativePath = "riscv64/linker64";
+const char* kVdsoRelativePath = "riscv64/libnative_bridge_vdso.so";
 const char* kProxyPrefix = "libberberis_proxy_";
 
 GuestAddr InitKernelArgs(GuestAddr guest_sp,
diff --git a/guest_os_primitives/guest_map_shadow.cc b/guest_os_primitives/guest_map_shadow.cc
index 4fecbc5e..1676d4e7 100644
--- a/guest_os_primitives/guest_map_shadow.cc
+++ b/guest_os_primitives/guest_map_shadow.cc
@@ -18,11 +18,13 @@
 
 #include <sys/mman.h>
 #include <climits>  // CHAR_BIT
+#include <cmath>
 #include <cstddef>
 #include <mutex>
 #include <tuple>
 
 #include "berberis/base/bit_util.h"
+#include "berberis/base/config.h"  // kGuestPageSize
 #include "berberis/base/forever_alloc.h"
 #include "berberis/base/large_mmap.h"
 #include "berberis/base/logging.h"
@@ -34,8 +36,6 @@ namespace berberis {
 
 namespace {
 
-// One bit per each 4K page.
-constexpr size_t kGuestPageSizeLog2 = 12;
 #if defined(BERBERIS_GUEST_LP64)
 // On LP64 the address space is limited to 48 bits
 constexpr size_t kGuestAddressSizeLog2 = 48;
@@ -44,8 +44,11 @@ constexpr size_t kMaxGuestAddress{0xffff'ffff'ffff};
 constexpr size_t kGuestAddressSizeLog2 = sizeof(GuestAddr) * CHAR_BIT;
 constexpr size_t kMaxGuestAddress{0xffff'ffff};
 #endif
-constexpr size_t kGuestPageSize = 1 << kGuestPageSizeLog2;  // 4096
-constexpr size_t kShadowSize = 1UL << (kGuestAddressSizeLog2 - kGuestPageSizeLog2 - 3);
+
+const size_t kGuestPageSize = config::kGuestPageSize;
+// One bit per each page.
+const size_t kGuestPageSizeLog2 = std::log2(kGuestPageSize);
+const size_t kShadowSize = 1UL << (kGuestAddressSizeLog2 - kGuestPageSizeLog2 - 3);
 
 inline GuestAddr AlignDownGuestPageSize(GuestAddr addr) {
   return AlignDown(addr, kGuestPageSize);
diff --git a/guest_os_primitives/guest_thread_manager.cc b/guest_os_primitives/guest_thread_manager.cc
index 0d715c86..7e66d76e 100644
--- a/guest_os_primitives/guest_thread_manager.cc
+++ b/guest_os_primitives/guest_thread_manager.cc
@@ -35,6 +35,8 @@ pthread_key_t g_guest_thread_key;
 
 namespace {
 
+GuestThreadExitListenerFn g_guest_thread_exit_listener = nullptr;
+
 void GuestThreadDtor(void* /* arg */) {
   // TLS cache was cleared by pthread_exit.
   // TODO(b/280671643): Postpone detach to last pthread destructor iteration.
@@ -44,6 +46,13 @@ void GuestThreadDtor(void* /* arg */) {
 
 }  // namespace
 
+GuestThreadExitListenerFn RegisterGuestThreadExitListener(GuestThreadExitListenerFn new_listener) {
+  CHECK(new_listener != nullptr);
+  auto old_listener = g_guest_thread_exit_listener;
+  g_guest_thread_exit_listener = new_listener;
+  return old_listener;
+}
+
 // Not thread safe, not async signals safe!
 void InitGuestThreadManager() {
   // Here we don't need pthread_once, which is not reentrant due to spinlocks.
@@ -101,6 +110,10 @@ void ExitCurrentThread(int status) {
     OnRemoveGuestThread(tid, thread);
   }
 
+  if (g_guest_thread_exit_listener != nullptr) {
+    g_guest_thread_exit_listener(tid);
+  }
+
   TRACE("guest thread exited %d", tid);
   GuestThread::Exit(thread, status);
 }
diff --git a/guest_os_primitives/include/berberis/guest_os_primitives/guest_thread.h b/guest_os_primitives/include/berberis/guest_os_primitives/guest_thread.h
index d500428e..e8f68ab6 100644
--- a/guest_os_primitives/include/berberis/guest_os_primitives/guest_thread.h
+++ b/guest_os_primitives/include/berberis/guest_os_primitives/guest_thread.h
@@ -150,6 +150,16 @@ class GuestThread {
   size_t sig_alt_stack_size_ = 0;
 };
 
+using GuestThreadExitListenerFn = void (*)(pid_t);
+
+// This function is supposed to be called during BerberisInit() to
+// register a listener to be called during GuestThread exit.
+//
+// Returns:
+//  Old guest thread listener (which could be nullptr), new listener is supposed
+//  to call the old one if it is not nullptr.
+GuestThreadExitListenerFn RegisterGuestThreadExitListener(GuestThreadExitListenerFn new_listener);
+
 }  // namespace berberis
 
 #endif  // BERBERIS_GUEST_OS_PRIMITIVES_GUEST_THREAD_H_
diff --git a/guest_state/riscv64/include/berberis/guest_state/guest_state_arch.h b/guest_state/riscv64/include/berberis/guest_state/guest_state_arch.h
index 99d55ce3..a497adb1 100644
--- a/guest_state/riscv64/include/berberis/guest_state/guest_state_arch.h
+++ b/guest_state/riscv64/include/berberis/guest_state/guest_state_arch.h
@@ -193,7 +193,7 @@ inline constexpr bool CsrWritable(CsrName name) {
 }
 
 template <typename Processor>
-bool ProcessCsrNameAsTemplateParameter(CsrName name, Processor& processor) {
+bool ProcessCsrNameAsTemplateParameter(CsrName name, Processor&& processor) {
 #define BERBERIS_RISV64_PROCESS_CSR(EnumName, field_name, field_mask) CsrName::k##EnumName,
 #define BERBERIS_RISV64_PROCESS_NOSTORAGE_CSR(EnumName) CsrName::k##EnumName
   return ProcessCsrNameAsTemplateParameterImpl<BERBERIS_RISV64_PROCESS_ALL_SUPPORTED_CSRS>(
diff --git a/heavy_optimizer/riscv64/Android.bp b/heavy_optimizer/riscv64/Android.bp
index 96c10759..d2713103 100644
--- a/heavy_optimizer/riscv64/Android.bp
+++ b/heavy_optimizer/riscv64/Android.bp
@@ -47,6 +47,7 @@ cc_library_static {
     ],
     srcs: [
         "frontend.cc",
+        "frontend_demultiplexers.cc",
         "heavy_optimize_region.cc",
     ],
 }
diff --git a/heavy_optimizer/riscv64/call_intrinsic.h b/heavy_optimizer/riscv64/call_intrinsic.h
index e85c80a6..6dc25f77 100644
--- a/heavy_optimizer/riscv64/call_intrinsic.h
+++ b/heavy_optimizer/riscv64/call_intrinsic.h
@@ -20,7 +20,6 @@
 #include <type_traits>
 
 #include "berberis/backend/code_emitter.h"
-#include "berberis/backend/common/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir_builder.h"
 #include "berberis/base/bit_util.h"
@@ -135,11 +134,12 @@ void LoadCallIntrinsicResult(x86_64::MachineIRBuilder* builder,
     auto second_reg = std::get<1>(result);
 
     if constexpr (std::is_same_v<FirstElementType, SIMD128Register>) {
-      builder->Gen<x86_64::MovdquXRegMemBaseDisp>(first_reg.machine_reg(), result_ptr, 0);
+      builder->Gen<x86_64::MovdquXRegOp>(first_reg.machine_reg(), {.base = result_ptr});
       if constexpr (std::is_same_v<SecondElementType, SIMD128Register>) {
-        builder->Gen<x86_64::MovdquXRegMemBaseDisp>(second_reg.machine_reg(), result_ptr, 16);
+        builder->Gen<x86_64::MovdquXRegOp>(second_reg.machine_reg(),
+                                           {.base = result_ptr, .disp = 16});
       } else if constexpr (std::is_integral_v<SecondElementType>) {
-        builder->Gen<x86_64::MovqRegMemBaseDisp>(second_reg, result_ptr, 16);
+        builder->Gen<x86_64::MovqRegOp>(second_reg, {.base = result_ptr, .disp = 16});
       } else {
         static_assert(kDependentTypeFalse<IntrinsicResType>, "Unsupported intrinsic return type.");
       }
@@ -154,12 +154,12 @@ void LoadCallIntrinsicResult(x86_64::MachineIRBuilder* builder,
     if constexpr (std::is_same_v<FirstElementType, SIMD128Register> &&
                   std::is_same_v<SecondElementType, SIMD128Register> &&
                   std::is_same_v<ThirdElementType, SIMD128Register>) {
-      builder->Gen<x86_64::MovdquXRegMemBaseDisp>(
-          std::get<0>(result).machine_reg(), result_ptr, 0 * 16);
-      builder->Gen<x86_64::MovdquXRegMemBaseDisp>(
-          std::get<1>(result).machine_reg(), result_ptr, 1 * 16);
-      builder->Gen<x86_64::MovdquXRegMemBaseDisp>(
-          std::get<2>(result).machine_reg(), result_ptr, 2 * 16);
+      builder->Gen<x86_64::MovdquXRegOp>(std::get<0>(result).machine_reg(),
+                                         {.base = result_ptr, .disp = 0 * 16});
+      builder->Gen<x86_64::MovdquXRegOp>(std::get<1>(result).machine_reg(),
+                                         {.base = result_ptr, .disp = 1 * 16});
+      builder->Gen<x86_64::MovdquXRegOp>(std::get<2>(result).machine_reg(),
+                                         {.base = result_ptr, .disp = 2 * 16});
     } else {
       static_assert(kDependentTypeFalse<IntrinsicResType>, "Unsupported intrinsic return type.");
     }
@@ -173,14 +173,14 @@ void LoadCallIntrinsicResult(x86_64::MachineIRBuilder* builder,
                   std::is_same_v<SecondElementType, SIMD128Register> &&
                   std::is_same_v<ThirdElementType, SIMD128Register> &&
                   std::is_same_v<FourthElementType, SIMD128Register>) {
-      builder->Gen<x86_64::MovdquXRegMemBaseDisp>(
-          std::get<0>(result).machine_reg(), result_ptr, 0 * 16);
-      builder->Gen<x86_64::MovdquXRegMemBaseDisp>(
-          std::get<1>(result).machine_reg(), result_ptr, 1 * 16);
-      builder->Gen<x86_64::MovdquXRegMemBaseDisp>(
-          std::get<2>(result).machine_reg(), result_ptr, 2 * 16);
-      builder->Gen<x86_64::MovdquXRegMemBaseDisp>(
-          std::get<3>(result).machine_reg(), result_ptr, 3 * 16);
+      builder->Gen<x86_64::MovdquXRegOp>(std::get<0>(result).machine_reg(),
+                                         {.base = result_ptr, .disp = 0 * 16});
+      builder->Gen<x86_64::MovdquXRegOp>(std::get<1>(result).machine_reg(),
+                                         {.base = result_ptr, .disp = 1 * 16});
+      builder->Gen<x86_64::MovdquXRegOp>(std::get<2>(result).machine_reg(),
+                                         {.base = result_ptr, .disp = 2 * 16});
+      builder->Gen<x86_64::MovdquXRegOp>(std::get<3>(result).machine_reg(),
+                                         {.base = result_ptr, .disp = 3 * 16});
     } else {
       static_assert(kDependentTypeFalse<IntrinsicResType>, "Unsupported intrinsic return type.");
     }
diff --git a/heavy_optimizer/riscv64/call_intrinsic_tests.cc b/heavy_optimizer/riscv64/call_intrinsic_tests.cc
index cbbef0d8..3af48e68 100644
--- a/heavy_optimizer/riscv64/call_intrinsic_tests.cc
+++ b/heavy_optimizer/riscv64/call_intrinsic_tests.cc
@@ -114,7 +114,7 @@ void CallOneArgumentIntrinsicUseIntegral(IntrinsicFunc func, T argument, uint64_
   CallIntrinsicImpl(&builder, func, result_register, flag_register, argument);
 
   builder.Gen<x86_64::MovqRegImm>(result_value_addr_reg, bit_cast<uintptr_t>(result));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(result_value_addr_reg, 0, result_register);
+  builder.Gen<x86_64::MovqOpReg>({.base = result_value_addr_reg}, result_register);
 
   ExecTest test;
   test.Init(&machine_ir);
@@ -138,7 +138,7 @@ void CallOneArgumentIntrinsicUseRegister(IntrinsicFunc func, uint64_t argument,
   CallIntrinsicImpl(&builder, func, result_register, flag_register, argument_register);
 
   builder.Gen<x86_64::MovqRegImm>(result_value_addr_reg, bit_cast<uintptr_t>(result));
-  builder.Gen<x86_64::MovqMemBaseDispReg>(result_value_addr_reg, 0, result_register);
+  builder.Gen<x86_64::MovqOpReg>({.base = result_value_addr_reg}, result_register);
 
   ExecTest test;
   test.Init(&machine_ir);
diff --git a/heavy_optimizer/riscv64/frontend.cc b/heavy_optimizer/riscv64/frontend.cc
index 8dae1afc..7666444f 100644
--- a/heavy_optimizer/riscv64/frontend.cc
+++ b/heavy_optimizer/riscv64/frontend.cc
@@ -19,7 +19,6 @@
 #include <cstddef>
 
 #include "berberis/assembler/x86_64.h"
-#include "berberis/backend/common/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/base/checks.h"
 #include "berberis/base/config.h"
@@ -233,8 +232,9 @@ void HeavyOptimizerFrontend::ReplaceJumpWithBranch(MachineBasicBlock* bb,
     // fall-through jump for the current bb. At the same time exit_bb can be a fall-through jump
     // and benchmarks benefit from it.
     const size_t offset = offsetof(ThreadState, pending_signals_status);
-    auto* cmpb = ir->NewInsn<x86_64::CmpbMemBaseDispImm>(
-        x86_64::kMachineRegRBP, offset, kPendingSignalsPresent, GetFlagsRegister());
+    auto* cmpb = ir->NewInsn<x86_64::CmpbOpImm>({.base = x86_64::kMachineRegRBP, .disp = offset},
+                                                kPendingSignalsPresent,
+                                                GetFlagsRegister());
     *jump_it = cmpb;
     auto* cond_branch = ir->NewInsn<PseudoCondBranch>(
         x86_64::Assembler::Condition::kEqual, exit_bb, target_bb, GetFlagsRegister());
@@ -658,25 +658,25 @@ Register HeavyOptimizerFrontend::LoadWithoutRecovery(Decoder::LoadOperandType op
   auto res = AllocTempReg();
   switch (operand_type) {
     case Decoder::LoadOperandType::k8bitUnsigned:
-      Gen<x86_64::MovzxblRegMemBaseDisp>(res, base, disp);
+      Gen<x86_64::MovzxblRegOp>(res, {.base = base, .disp = disp});
       break;
     case Decoder::LoadOperandType::k16bitUnsigned:
-      Gen<x86_64::MovzxwlRegMemBaseDisp>(res, base, disp);
+      Gen<x86_64::MovzxwlRegOp>(res, {.base = base, .disp = disp});
       break;
     case Decoder::LoadOperandType::k32bitUnsigned:
-      Gen<x86_64::MovlRegMemBaseDisp>(res, base, disp);
+      Gen<x86_64::MovlRegOp>(res, {.base = base, .disp = disp});
       break;
     case Decoder::LoadOperandType::k64bit:
-      Gen<x86_64::MovqRegMemBaseDisp>(res, base, disp);
+      Gen<x86_64::MovqRegOp>(res, {.base = base, .disp = disp});
       break;
     case Decoder::LoadOperandType::k8bitSigned:
-      Gen<x86_64::MovsxbqRegMemBaseDisp>(res, base, disp);
+      Gen<x86_64::MovsxbqRegOp>(res, {.base = base, .disp = disp});
       break;
     case Decoder::LoadOperandType::k16bitSigned:
-      Gen<x86_64::MovsxwqRegMemBaseDisp>(res, base, disp);
+      Gen<x86_64::MovsxwqRegOp>(res, {.base = base, .disp = disp});
       break;
     case Decoder::LoadOperandType::k32bitSigned:
-      Gen<x86_64::MovsxlqRegMemBaseDisp>(res, base, disp);
+      Gen<x86_64::MovsxlqRegOp>(res, {.base = base, .disp = disp});
       break;
     default:
       Undefined();
@@ -693,32 +693,32 @@ Register HeavyOptimizerFrontend::LoadWithoutRecovery(Decoder::LoadOperandType op
   auto res = AllocTempReg();
   switch (operand_type) {
     case Decoder::LoadOperandType::k8bitUnsigned:
-      Gen<x86_64::MovzxblRegMemBaseIndexDisp>(
-          res, base, index, x86_64::MachineMemOperandScale::kOne, disp);
+      Gen<x86_64::MovzxblRegOp>(
+          res, {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp});
       break;
     case Decoder::LoadOperandType::k16bitUnsigned:
-      Gen<x86_64::MovzxwlRegMemBaseIndexDisp>(
-          res, base, index, x86_64::MachineMemOperandScale::kOne, disp);
+      Gen<x86_64::MovzxwlRegOp>(
+          res, {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp});
       break;
     case Decoder::LoadOperandType::k32bitUnsigned:
-      Gen<x86_64::MovlRegMemBaseIndexDisp>(
-          res, base, index, x86_64::MachineMemOperandScale::kOne, disp);
+      Gen<x86_64::MovlRegOp>(
+          res, {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp});
       break;
     case Decoder::LoadOperandType::k64bit:
-      Gen<x86_64::MovqRegMemBaseIndexDisp>(
-          res, base, index, x86_64::MachineMemOperandScale::kOne, disp);
+      Gen<x86_64::MovqRegOp>(
+          res, {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp});
       break;
     case Decoder::LoadOperandType::k8bitSigned:
-      Gen<x86_64::MovsxbqRegMemBaseIndexDisp>(
-          res, base, index, x86_64::MachineMemOperandScale::kOne, disp);
+      Gen<x86_64::MovsxbqRegOp>(
+          res, {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp});
       break;
     case Decoder::LoadOperandType::k16bitSigned:
-      Gen<x86_64::MovsxwqRegMemBaseIndexDisp>(
-          res, base, index, x86_64::MachineMemOperandScale::kOne, disp);
+      Gen<x86_64::MovsxwqRegOp>(
+          res, {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp});
       break;
     case Decoder::LoadOperandType::k32bitSigned:
-      Gen<x86_64::MovsxlqRegMemBaseIndexDisp>(
-          res, base, index, x86_64::MachineMemOperandScale::kOne, disp);
+      Gen<x86_64::MovsxlqRegOp>(
+          res, {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp});
       break;
     default:
       Undefined();
@@ -779,16 +779,16 @@ void HeavyOptimizerFrontend::StoreWithoutRecovery(Decoder::MemoryDataOperandType
                                                   Register data) {
   switch (operand_type) {
     case Decoder::MemoryDataOperandType::k8bit:
-      Gen<x86_64::MovbMemBaseDispReg>(base, disp, data);
+      Gen<x86_64::MovbOpReg>({.base = base, .disp = disp}, data);
       break;
     case Decoder::MemoryDataOperandType::k16bit:
-      Gen<x86_64::MovwMemBaseDispReg>(base, disp, data);
+      Gen<x86_64::MovwOpReg>({.base = base, .disp = disp}, data);
       break;
     case Decoder::MemoryDataOperandType::k32bit:
-      Gen<x86_64::MovlMemBaseDispReg>(base, disp, data);
+      Gen<x86_64::MovlOpReg>({.base = base, .disp = disp}, data);
       break;
     case Decoder::MemoryDataOperandType::k64bit:
-      Gen<x86_64::MovqMemBaseDispReg>(base, disp, data);
+      Gen<x86_64::MovqOpReg>({.base = base, .disp = disp}, data);
       break;
     default:
       return Undefined();
@@ -802,20 +802,20 @@ void HeavyOptimizerFrontend::StoreWithoutRecovery(Decoder::MemoryDataOperandType
                                                   Register data) {
   switch (operand_type) {
     case Decoder::MemoryDataOperandType::k8bit:
-      Gen<x86_64::MovbMemBaseIndexDispReg>(
-          base, index, x86_64::MachineMemOperandScale::kOne, disp, data);
+      Gen<x86_64::MovbOpReg>(
+          {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp}, data);
       break;
     case Decoder::MemoryDataOperandType::k16bit:
-      Gen<x86_64::MovwMemBaseIndexDispReg>(
-          base, index, x86_64::MachineMemOperandScale::kOne, disp, data);
+      Gen<x86_64::MovwOpReg>(
+          {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp}, data);
       break;
     case Decoder::MemoryDataOperandType::k32bit:
-      Gen<x86_64::MovlMemBaseIndexDispReg>(
-          base, index, x86_64::MachineMemOperandScale::kOne, disp, data);
+      Gen<x86_64::MovlOpReg>(
+          {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp}, data);
       break;
     case Decoder::MemoryDataOperandType::k64bit:
-      Gen<x86_64::MovqMemBaseIndexDispReg>(
-          base, index, x86_64::MachineMemOperandScale::kOne, disp, data);
+      Gen<x86_64::MovqOpReg>(
+          {.base = base, .index = index, x86_64::Assembler::kTimesOne, .disp = disp}, data);
       break;
     default:
       return Undefined();
@@ -856,7 +856,7 @@ void HeavyOptimizerFrontend::Fence(Decoder::FenceOpcode /* opcode */,
 void HeavyOptimizerFrontend::MemoryRegionReservationLoad(Register aligned_addr) {
   // Store aligned_addr in CPUState.
   int32_t address_offset = GetThreadStateReservationAddressOffset();
-  Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, address_offset, aligned_addr);
+  Gen<x86_64::MovqOpReg>({.base = x86_64::kMachineRegRBP, .disp = address_offset}, aligned_addr);
 
   // MemoryRegionReservation::SetOwner(aligned_addr, &(state->cpu)).
   builder_.GenCallImm(bit_cast<uint64_t>(&MemoryRegionReservation::SetOwner),
@@ -868,9 +868,9 @@ void HeavyOptimizerFrontend::MemoryRegionReservationLoad(Register aligned_addr)
 
   // Load reservation value and store it in CPUState.
   auto reservation = AllocTempReg();
-  Gen<x86_64::MovqRegMemBaseDisp>(reservation, aligned_addr, 0);
+  Gen<x86_64::MovqRegOp>(reservation, {.base = aligned_addr});
   int32_t value_offset = GetThreadStateReservationValueOffset();
-  Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, value_offset, reservation);
+  Gen<x86_64::MovqOpReg>({.base = x86_64::kMachineRegRBP, .disp = value_offset}, reservation);
 }
 
 Register HeavyOptimizerFrontend::MemoryRegionReservationExchange(Register aligned_addr,
@@ -888,8 +888,9 @@ Register HeavyOptimizerFrontend::MemoryRegionReservationExchange(Register aligne
   // MemoryRegionReservation::Clear.
   Register stored_aligned_addr = AllocTempReg();
   int32_t address_offset = GetThreadStateReservationAddressOffset();
-  Gen<x86_64::MovqRegMemBaseDisp>(stored_aligned_addr, x86_64::kMachineRegRBP, address_offset);
-  Gen<x86_64::MovqMemBaseDispImm>(x86_64::kMachineRegRBP, address_offset, kNullGuestAddr);
+  Gen<x86_64::MovqRegOp>(stored_aligned_addr,
+                         {.base = x86_64::kMachineRegRBP, .disp = address_offset});
+  Gen<x86_64::MovqOpImm>({.base = x86_64::kMachineRegRBP, .disp = address_offset}, kNullGuestAddr);
   // Compare aligned_addr to the one in CPUState.
   Gen<x86_64::CmpqRegReg>(stored_aligned_addr, aligned_addr, GetFlagsRegister());
   Gen<PseudoCondBranch>(
@@ -899,7 +900,8 @@ Register HeavyOptimizerFrontend::MemoryRegionReservationExchange(Register aligne
   // Load new reservation value into integer register where CmpXchgq expects it.
   Register new_reservation_value = AllocTempReg();
   int32_t value_offset = GetThreadStateReservationValueOffset();
-  Gen<x86_64::MovqRegMemBaseDisp>(new_reservation_value, x86_64::kMachineRegRBP, value_offset);
+  Gen<x86_64::MovqRegOp>(new_reservation_value,
+                         {.base = x86_64::kMachineRegRBP, .disp = value_offset});
 
   MemoryRegionReservationSwapWithLockedOwner(
       aligned_addr, curr_reservation_value, new_reservation_value, failure_bb);
@@ -949,11 +951,11 @@ void HeavyOptimizerFrontend::MemoryRegionReservationSwapWithLockedOwner(
   builder_.StartBasicBlock(lock_success_bb);
   auto rax = AllocTempReg();
   Gen<PseudoCopy>(rax, curr_reservation_value, 8);
-  Gen<x86_64::LockCmpXchgqRegMemBaseDispReg>(
-      rax, aligned_addr, 0, new_reservation_value, GetFlagsRegister());
+  Gen<x86_64::LockCmpXchgqRegOpReg>(
+      rax, {.base = aligned_addr}, new_reservation_value, GetFlagsRegister());
 
   // MemoryRegionReservation::Unlock(lock_entry)
-  Gen<x86_64::MovqMemBaseDispImm>(lock_entry, 0, 0);
+  Gen<x86_64::MovqOpImm>({.base = lock_entry}, 0);
   // Zero-flag is set if CmpXchg is successful.
   Gen<PseudoCondBranch>(
       x86_64::Assembler::Condition::kNotZero, failure_bb, swap_success_bb, GetFlagsRegister());
diff --git a/heavy_optimizer/riscv64/frontend.h b/heavy_optimizer/riscv64/frontend.h
index 8e37fcb4..494f70ea 100644
--- a/heavy_optimizer/riscv64/frontend.h
+++ b/heavy_optimizer/riscv64/frontend.h
@@ -49,6 +49,17 @@ class HeavyOptimizerFrontend {
   using Float32 = intrinsics::Float32;
   using Float64 = intrinsics::Float64;
 
+  using TemplateTypeId = intrinsics::TemplateTypeId;
+  template <typename Type>
+  static constexpr auto kIdFromType = intrinsics::kIdFromType<Type>;
+  template <auto kEnumValue>
+  using TypeFromId = intrinsics::TypeFromId<kEnumValue>;
+  template <auto ValueParam>
+  using Value = intrinsics::Value<ValueParam>;
+  static constexpr TemplateTypeId IntSizeToTemplateTypeId(uint8_t size, bool is_signed = false) {
+    return intrinsics::IntSizeToTemplateTypeId(size, is_signed);
+  }
+
   struct MemoryOperand {
     Register base{0};
     // We call the following field "index" even though we do not scale it at the
@@ -172,8 +183,8 @@ class HeavyOptimizerFrontend {
   // Atomic extensions.
   //
 
-  template <typename IntType, bool aq, bool rl>
-  Register Lr(Register addr) {
+  template <intrinsics::TemplateTypeId IntType, bool aq, bool rl>
+  Register Lr(Register addr, Value<IntType>, Value<aq>, Value<rl>) {
     Register aligned_addr = AllocTempReg();
     Gen<PseudoCopy>(aligned_addr, addr, 8);
     // The immediate is sign extended to 64-bit.
@@ -186,14 +197,14 @@ class HeavyOptimizerFrontend {
     Gen<x86_64::SubqRegReg>(addr_offset, aligned_addr, GetFlagsRegister());
 
     // Load the requested part from CPUState.
-    return LoadWithoutRecovery(ToLoadOperandType<IntType>(),
+    return LoadWithoutRecovery(ToLoadOperandType<TypeFromId<IntType>>(),
                                x86_64::kMachineRegRBP,
                                addr_offset,
                                GetThreadStateReservationValueOffset());
   }
 
-  template <typename IntType, bool aq, bool rl>
-  Register Sc(Register addr, Register data) {
+  template <intrinsics::TemplateTypeId IntType, bool aq, bool rl>
+  Register Sc(Register addr, Register data, Value<IntType>, Value<aq>, Value<rl>) {
     // Compute aligned_addr.
     auto aligned_addr = AllocTempReg();
     Gen<PseudoCopy>(aligned_addr, addr, 8);
@@ -203,13 +214,14 @@ class HeavyOptimizerFrontend {
     // Load current monitor value before we clobber it.
     auto reservation_value = AllocTempReg();
     int32_t value_offset = GetThreadStateReservationValueOffset();
-    Gen<x86_64::MovqRegMemBaseDisp>(reservation_value, x86_64::kMachineRegRBP, value_offset);
+    Gen<x86_64::MovqRegOp>(reservation_value,
+                           {.base = x86_64::kMachineRegRBP, .disp = value_offset});
     Register addr_offset = AllocTempReg();
     Gen<PseudoCopy>(addr_offset, addr, 8);
     Gen<x86_64::SubqRegReg>(addr_offset, aligned_addr, GetFlagsRegister());
     // It's okay to clobber reservation_value since we clear out reservation_address in
     // MemoryRegionReservationExchange anyway.
-    StoreWithoutRecovery(ToMemoryDataOperandType<IntType>(),
+    StoreWithoutRecovery(ToMemoryDataOperandType<TypeFromId<IntType>>(),
                          x86_64::kMachineRegRBP,
                          addr_offset,
                          value_offset,
@@ -241,11 +253,33 @@ class HeavyOptimizerFrontend {
     builder_.GenGetSimd<8>(result.machine_reg(), GetThreadStateFRegOffset(reg));
     FpRegister unboxed_result = AllocTempSimdReg();
     if (host_platform::kHasAVX) {
-      builder_.Gen<x86_64::MacroUnboxNanFloat32AVX>(unboxed_result.machine_reg(),
-                                                    result.machine_reg());
+      // This code is defined as intrinsic but if we would call it as intrinsic it would be called
+      // recursively.
+      builder_.Gen<x86_64::MachineInsn<device_arch_info::DeviceInsnInfo<
+          &MacroAssembler<x86_64::Assembler>::UnboxNanAVX<Float32>,
+          "UNBOX_F32",
+          true,
+          []<typename Opcode> { return Opcode::kMachineOpUnboxNanFloat32AVX; },
+          x86_64::device_arch_info::HasAVX,
+          std::tuple<device_arch_info::OperandInfo<x86_64::device_arch_info::FpReg32,
+                                                   device_arch_info::kDef>,
+                     device_arch_info::OperandInfo<x86_64::device_arch_info::FpReg64,
+                                                   device_arch_info::kUseDef>>>>>(
+          unboxed_result.machine_reg(), result.machine_reg());
     } else {
-      builder_.Gen<x86_64::MacroUnboxNanFloat32>(unboxed_result.machine_reg(),
-                                                 result.machine_reg());
+      // This code is defined as intrinsic but if we would call it as intrinsic it would be called
+      // recursively.
+      builder_.Gen<x86_64::MachineInsn<device_arch_info::DeviceInsnInfo<
+          &MacroAssembler<x86_64::Assembler>::UnboxNan<Float32>,
+          "UNBOX_F32",
+          true,
+          []<typename Opcode> { return Opcode::kMachineOpUnboxNanFloat32; },
+          device_arch_info::NoCPUIDRestriction,
+          std::tuple<device_arch_info::OperandInfo<x86_64::device_arch_info::FpReg32,
+                                                   device_arch_info::kDef>,
+                     device_arch_info::OperandInfo<x86_64::device_arch_info::FpReg64,
+                                                   device_arch_info::kUseDef>>>>>(
+          unboxed_result.machine_reg(), result.machine_reg());
     }
     return unboxed_result;
   }
@@ -253,9 +287,31 @@ class HeavyOptimizerFrontend {
   template <typename FloatType>
   void NanBoxFpReg(FpRegister value) {
     if (host_platform::kHasAVX) {
-      builder_.Gen<x86_64::MacroNanBoxFloat32AVX>(value.machine_reg(), value.machine_reg());
+      // This code is defined as intrinsic but if we would call it as intrinsic it would be called
+      // recursively.
+      builder_.Gen<x86_64::MachineInsn<device_arch_info::DeviceInsnInfo<
+          &MacroAssembler<x86_64::Assembler>::NanBoxAVX<Float32>,
+          "BOX_F32",
+          true,
+          []<typename Opcode> { return Opcode::kMachineOpNanBoxFloat32AVX; },
+          x86_64::device_arch_info::HasAVX,
+          std::tuple<device_arch_info::OperandInfo<x86_64::device_arch_info::FpReg64,
+                                                   device_arch_info::kDef>,
+                     device_arch_info::OperandInfo<x86_64::device_arch_info::FpReg32,
+                                                   device_arch_info::kUseDef>>>>>(
+          value.machine_reg(), value.machine_reg());
     } else {
-      builder_.Gen<x86_64::MacroNanBoxFloat32>(value.machine_reg());
+      // This code is defined as intrinsic but if we would call it as intrinsic it would be called
+      // recursively.
+      builder_.Gen<x86_64::MachineInsn<device_arch_info::DeviceInsnInfo<
+          &MacroAssembler<x86_64::Assembler>::NanBox<Float32>,
+          "BOX_F32",
+          true,
+          []<typename Opcode> { return Opcode::kMachineOpNanBoxFloat32; },
+          device_arch_info::NoCPUIDRestriction,
+          std::tuple<device_arch_info::OperandInfo<x86_64::device_arch_info::FpReg64,
+                                                   device_arch_info::kUseDef>>>>>(
+          value.machine_reg());
     }
   }
 
@@ -272,9 +328,9 @@ class HeavyOptimizerFrontend {
   FpRegister LoadFp(Register arg, int16_t offset) {
     auto res = AllocTempSimdReg();
     if constexpr (std::is_same_v<DataType, Float32>) {
-      Gen<x86_64::MovssXRegMemBaseDisp>(res.machine_reg(), arg, offset);
+      Gen<x86_64::MovssXRegOp>(res.machine_reg(), {.base = arg, .disp = offset});
     } else if constexpr (std::is_same_v<DataType, Float64>) {
-      Gen<x86_64::MovsdXRegMemBaseDisp>(res.machine_reg(), arg, offset);
+      Gen<x86_64::MovsdXRegOp>(res.machine_reg(), {.base = arg, .disp = offset});
     } else {
       static_assert(kDependentTypeFalse<DataType>);
     }
@@ -284,9 +340,9 @@ class HeavyOptimizerFrontend {
   template <typename DataType>
   void StoreFp(Register arg, int16_t offset, FpRegister data) {
     if constexpr (std::is_same_v<DataType, Float32>) {
-      Gen<x86_64::MovssMemBaseDispXReg>(arg, offset, data.machine_reg());
+      Gen<x86_64::MovssOpXReg>({.base = arg, .disp = offset}, data.machine_reg());
     } else if constexpr (std::is_same_v<DataType, Float64>) {
-      Gen<x86_64::MovsdMemBaseDispXReg>(arg, offset, data.machine_reg());
+      Gen<x86_64::MovsdOpXReg>({.base = arg, .disp = offset}, data.machine_reg());
     } else {
       static_assert(kDependentTypeFalse<DataType>);
     }
@@ -322,6 +378,9 @@ class HeavyOptimizerFrontend {
   // Intrinsic proxy methods.
   //
 
+#ifdef BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER
+#include "berberis/intrinsics/demultiplexer_intrinsics_hooks-inl.h"
+#endif
 #include "berberis/intrinsics/translator_intrinsics_hooks-inl.h"
 
   //
@@ -344,9 +403,11 @@ class HeavyOptimizerFrontend {
   [[nodiscard]] Register GetCsr() {
     auto csr_reg = AllocTempReg();
     if constexpr (std::is_same_v<CsrFieldType<kName>, uint8_t>) {
-      Gen<x86_64::MovzxblRegMemBaseDisp>(csr_reg, x86_64::kMachineRegRBP, kCsrFieldOffset<kName>);
+      Gen<x86_64::MovzxblRegOp>(csr_reg,
+                                {.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<kName>});
     } else if constexpr (std::is_same_v<CsrFieldType<kName>, uint64_t>) {
-      Gen<x86_64::MovqRegMemBaseDisp>(csr_reg, x86_64::kMachineRegRBP, kCsrFieldOffset<kName>);
+      Gen<x86_64::MovqRegOp>(csr_reg,
+                             {.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<kName>});
     } else {
       static_assert(kDependentTypeFalse<CsrFieldType<kName>>);
     }
@@ -358,13 +419,11 @@ class HeavyOptimizerFrontend {
     // Note: csr immediate only have 5 bits in RISC-V encoding which guarantess us that
     // “imm & kCsrMask<kName>”can be used as 8-bit immediate.
     if constexpr (std::is_same_v<CsrFieldType<kName>, uint8_t>) {
-      Gen<x86_64::MovbMemBaseDispImm>(x86_64::kMachineRegRBP,
-                                      kCsrFieldOffset<kName>,
-                                      static_cast<int8_t>(imm & kCsrMask<kName>));
+      Gen<x86_64::MovbOpImm>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<kName>},
+                             static_cast<int8_t>(imm & kCsrMask<kName>));
     } else if constexpr (std::is_same_v<CsrFieldType<kName>, uint64_t>) {
-      Gen<x86_64::MovbMemBaseDispImm>(x86_64::kMachineRegRBP,
-                                      kCsrFieldOffset<kName>,
-                                      static_cast<int8_t>(imm & kCsrMask<kName>));
+      Gen<x86_64::MovbOpImm>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<kName>},
+                             static_cast<int8_t>(imm & kCsrMask<kName>));
     } else {
       static_assert(kDependentTypeFalse<CsrFieldType<kName>>);
     }
@@ -376,11 +435,11 @@ class HeavyOptimizerFrontend {
     Gen<PseudoCopy>(tmp, arg, sizeof(CsrFieldType<kName>));
     if constexpr (sizeof(CsrFieldType<kName>) == 1) {
       Gen<x86_64::AndbRegImm>(tmp, kCsrMask<kName>, GetFlagsRegister());
-      Gen<x86_64::MovbMemBaseDispReg>(x86_64::kMachineRegRBP, kCsrFieldOffset<kName>, tmp);
+      Gen<x86_64::MovbOpReg>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<kName>}, tmp);
     } else if constexpr (sizeof(CsrFieldType<kName>) == 8) {
-      Gen<x86_64::AndqRegMemAbsolute>(
-          tmp, constants_pool::kConst<uint64_t{kCsrMask<kName>}>, GetFlagsRegister());
-      Gen<x86_64::MovqMemBaseDispReg>(x86_64::kMachineRegRBP, kCsrFieldOffset<kName>, tmp);
+      Gen<x86_64::AndqRegOp>(
+          tmp, {.disp = constants_pool::kConst<uint64_t{kCsrMask<kName>}>}, GetFlagsRegister());
+      Gen<x86_64::MovqOpReg>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<kName>}, tmp);
     } else {
       static_assert(kDependentTypeFalse<CsrFieldType<kName>>);
     }
@@ -451,6 +510,112 @@ class HeavyOptimizerFrontend {
     return builder_.Gen<InsnType, Args...>(args...);
   }
 
+  template <template <typename> typename InsnType>
+  using MachineInsnType =
+      x86_64::MachineInsn<typename InsnType<typename CodeEmitter::Assemblers>::DeviceInsnInfo>;
+
+  template <template <typename> typename InsnType, size_t N>
+  using GenArg = std::tuple_element_t<
+      N,
+      typename x86_64::MachineInsnOperandsHelper<typename InsnType<
+          typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple>;
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen()
+      -> std::enable_if_t<
+          std::tuple_size_v<typename x86_64::MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 0,
+          MachineInsnType<InsnType>*> {
+    return builder_.Gen<MachineInsnType<InsnType>>();
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename x86_64::MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 1,
+          MachineInsnType<InsnType>*> {
+    return builder_.Gen<MachineInsnType<InsnType>, GenArg<InsnType, 0>>(arg0);
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0, GenArg<InsnType, 1> arg1)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename x86_64::MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 2,
+          MachineInsnType<InsnType>*> {
+    return builder_.Gen<MachineInsnType<InsnType>, GenArg<InsnType, 0>, GenArg<InsnType, 1>>(arg0,
+                                                                                             arg1);
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0,
+                           GenArg<InsnType, 1> arg1,
+                           GenArg<InsnType, 2> arg2)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename x86_64::MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 3,
+          MachineInsnType<InsnType>*> {
+    return builder_.Gen<MachineInsnType<InsnType>,
+                        GenArg<InsnType, 0>,
+                        GenArg<InsnType, 1>,
+                        GenArg<InsnType, 2>>(arg0, arg1, arg2);
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0,
+                           GenArg<InsnType, 1> arg1,
+                           GenArg<InsnType, 2> arg2,
+                           GenArg<InsnType, 3> arg3)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename x86_64::MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 4,
+          MachineInsnType<InsnType>*> {
+    return builder_.Gen<MachineInsnType<InsnType>,
+                        GenArg<InsnType, 0>,
+                        GenArg<InsnType, 1>,
+                        GenArg<InsnType, 2>,
+                        GenArg<InsnType, 3>>(arg0, arg1, arg2, arg3);
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0,
+                           GenArg<InsnType, 1> arg1,
+                           GenArg<InsnType, 2> arg2,
+                           GenArg<InsnType, 3> arg3,
+                           GenArg<InsnType, 4> arg4)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename x86_64::MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 5,
+          MachineInsnType<InsnType>*> {
+    return builder_.Gen<MachineInsnType<InsnType>,
+                        GenArg<InsnType, 0>,
+                        GenArg<InsnType, 1>,
+                        GenArg<InsnType, 2>,
+                        GenArg<InsnType, 3>,
+                        GenArg<InsnType, 4>>(arg0, arg1, arg2, arg3, arg4);
+  }
+
+  template <template <typename> typename InsnType>
+  /*may_discard*/ auto Gen(GenArg<InsnType, 0> arg0,
+                           GenArg<InsnType, 1> arg1,
+                           GenArg<InsnType, 2> arg2,
+                           GenArg<InsnType, 3> arg3,
+                           GenArg<InsnType, 4> arg4,
+                           GenArg<InsnType, 5> arg5)
+      -> std::enable_if_t<
+          std::tuple_size_v<typename x86_64::MachineInsnOperandsHelper<typename InsnType<
+              typename CodeEmitter::Assemblers>::DeviceInsnInfo>::ConstructorArgsTuple> == 6,
+          MachineInsnType<InsnType>*> {
+    return builder_.Gen<MachineInsnType<InsnType>,
+                        GenArg<InsnType, 0>,
+                        GenArg<InsnType, 1>,
+                        GenArg<InsnType, 2>,
+                        GenArg<InsnType, 3>,
+                        GenArg<InsnType, 4>,
+                        GenArg<InsnType, 5>>(arg0, arg1, arg2, arg3, arg4, arg5);
+  }
+
   static x86_64::Assembler::Condition ToAssemblerCond(Decoder::BranchOpcode opcode);
 
   [[nodiscard]] Register AllocTempReg();
@@ -512,8 +677,8 @@ HeavyOptimizerFrontend::GetCsr<CsrName::kFCsr>() {
   auto tmp = AllocTempReg();
   InlineIntrinsicForHeavyOptimizer<&intrinsics::FeGetExceptions>(
       &builder_, tmp, GetFlagsRegister());
-  Gen<x86_64::MovzxbqRegMemBaseDisp>(
-      csr_reg, x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kFrm>);
+  Gen<x86_64::MovzxbqRegOp>(
+      csr_reg, {.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kFrm>});
   Gen<x86_64::ShlbRegImm>(csr_reg, 5, GetFlagsRegister());
   Gen<x86_64::OrbRegReg>(csr_reg, tmp, GetFlagsRegister());
   return csr_reg;
@@ -535,7 +700,8 @@ template <>
 [[nodiscard]] inline HeavyOptimizerFrontend::Register
 HeavyOptimizerFrontend::GetCsr<CsrName::kVxrm>() {
   auto reg = AllocTempReg();
-  Gen<x86_64::MovzxbqRegMemBaseDisp>(reg, x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kVcsr>);
+  Gen<x86_64::MovzxbqRegOp>(
+      reg, {.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kVcsr>});
   Gen<x86_64::AndbRegImm>(reg, 0b11, GetFlagsRegister());
   return reg;
 }
@@ -544,7 +710,8 @@ template <>
 [[nodiscard]] inline HeavyOptimizerFrontend::Register
 HeavyOptimizerFrontend::GetCsr<CsrName::kVxsat>() {
   auto reg = AllocTempReg();
-  Gen<x86_64::MovzxbqRegMemBaseDisp>(reg, x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kVcsr>);
+  Gen<x86_64::MovzxbqRegOp>(
+      reg, {.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kVcsr>});
   Gen<x86_64::ShrbRegImm>(reg, 2, GetFlagsRegister());
   return reg;
 }
@@ -558,8 +725,8 @@ inline void HeavyOptimizerFrontend::SetCsr<CsrName::kFCsr>(uint8_t imm) {
   // But Csrrwi may clear it.  And we actually may only arrive here from Csrrwi.
   // Thus, technically, we know that imm >> 5 is always zero, but it doesn't look like a good idea
   // to rely on that: it's very subtle and it only affects code generation speed.
-  Gen<x86_64::MovbMemBaseDispImm>(
-      x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kFrm>, static_cast<int8_t>(imm >> 5));
+  Gen<x86_64::MovbOpImm>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kFrm>},
+                         static_cast<int8_t>(imm >> 5));
   InlineIntrinsicForHeavyOptimizerVoid<&intrinsics::FeSetExceptionsAndRoundImm>(
       &builder_, GetFlagsRegister(), imm);
 }
@@ -578,8 +745,8 @@ inline void HeavyOptimizerFrontend::SetCsr<CsrName::kFCsr>(Register arg) {
   Gen<PseudoDefReg>(rounding_mode);
   Gen<x86_64::ShldlRegRegImm>(rounding_mode, arg, int8_t{32 - 5}, GetFlagsRegister());
   Gen<x86_64::AndbRegImm>(rounding_mode, kCsrMask<CsrName::kFrm>, GetFlagsRegister());
-  Gen<x86_64::MovbMemBaseDispReg>(
-      x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kFrm>, rounding_mode);
+  Gen<x86_64::MovbOpReg>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kFrm>},
+                         rounding_mode);
   InlineIntrinsicForHeavyOptimizerVoid<&intrinsics::FeSetExceptionsAndRound>(
       &builder_, GetFlagsRegister(), exceptions, rounding_mode);
 }
@@ -599,9 +766,8 @@ inline void HeavyOptimizerFrontend::SetCsr<CsrName::kFFlags>(Register arg) {
 
 template <>
 inline void HeavyOptimizerFrontend::SetCsr<CsrName::kFrm>(uint8_t imm) {
-  Gen<x86_64::MovbMemBaseDispImm>(x86_64::kMachineRegRBP,
-                                  kCsrFieldOffset<CsrName::kFrm>,
-                                  static_cast<int8_t>(imm & kCsrMask<CsrName::kFrm>));
+  Gen<x86_64::MovbOpImm>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kFrm>},
+                         static_cast<int8_t>(imm & kCsrMask<CsrName::kFrm>));
   FeSetRoundImm(static_cast<int8_t>(imm & kCsrMask<CsrName::kFrm>));
 }
 
@@ -611,7 +777,8 @@ inline void HeavyOptimizerFrontend::SetCsr<CsrName::kFrm>(Register arg) {
   auto tmp = AllocTempReg();
   Gen<PseudoCopy>(tmp, arg, 1);
   Gen<x86_64::AndbRegImm>(tmp, kCsrMask<CsrName::kFrm>, GetFlagsRegister());
-  Gen<x86_64::MovbMemBaseDispReg>(x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kFrm>, tmp);
+  Gen<x86_64::MovbOpReg>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kFrm>},
+                         tmp);
   FeSetRound(tmp);
 }
 
@@ -619,47 +786,56 @@ template <>
 inline void HeavyOptimizerFrontend::SetCsr<CsrName::kVxrm>(uint8_t imm) {
   imm &= 0b11;
   if (imm != 0b11) {
-    Gen<x86_64::AndbMemBaseDispImm>(
-        x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kVcsr>, 0b100, GetFlagsRegister());
+    Gen<x86_64::AndbOpImm>(
+        {.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kVcsr>},
+        0b100,
+        GetFlagsRegister());
   }
   if (imm != 0b00) {
-    Gen<x86_64::OrbMemBaseDispImm>(
-        x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kVcsr>, imm, GetFlagsRegister());
+    Gen<x86_64::OrbOpImm>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kVcsr>},
+                          imm,
+                          GetFlagsRegister());
   }
 }
 
 template <>
 inline void HeavyOptimizerFrontend::SetCsr<CsrName::kVxrm>(Register arg) {
-  Gen<x86_64::AndbMemBaseDispImm>(
-      x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kVcsr>, 0b100, GetFlagsRegister());
+  Gen<x86_64::AndbOpImm>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kVcsr>},
+                         0b100,
+                         GetFlagsRegister());
   Gen<x86_64::AndbRegImm>(arg, 0b11, GetFlagsRegister());
-  Gen<x86_64::OrbMemBaseDispReg>(
-      x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kVcsr>, arg, GetFlagsRegister());
+  Gen<x86_64::OrbOpReg>(
+      {x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kVcsr>}, arg, GetFlagsRegister());
 }
 
 template <>
 inline void HeavyOptimizerFrontend::SetCsr<CsrName::kVxsat>(uint8_t imm) {
   if (imm & 0b1) {
-    Gen<x86_64::OrbMemBaseDispImm>(
-        x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kVcsr>, 0b100, GetFlagsRegister());
+    Gen<x86_64::OrbOpImm>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kVcsr>},
+                          0b100,
+                          GetFlagsRegister());
   } else {
-    Gen<x86_64::AndbMemBaseDispImm>(
-        x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kVcsr>, 0b11, GetFlagsRegister());
+    Gen<x86_64::AndbOpImm>(
+        {.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kVcsr>},
+        0b11,
+        GetFlagsRegister());
   }
 }
 
 template <>
 inline void HeavyOptimizerFrontend::SetCsr<CsrName::kVxsat>(Register arg) {
   using Condition = x86_64::Assembler::Condition;
-  Gen<x86_64::AndbMemBaseDispImm>(
-      x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kVcsr>, 0b11, GetFlagsRegister());
+  Gen<x86_64::AndbOpImm>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kVcsr>},
+                         0b11,
+                         GetFlagsRegister());
   Gen<x86_64::TestbRegImm>(arg, 1, GetFlagsRegister());
   auto tmp = AllocTempReg();
   Gen<x86_64::SetccReg>(Condition::kNotZero, tmp, GetFlagsRegister());
   Gen<x86_64::MovzxbqRegReg>(tmp, tmp);
   Gen<x86_64::ShlbRegImm>(tmp, int8_t{2}, GetFlagsRegister());
-  Gen<x86_64::OrbMemBaseDispReg>(
-      x86_64::kMachineRegRBP, kCsrFieldOffset<CsrName::kVcsr>, tmp, GetFlagsRegister());
+  Gen<x86_64::OrbOpReg>({.base = x86_64::kMachineRegRBP, .disp = kCsrFieldOffset<CsrName::kVcsr>},
+                        tmp,
+                        GetFlagsRegister());
 }
 
 }  // namespace berberis
diff --git a/heavy_optimizer/riscv64/frontend_demultiplexers.cc b/heavy_optimizer/riscv64/frontend_demultiplexers.cc
new file mode 100644
index 00000000..fc5039c9
--- /dev/null
+++ b/heavy_optimizer/riscv64/frontend_demultiplexers.cc
@@ -0,0 +1,29 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER
+
+#include "frontend.h"
+
+namespace berberis {
+
+#define BERBERIS_INTRINSICS_HOOKS_LISTENER HeavyOptimizerFrontend::
+#include "berberis/intrinsics/demultiplexer_intrinsics_hooks-inl.h"
+#undef BERBERIS_INTRINSICS_HOOKS_LISTENER
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER
diff --git a/heavy_optimizer/riscv64/inline_intrinsic.h b/heavy_optimizer/riscv64/inline_intrinsic.h
index 2b9e7870..de0c1273 100644
--- a/heavy_optimizer/riscv64/inline_intrinsic.h
+++ b/heavy_optimizer/riscv64/inline_intrinsic.h
@@ -25,16 +25,14 @@
 #include <variant>
 
 #include "berberis/assembler/x86_64.h"
-#include "berberis/backend/common/machine_ir.h"
-#include "berberis/backend/x86_64/machine_insn_intrinsics.h"
 #include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/backend/x86_64/machine_ir_builder.h"
 #include "berberis/base/checks.h"
 #include "berberis/base/config.h"
 #include "berberis/base/dependent_false.h"
-#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h"
 #include "berberis/intrinsics/intrinsics.h"
 #include "berberis/intrinsics/intrinsics_args.h"
+#include "berberis/intrinsics/intrinsics_bindings.h"
 #include "berberis/intrinsics/intrinsics_process_bindings.h"
 #include "berberis/intrinsics/macro_assembler.h"
 #include "berberis/runtime_primitives/platform.h"
@@ -177,7 +175,7 @@ template <typename DestRegClass, typename SrcRegClass>
 void Mov(x86_64::MachineIRBuilder* builder, MachineReg dest, MachineReg src) {
   using DestType = typename DestRegClass::Type;
   using SrcType = typename SrcRegClass::Type;
-  constexpr const auto src_reg_class = SrcRegClass::template kRegClass<x86_64::MachineInsnX86_64>;
+  constexpr const auto& src_reg_class = x86_64::kRegisterClass<SrcRegClass>;
   if constexpr (std::is_integral_v<DestType>) {
     if constexpr (std::is_integral_v<SrcType>) {
       builder->Gen<PseudoCopy>(dest, src, src_reg_class.RegSize());
@@ -232,17 +230,17 @@ void Mov(x86_64::MachineIRBuilder* builder, MachineReg dest, MachineReg src) {
 template <typename DestRegClass, typename SrcReg>
 void MovFromInput(x86_64::MachineIRBuilder* builder, MachineReg dest, SrcReg src) {
   if constexpr (std::is_same_v<SrcReg, SimdReg>) {
-    Mov<DestRegClass, intrinsics::bindings::XmmReg>(builder, dest, src.machine_reg());
+    Mov<DestRegClass, x86_64::device_arch_info::XmmReg>(builder, dest, src.machine_reg());
   } else {
-    Mov<DestRegClass, intrinsics::bindings::GeneralReg64>(builder, dest, src);
+    Mov<DestRegClass, x86_64::device_arch_info::GeneralReg64>(builder, dest, src);
   }
 }
 template <typename SrcRegClass, typename DestReg>
 void MovToResult(x86_64::MachineIRBuilder* builder, DestReg dest, MachineReg src) {
   if constexpr (std::is_same_v<DestReg, SimdReg>) {
-    Mov<intrinsics::bindings::XmmReg, SrcRegClass>(builder, dest.machine_reg(), src);
+    Mov<x86_64::device_arch_info::XmmReg, SrcRegClass>(builder, dest.machine_reg(), src);
   } else {
-    Mov<intrinsics::bindings::GeneralReg64, SrcRegClass>(builder, dest, src);
+    Mov<x86_64::device_arch_info::GeneralReg64, SrcRegClass>(builder, dest, src);
   }
 }
 
@@ -266,19 +264,12 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
             typename Result,
             typename Callback,
             typename... Args>
-  friend constexpr Result intrinsics::bindings::ProcessBindings(Callback callback,
-                                                                Result def_result,
-                                                                Args&&... args);
-
-  template <auto kIntrinsicTemplateName,
-            auto kMacroInstructionTemplateName,
-            auto kMnemo,
-            typename GetOpcode,
-            typename CPUIDRestrictionTemplateValue,
-            typename PreciseNanOperationsHandlingTemplateValue,
-            bool kSideEffectsTemplateValue,
-            typename... Types>
-  friend class intrinsics::bindings::AsmCallInfo;
+  friend constexpr Result x86_64::intrinsics::bindings::ProcessBindings(Callback callback,
+                                                                        Result def_result,
+                                                                        Args&&... args);
+
+  template <StringLiteral kIntrinsic, typename... Types>
+  friend class intrinsics::bindings::IntrinsicBindingInfo;
 
   TryBindingBasedInlineIntrinsicForHeavyOptimizer() = delete;
   TryBindingBasedInlineIntrinsicForHeavyOptimizer(
@@ -301,7 +292,7 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
         input_args_(std::tuple{args...}),
         success_(intrinsics::bindings::ProcessBindings<
                  kFunction,
-                 typename MacroAssembler<x86_64::Assembler>::MacroAssemblers,
+                 typename MacroAssembler<x86_64::Assembler>::Assemblers,
                  bool,
                  TryBindingBasedInlineIntrinsicForHeavyOptimizer&>(*this, false)) {}
 
@@ -309,188 +300,193 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
 
   // TODO(b/232598137) The MachineIR bindings for some macros can't be instantiated yet. This should
   // be removed once they're supported.
-  template <typename AsmCallInfo,
-            std::enable_if_t<AsmCallInfo::template kOpcode<MachineOpcode> ==
+  template <typename IntrinsicBindingInfo,
+            std::enable_if_t<IntrinsicBindingInfo::template kOpcode<MachineOpcode> ==
                                  MachineOpcode::kMachineOpUndefined,
                              bool> = true>
-  std::optional<bool> /*ProcessBindingsClient*/ operator()(AsmCallInfo /* asm_call_info */) {
+  std::optional<bool> /*ProcessBindingsClient*/ operator()(
+      IntrinsicBindingInfo /* asm_call_info */) {
     return false;
   }
 
-  template <typename AsmCallInfo,
-            std::enable_if_t<AsmCallInfo::template kOpcode<MachineOpcode> !=
+  template <typename IntrinsicBindingInfo,
+            std::enable_if_t<IntrinsicBindingInfo::template kOpcode<MachineOpcode> !=
                                  MachineOpcode::kMachineOpUndefined,
                              bool> = true>
-  std::optional<bool> /*ProcessBindingsClient*/ operator()(AsmCallInfo asm_call_info) {
-    static_assert(std::is_same_v<decltype(kFunction), typename AsmCallInfo::IntrinsicType>);
-    static_assert(std::is_same_v<typename AsmCallInfo::PreciseNanOperationsHandling,
+  std::optional<bool> /*ProcessBindingsClient*/ operator()(IntrinsicBindingInfo asm_call_info) {
+    static_assert(
+        std::is_same_v<decltype(kFunction), typename IntrinsicBindingInfo::IntrinsicType>);
+    static_assert(std::is_same_v<typename IntrinsicBindingInfo::PreciseNanOperationsHandling,
                                  intrinsics::bindings::NoNansOperation>);
-    using CPUIDRestriction = AsmCallInfo::CPUIDRestriction;
-    if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX>) {
+    using CPUIDRestriction = IntrinsicBindingInfo::CPUIDRestriction;
+    if constexpr (std::is_same_v<CPUIDRestriction, x86_32_or_x86_64::device_arch_info::HasAVX>) {
       if (!host_platform::kHasAVX) {
         return {};
       }
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        x86_32_or_x86_64::device_arch_info::HasBMI>) {
       if (!host_platform::kHasBMI) {
         return {};
       }
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        x86_32_or_x86_64::device_arch_info::HasFMA>) {
+      if (!host_platform::kHasFMA) {
+        return {};
+      }
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        x86_32_or_x86_64::device_arch_info::HasLZCNT>) {
       if (!host_platform::kHasLZCNT) {
         return {};
       }
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        x86_32_or_x86_64::device_arch_info::HasPOPCNT>) {
       if (!host_platform::kHasPOPCNT) {
         return {};
       }
     } else if constexpr (std::is_same_v<CPUIDRestriction,
-                                        intrinsics::bindings::NoCPUIDRestriction>) {
+                                        x86_32_or_x86_64::device_arch_info::NoCPUIDRestriction>) {
       // No restrictions. Do nothing.
     } else {
-      static_assert(berberis::kDependentValueFalse<AsmCallInfo::kCPUIDRestriction>);
+      static_assert(berberis::kDependentValueFalse<IntrinsicBindingInfo::kCPUIDRestriction>);
     }
 
-    // constructor_args_t here is used to generate a tuple of constructor args from the AsmCallInfo
-    // bindings. The tuple parameter pack will be expanded by the tuple specialization on the
-    // MachineInsn in machine_insn_intrinsics.h.
-    using MachineInsn = typename AsmCallInfo::template MachineInsn<berberis::x86_64::MachineInsn,
-                                                                   x86_64::constructor_args_t,
-                                                                   MachineOpcode>;
-    std::apply(MachineInsn::kGenFunc,
+    std::apply(berberis::x86_64::MachineInsn<typename IntrinsicBindingInfo::DeviceInsnInfo>::
+                   template kGenFunc<x86_64::MachineIRBuilder>,
                std::tuple_cat(std::tuple<x86_64::MachineIRBuilder&>{*builder_},
-                              UnwrapSimdReg(AsmCallInfo::template MakeTuplefromBindings<
+                              UnwrapSimdReg(IntrinsicBindingInfo::template MakeTuplefromBindings<
                                             TryBindingBasedInlineIntrinsicForHeavyOptimizer&>(
                                   *this, asm_call_info))));
-    ProcessBindingsResults<AsmCallInfo>(type_wrapper<typename AsmCallInfo::Bindings>());
+    ProcessBindingsResults<IntrinsicBindingInfo>(
+        type_wrapper<typename IntrinsicBindingInfo::Bindings>(),
+        type_wrapper<typename IntrinsicBindingInfo::Operands>());
     return true;
   }
 
-  template <typename ArgBinding, typename AsmCallInfo>
-  auto /*MakeTuplefromBindingsClient*/ operator()(ArgTraits<ArgBinding>, AsmCallInfo) {
-    static constexpr const auto& arg_info = ArgTraits<ArgBinding>::arg_info;
-    if constexpr (arg_info.arg_type == ArgInfo::IMM_ARG) {
-      auto imm = std::get<arg_info.from>(input_args_);
+  template <typename ArgBinding, typename OperandInfo, typename IntrinsicBindingInfo>
+  auto /*MakeTuplefromBindingsClient*/ operator()(IntrinsicBindingInfo) {
+    if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IMM_ARG) {
+      auto imm = std::get<ArgBinding::kArgInfo.from>(input_args_);
       return std::tuple{imm};
     } else {
-      return ProcessArgInput<ArgBinding, AsmCallInfo>();
+      return ProcessArgInput<ArgBinding, OperandInfo, IntrinsicBindingInfo>();
     }
   }
 
-  template <typename ArgBinding, typename AsmCallInfo>
+  template <typename ArgBinding, typename OperandInfo, typename IntrinsicBindingInfo>
   auto ProcessArgInput() {
-    static constexpr const auto& arg_info = ArgTraits<ArgBinding>::arg_info;
-    using RegisterClass = typename ArgTraits<ArgBinding>::RegisterClass;
-    using Usage = typename ArgTraits<ArgBinding>::Usage;
-    static constexpr const auto kNumOut = std::tuple_size_v<typename AsmCallInfo::OutputArguments>;
-
-    if constexpr (arg_info.arg_type == ArgInfo::IN_ARG) {
-      static_assert(std::is_same_v<Usage, intrinsics::bindings::Use>);
-      static_assert(!RegisterClass::kIsImplicitReg);
+    using RegisterClass = typename OperandInfo::Class;
+    static constexpr auto kUsage = OperandInfo::kUsage;
+    static constexpr auto kNumOut =
+        std::tuple_size_v<typename IntrinsicBindingInfo::OutputArguments>;
+
+    if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IN_ARG) {
+      static_assert(kUsage == device_arch_info::kUse);
+      static_assert(!device_arch_info::kIsImplicitReg<OperandInfo>);
       if constexpr (RegisterClass::kAsRegister == 'x' &&
-                    std::is_same_v<std::tuple_element_t<arg_info.from, std::tuple<ArgType...>>,
-                                   MachineReg>) {
+                    std::is_same_v<
+                        std::tuple_element_t<ArgBinding::kArgInfo.from, std::tuple<ArgType...>>,
+                        MachineReg>) {
         auto xmm_reg = AllocVReg();
-        MovFromInput<RegisterClass>(builder_, xmm_reg, std::get<arg_info.from>(input_args_));
+        MovFromInput<RegisterClass>(
+            builder_, xmm_reg, std::get<ArgBinding::kArgInfo.from>(input_args_));
         return std::tuple{xmm_reg};
       } else {
-        return std::tuple{std::get<arg_info.from>(input_args_)};
+        return std::tuple{std::get<ArgBinding::kArgInfo.from>(input_args_)};
       }
-    } else if constexpr (arg_info.arg_type == ArgInfo::IN_OUT_ARG) {
+    } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IN_OUT_ARG) {
       static_assert(!std::is_same_v<ResType, std::monostate>);
-      static_assert(std::is_same_v<Usage, intrinsics::bindings::UseDef>);
-      static_assert(!RegisterClass::kIsImplicitReg);
+      static_assert(kUsage == device_arch_info::kUseDef);
+      static_assert(!device_arch_info::kIsImplicitReg<OperandInfo>);
       if constexpr (RegisterClass::kAsRegister == 'x') {
         if constexpr (kNumOut > 1) {
-          static_assert(kDependentTypeFalse<ArgTraits<ArgBinding>>);
+          static_assert(kDependentTypeFalse<ArgBinding>);
         } else {
           CHECK(xmm_result_reg_.IsInvalidReg());
           xmm_result_reg_ = AllocVReg();
           MovFromInput<RegisterClass>(
-              builder_, xmm_result_reg_, std::get<arg_info.from>(input_args_));
+              builder_, xmm_result_reg_, std::get<ArgBinding::kArgInfo.from>(input_args_));
           return std::tuple{xmm_result_reg_};
         }
       } else if constexpr (kNumOut > 1) {
-        auto res = std::get<arg_info.to>(result_);
-        MovFromInput<RegisterClass>(builder_, res, std::get<arg_info.from>(input_args_));
+        auto res = std::get<ArgBinding::kArgInfo.to>(result_);
+        MovFromInput<RegisterClass>(
+            builder_, res, std::get<ArgBinding::kArgInfo.from>(input_args_));
         return std::tuple{res};
       } else {
-        MovFromInput<RegisterClass>(builder_, result_, std::get<arg_info.from>(input_args_));
+        MovFromInput<RegisterClass>(
+            builder_, result_, std::get<ArgBinding::kArgInfo.from>(input_args_));
         return std::tuple{result_};
       }
-    } else if constexpr (arg_info.arg_type == ArgInfo::IN_OUT_TMP_ARG) {
+    } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IN_OUT_TMP_ARG) {
       static_assert(!std::is_same_v<ResType, std::monostate>);
-      static_assert(std::is_same_v<Usage, intrinsics::bindings::UseDef>);
-      static_assert(RegisterClass::kIsImplicitReg);
+      static_assert(kUsage == device_arch_info::kUseDef);
+      static_assert(device_arch_info::kIsImplicitReg<OperandInfo>);
       if constexpr (kNumOut > 1) {
-        static_assert(kDependentTypeFalse<ArgTraits<ArgBinding>>);
+        static_assert(kDependentTypeFalse<ArgBinding>);
       } else {
         CHECK(implicit_result_reg_.IsInvalidReg());
         implicit_result_reg_ = AllocVReg();
         MovFromInput<RegisterClass>(
-            builder_, implicit_result_reg_, std::get<arg_info.from>(input_args_));
+            builder_, implicit_result_reg_, std::get<ArgBinding::kArgInfo.from>(input_args_));
         return std::tuple{implicit_result_reg_};
       }
-    } else if constexpr (arg_info.arg_type == ArgInfo::IN_TMP_ARG) {
-      if constexpr (RegisterClass::kIsImplicitReg) {
+    } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IN_TMP_ARG) {
+      if constexpr (device_arch_info::kIsImplicitReg<OperandInfo>) {
         auto implicit_reg = AllocVReg();
-        MovFromInput<RegisterClass>(builder_, implicit_reg, std::get<arg_info.from>(input_args_));
+        MovFromInput<RegisterClass>(
+            builder_, implicit_reg, std::get<ArgBinding::kArgInfo.from>(input_args_));
         return std::tuple{implicit_reg};
       } else {
-        static_assert(std::is_same_v<Usage, intrinsics::bindings::UseDef>);
-        return std::tuple{std::get<arg_info.from>(input_args_)};
+        static_assert(kUsage == device_arch_info::kUseDef);
+        return std::tuple{std::get<ArgBinding::kArgInfo.from>(input_args_)};
       }
-    } else if constexpr (arg_info.arg_type == ArgInfo::OUT_TMP_ARG) {
+    } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::OUT_TMP_ARG) {
       if constexpr (kNumOut > 1) {
-        static_assert(kDependentTypeFalse<ArgTraits<ArgBinding>>);
+        static_assert(kDependentTypeFalse<ArgBinding>);
       } else {
         CHECK(implicit_result_reg_.IsInvalidReg());
         implicit_result_reg_ = AllocVReg();
         return std::tuple{implicit_result_reg_};
       }
-    } else if constexpr (arg_info.arg_type == ArgInfo::OUT_ARG) {
+    } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::OUT_ARG) {
       static_assert(!std::is_same_v<ResType, std::monostate>);
-      static_assert(std::is_same_v<Usage, intrinsics::bindings::Def> ||
-                    std::is_same_v<Usage, intrinsics::bindings::DefEarlyClobber>);
-      if constexpr (RegisterClass::kAsRegister == 'x') {
+      static_assert(kUsage == device_arch_info::kDef ||
+                    kUsage == device_arch_info::kDefEarlyClobber);
+      if constexpr (device_arch_info::kIsFLAGS<OperandInfo>) {
+        return std::tuple{flag_register_};
+      } else if constexpr (RegisterClass::kAsRegister == 'x') {
         CHECK(xmm_result_reg_.IsInvalidReg());
         xmm_result_reg_ = AllocVReg();
         return std::tuple{xmm_result_reg_};
       } else if constexpr (kNumOut > 1) {
-        return std::tuple{std::get<arg_info.to>(result_)};
-      } else if constexpr (RegisterClass::kIsImplicitReg) {
-        if constexpr (RegisterClass::kAsRegister == 0) {
-          return std::tuple{flag_register_};
-        } else {
-          CHECK(implicit_result_reg_.IsInvalidReg());
-          implicit_result_reg_ = AllocVReg();
-          return std::tuple{implicit_result_reg_};
-        }
+        return std::tuple{std::get<ArgBinding::kArgInfo.to>(result_)};
+      } else if constexpr (device_arch_info::kIsImplicitReg<OperandInfo>) {
+        CHECK(implicit_result_reg_.IsInvalidReg());
+        implicit_result_reg_ = AllocVReg();
+        return std::tuple{implicit_result_reg_};
       } else {
         return std::tuple{result_};
       }
-    } else if constexpr (arg_info.arg_type == ArgInfo::TMP_ARG) {
-      static_assert(std::is_same_v<Usage, intrinsics::bindings::Def> ||
-                    std::is_same_v<Usage, intrinsics::bindings::DefEarlyClobber>);
-      if constexpr (RegisterClass::kAsRegister == 'm') {
-        static_assert(std::is_same_v<Usage, intrinsics::bindings::DefEarlyClobber>);
+    } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::TMP_ARG) {
+      static_assert(kUsage == device_arch_info::kDef ||
+                    kUsage == device_arch_info::kDefEarlyClobber);
+      if constexpr (device_arch_info::kIsFLAGS<OperandInfo>) {
+        return std::tuple{flag_register_};
+      } else if constexpr (device_arch_info::kIsMemoryOperand<OperandInfo>) {
+        static_assert(kUsage == device_arch_info::kDefEarlyClobber);
         if (scratch_arg_ >= 2) {
           FATAL("Only two scratch registers are supported for now");
         }
-        return std::tuple{x86_64::kMachineRegRBP,
-                          static_cast<int32_t>(offsetof(ThreadState, intrinsics_scratch_area) +
-                                               config::kScratchAreaSlotSize * scratch_arg_++)};
-      } else if constexpr (RegisterClass::kIsImplicitReg) {
-        if constexpr (RegisterClass::kAsRegister == 0) {
-          return std::tuple{flag_register_};
-        } else {
-          auto implicit_reg = AllocVReg();
-          return std::tuple{implicit_reg};
-        }
+        return std::tuple{x86_64::MemoryOperand{
+            .base = x86_64::kMachineRegRBP,
+            .disp = static_cast<int32_t>(offsetof(ThreadState, intrinsics_scratch_area) +
+                                         config::kScratchAreaSlotSize * scratch_arg_++)}};
       } else {
         auto reg = AllocVReg();
         return std::tuple{reg};
       }
     } else {
-      static_assert(berberis::kDependentValueFalse<arg_info.arg_type>);
+      static_assert(berberis::kDependentValueFalse<ArgBinding::kArgInfo.arg_type>);
     }
   }
 
@@ -499,13 +495,14 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
     using type = T;
   };
 
-  template <typename AsmCallInfo, typename... ArgBinding>
-  void ProcessBindingsResults(type_wrapper<std::tuple<ArgBinding...>>) {
-    (ProcessBindingResult<ArgBinding, AsmCallInfo>(), ...);
-    if constexpr (std::tuple_size_v<typename AsmCallInfo::OutputArguments> == 0) {
+  template <typename IntrinsicBindingInfo, typename... ArgBinding, typename... OperandInfo>
+  void ProcessBindingsResults(type_wrapper<std::tuple<ArgBinding...>>,
+                              type_wrapper<std::tuple<OperandInfo...>>) {
+    (ProcessBindingResult<ArgBinding, OperandInfo, IntrinsicBindingInfo>(), ...);
+    if constexpr (std::tuple_size_v<typename IntrinsicBindingInfo::OutputArguments> == 0) {
       // No return value. Do nothing.
-    } else if constexpr (std::tuple_size_v<typename AsmCallInfo::OutputArguments> == 1) {
-      using ReturnType = std::tuple_element_t<0, typename AsmCallInfo::OutputArguments>;
+    } else if constexpr (std::tuple_size_v<typename IntrinsicBindingInfo::OutputArguments> == 1) {
+      using ReturnType = std::tuple_element_t<0, typename IntrinsicBindingInfo::OutputArguments>;
       if constexpr (std::is_integral_v<ReturnType> && sizeof(ReturnType) < sizeof(int32_t)) {
         // Don't handle these types just yet. We are not sure how to expand them and there
         // are no examples.
@@ -525,28 +522,27 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
         static_assert(kDependentTypeFalse<ReturnType>);
       }
     } else {
-      static_assert(kDependentTypeFalse<typename AsmCallInfo::OutputArguments>);
+      static_assert(kDependentTypeFalse<typename IntrinsicBindingInfo::OutputArguments>);
     }
   }
 
-  template <typename ArgBinding, typename AsmCallInfo>
+  template <typename ArgBinding, typename OperandInfo, typename IntrinsicBindingInfo>
   void ProcessBindingResult() {
-    if constexpr (ArgTraits<ArgBinding>::Class::kIsImmediate) {
+    if constexpr (device_arch_info::kIsImmediate<OperandInfo> ||
+                  device_arch_info::kIsFLAGS<OperandInfo> ||
+                  device_arch_info::kIsMemoryOperand<OperandInfo>) {
       return;
     } else {
-      using RegisterClass = typename ArgTraits<ArgBinding>::RegisterClass;
-      static constexpr const auto& arg_info = ArgTraits<ArgBinding>::arg_info;
-      if constexpr (RegisterClass::kAsRegister == 'm' || RegisterClass::kAsRegister == 0) {
-        return;
-      } else if constexpr ((arg_info.arg_type == ArgInfo::IN_OUT_ARG ||
-                            arg_info.arg_type == ArgInfo::OUT_ARG) &&
-                           RegisterClass::kAsRegister == 'x') {
+      using RegisterClass = typename OperandInfo::Class;
+      if constexpr ((ArgBinding::kArgInfo.arg_type == ArgInfo::IN_OUT_ARG ||
+                     ArgBinding::kArgInfo.arg_type == ArgInfo::OUT_ARG) &&
+                    RegisterClass::kAsRegister == 'x') {
         CHECK(!xmm_result_reg_.IsInvalidReg());
         MovToResult<RegisterClass>(builder_, result_, xmm_result_reg_);
-      } else if constexpr ((arg_info.arg_type == ArgInfo::OUT_ARG ||
-                            arg_info.arg_type == ArgInfo::IN_OUT_TMP_ARG ||
-                            arg_info.arg_type == ArgInfo::OUT_TMP_ARG) &&
-                           RegisterClass::kIsImplicitReg) {
+      } else if constexpr ((ArgBinding::kArgInfo.arg_type == ArgInfo::OUT_ARG ||
+                            ArgBinding::kArgInfo.arg_type == ArgInfo::IN_OUT_TMP_ARG ||
+                            ArgBinding::kArgInfo.arg_type == ArgInfo::OUT_TMP_ARG) &&
+                           device_arch_info::kIsImplicitReg<OperandInfo>) {
         CHECK(!implicit_result_reg_.IsInvalidReg());
         MovToResult<RegisterClass>(builder_, result_, implicit_result_reg_);
       }
diff --git a/interpreter/Android.bp b/interpreter/Android.bp
index 469e7da1..ec8fa56a 100644
--- a/interpreter/Android.bp
+++ b/interpreter/Android.bp
@@ -49,6 +49,7 @@ cc_library_static {
             ],
             srcs: [
                 "riscv64/faulty_memory_accesses_x86_64.cc",
+                "riscv64/interpreter-demultiplexers.cc",
                 "riscv64/interpreter-VLoadIndexedArgs.cc",
                 "riscv64/interpreter-VLoadStrideArgs.cc",
                 "riscv64/interpreter-VLoadUnitStrideArgs.cc",
diff --git a/interpreter/riscv64/interpreter-demultiplexers.cc b/interpreter/riscv64/interpreter-demultiplexers.cc
new file mode 100644
index 00000000..ee4a6861
--- /dev/null
+++ b/interpreter/riscv64/interpreter-demultiplexers.cc
@@ -0,0 +1,31 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER
+
+#include "interpreter.h"
+
+namespace berberis {
+
+#define BERBERIS_INTRINSICS_HOOKS_LISTENER Interpreter::
+#define BERBERIS_INTRINSICS_HOOKS_CONST const
+#include "berberis/intrinsics/demultiplexer_intrinsics_hooks-inl.h"
+#undef BERBERIS_INTRINSICS_HOOKS_CONST
+#undef BERBERIS_INTRINSICS_HOOKS_LISTENER
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER
diff --git a/interpreter/riscv64/interpreter.h b/interpreter/riscv64/interpreter.h
index aa9d5876..fc885746 100644
--- a/interpreter/riscv64/interpreter.h
+++ b/interpreter/riscv64/interpreter.h
@@ -73,6 +73,17 @@ class Interpreter {
   using Float32 = intrinsics::Float32;
   using Float64 = intrinsics::Float64;
 
+  using TemplateTypeId = intrinsics::TemplateTypeId;
+  template <typename Type>
+  static constexpr auto kIdFromType = intrinsics::kIdFromType<Type>;
+  template <auto kEnumValue>
+  using TypeFromId = intrinsics::TypeFromId<kEnumValue>;
+  template <auto ValueParam>
+  using Value = intrinsics::Value<ValueParam>;
+  static constexpr TemplateTypeId IntSizeToTemplateTypeId(uint8_t size, bool is_signed = false) {
+    return intrinsics::IntSizeToTemplateTypeId(size, is_signed);
+  }
+
   explicit Interpreter(ThreadState* state)
       : state_(state), branch_taken_(false), exception_raised_(false) {}
 
@@ -167,24 +178,25 @@ class Interpreter {
   }
 #endif
 
-  template <typename IntType, bool aq, bool rl>
-  Register Lr(int64_t addr) {
-    static_assert(std::is_integral_v<IntType>, "Lr: IntType must be integral");
-    static_assert(std::is_signed_v<IntType>, "Lr: IntType must be signed");
+  template <intrinsics::TemplateTypeId IntType, bool aq, bool rl>
+  Register Lr(int64_t addr, Value<IntType>, Value<aq>, Value<rl>) {
+    static_assert(std::is_integral_v<TypeFromId<IntType>>, "Lr: IntType must be integral");
+    static_assert(std::is_signed_v<TypeFromId<IntType>>, "Lr: IntType must be signed");
     CHECK(!exception_raised_);
     // Address must be aligned on size of IntType.
-    CHECK((addr % sizeof(IntType)) == 0ULL);
-    return MemoryRegionReservation::Load<IntType>(&state_->cpu, addr, AqRlToStdMemoryOrder(aq, rl));
+    CHECK((addr % sizeof(TypeFromId<IntType>)) == 0ULL);
+    return MemoryRegionReservation::Load<TypeFromId<IntType>>(
+        &state_->cpu, addr, AqRlToStdMemoryOrder(aq, rl));
   }
 
-  template <typename IntType, bool aq, bool rl>
-  Register Sc(int64_t addr, IntType val) {
-    static_assert(std::is_integral_v<IntType>, "Sc: IntType must be integral");
-    static_assert(std::is_signed_v<IntType>, "Sc: IntType must be signed");
+  template <intrinsics::TemplateTypeId IntType, bool aq, bool rl>
+  Register Sc(int64_t addr, TypeFromId<IntType> val, Value<IntType>, Value<aq>, Value<rl>) {
+    static_assert(std::is_integral_v<TypeFromId<IntType>>, "Sc: IntType must be integral");
+    static_assert(std::is_signed_v<TypeFromId<IntType>>, "Sc: IntType must be signed");
     CHECK(!exception_raised_);
     // Address must be aligned on size of IntType.
     CHECK((addr % sizeof(IntType)) == 0ULL);
-    return static_cast<Register>(MemoryRegionReservation::Store<IntType>(
+    return static_cast<Register>(MemoryRegionReservation::Store<TypeFromId<IntType>>(
         &state_->cpu, addr, val, AqRlToStdMemoryOrder(aq, rl)));
   }
 
@@ -4455,6 +4467,11 @@ class Interpreter {
     }
   }
 
+#ifdef BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER
+#define BERBERIS_INTRINSICS_HOOKS_CONST const
+#include "berberis/intrinsics/demultiplexer_intrinsics_hooks-inl.h"
+#undef BERBERIS_INTRINSICS_HOOKS_CONST
+#endif
 #include "berberis/intrinsics/interpreter_intrinsics_hooks-inl.h"
 
  private:
@@ -4788,7 +4805,7 @@ template <>
 #else
   CheckFpRegIsValid(reg);
   FpRegister value = state_->cpu.f[reg];
-  return UnboxNan<Float32>(value);
+  return UnboxNan(value, Value<intrinsics::kFloat32>{});
 #endif
 }
 
@@ -4812,7 +4829,7 @@ void inline Interpreter::NanBoxAndSetFpReg<Interpreter::Float32>(uint8_t reg, Fp
     return;
   }
   CheckFpRegIsValid(reg);
-  state_->cpu.f[reg] = NanBox<Float32>(value);
+  state_->cpu.f[reg] = NanBox(value, Value<intrinsics::kFloat32>{});
 }
 
 template <>
diff --git a/intrinsics/Android.bp b/intrinsics/Android.bp
index 3279c5fe..df692928 100644
--- a/intrinsics/Android.bp
+++ b/intrinsics/Android.bp
@@ -21,7 +21,10 @@ python_binary_host {
     name: "gen_intrinsics",
     main: "gen_intrinsics.py",
     srcs: ["gen_intrinsics.py"],
-    libs: ["asm_defs_lib"],
+    libs: [
+        "asm_defs_lib",
+        "gen_device_insn_info_lib",
+    ],
 }
 
 python_library_host {
@@ -36,7 +39,10 @@ python_test_host {
         "gen_intrinsics_test.py",
         "gen_intrinsics.py",
     ],
-    libs: ["asm_defs_lib"],
+    libs: [
+        "asm_defs_lib",
+        "gen_device_insn_info_lib",
+    ],
     test_suites: ["device-tests"],
     test_options: {
         unit_test: true,
@@ -119,9 +125,25 @@ filegroup {
     srcs: ["riscv64_to_x86_64/machine_ir_intrinsic_binding.json"],
 }
 
+filegroup {
+    name: "libberberis_macro_assembler_gen_inputs_all_to_x86_32_or_x86_64",
+    srcs: ["all_to_x86_32_or_x86_64/macro_def.json"],
+}
+
+filegroup {
+    name: "libberberis_macro_assembler_gen_inputs_all_to_x86_64",
+    srcs: [
+        ":libberberis_macro_assembler_gen_inputs_all_to_x86_32_or_x86_64",
+        "all_to_x86_64/macro_def.json",
+    ],
+}
+
 filegroup {
     name: "libberberis_macro_assembler_gen_inputs_riscv64_to_x86_64",
-    srcs: ["riscv64_to_x86_64/macro_def.json"],
+    srcs: [
+        ":libberberis_macro_assembler_gen_inputs_all_to_x86_64",
+        "riscv64_to_x86_64/macro_def.json",
+    ],
 }
 
 filegroup {
@@ -148,8 +170,8 @@ genrule {
     srcs: [
         ":libberberis_intrinsics_gen_inputs_riscv64_to_all",
         ":libberberis_machine_ir_intrinsic_binding_riscv64_to_x86_64",
-        ":libberberis_macro_assembler_gen_inputs_riscv64_to_x86_64",
         ":libberberis_assembler_gen_inputs_x86_64",
+        ":libberberis_macro_assembler_gen_inputs_riscv64_to_x86_64",
     ],
     tools: ["gen_intrinsics"],
     cmd: "$(location gen_intrinsics) --text_asm_intrinsics_bindings $(out) $(in)",
@@ -162,13 +184,14 @@ genrule {
         "berberis/intrinsics/intrinsics_process_bindings-inl.h",
         "berberis/intrinsics/interpreter_intrinsics_hooks-inl.h",
         "berberis/intrinsics/translator_intrinsics_hooks-inl.h",
+        "berberis/intrinsics/demultiplexer_intrinsics_hooks-inl.h",
         "berberis/intrinsics/mock_semantics_listener_intrinsics_hooks-inl.h",
     ],
     srcs: [
         ":libberberis_intrinsics_gen_inputs_riscv64_to_all",
         ":libberberis_machine_ir_intrinsic_binding_riscv64_to_x86_64",
-        ":libberberis_macro_assembler_gen_inputs_riscv64_to_x86_64",
         ":libberberis_assembler_gen_inputs_x86_64",
+        ":libberberis_macro_assembler_gen_inputs_riscv64_to_x86_64",
     ],
     tools: ["gen_intrinsics"],
     cmd: "$(location gen_intrinsics) --public_headers $(out) $(in)",
@@ -176,7 +199,11 @@ genrule {
 
 genrule {
     name: "libberberis_macro_assembler_gen_headers_riscv64_to_x86_64",
-    out: ["berberis/intrinsics/macro_assembler_interface-inl.h"],
+    out: [
+        "berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler_interface-inl.h",
+        "berberis/intrinsics/all_to_x86_64/macro_assembler_interface-inl.h",
+        "berberis/intrinsics/riscv64_to_x86_64/macro_assembler_interface-inl.h",
+    ],
     srcs: [":libberberis_macro_assembler_gen_inputs_riscv64_to_x86_64"],
     tools: ["gen_asm"],
     cmd: "$(location gen_asm) --binary-assembler $(out) $(in)",
@@ -187,6 +214,7 @@ genrule {
     out: [
         "berberis/intrinsics/intrinsics-inl.h",
         "berberis/intrinsics/interpreter_intrinsics_hooks-inl.h",
+        "berberis/intrinsics/demultiplexer_intrinsics_hooks-inl.h",
     ],
     srcs: [
         ":libberberis_intrinsics_gen_inputs_riscv64_to_all",
@@ -263,6 +291,7 @@ cc_defaults {
             header_libs: [
                 "libberberis_assembler_headers", // Immediates.
                 "libberberis_base_headers",
+                "libberberis_device_arch_info_headers",
                 "libberberis_runtime_primitives_headers",
             ],
             shared_libs: ["liblog"],
@@ -283,11 +312,13 @@ cc_library_headers {
     host_supported: true,
     header_libs: [
         "libberberis_base_headers",
+        "libberberis_device_arch_info_headers",
         "libberberis_intrinsics_headers",
         "libberberis_runtime_primitives_headers", // for platform.h
     ],
     export_header_lib_headers: [
         "libberberis_base_headers",
+        "libberberis_device_arch_info_headers",
         "libberberis_intrinsics_headers",
         "libberberis_runtime_primitives_headers", // for platform.h
     ],
@@ -331,10 +362,27 @@ cc_library_headers {
             export_include_dirs: [
                 "all_to_x86_32_or_x86_64/include",
             ],
+            generated_headers: [
+                "libberberis_verifier_assembler_gen_headers_x86_32",
+                "libberberis_verifier_assembler_gen_headers_x86_64",
+            ],
+            export_generated_headers: [
+                "libberberis_verifier_assembler_gen_headers_x86_32",
+                "libberberis_verifier_assembler_gen_headers_x86_64",
+            ],
         },
         x86_64: {
             export_include_dirs: [
                 "all_to_x86_32_or_x86_64/include",
+                "all_to_x86_64/include",
+            ],
+            generated_headers: [
+                "libberberis_verifier_assembler_gen_headers_x86_32",
+                "libberberis_verifier_assembler_gen_headers_x86_64",
+            ],
+            export_generated_headers: [
+                "libberberis_verifier_assembler_gen_headers_x86_32",
+                "libberberis_verifier_assembler_gen_headers_x86_64",
             ],
         },
         riscv64: {
@@ -453,23 +501,26 @@ cc_test_library {
         x86: {
             srcs: [
                 "all_to_x86_32_or_x86_64/intrinsics_float_test.cc",
+                "all_to_x86_32_or_x86_64/verifier_assembler_test.cc",
             ],
         },
         x86_64: {
             cflags: ["-mssse3"],
             srcs: [
                 "all_to_x86_32_or_x86_64/intrinsics_float_test.cc",
+                "all_to_x86_32_or_x86_64/verifier_assembler_test.cc",
                 "all_to_x86_64/tuple_test.cc",
                 // Note that these two tests technically should work on any platform that supports
-                // risv64 to something translation, but currently that's only x86-64.
+                // riscv64 to something translation, but currently that's only x86-64.
                 "riscv64_to_all/intrinsics_test.cc",
                 "riscv64_to_all/vector_intrinsics_test.cc",
             ],
         },
     },
-    static_libs: [
-        "libberberis_base",
-        "libberberis_intrinsics",
+    header_libs: [
+        "libberberis_base_headers",
+        "libberberis_device_arch_info_headers",
+        "libberberis_intrinsics_riscv64_headers",
     ],
     shared: {
         enabled: false,
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_bindings.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_bindings.h
deleted file mode 100644
index d6e9fc74..00000000
--- a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_bindings.h
+++ /dev/null
@@ -1,100 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef BERBERIS_INTRINSICS_COMMON_TO_RISCV_INTRINSICS_BINDINGS_H_
-#define BERBERIS_INTRINSICS_COMMON_TO_RISCV_INTRINSICS_BINDINGS_H_
-
-#include <cstdint>
-
-#include "berberis/assembler/riscv.h"
-#include "berberis/base/dependent_false.h"
-#include "berberis/intrinsics/common/intrinsics_bindings.h"
-#include "berberis/intrinsics/intrinsics_args.h"
-#include "berberis/intrinsics/type_traits.h"
-
-namespace berberis::intrinsics::bindings {
-
-class BImm {
- public:
-  using Type = riscv::BImmediate;
-  static constexpr bool kIsImmediate = true;
-};
-
-class CsrImm {
- public:
-  using Type = riscv::CsrImmediate;
-  static constexpr bool kIsImmediate = true;
-};
-
-class GeneralReg {
- public:
-  using Type = uint64_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = false;
-  static constexpr char kAsRegister = 'r';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kGeneralReg;
-};
-
-class IImm {
- public:
-  using Type = riscv::IImmediate;
-  static constexpr bool kIsImmediate = true;
-};
-
-class JImm {
- public:
-  using Type = riscv::JImmediate;
-  static constexpr bool kIsImmediate = true;
-};
-
-class PImm {
- public:
-  using Type = riscv::PImmediate;
-  static constexpr bool kIsImmediate = true;
-};
-
-class SImm {
- public:
-  using Type = riscv::SImmediate;
-  static constexpr bool kIsImmediate = true;
-};
-
-class Shift32Imm {
- public:
-  using Type = riscv::Shift32Immediate;
-  static constexpr bool kIsImmediate = true;
-};
-
-class Shift64Imm {
- public:
-  using Type = riscv::Shift64Immediate;
-  static constexpr bool kIsImmediate = true;
-};
-
-class UImm {
- public:
-  using Type = riscv::UImmediate;
-  static constexpr bool kIsImmediate = true;
-};
-
-// Tag classes. They are never instantioned, only used as tags to pass information about
-// bindings.
-class NoCPUIDRestriction;
-
-}  // namespace berberis::intrinsics::bindings
-
-#endif  // BERBERIS_INTRINSICS_COMMON_TO_RISCV_INTRINSICS_BINDINGS_H_
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h
index 3fc0ae2e..f868a01c 100644
--- a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h
@@ -27,7 +27,8 @@
 #include "berberis/base/checks.h"
 #include "berberis/base/config.h"
 #include "berberis/base/dependent_false.h"
-#include "berberis/intrinsics/all_to_riscv64/intrinsics_bindings.h"
+#include "berberis/device_arch_info/riscv64/device_arch_info.h"
+#include "berberis/intrinsics/common/intrinsics_bindings.h"
 
 namespace berberis {
 
@@ -196,19 +197,6 @@ class TextAssembler {
   static constexpr const char* kCPUIDRestrictionString =
       DerivedAssemblerType::template CPUIDRestrictionToString<CPUIDRestriction>();
 
-  // RISC-V doesn't have “a”, “b”, “c”, or “d” registers, but we need these to be able to compile
-  // the code generator.
-  template <char kConstraint>
-  class UnsupportedRegister {
-   public:
-    UnsupportedRegister operator=(Register) {
-      LOG_ALWAYS_FATAL("Registers of the class “%c” don't exist on RISC-V", kConstraint);
-    }
-  };
-  UnsupportedRegister<'a'> gpr_a;
-  UnsupportedRegister<'b'> gpr_b;
-  UnsupportedRegister<'c'> gpr_c;
-  UnsupportedRegister<'d'> gpr_d;
   // Note: stack pointer is not reflected in list of arguments, intrinsics use
   // it implicitly.
   Register gpr_s{Register::kStackPointer};
@@ -282,7 +270,7 @@ class TextAssembler {
  protected:
   template <typename CPUIDRestriction>
   static constexpr const char* CPUIDRestrictionToString() {
-    if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::NoCPUIDRestriction>) {
+    if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::NoCPUIDRestriction>) {
       return nullptr;
     } else {
       static_assert(kDependentTypeFalse<CPUIDRestriction>);
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/verifier_assembler_riscv.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/verifier_assembler_riscv.h
index 0b0ca381..0bcf6ef8 100644
--- a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/verifier_assembler_riscv.h
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/verifier_assembler_riscv.h
@@ -26,7 +26,7 @@
 #include "berberis/base/checks.h"
 #include "berberis/base/config.h"
 #include "berberis/base/dependent_false.h"
-#include "berberis/intrinsics/all_to_riscv64/intrinsics_bindings.h"
+#include "berberis/device_arch_info/riscv64/device_arch_info.h"
 #include "berberis/intrinsics/common/intrinsics_bindings.h"
 
 namespace berberis {
@@ -52,8 +52,7 @@ class VerifierAssembler {
    public:
     constexpr Register() : arg_no_(kNoRegister) {}
     constexpr Register(int arg_no) : arg_no_(arg_no) {}
-    constexpr Register(int arg_no,
-                       [[maybe_unused]] intrinsics::bindings::RegBindingKind binding_kind)
+    constexpr Register(int arg_no, [[maybe_unused]] device_arch_info::RegBindingKind binding_kind)
         : arg_no_(arg_no) {}
 
     int arg_no() const {
@@ -129,8 +128,12 @@ class VerifierAssembler {
 
   constexpr void CheckAppropriateDefEarlyClobbers() {}
 
+  constexpr void Check32BitRegisterIsZeroExtended([[maybe_unused]] int reg_no) {}
+
   constexpr void CheckLabelsAreBound() {}
 
+  constexpr void CheckNonLinearIntrinsicsUseDefRegisters() {}
+
   // Translate CPU restrictions into string.
   template <typename CPUIDRestriction>
   static constexpr const char* kCPUIDRestrictionString =
@@ -196,10 +199,12 @@ class VerifierAssembler {
 // Instructions.
 #include "gen_verifier_assembler_common_riscv-inl.h"  // NOLINT generated file
 
+  using AddressType = int64_t;
+
  protected:
   template <typename CPUIDRestriction>
   static constexpr const char* CPUIDRestrictionToString() {
-    if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::NoCPUIDRestriction>) {
+    if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::NoCPUIDRestriction>) {
       return nullptr;
     } else {
       static_assert(kDependentTypeFalse<CPUIDRestriction>);
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/intrinsics_bindings.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/intrinsics_bindings.h
new file mode 100644
index 00000000..1ecb8f24
--- /dev/null
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/intrinsics_bindings.h
@@ -0,0 +1,23 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_INTRINSICS_INTRINSICS_BINDINGS_H_
+#define BERBERIS_INTRINSICS_INTRINSICS_BINDINGS_H_
+
+#include "berberis/intrinsics/common/intrinsics_bindings.h"
+#include "berberis/intrinsics/device_arch_info.h"
+
+#endif  // BERBERIS_INTRINSICS_INTRINSICS_BINDINGS_H_
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/constants_pool.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/constants_pool.h
new file mode 100644
index 00000000..b5e2e3b1
--- /dev/null
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/constants_pool.h
@@ -0,0 +1,77 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_CONSTANTS_POOL_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_CONSTANTS_POOL_H_
+
+#include <cinttypes>
+
+#include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/common/constants_pool.h"
+
+namespace berberis::constants_pool {
+
+// 64 bit constants for use with arithmetic operations.
+// Used because only 32 bit immediates are supported on x86-64.
+
+template <auto Value>
+struct Const {};
+
+// Specialize Const<Value> using an out-of-line definition.
+#define BERBERIS_CONST_EXTERN(Value) \
+  template <>                        \
+  struct Const<Value> {              \
+    static const int32_t kValue;     \
+  }
+
+// Specialize Const<Value> using a reference to another constant's int32_t address.
+#define BERBERIS_CONST_ALIAS(Value, Alias)          \
+  template <>                                       \
+  struct Const<Value> {                             \
+    static constexpr const int32_t& kValue = Alias; \
+  }
+
+template <auto Value>
+inline const int32_t& kConst = Const<Value>::kValue;
+
+BERBERIS_CONST_EXTERN(uint32_t{32});
+BERBERIS_CONST_EXTERN(uint32_t{63});
+
+// Helper constant for BsrToClz conversion. 63 for int32_t, 127 for int64_t.
+template <typename IntType>
+inline constexpr int32_t kBsrToClz = kImpossibleTypeConst<IntType>;
+template <>
+inline const int32_t kBsrToClz<int32_t> = kConst<uint32_t{63}>;
+
+// Helper constant for width of the type. 32 for int32_t, 64 for int64_t.
+template <typename IntType>
+inline constexpr int32_t kWidthInBits = kImpossibleTypeConst<IntType>;
+template <>
+inline const int32_t kWidthInBits<int32_t> = kConst<uint32_t{32}>;
+
+}  // namespace berberis::constants_pool
+
+namespace berberis::constants_offsets {
+
+template <typename IntType>
+inline constexpr TypeConstantAccessor<&constants_pool::kBsrToClz<IntType>> kBsrToClz{};
+
+template <typename IntType>
+inline constexpr TypeConstantAccessor<&constants_pool::kWidthInBits<IntType>> kWidthInBits{};
+
+}  // namespace berberis::constants_offsets
+
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_CONSTANTS_POOL_H_
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
deleted file mode 100644
index 51cd64ee..00000000
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
+++ /dev/null
@@ -1,347 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_INTRINSICS_BINDINGS_H_
-#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_INTRINSICS_BINDINGS_H_
-
-#include <xmmintrin.h>
-
-#include <cstdint>
-
-#include "berberis/base/dependent_false.h"
-#include "berberis/intrinsics/common/intrinsics_bindings.h"
-#include "berberis/intrinsics/intrinsics_args.h"
-#include "berberis/intrinsics/type_traits.h"
-
-namespace berberis::intrinsics::bindings {
-
-class Imm2 {
- public:
-  using Type = int8_t;
-  static constexpr bool kIsImmediate = true;
-};
-
-class Imm8 {
- public:
-  using Type = int8_t;
-  static constexpr bool kIsImmediate = true;
-};
-
-class Imm16 {
- public:
-  using Type = int16_t;
-  static constexpr bool kIsImmediate = true;
-};
-
-class Imm32 {
- public:
-  using Type = int32_t;
-  static constexpr bool kIsImmediate = true;
-};
-
-class Imm64 {
- public:
-  using Type = int64_t;
-  static constexpr bool kIsImmediate = true;
-};
-
-class AL {
- public:
-  using Type = uint8_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'a';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kAL;
-};
-
-class AX {
- public:
-  using Type = uint16_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'a';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kAX;
-};
-
-class EAX {
- public:
-  using Type = uint32_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'a';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kEAX;
-};
-
-class RAX {
- public:
-  using Type = uint64_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'a';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kRAX;
-};
-
-class EBX {
- public:
-  using Type = uint32_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'b';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kEBX;
-};
-
-class RBX {
- public:
-  using Type = uint64_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'b';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kRBX;
-};
-
-class CL {
- public:
-  using Type = uint8_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'c';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kCL;
-};
-
-class CX {
- public:
-  using Type = uint16_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'c';
-};
-
-class ECX {
- public:
-  using Type = uint32_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'c';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kECX;
-};
-
-class RCX {
- public:
-  using Type = uint64_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'c';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kRCX;
-};
-
-class DL {
- public:
-  using Type = uint8_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'd';
-};
-
-class DX {
- public:
-  using Type = uint16_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'd';
-};
-
-class EDX {
- public:
-  using Type = uint32_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'd';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kEDX;
-};
-
-class RDX {
- public:
-  using Type = uint64_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 'd';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kRDX;
-};
-
-class GeneralReg8 {
- public:
-  using Type = uint8_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = false;
-  static constexpr char kAsRegister = 'q';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kGeneralReg8;
-};
-
-class GeneralReg16 {
- public:
-  using Type = uint16_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = false;
-  static constexpr char kAsRegister = 'r';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kGeneralReg16;
-};
-
-class GeneralReg32 {
- public:
-  using Type = uint32_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = false;
-  static constexpr char kAsRegister = 'r';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kGeneralReg32;
-};
-
-class GeneralReg64 {
- public:
-  using Type = uint64_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = false;
-  static constexpr char kAsRegister = 'r';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kGeneralReg64;
-};
-
-class FpReg32 {
- public:
-  using Type = __m128;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = false;
-  static constexpr char kAsRegister = 'x';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kFpReg32;
-};
-
-class FpReg64 {
- public:
-  using Type = __m128;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = false;
-  static constexpr char kAsRegister = 'x';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kFpReg64;
-};
-
-class VecReg128 {
- public:
-  using Type = __m128;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = false;
-  static constexpr char kAsRegister = 'x';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kVecReg128;
-};
-
-class XmmReg {
- public:
-  using Type = __m128;
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = false;
-  static constexpr char kAsRegister = 'x';
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kXmmReg;
-};
-
-class MemX87 {
- public:
-  static constexpr bool kIsImmediate = false;
-  static constexpr char kAsRegister = 'm';
-};
-
-// Tag classes. They are never instantioned, only used as tags to pass information about
-// bindings.
-class NoCPUIDRestriction;
-class Has3DNOW;
-class Has3DNOWP;
-class HasADX;
-class HasAES;
-class HasAESAVX;
-class HasAMXBF16;
-class HasAMXFP16;
-class HasAMXINT8;
-class HasAMXTILE;
-class HasAVX;
-class HasAVX2;
-class HasAVX5124FMAPS;
-class HasAVX5124VNNIW;
-class HasAVX512BF16;
-class HasAVX512BITALG;
-class HasAVX512BW;
-class HasAVX512CD;
-class HasAVX512DQ;
-class HasAVX512ER;
-class HasAVX512F;
-class HasAVX512FP16;
-class HasAVX512IFMA;
-class HasAVX512PF;
-class HasAVX512VBMI;
-class HasAVX512VBMI2;
-class HasAVX512VL;
-class HasAVX512VNNI;
-class HasAVX512VPOPCNTDQ;
-class HasBMI;
-class HasBMI2;
-class HasCLMUL;
-class HasCLMULAVX;
-class HasCMOV;
-class HasCMPXCHG16B;
-class HasCMPXCHG8B;
-class HasF16C;
-class HasFMA;
-class HasFMA4;
-class HasFXSAVE;
-class HasLZCNT;
-// BMI2 is set and PDEP/PEXT are ok to use. See more here:
-//   https://twitter.com/instlatx64/status/1322503571288559617
-class HashPDEP;
-class HasPOPCNT;
-class HasRDSEED;
-class HasSERIALIZE;
-class HasSHA;
-class HasSSE;
-class HasSSE2;
-class HasSSE3;
-class HasSSE4_1;
-class HasSSE4_2;
-class HasSSE4a;
-class HasSSSE3;
-class HasTBM;
-class HasVAES;
-class HasVPCLMULQD;
-class HasX87;
-class HasCustomCapability;
-class IsAuthenticAMD;
-
-}  // namespace berberis::intrinsics::bindings
-
-#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_INTRINSICS_BINDINGS_H_
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-impl.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-impl.h
new file mode 100644
index 00000000..39704ccd
--- /dev/null
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-impl.h
@@ -0,0 +1,79 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
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
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_MACRO_ASSEMBLER_IMPL_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_MACRO_ASSEMBLER_IMPL_H_
+
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/constants_pool.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler.h"
+
+namespace berberis {
+
+template <typename Assembler, typename AssemblerBase, typename SpecificMacroAssembler>
+template <typename Ti>
+constexpr void
+MacroAssemblerX86GuestAgnostic<Assembler, AssemblerBase, SpecificMacroAssembler>::ReverseBits(
+    Register dst,
+    Register src) {
+  static_assert(std::is_integral_v<Ti> && std::is_unsigned_v<Ti> && sizeof(Ti) <= sizeof(uint32_t));
+  using ImmType = std::make_signed_t<Ti>;
+  Mov<Ti>(dst, src);
+  Shr<Ti>(src, int8_t{1});
+  Shl<Ti>(dst, int8_t{1});
+  And<Ti>(src, static_cast<ImmType>(0x5555'5555));
+  And<Ti>(dst, static_cast<ImmType>(0xaaaa'aaaa));
+  Or<Ti>(dst, src);
+  Mov<Ti>(src, dst);
+  Shr<Ti>(src, int8_t{2});
+  Shl<Ti>(dst, int8_t{2});
+  And<Ti>(src, static_cast<ImmType>(0x3333'3333));
+  And<Ti>(dst, static_cast<ImmType>(0xcccc'cccc));
+  Or<Ti>(dst, src);
+  Mov<Ti>(src, dst);
+  Shr<Ti>(src, int8_t{4});
+  Shl<Ti>(dst, int8_t{4});
+  And<Ti>(src, static_cast<ImmType>(0x0f0f'0f0f));
+  And<Ti>(dst, static_cast<ImmType>(0xf0f0'f0f0));
+  Or<Ti>(dst, src);
+  if constexpr (sizeof(Ti) == sizeof(uint16_t)) {
+    Ror<Ti>(dst, 8);
+  } else if constexpr (sizeof(Ti) == sizeof(uint32_t)) {
+    Bswap<Ti>(dst);
+  }
+}
+
+template <typename Assembler, typename AssemblerBase, typename SpecificMacroAssembler>
+template <typename IntType>
+constexpr void
+MacroAssemblerX86GuestAgnostic<Assembler, AssemblerBase, SpecificMacroAssembler>::CountLeadingZeros(
+    Register result,
+    Register src) {
+  Bsr<IntType>(result, src);
+  Cmov<IntType>(Condition::kZero, result, {.disp = constants_offsets::kBsrToClz<IntType>});
+  Xor<IntType>(result, sizeof(IntType) * CHAR_BIT - 1);
+}
+
+template <typename Assembler, typename AssemblerBase, typename SpecificMacroAssembler>
+template <typename IntType>
+constexpr void MacroAssemblerX86GuestAgnostic<Assembler, AssemblerBase, SpecificMacroAssembler>::
+    CountTrailingZeros(Register result, Register src) {
+  Bsf<IntType>(result, src);
+  Cmov<IntType>(Condition::kZero, result, {.disp = constants_offsets::kWidthInBits<IntType>});
+}
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_MACRO_ASSEMBLER_IMPL_H_
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h
index ea2a230c..c6ca4fb7 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h
@@ -172,6 +172,7 @@ DEFINE_EXPAND_INSTRUCTION(Register dest, Register src)
       Assembler::asm_name##q##insn_siffix arguments;                                 \
     }                                                                                \
   }
+DEFINE_INT_INSTRUCTION(Bswap, Bswap, , kIntTypeLQ, (Register op), (op))
 DEFINE_INT_INSTRUCTION(CmpXchg, CmpXchg, , kIntType, (Operand dest, Register src), (dest, src))
 DEFINE_INT_INSTRUCTION(CmpXchg, CmpXchg, , kIntType, (Register dest, Register src), (dest, src))
 DEFINE_INT_INSTRUCTION(Lea, Lea, , kIntTypeWLQ, (Register dest, Operand src), (dest, src))
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler.h
new file mode 100644
index 00000000..d7e5c56a
--- /dev/null
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler.h
@@ -0,0 +1,64 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_MACRO_ASSEMBLER_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_MACRO_ASSEMBLER_H_
+
+#include <limits.h>
+#include <type_traits>  // is_same_v
+
+// Don't include arch-dependent parts because macro-assembler doesn't depend on implementation of
+// Float32/Float64 types but can be compiled for different architecture (soong's host architecture,
+// not device architecture AKA berberis' host architecture).
+#include "berberis/intrinsics/common/intrinsics_float.h"
+
+namespace berberis {
+
+class CompilerHooks;
+
+// When CRTP is used the derived class, supplied as template argument, can be used in the
+// *implementation* of base class, but couldn't be used as part of the *interface*.
+//
+// And macro-assembler *interface* depends on the Assembler, that's why it's supplied separately.
+//
+// And we also need base class to form hierarchy.
+//
+// Details at go/berberis-macroassembler-mixins
+template <typename AssemblerT, typename AssemblerBaseT, typename SpecificMacroAssemblerT>
+class MacroAssemblerX86GuestAgnostic : public AssemblerBaseT {
+ public:
+  using Assembler = AssemblerBaseT;
+  using AssemblerBase = AssemblerBaseT;
+  using SpecificMacroAssembler = SpecificMacroAssemblerT;
+
+#define IMPORT_ASSEMBLER_FUNCTIONS
+#include "berberis/assembler/gen_assembler_x86_common-using-inl.h"
+#undef IMPORT_ASSEMBLER_FUNCTIONS
+
+#define DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h"
+#undef DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
+
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler_interface-inl.h"  // NOLINT generated file
+
+  template <typename... Аrgs>
+  constexpr explicit MacroAssemblerX86GuestAgnostic(Аrgs&&... args)
+      : Assembler(std::forward<Аrgs>(args)...) {}
+};
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_MACRO_ASSEMBLER_H_
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_or_x86_64.h
similarity index 89%
rename from intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
rename to intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_or_x86_64.h
index 15ea0572..cf47dbfa 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_or_x86_64.h
@@ -14,8 +14,8 @@
  * limitations under the License.
  */
 
-#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_TEXT_ASSEMBLER_COMMON_H_
-#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_TEXT_ASSEMBLER_COMMON_H_
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_TEXT_ASSEMBLER_COMMON_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_TEXT_ASSEMBLER_COMMON_H_
 
 #include <array>
 #include <cstdint>
@@ -26,7 +26,7 @@
 #include "berberis/base/checks.h"
 #include "berberis/base/config.h"
 #include "berberis/base/dependent_false.h"
-#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h"
+#include "berberis/intrinsics/common/intrinsics_bindings.h"
 
 namespace berberis {
 
@@ -48,7 +48,7 @@ inline int32_t GetOffset(int32_t address) {
 
 }  // namespace constants_pool
 
-namespace x86_32_and_x86_64 {
+namespace x86_32_or_x86_64 {
 
 template <typename DerivedAssemblerType>
 class TextAssembler {
@@ -334,48 +334,47 @@ class TextAssembler {
  protected:
   template <typename CPUIDRestriction>
   static constexpr const char* CPUIDRestrictionToString() {
-    if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::NoCPUIDRestriction>) {
+    if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::NoCPUIDRestriction>) {
       return nullptr;
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::IsAuthenticAMD>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::IsAuthenticAMD>) {
       return "host_platform::kIsAuthenticAMD";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAES>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasAES>) {
       return "host_platform::kHasAES";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAESAVX>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasAESAVX>) {
       return "host_platform::kHasAES && host_platform::kHasAVX";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasAVX>) {
       return "host_platform::kHasAVX";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasBMI>) {
       return "host_platform::kHasBMI";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasF16C>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasF16C>) {
       return "host_platform::kHasF16C";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasCLMUL>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasCLMUL>) {
       return "host_platform::kHasCLMUL";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasCLMULAVX>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasCLMULAVX>) {
       return "host_platform::kHasCLMUL && host_platform::kHasAVX";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasFMA>) {
       return "host_platform::kHasFMA";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA4>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasFMA4>) {
       return "host_platform::kHasFMA4";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasLZCNT>) {
       return "host_platform::kHasLZCNT";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasPOPCNT>) {
       return "host_platform::kHasPOPCNT";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE3>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasSSE3>) {
       return "host_platform::kHasSSE3";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSSE3>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasSSSE3>) {
       return "host_platform::kHasSSSE3";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_1>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasSSE4_1>) {
       return "host_platform::kHasSSE4_1";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_2>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasSSE4_2>) {
       return "host_platform::kHasSSE4_2";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSSE3>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasSSSE3>) {
       return "host_platform::kHasSSSE3";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasVAES>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasVAES>) {
       return "host_platform::kHasVAES";
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasVPCLMULQD>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasVPCLMULQD>) {
       return "host_platform::kHasVPCLMULQD";
-    } else if constexpr (std::is_same_v<CPUIDRestriction,
-                                        intrinsics::bindings::HasCustomCapability>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::HasCustomCapability>) {
       return "host_platform::kHasCustomCapability";
     } else {
       static_assert(kDependentTypeFalse<CPUIDRestriction>);
@@ -611,8 +610,8 @@ inline void TextAssembler<DerivedAssemblerType>::Instruction(const char* name,
   fprintf(out_, "\\n\"\n");
 }
 
-}  // namespace x86_32_and_x86_64
+}  // namespace x86_32_or_x86_64
 
 }  // namespace berberis
 
-#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_TEXT_ASSEMBLER_COMMON_H_
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_TEXT_ASSEMBLER_COMMON_H_
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_and_x86_64.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_or_x86_64.h
similarity index 58%
rename from intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_and_x86_64.h
rename to intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_or_x86_64.h
index 713c8232..92429567 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_and_x86_64.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_or_x86_64.h
@@ -14,23 +14,24 @@
  * limitations under the License.
  */
 
-#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_VERIFIER_ASSEMBLER_COMMON_H_
-#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_VERIFIER_ASSEMBLER_COMMON_H_
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_VERIFIER_ASSEMBLER_COMMON_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_VERIFIER_ASSEMBLER_COMMON_H_
 
 #include <array>
 #include <cstdint>
 #include <cstdio>
+#include <optional>
 #include <string>
 
 #include "berberis/base/checks.h"
 #include "berberis/base/config.h"
 #include "berberis/base/dependent_false.h"
-#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h"
+#include "berberis/device_arch_info/x86_32_or_x86_64/device_arch_info.h"
 #include "berberis/intrinsics/common/intrinsics_bindings.h"
 
 namespace berberis {
 
-namespace x86_32_and_x86_64 {
+namespace x86_32_or_x86_64 {
 
 template <typename DerivedAssemblerType>
 class VerifierAssembler {
@@ -82,9 +83,9 @@ class VerifierAssembler {
 
   class Register {
    public:
-    constexpr Register(int arg_no)
-        : arg_no_(arg_no), binding_kind_(intrinsics::bindings::kUndefined) {}
-    constexpr Register(int arg_no, intrinsics::bindings::RegBindingKind binding_kind)
+    constexpr Register(std::optional<Register> reg)
+        : Register(reg.has_value() ? *reg : (FATAL("attempt to use undeclared register"), *reg)) {}
+    constexpr Register(int arg_no, device_arch_info::RegBindingKind binding_kind)
         : arg_no_(arg_no), binding_kind_(binding_kind) {}
 
     constexpr int arg_no() const {
@@ -102,9 +103,7 @@ class VerifierAssembler {
     // Used in Operand to deal with references to scratch area.
     static constexpr int kScratchPointer = -3;
 
-    constexpr intrinsics::bindings::RegBindingKind get_binding_kind() const {
-      return binding_kind_;
-    }
+    constexpr device_arch_info::RegBindingKind get_binding_kind() const { return binding_kind_; }
 
    private:
     friend struct Operand;
@@ -114,7 +113,7 @@ class VerifierAssembler {
     //
     // Default value (-1) means it's not assigned yet (thus couldn't be used).
     int arg_no_;
-    intrinsics::bindings::RegBindingKind binding_kind_;
+    device_arch_info::RegBindingKind binding_kind_;
   };
 
   class X87Register {
@@ -141,10 +140,8 @@ class VerifierAssembler {
   class SIMDRegister {
    public:
     friend class SIMDRegister<384 - kBits>;
-    constexpr SIMDRegister(int arg_no)
-        : arg_no_(arg_no), binding_kind_(intrinsics::bindings::kUndefined) {}
 
-    constexpr SIMDRegister(int arg_no, intrinsics::bindings::RegBindingKind binding_kind)
+    constexpr SIMDRegister(int arg_no, device_arch_info::RegBindingKind binding_kind)
         : arg_no_(arg_no), binding_kind_(binding_kind) {}
 
     constexpr int arg_no() const {
@@ -166,9 +163,7 @@ class VerifierAssembler {
       return std::enable_if_t<kBits != 256, SIMDRegister<256>>{arg_no_, binding_kind_};
     }
 
-    constexpr intrinsics::bindings::RegBindingKind get_binding_kind() const {
-      return binding_kind_;
-    }
+    constexpr device_arch_info::RegBindingKind get_binding_kind() const { return binding_kind_; }
 
    private:
     // Register number created during creation of assembler call.
@@ -177,7 +172,7 @@ class VerifierAssembler {
     // Default value (-1) means it's not assigned yet (thus couldn't be used).
     static constexpr int kNoRegister = -1;
     int arg_no_;
-    intrinsics::bindings::RegBindingKind binding_kind_;
+    device_arch_info::RegBindingKind binding_kind_;
   };
 
   using XMMRegister = SIMDRegister<128>;
@@ -186,8 +181,8 @@ class VerifierAssembler {
   using XRegister = XMMRegister;
 
   struct Operand {
-    Register base = Register{Register::kNoRegister};
-    Register index = Register{Register::kNoRegister};
+    std::optional<Register> base{};
+    std::optional<Register> index{};
     ScaleFactor scale = kTimesOne;
     int32_t disp = 0;
   };
@@ -197,26 +192,28 @@ class VerifierAssembler {
   // These start as Register::kNoRegister but can be changed if they are used as arguments to
   // something else.
   // If they are not coming as arguments then using them is compile-time error!
-  Register gpr_a{Register::kNoRegister};
-  Register gpr_b{Register::kNoRegister};
-  Register gpr_c{Register::kNoRegister};
-  Register gpr_d{Register::kNoRegister};
-  // Note: stack pointer is not reflected in list of arguments, intrinsics use
-  // it implicitly.
-  Register gpr_s{Register::kStackPointer};
+  std::optional<Register> gpr_a{};
+  std::optional<Register> gpr_b{};
+  std::optional<Register> gpr_c{};
+  std::optional<Register> gpr_d{};
+  // Note: stack pointer is not reflected in list of arguments, intrinsics use it implicitly.
+  // It's also always defined on the entrance to intrinsics and, if modified, has to be restored.
+  // But kUse/kDef is not precise enough to describe “this register could be touched but has to be
+  // restored” requirement, thus we define it as kUseDef.
+  Register gpr_s{Register::kStackPointer, device_arch_info::kUseDef};
   // Used in Operand as pseudo-register to temporary operand.
-  Register gpr_scratch{Register::kScratchPointer};
+  std::optional<Register> gpr_scratch{};
 
   // In x86-64 case we could refer to kBerberisMacroAssemblerConstants via %rip.
   // In x86-32 mode, on the other hand, we need complex dance to access it via GOT.
   // Intrinsics which use these constants receive it via additional parameter - and
   // we need to know if it's needed or not.
-  Register gpr_macroassembler_constants{Register::kNoRegister};
+  std::optional<Register> gpr_macroassembler_constants{};
   bool need_gpr_macroassembler_constants() const { return need_gpr_macroassembler_constants_; }
 
-  Register gpr_macroassembler_scratch{Register::kNoRegister};
+  std::optional<Register> gpr_macroassembler_scratch{};
   bool need_gpr_macroassembler_scratch() const { return need_gpr_macroassembler_scratch_; }
-  Register gpr_macroassembler_scratch2{Register::kNoRegister};
+  std::optional<Register> gpr_macroassembler_scratch2{};
 
   bool need_aesavx = false;
   bool need_aes = false;
@@ -261,37 +258,37 @@ class VerifierAssembler {
     constexpr void CheckValidRegisterUse(bool is_fixed) {
       if (intrinsic_defined_def_general_register ||
           (intrinsic_defined_def_fixed_register && !is_fixed)) {
-        printf(
-            "error: intrinsic used a 'use' general register after writing to a 'def' general  "
-            "register\n");
+        FATAL(
+            "error: intrinsic used a 'use' general register after writing to a 'def' general "
+            "register");
       }
     }
 
     constexpr void CheckValidXMMRegisterUse() {
       if (intrinsic_defined_def_xmm_register) {
-        printf(
-            "error: intrinsic used a 'use' xmm register after writing to a 'def' xmm  "
-            "register\n");
+        FATAL(
+            "error: intrinsic used a 'use' xmm register after writing to a 'def' xmm "
+            "register");
       }
     }
 
     constexpr void CheckAppropriateDefEarlyClobbers() {
       for (int i = 0; i < kMaxRegisters; i++) {
-        if (intrinsic_defined_def_early_clobber_fixed_register[i] &&
-            !valid_def_early_clobber_register[i]) {
-          printf(
+        if (intrinsic_defined_def_early_clobber_fixed_register.at(i) &&
+            !valid_def_early_clobber_register.at(i)) {
+          FATAL(
               "error: intrinsic never used a 'use' general register after writing to a "
               "'def_early_clobber' fixed register");
         }
-        if (intrinsic_defined_def_early_clobber_general_register[i] &&
-            !valid_def_early_clobber_register[i]) {
-          printf(
+        if (intrinsic_defined_def_early_clobber_general_register.at(i) &&
+            !valid_def_early_clobber_register.at(i)) {
+          FATAL(
               "error: intrinsic never used a 'use' general/fixed register after writing to a "
               "'def_early_clobber' general register");
         }
-        if (intrinsic_defined_def_early_clobber_xmm_register[i] &&
-            !valid_def_early_clobber_register[i]) {
-          printf(
+        if (intrinsic_defined_def_early_clobber_xmm_register.at(i) &&
+            !valid_def_early_clobber_register.at(i)) {
+          FATAL(
               "error: intrinsic never used a 'use' xmm register after writing to a "
               "'def_early_clobber' xmm register");
         }
@@ -299,8 +296,8 @@ class VerifierAssembler {
     }
 
     constexpr void CheckValidDefOrDefEarlyClobberRegisterUse(int reg_arg_no) {
-      if (!intrinsic_defined_def_or_def_early_clobber_register[reg_arg_no]) {
-        printf("error: intrinsic read a def/def_early_clobber register before writing to it");
+      if (!intrinsic_defined_def_or_def_early_clobber_register.at(reg_arg_no)) {
+        FATAL("error: intrinsic read a def/def_early_clobber register before writing to it");
       }
     }
 
@@ -312,25 +309,25 @@ class VerifierAssembler {
       }
     }
 
-    constexpr void UpdateIntrinsicDefineDefOrDefEarlyClobberReigster(int reg_arg_no) {
-      intrinsic_defined_def_or_def_early_clobber_register[reg_arg_no] = true;
+    constexpr void UpdateIntrinsicDefOrDefEarlyClobberRegister(int reg_arg_no) {
+      intrinsic_defined_def_or_def_early_clobber_register.at(reg_arg_no) = true;
     }
 
     constexpr void UpdateIntrinsicRegisterDefEarlyClobber(int reg_arg_no, bool is_fixed) {
       if (is_fixed) {
-        intrinsic_defined_def_early_clobber_fixed_register[reg_arg_no] = true;
+        intrinsic_defined_def_early_clobber_fixed_register.at(reg_arg_no) = true;
       } else {
-        intrinsic_defined_def_early_clobber_general_register[reg_arg_no] = true;
+        intrinsic_defined_def_early_clobber_general_register.at(reg_arg_no) = true;
       }
     }
 
-    constexpr void UpdateIntrinsicRegisterUse([[maybe_unused]] bool is_fixed) {
+    constexpr void UpdateIntrinsicRegisterUse(bool is_fixed) {
       for (int i = 0; i < kMaxRegisters; i++) {
-        if (intrinsic_defined_def_early_clobber_general_register[i]) {
-          valid_def_early_clobber_register[i] = true;
+        if (intrinsic_defined_def_early_clobber_general_register.at(i)) {
+          valid_def_early_clobber_register.at(i) = true;
         }
-        if (intrinsic_defined_def_early_clobber_fixed_register[i] && !is_fixed) {
-          valid_def_early_clobber_register[i] = true;
+        if (intrinsic_defined_def_early_clobber_fixed_register.at(i) && !is_fixed) {
+          valid_def_early_clobber_register.at(i) = true;
         }
       }
     }
@@ -338,29 +335,66 @@ class VerifierAssembler {
     constexpr void UpdateIntrinsicXMMRegisterDef() { intrinsic_defined_def_xmm_register = true; }
 
     constexpr void UpdateIntrinsicXMMRegisterDefEarlyClobber(int reg_arg_no) {
-      intrinsic_defined_def_early_clobber_xmm_register[reg_arg_no] = true;
+      intrinsic_defined_def_early_clobber_xmm_register.at(reg_arg_no) = true;
     }
 
     constexpr void UpdateIntrinsicXMMRegisterUse() {
       for (int i = 0; i < kMaxRegisters; i++) {
-        if (intrinsic_defined_def_early_clobber_xmm_register[i]) {
-          valid_def_early_clobber_register[i] = true;
+        if (intrinsic_defined_def_early_clobber_xmm_register.at(i)) {
+          valid_def_early_clobber_register.at(i) = true;
         }
       }
     }
 
+    constexpr void Update32BitRegisterExtension(int reg_arg_no, bool is_zero_extended) {
+      if (is_zero_extended) {
+        zero_extended_32_bit_register.at(reg_arg_no) = true;
+      } else {
+        zero_extended_32_bit_register.at(reg_arg_no) = false;
+      }
+    }
+
+    enum {
+      kFixedRegisterShift,
+      kGeneralRegisterShift,
+      kXMMRegisterShift,
+      kNumStateBits,
+    };
+
+    constexpr int GetNonLinearUseDefState() {
+      int state = 0;
+      if (intrinsic_defined_def_fixed_register) {
+        state += 1 << kFixedRegisterShift;
+      }
+      if (intrinsic_defined_def_general_register) {
+        state += 1 << kGeneralRegisterShift;
+      }
+      if (intrinsic_defined_def_xmm_register) {
+        state += 1 << kXMMRegisterShift;
+      }
+      return state;
+    }
+
+    constexpr void Check32BitRegisterIsZeroExtended(int reg_no) {
+      if (!zero_extended_32_bit_register.at(reg_no)) {
+        FATAL("error: intrinsic didn't zero extend 32 bit output register");
+      }
+    }
+
    private:
-    bool intrinsic_defined_def_general_register = false;
     bool intrinsic_defined_def_fixed_register = false;
+    bool intrinsic_defined_def_general_register = false;
     bool intrinsic_defined_def_xmm_register = false;
 
-    bool intrinsic_defined_def_or_def_early_clobber_register[kMaxRegisters] = {};
+    std::array<bool, kMaxRegisters> intrinsic_defined_def_or_def_early_clobber_register{};
+
+    std::array<bool, kMaxRegisters> intrinsic_defined_def_early_clobber_fixed_register{};
+    std::array<bool, kMaxRegisters> intrinsic_defined_def_early_clobber_general_register{};
+    std::array<bool, kMaxRegisters> intrinsic_defined_def_early_clobber_xmm_register{};
 
-    bool intrinsic_defined_def_early_clobber_fixed_register[kMaxRegisters] = {};
-    bool intrinsic_defined_def_early_clobber_general_register[kMaxRegisters] = {};
-    bool intrinsic_defined_def_early_clobber_xmm_register[kMaxRegisters] = {};
+    std::array<bool, kMaxRegisters> valid_def_early_clobber_register{};
 
-    bool valid_def_early_clobber_register[kMaxRegisters] = {};
+    std::array<bool, kMaxRegisters> zero_extended_32_bit_register{};
   };
 
   RegisterUsageFlags register_usage_flags;
@@ -388,6 +422,35 @@ class VerifierAssembler {
 
     constexpr void UpdateInstructionXMMRegisterUse() { instruction_used_use_xmm_register = true; }
 
+    constexpr bool CheckVisited(RegisterUsageFlags use_def_flags) {
+      return use_def_state_checked.at(use_def_flags.GetNonLinearUseDefState());
+    }
+
+    constexpr void SetVisited(RegisterUsageFlags use_def_flags) {
+      use_def_state_checked.at(use_def_flags.GetNonLinearUseDefState()) = true;
+    }
+
+    constexpr void ProcessInstructionUseDefs(RegisterUsageFlags& use_def_flags) {
+      if (instruction_used_use_fixed_register) {
+        use_def_flags.CheckValidRegisterUse(true);
+      }
+      if (instruction_used_use_general_register) {
+        use_def_flags.CheckValidRegisterUse(false);
+      }
+      if (instruction_used_use_xmm_register) {
+        use_def_flags.CheckValidXMMRegisterUse();
+      }
+      if (instruction_defined_def_fixed_register) {
+        use_def_flags.UpdateIntrinsicRegisterDef(true);
+      }
+      if (instruction_defined_def_general_register) {
+        use_def_flags.UpdateIntrinsicRegisterDef(false);
+      }
+      if (instruction_defined_def_xmm_register) {
+        use_def_flags.UpdateIntrinsicXMMRegisterDef();
+      }
+    }
+
     bool instruction_defined_def_fixed_register = false;
     bool instruction_defined_def_general_register = false;
     bool instruction_defined_def_xmm_register = false;
@@ -399,6 +462,15 @@ class VerifierAssembler {
     bool is_unconditional_jump = false;
     bool is_conditional_jump = false;
     Label* jump_target = nullptr;
+
+    // The check for each instruction is fully defined by prior `def` register flags.
+    // When we reach an instruction by different paths, we may arrive with different 'def' flags. We
+    // use this array to memorize which `def` combinations we have checked already.
+    //
+    // The state to keep track of is whether a 'def' register of each of the three types (general,
+    // fixed and xmm) has been written in the intrinsic yet. Thus, there are 2^3 = 8 possible states
+    // of an instruction.
+    std::array<bool, 1 << RegisterUsageFlags::kNumStateBits> use_def_state_checked{};
   };
 
   constexpr void CheckAppropriateDefEarlyClobbers() {
@@ -408,29 +480,72 @@ class VerifierAssembler {
     register_usage_flags.CheckAppropriateDefEarlyClobbers();
   }
 
+  constexpr void Check32BitRegisterIsZeroExtended(int reg_no) {
+    if (intrinsic_is_non_linear) {
+      return;
+    }
+    register_usage_flags.Check32BitRegisterIsZeroExtended(reg_no);
+  }
+
   constexpr void CheckLabelsAreBound() {
     if (!intrinsic_is_non_linear) {
       return;
     }
-    for (int i = 0; i < current_instruction; i++) {
-      if (instructions[i].is_conditional_jump || instructions[i].is_unconditional_jump) {
-        if (instructions[i].jump_target->bound == false) {
-          printf("error: intrinsic jumps to a label that was never bound\n");
+    for (int i = 0; i < num_instructions_; i++) {
+      if (instructions.at(i).is_conditional_jump || instructions.at(i).is_unconditional_jump) {
+        if (instructions.at(i).jump_target->bound == false) {
+          FATAL("error: intrinsic jumps to a label that was never bound");
         }
       }
     }
   }
 
+  constexpr void CheckNonLinearIntrinsicsUseDefRegisters() {
+    if (!intrinsic_is_non_linear) {
+      return;
+    }
+    // Uses DFS to check that a 'use' register is never used after a 'def' register is written on
+    // all paths of a non-linear intrinsic.
+    RegisterUsageFlags use_def_flags{};
+    CheckInstructionRecursive(0, use_def_flags);
+  }
+
+  constexpr void CheckInstructionRecursive(int current_instruction,
+                                           RegisterUsageFlags use_def_flags) {
+    CHECK_LE(current_instruction, num_instructions_);
+    if (current_instruction == num_instructions_) {
+      // Reached end of intrinsic.
+      return;
+    }
+    if (instructions.at(current_instruction).CheckVisited(use_def_flags)) {
+      // Already visited this instruction with the same use_def state.
+      return;
+    }
+    instructions.at(current_instruction).SetVisited(use_def_flags);
+    instructions.at(current_instruction).ProcessInstructionUseDefs(use_def_flags);
+    if (instructions.at(current_instruction).is_unconditional_jump ||
+        instructions.at(current_instruction).is_conditional_jump) {
+      // Explore execution path given that jump is taken.
+      CheckInstructionRecursive(instructions.at(current_instruction).jump_target->index,
+                                use_def_flags);
+    }
+    if (instructions.at(current_instruction).is_unconditional_jump) {
+      return;
+    }
+    // Explore execution path given that we move to the next instruction.
+    CheckInstructionRecursive(current_instruction + 1, use_def_flags);
+  }
+
   constexpr void Bind(Label* label) {
     CHECK_EQ(label->bound, false);
-    intrinsic_is_non_linear = true;
-    label->index = current_instruction;
+    label->index = num_instructions_;
     label->bound = true;
   }
 
   constexpr Label* MakeLabel() {
-    labels_[num_labels_] = {{num_labels_}};
-    return &labels_[num_labels_++];
+    intrinsic_is_non_linear = true;
+    labels_.at(num_labels_) = {{num_labels_}};
+    return &labels_.at(num_labels_++);
   }
 
   template <typename... Args>
@@ -462,96 +577,94 @@ class VerifierAssembler {
     // penalty. Thus, we first ensure that AVX-using intrinsics don't use SSE instructions, before
     // propagating required feature dependencies correctly.
     if (need_avx && need_sse_or_sse2) {
-      printf("error: intrinsic used both AVX and SSE instructions\n");
+      FATAL("error: intrinsic used both AVX and SSE instructions");
     }
 
-    constexpr bool expect_bmi = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>;
-    constexpr bool expect_f16c = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasF16C>;
-    constexpr bool expect_fma = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA>;
-    constexpr bool expect_fma4 = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA4>;
-    constexpr bool expect_lzcnt = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>;
-    constexpr bool expect_vaes = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasVAES>;
+    constexpr bool expect_bmi = std::is_same_v<CPUIDRestriction, device_arch_info::HasBMI>;
+    constexpr bool expect_f16c = std::is_same_v<CPUIDRestriction, device_arch_info::HasF16C>;
+    constexpr bool expect_fma = std::is_same_v<CPUIDRestriction, device_arch_info::HasFMA>;
+    constexpr bool expect_fma4 = std::is_same_v<CPUIDRestriction, device_arch_info::HasFMA4>;
+    constexpr bool expect_lzcnt = std::is_same_v<CPUIDRestriction, device_arch_info::HasLZCNT>;
+    constexpr bool expect_vaes = std::is_same_v<CPUIDRestriction, device_arch_info::HasVAES>;
     constexpr bool expect_vpclmulqd =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasVPCLMULQD>;
+        std::is_same_v<CPUIDRestriction, device_arch_info::HasVPCLMULQD>;
     constexpr bool expect_aesavx =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAESAVX> || expect_vaes;
-    constexpr bool expect_aes = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAES>;
+        std::is_same_v<CPUIDRestriction, device_arch_info::HasAESAVX> || expect_vaes;
+    constexpr bool expect_aes = std::is_same_v<CPUIDRestriction, device_arch_info::HasAES>;
     constexpr bool expect_clmulavx =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasCLMULAVX> || expect_vpclmulqd;
-    constexpr bool expect_clmul = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasCLMUL>;
-    constexpr bool expect_popcnt =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>;
-    constexpr bool expect_avx = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX> ||
+        std::is_same_v<CPUIDRestriction, device_arch_info::HasCLMULAVX> || expect_vpclmulqd;
+    constexpr bool expect_clmul = std::is_same_v<CPUIDRestriction, device_arch_info::HasCLMUL>;
+    constexpr bool expect_popcnt = std::is_same_v<CPUIDRestriction, device_arch_info::HasPOPCNT>;
+    constexpr bool expect_avx = std::is_same_v<CPUIDRestriction, device_arch_info::HasAVX> ||
                                 expect_aesavx || expect_clmulavx || expect_f16c || expect_fma ||
                                 expect_fma4;
     constexpr bool expect_sse4_2 =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_2> || expect_aes ||
-        expect_clmul;
+        std::is_same_v<CPUIDRestriction, device_arch_info::HasSSE4_2> || expect_aes || expect_clmul;
     constexpr bool expect_sse4_1 =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_1> || expect_sse4_2;
+        std::is_same_v<CPUIDRestriction, device_arch_info::HasSSE4_1> || expect_sse4_2;
     constexpr bool expect_ssse3 =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSSE3> || expect_sse4_1;
+        std::is_same_v<CPUIDRestriction, device_arch_info::HasSSSE3> || expect_sse4_1;
     constexpr bool expect_sse3 =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE3> || expect_ssse3;
+        std::is_same_v<CPUIDRestriction, device_arch_info::HasSSE3> || expect_ssse3;
 
     // Note that we don't check SSE or SSE2, since we assume SSE2 is always available.
 
     if (expect_aesavx != need_aesavx) {
-      printf("error: expect_aesavx != need_aesavx\n");
+      FATAL("error: expect_aesavx != need_aesavx");
     }
     if (expect_aes != need_aes) {
-      printf("error: expect_aes != need_aes\n");
+      FATAL("error: expect_aes != need_aes");
     }
     if (expect_avx != need_avx) {
-      printf("error: expect_avx != need_avx\n");
+      FATAL("error: expect_avx != need_avx");
     }
     if (expect_bmi != need_bmi) {
-      printf("error: expect_bmi != need_bmi\n");
+      FATAL("error: expect_bmi != need_bmi");
     }
     if (expect_clmulavx != need_clmulavx) {
-      printf("error: expect_clmulavx != need_clmulavx\n");
+      FATAL("error: expect_clmulavx != need_clmulavx");
     }
     if (expect_clmul != need_clmul) {
-      printf("error: expect_clmul != need_clmul\n");
+      FATAL("error: expect_clmul != need_clmul");
     }
     if (expect_f16c != need_f16c) {
-      printf("error: expect_f16c != need_f16c\n");
+      FATAL("error: expect_f16c != need_f16c");
     }
     if (expect_fma != need_fma) {
-      printf("error: expect_fma != need_fma\n");
+      FATAL("error: expect_fma != need_fma");
     }
     if (expect_fma4 != need_fma4) {
-      printf("error: expect_fma4 != need_fma4\n");
+      FATAL("error: expect_fma4 != need_fma4");
     }
     if (expect_lzcnt != need_lzcnt) {
-      printf("error: expect_lzcnt != need_lzcnt\n");
+      FATAL("error: expect_lzcnt != need_lzcnt");
     }
     if (expect_popcnt != need_popcnt) {
-      printf("error: expect_popcnt != need_popcnt\n");
+      FATAL("error: expect_popcnt != need_popcnt");
     }
     if (expect_sse3 != need_sse3) {
-      printf("error: expect_sse3 != need_sse3\n");
+      FATAL("error: expect_sse3 != need_sse3");
     }
     if (expect_ssse3 != need_ssse3) {
-      printf("error: expect_ssse3 != need_ssse3\n");
+      FATAL("error: expect_ssse3 != need_ssse3");
     }
     if (expect_sse4_1 != need_sse4_1) {
-      printf("error: expect_sse4_1 != need_sse4_1\n");
+      FATAL("error: expect_sse4_1 != need_sse4_1");
     }
     if (expect_sse4_2 != need_sse4_2) {
-      printf("error: expect_sse4_2 != need_sse4_2\n");
+      FATAL("error: expect_sse4_2 != need_sse4_2");
     }
     if (expect_vaes != need_vaes) {
-      printf("error: expect_vaes != need_vaes\n");
+      FATAL("error: expect_vaes != need_vaes");
     }
     if (expect_vpclmulqd != need_vpclmulqd) {
-      printf("error: expect_vpclmulqd != need_vpclmulqd\n");
+      FATAL("error: expect_vpclmulqd != need_vpclmulqd");
     }
   }
 
   constexpr void CheckFlagsBinding(bool expect_flags) {
     if (expect_flags != defines_flags) {
-      printf("error: expect_flags != defines_flags\n");
+      FATAL("error: expect_flags != defines_flags");
     }
   }
 
@@ -672,135 +785,139 @@ class VerifierAssembler {
   constexpr void SetDefinesFLAGS() { defines_flags = true; }
 
   constexpr bool RegisterIsFixed(Register reg) {
-    if (gpr_a.register_initialised()) {
+    if (gpr_a.has_value()) {
       if (reg == gpr_a) return true;
     }
-    if (gpr_b.register_initialised()) {
+    if (gpr_b.has_value()) {
       if (reg == gpr_b) return true;
     }
-    if (gpr_c.register_initialised()) {
+    if (gpr_c.has_value()) {
       if (reg == gpr_c) return true;
     }
-    if (gpr_d.register_initialised()) {
+    if (gpr_d.has_value()) {
       if (reg == gpr_d) return true;
     }
+    if (reg == gpr_s) return true;
     return false;
   }
 
-  constexpr void RegisterDef(Register reg) {
-    if (reg.get_binding_kind() == intrinsics::bindings::kDef ||
-        reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
-      register_usage_flags.UpdateIntrinsicDefineDefOrDefEarlyClobberReigster(reg.arg_no());
+  constexpr void RegisterDef(Register reg, bool is_zero_extended = false) {
+    if (reg.get_binding_kind() == device_arch_info::kUse) {
+      FATAL("error: intrinsic defined a 'use' register");
     }
-    if (reg.get_binding_kind() == intrinsics::bindings::kDef) {
-      instructions[current_instruction].UpdateInstructionRegisterDef(RegisterIsFixed(reg));
+    if (reg.get_binding_kind() == device_arch_info::kDef ||
+        reg.get_binding_kind() == device_arch_info::kDefEarlyClobber) {
+      register_usage_flags.UpdateIntrinsicDefOrDefEarlyClobberRegister(reg.arg_no());
+    }
+    if (reg.get_binding_kind() == device_arch_info::kDef) {
+      instructions.at(num_instructions_).UpdateInstructionRegisterDef(RegisterIsFixed(reg));
       register_usage_flags.UpdateIntrinsicRegisterDef(RegisterIsFixed(reg));
-    } else if (reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
+    } else if (reg.get_binding_kind() == device_arch_info::kDefEarlyClobber) {
       register_usage_flags.UpdateIntrinsicRegisterDefEarlyClobber(reg.arg_no(),
                                                                   RegisterIsFixed(reg));
     }
-    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
-      printf("error: intrinsic defined a 'use' register\n");
+    if (!RegisterIsFixed(reg)) {
+      register_usage_flags.Update32BitRegisterExtension(reg.arg_no(), is_zero_extended);
     }
   }
 
-  constexpr void RegisterDef(XMMRegister reg) {
-    if (reg.get_binding_kind() == intrinsics::bindings::kDef ||
-        reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
-      register_usage_flags.UpdateIntrinsicDefineDefOrDefEarlyClobberReigster(reg.arg_no());
+  constexpr void RegisterDef(XMMRegister reg, [[maybe_unused]] bool is_zero_extended = false) {
+    if (reg.get_binding_kind() == device_arch_info::kUse) {
+      FATAL("error: intrinsic defined a 'use' XMM register");
+    }
+    if (reg.get_binding_kind() == device_arch_info::kDef ||
+        reg.get_binding_kind() == device_arch_info::kDefEarlyClobber) {
+      register_usage_flags.UpdateIntrinsicDefOrDefEarlyClobberRegister(reg.arg_no());
     }
-    if (reg.get_binding_kind() == intrinsics::bindings::kDef) {
-      instructions[current_instruction].UpdateInstructionXMMRegisterDef();
+    if (reg.get_binding_kind() == device_arch_info::kDef) {
+      instructions.at(num_instructions_).UpdateInstructionXMMRegisterDef();
       register_usage_flags.UpdateIntrinsicXMMRegisterDef();
-    } else if (reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
+    } else if (reg.get_binding_kind() == device_arch_info::kDefEarlyClobber) {
       register_usage_flags.UpdateIntrinsicXMMRegisterDefEarlyClobber(reg.arg_no());
     }
-    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
-      printf("error: intrinsic defined a 'use' XMM register\n");
-    }
   }
 
   constexpr void RegisterUse(Register reg) {
-    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
-      instructions[current_instruction].UpdateInstructionRegisterUse(RegisterIsFixed(reg));
+    if (reg.get_binding_kind() == device_arch_info::kUse) {
+      instructions.at(num_instructions_).UpdateInstructionRegisterUse(RegisterIsFixed(reg));
     }
     if (intrinsic_is_non_linear) {
       return;
     }
-    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
+    if (reg.get_binding_kind() == device_arch_info::kUse) {
       register_usage_flags.CheckValidRegisterUse(RegisterIsFixed(reg));
       register_usage_flags.UpdateIntrinsicRegisterUse(RegisterIsFixed(reg));
     }
-    if (reg.get_binding_kind() == intrinsics::bindings::kDef ||
-        reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
+    if (reg.get_binding_kind() == device_arch_info::kDef ||
+        reg.get_binding_kind() == device_arch_info::kDefEarlyClobber) {
       register_usage_flags.CheckValidDefOrDefEarlyClobberRegisterUse(reg.arg_no());
     }
   }
 
   constexpr void RegisterUse(XMMRegister reg) {
-    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
-      instructions[current_instruction].UpdateInstructionXMMRegisterUse();
+    if (reg.get_binding_kind() == device_arch_info::kUse) {
+      instructions.at(num_instructions_).UpdateInstructionXMMRegisterUse();
     }
     if (intrinsic_is_non_linear) {
       return;
     }
-    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
+    if (reg.get_binding_kind() == device_arch_info::kUse) {
       register_usage_flags.CheckValidXMMRegisterUse();
       register_usage_flags.UpdateIntrinsicXMMRegisterUse();
     }
     if (!kCheckDefOrDefEarlyClobberXMMRegistersAreWrittenBeforeRead) {
       return;
     }
-    if (reg.get_binding_kind() == intrinsics::bindings::kDef ||
-        reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
+    if (reg.get_binding_kind() == device_arch_info::kDef ||
+        reg.get_binding_kind() == device_arch_info::kDefEarlyClobber) {
       register_usage_flags.CheckValidDefOrDefEarlyClobberRegisterUse(reg.arg_no());
     }
   }
 
   template <typename RegisterType>
   constexpr void HandleDefOrDefEarlyClobberRegisterReset(RegisterType reg1, RegisterType reg2) {
-    if (reg1 == reg2 && (reg1.get_binding_kind() == intrinsics::bindings::kDef ||
-                         reg1.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber)) {
-      register_usage_flags.UpdateIntrinsicDefineDefOrDefEarlyClobberReigster(reg1.arg_no());
+    if (reg1 == reg2 && (reg1.get_binding_kind() == device_arch_info::kDef ||
+                         reg1.get_binding_kind() == device_arch_info::kDefEarlyClobber)) {
+      register_usage_flags.UpdateIntrinsicDefOrDefEarlyClobberRegister(reg1.arg_no());
     }
   }
 
   constexpr void HandleDefOrDefEarlyClobberRegisterReset(XMMRegister reg1,
                                                          XMMRegister reg2,
                                                          XMMRegister reg3) {
-    if (reg2 == reg3 && (reg1.get_binding_kind() == intrinsics::bindings::kDef ||
-                         reg1.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber)) {
-      register_usage_flags.UpdateIntrinsicDefineDefOrDefEarlyClobberReigster(reg1.arg_no());
+    if (reg2 == reg3 && (reg1.get_binding_kind() == device_arch_info::kDef ||
+                         reg1.get_binding_kind() == device_arch_info::kDefEarlyClobber)) {
+      register_usage_flags.UpdateIntrinsicDefOrDefEarlyClobberRegister(reg1.arg_no());
     }
   }
 
-  constexpr void HandleConditionalJump([[maybe_unused]] const Label& label) {
-    instructions[current_instruction].is_conditional_jump = true;
-    instructions[current_instruction].jump_target = const_cast<Label*>(&label);
+  constexpr void HandleConditionalJump(const Label& label) {
+    instructions.at(num_instructions_).is_conditional_jump = true;
+    instructions.at(num_instructions_).jump_target = const_cast<Label*>(&label);
   }
 
-  constexpr void HandleUnconditionalJump([[maybe_unused]] const Label& label) {
-    instructions[current_instruction].is_unconditional_jump = true;
-    instructions[current_instruction].jump_target = const_cast<Label*>(&label);
+  constexpr void HandleUnconditionalJump(const Label& label) {
+    instructions.at(num_instructions_).is_unconditional_jump = true;
+    instructions.at(num_instructions_).jump_target = const_cast<Label*>(&label);
   }
 
   constexpr void HandleUnconditionalJumpRegister() {
-    printf("error: intrinsic does jump to register\n");
+    FATAL("error: intrinsic does jump to register");
   }
 
-  constexpr void EndInstruction() { current_instruction++; }
+  constexpr void EndInstruction() { num_instructions_++; }
 
  private:
   // Time complexity of checking correct use/def register bindings for non linear intrinsics is 2^n.
   // Therefore, we only handle intrinsics with maximum of 5 labels. Also, no intrinsics exist with >
   // 5 labels, so we can use this array for all intrinsics.
   static constexpr int kMaxLabels = 5;
-  Label labels_[kMaxLabels];
+  std::array<Label, kMaxLabels> labels_{};
   size_t num_labels_ = 0;
 
-  int current_instruction = 0;
+  int num_instructions_ = 0;
   static constexpr int kMaxInstructions = 300;
-  Instruction instructions[kMaxInstructions] = {};
+  std::array<Instruction, kMaxInstructions> instructions{};
 
   VerifierAssembler(const VerifierAssembler&) = delete;
   VerifierAssembler(VerifierAssembler&&) = delete;
@@ -808,8 +925,8 @@ class VerifierAssembler {
   void operator=(VerifierAssembler&&) = delete;
 };
 
-}  // namespace x86_32_and_x86_64
+}  // namespace x86_32_or_x86_64
 
 }  // namespace berberis
 
-#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_VERIFIER_ASSEMBLER_COMMON_H_
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_X86_64_VERIFIER_ASSEMBLER_COMMON_H_
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/intrinsics_bindings.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/intrinsics_bindings.h
index fe32c39e..ca8f2f71 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/intrinsics_bindings.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/intrinsics_bindings.h
@@ -17,6 +17,7 @@
 #ifndef BERBERIS_INTRINSICS_INTRINSICS_BINDINGS_H_
 #define BERBERIS_INTRINSICS_INTRINSICS_BINDINGS_H_
 
-#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h"
+#include "berberis/device_arch_info/x86_32_or_x86_64/device_arch_info.h"
+#include "berberis/intrinsics/common/intrinsics_bindings.h"
 
 #endif  // BERBERIS_INTRINSICS_INTRINSICS_BINDINGS_H_
diff --git a/intrinsics/all_to_x86_32_or_x86_64/macro_def.json b/intrinsics/all_to_x86_32_or_x86_64/macro_def.json
new file mode 100644
index 00000000..e507c8d1
--- /dev/null
+++ b/intrinsics/all_to_x86_32_or_x86_64/macro_def.json
@@ -0,0 +1,34 @@
+{
+  "insns": [
+    {
+      "name": "CountLeadingZerosU32",
+      "args": [
+        { "class": "GeneralReg32", "usage": "def" },
+        { "class": "GeneralReg32", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "CountLeadingZeros<int32_t>",
+      "mnemo": "CLZ_I32"
+    },
+    {
+      "name": "CountTrailingZerosU32",
+      "args": [
+        { "class": "GeneralReg32", "usage": "def" },
+        { "class": "GeneralReg32", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "CountTrailingZeros<int32_t>",
+      "mnemo": "CTZ_I32"
+    },
+    {
+      "name": "ReverseBitsU32",
+      "args": [
+        { "class": "GeneralReg32", "usage": "def" },
+        { "class": "GeneralReg32", "usage": "use_def" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "ReverseBits<uint32_t>",
+      "mnemo": "REVERSE_BITS_U32"
+    }
+  ]
+}
diff --git a/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_test.cc b/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_test.cc
new file mode 100644
index 00000000..abc1c7a4
--- /dev/null
+++ b/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_test.cc
@@ -0,0 +1,495 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "gtest/gtest.h"
+
+#include "berberis/device_arch_info/x86_64/device_arch_info.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_or_x86_64.h"
+#include "berberis/intrinsics/intrinsics_bindings.h"
+
+namespace berberis {
+
+namespace {
+
+using intrinsics::bindings::IntrinsicBindingInfo;
+using intrinsics::bindings::NoNansOperation;
+
+using x86_64::device_arch_info::FLAGS;
+using x86_64::device_arch_info::GeneralReg32;
+using x86_64::device_arch_info::XmmReg;
+
+using x86_32_or_x86_64::device_arch_info::HasSSE3;
+
+using device_arch_info::NoCPUIDRestriction;
+
+template <typename RegisterClassTemplateName, device_arch_info::RegBindingKind kUsageTemplateName>
+using Operand = device_arch_info::OperandInfo<RegisterClassTemplateName, kUsageTemplateName>;
+using device_arch_info::DeviceInsnInfo;
+
+constexpr auto kDef = device_arch_info::kDef;
+constexpr auto kDefEarlyClobber = device_arch_info::kDefEarlyClobber;
+constexpr auto kUse = device_arch_info::kUse;
+constexpr auto kUseDef = device_arch_info::kUseDef;
+
+template <typename Assembler>
+class MacroAssembler : public Assembler {
+ public:
+  using Assemblers = std::tuple<MacroAssembler<Assembler>,
+                                typename Assembler::BaseAssembler,
+                                typename Assembler::FinalAssembler>;
+  template <typename... Args>
+  constexpr explicit MacroAssembler(Args&&... args) : Assembler(std::forward<Args>(args)...) {}
+
+#define IMPORT_ASSEMBLER_FUNCTIONS
+#include "berberis/assembler/gen_assembler_x86_common-using-inl.h"
+#undef IMPORT_ASSEMBLER_FUNCTIONS
+
+#define DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h"
+#undef DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
+
+  // dst: USE_DEF, src1: USE
+  constexpr void SSE3Intrinsic(XMMRegister dst, XMMRegister src1) { Haddpd(dst, src1); }
+
+  // dst: DEF_EARLY_CLOBBER, src1: USE_DEF, src2: USE, flags: DEF
+  constexpr void LinearRegisterIntrinsic(Register dst, Register src1, Register src2) {
+    Addl(src1, src2);  // Writes to FLAGS
+    Movl(dst, src1);
+    Addl(dst, src2);
+  }
+
+  // dst: DEF_EARLY_CLOBBER, src1: USE, src2: USE
+  constexpr void LinearXMMRegisterIntrinsic(XMMRegister dst, XMMRegister src1, XMMRegister src2) {
+    Pmov(dst, src1);
+    Pmov(dst, src2);
+  }
+
+  // dst: DEF, src1: USE
+  constexpr void InfinitelyLoopingIntrinsicWithDef(Register dst, Register src1) {
+    Label* l1 = MakeLabel();
+    Movl(dst, src1);
+    Bind(l1);
+    Jmp(*l1);
+  }
+
+  // dst: DEF_EARLY_CLOBBER, src1: USE
+  constexpr void InfinitelyLoopingIntrinsicWithDefEarlyClobber(Register dst, Register src1) {
+    Label* l1 = MakeLabel();
+    Cmpl(src1, src1);
+    Bind(l1);
+    Movl(dst, src1);
+    Jcc(Assembler::Condition::kZero, *l1);
+  }
+
+  // dst: DEF, src1: USE, flags: DEF
+  constexpr void ForwardJumpingIntrinsicWithDef(Register dst, Register src1) {
+    Label* l1 = MakeLabel();
+    Label* l2 = MakeLabel();
+    Label* done = MakeLabel();
+
+    Movl(dst, src1);
+
+    Jcc(Assembler::Condition::kZero, *l1);
+    Jcc(Assembler::Condition::kZero, *l2);
+
+    Addl(dst, dst);
+    Jmp(*done);
+
+    Bind(l1);
+    Addl(dst, dst);
+    Jmp(*done);
+
+    Bind(l2);
+    Addl(dst, dst);
+    Jmp(*done);
+
+    Bind(done);
+  }
+
+  // dst: DEF_EARLY_CLOBBER, src1: USE, flags: DEF
+  constexpr void ForwardJumpingIntrinsicWithDefEarlyClobber(Register dst, Register src1) {
+    Label* l1 = MakeLabel();
+    Label* l2 = MakeLabel();
+    Label* done = MakeLabel();
+
+    Movl(dst, src1);
+
+    Jcc(Assembler::Condition::kZero, *l1);
+    // Taking jump to l2 is the invalid path.
+    Jcc(Assembler::Condition::kZero, *l2);
+
+    Addl(dst, dst);
+    Jmp(*done);
+
+    Bind(l1);
+    Addl(dst, dst);
+    Jmp(*done);
+
+    Bind(l2);
+    Addl(dst, src1);
+    Jmp(*done);
+
+    Bind(done);
+  }
+
+  // dst: DEF_EARLY_CLOBBER, src1: USE
+  constexpr void LoopingIntrinsicWithDefEarlyClobber(XMMRegister dst, XMMRegister src1) {
+    Label* l1 = MakeLabel();
+    Label* out = MakeLabel();
+
+    Bind(l1);
+    Jcc(Assembler::Condition::kZero, *out);
+    Pxor(dst, dst);
+    Jmp(*l1);
+
+    Bind(out);
+    Pmov(dst, src1);
+  }
+
+  // dst: DEF, src1: USE
+  constexpr void IntrinsicWith32BitOutputNotZeroExtended(Register dst, Register src1) {
+    // TODO(b/421334152): This intrinsic, is actually, technically valid since Addb maintains the
+    // zero extended bits from Addl. However, current implementation assumes that only 32 bit insns
+    // execute/maintain zero extension.
+    Movl(dst, src1);
+    Addb(dst, dst);
+  }
+
+  using AddressType = int64_t;
+};
+
+class VerifierAssembler : public x86_32_or_x86_64::VerifierAssembler<VerifierAssembler> {
+ public:
+  using BaseAssembler = x86_32_or_x86_64::VerifierAssembler<VerifierAssembler>;
+  using FinalAssembler = VerifierAssembler;
+
+  constexpr VerifierAssembler() : BaseAssembler() {}
+
+ private:
+  VerifierAssembler(const VerifierAssembler&) = delete;
+  VerifierAssembler(VerifierAssembler&&) = delete;
+  void operator=(const VerifierAssembler&) = delete;
+  void operator=(VerifierAssembler&&) = delete;
+  using DerivedAssemblerType = VerifierAssembler;
+
+  friend BaseAssembler;
+};
+
+template <typename IntrinsicBindingInfo>
+constexpr void VerifyIntrinsic() {
+  int register_numbers[std::tuple_size_v<typename IntrinsicBindingInfo::Bindings> == 0
+                           ? 1
+                           : std::tuple_size_v<typename IntrinsicBindingInfo::Bindings>];
+  AssignRegisterNumbers<IntrinsicBindingInfo>(register_numbers);
+  MacroAssembler<VerifierAssembler> as;
+  CallVerifierAssembler<IntrinsicBindingInfo, MacroAssembler<VerifierAssembler>>(&as,
+                                                                                 register_numbers);
+  // Verify CPU vendor and SSE restrictions.
+  as.CheckCPUIDRestriction<typename IntrinsicBindingInfo::CPUIDRestriction>();
+
+  // Verify that intrinsic's bindings correctly states that intrinsic uses/doesn't use FLAGS
+  // register.
+  bool expect_flags = CheckIntrinsicHasFlagsBinding<IntrinsicBindingInfo>();
+  as.CheckFlagsBinding(expect_flags);
+  as.CheckAppropriateDefEarlyClobbers();
+  if (sizeof(MacroAssembler<VerifierAssembler>::AddressType) == sizeof(int64_t)) {
+    Check32BitRegistersAreZeroExtended<IntrinsicBindingInfo, MacroAssembler<VerifierAssembler>>(
+        &as);
+  }
+  as.CheckLabelsAreBound();
+  as.CheckNonLinearIntrinsicsUseDefRegisters();
+}
+
+static constexpr const char kBindingName[] = "TestInstruction";
+static constexpr const char kBindingMnemo[] = "TEST_0";
+
+using Assemblers = MacroAssembler<VerifierAssembler>::Assemblers;
+
+TEST(VerifierAssembler, TestCorrectCPUID) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<SIMD128Register, SIMD128Register>,
+      std::tuple<SIMD128Register>,
+      std::tuple<InOutArg<0, 0>, InArg<1>>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::SSE3Intrinsic,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     HasSSE3,
+                     std::tuple<Operand<XmmReg, kDef>, Operand<XmmReg, kUse>>>>;
+
+  VerifyIntrinsic<IntrinsicBindingInfo>();
+}
+
+TEST(VerifierAssembler, TestIncorrectCPUID) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<SIMD128Register, SIMD128Register>,
+      std::tuple<SIMD128Register>,
+      std::tuple<InOutArg<0, 0>, InArg<1>>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::SSE3Intrinsic,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     NoCPUIDRestriction,
+                     std::tuple<Operand<XmmReg, kDef>, Operand<XmmReg, kUse>>>>;
+
+  ASSERT_DEATH(VerifyIntrinsic<IntrinsicBindingInfo>(), "error: expect_sse3 != need_sse3");
+}
+
+TEST(VerifierAssembler, TestFlagsIntrinsicWithNoFlagsBinding) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<uint32_t, uint32_t>,
+      std::tuple<uint32_t>,
+      std::tuple<OutArg<0>, InOutArg<1, 1>, InArg<2>>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::LinearRegisterIntrinsic,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     NoCPUIDRestriction,
+                     std::tuple<Operand<GeneralReg32, kDefEarlyClobber>,
+                                Operand<GeneralReg32, kUseDef>,
+                                Operand<GeneralReg32, kUse>>>>;
+
+  ASSERT_DEATH(VerifyIntrinsic<IntrinsicBindingInfo>(), "error: expect_flags != defines_flags");
+}
+
+TEST(VerifierAssembler, TestNoFlagsIntrinsicWithFlagsBinding) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<SIMD128Register, SIMD128Register>,
+      std::tuple<SIMD128Register>,
+      std::tuple<OutArg<0>, InArg<0>, InArg<1>, TmpArg>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::LinearXMMRegisterIntrinsic,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     NoCPUIDRestriction,
+                     std::tuple<Operand<XmmReg, kDefEarlyClobber>,
+                                Operand<XmmReg, kUse>,
+                                Operand<XmmReg, kUse>,
+                                Operand<FLAGS, kDef>>>>;
+
+  ASSERT_DEATH(VerifyIntrinsic<IntrinsicBindingInfo>(), "error: expect_flags != defines_flags");
+}
+
+TEST(VerifierAssembler, TestValidRegisterUseDef) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<uint32_t, uint32_t>,
+      std::tuple<uint32_t>,
+      std::tuple<OutArg<0>, InOutArg<1, 1>, InArg<2>, TmpArg>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::LinearRegisterIntrinsic,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     NoCPUIDRestriction,
+                     std::tuple<Operand<GeneralReg32, kDefEarlyClobber>,
+                                Operand<GeneralReg32, kUseDef>,
+                                Operand<GeneralReg32, kUse>,
+                                Operand<FLAGS, kDef>>>>;
+
+  VerifyIntrinsic<IntrinsicBindingInfo>();
+}
+
+TEST(VerifierAssembler, TestInvalidRegisterUseDef) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<uint32_t, uint32_t>,
+      std::tuple<uint32_t>,
+      std::tuple<OutArg<0>, InOutArg<1, 1>, InArg<2>, TmpArg>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::LinearRegisterIntrinsic,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     NoCPUIDRestriction,
+                     std::tuple<Operand<GeneralReg32, kDef>,
+                                Operand<GeneralReg32, kUseDef>,
+                                Operand<GeneralReg32, kUse>,
+                                Operand<FLAGS, kDef>>>>;
+
+  ASSERT_DEATH(
+      VerifyIntrinsic<IntrinsicBindingInfo>(),
+      "error: intrinsic used a 'use' general register after writing to a 'def' general register");
+}
+
+TEST(VerifierAssembler, TestValidXMMRegisterUseDef) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<SIMD128Register, SIMD128Register>,
+      std::tuple<SIMD128Register>,
+      std::tuple<OutArg<0>, InArg<0>, InArg<1>>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::LinearXMMRegisterIntrinsic,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     NoCPUIDRestriction,
+                     std::tuple<Operand<XmmReg, kDefEarlyClobber>,
+                                Operand<XmmReg, kUse>,
+                                Operand<XmmReg, kUse>>>>;
+
+  VerifyIntrinsic<IntrinsicBindingInfo>();
+}
+
+TEST(VerifierAssembler, TestInvalidXMMRegisterUseDef) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<SIMD128Register, SIMD128Register>,
+      std::tuple<SIMD128Register>,
+      std::tuple<OutArg<0>, InArg<0>, InArg<1>>,
+      DeviceInsnInfo<
+          &std::tuple_element_t<0, Assemblers>::LinearXMMRegisterIntrinsic,
+          kBindingMnemo,
+          false,
+          nullptr,
+          NoCPUIDRestriction,
+          std::tuple<Operand<XmmReg, kDef>, Operand<XmmReg, kUse>, Operand<XmmReg, kUse>>>>;
+
+  ASSERT_DEATH(VerifyIntrinsic<IntrinsicBindingInfo>(),
+               "error: intrinsic used a 'use' xmm register after writing to a 'def' xmm register");
+}
+
+TEST(VerifierAssembler, TestValidInfinitelyLoopingValidIntrinsic) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<uint32_t>,
+      std::tuple<uint32_t>,
+      std::tuple<OutArg<0>, InArg<0>>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::InfinitelyLoopingIntrinsicWithDef,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     NoCPUIDRestriction,
+                     std::tuple<Operand<GeneralReg32, kDef>, Operand<GeneralReg32, kUse>>>>;
+
+  VerifyIntrinsic<IntrinsicBindingInfo>();
+}
+
+TEST(VerifierAssembler, TestInvalidInfinitelyLoopingIntrinsic) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<uint32_t>,
+      std::tuple<uint32_t>,
+      std::tuple<OutArg<0>, InArg<0>, TmpArg>,
+      DeviceInsnInfo<
+          &std::tuple_element_t<0, Assemblers>::InfinitelyLoopingIntrinsicWithDefEarlyClobber,
+          kBindingMnemo,
+          false,
+          nullptr,
+          NoCPUIDRestriction,
+          std::tuple<Operand<GeneralReg32, kDef>,
+                     Operand<GeneralReg32, kUse>,
+                     Operand<FLAGS, kDef>>>>;
+
+  ASSERT_DEATH(
+      VerifyIntrinsic<IntrinsicBindingInfo>(),
+      "error: intrinsic used a 'use' general register after writing to a 'def' general register");
+}
+
+TEST(VerifierAssembler, TestValidForwardJumpingIntrinsic) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<uint32_t>,
+      std::tuple<uint32_t>,
+      std::tuple<OutArg<0>, InArg<0>, TmpArg>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::ForwardJumpingIntrinsicWithDef,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     NoCPUIDRestriction,
+                     std::tuple<Operand<GeneralReg32, kDef>,
+                                Operand<GeneralReg32, kUse>,
+                                Operand<FLAGS, kDef>>>>;
+
+  VerifyIntrinsic<IntrinsicBindingInfo>();
+}
+
+TEST(VerifierAssembler, TestInvalidForwardJumpingIntrinsic) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<uint32_t>,
+      std::tuple<uint32_t>,
+      std::tuple<OutArg<0>, InArg<0>, TmpArg>,
+      DeviceInsnInfo<
+          &std::tuple_element_t<0, Assemblers>::ForwardJumpingIntrinsicWithDefEarlyClobber,
+          kBindingMnemo,
+          false,
+          nullptr,
+          NoCPUIDRestriction,
+          std::tuple<Operand<GeneralReg32, kDef>,
+                     Operand<GeneralReg32, kUse>,
+                     Operand<FLAGS, kDef>>>>;
+
+  ASSERT_DEATH(
+      VerifyIntrinsic<IntrinsicBindingInfo>(),
+      "error: intrinsic used a 'use' general register after writing to a 'def' general register");
+}
+
+TEST(VerifierAssembler, TestInvalidLoopingIntrinsic) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<SIMD128Register>,
+      std::tuple<SIMD128Register>,
+      std::tuple<OutArg<0>, InArg<0>>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::LoopingIntrinsicWithDefEarlyClobber,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     NoCPUIDRestriction,
+                     std::tuple<Operand<XmmReg, kDef>, Operand<XmmReg, kUse>>>>;
+
+  ASSERT_DEATH(VerifyIntrinsic<IntrinsicBindingInfo>(),
+               "error: intrinsic used a 'use' xmm register after writing to a 'def' xmm register");
+}
+
+TEST(VerifierAssembler, Test32BitOutputWithNoZeroExtensionIntrinsic) {
+  using IntrinsicBindingInfo = IntrinsicBindingInfo<
+      kBindingName,
+      NoNansOperation,
+      std::tuple<uint32_t>,
+      std::tuple<uint32_t>,
+      std::tuple<OutArg<0>, InArg<0>, TmpArg>,
+      DeviceInsnInfo<&std::tuple_element_t<0, Assemblers>::IntrinsicWith32BitOutputNotZeroExtended,
+                     kBindingMnemo,
+                     false,
+                     nullptr,
+                     NoCPUIDRestriction,
+                     std::tuple<Operand<GeneralReg32, kDef>,
+                                Operand<GeneralReg32, kUse>,
+                                Operand<FLAGS, kDef>>>>;
+
+  ASSERT_DEATH(VerifyIntrinsic<IntrinsicBindingInfo>(),
+               "error: intrinsic didn't zero extend 32 bit output register");
+}
+
+}  // namespace
+
+}  // namespace berberis
diff --git a/intrinsics/all_to_x86_64/include/berberis/intrinsics/all_to_x86_64/constants_pool.h b/intrinsics/all_to_x86_64/include/berberis/intrinsics/all_to_x86_64/constants_pool.h
new file mode 100644
index 00000000..fac15b94
--- /dev/null
+++ b/intrinsics/all_to_x86_64/include/berberis/intrinsics/all_to_x86_64/constants_pool.h
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
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
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_64_CONSTANTS_POOL_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_64_CONSTANTS_POOL_H_
+
+#include <cinttypes>
+
+#include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/constants_pool.h"
+#include "berberis/intrinsics/common/constants_pool.h"
+
+namespace berberis::constants_pool {
+
+BERBERIS_CONST_EXTERN(uint64_t{64});
+BERBERIS_CONST_EXTERN(uint64_t{127});
+
+// Helper constant for BsrToClz conversion. 63 for int32_t, 127 for int64_t.
+template <>
+inline const int32_t& kBsrToClz<int64_t> = kConst<uint64_t{127}>;
+
+// Helper constant for width of the type. 32 for int32_t, 64 for int64_t.
+template <>
+inline const int32_t& kWidthInBits<int64_t> = kConst<uint64_t{64}>;
+
+}  // namespace berberis::constants_pool
+
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_64_CONSTANTS_POOL_H_
diff --git a/intrinsics/all_to_x86_64/include/berberis/intrinsics/all_to_x86_64/macro_assembler-impl.h b/intrinsics/all_to_x86_64/include/berberis/intrinsics/all_to_x86_64/macro_assembler-impl.h
new file mode 100644
index 00000000..cb3b778c
--- /dev/null
+++ b/intrinsics/all_to_x86_64/include/berberis/intrinsics/all_to_x86_64/macro_assembler-impl.h
@@ -0,0 +1,71 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_64_MACRO_ASSEMBLER_IMPL_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_64_MACRO_ASSEMBLER_IMPL_H_
+
+#include "berberis/intrinsics/all_to_x86_64/constants_pool.h"
+#include "berberis/intrinsics/all_to_x86_64/macro_assembler.h"
+
+namespace berberis {
+
+template <typename Assembler, typename AssemblerBase, typename SpecificMacroAssembler>
+template <typename IntType>
+constexpr void MacroAssemblerX86_64GuestAgnostic<Assembler, AssemblerBase, SpecificMacroAssembler>::
+    CountLeadingZeros(Register result, Register src) {
+  AssemblerBase::template CountLeadingZeros<IntType>(result, src);
+}
+
+template <typename Assembler, typename AssemblerBase, typename SpecificMacroAssembler>
+template <typename IntType>
+constexpr void MacroAssemblerX86_64GuestAgnostic<Assembler, AssemblerBase, SpecificMacroAssembler>::
+    CountTrailingZeros(Register result, Register src) {
+  AssemblerBase::template CountTrailingZeros<IntType>(result, src);
+}
+
+template <typename Assembler, typename AssemblerBase, typename SpecificMacroAssembler>
+constexpr void
+MacroAssemblerX86_64GuestAgnostic<Assembler, AssemblerBase, SpecificMacroAssembler>::ReverseBitsU64(
+    Register dst,
+    Register src,
+    Register tmp) {
+  Mov<uint64_t>(tmp, 0x5555'5555'5555'5555);
+  Mov<uint64_t>(dst, src);
+  Shr<uint64_t>(src, int8_t{1});
+  And<uint64_t>(dst, tmp);
+  And<uint64_t>(src, tmp);
+  Mov<uint64_t>(tmp, 0x3333'3333'3333'3333);
+  Shl<uint64_t>(dst, int8_t{1});
+  Or<uint64_t>(src, dst);
+  Mov<uint64_t>(dst, src);
+  Shr<uint64_t>(src, int8_t{2});
+  And<uint64_t>(dst, tmp);
+  And<uint64_t>(src, tmp);
+  Mov<uint64_t>(tmp, 0x0f0f'0f0f'0f0f'0f0f);
+  Shl<uint64_t>(dst, int8_t{2});
+  Or<uint64_t>(src, dst);
+  Mov<uint64_t>(dst, src);
+  Shr<uint64_t>(src, int8_t{4});
+  And<uint64_t>(dst, tmp);
+  And<uint64_t>(src, tmp);
+  Shl<uint64_t>(dst, int8_t{4});
+  Or<uint64_t>(dst, src);
+  Bswap<uint64_t>(dst);
+}
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_64_MACRO_ASSEMBLER_IMPL_H_
diff --git a/intrinsics/all_to_x86_64/include/berberis/intrinsics/all_to_x86_64/macro_assembler.h b/intrinsics/all_to_x86_64/include/berberis/intrinsics/all_to_x86_64/macro_assembler.h
new file mode 100644
index 00000000..75cad4f2
--- /dev/null
+++ b/intrinsics/all_to_x86_64/include/berberis/intrinsics/all_to_x86_64/macro_assembler.h
@@ -0,0 +1,64 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_64_MACRO_ASSEMBLER_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_64_MACRO_ASSEMBLER_H_
+
+#include <limits.h>
+#include <type_traits>  // is_same_v
+
+// Don't include arch-dependent parts because macro-assembler doesn't depend on implementation of
+// Float32/Float64 types but can be compiled for different architecture (soong's host architecture,
+// not device architecture AKA berberis' host architecture).
+#include "berberis/intrinsics/common/intrinsics_float.h"
+
+namespace berberis {
+
+class CompilerHooks;
+
+// When CRTP is used the derived class, supplied as template argument, can be used in the
+// *implementation* of base class, but couldn't be used as part of the *interface*.
+//
+// And macro-assembler *interface* depends on the Assembler, that's why it's supplied separately.
+//
+// And we also need base class to form hierarchy.
+//
+// Details at go/berberis-macroassembler-mixins
+template <typename AssemblerT, typename AssemblerBaseT, typename SpecificMacroAssemblerT>
+class MacroAssemblerX86_64GuestAgnostic : public AssemblerBaseT {
+ public:
+  using Assembler = AssemblerBaseT;
+  using AssemblerBase = AssemblerBaseT;
+  using SpecificMacroAssembler = SpecificMacroAssemblerT;
+
+#define IMPORT_ASSEMBLER_FUNCTIONS
+#include "berberis/assembler/gen_assembler_x86_64-using-inl.h"
+#undef IMPORT_ASSEMBLER_FUNCTIONS
+
+#define DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h"
+#undef DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
+
+#include "berberis/intrinsics/all_to_x86_64/macro_assembler_interface-inl.h"  // NOLINT generated file
+
+  template <typename... Аrgs>
+  constexpr explicit MacroAssemblerX86_64GuestAgnostic(Аrgs&&... args)
+      : AssemblerBase(std::forward<Аrgs>(args)...) {}
+};
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_64_MACRO_ASSEMBLER_H_
diff --git a/intrinsics/all_to_x86_64/macro_def.json b/intrinsics/all_to_x86_64/macro_def.json
new file mode 100644
index 00000000..f6402734
--- /dev/null
+++ b/intrinsics/all_to_x86_64/macro_def.json
@@ -0,0 +1,35 @@
+{
+  "insns": [
+    {
+      "name": "CountLeadingZerosU64",
+      "args": [
+        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "GeneralReg64", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "CountLeadingZeros<int64_t>",
+      "mnemo": "CLZ_I64"
+    },
+    {
+      "name": "CountTrailingZerosU64",
+      "args": [
+        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "GeneralReg64", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "CountTrailingZeros<int64_t>",
+      "mnemo": "CTZ_I64"
+    },
+    {
+      "name": "ReverseBitsU64",
+      "args": [
+        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "GeneralReg64", "usage": "use_def" },
+        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "ReverseBitsU64",
+      "mnemo": "REVERSE_BITS_U64"
+    }
+  ]
+}
diff --git a/intrinsics/gen_intrinsics.py b/intrinsics/gen_intrinsics.py
index aba8f346..c7d138ca 100755
--- a/intrinsics/gen_intrinsics.py
+++ b/intrinsics/gen_intrinsics.py
@@ -20,6 +20,7 @@
 from collections import OrderedDict
 
 import asm_defs
+import gen_device_insn_info_lib
 import json
 import os
 import re
@@ -144,14 +145,17 @@ def _get_c_type(arg_type):
   raise Exception('Type %s not supported' % (arg_type))
 
 
-def _get_semantic_player_type(arg_type, type_map):
+def _get_semantic_player_type(arg_type, type_map, listener=''):
   if type_map is not None and type_map != False and arg_type in type_map:
-    return type_map[arg_type]
+    type = type_map[arg_type]
+    if type in ('FpRegister', 'Register', 'SimdRegister'):
+      return listener + type
+    return type
   if arg_type in ('Float16', 'Float32', 'Float64', 'vec'):
-    return 'SimdRegister'
+    return listener + 'SimdRegister'
   if _is_imm_type(arg_type):
     return _get_imm_c_type(arg_type)
-  return 'Register'
+  return listener + 'Register'
 
 
 def _gen_scalar_intr_decl(f, name, intr):
@@ -191,9 +195,8 @@ def _gen_template_intr_decl(f, name, intr):
 def _get_template_parameters(
     variants,
     precise_nans=False,
-    use_type_id=False,
     extra=['enum PreferredIntrinsicsImplementation = kUseAssemblerImplementationIfPossible']):
-  if use_type_id:
+  if len(extra) == 0:
     typename = 'intrinsics::TemplateTypeId'
   else:
     typename = 'typename'
@@ -251,19 +254,19 @@ def _is_simd128_conversion_required(t, type_map=None):
           _get_c_type(t) != 'SIMD128Register')
 
 
-def _get_semantics_player_hook_result(intr):
+def _get_semantics_player_hook_result(intr, listener=''):
   outs = intr['out']
   if len(outs) == 0:
     return 'void'
   elif len(outs) == 1:
     # No tuple for single result.
-    return _get_semantic_player_type(outs[0], intr.get('sem-player-types'))
+    return _get_semantic_player_type(outs[0], intr.get('sem-player-types'), listener)
   return 'std::tuple<' + ', '.join(
-      _get_semantic_player_type(out, intr.get('sem-player-types'))
+      _get_semantic_player_type(out, intr.get('sem-player-types'), listener)
       for out in outs) + '>'
 
 
-def _get_semantics_player_hook_proto_components(name, intr):
+def _get_semantics_player_hook_proto_components(name, intr, listener=''):
   ins = intr['in']
 
   args = []
@@ -278,31 +281,34 @@ def _get_semantics_player_hook_proto_components(name, intr):
 
   args += [
       '%s arg%d' % (
-          _get_semantic_player_type(op, intr.get('sem-player-types')), num)
+          _get_semantic_player_type(op, intr.get('sem-player-types'), listener), num)
       for num, op in enumerate(ins)
   ]
 
-  result = _get_semantics_player_hook_result(intr)
+  result = _get_semantics_player_hook_result(intr, listener)
 
   return result, name, ', '.join(args)
 
 
-def _get_semantics_player_hook_proto(name, intr, use_type_id=False):
-  result, name, params = _get_semantics_player_hook_proto_components(name, intr)
+def _get_semantics_player_hook_proto(name, intr, make_template=True, listener=''):
+  if listener != '':
+    make_template = False
+  result, name, params = _get_semantics_player_hook_proto_components(name, intr, listener)
   if intr.get('class') == 'template':
-    template_parameters = _get_template_parameters(
-      intr.get('variants'), use_type_id=use_type_id, extra = [])
-    values = ''
-    if use_type_id:
+    template_parameters = _get_template_parameters(intr.get('variants'), extra = [])
+    if make_template:
       spec_arguments = _get_template_spec_arguments(intr.get('variants'))
       values = ', ' + ', '.join(
           ['intrinsics::Value<%s>' % argument for argument in spec_arguments])
-    return 'template<%s>\n%s %s(%s%s)' % (
-      template_parameters, result, name, params, values)
+      return 'template<%s>\n%s %s(%s%s)' % (
+        template_parameters, result, name, params, values)
+    else:
+      return '%s %s%s(%s, %s)' % (
+        result, listener, name, params, template_parameters)
   return '%s %s(%s)' % (result, name, params)
 
 
-def _get_interpreter_hook_call_expr(name, intr, desc=None, use_type_id=False):
+def _get_interpreter_hook_call_expr(name, intr, desc=None):
   ins = intr['in']
   outs = intr['out']
 
@@ -312,7 +318,7 @@ def _get_interpreter_hook_call_expr(name, intr, desc=None, use_type_id=False):
     semantic_player_type = _get_semantic_player_type(
         op, intr.get('sem-player-types'))
     if semantic_player_type == 'FpRegister':
-      if op.startswith('Type') and use_type_id:
+      if op.startswith('Type'):
         op = 'intrinsics::TypeFromId<%s>' % op
       call_params.append('FPRegToFloat<%s>(%s)' % (op, arg))
     elif semantic_player_type == 'SimdRegister':
@@ -321,12 +327,12 @@ def _get_interpreter_hook_call_expr(name, intr, desc=None, use_type_id=False):
       call_params.append('berberis::bit_cast<%s>(%s)' % (_get_c_type(op), arg))
     else:
       c_type = _get_c_type(op)
-      if c_type.startswith('Type') and use_type_id:
+      if c_type.startswith('Type'):
         c_type = 'intrinsics::TypeFromId<%s>' % c_type
       call_params.append('GPRRegToInteger<%s>(%s)' % (c_type, arg))
 
   call_expr = 'intrinsics::%s%s(%s)' % (
-      name, _get_desc_specializations(intr, desc, use_type_id), ', '.join(call_params))
+      name, _get_desc_specializations(intr, desc), ', '.join(call_params))
 
   if len(outs) == 1:
     # Unwrap tuple for single result.
@@ -357,19 +363,22 @@ def _get_interpreter_hook_call_expr(name, intr, desc=None, use_type_id=False):
   return call_expr
 
 
-def _get_interpreter_hook_return_stmt(name, intr, desc=None, use_type_id=False):
-  return 'return ' + _get_interpreter_hook_call_expr(name, intr, desc, use_type_id) + ';'
+def _get_interpreter_hook_return_stmt(name, intr, desc=None):
+  return 'return ' + _get_interpreter_hook_call_expr(name, intr, desc) + ';'
+
 
 def _get_unused(intr):
   call_expr = 'UNUSED(%s);' % ', '.join('arg%d' % (num) for num, _ in enumerate(intr['in']))
   return call_expr
 
+
 def _get_placeholder_return_stmt(intr, f):
   print(INDENT + _get_unused(intr), file=f)
   outs = intr['out']
   if outs:
     print(INDENT + 'return {};', file=f)
 
+
 def _get_semantics_player_hook_raw_vector_body(name, intr, get_return_stmt):
   outs = intr['out']
   if (len(outs) == 0):
@@ -438,8 +447,13 @@ def _get_interpreter_hook_vector_body(name, intr):
       name, intr, _get_interpreter_hook_return_stmt)
 
 
-def _gen_interpreter_hook(f, name, intr, option, use_type_id=False):
-  print('%s const {' % (_get_semantics_player_hook_proto(name, intr, use_type_id)), file=f)
+def _gen_interpreter_hook(f, name, intr, option):
+  if intr.get('class') == 'template':
+    print('#ifndef BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER\n'
+          '%s const;\n#endif' % (
+        _get_semantics_player_hook_proto(name, intr, make_template=False)), file=f)
+  print('%s const {' % (
+      _get_semantics_player_hook_proto(name, intr)), file=f)
 
   if _is_vector_class(intr):
     if 'raw' in intr['variants']:
@@ -454,35 +468,38 @@ def _gen_interpreter_hook(f, name, intr, option, use_type_id=False):
     lines = [INDENT + l for l in lines]
     print('\n'.join(lines), file=f)
   else:
-    if intr.get('class') == 'template':
-      _gen_template_parameters_verifier(f, intr, use_type_id)
     # TODO(b/363057506): Add float support and clean up the logic here.
     arm64_allowlist = ['AmoAdd', 'AmoAnd', 'AmoMax', 'AmoMin', 'AmoOr', 'AmoSwap', 'AmoXor', 'Bclr',
-                       'Bclri', 'Bext', 'Bexti', 'Binv', 'Binvi', 'Bset', 'Bseti', 'Div', 'Max',
-                       'Min', 'Rem', 'Rev8', 'Rol', 'Ror', 'Sext', 'Sh1add', 'Sh1adduw', 'Sh2add',
+                       'Bclri', 'Bext', 'Bexti', 'Binv', 'Binvi', 'Bset', 'Bseti', 'DivRiscV', 'Max',
+                       'Min', 'RemRiscV', 'Rev8', 'Rol', 'Ror', 'Sext', 'Sh1add', 'Sh1adduw', 'Sh2add',
                        'Sh2adduw', 'Sh3add', 'Sh3adduw', 'Zext', 'UnboxNan']
     if (option == 'arm64') and (name not in arm64_allowlist):
       _get_placeholder_return_stmt(intr, f)
     else:
-      print(INDENT + _get_interpreter_hook_return_stmt(name, intr, use_type_id=use_type_id), file=f)
+      print(INDENT + _get_interpreter_hook_return_stmt(name, intr), file=f)
 
-  print('}\n', file=f)
+    print('}\n', file=f)
 
 
-def _get_translator_hook_call_expr(name, intr, desc=None, use_type_id=False):
-  desc_spec = _get_desc_specializations(intr, desc, use_type_id)
+def _get_translator_hook_call_expr(name, intr, desc=None):
+  desc_spec = _get_desc_specializations(intr, desc)
   args = [('arg%d' % n) for n, _ in enumerate(intr['in'])]
   template_params = ['&intrinsics::' + name + desc_spec]
   template_params += [_get_semantics_player_hook_result(intr)]
   return 'CallIntrinsic<%s>(%s)' % (', '.join(template_params), ', '.join(args))
 
 
-def _get_translator_hook_return_stmt(name, intr, desc=None, use_type_id=False):
-  return 'return ' + _get_translator_hook_call_expr(name, intr, desc, use_type_id) + ';'
+def _get_translator_hook_return_stmt(name, intr, desc=None):
+  return 'return ' + _get_translator_hook_call_expr(name, intr, desc) + ';'
 
 
-def _gen_translator_hook(f, name, intr, use_type_id=False):
-  print('%s {' % (_get_semantics_player_hook_proto(name, intr, use_type_id)), file=f)
+def _gen_translator_hook(f, name, intr):
+  if intr.get('class') == 'template':
+    print('#ifndef BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER\n'
+          '%s;\n#endif' % (
+        _get_semantics_player_hook_proto(name, intr, make_template=False)), file=f)
+  print('%s {' % (
+      _get_semantics_player_hook_proto(name, intr)), file=f)
 
   if _is_vector_class(intr):
     if 'raw' in intr['variants']:
@@ -499,9 +516,50 @@ def _gen_translator_hook(f, name, intr, use_type_id=False):
     lines = [INDENT + l for l in lines]
     print('\n'.join(lines), file=f)
   else:
-    if intr.get('class') == 'template':
-      _gen_template_parameters_verifier(f, intr, use_type_id)
-    print(INDENT + _get_translator_hook_return_stmt(name, intr, use_type_id=use_type_id), file=f)
+    print(INDENT + _get_translator_hook_return_stmt(name, intr), file=f)
+
+  print('}\n', file=f)
+
+
+def _get_expectations_for_variant(variant):
+  expectations = []
+  for param in variant.split(','):
+    param = param.strip()
+    if (re.search('[_a-zA-Z]', param) and
+        not param in (['true', 'false'] + _ROUNDING_MODES)):
+      expectations.append('intrinsics::kIdFromType<%s>' % param)
+    else:
+       expectations.append(param)
+  return expectations
+
+
+def _get_semantics_player_hook_template_switch(name, intr):
+  variables = _get_template_spec_arguments(intr.get('variants'))
+  yield 'switch (intrinsics::TrivialDemultiplexer(%s)) {' % ', '.join(variables)
+  for variant in intr.get('variants'):
+    expectations =  _get_expectations_for_variant(variant)
+    yield '%scase intrinsics::TrivialDemultiplexer(%s):' % (
+      INDENT, ', '.join(expectations))
+    yield 2 * INDENT + "// Disable LOG_NDEBUG to use DCHECK for debugging!"
+    for expectation, variable in zip(expectations, variables):
+      yield 2 * INDENT + 'DCHECK_EQ(%s, %s);' % (expectation, variable)
+    yield 2 * INDENT + 'return %s(%s);' % (
+      name,
+      ','.join(list('arg%d' % arg[0] for arg in enumerate(intr['in'])) +
+               list(f'intrinsics::Value<{expectation}>{{}}'
+                    for expectation in expectations)))
+  yield INDENT + 'default:'
+  yield 2 * INDENT + 'FATAL("Unsupported size");'
+  yield '}'
+
+
+def _gen_demultiplexer_hook(f, name, intr):
+  print('%s BERBERIS_INTRINSICS_HOOKS_CONST {' % _get_semantics_player_hook_proto(
+      name, intr, listener=' BERBERIS_INTRINSICS_HOOKS_LISTENER '), file=f)
+  lines = _get_semantics_player_hook_template_switch(name, intr)
+
+  lines = [INDENT + l for l in lines]
+  print('\n'.join(lines), file=f)
 
   print('}\n', file=f)
 
@@ -510,21 +568,14 @@ def _gen_mock_semantics_listener_hook(f, name, intr):
   result, name, params = _get_semantics_player_hook_proto_components(name, intr)
   if intr.get('class') == 'template':
     spec_arguments = _get_template_spec_arguments(intr.get('variants'))
-    for use_type_id in [True, False]:
-      template_parameters = _get_template_parameters(
-        intr.get('variants'), use_type_id=use_type_id, extra = [])
-      args = ', '.join(
-         [('arg%d' % n) for n, _ in enumerate(intr['in'])] +
-         [arg
-            if use_type_id or not arg.startswith('Type') else
-          'intrinsics::kIdFromType<%s>' % arg
-          for arg in spec_arguments])
-      values = ''
-      if use_type_id:
-        values = ', ' + ', '.join(
-            ['intrinsics::Value<%s>' % argument for argument in spec_arguments])
-      print('template<%s>\n%s %s(%s%s) {\n  return %s(%s);\n}' % (
-        template_parameters, result, name, params, values, name, args), file=f)
+    template_parameters = _get_template_parameters(intr.get('variants'), extra = [])
+    args = ', '.join([('arg%d' % n) for n, _ in enumerate(intr['in'])] + spec_arguments)
+    values = ', ' + ', '.join(
+        ['intrinsics::Value<%s>' % argument for argument in spec_arguments])
+    print('template<%s>\n%s %s(%s%s) {' % (
+      template_parameters, result, name, params, values), file=f)
+    _gen_template_parameters_verifier(f, intr)
+    print('%sreturn %s(%s);\n}' % (INDENT, name, args), file=f)
     params = ', '.join(
       [params] +
       ['%s %s' % (
@@ -538,24 +589,15 @@ def _gen_mock_semantics_listener_hook(f, name, intr):
   print('MOCK_METHOD((%s), %s, (%s));' % (result, name, params), file=f)
 
 
-def _gen_template_parameters_verifier(f, intr, use_type_id=False):
-  received_params = ', '.join(
-    param
-      if not param.strip().startswith('Type') or use_type_id else
-    f'intrinsics::kIdFromType<{param}>'
-    for param in _get_template_spec_arguments(intr.get('variants')))
+def _gen_template_parameters_verifier(f, intr):
+  received_params = ', '.join(_get_template_spec_arguments(intr.get('variants')))
   print('%sstatic_assert(%s);' % (
    INDENT,
    ' || '.join(
     'std::tuple{%s} == std::tuple{%s}' % (
       received_params,
-      ', '.join(
-        param
-          if param.strip() in ['true', 'false'] + _ROUNDING_MODES or
-             not re.search('[_a-zA-Z]', param) else
-        f'intrinsics::kIdFromType<{param}>'
-        for param in variant.split(',')))
-     for variant in intr.get('variants'))), file=f)
+      ', '.join(_get_expectations_for_variant(variant)))
+      for variant in intr.get('variants'))), file=f)
 
 
 def _check_signed_variant(variant, desc):
@@ -694,9 +736,9 @@ def _get_cast_from_simd128(var, target_type, ptr_bits):
   return '%s%s' % (var, cast_map[c_type])
 
 
-def _get_desc_specializations(intr, desc=None, use_type_id=False):
+def _get_desc_specializations(intr, desc=None):
   if intr.get('class') == 'template':
-    spec = _get_template_spec_arguments(intr.get('variants'), use_type_id)
+    spec = _get_template_spec_arguments(intr.get('variants'), use_type_id=True)
   elif hasattr(desc, 'c_type'):
     spec = [desc.c_type, str(desc.num_elements)]
   elif hasattr(desc, 'num_elements'):
@@ -799,194 +841,148 @@ def _gen_semantic_player_types(intrs):
 def _gen_interpreter_intrinsics_hooks_impl_inl_h(f, intrs, option):
   print(AUTOGEN, file=f)
   for name, intr in intrs:
-    if intr.get('class') == 'template':
-      _gen_interpreter_hook(
-          f, name, intr, option, use_type_id=True)
     _gen_interpreter_hook(f, name, intr, option)
 
 
 def _gen_translator_intrinsics_hooks_impl_inl_h(f, intrs):
   print(AUTOGEN, file=f)
   for name, intr in intrs:
-    if intr.get('class') == 'template':
-      _gen_translator_hook(
-          f, name, intr, use_type_id=True)
     _gen_translator_hook(f, name, intr)
 
 
+def _gen_demultiplexer_intrinsics_hooks_impl_inl_h(f, intrs):
+  print(AUTOGEN, file=f)
+  print("""
+#ifndef BERBERIS_INTRINSICS_HOOKS_LISTENER
+#define BERBERIS_INTRINSICS_HOOKS_LISTENER
+#endif
+
+#ifndef BERBERIS_INTRINSICS_HOOKS_CONST
+#define BERBERIS_INTRINSICS_HOOKS_CONST
+#endif
+
+#ifndef BERBERIS_INTRINSICS_HOOKS_SHARDS_COUNT
+#define BERBERIS_INTRINSICS_HOOKS_SHARDS_COUNT 1
+#define BERBERIS_INTRINSICS_HOOKS_SHARD 0
+#endif
+""", file=f)
+  counter = 0
+  for name, intr in intrs:
+    if intr.get('class') == 'template':
+      print('#if %d %% BERBERIS_INTRINSICS_HOOKS_SHARDS_COUNT == '
+            'BERBERIS_INTRINSICS_HOOKS_SHARD' % counter, file=f)
+      _gen_demultiplexer_hook(f, name, intr)
+      print('#endif', file=f)
+      counter += 1
+
+
 def _gen_mock_semantics_listener_intrinsics_hooks_impl_inl_h(f, intrs):
   print(AUTOGEN, file=f)
   for name, intr in intrs:
     _gen_mock_semantics_listener_hook(f, name, intr)
 
 
-def _get_reg_operand_info(arg, info_prefix=None):
+def _get_binding_info(arg):
   need_tmp = arg['class'] in ('EAX', 'EDX', 'CL', 'ECX')
-  if info_prefix is None:
-    class_info = 'void'
-  else:
-    class_info = '%s::%s' % (info_prefix, arg['class'])
   if arg['class'] == 'Imm8':
-    return 'ImmArg<%d, int8_t, %s>' % (arg['ir_arg'], class_info)
-  if info_prefix is None:
-    using_info = 'void'
-  else:
-    using_info = '%s::%s' % (info_prefix, {
-        'def': 'Def',
-        'def_early_clobber': 'DefEarlyClobber',
-        'use': 'Use',
-        'use_def': 'UseDef'
-    }[arg['usage']])
+    return 'ImmArg<%d>' % (arg['ir_arg'])
   if arg['usage'] == 'use':
     if need_tmp:
-      return 'InTmpArg<%d, %s, %s>' % (arg['ir_arg'], class_info, using_info)
-    return 'InArg<%d, %s, %s>' % (arg['ir_arg'], class_info, using_info)
+      return 'InTmpArg<%d>' % arg['ir_arg']
+    return 'InArg<%d>' % arg['ir_arg']
   if arg['usage'] in ('def', 'def_early_clobber'):
     assert 'ir_arg' not in arg
     if 'ir_res' in arg:
       if need_tmp:
-        return 'OutTmpArg<%d, %s, %s>' % (arg['ir_res'], class_info, using_info)
-      return 'OutArg<%d, %s, %s>' % (arg['ir_res'], class_info, using_info)
-    return 'TmpArg<%s, %s>' % (class_info, using_info)
+        return 'OutTmpArg<%d>' % arg['ir_res']
+      return 'OutArg<%d>' % arg['ir_res']
+    return 'TmpArg'
   if arg['usage'] == 'use_def':
     if 'ir_res' in arg:
       if need_tmp:
-        return 'InOutTmpArg<%s, %s, %s, %s>' % (arg['ir_arg'], arg['ir_res'],
-                                                class_info, using_info)
-      return 'InOutArg<%s, %s, %s, %s>' % (arg['ir_arg'], arg['ir_res'],
-                                           class_info, using_info)
-    return 'InTmpArg<%s, %s, %s>' % (arg['ir_arg'], class_info, using_info)
+        return 'InOutTmpArg<%s, %s>' % (arg['ir_arg'], arg['ir_res'])
+      return 'InOutArg<%s, %s>' % (arg['ir_arg'], arg['ir_res'])
+    return 'InTmpArg<%s>' % (arg['ir_arg'])
   assert False, 'unknown operand usage %s' % (arg['usage'])
 
 
-def _gen_make_intrinsics(f, intrs, archs):
+def _get_bindings_info(args):
+  return 'std::tuple<%s>' % ', '.join(_get_binding_info(arg) for arg in args)
+
+
+def _gen_process_all_bindings(f, intrs, archs):
   print("%s" % AUTOGEN, file=f)
   callback_lines = []
-  static_names = []
-  static_mnemos = []
   for line in _gen_c_intrinsics_generator(
-      intrs, _is_interpreter_compatible_assembler, False, static_names, static_mnemos):
+      intrs, _is_interpreter_compatible_assembler, False):
     callback_lines.append(line)
-  print(
-"""
-/* Note: we generate binding names and binding mnemos used by callbacks in ProcessAllBindings
-globally so that ProcessAllBindings can be constexpr.
-
-Once we can use C++23, these can be declared locally in ProcessAllBindings.*/""", file=f)
-  print("namespace process_all_bindings_strings {", file = f)
-  for static_name in static_names:
-    print("   %s" % static_name, file=f)
-  for static_mnemo in static_mnemos:
-    print("   %s" % static_mnemo, file=f)
-  print("} // process_all_bindings_strings", file = f)
+  # Put implementation into arch-specific namespace to access bindings.
+  print("namespace %s {\n" % archs[-1], file = f)
   print("""
-template <typename MacroAssembler,
+template <typename MacroAssemblers,
           typename Callback,
           typename... Args>
 constexpr void ProcessAllBindings([[maybe_unused]] Callback callback,
                         [[maybe_unused]] Args&&... args) {
-  using intrinsics::Float16;
-  using intrinsics::Float32;
-  using intrinsics::Float64;
-  using namespace process_all_bindings_strings;""",
+  using berberis::intrinsics::Float16;
+  using berberis::intrinsics::Float32;
+  using berberis::intrinsics::Float64;""",
     file=f)
   for line in callback_lines:
     print(line, file=f)
-  print('}', file=f)
+  print("""
+}
 
-def _gen_opcode_generators_f(f, intrs):
-  for line in _gen_opcode_generators(intrs):
-    print(line, file=f)
+}  // namespace %s
 
-def _gen_opcode_generators(intrs):
-  opcode_generators = {}
-  for name, intr in intrs:
-    if 'asm' not in intr:
-      continue
-    if 'variants' in intr:
-      variants = _get_formats_with_descriptions(intr)
-      variants = sorted(variants, key=lambda variant: variant[1].index)
-      # Collect intr_asms for all variants of intrinsic.
-      # Note: not all variants are guaranteed to have an asm variant!
-      # If that happens the list of intr_asms for that variant will be empty.
-      variants = [[
-          intr_asm for intr_asm in _gen_sorted_asms(intr)
-          if fmt in intr_asm['variants']
-      ] for fmt, _ in variants]
-      # Print intrinsic generator
-      for intr_asms in variants:
-        if len(intr_asms) > 0:
-          for intr_asm in intr_asms:
-            if not _is_translator_compatible_assembler(intr_asm):
-              continue
-            for line in _gen_opcode_generator(intr_asm, opcode_generators):
-              yield line
-    else:
-      for intr_asm in _gen_sorted_asms(intr):
-        if not _is_translator_compatible_assembler(intr_asm):
-          continue
-        for line in _gen_opcode_generator(intr_asm, opcode_generators):
-          yield line
+using %s::ProcessAllBindings;
+""" % (archs[-1], archs[-1]), file=f)
 
-def _gen_opcode_generator(asm, opcode_generators):
-  name = asm['name']
-  num_mem_args = sum(1 for arg in asm['args'] if arg.get('class').startswith("Mem") and arg.get('usage') == 'def_early_clobber')
-  opcode = 'Undefined' if num_mem_args > 2 else (asm_defs.get_mem_macro_name(asm, '').replace("Mem", "MemBaseDisp")) if num_mem_args > 0 else name
-
-  if name not in opcode_generators:
-    opcode_generators[name] = True
-    yield """
-// TODO(b/260725458): Pass lambda as template argument after C++20 becomes available.
-class GetOpcode%s {
- public:
-  template <typename Opcode>
-  constexpr auto operator()() {
-    return Opcode::kMachineOp%s;
-  }
-};""" % (name, opcode)
 
 def _gen_process_bindings(f, intrs, archs):
   print("%s" % AUTOGEN, file=f)
   callback_lines = []
-  static_names = []
-  static_mnemos = []
   for line in _gen_c_intrinsics_generator(
-      intrs, _is_translator_compatible_assembler, True, static_names, static_mnemos):
+      intrs, _is_translator_compatible_assembler, True):
     callback_lines.append(line)
-  print(
-"""
-/* Note: we generate binding names and binding mnemos used by callbacks in ProcessBindings
-globally so that ProcessBindings can be constexpr.
-
-Once we can use C++23, these can be declared locally in ProcessBindings.*/""", file=f)
-  print("namespace process_bindings_strings {", file = f)
-  for static_name in static_names:
-    print("   %s" % static_name, file=f)
-  for static_mnemo in static_mnemos:
-    print("   %s" % static_mnemo, file=f)
-  print("} // process_bindings_strings", file = f)
-  _gen_opcode_generators_f(f, intrs)
-
+  # Include definitions of registers for appropriate type of bindings
+  print('#include "berberis/device_arch_info/%s/device_arch_info.h"' % archs[-1], file = f)
+  # Put implementation into arch-specific namespace to access bindings.
+  print('namespace berberis{\n\nnamespace %s::intrinsics::bindings {' % archs[-1], file = f)
   print("""
+template <auto kFunction>
+using FunctionCompareTag = berberis::intrinsics::bindings::FunctionCompareTag<kFunction>;
+
 template <auto kFunc,
-          typename MacroAssembler,
+          typename MacroAssemblers,
           typename Result,
           typename Callback,
           typename... Args>
 constexpr Result ProcessBindings(Callback callback, Result def_result, Args&&... args) {
-  using namespace process_bindings_strings;""",
+  using berberis::intrinsics::Float16;
+  using berberis::intrinsics::Float32;
+  using berberis::intrinsics::Float64;""",
     file=f)
   for line in callback_lines:
     print(line, file=f)
   print("""  }
   return std::forward<Result>(def_result);
-}""", file=f)
+}
+
+}  // namespace %s::intrinsics::bindings
+
+namespace intrinsics::bindings {
+
+using %s::intrinsics::bindings::ProcessBindings;
 
+}  // namespace intrinsics::bindings
 
-def _gen_c_intrinsics_generator(
-    intrs, check_compatible_assembler, gen_builder, static_names, static_mnemos):
-  string_labels = {}
-  mnemo_idx = [0]
+}  // namespace berberis
+""" % (archs[-1], archs[-1]), file=f)
+
+
+def _gen_c_intrinsics_generator(intrs, check_compatible_assembler, gen_builder):
+  processed_names = set()
   for name, intr in intrs:
     ins = intr.get('in')
     outs = intr.get('out')
@@ -1017,24 +1013,18 @@ def _gen_c_intrinsics_generator(
             for line in _gen_c_intrinsic('%s<%s>' % (name, spec),
                                          intr,
                                          intr_asm,
-                                         string_labels,
-                                         mnemo_idx,
+                                         processed_names,
                                          check_compatible_assembler,
-                                         gen_builder,
-                                         static_names,
-                                         static_mnemos):
+                                         gen_builder):
               yield line
     else:
       for intr_asm in _gen_sorted_asms(intr):
         for line in _gen_c_intrinsic(name,
                                      intr,
                                      intr_asm,
-                                     string_labels,
-                                     mnemo_idx,
+                                     processed_names,
                                      check_compatible_assembler,
-                                     gen_builder,
-                                     static_names,
-                                     static_mnemos):
+                                     gen_builder):
           yield line
 
 
@@ -1071,28 +1061,16 @@ _KNOWN_FEATURES_KEYS = {
 }
 
 
-def _gen_c_intrinsic(name,
-                     intr,
-                     asm,
-                     string_labels,
-                     mnemo_idx,
-                     check_compatible_assembler,
-                     gen_builder,
-                     static_names,
-                     static_mnemos):
+def _gen_c_intrinsic(
+    name, intr, asm, processed_names, check_compatible_assembler, gen_builder):
   if not check_compatible_assembler(asm):
     return
 
-  cpuid_restriction = 'intrinsics::bindings::NoCPUIDRestriction'
-  if 'feature' in asm:
-    if asm['feature'] == 'AuthenticAMD':
-      cpuid_restriction = 'intrinsics::bindings::IsAuthenticAMD'
-    else:
-      cpuid_restriction = 'intrinsics::bindings::Has%s' % asm['feature']
+  cpuid_restriction = gen_device_insn_info_lib._get_cpuid_restriction(asm)
 
-  nan_restriction = 'intrinsics::bindings::NoNansOperation'
+  nan_restriction = 'berberis::intrinsics::bindings::NoNansOperation'
   if 'nan' in asm:
-    nan_restriction = 'intrinsics::bindings::%sNanOperationsHandling' % asm['nan']
+    nan_restriction = 'berberis::intrinsics::bindings::%sNanOperationsHandling' % asm['nan']
     template_arg = 'true' if asm['nan'] == "Precise" else "false"
     if '<' in name:
       template_pos = name.index('<')
@@ -1100,44 +1078,37 @@ def _gen_c_intrinsic(name,
     else:
       name += '<' + template_arg + '>'
 
-  if name not in string_labels:
-    name_label = 'BINDING_NAME%d' % len(string_labels)
-    string_labels[name] = name_label
-    if check_compatible_assembler == _is_translator_compatible_assembler:
+  if name not in processed_names:
+    if gen_builder:
       yield ' %s if constexpr (std::is_same_v<FunctionCompareTag<kFunc>,' % (
-        '' if name_label == 'BINDING_NAME0' else ' } else'
+        '' if len(processed_names) == 0 else ' } else'
       )
-      yield '                                      FunctionCompareTag<%s>>) {' % name
-    static_names.append('static constexpr const char %s[] = "%s";' % (name_label, name))
-  else:
-    name_label = string_labels[name]
-
-  mnemo = asm['mnemo']
-  mnemo_label = 'BINDING_MNEMO%d' % mnemo_idx[0]
-  mnemo_idx[0] += 1
-  static_mnemos.append('static constexpr const char %s[] = "%s";' % (mnemo_label, mnemo))
+      yield '%s FunctionCompareTag<berberis::intrinsics::%s>>) {' % (' ' * 36, name)
+    processed_names.add(name)
 
   restriction = [cpuid_restriction, nan_restriction]
 
-  if check_compatible_assembler == _is_translator_compatible_assembler:
+  if gen_builder:
     yield '    if (auto result = callback('
   else:
     yield '    callback('
-  yield '          intrinsics::bindings::AsmCallInfo<'
-  yield '              %s>(),' % (
+  yield '          berberis::intrinsics::bindings::IntrinsicBindingInfo<'
+  yield '              %s,' % (
     ',\n              '.join(
-        [name_label,
-         _get_asm_reference(asm),
-         mnemo_label,
-         _get_builder_reference(intr, asm) if gen_builder else 'void',
-         cpuid_restriction,
+        ['"%s"' % name,
          nan_restriction,
-         'true' if _intr_has_side_effects(intr) else 'false',
          _get_c_type_tuple(intr['in']),
-         _get_c_type_tuple(intr['out'])] +
-        [_get_reg_operand_info(arg, 'intrinsics::bindings')
-         for arg in asm['args']]))
-  if check_compatible_assembler == _is_translator_compatible_assembler:
+         _get_c_type_tuple(intr['out']),
+         _get_bindings_info(asm['args'])]))
+  yield '              device_arch_info::DeviceInsnInfo<%s>>(),' % (
+    ',\n                  '.join(
+        [gen_device_insn_info_lib._get_asm_reference(asm),
+         '"%s"' % asm['mnemo'],
+         'true' if _intr_has_side_effects(intr) else 'false',
+         gen_device_insn_info_lib._get_opcode_reference(asm),
+         cpuid_restriction,
+         gen_device_insn_info_lib._get_reg_operands_info(asm['args'])]))
+  if gen_builder:
     yield '          std::forward<Args>(args)...); result.has_value()) {'
     yield '      return *std::move(result);'
     yield '    }'
@@ -1150,57 +1121,6 @@ def _get_c_type_tuple(arguments):
         _get_c_type(argument) for argument in arguments)
 
 
-def _get_asm_type(asm, prefix=''):
-  args = filter(
-    lambda arg: not asm_defs.is_implicit_reg(arg['class']), asm['args'])
-  return ', '.join(_get_asm_operand_type(arg, prefix) for arg in args)
-
-
-def _get_asm_operand_type(arg, prefix=''):
-  cls = arg.get('class')
-  if asm_defs.is_x87reg(cls):
-    return prefix + 'X87Register'
-  if asm_defs.is_greg(cls):
-    return prefix + 'Register'
-  if asm_defs.is_xreg(cls):
-    return prefix + 'XMMRegister'
-  if asm_defs.is_mem_op(cls):
-    return 'const ' + prefix + 'Operand&'
-  if asm_defs.is_imm(cls):
-    if cls == 'Imm2':
-      return 'int8_t'
-    return 'int' + cls[3:] + '_t'
-  assert False
-
-
-def _get_asm_reference(asm):
-  # Because of misfeature of Itanium C++ ABI we couldn't just use MacroAssembler
-  # to static cast these references if we want to use them as template argument:
-  # https://ibob.bg/blog/2018/08/18/a-bug-in-the-cpp-standard/
-
-  # Thankfully there are usually no need to use the same trick for MacroInstructions
-  # since we may always rename these, except when immediates are involved.
-
-  # But for assembler we need to use actual type from where these
-  # instructions come from!
-  #
-  # E.g. LZCNT have to be processed like this:
-  #   static_cast<void (Assembler_common_x86::*)(
-  #     typename Assembler_common_x86::Register,
-  #     typename Assembler_common_x86::Register)>(
-  #       &Assembler_common_x86::Lzcntl)
-  assembler = 'std::tuple_element_t<%s, MacroAssembler>' % asm['macroassembler']
-  return 'static_cast<void (%s::*)(%s)>(%s&%s::%s%s)' % (
-      assembler,
-      _get_asm_type(asm, 'typename %s::' % assembler),
-      '\n                  ',
-      assembler,
-      'template ' if '<' in asm['asm'] else '',
-      asm['asm'])
-
-def _get_builder_reference(intr, asm):
-  return 'GetOpcode%s' % (asm['name'])
-
 def _load_intrs_def_files(intrs_def_files):
   result = {}
   for intrs_def in intrs_def_files:
@@ -1301,21 +1221,20 @@ def _add_asm_insn(intrs, arch_intr, insn):
   intrs[name]['asm'].append(insn)
 
 
-def _open_asm_def_files(def_files, arch_def_files, asm_def_files, need_archs=True):
+def _open_asm_def_files(def_files, arch_def_files, asm_def_files):
   intrs = _load_intrs_def_files(def_files)
   expanded_intrs = _expand_template_intrinsics(intrs)
   arch_intrs = _load_intrs_arch_def(arch_def_files)
   archs = []
-  macro_assemblers = 0
+  assemblers = 0
   for macro_def in asm_def_files:
-    arch, arch_intrs = _load_macro_def(expanded_intrs, arch_intrs, macro_def, macro_assemblers)
-    macro_assemblers += 1
+    arch, arch_intrs = _load_macro_def(expanded_intrs, arch_intrs, macro_def, assemblers)
+    if arch is not None:
+      archs.append(arch)
+    assemblers += 1
   # Make sure that all intrinsics were found during processing of arch_intrs.
   assert arch_intrs == []
-  if need_archs:
-    return archs, sorted(intrs.items()), sorted(expanded_intrs.items())
-  else:
-    return sorted(intrs.items())
+  return archs, sorted(intrs.items()), sorted(expanded_intrs.items())
 
 
 def _expand_template_intrinsics(intrs):
@@ -1324,7 +1243,20 @@ def _expand_template_intrinsics(intrs):
     if intr.get('class') != 'template':
       expanded_intrs[name] = intr
     else:
-     for variant in intr.get('variants'):
+     variants = intr.get('variants').copy()
+     # These intrinsics serve a dual duty:
+     #   1. They are used to implement regular instructions.
+     #   2. They are used to implement vector instrinsics.
+     # And there's a dilemma: 8bit and 16bit sizes are not supported in #1 but
+     # are needed for #2.
+     # This hack helps us to resolve it. If we would have more such intrinsics
+     # we may need to extend JSON capabilities.
+     if name in ('Aadd', 'Asub', 'DivRiscV', 'RemRiscV', 'Roundoff'):
+       if 'int8_t' not in variants: variants += ['int8_t']
+       if 'uint8_t' not in variants: variants += ['uint8_t']
+       if 'int16_t' not in variants: variants += ['int16_t']
+       if 'uint16_t' not in variants: variants += ['uint16_t']
+     for variant in variants:
        types = {}
        params = [param.strip() for param in variant.split(',')]
        for param in params:
@@ -1346,6 +1278,7 @@ def main(argv):
   #                                      <intrinsics_process_bindings-inl.h>
   #                                      <interpreter_intrinsics_hooks-inl.h>
   #                                      <translator_intrinsics_hooks-inl.h>
+  #                                      <demultiplexer_intrinsics_hooks-inl.h>,
   #                                      <mock_semantics_listener_intrinsics_hooks-inl.h>
   #                                      <riscv64_to_x86_64/intrinsic_def.json",
   #                                      ...
@@ -1373,7 +1306,7 @@ def main(argv):
   option = argv[1]
   if option == 'arm64':
     mode = argv[2]
-    out_files_end = 5
+    out_files_end = 6
     def_files_end = out_files_end
     while argv[def_files_end].endswith('intrinsic_def.json'):
       def_files_end += 1
@@ -1383,11 +1316,12 @@ def main(argv):
     _gen_intrinsics_inl_h(open_out_file(argv[3]), intrs)
     _gen_semantic_player_types(intrs)
     _gen_interpreter_intrinsics_hooks_impl_inl_h(open_out_file(argv[4]), intrs, option)
+    _gen_demultiplexer_intrinsics_hooks_impl_inl_h(open_out_file(argv[5]), intrs)
     return 0
 
   mode = argv[1]
   if mode in ('--text_asm_intrinsics_bindings', '--public_headers'):
-    out_files_end = 3 if mode == '--text_asm_intrinsics_bindings' else 7
+    out_files_end = 3 if mode == '--text_asm_intrinsics_bindings' else 8
     def_files_end = out_files_end
     while argv[def_files_end].endswith('intrinsic_def.json'):
       def_files_end += 1
@@ -1397,10 +1331,9 @@ def main(argv):
     archs, intrs, expanded_intrs = _open_asm_def_files(
       argv[out_files_end:def_files_end],
       argv[def_files_end:arch_def_files_end],
-      argv[arch_def_files_end:],
-      True)
+      argv[arch_def_files_end:])
     if mode == '--text_asm_intrinsics_bindings':
-      _gen_make_intrinsics(open_out_file(argv[2]), expanded_intrs, archs)
+      _gen_process_all_bindings(open_out_file(argv[2]), expanded_intrs, archs)
     else:
       _gen_intrinsics_inl_h(open_out_file(argv[2]), intrs)
       _gen_process_bindings(open_out_file(argv[3]), expanded_intrs, archs)
@@ -1408,8 +1341,10 @@ def main(argv):
       _gen_interpreter_intrinsics_hooks_impl_inl_h(open_out_file(argv[4]), intrs, '')
       _gen_translator_intrinsics_hooks_impl_inl_h(
           open_out_file(argv[5]), intrs)
-      _gen_mock_semantics_listener_intrinsics_hooks_impl_inl_h(
+      _gen_demultiplexer_intrinsics_hooks_impl_inl_h(
           open_out_file(argv[6]), intrs)
+      _gen_mock_semantics_listener_intrinsics_hooks_impl_inl_h(
+          open_out_file(argv[7]), intrs)
   else:
     assert False, 'unknown option %s' % (mode)
 
diff --git a/intrinsics/gen_intrinsics_test.py b/intrinsics/gen_intrinsics_test.py
index 205ae2f4..0da16206 100755
--- a/intrinsics/gen_intrinsics_test.py
+++ b/intrinsics/gen_intrinsics_test.py
@@ -41,15 +41,6 @@ class GenIntrinsicsTests(unittest.TestCase):
         }}
     gen_intrinsics._gen_semantic_player_types(intr.items())
     out = gen_intrinsics._get_semantics_player_hook_proto("Foo", intr["Foo"])
-    self.assertEqual(out,
-                     "template<typename Type0, typename Type1>\n"
-                     "Register Foo(Register arg0, "
-                                  "Register arg1, "
-                                  "FpRegister arg2, "
-                                  "Register arg3, "
-                                  "SimdRegister arg4, "
-                                  "uint8_t arg5)" ) # pyformat: disable
-    out = gen_intrinsics._get_semantics_player_hook_proto("Foo", intr["Foo"], use_type_id=True)
     self.assertEqual(out,
                      "template<intrinsics::TemplateTypeId Type0, intrinsics::TemplateTypeId Type1>\n"
                      "Register Foo(Register arg0, "
@@ -60,6 +51,18 @@ class GenIntrinsicsTests(unittest.TestCase):
                                   "uint8_t arg5, "
                                   "intrinsics::Value<Type0>, "
                                   "intrinsics::Value<Type1>)" ) # pyformat: disable
+    out = gen_intrinsics._get_semantics_player_hook_proto(
+        "Foo", intr["Foo"], listener=' Interpreter::')
+    self.assertEqual(out,
+                     " Interpreter::Register  Interpreter::Foo("
+                     " Interpreter::Register arg0, "
+                     " Interpreter::Register arg1, "
+                     " Interpreter::FpRegister arg2, "
+                     " Interpreter::Register arg3, "
+                     " Interpreter::SimdRegister arg4,"
+                     " uint8_t arg5,"
+                     " intrinsics::TemplateTypeId Type0,"
+                     " intrinsics::TemplateTypeId Type1)" ) # pyformat: disable
 
   def test_get_semantics_player_hook_proto_operand_types(self):
     out = gen_intrinsics._get_semantics_player_hook_proto(
@@ -101,17 +104,6 @@ class GenIntrinsicsTests(unittest.TestCase):
         }}
     gen_intrinsics._gen_semantic_player_types(intr.items())
     out = gen_intrinsics._get_interpreter_hook_call_expr("Foo", intr["Foo"])
-    self.assertEqual(
-        out,
-        "IntegerToGPRReg(std::get<0>(intrinsics::Foo<Type0, Type1>("
-            "GPRRegToInteger<uint32_t>(arg0), "
-            "GPRRegToInteger<uint8_t>(arg1), "
-            "FPRegToFloat<Type0>(arg2), "
-            "GPRRegToInteger<Type1>(arg3), "
-            "arg4, "
-            "GPRRegToInteger<uint8_t>(arg5))))" ) # pyforman: disable
-    out = gen_intrinsics._get_interpreter_hook_call_expr("Foo", intr["Foo"], use_type_id=True)
-    self.maxDiff = None
     self.assertEqual(
         out,
         "IntegerToGPRReg(std::get<0>(intrinsics::Foo<"
@@ -414,18 +406,105 @@ class GenIntrinsicsTests(unittest.TestCase):
         }
     out = io.StringIO()
     gen_intrinsics._gen_template_parameters_verifier(out, intrinsic)
-    self.assertSequenceEqual(out.getvalue(),
-                             "  static_assert(std::tuple{intrinsics::kIdFromType<Type0>} == "
-                             "std::tuple{intrinsics::kIdFromType<int32_t>} || "
-                             "std::tuple{intrinsics::kIdFromType<Type0>} == "
-                             "std::tuple{intrinsics::kIdFromType<int64_t>});\n") # pyformat: disable
-    out = io.StringIO()
-    gen_intrinsics._gen_template_parameters_verifier(out, intrinsic, use_type_id=True)
     self.assertSequenceEqual(out.getvalue(),
                              "  static_assert(std::tuple{Type0} == "
                              "std::tuple{intrinsics::kIdFromType<int32_t>} || std::tuple{Type0} == "
                              "std::tuple{intrinsics::kIdFromType<int64_t>});\n") # pyformat: disable
 
+  def test_gen_interpreter_hook(self):
+    intrinsic = {
+            "class": "template",
+            "variants": [ "int32_t", "int64_t" ],
+            "in": [ "Type0", "int8_t" ],
+            "out": [ "Type0" ]
+        }
+    out = io.StringIO()
+    gen_intrinsics._gen_interpreter_hook(out, "Foo", intrinsic, '')
+    self.assertSequenceEqual(out.getvalue(),
+                             "#ifndef BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER\n"
+                             "Register Foo(Register arg0, Register arg1, intrinsics::TemplateTypeId Type0) "
+                             "const;\n"
+                             "#endif\n"
+                             "template<intrinsics::TemplateTypeId Type0>\n"
+                             "Register Foo(Register arg0, Register arg1, intrinsics::Value<Type0>) const "
+                             "{\n"
+                             "  return "
+                             "std::get<0>(intrinsics::Foo<intrinsics::TypeFromId<Type0>>("
+                             "GPRRegToInteger<intrinsics::TypeFromId<Type0>>(arg0), "
+                             "GPRRegToInteger<int8_t>(arg1)));\n"
+                             "}\n\n") # pyformat: disable
+
+
+  def test_gen_demultiplexer_hook(self):
+    intrinsic = {
+            "class": "template",
+            "variants": [ "int32_t", "int64_t" ],
+            "in": [ "Type0", "int8_t" ],
+            "out": [ "Type0" ]
+        }
+    out = io.StringIO()
+    gen_intrinsics._gen_demultiplexer_hook(out, "Foo", intrinsic)
+    self.assertSequenceEqual(out.getvalue(),
+                             " BERBERIS_INTRINSICS_HOOKS_LISTENER Register  "
+                             "BERBERIS_INTRINSICS_HOOKS_LISTENER Foo( BERBERIS_INTRINSICS_HOOKS_LISTENER "
+                             "Register arg0,  BERBERIS_INTRINSICS_HOOKS_LISTENER Register arg1, "
+                             "intrinsics::TemplateTypeId Type0) BERBERIS_INTRINSICS_HOOKS_CONST {\n"
+                             "  switch (intrinsics::TrivialDemultiplexer(Type0)) {\n"
+                             "    case "
+                             "intrinsics::TrivialDemultiplexer(intrinsics::kIdFromType<int32_t>):\n"
+                             "      // Disable LOG_NDEBUG to use DCHECK for debugging!\n"
+                             "      DCHECK_EQ(intrinsics::kIdFromType<int32_t>, Type0);\n"
+                             "      return "
+                             "Foo(arg0,arg1,intrinsics::Value<intrinsics::kIdFromType<int32_t>>{});\n"
+                             "    case "
+                             "intrinsics::TrivialDemultiplexer(intrinsics::kIdFromType<int64_t>):\n"
+                             "      // Disable LOG_NDEBUG to use DCHECK for debugging!\n"
+                             "      DCHECK_EQ(intrinsics::kIdFromType<int64_t>, Type0);\n"
+                             "      return "
+                             "Foo(arg0,arg1,intrinsics::Value<intrinsics::kIdFromType<int64_t>>{});\n"
+                             "    default:\n"
+                             "      FATAL(\"Unsupported size\");\n"
+                             "  }\n"
+                             "}\n\n") # pyformat: disable
+
+
+  def test_gen_demultiplexer_hook_multiple_types(self):
+    intrinsic = {
+            "class": "template",
+            "variants": [ "int32_t, Float32", "int64_t, Float64" ],
+            "in": [ "Type0", "int8_t" ],
+            "out": [ "Type0" ]
+        }
+    out = io.StringIO()
+    gen_intrinsics._gen_demultiplexer_hook(out, "Foo", intrinsic)
+    self.assertSequenceEqual(out.getvalue(),
+                             " BERBERIS_INTRINSICS_HOOKS_LISTENER Register  "
+                             "BERBERIS_INTRINSICS_HOOKS_LISTENER Foo( BERBERIS_INTRINSICS_HOOKS_LISTENER "
+                             "Register arg0,  BERBERIS_INTRINSICS_HOOKS_LISTENER Register arg1, "
+                             "intrinsics::TemplateTypeId Type0, intrinsics::TemplateTypeId Type1) "
+                             "BERBERIS_INTRINSICS_HOOKS_CONST {\n"
+                             "  switch (intrinsics::TrivialDemultiplexer(Type0, Type1)) {\n"
+                             "    case intrinsics::TrivialDemultiplexer(intrinsics::kIdFromType<int32_t>, "
+                             "intrinsics::kIdFromType<Float32>):\n"
+                             "      // Disable LOG_NDEBUG to use DCHECK for debugging!\n"
+                             "      DCHECK_EQ(intrinsics::kIdFromType<int32_t>, Type0);\n"
+                             "      DCHECK_EQ(intrinsics::kIdFromType<Float32>, Type1);\n"
+                             "      return "
+                             "Foo(arg0,arg1,intrinsics::Value<intrinsics::kIdFromType<int32_t>>{},"
+                             "intrinsics::Value<intrinsics::kIdFromType<Float32>>{});\n"
+                             "    case intrinsics::TrivialDemultiplexer(intrinsics::kIdFromType<int64_t>, "
+                             "intrinsics::kIdFromType<Float64>):\n"
+                             "      // Disable LOG_NDEBUG to use DCHECK for debugging!\n"
+                             "      DCHECK_EQ(intrinsics::kIdFromType<int64_t>, Type0);\n"
+                             "      DCHECK_EQ(intrinsics::kIdFromType<Float64>, Type1);\n"
+                             "      return "
+                             "Foo(arg0,arg1,intrinsics::Value<intrinsics::kIdFromType<int64_t>>{},"
+                             "intrinsics::Value<intrinsics::kIdFromType<Float64>>{});\n"
+                             "    default:\n"
+                             "      FATAL(\"Unsupported size\");\n"
+                             "  }\n"
+                             "}\n\n") # pyformat: disable
+
 
 if __name__ == "__main__":
   unittest.main(verbosity=2)
diff --git a/intrinsics/gen_text_asm_intrinsics.cc b/intrinsics/gen_text_asm_intrinsics.cc
index 49884214..ae0d989d 100644
--- a/intrinsics/gen_text_asm_intrinsics.cc
+++ b/intrinsics/gen_text_asm_intrinsics.cc
@@ -39,55 +39,55 @@
 
 namespace berberis {
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateOutputVariables(FILE* out, int indent);
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateTemporaries(FILE* out, int indent);
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateInShadows(FILE* out, int indent);
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateAssemblerOuts(FILE* out, int indent);
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateAssemblerIns(FILE* out,
                           int indent,
                           int* register_numbers,
                           bool need_gpr_macroassembler_scratch,
                           bool need_gpr_macroassembler_constants);
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateOutShadows(FILE* out, int indent);
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateElementsList(FILE* out,
                           int indent,
                           const std::string& prefix,
                           const std::string& suffix,
                           const std::vector<std::string>& elements);
-template <typename AsmCallInfo, typename Arg>
-constexpr bool NeedInputShadow(Arg arg);
-template <typename AsmCallInfo, typename Arg>
-constexpr bool NeedOutputShadow(Arg arg);
+template <typename IntrinsicBindingInfo, typename Binding, typename Operand>
+constexpr bool NeedInputShadow();
+template <typename IntrinsicBindingInfo, typename Binding, typename Operand>
+constexpr bool NeedOutputShadow();
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateFunctionHeader(FILE* out, int indent) {
-  if (strchr(AsmCallInfo::kIntrinsic, '<')) {
+  if (strchr(IntrinsicBindingInfo::kIntrinsic, '<')) {
     fprintf(out, "template <>\n");
   }
   std::string prefix;
-  if constexpr (std::tuple_size_v<typename AsmCallInfo::OutputArguments> == 0) {
-    prefix = "inline void " + std::string(AsmCallInfo::kIntrinsic) + "(";
+  if constexpr (std::tuple_size_v<typename IntrinsicBindingInfo::OutputArguments> == 0) {
+    prefix = "inline void " + std::string(IntrinsicBindingInfo::kIntrinsic) + "(";
   } else {
     const char* prefix_of_prefix = "inline std::tuple<";
-    for (const char* type_name : AsmCallInfo::OutputArgumentsTypeNames) {
+    for (const char* type_name : IntrinsicBindingInfo::OutputArgumentsTypeNames) {
       prefix += prefix_of_prefix + std::string(type_name);
       prefix_of_prefix = ", ";
     }
-    prefix += "> " + std::string(AsmCallInfo::kIntrinsic) + "(";
+    prefix += "> " + std::string(IntrinsicBindingInfo::kIntrinsic) + "(";
   }
   std::vector<std::string> ins;
-  for (const char* type_name : AsmCallInfo::InputArgumentsTypeNames) {
+  for (const char* type_name : IntrinsicBindingInfo::InputArgumentsTypeNames) {
     ins.push_back("[[maybe_unused]] " + std::string(type_name) + " in" +
                   std::to_string(ins.size()));
   }
-  GenerateElementsList<AsmCallInfo>(out, indent, prefix, ") {", ins);
+  GenerateElementsList<IntrinsicBindingInfo>(out, indent, prefix, ") {", ins);
   fprintf(out,
           "  [[maybe_unused]]  alignas(berberis::config::kScratchAreaAlign)"
           " uint8_t scratch[berberis::config::kScratchAreaSize];\n");
@@ -96,29 +96,16 @@ void GenerateFunctionHeader(FILE* out, int indent) {
           " scratch[berberis::config::kScratchAreaSlotSize];\n");
 }
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 constexpr void CallAssembler(MacroAssembler<TextAssembler>* as, int* register_numbers) {
   int arg_counter = 0;
-  AsmCallInfo::ProcessBindings([&arg_counter, &as, register_numbers](auto arg) {
-    using RegisterClass = typename decltype(arg)::RegisterClass;
-    if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-      if constexpr (RegisterClass::kAsRegister != 'm') {
-        if constexpr (RegisterClass::kIsImplicitReg) {
-          if constexpr (RegisterClass::kAsRegister == 'a') {
-            as->gpr_a =
-                typename MacroAssembler<TextAssembler>::Register(register_numbers[arg_counter]);
-          } else if constexpr (RegisterClass::kAsRegister == 'b') {
-            as->gpr_b =
-                typename MacroAssembler<TextAssembler>::Register(register_numbers[arg_counter]);
-          } else if constexpr (RegisterClass::kAsRegister == 'c') {
-            as->gpr_c =
-                typename MacroAssembler<TextAssembler>::Register(register_numbers[arg_counter]);
-          } else {
-            static_assert(RegisterClass::kAsRegister == 'd');
-            as->gpr_d =
-                typename MacroAssembler<TextAssembler>::Register(register_numbers[arg_counter]);
-          }
-        }
+  IntrinsicBindingInfo::ProcessBindings([&arg_counter,
+                                         &as,
+                                         register_numbers]<typename Binding, typename Operand> {
+    if constexpr (device_arch_info::kIsRegister<Operand> && !device_arch_info::kIsFLAGS<Operand>) {
+      if constexpr (device_arch_info::kIsImplicitReg<Operand>) {
+        as->*(Operand::Class::template kAssemblerRegisterPointer<MacroAssembler<TextAssembler>>) =
+            typename MacroAssembler<TextAssembler>::Register(register_numbers[arg_counter]);
       }
       ++arg_counter;
     }
@@ -126,145 +113,154 @@ constexpr void CallAssembler(MacroAssembler<TextAssembler>* as, int* register_nu
   as->gpr_macroassembler_constants = typename MacroAssembler<TextAssembler>::Register(arg_counter);
   arg_counter = 0;
   int scratch_counter = 0;
-  std::apply(AsmCallInfo::kMacroInstruction,
-             std::tuple_cat(
-                 std::tuple<MacroAssembler<TextAssembler>&>{*as},
-                 AsmCallInfo::MakeTuplefromBindings(
-                     [&as, &arg_counter, &scratch_counter, register_numbers](auto arg) {
-                       using RegisterClass = typename decltype(arg)::RegisterClass;
-                       if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-                         if constexpr (RegisterClass::kAsRegister == 'm') {
-                           if (scratch_counter == 0) {
-                             as->gpr_macroassembler_scratch =
-                                 typename MacroAssembler<TextAssembler>::Register(arg_counter++);
-                           } else if (scratch_counter == 1) {
-                             as->gpr_macroassembler_scratch2 =
-                                 typename MacroAssembler<TextAssembler>::Register(arg_counter++);
+  std::apply(
+      IntrinsicBindingInfo::kEmitInsnFunc,
+      std::tuple_cat(std::tuple<MacroAssembler<TextAssembler>&>{*as},
+                     IntrinsicBindingInfo::MakeTuplefromBindings(
+                         [&as,
+                          &arg_counter,
+                          &scratch_counter,
+                          register_numbers]<typename Binding, typename Operand> {
+                           if constexpr (device_arch_info::kIsMemoryOperand<Operand>) {
+                             if (scratch_counter == 0) {
+                               as->gpr_macroassembler_scratch =
+                                   typename MacroAssembler<TextAssembler>::Register(arg_counter++);
+                             } else if (scratch_counter == 1) {
+                               as->gpr_macroassembler_scratch2 =
+                                   typename MacroAssembler<TextAssembler>::Register(arg_counter++);
+                             } else {
+                               FATAL("Only two scratch registers are supported for now");
+                             }
+                             // Note: as->gpr_scratch in combination with offset is treated by text
+                             // assembler specially.  We rely on offset set here to be the same as
+                             // scratch2 address in scratch buffer.
+                             return std::tuple{typename MacroAssembler<TextAssembler>::Operand{
+                                 .base = as->gpr_scratch,
+                                 .disp = static_cast<int32_t>(config::kScratchAreaSlotSize *
+                                                              scratch_counter++)}};
+                           } else if constexpr (device_arch_info::kIsRegister<Operand> &&
+                                                !device_arch_info::kIsFLAGS<Operand>) {
+                             if constexpr (device_arch_info::kIsImplicitReg<Operand>) {
+                               ++arg_counter;
+                               return std::tuple{};
+                             } else {
+                               return std::tuple{register_numbers[arg_counter++]};
+                             }
                            } else {
-                             FATAL("Only two scratch registers are supported for now");
+                             return std::tuple{};
                            }
-                           // Note: as->gpr_scratch in combination with offset is treated by text
-                           // assembler specially.  We rely on offset set here to be the same as
-                           // scratch2 address in scratch buffer.
-                           return std::tuple{typename MacroAssembler<TextAssembler>::Operand{
-                               .base = as->gpr_scratch,
-                               .disp = static_cast<int32_t>(config::kScratchAreaSlotSize *
-                                                            scratch_counter++)}};
-                         } else if constexpr (RegisterClass::kIsImplicitReg) {
-                           ++arg_counter;
-                           return std::tuple{};
-                         } else {
-                           return std::tuple{register_numbers[arg_counter++]};
-                         }
-                       } else {
-                         return std::tuple{};
-                       }
-                     })));
+                         })));
 }
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateFunctionBody(FILE* out, int indent) {
   // Declare out variables.
-  GenerateOutputVariables<AsmCallInfo>(out, indent);
+  GenerateOutputVariables<IntrinsicBindingInfo>(out, indent);
   // Declare temporary variables.
-  GenerateTemporaries<AsmCallInfo>(out, indent);
+  GenerateTemporaries<IntrinsicBindingInfo>(out, indent);
   // We need "shadow variables" for ins of types: Float32, Float64 and SIMD128Register.
   // This is because assembler does not accept these arguments for XMMRegisters and
   // we couldn't use "float"/"double" function arguments because if ABI issues.
-  GenerateInShadows<AsmCallInfo>(out, indent);
+  GenerateInShadows<IntrinsicBindingInfo>(out, indent);
   // Even if we don't pass any registers we need to allocate at least one element.
-  int register_numbers[std::tuple_size_v<typename AsmCallInfo::Bindings> == 0
+  int register_numbers[std::tuple_size_v<typename IntrinsicBindingInfo::Bindings> == 0
                            ? 1
-                           : std::tuple_size_v<typename AsmCallInfo::Bindings>];
+                           : std::tuple_size_v<typename IntrinsicBindingInfo::Bindings>];
   // Assign numbers to registers - we need to pass them to assembler and then, later,
   // to Generator of Input Variable line.
-  AssignRegisterNumbers<AsmCallInfo>(register_numbers);
+  AssignRegisterNumbers<IntrinsicBindingInfo>(register_numbers);
   // Print opening line for asm call.
-  if constexpr (AsmCallInfo::kSideEffects) {
+  if constexpr (IntrinsicBindingInfo::kSideEffects) {
     fprintf(out, "%*s__asm__ __volatile__(\n", indent, "");
   } else {
     fprintf(out, "%*s__asm__(\n", indent, "");
   }
   // Call text assembler to produce the body of an asm call.
   MacroAssembler<TextAssembler> as(indent, out);
-  CallAssembler<AsmCallInfo>(&as, register_numbers);
+  CallAssembler<IntrinsicBindingInfo>(&as, register_numbers);
   // Assembler instruction outs.
-  GenerateAssemblerOuts<AsmCallInfo>(out, indent);
+  GenerateAssemblerOuts<IntrinsicBindingInfo>(out, indent);
   // Assembler instruction ins.
-  GenerateAssemblerIns<AsmCallInfo>(out,
-                                    indent,
-                                    register_numbers,
-                                    as.need_gpr_macroassembler_scratch(),
-                                    as.need_gpr_macroassembler_constants());
+  GenerateAssemblerIns<IntrinsicBindingInfo>(out,
+                                             indent,
+                                             register_numbers,
+                                             as.need_gpr_macroassembler_scratch(),
+                                             as.need_gpr_macroassembler_constants());
   // Close asm call.
   fprintf(out, "%*s);\n", indent, "");
   // Generate copies from shadows to outputs.
-  GenerateOutShadows<AsmCallInfo>(out, indent);
+  GenerateOutShadows<IntrinsicBindingInfo>(out, indent);
   // Return value from function.
-  if constexpr (std::tuple_size_v<typename AsmCallInfo::OutputArguments> > 0) {
+  if constexpr (std::tuple_size_v<typename IntrinsicBindingInfo::OutputArguments> > 0) {
     std::vector<std::string> outs;
-    for (std::size_t id = 0; id < std::tuple_size_v<typename AsmCallInfo::OutputArguments>; ++id) {
+    for (std::size_t id = 0; id < std::tuple_size_v<typename IntrinsicBindingInfo::OutputArguments>;
+         ++id) {
       outs.push_back("out" + std::to_string(id));
     }
-    GenerateElementsList<AsmCallInfo>(out, indent, "return {", "};", outs);
+    GenerateElementsList<IntrinsicBindingInfo>(out, indent, "return {", "};", outs);
   }
 }
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateOutputVariables(FILE* out, int indent) {
   std::size_t id = 0;
-  for (const char* type_name : AsmCallInfo::OutputArgumentsTypeNames) {
+  for (const char* type_name : IntrinsicBindingInfo::OutputArgumentsTypeNames) {
     fprintf(out, "%*s%s out%zd;\n", indent, "", type_name, id++);
   }
 }
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateTemporaries(FILE* out, int indent) {
   std::size_t id = 0;
-  AsmCallInfo::ProcessBindings([out, &id, indent](auto arg) {
-    using RegisterClass = typename decltype(arg)::RegisterClass;
-    if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-      if constexpr (!HaveInput(arg.arg_info) && !HaveOutput(arg.arg_info)) {
-        static_assert(
-            std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::Def> ||
-            std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::DefEarlyClobber>);
-        fprintf(out,
-                "%*s%s tmp%zd;\n",
-                indent,
-                "",
-                TypeTraits<typename RegisterClass::Type>::kName,
-                id++);
-      }
+  IntrinsicBindingInfo::ProcessBindings([out, &id, indent]<typename Binding, typename Operand> {
+    using RegisterClass = Operand::Class;
+    if constexpr (!device_arch_info::kIsFLAGS<Operand> && !HaveInput(Binding::kArgInfo) &&
+                  !HaveOutput(Binding::kArgInfo)) {
+      static_assert(Operand::kUsage == device_arch_info::kDef ||
+                    Operand::kUsage == device_arch_info::kDefEarlyClobber);
+      fprintf(out,
+              "%*s%s tmp%zd;\n",
+              indent,
+              "",
+              TypeTraits<typename RegisterClass::Type>::kName,
+              id++);
     }
   });
 }
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateInShadows(FILE* out, int indent) {
-  AsmCallInfo::ProcessBindings([out, indent](auto arg) {
-    using RegisterClass = typename decltype(arg)::RegisterClass;
-    if constexpr (RegisterClass::kAsRegister == 'm') {
+  IntrinsicBindingInfo::ProcessBindings([out, indent]<typename Binding, typename Operand> {
+    using RegisterClass = Operand::Class;
+    if constexpr (device_arch_info::kIsMemoryOperand<Operand>) {
       // Only temporary memory scratch area is supported.
-      static_assert(!HaveInput(arg.arg_info) && !HaveOutput(arg.arg_info));
+      static_assert(!HaveInput(Binding::kArgInfo) && !HaveOutput(Binding::kArgInfo));
+    } else if constexpr (device_arch_info::kIsFLAGS<Operand>) {
+      // Flags don't require any special variables.
     } else if constexpr (RegisterClass::kAsRegister == 'r') {
       // TODO(b/138439904): remove when clang handling of 'r' constraint would be fixed.
-      if constexpr (NeedInputShadow<AsmCallInfo>(arg)) {
-        fprintf(out, "%2$*1$suint32_t in%3$d_shadow = in%3$d;\n", indent, "", arg.arg_info.from);
+      if constexpr (NeedInputShadow<IntrinsicBindingInfo, Binding, Operand>()) {
+        fprintf(
+            out, "%2$*1$suint32_t in%3$d_shadow = in%3$d;\n", indent, "", Binding::kArgInfo.from);
       }
-      if constexpr (NeedOutputShadow<AsmCallInfo>(arg)) {
-        fprintf(out, "%*suint32_t out%d_shadow;\n", indent, "", arg.arg_info.to);
+      if constexpr (NeedOutputShadow<IntrinsicBindingInfo, Binding, Operand>()) {
+        fprintf(out, "%*suint32_t out%d_shadow;\n", indent, "", Binding::kArgInfo.to);
       }
     } else if constexpr (RegisterClass::kAsRegister == 'x') {
-      if constexpr (HaveInput(arg.arg_info)) {
-        using Type = std::tuple_element_t<arg.arg_info.from, typename AsmCallInfo::InputArguments>;
+      if constexpr (HaveInput(Binding::kArgInfo)) {
+        using Type = std::tuple_element_t<Binding::kArgInfo.from,
+                                          typename IntrinsicBindingInfo::InputArguments>;
         const char* type_name = TypeTraits<Type>::kName;
         const char* xmm_type_name;
         const char* expanded = "";
         // Types allowed for 'x' restriction are float, double and __m128/__m128i/__m128d
         // First two work for {,u}int32_t and {,u}int64_t, but small integer types must be expanded.
         if constexpr (std::is_integral_v<Type> && sizeof(Type) < sizeof(int32_t)) {
-          fprintf(
-              out, "%2$*1$suint32_t in%3$d_expanded = in%3$d;\n", indent, "", arg.arg_info.from);
+          fprintf(out,
+                  "%2$*1$suint32_t in%3$d_expanded = in%3$d;\n",
+                  indent,
+                  "",
+                  Binding::kArgInfo.from);
           type_name = TypeTraits<uint32_t>::kName;
           xmm_type_name =
               TypeTraits<typename TypeTraits<typename TypeTraits<uint32_t>::Float>::Raw>::kName;
@@ -276,12 +272,12 @@ void GenerateInShadows(FILE* out, int indent) {
         } else if constexpr (std::is_same_v<Type, intrinsics::Float16>) {
           // It's a bit strange that _Float16 is not accepted in XMM register, but it's also not
           // clear if it's a bug or not. Just use __m128 for now.
-          fprintf(out, "%2$*1$s__m128 in%3$d_expanded;\n", indent, "", arg.arg_info.from);
+          fprintf(out, "%2$*1$s__m128 in%3$d_expanded;\n", indent, "", Binding::kArgInfo.from);
           fprintf(out,
                   "%2$*1$smemcpy(&in%3$d_expanded, &in%3$d, sizeof(Float16));\n",
                   indent,
                   "",
-                  arg.arg_info.from);
+                  Binding::kArgInfo.from);
           type_name = "__m128";
           xmm_type_name = "__m128";
           expanded = "_expanded";
@@ -289,7 +285,7 @@ void GenerateInShadows(FILE* out, int indent) {
           // Float32/Float64 can not be used, we need to use raw float/double.
           xmm_type_name = TypeTraits<typename TypeTraits<Type>::Raw>::kName;
         }
-        fprintf(out, "%*s%s in%d_shadow;\n", indent, "", xmm_type_name, arg.arg_info.from);
+        fprintf(out, "%*s%s in%d_shadow;\n", indent, "", xmm_type_name, Binding::kArgInfo.from);
         fprintf(out,
                 "%*sstatic_assert(sizeof(%s) == sizeof(%s));\n",
                 indent,
@@ -303,12 +299,13 @@ void GenerateInShadows(FILE* out, int indent) {
                 "%2$*1$smemcpy(&in%3$d_shadow, &in%3$d%4$s, sizeof(%5$s));\n",
                 indent,
                 "",
-                arg.arg_info.from,
+                Binding::kArgInfo.from,
                 expanded,
                 xmm_type_name);
       }
-      if constexpr (HaveOutput(arg.arg_info)) {
-        using Type = std::tuple_element_t<arg.arg_info.to, typename AsmCallInfo::OutputArguments>;
+      if constexpr (HaveOutput(Binding::kArgInfo)) {
+        using Type = std::tuple_element_t<Binding::kArgInfo.to,
+                                          typename IntrinsicBindingInfo::OutputArguments>;
         const char* xmm_type_name;
         // {,u}int32_t and {,u}int64_t have to be converted to float/double.
         if constexpr (std::is_integral_v<Type>) {
@@ -322,55 +319,54 @@ void GenerateInShadows(FILE* out, int indent) {
           // Float32/Float64 can not be used, we need to use raw float/double.
           xmm_type_name = TypeTraits<typename TypeTraits<Type>::Raw>::kName;
         }
-        fprintf(out, "%*s%s out%d_shadow;\n", indent, "", xmm_type_name, arg.arg_info.to);
+        fprintf(out, "%*s%s out%d_shadow;\n", indent, "", xmm_type_name, Binding::kArgInfo.to);
       }
     }
   });
 }
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateAssemblerOuts(FILE* out, int indent) {
   std::vector<std::string> outs;
   int tmp_id = 0;
-  AsmCallInfo::ProcessBindings([&outs, &tmp_id](auto arg) {
-    using RegisterClass = typename decltype(arg)::RegisterClass;
-    if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS> &&
-                  !std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::Use>) {
+  IntrinsicBindingInfo::ProcessBindings([&outs, &tmp_id]<typename Binding, typename Operand> {
+    using RegisterClass = Operand::Class;
+    if constexpr (!device_arch_info::kIsFLAGS<Operand> &&
+                  Operand::kUsage != device_arch_info::kUse) {
       std::string out = "\"=";
-      if constexpr (std::is_same_v<typename decltype(arg)::Usage,
-                                   intrinsics::bindings::DefEarlyClobber>) {
+      if constexpr (Operand::kUsage == device_arch_info::kDefEarlyClobber) {
         out += "&";
       }
       out += RegisterClass::kAsRegister;
-      if constexpr (HaveOutput(arg.arg_info)) {
-        bool need_shadow = NeedOutputShadow<AsmCallInfo>(arg);
-        out += "\"(out" + std::to_string(arg.arg_info.to) + (need_shadow ? "_shadow)" : ")");
-      } else if constexpr (HaveInput(arg.arg_info)) {
-        bool need_shadow = NeedInputShadow<AsmCallInfo>(arg);
-        out += "\"(in" + std::to_string(arg.arg_info.from) + (need_shadow ? "_shadow)" : ")");
+      if constexpr (HaveOutput(Binding::kArgInfo)) {
+        bool need_shadow = NeedOutputShadow<IntrinsicBindingInfo, Binding, Operand>();
+        out += "\"(out" + std::to_string(Binding::kArgInfo.to) + (need_shadow ? "_shadow)" : ")");
+      } else if constexpr (HaveInput(Binding::kArgInfo)) {
+        bool need_shadow = NeedInputShadow<IntrinsicBindingInfo, Binding, Operand>();
+        out += "\"(in" + std::to_string(Binding::kArgInfo.from) + (need_shadow ? "_shadow)" : ")");
       } else {
         out += "\"(tmp" + std::to_string(tmp_id++) + ")";
       }
       outs.push_back(out);
     }
   });
-  GenerateElementsList<AsmCallInfo>(out, indent, "  : ", "", outs);
+  GenerateElementsList<IntrinsicBindingInfo>(out, indent, "  : ", "", outs);
 }
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateAssemblerIns(FILE* out,
                           int indent,
                           int* register_numbers,
                           bool need_gpr_macroassembler_scratch,
                           bool need_gpr_macroassembler_constants) {
   std::vector<std::string> ins;
-  AsmCallInfo::ProcessBindings([&ins](auto arg) {
-    using RegisterClass = typename decltype(arg)::RegisterClass;
-    if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS> &&
-                  std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::Use>) {
+  IntrinsicBindingInfo::ProcessBindings([&ins]<typename Binding, typename Operand> {
+    using RegisterClass = Operand::Class;
+    if constexpr (!device_arch_info::kIsFLAGS<Operand> &&
+                  Operand::kUsage == device_arch_info::kUse) {
       ins.push_back("\"" + std::string(1, RegisterClass::kAsRegister) + "\"(in" +
-                    std::to_string(arg.arg_info.from) +
-                    (NeedInputShadow<AsmCallInfo>(arg) ? "_shadow)" : ")"));
+                    std::to_string(Binding::kArgInfo.from) +
+                    (NeedInputShadow<IntrinsicBindingInfo, Binding, Operand>() ? "_shadow)" : ")"));
     }
   });
   if (need_gpr_macroassembler_scratch) {
@@ -381,36 +377,39 @@ void GenerateAssemblerIns(FILE* out,
         "\"m\"(*reinterpret_cast<const char*>(&constants_pool::kBerberisMacroAssemblerConstants))");
   }
   int arg_counter = 0;
-  AsmCallInfo::ProcessBindings([&ins, &arg_counter, register_numbers](auto arg) {
-    using RegisterClass = typename decltype(arg)::RegisterClass;
-    if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-      if constexpr (HaveInput(arg.arg_info) &&
-                    !std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::Use>) {
-        ins.push_back("\"" + std::to_string(register_numbers[arg_counter]) + "\"(in" +
-                      std::to_string(arg.arg_info.from) +
-                      (NeedInputShadow<AsmCallInfo>(arg) ? "_shadow)" : ")"));
-      }
-      ++arg_counter;
+  IntrinsicBindingInfo::ProcessBindings([&ins,
+                                         &arg_counter,
+                                         register_numbers]<typename Binding, typename Operand> {
+    if constexpr (!device_arch_info::kIsFLAGS<Operand> && HaveInput(Binding::kArgInfo) &&
+                  Operand::kUsage != device_arch_info::kUse) {
+      ins.push_back("\"" + std::to_string(register_numbers[arg_counter]) + "\"(in" +
+                    std::to_string(Binding::kArgInfo.from) +
+                    (NeedInputShadow<IntrinsicBindingInfo, Binding, Operand>() ? "_shadow)" : ")"));
     }
+    ++arg_counter;
   });
-  GenerateElementsList<AsmCallInfo>(out, indent, "  : ", "", ins);
+  GenerateElementsList<IntrinsicBindingInfo>(out, indent, "  : ", "", ins);
 }
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateOutShadows(FILE* out, int indent) {
-  AsmCallInfo::ProcessBindings([out, indent](auto arg) {
-    using RegisterClass = typename decltype(arg)::RegisterClass;
-    if constexpr (RegisterClass::kAsRegister == 'r') {
+  IntrinsicBindingInfo::ProcessBindings([out, indent]<typename Binding, typename Operand> {
+    using RegisterClass = Operand::Class;
+    if constexpr (device_arch_info::kIsFLAGS<Operand>) {
+      // Flags don't require shadows.
+    } else if constexpr (RegisterClass::kAsRegister == 'r') {
       // TODO(b/138439904): remove when clang handling of 'r' constraint would be fixed.
-      if constexpr (HaveOutput(arg.arg_info)) {
-        using Type = std::tuple_element_t<arg.arg_info.to, typename AsmCallInfo::OutputArguments>;
+      if constexpr (HaveOutput(Binding::kArgInfo)) {
+        using Type = std::tuple_element_t<Binding::kArgInfo.to,
+                                          typename IntrinsicBindingInfo::OutputArguments>;
         if constexpr (sizeof(Type) == sizeof(uint8_t)) {
-          fprintf(out, "%2$*1$sout%3$d = out%3$d_shadow;\n", indent, "", arg.arg_info.to);
+          fprintf(out, "%2$*1$sout%3$d = out%3$d_shadow;\n", indent, "", Binding::kArgInfo.to);
         }
       }
     } else if constexpr (RegisterClass::kAsRegister == 'x') {
-      if constexpr (HaveOutput(arg.arg_info)) {
-        using Type = std::tuple_element_t<arg.arg_info.to, typename AsmCallInfo::OutputArguments>;
+      if constexpr (HaveOutput(Binding::kArgInfo)) {
+        using Type = std::tuple_element_t<Binding::kArgInfo.to,
+                                          typename IntrinsicBindingInfo::OutputArguments>;
         const char* type_name = TypeTraits<Type>::kName;
         const char* xmm_type_name;
         // {,u}int32_t and {,u}int64_t have to be converted to float/double.
@@ -439,14 +438,14 @@ void GenerateOutShadows(FILE* out, int indent) {
                 "%2$*1$smemcpy(&out%3$d, &out%3$d_shadow, sizeof(%4$s));\n",
                 indent,
                 "",
-                arg.arg_info.to,
+                Binding::kArgInfo.to,
                 xmm_type_name);
       }
     }
   });
 }
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 void GenerateElementsList(FILE* out,
                           int indent,
                           const std::string& prefix,
@@ -474,18 +473,18 @@ void GenerateElementsList(FILE* out,
   fprintf(out, "%s\n", suffix.c_str());
 }
 
-template <typename AsmCallInfo, typename Arg>
-constexpr bool NeedInputShadow(Arg arg) {
-  using RegisterClass = typename Arg::RegisterClass;
+template <typename IntrinsicBindingInfo, typename Binding, typename Operand>
+constexpr bool NeedInputShadow() {
+  using RegisterClass = Operand::Class;
   // Without shadow clang silently converts 'r' restriction into 'q' restriction which
   // is wrong: if %ah or %bh is picked we would produce incorrect result here.
   // TODO(b/138439904): remove when clang handling of 'r' constraint would be fixed.
-  if constexpr (RegisterClass::kAsRegister == 'r' && HaveInput(arg.arg_info)) {
+  if constexpr (RegisterClass::kAsRegister == 'r' && HaveInput(Binding::kArgInfo)) {
     // Only 8-bit registers are special because each 16-bit registers include two of them
     // (%al/%ah, %cl/%ch, %dl/%dh, %bl/%bh).
     // Mix of 16-bit and 64-bit registers doesn't trigger bug in Clang.
-    if constexpr (sizeof(std::tuple_element_t<arg.arg_info.from,
-                                              typename AsmCallInfo::InputArguments>) ==
+    if constexpr (sizeof(std::tuple_element_t<Binding::kArgInfo.from,
+                                              typename IntrinsicBindingInfo::InputArguments>) ==
                   sizeof(uint8_t)) {
       return true;
     }
@@ -495,18 +494,18 @@ constexpr bool NeedInputShadow(Arg arg) {
   return false;
 }
 
-template <typename AsmCallInfo, typename Arg>
-constexpr bool NeedOutputShadow(Arg arg) {
-  using RegisterClass = typename Arg::RegisterClass;
+template <typename IntrinsicBindingInfo, typename Binding, typename Operand>
+constexpr bool NeedOutputShadow() {
+  using RegisterClass = Operand::Class;
   // Without shadow clang silently converts 'r' restriction into 'q' restriction which
   // is wrong: if %ah or %bh is picked we would produce incorrect result here.
   // TODO(b/138439904): remove when clang handling of 'r' constraint would be fixed.
-  if constexpr (RegisterClass::kAsRegister == 'r' && HaveOutput(arg.arg_info)) {
+  if constexpr (RegisterClass::kAsRegister == 'r' && HaveOutput(Binding::kArgInfo)) {
     // Only 8-bit registers are special because each some 16-bit registers include two of
     // them (%al/%ah, %cl/%ch, %dl/%dh, %bl/%bh).
     // Mix of 16-bit and 64-bit registers don't trigger bug in Clang.
-    if constexpr (sizeof(std::tuple_element_t<arg.arg_info.to,
-                                              typename AsmCallInfo::OutputArguments>) ==
+    if constexpr (sizeof(std::tuple_element_t<Binding::kArgInfo.to,
+                                              typename IntrinsicBindingInfo::OutputArguments>) ==
                   sizeof(uint8_t)) {
       return true;
     }
@@ -518,32 +517,36 @@ constexpr bool NeedOutputShadow(Arg arg) {
 
 #include "text_asm_intrinsics_process_bindings-inl.h"
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo>
 constexpr void VerifyIntrinsic() {
-  int register_numbers[std::tuple_size_v<typename AsmCallInfo::Bindings> == 0
+  int register_numbers[std::tuple_size_v<typename IntrinsicBindingInfo::Bindings> == 0
                            ? 1
-                           : std::tuple_size_v<typename AsmCallInfo::Bindings>];
-  AssignRegisterNumbers<AsmCallInfo>(register_numbers);
+                           : std::tuple_size_v<typename IntrinsicBindingInfo::Bindings>];
+  AssignRegisterNumbers<IntrinsicBindingInfo>(register_numbers);
   MacroAssembler<VerifierAssembler> as;
-  CallVerifierAssembler<AsmCallInfo, MacroAssembler<VerifierAssembler>>(&as, register_numbers);
+  CallVerifierAssembler<IntrinsicBindingInfo, MacroAssembler<VerifierAssembler>>(&as,
+                                                                                 register_numbers);
   // Verify CPU vendor and SSE restrictions.
-  as.CheckCPUIDRestriction<typename AsmCallInfo::CPUIDRestriction>();
+  as.CheckCPUIDRestriction<typename IntrinsicBindingInfo::CPUIDRestriction>();
 
   // Verify that intrinsic's bindings correctly states that intrinsic uses/doesn't use FLAGS
   // register.
-  bool expect_flags = false;
-  CheckIntrinsicHasFlagsBinding<AsmCallInfo>(expect_flags);
+  bool expect_flags = CheckIntrinsicHasFlagsBinding<IntrinsicBindingInfo>();
   as.CheckFlagsBinding(expect_flags);
   as.CheckAppropriateDefEarlyClobbers();
+  if (sizeof(MacroAssembler<VerifierAssembler>::AddressType) == sizeof(int64_t)) {
+    Check32BitRegistersAreZeroExtended<IntrinsicBindingInfo, MacroAssembler<VerifierAssembler>>(
+        &as);
+  }
   as.CheckLabelsAreBound();
+  as.CheckNonLinearIntrinsicsUseDefRegisters();
 }
 
 constexpr bool VerifyTextAsmIntrinsics() {
-  ProcessAllBindings<MacroAssembler<VerifierAssembler>::MacroAssemblers>(
-      [](auto&& asm_call_generator) {
-        using AsmCallInfo = std::decay_t<decltype(asm_call_generator)>;
-        VerifyIntrinsic<AsmCallInfo>();
-      });
+  ProcessAllBindings<MacroAssembler<VerifierAssembler>::Assemblers>([](auto&& asm_call_generator) {
+    using IntrinsicBindingInfo = std::decay_t<decltype(asm_call_generator)>;
+    VerifyIntrinsic<IntrinsicBindingInfo>();
+  });
   return true;
 }
 
@@ -560,13 +563,14 @@ void GenerateTextAsmIntrinsics(FILE* out) {
   const char* cpuid_restriction = nullptr /* NoCPUIDRestriction */;
   bool if_opened = false;
   std::string running_name;
-  ProcessAllBindings<MacroAssembler<TextAssembler>::MacroAssemblers>(
+  ProcessAllBindings<MacroAssembler<TextAssembler>::Assemblers>(
       [&running_name, &if_opened, &cpuid_restriction, out](auto&& asm_call_generator) {
-        using AsmCallInfo = std::decay_t<decltype(asm_call_generator)>;
+        using IntrinsicBindingInfo = std::decay_t<decltype(asm_call_generator)>;
         std::string full_name = std::string(asm_call_generator.kIntrinsic,
                                             std::strlen(asm_call_generator.kIntrinsic) - 1) +
                                 ", kUseCppImplementation>";
-        if (size_t arguments_count = std::tuple_size_v<typename AsmCallInfo::InputArguments>) {
+        if (size_t arguments_count =
+                std::tuple_size_v<typename IntrinsicBindingInfo::InputArguments>) {
           full_name += "(in0";
           for (size_t i = 1; i < arguments_count; ++i) {
             full_name += ", in" + std::to_string(i);
@@ -588,13 +592,13 @@ void GenerateTextAsmIntrinsics(FILE* out) {
           if (!running_name.empty()) {
             fprintf(out, "};\n\n");
           }
-          GenerateFunctionHeader<AsmCallInfo>(out, 0);
+          GenerateFunctionHeader<IntrinsicBindingInfo>(out, 0);
           running_name = full_name;
         }
-        using CPUIDRestriction = AsmCallInfo::CPUIDRestriction;
+        using CPUIDRestriction = IntrinsicBindingInfo::CPUIDRestriction;
         // Note: this series of "if constexpr" expressions is the only place where cpuid_restriction
         // may get a concrete non-zero value;
-        if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::NoCPUIDRestriction>) {
+        if constexpr (std::is_same_v<CPUIDRestriction, device_arch_info::NoCPUIDRestriction>) {
           if (cpuid_restriction) {
             fprintf(out, "  } else {\n");
             cpuid_restriction = nullptr;
@@ -609,7 +613,7 @@ void GenerateTextAsmIntrinsics(FILE* out) {
           cpuid_restriction = TextAssembler::kCPUIDRestrictionString<CPUIDRestriction>;
           fprintf(out, "%s) {\n", cpuid_restriction);
         }
-        GenerateFunctionBody<AsmCallInfo>(out, 2 + 2 * if_opened);
+        GenerateFunctionBody<IntrinsicBindingInfo>(out, 2 + 2 * if_opened);
       });
   if (if_opened) {
     fprintf(out, "  }\n");
@@ -649,7 +653,7 @@ int main(int argc, char* argv[]) {
 #define %2$s_%3$s_INTRINSICS_INTRINSICS_H_
 
 #if defined(__i386__) || defined(__x86_64__)
-#include <xmmintrin.h>
+#include <x86intrin.h>
 #endif
 
 #include "berberis/base/config.h"
diff --git a/intrinsics/include/berberis/intrinsics/common/intrinsics.h b/intrinsics/include/berberis/intrinsics/common/intrinsics.h
index 6550bc94..71dced30 100644
--- a/intrinsics/include/berberis/intrinsics/common/intrinsics.h
+++ b/intrinsics/include/berberis/intrinsics/common/intrinsics.h
@@ -18,6 +18,7 @@
 #define BERBERIS_INTRINSICS_COMMON_INTRINSICS_H_
 
 #include <cstdint>
+#include <type_traits>
 
 #include "berberis/base/checks.h"
 #include "berberis/base/dependent_false.h"
@@ -221,6 +222,18 @@ DEFINE_VALUE_OPERATOR(||)
 
 #pragma pop_macro("DEFINE_VALUE_OPERATOR")
 
+// Note: this is very simple demultiplexer and it's NOT guaranteed to always work (especially if
+// someone would use it with more than 8 parameters), but it would start producing collisions then
+// we wouldn't really have any runtime issues because we use these values in a switch – and in C++
+// an attempt to have to different case's in a switch is a compile-time error.
+template <typename... Param>
+constexpr int TrivialDemultiplexer(Param... param) {
+  int variant_index = 0;
+  int index = 0;
+  ((variant_index ^= param << index, index += 4), ...);
+  return variant_index;
+}
+
 // A solution for the inability to call generic implementation from specialization.
 // Declaration:
 //   template <typename Type,
diff --git a/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h b/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h
index 637912b3..e0868c6c 100644
--- a/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h
+++ b/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h
@@ -20,6 +20,8 @@
 #include <cstdint>
 
 #include "berberis/base/dependent_false.h"
+#include "berberis/base/string_literal.h"
+#include "berberis/device_arch_info/common/device_arch_info.h"
 #include "berberis/intrinsics/intrinsics_args.h"
 #include "berberis/intrinsics/type_traits.h"
 
@@ -27,265 +29,179 @@ namespace berberis {
 
 namespace intrinsics::bindings {
 
-class FLAGS {
- public:
-  static constexpr bool kIsImmediate = false;
-  static constexpr bool kIsImplicitReg = true;
-  static constexpr char kAsRegister = 0;
-  template <typename MachineInsnArch>
-  static constexpr auto kRegClass = MachineInsnArch::kFLAGS;
-};
-
-class Mem8 {
- public:
-  using Type = uint8_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr char kAsRegister = 'm';
-};
-
-class Mem16 {
- public:
-  using Type = uint16_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr char kAsRegister = 'm';
-};
-
-class Mem32 {
- public:
-  using Type = uint32_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr char kAsRegister = 'm';
-};
-
-class Mem64 {
- public:
-  using Type = uint64_t;
-  static constexpr bool kIsImmediate = false;
-  static constexpr char kAsRegister = 'm';
-};
-
-// Tag classes. They are never instantioned, only used as tags to pass information about
-// bindings.
-class Def;
-class DefEarlyClobber;
-class Use;
-class UseDef;
-
-template <typename Tag, typename MachineRegKind>
-constexpr auto ToRegKind() {
-  if constexpr (std::is_same_v<Tag, Def>) {
-    return MachineRegKind::kDef;
-  } else if constexpr (std::is_same_v<Tag, DefEarlyClobber>) {
-    return MachineRegKind::kDefEarlyClobber;
-  } else if constexpr (std::is_same_v<Tag, Use>) {
-    return MachineRegKind::kUse;
-  } else if constexpr (std::is_same_v<Tag, UseDef>) {
-    return MachineRegKind::kUseDef;
-  } else {
-    static_assert(kDependentTypeFalse<Tag>);
-  }
-}
-
-template <typename Tag, typename MachineRegKind>
-inline constexpr auto kRegKind = ToRegKind<Tag, MachineRegKind>();
-
-enum RegBindingKind { kDef, kDefEarlyClobber, kUse, kUseDef, kUndefined };
-
-// Tag classes. They are never instantioned, only used as tags to pass information about
-// bindings.
-class NoCPUIDRestriction;  // All CPUs have at least “no CPUID restriction” mode.
-
 // Tag classes. They are never instantioned, only used as tags to pass information about
 // bindings.
 class NoNansOperation;
 class PreciseNanOperationsHandling;
 class ImpreciseNanOperationsHandling;
 
-template <auto kIntrinsicTemplateName,
-          auto kMacroInstructionTemplateName,
-          auto kMnemo,
-          typename GetOpcode,
-          typename CPUIDRestrictionTemplateValue,
-          typename PreciseNanOperationsHandlingTemplateValue,
-          bool kSideEffectsTemplateValue,
-          typename... Types>
-class AsmCallInfo;
+template <StringLiteral kIntrinsic, typename... Types>
+class IntrinsicBindingInfo;
 
-template <auto kIntrinsicTemplateName,
-          auto kMacroInstructionTemplateName,
-          auto kMnemo,
-          typename GetOpcode,
-          typename CPUIDRestrictionTemplateValue,
-          typename PreciseNanOperationsHandlingTemplateValue,
-          bool kSideEffectsTemplateValue,
+template <StringLiteral kIntrinsic_,
+          auto kEmitInsnFunc_,
+          StringLiteral kMnemo,
+          auto GetOpcode,
+          typename CPUIDRestriction_,
+          typename PreciseNanOperationsHandling_,
+          bool kSideEffects_,
           typename... InputArgumentsTypes,
           typename... OutputArgumentsTypes,
-          typename... BindingsTypes>
-class AsmCallInfo<kIntrinsicTemplateName,
-                  kMacroInstructionTemplateName,
-                  kMnemo,
-                  GetOpcode,
-                  CPUIDRestrictionTemplateValue,
-                  PreciseNanOperationsHandlingTemplateValue,
-                  kSideEffectsTemplateValue,
-                  std::tuple<InputArgumentsTypes...>,
-                  std::tuple<OutputArgumentsTypes...>,
-                  BindingsTypes...>
+          typename... BindingsTypes,
+          typename... OperandsTypes>
+class IntrinsicBindingInfo<kIntrinsic_,
+                           PreciseNanOperationsHandling_,
+                           std::tuple<InputArgumentsTypes...>,
+                           std::tuple<OutputArgumentsTypes...>,
+                           std::tuple<BindingsTypes...>,
+                           device_arch_info::DeviceInsnInfo<kEmitInsnFunc_,
+                                                            kMnemo,
+                                                            kSideEffects_,
+                                                            GetOpcode,
+                                                            CPUIDRestriction_,
+                                                            std::tuple<OperandsTypes...>>>
     final {
  public:
-  static constexpr auto kIntrinsic = kIntrinsicTemplateName;
-  static constexpr auto kMacroInstruction = kMacroInstructionTemplateName;
-  // TODO(b/260725458): Use lambda template argument after C++20 becomes available.
+  static constexpr auto kIntrinsic = kIntrinsic_;
+  static constexpr auto kEmitInsnFunc = kEmitInsnFunc_;
   template <typename Opcode>
-  static constexpr auto kOpcode = GetOpcode{}.template operator()<Opcode>();
-  using CPUIDRestriction = CPUIDRestrictionTemplateValue;
-  using PreciseNanOperationsHandling = PreciseNanOperationsHandlingTemplateValue;
-  static constexpr bool kSideEffects = kSideEffectsTemplateValue;
+  static constexpr auto kOpcode = GetOpcode.template operator()<Opcode>();
+  using CPUIDRestriction = CPUIDRestriction_;
+  using PreciseNanOperationsHandling = PreciseNanOperationsHandling_;
+  static constexpr bool kSideEffects = kSideEffects_;
   static constexpr const char* InputArgumentsTypeNames[] = {
       TypeTraits<InputArgumentsTypes>::kName...};
   static constexpr const char* OutputArgumentsTypeNames[] = {
       TypeTraits<OutputArgumentsTypes>::kName...};
   template <typename Callback, typename... Args>
   constexpr static void ProcessBindings(Callback&& callback, Args&&... args) {
-    (callback(ArgTraits<BindingsTypes>(), std::forward<Args>(args)...), ...);
+    (callback.template operator()<BindingsTypes, OperandsTypes>(std::forward<Args>(args)...), ...);
   }
   template <typename Callback, typename... Args>
   constexpr static bool VerifyBindings(Callback&& callback, Args&&... args) {
-    return (callback(ArgTraits<BindingsTypes>(), std::forward<Args>(args)...) && ...);
+    return (
+        callback.template operator()<BindingsTypes, OperandsTypes>(std::forward<Args>(args)...) &&
+        ...);
   }
   template <typename Callback, typename... Args>
   constexpr static auto MakeTuplefromBindings(Callback&& callback, Args&&... args) {
-    return std::tuple_cat(callback(ArgTraits<BindingsTypes>(), std::forward<Args>(args)...)...);
+    return std::tuple_cat(
+        callback.template operator()<BindingsTypes, OperandsTypes>(std::forward<Args>(args)...)...);
   }
   using InputArguments = std::tuple<InputArgumentsTypes...>;
   using OutputArguments = std::tuple<OutputArgumentsTypes...>;
   using Bindings = std::tuple<BindingsTypes...>;
+  using Operands = std::tuple<OperandsTypes...>;
   using IntrinsicType = std::conditional_t<std::tuple_size_v<OutputArguments> == 0,
                                            void (*)(InputArgumentsTypes...),
                                            OutputArguments (*)(InputArgumentsTypes...)>;
-  template <template <typename, auto, auto, typename...> typename MachineInsnType,
-            template <typename...>
-            typename ConstructorArgs,
-            typename Opcode>
-  using MachineInsn = MachineInsnType<AsmCallInfo,
-                                      kMnemo,
-                                      kOpcode<Opcode>,
-                                      ConstructorArgs<BindingsTypes...>,
-                                      BindingsTypes...>;
+  using DeviceInsnInfo = device_arch_info::
+      DeviceInsnInfo<kEmitInsnFunc, kMnemo, kSideEffects_, GetOpcode, CPUIDRestriction, Operands>;
 };
 
 }  // namespace intrinsics::bindings
 
-template <typename AsmCallInfo>
+template <typename IntrinsicBindingInfo, typename AssemblerType>
+constexpr void Check32BitRegistersAreZeroExtended(AssemblerType* as) {
+  int id = 0;
+  IntrinsicBindingInfo::ProcessBindings([&as, &id]<typename Binding, typename Operand> {
+    if constexpr (!device_arch_info::kIsImmediate<Operand> &&
+                  !device_arch_info::kIsFLAGS<Operand>) {
+      if constexpr (HaveOutput(Binding::kArgInfo)) {
+        static_assert(Operand::kUsage != device_arch_info::kUse);
+        if constexpr (device_arch_info::kIsGeneralReg32<Operand>) {
+          as->Check32BitRegisterIsZeroExtended(id);
+        }
+        id++;
+      }
+    }
+  });
+}
+
+template <typename IntrinsicBindingInfo>
 constexpr void AssignRegisterNumbers(int* register_numbers) {
   // Assign number for output (and temporary) arguments.
   std::size_t id = 0;
   int arg_counter = 0;
-  AsmCallInfo::ProcessBindings([&id, &arg_counter, &register_numbers](auto arg) {
-    if constexpr (!IsImmediate(decltype(arg)::arg_info)) {
-      using RegisterClass = typename decltype(arg)::RegisterClass;
-      if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-        if constexpr (!std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::Use>) {
-          register_numbers[arg_counter] = id++;
+  IntrinsicBindingInfo::ProcessBindings(
+      [&id, &arg_counter, &register_numbers]<typename Binding, typename Operand> {
+        if constexpr (!device_arch_info::kIsImmediate<Operand> &&
+                      !device_arch_info::kIsFLAGS<Operand>) {
+          if constexpr (Operand::kUsage != device_arch_info::kUse) {
+            register_numbers[arg_counter] = id++;
+          }
+          ++arg_counter;
         }
-        ++arg_counter;
-      }
-    }
-  });
+      });
   // Assign numbers for input arguments.
   arg_counter = 0;
-  AsmCallInfo::ProcessBindings([&id, &arg_counter, &register_numbers](auto arg) {
-    if constexpr (!IsImmediate(decltype(arg)::arg_info)) {
-      using RegisterClass = typename decltype(arg)::RegisterClass;
-      if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-        if constexpr (std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::Use>) {
-          register_numbers[arg_counter] = id++;
+  IntrinsicBindingInfo::ProcessBindings(
+      [&id, &arg_counter, &register_numbers]<typename Binding, typename Operand> {
+        if constexpr (!device_arch_info::kIsImmediate<Operand> &&
+                      !device_arch_info::kIsFLAGS<Operand>) {
+          if constexpr (Operand::kUsage == device_arch_info::kUse) {
+            register_numbers[arg_counter] = id++;
+          }
+          ++arg_counter;
         }
-        ++arg_counter;
-      }
-    }
-  });
+      });
 }
 
-template <typename AsmCallInfo>
-constexpr void CheckIntrinsicHasFlagsBinding(bool& expect_flags) {
-  AsmCallInfo::ProcessBindings([&expect_flags](auto arg) {
-    if constexpr (!IsImmediate(decltype(arg)::arg_info)) {
-      using RegisterClass = typename decltype(arg)::RegisterClass;
-      if constexpr (std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-        expect_flags = true;
-      }
+template <typename DeviceInsnInfo>
+constexpr bool CheckIntrinsicHasFlagsBinding() {
+  bool expect_flags = false;
+  DeviceInsnInfo::ProcessBindings([&expect_flags]<typename Binding, typename Operand> {
+    if constexpr (device_arch_info::kIsFLAGS<Operand>) {
+      expect_flags = true;
     }
   });
+  return expect_flags;
 }
 
-template <typename AsmCallInfo, typename AssemblerType>
+template <typename IntrinsicBindingInfo, typename AssemblerType>
 constexpr void CallVerifierAssembler(AssemblerType* as, int* register_numbers) {
   int arg_counter = 0;
-  AsmCallInfo::ProcessBindings([&arg_counter, &as, register_numbers](auto arg) {
-    if constexpr (!IsImmediate(decltype(arg)::arg_info)) {
-      using RegisterClass = typename decltype(arg)::RegisterClass;
-      if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-        if constexpr (RegisterClass::kAsRegister != 'm') {
-          if constexpr (RegisterClass::kIsImplicitReg) {
-            if constexpr (RegisterClass::kAsRegister == 'a') {
-              as->gpr_a = typename AssemblerType::Register(
-                  register_numbers[arg_counter],
-                  intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
-                                                  intrinsics::bindings::RegBindingKind>());
-            } else if constexpr (RegisterClass::kAsRegister == 'b') {
-              as->gpr_b = typename AssemblerType::Register(
-                  register_numbers[arg_counter],
-                  intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
-                                                  intrinsics::bindings::RegBindingKind>());
-            } else if constexpr (RegisterClass::kAsRegister == 'c') {
-              as->gpr_c = typename AssemblerType::Register(
-                  register_numbers[arg_counter],
-                  intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
-                                                  intrinsics::bindings::RegBindingKind>());
-            } else {
-              static_assert(RegisterClass::kAsRegister == 'd');
-              as->gpr_d = typename AssemblerType::Register(
-                  register_numbers[arg_counter],
-                  intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
-                                                  intrinsics::bindings::RegBindingKind>());
-            }
-          }
+  IntrinsicBindingInfo::ProcessBindings(
+      [&arg_counter, &as, register_numbers]<typename Binding, typename Operand> {
+        if constexpr (device_arch_info::kIsImplicitReg<Operand> &&
+                      !device_arch_info::kIsFLAGS<Operand>) {
+          as->*(Operand::Class::template kAssemblerRegisterPointer<AssemblerType>) =
+              typename AssemblerType::Register{register_numbers[arg_counter], Operand::kUsage};
         }
         ++arg_counter;
-      }
-    }
-  });
-  as->gpr_macroassembler_constants = typename AssemblerType::Register(arg_counter);
+      });
+  // Macroassembler constants register points to the constant pool. Intrinsics can read from it
+  // but shouldn't change it's address, that's why it's always kUse.
+  as->gpr_macroassembler_constants =
+      typename AssemblerType::Register{arg_counter, device_arch_info::kUse};
   arg_counter = 0;
   int scratch_counter = 0;
   std::apply(
-      AsmCallInfo::kMacroInstruction,
+      IntrinsicBindingInfo::kEmitInsnFunc,
       std::tuple_cat(
           std::tuple<AssemblerType&>{*as},
-          AsmCallInfo::MakeTuplefromBindings([&as,
-                                              &arg_counter,
-                                              &scratch_counter,
-                                              register_numbers](auto arg) {
-            if constexpr (IsImmediate(decltype(arg)::arg_info)) {
-              // TODO(b/394278175): We don't have access to the value of the immediate argument
-              // here. The value of the immediate argument often decides which instructions in
-              // an intrinsic are called, by being used in conditional statements. We need to
-              // make sure that all possible instructions in the intrinsic are executed when
-              // using VerifierAssembler on inline-only intrinsics. For now, we set immediate
-              // argument to 2, since it generally covers most instructions in inline-only
-              // intrinsics.
-              return std::tuple{2};
-            } else {
-              using RegisterClass = typename decltype(arg)::RegisterClass;
-              if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-                if constexpr (RegisterClass::kAsRegister == 'm') {
+          IntrinsicBindingInfo::MakeTuplefromBindings(
+              [&as,
+               &arg_counter,
+               &scratch_counter,
+               register_numbers]<typename Binding, typename Operand> {
+                if constexpr (device_arch_info::kIsImmediate<Operand>) {
+                  // TODO(b/394278175): We don't have access to the value of the immediate argument
+                  // here. The value of the immediate argument often decides which instructions in
+                  // an intrinsic are called, by being used in conditional statements. We need to
+                  // make sure that all possible instructions in the intrinsic are executed when
+                  // using VerifierAssembler on inline-only intrinsics. For now, we set immediate
+                  // argument to 2, since it generally covers most instructions in inline-only
+                  // intrinsics.
+                  return std::tuple{2};
+                } else if constexpr (device_arch_info::kIsMemoryOperand<Operand>) {
+                  static_assert(Operand::kUsage == device_arch_info::kDefEarlyClobber);
                   if (scratch_counter == 0) {
-                    as->gpr_macroassembler_scratch =
-                        typename AssemblerType::Register(arg_counter++);
+                    as->gpr_macroassembler_scratch = typename AssemblerType::Register(
+                        arg_counter++, device_arch_info::kDefEarlyClobber);
                   } else if (scratch_counter == 1) {
-                    as->gpr_macroassembler_scratch2 =
-                        typename AssemblerType::Register(arg_counter++);
+                    as->gpr_macroassembler_scratch2 = typename AssemblerType::Register(
+                        arg_counter++, device_arch_info::kDefEarlyClobber);
                   } else {
                     FATAL("Only two scratch registers are supported for now");
                   }
@@ -296,30 +212,29 @@ constexpr void CallVerifierAssembler(AssemblerType* as, int* register_numbers) {
                       .base = as->gpr_scratch,
                       .disp =
                           static_cast<int32_t>(config::kScratchAreaSlotSize * scratch_counter++)}};
-                } else if constexpr (RegisterClass::kIsImplicitReg) {
-                  ++arg_counter;
-                  return std::tuple{};
                 } else {
-                  if constexpr (RegisterClass::kAsRegister == 'q' ||
-                                RegisterClass::kAsRegister == 'r') {
-                    return std::tuple{typename AssemblerType::Register(
-                        register_numbers[arg_counter++],
-                        intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
-                                                        intrinsics::bindings::RegBindingKind>())};
-                  } else if constexpr (RegisterClass::kAsRegister == 'x') {
-                    return std::tuple{typename AssemblerType::XRegister(
-                        register_numbers[arg_counter++],
-                        intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
-                                                        intrinsics::bindings::RegBindingKind>())};
+                  if constexpr (!device_arch_info::kIsFLAGS<Operand>) {
+                    if constexpr (device_arch_info::kIsImplicitReg<Operand>) {
+                      ++arg_counter;
+                      return std::tuple{};
+                    } else {
+                      using RegisterClass = Operand::Class;
+                      if constexpr (RegisterClass::kAsRegister == 'q' ||
+                                    RegisterClass::kAsRegister == 'r') {
+                        return std::tuple{typename AssemblerType::Register{
+                            register_numbers[arg_counter++], Operand::kUsage}};
+                      } else if constexpr (RegisterClass::kAsRegister == 'x') {
+                        return std::tuple{typename AssemblerType::XRegister{
+                            register_numbers[arg_counter++], Operand::kUsage}};
+                      } else {
+                        static_assert(kDependentValueFalse<RegisterClass::kAsRegister>);
+                      }
+                    }
                   } else {
-                    static_assert(kDependentValueFalse<RegisterClass::kAsRegister>);
+                    return std::tuple{};
                   }
                 }
-              } else {
-                return std::tuple{};
-              }
-            }
-          })));
+              })));
 }
 
 }  // namespace berberis
diff --git a/intrinsics/include/berberis/intrinsics/intrinsics_args.h b/intrinsics/include/berberis/intrinsics/intrinsics_args.h
index aa0ff66f..a1a79f0f 100644
--- a/intrinsics/include/berberis/intrinsics/intrinsics_args.h
+++ b/intrinsics/include/berberis/intrinsics/intrinsics_args.h
@@ -118,102 +118,51 @@ struct ArgInfo {
   const int to = 0;
 };
 
-template <int N, typename RegisterClass = void, typename Usage = void>
-class InArg;
-
-template <int N, typename RegisterClass = void, typename Usage = void>
-class OutArg;
-
-template <int N, typename RegisterClass = void, typename Usage = void>
-class OutTmpArg;
-
-template <int N, int M, typename RegisterClass = void, typename Usage = void>
-class InOutArg;
-
-template <int N, int M, typename RegisterClass = void, typename Usage = void>
-class InOutTmpArg;
-
-template <int N, typename RegisterClass = void, typename Usage = void>
-class InTmpArg;
-
-template <int N, typename ImmType, typename ImmediateClass = void>
-class ImmArg;
-
-template <typename RegisterClass = void, typename Usage = void>
-class TmpArg;
-
-template <typename ArgInfo>
-class ArgTraits;
-
-template <int N, typename RegisterClassType, typename UsageType>
-class ArgTraits<InArg<N, RegisterClassType, UsageType>> {
+template <int N>
+class InArg {
  public:
-  using Class = RegisterClassType;
-  using RegisterClass = RegisterClassType;
-  using Usage = UsageType;
-  static constexpr ArgInfo arg_info{.arg_type = ArgInfo::IN_ARG, .from = N};
+  static constexpr ArgInfo kArgInfo{.arg_type = ArgInfo::IN_ARG, .from = N};
 };
 
-template <int N, typename RegisterClassType, typename UsageType>
-class ArgTraits<OutArg<N, RegisterClassType, UsageType>> {
+template <int N>
+class OutArg {
  public:
-  using Class = RegisterClassType;
-  using RegisterClass = RegisterClassType;
-  using Usage = UsageType;
-  static constexpr ArgInfo arg_info{.arg_type = ArgInfo::OUT_ARG, .to = N};
+  static constexpr ArgInfo kArgInfo{.arg_type = ArgInfo::OUT_ARG, .to = N};
 };
 
-template <int N, typename RegisterClassType, typename UsageType>
-class ArgTraits<OutTmpArg<N, RegisterClassType, UsageType>> {
+template <int N>
+class OutTmpArg {
  public:
-  using Class = RegisterClassType;
-  using RegisterClass = RegisterClassType;
-  using Usage = UsageType;
-  static constexpr ArgInfo arg_info{.arg_type = ArgInfo::OUT_TMP_ARG, .to = N};
+  static constexpr ArgInfo kArgInfo{.arg_type = ArgInfo::OUT_TMP_ARG, .to = N};
 };
 
-template <int N, int M, typename RegisterClassType, typename UsageType>
-class ArgTraits<InOutArg<N, M, RegisterClassType, UsageType>> {
+template <int N, int M>
+class InOutArg {
  public:
-  using Class = RegisterClassType;
-  using RegisterClass = RegisterClassType;
-  using Usage = UsageType;
-  static constexpr ArgInfo arg_info{.arg_type = ArgInfo::IN_OUT_ARG, .from = N, .to = M};
+  static constexpr ArgInfo kArgInfo{.arg_type = ArgInfo::IN_OUT_ARG, .from = N, .to = M};
 };
 
-template <int N, int M, typename RegisterClassType, typename UsageType>
-class ArgTraits<InOutTmpArg<N, M, RegisterClassType, UsageType>> {
+template <int N, int M>
+class InOutTmpArg {
  public:
-  using Class = RegisterClassType;
-  using RegisterClass = RegisterClassType;
-  using Usage = UsageType;
-  static constexpr ArgInfo arg_info{.arg_type = ArgInfo::IN_OUT_TMP_ARG, .from = N, .to = M};
+  static constexpr ArgInfo kArgInfo{.arg_type = ArgInfo::IN_OUT_TMP_ARG, .from = N, .to = M};
 };
 
-template <int N, typename RegisterClassType, typename UsageType>
-class ArgTraits<InTmpArg<N, RegisterClassType, UsageType>> {
+template <int N>
+class InTmpArg {
  public:
-  using Class = RegisterClassType;
-  using RegisterClass = RegisterClassType;
-  using Usage = UsageType;
-  static constexpr ArgInfo arg_info{.arg_type = ArgInfo::IN_TMP_ARG, .from = N};
+  static constexpr ArgInfo kArgInfo{.arg_type = ArgInfo::IN_TMP_ARG, .from = N};
 };
 
-template <int N, typename ImmType, typename ImmediateClassType>
-class ArgTraits<ImmArg<N, ImmType, ImmediateClassType>> {
+template <int N, typename ImmType = void>
+class ImmArg {
  public:
-  using Class = ImmediateClassType;
-  using ImmediateClass = ImmediateClassType;
-  static constexpr ArgInfo arg_info{.arg_type = ArgInfo::IMM_ARG, .from = N};
+  static constexpr ArgInfo kArgInfo{.arg_type = ArgInfo::IMM_ARG, .from = N};
 };
 
-template <typename RegisterClassType, typename UsageType>
-class ArgTraits<TmpArg<RegisterClassType, UsageType>> {
+class TmpArg {
  public:
-  using Class = RegisterClassType;
-  using RegisterClass = RegisterClassType;
-  using Usage = UsageType;
-  static constexpr ArgInfo arg_info{.arg_type = ArgInfo::TMP_ARG};
+  static constexpr ArgInfo kArgInfo{.arg_type = ArgInfo::TMP_ARG};
 };
 
 // We couldn't use standard "throw std::logic_error(...)" approach here because that code is
@@ -274,9 +223,9 @@ constexpr bool IsCompatible(const ArgInfo* arguments) {
   return true;
 }
 
-template <typename MachineInsn, typename... Args>
+template <typename MachineInsn, typename... Args, typename... Operands>
 constexpr bool IsCompatible() {
-  const ArgInfo arguments[] = {ArgTraits<Args>::arg_info...};
+  const ArgInfo arguments[] = {Args::kArgInfo...};
   // Note: we couldn't pass arguments as an array into IsCompatible by reference
   // because this would cause compilation error in case where we have no arguments.
   //
diff --git a/intrinsics/include/berberis/intrinsics/intrinsics_process_bindings.h b/intrinsics/include/berberis/intrinsics/intrinsics_process_bindings.h
index 4341f63d..ac38cc65 100644
--- a/intrinsics/include/berberis/intrinsics/intrinsics_process_bindings.h
+++ b/intrinsics/include/berberis/intrinsics/intrinsics_process_bindings.h
@@ -33,8 +33,8 @@ namespace berberis::intrinsics::bindings {
 template <auto kFunction>
 class FunctionCompareTag;
 
-#include "berberis/intrinsics/intrinsics_process_bindings-inl.h"
-
 }  // namespace berberis::intrinsics::bindings
 
+#include "berberis/intrinsics/intrinsics_process_bindings-inl.h"
+
 #endif  // BERBERIS_INTRINSICS_INTRINSICS_BINDINGS_H_
diff --git a/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
index 38617959..0e7d66c2 100644
--- a/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
+++ b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
@@ -1225,16 +1225,16 @@ DEFINE_2OP_ARITHMETIC_INTRINSIC_VX(mulhsu, auto [arg1, arg2] = std::tuple{args..
                                                  Widen(BitCastToUnsigned(arg2))))
 DEFINE_2OP_ARITHMETIC_INTRINSIC_VV(
     div,
-    ElementType{std::get<0>(Div(static_cast<typename ElementType::BaseType>(args)...))})
+    ElementType{std::get<0>(DivRiscV(static_cast<typename ElementType::BaseType>(args)...))})
 DEFINE_2OP_ARITHMETIC_INTRINSIC_VX(
     div,
-    ElementType{std::get<0>(Div(static_cast<typename ElementType::BaseType>(args)...))})
+    ElementType{std::get<0>(DivRiscV(static_cast<typename ElementType::BaseType>(args)...))})
 DEFINE_2OP_ARITHMETIC_INTRINSIC_VV(
     rem,
-    ElementType{std::get<0>(Rem(static_cast<typename ElementType::BaseType>(args)...))})
+    ElementType{std::get<0>(RemRiscV(static_cast<typename ElementType::BaseType>(args)...))})
 DEFINE_2OP_ARITHMETIC_INTRINSIC_VX(
     rem,
-    ElementType{std::get<0>(Rem(static_cast<typename ElementType::BaseType>(args)...))})
+    ElementType{std::get<0>(RemRiscV(static_cast<typename ElementType::BaseType>(args)...))})
 
 DEFINE_2OP_WIDEN_ARITHMETIC_INTRINSIC_VV(add, (args + ...))
 DEFINE_2OP_WIDEN_ARITHMETIC_INTRINSIC_VX(add, (args + ...))
diff --git a/intrinsics/riscv64_to_all/intrinsic_def.json b/intrinsics/riscv64_to_all/intrinsic_def.json
index 4288d861..2d81be34 100644
--- a/intrinsics/riscv64_to_all/intrinsic_def.json
+++ b/intrinsics/riscv64_to_all/intrinsic_def.json
@@ -17,16 +17,7 @@
   "Aadd": {
     "comment": "Averaging add (scalar).",
     "class": "template",
-    "variants": [
-      "int8_t",
-      "int16_t",
-      "int32_t",
-      "int64_t",
-      "uint8_t",
-      "uint16_t",
-      "uint32_t",
-      "uint64_t"
-    ],
+    "variants": [ "int32_t", "int64_t", "uint32_t", "uint64_t" ],
     "in": [ "int8_t", "Type0", "Type0" ],
     "out": [ "Type0" ]
   },
@@ -181,16 +172,7 @@
   "Asub": {
     "comment": "Averaging subtract (scalar).",
     "class": "template",
-    "variants": [
-      "int8_t",
-      "int16_t",
-      "int32_t",
-      "int64_t",
-      "uint8_t",
-      "uint16_t",
-      "uint32_t",
-      "uint64_t"
-    ],
+    "variants": [ "int32_t", "int64_t", "uint32_t", "uint64_t" ],
     "in": [ "int8_t", "Type0", "Type0" ],
     "out": [ "Type0" ]
   },
@@ -276,19 +258,10 @@
     "in": [ "Type0" ],
     "out": [ "int64_t" ]
   },
-  "Div": {
+  "DivRiscV": {
     "comment": "Integer division",
     "class": "template",
-    "variants": [
-      "int8_t",
-      "int16_t",
-      "int32_t",
-      "int64_t",
-      "uint8_t",
-      "uint16_t",
-      "uint32_t",
-      "uint64_t"
-    ],
+    "variants": [ "int32_t", "int64_t", "uint32_t", "uint64_t" ],
     "in": [ "Type0", "Type0" ],
     "out": [ "Type0" ]
   },
@@ -646,19 +619,10 @@
     "in": [ "uint64_t" ],
     "out": [ "uint64_t" ]
   },
-  "Rem": {
+  "RemRiscV": {
     "comment": "Integer remainder",
     "class": "template",
-    "variants": [
-      "int8_t",
-      "int16_t",
-      "int32_t",
-      "int64_t",
-      "uint8_t",
-      "uint16_t",
-      "uint32_t",
-      "uint64_t"
-    ],
+    "variants": [ "int32_t", "int64_t", "uint32_t", "uint64_t" ],
     "in": [ "Type0", "Type0" ],
     "out": [ "Type0" ]
   },
@@ -685,16 +649,7 @@
   "Roundoff": {
     "comment": "Fixed point conversion with rounding (but without narrowing).",
     "class": "template",
-    "variants": [
-      "int8_t",
-      "int16_t",
-      "int32_t",
-      "int64_t",
-      "uint8_t",
-      "uint16_t",
-      "uint32_t",
-      "uint64_t"
-    ],
+    "variants": [ "int32_t", "int64_t", "uint32_t", "uint64_t" ],
     "in": [ "int8_t", "Type0", "Type0" ],
     "out": [ "Type0" ]
   },
diff --git a/intrinsics/riscv64_to_all/intrinsics_test.cc b/intrinsics/riscv64_to_all/intrinsics_test.cc
index 839884b2..81ca48fa 100644
--- a/intrinsics/riscv64_to_all/intrinsics_test.cc
+++ b/intrinsics/riscv64_to_all/intrinsics_test.cc
@@ -72,35 +72,40 @@ TEST(Intrinsics, Asub) {
   Verify.operator()<uint8_t>(ROD);
 }
 
-TEST(Intrinsics, Div) {
-  ASSERT_EQ(std::get<0>(Div<int8_t>(int8_t{-128}, int8_t{0})), int8_t{-1});
-  ASSERT_EQ(std::get<0>(Div<int8_t>(int8_t{-128}, int8_t{-1})), int8_t{-128});
-  ASSERT_EQ(std::get<0>(Div<int8_t>(int8_t{-128}, int8_t{-2})), int8_t{64});
-  ASSERT_EQ(std::get<0>(Div<uint8_t>(uint8_t{128}, uint8_t{0})), uint8_t{255});
-  ASSERT_EQ(std::get<0>(Div<uint8_t>(uint8_t{128}, uint8_t{1})), uint8_t{128});
-  ASSERT_EQ(std::get<0>(Div<uint8_t>(uint8_t{128}, uint8_t{2})), uint8_t{64});
-  ASSERT_EQ(std::get<0>(Div<int16_t>(int16_t{-32768}, int16_t{0})), int16_t{-1});
-  ASSERT_EQ(std::get<0>(Div<int16_t>(int16_t{-32768}, int16_t{-1})), int16_t{-32768});
-  ASSERT_EQ(std::get<0>(Div<int16_t>(int16_t{-32768}, int16_t{-2})), int16_t{16384});
-  ASSERT_EQ(std::get<0>(Div<uint16_t>(uint16_t{32768}, uint16_t{0})), uint16_t{65535});
-  ASSERT_EQ(std::get<0>(Div<uint16_t>(uint16_t{32768}, uint16_t{1})), uint16_t{32768});
-  ASSERT_EQ(std::get<0>(Div<uint16_t>(uint16_t{32768}, uint16_t{2})), uint16_t{16384});
-  ASSERT_EQ(std::get<0>(Div<int32_t>(int32_t{-2147483648}, int32_t{0})), int32_t{-1});
-  ASSERT_EQ(std::get<0>(Div<int32_t>(int32_t{-2147483648}, int32_t{-1})), int32_t{-2147483648});
-  ASSERT_EQ(std::get<0>(Div<int32_t>(int32_t{-2147483648}, int32_t{-2})), int32_t{1073741824});
-  ASSERT_EQ(std::get<0>(Div<uint32_t>(uint32_t{2147483648}, uint32_t{0})), uint32_t{4294967295});
-  ASSERT_EQ(std::get<0>(Div<uint32_t>(uint32_t{2147483648}, uint32_t{1})), uint32_t{2147483648});
-  ASSERT_EQ(std::get<0>(Div<uint32_t>(uint32_t{2147483648}, uint32_t{2})), uint32_t{1073741824});
-  ASSERT_EQ(std::get<0>(Div<int64_t>(int64_t{-9223372036854775807 - 1}, int64_t{0})), int64_t{-1});
-  ASSERT_EQ(std::get<0>(Div<int64_t>(int64_t{-9223372036854775807 - 1}, int64_t{-1})),
+TEST(Intrinsics, DivRiscV) {
+  ASSERT_EQ(std::get<0>(DivRiscV<int8_t>(int8_t{-128}, int8_t{0})), int8_t{-1});
+  ASSERT_EQ(std::get<0>(DivRiscV<int8_t>(int8_t{-128}, int8_t{-1})), int8_t{-128});
+  ASSERT_EQ(std::get<0>(DivRiscV<int8_t>(int8_t{-128}, int8_t{-2})), int8_t{64});
+  ASSERT_EQ(std::get<0>(DivRiscV<uint8_t>(uint8_t{128}, uint8_t{0})), uint8_t{255});
+  ASSERT_EQ(std::get<0>(DivRiscV<uint8_t>(uint8_t{128}, uint8_t{1})), uint8_t{128});
+  ASSERT_EQ(std::get<0>(DivRiscV<uint8_t>(uint8_t{128}, uint8_t{2})), uint8_t{64});
+  ASSERT_EQ(std::get<0>(DivRiscV<int16_t>(int16_t{-32768}, int16_t{0})), int16_t{-1});
+  ASSERT_EQ(std::get<0>(DivRiscV<int16_t>(int16_t{-32768}, int16_t{-1})), int16_t{-32768});
+  ASSERT_EQ(std::get<0>(DivRiscV<int16_t>(int16_t{-32768}, int16_t{-2})), int16_t{16384});
+  ASSERT_EQ(std::get<0>(DivRiscV<uint16_t>(uint16_t{32768}, uint16_t{0})), uint16_t{65535});
+  ASSERT_EQ(std::get<0>(DivRiscV<uint16_t>(uint16_t{32768}, uint16_t{1})), uint16_t{32768});
+  ASSERT_EQ(std::get<0>(DivRiscV<uint16_t>(uint16_t{32768}, uint16_t{2})), uint16_t{16384});
+  ASSERT_EQ(std::get<0>(DivRiscV<int32_t>(int32_t{-2147483648}, int32_t{0})), int32_t{-1});
+  ASSERT_EQ(std::get<0>(DivRiscV<int32_t>(int32_t{-2147483648}, int32_t{-1})),
+            int32_t{-2147483648});
+  ASSERT_EQ(std::get<0>(DivRiscV<int32_t>(int32_t{-2147483648}, int32_t{-2})), int32_t{1073741824});
+  ASSERT_EQ(std::get<0>(DivRiscV<uint32_t>(uint32_t{2147483648}, uint32_t{0})),
+            uint32_t{4294967295});
+  ASSERT_EQ(std::get<0>(DivRiscV<uint32_t>(uint32_t{2147483648}, uint32_t{1})),
+            uint32_t{2147483648});
+  ASSERT_EQ(std::get<0>(DivRiscV<uint32_t>(uint32_t{2147483648}, uint32_t{2})),
+            uint32_t{1073741824});
+  ASSERT_EQ(std::get<0>(DivRiscV<int64_t>(int64_t{-9223372036854775807 - 1}, int64_t{0})),
+            int64_t{-1});
+  ASSERT_EQ(std::get<0>(DivRiscV<int64_t>(int64_t{-9223372036854775807 - 1}, int64_t{-1})),
             int64_t{-9223372036854775807 - 1});
-  ASSERT_EQ(std::get<0>(Div<int64_t>(int64_t{-9223372036854775807 - 1}, int64_t{-2})),
+  ASSERT_EQ(std::get<0>(DivRiscV<int64_t>(int64_t{-9223372036854775807 - 1}, int64_t{-2})),
             int64_t{4611686018427387904});
-  ASSERT_EQ(std::get<0>(Div<uint64_t>(uint64_t{9223372036854775808U}, uint64_t{0})),
+  ASSERT_EQ(std::get<0>(DivRiscV<uint64_t>(uint64_t{9223372036854775808U}, uint64_t{0})),
             uint64_t{18446744073709551615U});
-  ASSERT_EQ(std::get<0>(Div<uint64_t>(uint64_t{9223372036854775808U}, uint64_t{1})),
+  ASSERT_EQ(std::get<0>(DivRiscV<uint64_t>(uint64_t{9223372036854775808U}, uint64_t{1})),
             uint64_t{9223372036854775808U});
-  ASSERT_EQ(std::get<0>(Div<uint64_t>(uint64_t{9223372036854775808U}, uint64_t{2})),
+  ASSERT_EQ(std::get<0>(DivRiscV<uint64_t>(uint64_t{9223372036854775808U}, uint64_t{2})),
             uint64_t{4611686018427387904});
 }
 
diff --git a/intrinsics/riscv64_to_all/vector_intrinsics_test.cc b/intrinsics/riscv64_to_all/vector_intrinsics_test.cc
index fecaa3fa..e8aea4f4 100644
--- a/intrinsics/riscv64_to_all/vector_intrinsics_test.cc
+++ b/intrinsics/riscv64_to_all/vector_intrinsics_test.cc
@@ -16,7 +16,7 @@
 
 #include "gtest/gtest.h"
 
-#include "xmmintrin.h"
+#include <x86intrin.h>
 
 #include <array>
 #include <cstdint>
diff --git a/intrinsics/riscv64_to_arm64/include/berberis/intrinsics/intrinsics.h b/intrinsics/riscv64_to_arm64/include/berberis/intrinsics/intrinsics.h
index 22cf62db..71bdd810 100644
--- a/intrinsics/riscv64_to_arm64/include/berberis/intrinsics/intrinsics.h
+++ b/intrinsics/riscv64_to_arm64/include/berberis/intrinsics/intrinsics.h
@@ -55,18 +55,6 @@ inline std::tuple<uint64_t> Bset(uint64_t in1, uint64_t in2) {
   return {in1 | ShiftedOne(in2)};
 };
 
-template <typename T, enum PreferredIntrinsicsImplementation>
-inline std::tuple<T> Div(T in1, T in2) {
-  static_assert(std::is_integral_v<T>);
-
-  if (in2 == 0) {
-    return ~T{0};
-  } else if (std::is_signed_v<T> && in2 == -1 && in1 == std::numeric_limits<T>::min()) {
-    return {std::numeric_limits<T>::min()};
-  }
-  return {in1 / in2};
-};
-
 template <typename T, enum PreferredIntrinsicsImplementation>
 inline std::tuple<T> Max(T in1, T in2) {
   static_assert(std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>);
@@ -80,7 +68,19 @@ inline std::tuple<T> Min(T in1, T in2) {
 };
 
 template <typename T, enum PreferredIntrinsicsImplementation>
-inline std::tuple<T> Rem(T in1, T in2) {
+inline std::tuple<T> DivRiscV(T in1, T in2) {
+  static_assert(std::is_integral_v<T>);
+
+  if (in2 == 0) {
+    return ~T{0};
+  } else if (std::is_signed_v<T> && in2 == -1 && in1 == std::numeric_limits<T>::min()) {
+    return {std::numeric_limits<T>::min()};
+  }
+  return {in1 / in2};
+};
+
+template <typename T, enum PreferredIntrinsicsImplementation>
+inline std::tuple<T> RemRiscV(T in1, T in2) {
   static_assert(std::is_integral_v<T>);
 
   if (in2 == 0) {
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/constants_pool.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/constants_pool.h
index 7351ce1c..864f4e33 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/constants_pool.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/constants_pool.h
@@ -20,6 +20,7 @@
 #include <cinttypes>
 
 #include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/all_to_x86_64/constants_pool.h"
 #include "berberis/intrinsics/common/constants_pool.h"
 #include "berberis/intrinsics/common/intrinsics_float.h"
 
@@ -98,58 +99,27 @@ VECTOR_CONST_ALIAS(int64_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
 #pragma pop_macro("VECTOR_CONST_EXTERN")
 #pragma pop_macro("VECTOR_CONST_ALIAS")
 
-// 64 bit constants for use with arithmetic operations.
-// Used because only 32 bit immediates are supported on x86-64.
-
-template <auto Value>
-struct Const {};
-
-// Specialize Const<Value> using an out-of-line definition.
-#pragma push_macro("CONST_EXTERN")
-#define CONST_EXTERN(Value)      \
-  template <>                    \
-  struct Const<Value> {          \
-    static const int32_t kValue; \
-  }
-
-// Specialize Const<Value> using a reference to another constant's int32_t address.
-#pragma push_macro("CONST_ALIAS")
-#define CONST_ALIAS(Value, Alias)                   \
-  template <>                                       \
-  struct Const<Value> {                             \
-    static constexpr const int32_t& kValue = Alias; \
-  }
-
-template <auto Value>
-inline const int32_t& kConst = Const<Value>::kValue;
-
-CONST_EXTERN(uint32_t{32});
-CONST_EXTERN(uint32_t{63});
-CONST_EXTERN(uint64_t{64});
-CONST_EXTERN(uint64_t{127});
-
-CONST_ALIAS(int8_t{0x00}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
-CONST_ALIAS(uint8_t{0x00}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
-CONST_ALIAS(int16_t{0x0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
-CONST_ALIAS(uint16_t{0x0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
-CONST_ALIAS(int32_t{0x0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
-CONST_ALIAS(uint32_t{0x0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
-CONST_ALIAS(int64_t{0x0000'0000'0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
-CONST_ALIAS(uint64_t{0x0000'0000'0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
-
-CONST_EXTERN(uint64_t{0x8000'0000'0000'00ff});
-
-CONST_ALIAS(int8_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
-CONST_ALIAS(uint8_t{0xff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
-CONST_ALIAS(int16_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
-CONST_ALIAS(uint16_t{0xffff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
-CONST_ALIAS(int32_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
-CONST_ALIAS(uint32_t{0xffff'ffff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
-CONST_ALIAS(int64_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
-CONST_ALIAS(uint64_t{0xffff'ffff'ffff'ffff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
-
-#pragma pop_macro("CONST_EXTERN")
-#pragma pop_macro("CONST_ALIAS")
+BERBERIS_CONST_ALIAS(int8_t{0x00}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+BERBERIS_CONST_ALIAS(uint8_t{0x00}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+BERBERIS_CONST_ALIAS(int16_t{0x0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+BERBERIS_CONST_ALIAS(uint16_t{0x0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+BERBERIS_CONST_ALIAS(int32_t{0x0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+BERBERIS_CONST_ALIAS(uint32_t{0x0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+BERBERIS_CONST_ALIAS(int64_t{0x0000'0000'0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+BERBERIS_CONST_ALIAS(uint64_t{0x0000'0000'0000'0000},
+                     kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+
+BERBERIS_CONST_EXTERN(uint64_t{0x8000'0000'0000'00ff});
+
+BERBERIS_CONST_ALIAS(int8_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+BERBERIS_CONST_ALIAS(uint8_t{0xff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+BERBERIS_CONST_ALIAS(int16_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+BERBERIS_CONST_ALIAS(uint16_t{0xffff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+BERBERIS_CONST_ALIAS(int32_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+BERBERIS_CONST_ALIAS(uint32_t{0xffff'ffff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+BERBERIS_CONST_ALIAS(int64_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+BERBERIS_CONST_ALIAS(uint64_t{0xffff'ffff'ffff'ffff},
+                     kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
 
 // Constant suitable for NaN boxing of RISC-V 32bit float with PXor.
 // Note: technically we only need to Nan-box Float32 since we don't support Float16 yet.
@@ -176,22 +146,6 @@ template <>
 inline const int32_t& kCanonicalNans<intrinsics::Float64> =
     kVectorConst<uint64_t{0x7ff8'0000'0000'0000}>;
 
-// Helper constant for BsrToClz conversion. 63 for int32_t, 127 for int64_t.
-template <typename IntType>
-inline constexpr int32_t kBsrToClz = kImpossibleTypeConst<IntType>;
-template <>
-inline const int32_t kBsrToClz<int32_t> = kConst<uint32_t{63}>;
-template <>
-inline const int32_t kBsrToClz<int64_t> = kConst<uint64_t{127}>;
-
-// Helper constant for width of the type. 32 for int32_t, 64 for int64_t.
-template <typename IntType>
-inline constexpr int32_t kWidthInBits = kImpossibleTypeConst<IntType>;
-template <>
-inline const int32_t kWidthInBits<int32_t> = kConst<uint32_t{32}>;
-template <>
-inline const int32_t kWidthInBits<int64_t> = kConst<uint64_t{64}>;
-
 extern const int32_t kRiscVToX87Exceptions;
 extern const int32_t kX87ToRiscVExceptions;
 
@@ -217,9 +171,6 @@ inline constexpr ConstantAccessor<&constants_pool::kRiscVToX87Exceptions> kRiscV
 
 inline constexpr ConstantAccessor<&constants_pool::kX87ToRiscVExceptions> kX87ToRiscVExceptions;
 
-template <typename IntType>
-inline constexpr TypeConstantAccessor<&constants_pool::kBsrToClz<IntType>> kBsrToClz{};
-
 template <typename FloatType>
 inline constexpr TypeConstantAccessor<&constants_pool::kCanonicalNans<FloatType>> kCanonicalNans{};
 
@@ -229,9 +180,6 @@ inline constexpr TypeConstantAccessor<&constants_pool::kNanBox<FloatType>> kNanB
 template <typename FloatType>
 inline constexpr TypeConstantAccessor<&constants_pool::kNanBoxedNans<FloatType>> kNanBoxedNans{};
 
-template <typename IntType>
-inline constexpr TypeConstantAccessor<&constants_pool::kWidthInBits<IntType>> kWidthInBits{};
-
 template <auto Value>
 inline constexpr VectorConstantAccessor<Value> kVectorConst{};
 
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
index 87843dc3..b65f0796 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
@@ -24,6 +24,8 @@
 #include <tuple>
 #include <utility>
 
+#include "berberis/intrinsics//all_to_x86_32_or_x86_64/macro_assembler.h"
+#include "berberis/intrinsics//all_to_x86_64/macro_assembler.h"
 // Don't include arch-dependent parts because macro-assembler doesn't depend on implementation of
 // Float32/Float64 types but can be compiled for different architecture (soong's host architecture,
 // not device architecture AKA berberis' host architecture).
@@ -32,15 +34,31 @@
 
 namespace berberis {
 
+// Note: MacroAssembler specifies the full inheritance plan for all mixed-in assemblers.
+// Details at go/berberis-macroassembler-mixins
 template <typename Assembler>
-class MacroAssembler : public Assembler {
+class MacroAssembler
+    : public MacroAssemblerX86_64GuestAgnostic<
+          Assembler,
+          MacroAssemblerX86GuestAgnostic<Assembler, Assembler, MacroAssembler<Assembler>>,
+          MacroAssembler<Assembler>> {
  public:
-  using MacroAssemblers = std::tuple<MacroAssembler<Assembler>,
-                                     typename Assembler::BaseAssembler,
-                                     typename Assembler::FinalAssembler>;
+  using Assemblers = std::tuple<
+      typename Assembler::BaseAssembler,
+      typename Assembler::FinalAssembler,
+      MacroAssemblerX86GuestAgnostic<Assembler, Assembler, MacroAssembler<Assembler>>,
+      MacroAssemblerX86_64GuestAgnostic<
+          Assembler,
+          MacroAssemblerX86GuestAgnostic<Assembler, Assembler, MacroAssembler<Assembler>>,
+          MacroAssembler<Assembler>>,
+      MacroAssembler<Assembler>>;
 
   template <typename... Args>
-  constexpr explicit MacroAssembler(Args&&... args) : Assembler(std::forward<Args>(args)...) {}
+  constexpr explicit MacroAssembler(Args&&... args)
+      : MacroAssemblerX86_64GuestAgnostic<
+            Assembler,
+            MacroAssemblerX86GuestAgnostic<Assembler, Assembler, MacroAssembler<Assembler>>,
+            MacroAssembler<Assembler>>(std::forward<Args>(args)...) {}
 
 #define IMPORT_ASSEMBLER_FUNCTIONS
 #include "berberis/assembler/gen_assembler_x86_64-using-inl.h"
@@ -58,7 +76,9 @@ class MacroAssembler : public Assembler {
     Vpandn(result, src, {.disp = constants_offsets::kVectorConst<uint8_t{0b1111'1111}>});
   }
 
-#include "berberis/intrinsics/macro_assembler_interface-inl.h"  // NOLINT generated file
+#include "berberis/intrinsics/riscv64_to_x86_64/macro_assembler_interface-inl.h"  // NOLINT generated file
+
+  using AddressType = int64_t;
 
  private:
 
@@ -71,6 +91,8 @@ class MacroAssembler : public Assembler {
 }  // namespace berberis
 
 // Macro specializations.
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-impl.h"
+#include "berberis/intrinsics/all_to_x86_64/macro_assembler-impl.h"
 #include "berberis/intrinsics/macro_assembler_arith_impl.h"
 #include "berberis/intrinsics/macro_assembler_bitmanip_impl.h"
 #include "berberis/intrinsics/macro_assembler_floating_point_impl.h"
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h
index 03f84e11..1a0c522a 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h
@@ -29,7 +29,7 @@ namespace berberis {
 // gpr_d and FLAGS are clobbered by that macroinstruction.
 template <typename Assembler>
 template <typename IntType>
-constexpr void MacroAssembler<Assembler>::MacroDiv(Register src) {
+constexpr void MacroAssembler<Assembler>::DivRiscV(Register src) {
   Label* zero = MakeLabel();
   Label* done = MakeLabel();
   Test<IntType>(src, src);
@@ -88,7 +88,7 @@ constexpr void MacroAssembler<Assembler>::MacroDiv(Register src) {
 // For 8-bit: remainder is returned in gpr_a. FLAGS are clobbered.
 template <typename Assembler>
 template <typename IntType>
-constexpr void MacroAssembler<Assembler>::MacroRem(Register src) {
+constexpr void MacroAssembler<Assembler>::RemRiscV(Register src) {
   Label* zero = MakeLabel();
   Label* overflow = MakeLabel();
   Label* done = MakeLabel();
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_bitmanip_impl.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_bitmanip_impl.h
index 9b89daaf..21e6ec81 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_bitmanip_impl.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_bitmanip_impl.h
@@ -26,7 +26,7 @@ namespace berberis {
 
 template <typename Assembler>
 template <typename IntType>
-constexpr void MacroAssembler<Assembler>::MacroClz(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::Clz(Register result, Register src) {
   Bsr<IntType>(result, src);
   Cmov<IntType>(Condition::kZero, result, {.disp = constants_offsets::kBsrToClz<IntType>});
   Xor<IntType>(result, sizeof(IntType) * CHAR_BIT - 1);
@@ -34,14 +34,14 @@ constexpr void MacroAssembler<Assembler>::MacroClz(Register result, Register src
 
 template <typename Assembler>
 template <typename IntType>
-constexpr void MacroAssembler<Assembler>::MacroCtz(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::Ctz(Register result, Register src) {
   Bsf<IntType>(result, src);
   Cmov<IntType>(Condition::kZero, result, {.disp = constants_offsets::kWidthInBits<IntType>});
 }
 
 template <typename Assembler>
 template <typename IntType>
-constexpr void MacroAssembler<Assembler>::MacroMax(Register result, Register src1, Register src2) {
+constexpr void MacroAssembler<Assembler>::Max(Register result, Register src1, Register src2) {
   Mov<IntType>(result, src1);
   Cmp<IntType>(src1, src2);
   if constexpr (std::is_signed_v<IntType>) {
@@ -53,7 +53,7 @@ constexpr void MacroAssembler<Assembler>::MacroMax(Register result, Register src
 
 template <typename Assembler>
 template <typename IntType>
-constexpr void MacroAssembler<Assembler>::MacroMin(Register result, Register src1, Register src2) {
+constexpr void MacroAssembler<Assembler>::Min(Register result, Register src1, Register src2) {
   Mov<IntType>(result, src1);
   Cmp<IntType>(src1, src2);
   if constexpr (std::is_signed_v<IntType>) {
@@ -64,58 +64,58 @@ constexpr void MacroAssembler<Assembler>::MacroMin(Register result, Register src
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroOrcb(XMMRegister result) {
+constexpr void MacroAssembler<Assembler>::Orcb(XMMRegister result) {
   Pcmpeqb(result, {.disp = constants_offsets::kVectorConst<uint8_t{0}>});
   PNot(result);
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroOrcbAVX(XMMRegister result, XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::OrcbAVX(XMMRegister result, XMMRegister src) {
   Vpcmpeqb(result, src, {.disp = constants_offsets::kVectorConst<uint8_t{0}>});
   Vpnot(result, result);
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroAdduw(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::Adduw(Register result, Register src) {
   Movl(result, result);
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesOne});
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroSh1adduw(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::Sh1adduw(Register result, Register src) {
   Movl(result, result);
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesTwo});
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroSh2adduw(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::Sh2adduw(Register result, Register src) {
   Movl(result, result);
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesFour});
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroSh3adduw(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::Sh3adduw(Register result, Register src) {
   Movl(result, result);
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesEight});
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroSh1add(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::Sh1add(Register result, Register src) {
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesTwo});
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroSh2add(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::Sh2add(Register result, Register src) {
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesFour});
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroSh3add(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::Sh3add(Register result, Register src) {
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesEight});
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroBext(Register result, Register src1, Register src2) {
+constexpr void MacroAssembler<Assembler>::Bext(Register result, Register src1, Register src2) {
   Btq(src1, src2);
   Movl(result, 0);
   Setcc(Condition::kCarry, result);
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_floating_point_impl.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_floating_point_impl.h
index 48acf4b5..7980e6b1 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_floating_point_impl.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_floating_point_impl.h
@@ -44,8 +44,7 @@ constexpr int32_t kRiscVRoundingModes = 0b1110'0111'00;
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroCanonicalizeNan(XMMRegister result,
-                                                               XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::CanonicalizeNan(XMMRegister result, XMMRegister src) {
   Pmov(result, src);
   Cmpords<FloatType>(result, src);
   Pand(src, result);
@@ -55,8 +54,7 @@ constexpr void MacroAssembler<Assembler>::MacroCanonicalizeNan(XMMRegister resul
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroCanonicalizeNanAVX(XMMRegister result,
-                                                                  XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::CanonicalizeNanAVX(XMMRegister result, XMMRegister src) {
   Vcmpords<FloatType>(result, src, src);
   Vpand(src, src, result);
   Vpandn(result, result, {.disp = constants_offsets::kCanonicalNans<FloatType>});
@@ -65,9 +63,7 @@ constexpr void MacroAssembler<Assembler>::MacroCanonicalizeNanAVX(XMMRegister re
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroFeq(Register result,
-                                                   XMMRegister src1,
-                                                   XMMRegister src2) {
+constexpr void MacroAssembler<Assembler>::Feq(Register result, XMMRegister src1, XMMRegister src2) {
   Cmpeqs<FloatType>(src1, src2);
   Mov<FloatType>(result, src1);
   And<int32_t>(result, 1);
@@ -75,10 +71,10 @@ constexpr void MacroAssembler<Assembler>::MacroFeq(Register result,
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroFeqAVX(Register result,
-                                                      XMMRegister src1,
-                                                      XMMRegister src2,
-                                                      XMMRegister tmp) {
+constexpr void MacroAssembler<Assembler>::FeqAVX(Register result,
+                                                 XMMRegister src1,
+                                                 XMMRegister src2,
+                                                 XMMRegister tmp) {
   Vcmpeqs<FloatType>(tmp, src1, src2);
   Vmov<FloatType>(result, tmp);
   And<int32_t>(result, 1);
@@ -87,8 +83,7 @@ constexpr void MacroAssembler<Assembler>::MacroFeqAVX(Register result,
 // Note: result is returned in %rax which is implicit argument of that macro-instruction.
 // Explicit argument is temporary needed to handle Stmxcsr instruction.
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroFeGetExceptionsTranslate(
-    const Operand& mxcsr_scratch) {
+constexpr void MacroAssembler<Assembler>::FeGetExceptionsTranslate(const Operand& mxcsr_scratch) {
   // Store x87 status word in the AX.
   Fnstsw();
   // Store MXCSR in scratch slot.
@@ -105,7 +100,7 @@ constexpr void MacroAssembler<Assembler>::MacroFeGetExceptionsTranslate(
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundImmTranslate(
+constexpr void MacroAssembler<Assembler>::FeSetExceptionsAndRoundImmTranslate(
     const Operand& fenv_scratch,
     int8_t exceptions_and_rm) {
   int8_t exceptions = exceptions_and_rm & 0b1'1111;
@@ -158,7 +153,7 @@ constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundImmTransla
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundTranslate(
+constexpr void MacroAssembler<Assembler>::FeSetExceptionsAndRoundTranslate(
     Register exceptions,
     const Operand& fenv_scratch,
     Register scratch_register) {
@@ -216,9 +211,8 @@ constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundTranslate(
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsImmTranslate(
-    const Operand& fenv_scratch,
-    int8_t exceptions) {
+constexpr void MacroAssembler<Assembler>::FeSetExceptionsImmTranslate(const Operand& fenv_scratch,
+                                                                      int8_t exceptions) {
   // Note: in 32bit/64bit mode it's at offset 4, not 2 as one may imagine.
   // Two bytes after control word are ignored.
   Operand x87_status_word = {.base = fenv_scratch.base,
@@ -256,9 +250,9 @@ constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsImmTranslate(
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsTranslate(Register exceptions,
-                                                                        const Operand& fenv_scratch,
-                                                                        Register x87_exceptions) {
+constexpr void MacroAssembler<Assembler>::FeSetExceptionsTranslate(Register exceptions,
+                                                                   const Operand& fenv_scratch,
+                                                                   Register x87_exceptions) {
   // Note: in 32bit/64bit mode it's at offset 4, not 2 as one may imagine.
   // Two bytes after control word are ignored.
   Operand x87_status_word = {.base = fenv_scratch.base,
@@ -298,9 +292,9 @@ constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsTranslate(Register
 // Note: actual rounding mode comes in %cl which is implicit argument of that macro-instruction.
 // All explicit arguments are temporaries.
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroFeSetRound(Register x87_sse_round,
-                                                          const Operand& cw_scratch,
-                                                          const Operand& mxcsr_scratch) {
+constexpr void MacroAssembler<Assembler>::FeSetRound(Register x87_sse_round,
+                                                     const Operand& cw_scratch,
+                                                     const Operand& mxcsr_scratch) {
   // Store x87 control world in first scratch slot.
   Fnstcw(cw_scratch);
   // Store MXCSR in second scratch slot.
@@ -331,9 +325,9 @@ constexpr void MacroAssembler<Assembler>::MacroFeSetRound(Register x87_sse_round
 }
 
 template <typename Assembler>
-constexpr void MacroAssembler<Assembler>::MacroFeSetRoundImmTranslate(const Operand& cw_scratch,
-                                                                      const Operand& mxcsr_scratch,
-                                                                      int8_t rm) {
+constexpr void MacroAssembler<Assembler>::FeSetRoundImmTranslate(const Operand& cw_scratch,
+                                                                 const Operand& mxcsr_scratch,
+                                                                 int8_t rm) {
   // Store x87 control world in first scratch slot.
   Fnstcw(cw_scratch);
   // Store MXCSR in second scratch slot.
@@ -358,9 +352,7 @@ constexpr void MacroAssembler<Assembler>::MacroFeSetRoundImmTranslate(const Oper
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroFle(Register result,
-                                                   XMMRegister src1,
-                                                   XMMRegister src2) {
+constexpr void MacroAssembler<Assembler>::Fle(Register result, XMMRegister src1, XMMRegister src2) {
   Cmples<FloatType>(src1, src2);
   Mov<FloatType>(result, src1);
   And<int32_t>(result, 1);
@@ -368,17 +360,16 @@ constexpr void MacroAssembler<Assembler>::MacroFle(Register result,
 
 template <typename Assembler>
 template <typename FormatTo, typename FormatFrom>
-constexpr void MacroAssembler<Assembler>::MacroFCvtFloatToInteger(Register result,
-                                                                  XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::FCvtFloatToInteger(Register result, XMMRegister src) {
   Cvt<FormatFrom, FormatTo>(result, src);
 }
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroFleAVX(Register result,
-                                                      XMMRegister src1,
-                                                      XMMRegister src2,
-                                                      XMMRegister tmp) {
+constexpr void MacroAssembler<Assembler>::FleAVX(Register result,
+                                                 XMMRegister src1,
+                                                 XMMRegister src2,
+                                                 XMMRegister tmp) {
   Vcmples<FloatType>(tmp, src1, src2);
   Vmov<FloatType>(result, tmp);
   And<int32_t>(result, 1);
@@ -386,9 +377,7 @@ constexpr void MacroAssembler<Assembler>::MacroFleAVX(Register result,
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroFlt(Register result,
-                                                   XMMRegister src1,
-                                                   XMMRegister src2) {
+constexpr void MacroAssembler<Assembler>::Flt(Register result, XMMRegister src1, XMMRegister src2) {
   Cmplts<FloatType>(src1, src2);
   Mov<FloatType>(result, src1);
   And<int32_t>(result, 1);
@@ -396,10 +385,10 @@ constexpr void MacroAssembler<Assembler>::MacroFlt(Register result,
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroFltAVX(Register result,
-                                                      XMMRegister src1,
-                                                      XMMRegister src2,
-                                                      XMMRegister tmp) {
+constexpr void MacroAssembler<Assembler>::FltAVX(Register result,
+                                                 XMMRegister src1,
+                                                 XMMRegister src2,
+                                                 XMMRegister tmp) {
   Vcmplts<FloatType>(tmp, src1, src2);
   Vmov<FloatType>(result, tmp);
   And<int32_t>(result, 1);
@@ -407,7 +396,7 @@ constexpr void MacroAssembler<Assembler>::MacroFltAVX(Register result,
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroNanBox(XMMRegister arg) {
+constexpr void MacroAssembler<Assembler>::NanBox(XMMRegister arg) {
   static_assert(std::is_same_v<FloatType, Float32>);
 
   Por(arg, {.disp = constants_offsets::kNanBox<Float32>});
@@ -415,7 +404,7 @@ constexpr void MacroAssembler<Assembler>::MacroNanBox(XMMRegister arg) {
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroNanBoxAVX(XMMRegister result, XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::NanBoxAVX(XMMRegister result, XMMRegister src) {
   static_assert(std::is_same_v<FloatType, Float32>);
 
   Vpor(result, src, {.disp = constants_offsets::kNanBox<Float32>});
@@ -423,7 +412,7 @@ constexpr void MacroAssembler<Assembler>::MacroNanBoxAVX(XMMRegister result, XMM
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroUnboxNan(XMMRegister result, XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::UnboxNan(XMMRegister result, XMMRegister src) {
   static_assert(std::is_same_v<FloatType, Float32>);
 
   Pmov(result, src);
@@ -437,7 +426,7 @@ constexpr void MacroAssembler<Assembler>::MacroUnboxNan(XMMRegister result, XMMR
 
 template <typename Assembler>
 template <typename FloatType>
-constexpr void MacroAssembler<Assembler>::MacroUnboxNanAVX(XMMRegister result, XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::UnboxNanAVX(XMMRegister result, XMMRegister src) {
   static_assert(std::is_same_v<FloatType, Float32>);
 
   Vpcmpeq<typename TypeTraits<FloatType>::Int>(
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h
index 6a9b00e5..fd8a13cb 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h
@@ -17,8 +17,7 @@
 #ifndef RISCV64_TO_X86_64_BERBERIS_INTRINSICS_VECTOR_INTRINSICS_H_
 #define RISCV64_TO_X86_64_BERBERIS_INTRINSICS_VECTOR_INTRINSICS_H_
 
-#include <tmmintrin.h>
-#include <xmmintrin.h>
+#include <x86intrin.h>
 
 #include "berberis/base/dependent_false.h"
 #include "berberis/intrinsics/common/intrinsics.h"
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/verifier_assembler.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/verifier_assembler.h
index fad0f1b1..13e5c820 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/verifier_assembler.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/verifier_assembler.h
@@ -19,13 +19,13 @@
 
 #include <stdio.h>
 
-#include "berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_and_x86_64.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_or_x86_64.h"
 
 namespace berberis {
 
-class VerifierAssembler : public x86_32_and_x86_64::VerifierAssembler<VerifierAssembler> {
+class VerifierAssembler : public x86_32_or_x86_64::VerifierAssembler<VerifierAssembler> {
  public:
-  using BaseAssembler = x86_32_and_x86_64::VerifierAssembler<VerifierAssembler>;
+  using BaseAssembler = x86_32_or_x86_64::VerifierAssembler<VerifierAssembler>;
   using FinalAssembler = VerifierAssembler;
 
   constexpr VerifierAssembler([[maybe_unused]] int indent, [[maybe_unused]] FILE* out)
diff --git a/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json b/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json
index a517e666..d9d1ff2c 100644
--- a/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json
+++ b/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json
@@ -70,7 +70,7 @@
   },
   {
     "name": "Clz<int32_t>",
-    "insn": "ClzInt32",
+    "insn": "CountLeadingZerosU32",
     "in": [ 1 ],
     "out": [ 0 ]
   },
@@ -83,7 +83,7 @@
   },
   {
     "name": "Clz<int64_t>",
-    "insn": "ClzInt64",
+    "insn": "CountLeadingZerosU64",
     "in": [ 1 ],
     "out": [ 0 ]
   },
@@ -110,7 +110,7 @@
   },
   {
     "name": "Ctz<int32_t>",
-    "insn": "CtzInt32",
+    "insn": "CountTrailingZerosU32",
     "in": [ 1 ],
     "out": [ 0 ]
   },
@@ -123,7 +123,7 @@
   },
   {
     "name": "Ctz<int64_t>",
-    "insn": "CtzInt64",
+    "insn": "CountTrailingZerosU64",
     "in": [ 1 ],
     "out": [ 0 ]
   },
@@ -135,50 +135,50 @@
     "out": [ 0 ]
   },
   {
-    "name": "Div<int8_t>",
-    "insn": "DivInt8",
+    "name": "DivRiscV<int8_t>",
+    "insn": "DivI8RiscV",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Div<int16_t>",
-    "insn": "DivInt16",
+    "name": "DivRiscV<int16_t>",
+    "insn": "DivI16RiscV",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Div<int32_t>",
-    "insn": "DivInt32",
+    "name": "DivRiscV<int32_t>",
+    "insn": "DivI32RiscV",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Div<int64_t>",
-    "insn": "DivInt64",
+    "name": "DivRiscV<int64_t>",
+    "insn": "DivI64RiscV",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Div<uint8_t>",
-    "insn": "DivUInt8",
+    "name": "DivRiscV<uint8_t>",
+    "insn": "DivU8RiscV",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Div<uint16_t>",
-    "insn": "DivUInt16",
+    "name": "DivRiscV<uint16_t>",
+    "insn": "DivU16RiscV",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Div<uint32_t>",
-    "insn": "DivUInt32",
+    "name": "DivRiscV<uint32_t>",
+    "insn": "DivU32RiscV",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Div<uint64_t>",
-    "insn": "DivUInt64",
+    "name": "DivRiscV<uint64_t>",
+    "insn": "DivU64RiscV",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
@@ -210,25 +210,25 @@
   },
   {
     "name": "FCvtFloatToIntegerHostRounding<int32_t, Float32>",
-    "insn": "MacroFCvtFloat32ToInt32",
+    "insn": "FCvtFloat32ToInt32",
     "in": [ 1 ],
     "out": [ 0 ]
   },
   {
     "name": "FCvtFloatToIntegerHostRounding<int32_t, Float64>",
-    "insn": "MacroFCvtFloat64ToInt32",
+    "insn": "FCvtFloat64ToInt32",
     "in": [ 1 ],
     "out": [ 0 ]
   },
   {
     "name": "FCvtFloatToIntegerHostRounding<int64_t, Float32>",
-    "insn": "MacroFCvtFloat32ToInt64",
+    "insn": "FCvtFloat32ToInt64",
     "in": [ 1 ],
     "out": [ 0 ]
   },
   {
     "name": "FCvtFloatToIntegerHostRounding<int64_t, Float64>",
-    "insn": "MacroFCvtFloat64ToInt64",
+    "insn": "FCvtFloat64ToInt64",
     "in": [ 1 ],
     "out": [ 0 ]
   },
@@ -368,133 +368,133 @@
   },
   {
     "name": "FeGetExceptions",
-    "insn": "MacroFeGetExceptionsTranslate",
+    "insn": "FeGetExceptionsTranslate",
     "usage": "inline-only",
     "in": [],
     "out": [ 1 ]
   },
   {
     "name": "FeSetExceptionsAndRoundImm",
-    "insn": "MacroFeSetExceptionsAndRoundImmTranslate",
+    "insn": "FeSetExceptionsAndRoundImmTranslate",
     "usage": "inline-only",
     "in": [ 1 ],
     "out": []
   },
   {
     "name": "FeSetExceptionsAndRound",
-    "insn": "MacroFeSetExceptionsAndRoundTranslate",
+    "insn": "FeSetExceptionsAndRoundTranslate",
     "usage": "inline-only",
     "in": [ 0, 3 ],
     "out": []
   },
   {
     "name": "FeSetExceptionsImm",
-    "insn": "MacroFeSetExceptionsImmTranslate",
+    "insn": "FeSetExceptionsImmTranslate",
     "usage": "inline-only",
     "in": [ 1 ],
     "out": []
   },
   {
     "name": "FeSetExceptions",
-    "insn": "MacroFeSetExceptionsTranslate",
+    "insn": "FeSetExceptionsTranslate",
     "usage": "inline-only",
     "in": [ 0 ],
     "out": []
   },
   {
     "name": "FeSetRound",
-    "insn": "MacroFeSetRound",
+    "insn": "FeSetRound",
     "in": [ 3 ],
     "out": []
   },
   {
     "name": "FeSetRoundImm",
-    "insn": "MacroFeSetRoundImmTranslate",
+    "insn": "FeSetRoundImmTranslate",
     "usage": "inline-only",
     "in": [ 2 ],
     "out": []
   },
   {
     "name": "FeSetRoundImm",
-    "insn": "MacroFeSetRound",
+    "insn": "FeSetRound",
     "usage": "no-inline",
     "in": [ 3 ],
     "out": []
   },
   {
     "name": "Feq<Float32>",
-    "insn": "MacroFeqFloat32",
+    "insn": "FeqFloat32",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Feq<Float32>",
-    "insn": "MacroFeqFloat32AVX",
+    "insn": "FeqFloat32AVX",
     "feature": "AVX",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Feq<Float64>",
-    "insn": "MacroFeqFloat64",
+    "insn": "FeqFloat64",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Feq<Float64>",
-    "insn": "MacroFeqFloat64AVX",
+    "insn": "FeqFloat64AVX",
     "feature": "AVX",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Fle<Float32>",
-    "insn": "MacroFleFloat32",
+    "insn": "FleFloat32",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Fle<Float32>",
-    "insn": "MacroFleFloat32AVX",
+    "insn": "FleFloat32AVX",
     "feature": "AVX",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Fle<Float64>",
-    "insn": "MacroFleFloat64",
+    "insn": "FleFloat64",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Fle<Float64>",
-    "insn": "MacroFleFloat64AVX",
+    "insn": "FleFloat64AVX",
     "feature": "AVX",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Flt<Float32>",
-    "insn": "MacroFltFloat32",
+    "insn": "FltFloat32",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Flt<Float32>",
-    "insn": "MacroFltFloat32AVX",
+    "insn": "FltFloat32AVX",
     "feature": "AVX",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Flt<Float64>",
-    "insn": "MacroFltFloat64",
+    "insn": "FltFloat64",
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
   {
     "name": "Flt<Float64>",
-    "insn": "MacroFltFloat64AVX",
+    "insn": "FltFloat64AVX",
     "feature": "AVX",
     "in": [ 1, 2 ],
     "out": [ 0 ]
@@ -577,13 +577,13 @@
   },
   {
     "name": "NanBox<Float32>",
-    "insn": "MacroNanBoxFloat32",
+    "insn": "NanBoxFloat32",
     "in": [ 0 ],
     "out": [ 0 ]
   },
   {
     "name": "NanBox<Float32>",
-    "insn": "MacroNanBoxFloat32AVX",
+    "insn": "NanBoxFloat32AVX",
     "feature": "AVX",
     "in": [ 1 ],
     "out": [ 0 ]
@@ -602,50 +602,50 @@
     "out": [ 0 ]
   },
   {
-    "name": "Rem<int8_t>",
-    "insn": "RemInt8",
+    "name": "RemRiscV<int8_t>",
+    "insn": "RemI8RiscV",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Rem<int16_t>",
-    "insn": "RemInt16",
+    "name": "RemRiscV<int16_t>",
+    "insn": "RemI16RiscV",
     "in": [ 1, 0 ],
     "out": [ 2 ]
   },
   {
-    "name": "Rem<int32_t>",
-    "insn": "RemInt32",
+    "name": "RemRiscV<int32_t>",
+    "insn": "RemI32RiscV",
     "in": [ 1, 0 ],
     "out": [ 2 ]
   },
   {
-    "name": "Rem<int64_t>",
-    "insn": "RemInt64",
+    "name": "RemRiscV<int64_t>",
+    "insn": "RemI64RiscV",
     "in": [ 1, 0 ],
     "out": [ 2 ]
   },
   {
-    "name": "Rem<uint8_t>",
-    "insn": "RemUInt8",
+    "name": "RemRiscV<uint8_t>",
+    "insn": "RemU8RiscV",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Rem<uint16_t>",
-    "insn": "RemUInt16",
+    "name": "RemRiscV<uint16_t>",
+    "insn": "RemU16RiscV",
     "in": [ 1, 0 ],
     "out": [ 2 ]
   },
   {
-    "name": "Rem<uint32_t>",
-    "insn": "RemUInt32",
+    "name": "RemRiscV<uint32_t>",
+    "insn": "RemU32RiscV",
     "in": [ 1, 0 ],
     "out": [ 2 ]
   },
   {
-    "name": "Rem<uint64_t>",
-    "insn": "RemUInt64",
+    "name": "RemRiscV<uint64_t>",
+    "insn": "RemU64RiscV",
     "in": [ 1, 0 ],
     "out": [ 2 ]
   },
@@ -729,13 +729,13 @@
   },
   {
     "name": "UnboxNan<Float32>",
-    "insn": "MacroUnboxNanFloat32",
+    "insn": "UnboxNanFloat32",
     "in": [ 1 ],
     "out": [ 0 ]
   },
   {
     "name": "UnboxNan<Float32>",
-    "insn": "MacroUnboxNanFloat32AVX",
+    "insn": "UnboxNanFloat32AVX",
     "feature": "AVX",
     "in": [ 1 ],
     "out": [ 0 ]
diff --git a/intrinsics/riscv64_to_x86_64/macro_def.json b/intrinsics/riscv64_to_x86_64/macro_def.json
index f9d7075d..13b4daee 100644
--- a/intrinsics/riscv64_to_x86_64/macro_def.json
+++ b/intrinsics/riscv64_to_x86_64/macro_def.json
@@ -21,8 +21,8 @@
         { "class": "GeneralReg64", "usage": "use_def" },
         { "class": "GeneralReg64", "usage": "use" }
       ],
-      "asm": "MacroAdduw",
-      "mnemo": "MACRO_ADDUW"
+      "asm": "Adduw",
+      "mnemo": "ADDUW"
     },
     {
       "name": "Bext",
@@ -32,8 +32,8 @@
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroBext",
-      "mnemo": "MACRO_BEXT"
+      "asm": "Bext",
+      "mnemo": "BEXT"
     },
     {
       "name": "CanonicalizeNanFloat32",
@@ -41,8 +41,8 @@
         { "class": "FpReg32", "usage": "def" },
         { "class": "FpReg32", "usage": "use_def" }
       ],
-      "asm": "MacroCanonicalizeNan<intrinsics::Float32>",
-      "mnemo": "MACRO_CANONICALIZE_F32"
+      "asm": "CanonicalizeNan<Float32>",
+      "mnemo": "CANONICALIZE_F32"
     },
     {
       "name": "CanonicalizeNanFloat32AVX",
@@ -50,8 +50,8 @@
         { "class": "FpReg32", "usage": "def" },
         { "class": "FpReg32", "usage": "use_def" }
       ],
-      "asm": "MacroCanonicalizeNanAVX<intrinsics::Float32>",
-      "mnemo": "MACRO_CANONICALIZE_F32"
+      "asm": "CanonicalizeNanAVX<Float32>",
+      "mnemo": "CANONICALIZE_F32"
     },
     {
       "name": "CanonicalizeNanFloat64",
@@ -59,8 +59,8 @@
         { "class": "FpReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" }
       ],
-      "asm": "MacroCanonicalizeNan<intrinsics::Float64>",
-      "mnemo": "MACRO_CANONICALIZE_F64"
+      "asm": "CanonicalizeNan<Float64>",
+      "mnemo": "CANONICALIZE_F64"
     },
     {
       "name": "CanonicalizeNanFloat64AVX",
@@ -68,8 +68,8 @@
         { "class": "FpReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" }
       ],
-      "asm": "MacroCanonicalizeNanAVX<intrinsics::Float64>",
-      "mnemo": "MACRO_CANONICALIZE_F64"
+      "asm": "CanonicalizeNanAVX<Float64>",
+      "mnemo": "CANONICALIZE_F64"
     },
     {
       "name": "ClzInt32",
@@ -78,7 +78,7 @@
         { "class": "GeneralReg32", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroClz<int32_t>",
+      "asm": "Clz<int32_t>",
       "mnemo": "CLZ_I32"
     },
     {
@@ -88,7 +88,7 @@
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroClz<int64_t>",
+      "asm": "Clz<int64_t>",
       "mnemo": "CLZ_I64"
     },
     {
@@ -98,7 +98,7 @@
         { "class": "GeneralReg32", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroCtz<int32_t>",
+      "asm": "Ctz<int32_t>",
       "mnemo": "CTZ_I32"
     },
     {
@@ -108,181 +108,181 @@
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroCtz<int64_t>",
+      "asm": "Ctz<int64_t>",
       "mnemo": "CTZ_I64"
     },
     {
-      "name": "DivInt8",
+      "name": "DivI8RiscV",
       "args": [
         { "class": "GeneralReg8", "usage": "use" },
         { "class": "AX", "usage": "use_def" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroDiv<int8_t>",
-      "mnemo": "MACRO_DIV8"
+      "asm": "DivRiscV<int8_t>",
+      "mnemo": "DIV_I8_RISCV"
     },
     {
-      "name": "DivInt16",
+      "name": "DivI16RiscV",
       "args": [
         { "class": "GeneralReg16", "usage": "use" },
         { "class": "AX", "usage": "use_def" },
         { "class": "DX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroDiv<int16_t>",
-      "mnemo": "MACRO_DIV16"
+      "asm": "DivRiscV<int16_t>",
+      "mnemo": "DIV_I16_RISCV"
     },
     {
-      "name": "DivInt32",
+      "name": "DivI32RiscV",
       "args": [
         { "class": "GeneralReg32", "usage": "use" },
         { "class": "EAX", "usage": "use_def" },
         { "class": "EDX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroDiv<int32_t>",
-      "mnemo": "MACRO_DIV32"
+      "asm": "DivRiscV<int32_t>",
+      "mnemo": "DIV_I32_RISCV"
     },
     {
-      "name": "DivInt64",
+      "name": "DivI64RiscV",
       "args": [
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "EAX", "usage": "use_def" },
         { "class": "EDX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroDiv<int64_t>",
-      "mnemo": "MACRO_DIV64"
+      "asm": "DivRiscV<int64_t>",
+      "mnemo": "DIV_I64_RISCV"
     },
     {
-      "name": "DivUInt8",
+      "name": "DivU8RiscV",
       "args": [
         { "class": "GeneralReg8", "usage": "use" },
         { "class": "AX", "usage": "use_def" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroDiv<uint8_t>",
-      "mnemo": "MACRO_UDIV8"
+      "asm": "DivRiscV<uint8_t>",
+      "mnemo": "DIV_U8_RISCV"
     },
     {
-      "name": "DivUInt16",
+      "name": "DivU16RiscV",
       "args": [
         { "class": "GeneralReg16", "usage": "use" },
         { "class": "AX", "usage": "use_def" },
         { "class": "DX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroDiv<uint16_t>",
-      "mnemo": "MACRO_UDIV16"
+      "asm": "DivRiscV<uint16_t>",
+      "mnemo": "DIV_U16_RISCV"
     },
     {
-      "name": "DivUInt32",
+      "name": "DivU32RiscV",
       "args": [
         { "class": "GeneralReg32", "usage": "use" },
         { "class": "EAX", "usage": "use_def" },
         { "class": "EDX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroDiv<uint32_t>",
-      "mnemo": "MACRO_UDIV32"
+      "asm": "DivRiscV<uint32_t>",
+      "mnemo": "DIV_U32_RISCV"
     },
     {
-      "name": "DivUInt64",
+      "name": "DivU64RiscV",
       "args": [
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "EAX", "usage": "use_def" },
         { "class": "EDX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroDiv<uint64_t>",
-      "mnemo": "MACRO_UDIV64"
+      "asm": "DivRiscV<uint64_t>",
+      "mnemo": "DIV_U64_RISCV"
     },
     {
-      "name": "MacroFCvtFloat32ToInt32",
+      "name": "FCvtFloat32ToInt32",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" }
       ],
-      "asm": "MacroFCvtFloatToInteger<int32_t, intrinsics::Float32>",
-      "mnemo": "MACRO_FCvtFloatToInteger"
+      "asm": "FCvtFloatToInteger<int32_t, Float32>",
+      "mnemo": "FCvtFloatToInteger"
     },
     {
-      "name": "MacroFCvtFloat32ToInt64",
+      "name": "FCvtFloat32ToInt64",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" }
       ],
-      "asm": "MacroFCvtFloatToInteger<int64_t, intrinsics::Float32>",
-      "mnemo": "MACRO_FCvtFloatToInteger"
+      "asm": "FCvtFloatToInteger<int64_t, Float32>",
+      "mnemo": "FCvtFloatToInteger"
     },
     {
-      "name": "MacroFCvtFloat64ToInt32",
+      "name": "FCvtFloat64ToInt32",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" }
       ],
-      "asm": "MacroFCvtFloatToInteger<int32_t, intrinsics::Float64>",
-      "mnemo": "MACRO_FCvtFloatToInteger"
+      "asm": "FCvtFloatToInteger<int32_t, Float64>",
+      "mnemo": "FCvtFloatToInteger"
     },
     {
-      "name": "MacroFCvtFloat64ToInt64",
+      "name": "FCvtFloat64ToInt64",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" }
       ],
-      "asm": "MacroFCvtFloatToInteger<int64_t, intrinsics::Float64>",
-      "mnemo": "MACRO_FCvtFloatToInteger"
+      "asm": "FCvtFloatToInteger<int64_t, Float64>",
+      "mnemo": "FCvtFloatToInteger"
     },
     {
-      "name": "MacroFeGetExceptionsTranslate",
+      "name": "FeGetExceptionsTranslate",
       "args": [
         { "class": "Mem32", "usage": "def_early_clobber" },
         { "class": "RAX", "usage": "def" }
       ],
-      "asm": "MacroFeGetExceptionsTranslate",
-      "mnemo": "MACRO_FE_GET_EXCEPTIONS"
+      "asm": "FeGetExceptionsTranslate",
+      "mnemo": "FE_GET_EXCEPTIONS"
     },
     {
-      "name": "MacroFeSetExceptionsAndRoundImmTranslate",
+      "name": "FeSetExceptionsAndRoundImmTranslate",
       "args": [
         { "class": "MemX87", "usage": "def_early_clobber" },
         { "class": "Imm8" }
       ],
-      "asm": "MacroFeSetExceptionsAndRoundImmTranslate",
-      "mnemo": "MACRO_FE_SET_EXCEPTIONS_AND_ROUND"
+      "asm": "FeSetExceptionsAndRoundImmTranslate",
+      "mnemo": "FE_SET_EXCEPTIONS_AND_ROUND"
     },
     {
-      "name": "MacroFeSetExceptionsAndRoundTranslate",
+      "name": "FeSetExceptionsAndRoundTranslate",
       "args": [
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "MemX87", "usage": "def_early_clobber" },
         { "class": "GeneralReg8", "usage": "def" },
         { "class": "CL", "usage": "use" }
       ],
-      "asm": "MacroFeSetExceptionsAndRoundTranslate",
-      "mnemo": "MACRO_FE_SET_EXCEPTIONS_AND_ROUND"
+      "asm": "FeSetExceptionsAndRoundTranslate",
+      "mnemo": "FE_SET_EXCEPTIONS_AND_ROUND"
     },
     {
-      "name": "MacroFeSetExceptionsImmTranslate",
+      "name": "FeSetExceptionsImmTranslate",
       "args": [
         { "class": "MemX87", "usage": "def_early_clobber" },
         { "class": "Imm8" }
       ],
-      "asm": "MacroFeSetExceptionsImmTranslate",
-      "mnemo": "MACRO_FE_SET_EXCEPTIONS"
+      "asm": "FeSetExceptionsImmTranslate",
+      "mnemo": "FE_SET_EXCEPTIONS"
     },
     {
-      "name": "MacroFeSetExceptionsTranslate",
+      "name": "FeSetExceptionsTranslate",
       "args": [
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "MemX87", "usage": "def_early_clobber" },
         { "class": "GeneralReg8", "usage": "def" }
       ],
-      "asm": "MacroFeSetExceptionsTranslate",
-      "mnemo": "MACRO_FE_SET_EXCEPTIONS"
+      "asm": "FeSetExceptionsTranslate",
+      "mnemo": "FE_SET_EXCEPTIONS"
     },
     {
-      "name": "MacroFeSetRound",
+      "name": "FeSetRound",
       "args": [
         { "class": "GeneralReg64", "usage": "def_early_clobber" },
         { "class": "Mem16", "usage": "def_early_clobber" },
@@ -290,32 +290,32 @@
         { "class": "CL", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFeSetRound",
-      "mnemo": "MACRO_FE_SET_ROUND"
+      "asm": "FeSetRound",
+      "mnemo": "FE_SET_ROUND"
     },
     {
-      "name": "MacroFeSetRoundImmTranslate",
+      "name": "FeSetRoundImmTranslate",
       "args": [
         { "class": "Mem16", "usage": "def_early_clobber" },
         { "class": "Mem32", "usage": "def_early_clobber" },
         { "class": "Imm8" }
       ],
-      "asm": "MacroFeSetRoundImmTranslate",
-      "mnemo": "MACRO_FE_SET_ROUND"
+      "asm": "FeSetRoundImmTranslate",
+      "mnemo": "FE_SET_ROUND"
     },
     {
-      "name": "MacroFeqFloat32",
+      "name": "FeqFloat32",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use_def" },
         { "class": "FpReg32", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFeq<intrinsics::Float32>",
-      "mnemo": "MACRO_FEQ_F32"
+      "asm": "Feq<Float32>",
+      "mnemo": "FEQ_F32"
     },
     {
-      "name": "MacroFeqFloat32AVX",
+      "name": "FeqFloat32AVX",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use" },
@@ -323,22 +323,22 @@
         { "class": "FpReg32", "usage": "def" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFeqAVX<intrinsics::Float32>",
-      "mnemo": "MACRO_FEQ_F32"
+      "asm": "FeqAVX<Float32>",
+      "mnemo": "FEQ_F32"
     },
     {
-      "name": "MacroFeqFloat64",
+      "name": "FeqFloat64",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" },
         { "class": "FpReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFeq<intrinsics::Float64>",
-      "mnemo": "MACRO_FEQ_F64"
+      "asm": "Feq<Float64>",
+      "mnemo": "FEQ_F64"
     },
     {
-      "name": "MacroFeqFloat64AVX",
+      "name": "FeqFloat64AVX",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use" },
@@ -346,22 +346,22 @@
         { "class": "FpReg64", "usage": "def" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFeqAVX<intrinsics::Float64>",
-      "mnemo": "MACRO_FEQ_F64"
+      "asm": "FeqAVX<Float64>",
+      "mnemo": "FEQ_F64"
     },
     {
-      "name": "MacroFleFloat32",
+      "name": "FleFloat32",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use_def" },
         { "class": "FpReg32", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFle<intrinsics::Float32>",
-      "mnemo": "MACRO_FLE_F32"
+      "asm": "Fle<Float32>",
+      "mnemo": "FLE_F32"
     },
     {
-      "name": "MacroFleFloat32AVX",
+      "name": "FleFloat32AVX",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use" },
@@ -369,22 +369,22 @@
         { "class": "FpReg32", "usage": "def" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFleAVX<intrinsics::Float32>",
-      "mnemo": "MACRO_FLE_F32"
+      "asm": "FleAVX<Float32>",
+      "mnemo": "FLE_F32"
     },
     {
-      "name": "MacroFleFloat64",
+      "name": "FleFloat64",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" },
         { "class": "FpReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFle<intrinsics::Float64>",
-      "mnemo": "MACRO_FLE_F64"
+      "asm": "Fle<Float64>",
+      "mnemo": "FLE_F64"
     },
     {
-      "name": "MacroFleFloat64AVX",
+      "name": "FleFloat64AVX",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use" },
@@ -392,22 +392,22 @@
         { "class": "FpReg64", "usage": "def" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFleAVX<intrinsics::Float64>",
-      "mnemo": "MACRO_FLE_F64"
+      "asm": "FleAVX<Float64>",
+      "mnemo": "FLE_F64"
     },
     {
-      "name": "MacroFltFloat32",
+      "name": "FltFloat32",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use_def" },
         { "class": "FpReg32", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFlt<intrinsics::Float32>",
-      "mnemo": "MACRO_FLT_F32"
+      "asm": "Flt<Float32>",
+      "mnemo": "FLT_F32"
     },
     {
-      "name": "MacroFltFloat32AVX",
+      "name": "FltFloat32AVX",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use" },
@@ -415,22 +415,22 @@
         { "class": "FpReg32", "usage": "def" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFltAVX<intrinsics::Float32>",
-      "mnemo": "MACRO_FLT_F32"
+      "asm": "FltAVX<Float32>",
+      "mnemo": "FLT_F32"
     },
     {
-      "name": "MacroFltFloat64",
+      "name": "FltFloat64",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" },
         { "class": "FpReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFlt<intrinsics::Float64>",
-      "mnemo": "MACRO_FLT_F64"
+      "asm": "Flt<Float64>",
+      "mnemo": "FLT_F64"
     },
     {
-      "name": "MacroFltFloat64AVX",
+      "name": "FltFloat64AVX",
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use" },
@@ -438,43 +438,8 @@
         { "class": "FpReg64", "usage": "def" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroFltAVX<intrinsics::Float64>",
-      "mnemo": "MACRO_FLT_F64"
-    },
-    {
-      "name": "MacroNanBoxFloat32",
-      "args": [
-        { "class": "FpReg64", "usage": "use_def" }
-      ],
-      "asm": "MacroNanBox<intrinsics::Float32>",
-      "mnemo": "MACRO_BOX_F32"
-    },
-    {
-      "name": "MacroNanBoxFloat32AVX",
-      "args": [
-        { "class": "FpReg64", "usage": "def" },
-        { "class": "FpReg32", "usage": "use" }
-      ],
-      "asm": "MacroNanBoxAVX<intrinsics::Float32>",
-      "mnemo": "MACRO_BOX_F32"
-    },
-    {
-      "name": "MacroUnboxNanFloat32",
-      "args": [
-        { "class": "FpReg32", "usage": "def" },
-        { "class": "FpReg64", "usage": "use_def" }
-      ],
-      "asm": "MacroUnboxNan<intrinsics::Float32>",
-      "mnemo": "MACRO_UNBOX_F32"
-    },
-    {
-      "name": "MacroUnboxNanFloat32AVX",
-      "args": [
-        { "class": "FpReg32", "usage": "def" },
-        { "class": "FpReg64", "usage": "use_def" }
-      ],
-      "asm": "MacroUnboxNanAVX<intrinsics::Float32>",
-      "mnemo": "MACRO_UNBOX_F32"
+      "asm": "FltAVX<Float64>",
+      "mnemo": "FLT_F64"
     },
     {
       "name": "MaxInt64",
@@ -484,8 +449,8 @@
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroMax<int64_t>",
-      "mnemo": "MACRO_MAX_I64"
+      "asm": "Max<int64_t>",
+      "mnemo": "MAX_I64"
     },
     {
       "name": "MaxUInt64",
@@ -495,8 +460,8 @@
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroMax<uint64_t>",
-      "mnemo": "MACRO_MAX_U64"
+      "asm": "Max<uint64_t>",
+      "mnemo": "MAX_U64"
     },
     {
       "name": "MinInt64",
@@ -506,8 +471,8 @@
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroMin<int64_t>",
-      "mnemo": "MACRO_MIN_I64"
+      "asm": "Min<int64_t>",
+      "mnemo": "MIN_I64"
     },
     {
       "name": "MinUInt64",
@@ -517,16 +482,33 @@
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroMin<uint64_t>",
-      "mnemo": "MACRO_MIN_U64"
+      "asm": "Min<uint64_t>",
+      "mnemo": "MIN_U64"
+    },
+    {
+      "name": "NanBoxFloat32",
+      "args": [
+        { "class": "FpReg64", "usage": "use_def" }
+      ],
+      "asm": "NanBox<Float32>",
+      "mnemo": "BOX_F32"
+    },
+    {
+      "name": "NanBoxFloat32AVX",
+      "args": [
+        { "class": "FpReg64", "usage": "def" },
+        { "class": "FpReg32", "usage": "use" }
+      ],
+      "asm": "NanBoxAVX<Float32>",
+      "mnemo": "BOX_F32"
     },
     {
       "name": "Orcb",
       "args": [
         { "class": "FpReg64", "usage": "use_def" }
       ],
-      "asm": "MacroOrcb",
-      "mnemo": "MACRO_ORCB"
+      "asm": "Orcb",
+      "mnemo": "ORCB"
     },
     {
       "name": "OrcbAVX",
@@ -534,94 +516,94 @@
         { "class": "FpReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use" }
       ],
-      "asm": "MacroOrcbAVX",
-      "mnemo": "MACRO_ORCB"
+      "asm": "OrcbAVX",
+      "mnemo": "ORCB"
     },
     {
-      "name": "RemInt8",
+      "name": "RemI8RiscV",
       "args": [
         { "class": "GeneralReg8", "usage": "use" },
         { "class": "AX", "usage": "use_def" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroRem<int8_t>",
-      "mnemo": "MACRO_REM8"
+      "asm": "RemRiscV<int8_t>",
+      "mnemo": "REM_I8_RISCV"
     },
     {
-      "name": "RemInt16",
+      "name": "RemI16RiscV",
       "args": [
         { "class": "GeneralReg16", "usage": "use" },
         { "class": "AX", "usage": "use_def" },
         { "class": "DX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroRem<int16_t>",
-      "mnemo": "MACRO_REM16"
+      "asm": "RemRiscV<int16_t>",
+      "mnemo": "REM_I16_RISCV"
     },
     {
-      "name": "RemInt32",
+      "name": "RemI32RiscV",
       "args": [
         { "class": "GeneralReg32", "usage": "use" },
         { "class": "EAX", "usage": "use_def" },
         { "class": "EDX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroRem<int32_t>",
-      "mnemo": "MACRO_REM32"
+      "asm": "RemRiscV<int32_t>",
+      "mnemo": "REM_I32_RISCV"
     },
     {
-      "name": "RemInt64",
+      "name": "RemI64RiscV",
       "args": [
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "EAX", "usage": "use_def" },
         { "class": "EDX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroRem<int64_t>",
-      "mnemo": "MACRO_REM64"
+      "asm": "RemRiscV<int64_t>",
+      "mnemo": "REM_I64_RISCV"
     },
     {
-      "name": "RemUInt8",
+      "name": "RemU8RiscV",
       "args": [
         { "class": "GeneralReg8", "usage": "use" },
         { "class": "AX", "usage": "use_def" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroRem<uint8_t>",
-      "mnemo": "MACRO_UREM8"
+      "asm": "RemRiscV<uint8_t>",
+      "mnemo": "REM_U8_RISCV"
     },
     {
-      "name": "RemUInt16",
+      "name": "RemU16RiscV",
       "args": [
         { "class": "GeneralReg16", "usage": "use" },
         { "class": "AX", "usage": "use_def" },
         { "class": "DX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroRem<uint16_t>",
-      "mnemo": "MACRO_UREM16"
+      "asm": "RemRiscV<uint16_t>",
+      "mnemo": "REM_U16_RISCV"
     },
     {
-      "name": "RemUInt32",
+      "name": "RemU32RiscV",
       "args": [
         { "class": "GeneralReg32", "usage": "use" },
         { "class": "EAX", "usage": "use_def" },
         { "class": "EDX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroRem<uint32_t>",
-      "mnemo": "MACRO_UREM32"
+      "asm": "RemRiscV<uint32_t>",
+      "mnemo": "REM_U32_RISCV"
     },
     {
-      "name": "RemUInt64",
+      "name": "RemU64RiscV",
       "args": [
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "EAX", "usage": "use_def" },
         { "class": "EDX", "usage": "def_early_clobber" },
         { "class": "FLAGS", "usage": "def" }
       ],
-      "asm": "MacroRem<uint64_t>",
-      "mnemo": "MACRO_UREM64"
+      "asm": "RemRiscV<uint64_t>",
+      "mnemo": "REM_U64_RISCV"
     },
     {
       "name": "Sh1add",
@@ -629,8 +611,8 @@
         { "class": "GeneralReg64", "usage": "use_def" },
         { "class": "GeneralReg64", "usage": "use" }
       ],
-      "asm": "MacroSh1add",
-      "mnemo": "MACRO_SH1ADD"
+      "asm": "Sh1add",
+      "mnemo": "SH1ADD"
     },
     {
       "name": "Sh1adduw",
@@ -638,8 +620,8 @@
         { "class": "GeneralReg64", "usage": "use_def" },
         { "class": "GeneralReg64", "usage": "use" }
       ],
-      "asm": "MacroSh1adduw",
-      "mnemo": "MACRO_SH1ADDUW"
+      "asm": "Sh1adduw",
+      "mnemo": "SH1ADDUW"
     },
     {
       "name": "Sh2add",
@@ -647,8 +629,8 @@
         { "class": "GeneralReg64", "usage": "use_def" },
         { "class": "GeneralReg64", "usage": "use" }
       ],
-      "asm": "MacroSh2add",
-      "mnemo": "MACRO_SH2ADD"
+      "asm": "Sh2add",
+      "mnemo": "SH2ADD"
     },
     {
       "name": "Sh2adduw",
@@ -656,8 +638,8 @@
         { "class": "GeneralReg64", "usage": "use_def" },
         { "class": "GeneralReg64", "usage": "use" }
       ],
-      "asm": "MacroSh2adduw",
-      "mnemo": "MACRO_SH2ADDUW"
+      "asm": "Sh2adduw",
+      "mnemo": "SH2ADDUW"
     },
     {
       "name": "Sh3add",
@@ -665,8 +647,8 @@
         { "class": "GeneralReg64", "usage": "use_def" },
         { "class": "GeneralReg64", "usage": "use" }
       ],
-      "asm": "MacroSh3add",
-      "mnemo": "MACRO_SH3ADD"
+      "asm": "Sh3add",
+      "mnemo": "SH3ADD"
     },
     {
       "name": "Sh3adduw",
@@ -674,8 +656,26 @@
         { "class": "GeneralReg64", "usage": "use_def" },
         { "class": "GeneralReg64", "usage": "use" }
       ],
-      "asm": "MacroSh3adduw",
-      "mnemo": "MACRO_SH3ADDUW"
+      "asm": "Sh3adduw",
+      "mnemo": "SH3ADDUW"
+    },
+    {
+      "name": "UnboxNanFloat32",
+      "args": [
+        { "class": "FpReg32", "usage": "def" },
+        { "class": "FpReg64", "usage": "use_def" }
+      ],
+      "asm": "UnboxNan<Float32>",
+      "mnemo": "UNBOX_F32"
+    },
+    {
+      "name": "UnboxNanFloat32AVX",
+      "args": [
+        { "class": "FpReg32", "usage": "def" },
+        { "class": "FpReg64", "usage": "use_def" }
+      ],
+      "asm": "UnboxNanAVX<Float32>",
+      "mnemo": "UNBOX_F32"
     }
   ]
 }
diff --git a/intrinsics/riscv64_to_x86_64/text_assembler.h b/intrinsics/riscv64_to_x86_64/text_assembler.h
index a157f3f7..07526060 100644
--- a/intrinsics/riscv64_to_x86_64/text_assembler.h
+++ b/intrinsics/riscv64_to_x86_64/text_assembler.h
@@ -19,13 +19,14 @@
 
 #include <stdio.h>
 
-#include "berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h"
+#include "berberis/device_arch_info/x86_64/device_arch_info.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_or_x86_64.h"
 
 namespace berberis {
 
-class TextAssembler : public x86_32_and_x86_64::TextAssembler<TextAssembler> {
+class TextAssembler : public x86_32_or_x86_64::TextAssembler<TextAssembler> {
  public:
-  using BaseAssembler = x86_32_and_x86_64::TextAssembler<TextAssembler>;
+  using BaseAssembler = x86_32_or_x86_64::TextAssembler<TextAssembler>;
   using FinalAssembler = TextAssembler;
 
   TextAssembler(int indent, FILE* out) : BaseAssembler(indent, out) {}
diff --git a/jni/Android.bp b/jni/Android.bp
index 21dca9c0..d76c7c8f 100644
--- a/jni/Android.bp
+++ b/jni/Android.bp
@@ -19,7 +19,7 @@ package {
 }
 
 python_binary_host {
-    name: "berberis_gen_jni_trampolines",
+    name: "gen_jni_trampolines",
     main: "gen_jni_trampolines.py",
     srcs: ["gen_jni_trampolines.py"],
 }
@@ -28,8 +28,8 @@ genrule {
     name: "libberberis_jni_gen_headers",
     out: ["jni_trampolines-inl.h"],
     srcs: ["api.json"],
-    tools: ["berberis_gen_jni_trampolines"],
-    cmd: "$(location berberis_gen_jni_trampolines) $(out) $(in)",
+    tools: ["gen_jni_trampolines"],
+    cmd: "$(location gen_jni_trampolines) $(out) $(in)",
 }
 
 cc_library_headers {
@@ -63,6 +63,7 @@ cc_defaults {
         "libberberis_guest_loader_headers",
         "libberberis_jni_headers",
         "libberberis_native_bridge_headers",
+        "libberberis_guest_os_primitives_headers",
         "libberberis_guest_state_headers",
         "libberberis_runtime_primitives_headers",
     ],
diff --git a/jni/gen_jni_trampolines.py b/jni/gen_jni_trampolines.py
old mode 100755
new mode 100644
diff --git a/jni/include/berberis/jni/jni_trampolines.h b/jni/include/berberis/jni/jni_trampolines.h
index 3a371895..70d240b9 100644
--- a/jni/include/berberis/jni/jni_trampolines.h
+++ b/jni/include/berberis/jni/jni_trampolines.h
@@ -29,7 +29,6 @@ HostCode WrapGuestJNIFunction(GuestAddr pc,
                               const char* shorty,
                               const char* name,
                               bool has_jnienv_and_jobject);
-HostCode WrapGuestJNIOnLoad(GuestAddr pc);
 
 GuestType<JNIEnv*> ToGuestJNIEnv(JNIEnv* host_jni_env);
 JNIEnv* ToHostJNIEnv(GuestType<JNIEnv*> guest_jni_env);
@@ -37,6 +36,8 @@ JNIEnv* ToHostJNIEnv(GuestType<JNIEnv*> guest_jni_env);
 GuestType<JavaVM*> ToGuestJavaVM(JavaVM* host_java_vm);
 JavaVM* ToHostJavaVM(GuestType<JavaVM*> guest_java_vm);
 
+void InitializeJNI();
+
 }  // namespace berberis
 
 #endif  // BERBERIS_ANDROID_API_JNI_JNI_TRAMPOLINES_H_
diff --git a/jni/jni_trampolines.cc b/jni/jni_trampolines.cc
index 899a7232..a6279d75 100644
--- a/jni/jni_trampolines.cc
+++ b/jni/jni_trampolines.cc
@@ -33,10 +33,12 @@
 #include "berberis/guest_abi/guest_arguments.h"
 #include "berberis/guest_abi/guest_params.h"
 #include "berberis/guest_abi/guest_type.h"
+#include "berberis/guest_os_primitives/guest_thread.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/guest_state/guest_state.h"
 #include "berberis/native_bridge/jmethod_shorty.h"
 #include "berberis/runtime_primitives/host_code.h"
+#include "berberis/runtime_primitives/known_guest_function_wrapper.h"
 #include "berberis/runtime_primitives/runtime_library.h"
 
 #include "guest_jni_trampolines.h"
@@ -253,6 +255,11 @@ JavaVM* g_host_java_vm;
 // from this map.
 std::map<pid_t, JNIEnvMapping> g_jni_env_mappings;
 
+void RemoveJNIEnvMappingForTid(pid_t tid) {
+  std::lock_guard<std::mutex> lock(g_jni_guard_mutex);
+  g_jni_env_mappings.erase(tid);
+}
+
 void DoJavaVMTrampoline_DestroyJavaVM(HostCode /* callee */, ProcessState* state) {
   using PFN_callee = decltype(std::declval<JavaVM>().functions->DestroyJavaVM);
   auto [arg_vm] = GuestParamsValues<PFN_callee>(state);
@@ -437,4 +444,23 @@ JavaVM* ToHostJavaVM(GuestType<JavaVM*> guest_java_vm) {
   return ToHostAddr(guest_java_vm);
 }
 
+namespace {
+
+GuestThreadExitListenerFn g_next_guest_thread_exit_listener = nullptr;
+
+void JNIGuestThreadListener(pid_t tid) {
+  RemoveJNIEnvMappingForTid(tid);
+  if (g_next_guest_thread_exit_listener != nullptr) {
+    g_next_guest_thread_exit_listener(tid);
+  }
+}
+
+}  // namespace
+
+void InitializeJNI() {
+  RegisterKnownGuestFunctionWrapper("JNI_OnLoad", WrapGuestJNIOnLoad);
+  CHECK(g_next_guest_thread_exit_listener == nullptr);
+  g_next_guest_thread_exit_listener = RegisterGuestThreadExitListener(JNIGuestThreadListener);
+}
+
 }  // namespace berberis
diff --git a/lite_translator/Android.bp b/lite_translator/Android.bp
index e1fe9ee5..c062ac17 100644
--- a/lite_translator/Android.bp
+++ b/lite_translator/Android.bp
@@ -49,6 +49,7 @@ cc_library_static {
     srcs: [
         "riscv64_to_x86_64/lite_translate_region.cc",
         "riscv64_to_x86_64/lite_translator.cc",
+        "riscv64_to_x86_64/lite_translator_demultiplexers.cc",
     ],
 }
 
diff --git a/lite_translator/riscv64_to_x86_64/call_intrinsic.h b/lite_translator/riscv64_to_x86_64/call_intrinsic.h
index 75d4f453..1e20fcfa 100644
--- a/lite_translator/riscv64_to_x86_64/call_intrinsic.h
+++ b/lite_translator/riscv64_to_x86_64/call_intrinsic.h
@@ -46,10 +46,7 @@ constexpr int8_t kRegIsNotOnStack = -1;
 // Map from register number to offset in CallIntrinsic save area. Counted in 8-byte slots.
 inline constexpr auto kRegOffsetsOnStack = []() {
   std::array<int8_t, 16> regs_on_stack = {};
-  // regs_on_stack.fill(kRegIsNotOnStack); - needs C++20
-  for (auto& num : regs_on_stack) {
-    num = kRegIsNotOnStack;
-  }
+  regs_on_stack.fill(kRegIsNotOnStack);
 
   int8_t stack_allocation_size = 0;
   for (auto reg : kCallerSavedRegs) {
@@ -81,10 +78,7 @@ constexpr x86_64::Assembler::XMMRegister kCallerSavedXMMRegs[] = {
 // Map from register number to offset in CallIntrinsic save area. Counted in 8-byte slots.
 inline constexpr auto kSimdRegOffsetsOnStack = []() {
   std::array<int8_t, 16> simd_regs_on_stack = {};
-  // simd_regs_on_stack.fill(kRegIsNotOnStack); - needs C++20
-  for (auto& num : simd_regs_on_stack) {
-    num = kRegIsNotOnStack;
-  }
+  simd_regs_on_stack.fill(kRegIsNotOnStack);
 
   int8_t stack_allocation_size = AlignUp(std::size(kCallerSavedRegs), 2);
   for (auto reg : kCallerSavedXMMRegs) {
diff --git a/lite_translator/riscv64_to_x86_64/inline_intrinsic.h b/lite_translator/riscv64_to_x86_64/inline_intrinsic.h
index 2d581b60..504f4cfe 100644
--- a/lite_translator/riscv64_to_x86_64/inline_intrinsic.h
+++ b/lite_translator/riscv64_to_x86_64/inline_intrinsic.h
@@ -205,18 +205,11 @@ class TryBindingBasedInlineIntrinsic {
             typename Result,
             typename Callback,
             typename... Args>
-  friend constexpr Result intrinsics::bindings::ProcessBindings(Callback callback,
-                                                                Result def_result,
-                                                                Args&&... args);
-  template <auto kIntrinsicTemplateName,
-            auto kMacroInstructionTemplateName,
-            auto kMnemo,
-            typename GetOpcode,
-            typename kCPUIDRestrictionTemplateValue,
-            typename kPreciseNanOperationsHandlingTemplateValue,
-            bool kSideEffectsTemplateValue,
-            typename... Types>
-  friend class intrinsics::bindings::AsmCallInfo;
+  friend constexpr Result x86_64::intrinsics::bindings::ProcessBindings(Callback callback,
+                                                                        Result def_result,
+                                                                        Args&&... args);
+  template <StringLiteral kIntrinsic, typename... Types>
+  friend class intrinsics::bindings::IntrinsicBindingInfo;
 
   TryBindingBasedInlineIntrinsic() = delete;
   TryBindingBasedInlineIntrinsic(const TryBindingBasedInlineIntrinsic&) = delete;
@@ -236,48 +229,58 @@ class TryBindingBasedInlineIntrinsic {
         input_args_(std::tuple{args...}),
         success_(intrinsics::bindings::ProcessBindings<
                  kFunction,
-                 typename MacroAssembler<x86_64::Assembler>::MacroAssemblers,
+                 typename MacroAssembler<x86_64::Assembler>::Assemblers,
                  bool,
                  TryBindingBasedInlineIntrinsic&>(*this, false)) {}
   operator bool() { return success_; }
 
-  template <typename AsmCallInfo>
-  std::optional<bool> /*ProcessBindingsClient*/ operator()(AsmCallInfo asm_call_info) {
-    static_assert(std::is_same_v<decltype(kFunction), typename AsmCallInfo::IntrinsicType>);
-    static_assert(std::is_same_v<typename AsmCallInfo::PreciseNanOperationsHandling,
+  template <typename IntrinsicBindingInfo>
+  std::optional<bool> /*ProcessBindingsClient*/ operator()(IntrinsicBindingInfo asm_call_info) {
+    static_assert(
+        std::is_same_v<decltype(kFunction), typename IntrinsicBindingInfo::IntrinsicType>);
+    static_assert(std::is_same_v<typename IntrinsicBindingInfo::PreciseNanOperationsHandling,
                                  intrinsics::bindings::NoNansOperation>);
-    using CPUIDRestriction = AsmCallInfo::CPUIDRestriction;
-    if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX>) {
+    using CPUIDRestriction = IntrinsicBindingInfo::CPUIDRestriction;
+    if constexpr (std::is_same_v<CPUIDRestriction, x86_32_or_x86_64::device_arch_info::HasAVX>) {
       if (!host_platform::kHasAVX) {
         return {};
       }
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        x86_32_or_x86_64::device_arch_info::HasBMI>) {
       if (!host_platform::kHasBMI) {
         return {};
       }
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        x86_32_or_x86_64::device_arch_info::HasFMA>) {
+      if (!host_platform::kHasFMA) {
+        return {};
+      }
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        x86_32_or_x86_64::device_arch_info::HasLZCNT>) {
       if (!host_platform::kHasLZCNT) {
         return {};
       }
-    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>) {
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        x86_32_or_x86_64::device_arch_info::HasPOPCNT>) {
       if (!host_platform::kHasPOPCNT) {
         return {};
       }
     } else if constexpr (std::is_same_v<CPUIDRestriction,
-                                        intrinsics::bindings::NoCPUIDRestriction>) {
+                                        x86_32_or_x86_64::device_arch_info::NoCPUIDRestriction>) {
       // No restrictions. Do nothing.
     } else {
-      static_assert(kDependentValueFalse<AsmCallInfo::kCPUIDRestriction>);
+      static_assert(kDependentValueFalse<IntrinsicBindingInfo::kCPUIDRestriction>);
     }
     std::apply(
-        AsmCallInfo::kMacroInstruction,
-        std::tuple_cat(std::tuple<MacroAssembler<x86_64::Assembler>&>{as_},
-                       AsmCallInfo::template MakeTuplefromBindings<TryBindingBasedInlineIntrinsic&>(
-                           *this, asm_call_info)));
-    if constexpr (std::tuple_size_v<typename AsmCallInfo::OutputArguments> == 0) {
+        IntrinsicBindingInfo::kEmitInsnFunc,
+        std::tuple_cat(
+            std::tuple<MacroAssembler<x86_64::Assembler>&>{as_},
+            IntrinsicBindingInfo::template MakeTuplefromBindings<TryBindingBasedInlineIntrinsic&>(
+                *this, asm_call_info)));
+    if constexpr (std::tuple_size_v<typename IntrinsicBindingInfo::OutputArguments> == 0) {
       // No return value. Do nothing.
-    } else if constexpr (std::tuple_size_v<typename AsmCallInfo::OutputArguments> == 1) {
-      using ReturnType = std::tuple_element_t<0, typename AsmCallInfo::OutputArguments>;
+    } else if constexpr (std::tuple_size_v<typename IntrinsicBindingInfo::OutputArguments> == 1) {
+      using ReturnType = std::tuple_element_t<0, typename IntrinsicBindingInfo::OutputArguments>;
       if constexpr (std::is_integral_v<ReturnType>) {
         if (result_reg_ != x86_64::Assembler::no_register) {
           Mov<ReturnType>(as_, result_, result_reg_);
@@ -308,95 +311,108 @@ class TryBindingBasedInlineIntrinsic {
         static_assert(kDependentTypeFalse<ReturnType>);
       }
     } else {
-      static_assert(kDependentTypeFalse<typename AsmCallInfo::OutputArguments>);
+      static_assert(kDependentTypeFalse<typename IntrinsicBindingInfo::OutputArguments>);
     }
     return {true};
   }
 
-  template <typename ArgBinding, typename AsmCallInfo>
-  auto /*MakeTuplefromBindingsClient*/ operator()(ArgTraits<ArgBinding>, AsmCallInfo) {
-    static constexpr const auto& arg_info = ArgTraits<ArgBinding>::arg_info;
-    if constexpr (arg_info.arg_type == ArgInfo::IMM_ARG) {
-      return ProcessArgInput<ArgBinding, AsmCallInfo>(reg_alloc_);
+  template <typename ArgBinding, typename OperandInfo, typename IntrinsicBindingInfo>
+  auto /*MakeTuplefromBindingsClient*/ operator()(IntrinsicBindingInfo) {
+    if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IMM_ARG) {
+      return ProcessArgInput<ArgBinding, OperandInfo, IntrinsicBindingInfo>(reg_alloc_);
     } else {
-      using RegisterClass = typename ArgTraits<ArgBinding>::RegisterClass;
-      if constexpr (RegisterClass::kAsRegister == 'x') {
-        return ProcessArgInput<ArgBinding, AsmCallInfo>(simd_reg_alloc_);
+      using RegisterClass = typename OperandInfo::Class;
+      if constexpr (device_arch_info::kIsFLAGS<OperandInfo>) {
+        return ProcessArgInput<ArgBinding, OperandInfo, IntrinsicBindingInfo>(nullptr);
+      } else if constexpr (RegisterClass::kAsRegister == 'x') {
+        return ProcessArgInput<ArgBinding, OperandInfo, IntrinsicBindingInfo>(simd_reg_alloc_);
       } else {
-        return ProcessArgInput<ArgBinding, AsmCallInfo>(reg_alloc_);
+        return ProcessArgInput<ArgBinding, OperandInfo, IntrinsicBindingInfo>(reg_alloc_);
       }
     }
   }
 
-  template <typename ArgBinding, typename AsmCallInfo, typename RegAllocForArg>
+  template <typename ArgBinding,
+            typename OperandInfo,
+            typename IntrinsicBindingInfo,
+            typename RegAllocForArg>
   auto ProcessArgInput(RegAllocForArg&& reg_alloc) {
-    static constexpr const auto& arg_info = ArgTraits<ArgBinding>::arg_info;
-    if constexpr (arg_info.arg_type == ArgInfo::IMM_ARG) {
-      return std::tuple{std::get<arg_info.from>(input_args_)};
+    if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IMM_ARG) {
+      return std::tuple{std::get<ArgBinding::kArgInfo.from>(input_args_)};
     } else {
-      using RegisterClass = typename ArgTraits<ArgBinding>::RegisterClass;
-      using Usage = typename ArgTraits<ArgBinding>::Usage;
-      if constexpr (arg_info.arg_type == ArgInfo::IN_ARG) {
-        using Type = std::tuple_element_t<arg_info.from, typename AsmCallInfo::InputArguments>;
+      using RegisterClass = typename OperandInfo::Class;
+      static constexpr auto kUsage = OperandInfo::kUsage;
+      if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IN_ARG) {
+        using Type = std::tuple_element_t<ArgBinding::kArgInfo.from,
+                                          typename IntrinsicBindingInfo::InputArguments>;
         if constexpr (RegisterClass::kAsRegister == 'x' && std::is_integral_v<Type>) {
           auto reg = reg_alloc();
-          Mov<typename TypeTraits<int64_t>::Float>(as_, reg, std::get<arg_info.from>(input_args_));
+          Mov<typename TypeTraits<int64_t>::Float>(
+              as_, reg, std::get<ArgBinding::kArgInfo.from>(input_args_));
           return std::tuple{reg};
         } else {
-          static_assert(std::is_same_v<Usage, intrinsics::bindings::Use>);
-          static_assert(!RegisterClass::kIsImplicitReg);
-          return std::tuple{std::get<arg_info.from>(input_args_)};
+          static_assert(kUsage == device_arch_info::kUse);
+          static_assert(!device_arch_info::kIsImplicitReg<OperandInfo>);
+          return std::tuple{std::get<ArgBinding::kArgInfo.from>(input_args_)};
         }
-      } else if constexpr (arg_info.arg_type == ArgInfo::IN_OUT_ARG) {
-        using Type = std::tuple_element_t<arg_info.from, typename AsmCallInfo::InputArguments>;
-        static_assert(std::is_same_v<Usage, intrinsics::bindings::UseDef>);
-        static_assert(!RegisterClass::kIsImplicitReg);
+      } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IN_OUT_ARG) {
+        using Type = std::tuple_element_t<ArgBinding::kArgInfo.from,
+                                          typename IntrinsicBindingInfo::InputArguments>;
+        static_assert(kUsage == device_arch_info::kUseDef);
+        static_assert(!device_arch_info::kIsImplicitReg<OperandInfo>);
         if constexpr (RegisterClass::kAsRegister == 'x' && std::is_integral_v<Type>) {
           static_assert(std::is_integral_v<
-                        std::tuple_element_t<arg_info.to, typename AsmCallInfo::OutputArguments>>);
+                        std::tuple_element_t<ArgBinding::kArgInfo.to,
+                                             typename IntrinsicBindingInfo::OutputArguments>>);
           CHECK_EQ(result_xmm_reg_, x86_64::Assembler::no_xmm_register);
           result_xmm_reg_ = reg_alloc();
           Mov<typename TypeTraits<int64_t>::Float>(
-              as_, result_xmm_reg_, std::get<arg_info.from>(input_args_));
+              as_, result_xmm_reg_, std::get<ArgBinding::kArgInfo.from>(input_args_));
           return std::tuple{result_xmm_reg_};
         } else {
-          Mov<std::tuple_element_t<arg_info.from, typename AsmCallInfo::InputArguments>>(
-              as_, result_, std::get<arg_info.from>(input_args_));
+          Mov<std::tuple_element_t<ArgBinding::kArgInfo.from,
+                                   typename IntrinsicBindingInfo::InputArguments>>(
+              as_, result_, std::get<ArgBinding::kArgInfo.from>(input_args_));
           return std::tuple{result_};
         }
-      } else if constexpr (arg_info.arg_type == ArgInfo::IN_TMP_ARG) {
+      } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IN_TMP_ARG) {
         if constexpr (RegisterClass::kAsRegister == 'c') {
-          Mov<std::tuple_element_t<arg_info.from, typename AsmCallInfo::InputArguments>>(
-              as_, as_.rcx, std::get<arg_info.from>(input_args_));
+          Mov<std::tuple_element_t<ArgBinding::kArgInfo.from,
+                                   typename IntrinsicBindingInfo::InputArguments>>(
+              as_, as_.rcx, std::get<ArgBinding::kArgInfo.from>(input_args_));
           return std::tuple{};
         } else if constexpr (RegisterClass::kAsRegister == 'a') {
-          Mov<std::tuple_element_t<arg_info.from, typename AsmCallInfo::InputArguments>>(
-              as_, as_.rax, std::get<arg_info.from>(input_args_));
+          Mov<std::tuple_element_t<ArgBinding::kArgInfo.from,
+                                   typename IntrinsicBindingInfo::InputArguments>>(
+              as_, as_.rax, std::get<ArgBinding::kArgInfo.from>(input_args_));
           return std::tuple{};
         } else {
-          static_assert(std::is_same_v<Usage, intrinsics::bindings::UseDef>);
-          static_assert(!RegisterClass::kIsImplicitReg);
+          static_assert(kUsage == device_arch_info::kUseDef);
+          static_assert(!device_arch_info::kIsImplicitReg<OperandInfo>);
           auto reg = reg_alloc();
-          Mov<std::tuple_element_t<arg_info.from, typename AsmCallInfo::InputArguments>>(
-              as_, reg, std::get<arg_info.from>(input_args_));
+          Mov<std::tuple_element_t<ArgBinding::kArgInfo.from,
+                                   typename IntrinsicBindingInfo::InputArguments>>(
+              as_, reg, std::get<ArgBinding::kArgInfo.from>(input_args_));
           return std::tuple{reg};
         }
-      } else if constexpr (arg_info.arg_type == ArgInfo::IN_OUT_TMP_ARG) {
-        using Type = std::tuple_element_t<arg_info.from, typename AsmCallInfo::InputArguments>;
-        static_assert(std::is_same_v<Usage, intrinsics::bindings::UseDef>);
-        static_assert(RegisterClass::kIsImplicitReg);
+      } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::IN_OUT_TMP_ARG) {
+        using Type = std::tuple_element_t<ArgBinding::kArgInfo.from,
+                                          typename IntrinsicBindingInfo::InputArguments>;
+        static_assert(kUsage == device_arch_info::kUseDef);
+        static_assert(device_arch_info::kIsImplicitReg<OperandInfo>);
         if constexpr (RegisterClass::kAsRegister == 'a') {
           CHECK_EQ(result_reg_, x86_64::Assembler::no_register);
-          Mov<Type>(as_, as_.rax, std::get<arg_info.from>(input_args_));
+          Mov<Type>(as_, as_.rax, std::get<ArgBinding::kArgInfo.from>(input_args_));
           result_reg_ = as_.rax;
           return std::tuple{};
         } else {
-          static_assert(kDependentValueFalse<arg_info.arg_type>);
+          static_assert(kDependentValueFalse<ArgBinding::kArgInfo>);
         }
-      } else if constexpr (arg_info.arg_type == ArgInfo::OUT_ARG) {
-        using Type = std::tuple_element_t<arg_info.to, typename AsmCallInfo::OutputArguments>;
-        static_assert(std::is_same_v<Usage, intrinsics::bindings::Def> ||
-                      std::is_same_v<Usage, intrinsics::bindings::DefEarlyClobber>);
+      } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::OUT_ARG) {
+        using Type = std::tuple_element_t<ArgBinding::kArgInfo.to,
+                                          typename IntrinsicBindingInfo::OutputArguments>;
+        static_assert(kUsage == device_arch_info::kDef ||
+                      kUsage == device_arch_info::kDefEarlyClobber);
         if constexpr (RegisterClass::kAsRegister == 'a') {
           CHECK_EQ(result_reg_, x86_64::Assembler::no_register);
           result_reg_ = as_.rax;
@@ -406,7 +422,7 @@ class TryBindingBasedInlineIntrinsic {
           result_reg_ = as_.rcx;
           return std::tuple{};
         } else {
-          static_assert(!RegisterClass::kIsImplicitReg);
+          static_assert(!device_arch_info::kIsImplicitReg<OperandInfo>);
           if constexpr (RegisterClass::kAsRegister == 'x' && std::is_integral_v<Type>) {
             CHECK_EQ(result_xmm_reg_, x86_64::Assembler::no_xmm_register);
             result_xmm_reg_ = reg_alloc();
@@ -415,17 +431,17 @@ class TryBindingBasedInlineIntrinsic {
             return std::tuple{result_};
           }
         }
-      } else if constexpr (arg_info.arg_type == ArgInfo::OUT_TMP_ARG) {
+      } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::OUT_TMP_ARG) {
         if constexpr (RegisterClass::kAsRegister == 'd') {
           result_reg_ = as_.rdx;
           return std::tuple{};
         } else {
-          static_assert(kDependentValueFalse<arg_info.arg_type>);
+          static_assert(kDependentValueFalse<ArgBinding::kArgInfo>);
         }
-      } else if constexpr (arg_info.arg_type == ArgInfo::TMP_ARG) {
-        static_assert(std::is_same_v<Usage, intrinsics::bindings::Def> ||
-                      std::is_same_v<Usage, intrinsics::bindings::DefEarlyClobber>);
-        if constexpr (RegisterClass::kAsRegister == 'm') {
+      } else if constexpr (ArgBinding::kArgInfo.arg_type == ArgInfo::TMP_ARG) {
+        static_assert(kUsage == device_arch_info::kDef ||
+                      kUsage == device_arch_info::kDefEarlyClobber);
+        if constexpr (device_arch_info::kIsMemoryOperand<OperandInfo>) {
           if (scratch_arg_ >= config::kScratchAreaSize / config::kScratchAreaSlotSize) {
             FATAL("Only two scratch registers are supported for now");
           }
@@ -433,13 +449,13 @@ class TryBindingBasedInlineIntrinsic {
               .base = as_.rbp,
               .disp = static_cast<int>(offsetof(ThreadState, intrinsics_scratch_area) +
                                        config::kScratchAreaSlotSize * scratch_arg_++)}};
-        } else if constexpr (RegisterClass::kIsImplicitReg) {
+        } else if constexpr (device_arch_info::kIsImplicitReg<OperandInfo>) {
           return std::tuple{};
         } else {
           return std::tuple{reg_alloc()};
         }
       } else {
-        static_assert(kDependentValueFalse<arg_info.arg_type>);
+        static_assert(kDependentValueFalse<ArgBinding::kArgInfo>);
       }
     }
   }
diff --git a/lite_translator/riscv64_to_x86_64/lite_translator.h b/lite_translator/riscv64_to_x86_64/lite_translator.h
index 50407baa..0e23dfe8 100644
--- a/lite_translator/riscv64_to_x86_64/lite_translator.h
+++ b/lite_translator/riscv64_to_x86_64/lite_translator.h
@@ -61,6 +61,17 @@ class LiteTranslator {
   using Float32 = intrinsics::Float32;
   using Float64 = intrinsics::Float64;
 
+  using TemplateTypeId = intrinsics::TemplateTypeId;
+  template <typename Type>
+  static constexpr auto kIdFromType = intrinsics::kIdFromType<Type>;
+  template <auto kEnumValue>
+  using TypeFromId = intrinsics::TypeFromId<kEnumValue>;
+  template <auto ValueParam>
+  using Value = intrinsics::Value<ValueParam>;
+  static constexpr TemplateTypeId IntSizeToTemplateTypeId(uint8_t size, bool is_signed = false) {
+    return intrinsics::IntSizeToTemplateTypeId(size, is_signed);
+  }
+
   explicit LiteTranslator(MachineCode* machine_code,
                           GuestAddr pc,
                           LiteTranslateParams params = LiteTranslateParams{})
@@ -251,9 +262,9 @@ class LiteTranslator {
     SimdRegister result = GetFpReg(reg);
     SimdRegister unboxed_result = AllocTempSimdReg();
     if (host_platform::kHasAVX) {
-      as_.MacroUnboxNanAVX<FloatType>(unboxed_result, result);
+      as_.UnboxNanAVX<FloatType>(unboxed_result, result);
     } else {
-      as_.MacroUnboxNan<FloatType>(unboxed_result, result);
+      as_.UnboxNan<FloatType>(unboxed_result, result);
     }
     return unboxed_result;
   }
@@ -261,10 +272,10 @@ class LiteTranslator {
   template <typename FloatType>
   void NanBoxFpReg(FpRegister value) {
     if (host_platform::kHasAVX) {
-      as_.MacroNanBoxAVX<FloatType>(value, value);
+      as_.NanBoxAVX<FloatType>(value, value);
       return;
     }
-    as_.MacroNanBox<FloatType>(value);
+    as_.NanBox<FloatType>(value);
   }
 
   template <typename FloatType>
@@ -362,6 +373,9 @@ class LiteTranslator {
     }
   }
 
+#ifdef BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER
+#include "berberis/intrinsics/demultiplexer_intrinsics_hooks-inl.h"
+#endif
 #include "berberis/intrinsics/translator_intrinsics_hooks-inl.h"
 
   bool is_region_end_reached() const { return is_region_end_reached_; }
@@ -412,14 +426,14 @@ class LiteTranslator {
     return Assembler::no_xmm_register;
   };
 
-  template <typename IntType, bool aq, bool rl>
-  Register Lr(Register /* addr */) {
+  template <intrinsics::TemplateTypeId IntType, bool aq, bool rl>
+  Register Lr(Register, Value<IntType>, Value<aq>, Value<rl>) {
     Undefined();
     return Assembler::no_register;
   }
 
-  template <typename IntType, bool aq, bool rl>
-  Register Sc(Register /* addr */, Register /* data */) {
+  template <intrinsics::TemplateTypeId IntType, bool aq, bool rl>
+  Register Sc(Register, Register, Value<IntType>, Value<aq>, Value<rl>) {
     Undefined();
     return Assembler::no_register;
   }
@@ -538,7 +552,7 @@ inline void LiteTranslator::SetCsr<CsrName::kFCsr>(uint8_t imm) {
   // to rely on that: it's very subtle and it only affects code generation speed.
   as_.Mov<uint8_t>({.base = Assembler::rbp, .disp = kCsrFieldOffset<CsrName::kFrm>},
                    static_cast<int8_t>(imm >> 5));
-  as_.MacroFeSetExceptionsAndRoundImmTranslate(
+  as_.FeSetExceptionsAndRoundImmTranslate(
       {Assembler::rbp, .disp = static_cast<int>(offsetof(ThreadState, intrinsics_scratch_area))},
       imm);
 }
@@ -553,7 +567,7 @@ inline void LiteTranslator::SetCsr<CsrName::kFCsr>(Register arg) {
   as_.And<uint8_t>(Assembler::rcx, kCsrMask<CsrName::kFrm>);
   as_.Mov<uint8_t>({.base = Assembler::rbp, .disp = kCsrFieldOffset<CsrName::kFrm>},
                    Assembler::rcx);
-  as_.MacroFeSetExceptionsAndRoundTranslate(
+  as_.FeSetExceptionsAndRoundTranslate(
       Assembler::rax,
       {Assembler::rbp, .disp = static_cast<int>(offsetof(ThreadState, intrinsics_scratch_area))},
       Assembler::rax);
diff --git a/lite_translator/riscv64_to_x86_64/lite_translator_demultiplexers.cc b/lite_translator/riscv64_to_x86_64/lite_translator_demultiplexers.cc
new file mode 100644
index 00000000..000f9456
--- /dev/null
+++ b/lite_translator/riscv64_to_x86_64/lite_translator_demultiplexers.cc
@@ -0,0 +1,29 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER
+
+#include "lite_translator.h"
+
+namespace berberis {
+
+#define BERBERIS_INTRINSICS_HOOKS_LISTENER LiteTranslator::
+#include "berberis/intrinsics/demultiplexer_intrinsics_hooks-inl.h"
+#undef BERBERIS_INTRINSICS_HOOKS_LISTENER
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_HOOKS_INLINE_DEMULTIPLEXER
diff --git a/native_bridge/native_bridge.cc b/native_bridge/native_bridge.cc
index dcabb4a8..3f665007 100644
--- a/native_bridge/native_bridge.cc
+++ b/native_bridge/native_bridge.cc
@@ -148,9 +148,9 @@ NdktNativeBridge::~NdktNativeBridge() {}
 
 bool NdktNativeBridge::Initialize(std::string* error_msg) {
   guest_loader_ = berberis::GuestLoader::StartAppProcessInNewThread(error_msg);
-  berberis::RegisterKnownGuestFunctionWrapper("JNI_OnLoad", berberis::WrapGuestJNIOnLoad);
   berberis::RegisterKnownGuestFunctionWrapper("ANativeActivity_onCreate",
                                               berberis::WrapGuestNativeActivityOnCreate);
+  berberis::InitializeJNI();
   return guest_loader_ != nullptr;
 }
 
diff --git a/native_bridge/riscv64/native_bridge.cc b/native_bridge/riscv64/native_bridge.cc
index 2d21ee76..748de5fc 100644
--- a/native_bridge/riscv64/native_bridge.cc
+++ b/native_bridge/riscv64/native_bridge.cc
@@ -23,11 +23,11 @@ const char* kGuestIsa = "riscv64";
 const char* kSupportedLibraryPathSubstring = "/lib/riscv64";
 
 const android::NativeBridgeRuntimeValues kNativeBridgeRuntimeValues = {
-    .os_arch = "riscv64",
-    .cpu_abi = "riscv64",
+    .os_arch = nullptr,
+    .cpu_abi = nullptr,
     .cpu_abi2 = nullptr,
     .supported_abis = nullptr,
     .abi_count = 0,
 };
 
-}  // namespace berberis
\ No newline at end of file
+}  // namespace berberis
diff --git a/runtime/riscv64/translator_x86_64.cc b/runtime/riscv64/translator_x86_64.cc
index 516c45d0..028588c9 100644
--- a/runtime/riscv64/translator_x86_64.cc
+++ b/runtime/riscv64/translator_x86_64.cc
@@ -91,7 +91,7 @@ enum class TranslationGear {
 };
 
 size_t GetExecutableRegionSize(GuestAddr pc) {
-  // With kGuestPageSize=4k we scan at least 1k instructions, which should be enough for a single
+  // With kGuestPageSize>=4k we scan at least 1k instructions, which should be enough for a single
   // region.
   auto [is_exec, exec_size] =
       GuestMapShadow::GetInstance()->GetExecutableRegionSize(pc, config::kGuestPageSize);
diff --git a/runtime_primitives/Android.bp b/runtime_primitives/Android.bp
index 86820c1f..f7036623 100644
--- a/runtime_primitives/Android.bp
+++ b/runtime_primitives/Android.bp
@@ -42,6 +42,7 @@ cc_library_static {
         "code_pool.cc",
         "crash_reporter.cc",
         "exec_region_anonymous.cc",
+        "guest_code_region.cc",
         "guest_function_wrapper_impl.cc",
         "host_entries.cc",
         "host_function_wrapper_impl.cc",
diff --git a/runtime_primitives/guest_code_region.cc b/runtime_primitives/guest_code_region.cc
new file mode 100644
index 00000000..65774540
--- /dev/null
+++ b/runtime_primitives/guest_code_region.cc
@@ -0,0 +1,194 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "berberis/runtime_primitives/guest_code_region.h"
+
+#include <cstddef>
+#include <string>
+
+#include "berberis/base/arena_alloc.h"
+#include "berberis/base/arena_list.h"
+#include "berberis/base/arena_map.h"
+#include "berberis/base/arena_set.h"
+#include "berberis/base/arena_vector.h"
+#include "berberis/base/stringprintf.h"
+#include "berberis/guest_state/guest_addr.h"
+
+namespace berberis {
+
+GuestCodeBasicBlock* GuestCodeRegion::NewBasicBlock(GuestAddr guest_addr,
+                                                    size_t size,
+                                                    const ArenaVector<GuestAddr>& out_edges) {
+  CHECK(!code_region_finalized_);
+  auto [it, inserted] = basic_blocks_.try_emplace(guest_addr, arena_, guest_addr, size, out_edges);
+  CHECK(inserted);
+  branch_targets_.insert(out_edges.begin(), out_edges.end());
+  return &it->second;
+}
+
+void GuestCodeRegion::ResolveEdges() {
+  CHECK(!code_region_finalized_);
+  ValidateRegionBeforeFinalize();
+  SplitBasicBlocks();
+  // SplitBasicBlocks can end up splitting a block
+  // into referenced and unreferenced ones, so it
+  // needs to happen before RemoveUnreferencedBlocks.
+  RemoveUnreachableBlocks();
+  ResolveInEdges();
+  code_region_finalized_ = true;
+}
+
+ArenaSet<GuestAddr> GuestCodeRegion::CollectReachableBranchTargets() const {
+  ArenaSet<GuestAddr> reachable_targets(arena_);
+  ArenaList<GuestAddr> worklist_targets(arena_);
+
+  const GuestAddr kRegionStartAddr = basic_blocks_.begin()->first;
+  const GuestAddr kRegionEndAddr = basic_blocks_.rbegin()->second.end_addr();
+  const size_t kRegionSize = kRegionEndAddr - kRegionStartAddr;
+
+  ArenaVector<bool> visited_target_offsets(kRegionSize, false, arena_);
+
+  worklist_targets.push_back(kRegionStartAddr);
+
+  // Collect reachable branch targets.
+  while (!worklist_targets.empty()) {
+    GuestAddr branch_addr = worklist_targets.front();
+    worklist_targets.pop_front();
+
+    auto it = basic_blocks_.find(branch_addr);
+    if (it == basic_blocks_.end()) {
+      continue;
+    }
+
+    CHECK_GE(branch_addr, kRegionStartAddr);
+    CHECK_LT(branch_addr, kRegionEndAddr);
+    if (visited_target_offsets.at(branch_addr - kRegionStartAddr)) {
+      continue;
+    }
+
+    const auto& basic_block = it->second;
+    worklist_targets.insert(
+        worklist_targets.end(), basic_block.out_edges().begin(), basic_block.out_edges().end());
+    reachable_targets.insert(basic_block.out_edges().begin(), basic_block.out_edges().end());
+    visited_target_offsets[branch_addr - kRegionStartAddr] = true;
+  };
+
+  return reachable_targets;
+}
+
+void GuestCodeRegion::RemoveUnreachableBlocks() {
+  CHECK(!basic_blocks_.empty());
+
+  auto branch_targets = CollectReachableBranchTargets();
+
+  // Remove unreachable basic_blocks.
+  auto bb_it = basic_blocks_.begin();
+  // Always keep the first basic block.
+  ++bb_it;
+
+  while (bb_it != basic_blocks_.end()) {
+    if (branch_targets.contains(bb_it->first)) {
+      ++bb_it;
+    } else {
+      bb_it = basic_blocks_.erase(bb_it);
+    }
+  }
+
+  // Update branch_targets.
+  branch_targets_ = std::move(branch_targets);
+}
+
+void GuestCodeRegion::SplitBasicBlocks() {
+  for (auto branch_target : branch_targets_) {
+    auto it = basic_blocks_.upper_bound(branch_target);
+    if (it == basic_blocks_.begin()) {
+      continue;
+    }
+
+    --it;
+    auto& [guest_addr, code_block] = *it;
+    if (branch_target <= guest_addr || branch_target >= code_block.end_addr()) {
+      // Nothing to split.
+      continue;
+    }
+
+    size_t updated_size = branch_target - code_block.start_addr();
+    size_t new_code_block_size = code_block.size() - updated_size;
+
+    NewBasicBlock(branch_target, new_code_block_size, code_block.out_edges());
+
+    code_block.SetSize(updated_size);
+    code_block.SetOutEdges(ArenaVector<GuestAddr>({branch_target}, arena_));
+  }
+}
+
+void GuestCodeRegion::ResolveInEdges() {
+  for (auto& [source_addr, basic_block] : basic_blocks_) {
+    for (auto target_addr : basic_block.out_edges()) {
+      auto it = basic_blocks_.find(target_addr);
+      if (it != basic_blocks_.end()) {
+        it->second.AddInEdge(source_addr);
+      }
+    }
+  }
+}
+
+void GuestCodeRegion::ValidateRegionBeforeFinalize() const {
+  GuestAddr last_seen_end_addr = kNullGuestAddr;
+  for (const auto& [start_addr, basic_block] : basic_blocks_) {
+    CHECK_GE(start_addr, last_seen_end_addr);
+    last_seen_end_addr = basic_block.end_addr();
+    CHECK(basic_block.in_edges().empty());
+  }
+}
+
+std::string GuestCodeRegion::GetDebugString() const {
+  std::string out;
+  out += StringPrintf("BasicBlocks: { size=%zd, elements=[", basic_blocks_.size());
+  for (const auto& basic_block : basic_blocks_) {
+    out += " ";
+    out += basic_block.second.GetDebugString();
+  }
+
+  out += "]}\n";
+  out += "branch_targets={";
+  for (auto addr : branch_targets_) {
+    out += StringPrintf(" %zx", addr);
+  }
+
+  out += "}";
+
+  return out;
+}
+
+std::string GuestCodeBasicBlock::GetDebugString() const {
+  std::string out = "(";
+  out += StringPrintf("start=%zx, size=0x%zx(%zd), ", start_addr_, size_, size_);
+  out += "in_edges={";
+  for (auto addr : in_edges_) {
+    out += StringPrintf(" %zx", addr);
+  }
+  out += " }, out_edges={";
+
+  for (auto addr : out_edges_) {
+    out += StringPrintf(" %zx", addr);
+  }
+
+  out += " })";
+  return out;
+}
+
+}  // namespace berberis
diff --git a/runtime_primitives/guest_code_region_test.cc b/runtime_primitives/guest_code_region_test.cc
index 367dc030..3ab9263e 100644
--- a/runtime_primitives/guest_code_region_test.cc
+++ b/runtime_primitives/guest_code_region_test.cc
@@ -32,28 +32,28 @@ TEST(GuestCodeRegion, Smoke) {
   EXPECT_TRUE(region.branch_targets().empty());
 
   {
-    // 42 - 50 ->{8, 100}
-    auto* bb = region.NewBasicBlock(42, 8, ArenaVector<GuestAddr>({8, 100}, &arena));
+    // 42 - 50 ->{8, 56, 100}
+    auto* bb = region.NewBasicBlock(42, 8, ArenaVector<GuestAddr>({8, 56, 100}, &arena));
     EXPECT_EQ(bb->start_addr(), 42u);
     EXPECT_EQ(bb->size(), 8u);
     EXPECT_EQ(bb->end_addr(), 50u);
-    EXPECT_THAT(bb->out_edges(), ElementsAre(8, 100));
+    EXPECT_THAT(bb->out_edges(), ElementsAre(8, 56, 100));
     EXPECT_TRUE(bb->in_edges().empty());
   }
 
-  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 100));
+  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 56, 100));
 
   {
-    // 56 - 60 -> {42, 120}
-    auto* bb = region.NewBasicBlock(56, 4, ArenaVector<GuestAddr>({42, 50}, &arena));
+    // 56 - 60 -> {50, 120}
+    auto* bb = region.NewBasicBlock(56, 4, ArenaVector<GuestAddr>({50, 120}, &arena));
     EXPECT_EQ(bb->start_addr(), 56u);
     EXPECT_EQ(bb->size(), 4u);
     EXPECT_EQ(bb->end_addr(), 60u);
-    EXPECT_THAT(bb->out_edges(), ElementsAre(42, 50));
+    EXPECT_THAT(bb->out_edges(), ElementsAre(50, 120));
     EXPECT_TRUE(bb->in_edges().empty());
   }
 
-  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 42, 50, 100));
+  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 50, 56, 100, 120));
 
   region.ResolveEdges();
 
@@ -66,12 +66,12 @@ TEST(GuestCodeRegion, Smoke) {
 
   {
     auto& bb = basic_blocks.at(42);
-    EXPECT_THAT(bb.in_edges(), ElementsAre(56));
+    EXPECT_TRUE(bb.in_edges().empty());
   }
 
   {
     auto& bb = basic_blocks.at(56);
-    EXPECT_TRUE(bb.in_edges().empty());
+    EXPECT_THAT(bb.in_edges(), ElementsAre(42));
   }
 }
 
@@ -118,6 +118,114 @@ TEST(GuestCodeRegion, ResolveEdges) {
   }
 }
 
+TEST(GuestCodeRegion, RemoveUnreachableBlocks) {
+  Arena arena;
+  GuestCodeRegion region(&arena);
+
+  //
+  // Before ResolveEdges:
+  //
+  // bb-1 -> bb-3, external-1
+  // bb-2 -> bb-4, bb-6, external-2
+  // bb-3 -> bb-6
+  // bb-4 -> external-1
+  // bb-5 (5 and 6 are initially one block which reference from bb-3
+  //       splits into two blocks, and since bb-5 after split is not
+  //       referenced it is expected to be removed)
+  // bb-6
+  // bb-7 -> bb-1, bb-2, bb-8
+  // bb-8 -> bb-7, external-3
+  //
+  // In this case block 2 is dangling and expected to be removed
+  // and since block-4 after that also becomes dangling it is also
+  // removed. block-6 though still has an incoming edge from block-3
+  // and left in place, block-5 is also dangling and is removed.
+  //
+  // Blocks 7 and 8 have circular dependencies and shall also be removed.
+  //
+
+  // 1 -> 3
+  region.NewBasicBlock(10, 8, ArenaVector<GuestAddr>({30, 1010}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(30, 1010));
+
+  // 2 -> 4, 6
+  region.NewBasicBlock(20, 8, ArenaVector<GuestAddr>({40, 60, 1020}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(30, 40, 60, 1010, 1020));
+
+  // 3 -> 6
+  region.NewBasicBlock(30, 8, ArenaVector<GuestAddr>({60}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(30, 40, 60, 1010, 1020));
+
+  // 4 ->
+  region.NewBasicBlock(40, 8, ArenaVector<GuestAddr>({1010}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(30, 40, 60, 1010, 1020));
+
+  // 5 + 6 ->
+  region.NewBasicBlock(50, 18, ArenaVector<GuestAddr>({}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(30, 40, 60, 1010, 1020));
+
+  // 7 -> 1, 2, 8
+  region.NewBasicBlock(70, 8, ArenaVector<GuestAddr>({10, 20, 80}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(10, 20, 30, 40, 60, 80, 1010, 1020));
+
+  // 8 -> 2, 7
+  region.NewBasicBlock(80, 8, ArenaVector<GuestAddr>({70, 1030}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(10, 20, 30, 40, 60, 70, 80, 1010, 1020, 1030));
+
+  region.ResolveEdges();
+
+  // After ResolveEdges:
+  //
+  // bb-1 -> bb-3, external-1
+  // bb-3 -> bb-6
+  // bb-6
+  //
+  // We also check that external branches referenced by
+  // removed blocks are not removed from branch_targets.
+
+  auto& basic_blocks = region.basic_blocks();
+  ASSERT_EQ(basic_blocks.size(), 3u);
+  ASSERT_TRUE(basic_blocks.contains(10));
+  ASSERT_TRUE(basic_blocks.contains(30));
+  ASSERT_TRUE(basic_blocks.contains(60));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(30, 60, 1010));
+
+  {
+    auto bb = basic_blocks.at(10);
+    EXPECT_EQ(bb.start_addr(), 10u);
+    EXPECT_EQ(bb.size(), 8u);
+    EXPECT_EQ(bb.end_addr(), 18u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(30, 1010));
+    EXPECT_TRUE(bb.in_edges().empty());
+  }
+
+  {
+    auto bb = basic_blocks.at(30);
+    EXPECT_EQ(bb.start_addr(), 30u);
+    EXPECT_EQ(bb.size(), 8u);
+    EXPECT_EQ(bb.end_addr(), 38u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(60));
+    EXPECT_THAT(bb.in_edges(), ElementsAre(10));
+  }
+
+  {
+    auto bb = basic_blocks.at(60);
+    EXPECT_EQ(bb.start_addr(), 60u);
+    EXPECT_EQ(bb.size(), 8u);
+    EXPECT_EQ(bb.end_addr(), 68u);
+    EXPECT_TRUE(bb.out_edges().empty());
+    EXPECT_THAT(bb.in_edges(), ElementsAre(30));
+  }
+}
+
 TEST(GuestCodeRegion, SplitBasicBlock) {
   Arena arena;
   GuestCodeRegion region(&arena);
@@ -128,20 +236,21 @@ TEST(GuestCodeRegion, SplitBasicBlock) {
   EXPECT_THAT(region.branch_targets(), ElementsAre(110, 150, 220));
 
   // 100 - 120
-  region.NewBasicBlock(100, 20, ArenaVector<GuestAddr>({8, 50, 1000}, &arena));
+  region.NewBasicBlock(100, 20, ArenaVector<GuestAddr>({8, 50, 200, 1000}, &arena));
 
-  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 50, 110, 150, 220, 1000));
+  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 50, 110, 150, 200, 220, 1000));
 
   // 200 - 240
-  region.NewBasicBlock(200, 40, ArenaVector<GuestAddr>({80, 120, 240}, &arena));
+  region.NewBasicBlock(200, 40, ArenaVector<GuestAddr>({80, 100, 120, 240}, &arena));
 
-  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 50, 80, 110, 120, 150, 220, 240, 1000));
+  EXPECT_THAT(region.branch_targets(),
+              ElementsAre(8, 50, 80, 100, 110, 120, 150, 200, 220, 240, 1000));
 
   // 240 - 250
   region.NewBasicBlock(240, 50, ArenaVector<GuestAddr>({10, 210, 230}, &arena));
 
   EXPECT_THAT(region.branch_targets(),
-              ElementsAre(8, 10, 50, 80, 110, 120, 150, 210, 220, 230, 240, 1000));
+              ElementsAre(8, 10, 50, 80, 100, 110, 120, 150, 200, 210, 220, 230, 240, 1000));
 
   region.ResolveEdges();
 
@@ -157,6 +266,9 @@ TEST(GuestCodeRegion, SplitBasicBlock) {
   ASSERT_TRUE(basic_blocks.contains(230));
   ASSERT_TRUE(basic_blocks.contains(240));
 
+  EXPECT_THAT(region.branch_targets(),
+              ElementsAre(8, 10, 50, 80, 100, 110, 120, 150, 200, 210, 220, 230, 240, 1000));
+
   {
     auto bb = basic_blocks.at(42);
     EXPECT_EQ(bb.start_addr(), 42u);
@@ -181,7 +293,7 @@ TEST(GuestCodeRegion, SplitBasicBlock) {
     EXPECT_EQ(bb.size(), 10u);
     EXPECT_EQ(bb.end_addr(), 110u);
     EXPECT_THAT(bb.out_edges(), ElementsAre(110));
-    EXPECT_TRUE(bb.in_edges().empty());
+    EXPECT_THAT(bb.in_edges(), ElementsAre(230));
   }
 
   {
@@ -189,7 +301,7 @@ TEST(GuestCodeRegion, SplitBasicBlock) {
     EXPECT_EQ(bb.start_addr(), 110u);
     EXPECT_EQ(bb.size(), 10u);
     EXPECT_EQ(bb.end_addr(), 120u);
-    EXPECT_THAT(bb.out_edges(), ElementsAre(8, 50, 1000));
+    EXPECT_THAT(bb.out_edges(), ElementsAre(8, 50, 200, 1000));
     EXPECT_THAT(bb.in_edges(), ElementsAre(50, 100));
   }
 
@@ -199,7 +311,7 @@ TEST(GuestCodeRegion, SplitBasicBlock) {
     EXPECT_EQ(bb.size(), 10u);
     EXPECT_EQ(bb.end_addr(), 210u);
     EXPECT_THAT(bb.out_edges(), ElementsAre(210));
-    EXPECT_TRUE(bb.in_edges().empty());
+    EXPECT_THAT(bb.in_edges(), ElementsAre(110));
   }
 
   {
@@ -225,7 +337,7 @@ TEST(GuestCodeRegion, SplitBasicBlock) {
     EXPECT_EQ(bb.start_addr(), 230u);
     EXPECT_EQ(bb.size(), 10u);
     EXPECT_EQ(bb.end_addr(), 240u);
-    EXPECT_THAT(bb.out_edges(), ElementsAre(80, 120, 240));
+    EXPECT_THAT(bb.out_edges(), ElementsAre(80, 100, 120, 240));
     EXPECT_THAT(bb.in_edges(), ElementsAre(220, 240));
   }
 
diff --git a/runtime_primitives/include/berberis/runtime_primitives/guest_code_region.h b/runtime_primitives/include/berberis/runtime_primitives/guest_code_region.h
index c7d3d306..d3632a68 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/guest_code_region.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/guest_code_region.h
@@ -17,6 +17,8 @@
 #ifndef BERBERIS_RUNTIME_PRIMITIVES_GUEST_CODE_REGION_H_
 #define BERBERIS_RUNTIME_PRIMITIVES_GUEST_CODE_REGION_H_
 
+#include <cstddef>
+
 #include "berberis/base/arena_alloc.h"
 #include "berberis/base/arena_map.h"
 #include "berberis/base/arena_set.h"
@@ -45,6 +47,8 @@ class GuestCodeBasicBlock {
   [[nodiscard]] const ArenaVector<GuestAddr>& out_edges() const { return out_edges_; }
   [[nodiscard]] const ArenaVector<GuestAddr>& in_edges() const { return in_edges_; }
 
+  [[nodiscard]] std::string GetDebugString() const;
+
  private:
   const GuestAddr start_addr_;
   size_t size_;
@@ -59,23 +63,10 @@ class GuestCodeRegion {
 
   /* may_discard */ GuestCodeBasicBlock* NewBasicBlock(GuestAddr guest_addr,
                                                        size_t size,
-                                                       const ArenaVector<GuestAddr>& out_edges) {
-    CHECK(!code_region_finalized_);
-    auto [it, inserted] =
-        basic_blocks_.try_emplace(guest_addr, arena_, guest_addr, size, out_edges);
-    CHECK(inserted);
-    branch_targets_.insert(out_edges.begin(), out_edges.end());
-    return &it->second;
-  }
+                                                       const ArenaVector<GuestAddr>& out_edges);
 
   // This method must be called only once.
-  void ResolveEdges() {
-    CHECK(!code_region_finalized_);
-    ValidateRegionBeforeFinalize();
-    SplitBasicBlocks();
-    ResolveInEdges();
-    code_region_finalized_ = true;
-  }
+  void ResolveEdges();
 
   [[nodiscard]] const ArenaMap<GuestAddr, GuestCodeBasicBlock>& basic_blocks() const {
     return basic_blocks_;
@@ -83,50 +74,18 @@ class GuestCodeRegion {
 
   [[nodiscard]] const ArenaSet<GuestAddr>& branch_targets() const { return branch_targets_; }
 
- private:
-  void SplitBasicBlocks() {
-    for (auto branch_target : branch_targets_) {
-      auto it = basic_blocks_.upper_bound(branch_target);
-      if (it == basic_blocks_.begin()) {
-        continue;
-      }
-
-      --it;
-      auto& [guest_addr, code_block] = *it;
-      if (branch_target <= guest_addr || branch_target >= code_block.end_addr()) {
-        // Nothing to split.
-        continue;
-      }
-
-      size_t updated_size = branch_target - code_block.start_addr();
-      size_t new_code_block_size = code_block.size() - updated_size;
-
-      NewBasicBlock(branch_target, new_code_block_size, code_block.out_edges());
-
-      code_block.SetSize(updated_size);
-      code_block.SetOutEdges(ArenaVector<GuestAddr>({branch_target}, arena_));
-    }
-  }
-
-  void ResolveInEdges() {
-    for (auto& [source_addr, basic_block] : basic_blocks_) {
-      for (auto target_addr : basic_block.out_edges()) {
-        auto it = basic_blocks_.find(target_addr);
-        if (it != basic_blocks_.end()) {
-          it->second.AddInEdge(source_addr);
-        }
-      }
-    }
-  }
+  [[nodiscard]] std::string GetDebugString() const;
 
-  void ValidateRegionBeforeFinalize() const {
-    GuestAddr last_seen_end_addr = kNullGuestAddr;
-    for (const auto& [start_addr, basic_block] : basic_blocks_) {
-      CHECK_GE(start_addr, last_seen_end_addr);
-      last_seen_end_addr = basic_block.end_addr();
-      CHECK(basic_block.in_edges().empty());
-    }
-  }
+ private:
+  // Collects targets reachable from the first basic_block.
+  // The first block is included in the result iff it's reachable from
+  // some other block (through a back edge). The resulted set contains
+  // external reachable branch_targets as well as internal ones.
+  ArenaSet<GuestAddr> CollectReachableBranchTargets() const;
+  void SplitBasicBlocks();
+  void RemoveUnreachableBlocks();
+  void ResolveInEdges();
+  void ValidateRegionBeforeFinalize() const;
 
   Arena* arena_;
   ArenaMap<GuestAddr, GuestCodeBasicBlock> basic_blocks_;
diff --git a/tools/nogrod/Android.bp b/tools/nogrod/Android.bp
index 52056036..7e3c8653 100644
--- a/tools/nogrod/Android.bp
+++ b/tools/nogrod/Android.bp
@@ -20,7 +20,6 @@ package {
 cc_defaults {
     name: "nogrod_defaults",
     defaults: ["berberis_defaults_64"],
-    cpp_std: "c++20",
 }
 
 cc_library {
diff --git a/tools/nogrod/dwarf_abbrev.cc b/tools/nogrod/dwarf_abbrev.cc
index d2887afd..09468ba7 100644
--- a/tools/nogrod/dwarf_abbrev.cc
+++ b/tools/nogrod/dwarf_abbrev.cc
@@ -32,36 +32,16 @@ using berberis::StringPrintf;
 
 class DwarfClasses {
  public:
-  DwarfClasses() { classes_[0] = {}; }
+  DwarfClasses() { classes_ = {}; }
 
   DwarfClasses(std::initializer_list<const DwarfClass*> classes) {
-    classes_[0] = std::vector(classes);
+    classes_ = std::vector(classes);
   }
 
-  DwarfClasses(
-      std::initializer_list<std::map<uint16_t, std::vector<const DwarfClass*>>::value_type> classes)
-      : classes_(classes) {}
-
-  [[nodiscard]] const std::vector<const DwarfClass*>* get(uint16_t version) const {
-    auto candidate = classes_.find(version);
-    if (candidate != classes_.end()) {
-      return &candidate->second;
-    }
-
-    for (auto it = classes_.begin(), end = classes_.end(); it != end; ++it) {
-      if (it->first <= version) {
-        candidate = it;
-      } else {
-        break;
-      }
-    }
-
-    return candidate != classes_.end() ? &candidate->second : nullptr;
-  }
+  [[nodiscard]] const std::vector<const DwarfClass*>* get() const { return &classes_; }
 
  private:
-  // classes for every version
-  std::map<uint16_t, std::vector<const DwarfClass*>> classes_;
+  std::vector<const DwarfClass*> classes_;
 };
 
 struct AbbrevDescriptor {
@@ -130,283 +110,300 @@ const AbbrevDescriptor kFormDescriptors[] = {
 
 const AbbrevDescriptor kNameDescriptors[] = {
   { 0x00, { }, "null" },
-  { 0x01, { { 2, { DwarfClass::kReference } } }, "DW_AT_sibling" },
+  { 0x01, { DwarfClass::kReference }, "DW_AT_sibling" },
   { 0x02, {
-            { 2, { DwarfClass::kBlock, DwarfClass::kConstant } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kLoclistsptr } },
-            { 4, { DwarfClass::kExprloc, DwarfClass::kLoclistsptr } },
-            { 5, { DwarfClass::kExprloc, DwarfClass::kLoclist } },
+            DwarfClass::kBlock,
+            DwarfClass::kConstant,
+            DwarfClass::kLoclistsptr,
+            DwarfClass::kExprloc,
+            DwarfClass::kLoclist,
           }, "DW_AT_location" },
-  { 0x03, { { 2, { DwarfClass::kString } } }, "DW_AT_name" },
+  { 0x03, { DwarfClass::kString }, "DW_AT_name" },
   { 0x04, { }, "Reserved 0x04" },
   { 0x05, { }, "Reserved 0x05" },
   { 0x06, { }, "Reserved 0x06" },
   { 0x07, { }, "Reserved 0x07" },
   { 0x08, { }, "Reserved 0x08" },
-  { 0x09, { { 2, { DwarfClass::kConstant } } }, "DW_AT_ordering" },
+  { 0x09, { DwarfClass::kConstant }, "DW_AT_ordering" },
   { 0x0a, { }, "Reserved 0x0a" },
-  { 0x0b, {
-            { 2, { DwarfClass::kConstant } },
-            { 3, { DwarfClass::kBlock,
-                   DwarfClass::kConstant,
-                   DwarfClass::kReference } },
-            { 4, { DwarfClass::kConstant,
-                   DwarfClass::kExprloc,
-                   DwarfClass::kReference } },
+  { 0x0b, { DwarfClass::kConstant,
+            DwarfClass::kBlock,
+            DwarfClass::kReference,
+            DwarfClass::kExprloc,
           }, "DW_AT_byte_size" },
   { 0x0c, {
-            { 2, { DwarfClass::kConstant } },
-            { 3, { DwarfClass::kConstant,
-                   DwarfClass::kBlock,
-                   DwarfClass::kReference } },
-            { 4, { DwarfClass::kConstant,
-                   DwarfClass::kExprloc,
-                   DwarfClass::kReference } },
+            DwarfClass::kConstant,
+            DwarfClass::kBlock,
+            DwarfClass::kExprloc,
+            DwarfClass::kReference,
           }, "DW_AT_bit_offset" }, // Removed in dwarf5??
   { 0x0d, {
-            { 2, { DwarfClass::kConstant } },
-            { 3, { DwarfClass::kConstant,
-                   DwarfClass::kBlock,
-                   DwarfClass::kReference } },
-            { 4, { DwarfClass::kConstant,
-                   DwarfClass::kExprloc,
-                   DwarfClass::kReference } },
+            DwarfClass::kConstant,
+            DwarfClass::kBlock,
+            DwarfClass::kExprloc,
+            DwarfClass::kReference,
           }, "DW_AT_bit_size" },
   { 0x0e, { }, "Reserved 0x0e" },
   { 0x0f, { }, "Reserved 0x0f" },
   { 0x10, {
-            { 2, { DwarfClass::kConstant } },
-            { 3, { DwarfClass::kLineptr } },
+            DwarfClass::kConstant,
+            DwarfClass::kLineptr,
           }, "DW_AT_stmt_list" },
-  { 0x11, { { 2, { DwarfClass::kAddress } } }, "DW_AT_low_pc" },
+  { 0x11, { DwarfClass::kAddress }, "DW_AT_low_pc" },
   { 0x12, {
-            { 2, { DwarfClass::kAddress } },
-            { 4, { DwarfClass::kAddress, DwarfClass::kConstant } },
+            DwarfClass::kAddress,
+            DwarfClass::kConstant,
           }, "DW_AT_high_pc" },
-  { 0x13, { { 2, { DwarfClass::kConstant } } }, "DW_AT_language" },
+  { 0x13, { DwarfClass::kConstant }, "DW_AT_language" },
   { 0x14, { }, "Reserved 0x14" },
-  { 0x15, { { 2, { DwarfClass::kReference } } }, "DW_AT_discr" },
-  { 0x16, { { 2, { DwarfClass::kConstant } } }, "DW_AT_discr_value" },
-  { 0x17, { { 2, { DwarfClass::kConstant } } }, "DW_AT_visibility" },
-  { 0x18, { { 2, { DwarfClass::kReference } } }, "DW_AT_import" },
+  { 0x15, { DwarfClass::kReference }, "DW_AT_discr" },
+  { 0x16, { DwarfClass::kConstant }, "DW_AT_discr_value" },
+  { 0x17, { DwarfClass::kConstant }, "DW_AT_visibility" },
+  { 0x18, { DwarfClass::kReference }, "DW_AT_import" },
   { 0x19, {
-            { 2, { DwarfClass::kBlock, DwarfClass::kConstant } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kLoclistsptr } },
-            { 4, { DwarfClass::kExprloc, DwarfClass::kLoclistsptr } },
-            { 5, { DwarfClass::kExprloc/*, DwarfClass::kLoclist */, DwarfClass::kReference } },
+            DwarfClass::kBlock,
+            DwarfClass::kConstant,
+            DwarfClass::kLoclistsptr,
+            DwarfClass::kExprloc,
+            /*, DwarfClass::kLoclist */
+            DwarfClass::kReference,
           }, "DW_AT_string_length" },
-  { 0x1a, { { 2, { DwarfClass::kReference } } }, "DW_AT_common_reference" },
-  { 0x1b, { { 2, { DwarfClass::kString } } }, "DW_AT_comp_dir" },
+  { 0x1a, { DwarfClass::kReference }, "DW_AT_common_reference" },
+  { 0x1b, { DwarfClass::kString }, "DW_AT_comp_dir" },
   { 0x1c, {
-            { 2, { DwarfClass::kBlock, DwarfClass::kConstant, DwarfClass::kString } }
+            DwarfClass::kBlock,
+            DwarfClass::kConstant,
+            DwarfClass::kString,
           }, "DW_AT_const_value" },
-  { 0x1d, { { 2, { DwarfClass::kReference } } }, "DW_AT_containing_type" },
+  { 0x1d, { DwarfClass::kReference }, "DW_AT_containing_type" },
   { 0x1e, {
-            { 2, { DwarfClass::kReference } },
-            { 5, { DwarfClass::kConstant,
-                   DwarfClass::kReference,
-                   DwarfClass::kFlag } }
-          }, "DW_AT_default_value" },
+            DwarfClass::kReference,
+            DwarfClass::kConstant,
+            DwarfClass::kFlag
+          }, "DW_AT_default_value" }, // manually adjusted from v5
   { 0x1f, { }, "Reserved 0x1f" },
-  { 0x20, { { 2, { DwarfClass::kConstant } } }, "DW_AT_inline" },
-  { 0x21, { { 2, { DwarfClass::kFlag } } }, "DW_AT_is_optional" },
+  { 0x20, { DwarfClass::kConstant }, "DW_AT_inline" },
+  { 0x21, { DwarfClass::kFlag }, "DW_AT_is_optional" },
   { 0x22, {
-            { 2, { DwarfClass::kConstant, DwarfClass::kReference } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kConstant, DwarfClass::kReference } },
-            { 4, { DwarfClass::kConstant, DwarfClass::kExprloc, DwarfClass::kReference } },
+            DwarfClass::kConstant,
+            DwarfClass::kReference,
+            DwarfClass::kBlock,
+            DwarfClass::kExprloc,
           }, "DW_AT_lower_bound" },
   { 0x23, { }, "Reserved 0x23" },
   { 0x24, { }, "Reserved 0x24" },
-  { 0x25, { { 2, { DwarfClass::kString } } }, "DW_AT_producer" },
+  { 0x25, { DwarfClass::kString }, "DW_AT_producer" },
   { 0x26, { }, "Reserved 0x26" },
-  { 0x27, { { 2, { DwarfClass::kFlag } } }, "DW_AT_prototyped" },
+  { 0x27, { DwarfClass::kFlag }, "DW_AT_prototyped" },
   { 0x28, { }, "Reserved 0x28" },
   { 0x29, { }, "Reserved 0x29" },
   { 0x2a, {
-            { 2, { DwarfClass::kBlock, DwarfClass::kConstant } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kLoclistsptr } },
-            { 4, { DwarfClass::kExprloc, DwarfClass::kLoclistsptr } },
-            { 5, { DwarfClass::kExprloc, /* DwarfClass::kLoclist */ } }
+            DwarfClass::kBlock,
+            DwarfClass::kConstant,
+            DwarfClass::kLoclistsptr,
+            DwarfClass::kExprloc,
+            /* DwarfClass::kLoclist */
           }, "DW_AT_return_addr" },
   { 0x2b, { }, "Reserved 0x2b" },
   { 0x2c, {
-            { 2, { DwarfClass::kConstant } },
-            { 4, { DwarfClass::kConstant, DwarfClass::kRnglistsptr } },
-            { 5, { DwarfClass::kConstant, /* DwarfClass::kRnglist */ } }
+            DwarfClass::kRnglistsptr,
+            DwarfClass::kConstant,
+            /* DwarfClass::kRnglist */
           }, "DW_AT_start_scope" },
   { 0x2d, { }, "Reserved 0x2d" },
   { 0x2e, {
-            { 2, { DwarfClass::kConstant } },
-            { 4, { DwarfClass::kConstant, DwarfClass::kExprloc, DwarfClass::kReference } },
+            DwarfClass::kConstant,
+            DwarfClass::kExprloc,
+            DwarfClass::kReference,
           }, "DW_AT_bit_stride" },  // called "DW_AT_stride_size" in dwarf2
   { 0x2f, {
-            { 2, { DwarfClass::kConstant, DwarfClass::kReference } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kConstant, DwarfClass::kReference } },
-            { 4, { DwarfClass::kConstant, DwarfClass::kExprloc, DwarfClass::kReference } },
+            DwarfClass::kConstant,
+            DwarfClass::kReference,
+            DwarfClass::kBlock,
+            DwarfClass::kExprloc,
           }, "DW_AT_upper_bound" },
   { 0x30, { }, "Reserved 0x30" },
-  { 0x31, { { 2, { DwarfClass::kReference } } }, "DW_AT_abstract_origin" },
-  { 0x32, { { 2, { DwarfClass::kConstant } } }, "DW_AT_accessibility" },
-  { 0x33, { { 2, { DwarfClass::kConstant } } }, "DW_AT_address_class" },
-  { 0x34, { { 2, { DwarfClass::kFlag } } }, "DW_AT_artificial" },
-  { 0x35, { { 2, { DwarfClass::kReference } } }, "DW_AT_base_types" },
-  { 0x36, { { 2, { DwarfClass::kConstant } } }, "DW_AT_calling_convention" },
+  { 0x31, { DwarfClass::kReference }, "DW_AT_abstract_origin" },
+  { 0x32, { DwarfClass::kConstant }, "DW_AT_accessibility" },
+  { 0x33, { DwarfClass::kConstant }, "DW_AT_address_class" },
+  { 0x34, { DwarfClass::kFlag }, "DW_AT_artificial" },
+  { 0x35, { DwarfClass::kReference }, "DW_AT_base_types" },
+  { 0x36, { DwarfClass::kConstant }, "DW_AT_calling_convention" },
   { 0x37, {
-            { 2, { DwarfClass::kConstant, DwarfClass::kReference } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kConstant, DwarfClass::kReference } },
-            { 4, { DwarfClass::kConstant, DwarfClass::kExprloc, DwarfClass::kReference } },
+            DwarfClass::kConstant,
+            DwarfClass::kReference,
+            DwarfClass::kBlock,
+            DwarfClass::kExprloc,
           }, "DW_AT_count" },
   { 0x38, {
-            { 2, { DwarfClass::kBlock, DwarfClass::kReference } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kConstant, DwarfClass::kLoclistsptr } },
-            { 4, { DwarfClass::kConstant, DwarfClass::kExprloc, DwarfClass::kLoclistsptr } },
-            { 5, { DwarfClass::kConstant, DwarfClass::kExprloc /*, DwarfClass::kLoclist */ } },
+            DwarfClass::kBlock,
+            DwarfClass::kReference,
+            DwarfClass::kConstant,
+            DwarfClass::kLoclistsptr,
+            DwarfClass::kExprloc,
+            /*, DwarfClass::kLoclist */
           }, "DW_AT_data_member_location" },
-  { 0x39, { { 2, { DwarfClass::kConstant } } }, "DW_AT_decl_column" },
-  { 0x3a, { { 2, { DwarfClass::kConstant } } }, "DW_AT_decl_file" },
-  { 0x3b, { { 2, { DwarfClass::kConstant } } }, "DW_AT_decl_line" },
-  { 0x3c, { { 2, { DwarfClass::kFlag } } }, "DW_AT_declaration" },
-  { 0x3d, { { 2, { DwarfClass::kBlock } } }, "DW_AT_discr_list" },
-  { 0x3e, { { 2, { DwarfClass::kConstant } } }, "DW_AT_encoding" },
-  { 0x3f, { { 2, { DwarfClass::kFlag } } }, "DW_AT_external" },
+  { 0x39, { DwarfClass::kConstant }, "DW_AT_decl_column" },
+  { 0x3a, { DwarfClass::kConstant }, "DW_AT_decl_file" },
+  { 0x3b, { DwarfClass::kConstant }, "DW_AT_decl_line" },
+  { 0x3c, { DwarfClass::kFlag }, "DW_AT_declaration" },
+  { 0x3d, { DwarfClass::kBlock }, "DW_AT_discr_list" },
+  { 0x3e, { DwarfClass::kConstant }, "DW_AT_encoding" },
+  { 0x3f, { DwarfClass::kFlag }, "DW_AT_external" },
   { 0x40, {
-            { 2, { DwarfClass::kBlock, DwarfClass::kConstant } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kLoclistsptr } },
-            { 4, { DwarfClass::kExprloc, DwarfClass::kLoclistsptr } },
-            { 5, { DwarfClass::kExprloc, /* DwarfClass::kLoclist */ } },
+            DwarfClass::kBlock,
+            DwarfClass::kConstant,
+            DwarfClass::kLoclistsptr,
+            DwarfClass::kExprloc,
+            /* DwarfClass::kLoclist */
           }, "DW_AT_frame_base" },
-  { 0x41, { { 2, { DwarfClass::kReference } } }, "DW_AT_friend" },
-  { 0x42, { { 2, { DwarfClass::kConstant } } }, "DW_AT_identifier_case" },
+  { 0x41, { DwarfClass::kReference }, "DW_AT_friend" },
+  { 0x42, { DwarfClass::kConstant }, "DW_AT_identifier_case" },
   { 0x43, {
-            { 2, { DwarfClass::kConstant } },
-            { 3, { DwarfClass::kMacptr } },
+            DwarfClass::kConstant,
+            DwarfClass::kMacptr,
           }, "DW_AT_macro_info" }, // Removed in dwarf5??
   { 0x44, {
-            { 2, { DwarfClass::kBlock } },
-            { 4, { DwarfClass::kReference } },
+            DwarfClass::kBlock,
+            DwarfClass::kReference,
           }, "DW_AT_namelist_item" },
-  { 0x45, { { 2, { DwarfClass::kReference } } }, "DW_AT_priority" },
+  { 0x45, { DwarfClass::kReference }, "DW_AT_priority" },
   { 0x46, {
-            { 2, { DwarfClass::kBlock, DwarfClass::kConstant } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kLoclistsptr } },
-            { 4, { DwarfClass::kExprloc, DwarfClass::kLoclistsptr } },
-            { 5, { DwarfClass::kExprloc, /* DwarfClass::kLoclist */ } },
+            DwarfClass::kBlock,
+            DwarfClass::kConstant,
+            DwarfClass::kLoclistsptr,
+            DwarfClass::kExprloc,
+            /* DwarfClass::kLoclist */
           }, "DW_AT_segment" },
-  { 0x47, { { 2, { DwarfClass::kReference } } }, "DW_AT_specification" },
+  { 0x47, { DwarfClass::kReference }, "DW_AT_specification" },
   { 0x48, {
-            { 2, { DwarfClass::kBlock, DwarfClass::kConstant } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kLoclistsptr } },
-            { 4, { DwarfClass::kExprloc, DwarfClass::kLoclistsptr } },
-            { 5, { DwarfClass::kExprloc, /* DwarfClass::kLoclist */ } },
+            DwarfClass::kBlock,
+            DwarfClass::kConstant,
+            DwarfClass::kLoclistsptr,
+            DwarfClass::kExprloc,
+            /* DwarfClass::kLoclist */
           }, "DW_AT_static_link" },
-  { 0x49, { { 2, { DwarfClass::kReference } } }, "DW_AT_type" },
+  { 0x49, { DwarfClass::kReference }, "DW_AT_type" },
   { 0x4a, {
-            { 2, { DwarfClass::kBlock, DwarfClass::kConstant } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kLoclistsptr } },
-            { 4, { DwarfClass::kExprloc, DwarfClass::kLoclistsptr } },
-            { 5, { DwarfClass::kExprloc, /* DwarfClass::kLoclist */ } },
+            DwarfClass::kBlock,
+            DwarfClass::kConstant,
+            DwarfClass::kLoclistsptr,
+            DwarfClass::kExprloc,
+            /* DwarfClass::kLoclist */
           }, "DW_AT_use_location" },
-  { 0x4b, { { 2, { DwarfClass::kFlag } } }, "DW_AT_variable_parameter" },
-  { 0x4c, { { 2, { DwarfClass::kConstant } } }, "DW_AT_virtuality" },
+  { 0x4b, { DwarfClass::kFlag }, "DW_AT_variable_parameter" },
+  { 0x4c, { DwarfClass::kConstant }, "DW_AT_virtuality" },
   { 0x4d, {
-            { 2, { DwarfClass::kBlock, DwarfClass::kReference } },
-            { 3, { DwarfClass::kBlock, DwarfClass::kLoclistsptr } },
-            { 4, { DwarfClass::kExprloc, DwarfClass::kLoclistsptr } },
-            { 5, { DwarfClass::kExprloc, /* DwarfClass::kLoclist */ } },
+            DwarfClass::kBlock,
+            DwarfClass::kReference,
+            DwarfClass::kLoclistsptr,
+            DwarfClass::kExprloc,
+            /* DwarfClass::kLoclist */
           }, "DW_AT_vtable_elem_location" },
   // Dwarf 3
   { 0x4e, {
-            { 3, { DwarfClass::kBlock, DwarfClass::kConstant, DwarfClass::kReference } },
-            { 4, { DwarfClass::kConstant, DwarfClass::kExprloc, DwarfClass::kReference } },
+            DwarfClass::kBlock,
+            DwarfClass::kConstant,
+            DwarfClass::kExprloc,
+            DwarfClass::kReference,
           }, "DW_AT_allocated" },
   { 0x4f, {
-            { 3, { DwarfClass::kBlock, DwarfClass::kConstant, DwarfClass::kReference } },
-            { 4, { DwarfClass::kConstant, DwarfClass::kExprloc, DwarfClass::kReference } },
+            DwarfClass::kBlock,
+            DwarfClass::kReference,
+            DwarfClass::kConstant,
+            DwarfClass::kExprloc,
           }, "DW_AT_associated" },
   { 0x50, {
-            { 3, { DwarfClass::kBlock } },
-            { 4, { DwarfClass::kExprloc } },
+            DwarfClass::kBlock,
+            DwarfClass::kExprloc,
           }, "DW_AT_data_location" },
   { 0x51, {
-            { 3, { DwarfClass::kBlock, DwarfClass::kConstant, DwarfClass::kReference } },
-            { 4, { DwarfClass::kConstant, DwarfClass::kExprloc, DwarfClass::kReference } },
+            DwarfClass::kBlock,
+            DwarfClass::kConstant,
+            DwarfClass::kReference,
+            DwarfClass::kExprloc,
           }, "DW_AT_byte_stride" },
   { 0x52, {
-            { 3, { DwarfClass::kAddress } },
-            { 5, { DwarfClass::kAddress, DwarfClass::kConstant } },
+            DwarfClass::kAddress,
+            DwarfClass::kConstant,
           }, "DW_AT_entry_pc" },
-  { 0x53, { { 3, { DwarfClass::kFlag } } }, "DW_AT_use_UTF8" },
-  { 0x54, { { 3, { DwarfClass::kReference } } }, "DW_AT_extension" },
+  { 0x53, { DwarfClass::kFlag }, "DW_AT_use_UTF8" },
+  { 0x54, { DwarfClass::kReference }, "DW_AT_extension" },
   { 0x55, {
-            { 2, { DwarfClass::kConstant } },  // not in spec, but clang uses this in dwarf2??
-            { 3, { DwarfClass::kRnglistsptr } },
-            { 5, { DwarfClass::kRnglist } },
+            DwarfClass::kConstant,  // not in spec, but clang uses this in dwarf2??
+            DwarfClass::kRnglistsptr,
+            DwarfClass::kRnglist,
           }, "DW_AT_ranges" },
   { 0x56, {
-            { 3, { DwarfClass::kAddress,
-                   DwarfClass::kFlag,
-                   DwarfClass::kReference,
-                   DwarfClass::kString } },
+            DwarfClass::kAddress,
+            DwarfClass::kFlag,
+            DwarfClass::kReference,
+            DwarfClass::kString,
           }, "DW_AT_trampoline" },
-  { 0x57, { { 3, { DwarfClass::kConstant } } }, "DW_AT_call_column" },
-  { 0x58, { { 3, { DwarfClass::kConstant } } }, "DW_AT_call_file" },
-  { 0x59, { { 3, { DwarfClass::kConstant } } }, "DW_AT_call_line" },
-  { 0x5a, { { 3, { DwarfClass::kString } } }, "DW_AT_description" },
-  { 0x5b, { { 3, { DwarfClass::kConstant } } }, "DW_AT_binary_scale" },
-  { 0x5c, { { 3, { DwarfClass::kConstant } } }, "DW_AT_decimal_scale" },
-  { 0x5d, { { 3, { DwarfClass::kReference } } }, "DW_AT_small" },
-  { 0x5e, { { 3, { DwarfClass::kConstant } } }, "DW_AT_decimal_sign" },
-  { 0x5f, { { 3, { DwarfClass::kConstant } } }, "DW_AT_digit_count" },
-  { 0x60, { { 3, { DwarfClass::kString } } }, "DW_AT_picture_string" },
-  { 0x61, { { 3, { DwarfClass::kFlag } } }, "DW_AT_mutable" },
-  { 0x62, { { 3, { DwarfClass::kFlag } } }, "DW_AT_thread_scaled" },
-  { 0x63, { { 3, { DwarfClass::kFlag } } }, "DW_AT_explicit" },
-  { 0x64, { { 3, { DwarfClass::kReference } } }, "DW_AT_object_pointer" },
-  { 0x65, { { 3, { DwarfClass::kConstant } } }, "DW_AT_endianity" },
-  { 0x66, { { 3, { DwarfClass::kFlag } } }, "DW_AT_elemental" },
-  { 0x67, { { 3, { DwarfClass::kFlag } } }, "DW_AT_pure" },
-  { 0x68, { { 3, { DwarfClass::kFlag } } }, "DW_AT_recursive" },
+  // TODO(b/409026302): DWARF spec states that DW_AT_call_column requires DWARF version >= v3,
+  // however this exists in a v2 compile unit in libandroid_runtime DWARF file. As a workaround,
+  // we manually set this attribute (as well as a few others below, marked by "manually adjusted")
+  // to v2. We should consider removing correct version checking entirely, since such discrepancies
+  // occur frequently, and all that matters is that it parses correctly.
+  { 0x57, {DwarfClass::kConstant }, "DW_AT_call_column" }, // manually adjusted from v3
+  { 0x58, {DwarfClass::kConstant }, "DW_AT_call_file" }, // manually adjusted from v3
+  { 0x59, {DwarfClass::kConstant }, "DW_AT_call_line" }, // manually adjusted from v3
+  { 0x5a, {DwarfClass::kString }, "DW_AT_description" },
+  { 0x5b, {DwarfClass::kConstant }, "DW_AT_binary_scale" },
+  { 0x5c, {DwarfClass::kConstant }, "DW_AT_decimal_scale" },
+  { 0x5d, {DwarfClass::kReference }, "DW_AT_small" },
+  { 0x5e, {DwarfClass::kConstant }, "DW_AT_decimal_sign" },
+  { 0x5f, {DwarfClass::kConstant }, "DW_AT_digit_count" },
+  { 0x60, {DwarfClass::kString }, "DW_AT_picture_string" },
+  { 0x61, {DwarfClass::kFlag }, "DW_AT_mutable" },
+  { 0x62, {DwarfClass::kFlag }, "DW_AT_thread_scaled" },
+  { 0x63, {DwarfClass::kFlag }, "DW_AT_explicit" },
+  { 0x64, {DwarfClass::kReference }, "DW_AT_object_pointer" },
+  { 0x65, {DwarfClass::kConstant }, "DW_AT_endianity" },
+  { 0x66, {DwarfClass::kFlag }, "DW_AT_elemental" },
+  { 0x67, {DwarfClass::kFlag }, "DW_AT_pure" },
+  { 0x68, {DwarfClass::kFlag }, "DW_AT_recursive" },
   // Dwarf 4
-  { 0x69, { { 4, { DwarfClass::kReference } } }, "DW_AT_signature" },
-  { 0x6a, { { 4, { DwarfClass::kFlag } } }, "DW_AT_main_subprogram" },
-  { 0x6b, { { 4, { DwarfClass::kConstant } } }, "DW_AT_data_bit_offset" },
-  { 0x6c, { { 4, { DwarfClass::kFlag } } }, "DW_AT_const_expr" },
-  { 0x6d, { { 4, { DwarfClass::kFlag } } }, "DW_AT_enum_class" },
-  { 0x6e, { { 4, { DwarfClass::kString } } }, "DW_AT_linkage_name" },
+  { 0x69, { DwarfClass::kReference }, "DW_AT_signature" },
+  { 0x6a, { DwarfClass::kFlag }, "DW_AT_main_subprogram" },
+  { 0x6b, { DwarfClass::kConstant }, "DW_AT_data_bit_offset" },
+  { 0x6c, { DwarfClass::kFlag }, "DW_AT_const_expr" },
+  { 0x6d, { DwarfClass::kFlag }, "DW_AT_enum_class" },
+  { 0x6e, { DwarfClass::kString }, "DW_AT_linkage_name" }, // manually adjusted from v4
   // Dwarf 5
-  { 0x6f, { { 5, { DwarfClass::kConstant } } }, "DW_AT_string_length_bit_size" },
-  { 0x70, { { 5, { DwarfClass::kConstant } } }, "DW_AT_string_length_byte_size" },
-  { 0x71, { { 5, { DwarfClass::kConstant, DwarfClass::kExprloc } } }, "DW_AT_rank" },
-  { 0x72, { { 5, { DwarfClass::kStroffsetsptr } } }, "DW_AT_str_offset_base" },
-  { 0x73, { { 5, { DwarfClass::kAddrptr } } }, "DW_AT_addr_base" },
-  { 0x74, { { 5, { DwarfClass::kRnglistsptr } } }, "DW_AT_rnglists_base" },
+  { 0x6f, { DwarfClass::kConstant }, "DW_AT_string_length_bit_size" },
+  { 0x70, { DwarfClass::kConstant }, "DW_AT_string_length_byte_size" },
+  { 0x71, { DwarfClass::kConstant, DwarfClass::kExprloc }, "DW_AT_rank" },
+  { 0x72, { DwarfClass::kStroffsetsptr }, "DW_AT_str_offset_base" },
+  { 0x73, { DwarfClass::kAddrptr }, "DW_AT_addr_base" },
+  { 0x74, { DwarfClass::kRnglistsptr }, "DW_AT_rnglists_base" },
   { 0x75, { }, "Unused 0x75" },
-  { 0x76, { { 5, { DwarfClass::kString } } }, "DW_AT_dwo_name" },
+  { 0x76, { DwarfClass::kString }, "DW_AT_dwo_name" },
   // The following are dwarf 5 by spec but clang still injects it to dwarf4
-  { 0x77, { { 4, { DwarfClass::kFlag } } }, "DW_AT_reference" },
-  { 0x78, { { 4, { DwarfClass::kFlag } } }, "DW_AT_rvalue_reference" },
-  { 0x79, { { 5, { DwarfClass::kMacptr } } }, "DW_AT_macros" },
-  { 0x7a, { { 5, { DwarfClass::kFlag } } }, "DW_AT_call_all_calls" },
-  { 0x7b, { { 5, { DwarfClass::kFlag } } }, "DW_AT_call_all_source_calls" },
-  { 0x7c, { { 5, { DwarfClass::kFlag } } }, "DW_AT_call_all_tail_calls" },
-  { 0x7d, { { 5, { DwarfClass::kAddress } } }, "DW_AT_call_return_pc" },
-  { 0x7e, { { 5, { DwarfClass::kExprloc } } }, "DW_AT_call_value" },
+  { 0x77, { DwarfClass::kFlag }, "DW_AT_reference" },
+  { 0x78, { DwarfClass::kFlag }, "DW_AT_rvalue_reference" },
+  { 0x79, { DwarfClass::kMacptr }, "DW_AT_macros" },
+  { 0x7a, { DwarfClass::kFlag }, "DW_AT_call_all_calls" },
+  { 0x7b, { DwarfClass::kFlag }, "DW_AT_call_all_source_calls" },
+  { 0x7c, { DwarfClass::kFlag }, "DW_AT_call_all_tail_calls" },
+  { 0x7d, { DwarfClass::kAddress }, "DW_AT_call_return_pc" },
+  { 0x7e, { DwarfClass::kExprloc }, "DW_AT_call_value" },
   // kReference is not allowed for DW_AT_call_origin by DWARF5 standard, but it is used by clang
-  { 0x7f, { { 5, { DwarfClass::kExprloc, DwarfClass::kReference } } }, "DW_AT_call_origin" },
-  { 0x80, { { 5, { DwarfClass::kReference } } }, "DW_AT_call_parameter" },
-  { 0x81, { { 5, { DwarfClass::kAddress } } }, "DW_AT_call_pc" },
-  { 0x82, { { 5, { DwarfClass::kFlag } } }, "DW_AT_call_tail_call" },
-  { 0x83, { { 5, { DwarfClass::kExprloc } } }, "DW_AT_call_target" },
-  { 0x84, { { 5, { DwarfClass::kExprloc } } }, "DW_AT_call_target_clobbered" },
-  { 0x85, { { 5, { DwarfClass::kExprloc } } }, "DW_AT_call_data_location" },
-  { 0x86, { { 5, { DwarfClass::kExprloc } } }, "DW_AT_call_data_value" },
+  { 0x7f, { DwarfClass::kExprloc, DwarfClass::kReference }, "DW_AT_call_origin" },
+  { 0x80, { DwarfClass::kReference }, "DW_AT_call_parameter" },
+  { 0x81, { DwarfClass::kAddress }, "DW_AT_call_pc" },
+  { 0x82, { DwarfClass::kFlag }, "DW_AT_call_tail_call" },
+  { 0x83, { DwarfClass::kExprloc }, "DW_AT_call_target" },
+  { 0x84, { DwarfClass::kExprloc }, "DW_AT_call_target_clobbered" },
+  { 0x85, { DwarfClass::kExprloc }, "DW_AT_call_data_location" },
+  { 0x86, { DwarfClass::kExprloc }, "DW_AT_call_data_value" },
   // Apparently clang uses these in dwarf4 CUs
-  { 0x87, { { 4, { DwarfClass::kFlag } } }, "DW_AT_noreturn" },
-  { 0x88, { { 4, { DwarfClass::kConstant } } }, "DW_AT_alignment" },
-  { 0x89, { { 4, { DwarfClass::kFlag } } }, "DW_AT_export_symbols" },
-  { 0x8a, { { 5, { DwarfClass::kFlag } } }, "DW_AT_deleted" },
-  { 0x8b, { { 5, { DwarfClass::kConstant } } }, "DW_AT_defaulted" },
-  { 0x8c, { { 5, { DwarfClass::kLoclistsptr } } }, "DW_AT_loclists_base" },
+  { 0x87, { DwarfClass::kFlag }, "DW_AT_noreturn" }, // manually adjusted from v4
+  { 0x88, { DwarfClass::kConstant }, "DW_AT_alignment" }, // manually adjusted from v4
+  { 0x89, { DwarfClass::kFlag }, "DW_AT_export_symbols" },
+  { 0x8a, { DwarfClass::kFlag }, "DW_AT_deleted" },
+  { 0x8b, { DwarfClass::kConstant }, "DW_AT_defaulted" },
+  { 0x8c, { DwarfClass::kLoclistsptr }, "DW_AT_loclists_base" },
 };
 // clang-format on
 
@@ -475,6 +472,12 @@ const AbbrevDescriptor* GetNameDescriptor(uint32_t name) {
       return &kAtGnuEntryView;
   }
 
+  // DW_AT_linkage_name should have replaced all instances of DW_AT_MIPS_linkage_name. However,
+  // libandroid_runtime DWARF contains some of such instances, hence this workaround.
+  if (name == DW_AT_MIPS_linkage_name) {
+    name = DW_AT_linkage_name;
+  }
+
   if (name > DW_AT_MAX_VALUE) {
     return nullptr;
   }
@@ -765,7 +768,11 @@ class DwarfClassReference : public DwarfClass {
         offset = cu->unit_offset() + bs->ReadLeb128();
         break;
       case DW_FORM_ref_addr:
-        offset = cu->is_dwarf64() ? bs->ReadUint64() : bs->ReadUint32();
+        if (cu->version() <= 2) {
+          offset = cu->address_size() == 8 ? bs->ReadUint64() : bs->ReadUint32();
+        } else {
+          offset = cu->is_dwarf64() ? bs->ReadUint64() : bs->ReadUint32();
+        }
         break;
       // TODO(dimitry): DW_FORM_ref_sig8?
       default:
@@ -828,10 +835,7 @@ class DwarfClassString : public DwarfClass {
   }
 };
 
-const DwarfClass* FindDwarfClass(uint16_t version,
-                                 uint32_t name,
-                                 uint32_t form,
-                                 std::string* error_msg) {
+const DwarfClass* FindDwarfClass(uint32_t name, uint32_t form, std::string* error_msg) {
   if (form > DW_FORM_MAX_VALUE) {
     *error_msg = StringPrintf("Invalid abbrev attribute form: 0x%x", form);
     return nullptr;
@@ -843,19 +847,18 @@ const DwarfClass* FindDwarfClass(uint16_t version,
     return nullptr;
   }
 
-  auto name_classes = name_descriptor->classes.get(version);
+  auto name_classes = name_descriptor->classes.get();
   if (name_classes == nullptr) {
-    *error_msg = StringPrintf(
-        "failed to lookup classes for %s (0x%x) version=%d", name_descriptor->name, name, version);
+    *error_msg =
+        StringPrintf("failed to lookup classes for %s (0x%x)", name_descriptor->name, name);
     return nullptr;
   }
 
   auto& form_descriptor = kFormDescriptors[form];
-  auto form_classes = form_descriptor.classes.get(version);
+  auto form_classes = form_descriptor.classes.get();
 
   if (form_classes == nullptr) {
-    *error_msg = StringPrintf(
-        "failed to lookup classes for %s (0x%x) version=%d", form_descriptor.name, form, version);
+    *error_msg = StringPrintf("failed to lookup classes for %s (0x%x)", form_descriptor.name, form);
     return nullptr;
   }
 
@@ -884,12 +887,11 @@ const DwarfClass* FindDwarfClass(uint16_t version,
   }
 
   if (result == nullptr) {
-    *error_msg = StringPrintf("form %s (0x%x) is not applicable to the name %s (0x%x) version=%d.",
+    *error_msg = StringPrintf("form %s (0x%x) is not applicable to the name %s (0x%x)",
                               form_descriptor.name,
                               form,
                               name_descriptor->name,
-                              name,
-                              version);
+                              name);
   }
 
   return result;
@@ -959,6 +961,11 @@ std::optional<std::string> DwarfAttributeValue<std::string>::StringValue() const
   return value_;
 }
 
+template <>
+std::optional<uint64_t> DwarfAttributeValue<int64_t>::Uint64Value() const {
+  return value_;
+}
+
 template <>
 std::optional<uint64_t> DwarfAttributeValue<uint64_t>::Uint64Value() const {
   return value_;
@@ -992,7 +999,6 @@ void DwarfStrXAttribute::Resolve(DwarfContext* context) {
 }
 
 std::unique_ptr<const DwarfAbbrevAttribute> DwarfAbbrevAttribute::CreateAbbrevAttribute(
-    uint16_t version,
     uint32_t name,
     uint32_t form,
     int64_t value,
@@ -1003,7 +1009,7 @@ std::unique_ptr<const DwarfAbbrevAttribute> DwarfAbbrevAttribute::CreateAbbrevAt
     return nullptr;
   }
 
-  const DwarfClass* dwarf_class = FindDwarfClass(version, name, form, error_msg);
+  const DwarfClass* dwarf_class = FindDwarfClass(name, form, error_msg);
 
   if (dwarf_class == nullptr) {
     return nullptr;
diff --git a/tools/nogrod/dwarf_abbrev.h b/tools/nogrod/dwarf_abbrev.h
index ddffeb54..10d39010 100644
--- a/tools/nogrod/dwarf_abbrev.h
+++ b/tools/nogrod/dwarf_abbrev.h
@@ -164,8 +164,7 @@ class DwarfClass {
 
 class DwarfAbbrevAttribute {
  public:
-  static std::unique_ptr<const DwarfAbbrevAttribute> CreateAbbrevAttribute(uint16_t version,
-                                                                           uint32_t name,
+  static std::unique_ptr<const DwarfAbbrevAttribute> CreateAbbrevAttribute(uint32_t name,
                                                                            uint32_t form,
                                                                            int64_t value,
                                                                            std::string* error_msg);
diff --git a/tools/nogrod/dwarf_constants.h b/tools/nogrod/dwarf_constants.h
index a06ca48d..d0d90b9d 100644
--- a/tools/nogrod/dwarf_constants.h
+++ b/tools/nogrod/dwarf_constants.h
@@ -277,6 +277,8 @@ constexpr uint16_t DW_AT_loclists_base = 0x8c;
 
 constexpr uint16_t DW_AT_MAX_VALUE = DW_AT_loclists_base;
 
+constexpr uint16_t DW_AT_MIPS_linkage_name = 0x2007;
+
 // GNU extension attributes
 constexpr uint16_t DW_AT_GNU_vector = 0x2107;
 constexpr uint16_t DW_AT_GNU_template_name = 0x2110;
diff --git a/tools/nogrod/dwarf_info.cc b/tools/nogrod/dwarf_info.cc
index 19772acd..a6fbe1b9 100644
--- a/tools/nogrod/dwarf_info.cc
+++ b/tools/nogrod/dwarf_info.cc
@@ -195,8 +195,7 @@ class DwarfParser {
     // Even though in .so files abbrev codes is a sequence [1..n]
     // the spec does not specify this as a requirement. Therefore
     // it is safer to use unordered_map.
-    std::unordered_map<uint64_t, DwarfAbbrev>* abbrev_map =
-        ReadAbbrev(version, abbrev_offset, error_msg);
+    std::unordered_map<uint64_t, DwarfAbbrev>* abbrev_map = ReadAbbrev(abbrev_offset, error_msg);
 
     if (abbrev_map == nullptr) {
       *error_msg =
@@ -230,9 +229,7 @@ class DwarfParser {
     return cu;
   }
 
-  std::unordered_map<uint64_t, DwarfAbbrev>* ReadAbbrev(uint16_t version,
-                                                        uint64_t offset,
-                                                        std::string* error_msg) {
+  std::unordered_map<uint64_t, DwarfAbbrev>* ReadAbbrev(uint64_t offset, std::string* error_msg) {
     auto it = abbrevs_.find(offset);
     if (it != abbrevs_.end()) {
       return &it->second;
@@ -280,8 +277,7 @@ class DwarfParser {
         }
 
         std::unique_ptr<const DwarfAbbrevAttribute> abbrev_attribute =
-            DwarfAbbrevAttribute::CreateAbbrevAttribute(
-                version, attr_name, attr_form, value, error_msg);
+            DwarfAbbrevAttribute::CreateAbbrevAttribute(attr_name, attr_form, value, error_msg);
 
         if (!abbrev_attribute) {
           *error_msg =
diff --git a/tools/nogrod/main.cc b/tools/nogrod/main.cc
index de1fdd8e..cffdbc58 100644
--- a/tools/nogrod/main.cc
+++ b/tools/nogrod/main.cc
@@ -569,6 +569,54 @@ std::string UpdateName(std::string original, bool is_first, std::string base_nam
   return original;
 }
 
+const TypeInfo* ParseDie(const nogrod::DwarfDie* start,
+                         const nogrod::DwarfDie* referenced_by,
+                         const nogrod::DwarfInfo* dwarf_info,
+                         std::unordered_map<uint64_t, std::unique_ptr<TypeInfo>>* types);
+
+void GenerateClassTemplateParameter(std::string& template_params,
+                                    const nogrod::DwarfDie* child,
+                                    const nogrod::DwarfDie* die,
+                                    const nogrod::DwarfInfo* dwarf_info,
+                                    std::unordered_map<uint64_t, std::unique_ptr<TypeInfo>>* types,
+                                    bool is_first_template_parameter) {
+  auto child_type_die = GetAtTypeDie(child, dwarf_info);
+  if (child_type_die == nullptr) {
+    return;
+  }
+
+  if (child->tag() == DW_TAG_template_type_parameter) {
+    auto child_type_info = ParseDie(child_type_die, die, dwarf_info, types);
+    template_params = UpdateName(
+        template_params, is_first_template_parameter, (child_type_info->base_name()).c_str());
+    return;
+  }
+
+  if (child->tag() != DW_TAG_template_value_parameter) {
+    return;
+  }
+
+  auto child_type_info = ParseDie(child_type_die, die, dwarf_info, types);
+
+  auto num = child->GetUint64Attribute(DW_AT_const_value);
+  if (num) {
+    if (std::string_view{child_type_info->base_name()}.find("bool") != std::string_view::npos) {
+      std::string bool_val = num.value() == 0 ? "false" : "true";
+      template_params = UpdateName(template_params, is_first_template_parameter, bool_val);
+    } else {
+      template_params =
+          UpdateName(template_params, is_first_template_parameter, std::to_string(num.value()));
+    }
+  } else {
+    // Dwarf spec states that DW_TAG_value_parameter entries have a DW_AT_const_value or
+    // DW_AT_location attribute, which gives the value of the value parameter. However, in practice
+    // we often see parameter values which have neither attribute (e.g function pointers.) In such
+    // cases, we use the type of the parameter, as we do in DW_TAG_template_type_parameter entries.
+    template_params = UpdateName(
+        template_params, is_first_template_parameter, (child_type_info->base_name()).c_str());
+  }
+}
+
 std::string GenerateClassName(const auto& children,
                               auto class_name,
                               const nogrod::DwarfDie* die,
@@ -581,42 +629,13 @@ std::string GenerateClassName(const auto& children,
     if (child->tag() == DW_TAG_GNU_template_parameter_pack) {
       const auto& parameter_pack_children = child->children();
       for (auto child_child : parameter_pack_children) {
-        if (child_child->tag() == DW_TAG_template_type_parameter ||
-            child_child->tag() == DW_TAG_template_value_parameter) {
-          auto temp_type_die = GetAtTypeDie(child_child, dwarf_info);
-          if (temp_type_die == nullptr) {
-            continue;
-          }
-          auto template_type_info = ParseDie(temp_type_die, child, dwarf_info, types);
-          template_params =
-              UpdateName(template_params, i == 0, (template_type_info->base_name()).c_str());
-          continue;
-        }
+        GenerateClassTemplateParameter(
+            template_params, child_child, child, dwarf_info, types, i == 0);
       }
       continue;
     }
 
-    if (child->tag() == DW_TAG_template_type_parameter ||
-        child->tag() == DW_TAG_template_value_parameter) {
-      auto child_type_die = GetAtTypeDie(child, dwarf_info);
-      if (child_type_die == nullptr) {
-        continue;
-      }
-      auto child_type_info = ParseDie(child_type_die, die, dwarf_info, types);
-
-      if (std::string_view{child_type_info->base_name()}.find("bool") != std::string_view::npos) {
-        auto num = child->GetUint64Attribute(DW_AT_const_value);
-        if (num) {
-          // Using the value of bool to avoid dedup failure
-          std::string bool_val = num.value() == 0 ? "false" : "true";
-          template_params = UpdateName(template_params, i == 0, bool_val);
-        }
-      } else {
-        template_params =
-            UpdateName(template_params, i == 0, (child_type_info->base_name()).c_str());
-      }
-      continue;
-    }
+    GenerateClassTemplateParameter(template_params, child, die, dwarf_info, types, i == 0);
   }
 
   if (!template_params.empty()) {
@@ -626,11 +645,6 @@ std::string GenerateClassName(const auto& children,
   return class_name;
 }
 
-const TypeInfo* ParseDie(const nogrod::DwarfDie* start,
-                         const nogrod::DwarfDie* referenced_by,
-                         const nogrod::DwarfInfo* dwarf_info,
-                         std::unordered_map<uint64_t, std::unique_ptr<TypeInfo>>* types);
-
 const TypeInfo* ParseClass(const char* kind,
                            const nogrod::DwarfDie* die,
                            const nogrod::DwarfDie* referenced_by,
diff --git a/tools/prettify_asm.py b/tools/prettify_asm.py
index ec63dc21..d35f395a 100755
--- a/tools/prettify_asm.py
+++ b/tools/prettify_asm.py
@@ -90,9 +90,9 @@ def main(argv):
       return match
 
   # Make short lists one-liners
-  text = re.sub('[\[{][^][{}]*[]}]', replace_if_short, text)
+  text = re.sub('[\\[{][^][{}]*[]}]', replace_if_short, text)
   # Allow opcodes list.
-  text = re.sub('[\[{][^][{}]*"opcodes"[^][{}]*[\[{][^][{}]*[]}][^][{}]*[]}]', replace_if_short, text)
+  text = re.sub('[\\[{][^][{}]*"opcodes"[^][{}]*[\\[{][^][{}]*[]}][^][{}]*[]}]', replace_if_short, text)
 
   # Remove trailing spaces
   text = re.sub(' $', '', text, flags=re.MULTILINE)
diff --git a/tools/prettify_intrinsics.py b/tools/prettify_intrinsics.py
index 14bfe5ba..895808df 100755
--- a/tools/prettify_intrinsics.py
+++ b/tools/prettify_intrinsics.py
@@ -90,7 +90,7 @@ def main(argv):
       return match
 
   # Make short lists one-liners
-  text = re.sub('[\[{][^][{}]*[]}]', replace_if_short, text)
+  text = re.sub('[\\[{][^][{}]*[]}]', replace_if_short, text)
 
   # Remove trailing spaces
   text = re.sub(' $', '', text, flags=re.MULTILINE)
diff --git a/tools/prettify_ir_binding.py b/tools/prettify_ir_binding.py
index 1f39c49b..c1c3dc25 100755
--- a/tools/prettify_ir_binding.py
+++ b/tools/prettify_ir_binding.py
@@ -89,7 +89,7 @@ def main(argv):
       return match
 
   # Make short lists one-liners
-  text = re.sub('[\[{][^][{}]*[]}]', replace_if_short, text)
+  text = re.sub('[\\[{][^][{}]*[]}]', replace_if_short, text)
 
   # Remove trailing spaces
   text = re.sub(' $', '', text, flags=re.MULTILINE)
```

