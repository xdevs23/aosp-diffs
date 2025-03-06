```diff
diff --git a/Android.bp b/Android.bp
index ab519d2b..f5702d54 100644
--- a/Android.bp
+++ b/Android.bp
@@ -157,7 +157,7 @@ cc_library_shared {
         "libbase",
         "libberberis_assembler",
         "libberberis_base",
-        "libberberis_base_elf_backed_exec_region",
+        "libberberis_elf_backed_exec_region",
         "libberberis_instrument",
         "libberberis_intrinsics",
         "libberberis_kernel_api_riscv64",
@@ -193,7 +193,7 @@ cc_library_shared {
                 "libberberis_guest_os_primitives_riscv64",
                 // Android debuggerd reference symbols from get_cpu_state.
                 "libberberis_guest_state_riscv64",
-                "libberberis_runtime_riscv64_to_x86_64",
+                "libberberis_runtime_riscv64",
             ],
             export_static_lib_headers: [
                 "libberberis_guest_loader_riscv64",
@@ -221,7 +221,7 @@ cc_test_host {
     static_libs: [
         "libberberis_assembler",
         "libberberis_base",
-        "libberberis_base_elf_backed_exec_region",
+        "libberberis_elf_backed_exec_region",
         "libberberis_intrinsics",
         "libberberis_instrument",
         "libberberis_runtime_primitives",
@@ -235,7 +235,7 @@ cc_test_host {
     whole_static_libs: [
         "libberberis_assembler_unit_tests",
         "libberberis_base_unit_tests",
-        "libberberis_base_elf_backed_exec_region_unit_tests",
+        "libberberis_elf_backed_exec_region_unit_tests",
         "libberberis_calling_conventions_unit_tests",
         "libberberis_intrinsics_unit_tests",
         "libberberis_tinyloader_unit_tests",
@@ -271,7 +271,7 @@ cc_test_host {
                 "libberberis_macro_assembler_riscv64_to_x86_64",
                 "libberberis_intrinsics_riscv64",
                 "libberberis_runtime",
-                "libberberis_runtime_riscv64_to_x86_64",
+                "libberberis_runtime_riscv64",
                 "libberberis_runtime_primitives_riscv64",
                 "libberberis_code_gen_lib_riscv64",
             ],
diff --git a/OWNERS b/OWNERS
index e4a726eb..b0bc793f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,5 @@
 levarum@google.com
 khim@google.com
 dimitry@google.com
+anthonyjon@google.com
+richardfung@google.com
diff --git a/assembler/asm_defs.py b/assembler/asm_defs.py
index 530b1d60..c75d30d1 100644
--- a/assembler/asm_defs.py
+++ b/assembler/asm_defs.py
@@ -93,7 +93,8 @@ def is_mem_op(arg_type):
     # Universal memory operands
     'Mem', 'Mem8', 'Mem16', 'Mem32', 'Mem64', 'Mem128',
     # x86 memory operands
-    'MemX87', 'MemX8716', 'MemX8732', 'MemX8764', 'MemX8780', 'VecMem32', 'VecMem64', 'VecMem128')
+    'MemX87', 'MemX8716', 'MemX8732', 'MemX8764', 'MemX8780',
+    'VecMem32', 'VecMem64', 'VecMem128', 'VecMem256')
 
 
 def is_cond(arg_type):
@@ -132,6 +133,10 @@ def is_xreg(arg_type):
                       'FpReg32', 'FpReg64')
 
 
+def is_yreg(arg_type):
+  return arg_type in ('YmmReg','VecReg256')
+
+
 # Operands of this type are NOT passed to assembler
 def is_implicit_reg(arg_type):
   return arg_type in ('RAX', 'EAX', 'AX', 'AL',
@@ -163,6 +168,8 @@ def get_mem_macro_name(insn, addr_mode = None):
       macro_name += 'FReg'
     elif is_xreg(clazz):
       macro_name += 'XReg'
+    elif is_yreg(clazz):
+      macro_name += 'YReg'
     elif is_imm(clazz):
       macro_name += 'Imm'
     elif is_mem_op(clazz):
diff --git a/assembler/assembler_test.cc b/assembler/assembler_test.cc
index 9ec9f91a..6dc2e9bc 100644
--- a/assembler/assembler_test.cc
+++ b/assembler/assembler_test.cc
@@ -36,12 +36,19 @@
 using CodeEmitter = berberis::x86_32::Assembler;
 #elif defined(__amd64__)
 using CodeEmitter = berberis::x86_64::Assembler;
+#elif defined(__riscv)
+using CodeEmitter = berberis::rv64::Assembler;
 #else
 #error "Unsupported platform"
 #endif
 
 namespace berberis {
 
+enum class CPUArch {
+  kX86_64,
+  kRiscv64,
+};
+
 int Callee() {
   return 239;
 }
@@ -50,10 +57,19 @@ float FloatFunc(float f1, float f2) {
   return f1 - f2;
 }
 
+inline bool IsInstructionEqual(std::string code_str1,
+                               std::string code_str2,
+                               uint32_t insn,
+                               uint32_t insn_size) {
+  return code_str1.compare(
+             insn * (insn_size + 1), insn_size, code_str2, insn * (insn_size + 1), insn_size) == 0;
+}
+
 template <typename ParcelInt>
 inline bool CompareCode(const ParcelInt* code_template_begin,
                         const ParcelInt* code_template_end,
-                        const MachineCode& code) {
+                        const MachineCode& code,
+                        CPUArch arch) {
   if ((code_template_end - code_template_begin) * sizeof(ParcelInt) != code.install_size()) {
     ALOGE("Code size mismatch: %zd != %u",
           (code_template_end - code_template_begin) * static_cast<unsigned>(sizeof(ParcelInt)),
@@ -66,9 +82,34 @@ inline bool CompareCode(const ParcelInt* code_template_begin,
     MachineCode code2;
     code2.AddSequence(code_template_begin, code_template_end - code_template_begin);
     std::string code_str1, code_str2;
-    code.AsString(&code_str1);
-    code2.AsString(&code_str2);
-    ALOGE("assembler generated\n%s\nshall be\n%s", code_str1.c_str(), code_str2.c_str());
+    uint32_t insn_size = 0;
+    switch (arch) {
+      case CPUArch::kRiscv64:
+        insn_size = 8;
+        code.AsString(&code_str1, InstructionSize::FourBytes);
+        code2.AsString(&code_str2, InstructionSize::FourBytes);
+        break;
+      case CPUArch::kX86_64:
+        insn_size = 2;
+        code.AsString(&code_str1, InstructionSize::OneByte);
+        code2.AsString(&code_str2, InstructionSize::OneByte);
+        break;
+    }
+    CHECK_EQ(code_str1.size() % (insn_size + 1), 0);
+    CHECK_EQ(code_str2.size() % (insn_size + 1), 0);
+    uint32_t number_of_instructions = code_str1.size() / (insn_size + 1);
+    // Skip identical part.
+    uint32_t insn = 0;
+    while (insn < number_of_instructions &&
+           IsInstructionEqual(code_str1, code_str2, insn, insn_size)) {
+      insn++;
+    }
+    for (uint32_t i = insn; i < insn + 20 && i < number_of_instructions; i++) {
+      ALOGE("Assembler generated: %s, should be %s\n",
+            code_str1.substr(i * (insn_size + 1), insn_size).c_str(),
+            code_str2.substr(i * (insn_size + 1), insn_size).c_str());
+    }
+
     return false;
   }
   return true;
@@ -95,7 +136,7 @@ bool AssemblerTest() {
   assembler.Sb(Assembler::x14, data_end, Assembler::x15);
   assembler.Sh(Assembler::x16, data_end, Assembler::x17);
   assembler.Sw(Assembler::x18, data_end, Assembler::x19);
-  assembler.Lla(Assembler::x20, data_end);
+  assembler.La(Assembler::x20, data_end);
   assembler.Bcc(Assembler::Condition::kEqual, Assembler::x1, Assembler::x2, label);
   assembler.Bcc(Assembler::Condition::kNotEqual, Assembler::x3, Assembler::x4, label);
   assembler.Bcc(Assembler::Condition::kLess, Assembler::x5, Assembler::x6, label);
@@ -132,9 +173,18 @@ bool AssemblerTest() {
   assembler.PrefetchI({.base = Assembler::x1, .disp = 32});
   assembler.PrefetchR({.base = Assembler::x2, .disp = 64});
   assembler.PrefetchW({.base = Assembler::x3, .disp = 96});
+  assembler.Li(Assembler::x15, static_cast<int32_t>(0xaf));
+  assembler.Seqz(Assembler::x20, Assembler::x10);
+  assembler.Snez(Assembler::x2, Assembler::x9);
+  assembler.Sltz(Assembler::x30, Assembler::x1);
+  assembler.Sgtz(Assembler::x25, Assembler::x16);
+  assembler.J(0x42);
+  assembler.Jal(-0x26);
+  assembler.Jr(Assembler::x19);
+  assembler.Jalr(Assembler::x7);
   // Move target position for more than 2048 bytes down to ensure auipc would use non-zero
   // immediate.
-  for (size_t index = 120; index < 1200; ++index) {
+  for (size_t index = 138; index < 1200; ++index) {
     assembler.TwoByte(uint16_t{0});
   }
   assembler.Fld(Assembler::f1, data_begin, Assembler::x2);
@@ -149,8 +199,10 @@ bool AssemblerTest() {
   assembler.Sb(Assembler::x14, data_begin, Assembler::x15);
   assembler.Sh(Assembler::x16, data_begin, Assembler::x17);
   assembler.Sw(Assembler::x18, data_begin, Assembler::x19);
-  assembler.Lla(Assembler::x20, data_begin);
+  assembler.La(Assembler::x20, data_begin);
   assembler.Bind(&data_end);
+  assembler.Bexti(Assembler::x16, Assembler::x1, 20);
+  assembler.Rori(Assembler::x5, Assembler::x3, 5);
   assembler.Finalize();
 
   // clang-format off
@@ -215,7 +267,16 @@ bool AssemblerTest() {
     0xe013, 0x0200,     //        prefetch.i 32(x1)
     0x6013, 0x0411,     //        prefetch.r 64(x2)
     0xe013, 0x0631,     //        prefetch.w 96(x3)
-    [ 120 ... 1199 ] = 0,//       padding
+    0x0793, 0x0af0,     //        addi x15, x15, 0xaf
+    0x3a13, 0x0015,     //        sltiu x20, x10, 1
+    0x3133, 0x0090,     //        sltu x2, x0, x9
+    0xaf33, 0x0000,     //        slt x30, x1, x0
+    0x2cb3, 0x0100,     //        slt x25, x0, x16
+    0x006f, 0x0420,     //        jal zero, 0x42
+    0xf0ef, 0xfdbf,     //        jal x1, -0x26
+    0x8067, 0x0009,     //        jalr zero, x19, 0
+    0x80e7, 0x0003,     //        jalr x1, x7, 0
+    [ 138 ... 1199 ] = 0,//       padding
     0xf117, 0xffff,     //        auipc   x2, -4096
     0x3087, 0x6a01,     //        fld     f1,1696(x2)
     0xf217, 0xffff,     //        auipc   x4, -4096
@@ -242,10 +303,12 @@ bool AssemblerTest() {
     0xa423, 0x6529,     //        sw      x18,1608(x19)
     0xfa17, 0xffff,     //        auipc   x20, -4096
     0x0a13, 0x640a,     //        addi    x20,x20,1600
+    0xd813, 0x4940,     //        bexti    x16,x1,20
+    0xd293, 0x6051,     //        rori    x5, x3, 5
   };                    // end:
   // clang-format on
 
-  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code);
+  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code, CPUArch::kRiscv64);
 }
 
 }  // namespace rv32
@@ -305,15 +368,43 @@ bool AssemblerTest() {
   assembler.PrefetchI({.base = Assembler::x1, .disp = 32});
   assembler.PrefetchR({.base = Assembler::x2, .disp = 64});
   assembler.PrefetchW({.base = Assembler::x3, .disp = 96});
+  assembler.Li(Assembler::x10, static_cast<int64_t>(0xaaaa'0aa0'aaa0'0aaa));
+  assembler.Ret();
+  assembler.Call(data_end);
+  assembler.Tail(data_end);
+  assembler.Bgt(Assembler::x4, Assembler::x0, data_end);
+  assembler.Bgtu(Assembler::x2, Assembler::x20, data_end);
+  assembler.Ble(Assembler::x1, Assembler::x30, data_end);
+  assembler.Bleu(Assembler::x8, Assembler::x16, data_end);
+  assembler.Beqz(Assembler::x5, data_end);
+  assembler.Bnez(Assembler::x4, data_end);
+  assembler.Blez(Assembler::x2, data_end);
+  assembler.Bgez(Assembler::x3, data_end);
+  assembler.Bltz(Assembler::x9, data_end);
+  assembler.Bgtz(Assembler::x12, data_end);
   // Move target position for more than 2048 bytes down to ensure auipc would use non-zero
   // immediate.
-  for (size_t index = 96; index < 1200; ++index) {
+  for (size_t index = 142; index < 1200; ++index) {
     assembler.TwoByte(uint16_t{0});
   }
   assembler.Ld(Assembler::x1, data_begin);
   assembler.Lwu(Assembler::x2, data_begin);
   assembler.Sd(Assembler::x3, data_begin, Assembler::x4);
   assembler.Bind(&data_end);
+  assembler.SextW(Assembler::x15, Assembler::x12);
+  assembler.AddUW(Assembler::x14, Assembler::x22, Assembler::x29);
+  assembler.ZextW(Assembler::x13, Assembler::x21);
+  assembler.Sh3add(Assembler::x13, Assembler::x9, Assembler::x10);
+  assembler.Bexti(Assembler::x16, Assembler::x1, 53);
+  assembler.Rori(Assembler::x22, Assembler::x30, 43);
+  assembler.Roriw(Assembler::x29, Assembler::x2, 30);
+  assembler.Ror(Assembler::x14, Assembler::x1, Assembler::x10);
+  assembler.Rorw(Assembler::x25, Assembler::x5, Assembler::x4);
+  assembler.Not(Assembler::x10, Assembler::x4);
+  assembler.Neg(Assembler::x11, Assembler::x3);
+  assembler.Negw(Assembler::x12, Assembler::x2);
+  assembler.SextB(Assembler::x22, Assembler::x7);
+  assembler.SextH(Assembler::x23, Assembler::x8);
   assembler.Finalize();
 
   // clang-format off
@@ -366,17 +457,54 @@ bool AssemblerTest() {
     0xe013, 0x0200,     //        prefetch.i 32(x1)
     0x6013, 0x0411,     //        prefetch.r 64(x2)
     0xe013, 0x0631,     //        prefetch.w 96(x3)
-    [ 96 ... 1199 ] = 0,//        padding
+    0x5537,0xfd55,      //        lui a0, 0xfd555
+    0x0513, 0x0555,     //        addi a0, a0, 85
+    0x1513, 0x00d5,     //        slli a0, a0, 0xd
+    0x0513, 0x0ab5,     //        addi a0, a0, 171
+    0x1513, 0x00c5,     //        slli a0, a0, 0xc
+    0x0513, 0xa015,     //        addi a0, a0, -1535
+    0x1513, 0x00c5,     //        slli a0, a0, 0xc
+    0x0513, 0xaaa5,     //        addi a0,a0,-1366
+    0x8067, 0x0000,     //        ret
+    0x1317, 0x0000,     //        auipc x6, 0x1
+    0x00e7, 0x8943,     //        jalr x1, x6, -1900
+    0x1317, 0x0000,     //        auipc x6, 0x1
+    0x0067, 0x88c3,     //        jalr x0, x6, -1908
+    0x42e3, 0x0840,     //        blt x0, x4, 0x884
+    0x60e3, 0x082a,     //        bltu x20, x2, 0x880
+    0x5ee3, 0x061f,     //        bge x30, x1, 0x87c
+    0x7ce3, 0x0688,     //        bgeu x16, x8, 0x878
+    0x8ae3, 0x0602,     //        beq x5, 0x874
+    0x18e3, 0x0602,     //        bne x4, 0x870
+    0x56e3, 0x0620,     //        ble x2, 0x86c
+    0xd4e3, 0x0601,     //        bge x3, 0x868
+    0xc2e3, 0x0604,     //        blt x9, 0x864
+    0x40e3, 0x06c0,     //        bgt x12, 0x860
+    [ 142 ... 1199 ] = 0,//        padding
     0xf097, 0xffff,     //        auipc   x1, -4096
     0xb083, 0x6a00,     //        ld      x1, 1696(x1)
     0xf117, 0xffff,     //        auipc   x2, -4096
     0x6103, 0x6981,     //        lwu     x2, 1688(x2)
     0xf217, 0xffff,     //        auipc   x4, -4096
     0x3823, 0x6832,     //        sd      x3, 1680(x4)
+    0x079b, 0x0006,     //        addi.w x15, x12, 0
+    0x073b, 0x09db,     //        add.uw x14, x22, x29
+    0x86bb, 0x080a,     //        add.uw x13, x21, zero
+    0xe6b3, 0x20a4,     //        sh3add x13, x9, x10
+    0xd813, 0x4b50,     //        bexti x16, x1, 53
+    0x5b13, 0x62bf,     //        rori x22, x30, 43
+    0x5e9b, 0x61e1,     //        roriw x29, x2, 30
+    0xd733, 0x60a0,     //        ror x14, x1, x10
+    0xdcbb, 0x6042,     //        rorw x25, x5, x4
+    0x4513, 0xfff2,     //        xori x10, x4, -1
+    0x05b3, 0x4030,     //        sub x11, zero, x3
+    0x063b, 0x4020,     //        subw x12, zero, x2
+    0x9b13, 0x6043,     //        sext.b x22, x7
+    0x1b93, 0x6054,     //        sext.h x23, x8
   };                    // end:
   // clang-format on
 
-  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code);
+  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code, CPUArch::kRiscv64);
 }
 
 }  // namespace rv64
@@ -419,7 +547,7 @@ bool AssemblerTest() {
   };
   // clang-format on
 
-  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code);
+  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code, CPUArch::kX86_64);
 }
 
 }  // namespace x86_32
@@ -453,7 +581,7 @@ bool AssemblerTest() {
   };
   // clang-format on
 
-  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code);
+  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code, CPUArch::kX86_64);
 }
 
 }  // namespace x86_64
@@ -758,7 +886,7 @@ bool CondTest1() {
   ScopedExecRegion exec(&code);
 
   std::string code_str;
-  code.AsString(&code_str);
+  code.AsString(&code_str, InstructionSize::OneByte);
   using TestFunc = uint32_t(int, int);
   auto target_func = exec.get<TestFunc>();
   uint32_t result;
@@ -1141,7 +1269,8 @@ bool ExhaustiveTest() {
 #endif
   as.Finalize();
 
-  return CompareCode(berberis_gnu_as_output_start, berberis_gnu_as_output_end, code);
+  return CompareCode(
+      berberis_gnu_as_output_start, berberis_gnu_as_output_end, code, CPUArch::kX86_64);
 }
 
 bool MixedAssembler() {
@@ -1173,7 +1302,7 @@ bool MixedAssembler() {
   };
   // clang-format on
 
-  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code);
+  return CompareCode(std::begin(kCodeTemplate), std::end(kCodeTemplate), code, CPUArch::kX86_64);
 }
 #endif
 
@@ -1211,6 +1340,10 @@ TEST(Assembler, AssemblerTest) {
   EXPECT_TRUE(berberis::x86_64::ReadGlobalTest());
   EXPECT_TRUE(berberis::x86_64::MemShiftTest());
 #endif
+  // Currently we don't support these tests for riscv.
+  // TODO(b/352784623): Implement for riscv.
+#if defined(__i386__) || defined(__x86_64__)
   EXPECT_TRUE(berberis::ExhaustiveTest());
   EXPECT_TRUE(berberis::MixedAssembler());
+#endif
 }
diff --git a/assembler/gen_asm.py b/assembler/gen_asm.py
index 67412a86..0340f9ff 100644
--- a/assembler/gen_asm.py
+++ b/assembler/gen_asm.py
@@ -25,6 +25,8 @@ import sys
 
 INDENT = '  '
 
+ROUNDING_MODES = ['FE_TONEAREST', 'FE_DOWNWARD', 'FE_UPWARD', 'FE_TOWARDZERO', 'FE_TIESAWAY']
+
 _imm_types = {
     # x86 immediates
     'Imm2': 'int8_t',
@@ -56,6 +58,8 @@ def _get_arg_type_name(arg, insn_type):
     return 'FpRegister'
   if asm_defs.is_xreg(cls):
     return 'XMMRegister'
+  if asm_defs.is_yreg(cls):
+    return 'YMMRegister'
   if asm_defs.is_imm(cls):
     return _imm_types[cls]
   if asm_defs.is_disp(cls):
@@ -108,6 +112,7 @@ def _get_template_name(insn):
   if '<' not in name:
     return None, name
   return 'template <%s>' % ', '.join(
+      'int' if param.strip() in ROUNDING_MODES else
       'bool' if param.strip() in ('true', 'false') else
       'typename' if re.search('[_a-zA-Z]', param) else 'int'
       for param in name.split('<',1)[1][:-1].split(',')), name.split('<')[0]
@@ -381,7 +386,9 @@ _ARGUMENT_FORMATS_TO_SIZES = {
   'VecMem32': 'VectorMemory32Bit',
   'VecMem64': 'VectorMemory64Bit',
   'VecMem128': 'VectorMemory128Bit',
-  'VecReg128' : 'VectorRegister128Bit'
+  'VecMem256': 'VectorMemory256Bit',
+  'VecReg128' : 'VectorRegister128Bit',
+  'VecReg256' : 'VectorRegister256Bit'
 }
 
 
diff --git a/assembler/gen_asm_tests_x86.py b/assembler/gen_asm_tests_x86.py
index 827649a7..6e8f3467 100644
--- a/assembler/gen_asm_tests_x86.py
+++ b/assembler/gen_asm_tests_x86.py
@@ -101,7 +101,9 @@ sample_att_arguments_x86_32 = {
     'GeneralReg32': ('%ECX', '%EDX', '%EBX', '%ESP',
                      '%EBP', '%ESI', '%EDI', '%EAX'),
     'VecReg128': tuple('%%XMM%d' % N for N in (0, 4, 7)),
+    'VecReg256': tuple('%%YMM%d' % N for N in (0, 4, 7)),
     'XmmReg': tuple('%%XMM%d' % N for N in (0, 4, 7)),
+    'YmmReg': tuple('%%YMM%d' % N for N in (0, 4, 7)),
     'FpReg32': tuple('%%XMM%d' % N for N in range(8)),
     'FpReg64': tuple('%%XMM%d' % N for N in range(8)),
     'Label': ('0b', '1b', '2f'),
@@ -130,7 +132,9 @@ sample_att_arguments_x86_64 = {
                      '%R9', '%R10', '%R11', '%R12',
                      '%R13', '%R14', '%R15', '%RAX',),
     'VecReg128': tuple('%%XMM%d' % N for N in range(0, 16, 5)),
+    'VecReg256': tuple('%%YMM%d' % N for N in range(0, 16, 5)),
     'XmmReg': tuple('%%XMM%d' % N for N in range(0, 16, 5)),
+    'YmmReg': tuple('%%YMM%d' % N for N in range(0, 16, 5)),
     'FpReg32': tuple('%%XMM%d' % N for N in range(16)),
     'FpReg64': tuple('%%XMM%d' % N for N in range(16)),
     'Label': ('0b', '1b', '2f'),
@@ -183,7 +187,9 @@ sample_arc_arguments_x86_32 = {
     'GeneralReg16': gp_registers_32,
     'GeneralReg32': gp_registers_32,
     'VecReg128': tuple('Assembler::xmm%d' % N for N in (0, 4, 7)),
+    'VecReg256': tuple('Assembler::xmm%d.To256Bit()' % N for N in (0, 4, 7)),
     'XmmReg': tuple('Assembler::xmm%d' % N for N in (0, 4, 7)),
+    'YmmReg': tuple('Assembler::xmm%d.To256Bit()' % N for N in (0, 4, 7)),
     'FpReg32': tuple('Assembler::xmm%d' % N for N in range(8)),
     'FpReg64': tuple('Assembler::xmm%d' % N for N in range(8)),
 }
@@ -195,7 +201,9 @@ sample_arc_arguments_x86_64 = {
     'GeneralReg32': gp_registers_64,
     'GeneralReg64': gp_registers_64,
     'VecReg128': tuple('Assembler::xmm%d' % N for N in range(0, 16, 5)),
+    'VecReg256': tuple('Assembler::xmm%d.To256Bit()' % N for N in range(0, 16, 5)),
     'XmmReg': tuple('Assembler::xmm%d' % N for N in range(0, 16, 5)),
+    'YmmReg': tuple('Assembler::xmm%d.To256Bit()' % N for N in range(0, 16, 5)),
     'FpReg32': tuple('Assembler::xmm%d' % N for N in range(16)),
     'FpReg64': tuple('Assembler::xmm%d' % N for N in range(16)),
 }
@@ -251,7 +259,7 @@ def _update_arguments(x86_64):
             if index not in ('%ESP', '%RSP')]
   for mem_arg in ('Mem', 'Mem8', 'Mem16', 'Mem32', 'Mem64', 'Mem128',
                   'MemX87', 'MemX8716', 'MemX8732', 'MemX8764', 'MemX8780',
-                  'VecMem32', 'VecMem64', 'VecMem128'):
+                  'VecMem32', 'VecMem64', 'VecMem128', 'VecMem256'):
     sample_att_arguments[mem_arg] = tuple(addrs)
 
   sample_att_arguments['GeneralReg'] = sample_att_arguments[addr]
@@ -277,7 +285,7 @@ def _update_arguments(x86_64):
             if 'Assembler::esp' not in index and 'Assembler::rsp' not in index]
   for mem_arg in ('Mem', 'Mem8', 'Mem16', 'Mem32', 'Mem64', 'Mem128',
                   'MemX87', 'MemX8716', 'MemX8732', 'MemX8764', 'MemX8780',
-                  'VecMem32', 'VecMem64', 'VecMem128'):
+                  'VecMem32', 'VecMem64', 'VecMem128', 'VecMem256'):
     sample_arc_arguments[mem_arg] = tuple(addrs)
 
   sample_arc_arguments['GeneralReg'] = sample_arc_arguments[addr]
@@ -546,7 +554,10 @@ def _argument_class_to_arc_type(arg_class):
   elif sample_arc_arguments[arg_class][0].startswith('Assembler::st'):
     return 'Assembler::X87Register'
   elif sample_arc_arguments[arg_class][0].startswith('Assembler::xmm'):
-    return 'Assembler::XMMRegister'
+    if sample_arc_arguments[arg_class][0].endswith(".To256Bit()"):
+      return 'Assembler::YMMRegister'
+    else:
+      return 'Assembler::XMMRegister'
   else:
     return sample_arc_arguments[arg_class][0].split('(')[0]
 
diff --git a/assembler/include/berberis/assembler/machine_code.h b/assembler/include/berberis/assembler/machine_code.h
index 33d83078..f7e746d8 100644
--- a/assembler/include/berberis/assembler/machine_code.h
+++ b/assembler/include/berberis/assembler/machine_code.h
@@ -25,12 +25,22 @@
 
 #include "berberis/base/arena_alloc.h"
 #include "berberis/base/arena_vector.h"
-#include "berberis/base/exec_region_anonymous.h"
 #include "berberis/base/forever_map.h"
 #include "berberis/base/macros.h"  // DISALLOW_COPY_AND_ASSIGN
 
+#if defined(__riscv)
+#include <sys/cachectl.h>
+#endif
+
 namespace berberis {
 
+enum class InstructionSize {
+  // x86 assembly has 1 byte instructions.
+  OneByte,
+  // riscv and arm64 assembly have 4 bytes instructions.
+  FourBytes,
+};
+
 enum class RelocationType {
   // Convert absolute address to PC-relative displacement.
   // Ensure displacement fits in 32-bit value.
@@ -81,7 +91,7 @@ class MachineCode {
 
   void AddU8(uint8_t v) { code_.push_back(v); }
 
-  void AsString(std::string* result) const;
+  void AsString(std::string* result, InstructionSize insn_size) const;
 
   void AddRelocation(uint32_t dst, RelocationType type, uint32_t pc, intptr_t data) {
     relocations_.push_back(Relocation{dst, type, pc, data});
@@ -92,6 +102,9 @@ class MachineCode {
   void Install(ExecRegionType* exec, const uint8_t* code, RecoveryMap* recovery_map) {
     PerformRelocations(code, recovery_map);
     exec->Write(code, AddrAs<uint8_t>(0), code_.size());
+#if defined(__riscv)
+    __riscv_flush_icache((void*)code, (void*)(code + code_.size()), 0);
+#endif
   }
 
   // Install to writable memory.
@@ -101,7 +114,7 @@ class MachineCode {
   }
 
   // Print generated code to stderr.
-  void DumpCode() const;
+  void DumpCode(InstructionSize insn_size) const;
 
  private:
   struct Relocation {
diff --git a/assembler/include/berberis/assembler/riscv.h b/assembler/include/berberis/assembler/riscv.h
index 3771246c..80430c3a 100644
--- a/assembler/include/berberis/assembler/riscv.h
+++ b/assembler/include/berberis/assembler/riscv.h
@@ -762,6 +762,53 @@ class Assembler : public AssemblerBase {
   static constexpr FpRegister ft10{30};
   static constexpr FpRegister ft11{31};
 
+  class VRegister {
+   public:
+    constexpr bool operator==(const VRegister& reg) const { return num_ == reg.num_; }
+    constexpr bool operator!=(const VRegister& reg) const { return num_ != reg.num_; }
+    constexpr uint8_t GetPhysicalIndex() { return num_; }
+    friend constexpr uint8_t ValueForFmtSpec(VRegister value) { return value.num_; }
+    friend class Assembler<DerivedAssemblerType>;
+
+   private:
+    explicit constexpr VRegister(uint8_t num) : num_(num) {}
+    uint8_t num_;
+  };
+
+  static constexpr VRegister no_v_register{0x80};
+  static constexpr VRegister v0{0};
+  static constexpr VRegister v1{1};
+  static constexpr VRegister v2{2};
+  static constexpr VRegister v3{3};
+  static constexpr VRegister v4{4};
+  static constexpr VRegister v5{5};
+  static constexpr VRegister v6{6};
+  static constexpr VRegister v7{7};
+  static constexpr VRegister v8{8};
+  static constexpr VRegister v9{9};
+  static constexpr VRegister v10{10};
+  static constexpr VRegister v11{11};
+  static constexpr VRegister v12{12};
+  static constexpr VRegister v13{13};
+  static constexpr VRegister v14{14};
+  static constexpr VRegister v15{15};
+  static constexpr VRegister v16{16};
+  static constexpr VRegister v17{17};
+  static constexpr VRegister v18{18};
+  static constexpr VRegister v19{19};
+  static constexpr VRegister v20{20};
+  static constexpr VRegister v21{21};
+  static constexpr VRegister v22{22};
+  static constexpr VRegister v23{23};
+  static constexpr VRegister v24{24};
+  static constexpr VRegister v25{25};
+  static constexpr VRegister v26{26};
+  static constexpr VRegister v27{27};
+  static constexpr VRegister v28{28};
+  static constexpr VRegister v29{29};
+  static constexpr VRegister v30{30};
+  static constexpr VRegister v31{31};
+
   template <typename RegisterType, typename ImmediateType>
   struct Operand {
     RegisterType base{0};
@@ -1021,6 +1068,11 @@ class Assembler : public AssemblerBase {
     return EmitInstruction<kOpcode, 0x01f0'7fff>(Rs1(operand.base), operand.disp);
   }
 
+  template <uint32_t kOpcode, typename ArgumentsType0, typename ArgumentsType1>
+  void EmitRTypeInstruction(ArgumentsType0&& argument0, ArgumentsType1&& argument1) {
+    return EmitInstruction<kOpcode, 0xfff0'707f>(Rd(argument0), Rs1(argument1));
+  }
+
   template <uint32_t kOpcode, typename ArgumentsType0, typename ArgumentsType1>
   void EmitRTypeInstruction(ArgumentsType0&& argument0,
                             ArgumentsType1&& argument1,
@@ -1134,7 +1186,7 @@ BERBERIS_DEFINE_LOAD_INSTRUCTION(Lw, 0x0000'2003)
 #undef BERBERIS_DEFINE_LOAD_INSTRUCTION
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Lla(Register arg0, const Label& label) {
+inline void Assembler<DerivedAssemblerType>::La(Register arg0, const Label& label) {
   CHECK_NE(arg0, x0);
   jumps_.push_back(Jump{&label, pc(), false});
   // First issue auipc to load top 20 bits of difference between pc and target address
@@ -1193,7 +1245,7 @@ inline void Assembler<DerivedAssemblerType>::ResolveJumps() {
                   int32_t data : 12;
                 } bottom = {offset};
                 *AddrAs<int32_t>(pc) |= UImmediate{top}.EncodedValue();
-                *AddrAs<int32_t>(pc + 4) |= (*AddrAs<int32_t>(pc + 4) & 32)
+                *AddrAs<int32_t>(pc + 4) |= ((*AddrAs<int32_t>(pc + 4) & 96) == 32)
                                                 ? SImmediate{bottom.data}.EncodedValue()
                                                 : IImmediate{bottom.data}.EncodedValue();
                 return true;
@@ -1224,8 +1276,161 @@ inline void Assembler<DerivedAssemblerType>::Mv(Register dest, Register src) {
   Addi(dest, src, 0);
 }
 
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Li(Register dest, int32_t imm32) {
+  // If the value fits into 12bit I-Immediate type, load using addi.
+  if (-2048 <= imm32 && imm32 <= 2047) {
+    Addi(dest, Assembler::zero, static_cast<IImmediate>(imm32));
+  } else {
+    // Otherwise we need to use 2 instructions: lui to load top 20 bits and addi for bottom 12 bits,
+    // however since the I-Immediate is signed, we could not just split the number into 2 parts: for
+    // example loading 4095 should result in loading 1 in upper 20 bits (lui 0x1) and then
+    // subtracting 1 (addi dest, dest, -1).
+    // Perform calculations on unsigned type to avoid undefined behavior.
+    uint32_t uimm = static_cast<uint32_t>(imm32);
+    // Since bottom 12bits are loaded via a 12-bit signed immediate, we need to add the sign bit to
+    // the top part.
+    int32_t top = (uimm + ((uimm & (1U << 11)) << 1)) & 0xffff'f000;
+    // Sign extends the bottom 12 bits.
+    struct {
+      int32_t data : 12;
+    } bottom = {imm32};
+    Lui(dest, static_cast<UImmediate>(top));
+    if (bottom.data) {
+      Addi(dest, dest, static_cast<IImmediate>(bottom.data));
+    }
+  }
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Ret() {
+  Jalr(Assembler::x0, Assembler::x1, static_cast<IImmediate>(0));
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Call(const Label& label) {
+  jumps_.push_back(Jump{&label, pc(), false});
+  // First issue auipc to load top 20 bits of difference between pc and target address
+  EmitUTypeInstruction<uint32_t{0x0000'0017}>(Assembler::x6, UImmediate{0});
+  // The low 12 bite of difference will be added with jalr instruction
+  EmitITypeInstruction<uint32_t{0x0000'0067}>(Assembler::x1, Assembler::x6, IImmediate{0});
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Tail(const Label& label) {
+  jumps_.push_back(Jump{&label, pc(), false});
+  // First issue auipc to load top 20 bits of difference between pc and target address
+  EmitUTypeInstruction<uint32_t{0x0000'0017}>(Assembler::x6, UImmediate{0});
+  // The low 12 bite of difference will be added with jalr instruction
+  EmitITypeInstruction<uint32_t{0x0000'0067}>(Assembler::x0, Assembler::x6, IImmediate{0});
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Bgt(Register arg0, Register arg1, const Label& label) {
+  Blt(arg1, arg0, label);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Bgtu(Register arg0,
+                                                  Register arg1,
+                                                  const Label& label) {
+  Bltu(arg1, arg0, label);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Ble(Register arg0, Register arg1, const Label& label) {
+  Bge(arg1, arg0, label);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Bleu(Register arg0,
+                                                  Register arg1,
+                                                  const Label& label) {
+  Bgeu(arg1, arg0, label);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Beqz(Register arg0, const Label& label) {
+  Beq(arg0, zero, label);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Bnez(Register arg0, const Label& label) {
+  Bne(arg0, zero, label);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Blez(Register arg0, const Label& label) {
+  Ble(arg0, zero, label);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Bgez(Register arg0, const Label& label) {
+  Bge(arg0, zero, label);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Bltz(Register arg0, const Label& label) {
+  Blt(arg0, zero, label);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Bgtz(Register arg0, const Label& label) {
+  Bgt(arg0, zero, label);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Seqz(Register arg0, Register arg1) {
+  Sltiu(arg0, arg1, static_cast<IImmediate>(1));
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Snez(Register arg0, Register arg1) {
+  Sltu(arg0, zero, arg1);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Sltz(Register arg0, Register arg1) {
+  Slt(arg0, arg1, zero);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Sgtz(Register arg0, Register arg1) {
+  Slt(arg0, zero, arg1);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::J(JImmediate arg0) {
+  Jal(zero, arg0);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Jal(JImmediate arg0) {
+  Jal(x1, arg0);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Jr(Register arg0) {
+  Jalr(zero, arg0, 0);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Jalr(Register arg0) {
+  Jalr(x1, arg0, 0);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Not(Register arg0, Register arg1) {
+  Xori(arg0, arg1, -1);
+}
+
+template <typename DerivedAssemblerType>
+inline void Assembler<DerivedAssemblerType>::Neg(Register arg0, Register arg1) {
+  Sub(arg0, zero, arg1);
+}
+
 }  // namespace riscv
 
 }  // namespace berberis
 
-#endif  // BERBERIS_ASSEMBLER_COMMON_X86_H_
+#endif  // BERBERIS_ASSEMBLER_COMMON_RISCV_H_
diff --git a/assembler/include/berberis/assembler/rv64.h b/assembler/include/berberis/assembler/rv64.h
index e702adea..434470cf 100644
--- a/assembler/include/berberis/assembler/rv64.h
+++ b/assembler/include/berberis/assembler/rv64.h
@@ -19,6 +19,7 @@
 #ifndef BERBERIS_ASSEMBLER_RV64_H_
 #define BERBERIS_ASSEMBLER_RV64_H_
 
+#include <bit>          // std::countr_zero
 #include <type_traits>  // std::is_same
 
 #include "berberis/assembler/riscv.h"
@@ -60,6 +61,7 @@ class Assembler : public riscv::Assembler<Assembler> {
   Assembler(Assembler&&) = delete;
   void operator=(const Assembler&) = delete;
   void operator=(Assembler&&) = delete;
+  void Li32(Register dest, int32_t imm32);
 };
 
 inline void Assembler::Ld(Register arg0, const Label& label) {
@@ -70,6 +72,36 @@ inline void Assembler::Ld(Register arg0, const Label& label) {
   EmitITypeInstruction<uint32_t{0x0000'3003}>(arg0, Operand<Register, IImmediate>{.base = arg0});
 }
 
+// It's needed to unhide 32bit immediate version.
+inline void Assembler::Li32(Register dest, int32_t imm32) {
+  BaseAssembler::Li(dest, imm32);
+};
+
+inline void Assembler::Li(Register dest, int64_t imm64) {
+  int32_t imm32 = static_cast<int32_t>(imm64);
+  if (static_cast<int64_t>(imm32) == imm64) {
+    Li32(dest, imm32);
+  } else {
+    // Perform calculations on unsigned type to avoid undefined behavior.
+    uint64_t uimm = static_cast<uint64_t>(imm64);
+    if (imm64 & 0xfff) {
+      // Since bottom 12bits are loaded via a 12-bit signed immediate, we need to transfer the sign
+      // bit to the top part.
+      int64_t top = (uimm + ((uimm & (1ULL << 11)) << 1)) & 0xffff'ffff'ffff'f000;
+      // Sign extends the bottom 12 bits.
+      struct {
+        int64_t data : 12;
+      } bottom = {imm64};
+      Li(dest, top);
+      Addi(dest, dest, static_cast<IImmediate>(bottom.data));
+    } else {
+      uint8_t zeros = std::countr_zero(uimm);
+      Li(dest, imm64 >> zeros);
+      Slli(dest, dest, static_cast<Shift64Immediate>(zeros));
+    }
+  }
+}
+
 inline void Assembler::Lwu(Register arg0, const Label& label) {
   jumps_.push_back(Jump{&label, pc(), false});
   // First issue auipc to load top 20 bits of difference between pc and target address
@@ -86,6 +118,18 @@ inline void Assembler::Sd(Register arg0, const Label& label, Register arg2) {
   EmitSTypeInstruction<uint32_t{0x0000'3023}>(arg0, Operand<Register, SImmediate>{.base = arg2});
 }
 
+inline void Assembler::SextW(Register arg0, Register arg1) {
+  Addiw(arg0, arg1, 0);
+}
+
+inline void Assembler::ZextW(Register arg0, Register arg1) {
+  AddUW(arg0, arg1, zero);
+}
+
+inline void Assembler::Negw(Register arg0, Register arg1) {
+  Subw(arg0, zero, arg1);
+}
+
 }  // namespace berberis::rv64
 
 #endif  // BERBERIS_ASSEMBLER_RV64_H_
diff --git a/assembler/include/berberis/assembler/rv64i.h b/assembler/include/berberis/assembler/rv64i.h
index 99815f54..8bd818ab 100644
--- a/assembler/include/berberis/assembler/rv64i.h
+++ b/assembler/include/berberis/assembler/rv64i.h
@@ -42,6 +42,7 @@ class Assembler : public ::berberis::rv64::Assembler {
   static constexpr Register t1{6};
   static constexpr Register t2{7};
   static constexpr Register s0{8};
+  static constexpr Register fp{8};
   static constexpr Register s1{9};
   static constexpr Register a0{10};
   static constexpr Register a1{11};
diff --git a/assembler/include/berberis/assembler/x86_32.h b/assembler/include/berberis/assembler/x86_32.h
index bd88a2b6..cbccdc79 100644
--- a/assembler/include/berberis/assembler/x86_32.h
+++ b/assembler/include/berberis/assembler/x86_32.h
@@ -145,7 +145,7 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
 
   // TODO(b/127356868): decide what to do with these functions when cross-arch assembler is used.
 
-#ifdef __i386__
+#if defined(__i386__)
 
   // Unside Call(Reg), hidden by special version below.
   using BaseAssembler::Call;
@@ -161,11 +161,15 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
   // Unside Jcc(Label), hidden by special version below.
   using BaseAssembler::Jcc;
 
-  // Make sure only type void* can be passed to function below, not Label* or any other type.
+  // Make sure only type void* can be passed to function below, not Label* or any other pointer.
   template <typename T>
   auto Jcc(Condition cc, T* target) -> void = delete;
 
-  void Jcc(Condition cc, const void* target) {
+  template <typename T>
+  auto Jcc(Condition cc, T target)
+      -> std::enable_if_t<std::is_integral_v<T> && sizeof(uintptr_t) < sizeof(T)> = delete;
+
+  void Jcc(Condition cc, uintptr_t target) {
     if (cc == Condition::kAlways) {
       Jmp(target);
       return;
@@ -177,26 +181,32 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
     Emit8(0x80 | static_cast<uint8_t>(cc));
     Emit32(0xcccccccc);
     // Set last 4 bytes to displacement from current pc to 'target'.
-    AddRelocation(
-        pc() - 4, RelocationType::RelocAbsToDisp32, pc(), reinterpret_cast<intptr_t>(target));
+    AddRelocation(pc() - 4, RelocationType::RelocAbsToDisp32, pc(), bit_cast<intptr_t>(target));
   }
 
+  void Jcc(Condition cc, const void* target) { Jcc(cc, bit_cast<uintptr_t>(target)); }
+
   // Unside Jmp(Reg), hidden by special version below.
   using BaseAssembler::Jmp;
 
-  // Make sure only type void* can be passed to function below, not Label* or any other type.
+  // Make sure only type void* can be passed to function below, not Label* or any other pointer.
   template <typename T>
   auto Jmp(T* target) -> void = delete;
 
-  void Jmp(const void* target) {
+  template <typename T>
+  auto Jmp(T target)
+      -> std::enable_if_t<std::is_integral_v<T> && sizeof(uintptr_t) < sizeof(T)> = delete;
+
+  void Jmp(uintptr_t target) {
     Emit8(0xe9);
     Emit32(0xcccccccc);
     // Set last 4 bytes to displacement from current pc to 'target'.
-    AddRelocation(
-        pc() - 4, RelocationType::RelocAbsToDisp32, pc(), reinterpret_cast<intptr_t>(target));
+    AddRelocation(pc() - 4, RelocationType::RelocAbsToDisp32, pc(), bit_cast<intptr_t>(target));
   }
 
-#endif
+  void Jmp(const void* target) { Jmp(bit_cast<uintptr_t>(target)); }
+
+#endif  // defined(__i386__)
 
  private:
   Assembler() = delete;
diff --git a/assembler/include/berberis/assembler/x86_32_and_x86_64.h b/assembler/include/berberis/assembler/x86_32_and_x86_64.h
index 81680482..825db8ed 100644
--- a/assembler/include/berberis/assembler/x86_32_and_x86_64.h
+++ b/assembler/include/berberis/assembler/x86_32_and_x86_64.h
@@ -169,21 +169,33 @@ class Assembler : public AssemblerBase {
   static constexpr X87Register st6{6};
   static constexpr X87Register st7{7};
 
-  class XMMRegister {
+  template <int kBits>
+  class SIMDRegister {
    public:
-    constexpr bool operator==(const XMMRegister& reg) const { return num_ == reg.num_; }
-    constexpr bool operator!=(const XMMRegister& reg) const { return num_ != reg.num_; }
+    constexpr bool operator==(const SIMDRegister& reg) const { return num_ == reg.num_; }
+    constexpr bool operator!=(const SIMDRegister& reg) const { return num_ != reg.num_; }
     constexpr uint8_t GetPhysicalIndex() { return num_; }
-    friend constexpr uint8_t ValueForFmtSpec(XMMRegister value) { return value.num_; }
+    friend constexpr uint8_t ValueForFmtSpec(SIMDRegister value) { return value.num_; }
     friend class Assembler<DerivedAssemblerType>;
     friend class x86_32::Assembler;
     friend class x86_64::Assembler;
+    friend class SIMDRegister<384 - kBits>;
+
+    constexpr auto To128Bit() const {
+      return std::enable_if_t<kBits != 128, SIMDRegister<128>>{num_};
+    }
+    constexpr auto To256Bit() const {
+      return std::enable_if_t<kBits != 256, SIMDRegister<256>>{num_};
+    }
 
    private:
-    explicit constexpr XMMRegister(uint8_t num) : num_(num) {}
+    explicit constexpr SIMDRegister(uint8_t num) : num_(num) {}
     uint8_t num_;
   };
 
+  using XMMRegister = SIMDRegister<128>;
+  using YMMRegister = SIMDRegister<256>;
+
   enum ScaleFactor { kTimesOne = 0, kTimesTwo = 1, kTimesFour = 2, kTimesEight = 3 };
 
   struct Operand {
@@ -274,7 +286,7 @@ class Assembler : public AssemblerBase {
 #include "berberis/assembler/gen_assembler_x86_32_and_x86_64-inl.h"  // NOLINT generated file
 
   // Flow control.
-  void Jmp(int32_t offset) {
+  void JmpRel(int32_t offset) {
     CHECK_GE(offset, INT32_MIN + 2);
     int32_t short_offset = offset - 2;
     if (IsInRange<int8_t>(short_offset)) {
@@ -293,9 +305,9 @@ class Assembler : public AssemblerBase {
     Emit32(offset - 5);
   }
 
-  void Jcc(Condition cc, int32_t offset) {
+  void JccRel(Condition cc, int32_t offset) {
     if (cc == Condition::kAlways) {
-      Jmp(offset);
+      JmpRel(offset);
       return;
     }
     if (cc == Condition::kNever) {
@@ -322,46 +334,53 @@ class Assembler : public AssemblerBase {
     uint8_t num_;
   };
 
-  struct Register32Bit {
-    explicit constexpr Register32Bit(Register reg) : num_(reg.num_) {}
-    explicit constexpr Register32Bit(XMMRegister reg) : num_(reg.num_) {}
+  // Any register number that doesn't need special processing.
+  struct SizeAgnosticRegister {
+    explicit constexpr SizeAgnosticRegister(Register reg) : num_(reg.num_) {}
+    explicit constexpr SizeAgnosticRegister(XMMRegister reg) : num_(reg.num_) {}
+    explicit constexpr SizeAgnosticRegister(YMMRegister reg) : num_(reg.num_) {}
     uint8_t num_;
   };
 
-  // 16-bit and 128-bit vector registers follow the same rules as 32-bit registers.
-  using Register16Bit = Register32Bit;
-  using VectorRegister128Bit = Register32Bit;
+  // 16-bit, 32bit, 128-bit, and 256bit vector registers don't need special rules.
+  using Register16Bit = SizeAgnosticRegister;
+  using Register32Bit = SizeAgnosticRegister;
+  using VectorRegister128Bit = SizeAgnosticRegister;
+  using VectorRegister256Bit = SizeAgnosticRegister;
   // Certain instructions (Enter/Leave, Jcc/Jmp/Loop, Call/Ret, Push/Pop) always operate
   // on registers of default size (32-bit in 32-bit mode, 64-bit in 64-bit mode (see
   // "Instructions Not Requiring REX Prefix in 64-Bit Mode" table in 24594 AMD Manual)
-  // Map these to Register32Bit, too, since they don't need REX.W even in 64-bit mode.
+  // Map these to SizeAgnosticRegister, too, since they don't need REX.W even in 64-bit mode.
   //
   // x87 instructions fall into that category, too, since they were not expanded in x86-64 mode.
-  using RegisterDefaultBit = Register32Bit;
+  using RegisterDefaultBit = SizeAgnosticRegister;
 
-  struct Memory32Bit {
-    explicit Memory32Bit(const Operand& op) : operand(op) {}
+  // Any memory address that doesn't need special processing.
+  struct SizeAgnosticMemory {
+    explicit SizeAgnosticMemory(const Operand& op) : operand(op) {}
     Operand operand;
   };
 
   // 8-bit, 16-bit, 128-bit memory behave the same as 32-bit memory.
   // Only 64-bit memory is different.
-  using Memory8Bit = Memory32Bit;
-  using Memory16Bit = Memory32Bit;
+  using Memory8Bit = SizeAgnosticMemory;
+  using Memory16Bit = SizeAgnosticMemory;
+  using Memory32Bit = SizeAgnosticMemory;
   // Some instructions have memory operand that have unspecified size (lea, prefetch, etc),
-  // they are encoded like Memory32Bit, anyway.
-  using MemoryDefaultBit = Memory32Bit;
+  // they are encoded like SizeAgnosticMemory, anyway.
+  using MemoryDefaultBit = SizeAgnosticMemory;
   // X87 instructions always use the same encoding - even for 64-bit or 28-bytes
   // memory operands (like in fldenv/fnstenv)
-  using MemoryX87 = Memory32Bit;
-  using MemoryX8716Bit = Memory32Bit;
-  using MemoryX8732Bit = Memory32Bit;
-  using MemoryX8764Bit = Memory32Bit;
-  using MemoryX8780Bit = Memory32Bit;
+  using MemoryX87 = SizeAgnosticMemory;
+  using MemoryX8716Bit = SizeAgnosticMemory;
+  using MemoryX8732Bit = SizeAgnosticMemory;
+  using MemoryX8764Bit = SizeAgnosticMemory;
+  using MemoryX8780Bit = SizeAgnosticMemory;
   // Most vector instructions don't need to use REX.W to access 64-bit or 128-bit memory.
-  using VectorMemory32Bit = Memory32Bit;
-  using VectorMemory64Bit = Memory32Bit;
-  using VectorMemory128Bit = Memory32Bit;
+  using VectorMemory32Bit = SizeAgnosticMemory;
+  using VectorMemory64Bit = SizeAgnosticMemory;
+  using VectorMemory128Bit = SizeAgnosticMemory;
+  using VectorMemory256Bit = SizeAgnosticMemory;
 
   // Labels types for memory quantities.  Note that names are similar to the ones before because
   // they are autogenerated.  E.g. VectorLabel32Bit should be read as “VECTOR's operation LABEL
@@ -852,7 +871,7 @@ inline void Assembler<DerivedAssemblerType>::Jcc(Condition cc, const Label& labe
   // Then jcc by label will be of fixed size (5 bytes)
   if (label.IsBound()) {
     int32_t offset = label.position() - pc();
-    Jcc(cc, offset);
+    JccRel(cc, offset);
   } else {
     Emit16(0x800f | (static_cast<uint8_t>(cc) << 8));
     Emit32(0xfffffffc);
@@ -866,7 +885,7 @@ inline void Assembler<DerivedAssemblerType>::Jmp(const Label& label) {
   // Then jmp by label will be of fixed size (5 bytes)
   if (label.IsBound()) {
     int32_t offset = label.position() - pc();
-    Jmp(offset);
+    JmpRel(offset);
   } else {
     Emit8(0xe9);
     Emit32(0xfffffffc);
@@ -896,11 +915,11 @@ template <typename DerivedAssemblerType>
 inline void Assembler<DerivedAssemblerType>::Xchgl(Register dest, Register src) {
   if (DerivedAssemblerType::IsAccumulator(src) || DerivedAssemblerType::IsAccumulator(dest)) {
     Register other = DerivedAssemblerType::IsAccumulator(src) ? dest : src;
-    EmitInstruction<0x90>(Register32Bit(other));
+    EmitInstruction<0x90>(SizeAgnosticRegister(other));
   } else {
     // Clang 8 (after r330298) puts dest before src.  We are comparing output
     // to clang in exhaustive test thus we want to match clang behavior exactly.
-    EmitInstruction<0x87>(Register32Bit(dest), Register32Bit(src));
+    EmitInstruction<0x87>(SizeAgnosticRegister(dest), SizeAgnosticRegister(src));
   }
 }
 
diff --git a/assembler/include/berberis/assembler/x86_64.h b/assembler/include/berberis/assembler/x86_64.h
index 64560698..5d29d690 100644
--- a/assembler/include/berberis/assembler/x86_64.h
+++ b/assembler/include/berberis/assembler/x86_64.h
@@ -151,11 +151,15 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
   // Unhide Jcc(Label), hidden by special version below.
   using BaseAssembler::Jcc;
 
-  // Make sure only type void* can be passed to function below, not Label* or any other type.
+  // Make sure only type void* can be passed to function below, not Label* or any other pointer.
   template <typename T>
   auto Jcc(Condition cc, T* target) -> void = delete;
 
-  void Jcc(Condition cc, const void* target) {
+  template <typename T>
+  auto Jcc(Condition cc, T target)
+      -> std::enable_if_t<std::is_integral_v<T> && sizeof(uintptr_t) < sizeof(T)> = delete;
+
+  void Jcc(Condition cc, uintptr_t target) {
     if (cc == Condition::kAlways) {
       Jmp(target);
       return;
@@ -176,14 +180,20 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
     Emit64(bit_cast<int64_t>(target));
   }
 
+  void Jcc(Condition cc, const void* target) { Jcc(cc, bit_cast<uintptr_t>(target)); }
+
   // Unhide Jmp(Reg), hidden by special version below.
   using BaseAssembler::Jmp;
 
-  // Make sure only type void* can be passed to function below, not Label* or any other type.
+  // Make sure only type void* can be passed to function below, not Label* or any other pointer.
   template <typename T>
   auto Jmp(T* target) -> void = delete;
 
-  void Jmp(const void* target) {
+  template <typename T>
+  auto Jmp(T target)
+      -> std::enable_if_t<std::is_integral_v<T> && sizeof(uintptr_t) < sizeof(T)> = delete;
+
+  void Jmp(uintptr_t target) {
     // There are no jump instruction with properties we need thus we emulate it.
     // This is what the following code looks like when decoded with objdump (if
     // target address is 0x123456789abcdef0):
@@ -196,6 +206,8 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
     Emit64(bit_cast<int64_t>(target));
   }
 
+  void Jmp(const void* target) { Jmp(bit_cast<uintptr_t>(target)); }
+
 #endif
 
  private:
diff --git a/assembler/instructions/insn_def_riscv.json b/assembler/instructions/insn_def_riscv.json
index 0fd186bf..3d14c5ea 100644
--- a/assembler/instructions/insn_def_riscv.json
+++ b/assembler/instructions/insn_def_riscv.json
@@ -16,16 +16,6 @@
   ],
   "arch": "common_riscv",
   "insns": [
-    {
-      "encodings": {
-        "auipc": { "opcode": "0000_0017", "type": "U-Type" },
-        "lui": { "opcode": "0000_0017", "type": "U-Type" }
-      },
-      "args": [
-        { "class": "GeneralReg", "usage": "def" },
-        { "class": "U-Imm" }
-      ]
-    },
     {
       "encodings": {
         "add": { "opcode": "0000_0033", "type": "R-type" },
@@ -39,6 +29,8 @@
         "or": { "opcode": "0000_6033", "type": "R-type" },
         "rem": { "opcode": "0200_6033", "type": "R-type" },
         "remu": { "opcode": "0200_7033", "type": "R-type" },
+        "ror": { "opcode": "6000_5033", "type": "R-type" },
+        "sh3add": { "opcode": "2000_6033", "type": "R-type" },
         "sll": { "opcode": "0000_1033", "type": "R-type" },
         "slt": { "opcode": "0000_2033", "type": "R-type" },
         "sltu": { "opcode": "0000_3033", "type": "R-type" },
@@ -71,6 +63,16 @@
         { "class": "I-Imm" }
       ]
     },
+    {
+      "encodings": {
+        "auipc": { "opcode": "0000_0017", "type": "U-Type" },
+        "lui": { "opcode": "0000_0037", "type": "U-Type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "U-Imm" }
+      ]
+    },
     {
       "stems": [ "bcc" ],
       "args": [
@@ -89,14 +91,22 @@
         { "class": "Label" }
       ]
     },
+    {
+      "stems": [ "beq", "bge", "bgeu", "bgt", "bgtu", "ble", "bleu", "blt", "bltu", "bne" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Label" }
+      ]
+    },
     {
       "encodings": {
-         "beq": { "opcode": "0000_0063", "type": "B-Type" },
-         "bge": { "opcode": "0000_5063", "type": "B-Type" },
-         "bgeu": { "opcode": "0000_7063", "type": "B-Type" },
-         "blt": { "opcode": "0000_4063", "type": "B-Type" },
-         "bltu": { "opcode": "0000_6063", "type": "B-Type" },
-         "bne": { "opcode": "0000_1063", "type": "B-Type" }
+        "beq": { "opcode": "0000_0063", "type": "B-Type" },
+        "bge": { "opcode": "0000_5063", "type": "B-Type" },
+        "bgeu": { "opcode": "0000_7063", "type": "B-Type" },
+        "blt": { "opcode": "0000_4063", "type": "B-Type" },
+        "bltu": { "opcode": "0000_6063", "type": "B-Type" },
+        "bne": { "opcode": "0000_1063", "type": "B-Type" }
       },
       "args": [
         { "class": "GeneralReg", "usage": "use" },
@@ -105,23 +115,16 @@
       ]
     },
     {
-      "stems": [ "beq", "bge", "bgeu", "blt", "bltu", "bne" ],
+      "stems": [ "beqz", "bgez", "bgtz", "blez", "bltz", "bnez" ],
       "args": [
-        { "class": "GeneralReg", "usage": "use" },
         { "class": "GeneralReg", "usage": "use" },
         { "class": "Label" }
       ]
     },
     {
-      "encodings": {
-        "csrrc": { "opcode": "0000_3073", "type": "I-type" },
-        "csrrs": { "opcode": "0000_2073", "type": "I-type" },
-        "csrrw": { "opcode": "0000_1073", "type": "I-type" }
-      },
+      "stems": [ "call", "tail" ],
       "args": [
-        { "class": "GeneralReg", "usage": "def" },
-        { "class": "CsrReg", "usage": "use_def" },
-        { "class": "GeneralReg", "usage": "use" }
+        { "class": "Label" }
       ]
     },
     {
@@ -139,12 +142,24 @@
         { "class": "Csr-Imm" }
       ]
     },
+    {
+      "encodings": {
+        "csrrc": { "opcode": "0000_3073", "type": "I-type" },
+        "csrrs": { "opcode": "0000_2073", "type": "I-type" },
+        "csrrw": { "opcode": "0000_1073", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "CsrReg", "usage": "use_def" },
+        { "class": "GeneralReg", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "fcvt.d.s": { "opcode": "4200_0053", "type": "R-type" },
         "fcvt.s.d": { "opcode": "4010_0053", "type": "R-type" },
-        "fsqrt.s": { "opcode": "5800_0053", "type": "R-type" },
-        "fsqrt.d": { "opcode": "5a00_0053", "type": "R-type" }
+        "fsqrt.d": { "opcode": "5a00_0053", "type": "R-type" },
+        "fsqrt.s": { "opcode": "5800_0053", "type": "R-type" }
       },
       "args": [
         { "class": "FpReg", "usage": "def" },
@@ -168,8 +183,8 @@
     {
       "encodings": {
         "fcvt.w.d": { "opcode": "c200_0053", "type": "R-type" },
-        "fcvt.wu.d": { "opcode": "c210_0053", "type": "R-type" },
         "fcvt.w.s": { "opcode": "c000_0053", "type": "R-type" },
+        "fcvt.wu.d": { "opcode": "c210_0053", "type": "R-type" },
         "fcvt.wu.s": { "opcode": "c010_0053", "type": "R-type" }
       },
       "args": [
@@ -178,15 +193,6 @@
         { "class": "Rm", "usage": "use" }
       ]
     },
-    {
-      "encodings": {
-        "fld": { "opcode": "0000_3007", "type": "I-type" }
-      },
-      "args": [
-        { "class": "FpReg", "usage": "def" },
-        { "class": "Mem64", "usage": "use" }
-      ]
-    },
     {
       "stems": [ "fld", "flw" ],
       "args": [
@@ -197,20 +203,20 @@
     },
     {
       "encodings": {
-        "flw": { "opcode": "0000_2007", "type": "I-type" }
+        "fld": { "opcode": "0000_3007", "type": "I-type" }
       },
       "args": [
         { "class": "FpReg", "usage": "def" },
-        { "class": "Mem32", "usage": "use" }
+        { "class": "Mem64", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "fsd": { "opcode": "0000_3027", "type": "S-type" }
+        "flw": { "opcode": "0000_2007", "type": "I-type" }
       },
       "args": [
-        { "class": "FpReg", "usage": "use" },
-        { "class": "Mem64", "usage": "def" }
+        { "class": "FpReg", "usage": "def" },
+        { "class": "Mem32", "usage": "use" }
       ]
     },
     {
@@ -221,6 +227,15 @@
         { "class": "GeneralReg", "usage": "def" }
       ]
     },
+    {
+      "encodings": {
+        "fsd": { "opcode": "0000_3027", "type": "S-type" }
+      },
+      "args": [
+        { "class": "FpReg", "usage": "use" },
+        { "class": "Mem64", "usage": "def" }
+      ]
+    },
     {
       "encodings": {
         "fsw": { "opcode": "0000_2027", "type": "S-type" }
@@ -230,6 +245,12 @@
         { "class": "Mem32", "usage": "def" }
       ]
     },
+    {
+      "stems": [ "j", "jal" ],
+      "args": [
+        { "class": "J-Imm" }
+      ]
+    },
     {
       "encodings": {
         "jal": { "opcode": "0000_006f", "type": "J-Type" }
@@ -246,6 +267,12 @@
         { "class": "Label" }
       ]
     },
+    {
+      "stems": [ "jalr", "jr" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "jalr": { "opcode": "0000_0067", "type": "I-type" }
@@ -256,20 +283,20 @@
       ]
     },
     {
-      "encodings": {
-        "lb": { "opcode": "0000_0003", "type": "I-type" },
-        "lbu": { "opcode": "0000_4003", "type": "I-type" }
-      },
+      "stems": [ "la", "lb", "lbu", "lh", "lhu", "lw" ],
       "args": [
         { "class": "GeneralReg", "usage": "def" },
-        { "class": "Mem8", "usage": "use" }
+        { "class": "Label" }
       ]
     },
     {
-      "stems": [ "lb", "lbu", "lh", "lhu", "lla", "lw" ],
+      "encodings": {
+        "lb": { "opcode": "0000_0003", "type": "I-type" },
+        "lbu": { "opcode": "0000_4003", "type": "I-type" }
+      },
       "args": [
         { "class": "GeneralReg", "usage": "def" },
-        { "class": "Label" }
+        { "class": "Mem8", "usage": "use" }
       ]
     },
     {
@@ -282,6 +309,13 @@
         { "class": "Mem16", "usage": "use" }
       ]
     },
+    {
+      "stems": [ "li" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Imm32", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "lw": { "opcode": "0000_2003", "type": "I-type" }
@@ -291,6 +325,13 @@
         { "class": "Mem32", "usage": "use" }
       ]
     },
+    {
+      "stems": [ "mv", "neg", "not" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "prefetch.i": { "opcode": "0000_6013", "type": "P-type" },
@@ -301,6 +342,18 @@
         { "class": "Mem", "usage": "use" }
       ]
     },
+    {
+      "stems": [ "ret" ],
+      "args": []
+    },
+    {
+      "stems": [ "sb", "sh", "sw" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Label" },
+        { "class": "GeneralReg", "usage": "def" }
+      ]
+    },
     {
       "encodings": {
         "sb": { "opcode": "0000_0023", "type": "S-type" }
@@ -311,11 +364,20 @@
       ]
     },
     {
-      "stems": [ "sb", "sh", "sw" ],
+      "stems": [ "seqz", "sgtz", "sltz", "snez" ],
       "args": [
-        { "class": "GeneralReg", "usage": "use" },
-        { "class": "Label" },
-        { "class": "GeneralReg", "usage": "def" }
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "sext.b": { "opcode": "6040_1013", "type": "R-type" },
+        "sext.h": { "opcode": "6050_1013", "type": "R-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" }
       ]
     },
     {
@@ -335,13 +397,6 @@
         { "class": "GeneralReg", "usage": "use" },
         { "class": "Mem32", "usage": "def" }
       ]
-    },
-    {
-      "stems": [ "mv" ],
-      "args": [
-        { "class": "GeneralReg", "usage": "def" },
-        { "class": "GeneralReg", "usage": "use" }
-      ]
     }
   ]
 }
diff --git a/assembler/instructions/insn_def_rv32.json b/assembler/instructions/insn_def_rv32.json
index 96a6cd5b..4ac7697c 100644
--- a/assembler/instructions/insn_def_rv32.json
+++ b/assembler/instructions/insn_def_rv32.json
@@ -18,6 +18,8 @@
   "insns": [
     {
       "encodings": {
+        "bexti": { "opcode": "4800_5013", "type": "I-type" },
+        "rori": { "opcode": "6000_5013", "type": "I-type" },
         "slli": { "opcode": "0000_1013", "type": "I-type" },
         "srai": { "opcode": "4000_5013", "type": "I-type" },
         "srli": { "opcode": "0000_5013", "type": "I-type" }
diff --git a/assembler/instructions/insn_def_rv64.json b/assembler/instructions/insn_def_rv64.json
index fdee9578..ab544a0c 100644
--- a/assembler/instructions/insn_def_rv64.json
+++ b/assembler/instructions/insn_def_rv64.json
@@ -18,12 +18,14 @@
   "insns": [
     {
       "encodings": {
+        "AddUW": { "opcode": "0800_003b", "type": "R-type" },
         "addw": { "opcode": "0000_003b", "type": "R-type" },
         "divuw": { "opcode": "0200_503b", "type": "R-type" },
         "divw": { "opcode": "0200_403b", "type": "R-type" },
         "mulw": { "opcode": "0200_003b", "type": "R-type" },
         "remuw": { "opcode": "0200_703b", "type": "R-type" },
         "remw": { "opcode": "0200_603b", "type": "R-type" },
+        "rorw": { "opcode": "6000_503b", "type": "R-type" },
         "sllw": { "opcode": "0000_103b", "type": "R-type" },
         "subw": { "opcode": "4000_003b", "type": "R-type" }
       },
@@ -33,6 +35,13 @@
         { "class": "GeneralReg", "usage": "use" }
       ]
     },
+    {
+      "stems": [ "SextW", "ZextW", "negw" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "addiw": { "opcode": "0000_001b", "type": "I-type" }
@@ -43,6 +52,20 @@
         { "class": "I-Imm" }
       ]
     },
+    {
+      "encodings": {
+        "bexti": { "opcode": "4800_5013", "type": "I-type" },
+        "rori": { "opcode": "6000_5013", "type": "I-type" },
+        "slli": { "opcode": "0000_1013", "type": "I-type" },
+        "srai": { "opcode": "4000_5013", "type": "I-type" },
+        "srli": { "opcode": "0000_5013", "type": "I-type" }
+      },
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "GeneralReg", "usage": "use" },
+        { "class": "Shift64-Imm" }
+      ]
+    },
     {
       "encodings": {
         "fcvt.d.l": { "opcode": "d220_0053", "type": "R-type" },
@@ -59,8 +82,8 @@
     {
       "encodings": {
         "fcvt.l.d": { "opcode": "c220_0053", "type": "R-type" },
-        "fcvt.lu.d": { "opcode": "c230_0053", "type": "R-type" },
         "fcvt.l.s": { "opcode": "c020_0053", "type": "R-type" },
+        "fcvt.lu.d": { "opcode": "c230_0053", "type": "R-type" },
         "fcvt.lu.s": { "opcode": "c030_0053", "type": "R-type" }
       },
       "args": [
@@ -69,6 +92,13 @@
         { "class": "Rm", "usage": "use" }
       ]
     },
+    {
+      "stems": [ "ld", "lwu" ],
+      "args": [
+        { "class": "GeneralReg", "usage": "def" },
+        { "class": "Label" }
+      ]
+    },
     {
       "encodings": {
         "ld": { "opcode": "0000_3003", "type": "I-type" }
@@ -79,10 +109,10 @@
       ]
     },
     {
-      "stems": [ "ld", "lwu" ],
+      "stems": [ "li" ],
       "args": [
         { "class": "GeneralReg", "usage": "def" },
-        { "class": "Label" }
+        { "class": "Imm64", "usage": "use" }
       ]
     },
     {
@@ -96,18 +126,7 @@
     },
     {
       "encodings": {
-        "slli": { "opcode": "0000_1013", "type": "I-type" },
-        "srai": { "opcode": "4000_5013", "type": "I-type" },
-        "srli": { "opcode": "0000_5013", "type": "I-type" }
-      },
-      "args": [
-        { "class": "GeneralReg", "usage": "def" },
-        { "class": "GeneralReg", "usage": "use" },
-        { "class": "Shift64-Imm" }
-      ]
-    },
-    {
-      "encodings": {
+        "roriw": { "opcode": "6000_501b", "type": "I-type" },
         "slliw": { "opcode": "0000_101b", "type": "I-type" },
         "sraiw": { "opcode": "4000_501b", "type": "I-type" },
         "srliw": { "opcode": "0000_501b", "type": "I-type" }
@@ -119,20 +138,20 @@
       ]
     },
     {
-      "encodings": {
-        "sd": { "opcode": "0000_3023", "type": "S-type" }
-      },
+      "stems": [ "sd" ],
       "args": [
         { "class": "GeneralReg", "usage": "use" },
-        { "class": "Mem64", "usage": "def" }
+        { "class": "Label" },
+        { "class": "GeneralReg", "usage": "def" }
       ]
     },
     {
-      "stems": [ "sd" ],
+      "encodings": {
+        "sd": { "opcode": "0000_3023", "type": "S-type" }
+      },
       "args": [
         { "class": "GeneralReg", "usage": "use" },
-        { "class": "Label" },
-        { "class": "GeneralReg", "usage": "def" }
+        { "class": "Mem64", "usage": "def" }
       ]
     }
   ]
diff --git a/assembler/instructions/insn_def_x86.json b/assembler/instructions/insn_def_x86.json
index 084cb8bd..37e694df 100644
--- a/assembler/instructions/insn_def_x86.json
+++ b/assembler/instructions/insn_def_x86.json
@@ -75,23 +75,23 @@
     },
     {
       "encodings": {
-        "Adcl": { "opcodes": [ "81", "2" ] },
-        "Sbbl": { "opcodes": [ "81", "3" ] }
+        "Adcl": { "opcode": "11", "type": "reg_to_rm" },
+        "Sbbl": { "opcode": "19", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "use_def" },
-        { "class": "Imm32" },
+        { "class": "GeneralReg32", "usage": "use" },
         { "class": "FLAGS", "usage": "use_def" }
       ]
     },
     {
       "encodings": {
-        "Adcl": { "opcode": "11", "type": "reg_to_rm" },
-        "Sbbl": { "opcode": "19", "type": "reg_to_rm" }
+        "Adcl": { "opcodes": [ "81", "2" ] },
+        "Sbbl": { "opcodes": [ "81", "3" ] }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "use_def" },
-        { "class": "GeneralReg32", "usage": "use" },
+        { "class": "Imm32" },
         { "class": "FLAGS", "usage": "use_def" }
       ]
     },
@@ -132,23 +132,23 @@
     },
     {
       "encodings": {
-        "Adcw": { "opcodes": [ "66", "81", "2" ] },
-        "Sbbw": { "opcodes": [ "66", "81", "3" ] }
+        "Adcw": { "opcodes": [ "66", "11" ], "type": "reg_to_rm" },
+        "Sbbw": { "opcodes": [ "66", "19" ], "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg16/Mem16", "usage": "use_def" },
-        { "class": "Imm16" },
+        { "class": "GeneralReg16", "usage": "use" },
         { "class": "FLAGS", "usage": "use_def" }
       ]
     },
     {
       "encodings": {
-        "Adcw": { "opcodes": [ "66", "11" ], "type": "reg_to_rm" },
-        "Sbbw": { "opcodes": [ "66", "19" ], "type": "reg_to_rm" }
+        "Adcw": { "opcodes": [ "66", "81", "2" ] },
+        "Sbbw": { "opcodes": [ "66", "81", "3" ] }
       },
       "args": [
         { "class": "GeneralReg16/Mem16", "usage": "use_def" },
-        { "class": "GeneralReg16", "usage": "use" },
+        { "class": "Imm16" },
         { "class": "FLAGS", "usage": "use_def" }
       ]
     },
@@ -736,23 +736,23 @@
     },
     {
       "encodings": {
-        "Cmpb": { "opcodes": [ "80", "7" ] },
-        "Testb": { "opcodes": [ "F6", "0" ] }
+        "Cmpb": { "opcode": "38", "type": "reg_to_rm" },
+        "Testb": { "opcode": "84", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg8/Mem8", "usage": "use" },
-        { "class": "Imm8" },
+        { "class": "GeneralReg8", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
       ]
     },
     {
       "encodings": {
-        "Cmpb": { "opcode": "38", "type": "reg_to_rm" },
-        "Testb": { "opcode": "84", "type": "reg_to_rm" }
+        "Cmpb": { "opcodes": [ "80", "7" ] },
+        "Testb": { "opcodes": [ "F6", "0" ] }
       },
       "args": [
         { "class": "GeneralReg8/Mem8", "usage": "use" },
-        { "class": "GeneralReg8", "usage": "use" },
+        { "class": "Imm8" },
         { "class": "FLAGS", "usage": "def" }
       ]
     },
@@ -1227,8 +1227,8 @@
         "Int3": { "opcode": "CC" },
         "Lfence": { "opcodes": [ "0F", "AE", "E8" ] },
         "Mfence": { "opcodes": [ "0F", "AE", "F0" ] },
-        "Sfence": { "opcodes": [ "0F", "AE", "F8" ] },
         "Nop": { "opcode": "90" },
+        "Sfence": { "opcodes": [ "0F", "AE", "F8" ] },
         "UD2": { "opcodes": [ "0F", "0B" ] },
         "Wait": { "opcode": "9B" }
       },
@@ -1585,12 +1585,6 @@
         { "class": "FLAGS", "usage": "use" }
       ]
     },
-    {
-      "stems": [ "Jmp" ],
-      "args": [
-        { "class": "Label" }
-      ]
-    },
     {
       "encodings": {
         "Jmp": { "opcodes": [ "FF", "4" ] }
@@ -1599,6 +1593,12 @@
         { "class": "GeneralReg", "usage": "use" }
       ]
     },
+    {
+      "stems": [ "Jmp" ],
+      "args": [
+        { "class": "Label" }
+      ]
+    },
     {
       "encodings": {
         "Lahf": { "opcode": "9F" }
@@ -1660,6 +1660,39 @@
         { "class": "FLAGS", "usage": "def" }
       ]
     },
+    {
+      "encodings": {
+        "Lock Xaddb": { "opcodes": [ "F0", "0F", "C0" ], "type": "reg_to_rm" },
+        "Xaddb": { "opcodes": [ "0F", "C0" ], "type": "reg_to_rm" }
+      },
+      "args": [
+        { "class": "Mem8", "usage": "use_def" },
+        { "class": "GeneralReg8", "usage": "use_def" },
+        { "class": "FLAGS", "usage": "use_def" }
+      ]
+    },
+    {
+      "encodings": {
+        "Lock Xaddl": { "opcodes": [ "F0", "0F", "C1" ], "type": "reg_to_rm" },
+        "Xaddl": { "opcodes": [ "0F", "C1" ], "type": "reg_to_rm" }
+      },
+      "args": [
+        { "class": "Mem32", "usage": "use_def" },
+        { "class": "GeneralReg32", "usage": "use_def" },
+        { "class": "FLAGS", "usage": "use_def" }
+      ]
+    },
+    {
+      "encodings": {
+        "Lock Xaddw": { "opcodes": [ "F0", "66", "0F", "C1" ], "type": "reg_to_rm" },
+        "Xaddw": { "opcodes": [ "66", "0F", "C1" ], "type": "reg_to_rm" }
+      },
+      "args": [
+        { "class": "Mem16", "usage": "use_def" },
+        { "class": "GeneralReg16", "usage": "use_def" },
+        { "class": "FLAGS", "usage": "use_def" }
+      ]
+    },
     {
       "encodings": {
         "Movapd": { "opcodes": [ "66", "0F", "29" ] },
@@ -1812,20 +1845,20 @@
     },
     {
       "encodings": {
-        "Movl": { "opcode": "8B" }
+        "Movl": { "opcode": "B8" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "def" },
-        { "class": "Mem32", "usage": "use" }
+        { "class": "Imm32" }
       ]
     },
     {
       "encodings": {
-        "Movl": { "opcode": "B8" }
+        "Movl": { "opcode": "8B" }
       },
       "args": [
         { "class": "GeneralReg32", "usage": "def" },
-        { "class": "Imm32" }
+        { "class": "Mem32", "usage": "use" }
       ]
     },
     {
@@ -2521,6 +2554,112 @@
         { "class": "VecReg128/VecMem128", "usage": "use" }
       ]
     },
+    {
+      "encodings": {
+        "Vaddpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "58" ], "type": "optimizable_using_commutation" },
+        "Vaddps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "58" ], "type": "optimizable_using_commutation" },
+        "Vandpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "54" ], "type": "optimizable_using_commutation" },
+        "Vandps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "54" ], "type": "optimizable_using_commutation" },
+        "Vcmpeqpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "C2", "00" ], "type": "optimizable_using_commutation" },
+        "Vcmpeqps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "C2", "00" ], "type": "optimizable_using_commutation" },
+        "Vcmplepd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "C2", "02" ], "type": "vex_rm_to_reg" },
+        "Vcmpleps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "C2", "02" ], "type": "vex_rm_to_reg" },
+        "Vcmpltpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "C2", "01" ], "type": "vex_rm_to_reg" },
+        "Vcmpltps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "C2", "01" ], "type": "vex_rm_to_reg" },
+        "Vcmpneqpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "C2", "04" ], "type": "optimizable_using_commutation" },
+        "Vcmpneqps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "C2", "04" ], "type": "optimizable_using_commutation" },
+        "Vcmpnlepd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "C2", "06" ], "type": "vex_rm_to_reg" },
+        "Vcmpnleps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "C2", "06" ], "type": "vex_rm_to_reg" },
+        "Vcmpnltpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "C2", "05" ], "type": "vex_rm_to_reg" },
+        "Vcmpnltps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "C2", "05" ], "type": "vex_rm_to_reg" },
+        "Vcmpordpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "C2", "07" ], "type": "optimizable_using_commutation" },
+        "Vcmpordps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "C2", "07" ], "type": "optimizable_using_commutation" },
+        "Vcmpunordpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "C2", "03" ], "type": "optimizable_using_commutation" },
+        "Vcmpunordps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "C2", "03" ], "type": "optimizable_using_commutation" },
+        "Vdivpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "5E" ], "type": "vex_rm_to_reg" },
+        "Vdivps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "5E" ], "type": "vex_rm_to_reg" },
+        "Vhaddpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "7C" ], "type": "vex_rm_to_reg" },
+        "Vhaddps": { "feature": "AVX", "opcodes": [ "C4", "01", "07", "7C" ], "type": "vex_rm_to_reg" },
+        "Vmaxpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "5F" ], "type": "vex_rm_to_reg" },
+        "Vmaxps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "5F" ], "type": "vex_rm_to_reg" },
+        "Vminpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "5D" ], "type": "vex_rm_to_reg" },
+        "Vminps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "5D" ], "type": "vex_rm_to_reg" },
+        "Vmulpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "59" ], "type": "optimizable_using_commutation" },
+        "Vmulps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "59" ], "type": "optimizable_using_commutation" },
+        "Vorpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "56" ], "type": "optimizable_using_commutation" },
+        "Vorps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "56" ], "type": "optimizable_using_commutation" },
+        "Vpackssdw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "6B" ], "type": "vex_rm_to_reg" },
+        "Vpacksswb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "63" ], "type": "vex_rm_to_reg" },
+        "Vpackusdw": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "2B" ], "type": "vex_rm_to_reg" },
+        "Vpackuswb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "67" ], "type": "vex_rm_to_reg" },
+        "Vpaddb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "FC" ], "type": "optimizable_using_commutation" },
+        "Vpaddd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "FE" ], "type": "optimizable_using_commutation" },
+        "Vpaddq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "D4" ], "type": "optimizable_using_commutation" },
+        "Vpaddsb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "EC" ], "type": "optimizable_using_commutation" },
+        "Vpaddsw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "ED" ], "type": "optimizable_using_commutation" },
+        "Vpaddusb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "DC" ], "type": "optimizable_using_commutation" },
+        "Vpaddusw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "DD" ], "type": "optimizable_using_commutation" },
+        "Vpaddw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "FD" ], "type": "optimizable_using_commutation" },
+        "Vpand": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "DB" ], "type": "optimizable_using_commutation" },
+        "Vpandn": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "DF" ], "type": "vex_rm_to_reg" },
+        "Vpavgb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "E0" ], "type": "optimizable_using_commutation" },
+        "Vpavgw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "E3" ], "type": "optimizable_using_commutation" },
+        "Vpcmpeqb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "74" ], "type": "optimizable_using_commutation" },
+        "Vpcmpeqd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "76" ], "type": "optimizable_using_commutation" },
+        "Vpcmpeqq": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "29" ], "type": "vex_rm_to_reg" },
+        "Vpcmpeqw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "75" ], "type": "optimizable_using_commutation" },
+        "Vpcmpgtb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "64" ], "type": "vex_rm_to_reg" },
+        "Vpcmpgtd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "66" ], "type": "vex_rm_to_reg" },
+        "Vpcmpgtq": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "37" ], "type": "vex_rm_to_reg" },
+        "Vpcmpgtw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "65" ], "type": "vex_rm_to_reg" },
+        "Vpmaxsb": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "3C" ], "type": "vex_rm_to_reg" },
+        "Vpmaxsd": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "3D" ], "type": "vex_rm_to_reg" },
+        "Vpmaxsw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "EE" ], "type": "optimizable_using_commutation" },
+        "Vpmaxub": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "DE" ], "type": "optimizable_using_commutation" },
+        "Vpmaxud": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "3F" ], "type": "vex_rm_to_reg" },
+        "Vpmaxuw": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "3E" ], "type": "vex_rm_to_reg" },
+        "Vpminsb": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "38" ], "type": "vex_rm_to_reg" },
+        "Vpminsd": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "39" ], "type": "vex_rm_to_reg" },
+        "Vpminsw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "EA" ], "type": "optimizable_using_commutation" },
+        "Vpminub": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "DA" ], "type": "optimizable_using_commutation" },
+        "Vpminud": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "3B" ], "type": "vex_rm_to_reg" },
+        "Vpminuw": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "3A" ], "type": "vex_rm_to_reg" },
+        "Vpmulhrsw": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "0B" ], "type": "vex_rm_to_reg" },
+        "Vpmulhw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "E5" ], "type": "optimizable_using_commutation" },
+        "Vpmulld": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "40" ], "type": "vex_rm_to_reg" },
+        "Vpmullw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "D5" ], "type": "optimizable_using_commutation" },
+        "Vpmuludq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "F4" ], "type": "optimizable_using_commutation" },
+        "Vpor": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "EB" ], "type": "optimizable_using_commutation" },
+        "Vpsadbw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "F6" ], "type": "optimizable_using_commutation" },
+        "Vpshufb": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "00" ], "type": "vex_rm_to_reg" },
+        "Vpsubb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "F8" ], "type": "vex_rm_to_reg" },
+        "Vpsubd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "FA" ], "type": "vex_rm_to_reg" },
+        "Vpsubq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "FB" ], "type": "vex_rm_to_reg" },
+        "Vpsubsb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "E8" ], "type": "vex_rm_to_reg" },
+        "Vpsubsw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "E9" ], "type": "vex_rm_to_reg" },
+        "Vpsubusb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "D8" ], "type": "vex_rm_to_reg" },
+        "Vpsubusw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "D9" ], "type": "vex_rm_to_reg" },
+        "Vpsubw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "F9" ], "type": "vex_rm_to_reg" },
+        "Vpunpckhbw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "68" ], "type": "vex_rm_to_reg" },
+        "Vpunpckhdq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "6A" ], "type": "vex_rm_to_reg" },
+        "Vpunpckhqdq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "6D" ], "type": "vex_rm_to_reg" },
+        "Vpunpckhwd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "69" ], "type": "vex_rm_to_reg" },
+        "Vpunpcklbw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "60" ], "type": "vex_rm_to_reg" },
+        "Vpunpckldq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "62" ], "type": "vex_rm_to_reg" },
+        "Vpunpcklqdq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "6C" ], "type": "vex_rm_to_reg" },
+        "Vpunpcklwd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "61" ], "type": "vex_rm_to_reg" },
+        "Vpxor": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "EF" ], "type": "optimizable_using_commutation" },
+        "Vsubpd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "5C" ], "type": "vex_rm_to_reg" },
+        "Vsubps": { "feature": "AVX2", "opcodes": [ "C4", "01", "04", "5C" ], "type": "vex_rm_to_reg" },
+        "Vxorpd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "57" ], "type": "optimizable_using_commutation" },
+        "Vxorps": { "feature": "AVX2", "opcodes": [ "C4", "01", "04", "57" ], "type": "optimizable_using_commutation" }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecReg256/VecMem256", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "Vaddsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "58" ], "type": "optimizable_using_commutation" },
@@ -2892,6 +3031,23 @@
         { "class": "Imm8" }
       ]
     },
+    {
+      "encodings": {
+        "Vpslld": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "F2" ], "type": "vex_rm_to_reg" },
+        "Vpsllq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "F3" ], "type": "vex_rm_to_reg" },
+        "Vpsllw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "F1" ], "type": "vex_rm_to_reg" },
+        "Vpsrad": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "E2" ], "type": "vex_rm_to_reg" },
+        "Vpsraw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "E1" ], "type": "vex_rm_to_reg" },
+        "Vpsrld": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "D2" ], "type": "vex_rm_to_reg" },
+        "Vpsrlq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "D3" ], "type": "vex_rm_to_reg" },
+        "Vpsrlw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "D1" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecReg128/VecMem128", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "Vroundsd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "0B" ], "type": "vex_rm_to_reg" }
@@ -2926,6 +3082,15 @@
         { "class": "Imm8" }
       ]
     },
+    {
+      "encodings": {
+        "Xchgb": { "opcode": "86" }
+      },
+      "args": [
+        { "class": "GeneralReg8", "usage": "use_def" },
+        { "class": "Mem8", "usage": "use_def" }
+      ]
+    },
     {
       "stems": [ "Xchgl" ],
       "args": [
@@ -2941,6 +3106,15 @@
         { "class": "GeneralReg32", "usage": "use_def" },
         { "class": "Mem32", "usage": "use_def" }
       ]
+    },
+    {
+      "encodings": {
+        "Xchgw": { "opcodes": [ "66", "87" ] }
+      },
+      "args": [
+        { "class": "GeneralReg16", "usage": "use_def" },
+        { "class": "Mem16", "usage": "use_def" }
+      ]
     }
   ]
 }
diff --git a/assembler/instructions/insn_def_x86_64.json b/assembler/instructions/insn_def_x86_64.json
index aa3551ba..c77339f8 100644
--- a/assembler/instructions/insn_def_x86_64.json
+++ b/assembler/instructions/insn_def_x86_64.json
@@ -29,23 +29,23 @@
     },
     {
       "encodings": {
-        "Adcq": { "opcodes": [ "81", "2" ] },
-        "Sbbq": { "opcodes": [ "81", "3" ] }
+        "Adcq": { "opcode": "11", "type": "reg_to_rm" },
+        "Sbbq": { "opcode": "19", "type": "reg_to_rm" }
       },
       "args": [
         { "class": "GeneralReg64/Mem64", "usage": "use_def" },
-        { "class": "Imm32" },
+        { "class": "GeneralReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "use_def" }
       ]
     },
     {
       "encodings": {
-        "Adcq": { "opcode": "11", "type": "reg_to_rm" },
-        "Sbbq": { "opcode": "19", "type": "reg_to_rm" }
+        "Adcq": { "opcodes": [ "81", "2" ] },
+        "Sbbq": { "opcodes": [ "81", "3" ] }
       },
       "args": [
         { "class": "GeneralReg64/Mem64", "usage": "use_def" },
-        { "class": "GeneralReg64", "usage": "use" },
+        { "class": "Imm32" },
         { "class": "FLAGS", "usage": "use_def" }
       ]
     },
@@ -507,6 +507,17 @@
         { "class": "FLAGS", "usage": "def" }
       ]
     },
+    {
+      "encodings": {
+        "Lock Xaddq": { "opcodes": [ "F0", "0F", "C1" ], "type": "reg_to_rm" },
+        "Xaddq": { "opcodes": [ "0F", "C1" ], "type": "reg_to_rm" }
+      },
+      "args": [
+        { "class": "Mem64", "usage": "use_def" },
+        { "class": "GeneralReg64", "usage": "use_def" },
+        { "class": "FLAGS", "usage": "use_def" }
+      ]
+    },
     {
       "encodings": {
         "Movq": { "opcodes": [ "66", "0F", "7E" ], "type": "reg_to_rm" },
@@ -536,20 +547,20 @@
     },
     {
       "encodings": {
-        "Movq": { "opcode": "89", "type": "reg_to_rm" }
+        "Movq": { "opcode": "8B" }
       },
       "args": [
-        { "class": "GeneralReg64/Mem64", "usage": "def" },
-        { "class": "GeneralReg64", "usage": "use" }
+        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "Mem64", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "Movq": { "opcode": "8B" }
+        "Movq": { "opcode": "89", "type": "reg_to_rm" }
       },
       "args": [
-        { "class": "GeneralReg64", "usage": "def" },
-        { "class": "Mem64", "usage": "use" }
+        { "class": "GeneralReg64/Mem64", "usage": "def" },
+        { "class": "GeneralReg64", "usage": "use" }
       ]
     },
     {
diff --git a/assembler/machine_code.cc b/assembler/machine_code.cc
index c4bf0475..4c2bf97b 100644
--- a/assembler/machine_code.cc
+++ b/assembler/machine_code.cc
@@ -43,11 +43,27 @@ inline char print_halfbyte(uint8_t b) {
   return b < 0xa ? b + '0' : (b - 0xa) + 'a';
 }
 
-void MachineCode::AsString(std::string* result) const {
-  for (uint8_t insn : code_) {
-    *result += print_halfbyte(insn >> 4);
-    *result += print_halfbyte(insn & 0xf);
-    *result += ' ';
+inline std::string print_byte(uint8_t b) {
+  std::string byte_str = "";
+  byte_str += print_halfbyte(b >> 4);
+  byte_str += print_halfbyte(b & 0xf);
+  return byte_str;
+}
+
+void MachineCode::AsString(std::string* result, InstructionSize insn_size) const {
+  if (insn_size == InstructionSize::OneByte) {
+    for (uint8_t insn : code_) {
+      *result += print_byte(insn);
+      *result += ' ';
+    }
+  } else {
+    for (uint32_t i = 0; i + 3 < code_.size(); i += 4) {
+      *result += print_byte(code_[i + 3]);
+      *result += print_byte(code_[i + 2]);
+      *result += print_byte(code_[i + 1]);
+      *result += print_byte(code_[i]);
+      *result += ' ';
+    }
   }
 }
 
@@ -73,9 +89,9 @@ void MachineCode::PerformRelocations(const uint8_t* code, RecoveryMap* recovery_
   }
 }
 
-void MachineCode::DumpCode() const {
+void MachineCode::DumpCode(InstructionSize insn_size) const {
   std::string code_str;
-  AsString(&code_str);
+  AsString(&code_str, insn_size);
   ALOGE("%s\n", code_str.c_str());
 }
 
diff --git a/backend/include/berberis/backend/x86_64/machine_ir.h b/backend/include/berberis/backend/x86_64/machine_ir.h
index 4a8c7fb3..3cc44cf4 100644
--- a/backend/include/berberis/backend/x86_64/machine_ir.h
+++ b/backend/include/berberis/backend/x86_64/machine_ir.h
@@ -43,7 +43,12 @@ enum MachineOpcode : int {
   kMachineOpPseudoJump,
   kMachineOpPseudoReadFlags,
   kMachineOpPseudoWriteFlags,
+// Some frontends may need additional opcodes currently.
+// Ideally we may want to separate froentend and backend, but for now only include
+// berberis/backend/x86_64/machine_opcode_guest-inl.h if it exists.
+#if __has_include("berberis/backend/x86_64/machine_opcode_guest-inl.h")
 #include "berberis/backend/x86_64/machine_opcode_guest-inl.h"
+#endif  // __has_include("berberis/backend/x86_64/machine_opcode_guest-inl.h")
 #include "machine_opcode_x86_64-inl.h"  // NOLINT generated file!
 };
 
@@ -117,6 +122,7 @@ class MachineInsnX86_64 : public MachineInsn {
  public:
   static constexpr const auto kEAX = x86_64::kEAX;
   static constexpr const auto kRAX = x86_64::kRAX;
+  static constexpr const auto kAL = x86_64::kAL;
   static constexpr const auto kCL = x86_64::kCL;
   static constexpr const auto kECX = x86_64::kECX;
   static constexpr const auto kRCX = x86_64::kRCX;
diff --git a/backend/x86_64/lir_instructions.json b/backend/x86_64/lir_instructions.json
index ba093ff1..5ac7f33b 100644
--- a/backend/x86_64/lir_instructions.json
+++ b/backend/x86_64/lir_instructions.json
@@ -90,7 +90,11 @@
         "TestwRegImm",
         "TestwRegReg",
         "Lfence",
+        "LockCmpXchgbRegMemRegInsns",
+        "LockCmpXchgwRegMemRegInsns",
+        "LockCmpXchglRegMemRegInsns",
         "LockCmpXchgqRegMemRegInsns",
+        "LockCmpXchg8bRegRegRegRegMemInsns",
         "LockCmpXchg16bRegRegRegRegMemInsns",
         "Mfence",
         "MovbMemImmInsns",
@@ -211,10 +215,14 @@
         "VmovapsXRegXReg",
         "VmovsdXRegXRegXReg",
         "VmovssXRegXRegXReg",
+        "XchgbRegMemInsns",
+        "XchgwRegMemInsns",
+        "XchglRegMemInsns",
+        "XchgqRegMemInsns",
         "XorlRegImm",
         "XorlRegReg",
         "XorpdXRegXReg",
         "XorqRegImm",
         "XorqRegReg"
     ]
-}
\ No newline at end of file
+}
diff --git a/backend/x86_64/reg_class_def.json b/backend/x86_64/reg_class_def.json
index 20deebc6..aecdf6ae 100644
--- a/backend/x86_64/reg_class_def.json
+++ b/backend/x86_64/reg_class_def.json
@@ -139,6 +139,13 @@
         "RAX"
       ]
     },
+    {
+      "name": "AL",
+      "size": 1,
+      "regs": [
+        "RAX"
+      ]
+    },
     {
       "name": "RBX",
       "size": 8,
diff --git a/base/Android.bp b/base/Android.bp
index 7ba8a049..87a36e32 100644
--- a/base/Android.bp
+++ b/base/Android.bp
@@ -52,7 +52,6 @@ cc_library_static {
         "config_globals.cc",
         "config_globals_custom.cc",
         "exec_region.cc",
-        "exec_region_anonymous.cc",
         "format_buffer.cc",
         "large_mmap.cc",
         "maps_snapshot.cc",
@@ -81,35 +80,6 @@ cc_library_static {
     export_header_lib_headers: ["libberberis_base_headers"],
 }
 
-cc_library_static {
-    name: "libberberis_base_elf_backed_exec_region",
-    defaults: ["berberis_all_hosts_defaults"],
-    host_supported: true,
-    target: {
-        bionic: {
-            srcs: ["exec_region_elf_backed.cc"],
-        },
-    },
-
-    header_libs: ["libberberis_base_headers"],
-    export_header_lib_headers: ["libberberis_base_headers"],
-}
-
-// ATTENTION: do not use it outside of static tests!
-cc_library_static {
-    name: "libberberis_base_elf_backed_exec_region_for_static_tests",
-    defaults: ["berberis_all_hosts_defaults"],
-    host_supported: true,
-    target: {
-        bionic: {
-            srcs: ["exec_region_elf_backed_for_static_tests.cc"],
-        },
-    },
-
-    header_libs: ["libberberis_base_headers"],
-    export_header_lib_headers: ["libberberis_base_headers"],
-}
-
 cc_test_library {
     name: "libberberis_base_unit_tests",
     defaults: ["berberis_test_library_defaults"],
@@ -117,8 +87,6 @@ cc_test_library {
         "arena_test.cc",
         "arena_zeroed_array_test.cc",
         "bit_util_test.cc",
-        "exec_region_anonymous.cc",
-        "exec_region_anonymous_test.cc",
         "forever_alloc_test.cc",
         "forever_pool_test.cc",
         "format_buffer_test.cc",
@@ -127,18 +95,8 @@ cc_test_library {
         "maps_snapshot_test.cc",
         "memfd_backed_mmap_test.cc",
         "mmap_pool_test.cc",
+        "mmap_test.cc",
         "pointer_and_counter_test.cc",
     ],
     header_libs: ["libberberis_base_headers"],
 }
-
-cc_test_library {
-    name: "libberberis_base_elf_backed_exec_region_unit_tests",
-    defaults: ["berberis_test_library_defaults"],
-    target: {
-        bionic: {
-            srcs: ["exec_region_elf_backed_test.cc"],
-        },
-    },
-    header_libs: ["libberberis_base_headers"],
-}
diff --git a/base/config_globals_custom.cc b/base/config_globals_custom.cc
index 70ccba29..98fb01a5 100644
--- a/base/config_globals_custom.cc
+++ b/base/config_globals_custom.cc
@@ -41,6 +41,10 @@ std::string ToString(ConfigFlag flag) {
       return "disable-reg-map";
     case kEnableDisjointRegionsTranslation:
       return "enable-disjoint-regions-translation";
+    case kLocalExperiment:
+      return "local-experiment";
+    case kPlatformCustomCPUCapability:
+      return "platform-custom-cpu-capability";
     case kNumConfigFlags:
       break;
   }
diff --git a/base/include/berberis/base/arena_list.h b/base/include/berberis/base/arena_list.h
index 28c6c559..2bb5379d 100644
--- a/base/include/berberis/base/arena_list.h
+++ b/base/include/berberis/base/arena_list.h
@@ -23,8 +23,8 @@
 
 namespace berberis {
 
-template <class T>
-using ArenaList = std::list<T, ArenaAllocator<T> >;
+template <class Type>
+using ArenaList = std::list<Type, ArenaAllocator<Type> >;
 
 }  // namespace berberis
 
diff --git a/base/include/berberis/base/arena_map.h b/base/include/berberis/base/arena_map.h
index 94457fd3..477d2a5e 100644
--- a/base/include/berberis/base/arena_map.h
+++ b/base/include/berberis/base/arena_map.h
@@ -23,8 +23,9 @@
 
 namespace berberis {
 
-template <typename K, typename T, typename C = std::less<K> >
-using ArenaMap = std::map<K, T, C, ArenaAllocator<std::pair<const K, T> > >;
+template <typename KeyType, typename ValueType, typename Compare = std::less<KeyType> >
+using ArenaMap =
+    std::map<KeyType, ValueType, Compare, ArenaAllocator<std::pair<const KeyType, ValueType> > >;
 
 }  // namespace berberis
 
diff --git a/base/include/berberis/base/arena_set.h b/base/include/berberis/base/arena_set.h
new file mode 100644
index 00000000..2f861245
--- /dev/null
+++ b/base/include/berberis/base/arena_set.h
@@ -0,0 +1,31 @@
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
+#ifndef BERBERIS_BASE_ARENA_SET_H_
+#define BERBERIS_BASE_ARENA_SET_H_
+
+#include <set>
+
+#include "berberis/base/arena_alloc.h"
+
+namespace berberis {
+
+template <typename Type, typename Compare = std::less<Type> >
+using ArenaSet = std::set<Type, Compare, ArenaAllocator<Type> >;
+
+}  // namespace berberis
+
+#endif  // BERBERIS_BASE_ARENA_SET_H_
\ No newline at end of file
diff --git a/base/include/berberis/base/arena_vector.h b/base/include/berberis/base/arena_vector.h
index 41ceac64..6db19d02 100644
--- a/base/include/berberis/base/arena_vector.h
+++ b/base/include/berberis/base/arena_vector.h
@@ -23,8 +23,8 @@
 
 namespace berberis {
 
-template <class T>
-using ArenaVector = std::vector<T, ArenaAllocator<T> >;
+template <class Type>
+using ArenaVector = std::vector<Type, ArenaAllocator<Type> >;
 
 }  // namespace berberis
 
diff --git a/base/include/berberis/base/arena_zeroed_array.h b/base/include/berberis/base/arena_zeroed_array.h
index 778ef18a..717c3443 100644
--- a/base/include/berberis/base/arena_zeroed_array.h
+++ b/base/include/berberis/base/arena_zeroed_array.h
@@ -28,30 +28,30 @@ namespace berberis {
 // TODO(b/117224636): This is a workaround for slow zero-initialized ArenaVector.
 // Alternatively, we could zero-initialize memory when Arena allocates memory, eliminating
 // the need to zero-initialize memory in every data structure allocated from Arena.
-template <typename T>
+template <typename Type>
 class ArenaZeroedArray {
  public:
   ArenaZeroedArray(size_t size, Arena* arena)
-      : size_(size), array_(NewArrayInArena<T>(arena, size)) {
-    memset(array_, 0, sizeof(T) * size);
+      : size_(size), array_(NewArrayInArena<Type>(arena, size)) {
+    memset(array_, 0, sizeof(Type) * size);
   }
 
-  const T& operator[](size_t i) const { return array_[i]; }
-  T& operator[](size_t i) { return array_[i]; }
+  const Type& operator[](size_t i) const { return array_[i]; }
+  Type& operator[](size_t i) { return array_[i]; }
 
-  const T& at(size_t i) const {
+  const Type& at(size_t i) const {
     CHECK_LT(i, size_);
     return array_[i];
   }
 
-  T& at(size_t i) {
+  Type& at(size_t i) {
     CHECK_LT(i, size_);
     return array_[i];
   }
 
  private:
   size_t size_;
-  T* array_;
+  Type* array_;
 };
 
 }  // namespace berberis
diff --git a/base/include/berberis/base/bit_util.h b/base/include/berberis/base/bit_util.h
index ff348c87..53af60f5 100644
--- a/base/include/berberis/base/bit_util.h
+++ b/base/include/berberis/base/bit_util.h
@@ -222,15 +222,12 @@ template <typename T>
   // We couldn't use C++20 std::countr_zero yet ( http://b/318678905 ) for __uint128_t .
   // Switch to std::popcount when/if that bug would be fixed.
   static_assert(!std::is_signed_v<T>);
-#if defined(__x86_64__)
-  if constexpr (sizeof(T) == sizeof(unsigned __int128)) {
+  if constexpr (sizeof(T) == 16) {
     if (static_cast<uint64_t>(x) == 0) {
       return __builtin_ctzll(x >> 64) + 64;
     }
     return __builtin_ctzll(x);
-  } else
-#endif
-      if constexpr (sizeof(T) == sizeof(uint64_t)) {
+  } else if constexpr (sizeof(T) == sizeof(uint64_t)) {
     return __builtin_ctzll(x);
   } else if constexpr (sizeof(T) == sizeof(uint32_t)) {
     return __builtin_ctz(x);
@@ -259,12 +256,9 @@ template <typename T>
   // We couldn't use C++20 std::popcount yet ( http://b/318678905 ) for __uint128_t .
   // Switch to std::popcount when/if that bug would be fixed.
   static_assert(!std::is_signed_v<T>);
-#if defined(__x86_64__)
-  if constexpr (sizeof(T) == sizeof(unsigned __int128)) {
+  if constexpr (sizeof(T) == 16) {
     return __builtin_popcountll(x) + __builtin_popcountll(x >> 64);
-  } else
-#endif
-      if constexpr (sizeof(T) == sizeof(uint64_t)) {
+  } else if constexpr (sizeof(T) == sizeof(uint64_t)) {
     return __builtin_popcountll(x);
   } else if constexpr (sizeof(T) == sizeof(uint32_t)) {
     return __builtin_popcount(x);
diff --git a/base/include/berberis/base/checks.h b/base/include/berberis/base/checks.h
index 99fcfb00..cff3def3 100644
--- a/base/include/berberis/base/checks.h
+++ b/base/include/berberis/base/checks.h
@@ -78,9 +78,9 @@ constexpr auto&& ValueForFmtSpec(auto&& value) {
 
 #define UNREACHABLE() FATAL("This code is (supposed to be) unreachable.")
 
-#define FATAL_UNIMPL_INSN_IF_NOT_BRINGUP()           \
-  if (!berberis::config::kInstructionsBringupMode) { \
-    FATAL("Unimplemented instruction!");             \
+#define FATAL_UNIMPL_INSN_IF_NOT_BRINGUP()            \
+  if (!berberis::config::kInstructionsBringupMode) {  \
+    FATAL("Unimplemented instruction: %s", __func__); \
   }
 
 #ifdef CHECK
diff --git a/base/include/berberis/base/config_globals.h b/base/include/berberis/base/config_globals.h
index b6aa07d5..634b520f 100644
--- a/base/include/berberis/base/config_globals.h
+++ b/base/include/berberis/base/config_globals.h
@@ -54,6 +54,11 @@ enum ConfigFlag {
   kEnableDisjointRegionsTranslation,
   kVerboseTranslation,
   kAccurateSigsegv,
+  // A convenience flag with no specific implied feature. Use it to conduct local experiments
+  // without recompilation and without the need to add a new flag.
+  kLocalExperiment,
+  // A convenience flag which enables a custom platform capability.
+  kPlatformCustomCPUCapability,
   kNumConfigFlags
 };
 
diff --git a/base/include/berberis/base/fd.h b/base/include/berberis/base/fd.h
index 27af9d6f..bce07774 100644
--- a/base/include/berberis/base/fd.h
+++ b/base/include/berberis/base/fd.h
@@ -27,16 +27,6 @@
 #include "berberis/base/logging.h"
 #include "berberis/base/raw_syscall.h"
 
-// glibc in prebuilts does not have memfd_create
-#if defined(__linux__) && !defined(__NR_memfd_create)
-#if defined(__x86_64__)
-#define __NR_memfd_create 319
-#elif defined(__i386__)
-#define __NR_memfd_create 356
-#endif  // defined(__i386__)
-#define MFD_CLOEXEC 0x0001U
-#endif  // defined(__linux__) && !defined(__NR_memfd_create)
-
 namespace berberis {
 
 inline int CreateMemfdOrDie(const char* name) {
diff --git a/base/include/berberis/base/forever_alloc.h b/base/include/berberis/base/forever_alloc.h
index 1541a73d..ac839ed4 100644
--- a/base/include/berberis/base/forever_alloc.h
+++ b/base/include/berberis/base/forever_alloc.h
@@ -97,6 +97,25 @@ inline void* AllocateForever(size_t size, size_t align) {
   return g_forever_allocator.Allocate(size, align);
 }
 
+template <typename Type>
+inline Type* NewForever() {
+  return new (AllocateForever(sizeof(Type), alignof(Type))) Type();
+}
+
+// NewForever that can only be used by an instance of Type.
+template <typename Type>
+class PrivateNewForever {
+ private:
+  // No instances of this helper class are allowed.
+  PrivateNewForever() = delete;
+  // To make Type() accessible here Type must declare PrivateNewForever<Type> as a friend.
+  static Type* Alloc() {
+    // Note: we cannot simply call NewForever<Type> here since it's not a friend of Type.
+    return new (AllocateForever(sizeof(Type), alignof(Type))) Type();
+  }
+  friend Type;
+};
+
 }  // namespace berberis
 
 #endif  // BERBERIS_BASE_FOREVER_ALLOC_H_
diff --git a/base/include/berberis/base/maps_snapshot.h b/base/include/berberis/base/maps_snapshot.h
index 3b0d8fe7..f03e111e 100644
--- a/base/include/berberis/base/maps_snapshot.h
+++ b/base/include/berberis/base/maps_snapshot.h
@@ -24,6 +24,7 @@
 #include "berberis/base/arena_alloc.h"
 #include "berberis/base/arena_map.h"
 #include "berberis/base/arena_string.h"
+#include "berberis/base/forever_alloc.h"  // friend PrivateNewForever
 
 namespace berberis {
 
@@ -54,6 +55,8 @@ class MapsSnapshot {
   Arena arena_;
   std::mutex mutex_;
   ArenaMap<uintptr_t, Record> maps_;
+
+  friend PrivateNewForever<MapsSnapshot>;
 };
 
 }  // namespace berberis
diff --git a/base/include/berberis/base/memfd_backed_mmap.h b/base/include/berberis/base/memfd_backed_mmap.h
index 4871e1ad..5eee98fe 100644
--- a/base/include/berberis/base/memfd_backed_mmap.h
+++ b/base/include/berberis/base/memfd_backed_mmap.h
@@ -22,7 +22,8 @@
 
 namespace berberis {
 
-int CreateAndFillMemfd(const char* name, size_t memfd_file_size, uintptr_t value);
+template <typename T>
+int CreateAndFillMemfd(const char* name, size_t memfd_file_size, T value);
 
 void* CreateMemfdBackedMapOrDie(int memfd, size_t map_size, size_t memfd_file_size);
 
diff --git a/base/include/berberis/base/mmap.h b/base/include/berberis/base/mmap.h
index df74c1a8..06277939 100644
--- a/base/include/berberis/base/mmap.h
+++ b/base/include/berberis/base/mmap.h
@@ -52,6 +52,10 @@ constexpr bool IsAlignedPageSize(T x) {
   return IsAligned(x, kPageSize);
 }
 
+enum MmapBerberisFlags {
+  kMmapBerberis32Bit = 1,
+};
+
 struct MmapImplArgs {
   void* addr = nullptr;
   size_t size = 0;
@@ -59,6 +63,7 @@ struct MmapImplArgs {
   int flags = MAP_PRIVATE | MAP_ANONYMOUS;
   int fd = -1;
   off_t offset = 0;
+  int berberis_flags = 0;
 };
 
 void* MmapImpl(MmapImplArgs args);
diff --git a/base/include/berberis/base/scoped_fd.h b/base/include/berberis/base/scoped_fd.h
new file mode 100644
index 00000000..a4dd6d04
--- /dev/null
+++ b/base/include/berberis/base/scoped_fd.h
@@ -0,0 +1,47 @@
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
+#ifndef BERBERIS_BASE_SCOPED_FD_H
+#define BERBERIS_BASE_SCOPED_FD_H
+
+#include <unistd.h>
+
+namespace berberis {
+
+class ScopedFd {
+ public:
+  ScopedFd(int fd) : fd_{fd} {}
+  ScopedFd(const ScopedFd&) = delete;
+  ScopedFd(ScopedFd&&) = delete;
+  ScopedFd& operator=(const ScopedFd&) = delete;
+  ScopedFd& operator=(ScopedFd&&) = delete;
+  ~ScopedFd() { reset(-1); }
+
+ private:
+  void reset(int fd) {
+    if (fd_ != -1) {
+      close(fd_);
+    }
+
+    fd_ = fd;
+  }
+
+  int fd_;
+};
+
+}  // namespace berberis
+
+#endif  // BERBERIS_BASE_SCOPED_FD_H
diff --git a/base/maps_snapshot.cc b/base/maps_snapshot.cc
index 48218bf1..cb34ae12 100644
--- a/base/maps_snapshot.cc
+++ b/base/maps_snapshot.cc
@@ -22,13 +22,14 @@
 #include <optional>
 
 #include "berberis/base/arena_string.h"
+#include "berberis/base/forever_alloc.h"
 #include "berberis/base/tracing.h"
 
 namespace berberis {
 
 MapsSnapshot* MapsSnapshot::GetInstance() {
-  static MapsSnapshot g_maps_snapshot;
-  return &g_maps_snapshot;
+  static auto* g_maps_snapshot = PrivateNewForever<MapsSnapshot>::Alloc();
+  return g_maps_snapshot;
 }
 
 void MapsSnapshot::Update() {
diff --git a/base/memfd_backed_mmap.cc b/base/memfd_backed_mmap.cc
index 6f5a44b9..9aff0541 100644
--- a/base/memfd_backed_mmap.cc
+++ b/base/memfd_backed_mmap.cc
@@ -19,6 +19,9 @@
 #include <sys/mman.h>
 #include <unistd.h>
 
+#include <atomic>
+#include <type_traits>
+
 #include "berberis/base/fd.h"
 #include "berberis/base/large_mmap.h"
 #include "berberis/base/logging.h"
@@ -27,7 +30,10 @@
 namespace berberis {
 
 // Creates memfd region of memfd_file_size bytes filled with value.
-int CreateAndFillMemfd(const char* name, size_t memfd_file_size, uintptr_t value) {
+template <typename T>
+int CreateAndFillMemfd(const char* name, size_t memfd_file_size, T value) {
+  static_assert(std::is_integral_v<T> || std::is_pointer_v<T>,
+                "T must be an integral or pointer type");
   const size_t kPageSize = sysconf(_SC_PAGE_SIZE);
   CHECK_EQ(memfd_file_size % sizeof(value), 0);
   CHECK_EQ(memfd_file_size % kPageSize, 0);
@@ -35,7 +41,7 @@ int CreateAndFillMemfd(const char* name, size_t memfd_file_size, uintptr_t value
   // Use intermediate map to fully initialize file content. It lets compiler
   // optimize the loop below and limits WriteFully to fd to one call. Running
   // the Memfd.uintptr_t test on this showed 4x performance improvement.
-  uintptr_t* memfd_file_content = static_cast<uintptr_t*>(MmapOrDie(memfd_file_size));
+  T* memfd_file_content = static_cast<T*>(MmapOrDie(memfd_file_size));
 
   for (size_t i = 0; i < memfd_file_size / sizeof(value); ++i) {
     memfd_file_content[i] = value;
@@ -50,6 +56,20 @@ int CreateAndFillMemfd(const char* name, size_t memfd_file_size, uintptr_t value
   return memfd;
 }
 
+template int CreateAndFillMemfd<uintptr_t>(const char* name,
+                                           size_t memfd_file_size,
+                                           uintptr_t value);
+template int CreateAndFillMemfd<std::atomic<uintptr_t>*>(const char* name,
+                                                         size_t memfd_file_size,
+                                                         std::atomic<uintptr_t>* value);
+
+#if defined(__LP64__)
+template int CreateAndFillMemfd<uint32_t>(const char* name, size_t memfd_file_size, uint32_t value);
+template int CreateAndFillMemfd<std::atomic<uint32_t>*>(const char* name,
+                                                        size_t memfd_file_size,
+                                                        std::atomic<uint32_t>* value);
+#endif
+
 // Allocates a region of map_size bytes and backs it in chunks with memfd region
 // of memfd_file_size bytes.
 void* CreateMemfdBackedMapOrDie(int memfd, size_t map_size, size_t memfd_file_size) {
diff --git a/base/mmap_posix.cc b/base/mmap_posix.cc
index 0944fa5f..8baff84d 100644
--- a/base/mmap_posix.cc
+++ b/base/mmap_posix.cc
@@ -18,11 +18,107 @@
 
 #include <sys/mman.h>
 
+#include <atomic>
+#include <cstdint>
+#include <cstdlib>
+#include <random>  // for old versions of GLIBC only (see below)
+
 #include "berberis/base/checks.h"
 
 namespace berberis {
 
+#if defined(__LP64__) && !defined(__x86_64__)
+namespace {
+
+// arc4random was introduced in GLIBC 2.36
+#if defined(__GLIBC__) && ((__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 36)))
+uint32_t arc4random_uniform(uint32_t upper_bound) {
+  // Fall back to implementation-defined stl random
+  static std::random_device random_device("/dev/urandom");
+  static std::mt19937 generator(random_device());
+  std::uniform_int_distribution<uint32_t> distrib(0, upper_bound);
+  return distrib(generator);
+}
+#endif
+
+void* TryMmap32Bit(MmapImplArgs args) {
+  // Outside of x86_64 mapping in the lower 32bit address space
+  // is achieved by trying to map at the random 32bit address with
+  // hint and then verifying that the resulted map indeed falls in
+  // lower 32bit address space. Note that if another mapping already
+  // exists "the kernel picks a new address that may or may not
+  // depend on the hint." which makes it more difficult.
+
+  constexpr uintptr_t kMinAddress = 0x10000;
+
+  // This is always positive hence no sign-extend.
+  constexpr uintptr_t kMaxAddress = std::numeric_limits<int32_t>::max();
+
+  // This number is somewhat arbitrary. We want it to be big enough so that it
+  // doesn't fail prematurely when 2G space has lower availability, but not too
+  // big so it doesn't take forever.
+  constexpr size_t kMaxMapAttempts = 512;
+
+  static std::atomic<uintptr_t> saved_hint = 0;
+  uintptr_t hint = saved_hint.load();
+
+  uintptr_t arc4_random_upper_bound = kMaxAddress - kMinAddress;
+
+  if (args.size == 0) {
+    return MAP_FAILED;
+  }
+
+  if (__builtin_usubl_overflow(arc4_random_upper_bound, args.size, &arc4_random_upper_bound)) {
+    return MAP_FAILED;
+  }
+  CHECK_LE(arc4_random_upper_bound, kMaxAddress - kMinAddress);
+
+  if (hint == 0 || hint > (arc4_random_upper_bound + kMinAddress)) {
+    hint = arc4random_uniform(static_cast<uint32_t>(arc4_random_upper_bound)) + kMinAddress;
+  }
+
+  for (size_t i = 0; i < kMaxMapAttempts; i++) {
+    // PROT_NONE, MAP_NORESERVE to make it faster since this may take several attempts.
+    // We'll do another mmap() with proper flags on top of this one below.
+    void* addr = mmap(reinterpret_cast<void*>(hint),
+                      args.size,
+                      PROT_NONE,
+                      MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE,
+                      0,
+                      0);
+    if (addr == MAP_FAILED) {
+      return MAP_FAILED;
+    }
+
+    uintptr_t start = reinterpret_cast<uintptr_t>(addr);
+    uintptr_t end = start + args.size;
+
+    if (end <= kMaxAddress) {
+      saved_hint.store(AlignUpPageSize(end));  // next hint
+      return mmap(addr, args.size, args.prot, MAP_FIXED | args.flags, args.fd, args.offset);
+    }
+
+    hint = arc4random_uniform(static_cast<uint32_t>(arc4_random_upper_bound)) + kMinAddress;
+  }
+
+  saved_hint.store(0);
+  return MAP_FAILED;
+}
+
+}  // namespace
+
+#endif  // defined(__LP64__) && !defined(__x86_64__)
+
 void* MmapImpl(MmapImplArgs args) {
+  if ((args.berberis_flags & kMmapBerberis32Bit) != 0) {
+    // This doesn't make sense for MAP_FIXED
+    CHECK_EQ(args.flags & MAP_FIXED, 0);
+#if defined(__x86_64__)
+    args.flags |= MAP_32BIT;
+#elif defined(__LP64__)
+    return TryMmap32Bit(args);
+#endif
+  }
   return mmap(args.addr, args.size, args.prot, args.flags, args.fd, args.offset);
 }
 
diff --git a/base/mmap_test.cc b/base/mmap_test.cc
new file mode 100644
index 00000000..003b67b5
--- /dev/null
+++ b/base/mmap_test.cc
@@ -0,0 +1,63 @@
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
+#include "gtest/gtest.h"
+
+#include "berberis/base/mmap.h"
+
+#include <sys/mman.h>
+
+#include <cstdint>
+
+namespace berberis {
+
+namespace {
+
+#if defined(__LP64__)
+TEST(MmapTest, kMmapImpl_MmapBerberis32Bit) {
+  constexpr size_t k8Mb = 0x1 << 23;
+  for (size_t i = 0; i < 100; i++) {
+    void* result = MmapImpl({.size = k8Mb,
+                             .prot = PROT_READ | PROT_WRITE,
+                             .flags = MAP_PRIVATE | MAP_ANONYMOUS,
+                             .berberis_flags = kMmapBerberis32Bit});
+    ASSERT_NE(result, MAP_FAILED);
+    *reinterpret_cast<uint64_t*>(result) = 42;
+    ASSERT_EQ(*reinterpret_cast<uint64_t*>(result), 42UL);
+  }
+}
+
+TEST(MmapTest, MmapImpl_kMmapBerberis32Bit_FailsFor4G) {
+  constexpr size_t k4Gb = 0x1L << 32;
+  void* result = MmapImpl({.size = k4Gb,
+                           .prot = PROT_READ | PROT_WRITE,
+                           .flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
+                           .berberis_flags = kMmapBerberis32Bit});
+  ASSERT_EQ(result, MAP_FAILED);
+}
+
+TEST(MmapTest, MmapImpl_kMmapBerberis32Bit_FailsFor0) {
+  void* result = MmapImpl({.size = 0,
+                           .prot = PROT_READ | PROT_WRITE,
+                           .flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
+                           .berberis_flags = kMmapBerberis32Bit});
+  ASSERT_EQ(result, MAP_FAILED);
+}
+#endif
+
+}  // namespace
+
+}  // namespace berberis
diff --git a/code_gen_lib/Android.bp b/code_gen_lib/Android.bp
index ca7587d4..50a6c79a 100644
--- a/code_gen_lib/Android.bp
+++ b/code_gen_lib/Android.bp
@@ -34,16 +34,52 @@ cc_library_headers {
     ],
 }
 
-cc_library_static {
-    name: "libberberis_code_gen_lib_riscv64",
-    defaults: ["berberis_defaults_64"],
+filegroup {
+    name: "berberis_code_gen_lib_riscv64_to_x86_64_files",
+    srcs: ["riscv64_to_x86_64/gen_wrapper.cc"],
+}
+
+filegroup {
+    name: "berberis_code_gen_lib_all_to_x86_32_files",
+    srcs: ["all_to_x86_32/code_gen_lib.cc"],
+}
+
+filegroup {
+    name: "berberis_code_gen_lib_arm_to_x86_32_files",
+    srcs: ["arm_to_x86_32/gen_wrapper.cc"],
+}
+
+filegroup {
+    name: "berberis_code_gen_lib_all_to_x86_64_files",
+    srcs: ["all_to_x86_64/code_gen_lib.cc"],
+}
+
+filegroup {
+    name: "berberis_code_gen_lib_arm64_to_x86_64_files",
+    srcs: ["arm64_to_x86_64/gen_wrapper.cc"],
+}
+
+filegroup {
+    name: "berberis_code_gen_lib_all_to_riscv64_files",
+    srcs: [
+        "all_to_riscv64/code_gen_lib.cc",
+        "all_to_riscv64/gen_wrapper.cc",
+    ],
+}
+
+cc_defaults {
+    name: "berberis_code_gen_lib_defaults",
+    defaults: ["berberis_guest_agnostic_defaults"],
     host_supported: true,
     arch: {
+        x86: {
+            srcs: [":berberis_code_gen_lib_all_to_x86_32_files"],
+        },
         x86_64: {
-            srcs: [
-                "code_gen_lib_riscv64_to_x86_64.cc",
-                "gen_wrapper_riscv64_to_x86_64.cc",
-            ],
+            srcs: [":berberis_code_gen_lib_all_to_x86_64_files"],
+        },
+        riscv64: {
+            srcs: [":berberis_code_gen_lib_all_to_riscv64_files"],
         },
     },
     header_libs: [
@@ -51,10 +87,31 @@ cc_library_static {
         "libberberis_base_headers",
         "libberberis_calling_conventions_headers",
         "libberberis_code_gen_lib_headers",
+        "libberberis_kernel_api_headers",
+        "libberberis_instrument_headers",
+    ],
+    export_header_lib_headers: [
+        "libberberis_assembler_headers",
+        "libberberis_code_gen_lib_headers",
+    ],
+}
+
+cc_library_static {
+    name: "libberberis_code_gen_lib_riscv64",
+    defaults: [
+        "berberis_defaults_64",
+        "berberis_code_gen_lib_defaults",
+    ],
+    host_supported: true,
+    arch: {
+        x86_64: {
+            header_libs: ["berberis_code_gen_lib_riscv64_to_all_headers"],
+            srcs: [":berberis_code_gen_lib_riscv64_to_x86_64_files"],
+        },
+    },
+    header_libs: [
         "libberberis_guest_abi_riscv64_headers",
         "libberberis_guest_state_headers",
-        "libberberis_instrument_headers",
-        "libberberis_kernel_api_headers",
         "libberberis_macro_assembler_headers_riscv64_to_x86_64",
         "libberberis_runtime_primitives_headers",
     ],
diff --git a/code_gen_lib/all_to_riscv64/code_gen_lib.cc b/code_gen_lib/all_to_riscv64/code_gen_lib.cc
new file mode 100644
index 00000000..512b9dc7
--- /dev/null
+++ b/code_gen_lib/all_to_riscv64/code_gen_lib.cc
@@ -0,0 +1,87 @@
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
+#include "berberis/code_gen_lib/code_gen_lib.h"
+
+#include "berberis/assembler/machine_code.h"
+#include "berberis/assembler/rv64i.h"
+#include "berberis/base/macros.h"
+#include "berberis/guest_state/guest_addr.h"
+#include "berberis/runtime_primitives/host_code.h"
+#include "berberis/runtime_primitives/runtime_library.h"
+#include "berberis/runtime_primitives/translation_cache.h"
+
+namespace berberis {
+
+void GenTrampolineAdaptor(MachineCode* mc,
+                          GuestAddr pc,
+                          HostCode marshall,
+                          const void* callee,
+                          const char* name) {
+  UNUSED(mc, pc, marshall, callee, name);
+}
+
+void EmitDirectDispatch(rv64i::Assembler* as, GuestAddr pc, bool check_pending_signals) {
+  UNUSED(check_pending_signals);
+  // insn_addr is passed between regions in s11.
+  as->Li(as->s11, pc);
+
+  if (!config::kLinkJumpsBetweenRegions) {
+    as->Li(as->t1, reinterpret_cast<uint64_t>(kEntryExitGeneratedCode));
+    as->Jr(as->t1);
+    return;
+  }
+
+  // TODO(b/352784623): Check for pending signals.
+
+  CHECK_EQ(pc & GuestAddr{0xffff'0000'0000'0000U}, 0);
+  as->Li(as->t1, reinterpret_cast<uint64_t>(TranslationCache::GetInstance()->GetHostCodePtr(pc)));
+  as->Ld(as->t1, {.base = rv64i::Assembler::t1, .disp = 0});
+  as->Jr(as->t1);
+}
+
+void EmitIndirectDispatch(rv64i::Assembler* as, rv64i::Assembler::Register target) {
+  // insn_addr is passed between regions in s11.
+  if (target != as->s11) {
+    as->Mv(as->s11, target);
+  }
+
+  if (!config::kLinkJumpsBetweenRegions) {
+    as->Li(as->t1, reinterpret_cast<uint64_t>(kEntryExitGeneratedCode));
+    as->Jr(as->t1);
+    return;
+  }
+
+  // TODO(b/352784623): Add check for signals.
+
+  auto main_table_ptr = TranslationCache::GetInstance()->main_table_ptr();
+
+  as->Lui(as->t1, 0x1000000);
+  as->Addi(as->t1, as->t1, -1);
+  as->Srli(as->t2, as->s11, 24);
+  as->And(as->t2, as->t2, as->t1);
+  as->Li(as->t3, reinterpret_cast<uint64_t>(main_table_ptr));
+  as->Sh3add(as->t2, as->t2, as->t3);
+  as->Ld(as->t2, {.base = rv64i::Assembler::t2, .disp = 0});
+
+  as->And(as->t1, as->t1, as->s11);
+  as->Sh3add(as->t1, as->t1, as->t2);
+  as->Ld(as->t1, {.base = rv64i::Assembler::t1, .disp = 0});
+
+  as->Jr(as->t1);
+}
+
+}  // namespace berberis
diff --git a/code_gen_lib/all_to_riscv64/gen_wrapper.cc b/code_gen_lib/all_to_riscv64/gen_wrapper.cc
new file mode 100644
index 00000000..4f526b7c
--- /dev/null
+++ b/code_gen_lib/all_to_riscv64/gen_wrapper.cc
@@ -0,0 +1,34 @@
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
+#include "berberis/code_gen_lib/gen_wrapper.h"
+
+#include "berberis/assembler/machine_code.h"
+#include "berberis/base/macros.h"
+#include "berberis/guest_state/guest_addr.h"
+#include "berberis/runtime_primitives/host_code.h"
+
+namespace berberis {
+
+void GenWrapGuestFunction(MachineCode* mc,
+                          GuestAddr pc,
+                          const char* signature,
+                          HostCode guest_runner,
+                          const char* name) {
+  UNUSED(mc, pc, signature, guest_runner, name);
+}
+
+}  // namespace berberis
diff --git a/code_gen_lib/all_to_x86_32/code_gen_lib.cc b/code_gen_lib/all_to_x86_32/code_gen_lib.cc
new file mode 100644
index 00000000..51ae8abb
--- /dev/null
+++ b/code_gen_lib/all_to_x86_32/code_gen_lib.cc
@@ -0,0 +1,198 @@
+/*
+ * Copyright (C) 2014 The Android Open Source Project
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
+#include "berberis/code_gen_lib/code_gen_lib.h"
+
+#include "berberis/assembler/machine_code.h"
+#include "berberis/assembler/x86_32.h"
+#include "berberis/base/bit_util.h"
+#include "berberis/base/config.h"
+#include "berberis/calling_conventions/calling_conventions_x86_32.h"
+#include "berberis/code_gen_lib/code_gen_lib_arch.h"
+#include "berberis/guest_state/guest_addr.h"
+#include "berberis/guest_state/guest_state.h"
+#include "berberis/instrument/trampolines.h"
+#include "berberis/runtime_primitives/host_code.h"
+#include "berberis/runtime_primitives/translation_cache.h"
+
+namespace berberis {
+
+namespace x86_32 {
+
+namespace {
+
+// State register pointer must be callee saved.
+// Use of EBP allows shorter context read instructions.
+constexpr Assembler::Register kStateRegister = Assembler::ebp;
+
+// Emitted code checks if some emulated signal is pending. If yes,
+// it returns to the main dispatcher to handle the signal.
+// To ensure we don't loop endlessly in generated code without checks
+// for pending signals, this must be called on every exit from region (given
+// there are no loops in regions). Thus we call it in EmitJump for static
+// branches out of the regions and EmitDispatch for dynamic ones.
+void EmitCheckSignalsAndMaybeReturn(Assembler* as) {
+  // C++:
+  //   std::atomic_int_least8_t pending_signals_status;
+  //   uint8_t status = pending_signals_status.load(std::memory_order_acquire);
+  //   if (status == kPendingSignalsPresent) { ... }
+  // x86_32 asm:
+  //   cmpb pending_signals_status, kPendingSignalsPresent
+  const size_t offset = offsetof(ThreadState, pending_signals_status);
+  as->Cmpb({.base = kStateRegister, .disp = offset}, kPendingSignalsPresent);
+  as->Jcc(Assembler::Condition::kEqual, kEntryExitGeneratedCode);
+}
+
+// The offset of insn_addr is hard-coded in runtime_library_x86_32.S.  The
+// static_assert below is to ensure that the offset is still as expected.
+static_assert(offsetof(ThreadState, cpu.insn_addr) == 0x48, "");
+
+void EmitDispatch(Assembler* as, Assembler::Register target) {
+  // We are carrying target over in EAX, but we also need it in another
+  // temporary register that we'll clobber during mapping to the host address.
+  Assembler::Register reg1{Assembler::no_register};
+  if (target == Assembler::eax) {
+    reg1 = Assembler::ecx;
+    as->Movl(reg1, target);
+  } else {
+    reg1 = target;
+    as->Movl(Assembler::eax, target);
+  }
+
+  // Allocate another temporary register.
+  Assembler::Register reg2 = reg1 == Assembler::ecx ? Assembler::edx : Assembler::ecx;
+
+  if (!config::kLinkJumpsBetweenRegions) {
+    as->Jmp(kEntryExitGeneratedCode);
+    return;
+  }
+
+  EmitCheckSignalsAndMaybeReturn(as);
+
+  auto* translation_cache = TranslationCache::GetInstance();
+  auto main_table_ptr = translation_cache->main_table_ptr();
+
+  // eax, reg1: guest pc
+  //
+  // movzwl %eax,%reg2
+  // shr    $0x10,%reg1
+  // mov    main_table_ptr(,%reg1,4),%reg1
+  // jmp    *(%reg1,%reg2,4)
+  as->Movzxwl(reg2, Assembler::eax);
+  as->Shrl(reg1, int8_t{16});
+  as->Movl(
+      reg1,
+      {.index = reg1, .scale = Assembler::kTimesFour, .disp = bit_cast<int32_t>(main_table_ptr)});
+  as->Jmpl({.base = reg1, .index = reg2, .scale = Assembler::kTimesFour});
+}
+
+void GenTrampolineAdaptor(MachineCode* mc,
+                          GuestAddr pc,
+                          HostCode marshall,
+                          const void* callee,
+                          const char* name) {
+  Assembler as(mc);
+  // void Trampoline(void*, ThreadState*);
+  // void LogTrampoline(ThreadState*, const char*);
+  EmitAllocStackFrame(&as, 8);
+
+  // Update insn_addr to the current PC.  This way, code generated by this
+  // function does not require insn_addr to be up to date upon entry.  Note that
+  // the trampoline that we call requires insn_addr to be up to date.
+  as.Movl({.base = kStateRegister, .disp = offsetof(ThreadState, cpu.insn_addr)}, pc);
+  as.Movl({.base = kStateRegister, .disp = offsetof(ThreadState, residence)},
+          kOutsideGeneratedCode);
+
+  if (kInstrumentTrampolines) {
+    if (auto instrument = GetOnTrampolineCall(name)) {
+      as.Movl({.base = as.esp}, kStateRegister);
+      as.Movl({.base = as.esp, .disp = 4}, bit_cast<int32_t>(name));
+      as.Call(AsHostCode(instrument));
+    }
+  }
+
+  as.Movl({.base = as.esp}, reinterpret_cast<uintptr_t>(callee));
+  as.Movl({.base = as.esp, .disp = 4}, kStateRegister);
+  as.Call(marshall);
+
+  if (kInstrumentTrampolines) {
+    if (auto instrument = GetOnTrampolineReturn(name)) {
+      as.Movl({.base = as.esp}, kStateRegister);
+      as.Movl({.base = as.esp, .disp = 4}, bit_cast<int32_t>(name));
+      as.Call(AsHostCode(instrument));
+    }
+  }
+
+  EmitFreeStackFrame(&as, 8);
+  // jump to guest return address
+  as.Movl(as.eax, {.base = kStateRegister, .disp = kReturnAddressRegisterOffset});
+  // We are returning to generated code.
+  as.Movl({.base = kStateRegister, .disp = offsetof(ThreadState, residence)}, kInsideGeneratedCode);
+  EmitDispatch(&as, as.eax);
+  as.Finalize();
+}
+
+}  // namespace
+
+void EmitAllocStackFrame(Assembler* as, uint32_t frame_size) {
+  if (frame_size > config::kFrameSizeAtTranslatedCode) {
+    uint32_t extra_size = AlignUp(frame_size - config::kFrameSizeAtTranslatedCode,
+                                  CallingConventions::kStackAlignmentBeforeCall);
+    as->Subl(Assembler::esp, extra_size);
+  }
+}
+
+void EmitFreeStackFrame(Assembler* as, uint32_t frame_size) {
+  if (frame_size > config::kFrameSizeAtTranslatedCode) {
+    uint32_t extra_size = AlignUp(frame_size - config::kFrameSizeAtTranslatedCode,
+                                  CallingConventions::kStackAlignmentBeforeCall);
+    as->Addl(Assembler::esp, extra_size);
+  }
+}
+
+void EmitJump(Assembler* as, GuestAddr target) {
+  // Attention! Always sync insn_addr as we may be jumping out of translated code (e.g.
+  // non-translated code handler or trampolines that require synced state to run signal handlers).
+  as->Movl(Assembler::eax, target);
+
+  if (!config::kLinkJumpsBetweenRegions) {
+    as->Jmp(kEntryExitGeneratedCode);
+    return;
+  }
+
+  EmitCheckSignalsAndMaybeReturn(as);
+
+  // Now we have same stack state as we had on entry to this
+  // code, so we can just do tail call to other translation unit.
+  as->Jmpl({.disp = bit_cast<int32_t>(TranslationCache::GetInstance()->GetHostCodePtr(target))});
+}
+
+// ATTENTION: 'target' should be a general register - see constraints for PseudoIndirectJump!
+void EmitIndirectJump(Assembler* as, Assembler::Register target) {
+  EmitDispatch(as, target);
+}
+
+}  // namespace x86_32
+
+void GenTrampolineAdaptor(MachineCode* mc,
+                          GuestAddr pc,
+                          HostCode marshall,
+                          const void* callee,
+                          const char* name) {
+  x86_32::GenTrampolineAdaptor(mc, pc, marshall, callee, name);
+}
+
+}  // namespace berberis
diff --git a/code_gen_lib/code_gen_lib_riscv64_to_x86_64.cc b/code_gen_lib/all_to_x86_64/code_gen_lib.cc
similarity index 85%
rename from code_gen_lib/code_gen_lib_riscv64_to_x86_64.cc
rename to code_gen_lib/all_to_x86_64/code_gen_lib.cc
index 9f2511b8..491df4d8 100644
--- a/code_gen_lib/code_gen_lib_riscv64_to_x86_64.cc
+++ b/code_gen_lib/all_to_x86_64/code_gen_lib.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2019 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -18,10 +18,10 @@
 
 #include "berberis/assembler/machine_code.h"
 #include "berberis/assembler/x86_64.h"
-#include "berberis/base/bit_util.h"
 #include "berberis/base/checks.h"
 #include "berberis/base/config.h"
 #include "berberis/calling_conventions/calling_conventions_x86_64.h"
+#include "berberis/code_gen_lib/code_gen_lib_arch.h"
 #include "berberis/code_gen_lib/gen_adaptor.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/guest_state/guest_state.h"
@@ -88,9 +88,9 @@ void GenTrampolineAdaptor(MachineCode* mc,
     }
   }
 
-  // j ra
+  // jump to guest return address
   // Prefer rdx, since rax/rcx will result in extra moves inside EmitIndirectDispatch.
-  as.Movq(as.rdx, {.base = as.rbp, .disp = offsetof(ThreadState, cpu.x[RA])});
+  as.Movq(as.rdx, {.base = as.rbp, .disp = kReturnAddressRegisterOffset});
   // We are returning to generated code.
   as.Movq({.base = as.rbp, .disp = offsetof(ThreadState, residence)}, kInsideGeneratedCode);
   EmitIndirectDispatch(&as, as.rdx);
@@ -130,10 +130,11 @@ void EmitDirectDispatch(x86_64::Assembler* as, GuestAddr pc, bool check_pending_
     EmitCheckSignalsAndMaybeReturn(as);
   }
 
-  CHECK_EQ(pc & 0xffff000000000000, 0);
+  CHECK_EQ(pc & 0xffff'0000'0000'0000, 0);
   as->Movq(as->rcx,
            reinterpret_cast<uint64_t>(TranslationCache::GetInstance()->GetHostCodePtr(pc)));
-  as->Jmpq({.base = as->rcx});
+  as->Movl(as->rcx, {.base = as->rcx});
+  as->Jmp(as->rcx);
 }
 
 void EmitExitGeneratedCode(x86_64::Assembler* as, x86_64::Assembler::Register target) {
@@ -147,36 +148,41 @@ void EmitExitGeneratedCode(x86_64::Assembler* as, x86_64::Assembler::Register ta
 
 void EmitIndirectDispatch(x86_64::Assembler* as, x86_64::Assembler::Register target) {
   // insn_addr is passed between regions in rax.
-  as->Movq(as->rax, target);
+  if (target != as->rax) {
+    as->Movq(as->rax, target);
+  }
 
   if (!config::kLinkJumpsBetweenRegions) {
     as->Jmp(kEntryExitGeneratedCode);
     return;
   }
 
-  // rax and rcx are used as scratches.
-  if (target == as->rax || target == as->rcx) {
-    as->Movq(as->rdx, target);
-    target = as->rdx;
-  }
-
   EmitCheckSignalsAndMaybeReturn(as);
 
   auto main_table_ptr = TranslationCache::GetInstance()->main_table_ptr();
 
-  as->Shrq(as->rax, int8_t{24});
-  as->Andl(as->rax, 0xffffff);
-  as->Movq(as->rcx, reinterpret_cast<uint64_t>(main_table_ptr));
-  as->Movq(as->rcx, {.base = as->rcx, .index = as->rax, .scale = x86_64::Assembler::kTimesEight});
-
-  as->Movq(as->rax, target);
-  as->Andq(as->rax, 0xffffff);
-  as->Movq(as->rcx, {.base = as->rcx, .index = as->rax, .scale = x86_64::Assembler::kTimesEight});
-
-  // insn_addr is passed between regions in rax.
-  as->Movq(as->rax, target);
-
-  as->Jmp(as->rcx);
+  // Rax holds insn_addr. We use target and/or rcx/rdx for scratches.
+  x86_64::Assembler::Register scratch1 = target;
+  x86_64::Assembler::Register scratch2 = as->rcx;
+  if (target == as->rax) {
+    as->Movq(as->rdx, target);
+    scratch1 = as->rdx;
+  } else if (target == as->rcx) {
+    scratch1 = as->rcx;
+    scratch2 = as->rdx;
+  }
+  // scratch1 always holds insn_addr at this point.
+  as->Shrq(scratch1, int8_t{24});
+  as->Andl(scratch1, 0xff'ffff);
+  as->Movq(scratch2, reinterpret_cast<uint64_t>(main_table_ptr));
+  as->Movq(scratch2,
+           {.base = scratch2, .index = scratch1, .scale = x86_64::Assembler::kTimesEight});
+
+  as->Movq(scratch1, as->rax);
+  as->Andl(scratch1, 0xff'ffff);
+  as->Movl(scratch2, {.base = scratch2, .index = scratch1, .scale = x86_64::Assembler::kTimesFour});
+
+  as->Jmp(scratch2);
 }
 
 void EmitAllocStackFrame(x86_64::Assembler* as, uint32_t frame_size) {
diff --git a/code_gen_lib/arm64_to_all/Android.bp b/code_gen_lib/arm64_to_all/Android.bp
new file mode 100644
index 00000000..7360c2c5
--- /dev/null
+++ b/code_gen_lib/arm64_to_all/Android.bp
@@ -0,0 +1,27 @@
+// Copyright (C) 2024 The Android Open Source Project
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
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library_headers {
+    name: "berberis_code_gen_lib_arm64_to_all_headers",
+    defaults: ["berberis_arm64_defaults"],
+    host_supported: true,
+    header_libs: [
+        "libberberis_guest_state_arm64_headers",
+    ],
+    export_include_dirs: ["include"],
+}
diff --git a/code_gen_lib/arm64_to_all/include/berberis/code_gen_lib/code_gen_lib_arch.h b/code_gen_lib/arm64_to_all/include/berberis/code_gen_lib/code_gen_lib_arch.h
new file mode 100644
index 00000000..8d07f7a4
--- /dev/null
+++ b/code_gen_lib/arm64_to_all/include/berberis/code_gen_lib/code_gen_lib_arch.h
@@ -0,0 +1,27 @@
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
+#ifndef BERBERIS_CODE_GEN_LIB_CODE_GEN_LIB_ARCH_H_
+#define BERBERIS_CODE_GEN_LIB_CODE_GEN_LIB_ARCH_H_
+
+#include "berberis/guest_state/guest_state.h"
+
+namespace berberis {
+
+inline constexpr size_t kReturnAddressRegisterOffset = offsetof(ThreadState, cpu.x[30]);
+
+}  // namespace berberis
+#endif  // BERBERIS_CODE_GEN_LIB_CODE_GEN_LIB_ARCH_H_
diff --git a/code_gen_lib/arm64_to_x86_64/gen_wrapper.cc b/code_gen_lib/arm64_to_x86_64/gen_wrapper.cc
new file mode 100644
index 00000000..96d01b29
--- /dev/null
+++ b/code_gen_lib/arm64_to_x86_64/gen_wrapper.cc
@@ -0,0 +1,180 @@
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
+#include "berberis/code_gen_lib/gen_wrapper.h"
+
+#include "berberis/assembler/machine_code.h"
+#include "berberis/assembler/x86_64.h"
+#include "berberis/base/bit_util.h"
+#include "berberis/base/logging.h"
+#include "berberis/guest_abi/guest_arguments.h"
+#include "berberis/guest_state/guest_addr.h"
+#include "berberis/runtime_primitives/host_code.h"
+
+namespace berberis {
+
+using x86_64::Assembler;
+
+void GenWrapGuestFunction(MachineCode* mc,
+                          GuestAddr pc,
+                          const char* signature,
+                          HostCode guest_runner,
+                          const char* name) {
+  UNUSED(name);
+
+  Assembler as(mc);
+
+  // On function entry, rsp + 8 is a multiple of 16.
+  // Right before next function call, rsp is a multiple of 16.
+
+  // Default prologue.
+  as.Push(Assembler::rbp);
+  as.Movq(Assembler::rbp, Assembler::rsp);
+
+  static_assert(alignof(GuestArgumentBuffer) <= 16, "unexpected GuestArgumentBuffer alignment");
+
+  // Estimate guest argument buffer size.
+  // Each argument can be 2 8-bytes at most. Result can be 2 8-bytes at most.
+  // At least 8 arguments go to registers in GuestArgumentBuffer.
+  // First 8-byte of stack is in GuestArgumentBuffer.
+  // Result is return on registers in GuestArgumentBuffer.
+  // TODO(eaeltsin): maybe run parameter passing to calculate exactly?
+  size_t num_args = strlen(signature) - 1;
+  size_t max_stack_argv_size = (num_args > 8 ? num_args - 8 : 0) * 16;
+  size_t guest_argument_buffer_size = sizeof(GuestArgumentBuffer) - 8 + max_stack_argv_size;
+
+  size_t aligned_frame_size = AlignUp(guest_argument_buffer_size, 16);
+
+  // Allocate stack frame.
+  as.Subq(Assembler::rsp, static_cast<int32_t>(aligned_frame_size));
+
+  // rsp is 16-bytes aligned and points to GuestArgumentBuffer.
+
+  constexpr int kArgcOffset = offsetof(GuestArgumentBuffer, argc);
+  constexpr int kRescOffset = offsetof(GuestArgumentBuffer, resc);
+  constexpr int kArgvOffset = offsetof(GuestArgumentBuffer, argv);
+  constexpr int kSimdArgcOffset = offsetof(GuestArgumentBuffer, simd_argc);
+  constexpr int kSimdRescOffset = offsetof(GuestArgumentBuffer, simd_resc);
+  constexpr int kSimdArgvOffset = offsetof(GuestArgumentBuffer, simd_argv);
+  constexpr int kStackArgcOffset = offsetof(GuestArgumentBuffer, stack_argc);
+  constexpr int kStackArgvOffset = offsetof(GuestArgumentBuffer, stack_argv);
+
+  const int params_offset = aligned_frame_size + 16;
+
+  // Convert parameters and set argc.
+  int argc = 0;
+  int simd_argc = 0;
+  int stack_argc = 0;
+  int host_stack_argc = 0;
+  for (size_t i = 1; signature[i] != '\0'; ++i) {
+    if (signature[i] == 'z' || signature[i] == 'b' || signature[i] == 's' || signature[i] == 'c' ||
+        signature[i] == 'i' || signature[i] == 'p' || signature[i] == 'l') {
+      static constexpr Assembler::Register kParamRegs[] = {
+          Assembler::rdi,
+          Assembler::rsi,
+          Assembler::rdx,
+          Assembler::rcx,
+          Assembler::r8,
+          Assembler::r9,
+      };
+      if (argc < static_cast<int>(std::size(kParamRegs))) {
+        as.Movq({.base = Assembler::rsp, .disp = kArgvOffset + argc * 8}, kParamRegs[argc]);
+      } else if (argc < 8) {
+        as.Movq(Assembler::rax,
+                {.base = Assembler::rsp, .disp = params_offset + host_stack_argc * 8});
+        ++host_stack_argc;
+        as.Movq({.base = Assembler::rsp, .disp = kArgvOffset + argc * 8}, Assembler::rax);
+      } else {
+        as.Movq(Assembler::rax,
+                {.base = Assembler::rsp, .disp = params_offset + host_stack_argc * 8});
+        ++host_stack_argc;
+        as.Movq({.base = Assembler::rsp, .disp = kStackArgvOffset + stack_argc * 8},
+                Assembler::rax);
+        ++stack_argc;
+      }
+      ++argc;
+    } else if (signature[i] == 'f' || signature[i] == 'd') {
+      static constexpr Assembler::XMMRegister kParamRegs[] = {
+          Assembler::xmm0,
+          Assembler::xmm1,
+          Assembler::xmm2,
+          Assembler::xmm3,
+          Assembler::xmm4,
+          Assembler::xmm5,
+          Assembler::xmm6,
+          Assembler::xmm7,
+      };
+      if (simd_argc < static_cast<int>(std::size(kParamRegs))) {
+        as.Movq({.base = Assembler::rsp, .disp = kSimdArgvOffset + simd_argc * 16},
+                kParamRegs[simd_argc]);
+      } else {
+        as.Movq(Assembler::rax,
+                {.base = Assembler::rsp, .disp = params_offset + host_stack_argc * 8});
+        ++host_stack_argc;
+        as.Movq({.base = Assembler::rsp, .disp = kStackArgvOffset + stack_argc * 8},
+                Assembler::rax);
+        ++stack_argc;
+      }
+      ++simd_argc;
+    } else {
+      FATAL("signature char '%c' not supported", signature[i]);
+    }
+  }
+  as.Movl({.base = Assembler::rsp, .disp = kArgcOffset}, std::min(argc, 8));
+  as.Movl({.base = Assembler::rsp, .disp = kSimdArgcOffset}, std::min(simd_argc, 8));
+  // ATTENTION: GuestArgumentBuffer::stack_argc is in bytes!
+  as.Movl({.base = Assembler::rsp, .disp = kStackArgcOffset}, stack_argc * 8);
+
+  // Set resc.
+  if (signature[0] == 'z' || signature[0] == 'b' || signature[0] == 's' ||
+      signature[0] == 'c' | signature[0] == 'i' || signature[0] == 'p' || signature[0] == 'l') {
+    as.Movl({.base = Assembler::rsp, .disp = kRescOffset}, 1);
+    as.Movl({.base = Assembler::rsp, .disp = kSimdRescOffset}, 0);
+  } else if (signature[0] == 'f' || signature[0] == 'd') {
+    as.Movl({.base = Assembler::rsp, .disp = kRescOffset}, 0);
+    as.Movl({.base = Assembler::rsp, .disp = kSimdRescOffset}, 1);
+  } else {
+    CHECK_EQ('v', signature[0]);
+    as.Movl({.base = Assembler::rsp, .disp = kRescOffset}, 0);
+    as.Movl({.base = Assembler::rsp, .disp = kSimdRescOffset}, 0);
+  }
+
+  // Call guest runner.
+  as.Movq(Assembler::rdi, pc);
+  as.Movq(Assembler::rsi, Assembler::rsp);
+  as.Call(guest_runner);
+
+  // Get the result.
+  if (signature[0] == 'z' || signature[0] == 'b' || signature[0] == 's' ||
+      signature[0] == 'c' | signature[0] == 'i' || signature[0] == 'p' || signature[0] == 'l') {
+    as.Movq(Assembler::rax, {.base = Assembler::rsp, .disp = kArgvOffset});
+  } else if (signature[0] == 'f' || signature[0] == 'd') {
+    as.Movq(Assembler::xmm0, {.base = Assembler::rsp, .disp = kSimdArgvOffset});
+  } else {
+    CHECK_EQ('v', signature[0]);
+  }
+
+  // Free stack frame.
+  as.Addq(Assembler::rsp, static_cast<int32_t>(aligned_frame_size));
+
+  // Default epilogue.
+  as.Pop(Assembler::rbp);
+  as.Ret();
+
+  as.Finalize();
+}
+
+}  // namespace berberis
diff --git a/code_gen_lib/arm_to_all/Android.bp b/code_gen_lib/arm_to_all/Android.bp
new file mode 100644
index 00000000..301f5998
--- /dev/null
+++ b/code_gen_lib/arm_to_all/Android.bp
@@ -0,0 +1,27 @@
+// Copyright (C) 2024 The Android Open Source Project
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
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library_headers {
+    name: "berberis_code_gen_lib_arm_to_all_headers",
+    defaults: ["berberis_arm_defaults"],
+    host_supported: true,
+    header_libs: [
+        "libberberis_guest_state_arm_headers",
+    ],
+    export_include_dirs: ["include"],
+}
diff --git a/code_gen_lib/arm_to_all/include/berberis/code_gen_lib/code_gen_lib_arch.h b/code_gen_lib/arm_to_all/include/berberis/code_gen_lib/code_gen_lib_arch.h
new file mode 100644
index 00000000..b8632be4
--- /dev/null
+++ b/code_gen_lib/arm_to_all/include/berberis/code_gen_lib/code_gen_lib_arch.h
@@ -0,0 +1,27 @@
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
+#ifndef BERBERIS_CODE_GEN_LIB_CODE_GEN_LIB_ARCH_H_
+#define BERBERIS_CODE_GEN_LIB_CODE_GEN_LIB_ARCH_H_
+
+#include "berberis/guest_state/guest_state.h"
+
+namespace berberis {
+
+inline constexpr size_t kReturnAddressRegisterOffset = offsetof(ThreadState, cpu.r[14]);
+
+}  // namespace berberis
+#endif  // BERBERIS_CODE_GEN_LIB_CODE_GEN_LIB_ARCH_H_
diff --git a/code_gen_lib/arm_to_x86_32/gen_wrapper.cc b/code_gen_lib/arm_to_x86_32/gen_wrapper.cc
new file mode 100644
index 00000000..fe8567e7
--- /dev/null
+++ b/code_gen_lib/arm_to_x86_32/gen_wrapper.cc
@@ -0,0 +1,148 @@
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
+#include "berberis/code_gen_lib/gen_wrapper.h"
+
+#include "berberis/assembler/machine_code.h"
+#include "berberis/assembler/x86_32.h"
+#include "berberis/base/bit_util.h"
+#include "berberis/base/logging.h"
+#include "berberis/guest_abi/guest_arguments.h"
+#include "berberis/guest_abi/guest_call.h"
+#include "berberis/guest_state/guest_addr.h"
+#include "berberis/runtime_primitives/host_code.h"
+
+namespace berberis {
+
+using x86_32::Assembler;
+
+void GenWrapGuestFunction(MachineCode* mc,
+                          GuestAddr pc,
+                          const char* signature,
+                          HostCode guest_runner,
+                          const char* name) {
+  UNUSED(name);
+
+  // Stack frame
+  // -----------
+  // esp, aligned on 16             -> [argument 0: pc]
+  //                                   [argument 1: guest argument buffer addr]
+  // aligned on 4                   -> [guest argument buffer]
+  //                                   [...]
+  // esp after prologue             -> [saved ebp]
+  // esp after call                 -> [return addr]
+  // esp before call, aligned on 16 -> [parameter 0]
+  //                                   [...]
+
+  Assembler as(mc);
+
+  // On function entry, esp + 4 is a multiple of 16.
+  // Right before next function call, esp is a multiple of 16.
+
+  // Default prologue.
+  as.Push(Assembler::ebp);
+  as.Movl(Assembler::ebp, Assembler::esp);
+
+  static_assert(alignof(GuestArgumentBuffer) <= 4, "unexpected GuestArgumentBuffer alignment");
+
+  // Estimate guest argument buffer size.
+  // Each argument can be 2 4-bytes at most. Result can be 2 4-bytes at most.
+  // First 4-byte is in the GuestArgumentBuffer.
+  // TODO(eaeltsin): maybe run parameter passing to calculate exactly?
+  size_t max_argv_size = strlen(signature) * 8;
+  size_t guest_argument_buffer_size = sizeof(GuestArgumentBuffer) - 4 + max_argv_size;
+
+  // Stack frame size is guest argument buffer + 2 4-bytes for guest runner arguments.
+  size_t frame_size = guest_argument_buffer_size + 8;
+
+  // Curr esp + 8 is a multiple of 16.
+  // New esp is a multiple of 16.
+  size_t aligned_frame_size = AlignUp(frame_size + 8, 16) - 8;
+
+  // Allocate stack frame.
+  as.Subl(Assembler::esp, aligned_frame_size);
+
+  constexpr int kArgcOffset = 8 + offsetof(GuestArgumentBuffer, argc);
+  constexpr int kRescOffset = 8 + offsetof(GuestArgumentBuffer, resc);
+  constexpr int kArgvOffset = 8 + offsetof(GuestArgumentBuffer, argv);
+
+  const int params_offset = aligned_frame_size + 8;
+
+  // Convert parameters and set argc.
+  int host_argc = 0;
+  int argc = 0;
+  for (size_t i = 1; signature[i] != '\0'; ++i) {
+    if (signature[i] == 'z' || signature[i] == 'b' || signature[i] == 's' || signature[i] == 'c' ||
+        signature[i] == 'i' || signature[i] == 'p' || signature[i] == 'f') {
+      as.Movl(Assembler::eax, {.base = Assembler::esp, .disp = params_offset + 4 * host_argc});
+      ++host_argc;
+      as.Movl({.base = Assembler::esp, .disp = kArgvOffset + 4 * argc}, Assembler::eax);
+      ++argc;
+    } else if (signature[i] == 'l' || signature[i] == 'd') {
+      as.Movl(Assembler::eax, {.base = Assembler::esp, .disp = params_offset + 4 * host_argc});
+      as.Movl(Assembler::edx, {.base = Assembler::esp, .disp = params_offset + 4 * host_argc + 4});
+      host_argc += 2;
+      argc = AlignUp(argc, 2);
+      as.Movl({.base = Assembler::esp, .disp = kArgvOffset + 4 * argc}, Assembler::eax);
+      as.Movl({.base = Assembler::esp, .disp = kArgvOffset + 4 * argc + 4}, Assembler::edx);
+      argc += 2;
+    } else {
+      FATAL("signature char '%c' not supported", signature[i]);
+    }
+  }
+  as.Movl({.base = Assembler::esp, .disp = kArgcOffset}, argc);
+
+  // Set resc.
+  if (signature[0] == 'z' || signature[0] == 'b' || signature[0] == 's' ||
+      signature[0] == 'c' | signature[0] == 'i' || signature[0] == 'p' || signature[0] == 'f') {
+    as.Movl({.base = Assembler::esp, .disp = kRescOffset}, 1);
+  } else if (signature[0] == 'l' || signature[0] == 'd') {
+    as.Movl({.base = Assembler::esp, .disp = kRescOffset}, 2);
+  } else {
+    CHECK_EQ('v', signature[0]);
+    as.Movl({.base = Assembler::esp, .disp = kRescOffset}, 0);
+  }
+
+  // Call guest runner.
+  as.Movl({.base = Assembler::esp, .disp = 0}, pc);
+  as.Leal(Assembler::eax, {.base = Assembler::esp, .disp = 8});
+  as.Movl({.base = Assembler::esp, .disp = 4}, Assembler::eax);
+  as.Call(guest_runner);
+
+  // Get the result.
+  if (signature[0] == 'z' || signature[0] == 'b' || signature[0] == 's' ||
+      signature[0] == 'c' | signature[0] == 'i' || signature[0] == 'p') {
+    as.Movl(Assembler::eax, {.base = Assembler::esp, .disp = kArgvOffset});
+  } else if (signature[0] == 'l') {
+    as.Movl(Assembler::eax, {.base = Assembler::esp, .disp = kArgvOffset});
+    as.Movl(Assembler::edx, {.base = Assembler::esp, .disp = kArgvOffset + 4});
+  } else if (signature[0] == 'f') {
+    as.Flds({.base = Assembler::esp, .disp = kArgvOffset});
+  } else if (signature[0] == 'd') {
+    as.Fldl({.base = Assembler::esp, .disp = kArgvOffset});
+  }
+
+  // Free stack frame.
+  as.Addl(Assembler::esp, aligned_frame_size);
+
+  // Default epilogue.
+  as.Pop(Assembler::ebp);
+  as.Ret();
+
+  as.Finalize();
+}
+
+}  // namespace berberis
diff --git a/code_gen_lib/code_gen_lib_riscv64_test.cc b/code_gen_lib/code_gen_lib_riscv64_test.cc
index 7eb58431..ca72bbdb 100644
--- a/code_gen_lib/code_gen_lib_riscv64_test.cc
+++ b/code_gen_lib/code_gen_lib_riscv64_test.cc
@@ -108,7 +108,7 @@ TEST(CodeGenLib, GenTrampolineAdaptorResidence) {
   ScopedExecRegion generated_code_exec(&generated_code);
 
   AddToTranslationCache(ToGuestAddr(&g_ret_insn),
-                        {generated_code_exec.get(), generated_code.install_size()});
+                        {generated_code_exec.GetHostCodeAddr(), generated_code.install_size()});
 
   g_state.cpu.insn_addr = 0;
   SetLinkRegister(g_state.cpu, ToGuestAddr(&g_ret_insn));
diff --git a/code_gen_lib/include/berberis/code_gen_lib/code_gen_lib.h b/code_gen_lib/include/berberis/code_gen_lib/code_gen_lib.h
index a65885d7..6b1d4b62 100644
--- a/code_gen_lib/include/berberis/code_gen_lib/code_gen_lib.h
+++ b/code_gen_lib/include/berberis/code_gen_lib/code_gen_lib.h
@@ -21,15 +21,16 @@
 
 #if defined(__i386__)
 #include "berberis/assembler/x86_32.h"
-#endif
-
-#if defined(__x86_64__)
+#elif defined(__x86_64__)
 #include "berberis/assembler/x86_64.h"
+#elif defined(__riscv)
+#include "berberis/assembler/rv64i.h"
 #endif
 
 namespace berberis {
 
 #if defined(__i386__)
+
 namespace x86_32 {
 
 void EmitAllocStackFrame(Assembler* as, uint32_t frame_size);
@@ -39,15 +40,18 @@ void EmitJump(Assembler* as, GuestAddr target);
 void EmitIndirectJump(Assembler* as, Assembler::Register target);
 
 }  // namespace x86_32
-#endif
 
-#if defined(__x86_64__)
+#elif defined(__x86_64__)
 void EmitSyscall(x86_64::Assembler* as, GuestAddr pc);
 void EmitDirectDispatch(x86_64::Assembler* as, GuestAddr pc, bool check_pending_signals);
 void EmitIndirectDispatch(x86_64::Assembler* as, x86_64::Assembler::Register target);
 void EmitExitGeneratedCode(x86_64::Assembler* as, x86_64::Assembler::Register target);
 void EmitAllocStackFrame(x86_64::Assembler* as, uint32_t frame_size);
 void EmitFreeStackFrame(x86_64::Assembler* as, uint32_t frame_size);
+#elif defined(__riscv)
+void EmitDirectDispatch(rv64i::Assembler* as, GuestAddr pc, bool check_pending_signals);
+void EmitIndirectDispatch(rv64i::Assembler* as, rv64i::Assembler::Register target);
+void EmitExitGeneratedCode(rv64i::Assembler* as, rv64i::Assembler::Register target);
 #endif
 
 }  // namespace berberis
diff --git a/code_gen_lib/riscv64_to_all/Android.bp b/code_gen_lib/riscv64_to_all/Android.bp
new file mode 100644
index 00000000..8d93f292
--- /dev/null
+++ b/code_gen_lib/riscv64_to_all/Android.bp
@@ -0,0 +1,27 @@
+// Copyright (C) 2024 The Android Open Source Project
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
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library_headers {
+    name: "berberis_code_gen_lib_riscv64_to_all_headers",
+    defaults: ["berberis_defaults"],
+    host_supported: true,
+    header_libs: [
+        "libberberis_guest_state_riscv64_headers",
+    ],
+    export_include_dirs: ["include"],
+}
diff --git a/code_gen_lib/riscv64_to_all/include/berberis/code_gen_lib/code_gen_lib_arch.h b/code_gen_lib/riscv64_to_all/include/berberis/code_gen_lib/code_gen_lib_arch.h
new file mode 100644
index 00000000..4e817713
--- /dev/null
+++ b/code_gen_lib/riscv64_to_all/include/berberis/code_gen_lib/code_gen_lib_arch.h
@@ -0,0 +1,27 @@
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
+#ifndef BERBERIS_CODE_GEN_LIB_CODE_GEN_LIB_ARCH_H_
+#define BERBERIS_CODE_GEN_LIB_CODE_GEN_LIB_ARCH_H_
+
+#include "berberis/guest_state/guest_state.h"
+
+namespace berberis {
+
+inline constexpr size_t kReturnAddressRegisterOffset = offsetof(ThreadState, cpu.x[RA]);
+
+}  // namespace berberis
+#endif  // BERBERIS_CODE_GEN_LIB_CODE_GEN_LIB_ARCH_H_
diff --git a/code_gen_lib/gen_wrapper_riscv64_to_x86_64.cc b/code_gen_lib/riscv64_to_x86_64/gen_wrapper.cc
similarity index 100%
rename from code_gen_lib/gen_wrapper_riscv64_to_x86_64.cc
rename to code_gen_lib/riscv64_to_x86_64/gen_wrapper.cc
diff --git a/guest_abi/Android.bp b/guest_abi/Android.bp
index 14fd6550..5a7fb239 100644
--- a/guest_abi/Android.bp
+++ b/guest_abi/Android.bp
@@ -23,12 +23,14 @@ cc_library_headers {
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: [
+        "jni_headers",
         "libberberis_base_headers",
         "libberberis_calling_conventions_headers",
         "libberberis_guest_state_headers",
         "libberberis_runtime_primitives_headers",
     ],
     export_header_lib_headers: [
+        "jni_headers",
         "libberberis_base_headers",
         "libberberis_calling_conventions_headers",
         "libberberis_guest_state_headers",
diff --git a/guest_abi/include/berberis/guest_abi/function_wrappers.h b/guest_abi/include/berberis/guest_abi/function_wrappers.h
index 1f4918c3..4f854767 100644
--- a/guest_abi/include/berberis/guest_abi/function_wrappers.h
+++ b/guest_abi/include/berberis/guest_abi/function_wrappers.h
@@ -19,6 +19,8 @@
 
 #include <utility>
 
+#include <jni.h>
+
 #include "berberis/guest_abi/guest_abi.h"  // IWYU pragma: export.
 #include "berberis/guest_abi/guest_function_wrapper.h"
 #include "berberis/guest_abi/guest_params.h"
@@ -28,6 +30,8 @@
 
 namespace berberis {
 
+extern JNIEnv* ToHostJNIEnv(GuestType<JNIEnv*> guest_jni_env);
+
 // Setup and run trampoline function.
 template <typename Func,
           GuestAbi::CallingConventionsVariant kCallingConventionsVariant = GuestAbi::kDefaultAbi>
@@ -38,6 +42,7 @@ template <typename Arg,
 struct GetGuestArgumentClass {
  public:
   static_assert(!std::is_pointer_v<Arg> || !std::is_function_v<std::remove_pointer_t<Arg>>);
+  static_assert(!std::is_pointer_v<Arg> || !std::is_same_v<std::remove_pointer_t<Arg>, JNIEnv>);
   decltype(auto) operator()(Arg arg) const { return arg; }
 };
 
@@ -51,6 +56,14 @@ struct GetGuestArgumentClass<Res (*)(Args...), kCallingConventionsVariant> {
   }
 };
 
+template <GuestAbi::CallingConventionsVariant kCallingConventionsVariant>
+struct GetGuestArgumentClass<JNIEnv*, kCallingConventionsVariant> {
+ public:
+  decltype(auto) operator()(GuestType<JNIEnv*> guest_jni_env) const {
+    return ToHostJNIEnv(guest_jni_env);
+  }
+};
+
 template <typename Arg,
           GuestAbi::CallingConventionsVariant kCallingConventionsVariant = GuestAbi::kDefaultAbi>
 inline constexpr auto GetGuestArgument = GetGuestArgumentClass<Arg, kCallingConventionsVariant>{};
diff --git a/guest_abi/riscv64/Android.bp b/guest_abi/riscv64/Android.bp
index 8f08cd69..1d6ff138 100644
--- a/guest_abi/riscv64/Android.bp
+++ b/guest_abi/riscv64/Android.bp
@@ -19,7 +19,7 @@ package {
 
 cc_library_headers {
     name: "libberberis_guest_abi_riscv64_headers",
-    defaults: ["berberis_defaults_64"],
+    defaults: ["berberis_all_hosts_defaults_64"],
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: [
@@ -34,7 +34,7 @@ cc_library_headers {
 
 cc_library_static {
     name: "libberberis_guest_abi_riscv64",
-    defaults: ["berberis_defaults_64"],
+    defaults: ["berberis_all_hosts_defaults_64"],
     host_supported: true,
     srcs: [
         "guest_call.cc",
diff --git a/guest_loader/Android.bp b/guest_loader/Android.bp
index 64755f0b..914c0ae9 100644
--- a/guest_loader/Android.bp
+++ b/guest_loader/Android.bp
@@ -122,7 +122,7 @@ cc_test {
     ],
     static_libs: [
         "libberberis_guest_loader_riscv64",
-        "libberberis_runtime_riscv64_to_x86_64",
+        "libberberis_runtime_riscv64",
     ],
     shared_libs: [
         "libberberis_riscv64",
diff --git a/guest_loader/app_process.cc b/guest_loader/app_process.cc
index 386c8fbe..ce4275ca 100644
--- a/guest_loader/app_process.cc
+++ b/guest_loader/app_process.cc
@@ -21,41 +21,66 @@
 #include <condition_variable>
 #include <mutex>
 
+#include "berberis/base/forever_alloc.h"
+
 namespace berberis {
 
 namespace {
 
-std::mutex g_guest_loader_mtx;
-std::condition_variable g_guest_loader_cv;
-bool g_guest_loader_initialized = false;
+class AppProcess {
+ public:
+  static AppProcess* GetInstance() {
+    static auto* g_app_process = NewForever<AppProcess>();
+    return g_app_process;
+  }
+
+  void PostInit() {
+    {
+      std::lock_guard<std::mutex> guard(mutex_);
+      initialized_ = true;
+    }
+    cv_.notify_all();
+
+    // Expect this call to occur on the main guest thread, after app
+    // initialization is done. Force exit since keeping the thread in the
+    // background might confuse an app that expects to be single-threaded.
+    // Specifically, this scenario happens when guest code is executed in
+    // app-zygote before forking children (b/146904103).
+    //
+    // Other threads may use main thread's stack to access argc/argv/auxvals.
+    // We ensure that stack is retained after pthread_exit() by disallowing
+    // stack unmap in main guest thread when starting an executable.
+    //
+    // Note that we cannot just let the thread exit from main(), which would
+    // exit the whole process, not just this thread.
+    pthread_exit(nullptr);
+  }
+
+  void WaitForPostInit() {
+    std::unique_lock<std::mutex> lock(mutex_);
+    cv_.wait(lock, [this] { return initialized_; });
+  }
+
+ private:
+  AppProcess() = default;
+  AppProcess(const AppProcess&) = delete;
+  AppProcess& operator=(const AppProcess&) = delete;
+
+  friend AppProcess* NewForever<AppProcess>();
+
+  std::mutex mutex_;
+  std::condition_variable cv_;
+  bool initialized_ = false;
+};
 
 }  // namespace
 
 void AppProcessPostInit() {
-  {
-    std::lock_guard<std::mutex> guard(g_guest_loader_mtx);
-    g_guest_loader_initialized = true;
-  }
-  g_guest_loader_cv.notify_all();
-
-  // Expect this call to occur on the main guest thread, after app
-  // initialization is done. Force exit since keeping the thread in the
-  // background might confuse an app that expects to be single-threaded.
-  // Specifically, this scenario happens when guest code is executed in
-  // app-zygote before forking children (b/146904103).
-  //
-  // Other threads may use main thread's stack to access argc/argv/auxvals.
-  // We ensure that stack is retained after pthread_exit() by disallowing
-  // stack unmap in main guest thread when starting an executable.
-  //
-  // Note that we cannot just let the thread exit from main(), which would
-  // exit the whole process, not just this thread.
-  pthread_exit(nullptr);
+  AppProcess::GetInstance()->PostInit();
 }
 
 void WaitForAppProcess() {
-  std::unique_lock<std::mutex> lock(g_guest_loader_mtx);
-  g_guest_loader_cv.wait(lock, [] { return g_guest_loader_initialized; });
+  AppProcess::GetInstance()->WaitForPostInit();
 }
 
-}  // namespace berberis
\ No newline at end of file
+}  // namespace berberis
diff --git a/guest_loader/guest_loader.cc b/guest_loader/guest_loader.cc
index 4aa90769..83f8dc38 100644
--- a/guest_loader/guest_loader.cc
+++ b/guest_loader/guest_loader.cc
@@ -17,11 +17,11 @@
 #include "berberis/guest_loader/guest_loader.h"
 
 #include <algorithm>   // std::generate
+#include <atomic>
 #include <climits>     // CHAR_BIT
 #include <cstdint>
 #include <cstdlib>
 #include <functional>  // std::ref
-#include <mutex>
 #include <random>
 #include <thread>
 
@@ -251,21 +251,21 @@ bool InitializeLinker(LinkerCallbacks* linker_callbacks,
          InitializeLinkerCallbacksArch(linker_callbacks, linker_elf_file, error_msg);
 }
 
-std::mutex g_guest_loader_instance_mtx;
-GuestLoader* g_guest_loader_instance;
+std::atomic<GuestLoader*> g_guest_loader_instance;
 
 }  // namespace
 
 GuestLoader::GuestLoader() = default;
 
-GuestLoader::~GuestLoader() = default;
+GuestLoader::~GuestLoader() {
+  delete g_guest_loader_instance.load();
+};
 
 GuestLoader* GuestLoader::CreateInstance(const char* main_executable_path,
                                          const char* vdso_path,
                                          const char* loader_path,
                                          std::string* error_msg) {
-  std::lock_guard<std::mutex> lock(g_guest_loader_instance_mtx);
-  CHECK(g_guest_loader_instance == nullptr);
+  CHECK_EQ(g_guest_loader_instance.load(), nullptr);
 
   TRACE(
       "GuestLoader::CreateInstance(main_executable_path=\"%s\", "
@@ -337,13 +337,12 @@ GuestLoader* GuestLoader::CreateInstance(const char* main_executable_path,
   }
 
   g_guest_loader_instance = instance.release();
-  return g_guest_loader_instance;
+  return g_guest_loader_instance.load();
 }
 
 GuestLoader* GuestLoader::GetInstance() {
-  std::lock_guard<std::mutex> lock(g_guest_loader_instance_mtx);
-  CHECK(g_guest_loader_instance != nullptr);
-  return g_guest_loader_instance;
+  CHECK_NE(g_guest_loader_instance.load(), nullptr);
+  return g_guest_loader_instance.load();
 }
 
 void GuestLoader::StartGuestMainThread() {
diff --git a/guest_loader/include/berberis/guest_loader/guest_loader.h b/guest_loader/include/berberis/guest_loader/guest_loader.h
index 642e6242..807cdf61 100644
--- a/guest_loader/include/berberis/guest_loader/guest_loader.h
+++ b/guest_loader/include/berberis/guest_loader/guest_loader.h
@@ -104,7 +104,7 @@ class GuestLoader {
                               char* envp[],
                               std::string* error_msg);
 
-  // If GetInstance() called before Initialize() it will return nullptr
+  // It's only valid to call this after CreateInstance is finished.
   static GuestLoader* GetInstance();
 
   uintptr_t DlUnwindFindExidx(uintptr_t pc, int* pcount);
@@ -157,4 +157,4 @@ class GuestLoader {
 
 }  // namespace berberis
 
-#endif  // BERBERIS_GUEST_LOADER_GUEST_LOADER_H_
\ No newline at end of file
+#endif  // BERBERIS_GUEST_LOADER_GUEST_LOADER_H_
diff --git a/guest_os_primitives/Android.bp b/guest_os_primitives/Android.bp
index e39d7b9c..7e74a74a 100644
--- a/guest_os_primitives/Android.bp
+++ b/guest_os_primitives/Android.bp
@@ -19,7 +19,7 @@ package {
 
 cc_library_headers {
     name: "libberberis_guest_os_primitives_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["include"],
     header_libs: [
@@ -38,14 +38,14 @@ cc_library_headers {
 // Don't depend on these headers in other modules.
 cc_library_headers {
     name: "_libberberis_guest_os_primitives_private_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["."],
 }
 
 cc_library_headers {
     name: "libberberis_guest_os_primitives_riscv64_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["riscv64/include"],
     header_libs: [
@@ -71,6 +71,11 @@ filegroup {
     ],
 }
 
+filegroup {
+    name: "libberberis_guest_os_primitives_common_arm64_srcs",
+    srcs: ["unmap_and_exit_arm64.S"],
+}
+
 filegroup {
     name: "libberberis_guest_os_primitives_common_x86_32_srcs",
     srcs: ["unmap_and_exit_x86_32.S"],
@@ -81,19 +86,30 @@ filegroup {
     srcs: ["unmap_and_exit_x86_64.S"],
 }
 
+filegroup {
+    name: "libberberis_guest_os_primitives_common_riscv64_srcs",
+    srcs: ["unmap_and_exit_riscv64.cc"],
+}
+
 // Common sources to be shared across arch-specific libraries.
 cc_defaults {
     name: "libberberis_guest_os_primitives_common_defaults",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     srcs: [":libberberis_guest_os_primitives_common_srcs"],
     arch: {
+        arm64: {
+            srcs: [":libberberis_guest_os_primitives_common_arm64_srcs"],
+        },
         x86: {
             srcs: [":libberberis_guest_os_primitives_common_x86_32_srcs"],
         },
         x86_64: {
             srcs: [":libberberis_guest_os_primitives_common_x86_64_srcs"],
         },
+        riscv64: {
+            srcs: [":libberberis_guest_os_primitives_common_riscv64_srcs"],
+        },
     },
     header_libs: [
         "libberberis_base_headers",
@@ -126,7 +142,7 @@ filegroup {
 // libberberis_guest_os_primitives_common_arch_defaults.
 cc_library_headers {
     name: "_libberberis_guest_os_primitives_local_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["."],
 }
@@ -148,13 +164,24 @@ cc_defaults {
 cc_library_static {
     name: "libberberis_guest_os_primitives_riscv64",
     defaults: [
-        "berberis_defaults_64",
+        "berberis_all_hosts_defaults_64",
         "libberberis_guest_os_primitives_common_defaults",
         "libberberis_guest_os_primitives_common_arch_defaults",
     ],
     host_supported: true,
+    arch: {
+        arm64: {
+            srcs: [
+                "riscv64/gen_syscall_numbers_arm64.cc",
+            ],
+        },
+        x86_64: {
+            srcs: [
+                "riscv64/gen_syscall_numbers_x86_64.cc",
+            ],
+        },
+    },
     srcs: [
-        "riscv64/gen_syscall_numbers.cc",
         "riscv64/guest_setjmp.cc",
         "riscv64/guest_signal.cc",
     ],
diff --git a/guest_os_primitives/get_tls.h b/guest_os_primitives/get_tls.h
index cb154291..e6a01907 100644
--- a/guest_os_primitives/get_tls.h
+++ b/guest_os_primitives/get_tls.h
@@ -40,6 +40,13 @@ namespace berberis {
     __asm__("mv %0, tp" : "=r"(__val)); \
     __val;                              \
   })
+#elif defined(__aarch64__)
+#define GetTls()                                \
+  ({                                            \
+    void** __val;                               \
+    __asm__("mrs %0, tpidr_el0" : "=r"(__val)); \
+    __val;                                      \
+  })
 #else
 #error unsupported architecture
 #endif
diff --git a/guest_os_primitives/guest_map_shadow.cc b/guest_os_primitives/guest_map_shadow.cc
index 0e09e1e5..f5b45948 100644
--- a/guest_os_primitives/guest_map_shadow.cc
+++ b/guest_os_primitives/guest_map_shadow.cc
@@ -21,6 +21,7 @@
 #include <mutex>
 
 #include "berberis/base/bit_util.h"
+#include "berberis/base/forever_alloc.h"
 #include "berberis/base/large_mmap.h"
 #include "berberis/base/logging.h"
 #include "berberis/base/mmap.h"
@@ -36,8 +37,10 @@ constexpr size_t kGuestPageSizeLog2 = 12;
 #if defined(BERBERIS_GUEST_LP64)
 // On LP64 the address space is limited to 48 bits
 constexpr size_t kGuestAddressSizeLog2 = 48;
+constexpr size_t kMaxGuestAddress{0xffff'ffff'ffff};
 #else
 constexpr size_t kGuestAddressSizeLog2 = sizeof(GuestAddr) * CHAR_BIT;
+constexpr size_t kMaxGuestAddress{0xffff'ffff};
 #endif
 constexpr size_t kGuestPageSize = 1 << kGuestPageSizeLog2;  // 4096
 constexpr size_t kShadowSize = 1UL << (kGuestAddressSizeLog2 - kGuestPageSizeLog2 - 3);
@@ -61,18 +64,28 @@ bool DoIntervalsIntersect(const void* start,
 }  // namespace
 
 GuestMapShadow* GuestMapShadow::GetInstance() {
-  static GuestMapShadow g_map_shadow;
-  return &g_map_shadow;
+  static auto* g_map_shadow = NewForever<GuestMapShadow>();
+  return g_map_shadow;
 }
 
 bool GuestMapShadow::IsExecAddr(GuestAddr addr) const {
-  uint32_t page = addr >> kGuestPageSizeLog2;
+  if (addr > kMaxGuestAddress) {
+    // Addresses outside the supported range are always non-executable.
+    // In practice we may end up here when parsing kernel addresses
+    // from /proc/self/maps.
+    return false;
+  }
+  uintptr_t page = addr >> kGuestPageSizeLog2;
   return shadow_[page >> 3] & (1 << (page & 7));
 }
 
 // Returns true if value changed.
 bool GuestMapShadow::SetExecAddr(GuestAddr addr, int set) {
-  uint32_t page = addr >> kGuestPageSizeLog2;
+  if (addr > kMaxGuestAddress) {
+    // See IsExecAddr for explanation.
+    return false;
+  }
+  uintptr_t page = addr >> kGuestPageSizeLog2;
   uint8_t mask = 1 << (page & 7);
   int old = shadow_[page >> 3] & mask;
   if (set) {
diff --git a/guest_os_primitives/guest_map_shadow_test.cc b/guest_os_primitives/guest_map_shadow_test.cc
index 6b74b08b..5475d712 100644
--- a/guest_os_primitives/guest_map_shadow_test.cc
+++ b/guest_os_primitives/guest_map_shadow_test.cc
@@ -34,8 +34,8 @@ class GuestMapShadowTest : public ::testing::Test {
   }
 };
 
-constexpr GuestAddr kGuestAddr = GuestAddr{0x7f018000};
-constexpr size_t kGuestRegionSize = GuestAddr{0x00020000};
+constexpr GuestAddr kGuestAddr{0x7f018000};
+constexpr size_t kGuestRegionSize{0x00020000};
 
 TEST_F(GuestMapShadowTest, smoke) {
   auto shadow = std::make_unique<GuestMapShadow>();
@@ -137,6 +137,26 @@ TEST_F(GuestMapShadowTest, ProtectedMappings) {
   EXPECT_FALSE(shadow->IntersectsWithProtectedMapping(kAnotherEnd, kAnotherEnd + kGuestRegionSize));
 }
 
+#if defined(BERBERIS_GUEST_LP64)
+
+TEST_F(GuestMapShadowTest, 64BitAddress) {
+  auto shadow = std::make_unique<GuestMapShadow>();
+  // We only really allow up to 48 bit addresses.
+  constexpr uint64_t k64BitAddr{0x0000'7fff'dddd'ccccULL};
+
+  ASSERT_EQ(kBitUnset, shadow->GetExecutable(k64BitAddr, kGuestRegionSize));
+
+  shadow->SetExecutable(k64BitAddr, kGuestRegionSize);
+
+  ASSERT_EQ(kBitSet, shadow->GetExecutable(k64BitAddr, kGuestRegionSize));
+  // The address with 4 upper bits truncated doesn't map to
+  // the same entry as the full address (b/369950324).
+  constexpr uint64_t kTruncated64BitAddr{k64BitAddr & ~(uint64_t{0xf} << 44)};
+  ASSERT_EQ(kBitUnset, shadow->GetExecutable(kTruncated64BitAddr, kGuestRegionSize));
+}
+
+#endif
+
 }  // namespace
 
 }  // namespace berberis
diff --git a/guest_os_primitives/guest_signal_action.cc b/guest_os_primitives/guest_signal_action.cc
index d5a7448f..01eba2e2 100644
--- a/guest_os_primitives/guest_signal_action.cc
+++ b/guest_os_primitives/guest_signal_action.cc
@@ -65,6 +65,8 @@ void ConvertHostSigactionToGuest(const HostStructSigaction* host_sa, Guest_sigac
       }
 #elif defined(__riscv)
       LOG_ALWAYS_FATAL("Unimplemented for riscv64");
+#elif defined(__aarch64__)
+      LOG_ALWAYS_FATAL("Unimplemented for arm64");
 #else
 #error "Unknown host arch"
 #endif
diff --git a/guest_os_primitives/guest_signal_handling.cc b/guest_os_primitives/guest_signal_handling.cc
index 0a800b61..2b3e26e3 100644
--- a/guest_os_primitives/guest_signal_handling.cc
+++ b/guest_os_primitives/guest_signal_handling.cc
@@ -25,6 +25,7 @@
 
 #include "berberis/base/checks.h"
 #include "berberis/base/config_globals.h"
+#include "berberis/base/forever_alloc.h"
 #include "berberis/base/tracing.h"
 #include "berberis/guest_os_primitives/guest_signal.h"
 #include "berberis/guest_os_primitives/guest_thread.h"
@@ -65,41 +66,46 @@ bool IsPendingSignalWithoutRecoveryCodeFatal(siginfo_t* info) {
   }
 }
 
-GuestSignalActionsTable g_signal_actions;
 // Technically guest threads may work with different signal action tables, so it's possible to
 // optimize by using different mutexes. But it's rather an exotic corner case, so we keep it simple.
-std::mutex g_signal_actions_guard_mutex;
+std::mutex* GetSignalActionsGuardMutex() {
+  static auto* g_mutex = NewForever<std::mutex>();
+  return g_mutex;
+}
 
 const Guest_sigaction* FindSignalHandler(const GuestSignalActionsTable& signal_actions,
                                          int signal) {
   CHECK_GT(signal, 0);
   CHECK_LE(signal, Guest__KERNEL__NSIG);
-  std::lock_guard<std::mutex> lock(g_signal_actions_guard_mutex);
+  std::lock_guard<std::mutex> lock(*GetSignalActionsGuardMutex());
   return &signal_actions.at(signal - 1).GetClaimedGuestAction();
 }
 
+uintptr_t GetHostRegIP(const ucontext_t* ucontext) {
 #if defined(__i386__)
-constexpr size_t kHostRegIP = REG_EIP;
+  return ucontext->uc_mcontext.gregs[REG_EIP];
 #elif defined(__x86_64__)
-constexpr size_t kHostRegIP = REG_RIP;
+  return ucontext->uc_mcontext.gregs[REG_RIP];
 #elif defined(__riscv)
-constexpr size_t kHostRegIP = REG_PC;
+  return ucontext->uc_mcontext.__gregs[REG_PC];
+#elif defined(__aarch64__)
+  return ucontext->uc_mcontext.pc;
 #else
 #error "Unknown host arch"
 #endif
-uintptr_t GetHostRegIP(const ucontext_t* ucontext) {
-#if defined(__riscv)
-  return ucontext->uc_mcontext.__gregs[kHostRegIP];
-#else
-  return ucontext->uc_mcontext.gregs[kHostRegIP];
-#endif
 }
 
 void SetHostRegIP(ucontext* ucontext, uintptr_t addr) {
-#if defined(__riscv)
-  ucontext->uc_mcontext.__gregs[kHostRegIP] = addr;
+#if defined(__i386__)
+  ucontext->uc_mcontext.gregs[REG_EIP] = addr;
+#elif defined(__x86_64__)
+  ucontext->uc_mcontext.gregs[REG_RIP] = addr;
+#elif defined(__riscv)
+  ucontext->uc_mcontext.__gregs[REG_PC] = addr;
+#elif defined(__aarch64__)
+  ucontext->uc_mcontext.pc = addr;
 #else
-  ucontext->uc_mcontext.gregs[kHostRegIP] = addr;
+#error "Unknown host arch"
 #endif
 }
 
@@ -180,14 +186,15 @@ bool IsReservedSignal(int signal) {
 }  // namespace
 
 void GuestThread::SetDefaultSignalActionsTable() {
+  static auto* g_signal_actions = NewForever<GuestSignalActionsTable>();
   // We need to initialize shared_ptr, but we don't want to attempt to delete the default
   // signal actions when guest thread terminates. Hence we specify a void deleter.
-  signal_actions_ = std::shared_ptr<GuestSignalActionsTable>(&g_signal_actions, [](auto) {});
+  signal_actions_ = std::shared_ptr<GuestSignalActionsTable>(g_signal_actions, [](auto) {});
 }
 
 void GuestThread::CloneSignalActionsTableFrom(GuestSignalActionsTable* from_table) {
   // Need lock to make sure from_table isn't changed concurrently.
-  std::lock_guard<std::mutex> lock(g_signal_actions_guard_mutex);
+  std::lock_guard<std::mutex> lock(*GetSignalActionsGuardMutex());
   signal_actions_ = std::make_shared<GuestSignalActionsTable>(*from_table);
 }
 
@@ -329,6 +336,10 @@ bool SetGuestSignalHandler(int signal,
                            const Guest_sigaction* act,
                            Guest_sigaction* old_act,
                            int* error) {
+#if defined(__riscv)
+  TRACE("ATTENTION: SetGuestSignalHandler is unimplemented - skipping it without raising an error");
+  return true;
+#endif
   if (signal < 1 || signal > Guest__KERNEL__NSIG) {
     *error = EINVAL;
     return false;
@@ -339,7 +350,7 @@ bool SetGuestSignalHandler(int signal,
     act = nullptr;
   }
 
-  std::lock_guard<std::mutex> lock(g_signal_actions_guard_mutex);
+  std::lock_guard<std::mutex> lock(*GetSignalActionsGuardMutex());
   GuestSignalAction& action = GetCurrentGuestThread()->GetSignalActionsTable()->at(signal - 1);
   return action.Change(signal, act, HandleHostSignal, old_act, error);
 }
diff --git a/guest_os_primitives/guest_thread_manager.cc b/guest_os_primitives/guest_thread_manager.cc
index e889a859..0d715c86 100644
--- a/guest_os_primitives/guest_thread_manager.cc
+++ b/guest_os_primitives/guest_thread_manager.cc
@@ -33,9 +33,6 @@ namespace berberis {
 // Manages thread local storage (TLS) for the current thread's GuestThread instance.
 pthread_key_t g_guest_thread_key;
 
-// Tracks GuestThread instances across all threads.
-GuestThreadMap g_guest_thread_map_;
-
 namespace {
 
 void GuestThreadDtor(void* /* arg */) {
@@ -59,7 +56,7 @@ GuestThread* GetCurrentGuestThread() {
 }
 
 void ResetCurrentGuestThreadAfterFork(GuestThread* thread) {
-  g_guest_thread_map_.ResetThreadTable(GettidSyscall(), thread);
+  GuestThreadMap::GetInstance()->ResetThreadTable(GettidSyscall(), thread);
 #if defined(__BIONIC__)
   // Force (host) bionic to update cached tid if necessary
   // 1. Bionic `clone` implementation resets cached `tid` before syscall
@@ -83,7 +80,7 @@ bool GetGuestThreadAttr(pid_t tid,
                         size_t* stack_size,
                         size_t* guard_size,
                         int* error) {
-  GuestThread* thread = g_guest_thread_map_.FindThread(tid);
+  GuestThread* thread = GuestThreadMap::GetInstance()->FindThread(tid);
   if (thread) {
     thread->GetAttr(stack_base, stack_size, guard_size);
     return true;
@@ -99,7 +96,7 @@ void ExitCurrentThread(int status) {
   ScopedSignalBlocker signal_blocker;
 
   // Remove thread from global table.
-  GuestThread* thread = g_guest_thread_map_.RemoveThread(tid);
+  GuestThread* thread = GuestThreadMap::GetInstance()->RemoveThread(tid);
   if (kInstrumentGuestThread) {
     OnRemoveGuestThread(tid, thread);
   }
@@ -120,7 +117,7 @@ void FlushGuestCodeCache() {
   // TODO(b/28081995): at the moment we don't wait for acknowledgment. This
   // might cause subtle guest logic failures.
   pid_t current_tid = GettidSyscall();
-  g_guest_thread_map_.ForEachThread([current_tid](pid_t tid, GuestThread* thread) {
+  GuestThreadMap::GetInstance()->ForEachThread([current_tid](pid_t tid, GuestThread* thread) {
     // ATTENTION: we probably don't want to force current thread to dispatcher
     // and to wait for it to acknowledge :) Assume caller of this function
     // (syscall emulation or trampoline) will force re-read from translation
@@ -155,7 +152,7 @@ GuestThread* AttachCurrentThread(bool register_dtor, bool* attached) {
   ScopedSignalBlocker signal_blocker;
 
   pid_t tid = GettidSyscall();
-  GuestThread* thread = g_guest_thread_map_.FindThread(tid);
+  GuestThread* thread = GuestThreadMap::GetInstance()->FindThread(tid);
   if (thread) {
     // Thread was already attached.
     *attached = false;
@@ -195,7 +192,7 @@ void InsertCurrentThread(GuestThread* thread, bool register_dtor) {
   // Thread should not be already in the table!
   // If signal came after we checked tls cache or table but before we blocked signals, it should
   // have attached AND detached the thread!
-  g_guest_thread_map_.InsertThread(tid, thread);
+  GuestThreadMap::GetInstance()->InsertThread(tid, thread);
   if (register_dtor) {
     CHECK_EQ(0, pthread_setspecific(g_guest_thread_key, thread));
   }
@@ -214,7 +211,7 @@ void DetachCurrentThread() {
   ScopedSignalBlocker signal_blocker;
 
   // Remove thread from global table.
-  GuestThread* thread = g_guest_thread_map_.RemoveThread(tid);
+  GuestThread* thread = GuestThreadMap::GetInstance()->RemoveThread(tid);
   if (kInstrumentGuestThread) {
     OnRemoveGuestThread(tid, thread);
   }
diff --git a/guest_os_primitives/guest_thread_map.cc b/guest_os_primitives/guest_thread_map.cc
index 385d98e6..4b3aaf9a 100644
--- a/guest_os_primitives/guest_thread_map.cc
+++ b/guest_os_primitives/guest_thread_map.cc
@@ -18,12 +18,18 @@
 #include <mutex>
 
 #include "berberis/base/checks.h"
+#include "berberis/base/forever_alloc.h"
 #include "berberis/guest_os_primitives/guest_thread.h"
 
 #include "guest_thread_map.h"
 
 namespace berberis {
 
+GuestThreadMap* GuestThreadMap::GetInstance() {
+  static auto* g_guest_thread_map = NewForever<GuestThreadMap>();
+  return g_guest_thread_map;
+}
+
 void GuestThreadMap::ResetThreadTable(pid_t tid, GuestThread* thread) {
   std::lock_guard<std::mutex> lock(mutex_);
   map_.clear();
@@ -54,4 +60,4 @@ GuestThread* GuestThreadMap::FindThread(pid_t tid) {
   return it->second;
 }
 
-}  // namespace berberis
\ No newline at end of file
+}  // namespace berberis
diff --git a/guest_os_primitives/guest_thread_map.h b/guest_os_primitives/guest_thread_map.h
index 09820ee4..60385fa7 100644
--- a/guest_os_primitives/guest_thread_map.h
+++ b/guest_os_primitives/guest_thread_map.h
@@ -27,6 +27,8 @@ namespace berberis {
 
 class GuestThreadMap {
  public:
+  static GuestThreadMap* GetInstance();
+
   void ResetThreadTable(pid_t tid, GuestThread* thread);
   void InsertThread(pid_t tid, GuestThread* thread);
   GuestThread* RemoveThread(pid_t tid);
@@ -42,10 +44,16 @@ class GuestThreadMap {
   }
 
  private:
+  GuestThreadMap() = default;
+  GuestThreadMap(const GuestThreadMap&) = delete;
+  GuestThreadMap& operator=(const GuestThreadMap&) = delete;
+
+  friend GuestThreadMap* NewForever<GuestThreadMap>();
+
   ForeverMap<pid_t, GuestThread*> map_;
   std::mutex mutex_;
 };
 
 }  // namespace berberis
 
-#endif  // BERBERIS_GUEST_OS_PRIMITIVES_GUEST_THREAD_MAP_H_
\ No newline at end of file
+#endif  // BERBERIS_GUEST_OS_PRIMITIVES_GUEST_THREAD_MAP_H_
diff --git a/guest_os_primitives/riscv64/gen_syscall_numbers_arm64.cc b/guest_os_primitives/riscv64/gen_syscall_numbers_arm64.cc
new file mode 100644
index 00000000..b70add76
--- /dev/null
+++ b/guest_os_primitives/riscv64/gen_syscall_numbers_arm64.cc
@@ -0,0 +1,1259 @@
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
+#include "berberis/guest_os_primitives/gen_syscall_numbers.h"
+
+namespace berberis {
+
+int ToHostSyscallNumber(int nr) {
+  switch (nr) {
+    case 202:  // __NR_accept
+      return 202;
+    case 242:  // __NR_accept4
+      return 242;
+    case 89:  // __NR_acct
+      return 89;
+    case 217:  // __NR_add_key
+      return 217;
+    case 171:  // __NR_adjtimex
+      return 171;
+    case 200:  // __NR_bind
+      return 200;
+    case 280:  // __NR_bpf
+      return 280;
+    case 214:  // __NR_brk
+      return 214;
+    case 90:  // __NR_capget
+      return 90;
+    case 91:  // __NR_capset
+      return 91;
+    case 49:  // __NR_chdir
+      return 49;
+    case 51:  // __NR_chroot
+      return 51;
+    case 266:  // __NR_clock_adjtime
+      return 266;
+    case 114:  // __NR_clock_getres
+      return 114;
+    case 113:  // __NR_clock_gettime
+      return 113;
+    case 115:  // __NR_clock_nanosleep
+      return 115;
+    case 112:  // __NR_clock_settime
+      return 112;
+    case 220:  // __NR_clone
+      return 220;
+    case 435:  // __NR_clone3
+      return 435;
+    case 57:  // __NR_close
+      return 57;
+    case 436:  // __NR_close_range
+      return 436;
+    case 203:  // __NR_connect
+      return 203;
+    case 285:  // __NR_copy_file_range
+      return 285;
+    case 106:  // __NR_delete_module
+      return 106;
+    case 23:  // __NR_dup
+      return 23;
+    case 24:  // __NR_dup3
+      return 24;
+    case 20:  // __NR_epoll_create1
+      return 20;
+    case 21:  // __NR_epoll_ctl
+      return 21;
+    case 22:  // __NR_epoll_pwait
+      return 22;
+    case 441:  // __NR_epoll_pwait2
+      return 441;
+    case 19:  // __NR_eventfd2
+      return 19;
+    case 221:  // __NR_execve
+      return 221;
+    case 281:  // __NR_execveat
+      return 281;
+    case 93:  // __NR_exit
+      return 93;
+    case 94:  // __NR_exit_group
+      return 94;
+    case 48:  // __NR_faccessat
+      return 48;
+    case 439:  // __NR_faccessat2
+      return 439;
+    case 223:  // __NR_fadvise64
+      return 223;
+    case 47:  // __NR_fallocate
+      return 47;
+    case 262:  // __NR_fanotify_init
+      return 262;
+    case 263:  // __NR_fanotify_mark
+      return 263;
+    case 50:  // __NR_fchdir
+      return 50;
+    case 52:  // __NR_fchmod
+      return 52;
+    case 53:  // __NR_fchmodat
+      return 53;
+    case 55:  // __NR_fchown
+      return 55;
+    case 54:  // __NR_fchownat
+      return 54;
+    case 25:  // __NR_fcntl
+      return 25;
+    case 83:  // __NR_fdatasync
+      return 83;
+    case 10:  // __NR_fgetxattr
+      return 10;
+    case 273:  // __NR_finit_module
+      return 273;
+    case 13:  // __NR_flistxattr
+      return 13;
+    case 32:  // __NR_flock
+      return 32;
+    case 16:  // __NR_fremovexattr
+      return 16;
+    case 431:  // __NR_fsconfig
+      return 431;
+    case 7:  // __NR_fsetxattr
+      return 7;
+    case 432:  // __NR_fsmount
+      return 432;
+    case 430:  // __NR_fsopen
+      return 430;
+    case 433:  // __NR_fspick
+      return 433;
+    case 80:  // __NR_fstat
+      return 80;
+    case 44:  // __NR_fstatfs
+      return 44;
+    case 82:  // __NR_fsync
+      return 82;
+    case 46:  // __NR_ftruncate
+      return 46;
+    case 98:  // __NR_futex
+      return 98;
+    case 449:  // __NR_futex_waitv
+      return 449;
+    case 236:  // __NR_get_mempolicy
+      return 236;
+    case 100:  // __NR_get_robust_list
+      return 100;
+    case 168:  // __NR_getcpu
+      return 168;
+    case 17:  // __NR_getcwd
+      return 17;
+    case 61:  // __NR_getdents64
+      return 61;
+    case 177:  // __NR_getegid
+      return 177;
+    case 175:  // __NR_geteuid
+      return 175;
+    case 176:  // __NR_getgid
+      return 176;
+    case 158:  // __NR_getgroups
+      return 158;
+    case 102:  // __NR_getitimer
+      return 102;
+    case 205:  // __NR_getpeername
+      return 205;
+    case 155:  // __NR_getpgid
+      return 155;
+    case 172:  // __NR_getpid
+      return 172;
+    case 173:  // __NR_getppid
+      return 173;
+    case 141:  // __NR_getpriority
+      return 141;
+    case 278:  // __NR_getrandom
+      return 278;
+    case 150:  // __NR_getresgid
+      return 150;
+    case 148:  // __NR_getresuid
+      return 148;
+    case 163:  // __NR_getrlimit
+      return 163;
+    case 165:  // __NR_getrusage
+      return 165;
+    case 156:  // __NR_getsid
+      return 156;
+    case 204:  // __NR_getsockname
+      return 204;
+    case 209:  // __NR_getsockopt
+      return 209;
+    case 178:  // __NR_gettid
+      return 178;
+    case 169:  // __NR_gettimeofday
+      return 169;
+    case 174:  // __NR_getuid
+      return 174;
+    case 8:  // __NR_getxattr
+      return 8;
+    case 105:  // __NR_init_module
+      return 105;
+    case 27:  // __NR_inotify_add_watch
+      return 27;
+    case 26:  // __NR_inotify_init1
+      return 26;
+    case 28:  // __NR_inotify_rm_watch
+      return 28;
+    case 3:  // __NR_io_cancel
+      return 3;
+    case 1:  // __NR_io_destroy
+      return 1;
+    case 4:  // __NR_io_getevents
+      return 4;
+    case 292:  // __NR_io_pgetevents
+      return 292;
+    case 0:  // __NR_io_setup
+      return 0;
+    case 2:  // __NR_io_submit
+      return 2;
+    case 426:  // __NR_io_uring_enter
+      return 426;
+    case 427:  // __NR_io_uring_register
+      return 427;
+    case 425:  // __NR_io_uring_setup
+      return 425;
+    case 29:  // __NR_ioctl
+      return 29;
+    case 31:  // __NR_ioprio_get
+      return 31;
+    case 30:  // __NR_ioprio_set
+      return 30;
+    case 272:  // __NR_kcmp
+      return 272;
+    case 294:  // __NR_kexec_file_load
+      return 294;
+    case 104:  // __NR_kexec_load
+      return 104;
+    case 219:  // __NR_keyctl
+      return 219;
+    case 129:  // __NR_kill
+      return 129;
+    case 445:  // __NR_landlock_add_rule
+      return 445;
+    case 444:  // __NR_landlock_create_ruleset
+      return 444;
+    case 446:  // __NR_landlock_restrict_self
+      return 446;
+    case 9:  // __NR_lgetxattr
+      return 9;
+    case 37:  // __NR_linkat
+      return 37;
+    case 201:  // __NR_listen
+      return 201;
+    case 11:  // __NR_listxattr
+      return 11;
+    case 12:  // __NR_llistxattr
+      return 12;
+    case 18:  // __NR_lookup_dcookie
+      return 18;
+    case 15:  // __NR_lremovexattr
+      return 15;
+    case 62:  // __NR_lseek
+      return 62;
+    case 6:  // __NR_lsetxattr
+      return 6;
+    case 233:  // __NR_madvise
+      return 233;
+    case 235:  // __NR_mbind
+      return 235;
+    case 283:  // __NR_membarrier
+      return 283;
+    case 279:  // __NR_memfd_create
+      return 279;
+    case 447:  // __NR_memfd_secret
+      return 447;
+    case 238:  // __NR_migrate_pages
+      return 238;
+    case 232:  // __NR_mincore
+      return 232;
+    case 34:  // __NR_mkdirat
+      return 34;
+    case 33:  // __NR_mknodat
+      return 33;
+    case 228:  // __NR_mlock
+      return 228;
+    case 284:  // __NR_mlock2
+      return 284;
+    case 230:  // __NR_mlockall
+      return 230;
+    case 222:  // __NR_mmap
+      return 222;
+    case 40:  // __NR_mount
+      return 40;
+    case 442:  // __NR_mount_setattr
+      return 442;
+    case 429:  // __NR_move_mount
+      return 429;
+    case 239:  // __NR_move_pages
+      return 239;
+    case 226:  // __NR_mprotect
+      return 226;
+    case 185:  // __NR_mq_getsetattr
+      return 185;
+    case 184:  // __NR_mq_notify
+      return 184;
+    case 180:  // __NR_mq_open
+      return 180;
+    case 183:  // __NR_mq_timedreceive
+      return 183;
+    case 182:  // __NR_mq_timedsend
+      return 182;
+    case 181:  // __NR_mq_unlink
+      return 181;
+    case 216:  // __NR_mremap
+      return 216;
+    case 187:  // __NR_msgctl
+      return 187;
+    case 186:  // __NR_msgget
+      return 186;
+    case 188:  // __NR_msgrcv
+      return 188;
+    case 189:  // __NR_msgsnd
+      return 189;
+    case 227:  // __NR_msync
+      return 227;
+    case 229:  // __NR_munlock
+      return 229;
+    case 231:  // __NR_munlockall
+      return 231;
+    case 215:  // __NR_munmap
+      return 215;
+    case 264:  // __NR_name_to_handle_at
+      return 264;
+    case 101:  // __NR_nanosleep
+      return 101;
+    case 79:  // __NR_newfstatat
+      return 79;
+    case 42:  // __NR_nfsservctl
+      return 42;
+    case 265:  // __NR_open_by_handle_at
+      return 265;
+    case 428:  // __NR_open_tree
+      return 428;
+    case 56:  // __NR_openat
+      return 56;
+    case 437:  // __NR_openat2
+      return 437;
+    case 241:  // __NR_perf_event_open
+      return 241;
+    case 92:  // __NR_personality
+      return 92;
+    case 438:  // __NR_pidfd_getfd
+      return 438;
+    case 434:  // __NR_pidfd_open
+      return 434;
+    case 424:  // __NR_pidfd_send_signal
+      return 424;
+    case 59:  // __NR_pipe2
+      return 59;
+    case 41:  // __NR_pivot_root
+      return 41;
+    case 289:  // __NR_pkey_alloc
+      return 289;
+    case 290:  // __NR_pkey_free
+      return 290;
+    case 288:  // __NR_pkey_mprotect
+      return 288;
+    case 73:  // __NR_ppoll
+      return 73;
+    case 167:  // __NR_prctl
+      return 167;
+    case 67:  // __NR_pread64
+      return 67;
+    case 69:  // __NR_preadv
+      return 69;
+    case 286:  // __NR_preadv2
+      return 286;
+    case 261:  // __NR_prlimit64
+      return 261;
+    case 440:  // __NR_process_madvise
+      return 440;
+    case 448:  // __NR_process_mrelease
+      return 448;
+    case 270:  // __NR_process_vm_readv
+      return 270;
+    case 271:  // __NR_process_vm_writev
+      return 271;
+    case 72:  // __NR_pselect6
+      return 72;
+    case 117:  // __NR_ptrace
+      return 117;
+    case 68:  // __NR_pwrite64
+      return 68;
+    case 70:  // __NR_pwritev
+      return 70;
+    case 287:  // __NR_pwritev2
+      return 287;
+    case 60:  // __NR_quotactl
+      return 60;
+    case 443:  // __NR_quotactl_fd
+      return 443;
+    case 63:  // __NR_read
+      return 63;
+    case 213:  // __NR_readahead
+      return 213;
+    case 78:  // __NR_readlinkat
+      return 78;
+    case 65:  // __NR_readv
+      return 65;
+    case 142:  // __NR_reboot
+      return 142;
+    case 207:  // __NR_recvfrom
+      return 207;
+    case 243:  // __NR_recvmmsg
+      return 243;
+    case 212:  // __NR_recvmsg
+      return 212;
+    case 234:  // __NR_remap_file_pages
+      return 234;
+    case 14:  // __NR_removexattr
+      return 14;
+    case 38:  // __NR_renameat
+      return 38;
+    case 276:  // __NR_renameat2
+      return 276;
+    case 218:  // __NR_request_key
+      return 218;
+    case 128:  // __NR_restart_syscall
+      return 128;
+    case 293:  // __NR_rseq
+      return 293;
+    case 134:  // __NR_rt_sigaction
+      return 134;
+    case 136:  // __NR_rt_sigpending
+      return 136;
+    case 135:  // __NR_rt_sigprocmask
+      return 135;
+    case 138:  // __NR_rt_sigqueueinfo
+      return 138;
+    case 139:  // __NR_rt_sigreturn
+      return 139;
+    case 133:  // __NR_rt_sigsuspend
+      return 133;
+    case 137:  // __NR_rt_sigtimedwait
+      return 137;
+    case 240:  // __NR_rt_tgsigqueueinfo
+      return 240;
+    case 125:  // __NR_sched_get_priority_max
+      return 125;
+    case 126:  // __NR_sched_get_priority_min
+      return 126;
+    case 123:  // __NR_sched_getaffinity
+      return 123;
+    case 275:  // __NR_sched_getattr
+      return 275;
+    case 121:  // __NR_sched_getparam
+      return 121;
+    case 120:  // __NR_sched_getscheduler
+      return 120;
+    case 127:  // __NR_sched_rr_get_interval
+      return 127;
+    case 122:  // __NR_sched_setaffinity
+      return 122;
+    case 274:  // __NR_sched_setattr
+      return 274;
+    case 118:  // __NR_sched_setparam
+      return 118;
+    case 119:  // __NR_sched_setscheduler
+      return 119;
+    case 124:  // __NR_sched_yield
+      return 124;
+    case 277:  // __NR_seccomp
+      return 277;
+    case 191:  // __NR_semctl
+      return 191;
+    case 190:  // __NR_semget
+      return 190;
+    case 193:  // __NR_semop
+      return 193;
+    case 192:  // __NR_semtimedop
+      return 192;
+    case 71:  // __NR_sendfile
+      return 71;
+    case 269:  // __NR_sendmmsg
+      return 269;
+    case 211:  // __NR_sendmsg
+      return 211;
+    case 206:  // __NR_sendto
+      return 206;
+    case 237:  // __NR_set_mempolicy
+      return 237;
+    case 450:  // __NR_set_mempolicy_home_node
+      return 450;
+    case 99:  // __NR_set_robust_list
+      return 99;
+    case 96:  // __NR_set_tid_address
+      return 96;
+    case 162:  // __NR_setdomainname
+      return 162;
+    case 152:  // __NR_setfsgid
+      return 152;
+    case 151:  // __NR_setfsuid
+      return 151;
+    case 144:  // __NR_setgid
+      return 144;
+    case 159:  // __NR_setgroups
+      return 159;
+    case 161:  // __NR_sethostname
+      return 161;
+    case 103:  // __NR_setitimer
+      return 103;
+    case 268:  // __NR_setns
+      return 268;
+    case 154:  // __NR_setpgid
+      return 154;
+    case 140:  // __NR_setpriority
+      return 140;
+    case 143:  // __NR_setregid
+      return 143;
+    case 149:  // __NR_setresgid
+      return 149;
+    case 147:  // __NR_setresuid
+      return 147;
+    case 145:  // __NR_setreuid
+      return 145;
+    case 164:  // __NR_setrlimit
+      return 164;
+    case 157:  // __NR_setsid
+      return 157;
+    case 208:  // __NR_setsockopt
+      return 208;
+    case 170:  // __NR_settimeofday
+      return 170;
+    case 146:  // __NR_setuid
+      return 146;
+    case 5:  // __NR_setxattr
+      return 5;
+    case 196:  // __NR_shmat
+      return 196;
+    case 195:  // __NR_shmctl
+      return 195;
+    case 197:  // __NR_shmdt
+      return 197;
+    case 194:  // __NR_shmget
+      return 194;
+    case 210:  // __NR_shutdown
+      return 210;
+    case 132:  // __NR_sigaltstack
+      return 132;
+    case 74:  // __NR_signalfd4
+      return 74;
+    case 198:  // __NR_socket
+      return 198;
+    case 199:  // __NR_socketpair
+      return 199;
+    case 76:  // __NR_splice
+      return 76;
+    case 43:  // __NR_statfs
+      return 43;
+    case 291:  // __NR_statx
+      return 291;
+    case 225:  // __NR_swapoff
+      return 225;
+    case 224:  // __NR_swapon
+      return 224;
+    case 36:  // __NR_symlinkat
+      return 36;
+    case 81:  // __NR_sync
+      return 81;
+    case 84:  // __NR_sync_file_range
+      return 84;
+    case 267:  // __NR_syncfs
+      return 267;
+    case 179:  // __NR_sysinfo
+      return 179;
+    case 116:  // __NR_syslog
+      return 116;
+    case 77:  // __NR_tee
+      return 77;
+    case 131:  // __NR_tgkill
+      return 131;
+    case 107:  // __NR_timer_create
+      return 107;
+    case 111:  // __NR_timer_delete
+      return 111;
+    case 109:  // __NR_timer_getoverrun
+      return 109;
+    case 108:  // __NR_timer_gettime
+      return 108;
+    case 110:  // __NR_timer_settime
+      return 110;
+    case 85:  // __NR_timerfd_create
+      return 85;
+    case 87:  // __NR_timerfd_gettime
+      return 87;
+    case 86:  // __NR_timerfd_settime
+      return 86;
+    case 153:  // __NR_times
+      return 153;
+    case 130:  // __NR_tkill
+      return 130;
+    case 45:  // __NR_truncate
+      return 45;
+    case 166:  // __NR_umask
+      return 166;
+    case 39:  // __NR_umount2
+      return 39;
+    case 160:  // __NR_uname
+      return 160;
+    case 35:  // __NR_unlinkat
+      return 35;
+    case 97:  // __NR_unshare
+      return 97;
+    case 282:  // __NR_userfaultfd
+      return 282;
+    case 88:  // __NR_utimensat
+      return 88;
+    case 58:  // __NR_vhangup
+      return 58;
+    case 75:  // __NR_vmsplice
+      return 75;
+    case 260:  // __NR_wait4
+      return 260;
+    case 95:  // __NR_waitid
+      return 95;
+    case 64:  // __NR_write
+      return 64;
+    case 66:  // __NR_writev
+      return 66;
+    default:
+      return -1;
+  }
+}
+
+int ToGuestSyscallNumber(int nr) {
+  switch (nr) {
+    case 202:  // __NR_accept
+      return 202;
+    case 242:  // __NR_accept4
+      return 242;
+    case 89:  // __NR_acct
+      return 89;
+    case 217:  // __NR_add_key
+      return 217;
+    case 171:  // __NR_adjtimex
+      return 171;
+    case 200:  // __NR_bind
+      return 200;
+    case 280:  // __NR_bpf
+      return 280;
+    case 214:  // __NR_brk
+      return 214;
+    case 90:  // __NR_capget
+      return 90;
+    case 91:  // __NR_capset
+      return 91;
+    case 49:  // __NR_chdir
+      return 49;
+    case 51:  // __NR_chroot
+      return 51;
+    case 266:  // __NR_clock_adjtime
+      return 266;
+    case 114:  // __NR_clock_getres
+      return 114;
+    case 113:  // __NR_clock_gettime
+      return 113;
+    case 115:  // __NR_clock_nanosleep
+      return 115;
+    case 112:  // __NR_clock_settime
+      return 112;
+    case 220:  // __NR_clone
+      return 220;
+    case 435:  // __NR_clone3
+      return 435;
+    case 57:  // __NR_close
+      return 57;
+    case 436:  // __NR_close_range
+      return 436;
+    case 203:  // __NR_connect
+      return 203;
+    case 285:  // __NR_copy_file_range
+      return 285;
+    case 106:  // __NR_delete_module
+      return 106;
+    case 23:  // __NR_dup
+      return 23;
+    case 24:  // __NR_dup3
+      return 24;
+    case 20:  // __NR_epoll_create1
+      return 20;
+    case 21:  // __NR_epoll_ctl
+      return 21;
+    case 22:  // __NR_epoll_pwait
+      return 22;
+    case 441:  // __NR_epoll_pwait2
+      return 441;
+    case 19:  // __NR_eventfd2
+      return 19;
+    case 221:  // __NR_execve
+      return 221;
+    case 281:  // __NR_execveat
+      return 281;
+    case 93:  // __NR_exit
+      return 93;
+    case 94:  // __NR_exit_group
+      return 94;
+    case 48:  // __NR_faccessat
+      return 48;
+    case 439:  // __NR_faccessat2
+      return 439;
+    case 223:  // __NR_fadvise64
+      return 223;
+    case 47:  // __NR_fallocate
+      return 47;
+    case 262:  // __NR_fanotify_init
+      return 262;
+    case 263:  // __NR_fanotify_mark
+      return 263;
+    case 50:  // __NR_fchdir
+      return 50;
+    case 52:  // __NR_fchmod
+      return 52;
+    case 53:  // __NR_fchmodat
+      return 53;
+    case 55:  // __NR_fchown
+      return 55;
+    case 54:  // __NR_fchownat
+      return 54;
+    case 25:  // __NR_fcntl
+      return 25;
+    case 83:  // __NR_fdatasync
+      return 83;
+    case 10:  // __NR_fgetxattr
+      return 10;
+    case 273:  // __NR_finit_module
+      return 273;
+    case 13:  // __NR_flistxattr
+      return 13;
+    case 32:  // __NR_flock
+      return 32;
+    case 16:  // __NR_fremovexattr
+      return 16;
+    case 431:  // __NR_fsconfig
+      return 431;
+    case 7:  // __NR_fsetxattr
+      return 7;
+    case 432:  // __NR_fsmount
+      return 432;
+    case 430:  // __NR_fsopen
+      return 430;
+    case 433:  // __NR_fspick
+      return 433;
+    case 80:  // __NR_fstat
+      return 80;
+    case 44:  // __NR_fstatfs
+      return 44;
+    case 82:  // __NR_fsync
+      return 82;
+    case 46:  // __NR_ftruncate
+      return 46;
+    case 98:  // __NR_futex
+      return 98;
+    case 449:  // __NR_futex_waitv
+      return 449;
+    case 236:  // __NR_get_mempolicy
+      return 236;
+    case 100:  // __NR_get_robust_list
+      return 100;
+    case 168:  // __NR_getcpu
+      return 168;
+    case 17:  // __NR_getcwd
+      return 17;
+    case 61:  // __NR_getdents64
+      return 61;
+    case 177:  // __NR_getegid
+      return 177;
+    case 175:  // __NR_geteuid
+      return 175;
+    case 176:  // __NR_getgid
+      return 176;
+    case 158:  // __NR_getgroups
+      return 158;
+    case 102:  // __NR_getitimer
+      return 102;
+    case 205:  // __NR_getpeername
+      return 205;
+    case 155:  // __NR_getpgid
+      return 155;
+    case 172:  // __NR_getpid
+      return 172;
+    case 173:  // __NR_getppid
+      return 173;
+    case 141:  // __NR_getpriority
+      return 141;
+    case 278:  // __NR_getrandom
+      return 278;
+    case 150:  // __NR_getresgid
+      return 150;
+    case 148:  // __NR_getresuid
+      return 148;
+    case 163:  // __NR_getrlimit
+      return 163;
+    case 165:  // __NR_getrusage
+      return 165;
+    case 156:  // __NR_getsid
+      return 156;
+    case 204:  // __NR_getsockname
+      return 204;
+    case 209:  // __NR_getsockopt
+      return 209;
+    case 178:  // __NR_gettid
+      return 178;
+    case 169:  // __NR_gettimeofday
+      return 169;
+    case 174:  // __NR_getuid
+      return 174;
+    case 8:  // __NR_getxattr
+      return 8;
+    case 105:  // __NR_init_module
+      return 105;
+    case 27:  // __NR_inotify_add_watch
+      return 27;
+    case 26:  // __NR_inotify_init1
+      return 26;
+    case 28:  // __NR_inotify_rm_watch
+      return 28;
+    case 3:  // __NR_io_cancel
+      return 3;
+    case 1:  // __NR_io_destroy
+      return 1;
+    case 4:  // __NR_io_getevents
+      return 4;
+    case 292:  // __NR_io_pgetevents
+      return 292;
+    case 0:  // __NR_io_setup
+      return 0;
+    case 2:  // __NR_io_submit
+      return 2;
+    case 426:  // __NR_io_uring_enter
+      return 426;
+    case 427:  // __NR_io_uring_register
+      return 427;
+    case 425:  // __NR_io_uring_setup
+      return 425;
+    case 29:  // __NR_ioctl
+      return 29;
+    case 31:  // __NR_ioprio_get
+      return 31;
+    case 30:  // __NR_ioprio_set
+      return 30;
+    case 272:  // __NR_kcmp
+      return 272;
+    case 294:  // __NR_kexec_file_load
+      return 294;
+    case 104:  // __NR_kexec_load
+      return 104;
+    case 219:  // __NR_keyctl
+      return 219;
+    case 129:  // __NR_kill
+      return 129;
+    case 445:  // __NR_landlock_add_rule
+      return 445;
+    case 444:  // __NR_landlock_create_ruleset
+      return 444;
+    case 446:  // __NR_landlock_restrict_self
+      return 446;
+    case 9:  // __NR_lgetxattr
+      return 9;
+    case 37:  // __NR_linkat
+      return 37;
+    case 201:  // __NR_listen
+      return 201;
+    case 11:  // __NR_listxattr
+      return 11;
+    case 12:  // __NR_llistxattr
+      return 12;
+    case 18:  // __NR_lookup_dcookie
+      return 18;
+    case 15:  // __NR_lremovexattr
+      return 15;
+    case 62:  // __NR_lseek
+      return 62;
+    case 6:  // __NR_lsetxattr
+      return 6;
+    case 233:  // __NR_madvise
+      return 233;
+    case 235:  // __NR_mbind
+      return 235;
+    case 283:  // __NR_membarrier
+      return 283;
+    case 279:  // __NR_memfd_create
+      return 279;
+    case 447:  // __NR_memfd_secret
+      return 447;
+    case 238:  // __NR_migrate_pages
+      return 238;
+    case 232:  // __NR_mincore
+      return 232;
+    case 34:  // __NR_mkdirat
+      return 34;
+    case 33:  // __NR_mknodat
+      return 33;
+    case 228:  // __NR_mlock
+      return 228;
+    case 284:  // __NR_mlock2
+      return 284;
+    case 230:  // __NR_mlockall
+      return 230;
+    case 222:  // __NR_mmap
+      return 222;
+    case 40:  // __NR_mount
+      return 40;
+    case 442:  // __NR_mount_setattr
+      return 442;
+    case 429:  // __NR_move_mount
+      return 429;
+    case 239:  // __NR_move_pages
+      return 239;
+    case 226:  // __NR_mprotect
+      return 226;
+    case 185:  // __NR_mq_getsetattr
+      return 185;
+    case 184:  // __NR_mq_notify
+      return 184;
+    case 180:  // __NR_mq_open
+      return 180;
+    case 183:  // __NR_mq_timedreceive
+      return 183;
+    case 182:  // __NR_mq_timedsend
+      return 182;
+    case 181:  // __NR_mq_unlink
+      return 181;
+    case 216:  // __NR_mremap
+      return 216;
+    case 187:  // __NR_msgctl
+      return 187;
+    case 186:  // __NR_msgget
+      return 186;
+    case 188:  // __NR_msgrcv
+      return 188;
+    case 189:  // __NR_msgsnd
+      return 189;
+    case 227:  // __NR_msync
+      return 227;
+    case 229:  // __NR_munlock
+      return 229;
+    case 231:  // __NR_munlockall
+      return 231;
+    case 215:  // __NR_munmap
+      return 215;
+    case 264:  // __NR_name_to_handle_at
+      return 264;
+    case 101:  // __NR_nanosleep
+      return 101;
+    case 79:  // __NR_newfstatat
+      return 79;
+    case 42:  // __NR_nfsservctl
+      return 42;
+    case 265:  // __NR_open_by_handle_at
+      return 265;
+    case 428:  // __NR_open_tree
+      return 428;
+    case 56:  // __NR_openat
+      return 56;
+    case 437:  // __NR_openat2
+      return 437;
+    case 241:  // __NR_perf_event_open
+      return 241;
+    case 92:  // __NR_personality
+      return 92;
+    case 438:  // __NR_pidfd_getfd
+      return 438;
+    case 434:  // __NR_pidfd_open
+      return 434;
+    case 424:  // __NR_pidfd_send_signal
+      return 424;
+    case 59:  // __NR_pipe2
+      return 59;
+    case 41:  // __NR_pivot_root
+      return 41;
+    case 289:  // __NR_pkey_alloc
+      return 289;
+    case 290:  // __NR_pkey_free
+      return 290;
+    case 288:  // __NR_pkey_mprotect
+      return 288;
+    case 73:  // __NR_ppoll
+      return 73;
+    case 167:  // __NR_prctl
+      return 167;
+    case 67:  // __NR_pread64
+      return 67;
+    case 69:  // __NR_preadv
+      return 69;
+    case 286:  // __NR_preadv2
+      return 286;
+    case 261:  // __NR_prlimit64
+      return 261;
+    case 440:  // __NR_process_madvise
+      return 440;
+    case 448:  // __NR_process_mrelease
+      return 448;
+    case 270:  // __NR_process_vm_readv
+      return 270;
+    case 271:  // __NR_process_vm_writev
+      return 271;
+    case 72:  // __NR_pselect6
+      return 72;
+    case 117:  // __NR_ptrace
+      return 117;
+    case 68:  // __NR_pwrite64
+      return 68;
+    case 70:  // __NR_pwritev
+      return 70;
+    case 287:  // __NR_pwritev2
+      return 287;
+    case 60:  // __NR_quotactl
+      return 60;
+    case 443:  // __NR_quotactl_fd
+      return 443;
+    case 63:  // __NR_read
+      return 63;
+    case 213:  // __NR_readahead
+      return 213;
+    case 78:  // __NR_readlinkat
+      return 78;
+    case 65:  // __NR_readv
+      return 65;
+    case 142:  // __NR_reboot
+      return 142;
+    case 207:  // __NR_recvfrom
+      return 207;
+    case 243:  // __NR_recvmmsg
+      return 243;
+    case 212:  // __NR_recvmsg
+      return 212;
+    case 234:  // __NR_remap_file_pages
+      return 234;
+    case 14:  // __NR_removexattr
+      return 14;
+    case 38:  // __NR_renameat
+      return 38;
+    case 276:  // __NR_renameat2
+      return 276;
+    case 218:  // __NR_request_key
+      return 218;
+    case 128:  // __NR_restart_syscall
+      return 128;
+    case 293:  // __NR_rseq
+      return 293;
+    case 134:  // __NR_rt_sigaction
+      return 134;
+    case 136:  // __NR_rt_sigpending
+      return 136;
+    case 135:  // __NR_rt_sigprocmask
+      return 135;
+    case 138:  // __NR_rt_sigqueueinfo
+      return 138;
+    case 139:  // __NR_rt_sigreturn
+      return 139;
+    case 133:  // __NR_rt_sigsuspend
+      return 133;
+    case 137:  // __NR_rt_sigtimedwait
+      return 137;
+    case 240:  // __NR_rt_tgsigqueueinfo
+      return 240;
+    case 125:  // __NR_sched_get_priority_max
+      return 125;
+    case 126:  // __NR_sched_get_priority_min
+      return 126;
+    case 123:  // __NR_sched_getaffinity
+      return 123;
+    case 275:  // __NR_sched_getattr
+      return 275;
+    case 121:  // __NR_sched_getparam
+      return 121;
+    case 120:  // __NR_sched_getscheduler
+      return 120;
+    case 127:  // __NR_sched_rr_get_interval
+      return 127;
+    case 122:  // __NR_sched_setaffinity
+      return 122;
+    case 274:  // __NR_sched_setattr
+      return 274;
+    case 118:  // __NR_sched_setparam
+      return 118;
+    case 119:  // __NR_sched_setscheduler
+      return 119;
+    case 124:  // __NR_sched_yield
+      return 124;
+    case 277:  // __NR_seccomp
+      return 277;
+    case 191:  // __NR_semctl
+      return 191;
+    case 190:  // __NR_semget
+      return 190;
+    case 193:  // __NR_semop
+      return 193;
+    case 192:  // __NR_semtimedop
+      return 192;
+    case 71:  // __NR_sendfile
+      return 71;
+    case 269:  // __NR_sendmmsg
+      return 269;
+    case 211:  // __NR_sendmsg
+      return 211;
+    case 206:  // __NR_sendto
+      return 206;
+    case 237:  // __NR_set_mempolicy
+      return 237;
+    case 450:  // __NR_set_mempolicy_home_node
+      return 450;
+    case 99:  // __NR_set_robust_list
+      return 99;
+    case 96:  // __NR_set_tid_address
+      return 96;
+    case 162:  // __NR_setdomainname
+      return 162;
+    case 152:  // __NR_setfsgid
+      return 152;
+    case 151:  // __NR_setfsuid
+      return 151;
+    case 144:  // __NR_setgid
+      return 144;
+    case 159:  // __NR_setgroups
+      return 159;
+    case 161:  // __NR_sethostname
+      return 161;
+    case 103:  // __NR_setitimer
+      return 103;
+    case 268:  // __NR_setns
+      return 268;
+    case 154:  // __NR_setpgid
+      return 154;
+    case 140:  // __NR_setpriority
+      return 140;
+    case 143:  // __NR_setregid
+      return 143;
+    case 149:  // __NR_setresgid
+      return 149;
+    case 147:  // __NR_setresuid
+      return 147;
+    case 145:  // __NR_setreuid
+      return 145;
+    case 164:  // __NR_setrlimit
+      return 164;
+    case 157:  // __NR_setsid
+      return 157;
+    case 208:  // __NR_setsockopt
+      return 208;
+    case 170:  // __NR_settimeofday
+      return 170;
+    case 146:  // __NR_setuid
+      return 146;
+    case 5:  // __NR_setxattr
+      return 5;
+    case 196:  // __NR_shmat
+      return 196;
+    case 195:  // __NR_shmctl
+      return 195;
+    case 197:  // __NR_shmdt
+      return 197;
+    case 194:  // __NR_shmget
+      return 194;
+    case 210:  // __NR_shutdown
+      return 210;
+    case 132:  // __NR_sigaltstack
+      return 132;
+    case 74:  // __NR_signalfd4
+      return 74;
+    case 198:  // __NR_socket
+      return 198;
+    case 199:  // __NR_socketpair
+      return 199;
+    case 76:  // __NR_splice
+      return 76;
+    case 43:  // __NR_statfs
+      return 43;
+    case 291:  // __NR_statx
+      return 291;
+    case 225:  // __NR_swapoff
+      return 225;
+    case 224:  // __NR_swapon
+      return 224;
+    case 36:  // __NR_symlinkat
+      return 36;
+    case 81:  // __NR_sync
+      return 81;
+    case 84:  // __NR_sync_file_range
+      return 84;
+    case 267:  // __NR_syncfs
+      return 267;
+    case 179:  // __NR_sysinfo
+      return 179;
+    case 116:  // __NR_syslog
+      return 116;
+    case 77:  // __NR_tee
+      return 77;
+    case 131:  // __NR_tgkill
+      return 131;
+    case 107:  // __NR_timer_create
+      return 107;
+    case 111:  // __NR_timer_delete
+      return 111;
+    case 109:  // __NR_timer_getoverrun
+      return 109;
+    case 108:  // __NR_timer_gettime
+      return 108;
+    case 110:  // __NR_timer_settime
+      return 110;
+    case 85:  // __NR_timerfd_create
+      return 85;
+    case 87:  // __NR_timerfd_gettime
+      return 87;
+    case 86:  // __NR_timerfd_settime
+      return 86;
+    case 153:  // __NR_times
+      return 153;
+    case 130:  // __NR_tkill
+      return 130;
+    case 45:  // __NR_truncate
+      return 45;
+    case 166:  // __NR_umask
+      return 166;
+    case 39:  // __NR_umount2
+      return 39;
+    case 160:  // __NR_uname
+      return 160;
+    case 35:  // __NR_unlinkat
+      return 35;
+    case 97:  // __NR_unshare
+      return 97;
+    case 282:  // __NR_userfaultfd
+      return 282;
+    case 88:  // __NR_utimensat
+      return 88;
+    case 58:  // __NR_vhangup
+      return 58;
+    case 75:  // __NR_vmsplice
+      return 75;
+    case 260:  // __NR_wait4
+      return 260;
+    case 95:  // __NR_waitid
+      return 95;
+    case 64:  // __NR_write
+      return 64;
+    case 66:  // __NR_writev
+      return 66;
+    default:
+      return -1;
+  }
+}
+
+}  // namespace berberis
diff --git a/guest_os_primitives/riscv64/gen_syscall_numbers.cc b/guest_os_primitives/riscv64/gen_syscall_numbers_x86_64.cc
similarity index 100%
rename from guest_os_primitives/riscv64/gen_syscall_numbers.cc
rename to guest_os_primitives/riscv64/gen_syscall_numbers_x86_64.cc
diff --git a/guest_os_primitives/unmap_and_exit_arm64.S b/guest_os_primitives/unmap_and_exit_arm64.S
new file mode 100644
index 00000000..f808796c
--- /dev/null
+++ b/guest_os_primitives/unmap_and_exit_arm64.S
@@ -0,0 +1,32 @@
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
+#include <linux/unistd.h>
+
+    .globl berberis_UnmapAndExit
+    .balign 16
+
+berberis_UnmapAndExit:
+
+    mov x8, #__NR_munmap
+    svc #0
+
+    mov x0, x2
+
+    mov x8, #__NR_exit
+    svc #0
+
+    ret
diff --git a/guest_os_primitives/unmap_and_exit_riscv64.cc b/guest_os_primitives/unmap_and_exit_riscv64.cc
new file mode 100644
index 00000000..26d1631a
--- /dev/null
+++ b/guest_os_primitives/unmap_and_exit_riscv64.cc
@@ -0,0 +1,32 @@
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
+#include <linux/unistd.h>
+
+#include <cstddef>
+
+extern "C" [[gnu::naked]] [[gnu::noinline]] void berberis_UnmapAndExit(void* /*ptr*/,
+                                                                       size_t /*size*/,
+                                                                       int /*status*/) {
+  asm("li a7, %0\n"
+      "ecall\n"
+      "mv a0, a1\n"
+      "li a7, %1\n"
+      "ecall\n"
+      "ret\n"
+      :
+      : "i"(__NR_munmap), "i"(__NR_exit));
+}
diff --git a/guest_state/arm64/include/berberis/guest_state/guest_state_arch.h b/guest_state/arm64/include/berberis/guest_state/guest_state_arch.h
index 13dc34f7..dea26670 100644
--- a/guest_state/arm64/include/berberis/guest_state/guest_state_arch.h
+++ b/guest_state/arm64/include/berberis/guest_state/guest_state_arch.h
@@ -53,8 +53,10 @@ struct ThreadState {
   void* thread_state_storage;
 };
 
-constexpr unsigned kNumGuestRegs = std::size(CPUState{}.x);
+inline constexpr unsigned kNumGuestRegs = std::size(CPUState{}.x);
+inline constexpr unsigned kNumGuestSimdRegs = std::size(CPUState{}.v);
 
+inline constexpr unsigned kGuestCacheLineSize = 64;
 }  // namespace berberis
 
 #endif  // BERBERIS_GUEST_STATE_GUEST_STATE_ARCH_H_
diff --git a/heavy_optimizer/riscv64/inline_intrinsic.h b/heavy_optimizer/riscv64/inline_intrinsic.h
index c7612550..e8d6980f 100644
--- a/heavy_optimizer/riscv64/inline_intrinsic.h
+++ b/heavy_optimizer/riscv64/inline_intrinsic.h
@@ -323,11 +323,8 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
                              bool> = true>
   std::optional<bool> /*ProcessBindingsClient*/ operator()(AsmCallInfo asm_call_info) {
     static_assert(std::is_same_v<decltype(kFunction), typename AsmCallInfo::IntrinsicType>);
-    if constexpr (!std::is_same_v<typename AsmCallInfo::PreciseNanOperationsHandling,
-                                  intrinsics::bindings::NoNansOperation>) {
-      return false;
-    }
-
+    static_assert(std::is_same_v<typename AsmCallInfo::PreciseNanOperationsHandling,
+                                 intrinsics::bindings::NoNansOperation>);
     using CPUIDRestriction = AsmCallInfo::CPUIDRestriction;
     if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX>) {
       if (!host_platform::kHasAVX) {
diff --git a/interpreter/Android.bp b/interpreter/Android.bp
index a51d4552..469e7da1 100644
--- a/interpreter/Android.bp
+++ b/interpreter/Android.bp
@@ -102,6 +102,7 @@ cc_test {
         "libberberis_interpreter_riscv64",
         "libberberis_kernel_api_riscv64",
         "liblog",
+        "libberberis_intrinsics_riscv64",
     ],
     srcs: [
         "riscv64/faulty_memory_accesses_test.cc",
diff --git a/interpreter/riscv64/interpreter-main.cc b/interpreter/riscv64/interpreter-main.cc
index 4ba8d31b..4f482502 100644
--- a/interpreter/riscv64/interpreter-main.cc
+++ b/interpreter/riscv64/interpreter-main.cc
@@ -22,11 +22,7 @@
 #include "berberis/guest_state/guest_state.h"
 
 #include "../faulty_memory_accesses.h"
-#if defined(__x86_64__)
 #include "interpreter.h"
-#elif defined(__aarch64__)
-#include "interpreter_arm64.h"
-#endif
 
 namespace berberis {
 
diff --git a/interpreter/riscv64/interpreter.h b/interpreter/riscv64/interpreter.h
index aaad543b..32961743 100644
--- a/interpreter/riscv64/interpreter.h
+++ b/interpreter/riscv64/interpreter.h
@@ -30,14 +30,17 @@
 #include "berberis/guest_state/guest_state.h"
 #include "berberis/intrinsics/guest_cpu_flags.h"  // ToHostRoundingMode
 #include "berberis/intrinsics/intrinsics.h"
-#include "berberis/intrinsics/intrinsics_float.h"
 #include "berberis/intrinsics/riscv64_to_all/vector_intrinsics.h"
 #include "berberis/intrinsics/simd_register.h"
 #include "berberis/intrinsics/type_traits.h"
 #include "berberis/kernel_api/run_guest_syscall.h"
-#include "berberis/runtime_primitives/interpret_helpers.h"
 #include "berberis/runtime_primitives/memory_region_reservation.h"
+
+#if !defined(__aarch64__)
+#include "berberis/intrinsics/intrinsics_float.h"
+#include "berberis/runtime_primitives/interpret_helpers.h"
 #include "berberis/runtime_primitives/recovery_code.h"
+#endif
 
 #include "regs.h"
 
@@ -93,6 +96,36 @@ class Interpreter {
     return UpdateCsr(static_cast<Decoder::CsrOpcode>(opcode), imm, csr);
   }
 
+#if defined(__aarch64__)
+  void Fence(Decoder::FenceOpcode /*opcode*/,
+             Register /*src*/,
+             bool sw,
+             bool sr,
+             bool /*so*/,
+             bool /*si*/,
+             bool pw,
+             bool pr,
+             bool /*po*/,
+             bool /*pi*/) {
+    bool read_fence = sr | pr;
+    bool write_fence = sw | pw;
+    // "ish" is for inner shareable access, which is normally needed by userspace programs.
+    if (read_fence) {
+      if (write_fence) {
+        // This is equivalent to "fence rw,rw".
+        asm volatile("dmb ish" ::: "memory");
+      } else {
+        // "ishld" is equivalent to "fence r,rw", which is stronger than what we need here
+        // ("fence r,r"). However, it is the closet option that ARM offers.
+        asm volatile("dmb ishld" ::: "memory");
+      }
+    } else if (write_fence) {
+      // "st" is equivalent to "fence w,w".
+      asm volatile("dmb ishst" ::: "memory");
+    }
+    return;
+  }
+#else
   // Note: we prefer not to use C11/C++ atomic_thread_fence or even gcc/clang builtin
   // __atomic_thread_fence because all these function rely on the fact that compiler never uses
   // non-temporal loads and stores and only issue “mfence” when sequentially consistent ordering is
@@ -132,6 +165,7 @@ class Interpreter {
     }
     return;
   }
+#endif
 
   template <typename IntType, bool aq, bool rl>
   Register Lr(int64_t addr) {
@@ -176,6 +210,7 @@ class Interpreter {
         return Int64(arg1) < Int64(arg2) ? 1 : 0;
       case Decoder::OpOpcode::kSltu:
         return UInt64(arg1) < UInt64(arg2) ? 1 : 0;
+#if !defined(__aarch64__)
       case Decoder::OpOpcode::kMul:
         return Int64(arg1) * Int64(arg2);
       case Decoder::OpOpcode::kMulh:
@@ -184,6 +219,7 @@ class Interpreter {
         return NarrowTopHalf(Widen(Int64(arg1)) * BitCastToSigned(Widen(UInt64(arg2))));
       case Decoder::OpOpcode::kMulhu:
         return NarrowTopHalf(Widen(UInt64(arg1)) * Widen(UInt64(arg2)));
+#endif
       case Decoder::OpOpcode::kAndn:
         return Int64(arg1) & (~Int64(arg2));
       case Decoder::OpOpcode::kOrn:
@@ -197,6 +233,11 @@ class Interpreter {
   }
 
   Register Op32(Decoder::Op32Opcode opcode, Register arg1, Register arg2) {
+#if defined(__aarch64__)
+    UNUSED(opcode, arg1, arg2);
+    Undefined();
+    return {};
+#else
     switch (opcode) {
       case Decoder::Op32Opcode::kAddw:
         return Widen(TruncateTo<Int32>(arg1) + TruncateTo<Int32>(arg2));
@@ -214,6 +255,7 @@ class Interpreter {
         Undefined();
         return {};
     }
+#endif
   }
 
   Register Load(Decoder::LoadOperandType operand_type, Register arg, int16_t offset) {
@@ -241,6 +283,11 @@ class Interpreter {
 
   template <typename DataType>
   FpRegister LoadFp(Register arg, int16_t offset) {
+#if defined(__aarch64__)
+    UNUSED(arg, offset);
+    Undefined();
+    return {};
+#else
     static_assert(std::is_same_v<DataType, Float32> || std::is_same_v<DataType, Float64>);
     CHECK(!exception_raised_);
     DataType* ptr = ToHostAddr<DataType>(arg + offset);
@@ -250,6 +297,7 @@ class Interpreter {
       return {};
     }
     return result.value;
+#endif
   }
 
   Register OpImm(Decoder::OpImmOpcode opcode, Register arg, int16_t imm) {
@@ -280,6 +328,11 @@ class Interpreter {
   }
 
   Register OpImm32(Decoder::OpImm32Opcode opcode, Register arg, int16_t imm) {
+#if defined(__aarch64__)
+    UNUSED(opcode, arg, imm);
+    Undefined();
+    return {};
+#else
     switch (opcode) {
       case Decoder::OpImm32Opcode::kAddiw:
         return int32_t(arg) + int32_t{imm};
@@ -287,6 +340,7 @@ class Interpreter {
         Undefined();
         return {};
     }
+#endif
   }
 
   // TODO(b/232598137): rework ecall to not take parameters explicitly.
@@ -309,6 +363,11 @@ class Interpreter {
   Register Srai(Register arg, int8_t imm) { return bit_cast<int64_t>(arg) >> imm; }
 
   Register ShiftImm32(Decoder::ShiftImm32Opcode opcode, Register arg, uint16_t imm) {
+#if defined(__aarch64__)
+    UNUSED(opcode, arg, imm);
+    Undefined();
+    return {};
+#else
     switch (opcode) {
       case Decoder::ShiftImm32Opcode::kSlliw:
         return int32_t(arg) << int32_t{imm};
@@ -320,6 +379,7 @@ class Interpreter {
         Undefined();
         return {};
     }
+#endif
   }
 
   Register Rori(Register arg, int8_t shamt) {
@@ -328,8 +388,14 @@ class Interpreter {
   }
 
   Register Roriw(Register arg, int8_t shamt) {
+#if defined(__aarch64__)
+    UNUSED(arg, shamt);
+    Undefined();
+    return {};
+#else
     CheckShamt32IsValid(shamt);
     return int32_t(((uint32_t(arg) >> shamt)) | (uint32_t(arg) << (32 - shamt)));
+#endif
   }
 
   void Store(Decoder::MemoryDataOperandType operand_type,
@@ -357,10 +423,15 @@ class Interpreter {
 
   template <typename DataType>
   void StoreFp(Register arg, int16_t offset, FpRegister data) {
+#if defined(__aarch64__)
+    UNUSED(arg, offset, data);
+    Undefined();
+#else
     static_assert(std::is_same_v<DataType, Float32> || std::is_same_v<DataType, Float64>);
     CHECK(!exception_raised_);
     DataType* ptr = ToHostAddr<DataType>(arg + offset);
     exception_raised_ = FaultyStore(ptr, sizeof(DataType), data);
+#endif
   }
 
   void CompareAndBranch(Decoder::BranchOpcode opcode,
@@ -4294,11 +4365,15 @@ class Interpreter {
   void Nop() {}
 
   void Undefined() {
+#if defined(__aarch64__)
+    abort();
+#else
     UndefinedInsn(GetInsnAddr());
     // If there is a guest handler registered for SIGILL we'll delay its processing until the next
     // sync point (likely the main dispatching loop) due to enabled pending signals. Thus we must
     // ensure that insn_addr isn't automatically advanced in FinalizeInsn.
     exception_raised_ = true;
+#endif
   }
 
   //
@@ -4342,17 +4417,30 @@ class Interpreter {
   // Various helper methods.
   //
 
+#if defined(__aarch64__)
+  template <CsrName kName>
+  [[nodiscard]] Register GetCsr() {
+    Undefined();
+    return {};
+  }
+#else
   template <CsrName kName>
   [[nodiscard]] Register GetCsr() const {
     return state_->cpu.*CsrFieldAddr<kName>;
   }
+#endif
 
   template <CsrName kName>
   void SetCsr(Register arg) {
+#if defined(__aarch64__)
+    UNUSED(arg);
+    Undefined();
+#else
     if (exception_raised_) {
       return;
     }
     state_->cpu.*CsrFieldAddr<kName> = arg & kCsrMask<kName>;
+#endif
   }
 
   [[nodiscard]] uint64_t GetImm(uint64_t imm) const { return imm; }
@@ -4620,6 +4708,7 @@ class Interpreter {
   bool exception_raised_;
 };
 
+#if !defined(__aarch64__)
 template <>
 [[nodiscard]] Interpreter::Register inline Interpreter::GetCsr<CsrName::kCycle>() const {
   return CPUClockCount();
@@ -4687,19 +4776,33 @@ void inline Interpreter::SetCsr<CsrName::kVxsat>(Register arg) {
       (state_->cpu.*CsrFieldAddr<CsrName::kVcsr> & 0b11) | ((arg & 0b1) << 2);
 }
 
+#endif
+
 template <>
 [[nodiscard]] Interpreter::FpRegister inline Interpreter::GetFRegAndUnboxNan<Interpreter::Float32>(
     uint8_t reg) {
+#if defined(__aarch64__)
+  UNUSED(reg);
+  Interpreter::Undefined();
+  return {};
+#else
   CheckFpRegIsValid(reg);
   FpRegister value = state_->cpu.f[reg];
   return UnboxNan<Float32>(value);
+#endif
 }
 
 template <>
 [[nodiscard]] Interpreter::FpRegister inline Interpreter::GetFRegAndUnboxNan<Interpreter::Float64>(
     uint8_t reg) {
+#if defined(__aarch64__)
+  UNUSED(reg);
+  Interpreter::Undefined();
+  return {};
+#else
   CheckFpRegIsValid(reg);
   return state_->cpu.f[reg];
+#endif
 }
 
 template <>
diff --git a/interpreter/riscv64/interpreter_arm64.h b/interpreter/riscv64/interpreter_arm64.h
deleted file mode 100644
index 32cc56d9..00000000
--- a/interpreter/riscv64/interpreter_arm64.h
+++ /dev/null
@@ -1,665 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file excenaupt in compliance with the License.
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
-#include "berberis/interpreter/riscv64/interpreter.h"
-
-#include <atomic>
-#include <cstdint>
-#include <cstdlib>
-
-#include "berberis/base/bit_util.h"
-#include "berberis/decoder/riscv64/decoder.h"
-#include "berberis/decoder/riscv64/semantics_player.h"
-#include "berberis/guest_state/guest_addr.h"
-#include "berberis/intrinsics/riscv64_to_all/intrinsics.h"
-#include "berberis/kernel_api/run_guest_syscall.h"
-#include "berberis/runtime_primitives/memory_region_reservation.h"
-
-#include "regs.h"
-
-#include "../faulty_memory_accesses.h"
-
-namespace berberis {
-
-inline constexpr std::memory_order AqRlToStdMemoryOrder(bool aq, bool rl) {
-  if (aq) {
-    return rl ? std::memory_order_acq_rel : std::memory_order_acquire;
-  } else {
-    return rl ? std::memory_order_release : std::memory_order_relaxed;
-  }
-}
-
-class Interpreter {
- public:
-  using CsrName = berberis::CsrName;
-  using Decoder = Decoder<SemanticsPlayer<Interpreter>>;
-  using Register = uint64_t;
-  static constexpr Register no_register = 0;
-  using FpRegister = uint64_t;
-  static constexpr FpRegister no_fp_register = 0;
-  using Float32 = float;
-  using Float64 = double;
-
-  explicit Interpreter(ThreadState* state)
-      : state_(state), branch_taken_(false), exception_raised_(false) {}
-
-  //
-  // Instruction implementations.
-  //
-
-  Register UpdateCsr(Decoder::CsrOpcode opcode, Register arg, Register csr) {
-    UNUSED(opcode, arg, csr);
-    Undefined();
-    return {};
-  }
-
-  Register UpdateCsr(Decoder::CsrImmOpcode opcode, uint8_t imm, Register csr) {
-    UNUSED(opcode, imm, csr);
-    Undefined();
-    return {};
-  }
-
-  void Fence(Decoder::FenceOpcode /*opcode*/,
-             Register /*src*/,
-             bool sw,
-             bool sr,
-             bool /*so*/,
-             bool /*si*/,
-             bool pw,
-             bool pr,
-             bool /*po*/,
-             bool /*pi*/) {
-    bool read_fence = sr | pr;
-    bool write_fence = sw | pw;
-    // "ish" is for inner shareable access, which is normally needed by userspace programs.
-    if (read_fence) {
-      if (write_fence) {
-        // This is equivalent to "fence rw,rw".
-        asm volatile("dmb ish" ::: "memory");
-      } else {
-        // "ishld" is equivalent to "fence r,rw", which is stronger than what we need here
-        // ("fence r,r"). However, it is the closet option that ARM offers.
-        asm volatile("dmb ishld" ::: "memory");
-      }
-    } else if (write_fence) {
-      // "st" is equivalent to "fence w,w".
-      asm volatile("dmb ishst" ::: "memory");
-    }
-    return;
-  }
-
-  template <typename IntType, bool aq, bool rl>
-  Register Lr(int64_t addr) {
-    // TODO(b/358214671): use more efficient way for MemoryRegionReservation.
-    static_assert(std::is_integral_v<IntType>, "Lr: IntType must be integral");
-    static_assert(std::is_signed_v<IntType>, "Lr: IntType must be signed");
-    CHECK(!exception_raised_);
-    // Address must be aligned on size of IntType.
-    CHECK((addr % sizeof(IntType)) == 0ULL);
-    return MemoryRegionReservation::Load<IntType>(&state_->cpu, addr, AqRlToStdMemoryOrder(aq, rl));
-  }
-
-  template <typename IntType, bool aq, bool rl>
-  Register Sc(int64_t addr, IntType val) {
-    // TODO(b/358214671): use more efficient way for MemoryRegionReservation.
-    static_assert(std::is_integral_v<IntType>, "Sc: IntType must be integral");
-    static_assert(std::is_signed_v<IntType>, "Sc: IntType must be signed");
-    CHECK(!exception_raised_);
-    // Address must be aligned on size of IntType.
-    CHECK((addr % sizeof(IntType)) == 0ULL);
-    return static_cast<Register>(MemoryRegionReservation::Store<IntType>(
-        &state_->cpu, addr, val, AqRlToStdMemoryOrder(aq, rl)));
-  }
-
-  Register Op(Decoder::OpOpcode opcode, Register arg1, Register arg2) {
-    switch (opcode) {
-      case Decoder::OpOpcode::kAdd:
-        return Int64(arg1) + Int64(arg2);
-      case Decoder::OpOpcode::kSub:
-        return Int64(arg1) - Int64(arg2);
-      case Decoder::OpOpcode::kAnd:
-        return Int64(arg1) & Int64(arg2);
-      case Decoder::OpOpcode::kOr:
-        return Int64(arg1) | Int64(arg2);
-      case Decoder::OpOpcode::kXor:
-        return Int64(arg1) ^ Int64(arg2);
-      case Decoder::OpOpcode::kSll:
-        return Int64(arg1) << Int64(arg2);
-      case Decoder::OpOpcode::kSrl:
-        return UInt64(arg1) >> Int64(arg2);
-      case Decoder::OpOpcode::kSra:
-        return Int64(arg1) >> Int64(arg2);
-      case Decoder::OpOpcode::kSlt:
-        return Int64(arg1) < Int64(arg2) ? 1 : 0;
-      case Decoder::OpOpcode::kSltu:
-        return UInt64(arg1) < UInt64(arg2) ? 1 : 0;
-      case Decoder::OpOpcode::kAndn:
-        return Int64(arg1) & (~Int64(arg2));
-      case Decoder::OpOpcode::kOrn:
-        return Int64(arg1) | (~Int64(arg2));
-      case Decoder::OpOpcode::kXnor:
-        return ~(Int64(arg1) ^ Int64(arg2));
-      default:
-        Undefined();
-        return {};
-    }
-  }
-
-  Register Op32(Decoder::Op32Opcode opcode, Register arg1, Register arg2) {
-    UNUSED(opcode, arg1, arg2);
-    Undefined();
-    return {};
-  }
-
-  Register Load(Decoder::LoadOperandType operand_type, Register arg, int16_t offset) {
-    void* ptr = ToHostAddr<void>(arg + offset);
-    switch (operand_type) {
-      case Decoder::LoadOperandType::k8bitUnsigned:
-        return Load<uint8_t>(ptr);
-      case Decoder::LoadOperandType::k16bitUnsigned:
-        return Load<uint16_t>(ptr);
-      case Decoder::LoadOperandType::k32bitUnsigned:
-        return Load<uint32_t>(ptr);
-      case Decoder::LoadOperandType::k64bit:
-        return Load<uint64_t>(ptr);
-      case Decoder::LoadOperandType::k8bitSigned:
-        return Load<int8_t>(ptr);
-      case Decoder::LoadOperandType::k16bitSigned:
-        return Load<int16_t>(ptr);
-      case Decoder::LoadOperandType::k32bitSigned:
-        return Load<int32_t>(ptr);
-      default:
-        Undefined();
-        return {};
-    }
-  }
-
-  template <typename DataType>
-  FpRegister LoadFp(Register arg, int16_t offset) {
-    UNUSED(arg, offset);
-    Undefined();
-    return {};
-  }
-
-  Register OpImm(Decoder::OpImmOpcode opcode, Register arg, int16_t imm) {
-    switch (opcode) {
-      case Decoder::OpImmOpcode::kAddi:
-        return arg + int64_t{imm};
-      case Decoder::OpImmOpcode::kSlti:
-        return bit_cast<int64_t>(arg) < int64_t{imm} ? 1 : 0;
-      case Decoder::OpImmOpcode::kSltiu:
-        return arg < bit_cast<uint64_t>(int64_t{imm}) ? 1 : 0;
-      case Decoder::OpImmOpcode::kXori:
-        return arg ^ int64_t { imm };
-      case Decoder::OpImmOpcode::kOri:
-        return arg | int64_t{imm};
-      case Decoder::OpImmOpcode::kAndi:
-        return arg & int64_t{imm};
-      default:
-        Undefined();
-        return {};
-    }
-  }
-
-  Register Lui(int32_t imm) { return int64_t{imm}; }
-
-  Register Auipc(int32_t imm) {
-    uint64_t pc = state_->cpu.insn_addr;
-    return pc + int64_t{imm};
-  }
-
-  Register OpImm32(Decoder::OpImm32Opcode opcode, Register arg, int16_t imm) {
-    UNUSED(opcode, arg, imm);
-    Undefined();
-    return {};
-  }
-
-  // TODO(b/232598137): rework ecall to not take parameters explicitly.
-  Register Ecall(Register /* syscall_nr */,
-                 Register /* arg0 */,
-                 Register /* arg1 */,
-                 Register /* arg2 */,
-                 Register /* arg3 */,
-                 Register /* arg4 */,
-                 Register /* arg5 */) {
-    CHECK(!exception_raised_);
-    RunGuestSyscall(state_);
-    return state_->cpu.x[A0];
-  }
-
-  Register Slli(Register arg, int8_t imm) { return arg << imm; }
-
-  Register Srli(Register arg, int8_t imm) { return arg >> imm; }
-
-  Register Srai(Register arg, int8_t imm) { return bit_cast<int64_t>(arg) >> imm; }
-
-  Register ShiftImm32(Decoder::ShiftImm32Opcode opcode, Register arg, uint16_t imm) {
-    UNUSED(opcode, arg, imm);
-    Undefined();
-    return {};
-  }
-
-  Register Rori(Register arg, int8_t shamt) {
-    CheckShamtIsValid(shamt);
-    return (((uint64_t(arg) >> shamt)) | (uint64_t(arg) << (64 - shamt)));
-  }
-
-  Register Roriw(Register arg, int8_t shamt) {
-    UNUSED(arg, shamt);
-    Undefined();
-    return {};
-  }
-
-  void Store(Decoder::MemoryDataOperandType operand_type,
-             Register arg,
-             int16_t offset,
-             Register data) {
-    void* ptr = ToHostAddr<void>(arg + offset);
-    switch (operand_type) {
-      case Decoder::MemoryDataOperandType::k8bit:
-        Store<uint8_t>(ptr, data);
-        break;
-      case Decoder::MemoryDataOperandType::k16bit:
-        Store<uint16_t>(ptr, data);
-        break;
-      case Decoder::MemoryDataOperandType::k32bit:
-        Store<uint32_t>(ptr, data);
-        break;
-      case Decoder::MemoryDataOperandType::k64bit:
-        Store<uint64_t>(ptr, data);
-        break;
-      default:
-        return Undefined();
-    }
-  }
-
-  template <typename DataType>
-  void StoreFp(Register arg, int16_t offset, FpRegister data) {
-    UNUSED(arg, offset, data);
-    Undefined();
-  }
-
-  void CompareAndBranch(Decoder::BranchOpcode opcode,
-                        Register arg1,
-                        Register arg2,
-                        int16_t offset) {
-    bool cond_value;
-    switch (opcode) {
-      case Decoder::BranchOpcode::kBeq:
-        cond_value = arg1 == arg2;
-        break;
-      case Decoder::BranchOpcode::kBne:
-        cond_value = arg1 != arg2;
-        break;
-      case Decoder::BranchOpcode::kBltu:
-        cond_value = arg1 < arg2;
-        break;
-      case Decoder::BranchOpcode::kBgeu:
-        cond_value = arg1 >= arg2;
-        break;
-      case Decoder::BranchOpcode::kBlt:
-        cond_value = bit_cast<int64_t>(arg1) < bit_cast<int64_t>(arg2);
-        break;
-      case Decoder::BranchOpcode::kBge:
-        cond_value = bit_cast<int64_t>(arg1) >= bit_cast<int64_t>(arg2);
-        break;
-      default:
-        return Undefined();
-    }
-
-    if (cond_value) {
-      Branch(offset);
-    }
-  }
-
-  void Branch(int32_t offset) {
-    CHECK(!exception_raised_);
-    state_->cpu.insn_addr += offset;
-    branch_taken_ = true;
-  }
-
-  void BranchRegister(Register base, int16_t offset) {
-    CHECK(!exception_raised_);
-    state_->cpu.insn_addr = (base + offset) & ~uint64_t{1};
-    branch_taken_ = true;
-  }
-
-  FpRegister Fmv(FpRegister arg) { return arg; }
-
-  //
-  // V extensions.
-  //
-
-  enum class TailProcessing {
-    kUndisturbed = 0,
-    kAgnostic = 1,
-  };
-
-  enum class InactiveProcessing {
-    kUndisturbed = 0,
-    kAgnostic = 1,
-  };
-
-  enum class VectorSelectElementWidth {
-    k8bit = 0b000,
-    k16bit = 0b001,
-    k32bit = 0b010,
-    k64bit = 0b011,
-    kMaxValue = 0b111,
-  };
-
-  enum class VectorRegisterGroupMultiplier {
-    k1register = 0b000,
-    k2registers = 0b001,
-    k4registers = 0b010,
-    k8registers = 0b011,
-    kEigthOfRegister = 0b101,
-    kQuarterOfRegister = 0b110,
-    kHalfOfRegister = 0b111,
-    kMaxValue = 0b111,
-  };
-
-  static constexpr size_t NumberOfRegistersInvolved(VectorRegisterGroupMultiplier vlmul) {
-    switch (vlmul) {
-      case VectorRegisterGroupMultiplier::k2registers:
-        return 2;
-      case VectorRegisterGroupMultiplier::k4registers:
-        return 4;
-      case VectorRegisterGroupMultiplier::k8registers:
-        return 8;
-      default:
-        return 1;
-    }
-  }
-
-  static constexpr size_t NumRegistersInvolvedForWideOperand(VectorRegisterGroupMultiplier vlmul) {
-    switch (vlmul) {
-      case VectorRegisterGroupMultiplier::k1register:
-        return 2;
-      case VectorRegisterGroupMultiplier::k2registers:
-        return 4;
-      case VectorRegisterGroupMultiplier::k4registers:
-        return 8;
-      default:
-        return 1;
-    }
-  }
-
-  template <typename ElementType, VectorRegisterGroupMultiplier vlmul>
-  static constexpr size_t GetVlmax() {
-    return 0;
-  }
-
-  template <typename VOpArgs, typename... ExtraArgs>
-  void OpVector(const VOpArgs& args, [[maybe_unused]] ExtraArgs... extra_args) {
-    UNUSED(args);
-    Undefined();
-  }
-
-  template <typename ElementType, typename VOpArgs, typename... ExtraArgs>
-  void OpVector(const VOpArgs& args, Register vtype, [[maybe_unused]] ExtraArgs... extra_args) {
-    UNUSED(args, vtype);
-    Undefined();
-  }
-
-  template <typename ElementType, typename VOpArgs, typename... ExtraArgs>
-  void OpVector(const VOpArgs& args,
-                VectorRegisterGroupMultiplier vlmul,
-                Register vtype,
-                [[maybe_unused]] ExtraArgs... extra_args) {
-    UNUSED(args, vlmul, vtype);
-    Undefined();
-  }
-
-  template <typename ElementType,
-            VectorRegisterGroupMultiplier vlmul,
-            typename VOpArgs,
-            typename... ExtraArgs>
-  void OpVector(const VOpArgs& args, Register vtype, [[maybe_unused]] ExtraArgs... extra_args) {
-    UNUSED(args, vtype);
-    Undefined();
-  }
-
-  template <typename ElementType,
-            VectorRegisterGroupMultiplier vlmul,
-            auto vma,
-            typename VOpArgs,
-            typename... ExtraArgs>
-  void OpVector(const VOpArgs& args, Register vtype, [[maybe_unused]] ExtraArgs... extra_args) {
-    UNUSED(args, vtype);
-    Undefined();
-  }
-
-  template <typename ElementType,
-            size_t kSegmentSize,
-            VectorRegisterGroupMultiplier vlmul,
-            auto vma,
-            typename VOpArgs,
-            typename... ExtraArgs>
-  void OpVector(const VOpArgs& args, Register vtype, [[maybe_unused]] ExtraArgs... extra_args) {
-    UNUSED(args, vtype);
-    Undefined();
-  }
-
-  template <size_t kSegmentSize,
-            typename IndexElementType,
-            size_t kIndexRegistersInvolved,
-            TailProcessing vta,
-            auto vma,
-            typename VOpArgs,
-            typename... ExtraArgs>
-  void OpVector(const VOpArgs& args, Register vtype, [[maybe_unused]] ExtraArgs... extra_args) {
-    UNUSED(args, vtype);
-    Undefined();
-  }
-
-  template <typename DataElementType,
-            size_t kSegmentSize,
-            typename IndexElementType,
-            size_t kIndexRegistersInvolved,
-            TailProcessing vta,
-            auto vma,
-            typename VOpArgs,
-            typename... ExtraArgs>
-  void OpVector(const VOpArgs& args,
-                VectorRegisterGroupMultiplier vlmul,
-                [[maybe_unused]] ExtraArgs... extra_args) {
-    UNUSED(args, vlmul);
-    Undefined();
-  }
-
-  void Nop() {}
-
-  void Undefined() {
-    // If there is a guest handler registered for SIGILL we'll delay its processing until the next
-    // sync point (likely the main dispatching loop) due to enabled pending signals. Thus we must
-    // ensure that insn_addr isn't automatically advanced in FinalizeInsn.
-    exception_raised_ = true;
-    abort();
-  }
-
-  void Unimplemented() {
-    // TODO(b/265372622): Replace with fatal from logging.h.
-    abort();
-  }
-
-  //
-  // Guest state getters/setters.
-  //
-
-  Register GetReg(uint8_t reg) const {
-    CheckRegIsValid(reg);
-    return state_->cpu.x[reg];
-  }
-
-  void SetReg(uint8_t reg, Register value) {
-    if (exception_raised_) {
-      // Do not produce side effects.
-      return;
-    }
-    CheckRegIsValid(reg);
-    state_->cpu.x[reg] = value;
-  }
-
-  FpRegister GetFpReg(uint8_t reg) const {
-    CheckFpRegIsValid(reg);
-    return state_->cpu.f[reg];
-  }
-
-  template <typename FloatType>
-  FpRegister GetFRegAndUnboxNan(uint8_t reg);
-
-  template <typename FloatType>
-  void NanBoxAndSetFpReg(uint8_t reg, FpRegister value);
-
-  //
-  // Various helper methods.
-  //
-
-  template <CsrName kName>
-  [[nodiscard]] Register GetCsr() {
-    Undefined();
-    return {};
-  }
-
-  template <CsrName kName>
-  void SetCsr(Register arg) {
-    UNUSED(arg);
-    Undefined();
-  }
-
-  uint64_t GetImm(uint64_t imm) const { return imm; }
-
-  [[nodiscard]] Register Copy(Register value) const { return value; }
-
-  void FinalizeInsn(uint8_t insn_len) {
-    if (!branch_taken_ && !exception_raised_) {
-      state_->cpu.insn_addr += insn_len;
-    }
-  }
-
-  [[nodiscard]] GuestAddr GetInsnAddr() const { return state_->cpu.insn_addr; }
-
-#include "berberis/intrinsics/interpreter_intrinsics_hooks-inl.h"
-
- private:
-  template <typename DataType>
-  Register Load(const void* ptr) {
-    static_assert(std::is_integral_v<DataType>);
-    CHECK(!exception_raised_);
-    FaultyLoadResult result = FaultyLoad(ptr, sizeof(DataType));
-    if (result.is_fault) {
-      exception_raised_ = true;
-      return {};
-    }
-    return static_cast<DataType>(result.value);
-  }
-
-  template <typename DataType>
-  void Store(void* ptr, uint64_t data) {
-    static_assert(std::is_integral_v<DataType>);
-    CHECK(!exception_raised_);
-    exception_raised_ = FaultyStore(ptr, sizeof(DataType), data);
-  }
-
-  void CheckShamtIsValid(int8_t shamt) const {
-    CHECK_GE(shamt, 0);
-    CHECK_LT(shamt, 64);
-  }
-
-  void CheckShamt32IsValid(int8_t shamt) const {
-    CHECK_GE(shamt, 0);
-    CHECK_LT(shamt, 32);
-  }
-
-  void CheckRegIsValid(uint8_t reg) const {
-    CHECK_GT(reg, 0u);
-    CHECK_LE(reg, std::size(state_->cpu.x));
-  }
-
-  void CheckFpRegIsValid(uint8_t reg) const { CHECK_LT(reg, std::size(state_->cpu.f)); }
-
-  ProcessState* state_;
-  bool branch_taken_;
-  bool exception_raised_;
-};
-
-template <>
-[[nodiscard]] Interpreter::FpRegister inline Interpreter::GetFRegAndUnboxNan<Interpreter::Float32>(
-    uint8_t reg) {
-  UNUSED(reg);
-  Interpreter::Undefined();
-  return {};
-}
-
-template <>
-[[nodiscard]] Interpreter::FpRegister inline Interpreter::GetFRegAndUnboxNan<Interpreter::Float64>(
-    uint8_t reg) {
-  UNUSED(reg);
-  Interpreter::Undefined();
-  return {};
-}
-
-template <>
-void inline Interpreter::NanBoxAndSetFpReg<Interpreter::Float32>(uint8_t reg, FpRegister value) {
-  if (exception_raised_) {
-    // Do not produce side effects.
-    return;
-  }
-  CheckFpRegIsValid(reg);
-  state_->cpu.f[reg] = NanBox<Float32>(value);
-}
-
-template <>
-void inline Interpreter::NanBoxAndSetFpReg<Interpreter::Float64>(uint8_t reg, FpRegister value) {
-  if (exception_raised_) {
-    // Do not produce side effects.
-    return;
-  }
-  CheckFpRegIsValid(reg);
-  state_->cpu.f[reg] = value;
-}
-
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadIndexedArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadStrideArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadUnitStrideArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpFVfArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpFVvArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIViArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIVvArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIVxArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpMVvArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpMVxArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreIndexedArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreStrideArgs& args);
-template <>
-extern void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreUnitStrideArgs& args);
-#endif
-
-}  // namespace berberis
diff --git a/interpreter/riscv64/interpreter_arm64_test.cc b/interpreter/riscv64/interpreter_arm64_test.cc
index 95d1cae5..a4f390ae 100644
--- a/interpreter/riscv64/interpreter_arm64_test.cc
+++ b/interpreter/riscv64/interpreter_arm64_test.cc
@@ -41,17 +41,16 @@ class Riscv64ToArm64InterpreterTest : public ::testing::Test {
   template <uint8_t kInsnSize = 4>
   void RunInstruction(const uint32_t& insn_bytes) {
     state_.cpu.insn_addr = ToGuestAddr(&insn_bytes);
-    InterpretInsn(&state_);
+    EXPECT_TRUE(RunOneInstruction<kInsnSize>(&state_, state_.cpu.insn_addr + kInsnSize));
   }
 
   void TestOp(uint32_t insn_bytes,
-              // The tuple is [arg1, arg2, expected_result].
               std::initializer_list<std::tuple<uint64_t, uint64_t, uint64_t>> args) {
-    for (auto arg : args) {
-      SetXReg<2>(state_.cpu, std::get<0>(arg));
-      SetXReg<3>(state_.cpu, std::get<1>(arg));
+    for (auto [arg1, arg2, expected_result] : args) {
+      SetXReg<2>(state_.cpu, arg1);
+      SetXReg<3>(state_.cpu, arg2);
       RunInstruction(insn_bytes);
-      EXPECT_EQ(GetXReg<1>(state_.cpu), std::get<2>(arg));
+      EXPECT_EQ(GetXReg<1>(state_.cpu), expected_result);
     }
   }
 
@@ -245,12 +244,69 @@ TEST_F(Riscv64ToArm64InterpreterTest, OpInstructions) {
              {23, 19, 0},
              {~0ULL, 0, 0},
          });
+  // Div
+  TestOp(0x23140b3, {{0x9999'9999'9999'9999, 0x3333, 0xfffd'fffd'fffd'fffe}});
+  TestOp(0x23140b3, {{42, 2, 21}});
+  TestOp(0x23140b3, {{42, 0, -1}});
+  TestOp(0x23140b3, {{-2147483648, -1, 2147483648}});
+  TestOp(0x23140b3, {{0x8000'0000'0000'0000, -1, 0x8000'0000'0000'0000}});
+  // Divu
+  TestOp(0x23150b3, {{0x9999'9999'9999'9999, 0x3333, 0x0003'0003'0003'0003}});
+  TestOp(0x23150b3, {{42, 2, 21}});
+  TestOp(0x23150b3, {{42, 0, 0xffff'ffff'ffff'ffffULL}});
+  // Rem
+  TestOp(0x23160b3, {{0x9999'9999'9999'9999, 0x3333, 0xffff'ffff'ffff'ffff}});
+  TestOp(0x23160b3, {{0x9999'9999'9999'9999, 0, 0x9999'9999'9999'9999}});
+  // Remu
+  TestOp(0x23170b3, {{0x9999'9999'9999'9999, 0x3333, 0}});
+  TestOp(0x23170b3, {{0x9999'9999'9999'9999, 0, 0x9999'9999'9999'9999}});
   // Andn
   TestOp(0x403170b3, {{0b0101, 0b0011, 0b0100}});
   // Orn
   TestOp(0x403160b3, {{0b0101, 0b0011, 0xffff'ffff'ffff'fffd}});
   // Xnor
   TestOp(0x403140b3, {{0b0101, 0b0011, 0xffff'ffff'ffff'fff9}});
+  // Max
+  TestOp(0x0a3160b3, {{bit_cast<uint64_t>(int64_t{-5}), 4, 4}});
+  TestOp(0x0a3160b3,
+         {{bit_cast<uint64_t>(int64_t{-5}),
+           bit_cast<uint64_t>(int64_t{-10}),
+           bit_cast<uint64_t>(int64_t{-5})}});
+  // Maxu
+  TestOp(0x0a3170b3, {{50, 1, 50}});
+  // Min
+  TestOp(0x0a3140b3, {{bit_cast<uint64_t>(int64_t{-5}), 4, bit_cast<uint64_t>(int64_t{-5})}});
+  TestOp(0x0a3140b3,
+         {{bit_cast<uint64_t>(int64_t{-5}),
+           bit_cast<uint64_t>(int64_t{-10}),
+           bit_cast<uint64_t>(int64_t{-10})}});
+  // Minu
+  TestOp(0x0a3150b3, {{50, 1, 1}});
+  // Ror
+  TestOp(0x603150b3, {{0xf000'0000'0000'000fULL, 4, 0xff00'0000'0000'0000ULL}});
+  TestOp(0x603150b3, {{0xf000'0000'0000'000fULL, 8, 0x0ff0'0000'0000'0000ULL}});
+  // // Rol
+  TestOp(0x603110b3, {{0xff00'0000'0000'0000ULL, 4, 0xf000'0000'0000'000fULL}});
+  TestOp(0x603110b3, {{0x000f'ff00'0000'000fULL, 8, 0x0fff'0000'0000'0f00ULL}});
+  // Sh1add
+  TestOp(0x203120b3, {{0x0008'0000'0000'0001, 0x1001'0001'0000'0000ULL, 0x1011'0001'0000'0002ULL}});
+  // Sh2add
+  TestOp(0x203140b3, {{0x0008'0000'0000'0001, 0x0001'0001'0000'0000ULL, 0x0021'0001'0000'0004ULL}});
+  // Sh3add
+  TestOp(0x203160b3, {{0x0008'0000'0000'0001, 0x1001'0011'0000'0000ULL, 0x1041'0011'0000'0008ULL}});
+  // Bclr
+  TestOp(0x483110b3, {{0b1000'0001'0000'0001ULL, 0, 0b1000'0001'0000'0000ULL}});
+  TestOp(0x483110b3, {{0b1000'0001'0000'0001ULL, 8, 0b1000'0000'0000'0001ULL}});
+  // Bext
+  TestOp(0x483150b3, {{0b1000'0001'0000'0001ULL, 0, 0b0000'0000'0000'0001ULL}});
+  TestOp(0x483150b3, {{0b1000'0001'0000'0001ULL, 8, 0b0000'0000'0000'0001ULL}});
+  TestOp(0x483150b3, {{0b1000'0001'0000'0001ULL, 7, 0b0000'0000'0000'0000ULL}});
+  // Binv
+  TestOp(0x683110b3, {{0b1000'0001'0000'0001ULL, 0, 0b1000'0001'0000'0000ULL}});
+  TestOp(0x683110b3, {{0b1000'0001'0000'0001ULL, 1, 0b1000'0001'0000'0011ULL}});
+  // Bset
+  TestOp(0x283110b3, {{0b1000'0001'0000'0001ULL, 0, 0b1000'0001'0000'0001ULL}});
+  TestOp(0x283110b3, {{0b1000'0001'0000'0001ULL, 1, 0b1000'0001'0000'0011ULL}});
 }
 
 TEST_F(Riscv64ToArm64InterpreterTest, OpImmInstructions) {
@@ -284,6 +340,30 @@ TEST_F(Riscv64ToArm64InterpreterTest, OpImmInstructions) {
   TestOpImm(0x40015093, {{0xf000'0000'0000'0000ULL, 12, 0xffff'0000'0000'0000ULL}});
   // Rori
   TestOpImm(0x60015093, {{0xf000'0000'0000'000fULL, 4, 0xff00'0000'0000'0000ULL}});
+  // Rev8
+  TestOpImm(0x6b815093, {{0x0000'0000'0000'000fULL, 0, 0x0f00'0000'0000'0000ULL}});
+  TestOpImm(0x6b815093, {{0xf000'0000'0000'0000ULL, 0, 0x0000'0000'0000'00f0ULL}});
+  TestOpImm(0x6b815093, {{0x00f0'0000'0000'0000ULL, 0, 0x0000'0000'0000'f000ULL}});
+  TestOpImm(0x6b815093, {{0x0000'000f'0000'0000ULL, 0, 0x0000'0000'0f00'0000ULL}});
+
+  // Sext.b
+  TestOpImm(0x60411093, {{0b1111'1110, 0, 0xffff'ffff'ffff'fffe}});  // -2
+  // Sext.h
+  TestOpImm(0x60511093, {{0b1111'1110, 0, 0xfe}});
+  TestOpImm(0x60511093, {{0b1111'1111'1111'1110, 0, 0xffff'ffff'ffff'fffe}});
+  // Bclri
+  TestOpImm(0x48011093, {{0b1000'0001'0000'0001ULL, 0, 0b1000'0001'0000'0000ULL}});
+  TestOpImm(0x48011093, {{0b1000'0001'0000'0001ULL, 8, 0b1000'0000'0000'0001ULL}});
+  // Bexti
+  TestOpImm(0x48015093, {{0b1000'0001'0000'0001ULL, 0, 0b0000'0000'0000'0001ULL}});
+  TestOpImm(0x48015093, {{0b1000'0001'0000'0001ULL, 8, 0b0000'0000'0000'0001ULL}});
+  TestOpImm(0x48015093, {{0b1000'0001'0000'0001ULL, 7, 0b0000'0000'0000'0000ULL}});
+  // Binvi
+  TestOpImm(0x68011093, {{0b1000'0001'0000'0001ULL, 0, 0b1000'0001'0000'0000ULL}});
+  TestOpImm(0x68011093, {{0b1000'0001'0000'0001ULL, 1, 0b1000'0001'0000'0011ULL}});
+  // Bseti
+  TestOpImm(0x28011093, {{0b1000'0001'0000'0001ULL, 0, 0b1000'0001'0000'0001ULL}});
+  TestOpImm(0x28011093, {{0b1000'0001'0000'0001ULL, 1, 0b1000'0001'0000'0011ULL}});
 }
 
 TEST_F(Riscv64ToArm64InterpreterTest, UpperImmInstructions) {
diff --git a/interpreter/riscv64/regs.h b/interpreter/riscv64/regs.h
index 3168b3a5..f649e76b 100644
--- a/interpreter/riscv64/regs.h
+++ b/interpreter/riscv64/regs.h
@@ -45,7 +45,6 @@ inline auto IntegerToGPRReg(IntegerType arg)
   }
 }
 
-#if !defined(__aarch64__)
 template <typename FloatType>
 inline FloatType FPRegToFloat(uint64_t arg);
 
@@ -74,7 +73,6 @@ template <>
 inline uint64_t FloatToFPReg<intrinsics::Float64>(intrinsics::Float64 arg) {
   return bit_cast<uint64_t>(arg);
 }
-#endif
 
 }  // namespace berberis
 
diff --git a/intrinsics/Android.bp b/intrinsics/Android.bp
index ad8fbfe2..f36a67ef 100644
--- a/intrinsics/Android.bp
+++ b/intrinsics/Android.bp
@@ -264,6 +264,9 @@ cc_library_headers {
         arm64: {
             generated_headers: ["libberberis_intrinsics_gen_public_headers_riscv64_to_arm64"],
             export_generated_headers: ["libberberis_intrinsics_gen_public_headers_riscv64_to_arm64"],
+            export_include_dirs: [
+                "riscv64_to_arm64/include",
+            ],
         },
         x86_64: {
             generated_headers: [
@@ -385,7 +388,7 @@ cc_library_static {
 
 cc_library_static {
     name: "libberberis_intrinsics_riscv64",
-    defaults: ["berberis_defaults_64"],
+    defaults: ["berberis_all_hosts_defaults_64"],
     host_supported: true,
     srcs: [
         "riscv64_to_all/intrinsics.cc",
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h
index 9b1b01db..a8a58590 100644
--- a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h
@@ -197,19 +197,17 @@ inline Float32 FPRound(const Float32& value, uint32_t round_control) {
           : "f"(result.value_));
       break;
     case FE_TIESAWAY:
-      // Convert positive value to integer with rounding down.
+      // Convert positive value to integer with rounding up.
       asm("fcvt.w.s %0, %1, rup" : "=r"(compare_result) : "f"(positive_value.value_));
-      // Subtract ½ from the rounded avlue and compare to the previously calculated positive value.
+      // Subtract .5 from the rounded avlue and compare to the previously calculated positive value.
       // Note: here we don't have to deal with infinities, NaNs, values that are too large, etc,
       // since they are all handled above before we reach that line.
-      //  But coding that in C++ gives compiler opportunity to use Zfa, if it's enabled.
+      // But coding that in C++ gives compiler opportunity to use Zfa, if it's enabled.
       if (positive_value.value_ ==
           static_cast<float>(static_cast<float>(static_cast<int32_t>(compare_result)) - 0.5f)) {
         // If they are equal then we already have the final result (but without correct sign bit).
         // Thankfully RISC-V includes operation that can be used to pick sign from original value.
-        asm("fsgnj.s %0, %1, %2"
-            : "=f"(result.value_)
-            : "f"(positive_value.value_), "f"(result.value_));
+        result.value_ = static_cast<float>(static_cast<int32_t>(compare_result));
       } else {
         // Otherwise we may now use conversion to nearest.
         asm("fcvt.w.s %1, %2, rne\n"
@@ -221,6 +219,8 @@ inline Float32 FPRound(const Float32& value, uint32_t round_control) {
     default:
       FATAL("Unknown round_control in FPRound!");
   }
+  // Pick sign from original value. This is needed for -0 corner cases and ties away.
+  asm("fsgnj.s %0, %1, %2" : "=f"(result.value_) : "f"(result.value_), "f"(value.value_));
   return result;
 }
 
@@ -275,18 +275,16 @@ inline Float64 FPRound(const Float64& value, uint32_t round_control) {
           : "f"(result.value_));
       break;
     case FE_TIESAWAY:
-      // Convert positive value to integer with rounding down.
+      // Convert positive value to integer with rounding up.
       asm("fcvt.l.d %0, %1, rup" : "=r"(compare_result) : "f"(positive_value.value_));
-      // Subtract ½ from the rounded avlue and compare to the previously calculated positive value.
+      // Subtract .5 from the rounded value and compare to the previously calculated positive value.
       // Note: here we don't have to deal with infinities, NaNs, values that are too large, etc,
       // since they are all handled above before we reach that line.
-      //  But coding that in C++ gives compiler opportunity to use Zfa, if it's enabled.
+      // But coding that in C++ gives compiler opportunity to use Zfa, if it's enabled.
       if (positive_value.value_ == static_cast<double>(compare_result) - 0.5) {
         // If they are equal then we already have the final result (but without correct sign bit).
         // Thankfully RISC-V includes operation that can be used to pick sign from original value.
-        asm("fsgnj.d %0, %1, %2"
-            : "=f"(result.value_)
-            : "f"(positive_value.value_), "f"(result.value_));
+        result.value_ = static_cast<double>(compare_result);
       } else {
         // Otherwise we may now use conversion to nearest.
         asm("fcvt.l.d %1, %2, rne\n"
@@ -298,6 +296,8 @@ inline Float64 FPRound(const Float64& value, uint32_t round_control) {
     default:
       FATAL("Unknown round_control in FPRound!");
   }
+  // Pick sign from original value. This is needed for -0 corner cases and ties away.
+  asm("fsgnj.d %0, %1, %2" : "=f"(result.value_) : "f"(result.value_), "f"(value.value_));
   return result;
 }
 
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
index 36124ace..b9facd6b 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
@@ -64,6 +64,8 @@ class AL {
   static constexpr bool kIsImmediate = false;
   static constexpr bool kIsImplicitReg = true;
   static constexpr char kAsRegister = 'a';
+  template <typename MachineInsnArch>
+  static constexpr auto kRegClass = MachineInsnArch::kAL;
 };
 
 class AX {
@@ -313,6 +315,7 @@ class HasSSSE3;
 class HasTBM;
 class HasVAES;
 class HasX87;
+class HasCustomCapability;
 class IsAuthenticAMD;
 
 }  // namespace berberis::intrinsics::bindings
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/macro_assembler-inl.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h
similarity index 100%
rename from intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/macro_assembler-inl.h
rename to intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
index 9f317aeb..79b9a372 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
@@ -153,20 +153,41 @@ class TextAssembler {
     int arg_no_;
   };
 
-  class XMMRegister {
+  template <int kBits>
+  class SIMDRegister {
    public:
-    constexpr XMMRegister(int arg_no) : arg_no_(arg_no) {}
+    friend class SIMDRegister<384 - kBits>;
+    constexpr SIMDRegister(int arg_no) : arg_no_(arg_no) {}
     int arg_no() const {
       CHECK_NE(arg_no_, kNoRegister);
       return arg_no_;
     }
 
-    constexpr bool operator==(const XMMRegister& other) const { return arg_no() == other.arg_no(); }
-    constexpr bool operator!=(const XMMRegister& other) const { return arg_no() != other.arg_no(); }
+    constexpr bool operator==(const SIMDRegister& other) const {
+      return arg_no() == other.arg_no();
+    }
+    constexpr bool operator!=(const SIMDRegister& other) const {
+      return arg_no() != other.arg_no();
+    }
+
+    constexpr auto To128Bit() const {
+      return std::enable_if_t<kBits != 128, SIMDRegister<128>>{arg_no_};
+    }
+    constexpr auto To256Bit() const {
+      return std::enable_if_t<kBits != 256, SIMDRegister<256>>{arg_no_};
+    }
 
     template <typename MacroAssembler>
-    friend const std::string ToGasArgument(const XMMRegister& reg, MacroAssembler*) {
-      return '%' + std::to_string(reg.arg_no());
+    friend const std::string ToGasArgument(const SIMDRegister& reg, MacroAssembler*) {
+      if constexpr (kBits == 128) {
+        return "%x" + std::to_string(reg.arg_no());
+      } else if constexpr (kBits == 256) {
+        return "%t" + std::to_string(reg.arg_no());
+      } else if constexpr (kBits == 512) {
+        return "%g" + std::to_string(reg.arg_no());
+      } else {
+        static_assert(kDependentValueFalse<kBits>);
+      }
     }
 
    private:
@@ -178,6 +199,9 @@ class TextAssembler {
     int arg_no_;
   };
 
+  using XMMRegister = SIMDRegister<128>;
+  using YMMRegister = SIMDRegister<256>;
+
   struct Operand {
     Register base = Register{Register::kNoRegister};
     Register index = Register{Register::kNoRegister};
@@ -248,6 +272,7 @@ class TextAssembler {
   Register gpr_macroassembler_scratch2{Register::kNoRegister};
 
   bool need_avx = false;
+  bool need_avx2 = false;
   bool need_bmi = false;
   bool need_bmi2 = false;
   bool need_fma = false;
@@ -258,6 +283,7 @@ class TextAssembler {
   bool need_ssse3 = false;
   bool need_sse4_1 = false;
   bool need_sse4_2 = false;
+  bool has_custom_capability = false;
 
   void Bind(Label* label) {
     CHECK_EQ(label->bound, false);
@@ -379,6 +405,9 @@ class TextAssembler {
       return "host_platform::kHasSSE4_2";
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSSE3>) {
       return "host_platform::kHasSSSE3";
+    } else if constexpr (std::is_same_v<CPUIDRestriction,
+                                        intrinsics::bindings::HasCustomCapability>) {
+      return "host_platform::kHasCustomCapability";
     } else {
       static_assert(kDependentTypeFalse<CPUIDRestriction>);
     }
@@ -423,6 +452,11 @@ class TextAssembler {
     SetRequiredFeatureSSE4_2();
   }
 
+  void SetRequiredFeatureAVX2() {
+    need_avx2 = true;
+    SetRequiredFeatureAVX();
+  }
+
   void SetRequiredFeatureBMI() {
     need_bmi = true;
   }
@@ -470,6 +504,8 @@ class TextAssembler {
     SetRequiredFeatureSSE4_1();
   }
 
+  void SetHasCustomCapability() { has_custom_capability = true; }
+
   template <typename... Args>
   void Instruction(const char* name, Condition cond, const Args&... args);
 
@@ -576,12 +612,16 @@ template <typename DerivedAssemblerType>
 template <typename... Args>
 inline void TextAssembler<DerivedAssemblerType>::Instruction(const char* name,
                                                              const Args&... args) {
-  for (auto it : std::array<std::tuple<const char*, const char*>, 18>{
+  for (auto it : std::array<std::tuple<const char*, const char*>, 22>{
            {// Note: SSE doesn't include simple register-to-register move instruction.
             // You are supposed to use one of half-dozen variants depending on what you
             // are doing.
             //
             // Pseudoinstructions with embedded "lock" prefix.
+            {"Lock Xaddb", "Lock; Xaddb"},
+            {"Lock Xaddw", "Lock; Xaddw"},
+            {"Lock Xaddl", "Lock; Xaddl"},
+            {"Lock Xaddq", "Lock; Xaddq"},
             {"LockCmpXchg8b", "Lock; CmppXchg8b"},
             {"LockCmpXchg16b", "Lock; CmppXchg16b"},
             {"LockCmpXchgb", "Lock; CmppXchgb"},
diff --git a/intrinsics/gen_intrinsics.py b/intrinsics/gen_intrinsics.py
index 55913a52..f26ea8f4 100755
--- a/intrinsics/gen_intrinsics.py
+++ b/intrinsics/gen_intrinsics.py
@@ -104,6 +104,8 @@ class VecSize(object):
 
 _VECTOR_SIZES = {'X64': VecSize(64, 1), 'X128': VecSize(128, 2)}
 
+_ROUNDING_MODES = ['FE_TONEAREST', 'FE_DOWNWARD', 'FE_UPWARD', 'FE_TOWARDZERO', 'FE_TIESAWAY']
+
 
 def _is_imm_type(arg_type):
   return 'imm' in arg_type
@@ -126,7 +128,7 @@ def _get_imm_c_type(arg_type):
 
 
 def _get_c_type(arg_type):
-  if (arg_type in ('Float32', 'Float64', 'int8_t', 'uint8_t', 'int16_t',
+  if (arg_type in ('Float16', 'Float32', 'Float64', 'int8_t', 'uint8_t', 'int16_t',
                   'uint16_t', 'int32_t', 'uint32_t', 'int64_t', 'uint64_t',
                   'volatile uint8_t*', 'volatile uint32_t*') or
       _is_template_type(arg_type)):
@@ -137,13 +139,15 @@ def _get_c_type(arg_type):
     return _get_imm_c_type(arg_type)
   if arg_type == 'vec':
     return 'SIMD128Register'
+  if arg_type in _ROUNDING_MODES:
+    return 'int'
   raise Exception('Type %s not supported' % (arg_type))
 
 
 def _get_semantic_player_type(arg_type, type_map):
   if type_map is not None and arg_type in type_map:
     return type_map[arg_type]
-  if arg_type in ('Float32', 'Float64', 'vec'):
+  if arg_type in ('Float16', 'Float32', 'Float64', 'vec'):
     return 'SimdRegister'
   if _is_imm_type(arg_type):
     return _get_imm_c_type(arg_type)
@@ -179,11 +183,14 @@ def _gen_template_intr_decl(f, name, intr):
   comment = intr.get('comment')
   if comment:
     print('// %s.' % (comment), file=f)
-  print('template <%s>' % _get_template_arguments(intr.get('variants')), file=f)
+  print('template <%s>' % _get_template_arguments(
+      intr.get('variants'), intr.get('precise_nans', False)), file=f)
   print('%s %s(%s);' % (retval, name, ', '.join(params)), file=f)
 
 
-def _get_template_arguments(variants,
+def _get_template_arguments(
+    variants,
+    precise_nans = False,
     extra = ['enum PreferredIntrinsicsImplementation = kUseAssemblerImplementationIfPossible']):
   template = None
   for variant in variants:
@@ -192,11 +199,13 @@ def _get_template_arguments(variants,
       nonlocal counter
       counter += 1
       return counter
-    new_template = ', '.join([
-      'bool kBool%s' % get_counter() if param.strip() in ('true', 'false') else
-      'typename Type%d' % get_counter() if re.search('[_a-zA-Z]', param) else
-      'int kInt%s' % get_counter()
-      for param in variant.split(',')] + extra)
+    new_template = ', '.join(
+      (["bool kPreciseNaNOperationsHandling"] if precise_nans else []) +
+      ['bool kBool%s' % get_counter() if param.strip() in ('true', 'false') else
+       'uint32_t kInt%s' % get_counter() if param.strip() in _ROUNDING_MODES else
+       'typename Type%d' % get_counter() if re.search('[_a-zA-Z]', param) else
+       'int kInt%s' % get_counter()
+       for param in variant.split(',')] + extra)
     assert template is None or template == new_template
     template = new_template
   return template
@@ -253,7 +262,7 @@ def _get_semantics_player_hook_proto(name, intr):
   result, name, args = _get_semantics_player_hook_proto_components(name, intr)
   if intr.get('class') == 'template':
     return 'template<%s>\n%s %s(%s)' % (
-      _get_template_arguments(intr.get('variants'), []), result, name, args)
+      _get_template_arguments(intr.get('variants'), False, []), result, name, args)
   return '%s %s(%s)' % (result, name, args)
 
 
@@ -296,7 +305,7 @@ def _get_interpreter_hook_call_expr(name, intr, desc=None):
       # can keep simple code here for now.
       if _is_simd128_conversion_required(outs[0]):
         out_type = _get_c_type(outs[0])
-        if out_type in ('Float32', 'Float64'):
+        if out_type in ('Float16', 'Float32', 'Float64'):
           call_expr = 'FloatToFPReg(%s)' % call_expr
         else:
           raise Exception('Type %s is not supported' % (out_type))
@@ -347,7 +356,7 @@ def _is_unsigned(intr):
 def _get_vector_format_init_expr(intr):
   variants = intr.get('variants')
 
-  if ('Float32' in variants or 'Float64' in variants):
+  if ('Float16' in variants or 'Float32' in variants or 'Float64' in variants):
     return 'intrinsics::GetVectorFormatFP(elem_size, elem_num)'
 
   assert _is_signed(intr) or _is_unsigned(intr), "Unexpected intrinsic class"
@@ -406,7 +415,10 @@ def _gen_interpreter_hook(f, name, intr, option):
     print('\n'.join(lines), file=f)
   else:
     # TODO(b/363057506): Add float support and clean up the logic here.
-    arm64_allowlist = ['AmoAdd', 'AmoAnd', 'AmoMax', 'AmoMin', 'AmoOr', 'AmoSwap', 'AmoXor']
+    arm64_allowlist = ['AmoAdd', 'AmoAnd', 'AmoMax', 'AmoMin', 'AmoOr', 'AmoSwap', 'AmoXor', 'Bclr',
+                       'Bclri', 'Bext', 'Bexti', 'Binv', 'Binvi', 'Bset', 'Bseti', 'Div', 'Max',
+                       'Min', 'Rem', 'Rev8', 'Rol', 'Ror', 'Sext', 'Sh1add', 'Sh1adduw', 'Sh2add',
+                       'Sh2adduw', 'Sh3add', 'Sh3adduw', 'Zext', 'UnboxNan']
     if (option == 'arm64') and (name not in arm64_allowlist):
       _get_placeholder_return_stmt(intr, f)
     else:
@@ -455,9 +467,14 @@ def _gen_mock_semantics_listener_hook(f, name, intr):
   result, name, args = _get_semantics_player_hook_proto_components(name, intr)
   if intr.get('class') == 'template':
     print('template<%s>\n%s %s(%s) {\n  return %s(%s);\n}' % (
-      _get_template_arguments(intr.get('variants'), []), result, name, args, name, ', '.join([
-      'intrinsics::kEnumFromTemplateType<%s>' % arg if arg.startswith('Type') else arg
-      for arg in _get_template_spec_arguments(intr.get('variants'))] +
+      _get_template_arguments(intr.get('variants'), False, []),
+      result,
+      name,
+      args,
+      name,
+      ', '.join([
+        'intrinsics::kEnumFromTemplateType<%s>' % arg if arg.startswith('Type') else arg
+        for arg in _get_template_spec_arguments(intr.get('variants'))] +
       [('arg%d' % n) for n, _ in enumerate(intr['in'])])), file=f)
     args = ', '.join([
       '%s %s' % (
@@ -534,6 +551,8 @@ def _check_typed_variant(variant, desc):
   if not desc.is_unsigned and not desc.is_float:
     return _check_signed_variant(variant, desc)
   if desc.is_float:
+    if desc.element_size == 2:
+      return variant == 'Float16'
     if desc.element_size == 4:
       return variant == 'Float32'
     if desc.element_size == 8:
@@ -588,7 +607,7 @@ def _get_cast_from_simd128(var, target_type, ptr_bits):
                                                   ptr_bits)
 
   c_type = _get_c_type(target_type)
-  if c_type in ('Float32', 'Float64'):
+  if c_type in ('Float16', 'Float32', 'Float64'):
     return 'FPRegToFloat<intrinsics::%s>(%s)' % (c_type, var)
 
   cast_map = {
@@ -631,6 +650,7 @@ def _get_template_spec_arguments(variants):
       return counter
     new_spec = [
       'kBool%s' % get_counter() if param.strip() in ('true', 'false') else
+      'kInt%s' % get_counter() if param.strip() in _ROUNDING_MODES else
       'Type%d' % get_counter() if re.search('[_a-zA-Z]', param) else
       'kInt%s' % get_counter()
       for param in variant.split(',')]
@@ -640,14 +660,16 @@ def _get_template_spec_arguments(variants):
 
 
 def _intr_has_side_effects(intr, fmt=None):
+  ins = intr.get('in')
+  outs = intr.get('out')
   # If we have 'has_side_effects' mark in JSON file then we use it "as is".
   if 'has_side_effects' in intr:
     return intr.get('has_side_effects')
   # Otherwise we mark all floating-point related intrinsics as "volatile".
   # TODO(b/68857496): move that information in HIR/LIR and stop doing that.
-  if 'Float32' in intr.get('in') or 'Float64' in intr.get('in'):
+  if 'Float16' in ins or 'Float32' in ins or 'Float64' in ins:
     return True
-  if 'Float32' in intr.get('out') or 'Float64' in intr.get('out'):
+  if 'Float16' in outs or  'Float32' in outs or 'Float64' in outs:
     return True
   if fmt is not None and fmt.startswith('F'):
     return True
@@ -674,6 +696,7 @@ def _gen_semantic_player_types(intrs):
           counter += 1
           return counter
         new_map = {
+          'Float16': 'FpRegister',
           'Float32': 'FpRegister',
           'Float64': 'FpRegister',
         }
@@ -682,7 +705,7 @@ def _gen_semantic_player_types(intrs):
                             re.search('[_a-zA-Z]', param),
             variant.split(',')):
           new_map['Type%d' % get_counter()] = (
-              'FpRegister' if type.strip() in ('Float32', 'Float64') else
+              'FpRegister' if type.strip() in ('Float16', 'Float32', 'Float64') else
               _get_semantic_player_type(type, None))
         assert map is None or map == new_map
         map = new_map
@@ -900,7 +923,8 @@ _KNOWN_FEATURES_KEYS = {
   'AVX': '017',
   'AVX2': '018',
   'FMA': '019',
-  'FMA4': '020'
+  'FMA4': '020',
+  'CustomCapability': '021'
 }
 
 
@@ -1098,7 +1122,11 @@ def _add_asm_insn(intrs, arch_intr, insn):
   assert 'feature' not in insn or insn['feature'] == arch_intr['feature']
   assert 'nan' not in insn or insn['nan'] == arch_intr['nan']
   assert 'usage' not in insn or insn['usage'] == arch_intr['usage']
-  assert len(intrs[name]['in']) == len(arch_intr['in'])
+  # Some intrinsics have extra inputs which can be ignored. e,g fpcr could be
+  # ignored when not needed for precise emulation of NaNs.
+  # Therefore we check that number inputs to (macro) instruction is less than
+  # or equal to number of inputs to number of inputs to intrinsic.
+  assert len(intrs[name]['in']) >= len(arch_intr['in'])
   assert len(intrs[name]['out']) == len(arch_intr['out'])
 
   if 'variants' in arch_intr:
diff --git a/intrinsics/gen_text_asm_intrinsics.cc b/intrinsics/gen_text_asm_intrinsics.cc
index b03bf4da..f8c0849a 100644
--- a/intrinsics/gen_text_asm_intrinsics.cc
+++ b/intrinsics/gen_text_asm_intrinsics.cc
@@ -87,7 +87,8 @@ void GenerateFunctionHeader(FILE* out, int indent) {
   }
   std::vector<std::string> ins;
   for (const char* type_name : AsmCallInfo::InputArgumentsTypeNames) {
-    ins.push_back(std::string(type_name) + " in" + std::to_string(ins.size()));
+    ins.push_back("[[maybe_unused]] " + std::string(type_name) + " in" +
+                  std::to_string(ins.size()));
   }
   GenerateElementsList<AsmCallInfo>(out, indent, prefix, ") {", ins);
   fprintf(out,
diff --git a/intrinsics/include/berberis/intrinsics/common/intrinsics.h b/intrinsics/include/berberis/intrinsics/common/intrinsics.h
index f6aa056d..dda437d4 100644
--- a/intrinsics/include/berberis/intrinsics/common/intrinsics.h
+++ b/intrinsics/include/berberis/intrinsics/common/intrinsics.h
@@ -20,10 +20,7 @@
 #include <cstdint>
 
 #include "berberis/base/dependent_false.h"
-
-#if !defined(__aarch64__)
-#include "berberis/intrinsics/common/intrinsics_float.h"  // Float32/Float64
-#endif
+#include "berberis/intrinsics/common/intrinsics_float.h"  // Float16/Float32/Float64
 
 namespace berberis {
 
@@ -40,6 +37,7 @@ enum EnumFromTemplateType {
   kUInt32T,
   kInt64T,
   kUInt64T,
+  kFloat16,
   kFloat32,
   kFloat64,
   kSIMD128Register,
@@ -63,6 +61,8 @@ constexpr EnumFromTemplateType TypeToEnumFromTemplateType() {
     return EnumFromTemplateType::kUInt64T;
   } else if constexpr (std::is_same_v<uint64_t, std::decay_t<Type>>) {
     return EnumFromTemplateType::kUInt64T;
+  } else if constexpr (std::is_same_v<Float16, std::decay_t<Type>>) {
+    return EnumFromTemplateType::kFloat16;
   } else if constexpr (std::is_same_v<Float32, std::decay_t<Type>>) {
     return EnumFromTemplateType::kFloat32;
   } else if constexpr (std::is_same_v<Float64, std::decay_t<Type>>) {
diff --git a/intrinsics/include/berberis/intrinsics/intrinsics_atomics_impl.h b/intrinsics/include/berberis/intrinsics/intrinsics_atomics_impl.h
index 3fe4b247..5dd85e62 100644
--- a/intrinsics/include/berberis/intrinsics/intrinsics_atomics_impl.h
+++ b/intrinsics/include/berberis/intrinsics/intrinsics_atomics_impl.h
@@ -21,6 +21,7 @@
 #include <type_traits>
 
 #include "berberis/guest_state/guest_addr.h"
+#include "berberis/intrinsics/common/intrinsics.h"
 
 namespace berberis::intrinsics {
 
@@ -57,7 +58,6 @@ inline constexpr int AqRlToMemoryOrder(bool aq, bool rl) {
 template <typename IntType, bool aq, bool rl, enum PreferredIntrinsicsImplementation>
 std::tuple<IntType> AmoAdd(int64_t arg1, IntType arg2) {
   static_assert(std::is_integral_v<IntType>, "AmoAdd: IntType must be integral");
-  static_assert(std::is_signed_v<IntType>, "AmoAdd: IntType must be signed");
   auto ptr = ToHostAddr<IntType>(arg1);
   return {__atomic_fetch_add(ptr, arg2, AqRlToMemoryOrder(aq, rl))};
 }
@@ -65,29 +65,45 @@ std::tuple<IntType> AmoAdd(int64_t arg1, IntType arg2) {
 template <typename IntType, bool aq, bool rl, enum PreferredIntrinsicsImplementation>
 std::tuple<IntType> AmoAnd(int64_t arg1, IntType arg2) {
   static_assert(std::is_integral_v<IntType>, "AmoAnd: IntType must be integral");
-  static_assert(std::is_signed_v<IntType>, "AmoAnd: IntType must be signed");
   auto ptr = ToHostAddr<IntType>(arg1);
   return {__atomic_fetch_and(ptr, arg2, AqRlToMemoryOrder(aq, rl))};
 }
 
-template <typename IntType, bool aq, bool rl, enum PreferredIntrinsicsImplementation>
-std::tuple<IntType> AmoMax(int64_t arg1, IntType arg2) {
+template <typename IntType,
+          typename RetType,
+          bool aq,
+          bool rl,
+          enum PreferredIntrinsicsImplementation>
+std::tuple<RetType> AmoMax(int64_t arg1, IntType arg2) {
   static_assert(std::is_integral_v<IntType>, "AmoMax: IntType must be integral");
   auto ptr = ToHostAddr<IntType>(arg1);
   return {__atomic_fetch_max(ptr, arg2, AqRlToMemoryOrder(aq, rl))};
 }
 
-template <typename IntType, bool aq, bool rl, enum PreferredIntrinsicsImplementation>
-std::tuple<IntType> AmoMin(int64_t arg1, IntType arg2) {
+template <typename IntType, bool aq, bool rl, enum PreferredIntrinsicsImplementation preferred_impl>
+std::tuple<IntType> AmoMax(int64_t arg1, IntType arg2) {
+  return AmoMax<IntType, IntType, aq, rl, preferred_impl>(arg1, arg2);
+}
+
+template <typename IntType,
+          typename RetType,
+          bool aq,
+          bool rl,
+          enum PreferredIntrinsicsImplementation>
+std::tuple<RetType> AmoMin(int64_t arg1, IntType arg2) {
   static_assert(std::is_integral_v<IntType>, "AmoMin: IntType must be integral");
   auto ptr = ToHostAddr<IntType>(arg1);
   return {__atomic_fetch_min(ptr, arg2, AqRlToMemoryOrder(aq, rl))};
 }
 
+template <typename IntType, bool aq, bool rl, enum PreferredIntrinsicsImplementation preferred_impl>
+std::tuple<IntType> AmoMin(int64_t arg1, IntType arg2) {
+  return AmoMin<IntType, IntType, aq, rl, preferred_impl>(arg1, arg2);
+}
+
 template <typename IntType, bool aq, bool rl, enum PreferredIntrinsicsImplementation>
 std::tuple<IntType> AmoOr(int64_t arg1, IntType arg2) {
   static_assert(std::is_integral_v<IntType>, "AmoOr: IntType must be integral");
-  static_assert(std::is_signed_v<IntType>, "AmoOr: IntType must be signed");
   auto ptr = ToHostAddr<IntType>(arg1);
   return {__atomic_fetch_or(ptr, arg2, AqRlToMemoryOrder(aq, rl))};
 }
@@ -103,7 +119,6 @@ std::tuple<IntType> AmoSwap(int64_t arg1, IntType arg2) {
 template <typename IntType, bool aq, bool rl, enum PreferredIntrinsicsImplementation>
 std::tuple<IntType> AmoXor(int64_t arg1, IntType arg2) {
   static_assert(std::is_integral_v<IntType>, "AmoXor: IntType must be integral");
-  static_assert(std::is_signed_v<IntType>, "AmoXor: IntType must be signed");
   auto ptr = ToHostAddr<IntType>(arg1);
   return {__atomic_fetch_xor(ptr, arg2, AqRlToMemoryOrder(aq, rl))};
 }
diff --git a/intrinsics/include/berberis/intrinsics/intrinsics_floating_point_impl.h b/intrinsics/include/berberis/intrinsics/intrinsics_floating_point_impl.h
index 63336150..206dc269 100644
--- a/intrinsics/include/berberis/intrinsics/intrinsics_floating_point_impl.h
+++ b/intrinsics/include/berberis/intrinsics/intrinsics_floating_point_impl.h
@@ -24,11 +24,16 @@
 #include "berberis/base/bit_util.h"
 #include "berberis/intrinsics/guest_cpu_flags.h"
 #include "berberis/intrinsics/intrinsics.h"
+#if defined(__aarch64__)
+#include "berberis/intrinsics/common/intrinsics_float.h"
+#else
 #include "berberis/intrinsics/intrinsics_float.h"  // Float32/Float64/ProcessNans
+#endif
 #include "berberis/intrinsics/type_traits.h"
 
 namespace berberis::intrinsics {
 
+#if !defined(__aarch64__)
 template <typename FloatType,
           enum PreferredIntrinsicsImplementation kPreferredIntrinsicsImplementation>
 std::tuple<FloatType> FAdd(int8_t rm, int8_t frm, FloatType arg1, FloatType arg2) {
@@ -273,6 +278,7 @@ std::tuple<FloatType> FNMSub(int8_t rm,
       arg2,
       arg3);
 }
+#endif
 
 template <typename FloatType>
 FloatType CanonicalizeNanTuple(std::tuple<FloatType> arg) {
@@ -321,6 +327,7 @@ FloatType RSqrtEstimate(FloatType op) {
   }
 }
 
+#if !defined(__aarch64__)
 template <typename FloatType, enum PreferredIntrinsicsImplementation>
 std::tuple<FloatType> FNMSubHostRounding(FloatType arg1, FloatType arg2, FloatType arg3) {
   return {intrinsics::MulAdd(intrinsics::Negative(arg1), arg2, intrinsics::Negative(arg3))};
@@ -382,6 +389,7 @@ template <typename FloatType, enum PreferredIntrinsicsImplementation>
 std::tuple<FloatType> FSubHostRounding(FloatType arg1, FloatType arg2) {
   return {arg1 - arg2};
 }
+#endif
 
 }  // namespace berberis::intrinsics
 
diff --git a/intrinsics/include/berberis/intrinsics/simd_register.h b/intrinsics/include/berberis/intrinsics/simd_register.h
index 8c0cdfb1..419fd0c5 100644
--- a/intrinsics/include/berberis/intrinsics/simd_register.h
+++ b/intrinsics/include/berberis/intrinsics/simd_register.h
@@ -263,11 +263,7 @@ class SIMD128Register {
 
 static_assert(sizeof(SIMD128Register) == 16, "Unexpected size of SIMD128Register");
 
-#if defined(__i386__)
-static_assert(alignof(SIMD128Register) == 16, "Unexpected align of SIMD128Register");
-#elif defined(__x86_64__)
-static_assert(alignof(SIMD128Register) == 16, "Unexpected align of SIMD128Register");
-#elif defined(__riscv)
+#if defined(__i386__) || defined(__x86_64__) || defined(__riscv) || defined(__aarch64__)
 static_assert(alignof(SIMD128Register) == 16, "Unexpected align of SIMD128Register");
 #else
 #error Unsupported architecture
diff --git a/intrinsics/include/berberis/intrinsics/type_traits.h b/intrinsics/include/berberis/intrinsics/type_traits.h
index 5f4241f1..b7f229c0 100644
--- a/intrinsics/include/berberis/intrinsics/type_traits.h
+++ b/intrinsics/include/berberis/intrinsics/type_traits.h
@@ -40,6 +40,7 @@ template <>
 struct TypeTraits<uint16_t> {
   using Wide = uint32_t;
   using Narrow = uint8_t;
+  using Float = intrinsics::Float16;
   static constexpr int kBits = 16;
   static constexpr char kName[] = "uint16_t";
 };
@@ -75,6 +76,7 @@ template <>
 struct TypeTraits<int16_t> {
   using Wide = int32_t;
   using Narrow = int8_t;
+  using Float = intrinsics::Float16;
   static constexpr int kBits = 16;
   static constexpr char kName[] = "int16_t";
 };
diff --git a/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/intrinsics.h b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/intrinsics.h
index f9565ebc..2e35e3d5 100644
--- a/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/intrinsics.h
+++ b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/intrinsics.h
@@ -28,23 +28,21 @@
 #include "berberis/base/bit_util.h"
 #include "berberis/intrinsics/intrinsics_float.h"  // Float32/Float64/ProcessNans
 #include "berberis/intrinsics/type_traits.h"
+#else
+#include "berberis/intrinsics/common/intrinsics_float.h"
 #endif
 
 namespace berberis::intrinsics {
 
-#if defined(__aarch64__)
-using Float64 = double;
-#endif
-
 #include "berberis/intrinsics/intrinsics-inl.h"  // NOLINT: generated file!
 
 }  // namespace berberis::intrinsics
 
 #include "berberis/intrinsics/intrinsics_atomics_impl.h"
-#if !defined(__aarch64__)
 #include "berberis/intrinsics/intrinsics_bitmanip_impl.h"
+#if !defined(__aarch64__)
 #include "berberis/intrinsics/intrinsics_fixed_point_impl.h"
-#include "berberis/intrinsics/intrinsics_floating_point_impl.h"
 #endif
+#include "berberis/intrinsics/intrinsics_floating_point_impl.h"
 
 #endif  // BERBERIS_INTRINSICS_RISCV64_TO_ALL_INTRINSICS_H_
diff --git a/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
index b9cf29e3..9bdb9052 100644
--- a/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
+++ b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
@@ -27,7 +27,12 @@
 #include "berberis/base/bit_util.h"
 #include "berberis/base/dependent_false.h"
 #include "berberis/intrinsics/intrinsics.h"        // PreferredIntrinsicsImplementation
+#if defined(__aarch64__)
+#include "berberis/intrinsics/common/intrinsics_float.h"
+#include "berberis/intrinsics/vector_intrinsics.h"
+#else
 #include "berberis/intrinsics/intrinsics_float.h"  // Float32/Float64
+#endif
 #include "berberis/intrinsics/simd_register.h"
 #include "berberis/intrinsics/type_traits.h"
 
@@ -132,7 +137,7 @@ template <typename ElementType>
   return {result};
 }
 
-#ifndef __x86_64__
+#if !defined(__x86_64__) && !defined(__aarch64__)
 template <typename ElementType>
 [[nodiscard]] inline std::tuple<SIMD128Register> BitMaskToSimdMask(size_t mask) {
   return {BitMaskToSimdMaskForTests<ElementType>(mask)};
@@ -165,6 +170,7 @@ SimdMaskToBitMask(SIMD128Register simd_mask) {
 }
 #endif
 
+#if !defined(__aarch64__)
 template <auto kElement>
 [[nodiscard]] inline std::tuple<SIMD128Register> VectorMaskedElementToForTests(
     SIMD128Register simd_mask,
@@ -187,6 +193,8 @@ template <typename ElementType>
 }
 #endif
 
+#endif
+
 // For instructions that operate on carry bits, expands single bit from mask register
 //     into vector argument
 template <typename ElementType, TailProcessing vta, auto vma>
diff --git a/intrinsics/riscv64_to_all/intrinsic_def.json b/intrinsics/riscv64_to_all/intrinsic_def.json
index 6939f09d..4288d861 100644
--- a/intrinsics/riscv64_to_all/intrinsic_def.json
+++ b/intrinsics/riscv64_to_all/intrinsic_def.json
@@ -19,12 +19,12 @@
     "class": "template",
     "variants": [
       "int8_t",
-      "uint8_t",
       "int16_t",
-      "uint16_t",
       "int32_t",
-      "uint32_t",
       "int64_t",
+      "uint8_t",
+      "uint16_t",
+      "uint32_t",
       "uint64_t"
     ],
     "in": [ "int8_t", "Type0", "Type0" ],
@@ -183,12 +183,12 @@
     "class": "template",
     "variants": [
       "int8_t",
-      "uint8_t",
       "int16_t",
-      "uint16_t",
       "int32_t",
-      "uint32_t",
       "int64_t",
+      "uint8_t",
+      "uint16_t",
+      "uint32_t",
       "uint64_t"
     ],
     "in": [ "int8_t", "Type0", "Type0" ],
@@ -281,28 +281,12 @@
     "class": "template",
     "variants": [
       "int8_t",
-      "uint8_t",
       "int16_t",
-      "uint16_t",
       "int32_t",
-      "uint32_t",
       "int64_t",
-      "uint64_t"
-    ],
-    "in": [ "Type0", "Type0" ],
-    "out": [ "Type0" ]
-  },
-  "Rem": {
-    "comment": "Integer remainder",
-    "class": "template",
-    "variants": [
-      "int8_t",
       "uint8_t",
-      "int16_t",
       "uint16_t",
-      "int32_t",
       "uint32_t",
-      "int64_t",
       "uint64_t"
     ],
     "in": [ "Type0", "Type0" ],
@@ -399,60 +383,6 @@
     "in": [ "Type0", "Type0" ],
     "out": [ "Type0" ]
   },
-  "FeGetExceptions": {
-    "comment": "Read exceptions state from x87 status word and MXCSR.",
-    "class": "scalar",
-    "in": [],
-    "out": [ "uint64_t" ],
-    "side_effects_comment": "Reads state from host CPU. State may be affected to floating point instructions.",
-    "has_side_effects": true
-  },
-  "FeSetExceptions": {
-    "comment": "Store exceptions state into x87 status word and MXCSR. Only low five bits are set on input!",
-    "class": "scalar",
-    "in": [ "uint64_t" ],
-    "out": [],
-    "side_effects_comment": "Stores state to host CPU. State may be affected to floating point instructions.",
-    "has_side_effects": true
-  },
-  "FeSetExceptionsAndRound": {
-    "comment": "Store exceptions state into x87 status word and MXCSR. Only low five bits are set on input!",
-    "class": "scalar",
-    "in": [ "uint64_t", "uint8_t" ],
-    "out": [],
-    "side_effects_comment": "Stores state to host CPU. State may be affected to floating point instructions.",
-    "has_side_effects": true
-  },
-  "FeSetExceptionsImm": {
-    "comment": "Store exceptions state into x87 status word and MXCSR. Only low five bits are set on input!",
-    "class": "scalar",
-    "in": [ "uimm8" ],
-    "out": [],
-    "side_effects_comment": "Stores state to host CPU. State may be affected to floating point instructions.",
-    "has_side_effects": true
-  },
-  "FeSetExceptionsAndRoundImm": {
-    "comment": "Store exceptions state into x87 status word and MXCSR. Only low five bits are set on input!",
-    "class": "scalar",
-    "in": [ "uimm8" ],
-    "out": [],
-    "side_effects_comment": "Stores state to host CPU. State may be affected to floating point instructions.",
-    "has_side_effects": true
-  },
-  "FeSetRound": {
-    "comment": "Store guest rounding mode in the host FPU state. Only low three bits are set on input!",
-    "class": "scalar",
-    "in": [ "uint64_t" ],
-    "out": [],
-    "has_side_effects": true
-  },
-  "FeSetRoundImm": {
-    "comment": "Store guest rounding mode in the host FPU state. Only low three bits are set on input!",
-    "class": "scalar",
-    "in": [ "uimm8" ],
-    "out": [],
-    "has_side_effects": true
-  },
   "FMAdd": {
     "comment": "Fused multiply-addition",
     "class": "template",
@@ -592,22 +522,76 @@
     "in": [ "Type0", "Type0" ],
     "out": [ "Type0" ]
   },
+  "FeGetExceptions": {
+    "comment": "Read exceptions state from x87 status word and MXCSR.",
+    "class": "scalar",
+    "in": [],
+    "out": [ "uint64_t" ],
+    "side_effects_comment": "Reads state from host CPU. State may be affected to floating point instructions.",
+    "has_side_effects": true
+  },
+  "FeSetExceptions": {
+    "comment": "Store exceptions state into x87 status word and MXCSR. Only low five bits are set on input!",
+    "class": "scalar",
+    "in": [ "uint64_t" ],
+    "out": [],
+    "side_effects_comment": "Stores state to host CPU. State may be affected to floating point instructions.",
+    "has_side_effects": true
+  },
+  "FeSetExceptionsAndRound": {
+    "comment": "Store exceptions state into x87 status word and MXCSR. Only low five bits are set on input!",
+    "class": "scalar",
+    "in": [ "uint64_t", "uint8_t" ],
+    "out": [],
+    "side_effects_comment": "Stores state to host CPU. State may be affected to floating point instructions.",
+    "has_side_effects": true
+  },
+  "FeSetExceptionsAndRoundImm": {
+    "comment": "Store exceptions state into x87 status word and MXCSR. Only low five bits are set on input!",
+    "class": "scalar",
+    "in": [ "uimm8" ],
+    "out": [],
+    "side_effects_comment": "Stores state to host CPU. State may be affected to floating point instructions.",
+    "has_side_effects": true
+  },
+  "FeSetExceptionsImm": {
+    "comment": "Store exceptions state into x87 status word and MXCSR. Only low five bits are set on input!",
+    "class": "scalar",
+    "in": [ "uimm8" ],
+    "out": [],
+    "side_effects_comment": "Stores state to host CPU. State may be affected to floating point instructions.",
+    "has_side_effects": true
+  },
+  "FeSetRound": {
+    "comment": "Store guest rounding mode in the host FPU state. Only low three bits are set on input!",
+    "class": "scalar",
+    "in": [ "uint64_t" ],
+    "out": [],
+    "has_side_effects": true
+  },
+  "FeSetRoundImm": {
+    "comment": "Store guest rounding mode in the host FPU state. Only low three bits are set on input!",
+    "class": "scalar",
+    "in": [ "uimm8" ],
+    "out": [],
+    "has_side_effects": true
+  },
   "Feq": {
-    "comment": "Floating point comparison for \u201cequal\u201d (quiet comparison)",
+    "comment": "Floating point comparison for “equal” (quiet comparison)",
     "class": "template",
     "variants": [ "Float32", "Float64" ],
     "in": [ "Type0", "Type0" ],
     "out": [ "int64_t" ]
   },
   "Fle": {
-    "comment": "Floating point comparison for \u201cless of equal\u201d (signaling comparison)",
+    "comment": "Floating point comparison for “less of equal” (signaling comparison)",
     "class": "template",
     "variants": [ "Float32", "Float64" ],
     "in": [ "Type0", "Type0" ],
     "out": [ "int64_t" ]
   },
   "Flt": {
-    "comment": "Floating point comparison for \u201cless\u201d (quiet comparison)",
+    "comment": "Floating point comparison for “less” (quiet comparison)",
     "class": "template",
     "variants": [ "Float32", "Float64" ],
     "in": [ "Type0", "Type0" ],
@@ -662,6 +646,22 @@
     "in": [ "uint64_t" ],
     "out": [ "uint64_t" ]
   },
+  "Rem": {
+    "comment": "Integer remainder",
+    "class": "template",
+    "variants": [
+      "int8_t",
+      "int16_t",
+      "int32_t",
+      "int64_t",
+      "uint8_t",
+      "uint16_t",
+      "uint32_t",
+      "uint64_t"
+    ],
+    "in": [ "Type0", "Type0" ],
+    "out": [ "Type0" ]
+  },
   "Rev8": {
     "comment": "Byte reverse.",
     "class": "scalar",
@@ -671,14 +671,14 @@
   "Rol": {
     "comment": "Rotate left.",
     "class": "template",
-    "variants": [ "int64_t", "int32_t" ],
+    "variants": [ "int32_t", "int64_t" ],
     "in": [ "Type0", "int8_t" ],
     "out": [ "Type0" ]
   },
   "Ror": {
     "comment": "Rotate right.",
     "class": "template",
-    "variants": [ "int64_t", "int32_t" ],
+    "variants": [ "int32_t", "int64_t" ],
     "in": [ "Type0", "int8_t" ],
     "out": [ "Type0" ]
   },
@@ -687,12 +687,12 @@
     "class": "template",
     "variants": [
       "int8_t",
-      "uint8_t",
       "int16_t",
-      "uint16_t",
       "int32_t",
-      "uint32_t",
       "int64_t",
+      "uint8_t",
+      "uint16_t",
+      "uint32_t",
       "uint64_t"
     ],
     "in": [ "int8_t", "Type0", "Type0" ],
@@ -772,16 +772,16 @@
     "in": [ "uint64_t", "uimm16" ],
     "out": [ "uint64_t", "uint64_t" ]
   },
-  "Vsetvlmax": {
+  "Vsetvlimax": {
     "comment": "Test vtype and set vl accordingly.",
     "class": "scalar",
-    "in": [ "uint64_t" ],
+    "in": [ "uimm16" ],
     "out": [ "uint64_t", "uint64_t" ]
   },
-  "Vsetvlimax": {
+  "Vsetvlmax": {
     "comment": "Test vtype and set vl accordingly.",
     "class": "scalar",
-    "in": [ "uimm16" ],
+    "in": [ "uint64_t" ],
     "out": [ "uint64_t", "uint64_t" ]
   },
   "Vtestvl": {
diff --git a/intrinsics/riscv64_to_all/intrinsics.cc b/intrinsics/riscv64_to_all/intrinsics.cc
index e495e2b9..710396f6 100644
--- a/intrinsics/riscv64_to_all/intrinsics.cc
+++ b/intrinsics/riscv64_to_all/intrinsics.cc
@@ -37,11 +37,13 @@ std::tuple<uint64_t> Bseti(uint64_t src, uint8_t imm) {
   return {src | (uint64_t{1} << imm)};
 }
 
+#if defined(__x86_64__)
 std::tuple<uint64_t> CPUClockCount() {
   uint64_t a, d;
   asm volatile("rdtsc" : "=a"(a), "=d"(d));
   return (d << 32) | a;
 }
+#endif
 
 std::tuple<uint64_t> Slliuw(uint32_t src, uint8_t imm) {
   return {uint64_t{src} << imm};
diff --git a/intrinsics/riscv64_to_arm64/include/berberis/intrinsics/intrinsics.h b/intrinsics/riscv64_to_arm64/include/berberis/intrinsics/intrinsics.h
new file mode 100644
index 00000000..22cf62db
--- /dev/null
+++ b/intrinsics/riscv64_to_arm64/include/berberis/intrinsics/intrinsics.h
@@ -0,0 +1,165 @@
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
+// Once JIT is ready, this file should be automatically generated by
+// gen_text_asm_intrinsics.cc
+
+#ifndef RISCV64_TO_ARM64_BERBERIS_INTRINSICS_H_
+#define RISCV64_TO_ARM64_BERBERIS_INTRINSICS_H_
+
+#include <algorithm>
+#include <cstdint>
+#include <tuple>
+#include <type_traits>
+
+#include "berberis/intrinsics/riscv64_to_all/intrinsics.h"
+
+namespace berberis {
+
+namespace intrinsics {
+
+inline uint64_t ShiftedOne(uint64_t shift_amount) {
+  return uint64_t{1} << (shift_amount % 64);
+}
+
+inline std::tuple<uint64_t> Bclr(uint64_t in1, uint64_t in2) {
+  // Clear the specified bit.
+  return {in1 & ~ShiftedOne(in2)};
+};
+
+inline std::tuple<uint64_t> Bext(uint64_t in1, uint64_t in2) {
+  // Return whether the bit is set.
+  return {(in1 & ShiftedOne(in2)) ? 1 : 0};
+};
+
+inline std::tuple<uint64_t> Binv(uint64_t in1, uint64_t in2) {
+  // Toggle the specified bit.
+  return {in1 ^ ShiftedOne(in2)};
+};
+
+inline std::tuple<uint64_t> Bset(uint64_t in1, uint64_t in2) {
+  // Set the specified bit.
+  return {in1 | ShiftedOne(in2)};
+};
+
+template <typename T, enum PreferredIntrinsicsImplementation>
+inline std::tuple<T> Div(T in1, T in2) {
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
+inline std::tuple<T> Max(T in1, T in2) {
+  static_assert(std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>);
+  return {std::max(in1, in2)};
+};
+
+template <typename T, enum PreferredIntrinsicsImplementation>
+inline std::tuple<T> Min(T in1, T in2) {
+  static_assert(std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>);
+  return {std::min(in1, in2)};
+};
+
+template <typename T, enum PreferredIntrinsicsImplementation>
+inline std::tuple<T> Rem(T in1, T in2) {
+  static_assert(std::is_integral_v<T>);
+
+  if (in2 == 0) {
+    return {in1};
+  } else if (std::is_signed_v<T> && in2 == -1 && in1 == std::numeric_limits<T>::min()) {
+    return {0};
+  }
+  return {in1 % in2};
+};
+
+inline std::tuple<uint64_t> Rev8(uint64_t in1) {
+  return {__builtin_bswap64(in1)};
+};
+
+template <typename T, enum PreferredIntrinsicsImplementation>
+inline std::tuple<T> Rol(T in1, int8_t in2) {
+  static_assert(std::is_same_v<T, int32_t> || std::is_same_v<T, int64_t>);
+  // We need unsigned shifts, so that shifted-in bits are filled with zeroes.
+  if (std::is_same_v<T, int32_t>) {
+    return {(static_cast<uint32_t>(in1) << (in2 % 32)) |
+            (static_cast<uint32_t>(in1) >> (32 - (in2 % 32)))};
+  } else {
+    return {(static_cast<uint64_t>(in1) << (in2 % 64)) |
+            (static_cast<uint64_t>(in1) >> (64 - (in2 % 64)))};
+  }
+};
+
+template <typename T, enum PreferredIntrinsicsImplementation>
+inline std::tuple<T> Ror(T in1, int8_t in2) {
+  static_assert(std::is_same_v<T, int32_t> || std::is_same_v<T, int64_t>);
+  // We need unsigned shifts, so that shifted-in bits are filled with zeroes.
+  if (std::is_same_v<T, int32_t>) {
+    return {(static_cast<uint32_t>(in1) >> (in2 % 32)) |
+            (static_cast<uint32_t>(in1) << (32 - (in2 % 32)))};
+  } else {
+    return {(static_cast<uint64_t>(in1) >> (in2 % 64)) |
+            (static_cast<uint64_t>(in1) << (64 - (in2 % 64)))};
+  }
+};
+
+template <typename T, enum PreferredIntrinsicsImplementation>
+inline std::tuple<int64_t> Sext(T in1) {
+  static_assert(std::is_same_v<T, int8_t> || std::is_same_v<T, int16_t>);
+  return {static_cast<int64_t>(in1)};
+};
+
+inline std::tuple<uint64_t> Sh1add(uint64_t in1, uint64_t in2) {
+  return {uint64_t{in1} * 2 + in2};
+};
+
+inline std::tuple<uint64_t> Sh1adduw(uint32_t in1, uint64_t in2) {
+  return Sh1add(uint64_t{in1}, in2);
+};
+
+inline std::tuple<uint64_t> Sh2add(uint64_t in1, uint64_t in2) {
+  return {uint64_t{in1} * 4 + in2};
+};
+
+inline std::tuple<uint64_t> Sh2adduw(uint32_t in1, uint64_t in2) {
+  return Sh2add(uint64_t{in1}, in2);
+};
+
+inline std::tuple<uint64_t> Sh3add(uint64_t in1, uint64_t in2) {
+  return {uint64_t{in1} * 8 + in2};
+};
+
+inline std::tuple<uint64_t> Sh3adduw(uint32_t in1, uint64_t in2) {
+  return Sh3add(uint64_t{in1}, in2);
+};
+
+template <typename T, enum PreferredIntrinsicsImplementation>
+inline std::tuple<uint64_t> Zext(T in1) {
+  static_assert(std::is_same_v<T, uint32_t> || std::is_same_v<T, uint16_t> ||
+                std::is_same_v<T, uint8_t>);
+  return {static_cast<uint64_t>(in1)};
+};
+
+}  // namespace intrinsics
+
+}  // namespace berberis
+
+#endif  // RISCV64_TO_ARM64_BERBERIS_INTRINSICS_H_
diff --git a/intrinsics/riscv64_to_arm64/include/berberis/intrinsics/vector_intrinsics.h b/intrinsics/riscv64_to_arm64/include/berberis/intrinsics/vector_intrinsics.h
new file mode 100644
index 00000000..f203dee0
--- /dev/null
+++ b/intrinsics/riscv64_to_arm64/include/berberis/intrinsics/vector_intrinsics.h
@@ -0,0 +1,36 @@
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
+#ifndef RISCV64_TO_ARM64_BERBERIS_INTRINSICS_VECTOR_INTRINSICS_H_
+#define RISCV64_TO_ARM64_BERBERIS_INTRINSICS_VECTOR_INTRINSICS_H_
+
+#include "berberis/intrinsics/simd_register.h"
+
+namespace berberis::intrinsics {
+
+template <typename ElementType>
+[[nodiscard, gnu::pure]] inline std::tuple<SIMD128Register> BitMaskToSimdMask(
+    [[maybe_unused]] size_t mask) {
+  SIMD128Register result;
+  abort();
+  return {result};
+}
+
+}  // namespace berberis::intrinsics
+
+#include "berberis/intrinsics/riscv64_to_all/vector_intrinsics.h"
+
+#endif  // RISCV64_TO_ARM64_BERBERIS_INTRINSICS_VECTOR_INTRINSICS_H_
\ No newline at end of file
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
index 3035ae0c..87a3b3ea 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
@@ -44,7 +44,7 @@ class MacroAssembler : public Assembler {
   }
 
 #define DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
-#include "berberis/intrinsics/macro_assembler-inl.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h"
 
   void PNot(XMMRegister result) {
     Pandn(result, {.disp = constants_pool::kVectorConst<uint8_t{0b1111'1111}>});
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h
index 4e948359..66ce200e 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h
@@ -83,8 +83,9 @@ void MacroAssembler<Assembler>::MacroDiv(Register src) {
   Bind(done);
 }
 
-// Divisor comes in "src", dividend comes in gpr_a, remainder is returned in gpr_d.
-// gpr_a and FLAGS are clobbered by that macroinstruction.
+// Divisor comes in "src", dividend comes in gpr_a.
+// For 16/32/64-bit: remainder is returned in gpr_d. gpr_a and FLAGS are clobbered.
+// For 8-bit: remainder is returned in gpr_a. FLAGS are clobbered.
 template <typename Assembler>
 template <typename IntType>
 void MacroAssembler<Assembler>::MacroRem(Register src) {
@@ -142,10 +143,8 @@ void MacroAssembler<Assembler>::MacroRem(Register src) {
   Jmp(*done);
 
   Bind(zero);
-  if constexpr (std::is_same_v<IntType, uint8_t> || std::is_same_v<IntType, int8_t>) {
-    Mov<int8_t>(gpr_a, src);
-  } else {
-    Mov<IntType>(gpr_d, src);
+  if constexpr (!std::is_same_v<IntType, uint8_t> && !std::is_same_v<IntType, int8_t>) {
+    Mov<IntType>(gpr_d, gpr_a);
   }
   Jmp(*done);
 
diff --git a/intrinsics/riscv64_to_x86_64/macro_def.json b/intrinsics/riscv64_to_x86_64/macro_def.json
index 1420d4aa..55b96e0d 100644
--- a/intrinsics/riscv64_to_x86_64/macro_def.json
+++ b/intrinsics/riscv64_to_x86_64/macro_def.json
@@ -197,92 +197,6 @@
       "asm": "MacroDiv<uint64_t>",
       "mnemo": "MACRO_UDIV64"
     },
-    {
-      "name": "RemInt8",
-      "args": [
-        { "class": "GeneralReg8", "usage": "use" },
-        { "class": "AX", "usage": "use_def" },
-        { "class": "FLAGS", "usage": "def" }
-      ],
-      "asm": "MacroRem<int8_t>",
-      "mnemo": "MACRO_REM8"
-    },
-    {
-      "name": "RemInt16",
-      "args": [
-        { "class": "GeneralReg16", "usage": "use" },
-        { "class": "AX", "usage": "use_def" },
-        { "class": "DX", "usage": "def_early_clobber" },
-        { "class": "FLAGS", "usage": "def" }
-      ],
-      "asm": "MacroRem<int16_t>",
-      "mnemo": "MACRO_REM16"
-    },
-    {
-      "name": "RemInt32",
-      "args": [
-        { "class": "GeneralReg32", "usage": "use" },
-        { "class": "EAX", "usage": "use_def" },
-        { "class": "EDX", "usage": "def_early_clobber" },
-        { "class": "FLAGS", "usage": "def" }
-      ],
-      "asm": "MacroRem<int32_t>",
-      "mnemo": "MACRO_REM32"
-    },
-    {
-      "name": "RemInt64",
-      "args": [
-        { "class": "GeneralReg64", "usage": "use" },
-        { "class": "EAX", "usage": "use_def" },
-        { "class": "EDX", "usage": "def_early_clobber" },
-        { "class": "FLAGS", "usage": "def" }
-      ],
-      "asm": "MacroRem<int64_t>",
-      "mnemo": "MACRO_REM64"
-    },
-    {
-      "name": "RemUInt8",
-      "args": [
-        { "class": "GeneralReg8", "usage": "use" },
-        { "class": "AX", "usage": "use_def" },
-        { "class": "FLAGS", "usage": "def" }
-      ],
-      "asm": "MacroRem<uint8_t>",
-      "mnemo": "MACRO_UREM8"
-    },
-    {
-      "name": "RemUInt16",
-      "args": [
-        { "class": "GeneralReg16", "usage": "use" },
-        { "class": "AX", "usage": "use_def" },
-        { "class": "DX", "usage": "def_early_clobber" },
-        { "class": "FLAGS", "usage": "def" }
-      ],
-      "asm": "MacroRem<uint16_t>",
-      "mnemo": "MACRO_UREM16"
-    },
-    {
-      "name": "RemUInt32",
-      "args": [
-        { "class": "GeneralReg32", "usage": "use" },
-        { "class": "EAX", "usage": "use_def" },
-        { "class": "EDX", "usage": "def_early_clobber" },
-        { "class": "FLAGS", "usage": "def" }
-      ],
-      "asm": "MacroRem<uint32_t>",
-      "mnemo": "MACRO_UREM32"
-    },
-    {
-      "name": "RemUInt64",
-      "args": [
-        { "class": "GeneralReg64", "usage": "use" },
-        { "class": "EAX", "usage": "use_def" },
-        { "class": "EDX", "usage": "def_early_clobber" },
-        { "class": "FLAGS", "usage": "def" }
-      ],
-      "asm": "MacroRem<uint64_t>",
-      "mnemo": "MACRO_UREM64"
-    },
     {
       "name": "MacroFCvtFloat32ToInt32",
       "args": [
@@ -319,48 +233,6 @@
       "asm": "MacroFCvtFloatToInteger<int64_t, intrinsics::Float64>",
       "mnemo": "MACRO_FCvtFloatToInteger"
     },
-    {
-      "name": "MacroFeqFloat32",
-      "args": [
-        { "class": "GeneralReg64", "usage": "def" },
-        { "class": "FpReg32", "usage": "use_def" },
-        { "class": "FpReg32", "usage": "use" }
-      ],
-      "asm": "MacroFeq<intrinsics::Float32>",
-      "mnemo": "MACRO_FEQ_F32"
-    },
-    {
-      "name": "MacroFeqFloat32AVX",
-      "args": [
-        { "class": "GeneralReg64", "usage": "def" },
-        { "class": "FpReg32", "usage": "use" },
-        { "class": "FpReg32", "usage": "use" },
-        { "class": "FpReg32", "usage": "def" }
-      ],
-      "asm": "MacroFeqAVX<intrinsics::Float32>",
-      "mnemo": "MACRO_FEQ_F32"
-    },
-    {
-      "name": "MacroFeqFloat64",
-      "args": [
-        { "class": "GeneralReg64", "usage": "def" },
-        { "class": "FpReg64", "usage": "use_def" },
-        { "class": "FpReg64", "usage": "use" }
-      ],
-      "asm": "MacroFeq<intrinsics::Float64>",
-      "mnemo": "MACRO_FEQ_F64"
-    },
-    {
-      "name": "MacroFeqFloat64AVX",
-      "args": [
-        { "class": "GeneralReg64", "usage": "def" },
-        { "class": "FpReg64", "usage": "use" },
-        { "class": "FpReg64", "usage": "use" },
-        { "class": "FpReg64", "usage": "def" }
-      ],
-      "asm": "MacroFeqAVX<intrinsics::Float64>",
-      "mnemo": "MACRO_FEQ_F64"
-    },
     {
       "name": "MacroFeGetExceptionsTranslate",
       "args": [
@@ -430,6 +302,48 @@
       "asm": "MacroFeSetRoundImmTranslate",
       "mnemo": "MACRO_FE_SET_ROUND"
     },
+    {
+      "name": "MacroFeqFloat32",
+      "args": [
+        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "FpReg32", "usage": "use_def" },
+        { "class": "FpReg32", "usage": "use" }
+      ],
+      "asm": "MacroFeq<intrinsics::Float32>",
+      "mnemo": "MACRO_FEQ_F32"
+    },
+    {
+      "name": "MacroFeqFloat32AVX",
+      "args": [
+        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "FpReg32", "usage": "use" },
+        { "class": "FpReg32", "usage": "use" },
+        { "class": "FpReg32", "usage": "def" }
+      ],
+      "asm": "MacroFeqAVX<intrinsics::Float32>",
+      "mnemo": "MACRO_FEQ_F32"
+    },
+    {
+      "name": "MacroFeqFloat64",
+      "args": [
+        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "FpReg64", "usage": "use_def" },
+        { "class": "FpReg64", "usage": "use" }
+      ],
+      "asm": "MacroFeq<intrinsics::Float64>",
+      "mnemo": "MACRO_FEQ_F64"
+    },
+    {
+      "name": "MacroFeqFloat64AVX",
+      "args": [
+        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "FpReg64", "usage": "use" },
+        { "class": "FpReg64", "usage": "use" },
+        { "class": "FpReg64", "usage": "def" }
+      ],
+      "asm": "MacroFeqAVX<intrinsics::Float64>",
+      "mnemo": "MACRO_FEQ_F64"
+    },
     {
       "name": "MacroFleFloat32",
       "args": [
@@ -612,6 +526,92 @@
       "asm": "MacroOrcbAVX",
       "mnemo": "MACRO_ORCB"
     },
+    {
+      "name": "RemInt8",
+      "args": [
+        { "class": "GeneralReg8", "usage": "use" },
+        { "class": "AX", "usage": "use_def" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "MacroRem<int8_t>",
+      "mnemo": "MACRO_REM8"
+    },
+    {
+      "name": "RemInt16",
+      "args": [
+        { "class": "GeneralReg16", "usage": "use" },
+        { "class": "AX", "usage": "use_def" },
+        { "class": "DX", "usage": "def_early_clobber" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "MacroRem<int16_t>",
+      "mnemo": "MACRO_REM16"
+    },
+    {
+      "name": "RemInt32",
+      "args": [
+        { "class": "GeneralReg32", "usage": "use" },
+        { "class": "EAX", "usage": "use_def" },
+        { "class": "EDX", "usage": "def_early_clobber" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "MacroRem<int32_t>",
+      "mnemo": "MACRO_REM32"
+    },
+    {
+      "name": "RemInt64",
+      "args": [
+        { "class": "GeneralReg64", "usage": "use" },
+        { "class": "EAX", "usage": "use_def" },
+        { "class": "EDX", "usage": "def_early_clobber" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "MacroRem<int64_t>",
+      "mnemo": "MACRO_REM64"
+    },
+    {
+      "name": "RemUInt8",
+      "args": [
+        { "class": "GeneralReg8", "usage": "use" },
+        { "class": "AX", "usage": "use_def" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "MacroRem<uint8_t>",
+      "mnemo": "MACRO_UREM8"
+    },
+    {
+      "name": "RemUInt16",
+      "args": [
+        { "class": "GeneralReg16", "usage": "use" },
+        { "class": "AX", "usage": "use_def" },
+        { "class": "DX", "usage": "def_early_clobber" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "MacroRem<uint16_t>",
+      "mnemo": "MACRO_UREM16"
+    },
+    {
+      "name": "RemUInt32",
+      "args": [
+        { "class": "GeneralReg32", "usage": "use" },
+        { "class": "EAX", "usage": "use_def" },
+        { "class": "EDX", "usage": "def_early_clobber" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "MacroRem<uint32_t>",
+      "mnemo": "MACRO_UREM32"
+    },
+    {
+      "name": "RemUInt64",
+      "args": [
+        { "class": "GeneralReg64", "usage": "use" },
+        { "class": "EAX", "usage": "use_def" },
+        { "class": "EDX", "usage": "def_early_clobber" },
+        { "class": "FLAGS", "usage": "def" }
+      ],
+      "asm": "MacroRem<uint64_t>",
+      "mnemo": "MACRO_UREM64"
+    },
     {
       "name": "Sh1add",
       "args": [
diff --git a/jni/include/berberis/jni/jni_trampolines.h b/jni/include/berberis/jni/jni_trampolines.h
index 5cefb3b7..3a371895 100644
--- a/jni/include/berberis/jni/jni_trampolines.h
+++ b/jni/include/berberis/jni/jni_trampolines.h
@@ -31,10 +31,10 @@ HostCode WrapGuestJNIFunction(GuestAddr pc,
                               bool has_jnienv_and_jobject);
 HostCode WrapGuestJNIOnLoad(GuestAddr pc);
 
-GuestType<JNIEnv*> ToGuestJNIEnv(void* host_jni_env);
+GuestType<JNIEnv*> ToGuestJNIEnv(JNIEnv* host_jni_env);
 JNIEnv* ToHostJNIEnv(GuestType<JNIEnv*> guest_jni_env);
 
-GuestType<JavaVM*> ToGuestJavaVM(void* host_java_vm);
+GuestType<JavaVM*> ToGuestJavaVM(JavaVM* host_java_vm);
 JavaVM* ToHostJavaVM(GuestType<JavaVM*> guest_java_vm);
 
 }  // namespace berberis
diff --git a/jni/jni_trampolines.cc b/jni/jni_trampolines.cc
index c2ca4d6e..10e289a2 100644
--- a/jni/jni_trampolines.cc
+++ b/jni/jni_trampolines.cc
@@ -16,17 +16,26 @@
 
 #include "berberis/jni/jni_trampolines.h"
 
+#include <cstdint>
+#include <cstring>
+#include <deque>
+#include <map>
+#include <mutex>
 #include <vector>
 
 #include <jni.h>  // NOLINT [build/include_order]
 
+#include "berberis/base/checks.h"
 #include "berberis/base/logging.h"
+#include "berberis/base/tracing.h"
 #include "berberis/guest_abi/function_wrappers.h"
 #include "berberis/guest_abi/guest_arguments.h"
 #include "berberis/guest_abi/guest_params.h"
+#include "berberis/guest_abi/guest_type.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/guest_state/guest_state.h"
 #include "berberis/native_bridge/jmethod_shorty.h"
+#include "berberis/runtime_primitives/host_code.h"
 #include "berberis/runtime_primitives/runtime_library.h"
 
 #include "guest_jni_trampolines.h"
@@ -111,10 +120,10 @@ HostCode WrapGuestJNIFunction(GuestAddr pc,
                               const char* shorty,
                               const char* name,
                               bool has_jnienv_and_jobject) {
-  const int kMaxSignatureSize = 128;
-  char signature[kMaxSignatureSize];
+  const size_t size = strlen(shorty);
+  char signature[size + /* env, clazz and trailing zero */ 3];
   ConvertDalvikShortyToWrapperSignature(
-      signature, kMaxSignatureSize, shorty, has_jnienv_and_jobject);
+      signature, sizeof(signature), shorty, has_jnienv_and_jobject);
   auto guest_runner = has_jnienv_and_jobject ? RunGuestJNIFunction : RunGuestCall;
   return WrapGuestFunctionImpl(pc, signature, guest_runner, name);
 }
@@ -164,7 +173,7 @@ std::vector<jvalue> ConvertVAList(JNIEnv* env, jmethodID methodID, GuestVAListPa
         arg.l = params.GetParam<jobject>();
         break;
       default:
-        LOG_ALWAYS_FATAL("Failed to convert Dalvik char '%c'", c);
+        FATAL("Failed to convert Dalvik char '%c'", c);
         break;
     }
   }
@@ -218,6 +227,25 @@ struct KnownMethodTrampoline {
 
 #include "jni_trampolines-inl.h"  // NOLINT(build/include)
 
+// According to our observations there is only one instance of JavaVM
+// and there are 1 or sometimes more instances of JNIEnv per thread created
+// by Java Runtime (JNIEnv instances are not shared between different threads).
+//
+// This is why we store one global mapping for JavaVM for the app.
+// And multiple mappings of JNIEnv per thread. There is often only one JNIEnv
+// per thread, but we have seen examples where 2 instances where created.
+//
+// It is likely that the new JNIEnv instance for the thread supersedes the
+// previous one but the code below does not make this assumption.
+std::mutex g_java_vm_guard_mutex;
+
+JavaVM g_guest_java_vm;
+JavaVM* g_host_java_vm;
+
+thread_local std::deque<JNIEnv> g_guest_jni_envs;
+thread_local std::map<GuestType<JNIEnv*>, JNIEnv*> g_guest_to_host_jni_env;
+thread_local std::map<JNIEnv*, GuestType<JNIEnv*>> g_host_to_guest_jni_env;
+
 void DoJavaVMTrampoline_DestroyJavaVM(HostCode /* callee */, ProcessState* state) {
   using PFN_callee = decltype(std::declval<JavaVM>().functions->DestroyJavaVM);
   auto [arg_vm] = GuestParamsValues<PFN_callee>(state);
@@ -263,7 +291,7 @@ void DoJavaVMTrampoline_GetEnv(HostCode /* callee */, ProcessState* state) {
   auto&& [ret] = GuestReturnReference<PFN_callee>(state);
   ret = (arg_java_vm->functions)->GetEnv(arg_java_vm, &env, arg_version);
 
-  GuestType<JNIEnv*> guest_jni_env = ToGuestJNIEnv(env);
+  GuestType<JNIEnv*> guest_jni_env = ToGuestJNIEnv(static_cast<JNIEnv*>(env));
   memcpy(arg_env_ptr, &guest_jni_env, sizeof(guest_jni_env));
 
   LOG_JNI("= jint(%d)", ret);
@@ -310,7 +338,7 @@ std::atomic<uint32_t> g_java_vm_wrapped = {0};
 
 }  // namespace
 
-GuestType<JNIEnv*> ToGuestJNIEnv(void* host_jni_env) {
+GuestType<JNIEnv*> ToGuestJNIEnv(JNIEnv* host_jni_env) {
   if (!host_jni_env) {
     return 0;
   }
@@ -325,24 +353,73 @@ GuestType<JNIEnv*> ToGuestJNIEnv(void* host_jni_env) {
     WrapJNIEnv(host_jni_env);
     std::atomic_store_explicit(&g_jni_env_wrapped, 1U, std::memory_order_release);
   }
-  return static_cast<JNIEnv*>(host_jni_env);
+
+  auto it = g_host_to_guest_jni_env.find(host_jni_env);
+  if (it != g_host_to_guest_jni_env.end()) {
+    return it->second;
+  }
+
+  g_guest_jni_envs.emplace_back(*host_jni_env);
+  JNIEnv* guest_jni_env = &g_guest_jni_envs.back();
+  auto [unused_it1, host_to_guest_inserted] =
+      g_host_to_guest_jni_env.try_emplace(host_jni_env, guest_jni_env);
+  CHECK(host_to_guest_inserted);
+
+  auto [unused_it2, guest_to_host_inserted] =
+      g_guest_to_host_jni_env.try_emplace(guest_jni_env, host_jni_env);
+  CHECK(guest_to_host_inserted);
+
+  return guest_jni_env;
 }
 
 JNIEnv* ToHostJNIEnv(GuestType<JNIEnv*> guest_jni_env) {
-  return static_cast<JNIEnv*>(guest_jni_env);
+  auto it = g_guest_to_host_jni_env.find(guest_jni_env);
+
+  if (it == g_guest_to_host_jni_env.end()) {
+    ALOGE("Unexpected guest JNIEnv: %p (it was never passed to guest), passing to host 'as is'",
+          ToHostAddr(guest_jni_env));
+    TRACE("Unexpected guest JNIEnv: %p (it was never passed to guest), passing to host 'as is'",
+          ToHostAddr(guest_jni_env));
+    return ToHostAddr(guest_jni_env);
+  }
+
+  return it->second;
 }
 
-GuestType<JavaVM*> ToGuestJavaVM(void* host_java_vm) {
+GuestType<JavaVM*> ToGuestJavaVM(JavaVM* host_java_vm) {
   CHECK(host_java_vm);
   if (std::atomic_load_explicit(&g_java_vm_wrapped, std::memory_order_acquire) == 0U) {
     WrapJavaVM(host_java_vm);
     std::atomic_store_explicit(&g_java_vm_wrapped, 1U, std::memory_order_release);
   }
-  return static_cast<JavaVM*>(host_java_vm);
+
+  std::lock_guard<std::mutex> lock(g_java_vm_guard_mutex);
+  if (g_host_java_vm == nullptr) {
+    g_guest_java_vm = *host_java_vm;
+    g_host_java_vm = host_java_vm;
+  }
+
+  if (g_host_java_vm != host_java_vm) {
+    TRACE("Warning: Unexpected host JavaVM: %p (expecting %p), passing as is",
+          host_java_vm,
+          g_host_java_vm);
+    return host_java_vm;
+  }
+
+  return &g_guest_java_vm;
 }
 
 JavaVM* ToHostJavaVM(GuestType<JavaVM*> guest_java_vm) {
-  return static_cast<JavaVM*>(guest_java_vm);
+  std::lock_guard<std::mutex> lock(g_java_vm_guard_mutex);
+  if (ToHostAddr(guest_java_vm) == &g_guest_java_vm) {
+    return g_host_java_vm;
+  }
+
+  TRACE("Warning: Unexpected guest JavaVM: %p (expecting %p), passing as is",
+        ToHostAddr(guest_java_vm),
+        &g_guest_java_vm);
+
+  return ToHostAddr(guest_java_vm);
 }
 
 }  // namespace berberis
diff --git a/kernel_api/open_emulation.cc b/kernel_api/open_emulation.cc
index 8a72e33e..d3e39735 100644
--- a/kernel_api/open_emulation.cc
+++ b/kernel_api/open_emulation.cc
@@ -31,6 +31,7 @@
 #include "berberis/base/arena_vector.h"
 #include "berberis/base/checks.h"
 #include "berberis/base/fd.h"
+#include "berberis/base/forever_alloc.h"
 #include "berberis/base/tracing.h"
 #include "berberis/guest_os_primitives/guest_map_shadow.h"
 #include "berberis/guest_state/guest_addr.h"
@@ -45,8 +46,8 @@ class EmulatedFileDescriptors {
   explicit EmulatedFileDescriptors() : fds_(&arena_) {}
 
   static EmulatedFileDescriptors* GetInstance() {
-    static EmulatedFileDescriptors g_emulated_proc_self_maps_fds;
-    return &g_emulated_proc_self_maps_fds;
+    static auto* g_emulated_proc_self_maps_fds = NewForever<EmulatedFileDescriptors>();
+    return g_emulated_proc_self_maps_fds;
   }
 
   // Not copyable or movable.
diff --git a/lite_translator/include/berberis/lite_translator/lite_translate_region.h b/lite_translator/include/berberis/lite_translator/lite_translate_region.h
index be48ef5e..9de2fdae 100644
--- a/lite_translator/include/berberis/lite_translator/lite_translate_region.h
+++ b/lite_translator/include/berberis/lite_translator/lite_translate_region.h
@@ -34,7 +34,7 @@ struct LiteTranslateParams {
   uint32_t* counter_location = nullptr;
   uint32_t counter_threshold = config::kGearSwitchThreshold;
   HostCode counter_threshold_callback =
-      AsHostCode(berberis::berberis_entry_HandleLightCounterThresholdReached);
+      AsHostCode(berberis::berberis_entry_HandleLiteCounterThresholdReached);
 };
 
 bool LiteTranslateRange(GuestAddr start_pc,
diff --git a/lite_translator/riscv64_to_x86_64/lite_translate_region_exec_tests.cc b/lite_translator/riscv64_to_x86_64/lite_translate_region_exec_tests.cc
index 0f0903ad..86bc665b 100644
--- a/lite_translator/riscv64_to_x86_64/lite_translate_region_exec_tests.cc
+++ b/lite_translator/riscv64_to_x86_64/lite_translate_region_exec_tests.cc
@@ -125,7 +125,7 @@ TEST_F(Riscv64LiteTranslateRegionTest, GracefulFailure) {
 jmp_buf g_jmp_buf;
 
 extern "C" __attribute__((used, __visibility__("hidden"))) void
-LightTranslateRegionTest_HandleThresholdReached() {
+LiteTranslateRegionTest_HandleThresholdReached() {
   // We are in generated code, so the easiest way to recover without using
   // runtime library internals is to longjmp.
   longjmp(g_jmp_buf, 1);
@@ -135,7 +135,7 @@ LightTranslateRegionTest_HandleThresholdReached() {
 // need this proxy to normal C++ ABI function. Stack in generated code is
 // aligned properly for calls.
 __attribute__((naked)) void CounterThresholdReached() {
-  asm(R"(call LightTranslateRegionTest_HandleThresholdReached)");
+  asm(R"(call LiteTranslateRegionTest_HandleThresholdReached)");
 }
 
 TEST_F(Riscv64LiteTranslateRegionTest, ProfileCounter) {
diff --git a/program_runner/Android.bp b/program_runner/Android.bp
index f9f93e88..21bf325d 100644
--- a/program_runner/Android.bp
+++ b/program_runner/Android.bp
@@ -60,6 +60,7 @@ cc_defaults {
         "libberberis_interpreter_riscv64",
         "libberberis_kernel_api_riscv64",
         "libberberis_tinyloader",
+        "libberberis_intrinsics_riscv64",
     ],
     shared_libs: [
         "libbase",
diff --git a/proxy_loader/proxy_loader.cc b/proxy_loader/proxy_loader.cc
index b2133840..ae557bbe 100644
--- a/proxy_loader/proxy_loader.cc
+++ b/proxy_loader/proxy_loader.cc
@@ -22,7 +22,8 @@
 #include <mutex>
 #include <string>
 
-#include "berberis/base/logging.h"
+#include "berberis/base/checks.h"
+#include "berberis/base/forever_alloc.h"
 #include "berberis/base/tracing.h"
 #include "berberis/proxy_loader/proxy_library_builder.h"
 
@@ -63,16 +64,15 @@ void InterceptGuestSymbol(GuestAddr addr,
                           const char* library_name,
                           const char* name,
                           const char* proxy_prefix) {
-  static std::mutex g_guard_mutex;
-  std::lock_guard<std::mutex> guard(g_guard_mutex);
+  static auto* g_mutex = NewForever<std::mutex>();
+  std::lock_guard<std::mutex> guard(*g_mutex);
 
   using Libraries = std::map<std::string, ProxyLibraryBuilder>;
-  static Libraries g_libraries;
+  static auto* g_libraries = NewForever<Libraries>();
 
-  auto res = g_libraries.insert({library_name, {}});
+  auto res = g_libraries->insert({library_name, {}});
   if (res.second && !LoadProxyLibrary(&res.first->second, library_name, proxy_prefix)) {
-    LOG_ALWAYS_FATAL(
-        "Unable to load library \"%s\" (upon using symbol \"%s\")", library_name, name);
+    FATAL("Unable to load library \"%s\" (upon using symbol \"%s\")", library_name, name);
   }
 
   res.first->second.InterceptSymbol(addr, name);
diff --git a/runtime/Android.bp b/runtime/Android.bp
index c94e7905..1f0d3033 100644
--- a/runtime/Android.bp
+++ b/runtime/Android.bp
@@ -19,11 +19,18 @@ package {
 
 cc_library_headers {
     name: "libberberis_runtime_headers",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     export_include_dirs: ["include"],
 }
 
+filegroup {
+    name: "berberis_runtime_library_arm64_srcs",
+    srcs: [
+        "runtime_library_arm64.cc",
+    ],
+}
+
 filegroup {
     name: "berberis_runtime_library_x86_64_srcs",
     srcs: [
@@ -41,60 +48,28 @@ filegroup {
 cc_defaults {
     name: "berberis_runtime_library_defaults",
     arch: {
+        arm64: {
+            srcs: [":berberis_runtime_library_arm64_srcs"],
+        },
         x86_64: {
             srcs: [":berberis_runtime_library_x86_64_srcs"],
-            header_libs: [
-                "libberberis_base_headers",
-                "libberberis_runtime_primitives_headers",
-            ],
         },
         riscv64: {
             srcs: [":berberis_runtime_library_riscv64_srcs"],
-            header_libs: [
-                "libberberis_base_headers",
-                "libberberis_runtime_primitives_headers",
-            ],
         },
     },
-    // Targets using these defaults must provide the following guest-specific fields:
-    // header_libs: ["libberberis_guest_state_<guest>_headers"],
-    // export_header_lib_headers: ["libberberis_guest_state_<guest>_headers"],
-}
-
-cc_library_static {
-    name: "libberberis_runtime_riscv64_to_x86_64",
-    defaults: [
-        "berberis_defaults_64",
-        "berberis_runtime_library_defaults",
-    ],
-    host_supported: true,
-    srcs: [
-        "init_guest_arch.cc",
-        "run_guest_call_riscv64.cc",
-        "translator_riscv64.cc",
-    ],
-    whole_static_libs: ["libberberis_runtime"],
     header_libs: [
         "libberberis_base_headers",
-        "libberberis_calling_conventions_headers",
-        "libberberis_guest_abi_riscv64_headers",
-        "libberberis_guest_os_primitives_headers",
-        "libberberis_guest_state_riscv64_headers",
-        "libberberis_heavy_optimizer_riscv64_headers",
-        "libberberis_instrument_headers",
-        "libberberis_interpreter_riscv64_headers",
-        "libberberis_lite_translator_headers",
-        "libberberis_runtime_headers",
         "libberberis_runtime_primitives_headers",
     ],
-    export_header_lib_headers: [
-        "libberberis_runtime_headers",
-    ],
+    // Targets using these defaults must provide the following guest-specific fields:
+    // header_libs: ["libberberis_guest_state_<guest>_headers"],
+    // export_header_lib_headers: ["libberberis_guest_state_<guest>_headers"],
 }
 
 cc_library_static {
     name: "libberberis_runtime",
-    defaults: ["berberis_defaults"],
+    defaults: ["berberis_all_hosts_defaults"],
     host_supported: true,
     header_libs: [
         "libberberis_base_headers",
@@ -114,20 +89,3 @@ cc_library_static {
         "translator.cc",
     ],
 }
-
-cc_test_library {
-    name: "libberberis_runtime_riscv64_unit_tests",
-    defaults: ["berberis_test_library_defaults_64"],
-    srcs: [
-        "execute_guest_test.cc",
-        "translator_riscv64_test.cc",
-    ],
-    header_libs: [
-        "libberberis_base_headers",
-        "libberberis_guest_state_riscv64_headers",
-        "libberberis_runtime_headers",
-        "libberberis_guest_os_primitives_headers",
-        "libberberis_lite_translator_headers",
-        "libberberis_runtime_primitives_headers",
-    ],
-}
diff --git a/runtime/execute_guest.cc b/runtime/execute_guest.cc
index 18d35bcb..6d766f3a 100644
--- a/runtime/execute_guest.cc
+++ b/runtime/execute_guest.cc
@@ -59,7 +59,7 @@ void ExecuteGuest(ThreadState* state) {
     }
 
     // ATTENTION: this should be the only place to run translated code!
-    berberis_RunGeneratedCode(state, code);
+    berberis_RunGeneratedCode(state, AsHostCode(code));
   }
 }
 
diff --git a/runtime/include/berberis/runtime/translator.h b/runtime/include/berberis/runtime/translator.h
index e7ebd53b..9aea364f 100644
--- a/runtime/include/berberis/runtime/translator.h
+++ b/runtime/include/berberis/runtime/translator.h
@@ -17,14 +17,10 @@
 #ifndef BERBERIS_RUNTIME_TRANSLATOR_H_
 #define BERBERIS_RUNTIME_TRANSLATOR_H_
 
-#include "berberis/guest_state/guest_addr.h"
-
 namespace berberis {
 
 void InitTranslator();
 
-void TranslateRegionAtFirstGear(GuestAddr pc);
-
 }  // namespace berberis
 
 #endif  // BERBERIS_RUNTIME_TRANSLATOR_H_
diff --git a/runtime/riscv64/Android.bp b/runtime/riscv64/Android.bp
new file mode 100644
index 00000000..0685d68e
--- /dev/null
+++ b/runtime/riscv64/Android.bp
@@ -0,0 +1,88 @@
+// Copyright (C) 2024 The Android Open Source Project
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
+cc_library_static {
+    name: "libberberis_runtime_riscv64",
+    defaults: [
+        "berberis_all_hosts_defaults_64",
+        "berberis_runtime_library_defaults",
+    ],
+    host_supported: true,
+    arch: {
+        arm64: {
+            srcs: [
+                "translator_arm64.cc",
+            ],
+        },
+        x86_64: {
+            srcs: [
+                "translator_x86_64.cc",
+            ],
+            header_libs: [
+                "libberberis_heavy_optimizer_riscv64_headers",
+                "libberberis_lite_translator_headers",
+            ],
+        },
+    },
+    srcs: [
+        "init_guest_arch.cc",
+        "run_guest_call.cc",
+        "translator.cc",
+    ],
+    whole_static_libs: ["libberberis_runtime"],
+    header_libs: [
+        "libberberis_base_headers",
+        "libberberis_calling_conventions_headers",
+        "libberberis_guest_abi_riscv64_headers",
+        "libberberis_guest_os_primitives_headers",
+        "libberberis_guest_state_riscv64_headers",
+        "libberberis_instrument_headers",
+        "libberberis_interpreter_riscv64_headers",
+        "libberberis_runtime_headers",
+        "libberberis_runtime_primitives_headers",
+    ],
+    export_header_lib_headers: [
+        "libberberis_runtime_headers",
+    ],
+}
+
+cc_test_library {
+    name: "libberberis_runtime_riscv64_unit_tests",
+    defaults: ["berberis_test_library_defaults_64"],
+    arch: {
+        x86_64: {
+            srcs: [
+                "translator_x86_64_test.cc",
+            ],
+            header_libs: [
+                "libberberis_lite_translator_headers",
+            ],
+        },
+    },
+    srcs: [
+        "execute_guest_test.cc",
+    ],
+    header_libs: [
+        "libberberis_base_headers",
+        "libberberis_guest_os_primitives_headers",
+        "libberberis_guest_state_riscv64_headers",
+        "libberberis_runtime_headers",
+        "libberberis_runtime_primitives_headers",
+    ],
+}
diff --git a/runtime/execute_guest_test.cc b/runtime/riscv64/execute_guest_test.cc
similarity index 100%
rename from runtime/execute_guest_test.cc
rename to runtime/riscv64/execute_guest_test.cc
diff --git a/runtime/init_guest_arch.cc b/runtime/riscv64/init_guest_arch.cc
similarity index 100%
rename from runtime/init_guest_arch.cc
rename to runtime/riscv64/init_guest_arch.cc
diff --git a/runtime/run_guest_call_riscv64.cc b/runtime/riscv64/run_guest_call.cc
similarity index 100%
rename from runtime/run_guest_call_riscv64.cc
rename to runtime/riscv64/run_guest_call.cc
diff --git a/runtime/riscv64/translator.cc b/runtime/riscv64/translator.cc
new file mode 100644
index 00000000..9064cb73
--- /dev/null
+++ b/runtime/riscv64/translator.cc
@@ -0,0 +1,97 @@
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
+#include "berberis/runtime/translator.h"
+#include "translator.h"
+
+#include <cstdint>
+#include <cstdlib>
+#include <tuple>
+
+#include "berberis/assembler/machine_code.h"
+#include "berberis/guest_os_primitives/guest_map_shadow.h"
+#include "berberis/interpreter/riscv64/interpreter.h"
+#include "berberis/runtime_primitives/code_pool.h"
+#include "berberis/runtime_primitives/host_code.h"
+#include "berberis/runtime_primitives/profiler_interface.h"
+#include "berberis/runtime_primitives/translation_cache.h"
+#include "berberis/runtime_primitives/virtual_guest_call_frame.h"
+
+namespace berberis {
+
+namespace {
+
+// Syntax sugar.
+GuestCodeEntry::Kind kSpecialHandler = GuestCodeEntry::Kind::kSpecialHandler;
+
+// Use aligned address of this variable as the default stop address for guest execution.
+// It should never coincide with any guest address or address of a wrapped host symbol.
+// Unwinder might examine nearby insns.
+alignas(4) uint32_t g_native_bridge_call_guest[] = {
+    // <native_bridge_call_guest>:
+    0xd503201f,  // nop
+    0xd503201f,  // nop  <--
+    0xd503201f,  // nop
+};
+
+uint8_t GetRiscv64InsnSize(GuestAddr pc) {
+  constexpr uint16_t kInsnLenMask = uint16_t{0b11};
+  if ((*ToHostAddr<uint16_t>(pc) & kInsnLenMask) != kInsnLenMask) {
+    return 2;
+  }
+  return 4;
+}
+
+}  // namespace
+
+HostCodePiece InstallTranslated(MachineCode* machine_code,
+                                GuestAddr pc,
+                                size_t size,
+                                const char* prefix) {
+  HostCodeAddr host_code = GetDefaultCodePoolInstance()->Add(machine_code);
+  ProfilerLogGeneratedCode(AsHostCode(host_code), machine_code->install_size(), pc, size, prefix);
+  return {host_code, machine_code->install_size()};
+}
+
+// Check whether the given guest program counter is executable, accounting for compressed
+// instructions. Returns a tuple indicating whether the memory is executable and the size of the
+// first instruction in bytes.
+std::tuple<bool, uint8_t> IsPcExecutable(GuestAddr pc, GuestMapShadow* guest_map_shadow) {
+  // First check if the instruction would be in executable memory if it is compressed.  This
+  // prevents dereferencing unknown memory to determine the size of the instruction.
+  constexpr uint8_t kMinimumInsnSize = 2;
+  if (!guest_map_shadow->IsExecutable(pc, kMinimumInsnSize)) {
+    return {false, kMinimumInsnSize};
+  }
+
+  // Now check the rest of the instruction based on its size.  It is now safe to dereference the
+  // memory at pc because at least two bytes are within known executable memory.
+  uint8_t first_insn_size = GetRiscv64InsnSize(pc);
+  if (first_insn_size > kMinimumInsnSize &&
+      !guest_map_shadow->IsExecutable(pc + kMinimumInsnSize, first_insn_size - kMinimumInsnSize)) {
+    return {false, first_insn_size};
+  }
+
+  return {true, first_insn_size};
+}
+
+void InitTranslator() {
+  InitTranslatorArch();
+  InitVirtualGuestCallFrameReturnAddress(ToGuestAddr(g_native_bridge_call_guest + 1));
+  InitInterpreter();
+}
+
+}  // namespace berberis
diff --git a/runtime/riscv64/translator.h b/runtime/riscv64/translator.h
new file mode 100644
index 00000000..976bdce5
--- /dev/null
+++ b/runtime/riscv64/translator.h
@@ -0,0 +1,42 @@
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
+#ifndef BERBERIS_RUNTIME_RISCV64_TRANSLATOR_H_
+#define BERBERIS_RUNTIME_RISCV64_TRANSLATOR_H_
+
+#include <cstdint>
+#include <cstdlib>
+#include <tuple>
+
+#include "berberis/assembler/machine_code.h"
+#include "berberis/guest_os_primitives/guest_map_shadow.h"
+#include "berberis/guest_state/guest_addr.h"
+#include "berberis/runtime_primitives/host_code.h"
+#include "berberis/runtime_primitives/translation_cache.h"
+
+namespace berberis {
+
+HostCodePiece InstallTranslated(MachineCode* machine_code,
+                                GuestAddr pc,
+                                size_t size,
+                                const char* prefix);
+std::tuple<bool, uint8_t> IsPcExecutable(GuestAddr pc, GuestMapShadow* guest_map_shadow);
+
+void InitTranslatorArch();
+
+}  // namespace berberis
+
+#endif  // BERBERIS_RUNTIME_RISCV64_TRANSLATOR_H_
diff --git a/runtime/riscv64/translator_arm64.cc b/runtime/riscv64/translator_arm64.cc
new file mode 100644
index 00000000..ff7be65d
--- /dev/null
+++ b/runtime/riscv64/translator_arm64.cc
@@ -0,0 +1,74 @@
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
+#include "translator.h"
+
+#include "berberis/base/checks.h"
+#include "berberis/guest_os_primitives/guest_map_shadow.h"
+#include "berberis/guest_state/guest_addr.h"
+#include "berberis/guest_state/guest_state_opaque.h"
+#include "berberis/interpreter/riscv64/interpreter.h"
+#include "berberis/runtime_primitives/host_code.h"
+#include "berberis/runtime_primitives/runtime_library.h"
+#include "berberis/runtime_primitives/translation_cache.h"
+
+namespace berberis {
+
+void InitTranslatorArch() {}
+
+void TranslateRegion(GuestAddr pc) {
+  using Kind = GuestCodeEntry::Kind;
+
+  TranslationCache* cache = TranslationCache::GetInstance();
+
+  GuestCodeEntry* entry = cache->AddAndLockForTranslation(pc, 0);
+  if (!entry) {
+    return;
+  }
+
+  GuestMapShadow* guest_map_shadow = GuestMapShadow::GetInstance();
+  auto [is_executable, insn_size] = IsPcExecutable(pc, guest_map_shadow);
+  if (!is_executable) {
+    cache->SetTranslatedAndUnlock(pc, entry, insn_size, Kind::kSpecialHandler, {kEntryNoExec, 0});
+    return;
+  }
+
+  cache->SetTranslatedAndUnlock(pc, entry, insn_size, Kind::kInterpreted, {kEntryInterpret, 0});
+}
+
+// ATTENTION: This symbol gets called directly, without PLT. To keep text
+// sharable we should prevent preemption of this symbol, so do not export it!
+// TODO(b/232598137): may be set default visibility to protected instead?
+extern "C" __attribute__((used, __visibility__("hidden"))) void berberis_HandleNotTranslated(
+    ThreadState* state) {
+  TranslateRegion(state->cpu.insn_addr);
+}
+
+extern "C" __attribute__((used, __visibility__("hidden"))) void berberis_HandleInterpret(
+    ThreadState* state) {
+  InterpretInsn(state);
+}
+
+extern "C" __attribute__((used, __visibility__("hidden"))) const void* berberis_GetDispatchAddress(
+    ThreadState* state) {
+  CHECK(state);
+  if (ArePendingSignalsPresent(*state)) {
+    return AsHostCode(kEntryExitGeneratedCode);
+  }
+  return AsHostCode(TranslationCache::GetInstance()->GetHostCodePtr(state->cpu.insn_addr)->load());
+}
+
+}  // namespace berberis
diff --git a/runtime/translator_riscv64.cc b/runtime/riscv64/translator_x86_64.cc
similarity index 79%
rename from runtime/translator_riscv64.cc
rename to runtime/riscv64/translator_x86_64.cc
index 6410eb7c..3be45f80 100644
--- a/runtime/translator_riscv64.cc
+++ b/runtime/riscv64/translator_x86_64.cc
@@ -14,8 +14,9 @@
  * limitations under the License.
  */
 
-#include "translator_riscv64.h"
+#include "translator_x86_64.h"
 #include "berberis/runtime/translator.h"
+#include "translator.h"
 
 #include <cstdint>
 #include <cstdlib>
@@ -31,12 +32,9 @@
 #include "berberis/heavy_optimizer/riscv64/heavy_optimize_region.h"
 #include "berberis/interpreter/riscv64/interpreter.h"
 #include "berberis/lite_translator/lite_translate_region.h"
-#include "berberis/runtime_primitives/code_pool.h"
 #include "berberis/runtime_primitives/host_code.h"
-#include "berberis/runtime_primitives/profiler_interface.h"
 #include "berberis/runtime_primitives/runtime_library.h"
 #include "berberis/runtime_primitives/translation_cache.h"
-#include "berberis/runtime_primitives/virtual_guest_call_frame.h"
 
 namespace berberis {
 
@@ -45,7 +43,7 @@ namespace {
 // Syntax sugar.
 GuestCodeEntry::Kind kSpecialHandler = GuestCodeEntry::Kind::kSpecialHandler;
 GuestCodeEntry::Kind kInterpreted = GuestCodeEntry::Kind::kInterpreted;
-GuestCodeEntry::Kind kLightTranslated = GuestCodeEntry::Kind::kLightTranslated;
+GuestCodeEntry::Kind kLiteTranslated = GuestCodeEntry::Kind::kLiteTranslated;
 GuestCodeEntry::Kind kHeavyOptimized = GuestCodeEntry::Kind::kHeavyOptimized;
 
 enum class TranslationMode {
@@ -53,8 +51,8 @@ enum class TranslationMode {
   kLiteTranslateOrFallbackToInterpret,
   kHeavyOptimizeOrFallbackToInterpret,
   kHeavyOptimizeOrFallbackToLiteTranslator,
-  kLightTranslateThenHeavyOptimize,
-  kTwoGear = kLightTranslateThenHeavyOptimize,
+  kLiteTranslateThenHeavyOptimize,
+  kTwoGear = kLiteTranslateThenHeavyOptimize,
   kNumModes
 };
 
@@ -86,44 +84,15 @@ void UpdateTranslationMode() {
   LOG_ALWAYS_FATAL("Unrecognized translation mode '%s'", config_mode);
 }
 
-// Use aligned address of this variable as the default stop address for guest execution.
-// It should never coincide with any guest address or address of a wrapped host symbol.
-// Unwinder might examine nearby insns.
-alignas(4) uint32_t g_native_bridge_call_guest[] = {
-    // <native_bridge_call_guest>:
-    0xd503201f,  // nop
-    0xd503201f,  // nop  <--
-    0xd503201f,  // nop
-};
-
 enum class TranslationGear {
   kFirst,
   kSecond,
 };
 
-uint8_t GetRiscv64InsnSize(GuestAddr pc) {
-  constexpr uint16_t kInsnLenMask = uint16_t{0b11};
-  if ((*ToHostAddr<uint16_t>(pc) & kInsnLenMask) != kInsnLenMask) {
-    return 2;
-  }
-  return 4;
-}
-
 }  // namespace
 
-HostCodePiece InstallTranslated(MachineCode* machine_code,
-                                GuestAddr pc,
-                                size_t size,
-                                const char* prefix) {
-  HostCode host_code = GetDefaultCodePoolInstance()->Add(machine_code);
-  ProfilerLogGeneratedCode(host_code, machine_code->install_size(), pc, size, prefix);
-  return {host_code, machine_code->install_size()};
-}
-
-void InitTranslator() {
+void InitTranslatorArch() {
   UpdateTranslationMode();
-  InitVirtualGuestCallFrameReturnAddress(ToGuestAddr(g_native_bridge_call_guest + 1));
-  InitInterpreter();
 }
 
 // Exported for testing only.
@@ -137,7 +106,7 @@ std::tuple<bool, HostCodePiece, size_t, GuestCodeEntry::Kind> TryLiteTranslateAn
   size_t size = stop_pc - pc;
 
   if (success) {
-    return {true, InstallTranslated(&machine_code, pc, size, "lite"), size, kLightTranslated};
+    return {true, InstallTranslated(&machine_code, pc, size, "lite"), size, kLiteTranslated};
   }
 
   if (size == 0) {
@@ -152,7 +121,7 @@ std::tuple<bool, HostCodePiece, size_t, GuestCodeEntry::Kind> TryLiteTranslateAn
   return {true,
           InstallTranslated(&another_machine_code, pc, size, "lite_range"),
           size,
-          kLightTranslated};
+          kLiteTranslated};
 }
 
 // Exported for testing only.
@@ -190,20 +159,8 @@ void TranslateRegion(GuestAddr pc) {
   }
 
   GuestMapShadow* guest_map_shadow = GuestMapShadow::GetInstance();
-
-  // First check if the instruction would be in executable memory if it is compressed.  This
-  // prevents dereferencing unknown memory to determine the size of the instruction.
-  constexpr uint8_t kMinimumInsnSize = 2;
-  if (!guest_map_shadow->IsExecutable(pc, kMinimumInsnSize)) {
-    cache->SetTranslatedAndUnlock(pc, entry, kMinimumInsnSize, kSpecialHandler, {kEntryNoExec, 0});
-    return;
-  }
-
-  // Now check the rest of the instruction based on its size.  It is now safe to dereference the
-  // memory at pc because at least two bytes are within known executable memory.
-  uint8_t first_insn_size = GetRiscv64InsnSize(pc);
-  if (first_insn_size > kMinimumInsnSize &&
-      !guest_map_shadow->IsExecutable(pc + kMinimumInsnSize, first_insn_size - kMinimumInsnSize)) {
+  auto [is_executable, first_insn_size] = IsPcExecutable(pc, guest_map_shadow);
+  if (!is_executable) {
     cache->SetTranslatedAndUnlock(pc, entry, first_insn_size, kSpecialHandler, {kEntryNoExec, 0});
     return;
   }
@@ -296,13 +253,13 @@ extern "C" __attribute__((used, __visibility__("hidden"))) const void* berberis_
     ThreadState* state) {
   CHECK(state);
   if (ArePendingSignalsPresent(*state)) {
-    return kEntryExitGeneratedCode;
+    return AsHostCode(kEntryExitGeneratedCode);
   }
-  return TranslationCache::GetInstance()->GetHostCodePtr(state->cpu.insn_addr)->load();
+  return AsHostCode(TranslationCache::GetInstance()->GetHostCodePtr(state->cpu.insn_addr)->load());
 }
 
 extern "C" __attribute__((used, __visibility__("hidden"))) void
-berberis_HandleLightCounterThresholdReached(ThreadState* state) {
+berberis_HandleLiteCounterThresholdReached(ThreadState* state) {
   CHECK(g_translation_mode == TranslationMode::kTwoGear);
   TranslateRegion<TranslationGear::kSecond>(state->cpu.insn_addr);
 }
diff --git a/runtime/translator_riscv64.h b/runtime/riscv64/translator_x86_64.h
similarity index 87%
rename from runtime/translator_riscv64.h
rename to runtime/riscv64/translator_x86_64.h
index ccb8ffd8..b7f01a0f 100644
--- a/runtime/translator_riscv64.h
+++ b/runtime/riscv64/translator_x86_64.h
@@ -14,8 +14,8 @@
  * limitations under the License.
  */
 
-#ifndef BERBERIS_RUNTIME_TRANSLATOR_RISCV64_H_
-#define BERBERIS_RUNTIME_TRANSLATOR_RISCV64_H_
+#ifndef BERBERIS_RUNTIME_RISCV64_TRANSLATOR_X86_64_H_
+#define BERBERIS_RUNTIME_RISCV64_TRANSLATOR_X86_64_H_
 
 #include <cstddef>
 #include <tuple>
@@ -34,4 +34,4 @@ std::tuple<bool, HostCodePiece, size_t, GuestCodeEntry::Kind> HeavyOptimizeRegio
 
 }  // namespace berberis
 
-#endif  // BERBERIS_RUNTIME_TRANSLATOR_RISCV64_H_
\ No newline at end of file
+#endif  // BERBERIS_RUNTIME_RISCV64_TRANSLATOR_X86_64_H_
diff --git a/runtime/translator_riscv64_test.cc b/runtime/riscv64/translator_x86_64_test.cc
similarity index 80%
rename from runtime/translator_riscv64_test.cc
rename to runtime/riscv64/translator_x86_64_test.cc
index 9adba22f..852abd45 100644
--- a/runtime/translator_riscv64_test.cc
+++ b/runtime/riscv64/translator_x86_64_test.cc
@@ -19,13 +19,13 @@
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/runtime_primitives/translation_cache.h"
 
-#include "translator_riscv64.h"
+#include "translator_x86_64.h"
 
 namespace berberis {
 
 namespace {
 
-TEST(TranslatorRiscv64, LiteTranslateSupportedRegion) {
+TEST(TranslatorRiscv64ToX86_64, LiteTranslateSupportedRegion) {
   static const uint32_t code[] = {
       0x002081b3,  // add x3, x1, x2
       0x008000ef,  // jal x1, 8
@@ -35,13 +35,13 @@ TEST(TranslatorRiscv64, LiteTranslateSupportedRegion) {
       TryLiteTranslateAndInstallRegion(ToGuestAddr(code));
 
   EXPECT_TRUE(success);
-  EXPECT_NE(host_code_piece.code, nullptr);
+  EXPECT_NE(host_code_piece.code, kNullHostCodeAddr);
   EXPECT_GT(host_code_piece.size, 0U);
   EXPECT_EQ(guest_size, 8U);
-  EXPECT_EQ(kind, GuestCodeEntry::Kind::kLightTranslated);
+  EXPECT_EQ(kind, GuestCodeEntry::Kind::kLiteTranslated);
 }
 
-TEST(TranslatorRiscv64, LiteTranslateUnsupportedRegion) {
+TEST(TranslatorRiscv64ToX86_64, LiteTranslateUnsupportedRegion) {
   static const uint32_t code[] = {
       0x00000073,  // ecall #0x0
   };
@@ -52,7 +52,7 @@ TEST(TranslatorRiscv64, LiteTranslateUnsupportedRegion) {
   EXPECT_FALSE(success);
 }
 
-TEST(TranslatorRiscv64, LiteTranslatePartiallySupportedRegion) {
+TEST(TranslatorRiscv64ToX86_64, LiteTranslatePartiallySupportedRegion) {
   static const uint32_t code[] = {
       0x002081b3,  // add x3, x1, x2
       0x00000073,  // ecall #0x0
@@ -62,13 +62,13 @@ TEST(TranslatorRiscv64, LiteTranslatePartiallySupportedRegion) {
       TryLiteTranslateAndInstallRegion(ToGuestAddr(code));
 
   EXPECT_TRUE(success);
-  EXPECT_NE(host_code_piece.code, nullptr);
+  EXPECT_NE(host_code_piece.code, kNullHostCodeAddr);
   EXPECT_GT(host_code_piece.size, 0U);
   EXPECT_EQ(guest_size, 4U);
-  EXPECT_EQ(kind, GuestCodeEntry::Kind::kLightTranslated);
+  EXPECT_EQ(kind, GuestCodeEntry::Kind::kLiteTranslated);
 }
 
-TEST(TranslatorRiscv64, HeavyOptimizeSupportedRegion) {
+TEST(TranslatorRiscv64ToX86_64, HeavyOptimizeSupportedRegion) {
   static const uint32_t code[] = {
       0x008000ef,  // jal x1, 8
   };
@@ -82,7 +82,7 @@ TEST(TranslatorRiscv64, HeavyOptimizeSupportedRegion) {
   EXPECT_EQ(kind, GuestCodeEntry::Kind::kHeavyOptimized);
 }
 
-TEST(TranslatorRiscv64, HeavyOptimizeUnsupportedRegion) {
+TEST(TranslatorRiscv64ToX86_64, HeavyOptimizeUnsupportedRegion) {
   static const uint32_t code[] = {
       0x0000100f,  // fence.i
   };
diff --git a/runtime/runtime_library_arm64.cc b/runtime/runtime_library_arm64.cc
new file mode 100644
index 00000000..02f8eaeb
--- /dev/null
+++ b/runtime/runtime_library_arm64.cc
@@ -0,0 +1,238 @@
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
+#include "berberis/runtime_primitives/runtime_library.h"
+
+#include <cstdlib>
+
+#include "berberis/guest_state/guest_state.h"
+#include "berberis/runtime_primitives/host_code.h"
+
+namespace berberis {
+
+// "Calling conventions" among generated code and trampolines
+// ==========================================================
+//
+// Introduction
+// ------------
+//
+// To ensure the high performance of our generated code, we employ a couple of
+// techniques:
+//
+// - We allow generated regions to jump among them without transferring control
+//   back to Berberis runtime.
+//
+// - We use custom "calling conventions" that are different from the standard
+//   aapcs64 calling conventions, with some items passed in registers.
+//
+// Entry and exits
+// ---------------
+//
+// Upon entry into generated code and trampoline adapters, we must have:
+//
+// - x29 pointing to ThreadState,
+//
+// - every field in ThreadState up to date, except insn_addr, and
+//
+// - x0 containing up-to-date value for potentially stale ThreadState::insn_addr.
+//
+// Since we jump among generated code and trampolines, each region must adhere
+// to the "calling conventions" above as it exits.
+//
+// Each region is allowed to use the stack pointed to by sp. However, it must
+// restore sp before exiting.
+//
+// x19-x30 and the lower 64 bits of v8-v15 are callee saved. All other registers,
+// and the upper 64 bits of v8-v15, are caller saved. That is, regions are
+// allowed to use them without restoring their original values.
+//
+// Berberis -> generated code
+// ---------------------------------
+//
+// If we are transferring control to generated code and trampolines from the
+// Berberis runtime, such as ExecuteGuest, then we must do so via
+// berberis_RunGeneratedCode, which is responsible for setting up registers for
+// the "calling conventions".
+//
+// Generated code -> Berberis
+// ---------------------------------
+//
+// When we are exiting generate code, we must do so via END_GENERATED_CODE macro
+// defined in this file. The macro ensures that ThreadState is fully up to date,
+// including insn_addr, before transferring control back to the Berberis
+// runtime.
+
+namespace {
+
+// Number of bytes used for storing callee-saved registers on the stack when
+// entering and exiting generated code. There are a total of 20 64-bit
+// callee-saved registers.
+constexpr size_t kCalleeSavedFrameSize = 8 * 20;
+
+}  // namespace
+
+extern "C" {
+
+// Perform all the steps needed to exit generated code except return, which is
+// up to the users of this macro. The users of this macro may choose to perform
+// a sibling call as necessary.
+// clang-format off
+#define END_GENERATED_CODE(EXIT_INSN)                                   \
+  asm(                                                                  \
+      /* Sync insn_addr. */                                             \
+      "str x0, [x29, %[InsnAddr]]\n"                                    \
+      /* Set kOutsideGeneratedCode residence. */                        \
+      "mov w28, %[OutsideGeneratedCode]\n"                              \
+      "strb w28, [x29, %[Residence]]\n"                                 \
+                                                                        \
+      /* Set x0 to the pointer to the guest state so that               \
+       * we can perform a sibling call to functions like                \
+       * berberis_HandleNotTranslated.                                  \
+       */                                                               \
+      "mov x0, x29\n"                                                   \
+                                                                        \
+      /* Epilogue */                                                    \
+      "ldp d15, d14, [sp]\n"                                            \
+      "ldp d13, d12, [sp, 16]\n"                                        \
+      "ldp d11, d10, [sp, 32]\n"                                        \
+      "ldp d9, d8, [sp, 48]\n"                                          \
+      "ldp x29, x28, [sp, 64]\n"                                        \
+      "ldp x27, x26, [sp, 80]\n"                                        \
+      "ldp x25, x24, [sp, 96]\n"                                        \
+      "ldp x23, x22, [sp, 112]\n"                                       \
+      "ldp x21, x20, [sp, 128]\n"                                       \
+      "ldp x19, lr, [sp, 144]\n"                                        \
+      "add sp, sp, %[CalleeSavedFrameSize]\n"                               \
+                                                                        \
+      EXIT_INSN                                                         \
+      ::[InsnAddr] "p"(offsetof(berberis::ThreadState, cpu.insn_addr)), \
+      [Residence] "p"(offsetof(berberis::ThreadState, residence)),      \
+      [OutsideGeneratedCode] "M"(berberis::kOutsideGeneratedCode),      \
+      [CalleeSavedFrameSize] "I"(kCalleeSavedFrameSize))
+// clang-format on
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_RunGeneratedCode(ThreadState* state, HostCode code) {
+  // Parameters are in x0 - state and x1 - code
+  //
+  // In aapcs64, the stack must be aligned on 16 at every call instruction (sp mod 16 = 0).
+  // See https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst (6.4.5.1)
+
+  // clang-format off
+  asm(
+    // Prologue
+    "sub sp, sp, %[CalleeSavedFrameSize]\n"
+    "stp x19, lr, [sp, 144]\n"
+    "stp x21, x20, [sp, 128]\n"
+    "stp x23, x22, [sp, 112]\n"
+    "stp x25, x24, [sp, 96]\n"
+    "stp x27, x26, [sp, 80]\n"
+    "stp x29, x28, [sp, 64]\n"
+    "stp d9, d8, [sp, 48]\n"
+    "stp d11, d10, [sp, 32]\n"
+    "stp d13, d12, [sp, 16]\n"
+    "stp d15, d14, [sp]\n"
+
+    // Set state pointer
+    "mov x29, x0\n"
+
+    // Set insn_addr.
+    "ldr x0, [x29, %[InsnAddr]]\n"
+    // Set kInsideGeneratedCode residence.
+    "mov w28, %[InsideGeneratedCode]\n"
+    "strb w28, [x29, %[Residence]]\n"
+
+    // Jump to entry
+    "br x1"
+    ::[InsnAddr] "p"(offsetof(ThreadState, cpu.insn_addr)),
+    [Residence] "p"(offsetof(ThreadState, residence)),
+    [InsideGeneratedCode] "M"(kInsideGeneratedCode),
+    [CalleeSavedFrameSize] "I"(kCalleeSavedFrameSize));
+  // clang-format on
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_Interpret() {
+  // clang-format off
+  asm(
+    // Sync insn_addr.
+    "str x0, [x29, %[InsnAddr]]\n"
+    // Set kOutsideGeneratedCode residence. */
+    "mov w28, %[OutsideGeneratedCode]\n"
+    "strb w28, [x29, %[Residence]]\n"
+
+    // x29 holds the pointer to state which is the argument to the call.
+    "mov x0, x29\n"
+    "bl berberis_HandleInterpret\n"
+
+    // x0 may be clobbered by the call above, so init it again.
+    "mov x0, x29\n"
+    "bl berberis_GetDispatchAddress\n"
+    "mov x1, x0\n"
+
+    // Set insn_addr.
+    "ldr x0, [x29, %[InsnAddr]]\n"
+    // Set kInsideGeneratedCode residence.
+    "mov w28, %[InsideGeneratedCode]\n"
+    "strb w28, [x29, %[Residence]]\n"
+
+    "br x1\n"
+    ::[InsnAddr] "p"(offsetof(berberis::ThreadState, cpu.insn_addr)),
+    [Residence] "p"(offsetof(berberis::ThreadState, residence)),
+    [OutsideGeneratedCode] "M"(berberis::kOutsideGeneratedCode),
+    [InsideGeneratedCode] "M"(berberis::kInsideGeneratedCode));
+  // clang-format on
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_ExitGeneratedCode() {
+  END_GENERATED_CODE("ret");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_Stop() {
+  END_GENERATED_CODE("ret");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_NoExec() {
+  END_GENERATED_CODE("b berberis_HandleNoExec");
+  // void berberis_HandleNoExec(ThreadState*);
+  // Perform a sibling call to berberis_HandleNoExec. The only parameter
+  // is state which is saved in x0 by END_GENERATED_CODE.
+  // TODO(b/232598137): Remove state from HandleNoExec parameters. Get it from
+  // the guest thread instead.
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_NotTranslated() {
+  END_GENERATED_CODE("b berberis_HandleNotTranslated");
+  // void berberis_HandleNotTranslated(ThreadState*);
+  // See the comment above about the sibling call.
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_Translating() {
+  // TODO(b/232598137): Run interpreter while translation is in progress.
+  END_GENERATED_CODE("ret");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_Invalidating() {
+  // TODO(b/232598137): maybe call sched_yield() here.
+  END_GENERATED_CODE("ret");
+}
+
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_Wrapping() {
+  // TODO(b/232598137): maybe call sched_yield() here.
+  END_GENERATED_CODE("ret");
+}
+
+}  // extern "C"
+
+}  // namespace berberis
diff --git a/runtime/runtime_library_riscv64.cc b/runtime/runtime_library_riscv64.cc
index 5721e1d3..86e0ddc1 100644
--- a/runtime/runtime_library_riscv64.cc
+++ b/runtime/runtime_library_riscv64.cc
@@ -16,27 +16,159 @@
 
 #include "berberis/runtime_primitives/runtime_library.h"
 
-// TODO: b/352784623 - These need to be implemented by the time we activate
-// translation cache.
+#include "berberis/base/config.h"
+#include "berberis/guest_state/guest_state.h"
+
+extern "C" void berberis_HandleNotTranslated(berberis::ThreadState* state);
+extern "C" void berberis_GetDispatchAddress(berberis::ThreadState* state);
+extern "C" void berberis_HandleInterpret(berberis::ThreadState* state);
+
+// Helpers ensure that the functions below are available in PLT.
+__attribute__((used, __visibility__("hidden"))) extern "C" void helper_NotTranslated(
+    berberis::ThreadState* state) {
+  berberis_HandleNotTranslated(state);
+}
+
+__attribute__((used, __visibility__("hidden"))) extern "C" void helper_GetDispatchAddress(
+    berberis::ThreadState* state) {
+  berberis_GetDispatchAddress(state);
+}
+
+__attribute__((used, __visibility__("hidden"))) extern "C" void helper_HandleInterpret(
+    berberis::ThreadState* state) {
+  berberis_HandleInterpret(state);
+}
+
+// Perform all the steps needed to exit generated code except return, which is
+// up to the users of this macro. The users of this macro may choose to perform
+// a sibling call as necessary.
+// clang-format off
+#define END_GENERATED_CODE(EXIT_INSN)                                   \
+  asm(                                                                  \
+      /* Sync insn_addr. */                                             \
+      "sd s11, %[InsnAddr](fp)\n"                                       \
+      /* Set kOutsideGeneratedCode residence. */                        \
+      "li t1, %[OutsideGeneratedCode]\n"                                \
+      "sb t1, %[Residence](fp)\n"                                       \
+                                                                        \
+      /* Set a0 to the pointer to the guest state so that               \
+       * we can perform a sibling call to functions like                \
+       * berberis_HandleNotTranslated.                                  \
+       */                                                               \
+      "mv a0, fp\n"                                                     \
+                                                                        \
+      /* Epilogue */                                                    \
+      "ld ra, 96(sp)\n"                                                 \
+      "ld fp, 88(sp)\n"                                                 \
+      "ld s1, 80(sp)\n"                                                 \
+      "ld s2, 72(sp)\n"                                                 \
+      "ld s3, 64(sp)\n"                                                 \
+      "ld s4, 56(sp)\n"                                                 \
+      "ld s5, 48(sp)\n"                                                 \
+      "ld s6, 40(sp)\n"                                                 \
+      "ld s7, 32(sp)\n"                                                 \
+      "ld s8, 24(sp)\n"                                                 \
+      "ld s9, 16(sp)\n"                                                 \
+      "ld s10, 8(sp)\n"                                                 \
+      "ld s11, 0(sp)\n"                                                 \
+      "addi sp, sp, 112\n"                                              \
+                                                                        \
+      EXIT_INSN                                                         \
+      ::[InsnAddr] "I"(offsetof(berberis::ThreadState, cpu.insn_addr)), \
+      [Residence] "I"(offsetof(berberis::ThreadState, residence)),      \
+      [OutsideGeneratedCode] "I"(berberis::kOutsideGeneratedCode))
+// clang-format on
 
 namespace berberis {
 
 extern "C" {
 
 [[gnu::naked]] [[gnu::noinline]] void berberis_RunGeneratedCode(ThreadState* state, HostCode code) {
-  asm("unimp");
+  // Parameters are in a0 - state and a1 - code.
+  // Instruction address is saved in s11. This is also the last register to be allocated within a
+  // region. This approach maximizes the chance of s11 being not clobbered and thus facilitates
+  // debugging.
+  //
+  // On riscv64 Linux, stack should be aligned on 16 at every call insn.
+  // That means stack is always 0 mod 16 on function entry.
+  // See https://riscv.org/wp-content/uploads/2015/01/riscv-calling.pdf (18.2).
+  //
+  // We are saving all general purpose callee saved registers.
+  // TODO(b/352784623): Save fp registers when we start using them.
+
+  // clang-format off
+  asm(
+    // Prologue
+      "addi sp, sp, -112\n"
+      "sd s11, 0(sp)\n"
+      "sd s10, 8(sp)\n"
+      "sd s9, 16(sp)\n"
+      "sd s8, 24(sp)\n"
+      "sd s7, 32(sp)\n"
+      "sd s6, 40(sp)\n"
+      "sd s5, 48(sp)\n"
+      "sd s4, 56(sp)\n"
+      "sd s3, 64(sp)\n"
+      "sd s2, 72(sp)\n"
+      "sd s1, 80(sp)\n"
+      "sd fp, 88(sp)\n"
+      "sd ra, 96(sp)\n"
+
+      // Set state pointer.
+      "mv fp, a0\n"  // kStateRegister, kOmitFramePointer
+
+      // Set insn_addr.
+      "ld s11, %[InsnAddr](fp)\n"
+      // Set kInsideGeneratedCode residence.
+      "li t1, %[InsideGeneratedCode]\n"
+      "sb t1, %[Residence](fp)\n"
+
+      // Jump to entry.
+      "jr a1\n"
+      ::[InsnAddr] "I"(offsetof(ThreadState, cpu.insn_addr)),
+  [Residence] "I"(offsetof(ThreadState, residence)),
+  [InsideGeneratedCode] "I"(kInsideGeneratedCode));
+  // clang-format on
 }
 
 [[gnu::naked]] [[gnu::noinline]] void berberis_entry_Interpret() {
-  asm("unimp");
+  // clang-format off
+  asm(
+    //Sync insn_addr.
+      "sd s11, %[InsnAddr](fp)\n"
+      // Set kOutsideGeneratedCode residence.
+      "li t0, %[OutsideGeneratedCode]\n"
+      "sb t0, %[Residence](fp)\n"
+
+      // fp holds the pointer to state which is the argument to the call.
+      "mv a0, fp\n"
+      "call berberis_HandleInterpret@plt\n"
+
+      // a0 may be clobbered by the call abobe, so init it again.
+      "mv a0, fp\n"
+      "call berberis_GetDispatchAddress@plt\n"
+      "mv t1, a0\n"
+
+      // Set insn_addr.
+      "ld s11, %[InsnAddr](fp)\n"
+      // Set kInsideGeneratedCode residence.
+      "li t0, %[InsideGeneratedCode]\n"
+      "sb t0, %[Residence](fp)\n"
+
+      "jr t1\n"
+      ::[InsnAddr] "I"(offsetof(berberis::ThreadState, cpu.insn_addr)),
+  [Residence] "I"(offsetof(berberis::ThreadState, residence)),
+  [OutsideGeneratedCode] "I"(berberis::kOutsideGeneratedCode),
+  [InsideGeneratedCode] "I"(berberis::kInsideGeneratedCode));
+  // clang-format on
 }
 
 [[gnu::naked]] [[gnu::noinline]] void berberis_entry_ExitGeneratedCode() {
-  asm("unimp");
+  END_GENERATED_CODE("ret");
 }
 
 [[gnu::naked]] [[gnu::noinline]] void berberis_entry_Stop() {
-  asm("unimp");
+  END_GENERATED_CODE("ret");
 }
 
 [[gnu::naked]] [[gnu::noinline]] void berberis_entry_NoExec() {
@@ -44,7 +176,8 @@ extern "C" {
 }
 
 [[gnu::naked]] [[gnu::noinline]] void berberis_entry_NotTranslated() {
-  asm("unimp");
+  // @plt is needed since the symbol is dynamically linked.
+  END_GENERATED_CODE("tail berberis_HandleNotTranslated@plt");
 }
 
 [[gnu::naked]] [[gnu::noinline]] void berberis_entry_Translating() {
@@ -59,7 +192,7 @@ extern "C" {
   asm("unimp");
 }
 
-[[gnu::naked]] [[gnu::noinline]] void berberis_entry_HandleLightCounterThresholdReached() {
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_HandleLiteCounterThresholdReached() {
   asm("unimp");
 }
 
diff --git a/runtime/runtime_library_x86_64.cc b/runtime/runtime_library_x86_64.cc
index 2719723d..a3227191 100644
--- a/runtime/runtime_library_x86_64.cc
+++ b/runtime/runtime_library_x86_64.cc
@@ -230,16 +230,16 @@ extern "C" [[gnu::naked]] [[gnu::noinline]] void berberis_entry_Interpret() {
   END_GENERATED_CODE("ret");
 }
 
-[[gnu::naked]] [[gnu::noinline]] void berberis_entry_HandleLightCounterThresholdReached() {
-  // void berberis_HandleLightCounterThresholdReached(ProcessState*);
-  // Perform a sibling call to berberis_HandleLightCounterThresholdReached. The
+[[gnu::naked]] [[gnu::noinline]] void berberis_entry_HandleLiteCounterThresholdReached() {
+  // void berberis_HandleLiteCounterThresholdReached(ProcessState*);
+  // Perform a sibling call to berberis_HandleLiteCounterThresholdReached. The
   // only parameter is state which is saved in %rdi by END_GENERATED_CODE. We
   // could call the function here instead of jumping to it, but it would be more
   // work to do so because we would have to align the stack and issue the "ret"
   // instruction after the call.
-  // TODO(b/232598137): Remove state from HandleLightCounterThresholdReached
+  // TODO(b/232598137): Remove state from HandleLiteThresholdReached
   // parameters. Get it from the guest thread instead.
-  END_GENERATED_CODE("jmp berberis_HandleLightCounterThresholdReached");
+  END_GENERATED_CODE("jmp berberis_HandleLiteCounterThresholdReached");
 }
 
 }  // extern "C"
diff --git a/runtime_primitives/Android.bp b/runtime_primitives/Android.bp
index 38d5c006..b9c85190 100644
--- a/runtime_primitives/Android.bp
+++ b/runtime_primitives/Android.bp
@@ -41,6 +41,7 @@ cc_library_static {
     srcs: [
         "code_pool.cc",
         "crash_reporter.cc",
+        "exec_region_anonymous.cc",
         "guest_function_wrapper_impl.cc",
         "host_entries.cc",
         "host_function_wrapper_impl.cc",
@@ -96,7 +97,7 @@ cc_defaults {
 cc_library_static {
     name: "libberberis_runtime_primitives_riscv64",
     defaults: [
-        "berberis_defaults_64",
+        "berberis_all_hosts_defaults_64",
         "berberis_memory_region_reservation_defaults",
     ],
     host_supported: true,
@@ -126,6 +127,7 @@ cc_test_library {
     host_supported: true,
     srcs: [
         "code_pool_test.cc",
+        "exec_region_anonymous_test.cc",
         "signal_queue_test.cc",
         "table_of_tables_test.cc",
     ],
@@ -155,3 +157,51 @@ cc_test_library {
         "libberberis_runtime_primitives_headers",
     ],
 }
+
+cc_library_static {
+    name: "libberberis_elf_backed_exec_region",
+    defaults: ["berberis_all_hosts_defaults"],
+    host_supported: true,
+    target: {
+        bionic: {
+            srcs: ["exec_region_elf_backed.cc"],
+        },
+    },
+
+    header_libs: [
+        "libberberis_base_headers",
+        "libberberis_runtime_primitives_headers",
+        "libberberis_tinyloader_headers",
+    ],
+}
+
+// ATTENTION: do not use it outside of static tests!
+cc_library_static {
+    name: "libberberis_elf_backed_exec_region_for_static_tests",
+    defaults: ["berberis_all_hosts_defaults"],
+    host_supported: true,
+    target: {
+        bionic: {
+            srcs: ["exec_region_elf_backed_for_static_tests.cc"],
+        },
+    },
+
+    header_libs: [
+        "libberberis_base_headers",
+        "libberberis_runtime_primitives_headers",
+    ],
+}
+
+cc_test_library {
+    name: "libberberis_elf_backed_exec_region_unit_tests",
+    defaults: ["berberis_test_library_defaults"],
+    target: {
+        bionic: {
+            srcs: ["exec_region_elf_backed_test.cc"],
+        },
+    },
+    header_libs: [
+        "libberberis_base_headers",
+        "libberberis_runtime_primitives_headers",
+    ],
+}
diff --git a/runtime_primitives/code_pool.cc b/runtime_primitives/code_pool.cc
index 076a8847..fb6fcf1a 100644
--- a/runtime_primitives/code_pool.cc
+++ b/runtime_primitives/code_pool.cc
@@ -19,10 +19,11 @@
 #include <cstring>
 #include <mutex>
 
-#include "berberis/base/exec_region_anonymous.h"
+#include "berberis/base/forever_alloc.h"
+#include "berberis/runtime_primitives/exec_region_anonymous.h"
 
 #if defined(__BIONIC__)
-#include "berberis/base/exec_region_elf_backed.h"
+#include "berberis/runtime_primitives/exec_region_elf_backed.h"
 #endif
 
 namespace berberis {
@@ -44,14 +45,14 @@ void ResetAllExecRegions() {
 }
 
 CodePool<ExecRegionAnonymousFactory>* GetDefaultCodePoolInstance() {
-  static CodePool<ExecRegionAnonymousFactory> g_code_pool;
-  return &g_code_pool;
+  static auto* g_code_pool = NewForever<CodePool<ExecRegionAnonymousFactory>>();
+  return g_code_pool;
 }
 
 #if defined(__BIONIC__)
 CodePool<ExecRegionElfBackedFactory>* GetFunctionWrapperCodePoolInstance() {
-  static CodePool<ExecRegionElfBackedFactory> g_code_pool;
-  return &g_code_pool;
+  static auto* g_code_pool = NewForever<CodePool<ExecRegionElfBackedFactory>>();
+  return g_code_pool;
 }
 #else
 CodePool<ExecRegionAnonymousFactory>* GetFunctionWrapperCodePoolInstance() {
@@ -60,8 +61,8 @@ CodePool<ExecRegionAnonymousFactory>* GetFunctionWrapperCodePoolInstance() {
 #endif
 
 DataPool* DataPool::GetInstance() {
-  static DataPool g_data_pool;
-  return &g_data_pool;
+  static auto* g_data_pool = NewForever<DataPool>();
+  return g_data_pool;
 }
 
 }  // namespace berberis
diff --git a/runtime_primitives/code_pool_test.cc b/runtime_primitives/code_pool_test.cc
index efd6a147..6376611f 100644
--- a/runtime_primitives/code_pool_test.cc
+++ b/runtime_primitives/code_pool_test.cc
@@ -57,6 +57,7 @@ uint8_t* AllocExecutableRegion() {
       .size = MockExecRegionFactory::kExecRegionSize,
       .prot = PROT_NONE,
       .flags = MAP_PRIVATE | MAP_ANONYMOUS,
+      .berberis_flags = kMmapBerberis32Bit,
   }));
 }
 
@@ -86,7 +87,7 @@ TEST(CodePool, Smoke) {
     constexpr std::string_view kCode = "test1";
     machine_code.AddSequence(kCode.data(), kCode.size());
     auto host_code = code_pool.Add(&machine_code);
-    ASSERT_EQ(host_code, first_exec_region_memory_exec);
+    ASSERT_EQ(host_code, AsHostCodeAddr(first_exec_region_memory_exec));
     EXPECT_EQ(std::string_view{reinterpret_cast<const char*>(first_exec_region_memory_write)},
               kCode);
   }
@@ -98,7 +99,7 @@ TEST(CodePool, Smoke) {
     constexpr std::string_view kCode = "test2";
     machine_code.AddSequence(kCode.data(), kCode.size());
     auto host_code = code_pool.Add(&machine_code);
-    ASSERT_EQ(host_code, second_exec_region_memory_exec);
+    ASSERT_EQ(host_code, AsHostCodeAddr(second_exec_region_memory_exec));
     EXPECT_EQ(std::string_view{reinterpret_cast<const char*>(second_exec_region_memory_write)},
               kCode);
   }
diff --git a/base/exec_region_anonymous.cc b/runtime_primitives/exec_region_anonymous.cc
similarity index 65%
rename from base/exec_region_anonymous.cc
rename to runtime_primitives/exec_region_anonymous.cc
index 196a14be..9c0e4288 100644
--- a/base/exec_region_anonymous.cc
+++ b/runtime_primitives/exec_region_anonymous.cc
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#include "berberis/base/exec_region_anonymous.h"
+#include "berberis/runtime_primitives/exec_region_anonymous.h"
 
 #include <sys/mman.h>
 
@@ -29,9 +29,19 @@ ExecRegion ExecRegionAnonymousFactory::Create(size_t size) {
   auto fd = CreateMemfdOrDie("exec");
   FtruncateOrDie(fd, static_cast<off64_t>(size));
 
+#if defined(__x86_64__)
+  constexpr int kBerberisFlags = kMmapBerberis32Bit;
+#else
+  // TODO(b/363611588): enable for other backends (arm64/riscv64)
+  constexpr int kBerberisFlags = 0;
+#endif  // defined(__x86_64__)
+
   ExecRegion result{
-      static_cast<uint8_t*>(MmapImplOrDie(
-          {.size = size, .prot = PROT_READ | PROT_EXEC, .flags = MAP_SHARED, .fd = fd})),
+      static_cast<uint8_t*>(MmapImplOrDie({.size = size,
+                                           .prot = PROT_READ | PROT_EXEC,
+                                           .flags = MAP_SHARED,
+                                           .fd = fd,
+                                           .berberis_flags = kBerberisFlags})),
       static_cast<uint8_t*>(MmapImplOrDie(
           {.size = size, .prot = PROT_READ | PROT_WRITE, .flags = MAP_SHARED, .fd = fd})),
       size};
diff --git a/base/exec_region_anonymous_test.cc b/runtime_primitives/exec_region_anonymous_test.cc
similarity index 94%
rename from base/exec_region_anonymous_test.cc
rename to runtime_primitives/exec_region_anonymous_test.cc
index 4bcb23ab..657c33e1 100644
--- a/base/exec_region_anonymous_test.cc
+++ b/runtime_primitives/exec_region_anonymous_test.cc
@@ -18,7 +18,7 @@
 
 #include <utility>
 
-#include "berberis/base/exec_region_anonymous.h"
+#include "berberis/runtime_primitives/exec_region_anonymous.h"
 
 namespace berberis {
 
diff --git a/base/exec_region_elf_backed.cc b/runtime_primitives/exec_region_elf_backed.cc
similarity index 74%
rename from base/exec_region_elf_backed.cc
rename to runtime_primitives/exec_region_elf_backed.cc
index 440449e3..2a05f692 100644
--- a/base/exec_region_elf_backed.cc
+++ b/runtime_primitives/exec_region_elf_backed.cc
@@ -14,7 +14,8 @@
  * limitations under the License.
  */
 
-#include "berberis/base/exec_region_elf_backed.h"
+#include "berberis/runtime_primitives/exec_region_elf_backed.h"
+#include "berberis/tiny_loader/tiny_loader.h"
 
 #include <android/dlext.h>
 #include <dlfcn.h>
@@ -40,7 +41,21 @@ namespace berberis {
 ExecRegion ExecRegionElfBackedFactory::Create(size_t size) {
   size = AlignUpPageSize(size);
 
-  android_dlextinfo dlextinfo{.flags = ANDROID_DLEXT_FORCE_LOAD};
+  // Since we cannot force android loader to map library in lower 2G memory we will need
+  // to reserve the space first and then direct the loader to load the library at that address.
+  size_t load_size = TinyLoader::CalculateLoadSize(kExecRegionLibraryPath, nullptr);
+  CHECK_NE(load_size, 0);
+
+  void* load_addr = MmapImplOrDie({.addr = nullptr,
+                                   .size = load_size,
+                                   .prot = PROT_NONE,
+                                   .flags = MAP_ANONYMOUS | MAP_PRIVATE,
+                                   .berberis_flags = kMmapBerberis32Bit});
+
+  android_dlextinfo dlextinfo{.flags = ANDROID_DLEXT_FORCE_LOAD | ANDROID_DLEXT_RESERVED_ADDRESS,
+                              .reserved_addr = load_addr,
+                              .reserved_size = load_size};
+
   void* handle = android_dlopen_ext(kExecRegionLibraryPath, RTLD_NOW, &dlextinfo);
   if (handle == nullptr) {
     FATAL("Couldn't load \"%s\": %s", kExecRegionLibraryPath, dlerror());
diff --git a/base/exec_region_elf_backed_for_static_tests.cc b/runtime_primitives/exec_region_elf_backed_for_static_tests.cc
similarity index 87%
rename from base/exec_region_elf_backed_for_static_tests.cc
rename to runtime_primitives/exec_region_elf_backed_for_static_tests.cc
index d4b64fbb..d129ada1 100644
--- a/base/exec_region_elf_backed_for_static_tests.cc
+++ b/runtime_primitives/exec_region_elf_backed_for_static_tests.cc
@@ -14,9 +14,8 @@
  * limitations under the License.
  */
 
-#include "berberis/base/exec_region_elf_backed.h"
-
-#include "berberis/base/exec_region_anonymous.h"
+#include "berberis/runtime_primitives/exec_region_anonymous.h"
+#include "berberis/runtime_primitives/exec_region_elf_backed.h"
 
 namespace berberis {
 
diff --git a/base/exec_region_elf_backed_test.cc b/runtime_primitives/exec_region_elf_backed_test.cc
similarity index 96%
rename from base/exec_region_elf_backed_test.cc
rename to runtime_primitives/exec_region_elf_backed_test.cc
index 3eeb4570..3d77addd 100644
--- a/base/exec_region_elf_backed_test.cc
+++ b/runtime_primitives/exec_region_elf_backed_test.cc
@@ -16,7 +16,7 @@
 
 #include "gtest/gtest.h"
 
-#include "berberis/base/exec_region_elf_backed.h"
+#include "berberis/runtime_primitives/exec_region_elf_backed.h"
 
 #include <dlfcn.h>
 
diff --git a/runtime_primitives/guest_function_wrapper_impl.cc b/runtime_primitives/guest_function_wrapper_impl.cc
index f1e8eded..6294c516 100644
--- a/runtime_primitives/guest_function_wrapper_impl.cc
+++ b/runtime_primitives/guest_function_wrapper_impl.cc
@@ -22,6 +22,7 @@
 #include <utility>
 
 #include "berberis/assembler/machine_code.h"
+#include "berberis/base/forever_alloc.h"
 #include "berberis/base/forever_map.h"
 #include "berberis/base/logging.h"
 #include "berberis/code_gen_lib/gen_wrapper.h"
@@ -56,8 +57,8 @@ namespace {
 class WrapperCache {
  public:
   static WrapperCache* GetInstance() {
-    static WrapperCache g_wrapper_cache;
-    return &g_wrapper_cache;
+    static auto* g_wrapper_cache = NewForever<WrapperCache>();
+    return g_wrapper_cache;
   }
 
   HostCode Find(GuestAddr pc, const char* signature, HostCode guest_runner) const {
@@ -76,7 +77,7 @@ class WrapperCache {
     std::pair<WrapperMap::iterator, bool> res = map_.insert(
         std::make_pair(std::make_tuple(pc, std::string(signature), guest_runner), nullptr));
     if (res.second) {
-      res.first->second = GetFunctionWrapperCodePoolInstance()->Add(mc);
+      res.first->second = AsHostCode(GetFunctionWrapperCodePoolInstance()->Add(mc));
     }
     return res.first->second;
   }
@@ -100,6 +101,8 @@ class WrapperCache {
 
   WrapperMap map_;
   mutable std::mutex mutex_;
+
+  friend WrapperCache* NewForever<WrapperCache>();
 };
 
 IsAddressGuestExecutableFunc g_is_address_guest_executable_func = nullptr;
diff --git a/runtime_primitives/host_entries.cc b/runtime_primitives/host_entries.cc
index 0cdd6d14..a01cdc87 100644
--- a/runtime_primitives/host_entries.cc
+++ b/runtime_primitives/host_entries.cc
@@ -24,20 +24,20 @@
 
 namespace berberis {
 
-HostCode kEntryInterpret;
-HostCode kEntryExitGeneratedCode;
-HostCode kEntryStop;
-HostCode kEntryNoExec;
-HostCode kEntryNotTranslated;
-HostCode kEntryTranslating;
-HostCode kEntryInvalidating;
-HostCode kEntryWrapping;
+HostCodeAddr kEntryInterpret;
+HostCodeAddr kEntryExitGeneratedCode;
+HostCodeAddr kEntryStop;
+HostCodeAddr kEntryNoExec;
+HostCodeAddr kEntryNotTranslated;
+HostCodeAddr kEntryTranslating;
+HostCodeAddr kEntryInvalidating;
+HostCodeAddr kEntryWrapping;
 
 namespace {
 // This function installs a trampoline in the CodePool address space.
 // This needed to ensure that all entries in the translation cache
 // are always pointing to the memory allocated via CodePool.
-HostCode InstallEntryTrampoline(HostCode target_function_ptr) {
+HostCodeAddr InstallEntryTrampoline(HostCode target_function_ptr) {
 #if defined(__x86_64__)
   MachineCode mc;
   x86_64::Assembler as(&mc);
@@ -45,7 +45,7 @@ HostCode InstallEntryTrampoline(HostCode target_function_ptr) {
   as.Finalize();
   return GetDefaultCodePoolInstance()->Add(&mc);
 #else
-  return target_function_ptr;
+  return AsHostCodeAddr(target_function_ptr);
 #endif
 }
 }  // namespace
diff --git a/runtime_primitives/host_function_wrapper_impl.cc b/runtime_primitives/host_function_wrapper_impl.cc
index dc3cfb0b..a6ff50c0 100644
--- a/runtime_primitives/host_function_wrapper_impl.cc
+++ b/runtime_primitives/host_function_wrapper_impl.cc
@@ -17,12 +17,12 @@
 #include "berberis/runtime_primitives/host_function_wrapper_impl.h"
 
 #include "berberis/assembler/machine_code.h"
-#include "berberis/base/exec_region_anonymous.h"
 #include "berberis/base/tracing.h"
 #include "berberis/code_gen_lib/gen_adaptor.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/runtime_primitives/checks.h"
 #include "berberis/runtime_primitives/code_pool.h"
+#include "berberis/runtime_primitives/exec_region_anonymous.h"
 #include "berberis/runtime_primitives/host_code.h"
 #include "berberis/runtime_primitives/translation_cache.h"
 
diff --git a/runtime_primitives/include/berberis/runtime_primitives/code_pool.h b/runtime_primitives/include/berberis/runtime_primitives/code_pool.h
index 40e0579f..2f653adf 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/code_pool.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/code_pool.h
@@ -23,11 +23,11 @@
 #include "berberis/assembler/machine_code.h"
 #include "berberis/base/arena_alloc.h"
 #include "berberis/base/exec_region.h"
-#include "berberis/base/exec_region_anonymous.h"
+#include "berberis/runtime_primitives/exec_region_anonymous.h"
 #include "berberis/runtime_primitives/host_code.h"
 
 #if defined(__BIONIC__)
-#include "berberis/base/exec_region_elf_backed.h"
+#include "berberis/runtime_primitives/exec_region_elf_backed.h"
 #endif
 
 namespace berberis {
@@ -45,15 +45,17 @@ class CodePool {
   CodePool(CodePool&&) = delete;
   CodePool& operator=(CodePool&&) = delete;
 
-  [[nodiscard]] HostCode Add(MachineCode* code) {
+  [[nodiscard]] HostCodeAddr Add(MachineCode* code) {
     std::lock_guard<std::mutex> lock(mutex_);
 
     uint32_t size = code->install_size();
 
-    // This is the start of a generated code region which is always a branch
-    // target. Align on 16-bytes as recommended by Intel.
-    // TODO(b/232598137) Extract this into host specified behavior.
-    current_address_ = AlignUp(current_address_, 16);
+    // Align region start on 64-byte cache line to facilite more stable instruction fetch
+    // performance on benchmarks. Region start is always a branch target, so this also ensures
+    // 16-bytes alignment for branch targets recommended by Intel.
+    // TODO(b/200327919): Try only doing this for heavy-optimized code to avoid extra gaps between
+    // lite-translated regions.
+    current_address_ = AlignUp(current_address_, 64);
 
     if (exec_.end() < current_address_ + size) {
       ResetExecRegion(size);
@@ -63,7 +65,7 @@ class CodePool {
     current_address_ += size;
 
     code->Install(&exec_, result, &recovery_map_);
-    return result;
+    return AsHostCodeAddr(result);
   }
 
   [[nodiscard]] uintptr_t FindRecoveryCode(uintptr_t fault_addr) const {
diff --git a/base/include/berberis/base/exec_region_anonymous.h b/runtime_primitives/include/berberis/runtime_primitives/exec_region_anonymous.h
similarity index 96%
rename from base/include/berberis/base/exec_region_anonymous.h
rename to runtime_primitives/include/berberis/runtime_primitives/exec_region_anonymous.h
index 9f91c8e4..21fc7745 100644
--- a/base/include/berberis/base/exec_region_anonymous.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/exec_region_anonymous.h
@@ -20,7 +20,7 @@
 #include <cstddef>
 #include <cstdint>
 
-#include "exec_region.h"
+#include "berberis/base/exec_region.h"
 
 namespace berberis {
 
diff --git a/base/include/berberis/base/exec_region_elf_backed.h b/runtime_primitives/include/berberis/runtime_primitives/exec_region_elf_backed.h
similarity index 96%
rename from base/include/berberis/base/exec_region_elf_backed.h
rename to runtime_primitives/include/berberis/runtime_primitives/exec_region_elf_backed.h
index 04125859..abab95c8 100644
--- a/base/include/berberis/base/exec_region_elf_backed.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/exec_region_elf_backed.h
@@ -20,7 +20,7 @@
 #include <cstddef>
 #include <cstdint>
 
-#include "exec_region.h"
+#include "berberis/base/exec_region.h"
 
 namespace berberis {
 
diff --git a/runtime_primitives/include/berberis/runtime_primitives/host_code.h b/runtime_primitives/include/berberis/runtime_primitives/host_code.h
index c48a4f2b..026fcca4 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/host_code.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/host_code.h
@@ -18,11 +18,41 @@
 
 #include <cstdint>
 
+#include "berberis/base/bit_util.h"
+#include "berberis/base/checks.h"
+
 namespace berberis {
 
 // Pointer to host executable machine code.
 using HostCode = const void*;
 
+// Type used in translation cache and for host_entries
+#if defined(__x86_64__)
+using HostCodeAddr = uint32_t;
+
+inline HostCodeAddr AsHostCodeAddr(HostCode host_code) {
+  CHECK(IsInRange<HostCodeAddr>(bit_cast<uintptr_t>(host_code)));
+  return static_cast<HostCodeAddr>(bit_cast<uintptr_t>(host_code));
+}
+
+inline HostCode AsHostCode(HostCodeAddr host_code_addr) {
+  return bit_cast<HostCode>(uintptr_t{host_code_addr});
+}
+#else
+// TODO(b/363611588): use uint32_t for other 64bit backends (arm64/riscv64)
+using HostCodeAddr = uintptr_t;
+
+inline HostCodeAddr AsHostCodeAddr(HostCode host_code) {
+  return bit_cast<HostCodeAddr>(host_code);
+}
+
+inline HostCode AsHostCode(HostCodeAddr host_code_addr) {
+  return bit_cast<HostCode>(host_code_addr);
+}
+#endif  // defined(__x86_64__)
+
+constexpr HostCodeAddr kNullHostCodeAddr = 0;
+
 template <typename T>
 inline HostCode AsHostCode(T ptr) {
   return reinterpret_cast<HostCode>(ptr);
@@ -67,7 +97,7 @@ inline AsFuncPtrAdaptor AsFuncPtr(HostCode ptr) {
 }
 
 struct HostCodePiece {
-  HostCode code;
+  HostCodeAddr code;
   uint32_t size;
 };
 
diff --git a/runtime_primitives/include/berberis/runtime_primitives/platform.h b/runtime_primitives/include/berberis/runtime_primitives/platform.h
index e17bcf02..7b5f5ce5 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/platform.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/platform.h
@@ -53,6 +53,7 @@ extern const struct PlatformCapabilities {
   bool kHasSSE4a;
   bool kHasSSE4_1;
   bool kHasSSE4_2;
+  bool kHasCustomCapability;
 } kPlatformCapabilities;
 // These are "runtime constants": they can not be determined at compile
 // time but each particular CPU has them set to true or false and that
@@ -75,6 +76,7 @@ inline const bool& kHasSSSE3 = kPlatformCapabilities.kHasSSSE3;
 inline const bool& kHasSSE4a = kPlatformCapabilities.kHasSSE4a;
 inline const bool& kHasSSE4_1 = kPlatformCapabilities.kHasSSE4_1;
 inline const bool& kHasSSE4_2 = kPlatformCapabilities.kHasSSE4_2;
+inline const bool& kHasCustomCapability = kPlatformCapabilities.kHasCustomCapability;
 #endif
 
 }  // namespace berberis::host_platform
diff --git a/runtime_primitives/include/berberis/runtime_primitives/runtime_library.h b/runtime_primitives/include/berberis/runtime_primitives/runtime_library.h
index cb41c747..98872088 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/runtime_library.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/runtime_library.h
@@ -30,7 +30,7 @@ void berberis_entry_Interpret();
 void berberis_entry_ExitGeneratedCode();
 void berberis_entry_Stop();
 void berberis_entry_NoExec();
-void berberis_entry_HandleLightCounterThresholdReached();
+void berberis_entry_HandleLiteCounterThresholdReached();
 
 // TODO(b/232598137): use status variable instead?
 void berberis_entry_NotTranslated();
@@ -46,14 +46,14 @@ __attribute__((__visibility__("hidden"))) void berberis_HandleNoExec(ThreadState
 }  // extern "C"
 
 // These constants are initialized by InitHostEntries()
-extern HostCode kEntryInterpret;
-extern HostCode kEntryExitGeneratedCode;
-extern HostCode kEntryStop;
-extern HostCode kEntryNoExec;
-extern HostCode kEntryNotTranslated;
-extern HostCode kEntryTranslating;
-extern HostCode kEntryInvalidating;
-extern HostCode kEntryWrapping;
+extern HostCodeAddr kEntryInterpret;
+extern HostCodeAddr kEntryExitGeneratedCode;
+extern HostCodeAddr kEntryStop;
+extern HostCodeAddr kEntryNoExec;
+extern HostCodeAddr kEntryNotTranslated;
+extern HostCodeAddr kEntryTranslating;
+extern HostCodeAddr kEntryInvalidating;
+extern HostCodeAddr kEntryWrapping;
 
 void InitHostEntries();
 
diff --git a/runtime_primitives/include/berberis/runtime_primitives/table_of_tables.h b/runtime_primitives/include/berberis/runtime_primitives/table_of_tables.h
index 7eb9f63e..6d447b8f 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/table_of_tables.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/table_of_tables.h
@@ -33,13 +33,12 @@ template <typename Key, typename T>
 class TableOfTables {
  public:
   explicit TableOfTables(T default_value) : default_value_(default_value) {
-    static_assert(sizeof(T) == sizeof(uintptr_t));
+    static_assert(sizeof(T) == sizeof(uintptr_t) || sizeof(T) == sizeof(uint32_t));
     CHECK_NE(default_value, T{0});
     default_table_ = static_cast<decltype(default_table_)>(CreateMemfdBackedMapOrDie(
         GetOrAllocDefaultMemfdUnsafe(), kChildTableBytes, kMemfdRegionSize));
 
-    int main_memfd =
-        CreateAndFillMemfd("main", kMemfdRegionSize, reinterpret_cast<uintptr_t>(default_table_));
+    int main_memfd = CreateAndFillMemfd("main", kMemfdRegionSize, default_table_);
     main_table_ = static_cast<decltype(main_table_)>(
         CreateMemfdBackedMapOrDie(main_memfd, kTableSize * sizeof(T*), kMemfdRegionSize));
     close(main_memfd);
@@ -109,8 +108,7 @@ class TableOfTables {
 
   int GetOrAllocDefaultMemfdUnsafe() {
     if (default_memfd_ == -1) {
-      default_memfd_ = CreateAndFillMemfd(
-          "child", kMemfdRegionSize, reinterpret_cast<uintptr_t>(default_value_));
+      default_memfd_ = CreateAndFillMemfd("child", kMemfdRegionSize, default_value_);
     }
     return default_memfd_;
   }
diff --git a/runtime_primitives/include/berberis/runtime_primitives/translation_cache.h b/runtime_primitives/include/berberis/runtime_primitives/translation_cache.h
index 57396bce..b596749f 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/translation_cache.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/translation_cache.h
@@ -34,7 +34,7 @@ namespace berberis {
 // ATTENTION: associated guest pc and host code pointer never change!
 // TODO(b/232598137): consider making TranslationCache-internal!
 struct GuestCodeEntry {
-  std::atomic<HostCode>* const host_code;
+  std::atomic<HostCodeAddr>* const host_code;
 
   // Fields below are protected by TranslationCache mutex.
 
@@ -46,7 +46,7 @@ struct GuestCodeEntry {
 
   enum class Kind {
     kInterpreted,
-    kLightTranslated,
+    kLiteTranslated,
     kHeavyOptimized,
     kGuestWrapped,
     kHostWrapped,
@@ -129,7 +129,7 @@ class TranslationCache {
   // is no entry for the given PC.
   [[nodiscard]] GuestCodeEntry* AddAndLockForTranslation(GuestAddr pc, uint32_t counter_threshold);
 
-  // Locks entry for the given PC for translation if it's currently in LightTranslated state.
+  // Locks entry for the given PC for translation if it's currently in LiteTranslated state.
   // If successful returns the locked entry, otherwise returns nullptr.
   [[nodiscard]] GuestCodeEntry* LockForGearUpTranslation(GuestAddr pc);
 
@@ -163,11 +163,11 @@ class TranslationCache {
   // Invalidate region of entries.
   void InvalidateGuestRange(GuestAddr start, GuestAddr end);
 
-  [[nodiscard]] const std::atomic<std::atomic<HostCode>*>* main_table_ptr() const {
+  [[nodiscard]] const std::atomic<std::atomic<HostCodeAddr>*>* main_table_ptr() const {
     return address_map_.main_table();
   }
 
-  [[nodiscard]] const std::atomic<HostCode>* GetHostCodePtr(GuestAddr pc) {
+  [[nodiscard]] const std::atomic<HostCodeAddr>* GetHostCodePtr(GuestAddr pc) {
     return address_map_.GetPointer(pc);
   }
 
@@ -183,13 +183,13 @@ class TranslationCache {
  private:
   [[nodiscard]] GuestCodeEntry* LookupGuestCodeEntryUnsafe(GuestAddr pc);
   [[nodiscard]] const GuestCodeEntry* LookupGuestCodeEntryUnsafe(GuestAddr pc) const;
-  [[nodiscard]] std::atomic<HostCode>* GetHostCodePtrWritable(GuestAddr pc) {
+  [[nodiscard]] std::atomic<HostCodeAddr>* GetHostCodePtrWritable(GuestAddr pc) {
     return address_map_.GetPointer(pc);
   }
 
   // Add call record for an address, reuse if already here.
   [[nodiscard]] GuestCodeEntry* AddUnsafe(GuestAddr pc,
-                                          std::atomic<HostCode>* host_code_ptr,
+                                          std::atomic<HostCodeAddr>* host_code_ptr,
                                           HostCodePiece host_code_piece,
                                           uint32_t guest_size,
                                           GuestCodeEntry::Kind kind,
@@ -209,7 +209,7 @@ class TranslationCache {
   ForeverMap<GuestAddr, GuestCodeEntry> guest_entries_;
 
   // Maps guest code addresses to the host address of the translated code.
-  TableOfTables<GuestAddr, HostCode> address_map_{kEntryNotTranslated};
+  TableOfTables<GuestAddr, HostCodeAddr> address_map_{kEntryNotTranslated};
 
   // The size of the largest entry.
   // Wrapped entries do not update it, so if we only have wrapped the size
diff --git a/runtime_primitives/known_guest_function_wrapper.cc b/runtime_primitives/known_guest_function_wrapper.cc
index f49e30f2..0709fe01 100644
--- a/runtime_primitives/known_guest_function_wrapper.cc
+++ b/runtime_primitives/known_guest_function_wrapper.cc
@@ -20,6 +20,7 @@
 #include <mutex>
 #include <string>
 
+#include "berberis/base/forever_alloc.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/runtime_primitives/host_code.h"
 
@@ -27,23 +28,46 @@ namespace berberis {
 
 namespace {
 
-std::map<std::string, HostCode (*)(GuestAddr)> g_function_wrappers;
-std::mutex g_guard_mutex;
+class GuestFunctionWrapper {
+ public:
+  static GuestFunctionWrapper* GetInstance() {
+    static auto* g_wrapper = NewForever<GuestFunctionWrapper>();
+    return g_wrapper;
+  }
+
+  void RegisterKnown(const char* name, HostCode (*wrapper)(GuestAddr)) {
+    std::lock_guard<std::mutex> guard(mutex_);
+    wrappers_.insert({name, wrapper});
+  }
+
+  HostCode WrapKnown(GuestAddr guest_addr, const char* name) {
+    std::lock_guard<std::mutex> guard(mutex_);
+    auto wrapper = wrappers_.find(name);
+    if (wrapper == end(wrappers_)) {
+      return nullptr;
+    }
+    return wrapper->second(guest_addr);
+  }
+
+ private:
+  GuestFunctionWrapper() = default;
+  GuestFunctionWrapper(const GuestFunctionWrapper&) = delete;
+  GuestFunctionWrapper& operator=(const GuestFunctionWrapper&) = delete;
+
+  friend GuestFunctionWrapper* NewForever<GuestFunctionWrapper>();
+
+  std::map<std::string, HostCode (*)(GuestAddr)> wrappers_;
+  std::mutex mutex_;
+};
 
 }  // namespace
 
 void RegisterKnownGuestFunctionWrapper(const char* name, HostCode (*wrapper)(GuestAddr)) {
-  std::lock_guard<std::mutex> guard(g_guard_mutex);
-  g_function_wrappers.insert({name, wrapper});
+  GuestFunctionWrapper::GetInstance()->RegisterKnown(name, wrapper);
 }
 
 HostCode WrapKnownGuestFunction(GuestAddr guest_addr, const char* name) {
-  std::lock_guard<std::mutex> guard(g_guard_mutex);
-  auto wrapper = g_function_wrappers.find(name);
-  if (wrapper == end(g_function_wrappers)) {
-    return nullptr;
-  }
-  return wrapper->second(guest_addr);
+  return GuestFunctionWrapper::GetInstance()->WrapKnown(guest_addr, name);
 }
 
 };  // namespace berberis
diff --git a/runtime_primitives/platform.cc b/runtime_primitives/platform.cc
index de4ff46d..b7dea2eb 100644
--- a/runtime_primitives/platform.cc
+++ b/runtime_primitives/platform.cc
@@ -15,6 +15,7 @@
  */
 
 #include "berberis/runtime_primitives/platform.h"
+#include "berberis/base/config_globals.h"
 
 #if defined(__i386__) || defined(__x86_64__)
 #include <cpuid.h>
@@ -68,6 +69,7 @@ auto Init() {
   platform_capabilities.kHasBMI2 = ebx & bit_BMI2;
   platform_capabilities.kHasPDEP = ebx & bit_BMI2 && use_pdep_if_present;
   platform_capabilities.kHasSHA = ebx & bit_SHA;
+  platform_capabilities.kHasCustomCapability = IsConfigFlagSet(kPlatformCustomCPUCapability);
   return platform_capabilities;
 }
 #endif
diff --git a/runtime_primitives/translation_cache.cc b/runtime_primitives/translation_cache.cc
index 4be1872c..67c858a2 100644
--- a/runtime_primitives/translation_cache.cc
+++ b/runtime_primitives/translation_cache.cc
@@ -21,6 +21,7 @@
 #include <mutex>  // std::lock_guard, std::mutex
 
 #include "berberis/base/checks.h"
+#include "berberis/base/forever_alloc.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/runtime_primitives/host_code.h"
 #include "berberis/runtime_primitives/runtime_library.h"
@@ -28,8 +29,8 @@
 namespace berberis {
 
 TranslationCache* TranslationCache::GetInstance() {
-  static TranslationCache g_translation_cache;
-  return &g_translation_cache;
+  static auto* g_translation_cache = NewForever<TranslationCache>();
+  return g_translation_cache;
 }
 
 GuestCodeEntry* TranslationCache::AddAndLockForTranslation(GuestAddr pc,
@@ -72,9 +73,9 @@ GuestCodeEntry* TranslationCache::LockForGearUpTranslation(GuestAddr pc) {
     return nullptr;
   }
 
-  // This method should be called for light-translated region, but we cannot
+  // This method should be called for lite-translated region, but we cannot
   // guarantee they stay as such before we lock the mutex.
-  if (entry->kind != GuestCodeEntry::Kind::kLightTranslated) {
+  if (entry->kind != GuestCodeEntry::Kind::kLiteTranslated) {
     return nullptr;
   }
 
@@ -153,7 +154,7 @@ void TranslationCache::SetWrappedAndUnlock(GuestAddr pc,
                                            HostCodePiece code) {
   std::lock_guard<std::mutex> lock(mutex_);
 
-  auto* current = entry->host_code->load();
+  auto current = entry->host_code->load();
 
   // Might have been invalidated while wrapping.
   if (current == kEntryInvalidating) {
@@ -186,7 +187,7 @@ bool TranslationCache::IsHostFunctionWrapped(GuestAddr pc) const {
 }
 
 GuestCodeEntry* TranslationCache::AddUnsafe(GuestAddr pc,
-                                            std::atomic<HostCode>* host_code_ptr,
+                                            std::atomic<HostCodeAddr>* host_code_ptr,
                                             HostCodePiece host_code_piece,
                                             uint32_t guest_size,
                                             GuestCodeEntry::Kind kind,
@@ -231,12 +232,12 @@ const GuestCodeEntry* TranslationCache::LookupGuestCodeEntryUnsafe(GuestAddr pc)
 
 GuestAddr TranslationCache::SlowLookupGuestCodeEntryPCByHostPC(HostCode pc) {
   std::lock_guard<std::mutex> lock(mutex_);
+  const auto pc_addr = AsHostCodeAddr(pc);
 
   for (auto& it : guest_entries_) {
     auto* entry = &it.second;
     auto host_code = entry->host_code->load();
-    if (host_code <= pc &&
-        pc < AsHostCode(reinterpret_cast<uintptr_t>(host_code) + entry->host_size)) {
+    if (host_code <= pc_addr && pc_addr < host_code + entry->host_size) {
       return it.first;
     }
   }
@@ -286,7 +287,7 @@ void TranslationCache::InvalidateGuestRange(GuestAddr start, GuestAddr end) {
       break;
     }
 
-    HostCode current = entry->host_code->load();
+    HostCodeAddr current = entry->host_code->load();
 
     if (current == kEntryInvalidating) {
       // Translating but invalidated entry is handled in SetTranslatedAndUnlock.
diff --git a/runtime_primitives/translation_cache_test.cc b/runtime_primitives/translation_cache_test.cc
index e1c43c74..67c336f9 100644
--- a/runtime_primitives/translation_cache_test.cc
+++ b/runtime_primitives/translation_cache_test.cc
@@ -120,7 +120,7 @@ TEST(TranslationCacheTest, AddAndLockForWrapping) {
   ASSERT_FALSE(tc.AddAndLockForWrapping(pc + 64));
 }
 
-HostCode kHostCodeStub = AsHostCode(0xdeadbeef);
+HostCodeAddr kHostCodeStub = AsHostCodeAddr(AsHostCode(0xdeadbeef));
 
 void TestWrappingWorker(TranslationCache* tc, GuestAddr pc) {
   while (true) {
@@ -220,7 +220,7 @@ TEST(TranslationCacheTest, InvalidateNotTranslated) {
 
 TEST(TranslationCacheTest, InvalidateTranslated) {
   constexpr GuestAddr pc = 0x12345678;
-  const auto host_code = AsHostCode(0xdeadbeef);
+  const auto host_code = AsHostCodeAddr(AsHostCode(0xdeadbeef));
 
   TranslationCache tc;
 
@@ -239,7 +239,7 @@ TEST(TranslationCacheTest, InvalidateTranslated) {
 
 TEST(TranslationCacheTest, InvalidateTranslating) {
   constexpr GuestAddr pc = 0x12345678;
-  const auto host_code = AsHostCode(0xdeadbeef);
+  const auto host_code = AsHostCodeAddr(AsHostCode(0xdeadbeef));
 
   TranslationCache tc;
 
@@ -260,7 +260,7 @@ TEST(TranslationCacheTest, InvalidateTranslating) {
 
 TEST(TranslationCacheTest, InvalidateTranslatingOutOfRange) {
   constexpr GuestAddr pc = 0x12345678;
-  const auto host_code = AsHostCode(0xdeadbeef);
+  const auto host_code = AsHostCodeAddr(AsHostCode(0xdeadbeef));
 
   TranslationCache tc;
 
@@ -278,7 +278,7 @@ TEST(TranslationCacheTest, InvalidateTranslatingOutOfRange) {
   ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(pc)->load());
 }
 
-bool Translate(TranslationCache* tc, GuestAddr pc, uint32_t size, HostCode host_code) {
+bool Translate(TranslationCache* tc, GuestAddr pc, uint32_t size, HostCodeAddr host_code) {
   GuestCodeEntry* entry = tc->AddAndLockForTranslation(pc, 0);
   if (!entry) {
     return false;
@@ -290,7 +290,7 @@ bool Translate(TranslationCache* tc, GuestAddr pc, uint32_t size, HostCode host_
 
 TEST(TranslationCacheTest, LockForGearUpTranslation) {
   constexpr GuestAddr pc = 0x12345678;
-  const auto host_code = AsHostCode(0xdeadbeef);
+  const auto host_code = AsHostCodeAddr(AsHostCode(0xdeadbeef));
 
   TranslationCache tc;
 
@@ -302,10 +302,10 @@ TEST(TranslationCacheTest, LockForGearUpTranslation) {
   ASSERT_TRUE(entry);
   ASSERT_EQ(entry->kind, GuestCodeEntry::Kind::kSpecialHandler);
 
-  // Cannot lock if kind is not kLightTranslated.
+  // Cannot lock if kind is not kLiteTranslated.
   ASSERT_FALSE(tc.LockForGearUpTranslation(pc));
 
-  entry->kind = GuestCodeEntry::Kind::kLightTranslated;
+  entry->kind = GuestCodeEntry::Kind::kLiteTranslated;
 
   entry = tc.LockForGearUpTranslation(pc);
   ASSERT_TRUE(entry);
@@ -323,7 +323,7 @@ TEST(TranslationCacheTest, LockForGearUpTranslation) {
 
 TEST(TranslationCacheTest, InvalidateRange) {
   constexpr GuestAddr pc = 0x12345678;
-  const auto host_code = AsHostCode(0xdeadbeef);
+  const auto host_code = AsHostCodeAddr(AsHostCode(0xdeadbeef));
 
   TranslationCache tc;
 
@@ -342,7 +342,7 @@ TEST(TranslationCacheTest, InvalidateRange) {
   ASSERT_EQ(host_code, tc.GetHostCodePtr(pc + 2)->load());
 }
 
-bool Wrap(TranslationCache* tc, GuestAddr pc, HostCode host_code) {
+bool Wrap(TranslationCache* tc, GuestAddr pc, HostCodeAddr host_code) {
   GuestCodeEntry* entry = tc->AddAndLockForWrapping(pc);
   if (!entry) {
     return false;
diff --git a/test_utils/include/berberis/test_utils/insn_tests_riscv64-inl.h b/test_utils/include/berberis/test_utils/insn_tests_riscv64-inl.h
index c8ab6104..315a60f8 100644
--- a/test_utils/include/berberis/test_utils/insn_tests_riscv64-inl.h
+++ b/test_utils/include/berberis/test_utils/insn_tests_riscv64-inl.h
@@ -1384,10 +1384,14 @@ TEST_F(TESTSUITE, OpInstructions) {
 
   // Divu
   TestOp(0x23150b3, {{0x9999'9999'9999'9999, 0x3333, 0x0003'0003'0003'0003}});
+  TestOp(0x23150b3, {{42, 2, 21}});
+  TestOp(0x23150b3, {{42, 0, 0xffff'ffff'ffff'ffffULL}});
   // Rem
   TestOp(0x23160b3, {{0x9999'9999'9999'9999, 0x3333, 0xffff'ffff'ffff'ffff}});
+  TestOp(0x23160b3, {{0x9999'9999'9999'9999, 0, 0x9999'9999'9999'9999}});
   // Remu
   TestOp(0x23170b3, {{0x9999'9999'9999'9999, 0x3333, 0}});
+  TestOp(0x23170b3, {{0x9999'9999'9999'9999, 0, 0x9999'9999'9999'9999}});
   // Andn
   TestOp(0x403170b3, {{0b0101, 0b0011, 0b0100}});
   // Orn
@@ -1552,7 +1556,7 @@ TEST_F(TESTSUITE, OpImmInstructions) {
   // Binvi
   TestOpImm(0x68011093, {{0b1000'0001'0000'0001ULL, 0, 0b1000'0001'0000'0000ULL}});
   TestOpImm(0x68011093, {{0b1000'0001'0000'0001ULL, 1, 0b1000'0001'0000'0011ULL}});
-  // Bset
+  // Bseti
   TestOpImm(0x28011093, {{0b1000'0001'0000'0001ULL, 0, 0b1000'0001'0000'0001ULL}});
   TestOpImm(0x28011093, {{0b1000'0001'0000'0001ULL, 1, 0b1000'0001'0000'0011ULL}});
 }
diff --git a/test_utils/include/berberis/test_utils/scoped_exec_region.h b/test_utils/include/berberis/test_utils/scoped_exec_region.h
index 38542c92..3329b9b5 100644
--- a/test_utils/include/berberis/test_utils/scoped_exec_region.h
+++ b/test_utils/include/berberis/test_utils/scoped_exec_region.h
@@ -20,7 +20,8 @@
 
 #include "berberis/assembler/machine_code.h"
 #include "berberis/base/bit_util.h"
-#include "berberis/base/exec_region_anonymous.h"
+#include "berberis/runtime_primitives/exec_region_anonymous.h"
+#include "berberis/runtime_primitives/host_code.h"
 
 namespace berberis {
 
@@ -48,6 +49,8 @@ class ScopedExecRegion {
     return bit_cast<const T*>(exec_.begin());
   }
 
+  HostCodeAddr GetHostCodeAddr() const { return AsHostCodeAddr(AsHostCode(exec_.begin())); }
+
   [[nodiscard]] const RecoveryMap& recovery_map() const { return recovery_map_; }
 
  private:
diff --git a/tests/inline_asm_tests/main_arm64.cc b/tests/inline_asm_tests/main_arm64.cc
index 0d40a634..578e6cf4 100644
--- a/tests/inline_asm_tests/main_arm64.cc
+++ b/tests/inline_asm_tests/main_arm64.cc
@@ -3440,6 +3440,14 @@ TEST(Arm64InsnTest, MulAddF64IndexedElem) {
   ASSERT_EQ(AsmFmla(arg1, arg2, arg3), bit_cast<uint64_t>(16.0));
 }
 
+TEST(Arm64InsnTest, MulAddF64x2) {
+  constexpr auto AsmFmla = ASM_INSN_WRAP_FUNC_W_RES_WW0_ARG("fmla %0.2d, %1.2d, %2.2d");
+  __uint128_t arg1 = MakeF64x2(1.0f, 2.0f);
+  __uint128_t arg2 = MakeF64x2(3.0f, 1.0f);
+  __uint128_t arg3 = MakeF64x2(2.0f, 3.0f);
+  ASSERT_EQ(AsmFmla(arg1, arg2, arg3), MakeF64x2(5.0f, 5.0f));
+}
+
 TEST(Arm64InsnTest, MulAddF32x4IndexedElem) {
   constexpr auto AsmFmla = ASM_INSN_WRAP_FUNC_W_RES_WW0_ARG("fmla %0.4s, %1.4s, %2.s[2]");
   __uint128_t arg1 = MakeF32x4(1.0f, 2.0f, 4.0f, 3.0f);
@@ -3504,6 +3512,22 @@ TEST(Arm64InsnTest, MulSubF32IndexedElem) {
   ASSERT_EQ(AsmFmls(arg1, arg2, arg3), bit_cast<uint32_t>(4.0f));
 }
 
+TEST(Arm64InsnTest, MulSubF32x4IndexedElem) {
+  constexpr auto AsmFmls = ASM_INSN_WRAP_FUNC_W_RES_WW0_ARG("fmls %0.4s, %1.4s, %2.s[2]");
+  __uint128_t arg1 = MakeF32x4(1.0f, 2.0f, 4.0f, 3.0f);
+  __uint128_t arg2 = MakeF32x4(3.0f, 1.0f, 2.0f, 4.0f);
+  __uint128_t arg3 = MakeF32x4(2.0f, 3.0f, 1.0f, 2.0f);
+  ASSERT_EQ(AsmFmls(arg1, arg2, arg3), MakeF32x4(0.0f, -1.0f, -7.0f, -4.0f));
+}
+
+TEST(Arm64InsnTest, MulSubF64x2) {
+  constexpr auto AsmFmls = ASM_INSN_WRAP_FUNC_W_RES_WW0_ARG("fmls %0.2d, %1.2d, %2.2d");
+  __uint128_t arg1 = MakeF64x2(1.0f, 2.0f);
+  __uint128_t arg2 = MakeF64x2(3.0f, 1.0f);
+  __uint128_t arg3 = MakeF64x2(2.0f, 3.0f);
+  ASSERT_EQ(AsmFmls(arg1, arg2, arg3), MakeF64x2(-1.0f, 1.0f));
+}
+
 TEST(Arm64InsnTest, MulSubF64IndexedElem) {
   constexpr auto AsmFmls = ASM_INSN_WRAP_FUNC_W_RES_WW0_ARG("fmls %d0, %d1, %2.d[1]");
   __uint128_t arg1 = MakeF64x2(2.0, 5.0);
@@ -3513,14 +3537,6 @@ TEST(Arm64InsnTest, MulSubF64IndexedElem) {
   ASSERT_EQ(AsmFmls(arg1, arg2, arg3), bit_cast<uint64_t>(4.0));
 }
 
-TEST(Arm64InsnTest, MulSubF32x4IndexedElem) {
-  constexpr auto AsmFmls = ASM_INSN_WRAP_FUNC_W_RES_WW0_ARG("fmls %0.4s, %1.4s, %2.s[2]");
-  __uint128_t arg1 = MakeF32x4(1.0f, 2.0f, 4.0f, 3.0f);
-  __uint128_t arg2 = MakeF32x4(3.0f, 1.0f, 2.0f, 4.0f);
-  __uint128_t arg3 = MakeF32x4(2.0f, 3.0f, 1.0f, 2.0f);
-  ASSERT_EQ(AsmFmls(arg1, arg2, arg3), MakeF32x4(0.0f, -1.0f, -7.0f, -4.0f));
-}
-
 TEST(Arm64InsnTest, CompareEqualF32) {
   constexpr auto AsmFcmeq = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("fcmeq %s0, %s1, %s2");
   uint32_t two = bit_cast<uint32_t>(2.0f);
@@ -4181,6 +4197,20 @@ TEST(Arm64InsnTest, SubInt64x2) {
   ASSERT_EQ(res, MakeUInt128(0xf05ab9e150f64c76ULL, 0xfcd31262935bf1d0ULL));
 }
 
+TEST(Arm64InsnTest, SubInt32x4) {
+  __uint128_t op1 = MakeUInt128(0x0000000A00000005ULL, 0x0000000C00000C45ULL);
+  __uint128_t op2 = MakeUInt128(0x0000000500000003ULL, 0x0000000200000C45ULL);
+  __uint128_t rd = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("sub %0.4s, %1.4s, %2.4s")(op1, op2);
+  ASSERT_EQ(rd, MakeUInt128(0x0000000500000002ULL, 0x00000000A00000000ULL));
+}
+
+TEST(Arm64InsnTest, SubInt32x2) {
+  __uint128_t op1 = MakeUInt128(0x0000000000000005ULL, 0x0000000000000C45ULL);
+  __uint128_t op2 = MakeUInt128(0x0000000000000003ULL, 0x0000000000000C45ULL);
+  __uint128_t rd = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("sub %0.2s, %1.2s, %2.2s")(op1, op2);
+  ASSERT_EQ(rd, MakeUInt128(0x0000000000000002ULL, 0x00000000000000000ULL));
+}
+
 TEST(Arm64InsnTest, SubInt16x4) {
   __uint128_t arg1 = MakeUInt128(0x8888777766665555ULL, 0);
   __uint128_t arg2 = MakeUInt128(0x1111222233334444ULL, 0);
diff --git a/tests/jni_tests/jni/jni_tests.cc b/tests/jni_tests/jni/jni_tests.cc
index 02d06056..7fa4f9ea 100644
--- a/tests/jni_tests/jni/jni_tests.cc
+++ b/tests/jni_tests/jni/jni_tests.cc
@@ -96,4 +96,41 @@ JNIEXPORT jint JNICALL Java_com_berberis_jnitests_JniTests_callCallIntFromJNI(JN
   return env->CallStaticIntMethod(clazz, method_id);
 }
 
+// Prevent clang-format form unfolding it into 125+ lines.
+// clang-format off
+JNIEXPORT jint JNICALL Java_com_berberis_jnitests_JniTests_Sum125(
+    JNIEnv*,
+    jclass,
+    jint arg1, jint arg2, jint arg3, jint arg4, jint arg5, jint arg6, jint arg7, jint arg8,
+    jint arg9, jint arg10, jint arg11, jint arg12, jint arg13, jint arg14, jint arg15, jint arg16,
+    jint arg17, jint arg18, jint arg19, jint arg20, jint arg21, jint arg22, jint arg23, jint arg24,
+    jint arg25, jint arg26, jint arg27, jint arg28, jint arg29, jint arg30, jint arg31, jint arg32,
+    jint arg33, jint arg34, jint arg35, jint arg36, jint arg37, jint arg38, jint arg39, jint arg40,
+    jint arg41, jint arg42, jint arg43, jint arg44, jint arg45, jint arg46, jint arg47, jint arg48,
+    jint arg49, jint arg50, jint arg51, jint arg52, jint arg53, jint arg54, jint arg55, jint arg56,
+    jint arg57, jint arg58, jint arg59, jint arg60, jint arg61, jint arg62, jint arg63, jint arg64,
+    jint arg65, jint arg66, jint arg67, jint arg68, jint arg69, jint arg70, jint arg71, jint arg72,
+    jint arg73, jint arg74, jint arg75, jint arg76, jint arg77, jint arg78, jint arg79, jint arg80,
+    jint arg81, jint arg82, jint arg83, jint arg84, jint arg85, jint arg86, jint arg87, jint arg88,
+    jint arg89, jint arg90, jint arg91, jint arg92, jint arg93, jint arg94, jint arg95, jint arg96,
+    jint arg97, jint arg98, jint arg99, jint arg100, jint arg101, jint arg102, jint arg103,
+    jint arg104, jint arg105, jint arg106, jint arg107, jint arg108, jint arg109, jint arg110,
+    jint arg111, jint arg112, jint arg113, jint arg114, jint arg115, jint arg116, jint arg117,
+    jint arg118, jint arg119, jint arg120, jint arg121, jint arg122, jint arg123, jint arg124,
+    jint arg125) {
+  // clang-format on
+  return arg1 + arg2 + arg3 + arg4 + arg5 + arg6 + arg7 + arg8 + arg9 + arg10 + arg11 + arg12 +
+         arg13 + arg14 + arg15 + arg16 + arg17 + arg18 + arg19 + arg20 + arg21 + arg22 + arg23 +
+         arg24 + arg25 + arg26 + arg27 + arg28 + arg29 + arg30 + arg31 + arg32 + arg33 + arg34 +
+         arg35 + arg36 + arg37 + arg38 + arg39 + arg40 + arg41 + arg42 + arg43 + arg44 + arg45 +
+         arg46 + arg47 + arg48 + arg49 + arg50 + arg51 + arg52 + arg53 + arg54 + arg55 + arg56 +
+         arg57 + arg58 + arg59 + arg60 + arg61 + arg62 + arg63 + arg64 + arg65 + arg66 + arg67 +
+         arg68 + arg69 + arg70 + arg71 + arg72 + arg73 + arg74 + arg75 + arg76 + arg77 + arg78 +
+         arg79 + arg80 + arg81 + arg82 + arg83 + arg84 + arg85 + arg86 + arg87 + arg88 + arg89 +
+         arg90 + arg91 + arg92 + arg93 + arg94 + arg95 + arg96 + arg97 + arg98 + arg99 + arg100 +
+         arg101 + arg102 + arg103 + arg104 + arg105 + arg106 + arg107 + arg108 + arg109 + arg110 +
+         arg111 + arg112 + arg113 + arg114 + arg115 + arg116 + arg117 + arg118 + arg119 + arg120 +
+         arg121 + arg122 + arg123 + arg124 + arg125;
+}
+
 }  // extern "C"
diff --git a/tests/jni_tests/src/com/berberis/jnitests/JniTests.java b/tests/jni_tests/src/com/berberis/jnitests/JniTests.java
index 9a56f221..c37cc14b 100644
--- a/tests/jni_tests/src/com/berberis/jnitests/JniTests.java
+++ b/tests/jni_tests/src/com/berberis/jnitests/JniTests.java
@@ -95,4 +95,41 @@ public final class JniTests {
     public void testCallNativeCallJavaCallNative() {
       assertEquals(42, callCallIntFromJNI());
     }
+
+    @Test
+    public void testCallNativeMethodWith125Args() {
+        assertEquals(5250, Sum125(
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
+                42, 42, 42, 42, 42));
+    }
+
+    static native int Sum125(
+            int arg1, int arg2, int arg3, int arg4, int arg5, int arg6, int arg7, int arg8,
+            int arg9, int arg10, int arg11, int arg12, int arg13, int arg14, int arg15, int arg16,
+            int arg17, int arg18, int arg19, int arg20, int arg21, int arg22, int arg23, int arg24,
+            int arg25, int arg26, int arg27, int arg28, int arg29, int arg30, int arg31, int arg32,
+            int arg33, int arg34, int arg35, int arg36, int arg37, int arg38, int arg39, int arg40,
+            int arg41, int arg42, int arg43, int arg44, int arg45, int arg46, int arg47, int arg48,
+            int arg49, int arg50, int arg51, int arg52, int arg53, int arg54, int arg55, int arg56,
+            int arg57, int arg58, int arg59, int arg60, int arg61, int arg62, int arg63, int arg64,
+            int arg65, int arg66, int arg67, int arg68, int arg69, int arg70, int arg71, int arg72,
+            int arg73, int arg74, int arg75, int arg76, int arg77, int arg78, int arg79, int arg80,
+            int arg81, int arg82, int arg83, int arg84, int arg85, int arg86, int arg87, int arg88,
+            int arg89, int arg90, int arg91, int arg92, int arg93, int arg94, int arg95, int arg96,
+            int arg97, int arg98, int arg99, int arg100, int arg101, int arg102, int arg103,
+            int arg104, int arg105, int arg106, int arg107, int arg108, int arg109, int arg110,
+            int arg111, int arg112, int arg113, int arg114, int arg115, int arg116, int arg117,
+            int arg118, int arg119, int arg120, int arg121, int arg122, int arg123, int arg124,
+            int arg125);
 }
diff --git a/tests/ndk_program_tests/arm/sigill_test.cc b/tests/ndk_program_tests/arm/sigill_test.cc
index 6c1fd036..46f66990 100644
--- a/tests/ndk_program_tests/arm/sigill_test.cc
+++ b/tests/ndk_program_tests/arm/sigill_test.cc
@@ -22,7 +22,7 @@
 
 #include <cstdio>
 
-#include "scoped_sigaction.h"
+#include "berberis/ndk_program_tests/scoped_sigaction.h"
 
 namespace {
 
diff --git a/tests/ndk_program_tests/arm64/sigill_test.cc b/tests/ndk_program_tests/arm64/sigill_test.cc
index f8605582..38f2e18a 100644
--- a/tests/ndk_program_tests/arm64/sigill_test.cc
+++ b/tests/ndk_program_tests/arm64/sigill_test.cc
@@ -22,7 +22,7 @@
 
 #include <cstdio>
 
-#include "scoped_sigaction.h"
+#include "berberis/ndk_program_tests/scoped_sigaction.h"
 
 namespace {
 
diff --git a/tests/ndk_program_tests/file.h b/tests/ndk_program_tests/file.h
deleted file mode 100644
index d9e46795..00000000
--- a/tests/ndk_program_tests/file.h
+++ /dev/null
@@ -1,78 +0,0 @@
-/*
- * Copyright (C) 2014 The Android Open Source Project
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
-// Common header for manipulations with files.
-#ifndef BERBERIS_TESTS_TESTS_APK_JNI_FILE_H_
-#define BERBERIS_TESTS_TESTS_APK_JNI_FILE_H_
-
-#include <unistd.h>
-
-#include <cstdio>
-#include <cstdlib>
-
-inline const char* InitTempFileTemplate() {
-  // tempnam() is not recommended for use, but we only use it to get the
-  // temp dir as it varies on different platforms. E.g. /tmp on Linux,
-  // or /data/local/tmp on Android. The actual file creation is done by
-  // the reliable mkstemp().
-  char* gen_name = tempnam(/* dir */ nullptr, /* prefix */ nullptr);
-  char* template_name;
-  asprintf(&template_name, "%s-ndk-tests-XXXXXX", gen_name);
-  free(gen_name);
-  return template_name;
-}
-
-inline const char* TempFileTemplate() {
-  static const char* kTemplateName = InitTempFileTemplate();
-  return kTemplateName;
-}
-
-class TempFile {
- public:
-  TempFile() {
-    file_name_ = strdup(TempFileTemplate());
-    // Altenatively we could have created a file descriptor by tmpfile() or
-    // mkstemp() with the relative filename, but then there is no portable way
-    // to identify the full file name.
-    fd_ = mkstemp(file_name_);
-    if (fd_ < 0) {
-      file_ = NULL;
-      return;
-    }
-    file_ = fdopen(fd_, "r+");
-  }
-
-  ~TempFile() {
-    if (file_ != NULL) {
-      fclose(file_);
-    }
-    unlink(file_name_);
-    free(file_name_);
-  }
-
-  FILE* get() { return file_; }
-
-  int fd() { return fd_; }
-
-  const char* FileName() { return file_name_; }
-
- private:
-  FILE* file_;
-  char* file_name_;
-  int fd_;
-};
-
-#endif  // BERBERIS_TESTS_TESTS_APK_JNI_FILE_H_
diff --git a/tests/ndk_program_tests/file_test.cc b/tests/ndk_program_tests/file_test.cc
index eab9ff01..d1634688 100644
--- a/tests/ndk_program_tests/file_test.cc
+++ b/tests/ndk_program_tests/file_test.cc
@@ -29,7 +29,7 @@
 #include <cstdio>
 #include <cstdlib>
 
-#include "file.h"  // NOLINT
+#include "berberis/ndk_program_tests/file.h"
 
 //------------------------------------------------------------------------------
 // Test simple file IO
diff --git a/tests/ndk_program_tests/scoped_sigaction.h b/tests/ndk_program_tests/scoped_sigaction.h
deleted file mode 100644
index 15577238..00000000
--- a/tests/ndk_program_tests/scoped_sigaction.h
+++ /dev/null
@@ -1,39 +0,0 @@
-/*
- * Copyright (C) 2014 The Android Open Source Project
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
-#ifndef BERBERIS_TESTS_NDK_PROGRAM_TESTS_SCOPED_SIGACTION_H_
-#define BERBERIS_TESTS_NDK_PROGRAM_TESTS_SCOPED_SIGACTION_H_
-
-#include "gtest/gtest.h"
-
-#include <signal.h>
-
-class ScopedSigaction {
- public:
-  ScopedSigaction(int sig, const struct sigaction* act) : sig_(sig) { Init(act); }
-
-  ~ScopedSigaction() { Fini(); }
-
- private:
-  void Init(const struct sigaction* act) { ASSERT_EQ(0, sigaction(sig_, act, &old_act_)); }
-
-  void Fini() { ASSERT_EQ(0, sigaction(sig_, &old_act_, nullptr)); }
-
-  int sig_;
-  struct sigaction old_act_;
-};
-
-#endif  // BERBERIS_TESTS_NDK_PROGRAM_TESTS_SCOPED_SIGACTION_H_
diff --git a/tiny_loader/include/berberis/tiny_loader/tiny_loader.h b/tiny_loader/include/berberis/tiny_loader/tiny_loader.h
index 9ebc1da2..93e6b806 100644
--- a/tiny_loader/include/berberis/tiny_loader/tiny_loader.h
+++ b/tiny_loader/include/berberis/tiny_loader/tiny_loader.h
@@ -43,6 +43,9 @@ class TinyLoader {
   static bool LoadFromMemory(const char* path, void* address, size_t size,
                              LoadedElfFile* loaded_elf_file, std::string* error_msg);
 
+  // Returns 0 in the case of error.
+  static size_t CalculateLoadSize(const char* path, std::string* error_msg);
+
  private:
   DISALLOW_IMPLICIT_CONSTRUCTORS(TinyLoader);
 };
diff --git a/tiny_loader/tests/tiny_loader_tests.cc b/tiny_loader/tests/tiny_loader_tests.cc
index 662b6729..b418b81d 100644
--- a/tiny_loader/tests/tiny_loader_tests.cc
+++ b/tiny_loader/tests/tiny_loader_tests.cc
@@ -18,6 +18,8 @@
 
 #include "berberis/tiny_loader/tiny_loader.h"
 
+#include <cstddef>
+#include <cstdint>
 #include <string>
 
 #include <sys/user.h>
@@ -33,6 +35,7 @@ const constexpr char* kTestLibInvalidElfClassName = "libtinytest_invalid_elf_cla
 const constexpr char* kTestLibGnuName = "libtinytest.so";
 const constexpr char* kTestLibSysvName = "libtinytest_sysv.so";
 const constexpr char* kTestExecutableName = "tiny_static_executable";
+constexpr size_t kTestLibGnuLoadSize = 0x3000;
 
 #if defined(__LP64__)
 constexpr uintptr_t kStaticExecutableEntryPoint = 0x1ce00;
@@ -132,6 +135,14 @@ TEST(tiny_loader, library_sysv_hash) {
   TestLoadLibrary(kTestLibSysvName);
 }
 
+TEST(tiny_loader, CalculateLoadSize) {
+  std::string error_msg;
+  std::string elf_filepath;
+  ASSERT_TRUE(GetTestElfFilepath(kTestLibGnuName, &elf_filepath, &error_msg)) << error_msg;
+  size_t size = TinyLoader::CalculateLoadSize(elf_filepath.c_str(), &error_msg);
+  EXPECT_EQ(size, kTestLibGnuLoadSize);
+}
+
 TEST(tiny_loader, library_invalid_elf_class) {
   LoadedElfFile loaded_elf_file;
   std::string error_msg;
diff --git a/tiny_loader/tiny_loader.cc b/tiny_loader/tiny_loader.cc
index 400c8219..9b3da357 100644
--- a/tiny_loader/tiny_loader.cc
+++ b/tiny_loader/tiny_loader.cc
@@ -24,11 +24,15 @@
 #include <sys/user.h>
 #include <unistd.h>
 
+#include <cstddef>
+#include <tuple>
+
 #include "berberis/base/bit_util.h"
 #include "berberis/base/checks.h"
 #include "berberis/base/mapped_file_fragment.h"
 #include "berberis/base/page_size.h"
 #include "berberis/base/prctl_helpers.h"
+#include "berberis/base/scoped_fd.h"
 #include "berberis/base/stringprintf.h"
 
 #define MAYBE_MAP_FLAG(x, from, to) (((x) & (from)) ? (to) : 0)
@@ -125,14 +129,21 @@ class TinyElfLoader {
  public:
   explicit TinyElfLoader(const char* name);
 
-  bool LoadFromFile(int fd, off64_t file_size, size_t align, TinyLoader::mmap64_fn_t mmap64_fn,
-                    TinyLoader::munmap_fn_t munmap_fn, LoadedElfFile* loaded_elf_file);
+  std::tuple<bool, size_t> CalculateLoadSize(const char* path);
+
+  bool LoadFromFile(const char* path,
+                    size_t align,
+                    TinyLoader::mmap64_fn_t mmap64_fn,
+                    TinyLoader::munmap_fn_t munmap_fn,
+                    LoadedElfFile* loaded_elf_file);
 
   bool LoadFromMemory(void* load_addr, size_t load_size, LoadedElfFile* loaded_elf_file);
 
   const std::string& error_msg() const { return error_msg_; }
 
  private:
+  // Returns success, fd and file_size.
+  std::tuple<bool, int, size_t> OpenFile(const char* path);
   bool CheckElfHeader(const ElfEhdr* header);
   bool ReadElfHeader(int fd, ElfEhdr* header);
   bool ReadProgramHeadersFromFile(const ElfEhdr* header, int fd, off64_t file_size,
@@ -615,7 +626,54 @@ bool TinyElfLoader::Parse(void* load_ptr, size_t load_size, LoadedElfFile* loade
   return true;
 }
 
-bool TinyElfLoader::LoadFromFile(int fd, off64_t file_size, size_t align,
+// Returns success, fd and file_size.
+std::tuple<bool, int, size_t> TinyElfLoader::OpenFile(const char* path) {
+  int fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));
+  if (fd == -1) {
+    set_error_msg(&error_msg_, "unable to open the file \"%s\": %s", path, strerror(errno));
+    return {false, -1, 0};
+  }
+
+  struct stat file_stat;
+  if (TEMP_FAILURE_RETRY(fstat(fd, &file_stat)) != 0) {
+    set_error_msg(
+        &error_msg_, "unable to stat file for the library \"%s\": %s", path, strerror(errno));
+    close(fd);
+    return {false, -1, 0};
+  }
+
+  return {true, fd, file_stat.st_size};
+}
+
+std::tuple<bool, size_t> TinyElfLoader::CalculateLoadSize(const char* path) {
+  auto [is_opened, fd, file_size] = OpenFile(path);
+  if (!is_opened) {
+    return {false, 0};
+  }
+
+  berberis::ScopedFd scoped_fd(fd);
+
+  ElfEhdr header;
+  const ElfPhdr* phdr_table = nullptr;
+  size_t phdr_num = 0;
+
+  if (!ReadElfHeader(fd, &header) ||
+      !ReadProgramHeadersFromFile(&header, fd, file_size, &phdr_table, &phdr_num)) {
+    return {false, 0};
+  }
+
+  ElfAddr min_vaddr;
+  size_t size = phdr_table_get_load_size(phdr_table, phdr_num, &min_vaddr);
+  if (size == 0) {
+    set_error_msg(&error_msg_, "\"%s\" has no loadable segments", name_);
+    return {false, 0};
+  }
+
+  return {true, size};
+}
+
+bool TinyElfLoader::LoadFromFile(const char* path,
+                                 size_t align,
                                  TinyLoader::mmap64_fn_t mmap64_fn,
                                  TinyLoader::munmap_fn_t munmap_fn,
                                  LoadedElfFile* loaded_elf_file) {
@@ -626,6 +684,13 @@ bool TinyElfLoader::LoadFromFile(int fd, off64_t file_size, size_t align,
   const ElfPhdr* phdr_table = nullptr;
   size_t phdr_num = 0;
 
+  auto [is_opened, fd, file_size] = OpenFile(path);
+  if (!is_opened) {
+    return false;
+  }
+
+  berberis::ScopedFd scoped_fd(fd);
+
   did_load_ = ReadElfHeader(fd, &header) &&
               ReadProgramHeadersFromFile(&header, fd, file_size, &phdr_table, &phdr_num) &&
               LoadSegments(fd, file_size, header.e_type, phdr_table, phdr_num, align, mmap64_fn,
@@ -644,35 +709,22 @@ bool TinyElfLoader::LoadFromMemory(void* load_addr, size_t load_size,
 
 }  // namespace
 
-bool TinyLoader::LoadFromFile(const char* path, size_t align, TinyLoader::mmap64_fn_t mmap64_fn,
-                              TinyLoader::munmap_fn_t munmap_fn, LoadedElfFile* loaded_elf_file,
+bool TinyLoader::LoadFromFile(const char* path,
+                              size_t align,
+                              TinyLoader::mmap64_fn_t mmap64_fn,
+                              TinyLoader::munmap_fn_t munmap_fn,
+                              LoadedElfFile* loaded_elf_file,
                               std::string* error_msg) {
-  int fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));
-  if (fd == -1) {
-    set_error_msg(error_msg, "unable to open the file \"%s\": %s", path, strerror(errno));
-    return false;
-  }
-
-  struct stat file_stat;
-  if (TEMP_FAILURE_RETRY(fstat(fd, &file_stat)) != 0) {
-    set_error_msg(error_msg, "unable to stat file for the library \"%s\": %s", path,
-                  strerror(errno));
-    close(fd);
-    return false;
-  }
-
   TinyElfLoader loader(path);
 
-  if (!loader.LoadFromFile(fd, file_stat.st_size, align, mmap64_fn, munmap_fn, loaded_elf_file)) {
+  if (!loader.LoadFromFile(path, align, mmap64_fn, munmap_fn, loaded_elf_file)) {
     if (error_msg != nullptr) {
       *error_msg = loader.error_msg();
     }
 
-    close(fd);
     return false;
   }
 
-  close(fd);
   return true;
 }
 
@@ -689,3 +741,17 @@ bool TinyLoader::LoadFromMemory(const char* path, void* address, size_t size,
 
   return true;
 }
+
+size_t TinyLoader::CalculateLoadSize(const char* path, std::string* error_msg) {
+  TinyElfLoader loader(path);
+  auto [success, size] = loader.CalculateLoadSize(path);
+  if (success) {
+    return size;
+  }
+
+  if (error_msg != nullptr) {
+    *error_msg = loader.error_msg();
+  }
+
+  return 0;
+}
diff --git a/tools/difflist.sh b/tools/difflist.sh
new file mode 100755
index 00000000..32bc130b
--- /dev/null
+++ b/tools/difflist.sh
@@ -0,0 +1,98 @@
+#!/bin/bash
+#
+#
+# Copyright (C) 2018 The Android Open Source Project
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
+#
+# Note: have to be run from the root of the repository and you must ensure that
+# both remotes goog/mirror-aosp-main and goog/main exists.
+
+aosp_branch=goog/mirror-aosp-main
+local_branch=goog/main
+
+set -eu
+
+if [[ -d "frameworks/libs/binary_translation" ]]; then
+  cd "frameworks/libs/binary_translation"
+else
+  while ! [[ -d ".git" ]]; do
+    cd ..
+    if [[ "$PWD" == "/" ]]; then
+      echo "Couldn't find working directory"
+      exit 1
+    fi
+  done
+fi
+
+readarray -t files < <(
+  git diff "$aosp_branch" "$local_branch" |
+  grep '^diff --git' |
+  while read d g a b ; do
+    echo "${b:2}"
+  done
+)
+declare -A aosp_cls=() goog_cls=()
+for file in "${files[@]}"; do
+  readarray -t aosp_changes < <(
+    git log "$aosp_branch" "$file" |
+    grep '^commit ' |
+    cut -b 8-
+  )
+  declare -A aosp_changes_map
+  for aosp_change in "${aosp_changes[@]}"; do
+    aosp_change_id="$(
+      git log -n 1 "$aosp_change" | grep Change-Id: || true
+    )"
+    if ! [[ -z "${aosp_change_id}" ]]; then
+      aosp_changes_map["$aosp_change_id"]=https://googleplex-android-review.googlesource.com/q/commit:"$aosp_change"
+    fi
+  done
+  readarray -t goog_changes < <(
+    git log "$local_branch" "$file" |
+    grep '^commit ' |
+    cut -b 8-
+  )
+  declare -A goog_changes_map
+  for goog_change in "${goog_changes[@]}"; do
+    goog_change_id="$(
+      git log -n 1 "$goog_change" | grep Change-Id: || true
+    )"
+    if ! [[ -z "${goog_change_id}" ]]; then
+      goog_changes_map["$goog_change_id"]=https://googleplex-android-review.googlesource.com/q/commit:"$goog_change"
+    fi
+  done
+
+  for aosp_change_id in "${!aosp_changes_map[@]}"; do
+    if [[ "${goog_changes_map["$aosp_change_id"]:-absent}" = "absent" ]] ; then
+      aosp_cls[$aosp_change_id]="${aosp_changes_map[$aosp_change_id]}"
+    fi
+  done
+  for goog_change_id in "${!goog_changes_map[@]}"; do
+    if [[ "${aosp_changes_map["$goog_change_id"]:-absent}" = "absent" ]] ; then
+       goog_cls[$goog_change_id]="${goog_changes_map[$goog_change_id]}"
+    fi
+  done
+done
+if ((${#aosp_cls[@]}>0)); then
+  echo Only in AOSP:
+  for cl in "${!aosp_cls[@]}" ; do
+    echo "$cl => ${aosp_cls[$cl]}"
+  done
+fi
+if ((${#goog_cls[@]}>0)); then
+  echo Only in GOOG:
+  for cl in "${!goog_cls[@]}" ; do
+    echo "$cl => ${goog_cls[$cl]}"
+  done
+fi
```

