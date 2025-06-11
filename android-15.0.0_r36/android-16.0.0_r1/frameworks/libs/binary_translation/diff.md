```diff
diff --git a/Android.bp b/Android.bp
index f5702d54..9f8065d6 100644
--- a/Android.bp
+++ b/Android.bp
@@ -300,12 +300,63 @@ cc_test_host {
     },
 }
 
+// Clang violates psABI: https://groups.google.com/g/x86-64-abi/c/BjOOyihHuqg
+// We want to esnrue that possible fix of this bug wouldn't be unnoticed: b/382703210
+cc_test_host {
+    name: "berberis_host_tests_avx",
+    defaults: ["berberis_defaults"],
+    shared_libs: [
+        "libbase",
+        "liblog",
+    ],
+    arch: {
+        x86_64: {
+            cflags: ["-mavx"],
+            srcs: ["intrinsics/all_to_x86_64/tuple_test.cc"],
+            // Note: we must NOT use any static or shared libraries with SIMDRegister type involved
+            // here, only header_libs, because those may be compiled with no-avx.
+            // Safest way is to only use libbase/loblog needed for gTest itself.
+            header_libs: ["libberberis_intrinsics_headers"],
+        },
+    },
+    test_suites: ["device-tests"],
+    test_options: {
+        unit_test: true,
+    },
+}
+
+// Ensure that everything works in no-AVX case too (there clang follows psABI correctly).
+cc_test_host {
+    name: "berberis_host_tests_no_avx",
+    defaults: ["berberis_defaults"],
+    shared_libs: [
+        "libbase",
+        "liblog",
+    ],
+    arch: {
+        x86_64: {
+            cflags: ["-mno-avx"],
+            srcs: ["intrinsics/all_to_x86_64/tuple_test.cc"],
+            // Note: we must NOT use any static or shared libraries with SIMDRegister type involved
+            // here, only header_libs, because those may be compiled with avx.
+            // Safest way is to only use libbase/loblog needed for gTest itself.
+            header_libs: ["libberberis_intrinsics_headers"],
+        },
+    },
+    test_suites: ["device-tests"],
+    test_options: {
+        unit_test: true,
+    },
+}
+
 phony_rule_defaults {
     name: "berberis_all_deps_defaults",
     phony_deps: [
         "berberis_hello_world.native_bridge",
         "berberis_hello_world_static.native_bridge",
         "berberis_host_tests",
+        "berberis_host_tests_avx",
+        "berberis_host_tests_no_avx",
         "berberis_ndk_program_tests",
         "berberis_ndk_program_tests.native_bridge",
         "berberis_perf_tests_static.native_bridge",
diff --git a/assembler/Android.bp b/assembler/Android.bp
index e0f38f50..3e5af686 100644
--- a/assembler/Android.bp
+++ b/assembler/Android.bp
@@ -55,6 +55,11 @@ filegroup {
     ],
 }
 
+filegroup {
+    name: "libberberis_assembler_gen_inputs_riscv",
+    srcs: ["instructions/insn_def_riscv.json"],
+}
+
 filegroup {
     name: "libberberis_assembler_gen_inputs_x86_32",
     srcs: [
@@ -71,6 +76,11 @@ filegroup {
     ],
 }
 
+filegroup {
+    name: "libberberis_assembler_gen_inputs_x86_common",
+    srcs: ["instructions/insn_def_x86.json"],
+}
+
 genrule {
     name: "libberberis_assembler_gen_public_headers_riscv32",
     out: [
@@ -82,6 +92,14 @@ genrule {
     cmd: "$(location gen_asm) --binary-assembler $(out) $(in)",
 }
 
+genrule {
+    name: "libberberis_assembler_gen_public_headers_using_riscv32",
+    out: ["berberis/assembler/gen_assembler_rv32-using-inl.h"],
+    srcs: [":libberberis_assembler_gen_inputs_riscv32"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --using $(out) $(in)",
+}
+
 genrule {
     name: "libberberis_assembler_gen_public_headers_riscv64",
     out: [
@@ -93,6 +111,22 @@ genrule {
     cmd: "$(location gen_asm) --binary-assembler $(out) $(in)",
 }
 
+genrule {
+    name: "libberberis_assembler_gen_public_headers_using_riscv64",
+    out: ["berberis/assembler/gen_assembler_rv64-using-inl.h"],
+    srcs: [":libberberis_assembler_gen_inputs_riscv64"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --using $(out) $(in)",
+}
+
+genrule {
+    name: "libberberis_assembler_gen_public_headers_using_riscv",
+    out: ["berberis/assembler/gen_assembler_riscv-using-inl.h"],
+    srcs: [":libberberis_assembler_gen_inputs_riscv"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --using $(out) $(in)",
+}
+
 genrule {
     name: "libberberis_assembler_gen_public_headers_x86_32",
     out: [
@@ -104,6 +138,14 @@ genrule {
     cmd: "$(location gen_asm) --binary-assembler $(out) $(in)",
 }
 
+genrule {
+    name: "libberberis_assembler_gen_public_headers_using_x86_32",
+    out: ["berberis/assembler/gen_assembler_x86_32-using-inl.h"],
+    srcs: [":libberberis_assembler_gen_inputs_x86_32"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --using $(out) $(in)",
+}
+
 genrule {
     name: "libberberis_assembler_gen_public_headers_x86_64",
     out: [
@@ -115,6 +157,22 @@ genrule {
     cmd: "$(location gen_asm) --binary-assembler $(out) $(in)",
 }
 
+genrule {
+    name: "libberberis_assembler_gen_public_headers_using_x86_64",
+    out: ["berberis/assembler/gen_assembler_x86_64-using-inl.h"],
+    srcs: [":libberberis_assembler_gen_inputs_x86_64"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --using $(out) $(in)",
+}
+
+genrule {
+    name: "libberberis_assembler_gen_public_headers_using_x86_common",
+    out: ["berberis/assembler/gen_assembler_x86_common-using-inl.h"],
+    srcs: [":libberberis_assembler_gen_inputs_x86_common"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --using $(out) $(in)",
+}
+
 cc_library_headers {
     name: "libberberis_assembler_headers",
     defaults: ["berberis_all_hosts_defaults"],
@@ -123,15 +181,27 @@ cc_library_headers {
     export_header_lib_headers: ["libberberis_base_headers"],
     generated_headers: [
         "libberberis_assembler_gen_public_headers_riscv32",
+        "libberberis_assembler_gen_public_headers_using_riscv32",
         "libberberis_assembler_gen_public_headers_riscv64",
+        "libberberis_assembler_gen_public_headers_using_riscv64",
+        "libberberis_assembler_gen_public_headers_using_riscv",
         "libberberis_assembler_gen_public_headers_x86_32",
+        "libberberis_assembler_gen_public_headers_using_x86_32",
         "libberberis_assembler_gen_public_headers_x86_64",
+        "libberberis_assembler_gen_public_headers_using_x86_64",
+        "libberberis_assembler_gen_public_headers_using_x86_common",
     ],
     export_generated_headers: [
         "libberberis_assembler_gen_public_headers_riscv32",
+        "libberberis_assembler_gen_public_headers_using_riscv32",
         "libberberis_assembler_gen_public_headers_riscv64",
+        "libberberis_assembler_gen_public_headers_using_riscv64",
+        "libberberis_assembler_gen_public_headers_using_riscv",
         "libberberis_assembler_gen_public_headers_x86_32",
+        "libberberis_assembler_gen_public_headers_using_x86_32",
         "libberberis_assembler_gen_public_headers_x86_64",
+        "libberberis_assembler_gen_public_headers_using_x86_64",
+        "libberberis_assembler_gen_public_headers_using_x86_common",
     ],
     export_include_dirs: ["include"],
 }
diff --git a/assembler/asm_defs.py b/assembler/asm_defs.py
index c75d30d1..7b961bbd 100644
--- a/assembler/asm_defs.py
+++ b/assembler/asm_defs.py
@@ -143,7 +143,7 @@ def is_implicit_reg(arg_type):
                       'RCX', 'ECX', 'CL', 'ST', 'ST1',
                       'RDX', 'EDX', 'DX', 'CC',
                       'RBX', 'EBX', 'BX', 'SW',
-                      'RDI', 'RSI', 'RSP', 'FLAGS')
+                      'RDI', 'RSI', 'ESP', 'RSP', 'FLAGS')
 
 
 def exactly_one_of(iterable):
diff --git a/assembler/gen_asm.py b/assembler/gen_asm.py
index 0340f9ff..be960188 100644
--- a/assembler/gen_asm.py
+++ b/assembler/gen_asm.py
@@ -22,6 +22,7 @@ import os
 import re
 import sys
 
+from enum import Enum
 
 INDENT = '  '
 
@@ -47,6 +48,10 @@ _imm_types = {
     'Shift64-Imm': 'Shift64Immediate'
 }
 
+class AssemblerMode(Enum):
+  BINARY_ASSEMBLER = 0
+  TEXT_ASSEMBLER = 1
+  VERIFIER_ASSEMBLER = 3
 
 def _get_arg_type_name(arg, insn_type):
   cls = arg.get('class')
@@ -97,7 +102,7 @@ def _get_params(insn, filter=None):
       continue
     if filter is not None and filter(arg):
       continue
-    result.append("%s arg%d" % (
+    result.append("[[maybe_unused]] %s arg%d" % (
       _get_arg_type_name(arg, insn.get('type', None)), arg_count))
     arg_count += 1
   return ', '.join(result)
@@ -117,8 +122,98 @@ def _get_template_name(insn):
       'typename' if re.search('[_a-zA-Z]', param) else 'int'
       for param in name.split('<',1)[1][:-1].split(',')), name.split('<')[0]
 
+def _handle_jump(insn, jump_is_conditional, f):
+  arg_count = 0
+  for arg in insn.get('args'):
+    if _get_arg_type_name(arg, insn.get('type', None)) ==  "const Label&":
+      if jump_is_conditional:
+        print('  HandleConditionalJump(arg%d);' %
+        arg_count, file=f)
+        return
+      print('  HandleUnconditionalJump(arg%d);' %
+        arg_count, file=f)
+      return
+    if _get_arg_type_name(arg, insn.get('type', None)) ==  "Register":
+      assert(not jump_is_conditional)
+      print('  HandleUnconditionalJumpRegister();', file=f)
+    arg_count += 1
+
+def _check_insn_is_dependency_breaking(insn):
+  if "dependency_breaking" in insn:
+    return True
+
+def _handle_def_register_reset(name, insn, arch, f):
+  """
+  'def'/'def_early_clobber' registers in an intrinsic must be defined before they can be used.
+  Verifier assembler checks intrinsics to ensure that this is the case.
+  However, there are a number of special instructions where it is valid for a 'def'
+  register to be both read and written when it's first defined.
+  Example: A Xor instruction, using the same register as both input and output arguments sets this
+  register to 0, regardless of its initial value, effectively resetting the register.
+  Thus, it is valid for this instruction to read and write a 'def' register, even if it hasn't
+  been written to yet in the intrinsic.
+  """
+  if not _check_insn_is_dependency_breaking(insn):
+    return
+  if name.startswith("P") or name.startswith("V") or name.endswith("pd") or name.endswith("ps"):
+    register_type = "XMMRegister"
+  else:
+    register_type = "Register"
+  num_registers = 3 if name.startswith("V") else 2
+  arg_count = 0
+  registers = []
+  for arg in insn.get('args'):
+      if asm_defs.is_implicit_reg(arg.get('class')):
+        continue
+      if (_get_arg_type_name(arg, insn.get('type', None)) == register_type
+          and 'x86' in arch):
+        registers.append(arg_count)
+      arg_count += 1
+  if (len(registers) != num_registers):
+    return
+  if num_registers == 2:
+    print('  HandleDefOrDefEarlyClobberRegisterReset(arg%d, arg%d);' %
+    (registers[0], registers[1]), file=f)
+  else:
+    print('  HandleDefOrDefEarlyClobberRegisterReset(arg%d, arg%d, arg%d);' %
+    (registers[0], registers[1], registers[2]), file=f)
+
+def _get_implicit_fixed_register(arg_class):
+  if arg_class in ["AL", "AX", "EAX", "RAX"]:
+    return "gpr_a"
+  if arg_class in ["EBX", "RBX"]:
+    return "gpr_b"
+  if arg_class in ["CL", "CX", "ECX", "RCX"]:
+    return "gpr_c"
+  if arg_class in ["DL", "DX", "EDX", "RDX"]:
+    return "gpr_d"
+  return False
+
+def _gen_register_read_write_info(insn, arch):
+  # Process register uses before register defs. This ensures valid register uses are verified
+  # against register definitions that occurred only before the current instruction.
+  register_types_to_gen = ['Register', 'XMMRegister']
+  for usage in ('use', 'def'):
+    arg_count = 0
+    for arg in insn.get('args'):
+      if asm_defs.is_implicit_reg(arg.get('class')):
+        implicit_fixed_reg = _get_implicit_fixed_register(arg.get('class'))
+        if implicit_fixed_reg and (arg.get('usage') == usage or arg.get('usage') == "use_def"):
+          yield '  Register%s(%s);' % (usage.capitalize(), implicit_fixed_reg)
+        continue
+      if (_get_arg_type_name(arg, insn.get('type', None)) in register_types_to_gen
+          and 'x86' in arch):
+        if arg.get('usage') == usage or arg.get('usage') == "use_def":
+          yield '  Register%s(arg%d);' % (usage.capitalize(), arg_count)
+      arg_count += 1
 
-def _gen_generic_functions_h(f, insns, binary_assembler, arch):
+def _check_insn_uses_xmm(insn, arch):
+  for arg in insn.get('args'):
+    if (asm_defs.is_xreg(arg.get('class')) and 'x86' in arch):
+      return True
+  return False
+
+def _gen_generic_functions_h(f, insns, arch, assembler_mode):
   template_names = set()
   for insn in insns:
     template, name = _get_template_name(insn)
@@ -148,7 +243,7 @@ def _gen_generic_functions_h(f, insns, binary_assembler, arch):
     #
     # Text assembled passes "real" work down to GNU as, this works fine with
     # just a simple generic implementation.
-    if binary_assembler:
+    if assembler_mode == AssemblerMode.BINARY_ASSEMBLER:
       if 'opcode' in insn:
         assert '' not in insn
         insn['opcodes'] = [insn['opcode']]
@@ -168,7 +263,7 @@ def _gen_generic_functions_h(f, insns, binary_assembler, arch):
           else:
             assert False
         insn['processed_opcodes'] = opcodes
-        print('void %s(%s) {' % (name, params), file=f)
+        print('constexpr void %s(%s) {' % (name, params), file=f)
         if 'x86' in arch:
           _gen_emit_shortcut(f, insn, insns)
         _gen_emit_instruction(f, insn, arch)
@@ -178,19 +273,19 @@ def _gen_generic_functions_h(f, insns, binary_assembler, arch):
         # emulated on x86-32, too, if needed).
         if 'const Operand&' in params and 'x86' in arch:
           print("", file=f)
-          print('void %s(%s) {' % (
+          print('constexpr void %s(%s) {' % (
               name, params.replace('const Operand&', 'const LabelOperand')), file=f)
           _gen_emit_shortcut(f, insn, insns)
           _gen_emit_instruction(f, insn, arch, rip_operand=True)
           print('}\n', file=f)
         if 'Rounding' in params:
           print("", file=f)
-          print('void %s(%s) {' % (
+          print('constexpr void %s(%s) {' % (
               name, _get_params(insn, lambda arg: arg.get('class', '') == 'Rm')), file=f)
           _gen_emit_instruction(f, insn, arch, dyn_rm=True)
           print('}\n', file=f)
       else:
-        print('void %s(%s);' % (name, params), file=f)
+        print('constexpr void %s(%s);' % (name, params), file=f)
       # If immediate type is integer then we want to prevent automatic
       # conversions from integers of larger sizes.
       if imm_type is not None and "int" in imm_type:
@@ -202,15 +297,37 @@ def _gen_generic_functions_h(f, insns, binary_assembler, arch):
                     'std::enable_if_t<std::is_integral_v<ImmType> && '
                     'sizeof(%s) < sizeof(ImmType)> = delete;') % (
                         name, params.replace(imm_type, 'ImmType'), imm_type), file=f)
-    else:
-      print('void %s(%s) {' % (name, params), file=f);
-      if 'feature' in insn:
-        print('  SetRequiredFeature%s();' % insn['feature'], file=f)
+
+    elif assembler_mode == AssemblerMode.TEXT_ASSEMBLER:
+      print('constexpr void %s(%s) {' % (name, params), file=f)
       print('  Instruction(%s);' % ', '.join(
           ['"%s"' % insn.get('native-asm', name)] +
           list(_gen_instruction_args(insn, arch))), file=f)
       print('}', file=f)
 
+    else: # verifier_assembler
+      print('constexpr void %s(%s) {' % (name, params), file=f)
+      if (name == "Jcc" or name == "Jmp") and 'x86' in arch:
+        jump_is_conditional = name == "Jcc"
+        _handle_jump(insn, jump_is_conditional, f)
+        print(' EndInstruction();', file=f)
+        print('}', file=f)
+        continue
+      if 'feature' in insn:
+        print('  SetRequiredFeature%s();' % insn['feature'], file=f)
+      else:
+        if _check_insn_uses_xmm(insn, arch):
+          print('  SetRequiredFeatureSSEOrSSE2();', file=f)
+      for arg in insn.get('args'):
+        if arg["class"] == "FLAGS":
+          print('  SetDefinesFLAGS();', file=f)
+          break
+      _handle_def_register_reset(name, insn, arch, f)
+      for register_read_write in _gen_register_read_write_info(insn, arch):
+        print(register_read_write, file=f)
+      print('  EndInstruction();', file=f)
+      print('}', file=f)
+
 
 def _gen_instruction_args(insn, arch):
   arg_count = 0
@@ -383,6 +500,7 @@ _ARGUMENT_FORMATS_TO_SIZES = {
   'MemX8780': 'MemoryX8780Bit',
   'RegX87': 'X87Register',
   'XmmReg' : 'VectorRegister128Bit',
+  'YmmReg' : 'VectorRegister256Bit',
   'VecMem32': 'VectorMemory32Bit',
   'VecMem64': 'VectorMemory64Bit',
   'VecMem128': 'VectorMemory128Bit',
@@ -463,7 +581,7 @@ def _gen_memory_function_specializations_h(f, insns, arch):
           outgoing_args.append(arg_name)
       if template:
         print(template, file=f)
-      print('void %s(%s) {' % (macro_name, ', '.join(incoming_args)), file=f)
+      print('constexpr void %s(%s) {' % (macro_name, ', '.join(incoming_args)), file=f)
       print('  %s(%s);' % (insn.get('asm'), ', '.join(outgoing_args)), file=f)
       print('}', file=f)
 
@@ -488,26 +606,55 @@ def main(argv):
   #                   <def_common>
   #                   <def_arch>
   #                   ...
-
+  #
+  # Usage: gen_asm.py --using
+  #                   <def_common>
+  #                   <def_arch>
+  #                   ...
   mode = argv[1]
-  assert len(argv) % 2 == 0
-  filenames = argv[2:]
-  filename_pairs = ((filenames[i], filenames[len(filenames)//2 + i])
-                    for i in range(0, len(filenames)//2))
-
-  if mode == '--binary-assembler':
-    binary_assembler = True
-  elif mode == '--text-assembler':
-    binary_assembler = False
-  else:
+
+  if (mode != '--binary-assembler' and
+      mode != '--text-assembler' and
+      mode != '--verifier-assembler' and
+      mode != '--using'):
     assert False, 'unknown option %s' % (mode)
 
-  for out_filename, input_filename in filename_pairs:
-    arch, loaded_defs = _load_asm_defs(input_filename)
-    with open(out_filename, 'w') as out_file:
-      _gen_generic_functions_h(out_file, loaded_defs, binary_assembler, arch)
-      if binary_assembler and arch is not None and 'x86' in arch:
-        _gen_memory_function_specializations_h(out_file, loaded_defs, arch)
+  if mode == '--binary-assembler' or mode == '--text-assembler' or mode == "--verifier-assembler":
+    if mode == '--binary-assembler':
+      assembler_mode = AssemblerMode.BINARY_ASSEMBLER
+    elif mode == '--text-assembler':
+      assembler_mode = AssemblerMode.TEXT_ASSEMBLER
+    else:
+      assembler_mode = AssemblerMode.VERIFIER_ASSEMBLER
+
+    assert len(argv) % 2 == 0
+    filenames = argv[2:]
+    filename_pairs = ((filenames[i], filenames[len(filenames)//2 + i])
+                      for i in range(0, len(filenames)//2))
+
+    for out_filename, input_filename in filename_pairs:
+      arch, loaded_defs = _load_asm_defs(input_filename)
+      with open(out_filename, 'w') as out_file:
+        _gen_generic_functions_h(out_file, loaded_defs, arch, assembler_mode)
+        if assembler_mode == AssemblerMode.BINARY_ASSEMBLER and arch is not None and 'x86' in arch:
+          _gen_memory_function_specializations_h(out_file, loaded_defs, arch)
+  else:
+    assert mode == '--using'
+
+    instruction_names = set()
+    for input_filename in argv[3:]:
+      arch, loaded_defs = _load_asm_defs(input_filename)
+      for insn in loaded_defs:
+        instruction_names.add(insn['asm'])
+
+    with open(argv[2], 'w') as out_file:
+      print("""
+#ifndef IMPORT_ASSEMBLER_FUNCTIONS
+#error This file is supposed to be included from berberis/intrinsics/macro_assembler-inl.h
+#endif
+""", file=out_file)
+      for name in instruction_names:
+        print('using Assembler::%s;' % name, file=out_file)
 
 if __name__ == '__main__':
   sys.exit(main(sys.argv))
diff --git a/assembler/gen_asm_tests_x86.py b/assembler/gen_asm_tests_x86.py
index 6e8f3467..9099703e 100644
--- a/assembler/gen_asm_tests_x86.py
+++ b/assembler/gen_asm_tests_x86.py
@@ -219,6 +219,9 @@ MNEMO_TO_ASM = {
     'MOVZXBQ': 'MOVZBQ',
     'MOVZXWL': 'MOVZWL',
     'MOVZXWQ': 'MOVZWQ',
+}
+
+MNEMO_TO_ASM_MEM = {
     'VCVTPD2DQ': 'VCVTPD2DQX',
     'VCVTPD2PS': 'VCVTPD2PSX',
     'VCVTTPD2DQ': 'VCVTTPD2DQX'
@@ -229,7 +232,7 @@ FIXED_REGISTER_CLASSES = (
     'CL', 'ECX', 'RCX', 'ST', 'ST1',
     'DX', 'EDX', 'RDX', 'CC',
     'BX', 'EBX', 'RBX', 'SW',
-    'EBP', 'RSP', 'FLAGS'
+    'EBP', 'ESP', 'RSP', 'FLAGS'
 )
 
 
@@ -316,6 +319,8 @@ def _gen_att_instruction_variants(
     file, arc_name, insn_name, insn_args, fast_mode):
   if insn_name in MNEMO_TO_ASM:
     insn_name = MNEMO_TO_ASM[insn_name]
+  if insn_name in MNEMO_TO_ASM_MEM and 'VecMem128' in str(insn_args):
+    insn_name = MNEMO_TO_ASM_MEM[insn_name]
   insn_sample_args = []
   label_present = False
   if arc_name.endswith('ByOne'):
diff --git a/assembler/include/berberis/assembler/machine_code.h b/assembler/include/berberis/assembler/machine_code.h
index f7e746d8..a8bf2c34 100644
--- a/assembler/include/berberis/assembler/machine_code.h
+++ b/assembler/include/berberis/assembler/machine_code.h
@@ -20,6 +20,7 @@
 #ifndef BERBERIS_ASSEMBLER_MACHINE_CODE_H_
 #define BERBERIS_ASSEMBLER_MACHINE_CODE_H_
 
+#include <bit>
 #include <cstdint>
 #include <string>
 
@@ -76,7 +77,7 @@ class MachineCode {
 
   template <typename T>
   [[nodiscard]] const T* AddrAs(uint32_t offset) const {
-    return reinterpret_cast<const T*>(AddrOf(offset));
+    return std::bit_cast<const T*>(AddrOf(offset));
   }
 
   template <typename T>
diff --git a/assembler/include/berberis/assembler/riscv.h b/assembler/include/berberis/assembler/riscv.h
index 80430c3a..e74adcfd 100644
--- a/assembler/include/berberis/assembler/riscv.h
+++ b/assembler/include/berberis/assembler/riscv.h
@@ -867,7 +867,7 @@ class Assembler : public AssemblerBase {
   // Macro operations.
   void Finalize() { ResolveJumps(); }
 
-  void ResolveJumps();
+  constexpr void ResolveJumps();
 
   // Instructions.
 #include "berberis/assembler/gen_assembler_common_riscv-inl.h"  // NOLINT generated file!
@@ -1109,10 +1109,10 @@ class Assembler : public AssemblerBase {
 };
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Bcc(Condition cc,
-                                                 Register argument1,
-                                                 Register argument2,
-                                                 const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Bcc(Condition cc,
+                                                           Register argument1,
+                                                           Register argument2,
+                                                           const Label& label) {
   if (cc == Condition::kAlways) {
     Jal(zero, label);
     return;
@@ -1125,10 +1125,10 @@ inline void Assembler<DerivedAssemblerType>::Bcc(Condition cc,
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Bcc(Condition cc,
-                                                 Register argument1,
-                                                 Register argument2,
-                                                 BImmediate immediate) {
+constexpr inline void Assembler<DerivedAssemblerType>::Bcc(Condition cc,
+                                                           Register argument1,
+                                                           Register argument2,
+                                                           BImmediate immediate) {
   if (cc == Condition::kAlways) {
     int32_t encoded_immediate_value = immediate.EncodedValue();
     // Maybe better to provide an official interface to convert BImmediate into JImmediate?
@@ -1149,7 +1149,7 @@ inline void Assembler<DerivedAssemblerType>::Bcc(Condition cc,
 
 #define BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Name, TargetRegister, InstructionType, Opcode) \
   template <typename DerivedAssemblerType>                                                       \
-  inline void Assembler<DerivedAssemblerType>::Name(                                             \
+  constexpr inline void Assembler<DerivedAssemblerType>::Name(                                   \
       TargetRegister arg0, const Label& label, Register arg2) {                                  \
     CHECK_NE(arg2, x0);                                                                          \
     jumps_.push_back(Jump{&label, pc(), false});                                                 \
@@ -1168,15 +1168,15 @@ BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Sh, Register, S, 0x0000'1023)
 BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION(Sw, Register, S, 0x0000'2023)
 #undef BERBERIS_DEFINE_LOAD_OR_STORE_INSTRUCTION
 
-#define BERBERIS_DEFINE_LOAD_INSTRUCTION(Name, Opcode)                                         \
-  template <typename DerivedAssemblerType>                                                     \
-  inline void Assembler<DerivedAssemblerType>::Name(Register arg0, const Label& label) {       \
-    CHECK_NE(arg0, x0);                                                                        \
-    jumps_.push_back(Jump{&label, pc(), false});                                               \
-    /* First issue auipc to load top 20 bits of difference between pc and target address */    \
-    EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg0, UImmediate{0});                          \
-    /* The low 12 bite of difference will be encoded in the memory accessing instruction */    \
-    EmitITypeInstruction<uint32_t{Opcode}>(arg0, Operand<Register, IImmediate>{.base = arg0}); \
+#define BERBERIS_DEFINE_LOAD_INSTRUCTION(Name, Opcode)                                             \
+  template <typename DerivedAssemblerType>                                                         \
+  constexpr inline void Assembler<DerivedAssemblerType>::Name(Register arg0, const Label& label) { \
+    CHECK_NE(arg0, x0);                                                                            \
+    jumps_.push_back(Jump{&label, pc(), false});                                                   \
+    /* First issue auipc to load top 20 bits of difference between pc and target address */        \
+    EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg0, UImmediate{0});                              \
+    /* The low 12 bite of difference will be encoded in the memory accessing instruction */        \
+    EmitITypeInstruction<uint32_t{Opcode}>(arg0, Operand<Register, IImmediate>{.base = arg0});     \
   }
 BERBERIS_DEFINE_LOAD_INSTRUCTION(Lb, 0x0000'0003)
 BERBERIS_DEFINE_LOAD_INSTRUCTION(Lbu, 0x0000'4003)
@@ -1186,7 +1186,7 @@ BERBERIS_DEFINE_LOAD_INSTRUCTION(Lw, 0x0000'2003)
 #undef BERBERIS_DEFINE_LOAD_INSTRUCTION
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::La(Register arg0, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::La(Register arg0, const Label& label) {
   CHECK_NE(arg0, x0);
   jumps_.push_back(Jump{&label, pc(), false});
   // First issue auipc to load top 20 bits of difference between pc and target address
@@ -1197,7 +1197,7 @@ inline void Assembler<DerivedAssemblerType>::La(Register arg0, const Label& labe
 
 #define BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION(Name, Opcode)          \
   template <typename DerivedAssemblerType>                             \
-  inline void Assembler<DerivedAssemblerType>::Name(                   \
+  constexpr inline void Assembler<DerivedAssemblerType>::Name(         \
       Register arg0, Register arg1, const Label& label) {              \
     jumps_.push_back(Jump{&label, pc(), false});                       \
     EmitBTypeInstruction<uint32_t{Opcode}>(arg0, arg1, BImmediate{0}); \
@@ -1211,13 +1211,13 @@ BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION(Bne, 0x0000'1063)
 #undef BERBERIS_DEFINE_CONDITIONAL_INSTRUCTION
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Jal(Register argument0, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Jal(Register argument0, const Label& label) {
   jumps_.push_back(Jump{&label, pc(), false});
   EmitInstruction<0x0000'006f, 0x0000'007f>(Rd(argument0));
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::ResolveJumps() {
+constexpr inline void Assembler<DerivedAssemblerType>::ResolveJumps() {
   for (const auto& jump : jumps_) {
     const Label* label = jump.label;
     uint32_t pc = jump.pc;
@@ -1272,12 +1272,12 @@ inline void Assembler<DerivedAssemblerType>::ResolveJumps() {
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Mv(Register dest, Register src) {
+constexpr inline void Assembler<DerivedAssemblerType>::Mv(Register dest, Register src) {
   Addi(dest, src, 0);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Li(Register dest, int32_t imm32) {
+constexpr inline void Assembler<DerivedAssemblerType>::Li(Register dest, int32_t imm32) {
   // If the value fits into 12bit I-Immediate type, load using addi.
   if (-2048 <= imm32 && imm32 <= 2047) {
     Addi(dest, Assembler::zero, static_cast<IImmediate>(imm32));
@@ -1303,12 +1303,12 @@ inline void Assembler<DerivedAssemblerType>::Li(Register dest, int32_t imm32) {
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Ret() {
+constexpr inline void Assembler<DerivedAssemblerType>::Ret() {
   Jalr(Assembler::x0, Assembler::x1, static_cast<IImmediate>(0));
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Call(const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Call(const Label& label) {
   jumps_.push_back(Jump{&label, pc(), false});
   // First issue auipc to load top 20 bits of difference between pc and target address
   EmitUTypeInstruction<uint32_t{0x0000'0017}>(Assembler::x6, UImmediate{0});
@@ -1317,7 +1317,7 @@ inline void Assembler<DerivedAssemblerType>::Call(const Label& label) {
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Tail(const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Tail(const Label& label) {
   jumps_.push_back(Jump{&label, pc(), false});
   // First issue auipc to load top 20 bits of difference between pc and target address
   EmitUTypeInstruction<uint32_t{0x0000'0017}>(Assembler::x6, UImmediate{0});
@@ -1326,106 +1326,110 @@ inline void Assembler<DerivedAssemblerType>::Tail(const Label& label) {
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Bgt(Register arg0, Register arg1, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Bgt(Register arg0,
+                                                           Register arg1,
+                                                           const Label& label) {
   Blt(arg1, arg0, label);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Bgtu(Register arg0,
-                                                  Register arg1,
-                                                  const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Bgtu(Register arg0,
+                                                            Register arg1,
+                                                            const Label& label) {
   Bltu(arg1, arg0, label);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Ble(Register arg0, Register arg1, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Ble(Register arg0,
+                                                           Register arg1,
+                                                           const Label& label) {
   Bge(arg1, arg0, label);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Bleu(Register arg0,
-                                                  Register arg1,
-                                                  const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Bleu(Register arg0,
+                                                            Register arg1,
+                                                            const Label& label) {
   Bgeu(arg1, arg0, label);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Beqz(Register arg0, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Beqz(Register arg0, const Label& label) {
   Beq(arg0, zero, label);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Bnez(Register arg0, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Bnez(Register arg0, const Label& label) {
   Bne(arg0, zero, label);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Blez(Register arg0, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Blez(Register arg0, const Label& label) {
   Ble(arg0, zero, label);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Bgez(Register arg0, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Bgez(Register arg0, const Label& label) {
   Bge(arg0, zero, label);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Bltz(Register arg0, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Bltz(Register arg0, const Label& label) {
   Blt(arg0, zero, label);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Bgtz(Register arg0, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Bgtz(Register arg0, const Label& label) {
   Bgt(arg0, zero, label);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Seqz(Register arg0, Register arg1) {
+constexpr inline void Assembler<DerivedAssemblerType>::Seqz(Register arg0, Register arg1) {
   Sltiu(arg0, arg1, static_cast<IImmediate>(1));
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Snez(Register arg0, Register arg1) {
+constexpr inline void Assembler<DerivedAssemblerType>::Snez(Register arg0, Register arg1) {
   Sltu(arg0, zero, arg1);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Sltz(Register arg0, Register arg1) {
+constexpr inline void Assembler<DerivedAssemblerType>::Sltz(Register arg0, Register arg1) {
   Slt(arg0, arg1, zero);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Sgtz(Register arg0, Register arg1) {
+constexpr inline void Assembler<DerivedAssemblerType>::Sgtz(Register arg0, Register arg1) {
   Slt(arg0, zero, arg1);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::J(JImmediate arg0) {
+constexpr inline void Assembler<DerivedAssemblerType>::J(JImmediate arg0) {
   Jal(zero, arg0);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Jal(JImmediate arg0) {
+constexpr inline void Assembler<DerivedAssemblerType>::Jal(JImmediate arg0) {
   Jal(x1, arg0);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Jr(Register arg0) {
+constexpr inline void Assembler<DerivedAssemblerType>::Jr(Register arg0) {
   Jalr(zero, arg0, 0);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Jalr(Register arg0) {
+constexpr inline void Assembler<DerivedAssemblerType>::Jalr(Register arg0) {
   Jalr(x1, arg0, 0);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Not(Register arg0, Register arg1) {
+constexpr inline void Assembler<DerivedAssemblerType>::Not(Register arg0, Register arg1) {
   Xori(arg0, arg1, -1);
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Neg(Register arg0, Register arg1) {
+constexpr inline void Assembler<DerivedAssemblerType>::Neg(Register arg0, Register arg1) {
   Sub(arg0, zero, arg1);
 }
 
diff --git a/assembler/include/berberis/assembler/rv64.h b/assembler/include/berberis/assembler/rv64.h
index 434470cf..02200cc9 100644
--- a/assembler/include/berberis/assembler/rv64.h
+++ b/assembler/include/berberis/assembler/rv64.h
@@ -61,10 +61,10 @@ class Assembler : public riscv::Assembler<Assembler> {
   Assembler(Assembler&&) = delete;
   void operator=(const Assembler&) = delete;
   void operator=(Assembler&&) = delete;
-  void Li32(Register dest, int32_t imm32);
+  constexpr void Li32(Register dest, int32_t imm32);
 };
 
-inline void Assembler::Ld(Register arg0, const Label& label) {
+constexpr inline void Assembler::Ld(Register arg0, const Label& label) {
   jumps_.push_back(Jump{&label, pc(), false});
   // First issue auipc to load top 20 bits of difference between pc and target address
   EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg0, UImmediate{0});
@@ -73,11 +73,11 @@ inline void Assembler::Ld(Register arg0, const Label& label) {
 }
 
 // It's needed to unhide 32bit immediate version.
-inline void Assembler::Li32(Register dest, int32_t imm32) {
+constexpr inline void Assembler::Li32(Register dest, int32_t imm32) {
   BaseAssembler::Li(dest, imm32);
 };
 
-inline void Assembler::Li(Register dest, int64_t imm64) {
+constexpr inline void Assembler::Li(Register dest, int64_t imm64) {
   int32_t imm32 = static_cast<int32_t>(imm64);
   if (static_cast<int64_t>(imm32) == imm64) {
     Li32(dest, imm32);
@@ -102,7 +102,7 @@ inline void Assembler::Li(Register dest, int64_t imm64) {
   }
 }
 
-inline void Assembler::Lwu(Register arg0, const Label& label) {
+constexpr inline void Assembler::Lwu(Register arg0, const Label& label) {
   jumps_.push_back(Jump{&label, pc(), false});
   // First issue auipc to load top 20 bits of difference between pc and target address
   EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg0, UImmediate{0});
@@ -110,7 +110,7 @@ inline void Assembler::Lwu(Register arg0, const Label& label) {
   EmitITypeInstruction<uint32_t{0x0000'6003}>(arg0, Operand<Register, IImmediate>{.base = arg0});
 }
 
-inline void Assembler::Sd(Register arg0, const Label& label, Register arg2) {
+constexpr inline void Assembler::Sd(Register arg0, const Label& label, Register arg2) {
   jumps_.push_back(Jump{&label, pc(), false});
   // First issue auipc to load top 20 bits of difference between pc and target address
   EmitUTypeInstruction<uint32_t{0x0000'0017}>(arg2, UImmediate{0});
@@ -118,15 +118,15 @@ inline void Assembler::Sd(Register arg0, const Label& label, Register arg2) {
   EmitSTypeInstruction<uint32_t{0x0000'3023}>(arg0, Operand<Register, SImmediate>{.base = arg2});
 }
 
-inline void Assembler::SextW(Register arg0, Register arg1) {
+constexpr inline void Assembler::SextW(Register arg0, Register arg1) {
   Addiw(arg0, arg1, 0);
 }
 
-inline void Assembler::ZextW(Register arg0, Register arg1) {
+constexpr inline void Assembler::ZextW(Register arg0, Register arg1) {
   AddUW(arg0, arg1, zero);
 }
 
-inline void Assembler::Negw(Register arg0, Register arg1) {
+constexpr inline void Assembler::Negw(Register arg0, Register arg1) {
   Subw(arg0, zero, arg1);
 }
 
diff --git a/assembler/include/berberis/assembler/x86_32.h b/assembler/include/berberis/assembler/x86_32.h
index cbccdc79..35bdf4aa 100644
--- a/assembler/include/berberis/assembler/x86_32.h
+++ b/assembler/include/berberis/assembler/x86_32.h
@@ -53,10 +53,21 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
   static constexpr XMMRegister xmm6{6};
   static constexpr XMMRegister xmm7{7};
 
+  static constexpr YMMRegister no_ymm_register{0x80};
+  static constexpr YMMRegister ymm0{0};
+  static constexpr YMMRegister ymm1{1};
+  static constexpr YMMRegister ymm2{2};
+  static constexpr YMMRegister ymm3{3};
+  static constexpr YMMRegister ymm4{4};
+  static constexpr YMMRegister ymm5{5};
+  static constexpr YMMRegister ymm6{6};
+  static constexpr YMMRegister ymm7{7};
+
   // Macroassembler uses these names to support both x86-32 and x86-64 modes.
   static constexpr Register gpr_a{0};
   static constexpr Register gpr_c{1};
   static constexpr Register gpr_d{2};
+  static constexpr Register gpr_b{3};
   static constexpr Register gpr_s{4};
 
 // Instructions.
@@ -78,7 +89,7 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
   using BaseAssembler::Movb;
 
   // Movb in 32-bit mode has certain optimizations not available in x86-64 mode
-  void Movb(Register dest, const Operand& src) {
+  constexpr void Movb(Register dest, const Operand& src) {
     if (IsAccumulator(dest) && src.base == no_register && src.index == no_register) {
       EmitInstruction<0xA0>(src.disp);
     } else {
@@ -86,7 +97,7 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
     }
   }
 
-  void Movb(const Operand& dest, Register src) {
+  constexpr void Movb(const Operand& dest, Register src) {
     if (dest.base == no_register && dest.index == no_register && IsAccumulator(src)) {
       EmitInstruction<0xA2>(dest.disp);
     } else {
@@ -98,7 +109,7 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
   using BaseAssembler::Movw;
 
   // Movw in 32-bit mode has certain optimizations not available in x86-64 mode
-  void Movw(Register dest, const Operand& src) {
+  constexpr void Movw(Register dest, const Operand& src) {
     if (IsAccumulator(dest) && src.base == no_register && src.index == no_register) {
       EmitInstruction<0x66, 0xA1>(src.disp);
     } else {
@@ -106,7 +117,7 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
     }
   }
 
-  void Movw(const Operand& dest, Register src) {
+  constexpr void Movw(const Operand& dest, Register src) {
     if (dest.base == no_register && dest.index == no_register && IsAccumulator(src)) {
       EmitInstruction<0x66, 0xA3>(dest.disp);
     } else {
@@ -118,7 +129,7 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
   using BaseAssembler::Movl;
 
   // Movl in 32-bit mode has certain optimizations not available in x86-64 mode
-  void Movl(Register dest, const Operand& src) {
+  constexpr void Movl(Register dest, const Operand& src) {
     if (IsAccumulator(dest) && src.base == no_register && src.index == no_register) {
       EmitInstruction<0xA1>(src.disp);
     } else {
@@ -126,7 +137,7 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
     }
   }
 
-  void Movl(const Operand& dest, Register src) {
+  constexpr void Movl(const Operand& dest, Register src) {
     if (dest.base == no_register && dest.index == no_register && IsAccumulator(src)) {
       EmitInstruction<0xA3>(dest.disp);
     } else {
@@ -304,15 +315,15 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
   // Emit the ModR/M byte, and optionally the SIB byte and
   // 1- or 4-byte offset for a memory operand.  Also used to encode
   // a three-bit opcode extension into the ModR/M byte.
-  void EmitOperandOp(int num_ber, const Operand& addr);
+  constexpr void EmitOperandOp(int num_ber, const Operand& addr);
   // Helper functions to handle various ModR/M and SIB combinations.
   // Should *only* be called from EmitOperandOp!
-  void EmitIndexDispOperand(int reg, const Operand& addr);
+  constexpr void EmitIndexDispOperand(int reg, const Operand& addr);
   template <typename ArgType, void (AssemblerBase::*)(ArgType)>
-  void EmitBaseIndexDispOperand(int base_modrm_and_sib, const Operand& addr);
+  constexpr void EmitBaseIndexDispOperand(int base_modrm_and_sib, const Operand& addr);
   // Emit ModR/M for rip-addressig.
   template <size_t kImmediatesSize>
-  void EmitRipOp(int num_, const Label& label);
+  constexpr void EmitRipOp(int num_, const Label& label);
 
   friend BaseAssembler;
 };
@@ -322,7 +333,7 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
 // makes effective size of that function very small.
 //
 // But for this to happen function have to be inline and in header.
-inline void Assembler::EmitOperandOp(int num_ber, const Operand& addr) {
+constexpr inline void Assembler::EmitOperandOp(int num_ber, const Operand& addr) {
   // Additional info (register num_ber, etc) is limited to 3 bits.
   CHECK_LE(unsigned(num_ber), 7);
 
@@ -355,14 +366,15 @@ inline void Assembler::EmitOperandOp(int num_ber, const Operand& addr) {
   }
 }
 
-inline void Assembler::EmitIndexDispOperand(int reg, const Operand& addr) {
+constexpr inline void Assembler::EmitIndexDispOperand(int reg, const Operand& addr) {
   // We only have index here, no base, use SIB but put %ebp in "base" field.
   Emit16(0x0504 | (addr.scale << 14) | (addr.index.num_ << 11) | reg);
   Emit32(addr.disp);
 }
 
-template <typename ArgType, void (AssemblerBase::*EmitBase)(ArgType)>
-inline void Assembler::EmitBaseIndexDispOperand(int base_modrm_and_sib, const Operand& addr) {
+template <typename ArgType, void (AssemblerBase::* EmitBase)(ArgType)>
+constexpr inline void Assembler::EmitBaseIndexDispOperand(int base_modrm_and_sib,
+                                                          const Operand& addr) {
   if (addr.disp == 0 && addr.base != ebp) {
     // We can omit zero displacement only if base isn't %ebp
     (this->*EmitBase)(base_modrm_and_sib);
diff --git a/assembler/include/berberis/assembler/x86_32_and_x86_64.h b/assembler/include/berberis/assembler/x86_32_and_x86_64.h
index 825db8ed..32f65d46 100644
--- a/assembler/include/berberis/assembler/x86_32_and_x86_64.h
+++ b/assembler/include/berberis/assembler/x86_32_and_x86_64.h
@@ -789,6 +789,21 @@ class Assembler : public AssemblerBase {
                                         std::forward<ArgumentsTypes>(arguments)...);
   }
 
+  template <uint8_t... kOpcodes,
+            typename ArgumentsType0,
+            typename ArgumentsType1,
+            typename ArgumentsType2,
+            typename... ArgumentsTypes>
+  void EmitVexRegToRmInstruction(ArgumentsType0&& argument0,
+                                 ArgumentsType1&& argument1,
+                                 ArgumentsType2&& argument2,
+                                 ArgumentsTypes&&... arguments) {
+    return EmitInstruction<kOpcodes...>(std::forward<ArgumentsType1>(argument2),
+                                        std::forward<ArgumentsType0>(argument0),
+                                        std::forward<ArgumentsType2>(argument1),
+                                        std::forward<ArgumentsTypes>(arguments)...);
+  }
+
   template <uint8_t... kOpcodes,
             typename ArgumentsType0,
             typename ArgumentsType1,
@@ -822,7 +837,7 @@ class Assembler : public AssemblerBase {
                                         std::forward<ArgumentsTypes>(arguments)...);
   }
 
-  void ResolveJumps();
+  constexpr void ResolveJumps();
 
  private:
   Assembler() = delete;
@@ -833,7 +848,7 @@ class Assembler : public AssemblerBase {
 };
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Pmov(XMMRegister dest, XMMRegister src) {
+constexpr inline void Assembler<DerivedAssemblerType>::Pmov(XMMRegister dest, XMMRegister src) {
   // SSE does not have operations for register-to-register integer move and
   // Intel explicitly recommends to use pshufd instead on Pentium4:
   //   See https://software.intel.com/en-us/articles/
@@ -847,7 +862,7 @@ inline void Assembler<DerivedAssemblerType>::Pmov(XMMRegister dest, XMMRegister
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Call(const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Call(const Label& label) {
   if (label.IsBound()) {
     int32_t offset = label.position() - pc();
     Call(offset);
@@ -859,7 +874,7 @@ inline void Assembler<DerivedAssemblerType>::Call(const Label& label) {
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Jcc(Condition cc, const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Jcc(Condition cc, const Label& label) {
   if (cc == Condition::kAlways) {
     Jmp(label);
     return;
@@ -880,7 +895,7 @@ inline void Assembler<DerivedAssemblerType>::Jcc(Condition cc, const Label& labe
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Jmp(const Label& label) {
+constexpr inline void Assembler<DerivedAssemblerType>::Jmp(const Label& label) {
   // TODO(eaeltsin): may be remove IsBound case?
   // Then jmp by label will be of fixed size (5 bytes)
   if (label.IsBound()) {
@@ -894,7 +909,7 @@ inline void Assembler<DerivedAssemblerType>::Jmp(const Label& label) {
 }
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::ResolveJumps() {
+constexpr inline void Assembler<DerivedAssemblerType>::ResolveJumps() {
   for (const auto& jump : jumps_) {
     const Label* label = jump.label;
     uint32_t pc = jump.pc;
@@ -912,7 +927,7 @@ inline void Assembler<DerivedAssemblerType>::ResolveJumps() {
 // Code size optimized instructions: they have different variants depending on registers used.
 
 template <typename DerivedAssemblerType>
-inline void Assembler<DerivedAssemblerType>::Xchgl(Register dest, Register src) {
+constexpr inline void Assembler<DerivedAssemblerType>::Xchgl(Register dest, Register src) {
   if (DerivedAssemblerType::IsAccumulator(src) || DerivedAssemblerType::IsAccumulator(dest)) {
     Register other = DerivedAssemblerType::IsAccumulator(src) ? dest : src;
     EmitInstruction<0x90>(SizeAgnosticRegister(other));
diff --git a/assembler/include/berberis/assembler/x86_64.h b/assembler/include/berberis/assembler/x86_64.h
index 5d29d690..786ae76b 100644
--- a/assembler/include/berberis/assembler/x86_64.h
+++ b/assembler/include/berberis/assembler/x86_64.h
@@ -73,10 +73,29 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
   static constexpr XMMRegister xmm14{14};
   static constexpr XMMRegister xmm15{15};
 
+  static constexpr YMMRegister no_ymm_register{0x80};
+  static constexpr YMMRegister ymm0{0};
+  static constexpr YMMRegister ymm1{1};
+  static constexpr YMMRegister ymm2{2};
+  static constexpr YMMRegister ymm3{3};
+  static constexpr YMMRegister ymm4{4};
+  static constexpr YMMRegister ymm5{5};
+  static constexpr YMMRegister ymm6{6};
+  static constexpr YMMRegister ymm7{7};
+  static constexpr YMMRegister ymm8{8};
+  static constexpr YMMRegister ymm9{9};
+  static constexpr YMMRegister ymm10{10};
+  static constexpr YMMRegister ymm11{11};
+  static constexpr YMMRegister ymm12{12};
+  static constexpr YMMRegister ymm13{13};
+  static constexpr YMMRegister ymm14{14};
+  static constexpr YMMRegister ymm15{15};
+
   // Macroassembler uses these names to support both x86-32 and x86-64 modes.
   static constexpr Register gpr_a{0};
   static constexpr Register gpr_c{1};
   static constexpr Register gpr_d{2};
+  static constexpr Register gpr_b{3};
   static constexpr Register gpr_s{4};
 
 // Instructions.
@@ -180,6 +199,25 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
     Emit64(bit_cast<int64_t>(target));
   }
 
+  // Emit short relative jcc to an absolute address.
+  //
+  // This is used to shorten jcc in the code installed in lower 2G address space.
+  // Use this if the target is also within this address space.
+  void Jcc32(Condition cc, uintptr_t target) {
+    if (cc == Condition::kAlways) {
+      Jmp32(target);
+      return;
+    } else if (cc == Condition::kNever) {
+      return;
+    }
+    CHECK_EQ(static_cast<uint8_t>(cc) & 0xf0, 0);
+    Emit8(0x0f);
+    Emit8(0x80 | static_cast<uint8_t>(cc));
+    Emit32(0xcccc'cccc);
+    // Set last 4 bytes to displacement from current pc to 'target'.
+    AddRelocation(pc() - 4, RelocationType::RelocAbsToDisp32, pc(), bit_cast<intptr_t>(target));
+  }
+
   void Jcc(Condition cc, const void* target) { Jcc(cc, bit_cast<uintptr_t>(target)); }
 
   // Unhide Jmp(Reg), hidden by special version below.
@@ -206,6 +244,16 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
     Emit64(bit_cast<int64_t>(target));
   }
 
+  // Emit short relative jump to an absolute address.
+  //
+  // This is used to shorten jmps in the code installed in lower 2G address space.
+  // Use this if the target is also within this address space.
+  void Jmp32(uintptr_t target) {
+    Emit8(0xe9);
+    Emit32(0xcccc'cccc);
+    AddRelocation(pc() - 4, RelocationType::RelocAbsToDisp32, pc(), target);
+  }
+
   void Jmp(const void* target) { Jmp(bit_cast<uintptr_t>(target)); }
 
 #endif
@@ -388,27 +436,27 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
   }
 
   template <typename ArgumentType>
-  void EmitOperandOp(ArgumentType argument, Operand operand) {
+  constexpr void EmitOperandOp(ArgumentType argument, Operand operand) {
     EmitOperandOp(static_cast<int>(argument.num_ & 0b111), operand);
   }
 
   template <size_t kImmediatesSize, typename ArgumentType>
-  void EmitRipOp(ArgumentType argument, const Label& label) {
+  constexpr void EmitRipOp(ArgumentType argument, const Label& label) {
     EmitRipOp<kImmediatesSize>(static_cast<int>(argument.num_) & 0b111, label);
   }
 
   // Emit the ModR/M byte, and optionally the SIB byte and
   // 1- or 4-byte offset for a memory operand.  Also used to encode
   // a three-bit opcode extension into the ModR/M byte.
-  void EmitOperandOp(int num_ber, const Operand& addr);
+  constexpr void EmitOperandOp(int num_ber, const Operand& addr);
   // Helper functions to handle various ModR/M and SIB combinations.
   // Should *only* be called from EmitOperandOp!
-  void EmitIndexDispOperand(int reg, const Operand& addr);
+  constexpr void EmitIndexDispOperand(int reg, const Operand& addr);
   template <typename ArgType, void (AssemblerBase::*)(ArgType)>
-  void EmitBaseIndexDispOperand(int base_modrm_and_sib, const Operand& addr);
+  constexpr void EmitBaseIndexDispOperand(int base_modrm_and_sib, const Operand& addr);
   // Emit ModR/M for rip-addressig.
   template <size_t kImmediatesSize>
-  void EmitRipOp(int num_, const Label& label);
+  constexpr void EmitRipOp(int num_, const Label& label);
 
   friend BaseAssembler;
 };
@@ -418,7 +466,7 @@ class Assembler : public x86_32_and_x86_64::Assembler<Assembler> {
 // makes effective size of that function very small.
 //
 // But for this to happen function have to be inline and in header.
-inline void Assembler::EmitOperandOp(int num_ber, const Operand& addr) {
+constexpr inline void Assembler::EmitOperandOp(int num_ber, const Operand& addr) {
   // Additional info (register num_ber, etc) is limited to 3 bits.
   CHECK_LE(unsigned(num_ber), 7);
 
@@ -453,21 +501,22 @@ inline void Assembler::EmitOperandOp(int num_ber, const Operand& addr) {
   }
 }
 
-inline void Assembler::EmitIndexDispOperand(int reg, const Operand& addr) {
+constexpr inline void Assembler::EmitIndexDispOperand(int reg, const Operand& addr) {
   // We only have index here, no base, use SIB but put %rbp in "base" field.
   Emit16(0x0504 | (addr.scale << 14) | ((addr.index.num_ & 7) << 11) | reg);
   Emit32(addr.disp);
 }
 
 template <size_t kImmediatesSize>
-inline void Assembler::EmitRipOp(int num_, const Label& label) {
+constexpr inline void Assembler::EmitRipOp(int num_, const Label& label) {
   Emit8(0x05 | (num_ << 3));
   jumps_.push_back(Jump{&label, pc(), false});
   Emit32(0xfffffffc - kImmediatesSize);
 }
 
-template <typename ArgType, void (AssemblerBase::*EmitBase)(ArgType)>
-inline void Assembler::EmitBaseIndexDispOperand(int base_modrm_and_sib, const Operand& addr) {
+template <typename ArgType, void (AssemblerBase::* EmitBase)(ArgType)>
+constexpr inline void Assembler::EmitBaseIndexDispOperand(int base_modrm_and_sib,
+                                                          const Operand& addr) {
   if (addr.disp == 0 && addr.base != rbp && addr.base != r13) {
     // We can omit zero displacement only if base isn't %rbp/%r13
     (this->*EmitBase)(base_modrm_and_sib);
@@ -482,7 +531,7 @@ inline void Assembler::EmitBaseIndexDispOperand(int base_modrm_and_sib, const Op
   }
 }
 
-inline void Assembler::Movq(Register dest, int64_t imm64) {
+constexpr inline void Assembler::Movq(Register dest, int64_t imm64) {
   if (IsInRange<uint32_t>(imm64)) {
     // Shorter encoding.
     Movl(dest, static_cast<uint32_t>(imm64));
@@ -495,40 +544,72 @@ inline void Assembler::Movq(Register dest, int64_t imm64) {
   }
 }
 
-inline void Assembler::Vmovapd(XMMRegister arg0, XMMRegister arg1) {
-  if (arg0.num_ < 8 && arg1.num_ >= 8) {
+constexpr inline void Assembler::Vmovapd(XMMRegister arg0, XMMRegister arg1) {
+  if (IsSwapProfitable(arg1, arg0)) {
     return EmitInstruction<0xc4, 0x01, 0x01, 0x29>(VectorRegister128Bit(arg1),
                                                    VectorRegister128Bit(arg0));
   }
   EmitInstruction<0xc4, 0x01, 0x01, 0x28>(VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
 }
 
-inline void Assembler::Vmovaps(XMMRegister arg0, XMMRegister arg1) {
-  if (arg0.num_ < 8 && arg1.num_ >= 8) {
+constexpr inline void Assembler::Vmovapd(YMMRegister arg0, YMMRegister arg1) {
+  if (IsSwapProfitable(arg1, arg0)) {
+    return EmitInstruction<0xc4, 0x01, 0x05, 0x29>(VectorRegister256Bit(arg1),
+                                                   VectorRegister256Bit(arg0));
+  }
+  EmitInstruction<0xc4, 0x01, 0x05, 0x28>(VectorRegister256Bit(arg0), VectorRegister256Bit(arg1));
+}
+
+constexpr inline void Assembler::Vmovaps(XMMRegister arg0, XMMRegister arg1) {
+  if (IsSwapProfitable(arg1, arg0)) {
     return EmitInstruction<0xc4, 0x01, 0x00, 0x29>(VectorRegister128Bit(arg1),
                                                    VectorRegister128Bit(arg0));
   }
   EmitInstruction<0xc4, 0x01, 0x00, 0x28>(VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
 }
 
-inline void Assembler::Vmovdqa(XMMRegister arg0, XMMRegister arg1) {
-  if (arg0.num_ < 8 && arg1.num_ >= 8) {
+constexpr inline void Assembler::Vmovaps(YMMRegister arg0, YMMRegister arg1) {
+  if (IsSwapProfitable(arg1, arg0)) {
+    return EmitInstruction<0xc4, 0x01, 0x04, 0x29>(VectorRegister256Bit(arg1),
+                                                   VectorRegister256Bit(arg0));
+  }
+  EmitInstruction<0xc4, 0x01, 0x04, 0x28>(VectorRegister256Bit(arg0), VectorRegister256Bit(arg1));
+}
+
+constexpr inline void Assembler::Vmovdqa(XMMRegister arg0, XMMRegister arg1) {
+  if (IsSwapProfitable(arg1, arg0)) {
     return EmitInstruction<0xc4, 0x01, 0x01, 0x7F>(VectorRegister128Bit(arg1),
                                                    VectorRegister128Bit(arg0));
   }
   EmitInstruction<0xc4, 0x01, 0x01, 0x6F>(VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
 }
 
-inline void Assembler::Vmovdqu(XMMRegister arg0, XMMRegister arg1) {
-  if (arg0.num_ < 8 && arg1.num_ >= 8) {
+constexpr inline void Assembler::Vmovdqa(YMMRegister arg0, YMMRegister arg1) {
+  if (IsSwapProfitable(arg1, arg0)) {
+    return EmitInstruction<0xc4, 0x01, 0x05, 0x7F>(VectorRegister256Bit(arg1),
+                                                   VectorRegister256Bit(arg0));
+  }
+  EmitInstruction<0xc4, 0x01, 0x05, 0x6F>(VectorRegister256Bit(arg0), VectorRegister256Bit(arg1));
+}
+
+constexpr inline void Assembler::Vmovdqu(XMMRegister arg0, XMMRegister arg1) {
+  if (IsSwapProfitable(arg1, arg0)) {
     return EmitInstruction<0xc4, 0x01, 0x02, 0x7F>(VectorRegister128Bit(arg1),
                                                    VectorRegister128Bit(arg0));
   }
   EmitInstruction<0xc4, 0x01, 0x02, 0x6F>(VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
 }
 
-inline void Assembler::Vmovsd(XMMRegister arg0, XMMRegister arg1, XMMRegister arg2) {
-  if (arg0.num_ < 8 && arg2.num_ >= 8) {
+constexpr inline void Assembler::Vmovdqu(YMMRegister arg0, YMMRegister arg1) {
+  if (IsSwapProfitable(arg1, arg0)) {
+    return EmitInstruction<0xc4, 0x01, 0x06, 0x7F>(VectorRegister256Bit(arg1),
+                                                   VectorRegister256Bit(arg0));
+  }
+  EmitInstruction<0xc4, 0x01, 0x06, 0x6F>(VectorRegister256Bit(arg0), VectorRegister256Bit(arg1));
+}
+
+constexpr inline void Assembler::Vmovsd(XMMRegister arg0, XMMRegister arg1, XMMRegister arg2) {
+  if (IsSwapProfitable(arg2, arg0)) {
     return EmitInstruction<0xc4, 0x01, 0x03, 0x11>(
         VectorRegister128Bit(arg2), VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
   }
@@ -536,8 +617,8 @@ inline void Assembler::Vmovsd(XMMRegister arg0, XMMRegister arg1, XMMRegister ar
       VectorRegister128Bit(arg0), VectorRegister128Bit(arg2), VectorRegister128Bit(arg1));
 }
 
-inline void Assembler::Vmovss(XMMRegister arg0, XMMRegister arg1, XMMRegister arg2) {
-  if (arg0.num_ < 8 && arg2.num_ >= 8) {
+constexpr inline void Assembler::Vmovss(XMMRegister arg0, XMMRegister arg1, XMMRegister arg2) {
+  if (IsSwapProfitable(arg2, arg0)) {
     return EmitInstruction<0xc4, 0x01, 0x02, 0x11>(
         VectorRegister128Bit(arg2), VectorRegister128Bit(arg0), VectorRegister128Bit(arg1));
   }
@@ -545,7 +626,7 @@ inline void Assembler::Vmovss(XMMRegister arg0, XMMRegister arg1, XMMRegister ar
       VectorRegister128Bit(arg0), VectorRegister128Bit(arg2), VectorRegister128Bit(arg1));
 }
 
-inline void Assembler::Xchgq(Register dest, Register src) {
+constexpr inline void Assembler::Xchgq(Register dest, Register src) {
   // We compare output to that from clang and thus want to produce the same code.
   // 0x48 0x90 is suboptimal encoding for that operation (pure 0x90 does the same
   // and this is what gcc + gas are producing), but this is what clang <= 8 does.
diff --git a/assembler/instructions/insn_def_riscv.json b/assembler/instructions/insn_def_riscv.json
index 3d14c5ea..d5ce3a42 100644
--- a/assembler/instructions/insn_def_riscv.json
+++ b/assembler/instructions/insn_def_riscv.json
@@ -252,19 +252,19 @@
       ]
     },
     {
-      "encodings": {
-        "jal": { "opcode": "0000_006f", "type": "J-Type" }
-      },
+      "stems": [ "jal", "la", "lb", "lbu", "lh", "lhu", "lw" ],
       "args": [
         { "class": "GeneralReg", "usage": "def" },
-        { "class": "J-Imm" }
+        { "class": "Label" }
       ]
     },
     {
-      "stems": [ "jal" ],
+      "encodings": {
+        "jal": { "opcode": "0000_006f", "type": "J-Type" }
+      },
       "args": [
         { "class": "GeneralReg", "usage": "def" },
-        { "class": "Label" }
+        { "class": "J-Imm" }
       ]
     },
     {
@@ -282,13 +282,6 @@
         { "class": "Mem", "usage": "use" }
       ]
     },
-    {
-      "stems": [ "la", "lb", "lbu", "lh", "lhu", "lw" ],
-      "args": [
-        { "class": "GeneralReg", "usage": "def" },
-        { "class": "Label" }
-      ]
-    },
     {
       "encodings": {
         "lb": { "opcode": "0000_0003", "type": "I-type" },
@@ -326,7 +319,7 @@
       ]
     },
     {
-      "stems": [ "mv", "neg", "not" ],
+      "stems": [ "mv", "neg", "not", "seqz", "sgtz", "sltz", "snez" ],
       "args": [
         { "class": "GeneralReg", "usage": "def" },
         { "class": "GeneralReg", "usage": "use" }
@@ -363,13 +356,6 @@
         { "class": "Mem8", "usage": "def" }
       ]
     },
-    {
-      "stems": [ "seqz", "sgtz", "sltz", "snez" ],
-      "args": [
-        { "class": "GeneralReg", "usage": "def" },
-        { "class": "GeneralReg", "usage": "use" }
-      ]
-    },
     {
       "encodings": {
         "sext.b": { "opcode": "6040_1013", "type": "R-type" },
diff --git a/assembler/instructions/insn_def_x86.json b/assembler/instructions/insn_def_x86.json
index 37e694df..881df58e 100644
--- a/assembler/instructions/insn_def_x86.json
+++ b/assembler/instructions/insn_def_x86.json
@@ -76,7 +76,7 @@
     {
       "encodings": {
         "Adcl": { "opcode": "11", "type": "reg_to_rm" },
-        "Sbbl": { "opcode": "19", "type": "reg_to_rm" }
+        "Sbbl": { "opcode": "19", "type": "reg_to_rm", "dependency_breaking": "true" }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "use_def" },
@@ -245,8 +245,8 @@
         "Btrl": { "opcodes": [ "0F", "B3" ], "type": "reg_to_rm" },
         "Btsl": { "opcodes": [ "0F", "AB" ], "type": "reg_to_rm" },
         "Orl": { "opcode": "09", "type": "reg_to_rm" },
-        "Subl": { "opcode": "29", "type": "reg_to_rm" },
-        "Xorl": { "opcode": "31", "type": "reg_to_rm" }
+        "Subl": { "opcode": "29", "type": "reg_to_rm", "dependency_breaking": "true" },
+        "Xorl": { "opcode": "31", "type": "reg_to_rm", "dependency_breaking": "true" }
       },
       "args": [
         { "class": "GeneralReg32/Mem32", "usage": "use_def" },
@@ -323,6 +323,10 @@
       "encodings": {
         "Addpd": { "opcodes": [ "66", "0F", "58" ] },
         "Addps": { "opcodes": [ "0F", "58" ] },
+        "Aesdec": { "feature": "AES", "opcodes": [ "66", "0F", "38", "DE" ] },
+        "Aesdeclast": { "feature": "AES", "opcodes": [ "66", "0F", "38", "DF" ] },
+        "Aesenc": { "feature": "AES", "opcodes": [ "66", "0F", "38", "DC" ] },
+        "Aesenclast": { "feature": "AES", "opcodes": [ "66", "0F", "38", "DD" ] },
         "Andpd": { "opcodes": [ "66", "0F", "54" ] },
         "Andps": { "opcodes": [ "0F", "54" ] },
         "Cmpeqpd": { "opcodes": [ "66", "0F", "C2", "00" ] },
@@ -366,17 +370,21 @@
         "Paddusw": { "opcodes": [ "66", "0F", "DD" ] },
         "Paddw": { "opcodes": [ "66", "0F", "FD" ] },
         "Pand": { "opcodes": [ "66", "0F", "DB" ] },
-        "Pandn": { "opcodes": [ "66", "0F", "DF" ] },
+        "Pandn": { "opcodes": [ "66", "0F", "DF" ], "dependency_breaking": "true" },
         "Pavgb": { "opcodes": [ "66", "0F", "E0" ] },
         "Pavgw": { "opcodes": [ "66", "0F", "E3" ] },
-        "Pcmpeqb": { "opcodes": [ "66", "0F", "74" ] },
-        "Pcmpeqd": { "opcodes": [ "66", "0F", "76" ] },
-        "Pcmpeqq": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "29" ] },
-        "Pcmpeqw": { "opcodes": [ "66", "0F", "75" ] },
-        "Pcmpgtb": { "opcodes": [ "66", "0F", "64" ] },
-        "Pcmpgtd": { "opcodes": [ "66", "0F", "66" ] },
-        "Pcmpgtq": { "feature": "SSE4_2", "opcodes": [ "66", "0F", "38", "37" ] },
-        "Pcmpgtw": { "opcodes": [ "66", "0F", "65" ] },
+        "Pclmulhqhqdq": { "feature": "CLMUL", "opcodes": [ "66", "0F", "3A", "44", "11" ] },
+        "Pclmulhqlqdq": { "feature": "CLMUL", "opcodes": [ "66", "0F", "3A", "44", "01" ] },
+        "Pclmullqhqdq": { "feature": "CLMUL", "opcodes": [ "66", "0F", "3A", "44", "10" ] },
+        "Pclmullqlqdq": { "feature": "CLMUL", "opcodes": [ "66", "0F", "3A", "44", "00" ] },
+        "Pcmpeqb": { "opcodes": [ "66", "0F", "74" ], "dependency_breaking": "true" },
+        "Pcmpeqd": { "opcodes": [ "66", "0F", "76" ], "dependency_breaking": "true" },
+        "Pcmpeqq": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "29" ], "dependency_breaking": "true" },
+        "Pcmpeqw": { "opcodes": [ "66", "0F", "75" ], "dependency_breaking": "true" },
+        "Pcmpgtb": { "opcodes": [ "66", "0F", "64" ], "dependency_breaking": "true" },
+        "Pcmpgtd": { "opcodes": [ "66", "0F", "66" ], "dependency_breaking": "true" },
+        "Pcmpgtq": { "feature": "SSE4_2", "opcodes": [ "66", "0F", "38", "37" ], "dependency_breaking": "true" },
+        "Pcmpgtw": { "opcodes": [ "66", "0F", "65" ], "dependency_breaking": "true" },
         "Phaddd": { "feature": "SSSE3", "opcodes": [ "66", "0F", "38", "02" ] },
         "Phaddw": { "feature": "SSSE3", "opcodes": [ "66", "0F", "38", "01" ] },
         "Pmaxsb": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "3C" ] },
@@ -407,14 +415,14 @@
         "Psrld": { "opcodes": [ "66", "0F", "D2" ] },
         "Psrlq": { "opcodes": [ "66", "0F", "D3" ] },
         "Psrlw": { "opcodes": [ "66", "0F", "D1" ] },
-        "Psubb": { "opcodes": [ "66", "0F", "F8" ] },
-        "Psubd": { "opcodes": [ "66", "0F", "FA" ] },
-        "Psubq": { "opcodes": [ "66", "0F", "FB" ] },
+        "Psubb": { "opcodes": [ "66", "0F", "F8" ], "dependency_breaking": "true" },
+        "Psubd": { "opcodes": [ "66", "0F", "FA" ], "dependency_breaking": "true" },
+        "Psubq": { "opcodes": [ "66", "0F", "FB" ], "dependency_breaking": "true" },
         "Psubsb": { "opcodes": [ "66", "0F", "E8" ] },
         "Psubsw": { "opcodes": [ "66", "0F", "E9" ] },
         "Psubusb": { "opcodes": [ "66", "0F", "D8" ] },
         "Psubusw": { "opcodes": [ "66", "0F", "D9" ] },
-        "Psubw": { "opcodes": [ "66", "0F", "F9" ] },
+        "Psubw": { "opcodes": [ "66", "0F", "F9" ], "dependency_breaking": "true" },
         "Punpckhbw": { "opcodes": [ "66", "0F", "68" ] },
         "Punpckhdq": { "opcodes": [ "66", "0F", "6A" ] },
         "Punpckhqdq": { "opcodes": [ "66", "0F", "6D" ] },
@@ -423,13 +431,17 @@
         "Punpckldq": { "opcodes": [ "66", "0F", "62" ] },
         "Punpcklqdq": { "opcodes": [ "66", "0F", "6C" ] },
         "Punpcklwd": { "opcodes": [ "66", "0F", "61" ] },
-        "Pxor": { "opcodes": [ "66", "0F", "EF" ] },
+        "Pxor": { "opcodes": [ "66", "0F", "EF" ], "dependency_breaking": "true" },
         "Rsqrtps": { "opcodes": [ "0F", "52" ] },
         "Subpd": { "opcodes": [ "66", "0F", "5C" ] },
         "Subps": { "opcodes": [ "0F", "5C" ] },
+        "Unpckhpd": { "opcodes": [ "66", "0F", "15" ] },
+        "Unpckhps": { "opcodes": [ "0F", "15" ] },
+        "Unpcklpd": { "opcodes": [ "66", "0F", "14" ] },
+        "Unpcklps": { "opcodes": [ "0F", "14" ] },
         "Vrsqrtps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "52" ] },
-        "Xorpd": { "opcodes": [ "66", "0F", "57" ] },
-        "Xorps": { "opcodes": [ "0F", "57" ] }
+        "Xorpd": { "opcodes": [ "66", "0F", "57" ], "dependency_breaking": "true" },
+        "Xorps": { "opcodes": [ "0F", "57" ], "dependency_breaking": "true" }
       },
       "args": [
         { "class": "VecReg128", "usage": "use_def" },
@@ -554,6 +566,46 @@
         { "class": "FLAGS", "usage": "def" }
       ]
     },
+    {
+      "encodings": {
+        "Aesimc": { "feature": "AES", "opcodes": [ "66", "0F", "38", "DB" ] },
+        "Movq": { "opcodes": [ "F3", "0F", "7E" ] },
+        "Pmovsxbw": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "20" ] },
+        "Pmovsxdq": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "25" ] },
+        "Pmovsxwd": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "23" ] },
+        "Pmovzxbw": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "30" ] },
+        "Pmovzxdq": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "35" ] },
+        "Pmovzxwd": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "33" ] },
+        "Vaesimc": { "feature": "AESAVX", "opcodes": [ "C4", "02", "01", "DB" ] },
+        "Vmovq": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "7E" ] }
+      },
+      "args": [
+        { "class": "XmmReg", "usage": "def" },
+        { "class": "XmmReg/VecMem64", "usage": "use" }
+      ],
+      "comment": "Upper bits are zero-filled for Movq/Vmovq"
+    },
+    {
+      "encodings": {
+        "Aeskeygenassist": { "feature": "AVX", "opcodes": [ "66", "0F", "3A", "DF" ] },
+        "Pshufd": { "opcodes": [ "66", "0F", "70" ] },
+        "Pshufhw": { "opcodes": [ "F3", "0F", "70" ] },
+        "Pshuflw": { "opcodes": [ "F2", "0F", "70" ] },
+        "Roundpd": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "09" ] },
+        "Roundps": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "08" ] },
+        "Vaeskeygenassist": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "DF" ] },
+        "Vpshufd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "70" ] },
+        "Vpshufhw": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "70" ] },
+        "Vpshuflw": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "70" ] },
+        "Vroundpd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "09" ] },
+        "Vroundps": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "08" ] }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "def" },
+        { "class": "VecReg128/VecMem128", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
     {
       "encodings": {
         "Andnl": { "feature": "BMI", "opcodes": [ "C4", "02", "00", "F2" ], "type": "vex_rm_to_reg" }
@@ -571,7 +623,7 @@
         "Bzhil": { "feature": "BMI2", "opcodes": [ "C4", "02", "00", "F5" ] }
       },
       "args": [
-        { "class": "GeneralReg32", "usage": "use_def" },
+        { "class": "GeneralReg32", "usage": "def" },
         { "class": "GeneralReg32/Mem32", "usage": "use" },
         { "class": "GeneralReg32", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
@@ -619,7 +671,7 @@
     {
       "encodings": {
         "Btl": { "opcodes": [ "0F", "A3" ], "type": "reg_to_rm" },
-        "Cmpl": { "opcode": "39", "type": "reg_to_rm" },
+        "Cmpl": { "opcode": "39", "type": "reg_to_rm", "dependency_breaking": "true" },
         "Testl": { "opcode": "85", "type": "reg_to_rm" }
       },
       "args": [
@@ -874,10 +926,35 @@
         "Vcvtdq2pd": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "E6" ] },
         "Vcvtdq2ps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5B" ] },
         "Vcvtpd2dq": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "E6" ] },
+        "Vcvtpd2dqx": {
+          "comment": [
+            "Suffix “x” used to distingush 128bit memory operand from 256bit memory operand",
+            "This is common convention for assemblers that use AT&T syntax"
+          ],
+          "feature": "AVX",
+          "opcodes": [ "C4", "01", "03", "E6" ]
+        },
         "Vcvtpd2ps": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5A" ] },
+        "Vcvtpd2psx": {
+          "comment": [
+            "Suffix “x” used to distingush 128bit memory operand from 256bit memory operand",
+            "This is common convention for assemblers that use AT&T syntax"
+          ],
+          "feature": "AVX",
+          "opcodes": [ "C4", "01", "01", "5A" ]
+        },
+        "Vcvtph2ps": { "feature": "F16C", "opcodes": [ "C4", "02", "01", "13" ] },
         "Vcvtps2dq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5B" ] },
         "Vcvtps2pd": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5A" ] },
         "Vcvttpd2dq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E6" ] },
+        "Vcvttpd2dqx": {
+          "comment": [
+            "Suffix “x” used to distingush 128bit memory operand from 256bit memory operand",
+            "This is common convention for assemblers that use AT&T syntax"
+          ],
+          "feature": "AVX",
+          "opcodes": [ "C4", "01", "01", "E6" ]
+        },
         "Vcvttps2dq": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "5B" ] }
       },
       "args": [
@@ -1042,6 +1119,13 @@
         "Fabs": { "opcodes": [ "D9", "E1" ] },
         "Fchs": { "opcodes": [ "D9", "E0" ] },
         "Fcos": { "opcodes": [ "D9", "FF" ] },
+        "Fld1": { "opcodes": [ "D9", "E8" ] },
+        "Fldl2e": { "opcodes": [ "D9", "EA" ] },
+        "Fldl2t": { "opcodes": [ "D9", "E9" ] },
+        "Fldlg2": { "opcodes": [ "D9", "EC" ] },
+        "Fldln2": { "opcodes": [ "D9", "ED" ] },
+        "Fldpi": { "opcodes": [ "D9", "EB" ] },
+        "Fldz": { "opcodes": [ "D9", "EE" ] },
         "Frndint": { "opcodes": [ "D9", "FC" ] },
         "Fscale": { "opcodes": [ "D9", "FD" ] },
         "Fsin": { "opcodes": [ "D9", "FE" ] },
@@ -1332,20 +1416,6 @@
         { "class": "ST", "usage": "use" }
       ]
     },
-    {
-      "encodings": {
-        "Fld1": { "opcodes": [ "D9", "E8" ] },
-        "Fldl2e": { "opcodes": [ "D9", "EA" ] },
-        "Fldl2t": { "opcodes": [ "D9", "E9" ] },
-        "Fldlg2": { "opcodes": [ "D9", "EC" ] },
-        "Fldln2": { "opcodes": [ "D9", "ED" ] },
-        "Fldpi": { "opcodes": [ "D9", "EB" ] },
-        "Fldz": { "opcodes": [ "D9", "EE" ] }
-      },
-      "args": [
-        { "class": "ST", "usage": "use_def" }
-      ]
-    },
     {
       "encodings": {
         "Fld": { "opcodes": [ "D9", "0" ] }
@@ -1695,24 +1765,26 @@
     },
     {
       "encodings": {
-        "Movapd": { "opcodes": [ "66", "0F", "29" ] },
-        "Movaps": { "opcodes": [ "0F", "29" ] },
-        "Vmovapd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "29" ] },
-        "Vmovaps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "29" ] }
+        "Movapd": { "opcodes": [ "66", "0F", "28" ] },
+        "Movaps": { "opcodes": [ "0F", "28" ] },
+        "Movdqa": { "opcodes": [ "66", "0F", "6F" ] },
+        "Movdqu": { "opcodes": [ "F3", "0F", "6F" ] }
       },
       "args": [
-        { "class": "VecMem128", "usage": "def" },
-        { "class": "XmmReg", "usage": "use" }
+        { "class": "XmmReg", "usage": "def" },
+        { "class": "XmmReg/VecMem128", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "Movapd": { "opcodes": [ "66", "0F", "28" ] },
-        "Movaps": { "opcodes": [ "0F", "28" ] }
+        "Movapd": { "opcodes": [ "66", "0F", "29" ] },
+        "Movaps": { "opcodes": [ "0F", "29" ] },
+        "Vmovapd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "29" ] },
+        "Vmovaps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "29" ] }
       },
       "args": [
-        { "class": "XmmReg", "usage": "def" },
-        { "class": "XmmReg/VecMem128", "usage": "use" }
+        { "class": "VecMem128", "usage": "def" },
+        { "class": "XmmReg", "usage": "use" }
       ]
     },
     {
@@ -1792,16 +1864,6 @@
         { "class": "XmmReg", "usage": "use" }
       ]
     },
-    {
-      "encodings": {
-        "Movdqa": { "opcodes": [ "66", "0F", "6F" ] },
-        "Movdqu": { "opcodes": [ "F3", "0F", "6F" ] }
-      },
-      "args": [
-        { "class": "XmmReg", "usage": "def" },
-        { "class": "XmmReg/VecMem128", "usage": "use" }
-      ]
-    },
     {
       "encodings": {
         "Movhlps": { "opcodes": [ "0F", "12" ] },
@@ -1905,31 +1967,24 @@
     },
     {
       "encodings": {
-        "Movq": { "opcodes": [ "F3", "0F", "7E" ] },
-        "Pmovsxbw": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "20" ] },
-        "Pmovsxdq": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "25" ] },
-        "Pmovsxwd": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "23" ] },
-        "Pmovzxbw": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "30" ] },
-        "Pmovzxdq": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "35" ] },
-        "Pmovzxwd": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "38", "33" ] },
-        "Vmovq": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "7E" ] }
+        "Movsd": { "opcodes": [ "F2", "0F", "10" ] },
+        "Vmovsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "10" ] }
       },
       "args": [
         { "class": "XmmReg", "usage": "def" },
-        { "class": "XmmReg/VecMem64", "usage": "use" }
+        { "class": "VecMem64", "usage": "use" }
       ],
-      "comment": "Upper bits are zero-filled for Movq/Vmovq"
+      "comment": "Upper bits are zero-filled"
     },
     {
       "encodings": {
-        "Movsd": { "opcodes": [ "F2", "0F", "10" ] },
-        "Vmovsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "10" ] }
+        "Movss": { "opcodes": [ "F3", "0F", "11" ] },
+        "Vmovss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "11" ] }
       },
       "args": [
-        { "class": "XmmReg", "usage": "def" },
-        { "class": "VecMem64", "usage": "use" }
-      ],
-      "comment": "Upper bits are zero-filled"
+        { "class": "Mem32", "usage": "def" },
+        { "class": "XmmReg", "usage": "use" }
+      ]
     },
     {
       "encodings": {
@@ -1942,15 +1997,6 @@
       ],
       "comment": "Upper bits are zero-filled"
     },
-    {
-      "encodings": {
-        "Movss": { "opcodes": [ "F3", "0F", "11" ] }
-      },
-      "args": [
-        { "class": "Mem32", "usage": "def" },
-        { "class": "XmmReg", "usage": "use" }
-      ]
-    },
     {
       "encodings": {
         "Movsxbl": { "opcodes": [ "0F", "BE" ] },
@@ -2071,6 +2117,18 @@
         { "class": "GeneralReg16/Mem16", "usage": "use_def" }
       ]
     },
+    {
+      "encodings": {
+        "Pclmulqdq": { "feature": "CLMUL", "opcodes": [ "66", "0F", "3A", "44" ] },
+        "Shufpd": { "opcodes": [ "66", "0F", "C6" ] },
+        "Shufps": { "opcodes": [ "0F", "C6" ] }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "use_def" },
+        { "class": "VecReg128/VecMem128", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
     {
       "encodings": {
         "Pextrb": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "14" ], "type": "reg_to_rm" },
@@ -2086,6 +2144,39 @@
         { "class": "Imm8" }
       ]
     },
+    {
+      "encodings": {
+        "Pextrb": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "14" ], "type": "reg_to_rm" },
+        "Vpextrb": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "14" ], "type": "reg_to_rm" }
+      },
+      "args": [
+        { "class": "Mem8", "usage": "def" },
+        { "class": "VecReg128", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Pextrd": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "16" ], "type": "reg_to_rm" },
+        "Vpextrd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "16" ], "type": "reg_to_rm" }
+      },
+      "args": [
+        { "class": "Mem32", "usage": "def" },
+        { "class": "VecReg128", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Pextrw": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "15" ] },
+        "Vpextrw": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "15" ] }
+      },
+      "args": [
+        { "class": "Mem16", "usage": "def" },
+        { "class": "VecReg128", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
     {
       "encodings": {
         "Pinsrb": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "20" ] },
@@ -2098,6 +2189,36 @@
         { "class": "Imm8" }
       ]
     },
+    {
+      "encodings": {
+        "Pinsrb": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "20" ] }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "use_def" },
+        { "class": "Mem8", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Pinsrd": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "22" ] }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "use_def" },
+        { "class": "Mem32", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Pinsrw": { "opcodes": [ "66", "0F", "C4" ] }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "use_def" },
+        { "class": "Mem16", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
     {
       "encodings": {
         "Pmovmskb": { "opcodes": [ "66", "0F", "D7" ] },
@@ -2129,25 +2250,6 @@
         { "class": "GeneralReg", "usage": "def" }
       ]
     },
-    {
-      "encodings": {
-        "Pshufd": { "opcodes": [ "66", "0F", "70" ] },
-        "Pshufhw": { "opcodes": [ "F3", "0F", "70" ] },
-        "Pshuflw": { "opcodes": [ "F2", "0F", "70" ] },
-        "Roundpd": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "09" ] },
-        "Roundps": { "feature": "SSE4_1", "opcodes": [ "66", "0F", "3A", "08" ] },
-        "Vpshufd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "70" ] },
-        "Vpshufhw": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "70" ] },
-        "Vpshuflw": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "70" ] },
-        "Vroundpd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "09" ] },
-        "Vroundps": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "08" ] }
-      },
-      "args": [
-        { "class": "VecReg128", "usage": "def" },
-        { "class": "VecReg128/VecMem128", "usage": "use" },
-        { "class": "Imm8" }
-      ]
-    },
     {
       "encodings": {
         "Pslld": { "opcodes": [ "66", "0F", "72", "6" ] },
@@ -2382,17 +2484,6 @@
         { "class": "FLAGS", "usage": "def" }
       ]
     },
-    {
-      "encodings": {
-        "Shufpd": { "opcodes": [ "66", "0F", "C6" ] },
-        "Shufps": { "opcodes": [ "0F", "C6" ] }
-      },
-      "args": [
-        { "class": "VecReg128", "usage": "use_def" },
-        { "class": "VecReg128/VecMem128", "usage": "use" },
-        { "class": "Imm8" }
-      ]
-    },
     {
       "encodings": {
         "Sqrtsd": { "opcodes": [ "F2", "0F", "51" ] }
@@ -2444,6 +2535,10 @@
       "encodings": {
         "Vaddpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "58" ], "type": "optimizable_using_commutation" },
         "Vaddps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "58" ], "type": "optimizable_using_commutation" },
+        "Vaesdec": { "feature": "AESAVX", "opcodes": [ "C4", "02", "01", "DE" ], "type": "vex_rm_to_reg" },
+        "Vaesdeclast": { "feature": "AESAVX", "opcodes": [ "C4", "02", "01", "DF" ], "type": "vex_rm_to_reg" },
+        "Vaesenc": { "feature": "AESAVX", "opcodes": [ "C4", "02", "01", "DC" ], "type": "vex_rm_to_reg" },
+        "Vaesenclast": { "feature": "AESAVX", "opcodes": [ "C4", "02", "01", "DD" ], "type": "vex_rm_to_reg" },
         "Vandpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "54" ], "type": "optimizable_using_commutation" },
         "Vandps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "54" ], "type": "optimizable_using_commutation" },
         "Vcmpeqpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C2", "00" ], "type": "optimizable_using_commutation" },
@@ -2487,17 +2582,21 @@
         "Vpaddusw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DD" ], "type": "optimizable_using_commutation" },
         "Vpaddw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FD" ], "type": "optimizable_using_commutation" },
         "Vpand": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DB" ], "type": "optimizable_using_commutation" },
-        "Vpandn": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DF" ], "type": "vex_rm_to_reg" },
+        "Vpandn": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "DF" ], "type": "vex_rm_to_reg", "dependency_breaking": "true" },
         "Vpavgb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E0" ], "type": "optimizable_using_commutation" },
         "Vpavgw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E3" ], "type": "optimizable_using_commutation" },
-        "Vpcmpeqb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "74" ], "type": "optimizable_using_commutation" },
-        "Vpcmpeqd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "76" ], "type": "optimizable_using_commutation" },
-        "Vpcmpeqq": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "29" ], "type": "vex_rm_to_reg" },
-        "Vpcmpeqw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "75" ], "type": "optimizable_using_commutation" },
-        "Vpcmpgtb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "64" ], "type": "vex_rm_to_reg" },
-        "Vpcmpgtd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "66" ], "type": "vex_rm_to_reg" },
-        "Vpcmpgtq": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "37" ], "type": "vex_rm_to_reg" },
-        "Vpcmpgtw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "65" ], "type": "vex_rm_to_reg" },
+        "Vpclmulhqhqdq": { "feature": "CLMULAVX", "opcodes": [ "C4", "03", "01", "44", "11" ], "type": "vex_rm_to_reg" },
+        "Vpclmulhqlqdq": { "feature": "CLMULAVX", "opcodes": [ "C4", "03", "01", "44", "01" ], "type": "vex_rm_to_reg" },
+        "Vpclmullqhqdq": { "feature": "CLMULAVX", "opcodes": [ "C4", "03", "01", "44", "10" ], "type": "vex_rm_to_reg" },
+        "Vpclmullqlqdq": { "feature": "CLMULAVX", "opcodes": [ "C4", "03", "01", "44", "00" ], "type": "vex_rm_to_reg" },
+        "Vpcmpeqb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "74" ], "type": "optimizable_using_commutation", "dependency_breaking": "true" },
+        "Vpcmpeqd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "76" ], "type": "optimizable_using_commutation", "dependency_breaking": "true" },
+        "Vpcmpeqq": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "29" ], "type": "vex_rm_to_reg", "dependency_breaking": "true" },
+        "Vpcmpeqw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "75" ], "type": "optimizable_using_commutation", "dependency_breaking": "true" },
+        "Vpcmpgtb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "64" ], "type": "vex_rm_to_reg", "dependency_breaking": "true" },
+        "Vpcmpgtd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "66" ], "type": "vex_rm_to_reg", "dependency_breaking": "true" },
+        "Vpcmpgtq": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "37" ], "type": "vex_rm_to_reg", "dependency_breaking": "true" },
+        "Vpcmpgtw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "65" ], "type": "vex_rm_to_reg", "dependency_breaking": "true" },
         "Vpmaxsb": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3C" ], "type": "vex_rm_to_reg" },
         "Vpmaxsd": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "3D" ], "type": "vex_rm_to_reg" },
         "Vpmaxsw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EE" ], "type": "optimizable_using_commutation" },
@@ -2526,14 +2625,14 @@
         "Vpsrld": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D2" ], "type": "vex_rm_to_reg" },
         "Vpsrlq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D3" ], "type": "vex_rm_to_reg" },
         "Vpsrlw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D1" ], "type": "vex_rm_to_reg" },
-        "Vpsubb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F8" ], "type": "vex_rm_to_reg" },
-        "Vpsubd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FA" ], "type": "vex_rm_to_reg" },
-        "Vpsubq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FB" ], "type": "vex_rm_to_reg" },
+        "Vpsubb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F8" ], "type": "vex_rm_to_reg", "dependency_breaking": "true" },
+        "Vpsubd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FA" ], "type": "vex_rm_to_reg", "dependency_breaking": "true" },
+        "Vpsubq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "FB" ], "type": "vex_rm_to_reg", "dependency_breaking": "true" },
         "Vpsubsb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E8" ], "type": "vex_rm_to_reg" },
         "Vpsubsw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "E9" ], "type": "vex_rm_to_reg" },
         "Vpsubusb": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D8" ], "type": "vex_rm_to_reg" },
         "Vpsubusw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "D9" ], "type": "vex_rm_to_reg" },
-        "Vpsubw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F9" ], "type": "vex_rm_to_reg" },
+        "Vpsubw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "F9" ], "type": "vex_rm_to_reg", "dependency_breaking": "true" },
         "Vpunpckhbw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "68" ], "type": "vex_rm_to_reg" },
         "Vpunpckhdq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6A" ], "type": "vex_rm_to_reg" },
         "Vpunpckhqdq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6D" ], "type": "vex_rm_to_reg" },
@@ -2542,11 +2641,15 @@
         "Vpunpckldq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "62" ], "type": "vex_rm_to_reg" },
         "Vpunpcklqdq": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6C" ], "type": "vex_rm_to_reg" },
         "Vpunpcklwd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "61" ], "type": "vex_rm_to_reg" },
-        "Vpxor": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EF" ], "type": "optimizable_using_commutation" },
+        "Vpxor": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "EF" ], "type": "optimizable_using_commutation", "dependency_breaking": "true" },
         "Vsubpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "5C" ], "type": "vex_rm_to_reg" },
         "Vsubps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "5C" ], "type": "vex_rm_to_reg" },
-        "Vxorpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "57" ], "type": "optimizable_using_commutation" },
-        "Vxorps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "57" ], "type": "optimizable_using_commutation" }
+        "Vunpckhpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "15" ], "type": "vex_rm_to_reg" },
+        "Vunpckhps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "15" ], "type": "vex_rm_to_reg" },
+        "Vunpcklpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "14" ], "type": "vex_rm_to_reg" },
+        "Vunpcklps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "14" ], "type": "vex_rm_to_reg" },
+        "Vxorpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "57" ], "type": "optimizable_using_commutation", "dependency_breaking": "true" },
+        "Vxorps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "57" ], "type": "optimizable_using_commutation", "dependency_breaking": "true" }
       },
       "args": [
         { "class": "VecReg128", "usage": "def" },
@@ -2558,6 +2661,10 @@
       "encodings": {
         "Vaddpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "58" ], "type": "optimizable_using_commutation" },
         "Vaddps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "58" ], "type": "optimizable_using_commutation" },
+        "Vaesdec": { "feature": "VAES", "opcodes": [ "C4", "02", "05", "DE" ], "type": "vex_rm_to_reg" },
+        "Vaesdeclast": { "feature": "VAES", "opcodes": [ "C4", "02", "05", "DF" ], "type": "vex_rm_to_reg" },
+        "Vaesenc": { "feature": "VAES", "opcodes": [ "C4", "02", "05", "DC" ], "type": "vex_rm_to_reg" },
+        "Vaesenclast": { "feature": "VAES", "opcodes": [ "C4", "02", "05", "DD" ], "type": "vex_rm_to_reg" },
         "Vandpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "54" ], "type": "optimizable_using_commutation" },
         "Vandps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "54" ], "type": "optimizable_using_commutation" },
         "Vcmpeqpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "C2", "00" ], "type": "optimizable_using_commutation" },
@@ -2604,6 +2711,10 @@
         "Vpandn": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "DF" ], "type": "vex_rm_to_reg" },
         "Vpavgb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "E0" ], "type": "optimizable_using_commutation" },
         "Vpavgw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "E3" ], "type": "optimizable_using_commutation" },
+        "Vpclmulhqhqdq": { "feature": "VPCLMULQD", "opcodes": [ "C4", "03", "05", "44", "11" ], "type": "vex_rm_to_reg" },
+        "Vpclmulhqlqdq": { "feature": "VPCLMULQD", "opcodes": [ "C4", "03", "05", "44", "01" ], "type": "vex_rm_to_reg" },
+        "Vpclmullqhqdq": { "feature": "VPCLMULQD", "opcodes": [ "C4", "03", "05", "44", "10" ], "type": "vex_rm_to_reg" },
+        "Vpclmullqlqdq": { "feature": "VPCLMULQD", "opcodes": [ "C4", "03", "05", "44", "00" ], "type": "vex_rm_to_reg" },
         "Vpcmpeqb": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "74" ], "type": "optimizable_using_commutation" },
         "Vpcmpeqd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "76" ], "type": "optimizable_using_commutation" },
         "Vpcmpeqq": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "29" ], "type": "vex_rm_to_reg" },
@@ -2651,6 +2762,10 @@
         "Vpxor": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "EF" ], "type": "optimizable_using_commutation" },
         "Vsubpd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "5C" ], "type": "vex_rm_to_reg" },
         "Vsubps": { "feature": "AVX2", "opcodes": [ "C4", "01", "04", "5C" ], "type": "vex_rm_to_reg" },
+        "Vunpckhpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "15" ], "type": "vex_rm_to_reg" },
+        "Vunpckhps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "15" ], "type": "vex_rm_to_reg" },
+        "Vunpcklpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "14" ], "type": "vex_rm_to_reg" },
+        "Vunpcklps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "14" ], "type": "vex_rm_to_reg" },
         "Vxorpd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "57" ], "type": "optimizable_using_commutation" },
         "Vxorps": { "feature": "AVX2", "opcodes": [ "C4", "01", "04", "57" ], "type": "optimizable_using_commutation" }
       },
@@ -2704,65 +2819,241 @@
     },
     {
       "encodings": {
-        "Vcvtsd2ss": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "5A" ], "type": "vex_rm_to_reg" }
+        "Vblendvps": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "4A" ], "type": "vex_rm_imm_to_reg" },
+        "Vblendvpd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "4B" ], "type": "vex_rm_imm_to_reg" }
       },
       "args": [
-        { "class": "FpReg32", "usage": "def" },
+        { "class": "XmmReg", "usage": "use_def" },
         { "class": "XmmReg", "usage": "use" },
-        { "class": "FpReg64/VecMem64", "usage": "use" }
+        { "class": "XmmReg/VecMem128", "usage": "use" },
+        { "class": "XmmReg", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "Vcvtsi2sdl": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "2A" ], "type": "vex_rm_to_reg" }
+        "Vblendvps": { "feature": "AVX", "opcodes": [ "C4", "03", "05", "4A" ], "type": "vex_rm_imm_to_reg" },
+        "Vblendvpd": { "feature": "AVX", "opcodes": [ "C4", "03", "05", "4B" ], "type": "vex_rm_imm_to_reg" }
       },
       "args": [
-        { "class": "FpReg64", "usage": "def" },
-        { "class": "XmmReg", "usage": "use" },
-        { "class": "GeneralReg32/Mem32", "usage": "use" }
+        { "class": "YmmReg", "usage": "use_def" },
+        { "class": "YmmReg", "usage": "use" },
+        { "class": "YmmReg/VecMem128", "usage": "use" },
+        { "class": "YmmReg", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "Vcvtsi2ssl": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "2A" ], "type": "vex_rm_to_reg" }
+        "Vbroadcastf128": { "feature": "AVX", "opcodes": [ "C4", "02", "05", "1a" ] },
+        "Vbroadcasti128": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "5a" ] }
       },
       "args": [
-        { "class": "FpReg32", "usage": "def" },
-        { "class": "XmmReg", "usage": "use" },
-        { "class": "GeneralReg32/Mem32", "usage": "use" }
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecMem128", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "Vcvtss2sd": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "5A" ], "type": "vex_rm_to_reg" }
+        "Vbroadcastsd": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "19" ] },
+        "Vbroadcastss": { "feature": "AVX2", "opcodes": [ "C4", "02", "05", "18" ] }
       },
       "args": [
-        { "class": "FpReg64", "usage": "def" },
-        { "class": "XmmReg", "usage": "use" },
-        { "class": "FpReg32/VecMem32", "usage": "use" }
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "XmmReg", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "Vfmadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "98" ], "type": "vex_rm_to_reg" },
-        "Vfmadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "98" ], "type": "vex_rm_to_reg" },
-        "Vfmadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A8" ], "type": "vex_rm_to_reg" },
-        "Vfmadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A8" ], "type": "vex_rm_to_reg" },
-        "Vfmadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B8" ], "type": "vex_rm_to_reg" },
-        "Vfmadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B8" ], "type": "vex_rm_to_reg" },
-        "Vfmaddsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "96" ], "type": "vex_rm_to_reg" },
-        "Vfmaddsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "96" ], "type": "vex_rm_to_reg" },
-        "Vfmaddsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A6" ], "type": "vex_rm_to_reg" },
-        "Vfmaddsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A6" ], "type": "vex_rm_to_reg" },
-        "Vfmaddsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B6" ], "type": "vex_rm_to_reg" },
-        "Vfmaddsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B6" ], "type": "vex_rm_to_reg" },
-        "Vfmsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9A" ], "type": "vex_rm_to_reg" },
-        "Vfmsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9A" ], "type": "vex_rm_to_reg" },
-        "Vfmsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AA" ], "type": "vex_rm_to_reg" },
-        "Vfmsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AA" ], "type": "vex_rm_to_reg" },
-        "Vfmsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BA" ], "type": "vex_rm_to_reg" },
-        "Vfmsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BA" ], "type": "vex_rm_to_reg" },
-        "Vfmsubadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "97" ], "type": "vex_rm_to_reg" },
+        "Vbroadcastsd": { "feature": "AVX", "opcodes": [ "C4", "02", "05", "19" ] }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecMem64", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vbroadcastss": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "18" ] }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "def" },
+        { "class": "VecMem32", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vbroadcastss": { "feature": "AVX2", "opcodes": [ "C4", "02", "01", "18" ] }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "def" },
+        { "class": "XmmReg", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vbroadcastss": { "feature": "AVX", "opcodes": [ "C4", "02", "05", "18" ] }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecMem32", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vcvtdq2pd": { "feature": "AVX", "opcodes": [ "C4", "01", "06", "E6" ] },
+        "Vcvtph2ps": { "feature": "F16C", "opcodes": [ "C4", "02", "05", "13" ] },
+        "Vcvtps2pd": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "5A" ] }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg128/VecMem128", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vcvtdq2ps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "5B" ] },
+        "Vcvtps2dq": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "5B" ] },
+        "Vcvttps2dq": { "feature": "AVX", "opcodes": [ "C4", "01", "06", "5B" ] }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256/VecMem256", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vcvtpd2dq": { "feature": "AVX", "opcodes": [ "C4", "01", "07", "E6" ] },
+        "Vcvtpd2ps": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "5A" ] },
+        "Vcvttpd2dq": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "E6" ] }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vcvtpd2dqy": {
+          "comment": [
+            "Suffix “y” used to distingush 128bit memory operand from 256bit memory operand",
+            "This is common convention for assemblers that use AT&T syntax"
+          ],
+          "feature": "AVX",
+          "opcodes": [ "C4", "01", "07", "E6" ]
+        },
+        "Vcvtpd2psy": {
+          "comment": [
+            "Suffix “y” used to distingush 128bit memory operand from 256bit memory operand",
+            "This is common convention for assemblers that use AT&T syntax"
+          ],
+          "feature": "AVX",
+          "opcodes": [ "C4", "01", "05", "5A" ]
+        },
+        "Vcvttpd2dqy": {
+          "comment": [
+            "Suffix “y” used to distingush 128bit memory operand from 256bit memory operand",
+            "This is common convention for assemblers that use AT&T syntax"
+          ],
+          "feature": "AVX",
+          "opcodes": [ "C4", "01", "05", "E6" ]
+        }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "def" },
+        { "class": "VecReg256/VecMem256", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vcvtps2ph": { "feature": "F16C", "opcodes": [ "C4", "03", "05", "1D" ], "type": "reg_to_rm" }
+      },
+      "args": [
+        { "class": "VecReg128/VecMem128", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vcvtps2ph": { "feature": "F16C", "opcodes": [ "C4", "03", "01", "1D" ], "type": "reg_to_rm" }
+      },
+      "args": [
+        { "class": "XmmReg/VecMem64", "usage": "def" },
+        { "class": "VecReg128", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vcvtsd2ss": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "5A" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "FpReg32", "usage": "def" },
+        { "class": "XmmReg", "usage": "use" },
+        { "class": "FpReg64/VecMem64", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vcvtsi2sdl": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "2A" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "FpReg64", "usage": "def" },
+        { "class": "XmmReg", "usage": "use" },
+        { "class": "GeneralReg32/Mem32", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vcvtsi2ssl": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "2A" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "FpReg32", "usage": "def" },
+        { "class": "XmmReg", "usage": "use" },
+        { "class": "GeneralReg32/Mem32", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vcvtss2sd": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "5A" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "FpReg64", "usage": "def" },
+        { "class": "XmmReg", "usage": "use" },
+        { "class": "FpReg32/VecMem32", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vextractf128": { "feature": "AVX", "opcodes": [ "C4", "03", "05", "19" ], "type": "reg_to_rm" },
+        "Vextracti128": { "feature": "AVX2", "opcodes": [ "C4", "03", "05", "39" ], "type": "reg_to_rm" }
+      },
+      "args": [
+        { "class": "VecReg128/VecMem128", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vfmadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "98" ], "type": "vex_rm_to_reg" },
+        "Vfmadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "98" ], "type": "vex_rm_to_reg" },
+        "Vfmadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A8" ], "type": "vex_rm_to_reg" },
+        "Vfmadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A8" ], "type": "vex_rm_to_reg" },
+        "Vfmadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B8" ], "type": "vex_rm_to_reg" },
+        "Vfmadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B8" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "96" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "96" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A6" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A6" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "B6" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "B6" ], "type": "vex_rm_to_reg" },
+        "Vfmsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "9A" ], "type": "vex_rm_to_reg" },
+        "Vfmsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "9A" ], "type": "vex_rm_to_reg" },
+        "Vfmsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "AA" ], "type": "vex_rm_to_reg" },
+        "Vfmsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "AA" ], "type": "vex_rm_to_reg" },
+        "Vfmsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "BA" ], "type": "vex_rm_to_reg" },
+        "Vfmsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "BA" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "97" ], "type": "vex_rm_to_reg" },
         "Vfmsubadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "97" ], "type": "vex_rm_to_reg" },
         "Vfmsubadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "A7" ], "type": "vex_rm_to_reg" },
         "Vfmsubadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "01", "A7" ], "type": "vex_rm_to_reg" },
@@ -2787,6 +3078,51 @@
         { "class": "VecReg128/VecMem128", "usage": "use" }
       ]
     },
+    {
+      "encodings": {
+        "Vfmadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "98" ], "type": "vex_rm_to_reg" },
+        "Vfmadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "98" ], "type": "vex_rm_to_reg" },
+        "Vfmadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "A8" ], "type": "vex_rm_to_reg" },
+        "Vfmadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "A8" ], "type": "vex_rm_to_reg" },
+        "Vfmadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "B8" ], "type": "vex_rm_to_reg" },
+        "Vfmadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "B8" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "96" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "96" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "A6" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "A6" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "B6" ], "type": "vex_rm_to_reg" },
+        "Vfmaddsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "B6" ], "type": "vex_rm_to_reg" },
+        "Vfmsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "9A" ], "type": "vex_rm_to_reg" },
+        "Vfmsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "9A" ], "type": "vex_rm_to_reg" },
+        "Vfmsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "AA" ], "type": "vex_rm_to_reg" },
+        "Vfmsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "AA" ], "type": "vex_rm_to_reg" },
+        "Vfmsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "BA" ], "type": "vex_rm_to_reg" },
+        "Vfmsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "BA" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "97" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "97" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "A7" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "A7" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "B7" ], "type": "vex_rm_to_reg" },
+        "Vfmsubadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "B7" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "9C" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "9C" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "AC" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "AC" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "BC" ], "type": "vex_rm_to_reg" },
+        "Vfnmadd231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "BC" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub132pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "9E" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub132ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "9E" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub213pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "AE" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub213ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "AE" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub231pd": { "feature": "FMA", "opcodes": [ "C4", "02", "85", "BE" ], "type": "vex_rm_to_reg" },
+        "Vfnmsub231ps": { "feature": "FMA", "opcodes": [ "C4", "02", "05", "BE" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "use_def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecReg256/VecMem256", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "Vfmadd132sd": { "feature": "FMA", "opcodes": [ "C4", "02", "81", "99" ], "type": "vex_rm_to_reg" },
@@ -2873,6 +3209,50 @@
         { "class": "VecReg128/VecMem128", "usage": "use" }
       ]
     },
+    {
+      "encodings": {
+        "Vfmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "69" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "68" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmaddsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "5D" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmaddsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "5C" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmsubaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "5F" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmsubaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "5E" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "6D" ], "type": "vex_rm_imm_to_reg" },
+        "Vfmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "6C" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "79" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "78" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "7D" ], "type": "vex_rm_imm_to_reg" },
+        "Vfnmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "05", "7C" ], "type": "vex_rm_imm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecMem256", "usage": "use" },
+        { "class": "VecReg256", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vfmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "69" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "68" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmaddsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "5D" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmaddsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "5C" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmsubaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "5F" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmsubaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "5E" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "6D" ], "type": "vex_imm_rm_to_reg" },
+        "Vfmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "6C" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmaddpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "79" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmaddps": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "78" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmsubpd": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "7D" ], "type": "vex_imm_rm_to_reg" },
+        "Vfnmsubps": { "feature": "FMA4", "opcodes": [ "C4", "03", "85", "7C" ], "type": "vex_imm_rm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecReg256/VecMem256", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "Vfmaddsd": { "feature": "FMA4", "opcodes": [ "C4", "03", "01", "6B" ], "type": "vex_rm_imm_to_reg" },
@@ -2931,16 +3311,76 @@
     },
     {
       "encodings": {
-        "Vmovapd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "28" ] },
-        "Vmovaps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "28" ] }
+        "Vinsertf128": { "feature": "AVX", "opcodes": [ "C4", "03", "05", "18" ], "type": "vex_rm_to_reg" },
+        "Vinserti128": { "feature": "AVX2", "opcodes": [ "C4", "03", "05", "38" ], "type": "vex_rm_to_reg" }
       },
       "args": [
-        { "class": "XmmReg", "usage": "def" },
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecReg128/VecMem128", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vmaskmovpd": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "2F" ], "type": "vex_reg_to_rm" },
+        "Vmaskmovps": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "2E" ], "type": "vex_reg_to_rm" }
+      },
+      "args": [
+        { "class": "VecMem128", "usage": "def" },
+        { "class": "VecReg128", "usage": "use" },
+        { "class": "VecReg128", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vmaskmovpd": { "feature": "AVX", "opcodes": [ "C4", "02", "05", "2F" ], "type": "vex_reg_to_rm" },
+        "Vmaskmovps": { "feature": "AVX", "opcodes": [ "C4", "02", "05", "2E" ], "type": "vex_reg_to_rm" }
+      },
+      "args": [
+        { "class": "VecMem256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecReg256", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vmaskmovpd": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "2D" ] },
+        "Vmaskmovps": { "feature": "AVX", "opcodes": [ "C4", "02", "01", "2C" ] }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "def" },
+        { "class": "VecReg128", "usage": "use" },
         { "class": "VecMem128", "usage": "use" }
       ]
     },
     {
       "encodings": {
+        "Vmaskmovpd": { "feature": "AVX", "opcodes": [ "C4", "02", "05", "2D" ] },
+        "Vmaskmovps": { "feature": "AVX", "opcodes": [ "C4", "02", "05", "2C" ] }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecMem256", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vmovapd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "29" ] },
+        "Vmovaps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "29" ] },
+        "Vmovdqa": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "7F" ] },
+        "Vmovdqu": { "feature": "AVX", "opcodes": [ "C4", "01", "06", "7F" ] }
+      },
+      "args": [
+        { "class": "VecMem256", "usage": "def" },
+        { "class": "YmmReg", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vmovapd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "28" ] },
+        "Vmovaps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "28" ] },
         "Vmovdqa": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6F" ] },
         "Vmovdqu": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "6F" ] }
       },
@@ -2949,6 +3389,18 @@
         { "class": "VecMem128", "usage": "use" }
       ]
     },
+    {
+      "encodings": {
+        "Vmovapd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "28" ] },
+        "Vmovaps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "28" ] },
+        "Vmovdqa": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "6F" ] },
+        "Vmovdqu": { "feature": "AVX", "opcodes": [ "C4", "01", "06", "6F" ] }
+      },
+      "args": [
+        { "class": "YmmReg", "usage": "def" },
+        { "class": "VecMem256", "usage": "use" }
+      ]
+    },
     {
       "encodings": {
         "Vmovhlps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "12" ], "type": "vex_rm_to_reg" },
@@ -2973,6 +3425,42 @@
         { "class": "VecMem64", "usage": "use" }
       ]
     },
+    {
+      "encodings": {
+        "Vmovmskpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "50" ] },
+        "Vmovmskps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "50" ] }
+      },
+      "args": [
+        { "class": "GeneralReg32", "usage": "def" },
+        { "class": "YmmReg", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vpclmulqdq": { "feature": "CLMULAVX", "opcodes": [ "C4", "03", "01", "44" ], "type": "vex_rm_to_reg" },
+        "Vshufpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C6" ], "type": "vex_rm_to_reg" },
+        "Vshufps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C6" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "def" },
+        { "class": "VecReg128", "usage": "use" },
+        { "class": "VecReg128/VecMem128", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vpclmulqdq": { "feature": "VPCLMULQD", "opcodes": [ "C4", "03", "05", "44" ], "type": "vex_rm_to_reg" },
+        "Vshufpd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "C6" ], "type": "vex_rm_to_reg" },
+        "Vshufps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "C6" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecReg256/VecMem256", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
     {
       "encodings": {
         "Vpermil2pd": { "feature": "AVX", "opcodes": [ "C4", "03", "81", "49" ], "type": "vex_imm_rm_to_reg" },
@@ -2999,6 +3487,32 @@
         { "class": "Imm2" }
       ]
     },
+    {
+      "encodings": {
+        "Vpermil2pd": { "feature": "AVX", "opcodes": [ "C4", "03", "85", "49" ], "type": "vex_imm_rm_to_reg" },
+        "Vpermil2ps": { "feature": "AVX", "opcodes": [ "C4", "03", "85", "48" ], "type": "vex_imm_rm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecMem256", "usage": "use" },
+        { "class": "Imm2" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vpermil2pd": { "feature": "AVX", "opcodes": [ "C4", "03", "05", "49" ], "type": "vex_rm_imm_to_reg" },
+        "Vpermil2ps": { "feature": "AVX", "opcodes": [ "C4", "03", "05", "48" ], "type": "vex_rm_imm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "VecReg256/VecMem256", "usage": "use" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "Imm2" }
+      ]
+    },
     {
       "encodings": {
         "Vpinsrb": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "20" ], "type": "vex_rm_to_reg" },
@@ -3012,6 +3526,62 @@
         { "class": "Imm8" }
       ]
     },
+    {
+      "encodings": {
+        "Vpinsrb": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "20" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "use_def" },
+        { "class": "VecReg128", "usage": "use" },
+        { "class": "Mem8", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vpinsrd": { "feature": "AVX", "opcodes": [ "C4", "03", "01", "22" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "use_def" },
+        { "class": "VecReg128", "usage": "use" },
+        { "class": "Mem32", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vpinsrw": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C4" ], "type": "vex_rm_to_reg" }
+      },
+      "args": [
+        { "class": "VecReg128", "usage": "use_def" },
+        { "class": "VecReg128", "usage": "use" },
+        { "class": "Mem16", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vpmovmskb": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "D7" ] }
+      },
+      "args": [
+        { "class": "GeneralReg32", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" }
+      ]
+    },
+    {
+      "encodings": {
+        "Vpshufd": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "70" ] },
+        "Vpshufhw": { "feature": "AVX2", "opcodes": [ "C4", "01", "06", "70" ] },
+        "Vpshuflw": { "feature": "AVX2", "opcodes": [ "C4", "01", "07", "70" ] },
+        "Vroundpd": { "feature": "AVX", "opcodes": [ "C4", "03", "05", "09" ] },
+        "Vroundps": { "feature": "AVX", "opcodes": [ "C4", "03", "05", "08" ] }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256/VecMem256", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
     {
       "encodings": {
         "Vpslld": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "72", "6" ], "type": "rm_to_vex" },
@@ -3031,6 +3601,25 @@
         { "class": "Imm8" }
       ]
     },
+    {
+      "encodings": {
+        "Vpslld": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "72", "6" ], "type": "rm_to_vex" },
+        "Vpslldq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "73", "7" ], "type": "rm_to_vex" },
+        "Vpsllq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "73", "6" ], "type": "rm_to_vex" },
+        "Vpsllw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "71", "6" ], "type": "rm_to_vex" },
+        "Vpsrad": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "72", "4" ], "type": "rm_to_vex" },
+        "Vpsraw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "71", "4" ], "type": "rm_to_vex" },
+        "Vpsrld": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "72", "2" ], "type": "rm_to_vex" },
+        "Vpsrldq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "73", "3" ], "type": "rm_to_vex" },
+        "Vpsrlq": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "73", "2" ], "type": "rm_to_vex" },
+        "Vpsrlw": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "71", "2" ], "type": "rm_to_vex" }
+      },
+      "args": [
+        { "class": "VecReg256", "usage": "def" },
+        { "class": "VecReg256", "usage": "use" },
+        { "class": "Imm8" }
+      ]
+    },
     {
       "encodings": {
         "Vpslld": { "feature": "AVX2", "opcodes": [ "C4", "01", "05", "F2" ], "type": "vex_rm_to_reg" },
@@ -3072,14 +3661,11 @@
     },
     {
       "encodings": {
-        "Vshufpd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "C6" ], "type": "vex_rm_to_reg" },
-        "Vshufps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "C6" ], "type": "vex_rm_to_reg" }
+        "Vrsqrtps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "52" ] }
       },
       "args": [
-        { "class": "VecReg128", "usage": "def" },
-        { "class": "VecReg128", "usage": "use" },
-        { "class": "VecReg128/VecMem128", "usage": "use" },
-        { "class": "Imm8" }
+        { "class": "VecReg256", "usage": "use_def" },
+        { "class": "VecReg256/VecMem256", "usage": "use" }
       ]
     },
     {
diff --git a/assembler/instructions/insn_def_x86_32.json b/assembler/instructions/insn_def_x86_32.json
index e7efa194..7cac213c 100644
--- a/assembler/instructions/insn_def_x86_32.json
+++ b/assembler/instructions/insn_def_x86_32.json
@@ -18,10 +18,12 @@
   "insns": [
     {
       "encodings": {
-        "Calll": { "opcodes": [ "FF", "2" ] }
+        "Calll": { "opcodes": [ "FF", "2" ] },
+        "Popl": { "opcodes": [ "8F", "0" ] },
+        "Pushl": { "opcodes": [ "FF", "6" ] }
       },
       "args": [
-        { "class": "RSP", "usage": "use_def" },
+        { "class": "ESP", "usage": "use_def" },
         { "class": "Mem32", "usage": "use" }
       ]
     },
@@ -55,51 +57,55 @@
     },
     {
       "encodings": {
-        "Popl": { "opcodes": [ "8F", "0" ] }
+        "Vmovapd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "28" ] },
+        "Vmovaps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "28" ] },
+        "Vmovdqa": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6F" ] },
+        "Vmovdqu": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "6F" ] }
       },
       "args": [
-        { "class": "RSP", "usage": "use_def" },
-        { "class": "Mem32", "usage": "def" }
+        { "class": "XmmReg", "usage": "def" },
+        { "class": "XmmReg", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "Pushl": { "opcodes": [ "FF", "6" ] }
+        "Vmovapd": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "28" ] },
+        "Vmovaps": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "28" ] },
+        "Vmovdqa": { "feature": "AVX", "opcodes": [ "C4", "01", "05", "6F" ] },
+        "Vmovdqu": { "feature": "AVX", "opcodes": [ "C4", "01", "06", "6F" ] }
       },
       "args": [
-        { "class": "RSP", "usage": "use_def" },
-        { "class": "Mem32", "usage": "use" }
+        { "class": "YmmReg", "usage": "def" },
+        { "class": "YmmReg", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "Vmovapd": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "28" ] },
-        "Vmovaps": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "28" ] }
+        "Vmovsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "10" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "XmmReg", "usage": "def" },
-        { "class": "XmmReg", "usage": "use" }
+        { "class": "XmmReg", "usage": "use" },
+        { "class": "FpReg64", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "Vmovdqa": { "feature": "AVX", "opcodes": [ "C4", "01", "01", "6F" ] },
-        "Vmovdqu": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "6F" ] }
+        "Vmovss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "10" ], "type": "vex_rm_to_reg" }
       },
       "args": [
         { "class": "XmmReg", "usage": "def" },
-        { "class": "XmmReg", "usage": "use" }
+        { "class": "XmmReg", "usage": "use" },
+        { "class": "FpReg32", "usage": "use" }
       ]
     },
     {
       "encodings": {
-        "Vmovsd": { "feature": "AVX", "opcodes": [ "C4", "01", "03", "10" ], "type": "vex_rm_to_reg" },
-        "Vmovss": { "feature": "AVX", "opcodes": [ "C4", "01", "02", "10" ], "type": "vex_rm_to_reg" }
+        "Xlatb": { "opcode": "d7" }
       },
       "args": [
-        { "class": "XmmReg", "usage": "def" },
-        { "class": "XmmReg", "usage": "use" },
-        { "class": "XmmReg", "usage": "use" }
+        { "class": "AL", "usage": "use_def" },
+        { "class": "EBX", "usage": "use" }
       ]
     }
   ]
diff --git a/assembler/instructions/insn_def_x86_64.json b/assembler/instructions/insn_def_x86_64.json
index c77339f8..1fd41555 100644
--- a/assembler/instructions/insn_def_x86_64.json
+++ b/assembler/instructions/insn_def_x86_64.json
@@ -172,7 +172,7 @@
         "Bzhiq": { "feature": "BMI2", "opcodes": [ "C4", "02", "80", "F5" ] }
       },
       "args": [
-        { "class": "GeneralReg64", "usage": "use_def" },
+        { "class": "GeneralReg64", "usage": "def" },
         { "class": "GeneralReg64/Mem64", "usage": "use" },
         { "class": "GeneralReg64", "usage": "use" },
         { "class": "FLAGS", "usage": "def" }
@@ -217,7 +217,9 @@
     },
     {
       "encodings": {
-        "Callq": { "opcodes": [ "FF", "2" ] }
+        "Callq": { "opcodes": [ "FF", "2" ] },
+        "Popq": { "opcodes": [ "8F", "0" ] },
+        "Pushq": { "opcodes": [ "FF", "6" ] }
       },
       "args": [
         { "class": "RSP", "usage": "use_def" },
@@ -627,7 +629,7 @@
         "Vpextrq": { "feature": "AVX", "opcodes": [ "C4", "03", "81", "16" ], "type": "reg_to_rm" }
       },
       "args": [
-        { "class": "GeneralReg64", "usage": "def" },
+        { "class": "GeneralReg64/Mem64", "usage": "def" },
         { "class": "VecReg128", "usage": "use" },
         { "class": "Imm8" }
       ]
@@ -638,28 +640,10 @@
       },
       "args": [
         { "class": "VecReg128", "usage": "use_def" },
-        { "class": "GeneralReg64", "usage": "use" },
+        { "class": "GeneralReg64/Mem64", "usage": "use" },
         { "class": "Imm8" }
       ]
     },
-    {
-      "encodings": {
-        "Popq": { "opcodes": [ "8F", "0" ] }
-      },
-      "args": [
-        { "class": "RSP", "usage": "use_def" },
-        { "class": "VecMem64", "usage": "def" }
-      ]
-    },
-    {
-      "encodings": {
-        "Pushq": { "opcodes": [ "FF", "6" ] }
-      },
-      "args": [
-        { "class": "RSP", "usage": "use_def" },
-        { "class": "VecMem64", "usage": "use" }
-      ]
-    },
     {
       "encodings": {
         "RclqByCl": { "opcodes": [ "D3", "2" ] },
@@ -749,6 +733,14 @@
         { "class": "XmmReg", "usage": "use" }
       ]
     },
+    {
+      "stems": [ "Vmovapd", "Vmovaps", "Vmovdqa", "Vmovdqu" ],
+      "feature": "AVX",
+      "args": [
+        { "class": "YmmReg", "usage": "def" },
+        { "class": "YmmReg", "usage": "use" }
+      ]
+    },
     {
       "stems": [ "Vmovsd", "Vmovss" ],
       "args": [
@@ -764,10 +756,17 @@
       "args": [
         { "class": "VecReg128", "usage": "def" },
         { "class": "VecReg128", "usage": "use" },
-        { "class": "GeneralReg64", "usage": "use" },
+        { "class": "GeneralReg64/Mem64", "usage": "use" },
         { "class": "Imm8" }
       ]
     },
+    {
+      "encodings": {
+        "Vzeroupper": { "feature": "AVX", "opcodes": [ "C4", "01", "00", "77" ]},
+        "Vzeroall": { "feature": "AVX", "opcodes": [ "C4", "01", "04", "77" ]}
+      },
+      "args": []
+    },
     {
       "stems": [ "Xchgq" ],
       "args": [
@@ -783,6 +782,15 @@
         { "class": "GeneralReg64", "usage": "use_def" },
         { "class": "Mem64", "usage": "use_def" }
       ]
+    },
+    {
+      "encodings": {
+        "Xlatb": { "opcode": "d7" }
+      },
+      "args": [
+        { "class": "AL", "usage": "use_def" },
+        { "class": "RBX", "usage": "use" }
+      ]
     }
   ]
 }
diff --git a/assembler/machine_code.cc b/assembler/machine_code.cc
index 4c2bf97b..4b19975d 100644
--- a/assembler/machine_code.cc
+++ b/assembler/machine_code.cc
@@ -16,6 +16,7 @@
 
 #include "berberis/assembler/machine_code.h"
 
+#include <bit>
 #include <string>
 
 #include "berberis/base/bit_util.h"
@@ -71,7 +72,7 @@ void MachineCode::PerformRelocations(const uint8_t* code, RecoveryMap* recovery_
   for (const auto& rel : relocations_) {
     switch (rel.type) {
       case RelocationType::RelocAbsToDisp32: {
-        intptr_t start = reinterpret_cast<intptr_t>(code);
+        intptr_t start = std::bit_cast<intptr_t>(code);
         intptr_t pc = start + rel.pc;
         intptr_t disp = rel.data - pc;
         CHECK(IsInRange<int32_t>(disp));
diff --git a/backend/Android.bp b/backend/Android.bp
index 5481d720..8a0aef2a 100644
--- a/backend/Android.bp
+++ b/backend/Android.bp
@@ -180,6 +180,7 @@ filegroup {
         "x86_64/code.cc",
         "x86_64/code_debug.cc",
         "x86_64/code_emit.cc",
+        "x86_64/code_gen.cc",
         "x86_64/context_liveness_analyzer.cc",
         "x86_64/insn_folding.cc",
         "x86_64/liveness_analyzer.cc",
@@ -188,6 +189,7 @@ filegroup {
         "x86_64/machine_ir_analysis.cc",
         "x86_64/machine_ir_check.cc",
         "x86_64/machine_ir_opt.cc",
+        "x86_64/read_flags_optimizer.cc",
         "x86_64/rename_copy_uses.cc",
         "x86_64/rename_vregs.cc",
         "x86_64/rename_vregs_local.cc",
@@ -219,9 +221,6 @@ cc_library_static {
     header_libs: [
         "libberberis_backend_headers_riscv64_to_x86_64",
     ],
-    srcs: [
-        "riscv64_to_x86_64/code_gen.cc",
-    ],
 }
 
 cc_library_headers {
@@ -247,6 +246,7 @@ filegroup {
         "x86_64/machine_ir_opt_test.cc",
         "x86_64/machine_ir_test.cc",
         "x86_64/machine_ir_test_corpus.cc",
+        "x86_64/read_flags_optimizer_test.cc",
         "x86_64/rename_copy_uses_test.cc",
         "x86_64/rename_vregs_test.cc",
         "x86_64/rename_vregs_local_test.cc",
diff --git a/backend/gen_lir_lib.py b/backend/gen_lir_lib.py
index ca2c300c..5ff15032 100755
--- a/backend/gen_lir_lib.py
+++ b/backend/gen_lir_lib.py
@@ -60,6 +60,7 @@ import sys
 def _is_reg(arg_type):
   return (asm_defs.is_greg(arg_type) or
           asm_defs.is_xreg(arg_type) or
+          asm_defs.is_yreg(arg_type) or
           asm_defs.is_implicit_reg(arg_type))
 
 
@@ -89,6 +90,8 @@ def _make_reg_operand(r, usage, kind):
      op.asm_arg = 'GetGReg(RegAt(%d))' % (r)
    elif asm_defs.is_xreg(kind):
      op.asm_arg = 'GetXReg(RegAt(%d))' % (r)
+   elif asm_defs.is_yreg(kind):
+     op.asm_arg = 'GetYReg(RegAt(%d))' % (r)
    elif asm_defs.is_implicit_reg(kind):
      op.asm_arg = None
    else:
@@ -238,7 +241,7 @@ def _get_insn_debug_operands(insn):
   for arg in insn.get('args'):
     kind = arg.get('class')
     if _is_reg(kind):
-      if asm_defs.is_greg(kind) or asm_defs.is_xreg(kind):
+      if asm_defs.is_greg(kind) or asm_defs.is_xreg(kind) or asm_defs.is_yreg(kind):
         res.append('GetRegOperandDebugString(this, %d)' % (r))
       elif asm_defs.is_implicit_reg(kind):
         res.append('GetImplicitRegOperandDebugString(this, %d)' % (r))
diff --git a/backend/include/berberis/backend/common/machine_ir.h b/backend/include/berberis/backend/common/machine_ir.h
index 779ed4e9..b18d59c2 100644
--- a/backend/include/berberis/backend/common/machine_ir.h
+++ b/backend/include/berberis/backend/common/machine_ir.h
@@ -225,7 +225,9 @@ class MachineInsn {
 
   [[nodiscard]] bool has_side_effects() const {
     return (kind_ == kMachineInsnSideEffects) || recovery_info_.bb ||
-           (recovery_info_.pc != kNullGuestAddr);
+           (recovery_info_.pc != kNullGuestAddr) ||
+           // Instructions not touching registers are always only used for their other side effects.
+           NumRegOperands() == 0;
   }
 
   [[nodiscard]] bool is_copy() const { return kind_ == kMachineInsnCopy; }
@@ -251,6 +253,8 @@ class MachineInsn {
         kind_(kind),
         recovery_info_{nullptr, kNullGuestAddr} {}
 
+  void SetRegs(MachineReg* regs) { regs_ = regs; }
+
  private:
   // We either recover by building explicit recovery blocks or by storing recovery pc.
   // TODO(b/200327919): Convert this to union? We'll need to know which one is used during
@@ -591,6 +595,7 @@ class PseudoReadFlags : public MachineInsn {
   };
 
   PseudoReadFlags(WithOverflowEnum with_overflow, MachineReg dst, MachineReg flags);
+  PseudoReadFlags(const PseudoReadFlags& other);
 
   std::string GetDebugString() const override;
   void Emit(CodeEmitter* as) const override;
diff --git a/backend/include/berberis/backend/x86_64/code_emit.h b/backend/include/berberis/backend/x86_64/code_emit.h
index c5ad6a81..451322e0 100644
--- a/backend/include/berberis/backend/x86_64/code_emit.h
+++ b/backend/include/berberis/backend/x86_64/code_emit.h
@@ -28,6 +28,7 @@ namespace berberis::x86_64 {
 
 Assembler::Register GetGReg(MachineReg r);
 Assembler::XMMRegister GetXReg(MachineReg r);
+Assembler::YMMRegister GetYReg(MachineReg r);
 Assembler::ScaleFactor ToScaleFactor(MachineMemOperandScale scale);
 
 }  // namespace berberis::x86_64
diff --git a/backend/include/berberis/backend/x86_64/machine_insn_intrinsics.h b/backend/include/berberis/backend/x86_64/machine_insn_intrinsics.h
index bb100c64..bd2bcc72 100644
--- a/backend/include/berberis/backend/x86_64/machine_insn_intrinsics.h
+++ b/backend/include/berberis/backend/x86_64/machine_insn_intrinsics.h
@@ -132,7 +132,7 @@ class MachineInsn<AsmCallInfo, kMnemo, kOpcode, std::tuple<CtorArgs...>, Binding
       &MachineIRBuilder::template Gen<MachineInsn>;
 
   explicit MachineInsn(CtorArgs... args) : MachineInsnX86_64(&kInfo) {
-    ProcessArgs<0 /* reg_idx */, 0 /* mem_idx */, false /* is_disp */, Bindings...>(args...);
+    ProcessArgs<0 /* reg_idx */, 0 /* disp_idx */, Bindings...>(args...);
   }
 
   static constexpr MachineInsnInfo kInfo = GenMachineInsnInfoT<RegBindings>::value;
@@ -149,7 +149,7 @@ class MachineInsn<AsmCallInfo, kMnemo, kOpcode, std::tuple<CtorArgs...>, Binding
   void Emit(CodeEmitter* as) const override {
     std::apply(AsmCallInfo::kMacroInstruction,
                std::tuple_cat(std::tuple<CodeEmitter&>{*as},
-                              EmitArgs<0 /* reg_idx */, 0 /* mem_idx */, Bindings...>()));
+                              EmitArgs<0 /* reg_idx */, 0 /* disp_idx */, Bindings...>()));
   }
 
   int32_t disp2() const { return disp2_; }
@@ -158,44 +158,53 @@ class MachineInsn<AsmCallInfo, kMnemo, kOpcode, std::tuple<CtorArgs...>, Binding
  private:
   int32_t disp2_;
 
-  // TODO(b/260725458): Use inline template lambda instead after C++20 becomes available.
-  template <size_t, size_t, bool, typename...>
+  template <size_t, size_t, typename...>
   void ProcessArgs() {}
 
   template <size_t reg_idx,
-            size_t mem_idx,
-            bool is_disp,
+            size_t disp_idx,
             typename B,
             typename... BindingsRest,
             typename T,
             typename... Args>
-  void ProcessArgs(T arg, Args... args) {
-    if constexpr (ArgTraits<B>::Class::kIsImmediate) {
-      this->set_imm(arg);
-      ProcessArgs<reg_idx, mem_idx, false, BindingsRest..., Args...>(args...);
-    } else if constexpr (ArgTraits<B>::RegisterClass::kAsRegister == 'm' && !is_disp) {
-      // Only tmp memory args are supported.
-      static_assert(ArgTraits<B>::arg_info.arg_type == ArgInfo::TMP_ARG);
-      this->SetRegAt(reg_idx, arg);
-      // Note that mem is non incr'ed. We want to process the disp portion next. This is
-      // why `is_disp` is set to `true` here and we keep the binding `B`. This can't be done
-      // in a single pass because they're each a different `arg`.
-      ProcessArgs<reg_idx + 1, mem_idx, true, B, BindingsRest..., Args...>(args...);
-    } else if constexpr (ArgTraits<B>::RegisterClass::kAsRegister == 'm' && is_disp) {
-      static_assert(ArgTraits<B>::arg_info.arg_type == ArgInfo::TMP_ARG);
-      if constexpr (mem_idx == 0) {
-        this->set_disp(arg);
-      } else if constexpr (mem_idx == 1) {
-        this->set_disp2(arg);
-      }
-      // We finished processing the mem binding, reset is_disp and incr mem_idx.
-      ProcessArgs<reg_idx, mem_idx + 1, false, BindingsRest..., Args...>(args...);
-    } else if constexpr (std::is_same_v<MachineReg, T>) {
-      this->SetRegAt(reg_idx, arg);
-      ProcessArgs<reg_idx + 1, mem_idx, false, BindingsRest..., Args...>(args...);
+  auto ProcessArgs(T arg, Args... args) -> std::enable_if_t<ArgTraits<B>::Class::kIsImmediate> {
+    this->set_imm(arg);
+    ProcessArgs<reg_idx, disp_idx, BindingsRest...>(args...);
+  }
+
+  template <size_t reg_idx,
+            size_t disp_idx,
+            typename B,
+            typename... BindingsRest,
+            typename T,
+            typename... Args>
+  auto ProcessArgs(T arg, Args... args)
+      -> std::enable_if_t<ArgTraits<B>::RegisterClass::kAsRegister != 'm'> {
+    static_assert(std::is_same_v<MachineReg, T>);
+    this->SetRegAt(reg_idx, arg);
+    ProcessArgs<reg_idx + 1, disp_idx, BindingsRest...>(args...);
+  }
+
+  template <size_t reg_idx,
+            size_t disp_idx,
+            typename B,
+            typename... BindingsRest,
+            typename T1,
+            typename T2,
+            typename... Args>
+  auto ProcessArgs(T1 base, T2 disp, Args... args)
+      -> std::enable_if_t<ArgTraits<B>::RegisterClass::kAsRegister == 'm'> {
+    // Only tmp memory args are supported.
+    static_assert(ArgTraits<B>::arg_info.arg_type == ArgInfo::TMP_ARG);
+    this->SetRegAt(reg_idx, base);
+    if constexpr (disp_idx == 0) {
+      this->set_disp(disp);
+    } else if constexpr (disp_idx == 1) {
+      this->set_disp2(disp);
     } else {
-      static_assert(kDependentTypeFalse<T>);
+      static_assert(kDependentValueFalse<disp_idx>);
     }
+    ProcessArgs<reg_idx + 1, disp_idx + 1, BindingsRest...>(args...);
   }
 
   static constexpr auto GetInsnKind() {
@@ -230,7 +239,7 @@ class MachineInsn<AsmCallInfo, kMnemo, kOpcode, std::tuple<CtorArgs...>, Binding
   template <typename... Args>
   void ProcessDebugString(std::string* s) const {
     *s +=
-        " " + ProcessDebugStringArgs<0 /* arg_idx */, 0 /* reg_idx */, 0 /* mem_idx */, Args...>();
+        " " + ProcessDebugStringArgs<0 /* arg_idx */, 0 /* reg_idx */, 0 /* disp_idx */, Args...>();
     if (this->recovery_pc()) {
       *s += StringPrintf(" <0x%" PRIxPTR ">", this->recovery_pc());
     }
@@ -240,7 +249,7 @@ class MachineInsn<AsmCallInfo, kMnemo, kOpcode, std::tuple<CtorArgs...>, Binding
   template <>
   void ProcessDebugString<>(std::string*) const {}
 
-  template <size_t arg_idx, size_t reg_idx, size_t mem_idx, typename T, typename... Args>
+  template <size_t arg_idx, size_t reg_idx, size_t disp_idx, typename T, typename... Args>
   std::string ProcessDebugStringArgs() const {
     std::string prefix;
     if constexpr (arg_idx > 0) {
@@ -248,25 +257,25 @@ class MachineInsn<AsmCallInfo, kMnemo, kOpcode, std::tuple<CtorArgs...>, Binding
     }
     if constexpr (ArgTraits<T>::Class::kIsImmediate) {
       return prefix + GetImmOperandDebugString(this) +
-             ProcessDebugStringArgs<arg_idx + 1, reg_idx, mem_idx, Args...>();
+             ProcessDebugStringArgs<arg_idx + 1, reg_idx, disp_idx, Args...>();
     } else if constexpr (ArgTraits<T>::Class::kAsRegister == 'm') {
-      if constexpr (mem_idx == 0) {
+      if constexpr (disp_idx == 0) {
         return prefix + GetBaseDispMemOperandDebugString(this, reg_idx) +
-               ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, mem_idx + 1, Args...>();
-      } else if constexpr (mem_idx == 1) {
+               ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, disp_idx + 1, Args...>();
+      } else if constexpr (disp_idx == 1) {
         return prefix +
                StringPrintf(
                    "[%s + 0x%x]", GetRegOperandDebugString(this, reg_idx).c_str(), disp2()) +
-               ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, mem_idx + 1, Args...>();
+               ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, disp_idx + 1, Args...>();
       } else {
-        static_assert(kDependentValueFalse<mem_idx>);
+        static_assert(kDependentValueFalse<disp_idx>);
       }
     } else if constexpr (ArgTraits<T>::RegisterClass::kIsImplicitReg) {
       return prefix + GetImplicitRegOperandDebugString(this, reg_idx) +
-             ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, mem_idx, Args...>();
+             ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, disp_idx, Args...>();
     } else {
       return prefix + GetRegOperandDebugString(this, reg_idx) +
-             ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, mem_idx, Args...>();
+             ProcessDebugStringArgs<arg_idx + 1, reg_idx + 1, disp_idx, Args...>();
     }
   }
 
@@ -281,35 +290,35 @@ class MachineInsn<AsmCallInfo, kMnemo, kOpcode, std::tuple<CtorArgs...>, Binding
     return std::tuple{};
   }
 
-  template <size_t reg_idx, size_t mem_idx, typename T, typename... Args>
+  template <size_t reg_idx, size_t disp_idx, typename T, typename... Args>
   auto EmitArgs() const {
     if constexpr (ArgTraits<T>::Class::kIsImmediate) {
       return std::tuple_cat(
           std::tuple{static_cast<constructor_one_arg_t<T>>(MachineInsnX86_64::imm())},
-          EmitArgs<reg_idx, mem_idx, Args...>());
+          EmitArgs<reg_idx, disp_idx, Args...>());
     } else if constexpr (ArgTraits<T>::RegisterClass::kAsRegister == 'x') {
       return std::tuple_cat(std::tuple{GetXReg(this->RegAt(reg_idx))},
-                            EmitArgs<reg_idx + 1, mem_idx, Args...>());
+                            EmitArgs<reg_idx + 1, disp_idx, Args...>());
     } else if constexpr (ArgTraits<T>::RegisterClass::kAsRegister == 'r' ||
                          ArgTraits<T>::RegisterClass::kAsRegister == 'q') {
       return std::tuple_cat(std::tuple{GetGReg(this->RegAt(reg_idx))},
-                            EmitArgs<reg_idx + 1, mem_idx, Args...>());
+                            EmitArgs<reg_idx + 1, disp_idx, Args...>());
     } else if constexpr (ArgTraits<T>::RegisterClass::kAsRegister == 'm' &&
                          std::is_same_v<typename ArgTraits<T>::Usage,
                                         intrinsics::bindings::DefEarlyClobber>) {
-      if constexpr (mem_idx == 0) {
+      if constexpr (disp_idx == 0) {
         return std::tuple_cat(std::tuple{Assembler::Operand{.base = GetGReg(this->RegAt(reg_idx)),
                                                             .disp = static_cast<int32_t>(disp())}},
-                              EmitArgs<reg_idx + 1, mem_idx + 1, Args...>());
-      } else if constexpr (mem_idx == 1) {
+                              EmitArgs<reg_idx + 1, disp_idx + 1, Args...>());
+      } else if constexpr (disp_idx == 1) {
         return std::tuple_cat(std::tuple{Assembler::Operand{.base = GetGReg(this->RegAt(reg_idx)),
                                                             .disp = static_cast<int32_t>(disp2())}},
-                              EmitArgs<reg_idx + 1, mem_idx + 1, Args...>());
+                              EmitArgs<reg_idx + 1, disp_idx + 1, Args...>());
       } else {
         static_assert(kDependentTypeFalse<T>);
       }
     } else if constexpr (ArgTraits<T>::RegisterClass::kIsImplicitReg) {
-      return EmitArgs<reg_idx, mem_idx, Args...>();
+      return EmitArgs<reg_idx, disp_idx, Args...>();
     } else {
       static_assert(kDependentTypeFalse<T>);
     }
diff --git a/backend/include/berberis/backend/x86_64/machine_ir.h b/backend/include/berberis/backend/x86_64/machine_ir.h
index 3cc44cf4..ca31588d 100644
--- a/backend/include/berberis/backend/x86_64/machine_ir.h
+++ b/backend/include/berberis/backend/x86_64/machine_ir.h
@@ -123,6 +123,9 @@ class MachineInsnX86_64 : public MachineInsn {
   static constexpr const auto kEAX = x86_64::kEAX;
   static constexpr const auto kRAX = x86_64::kRAX;
   static constexpr const auto kAL = x86_64::kAL;
+  static constexpr const auto kAX = x86_64::kAX;
+  static constexpr const auto kEBX = x86_64::kEBX;
+  static constexpr const auto kRBX = x86_64::kRBX;
   static constexpr const auto kCL = x86_64::kCL;
   static constexpr const auto kECX = x86_64::kECX;
   static constexpr const auto kRCX = x86_64::kRCX;
@@ -138,6 +141,18 @@ class MachineInsnX86_64 : public MachineInsn {
   static constexpr const auto kXmmReg = x86_64::kXmmReg;
   static constexpr const auto kFLAGS = x86_64::kFLAGS;
 
+  MachineInsnX86_64(const MachineInsnX86_64& other) : MachineInsn(other) {
+    for (int i = 0; i < kMaxMachineRegOperands; i++) {
+      regs_[i] = other.regs_[i];
+    }
+    scale_ = other.scale_;
+    disp_ = other.disp_;
+    imm_ = other.imm_;
+    cond_ = other.cond_;
+
+    SetRegs(regs_);
+  }
+
   ~MachineInsnX86_64() override {
     // No code here - will never be called!
   }
@@ -243,7 +258,6 @@ class CallImm : public MachineInsnX86_64 {
     RegType reg_type;
   };
 
- public:
   explicit CallImm(uint64_t imm);
 
   [[nodiscard]] static int GetIntArgIndex(int i);
@@ -255,6 +269,10 @@ class CallImm : public MachineInsnX86_64 {
 
   [[nodiscard]] std::string GetDebugString() const override;
   void Emit(CodeEmitter* as) const override;
+  void EnableCustomAVX256ABI() { custom_avx256_abi_ = true; };
+
+ private:
+  bool custom_avx256_abi_;
 };
 
 // An auxiliary instruction to express data-flow for CallImm arguments.  It uses the same vreg as
diff --git a/backend/include/berberis/backend/x86_64/read_flags_optimizer.h b/backend/include/berberis/backend/x86_64/read_flags_optimizer.h
new file mode 100644
index 00000000..c43f67bf
--- /dev/null
+++ b/backend/include/berberis/backend/x86_64/read_flags_optimizer.h
@@ -0,0 +1,41 @@
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
+#ifndef BERBERIS_BACKEND_X86_64_READ_FLAGS_OPTIMIZER_H_
+#define BERBERIS_BACKEND_X86_64_READ_FLAGS_OPTIMIZER_H_
+
+#include "berberis/backend/common/machine_ir.h"
+#include "berberis/backend/x86_64/machine_ir.h"
+#include "berberis/backend/x86_64/machine_ir_analysis.h"
+#include "berberis/base/arena_vector.h"
+
+namespace berberis::x86_64 {
+
+using InsnGenerator = MachineInsn* (*)(MachineIR*, MachineInsn*);
+
+bool CheckRegsUnusedWithinInsnRange(MachineInsnList::iterator insn_it,
+                                    MachineInsnList::iterator end,
+                                    ArenaVector<MachineReg>& regs);
+bool CheckPostLoopNode(MachineBasicBlock* block, const ArenaVector<MachineReg>& regs);
+bool CheckSuccessorNode(Loop* loop, MachineBasicBlock* block, ArenaVector<MachineReg>& regs);
+std::optional<InsnGenerator> GetInsnGen(MachineOpcode opcode);
+bool RegsLiveInBasicBlock(MachineBasicBlock* bb, const ArenaVector<MachineReg>& regs);
+std::optional<MachineInsnList::iterator> FindFlagSettingInsn(MachineInsnList::iterator insn_it,
+                                                             MachineInsnList::iterator begin,
+                                                             MachineReg reg);
+}  // namespace berberis::x86_64
+
+#endif  // BERBERIS_BACKEND_X86_64_READ_FLAGS_OPTIMIZER_H_
diff --git a/backend/x86_64/code.cc b/backend/x86_64/code.cc
index 74c1e208..6489dcd2 100644
--- a/backend/x86_64/code.cc
+++ b/backend/x86_64/code.cc
@@ -14,6 +14,8 @@
  * limitations under the License.
  */
 
+#include <array>
+
 #include "berberis/backend/x86_64/machine_ir.h"
 #include "berberis/base/logging.h"
 #include "berberis/guest_state/guest_addr.h"
@@ -81,7 +83,7 @@ constexpr MachineRegKind kPseudoWriteFlagsInfo[] = {{&kRAX, MachineRegKind::kUse
 
 }  // namespace
 
-CallImm::CallImm(uint64_t imm) : MachineInsnX86_64(&kCallImmInfo) {
+CallImm::CallImm(uint64_t imm) : MachineInsnX86_64(&kCallImmInfo), custom_avx256_abi_{false} {
   set_imm(imm);
 }
 
@@ -225,6 +227,15 @@ PseudoReadFlags::PseudoReadFlags(WithOverflowEnum with_overflow, MachineReg dst,
       regs_{dst, flags},
       with_overflow_(with_overflow == kWithOverflow) {}
 
+PseudoReadFlags::PseudoReadFlags(const PseudoReadFlags& other) : MachineInsn(other) {
+  with_overflow_ = other.with_overflow_;
+  for (size_t i = 0; i < std::size(regs_); i++) {
+    regs_[i] = other.regs_[i];
+  }
+
+  SetRegs(regs_);
+}
+
 const MachineOpcode PseudoWriteFlags::kOpcode = kMachineOpPseudoWriteFlags;
 
 PseudoWriteFlags::PseudoWriteFlags(MachineReg src, MachineReg flags)
diff --git a/backend/x86_64/code_emit.cc b/backend/x86_64/code_emit.cc
index 476554bf..cb093af2 100644
--- a/backend/x86_64/code_emit.cc
+++ b/backend/x86_64/code_emit.cc
@@ -206,6 +206,10 @@ Assembler::XMMRegister GetXReg(MachineReg r) {
   return kHardRegs[r.reg() - kMachineRegXMM0.reg()];
 }
 
+Assembler::YMMRegister GetYReg(MachineReg r) {
+  return GetXReg(r).To256Bit();
+}
+
 Assembler::ScaleFactor ToScaleFactor(MachineMemOperandScale scale) {
   switch (scale) {
     case MachineMemOperandScale::kOne:
@@ -221,6 +225,15 @@ Assembler::ScaleFactor ToScaleFactor(MachineMemOperandScale scale) {
 
 void CallImm::Emit(CodeEmitter* as) const {
   as->Call(AsHostCode(imm()));
+  if (custom_avx256_abi_) {
+    // We don't support 256bit registers in IR. So we hide this YMM0 inside CallImm
+    // and forward the result to IR in (XMM0, XMM1). See go/ndkt-avx-runtime.
+    as->Vextractf128(as->xmm1, as->ymm0, uint8_t{1});
+  }
+#ifdef __AVX__
+  // Clean-up potentially dirty upper bits after executing AVX256 instructions in runtime.
+  as->Vzeroupper();
+#endif
 }
 
 }  // namespace x86_64
diff --git a/backend/riscv64_to_x86_64/code_gen.cc b/backend/x86_64/code_gen.cc
similarity index 90%
rename from backend/riscv64_to_x86_64/code_gen.cc
rename to backend/x86_64/code_gen.cc
index 6ae1afd4..0f18339a 100644
--- a/backend/riscv64_to_x86_64/code_gen.cc
+++ b/backend/x86_64/code_gen.cc
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2023 The Android Open Source Project
+ * Copyright (C) 2021 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -28,15 +28,15 @@
 #include "berberis/backend/x86_64/machine_ir_opt.h"
 #include "berberis/backend/x86_64/rename_copy_uses.h"
 #include "berberis/backend/x86_64/rename_vregs.h"
+#include "berberis/base/checks.h"
 #include "berberis/base/config_globals.h"
-#include "berberis/base/logging.h"
 #include "berberis/base/tracing.h"
 
 namespace berberis::x86_64 {
 
 void GenCode(MachineIR* machine_ir, MachineCode* machine_code, const GenCodeParams& params) {
   CHECK_EQ(CheckMachineIR(*machine_ir), kMachineIRCheckSuccess);
-  if (IsConfigFlagSet(kVerboseTranslation)) {
+  if (IsConfigFlagSet(kVerboseTranslation) || IsConfigFlagSet(kPrintIRs)) {
     TRACE("MachineIR before optimizations {\n");
     TRACE("%s", machine_ir->GetDebugString().c_str());
     TRACE("}\n\n");
@@ -44,7 +44,6 @@ void GenCode(MachineIR* machine_ir, MachineCode* machine_code, const GenCodePara
 
   RemoveCriticalEdges(machine_ir);
 
-  ReorderBasicBlocksInReversePostOrder(machine_ir);
   MoveColdBlocksToEnd(machine_ir);
 
   RemoveLoopGuestContextAccesses(machine_ir);
@@ -57,6 +56,8 @@ void GenCode(MachineIR* machine_ir, MachineCode* machine_code, const GenCodePara
   RenameCopyUses(machine_ir);
   RemoveDeadCode(machine_ir);
 
+  FoldWriteFlags(machine_ir);
+
   AllocRegs(machine_ir);
 
   RemoveNopPseudoCopy(machine_ir);
@@ -64,7 +65,7 @@ void GenCode(MachineIR* machine_ir, MachineCode* machine_code, const GenCodePara
 
   CHECK_EQ(CheckMachineIR(*machine_ir), kMachineIRCheckSuccess);
 
-  if (IsConfigFlagSet(kVerboseTranslation)) {
+  if (IsConfigFlagSet(kVerboseTranslation) || IsConfigFlagSet(kPrintIRs)) {
     TRACE("MachineIR before emit {\n");
     TRACE("%s", machine_ir->GetDebugString().c_str());
     TRACE("}\n\n");
diff --git a/backend/x86_64/lir_instructions.json b/backend/x86_64/lir_instructions.json
index 5ac7f33b..713c0642 100644
--- a/backend/x86_64/lir_instructions.json
+++ b/backend/x86_64/lir_instructions.json
@@ -215,6 +215,7 @@
         "VmovapsXRegXReg",
         "VmovsdXRegXRegXReg",
         "VmovssXRegXRegXReg",
+        "Vzeroupper",
         "XchgbRegMemInsns",
         "XchgwRegMemInsns",
         "XchglRegMemInsns",
diff --git a/backend/x86_64/read_flags_optimizer.cc b/backend/x86_64/read_flags_optimizer.cc
new file mode 100644
index 00000000..9196c105
--- /dev/null
+++ b/backend/x86_64/read_flags_optimizer.cc
@@ -0,0 +1,184 @@
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
+#include "berberis/backend/x86_64/read_flags_optimizer.h"
+
+#include <optional>
+
+#include "berberis/backend/common/machine_ir.h"
+#include "berberis/backend/x86_64/machine_ir.h"
+#include "berberis/base/algorithm.h"
+#include "berberis/base/arena_vector.h"
+
+namespace berberis::x86_64 {
+
+// Reads range of instructions to see if any of the registers in regs is used.
+// Will also insert new registers into regs if we encounter PSEUDO_COPY.
+// Returns true iff we reach the end without encountering any uses of regs.
+bool CheckRegsUnusedWithinInsnRange(MachineInsnList::iterator insn_it,
+                                    MachineInsnList::iterator end,
+                                    ArenaVector<MachineReg>& regs) {
+  for (; insn_it != end; ++insn_it) {
+    for (auto i = 0; i < (*insn_it)->NumRegOperands(); i++) {
+      if (Contains(regs, (*insn_it)->RegAt(i))) {
+        if (AsMachineInsnX86_64(*insn_it)->opcode() != kMachineOpPseudoCopy || i != 1) {
+          return false;
+        }
+        regs.push_back((*insn_it)->RegAt(0));
+      }
+    }
+  }
+  return true;
+}
+
+// Checks if a successor node meets requirements for read flags optimization
+// Requirements:
+// * must be exit node or not use registers
+// * only one in_edge - guarantees register comes from the readflags node
+// * any registers from regs can only be live_in to the post loop nodes
+// * nothing from regs used in node
+// * Postloop node connected to this node must meet same post loop node as
+//   original node with readflags instruction
+//
+// Returns true iff this node doesn't stop us from using the optimization.
+bool CheckSuccessorNode(Loop* loop, MachineBasicBlock* bb, ArenaVector<MachineReg>& regs) {
+  // If the node doesn't actually use any of regs we can just skip it.
+  if (!RegsLiveInBasicBlock(bb, regs)) {
+    return true;
+  }
+
+  // To simplify things we only allow one in_edge.
+  if (bb->in_edges().size() != 1) {
+    return false;
+  }
+
+  MachineEdge* postloop_edge;
+  MachineEdge* loop_edge;
+  // Nodes have at most 2 out_edges so if this is a successor node there can be
+  // at most one postloop edge.
+  for (auto edge : bb->out_edges()) {
+    if (Contains(*loop, edge->dst())) {
+      loop_edge = edge;
+    } else {
+      // There should only be one exit edge.
+      CHECK_EQ(postloop_edge, nullptr);
+      postloop_edge = edge;
+    }
+  }
+  // Check if exit node.
+  if (postloop_edge == nullptr) {
+    return false;
+  }
+  CHECK(loop_edge);
+
+  // Check regs not used in node. Note this can add additional elements into regs.
+  if (!CheckRegsUnusedWithinInsnRange(bb->insn_list().begin(), bb->insn_list().end(), regs)) {
+    return false;
+  }
+  // Check if regs found in live_in of other loop nodes.
+  // Must be done after CheckRegsUnusedWithinInsnRange in case we added new registers to regs.
+  if (RegsLiveInBasicBlock(loop_edge->dst(), regs)) {
+    return false;
+  }
+  // Check post loop nodes.
+  return CheckPostLoopNode(postloop_edge->dst(), regs);
+}
+
+// Checks if this post loop node meets requirements for the read flags
+// optimization.
+// Requirements:
+// * the node must have only one in_edge - this guarantees the register is coming
+// from the readflags
+// * nothing in regs should be in live_out
+bool CheckPostLoopNode(MachineBasicBlock* bb, const ArenaVector<MachineReg>& regs) {
+  // If the node doesn't actually use any of regs we can just skip it.
+  if (!RegsLiveInBasicBlock(bb, regs)) {
+    return true;
+  }
+
+  // Check that there's only one in_edge.
+  if (bb->in_edges().size() != 1) {
+    return false;
+  }
+  // Check that it's not live_out.
+  for (auto r : bb->live_out()) {
+    if (Contains(regs, r)) {
+      return false;
+    }
+  }
+  return true;
+}
+
+// Checks if anything in regs is in bb->live_in().
+bool RegsLiveInBasicBlock(MachineBasicBlock* bb, const ArenaVector<MachineReg>& regs) {
+  for (auto r : bb->live_in()) {
+    if (Contains(regs, r)) {
+      return true;
+    }
+  }
+  return false;
+}
+
+template <typename T>
+MachineInsn* CopyInstruction(MachineIR* machine_ir, MachineInsn* insn) {
+  return machine_ir->NewInsn<T>(*static_cast<T*>(insn));
+}
+
+std::optional<InsnGenerator> GetInsnGen(MachineOpcode opcode) {
+  switch (opcode) {
+    case kMachineOpAddqRegReg:
+      return CopyInstruction<AddqRegReg>;
+    case kMachineOpPseudoReadFlags:
+      return CopyInstruction<PseudoReadFlags>;
+    case kMachineOpCmplRegImm:
+      return CopyInstruction<CmplRegImm>;
+    case kMachineOpCmplRegReg:
+      return CopyInstruction<CmpqRegReg>;
+    case kMachineOpCmpqRegImm:
+      return CopyInstruction<CmpqRegImm>;
+    case kMachineOpCmpqRegReg:
+      return CopyInstruction<CmpqRegReg>;
+    case kMachineOpSublRegImm:
+      return CopyInstruction<SublRegImm>;
+    case kMachineOpSublRegReg:
+      return CopyInstruction<SublRegReg>;
+    case kMachineOpSubqRegImm:
+      return CopyInstruction<SubqRegImm>;
+    case kMachineOpSubqRegReg:
+      return CopyInstruction<SubqRegReg>;
+    default:
+      return std::nullopt;
+  }
+}
+
+// Finds the instruction which sets a flag register.
+// insn_it should point to one past the element we first want to check
+// (typically it should point to the readflags instruction).
+std::optional<MachineInsnList::iterator> FindFlagSettingInsn(MachineInsnList::iterator insn_it,
+                                                             MachineInsnList::iterator begin,
+                                                             MachineReg reg) {
+  while (insn_it != begin) {
+    insn_it--;
+    for (int i = 0; i < (*insn_it)->NumRegOperands(); i++) {
+      if ((*insn_it)->RegAt(i) == reg && (*insn_it)->RegKindAt(i).IsDef()) {
+        return insn_it;
+      }
+    }
+  }
+  return std::nullopt;
+}
+
+}  // namespace berberis::x86_64
diff --git a/backend/x86_64/read_flags_optimizer_test.cc b/backend/x86_64/read_flags_optimizer_test.cc
new file mode 100644
index 00000000..2b56e5ac
--- /dev/null
+++ b/backend/x86_64/read_flags_optimizer_test.cc
@@ -0,0 +1,384 @@
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
+#include <tuple>
+
+#include "berberis/backend/x86_64/read_flags_optimizer.h"
+
+#include "berberis/backend/common/machine_ir.h"
+#include "berberis/backend/x86_64/machine_ir_analysis.h"
+#include "berberis/backend/x86_64/machine_ir_builder.h"
+#include "berberis/backend/x86_64/machine_ir_check.h"
+#include "berberis/base/arena_alloc.h"
+#include "berberis/base/arena_vector.h"
+
+namespace berberis::x86_64 {
+
+namespace {
+
+std::tuple<MachineBasicBlock*, MachineBasicBlock*, MachineBasicBlock*, MachineBasicBlock*>
+BuildBasicLoop(MachineIR* machine_ir) {
+  x86_64::MachineIRBuilder builder(machine_ir);
+
+  auto bb0 = machine_ir->NewBasicBlock();
+  auto bb1 = machine_ir->NewBasicBlock();
+  auto bb2 = machine_ir->NewBasicBlock();
+  auto bb3 = machine_ir->NewBasicBlock();
+  machine_ir->AddEdge(bb0, bb1);
+  machine_ir->AddEdge(bb1, bb2);
+  machine_ir->AddEdge(bb2, bb1);
+  machine_ir->AddEdge(bb2, bb3);
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<PseudoBranch>(bb1);
+  builder.StartBasicBlock(bb1);
+  builder.Gen<PseudoBranch>(bb2);
+
+  builder.StartBasicBlock(bb2);
+  builder.Gen<PseudoCondBranch>(CodeEmitter::Condition::kZero, bb1, bb3, kMachineRegFLAGS);
+
+  builder.StartBasicBlock(bb3);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  return {bb0, bb1, bb2, bb3};
+}
+
+TEST(MachineIRReadFlagsOptimizer, CheckRegsUnusedWithinInsnRangeAddsReg) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags1 = machine_ir.AllocVReg();
+  ArenaVector<MachineReg> regs({flags0}, machine_ir.arena());
+
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<PseudoReadFlags>(PseudoReadFlags::kWithOverflow, flags0, kMachineRegFLAGS);
+  builder.Gen<PseudoCopy>(flags1, flags0, 8);
+  builder.Gen<PseudoWriteFlags>(flags1, kMachineRegFLAGS);
+  builder.Gen<PseudoBranch>(bb1);
+
+  builder.StartBasicBlock(bb1);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  auto insn_it = bb0->insn_list().begin();
+  // Skip the pseudoreadflags instruction.
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+  insn_it++;
+  ASSERT_FALSE(CheckRegsUnusedWithinInsnRange(insn_it, bb0->insn_list().end(), regs));
+  ASSERT_TRUE(
+      CheckRegsUnusedWithinInsnRange(bb1->insn_list().begin(), bb1->insn_list().end(), regs));
+  ASSERT_EQ(regs.size(), 2UL);
+}
+
+TEST(MachineIRReadFlagsOptimizer, CheckRegsUnusedWithinInsnRange) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags1 = machine_ir.AllocVReg();
+  ArenaVector<MachineReg> regs0({flags0}, machine_ir.arena());
+  ArenaVector<MachineReg> regs1({flags1}, machine_ir.arena());
+
+  auto bb0 = machine_ir.NewBasicBlock();
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<MovqRegImm>(flags0, 123);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+  auto insn_it = bb0->insn_list().begin();
+  ASSERT_FALSE(CheckRegsUnusedWithinInsnRange(insn_it, bb0->insn_list().end(), regs0));
+  ASSERT_TRUE(CheckRegsUnusedWithinInsnRange(insn_it, bb0->insn_list().end(), regs1));
+  ASSERT_EQ(regs0.size(), 1UL);
+}
+
+TEST(MachineIRReadFlagsOptimizer, CheckPostLoopNodeLifetime) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags = machine_ir.AllocVReg();
+  MachineReg flags_copy = machine_ir.AllocVReg();
+  ArenaVector<MachineReg> regs({flags, flags_copy}, machine_ir.arena());
+
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<PseudoReadFlags>(PseudoReadFlags::kWithOverflow, flags, kMachineRegFLAGS);
+  builder.Gen<PseudoCopy>(flags_copy, flags, 8);
+  builder.Gen<PseudoBranch>(bb1);
+
+  builder.StartBasicBlock(bb1);
+  builder.Gen<x86_64::AddqRegReg>(flags_copy, flags_copy, kMachineRegFLAGS);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  bb1->live_in().push_back(flags_copy);
+  ASSERT_TRUE(CheckPostLoopNode(bb1, regs));
+
+  // Should fail because flags_copy shouldln't outlive bb1.
+  bb1->live_out().push_back(flags_copy);
+  ASSERT_FALSE(CheckPostLoopNode(bb1, regs));
+}
+
+// CheckPostLoopNode should pass if no livein.
+TEST(MachineIRReadFlagsOptimizer, CheckPostLoopNodeLiveIn) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags = machine_ir.AllocVReg();
+  ArenaVector<MachineReg> regs({flags}, machine_ir.arena());
+
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  auto bb2 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+  machine_ir.AddEdge(bb1, bb2);
+  machine_ir.AddEdge(bb2, bb1);
+
+  // This should pass even though in_edges > 1 because it has no live_in.
+  ASSERT_TRUE(CheckPostLoopNode(bb1, regs));
+
+  // Just to keep us honest that it fails.
+  bb1->live_in().push_back(flags);
+  ASSERT_FALSE(CheckPostLoopNode(bb1, regs));
+}
+
+// Test that CheckPostLoopNode fails when node has more than one in_edge.
+TEST(MachineIRReadFlagsOptimizer, CheckPostLoopNodeInEdges) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags = machine_ir.AllocVReg();
+  ArenaVector<MachineReg> regs({flags}, machine_ir.arena());
+
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  auto bb2 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+  machine_ir.AddEdge(bb1, bb2);
+
+  bb1->live_in().push_back(flags);
+  ASSERT_TRUE(CheckPostLoopNode(bb1, regs));
+  machine_ir.AddEdge(bb2, bb1);
+  ASSERT_FALSE(CheckPostLoopNode(bb1, regs));
+}
+
+// Test that CheckSuccessorNode fails if we are using register in regs.
+TEST(MachineIRReadFlagsOptimizer, CheckSuccessorNodeFailsIfUsingRegisters) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags = machine_ir.AllocVReg();
+  ArenaVector<MachineReg> regs({flags}, machine_ir.arena());
+
+  auto [preloop, loop_head, loop_exit, postloop] = BuildBasicLoop(&machine_ir);
+  loop_exit->live_in().push_back(flags);
+  loop_exit->insn_list().insert(loop_exit->insn_list().begin(),
+                                machine_ir.NewInsn<MovqRegImm>(flags, 123));
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  auto loop_tree = BuildLoopTree(&machine_ir);
+  auto loop = loop_tree.root()->GetInnerloopNode(0)->loop();
+  ASSERT_FALSE(CheckSuccessorNode(loop, loop_exit, regs));
+}
+
+TEST(MachineIRReadFlagsOptimizer, CheckSuccessorNodeFailsIfNotExit) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags = machine_ir.AllocVReg();
+  ArenaVector<MachineReg> regs({flags}, machine_ir.arena());
+
+  auto bb0 = machine_ir.NewBasicBlock();
+  auto bb1 = machine_ir.NewBasicBlock();
+  auto bb2 = machine_ir.NewBasicBlock();
+  machine_ir.AddEdge(bb0, bb1);
+  machine_ir.AddEdge(bb1, bb2);
+  machine_ir.AddEdge(bb2, bb1);
+  bb2->live_in().push_back(flags);
+
+  builder.StartBasicBlock(bb0);
+  builder.Gen<PseudoBranch>(bb1);
+  builder.StartBasicBlock(bb1);
+  builder.Gen<PseudoBranch>(bb2);
+  builder.StartBasicBlock(bb2);
+  builder.Gen<PseudoBranch>(bb1);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  auto loop_tree = BuildLoopTree(&machine_ir);
+  auto loop = loop_tree.root()->GetInnerloopNode(0)->loop();
+  // Should fail because not an exit node.
+  ASSERT_FALSE(CheckSuccessorNode(loop, bb2, regs));
+}
+
+// Check that we test for only one in_edge.
+TEST(MachineIRReadFlagsOptimizer, CheckSuccessorNodeInEdges) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags = machine_ir.AllocVReg();
+  ArenaVector<MachineReg> regs({flags}, machine_ir.arena());
+
+  auto [preloop, loop_head, loop_exit, postloop] = BuildBasicLoop(&machine_ir);
+
+  auto loop_tree = BuildLoopTree(&machine_ir);
+  auto loop = loop_tree.root()->GetInnerloopNode(0)->loop();
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  loop_exit->live_in().push_back(flags);
+  ASSERT_TRUE(CheckSuccessorNode(loop, loop_exit, regs));
+  machine_ir.AddEdge(preloop, loop_exit);
+  ASSERT_FALSE(CheckSuccessorNode(loop, loop_exit, regs));
+}
+
+// regs should not be live_in to other loop nodes.
+TEST(MachineIRReadFlagsOptimizer, CheckSuccessorNodeLiveIn) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags1 = machine_ir.AllocVReg();
+  ArenaVector<MachineReg> regs({flags0}, machine_ir.arena());
+
+  auto [preloop, loop_head, loop_exit, postloop] = BuildBasicLoop(&machine_ir);
+
+  loop_exit->live_in().push_back(flags0);
+
+  loop_exit->insn_list().insert(loop_exit->insn_list().begin(),
+                                machine_ir.NewInsn<PseudoCopy>(flags1, flags0, 8));
+
+  postloop->live_in().push_back(flags1);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  auto loop_tree = BuildLoopTree(&machine_ir);
+  auto loop = loop_tree.root()->GetInnerloopNode(0)->loop();
+
+  ASSERT_TRUE(CheckSuccessorNode(loop, loop_exit, regs));
+  // Remove flags1.
+  regs.pop_back();
+
+  // Make sure we fail if flags0 is live_in of another loop node.
+  loop_head->live_in().push_back(flags0);
+  ASSERT_FALSE(CheckSuccessorNode(loop, loop_exit, regs));
+
+  // Reset state.
+  loop_head->live_in().pop_back();
+  regs.pop_back();
+
+  // Make sure that we check live_in after CheckRegsUnusedWithinInsnRange.
+  loop_head->live_in().push_back(flags1);
+  ASSERT_FALSE(CheckSuccessorNode(loop, loop_exit, regs));
+}
+
+// Helper function to check that two instructions are the same.
+void TestCopiedInstruction(MachineIR* machine_ir, MachineInsn* insn) {
+  MachineReg reg = machine_ir->AllocVReg();
+
+  auto gen = GetInsnGen(insn->opcode());
+  ASSERT_TRUE(gen.has_value());
+  auto* copy = gen.value()(machine_ir, insn);
+
+  ASSERT_EQ(copy->opcode(), insn->opcode());
+  ASSERT_EQ(copy->NumRegOperands(), insn->NumRegOperands());
+  for (auto i = 0; i < insn->NumRegOperands(); i++) {
+    ASSERT_EQ(copy->RegAt(i), insn->RegAt(i));
+  }
+
+  // Check that it's a deep copy.
+  copy->SetRegAt(0, reg);
+  ASSERT_NE(copy->RegAt(0), insn->RegAt(0));
+  ASSERT_EQ(copy->RegAt(0), reg);
+}
+
+TEST(MachineIRReadFlagsOptimizer, GetInsnGen) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  TestCopiedInstruction(&machine_ir,
+                        machine_ir.NewInsn<AddqRegReg>(
+                            machine_ir.AllocVReg(), machine_ir.AllocVReg(), kMachineRegFLAGS));
+  // PseudoReadFlags is a special case as it has its own member variables and
+  // doesn't inherit from MachineInsnX86_64 so we test it too.
+  TestCopiedInstruction(
+      &machine_ir,
+      machine_ir.NewInsn<PseudoReadFlags>(
+          PseudoReadFlags::kWithOverflow, machine_ir.AllocVReg(), kMachineRegFLAGS));
+}
+
+TEST(MachineIRReadFlagsOptimizer, FindFlagSettingInsn) {
+  Arena arena;
+  x86_64::MachineIR machine_ir(&arena);
+  x86_64::MachineIRBuilder builder(&machine_ir);
+
+  MachineReg reg0 = machine_ir.AllocVReg();
+  MachineReg reg1 = machine_ir.AllocVReg();
+  MachineReg flags0 = machine_ir.AllocVReg();
+  MachineReg flags1 = machine_ir.AllocVReg();
+  MachineReg reg_with_flags0 = machine_ir.AllocVReg();
+
+  auto bb = machine_ir.NewBasicBlock();
+  builder.StartBasicBlock(bb);
+  builder.Gen<AddqRegReg>(reg0, reg1, flags0);
+  builder.Gen<SubqRegImm>(reg1, 1234, flags0);
+  builder.Gen<AddqRegReg>(reg1, reg0, flags1);
+  builder.Gen<PseudoReadFlags>(PseudoReadFlags::kWithOverflow, reg_with_flags0, flags0);
+  builder.Gen<PseudoJump>(kNullGuestAddr);
+
+  ASSERT_EQ(x86_64::CheckMachineIR(machine_ir), x86_64::kMachineIRCheckSuccess);
+
+  // Move to PseudoReadFlags.
+  auto insn_it = std::prev(bb->insn_list().end(), 2);
+  ASSERT_EQ((*insn_it)->opcode(), kMachineOpPseudoReadFlags);
+
+  auto flag_setter = FindFlagSettingInsn(insn_it, bb->insn_list().begin(), flags0);
+  ASSERT_TRUE(flag_setter.has_value());
+  ASSERT_EQ((*flag_setter.value())->opcode(), kMachineOpSubqRegImm);
+
+  // Test that we exit properly when we can't find the instruction.
+  // Move to second AddqRegReg.
+  insn_it--;
+  flag_setter = FindFlagSettingInsn(insn_it, bb->insn_list().begin(), flags1);
+  ASSERT_FALSE(flag_setter.has_value());
+}
+
+}  // namespace
+
+}  // namespace berberis::x86_64
diff --git a/backend/x86_64/reg_class_def.json b/backend/x86_64/reg_class_def.json
index aecdf6ae..204c8254 100644
--- a/backend/x86_64/reg_class_def.json
+++ b/backend/x86_64/reg_class_def.json
@@ -61,6 +61,13 @@
         "XMM0"
       ]
     },
+    {
+      "name": "YmmReg",
+      "size": 32,
+      "regs": [
+        "XmmReg"
+      ]
+    },
     {
       "name": "Reg64",
       "size": 8,
@@ -118,6 +125,13 @@
         "XmmReg"
       ]
     },
+    {
+      "name": "VecReg256",
+      "size": 32,
+      "regs": [
+        "XmmReg"
+      ]
+    },
     {
       "name": "RAX",
       "size": 8,
diff --git a/base/config_globals_custom.cc b/base/config_globals_custom.cc
index 98fb01a5..f2eacfb3 100644
--- a/base/config_globals_custom.cc
+++ b/base/config_globals_custom.cc
@@ -41,6 +41,16 @@ std::string ToString(ConfigFlag flag) {
       return "disable-reg-map";
     case kEnableDisjointRegionsTranslation:
       return "enable-disjoint-regions-translation";
+    case kDisableIntrinsicInlining:
+      return "disable-intrinsic-inlining";
+    case kMergeProfilesForSameModeRegions:
+      return "merge-profiles-for-same-mode-regions";
+    case kPrintTranslatedAddrs:
+      return "print-translated-addrs";
+    case kPrintIRs:
+      return "print-irs";
+    case kPrintCodePoolSize:
+      return "print-code-pool-size";
     case kLocalExperiment:
       return "local-experiment";
     case kPlatformCustomCPUCapability:
diff --git a/base/include/berberis/base/config_globals.h b/base/include/berberis/base/config_globals.h
index 634b520f..9e282573 100644
--- a/base/include/berberis/base/config_globals.h
+++ b/base/include/berberis/base/config_globals.h
@@ -54,6 +54,11 @@ enum ConfigFlag {
   kEnableDisjointRegionsTranslation,
   kVerboseTranslation,
   kAccurateSigsegv,
+  kDisableIntrinsicInlining,
+  kMergeProfilesForSameModeRegions,
+  kPrintTranslatedAddrs,
+  kPrintIRs,
+  kPrintCodePoolSize,
   // A convenience flag with no specific implied feature. Use it to conduct local experiments
   // without recompilation and without the need to add a new flag.
   kLocalExperiment,
diff --git a/base/include/berberis/base/exec_region.h b/base/include/berberis/base/exec_region.h
index 4c8c5c13..3d0209bc 100644
--- a/base/include/berberis/base/exec_region.h
+++ b/base/include/berberis/base/exec_region.h
@@ -67,6 +67,7 @@ class ExecRegion {
 
   [[nodiscard]] const uint8_t* begin() const { return exec_; }
   [[nodiscard]] const uint8_t* end() const { return exec_ + size_; }
+  [[nodiscard]] size_t size() const { return size_; }
 
   void Write(const uint8_t* dst, const void* src, size_t size);
 
diff --git a/base/include/berberis/base/struct_check.h b/base/include/berberis/base/struct_check.h
index ebc110ad..47def746 100644
--- a/base/include/berberis/base/struct_check.h
+++ b/base/include/berberis/base/struct_check.h
@@ -57,6 +57,14 @@ namespace berberis {
                 "size of `" #field "' field in " #type " must be " #size       \
                 " bit because it's " #size " bit on guest")
 
+#define CHECK_FIELD_LAYOUT_RELATIVE(type, field, previous_field, offset, size)                 \
+  static_assert((offsetof(type, field) - offsetof(type, previous_field)) * CHAR_BIT == offset, \
+                "offset of `" #field "' field in " #type " must be " #offset                   \
+                " because it's " #offset " on guest");                                         \
+  static_assert(sizeof(static_cast<type*>(nullptr)->field) * CHAR_BIT == size,                 \
+                "size of `" #field "' field in " #type " must be " #size                       \
+                " bit because it's " #size " bit on guest")
+
 }  // namespace berberis
 
 #endif  // BERBERIS_BASE_STRUCT_CHECK_H_
diff --git a/base/prctl_helpers.cc b/base/prctl_helpers.cc
index 8c441758..e0fb9615 100644
--- a/base/prctl_helpers.cc
+++ b/base/prctl_helpers.cc
@@ -22,8 +22,10 @@
 // enabled). It's always enabled in Android kernerls, but otherwise on Linux may be disabled
 // depending on CONFIG_ANON_VMA_NAME boot config flag. So the caller needs to check the result to
 // see if it actually worked.
-#if defined(__GLIBC__)
+#if !defined(PR_SET_VMA)
 #define PR_SET_VMA 0x53564d41
+#endif
+#if !defined(PR_SET_VMA_ANON_NAME)
 #define PR_SET_VMA_ANON_NAME 0
 #endif
 
diff --git a/code_gen_lib/all_to_x86_64/code_gen_lib.cc b/code_gen_lib/all_to_x86_64/code_gen_lib.cc
index 491df4d8..26f499c6 100644
--- a/code_gen_lib/all_to_x86_64/code_gen_lib.cc
+++ b/code_gen_lib/all_to_x86_64/code_gen_lib.cc
@@ -48,7 +48,7 @@ void EmitCheckSignalsAndMaybeReturn(x86_64::Assembler* as) {
   //   cmpb pending_signals_status, kPendingSignalsPresent
   const size_t offset = offsetof(ThreadState, pending_signals_status);
   as->Cmpb({.base = x86_64::Assembler::rbp, .disp = offset}, kPendingSignalsPresent);
-  as->Jcc(x86_64::Assembler::Condition::kEqual, kEntryExitGeneratedCode);
+  as->Jcc32(x86_64::Assembler::Condition::kEqual, kEntryExitGeneratedCode);
 }
 
 }  // namespace
@@ -88,6 +88,11 @@ void GenTrampolineAdaptor(MachineCode* mc,
     }
   }
 
+#ifdef __AVX__
+  // Clean up dirty AVX256 state if induced by calls to runtime.
+  as.Vzeroupper();
+#endif
+
   // jump to guest return address
   // Prefer rdx, since rax/rcx will result in extra moves inside EmitIndirectDispatch.
   as.Movq(as.rdx, {.base = as.rbp, .disp = kReturnAddressRegisterOffset});
@@ -122,7 +127,7 @@ void EmitDirectDispatch(x86_64::Assembler* as, GuestAddr pc, bool check_pending_
   as->Movq(as->rax, pc);
 
   if (!config::kLinkJumpsBetweenRegions) {
-    as->Jmp(kEntryExitGeneratedCode);
+    as->Jmp32(kEntryExitGeneratedCode);
     return;
   }
 
@@ -143,7 +148,7 @@ void EmitExitGeneratedCode(x86_64::Assembler* as, x86_64::Assembler::Register ta
     as->Movq(as->rax, target);
   }
 
-  as->Jmp(kEntryExitGeneratedCode);
+  as->Jmp32(kEntryExitGeneratedCode);
 }
 
 void EmitIndirectDispatch(x86_64::Assembler* as, x86_64::Assembler::Register target) {
@@ -153,7 +158,7 @@ void EmitIndirectDispatch(x86_64::Assembler* as, x86_64::Assembler::Register tar
   }
 
   if (!config::kLinkJumpsBetweenRegions) {
-    as->Jmp(kEntryExitGeneratedCode);
+    as->Jmp32(kEntryExitGeneratedCode);
     return;
   }
 
diff --git a/decoder/include/berberis/decoder/riscv64/semantics_player.h b/decoder/include/berberis/decoder/riscv64/semantics_player.h
index c9c53e42..67a9d8df 100644
--- a/decoder/include/berberis/decoder/riscv64/semantics_player.h
+++ b/decoder/include/berberis/decoder/riscv64/semantics_player.h
@@ -842,62 +842,31 @@ class SemanticsPlayer {
   // TODO(b/300690740): develop and implement strategy which would allow us to support vector
   // intrinsics not just in the interpreter.
 
-  void OpVector(const typename Decoder::VLoadIndexedArgs& args) {
-    Register arg2 = GetRegOrZero(args.src);
-    listener_->OpVector(args, arg2);
-  }
+  void OpVector(const typename Decoder::VLoadIndexedArgs& args);
 
-  void OpVector(const typename Decoder::VLoadStrideArgs& args) {
-    Register arg2 = GetRegOrZero(args.src);
-    Register arg3 = GetRegOrZero(args.std);
-    listener_->OpVector(args, arg2, arg3);
-  }
+  void OpVector(const typename Decoder::VLoadStrideArgs& args);
 
-  void OpVector(const typename Decoder::VLoadUnitStrideArgs& args) {
-    Register arg2 = GetRegOrZero(args.src);
-    listener_->OpVector(args, arg2);
-  }
+  void OpVector(const typename Decoder::VLoadUnitStrideArgs& args);
 
-  void OpVector(const typename Decoder::VOpFVfArgs& args) {
-    // Note: we don't have information here to chosee between GetFRegAndUnboxNan<Float32> and
-    // GetFRegAndUnboxNan<Float64> because that depends on vtype.
-    FpRegister arg2 = GetFpReg(args.src2);
-    listener_->OpVector(args, arg2);
-  }
+  void OpVector(const typename Decoder::VOpFVfArgs& args);
 
-  void OpVector(const typename Decoder::VOpFVvArgs& args) { listener_->OpVector(args); }
+  void OpVector(const typename Decoder::VOpFVvArgs& args);
 
-  void OpVector(const typename Decoder::VOpIViArgs& args) { listener_->OpVector(args); }
+  void OpVector(const typename Decoder::VOpIViArgs& args);
 
-  void OpVector(const typename Decoder::VOpIVvArgs& args) { listener_->OpVector(args); }
+  void OpVector(const typename Decoder::VOpIVvArgs& args);
 
-  void OpVector(const typename Decoder::VOpMVvArgs& args) { listener_->OpVector(args); }
+  void OpVector(const typename Decoder::VOpMVvArgs& args);
 
-  void OpVector(const typename Decoder::VOpIVxArgs& args) {
-    Register arg2 = GetRegOrZero(args.src2);
-    listener_->OpVector(args, arg2);
-  }
+  void OpVector(const typename Decoder::VOpIVxArgs& args);
 
-  void OpVector(const typename Decoder::VOpMVxArgs& args) {
-    Register arg2 = GetRegOrZero(args.src2);
-    listener_->OpVector(args, arg2);
-  }
+  void OpVector(const typename Decoder::VOpMVxArgs& args);
 
-  void OpVector(const typename Decoder::VStoreIndexedArgs& args) {
-    Register arg2 = GetRegOrZero(args.src);
-    listener_->OpVector(args, arg2);
-  }
+  void OpVector(const typename Decoder::VStoreIndexedArgs& args);
 
-  void OpVector(const typename Decoder::VStoreStrideArgs& args) {
-    Register arg2 = GetRegOrZero(args.src);
-    Register arg3 = GetRegOrZero(args.std);
-    listener_->OpVector(args, arg2, arg3);
-  }
+  void OpVector(const typename Decoder::VStoreStrideArgs& args);
 
-  void OpVector(const typename Decoder::VStoreUnitStrideArgs& args) {
-    Register arg2 = GetRegOrZero(args.src);
-    listener_->OpVector(args, arg2);
-  }
+  void OpVector(const typename Decoder::VStoreUnitStrideArgs& args);
 
   void Vsetivli(const typename Decoder::VsetivliArgs& args) {
     // Note: it's unclear whether args.avl should be treated similarly to x0 in Vsetvli or not.
@@ -1140,6 +1109,90 @@ class SemanticsPlayer {
   SemanticsListener* listener_;
 };
 
+// Note: we explicitly instantiate these functions in different files to speedup the compilation.
+// For that they have to be defined outside the class.
+// Read https://learn.microsoft.com/en-us/cpp/cpp/explicit-instantiation for more information.
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VLoadIndexedArgs& args) {
+  Register arg2 = GetRegOrZero(args.src);
+  listener_->OpVector(args, arg2);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VLoadStrideArgs& args) {
+  Register arg2 = GetRegOrZero(args.src);
+  Register arg3 = GetRegOrZero(args.std);
+  listener_->OpVector(args, arg2, arg3);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(
+    const typename Decoder::VLoadUnitStrideArgs& args) {
+  Register arg2 = GetRegOrZero(args.src);
+  listener_->OpVector(args, arg2);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VOpFVfArgs& args) {
+  // Note: we don't have information here to chosee between GetFRegAndUnboxNan<Float32> and
+  // GetFRegAndUnboxNan<Float64> because that depends on vtype.
+  FpRegister arg2 = GetFpReg(args.src2);
+  listener_->OpVector(args, arg2);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VOpFVvArgs& args) {
+  listener_->OpVector(args);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VOpIViArgs& args) {
+  listener_->OpVector(args);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VOpIVvArgs& args) {
+  listener_->OpVector(args);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VOpMVvArgs& args) {
+  listener_->OpVector(args);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VOpIVxArgs& args) {
+  Register arg2 = GetRegOrZero(args.src2);
+  listener_->OpVector(args, arg2);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VOpMVxArgs& args) {
+  Register arg2 = GetRegOrZero(args.src2);
+  listener_->OpVector(args, arg2);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VStoreIndexedArgs& args) {
+  Register arg2 = GetRegOrZero(args.src);
+  listener_->OpVector(args, arg2);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(const typename Decoder::VStoreStrideArgs& args) {
+  Register arg2 = GetRegOrZero(args.src);
+  Register arg3 = GetRegOrZero(args.std);
+  listener_->OpVector(args, arg2, arg3);
+}
+
+template <class SemanticsListener>
+void SemanticsPlayer<SemanticsListener>::OpVector(
+    const typename Decoder::VStoreUnitStrideArgs& args) {
+  Register arg2 = GetRegOrZero(args.src);
+  listener_->OpVector(args, arg2);
+}
+
 }  // namespace berberis
 
 #endif  // BERBERIS_DECODER_RISCV64_SEMANTICS_PLAYER_H_
diff --git a/guest_os_primitives/guest_map_shadow.cc b/guest_os_primitives/guest_map_shadow.cc
index f5b45948..4fecbc5e 100644
--- a/guest_os_primitives/guest_map_shadow.cc
+++ b/guest_os_primitives/guest_map_shadow.cc
@@ -18,7 +18,9 @@
 
 #include <sys/mman.h>
 #include <climits>  // CHAR_BIT
+#include <cstddef>
 #include <mutex>
+#include <tuple>
 
 #include "berberis/base/bit_util.h"
 #include "berberis/base/forever_alloc.h"
@@ -124,17 +126,24 @@ GuestMapShadow::~GuestMapShadow() {
   MunmapOrDie(shadow_, kShadowSize);
 }
 
-BitValue GuestMapShadow::GetExecutable(GuestAddr start, size_t size) const {
+std::tuple<bool, size_t> GuestMapShadow::GetExecutableRegionSize(GuestAddr start,
+                                                                 size_t scan_size) const {
   GuestAddr pc = AlignDownGuestPageSize(start);
-  GuestAddr end = AlignUpGuestPageSize(start + size);
+  GuestAddr scan_end_pc = AlignUpGuestPageSize(start + scan_size);
 
   bool is_exec = IsExecAddr(pc);
-  pc += kGuestPageSize;
-  while (pc < end) {
+  for (pc += kGuestPageSize; pc < scan_end_pc; pc += kGuestPageSize) {
     if (is_exec != IsExecAddr(pc)) {
-      return kBitMixed;
+      break;
     }
-    pc += kGuestPageSize;
+  }
+  return {is_exec, pc - start};
+}
+
+BitValue GuestMapShadow::GetExecutable(GuestAddr start, size_t scan_size) const {
+  auto [is_exec, region_size] = GetExecutableRegionSize(start, scan_size);
+  if (region_size < scan_size) {
+    return kBitMixed;
   }
   return is_exec ? kBitSet : kBitUnset;
 }
diff --git a/guest_os_primitives/guest_map_shadow_test.cc b/guest_os_primitives/guest_map_shadow_test.cc
index 5475d712..25875ef1 100644
--- a/guest_os_primitives/guest_map_shadow_test.cc
+++ b/guest_os_primitives/guest_map_shadow_test.cc
@@ -32,71 +32,76 @@ class GuestMapShadowTest : public ::testing::Test {
     ::testing::Test::SetUp();
     InitLargeMmap();
   }
+
+  template <bool kExpectedExec, size_t kExpectedSize>
+  void ExpectExecRegionSize(GuestAddr start, size_t test_size) {
+    auto [is_exec, size] = shadow_.GetExecutableRegionSize(start, test_size);
+    EXPECT_EQ(is_exec, kExpectedExec);
+    EXPECT_EQ(size, kExpectedSize);
+  }
+
+  GuestMapShadow shadow_;
 };
 
 constexpr GuestAddr kGuestAddr{0x7f018000};
 constexpr size_t kGuestRegionSize{0x00020000};
 
-TEST_F(GuestMapShadowTest, smoke) {
-  auto shadow = std::make_unique<GuestMapShadow>();
-
-  ASSERT_EQ(kBitUnset, shadow->GetExecutable(kGuestAddr, kGuestRegionSize));
-  ASSERT_TRUE(!shadow->IsExecutable(kGuestAddr, 1));
-  ASSERT_TRUE(!shadow->IsExecutable(kGuestAddr, kGuestRegionSize));
-
-  shadow->SetExecutable(kGuestAddr, kGuestRegionSize / 2);
-
-  ASSERT_EQ(kBitMixed, shadow->GetExecutable(kGuestAddr, kGuestRegionSize));
-  ASSERT_EQ(kBitSet, shadow->GetExecutable(kGuestAddr, kGuestRegionSize / 2));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, 1));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, kGuestRegionSize / 2));
-  ASSERT_TRUE(!shadow->IsExecutable(kGuestAddr, kGuestRegionSize));
-
-  shadow->SetExecutable(kGuestAddr, kGuestRegionSize);
-  ASSERT_EQ(kBitSet, shadow->GetExecutable(kGuestAddr, kGuestRegionSize));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, 1));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, kGuestRegionSize / 2));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, kGuestRegionSize));
-
-  shadow->ClearExecutable(kGuestAddr, kGuestRegionSize * 2);
-  ASSERT_EQ(kBitUnset, shadow->GetExecutable(kGuestAddr, kGuestRegionSize));
-  ASSERT_TRUE(!shadow->IsExecutable(kGuestAddr, 1));
-  ASSERT_TRUE(!shadow->IsExecutable(kGuestAddr, kGuestRegionSize / 2));
-  ASSERT_TRUE(!shadow->IsExecutable(kGuestAddr, kGuestRegionSize));
+TEST_F(GuestMapShadowTest, Basic) {
+  ASSERT_EQ(kBitUnset, shadow_.GetExecutable(kGuestAddr, kGuestRegionSize));
+  ASSERT_TRUE(!shadow_.IsExecutable(kGuestAddr, 1));
+  ASSERT_TRUE(!shadow_.IsExecutable(kGuestAddr, kGuestRegionSize));
+
+  shadow_.SetExecutable(kGuestAddr, kGuestRegionSize / 2);
+
+  ASSERT_EQ(kBitMixed, shadow_.GetExecutable(kGuestAddr, kGuestRegionSize));
+  ASSERT_EQ(kBitSet, shadow_.GetExecutable(kGuestAddr, kGuestRegionSize / 2));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, 1));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, kGuestRegionSize / 2));
+  ASSERT_TRUE(!shadow_.IsExecutable(kGuestAddr, kGuestRegionSize));
+
+  shadow_.SetExecutable(kGuestAddr, kGuestRegionSize);
+  ASSERT_EQ(kBitSet, shadow_.GetExecutable(kGuestAddr, kGuestRegionSize));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, 1));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, kGuestRegionSize / 2));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, kGuestRegionSize));
+
+  shadow_.ClearExecutable(kGuestAddr, kGuestRegionSize * 2);
+  ASSERT_EQ(kBitUnset, shadow_.GetExecutable(kGuestAddr, kGuestRegionSize));
+  ASSERT_TRUE(!shadow_.IsExecutable(kGuestAddr, 1));
+  ASSERT_TRUE(!shadow_.IsExecutable(kGuestAddr, kGuestRegionSize / 2));
+  ASSERT_TRUE(!shadow_.IsExecutable(kGuestAddr, kGuestRegionSize));
 }
 
-TEST_F(GuestMapShadowTest, remap) {
+TEST_F(GuestMapShadowTest, Remap) {
   constexpr GuestAddr kRemapAddr = 0x00107000;
   constexpr size_t kRemapRegionSize1 = kGuestRegionSize / 2;
   constexpr size_t kRemapRegionSize2 = kGuestRegionSize * 2;
 
-  auto shadow = std::make_unique<GuestMapShadow>();
-
-  shadow->SetExecutable(kGuestAddr, kGuestRegionSize);
-  ASSERT_EQ(kBitSet, shadow->GetExecutable(kGuestAddr, kGuestRegionSize));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, 1));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, kGuestRegionSize / 2));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, kGuestRegionSize));
-
-  shadow->RemapExecutable(kGuestAddr, kGuestRegionSize, kRemapAddr, kRemapRegionSize1);
-  ASSERT_EQ(kBitUnset, shadow->GetExecutable(kGuestAddr, kGuestRegionSize));
-  ASSERT_TRUE(!shadow->IsExecutable(kGuestAddr, 1));
-  ASSERT_TRUE(!shadow->IsExecutable(kGuestAddr, kGuestRegionSize / 2));
-  ASSERT_TRUE(!shadow->IsExecutable(kGuestAddr, kGuestRegionSize));
-
-  ASSERT_EQ(kBitSet, shadow->GetExecutable(kRemapAddr, kRemapRegionSize1));
-  ASSERT_TRUE(shadow->IsExecutable(kRemapAddr, 1));
-  ASSERT_TRUE(shadow->IsExecutable(kRemapAddr, kRemapRegionSize1));
-
-  shadow->RemapExecutable(kRemapAddr, kRemapRegionSize1, kGuestAddr, kRemapRegionSize2);
-  ASSERT_EQ(kBitUnset, shadow->GetExecutable(kRemapAddr, kRemapRegionSize1));
-  ASSERT_TRUE(!shadow->IsExecutable(kRemapAddr, 1));
-  ASSERT_TRUE(!shadow->IsExecutable(kRemapAddr, kRemapRegionSize1));
-
-  ASSERT_EQ(kBitSet, shadow->GetExecutable(kGuestAddr, kRemapRegionSize2));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, 1));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, kRemapRegionSize2 / 2));
-  ASSERT_TRUE(shadow->IsExecutable(kGuestAddr, kRemapRegionSize2));
+  shadow_.SetExecutable(kGuestAddr, kGuestRegionSize);
+  ASSERT_EQ(kBitSet, shadow_.GetExecutable(kGuestAddr, kGuestRegionSize));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, 1));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, kGuestRegionSize / 2));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, kGuestRegionSize));
+
+  shadow_.RemapExecutable(kGuestAddr, kGuestRegionSize, kRemapAddr, kRemapRegionSize1);
+  ASSERT_EQ(kBitUnset, shadow_.GetExecutable(kGuestAddr, kGuestRegionSize));
+  ASSERT_TRUE(!shadow_.IsExecutable(kGuestAddr, 1));
+  ASSERT_TRUE(!shadow_.IsExecutable(kGuestAddr, kGuestRegionSize / 2));
+  ASSERT_TRUE(!shadow_.IsExecutable(kGuestAddr, kGuestRegionSize));
+
+  ASSERT_EQ(kBitSet, shadow_.GetExecutable(kRemapAddr, kRemapRegionSize1));
+  ASSERT_TRUE(shadow_.IsExecutable(kRemapAddr, 1));
+  ASSERT_TRUE(shadow_.IsExecutable(kRemapAddr, kRemapRegionSize1));
+
+  shadow_.RemapExecutable(kRemapAddr, kRemapRegionSize1, kGuestAddr, kRemapRegionSize2);
+  ASSERT_EQ(kBitUnset, shadow_.GetExecutable(kRemapAddr, kRemapRegionSize1));
+  ASSERT_TRUE(!shadow_.IsExecutable(kRemapAddr, 1));
+  ASSERT_TRUE(!shadow_.IsExecutable(kRemapAddr, kRemapRegionSize1));
+
+  ASSERT_EQ(kBitSet, shadow_.GetExecutable(kGuestAddr, kRemapRegionSize2));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, 1));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, kRemapRegionSize2 / 2));
+  ASSERT_TRUE(shadow_.IsExecutable(kGuestAddr, kRemapRegionSize2));
 }
 
 TEST_F(GuestMapShadowTest, ProtectedMappings) {
@@ -104,59 +109,71 @@ TEST_F(GuestMapShadowTest, ProtectedMappings) {
   const char* kEnd = kStart + kGuestRegionSize;
   const size_t kHalf = kGuestRegionSize / 2;
 
-  auto shadow = std::make_unique<GuestMapShadow>();
-
-  shadow->AddProtectedMapping(kStart, kEnd);
+  shadow_.AddProtectedMapping(kStart, kEnd);
 
-  EXPECT_TRUE(shadow->IntersectsWithProtectedMapping(kStart, kEnd));
+  EXPECT_TRUE(shadow_.IntersectsWithProtectedMapping(kStart, kEnd));
 
   // Intersecting mappings are also protected.
-  EXPECT_TRUE(shadow->IntersectsWithProtectedMapping(kStart - kHalf, kEnd - kHalf));
-  EXPECT_TRUE(shadow->IntersectsWithProtectedMapping(kStart + kHalf, kEnd + kHalf));
+  EXPECT_TRUE(shadow_.IntersectsWithProtectedMapping(kStart - kHalf, kEnd - kHalf));
+  EXPECT_TRUE(shadow_.IntersectsWithProtectedMapping(kStart + kHalf, kEnd + kHalf));
 
   // Adjacent mappings are not protected.
-  EXPECT_FALSE(shadow->IntersectsWithProtectedMapping(kStart - kGuestRegionSize, kStart));
-  EXPECT_FALSE(shadow->IntersectsWithProtectedMapping(kEnd, kEnd + kGuestRegionSize));
+  EXPECT_FALSE(shadow_.IntersectsWithProtectedMapping(kStart - kGuestRegionSize, kStart));
+  EXPECT_FALSE(shadow_.IntersectsWithProtectedMapping(kEnd, kEnd + kGuestRegionSize));
 
   // Add and test another mapping.
 
   const char* kAnotherStart = kStart + kGuestRegionSize;
   const char* kAnotherEnd = kAnotherStart + kGuestRegionSize;
-  shadow->AddProtectedMapping(kAnotherStart, kAnotherEnd);
+  shadow_.AddProtectedMapping(kAnotherStart, kAnotherEnd);
 
-  EXPECT_TRUE(shadow->IntersectsWithProtectedMapping(kAnotherStart, kAnotherEnd));
+  EXPECT_TRUE(shadow_.IntersectsWithProtectedMapping(kAnotherStart, kAnotherEnd));
 
   // Intersecting mappings, including those that span across
   // multiple protected mappings, are also protected.
-  EXPECT_TRUE(shadow->IntersectsWithProtectedMapping(kAnotherStart - kHalf, kAnotherEnd - kHalf));
-  EXPECT_TRUE(shadow->IntersectsWithProtectedMapping(kAnotherStart + kHalf, kAnotherEnd + kHalf));
-  EXPECT_TRUE(shadow->IntersectsWithProtectedMapping(kStart - kHalf, kAnotherEnd + kHalf));
+  EXPECT_TRUE(shadow_.IntersectsWithProtectedMapping(kAnotherStart - kHalf, kAnotherEnd - kHalf));
+  EXPECT_TRUE(shadow_.IntersectsWithProtectedMapping(kAnotherStart + kHalf, kAnotherEnd + kHalf));
+  EXPECT_TRUE(shadow_.IntersectsWithProtectedMapping(kStart - kHalf, kAnotherEnd + kHalf));
 
   // Adjacent mappings, including between the protected mappings, are not protected.
-  EXPECT_FALSE(shadow->IntersectsWithProtectedMapping(kEnd, kAnotherStart));
-  EXPECT_FALSE(shadow->IntersectsWithProtectedMapping(kAnotherEnd, kAnotherEnd + kGuestRegionSize));
+  EXPECT_FALSE(shadow_.IntersectsWithProtectedMapping(kEnd, kAnotherStart));
+  EXPECT_FALSE(shadow_.IntersectsWithProtectedMapping(kAnotherEnd, kAnotherEnd + kGuestRegionSize));
 }
 
 #if defined(BERBERIS_GUEST_LP64)
 
 TEST_F(GuestMapShadowTest, 64BitAddress) {
-  auto shadow = std::make_unique<GuestMapShadow>();
   // We only really allow up to 48 bit addresses.
   constexpr uint64_t k64BitAddr{0x0000'7fff'dddd'ccccULL};
 
-  ASSERT_EQ(kBitUnset, shadow->GetExecutable(k64BitAddr, kGuestRegionSize));
+  ASSERT_EQ(kBitUnset, shadow_.GetExecutable(k64BitAddr, kGuestRegionSize));
 
-  shadow->SetExecutable(k64BitAddr, kGuestRegionSize);
+  shadow_.SetExecutable(k64BitAddr, kGuestRegionSize);
 
-  ASSERT_EQ(kBitSet, shadow->GetExecutable(k64BitAddr, kGuestRegionSize));
+  ASSERT_EQ(kBitSet, shadow_.GetExecutable(k64BitAddr, kGuestRegionSize));
   // The address with 4 upper bits truncated doesn't map to
   // the same entry as the full address (b/369950324).
   constexpr uint64_t kTruncated64BitAddr{k64BitAddr & ~(uint64_t{0xf} << 44)};
-  ASSERT_EQ(kBitUnset, shadow->GetExecutable(kTruncated64BitAddr, kGuestRegionSize));
+  ASSERT_EQ(kBitUnset, shadow_.GetExecutable(kTruncated64BitAddr, kGuestRegionSize));
 }
 
 #endif
 
+TEST_F(GuestMapShadowTest, GetExecutableRegionSize) {
+  shadow_.SetExecutable(kGuestAddr, kGuestRegionSize);
+
+  ExpectExecRegionSize<false, kGuestRegionSize>(kGuestAddr - kGuestRegionSize, kGuestRegionSize);
+  ExpectExecRegionSize<true, kGuestRegionSize>(kGuestAddr, kGuestRegionSize);
+  ExpectExecRegionSize<false, kGuestRegionSize>(kGuestAddr + kGuestRegionSize, kGuestRegionSize);
+
+  // Cases where region size is shorter than the tested size.
+  ExpectExecRegionSize<false, kGuestRegionSize / 2>(kGuestAddr - kGuestRegionSize / 2,
+                                                    kGuestRegionSize);
+  ExpectExecRegionSize<true, kGuestRegionSize / 2>(kGuestAddr + kGuestRegionSize / 2,
+                                                   kGuestRegionSize);
+  ExpectExecRegionSize<true, kGuestRegionSize>(kGuestAddr, kGuestRegionSize * 2);
+}
+
 }  // namespace
 
 }  // namespace berberis
diff --git a/guest_os_primitives/guest_signal_handling.cc b/guest_os_primitives/guest_signal_handling.cc
index 2b3e26e3..350443e5 100644
--- a/guest_os_primitives/guest_signal_handling.cc
+++ b/guest_os_primitives/guest_signal_handling.cc
@@ -16,6 +16,7 @@
 
 #include <atomic>
 #include <csignal>
+#include <cstring>
 #include <memory>
 #include <mutex>
 
@@ -23,6 +24,7 @@
 #include <platform/bionic/reserved_signals.h>
 #endif
 
+#include "berberis/base/bit_util.h"
 #include "berberis/base/checks.h"
 #include "berberis/base/config_globals.h"
 #include "berberis/base/forever_alloc.h"
@@ -31,7 +33,9 @@
 #include "berberis/guest_os_primitives/guest_thread.h"
 #include "berberis/guest_os_primitives/guest_thread_manager.h"
 #include "berberis/guest_os_primitives/syscall_numbers.h"
+#include "berberis/guest_state/guest_addr.h"
 #include "berberis/guest_state/guest_state_opaque.h"
+#include "berberis/runtime_primitives/crash_reporter.h"
 #include "berberis/runtime_primitives/recovery_code.h"
 
 #include "guest_signal_action.h"
@@ -111,7 +115,12 @@ void SetHostRegIP(ucontext* ucontext, uintptr_t addr) {
 
 // Can be interrupted by another HandleHostSignal!
 void HandleHostSignal(int sig, siginfo_t* info, void* context) {
-  TRACE("handle host signal %d", sig);
+  ucontext_t* ucontext = bit_cast<ucontext_t*>(context);
+  TRACE("Handle host signal %s (%d) at pc=%p si_addr=%p",
+        strsignal(sig),
+        sig,
+        bit_cast<void*>(GetHostRegIP(ucontext)),
+        info->si_addr);
 
   bool attached;
   GuestThread* thread = AttachCurrentThread(false, &attached);
@@ -133,7 +142,6 @@ void HandleHostSignal(int sig, siginfo_t* info, void* context) {
     CHECK(!attached);
 
     // Run recovery code to restore precise context and exit generated code.
-    ucontext_t* ucontext = reinterpret_cast<ucontext_t*>(context);
     uintptr_t addr = GetHostRegIP(ucontext);
     uintptr_t recovery_addr = FindRecoveryCode(addr, thread->state());
 
@@ -152,14 +160,17 @@ void HandleHostSignal(int sig, siginfo_t* info, void* context) {
       }
       SetHostRegIP(ucontext, recovery_addr);
       TRACE("guest signal handler suspended, run recovery for host pc %p at host pc %p",
-            reinterpret_cast<void*>(addr),
-            reinterpret_cast<void*>(recovery_addr));
+            bit_cast<void*>(addr),
+            bit_cast<void*>(recovery_addr));
     } else {
       // Failed to find recovery code.
       // Translated code should be arranged to continue till
       // the next pending signals check unless it's fatal.
       if (IsPendingSignalWithoutRecoveryCodeFatal(info)) {
-        LOG_ALWAYS_FATAL("Cannot process signal %d", sig);
+        HandleFatalSignal(sig, info, context);
+        // If the raised signal is blocked we may need to return from the handler to unblock it.
+        TRACE("Detected return from HandleFatalSignal, continue");
+        return;
       }
       TRACE("guest signal handler suspended, continue");
     }
diff --git a/guest_os_primitives/guest_thread_clone.cc b/guest_os_primitives/guest_thread_clone.cc
index 8aa87acd..05dd141e 100644
--- a/guest_os_primitives/guest_thread_clone.cc
+++ b/guest_os_primitives/guest_thread_clone.cc
@@ -63,16 +63,26 @@ void SemPostOrDie(sem_t* sem) {
   // Note that sem_destroy itself may do nothing (bionic and glibc are like that), the actual
   // destruction happens because we free up memory (e.g. stack frame) where sem_t is stored.
   // More details at https://sourceware.org/bugzilla/show_bug.cgi?id=12674
-#if defined(__GLIBC__) && ((__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 21)))
+#if defined(__GLIBC__)
+
+#if (__GLIBC__ < 2) || ((__GLIBC__ == 2) && (__GLIBC_MINOR__ < 21))
   // GLibc before 2.21 may return EINVAL in the above situation. We ignore it since we cannot do
   // anything about it, and it doesn't really break anything: we just acknowledge the fact that the
   // semaphore can be destoyed already.
-  LOG_ALWAYS_FATAL_IF(error != 0 && error != EINVAL, "sem_post returned error=%s", strerror(errno));
+  LOG_ALWAYS_FATAL_IF(error != 0 && errno != EINVAL, "sem_post returned error=%s", strerror(errno));
 #else
-  // Bionic and recent GLibc ignore the error code returned
-  // from FUTEX_WAKE. So, they never return EINVAL.
-  LOG_ALWAYS_FATAL_IF(error != 0, "sem_post returned error=%s", strerror(errno));
+  // Recent GLibc ignores the error code returned from FUTEX_WAKE. So, it never returns EINVAL.
+  LOG_ALWAYS_FATAL_IF(error != 0,
+                      "sem_post returned error=%s GLIBC=%d GLIBC_MINOR=%d",
+                      strerror(errno),
+                      __GLIBC__,
+                      __GLIBC_MINOR__);
 #endif
+
+#else
+  // Bionic ignores the error code returned from FUTEX_WAKE. So, it never returns EINVAL.
+  LOG_ALWAYS_FATAL_IF(error != 0, "sem_post returned error=%s", strerror(errno));
+#endif  // defined(__GLIBC__)
 }
 
 int RunClonedGuestThread(void* arg) {
diff --git a/guest_os_primitives/include/berberis/guest_os_primitives/guest_map_shadow.h b/guest_os_primitives/include/berberis/guest_os_primitives/guest_map_shadow.h
index 5cf30096..e9774d72 100644
--- a/guest_os_primitives/include/berberis/guest_os_primitives/guest_map_shadow.h
+++ b/guest_os_primitives/include/berberis/guest_os_primitives/guest_map_shadow.h
@@ -38,6 +38,8 @@ class GuestMapShadow {
   GuestMapShadow();
   ~GuestMapShadow();
 
+  [[nodiscard]] std::tuple<bool, size_t> GetExecutableRegionSize(GuestAddr start,
+                                                                 size_t max_size) const;
   [[nodiscard]] BitValue GetExecutable(GuestAddr start, size_t size) const;
 
   // Check if region start..start+size is fully executable.
diff --git a/guest_state/Android.bp b/guest_state/Android.bp
index f244a91b..89e8f13b 100644
--- a/guest_state/Android.bp
+++ b/guest_state/Android.bp
@@ -114,6 +114,7 @@ cc_library_static {
         "berberis_guest_state_defaults",
     ],
     srcs: [
+        "arm/get_cpu_state.cc",
         "arm/guest_state_arch.cc",
     ],
     header_libs: [
@@ -145,3 +146,16 @@ cc_test_library {
     header_libs: ["libberberis_guest_state_arm64_headers"],
     export_header_lib_headers: ["libberberis_guest_state_arm64_headers"],
 }
+
+cc_test_library {
+    name: "libberberis_cpu_state_arm_unit_test",
+    defaults: [
+        "berberis_arm_defaults",
+        "berberis_test_library_defaults",
+        "berberis_guest_state_defaults",
+        "berberis_guest_state_headers_defaults",
+    ],
+    srcs: ["arm/get_cpu_state_test.cc"],
+    header_libs: ["libberberis_guest_state_arm_headers"],
+    export_header_lib_headers: ["libberberis_guest_state_arm_headers"],
+}
diff --git a/guest_state/arm/get_cpu_state.cc b/guest_state/arm/get_cpu_state.cc
new file mode 100644
index 00000000..c8c5abc9
--- /dev/null
+++ b/guest_state/arm/get_cpu_state.cc
@@ -0,0 +1,51 @@
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
+#include "berberis/guest_state/get_cpu_state_opaque.h"
+#include "native_bridge_support/guest_state_accessor/accessor.h"
+
+#include "berberis/base/logging.h"
+#include "berberis/guest_state/guest_state_arch.h"
+
+#include <cstddef>
+#include <cstring>
+
+namespace berberis {
+
+int GetCpuState(NativeBridgeGuestRegs* guest_regs, const CPUState* state) {
+  if (guest_regs->guest_arch != NATIVE_BRIDGE_ARCH_ARM) {
+    ALOGE("The guest architecture is unmatched: %llu", guest_regs->guest_arch);
+    return NATIVE_BRIDGE_GUEST_STATE_ACCESSOR_ERROR_UNSUPPORTED_ARCH;
+  }
+  memcpy(&guest_regs->regs_arm.r, &state->r, sizeof(state->r));
+  guest_regs->regs_arm.r[15] = state->insn_addr;
+  memcpy(&guest_regs->regs_arm.q, &state->d, sizeof(state->d));
+  return 0;
+}
+
+extern "C" __attribute__((visibility("default"))) int LoadGuestStateRegisters(
+    const void* guest_state_data,
+    size_t guest_state_data_size,
+    NativeBridgeGuestRegs* guest_regs) {
+  if (guest_state_data_size < sizeof(ThreadState)) {
+    ALOGE("The guest state data size is invalid: %zu", guest_state_data_size);
+    return NATIVE_BRIDGE_GUEST_STATE_ACCESSOR_ERROR_INVALID_STATE;
+  }
+  guest_regs->guest_arch = NATIVE_BRIDGE_ARCH_ARM;
+  return GetCpuState(guest_regs, &(static_cast<const ThreadState*>(guest_state_data))->cpu);
+}
+
+}  // namespace berberis
diff --git a/guest_state/arm/get_cpu_state_test.cc b/guest_state/arm/get_cpu_state_test.cc
new file mode 100644
index 00000000..7f7fdfde
--- /dev/null
+++ b/guest_state/arm/get_cpu_state_test.cc
@@ -0,0 +1,64 @@
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
+#include <cstddef>
+#include <cstring>
+
+#include "berberis/guest_state/get_cpu_state_opaque.h"
+#include "berberis/guest_state/guest_state_arch.h"
+#include "native_bridge_support/guest_state_accessor/accessor.h"
+
+namespace berberis {
+
+namespace {
+
+TEST(GetArmCpuStateTest, TestValuesSet) {
+  NativeBridgeGuestRegs guest_regs{.guest_arch = NATIVE_BRIDGE_ARCH_ARM};
+  CPUState cpu_state;
+  for (size_t off = 0; off < sizeof(CPUState); off++) {
+    auto val = off % 199;  // 199 is prime to avoid regularly repeating values in registers
+    memcpy(reinterpret_cast<char*>(&cpu_state) + off, &val, 1);
+  }
+
+  EXPECT_EQ(GetCpuState(&guest_regs, &cpu_state), 0);
+
+  for (std::size_t i = 0; i < 15; i++) {
+    EXPECT_EQ(guest_regs.regs_arm.r[i], cpu_state.r[i]);
+  }
+  EXPECT_EQ(guest_regs.regs_arm.r[15], cpu_state.insn_addr);
+  for (std::size_t i = 0; i < 32; i++) {
+    EXPECT_EQ(guest_regs.regs_arm.q[i], cpu_state.d[i]);
+  }
+}
+
+TEST(GetArmCpuStateTest, TestErrorSize) {
+  NativeBridgeGuestRegs guest_regs{.guest_arch = NATIVE_BRIDGE_ARCH_ARM};
+  int res = LoadGuestStateRegisters(nullptr, sizeof(ThreadState) - 1, &guest_regs);
+  EXPECT_EQ(res, NATIVE_BRIDGE_GUEST_STATE_ACCESSOR_ERROR_INVALID_STATE);
+}
+
+TEST(GetArmCpuStateTest, TestErrorArch) {
+  NativeBridgeGuestRegs guest_regs{.guest_arch = NATIVE_BRIDGE_ARCH_RISCV64};
+  CPUState cpu_state;
+  int res = GetCpuState(&guest_regs, &cpu_state);
+  EXPECT_EQ(res, NATIVE_BRIDGE_GUEST_STATE_ACCESSOR_ERROR_UNSUPPORTED_ARCH);
+}
+
+}  // namespace
+
+}  // namespace berberis
diff --git a/guest_state/arm64/get_cpu_state.cc b/guest_state/arm64/get_cpu_state.cc
index 894ed30b..f3da4c3c 100644
--- a/guest_state/arm64/get_cpu_state.cc
+++ b/guest_state/arm64/get_cpu_state.cc
@@ -14,14 +14,29 @@
  * limitations under the License.
  */
 
-#include "berberis/base/logging.h"
 #include "berberis/guest_state/get_cpu_state_opaque.h"
-#include "berberis/guest_state/guest_state_arch.h"
-#include "berberis/guest_state/guest_state_opaque.h"
 #include "native_bridge_support/guest_state_accessor/accessor.h"
 
+#include "berberis/base/logging.h"
+#include "berberis/guest_state/guest_state_arch.h"
+
+#include <cstddef>
+#include <cstring>
+
 namespace berberis {
 
+int GetCpuState(NativeBridgeGuestRegs* guest_regs, const CPUState* state) {
+  if (guest_regs->guest_arch != NATIVE_BRIDGE_ARCH_ARM64) {
+    ALOGE("The guest architecture is unmatched: %lu", guest_regs->guest_arch);
+    return NATIVE_BRIDGE_GUEST_STATE_ACCESSOR_ERROR_UNSUPPORTED_ARCH;
+  }
+  memcpy(&guest_regs->regs_arm64.x, &state->x, sizeof(guest_regs->regs_arm64.x));
+  memcpy(&guest_regs->regs_arm64.sp, &state->sp, sizeof(guest_regs->regs_arm64.sp));
+  memcpy(&guest_regs->regs_arm64.ip, &state->insn_addr, sizeof(guest_regs->regs_arm64.ip));
+  memcpy(&guest_regs->regs_arm64.v, &state->v, sizeof(guest_regs->regs_arm64.v));
+  return 0;
+}
+
 extern "C" __attribute__((visibility("default"))) int LoadGuestStateRegisters(
     const void* guest_state_data,
     size_t guest_state_data_size,
@@ -34,15 +49,4 @@ extern "C" __attribute__((visibility("default"))) int LoadGuestStateRegisters(
   return GetCpuState(guest_regs, &(static_cast<const ThreadState*>(guest_state_data))->cpu);
 }
 
-int GetCpuState(NativeBridgeGuestRegs* guest_regs, const CPUState* state) {
-  if (guest_regs->guest_arch != NATIVE_BRIDGE_ARCH_ARM64) {
-    ALOGE("The guest architecture is unmatched: %lu", guest_regs->guest_arch);
-    return NATIVE_BRIDGE_GUEST_STATE_ACCESSOR_ERROR_UNSUPPORTED_ARCH;
-  }
-  memcpy(&guest_regs->regs_arm64.x, &state->x, sizeof(guest_regs->regs_arm64.x));
-  memcpy(&guest_regs->regs_arm64.sp, &state->sp, sizeof(guest_regs->regs_arm64.sp));
-  memcpy(&guest_regs->regs_arm64.ip, &state->insn_addr, sizeof(guest_regs->regs_arm64.ip));
-  memcpy(&guest_regs->regs_arm64.v, &state->v, sizeof(guest_regs->regs_arm64.v));
-  return 0;
-}
 }  // namespace berberis
diff --git a/guest_state/arm64/guest_state_arch.cc b/guest_state/arm64/guest_state_arch.cc
index 3018a90d..1e7f9670 100644
--- a/guest_state/arm64/guest_state_arch.cc
+++ b/guest_state/arm64/guest_state_arch.cc
@@ -99,4 +99,10 @@ std::size_t GetThreadStateFlagOffset() {
   return offsetof(ThreadState, cpu.flags);
 }
 
+GuestAddr GetGuestAddrRangeEnd() {
+  // We only support up to 47-bit addresses on Linux.
+  // Note that addresses with 48th bit set are only used on the kernel side.
+  return GuestAddr{1} << 47;
+}
+
 }  // namespace berberis
diff --git a/guest_state/include/berberis/guest_state/guest_addr.h b/guest_state/include/berberis/guest_state/guest_addr.h
index 411bd827..517e0e58 100644
--- a/guest_state/include/berberis/guest_state/guest_addr.h
+++ b/guest_state/include/berberis/guest_state/guest_addr.h
@@ -25,6 +25,7 @@ namespace berberis {
 using GuestAddr = uintptr_t;
 
 constexpr GuestAddr kNullGuestAddr = {};
+GuestAddr GetGuestAddrRangeEnd();
 
 template <typename T>
 inline GuestAddr ToGuestAddr(T* addr) {
diff --git a/guest_state/riscv64/get_cpu_state.cc b/guest_state/riscv64/get_cpu_state.cc
index 52bada89..9538bf99 100644
--- a/guest_state/riscv64/get_cpu_state.cc
+++ b/guest_state/riscv64/get_cpu_state.cc
@@ -14,14 +14,29 @@
  * limitations under the License.
  */
 
-#include "berberis/base/logging.h"
 #include "berberis/guest_state/get_cpu_state_opaque.h"
-#include "berberis/guest_state/guest_state_arch.h"
-#include "berberis/guest_state/guest_state_opaque.h"
 #include "native_bridge_support/guest_state_accessor/accessor.h"
 
+#include "berberis/base/logging.h"
+#include "berberis/guest_state/guest_state_arch.h"
+
+#include <cstddef>
+#include <cstring>
+
 namespace berberis {
 
+int GetCpuState(NativeBridgeGuestRegs* guest_regs, const CPUState* state) {
+  if (guest_regs->guest_arch != NATIVE_BRIDGE_ARCH_RISCV64) {
+    ALOGE("The guest architecture is unmatched: %lu", guest_regs->guest_arch);
+    return NATIVE_BRIDGE_GUEST_STATE_ACCESSOR_ERROR_UNSUPPORTED_ARCH;
+  }
+  memcpy(&guest_regs->regs_riscv64.x, &state->x, sizeof(guest_regs->regs_riscv64.x));
+  memcpy(&guest_regs->regs_riscv64.f, &state->f, sizeof(guest_regs->regs_riscv64.f));
+  memcpy(&guest_regs->regs_riscv64.v, &state->v, sizeof(guest_regs->regs_riscv64.v));
+  memcpy(&guest_regs->regs_riscv64.ip, &state->insn_addr, sizeof(guest_regs->regs_riscv64.ip));
+  return 0;
+}
+
 extern "C" __attribute__((visibility("default"))) int LoadGuestStateRegisters(
     const void* guest_state_data,
     size_t guest_state_data_size,
@@ -34,15 +49,4 @@ extern "C" __attribute__((visibility("default"))) int LoadGuestStateRegisters(
   return GetCpuState(guest_regs, &(static_cast<const ThreadState*>(guest_state_data))->cpu);
 }
 
-int GetCpuState(NativeBridgeGuestRegs* guest_regs, const CPUState* state) {
-  if (guest_regs->guest_arch != NATIVE_BRIDGE_ARCH_RISCV64) {
-    ALOGE("The guest architecture is unmatched: %lu", guest_regs->guest_arch);
-    return NATIVE_BRIDGE_GUEST_STATE_ACCESSOR_ERROR_UNSUPPORTED_ARCH;
-  }
-  memcpy(&guest_regs->regs_riscv64.x, &state->x, sizeof(guest_regs->regs_riscv64.x));
-  memcpy(&guest_regs->regs_riscv64.f, &state->f, sizeof(guest_regs->regs_riscv64.f));
-  memcpy(&guest_regs->regs_riscv64.v, &state->v, sizeof(guest_regs->regs_riscv64.v));
-  memcpy(&guest_regs->regs_riscv64.ip, &state->insn_addr, sizeof(guest_regs->regs_riscv64.ip));
-  return 0;
-}
 }  // namespace berberis
diff --git a/guest_state/riscv64/guest_state_arch.cc b/guest_state/riscv64/guest_state_arch.cc
index 48f2a6f5..2d43e0b7 100644
--- a/guest_state/riscv64/guest_state_arch.cc
+++ b/guest_state/riscv64/guest_state_arch.cc
@@ -115,4 +115,10 @@ std::size_t GetThreadStateFlagOffset() {
   CHECK(false);
 }
 
+GuestAddr GetGuestAddrRangeEnd() {
+  // We only support up to 47-bit addresses on Linux.
+  // Note that addresses with 48th bit set are only used on the kernel side.
+  return GuestAddr{1} << 47;
+}
+
 }  // namespace berberis
diff --git a/heavy_optimizer/riscv64/heavy_optimize_region.cc b/heavy_optimizer/riscv64/heavy_optimize_region.cc
index 1d1de652..dfd2ee25 100644
--- a/heavy_optimizer/riscv64/heavy_optimize_region.cc
+++ b/heavy_optimizer/riscv64/heavy_optimize_region.cc
@@ -44,7 +44,7 @@ std::tuple<GuestAddr, bool, size_t> HeavyOptimizeRegion(GuestAddr pc,
   size_t number_of_instructions = 0;
 
   while (number_of_instructions != params.max_number_of_instructions &&
-         !frontend.IsRegionEndReached()) {
+         frontend.GetInsnAddr() < params.end_pc && !frontend.IsRegionEndReached()) {
     frontend.StartInsn();
     auto size = decoder.Decode(ToHostAddr<uint16_t>(frontend.GetInsnAddr()));
     if (!frontend.success()) {
@@ -58,7 +58,7 @@ std::tuple<GuestAddr, bool, size_t> HeavyOptimizeRegion(GuestAddr pc,
   auto stop_pc = frontend.GetInsnAddr();
   frontend.Finalize(stop_pc);
 
-  if (IsConfigFlagSet(kVerboseTranslation)) {
+  if (IsConfigFlagSet(kVerboseTranslation) || IsConfigFlagSet(kPrintTranslatedAddrs)) {
     // Trace only after all the potential failure points.
     TRACE("Heavy optimizing 0x%lx (%lu bytes)", pc, stop_pc - pc);
   }
diff --git a/heavy_optimizer/riscv64/include/berberis/heavy_optimizer/riscv64/heavy_optimize_region.h b/heavy_optimizer/riscv64/include/berberis/heavy_optimizer/riscv64/heavy_optimize_region.h
index 39cb3cee..e03568ea 100644
--- a/heavy_optimizer/riscv64/include/berberis/heavy_optimizer/riscv64/heavy_optimize_region.h
+++ b/heavy_optimizer/riscv64/include/berberis/heavy_optimizer/riscv64/heavy_optimize_region.h
@@ -17,7 +17,8 @@
 #ifndef BERBERIS_HEAVY_OPTIMIZER_RISCV64_HEAVY_OPTIMIZE_REGION_H_
 #define BERBERIS_HEAVY_OPTIMIZER_RISCV64_HEAVY_OPTIMIZE_REGION_H_
 
-#include <cstdint>
+#include <cstddef>
+#include <limits>
 #include <tuple>
 
 #include "berberis/assembler/machine_code.h"
@@ -33,6 +34,7 @@ struct HeavyOptimizeParams {
   // of room for optimzations within this range. Thus this limitation has very little to no impact
   // on the generated code quality.
   size_t max_number_of_instructions = 200;
+  GuestAddr end_pc = GetGuestAddrRangeEnd();
 };
 
 std::tuple<GuestAddr, bool, size_t> HeavyOptimizeRegion(
diff --git a/heavy_optimizer/riscv64/inline_intrinsic.h b/heavy_optimizer/riscv64/inline_intrinsic.h
index e8d6980f..2b9e7870 100644
--- a/heavy_optimizer/riscv64/inline_intrinsic.h
+++ b/heavy_optimizer/riscv64/inline_intrinsic.h
@@ -266,9 +266,9 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
             typename Result,
             typename Callback,
             typename... Args>
-  friend Result intrinsics::bindings::ProcessBindings(Callback callback,
-                                                      Result def_result,
-                                                      Args&&... args);
+  friend constexpr Result intrinsics::bindings::ProcessBindings(Callback callback,
+                                                                Result def_result,
+                                                                Args&&... args);
 
   template <auto kIntrinsicTemplateName,
             auto kMacroInstructionTemplateName,
@@ -328,19 +328,19 @@ class TryBindingBasedInlineIntrinsicForHeavyOptimizer {
     using CPUIDRestriction = AsmCallInfo::CPUIDRestriction;
     if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX>) {
       if (!host_platform::kHasAVX) {
-        return false;
+        return {};
       }
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>) {
       if (!host_platform::kHasBMI) {
-        return false;
+        return {};
       }
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>) {
       if (!host_platform::kHasLZCNT) {
-        return false;
+        return {};
       }
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>) {
       if (!host_platform::kHasPOPCNT) {
-        return false;
+        return {};
       }
     } else if constexpr (std::is_same_v<CPUIDRestriction,
                                         intrinsics::bindings::NoCPUIDRestriction>) {
diff --git a/interpreter/riscv64/interpreter-VLoadIndexedArgs.cc b/interpreter/riscv64/interpreter-VLoadIndexedArgs.cc
index 6dd0f19d..867ca887 100644
--- a/interpreter/riscv64/interpreter-VLoadIndexedArgs.cc
+++ b/interpreter/riscv64/interpreter-VLoadIndexedArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadIndexedArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VLoadStrideArgs.cc b/interpreter/riscv64/interpreter-VLoadStrideArgs.cc
index ab8d78c5..71bbd85e 100644
--- a/interpreter/riscv64/interpreter-VLoadStrideArgs.cc
+++ b/interpreter/riscv64/interpreter-VLoadStrideArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadStrideArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VLoadUnitStrideArgs.cc b/interpreter/riscv64/interpreter-VLoadUnitStrideArgs.cc
index 63168fbd..628924a7 100644
--- a/interpreter/riscv64/interpreter-VLoadUnitStrideArgs.cc
+++ b/interpreter/riscv64/interpreter-VLoadUnitStrideArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadUnitStrideArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VOpFVfArgs.cc b/interpreter/riscv64/interpreter-VOpFVfArgs.cc
index 4701cef8..620e11f2 100644
--- a/interpreter/riscv64/interpreter-VOpFVfArgs.cc
+++ b/interpreter/riscv64/interpreter-VOpFVfArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpFVfArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VOpFVvArgs.cc b/interpreter/riscv64/interpreter-VOpFVvArgs.cc
index 7b99809c..98cccb60 100644
--- a/interpreter/riscv64/interpreter-VOpFVvArgs.cc
+++ b/interpreter/riscv64/interpreter-VOpFVvArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpFVvArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VOpIViArgs.cc b/interpreter/riscv64/interpreter-VOpIViArgs.cc
index f6ff4df1..dd106b6c 100644
--- a/interpreter/riscv64/interpreter-VOpIViArgs.cc
+++ b/interpreter/riscv64/interpreter-VOpIViArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIViArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VOpIVvArgs.cc b/interpreter/riscv64/interpreter-VOpIVvArgs.cc
index 5fe0e03c..a805058a 100644
--- a/interpreter/riscv64/interpreter-VOpIVvArgs.cc
+++ b/interpreter/riscv64/interpreter-VOpIVvArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIVvArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VOpIVxArgs.cc b/interpreter/riscv64/interpreter-VOpIVxArgs.cc
index f8cbecf7..9da2e60a 100644
--- a/interpreter/riscv64/interpreter-VOpIVxArgs.cc
+++ b/interpreter/riscv64/interpreter-VOpIVxArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIVxArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VOpMVvArgs.cc b/interpreter/riscv64/interpreter-VOpMVvArgs.cc
index d3bd73d6..dcc0a17c 100644
--- a/interpreter/riscv64/interpreter-VOpMVvArgs.cc
+++ b/interpreter/riscv64/interpreter-VOpMVvArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpMVvArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VOpMVxArgs.cc b/interpreter/riscv64/interpreter-VOpMVxArgs.cc
index 4dc7d6dc..2bb5b11e 100644
--- a/interpreter/riscv64/interpreter-VOpMVxArgs.cc
+++ b/interpreter/riscv64/interpreter-VOpMVxArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpMVxArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VStoreIndexedArgs.cc b/interpreter/riscv64/interpreter-VStoreIndexedArgs.cc
index 1d8eb0ee..6138aee0 100644
--- a/interpreter/riscv64/interpreter-VStoreIndexedArgs.cc
+++ b/interpreter/riscv64/interpreter-VStoreIndexedArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreIndexedArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VStoreStrideArgs.cc b/interpreter/riscv64/interpreter-VStoreStrideArgs.cc
index 9e32bb75..8e878f15 100644
--- a/interpreter/riscv64/interpreter-VStoreStrideArgs.cc
+++ b/interpreter/riscv64/interpreter-VStoreStrideArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreStrideArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter-VStoreUnitStrideArgs.cc b/interpreter/riscv64/interpreter-VStoreUnitStrideArgs.cc
index d12c16e8..daa5816d 100644
--- a/interpreter/riscv64/interpreter-VStoreUnitStrideArgs.cc
+++ b/interpreter/riscv64/interpreter-VStoreUnitStrideArgs.cc
@@ -14,13 +14,12 @@
  * limitations under the License.
  */
 
-#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
-#undef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 #include "interpreter.h"
 
+#ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
 namespace berberis {
 
 template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreUnitStrideArgs& args);
 
 }  // namespace berberis
-#endif
+#endif  // BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
diff --git a/interpreter/riscv64/interpreter.h b/interpreter/riscv64/interpreter.h
index 32961743..aa9d5876 100644
--- a/interpreter/riscv64/interpreter.h
+++ b/interpreter/riscv64/interpreter.h
@@ -4826,32 +4826,21 @@ void inline Interpreter::NanBoxAndSetFpReg<Interpreter::Float64>(uint8_t reg, Fp
 }
 
 #ifdef BERBERIS_RISCV64_INTERPRETER_SEPARATE_INSTANTIATION_OF_VECTOR_OPERATIONS
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
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadIndexedArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VLoadStrideArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(
+    const Decoder::VLoadUnitStrideArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpFVfArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpFVvArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIViArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIVvArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpIVxArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpMVvArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VOpMVxArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreIndexedArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(const Decoder::VStoreStrideArgs& args);
+extern template void SemanticsPlayer<Interpreter>::OpVector(
+    const Decoder::VStoreUnitStrideArgs& args);
 #endif
 
 }  // namespace berberis
diff --git a/interpreter/riscv64/interpreter_test.cc b/interpreter/riscv64/interpreter_test.cc
index 100c72d2..ae8cf640 100644
--- a/interpreter/riscv64/interpreter_test.cc
+++ b/interpreter/riscv64/interpreter_test.cc
@@ -1861,8 +1861,8 @@ class Riscv64InterpreterTest : public ::testing::Test {
             }
           } else {
             __uint128_t v8 = state_.cpu.v[8];
-            SIMD128Register affected_part{expected_result[0] &
-                                          (mask[0] & kFractionMaskInt8[vlmul - 4] | skip_mask[0])};
+            SIMD128Register affected_part{
+                expected_result[0] & ((mask[0] & kFractionMaskInt8[vlmul - 4]) | skip_mask[0])};
             SIMD128Register masked_part{expected_inactive[0] & ~mask[0] & ~skip_mask[0] &
                                         kFractionMaskInt8[vlmul - 4]};
             SIMD128Register tail_part{(vta ? kAgnosticResult : kUndisturbedResult) &
diff --git a/intrinsics/Android.bp b/intrinsics/Android.bp
index f36a67ef..3279c5fe 100644
--- a/intrinsics/Android.bp
+++ b/intrinsics/Android.bp
@@ -81,6 +81,39 @@ genrule {
     cmd: "$(location gen_asm) --text-assembler $(out) $(in)",
 }
 
+genrule {
+    name: "libberberis_verifier_assembler_gen_headers_riscv64",
+    out: [
+        "gen_verifier_assembler_common_riscv-inl.h",
+        "gen_verifier_assembler_riscv64-inl.h",
+    ],
+    srcs: [":libberberis_assembler_gen_inputs_riscv64"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --verifier-assembler $(out) $(in)",
+}
+
+genrule {
+    name: "libberberis_verifier_assembler_gen_headers_x86_32",
+    out: [
+        "gen_verifier_assembler_common_x86-inl.h",
+        "gen_verifier_assembler_x86_32-inl.h",
+    ],
+    srcs: [":libberberis_assembler_gen_inputs_x86_32"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --verifier-assembler $(out) $(in)",
+}
+
+genrule {
+    name: "libberberis_verifier_assembler_gen_headers_x86_64",
+    out: [
+        "gen_verifier_assembler_common_x86-inl.h",
+        "gen_verifier_assembler_x86_64-inl.h",
+    ],
+    srcs: [":libberberis_assembler_gen_inputs_x86_64"],
+    tools: ["gen_asm"],
+    cmd: "$(location gen_asm) --verifier-assembler $(out) $(in)",
+}
+
 filegroup {
     name: "libberberis_machine_ir_intrinsic_binding_riscv64_to_x86_64",
     srcs: ["riscv64_to_x86_64/machine_ir_intrinsic_binding.json"],
@@ -192,6 +225,7 @@ cc_binary_host {
                 "libberberis_intrinsics_gen_public_headers_riscv64_to_x86_64",
                 "libberberis_macro_assembler_gen_intrinsics_headers_riscv64_to_x86_64",
                 "libberberis_text_assembler_gen_headers_x86_64",
+                "libberberis_verifier_assembler_gen_headers_x86_64",
             ],
             header_libs: ["libberberis_macro_assembler_headers_riscv64_to_x86_64"],
             static_libs: ["libberberis_macro_assembler_riscv64_to_x86_64"],
@@ -382,8 +416,11 @@ cc_library_static {
     name: "libberberis_macro_assembler_riscv64_to_x86_64",
     defaults: ["berberis_defaults_64"],
     host_supported: true,
-    srcs: ["riscv64_to_x86_64/macro_assembler.cc"],
-    header_libs: ["libberberis_macro_assembler_headers_riscv64_to_x86_64"],
+    srcs: ["riscv64_to_x86_64/constants_pool.cc"],
+    header_libs: [
+        "libberberis_assembler_headers",
+        "libberberis_macro_assembler_headers_riscv64_to_x86_64",
+    ],
 }
 
 cc_library_static {
@@ -408,7 +445,10 @@ cc_test_library {
     name: "libberberis_intrinsics_unit_tests",
     defaults: ["berberis_defaults"],
     host_supported: true,
-    srcs: ["simd_register_test.cc"],
+    srcs: [
+        "enum_from_template_type_test.cc",
+        "simd_register_test.cc",
+    ],
     arch: {
         x86: {
             srcs: [
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h
index a8a58590..95ac1a8a 100644
--- a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/intrinsics_float.h
@@ -146,7 +146,7 @@ inline Float64 Negative(const Float64& v) {
   return result;
 }
 
-inline Float32 FPRound(const Float32& value, uint32_t round_control) {
+inline Float32 FPRound(const Float32& value, int round_control) {
   // RISC-V doesn't have any instructions that can be used used to implement FPRound efficiently
   // because conversion to integer returns an actual int (int32_t or int64_t) and that fails for
   // values that are larger than 1/ϵ – but all such values couldn't have fraction parts which means
@@ -224,7 +224,7 @@ inline Float32 FPRound(const Float32& value, uint32_t round_control) {
   return result;
 }
 
-inline Float64 FPRound(const Float64& value, uint32_t round_control) {
+inline Float64 FPRound(const Float64& value, int round_control) {
   // RISC-V doesn't have any instructions that can be used used to implement FPRound efficiently
   // because conversion to integer returns an actual int (int32_t or int64_t) and that fails for
   // values that are larger than 1/ϵ – but all such values couldn't have fraction parts which means
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h
index 49e8a1e9..3fc0ae2e 100644
--- a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/text_assembler_riscv.h
@@ -191,18 +191,24 @@ class TextAssembler {
 
   TextAssembler(int indent, FILE* out) : indent_(indent), out_(out) {}
 
-  // Verify CPU vendor and SSE restrictions.
-  template <typename CPUIDRestriction>
-  void CheckCPUIDRestriction() {}
-
   // Translate CPU restrictions into string.
   template <typename CPUIDRestriction>
   static constexpr const char* kCPUIDRestrictionString =
       DerivedAssemblerType::template CPUIDRestrictionToString<CPUIDRestriction>();
 
-  Register gpr_a{};
-  Register gpr_c{};
-  Register gpr_d{};
+  // RISC-V doesn't have “a”, “b”, “c”, or “d” registers, but we need these to be able to compile
+  // the code generator.
+  template <char kConstraint>
+  class UnsupportedRegister {
+   public:
+    UnsupportedRegister operator=(Register) {
+      LOG_ALWAYS_FATAL("Registers of the class “%c” don't exist on RISC-V", kConstraint);
+    }
+  };
+  UnsupportedRegister<'a'> gpr_a;
+  UnsupportedRegister<'b'> gpr_b;
+  UnsupportedRegister<'c'> gpr_c;
+  UnsupportedRegister<'d'> gpr_d;
   // Note: stack pointer is not reflected in list of arguments, intrinsics use
   // it implicitly.
   Register gpr_s{Register::kStackPointer};
diff --git a/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/verifier_assembler_riscv.h b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/verifier_assembler_riscv.h
new file mode 100644
index 00000000..0b0ca381
--- /dev/null
+++ b/intrinsics/all_to_riscv64/include/berberis/intrinsics/all_to_riscv64/verifier_assembler_riscv.h
@@ -0,0 +1,233 @@
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
+#ifndef BERBERIS_INTRINSICS_COMMON_TO_RISCV_VERIFIER_ASSEMBLER_COMMON_H_
+#define BERBERIS_INTRINSICS_COMMON_TO_RISCV_VERIFIER_ASSEMBLER_COMMON_H_
+
+#include <array>
+#include <cstdint>
+#include <cstdio>
+#include <string>
+
+#include "berberis/assembler/riscv.h"
+#include "berberis/base/checks.h"
+#include "berberis/base/config.h"
+#include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/all_to_riscv64/intrinsics_bindings.h"
+#include "berberis/intrinsics/common/intrinsics_bindings.h"
+
+namespace berberis {
+
+namespace riscv {
+
+template <typename DerivedAssemblerType>
+class VerifierAssembler {
+ public:
+  using Condition = riscv::Condition;
+  using Csr = riscv::Csr;
+  using Rounding = riscv::Rounding;
+
+  struct Label {
+    size_t id;
+    bool bound = false;
+  };
+
+  template <typename RegisterType, typename ImmediateType>
+  struct Operand;
+
+  class Register {
+   public:
+    constexpr Register() : arg_no_(kNoRegister) {}
+    constexpr Register(int arg_no) : arg_no_(arg_no) {}
+    constexpr Register(int arg_no,
+                       [[maybe_unused]] intrinsics::bindings::RegBindingKind binding_kind)
+        : arg_no_(arg_no) {}
+
+    int arg_no() const {
+      CHECK_NE(arg_no_, kNoRegister);
+      return arg_no_;
+    }
+
+    friend bool operator==(const Register&, const Register&) = default;
+
+    static constexpr int kNoRegister = -1;
+    static constexpr int kStackPointer = -2;
+    // Used in Operand to deal with references to scratch area.
+    static constexpr int kScratchPointer = -3;
+    static constexpr int kZeroRegister = -4;
+
+   private:
+    template <typename RegisterType, typename ImmediateType>
+    friend struct Operand;
+
+    // Register number created during creation of assembler call.
+    // See arg['arm_register'] in _gen_c_intrinsic_body in gen_intrinsics.py
+    //
+    // Default value (-1) means it's not assigned yet (thus couldn't be used).
+    int arg_no_;
+  };
+
+  class FpRegister {
+   public:
+    constexpr FpRegister() : arg_no_(kNoRegister) {}
+    constexpr FpRegister(int arg_no) : arg_no_(arg_no) {}
+    int arg_no() const {
+      CHECK_NE(arg_no_, kNoRegister);
+      return arg_no_;
+    }
+
+    friend bool operator==(const FpRegister&, const FpRegister&) = default;
+
+   private:
+    // Register number created during creation of assembler call.
+    // See arg['arm_register'] in _gen_c_intrinsic_body in gen_intrinsics.py
+    //
+    // Default value (-1) means it's not assigned yet (thus couldn't be used).
+    static constexpr int kNoRegister = -1;
+    int arg_no_;
+  };
+
+  template <typename RegisterType, typename ImmediateType>
+  struct Operand {
+    RegisterType base{0};
+    ImmediateType disp = 0;
+  };
+
+  using BImmediate = riscv::BImmediate;
+  using CsrImmediate = riscv::CsrImmediate;
+  using IImmediate = riscv::IImmediate;
+  using Immediate = riscv::Immediate;
+  using JImmediate = riscv::JImmediate;
+  using Shift32Immediate = riscv::Shift32Immediate;
+  using Shift64Immediate = riscv::Shift64Immediate;
+  using PImmediate = riscv::PImmediate;
+  using SImmediate = riscv::SImmediate;
+  using UImmediate = riscv::UImmediate;
+
+  using XRegister = Register;
+
+  constexpr VerifierAssembler() {}
+
+  // Verify CPU vendor and SSE restrictions.
+  template <typename CPUIDRestriction>
+  constexpr void CheckCPUIDRestriction() {}
+
+  constexpr void CheckFlagsBinding([[maybe_unused]] bool expect_flags) {}
+
+  constexpr void CheckAppropriateDefEarlyClobbers() {}
+
+  constexpr void CheckLabelsAreBound() {}
+
+  // Translate CPU restrictions into string.
+  template <typename CPUIDRestriction>
+  static constexpr const char* kCPUIDRestrictionString =
+      DerivedAssemblerType::template CPUIDRestrictionToString<CPUIDRestriction>();
+
+  // RISC-V doesn't have “a”, “b”, “c”, or “d” registers, but we need these to be able to compile
+  // the code generator.
+  template <char kConstraint>
+  class UnsupportedRegister {
+   public:
+    UnsupportedRegister operator=(Register) {
+      LOG_ALWAYS_FATAL("Registers of the class “%c” don't exist on RISC-V", kConstraint);
+    }
+  };
+
+  UnsupportedRegister<'a'> gpr_a;
+  UnsupportedRegister<'b'> gpr_b;
+  UnsupportedRegister<'c'> gpr_c;
+  UnsupportedRegister<'d'> gpr_d;
+  // Note: stack pointer is not reflected in list of arguments, intrinsics use
+  // it implicitly.
+  Register gpr_s{Register::kStackPointer};
+  // Used in Operand as pseudo-register to temporary operand.
+  Register gpr_scratch{Register::kScratchPointer};
+  // Intrinsics which use these constants receive it via additional parameter - and
+  // we need to know if it's needed or not.
+  Register gpr_macroassembler_constants{};
+  bool need_gpr_macroassembler_constants() const { return need_gpr_macroassembler_constants_; }
+
+  Register gpr_macroassembler_scratch{};
+  bool need_gpr_macroassembler_scratch() const { return need_gpr_macroassembler_scratch_; }
+  Register gpr_macroassembler_scratch2{};
+
+  Register zero{Register::kZeroRegister};
+
+  constexpr void Bind([[maybe_unused]] Label* label) {}
+
+  // Currently label_ is meaningless. Verifier assembler does not yet have a need for it.
+  constexpr Label* MakeLabel() { return &label_; }
+
+  template <typename... Args>
+  constexpr void Byte([[maybe_unused]] Args... args) {
+    static_assert((std::is_same_v<Args, uint8_t> && ...));
+  }
+
+  template <typename... Args>
+  constexpr void TwoByte([[maybe_unused]] Args... args) {
+    static_assert((std::is_same_v<Args, uint16_t> && ...));
+  }
+
+  template <typename... Args>
+  constexpr void FourByte([[maybe_unused]] Args... args) {
+    static_assert((std::is_same_v<Args, uint32_t> && ...));
+  }
+
+  template <typename... Args>
+  constexpr void EigthByte([[maybe_unused]] Args... args) {
+    static_assert((std::is_same_v<Args, uint64_t> && ...));
+  }
+
+  constexpr void P2Align([[maybe_unused]] uint32_t m) {}
+
+// Instructions.
+#include "gen_verifier_assembler_common_riscv-inl.h"  // NOLINT generated file
+
+ protected:
+  template <typename CPUIDRestriction>
+  static constexpr const char* CPUIDRestrictionToString() {
+    if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::NoCPUIDRestriction>) {
+      return nullptr;
+    } else {
+      static_assert(kDependentTypeFalse<CPUIDRestriction>);
+    }
+  }
+
+  bool need_gpr_macroassembler_constants_ = false;
+  bool need_gpr_macroassembler_scratch_ = false;
+
+  template <typename Arg>
+  constexpr void RegisterDef([[maybe_unused]] Arg reg) {}
+
+  template <typename Arg>
+  constexpr void RegisterUse([[maybe_unused]] Arg reg) {}
+
+  constexpr void EndInstruction() {}
+
+ private:
+  Label label_;
+
+  VerifierAssembler(const VerifierAssembler&) = delete;
+  VerifierAssembler(VerifierAssembler&&) = delete;
+  void operator=(const VerifierAssembler&) = delete;
+  void operator=(VerifierAssembler&&) = delete;
+};
+
+}  // namespace riscv
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_COMMON_TO_RISCV_VERIFIER_ASSEMBLER_COMMON_H_
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
index b9facd6b..51cd64ee 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h
@@ -74,6 +74,8 @@ class AX {
   static constexpr bool kIsImmediate = false;
   static constexpr bool kIsImplicitReg = true;
   static constexpr char kAsRegister = 'a';
+  template <typename MachineInsnArch>
+  static constexpr auto kRegClass = MachineInsnArch::kAX;
 };
 
 class EAX {
@@ -88,7 +90,7 @@ class EAX {
 
 class RAX {
  public:
-  using Type = uint32_t;
+  using Type = uint64_t;
   static constexpr bool kIsImmediate = false;
   static constexpr bool kIsImplicitReg = true;
   static constexpr char kAsRegister = 'a';
@@ -96,6 +98,26 @@ class RAX {
   static constexpr auto kRegClass = MachineInsnArch::kRAX;
 };
 
+class EBX {
+ public:
+  using Type = uint32_t;
+  static constexpr bool kIsImmediate = false;
+  static constexpr bool kIsImplicitReg = true;
+  static constexpr char kAsRegister = 'b';
+  template <typename MachineInsnArch>
+  static constexpr auto kRegClass = MachineInsnArch::kEBX;
+};
+
+class RBX {
+ public:
+  using Type = uint64_t;
+  static constexpr bool kIsImmediate = false;
+  static constexpr bool kIsImplicitReg = true;
+  static constexpr char kAsRegister = 'b';
+  template <typename MachineInsnArch>
+  static constexpr auto kRegClass = MachineInsnArch::kRBX;
+};
+
 class CL {
  public:
   using Type = uint8_t;
@@ -126,7 +148,7 @@ class ECX {
 
 class RCX {
  public:
-  using Type = uint32_t;
+  using Type = uint64_t;
   static constexpr bool kIsImmediate = false;
   static constexpr bool kIsImplicitReg = true;
   static constexpr char kAsRegister = 'c';
@@ -162,7 +184,7 @@ class EDX {
 
 class RDX {
  public:
-  using Type = uint32_t;
+  using Type = uint64_t;
   static constexpr bool kIsImmediate = false;
   static constexpr bool kIsImplicitReg = true;
   static constexpr char kAsRegister = 'd';
@@ -290,6 +312,7 @@ class HasAVX512VPOPCNTDQ;
 class HasBMI;
 class HasBMI2;
 class HasCLMUL;
+class HasCLMULAVX;
 class HasCMOV;
 class HasCMPXCHG16B;
 class HasCMPXCHG8B;
@@ -314,6 +337,7 @@ class HasSSE4a;
 class HasSSSE3;
 class HasTBM;
 class HasVAES;
+class HasVPCLMULQD;
 class HasX87;
 class HasCustomCapability;
 class IsAuthenticAMD;
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float.h
index f402cd9a..9764d431 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float.h
@@ -171,7 +171,7 @@ inline WrappedFloatType<FloatType> FPRoundTiesAway(WrappedFloatType<FloatType> v
   return FPRound(value, FE_TONEAREST);
 }
 
-inline Float32 FPRound(const Float32& value, uint32_t round_control) {
+inline Float32 FPRound(const Float32& value, int round_control) {
   Float32 result;
   switch (round_control) {
     case FE_HOSTROUND:
@@ -199,7 +199,7 @@ inline Float32 FPRound(const Float32& value, uint32_t round_control) {
   return result;
 }
 
-inline Float64 FPRound(const Float64& value, uint32_t round_control) {
+inline Float64 FPRound(const Float64& value, int round_control) {
   Float64 result;
   switch (round_control) {
     case FE_HOSTROUND:
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h
index 85c6c383..ea2a230c 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h
@@ -16,8 +16,6 @@
 
 #ifndef DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
 #error This file is supposed to be included from berberis/intrinsics/macro_assembler-inl.h
-#else
-#undef DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
 #endif
 
 using Condition = typename Assembler::Condition;
@@ -27,6 +25,7 @@ using Register = typename Assembler::Register;
 using ScaleFactor = typename Assembler::ScaleFactor;
 using XMMRegister = typename Assembler::XMMRegister;
 
+using Float16 = intrinsics::Float16;
 using Float32 = intrinsics::Float32;
 using Float64 = intrinsics::Float64;
 
@@ -74,104 +73,109 @@ static constexpr bool kUnsignedIntType = kFormatIs<IntType, uint8_t, uint16_t, u
 template <typename FloatType>
 static constexpr bool kFloatType = kFormatIs<FloatType, Float32, Float64>;
 
-#define DEFINE_EXPAND_INSTRUCTION(Declare_dest, Declare_src)         \
-  template <typename format_out, typename format_in>                 \
-  std::enable_if_t<kIntType<format_out> && kIntType<format_in> &&    \
-                   sizeof(format_in) <= sizeof(format_out)>          \
-  Expand(Declare_dest, Declare_src) {                                \
-    if constexpr (std::is_same_v<decltype(dest), decltype(src)> &&   \
-                  sizeof(format_out) == sizeof(format_in)) {         \
-      if (dest == src) {                                             \
-        return;                                                      \
-      }                                                              \
-    }                                                                \
-    if constexpr (kFormatIs<format_out, int8_t, uint8_t> &&          \
-                  kFormatIs<format_in, int8_t, uint8_t>) {           \
-      Assembler::Movb(dest, src);                                    \
-    } else if constexpr (kFormatIs<format_out, int16_t, uint16_t> && \
-                         kFormatIs<format_in, int8_t>) {             \
-      if constexpr (std::is_same_v<decltype(dest), decltype(src)>) { \
-        if (dest == Assembler::gpr_a && src == Assembler::gpr_a) {   \
-          Assembler::Cbw();                                          \
-          return;                                                    \
-        }                                                            \
-      }                                                              \
-      Assembler::Movsxbw(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int16_t, uint16_t> && \
-                         kFormatIs<format_in, uint8_t>) {            \
-      Assembler::Movzxbw(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int16_t, uint16_t> && \
-                         kFormatIs<format_in, int16_t, uint16_t>) {  \
-      Assembler::Movw(dest, src);                                    \
-    } else if constexpr (kFormatIs<format_out, int32_t, uint32_t> && \
-                         kFormatIs<format_in, int8_t>) {             \
-      Assembler::Movsxbl(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int32_t, uint32_t> && \
-                         kFormatIs<format_in, uint8_t>) {            \
-      Assembler::Movzxbl(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int32_t, uint32_t> && \
-                         kFormatIs<format_in, int16_t>) {            \
-      if constexpr (std::is_same_v<decltype(dest), decltype(src)>) { \
-        if (dest == Assembler::gpr_a && src == Assembler::gpr_a) {   \
-          Assembler::Cwde();                                         \
-          return;                                                    \
-        }                                                            \
-      }                                                              \
-      Assembler::Movsxwl(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int32_t, uint32_t> && \
-                         kFormatIs<format_in, uint16_t>) {           \
-      Assembler::Movzxwl(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int32_t, uint32_t> && \
-                         kFormatIs<format_in, int32_t, uint32_t>) {  \
-      Assembler::Movl(dest, src);                                    \
-    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> && \
-                         kFormatIs<format_in, int8_t>) {             \
-      Assembler::Movsxbq(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> && \
-                         kFormatIs<format_in, uint8_t>) {            \
-      Assembler::Movzxbl(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> && \
-                         kFormatIs<format_in, int16_t>) {            \
-      Assembler::Movsxwq(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> && \
-                         kFormatIs<format_in, uint16_t>) {           \
-      Assembler::Movzxwl(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> && \
-                         kFormatIs<format_in, int32_t>) {            \
-      if constexpr (std::is_same_v<decltype(dest), decltype(src)>) { \
-        if (dest == Assembler::gpr_a && src == Assembler::gpr_a) {   \
-          Assembler::Cdqe();                                         \
-          return;                                                    \
-        }                                                            \
-      }                                                              \
-      Assembler::Movsxlq(dest, src);                                 \
-    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> && \
-                         kFormatIs<format_in, uint32_t>) {           \
-      Assembler::Movl(dest, src);                                    \
-    } else {                                                         \
-      Assembler::Movq(dest, src);                                    \
-    }                                                                \
+template <typename FloatType>
+static constexpr bool kFloatType16_32_64 = kFormatIs<FloatType, Float16, Float32, Float64>;
+
+#define DEFINE_EXPAND_INSTRUCTION(Declare_dest, Declare_src)                \
+  template <typename format_out, typename format_in>                        \
+  constexpr std::enable_if_t<kIntType<format_out> && kIntType<format_in> && \
+                             sizeof(format_in) <= sizeof(format_out)>       \
+  Expand(Declare_dest, Declare_src) {                                       \
+    if constexpr (std::is_same_v<decltype(dest), decltype(src)> &&          \
+                  sizeof(format_out) == sizeof(format_in)) {                \
+      if (dest == src) {                                                    \
+        return;                                                             \
+      }                                                                     \
+    }                                                                       \
+    if constexpr (kFormatIs<format_out, int8_t, uint8_t> &&                 \
+                  kFormatIs<format_in, int8_t, uint8_t>) {                  \
+      Assembler::Movb(dest, src);                                           \
+    } else if constexpr (kFormatIs<format_out, int16_t, uint16_t> &&        \
+                         kFormatIs<format_in, int8_t>) {                    \
+      if constexpr (std::is_same_v<decltype(dest), decltype(src)>) {        \
+        if (dest == Assembler::gpr_a && src == Assembler::gpr_a) {          \
+          Assembler::Cbw();                                                 \
+          return;                                                           \
+        }                                                                   \
+      }                                                                     \
+      Assembler::Movsxbw(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int16_t, uint16_t> &&        \
+                         kFormatIs<format_in, uint8_t>) {                   \
+      Assembler::Movzxbw(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int16_t, uint16_t> &&        \
+                         kFormatIs<format_in, int16_t, uint16_t>) {         \
+      Assembler::Movw(dest, src);                                           \
+    } else if constexpr (kFormatIs<format_out, int32_t, uint32_t> &&        \
+                         kFormatIs<format_in, int8_t>) {                    \
+      Assembler::Movsxbl(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int32_t, uint32_t> &&        \
+                         kFormatIs<format_in, uint8_t>) {                   \
+      Assembler::Movzxbl(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int32_t, uint32_t> &&        \
+                         kFormatIs<format_in, int16_t>) {                   \
+      if constexpr (std::is_same_v<decltype(dest), decltype(src)>) {        \
+        if (dest == Assembler::gpr_a && src == Assembler::gpr_a) {          \
+          Assembler::Cwde();                                                \
+          return;                                                           \
+        }                                                                   \
+      }                                                                     \
+      Assembler::Movsxwl(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int32_t, uint32_t> &&        \
+                         kFormatIs<format_in, uint16_t>) {                  \
+      Assembler::Movzxwl(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int32_t, uint32_t> &&        \
+                         kFormatIs<format_in, int32_t, uint32_t>) {         \
+      Assembler::Movl(dest, src);                                           \
+    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> &&        \
+                         kFormatIs<format_in, int8_t>) {                    \
+      Assembler::Movsxbq(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> &&        \
+                         kFormatIs<format_in, uint8_t>) {                   \
+      Assembler::Movzxbl(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> &&        \
+                         kFormatIs<format_in, int16_t>) {                   \
+      Assembler::Movsxwq(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> &&        \
+                         kFormatIs<format_in, uint16_t>) {                  \
+      Assembler::Movzxwl(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> &&        \
+                         kFormatIs<format_in, int32_t>) {                   \
+      if constexpr (std::is_same_v<decltype(dest), decltype(src)>) {        \
+        if (dest == Assembler::gpr_a && src == Assembler::gpr_a) {          \
+          Assembler::Cdqe();                                                \
+          return;                                                           \
+        }                                                                   \
+      }                                                                     \
+      Assembler::Movsxlq(dest, src);                                        \
+    } else if constexpr (kFormatIs<format_out, int64_t, uint64_t> &&        \
+                         kFormatIs<format_in, uint32_t>) {                  \
+      Assembler::Movl(dest, src);                                           \
+    } else {                                                                \
+      Assembler::Movq(dest, src);                                           \
+    }                                                                       \
   }
 DEFINE_EXPAND_INSTRUCTION(Register dest, Operand src)
 DEFINE_EXPAND_INSTRUCTION(Register dest, Register src)
 #undef DEFINE_EXPAND_INSTRUCTION
 
-#define DEFINE_INT_INSTRUCTION(                                            \
-    insn_name, asm_name, insn_siffix, type_check, parameters, arguments)   \
-  template <typename format>                                               \
-  std::enable_if_t<type_check<format>> insn_name##insn_siffix parameters { \
-    if constexpr (kFormatIs<format, int8_t, uint8_t>) {                    \
-      Assembler::asm_name##b##insn_siffix arguments;                       \
-    } else if constexpr (kFormatIs<format, int16_t, uint16_t>) {           \
-      Assembler::asm_name##w##insn_siffix arguments;                       \
-    } else if constexpr (kFormatIs<format, int32_t, uint32_t>) {           \
-      Assembler::asm_name##l##insn_siffix arguments;                       \
-    } else {                                                               \
-      Assembler::asm_name##q##insn_siffix arguments;                       \
-    }                                                                      \
+#define DEFINE_INT_INSTRUCTION(                                                      \
+    insn_name, asm_name, insn_siffix, type_check, parameters, arguments)             \
+  template <typename format>                                                         \
+  constexpr std::enable_if_t<type_check<format>> insn_name##insn_siffix parameters { \
+    if constexpr (kFormatIs<format, int8_t, uint8_t>) {                              \
+      Assembler::asm_name##b##insn_siffix arguments;                                 \
+    } else if constexpr (kFormatIs<format, int16_t, uint16_t>) {                     \
+      Assembler::asm_name##w##insn_siffix arguments;                                 \
+    } else if constexpr (kFormatIs<format, int32_t, uint32_t>) {                     \
+      Assembler::asm_name##l##insn_siffix arguments;                                 \
+    } else {                                                                         \
+      Assembler::asm_name##q##insn_siffix arguments;                                 \
+    }                                                                                \
   }
 DEFINE_INT_INSTRUCTION(CmpXchg, CmpXchg, , kIntType, (Operand dest, Register src), (dest, src))
 DEFINE_INT_INSTRUCTION(CmpXchg, CmpXchg, , kIntType, (Register dest, Register src), (dest, src))
+DEFINE_INT_INSTRUCTION(Lea, Lea, , kIntTypeWLQ, (Register dest, Operand src), (dest, src))
+DEFINE_INT_INSTRUCTION(LockXadd, LockXadd, , kIntType, (Operand dest, Register src), (dest, src))
 DEFINE_INT_INSTRUCTION(LockCmpXchg,
                        LockCmpXchg,
                        ,
@@ -254,16 +258,16 @@ DEFINE_SHIFT_INSTRUCTION(Shr)
 #undef DEFINE_INT_INSTRUCTION
 #undef DEFINE_SHIFT_INSTRUCTION
 
-#define DEFINE_INT_INSTRUCTION(insn_name, parameters, arguments) \
-  template <typename format>                                     \
-  std::enable_if_t<kIntTypeWLQ<format>> insn_name parameters {   \
-    if constexpr (kFormatIs<format, int16_t, uint16_t>) {        \
-      Assembler::insn_name##w arguments;                         \
-    } else if constexpr (kFormatIs<format, int32_t, uint32_t>) { \
-      Assembler::insn_name##l arguments;                         \
-    } else {                                                     \
-      Assembler::insn_name##q arguments;                         \
-    }                                                            \
+#define DEFINE_INT_INSTRUCTION(insn_name, parameters, arguments)         \
+  template <typename format>                                             \
+  constexpr std::enable_if_t<kIntTypeWLQ<format>> insn_name parameters { \
+    if constexpr (kFormatIs<format, int16_t, uint16_t>) {                \
+      Assembler::insn_name##w arguments;                                 \
+    } else if constexpr (kFormatIs<format, int32_t, uint32_t>) {         \
+      Assembler::insn_name##l arguments;                                 \
+    } else {                                                             \
+      Assembler::insn_name##q arguments;                                 \
+    }                                                                    \
   }
 DEFINE_INT_INSTRUCTION(Cmov, (Condition cond, Register dest, Operand src), (cond, dest, src))
 DEFINE_INT_INSTRUCTION(Cmov, (Condition cond, Register dest, Register src), (cond, dest, src))
@@ -290,7 +294,9 @@ DEFINE_BIT_INSTRUCTION(Tzcnt)
 // Note: Mov<int32_t> from one register to that same register doesn't zero-out top 32bits,
 // like real Movq would! If you want that effect then use Expand<tnt32_t, int32_t> instead!
 template <typename format>
-std::enable_if_t<kIntType<format>> Mov(Register dest, Register src) {
+constexpr  // hmmmm
+    std::enable_if_t<kIntType<format>>
+    Mov(Register dest, Register src) {
   if (dest == src) {
     return;
   }
@@ -305,18 +311,18 @@ std::enable_if_t<kIntType<format>> Mov(Register dest, Register src) {
   }
 }
 
-#define DEFINE_INT_INSTRUCTION(insn_name, parameters, arguments)     \
-  template <typename target_format>                                  \
-  std::enable_if_t<kIntTypeBW<target_format>> insn_name parameters { \
-    if constexpr (kFormatIs<target_format, int8_t>) {                \
-      Assembler::insn_name##sswb arguments;                          \
-    } else if constexpr (kFormatIs<target_format, uint8_t>) {        \
-      Assembler::insn_name##uswb arguments;                          \
-    } else if constexpr (kFormatIs<target_format, int16_t>) {        \
-      Assembler::insn_name##ssdw arguments;                          \
-    } else {                                                         \
-      Assembler::insn_name##usdw arguments;                          \
-    }                                                                \
+#define DEFINE_INT_INSTRUCTION(insn_name, parameters, arguments)               \
+  template <typename target_format>                                            \
+  constexpr std::enable_if_t<kIntTypeBW<target_format>> insn_name parameters { \
+    if constexpr (kFormatIs<target_format, int8_t>) {                          \
+      Assembler::insn_name##sswb arguments;                                    \
+    } else if constexpr (kFormatIs<target_format, uint8_t>) {                  \
+      Assembler::insn_name##uswb arguments;                                    \
+    } else if constexpr (kFormatIs<target_format, int16_t>) {                  \
+      Assembler::insn_name##ssdw arguments;                                    \
+    } else {                                                                   \
+      Assembler::insn_name##usdw arguments;                                    \
+    }                                                                          \
   }
 #define DEFINE_XMM_INT_INSTRUCTIONS_GROUP(insn_name)                                             \
   DEFINE_INT_INSTRUCTION(P##insn_name, (XMMRegister dest, XMMRegister src), (dest, src))         \
@@ -327,18 +333,18 @@ std::enable_if_t<kIntType<format>> Mov(Register dest, Register src) {
       Vp##insn_name, (XMMRegister dest, XMMRegister src1, Operand src2), (dest, src1, src2))
 DEFINE_XMM_INT_INSTRUCTIONS_GROUP(ack)
 #undef DEFINE_INT_INSTRUCTION
-#define DEFINE_INT_INSTRUCTION(insn_name, parameters, arguments)    \
-  template <typename format>                                        \
-  std::enable_if_t<kUnsignedIntType<format>> insn_name parameters { \
-    if constexpr (kFormatIs<format, uint8_t>) {                     \
-      Assembler::insn_name##bw arguments;                           \
-    } else if constexpr (kFormatIs<format, uint16_t>) {             \
-      Assembler::insn_name##wd arguments;                           \
-    } else if constexpr (kFormatIs<format, uint32_t>) {             \
-      Assembler::insn_name##dq arguments;                           \
-    } else {                                                        \
-      Assembler::insn_name##qdq arguments;                          \
-    }                                                               \
+#define DEFINE_INT_INSTRUCTION(insn_name, parameters, arguments)              \
+  template <typename format>                                                  \
+  constexpr std::enable_if_t<kUnsignedIntType<format>> insn_name parameters { \
+    if constexpr (kFormatIs<format, uint8_t>) {                               \
+      Assembler::insn_name##bw arguments;                                     \
+    } else if constexpr (kFormatIs<format, uint16_t>) {                       \
+      Assembler::insn_name##wd arguments;                                     \
+    } else if constexpr (kFormatIs<format, uint32_t>) {                       \
+      Assembler::insn_name##dq arguments;                                     \
+    } else {                                                                  \
+      Assembler::insn_name##qdq arguments;                                    \
+    }                                                                         \
   }
 DEFINE_XMM_INT_INSTRUCTIONS_GROUP(unpckh)
 DEFINE_XMM_INT_INSTRUCTIONS_GROUP(unpckl)
@@ -348,7 +354,7 @@ DEFINE_XMM_INT_INSTRUCTIONS_GROUP(unpckl)
 #define DEFINE_XMM_INT_INSTRUCTION(                                           \
     insn_name, asm_name, type_check, parameters, arguments, signed, unsigned) \
   template <typename format>                                                  \
-  std::enable_if_t<type_check<format>> insn_name parameters {                 \
+  constexpr std::enable_if_t<type_check<format>> insn_name parameters {       \
     if constexpr (kFormatIs<format, int8_t>) {                                \
       Assembler::asm_name##signed##b arguments;                               \
     } else if constexpr (kFormatIs<format, uint8_t>) {                        \
@@ -427,11 +433,98 @@ DEFINE_XMM_INT_INSTRUCTIONS_GROUP(sub, sub, kIntType, , )
 DEFINE_XMM_INT_INSTRUCTIONS_GROUP(sl, sl, kIntTypeWLQ, l, l)
 DEFINE_XMM_INT_INSTRUCTIONS_GROUP(sr, sr, kIntTypePsr, a, l)
 #undef DEFINE_XMM_INT_INSTRUCTIONS_GROUP
+DEFINE_XMM_INT_INSTRUCTION(Pextr,
+                           Pextr,
+                           kIntType,
+                           (Register dest, XMMRegister src, int8_t imm),
+                           (dest, src, imm),
+                           , )
+DEFINE_XMM_INT_INSTRUCTION(Pextr,
+                           Pextr,
+                           kIntType,
+                           (Operand dest, XMMRegister src, int8_t imm),
+                           (dest, src, imm),
+                           , )
+DEFINE_XMM_INT_INSTRUCTION(Pinsr,
+                           Pinsr,
+                           kIntType,
+                           (XMMRegister dest, Register src, int8_t imm),
+                           (dest, src, imm),
+                           , )
+DEFINE_XMM_INT_INSTRUCTION(Pinsr,
+                           Pinsr,
+                           kIntType,
+                           (XMMRegister dest, Operand src, int8_t imm),
+                           (dest, src, imm),
+                           , )
+DEFINE_XMM_INT_INSTRUCTION(Vpextr,
+                           Vpextr,
+                           kIntType,
+                           (Register dest, XMMRegister src, int8_t imm),
+                           (dest, src, imm),
+                           , )
+DEFINE_XMM_INT_INSTRUCTION(Vpextr,
+                           Vpextr,
+                           kIntType,
+                           (Operand dest, XMMRegister src, int8_t imm),
+                           (dest, src, imm),
+                           , )
+DEFINE_XMM_INT_INSTRUCTION(Vpinsr,
+                           Vpinsr,
+                           kIntType,
+                           (XMMRegister dest, XMMRegister src1, Register src2, int8_t imm),
+                           (dest, src1, src2, imm),
+                           , )
+DEFINE_XMM_INT_INSTRUCTION(Vpinsr,
+                           Vpinsr,
+                           kIntType,
+                           (XMMRegister dest, XMMRegister src1, Operand src2, int8_t imm),
+                           (dest, src1, src2, imm),
+                           , )
 #undef DEFINE_XMM_INT_INSTRUCTION
 
+#define DEFINE_XMM_INT_EXPAND(insn_name, asm_name, parameters, arguments)                    \
+  template <typename FormatFrom, typename FormatTo>                                          \
+  constexpr std::enable_if_t<kIntTypeBWL<FormatFrom> && kIntTypeWLQ<FormatTo> &&             \
+                             std::is_signed_v<FormatFrom> == std::is_signed_v<FormatTo> &&   \
+                             sizeof(FormatFrom) < sizeof(FormatTo)>                          \
+      insn_name parameters {                                                                 \
+    if constexpr (kFormatIs<FormatFrom, int8_t> && kFormatIs<FormatTo, int16_t>) {           \
+      Assembler::asm_name##sxbw arguments;                                                   \
+    } else if constexpr (kFormatIs<FormatFrom, uint8_t> && kFormatIs<FormatTo, uint16_t>) {  \
+      Assembler::asm_name##zxbw arguments;                                                   \
+    } else if constexpr (kFormatIs<FormatFrom, int8_t> && kFormatIs<FormatTo, int32_t>) {    \
+      Assembler::asm_name##sxbd arguments;                                                   \
+    } else if constexpr (kFormatIs<FormatFrom, uint8_t> && kFormatIs<FormatTo, uint32_t>) {  \
+      Assembler::asm_name##zxbd arguments;                                                   \
+    } else if constexpr (kFormatIs<FormatFrom, int8_t> && kFormatIs<FormatTo, int64_t>) {    \
+      Assembler::asm_name##sxbq arguments;                                                   \
+    } else if constexpr (kFormatIs<FormatFrom, uint8_t> && kFormatIs<FormatTo, uint64_t>) {  \
+      Assembler::asm_name##zxbq arguments;                                                   \
+    } else if constexpr (kFormatIs<FormatFrom, int16_t> && kFormatIs<FormatTo, int32_t>) {   \
+      Assembler::asm_name##sxwd arguments;                                                   \
+    } else if constexpr (kFormatIs<FormatFrom, uint16_t> && kFormatIs<FormatTo, uint32_t>) { \
+      Assembler::asm_name##zxwd arguments;                                                   \
+    } else if constexpr (kFormatIs<FormatFrom, int16_t> && kFormatIs<FormatTo, int64_t>) {   \
+      Assembler::asm_name##sxwq arguments;                                                   \
+    } else if constexpr (kFormatIs<FormatFrom, uint16_t> && kFormatIs<FormatTo, uint64_t>) { \
+      Assembler::asm_name##zxwq arguments;                                                   \
+    } else if constexpr (kFormatIs<FormatFrom, int32_t> && kFormatIs<FormatTo, int64_t>) {   \
+      Assembler::asm_name##sxdq arguments;                                                   \
+    } else {                                                                                 \
+      static_assert(kFormatIs<FormatFrom, uint32_t> && kFormatIs<FormatTo, uint64_t>);       \
+      Assembler::asm_name##zxdq arguments;                                                   \
+    }                                                                                        \
+  }
+DEFINE_XMM_INT_EXPAND(Pmov, Pmov, (XMMRegister dest, XMMRegister src), (dest, src))
+DEFINE_XMM_INT_EXPAND(Pmov, Pmov, (XMMRegister dest, Operand src), (dest, src))
+DEFINE_XMM_INT_EXPAND(Vpmov, Vpmov, (XMMRegister dest, XMMRegister src), (dest, src))
+DEFINE_XMM_INT_EXPAND(Vpmov, Vpmov, (XMMRegister dest, Operand src), (dest, src))
+#undef DEFINE_XMM_INT_EXPAND
+
 #define DEFINE_MOVS_INSTRUCTION(insn_name, opt_check, parameters, arguments) \
   template <typename format>                                                 \
-  std::enable_if_t<kFloatType<format>> insn_name parameters {                \
+  constexpr std::enable_if_t<kFloatType<format>> insn_name parameters {      \
     if constexpr (kFormatIs<format, Float32>) {                              \
       opt_check;                                                             \
       Assembler::insn_name##s arguments;                                     \
@@ -454,14 +547,14 @@ DEFINE_MOVS_INSTRUCTION(Vmovs,
                         (dest, src1, src2))
 #undef DEFINE_MOVS_INSTRUCTION
 
-#define DEFINE_XMM_MOV_INSTRUCTION(insn_name, parameters, arguments) \
-  template <typename format>                                         \
-  std::enable_if_t<kFloatType<format>> insn_name parameters {        \
-    if constexpr (kFormatIs<format, Float32>) {                      \
-      Assembler::insn_name##d arguments;                             \
-    } else {                                                         \
-      Assembler::insn_name##q arguments;                             \
-    }                                                                \
+#define DEFINE_XMM_MOV_INSTRUCTION(insn_name, parameters, arguments)    \
+  template <typename format>                                            \
+  constexpr std::enable_if_t<kFloatType<format>> insn_name parameters { \
+    if constexpr (kFormatIs<format, Float32>) {                         \
+      Assembler::insn_name##d arguments;                                \
+    } else {                                                            \
+      Assembler::insn_name##q arguments;                                \
+    }                                                                   \
   }
 DEFINE_XMM_MOV_INSTRUCTION(Mov, (XMMRegister dest, Operand src), (dest, src))
 DEFINE_XMM_MOV_INSTRUCTION(Mov, (Operand dest, XMMRegister src), (dest, src))
@@ -473,19 +566,20 @@ DEFINE_XMM_MOV_INSTRUCTION(Vmov, (XMMRegister dest, Register src), (dest, src))
 DEFINE_XMM_MOV_INSTRUCTION(Vmov, (Register dest, XMMRegister src), (dest, src))
 #undef DEFINE_XMM_MOV_INSTRUCTION
 
-#define DEFINE_XMM_CVT_INSTRUCTION(insn_name, parameters, arguments)                           \
-  template <typename FormatFrom, typename FormatTo>                                            \
-  std::enable_if_t<kFloatType<FormatFrom> && kSignedIntType<FormatTo> && kIntTypeLQ<FormatTo>> \
-      insn_name parameters {                                                                   \
-    if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, int32_t>) {            \
-      Assembler::insn_name##ss2sil arguments;                                                  \
-    } else if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, int64_t>) {     \
-      Assembler::insn_name##ss2siq(dest, src);                                                 \
-    } else if constexpr (kFormatIs<FormatFrom, Float64> && kFormatIs<FormatTo, int32_t>) {     \
-      Assembler::insn_name##sd2sil(dest, src);                                                 \
-    } else {                                                                                   \
-      Assembler::insn_name##sd2siq(dest, src);                                                 \
-    }                                                                                          \
+#define DEFINE_XMM_CVT_INSTRUCTION(insn_name, parameters, arguments)                       \
+  template <typename FormatFrom, typename FormatTo>                                        \
+  constexpr std::enable_if_t<kFloatType<FormatFrom> && kSignedIntType<FormatTo> &&         \
+                             kIntTypeLQ<FormatTo>>                                         \
+      insn_name parameters {                                                               \
+    if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, int32_t>) {        \
+      Assembler::insn_name##ss2sil arguments;                                              \
+    } else if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, int64_t>) { \
+      Assembler::insn_name##ss2siq(dest, src);                                             \
+    } else if constexpr (kFormatIs<FormatFrom, Float64> && kFormatIs<FormatTo, int32_t>) { \
+      Assembler::insn_name##sd2sil(dest, src);                                             \
+    } else {                                                                               \
+      Assembler::insn_name##sd2siq(dest, src);                                             \
+    }                                                                                      \
   }
 DEFINE_XMM_CVT_INSTRUCTION(Cvt, (Register dest, XMMRegister src), (dest, src))
 DEFINE_XMM_CVT_INSTRUCTION(Cvt, (Register dest, Operand src), (dest, src))
@@ -497,19 +591,20 @@ DEFINE_XMM_CVT_INSTRUCTION(Vcvtt, (Register dest, XMMRegister src), (dest, src))
 DEFINE_XMM_CVT_INSTRUCTION(Vcvtt, (Register dest, Operand src), (dest, src))
 #undef DEFINE_XMM_CVT_INSTRUCTION
 
-#define DEFINE_XMM_CVT_INSTRUCTION(insn_name, parameters, arguments)                             \
-  template <typename FormatFrom, typename FormatTo>                                              \
-  std::enable_if_t<kSignedIntType<FormatFrom> && kIntTypeWL<FormatFrom> && kFloatType<FormatTo>> \
-      insn_name parameters {                                                                     \
-    if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, int32_t>) {              \
-      Assembler::insn_name##sil2ss arguments;                                                    \
-    } else if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, int64_t>) {       \
-      Assembler::insn_name##siq2ss(dest, src);                                                   \
-    } else if constexpr (kFormatIs<FormatFrom, Float64> && kFormatIs<FormatTo, int32_t>) {       \
-      Assembler::insn_name##sil2sd(dest, src);                                                   \
-    } else {                                                                                     \
-      Assembler::insn_name##siq2sd(dest, src);                                                   \
-    }                                                                                            \
+#define DEFINE_XMM_CVT_INSTRUCTION(insn_name, parameters, arguments)                       \
+  template <typename FormatFrom, typename FormatTo>                                        \
+  constexpr std::enable_if_t<kSignedIntType<FormatFrom> && kIntTypeWL<FormatFrom> &&       \
+                             kFloatType<FormatTo>>                                         \
+      insn_name parameters {                                                               \
+    if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, int32_t>) {        \
+      Assembler::insn_name##sil2ss arguments;                                              \
+    } else if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, int64_t>) { \
+      Assembler::insn_name##siq2ss(dest, src);                                             \
+    } else if constexpr (kFormatIs<FormatFrom, Float64> && kFormatIs<FormatTo, int32_t>) { \
+      Assembler::insn_name##sil2sd(dest, src);                                             \
+    } else {                                                                               \
+      Assembler::insn_name##siq2sd(dest, src);                                             \
+    }                                                                                      \
   }
 DEFINE_XMM_CVT_INSTRUCTION(Cvt, (XMMRegister dest, Register src), (dest, src))
 DEFINE_XMM_CVT_INSTRUCTION(Cvt, (XMMRegister dest, Operand src), (dest, src))
@@ -517,23 +612,35 @@ DEFINE_XMM_CVT_INSTRUCTION(Vcvt, (XMMRegister dest, Register src), (dest, src))
 DEFINE_XMM_CVT_INSTRUCTION(Vcvt, (XMMRegister dest, Operand src), (dest, src))
 #undef DEFINE_XMM_CVT_INSTRUCTION
 
-#define DEFINE_XMM_CVT_INSTRUCTION(insn_name, insn_suffix, parameters, arguments)   \
-  template <typename FormatFrom, typename FormatTo>                                 \
-  std::enable_if_t<kFloatType<FormatFrom> && kFloatType<FormatTo> &&                \
-                   sizeof(FormatFrom) != sizeof(FormatTo)>                          \
-      insn_name##insn_suffix parameters {                                           \
-    if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, Float64>) { \
-      Assembler::insn_name##insn_suffix##s2##insn_suffix##d arguments;              \
-    } else {                                                                        \
-      Assembler::insn_name##insn_suffix##d2##insn_suffix##s arguments;              \
-    }                                                                               \
+#define DEFINE_XMM_CVT_INSTRUCTION(insn_name, insn_suffix, parameters, arguments)              \
+  template <typename FormatFrom, typename FormatTo>                                            \
+  constexpr std::enable_if_t<kFloatType16_32_64<FormatFrom> && kFloatType16_32_64<FormatTo> && \
+                             sizeof(FormatFrom) != sizeof(FormatTo)>                           \
+      insn_name##insn_suffix parameters {                                                      \
+    if constexpr (kFormatIs<FormatFrom, Float16> && kFormatIs<FormatTo, Float32>) {            \
+      Assembler::insn_name##insn_suffix##h2##insn_suffix##s arguments;                         \
+    } else if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, Float16>) {     \
+      Assembler::insn_name##insn_suffix##s2##insn_suffix##h arguments;                         \
+    } else if constexpr (kFormatIs<FormatFrom, Float32> && kFormatIs<FormatTo, Float64>) {     \
+      Assembler::insn_name##insn_suffix##s2##insn_suffix##d arguments;                         \
+    } else {                                                                                   \
+      static_assert(kFormatIs<FormatFrom, Float64> && kFormatIs<FormatTo, Float32>);           \
+      Assembler::insn_name##insn_suffix##d2##insn_suffix##s arguments;                         \
+    }                                                                                          \
   }
 DEFINE_XMM_CVT_INSTRUCTION(Cvt, p, (XMMRegister dest, XMMRegister src), (dest, src))
 DEFINE_XMM_CVT_INSTRUCTION(Cvt, p, (XMMRegister dest, Operand src), (dest, src))
 DEFINE_XMM_CVT_INSTRUCTION(Cvt, s, (XMMRegister dest, XMMRegister src), (dest, src))
 DEFINE_XMM_CVT_INSTRUCTION(Cvt, s, (XMMRegister dest, Operand src), (dest, src))
-DEFINE_XMM_CVT_INSTRUCTION(Vcvt, p, (XMMRegister dest, XMMRegister src), (dest, src))
+DEFINE_XMM_CVT_INSTRUCTION(Vcvt,
+                           p,
+                           (XMMRegister dest, XMMRegister src, auto... extra),
+                           (dest, src, extra...))
 DEFINE_XMM_CVT_INSTRUCTION(Vcvt, p, (XMMRegister dest, Operand src), (dest, src))
+DEFINE_XMM_CVT_INSTRUCTION(Vcvt,
+                           p,
+                           (Operand dest, XMMRegister src, auto... extra),
+                           (dest, src, extra...))
 DEFINE_XMM_CVT_INSTRUCTION(Vcvt,
                            s,
                            (XMMRegister dest, XMMRegister src1, XMMRegister src2),
@@ -544,14 +651,14 @@ DEFINE_XMM_CVT_INSTRUCTION(Vcvt,
                            (dest, src1, src2))
 #undef DEFINE_XMM_CVT_INSTRUCTION
 
-#define DEFINE_XMM_FLOAT_INSTRUCTION(insn_name, parameters, arguments) \
-  template <typename format>                                           \
-  std::enable_if_t<kFloatType<format>> insn_name parameters {          \
-    if constexpr (kFormatIs<format, Float32>) {                        \
-      Assembler::insn_name##s arguments;                               \
-    } else {                                                           \
-      Assembler::insn_name##d arguments;                               \
-    }                                                                  \
+#define DEFINE_XMM_FLOAT_INSTRUCTION(insn_name, parameters, arguments)  \
+  template <typename format>                                            \
+  constexpr std::enable_if_t<kFloatType<format>> insn_name parameters { \
+    if constexpr (kFormatIs<format, Float32>) {                         \
+      Assembler::insn_name##s arguments;                                \
+    } else {                                                            \
+      Assembler::insn_name##d arguments;                                \
+    }                                                                   \
   }
 DEFINE_XMM_FLOAT_INSTRUCTION(Comis, (XMMRegister dest, Operand src), (dest, src))
 DEFINE_XMM_FLOAT_INSTRUCTION(Comis, (XMMRegister dest, XMMRegister src), (dest, src))
@@ -696,3 +803,21 @@ DEFINE_XMM_FLOAT_INSTRUCTION(Vrounds,
                              (XMMRegister dest, Operand src, uint8_t imm8),
                              (dest, src, imm8))
 #undef DEFINE_XMM_FLOAT_INSTRUCTION
+
+// Import useful assembler machinery besides instruction names.
+// gen_assembler_x86_64-using-inl.h – used for importing instructions – is autogenerated from JSON.
+using Assembler::Bind;
+using Assembler::MakeLabel;
+
+using Assembler::Byte;
+using Assembler::EigthByte;
+using Assembler::FourByte;
+using Assembler::P2Align;
+using Assembler::TwoByte;
+
+using Assembler::gpr_a;
+using Assembler::gpr_b;
+using Assembler::gpr_c;
+using Assembler::gpr_d;
+
+using Assembler::gpr_s;
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
index 79b9a372..15ea0572 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/text_assembler_x86_32_and_x86_64.h
@@ -252,6 +252,7 @@ class TextAssembler {
   // something else.
   // If they are not coming as arguments then using them is compile-time error!
   Register gpr_a{Register::kNoRegister};
+  Register gpr_b{Register::kNoRegister};
   Register gpr_c{Register::kNoRegister};
   Register gpr_d{Register::kNoRegister};
   // Note: stack pointer is not reflected in list of arguments, intrinsics use
@@ -271,20 +272,6 @@ class TextAssembler {
   bool need_gpr_macroassembler_scratch() const { return need_gpr_macroassembler_scratch_; }
   Register gpr_macroassembler_scratch2{Register::kNoRegister};
 
-  bool need_avx = false;
-  bool need_avx2 = false;
-  bool need_bmi = false;
-  bool need_bmi2 = false;
-  bool need_fma = false;
-  bool need_fma4 = false;
-  bool need_lzcnt = false;
-  bool need_popcnt = false;
-  bool need_sse3 = false;
-  bool need_ssse3 = false;
-  bool need_sse4_1 = false;
-  bool need_sse4_2 = false;
-  bool has_custom_capability = false;
-
   void Bind(Label* label) {
     CHECK_EQ(label->bound, false);
     fprintf(out_, "%*s\"%zd:\\n\"\n", indent_ + 2, "", label->id);
@@ -336,38 +323,6 @@ class TextAssembler {
     fprintf(out_, "%*s\".p2align %u\\n\"\n", indent_ + 2, "", m);
   }
 
-  // Verify CPU vendor and SSE restrictions.
-  template <typename CPUIDRestriction>
-  void CheckCPUIDRestriction() {
-    constexpr bool expect_bmi = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>;
-    constexpr bool expect_fma = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA>;
-    constexpr bool expect_fma4 = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA4>;
-    constexpr bool expect_lzcnt = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>;
-    constexpr bool expect_popcnt =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>;
-    constexpr bool expect_avx =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX> || expect_fma || expect_fma4;
-    constexpr bool expect_sse4_2 =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_2> || expect_avx;
-    constexpr bool expect_sse4_1 =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_1> || expect_sse4_2;
-    constexpr bool expect_ssse3 =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSSE3> || expect_sse4_1;
-    constexpr bool expect_sse3 =
-        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE3> || expect_ssse3;
-
-    CHECK_EQ(expect_avx, need_avx);
-    CHECK_EQ(expect_bmi, need_bmi);
-    CHECK_EQ(expect_fma, need_fma);
-    CHECK_EQ(expect_fma4, need_fma4);
-    CHECK_EQ(expect_lzcnt, need_lzcnt);
-    CHECK_EQ(expect_popcnt, need_popcnt);
-    CHECK_EQ(expect_sse3, need_sse3);
-    CHECK_EQ(expect_ssse3, need_ssse3);
-    CHECK_EQ(expect_sse4_1, need_sse4_1);
-    CHECK_EQ(expect_sse4_2, need_sse4_2);
-  }
-
   // Translate CPU restrictions into string.
   template <typename CPUIDRestriction>
   static constexpr const char* kCPUIDRestrictionString =
@@ -383,10 +338,20 @@ class TextAssembler {
       return nullptr;
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::IsAuthenticAMD>) {
       return "host_platform::kIsAuthenticAMD";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAES>) {
+      return "host_platform::kHasAES";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAESAVX>) {
+      return "host_platform::kHasAES && host_platform::kHasAVX";
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX>) {
       return "host_platform::kHasAVX";
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>) {
       return "host_platform::kHasBMI";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasF16C>) {
+      return "host_platform::kHasF16C";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasCLMUL>) {
+      return "host_platform::kHasCLMUL";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasCLMULAVX>) {
+      return "host_platform::kHasCLMUL && host_platform::kHasAVX";
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA>) {
       return "host_platform::kHasFMA";
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA4>) {
@@ -405,6 +370,10 @@ class TextAssembler {
       return "host_platform::kHasSSE4_2";
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSSE3>) {
       return "host_platform::kHasSSSE3";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasVAES>) {
+      return "host_platform::kHasVAES";
+    } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasVPCLMULQD>) {
+      return "host_platform::kHasVPCLMULQD";
     } else if constexpr (std::is_same_v<CPUIDRestriction,
                                         intrinsics::bindings::HasCustomCapability>) {
       return "host_platform::kHasCustomCapability";
@@ -447,64 +416,45 @@ class TextAssembler {
   constexpr static char kRsp[] = "%%rsp";
   using Register64Bit = RegisterTemplate<kRsp, 'q'>;
 
-  void SetRequiredFeatureAVX() {
-    need_avx = true;
-    SetRequiredFeatureSSE4_2();
-  }
+  void SetRequiredFeatureAESAVX() {}
 
-  void SetRequiredFeatureAVX2() {
-    need_avx2 = true;
-    SetRequiredFeatureAVX();
-  }
+  void SetRequiredFeatureAES() {}
 
-  void SetRequiredFeatureBMI() {
-    need_bmi = true;
-  }
+  void SetRequiredFeatureAVX() {}
 
-  void SetRequiredFeatureBMI2() {
-    need_bmi2 = true;
-  }
+  void SetRequiredFeatureAVX2() {}
 
-  void SetRequiredFeatureFMA() {
-    need_fma = true;
-    SetRequiredFeatureAVX();
-  }
+  void SetRequiredFeatureBMI() {}
 
-  void SetRequiredFeatureFMA4() {
-    need_fma4 = true;
-    SetRequiredFeatureAVX();
-  }
+  void SetRequiredFeatureBMI2() {}
 
-  void SetRequiredFeatureLZCNT() {
-    need_lzcnt = true;
-  }
+  void SetRequiredFeatureCLMULAVX() {}
 
-  void SetRequiredFeaturePOPCNT() {
-    need_popcnt = true;
-  }
+  void SetRequiredFeatureCLMUL() {}
 
-  void SetRequiredFeatureSSE3() {
-    need_sse3 = true;
-    // Note: we assume that SSE2 is always available thus we don't have have_sse2 or have_sse1
-    // variables.
-  }
+  void SetRequiredFeatureF16C() {}
 
-  void SetRequiredFeatureSSSE3() {
-    need_ssse3 = true;
-    SetRequiredFeatureSSE3();
-  }
+  void SetRequiredFeatureFMA() {}
 
-  void SetRequiredFeatureSSE4_1() {
-    need_sse4_1 = true;
-    SetRequiredFeatureSSSE3();
-  }
+  void SetRequiredFeatureFMA4() {}
 
-  void SetRequiredFeatureSSE4_2() {
-    need_sse4_2 = true;
-    SetRequiredFeatureSSE4_1();
-  }
+  void SetRequiredFeatureLZCNT() {}
+
+  void SetRequiredFeaturePOPCNT() {}
+
+  void SetRequiredFeatureSSE3() {}
+
+  void SetRequiredFeatureSSSE3() {}
+
+  void SetRequiredFeatureSSE4_1() {}
+
+  void SetRequiredFeatureSSE4_2() {}
+
+  void SetRequiredFeatureVAES() {}
+
+  void SetRequiredFeatureVPCLMULQD() {}
 
-  void SetHasCustomCapability() { has_custom_capability = true; }
+  void SetHasCustomCapability() {}
 
   template <typename... Args>
   void Instruction(const char* name, Condition cond, const Args&... args);
@@ -547,7 +497,7 @@ inline void TextAssembler<DerivedAssemblerType>::Instruction(const char* name,
                                                              Condition cond,
                                                              const Args&... args) {
   char name_with_condition[8] = {};
-  if (strcmp(name, "Cmovl") == 0 || strcmp(name, "Cmovq") == 0) {
+  if (strcmp(name, "Cmovw") == 0 || strcmp(name, "Cmovl") == 0 || strcmp(name, "Cmovq") == 0) {
     strcpy(name_with_condition, "Cmov");
   } else if (strcmp(name, "Jcc") == 0) {
     strcpy(name_with_condition, "J");
@@ -622,12 +572,12 @@ inline void TextAssembler<DerivedAssemblerType>::Instruction(const char* name,
             {"Lock Xaddw", "Lock; Xaddw"},
             {"Lock Xaddl", "Lock; Xaddl"},
             {"Lock Xaddq", "Lock; Xaddq"},
-            {"LockCmpXchg8b", "Lock; CmppXchg8b"},
-            {"LockCmpXchg16b", "Lock; CmppXchg16b"},
-            {"LockCmpXchgb", "Lock; CmppXchgb"},
-            {"LockCmpXchgl", "Lock; CmppXchgl"},
-            {"LockCmpXchgq", "Lock; CmppXchgq"},
-            {"LockCmpXchgw", "Lock; CmppXchgq"},
+            {"Lock CmpXchg8b", "Lock; CmpXchg8b"},
+            {"Lock CmpXchg16b", "Lock; CmpXchg16b"},
+            {"Lock CmpXchgb", "Lock; CmpXchgb"},
+            {"Lock CmpXchgl", "Lock; CmpXchgl"},
+            {"Lock CmpXchgq", "Lock; CmpXchgq"},
+            {"Lock CmpXchgw", "Lock; CmpXchgw"},
             // Our assembler has Pmov instruction which is supposed to pick the best
             // option - but currently we just map Pmov to Movaps.
             {"Pmov", "Movaps"},
diff --git a/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_and_x86_64.h b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_and_x86_64.h
new file mode 100644
index 00000000..713c8232
--- /dev/null
+++ b/intrinsics/all_to_x86_32_or_x86_64/include/berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_and_x86_64.h
@@ -0,0 +1,815 @@
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
+#ifndef BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_VERIFIER_ASSEMBLER_COMMON_H_
+#define BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_VERIFIER_ASSEMBLER_COMMON_H_
+
+#include <array>
+#include <cstdint>
+#include <cstdio>
+#include <string>
+
+#include "berberis/base/checks.h"
+#include "berberis/base/config.h"
+#include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/intrinsics_bindings.h"
+#include "berberis/intrinsics/common/intrinsics_bindings.h"
+
+namespace berberis {
+
+namespace x86_32_and_x86_64 {
+
+template <typename DerivedAssemblerType>
+class VerifierAssembler {
+ public:
+  // Condition class - 16 x86 conditions.
+  enum class Condition {
+    kOverflow = 0,
+    kNoOverflow = 1,
+    kBelow = 2,
+    kAboveEqual = 3,
+    kEqual = 4,
+    kNotEqual = 5,
+    kBelowEqual = 6,
+    kAbove = 7,
+    kNegative = 8,
+    kPositiveOrZero = 9,
+    kParityEven = 10,
+    kParityOdd = 11,
+    kLess = 12,
+    kGreaterEqual = 13,
+    kLessEqual = 14,
+    kGreater = 15,
+
+    // aka...
+    kCarry = kBelow,
+    kNotCarry = kAboveEqual,
+    kZero = kEqual,
+    kNotZero = kNotEqual,
+    kSign = kNegative,
+    kNotSign = kPositiveOrZero
+  };
+
+  enum ScaleFactor {
+    kTimesOne = 0,
+    kTimesTwo = 1,
+    kTimesFour = 2,
+    kTimesEight = 3,
+    // All our target systems use 32-bit pointers.
+    kTimesPointerSize = kTimesFour
+  };
+
+  struct Label {
+    size_t id;
+    int index = -1;
+    bool bound = false;
+  };
+
+  struct Operand;
+
+  class Register {
+   public:
+    constexpr Register(int arg_no)
+        : arg_no_(arg_no), binding_kind_(intrinsics::bindings::kUndefined) {}
+    constexpr Register(int arg_no, intrinsics::bindings::RegBindingKind binding_kind)
+        : arg_no_(arg_no), binding_kind_(binding_kind) {}
+
+    constexpr int arg_no() const {
+      CHECK_NE(arg_no_, kNoRegister);
+      return arg_no_;
+    }
+
+    constexpr bool register_initialised() const { return (arg_no_ != kNoRegister); }
+
+    constexpr bool operator==(const Register& other) const { return arg_no() == other.arg_no(); }
+    constexpr bool operator!=(const Register& other) const { return arg_no() != other.arg_no(); }
+
+    static constexpr int kNoRegister = -1;
+    static constexpr int kStackPointer = -2;
+    // Used in Operand to deal with references to scratch area.
+    static constexpr int kScratchPointer = -3;
+
+    constexpr intrinsics::bindings::RegBindingKind get_binding_kind() const {
+      return binding_kind_;
+    }
+
+   private:
+    friend struct Operand;
+
+    // Register number created during creation of assembler call.
+    // See arg['arm_register'] in _gen_c_intrinsic_body in gen_intrinsics.py
+    //
+    // Default value (-1) means it's not assigned yet (thus couldn't be used).
+    int arg_no_;
+    intrinsics::bindings::RegBindingKind binding_kind_;
+  };
+
+  class X87Register {
+   public:
+    constexpr X87Register(int arg_no) : arg_no_(arg_no) {}
+    int arg_no() const {
+      CHECK_NE(arg_no_, kNoRegister);
+      return arg_no_;
+    }
+
+    constexpr bool operator==(const X87Register& other) const { return arg_no_ == other.arg_no_; }
+    constexpr bool operator!=(const X87Register& other) const { return arg_no_ != other.arg_no_; }
+
+   private:
+    // Register number created during creation of assembler call.
+    // See arg['arm_register'] in _gen_c_intrinsic_body in gen_intrinsics.py
+    //
+    // Default value (-1) means it's not assigned yet (thus couldn't be used).
+    static constexpr int kNoRegister = -1;
+    int arg_no_;
+  };
+
+  template <int kBits>
+  class SIMDRegister {
+   public:
+    friend class SIMDRegister<384 - kBits>;
+    constexpr SIMDRegister(int arg_no)
+        : arg_no_(arg_no), binding_kind_(intrinsics::bindings::kUndefined) {}
+
+    constexpr SIMDRegister(int arg_no, intrinsics::bindings::RegBindingKind binding_kind)
+        : arg_no_(arg_no), binding_kind_(binding_kind) {}
+
+    constexpr int arg_no() const {
+      CHECK_NE(arg_no_, kNoRegister);
+      return arg_no_;
+    }
+
+    constexpr bool operator==(const SIMDRegister& other) const {
+      return arg_no() == other.arg_no();
+    }
+    constexpr bool operator!=(const SIMDRegister& other) const {
+      return arg_no() != other.arg_no();
+    }
+
+    constexpr auto To128Bit() const {
+      return std::enable_if_t<kBits != 128, SIMDRegister<128>>{arg_no_, binding_kind_};
+    }
+    constexpr auto To256Bit() const {
+      return std::enable_if_t<kBits != 256, SIMDRegister<256>>{arg_no_, binding_kind_};
+    }
+
+    constexpr intrinsics::bindings::RegBindingKind get_binding_kind() const {
+      return binding_kind_;
+    }
+
+   private:
+    // Register number created during creation of assembler call.
+    // See arg['arm_register'] in _gen_c_intrinsic_body in gen_intrinsics.py
+    //
+    // Default value (-1) means it's not assigned yet (thus couldn't be used).
+    static constexpr int kNoRegister = -1;
+    int arg_no_;
+    intrinsics::bindings::RegBindingKind binding_kind_;
+  };
+
+  using XMMRegister = SIMDRegister<128>;
+  using YMMRegister = SIMDRegister<256>;
+
+  using XRegister = XMMRegister;
+
+  struct Operand {
+    Register base = Register{Register::kNoRegister};
+    Register index = Register{Register::kNoRegister};
+    ScaleFactor scale = kTimesOne;
+    int32_t disp = 0;
+  };
+
+  constexpr VerifierAssembler() {}
+
+  // These start as Register::kNoRegister but can be changed if they are used as arguments to
+  // something else.
+  // If they are not coming as arguments then using them is compile-time error!
+  Register gpr_a{Register::kNoRegister};
+  Register gpr_b{Register::kNoRegister};
+  Register gpr_c{Register::kNoRegister};
+  Register gpr_d{Register::kNoRegister};
+  // Note: stack pointer is not reflected in list of arguments, intrinsics use
+  // it implicitly.
+  Register gpr_s{Register::kStackPointer};
+  // Used in Operand as pseudo-register to temporary operand.
+  Register gpr_scratch{Register::kScratchPointer};
+
+  // In x86-64 case we could refer to kBerberisMacroAssemblerConstants via %rip.
+  // In x86-32 mode, on the other hand, we need complex dance to access it via GOT.
+  // Intrinsics which use these constants receive it via additional parameter - and
+  // we need to know if it's needed or not.
+  Register gpr_macroassembler_constants{Register::kNoRegister};
+  bool need_gpr_macroassembler_constants() const { return need_gpr_macroassembler_constants_; }
+
+  Register gpr_macroassembler_scratch{Register::kNoRegister};
+  bool need_gpr_macroassembler_scratch() const { return need_gpr_macroassembler_scratch_; }
+  Register gpr_macroassembler_scratch2{Register::kNoRegister};
+
+  bool need_aesavx = false;
+  bool need_aes = false;
+  bool need_avx = false;
+  bool need_avx2 = false;
+  bool need_bmi = false;
+  bool need_bmi2 = false;
+  bool need_clmulavx = false;
+  bool need_clmul = false;
+  bool need_f16c = false;
+  bool need_fma = false;
+  bool need_fma4 = false;
+  bool need_lzcnt = false;
+  bool need_popcnt = false;
+  bool need_sse_or_sse2 = false;
+  bool need_sse3 = false;
+  bool need_ssse3 = false;
+  bool need_sse4_1 = false;
+  bool need_sse4_2 = false;
+  bool need_vaes = false;
+  bool need_vpclmulqd = false;
+  bool has_custom_capability = false;
+
+  bool defines_flags = false;
+
+  bool intrinsic_is_non_linear = false;
+
+  // We assume that maximum number of XMM/general/fixed registers binded to the intrinsic is 16.
+  // VerifierAssembler thus assumes arg_no will never be higher than this number. We use arrays of
+  // size 16 to track individual registers. If there is a register with an arg_no higher than 16, we
+  // will see a compiler error, since we detect out-of-bounds access to the array in constexpr.
+  static constexpr int kMaxRegisters = 16;
+
+  // Verifier Assmebler checks that 'def' or 'def_early_clober' XMM registers aren't read before
+  // they are written to, unless they are used in a dependency breaking instruction. However, many
+  // intrinsics first use and define an XMM register in a non dependency breaking instruction. This
+  // check is default disabled, but can be enabled to view and manually check these intrinsics.
+  static constexpr bool kCheckDefOrDefEarlyClobberXMMRegistersAreWrittenBeforeRead = false;
+
+  class RegisterUsageFlags {
+   public:
+    constexpr void CheckValidRegisterUse(bool is_fixed) {
+      if (intrinsic_defined_def_general_register ||
+          (intrinsic_defined_def_fixed_register && !is_fixed)) {
+        printf(
+            "error: intrinsic used a 'use' general register after writing to a 'def' general  "
+            "register\n");
+      }
+    }
+
+    constexpr void CheckValidXMMRegisterUse() {
+      if (intrinsic_defined_def_xmm_register) {
+        printf(
+            "error: intrinsic used a 'use' xmm register after writing to a 'def' xmm  "
+            "register\n");
+      }
+    }
+
+    constexpr void CheckAppropriateDefEarlyClobbers() {
+      for (int i = 0; i < kMaxRegisters; i++) {
+        if (intrinsic_defined_def_early_clobber_fixed_register[i] &&
+            !valid_def_early_clobber_register[i]) {
+          printf(
+              "error: intrinsic never used a 'use' general register after writing to a "
+              "'def_early_clobber' fixed register");
+        }
+        if (intrinsic_defined_def_early_clobber_general_register[i] &&
+            !valid_def_early_clobber_register[i]) {
+          printf(
+              "error: intrinsic never used a 'use' general/fixed register after writing to a "
+              "'def_early_clobber' general register");
+        }
+        if (intrinsic_defined_def_early_clobber_xmm_register[i] &&
+            !valid_def_early_clobber_register[i]) {
+          printf(
+              "error: intrinsic never used a 'use' xmm register after writing to a "
+              "'def_early_clobber' xmm register");
+        }
+      }
+    }
+
+    constexpr void CheckValidDefOrDefEarlyClobberRegisterUse(int reg_arg_no) {
+      if (!intrinsic_defined_def_or_def_early_clobber_register[reg_arg_no]) {
+        printf("error: intrinsic read a def/def_early_clobber register before writing to it");
+      }
+    }
+
+    constexpr void UpdateIntrinsicRegisterDef(bool is_fixed) {
+      if (is_fixed) {
+        intrinsic_defined_def_fixed_register = true;
+      } else {
+        intrinsic_defined_def_general_register = true;
+      }
+    }
+
+    constexpr void UpdateIntrinsicDefineDefOrDefEarlyClobberReigster(int reg_arg_no) {
+      intrinsic_defined_def_or_def_early_clobber_register[reg_arg_no] = true;
+    }
+
+    constexpr void UpdateIntrinsicRegisterDefEarlyClobber(int reg_arg_no, bool is_fixed) {
+      if (is_fixed) {
+        intrinsic_defined_def_early_clobber_fixed_register[reg_arg_no] = true;
+      } else {
+        intrinsic_defined_def_early_clobber_general_register[reg_arg_no] = true;
+      }
+    }
+
+    constexpr void UpdateIntrinsicRegisterUse([[maybe_unused]] bool is_fixed) {
+      for (int i = 0; i < kMaxRegisters; i++) {
+        if (intrinsic_defined_def_early_clobber_general_register[i]) {
+          valid_def_early_clobber_register[i] = true;
+        }
+        if (intrinsic_defined_def_early_clobber_fixed_register[i] && !is_fixed) {
+          valid_def_early_clobber_register[i] = true;
+        }
+      }
+    }
+
+    constexpr void UpdateIntrinsicXMMRegisterDef() { intrinsic_defined_def_xmm_register = true; }
+
+    constexpr void UpdateIntrinsicXMMRegisterDefEarlyClobber(int reg_arg_no) {
+      intrinsic_defined_def_early_clobber_xmm_register[reg_arg_no] = true;
+    }
+
+    constexpr void UpdateIntrinsicXMMRegisterUse() {
+      for (int i = 0; i < kMaxRegisters; i++) {
+        if (intrinsic_defined_def_early_clobber_xmm_register[i]) {
+          valid_def_early_clobber_register[i] = true;
+        }
+      }
+    }
+
+   private:
+    bool intrinsic_defined_def_general_register = false;
+    bool intrinsic_defined_def_fixed_register = false;
+    bool intrinsic_defined_def_xmm_register = false;
+
+    bool intrinsic_defined_def_or_def_early_clobber_register[kMaxRegisters] = {};
+
+    bool intrinsic_defined_def_early_clobber_fixed_register[kMaxRegisters] = {};
+    bool intrinsic_defined_def_early_clobber_general_register[kMaxRegisters] = {};
+    bool intrinsic_defined_def_early_clobber_xmm_register[kMaxRegisters] = {};
+
+    bool valid_def_early_clobber_register[kMaxRegisters] = {};
+  };
+
+  RegisterUsageFlags register_usage_flags;
+
+  struct Instruction {
+    constexpr void UpdateInstructionRegisterDef(bool is_fixed) {
+      if (is_fixed) {
+        instruction_defined_def_fixed_register = true;
+      } else {
+        instruction_defined_def_general_register = true;
+      }
+    }
+
+    constexpr void UpdateInstructionXMMRegisterDef() {
+      instruction_defined_def_xmm_register = true;
+    }
+
+    constexpr void UpdateInstructionRegisterUse(bool is_fixed) {
+      if (is_fixed) {
+        instruction_used_use_fixed_register = true;
+      } else {
+        instruction_used_use_general_register = true;
+      }
+    }
+
+    constexpr void UpdateInstructionXMMRegisterUse() { instruction_used_use_xmm_register = true; }
+
+    bool instruction_defined_def_fixed_register = false;
+    bool instruction_defined_def_general_register = false;
+    bool instruction_defined_def_xmm_register = false;
+
+    bool instruction_used_use_fixed_register = false;
+    bool instruction_used_use_general_register = false;
+    bool instruction_used_use_xmm_register = false;
+
+    bool is_unconditional_jump = false;
+    bool is_conditional_jump = false;
+    Label* jump_target = nullptr;
+  };
+
+  constexpr void CheckAppropriateDefEarlyClobbers() {
+    if (intrinsic_is_non_linear) {
+      return;
+    }
+    register_usage_flags.CheckAppropriateDefEarlyClobbers();
+  }
+
+  constexpr void CheckLabelsAreBound() {
+    if (!intrinsic_is_non_linear) {
+      return;
+    }
+    for (int i = 0; i < current_instruction; i++) {
+      if (instructions[i].is_conditional_jump || instructions[i].is_unconditional_jump) {
+        if (instructions[i].jump_target->bound == false) {
+          printf("error: intrinsic jumps to a label that was never bound\n");
+        }
+      }
+    }
+  }
+
+  constexpr void Bind(Label* label) {
+    CHECK_EQ(label->bound, false);
+    intrinsic_is_non_linear = true;
+    label->index = current_instruction;
+    label->bound = true;
+  }
+
+  constexpr Label* MakeLabel() {
+    labels_[num_labels_] = {{num_labels_}};
+    return &labels_[num_labels_++];
+  }
+
+  template <typename... Args>
+  constexpr void Byte([[maybe_unused]] Args... args) {
+    static_assert((std::is_same_v<Args, uint8_t> && ...));
+  }
+
+  template <typename... Args>
+  constexpr void TwoByte([[maybe_unused]] Args... args) {
+    static_assert((std::is_same_v<Args, uint16_t> && ...));
+  }
+
+  template <typename... Args>
+  constexpr void FourByte([[maybe_unused]] Args... args) {
+    static_assert((std::is_same_v<Args, uint32_t> && ...));
+  }
+
+  template <typename... Args>
+  constexpr void EigthByte([[maybe_unused]] Args... args) {
+    static_assert((std::is_same_v<Args, uint64_t> && ...));
+  }
+
+  constexpr void P2Align([[maybe_unused]] uint32_t m) {}
+
+  // Verify CPU vendor and SSE restrictions.
+  template <typename CPUIDRestriction>
+  constexpr void CheckCPUIDRestriction() {
+    // Technically AVX implies SSE but mixing AVX and SSE instructions can cause a performance
+    // penalty. Thus, we first ensure that AVX-using intrinsics don't use SSE instructions, before
+    // propagating required feature dependencies correctly.
+    if (need_avx && need_sse_or_sse2) {
+      printf("error: intrinsic used both AVX and SSE instructions\n");
+    }
+
+    constexpr bool expect_bmi = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>;
+    constexpr bool expect_f16c = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasF16C>;
+    constexpr bool expect_fma = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA>;
+    constexpr bool expect_fma4 = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasFMA4>;
+    constexpr bool expect_lzcnt = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>;
+    constexpr bool expect_vaes = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasVAES>;
+    constexpr bool expect_vpclmulqd =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasVPCLMULQD>;
+    constexpr bool expect_aesavx =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAESAVX> || expect_vaes;
+    constexpr bool expect_aes = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAES>;
+    constexpr bool expect_clmulavx =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasCLMULAVX> || expect_vpclmulqd;
+    constexpr bool expect_clmul = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasCLMUL>;
+    constexpr bool expect_popcnt =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>;
+    constexpr bool expect_avx = std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX> ||
+                                expect_aesavx || expect_clmulavx || expect_f16c || expect_fma ||
+                                expect_fma4;
+    constexpr bool expect_sse4_2 =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_2> || expect_aes ||
+        expect_clmul;
+    constexpr bool expect_sse4_1 =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE4_1> || expect_sse4_2;
+    constexpr bool expect_ssse3 =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSSE3> || expect_sse4_1;
+    constexpr bool expect_sse3 =
+        std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasSSE3> || expect_ssse3;
+
+    // Note that we don't check SSE or SSE2, since we assume SSE2 is always available.
+
+    if (expect_aesavx != need_aesavx) {
+      printf("error: expect_aesavx != need_aesavx\n");
+    }
+    if (expect_aes != need_aes) {
+      printf("error: expect_aes != need_aes\n");
+    }
+    if (expect_avx != need_avx) {
+      printf("error: expect_avx != need_avx\n");
+    }
+    if (expect_bmi != need_bmi) {
+      printf("error: expect_bmi != need_bmi\n");
+    }
+    if (expect_clmulavx != need_clmulavx) {
+      printf("error: expect_clmulavx != need_clmulavx\n");
+    }
+    if (expect_clmul != need_clmul) {
+      printf("error: expect_clmul != need_clmul\n");
+    }
+    if (expect_f16c != need_f16c) {
+      printf("error: expect_f16c != need_f16c\n");
+    }
+    if (expect_fma != need_fma) {
+      printf("error: expect_fma != need_fma\n");
+    }
+    if (expect_fma4 != need_fma4) {
+      printf("error: expect_fma4 != need_fma4\n");
+    }
+    if (expect_lzcnt != need_lzcnt) {
+      printf("error: expect_lzcnt != need_lzcnt\n");
+    }
+    if (expect_popcnt != need_popcnt) {
+      printf("error: expect_popcnt != need_popcnt\n");
+    }
+    if (expect_sse3 != need_sse3) {
+      printf("error: expect_sse3 != need_sse3\n");
+    }
+    if (expect_ssse3 != need_ssse3) {
+      printf("error: expect_ssse3 != need_ssse3\n");
+    }
+    if (expect_sse4_1 != need_sse4_1) {
+      printf("error: expect_sse4_1 != need_sse4_1\n");
+    }
+    if (expect_sse4_2 != need_sse4_2) {
+      printf("error: expect_sse4_2 != need_sse4_2\n");
+    }
+    if (expect_vaes != need_vaes) {
+      printf("error: expect_vaes != need_vaes\n");
+    }
+    if (expect_vpclmulqd != need_vpclmulqd) {
+      printf("error: expect_vpclmulqd != need_vpclmulqd\n");
+    }
+  }
+
+  constexpr void CheckFlagsBinding(bool expect_flags) {
+    if (expect_flags != defines_flags) {
+      printf("error: expect_flags != defines_flags\n");
+    }
+  }
+
+// Instructions.
+#include "gen_verifier_assembler_common_x86-inl.h"  // NOLINT generated file
+
+ protected:
+  bool need_gpr_macroassembler_constants_ = false;
+  bool need_gpr_macroassembler_scratch_ = false;
+
+  template <const char* kSpPrefix, char kRegisterPrefix>
+  class RegisterTemplate {
+   public:
+    explicit constexpr RegisterTemplate(Register reg) : reg_(reg) {}
+
+   private:
+    Register reg_;
+  };
+
+  constexpr static char kSpl[] = "%%spl";
+  using Register8Bit = RegisterTemplate<kSpl, 'b'>;
+  constexpr static char kSp[] = "%%sp";
+  using Register16Bit = RegisterTemplate<kSp, 'w'>;
+  constexpr static char kEsp[] = "%%esp";
+  using Register32Bit = RegisterTemplate<kEsp, 'k'>;
+  constexpr static char kRsp[] = "%%rsp";
+  using Register64Bit = RegisterTemplate<kRsp, 'q'>;
+
+  constexpr void SetRequiredFeatureAESAVX() {
+    need_aesavx = true;
+    SetRequiredFeatureAVX();
+  }
+
+  constexpr void SetRequiredFeatureAES() {
+    need_aes = true;
+    SetRequiredFeatureSSE4_2();
+  }
+
+  constexpr void SetRequiredFeatureAVX() {
+    // Technically AVX implies SSE but mixing AVX and SSE instructions can cause a performance
+    // penalty. Thus, we first ensure that AVX-using intrinsics don't use SSE instructions, before
+    // propagating required feature dependencies correctly.
+    need_avx = true;
+  }
+
+  constexpr void SetRequiredFeatureAVX2() {
+    need_avx2 = true;
+    SetRequiredFeatureAVX();
+  }
+
+  constexpr void SetRequiredFeatureBMI() { need_bmi = true; }
+
+  constexpr void SetRequiredFeatureBMI2() { need_bmi2 = true; }
+
+  constexpr void SetRequiredFeatureCLMULAVX() {
+    need_clmulavx = true;
+    SetRequiredFeatureAVX();
+  }
+
+  constexpr void SetRequiredFeatureCLMUL() {
+    need_clmul = true;
+    SetRequiredFeatureSSE4_2();
+  }
+
+  constexpr void SetRequiredFeatureF16C() {
+    need_f16c = true;
+    SetRequiredFeatureAVX();
+  }
+
+  constexpr void SetRequiredFeatureFMA() {
+    need_fma = true;
+    SetRequiredFeatureAVX();
+  }
+
+  constexpr void SetRequiredFeatureFMA4() {
+    need_fma4 = true;
+    SetRequiredFeatureAVX();
+  }
+
+  constexpr void SetRequiredFeatureLZCNT() { need_lzcnt = true; }
+
+  constexpr void SetRequiredFeaturePOPCNT() { need_popcnt = true; }
+
+  constexpr void SetRequiredFeatureSSEOrSSE2() { need_sse_or_sse2 = true; }
+
+  constexpr void SetRequiredFeatureSSE3() {
+    need_sse3 = true;
+    SetRequiredFeatureSSEOrSSE2();
+  }
+
+  constexpr void SetRequiredFeatureSSSE3() {
+    need_ssse3 = true;
+    SetRequiredFeatureSSE3();
+  }
+
+  constexpr void SetRequiredFeatureSSE4_1() {
+    need_sse4_1 = true;
+    SetRequiredFeatureSSSE3();
+  }
+
+  constexpr void SetRequiredFeatureSSE4_2() {
+    need_sse4_2 = true;
+    SetRequiredFeatureSSE4_1();
+  }
+
+  constexpr void SetRequiredFeatureVAES() {
+    need_vaes = true;
+    SetRequiredFeatureAESAVX();
+  }
+
+  constexpr void SetRequiredFeatureVPCLMULQD() {
+    need_vpclmulqd = true;
+    SetRequiredFeatureCLMULAVX();
+  }
+
+  constexpr void SetHasCustomCapability() { has_custom_capability = true; }
+
+  constexpr void SetDefinesFLAGS() { defines_flags = true; }
+
+  constexpr bool RegisterIsFixed(Register reg) {
+    if (gpr_a.register_initialised()) {
+      if (reg == gpr_a) return true;
+    }
+    if (gpr_b.register_initialised()) {
+      if (reg == gpr_b) return true;
+    }
+    if (gpr_c.register_initialised()) {
+      if (reg == gpr_c) return true;
+    }
+    if (gpr_d.register_initialised()) {
+      if (reg == gpr_d) return true;
+    }
+    return false;
+  }
+
+  constexpr void RegisterDef(Register reg) {
+    if (reg.get_binding_kind() == intrinsics::bindings::kDef ||
+        reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
+      register_usage_flags.UpdateIntrinsicDefineDefOrDefEarlyClobberReigster(reg.arg_no());
+    }
+    if (reg.get_binding_kind() == intrinsics::bindings::kDef) {
+      instructions[current_instruction].UpdateInstructionRegisterDef(RegisterIsFixed(reg));
+      register_usage_flags.UpdateIntrinsicRegisterDef(RegisterIsFixed(reg));
+    } else if (reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
+      register_usage_flags.UpdateIntrinsicRegisterDefEarlyClobber(reg.arg_no(),
+                                                                  RegisterIsFixed(reg));
+    }
+    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
+      printf("error: intrinsic defined a 'use' register\n");
+    }
+  }
+
+  constexpr void RegisterDef(XMMRegister reg) {
+    if (reg.get_binding_kind() == intrinsics::bindings::kDef ||
+        reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
+      register_usage_flags.UpdateIntrinsicDefineDefOrDefEarlyClobberReigster(reg.arg_no());
+    }
+    if (reg.get_binding_kind() == intrinsics::bindings::kDef) {
+      instructions[current_instruction].UpdateInstructionXMMRegisterDef();
+      register_usage_flags.UpdateIntrinsicXMMRegisterDef();
+    } else if (reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
+      register_usage_flags.UpdateIntrinsicXMMRegisterDefEarlyClobber(reg.arg_no());
+    }
+    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
+      printf("error: intrinsic defined a 'use' XMM register\n");
+    }
+  }
+
+  constexpr void RegisterUse(Register reg) {
+    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
+      instructions[current_instruction].UpdateInstructionRegisterUse(RegisterIsFixed(reg));
+    }
+    if (intrinsic_is_non_linear) {
+      return;
+    }
+    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
+      register_usage_flags.CheckValidRegisterUse(RegisterIsFixed(reg));
+      register_usage_flags.UpdateIntrinsicRegisterUse(RegisterIsFixed(reg));
+    }
+    if (reg.get_binding_kind() == intrinsics::bindings::kDef ||
+        reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
+      register_usage_flags.CheckValidDefOrDefEarlyClobberRegisterUse(reg.arg_no());
+    }
+  }
+
+  constexpr void RegisterUse(XMMRegister reg) {
+    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
+      instructions[current_instruction].UpdateInstructionXMMRegisterUse();
+    }
+    if (intrinsic_is_non_linear) {
+      return;
+    }
+    if (reg.get_binding_kind() == intrinsics::bindings::kUse) {
+      register_usage_flags.CheckValidXMMRegisterUse();
+      register_usage_flags.UpdateIntrinsicXMMRegisterUse();
+    }
+    if (!kCheckDefOrDefEarlyClobberXMMRegistersAreWrittenBeforeRead) {
+      return;
+    }
+    if (reg.get_binding_kind() == intrinsics::bindings::kDef ||
+        reg.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber) {
+      register_usage_flags.CheckValidDefOrDefEarlyClobberRegisterUse(reg.arg_no());
+    }
+  }
+
+  template <typename RegisterType>
+  constexpr void HandleDefOrDefEarlyClobberRegisterReset(RegisterType reg1, RegisterType reg2) {
+    if (reg1 == reg2 && (reg1.get_binding_kind() == intrinsics::bindings::kDef ||
+                         reg1.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber)) {
+      register_usage_flags.UpdateIntrinsicDefineDefOrDefEarlyClobberReigster(reg1.arg_no());
+    }
+  }
+
+  constexpr void HandleDefOrDefEarlyClobberRegisterReset(XMMRegister reg1,
+                                                         XMMRegister reg2,
+                                                         XMMRegister reg3) {
+    if (reg2 == reg3 && (reg1.get_binding_kind() == intrinsics::bindings::kDef ||
+                         reg1.get_binding_kind() == intrinsics::bindings::kDefEarlyClobber)) {
+      register_usage_flags.UpdateIntrinsicDefineDefOrDefEarlyClobberReigster(reg1.arg_no());
+    }
+  }
+
+  constexpr void HandleConditionalJump([[maybe_unused]] const Label& label) {
+    instructions[current_instruction].is_conditional_jump = true;
+    instructions[current_instruction].jump_target = const_cast<Label*>(&label);
+  }
+
+  constexpr void HandleUnconditionalJump([[maybe_unused]] const Label& label) {
+    instructions[current_instruction].is_unconditional_jump = true;
+    instructions[current_instruction].jump_target = const_cast<Label*>(&label);
+  }
+
+  constexpr void HandleUnconditionalJumpRegister() {
+    printf("error: intrinsic does jump to register\n");
+  }
+
+  constexpr void EndInstruction() { current_instruction++; }
+
+ private:
+  // Time complexity of checking correct use/def register bindings for non linear intrinsics is 2^n.
+  // Therefore, we only handle intrinsics with maximum of 5 labels. Also, no intrinsics exist with >
+  // 5 labels, so we can use this array for all intrinsics.
+  static constexpr int kMaxLabels = 5;
+  Label labels_[kMaxLabels];
+  size_t num_labels_ = 0;
+
+  int current_instruction = 0;
+  static constexpr int kMaxInstructions = 300;
+  Instruction instructions[kMaxInstructions] = {};
+
+  VerifierAssembler(const VerifierAssembler&) = delete;
+  VerifierAssembler(VerifierAssembler&&) = delete;
+  void operator=(const VerifierAssembler&) = delete;
+  void operator=(VerifierAssembler&&) = delete;
+};
+
+}  // namespace x86_32_and_x86_64
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_ALL_TO_X86_32_OR_x86_64_VERIFIER_ASSEMBLER_COMMON_H_
diff --git a/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float_test.cc b/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float_test.cc
index 53a66485..317e5b4c 100644
--- a/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float_test.cc
+++ b/intrinsics/all_to_x86_32_or_x86_64/intrinsics_float_test.cc
@@ -64,9 +64,9 @@ constexpr uint32_t kPlusInfinity32 = 0x7f800000;
 constexpr uint32_t kMinusInfinity32 = 0xff800000;
 // Default NaN created as result of math operations (when NaN wasn't an input).
 #if defined(__i386__) || defined(__x86_64__)
-constexpr uint32_t kDefaultNan32 = 0xffc00000;
+constexpr uint32_t kDefaultNaN32AsInteger = 0xffc00000;
 #else
-constexpr uint32_t kDefaultNan32 = 0x7fc00000;
+constexpr uint32_t kDefaultNaN32AsInteger = 0x7fc00000;
 #endif
 constexpr uint64_t kPlusZero64 = 0x0000000000000000;
 constexpr uint64_t kPlusOne64 = 0x3ff0000000000000;
@@ -75,9 +75,9 @@ constexpr uint64_t kMinusOne64 = 0xbff0000000000000;
 constexpr uint64_t kPlusInfinity64 = 0x7ff0000000000000;
 constexpr uint64_t kMinusInfinity64 = 0xfff0000000000000;
 #if defined(__i386__) || defined(__x86_64__)
-constexpr uint64_t kDefaultNan64 = 0xfff8000000000000;
+constexpr uint64_t kDefaultNaN64AsInteger = 0xfff8000000000000;
 #else
-constexpr uint64_t kDefaultNan64 = 0x7ff8000000000000;
+constexpr uint64_t kDefaultNaN64AsInteger = 0x7ff8000000000000;
 #endif
 
 #ifdef __i386__
@@ -155,11 +155,11 @@ TEST(FPU, Float32_InfPlusMinusInf) {
   // +inf + -inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kPlusInfinity32) +
                                        bit_cast<Float32, uint32_t>(kMinusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // -inf + +inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kMinusInfinity32) +
                                        bit_cast<Float32, uint32_t>(kPlusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
 }
 
 TEST(FPU, Float64_InfPlusMinusInf) {
@@ -174,11 +174,11 @@ TEST(FPU, Float64_InfPlusMinusInf) {
   // +inf + -inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kPlusInfinity64) +
                                        bit_cast<Float64, uint64_t>(kMinusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // -inf + +inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kMinusInfinity64) +
                                        bit_cast<Float64, uint64_t>(kPlusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
 }
 
 TEST(FPU, Float32_ZeroPlusMinusZero) {
@@ -231,11 +231,11 @@ TEST(FPU, Float32_InfMinusInf) {
   // +inf - +inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kPlusInfinity32) -
                                        bit_cast<Float32, uint32_t>(kPlusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // -inf - -inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kMinusInfinity32) -
                                        bit_cast<Float32, uint32_t>(kMinusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
 }
 
 TEST(FPU, Float64_InfMinusInf) {
@@ -250,11 +250,11 @@ TEST(FPU, Float64_InfMinusInf) {
   // +inf - +inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kPlusInfinity64) -
                                        bit_cast<Float64, uint64_t>(kPlusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // -inf - -inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kMinusInfinity64) -
                                        bit_cast<Float64, uint64_t>(kMinusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
 }
 
 TEST(FPU, Float32_ZeroMinusZero) {
@@ -299,70 +299,70 @@ TEST(FPU, Float32_InfMultiplyByZero) {
   // +inf * +0.f => dNaN
   uint32_t result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kPlusInfinity32) *
                                                 bit_cast<Float32, uint32_t>(kPlusZero32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // +0.f * +inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kPlusZero32) *
                                        bit_cast<Float32, uint32_t>(kPlusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // +inf * -0.f => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kPlusInfinity32) *
                                        bit_cast<Float32, uint32_t>(kMinusZero32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // -0.f * +inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kMinusZero32) *
                                        bit_cast<Float32, uint32_t>(kPlusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // -inf * +0.f => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kMinusInfinity32) *
                                        bit_cast<Float32, uint32_t>(kPlusZero32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // +0.f * -inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kPlusZero32) *
                                        bit_cast<Float32, uint32_t>(kMinusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // -inf * -0.f => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kMinusInfinity32) *
                                        bit_cast<Float32, uint32_t>(kMinusZero32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // -0.f * -inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kMinusZero32) *
                                        bit_cast<Float32, uint32_t>(kMinusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
 }
 
 TEST(FPU, Float64_InfMultiplyByZero) {
   // +inf * +0.0 => dNaN
   uint64_t result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kPlusInfinity64) *
                                                 bit_cast<Float64, uint64_t>(kPlusZero64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // +0.0 * +inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kPlusZero64) *
                                        bit_cast<Float64, uint64_t>(kPlusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // +inf * -0.0 => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kPlusInfinity64) *
                                        bit_cast<Float64, uint64_t>(kMinusZero64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // -0.0 * +inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kMinusZero64) *
                                        bit_cast<Float64, uint64_t>(kPlusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // -inf * +0.0 => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kMinusInfinity64) *
                                        bit_cast<Float64, uint64_t>(kPlusZero64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // +0.0 * -inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kPlusZero64) *
                                        bit_cast<Float64, uint64_t>(kMinusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // -inf * -0.0 => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kMinusInfinity64) *
                                        bit_cast<Float64, uint64_t>(kMinusZero64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // -0.0 * -inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kMinusZero64) *
                                        bit_cast<Float64, uint64_t>(kMinusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
 }
 
 TEST(FPU, Float32_ZeroMultiplyByZero) {
@@ -407,76 +407,76 @@ TEST(FPU, Float32_InfDivideByInf) {
   // +inf / +inf => dNaN
   uint32_t result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kPlusInfinity32) /
                                                 bit_cast<Float32, uint32_t>(kPlusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // +inf / -inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kPlusInfinity32) /
                                        bit_cast<Float32, uint32_t>(kMinusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // -inf / +inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kMinusInfinity32) /
                                        bit_cast<Float32, uint32_t>(kPlusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // -inf / -inf => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kMinusInfinity32) /
                                        bit_cast<Float32, uint32_t>(kMinusInfinity32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
 }
 
 TEST(FPU, Float64_InfDivideByInf) {
   // +inf / +inf => dNaN
   uint64_t result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kPlusInfinity64) /
                                                 bit_cast<Float64, uint64_t>(kPlusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // +inf / -inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kPlusInfinity64) /
                                        bit_cast<Float64, uint64_t>(kMinusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // -inf / +inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kMinusInfinity64) /
                                        bit_cast<Float64, uint64_t>(kPlusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // -inf / -inf => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kMinusInfinity64) /
                                        bit_cast<Float64, uint64_t>(kMinusInfinity64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
 }
 
 TEST(FPU, Float32_ZeroDivideByZero) {
   // +0.f - +0.f => dNaN
   uint32_t result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kPlusZero32) /
                                                 bit_cast<Float32, uint32_t>(kPlusZero32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // +0.f - -0.f => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kPlusZero32) /
                                        bit_cast<Float32, uint32_t>(kMinusZero32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // -0.f - +0.f => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kMinusZero32) /
                                        bit_cast<Float32, uint32_t>(kPlusZero32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
   // -0.f - +0.f => dNaN
   result = bit_cast<uint32_t, Float32>(bit_cast<Float32, uint32_t>(kMinusZero32) /
                                        bit_cast<Float32, uint32_t>(kMinusZero32));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
 }
 
 TEST(FPU, Float64_ZeroDivideByZero) {
   // +0.0 - +0.0 => dNaN
   uint64_t result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kPlusZero64) /
                                                 bit_cast<Float64, uint64_t>(kPlusZero64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // +0.0 - -0.0 => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kPlusZero64) /
                                        bit_cast<Float64, uint64_t>(kMinusZero64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // -0.0 - +0.0 => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kMinusZero64) /
                                        bit_cast<Float64, uint64_t>(kPlusZero64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
   // -0.0 - +0.0 => dNaN
   result = bit_cast<uint64_t, Float64>(bit_cast<Float64, uint64_t>(kMinusZero64) /
                                        bit_cast<Float64, uint64_t>(kMinusZero64));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
 }
 
 TEST(FPU, Float32_Sqrt) {
@@ -491,7 +491,7 @@ TEST(FPU, Float32_Sqrt) {
   EXPECT_EQ(result, kPlusOne32);
   // -1.0 => dNaN
   result = bit_cast<uint32_t, Float32>(Sqrt(bit_cast<Float32, uint32_t>(kMinusOne32)));
-  EXPECT_EQ(result, kDefaultNan32);
+  EXPECT_EQ(result, kDefaultNaN32AsInteger);
 }
 
 TEST(FPU, Float64_Sqrt) {
@@ -506,7 +506,7 @@ TEST(FPU, Float64_Sqrt) {
   EXPECT_EQ(result, kPlusOne64);
   // -1.0 => dNaN
   result = bit_cast<uint64_t, Float64>(Sqrt(bit_cast<Float64, uint64_t>(kMinusOne64)));
-  EXPECT_EQ(result, kDefaultNan64);
+  EXPECT_EQ(result, kDefaultNaN64AsInteger);
 }
 
 }  // namespace
diff --git a/intrinsics/all_to_x86_64/tuple_test.cc b/intrinsics/all_to_x86_64/tuple_test.cc
index 14f1b301..15e49565 100644
--- a/intrinsics/all_to_x86_64/tuple_test.cc
+++ b/intrinsics/all_to_x86_64/tuple_test.cc
@@ -21,25 +21,109 @@
 #include <tuple>
 
 #include "berberis/base/bit_util.h"
+#include "berberis/intrinsics/simd_register.h"
 
 #pragma clang diagnostic push
 // Clang does not allow use of C++ types in “extern "C"” functions - but we need to declare one to
 // test it.
 #pragma clang diagnostic ignored "-Wreturn-type-c-linkage"
 
-extern "C" std::tuple<uint64_t> AsmTupleTest(std::tuple<uint64_t>*);
+extern "C" std::tuple<uint64_t> AsmTupleTestI64(std::tuple<uint64_t>*);
 
 // This function takes first parameter %rdi and uses it as the address of a tuple.
-// If tuple is returned on registers it would contain address of a tuple passed via pointer.
+// If tuple is returned on registers it would contain the address of a tuple passed via pointer.
 // If tuple is returned on stack this would be address of the returned tuple (hidden parameter).
 asm(R"(.p2align 4, 0x90
-       .type AsmTupleTest,@function
-       AsmTupleTest:
+       .type AsmTupleTestI64,@function
+       AsmTupleTestI64:
        .cfi_startproc
        movl $42, (%rdi)
        movq %rdi, %rax
        ret
-       .size AsmTupleTest, .-AsmTupleTest
+       .size AsmTupleTestI64, .-AsmTupleTestI64
+       .cfi_endproc)");
+
+extern "C" std::tuple<berberis::SIMD128Register, berberis::SIMD128Register>
+AsmTupleTestSIMDRegisterSIMDRegister(
+    std::tuple<berberis::SIMD128Register, berberis::SIMD128Register>*);
+
+// This function takes first parameter %rdi and uses it as the address of a tuple.
+// If tuple is returned on registers it would contain the address of a tuple passed via pointer.
+// The function returns {this pointer, 0, garbage, garbage} in that case.
+// If tuple is returned on stack this would be address of the returned tuple (hidden parameter).
+// The function returns {1, 2, 3, 4} in that case.
+asm(R"(.p2align 4, 0x90
+       .type AsmTupleTestSIMDRegisterSIMDRegister,@function
+       AsmTupleTestSIMDRegisterSIMDRegister:
+       .cfi_startproc
+       movq $1, (%rdi)
+       movq $2, 8(%rdi)
+       movq $3, 16(%rdi)
+       movq $4, 24(%rdi)
+       movq %rdi, %rax
+       movq %rdi, %xmm0
+       ret
+       .size AsmTupleTestSIMDRegisterSIMDRegister, .-AsmTupleTestSIMDRegisterSIMDRegister
+       .cfi_endproc)");
+
+extern "C" std::tuple<berberis::SIMD128Register,
+                      berberis::SIMD128Register,
+                      berberis::SIMD128Register>
+AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegister(
+    std::tuple<berberis::SIMD128Register, berberis::SIMD128Register, berberis::SIMD128Register>*);
+
+// This function takes first parameter %rdi and uses it as the address of a tuple.
+// If tuple is returned on registers it would contain the address of a tuple passed via pointer.
+// The function returns {this pointer, 0, garbage, garbage} in that case.
+// If tuple is returned on stack this would be address of the returned tuple (hidden parameter).
+// The function returns {1, 2, 3, 4, 5, 6} in that case.
+asm(R"(.p2align 4, 0x90
+       .type AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegister,@function
+       AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegister:
+       .cfi_startproc
+       movq $1, (%rdi)
+       movq $2, 8(%rdi)
+       movq $3, 16(%rdi)
+       movq $4, 24(%rdi)
+       movq $5, 32(%rdi)
+       movq $6, 40(%rdi)
+       movq %rdi, %rax
+       movq %rdi, %xmm0
+       ret
+       .size AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegister, .-AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegister
+       .cfi_endproc)");
+
+extern "C" std::tuple<berberis::SIMD128Register,
+                      berberis::SIMD128Register,
+                      berberis::SIMD128Register,
+                      berberis::SIMD128Register>
+AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegisterSIMDRegister(
+    std::tuple<berberis::SIMD128Register,
+               berberis::SIMD128Register,
+               berberis::SIMD128Register,
+               berberis::SIMD128Register>*);
+
+// This function takes first parameter %rdi and uses it as the address of a tuple.
+// If tuple is returned on registers it would contain the address of a tuple passed via pointer.
+// The function returns {this pointer, 0, garbage, garbage} in that case.
+// If tuple is returned on stack this would be address of the returned tuple (hidden parameter).
+// The function returns {1, 2, 3, 4, 5, 6, 7, 8} in that case.
+asm(R"(.p2align 4, 0x90
+       .type AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegisterSIMDRegister,@function
+       AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegisterSIMDRegister:
+       .cfi_startproc
+       movq $1, (%rdi)
+       movq $2, 8(%rdi)
+       movq $3, 16(%rdi)
+       movq $4, 24(%rdi)
+       movq $5, 32(%rdi)
+       movq $6, 40(%rdi)
+       movq $7, 48(%rdi)
+       movq $8, 56(%rdi)
+       movq %rdi, %rax
+       movq %rdi, %xmm0
+       ret
+       .size AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegisterSIMDRegister, .-AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegisterSIMDRegister
        .cfi_endproc)");
 
 #pragma clang diagnostic pop
@@ -48,15 +132,22 @@ namespace berberis {
 
 namespace {
 
-std::optional<bool> TupleIsReturnedOnRegisters() {
-  std::tuple<uint64_t> result_if_on_regs{};
-  std::tuple<uint64_t> result_if_on_stack{};
+template <typename T, T AsmTupleTest(T*), typename ExpectedValue, typename ExpectedZeroValue>
+std::optional<bool> TupleIsReturnedOnRegisters(ExpectedValue kExpectedValue,
+                                               ExpectedZeroValue kExpectedZeroValue) {
+  T result_if_on_regs{};
+  T result_if_on_stack{};
   result_if_on_stack = AsmTupleTest(&result_if_on_regs);
-  if (std::get<uint64_t>(result_if_on_regs) == 42 &&
-      std::get<uint64_t>(result_if_on_stack) == bit_cast<uint64_t>(&result_if_on_regs)) {
-    return true;
-  } else if (std::get<uint64_t>(result_if_on_regs) == 0 &&
-             std::get<uint64_t>(result_if_on_stack) == 42) {
+  if (result_if_on_regs == kExpectedValue) {
+    // When result is on regs function returns a pointer to result_if_on_regs.
+    void* result_if_on_regs_ptr = &result_if_on_regs;
+    static_assert(sizeof(result_if_on_regs_ptr) <= sizeof(result_if_on_stack));
+    if (memcmp(&result_if_on_stack, &result_if_on_regs_ptr, sizeof(result_if_on_regs_ptr)) == 0) {
+      return true;
+    }
+    // Shouldn't happen with proper x86-64 compiler.
+    return {};
+  } else if (result_if_on_regs == kExpectedZeroValue && result_if_on_stack == kExpectedValue) {
     return false;
   } else {
     // Shouldn't happen with proper x86-64 compiler.
@@ -65,9 +156,11 @@ std::optional<bool> TupleIsReturnedOnRegisters() {
 }
 
 // Note: tuple is returned on registers when libc++ is used and on stack if libstdc++ is used.
-TEST(LibCxxAbi, Tuple) {
-  auto tuple_is_returned_on_registers = TupleIsReturnedOnRegisters();
-  EXPECT_TRUE(tuple_is_returned_on_registers.has_value());
+TEST(LibCxxAbi, Tuple_UInt64) {
+  auto tuple_is_returned_on_registers =
+      TupleIsReturnedOnRegisters<std::tuple<uint64_t>, AsmTupleTestI64>(std::tuple{uint64_t{42}},
+                                                                        std::tuple{uint64_t{0}});
+  ASSERT_TRUE(tuple_is_returned_on_registers.has_value());
 #ifdef _LIBCPP_VERSION
   EXPECT_TRUE(*tuple_is_returned_on_registers);
 #else
@@ -75,6 +168,42 @@ TEST(LibCxxAbi, Tuple) {
 #endif
 }
 
+// Note: tuple is returned on registers when libc++ is used and on stack if libstdc++ is used.
+TEST(LibCxxAbi, Tuple_SIMDRegisterSIMDRegister) {
+  auto tuple_is_returned_on_registers =
+      TupleIsReturnedOnRegisters<std::tuple<SIMD128Register, SIMD128Register>,
+                                 AsmTupleTestSIMDRegisterSIMDRegister>(
+          std::tuple{Int64x2{1, 2}, Int64x2{3, 4}}, std::tuple{Int64x2{0, 0}, Int64x2{0, 0}});
+  ASSERT_TRUE(tuple_is_returned_on_registers.has_value());
+#if defined(_LIBCPP_VERSION) && defined(__AVX__)
+  EXPECT_TRUE(*tuple_is_returned_on_registers);
+#else
+  EXPECT_FALSE(*tuple_is_returned_on_registers);
+#endif
+}
+
+// Note: tuple is returned on registers when libc++ is used and on stack if libstdc++ is used.
+TEST(LibCxxAbi, Tuple_SIMDRegisterSIMDRegisterSIMDRegister) {
+  auto tuple_is_returned_on_registers =
+      TupleIsReturnedOnRegisters<std::tuple<SIMD128Register, SIMD128Register, SIMD128Register>,
+                                 AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegister>(
+          std::tuple{Int64x2{1, 2}, Int64x2{3, 4}, Int64x2{5, 6}},
+          std::tuple{Int64x2{0, 0}, Int64x2{0, 0}, Int64x2{0, 0}});
+  ASSERT_TRUE(tuple_is_returned_on_registers.has_value());
+  EXPECT_FALSE(*tuple_is_returned_on_registers);
+}
+
+// Note: tuple is returned on registers when libc++ is used and on stack if libstdc++ is used.
+TEST(LibCxxAbi, Tuple_SIMDRegisterSIMDRegisterSIMDRegisterSIMDRegister) {
+  auto tuple_is_returned_on_registers = TupleIsReturnedOnRegisters<
+      std::tuple<SIMD128Register, SIMD128Register, SIMD128Register, SIMD128Register>,
+      AsmTupleTestSIMDRegisterSIMDRegisterSIMDRegisterSIMDRegister>(
+      std::tuple{Int64x2{1, 2}, Int64x2{3, 4}, Int64x2{5, 6}, Int64x2{7, 8}},
+      std::tuple{Int64x2{0, 0}, Int64x2{0, 0}, Int64x2{0, 0}, Int64x2{0, 0}});
+  ASSERT_TRUE(tuple_is_returned_on_registers.has_value());
+  EXPECT_FALSE(*tuple_is_returned_on_registers);
+}
+
 }  // namespace
 
 }  // namespace berberis
diff --git a/intrinsics/enum_from_template_type_test.cc b/intrinsics/enum_from_template_type_test.cc
new file mode 100644
index 00000000..5780e889
--- /dev/null
+++ b/intrinsics/enum_from_template_type_test.cc
@@ -0,0 +1,110 @@
+/*
+ * Copyright (C) 2013 The Android Open Source Project
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
+#include <cstdint>
+#include <type_traits>
+
+#include "berberis/intrinsics/common/intrinsics.h"
+#include "berberis/intrinsics/simd_register.h"
+
+namespace berberis::intrinsics {
+
+static_assert(kIdFromType<int8_t> == kInt8T);
+static_assert(kIdFromType<uint8_t> == kUInt8T);
+static_assert(kIdFromType<int16_t> == kInt16T);
+static_assert(kIdFromType<uint16_t> == kUInt16T);
+static_assert(kIdFromType<int32_t> == kInt32T);
+static_assert(kIdFromType<uint32_t> == kUInt32T);
+static_assert(kIdFromType<int64_t> == kInt64T);
+static_assert(kIdFromType<uint64_t> == kUInt64T);
+static_assert(kIdFromType<Float16> == kFloat16);
+static_assert(kIdFromType<Float32> == kFloat32);
+static_assert(kIdFromType<Float64> == kFloat64);
+static_assert(kIdFromType<SIMD128Register> == kSIMD128Register);
+
+static_assert(std::is_same_v<TypeFromId<kInt8T>, int8_t>);
+static_assert(std::is_same_v<TypeFromId<kUInt8T>, uint8_t>);
+static_assert(std::is_same_v<TypeFromId<kInt16T>, int16_t>);
+static_assert(std::is_same_v<TypeFromId<kUInt16T>, uint16_t>);
+static_assert(std::is_same_v<TypeFromId<kInt32T>, int32_t>);
+static_assert(std::is_same_v<TypeFromId<kUInt32T>, uint32_t>);
+static_assert(std::is_same_v<TypeFromId<kInt64T>, int64_t>);
+static_assert(std::is_same_v<TypeFromId<kUInt64T>, uint64_t>);
+static_assert(std::is_same_v<TypeFromId<kSIMD128Register>, SIMD128Register>);
+
+static_assert(TemplateTypeIdToFloat(kInt16T) == kFloat16);
+static_assert(TemplateTypeIdToFloat(kUInt16T) == kFloat16);
+static_assert(TemplateTypeIdToFloat(kInt32T) == kFloat32);
+static_assert(TemplateTypeIdToFloat(kUInt32T) == kFloat32);
+static_assert(TemplateTypeIdToFloat(kInt64T) == kFloat64);
+static_assert(TemplateTypeIdToFloat(kUInt64T) == kFloat64);
+
+static_assert(TemplateTypeIdToInt(kFloat16) == kUInt16T);
+static_assert(TemplateTypeIdToInt(kFloat32) == kUInt32T);
+static_assert(TemplateTypeIdToInt(kFloat64) == kUInt64T);
+
+static_assert(TemplateTypeIdToNarrow(kInt16T) == kInt8T);
+static_assert(TemplateTypeIdToNarrow(kUInt16T) == kUInt8T);
+static_assert(TemplateTypeIdToNarrow(kInt32T) == kInt16T);
+static_assert(TemplateTypeIdToNarrow(kUInt32T) == kUInt16T);
+static_assert(TemplateTypeIdToNarrow(kInt64T) == kInt32T);
+static_assert(TemplateTypeIdToNarrow(kUInt64T) == kUInt32T);
+static_assert(TemplateTypeIdToNarrow(kFloat32) == kFloat16);
+static_assert(TemplateTypeIdToNarrow(kFloat64) == kFloat32);
+
+static_assert(TemplateTypeIdToSigned(kInt8T) == kInt8T);
+static_assert(TemplateTypeIdToSigned(kUInt8T) == kInt8T);
+static_assert(TemplateTypeIdToSigned(kInt16T) == kInt16T);
+static_assert(TemplateTypeIdToSigned(kUInt16T) == kInt16T);
+static_assert(TemplateTypeIdToSigned(kInt32T) == kInt32T);
+static_assert(TemplateTypeIdToSigned(kUInt32T) == kInt32T);
+static_assert(TemplateTypeIdToSigned(kInt64T) == kInt64T);
+static_assert(TemplateTypeIdToSigned(kUInt64T) == kInt64T);
+
+static_assert(TemplateTypeIdSizeOf(kInt8T) == 1);
+static_assert(TemplateTypeIdSizeOf(kUInt8T) == 1);
+static_assert(TemplateTypeIdSizeOf(kInt16T) == 2);
+static_assert(TemplateTypeIdSizeOf(kUInt16T) == 2);
+static_assert(TemplateTypeIdSizeOf(kInt32T) == 4);
+static_assert(TemplateTypeIdSizeOf(kUInt32T) == 4);
+static_assert(TemplateTypeIdSizeOf(kInt64T) == 8);
+static_assert(TemplateTypeIdSizeOf(kUInt64T) == 8);
+static_assert(TemplateTypeIdSizeOf(kFloat16) == 2);
+static_assert(TemplateTypeIdSizeOf(kFloat32) == 4);
+static_assert(TemplateTypeIdSizeOf(kFloat64) == 8);
+static_assert(TemplateTypeIdSizeOf(kSIMD128Register) == 16);
+
+static_assert(TemplateTypeIdToUnsigned(kInt8T) == kUInt8T);
+static_assert(TemplateTypeIdToUnsigned(kUInt8T) == kUInt8T);
+static_assert(TemplateTypeIdToUnsigned(kInt16T) == kUInt16T);
+static_assert(TemplateTypeIdToUnsigned(kUInt16T) == kUInt16T);
+static_assert(TemplateTypeIdToUnsigned(kInt32T) == kUInt32T);
+static_assert(TemplateTypeIdToUnsigned(kUInt32T) == kUInt32T);
+static_assert(TemplateTypeIdToUnsigned(kInt64T) == kUInt64T);
+static_assert(TemplateTypeIdToUnsigned(kUInt64T) == kUInt64T);
+
+static_assert(TemplateTypeIdToWide(kInt8T) == kInt16T);
+static_assert(TemplateTypeIdToWide(kUInt8T) == kUInt16T);
+static_assert(TemplateTypeIdToWide(kInt16T) == kInt32T);
+static_assert(TemplateTypeIdToWide(kUInt16T) == kUInt32T);
+static_assert(TemplateTypeIdToWide(kInt32T) == kInt64T);
+static_assert(TemplateTypeIdToWide(kUInt32T) == kUInt64T);
+static_assert(TemplateTypeIdToWide(kFloat16) == kFloat32);
+static_assert(TemplateTypeIdToWide(kFloat32) == kFloat64);
+
+}  // namespace berberis::intrinsics
diff --git a/intrinsics/gen_intrinsics.py b/intrinsics/gen_intrinsics.py
index f26ea8f4..aba8f346 100755
--- a/intrinsics/gen_intrinsics.py
+++ b/intrinsics/gen_intrinsics.py
@@ -145,7 +145,7 @@ def _get_c_type(arg_type):
 
 
 def _get_semantic_player_type(arg_type, type_map):
-  if type_map is not None and arg_type in type_map:
+  if type_map is not None and type_map != False and arg_type in type_map:
     return type_map[arg_type]
   if arg_type in ('Float16', 'Float32', 'Float64', 'vec'):
     return 'SimdRegister'
@@ -183,15 +183,20 @@ def _gen_template_intr_decl(f, name, intr):
   comment = intr.get('comment')
   if comment:
     print('// %s.' % (comment), file=f)
-  print('template <%s>' % _get_template_arguments(
+  print('template <%s>' % _get_template_parameters(
       intr.get('variants'), intr.get('precise_nans', False)), file=f)
   print('%s %s(%s);' % (retval, name, ', '.join(params)), file=f)
 
 
-def _get_template_arguments(
+def _get_template_parameters(
     variants,
-    precise_nans = False,
-    extra = ['enum PreferredIntrinsicsImplementation = kUseAssemblerImplementationIfPossible']):
+    precise_nans=False,
+    use_type_id=False,
+    extra=['enum PreferredIntrinsicsImplementation = kUseAssemblerImplementationIfPossible']):
+  if use_type_id:
+    typename = 'intrinsics::TemplateTypeId'
+  else:
+    typename = 'typename'
   template = None
   for variant in variants:
     counter = -1
@@ -202,8 +207,8 @@ def _get_template_arguments(
     new_template = ', '.join(
       (["bool kPreciseNaNOperationsHandling"] if precise_nans else []) +
       ['bool kBool%s' % get_counter() if param.strip() in ('true', 'false') else
-       'uint32_t kInt%s' % get_counter() if param.strip() in _ROUNDING_MODES else
-       'typename Type%d' % get_counter() if re.search('[_a-zA-Z]', param) else
+       'int kInt%s' % get_counter() if param.strip() in _ROUNDING_MODES else
+       '%s Type%d' % (typename, get_counter()) if re.search('[_a-zA-Z]', param) else
        'int kInt%s' % get_counter()
        for param in variant.split(',')] + extra)
     assert template is None or template == new_template
@@ -211,6 +216,30 @@ def _get_template_arguments(
   return template
 
 
+def _gen_vector_intr_decl(f, name, intr):
+  ins = intr.get('in')
+  outs = intr.get('out')
+  params = [_get_c_type(op) for op in ins]
+  if len(outs) > 0:
+    retval = 'std::tuple<' + ', '.join(_get_c_type(out) for out in outs) + '>'
+  else:
+    retval = 'void'
+  comment = intr.get('comment')
+  if comment:
+    print('// %s.' % (comment), file=f)
+  if intr.get('precise_nans', False):
+    template_parameters = 'bool precise_nan_operations_handling, '
+  else:
+    template_parameters = ''
+  if not 'raw' in intr['variants']:
+    template_parameters += 'typename Type, '
+  template_parameters += 'int size, '
+  template_parameters += 'enum PreferredIntrinsicsImplementation'
+  template_parameters += ' = kUseAssemblerImplementationIfPossible'
+  print('template <%s>' % template_parameters, file=f)
+  print('%s %s(%s);' % (retval, name, ', '.join(params)), file=f)
+
+
 def _is_vector_class(intr):
   return intr.get('class') in ('vector_4', 'vector_8', 'vector_16',
                                'vector_8/16', 'vector_8/16/single',
@@ -258,15 +287,22 @@ def _get_semantics_player_hook_proto_components(name, intr):
   return result, name, ', '.join(args)
 
 
-def _get_semantics_player_hook_proto(name, intr):
-  result, name, args = _get_semantics_player_hook_proto_components(name, intr)
+def _get_semantics_player_hook_proto(name, intr, use_type_id=False):
+  result, name, params = _get_semantics_player_hook_proto_components(name, intr)
   if intr.get('class') == 'template':
-    return 'template<%s>\n%s %s(%s)' % (
-      _get_template_arguments(intr.get('variants'), False, []), result, name, args)
-  return '%s %s(%s)' % (result, name, args)
-
-
-def _get_interpreter_hook_call_expr(name, intr, desc=None):
+    template_parameters = _get_template_parameters(
+      intr.get('variants'), use_type_id=use_type_id, extra = [])
+    values = ''
+    if use_type_id:
+      spec_arguments = _get_template_spec_arguments(intr.get('variants'))
+      values = ', ' + ', '.join(
+          ['intrinsics::Value<%s>' % argument for argument in spec_arguments])
+    return 'template<%s>\n%s %s(%s%s)' % (
+      template_parameters, result, name, params, values)
+  return '%s %s(%s)' % (result, name, params)
+
+
+def _get_interpreter_hook_call_expr(name, intr, desc=None, use_type_id=False):
   ins = intr['in']
   outs = intr['out']
 
@@ -276,17 +312,21 @@ def _get_interpreter_hook_call_expr(name, intr, desc=None):
     semantic_player_type = _get_semantic_player_type(
         op, intr.get('sem-player-types'))
     if semantic_player_type == 'FpRegister':
+      if op.startswith('Type') and use_type_id:
+        op = 'intrinsics::TypeFromId<%s>' % op
       call_params.append('FPRegToFloat<%s>(%s)' % (op, arg))
     elif semantic_player_type == 'SimdRegister':
       call_params.append(_get_cast_from_simd128(arg, op, ptr_bits=64))
     elif '*' in _get_c_type(op):
       call_params.append('berberis::bit_cast<%s>(%s)' % (_get_c_type(op), arg))
     else:
-      call_params.append('GPRRegToInteger<%s>(%s)' % (_get_c_type(op), arg))
+      c_type = _get_c_type(op)
+      if c_type.startswith('Type') and use_type_id:
+        c_type = 'intrinsics::TypeFromId<%s>' % c_type
+      call_params.append('GPRRegToInteger<%s>(%s)' % (c_type, arg))
 
   call_expr = 'intrinsics::%s%s(%s)' % (
-      name, _get_desc_specializations(intr, desc).replace(
-          'Float', 'intrinsics::Float'), ', '.join(call_params))
+      name, _get_desc_specializations(intr, desc, use_type_id), ', '.join(call_params))
 
   if len(outs) == 1:
     # Unwrap tuple for single result.
@@ -317,8 +357,8 @@ def _get_interpreter_hook_call_expr(name, intr, desc=None):
   return call_expr
 
 
-def _get_interpreter_hook_return_stmt(name, intr, desc=None):
-  return 'return ' + _get_interpreter_hook_call_expr(name, intr, desc) + ';'
+def _get_interpreter_hook_return_stmt(name, intr, desc=None, use_type_id=False):
+  return 'return ' + _get_interpreter_hook_call_expr(name, intr, desc, use_type_id) + ';'
 
 def _get_unused(intr):
   call_expr = 'UNUSED(%s);' % ', '.join('arg%d' % (num) for num, _ in enumerate(intr['in']))
@@ -398,8 +438,8 @@ def _get_interpreter_hook_vector_body(name, intr):
       name, intr, _get_interpreter_hook_return_stmt)
 
 
-def _gen_interpreter_hook(f, name, intr, option):
-  print('%s const {' % (_get_semantics_player_hook_proto(name, intr)), file=f)
+def _gen_interpreter_hook(f, name, intr, option, use_type_id=False):
+  print('%s const {' % (_get_semantics_player_hook_proto(name, intr, use_type_id)), file=f)
 
   if _is_vector_class(intr):
     if 'raw' in intr['variants']:
@@ -414,6 +454,8 @@ def _gen_interpreter_hook(f, name, intr, option):
     lines = [INDENT + l for l in lines]
     print('\n'.join(lines), file=f)
   else:
+    if intr.get('class') == 'template':
+      _gen_template_parameters_verifier(f, intr, use_type_id)
     # TODO(b/363057506): Add float support and clean up the logic here.
     arm64_allowlist = ['AmoAdd', 'AmoAnd', 'AmoMax', 'AmoMin', 'AmoOr', 'AmoSwap', 'AmoXor', 'Bclr',
                        'Bclri', 'Bext', 'Bexti', 'Binv', 'Binvi', 'Bset', 'Bseti', 'Div', 'Max',
@@ -422,26 +464,25 @@ def _gen_interpreter_hook(f, name, intr, option):
     if (option == 'arm64') and (name not in arm64_allowlist):
       _get_placeholder_return_stmt(intr, f)
     else:
-      print(INDENT + _get_interpreter_hook_return_stmt(name, intr), file=f)
+      print(INDENT + _get_interpreter_hook_return_stmt(name, intr, use_type_id=use_type_id), file=f)
 
   print('}\n', file=f)
 
 
-def _get_translator_hook_call_expr(name, intr, desc = None):
-  desc_spec = _get_desc_specializations(intr, desc).replace(
-      'Float', 'intrinsics::Float')
+def _get_translator_hook_call_expr(name, intr, desc=None, use_type_id=False):
+  desc_spec = _get_desc_specializations(intr, desc, use_type_id)
   args = [('arg%d' % n) for n, _ in enumerate(intr['in'])]
   template_params = ['&intrinsics::' + name + desc_spec]
   template_params += [_get_semantics_player_hook_result(intr)]
   return 'CallIntrinsic<%s>(%s)' % (', '.join(template_params), ', '.join(args))
 
 
-def _get_translator_hook_return_stmt(name, intr, desc=None):
-  return 'return ' + _get_translator_hook_call_expr(name, intr, desc) + ';'
+def _get_translator_hook_return_stmt(name, intr, desc=None, use_type_id=False):
+  return 'return ' + _get_translator_hook_call_expr(name, intr, desc, use_type_id) + ';'
 
 
-def _gen_translator_hook(f, name, intr):
-  print('%s {' % (_get_semantics_player_hook_proto(name, intr)), file=f)
+def _gen_translator_hook(f, name, intr, use_type_id=False):
+  print('%s {' % (_get_semantics_player_hook_proto(name, intr, use_type_id)), file=f)
 
   if _is_vector_class(intr):
     if 'raw' in intr['variants']:
@@ -458,34 +499,63 @@ def _gen_translator_hook(f, name, intr):
     lines = [INDENT + l for l in lines]
     print('\n'.join(lines), file=f)
   else:
-    print(INDENT + _get_translator_hook_return_stmt(name, intr), file=f)
+    if intr.get('class') == 'template':
+      _gen_template_parameters_verifier(f, intr, use_type_id)
+    print(INDENT + _get_translator_hook_return_stmt(name, intr, use_type_id=use_type_id), file=f)
 
   print('}\n', file=f)
 
 
 def _gen_mock_semantics_listener_hook(f, name, intr):
-  result, name, args = _get_semantics_player_hook_proto_components(name, intr)
+  result, name, params = _get_semantics_player_hook_proto_components(name, intr)
   if intr.get('class') == 'template':
-    print('template<%s>\n%s %s(%s) {\n  return %s(%s);\n}' % (
-      _get_template_arguments(intr.get('variants'), False, []),
-      result,
-      name,
-      args,
-      name,
-      ', '.join([
-        'intrinsics::kEnumFromTemplateType<%s>' % arg if arg.startswith('Type') else arg
-        for arg in _get_template_spec_arguments(intr.get('variants'))] +
-      [('arg%d' % n) for n, _ in enumerate(intr['in'])])), file=f)
-    args = ', '.join([
-      '%s %s' % (
+    spec_arguments = _get_template_spec_arguments(intr.get('variants'))
+    for use_type_id in [True, False]:
+      template_parameters = _get_template_parameters(
+        intr.get('variants'), use_type_id=use_type_id, extra = [])
+      args = ', '.join(
+         [('arg%d' % n) for n, _ in enumerate(intr['in'])] +
+         [arg
+            if use_type_id or not arg.startswith('Type') else
+          'intrinsics::kIdFromType<%s>' % arg
+          for arg in spec_arguments])
+      values = ''
+      if use_type_id:
+        values = ', ' + ', '.join(
+            ['intrinsics::Value<%s>' % argument for argument in spec_arguments])
+      print('template<%s>\n%s %s(%s%s) {\n  return %s(%s);\n}' % (
+        template_parameters, result, name, params, values, name, args), file=f)
+    params = ', '.join(
+      [params] +
+      ['%s %s' % (
           {
               'kBoo': 'bool',
               'kInt': 'int',
-              'Type': 'intrinsics::EnumFromTemplateType'
+              'Type': 'intrinsics::TemplateTypeId'
           }[argument[0:4]],
           argument)
-      for argument in _get_template_spec_arguments(intr.get('variants'))] + [args])
-  print('MOCK_METHOD((%s), %s, (%s));' % (result, name, args), file=f)
+      for argument in spec_arguments])
+  print('MOCK_METHOD((%s), %s, (%s));' % (result, name, params), file=f)
+
+
+def _gen_template_parameters_verifier(f, intr, use_type_id=False):
+  received_params = ', '.join(
+    param
+      if not param.strip().startswith('Type') or use_type_id else
+    f'intrinsics::kIdFromType<{param}>'
+    for param in _get_template_spec_arguments(intr.get('variants')))
+  print('%sstatic_assert(%s);' % (
+   INDENT,
+   ' || '.join(
+    'std::tuple{%s} == std::tuple{%s}' % (
+      received_params,
+      ', '.join(
+        param
+          if param.strip() in ['true', 'false'] + _ROUNDING_MODES or
+             not re.search('[_a-zA-Z]', param) else
+        f'intrinsics::kIdFromType<{param}>'
+        for param in variant.split(',')))
+     for variant in intr.get('variants'))), file=f)
 
 
 def _check_signed_variant(variant, desc):
@@ -608,7 +678,7 @@ def _get_cast_from_simd128(var, target_type, ptr_bits):
 
   c_type = _get_c_type(target_type)
   if c_type in ('Float16', 'Float32', 'Float64'):
-    return 'FPRegToFloat<intrinsics::%s>(%s)' % (c_type, var)
+    return 'FPRegToFloat<%s>(%s)' % (c_type, var)
 
   cast_map = {
       'int8_t': '.Get<int8_t>(0)',
@@ -624,9 +694,9 @@ def _get_cast_from_simd128(var, target_type, ptr_bits):
   return '%s%s' % (var, cast_map[c_type])
 
 
-def _get_desc_specializations(intr, desc=None):
+def _get_desc_specializations(intr, desc=None, use_type_id=False):
   if intr.get('class') == 'template':
-    spec = _get_template_spec_arguments(intr.get('variants'))
+    spec = _get_template_spec_arguments(intr.get('variants'), use_type_id)
   elif hasattr(desc, 'c_type'):
     spec = [desc.c_type, str(desc.num_elements)]
   elif hasattr(desc, 'num_elements'):
@@ -640,7 +710,7 @@ def _get_desc_specializations(intr, desc=None):
   return '<%s>' % ', '.join(spec)
 
 
-def _get_template_spec_arguments(variants):
+def _get_template_spec_arguments(variants, use_type_id=False):
   spec = None
   for variant in variants:
     counter = -1
@@ -651,7 +721,10 @@ def _get_template_spec_arguments(variants):
     new_spec = [
       'kBool%s' % get_counter() if param.strip() in ('true', 'false') else
       'kInt%s' % get_counter() if param.strip() in _ROUNDING_MODES else
-      'Type%d' % get_counter() if re.search('[_a-zA-Z]', param) else
+      ('intrinsics::TypeFromId<Type%d>' % get_counter()
+          if use_type_id else
+       'Type%d' % get_counter())
+          if re.search('[_a-zA-Z]', param) else
       'kInt%s' % get_counter()
       for param in variant.split(',')]
     assert spec is None or spec == new_spec
@@ -683,6 +756,9 @@ def _gen_intrinsics_inl_h(f, intrs):
       _gen_scalar_intr_decl(f, name, intr)
     elif intr.get('class') == 'template':
       _gen_template_intr_decl(f, name, intr)
+    else:
+      assert intr.get('class').startswith('vector')
+      _gen_vector_intr_decl(f, name, intr)
 
 
 def _gen_semantic_player_types(intrs):
@@ -707,20 +783,34 @@ def _gen_semantic_player_types(intrs):
           new_map['Type%d' % get_counter()] = (
               'FpRegister' if type.strip() in ('Float16', 'Float32', 'Float64') else
               _get_semantic_player_type(type, None))
-        assert map is None or map == new_map
-        map = new_map
+        if map is None:
+          map = new_map
+        elif map != new_map:
+          # Note: we would use literal `False` as type, which would lead to
+          # compile-time error… that's Ok, because mix of ints and floats may
+          # only happen with vector intrinsics where types used are
+          # never arguments, but just specify type of vector element.
+          # If intrinsics actually have to receive such arguments that such
+          # intrinsics should be split in two.
+          map = False
       intr['sem-player-types'] = map
 
 
 def _gen_interpreter_intrinsics_hooks_impl_inl_h(f, intrs, option):
   print(AUTOGEN, file=f)
   for name, intr in intrs:
+    if intr.get('class') == 'template':
+      _gen_interpreter_hook(
+          f, name, intr, option, use_type_id=True)
     _gen_interpreter_hook(f, name, intr, option)
 
 
 def _gen_translator_intrinsics_hooks_impl_inl_h(f, intrs):
   print(AUTOGEN, file=f)
   for name, intr in intrs:
+    if intr.get('class') == 'template':
+      _gen_translator_hook(
+          f, name, intr, use_type_id=True)
     _gen_translator_hook(f, name, intr)
 
 
@@ -770,16 +860,38 @@ def _get_reg_operand_info(arg, info_prefix=None):
 
 
 def _gen_make_intrinsics(f, intrs, archs):
-  print("""%s
+  print("%s" % AUTOGEN, file=f)
+  callback_lines = []
+  static_names = []
+  static_mnemos = []
+  for line in _gen_c_intrinsics_generator(
+      intrs, _is_interpreter_compatible_assembler, False, static_names, static_mnemos):
+    callback_lines.append(line)
+  print(
+"""
+/* Note: we generate binding names and binding mnemos used by callbacks in ProcessAllBindings
+globally so that ProcessAllBindings can be constexpr.
+
+Once we can use C++23, these can be declared locally in ProcessAllBindings.*/""", file=f)
+  print("namespace process_all_bindings_strings {", file = f)
+  for static_name in static_names:
+    print("   %s" % static_name, file=f)
+  for static_mnemo in static_mnemos:
+    print("   %s" % static_mnemo, file=f)
+  print("} // process_all_bindings_strings", file = f)
+  print("""
 template <typename MacroAssembler,
           typename Callback,
           typename... Args>
-void ProcessAllBindings([[maybe_unused]] Callback callback,
-                        [[maybe_unused]] Args&&... args) {""" % AUTOGEN,
+constexpr void ProcessAllBindings([[maybe_unused]] Callback callback,
+                        [[maybe_unused]] Args&&... args) {
+  using intrinsics::Float16;
+  using intrinsics::Float32;
+  using intrinsics::Float64;
+  using namespace process_all_bindings_strings;""",
     file=f)
-  for line in _gen_c_intrinsics_generator(
-          intrs, _is_interpreter_compatible_assembler, False): # False for gen_builder
-      print(line, file=f)
+  for line in callback_lines:
+    print(line, file=f)
   print('}', file=f)
 
 def _gen_opcode_generators_f(f, intrs):
@@ -834,25 +946,45 @@ class GetOpcode%s {
 };""" % (name, opcode)
 
 def _gen_process_bindings(f, intrs, archs):
-  print('%s' % AUTOGEN, file=f)
+  print("%s" % AUTOGEN, file=f)
+  callback_lines = []
+  static_names = []
+  static_mnemos = []
+  for line in _gen_c_intrinsics_generator(
+      intrs, _is_translator_compatible_assembler, True, static_names, static_mnemos):
+    callback_lines.append(line)
+  print(
+"""
+/* Note: we generate binding names and binding mnemos used by callbacks in ProcessBindings
+globally so that ProcessBindings can be constexpr.
+
+Once we can use C++23, these can be declared locally in ProcessBindings.*/""", file=f)
+  print("namespace process_bindings_strings {", file = f)
+  for static_name in static_names:
+    print("   %s" % static_name, file=f)
+  for static_mnemo in static_mnemos:
+    print("   %s" % static_mnemo, file=f)
+  print("} // process_bindings_strings", file = f)
   _gen_opcode_generators_f(f, intrs)
+
   print("""
 template <auto kFunc,
           typename MacroAssembler,
           typename Result,
           typename Callback,
           typename... Args>
-Result ProcessBindings(Callback callback, Result def_result, Args&&... args) {""",
+constexpr Result ProcessBindings(Callback callback, Result def_result, Args&&... args) {
+  using namespace process_bindings_strings;""",
     file=f)
-  for line in _gen_c_intrinsics_generator(
-          intrs, _is_translator_compatible_assembler, True): # True for gen_builder
-      print(line, file=f)
+  for line in callback_lines:
+    print(line, file=f)
   print("""  }
   return std::forward<Result>(def_result);
 }""", file=f)
 
 
-def _gen_c_intrinsics_generator(intrs, check_compatible_assembler, gen_builder):
+def _gen_c_intrinsics_generator(
+    intrs, check_compatible_assembler, gen_builder, static_names, static_mnemos):
   string_labels = {}
   mnemo_idx = [0]
   for name, intr in intrs:
@@ -888,7 +1020,9 @@ def _gen_c_intrinsics_generator(intrs, check_compatible_assembler, gen_builder):
                                          string_labels,
                                          mnemo_idx,
                                          check_compatible_assembler,
-                                         gen_builder):
+                                         gen_builder,
+                                         static_names,
+                                         static_mnemos):
               yield line
     else:
       for intr_asm in _gen_sorted_asms(intr):
@@ -898,7 +1032,9 @@ def _gen_c_intrinsics_generator(intrs, check_compatible_assembler, gen_builder):
                                      string_labels,
                                      mnemo_idx,
                                      check_compatible_assembler,
-                                     gen_builder):
+                                     gen_builder,
+                                     static_names,
+                                     static_mnemos):
           yield line
 
 
@@ -922,9 +1058,16 @@ _KNOWN_FEATURES_KEYS = {
   'SSE4_2': '016',
   'AVX': '017',
   'AVX2': '018',
-  'FMA': '019',
-  'FMA4': '020',
-  'CustomCapability': '021'
+  'AES': '019',
+  'AESAVX': '020',
+  'VAES': '021',
+  'CLMUL': '012',
+  'CLMULAVX': '023',
+  'VPCLMULQD': '024',
+  'F16C': '025',
+  'FMA': '026',
+  'FMA4': '027',
+  'CustomCapability': '999'
 }
 
 
@@ -934,7 +1077,9 @@ def _gen_c_intrinsic(name,
                      string_labels,
                      mnemo_idx,
                      check_compatible_assembler,
-                     gen_builder):
+                     gen_builder,
+                     static_names,
+                     static_mnemos):
   if not check_compatible_assembler(asm):
     return
 
@@ -956,23 +1101,21 @@ def _gen_c_intrinsic(name,
       name += '<' + template_arg + '>'
 
   if name not in string_labels:
-    name_label = 'kName%d' % len(string_labels)
+    name_label = 'BINDING_NAME%d' % len(string_labels)
     string_labels[name] = name_label
     if check_compatible_assembler == _is_translator_compatible_assembler:
       yield ' %s if constexpr (std::is_same_v<FunctionCompareTag<kFunc>,' % (
-        '' if name_label == 'kName0' else ' } else'
+        '' if name_label == 'BINDING_NAME0' else ' } else'
       )
       yield '                                      FunctionCompareTag<%s>>) {' % name
-    yield '    static constexpr const char %s[] = "%s";' % (
-        name_label, name)
+    static_names.append('static constexpr const char %s[] = "%s";' % (name_label, name))
   else:
     name_label = string_labels[name]
 
   mnemo = asm['mnemo']
-  mnemo_label = 'kMnemo%d' % mnemo_idx[0]
+  mnemo_label = 'BINDING_MNEMO%d' % mnemo_idx[0]
   mnemo_idx[0] += 1
-  yield '    static constexpr const char %s[] = "%s";' % (
-      mnemo_label, mnemo)
+  static_mnemos.append('static constexpr const char %s[] = "%s";' % (mnemo_label, mnemo))
 
   restriction = [cpuid_restriction, nan_restriction]
 
@@ -1004,8 +1147,7 @@ def _gen_c_intrinsic(name,
 
 def _get_c_type_tuple(arguments):
     return 'std::tuple<%s>' % ', '.join(
-        _get_c_type(argument) for argument in arguments).replace(
-            'Float', 'intrinsics::Float')
+        _get_c_type(argument) for argument in arguments)
 
 
 def _get_asm_type(asm, prefix=''):
diff --git a/intrinsics/gen_intrinsics_test.py b/intrinsics/gen_intrinsics_test.py
index cd7c0070..205ae2f4 100755
--- a/intrinsics/gen_intrinsics_test.py
+++ b/intrinsics/gen_intrinsics_test.py
@@ -15,6 +15,7 @@
 # limitations under the License.
 #
 
+import io
 import sys
 import unittest
 
@@ -48,6 +49,17 @@ class GenIntrinsicsTests(unittest.TestCase):
                                   "Register arg3, "
                                   "SimdRegister arg4, "
                                   "uint8_t arg5)" ) # pyformat: disable
+    out = gen_intrinsics._get_semantics_player_hook_proto("Foo", intr["Foo"], use_type_id=True)
+    self.assertEqual(out,
+                     "template<intrinsics::TemplateTypeId Type0, intrinsics::TemplateTypeId Type1>\n"
+                     "Register Foo(Register arg0, "
+                                  "Register arg1, "
+                                  "FpRegister arg2, "
+                                  "Register arg3, "
+                                  "SimdRegister arg4, "
+                                  "uint8_t arg5, "
+                                  "intrinsics::Value<Type0>, "
+                                  "intrinsics::Value<Type1>)" ) # pyformat: disable
 
   def test_get_semantics_player_hook_proto_operand_types(self):
     out = gen_intrinsics._get_semantics_player_hook_proto(
@@ -98,6 +110,18 @@ class GenIntrinsicsTests(unittest.TestCase):
             "GPRRegToInteger<Type1>(arg3), "
             "arg4, "
             "GPRRegToInteger<uint8_t>(arg5))))" ) # pyforman: disable
+    out = gen_intrinsics._get_interpreter_hook_call_expr("Foo", intr["Foo"], use_type_id=True)
+    self.maxDiff = None
+    self.assertEqual(
+        out,
+        "IntegerToGPRReg(std::get<0>(intrinsics::Foo<"
+                "intrinsics::TypeFromId<Type0>, intrinsics::TypeFromId<Type1>>("
+            "GPRRegToInteger<uint32_t>(arg0), "
+            "GPRRegToInteger<uint8_t>(arg1), "
+            "FPRegToFloat<intrinsics::TypeFromId<Type0>>(arg2), "
+            "GPRRegToInteger<intrinsics::TypeFromId<Type1>>(arg3), "
+            "arg4, "
+            "GPRRegToInteger<uint8_t>(arg5))))" ) # pyforman: disable
 
   def test_get_interpreter_hook_call_expr_operand_types(self):
     out = gen_intrinsics._get_interpreter_hook_call_expr(
@@ -108,8 +132,8 @@ class GenIntrinsicsTests(unittest.TestCase):
     self.assertEqual(out,
                      "intrinsics::Foo(GPRRegToInteger<uint32_t>(arg0), "
                                      "GPRRegToInteger<uint8_t>(arg1), "
-                                     "FPRegToFloat<intrinsics::Float32>(arg2), "
-                                     "FPRegToFloat<intrinsics::Float64>(arg3), "
+                                     "FPRegToFloat<Float32>(arg2), "
+                                     "FPRegToFloat<Float64>(arg3), "
                                      "arg4, "
                                      "GPRRegToInteger<uint8_t>(arg5))" ) # pyforman: disable
 
@@ -215,7 +239,7 @@ class GenIntrinsicsTests(unittest.TestCase):
                              ("auto format = intrinsics::GetVectorFormatFP(elem_size, elem_num);",
                               "switch (format) {",
                               "  case intrinsics::kVectorF32x4:" ,
-                              "    return std::get<0>(intrinsics::Foo<intrinsics::Float32, 4>(arg0, arg1));",
+                              "    return std::get<0>(intrinsics::Foo<Float32, 4>(arg0, arg1));",
                               "  default:",
                               "    LOG_ALWAYS_FATAL(\"Unsupported format\");",
                               "}")) # pyformat: disable
@@ -380,5 +404,28 @@ class GenIntrinsicsTests(unittest.TestCase):
                               "    LOG_ALWAYS_FATAL(\"Unsupported format\");",
                               "}")) # pyformat: disable
 
+
+  def test_gen_template_parameters_verifier(self):
+    intrinsic = {
+            "class": "template",
+            "variants": [ "int32_t", "int64_t" ],
+            "in": [ "Type0", "int8_t" ],
+            "out": [ "Type0" ]
+        }
+    out = io.StringIO()
+    gen_intrinsics._gen_template_parameters_verifier(out, intrinsic)
+    self.assertSequenceEqual(out.getvalue(),
+                             "  static_assert(std::tuple{intrinsics::kIdFromType<Type0>} == "
+                             "std::tuple{intrinsics::kIdFromType<int32_t>} || "
+                             "std::tuple{intrinsics::kIdFromType<Type0>} == "
+                             "std::tuple{intrinsics::kIdFromType<int64_t>});\n") # pyformat: disable
+    out = io.StringIO()
+    gen_intrinsics._gen_template_parameters_verifier(out, intrinsic, use_type_id=True)
+    self.assertSequenceEqual(out.getvalue(),
+                             "  static_assert(std::tuple{Type0} == "
+                             "std::tuple{intrinsics::kIdFromType<int32_t>} || std::tuple{Type0} == "
+                             "std::tuple{intrinsics::kIdFromType<int64_t>});\n") # pyformat: disable
+
+
 if __name__ == "__main__":
   unittest.main(verbosity=2)
diff --git a/intrinsics/gen_text_asm_intrinsics.cc b/intrinsics/gen_text_asm_intrinsics.cc
index f8c0849a..49884214 100644
--- a/intrinsics/gen_text_asm_intrinsics.cc
+++ b/intrinsics/gen_text_asm_intrinsics.cc
@@ -33,6 +33,7 @@
 #include "berberis/intrinsics/macro_assembler.h"
 #include "berberis/intrinsics/simd_register.h"
 #include "berberis/intrinsics/type_traits.h"
+#include "berberis/intrinsics/verifier_assembler.h"
 
 #include "text_assembler.h"
 
@@ -45,10 +46,6 @@ void GenerateTemporaries(FILE* out, int indent);
 template <typename AsmCallInfo>
 void GenerateInShadows(FILE* out, int indent);
 template <typename AsmCallInfo>
-void AssignRegisterNumbers(int* register_numbers);
-template <typename AsmCallInfo>
-auto CallTextAssembler(FILE* out, int indent, int* register_numbers);
-template <typename AsmCallInfo>
 void GenerateAssemblerOuts(FILE* out, int indent);
 template <typename AsmCallInfo>
 void GenerateAssemblerIns(FILE* out,
@@ -99,6 +96,72 @@ void GenerateFunctionHeader(FILE* out, int indent) {
           " scratch[berberis::config::kScratchAreaSlotSize];\n");
 }
 
+template <typename AsmCallInfo>
+constexpr void CallAssembler(MacroAssembler<TextAssembler>* as, int* register_numbers) {
+  int arg_counter = 0;
+  AsmCallInfo::ProcessBindings([&arg_counter, &as, register_numbers](auto arg) {
+    using RegisterClass = typename decltype(arg)::RegisterClass;
+    if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
+      if constexpr (RegisterClass::kAsRegister != 'm') {
+        if constexpr (RegisterClass::kIsImplicitReg) {
+          if constexpr (RegisterClass::kAsRegister == 'a') {
+            as->gpr_a =
+                typename MacroAssembler<TextAssembler>::Register(register_numbers[arg_counter]);
+          } else if constexpr (RegisterClass::kAsRegister == 'b') {
+            as->gpr_b =
+                typename MacroAssembler<TextAssembler>::Register(register_numbers[arg_counter]);
+          } else if constexpr (RegisterClass::kAsRegister == 'c') {
+            as->gpr_c =
+                typename MacroAssembler<TextAssembler>::Register(register_numbers[arg_counter]);
+          } else {
+            static_assert(RegisterClass::kAsRegister == 'd');
+            as->gpr_d =
+                typename MacroAssembler<TextAssembler>::Register(register_numbers[arg_counter]);
+          }
+        }
+      }
+      ++arg_counter;
+    }
+  });
+  as->gpr_macroassembler_constants = typename MacroAssembler<TextAssembler>::Register(arg_counter);
+  arg_counter = 0;
+  int scratch_counter = 0;
+  std::apply(AsmCallInfo::kMacroInstruction,
+             std::tuple_cat(
+                 std::tuple<MacroAssembler<TextAssembler>&>{*as},
+                 AsmCallInfo::MakeTuplefromBindings(
+                     [&as, &arg_counter, &scratch_counter, register_numbers](auto arg) {
+                       using RegisterClass = typename decltype(arg)::RegisterClass;
+                       if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
+                         if constexpr (RegisterClass::kAsRegister == 'm') {
+                           if (scratch_counter == 0) {
+                             as->gpr_macroassembler_scratch =
+                                 typename MacroAssembler<TextAssembler>::Register(arg_counter++);
+                           } else if (scratch_counter == 1) {
+                             as->gpr_macroassembler_scratch2 =
+                                 typename MacroAssembler<TextAssembler>::Register(arg_counter++);
+                           } else {
+                             FATAL("Only two scratch registers are supported for now");
+                           }
+                           // Note: as->gpr_scratch in combination with offset is treated by text
+                           // assembler specially.  We rely on offset set here to be the same as
+                           // scratch2 address in scratch buffer.
+                           return std::tuple{typename MacroAssembler<TextAssembler>::Operand{
+                               .base = as->gpr_scratch,
+                               .disp = static_cast<int32_t>(config::kScratchAreaSlotSize *
+                                                            scratch_counter++)}};
+                         } else if constexpr (RegisterClass::kIsImplicitReg) {
+                           ++arg_counter;
+                           return std::tuple{};
+                         } else {
+                           return std::tuple{register_numbers[arg_counter++]};
+                         }
+                       } else {
+                         return std::tuple{};
+                       }
+                     })));
+}
+
 template <typename AsmCallInfo>
 void GenerateFunctionBody(FILE* out, int indent) {
   // Declare out variables.
@@ -123,16 +186,16 @@ void GenerateFunctionBody(FILE* out, int indent) {
     fprintf(out, "%*s__asm__(\n", indent, "");
   }
   // Call text assembler to produce the body of an asm call.
-  auto [need_gpr_macroassembler_scratch, need_gpr_macroassembler_constants] =
-      CallTextAssembler<AsmCallInfo>(out, indent, register_numbers);
+  MacroAssembler<TextAssembler> as(indent, out);
+  CallAssembler<AsmCallInfo>(&as, register_numbers);
   // Assembler instruction outs.
   GenerateAssemblerOuts<AsmCallInfo>(out, indent);
   // Assembler instruction ins.
   GenerateAssemblerIns<AsmCallInfo>(out,
                                     indent,
                                     register_numbers,
-                                    need_gpr_macroassembler_scratch,
-                                    need_gpr_macroassembler_constants);
+                                    as.need_gpr_macroassembler_scratch(),
+                                    as.need_gpr_macroassembler_constants());
   // Close asm call.
   fprintf(out, "%*s);\n", indent, "");
   // Generate copies from shadows to outputs.
@@ -210,6 +273,18 @@ void GenerateInShadows(FILE* out, int indent) {
           // {,u}int32_t and {,u}int64_t have to be converted to float/double.
           xmm_type_name =
               TypeTraits<typename TypeTraits<typename TypeTraits<Type>::Float>::Raw>::kName;
+        } else if constexpr (std::is_same_v<Type, intrinsics::Float16>) {
+          // It's a bit strange that _Float16 is not accepted in XMM register, but it's also not
+          // clear if it's a bug or not. Just use __m128 for now.
+          fprintf(out, "%2$*1$s__m128 in%3$d_expanded;\n", indent, "", arg.arg_info.from);
+          fprintf(out,
+                  "%2$*1$smemcpy(&in%3$d_expanded, &in%3$d, sizeof(Float16));\n",
+                  indent,
+                  "",
+                  arg.arg_info.from);
+          type_name = "__m128";
+          xmm_type_name = "__m128";
+          expanded = "_expanded";
         } else {
           // Float32/Float64 can not be used, we need to use raw float/double.
           xmm_type_name = TypeTraits<typename TypeTraits<Type>::Raw>::kName;
@@ -239,6 +314,10 @@ void GenerateInShadows(FILE* out, int indent) {
         if constexpr (std::is_integral_v<Type>) {
           xmm_type_name =
               TypeTraits<typename TypeTraits<typename TypeTraits<Type>::Float>::Raw>::kName;
+        } else if constexpr (std::is_same_v<Type, intrinsics::Float16>) {
+          // It's a bit strange that _Float16 is not accepted in XMM register, but it's also not
+          // clear if it's a bug or not. Just use __m128 for now.
+          xmm_type_name = "__m128";
         } else {
           // Float32/Float64 can not be used, we need to use raw float/double.
           xmm_type_name = TypeTraits<typename TypeTraits<Type>::Raw>::kName;
@@ -249,96 +328,6 @@ void GenerateInShadows(FILE* out, int indent) {
   });
 }
 
-template <typename AsmCallInfo>
-void AssignRegisterNumbers(int* register_numbers) {
-  // Assign number for output (and temporary) arguments.
-  std::size_t id = 0;
-  int arg_counter = 0;
-  AsmCallInfo::ProcessBindings([&id, &arg_counter, &register_numbers](auto arg) {
-    using RegisterClass = typename decltype(arg)::RegisterClass;
-    if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-      if constexpr (!std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::Use>) {
-        register_numbers[arg_counter] = id++;
-      }
-      ++arg_counter;
-    }
-  });
-  // Assign numbers for input arguments.
-  arg_counter = 0;
-  AsmCallInfo::ProcessBindings([&id, &arg_counter, &register_numbers](auto arg) {
-    using RegisterClass = typename decltype(arg)::RegisterClass;
-    if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-      if constexpr (std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::Use>) {
-        register_numbers[arg_counter] = id++;
-      }
-      ++arg_counter;
-    }
-  });
-}
-
-template <typename AsmCallInfo>
-auto CallTextAssembler(FILE* out, int indent, int* register_numbers) {
-  MacroAssembler<TextAssembler> as(indent, out);
-  int arg_counter = 0;
-  AsmCallInfo::ProcessBindings([&arg_counter, &as, register_numbers](auto arg) {
-    using RegisterClass = typename decltype(arg)::RegisterClass;
-    if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-      if constexpr (RegisterClass::kAsRegister != 'm') {
-        if constexpr (RegisterClass::kIsImplicitReg) {
-          if constexpr (RegisterClass::kAsRegister == 'a') {
-            as.gpr_a = TextAssembler::Register(register_numbers[arg_counter]);
-          } else if constexpr (RegisterClass::kAsRegister == 'c') {
-            as.gpr_c = TextAssembler::Register(register_numbers[arg_counter]);
-          } else {
-            static_assert(RegisterClass::kAsRegister == 'd');
-            as.gpr_d = TextAssembler::Register(register_numbers[arg_counter]);
-          }
-        }
-      }
-      ++arg_counter;
-    }
-  });
-  as.gpr_macroassembler_constants = TextAssembler::Register(arg_counter);
-  arg_counter = 0;
-  int scratch_counter = 0;
-  std::apply(AsmCallInfo::kMacroInstruction,
-             std::tuple_cat(
-                 std::tuple<MacroAssembler<TextAssembler>&>{as},
-                 AsmCallInfo::MakeTuplefromBindings(
-                     [&as, &arg_counter, &scratch_counter, register_numbers](auto arg) {
-                       using RegisterClass = typename decltype(arg)::RegisterClass;
-                       if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
-                         if constexpr (RegisterClass::kAsRegister == 'm') {
-                           if (scratch_counter == 0) {
-                             as.gpr_macroassembler_scratch = TextAssembler::Register(arg_counter++);
-                           } else if (scratch_counter == 1) {
-                             as.gpr_macroassembler_scratch2 =
-                                 TextAssembler::Register(arg_counter++);
-                           } else {
-                             FATAL("Only two scratch registers are supported for now");
-                           }
-                           // Note: as.gpr_scratch in combination with offset is treated by text
-                           // assembler specially.  We rely on offset set here to be the same as
-                           // scratch2 address in scratch buffer.
-                           return std::tuple{TextAssembler::Operand{
-                               .base = as.gpr_scratch,
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
-  // Verify CPU vendor and SSE restrictions.
-  as.CheckCPUIDRestriction<typename AsmCallInfo::CPUIDRestriction>();
-  return std::tuple{as.need_gpr_macroassembler_scratch(), as.need_gpr_macroassembler_constants()};
-}
-
 template <typename AsmCallInfo>
 void GenerateAssemblerOuts(FILE* out, int indent) {
   std::vector<std::string> outs;
@@ -432,12 +421,17 @@ void GenerateOutShadows(FILE* out, int indent) {
           // Float32/Float64 can not be used, we need to use raw float/double.
           xmm_type_name = TypeTraits<typename TypeTraits<Type>::Raw>::kName;
         }
-        fprintf(out,
-                "%*sstatic_assert(sizeof(%s) == sizeof(%s));\n",
-                indent,
-                "",
-                type_name,
-                xmm_type_name);
+        // It's a bit strange that _Float16 is not accepted in XMM register, but it's also not
+        // clear if it's a bug or not. We use __m128 for now and that means size of types don't
+        // match here.
+        if constexpr (!std::is_same_v<Type, intrinsics::Float16>) {
+          fprintf(out,
+                  "%*sstatic_assert(sizeof(%s) == sizeof(%s));\n",
+                  indent,
+                  "",
+                  type_name,
+                  xmm_type_name);
+        }
         // Note: it's not safe to use bit_cast here till we have std::bit_cast from C++20.
         // If optimizer wouldn't be enabled (e.g. if code is compiled with -O0) then bit_cast
         // would use %st on 32-bit platform which destroys NaNs.
@@ -524,7 +518,40 @@ constexpr bool NeedOutputShadow(Arg arg) {
 
 #include "text_asm_intrinsics_process_bindings-inl.h"
 
+template <typename AsmCallInfo>
+constexpr void VerifyIntrinsic() {
+  int register_numbers[std::tuple_size_v<typename AsmCallInfo::Bindings> == 0
+                           ? 1
+                           : std::tuple_size_v<typename AsmCallInfo::Bindings>];
+  AssignRegisterNumbers<AsmCallInfo>(register_numbers);
+  MacroAssembler<VerifierAssembler> as;
+  CallVerifierAssembler<AsmCallInfo, MacroAssembler<VerifierAssembler>>(&as, register_numbers);
+  // Verify CPU vendor and SSE restrictions.
+  as.CheckCPUIDRestriction<typename AsmCallInfo::CPUIDRestriction>();
+
+  // Verify that intrinsic's bindings correctly states that intrinsic uses/doesn't use FLAGS
+  // register.
+  bool expect_flags = false;
+  CheckIntrinsicHasFlagsBinding<AsmCallInfo>(expect_flags);
+  as.CheckFlagsBinding(expect_flags);
+  as.CheckAppropriateDefEarlyClobbers();
+  as.CheckLabelsAreBound();
+}
+
+constexpr bool VerifyTextAsmIntrinsics() {
+  ProcessAllBindings<MacroAssembler<VerifierAssembler>::MacroAssemblers>(
+      [](auto&& asm_call_generator) {
+        using AsmCallInfo = std::decay_t<decltype(asm_call_generator)>;
+        VerifyIntrinsic<AsmCallInfo>();
+      });
+  return true;
+}
+
 void GenerateTextAsmIntrinsics(FILE* out) {
+  // Verifier assembler verifies that CPU vendor and SSE restrictions for intrinsics are defined
+  // correctly.
+  static_assert(VerifyTextAsmIntrinsics());
+
   // Note: nullptr means "NoCPUIDRestriction", other values are only assigned in one place below
   // since the code in this function mostly cares only about three cases:
   //   • There are no CPU restrictions.
diff --git a/intrinsics/include/berberis/intrinsics/common/constants_pool.h b/intrinsics/include/berberis/intrinsics/common/constants_pool.h
new file mode 100644
index 00000000..2ba077bc
--- /dev/null
+++ b/intrinsics/include/berberis/intrinsics/common/constants_pool.h
@@ -0,0 +1,108 @@
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
+#ifndef BERBERIS_INTRINSICS_COMMON_CONSTANTS_POOL_H_
+#define BERBERIS_INTRINSICS_COMMON_CONSTANTS_POOL_H_
+
+#include <stdint.h>
+#include <bit>
+
+#include <type_traits>
+
+namespace berberis {
+
+namespace constants_pool {
+
+#if defined(__i386__) || defined(__x86_64__)
+using ConstPoolAddrType = int32_t;
+#else
+using ConstPoolAddrType = intptr_t;
+#endif
+
+// Vector constants, that is: constants are repeated to fill 128bit SIMD register.
+template <auto Value, typename = void>
+struct VectorConst {};
+
+template <auto Value>
+inline const int32_t& kVectorConst = VectorConst<Value>::kValue;
+
+template <auto Value>
+struct VectorConst<Value,
+                   std::enable_if_t<std::is_unsigned_v<std::remove_cvref_t<decltype(Value)>>>> {
+  static constexpr const ConstPoolAddrType& kValue =
+      kVectorConst<static_cast<std::make_signed_t<std::remove_cvref_t<decltype(Value)>>>(Value)>;
+};
+
+template <float Value>
+struct VectorConst<Value> {
+  static constexpr const ConstPoolAddrType& kValue = kVectorConst<std::bit_cast<int32_t>(Value)>;
+};
+
+template <double Value>
+struct VectorConst<Value> {
+  static constexpr const ConstPoolAddrType& kValue = kVectorConst<std::bit_cast<int64_t>(Value)>;
+};
+
+}  // namespace constants_pool
+
+namespace constants_offsets {
+
+// constants_offsets namespace includes compile-time versions of constants used in macro assembler
+// functions. This allows the static verifier assembler to use static versions of the macro-
+// assembly functions.
+using ConstPoolAddrType = constants_pool::ConstPoolAddrType;
+
+template <const int32_t* constant_addr>
+class ConstantAccessor {
+ public:
+  constexpr operator ConstPoolAddrType() const {
+    if (std::is_constant_evaluated()) {
+      return 0;
+    } else {
+      return *constant_addr;
+    }
+  }
+};
+
+template <const auto Value>
+class TypeConstantAccessor {
+ public:
+  constexpr operator ConstPoolAddrType() const {
+    if (std::is_constant_evaluated()) {
+      return 0;
+    } else {
+      return *Value;
+    }
+  }
+};
+
+template <const auto Value>
+class VectorConstantAccessor {
+ public:
+  constexpr operator ConstPoolAddrType() const {
+    if (std::is_constant_evaluated()) {
+      return 0;
+    } else {
+      return constants_pool::VectorConst<Value>::kValue;
+    }
+  }
+};
+
+}  // namespace constants_offsets
+
+}  // namespace berberis
+
+#endif  // BERBERIS_INTRINSICS_COMMON_CONSTANTS_POOL_H_
diff --git a/intrinsics/include/berberis/intrinsics/common/intrinsics.h b/intrinsics/include/berberis/intrinsics/common/intrinsics.h
index dda437d4..6550bc94 100644
--- a/intrinsics/include/berberis/intrinsics/common/intrinsics.h
+++ b/intrinsics/include/berberis/intrinsics/common/intrinsics.h
@@ -19,6 +19,7 @@
 
 #include <cstdint>
 
+#include "berberis/base/checks.h"
 #include "berberis/base/dependent_false.h"
 #include "berberis/intrinsics/common/intrinsics_float.h"  // Float16/Float32/Float64
 
@@ -27,56 +28,199 @@ namespace berberis {
 class SIMD128Register;
 
 namespace intrinsics {
-#if !defined(__aarch64__)
-enum EnumFromTemplateType {
-  kInt8T,
-  kUInt8T,
-  kInt16T,
-  kUInt16T,
-  kInt32T,
-  kUInt32T,
-  kInt64T,
-  kUInt64T,
-  kFloat16,
-  kFloat32,
-  kFloat64,
-  kSIMD128Register,
+
+// Value that's passed as argument of function or lambda couldn't be constexpr, but if it's
+// passed as part of argument type then it's different.
+// Class Value is empty, but carries the required information in its type.
+// It can also be automatically converted into value of the specified type when needed.
+// That way we can pass argument into a template as normal, non-template argument.
+template <auto ValueParam>
+class Value {
+ public:
+  using ValueType = std::remove_cvref_t<decltype(ValueParam)>;
+  static constexpr auto kValue = ValueParam;
+  constexpr operator ValueType() const { return kValue; }
+};
+
+enum TemplateTypeId : uint8_t {
+  kInt8T = 1,
+  kUInt8T = 0,
+  kInt16T = 3,
+  kUInt16T = 2,
+  kInt32T = 5,
+  kUInt32T = 4,
+  kInt64T = 7,
+  kUInt64T = 6,
+  kFloat16 = 10,
+  kFloat32 = 12,
+  kFloat64 = 14,
+  kSIMD128Register = 16,
 };
 
+constexpr TemplateTypeId TemplateTypeIdToFloat(TemplateTypeId value) {
+  DCHECK(value >= kUInt16T && value <= kInt64T);
+  return TemplateTypeId{static_cast<uint8_t>((value & 0x6) + 8)};
+}
+
+constexpr TemplateTypeId TemplateTypeIdToInt(TemplateTypeId value) {
+  DCHECK((value >= kFloat16 && value <= kFloat64) && !(value & 1));
+  return TemplateTypeId{static_cast<uint8_t>(value - 8)};
+}
+
+constexpr TemplateTypeId TemplateTypeIdToNarrow(TemplateTypeId value) {
+  DCHECK((value >= kUInt16T && value <= kInt64T) ||
+         ((value >= kFloat32 && value <= kFloat64) && !(value & 1)));
+  return TemplateTypeId{static_cast<uint8_t>(value - 2)};
+}
+
+constexpr TemplateTypeId TemplateTypeIdToSigned(TemplateTypeId value) {
+  DCHECK(value <= kInt64T);
+  return TemplateTypeId{static_cast<uint8_t>(value | 1)};
+}
+
+constexpr int TemplateTypeIdSizeOf(TemplateTypeId value) {
+  if (value == kSIMD128Register) {
+    return 16;
+  }
+  return 1 << ((value & 0b110) >> 1);
+}
+
+constexpr TemplateTypeId TemplateTypeIdToUnsigned(TemplateTypeId value) {
+  DCHECK(value <= kInt64T);
+  return TemplateTypeId{static_cast<uint8_t>(value & ~1)};
+}
+
+constexpr TemplateTypeId TemplateTypeIdToWide(TemplateTypeId value) {
+  DCHECK(value <= kInt32T || ((value >= kFloat16 && value <= kFloat32) && !(value & 1)));
+  return TemplateTypeId{static_cast<uint8_t>(value + 2)};
+}
+
 template <typename Type>
-constexpr EnumFromTemplateType TypeToEnumFromTemplateType() {
+constexpr TemplateTypeId IdFromType() {
   if constexpr (std::is_same_v<int8_t, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kInt8T;
+    return TemplateTypeId::kInt8T;
   } else if constexpr (std::is_same_v<uint8_t, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kUInt8T;
+    return TemplateTypeId::kUInt8T;
   } else if constexpr (std::is_same_v<int16_t, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kUInt16T;
+    return TemplateTypeId::kInt16T;
   } else if constexpr (std::is_same_v<uint16_t, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kUInt16T;
+    return TemplateTypeId::kUInt16T;
   } else if constexpr (std::is_same_v<int32_t, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kUInt32T;
+    return TemplateTypeId::kInt32T;
   } else if constexpr (std::is_same_v<uint32_t, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kUInt32T;
+    return TemplateTypeId::kUInt32T;
   } else if constexpr (std::is_same_v<int64_t, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kUInt64T;
+    return TemplateTypeId::kInt64T;
   } else if constexpr (std::is_same_v<uint64_t, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kUInt64T;
+    return TemplateTypeId::kUInt64T;
   } else if constexpr (std::is_same_v<Float16, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kFloat16;
+    return TemplateTypeId::kFloat16;
   } else if constexpr (std::is_same_v<Float32, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kFloat32;
-  } else if constexpr (std::is_same_v<Float64, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kFloat64;
+    return TemplateTypeId::kFloat32;
   } else if constexpr (std::is_same_v<Float64, std::decay_t<Type>>) {
-    return EnumFromTemplateType::kSIMD128Register;
+    return TemplateTypeId::kFloat64;
+  } else if constexpr (std::is_same_v<SIMD128Register, std::decay_t<Type>>) {
+    return TemplateTypeId::kSIMD128Register;
   } else {
     static_assert(kDependentTypeFalse<Type>);
   }
 }
 
 template <typename Type>
-constexpr EnumFromTemplateType kEnumFromTemplateType = TypeToEnumFromTemplateType<Type>();
-#endif
+constexpr TemplateTypeId kIdFromType = IdFromType<Type>();
+
+constexpr TemplateTypeId IntSizeToTemplateTypeId(uint8_t size, bool is_signed = false) {
+  DCHECK(std::has_single_bit(size));
+  DCHECK(size < 16);
+  return static_cast<TemplateTypeId>((std::countr_zero(size) << 1) + is_signed);
+}
+
+template <enum TemplateTypeId>
+class TypeFromIdHelper;
+
+#pragma push_macro("DEFINE_TEMPLATE_TYPE_FROM_ENUM")
+#undef DEFINE_TEMPLATE_TYPE_FROM_ENUM
+#define DEFINE_TEMPLATE_TYPE_FROM_ENUM(kEnumValue, TemplateType) \
+  template <>                                                    \
+  class TypeFromIdHelper<kEnumValue> {                           \
+   public:                                                       \
+    using Type = TemplateType;                                   \
+  }
+
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kInt8T, int8_t);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kUInt8T, uint8_t);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kInt16T, int16_t);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kUInt16T, uint16_t);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kInt32T, int32_t);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kUInt32T, uint32_t);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kInt64T, int64_t);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kUInt64T, uint64_t);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kFloat16, Float16);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kFloat32, Float32);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kFloat64, Float64);
+DEFINE_TEMPLATE_TYPE_FROM_ENUM(kSIMD128Register, SIMD128Register);
+
+#pragma pop_macro("DEFINE_TEMPLATE_TYPE_FROM_ENUM")
+
+template <enum TemplateTypeId kEnumValue>
+using TypeFromId = TypeFromIdHelper<kEnumValue>::Type;
+
+// If we carry TemplateTypeId then we can do the exact same manipulations wuth it as with
+// normal value, but also can get actual type from it and do appropriate operations:
+// make signed, make unsigned, widen, narrow, etc.
+template <TemplateTypeId ValueParam>
+class Value<ValueParam> {
+ public:
+  using Type = TypeFromId<ValueParam>;
+  using ValueType = TemplateTypeId;
+  static constexpr auto kValue = ValueParam;
+  constexpr operator TemplateTypeId() const { return kValue; }
+};
+
+#pragma push_macro("DEFINE_VALUE_FUNCTION")
+#undef DEFINE_VALUE_FUNCTION
+#define DEFINE_VALUE_FUNCTION(FunctionName)                                   \
+  template <TemplateTypeId ValueParam>                                        \
+  constexpr Value<FunctionName(ValueParam)> FunctionName(Value<ValueParam>) { \
+    return {};                                                                \
+  }
+
+DEFINE_VALUE_FUNCTION(TemplateTypeIdToFloat)
+DEFINE_VALUE_FUNCTION(TemplateTypeIdToInt)
+DEFINE_VALUE_FUNCTION(TemplateTypeIdToNarrow)
+DEFINE_VALUE_FUNCTION(TemplateTypeIdToSigned)
+DEFINE_VALUE_FUNCTION(TemplateTypeIdSizeOf)
+DEFINE_VALUE_FUNCTION(TemplateTypeIdToUnsigned)
+DEFINE_VALUE_FUNCTION(TemplateTypeIdToWide)
+
+#pragma pop_macro("DEFINE_VALUE_FUNCTION")
+
+#pragma push_macro("DEFINE_VALUE_OPERATOR")
+#undef DEFINE_VALUE_OPERATOR
+#define DEFINE_VALUE_OPERATOR(operator_name)                                       \
+  template <auto ValueParam1, auto ValueParam2>                                    \
+  constexpr Value<(ValueParam1 operator_name ValueParam2)> operator operator_name( \
+      Value<ValueParam1>, Value<ValueParam2>) {                                    \
+    return {};                                                                     \
+  }
+
+DEFINE_VALUE_OPERATOR(+)
+DEFINE_VALUE_OPERATOR(-)
+DEFINE_VALUE_OPERATOR(*)
+DEFINE_VALUE_OPERATOR(/)
+DEFINE_VALUE_OPERATOR(<<)
+DEFINE_VALUE_OPERATOR(>>)
+DEFINE_VALUE_OPERATOR(==)
+DEFINE_VALUE_OPERATOR(!=)
+DEFINE_VALUE_OPERATOR(>)
+DEFINE_VALUE_OPERATOR(<)
+DEFINE_VALUE_OPERATOR(<=)
+DEFINE_VALUE_OPERATOR(>=)
+DEFINE_VALUE_OPERATOR(&&)
+DEFINE_VALUE_OPERATOR(||)
+
+#pragma pop_macro("DEFINE_VALUE_OPERATOR")
+
 // A solution for the inability to call generic implementation from specialization.
 // Declaration:
 //   template <typename Type,
diff --git a/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h b/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h
index 4b82329d..637912b3 100644
--- a/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h
+++ b/intrinsics/include/berberis/intrinsics/common/intrinsics_bindings.h
@@ -23,7 +23,9 @@
 #include "berberis/intrinsics/intrinsics_args.h"
 #include "berberis/intrinsics/type_traits.h"
 
-namespace berberis::intrinsics::bindings {
+namespace berberis {
+
+namespace intrinsics::bindings {
 
 class FLAGS {
  public:
@@ -87,6 +89,8 @@ constexpr auto ToRegKind() {
 template <typename Tag, typename MachineRegKind>
 inline constexpr auto kRegKind = ToRegKind<Tag, MachineRegKind>();
 
+enum RegBindingKind { kDef, kDefEarlyClobber, kUse, kUseDef, kUndefined };
+
 // Tag classes. They are never instantioned, only used as tags to pass information about
 // bindings.
 class NoCPUIDRestriction;  // All CPUs have at least “no CPUID restriction” mode.
@@ -170,6 +174,154 @@ class AsmCallInfo<kIntrinsicTemplateName,
                                       BindingsTypes...>;
 };
 
-}  // namespace berberis::intrinsics::bindings
+}  // namespace intrinsics::bindings
+
+template <typename AsmCallInfo>
+constexpr void AssignRegisterNumbers(int* register_numbers) {
+  // Assign number for output (and temporary) arguments.
+  std::size_t id = 0;
+  int arg_counter = 0;
+  AsmCallInfo::ProcessBindings([&id, &arg_counter, &register_numbers](auto arg) {
+    if constexpr (!IsImmediate(decltype(arg)::arg_info)) {
+      using RegisterClass = typename decltype(arg)::RegisterClass;
+      if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
+        if constexpr (!std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::Use>) {
+          register_numbers[arg_counter] = id++;
+        }
+        ++arg_counter;
+      }
+    }
+  });
+  // Assign numbers for input arguments.
+  arg_counter = 0;
+  AsmCallInfo::ProcessBindings([&id, &arg_counter, &register_numbers](auto arg) {
+    if constexpr (!IsImmediate(decltype(arg)::arg_info)) {
+      using RegisterClass = typename decltype(arg)::RegisterClass;
+      if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
+        if constexpr (std::is_same_v<typename decltype(arg)::Usage, intrinsics::bindings::Use>) {
+          register_numbers[arg_counter] = id++;
+        }
+        ++arg_counter;
+      }
+    }
+  });
+}
+
+template <typename AsmCallInfo>
+constexpr void CheckIntrinsicHasFlagsBinding(bool& expect_flags) {
+  AsmCallInfo::ProcessBindings([&expect_flags](auto arg) {
+    if constexpr (!IsImmediate(decltype(arg)::arg_info)) {
+      using RegisterClass = typename decltype(arg)::RegisterClass;
+      if constexpr (std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
+        expect_flags = true;
+      }
+    }
+  });
+}
+
+template <typename AsmCallInfo, typename AssemblerType>
+constexpr void CallVerifierAssembler(AssemblerType* as, int* register_numbers) {
+  int arg_counter = 0;
+  AsmCallInfo::ProcessBindings([&arg_counter, &as, register_numbers](auto arg) {
+    if constexpr (!IsImmediate(decltype(arg)::arg_info)) {
+      using RegisterClass = typename decltype(arg)::RegisterClass;
+      if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
+        if constexpr (RegisterClass::kAsRegister != 'm') {
+          if constexpr (RegisterClass::kIsImplicitReg) {
+            if constexpr (RegisterClass::kAsRegister == 'a') {
+              as->gpr_a = typename AssemblerType::Register(
+                  register_numbers[arg_counter],
+                  intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
+                                                  intrinsics::bindings::RegBindingKind>());
+            } else if constexpr (RegisterClass::kAsRegister == 'b') {
+              as->gpr_b = typename AssemblerType::Register(
+                  register_numbers[arg_counter],
+                  intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
+                                                  intrinsics::bindings::RegBindingKind>());
+            } else if constexpr (RegisterClass::kAsRegister == 'c') {
+              as->gpr_c = typename AssemblerType::Register(
+                  register_numbers[arg_counter],
+                  intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
+                                                  intrinsics::bindings::RegBindingKind>());
+            } else {
+              static_assert(RegisterClass::kAsRegister == 'd');
+              as->gpr_d = typename AssemblerType::Register(
+                  register_numbers[arg_counter],
+                  intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
+                                                  intrinsics::bindings::RegBindingKind>());
+            }
+          }
+        }
+        ++arg_counter;
+      }
+    }
+  });
+  as->gpr_macroassembler_constants = typename AssemblerType::Register(arg_counter);
+  arg_counter = 0;
+  int scratch_counter = 0;
+  std::apply(
+      AsmCallInfo::kMacroInstruction,
+      std::tuple_cat(
+          std::tuple<AssemblerType&>{*as},
+          AsmCallInfo::MakeTuplefromBindings([&as,
+                                              &arg_counter,
+                                              &scratch_counter,
+                                              register_numbers](auto arg) {
+            if constexpr (IsImmediate(decltype(arg)::arg_info)) {
+              // TODO(b/394278175): We don't have access to the value of the immediate argument
+              // here. The value of the immediate argument often decides which instructions in
+              // an intrinsic are called, by being used in conditional statements. We need to
+              // make sure that all possible instructions in the intrinsic are executed when
+              // using VerifierAssembler on inline-only intrinsics. For now, we set immediate
+              // argument to 2, since it generally covers most instructions in inline-only
+              // intrinsics.
+              return std::tuple{2};
+            } else {
+              using RegisterClass = typename decltype(arg)::RegisterClass;
+              if constexpr (!std::is_same_v<RegisterClass, intrinsics::bindings::FLAGS>) {
+                if constexpr (RegisterClass::kAsRegister == 'm') {
+                  if (scratch_counter == 0) {
+                    as->gpr_macroassembler_scratch =
+                        typename AssemblerType::Register(arg_counter++);
+                  } else if (scratch_counter == 1) {
+                    as->gpr_macroassembler_scratch2 =
+                        typename AssemblerType::Register(arg_counter++);
+                  } else {
+                    FATAL("Only two scratch registers are supported for now");
+                  }
+                  // Note: as->gpr_scratch in combination with offset is treated by text
+                  // assembler specially.  We rely on offset set here to be the same as
+                  // scratch2 address in scratch buffer.
+                  return std::tuple{typename AssemblerType::Operand{
+                      .base = as->gpr_scratch,
+                      .disp =
+                          static_cast<int32_t>(config::kScratchAreaSlotSize * scratch_counter++)}};
+                } else if constexpr (RegisterClass::kIsImplicitReg) {
+                  ++arg_counter;
+                  return std::tuple{};
+                } else {
+                  if constexpr (RegisterClass::kAsRegister == 'q' ||
+                                RegisterClass::kAsRegister == 'r') {
+                    return std::tuple{typename AssemblerType::Register(
+                        register_numbers[arg_counter++],
+                        intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
+                                                        intrinsics::bindings::RegBindingKind>())};
+                  } else if constexpr (RegisterClass::kAsRegister == 'x') {
+                    return std::tuple{typename AssemblerType::XRegister(
+                        register_numbers[arg_counter++],
+                        intrinsics::bindings::ToRegKind<typename decltype(arg)::Usage,
+                                                        intrinsics::bindings::RegBindingKind>())};
+                  } else {
+                    static_assert(kDependentValueFalse<RegisterClass::kAsRegister>);
+                  }
+                }
+              } else {
+                return std::tuple{};
+              }
+            }
+          })));
+}
+
+}  // namespace berberis
 
 #endif  // BERBERIS_INTRINSICS_COMMON_INTRINSICS_BINDINGS_H_
diff --git a/intrinsics/include/berberis/intrinsics/common/intrinsics_float.h b/intrinsics/include/berberis/intrinsics/common/intrinsics_float.h
index db56e6d2..2bab6cff 100644
--- a/intrinsics/include/berberis/intrinsics/common/intrinsics_float.h
+++ b/intrinsics/include/berberis/intrinsics/common/intrinsics_float.h
@@ -106,7 +106,7 @@ class WrappedFloatType {
   friend inline WrappedFloatType Absolute(const WrappedFloatType& v);
   friend inline WrappedFloatType Negative(const WrappedFloatType& v);
   friend inline FPInfo FPClassify(const WrappedFloatType& v);
-  friend inline WrappedFloatType FPRound(const WrappedFloatType& value, uint32_t round_control);
+  friend inline WrappedFloatType FPRound(const WrappedFloatType& value, int round_control);
   friend inline int IsNan(const WrappedFloatType& v);
   friend inline int SignBit(const WrappedFloatType& v);
   friend inline WrappedFloatType Sqrt(const WrappedFloatType& v);
diff --git a/intrinsics/include/berberis/intrinsics/guest_rounding_modes.h b/intrinsics/include/berberis/intrinsics/guest_rounding_modes.h
index 23cce1be..2ec077ce 100644
--- a/intrinsics/include/berberis/intrinsics/guest_rounding_modes.h
+++ b/intrinsics/include/berberis/intrinsics/guest_rounding_modes.h
@@ -28,8 +28,8 @@ namespace berberis {
 
 // Special rounding mode value to tell intrinsics
 // and interpreter to use rounding mode stored on host.
-const uint32_t FE_HOSTROUND = static_cast<uint32_t>(-1);
-const uint32_t FE_TIESAWAY = static_cast<uint32_t>(-2);
+const int FE_HOSTROUND = -1;
+const int FE_TIESAWAY = -2;
 static_assert(FE_HOSTROUND != FE_TONEAREST);
 static_assert(FE_HOSTROUND != FE_UPWARD);
 static_assert(FE_HOSTROUND != FE_DOWNWARD);
diff --git a/intrinsics/include/berberis/intrinsics/simd_register.h b/intrinsics/include/berberis/intrinsics/simd_register.h
index 419fd0c5..712a79d8 100644
--- a/intrinsics/include/berberis/intrinsics/simd_register.h
+++ b/intrinsics/include/berberis/intrinsics/simd_register.h
@@ -37,15 +37,8 @@ template <typename T>
 template <typename T>
 constexpr T SIMD128RegisterSet(SIMD128Register* reg, T elem, int index) = delete;
 
-[[nodiscard]] constexpr bool operator==(SIMD128Register lhs, SIMD128Register rhs);
-[[nodiscard]] constexpr bool operator!=(SIMD128Register lhs, SIMD128Register rhs);
-[[nodiscard]] constexpr SIMD128Register operator&(SIMD128Register lhs, SIMD128Register rhs);
-[[nodiscard]] constexpr SIMD128Register operator|(SIMD128Register lhs, SIMD128Register rhs);
-[[nodiscard]] constexpr SIMD128Register operator^(SIMD128Register lhs, SIMD128Register rhs);
-[[nodiscard]] constexpr SIMD128Register operator~(SIMD128Register lhs);
-
 #if defined(__GNUC__)
-using Int8x16 = char __attribute__((__vector_size__(16), may_alias));
+using Int8x16 = signed char __attribute__((__vector_size__(16), may_alias));
 using UInt8x16 = unsigned char __attribute__((__vector_size__(16), may_alias));
 using Int16x8 = short __attribute__((__vector_size__(16), may_alias));
 using UInt16x8 = unsigned short __attribute__((__vector_size__(16), may_alias));
@@ -56,6 +49,11 @@ using Float64x2 = double __attribute__((__vector_size__(16), may_alias));
 using Int64x2 = long long __attribute__((__vector_size__(16), __aligned__(16), may_alias));
 using Float32x4 = float __attribute__((__vector_size__(16), __aligned__(16), may_alias));
 
+// Forward declaration for operator==(SIMD128Register, SIMD128Register)
+class SIMD128Register;
+template <>
+constexpr Int64x2 SIMD128RegisterGet<Int64x2>(const SIMD128Register* reg, int index);
+
 using UInt8x16Tuple =
     std::tuple<uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t,
                uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t>;
@@ -139,7 +137,9 @@ class SIMD128Register {
   static bool compareVectors(T x, T y) {
     T res = x == y;
     bool result = true;
-    for (int i = 0; i < int{sizeof(SIMD128Register) / sizeof(T)}; ++i) {
+    // Note: std::size couldn't be used here because __vector_size__ based vector is different type
+    // from regular vector.
+    for (size_t i = 0; i < sizeof(res) / sizeof(res[0]); ++i) {
       result &= res[i];
     }
     return result;
@@ -218,15 +218,41 @@ class SIMD128Register {
     }
   }
 #if defined(__GNUC__)
-  friend constexpr bool operator==(SIMD128Register lhs, SIMD128Register rhs);
-  friend constexpr bool operator!=(SIMD128Register lhs, SIMD128Register rhs);
-  friend constexpr SIMD128Register operator&(SIMD128Register lhs, SIMD128Register rhs);
+  // Note: it's important for us to keep these as hidden friends, otherwise compiler can decide to
+  // use that comparison operator for types that would, otherwise, be incomparable.
+  // E.g. it may use this operator to compare UInt128 and Int128 (b/384343268).
+  [[nodiscard]] friend constexpr bool operator==(SIMD128Register lhs, SIMD128Register rhs) {
+    // Note comparison of two vectors return vector of the same type. In such a case we need to
+    // merge many bools that we got.
+    // On CPUs with _mm_movemask_epi8 (native, like on x86, or emulated, like on Power)
+    // _mm_movemask_epi8 return 0xffff if and only if all comparisons returned true.
+    return SIMD128Register::compareVectors(lhs.Get<Int64x2>(), rhs.Get<Int64x2>());
+  }
+  [[nodiscard]] friend constexpr bool operator!=(SIMD128Register lhs, SIMD128Register rhs) {
+    // Note comparison of two vectors return vector of the same type. In such a case we need to
+    // merge many bools that we got.
+    // On CPUs with _mm_movemask_epi8 (native, like on x86, or emulated, like on Power)
+    // _mm_movemask_epi8 return 0xffff if and only if all comparisons returned true.
+    return !SIMD128Register::compareVectors(lhs.Get<Int64x2>(), rhs.Get<Int64x2>());
+  }
+  [[nodiscard]] friend constexpr SIMD128Register operator&(SIMD128Register lhs,
+                                                           SIMD128Register rhs) {
+    return lhs.Get<Int64x2>() & rhs.Get<Int64x2>();
+  }
   constexpr SIMD128Register& operator&=(SIMD128Register other) { return *this = *this & other; }
-  friend constexpr SIMD128Register operator|(SIMD128Register lhs, SIMD128Register rhs);
+  [[nodiscard]] friend constexpr SIMD128Register operator|(SIMD128Register lhs,
+                                                           SIMD128Register rhs) {
+    return lhs.Get<Int64x2>() | rhs.Get<Int64x2>();
+  }
   constexpr SIMD128Register& operator|=(SIMD128Register other) { return *this = *this | other; }
-  friend constexpr SIMD128Register operator^(SIMD128Register lhs, SIMD128Register rhs);
+  [[nodiscard]] friend constexpr SIMD128Register operator^(SIMD128Register lhs,
+                                                           SIMD128Register rhs) {
+    return lhs.Get<Int64x2>() ^ rhs.Get<Int64x2>();
+  }
   constexpr SIMD128Register& operator^=(SIMD128Register other) { return *this = *this ^ other; }
-  friend constexpr SIMD128Register operator~(SIMD128Register lhs);
+  [[nodiscard]] friend constexpr SIMD128Register operator~(SIMD128Register lhs) {
+    return ~lhs.Get<Int64x2>();
+  }
 #endif
 
  private:
@@ -249,6 +275,7 @@ class SIMD128Register {
 #endif
     // Note: we couldn't use Float32/Float64 here because [[gnu::vector]] only works with
     // raw integer or FP-types.
+    [[gnu::vector_size(16), gnu::may_alias]] _Float16 float16;
     [[gnu::vector_size(16), gnu::may_alias]] float float32;
     [[gnu::vector_size(16), gnu::may_alias]] double float64;
 #else
@@ -388,6 +415,7 @@ SIMD_128_FULL_REGISTER_GETTER_SETTER(Float64x2, float64);
 SIMD_128_FULL_REGISTER_GETTER_SETTER(Int64x2, int64);
 SIMD_128_FULL_REGISTER_GETTER_SETTER(Float32x4, float32);
 #endif
+SIMD_128_FLOAT_REGISTER_GETTER_SETTER(intrinsics::Float16, _Float16, float16);
 SIMD_128_FLOAT_REGISTER_GETTER_SETTER(intrinsics::Float32, float, float32);
 SIMD_128_FLOAT_REGISTER_GETTER_SETTER(intrinsics::Float64, double, float64);
 #undef SIMD_128_FULL_REGISTER_GETTER_SETTER
@@ -396,32 +424,6 @@ SIMD_128_FLOAT_REGISTER_GETTER_SETTER(intrinsics::Float64, double, float64);
 #undef SIMD_128_STDINT_REGISTER_GETTER_SETTER
 
 #if defined(__GNUC__)
-[[nodiscard]] constexpr bool operator==(SIMD128Register lhs, SIMD128Register rhs) {
-  // Note comparison of two vectors return vector of the same type. In such a case we need to
-  // merge many bools that we got.
-  // On CPUs with _mm_movemask_epi8 (native, like on x86, or emulated, like on Power)
-  // _mm_movemask_epi8 return 0xffff if and only if all comparisons returned true.
-  return SIMD128Register::compareVectors(lhs.Get<Int64x2>(), rhs.Get<Int64x2>());
-}
-[[nodiscard]] constexpr bool operator!=(SIMD128Register lhs, SIMD128Register rhs) {
-  // Note comparison of two vectors return vector of the same type. In such a case we need to
-  // merge many bools that we got.
-  // On CPUs with _mm_movemask_epi8 (native, like on x86, or emulated, like on Power)
-  // _mm_movemask_epi8 return 0xffff if and only if all comparisons returned true.
-  return !SIMD128Register::compareVectors(lhs.Get<Int64x2>(), rhs.Get<Int64x2>());
-}
-[[nodiscard]] constexpr SIMD128Register operator&(SIMD128Register lhs, SIMD128Register rhs) {
-  return lhs.Get<Int64x2>() & rhs.Get<Int64x2>();
-}
-[[nodiscard]] constexpr SIMD128Register operator|(SIMD128Register lhs, SIMD128Register rhs) {
-  return lhs.Get<Int64x2>() | rhs.Get<Int64x2>();
-}
-[[nodiscard]] constexpr SIMD128Register operator^(SIMD128Register lhs, SIMD128Register rhs) {
-  return lhs.Get<Int64x2>() ^ rhs.Get<Int64x2>();
-}
-[[nodiscard]] constexpr SIMD128Register operator~(SIMD128Register lhs) {
-  return ~lhs.Get<Int64x2>();
-}
 #endif
 
 }  // namespace berberis
diff --git a/intrinsics/include/berberis/intrinsics/type_traits.h b/intrinsics/include/berberis/intrinsics/type_traits.h
index b7f229c0..7550c768 100644
--- a/intrinsics/include/berberis/intrinsics/type_traits.h
+++ b/intrinsics/include/berberis/intrinsics/type_traits.h
@@ -143,11 +143,21 @@ struct TypeTraits<intrinsics::Float64> {
   static constexpr char kName[] = "Float64";
 };
 
+template <>
+struct TypeTraits<_Float16> {
+  using Int = int16_t;
+  using Wrapped = intrinsics::Float16;
+  using Wide = float;
+  static constexpr int kBits = 16;
+  static constexpr char kName[] = "_Float16";
+};
+
 template <>
 struct TypeTraits<float> {
   using Int = int32_t;
   using Wrapped = intrinsics::Float32;
   using Wide = double;
+  using Narrow = _Float16;
   static constexpr int kBits = 32;
   static constexpr char kName[] = "float";
 };
diff --git a/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
index 9bdb9052..38617959 100644
--- a/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
+++ b/intrinsics/riscv64_to_all/include/berberis/intrinsics/riscv64_to_all/vector_intrinsics.h
@@ -667,7 +667,7 @@ inline std::tuple<SIMD128Register> Vcpopm(SIMD128Register simd_src) {
 template <enum PreferredIntrinsicsImplementation = kUseAssemblerImplementationIfPossible>
 inline std::tuple<SIMD128Register> Vfirstm(SIMD128Register simd_src) {
   UInt128 src = simd_src.Get<UInt128>();
-  if (src == Int128{0}) {
+  if (src == UInt128{0}) {
     return ~UInt128{0};
   }
   return CountRZero(src);
diff --git a/intrinsics/riscv64_to_x86_64/macro_assembler.cc b/intrinsics/riscv64_to_x86_64/constants_pool.cc
similarity index 70%
rename from intrinsics/riscv64_to_x86_64/macro_assembler.cc
rename to intrinsics/riscv64_to_x86_64/constants_pool.cc
index d2c3338b..d24a3e19 100644
--- a/intrinsics/riscv64_to_x86_64/macro_assembler.cc
+++ b/intrinsics/riscv64_to_x86_64/constants_pool.cc
@@ -14,6 +14,8 @@
  * limitations under the License.
  */
 
+#include "berberis/intrinsics/constants_pool.h"
+
 #include <inttypes.h>
 #include <sys/mman.h>
 
@@ -22,8 +24,6 @@
 #include "berberis/base/struct_check.h"
 #include "berberis/intrinsics/simd_register.h"
 
-#include "berberis/intrinsics/macro_assembler.h"
-
 namespace berberis::constants_pool {
 
 // All constants we refer in macroinstructions are collected in MacroAssemblerConstants.
@@ -97,19 +97,15 @@ struct MacroAssemblerConstants {
   alignas(16) const int8_t kPMovmskqToPMovmskb[16] =
       {0, 8, -128, -128, -128, -128, -128, -128, -57, -24, -31, -6, -7, -128, -128, -128};
   alignas(16) const uint8_t kRiscVToX87Exceptions[32] = {
-      0x00, 0x20, 0x10, 0x30, 0x08, 0x28, 0x18, 0x38,
-      0x04, 0x24, 0x14, 0x34, 0x0c, 0x2c, 0x1c, 0x3c,
-      0x01, 0x21, 0x11, 0x31, 0x09, 0x29, 0x19, 0x39,
-      0x05, 0x25, 0x15, 0x35, 0x0d, 0x2d, 0x1d, 0x3d};
+      0x00, 0x20, 0x10, 0x30, 0x08, 0x28, 0x18, 0x38, 0x04, 0x24, 0x14,
+      0x34, 0x0c, 0x2c, 0x1c, 0x3c, 0x01, 0x21, 0x11, 0x31, 0x09, 0x29,
+      0x19, 0x39, 0x05, 0x25, 0x15, 0x35, 0x0d, 0x2d, 0x1d, 0x3d};
   alignas(16) const uint8_t kX87ToRiscVExceptions[64] = {
-      0x00, 0x10, 0x00, 0x10, 0x08, 0x18, 0x08, 0x18,
-      0x04, 0x14, 0x04, 0x14, 0x0c, 0x1c, 0x0c, 0x1c,
-      0x02, 0x12, 0x02, 0x12, 0x0a, 0x1a, 0x0a, 0x1a,
-      0x06, 0x16, 0x06, 0x16, 0x0e, 0x1e, 0x0e, 0x1e,
-      0x01, 0x11, 0x01, 0x11, 0x09, 0x19, 0x09, 0x19,
-      0x05, 0x15, 0x05, 0x15, 0x0d, 0x1d, 0x0d, 0x1d,
-      0x03, 0x13, 0x03, 0x13, 0x0b, 0x1b, 0x0b, 0x1b,
-      0x07, 0x17, 0x07, 0x17, 0x0f, 0x1f, 0x0f, 0x1f};
+      0x00, 0x10, 0x00, 0x10, 0x08, 0x18, 0x08, 0x18, 0x04, 0x14, 0x04, 0x14, 0x0c,
+      0x1c, 0x0c, 0x1c, 0x02, 0x12, 0x02, 0x12, 0x0a, 0x1a, 0x0a, 0x1a, 0x06, 0x16,
+      0x06, 0x16, 0x0e, 0x1e, 0x0e, 0x1e, 0x01, 0x11, 0x01, 0x11, 0x09, 0x19, 0x09,
+      0x19, 0x05, 0x15, 0x05, 0x15, 0x0d, 0x1d, 0x0d, 0x1d, 0x03, 0x13, 0x03, 0x13,
+      0x0b, 0x1b, 0x0b, 0x1b, 0x07, 0x17, 0x07, 0x17, 0x0f, 0x1f, 0x0f, 0x1f};
   // This table represents exactly what you see: 𝟏𝟐𝟖 + 𝐍 unset bits and then 𝟏𝟐𝟖 - 𝐍 set bits for 𝐍
   // in range from 𝟎 to 𝟕.  The last 𝟏𝟐𝟖 bits from line 𝐍 then it's mask for 𝐯𝐥 equal to 𝐍 and if
   // you shift start address down by 𝐌  bytes then you get mask for 𝟖 * 𝐌 + 𝐍 bits.
@@ -269,38 +265,89 @@ struct MacroAssemblerConstants {
 // Make sure Layout is the same in 32-bit mode and 64-bit mode.
 CHECK_STRUCT_LAYOUT(MacroAssemblerConstants, 27520, 128);
 CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kNanBoxFloat32, 0, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kNanBoxedNansFloat32, 128, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kCanonicalNansFloat32, 256, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kCanonicalNansFloat64, 384, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kFloat32One, 512, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kFloat64One, 640, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kFloat32PInf, 768, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kFloat32NInf, 896, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kFloat64PInf, 1024, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kFloat64NInf, 1152, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kMinInt8, 1280, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kMaxInt8, 1408, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kMinInt16, 1536, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kMaxInt16, 1664, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kMinInt32, 1792, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kMaxInt32, 1920, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kMinInt64, 2048, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kMaxInt64, 2176, 128);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kBsrToClzInt64, 2304, 64);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kWidthInBits64, 2368, 64);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kBsrToClzInt32, 2432, 32);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kWidthInBits32, 2464, 32);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, k0x8000_0000_0000_00ff, 2496, 64);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kRiscVToX87Exceptions, 2944, 256);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kX87ToRiscVExceptions, 3200, 512);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kBitMaskTable, 3712, 2048);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kVid64Bit, 5760, 1024);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kVid32Bit, 6784, 1024);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kVid16Bit, 7808, 1024);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kVid8Bit, 8832, 1024);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kBitMaskTo32bitMask, 9856, 256);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kBitMaskTo16bitMask, 10112, 1024);
-CHECK_FIELD_LAYOUT(MacroAssemblerConstants, kBitMaskTo8bitMask, 11136, 16384);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kNanBoxedNansFloat32,
+                            kNanBoxFloat32,
+                            128,
+                            128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kCanonicalNansFloat32,
+                            kNanBoxedNansFloat32,
+                            128,
+                            128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kCanonicalNansFloat64,
+                            kCanonicalNansFloat32,
+                            128,
+                            128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kFloat32One, kCanonicalNansFloat64, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kFloat64One, kFloat32One, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kFloat32PInf, kFloat64One, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kFloat32NInf, kFloat32PInf, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kFloat64PInf, kFloat32NInf, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kFloat64NInf, kFloat64PInf, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kMinInt8, kFloat64NInf, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kMaxInt8, kMinInt8, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kMinInt16, kMaxInt8, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kMaxInt16, kMinInt16, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kMinInt32, kMaxInt16, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kMaxInt32, kMinInt32, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kMinInt64, kMaxInt32, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kMaxInt64, kMinInt64, 128, 128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kBsrToClzInt64, kMaxInt64, 128, 64);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kWidthInBits64, kBsrToClzInt64, 64, 64);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kBsrToClzInt32, kWidthInBits64, 64, 32);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kWidthInBits32, kBsrToClzInt32, 32, 32);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            k0x8000_0000_0000_00ff,
+                            kWidthInBits32,
+                            32,
+                            64);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kPMovmskwToPMovmskb,
+                            k0x8000_0000_0000_00ff,
+                            64,
+                            128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kPMovmskdToPMovmskb,
+                            kPMovmskwToPMovmskb,
+                            128,
+                            128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kPMovmskqToPMovmskb,
+                            kPMovmskdToPMovmskb,
+                            128,
+                            128);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kRiscVToX87Exceptions,
+                            kPMovmskqToPMovmskb,
+                            128,
+                            256);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kX87ToRiscVExceptions,
+                            kRiscVToX87Exceptions,
+                            256,
+                            512);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kBitMaskTable,
+                            kX87ToRiscVExceptions,
+                            512,
+                            2048);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kVid64Bit, kBitMaskTable, 2048, 1024);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kVid32Bit, kVid64Bit, 1024, 1024);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kVid16Bit, kVid32Bit, 1024, 1024);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kVid8Bit, kVid16Bit, 1024, 1024);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants, kBitMaskTo32bitMask, kVid8Bit, 1024, 256);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kBitMaskTo16bitMask,
+                            kBitMaskTo32bitMask,
+                            256,
+                            1024);
+CHECK_FIELD_LAYOUT_RELATIVE(MacroAssemblerConstants,
+                            kBitMaskTo8bitMask,
+                            kBitMaskTo16bitMask,
+                            1024,
+                            16384);
 
 // Note: because we have aligned fields and thus padding in that data structure
 // value-initialization is both slower and larger than copy-initialization for
@@ -332,81 +379,48 @@ int32_t GetConstants() {
 
 extern const int32_t kBerberisMacroAssemblerConstantsRelocated;
 const int32_t kBerberisMacroAssemblerConstantsRelocated = GetConstants();
-template <>
-extern const int32_t kVectorConst<int8_t{-128}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kMinInt8);
-template <>
-extern const int32_t kVectorConst<int8_t{127}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kMaxInt8);
-template <>
-extern const int32_t kVectorConst<int16_t{-0x8000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kMinInt16);
-template <>
-extern const int32_t kVectorConst<int16_t{0x7fff}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kMaxInt16);
-template <>
-extern const int32_t kVectorConst<int32_t{static_cast<int32_t>(-0x8000'0000)}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kMinInt32);
-template <>
-extern const int32_t kVectorConst<int32_t{0x3f80'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kFloat32One);
-template <>
-extern const int32_t kVectorConst<int32_t{0x7f80'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kFloat32PInf);
-template <>
-extern const int32_t kVectorConst<int32_t{0x7fff'ffff}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kMaxInt32);
-template <>
-extern const int32_t kVectorConst<int32_t{-0x0080'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kFloat32NInf);
-template <>
-extern const int32_t kVectorConst<int64_t{static_cast<int64_t>(-0x8000'0000'0000'0000)}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kMinInt64);
-template <>
-extern const int32_t kVectorConst<int64_t{0x3ff0'0000'0000'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kFloat64One);
-template <>
-extern const int32_t kVectorConst<int64_t{0x7ff0'0000'0000'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kFloat64PInf);
-template <>
-extern const int32_t kVectorConst<int64_t{0x7fff'ffff'ffff'ffff}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kMaxInt64);
-template <>
-extern const int32_t kVectorConst<int64_t{-0x0010'0000'0000'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kFloat64NInf);
-template <>
-const int32_t kVectorConst<uint64_t{0x0000'0000'0000'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kBitMaskTable);
-template <>
-const int32_t kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kBitMaskTable) + 16;
-template <>
-const int32_t kVectorConst<uint64_t{0xffff'ffff'0000'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kNanBoxFloat32);
-template <>
-const int32_t kVectorConst<uint64_t{0xffff'ffff'7fc0'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kNanBoxedNansFloat32);
-template <>
-const int32_t kVectorConst<uint64_t{0x7fc0'0000'7fc0'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kCanonicalNansFloat32);
-template <>
-const int32_t kVectorConst<uint64_t{0x7ff8'0000'0000'0000}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kCanonicalNansFloat64);
-template <>
-const int32_t kConst<uint64_t{127}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kBsrToClzInt64);
-template <>
-const int32_t kConst<uint64_t{64}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kWidthInBits64);
-template <>
-const int32_t kConst<uint32_t{63}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kBsrToClzInt32);
-template <>
-const int32_t kConst<uint32_t{32}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, kWidthInBits32);
-template <>
-const int32_t kConst<uint64_t{0x8000'0000'0000'00ff}> =
-    GetConstants() + offsetof(MacroAssemblerConstants, k0x8000_0000_0000_00ff);
+
+#pragma push_macro("VECTOR_CONST_EXTERN")
+#define VECTOR_CONST_EXTERN(Value, Name, Offset) \
+  const int32_t VectorConst<Value>::kValue =     \
+      GetConstants() + offsetof(MacroAssemblerConstants, Name) + Offset;
+
+VECTOR_CONST_EXTERN(int8_t{-128}, kMinInt8, 0);
+VECTOR_CONST_EXTERN(int8_t{127}, kMaxInt8, 0);
+VECTOR_CONST_EXTERN(int16_t{-0x8000}, kMinInt16, 0);
+VECTOR_CONST_EXTERN(int16_t{0x7fff}, kMaxInt16, 0);
+VECTOR_CONST_EXTERN(int32_t{static_cast<int32_t>(-0x8000'0000)}, kMinInt32, 0);
+VECTOR_CONST_EXTERN(int32_t{0x3f80'0000}, kFloat32One, 0);
+VECTOR_CONST_EXTERN(int32_t{0x7f80'0000}, kFloat32PInf, 0);
+VECTOR_CONST_EXTERN(int32_t{0x7fff'ffff}, kMaxInt32, 0);
+VECTOR_CONST_EXTERN(int32_t{-0x0080'0000}, kFloat32NInf, 0);
+VECTOR_CONST_EXTERN(int64_t{static_cast<int64_t>(-0x8000'0000'0000'0000)}, kMinInt64, 0);
+VECTOR_CONST_EXTERN(int64_t{0x3ff0'0000'0000'0000}, kFloat64One, 0);
+VECTOR_CONST_EXTERN(int64_t{0x7ff0'0000'0000'0000}, kFloat64PInf, 0);
+VECTOR_CONST_EXTERN(int64_t{0x7fff'ffff'ffff'ffff}, kMaxInt64, 0);
+VECTOR_CONST_EXTERN(int64_t{-0x0010'0000'0000'0000}, kFloat64NInf, 0);
+VECTOR_CONST_EXTERN(uint64_t{0x0000'0000'0000'0000}, kBitMaskTable, 0);
+VECTOR_CONST_EXTERN(uint64_t{0xffff'ffff'ffff'ffff}, kBitMaskTable, 16);
+VECTOR_CONST_EXTERN(uint64_t{0xffff'ffff'0000'0000}, kNanBoxFloat32, 0);
+VECTOR_CONST_EXTERN(uint64_t{0xffff'ffff'7fc0'0000}, kNanBoxedNansFloat32, 0);
+VECTOR_CONST_EXTERN(uint64_t{0x7fc0'0000'7fc0'0000}, kCanonicalNansFloat32, 0);
+VECTOR_CONST_EXTERN(uint64_t{0x7ff8'0000'0000'0000}, kCanonicalNansFloat64, 0);
+
+#pragma pop_macro("VECTOR_CONST_EXTERN")
+
+#pragma push_macro("CONST_EXTERN")
+#define CONST_EXTERN(Value, Name, Offset) \
+  const int32_t Const<Value>::kValue =    \
+      GetConstants() + offsetof(MacroAssemblerConstants, Name) + Offset;
+
+CONST_EXTERN(uint64_t{127}, kBsrToClzInt64, 0);
+CONST_EXTERN(uint64_t{64}, kWidthInBits64, 0);
+CONST_EXTERN(uint32_t{63}, kBsrToClzInt32, 0);
+CONST_EXTERN(uint32_t{32}, kWidthInBits32, 0);
+CONST_EXTERN(uint64_t{0x8000'0000'0000'00ff}, k0x8000_0000_0000_00ff, 0);
+
+#pragma pop_macro("CONST_EXTERN")
+
 const int32_t kRiscVToX87Exceptions =
     GetConstants() + offsetof(MacroAssemblerConstants, kRiscVToX87Exceptions);
 const int32_t kX87ToRiscVExceptions =
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/constants_pool.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/constants_pool.h
new file mode 100644
index 00000000..7351ce1c
--- /dev/null
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/constants_pool.h
@@ -0,0 +1,240 @@
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
+#ifndef RISCV64_TO_X86_64_BERBERIS_INTRINSICS_CONSTANTS_POOL_H_
+#define RISCV64_TO_X86_64_BERBERIS_INTRINSICS_CONSTANTS_POOL_H_
+
+#include <cinttypes>
+
+#include "berberis/base/dependent_false.h"
+#include "berberis/intrinsics/common/constants_pool.h"
+#include "berberis/intrinsics/common/intrinsics_float.h"
+
+namespace berberis::constants_pool {
+
+// Specialize VectorConst<Value> using an out-of-line definition.
+#pragma push_macro("VECTOR_CONST_EXTERN")
+#define VECTOR_CONST_EXTERN(Value) \
+  template <>                      \
+  struct VectorConst<Value> {      \
+    static const int32_t kValue;   \
+  }
+
+// Specialize VectorConst<Value> using a reference to another constant's int32_t address.
+#pragma push_macro("VECTOR_CONST_ALIAS")
+#define VECTOR_CONST_ALIAS(Value, Alias)            \
+  template <>                                       \
+  struct VectorConst<Value> {                       \
+    static constexpr const int32_t& kValue = Alias; \
+  }
+
+VECTOR_CONST_EXTERN(int8_t{-128});
+VECTOR_CONST_EXTERN(int8_t{127});
+VECTOR_CONST_EXTERN(int16_t{-0x8000});
+VECTOR_CONST_EXTERN(int16_t{0x7fff});
+VECTOR_CONST_EXTERN(int32_t{static_cast<int32_t>(-0x8000'0000)});
+VECTOR_CONST_EXTERN(int32_t{-0x0080'0000});
+VECTOR_CONST_EXTERN(int32_t{0x3f80'0000});
+VECTOR_CONST_EXTERN(int32_t{0x7f80'0000});
+VECTOR_CONST_EXTERN(int32_t{0x7fff'ffff});
+VECTOR_CONST_EXTERN(int64_t{static_cast<int64_t>(-0x8000'0000'0000'0000)});
+VECTOR_CONST_EXTERN(int64_t{0x3ff0'0000'0000'0000});
+VECTOR_CONST_EXTERN(int64_t{0x7ff0'0000'0000'0000});
+VECTOR_CONST_EXTERN(int64_t{0x7fff'ffff'ffff'ffff});
+VECTOR_CONST_EXTERN(int64_t{-0x0010'0000'0000'0000});
+VECTOR_CONST_EXTERN(uint64_t{0x0000'0000'0000'0000});
+
+VECTOR_CONST_ALIAS(int8_t{0x00}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+VECTOR_CONST_ALIAS(uint8_t{0x00}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+VECTOR_CONST_ALIAS(int16_t{0x0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+VECTOR_CONST_ALIAS(uint16_t{0x0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+VECTOR_CONST_ALIAS(uint8_t{127}, kVectorConst<int8_t{127}>);
+VECTOR_CONST_ALIAS(uint8_t{128}, kVectorConst<int8_t{-128}>);
+VECTOR_CONST_ALIAS(uint16_t{0x7fff}, kVectorConst<int16_t{0x7fff}>);
+VECTOR_CONST_ALIAS(uint16_t{0x8000}, kVectorConst<int16_t{-0x8000}>);
+VECTOR_CONST_ALIAS(int32_t{0x0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+VECTOR_CONST_ALIAS(uint32_t{0x0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+VECTOR_CONST_ALIAS(uint32_t{0x3f80'0000}, kVectorConst<int32_t{0x3f80'0000}>);
+VECTOR_CONST_ALIAS(uint32_t{0x7f80'0000}, kVectorConst<int32_t{0x7f80'0000}>);
+VECTOR_CONST_ALIAS(uint32_t{0x7fff'ffff}, kVectorConst<int32_t{0x7fff'ffff}>);
+VECTOR_CONST_ALIAS(uint32_t{0x8000'0000},
+                   kVectorConst<int32_t{static_cast<int32_t>(-0x8000'0000)}>);
+VECTOR_CONST_ALIAS(uint32_t{0xff80'0000}, kVectorConst<int32_t{-0x0080'0000}>);
+VECTOR_CONST_ALIAS(int64_t{0x0000'0000'0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+
+VECTOR_CONST_EXTERN(uint64_t{0x7fc'00000'7fc'00000});
+
+VECTOR_CONST_ALIAS(uint64_t{0x7ff0'0000'0000'0000}, kVectorConst<int64_t{0x7ff0'0000'0000'0000}>);
+
+VECTOR_CONST_EXTERN(uint64_t{0x7ff8'0000'0000'0000});
+
+VECTOR_CONST_ALIAS(uint64_t{0xfff0'0000'0000'0000}, kVectorConst<int64_t{-0x0010'0000'0000'0000}>);
+
+VECTOR_CONST_EXTERN(uint64_t{0xffff'ffff'0000'0000});
+VECTOR_CONST_EXTERN(uint64_t{0xffff'ffff'7fc0'0000});
+VECTOR_CONST_EXTERN(uint64_t{0xffff'ffff'ffff'ffff});
+
+VECTOR_CONST_ALIAS(int8_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+VECTOR_CONST_ALIAS(uint8_t{0xff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+VECTOR_CONST_ALIAS(int16_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+VECTOR_CONST_ALIAS(uint16_t{0xffff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+VECTOR_CONST_ALIAS(int32_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+VECTOR_CONST_ALIAS(uint32_t{0xffff'ffff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+VECTOR_CONST_ALIAS(int64_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+
+#pragma pop_macro("VECTOR_CONST_EXTERN")
+#pragma pop_macro("VECTOR_CONST_ALIAS")
+
+// 64 bit constants for use with arithmetic operations.
+// Used because only 32 bit immediates are supported on x86-64.
+
+template <auto Value>
+struct Const {};
+
+// Specialize Const<Value> using an out-of-line definition.
+#pragma push_macro("CONST_EXTERN")
+#define CONST_EXTERN(Value)      \
+  template <>                    \
+  struct Const<Value> {          \
+    static const int32_t kValue; \
+  }
+
+// Specialize Const<Value> using a reference to another constant's int32_t address.
+#pragma push_macro("CONST_ALIAS")
+#define CONST_ALIAS(Value, Alias)                   \
+  template <>                                       \
+  struct Const<Value> {                             \
+    static constexpr const int32_t& kValue = Alias; \
+  }
+
+template <auto Value>
+inline const int32_t& kConst = Const<Value>::kValue;
+
+CONST_EXTERN(uint32_t{32});
+CONST_EXTERN(uint32_t{63});
+CONST_EXTERN(uint64_t{64});
+CONST_EXTERN(uint64_t{127});
+
+CONST_ALIAS(int8_t{0x00}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+CONST_ALIAS(uint8_t{0x00}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+CONST_ALIAS(int16_t{0x0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+CONST_ALIAS(uint16_t{0x0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+CONST_ALIAS(int32_t{0x0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+CONST_ALIAS(uint32_t{0x0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+CONST_ALIAS(int64_t{0x0000'0000'0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+CONST_ALIAS(uint64_t{0x0000'0000'0000'0000}, kVectorConst<uint64_t{0x0000'0000'0000'0000}>);
+
+CONST_EXTERN(uint64_t{0x8000'0000'0000'00ff});
+
+CONST_ALIAS(int8_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+CONST_ALIAS(uint8_t{0xff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+CONST_ALIAS(int16_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+CONST_ALIAS(uint16_t{0xffff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+CONST_ALIAS(int32_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+CONST_ALIAS(uint32_t{0xffff'ffff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+CONST_ALIAS(int64_t{-1}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+CONST_ALIAS(uint64_t{0xffff'ffff'ffff'ffff}, kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>);
+
+#pragma pop_macro("CONST_EXTERN")
+#pragma pop_macro("CONST_ALIAS")
+
+// Constant suitable for NaN boxing of RISC-V 32bit float with PXor.
+// Note: technically we only need to Nan-box Float32 since we don't support Float16 yet.
+template <typename FloatType>
+inline constexpr int32_t kNanBox = kImpossibleTypeConst<FloatType>;
+template <>
+inline const int32_t& kNanBox<intrinsics::Float32> = kVectorConst<uint64_t{0xffff'ffff'0000'0000}>;
+
+// Canonically Nan boxed canonical NaN.
+// Note: technically we only need to Nan-box Float32 since we don't support Float16 yet.
+template <typename FloatType>
+inline constexpr int32_t kNanBoxedNans = kImpossibleTypeConst<FloatType>;
+template <>
+inline const int32_t& kNanBoxedNans<intrinsics::Float32> =
+    kVectorConst<uint64_t{0xffff'ffff'7fc0'0000}>;
+
+// Canonical NaNs. Float32 and Float64 are supported.
+template <typename FloatType>
+inline constexpr int32_t kCanonicalNans = kImpossibleTypeConst<FloatType>;
+template <>
+inline const int32_t& kCanonicalNans<intrinsics::Float32> =
+    kVectorConst<uint64_t{0x7fc0'0000'7fc0'0000}>;
+template <>
+inline const int32_t& kCanonicalNans<intrinsics::Float64> =
+    kVectorConst<uint64_t{0x7ff8'0000'0000'0000}>;
+
+// Helper constant for BsrToClz conversion. 63 for int32_t, 127 for int64_t.
+template <typename IntType>
+inline constexpr int32_t kBsrToClz = kImpossibleTypeConst<IntType>;
+template <>
+inline const int32_t kBsrToClz<int32_t> = kConst<uint32_t{63}>;
+template <>
+inline const int32_t kBsrToClz<int64_t> = kConst<uint64_t{127}>;
+
+// Helper constant for width of the type. 32 for int32_t, 64 for int64_t.
+template <typename IntType>
+inline constexpr int32_t kWidthInBits = kImpossibleTypeConst<IntType>;
+template <>
+inline const int32_t kWidthInBits<int32_t> = kConst<uint32_t{32}>;
+template <>
+inline const int32_t kWidthInBits<int64_t> = kConst<uint64_t{64}>;
+
+extern const int32_t kRiscVToX87Exceptions;
+extern const int32_t kX87ToRiscVExceptions;
+
+extern const int32_t kVid64Bit;
+extern const int32_t kVid32Bit;
+extern const int32_t kVid16Bit;
+extern const int32_t kVid8Bit;
+
+extern const int32_t kBitMaskTable;
+extern const int32_t kBitMaskTo32bitMask;
+extern const int32_t kBitMaskTo16bitMask;
+extern const int32_t kBitMaskTo8bitMask;
+
+extern const int32_t kPMovmskwToPMovmskb;
+extern const int32_t kPMovmskdToPMovmskb;
+extern const int32_t kPMovmskqToPMovmskb;
+
+}  // namespace berberis::constants_pool
+
+namespace berberis::constants_offsets {
+
+inline constexpr ConstantAccessor<&constants_pool::kRiscVToX87Exceptions> kRiscVToX87Exceptions;
+
+inline constexpr ConstantAccessor<&constants_pool::kX87ToRiscVExceptions> kX87ToRiscVExceptions;
+
+template <typename IntType>
+inline constexpr TypeConstantAccessor<&constants_pool::kBsrToClz<IntType>> kBsrToClz{};
+
+template <typename FloatType>
+inline constexpr TypeConstantAccessor<&constants_pool::kCanonicalNans<FloatType>> kCanonicalNans{};
+
+template <typename FloatType>
+inline constexpr TypeConstantAccessor<&constants_pool::kNanBox<FloatType>> kNanBox{};
+
+template <typename FloatType>
+inline constexpr TypeConstantAccessor<&constants_pool::kNanBoxedNans<FloatType>> kNanBoxedNans{};
+
+template <typename IntType>
+inline constexpr TypeConstantAccessor<&constants_pool::kWidthInBits<IntType>> kWidthInBits{};
+
+template <auto Value>
+inline constexpr VectorConstantAccessor<Value> kVectorConst{};
+
+}  // namespace berberis::constants_offsets
+
+#endif  // RISCV64_TO_X86_64_BERBERIS_INTRINSICS_CONSTANTS_POOL_H_
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
index 87a3b3ea..87843dc3 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler.h
@@ -28,7 +28,7 @@
 // Float32/Float64 types but can be compiled for different architecture (soong's host architecture,
 // not device architecture AKA berberis' host architecture).
 #include "berberis/intrinsics/common/intrinsics_float.h"
-#include "berberis/intrinsics/macro_assembler_constants_pool.h"
+#include "berberis/intrinsics/constants_pool.h"
 
 namespace berberis {
 
@@ -40,64 +40,26 @@ class MacroAssembler : public Assembler {
                                      typename Assembler::FinalAssembler>;
 
   template <typename... Args>
-  explicit MacroAssembler(Args&&... args) : Assembler(std::forward<Args>(args)...) {
-  }
+  constexpr explicit MacroAssembler(Args&&... args) : Assembler(std::forward<Args>(args)...) {}
+
+#define IMPORT_ASSEMBLER_FUNCTIONS
+#include "berberis/assembler/gen_assembler_x86_64-using-inl.h"
+#undef IMPORT_ASSEMBLER_FUNCTIONS
 
 #define DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
 #include "berberis/intrinsics/all_to_x86_32_or_x86_64/macro_assembler-inl.h"
+#undef DEFINE_MACRO_ASSEMBLER_GENERIC_FUNCTIONS
 
-  void PNot(XMMRegister result) {
-    Pandn(result, {.disp = constants_pool::kVectorConst<uint8_t{0b1111'1111}>});
+  constexpr void PNot(XMMRegister result) {
+    Pandn(result, {.disp = constants_offsets::kVectorConst<uint8_t{0b1111'1111}>});
   }
 
-  void Vpnot(XMMRegister result, XMMRegister src) {
-    Vpandn(result, src, {.disp = constants_pool::kVectorConst<uint8_t{0b1111'1111}>});
+  constexpr void Vpnot(XMMRegister result, XMMRegister src) {
+    Vpandn(result, src, {.disp = constants_offsets::kVectorConst<uint8_t{0b1111'1111}>});
   }
 
 #include "berberis/intrinsics/macro_assembler_interface-inl.h"  // NOLINT generated file
 
-  using Assembler::Bind;
-  using Assembler::Btq;
-  using Assembler::Cbw;
-  using Assembler::Cdq;
-  using Assembler::Cqo;
-  using Assembler::Cwd;
-  using Assembler::Fldcw;
-  using Assembler::Fldenv;
-  using Assembler::Fnstcw;
-  using Assembler::Fnstenv;
-  using Assembler::Fnstsw;
-  using Assembler::Jcc;
-  using Assembler::Jmp;
-  using Assembler::Ldmxcsr;
-  using Assembler::Leal;
-  using Assembler::Leaq;
-  using Assembler::MakeLabel;
-  using Assembler::Movl;
-  using Assembler::Pand;
-  using Assembler::Pandn;
-  using Assembler::Pcmpeqb;
-  using Assembler::Pmov;
-  using Assembler::Por;
-  using Assembler::Pshufd;
-  using Assembler::Setcc;
-  using Assembler::Stmxcsr;
-  using Assembler::Vpand;
-  using Assembler::Vpandn;
-  using Assembler::Vpcmpeqb;
-  using Assembler::Vpor;
-  using Assembler::Vpshufd;
-
-  using Assembler::Byte;
-  using Assembler::TwoByte;
-  using Assembler::FourByte;
-  using Assembler::EigthByte;
-  using Assembler::P2Align;
-
-  using Assembler::gpr_a;
-  using Assembler::gpr_c;
-  using Assembler::gpr_d;
-
  private:
 
   // Useful constants for PshufXXX instructions.
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h
index 66ce200e..03f84e11 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_arith_impl.h
@@ -29,7 +29,7 @@ namespace berberis {
 // gpr_d and FLAGS are clobbered by that macroinstruction.
 template <typename Assembler>
 template <typename IntType>
-void MacroAssembler<Assembler>::MacroDiv(Register src) {
+constexpr void MacroAssembler<Assembler>::MacroDiv(Register src) {
   Label* zero = MakeLabel();
   Label* done = MakeLabel();
   Test<IntType>(src, src);
@@ -44,7 +44,7 @@ void MacroAssembler<Assembler>::MacroDiv(Register src) {
 
     if constexpr (std::is_same_v<IntType, int64_t>) {
       Cmp<IntType>(gpr_a,
-                   {.disp = constants_pool::kVectorConst<std::numeric_limits<IntType>::min()>});
+                   {.disp = constants_offsets::kVectorConst<std::numeric_limits<IntType>::min()>});
     } else {
       Cmp<IntType>(gpr_a, std::numeric_limits<IntType>::min());
     }
@@ -88,7 +88,7 @@ void MacroAssembler<Assembler>::MacroDiv(Register src) {
 // For 8-bit: remainder is returned in gpr_a. FLAGS are clobbered.
 template <typename Assembler>
 template <typename IntType>
-void MacroAssembler<Assembler>::MacroRem(Register src) {
+constexpr void MacroAssembler<Assembler>::MacroRem(Register src) {
   Label* zero = MakeLabel();
   Label* overflow = MakeLabel();
   Label* done = MakeLabel();
@@ -104,7 +104,7 @@ void MacroAssembler<Assembler>::MacroRem(Register src) {
 
     if constexpr (std::is_same_v<IntType, int64_t>) {
       Cmp<IntType>(gpr_a,
-                   {.disp = constants_pool::kVectorConst<std::numeric_limits<IntType>::min()>});
+                   {.disp = constants_offsets::kVectorConst<std::numeric_limits<IntType>::min()>});
     } else {
       Cmp<IntType>(gpr_a, std::numeric_limits<IntType>::min());
     }
@@ -131,7 +131,7 @@ void MacroAssembler<Assembler>::MacroRem(Register src) {
   } else {
     // We need to zero-extend eax into dx/edx/rdx to ensure 32-bit/64-bit/128-bit dividend is
     // correct.
-    Xor<uint64_t>(gpr_d, gpr_d);
+    Xor<uint32_t>(gpr_d, gpr_d);
   }
 
   Div<IntType>(src);
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_bitmanip_impl.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_bitmanip_impl.h
index f2624932..9b89daaf 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_bitmanip_impl.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_bitmanip_impl.h
@@ -26,22 +26,22 @@ namespace berberis {
 
 template <typename Assembler>
 template <typename IntType>
-void MacroAssembler<Assembler>::MacroClz(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::MacroClz(Register result, Register src) {
   Bsr<IntType>(result, src);
-  Cmov<IntType>(Condition::kZero, result, {.disp = constants_pool::kBsrToClz<IntType>});
+  Cmov<IntType>(Condition::kZero, result, {.disp = constants_offsets::kBsrToClz<IntType>});
   Xor<IntType>(result, sizeof(IntType) * CHAR_BIT - 1);
 }
 
 template <typename Assembler>
 template <typename IntType>
-void MacroAssembler<Assembler>::MacroCtz(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::MacroCtz(Register result, Register src) {
   Bsf<IntType>(result, src);
-  Cmov<IntType>(Condition::kZero, result, {.disp = constants_pool::kWidthInBits<IntType>});
+  Cmov<IntType>(Condition::kZero, result, {.disp = constants_offsets::kWidthInBits<IntType>});
 }
 
 template <typename Assembler>
 template <typename IntType>
-void MacroAssembler<Assembler>::MacroMax(Register result, Register src1, Register src2) {
+constexpr void MacroAssembler<Assembler>::MacroMax(Register result, Register src1, Register src2) {
   Mov<IntType>(result, src1);
   Cmp<IntType>(src1, src2);
   if constexpr (std::is_signed_v<IntType>) {
@@ -53,7 +53,7 @@ void MacroAssembler<Assembler>::MacroMax(Register result, Register src1, Registe
 
 template <typename Assembler>
 template <typename IntType>
-void MacroAssembler<Assembler>::MacroMin(Register result, Register src1, Register src2) {
+constexpr void MacroAssembler<Assembler>::MacroMin(Register result, Register src1, Register src2) {
   Mov<IntType>(result, src1);
   Cmp<IntType>(src1, src2);
   if constexpr (std::is_signed_v<IntType>) {
@@ -64,58 +64,58 @@ void MacroAssembler<Assembler>::MacroMin(Register result, Register src1, Registe
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroOrcb(XMMRegister result) {
-  Pcmpeqb(result, {.disp = constants_pool::kVectorConst<uint8_t{0}>});
+constexpr void MacroAssembler<Assembler>::MacroOrcb(XMMRegister result) {
+  Pcmpeqb(result, {.disp = constants_offsets::kVectorConst<uint8_t{0}>});
   PNot(result);
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroOrcbAVX(XMMRegister result, XMMRegister src) {
-  Vpcmpeqb(result, src, {.disp = constants_pool::kVectorConst<uint8_t{0}>});
+constexpr void MacroAssembler<Assembler>::MacroOrcbAVX(XMMRegister result, XMMRegister src) {
+  Vpcmpeqb(result, src, {.disp = constants_offsets::kVectorConst<uint8_t{0}>});
   Vpnot(result, result);
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroAdduw(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::MacroAdduw(Register result, Register src) {
   Movl(result, result);
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesOne});
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroSh1adduw(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::MacroSh1adduw(Register result, Register src) {
   Movl(result, result);
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesTwo});
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroSh2adduw(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::MacroSh2adduw(Register result, Register src) {
   Movl(result, result);
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesFour});
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroSh3adduw(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::MacroSh3adduw(Register result, Register src) {
   Movl(result, result);
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesEight});
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroSh1add(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::MacroSh1add(Register result, Register src) {
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesTwo});
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroSh2add(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::MacroSh2add(Register result, Register src) {
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesFour});
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroSh3add(Register result, Register src) {
+constexpr void MacroAssembler<Assembler>::MacroSh3add(Register result, Register src) {
   Leaq(result, {.base = src, .index = result, .scale = Assembler::kTimesEight});
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroBext(Register result, Register src1, Register src2) {
+constexpr void MacroAssembler<Assembler>::MacroBext(Register result, Register src1, Register src2) {
   Btq(src1, src2);
   Movl(result, 0);
   Setcc(Condition::kCarry, result);
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_constants_pool.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_constants_pool.h
deleted file mode 100644
index 57fcb4f4..00000000
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_constants_pool.h
+++ /dev/null
@@ -1,244 +0,0 @@
-/*
- * Copyright (C) 2020 The Android Open Source Project
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
-#ifndef RISCV64_TO_X86_64_BERBERIS_INTRINSICS_MACRO_ASSEMBLER_CONSTANTS_POOL_H_
-#define RISCV64_TO_X86_64_BERBERIS_INTRINSICS_MACRO_ASSEMBLER_CONSTANTS_POOL_H_
-
-#include <cinttypes>
-
-#include "berberis/base/dependent_false.h"
-#include "berberis/intrinsics/common/intrinsics_float.h"
-
-namespace berberis::constants_pool {
-
-// Vector constants, that is: constants are repeated to fill 128bit SIMD register.
-template <auto Value>
-inline constexpr int32_t kVectorConst = kImpossibleValueConst<Value>;
-template <>
-extern const int32_t kVectorConst<int8_t{-128}>;
-template <>
-extern const int32_t kVectorConst<int8_t{127}>;
-template <>
-extern const int32_t kVectorConst<int16_t{-0x8000}>;
-template <>
-extern const int32_t kVectorConst<int16_t{0x7fff}>;
-template <>
-extern const int32_t kVectorConst<int32_t{static_cast<int32_t>(-0x8000'0000)}>;
-template <>
-extern const int32_t kVectorConst<int32_t{-0x0080'0000}>;
-template <>
-extern const int32_t kVectorConst<int32_t{0x3f80'0000}>;
-template <>
-extern const int32_t kVectorConst<int32_t{0x7f80'0000}>;
-template <>
-extern const int32_t kVectorConst<int32_t{0x7fff'ffff}>;
-template <>
-extern const int32_t kVectorConst<int64_t{static_cast<int64_t>(-0x8000'0000'0000'0000)}>;
-template <>
-extern const int32_t kVectorConst<int64_t{0x3ff0'0000'0000'0000}>;
-template <>
-extern const int32_t kVectorConst<int64_t{0x7ff0'0000'0000'0000}>;
-template <>
-extern const int32_t kVectorConst<int64_t{0x7fff'ffff'ffff'ffff}>;
-template <>
-extern const int32_t kVectorConst<int64_t{-0x0010'0000'0000'0000}>;
-template <>
-extern const int32_t kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kVectorConst<int8_t{0x00}> = kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kVectorConst<uint8_t{0x00}> = kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kVectorConst<int16_t{0x0000}> = kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kVectorConst<uint16_t{0x0000}> =
-    kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kVectorConst<uint8_t{127}> = kVectorConst<int8_t{127}>;
-template <>
-inline const int32_t& kVectorConst<uint8_t{128}> = kVectorConst<int8_t{-128}>;
-template <>
-inline const int32_t& kVectorConst<uint16_t{0x7fff}> = kVectorConst<int16_t{0x7fff}>;
-template <>
-inline const int32_t& kVectorConst<uint16_t{0x8000}> = kVectorConst<int16_t{-0x8000}>;
-template <>
-inline const int32_t& kVectorConst<int32_t{0x0000'0000}> =
-    kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kVectorConst<uint32_t{0x0000'0000}> =
-    kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kVectorConst<uint32_t{0x3f80'0000}> = kVectorConst<int32_t{0x3f80'0000}>;
-template <>
-inline const int32_t& kVectorConst<uint32_t{0x7f80'0000}> = kVectorConst<int32_t{0x7f80'0000}>;
-template <>
-inline const int32_t& kVectorConst<uint32_t{0x7fff'ffff}> = kVectorConst<int32_t{0x7fff'ffff}>;
-template <>
-inline const int32_t& kVectorConst<uint32_t{0x8000'0000}> =
-    kVectorConst<int32_t{static_cast<int32_t>(-0x8000'0000)}>;
-template <>
-inline const int32_t& kVectorConst<uint32_t{0xff80'0000}> = kVectorConst<int32_t{-0x0080'0000}>;
-template <>
-inline const int32_t& kVectorConst<int64_t{0x0000'0000'0000'0000}> =
-    kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-extern const int32_t kVectorConst<uint64_t{0x7fc'00000'7fc'00000}>;
-template <>
-inline const int32_t& kVectorConst<uint64_t{0x7ff0'0000'0000'0000}> =
-    kVectorConst<int64_t{0x7ff0'0000'0000'0000}>;
-template <>
-extern const int32_t kVectorConst<uint64_t{0x7ff8'0000'0000'0000}>;
-template <>
-inline const int32_t& kVectorConst<uint64_t{0xfff0'0000'0000'0000}> =
-    kVectorConst<int64_t{-0x0010'0000'0000'0000}>;
-template <>
-extern const int32_t kVectorConst<uint64_t{0xffff'ffff'0000'0000}>;
-template <>
-extern const int32_t kVectorConst<uint64_t{0xffff'ffff'7fc0'0000}>;
-template <>
-extern const int32_t kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kVectorConst<int8_t{-1}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kVectorConst<uint8_t{0xff}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kVectorConst<int16_t{-1}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kVectorConst<uint16_t{0xffff}> =
-    kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kVectorConst<int32_t{-1}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kVectorConst<uint32_t{0xffff'ffff}> =
-    kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kVectorConst<int64_t{-1}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-
-// 64 bit constants for use with arithmetic operations.
-// Used because only 32 bit immediates are supported on x86-64.
-template <auto Value>
-inline constexpr int32_t kConst = kImpossibleValueConst<Value>;
-template <>
-extern const int32_t kConst<uint32_t{32}>;
-template <>
-extern const int32_t kConst<uint32_t{63}>;
-template <>
-extern const int32_t kConst<uint64_t{64}>;
-template <>
-extern const int32_t kConst<uint64_t{127}>;
-template <>
-extern const int32_t kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kConst<int8_t{0x00}> = kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kConst<uint8_t{0x00}> = kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kConst<int16_t{0x0000}> = kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kConst<uint16_t{0x0000}> = kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kConst<int32_t{0x0000'0000}> = kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kConst<uint32_t{0x0000'0000}> = kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kConst<int64_t{0x0000'0000'0000'0000}> =
-    kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-inline const int32_t& kConst<uint64_t{0x0000'0000'0000'0000}> =
-    kVectorConst<uint64_t{0x0000'0000'0000'0000}>;
-template <>
-extern const int32_t kConst<uint64_t{0x8000'0000'0000'00ff}>;
-template <>
-extern const int32_t kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kConst<int8_t{-1}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kConst<uint8_t{0xff}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kConst<int16_t{-1}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kConst<uint16_t{0xffff}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kConst<int32_t{-1}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kConst<uint32_t{0xffff'ffff}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kConst<int64_t{-1}> = kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-template <>
-inline const int32_t& kConst<uint64_t{0xffff'ffff'ffff'ffff}> =
-    kVectorConst<uint64_t{0xffff'ffff'ffff'ffff}>;
-
-// Constant suitable for NaN boxing of RISC-V 32bit float with PXor.
-// Note: technically we only need to Nan-box Float32 since we don't support Float16 yet.
-template <typename FloatType>
-inline constexpr int32_t kNanBox = kImpossibleTypeConst<FloatType>;
-template <>
-inline const int32_t& kNanBox<intrinsics::Float32> = kVectorConst<uint64_t{0xffff'ffff'0000'0000}>;
-
-// Canonically Nan boxed canonical NaN.
-// Note: technically we only need to Nan-box Float32 since we don't support Float16 yet.
-template <typename FloatType>
-inline constexpr int32_t kNanBoxedNans = kImpossibleTypeConst<FloatType>;
-template <>
-inline const int32_t& kNanBoxedNans<intrinsics::Float32> =
-    kVectorConst<uint64_t{0xffff'ffff'7fc0'0000}>;
-
-// Canonical NaNs. Float32 and Float64 are supported.
-template <typename FloatType>
-inline constexpr int32_t kCanonicalNans = kImpossibleTypeConst<FloatType>;
-template <>
-inline const int32_t& kCanonicalNans<intrinsics::Float32> =
-    kVectorConst<uint64_t{0x7fc0'0000'7fc0'0000}>;
-template <>
-inline const int32_t& kCanonicalNans<intrinsics::Float64> =
-    kVectorConst<uint64_t{0x7ff8'0000'0000'0000}>;
-
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
-extern const int32_t kRiscVToX87Exceptions;
-extern const int32_t kX87ToRiscVExceptions;
-
-extern const int32_t kVid64Bit;
-extern const int32_t kVid32Bit;
-extern const int32_t kVid16Bit;
-extern const int32_t kVid8Bit;
-
-extern const int32_t kBitMaskTable;
-extern const int32_t kBitMaskTo32bitMask;
-extern const int32_t kBitMaskTo16bitMask;
-extern const int32_t kBitMaskTo8bitMask;
-
-extern const int32_t kPMovmskwToPMovmskb;
-extern const int32_t kPMovmskdToPMovmskb;
-extern const int32_t kPMovmskqToPMovmskb;
-
-}  // namespace berberis::constants_pool
-
-#endif  // RISCV64_TO_X86_64_BERBERIS_INTRINSICS_MACRO_ASSEMBLER_CONSTANTS_POOL_H_
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_floating_point_impl.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_floating_point_impl.h
index 26be9c86..48acf4b5 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_floating_point_impl.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/macro_assembler_floating_point_impl.h
@@ -44,26 +44,30 @@ constexpr int32_t kRiscVRoundingModes = 0b1110'0111'00;
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroCanonicalizeNan(XMMRegister result, XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::MacroCanonicalizeNan(XMMRegister result,
+                                                               XMMRegister src) {
   Pmov(result, src);
   Cmpords<FloatType>(result, src);
   Pand(src, result);
-  Pandn(result, {.disp = constants_pool::kCanonicalNans<FloatType>});
+  Pandn(result, {.disp = constants_offsets::kCanonicalNans<FloatType>});
   Por(result, src);
 }
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroCanonicalizeNanAVX(XMMRegister result, XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::MacroCanonicalizeNanAVX(XMMRegister result,
+                                                                  XMMRegister src) {
   Vcmpords<FloatType>(result, src, src);
   Vpand(src, src, result);
-  Vpandn(result, result, {.disp = constants_pool::kCanonicalNans<FloatType>});
+  Vpandn(result, result, {.disp = constants_offsets::kCanonicalNans<FloatType>});
   Vpor(result, result, src);
 }
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroFeq(Register result, XMMRegister src1, XMMRegister src2) {
+constexpr void MacroAssembler<Assembler>::MacroFeq(Register result,
+                                                   XMMRegister src1,
+                                                   XMMRegister src2) {
   Cmpeqs<FloatType>(src1, src2);
   Mov<FloatType>(result, src1);
   And<int32_t>(result, 1);
@@ -71,10 +75,10 @@ void MacroAssembler<Assembler>::MacroFeq(Register result, XMMRegister src1, XMMR
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroFeqAVX(Register result,
-                                            XMMRegister src1,
-                                            XMMRegister src2,
-                                            XMMRegister tmp) {
+constexpr void MacroAssembler<Assembler>::MacroFeqAVX(Register result,
+                                                      XMMRegister src1,
+                                                      XMMRegister src2,
+                                                      XMMRegister tmp) {
   Vcmpeqs<FloatType>(tmp, src1, src2);
   Vmov<FloatType>(result, tmp);
   And<int32_t>(result, 1);
@@ -83,7 +87,8 @@ void MacroAssembler<Assembler>::MacroFeqAVX(Register result,
 // Note: result is returned in %rax which is implicit argument of that macro-instruction.
 // Explicit argument is temporary needed to handle Stmxcsr instruction.
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroFeGetExceptionsTranslate(const Operand& mxcsr_scratch) {
+constexpr void MacroAssembler<Assembler>::MacroFeGetExceptionsTranslate(
+    const Operand& mxcsr_scratch) {
   // Store x87 status word in the AX.
   Fnstsw();
   // Store MXCSR in scratch slot.
@@ -96,11 +101,11 @@ void MacroAssembler<Assembler>::MacroFeGetExceptionsTranslate(const Operand& mxc
   Expand<uint64_t, uint8_t>(gpr_a,
                             {.index = gpr_a,
                              .scale = Assembler::kTimesOne,
-                             .disp = constants_pool::kX87ToRiscVExceptions});
+                             .disp = constants_offsets::kX87ToRiscVExceptions});
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundImmTranslate(
+constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundImmTranslate(
     const Operand& fenv_scratch,
     int8_t exceptions_and_rm) {
   int8_t exceptions = exceptions_and_rm & 0b1'1111;
@@ -118,7 +123,7 @@ void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundImmTranslate(
                    .disp = fenv_scratch.disp + 28};
   // Convert RISC-V exceptions into x87 exceptions.
   uint8_t x87_exceptions = bit_cast<unsigned char*>(
-      static_cast<uintptr_t>(constants_pool::kRiscVToX87Exceptions))[exceptions];
+      static_cast<uintptr_t>(constants_offsets::kRiscVToX87Exceptions))[exceptions];
   // We have to store the whole floating point environment since it's not possible to just change
   // status word without affecting other state.
   Fnstenv(fenv_scratch);
@@ -153,9 +158,10 @@ void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundImmTranslate(
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundTranslate(Register exceptions,
-                                                                      const Operand& fenv_scratch,
-                                                                      Register scratch_register) {
+constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundTranslate(
+    Register exceptions,
+    const Operand& fenv_scratch,
+    Register scratch_register) {
   // Note: in 32bit/64bit mode it's at offset 4, not 2 as one may imagine.
   // Two bytes after control word are ignored.
   Operand x87_status_word = {.base = fenv_scratch.base,
@@ -176,7 +182,7 @@ void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundTranslate(Register e
   Mov<uint8_t>(scratch_register,
                {.index = exceptions,
                 .scale = Assembler::kTimesOne,
-                .disp = constants_pool::kRiscVToX87Exceptions});
+                .disp = constants_offsets::kRiscVToX87Exceptions});
   // Clean exceptions in the x87 environment. Note: in 32bit/64bit mode it's at offset 4, not 2 as
   // one may imagine. Two bytes after control word are ignored.
   And<uint8_t>(x87_status_word, static_cast<uint8_t>(~kX87MxcsrExceptionBits));
@@ -210,8 +216,9 @@ void MacroAssembler<Assembler>::MacroFeSetExceptionsAndRoundTranslate(Register e
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroFeSetExceptionsImmTranslate(const Operand& fenv_scratch,
-                                                                 int8_t exceptions) {
+constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsImmTranslate(
+    const Operand& fenv_scratch,
+    int8_t exceptions) {
   // Note: in 32bit/64bit mode it's at offset 4, not 2 as one may imagine.
   // Two bytes after control word are ignored.
   Operand x87_status_word = {.base = fenv_scratch.base,
@@ -225,7 +232,7 @@ void MacroAssembler<Assembler>::MacroFeSetExceptionsImmTranslate(const Operand&
                    .disp = fenv_scratch.disp + 28};
   // Convert RISC-V exceptions into x87 exceptions.
   uint8_t x87_exceptions = bit_cast<unsigned char*>(
-      static_cast<uintptr_t>(constants_pool::kRiscVToX87Exceptions))[exceptions];
+      static_cast<uintptr_t>(constants_offsets::kRiscVToX87Exceptions))[exceptions];
   // We have to store the whole floating point environment since it's not possible to just change
   // status word without affecting other state.
   Fnstenv(fenv_scratch);
@@ -249,9 +256,9 @@ void MacroAssembler<Assembler>::MacroFeSetExceptionsImmTranslate(const Operand&
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroFeSetExceptionsTranslate(Register exceptions,
-                                                              const Operand& fenv_scratch,
-                                                              Register x87_exceptions) {
+constexpr void MacroAssembler<Assembler>::MacroFeSetExceptionsTranslate(Register exceptions,
+                                                                        const Operand& fenv_scratch,
+                                                                        Register x87_exceptions) {
   // Note: in 32bit/64bit mode it's at offset 4, not 2 as one may imagine.
   // Two bytes after control word are ignored.
   Operand x87_status_word = {.base = fenv_scratch.base,
@@ -272,7 +279,7 @@ void MacroAssembler<Assembler>::MacroFeSetExceptionsTranslate(Register exception
   Mov<uint8_t>(x87_exceptions,
                {.index = exceptions,
                 .scale = Assembler::kTimesOne,
-                .disp = constants_pool::kRiscVToX87Exceptions});
+                .disp = constants_offsets::kRiscVToX87Exceptions});
   // Clean exceptions in the x87 environment. Note: in 32bit/64bit mode it's at offset 4, not 2 as
   // one may imagine. Two bytes after control word are ignored.
   And<uint8_t>(x87_status_word, static_cast<uint8_t>(~kX87MxcsrExceptionBits));
@@ -291,9 +298,9 @@ void MacroAssembler<Assembler>::MacroFeSetExceptionsTranslate(Register exception
 // Note: actual rounding mode comes in %cl which is implicit argument of that macro-instruction.
 // All explicit arguments are temporaries.
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroFeSetRound(Register x87_sse_round,
-                                                const Operand& cw_scratch,
-                                                const Operand& mxcsr_scratch) {
+constexpr void MacroAssembler<Assembler>::MacroFeSetRound(Register x87_sse_round,
+                                                          const Operand& cw_scratch,
+                                                          const Operand& mxcsr_scratch) {
   // Store x87 control world in first scratch slot.
   Fnstcw(cw_scratch);
   // Store MXCSR in second scratch slot.
@@ -324,9 +331,9 @@ void MacroAssembler<Assembler>::MacroFeSetRound(Register x87_sse_round,
 }
 
 template <typename Assembler>
-void MacroAssembler<Assembler>::MacroFeSetRoundImmTranslate(const Operand& cw_scratch,
-                                                            const Operand& mxcsr_scratch,
-                                                            int8_t rm) {
+constexpr void MacroAssembler<Assembler>::MacroFeSetRoundImmTranslate(const Operand& cw_scratch,
+                                                                      const Operand& mxcsr_scratch,
+                                                                      int8_t rm) {
   // Store x87 control world in first scratch slot.
   Fnstcw(cw_scratch);
   // Store MXCSR in second scratch slot.
@@ -351,7 +358,9 @@ void MacroAssembler<Assembler>::MacroFeSetRoundImmTranslate(const Operand& cw_sc
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroFle(Register result, XMMRegister src1, XMMRegister src2) {
+constexpr void MacroAssembler<Assembler>::MacroFle(Register result,
+                                                   XMMRegister src1,
+                                                   XMMRegister src2) {
   Cmples<FloatType>(src1, src2);
   Mov<FloatType>(result, src1);
   And<int32_t>(result, 1);
@@ -359,16 +368,17 @@ void MacroAssembler<Assembler>::MacroFle(Register result, XMMRegister src1, XMMR
 
 template <typename Assembler>
 template <typename FormatTo, typename FormatFrom>
-void MacroAssembler<Assembler>::MacroFCvtFloatToInteger(Register result, XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::MacroFCvtFloatToInteger(Register result,
+                                                                  XMMRegister src) {
   Cvt<FormatFrom, FormatTo>(result, src);
 }
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroFleAVX(Register result,
-                                            XMMRegister src1,
-                                            XMMRegister src2,
-                                            XMMRegister tmp) {
+constexpr void MacroAssembler<Assembler>::MacroFleAVX(Register result,
+                                                      XMMRegister src1,
+                                                      XMMRegister src2,
+                                                      XMMRegister tmp) {
   Vcmples<FloatType>(tmp, src1, src2);
   Vmov<FloatType>(result, tmp);
   And<int32_t>(result, 1);
@@ -376,7 +386,9 @@ void MacroAssembler<Assembler>::MacroFleAVX(Register result,
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroFlt(Register result, XMMRegister src1, XMMRegister src2) {
+constexpr void MacroAssembler<Assembler>::MacroFlt(Register result,
+                                                   XMMRegister src1,
+                                                   XMMRegister src2) {
   Cmplts<FloatType>(src1, src2);
   Mov<FloatType>(result, src1);
   And<int32_t>(result, 1);
@@ -384,10 +396,10 @@ void MacroAssembler<Assembler>::MacroFlt(Register result, XMMRegister src1, XMMR
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroFltAVX(Register result,
-                                            XMMRegister src1,
-                                            XMMRegister src2,
-                                            XMMRegister tmp) {
+constexpr void MacroAssembler<Assembler>::MacroFltAVX(Register result,
+                                                      XMMRegister src1,
+                                                      XMMRegister src2,
+                                                      XMMRegister tmp) {
   Vcmplts<FloatType>(tmp, src1, src2);
   Vmov<FloatType>(result, tmp);
   And<int32_t>(result, 1);
@@ -395,43 +407,44 @@ void MacroAssembler<Assembler>::MacroFltAVX(Register result,
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroNanBox(XMMRegister arg) {
+constexpr void MacroAssembler<Assembler>::MacroNanBox(XMMRegister arg) {
   static_assert(std::is_same_v<FloatType, Float32>);
 
-  Por(arg, {.disp = constants_pool::kNanBox<Float32>});
+  Por(arg, {.disp = constants_offsets::kNanBox<Float32>});
 }
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroNanBoxAVX(XMMRegister result, XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::MacroNanBoxAVX(XMMRegister result, XMMRegister src) {
   static_assert(std::is_same_v<FloatType, Float32>);
 
-  Vpor(result, src, {.disp = constants_pool::kNanBox<Float32>});
+  Vpor(result, src, {.disp = constants_offsets::kNanBox<Float32>});
 }
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroUnboxNan(XMMRegister result, XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::MacroUnboxNan(XMMRegister result, XMMRegister src) {
   static_assert(std::is_same_v<FloatType, Float32>);
 
   Pmov(result, src);
-  Pcmpeq<typename TypeTraits<FloatType>::Int>(result, {.disp = constants_pool::kNanBox<Float32>});
+  Pcmpeq<typename TypeTraits<FloatType>::Int>(result,
+                                              {.disp = constants_offsets::kNanBox<Float32>});
   Pshufd(result, result, kShuffleDDBB);
   Pand(src, result);
-  Pandn(result, {.disp = constants_pool::kNanBoxedNans<Float32>});
+  Pandn(result, {.disp = constants_offsets::kNanBoxedNans<Float32>});
   Por(result, src);
 }
 
 template <typename Assembler>
 template <typename FloatType>
-void MacroAssembler<Assembler>::MacroUnboxNanAVX(XMMRegister result, XMMRegister src) {
+constexpr void MacroAssembler<Assembler>::MacroUnboxNanAVX(XMMRegister result, XMMRegister src) {
   static_assert(std::is_same_v<FloatType, Float32>);
 
   Vpcmpeq<typename TypeTraits<FloatType>::Int>(
-      result, src, {.disp = constants_pool::kNanBox<Float32>});
+      result, src, {.disp = constants_offsets::kNanBox<Float32>});
   Vpshufd(result, result, kShuffleDDBB);
   Vpand(src, src, result);
-  Vpandn(result, result, {.disp = constants_pool::kNanBoxedNans<Float32>});
+  Vpandn(result, result, {.disp = constants_offsets::kNanBoxedNans<Float32>});
   Vpor(result, result, src);
 }
 
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h
index 150e1a1b..6a9b00e5 100644
--- a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/vector_intrinsics.h
@@ -22,7 +22,7 @@
 
 #include "berberis/base/dependent_false.h"
 #include "berberis/intrinsics/common/intrinsics.h"
-#include "berberis/intrinsics/macro_assembler_constants_pool.h"
+#include "berberis/intrinsics/constants_pool.h"
 #include "berberis/intrinsics/simd_register.h"
 
 // Define function to use in host-agnostic code.
diff --git a/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/verifier_assembler.h b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/verifier_assembler.h
new file mode 100644
index 00000000..fad0f1b1
--- /dev/null
+++ b/intrinsics/riscv64_to_x86_64/include/berberis/intrinsics/verifier_assembler.h
@@ -0,0 +1,56 @@
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
+#ifndef RISCV64_TO_X86_64_INTRINSICS_VERIFIER_ASSEMBLER_H_
+#define RISCV64_TO_X86_64_INTRINSICS_VERIFIER_ASSEMBLER_H_
+
+#include <stdio.h>
+
+#include "berberis/intrinsics/all_to_x86_32_or_x86_64/verifier_assembler_x86_32_and_x86_64.h"
+
+namespace berberis {
+
+class VerifierAssembler : public x86_32_and_x86_64::VerifierAssembler<VerifierAssembler> {
+ public:
+  using BaseAssembler = x86_32_and_x86_64::VerifierAssembler<VerifierAssembler>;
+  using FinalAssembler = VerifierAssembler;
+
+  constexpr VerifierAssembler([[maybe_unused]] int indent, [[maybe_unused]] FILE* out)
+      : BaseAssembler() {}
+  constexpr VerifierAssembler() : BaseAssembler() {}
+
+// Instructions.
+#include "gen_verifier_assembler_x86_64-inl.h"  // NOLINT generated file
+
+  // Unhide Movq(Mem, XMMReg) and Movq(XMMReg, Mem) hidden by Movq(Reg, Imm) and many others.
+  using BaseAssembler::Movq;
+
+ protected:
+  using RegisterDefaultBit = RegisterTemplate<kRsp, 'q'>;
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
+}  // namespace berberis
+
+#endif  // RISCV64_TO_X86_64_INTRINSICS_VERIFIER_ASSEMBLER_H_
diff --git a/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json b/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json
index 452d3657..a517e666 100644
--- a/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json
+++ b/intrinsics/riscv64_to_x86_64/machine_ir_intrinsic_binding.json
@@ -140,36 +140,18 @@
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
-  {
-    "name": "Div<uint8_t>",
-    "insn": "DivUInt8",
-    "in": [ 1, 0 ],
-    "out": [ 1 ]
-  },
   {
     "name": "Div<int16_t>",
     "insn": "DivInt16",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
-  {
-    "name": "Div<uint16_t>",
-    "insn": "DivUInt16",
-    "in": [ 1, 0 ],
-    "out": [ 1 ]
-  },
   {
     "name": "Div<int32_t>",
     "insn": "DivInt32",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
-  {
-    "name": "Div<uint32_t>",
-    "insn": "DivUInt32",
-    "in": [ 1, 0 ],
-    "out": [ 1 ]
-  },
   {
     "name": "Div<int64_t>",
     "insn": "DivInt64",
@@ -177,58 +159,28 @@
     "out": [ 1 ]
   },
   {
-    "name": "Div<uint64_t>",
-    "insn": "DivUInt64",
-    "in": [ 1, 0 ],
-    "out": [ 1 ]
-  },
-    {
-    "name": "Rem<int8_t>",
-    "insn": "RemInt8",
+    "name": "Div<uint8_t>",
+    "insn": "DivUInt8",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Rem<uint8_t>",
-    "insn": "RemUInt8",
+    "name": "Div<uint16_t>",
+    "insn": "DivUInt16",
     "in": [ 1, 0 ],
     "out": [ 1 ]
   },
   {
-    "name": "Rem<int16_t>",
-    "insn": "RemInt16",
-    "in": [ 1, 0 ],
-    "out": [ 2 ]
-  },
-  {
-    "name": "Rem<uint16_t>",
-    "insn": "RemUInt16",
-    "in": [ 1, 0 ],
-    "out": [ 2 ]
-  },
-  {
-    "name": "Rem<int32_t>",
-    "insn": "RemInt32",
-    "in": [ 1, 0 ],
-    "out": [ 2 ]
-  },
-  {
-    "name": "Rem<uint32_t>",
-    "insn": "RemUInt32",
-    "in": [ 1, 0 ],
-    "out": [ 2 ]
-  },
-  {
-    "name": "Rem<int64_t>",
-    "insn": "RemInt64",
+    "name": "Div<uint32_t>",
+    "insn": "DivUInt32",
     "in": [ 1, 0 ],
-    "out": [ 2 ]
+    "out": [ 1 ]
   },
   {
-    "name": "Rem<uint64_t>",
-    "insn": "RemUInt64",
+    "name": "Div<uint64_t>",
+    "insn": "DivUInt64",
     "in": [ 1, 0 ],
-    "out": [ 2 ]
+    "out": [ 1 ]
   },
   {
     "name": "FAddHostRounding<Float32>",
@@ -306,61 +258,6 @@
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
-  {
-    "name": "FeGetExceptions",
-    "insn": "MacroFeGetExceptionsTranslate",
-    "usage": "inline-only",
-    "in": [],
-    "out": [ 1 ]
-  },
-  {
-    "name": "FeSetExceptions",
-    "insn": "MacroFeSetExceptionsTranslate",
-    "usage": "inline-only",
-    "in": [ 0 ],
-    "out": []
-  },
-  {
-    "name": "FeSetExceptionsAndRound",
-    "insn": "MacroFeSetExceptionsAndRoundTranslate",
-    "usage": "inline-only",
-    "in": [ 0, 3 ],
-    "out": []
-  },
-  {
-    "name": "FeSetExceptionsImm",
-    "insn": "MacroFeSetExceptionsImmTranslate",
-    "usage": "inline-only",
-    "in": [ 1 ],
-    "out": []
-  },
-  {
-    "name": "FeSetExceptionsAndRoundImm",
-    "insn": "MacroFeSetExceptionsAndRoundImmTranslate",
-    "usage": "inline-only",
-    "in": [ 1 ],
-    "out": []
-  },
-  {
-    "name": "FeSetRound",
-    "insn": "MacroFeSetRound",
-    "in": [ 3 ],
-    "out": []
-  },
-  {
-    "name": "FeSetRoundImm",
-    "insn": "MacroFeSetRound",
-    "usage": "no-inline",
-    "in": [ 3 ],
-    "out": []
-  },
-  {
-    "name": "FeSetRoundImm",
-    "insn": "MacroFeSetRoundImmTranslate",
-    "usage": "inline-only",
-    "in": [ 2 ],
-    "out": []
-  },
   {
     "name": "FMAddHostRounding<Float32>",
     "insn": "Vfmadd231ssXRegXRegXReg",
@@ -469,6 +366,61 @@
     "in": [ 1, 2 ],
     "out": [ 0 ]
   },
+  {
+    "name": "FeGetExceptions",
+    "insn": "MacroFeGetExceptionsTranslate",
+    "usage": "inline-only",
+    "in": [],
+    "out": [ 1 ]
+  },
+  {
+    "name": "FeSetExceptionsAndRoundImm",
+    "insn": "MacroFeSetExceptionsAndRoundImmTranslate",
+    "usage": "inline-only",
+    "in": [ 1 ],
+    "out": []
+  },
+  {
+    "name": "FeSetExceptionsAndRound",
+    "insn": "MacroFeSetExceptionsAndRoundTranslate",
+    "usage": "inline-only",
+    "in": [ 0, 3 ],
+    "out": []
+  },
+  {
+    "name": "FeSetExceptionsImm",
+    "insn": "MacroFeSetExceptionsImmTranslate",
+    "usage": "inline-only",
+    "in": [ 1 ],
+    "out": []
+  },
+  {
+    "name": "FeSetExceptions",
+    "insn": "MacroFeSetExceptionsTranslate",
+    "usage": "inline-only",
+    "in": [ 0 ],
+    "out": []
+  },
+  {
+    "name": "FeSetRound",
+    "insn": "MacroFeSetRound",
+    "in": [ 3 ],
+    "out": []
+  },
+  {
+    "name": "FeSetRoundImm",
+    "insn": "MacroFeSetRoundImmTranslate",
+    "usage": "inline-only",
+    "in": [ 2 ],
+    "out": []
+  },
+  {
+    "name": "FeSetRoundImm",
+    "insn": "MacroFeSetRound",
+    "usage": "no-inline",
+    "in": [ 3 ],
+    "out": []
+  },
   {
     "name": "Feq<Float32>",
     "insn": "MacroFeqFloat32",
@@ -649,6 +601,54 @@
     "in": [ 1 ],
     "out": [ 0 ]
   },
+  {
+    "name": "Rem<int8_t>",
+    "insn": "RemInt8",
+    "in": [ 1, 0 ],
+    "out": [ 1 ]
+  },
+  {
+    "name": "Rem<int16_t>",
+    "insn": "RemInt16",
+    "in": [ 1, 0 ],
+    "out": [ 2 ]
+  },
+  {
+    "name": "Rem<int32_t>",
+    "insn": "RemInt32",
+    "in": [ 1, 0 ],
+    "out": [ 2 ]
+  },
+  {
+    "name": "Rem<int64_t>",
+    "insn": "RemInt64",
+    "in": [ 1, 0 ],
+    "out": [ 2 ]
+  },
+  {
+    "name": "Rem<uint8_t>",
+    "insn": "RemUInt8",
+    "in": [ 1, 0 ],
+    "out": [ 1 ]
+  },
+  {
+    "name": "Rem<uint16_t>",
+    "insn": "RemUInt16",
+    "in": [ 1, 0 ],
+    "out": [ 2 ]
+  },
+  {
+    "name": "Rem<uint32_t>",
+    "insn": "RemUInt32",
+    "in": [ 1, 0 ],
+    "out": [ 2 ]
+  },
+  {
+    "name": "Rem<uint64_t>",
+    "insn": "RemUInt64",
+    "in": [ 1, 0 ],
+    "out": [ 2 ]
+  },
   {
     "name": "Rev8",
     "insn": "BswapqReg",
@@ -680,14 +680,14 @@
     "out": [ 0 ]
   },
   {
-    "name": "Sext<int16_t>",
-    "insn": "MovsxwqRegReg",
+    "name": "Sext<int8_t>",
+    "insn": "MovsxbqRegReg",
     "in": [ 1 ],
     "out": [ 0 ]
   },
   {
-    "name": "Sext<int8_t>",
-    "insn": "MovsxbqRegReg",
+    "name": "Sext<int16_t>",
+    "insn": "MovsxwqRegReg",
     "in": [ 1 ],
     "out": [ 0 ]
   },
diff --git a/intrinsics/riscv64_to_x86_64/macro_def.json b/intrinsics/riscv64_to_x86_64/macro_def.json
index 55b96e0d..f9d7075d 100644
--- a/intrinsics/riscv64_to_x86_64/macro_def.json
+++ b/intrinsics/riscv64_to_x86_64/macro_def.json
@@ -38,7 +38,7 @@
     {
       "name": "CanonicalizeNanFloat32",
       "args": [
-        { "class": "FpReg32", "usage": "def_early_clobber" },
+        { "class": "FpReg32", "usage": "def" },
         { "class": "FpReg32", "usage": "use_def" }
       ],
       "asm": "MacroCanonicalizeNan<intrinsics::Float32>",
@@ -47,7 +47,7 @@
     {
       "name": "CanonicalizeNanFloat32AVX",
       "args": [
-        { "class": "FpReg32", "usage": "def_early_clobber" },
+        { "class": "FpReg32", "usage": "def" },
         { "class": "FpReg32", "usage": "use_def" }
       ],
       "asm": "MacroCanonicalizeNanAVX<intrinsics::Float32>",
@@ -56,7 +56,7 @@
     {
       "name": "CanonicalizeNanFloat64",
       "args": [
-        { "class": "FpReg64", "usage": "def_early_clobber" },
+        { "class": "FpReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" }
       ],
       "asm": "MacroCanonicalizeNan<intrinsics::Float64>",
@@ -65,7 +65,7 @@
     {
       "name": "CanonicalizeNanFloat64AVX",
       "args": [
-        { "class": "FpReg64", "usage": "def_early_clobber" },
+        { "class": "FpReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" }
       ],
       "asm": "MacroCanonicalizeNanAVX<intrinsics::Float64>",
@@ -287,7 +287,8 @@
         { "class": "GeneralReg64", "usage": "def_early_clobber" },
         { "class": "Mem16", "usage": "def_early_clobber" },
         { "class": "Mem32", "usage": "def_early_clobber" },
-        { "class": "CL", "usage": "use" }
+        { "class": "CL", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFeSetRound",
       "mnemo": "MACRO_FE_SET_ROUND"
@@ -307,7 +308,8 @@
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use_def" },
-        { "class": "FpReg32", "usage": "use" }
+        { "class": "FpReg32", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFeq<intrinsics::Float32>",
       "mnemo": "MACRO_FEQ_F32"
@@ -318,7 +320,8 @@
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use" },
         { "class": "FpReg32", "usage": "use" },
-        { "class": "FpReg32", "usage": "def" }
+        { "class": "FpReg32", "usage": "def" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFeqAVX<intrinsics::Float32>",
       "mnemo": "MACRO_FEQ_F32"
@@ -328,7 +331,8 @@
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" },
-        { "class": "FpReg64", "usage": "use" }
+        { "class": "FpReg64", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFeq<intrinsics::Float64>",
       "mnemo": "MACRO_FEQ_F64"
@@ -339,7 +343,8 @@
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use" },
         { "class": "FpReg64", "usage": "use" },
-        { "class": "FpReg64", "usage": "def" }
+        { "class": "FpReg64", "usage": "def" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFeqAVX<intrinsics::Float64>",
       "mnemo": "MACRO_FEQ_F64"
@@ -349,7 +354,8 @@
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use_def" },
-        { "class": "FpReg32", "usage": "use" }
+        { "class": "FpReg32", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFle<intrinsics::Float32>",
       "mnemo": "MACRO_FLE_F32"
@@ -360,7 +366,8 @@
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use" },
         { "class": "FpReg32", "usage": "use" },
-        { "class": "FpReg32", "usage": "def" }
+        { "class": "FpReg32", "usage": "def" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFleAVX<intrinsics::Float32>",
       "mnemo": "MACRO_FLE_F32"
@@ -370,7 +377,8 @@
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" },
-        { "class": "FpReg64", "usage": "use" }
+        { "class": "FpReg64", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFle<intrinsics::Float64>",
       "mnemo": "MACRO_FLE_F64"
@@ -381,7 +389,8 @@
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use" },
         { "class": "FpReg64", "usage": "use" },
-        { "class": "FpReg64", "usage": "def" }
+        { "class": "FpReg64", "usage": "def" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFleAVX<intrinsics::Float64>",
       "mnemo": "MACRO_FLE_F64"
@@ -391,7 +400,8 @@
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use_def" },
-        { "class": "FpReg32", "usage": "use" }
+        { "class": "FpReg32", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFlt<intrinsics::Float32>",
       "mnemo": "MACRO_FLT_F32"
@@ -402,7 +412,8 @@
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg32", "usage": "use" },
         { "class": "FpReg32", "usage": "use" },
-        { "class": "FpReg32", "usage": "def" }
+        { "class": "FpReg32", "usage": "def" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFltAVX<intrinsics::Float32>",
       "mnemo": "MACRO_FLT_F32"
@@ -412,7 +423,8 @@
       "args": [
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" },
-        { "class": "FpReg64", "usage": "use" }
+        { "class": "FpReg64", "usage": "use" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFlt<intrinsics::Float64>",
       "mnemo": "MACRO_FLT_F64"
@@ -423,7 +435,8 @@
         { "class": "GeneralReg64", "usage": "def" },
         { "class": "FpReg64", "usage": "use" },
         { "class": "FpReg64", "usage": "use" },
-        { "class": "FpReg64", "usage": "def" }
+        { "class": "FpReg64", "usage": "def" },
+        { "class": "FLAGS", "usage": "def" }
       ],
       "asm": "MacroFltAVX<intrinsics::Float64>",
       "mnemo": "MACRO_FLT_F64"
@@ -448,7 +461,7 @@
     {
       "name": "MacroUnboxNanFloat32",
       "args": [
-        { "class": "FpReg32", "usage": "def_early_clobber" },
+        { "class": "FpReg32", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" }
       ],
       "asm": "MacroUnboxNan<intrinsics::Float32>",
@@ -457,7 +470,7 @@
     {
       "name": "MacroUnboxNanFloat32AVX",
       "args": [
-        { "class": "FpReg32", "usage": "def_early_clobber" },
+        { "class": "FpReg32", "usage": "def" },
         { "class": "FpReg64", "usage": "use_def" }
       ],
       "asm": "MacroUnboxNanAVX<intrinsics::Float32>",
@@ -510,8 +523,7 @@
     {
       "name": "Orcb",
       "args": [
-        { "class": "FpReg64", "usage": "use_def" },
-        { "class": "FLAGS", "usage": "def" }
+        { "class": "FpReg64", "usage": "use_def" }
       ],
       "asm": "MacroOrcb",
       "mnemo": "MACRO_ORCB"
@@ -520,8 +532,7 @@
       "name": "OrcbAVX",
       "args": [
         { "class": "FpReg64", "usage": "def" },
-        { "class": "FpReg64", "usage": "use" },
-        { "class": "FLAGS", "usage": "def" }
+        { "class": "FpReg64", "usage": "use" }
       ],
       "asm": "MacroOrcbAVX",
       "mnemo": "MACRO_ORCB"
diff --git a/intrinsics/riscv64_to_x86_64/text_assembler.h b/intrinsics/riscv64_to_x86_64/text_assembler.h
index 855b6092..a157f3f7 100644
--- a/intrinsics/riscv64_to_x86_64/text_assembler.h
+++ b/intrinsics/riscv64_to_x86_64/text_assembler.h
@@ -14,8 +14,8 @@
  * limitations under the License.
  */
 
-#ifndef RISCV64_TO_X86_64_NDK_TRANSLATION_INTRINSICS_TEXT_ASSEMBLER_H_
-#define RISCV64_TO_X86_64_NDK_TRANSLATION_INTRINSICS_TEXT_ASSEMBLER_H_
+#ifndef BERBERIS_INTRINSICS_RISCV64_TO_X86_64_TEXT_ASSEMBLER_H_
+#define BERBERIS_INTRINSICS_RISCV64_TO_X86_64_TEXT_ASSEMBLER_H_
 
 #include <stdio.h>
 
@@ -95,4 +95,4 @@ void MakeExtraGuestFunctions(FILE* out) {
 
 }  // namespace berberis
 
-#endif  // RISCV64_TO_X86_64_NDK_TRANSLATION_INTRINSICS_TEXT_ASSEMBLER_H_
+#endif  // BERBERIS_INTRINSICS_RISCV64_TO_X86_64_TEXT_ASSEMBLER_H_
diff --git a/intrinsics/simd_register_test.cc b/intrinsics/simd_register_test.cc
index f556ad1d..3663a871 100644
--- a/intrinsics/simd_register_test.cc
+++ b/intrinsics/simd_register_test.cc
@@ -27,6 +27,15 @@ namespace {
 constexpr Int64x2 kLhs = {0x5555'5555'5555'5555, 0x5555'5555'5555'5555};
 constexpr Int64x2 kRhs = {0x3333'3333'3333'3333, 0x3333'3333'3333'3333};
 
+// Because comparison on SIMD128Register is based on comparison of UInt64x2 which produces
+// array and not bool we have to ensure we are processing these correctly.
+// This caused issues in the past, see b/384140395
+TEST(SIMD_REGISTER, TestCmp) {
+  SIMD128Register lhs = Int64x2{0, 1};
+  SIMD128Register rhs = Int64x2{0, 0};
+  ASSERT_NE(lhs, rhs);
+}
+
 TEST(SIMD_REGISTER, TestEq) {
   SIMD128Register lhs = kLhs;
   ASSERT_EQ(lhs, lhs);
diff --git a/jni/jni_trampolines.cc b/jni/jni_trampolines.cc
index 10e289a2..899a7232 100644
--- a/jni/jni_trampolines.cc
+++ b/jni/jni_trampolines.cc
@@ -26,6 +26,7 @@
 #include <jni.h>  // NOLINT [build/include_order]
 
 #include "berberis/base/checks.h"
+#include "berberis/base/gettid.h"
 #include "berberis/base/logging.h"
 #include "berberis/base/tracing.h"
 #include "berberis/guest_abi/function_wrappers.h"
@@ -237,14 +238,20 @@ struct KnownMethodTrampoline {
 //
 // It is likely that the new JNIEnv instance for the thread supersedes the
 // previous one but the code below does not make this assumption.
-std::mutex g_java_vm_guard_mutex;
+struct JNIEnvMapping {
+  std::deque<JNIEnv> guest_jni_envs;
+  std::map<GuestType<JNIEnv*>, JNIEnv*> guest_to_host_jni_env;
+  std::map<JNIEnv*, GuestType<JNIEnv*>> host_to_guest_jni_env;
+};
+
+std::mutex g_jni_guard_mutex;
 
 JavaVM g_guest_java_vm;
 JavaVM* g_host_java_vm;
 
-thread_local std::deque<JNIEnv> g_guest_jni_envs;
-thread_local std::map<GuestType<JNIEnv*>, JNIEnv*> g_guest_to_host_jni_env;
-thread_local std::map<JNIEnv*, GuestType<JNIEnv*>> g_host_to_guest_jni_env;
+// TODO(b/399909631): Add a callback from GuestThread::Destroy to remove entries
+// from this map.
+std::map<pid_t, JNIEnvMapping> g_jni_env_mappings;
 
 void DoJavaVMTrampoline_DestroyJavaVM(HostCode /* callee */, ProcessState* state) {
   using PFN_callee = decltype(std::declval<JavaVM>().functions->DestroyJavaVM);
@@ -354,28 +361,36 @@ GuestType<JNIEnv*> ToGuestJNIEnv(JNIEnv* host_jni_env) {
     std::atomic_store_explicit(&g_jni_env_wrapped, 1U, std::memory_order_release);
   }
 
-  auto it = g_host_to_guest_jni_env.find(host_jni_env);
-  if (it != g_host_to_guest_jni_env.end()) {
+  std::lock_guard<std::mutex> lock(g_jni_guard_mutex);
+  pid_t thread_id = GettidSyscall();
+  JNIEnvMapping& mapping = g_jni_env_mappings[thread_id];
+
+  auto it = mapping.host_to_guest_jni_env.find(host_jni_env);
+  if (it != mapping.host_to_guest_jni_env.end()) {
     return it->second;
   }
 
-  g_guest_jni_envs.emplace_back(*host_jni_env);
-  JNIEnv* guest_jni_env = &g_guest_jni_envs.back();
+  mapping.guest_jni_envs.emplace_back(*host_jni_env);
+  JNIEnv* guest_jni_env = &mapping.guest_jni_envs.back();
   auto [unused_it1, host_to_guest_inserted] =
-      g_host_to_guest_jni_env.try_emplace(host_jni_env, guest_jni_env);
+      mapping.host_to_guest_jni_env.try_emplace(host_jni_env, guest_jni_env);
   CHECK(host_to_guest_inserted);
 
   auto [unused_it2, guest_to_host_inserted] =
-      g_guest_to_host_jni_env.try_emplace(guest_jni_env, host_jni_env);
+      mapping.guest_to_host_jni_env.try_emplace(guest_jni_env, host_jni_env);
   CHECK(guest_to_host_inserted);
 
   return guest_jni_env;
 }
 
 JNIEnv* ToHostJNIEnv(GuestType<JNIEnv*> guest_jni_env) {
-  auto it = g_guest_to_host_jni_env.find(guest_jni_env);
+  std::lock_guard<std::mutex> lock(g_jni_guard_mutex);
+  pid_t thread_id = GettidSyscall();
+  JNIEnvMapping& mapping = g_jni_env_mappings[thread_id];
+
+  auto it = mapping.guest_to_host_jni_env.find(guest_jni_env);
 
-  if (it == g_guest_to_host_jni_env.end()) {
+  if (it == mapping.guest_to_host_jni_env.end()) {
     ALOGE("Unexpected guest JNIEnv: %p (it was never passed to guest), passing to host 'as is'",
           ToHostAddr(guest_jni_env));
     TRACE("Unexpected guest JNIEnv: %p (it was never passed to guest), passing to host 'as is'",
@@ -393,7 +408,7 @@ GuestType<JavaVM*> ToGuestJavaVM(JavaVM* host_java_vm) {
     std::atomic_store_explicit(&g_java_vm_wrapped, 1U, std::memory_order_release);
   }
 
-  std::lock_guard<std::mutex> lock(g_java_vm_guard_mutex);
+  std::lock_guard<std::mutex> lock(g_jni_guard_mutex);
   if (g_host_java_vm == nullptr) {
     g_guest_java_vm = *host_java_vm;
     g_host_java_vm = host_java_vm;
@@ -410,7 +425,7 @@ GuestType<JavaVM*> ToGuestJavaVM(JavaVM* host_java_vm) {
 }
 
 JavaVM* ToHostJavaVM(GuestType<JavaVM*> guest_java_vm) {
-  std::lock_guard<std::mutex> lock(g_java_vm_guard_mutex);
+  std::lock_guard<std::mutex> lock(g_jni_guard_mutex);
   if (ToHostAddr(guest_java_vm) == &g_guest_java_vm) {
     return g_host_java_vm;
   }
diff --git a/kernel_api/open_emulation.cc b/kernel_api/open_emulation.cc
index d3e39735..e0f350b2 100644
--- a/kernel_api/open_emulation.cc
+++ b/kernel_api/open_emulation.cc
@@ -20,6 +20,7 @@
 #include <sys/stat.h>
 #include <unistd.h>
 
+#include <cstdint>
 #include <cstdio>
 #include <cstring>
 #include <mutex>
@@ -141,27 +142,45 @@ int OpenatProcSelfMapsForGuest(int dirfd, int flags, mode_t mode) {
     uintptr_t start;
     uintptr_t end;
     int prot_offset;
-    if (sscanf(lines.at(i).c_str(), "%" SCNxPTR "-%" SCNxPTR " %n", &start, &end, &prot_offset) !=
-        2) {
-      if (!lines[i].empty()) {
-        TRACE("Cannot parse " PROC_SELF_MAPS " line : %s", lines.at(i).c_str());
+    auto& cur_line = lines.at(i);
+    if (sscanf(cur_line.c_str(), "%" SCNxPTR "-%" SCNxPTR " %n", &start, &end, &prot_offset) != 2) {
+      if (!cur_line.empty()) {
+        TRACE("Cannot parse " PROC_SELF_MAPS " line : %s", cur_line.c_str());
       }
-      guest_maps.append(lines.at(i) + "\n");
+      guest_maps.append(cur_line + "\n");
       continue;
     }
-    BitValue exec_status = maps_shadow->GetExecutable(GuestAddr(start), end - start);
-    if (exec_status == kBitMixed) {
-      // When we strip guest executable bit from host mappings the kernel may merge r-- and r-x
-      // mappings, resulting in kBitMixed executability state. We are avoiding such merging by
-      // SetVmaAnonName in MmapForGuest/MprotectForGuest. This isn't strictly guaranteed to work, so
-      // issue a warning if it doesn't, or if we got kBitMixed for another reason to investigate.
-      // TODO(b/322873334): Instead split such host mapping into several guest mappings.
-      TRACE("Unexpected " PROC_SELF_MAPS " mapping with mixed guest executability");
+    // Split the line into guest exec / no-exec chunks.
+    uintptr_t original_start = start;
+    while (start < end) {
+      auto [is_exec, region_size] =
+          maps_shadow->GetExecutableRegionSize(GuestAddr(start), end - start);
+      // prot_offset points to "rwxp", so offset of "x" is 2 symbols away.
+      cur_line.at(prot_offset + 2) = is_exec ? 'x' : '-';
+      if ((start == original_start) && ((start + region_size) >= end)) {
+        // Most often we should be able to just take the whole host line.
+        guest_maps.append(cur_line);
+        guest_maps.append("\n");
+        break;
+      }
+      // We cannot print into cur_line in place since we don't want the terminating null. Also the
+      // new range can theoretically be longer than the old one. E.g. if "a000-ba000" (len=10) is
+      // split into "a000-aa000" (len=10) and "aa000-ba000" (len=11).
+      // At max, for 64-bit pointers, we need 16(ptr)+1(-)+16(ptr)+1(\0)=34 symbols buffer,
+      // so 64-bytes should be more than enough.
+      char addr_range_buf[64];
+      int chars_num = snprintf(addr_range_buf,
+                               sizeof(addr_range_buf),
+                               "%" PRIxPTR "-%" PRIxPTR,
+                               start,
+                               start + region_size);
+      CHECK_LT(static_cast<size_t>(chars_num), sizeof(addr_range_buf));
+      guest_maps.append(addr_range_buf);
+      // Append the rest of the line starting from protections and including the front space.
+      guest_maps.append(cur_line.data() + prot_offset - 1);
+      guest_maps.append("\n");
+      start += region_size;
     }
-    // prot_offset points to "rwxp", so offset of "x" is 2 symbols away.
-    lines.at(i).at(prot_offset + 2) = (exec_status == kBitSet) ? 'x' : '-';
-
-    guest_maps.append(lines.at(i) + "\n");
   }
 
   // Normally /proc/self/maps doesn't have newline at the end.
diff --git a/kernel_api/sys_mman_emulation.cc b/kernel_api/sys_mman_emulation.cc
index 63249efd..11e924ad 100644
--- a/kernel_api/sys_mman_emulation.cc
+++ b/kernel_api/sys_mman_emulation.cc
@@ -43,18 +43,6 @@ void UpdateGuestProt(int guest_prot, void* addr, size_t length) {
   GuestAddr guest_addr = ToGuestAddr(addr);
   GuestMapShadow* shadow = GuestMapShadow::GetInstance();
   if (guest_prot & PROT_EXEC) {
-    // Since we strip guest executable bit from host mappings kernel may merge r-- and r-x guest
-    // mappings together, which is difficult to split back when emulating /proc/self/maps. Setting
-    // region name helps to prevent regions merging. It helps even if it's a file backed mapping,
-    // even though filename isn't visibly changed in /proc/self/maps in this case.
-    // Note that this name can be overridden by the app, which is fine as long as it's
-    // unique for this mapping. We do not remove this name if executable bit is
-    // removed which also should be fine since it's just a hint.
-    int res = SetVmaAnonName(addr, AlignUpPageSize(length), "[guest exec mapping hint]");
-    if (res == -1) {
-      TRACE("PR_SET_VMA_ANON_NAME failed with errno=%s", std::strerror(errno));
-    }
-
     shadow->SetExecutable(guest_addr, length);
   } else {
     shadow->ClearExecutable(guest_addr, length);
diff --git a/lite_translator/include/berberis/lite_translator/lite_translate_region.h b/lite_translator/include/berberis/lite_translator/lite_translate_region.h
index 9de2fdae..6e23617b 100644
--- a/lite_translator/include/berberis/lite_translator/lite_translate_region.h
+++ b/lite_translator/include/berberis/lite_translator/lite_translate_region.h
@@ -28,6 +28,7 @@
 namespace berberis {
 
 struct LiteTranslateParams {
+  GuestAddr end_pc = GetGuestAddrRangeEnd();
   bool allow_dispatch = true;
   bool enable_reg_mapping = true;
   bool enable_self_profiling = false;
@@ -37,10 +38,6 @@ struct LiteTranslateParams {
       AsHostCode(berberis::berberis_entry_HandleLiteCounterThresholdReached);
 };
 
-bool LiteTranslateRange(GuestAddr start_pc,
-                        GuestAddr end_pc,
-                        MachineCode* machine_code,
-                        LiteTranslateParams params);
 std::tuple<bool, GuestAddr> TryLiteTranslateRegion(GuestAddr start_pc,
                                                    MachineCode* machine_code,
                                                    LiteTranslateParams params);
diff --git a/lite_translator/riscv64_to_x86_64/inline_intrinsic.h b/lite_translator/riscv64_to_x86_64/inline_intrinsic.h
index 04896728..2d581b60 100644
--- a/lite_translator/riscv64_to_x86_64/inline_intrinsic.h
+++ b/lite_translator/riscv64_to_x86_64/inline_intrinsic.h
@@ -205,9 +205,9 @@ class TryBindingBasedInlineIntrinsic {
             typename Result,
             typename Callback,
             typename... Args>
-  friend Result intrinsics::bindings::ProcessBindings(Callback callback,
-                                                      Result def_result,
-                                                      Args&&... args);
+  friend constexpr Result intrinsics::bindings::ProcessBindings(Callback callback,
+                                                                Result def_result,
+                                                                Args&&... args);
   template <auto kIntrinsicTemplateName,
             auto kMacroInstructionTemplateName,
             auto kMnemo,
@@ -249,19 +249,19 @@ class TryBindingBasedInlineIntrinsic {
     using CPUIDRestriction = AsmCallInfo::CPUIDRestriction;
     if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasAVX>) {
       if (!host_platform::kHasAVX) {
-        return false;
+        return {};
       }
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasBMI>) {
       if (!host_platform::kHasBMI) {
-        return false;
+        return {};
       }
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasLZCNT>) {
       if (!host_platform::kHasLZCNT) {
-        return false;
+        return {};
       }
     } else if constexpr (std::is_same_v<CPUIDRestriction, intrinsics::bindings::HasPOPCNT>) {
       if (!host_platform::kHasPOPCNT) {
-        return false;
+        return {};
       }
     } else if constexpr (std::is_same_v<CPUIDRestriction,
                                         intrinsics::bindings::NoCPUIDRestriction>) {
diff --git a/lite_translator/riscv64_to_x86_64/lite_translate_insn_exec_tests.cc b/lite_translator/riscv64_to_x86_64/lite_translate_insn_exec_tests.cc
index d9146e15..b7fea4f4 100644
--- a/lite_translator/riscv64_to_x86_64/lite_translate_insn_exec_tests.cc
+++ b/lite_translator/riscv64_to_x86_64/lite_translate_insn_exec_tests.cc
@@ -35,20 +35,22 @@ namespace berberis {
 namespace {
 
 template <uint8_t kInsnSize = 4>
-bool RunOneInstruction(ThreadState* state, GuestAddr stop_pc) {
+bool RunOneInstruction(ThreadState* state, GuestAddr expected_stop_addr) {
   MachineCode machine_code;
-  bool success = LiteTranslateRange(state->cpu.insn_addr,
-                                    state->cpu.insn_addr + kInsnSize,
-                                    &machine_code,
-                                    LiteTranslateParams{.allow_dispatch = false});
+  auto [success, stop_pc] = TryLiteTranslateRegion(state->cpu.insn_addr,
+                                                   &machine_code,
+                                                   LiteTranslateParams{
+                                                       .end_pc = state->cpu.insn_addr + kInsnSize,
+                                                       .allow_dispatch = false,
+                                                   });
 
-  if (!success) {
+  if (!success || (stop_pc > state->cpu.insn_addr + kInsnSize)) {
     return false;
   }
 
   ScopedExecRegion exec(&machine_code);
 
-  TestingRunGeneratedCode(state, exec.get(), stop_pc);
+  TestingRunGeneratedCode(state, exec.get(), expected_stop_addr);
   return true;
 }
 
diff --git a/lite_translator/riscv64_to_x86_64/lite_translate_region.cc b/lite_translator/riscv64_to_x86_64/lite_translate_region.cc
index 5ccb80b9..a3ea3fc5 100644
--- a/lite_translator/riscv64_to_x86_64/lite_translate_region.cc
+++ b/lite_translator/riscv64_to_x86_64/lite_translate_region.cc
@@ -56,15 +56,16 @@ void GenIncrementProfileCounter(x86_64::Assembler* as, const LiteTranslateParams
   as->Jcc(x86_64::Assembler::Condition::kGreater, params.counter_threshold_callback);
 }
 
+}  // namespace
+
 // Returns the success status and
 // - in case of success, the pc of the next instruction past the translated region
 // - in case of failure, the pc of the failed instruction
 // Specifically, returnes input pc if we cannot translate even the first instruction.
-std::tuple<bool, GuestAddr> TryLiteTranslateRegionImpl(GuestAddr start_pc,
-                                                       GuestAddr end_pc,
-                                                       MachineCode* machine_code,
-                                                       LiteTranslateParams params) {
-  CHECK_LT(start_pc, end_pc);
+std::tuple<bool, GuestAddr> TryLiteTranslateRegion(GuestAddr start_pc,
+                                                   MachineCode* machine_code,
+                                                   LiteTranslateParams params) {
+  CHECK_LT(start_pc, params.end_pc);
   LiteTranslator translator(machine_code, start_pc, params);
   SemanticsPlayer sem_player(&translator);
   Decoder decoder(&sem_player);
@@ -73,7 +74,7 @@ std::tuple<bool, GuestAddr> TryLiteTranslateRegionImpl(GuestAddr start_pc,
     GenIncrementProfileCounter(translator.as(), params);
   }
 
-  while (translator.GetInsnAddr() != end_pc && !translator.is_region_end_reached()) {
+  while (translator.GetInsnAddr() < params.end_pc && !translator.is_region_end_reached()) {
     uint8_t insn_size = decoder.Decode(ToHostAddr<const uint16_t>(translator.GetInsnAddr()));
     if (!translator.success()) {
       return {false, translator.GetInsnAddr()};
@@ -87,23 +88,4 @@ std::tuple<bool, GuestAddr> TryLiteTranslateRegionImpl(GuestAddr start_pc,
   return {translator.success(), translator.GetInsnAddr()};
 }
 
-}  // namespace
-
-bool LiteTranslateRange(GuestAddr start_pc,
-                        GuestAddr end_pc,
-                        MachineCode* machine_code,
-                        LiteTranslateParams params) {
-  auto [success, stop_pc] = TryLiteTranslateRegionImpl(start_pc, end_pc, machine_code, params);
-  return success;
-}
-
-std::tuple<bool, GuestAddr> TryLiteTranslateRegion(GuestAddr start_pc,
-                                                   MachineCode* machine_code,
-                                                   LiteTranslateParams params) {
-  // This effectively makes translating code at max guest address impossible, but we
-  // assume that it's not practically significant.
-  return TryLiteTranslateRegionImpl(
-      start_pc, std::numeric_limits<GuestAddr>::max(), machine_code, params);
-}
-
 }  // namespace berberis
diff --git a/lite_translator/riscv64_to_x86_64/lite_translate_region_exec_tests.cc b/lite_translator/riscv64_to_x86_64/lite_translate_region_exec_tests.cc
index 86bc665b..699e05cd 100644
--- a/lite_translator/riscv64_to_x86_64/lite_translate_region_exec_tests.cc
+++ b/lite_translator/riscv64_to_x86_64/lite_translate_region_exec_tests.cc
@@ -44,12 +44,14 @@ class Riscv64LiteTranslateRegionTest : public ::testing::Test {
     Reset(code);
     GuestAddr code_end = ToGuestAddr(bit_cast<char*>(&code[0]) + sizeof(code));
     MachineCode machine_code;
-    bool success = LiteTranslateRange(state_.cpu.insn_addr,
-                                      code_end,
-                                      &machine_code,
-                                      LiteTranslateParams{.allow_dispatch = false});
-
-    if (!success) {
+    auto [success, stop_pc] = TryLiteTranslateRegion(state_.cpu.insn_addr,
+                                                     &machine_code,
+                                                     LiteTranslateParams{
+                                                         .end_pc = code_end,
+                                                         .allow_dispatch = false,
+                                                     });
+
+    if (!success || (stop_pc > code_end)) {
       return false;
     }
 
@@ -116,10 +118,14 @@ TEST_F(Riscv64LiteTranslateRegionTest, GracefulFailure) {
       0x00000073,  // ecall #0x0
   };
   MachineCode machine_code;
-  EXPECT_FALSE(LiteTranslateRange(ToGuestAddr(code),
-                                  ToGuestAddr(code) + 8,
-                                  &machine_code,
-                                  LiteTranslateParams{.allow_dispatch = false}));
+  auto [success, stop_pc] = TryLiteTranslateRegion(ToGuestAddr(code),
+                                                   &machine_code,
+                                                   LiteTranslateParams{
+                                                       .end_pc = ToGuestAddr(code) + 8,
+                                                       .allow_dispatch = false,
+                                                   });
+  EXPECT_FALSE(success);
+  EXPECT_EQ(stop_pc, ToGuestAddr(code) + 4);
 }
 
 jmp_buf g_jmp_buf;
@@ -150,17 +156,18 @@ TEST_F(Riscv64LiteTranslateRegionTest, ProfileCounter) {
   MachineCode machine_code;
   uint32_t counter;
   constexpr uint32_t kCounterThreshold = 42;
-  bool success = LiteTranslateRange(
+  auto [success, stop_pc] = TryLiteTranslateRegion(
       ToGuestAddr(code),
-      code_end,
       &machine_code,
       {
+          .end_pc = code_end,
           .enable_self_profiling = true,
           .counter_location = &counter,
           .counter_threshold = kCounterThreshold,
           .counter_threshold_callback = reinterpret_cast<const void*>(CounterThresholdReached),
       });
   ASSERT_TRUE(success);
+  ASSERT_EQ(stop_pc, code_end);
 
   ScopedExecRegion exec(&machine_code);
 
diff --git a/native_bridge/native_bridge.cc b/native_bridge/native_bridge.cc
index e2266d0b..dcabb4a8 100644
--- a/native_bridge/native_bridge.cc
+++ b/native_bridge/native_bridge.cc
@@ -47,7 +47,7 @@
 #include "berberis/runtime/berberis.h"
 #include "berberis/runtime_primitives/known_guest_function_wrapper.h"
 
-#define LOG_NB ALOGV  // redefine to ALOGD for debugging
+#define LOG_NB TRACE
 
 extern "C" {
 
@@ -89,7 +89,7 @@ namespace {
 // (deprecated methods do not work anymore) v2 support is needed to have NB call
 // getSignalHandler function.
 const constexpr uint32_t kNativeBridgeCallbackMinVersion = 2;
-const constexpr uint32_t kNativeBridgeCallbackVersion = 7;
+const constexpr uint32_t kNativeBridgeCallbackVersion = 8;
 const constexpr uint32_t kNativeBridgeCallbackMaxVersion = kNativeBridgeCallbackVersion;
 
 const android::NativeBridgeRuntimeCallbacks* g_runtime_callbacks = nullptr;
@@ -486,6 +486,7 @@ void* native_bridge_getTrampolineForFunctionPointer(const void* method,
 
   auto guest_addr = berberis::ToGuestAddr(method);
   if (!berberis::GuestMapShadow::GetInstance()->IsExecutable(guest_addr, 1)) {
+    LOG_NB("Not executable method - assuming it's a host library");
     // This is not guest code - happens when native_bridge falls back
     // to host libraries.
     return const_cast<void*>(method);
@@ -498,6 +499,13 @@ void* native_bridge_getTrampolineForFunctionPointer(const void* method,
       jni_call_type != android::JNICallType::kJNICallTypeCriticalNative));
 }
 
+bool native_bridge_isNativeBridgeFunctionPointer(const void* method) {
+  bool result =
+      berberis::GuestMapShadow::GetInstance()->IsExecutable(berberis::ToGuestAddr(method), 1);
+  LOG_NB("native_bridge_isNativeBridgeFunctionPointer(method=%p): %d", method, result);
+  return result;
+}
+
 void* native_bridge_getTrampoline(void* handle,
                                   const char* name,
                                   const char* shorty,
@@ -656,5 +664,6 @@ android::NativeBridgeCallbacks NativeBridgeItf = {
     &native_bridge_preZygoteFork,
     &native_bridge_getTrampolineWithJNICallType,
     &native_bridge_getTrampolineForFunctionPointer,
+    &native_bridge_isNativeBridgeFunctionPointer,
 };
 }  // extern "C"
diff --git a/native_bridge/native_bridge.h b/native_bridge/native_bridge.h
index 83b8dea8..840b029d 100644
--- a/native_bridge/native_bridge.h
+++ b/native_bridge/native_bridge.h
@@ -274,7 +274,7 @@ struct NativeBridgeCallbacks {
   // Get a native bridge trampoline for specified native method pointer.
   //
   // Parameters:
-  //   method [IN] pointer to method (ususally registered via call to RegisterNatives)
+  //   method [IN] pointer to method (usually registered via call to RegisterNatives)
   //   shorty [IN] short descriptor of native method
   //   len [IN] length of shorty
   //   jni_call_type [IN] the type of JNI call
@@ -284,6 +284,20 @@ struct NativeBridgeCallbacks {
                                            const char* shorty,
                                            uint32_t len,
                                            enum JNICallType jni_call_type);
+
+  // v8
+
+  // Check if the method pointer is executable with native_bridge.
+  //
+  // Parameters:
+  //   method [IN] pointer to a method implementation.
+  //
+  // Returns:
+  //   true if the method is in native bridge implementation executable address
+  //   space or in other words needs a trampoline to be able to run with native bridge.
+  //
+  // Introduced in: version 8
+  bool (*isNativeBridgeFunctionPointer)(const void* method);
 };
 
 // Runtime interfaces to native bridge.
diff --git a/runtime/riscv64/Android.bp b/runtime/riscv64/Android.bp
index 0685d68e..c803476e 100644
--- a/runtime/riscv64/Android.bp
+++ b/runtime/riscv64/Android.bp
@@ -71,6 +71,7 @@ cc_test_library {
                 "translator_x86_64_test.cc",
             ],
             header_libs: [
+                "berberis_test_utils_headers",
                 "libberberis_lite_translator_headers",
             ],
         },
diff --git a/runtime/riscv64/translator_x86_64.cc b/runtime/riscv64/translator_x86_64.cc
index 3be45f80..516c45d0 100644
--- a/runtime/riscv64/translator_x86_64.cc
+++ b/runtime/riscv64/translator_x86_64.cc
@@ -15,6 +15,7 @@
  */
 
 #include "translator_x86_64.h"
+#include "berberis/base/config.h"  // kGuestPageSize;
 #include "berberis/runtime/translator.h"
 #include "translator.h"
 
@@ -89,6 +90,16 @@ enum class TranslationGear {
   kSecond,
 };
 
+size_t GetExecutableRegionSize(GuestAddr pc) {
+  // With kGuestPageSize=4k we scan at least 1k instructions, which should be enough for a single
+  // region.
+  auto [is_exec, exec_size] =
+      GuestMapShadow::GetInstance()->GetExecutableRegionSize(pc, config::kGuestPageSize);
+  // Must be called on pc which is already proven to be executable.
+  CHECK(is_exec);
+  return exec_size;
+}
+
 }  // namespace
 
 void InitTranslatorArch() {
@@ -98,9 +109,10 @@ void InitTranslatorArch() {
 // Exported for testing only.
 std::tuple<bool, HostCodePiece, size_t, GuestCodeEntry::Kind> TryLiteTranslateAndInstallRegion(
     GuestAddr pc,
-    const LiteTranslateParams& params) {
+    LiteTranslateParams params) {
   MachineCode machine_code;
 
+  params.end_pc = pc + GetExecutableRegionSize(pc);
   auto [success, stop_pc] = TryLiteTranslateRegion(pc, &machine_code, params);
 
   size_t size = stop_pc - pc;
@@ -115,8 +127,10 @@ std::tuple<bool, HostCodePiece, size_t, GuestCodeEntry::Kind> TryLiteTranslateAn
   }
 
   MachineCode another_machine_code;
-  success = LiteTranslateRange(pc, stop_pc, &another_machine_code, params);
+  params.end_pc = stop_pc;
+  std::tie(success, stop_pc) = TryLiteTranslateRegion(pc, &another_machine_code, params);
   CHECK(success);
+  CHECK_EQ(stop_pc, params.end_pc);
 
   return {true,
           InstallTranslated(&another_machine_code, pc, size, "lite_range"),
@@ -128,13 +142,9 @@ std::tuple<bool, HostCodePiece, size_t, GuestCodeEntry::Kind> TryLiteTranslateAn
 std::tuple<bool, HostCodePiece, size_t, GuestCodeEntry::Kind> HeavyOptimizeRegion(GuestAddr pc) {
   MachineCode machine_code;
   auto [stop_pc, success, unused_number_of_processed_instructions] =
-      HeavyOptimizeRegion(pc, &machine_code);
+      HeavyOptimizeRegion(pc, &machine_code, {.end_pc = pc + GetExecutableRegionSize(pc)});
   size_t size = stop_pc - pc;
-  if (success) {
-    return {true, InstallTranslated(&machine_code, pc, size, "heavy"), size, kHeavyOptimized};
-  }
-
-  if (size == 0) {
+  if (!success && (size == 0)) {
     // Cannot translate even single instruction - the attempt failed.
     return {false, {}, 0, {}};
   }
@@ -215,19 +225,6 @@ void TranslateRegion(GuestAddr pc) {
     LOG_ALWAYS_FATAL("Unsupported translation mode %u", g_translation_mode);
   }
 
-  // Now that we know the size of the translated block, make sure the entire memory block has
-  // executable permission before saving it to the cache.
-  // TODO(b/232598137): installing kEntryNoExec for the *current* pc is completely incorrect as
-  // we've checked that it's executable above. The straightforward thing to do would be to
-  // check executability of each instruction while translating, and generating signal raise
-  // for non-executable ones. This handles the case when region contains conditional branch
-  // to non-executable code.
-  if (!guest_map_shadow->IsExecutable(pc, size)) {
-    TRACE("setting partly executable region at [0x%zx, 0x%zx) as not executable!", pc, pc + size);
-    cache->SetTranslatedAndUnlock(pc, entry, size, kSpecialHandler, {kEntryNoExec, 0});
-    return;
-  }
-
   cache->SetTranslatedAndUnlock(pc, entry, size, kind, host_code_piece);
 }
 
diff --git a/runtime/riscv64/translator_x86_64.h b/runtime/riscv64/translator_x86_64.h
index b7f01a0f..57e5adda 100644
--- a/runtime/riscv64/translator_x86_64.h
+++ b/runtime/riscv64/translator_x86_64.h
@@ -29,7 +29,7 @@ namespace berberis {
 
 std::tuple<bool, HostCodePiece, size_t, GuestCodeEntry::Kind> TryLiteTranslateAndInstallRegion(
     GuestAddr pc,
-    const LiteTranslateParams& params = LiteTranslateParams());
+    LiteTranslateParams params = LiteTranslateParams());
 std::tuple<bool, HostCodePiece, size_t, GuestCodeEntry::Kind> HeavyOptimizeRegion(GuestAddr pc);
 
 }  // namespace berberis
diff --git a/runtime/riscv64/translator_x86_64_test.cc b/runtime/riscv64/translator_x86_64_test.cc
index 852abd45..b8f85fda 100644
--- a/runtime/riscv64/translator_x86_64_test.cc
+++ b/runtime/riscv64/translator_x86_64_test.cc
@@ -16,8 +16,11 @@
 
 #include "gtest/gtest.h"
 
+#include "berberis/guest_os_primitives/guest_map_shadow.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/runtime_primitives/translation_cache.h"
+#include "berberis/test_utils/scoped_guest_exec_region.h"
+#include "berberis/test_utils/translation_test.h"
 
 #include "translator_x86_64.h"
 
@@ -25,11 +28,14 @@ namespace berberis {
 
 namespace {
 
-TEST(TranslatorRiscv64ToX86_64, LiteTranslateSupportedRegion) {
+class TranslatorRiscv64ToX86_64 : public TranslationTest {};
+
+TEST_F(TranslatorRiscv64ToX86_64, LiteTranslateSupportedRegion) {
   static const uint32_t code[] = {
       0x002081b3,  // add x3, x1, x2
       0x008000ef,  // jal x1, 8
   };
+  ScopedGuestExecRegion exec_region(ToGuestAddr(code), sizeof(code));
 
   auto [success, host_code_piece, guest_size, kind] =
       TryLiteTranslateAndInstallRegion(ToGuestAddr(code));
@@ -41,10 +47,11 @@ TEST(TranslatorRiscv64ToX86_64, LiteTranslateSupportedRegion) {
   EXPECT_EQ(kind, GuestCodeEntry::Kind::kLiteTranslated);
 }
 
-TEST(TranslatorRiscv64ToX86_64, LiteTranslateUnsupportedRegion) {
+TEST_F(TranslatorRiscv64ToX86_64, LiteTranslateUnsupportedRegion) {
   static const uint32_t code[] = {
       0x00000073,  // ecall #0x0
   };
+  ScopedGuestExecRegion exec_region(ToGuestAddr(code), sizeof(code));
 
   auto [success, host_code_piece, guest_size, kind] =
       TryLiteTranslateAndInstallRegion(ToGuestAddr(code));
@@ -52,11 +59,12 @@ TEST(TranslatorRiscv64ToX86_64, LiteTranslateUnsupportedRegion) {
   EXPECT_FALSE(success);
 }
 
-TEST(TranslatorRiscv64ToX86_64, LiteTranslatePartiallySupportedRegion) {
+TEST_F(TranslatorRiscv64ToX86_64, LiteTranslatePartiallySupportedRegion) {
   static const uint32_t code[] = {
       0x002081b3,  // add x3, x1, x2
       0x00000073,  // ecall #0x0
   };
+  ScopedGuestExecRegion exec_region(ToGuestAddr(code), sizeof(code));
 
   auto [success, host_code_piece, guest_size, kind] =
       TryLiteTranslateAndInstallRegion(ToGuestAddr(code));
@@ -68,10 +76,11 @@ TEST(TranslatorRiscv64ToX86_64, LiteTranslatePartiallySupportedRegion) {
   EXPECT_EQ(kind, GuestCodeEntry::Kind::kLiteTranslated);
 }
 
-TEST(TranslatorRiscv64ToX86_64, HeavyOptimizeSupportedRegion) {
+TEST_F(TranslatorRiscv64ToX86_64, HeavyOptimizeSupportedRegion) {
   static const uint32_t code[] = {
       0x008000ef,  // jal x1, 8
   };
+  ScopedGuestExecRegion exec_region(ToGuestAddr(code), sizeof(code));
 
   auto [success, host_code_piece, guest_size, kind] = HeavyOptimizeRegion(ToGuestAddr(code));
 
@@ -82,10 +91,11 @@ TEST(TranslatorRiscv64ToX86_64, HeavyOptimizeSupportedRegion) {
   EXPECT_EQ(kind, GuestCodeEntry::Kind::kHeavyOptimized);
 }
 
-TEST(TranslatorRiscv64ToX86_64, HeavyOptimizeUnsupportedRegion) {
+TEST_F(TranslatorRiscv64ToX86_64, HeavyOptimizeUnsupportedRegion) {
   static const uint32_t code[] = {
       0x0000100f,  // fence.i
   };
+  ScopedGuestExecRegion exec_region(ToGuestAddr(code), sizeof(code));
 
   auto [success, host_code_piece, guest_size, kind] = HeavyOptimizeRegion(ToGuestAddr(code));
 
diff --git a/runtime_primitives/Android.bp b/runtime_primitives/Android.bp
index b9c85190..86820c1f 100644
--- a/runtime_primitives/Android.bp
+++ b/runtime_primitives/Android.bp
@@ -128,6 +128,7 @@ cc_test_library {
     srcs: [
         "code_pool_test.cc",
         "exec_region_anonymous_test.cc",
+        "guest_code_region_test.cc",
         "signal_queue_test.cc",
         "table_of_tables_test.cc",
     ],
diff --git a/runtime_primitives/code_pool.cc b/runtime_primitives/code_pool.cc
index fb6fcf1a..6ca7a50b 100644
--- a/runtime_primitives/code_pool.cc
+++ b/runtime_primitives/code_pool.cc
@@ -41,6 +41,7 @@ void* DataPool::AddRaw(const void* ptr, uint32_t size) {
 
 void ResetAllExecRegions() {
   GetDefaultCodePoolInstance()->ResetExecRegion();
+  GetColdCodePoolInstance()->ResetExecRegion();
   GetFunctionWrapperCodePoolInstance()->ResetExecRegion();
 }
 
@@ -49,6 +50,11 @@ CodePool<ExecRegionAnonymousFactory>* GetDefaultCodePoolInstance() {
   return g_code_pool;
 }
 
+CodePool<ExecRegionAnonymousFactory>* GetColdCodePoolInstance() {
+  static auto* g_cold_code_pool = NewForever<CodePool<ExecRegionAnonymousFactory>>();
+  return g_cold_code_pool;
+}
+
 #if defined(__BIONIC__)
 CodePool<ExecRegionElfBackedFactory>* GetFunctionWrapperCodePoolInstance() {
   static auto* g_code_pool = NewForever<CodePool<ExecRegionElfBackedFactory>>();
diff --git a/runtime_primitives/crash_reporter.cc b/runtime_primitives/crash_reporter.cc
index 1dfb38fa..b3756fe8 100644
--- a/runtime_primitives/crash_reporter.cc
+++ b/runtime_primitives/crash_reporter.cc
@@ -31,27 +31,30 @@ namespace {
 
 struct sigaction g_orig_action[NSIG];
 
+}  // namespace
+
 void HandleFatalSignal(int sig, siginfo_t* info, void* context) {
-  TRACE("fatal signal %d", sig);
+  TRACE("Fatal signal %d", sig);
 
   OnCrash(sig, info, context);
 
-  // Let default crash reporter do the job.
-  // Restore original signal action, as default crash reporter can re-raise the signal.
+  // Let the default crash reporter do the job. Restore the original signal action, as the default
+  // crash reporter can re-raise the signal.
   sigaction(sig, &g_orig_action[sig], nullptr);
   if (g_orig_action[sig].sa_flags & SA_SIGINFO) {
-    // Run original signal action manually and provide actual siginfo and context.
+    // Run the original signal action manually and provide actual siginfo and context.
     g_orig_action[sig].sa_sigaction(sig, info, context);
   } else {
-    // This should be rare as debuggerd sets siginfo handlers for most signals!
-    // Original action doesn't accept siginfo and context :(
-    // Re-raise the signal as accurate as possible and hope for the best.
+    // This should be rare as debuggerd sets siginfo handlers for most signals. The original action
+    // doesn't accept siginfo and context, so we re-raise the signal as accurate as possible and
+    // hope for the best. If the signal is currently blocked we'll need to return from this handler
+    // for the signal to be delivered.
+    // TODO(b/232598137): Since the action doesn't accept siginfo it'll be ignored anyway, so
+    // maybe we should just call g_orig_action[sig].sa_handler(sig) for immediate delivery.
     syscall(SYS_rt_tgsigqueueinfo, GetpidSyscall(), GettidSyscall(), sig, info);
   }
 }
 
-}  // namespace
-
 void InitCrashReporter() {
   struct sigaction action {};
   action.sa_sigaction = HandleFatalSignal;
diff --git a/runtime_primitives/guest_code_region_test.cc b/runtime_primitives/guest_code_region_test.cc
new file mode 100644
index 00000000..367dc030
--- /dev/null
+++ b/runtime_primitives/guest_code_region_test.cc
@@ -0,0 +1,287 @@
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
+#include "gmock/gmock.h"
+#include "gtest/gtest.h"
+
+#include "berberis/runtime_primitives/guest_code_region.h"
+
+namespace berberis {
+
+namespace {
+
+using testing::ElementsAre;
+
+TEST(GuestCodeRegion, Smoke) {
+  Arena arena;
+  GuestCodeRegion region(&arena);
+
+  EXPECT_TRUE(region.branch_targets().empty());
+
+  {
+    // 42 - 50 ->{8, 100}
+    auto* bb = region.NewBasicBlock(42, 8, ArenaVector<GuestAddr>({8, 100}, &arena));
+    EXPECT_EQ(bb->start_addr(), 42u);
+    EXPECT_EQ(bb->size(), 8u);
+    EXPECT_EQ(bb->end_addr(), 50u);
+    EXPECT_THAT(bb->out_edges(), ElementsAre(8, 100));
+    EXPECT_TRUE(bb->in_edges().empty());
+  }
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 100));
+
+  {
+    // 56 - 60 -> {42, 120}
+    auto* bb = region.NewBasicBlock(56, 4, ArenaVector<GuestAddr>({42, 50}, &arena));
+    EXPECT_EQ(bb->start_addr(), 56u);
+    EXPECT_EQ(bb->size(), 4u);
+    EXPECT_EQ(bb->end_addr(), 60u);
+    EXPECT_THAT(bb->out_edges(), ElementsAre(42, 50));
+    EXPECT_TRUE(bb->in_edges().empty());
+  }
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 42, 50, 100));
+
+  region.ResolveEdges();
+
+  auto& basic_blocks = region.basic_blocks();
+
+  EXPECT_EQ(basic_blocks.size(), 2u);
+
+  ASSERT_TRUE(basic_blocks.contains(42));
+  ASSERT_TRUE(basic_blocks.contains(56));
+
+  {
+    auto& bb = basic_blocks.at(42);
+    EXPECT_THAT(bb.in_edges(), ElementsAre(56));
+  }
+
+  {
+    auto& bb = basic_blocks.at(56);
+    EXPECT_TRUE(bb.in_edges().empty());
+  }
+}
+
+TEST(GuestCodeRegion, ResolveEdges) {
+  Arena arena;
+  GuestCodeRegion region(&arena);
+
+  // 42 - 54
+  region.NewBasicBlock(42, 12, ArenaVector<GuestAddr>({100, 150, 200}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(100, 150, 200));
+
+  // 100 - 120
+  region.NewBasicBlock(100, 20, ArenaVector<GuestAddr>({8, 200, 1000}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 100, 150, 200, 1000));
+
+  // 200 - 240
+  region.NewBasicBlock(200, 40, ArenaVector<GuestAddr>({80, 120}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 80, 100, 120, 150, 200, 1000));
+
+  region.ResolveEdges();
+
+  auto& basic_blocks = region.basic_blocks();
+  ASSERT_EQ(basic_blocks.size(), 3u);
+  ASSERT_TRUE(basic_blocks.contains(42));
+  ASSERT_TRUE(basic_blocks.contains(100));
+  ASSERT_TRUE(basic_blocks.contains(200));
+
+  {
+    auto bb = basic_blocks.at(42);
+    EXPECT_TRUE(bb.in_edges().empty());
+  }
+
+  {
+    auto bb = basic_blocks.at(100);
+    EXPECT_THAT(bb.in_edges(), ElementsAre(42));
+  }
+
+  {
+    auto bb = basic_blocks.at(200);
+    EXPECT_THAT(bb.in_edges(), ElementsAre(42, 100));
+  }
+}
+
+TEST(GuestCodeRegion, SplitBasicBlock) {
+  Arena arena;
+  GuestCodeRegion region(&arena);
+
+  // 42 - 54
+  region.NewBasicBlock(42, 12, ArenaVector<GuestAddr>({110, 150, 220}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(110, 150, 220));
+
+  // 100 - 120
+  region.NewBasicBlock(100, 20, ArenaVector<GuestAddr>({8, 50, 1000}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 50, 110, 150, 220, 1000));
+
+  // 200 - 240
+  region.NewBasicBlock(200, 40, ArenaVector<GuestAddr>({80, 120, 240}, &arena));
+
+  EXPECT_THAT(region.branch_targets(), ElementsAre(8, 50, 80, 110, 120, 150, 220, 240, 1000));
+
+  // 240 - 250
+  region.NewBasicBlock(240, 50, ArenaVector<GuestAddr>({10, 210, 230}, &arena));
+
+  EXPECT_THAT(region.branch_targets(),
+              ElementsAre(8, 10, 50, 80, 110, 120, 150, 210, 220, 230, 240, 1000));
+
+  region.ResolveEdges();
+
+  auto& basic_blocks = region.basic_blocks();
+  ASSERT_EQ(basic_blocks.size(), 9u);
+  ASSERT_TRUE(basic_blocks.contains(42));
+  ASSERT_TRUE(basic_blocks.contains(50));
+  ASSERT_TRUE(basic_blocks.contains(100));
+  ASSERT_TRUE(basic_blocks.contains(110));
+  ASSERT_TRUE(basic_blocks.contains(200));
+  ASSERT_TRUE(basic_blocks.contains(210));
+  ASSERT_TRUE(basic_blocks.contains(220));
+  ASSERT_TRUE(basic_blocks.contains(230));
+  ASSERT_TRUE(basic_blocks.contains(240));
+
+  {
+    auto bb = basic_blocks.at(42);
+    EXPECT_EQ(bb.start_addr(), 42u);
+    EXPECT_EQ(bb.size(), 8u);
+    EXPECT_EQ(bb.end_addr(), 50u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(50));
+    EXPECT_TRUE(bb.in_edges().empty());
+  }
+
+  {
+    auto bb = basic_blocks.at(50);
+    EXPECT_EQ(bb.start_addr(), 50u);
+    EXPECT_EQ(bb.size(), 4u);
+    EXPECT_EQ(bb.end_addr(), 54u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(110, 150, 220));
+    EXPECT_THAT(bb.in_edges(), ElementsAre(42, 110));
+  }
+
+  {
+    auto bb = basic_blocks.at(100);
+    EXPECT_EQ(bb.start_addr(), 100u);
+    EXPECT_EQ(bb.size(), 10u);
+    EXPECT_EQ(bb.end_addr(), 110u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(110));
+    EXPECT_TRUE(bb.in_edges().empty());
+  }
+
+  {
+    auto bb = basic_blocks.at(110);
+    EXPECT_EQ(bb.start_addr(), 110u);
+    EXPECT_EQ(bb.size(), 10u);
+    EXPECT_EQ(bb.end_addr(), 120u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(8, 50, 1000));
+    EXPECT_THAT(bb.in_edges(), ElementsAre(50, 100));
+  }
+
+  {
+    auto bb = basic_blocks.at(200);
+    EXPECT_EQ(bb.start_addr(), 200u);
+    EXPECT_EQ(bb.size(), 10u);
+    EXPECT_EQ(bb.end_addr(), 210u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(210));
+    EXPECT_TRUE(bb.in_edges().empty());
+  }
+
+  {
+    auto bb = basic_blocks.at(210);
+    EXPECT_EQ(bb.start_addr(), 210u);
+    EXPECT_EQ(bb.size(), 10u);
+    EXPECT_EQ(bb.end_addr(), 220u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(220));
+    EXPECT_THAT(bb.in_edges(), ElementsAre(200, 240));
+  }
+
+  {
+    auto bb = basic_blocks.at(220);
+    EXPECT_EQ(bb.start_addr(), 220u);
+    EXPECT_EQ(bb.size(), 10u);
+    EXPECT_EQ(bb.end_addr(), 230u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(230));
+    EXPECT_THAT(bb.in_edges(), ElementsAre(50, 210));
+  }
+
+  {
+    auto bb = basic_blocks.at(230);
+    EXPECT_EQ(bb.start_addr(), 230u);
+    EXPECT_EQ(bb.size(), 10u);
+    EXPECT_EQ(bb.end_addr(), 240u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(80, 120, 240));
+    EXPECT_THAT(bb.in_edges(), ElementsAre(220, 240));
+  }
+
+  {
+    auto bb = basic_blocks.at(240);
+    EXPECT_EQ(bb.start_addr(), 240u);
+    EXPECT_EQ(bb.size(), 50u);
+    EXPECT_EQ(bb.end_addr(), 290u);
+    EXPECT_THAT(bb.out_edges(), ElementsAre(10, 210, 230));
+    EXPECT_THAT(bb.in_edges(), ElementsAre(230));
+  }
+}
+
+TEST(GuestCodeRegion, InvalidRegion) {
+  Arena arena;
+  GuestCodeRegion region(&arena);
+
+  // Overlapping code blocks are not allowed
+  region.NewBasicBlock(100, 60, ArenaVector<GuestAddr>({}, &arena));
+  region.NewBasicBlock(150, 50, ArenaVector<GuestAddr>({}, &arena));
+
+  EXPECT_DEATH(region.ResolveEdges(), "");
+}
+
+TEST(GuestCodeRegion, NoResolveEdgesTwice) {
+  Arena arena;
+  GuestCodeRegion region(&arena);
+
+  region.NewBasicBlock(100, 60, ArenaVector<GuestAddr>({}, &arena));
+
+  region.ResolveEdges();
+
+  EXPECT_DEATH(region.ResolveEdges(), "");
+}
+
+TEST(GuestCodeRegion, ResolveEdgesExpectsNoInEdges) {
+  Arena arena;
+  GuestCodeRegion region(&arena);
+
+  auto* bb = region.NewBasicBlock(100, 60, ArenaVector<GuestAddr>({}, &arena));
+  bb->AddInEdge(5);
+
+  EXPECT_DEATH(region.ResolveEdges(), "");
+}
+
+TEST(GuestCodeRegion, NoNewBasicBlockAfterResolveRegion) {
+  Arena arena;
+  GuestCodeRegion region(&arena);
+
+  region.NewBasicBlock(100, 60, ArenaVector<GuestAddr>({}, &arena));
+
+  region.ResolveEdges();
+
+  EXPECT_DEATH(region.NewBasicBlock(200, 20, ArenaVector<GuestAddr>({}, &arena)), "");
+}
+
+}  // namespace
+
+}  // namespace berberis
diff --git a/runtime_primitives/host_entries.cc b/runtime_primitives/host_entries.cc
index a01cdc87..d4a1c715 100644
--- a/runtime_primitives/host_entries.cc
+++ b/runtime_primitives/host_entries.cc
@@ -43,6 +43,7 @@ HostCodeAddr InstallEntryTrampoline(HostCode target_function_ptr) {
   x86_64::Assembler as(&mc);
   as.Jmp(target_function_ptr);
   as.Finalize();
+  // TODO(b/232598137): maybe use ColdPool?
   return GetDefaultCodePoolInstance()->Add(&mc);
 #else
   return AsHostCodeAddr(target_function_ptr);
diff --git a/runtime_primitives/host_function_wrapper_impl.cc b/runtime_primitives/host_function_wrapper_impl.cc
index a6ff50c0..8db43919 100644
--- a/runtime_primitives/host_function_wrapper_impl.cc
+++ b/runtime_primitives/host_function_wrapper_impl.cc
@@ -22,7 +22,6 @@
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/runtime_primitives/checks.h"
 #include "berberis/runtime_primitives/code_pool.h"
-#include "berberis/runtime_primitives/exec_region_anonymous.h"
 #include "berberis/runtime_primitives/host_code.h"
 #include "berberis/runtime_primitives/translation_cache.h"
 
@@ -49,8 +48,11 @@ void MakeTrampolineCallable(GuestAddr pc,
   if (entry) {
     MachineCode mc;
     GenTrampolineAdaptor(&mc, pc, AsHostCode(func), arg, name);
-    cache->SetWrappedAndUnlock(
-        pc, entry, is_host_func, {GetDefaultCodePoolInstance()->Add(&mc), mc.install_size()});
+    cache->SetWrappedAndUnlock(pc,
+                               entry,
+                               is_host_func,
+                               // TODO(b/232598137): Maybe use ColdCodePool?
+                               {GetDefaultCodePoolInstance()->Add(&mc), mc.install_size()});
   }
 }
 
diff --git a/runtime_primitives/include/berberis/runtime_primitives/code_pool.h b/runtime_primitives/include/berberis/runtime_primitives/code_pool.h
index 2f653adf..b1bc4d32 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/code_pool.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/code_pool.h
@@ -22,7 +22,9 @@
 
 #include "berberis/assembler/machine_code.h"
 #include "berberis/base/arena_alloc.h"
+#include "berberis/base/config_globals.h"
 #include "berberis/base/exec_region.h"
+#include "berberis/base/tracing.h"
 #include "berberis/runtime_primitives/exec_region_anonymous.h"
 #include "berberis/runtime_primitives/host_code.h"
 
@@ -37,7 +39,10 @@ namespace berberis {
 template <typename ExecRegionFactory>
 class CodePool {
  public:
-  CodePool() = default;
+  CodePool()
+      : exec_(ExecRegionFactory::Create(ExecRegionFactory::kExecRegionSize)),
+        current_address_{exec_.begin()},
+        detached_size_{0} {};
 
   // Not copyable or movable
   CodePool(const CodePool&) = delete;
@@ -57,6 +62,8 @@ class CodePool {
     // lite-translated regions.
     current_address_ = AlignUp(current_address_, 64);
 
+    // Note that pointer arithmetic on nullptr is undefined behavior.
+    CHECK_NE(current_address_, nullptr);
     if (exec_.end() < current_address_ + size) {
       ResetExecRegion(size);
     }
@@ -65,6 +72,11 @@ class CodePool {
     current_address_ += size;
 
     code->Install(&exec_, result, &recovery_map_);
+
+    if (IsConfigFlagSet(kPrintCodePoolSize)) {
+      TRACE("Code pool %p: new size %zu", this, GetTotalSize());
+    }
+
     return AsHostCodeAddr(result);
   }
 
@@ -78,17 +90,21 @@ class CodePool {
   }
 
   void ResetExecRegion(uint32_t size = ExecRegionFactory::kExecRegionSize) {
+    detached_size_ += exec_.size();
     exec_.Detach();
     exec_ = ExecRegionFactory::Create(std::max(size, ExecRegionFactory::kExecRegionSize));
     current_address_ = exec_.begin();
   }
 
+  size_t GetTotalSize() const { return detached_size_ + (current_address_ - exec_.begin()); }
+
  private:
   ExecRegion exec_;
-  const uint8_t* current_address_ = nullptr;
+  const uint8_t* current_address_;
   // TODO(b/232598137): have recovery map for each region instead!
   RecoveryMap recovery_map_;
   mutable std::mutex mutex_;
+  size_t detached_size_;
 };
 
 // Stored data for generated code.
@@ -116,6 +132,9 @@ void ResetAllExecRegions();
 
 // Returns default code pool.
 [[nodiscard]] CodePool<ExecRegionAnonymousFactory>* GetDefaultCodePoolInstance();
+// Use cold code pool to avoid interleaving cold code with hot code, as it induces more cache and
+// TLB misses (see go/ndkt-two-gear-overhead).
+[[nodiscard]] CodePool<ExecRegionAnonymousFactory>* GetColdCodePoolInstance();
 
 #if defined(__BIONIC__)
 [[nodiscard]] CodePool<ExecRegionElfBackedFactory>* GetFunctionWrapperCodePoolInstance();
diff --git a/runtime_primitives/include/berberis/runtime_primitives/crash_reporter.h b/runtime_primitives/include/berberis/runtime_primitives/crash_reporter.h
index 3ec1b5df..d359d519 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/crash_reporter.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/crash_reporter.h
@@ -17,9 +17,12 @@
 #ifndef BERBERIS_RUNTIME_PRIMITIVES_CRASH_REPORTER_H_
 #define BERBERIS_RUNTIME_PRIMITIVES_CRASH_REPORTER_H_
 
+#include <csignal>
+
 namespace berberis {
 
 void InitCrashReporter();
+void HandleFatalSignal(int sig, siginfo_t* info, void* context);
 
 }  // namespace berberis
 
diff --git a/runtime_primitives/include/berberis/runtime_primitives/guest_code_region.h b/runtime_primitives/include/berberis/runtime_primitives/guest_code_region.h
new file mode 100644
index 00000000..c7d3d306
--- /dev/null
+++ b/runtime_primitives/include/berberis/runtime_primitives/guest_code_region.h
@@ -0,0 +1,139 @@
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
+#ifndef BERBERIS_RUNTIME_PRIMITIVES_GUEST_CODE_REGION_H_
+#define BERBERIS_RUNTIME_PRIMITIVES_GUEST_CODE_REGION_H_
+
+#include "berberis/base/arena_alloc.h"
+#include "berberis/base/arena_map.h"
+#include "berberis/base/arena_set.h"
+#include "berberis/base/arena_vector.h"
+#include "berberis/guest_state/guest_addr.h"
+
+namespace berberis {
+
+class GuestCodeBasicBlock {
+ public:
+  explicit GuestCodeBasicBlock(Arena* arena,
+                               GuestAddr start_addr,
+                               size_t size,
+                               ArenaVector<GuestAddr> out_edges)
+      : start_addr_{start_addr}, size_{size}, in_edges_{arena}, out_edges_{std::move(out_edges)} {}
+
+  void SetOutEdges(ArenaVector<GuestAddr> out_edges) { out_edges_ = std::move(out_edges); }
+
+  void AddInEdge(GuestAddr source_addr) { in_edges_.push_back(source_addr); }
+
+  void SetSize(size_t size) { size_ = size; }
+
+  [[nodiscard]] GuestAddr start_addr() const { return start_addr_; }
+  [[nodiscard]] GuestAddr end_addr() const { return start_addr_ + size_; }
+  [[nodiscard]] size_t size() const { return size_; }
+  [[nodiscard]] const ArenaVector<GuestAddr>& out_edges() const { return out_edges_; }
+  [[nodiscard]] const ArenaVector<GuestAddr>& in_edges() const { return in_edges_; }
+
+ private:
+  const GuestAddr start_addr_;
+  size_t size_;
+  ArenaVector<GuestAddr> in_edges_;
+  ArenaVector<GuestAddr> out_edges_;
+};
+
+class GuestCodeRegion {
+ public:
+  explicit GuestCodeRegion(Arena* arena)
+      : arena_{arena}, basic_blocks_{arena}, branch_targets_{arena} {}
+
+  /* may_discard */ GuestCodeBasicBlock* NewBasicBlock(GuestAddr guest_addr,
+                                                       size_t size,
+                                                       const ArenaVector<GuestAddr>& out_edges) {
+    CHECK(!code_region_finalized_);
+    auto [it, inserted] =
+        basic_blocks_.try_emplace(guest_addr, arena_, guest_addr, size, out_edges);
+    CHECK(inserted);
+    branch_targets_.insert(out_edges.begin(), out_edges.end());
+    return &it->second;
+  }
+
+  // This method must be called only once.
+  void ResolveEdges() {
+    CHECK(!code_region_finalized_);
+    ValidateRegionBeforeFinalize();
+    SplitBasicBlocks();
+    ResolveInEdges();
+    code_region_finalized_ = true;
+  }
+
+  [[nodiscard]] const ArenaMap<GuestAddr, GuestCodeBasicBlock>& basic_blocks() const {
+    return basic_blocks_;
+  }
+
+  [[nodiscard]] const ArenaSet<GuestAddr>& branch_targets() const { return branch_targets_; }
+
+ private:
+  void SplitBasicBlocks() {
+    for (auto branch_target : branch_targets_) {
+      auto it = basic_blocks_.upper_bound(branch_target);
+      if (it == basic_blocks_.begin()) {
+        continue;
+      }
+
+      --it;
+      auto& [guest_addr, code_block] = *it;
+      if (branch_target <= guest_addr || branch_target >= code_block.end_addr()) {
+        // Nothing to split.
+        continue;
+      }
+
+      size_t updated_size = branch_target - code_block.start_addr();
+      size_t new_code_block_size = code_block.size() - updated_size;
+
+      NewBasicBlock(branch_target, new_code_block_size, code_block.out_edges());
+
+      code_block.SetSize(updated_size);
+      code_block.SetOutEdges(ArenaVector<GuestAddr>({branch_target}, arena_));
+    }
+  }
+
+  void ResolveInEdges() {
+    for (auto& [source_addr, basic_block] : basic_blocks_) {
+      for (auto target_addr : basic_block.out_edges()) {
+        auto it = basic_blocks_.find(target_addr);
+        if (it != basic_blocks_.end()) {
+          it->second.AddInEdge(source_addr);
+        }
+      }
+    }
+  }
+
+  void ValidateRegionBeforeFinalize() const {
+    GuestAddr last_seen_end_addr = kNullGuestAddr;
+    for (const auto& [start_addr, basic_block] : basic_blocks_) {
+      CHECK_GE(start_addr, last_seen_end_addr);
+      last_seen_end_addr = basic_block.end_addr();
+      CHECK(basic_block.in_edges().empty());
+    }
+  }
+
+  Arena* arena_;
+  ArenaMap<GuestAddr, GuestCodeBasicBlock> basic_blocks_;
+  ArenaSet<GuestAddr> branch_targets_;
+  bool code_region_finalized_{false};
+};
+
+}  // namespace berberis
+
+#endif  // BERBERIS_RUNTIME_PRIMITIVES_GUEST_CODE_REGION_H_
diff --git a/runtime_primitives/include/berberis/runtime_primitives/translation_cache.h b/runtime_primitives/include/berberis/runtime_primitives/translation_cache.h
index b596749f..484f942a 100644
--- a/runtime_primitives/include/berberis/runtime_primitives/translation_cache.h
+++ b/runtime_primitives/include/berberis/runtime_primitives/translation_cache.h
@@ -163,6 +163,10 @@ class TranslationCache {
   // Invalidate region of entries.
   void InvalidateGuestRange(GuestAddr start, GuestAddr end);
 
+  // Schedules gear shift translation for all lite-translated regions that are within range from
+  // target.
+  void TriggerGearShift(GuestAddr target, size_t range);
+
   [[nodiscard]] const std::atomic<std::atomic<HostCodeAddr>*>* main_table_ptr() const {
     return address_map_.main_table();
   }
diff --git a/runtime_primitives/profiler_interface.cc b/runtime_primitives/profiler_interface.cc
index e2131c05..cbafd0b6 100644
--- a/runtime_primitives/profiler_interface.cc
+++ b/runtime_primitives/profiler_interface.cc
@@ -138,17 +138,24 @@ void ProfilerLogGeneratedCode(const void* start,
 
   MappedNameBuffer mapped_name_buf = ConstructMappedNameBuffer(guest_start);
 
+  char guest_range_buf[64];
+
+  if (IsConfigFlagSet(kMergeProfilesForSameModeRegions)) {
+    guest_range_buf[0] = '\0';
+  } else {
+    FormatBuffer(guest_range_buf, sizeof(guest_range_buf), "_0x%lx+%zu", guest_start, guest_size);
+  }
+
   char buf[128];
   // start size symbol-name
   size_t n = FormatBuffer(buf,
                           sizeof(buf),
-                          "%p 0x%zx %s%s_0x%lx+%zu\n",
+                          "%p 0x%zx %s%s%s\n",
                           start,
                           size,
                           mapped_name_buf.data(),
                           jit_suffix,
-                          guest_start,
-                          guest_size);
+                          guest_range_buf);
   UNUSED(write(fd, buf, n));
 }
 
diff --git a/runtime_primitives/recovery_code.cc b/runtime_primitives/recovery_code.cc
index 4ec79542..f9006265 100644
--- a/runtime_primitives/recovery_code.cc
+++ b/runtime_primitives/recovery_code.cc
@@ -60,11 +60,16 @@ uintptr_t FindRecoveryCode(uintptr_t fault_addr, ThreadState* state) {
   // signal). If a signal interrupts CodePool::Add then calling FindRecoveryCode
   // in this state can cause deadlock.
   if (GetResidence(*state) == kInsideGeneratedCode) {
-    // TODO(b/228188293): we might need to traverse all code pool instances.
+    // TODO(b/232598137): Add an interface that we'll traverse all existing code pools, and
+    // hide these implementation details from the caller.
     recovery_addr = GetDefaultCodePoolInstance()->FindRecoveryCode(fault_addr);
     if (recovery_addr) {
       return recovery_addr;
     }
+    recovery_addr = GetColdCodePoolInstance()->FindRecoveryCode(fault_addr);
+    if (recovery_addr) {
+      return recovery_addr;
+    }
   }
   // Extra recovery code is in read-only mode after the init, so we don't need mutexes.
   // Note, that we cannot simply add extra recovery code to CodePool, since these
diff --git a/runtime_primitives/translation_cache.cc b/runtime_primitives/translation_cache.cc
index 67c858a2..72032631 100644
--- a/runtime_primitives/translation_cache.cc
+++ b/runtime_primitives/translation_cache.cc
@@ -20,7 +20,9 @@
 #include <map>
 #include <mutex>  // std::lock_guard, std::mutex
 
+#include "berberis/base/bit_util.h"
 #include "berberis/base/checks.h"
+#include "berberis/base/config.h"
 #include "berberis/base/forever_alloc.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/runtime_primitives/host_code.h"
@@ -302,4 +304,23 @@ void TranslationCache::InvalidateGuestRange(GuestAddr start, GuestAddr end) {
   }
 }
 
+void TranslationCache::TriggerGearShift(GuestAddr target, size_t range) {
+  std::lock_guard<std::mutex> lock(mutex_);
+  GuestAddr start = (target > range) ? target - range : kNullGuestAddr;
+
+  for (auto it = guest_entries_.lower_bound(start); it != guest_entries_.end(); ++it) {
+    auto& [guest_pc, entry] = *it;
+    CHECK_GT(entry.guest_size, 0);
+    if ((guest_pc > target) && ((guest_pc - target) > range)) {
+      break;
+    }
+    if (entry.kind == GuestCodeEntry::Kind::kLiteTranslated) {
+      // Lite translator may update the counter non-atomically for efficiency, but here
+      // we can be more strict.
+      auto* counter = bit_cast<std::atomic<uint32_t>*>(&entry.invocation_counter);
+      *counter = config::kGearSwitchThreshold;
+    }
+  }
+}
+
 }  // namespace berberis
diff --git a/runtime_primitives/translation_cache_test.cc b/runtime_primitives/translation_cache_test.cc
index 67c336f9..86b47c32 100644
--- a/runtime_primitives/translation_cache_test.cc
+++ b/runtime_primitives/translation_cache_test.cc
@@ -17,9 +17,11 @@
 #include "gtest/gtest.h"
 
 #include <chrono>  // chrono_literals::operator""ms
+#include <initializer_list>
 #include <string>
 #include <thread>  // this_thread::sleep_for
 
+#include "berberis/base/config.h"
 #include "berberis/guest_state/guest_addr.h"
 #include "berberis/runtime_primitives/host_code.h"
 #include "berberis/runtime_primitives/runtime_library.h"  // kEntry*
@@ -30,94 +32,90 @@ namespace berberis {
 namespace {
 
 using std::chrono_literals::operator""ms;
+// A test guest pc that is valid in both 32bit and 64bit modes.
+constexpr GuestAddr kGuestPC = 0x12345678;
 
 TEST(TranslationCacheTest, DefaultNotTranslated) {
-  constexpr GuestAddr pc = 0x12345678;
-
   TranslationCache tc;
 
-  EXPECT_EQ(tc.GetHostCodePtr(pc)->load(), kEntryNotTranslated);
-  EXPECT_EQ(tc.GetHostCodePtr(pc + 1024)->load(), kEntryNotTranslated);
-  EXPECT_EQ(tc.GetInvocationCounter(pc), 0U);
+  EXPECT_EQ(tc.GetHostCodePtr(kGuestPC)->load(), kEntryNotTranslated);
+  EXPECT_EQ(tc.GetHostCodePtr(kGuestPC + 1024)->load(), kEntryNotTranslated);
+  EXPECT_EQ(tc.GetInvocationCounter(kGuestPC), 0U);
 }
 
 TEST(TranslationCacheTest, UpdateInvocationCounter) {
-  constexpr GuestAddr pc = 0x12345678;
-
   TranslationCache tc;
 
   // Create entry
-  GuestCodeEntry* entry = tc.AddAndLockForTranslation(pc, 0);
+  GuestCodeEntry* entry = tc.AddAndLockForTranslation(kGuestPC, 0);
   ASSERT_TRUE(entry);
   EXPECT_EQ(entry->invocation_counter, 0U);
   entry->invocation_counter = 42;
-  tc.SetTranslatedAndUnlock(pc, entry, 1, GuestCodeEntry::Kind::kSpecialHandler, {kEntryNoExec, 0});
+  tc.SetTranslatedAndUnlock(
+      kGuestPC, entry, 1, GuestCodeEntry::Kind::kSpecialHandler, {kEntryNoExec, 0});
 
-  EXPECT_EQ(tc.GetInvocationCounter(pc), 42U);
+  EXPECT_EQ(tc.GetInvocationCounter(kGuestPC), 42U);
 }
 
 TEST(TranslationCacheTest, AddAndLockForTranslation) {
-  constexpr GuestAddr pc = 0x12345678;
-
   TranslationCache tc;
 
   // Cannot lock if counter is below the threshold, but entry is created anyway.
-  ASSERT_FALSE(tc.AddAndLockForTranslation(pc, 1));
-  GuestCodeEntry* entry = tc.LookupGuestCodeEntryUnsafeForTesting(pc);
+  ASSERT_FALSE(tc.AddAndLockForTranslation(kGuestPC, 1));
+  GuestCodeEntry* entry = tc.LookupGuestCodeEntryUnsafeForTesting(kGuestPC);
   ASSERT_TRUE(entry);
-  EXPECT_EQ(tc.GetHostCodePtr(pc)->load(), kEntryNotTranslated);
+  EXPECT_EQ(tc.GetHostCodePtr(kGuestPC)->load(), kEntryNotTranslated);
   EXPECT_EQ(entry->kind, GuestCodeEntry::Kind::kInterpreted);
-  EXPECT_EQ(tc.GetInvocationCounter(pc), 1U);
+  EXPECT_EQ(tc.GetInvocationCounter(kGuestPC), 1U);
 
   // Lock when counter is equal or above the threshold.
-  entry = tc.AddAndLockForTranslation(pc, 1);
+  entry = tc.AddAndLockForTranslation(kGuestPC, 1);
   ASSERT_TRUE(entry);
-  EXPECT_EQ(tc.GetHostCodePtr(pc)->load(), kEntryTranslating);
+  EXPECT_EQ(tc.GetHostCodePtr(kGuestPC)->load(), kEntryTranslating);
   EXPECT_EQ(entry->kind, GuestCodeEntry::Kind::kUnderProcessing);
-  EXPECT_EQ(tc.GetInvocationCounter(pc), 1U);
+  EXPECT_EQ(tc.GetInvocationCounter(kGuestPC), 1U);
 
   // Cannot lock locked.
-  ASSERT_FALSE(tc.AddAndLockForTranslation(pc, 0));
+  ASSERT_FALSE(tc.AddAndLockForTranslation(kGuestPC, 0));
 
   // Unlock.
-  tc.SetTranslatedAndUnlock(pc, entry, 1, GuestCodeEntry::Kind::kSpecialHandler, {kEntryNoExec, 0});
-  EXPECT_EQ(tc.GetHostCodePtr(pc)->load(), kEntryNoExec);
+  tc.SetTranslatedAndUnlock(
+      kGuestPC, entry, 1, GuestCodeEntry::Kind::kSpecialHandler, {kEntryNoExec, 0});
+  EXPECT_EQ(tc.GetHostCodePtr(kGuestPC)->load(), kEntryNoExec);
   EXPECT_EQ(entry->kind, GuestCodeEntry::Kind::kSpecialHandler);
 
   // Cannot lock translated.
-  ASSERT_FALSE(tc.AddAndLockForTranslation(pc, 0));
+  ASSERT_FALSE(tc.AddAndLockForTranslation(kGuestPC, 0));
 }
 
 constexpr bool kWrappedHostFunc = true;
 
 TEST(TranslationCacheTest, AddAndLockForWrapping) {
-  constexpr GuestAddr pc = 0x12345678;
-
   TranslationCache tc;
 
   // Add and lock nonexistent.
-  GuestCodeEntry* entry = tc.AddAndLockForWrapping(pc);
+  GuestCodeEntry* entry = tc.AddAndLockForWrapping(kGuestPC);
   ASSERT_TRUE(entry);
-  ASSERT_EQ(kEntryWrapping, tc.GetHostCodePtr(pc)->load());
+  ASSERT_EQ(kEntryWrapping, tc.GetHostCodePtr(kGuestPC)->load());
   ASSERT_EQ(entry->kind, GuestCodeEntry::Kind::kUnderProcessing);
 
   // Cannot lock locked.
-  ASSERT_FALSE(tc.AddAndLockForWrapping(pc));
+  ASSERT_FALSE(tc.AddAndLockForWrapping(kGuestPC));
 
   // Unlock.
-  tc.SetWrappedAndUnlock(pc, entry, kWrappedHostFunc, {kEntryNoExec, 0});
-  ASSERT_EQ(kEntryNoExec, tc.GetHostCodePtr(pc)->load());
+  tc.SetWrappedAndUnlock(kGuestPC, entry, kWrappedHostFunc, {kEntryNoExec, 0});
+  ASSERT_EQ(kEntryNoExec, tc.GetHostCodePtr(kGuestPC)->load());
   ASSERT_EQ(entry->kind, GuestCodeEntry::Kind::kHostWrapped);
 
   // Cannot lock wrapped.
-  ASSERT_FALSE(tc.AddAndLockForWrapping(pc));
+  ASSERT_FALSE(tc.AddAndLockForWrapping(kGuestPC));
 
   // Cannot lock not translated but already interpreted.
-  ASSERT_FALSE(tc.AddAndLockForTranslation(pc + 64, 1));
-  entry = tc.LookupGuestCodeEntryUnsafeForTesting(pc + 64);
+  ASSERT_FALSE(tc.AddAndLockForTranslation(kGuestPC + 64, 1));
+  entry = tc.LookupGuestCodeEntryUnsafeForTesting(kGuestPC + 64);
   ASSERT_TRUE(entry);
   ASSERT_EQ(entry->kind, GuestCodeEntry::Kind::kInterpreted);
-  ASSERT_FALSE(tc.AddAndLockForWrapping(pc + 64));
+  ASSERT_FALSE(tc.AddAndLockForWrapping(kGuestPC + 64));
 }
 
 HostCodeAddr kHostCodeStub = AsHostCodeAddr(AsHostCode(0xdeadbeef));
@@ -194,9 +192,8 @@ void TranslationCacheTestRunThreads() {
   }
 
   // Now introduce heavy contention.
-  GuestAddr pc = 0x12345678;
   for (auto& thread : threads) {
-    thread = std::thread(WorkerFunc, &tc, pc);
+    thread = std::thread(WorkerFunc, &tc, kGuestPC);
   }
 
   for (auto& thread : threads) {
@@ -205,77 +202,69 @@ void TranslationCacheTestRunThreads() {
 }
 
 TEST(TranslationCacheTest, InvalidateNotTranslated) {
-  constexpr GuestAddr pc = 0x12345678;
-
   TranslationCache tc;
 
-  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(pc)->load());
+  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(kGuestPC)->load());
 
-  tc.InvalidateGuestRange(pc, pc + 1);
+  tc.InvalidateGuestRange(kGuestPC, kGuestPC + 1);
 
   // Not translated stays not translated
-  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(pc)->load());
-  ASSERT_FALSE(tc.LookupGuestCodeEntryUnsafeForTesting(pc));
+  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(kGuestPC)->load());
+  ASSERT_FALSE(tc.LookupGuestCodeEntryUnsafeForTesting(kGuestPC));
 }
 
 TEST(TranslationCacheTest, InvalidateTranslated) {
-  constexpr GuestAddr pc = 0x12345678;
-  const auto host_code = AsHostCodeAddr(AsHostCode(0xdeadbeef));
-
   TranslationCache tc;
 
-  GuestCodeEntry* entry = tc.AddAndLockForTranslation(pc, 0);
+  GuestCodeEntry* entry = tc.AddAndLockForTranslation(kGuestPC, 0);
   ASSERT_TRUE(entry);
-  ASSERT_EQ(kEntryTranslating, tc.GetHostCodePtr(pc)->load());
+  ASSERT_EQ(kEntryTranslating, tc.GetHostCodePtr(kGuestPC)->load());
 
-  tc.SetTranslatedAndUnlock(pc, entry, 1, GuestCodeEntry::Kind::kHeavyOptimized, {host_code, 4});
-  ASSERT_EQ(host_code, tc.GetHostCodePtr(pc)->load());
+  tc.SetTranslatedAndUnlock(
+      kGuestPC, entry, 1, GuestCodeEntry::Kind::kHeavyOptimized, {kHostCodeStub, 4});
+  ASSERT_EQ(kHostCodeStub, tc.GetHostCodePtr(kGuestPC)->load());
 
-  tc.InvalidateGuestRange(pc, pc + 1);
+  tc.InvalidateGuestRange(kGuestPC, kGuestPC + 1);
 
-  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(pc)->load());
-  ASSERT_FALSE(tc.LookupGuestCodeEntryUnsafeForTesting(pc));
+  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(kGuestPC)->load());
+  ASSERT_FALSE(tc.LookupGuestCodeEntryUnsafeForTesting(kGuestPC));
 }
 
 TEST(TranslationCacheTest, InvalidateTranslating) {
-  constexpr GuestAddr pc = 0x12345678;
-  const auto host_code = AsHostCodeAddr(AsHostCode(0xdeadbeef));
-
   TranslationCache tc;
 
-  GuestCodeEntry* entry = tc.AddAndLockForTranslation(pc, 0);
+  GuestCodeEntry* entry = tc.AddAndLockForTranslation(kGuestPC, 0);
   ASSERT_TRUE(entry);
-  ASSERT_EQ(kEntryTranslating, tc.GetHostCodePtr(pc)->load());
+  ASSERT_EQ(kEntryTranslating, tc.GetHostCodePtr(kGuestPC)->load());
 
-  tc.InvalidateGuestRange(pc, pc + 1);
-  ASSERT_EQ(kEntryInvalidating, tc.GetHostCodePtr(pc)->load());
-  entry = tc.LookupGuestCodeEntryUnsafeForTesting(pc);
+  tc.InvalidateGuestRange(kGuestPC, kGuestPC + 1);
+  ASSERT_EQ(kEntryInvalidating, tc.GetHostCodePtr(kGuestPC)->load());
+  entry = tc.LookupGuestCodeEntryUnsafeForTesting(kGuestPC);
   ASSERT_TRUE(entry);
   ASSERT_EQ(entry->kind, GuestCodeEntry::Kind::kUnderProcessing);
 
-  tc.SetTranslatedAndUnlock(pc, entry, 1, GuestCodeEntry::Kind::kSpecialHandler, {host_code, 4});
-  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(pc)->load());
-  ASSERT_FALSE(tc.LookupGuestCodeEntryUnsafeForTesting(pc));
+  tc.SetTranslatedAndUnlock(
+      kGuestPC, entry, 1, GuestCodeEntry::Kind::kSpecialHandler, {kHostCodeStub, 4});
+  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(kGuestPC)->load());
+  ASSERT_FALSE(tc.LookupGuestCodeEntryUnsafeForTesting(kGuestPC));
 }
 
 TEST(TranslationCacheTest, InvalidateTranslatingOutOfRange) {
-  constexpr GuestAddr pc = 0x12345678;
-  const auto host_code = AsHostCodeAddr(AsHostCode(0xdeadbeef));
-
   TranslationCache tc;
 
-  GuestCodeEntry* entry = tc.AddAndLockForTranslation(pc, 0);
+  GuestCodeEntry* entry = tc.AddAndLockForTranslation(kGuestPC, 0);
   ASSERT_TRUE(entry);
-  ASSERT_EQ(kEntryTranslating, tc.GetHostCodePtr(pc)->load());
+  ASSERT_EQ(kEntryTranslating, tc.GetHostCodePtr(kGuestPC)->load());
 
   // Invalidate range that does *not* contain translating address.
   // The entry should still be invalidated, as translated region is only known after translation,
   // and it might overlap with the invalidated range.
-  tc.InvalidateGuestRange(pc + 100, pc + 101);
-  ASSERT_EQ(kEntryInvalidating, tc.GetHostCodePtr(pc)->load());
+  tc.InvalidateGuestRange(kGuestPC + 100, kGuestPC + 101);
+  ASSERT_EQ(kEntryInvalidating, tc.GetHostCodePtr(kGuestPC)->load());
 
-  tc.SetTranslatedAndUnlock(pc, entry, 1, GuestCodeEntry::Kind::kSpecialHandler, {host_code, 4});
-  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(pc)->load());
+  tc.SetTranslatedAndUnlock(
+      kGuestPC, entry, 1, GuestCodeEntry::Kind::kSpecialHandler, {kHostCodeStub, 4});
+  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(kGuestPC)->load());
 }
 
 bool Translate(TranslationCache* tc, GuestAddr pc, uint32_t size, HostCodeAddr host_code) {
@@ -289,57 +278,52 @@ bool Translate(TranslationCache* tc, GuestAddr pc, uint32_t size, HostCodeAddr h
 }
 
 TEST(TranslationCacheTest, LockForGearUpTranslation) {
-  constexpr GuestAddr pc = 0x12345678;
-  const auto host_code = AsHostCodeAddr(AsHostCode(0xdeadbeef));
-
   TranslationCache tc;
 
   // Cannot lock if not yet added.
-  ASSERT_FALSE(tc.LockForGearUpTranslation(pc));
+  ASSERT_FALSE(tc.LockForGearUpTranslation(kGuestPC));
 
-  ASSERT_TRUE(Translate(&tc, pc + 0, 1, host_code));
-  GuestCodeEntry* entry = tc.LookupGuestCodeEntryUnsafeForTesting(pc);
+  ASSERT_TRUE(Translate(&tc, kGuestPC + 0, 1, kHostCodeStub));
+  GuestCodeEntry* entry = tc.LookupGuestCodeEntryUnsafeForTesting(kGuestPC);
   ASSERT_TRUE(entry);
   ASSERT_EQ(entry->kind, GuestCodeEntry::Kind::kSpecialHandler);
 
   // Cannot lock if kind is not kLiteTranslated.
-  ASSERT_FALSE(tc.LockForGearUpTranslation(pc));
+  ASSERT_FALSE(tc.LockForGearUpTranslation(kGuestPC));
 
   entry->kind = GuestCodeEntry::Kind::kLiteTranslated;
 
-  entry = tc.LockForGearUpTranslation(pc);
+  entry = tc.LockForGearUpTranslation(kGuestPC);
   ASSERT_TRUE(entry);
-  ASSERT_EQ(kEntryTranslating, tc.GetHostCodePtr(pc)->load());
+  ASSERT_EQ(kEntryTranslating, tc.GetHostCodePtr(kGuestPC)->load());
   ASSERT_EQ(entry->kind, GuestCodeEntry::Kind::kUnderProcessing);
 
   // Unlock.
-  tc.SetTranslatedAndUnlock(pc, entry, 1, GuestCodeEntry::Kind::kHeavyOptimized, {kEntryNoExec, 0});
-  ASSERT_EQ(kEntryNoExec, tc.GetHostCodePtr(pc)->load());
+  tc.SetTranslatedAndUnlock(
+      kGuestPC, entry, 1, GuestCodeEntry::Kind::kHeavyOptimized, {kEntryNoExec, 0});
+  ASSERT_EQ(kEntryNoExec, tc.GetHostCodePtr(kGuestPC)->load());
   ASSERT_EQ(entry->kind, GuestCodeEntry::Kind::kHeavyOptimized);
 
   // Cannot lock translated.
-  ASSERT_FALSE(tc.AddAndLockForTranslation(pc, 0));
+  ASSERT_FALSE(tc.AddAndLockForTranslation(kGuestPC, 0));
 }
 
 TEST(TranslationCacheTest, InvalidateRange) {
-  constexpr GuestAddr pc = 0x12345678;
-  const auto host_code = AsHostCodeAddr(AsHostCode(0xdeadbeef));
-
   TranslationCache tc;
 
-  ASSERT_TRUE(Translate(&tc, pc + 0, 1, host_code));
-  ASSERT_TRUE(Translate(&tc, pc + 1, 1, host_code));
-  ASSERT_TRUE(Translate(&tc, pc + 2, 1, host_code));
+  ASSERT_TRUE(Translate(&tc, kGuestPC + 0, 1, kHostCodeStub));
+  ASSERT_TRUE(Translate(&tc, kGuestPC + 1, 1, kHostCodeStub));
+  ASSERT_TRUE(Translate(&tc, kGuestPC + 2, 1, kHostCodeStub));
 
-  ASSERT_EQ(host_code, tc.GetHostCodePtr(pc + 0)->load());
-  ASSERT_EQ(host_code, tc.GetHostCodePtr(pc + 1)->load());
-  ASSERT_EQ(host_code, tc.GetHostCodePtr(pc + 2)->load());
+  ASSERT_EQ(kHostCodeStub, tc.GetHostCodePtr(kGuestPC + 0)->load());
+  ASSERT_EQ(kHostCodeStub, tc.GetHostCodePtr(kGuestPC + 1)->load());
+  ASSERT_EQ(kHostCodeStub, tc.GetHostCodePtr(kGuestPC + 2)->load());
 
-  tc.InvalidateGuestRange(pc + 1, pc + 2);
+  tc.InvalidateGuestRange(kGuestPC + 1, kGuestPC + 2);
 
-  ASSERT_EQ(host_code, tc.GetHostCodePtr(pc + 0)->load());
-  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(pc + 1)->load());
-  ASSERT_EQ(host_code, tc.GetHostCodePtr(pc + 2)->load());
+  ASSERT_EQ(kHostCodeStub, tc.GetHostCodePtr(kGuestPC + 0)->load());
+  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(kGuestPC + 1)->load());
+  ASSERT_EQ(kHostCodeStub, tc.GetHostCodePtr(kGuestPC + 2)->load());
 }
 
 bool Wrap(TranslationCache* tc, GuestAddr pc, HostCodeAddr host_code) {
@@ -352,66 +336,113 @@ bool Wrap(TranslationCache* tc, GuestAddr pc, HostCodeAddr host_code) {
 }
 
 TEST(TranslationCacheTest, InvalidateWrapped) {
-  constexpr GuestAddr pc = 0x12345678;
-
   TranslationCache tc;
 
-  ASSERT_TRUE(Wrap(&tc, pc, kEntryNoExec));
+  ASSERT_TRUE(Wrap(&tc, kGuestPC, kEntryNoExec));
 
-  tc.InvalidateGuestRange(pc, pc + 1);
+  tc.InvalidateGuestRange(kGuestPC, kGuestPC + 1);
 
-  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(pc)->load());
+  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(kGuestPC)->load());
 }
 
 TEST(TranslationCacheTest, InvalidateWrappingWrap) {
-  constexpr GuestAddr pc = 0x12345678;
-
   TranslationCache tc;
 
-  GuestCodeEntry* entry = tc.AddAndLockForWrapping(pc);
+  GuestCodeEntry* entry = tc.AddAndLockForWrapping(kGuestPC);
   ASSERT_TRUE(entry);
 
-  tc.InvalidateGuestRange(pc, pc + 1);
-  ASSERT_EQ(kEntryInvalidating, tc.GetHostCodePtr(pc)->load());
+  tc.InvalidateGuestRange(kGuestPC, kGuestPC + 1);
+  ASSERT_EQ(kEntryInvalidating, tc.GetHostCodePtr(kGuestPC)->load());
 
-  tc.SetWrappedAndUnlock(pc, entry, kWrappedHostFunc, {kEntryNoExec, 0});
-  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(pc)->load());
+  tc.SetWrappedAndUnlock(kGuestPC, entry, kWrappedHostFunc, {kEntryNoExec, 0});
+  ASSERT_EQ(kEntryNotTranslated, tc.GetHostCodePtr(kGuestPC)->load());
 
-  ASSERT_TRUE(Wrap(&tc, pc, kEntryNoExec));
+  ASSERT_TRUE(Wrap(&tc, kGuestPC, kEntryNoExec));
 }
 
 TEST(TranslationCacheTest, WrapInvalidateWrap) {
-  constexpr GuestAddr pc = 0x12345678;
-
   TranslationCache tc;
 
-  ASSERT_TRUE(Wrap(&tc, pc, kEntryNoExec));
+  ASSERT_TRUE(Wrap(&tc, kGuestPC, kEntryNoExec));
 
-  tc.InvalidateGuestRange(pc, pc + 1);
+  tc.InvalidateGuestRange(kGuestPC, kGuestPC + 1);
 
-  ASSERT_TRUE(Wrap(&tc, pc, kEntryNoExec));
+  ASSERT_TRUE(Wrap(&tc, kGuestPC, kEntryNoExec));
 }
 
 TEST(TranslationCacheTest, WrapInvalidateTranslate) {
-  constexpr GuestAddr pc = 0x12345678;
-
   TranslationCache tc;
 
-  ASSERT_TRUE(Wrap(&tc, pc, kEntryNoExec));
+  ASSERT_TRUE(Wrap(&tc, kGuestPC, kEntryNoExec));
 
-  tc.InvalidateGuestRange(pc, pc + 1);
+  tc.InvalidateGuestRange(kGuestPC, kGuestPC + 1);
 
-  ASSERT_TRUE(Translate(&tc, pc, 1, kEntryNoExec));
+  ASSERT_TRUE(Translate(&tc, kGuestPC, 1, kEntryNoExec));
 }
 
-TEST(NdkTest, TranslationCacheWrappingStatesTest) {
+TEST(TranslationCacheTest, WrappingStatesTest) {
   TranslationCacheTestRunThreads<TestWrappingWorker>();
 }
 
-TEST(NdkTest, TranslationCacheTranslationStatesTest) {
+TEST(TranslationCacheTest, TranslationStatesTest) {
   TranslationCacheTestRunThreads<TestTranslationWorker>();
 }
 
+constexpr size_t kGuestGearShiftRange = 64;
+
+void TestTriggerGearShiftForAddresses(
+    GuestAddr pc,
+    std::initializer_list<std::tuple<GuestAddr, uint32_t>> addr_and_expected_counter_list) {
+  TranslationCache tc;
+  // Lite translate interesting addresses.
+  for (auto [pc, unused_counter] : addr_and_expected_counter_list) {
+    ASSERT_TRUE(Translate(&tc, pc, 1, kHostCodeStub));
+    GuestCodeEntry* entry = tc.LookupGuestCodeEntryUnsafeForTesting(pc);
+    ASSERT_TRUE(entry);
+    ASSERT_EQ(entry->kind, GuestCodeEntry::Kind::kSpecialHandler);
+    ASSERT_EQ(entry->invocation_counter, 0u);
+    entry->kind = GuestCodeEntry::Kind::kLiteTranslated;
+  }
+
+  tc.TriggerGearShift(pc, kGuestGearShiftRange);
+
+  for (auto [pc, expected_counter] : addr_and_expected_counter_list) {
+    ASSERT_EQ(tc.LookupGuestCodeEntryUnsafeForTesting(pc)->invocation_counter, expected_counter)
+        << "pc=" << pc;
+  }
+}
+
+TEST(TranslationCacheTest, TriggerGearShift) {
+  TestTriggerGearShiftForAddresses(kGuestPC,
+                                   {{kGuestPC, config::kGearSwitchThreshold},
+                                    {kGuestPC - kGuestGearShiftRange, config::kGearSwitchThreshold},
+                                    {kGuestPC - kGuestGearShiftRange - 1, 0},
+                                    {kGuestPC + kGuestGearShiftRange, config::kGearSwitchThreshold},
+                                    {kGuestPC + kGuestGearShiftRange + 1, 0}});
+}
+
+TEST(TranslationCacheTest, TriggerGearShiftTargetLessThanRange) {
+  constexpr GuestAddr kSmallGuestPC = kGuestGearShiftRange / 2;
+  TestTriggerGearShiftForAddresses(
+      kSmallGuestPC,
+      {{kSmallGuestPC, config::kGearSwitchThreshold},
+       {kNullGuestAddr, config::kGearSwitchThreshold},
+       {kSmallGuestPC + kGuestGearShiftRange, config::kGearSwitchThreshold}});
+}
+
+TEST(TranslationCacheTest, TriggerGearShiftDoesNotAffectNotLiteTranslated) {
+  TranslationCache tc;
+  ASSERT_TRUE(Translate(&tc, kGuestPC, 1, kHostCodeStub));
+  GuestCodeEntry* entry = tc.LookupGuestCodeEntryUnsafeForTesting(kGuestPC);
+  ASSERT_TRUE(entry);
+  ASSERT_EQ(entry->kind, GuestCodeEntry::Kind::kSpecialHandler);
+  ASSERT_EQ(entry->invocation_counter, 0u);
+
+  tc.TriggerGearShift(kGuestPC, kGuestGearShiftRange);
+
+  ASSERT_EQ(tc.LookupGuestCodeEntryUnsafeForTesting(kGuestPC)->invocation_counter, 0u);
+}
+
 }  // namespace
 
 }  // namespace berberis
diff --git a/test_utils/include/berberis/test_utils/scoped_guest_exec_region.h b/test_utils/include/berberis/test_utils/scoped_guest_exec_region.h
new file mode 100644
index 00000000..2340e554
--- /dev/null
+++ b/test_utils/include/berberis/test_utils/scoped_guest_exec_region.h
@@ -0,0 +1,48 @@
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
+#ifndef BERBERIS_TEST_UTILS_SCOPED_GUEST_EXEC_REGION_H_
+#define BERBERIS_TEST_UTILS_SCOPED_GUEST_EXEC_REGION_H_
+
+#include <cstddef>
+
+#include "berberis/guest_os_primitives/guest_map_shadow.h"
+#include "berberis/guest_state/guest_addr.h"
+
+namespace berberis {
+
+// Attention: We are setting and clearing executability for the whole page!
+class ScopedGuestExecRegion {
+ public:
+  ScopedGuestExecRegion(GuestAddr pc, size_t size) : pc_(pc), size_(size) {
+    GuestMapShadow::GetInstance()->SetExecutable(pc, size);
+  }
+
+  ScopedGuestExecRegion(const ScopedGuestExecRegion&) = delete;
+  ScopedGuestExecRegion& operator=(const ScopedGuestExecRegion&) = delete;
+  ScopedGuestExecRegion(const ScopedGuestExecRegion&&) = delete;
+  ScopedGuestExecRegion& operator=(const ScopedGuestExecRegion&&) = delete;
+
+  ~ScopedGuestExecRegion() { GuestMapShadow::GetInstance()->ClearExecutable(pc_, size_); }
+
+ private:
+  GuestAddr pc_;
+  size_t size_;
+};
+
+}  // namespace berberis
+
+#endif  // BERBERIS_TEST_UTILS_SCOPED_GUEST_EXEC_REGION_H_
diff --git a/tests/inline_asm_tests/main_arm64.cc b/tests/inline_asm_tests/main_arm64.cc
index 578e6cf4..7a43fe94 100644
--- a/tests/inline_asm_tests/main_arm64.cc
+++ b/tests/inline_asm_tests/main_arm64.cc
@@ -1450,7 +1450,7 @@ TEST(Arm64InsnTest, AsmConvertF32X32Scalar) {
   uint32_t arg2 = 0xc0d80000U;  // -6.75 in float
   ASSERT_EQ(AsmConvertF32X32(arg2), MakeUInt128(0xfff94000U, 0U));
 
-  ASSERT_EQ(AsmConvertF32X32(kDefaultNaN32), MakeUInt128(bit_cast<uint32_t>(0.0f), 0U));
+  ASSERT_EQ(AsmConvertF32X32(kDefaultNaN32AsInteger), MakeUInt128(bit_cast<uint32_t>(0.0f), 0U));
 }
 
 TEST(Arm64InsnTest, AsmConvertF32UX32Scalar) {
@@ -1461,7 +1461,7 @@ TEST(Arm64InsnTest, AsmConvertF32UX32Scalar) {
   uint32_t arg2 = 0xc1540000U;  // -13.25 in float
   ASSERT_EQ(AsmConvertF32UX32(arg2), MakeUInt128(0xfff2c000U, 0U));
 
-  ASSERT_EQ(AsmConvertF32UX32(kDefaultNaN32), MakeUInt128(bit_cast<uint32_t>(0.0f), 0U));
+  ASSERT_EQ(AsmConvertF32UX32(kDefaultNaN32AsInteger), MakeUInt128(bit_cast<uint32_t>(0.0f), 0U));
 }
 
 TEST(Arm64InsnTest, AsmConvertF32UX32With31FractionalBits) {
@@ -2655,6 +2655,13 @@ TEST(Arm64InsnTest, RecipSqrtEstimateF32) {
   ASSERT_EQ(AsmFrsqrte(bit_cast<uint32_t>(5.0f)), bit_cast<uint32_t>(0.4462890625f));
 }
 
+TEST(Arm64InsnTest, RecipSqrtEstimateF32x2) {
+  constexpr auto AsmFrsqrte = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("frsqrte %0.2s, %1.2s");
+  __uint128_t arg = MakeF32x4(2.0f, 3.0f, 0, 0);
+  __uint128_t res = AsmFrsqrte(arg);
+  ASSERT_EQ(res, MakeF32x4(0.705078125f, 0.576171875f, 0, 0));
+}
+
 TEST(Arm64InsnTest, RecipSqrtEstimateF32x4) {
   constexpr auto AsmFrsqrte = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("frsqrte %0.4s, %1.4s");
   __uint128_t arg = MakeF32x4(2.0f, 3.0f, 4.0f, 5.0f);
@@ -2794,8 +2801,8 @@ TEST(Arm64InsnTest, MaxFp32) {
   uint32_t fp_arg_three = bit_cast<uint32_t>(3.0f);
 
   ASSERT_EQ(AsmFmax(fp_arg_two, fp_arg_three), MakeU32x4(fp_arg_three, 0, 0, 0));
-  ASSERT_EQ(AsmFmax(kDefaultNaN32, fp_arg_three), kDefaultNaN32);
-  ASSERT_EQ(AsmFmax(fp_arg_three, kDefaultNaN32), kDefaultNaN32);
+  ASSERT_EQ(AsmFmax(kDefaultNaN32AsInteger, fp_arg_three), kDefaultNaN32AsInteger);
+  ASSERT_EQ(AsmFmax(fp_arg_three, kDefaultNaN32AsInteger), kDefaultNaN32AsInteger);
 }
 
 TEST(Arm64InsnTest, MaxFp64) {
@@ -2804,8 +2811,8 @@ TEST(Arm64InsnTest, MaxFp64) {
   uint64_t fp_arg_three = bit_cast<uint64_t>(3.0);
 
   ASSERT_EQ(AsmFmax(fp_arg_two, fp_arg_three), MakeUInt128(fp_arg_three, 0U));
-  ASSERT_EQ(AsmFmax(kDefaultNaN64, fp_arg_three), kDefaultNaN64);
-  ASSERT_EQ(AsmFmax(fp_arg_three, kDefaultNaN64), kDefaultNaN64);
+  ASSERT_EQ(AsmFmax(kDefaultNaN64AsInteger, fp_arg_three), kDefaultNaN64AsInteger);
+  ASSERT_EQ(AsmFmax(fp_arg_three, kDefaultNaN64AsInteger), kDefaultNaN64AsInteger);
 }
 
 TEST(Arm64InsnTest, MaxF32x4) {
@@ -2814,10 +2821,13 @@ TEST(Arm64InsnTest, MaxF32x4) {
   __uint128_t arg2 = MakeF32x4(0.0f, 1.0f, -3.0f, -3.0f);
   ASSERT_EQ(AsmFmax(arg1, arg2), MakeF32x4(0.0f, 2.0f, 3.0f, -3.0f));
 
-  __uint128_t arg3 = MakeF32x4(-0.0f, bit_cast<float>(kDefaultNaN32), 3.0f, -4.0f);
-  __uint128_t arg4 = MakeF32x4(0.0f, 1.0f, -3.0f, bit_cast<float>(kDefaultNaN32));
+  __uint128_t arg3 = MakeF32x4(-0.0f, bit_cast<float>(kDefaultNaN32AsInteger), 3.0f, -4.0f);
+  __uint128_t arg4 = MakeF32x4(0.0f, 1.0f, -3.0f, bit_cast<float>(kDefaultNaN32AsInteger));
   ASSERT_EQ(AsmFmax(arg3, arg4),
-            MakeF32x4(0.0f, bit_cast<float>(kDefaultNaN32), 3.0f, bit_cast<float>(kDefaultNaN32)));
+            MakeF32x4(0.0f,
+                      bit_cast<float>(kDefaultNaN32AsInteger),
+                      3.0f,
+                      bit_cast<float>(kDefaultNaN32AsInteger)));
 }
 
 TEST(Arm64InsnTest, MaxF64x2) {
@@ -2826,10 +2836,11 @@ TEST(Arm64InsnTest, MaxF64x2) {
   __uint128_t arg2 = MakeF64x2(0.0, -3.0);
   ASSERT_EQ(AsmFmax(arg1, arg2), MakeF64x2(0.0, 3.0));
 
-  __uint128_t arg3 = MakeF64x2(bit_cast<double>(kDefaultNaN64), 3.0);
-  __uint128_t arg4 = MakeF64x2(1.0, bit_cast<double>(kDefaultNaN64));
+  __uint128_t arg3 = MakeF64x2(bit_cast<double>(kDefaultNaN64AsInteger), 3.0);
+  __uint128_t arg4 = MakeF64x2(1.0, bit_cast<double>(kDefaultNaN64AsInteger));
   ASSERT_EQ(AsmFmax(arg3, arg4),
-            MakeF64x2(bit_cast<double>(kDefaultNaN64), bit_cast<double>(kDefaultNaN64)));
+            MakeF64x2(bit_cast<double>(kDefaultNaN64AsInteger),
+                      bit_cast<double>(kDefaultNaN64AsInteger)));
 }
 
 TEST(Arm64InsnTest, MaxNumberFp32) {
@@ -2840,10 +2851,12 @@ TEST(Arm64InsnTest, MaxNumberFp32) {
 
   ASSERT_EQ(AsmFmaxnm(fp_arg_two, fp_arg_three), MakeU32x4(fp_arg_three, 0, 0, 0));
 
-  ASSERT_EQ(AsmFmaxnm(fp_arg_two, kQuietNaN32), MakeU32x4(fp_arg_two, 0, 0, 0));
-  ASSERT_EQ(AsmFmaxnm(fp_arg_minus_two, kQuietNaN32), MakeU32x4(fp_arg_minus_two, 0, 0, 0));
-  ASSERT_EQ(AsmFmaxnm(kQuietNaN32, fp_arg_two), MakeU32x4(fp_arg_two, 0, 0, 0));
-  ASSERT_EQ(AsmFmaxnm(kQuietNaN32, fp_arg_minus_two), MakeU32x4(fp_arg_minus_two, 0, 0, 0));
+  ASSERT_EQ(AsmFmaxnm(fp_arg_two, kQuietNaN32AsInteger), MakeU32x4(fp_arg_two, 0, 0, 0));
+  ASSERT_EQ(AsmFmaxnm(fp_arg_minus_two, kQuietNaN32AsInteger),
+            MakeU32x4(fp_arg_minus_two, 0, 0, 0));
+  ASSERT_EQ(AsmFmaxnm(kQuietNaN32AsInteger, fp_arg_two), MakeU32x4(fp_arg_two, 0, 0, 0));
+  ASSERT_EQ(AsmFmaxnm(kQuietNaN32AsInteger, fp_arg_minus_two),
+            MakeU32x4(fp_arg_minus_two, 0, 0, 0));
 }
 
 TEST(Arm64InsnTest, MaxNumberFp64) {
@@ -2854,10 +2867,10 @@ TEST(Arm64InsnTest, MaxNumberFp64) {
 
   ASSERT_EQ(AsmFmaxnm(fp_arg_two, fp_arg_three), MakeUInt128(fp_arg_three, 0U));
 
-  ASSERT_EQ(AsmFmaxnm(fp_arg_two, kQuietNaN64), MakeUInt128(fp_arg_two, 0U));
-  ASSERT_EQ(AsmFmaxnm(fp_arg_minus_two, kQuietNaN64), MakeUInt128(fp_arg_minus_two, 0));
-  ASSERT_EQ(AsmFmaxnm(kQuietNaN64, fp_arg_two), MakeUInt128(fp_arg_two, 0));
-  ASSERT_EQ(AsmFmaxnm(kQuietNaN64, fp_arg_minus_two), MakeUInt128(fp_arg_minus_two, 0));
+  ASSERT_EQ(AsmFmaxnm(fp_arg_two, kQuietNaN64AsInteger), MakeUInt128(fp_arg_two, 0U));
+  ASSERT_EQ(AsmFmaxnm(fp_arg_minus_two, kQuietNaN64AsInteger), MakeUInt128(fp_arg_minus_two, 0));
+  ASSERT_EQ(AsmFmaxnm(kQuietNaN64AsInteger, fp_arg_two), MakeUInt128(fp_arg_two, 0));
+  ASSERT_EQ(AsmFmaxnm(kQuietNaN64AsInteger, fp_arg_minus_two), MakeUInt128(fp_arg_minus_two, 0));
 }
 
 TEST(Arm64InsnTest, MinNumberFp32) {
@@ -2868,10 +2881,12 @@ TEST(Arm64InsnTest, MinNumberFp32) {
 
   ASSERT_EQ(AsmFminnm(fp_arg_two, fp_arg_three), MakeU32x4(fp_arg_two, 0, 0, 0));
 
-  ASSERT_EQ(AsmFminnm(fp_arg_two, kQuietNaN32), MakeU32x4(fp_arg_two, 0, 0, 0));
-  ASSERT_EQ(AsmFminnm(fp_arg_minus_two, kQuietNaN32), MakeU32x4(fp_arg_minus_two, 0, 0, 0));
-  ASSERT_EQ(AsmFminnm(kQuietNaN32, fp_arg_two), MakeU32x4(fp_arg_two, 0, 0, 0));
-  ASSERT_EQ(AsmFminnm(kQuietNaN32, fp_arg_minus_two), MakeU32x4(fp_arg_minus_two, 0, 0, 0));
+  ASSERT_EQ(AsmFminnm(fp_arg_two, kQuietNaN32AsInteger), MakeU32x4(fp_arg_two, 0, 0, 0));
+  ASSERT_EQ(AsmFminnm(fp_arg_minus_two, kQuietNaN32AsInteger),
+            MakeU32x4(fp_arg_minus_two, 0, 0, 0));
+  ASSERT_EQ(AsmFminnm(kQuietNaN32AsInteger, fp_arg_two), MakeU32x4(fp_arg_two, 0, 0, 0));
+  ASSERT_EQ(AsmFminnm(kQuietNaN32AsInteger, fp_arg_minus_two),
+            MakeU32x4(fp_arg_minus_two, 0, 0, 0));
 }
 
 TEST(Arm64InsnTest, MinNumberFp64) {
@@ -2882,10 +2897,10 @@ TEST(Arm64InsnTest, MinNumberFp64) {
 
   ASSERT_EQ(AsmFminnm(fp_arg_two, fp_arg_three), MakeUInt128(fp_arg_two, 0U));
 
-  ASSERT_EQ(AsmFminnm(fp_arg_two, kQuietNaN64), MakeUInt128(fp_arg_two, 0U));
-  ASSERT_EQ(AsmFminnm(fp_arg_minus_two, kQuietNaN64), MakeUInt128(fp_arg_minus_two, 0));
-  ASSERT_EQ(AsmFminnm(kQuietNaN64, fp_arg_two), MakeUInt128(fp_arg_two, 0));
-  ASSERT_EQ(AsmFminnm(kQuietNaN64, fp_arg_minus_two), MakeUInt128(fp_arg_minus_two, 0));
+  ASSERT_EQ(AsmFminnm(fp_arg_two, kQuietNaN64AsInteger), MakeUInt128(fp_arg_two, 0U));
+  ASSERT_EQ(AsmFminnm(fp_arg_minus_two, kQuietNaN64AsInteger), MakeUInt128(fp_arg_minus_two, 0));
+  ASSERT_EQ(AsmFminnm(kQuietNaN64AsInteger, fp_arg_two), MakeUInt128(fp_arg_two, 0));
+  ASSERT_EQ(AsmFminnm(kQuietNaN64AsInteger, fp_arg_minus_two), MakeUInt128(fp_arg_minus_two, 0));
 }
 
 TEST(Arm64InsnTest, MaxNumberF32x4) {
@@ -2894,16 +2909,47 @@ TEST(Arm64InsnTest, MaxNumberF32x4) {
   __uint128_t arg2 = MakeF32x4(2.0f, 1.0f, -3.0f, -3.0f);
   ASSERT_EQ(AsmFmaxnm(arg1, arg2), MakeF32x4(2.0f, 2.0f, 3.0f, -3.0f));
 
-  __uint128_t arg3 =
-      MakeU32x4(bit_cast<uint32_t>(1.0f), bit_cast<uint32_t>(-1.0f), kQuietNaN32, kQuietNaN32);
-  __uint128_t arg4 =
-      MakeU32x4(kQuietNaN32, kQuietNaN32, bit_cast<uint32_t>(1.0f), bit_cast<uint32_t>(-1.0f));
+  __uint128_t arg3 = MakeU32x4(bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f),
+                               kNegativeQuietNaN32AsInteger,
+                               kQuietNaN32AsInteger);
+  __uint128_t arg4 = MakeU32x4(kNegativeQuietNaN32AsInteger,
+                               kQuietNaN32AsInteger,
+                               bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f));
   ASSERT_EQ(AsmFmaxnm(arg3, arg4), MakeF32x4(1.0f, -1.0f, 1.0f, -1.0f));
 
-  __uint128_t arg5 = MakeU32x4(
-      bit_cast<uint32_t>(1.0f), bit_cast<uint32_t>(-1.0f), kSignalingNaN32_1, kQuietNaN32);
-  __uint128_t arg6 = MakeU32x4(
-      kSignalingNaN32_1, kQuietNaN32, bit_cast<uint32_t>(1.0f), bit_cast<uint32_t>(-1.0f));
+  __uint128_t arg5 = MakeU32x4(bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f),
+                               kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger);
+  __uint128_t arg6 = MakeU32x4(kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger,
+                               bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f));
+  ASSERT_EQ(AsmFmaxnm(arg5, arg6),
+            MakeF32x4(bit_cast<float>(kDefaultNaN32AsInteger),
+                      -1.0f,
+                      bit_cast<float>(kDefaultNaN32AsInteger),
+                      -1.0f));
+
+  __uint128_t arg7 = MakeU32x4(kSignalingNaN32AsInteger_1,
+                               kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger,
+                               kQuietNaN32AsInteger);
+  __uint128_t arg8 = MakeU32x4(kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger,
+                               kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger);
+  ASSERT_EQ(AsmFmaxnm(arg7, arg8),
+            MakeF32x4(bit_cast<float>(kDefaultNaN32AsInteger),
+                      bit_cast<float>(kDefaultNaN32AsInteger),
+                      bit_cast<float>(kDefaultNaN32AsInteger),
+                      bit_cast<float>(kDefaultNaN32AsInteger)));
+
+  __uint128_t arg9 = MakeF32x4(-0.0f, -0.0f, 0.0f, 0.0f);
+  __uint128_t arg10 = MakeF32x4(-0.0f, 0.0f, -0.0f, 0.0f);
+  ASSERT_EQ(AsmFmaxnm(arg9, arg10), MakeF32x4(-0.0f, 0.0f, 0.0f, 0.0f));
 }
 
 TEST(Arm64InsnTest, MaxNumberF64x2) {
@@ -2912,23 +2958,58 @@ TEST(Arm64InsnTest, MaxNumberF64x2) {
   __uint128_t arg2 = MakeF64x2(2.0, -3.0);
   ASSERT_EQ(AsmFmaxnm(arg1, arg2), MakeF64x2(2.0, -3.0));
 
-  __uint128_t arg3 = MakeUInt128(bit_cast<uint64_t>(1.0), kQuietNaN64);
-  __uint128_t arg4 = MakeUInt128(kQuietNaN64, bit_cast<uint64_t>(-1.0));
+  __uint128_t arg3 = MakeUInt128(bit_cast<uint64_t>(1.0), kQuietNaN64AsInteger);
+  __uint128_t arg4 = MakeUInt128(kQuietNaN64AsInteger, bit_cast<uint64_t>(-1.0));
   ASSERT_EQ(AsmFmaxnm(arg3, arg4), MakeF64x2(1.0, -1.0));
 }
 
 TEST(Arm64InsnTest, MinNumberF32x4) {
   constexpr auto AsmFminnm = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("fminnm %0.4s, %1.4s, %2.4s");
-  __uint128_t arg1 = MakeF32x4(0.0f, 2.0f, 3.0f, -4.0f);
-  __uint128_t arg2 = MakeF32x4(-0.0f, 1.0f, -3.0f, -3.0f);
-  ASSERT_EQ(AsmFminnm(arg1, arg2), MakeF32x4(-0.0f, 1.0f, -3.0f, -4.0f));
-
-  __uint128_t arg3 =
-      MakeU32x4(bit_cast<uint32_t>(1.0f), bit_cast<uint32_t>(-1.0f), kQuietNaN32, kQuietNaN32);
-  __uint128_t arg4 =
-      MakeU32x4(kQuietNaN32, kQuietNaN32, bit_cast<uint32_t>(1.0f), bit_cast<uint32_t>(-1.0f));
-  __uint128_t res = AsmFminnm(arg3, arg4);
-  ASSERT_EQ(res, MakeF32x4(1.0f, -1.0f, 1.0f, -1.0f));
+  __uint128_t arg1 = MakeF32x4(-1.0f, 2.0f, 3.0f, -4.0f);
+  __uint128_t arg2 = MakeF32x4(2.0f, 1.0f, -3.0f, -3.0f);
+  ASSERT_EQ(AsmFminnm(arg1, arg2), MakeF32x4(-1.0f, 1.0f, -3.0f, -4.0f));
+
+  __uint128_t arg3 = MakeU32x4(bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f),
+                               kNegativeQuietNaN32AsInteger,
+                               kQuietNaN32AsInteger);
+  __uint128_t arg4 = MakeU32x4(kNegativeQuietNaN32AsInteger,
+                               kQuietNaN32AsInteger,
+                               bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f));
+  ASSERT_EQ(AsmFminnm(arg3, arg4), MakeF32x4(1.0f, -1.0f, 1.0f, -1.0f));
+
+  __uint128_t arg5 = MakeU32x4(bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f),
+                               kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger);
+  __uint128_t arg6 = MakeU32x4(kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger,
+                               bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f));
+  ASSERT_EQ(AsmFminnm(arg5, arg6),
+            MakeF32x4(bit_cast<float>(kDefaultNaN32AsInteger),
+                      -1.0f,
+                      bit_cast<float>(kDefaultNaN32AsInteger),
+                      -1.0f));
+
+  __uint128_t arg7 = MakeU32x4(kSignalingNaN32AsInteger_1,
+                               kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger,
+                               kQuietNaN32AsInteger);
+  __uint128_t arg8 = MakeU32x4(kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger,
+                               kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger);
+  ASSERT_EQ(AsmFminnm(arg7, arg8),
+            MakeF32x4(bit_cast<float>(kDefaultNaN32AsInteger),
+                      bit_cast<float>(kDefaultNaN32AsInteger),
+                      bit_cast<float>(kDefaultNaN32AsInteger),
+                      bit_cast<float>(kDefaultNaN32AsInteger)));
+
+  __uint128_t arg9 = MakeF32x4(-0.0f, -0.0f, 0.0f, 0.0f);
+  __uint128_t arg10 = MakeF32x4(-0.0f, 0.0f, -0.0f, 0.0f);
+  ASSERT_EQ(AsmFminnm(arg9, arg10), MakeF32x4(-0.0f, -0.0f, -0.0f, 0.0f));
 }
 
 TEST(Arm64InsnTest, MinNumberF64x2) {
@@ -2937,8 +3018,8 @@ TEST(Arm64InsnTest, MinNumberF64x2) {
   __uint128_t arg2 = MakeF64x2(-0.0, -3.0);
   ASSERT_EQ(AsmFminnm(arg1, arg2), MakeF64x2(-0.0, -3.0));
 
-  __uint128_t arg3 = MakeUInt128(bit_cast<uint64_t>(1.0), kQuietNaN64);
-  __uint128_t arg4 = MakeUInt128(kQuietNaN64, bit_cast<uint64_t>(-1.0));
+  __uint128_t arg3 = MakeUInt128(bit_cast<uint64_t>(1.0), kQuietNaN64AsInteger);
+  __uint128_t arg4 = MakeUInt128(kQuietNaN64AsInteger, bit_cast<uint64_t>(-1.0));
   __uint128_t res = AsmFminnm(arg3, arg4);
   ASSERT_EQ(res, MakeF64x2(1.0, -1.0));
 }
@@ -2949,8 +3030,8 @@ TEST(Arm64InsnTest, MinFp32) {
   uint32_t fp_arg_three = bit_cast<uint32_t>(3.0f);
 
   ASSERT_EQ(AsmFmin(fp_arg_two, fp_arg_three), MakeU32x4(fp_arg_two, 0, 0, 0));
-  ASSERT_EQ(AsmFmin(kDefaultNaN32, fp_arg_three), kDefaultNaN32);
-  ASSERT_EQ(AsmFmin(fp_arg_three, kDefaultNaN32), kDefaultNaN32);
+  ASSERT_EQ(AsmFmin(kDefaultNaN32AsInteger, fp_arg_three), kDefaultNaN32AsInteger);
+  ASSERT_EQ(AsmFmin(fp_arg_three, kDefaultNaN32AsInteger), kDefaultNaN32AsInteger);
 }
 
 TEST(Arm64InsnTest, MinFp64) {
@@ -2959,8 +3040,8 @@ TEST(Arm64InsnTest, MinFp64) {
   uint64_t fp_arg_three = bit_cast<uint64_t>(3.0);
 
   ASSERT_EQ(AsmFmin(fp_arg_two, fp_arg_three), MakeUInt128(fp_arg_two, 0U));
-  ASSERT_EQ(AsmFmin(kDefaultNaN64, fp_arg_three), kDefaultNaN64);
-  ASSERT_EQ(AsmFmin(fp_arg_three, kDefaultNaN64), kDefaultNaN64);
+  ASSERT_EQ(AsmFmin(kDefaultNaN64AsInteger, fp_arg_three), kDefaultNaN64AsInteger);
+  ASSERT_EQ(AsmFmin(fp_arg_three, kDefaultNaN64AsInteger), kDefaultNaN64AsInteger);
 }
 
 TEST(Arm64InsnTest, MinF32x4) {
@@ -2969,11 +3050,13 @@ TEST(Arm64InsnTest, MinF32x4) {
   __uint128_t arg2 = MakeF32x4(-0.0f, 1.0f, -3.0f, -3.0f);
   ASSERT_EQ(AsmFmin(arg1, arg2), MakeF32x4(-0.0f, 1.0f, -3.0f, -4.0f));
 
-  __uint128_t arg3 = MakeF32x4(-0.0f, bit_cast<float>(kDefaultNaN32), 3.0f, -4.0f);
-  __uint128_t arg4 = MakeF32x4(0.0f, 1.0f, -3.0f, bit_cast<float>(kDefaultNaN32));
-  ASSERT_EQ(
-      AsmFmin(arg3, arg4),
-      MakeF32x4(-0.0f, bit_cast<float>(kDefaultNaN32), -3.0f, bit_cast<float>(kDefaultNaN32)));
+  __uint128_t arg3 = MakeF32x4(-0.0f, bit_cast<float>(kDefaultNaN32AsInteger), 3.0f, -4.0f);
+  __uint128_t arg4 = MakeF32x4(0.0f, 1.0f, -3.0f, bit_cast<float>(kDefaultNaN32AsInteger));
+  ASSERT_EQ(AsmFmin(arg3, arg4),
+            MakeF32x4(-0.0f,
+                      bit_cast<float>(kDefaultNaN32AsInteger),
+                      -3.0f,
+                      bit_cast<float>(kDefaultNaN32AsInteger)));
 }
 
 TEST(Arm64InsnTest, MinF64x2) {
@@ -2982,10 +3065,11 @@ TEST(Arm64InsnTest, MinF64x2) {
   __uint128_t arg2 = MakeF64x2(-0.0, -3.0);
   ASSERT_EQ(AsmFmin(arg1, arg2), MakeF64x2(-0.0, -3.0));
 
-  __uint128_t arg3 = MakeF64x2(bit_cast<double>(kDefaultNaN64), 3.0);
-  __uint128_t arg4 = MakeF64x2(1.0, bit_cast<double>(kDefaultNaN64));
+  __uint128_t arg3 = MakeF64x2(bit_cast<double>(kDefaultNaN64AsInteger), 3.0);
+  __uint128_t arg4 = MakeF64x2(1.0, bit_cast<double>(kDefaultNaN64AsInteger));
   ASSERT_EQ(AsmFmin(arg3, arg4),
-            MakeF64x2(bit_cast<double>(kDefaultNaN64), bit_cast<double>(kDefaultNaN64)));
+            MakeF64x2(bit_cast<double>(kDefaultNaN64AsInteger),
+                      bit_cast<double>(kDefaultNaN64AsInteger)));
 }
 
 TEST(Arm64InsnTest, MaxPairwiseF32Scalar) {
@@ -2993,8 +3077,8 @@ TEST(Arm64InsnTest, MaxPairwiseF32Scalar) {
   __uint128_t arg1 = MakeF32x4(-3.0f, 2.0f, 7.0f, -0.0f);
   ASSERT_EQ(AsmFmaxp(arg1), bit_cast<uint32_t>(2.0f));
 
-  __uint128_t arg2 = MakeF32x4(bit_cast<float>(kDefaultNaN32), 2.0f, 7.0f, -0.0f);
-  ASSERT_EQ(AsmFmaxp(arg2), kDefaultNaN32);
+  __uint128_t arg2 = MakeF32x4(bit_cast<float>(kDefaultNaN32AsInteger), 2.0f, 7.0f, -0.0f);
+  ASSERT_EQ(AsmFmaxp(arg2), kDefaultNaN32AsInteger);
 }
 
 TEST(Arm64InsnTest, MaxPairwiseF32x4) {
@@ -3003,11 +3087,14 @@ TEST(Arm64InsnTest, MaxPairwiseF32x4) {
   __uint128_t arg2 = MakeF32x4(6.0f, 1.0f, -8.0f, 5.0f);
   ASSERT_EQ(AsmFmaxp(arg1, arg2), MakeF32x4(2.0f, 7.0f, 6.0f, 5.0f));
 
-  __uint128_t arg3 =
-      MakeF32x4(bit_cast<float>(kDefaultNaN32), 2.0f, 7.0f, bit_cast<float>(kDefaultNaN32));
+  __uint128_t arg3 = MakeF32x4(
+      bit_cast<float>(kDefaultNaN32AsInteger), 2.0f, 7.0f, bit_cast<float>(kDefaultNaN32AsInteger));
   __uint128_t arg4 = MakeF32x4(6.0f, 1.0f, -8.0f, 5.0f);
   ASSERT_EQ(AsmFmaxp(arg3, arg4),
-            MakeF32x4(bit_cast<float>(kDefaultNaN32), bit_cast<float>(kDefaultNaN32), 6.0f, 5.0f));
+            MakeF32x4(bit_cast<float>(kDefaultNaN32AsInteger),
+                      bit_cast<float>(kDefaultNaN32AsInteger),
+                      6.0f,
+                      5.0f));
 }
 
 TEST(Arm64InsnTest, MinPairwiseF32Scalar) {
@@ -3015,8 +3102,8 @@ TEST(Arm64InsnTest, MinPairwiseF32Scalar) {
   __uint128_t arg1 = MakeF32x4(-3.0f, 2.0f, 7.0f, -0.0f);
   ASSERT_EQ(AsmFminp(arg1), bit_cast<uint32_t>(-3.0f));
 
-  __uint128_t arg2 = MakeF32x4(bit_cast<float>(kDefaultNaN32), 2.0f, 7.0f, -0.0f);
-  ASSERT_EQ(AsmFminp(arg2), kDefaultNaN32);
+  __uint128_t arg2 = MakeF32x4(bit_cast<float>(kDefaultNaN32AsInteger), 2.0f, 7.0f, -0.0f);
+  ASSERT_EQ(AsmFminp(arg2), kDefaultNaN32AsInteger);
 }
 
 TEST(Arm64InsnTest, MinPairwiseF32x4) {
@@ -3025,11 +3112,14 @@ TEST(Arm64InsnTest, MinPairwiseF32x4) {
   __uint128_t arg2 = MakeF32x4(6.0f, 1.0f, -8.0f, 5.0f);
   ASSERT_EQ(AsmFminp(arg1, arg2), MakeF32x4(-3.0f, -0.0f, 1.0f, -8.0f));
 
-  __uint128_t arg3 =
-      MakeF32x4(bit_cast<float>(kDefaultNaN32), 2.0f, 7.0f, bit_cast<float>(kDefaultNaN32));
+  __uint128_t arg3 = MakeF32x4(
+      bit_cast<float>(kDefaultNaN32AsInteger), 2.0f, 7.0f, bit_cast<float>(kDefaultNaN32AsInteger));
   __uint128_t arg4 = MakeF32x4(6.0f, 1.0f, -8.0f, 5.0f);
   ASSERT_EQ(AsmFminp(arg3, arg4),
-            MakeF32x4(bit_cast<float>(kDefaultNaN32), bit_cast<float>(kDefaultNaN32), 1.0f, -8.0f));
+            MakeF32x4(bit_cast<float>(kDefaultNaN32AsInteger),
+                      bit_cast<float>(kDefaultNaN32AsInteger),
+                      1.0f,
+                      -8.0f));
 }
 
 TEST(Arm64InsnTest, MaxPairwiseNumberF32Scalar) {
@@ -3037,7 +3127,7 @@ TEST(Arm64InsnTest, MaxPairwiseNumberF32Scalar) {
   __uint128_t arg1 = MakeF32x4(-3.0f, 2.0f, 7.0f, -0.0f);
   ASSERT_EQ(AsmFmaxnmp(arg1), bit_cast<uint32_t>(2.0f));
 
-  __uint128_t arg2 = MakeF32x4(bit_cast<float>(kQuietNaN32), 2.0f, 7.0f, -0.0f);
+  __uint128_t arg2 = MakeF32x4(bit_cast<float>(kQuietNaN32AsInteger), 2.0f, 7.0f, -0.0f);
   ASSERT_EQ(AsmFmaxnmp(arg2), bit_cast<uint32_t>(2.0f));
 }
 
@@ -3047,8 +3137,8 @@ TEST(Arm64InsnTest, MaxPairwiseNumberF32x4) {
   __uint128_t arg2 = MakeF32x4(6.0f, 1.0f, -8.0f, 5.0f);
   ASSERT_EQ(AsmFmaxnmp(arg1, arg2), MakeF32x4(2.0f, 7.0f, 6.0f, 5.0f));
 
-  __uint128_t arg3 =
-      MakeF32x4(bit_cast<float>(kQuietNaN32), 2.0f, 7.0f, bit_cast<float>(kQuietNaN32));
+  __uint128_t arg3 = MakeF32x4(
+      bit_cast<float>(kQuietNaN32AsInteger), 2.0f, 7.0f, bit_cast<float>(kQuietNaN32AsInteger));
   __uint128_t arg4 = MakeF32x4(6.0f, 1.0f, -8.0f, 5.0f);
   ASSERT_EQ(AsmFmaxnmp(arg3, arg4), MakeF32x4(2.0f, 7.0f, 6.0f, 5.0f));
 }
@@ -3058,7 +3148,7 @@ TEST(Arm64InsnTest, MinPairwiseNumberF32Scalar) {
   __uint128_t arg1 = MakeF32x4(-3.0f, 2.0f, 7.0f, -0.0f);
   ASSERT_EQ(AsmFminnmp(arg1), bit_cast<uint32_t>(-3.0f));
 
-  __uint128_t arg2 = MakeF32x4(bit_cast<float>(kQuietNaN32), 2.0f, 7.0f, -0.0f);
+  __uint128_t arg2 = MakeF32x4(bit_cast<float>(kQuietNaN32AsInteger), 2.0f, 7.0f, -0.0f);
   ASSERT_EQ(AsmFminnmp(arg2), bit_cast<uint32_t>(2.0f));
 }
 
@@ -3068,8 +3158,8 @@ TEST(Arm64InsnTest, MinPairwiseNumberF32x4) {
   __uint128_t arg2 = MakeF32x4(6.0f, 1.0f, -8.0f, 5.0f);
   ASSERT_EQ(AsmFminnmp(arg1, arg2), MakeF32x4(-3.0f, -0.0f, 1.0f, -8.0f));
 
-  __uint128_t arg3 =
-      MakeF32x4(bit_cast<float>(kQuietNaN32), 2.0f, 7.0f, bit_cast<float>(kQuietNaN32));
+  __uint128_t arg3 = MakeF32x4(
+      bit_cast<float>(kQuietNaN32AsInteger), 2.0f, 7.0f, bit_cast<float>(kQuietNaN32AsInteger));
   __uint128_t arg4 = MakeF32x4(6.0f, 1.0f, -8.0f, 5.0f);
   ASSERT_EQ(AsmFminnmp(arg3, arg4), MakeF32x4(2.0f, 7.0f, 1.0f, -8.0f));
 }
@@ -3079,8 +3169,8 @@ TEST(Arm64InsnTest, MaxAcrossF32x4) {
   __uint128_t arg1 = MakeF32x4(0.0f, 2.0f, 3.0f, -4.0f);
   ASSERT_EQ(AsmFmaxv(arg1), bit_cast<uint32_t>(3.0f));
 
-  __uint128_t arg2 = MakeF32x4(0.0f, 2.0f, bit_cast<float>(kDefaultNaN32), -4.0f);
-  ASSERT_EQ(AsmFmaxv(arg2), kDefaultNaN32);
+  __uint128_t arg2 = MakeF32x4(0.0f, 2.0f, bit_cast<float>(kDefaultNaN32AsInteger), -4.0f);
+  ASSERT_EQ(AsmFmaxv(arg2), kDefaultNaN32AsInteger);
 }
 
 TEST(Arm64InsnTest, MinAcrossF32x4) {
@@ -3088,8 +3178,8 @@ TEST(Arm64InsnTest, MinAcrossF32x4) {
   __uint128_t arg1 = MakeF32x4(0.0f, 2.0f, 3.0f, -4.0f);
   ASSERT_EQ(AsmFminv(arg1), bit_cast<uint32_t>(-4.0f));
 
-  __uint128_t arg2 = MakeF32x4(0.0f, 2.0f, bit_cast<float>(kDefaultNaN32), -4.0f);
-  ASSERT_EQ(AsmFminv(arg2), kDefaultNaN32);
+  __uint128_t arg2 = MakeF32x4(0.0f, 2.0f, bit_cast<float>(kDefaultNaN32AsInteger), -4.0f);
+  ASSERT_EQ(AsmFminv(arg2), kDefaultNaN32AsInteger);
 }
 
 TEST(Arm64InsnTest, MaxNumberAcrossF32x4) {
@@ -3097,7 +3187,7 @@ TEST(Arm64InsnTest, MaxNumberAcrossF32x4) {
   __uint128_t arg1 = MakeF32x4(0.0f, 2.0f, 3.0f, -4.0f);
   ASSERT_EQ(AsmFmaxnmv(arg1), bit_cast<uint32_t>(3.0f));
 
-  __uint128_t arg2 = MakeF32x4(0.0f, bit_cast<float>(kQuietNaN32), 3.0f, -4.0f);
+  __uint128_t arg2 = MakeF32x4(0.0f, bit_cast<float>(kQuietNaN32AsInteger), 3.0f, -4.0f);
   ASSERT_EQ(AsmFmaxnmv(arg2), bit_cast<uint32_t>(3.0f));
 }
 
@@ -3106,7 +3196,7 @@ TEST(Arm64InsnTest, MinNumberAcrossF32x4) {
   __uint128_t arg1 = MakeF32x4(0.0f, 2.0f, 3.0f, -4.0f);
   ASSERT_EQ(AsmFminnmv(arg1), bit_cast<uint32_t>(-4.0f));
 
-  __uint128_t arg2 = MakeF32x4(0.0f, bit_cast<float>(kQuietNaN32), 3.0f, -4.0f);
+  __uint128_t arg2 = MakeF32x4(0.0f, bit_cast<float>(kQuietNaN32AsInteger), 3.0f, -4.0f);
   ASSERT_EQ(AsmFminnmv(arg2), bit_cast<uint32_t>(-4.0f));
 }
 
@@ -3543,8 +3633,8 @@ TEST(Arm64InsnTest, CompareEqualF32) {
   uint32_t six = bit_cast<uint32_t>(6.0f);
   ASSERT_EQ(AsmFcmeq(two, six), 0x00000000ULL);
   ASSERT_EQ(AsmFcmeq(two, two), 0xffffffffULL);
-  ASSERT_EQ(AsmFcmeq(kDefaultNaN32, two), 0x00000000ULL);
-  ASSERT_EQ(AsmFcmeq(two, kDefaultNaN32), 0x00000000ULL);
+  ASSERT_EQ(AsmFcmeq(kDefaultNaN32AsInteger, two), 0x00000000ULL);
+  ASSERT_EQ(AsmFcmeq(two, kDefaultNaN32AsInteger), 0x00000000ULL);
 }
 
 TEST(Arm64InsnTest, CompareEqualF32x4) {
@@ -3562,8 +3652,8 @@ TEST(Arm64InsnTest, CompareGreaterEqualF32) {
   ASSERT_EQ(AsmFcmge(two, six), 0x00000000ULL);
   ASSERT_EQ(AsmFcmge(two, two), 0xffffffffULL);
   ASSERT_EQ(AsmFcmge(six, two), 0xffffffffULL);
-  ASSERT_EQ(AsmFcmge(kDefaultNaN32, two), 0x00000000ULL);
-  ASSERT_EQ(AsmFcmge(two, kDefaultNaN32), 0x00000000ULL);
+  ASSERT_EQ(AsmFcmge(kDefaultNaN32AsInteger, two), 0x00000000ULL);
+  ASSERT_EQ(AsmFcmge(two, kDefaultNaN32AsInteger), 0x00000000ULL);
 }
 
 TEST(Arm64InsnTest, CompareGreaterEqualF32x4) {
@@ -3581,8 +3671,8 @@ TEST(Arm64InsnTest, CompareGreaterF32) {
   ASSERT_EQ(AsmFcmgt(two, six), 0x00000000ULL);
   ASSERT_EQ(AsmFcmgt(two, two), 0x00000000ULL);
   ASSERT_EQ(AsmFcmgt(six, two), 0xffffffffULL);
-  ASSERT_EQ(AsmFcmgt(kDefaultNaN32, two), 0x00000000ULL);
-  ASSERT_EQ(AsmFcmgt(two, kDefaultNaN32), 0x00000000ULL);
+  ASSERT_EQ(AsmFcmgt(kDefaultNaN32AsInteger, two), 0x00000000ULL);
+  ASSERT_EQ(AsmFcmgt(two, kDefaultNaN32AsInteger), 0x00000000ULL);
 }
 
 TEST(Arm64InsnTest, CompareGreaterF32x4) {
@@ -3696,8 +3786,8 @@ TEST(Arm64InsnTest, CompareEqualF64) {
   uint64_t six = bit_cast<uint64_t>(6.0);
   ASSERT_EQ(AsmFcmeq(two, six), 0x0000000000000000ULL);
   ASSERT_EQ(AsmFcmeq(two, two), 0xffffffffffffffffULL);
-  ASSERT_EQ(AsmFcmeq(kDefaultNaN64, two), 0x0000000000000000ULL);
-  ASSERT_EQ(AsmFcmeq(two, kDefaultNaN64), 0x0000000000000000ULL);
+  ASSERT_EQ(AsmFcmeq(kDefaultNaN64AsInteger, two), 0x0000000000000000ULL);
+  ASSERT_EQ(AsmFcmeq(two, kDefaultNaN64AsInteger), 0x0000000000000000ULL);
 }
 
 TEST(Arm64InsnTest, CompareEqualF64x2) {
@@ -3719,8 +3809,8 @@ TEST(Arm64InsnTest, CompareGreaterEqualF64) {
   ASSERT_EQ(AsmFcmge(two, six), 0x0000000000000000ULL);
   ASSERT_EQ(AsmFcmge(two, two), 0xffffffffffffffffULL);
   ASSERT_EQ(AsmFcmge(six, two), 0xffffffffffffffffULL);
-  ASSERT_EQ(AsmFcmge(kDefaultNaN64, two), 0x0000000000000000ULL);
-  ASSERT_EQ(AsmFcmge(two, kDefaultNaN64), 0x0000000000000000ULL);
+  ASSERT_EQ(AsmFcmge(kDefaultNaN64AsInteger, two), 0x0000000000000000ULL);
+  ASSERT_EQ(AsmFcmge(two, kDefaultNaN64AsInteger), 0x0000000000000000ULL);
 }
 
 TEST(Arm64InsnTest, CompareGreaterEqualF64x2) {
@@ -3742,8 +3832,8 @@ TEST(Arm64InsnTest, CompareGreaterF64) {
   ASSERT_EQ(AsmFcmgt(two, six), 0x0000000000000000ULL);
   ASSERT_EQ(AsmFcmgt(two, two), 0x0000000000000000ULL);
   ASSERT_EQ(AsmFcmgt(six, two), 0xffffffffffffffffULL);
-  ASSERT_EQ(AsmFcmgt(kDefaultNaN64, two), 0x0000000000000000ULL);
-  ASSERT_EQ(AsmFcmgt(two, kDefaultNaN64), 0x0000000000000000ULL);
+  ASSERT_EQ(AsmFcmgt(kDefaultNaN64AsInteger, two), 0x0000000000000000ULL);
+  ASSERT_EQ(AsmFcmgt(two, kDefaultNaN64AsInteger), 0x0000000000000000ULL);
 }
 
 TEST(Arm64InsnTest, CompareGreaterF64x2) {
@@ -4048,6 +4138,13 @@ TEST(Arm64InsnTest, ShiftLeftInt8x8) {
   ASSERT_EQ(res, MakeUInt128(0x00804000c0004040ULL, 0x0000000000000000ULL));
 }
 
+TEST(Arm64InsnTest, ShiftRightInsertInt8x8) {
+  __uint128_t arg1 = MakeUInt128(0x9112232618794059ULL, 0x9415540632701319ULL);
+  __uint128_t arg2 = MakeUInt128(0x1537675115830432ULL, 0x0849872092028092ULL);
+  __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_W0_ARG("sri %0.8b, %1.8b, #4")(arg1, arg2);
+  ASSERT_EQ(res, MakeUInt128(0x1931625211870435ULL, 0x0000000000000000ULL));
+}
+
 TEST(Arm64InsnTest, ShiftRightInsertInt64x1) {
   __uint128_t arg1 = MakeUInt128(0x9112232618794059ULL, 0x9415540632701319ULL);
   __uint128_t arg2 = MakeUInt128(0x1537675115830432ULL, 0x0849872092028092ULL);
@@ -4082,6 +4179,12 @@ TEST(Arm64InsnTest, ShiftLeftLongInt8x8) {
   ASSERT_EQ(res, MakeUInt128(0x2000200019009500ULL, 0x2600500069007600ULL));
 }
 
+TEST(Arm64InsnTest, UnsignedShiftLeftLongInt8x8) {
+  __uint128_t arg = MakeUInt128(0x2650697620201995ULL, 0x5484126500053944ULL);
+  __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("ushll %0.8h, %1.8b, #4")(arg);
+  ASSERT_EQ(res, MakeUInt128(0x200020001900950ULL, 0x260050006900760ULL));
+}
+
 TEST(Arm64InsnTest, ShiftLeftLongInt8x8Upper) {
   __uint128_t arg = MakeUInt128(0x9050429225978771ULL, 0x0667873840000616ULL);
   __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("shll2 %0.8h, %1.16b, #8")(arg);
@@ -6197,12 +6300,30 @@ TEST(Arm64InsnTest, UnsignedAbsoluteDifferenceAccumulateLongUpperInt16x8) {
   ASSERT_EQ(res, MakeUInt128(0x0988d34d9911b302ULL, 0x0235397b7046c371ULL));
 }
 
+TEST(Arm64InsnTest, SignedAddLongPairwiseInt8x8) {
+  __uint128_t arg = MakeUInt128(0x6164411096256633ULL, 0x7305409219519675ULL);
+  __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("saddlp %0.4h, %1.8b")(arg);
+  ASSERT_EQ(res, MakeUInt128(0x00c50051ffbb0099ULL, 0x0000000000000000ULL));
+}
+
 TEST(Arm64InsnTest, SignedAddLongPairwiseInt8x16) {
   __uint128_t arg = MakeUInt128(0x6164411096256633ULL, 0x7305409219519675ULL);
   __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("saddlp %0.8h, %1.16b")(arg);
   ASSERT_EQ(res, MakeUInt128(0x00c50051ffbb0099ULL, 0x0078ffd2006a000bULL));
 }
 
+TEST(Arm64InsnTest, SignedAddLongPairwiseInt16x4) {
+  __uint128_t arg = MakeUInt128(0x6164411096256633ULL, 0x7305409219519675ULL);
+  __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("saddlp %0.2s, %1.4h")(arg);
+  ASSERT_EQ(res, MakeUInt128(0x0000a274fffffc58ULL, 0x0000000000000000ULL));
+}
+
+TEST(Arm64InsnTest, SignedAddLongPairwiseInt16x8) {
+  __uint128_t arg = MakeUInt128(0x6164411096256633ULL, 0x7305409219519675ULL);
+  __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("saddlp %0.4s, %1.8h")(arg);
+  ASSERT_EQ(res, MakeUInt128(0xa274fffffc58ULL, 0xb397ffffafc6ULL));
+}
+
 TEST(Arm64InsnTest, SignedAddAccumulateLongPairwiseInt8x16) {
   __uint128_t arg1 = MakeUInt128(0x1991646384142707ULL, 0x7988708874229277ULL);
   __uint128_t arg2 = MakeUInt128(0x7217826030500994ULL, 0x5108247835729056ULL);
@@ -6286,13 +6407,27 @@ TEST(Arm64InsnTest, UnsignedSubLongUpper) {
   ASSERT_EQ(res, MakeUInt128(0x00002e81ffffcaf5ULL, 0x0000093400005058ULL));
 }
 
-TEST(Arm64InsnTest, SignedAddWide) {
+TEST(Arm64InsnTest, SignedAddWide8x8) {
+  __uint128_t arg1 = MakeUInt128(0x7844598183134112ULL, 0x9001999205981352ULL);
+  __uint128_t arg2 = MakeUInt128(0x2051173365856407ULL, 0x8264849427644113ULL);
+  __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("saddw %0.8h, %1.8h, %2.8b")(arg1, arg2);
+  ASSERT_EQ(res, MakeUInt128(0x78a9590683774119ULL, 0x902199e305af1385ULL));
+}
+
+TEST(Arm64InsnTest, SignedAddWide16x4) {
   __uint128_t arg1 = MakeUInt128(0x7844598183134112ULL, 0x9001999205981352ULL);
   __uint128_t arg2 = MakeUInt128(0x2051173365856407ULL, 0x8264849427644113ULL);
   __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("saddw %0.4s, %1.4s, %2.4h")(arg1, arg2);
   ASSERT_EQ(res, MakeUInt128(0x7844bf068313a519ULL, 0x9001b9e305982a85ULL));
 }
 
+TEST(Arm64InsnTest, SignedAddWide32x2) {
+  __uint128_t arg1 = MakeUInt128(0x7844598183134112ULL, 0x9001999205981352ULL);
+  __uint128_t arg2 = MakeUInt128(0x2051173365856407ULL, 0x8264849427644113ULL);
+  __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("saddw %0.2d, %1.2d, %2.2s")(arg1, arg2);
+  ASSERT_EQ(res, MakeUInt128(0x78445981e898a519ULL, 0x9001999225e92a85ULL));
+}
+
 TEST(Arm64InsnTest, SignedAddWideUpper) {
   __uint128_t arg1 = MakeUInt128(0x3407092233436577ULL, 0x9160128093179401ULL);
   __uint128_t arg2 = MakeUInt128(0x7185985999338492ULL, 0x3549564005709955ULL);
@@ -6314,13 +6449,27 @@ TEST(Arm64InsnTest, SignedSubWideUpper) {
   ASSERT_EQ(res, MakeUInt128(0x4510f0338356d684ULL, 0x691963ef5467342fULL));
 }
 
-TEST(Arm64InsnTest, UnsignedAddWide) {
+TEST(Arm64InsnTest, UnsignedAddWide8x8) {
+  __uint128_t arg1 = MakeUInt128(0x5870785951298344ULL, 0x1729535195378855ULL);
+  __uint128_t arg2 = MakeUInt128(0x3457374260859029ULL, 0x0817651557803905ULL);
+  __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("uaddw %0.8h, %1.8h, %2.8b")(arg1, arg2);
+  ASSERT_EQ(res, MakeUInt128(0x58d078de51b9836dULL, 0x175d53a8956e8897ULL));
+}
+
+TEST(Arm64InsnTest, UnsignedAddWide16x4) {
   __uint128_t arg1 = MakeUInt128(0x5870785951298344ULL, 0x1729535195378855ULL);
   __uint128_t arg2 = MakeUInt128(0x3457374260859029ULL, 0x0817651557803905ULL);
   __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("uaddw %0.4s, %1.4s, %2.4h")(arg1, arg2);
   ASSERT_EQ(res, MakeUInt128(0x5870d8de512a136dULL, 0x172987a89537bf97ULL));
 }
 
+TEST(Arm64InsnTest, UnsignedAddWide32x2) {
+  __uint128_t arg1 = MakeUInt128(0x5870785951298344ULL, 0x1729535195378855ULL);
+  __uint128_t arg2 = MakeUInt128(0x3457374260859029ULL, 0x0817651557803905ULL);
+  __uint128_t res = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("uaddw %0.2d, %1.2d, %2.2s")(arg1, arg2);
+  ASSERT_EQ(res, MakeUInt128(0x58707859b1af136dULL, 0x17295351c98ebf97ULL));
+}
+
 TEST(Arm64InsnTest, UnsignedAddWideUpper) {
   __uint128_t arg1 = MakeUInt128(0x7516493270950493ULL, 0x4639382432227188ULL);
   __uint128_t arg2 = MakeUInt128(0x5159740547021482ULL, 0x8971117779237612ULL);
diff --git a/tests/inline_asm_tests/main_riscv64.cc b/tests/inline_asm_tests/main_riscv64.cc
index 616d54d1..baaedcd1 100644
--- a/tests/inline_asm_tests/main_riscv64.cc
+++ b/tests/inline_asm_tests/main_riscv64.cc
@@ -415,12 +415,16 @@ void RunCommonVectorFunc(ExecInsnFunc exec_insn,
                          uint64_t vtype,
                          uint64_t vlin) {
   uint64_t unused_local;
-  if (scalar_int_res == nullptr) {
+  if (!scalar_int_res) {
     scalar_int_res = &unused_local;
   }
-  if (scalar_float_res == nullptr) {
+  if (!scalar_float_res) {
     scalar_float_res = &unused_local;
   }
+  SIMD128Register unused_simd_local[8];
+  if (!res) {
+    res = &unused_simd_local[0];
+  }
 
   uint64_t vl = vlin;
   // Mask register is, unconditionally, v0, and we need 8 or 24 to handle full 8-registers
@@ -12393,6 +12397,32 @@ TEST(InlineAsmTestRiscv64, TestVslideup) {
       /*skip=*/8);
 }
 
+[[gnu::naked]] void ExecVfirstm() {
+  asm("vfirst.m t0, v16\n\t"
+      "ret\n\t");
+}
+
+TEST(InlineAsmTestRiscv64, TestVfirstm) {
+  SIMD128Register source[16]{};
+  SIMD128Register unused_result[8]{};
+  // Setup 8-bit elements in 8 registers to involve all 128 bits in vl. Masks and tail processing
+  // aren't used in this test.
+  uint64_t vtype = 3;
+  for (uint64_t bit = 0; bit < 128; bit++) {
+    uint64_t result{~uint64_t{0}};
+    source[0] = __uint128_t{1} << bit;
+    RunCommonVectorFunc(
+        &ExecVfirstm, &source[0], nullptr, &result, nullptr, 0, 0, vtype, /*vl*/ 128);
+    EXPECT_EQ(result, bit);
+  }
+
+  // Also test the zero special case.
+  uint64_t result{0};
+  source[0] = __uint128_t{0};
+  RunCommonVectorFunc(&ExecVfirstm, &source[0], nullptr, &result, nullptr, 0, 0, vtype, /*vl*/ 128);
+  EXPECT_EQ(result, ~uint64_t{0});
+}
+
 }  // namespace
 
 }  // namespace berberis
diff --git a/tests/inline_asm_tests/precise_fp_arm64.cc b/tests/inline_asm_tests/precise_fp_arm64.cc
index 1ecdc2a7..ec623843 100644
--- a/tests/inline_asm_tests/precise_fp_arm64.cc
+++ b/tests/inline_asm_tests/precise_fp_arm64.cc
@@ -26,65 +26,65 @@ namespace {
 TEST(Arm64InsnTest, AddFp32PreciseNaN) {
   // Verify that FADD canonicalizes a qNaN to the default NaN.
   constexpr auto AsmFadd = ASM_INSN_WRAP_FUNC_W_RES_WWC_ARG("fadd %s0, %s1, %s2");
-  ASSERT_EQ(AsmFadd(kQuietNaN32, kOneF32, kFpcrDnBit), kDefaultNaN32);
+  ASSERT_EQ(AsmFadd(kQuietNaN32AsInteger, kOneF32AsInteger, kFpcrDnBit), kDefaultNaN32AsInteger);
 }
 
 TEST(Arm64InsnTest, AddFp64PreciseNaN) {
   // Verify that FADD canonicalizes a qNaN to the default NaN.
   constexpr auto AsmFadd = ASM_INSN_WRAP_FUNC_W_RES_WWC_ARG("fadd %d0, %d1, %d2");
-  ASSERT_EQ(AsmFadd(kQuietNaN64, kOneF64, kFpcrDnBit), kDefaultNaN64);
+  ASSERT_EQ(AsmFadd(kQuietNaN64AsInteger, kOneF64AsInteger, kFpcrDnBit), kDefaultNaN64AsInteger);
 }
 
 TEST(Arm64InsnTest, SubFp32PreciseNaN) {
   // Verify that FSUB canonicalizes a qNaN to the default NaN.
   constexpr auto AsmFsub = ASM_INSN_WRAP_FUNC_W_RES_WWC_ARG("fsub %s0, %s1, %s2");
-  ASSERT_EQ(AsmFsub(kQuietNaN32, kOneF32, kFpcrDnBit), kDefaultNaN32);
+  ASSERT_EQ(AsmFsub(kQuietNaN32AsInteger, kOneF32AsInteger, kFpcrDnBit), kDefaultNaN32AsInteger);
 }
 
 TEST(Arm64InsnTest, SubFp64PreciseNaN) {
   // Verify that FSUB canonicalizes a qNaN to the default NaN.
   constexpr auto AsmFsub = ASM_INSN_WRAP_FUNC_W_RES_WWC_ARG("fsub %d0, %d1, %d2");
-  ASSERT_EQ(AsmFsub(kQuietNaN64, kOneF64, kFpcrDnBit), kDefaultNaN64);
+  ASSERT_EQ(AsmFsub(kQuietNaN64AsInteger, kOneF64AsInteger, kFpcrDnBit), kDefaultNaN64AsInteger);
 }
 
 TEST(Arm64InsnTest, MulFp32PreciseNaN) {
   // Verify that FMUL canonicalizes a qNaN to the default NaN.
   constexpr auto AsmFmul = ASM_INSN_WRAP_FUNC_W_RES_WWC_ARG("fmul %s0, %s1, %s2");
-  ASSERT_EQ(AsmFmul(kQuietNaN32, kOneF32, kFpcrDnBit), kDefaultNaN32);
+  ASSERT_EQ(AsmFmul(kQuietNaN32AsInteger, kOneF32AsInteger, kFpcrDnBit), kDefaultNaN32AsInteger);
 }
 
 TEST(Arm64InsnTest, MulFp64PreciseNaN) {
   // Verify that FMUL canonicalizes a qNaN to the default NaN.
   constexpr auto AsmFmul = ASM_INSN_WRAP_FUNC_W_RES_WWC_ARG("fmul %d0, %d1, %d2");
-  ASSERT_EQ(AsmFmul(kQuietNaN64, kOneF64, kFpcrDnBit), kDefaultNaN64);
+  ASSERT_EQ(AsmFmul(kQuietNaN64AsInteger, kOneF64AsInteger, kFpcrDnBit), kDefaultNaN64AsInteger);
 }
 
 TEST(Arm64InsnTest, DivFp32PreciseNaN) {
   constexpr auto AsmFdiv = ASM_INSN_WRAP_FUNC_W_RES_WWC_ARG("fdiv %s0, %s1, %s2");
 
   // Verify that FDIV canonicalizes a qNaN to the default NaN.
-  __uint128_t arg1 = kDefaultNaN32 | (1U << 31);  // A qNaN
+  __uint128_t arg1 = kDefaultNaN32AsInteger | (1U << 31);  // A qNaN
   __uint128_t arg2 = bit_cast<uint32_t>(1.0f);
-  ASSERT_EQ(AsmFdiv(arg1, arg2, kFpcrDnBit), kDefaultNaN32);
+  ASSERT_EQ(AsmFdiv(arg1, arg2, kFpcrDnBit), kDefaultNaN32AsInteger);
 }
 
 TEST(Arm64InsnTest, DivFp64PreciseNaN) {
   constexpr auto AsmFdiv = ASM_INSN_WRAP_FUNC_W_RES_WWC_ARG("fdiv %d0, %d1, %d2");
 
   // Verify that FDIV canonicalizes a qNaN to the default NaN.
-  __uint128_t arg1 = kDefaultNaN64 | (1ULL << 63);  // A qNaN
+  __uint128_t arg1 = kDefaultNaN64AsInteger | (1ULL << 63);  // A qNaN
   __uint128_t arg2 = bit_cast<uint64_t>(1.0);
-  ASSERT_EQ(AsmFdiv(arg1, arg2, kFpcrDnBit), kDefaultNaN64);
+  ASSERT_EQ(AsmFdiv(arg1, arg2, kFpcrDnBit), kDefaultNaN64AsInteger);
 }
 
 TEST(Arm64InsnTest, DivFp64x2PreciseNaN) {
   constexpr auto AsmFdiv = ASM_INSN_WRAP_FUNC_W_RES_WWC_ARG("fdiv %0.2d, %1.2d, %2.2d");
 
   // Verify that FDIV canonicalizes a qNaN to the default NaN.
-  __uint128_t arg1 = MakeUInt128(bit_cast<uint64_t>(2.0), kDefaultNaN64 | (1ULL << 63));
+  __uint128_t arg1 = MakeUInt128(bit_cast<uint64_t>(2.0), kDefaultNaN64AsInteger | (1ULL << 63));
   __uint128_t arg2 = MakeF64x2(1.0, 1.0);
   __uint128_t res = AsmFdiv(arg1, arg2, kFpcrDnBit);
-  ASSERT_EQ(res, MakeUInt128(bit_cast<uint64_t>(2.0), kDefaultNaN64));
+  ASSERT_EQ(res, MakeUInt128(bit_cast<uint64_t>(2.0), kDefaultNaN64AsInteger));
 }
 
 TEST(Arm64InsnTest, MaxFp32PreciseNaN) {
@@ -92,13 +92,18 @@ TEST(Arm64InsnTest, MaxFp32PreciseNaN) {
   uint32_t fp_arg_two = bit_cast<uint32_t>(2.0f);
   uint32_t fp_arg_minus_two = bit_cast<uint32_t>(-2.0f);
 
-  ASSERT_EQ(AsmFmax(fp_arg_two, kQuietNaN32), MakeU32x4(kQuietNaN32, 0, 0, 0));
-  ASSERT_EQ(AsmFmax(fp_arg_minus_two, kQuietNaN32), MakeU32x4(kQuietNaN32, 0, 0, 0));
-  ASSERT_EQ(AsmFmax(kQuietNaN32, fp_arg_two), MakeU32x4(kQuietNaN32, 0, 0, 0));
-  ASSERT_EQ(AsmFmax(kQuietNaN32, fp_arg_minus_two), MakeU32x4(kQuietNaN32, 0, 0, 0));
-  ASSERT_EQ(AsmFmax(kSignalingNaN32_1, fp_arg_two), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
-  ASSERT_EQ(AsmFmax(kSignalingNaN32_1, fp_arg_minus_two), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
-  ASSERT_EQ(AsmFmax(kQuietNaN32, kSignalingNaN32_1), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
+  ASSERT_EQ(AsmFmax(fp_arg_two, kQuietNaN32AsInteger), MakeU32x4(kQuietNaN32AsInteger, 0, 0, 0));
+  ASSERT_EQ(AsmFmax(fp_arg_minus_two, kQuietNaN32AsInteger),
+            MakeU32x4(kQuietNaN32AsInteger, 0, 0, 0));
+  ASSERT_EQ(AsmFmax(kQuietNaN32AsInteger, fp_arg_two), MakeU32x4(kQuietNaN32AsInteger, 0, 0, 0));
+  ASSERT_EQ(AsmFmax(kQuietNaN32AsInteger, fp_arg_minus_two),
+            MakeU32x4(kQuietNaN32AsInteger, 0, 0, 0));
+  ASSERT_EQ(AsmFmax(kSignalingNaN32AsInteger_1, fp_arg_two),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
+  ASSERT_EQ(AsmFmax(kSignalingNaN32AsInteger_1, fp_arg_minus_two),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
+  ASSERT_EQ(AsmFmax(kQuietNaN32AsInteger, kSignalingNaN32AsInteger_1),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
 }
 
 TEST(Arm64InsnTest, MaxFp64PreciseNaN) {
@@ -106,13 +111,16 @@ TEST(Arm64InsnTest, MaxFp64PreciseNaN) {
   uint64_t fp_arg_two = bit_cast<uint64_t>(2.0);
   uint64_t fp_arg_minus_two = bit_cast<uint64_t>(-2.0);
 
-  ASSERT_EQ(AsmFmax(fp_arg_two, kQuietNaN64), MakeUInt128(kQuietNaN64, 0U));
-  ASSERT_EQ(AsmFmax(fp_arg_minus_two, kQuietNaN64), MakeUInt128(kQuietNaN64, 0));
-  ASSERT_EQ(AsmFmax(kQuietNaN64, fp_arg_two), MakeUInt128(kQuietNaN64, 0));
-  ASSERT_EQ(AsmFmax(kQuietNaN64, fp_arg_minus_two), MakeUInt128(kQuietNaN64, 0));
-  ASSERT_EQ(AsmFmax(kSignalingNaN64_1, fp_arg_two), MakeUInt128(kQuietNaN64_1, 0));
-  ASSERT_EQ(AsmFmax(kSignalingNaN64_1, fp_arg_minus_two), MakeUInt128(kQuietNaN64_1, 0));
-  ASSERT_EQ(AsmFmax(kQuietNaN64, kSignalingNaN64_1), MakeUInt128(kQuietNaN64_1, 0));
+  ASSERT_EQ(AsmFmax(fp_arg_two, kQuietNaN64AsInteger), MakeUInt128(kQuietNaN64AsInteger, 0U));
+  ASSERT_EQ(AsmFmax(fp_arg_minus_two, kQuietNaN64AsInteger), MakeUInt128(kQuietNaN64AsInteger, 0));
+  ASSERT_EQ(AsmFmax(kQuietNaN64AsInteger, fp_arg_two), MakeUInt128(kQuietNaN64AsInteger, 0));
+  ASSERT_EQ(AsmFmax(kQuietNaN64AsInteger, fp_arg_minus_two), MakeUInt128(kQuietNaN64AsInteger, 0));
+  ASSERT_EQ(AsmFmax(kSignalingNaN64AsInteger_1, fp_arg_two),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
+  ASSERT_EQ(AsmFmax(kSignalingNaN64AsInteger_1, fp_arg_minus_two),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
+  ASSERT_EQ(AsmFmax(kQuietNaN64AsInteger, kSignalingNaN64AsInteger_1),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
 }
 
 TEST(Arm64InsnTest, MaxNumberFp32PreciseNaN) {
@@ -120,10 +128,14 @@ TEST(Arm64InsnTest, MaxNumberFp32PreciseNaN) {
   uint32_t fp_arg_two = bit_cast<uint32_t>(2.0f);
   uint64_t fp_arg_minus_two = bit_cast<uint64_t>(-2.0);
 
-  ASSERT_EQ(AsmFmaxnm(kSignalingNaN32_1, fp_arg_two), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
-  ASSERT_EQ(AsmFmaxnm(fp_arg_two, kSignalingNaN32_1), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
-  ASSERT_EQ(AsmFmaxnm(kSignalingNaN32_1, fp_arg_minus_two), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
-  ASSERT_EQ(AsmFmaxnm(kQuietNaN32, kSignalingNaN32_1), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
+  ASSERT_EQ(AsmFmaxnm(kSignalingNaN32AsInteger_1, fp_arg_two),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
+  ASSERT_EQ(AsmFmaxnm(fp_arg_two, kSignalingNaN32AsInteger_1),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
+  ASSERT_EQ(AsmFmaxnm(kSignalingNaN32AsInteger_1, fp_arg_minus_two),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
+  ASSERT_EQ(AsmFmaxnm(kQuietNaN32AsInteger, kSignalingNaN32AsInteger_1),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
 }
 
 TEST(Arm64InsnTest, MaxNumberFp64PreciseNaN) {
@@ -131,10 +143,14 @@ TEST(Arm64InsnTest, MaxNumberFp64PreciseNaN) {
   uint64_t fp_arg_two = bit_cast<uint64_t>(2.0);
   uint64_t fp_arg_minus_two = bit_cast<uint64_t>(-2.0);
 
-  ASSERT_EQ(AsmFmaxnm(kSignalingNaN64_1, fp_arg_two), MakeUInt128(kQuietNaN64_1, 0));
-  ASSERT_EQ(AsmFmaxnm(fp_arg_two, kSignalingNaN64_1), MakeUInt128(kQuietNaN64_1, 0));
-  ASSERT_EQ(AsmFmaxnm(kSignalingNaN64_1, fp_arg_minus_two), MakeUInt128(kQuietNaN64_1, 0));
-  ASSERT_EQ(AsmFmaxnm(kQuietNaN64, kSignalingNaN64_1), MakeUInt128(kQuietNaN64_1, 0));
+  ASSERT_EQ(AsmFmaxnm(kSignalingNaN64AsInteger_1, fp_arg_two),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
+  ASSERT_EQ(AsmFmaxnm(fp_arg_two, kSignalingNaN64AsInteger_1),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
+  ASSERT_EQ(AsmFmaxnm(kSignalingNaN64AsInteger_1, fp_arg_minus_two),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
+  ASSERT_EQ(AsmFmaxnm(kQuietNaN64AsInteger, kSignalingNaN64AsInteger_1),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
 }
 
 TEST(Arm64InsnTest, MinFp32PreciseNaN) {
@@ -142,13 +158,18 @@ TEST(Arm64InsnTest, MinFp32PreciseNaN) {
   uint32_t fp_arg_two = bit_cast<uint32_t>(2.0f);
   uint32_t fp_arg_minus_two = bit_cast<uint32_t>(-2.0f);
 
-  ASSERT_EQ(AsmFmin(fp_arg_two, kQuietNaN32), MakeU32x4(kQuietNaN32, 0, 0, 0));
-  ASSERT_EQ(AsmFmin(fp_arg_minus_two, kQuietNaN32), MakeU32x4(kQuietNaN32, 0, 0, 0));
-  ASSERT_EQ(AsmFmin(kQuietNaN32, fp_arg_two), MakeU32x4(kQuietNaN32, 0, 0, 0));
-  ASSERT_EQ(AsmFmin(kQuietNaN32, fp_arg_minus_two), MakeU32x4(kQuietNaN32, 0, 0, 0));
-  ASSERT_EQ(AsmFmin(kSignalingNaN32_1, fp_arg_two), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
-  ASSERT_EQ(AsmFmin(kSignalingNaN32_1, fp_arg_minus_two), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
-  ASSERT_EQ(AsmFmin(kQuietNaN32, kSignalingNaN32_1), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
+  ASSERT_EQ(AsmFmin(fp_arg_two, kQuietNaN32AsInteger), MakeU32x4(kQuietNaN32AsInteger, 0, 0, 0));
+  ASSERT_EQ(AsmFmin(fp_arg_minus_two, kQuietNaN32AsInteger),
+            MakeU32x4(kQuietNaN32AsInteger, 0, 0, 0));
+  ASSERT_EQ(AsmFmin(kQuietNaN32AsInteger, fp_arg_two), MakeU32x4(kQuietNaN32AsInteger, 0, 0, 0));
+  ASSERT_EQ(AsmFmin(kQuietNaN32AsInteger, fp_arg_minus_two),
+            MakeU32x4(kQuietNaN32AsInteger, 0, 0, 0));
+  ASSERT_EQ(AsmFmin(kSignalingNaN32AsInteger_1, fp_arg_two),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
+  ASSERT_EQ(AsmFmin(kSignalingNaN32AsInteger_1, fp_arg_minus_two),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
+  ASSERT_EQ(AsmFmin(kQuietNaN32AsInteger, kSignalingNaN32AsInteger_1),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
 }
 
 TEST(Arm64InsnTest, MinFp64PreciseNaN) {
@@ -156,13 +177,16 @@ TEST(Arm64InsnTest, MinFp64PreciseNaN) {
   uint64_t fp_arg_two = bit_cast<uint64_t>(2.0);
   uint64_t fp_arg_minus_two = bit_cast<uint64_t>(-2.0);
 
-  ASSERT_EQ(AsmFmin(fp_arg_two, kQuietNaN64), MakeUInt128(kQuietNaN64, 0U));
-  ASSERT_EQ(AsmFmin(fp_arg_minus_two, kQuietNaN64), MakeUInt128(kQuietNaN64, 0));
-  ASSERT_EQ(AsmFmin(kQuietNaN64, fp_arg_two), MakeUInt128(kQuietNaN64, 0));
-  ASSERT_EQ(AsmFmin(kQuietNaN64, fp_arg_minus_two), MakeUInt128(kQuietNaN64, 0));
-  ASSERT_EQ(AsmFmin(kSignalingNaN64_1, fp_arg_two), MakeUInt128(kQuietNaN64_1, 0));
-  ASSERT_EQ(AsmFmin(kSignalingNaN64_1, fp_arg_minus_two), MakeUInt128(kQuietNaN64_1, 0));
-  ASSERT_EQ(AsmFmin(kQuietNaN64, kSignalingNaN64_1), MakeUInt128(kQuietNaN64_1, 0));
+  ASSERT_EQ(AsmFmin(fp_arg_two, kQuietNaN64AsInteger), MakeUInt128(kQuietNaN64AsInteger, 0U));
+  ASSERT_EQ(AsmFmin(fp_arg_minus_two, kQuietNaN64AsInteger), MakeUInt128(kQuietNaN64AsInteger, 0));
+  ASSERT_EQ(AsmFmin(kQuietNaN64AsInteger, fp_arg_two), MakeUInt128(kQuietNaN64AsInteger, 0));
+  ASSERT_EQ(AsmFmin(kQuietNaN64AsInteger, fp_arg_minus_two), MakeUInt128(kQuietNaN64AsInteger, 0));
+  ASSERT_EQ(AsmFmin(kSignalingNaN64AsInteger_1, fp_arg_two),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
+  ASSERT_EQ(AsmFmin(kSignalingNaN64AsInteger_1, fp_arg_minus_two),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
+  ASSERT_EQ(AsmFmin(kQuietNaN64AsInteger, kSignalingNaN64AsInteger_1),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
 }
 
 TEST(Arm64InsnTest, MinNumberFp32PreciseNaN) {
@@ -170,10 +194,14 @@ TEST(Arm64InsnTest, MinNumberFp32PreciseNaN) {
   uint32_t fp_arg_two = bit_cast<uint32_t>(2.0f);
   uint32_t fp_arg_minus_two = bit_cast<uint32_t>(-2.0f);
 
-  ASSERT_EQ(AsmFminnm(kSignalingNaN32_1, fp_arg_two), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
-  ASSERT_EQ(AsmFminnm(fp_arg_two, kSignalingNaN32_1), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
-  ASSERT_EQ(AsmFminnm(kSignalingNaN32_1, fp_arg_minus_two), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
-  ASSERT_EQ(AsmFminnm(kQuietNaN32, kSignalingNaN32_1), MakeU32x4(kQuietNaN32_1, 0, 0, 0));
+  ASSERT_EQ(AsmFminnm(kSignalingNaN32AsInteger_1, fp_arg_two),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
+  ASSERT_EQ(AsmFminnm(fp_arg_two, kSignalingNaN32AsInteger_1),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
+  ASSERT_EQ(AsmFminnm(kSignalingNaN32AsInteger_1, fp_arg_minus_two),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
+  ASSERT_EQ(AsmFminnm(kQuietNaN32AsInteger, kSignalingNaN32AsInteger_1),
+            MakeU32x4(kQuietNaN32AsInteger_1, 0, 0, 0));
 }
 
 TEST(Arm64InsnTest, MinNumberFp64PreciseNaN) {
@@ -181,89 +209,113 @@ TEST(Arm64InsnTest, MinNumberFp64PreciseNaN) {
   uint64_t fp_arg_two = bit_cast<uint64_t>(2.0);
   uint64_t fp_arg_minus_two = bit_cast<uint64_t>(-2.0);
 
-  ASSERT_EQ(AsmFminnm(kSignalingNaN64_1, fp_arg_two), MakeUInt128(kQuietNaN64_1, 0));
-  ASSERT_EQ(AsmFminnm(fp_arg_two, kSignalingNaN64_1), MakeUInt128(kQuietNaN64_1, 0));
-  ASSERT_EQ(AsmFminnm(kSignalingNaN64_1, fp_arg_minus_two), MakeUInt128(kQuietNaN64_1, 0));
-  ASSERT_EQ(AsmFminnm(kQuietNaN64, kSignalingNaN64_1), MakeUInt128(kQuietNaN64_1, 0));
+  ASSERT_EQ(AsmFminnm(kSignalingNaN64AsInteger_1, fp_arg_two),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
+  ASSERT_EQ(AsmFminnm(fp_arg_two, kSignalingNaN64AsInteger_1),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
+  ASSERT_EQ(AsmFminnm(kSignalingNaN64AsInteger_1, fp_arg_minus_two),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
+  ASSERT_EQ(AsmFminnm(kQuietNaN64AsInteger, kSignalingNaN64AsInteger_1),
+            MakeUInt128(kQuietNaN64AsInteger_1, 0));
 }
 
 TEST(Arm64InsnTest, MaxNumberF32x4PreciseNaN) {
   constexpr auto AsmFmaxnm = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("fmaxnm %0.4s, %1.4s, %2.4s");
-  __uint128_t arg1 = MakeU32x4(
-      bit_cast<uint32_t>(1.0f), bit_cast<uint32_t>(-1.0f), kSignalingNaN32_1, kQuietNaN32);
-  __uint128_t arg2 = MakeU32x4(
-      kSignalingNaN32_1, kQuietNaN32, bit_cast<uint32_t>(1.0f), bit_cast<uint32_t>(-1.0f));
-  ASSERT_EQ(
-      AsmFmaxnm(arg1, arg2),
-      MakeU32x4(
-          kQuietNaN32_1, bit_cast<uint32_t>(-1.0f), kQuietNaN32_1, bit_cast<uint32_t>(-1.0f)));
+  __uint128_t arg1 = MakeU32x4(bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f),
+                               kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger);
+  __uint128_t arg2 = MakeU32x4(kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger,
+                               bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f));
+  ASSERT_EQ(AsmFmaxnm(arg1, arg2),
+            MakeU32x4(kQuietNaN32AsInteger_1,
+                      bit_cast<uint32_t>(-1.0f),
+                      kQuietNaN32AsInteger_1,
+                      bit_cast<uint32_t>(-1.0f)));
 }
 
 TEST(Arm64InsnTest, MaxNumberF64x2PreciseNaN) {
   constexpr auto AsmFmaxnm = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("fmaxnm %0.2d, %1.2d, %2.2d");
-  __uint128_t arg1 = MakeUInt128(bit_cast<uint64_t>(1.0), kSignalingNaN64_1);
-  __uint128_t arg2 = MakeUInt128(kSignalingNaN64_1, bit_cast<uint64_t>(-1.0));
-  ASSERT_EQ(AsmFmaxnm(arg1, arg2), MakeUInt128(kQuietNaN64_1, kQuietNaN64_1));
+  __uint128_t arg1 = MakeUInt128(bit_cast<uint64_t>(1.0), kSignalingNaN64AsInteger_1);
+  __uint128_t arg2 = MakeUInt128(kSignalingNaN64AsInteger_1, bit_cast<uint64_t>(-1.0));
+  ASSERT_EQ(AsmFmaxnm(arg1, arg2), MakeUInt128(kQuietNaN64AsInteger_1, kQuietNaN64AsInteger_1));
 }
 
 TEST(Arm64InsnTest, MinNumberF32x4PreciseNaN) {
   constexpr auto AsmFminnm = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("fminnm %0.4s, %1.4s, %2.4s");
-  __uint128_t arg1 = MakeU32x4(
-      bit_cast<uint32_t>(1.0f), bit_cast<uint32_t>(-1.0f), kSignalingNaN32_1, kQuietNaN32);
-  __uint128_t arg2 = MakeU32x4(
-      kSignalingNaN32_1, kQuietNaN32, bit_cast<uint32_t>(1.0f), bit_cast<uint32_t>(-1.0f));
-  ASSERT_EQ(
-      AsmFminnm(arg1, arg2),
-      MakeU32x4(
-          kQuietNaN32_1, bit_cast<uint32_t>(-1.0f), kQuietNaN32_1, bit_cast<uint32_t>(-1.0f)));
+  __uint128_t arg1 = MakeU32x4(bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f),
+                               kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger);
+  __uint128_t arg2 = MakeU32x4(kSignalingNaN32AsInteger_1,
+                               kQuietNaN32AsInteger,
+                               bit_cast<uint32_t>(1.0f),
+                               bit_cast<uint32_t>(-1.0f));
+  ASSERT_EQ(AsmFminnm(arg1, arg2),
+            MakeU32x4(kQuietNaN32AsInteger_1,
+                      bit_cast<uint32_t>(-1.0f),
+                      kQuietNaN32AsInteger_1,
+                      bit_cast<uint32_t>(-1.0f)));
 }
 
 TEST(Arm64InsnTest, MinNumberF64x2PreciseNaN) {
   constexpr auto AsmFminnm = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("fminnm %0.2d, %1.2d, %2.2d");
-  __uint128_t arg1 = MakeUInt128(bit_cast<uint64_t>(1.0), kSignalingNaN64_1);
-  __uint128_t arg2 = MakeUInt128(kSignalingNaN64_1, bit_cast<uint64_t>(-1.0));
-  ASSERT_EQ(AsmFminnm(arg1, arg2), MakeUInt128(kQuietNaN64_1, kQuietNaN64_1));
+  __uint128_t arg1 = MakeUInt128(bit_cast<uint64_t>(1.0), kSignalingNaN64AsInteger_1);
+  __uint128_t arg2 = MakeUInt128(kSignalingNaN64AsInteger_1, bit_cast<uint64_t>(-1.0));
+  ASSERT_EQ(AsmFminnm(arg1, arg2), MakeUInt128(kQuietNaN64AsInteger_1, kQuietNaN64AsInteger_1));
 }
 
 TEST(Arm64InsnTest, MaxPairwiseNumberF32ScalarPreciseNaN) {
   constexpr auto AsmFmaxnmp = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("fmaxnmp %s0, %1.2s");
-  __uint128_t arg = MakeF32x4(bit_cast<float>(kSignalingNaN32_1), 2.0f, 7.0f, -0.0f);
-  ASSERT_EQ(AsmFmaxnmp(arg), kQuietNaN32_1);
+  __uint128_t arg = MakeF32x4(bit_cast<float>(kSignalingNaN32AsInteger_1), 2.0f, 7.0f, -0.0f);
+  ASSERT_EQ(AsmFmaxnmp(arg), kQuietNaN32AsInteger_1);
 }
 
 TEST(Arm64InsnTest, MaxPairwiseNumberF32x4PreciseNaN) {
   constexpr auto AsmFmaxnmp = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("fmaxnmp %0.4s, %1.4s, %2.4s");
-  __uint128_t arg1 =
-      MakeF32x4(bit_cast<float>(kSignalingNaN32_1), 2.0f, 7.0f, bit_cast<float>(kSignalingNaN32_1));
+  __uint128_t arg1 = MakeF32x4(bit_cast<float>(kSignalingNaN32AsInteger_1),
+                               2.0f,
+                               7.0f,
+                               bit_cast<float>(kSignalingNaN32AsInteger_1));
   __uint128_t arg2 = MakeF32x4(6.0f, 1.0f, -8.0f, 5.0f);
   ASSERT_EQ(AsmFmaxnmp(arg1, arg2),
-            MakeF32x4(bit_cast<float>(kQuietNaN32_1), bit_cast<float>(kQuietNaN32_1), 6.0f, 5.0f));
+            MakeF32x4(bit_cast<float>(kQuietNaN32AsInteger_1),
+                      bit_cast<float>(kQuietNaN32AsInteger_1),
+                      6.0f,
+                      5.0f));
 }
 
 TEST(Arm64InsnTest, MinPairwiseNumberF32ScalarPreciseNaN) {
   constexpr auto AsmFminnmp = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("fminnmp %s0, %1.2s");
-  __uint128_t arg = MakeF32x4(bit_cast<float>(kSignalingNaN32_1), 2.0f, 7.0f, -0.0f);
-  ASSERT_EQ(AsmFminnmp(arg), kQuietNaN32_1);
+  __uint128_t arg = MakeF32x4(bit_cast<float>(kSignalingNaN32AsInteger_1), 2.0f, 7.0f, -0.0f);
+  ASSERT_EQ(AsmFminnmp(arg), kQuietNaN32AsInteger_1);
 }
 
 TEST(Arm64InsnTest, MinPairwiseNumberF32x4PreciseNaN) {
   constexpr auto AsmFminnmp = ASM_INSN_WRAP_FUNC_W_RES_WW_ARG("fminnmp %0.4s, %1.4s, %2.4s");
-  __uint128_t arg1 =
-      MakeF32x4(bit_cast<float>(kSignalingNaN32_1), 2.0f, 7.0f, bit_cast<float>(kSignalingNaN32_1));
+  __uint128_t arg1 = MakeF32x4(bit_cast<float>(kSignalingNaN32AsInteger_1),
+                               2.0f,
+                               7.0f,
+                               bit_cast<float>(kSignalingNaN32AsInteger_1));
   __uint128_t arg2 = MakeF32x4(6.0f, 1.0f, -8.0f, 5.0f);
   ASSERT_EQ(AsmFminnmp(arg1, arg2),
-            MakeF32x4(bit_cast<float>(kQuietNaN32_1), bit_cast<float>(kQuietNaN32_1), 1.0f, -8.0f));
+            MakeF32x4(bit_cast<float>(kQuietNaN32AsInteger_1),
+                      bit_cast<float>(kQuietNaN32AsInteger_1),
+                      1.0f,
+                      -8.0f));
 }
 
 TEST(Arm64InsnTest, MaxNumberAcrossF32x4PreciseNaN) {
   constexpr auto AsmFmaxnmv = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("fmaxnmv %s0, %1.4s");
-  __uint128_t arg = MakeF32x4(0.0f, 2.0f, 3.0f, bit_cast<float>(kSignalingNaN32_1));
+  __uint128_t arg = MakeF32x4(0.0f, 2.0f, 3.0f, bit_cast<float>(kSignalingNaN32AsInteger_1));
   ASSERT_EQ(AsmFmaxnmv(arg), bit_cast<uint32_t>(2.0f));
 }
 
 TEST(Arm64InsnTest, MinNumberAcrossF32x4PreciseNaN) {
   constexpr auto AsmFminnmv = ASM_INSN_WRAP_FUNC_W_RES_W_ARG("fminnmv %s0, %1.4s");
-  __uint128_t arg = MakeF32x4(0.0f, 2.0f, 3.0f, bit_cast<float>(kSignalingNaN32_1));
+  __uint128_t arg = MakeF32x4(0.0f, 2.0f, 3.0f, bit_cast<float>(kSignalingNaN32AsInteger_1));
   ASSERT_EQ(AsmFminnmv(arg), bit_cast<uint32_t>(0.0f));
 }
 
@@ -273,9 +325,9 @@ TEST(Arm64InsnTest, AbdF64PreciseNaN) {
   // bit.  This means that if the difference is a "negative" NaN, then FABD
   // produces the positive one.  That is, a NaN input doesn't necessarily
   // propagate to the result as is even with the Default NaN mode turned off.
-  uint64_t arg1 = kDefaultNaN64 | (1ULL << 63);  // A "negative" qNaN
+  uint64_t arg1 = kDefaultNaN64AsInteger | (1ULL << 63);  // A "negative" qNaN
   uint64_t arg2 = bit_cast<uint32_t>(1.0f);
-  ASSERT_EQ(AsmFabd(arg1, arg2), kDefaultNaN64);
+  ASSERT_EQ(AsmFabd(arg1, arg2), kDefaultNaN64AsInteger);
 }
 
 TEST(Arm64InsnTest, DivFp32FlushToZero) {
@@ -320,7 +372,7 @@ TEST(Arm64InsnTest, AddFp64FpStatusIoc) {
   constexpr auto AsmFadd = ASM_INSN_WRAP_FUNC_WQ_RES_WW_ARG("fadd %d0, %d2, %d3");
 
   uint64_t fp_arg1 = 0x7ff4000000000000ULL;  // Nan
-  uint64_t fp_arg2 = kOneF64;
+  uint64_t fp_arg2 = kOneF64AsInteger;
   auto [res, fpsr] = AsmFadd(fp_arg1, fp_arg2);
   ASSERT_EQ(res, MakeUInt128(0x7ffc000000000000ULL, 0x0000000000000000ULL));
   ASSERT_EQ(fpsr, kFpsrIocBit);
diff --git a/tests/inline_asm_tests/utility.h b/tests/inline_asm_tests/utility.h
index 53acf17e..2777cce7 100644
--- a/tests/inline_asm_tests/utility.h
+++ b/tests/inline_asm_tests/utility.h
@@ -51,17 +51,19 @@ constexpr __uint128_t MakeU32x4(uint32_t u0, uint32_t u1, uint32_t u2, uint32_t
 }
 
 // Floating-point literals
-constexpr uint32_t kOneF32 = 0x3f800000U;
-constexpr uint64_t kOneF64 = 0x3ff0000000000000ULL;
-constexpr uint32_t kDefaultNaN32 = 0x7fc00000U;
-constexpr uint64_t kDefaultNaN64 = 0x7ff8000000000000ULL;
-constexpr uint32_t kQuietNaN32 = kDefaultNaN32;
-constexpr uint64_t kQuietNaN64 = kDefaultNaN64;
+constexpr uint32_t kOneF32AsInteger = 0x3f800000U;
+constexpr uint64_t kOneF64AsInteger = 0x3ff0000000000000ULL;
+constexpr uint32_t kDefaultNaN32AsInteger = 0x7fc00000U;
+constexpr uint64_t kDefaultNaN64AsInteger = 0x7ff8000000000000ULL;
+constexpr uint32_t kQuietNaN32AsInteger = kDefaultNaN32AsInteger;
+constexpr uint64_t kQuietNaN64AsInteger = kDefaultNaN64AsInteger;
+constexpr uint32_t kNegativeQuietNaN32AsInteger = kDefaultNaN32AsInteger ^ 0x80000000U;
+constexpr uint64_t kNegativeQuietNaN64 = kDefaultNaN64AsInteger ^ 8000000000000000ULL;
 // There are multiple quiet and signaling NaNs. These are the ones that have the LSB "on".
-constexpr uint32_t kSignalingNaN32_1 = 0x7f800001U;
-constexpr uint64_t kSignalingNaN64_1 = 0x7ff0000000000001ULL;
-constexpr uint32_t kQuietNaN32_1 = kQuietNaN32 | 1;
-constexpr uint64_t kQuietNaN64_1 = kQuietNaN64 | 1;
+constexpr uint32_t kSignalingNaN32AsInteger_1 = 0x7f800001U;
+constexpr uint64_t kSignalingNaN64AsInteger_1 = 0x7ff0000000000001ULL;
+constexpr uint32_t kQuietNaN32AsInteger_1 = kQuietNaN32AsInteger | 1;
+constexpr uint64_t kQuietNaN64AsInteger_1 = kQuietNaN64AsInteger | 1;
 
 constexpr uint32_t kFpcrFzBit = 1U << 24;
 constexpr uint32_t kFpcrDnBit = 1U << 25;
diff --git a/tests/ndk_program_tests/Android.bp b/tests/ndk_program_tests/Android.bp
index c7121cc0..84ab38c4 100644
--- a/tests/ndk_program_tests/Android.bp
+++ b/tests/ndk_program_tests/Android.bp
@@ -36,6 +36,7 @@ filegroup {
         "epoll_test.cc",
         "memory_order_test.cc",
         "mutex_test.cc",
+        "proc_self_maps_test.cc",
         "ptrace_test.cc",
         "resource_test.cc",
         "sem_test.cc",
@@ -90,7 +91,6 @@ cc_test {
     defaults: ["berberis_ndk_program_tests_defaults"],
     shared_libs: ["libz"],
     srcs: [
-        "proc_self_maps_test.cc",
         // TODO(b/187471779): Signal stress test is unstable with high number of repetitions.
         // TODO(b/188086209): Errno emulation is not thread-safe - some checks fail.
         "signal_stress_test.cc",
@@ -124,11 +124,13 @@ cc_defaults {
     arch: {
         arm: {
             srcs: [
+                "arm/handle_not_executable_test.cc",
                 "arm/sigill_test.cc",
             ],
         },
         arm64: {
             srcs: [
+                "arm64/handle_not_executable_test.cc",
                 "arm64/runtime_code_patching_test.cc",
                 "arm64/sigill_test.cc",
             ],
@@ -149,7 +151,6 @@ cc_defaults {
             srcs: [
                 "arm/arm_test.cc",
                 "arm/cpu_features_test.cc",
-                "arm/handle_not_executable_test.cc",
                 "arm/neon_test.cc",
                 "arm/runtime_code_patching_test.cc",
                 "arm/syscall_test.cc",
@@ -160,7 +161,6 @@ cc_defaults {
         arm64: {
             srcs: [
                 "arm64/cpu_features_test.cc",
-                "arm64/handle_not_executable_test.cc",
             ],
         },
     },
@@ -206,9 +206,6 @@ cc_test {
     srcs: [
         // TODO(b/187471779): fix for static executable.
         // "handle_not_executable_test.cc",
-        // TODO(b/297942688): We do not support accurate exec bit emulation in /proc/self/maps
-        // on systems without CONFIG_ANON_VMA_NAME.
-        // "proc_self_maps_test.cc",
         // TODO(b/187471779): Signal stress test is unstable with high number of repeatitions.
         // TODO(b/188086209): Errno emulation is not thread-safe - some checks fail.
         // "signal_stress_test.cc",
diff --git a/tests/ndk_program_tests/arm64/handle_not_executable_test.cc b/tests/ndk_program_tests/arm64/handle_not_executable_test.cc
index fc5a2177..167c1a61 100644
--- a/tests/ndk_program_tests/arm64/handle_not_executable_test.cc
+++ b/tests/ndk_program_tests/arm64/handle_not_executable_test.cc
@@ -16,6 +16,7 @@
 
 #include "gtest/gtest.h"
 
+#include <setjmp.h>
 #include <sys/mman.h>
 #include <unistd.h>  // sysconf(_SC_PAGESIZE)
 
@@ -23,6 +24,8 @@
 #include <cstdio>
 #include <cstring>
 
+#include "berberis/ndk_program_tests/scoped_sigaction.h"
+
 // Make sure compiler doesn't recognize undefined behavior and doesn't optimize out call to nullptr.
 volatile void* g_null_addr = nullptr;
 
@@ -48,61 +51,56 @@ TEST(HandleNotExecutable, PcLessThan4096) {
   ASSERT_EXIT((reinterpret_cast<Func>(4095))(), testing::KilledBySignal(SIGSEGV), "");
 }
 
+// Add some valid code to the end of the first page and graceful failure rescue at the beginning of
+// the second page.
 constexpr uint32_t kPageCrossingCode[] = {
-    //
     // First page
-    //
-
-    // str lr, [sp, #-8]! (push lr)
-    //
-    // We may need lr for graceful return if SIGSEGV doesn't happen.
-    0xf81f8ffe,
-    // blr x0
-    //
-    // The only way to check that this was executed (i.e. SIGSEGV didn't happen too early) is to
-    // print something to stderr. Call FirstPageExecutionHelper for this.
-    0xd63f0000,
     // mov x0, x0
-    //
-    // Make sure we cross pages without jumps (i.e. we don't return from blx directly to the second
-    // page).
     0xaa0003e0,
-
-    //
     // Second page
-    //
-
-    // ldr lr, [sp], #8 (pop lr)
-    //
     // If SIGSEGV doesn't happen, make sure we return cleanly.
-    0xf84087fe,
     // ret
     0xd65f03c0,
 };
 
-constexpr size_t kFirstPageInsnNum = 3;
-
-void FirstPageExecutionHelper() {
-  fprintf(stderr, "First page has executed");
+constexpr size_t kFirstPageCodeSize = 4;
+sigjmp_buf g_jmpbuf;
+uint8_t* g_noexec_page_addr = nullptr;
+
+void SigsegvHandler(int /* sig */, siginfo_t* /* info */, void* ctx) {
+  fprintf(stderr, "SIGSEGV caught\n");
+  // Warning: do not use ASSERT, so that we recover with longjump unconditionally.
+  // Otherwise we'll be calling the handler in infinite loop.
+  EXPECT_EQ(static_cast<ucontext*>(ctx)->uc_mcontext.pc,
+            reinterpret_cast<uintptr_t>(g_noexec_page_addr));
+  longjmp(g_jmpbuf, 1);
 }
 
 TEST(HandleNotExecutable, ExecutableToNotExecutablePageCrossing) {
   const long kPageSize = sysconf(_SC_PAGESIZE);
-  // Allocate two executable pages.
-  uint32_t* first_page = reinterpret_cast<uint32_t*>(mmap(
-      0, kPageSize * 2, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
-
-  uint32_t* second_page = first_page + (kPageSize / sizeof(uint32_t));
-  // Make second page nonexecutable.
-  mprotect(second_page, kPageSize, PROT_READ | PROT_WRITE);
-
-  uint32_t* start_addr = second_page - kFirstPageInsnNum;
+  // Allocate two pages.
+  uint8_t* first_page = static_cast<uint8_t*>(
+      mmap(0, kPageSize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
+  // Make first page executable.
+  mprotect(first_page, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC);
+
+  g_noexec_page_addr = first_page + kPageSize;
+  uint8_t* start_addr = g_noexec_page_addr - kFirstPageCodeSize;
   memcpy(start_addr, kPageCrossingCode, sizeof(kPageCrossingCode));
 
-  using Func = void (*)(void (*)());
-  ASSERT_EXIT((reinterpret_cast<Func>(start_addr))(&FirstPageExecutionHelper),
-              testing::KilledBySignal(SIGSEGV),
-              "First page has executed");
+  struct sigaction sa;
+  sa.sa_flags = SA_SIGINFO;
+  sigemptyset(&sa.sa_mask);
+  sa.sa_sigaction = SigsegvHandler;
+  ScopedSigaction scoped_sa(SIGSEGV, &sa);
+
+  if (setjmp(g_jmpbuf) == 0) {
+    fprintf(stderr, "Jumping to executable page before non-executable page\n");
+    reinterpret_cast<void (*)()>(start_addr)();
+    ADD_FAILURE() << "Function call should not have returned";
+  } else {
+    fprintf(stderr, "Successful recovery\n");
+  }
 
   munmap(first_page, kPageSize * 2);
 }
diff --git a/tests/ndk_program_tests/proc_self_maps_test.cc b/tests/ndk_program_tests/proc_self_maps_test.cc
index 78629714..5352f561 100644
--- a/tests/ndk_program_tests/proc_self_maps_test.cc
+++ b/tests/ndk_program_tests/proc_self_maps_test.cc
@@ -16,16 +16,19 @@
 
 #include "gtest/gtest.h"
 
+#include <fcntl.h>  // open
 #include <sys/mman.h>
-#include <unistd.h>  // sysconf(_SC_PAGESIZE)
+#include <unistd.h>  // close, sysconf(_SC_PAGESIZE)
 
 #include <cinttypes>
 #include <cstdint>
 #include <cstdio>
+#include <functional>
 #include <memory>
 
 namespace {
 
+const size_t kPageSize = sysconf(_SC_PAGESIZE);
 constexpr bool kExactMapping = true;
 
 template <bool kIsExactMapping = false>
@@ -60,15 +63,26 @@ bool IsExecutable(void* ptr, size_t size) {
       }
     }
   }
-  ADD_FAILURE() << "Didn't find address " << reinterpret_cast<void*>(addr) << " in /proc/self/maps";
+  ADD_FAILURE() << "Didn't find range " << ptr << "-" << reinterpret_cast<void*>(addr + size)
+                << " in /proc/self/maps";
   return false;
 }
 
+template <typename FuncType>
+class ScopeExit {
+ public:
+  explicit ScopeExit(FuncType f) : func_(f) {}
+  ~ScopeExit() { func_(); }
+
+ private:
+  FuncType func_;
+};
+
 TEST(ProcSelfMaps, ExecutableFromMmap) {
-  const size_t kPageSize = sysconf(_SC_PAGESIZE);
   uint8_t* mapping = reinterpret_cast<uint8_t*>(
       mmap(0, 3 * kPageSize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
   ASSERT_NE(mapping, nullptr);
+  auto mapping_cleanup = ScopeExit([mapping]() { EXPECT_EQ(0, munmap(mapping, 3 * kPageSize)); });
 
   ASSERT_FALSE(IsExecutable(mapping, 3 * kPageSize));
 
@@ -84,15 +98,13 @@ TEST(ProcSelfMaps, ExecutableFromMmap) {
   // Surrounding mappings can be merged with adjacent mappings. But this one must match exactly.
   ASSERT_TRUE(IsExecutable<kExactMapping>(mapping + kPageSize, kPageSize));
   ASSERT_FALSE(IsExecutable(mapping + 2 * kPageSize, kPageSize));
-
-  ASSERT_EQ(munmap(mapping, 3 * kPageSize), 0);
 }
 
 TEST(ProcSelfMaps, ExecutableFromMprotect) {
-  const size_t kPageSize = sysconf(_SC_PAGESIZE);
   uint8_t* mapping = reinterpret_cast<uint8_t*>(
       mmap(0, 3 * kPageSize, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
   ASSERT_NE(mapping, nullptr);
+  auto mapping_cleanup = ScopeExit([mapping]() { EXPECT_EQ(0, munmap(mapping, 3 * kPageSize)); });
 
   ASSERT_FALSE(IsExecutable(mapping, 3 * kPageSize));
 
@@ -102,8 +114,24 @@ TEST(ProcSelfMaps, ExecutableFromMprotect) {
   // Surrounding mappings can be merged with adjacent mappings. But this one must match exactly.
   ASSERT_TRUE(IsExecutable<kExactMapping>(mapping + kPageSize, kPageSize));
   ASSERT_FALSE(IsExecutable(mapping + 2 * kPageSize, kPageSize));
+}
+
+TEST(ProcSelfMaps, ExecutableFromFileBackedMmap) {
+  int fd = open("/dev/zero", O_RDONLY);
+  auto fd_cleanup = ScopeExit([fd]() { close(fd); });
+  uint8_t* mapping =
+      reinterpret_cast<uint8_t*>(mmap(0, 3 * kPageSize, PROT_READ, MAP_PRIVATE, fd, 0));
+  ASSERT_NE(mapping, nullptr);
+  auto mapping_cleanup = ScopeExit([mapping]() { EXPECT_EQ(0, munmap(mapping, 3 * kPageSize)); });
+
+  ASSERT_FALSE(IsExecutable(mapping, 3 * kPageSize));
 
-  ASSERT_EQ(munmap(mapping, 3 * kPageSize), 0);
+  ASSERT_EQ(0, mprotect(mapping + kPageSize, kPageSize, PROT_READ | PROT_EXEC));
+
+  // File-backed mappings shouldn't merge with the adjacent mappings and must match exactly.
+  ASSERT_FALSE(IsExecutable<kExactMapping>(mapping, kPageSize));
+  ASSERT_TRUE(IsExecutable<kExactMapping>(mapping + kPageSize, kPageSize));
+  ASSERT_FALSE(IsExecutable<kExactMapping>(mapping + 2 * kPageSize, kPageSize));
 }
 
 }  // namespace
diff --git a/tests/ndk_program_tests/riscv64/handle_not_executable_test.cc b/tests/ndk_program_tests/riscv64/handle_not_executable_test.cc
index 2c61a3ec..53f546fc 100644
--- a/tests/ndk_program_tests/riscv64/handle_not_executable_test.cc
+++ b/tests/ndk_program_tests/riscv64/handle_not_executable_test.cc
@@ -16,6 +16,7 @@
 
 #include "gtest/gtest.h"
 
+#include <setjmp.h>
 #include <sys/mman.h>
 #include <unistd.h>  // sysconf(_SC_PAGESIZE)
 
@@ -23,6 +24,8 @@
 #include <cstdio>
 #include <cstring>
 
+#include "berberis/ndk_program_tests/scoped_sigaction.h"
+
 // Make sure compiler doesn't recognize undefined behavior and doesn't optimize out call to nullptr.
 volatile void* g_null_addr = nullptr;
 
@@ -51,64 +54,53 @@ TEST(HandleNotExecutable, PcLessThan4096) {
 // Add some valid code to the end of the first page and graceful failure rescue at the beginning of
 // the second page.
 constexpr uint32_t kPageCrossingCode[] = {
-    //
     // First page
-    //
-
-    // addi sp, sp, -16
-    0xff010113,
-    // sd ra, 8(sp) (push ra)
-    //
-    // We may need ra for graceful return if SIGSEGV doesn't happen.
-    0x00113423,
-    // jalr a0
-    //
-    // The only way to check that this was executed (i.e. SIGSEGV didn't happen too early) is to
-    // print something to stderr. Call FirstPageExecutionHelper for this.
-    0x000500e7,
     // nop
-    //
-    // Make sure we cross pages without jumps (i.e. we don't return from jalr directly to the second
-    // page).
     0x00000013,
-
-    //
     // Second page
-    //
-
-    // ld ra, 8(sp) (pop ra)
-    //
     // If SIGSEGV doesn't happen, make sure we return cleanly.
-    0x00813083,
-    // addi sp, sp, 16
-    0x01010113,
     // ret
     0x00008067,
 };
 
-constexpr size_t kFirstPageInsnNum = 4;
-
-void FirstPageExecutionHelper() {
-  fprintf(stderr, "First page has executed");
+constexpr size_t kFirstPageCodeSize = 4;
+sigjmp_buf g_jmpbuf;
+uint8_t* g_noexec_page_addr = nullptr;
+
+void SigsegvHandler(int /* sig */, siginfo_t* /* info */, void* ctx) {
+  fprintf(stderr, "SIGSEGV caught\n");
+  // Warning: do not use ASSERT, so that we recover with longjump unconditionally.
+  // Otherwise we'll be calling the handler in infinite loop.
+  EXPECT_EQ(static_cast<ucontext*>(ctx)->uc_mcontext.__gregs[REG_PC],
+            reinterpret_cast<uintptr_t>(g_noexec_page_addr));
+  longjmp(g_jmpbuf, 1);
 }
 
 TEST(HandleNotExecutable, ExecutableToNotExecutablePageCrossing) {
   const long kPageSize = sysconf(_SC_PAGESIZE);
-  // Allocate two executable pages.
-  uint32_t* first_page = reinterpret_cast<uint32_t*>(mmap(
-      0, kPageSize * 2, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
-
-  uint32_t* second_page = first_page + (kPageSize / sizeof(uint32_t));
-  // Make second page nonexecutable.
-  mprotect(second_page, kPageSize, PROT_READ | PROT_WRITE);
-
-  uint32_t* start_addr = second_page - kFirstPageInsnNum;
+  // Allocate two pages.
+  uint8_t* first_page = static_cast<uint8_t*>(
+      mmap(0, kPageSize * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
+  // Make first page executable.
+  mprotect(first_page, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC);
+
+  g_noexec_page_addr = first_page + kPageSize;
+  uint8_t* start_addr = g_noexec_page_addr - kFirstPageCodeSize;
   memcpy(start_addr, kPageCrossingCode, sizeof(kPageCrossingCode));
 
-  using Func = void (*)(void (*)());
-  ASSERT_EXIT((reinterpret_cast<Func>(start_addr))(&FirstPageExecutionHelper),
-              testing::KilledBySignal(SIGSEGV),
-              "First page has executed");
+  struct sigaction sa;
+  sa.sa_flags = SA_SIGINFO;
+  sigemptyset(&sa.sa_mask);
+  sa.sa_sigaction = SigsegvHandler;
+  ScopedSigaction scoped_sa(SIGSEGV, &sa);
+
+  if (setjmp(g_jmpbuf) == 0) {
+    fprintf(stderr, "Jumping to executable page before non-executable page\n");
+    reinterpret_cast<void (*)()>(start_addr)();
+    ADD_FAILURE() << "Function call should not have returned";
+  } else {
+    fprintf(stderr, "Successful recovery\n");
+  }
 
   munmap(first_page, kPageSize * 2);
 }
diff --git a/tests/run_host_tests.mk b/tests/run_host_tests.mk
index d73738d6..7f5451d1 100644
--- a/tests/run_host_tests.mk
+++ b/tests/run_host_tests.mk
@@ -165,6 +165,14 @@ $(eval $(call add_test,berberis_host_tests,\
 	run_test,\
 	$(HOST_OUT)/nativetest64/berberis_host_tests/berberis_host_tests))
 
+$(eval $(call add_test,berberis_host_tests_avx,\
+	run_test,\
+	$(HOST_OUT)/nativetest64/berberis_host_tests_avx/berberis_host_tests_avx))
+
+$(eval $(call add_test,berberis_host_tests_no_avx,\
+	run_test,\
+	$(HOST_OUT)/nativetest64/berberis_host_tests_no_avx/berberis_host_tests_no_avx))
+
 endif  # BUILD_BERBERIS_RISCV64_TO_X86_64
 
 
diff --git a/tools/difflist.sh b/tools/difflist.sh
index 32bc130b..800050b0 100755
--- a/tools/difflist.sh
+++ b/tools/difflist.sh
@@ -55,7 +55,7 @@ for file in "${files[@]}"; do
       git log -n 1 "$aosp_change" | grep Change-Id: || true
     )"
     if ! [[ -z "${aosp_change_id}" ]]; then
-      aosp_changes_map["$aosp_change_id"]=https://googleplex-android-review.googlesource.com/q/commit:"$aosp_change"
+      aosp_changes_map["$aosp_change_id"]=https://r.android.com/q/commit:"$aosp_change"
     fi
   done
   readarray -t goog_changes < <(
diff --git a/tools/nogrod/main.cc b/tools/nogrod/main.cc
index db89e5a5..de1fdd8e 100644
--- a/tools/nogrod/main.cc
+++ b/tools/nogrod/main.cc
@@ -761,6 +761,12 @@ const TypeInfo* ParseClass(const char* kind,
       continue;
     }
 
+    if (child->tag() == DW_TAG_variable && child->GetBoolAttributeOr(DW_AT_external, false)) {
+      // Static data members of structures/classes are represented by variable entries flagged as
+      // external. Since static data members do not affect class layout it is safe to ignore them.
+      continue;
+    }
+
     if (child->tag() != DW_TAG_member) {  // see if this is the case...
       error("Unexpected tag 0x%x for the die at offset 0x%" PRIx64 ", expected DW_TAG_member",
             child->tag(),
diff --git a/tools/prettify_asm.py b/tools/prettify_asm.py
new file mode 100755
index 00000000..ec63dc21
--- /dev/null
+++ b/tools/prettify_asm.py
@@ -0,0 +1,108 @@
+#!/usr/bin/python
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
+#
+
+import json
+import re
+import sys
+
+# Add numbers to the names of fields to rearrange them better.
+# They would be removed from final file.
+field_substitute = {
+  'name' : '|000|name',
+  'encodings' : '|000|encodings',
+  'stems' : '|000|stems',
+  'feature' : '|001|feature',
+  'args' : '|010|args',
+  'comment' : '|015|comment',
+  'asm' : '|020|asm',
+  'opcodes' : '|021|opcodes',
+  'reg_to_rm' : '|022|reg_to_rm',
+  'mnemo' : '|030|mnemo',
+}
+
+def Version(str):
+  result = []
+  isdigit = False
+  word = ''
+  for char in str + ('a' if str[-1:].isdigit() else '0'):
+    if char.isdigit() == isdigit:
+      word += char
+    else:
+      if isdigit:
+        result.append(('0' * 1000 + word)[-1000:])
+      else:
+        result.append((word + ' ' * 1000)[:1000])
+      isdigit = not isdigit
+      word = char
+  return '.'.join(result)
+
+def main(argv):
+  # Usage: prettify_asm_def.py <file.json>
+
+  with open(argv[1]) as file:
+    obj = json.load(file)
+
+  insns = {}
+  for insn in obj['insns']:
+    if 'stems' in insn:
+      sorted_stems = sorted(insn['stems'])
+      insn['stems'] = sorted_stems
+      name = Version(', '.join(sorted_stems) + '; ' + str(insn['args']))
+    elif 'encodings' in insn:
+      sorted_stems = sorted(insn['encodings'])
+      name = Version(', '.join(sorted_stems) + '; ' + str(insn['args']))
+    else:
+      name = Version(insn['name'] + '; ' + str(insn['args']))
+    new_insn = {}
+    for field, value in insn.items():
+      new_insn[field_substitute[field]] = value
+    assert name not in insns
+    insns[name] = new_insn
+
+  obj['insns'] = [insn[1] for insn in sorted(iter(insns.items()))]
+
+  text = json.dumps(obj, indent=2, sort_keys=True)
+
+  # Remove numbers from names of fields
+  text = re.sub('[|][0-9][0-9][0-9][|]', '', text)
+
+  def replace_if_short(match):
+    match = match.group()
+    replace = ' '.join(match.split())
+    if len(replace) < 100 or (
+       len(replace) < 120 and 'optimizable_using_commutation' in replace):
+      return replace
+    else:
+      return match
+
+  # Make short lists one-liners
+  text = re.sub('[\[{][^][{}]*[]}]', replace_if_short, text)
+  # Allow opcodes list.
+  text = re.sub('[\[{][^][{}]*"opcodes"[^][{}]*[\[{][^][{}]*[]}][^][{}]*[]}]', replace_if_short, text)
+
+  # Remove trailing spaces
+  text = re.sub(' $', '', text, flags=re.MULTILINE)
+
+  # Fix the license
+  text = re.sub('\\\\u201c', '“', text, flags=re.MULTILINE)
+  text = re.sub('\\\\u201d', '”', text, flags=re.MULTILINE)
+
+  with open(argv[1], 'w') as file:
+    print(text, file=file)
+
+if __name__ == '__main__':
+  sys.exit(main(sys.argv))
diff --git a/tools/prettify_intrinsics.py b/tools/prettify_intrinsics.py
new file mode 100755
index 00000000..14bfe5ba
--- /dev/null
+++ b/tools/prettify_intrinsics.py
@@ -0,0 +1,106 @@
+#!/usr/bin/python
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
+#
+
+from collections import OrderedDict
+import json
+import re
+import sys
+
+# Add numbers to the names of fields to rearrange them better.
+# They will be removed from final file.
+field_substitute = {
+  "comment": "|000|comment",
+  "class": "|001|class",
+  "note": "|001|note",
+  "precise_nans": "|001|precise_nans",
+  "variants": "|001|variants",
+  "in": "|002|in",
+  "out": "|003|out",
+  "side_effects_comment": "|004|side_effects_comment",
+  "has_side_effects": "|005|has_side_effects"
+}
+
+def Version(str):
+  result = []
+  isdigit = False
+  word = ''
+  for char in str + ('a' if str[-1:].isdigit() else '0'):
+    if char.isdigit() == isdigit:
+      word += char
+    else:
+      if isdigit:
+        result.append(('0' * 1000 + word)[-1000:])
+      else:
+        result.append((word + ' ' * 1000)[:1000])
+      isdigit = not isdigit
+      word = char
+  return '.'.join(result)
+
+
+def main(argv):
+  # Usage: prettify_intrinsics.py <file.json>
+
+  with open(argv[1]) as file:
+    json_intrinsics = json.load(file)
+
+  out_intrinsics = OrderedDict()
+  license = None
+  for intrinsic_name, intrinsic_body in json_intrinsics.items():
+    new_intrinsic = {}
+    if intrinsic_name == 'License':
+      license = intrinsic_body
+    else:
+      for field, value in intrinsic_body.items():
+        if field == 'variants':
+          new_intrinsic[field_substitute[field]] = sorted(value, key=Version)
+        else:
+          new_intrinsic[field_substitute[field]] = value
+      out_intrinsics[intrinsic_name] = new_intrinsic
+
+  text = json.dumps(out_intrinsics, indent=2, sort_keys=True)
+
+  # Add license back if present
+  if license:
+    license = json.dumps([license], indent=2)
+    text = '{\n  "License":' + license[3:-2] + ',\n' + text[2:]
+
+  # Remove numbers from names of fields
+  text = re.sub('[|][0-9][0-9][0-9][|]', '', text)
+
+  def replace_if_short(match):
+    match = match.group()
+    replace = ' '.join(match.split())
+    if len(replace) < 90:
+      return replace
+    else:
+      return match
+
+  # Make short lists one-liners
+  text = re.sub('[\[{][^][{}]*[]}]', replace_if_short, text)
+
+  # Remove trailing spaces
+  text = re.sub(' $', '', text, flags=re.MULTILINE)
+
+  # Fix the license
+  text = re.sub('\\\\u201c', '“', text, flags=re.MULTILINE)
+  text = re.sub('\\\\u201d', '”', text, flags=re.MULTILINE)
+
+  with open(argv[1], 'w') as file:
+    print(text, file=file)
+
+if __name__ == '__main__':
+  sys.exit(main(sys.argv))
diff --git a/tools/prettify_ir_binding.py b/tools/prettify_ir_binding.py
new file mode 100755
index 00000000..1f39c49b
--- /dev/null
+++ b/tools/prettify_ir_binding.py
@@ -0,0 +1,105 @@
+#!/usr/bin/python
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
+#
+
+import json
+import re
+import sys
+
+# Add numbers to the names of fields to rearrange them better.
+# They would be removed from final file.
+field_substitute = {
+  'name' : '|000|name',
+  'variants' : '|001|variants',
+  'insn' : '|002|insn',
+  'feature' : '|003|feature',
+  'nan' : '|003|nan',
+  'usage' : '|003|usage',
+  'in' : '|004|in',
+  'out' : '|005|out',
+  'comment' : '|010|comment'
+}
+
+def Version(str):
+  result = []
+  isdigit = False
+  word = ''
+  for char in str + ('a' if str[-1:].isdigit() else '0'):
+    if char.isdigit() == isdigit:
+      word += char
+    else:
+      if isdigit:
+        result.append(('0' * 1000 + word)[-1000:])
+      else:
+        result.append((word + ' ' * 1000)[:1000])
+      isdigit = not isdigit
+      word = char
+  return '.'.join(result)
+
+
+def main(argv):
+  # Usage: prettify_ir_binding.py <file.json>
+
+  with open(argv[1]) as file:
+    json_bindings = json.load(file)
+
+  out_bindings = []
+  license_text = []
+  for binding in json_bindings:
+    new_binding = {}
+    if isinstance(binding, str):
+      license_text.append(binding)
+    else:
+      for field, value in binding.items():
+        new_binding[field_substitute[field]] = value
+      out_bindings.append(new_binding)
+
+  out_bindings = license_text + sorted(out_bindings,
+      key=lambda binding:
+          Version(binding[field_substitute['name']] +
+                  str(binding.get(field_substitute['variants'], '')) +
+                  str(binding.get(field_substitute['usage'], '')) +
+                  str(binding.get(field_substitute['nan'], '')) +
+                  str(binding.get(field_substitute['feature'], ''))))
+
+  text = json.dumps(out_bindings, indent=2, sort_keys=True)
+
+  # Remove numbers from names of fields
+  text = re.sub('[|][0-9][0-9][0-9][|]', '', text)
+
+  def replace_if_short(match):
+    match = match.group()
+    replace = ' '.join(match.split())
+    if len(replace) < 90:
+      return replace
+    else:
+      return match
+
+  # Make short lists one-liners
+  text = re.sub('[\[{][^][{}]*[]}]', replace_if_short, text)
+
+  # Remove trailing spaces
+  text = re.sub(' $', '', text, flags=re.MULTILINE)
+
+  # Fix the license
+  text = re.sub('\\\\u201c', '“', text, flags=re.MULTILINE)
+  text = re.sub('\\\\u201d', '”', text, flags=re.MULTILINE)
+
+  with open(argv[1], 'w') as file:
+    print(text, file=file)
+
+if __name__ == '__main__':
+  sys.exit(main(sys.argv))
```

