```diff
diff --git a/Android.bp b/Android.bp
index 6a042a4..5afc016 100644
--- a/Android.bp
+++ b/Android.bp
@@ -37,7 +37,7 @@ cc_defaults {
 cc_library_static {
     name: "libapf",
     defaults: ["apf_defaults"],
-    srcs: ["apf_interpreter.c"],
+    srcs: ["v4/apf_interpreter.c"],
     sdk_version: "24",
 }
 
@@ -50,6 +50,15 @@ cc_library_static {
     sdk_version: "24",
 }
 
+cc_library_static {
+    name: "libapfbuf",
+    defaults: ["apf_defaults"],
+    srcs: [
+        "next/test_buf_allocator.c",
+    ],
+    sdk_version: "24",
+}
+
 cc_binary_host {
     name: "apf_disassembler",
     defaults: ["apf_defaults"],
@@ -67,10 +76,10 @@ cc_binary_host {
     ],
     srcs: [
         "apf_run.c",
-        "apf_interpreter.c",
         "disassembler.c",
-        "v7/apf_interpreter.c",
-        "v7/test_buf_allocator.c",
+        "next/apf_interpreter.c",
+        "next/test_buf_allocator.c",
+        "v4/apf_interpreter.c",
     ],
     cflags: [
         "-DAPF_TRACE_HOOK=apf_trace_hook",
@@ -104,27 +113,3 @@ sh_test_host {
         unit_test: true,
     },
 }
-
-cc_test_host {
-    name: "apf_checksum_test",
-    srcs: [
-        "apf_checksum_test.cc",
-    ],
-    cflags: [
-        "-Wall",
-        "-Wno-unused-function",
-    ],
-    stl: "c++_static",
-}
-
-cc_test_host {
-    name: "apf_dns_test",
-    srcs: [
-        "apf_dns_test.cc",
-    ],
-    cflags: [
-        "-Wall",
-        "-Wno-unused-function",
-    ],
-    stl: "c++_static",
-}
diff --git a/OWNERS b/OWNERS
index eb9ff18..b0e134e 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,3 @@
-include platform/system/netd:/OWNERS
+# Bug component: 31808
+set noparent
+file:platform/packages/modules/Connectivity:main:/OWNERS_core_networking
diff --git a/apf.h b/apf.h
deleted file mode 100644
index 4722888..0000000
--- a/apf.h
+++ /dev/null
@@ -1,173 +0,0 @@
-/*
- * Copyright 2018, The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- * http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#ifndef ANDROID_APF_APF_H
-#define ANDROID_APF_APF_H
-
-// A brief overview of APF:
-//
-// APF machine is composed of:
-//  1. A read-only program consisting of bytecodes as described below.
-//  2. Two 32-bit registers, called R0 and R1.
-//  3. Sixteen 32-bit temporary memory slots (cleared between packets).
-//  4. A read-only packet.
-// The program is executed by the interpreter below and parses the packet
-// to determine if the application processor (AP) should be woken up to
-// handle the packet or if can be dropped.
-//
-// APF bytecode description:
-//
-// The APF interpreter uses big-endian byte order for loads from the packet
-// and for storing immediates in instructions.
-//
-// Each instruction starts with a byte composed of:
-//  Top 5 bits form "opcode" field, see *_OPCODE defines below.
-//  Next 2 bits form "size field", which indicate the length of an immediate
-//  value which follows the first byte.  Values in this field:
-//                 0 => immediate value is 0 and no bytes follow.
-//                 1 => immediate value is 1 byte big.
-//                 2 => immediate value is 2 bytes big.
-//                 3 => immediate value is 4 bytes big.
-//  Bottom bit forms "register" field, which indicates which register this
-//  instruction operates on.
-//
-//  There are three main categories of instructions:
-//  Load instructions
-//    These instructions load byte(s) of the packet into a register.
-//    They load either 1, 2 or 4 bytes, as determined by the "opcode" field.
-//    They load into the register specified by the "register" field.
-//    The immediate value that follows the first byte of the instruction is
-//    the byte offset from the beginning of the packet to load from.
-//    There are "indexing" loads which add the value in R1 to the byte offset
-//    to load from. The "opcode" field determines which loads are "indexing".
-//  Arithmetic instructions
-//    These instructions perform simple operations, like addition, on register
-//    values. The result of these instructions is always written into R0. One
-//    argument of the arithmetic operation is R0's value. The other argument
-//    of the arithmetic operation is determined by the "register" field:
-//            If the "register" field is 0 then the immediate value following
-//            the first byte of the instruction is used as the other argument
-//            to the arithmetic operation.
-//            If the "register" field is 1 then R1's value is used as the other
-//            argument to the arithmetic operation.
-//  Conditional jump instructions
-//    These instructions compare register R0's value with another value, and if
-//    the comparison succeeds, jump (i.e. adjust the program counter). The
-//    immediate value that follows the first byte of the instruction
-//    represents the jump target offset, i.e. the value added to the program
-//    counter if the comparison succeeds. The other value compared is
-//    determined by the "register" field:
-//            If the "register" field is 0 then another immediate value
-//            follows the jump target offset. This immediate value is of the
-//            same size as the jump target offset, and represents the value
-//            to compare against.
-//            If the "register" field is 1 then register R1's value is
-//            compared against.
-//    The type of comparison (e.g. equal to, greater than etc) is determined
-//    by the "opcode" field. The comparison interprets both values being
-//    compared as unsigned values.
-//
-//  Miscellaneous details:
-//
-//  Pre-filled temporary memory slot values
-//    When the APF program begins execution, three of the sixteen memory slots
-//    are pre-filled by the interpreter with values that may be useful for
-//    programs:
-//      Slot #11 contains the size (in bytes) of the APF program.
-//      Slot #12 contains the total size of the APF buffer (program + data).
-//      Slot #13 is filled with the IPv4 header length. This value is calculated
-//               by loading the first byte of the IPv4 header and taking the
-//               bottom 4 bits and multiplying their value by 4. This value is
-//               set to zero if the first 4 bits after the link layer header are
-//               not 4, indicating not IPv4.
-//      Slot #14 is filled with size of the packet in bytes, including the
-//               link-layer header if any.
-//      Slot #15 is filled with the filter age in seconds. This is the number of
-//               seconds since the AP sent the program to the chipset. This may
-//               be used by filters that should have a particular lifetime. For
-//               example, it can be used to rate-limit particular packets to one
-//               every N seconds.
-//  Special jump targets:
-//    When an APF program executes a jump to the byte immediately after the last
-//      byte of the progam (i.e., one byte past the end of the program), this
-//      signals the program has completed and determined the packet should be
-//      passed to the AP.
-//    When an APF program executes a jump two bytes past the end of the program,
-//      this signals the program has completed and determined the packet should
-//      be dropped.
-//  Jump if byte sequence doesn't match:
-//    This is a special instruction to facilitate matching long sequences of
-//    bytes in the packet. Initially it is encoded like a conditional jump
-//    instruction with two exceptions:
-//      The first byte of the instruction is always followed by two immediate
-//        fields: The first immediate field is the jump target offset like other
-//        conditional jump instructions. The second immediate field specifies the
-//        number of bytes to compare.
-//      These two immediate fields are followed by a sequence of bytes. These
-//        bytes are compared with the bytes in the packet starting from the
-//        position specified by the value of the register specified by the
-//        "register" field of the instruction.
-
-// Number of temporary memory slots, see ldm/stm instructions.
-#define MEMORY_ITEMS 16
-// Upon program execution, some temporary memory slots are prefilled:
-#define MEMORY_OFFSET_PROGRAM_SIZE 11     // Size of program (in bytes)
-#define MEMORY_OFFSET_DATA_SIZE 12        // Total size of program + data
-#define MEMORY_OFFSET_IPV4_HEADER_SIZE 13 // 4*([APF_FRAME_HEADER_SIZE]&15)
-#define MEMORY_OFFSET_PACKET_SIZE 14      // Size of packet in bytes.
-#define MEMORY_OFFSET_FILTER_AGE 15       // Age since filter installed in seconds.
-
-// Leave 0 opcode unused as it's a good indicator of accidental incorrect execution (e.g. data).
-#define LDB_OPCODE 1    // Load 1 byte from immediate offset, e.g. "ldb R0, [5]"
-#define LDH_OPCODE 2    // Load 2 bytes from immediate offset, e.g. "ldh R0, [5]"
-#define LDW_OPCODE 3    // Load 4 bytes from immediate offset, e.g. "ldw R0, [5]"
-#define LDBX_OPCODE 4   // Load 1 byte from immediate offset plus register, e.g. "ldbx R0, [5+R0]"
-#define LDHX_OPCODE 5   // Load 2 byte from immediate offset plus register, e.g. "ldhx R0, [5+R0]"
-#define LDWX_OPCODE 6   // Load 4 byte from immediate offset plus register, e.g. "ldwx R0, [5+R0]"
-#define ADD_OPCODE 7    // Add, e.g. "add R0,5"
-#define MUL_OPCODE 8    // Multiply, e.g. "mul R0,5"
-#define DIV_OPCODE 9    // Divide, e.g. "div R0,5"
-#define AND_OPCODE 10   // And, e.g. "and R0,5"
-#define OR_OPCODE 11    // Or, e.g. "or R0,5"
-#define SH_OPCODE 12    // Left shift, e.g, "sh R0, 5" or "sh R0, -5" (shifts right)
-#define LI_OPCODE 13    // Load signed immediate, e.g. "li R0,5"
-#define JMP_OPCODE 14   // Unconditional jump, e.g. "jmp label"
-#define JEQ_OPCODE 15   // Compare equal and branch, e.g. "jeq R0,5,label"
-#define JNE_OPCODE 16   // Compare not equal and branch, e.g. "jne R0,5,label"
-#define JGT_OPCODE 17   // Compare greater than and branch, e.g. "jgt R0,5,label"
-#define JLT_OPCODE 18   // Compare less than and branch, e.g. "jlt R0,5,label"
-#define JSET_OPCODE 19  // Compare any bits set and branch, e.g. "jset R0,5,label"
-#define JNEBS_OPCODE 20 // Compare not equal byte sequence, e.g. "jnebs R0,5,label,0x1122334455"
-#define EXT_OPCODE 21   // Immediate value is one of *_EXT_OPCODE
-#define LDDW_OPCODE 22  // Load 4 bytes from data address (register + simm): "lddw R0, [5+R1]"
-#define STDW_OPCODE 23  // Store 4 bytes to data address (register + simm): "stdw R0, [5+R1]"
-
-// Extended opcodes. These all have an opcode of EXT_OPCODE
-// and specify the actual opcode in the immediate field.
-#define LDM_EXT_OPCODE 0   // Load from temporary memory, e.g. "ldm R0,5"
-  // Values 0-15 represent loading the different temporary memory slots.
-#define STM_EXT_OPCODE 16  // Store to temporary memory, e.g. "stm R0,5"
-  // Values 16-31 represent storing to the different temporary memory slots.
-#define NOT_EXT_OPCODE 32  // Not, e.g. "not R0"
-#define NEG_EXT_OPCODE 33  // Negate, e.g. "neg R0"
-#define SWAP_EXT_OPCODE 34 // Swap, e.g. "swap R0,R1"
-#define MOV_EXT_OPCODE 35  // Move, e.g. "move R0,R1"
-
-#define EXTRACT_OPCODE(i) (((i) >> 3) & 31)
-#define EXTRACT_REGISTER(i) ((i) & 1)
-#define EXTRACT_IMM_LENGTH(i) (((i) >> 1) & 3)
-
-#endif  // ANDROID_APF_APF_H
diff --git a/apf_disassembler.c b/apf_disassembler.c
index e77d832..b12f182 100644
--- a/apf_disassembler.c
+++ b/apf_disassembler.c
@@ -14,10 +14,13 @@
  * limitations under the License.
  */
 
+#include <stdbool.h>
 #include <stdint.h>
 #include <stdio.h>
 
 #include "disassembler.h"
+#include "next/apf_defs.h"
+#include "next/apf.h"
 
 // Disassembles an APF program. A hex dump of the program is supplied on stdin.
 //
@@ -36,7 +39,15 @@ int main(void) {
       program[program_len++] = byte;
   }
 
-  for (uint32_t pc = 0; pc < program_len;) {
-      printf("%s\n", apf_disassemble(program, program_len, &pc));
+  const u8 v6_marker = JMP_OPCODE << 3 | 1;
+  const bool is_v6 = (program[0] & 0b11111001) == v6_marker;
+  if (is_v6) {
+      printf("APFv6 program:\n");
+  } else {
+      printf("APFv4 program:\n");
+  }
+  for (uint32_t pc = 0; pc < program_len + 2;) {
+      const disas_ret ret = apf_disassemble(program, program_len, &pc, is_v6);
+      printf("%s%s\n", ret.prefix, ret.content);
   }
 }
diff --git a/apf_interpreter.c b/apf_interpreter.c
deleted file mode 120000
index 7844a0d..0000000
--- a/apf_interpreter.c
+++ /dev/null
@@ -1 +0,0 @@
-v4/apf_interpreter.c
\ No newline at end of file
diff --git a/apf_interpreter.h b/apf_interpreter.h
deleted file mode 120000
index a07ceaf..0000000
--- a/apf_interpreter.h
+++ /dev/null
@@ -1 +0,0 @@
-v4/apf_interpreter.h
\ No newline at end of file
diff --git a/apf_run.c b/apf_run.c
index 2495547..98b51d4 100644
--- a/apf_run.c
+++ b/apf_run.c
@@ -28,9 +28,9 @@
 #include <string.h>
 
 #include "disassembler.h"
-#include "apf_interpreter.h"
-#include "v7/apf_interpreter.h"
-#include "v7/test_buf_allocator.h"
+#include "v4/apf_interpreter.h"
+#include "next/apf_interpreter.h"
+#include "next/test_buf_allocator.h"
 
 #define __unused __attribute__((unused))
 
@@ -155,7 +155,7 @@ int tracing_enabled = 0;
 void maybe_print_tracing_header() {
     if (!tracing_enabled) return;
 
-    printf("      R0       R1       PC  Instruction\n");
+    printf("      R0       R1       (size)    PC  Instruction\n");
     printf("-------------------------------------------------\n");
 
 }
@@ -192,14 +192,16 @@ void packet_handler(int use_apf_v6_interpreter, uint8_t* program,
     free(packet);
 }
 
+static int use_apf_v6_interpreter = 0;
 
 void apf_trace_hook(uint32_t pc, const uint32_t* regs, const uint8_t* program, uint32_t program_len,
                     const uint8_t* packet __unused, uint32_t packet_len __unused,
                     const uint32_t* memory __unused, uint32_t memory_len __unused) {
     if (!tracing_enabled) return;
 
-    printf("%8" PRIx32 " %8" PRIx32 " ", regs[0], regs[1]);
-    printf("%s\n", apf_disassemble(program, program_len, &pc));
+    printf("%8" PRIx32 " %8" PRIx32 "       ", regs[0], regs[1]);
+    const disas_ret ret = apf_disassemble(program, program_len, &pc, use_apf_v6_interpreter);
+    printf("%s%s\n", ret.prefix, ret.content);
 }
 
 // Process pcap file through APF filter and generate output files
@@ -284,7 +286,6 @@ int main(int argc, char* argv[]) {
     uint32_t data_len = 0;
     uint32_t filter_age = 0;
     int print_counter_enabled = 0;
-    int use_apf_v6_interpreter = 0;
 
     int opt;
     char *endptr;
diff --git a/devtools/.gitignore b/devtools/.gitignore
deleted file mode 100644
index a5c36b1..0000000
--- a/devtools/.gitignore
+++ /dev/null
@@ -1,2 +0,0 @@
-apf_interpreter.arm.o
-apf_interpreter.x86.o
diff --git a/devtools/apf_interpreter.c b/devtools/apf_interpreter.c
deleted file mode 120000
index a44bd13..0000000
--- a/devtools/apf_interpreter.c
+++ /dev/null
@@ -1 +0,0 @@
-../v7/apf_interpreter.c
\ No newline at end of file
diff --git a/devtools/apf_interpreter.h b/devtools/apf_interpreter.h
deleted file mode 120000
index 1aef88e..0000000
--- a/devtools/apf_interpreter.h
+++ /dev/null
@@ -1 +0,0 @@
-../v7/apf_interpreter.h
\ No newline at end of file
diff --git a/devtools/mk b/devtools/mk
deleted file mode 100755
index 870211a..0000000
--- a/devtools/mk
+++ /dev/null
@@ -1,28 +0,0 @@
-#!/bin/bash
-# Requires:
-#   sudo apt install gcc-arm-linux-gnueabihf gcc-arm-linux-gnueabi
-
-set -e
-set -u
-
-cd "${0%/*}"
-
-declare -ar FLAGS=(
-  '-std=c89'
-  '-pedantic'
-  '-Wall'
-  '-Werror'
-  '-Werror=implicit-fallthrough'
-  '-Werror=strict-prototypes'
-  '-Wsign-compare'
-  '-Wsign-conversion'
-  '-Wunused-parameter'
-  '-Wuninitialized'
-  '-Os'
-  '-fomit-frame-pointer'
-)
-
-arm-linux-gnueabi-gcc "${FLAGS[@]}" apf_interpreter.c -c -o apf_interpreter.arm.o
-clang -m32 "${FLAGS[@]}" -Wnullable-to-nonnull-conversion -Wthread-safety apf_interpreter.c -c -o apf_interpreter.x86.o
-size apf_interpreter.arm.o
-size apf_interpreter.x86.o
diff --git a/disassembler.c b/disassembler.c
index 9417466..ad5f5d6 100644
--- a/disassembler.c
+++ b/disassembler.c
@@ -19,8 +19,8 @@
 #include <stdio.h>
 #include <stdarg.h>
 
-#include "v7/apf_defs.h"
-#include "v7/apf.h"
+#include "next/apf_defs.h"
+#include "next/apf.h"
 #include "disassembler.h"
 
 // If "c" is of a signed type, generate a compile warning that gets promoted to an error.
@@ -28,7 +28,8 @@
 // superfluous ">= 0" with unsigned expressions generates compile warnings.
 #define ENFORCE_UNSIGNED(c) ((c)==(uint32_t)(c))
 
-char print_buf[1024];
+char prefix_buf[16];
+char print_buf[8196];
 char* buf_ptr;
 int buf_remain;
 bool v6_mode = false;
@@ -51,6 +52,7 @@ static void print_opcode(const char* opcode) {
 
 // Mapping from opcode number to opcode name.
 static const char* opcode_names [] = {
+    [PASSDROP_OPCODE] = NULL,
     [LDB_OPCODE] = "ldb",
     [LDH_OPCODE] = "ldh",
     [LDW_OPCODE] = "ldw",
@@ -71,10 +73,14 @@ static const char* opcode_names [] = {
     [JLT_OPCODE] = "jlt",
     [JSET_OPCODE] = "jset",
     [JBSMATCH_OPCODE] = NULL,
+    [EXT_OPCODE] = NULL,
     [LDDW_OPCODE] = "lddw",
     [STDW_OPCODE] = "stdw",
     [WRITE_OPCODE] = "write",
+    [PKTDATACOPY_OPCODE] = NULL,
     [JNSET_OPCODE] = "jnset",
+    [JBSPTRMATCH_OPCODE] = NULL,
+    [ALLOC_XMIT_OPCODE] = NULL,
 };
 
 static void print_jump_target(uint32_t target, uint32_t program_len) {
@@ -82,31 +88,74 @@ static void print_jump_target(uint32_t target, uint32_t program_len) {
         bprintf("PASS");
     } else if (target == program_len + 1) {
         bprintf("DROP");
+    } else if (target > program_len + 1) {
+        uint32_t ofs = target - program_len;
+        uint32_t imm = ofs >> 1;
+        bprintf((ofs & 1) ? "cnt_and_drop" : "cnt_and_pass");
+        bprintf("[cnt=%d]", imm);
     } else {
         bprintf("%u", target);
     }
 }
 
-const char* apf_disassemble(const uint8_t* program, uint32_t program_len, uint32_t* const ptr2pc) {
+static void print_qtype(int qtype) {
+    switch(qtype) {
+        case 1:
+            bprintf("A, ");
+            break;
+        case 28:
+            bprintf("AAAA, ");
+            break;
+        case 12:
+            bprintf("PTR, ");
+            break;
+        case 33:
+            bprintf("SRV, ");
+            break;
+        case 16:
+            bprintf("TXT, ");
+            break;
+        default:
+            bprintf("%d, ", qtype);
+    }
+}
+
+disas_ret apf_disassemble(const uint8_t* program, uint32_t program_len, uint32_t* const ptr2pc, bool is_v6) {
     buf_ptr = print_buf;
     buf_remain = sizeof(print_buf);
     if (*ptr2pc > program_len + 1) {
+        snprintf(prefix_buf, sizeof(prefix_buf), "(%4u) ", 0);
         bprintf("pc is overflow: pc %d, program_len: %d", *ptr2pc, program_len);
-        return print_buf;
+        disas_ret ret = {
+            .prefix = prefix_buf,
+            .content = print_buf
+        };
+        return ret;
     }
+    uint32_t prev_pc = *ptr2pc;
 
-    bprintf("%8u: ", *ptr2pc);
+    bprintf("%4u: ", *ptr2pc);
 
     if (*ptr2pc == program_len) {
+        snprintf(prefix_buf, sizeof(prefix_buf), "(%4u) ", 0);
         bprintf("PASS");
         ++(*ptr2pc);
-        return print_buf;
+        disas_ret ret = {
+            .prefix = prefix_buf,
+            .content = print_buf
+        };
+        return ret;
     }
 
     if (*ptr2pc == program_len + 1) {
+        snprintf(prefix_buf, sizeof(prefix_buf), "(%4u) ", 0);
         bprintf("DROP");
         ++(*ptr2pc);
-        return print_buf;
+        disas_ret ret = {
+            .prefix = prefix_buf,
+            .content = print_buf
+        };
+        return ret;
     }
 
     const uint8_t bytecode = program[(*ptr2pc)++];
@@ -200,7 +249,7 @@ const char* apf_disassemble(const uint8_t* program, uint32_t program_len, uint32
             const uint32_t cmp_imm = DECODE_IMM(1 << (len_field - 1));
             const uint32_t cnt = (cmp_imm >> 11) + 1; // 1+, up to 32 fits in u16
             const uint32_t len = cmp_imm & 2047; // 0..2047
-            bprintf("0x%x, ", len);
+            bprintf("(%u), ", len);
             print_jump_target(*ptr2pc + imm + cnt * len, program_len);
             bprintf(", ");
             if (cnt > 1) {
@@ -216,7 +265,7 @@ const char* apf_disassemble(const uint8_t* program, uint32_t program_len, uint32
                 }
             }
             if (cnt > 1) {
-                bprintf(" }");
+                bprintf(" }[%d]", cnt);
             }
             break;
         }
@@ -229,15 +278,38 @@ const char* apf_disassemble(const uint8_t* program, uint32_t program_len, uint32
             }
             break;
         case ADD_OPCODE:
+        case AND_OPCODE: {
+            PRINT_OPCODE();
+            if (is_v6) {
+                bprintf("r%d, ", reg_num);
+                if (!imm) {
+                    bprintf("r%d", 1 - reg_num);
+                } else if (opcode == AND_OPCODE) {
+                    bprintf("0x%x", signed_imm);
+                } else {
+                    bprintf("%d", signed_imm);
+                }
+            } else {
+                if (reg_num) {
+                    bprintf("r0, r1");
+                } else if (opcode == AND_OPCODE) {
+                    bprintf("r0, 0x%x", imm);
+                } else {
+                    bprintf("r0, %u", imm);
+                }
+            }
+            break;
+        }
         case MUL_OPCODE:
         case DIV_OPCODE:
-        case AND_OPCODE:
         case OR_OPCODE:
             PRINT_OPCODE();
             if (reg_num) {
                 bprintf("r0, r1");
             } else if (!imm && opcode == DIV_OPCODE) {
                 bprintf("pass (div 0)");
+            } else if (opcode == OR_OPCODE) {
+                bprintf("r0, 0x%x", imm);
             } else {
                 bprintf("r0, %u", imm);
             }
@@ -311,32 +383,56 @@ const char* apf_disassemble(const uint8_t* program, uint32_t program_len, uint32
                     }
                     if (imm == EPKTDATACOPYIMM_EXT_OPCODE) {
                         uint32_t len = DECODE_IMM(1);
-                        bprintf(" src=r0, len=%d", len);
+                        if (!len) len = 256 + DECODE_IMM(1);
+                        bprintf("src=r0, len=%d", len);
                     } else {
-                        bprintf(" src=r0, len=r1");
+                        bprintf("src=r0, len=r1");
                     }
 
                     break;
                 }
-                case JDNSQMATCH_EXT_OPCODE:       // 43
-                case JDNSAMATCH_EXT_OPCODE:       // 44
-                case JDNSQMATCHSAFE_EXT_OPCODE:   // 45
-                case JDNSAMATCHSAFE_EXT_OPCODE: { // 46
+                case JDNSAMATCH_EXT_OPCODE:
+                case JDNSQMATCH_EXT_OPCODE:
+                case JDNSQMATCH1_EXT_OPCODE:
+                case JDNSQMATCH2_EXT_OPCODE:
+                case JDNSAMATCHSAFE_EXT_OPCODE:
+                case JDNSQMATCHSAFE_EXT_OPCODE:
+                case JDNSQMATCHSAFE1_EXT_OPCODE:
+                case JDNSQMATCHSAFE2_EXT_OPCODE: {
                     uint32_t offs = DECODE_IMM(1 << (len_field - 1));
-                    int qtype = -1;
-                    switch(imm) {
+                    int qtype1 = -1;
+                    int qtype2 = -1;
+                    switch (imm) {
                         case JDNSQMATCH_EXT_OPCODE:
                             print_opcode(reg_num ? "jdnsqeq" : "jdnsqne");
-                            qtype = DECODE_IMM(1);
+                            qtype1 = DECODE_IMM(1);
                             break;
                         case JDNSQMATCHSAFE_EXT_OPCODE:
                             print_opcode(reg_num ? "jdnsqeqsafe" : "jdnsqnesafe");
-                            qtype = DECODE_IMM(1);
+                            qtype1 = DECODE_IMM(1);
                             break;
                         case JDNSAMATCH_EXT_OPCODE:
                             print_opcode(reg_num ? "jdnsaeq" : "jdnsane"); break;
                         case JDNSAMATCHSAFE_EXT_OPCODE:
                             print_opcode(reg_num ? "jdnsaeqsafe" : "jdnsanesafe"); break;
+                        case JDNSQMATCH2_EXT_OPCODE:
+                            qtype1 = DECODE_IMM(1);
+                            qtype2 = DECODE_IMM(1);
+                            print_opcode(reg_num ? "jdnsqeq2" : "jdnsqne2");
+                            break;
+                        case JDNSQMATCHSAFE2_EXT_OPCODE:
+                            qtype1 = DECODE_IMM(1);
+                            qtype2 = DECODE_IMM(1);
+                            print_opcode(reg_num ? "jdnsqeqsafe2" : "jdnsqnesafe2");
+                            break;
+                        case JDNSQMATCH1_EXT_OPCODE:
+                            qtype1 = DECODE_IMM(2);
+                            print_opcode(reg_num ? "jdnsqeq1" : "jdnsqne1");
+                            break;
+                        case JDNSQMATCHSAFE1_EXT_OPCODE:
+                            qtype1 = DECODE_IMM(2);
+                            print_opcode(reg_num ? "jdnsqeqsafe1" : "jdnsqnesafe1");
+                            break;
                         default:
                             bprintf("unknown_ext %u", imm); break;
                     }
@@ -348,15 +444,22 @@ const char* apf_disassemble(const uint8_t* program, uint32_t program_len, uint32
                     end += 2;
                     print_jump_target(end + offs, program_len);
                     bprintf(", ");
-                    if (imm == JDNSQMATCH_EXT_OPCODE || imm == JDNSQMATCHSAFE_EXT_OPCODE) {
-                        bprintf("%d, ", qtype);
+                    if (imm == JDNSQMATCH_EXT_OPCODE || imm == JDNSQMATCHSAFE_EXT_OPCODE ||
+                        imm == JDNSQMATCH1_EXT_OPCODE || imm == JDNSQMATCHSAFE1_EXT_OPCODE) {
+                        print_qtype(qtype1);
+                    } else if (imm == JDNSQMATCH2_EXT_OPCODE || imm == JDNSQMATCHSAFE2_EXT_OPCODE) {
+                        print_qtype(qtype1);
+                        print_qtype(qtype2);
                     }
                     while (*ptr2pc < end) {
                         uint8_t byte = program[(*ptr2pc)++];
+                        // value == 0xff is a wildcard that consumes the whole label.
                         // values < 0x40 could be lengths, but - and 0..9 are in practice usually
                         // too long to be lengths so print them as characters. All other chars < 0x40
                         // are not valid in dns character.
-                        if (byte == '-' || (byte >= '0' && byte <= '9') || byte >= 0x40) {
+                        if (byte == 0xff) {
+                            bprintf("(*)");
+                        } else if (byte == '-' || (byte >= '0' && byte <= '9') || byte >= 0x40) {
                             bprintf("%c", byte);
                         } else {
                             bprintf("(%d)", byte);
@@ -435,20 +538,67 @@ const char* apf_disassemble(const uint8_t* program, uint32_t program_len, uint32
             break;
         }
         case PKTDATACOPY_OPCODE: {
+            uint32_t src_offs = imm;
+            uint32_t copy_len = DECODE_IMM(1);
+            if (!copy_len) copy_len = 256 + DECODE_IMM(1);
             if (reg_num == 0) {
                 print_opcode("pktcopy");
+                bprintf("src=%d, len=%d", src_offs, copy_len);
             } else {
                 print_opcode("datacopy");
+                bprintf("src=%d, (%d)", src_offs, copy_len);
+                for (uint32_t i = 0; i < copy_len; ++i) {
+                    uint8_t byte = program[src_offs + i];
+                    bprintf("%02x", byte);
+                }
             }
-            uint32_t src_offs = imm;
-            uint32_t copy_len = DECODE_IMM(1);
-            bprintf("src=%d, len=%d", src_offs, copy_len);
             break;
         }
+        // JNSET_OPCODE handled up above
+        case JBSPTRMATCH_OPCODE: {
+            print_opcode(reg_num ? "jbsptreq" : "jbsptrne");
+            bprintf("pktofs=%d, ", DECODE_IMM(1));
+            const uint8_t cmp_imm = DECODE_IMM(1);
+            const uint8_t cnt = (cmp_imm >> 4) + 1; // 1..16
+            const uint8_t len = (cmp_imm & 15) + 1; // 1..16
+            bprintf("(%u), ", len);
+            print_jump_target(*ptr2pc + imm + cnt, program_len);
+            bprintf(", ");
+            if (cnt > 1) bprintf("{ ");
+            for (int i = 0; i < cnt; ++i) {
+                uint8_t ofs = program[(*ptr2pc)++];
+                bprintf("@%d[", ofs * 2);
+                for (int j = 0; j < len; ++j) bprintf("%02x", program[3 + 2 * ofs + j]);
+                bprintf("]");
+                if (i != cnt - 1) bprintf(", ");
+            }
+            if (cnt > 1) bprintf(" }[%d]", cnt);
+            break;
+        }
+        case ALLOC_XMIT_OPCODE:
+            if (reg_num) {
+                print_opcode("allocate");
+                bprintf("(%d)", 266 + 8 * imm);
+            } else {
+                if (len_field) {
+                    static const char * const protocol[4] = { "udp", "tcp", "icmp", "alert/icmp" };
+                    print_opcode(imm & 3 ? "transmit" : "transmitudp");
+                    bprintf("offload=%s/%s, partial_csum=0x%x", imm & 4 ? "ipv6" : "ipv4",
+                            protocol[imm & 3], imm >> 3);
+                } else {
+                    print_opcode("transmit");
+                }
+            }
+            break;
         // Unknown opcode
         default:
             bprintf("unknown %u", opcode);
             break;
     }
-    return print_buf;
+    snprintf(prefix_buf, sizeof(prefix_buf), "(%4u) ", (*ptr2pc - prev_pc));
+    disas_ret ret = {
+        .prefix = prefix_buf,
+        .content = print_buf
+    };
+    return ret;
 }
diff --git a/disassembler.h b/disassembler.h
index 3c40cd6..db4dcfe 100644
--- a/disassembler.h
+++ b/disassembler.h
@@ -22,6 +22,11 @@
 extern "C" {
 #endif
 
+typedef struct {
+    const char* prefix;
+    const char* content;
+} disas_ret;
+
 /**
  * Disassembles an APF program into a human-readable format.
  *
@@ -30,10 +35,12 @@ extern "C" {
  * @param ptr2pc pointer to the program counter which points to the current instruction.
  *           After function call, the program counter will be updated to point to the
  *           next instruction.
+ * @param ptr2pc pointer to the program counter which points to the current instruction.
+ * @param is_v6 if it is an APFv6 program or not.
  *
  * @return pointer to static buffer which contains human readable text.
  */
-const char* apf_disassemble(const uint8_t* program, uint32_t program_len, uint32_t* ptr2pc);
+disas_ret apf_disassemble(const uint8_t* program, uint32_t program_len, uint32_t* ptr2pc, bool is_v6);
 
 #ifdef __cplusplus
 }
diff --git a/next/.gitignore b/next/.gitignore
new file mode 100644
index 0000000..0c8e9cf
--- /dev/null
+++ b/next/.gitignore
@@ -0,0 +1,5 @@
+apf_interpreter.arm.o
+apf_interpreter.armt.o
+apf_interpreter.aarch64.o
+apf_interpreter.x86.o
+apf_interpreter.x86-64.o
diff --git a/v7/Android.bp b/next/Android.bp
similarity index 76%
rename from v7/Android.bp
rename to next/Android.bp
index 1277aaf..7ab382f 100644
--- a/v7/Android.bp
+++ b/next/Android.bp
@@ -19,7 +19,7 @@ package {
 }
 
 cc_defaults {
-    name: "apfv7_defaults",
+    name: "apfnext_defaults",
 
     cflags: [
         "-Wall",
@@ -37,11 +37,13 @@ cc_defaults {
 }
 
 cc_library_static {
-    name: "libapf_v7",
-    defaults: ["apfv7_defaults"],
+    name: "libapf_next",
+    defaults: ["apfnext_defaults"],
+    static_libs: [
+        "libapfbuf",
+    ],
     srcs: [
         "apf_interpreter.c",
-        "test_buf_allocator.c",
     ],
     sdk_version: "24",
 }
@@ -71,3 +73,27 @@ sh_test_host {
         unit_test: true,
     },
 }
+
+cc_test_host {
+    name: "apf_checksum_test",
+    srcs: [
+        "apf_checksum_test.cc",
+    ],
+    cflags: [
+        "-Wall",
+        "-Wno-unused-function",
+    ],
+    stl: "c++_static",
+}
+
+cc_test_host {
+    name: "apf_dns_test",
+    srcs: [
+        "apf_dns_test.cc",
+    ],
+    cflags: [
+        "-Wall",
+        "-Wno-unused-function",
+    ],
+    stl: "c++_static",
+}
diff --git a/v7/apf.h b/next/apf.h
similarity index 85%
rename from v7/apf.h
rename to next/apf.h
index 29f9785..7da3005 100644
--- a/v7/apf.h
+++ b/next/apf.h
@@ -206,12 +206,40 @@ typedef union {
  * R=0 means copy from packet.
  * R=1 means copy from APF program/data region.
  * The source offset is stored in imm1, copy length is stored in u8 imm2.
+ * APFv6.1: if u8 imm2 is 0 then copy length is 256 + extra u8 imm3
  * e.g. "pktcopy 0, 16" or "datacopy 0, 16"
  */
 #define PKTDATACOPY_OPCODE 25
 
 #define JNSET_OPCODE 26 // JSET with reverse condition (jump if no bits set)
 
+/* APFv6.1: Compare byte sequence [R=0 not] equal, e.g. "jbsptrne 22,16,label,<dataptr>"
+ * imm1 is jmp target
+ * imm2(u8) is offset [0..255] into packet
+ * imm3(u8) is (count - 1) * 16 + (compare_len - 1), thus both count & compare_len are in [1..16]
+ * which is followed by compare_len u8 'even offset' ptrs into max 526 byte data section to compare
+ * against - ie. they are multipied by 2 and have 3 added to them (to skip over 'datajmp u16')
+ * Warning: do not specify the same byte sequence multiple times.
+ */
+#define JBSPTRMATCH_OPCODE 27
+
+/* APFv6.1: Bytecode optimized allocate | transmit instruction.
+ * R=1 -> allocate(266 + imm * 8)
+ * R=0 -> transmit
+ *   immlen=0 -> no checksum offload (transmit ip_ofs=255)
+ *   immlen>0 -> with checksum offload (transmit(udp) ip_ofs=14 ...)
+ *     imm & 7 | type of offload      | ip_ofs | udp | csum_start  | csum_ofs      | partial_csum |
+ *         0   | ip4/udp              |   14   |  X  | 14+20-8 =26 | 14+20   +6=40 |   imm >> 3   |
+ *         1   | ip4/tcp              |   14   |     | 14+20-8 =26 | 14+20  +10=44 |     --"--    |
+ *         2   | ip4/icmp             |   14   |     | 14+20   =34 | 14+20   +2=36 |     --"--    |
+ *         3   | ip4/routeralert/icmp |   14   |     | 14+20+4 =38 | 14+20+4 +2=40 |     --"--    |
+ *         4   | ip6/udp              |   14   |  X  | 14+40-32=22 | 14+40   +6=60 |     --"--    |
+ *         5   | ip6/tcp              |   14   |     | 14+40-32=22 | 14+40  +10=64 |     --"--    |
+ *         6   | ip6/icmp             |   14   |     | 14+40-32=22 | 14+40   +2=56 |     --"--    |
+ *         7   | ip6/routeralert/icmp |   14   |     | 14+40-32=22 | 14+40+8 +2=64 |     --"--    |
+ */
+#define ALLOC_XMIT_OPCODE 28
+
 /* ---------------------------------------------------------------------------------------------- */
 
 // Extended opcodes.
@@ -233,6 +261,7 @@ typedef union {
  * On failure automatically executes 'pass 3'
  */
 #define ALLOCATE_EXT_OPCODE 36
+
 /* Transmit and deallocate the buffer (transmission can be delayed until the program
  * terminates).  Length of buffer is the output buffer pointer (0 means discard).
  * R=1 iff udp style L4 checksum
@@ -243,6 +272,7 @@ typedef union {
  * "e.g. transmit"
  */
 #define TRANSMIT_EXT_OPCODE 37
+
 /* Write 1, 2 or 4 byte value from register to the output buffer and auto-increment the
  * output buffer pointer.
  * e.g. "ewrite1 r0" or "ewrite2 r1"
@@ -257,10 +287,12 @@ typedef union {
  * R=0 means copy from packet.
  * R=1 means copy from APF program/data region.
  * The source offset is stored in R0, copy length is stored in u8 imm2 or R1.
+ * APFv6.1: if u8 imm2 is 0 then copy length is 256 + extra u8 imm3.
  * e.g. "epktcopy r0, 16", "edatacopy r0, 16", "epktcopy r0, r1", "edatacopy r0, r1"
  */
 #define EPKTDATACOPYIMM_EXT_OPCODE 41
 #define EPKTDATACOPYR1_EXT_OPCODE 42
+
 /* Jumps if the UDP payload content (starting at R0) does [not] match one
  * of the specified QNAMEs in question records, applying case insensitivity.
  * SAFE version PASSES corrupt packets, while the other one DROPS.
@@ -269,11 +301,15 @@ typedef union {
  * imm1: Extended opcode
  * imm2: Jump label offset
  * imm3(u8): Question type (PTR/SRV/TXT/A/AAAA)
+ *   note: imm3 is instead u16 in '1' version
  * imm4(bytes): null terminated list of null terminated LV-encoded QNAMEs
  * e.g.: "jdnsqeq R0,label,0xc,\002aa\005local\0\0", "jdnsqne R0,label,0xc,\002aa\005local\0\0"
  */
 #define JDNSQMATCH_EXT_OPCODE 43
 #define JDNSQMATCHSAFE_EXT_OPCODE 45
+#define JDNSQMATCH1_EXT_OPCODE 55
+#define JDNSQMATCHSAFE1_EXT_OPCODE 57
+
 /* Jumps if the UDP payload content (starting at R0) does [not] match one
  * of the specified NAMEs in answers/authority/additional records, applying
  * case insensitivity.
@@ -288,6 +324,23 @@ typedef union {
 #define JDNSAMATCH_EXT_OPCODE 44
 #define JDNSAMATCHSAFE_EXT_OPCODE 46
 
+/* Jumps if the UDP payload content (starting at R0) does [not] match one
+ * of the specified QNAMEs in question records, applying case insensitivity.
+ * The qtypes in the input packet can match either of the two supplied qtypes.
+ * SAFE version PASSES corrupt packets, while the other one DROPS.
+ * R=0/1 meaning 'does not match'/'matches'
+ * R0: Offset to UDP payload content
+ * imm1: Extended opcode
+ * imm2: Jump label offset
+ * imm3(u8): Question type1 (PTR/SRV/TXT/A/AAAA)
+ * imm4(u8): Question type2 (PTR/SRV/TXT/A/AAAA)
+ * imm5(bytes): null terminated list of null terminated LV-encoded QNAMEs
+ * e.g.: "jdnsqeq2 R0,label,A,AAAA,\002aa\005local\0\0",
+ *       "jdnsqne2 R0,label,A,AAAA,\002aa\005local\0\0"
+ */
+#define JDNSQMATCH2_EXT_OPCODE 51
+#define JDNSQMATCHSAFE2_EXT_OPCODE 53
+
 /* Jump if register is [not] one of the list of values
  * R bit - specifies the register (R0/R1) to test
  * imm1: Extended opcode
@@ -305,6 +358,8 @@ typedef union {
  */
 #define EXCEPTIONBUFFER_EXT_OPCODE 48
 
+// Note: 51, 53, 55, 57 used up above for DNS matching
+
 // This extended opcode is used to implement PKTDATACOPY_OPCODE
 #define PKTDATACOPYIMM_EXT_OPCODE 65536
 
diff --git a/v7/apf_assemble_test.xml b/next/apf_assemble_test.xml
similarity index 100%
rename from v7/apf_assemble_test.xml
rename to next/apf_assemble_test.xml
diff --git a/apf_checksum.h b/next/apf_checksum.h
similarity index 100%
rename from apf_checksum.h
rename to next/apf_checksum.h
diff --git a/apf_checksum_test.cc b/next/apf_checksum_test.cc
similarity index 100%
rename from apf_checksum_test.cc
rename to next/apf_checksum_test.cc
diff --git a/apf_defs.h b/next/apf_defs.h
similarity index 100%
rename from apf_defs.h
rename to next/apf_defs.h
diff --git a/apf_dns.h b/next/apf_dns.h
similarity index 91%
rename from apf_dns.h
rename to next/apf_dns.h
index aed9dfd..0720295 100644
--- a/apf_dns.h
+++ b/next/apf_dns.h
@@ -67,14 +67,16 @@ FUNC(match_result_type match_single_name(const u8* needle,
 
 /**
  * Check if DNS packet contains any of the target names with the provided
- * question_type.
+ * question_types.
  *
  * @param needles - non-NULL - pointer to DNS encoded target nameS to match against.
  *   example: [3]foo[3]com[0][3]bar[3]net[0][0]  -- note ends with an extra NULL byte.
  * @param needle_bound - non-NULL - points at first invalid byte past needles.
  * @param udp - non-NULL - pointer to the start of the UDP payload (DNS header).
  * @param udp_len - length of the UDP payload.
- * @param question_type - question type to match against or -1 to match answers.
+ * @param question_type1 - question type to match against or -1 to match answers.
+ *                         If question_type1 is -1, we won't check question_type2.
+ * @param question_type2 - question type to match against or -1 to match answers.
  *
  * @return 1 if matched, 0 if not matched, -1 if error in packet, -2 if error in program.
  */
@@ -82,7 +84,8 @@ FUNC(match_result_type match_names(const u8* needles,
                               const u8* const needle_bound,
                               const u8* const udp,
                               const u32 udp_len,
-                              const int question_type)) {
+                              const int question_type1,
+                              const int question_type2)) {
     u32 num_questions, num_answers;
     if (udp_len < 12) return error_packet;  /* lack of dns header */
 
@@ -103,12 +106,13 @@ FUNC(match_result_type match_names(const u8* needles,
             if (ofs + 2 > udp_len) return error_packet;
             qtype = (int)read_be16(udp + ofs);
             ofs += 4; /* skip be16 qtype & qclass */
-            if (question_type == -1) continue;
+            if (question_type1 == -1) continue;
             if (m == nomatch) continue;
-            if (qtype == 0xFF /* QTYPE_ANY */ || qtype == question_type) return match;
+            if (qtype == 0xFF /* QTYPE_ANY */ || qtype == question_type1 || qtype == question_type2)
+              return match;
         }
         /* match answers */
-        if (question_type == -1) for (i = 0; i < num_answers; ++i) {
+        if (question_type1 == -1) for (i = 0; i < num_answers; ++i) {
             match_result_type m = match_single_name(needles, needle_bound, udp, udp_len, &ofs);
             if (m < nomatch) return m;
             ofs += 8; /* skip be16 type, class & be32 ttl */
diff --git a/apf_dns_test.cc b/next/apf_dns_test.cc
similarity index 80%
rename from apf_dns_test.cc
rename to next/apf_dns_test.cc
index 9497ccd..5f0d23e 100644
--- a/apf_dns_test.cc
+++ b/next/apf_dns_test.cc
@@ -145,7 +145,9 @@ TEST(ApfDnsTest, MatchNamesInQuestions) {
         0xc0, 0x0e, // qname2 = b.local (name compression)
         0x00, 0x01, 0x00, 0x01 // type = A, class = 0x0001
     };
-    EXPECT_EQ(match_names(needles_match1, needles_match1 + sizeof(needles_match1),  udp_payload, sizeof(udp_payload), 0x01), match);
+    EXPECT_EQ(match_names(needles_match1, needles_match1 + sizeof(needles_match1),  udp_payload, sizeof(udp_payload), 0x01, 0x11), match);
+    EXPECT_EQ(match_names(needles_match1, needles_match1 + sizeof(needles_match1),  udp_payload, sizeof(udp_payload), 0x01, 0x01), match);
+    EXPECT_EQ(match_names(needles_match1, needles_match1 + sizeof(needles_match1),  udp_payload, sizeof(udp_payload), 0x11, 0x01), match);
     // needles = { A, B.LOCAL }
     const uint8_t needles_match2[] = {
         0x01, 'A',
@@ -155,7 +157,9 @@ TEST(ApfDnsTest, MatchNamesInQuestions) {
         0x00,
         0x00
     };
-    EXPECT_EQ(match_names(needles_match2, needles_match2 + sizeof(needles_match2), udp_payload, sizeof(udp_payload), 0x01), match);
+    EXPECT_EQ(match_names(needles_match2, needles_match2 + sizeof(needles_match2), udp_payload, sizeof(udp_payload), 0x01, 0x11), match);
+    EXPECT_EQ(match_names(needles_match2, needles_match2 + sizeof(needles_match2), udp_payload, sizeof(udp_payload), 0x01, 0x01), match);
+    EXPECT_EQ(match_names(needles_match2, needles_match2 + sizeof(needles_match2), udp_payload, sizeof(udp_payload), 0x11, 0x01), match);
     // needles = { *, B.* }
     const uint8_t needles_match2_star[] = {
         0xff,
@@ -165,7 +169,9 @@ TEST(ApfDnsTest, MatchNamesInQuestions) {
         0x00,
         0x00
     };
-    EXPECT_EQ(match_names(needles_match2_star, needles_match2_star + sizeof(needles_match2_star), udp_payload, sizeof(udp_payload), 0x01), match);
+    EXPECT_EQ(match_names(needles_match2_star, needles_match2_star + sizeof(needles_match2_star), udp_payload, sizeof(udp_payload), 0x01, 0x11), match);
+    EXPECT_EQ(match_names(needles_match2_star, needles_match2_star + sizeof(needles_match2_star), udp_payload, sizeof(udp_payload), 0x01, 0x01), match);
+    EXPECT_EQ(match_names(needles_match2_star, needles_match2_star + sizeof(needles_match2_star), udp_payload, sizeof(udp_payload), 0x11, 0x01), match);
     // needles = { C.LOCAL }
     const uint8_t needles_nomatch[] = {
         0x01, 'C',
@@ -173,7 +179,9 @@ TEST(ApfDnsTest, MatchNamesInQuestions) {
         0x00,
         0x00
     };
-    EXPECT_EQ(match_names(needles_nomatch, needles_nomatch + sizeof(needles_nomatch), udp_payload, sizeof(udp_payload), 0x01), nomatch);
+    EXPECT_EQ(match_names(needles_nomatch, needles_nomatch + sizeof(needles_nomatch), udp_payload, sizeof(udp_payload), 0x01, 0x11), nomatch);
+    EXPECT_EQ(match_names(needles_nomatch, needles_nomatch + sizeof(needles_nomatch), udp_payload, sizeof(udp_payload), 0x01, 0x01), nomatch);
+    EXPECT_EQ(match_names(needles_nomatch, needles_nomatch + sizeof(needles_nomatch), udp_payload, sizeof(udp_payload), 0x11, 0x01), nomatch);
     // needles = { C.* }
     const uint8_t needles_nomatch_star[] = {
         0x01, 'C',
@@ -181,7 +189,9 @@ TEST(ApfDnsTest, MatchNamesInQuestions) {
         0x00,
         0x00
     };
-    EXPECT_EQ(match_names(needles_nomatch_star, needles_nomatch_star + sizeof(needles_nomatch_star), udp_payload, sizeof(udp_payload), 0x01), nomatch);
+    EXPECT_EQ(match_names(needles_nomatch_star, needles_nomatch_star + sizeof(needles_nomatch_star), udp_payload, sizeof(udp_payload), 0x01, 0x11), nomatch);
+    EXPECT_EQ(match_names(needles_nomatch_star, needles_nomatch_star + sizeof(needles_nomatch_star), udp_payload, sizeof(udp_payload), 0x01, 0x01), nomatch);
+    EXPECT_EQ(match_names(needles_nomatch_star, needles_nomatch_star + sizeof(needles_nomatch_star), udp_payload, sizeof(udp_payload), 0x11, 0x01), nomatch);
 }
 
 TEST(ApfDnsTest, MatchNamesInAnswers) {
@@ -211,7 +221,7 @@ TEST(ApfDnsTest, MatchNamesInAnswers) {
         0x00, 0x00, 0x00, 0x78, // ttl = 120
         0x00, 0x04, 0xc0, 0xa8, 0x01, 0x09 // rdlengh = 4, rdata = 192.168.1.9
     };
-    EXPECT_EQ(match_names(needles_match1, needles_match1 + sizeof(needles_match1), udp_payload, sizeof(udp_payload), -1), match);
+    EXPECT_EQ(match_names(needles_match1, needles_match1 + sizeof(needles_match1), udp_payload, sizeof(udp_payload), -1, -1), match);
     // needles = { A, B.LOCAL }
     const uint8_t needles_match2[] = {
         0x01, 'A', 0x00,
@@ -220,7 +230,7 @@ TEST(ApfDnsTest, MatchNamesInAnswers) {
         0x00,
         0x00
     };
-    EXPECT_EQ(match_names(needles_match2, needles_match2 + sizeof(needles_match2), udp_payload, sizeof(udp_payload), -1), match);
+    EXPECT_EQ(match_names(needles_match2, needles_match2 + sizeof(needles_match2), udp_payload, sizeof(udp_payload), -1, -1), match);
     // needles = { *, B.* }
     const uint8_t needles_match2_star[] = {
         0xff,
@@ -229,7 +239,7 @@ TEST(ApfDnsTest, MatchNamesInAnswers) {
         0x00,
         0x00
     };
-    EXPECT_EQ(match_names(needles_match2_star, needles_match2_star + sizeof(needles_match2_star), udp_payload, sizeof(udp_payload), -1), match);
+    EXPECT_EQ(match_names(needles_match2_star, needles_match2_star + sizeof(needles_match2_star), udp_payload, sizeof(udp_payload), -1, -1), match);
     // needles = { C.LOCAL }
     const uint8_t needles_nomatch[] = {
         0x01, 'C',
@@ -237,7 +247,7 @@ TEST(ApfDnsTest, MatchNamesInAnswers) {
         0x00,
         0x00
     };
-    EXPECT_EQ(match_names(needles_nomatch, needles_nomatch + sizeof(needles_nomatch), udp_payload, sizeof(udp_payload), -1), nomatch);
+    EXPECT_EQ(match_names(needles_nomatch, needles_nomatch + sizeof(needles_nomatch), udp_payload, sizeof(udp_payload), -1, -1), nomatch);
     // needles = { C.* }
     const uint8_t needles_nomatch_star[] = {
         0x01, 'C',
@@ -245,7 +255,7 @@ TEST(ApfDnsTest, MatchNamesInAnswers) {
         0x00,
         0x00
     };
-    EXPECT_EQ(match_names(needles_nomatch_star, needles_nomatch_star + sizeof(needles_nomatch_star), udp_payload, sizeof(udp_payload), -1), nomatch);
+    EXPECT_EQ(match_names(needles_nomatch_star, needles_nomatch_star + sizeof(needles_nomatch_star), udp_payload, sizeof(udp_payload), -1, -1), nomatch);
 }
 
 } // namespace apf
diff --git a/v7/apf_interpreter.c b/next/apf_interpreter.c
similarity index 85%
rename from v7/apf_interpreter.c
rename to next/apf_interpreter.c
index 635ee3e..39c1760 100644
--- a/v7/apf_interpreter.c
+++ b/next/apf_interpreter.c
@@ -262,12 +262,40 @@ typedef union {
  * R=0 means copy from packet.
  * R=1 means copy from APF program/data region.
  * The source offset is stored in imm1, copy length is stored in u8 imm2.
+ * APFv6.1: if u8 imm2 is 0 then copy length is 256 + extra u8 imm3
  * e.g. "pktcopy 0, 16" or "datacopy 0, 16"
  */
 #define PKTDATACOPY_OPCODE 25
 
 #define JNSET_OPCODE 26 /* JSET with reverse condition (jump if no bits set) */
 
+/* APFv6.1: Compare byte sequence [R=0 not] equal, e.g. "jbsptrne 22,16,label,<dataptr>"
+ * imm1 is jmp target
+ * imm2(u8) is offset [0..255] into packet
+ * imm3(u8) is (count - 1) * 16 + (compare_len - 1), thus both count & compare_len are in [1..16]
+ * which is followed by compare_len u8 'even offset' ptrs into max 526 byte data section to compare
+ * against - ie. they are multipied by 2 and have 3 added to them (to skip over 'datajmp u16')
+ * Warning: do not specify the same byte sequence multiple times.
+ */
+#define JBSPTRMATCH_OPCODE 27
+
+/* APFv6.1: Bytecode optimized allocate | transmit instruction.
+ * R=1 -> allocate(266 + imm * 8)
+ * R=0 -> transmit
+ *   immlen=0 -> no checksum offload (transmit ip_ofs=255)
+ *   immlen>0 -> with checksum offload (transmit(udp) ip_ofs=14 ...)
+ *     imm & 7 | type of offload      | ip_ofs | udp | csum_start  | csum_ofs      | partial_csum |
+ *         0   | ip4/udp              |   14   |  X  | 14+20-8 =26 | 14+20   +6=40 |   imm >> 3   |
+ *         1   | ip4/tcp              |   14   |     | 14+20-8 =26 | 14+20  +10=44 |     --"--    |
+ *         2   | ip4/icmp             |   14   |     | 14+20   =34 | 14+20   +2=36 |     --"--    |
+ *         3   | ip4/routeralert/icmp |   14   |     | 14+20+4 =38 | 14+20+4 +2=40 |     --"--    |
+ *         4   | ip6/udp              |   14   |  X  | 14+40-32=22 | 14+40   +6=60 |     --"--    |
+ *         5   | ip6/tcp              |   14   |     | 14+40-32=22 | 14+40  +10=64 |     --"--    |
+ *         6   | ip6/icmp             |   14   |     | 14+40-32=22 | 14+40   +2=56 |     --"--    |
+ *         7   | ip6/routeralert/icmp |   14   |     | 14+40-32=22 | 14+40+8 +2=64 |     --"--    |
+ */
+#define ALLOC_XMIT_OPCODE 28
+
 /* ---------------------------------------------------------------------------------------------- */
 
 /* Extended opcodes. */
@@ -289,6 +317,7 @@ typedef union {
  * On failure automatically executes 'pass 3'
  */
 #define ALLOCATE_EXT_OPCODE 36
+
 /* Transmit and deallocate the buffer (transmission can be delayed until the program
  * terminates).  Length of buffer is the output buffer pointer (0 means discard).
  * R=1 iff udp style L4 checksum
@@ -299,6 +328,7 @@ typedef union {
  * "e.g. transmit"
  */
 #define TRANSMIT_EXT_OPCODE 37
+
 /* Write 1, 2 or 4 byte value from register to the output buffer and auto-increment the
  * output buffer pointer.
  * e.g. "ewrite1 r0" or "ewrite2 r1"
@@ -313,10 +343,12 @@ typedef union {
  * R=0 means copy from packet.
  * R=1 means copy from APF program/data region.
  * The source offset is stored in R0, copy length is stored in u8 imm2 or R1.
+ * APFv6.1: if u8 imm2 is 0 then copy length is 256 + extra u8 imm3.
  * e.g. "epktcopy r0, 16", "edatacopy r0, 16", "epktcopy r0, r1", "edatacopy r0, r1"
  */
 #define EPKTDATACOPYIMM_EXT_OPCODE 41
 #define EPKTDATACOPYR1_EXT_OPCODE 42
+
 /* Jumps if the UDP payload content (starting at R0) does [not] match one
  * of the specified QNAMEs in question records, applying case insensitivity.
  * SAFE version PASSES corrupt packets, while the other one DROPS.
@@ -325,11 +357,15 @@ typedef union {
  * imm1: Extended opcode
  * imm2: Jump label offset
  * imm3(u8): Question type (PTR/SRV/TXT/A/AAAA)
+ *   note: imm3 is instead u16 in '1' version
  * imm4(bytes): null terminated list of null terminated LV-encoded QNAMEs
  * e.g.: "jdnsqeq R0,label,0xc,\002aa\005local\0\0", "jdnsqne R0,label,0xc,\002aa\005local\0\0"
  */
 #define JDNSQMATCH_EXT_OPCODE 43
 #define JDNSQMATCHSAFE_EXT_OPCODE 45
+#define JDNSQMATCH1_EXT_OPCODE 55
+#define JDNSQMATCHSAFE1_EXT_OPCODE 57
+
 /* Jumps if the UDP payload content (starting at R0) does [not] match one
  * of the specified NAMEs in answers/authority/additional records, applying
  * case insensitivity.
@@ -344,6 +380,23 @@ typedef union {
 #define JDNSAMATCH_EXT_OPCODE 44
 #define JDNSAMATCHSAFE_EXT_OPCODE 46
 
+/* Jumps if the UDP payload content (starting at R0) does [not] match one
+ * of the specified QNAMEs in question records, applying case insensitivity.
+ * The qtypes in the input packet can match either of the two supplied qtypes.
+ * SAFE version PASSES corrupt packets, while the other one DROPS.
+ * R=0/1 meaning 'does not match'/'matches'
+ * R0: Offset to UDP payload content
+ * imm1: Extended opcode
+ * imm2: Jump label offset
+ * imm3(u8): Question type1 (PTR/SRV/TXT/A/AAAA)
+ * imm4(u8): Question type2 (PTR/SRV/TXT/A/AAAA)
+ * imm5(bytes): null terminated list of null terminated LV-encoded QNAMEs
+ * e.g.: "jdnsqeq2 R0,label,A,AAAA,\002aa\005local\0\0",
+ *       "jdnsqne2 R0,label,A,AAAA,\002aa\005local\0\0"
+ */
+#define JDNSQMATCH2_EXT_OPCODE 51
+#define JDNSQMATCHSAFE2_EXT_OPCODE 53
+
 /* Jump if register is [not] one of the list of values
  * R bit - specifies the register (R0/R1) to test
  * imm1: Extended opcode
@@ -361,6 +414,8 @@ typedef union {
  */
 #define EXCEPTIONBUFFER_EXT_OPCODE 48
 
+/* Note: 51, 53, 55, 57 used up above for DNS matching */
+
 /* This extended opcode is used to implement PKTDATACOPY_OPCODE */
 #define PKTDATACOPYIMM_EXT_OPCODE 65536
 
@@ -454,14 +509,16 @@ FUNC(match_result_type apf_internal_match_single_name(const u8* needle,
 
 /**
  * Check if DNS packet contains any of the target names with the provided
- * question_type.
+ * question_types.
  *
  * @param needles - non-NULL - pointer to DNS encoded target nameS to match against.
  *   example: [3]foo[3]com[0][3]bar[3]net[0][0]  -- note ends with an extra NULL byte.
  * @param needle_bound - non-NULL - points at first invalid byte past needles.
  * @param udp - non-NULL - pointer to the start of the UDP payload (DNS header).
  * @param udp_len - length of the UDP payload.
- * @param question_type - question type to match against or -1 to match answers.
+ * @param question_type1 - question type to match against or -1 to match answers.
+ *                         If question_type1 is -1, we won't check question_type2.
+ * @param question_type2 - question type to match against or -1 to match answers.
  *
  * @return 1 if matched, 0 if not matched, -1 if error in packet, -2 if error in program.
  */
@@ -469,7 +526,8 @@ FUNC(match_result_type apf_internal_match_names(const u8* needles,
                               const u8* const needle_bound,
                               const u8* const udp,
                               const u32 udp_len,
-                              const int question_type)) {
+                              const int question_type1,
+                              const int question_type2)) {
     u32 num_questions, num_answers;
     if (udp_len < 12) return error_packet;  /* lack of dns header */
 
@@ -490,12 +548,13 @@ FUNC(match_result_type apf_internal_match_names(const u8* needles,
             if (ofs + 2 > udp_len) return error_packet;
             qtype = (int)read_be16(udp + ofs);
             ofs += 4; /* skip be16 qtype & qclass */
-            if (question_type == -1) continue;
+            if (question_type1 == -1) continue;
             if (m == nomatch) continue;
-            if (qtype == 0xFF /* QTYPE_ANY */ || qtype == question_type) return match;
+            if (qtype == 0xFF /* QTYPE_ANY */ || qtype == question_type1 || qtype == question_type2)
+              return match;
         }
         /* match answers */
-        if (question_type == -1) for (i = 0; i < num_answers; ++i) {
+        if (question_type1 == -1) for (i = 0; i < num_answers; ++i) {
             match_result_type m = apf_internal_match_single_name(needles, needle_bound, udp, udp_len, &ofs);
             if (m < nomatch) return m;
             ofs += 8; /* skip be16 type, class & be32 ttl */
@@ -609,7 +668,7 @@ extern void APF_TRACE_HOOK(u32 pc, const u32* regs, const u8* program,
 #define ENFORCE_UNSIGNED(c) ((c)==(u32)(c))
 
 u32 apf_version(void) {
-    return 20240510;
+    return 20250228;
 }
 
 typedef struct {
@@ -694,9 +753,9 @@ static int do_apf_run(apf_context* ctx) {
     /* upper bound on the number of instructions in the program. */
     u32 instructions_remaining = ctx->program_len;
 
-    /* APFv6 requires at least 5 u32 counters at the end of ram, this makes counter[-5]++ valid */
+    /* APFv6.1 requires at least 6 u32 counters at the end of ram, this makes counter[-6]++ valid */
     /* This cannot wrap due to previous check, that enforced program_len & ram_len < 2GiB. */
-    if (ctx->program_len + 20 > ctx->ram_len) return EXCEPTION;
+    if (ctx->program_len + 24 > ctx->ram_len) return EXCEPTION;
 
     /* Only populate if packet long enough, and IP version is IPv4. */
     /* Note: this doesn't actually check the ethertype... */
@@ -716,9 +775,16 @@ static int do_apf_run(apf_context* ctx) {
     do {
       APF_TRACE_HOOK(ctx->pc, ctx->R, ctx->program, ctx->program_len,
                      ctx->packet, ctx->packet_len, ctx->mem.slot, ctx->ram_len);
-      if (ctx->pc == ctx->program_len + 1) return DROP;
-      if (ctx->pc == ctx->program_len) return PASS;
-      if (ctx->pc > ctx->program_len) return EXCEPTION;
+      if (ctx->pc >= ctx->program_len) {
+          u32 ofs = ctx->pc - ctx->program_len;
+          u32 imm = ofs >> 1;
+          if (imm > 0xFFFF) return EXCEPTION;
+          if (imm) {
+              if (4 * imm > ctx->ram_len) return EXCEPTION;
+              counter[-(s32)imm]++;
+          }
+          return (ofs & 1) ? DROP : PASS;
+      }
 
       {  /* half indent to avoid needless line length... */
 
@@ -766,7 +832,6 @@ static int do_apf_run(apf_context* ctx) {
             u32 offs = imm;
             /* Note: this can overflow and actually decrease offs. */
             if (opcode >= LDBX_OPCODE) offs += ctx->R[1];
-            ASSERT_IN_PACKET_BOUNDS(offs);
             switch (opcode) {
               case LDB_OPCODE:
               case LDBX_OPCODE:
@@ -856,6 +921,25 @@ static int do_apf_run(apf_context* ctx) {
             if (matched ^ !reg_num) ctx->pc += imm;
             break;
           }
+          case JBSPTRMATCH_OPCODE: {
+            u32 ofs = DECODE_U8();    /* 2nd imm, at worst 5 bytes past prog_len */
+            u8 cmp_imm = DECODE_U8(); /* 3rd imm, at worst 6 bytes past prog_len */
+            u8 cnt = (cmp_imm >> 4) + 1; /* 1..16 bytestrings to match */
+            u8 len = (cmp_imm & 15) + 1; /* 1..16 bytestring length */
+            const u32 last_packet_offs = ofs + len - 1;  /* min 0+1-1=0, max 255+16-1=270 */
+            Boolean matched = False;
+            /* imm is jump target offset. */
+            /* [ofs..last_packet_offs] are packet bytes to compare. */
+            ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
+            /* cnt underflow on final iteration not an issue as not used after loop. */
+            /* 4th (through max 19th) u8 immediates, this reaches at most 22 bytes past prog_len */
+            /* This assumes min ram size of 529 bytes, where APFv6.1 has min ram size of 3000 */
+            /* the +3 is to skip over the APFv6 'datajmp' instruction, while 2* to have access to 526 bytes, */
+            /* Primary purpose is for mac (6) & ipv6 (16) addresses, so even offsets should be easy... */
+            while (cnt--) matched |= !memcmp(ctx->program + 3 + 2 * DECODE_U8(), ctx->packet + ofs, len);
+            if (matched ^ !reg_num) ctx->pc += imm;
+            break;
+          }
           /* There is a difference in APFv4 and APFv6 arithmetic behaviour! */
           /* APFv4:  R[0] op= Rbit ? R[1] : imm;  (and it thus doesn't make sense to have R=1 && len_field>0) */
           /* APFv6+: REG  op= len_field ? imm : OTHER_REG;  (note: this is *DIFFERENT* with R=1 len_field==0) */
@@ -895,19 +979,22 @@ static int do_apf_run(apf_context* ctx) {
               case NEG_EXT_OPCODE: REG = -REG;      break;
               case MOV_EXT_OPCODE: REG = OTHER_REG; break;
               case SWAP_EXT_OPCODE: {
-                u32 tmp = REG;
-                REG = OTHER_REG;
-                OTHER_REG = tmp;
+                u32 tmp = ctx->R[0];
+                ctx->R[0] = ctx->R[1];
+                ctx->R[1] = tmp;
                 break;
               }
               case ALLOCATE_EXT_OPCODE:
+              do_allocate:
                 ASSERT_RETURN(ctx->tx_buf == NULL);
-                if (reg_num == 0) {
+                if (opcode == ALLOC_XMIT_OPCODE) {
+                    ctx->tx_buf_len = 266 + 8 * imm;
+                } else if (reg_num == 0) {
                     ctx->tx_buf_len = REG;
                 } else {
                     ctx->tx_buf_len = decode_be16(ctx); /* 2nd imm, at worst 6 B past prog_len */
                 }
-                /* checksumming functions requires minimum 266 byte buffer for correctness */
+                /* checksumming functions require minimum 266 byte buffer for correctness */
                 if (ctx->tx_buf_len < 266) ctx->tx_buf_len = 266;
                 ctx->tx_buf = apf_allocate_buffer(ctx->caller_ctx, ctx->tx_buf_len);
                 if (!ctx->tx_buf) {  /* allocate failure */
@@ -918,15 +1005,38 @@ static int do_apf_run(apf_context* ctx) {
                 memset(ctx->tx_buf, 0, ctx->tx_buf_len);
                 ctx->mem.named.tx_buf_offset = 0;
                 break;
-              case TRANSMIT_EXT_OPCODE: {
+              case TRANSMIT_EXT_OPCODE:
+              do_transmit: {
                 /* tx_buf_len cannot be large because we'd run out of RAM, */
                 /* so the above unsigned comparison effectively guarantees casting pkt_len */
                 /* to a signed value does not result in it going negative. */
-                u8 ip_ofs = DECODE_U8();              /* 2nd imm, at worst 5 B past prog_len */
-                u8 csum_ofs = DECODE_U8();            /* 3rd imm, at worst 6 B past prog_len */
+                u8 ip_ofs;
+                u8 csum_ofs;
                 u8 csum_start = 0;
                 u16 partial_csum = 0;
+                Boolean udp = reg_num;
                 u32 pkt_len = ctx->mem.named.tx_buf_offset;
+                if (opcode != ALLOC_XMIT_OPCODE) {
+                    /* parse TRANSMIT_EXT_OPCODE arguments */
+                    ip_ofs = DECODE_U8();                 /* 2nd imm, at worst 5 B past prog_len */
+                    csum_ofs = DECODE_U8();               /* 3rd imm, at worst 6 B past prog_len */
+                    if (csum_ofs < 255) {
+                        csum_start = DECODE_U8();         /* 4th imm, at worst 7 B past prog_len */
+                        partial_csum = decode_be16(ctx);  /* 5th imm, at worst 9 B past prog_len */
+                    }
+                } else if (imm_len) {
+                    /* parse ALLOC_XMIT_OPCODE (R=0) immediate */
+                    static const u8 auto_csum_start[8] = { 26, 26, 34, 38, 22, 22, 22, 22 };
+                    static const u8 auto_csum_ofs[8] =   { 40, 44, 36, 40, 60, 64, 56, 64 };
+                    ip_ofs = 14;
+                    csum_ofs = auto_csum_ofs[imm & 7];
+                    csum_start = auto_csum_start[imm & 7];
+                    partial_csum = imm >> 3;
+                    udp = !(imm & 3);
+                } else {
+                    /* ALLOC_XMIT_OPCODE (R=0) with no immediate */
+                    ip_ofs = csum_ofs = 255;
+                }
                 ASSERT_RETURN(ctx->tx_buf);
                 /* If pkt_len > allocate_buffer_len, it means sth. wrong */
                 /* happened and the tx_buf should be deallocated. */
@@ -934,14 +1044,9 @@ static int do_apf_run(apf_context* ctx) {
                     do_discard_buffer(ctx);
                     return EXCEPTION;
                 }
-                if (csum_ofs < 255) {
-                    csum_start = DECODE_U8();         /* 4th imm, at worst 7 B past prog_len */
-                    partial_csum = decode_be16(ctx);  /* 5th imm, at worst 9 B past prog_len */
-                }
                 {
                     int dscp = apf_internal_csum_and_return_dscp(ctx->tx_buf, (s32)pkt_len, ip_ofs,
-                                                    partial_csum, csum_start, csum_ofs,
-                                                    (Boolean)reg_num);
+                                                    partial_csum, csum_start, csum_ofs, udp);
                     int ret = apf_internal_do_transmit_buffer(ctx, pkt_len, dscp);
                     if (ret) { counter[-4]++; return EXCEPTION; } /* transmit failure */
                 }
@@ -956,6 +1061,7 @@ static int do_apf_run(apf_context* ctx) {
                 u32 copy_len = ctx->R[1];
                 if (imm != EPKTDATACOPYR1_EXT_OPCODE) {
                     copy_len = DECODE_U8();  /* 2nd imm, at worst 8 bytes past prog_len */
+                    if (!copy_len) copy_len = 256 + DECODE_U8(); /* at worst 9 bytes past prog_len */
                 }
                 ASSERT_RETURN(ctx->tx_buf);
                 ASSERT_IN_OUTPUT_BOUNDS(dst_offs, copy_len);
@@ -973,26 +1079,45 @@ static int do_apf_run(apf_context* ctx) {
                 ctx->mem.named.tx_buf_offset = dst_offs;
                 break;
               }
-              case JDNSQMATCH_EXT_OPCODE:       /* 43 */
-              case JDNSAMATCH_EXT_OPCODE:       /* 44 */
-              case JDNSQMATCHSAFE_EXT_OPCODE:   /* 45 */
-              case JDNSAMATCHSAFE_EXT_OPCODE: { /* 46 */
+              case JDNSQMATCH_EXT_OPCODE:        /* 43 - 43 =  0 = 0b0000, u8 */
+              case JDNSAMATCH_EXT_OPCODE:        /* 44 - 43 =  1 = 0b0001, */
+              case JDNSQMATCHSAFE_EXT_OPCODE:    /* 45 - 43 =  2 = 0b0010, u8 */
+              case JDNSAMATCHSAFE_EXT_OPCODE:    /* 46 - 43 =  3 = 0b0011, */
+              case JDNSQMATCH2_EXT_OPCODE:       /* 51 - 43 =  8 = 0b1000, u8 u8 */
+              case JDNSQMATCHSAFE2_EXT_OPCODE:   /* 53 - 43 = 10 = 0b1010, u8 u8 */
+              case JDNSQMATCH1_EXT_OPCODE:       /* 55 - 43 = 12 = 0b1100, u16 */
+              case JDNSQMATCHSAFE1_EXT_OPCODE: { /* 57 - 43 = 14 = 0b1110, u16 */
                 u32 jump_offs = decode_imm(ctx, imm_len); /* 2nd imm, at worst 8 B past prog_len */
-                int qtype = -1;
-                if (imm & 1) { /* JDNSQMATCH & JDNSQMATCHSAFE are *odd* extended opcodes */
-                    qtype = DECODE_U8();  /* 3rd imm, at worst 9 bytes past prog_len */
+                int qtype1 = -1;
+                int qtype2;
+                imm -= JDNSQMATCH_EXT_OPCODE;  /* Correction for easier opcode handling */
+                /* Now, we have: */
+                /*   imm & 1 --> no following u8 */
+                /*   imm & 2 --> 'SAFE' */
+                /*   imm & 4 --> join two u8s into a be16 */
+                /*   imm & 8 --> second u8 */
+                /* bit 0 clear means we need to parse a u8, set means 'A' opcode variety */
+                if (!(imm & 1)) qtype1 = DECODE_U8();  /* 3rd imm, at worst 9 bytes past prog_len */
+                /* bit 3 set means we need to parse another u8 */
+                if (imm & 8) {
+                    qtype2 = DECODE_U8();  /* 4th imm, at worst 10 bytes past prog_len */
+                } else {
+                    qtype2 = qtype1;
                 }
+                /* bit 2 set means we need to join the two u8s into a be16 */
+                if (imm & 4) qtype2 = qtype1 = (qtype1 << 8) | qtype2;
                 {
                     u32 udp_payload_offset = ctx->R[0];
                     match_result_type match_rst = apf_internal_match_names(ctx->program + ctx->pc,
                                                               ctx->program + ctx->program_len,
                                                               ctx->packet + udp_payload_offset,
                                                               ctx->packet_len - udp_payload_offset,
-                                                              qtype);
+                                                              qtype1,
+                                                              qtype2);
                     if (match_rst == error_program) return EXCEPTION;
                     if (match_rst == error_packet) {
                         counter[-5]++; /* increment error dns packet counter */
-                        return (imm >= JDNSQMATCHSAFE_EXT_OPCODE) ? PASS : DROP;
+                        return (imm & 2) ? PASS : DROP;  /* imm & 2 detects SAFE opcodes */
                     }
                     while (ctx->pc + 1 < ctx->program_len &&
                            (ctx->program[ctx->pc] || ctx->program[ctx->pc + 1])) {
@@ -1090,6 +1215,9 @@ static int do_apf_run(apf_context* ctx) {
             }
             break;
           }
+          case ALLOC_XMIT_OPCODE:
+            if (reg_num) goto do_allocate; else goto do_transmit;
+            break;
           default:  /* Unknown opcode */
             return EXCEPTION;  /* Bail out */
         }
diff --git a/v7/apf_interpreter.h b/next/apf_interpreter.h
similarity index 100%
rename from v7/apf_interpreter.h
rename to next/apf_interpreter.h
diff --git a/v7/apf_interpreter_assemble.sh b/next/apf_interpreter_assemble.sh
similarity index 100%
rename from v7/apf_interpreter_assemble.sh
rename to next/apf_interpreter_assemble.sh
diff --git a/devtools/apf_interpreter_minimal.c b/next/apf_interpreter_minimal.c
similarity index 100%
rename from devtools/apf_interpreter_minimal.c
rename to next/apf_interpreter_minimal.c
diff --git a/v7/apf_interpreter_source.c b/next/apf_interpreter_source.c
similarity index 82%
rename from v7/apf_interpreter_source.c
rename to next/apf_interpreter_source.c
index 6a70472..997966d 100644
--- a/v7/apf_interpreter_source.c
+++ b/next/apf_interpreter_source.c
@@ -63,7 +63,7 @@ extern void APF_TRACE_HOOK(u32 pc, const u32* regs, const u8* program,
 #define ENFORCE_UNSIGNED(c) ((c)==(u32)(c))
 
 u32 apf_version(void) {
-    return 20240510;
+    return 20250228;
 }
 
 typedef struct {
@@ -148,9 +148,9 @@ static int do_apf_run(apf_context* ctx) {
     // upper bound on the number of instructions in the program.
     u32 instructions_remaining = ctx->program_len;
 
-    // APFv6 requires at least 5 u32 counters at the end of ram, this makes counter[-5]++ valid
+    // APFv6.1 requires at least 6 u32 counters at the end of ram, this makes counter[-6]++ valid
     // This cannot wrap due to previous check, that enforced program_len & ram_len < 2GiB.
-    if (ctx->program_len + 20 > ctx->ram_len) return EXCEPTION;
+    if (ctx->program_len + 24 > ctx->ram_len) return EXCEPTION;
 
     // Only populate if packet long enough, and IP version is IPv4.
     // Note: this doesn't actually check the ethertype...
@@ -170,9 +170,16 @@ static int do_apf_run(apf_context* ctx) {
     do {
       APF_TRACE_HOOK(ctx->pc, ctx->R, ctx->program, ctx->program_len,
                      ctx->packet, ctx->packet_len, ctx->mem.slot, ctx->ram_len);
-      if (ctx->pc == ctx->program_len + 1) return DROP;
-      if (ctx->pc == ctx->program_len) return PASS;
-      if (ctx->pc > ctx->program_len) return EXCEPTION;
+      if (ctx->pc >= ctx->program_len) {
+          u32 ofs = ctx->pc - ctx->program_len;
+          u32 imm = ofs >> 1;
+          if (imm > 0xFFFF) return EXCEPTION;
+          if (imm) {
+              if (4 * imm > ctx->ram_len) return EXCEPTION;
+              counter[-(s32)imm]++;
+          }
+          return (ofs & 1) ? DROP : PASS;
+      }
 
       {  // half indent to avoid needless line length...
 
@@ -220,7 +227,6 @@ static int do_apf_run(apf_context* ctx) {
             u32 offs = imm;
             // Note: this can overflow and actually decrease offs.
             if (opcode >= LDBX_OPCODE) offs += ctx->R[1];
-            ASSERT_IN_PACKET_BOUNDS(offs);
             switch (opcode) {
               case LDB_OPCODE:
               case LDBX_OPCODE:
@@ -310,6 +316,25 @@ static int do_apf_run(apf_context* ctx) {
             if (matched ^ !reg_num) ctx->pc += imm;
             break;
           }
+          case JBSPTRMATCH_OPCODE: {
+            u32 ofs = DECODE_U8();    // 2nd imm, at worst 5 bytes past prog_len
+            u8 cmp_imm = DECODE_U8(); // 3rd imm, at worst 6 bytes past prog_len
+            u8 cnt = (cmp_imm >> 4) + 1; // 1..16 bytestrings to match
+            u8 len = (cmp_imm & 15) + 1; // 1..16 bytestring length
+            const u32 last_packet_offs = ofs + len - 1;  // min 0+1-1=0, max 255+16-1=270
+            bool matched = false;
+            // imm is jump target offset.
+            // [ofs..last_packet_offs] are packet bytes to compare.
+            ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
+            // cnt underflow on final iteration not an issue as not used after loop.
+            // 4th (through max 19th) u8 immediates, this reaches at most 22 bytes past prog_len
+            // This assumes min ram size of 529 bytes, where APFv6.1 has min ram size of 3000
+            // the +3 is to skip over the APFv6 'datajmp' instruction, while 2* to have access to 526 bytes,
+            // Primary purpose is for mac (6) & ipv6 (16) addresses, so even offsets should be easy...
+            while (cnt--) matched |= !memcmp(ctx->program + 3 + 2 * DECODE_U8(), ctx->packet + ofs, len);
+            if (matched ^ !reg_num) ctx->pc += imm;
+            break;
+          }
           // There is a difference in APFv4 and APFv6 arithmetic behaviour!
           // APFv4:  R[0] op= Rbit ? R[1] : imm;  (and it thus doesn't make sense to have R=1 && len_field>0)
           // APFv6+: REG  op= len_field ? imm : OTHER_REG;  (note: this is *DIFFERENT* with R=1 len_field==0)
@@ -349,19 +374,22 @@ static int do_apf_run(apf_context* ctx) {
               case NEG_EXT_OPCODE: REG = -REG;      break;
               case MOV_EXT_OPCODE: REG = OTHER_REG; break;
               case SWAP_EXT_OPCODE: {
-                u32 tmp = REG;
-                REG = OTHER_REG;
-                OTHER_REG = tmp;
+                u32 tmp = ctx->R[0];
+                ctx->R[0] = ctx->R[1];
+                ctx->R[1] = tmp;
                 break;
               }
               case ALLOCATE_EXT_OPCODE:
+              do_allocate:
                 ASSERT_RETURN(ctx->tx_buf == NULL);
-                if (reg_num == 0) {
+                if (opcode == ALLOC_XMIT_OPCODE) {
+                    ctx->tx_buf_len = 266 + 8 * imm;
+                } else if (reg_num == 0) {
                     ctx->tx_buf_len = REG;
                 } else {
                     ctx->tx_buf_len = decode_be16(ctx); // 2nd imm, at worst 6 B past prog_len
                 }
-                // checksumming functions requires minimum 266 byte buffer for correctness
+                // checksumming functions require minimum 266 byte buffer for correctness
                 if (ctx->tx_buf_len < 266) ctx->tx_buf_len = 266;
                 ctx->tx_buf = apf_allocate_buffer(ctx->caller_ctx, ctx->tx_buf_len);
                 if (!ctx->tx_buf) {  // allocate failure
@@ -372,15 +400,38 @@ static int do_apf_run(apf_context* ctx) {
                 memset(ctx->tx_buf, 0, ctx->tx_buf_len);
                 ctx->mem.named.tx_buf_offset = 0;
                 break;
-              case TRANSMIT_EXT_OPCODE: {
+              case TRANSMIT_EXT_OPCODE:
+              do_transmit: {
                 // tx_buf_len cannot be large because we'd run out of RAM,
                 // so the above unsigned comparison effectively guarantees casting pkt_len
                 // to a signed value does not result in it going negative.
-                u8 ip_ofs = DECODE_U8();              // 2nd imm, at worst 5 B past prog_len
-                u8 csum_ofs = DECODE_U8();            // 3rd imm, at worst 6 B past prog_len
+                u8 ip_ofs;
+                u8 csum_ofs;
                 u8 csum_start = 0;
                 u16 partial_csum = 0;
+                bool udp = reg_num;
                 u32 pkt_len = ctx->mem.named.tx_buf_offset;
+                if (opcode != ALLOC_XMIT_OPCODE) {
+                    // parse TRANSMIT_EXT_OPCODE arguments
+                    ip_ofs = DECODE_U8();                 // 2nd imm, at worst 5 B past prog_len
+                    csum_ofs = DECODE_U8();               // 3rd imm, at worst 6 B past prog_len
+                    if (csum_ofs < 255) {
+                        csum_start = DECODE_U8();         // 4th imm, at worst 7 B past prog_len
+                        partial_csum = decode_be16(ctx);  // 5th imm, at worst 9 B past prog_len
+                    }
+                } else if (imm_len) {
+                    // parse ALLOC_XMIT_OPCODE (R=0) immediate
+                    static const u8 auto_csum_start[8] = { 26, 26, 34, 38, 22, 22, 22, 22 };
+                    static const u8 auto_csum_ofs[8] =   { 40, 44, 36, 40, 60, 64, 56, 64 };
+                    ip_ofs = 14;
+                    csum_ofs = auto_csum_ofs[imm & 7];
+                    csum_start = auto_csum_start[imm & 7];
+                    partial_csum = imm >> 3;
+                    udp = !(imm & 3);
+                } else {
+                    // ALLOC_XMIT_OPCODE (R=0) with no immediate
+                    ip_ofs = csum_ofs = 255;
+                }
                 ASSERT_RETURN(ctx->tx_buf);
                 // If pkt_len > allocate_buffer_len, it means sth. wrong
                 // happened and the tx_buf should be deallocated.
@@ -388,14 +439,9 @@ static int do_apf_run(apf_context* ctx) {
                     do_discard_buffer(ctx);
                     return EXCEPTION;
                 }
-                if (csum_ofs < 255) {
-                    csum_start = DECODE_U8();         // 4th imm, at worst 7 B past prog_len
-                    partial_csum = decode_be16(ctx);  // 5th imm, at worst 9 B past prog_len
-                }
                 {
                     int dscp = csum_and_return_dscp(ctx->tx_buf, (s32)pkt_len, ip_ofs,
-                                                    partial_csum, csum_start, csum_ofs,
-                                                    (bool)reg_num);
+                                                    partial_csum, csum_start, csum_ofs, udp);
                     int ret = do_transmit_buffer(ctx, pkt_len, dscp);
                     if (ret) { counter[-4]++; return EXCEPTION; } // transmit failure
                 }
@@ -410,6 +456,7 @@ static int do_apf_run(apf_context* ctx) {
                 u32 copy_len = ctx->R[1];
                 if (imm != EPKTDATACOPYR1_EXT_OPCODE) {
                     copy_len = DECODE_U8();  // 2nd imm, at worst 8 bytes past prog_len
+                    if (!copy_len) copy_len = 256 + DECODE_U8(); // at worst 9 bytes past prog_len
                 }
                 ASSERT_RETURN(ctx->tx_buf);
                 ASSERT_IN_OUTPUT_BOUNDS(dst_offs, copy_len);
@@ -427,26 +474,45 @@ static int do_apf_run(apf_context* ctx) {
                 ctx->mem.named.tx_buf_offset = dst_offs;
                 break;
               }
-              case JDNSQMATCH_EXT_OPCODE:       // 43
-              case JDNSAMATCH_EXT_OPCODE:       // 44
-              case JDNSQMATCHSAFE_EXT_OPCODE:   // 45
-              case JDNSAMATCHSAFE_EXT_OPCODE: { // 46
+              case JDNSQMATCH_EXT_OPCODE:        // 43 - 43 =  0 = 0b0000, u8
+              case JDNSAMATCH_EXT_OPCODE:        // 44 - 43 =  1 = 0b0001,
+              case JDNSQMATCHSAFE_EXT_OPCODE:    // 45 - 43 =  2 = 0b0010, u8
+              case JDNSAMATCHSAFE_EXT_OPCODE:    // 46 - 43 =  3 = 0b0011,
+              case JDNSQMATCH2_EXT_OPCODE:       // 51 - 43 =  8 = 0b1000, u8 u8
+              case JDNSQMATCHSAFE2_EXT_OPCODE:   // 53 - 43 = 10 = 0b1010, u8 u8
+              case JDNSQMATCH1_EXT_OPCODE:       // 55 - 43 = 12 = 0b1100, u16
+              case JDNSQMATCHSAFE1_EXT_OPCODE: { // 57 - 43 = 14 = 0b1110, u16
                 u32 jump_offs = decode_imm(ctx, imm_len); // 2nd imm, at worst 8 B past prog_len
-                int qtype = -1;
-                if (imm & 1) { // JDNSQMATCH & JDNSQMATCHSAFE are *odd* extended opcodes
-                    qtype = DECODE_U8();  // 3rd imm, at worst 9 bytes past prog_len
+                int qtype1 = -1;
+                int qtype2;
+                imm -= JDNSQMATCH_EXT_OPCODE;  // Correction for easier opcode handling
+                // Now, we have:
+                //   imm & 1 --> no following u8
+                //   imm & 2 --> 'SAFE'
+                //   imm & 4 --> join two u8s into a be16
+                //   imm & 8 --> second u8
+                // bit 0 clear means we need to parse a u8, set means 'A' opcode variety
+                if (!(imm & 1)) qtype1 = DECODE_U8();  // 3rd imm, at worst 9 bytes past prog_len
+                // bit 3 set means we need to parse another u8
+                if (imm & 8) {
+                    qtype2 = DECODE_U8();  // 4th imm, at worst 10 bytes past prog_len
+                } else {
+                    qtype2 = qtype1;
                 }
+                // bit 2 set means we need to join the two u8s into a be16
+                if (imm & 4) qtype2 = qtype1 = (qtype1 << 8) | qtype2;
                 {
                     u32 udp_payload_offset = ctx->R[0];
                     match_result_type match_rst = match_names(ctx->program + ctx->pc,
                                                               ctx->program + ctx->program_len,
                                                               ctx->packet + udp_payload_offset,
                                                               ctx->packet_len - udp_payload_offset,
-                                                              qtype);
+                                                              qtype1,
+                                                              qtype2);
                     if (match_rst == error_program) return EXCEPTION;
                     if (match_rst == error_packet) {
                         counter[-5]++; // increment error dns packet counter
-                        return (imm >= JDNSQMATCHSAFE_EXT_OPCODE) ? PASS : DROP;
+                        return (imm & 2) ? PASS : DROP;  // imm & 2 detects SAFE opcodes
                     }
                     while (ctx->pc + 1 < ctx->program_len &&
                            (ctx->program[ctx->pc] || ctx->program[ctx->pc + 1])) {
@@ -544,6 +610,9 @@ static int do_apf_run(apf_context* ctx) {
             }
             break;
           }
+          case ALLOC_XMIT_OPCODE:
+            if (reg_num) goto do_allocate; else goto do_transmit;
+            break;
           default:  // Unknown opcode
             return EXCEPTION;  // Bail out
         }
diff --git a/apf_utils.h b/next/apf_utils.h
similarity index 100%
rename from apf_utils.h
rename to next/apf_utils.h
diff --git a/next/mk b/next/mk
new file mode 100755
index 0000000..ecc0d7d
--- /dev/null
+++ b/next/mk
@@ -0,0 +1,47 @@
+#!/bin/bash
+# Requires:
+#   sudo apt install gcc-arm-linux-gnueabihf gcc-arm-linux-gnueabi gcc-aarch64-linux-gnu
+
+set -e
+set -u
+
+cd "${0%/*}"
+
+declare -ar FLAGS=(
+  '-std=c89'
+  '-pedantic'
+  '-Wall'
+  '-Werror'
+  '-Werror=implicit-fallthrough'
+  '-Werror=strict-prototypes'
+  '-Wsign-compare'
+  '-Wsign-conversion'
+  '-Wunused-parameter'
+  '-Wuninitialized'
+  '-Os'
+  '-fomit-frame-pointer'
+)
+
+#                         __aeabi_uidiv __gnu_thumb1_case_uhi __gnu_thumb1_case_uqi
+# t=armv6-m         #2820 1             2                     2
+# t=armv6s-m        #2820 1             2                     2
+# t=armv7           #2868 1             0                     0
+  t=armv7-m         #2876 0             0                     0
+# t=armv7e-m        #2880 0             0                     0
+# t=armv8-m.base    #2760 0             2                     2
+# t=armv8-m.main    #2868 0             0                     0
+# t=armv8.1-m.main  #2924 0             0                     0
+arm-linux-gnueabi-gcc -march="${t}" "${FLAGS[@]}" apf_interpreter.c -c -o apf_interpreter.armt.o
+# This dumps external calls:
+#   llvm-objdump -d -r apf_interpreter.armt.o | grep -E --color=yes -A1 'f7ff fffe' | grep -E R_ARM_THM_CALL | grep -Ev $'\t(memcmp|memcpy|memset|apf_allocate_buffer|apf_transmit_buffer|apf_internal_[_a-z]+)$' || :
+
+arm-linux-gnueabi-gcc "${FLAGS[@]}" apf_interpreter.c -c -o apf_interpreter.arm.o
+aarch64-linux-gnu-gcc "${FLAGS[@]}" apf_interpreter.c -c -o apf_interpreter.aarch64.o
+clang -m32 "${FLAGS[@]}" -Wnullable-to-nonnull-conversion -Wthread-safety apf_interpreter.c -c -o apf_interpreter.x86.o
+clang -m64 "${FLAGS[@]}" -Wnullable-to-nonnull-conversion -Wthread-safety apf_interpreter.c -c -o apf_interpreter.x86-64.o
+
+size apf_interpreter.armt.o
+size apf_interpreter.arm.o     | tail -n +2
+size apf_interpreter.aarch64.o | tail -n +2
+size apf_interpreter.x86.o     | tail -n +2
+size apf_interpreter.x86-64.o  | tail -n +2
diff --git a/v7/test_buf_allocator.c b/next/test_buf_allocator.c
similarity index 100%
rename from v7/test_buf_allocator.c
rename to next/test_buf_allocator.c
diff --git a/v7/test_buf_allocator.h b/next/test_buf_allocator.h
similarity index 100%
rename from v7/test_buf_allocator.h
rename to next/test_buf_allocator.h
diff --git a/samples/ping4_offload_program_gen.py b/samples/ping4_offload_program_gen.py
new file mode 100644
index 0000000..f06931c
--- /dev/null
+++ b/samples/ping4_offload_program_gen.py
@@ -0,0 +1,38 @@
+import argparse
+import binascii
+
+def generate_apf_program(mac_raw, ip_raw):
+    """
+    Generates an APF program that supports ping4 offload.
+
+    Args:
+      mac_raw: The MAC address in raw string format (e.g., "00:11:22:33:44:55").
+      ip_raw: The IPv4 address in raw string format (e.g., "192.168.1.100").
+
+    Returns:
+      The generated APF program as a hex string.
+    """
+    mac_list = mac_raw.split(":")
+    ip_list = ip_raw.split(".")
+
+    ip_addr = "".join([f"{int(i):02x}" for i in ip_list])
+    mac_addr = "".join(mac_list)
+
+    program = "75001002030405060708060001080006040002AA300C32AA0FBA06AA09BA07AA08BA086A02BA096A06A20206020304050607031A120CAA2F021A888E080088B486DD0806033084006F08066A0EA30206000108000604033612147A27017A0202033A1A1C820200033868A30206FFFFFFFFFFFF020C1A267E000000020A0000010337020A1A267E000000020A0000010337AB24003CCA0606CB0306CB090ACB0306C60A000001CA0606CA1C04AA0A3A12AA1AAA25FFFF0339020B120C8400C608001A14563FFF00FF821511AB0D2A10820E446A3238A20206020304050607020D0A1E52F08202E003201A1E8600000002FFFFFFFF031D86000000020A0000FF031E0A1782100612149C00091FFFAB0D2A1082020703351A14563FFF00FF82570168A24D060203040506076A1EA244040A000001AA0D823F14AA0E8A0229031F0A22823308AA0EAA24CA0606CB0306CA0C0AC640010000C60A000001CA1A04C6000000003EFFFFFFDA6B26AA22AA2AAA250E24220000032268A30206FFFFFFFFFFFF0211031C020F7C000E86DD68A30206FFFFFFFFFFFF021603190A1482020002127A093A0A268202FF032B02150A3682FC8768A5000228063333000000013333FF4411223333FF5566773333FFBBCCDD020304050607FFFFFFFFFFFF032D6A26A20C0DFF0200000000000000000001FF3A0DA30203BBCCDD032D7215A3021020010000000000000100001BAABBCCDD032D0A157A02FF032C12128A0217032C0A377A0200032C6A3EA3021020010000000000000100001BAABBCCDD032D6A16A2021000000000000000000000000000000000021312128A021F02130A4E7A020102130A16AA2F020100FF032C0A509A02017202032CAB240056CA5006CB0306C486DDC660000000C600203AFFCA3E10CA1610C688000020C6E0000000CA3E10C40201CB0306AA250E3816003A032E82028503258216886A26A2020FFF0200000000000000000000000000032A0213"
+    program = program.replace("020304050607", mac_addr)
+    program = program.replace("0A000001", ip_addr)
+    return program
+
+def main():
+    """
+    The main method.
+    """
+    parser = argparse.ArgumentParser(description="Generate a ping4 offload APF program.")
+    parser.add_argument("mac", help="The DUT's MAC address (e.g., '00:11:22:33:44:55')")
+    parser.add_argument("ip", help="The DUT's IPv4 address (e.g., '192.168.1.100')")
+    args = parser.parse_args()
+    out_program = generate_apf_program(args.mac, args.ip)
+    print("APF Program:\n", out_program)
+
+if __name__ == '__main__':
+    main()
diff --git a/testdata/large_ra_without_counters.output b/testdata/large_ra_without_counters.output
index 967b204..9677cbb 100644
--- a/testdata/large_ra_without_counters.output
+++ b/testdata/large_ra_without_counters.output
@@ -1,26 +1,26 @@
-      R0       R1       PC  Instruction
+      R0       R1       (size)    PC  Instruction
 -------------------------------------------------
-       0        0        0: ldh         r0, [12]
-    86dd        0        2: jlt         r0, 0x600, DROP
-    86dd        0        7: jne         r0, 0x806, 64
-    86dd        0       64: jne         r0, 0x800, 141
-    86dd        0      141: jeq         r0, 0x86dd, 161
-    86dd        0      161: ldb         r0, [20]
-      3a        0      163: jeq         r0, 0x3a, 176
-      3a        0      176: ldb         r0, [54]
-      86        0      178: jeq         r0, 0x85, DROP
-      86        0      183: jne         r0, 0x88, 210
-      86        0      210: ldm         r0, m[14]
-      ee        0      212: jne         r0, 0x46, 297
-      ee        0      297: ldm         r0, m[14]
-      ee        0      299: jne         r0, 0x66, 433
-      ee        0      433: ldm         r0, m[14]
-      ee        0      435: jne         r0, 0x6e, 571
-      ee        0      571: ldm         r0, m[14]
-      ee        0      573: jne         r0, 0x5e, 687
-      ee        0      687: ldm         r0, m[14]
-      ee        0      689: jne         r0, 0x5e, 808
-      ee        0      808: ldm         r0, m[14]
-      ee        0      810: jne         r0, 0x4e, PASS
-      ee        0      908: PASS
+       0        0       (   2)    0: ldh         r0, [12]
+    86dd        0       (   5)    2: jlt         r0, 0x600, DROP
+    86dd        0       (   5)    7: jne         r0, 0x806, 64
+    86dd        0       (   5)   64: jne         r0, 0x800, 141
+    86dd        0       (   5)  141: jeq         r0, 0x86dd, 161
+    86dd        0       (   2)  161: ldb         r0, [20]
+      3a        0       (   3)  163: jeq         r0, 0x3a, 176
+      3a        0       (   2)  176: ldb         r0, [54]
+      86        0       (   5)  178: jeq         r0, 0x85, DROP
+      86        0       (   3)  183: jne         r0, 0x88, 210
+      86        0       (   2)  210: ldm         r0, m[14]
+      ee        0       (   3)  212: jne         r0, 0x46, 297
+      ee        0       (   2)  297: ldm         r0, m[14]
+      ee        0       (   3)  299: jne         r0, 0x66, 433
+      ee        0       (   2)  433: ldm         r0, m[14]
+      ee        0       (   3)  435: jne         r0, 0x6e, 571
+      ee        0       (   2)  571: ldm         r0, m[14]
+      ee        0       (   3)  573: jne         r0, 0x5e, 687
+      ee        0       (   2)  687: ldm         r0, m[14]
+      ee        0       (   3)  689: jne         r0, 0x5e, 808
+      ee        0       (   2)  808: ldm         r0, m[14]
+      ee        0       (   3)  810: jne         r0, 0x4e, PASS
+      ee        0       (   0)  908: PASS
 Packet passed
diff --git a/testdata/one_ra_with_counters.output b/testdata/one_ra_with_counters.output
index 4cd2b65..f10ab43 100644
--- a/testdata/one_ra_with_counters.output
+++ b/testdata/one_ra_with_counters.output
@@ -1,57 +1,57 @@
-      R0       R1       PC  Instruction
+      R0       R1       (size)    PC  Instruction
 -------------------------------------------------
-       0        0        0: li          r1, -4
-       0 fffffffc        2: lddw        r0, [r1]
-      29 fffffffc        3: add         r0, 1
-      2a fffffffc        5: stdw        r0, [r1]
-      2a fffffffc        6: ldh         r0, [12]
-    86dd fffffffc        8: li          r1, -104
-    86dd ffffff98       10: jlt         r0, 0x600, 503
-    86dd ffffff98       15: li          r1, -108
-    86dd ffffff94       17: jeq         r0, 0x88a2, 503
-    86dd ffffff94       22: jeq         r0, 0x88a4, 503
-    86dd ffffff94       27: jeq         r0, 0x88b8, 503
-    86dd ffffff94       32: jeq         r0, 0x88cd, 503
-    86dd ffffff94       37: jeq         r0, 0x88e3, 503
-    86dd ffffff94       42: jne         r0, 0x806, 115
-    86dd ffffff94      115: jne         r0, 0x800, 215
-    86dd ffffff94      215: jeq         r0, 0x86dd, 239
-    86dd ffffff94      239: ldb         r0, [20]
-      3a ffffff94      241: jeq         r0, 0x3a, 255
-      3a ffffff94      255: ldb         r0, [54]
-      86 ffffff94      257: li          r1, -84
-      86 ffffffac      259: jeq         r0, 0x85, 503
-      86 ffffffac      262: jne         r0, 0x88, 290
-      86 ffffffac      290: ldm         r0, m[14]
-      96 ffffffac      292: jne         r0, 0x96, 495
-      96 ffffffac      295: ldm         r0, m[15]
-       0 ffffffac      297: jgt         r0, 0x258, 495
-       0 ffffffac      302: li          r0, 0
-       0 ffffffac      303: jbsne       r0, 0xf, 495, 428e66343deb28a24b792e9086dd68
-       0 ffffffac      321: li          r0, 18
-      12 ffffffac      323: jbsne       r0, 0x26, 495, 00603afffe8000000000000002005efffe000265fe80000000000000408e66fffe343deb8600
-      12 ffffffac      364: li          r0, 58
-      3a ffffffac      366: jbsne       r0, 0x2, 495, 4000
-      3a ffffffac      371: ldh         r0, [60]
-     e10 ffffffac      373: jlt         r0, 0x258, 495
-     e10 ffffffac      378: li          r0, 62
-      3e ffffffac      380: jbsne       r0, 0x14, 495, 0000000000000000010100005e00026519050000
-      3e ffffffac      403: ldw         r0, [82]
-     e10 ffffffac      405: jlt         r0, 0x258, 495
-     e10 ffffffac      410: li          r0, 86
-      56 ffffffac      412: jbsne       r0, 0x24, 495, 2001486048600000000000000000884420014860486000000000000000008888030440c0
-      56 ffffffac      451: ldw         r0, [122]
-  278d00 ffffffac      453: jlt         r0, 0x258, 495
-  278d00 ffffffac      458: ldw         r0, [126]
-   93a80 ffffffac      460: jlt         r0, 0x258, 495
-   93a80 ffffffac      465: li          r0, 130
-      82 ffffffac      468: jbsne       r0, 0x14, 495, 000000002a0079e10abc0e000000000000000000
-      82 ffffffac      491: li          r1, -56
-      82 ffffffc8      493: jmp         503
-      82 ffffffc8      503: lddw        r0, [r1]
-      1b ffffffc8      504: add         r0, 1
-      1c ffffffc8      506: stdw        r0, [r1]
-      1c ffffffc8      507: jmp         DROP
-      1c ffffffc8      510: DROP
+       0        0       (   2)    0: li          r1, -4
+       0 fffffffc       (   1)    2: lddw        r0, [r1]
+      29 fffffffc       (   2)    3: add         r0, 1
+      2a fffffffc       (   1)    5: stdw        r0, [r1]
+      2a fffffffc       (   2)    6: ldh         r0, [12]
+    86dd fffffffc       (   2)    8: li          r1, -104
+    86dd ffffff98       (   5)   10: jlt         r0, 0x600, 503
+    86dd ffffff98       (   2)   15: li          r1, -108
+    86dd ffffff94       (   5)   17: jeq         r0, 0x88a2, 503
+    86dd ffffff94       (   5)   22: jeq         r0, 0x88a4, 503
+    86dd ffffff94       (   5)   27: jeq         r0, 0x88b8, 503
+    86dd ffffff94       (   5)   32: jeq         r0, 0x88cd, 503
+    86dd ffffff94       (   5)   37: jeq         r0, 0x88e3, 503
+    86dd ffffff94       (   5)   42: jne         r0, 0x806, 115
+    86dd ffffff94       (   5)  115: jne         r0, 0x800, 215
+    86dd ffffff94       (   5)  215: jeq         r0, 0x86dd, 239
+    86dd ffffff94       (   2)  239: ldb         r0, [20]
+      3a ffffff94       (   3)  241: jeq         r0, 0x3a, 255
+      3a ffffff94       (   2)  255: ldb         r0, [54]
+      86 ffffff94       (   2)  257: li          r1, -84
+      86 ffffffac       (   3)  259: jeq         r0, 0x85, 503
+      86 ffffffac       (   3)  262: jne         r0, 0x88, 290
+      86 ffffffac       (   2)  290: ldm         r0, m[14]
+      96 ffffffac       (   3)  292: jne         r0, 0x96, 495
+      96 ffffffac       (   2)  295: ldm         r0, m[15]
+       0 ffffffac       (   5)  297: jgt         r0, 0x258, 495
+       0 ffffffac       (   1)  302: li          r0, 0
+       0 ffffffac       (  18)  303: jbsne       r0, (15), 495, 428e66343deb28a24b792e9086dd68
+       0 ffffffac       (   2)  321: li          r0, 18
+      12 ffffffac       (  41)  323: jbsne       r0, (38), 495, 00603afffe8000000000000002005efffe000265fe80000000000000408e66fffe343deb8600
+      12 ffffffac       (   2)  364: li          r0, 58
+      3a ffffffac       (   5)  366: jbsne       r0, (2), 495, 4000
+      3a ffffffac       (   2)  371: ldh         r0, [60]
+     e10 ffffffac       (   5)  373: jlt         r0, 0x258, 495
+     e10 ffffffac       (   2)  378: li          r0, 62
+      3e ffffffac       (  23)  380: jbsne       r0, (20), 495, 0000000000000000010100005e00026519050000
+      3e ffffffac       (   2)  403: ldw         r0, [82]
+     e10 ffffffac       (   5)  405: jlt         r0, 0x258, 495
+     e10 ffffffac       (   2)  410: li          r0, 86
+      56 ffffffac       (  39)  412: jbsne       r0, (36), 495, 2001486048600000000000000000884420014860486000000000000000008888030440c0
+      56 ffffffac       (   2)  451: ldw         r0, [122]
+  278d00 ffffffac       (   5)  453: jlt         r0, 0x258, 495
+  278d00 ffffffac       (   2)  458: ldw         r0, [126]
+   93a80 ffffffac       (   5)  460: jlt         r0, 0x258, 495
+   93a80 ffffffac       (   3)  465: li          r0, 130
+      82 ffffffac       (  23)  468: jbsne       r0, (20), 495, 000000002a0079e10abc0e000000000000000000
+      82 ffffffac       (   2)  491: li          r1, -56
+      82 ffffffc8       (   2)  493: jmp         503
+      82 ffffffc8       (   1)  503: lddw        r0, [r1]
+      1b ffffffc8       (   2)  504: add         r0, 1
+      1c ffffffc8       (   1)  506: stdw        r0, [r1]
+      1c ffffffc8       (   2)  507: jmp         DROP
+      1c ffffffc8       (   0)  510: DROP
 Packet dropped
 Data: 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a
diff --git a/testdata/one_ra_with_counters_age_30.output b/testdata/one_ra_with_counters_age_30.output
index b2727f6..aae3f26 100644
--- a/testdata/one_ra_with_counters_age_30.output
+++ b/testdata/one_ra_with_counters_age_30.output
@@ -1,57 +1,57 @@
-      R0       R1       PC  Instruction
+      R0       R1       (size)    PC  Instruction
 -------------------------------------------------
-       0        0        0: li          r1, -4
-       0 fffffffc        2: lddw        r0, [r1]
-      29 fffffffc        3: add         r0, 1
-      2a fffffffc        5: stdw        r0, [r1]
-      2a fffffffc        6: ldh         r0, [12]
-    86dd fffffffc        8: li          r1, -104
-    86dd ffffff98       10: jlt         r0, 0x600, 503
-    86dd ffffff98       15: li          r1, -108
-    86dd ffffff94       17: jeq         r0, 0x88a2, 503
-    86dd ffffff94       22: jeq         r0, 0x88a4, 503
-    86dd ffffff94       27: jeq         r0, 0x88b8, 503
-    86dd ffffff94       32: jeq         r0, 0x88cd, 503
-    86dd ffffff94       37: jeq         r0, 0x88e3, 503
-    86dd ffffff94       42: jne         r0, 0x806, 115
-    86dd ffffff94      115: jne         r0, 0x800, 215
-    86dd ffffff94      215: jeq         r0, 0x86dd, 239
-    86dd ffffff94      239: ldb         r0, [20]
-      3a ffffff94      241: jeq         r0, 0x3a, 255
-      3a ffffff94      255: ldb         r0, [54]
-      86 ffffff94      257: li          r1, -84
-      86 ffffffac      259: jeq         r0, 0x85, 503
-      86 ffffffac      262: jne         r0, 0x88, 290
-      86 ffffffac      290: ldm         r0, m[14]
-      96 ffffffac      292: jne         r0, 0x96, 495
-      96 ffffffac      295: ldm         r0, m[15]
-      1e ffffffac      297: jgt         r0, 0x258, 495
-      1e ffffffac      302: li          r0, 0
-       0 ffffffac      303: jbsne       r0, 0xf, 495, 428e66343deb28a24b792e9086dd68
-       0 ffffffac      321: li          r0, 18
-      12 ffffffac      323: jbsne       r0, 0x26, 495, 00603afffe8000000000000002005efffe000265fe80000000000000408e66fffe343deb8600
-      12 ffffffac      364: li          r0, 58
-      3a ffffffac      366: jbsne       r0, 0x2, 495, 4000
-      3a ffffffac      371: ldh         r0, [60]
-     e10 ffffffac      373: jlt         r0, 0x258, 495
-     e10 ffffffac      378: li          r0, 62
-      3e ffffffac      380: jbsne       r0, 0x14, 495, 0000000000000000010100005e00026519050000
-      3e ffffffac      403: ldw         r0, [82]
-     e10 ffffffac      405: jlt         r0, 0x258, 495
-     e10 ffffffac      410: li          r0, 86
-      56 ffffffac      412: jbsne       r0, 0x24, 495, 2001486048600000000000000000884420014860486000000000000000008888030440c0
-      56 ffffffac      451: ldw         r0, [122]
-  278d00 ffffffac      453: jlt         r0, 0x258, 495
-  278d00 ffffffac      458: ldw         r0, [126]
-   93a80 ffffffac      460: jlt         r0, 0x258, 495
-   93a80 ffffffac      465: li          r0, 130
-      82 ffffffac      468: jbsne       r0, 0x14, 495, 000000002a0079e10abc0e000000000000000000
-      82 ffffffac      491: li          r1, -56
-      82 ffffffc8      493: jmp         503
-      82 ffffffc8      503: lddw        r0, [r1]
-      1b ffffffc8      504: add         r0, 1
-      1c ffffffc8      506: stdw        r0, [r1]
-      1c ffffffc8      507: jmp         DROP
-      1c ffffffc8      510: DROP
+       0        0       (   2)    0: li          r1, -4
+       0 fffffffc       (   1)    2: lddw        r0, [r1]
+      29 fffffffc       (   2)    3: add         r0, 1
+      2a fffffffc       (   1)    5: stdw        r0, [r1]
+      2a fffffffc       (   2)    6: ldh         r0, [12]
+    86dd fffffffc       (   2)    8: li          r1, -104
+    86dd ffffff98       (   5)   10: jlt         r0, 0x600, 503
+    86dd ffffff98       (   2)   15: li          r1, -108
+    86dd ffffff94       (   5)   17: jeq         r0, 0x88a2, 503
+    86dd ffffff94       (   5)   22: jeq         r0, 0x88a4, 503
+    86dd ffffff94       (   5)   27: jeq         r0, 0x88b8, 503
+    86dd ffffff94       (   5)   32: jeq         r0, 0x88cd, 503
+    86dd ffffff94       (   5)   37: jeq         r0, 0x88e3, 503
+    86dd ffffff94       (   5)   42: jne         r0, 0x806, 115
+    86dd ffffff94       (   5)  115: jne         r0, 0x800, 215
+    86dd ffffff94       (   5)  215: jeq         r0, 0x86dd, 239
+    86dd ffffff94       (   2)  239: ldb         r0, [20]
+      3a ffffff94       (   3)  241: jeq         r0, 0x3a, 255
+      3a ffffff94       (   2)  255: ldb         r0, [54]
+      86 ffffff94       (   2)  257: li          r1, -84
+      86 ffffffac       (   3)  259: jeq         r0, 0x85, 503
+      86 ffffffac       (   3)  262: jne         r0, 0x88, 290
+      86 ffffffac       (   2)  290: ldm         r0, m[14]
+      96 ffffffac       (   3)  292: jne         r0, 0x96, 495
+      96 ffffffac       (   2)  295: ldm         r0, m[15]
+      1e ffffffac       (   5)  297: jgt         r0, 0x258, 495
+      1e ffffffac       (   1)  302: li          r0, 0
+       0 ffffffac       (  18)  303: jbsne       r0, (15), 495, 428e66343deb28a24b792e9086dd68
+       0 ffffffac       (   2)  321: li          r0, 18
+      12 ffffffac       (  41)  323: jbsne       r0, (38), 495, 00603afffe8000000000000002005efffe000265fe80000000000000408e66fffe343deb8600
+      12 ffffffac       (   2)  364: li          r0, 58
+      3a ffffffac       (   5)  366: jbsne       r0, (2), 495, 4000
+      3a ffffffac       (   2)  371: ldh         r0, [60]
+     e10 ffffffac       (   5)  373: jlt         r0, 0x258, 495
+     e10 ffffffac       (   2)  378: li          r0, 62
+      3e ffffffac       (  23)  380: jbsne       r0, (20), 495, 0000000000000000010100005e00026519050000
+      3e ffffffac       (   2)  403: ldw         r0, [82]
+     e10 ffffffac       (   5)  405: jlt         r0, 0x258, 495
+     e10 ffffffac       (   2)  410: li          r0, 86
+      56 ffffffac       (  39)  412: jbsne       r0, (36), 495, 2001486048600000000000000000884420014860486000000000000000008888030440c0
+      56 ffffffac       (   2)  451: ldw         r0, [122]
+  278d00 ffffffac       (   5)  453: jlt         r0, 0x258, 495
+  278d00 ffffffac       (   2)  458: ldw         r0, [126]
+   93a80 ffffffac       (   5)  460: jlt         r0, 0x258, 495
+   93a80 ffffffac       (   3)  465: li          r0, 130
+      82 ffffffac       (  23)  468: jbsne       r0, (20), 495, 000000002a0079e10abc0e000000000000000000
+      82 ffffffac       (   2)  491: li          r1, -56
+      82 ffffffc8       (   2)  493: jmp         503
+      82 ffffffc8       (   1)  503: lddw        r0, [r1]
+      1b ffffffc8       (   2)  504: add         r0, 1
+      1c ffffffc8       (   1)  506: stdw        r0, [r1]
+      1c ffffffc8       (   2)  507: jmp         DROP
+      1c ffffffc8       (   0)  510: DROP
 Packet dropped
 Data: 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a
diff --git a/testdata/one_ra_with_counters_age_600.output b/testdata/one_ra_with_counters_age_600.output
index 6538ceb..0983573 100644
--- a/testdata/one_ra_with_counters_age_600.output
+++ b/testdata/one_ra_with_counters_age_600.output
@@ -1,57 +1,57 @@
-      R0       R1       PC  Instruction
+      R0       R1       (size)    PC  Instruction
 -------------------------------------------------
-       0        0        0: li          r1, -4
-       0 fffffffc        2: lddw        r0, [r1]
-      29 fffffffc        3: add         r0, 1
-      2a fffffffc        5: stdw        r0, [r1]
-      2a fffffffc        6: ldh         r0, [12]
-    86dd fffffffc        8: li          r1, -104
-    86dd ffffff98       10: jlt         r0, 0x600, 503
-    86dd ffffff98       15: li          r1, -108
-    86dd ffffff94       17: jeq         r0, 0x88a2, 503
-    86dd ffffff94       22: jeq         r0, 0x88a4, 503
-    86dd ffffff94       27: jeq         r0, 0x88b8, 503
-    86dd ffffff94       32: jeq         r0, 0x88cd, 503
-    86dd ffffff94       37: jeq         r0, 0x88e3, 503
-    86dd ffffff94       42: jne         r0, 0x806, 115
-    86dd ffffff94      115: jne         r0, 0x800, 215
-    86dd ffffff94      215: jeq         r0, 0x86dd, 239
-    86dd ffffff94      239: ldb         r0, [20]
-      3a ffffff94      241: jeq         r0, 0x3a, 255
-      3a ffffff94      255: ldb         r0, [54]
-      86 ffffff94      257: li          r1, -84
-      86 ffffffac      259: jeq         r0, 0x85, 503
-      86 ffffffac      262: jne         r0, 0x88, 290
-      86 ffffffac      290: ldm         r0, m[14]
-      96 ffffffac      292: jne         r0, 0x96, 495
-      96 ffffffac      295: ldm         r0, m[15]
-     258 ffffffac      297: jgt         r0, 0x258, 495
-     258 ffffffac      302: li          r0, 0
-       0 ffffffac      303: jbsne       r0, 0xf, 495, 428e66343deb28a24b792e9086dd68
-       0 ffffffac      321: li          r0, 18
-      12 ffffffac      323: jbsne       r0, 0x26, 495, 00603afffe8000000000000002005efffe000265fe80000000000000408e66fffe343deb8600
-      12 ffffffac      364: li          r0, 58
-      3a ffffffac      366: jbsne       r0, 0x2, 495, 4000
-      3a ffffffac      371: ldh         r0, [60]
-     e10 ffffffac      373: jlt         r0, 0x258, 495
-     e10 ffffffac      378: li          r0, 62
-      3e ffffffac      380: jbsne       r0, 0x14, 495, 0000000000000000010100005e00026519050000
-      3e ffffffac      403: ldw         r0, [82]
-     e10 ffffffac      405: jlt         r0, 0x258, 495
-     e10 ffffffac      410: li          r0, 86
-      56 ffffffac      412: jbsne       r0, 0x24, 495, 2001486048600000000000000000884420014860486000000000000000008888030440c0
-      56 ffffffac      451: ldw         r0, [122]
-  278d00 ffffffac      453: jlt         r0, 0x258, 495
-  278d00 ffffffac      458: ldw         r0, [126]
-   93a80 ffffffac      460: jlt         r0, 0x258, 495
-   93a80 ffffffac      465: li          r0, 130
-      82 ffffffac      468: jbsne       r0, 0x14, 495, 000000002a0079e10abc0e000000000000000000
-      82 ffffffac      491: li          r1, -56
-      82 ffffffc8      493: jmp         503
-      82 ffffffc8      503: lddw        r0, [r1]
-      1b ffffffc8      504: add         r0, 1
-      1c ffffffc8      506: stdw        r0, [r1]
-      1c ffffffc8      507: jmp         DROP
-      1c ffffffc8      510: DROP
+       0        0       (   2)    0: li          r1, -4
+       0 fffffffc       (   1)    2: lddw        r0, [r1]
+      29 fffffffc       (   2)    3: add         r0, 1
+      2a fffffffc       (   1)    5: stdw        r0, [r1]
+      2a fffffffc       (   2)    6: ldh         r0, [12]
+    86dd fffffffc       (   2)    8: li          r1, -104
+    86dd ffffff98       (   5)   10: jlt         r0, 0x600, 503
+    86dd ffffff98       (   2)   15: li          r1, -108
+    86dd ffffff94       (   5)   17: jeq         r0, 0x88a2, 503
+    86dd ffffff94       (   5)   22: jeq         r0, 0x88a4, 503
+    86dd ffffff94       (   5)   27: jeq         r0, 0x88b8, 503
+    86dd ffffff94       (   5)   32: jeq         r0, 0x88cd, 503
+    86dd ffffff94       (   5)   37: jeq         r0, 0x88e3, 503
+    86dd ffffff94       (   5)   42: jne         r0, 0x806, 115
+    86dd ffffff94       (   5)  115: jne         r0, 0x800, 215
+    86dd ffffff94       (   5)  215: jeq         r0, 0x86dd, 239
+    86dd ffffff94       (   2)  239: ldb         r0, [20]
+      3a ffffff94       (   3)  241: jeq         r0, 0x3a, 255
+      3a ffffff94       (   2)  255: ldb         r0, [54]
+      86 ffffff94       (   2)  257: li          r1, -84
+      86 ffffffac       (   3)  259: jeq         r0, 0x85, 503
+      86 ffffffac       (   3)  262: jne         r0, 0x88, 290
+      86 ffffffac       (   2)  290: ldm         r0, m[14]
+      96 ffffffac       (   3)  292: jne         r0, 0x96, 495
+      96 ffffffac       (   2)  295: ldm         r0, m[15]
+     258 ffffffac       (   5)  297: jgt         r0, 0x258, 495
+     258 ffffffac       (   1)  302: li          r0, 0
+       0 ffffffac       (  18)  303: jbsne       r0, (15), 495, 428e66343deb28a24b792e9086dd68
+       0 ffffffac       (   2)  321: li          r0, 18
+      12 ffffffac       (  41)  323: jbsne       r0, (38), 495, 00603afffe8000000000000002005efffe000265fe80000000000000408e66fffe343deb8600
+      12 ffffffac       (   2)  364: li          r0, 58
+      3a ffffffac       (   5)  366: jbsne       r0, (2), 495, 4000
+      3a ffffffac       (   2)  371: ldh         r0, [60]
+     e10 ffffffac       (   5)  373: jlt         r0, 0x258, 495
+     e10 ffffffac       (   2)  378: li          r0, 62
+      3e ffffffac       (  23)  380: jbsne       r0, (20), 495, 0000000000000000010100005e00026519050000
+      3e ffffffac       (   2)  403: ldw         r0, [82]
+     e10 ffffffac       (   5)  405: jlt         r0, 0x258, 495
+     e10 ffffffac       (   2)  410: li          r0, 86
+      56 ffffffac       (  39)  412: jbsne       r0, (36), 495, 2001486048600000000000000000884420014860486000000000000000008888030440c0
+      56 ffffffac       (   2)  451: ldw         r0, [122]
+  278d00 ffffffac       (   5)  453: jlt         r0, 0x258, 495
+  278d00 ffffffac       (   2)  458: ldw         r0, [126]
+   93a80 ffffffac       (   5)  460: jlt         r0, 0x258, 495
+   93a80 ffffffac       (   3)  465: li          r0, 130
+      82 ffffffac       (  23)  468: jbsne       r0, (20), 495, 000000002a0079e10abc0e000000000000000000
+      82 ffffffac       (   2)  491: li          r1, -56
+      82 ffffffc8       (   2)  493: jmp         503
+      82 ffffffc8       (   1)  503: lddw        r0, [r1]
+      1b ffffffc8       (   2)  504: add         r0, 1
+      1c ffffffc8       (   1)  506: stdw        r0, [r1]
+      1c ffffffc8       (   2)  507: jmp         DROP
+      1c ffffffc8       (   0)  510: DROP
 Packet dropped
 Data: 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a
diff --git a/testdata/one_ra_with_counters_age_601.output b/testdata/one_ra_with_counters_age_601.output
index 1789ae0..9192d56 100644
--- a/testdata/one_ra_with_counters_age_601.output
+++ b/testdata/one_ra_with_counters_age_601.output
@@ -1,36 +1,36 @@
-      R0       R1       PC  Instruction
+      R0       R1       (size)    PC  Instruction
 -------------------------------------------------
-       0        0        0: li          r1, -4
-       0 fffffffc        2: lddw        r0, [r1]
-      29 fffffffc        3: add         r0, 1
-      2a fffffffc        5: stdw        r0, [r1]
-      2a fffffffc        6: ldh         r0, [12]
-    86dd fffffffc        8: li          r1, -104
-    86dd ffffff98       10: jlt         r0, 0x600, 503
-    86dd ffffff98       15: li          r1, -108
-    86dd ffffff94       17: jeq         r0, 0x88a2, 503
-    86dd ffffff94       22: jeq         r0, 0x88a4, 503
-    86dd ffffff94       27: jeq         r0, 0x88b8, 503
-    86dd ffffff94       32: jeq         r0, 0x88cd, 503
-    86dd ffffff94       37: jeq         r0, 0x88e3, 503
-    86dd ffffff94       42: jne         r0, 0x806, 115
-    86dd ffffff94      115: jne         r0, 0x800, 215
-    86dd ffffff94      215: jeq         r0, 0x86dd, 239
-    86dd ffffff94      239: ldb         r0, [20]
-      3a ffffff94      241: jeq         r0, 0x3a, 255
-      3a ffffff94      255: ldb         r0, [54]
-      86 ffffff94      257: li          r1, -84
-      86 ffffffac      259: jeq         r0, 0x85, 503
-      86 ffffffac      262: jne         r0, 0x88, 290
-      86 ffffffac      290: ldm         r0, m[14]
-      96 ffffffac      292: jne         r0, 0x96, 495
-      96 ffffffac      295: ldm         r0, m[15]
-     259 ffffffac      297: jgt         r0, 0x258, 495
-     259 ffffffac      495: li          r1, -28
-     259 ffffffe4      497: lddw        r0, [r1]
-       0 ffffffe4      498: add         r0, 1
-       1 ffffffe4      500: stdw        r0, [r1]
-       1 ffffffe4      501: jmp         PASS
-       1 ffffffe4      509: PASS
+       0        0       (   2)    0: li          r1, -4
+       0 fffffffc       (   1)    2: lddw        r0, [r1]
+      29 fffffffc       (   2)    3: add         r0, 1
+      2a fffffffc       (   1)    5: stdw        r0, [r1]
+      2a fffffffc       (   2)    6: ldh         r0, [12]
+    86dd fffffffc       (   2)    8: li          r1, -104
+    86dd ffffff98       (   5)   10: jlt         r0, 0x600, 503
+    86dd ffffff98       (   2)   15: li          r1, -108
+    86dd ffffff94       (   5)   17: jeq         r0, 0x88a2, 503
+    86dd ffffff94       (   5)   22: jeq         r0, 0x88a4, 503
+    86dd ffffff94       (   5)   27: jeq         r0, 0x88b8, 503
+    86dd ffffff94       (   5)   32: jeq         r0, 0x88cd, 503
+    86dd ffffff94       (   5)   37: jeq         r0, 0x88e3, 503
+    86dd ffffff94       (   5)   42: jne         r0, 0x806, 115
+    86dd ffffff94       (   5)  115: jne         r0, 0x800, 215
+    86dd ffffff94       (   5)  215: jeq         r0, 0x86dd, 239
+    86dd ffffff94       (   2)  239: ldb         r0, [20]
+      3a ffffff94       (   3)  241: jeq         r0, 0x3a, 255
+      3a ffffff94       (   2)  255: ldb         r0, [54]
+      86 ffffff94       (   2)  257: li          r1, -84
+      86 ffffffac       (   3)  259: jeq         r0, 0x85, 503
+      86 ffffffac       (   3)  262: jne         r0, 0x88, 290
+      86 ffffffac       (   2)  290: ldm         r0, m[14]
+      96 ffffffac       (   3)  292: jne         r0, 0x96, 495
+      96 ffffffac       (   2)  295: ldm         r0, m[15]
+     259 ffffffac       (   5)  297: jgt         r0, 0x258, 495
+     259 ffffffac       (   2)  495: li          r1, -28
+     259 ffffffe4       (   1)  497: lddw        r0, [r1]
+       0 ffffffe4       (   2)  498: add         r0, 1
+       1 ffffffe4       (   1)  500: stdw        r0, [r1]
+       1 ffffffe4       (   2)  501: jmp         PASS
+       1 ffffffe4       (   0)  509: PASS
 Packet passed
 Data: 0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b0000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000002a
diff --git a/v6/Android.bp b/v6/Android.bp
new file mode 100644
index 0000000..405ddef
--- /dev/null
+++ b/v6/Android.bp
@@ -0,0 +1,49 @@
+//
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
+    default_applicable_licenses: ["hardware_google_apf_license"],
+}
+
+cc_defaults {
+    name: "apfv6_defaults",
+
+    cflags: [
+        "-Wall",
+        "-Werror",
+        "-Werror=implicit-fallthrough",
+        "-Werror=missing-prototypes",
+        "-Werror=strict-prototypes",
+        "-Wnullable-to-nonnull-conversion",
+        "-Wsign-compare",
+        "-Wsign-conversion",
+        "-Wthread-safety",
+        "-Wunused-parameter",
+        "-Wuninitialized",
+    ],
+}
+
+cc_library_static {
+    name: "libapf_v6",
+    defaults: ["apfv6_defaults"],
+    static_libs: [
+        "libapfbuf",
+    ],
+    srcs: [
+        "apf_interpreter.c",
+    ],
+    sdk_version: "24",
+}
diff --git a/v7/apf_checksum.h b/v7/apf_checksum.h
deleted file mode 120000
index 71ae895..0000000
--- a/v7/apf_checksum.h
+++ /dev/null
@@ -1 +0,0 @@
-../apf_checksum.h
\ No newline at end of file
diff --git a/v7/apf_defs.h b/v7/apf_defs.h
deleted file mode 120000
index 7e1dfa0..0000000
--- a/v7/apf_defs.h
+++ /dev/null
@@ -1 +0,0 @@
-../apf_defs.h
\ No newline at end of file
diff --git a/v7/apf_dns.h b/v7/apf_dns.h
deleted file mode 120000
index 504778f..0000000
--- a/v7/apf_dns.h
+++ /dev/null
@@ -1 +0,0 @@
-../apf_dns.h
\ No newline at end of file
diff --git a/v7/apf_utils.h b/v7/apf_utils.h
deleted file mode 120000
index 1ac8063..0000000
--- a/v7/apf_utils.h
+++ /dev/null
@@ -1 +0,0 @@
-../apf_utils.h
\ No newline at end of file
```

