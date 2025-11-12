```diff
diff --git a/Android.bp b/Android.bp
index 5afc016..1415c7e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -22,43 +22,153 @@ cc_defaults {
     name: "apf_defaults",
 
     cflags: [
-        "-DAPF_FRAME_HEADER_SIZE=14",
         "-Wall",
         "-Werror",
         "-Werror=implicit-fallthrough",
+        "-Werror=missing-prototypes",
+        "-Werror=strict-prototypes",
         "-Wnullable-to-nonnull-conversion",
         "-Wsign-compare",
+        "-Wsign-conversion",
         "-Wthread-safety",
         "-Wunused-parameter",
         "-Wuninitialized",
     ],
 }
 
-cc_library_static {
-    name: "libapf",
+cc_object {
+    name: "apfv2",
     defaults: ["apf_defaults"],
-    srcs: ["v4/apf_interpreter.c"],
+    device_supported: true,
+    host_supported: true,
+    srcs: [
+        "apf_trace_hook_weak.c",
+        "v2/apf_interpreter.c",
+    ],
+    cflags: [
+        "-Wno-missing-prototypes",
+        "-Wno-sign-conversion",
+        "-DAPF_FRAME_HEADER_SIZE=14",
+        "-DAPF_TRACE_HOOK=apf_trace_hook",
+        "-Daccept_packet=apfv2__accept_packet",
+    ],
     sdk_version: "24",
 }
 
-cc_library_static {
-    name: "libapfdisassembler",
+cc_object {
+    name: "apfv4",
     defaults: ["apf_defaults"],
+    device_supported: true,
+    host_supported: true,
     srcs: [
-        "disassembler.c",
+        "apf_trace_hook_weak.c",
+        "v4/apf_interpreter.c",
+    ],
+    cflags: [
+        "-Wno-missing-prototypes",
+        "-Wno-sign-conversion",
+        "-DAPF_FRAME_HEADER_SIZE=14",
+        "-DAPF_TRACE_HOOK=apf_trace_hook",
+        "-Daccept_packet=apfv4__accept_packet",
+    ],
+    sdk_version: "24",
+}
+
+cc_object {
+    name: "apfv6",
+    defaults: ["apf_defaults"],
+    device_supported: true,
+    host_supported: true,
+    srcs: [
+        "apf_trace_hook_weak.c",
+        "v6/apf_interpreter.c",
+    ],
+    cflags: [
+        "-fPIC",
+        "-Dapf_run=apfv6__apf_run",
+        "-Dapf_internal_do_transmit_buffer=apfv6__apf_internal_do_transmit_buffer",
+        "-Dapf_version=apfv6__apf_version",
+        "-Dapf_internal_csum_and_return_dscp=apfv6__apf_internal_csum_and_return_dscp",
+        "-Dapf_internal_calc_csum=apfv6__apf_internal_calc_csum",
+        "-Dapf_internal_match_names=apfv6__apf_internal_match_names",
+        "-Dapf_internal_match_single_name=apfv6__apf_internal_match_single_name",
+        "-DAPF_TRACE_HOOK=apf_trace_hook",
+    ],
+    sdk_version: "24",
+}
+
+cc_object {
+    name: "apfv61",
+    defaults: ["apf_defaults"],
+    device_supported: true,
+    host_supported: true,
+    srcs: [
+        "apf_trace_hook_weak.c",
+        "v6.1/apf_interpreter.c",
+    ],
+    cflags: [
+        "-fPIC",
+        "-Dapf_run=apfv61__apf_run",
+        "-Dapf_internal_do_transmit_buffer=apfv61__apf_internal_do_transmit_buffer",
+        "-Dapf_version=apfv61__apf_version",
+        "-Dapf_internal_csum_and_return_dscp=apfv61__apf_internal_csum_and_return_dscp",
+        "-Dapf_internal_calc_csum=apfv61__apf_internal_calc_csum",
+        "-Dapf_internal_match_names=apfv61__apf_internal_match_names",
+        "-Dapf_internal_match_single_name=apfv61__apf_internal_match_single_name",
+        "-DAPF_TRACE_HOOK=apf_trace_hook",
+    ],
+    sdk_version: "24",
+}
+
+cc_object {
+    name: "apfnext",
+    defaults: ["apf_defaults"],
+    device_supported: true,
+    host_supported: true,
+    srcs: [
+        "apf_trace_hook_weak.c",
+        "next/apf_interpreter.c",
+    ],
+    cflags: [
+        "-fPIC",
+        "-Dapf_run=apfnext__apf_run",
+        "-Dapf_internal_do_transmit_buffer=apfnext__apf_internal_do_transmit_buffer",
+        "-Dapf_version=apfnext__apf_version",
+        "-Dapf_internal_csum_and_return_dscp=apfnext__apf_internal_csum_and_return_dscp",
+        "-Dapf_internal_calc_csum=apfnext__apf_internal_calc_csum",
+        "-Dapf_internal_match_names=apfnext__apf_internal_match_names",
+        "-Dapf_internal_match_single_name=apfnext__apf_internal_match_single_name",
+        "-DAPF_TRACE_HOOK=apf_trace_hook",
     ],
     sdk_version: "24",
 }
 
 cc_library_static {
-    name: "libapfbuf",
+    name: "libapf",
     defaults: ["apf_defaults"],
+    device_supported: true,
+    host_supported: true,
     srcs: [
+        ":apfv2",
+        ":apfv4",
+        ":apfv6",
+        ":apfv61",
+        ":apfnext",
+        "apflib.c",
         "next/test_buf_allocator.c",
     ],
     sdk_version: "24",
 }
 
+cc_library_static {
+    name: "libapfdisassembler",
+    defaults: ["apf_defaults"],
+    srcs: [
+        "disassembler.c",
+    ],
+    sdk_version: "24",
+}
+
 cc_binary_host {
     name: "apf_disassembler",
     defaults: ["apf_defaults"],
@@ -72,16 +182,18 @@ cc_binary_host {
     name: "apf_run",
     defaults: ["apf_defaults"],
     static_libs: [
+        "libapf",
         "libpcap",
     ],
     srcs: [
         "apf_run.c",
         "disassembler.c",
-        "next/apf_interpreter.c",
         "next/test_buf_allocator.c",
-        "v4/apf_interpreter.c",
     ],
     cflags: [
+        "-Wno-missing-prototypes",
+        "-Wno-sign-conversion",
+        "-DAPF_FRAME_HEADER_SIZE=14",
         "-DAPF_TRACE_HOOK=apf_trace_hook",
     ],
     target: {
diff --git a/apf_run.c b/apf_run.c
index 98b51d4..73851d2 100644
--- a/apf_run.c
+++ b/apf_run.c
@@ -27,9 +27,8 @@
 #include <stdlib.h>
 #include <string.h>
 
+#include "apflib.h"
 #include "disassembler.h"
-#include "v4/apf_interpreter.h"
-#include "next/apf_interpreter.h"
 #include "next/test_buf_allocator.h"
 
 #define __unused __attribute__((unused))
@@ -179,13 +178,15 @@ void packet_handler(int use_apf_v6_interpreter, uint8_t* program,
 
     maybe_print_tracing_header();
 
+    double filter_age_16384ths = filter_age * 16384.0;
+
     int ret;
     if (use_apf_v6_interpreter) {
-        ret = apf_run(NULL, (uint32_t*)program, program_len, ram_len, packet, packet_len,
-                            filter_age);
+        ret = apf_run_generic(6000, (uint32_t*)program, program_len, ram_len, packet, packet_len,
+                              (uint32_t)filter_age_16384ths);
     } else {
-        ret = accept_packet(program, program_len, ram_len, packet, packet_len,
-                        filter_age);
+        ret = apf_run_generic(4, (uint32_t*)program, program_len, ram_len, packet, packet_len,
+                              (uint32_t)filter_age_16384ths);
     }
     printf("Packet %sed\n", ret ? "pass" : "dropp");
 
@@ -218,6 +219,8 @@ void file_handler(int use_apf_v6_interpreter, uint8_t* program,
     int pass = 0;
     int drop = 0;
 
+    double filter_age_16384ths = filter_age * 16384.0;
+
     pcap = pcap_open_offline(filename, errbuf);
     if (pcap == NULL) {
         printf("Open pcap file failed.\n");
@@ -238,11 +241,11 @@ void file_handler(int use_apf_v6_interpreter, uint8_t* program,
 
         int result;
         if (use_apf_v6_interpreter) {
-            result = apf_run(NULL, (uint32_t*)program, program_len, ram_len, apf_packet,
-                             apf_header.len, filter_age);
+            result = apf_run_generic(6000, (uint32_t*)program, program_len, ram_len, apf_packet,
+                                     apf_header.len, (uint32_t)filter_age_16384ths);
         } else {
-            result = accept_packet(program, program_len, ram_len, apf_packet,
-                                   apf_header.len, filter_age);
+            result = apf_run_generic(4, (uint32_t*)program, program_len, ram_len, apf_packet,
+                                     apf_header.len, (uint32_t)filter_age_16384ths);
         }
 
         if (!result){
diff --git a/apf_trace_hook_weak.c b/apf_trace_hook_weak.c
new file mode 100644
index 0000000..080879e
--- /dev/null
+++ b/apf_trace_hook_weak.c
@@ -0,0 +1,31 @@
+/*
+ * Copyright 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <inttypes.h>
+
+void __attribute__((weak)) apf_trace_hook(uint32_t pc, const uint32_t* regs,
+                                          const uint8_t* program, uint32_t program_len,
+                                          const uint8_t* packet, uint32_t packet_len,
+                                          const uint32_t* memory, uint32_t memory_len);
+
+void apf_trace_hook(uint32_t pc __attribute__((unused)),
+                    const uint32_t* regs __attribute__((unused)),
+                    const uint8_t* program __attribute__((unused)),
+                    uint32_t program_len __attribute__((unused)),
+                    const uint8_t* packet __attribute__((unused)),
+                    uint32_t packet_len __attribute__((unused)),
+                    const uint32_t* memory __attribute__((unused)),
+                    uint32_t memory_len __attribute__((unused))) {}
diff --git a/apflib.c b/apflib.c
new file mode 100644
index 0000000..48ee220
--- /dev/null
+++ b/apflib.c
@@ -0,0 +1,75 @@
+/*
+ * Copyright 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#define accept_packet apfv2__accept_packet
+#include <v2/apf_interpreter.h>
+#undef accept_packet
+#undef APF_VERSION  // 2
+
+#define accept_packet apfv4__accept_packet
+#include <v4/apf_interpreter.h>
+#undef accept_packet
+#undef APF_VERSION  // 4
+
+#define apf_run apfv6__apf_run
+#define apf_version apfv6__apf_version
+#include <v6/apf_interpreter.h>
+#undef apf_run
+#undef apf_version  // returns 6000
+
+#define apf_run apfv61__apf_run
+#define apf_version apfv61__apf_version
+#include <v6.1/apf_interpreter.h>
+#undef apf_run
+#undef apf_version  // returns 6100
+
+#define apf_run apfnext__apf_run
+#define apf_version apfnext__apf_version
+#include <next/apf_interpreter.h>
+#undef apf_run
+#undef apf_version
+
+#include "apflib.h"
+
+int apf_run_generic(const uint32_t apf_version,
+                    uint32_t* const program,
+                    const uint32_t program_len,
+                    const uint32_t ram_len,
+                    const uint8_t* packet,
+                    const uint32_t packet_len,
+                    const uint32_t filter_age_16384ths) {
+    uint8_t * const program8 = (uint8_t*)program;
+    const uint32_t filter_age = filter_age_16384ths >> 14;
+    void * const ctx = nullptr;
+
+    if (apf_version == 2)
+        return apfv2__accept_packet(program8, program_len, packet, packet_len, filter_age);
+
+    // Note: APFv3 is just APFv4 with somewhat broken memory/counter read API.
+    if (apf_version == 3 || apf_version == 4)
+        return apfv4__accept_packet(program8, program_len, ram_len, packet, packet_len, filter_age);
+
+    if (apf_version == apfv6__apf_version())  // 6000
+        return apfv6__apf_run(ctx, program, program_len, ram_len, packet, packet_len, filter_age_16384ths);
+
+    if (apf_version == apfv61__apf_version())  // 6100
+        return apfv61__apf_run(ctx, program, program_len, ram_len, packet, packet_len, filter_age_16384ths);
+
+    if (apf_version >= 20250228) // hardcoded (for now) to allow evolving apfnext__apf_version()
+        return apfnext__apf_run(ctx, program, program_len, ram_len, packet, packet_len, filter_age_16384ths);
+
+    return -1;
+}
diff --git a/apflib.h b/apflib.h
new file mode 100644
index 0000000..95f0cda
--- /dev/null
+++ b/apflib.h
@@ -0,0 +1,32 @@
+/*
+ * Copyright 2025, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+int apf_run_generic(const uint32_t apf_version,
+                    uint32_t * const program,
+                    const uint32_t program_len,
+                    const uint32_t ram_len,
+                    const uint8_t *packet,
+                    const uint32_t packet_len,
+                    const uint32_t filter_age_16384ths);
+
+#ifdef __cplusplus
+}
+#endif
diff --git a/disassembler.c b/disassembler.c
index ad5f5d6..b501eb5 100644
--- a/disassembler.c
+++ b/disassembler.c
@@ -31,7 +31,7 @@
 char prefix_buf[16];
 char print_buf[8196];
 char* buf_ptr;
-int buf_remain;
+size_t buf_remain;
 bool v6_mode = false;
 
 __attribute__ ((format (printf, 1, 2) ))
@@ -41,9 +41,9 @@ static void bprintf(const char* format, ...) {
     int ret = vsnprintf(buf_ptr, buf_remain, format, args);
     va_end(args);
     if (ret < 0) return;
-    if (ret >= buf_remain) ret = buf_remain;
-    buf_ptr += ret;
-    buf_remain -= ret;
+    size_t used = ((size_t)ret >= buf_remain) ? buf_remain : (size_t)ret;
+    buf_ptr += used;
+    buf_remain -= used;
 }
 
 static void print_opcode(const char* opcode) {
@@ -98,8 +98,8 @@ static void print_jump_target(uint32_t target, uint32_t program_len) {
     }
 }
 
-static void print_qtype(int qtype) {
-    switch(qtype) {
+static void print_qtype(uint32_t qtype) {
+    switch (qtype) {
         case 1:
             bprintf("A, ");
             break;
@@ -177,7 +177,8 @@ disas_ret apf_disassemble(const uint8_t* program, uint32_t program_len, uint32_t
         const uint32_t imm_len = 1 << (len_field - 1);
         imm = DECODE_IMM(imm_len);
         // Sign extend imm into signed_imm.
-        signed_imm = imm << ((4 - imm_len) * 8);
+        signed_imm = (int32_t)imm;
+        signed_imm <<= (4 - imm_len) * 8;
         signed_imm >>= (4 - imm_len) * 8;
     }
     switch (opcode) {
@@ -400,8 +401,8 @@ disas_ret apf_disassemble(const uint8_t* program, uint32_t program_len, uint32_t
                 case JDNSQMATCHSAFE1_EXT_OPCODE:
                 case JDNSQMATCHSAFE2_EXT_OPCODE: {
                     uint32_t offs = DECODE_IMM(1 << (len_field - 1));
-                    int qtype1 = -1;
-                    int qtype2 = -1;
+                    uint32_t qtype1;
+                    uint32_t qtype2;
                     switch (imm) {
                         case JDNSQMATCH_EXT_OPCODE:
                             print_opcode(reg_num ? "jdnsqeq" : "jdnsqne");
diff --git a/next/Android.bp b/next/Android.bp
index 7ab382f..6fb4003 100644
--- a/next/Android.bp
+++ b/next/Android.bp
@@ -14,40 +14,6 @@
 // limitations under the License.
 //
 
-package {
-    default_applicable_licenses: ["hardware_google_apf_license"],
-}
-
-cc_defaults {
-    name: "apfnext_defaults",
-
-    cflags: [
-        "-Wall",
-        "-Werror",
-        "-Werror=implicit-fallthrough",
-        "-Werror=missing-prototypes",
-        "-Werror=strict-prototypes",
-        "-Wnullable-to-nonnull-conversion",
-        "-Wsign-compare",
-        "-Wsign-conversion",
-        "-Wthread-safety",
-        "-Wunused-parameter",
-        "-Wuninitialized",
-    ],
-}
-
-cc_library_static {
-    name: "libapf_next",
-    defaults: ["apfnext_defaults"],
-    static_libs: [
-        "libapfbuf",
-    ],
-    srcs: [
-        "apf_interpreter.c",
-    ],
-    sdk_version: "24",
-}
-
 sh_test_host {
     name: "apf_assemble_test",
     src: "apf_interpreter_assemble.sh",
diff --git a/next/apf.h b/next/apf.h
index 7da3005..3c547f6 100644
--- a/next/apf.h
+++ b/next/apf.h
@@ -159,7 +159,7 @@ typedef union {
 /* Unconditionally pass (if R=0) or drop (if R=1) packet and optionally increment counter.
  * An optional non-zero unsigned immediate value can be provided to encode the counter number.
  * The counter is located (-4 * counter number) bytes from the end of the data region.
- * It is a U32 big-endian value and is always incremented by 1.
+ * It is a U32 firmware native endian value and is always incremented by 1.
  * This is more or less equivalent to: lddw R0, -4*N; add R0, 1; stdw R0, -4*N; {pass,drop}
  * e.g. "pass", "pass 1", "drop", "drop 1"
  */
diff --git a/next/apf_interpreter.c b/next/apf_interpreter.c
index 39c1760..380350d 100644
--- a/next/apf_interpreter.c
+++ b/next/apf_interpreter.c
@@ -215,7 +215,7 @@ typedef union {
 /* Unconditionally pass (if R=0) or drop (if R=1) packet and optionally increment counter.
  * An optional non-zero unsigned immediate value can be provided to encode the counter number.
  * The counter is located (-4 * counter number) bytes from the end of the data region.
- * It is a U32 big-endian value and is always incremented by 1.
+ * It is a U32 firmware native endian value and is always incremented by 1.
  * This is more or less equivalent to: lddw R0, -4*N; add R0, 1; stdw R0, -4*N; {pass,drop}
  * e.g. "pass", "pass 1", "drop", "drop 1"
  */
@@ -1234,6 +1234,7 @@ static int apf_runner(void* ctx, u32* const program, const u32 program_len,
     /* APFv6 interpreter requires program & ram_len to be 4 byte aligned. */
     if (3 & (uintptr_t)program) return EXCEPTION;
     if (3 & ram_len) return EXCEPTION;
+    if (ram_len < 1024) return EXCEPTION; /* due to JBSPTR */
 
     /* We rely on ram_len + 65536 not overflowing, so require ram_len < 2GiB */
     /* Similarly LDDW/STDW have special meaning for negative ram offsets. */
diff --git a/next/apf_interpreter_source.c b/next/apf_interpreter_source.c
index 997966d..0a8b79f 100644
--- a/next/apf_interpreter_source.c
+++ b/next/apf_interpreter_source.c
@@ -629,6 +629,7 @@ static int apf_runner(void* ctx, u32* const program, const u32 program_len,
     // APFv6 interpreter requires program & ram_len to be 4 byte aligned.
     if (3 & (uintptr_t)program) return EXCEPTION;
     if (3 & ram_len) return EXCEPTION;
+    if (ram_len < 1024) return EXCEPTION; // due to JBSPTR
 
     // We rely on ram_len + 65536 not overflowing, so require ram_len < 2GiB
     // Similarly LDDW/STDW have special meaning for negative ram offsets.
diff --git a/v2/apf.h b/v2/apf.h
new file mode 100644
index 0000000..2ae48ec
--- /dev/null
+++ b/v2/apf.h
@@ -0,0 +1,161 @@
+/*
+ * Copyright 2016, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+// A brief overview of APF:
+//
+// APF machine is composed of:
+//  1. A read-only program consisting of bytecodes as described below.
+//  2. Two 32-bit registers, called R0 and R1.
+//  3. Sixteen 32-bit memory slots.
+//  4. A read-only packet.
+// The program is executed by the interpreter below and parses the packet
+// to determine if the application processor (AP) should be woken up to
+// handle the packet or if can be dropped.
+//
+// APF bytecode description:
+//
+// The APF interpreter uses big-endian byte order for loads from the packet
+// and for storing immediates in instructions.
+//
+// Each instruction starts with a byte composed of:
+//  Top 5 bits form "opcode" field, see *_OPCODE defines below.
+//  Next 2 bits form "size field", which indicate the length of an immediate
+//  value which follows the first byte.  Values in this field:
+//                 0 => immediate value is 0 and no bytes follow.
+//                 1 => immediate value is 1 byte big.
+//                 2 => immediate value is 2 bytes big.
+//                 3 => immediate value is 4 bytes big.
+//  Bottom bit forms "register" field, which indicates which register this
+//  instruction operates on.
+//
+//  There are three main categories of instructions:
+//  Load instructions
+//    These instructions load byte(s) of the packet into a register.
+//    They load either 1, 2 or 4 bytes, as determined by the "opcode" field.
+//    They load into the register specified by the "register" field.
+//    The immediate value that follows the first byte of the instruction is
+//    the byte offset from the begining of the packet to load from.
+//    There are "indexing" loads which add the value in R1 to the byte offset
+//    to load from. The "opcode" field determines which loads are "indexing".
+//  Arithmetic instructions
+//    These instructions perform simple operations, like addition, on register
+//    values. The result of these instructions is always written into R0. One
+//    argument of the arithmetic operation is R0's value. The other argument
+//    of the arithmetic operation is determined by the "register" field:
+//            If the "register" field is 0 then the immediate value following
+//            the first byte of the instruction is used as the other argument
+//            to the arithmetic operation.
+//            If the "register" field is 1 then R1's value is used as the other
+//            argument to the arithmetic operation.
+//  Conditional jump instructions
+//    These instructions compare register R0's value with another value, and if
+//    the comparison succeeds, jump (i.e. adjust the program counter). The
+//    immediate value that follows the first byte of the instruction
+//    represents the jump target offset, i.e. the value added to the program
+//    counter if the comparison succeeds. The other value compared is
+//    determined by the "register" field:
+//            If the "register" field is 0 then another immediate value
+//            follows the jump target offset. This immediate value is of the
+//            same size as the jump target offset, and represents the value
+//            to compare against.
+//            If the "register" field is 1 then register R1's value is
+//            compared against.
+//    The type of comparison (e.g. equal to, greater than etc) is determined
+//    by the "opcode" field. The comparison interprets both values being
+//    compared as unsigned values.
+//
+//  Miscellaneous details:
+//
+//  Pre-filled memory slot values
+//    When the APF program begins execution, three of the sixteen memory slots
+//    are pre-filled by the interpreter with values that may be useful for
+//    programs:
+//      Slot #13 is filled with the IPv4 header length. This value is calculated
+//               by loading the first byte of the IPv4 header and taking the
+//               bottom 4 bits and multiplying their value by 4. This value is
+//               set to zero if the first 4 bits after the link layer header are
+//               not 4, indicating not IPv4.
+//      Slot #14 is filled with size of the packet in bytes, including the
+//               link-layer header if any.
+//      Slot #15 is filled with the filter age in seconds. This is the number of
+//               seconds since the AP send the program to the chipset. This may
+//               be used by filters that should have a particular lifetime. For
+//               example, it can be used to rate-limit particular packets to one
+//               every N seconds.
+//  Special jump targets:
+//    When an APF program executes a jump to the byte immediately after the last
+//      byte of the progam (i.e., one byte past the end of the program), this
+//      signals the program has completed and determined the packet should be
+//      passed to the AP.
+//    When an APF program executes a jump two bytes past the end of the program,
+//      this signals the program has completed and determined the packet should
+//      be dropped.
+//  Jump if byte sequence doesn't match:
+//    This is a special instruction to facilitate matching long sequences of
+//    bytes in the packet. Initially it is encoded like a conditional jump
+//    instruction with two exceptions:
+//      The first byte of the instruction is always followed by two immediate
+//        fields: The first immediate field is the jump target offset like other
+//        conditional jump instructions. The second immediate field specifies the
+//        number of bytes to compare.
+//      These two immediate fields are followed by a sequence of bytes. These
+//        bytes are compared with the bytes in the packet starting from the
+//        position specified by the value of the register specified by the
+//        "register" field of the instruction.
+
+// Number of memory slots, see ldm/stm instructions.
+#define MEMORY_ITEMS 16
+// Upon program execution starting some memory slots are prefilled:
+#define MEMORY_OFFSET_IPV4_HEADER_SIZE 13 // 4*([APF_FRAME_HEADER_SIZE]&15)
+#define MEMORY_OFFSET_PACKET_SIZE 14      // Size of packet in bytes.
+#define MEMORY_OFFSET_FILTER_AGE 15       // Age since filter installed in seconds.
+
+// Leave 0 opcode unused as it's a good indicator of accidental incorrect execution (e.g. data).
+#define LDB_OPCODE 1    // Load 1 byte from immediate offset, e.g. "ldb R0, [5]"
+#define LDH_OPCODE 2    // Load 2 bytes from immediate offset, e.g. "ldh R0, [5]"
+#define LDW_OPCODE 3    // Load 4 bytes from immediate offset, e.g. "ldw R0, [5]"
+#define LDBX_OPCODE 4   // Load 1 byte from immediate offset plus register, e.g. "ldbx R0, [5]R0"
+#define LDHX_OPCODE 5   // Load 2 byte from immediate offset plus register, e.g. "ldhx R0, [5]R0"
+#define LDWX_OPCODE 6   // Load 4 byte from immediate offset plus register, e.g. "ldwx R0, [5]R0"
+#define ADD_OPCODE 7    // Add, e.g. "add R0,5"
+#define MUL_OPCODE 8    // Multiply, e.g. "mul R0,5"
+#define DIV_OPCODE 9    // Divide, e.g. "div R0,5"
+#define AND_OPCODE 10   // And, e.g. "and R0,5"
+#define OR_OPCODE 11    // Or, e.g. "or R0,5"
+#define SH_OPCODE 12    // Left shift, e.g, "sh R0, 5" or "sh R0, -5" (shifts right)
+#define LI_OPCODE 13    // Load immediate, e.g. "li R0,5" (immediate encoded as signed value)
+#define JMP_OPCODE 14   // Unconditional jump, e.g. "jmp label"
+#define JEQ_OPCODE 15   // Compare equal and branch, e.g. "jeq R0,5,label"
+#define JNE_OPCODE 16   // Compare not equal and branch, e.g. "jne R0,5,label"
+#define JGT_OPCODE 17   // Compare greater than and branch, e.g. "jgt R0,5,label"
+#define JLT_OPCODE 18   // Compare less than and branch, e.g. "jlt R0,5,label"
+#define JSET_OPCODE 19  // Compare any bits set and branch, e.g. "jset R0,5,label"
+#define JNEBS_OPCODE 20 // Compare not equal byte sequence, e.g. "jnebs R0,5,label,0x1122334455"
+#define EXT_OPCODE 21   // Immediate value is one of *_EXT_OPCODE
+// Extended opcodes. These all have an opcode of EXT_OPCODE
+// and specify the actual opcode in the immediate field.
+#define LDM_EXT_OPCODE 0   // Load from memory, e.g. "ldm R0,5"
+  // Values 0-15 represent loading the different memory slots.
+#define STM_EXT_OPCODE 16  // Store to memory, e.g. "stm R0,5"
+  // Values 16-31 represent storing to the different memory slots.
+#define NOT_EXT_OPCODE 32  // Not, e.g. "not R0"
+#define NEG_EXT_OPCODE 33  // Negate, e.g. "neg R0"
+#define SWAP_EXT_OPCODE 34 // Swap, e.g. "swap R0,R1"
+#define MOV_EXT_OPCODE 35  // Move, e.g. "move R0,R1"
+
+#define EXTRACT_OPCODE(i) (((i) >> 3) & 31)
+#define EXTRACT_REGISTER(i) ((i) & 1)
+#define EXTRACT_IMM_LENGTH(i) (((i) >> 1) & 3)
diff --git a/v2/apf_interpreter.c b/v2/apf_interpreter.c
new file mode 100644
index 0000000..924b23e
--- /dev/null
+++ b/v2/apf_interpreter.c
@@ -0,0 +1,278 @@
+/*
+ * Copyright 2016, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "apf_interpreter.h"
+
+#include <string.h> // For memcmp
+
+#include "apf.h"
+
+// Return code indicating "packet" should accepted.
+#define PASS_PACKET 1
+// Return code indicating "packet" should be dropped.
+#define DROP_PACKET 0
+// Verify an internal condition and accept packet if it fails.
+#define ASSERT_RETURN(c) if (!(c)) return PASS_PACKET
+// If "c" is of an unsigned type, generate a compile warning that gets promoted to an error.
+// This makes bounds checking simpler because ">= 0" can be avoided. Otherwise adding
+// superfluous ">= 0" with unsigned expressions generates compile warnings.
+#define ENFORCE_UNSIGNED(c) ((c)==(uint32_t)(c))
+
+/**
+ * Runs a packet filtering program over a packet.
+ *
+ * @param program the program bytecode.
+ * @param program_len the length of {@code apf_program} in bytes.
+ * @param packet the packet bytes, starting from the 802.3 header and not
+ *               including any CRC bytes at the end.
+ * @param packet_len the length of {@code packet} in bytes.
+ * @param filter_age the number of seconds since the filter was programmed.
+ *
+ * @return non-zero if packet should be passed to AP, zero if
+ *         packet should be dropped.
+ */
+int accept_packet(const uint8_t* program, uint32_t program_len,
+                  const uint8_t* packet, uint32_t packet_len,
+                  uint32_t filter_age) {
+// Is offset within program bounds?
+#define IN_PROGRAM_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < program_len)
+// Is offset within packet bounds?
+#define IN_PACKET_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < packet_len)
+// Accept packet if not within program bounds
+#define ASSERT_IN_PROGRAM_BOUNDS(p) ASSERT_RETURN(IN_PROGRAM_BOUNDS(p))
+// Accept packet if not within packet bounds
+#define ASSERT_IN_PACKET_BOUNDS(p) ASSERT_RETURN(IN_PACKET_BOUNDS(p))
+  // Program counter.
+  uint32_t pc = 0;
+// Accept packet if not within program or not ahead of program counter
+#define ASSERT_FORWARD_IN_PROGRAM(p) ASSERT_RETURN(IN_PROGRAM_BOUNDS(p) && (p) >= pc)
+  // Memory slot values.
+  uint32_t memory[MEMORY_ITEMS] = {};
+  // Fill in pre-filled memory slot values.
+  memory[MEMORY_OFFSET_PACKET_SIZE] = packet_len;
+  memory[MEMORY_OFFSET_FILTER_AGE] = filter_age;
+  ASSERT_IN_PACKET_BOUNDS(APF_FRAME_HEADER_SIZE);
+  // Only populate if IP version is IPv4.
+  if ((packet[APF_FRAME_HEADER_SIZE] & 0xf0) == 0x40) {
+      memory[MEMORY_OFFSET_IPV4_HEADER_SIZE] = (packet[APF_FRAME_HEADER_SIZE] & 15) * 4;
+  }
+  // Register values.
+  uint32_t registers[2] = {};
+  // Count of instructions remaining to execute. This is done to ensure an
+  // upper bound on execution time. It should never be hit and is only for
+  // safety. Initialize to the number of bytes in the program which is an
+  // upper bound on the number of instructions in the program.
+  uint32_t instructions_remaining = program_len;
+
+  do {
+      if (pc == program_len) {
+          return PASS_PACKET;
+      } else if (pc == (program_len + 1)) {
+          return DROP_PACKET;
+      }
+      ASSERT_IN_PROGRAM_BOUNDS(pc);
+      const uint8_t bytecode = program[pc++];
+      const uint32_t opcode = EXTRACT_OPCODE(bytecode);
+      const uint32_t reg_num = EXTRACT_REGISTER(bytecode);
+#define REG (registers[reg_num])
+#define OTHER_REG (registers[reg_num ^ 1])
+      // All instructions have immediate fields, so load them now.
+      const uint32_t len_field = EXTRACT_IMM_LENGTH(bytecode);
+      uint32_t imm = 0;
+      int32_t signed_imm = 0;
+      if (len_field != 0) {
+          const uint32_t imm_len = 1 << (len_field - 1);
+          ASSERT_FORWARD_IN_PROGRAM(pc + imm_len - 1);
+          uint32_t i;
+          for (i = 0; i < imm_len; i++)
+              imm = (imm << 8) | program[pc++];
+          // Sign extend imm into signed_imm.
+          signed_imm = imm << ((4 - imm_len) * 8);
+          signed_imm >>= (4 - imm_len) * 8;
+      }
+      switch (opcode) {
+          case LDB_OPCODE:
+          case LDH_OPCODE:
+          case LDW_OPCODE:
+          case LDBX_OPCODE:
+          case LDHX_OPCODE:
+          case LDWX_OPCODE: {
+              uint32_t offs = imm;
+              if (opcode >= LDBX_OPCODE) {
+                  // Note: this can overflow and actually decrease offs.
+                  offs += registers[1];
+              }
+              ASSERT_IN_PACKET_BOUNDS(offs);
+              uint32_t load_size;
+              switch (opcode) {
+                  case LDB_OPCODE:
+                  case LDBX_OPCODE:
+                    load_size = 1;
+                    break;
+                  case LDH_OPCODE:
+                  case LDHX_OPCODE:
+                    load_size = 2;
+                    break;
+                  case LDW_OPCODE:
+                  case LDWX_OPCODE:
+                    load_size = 4;
+                    break;
+                  // Immediately enclosing switch statement guarantees
+                  // opcode cannot be any other value.
+              }
+              const uint32_t end_offs = offs + (load_size - 1);
+              // Catch overflow/wrap-around.
+              ASSERT_RETURN(end_offs >= offs);
+              ASSERT_IN_PACKET_BOUNDS(end_offs);
+              uint32_t val = 0;
+              while (load_size--)
+                  val = (val << 8) | packet[offs++];
+              REG = val;
+              break;
+          }
+          case JMP_OPCODE:
+              // This can jump backwards. Infinite looping prevented by instructions_remaining.
+              pc += imm;
+              break;
+          case JEQ_OPCODE:
+          case JNE_OPCODE:
+          case JGT_OPCODE:
+          case JLT_OPCODE:
+          case JSET_OPCODE:
+          case JNEBS_OPCODE: {
+              // Load second immediate field.
+              uint32_t cmp_imm = 0;
+              if (reg_num == 1) {
+                  cmp_imm = registers[1];
+              } else if (len_field != 0) {
+                  uint32_t cmp_imm_len = 1 << (len_field - 1);
+                  ASSERT_FORWARD_IN_PROGRAM(pc + cmp_imm_len - 1);
+                  uint32_t i;
+                  for (i = 0; i < cmp_imm_len; i++)
+                      cmp_imm = (cmp_imm << 8) | program[pc++];
+              }
+              switch (opcode) {
+                  case JEQ_OPCODE:
+                      if (registers[0] == cmp_imm)
+                          pc += imm;
+                      break;
+                  case JNE_OPCODE:
+                      if (registers[0] != cmp_imm)
+                          pc += imm;
+                      break;
+                  case JGT_OPCODE:
+                      if (registers[0] > cmp_imm)
+                          pc += imm;
+                      break;
+                  case JLT_OPCODE:
+                      if (registers[0] < cmp_imm)
+                          pc += imm;
+                      break;
+                  case JSET_OPCODE:
+                      if (registers[0] & cmp_imm)
+                          pc += imm;
+                      break;
+                  case JNEBS_OPCODE: {
+                      // cmp_imm is size in bytes of data to compare.
+                      // pc is offset of program bytes to compare.
+                      // imm is jump target offset.
+                      // REG is offset of packet bytes to compare.
+                      ASSERT_FORWARD_IN_PROGRAM(pc + cmp_imm - 1);
+                      ASSERT_IN_PACKET_BOUNDS(REG);
+                      const uint32_t last_packet_offs = REG + cmp_imm - 1;
+                      ASSERT_RETURN(last_packet_offs >= REG);
+                      ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
+                      if (memcmp(program + pc, packet + REG, cmp_imm))
+                          pc += imm;
+                      // skip past comparison bytes
+                      pc += cmp_imm;
+                      break;
+                  }
+              }
+              break;
+          }
+          case ADD_OPCODE:
+              registers[0] += reg_num ? registers[1] : imm;
+              break;
+          case MUL_OPCODE:
+              registers[0] *= reg_num ? registers[1] : imm;
+              break;
+          case DIV_OPCODE: {
+              const uint32_t div_operand = reg_num ? registers[1] : imm;
+              ASSERT_RETURN(div_operand);
+              registers[0] /= div_operand;
+              break;
+          }
+          case AND_OPCODE:
+              registers[0] &= reg_num ? registers[1] : imm;
+              break;
+          case OR_OPCODE:
+              registers[0] |= reg_num ? registers[1] : imm;
+              break;
+          case SH_OPCODE: {
+              const int32_t shift_val = reg_num ? (int32_t)registers[1] : signed_imm;
+              if (shift_val > 0)
+                  registers[0] <<= shift_val;
+              else
+                  registers[0] >>= -shift_val;
+              break;
+          }
+          case LI_OPCODE:
+              REG = signed_imm;
+              break;
+          case EXT_OPCODE:
+              if (
+// If LDM_EXT_OPCODE is 0 and imm is compared with it, a compiler error will result,
+// instead just enforce that imm is unsigned (so it's always greater or equal to 0).
+#if LDM_EXT_OPCODE == 0
+                  ENFORCE_UNSIGNED(imm) &&
+#else
+                  imm >= LDM_EXT_OPCODE &&
+#endif
+                  imm < (LDM_EXT_OPCODE + MEMORY_ITEMS)) {
+                REG = memory[imm - LDM_EXT_OPCODE];
+              } else if (imm >= STM_EXT_OPCODE && imm < (STM_EXT_OPCODE + MEMORY_ITEMS)) {
+                memory[imm - STM_EXT_OPCODE] = REG;
+              } else switch (imm) {
+                  case NOT_EXT_OPCODE:
+                    REG = ~REG;
+                    break;
+                  case NEG_EXT_OPCODE:
+                    REG = -REG;
+                    break;
+                  case SWAP_EXT_OPCODE: {
+                    uint32_t tmp = REG;
+                    REG = OTHER_REG;
+                    OTHER_REG = tmp;
+                    break;
+                  }
+                  case MOV_EXT_OPCODE:
+                    REG = OTHER_REG;
+                    break;
+                  // Unknown extended opcode
+                  default:
+                    // Bail out
+                    return PASS_PACKET;
+              }
+              break;
+          // Unknown opcode
+          default:
+              // Bail out
+              return PASS_PACKET;
+      }
+  } while (instructions_remaining--);
+  return PASS_PACKET;
+}
diff --git a/v2/apf_interpreter.h b/v2/apf_interpreter.h
new file mode 100644
index 0000000..5c9d774
--- /dev/null
+++ b/v2/apf_interpreter.h
@@ -0,0 +1,53 @@
+/*
+ * Copyright 2015, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef APF_V2_INTERPRETER_H_
+#define APF_V2_INTERPRETER_H_
+
+#include <stdint.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * Version of APF instruction set processed by accept_packet().
+ * Should be returned by wifi_get_packet_filter_info.
+ */
+#define APF_VERSION 2
+
+/**
+ * Runs a packet filtering program over a packet.
+ *
+ * @param program the program bytecode.
+ * @param program_len the length of {@code apf_program} in bytes.
+ * @param packet the packet bytes, starting from the 802.3 header and not
+ *               including any CRC bytes at the end.
+ * @param packet_len the length of {@code packet} in bytes.
+ * @param filter_age the number of seconds since the filter was programmed.
+ *
+ * @return non-zero if packet should be passed to AP, zero if
+ *         packet should be dropped.
+ */
+int accept_packet(const uint8_t* program, uint32_t program_len,
+                  const uint8_t* packet, uint32_t packet_len,
+                  uint32_t filter_age);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  // APF_V2_INTERPRETER_H_
diff --git a/v6.1/apf_interpreter.c b/v6.1/apf_interpreter.c
new file mode 100644
index 0000000..d280c5f
--- /dev/null
+++ b/v6.1/apf_interpreter.c
@@ -0,0 +1,1290 @@
+/*
+ * Copyright 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "apf_interpreter.h"
+
+#include <string.h>  /* For memcmp, memcpy, memset */
+
+#if __GNUC__ >= 7 || __clang__
+#define FALLTHROUGH __attribute__((fallthrough))
+#else
+#define FALLTHROUGH
+#endif
+
+typedef enum { False, True } Boolean;
+
+/* Begin include of apf_defs.h */
+typedef int8_t s8;
+typedef int16_t s16;
+typedef int32_t s32;
+
+typedef uint8_t u8;
+typedef uint16_t u16;
+typedef uint32_t u32;
+
+typedef enum {
+  error_program = -2,
+  error_packet = -1,
+  nomatch = False,
+  match = True
+} match_result_type;
+
+#define ETH_P_IP	0x0800
+#define ETH_P_IPV6	0x86DD
+
+#define ETH_HLEN	14
+#define IPV4_HLEN	20
+#define IPV6_HLEN	40
+#define TCP_HLEN	20
+#define UDP_HLEN	8
+
+#define FUNC(x) x; x
+/* End include of apf_defs.h */
+/* Begin include of apf.h */
+/*
+ * Copyright 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef ANDROID_APF_APF_H
+#define ANDROID_APF_APF_H
+
+/* A brief overview of APF:
+ *
+ * APF machine is composed of:
+ *  1. A read-only program consisting of bytecodes as described below.
+ *  2. Two 32-bit registers, called R0 and R1.
+ *  3. Sixteen 32-bit temporary memory slots (cleared between packets).
+ *  4. A read-only packet.
+ *  5. An optional read-write transmit buffer.
+ * The program is executed by the interpreter below and parses the packet
+ * to determine if the application processor (AP) should be woken up to
+ * handle the packet or if it can be dropped.  The program may also choose
+ * to allocate/transmit/deallocate the transmit buffer.
+ *
+ * APF bytecode description:
+ *
+ * The APF interpreter uses big-endian byte order for loads from the packet
+ * and for storing immediates in instructions.
+ *
+ * Each instruction starts with a byte composed of:
+ *  Top 5 bits form "opcode" field, see *_OPCODE defines below.
+ *  Next 2 bits form "size field", which indicates the length of an immediate
+ *  value which follows the first byte.  Values in this field:
+ *                 0 => immediate value is 0 and no bytes follow.
+ *                 1 => immediate value is 1 byte big.
+ *                 2 => immediate value is 2 bytes big.
+ *                 3 => immediate value is 4 bytes big.
+ *  Bottom bit forms "register" field, which (usually) indicates which register
+ *  this instruction operates on.
+ *
+ *  There are four main categories of instructions:
+ *  Load instructions
+ *    These instructions load byte(s) of the packet into a register.
+ *    They load either 1, 2 or 4 bytes, as determined by the "opcode" field.
+ *    They load into the register specified by the "register" field.
+ *    The immediate value that follows the first byte of the instruction is
+ *    the byte offset from the beginning of the packet to load from.
+ *    There are "indexing" loads which add the value in R1 to the byte offset
+ *    to load from. The "opcode" field determines which loads are "indexing".
+ *  Arithmetic instructions
+ *    These instructions perform simple operations, like addition, on register
+ *    values. The result of these instructions is always written into R0. One
+ *    argument of the arithmetic operation is R0's value. The other argument
+ *    of the arithmetic operation is determined by the "register" field:
+ *            If the "register" field is 0 then the immediate value following
+ *            the first byte of the instruction is used as the other argument
+ *            to the arithmetic operation.
+ *            If the "register" field is 1 then R1's value is used as the other
+ *            argument to the arithmetic operation.
+ *  Conditional jump instructions
+ *    These instructions compare register R0's value with another value, and if
+ *    the comparison succeeds, jump (i.e. adjust the program counter). The
+ *    immediate value that follows the first byte of the instruction
+ *    represents the jump target offset, i.e. the value added to the program
+ *    counter if the comparison succeeds. The other value compared is
+ *    determined by the "register" field:
+ *            If the "register" field is 0 then another immediate value
+ *            follows the jump target offset. This immediate value is of the
+ *            same size as the jump target offset, and represents the value
+ *            to compare against.
+ *            If the "register" field is 1 then register R1's value is
+ *            compared against.
+ *    The type of comparison (e.g. equal to, greater than etc) is determined
+ *    by the "opcode" field. The comparison interprets both values being
+ *    compared as unsigned values.
+ *  Miscellaneous instructions
+ *    Instructions for:
+ *      - allocating/transmitting/deallocating transmit buffer
+ *      - building the transmit packet (copying bytes into it)
+ *      - read/writing data section
+ *
+ *  Miscellaneous details:
+ *
+ *  Pre-filled temporary memory slot values
+ *    When the APF program begins execution, six of the sixteen memory slots
+ *    are pre-filled by the interpreter with values that may be useful for
+ *    programs:
+ *      #0 to #7 are zero initialized.
+ *      Slot #8  is initialized with apf version (on APF >4).
+ *      Slot #9  this is slot #15 with greater resolution (1/16384ths of a second)
+ *      Slot #10 starts at zero, implicitly used as tx buffer output pointer.
+ *      Slot #11 contains the size (in bytes) of the APF program.
+ *      Slot #12 contains the total size of the APF program + data.
+ *      Slot #13 is filled with the IPv4 header length. This value is calculated
+ *               by loading the first byte of the IPv4 header and taking the
+ *               bottom 4 bits and multiplying their value by 4. This value is
+ *               set to zero if the first 4 bits after the link layer header are
+ *               not 4, indicating not IPv4.
+ *      Slot #14 is filled with size of the packet in bytes, including the
+ *               ethernet link-layer header.
+ *      Slot #15 is filled with the filter age in seconds. This is the number of
+ *               seconds since the host installed the program. This may
+ *               be used by filters that should have a particular lifetime. For
+ *               example, it can be used to rate-limit particular packets to one
+ *               every N seconds.
+ *  Special jump targets:
+ *    When an APF program executes a jump to the byte immediately after the last
+ *      byte of the progam (i.e., one byte past the end of the program), this
+ *      signals the program has completed and determined the packet should be
+ *      passed to the AP.
+ *    When an APF program executes a jump two bytes past the end of the program,
+ *      this signals the program has completed and determined the packet should
+ *      be dropped.
+ *  Jump if byte sequence doesn't match:
+ *    This is a special instruction to facilitate matching long sequences of
+ *    bytes in the packet. Initially it is encoded like a conditional jump
+ *    instruction with two exceptions:
+ *      The first byte of the instruction is always followed by two immediate
+ *        fields: The first immediate field is the jump target offset like other
+ *        conditional jump instructions. The second immediate field specifies the
+ *        number of bytes to compare.
+ *      These two immediate fields are followed by a sequence of bytes. These
+ *        bytes are compared with the bytes in the packet starting from the
+ *        position specified by the value of the register specified by the
+ *        "register" field of the instruction.
+ */
+
+/* Number of temporary memory slots, see ldm/stm instructions. */
+#define MEMORY_ITEMS 16
+/* Upon program execution, some temporary memory slots are prefilled: */
+
+typedef union {
+  struct {
+    u32 pad[8];               /* 0..7 */
+    u32 apf_version;          /* 8:  Initialized with apf_version() */
+    u32 filter_age_16384ths;  /* 9:  Age since filter installed in 1/16384 seconds. */
+    u32 tx_buf_offset;        /* 10: Offset in tx_buf where next byte will be written */
+    u32 program_size;         /* 11: Size of program (in bytes) */
+    u32 ram_len;              /* 12: Total size of program + data, ie. ram_len */
+    u32 ipv4_header_size;     /* 13: 4*([APF_FRAME_HEADER_SIZE]&15) */
+    u32 packet_size;          /* 14: Size of packet in bytes. */
+    u32 filter_age;           /* 15: Age since filter installed in seconds. */
+  } named;
+  u32 slot[MEMORY_ITEMS];
+} memory_type;
+
+/* ---------------------------------------------------------------------------------------------- */
+
+/* Standard opcodes. */
+
+/* Unconditionally pass (if R=0) or drop (if R=1) packet and optionally increment counter.
+ * An optional non-zero unsigned immediate value can be provided to encode the counter number.
+ * The counter is located (-4 * counter number) bytes from the end of the data region.
+ * It is a U32 big-endian value and is always incremented by 1.
+ * This is more or less equivalent to: lddw R0, -4*N; add R0, 1; stdw R0, -4*N; {pass,drop}
+ * e.g. "pass", "pass 1", "drop", "drop 1"
+ */
+#define PASSDROP_OPCODE 0
+
+#define LDB_OPCODE 1    /* Load 1 byte  from immediate offset, e.g. "ldb R0, [5]" */
+#define LDH_OPCODE 2    /* Load 2 bytes from immediate offset, e.g. "ldh R0, [5]" */
+#define LDW_OPCODE 3    /* Load 4 bytes from immediate offset, e.g. "ldw R0, [5]" */
+#define LDBX_OPCODE 4   /* Load 1 byte  from immediate offset plus register, e.g. "ldbx R0, [5+R0]" */
+#define LDHX_OPCODE 5   /* Load 2 bytes from immediate offset plus register, e.g. "ldhx R0, [5+R0]" */
+#define LDWX_OPCODE 6   /* Load 4 bytes from immediate offset plus register, e.g. "ldwx R0, [5+R0]" */
+#define ADD_OPCODE 7    /* Add, e.g. "add R0,5" */
+#define MUL_OPCODE 8    /* Multiply, e.g. "mul R0,5" */
+#define DIV_OPCODE 9    /* Divide, e.g. "div R0,5" */
+#define AND_OPCODE 10   /* And, e.g. "and R0,5" */
+#define OR_OPCODE 11    /* Or, e.g. "or R0,5" */
+#define SH_OPCODE 12    /* Left shift, e.g. "sh R0, 5" or "sh R0, -5" (shifts right) */
+#define LI_OPCODE 13    /* Load signed immediate, e.g. "li R0,5" */
+#define JMP_OPCODE 14   /* Unconditional jump, e.g. "jmp label" */
+#define JEQ_OPCODE 15   /* Compare equal and branch, e.g. "jeq R0,5,label" */
+#define JNE_OPCODE 16   /* Compare not equal and branch, e.g. "jne R0,5,label" */
+#define JGT_OPCODE 17   /* Compare greater than and branch, e.g. "jgt R0,5,label" */
+#define JLT_OPCODE 18   /* Compare less than and branch, e.g. "jlt R0,5,label" */
+#define JSET_OPCODE 19  /* Compare any bits set and branch, e.g. "jset R0,5,label" */
+#define JBSMATCH_OPCODE 20 /* Compare byte sequence [R=0 not] equal, e.g. "jbsne R0,2,label,0x1122" */
+                           /* NOTE: Only APFv6+ implements R=1 'jbseq' version and multi match */
+                           /* imm1 is jmp target, imm2 is (cnt - 1) * 2048 + compare_len, */
+                           /* which is followed by cnt * compare_len bytes to compare against. */
+                           /* Warning: do not specify the same byte sequence multiple times. */
+#define EXT_OPCODE 21   /* Immediate value is one of *_EXT_OPCODE */
+#define LDDW_OPCODE 22  /* Load 4 bytes from data address (register + signed imm): "lddw R0, [5+R1]" */
+                        /* LDDW/STDW in APFv6+ *mode* load/store from counter specified in imm. */
+#define STDW_OPCODE 23  /* Store 4 bytes to data address (register + signed imm): "stdw R0, [5+R1]" */
+
+/* Write 1, 2 or 4 byte immediate to the output buffer and auto-increment the output buffer pointer.
+ * Immediate length field specifies size of write.  R must be 0.  imm_len != 0.
+ * e.g. "write 5"
+ */
+#define WRITE_OPCODE 24
+
+/* Copy bytes from input packet/APF program/data region to output buffer and
+ * auto-increment the output buffer pointer.
+ * Register bit is used to specify the source of data copy.
+ * R=0 means copy from packet.
+ * R=1 means copy from APF program/data region.
+ * The source offset is stored in imm1, copy length is stored in u8 imm2.
+ * APFv6.1: if u8 imm2 is 0 then copy length is 256 + extra u8 imm3
+ * e.g. "pktcopy 0, 16" or "datacopy 0, 16"
+ */
+#define PKTDATACOPY_OPCODE 25
+
+#define JNSET_OPCODE 26 /* JSET with reverse condition (jump if no bits set) */
+
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
+/* ---------------------------------------------------------------------------------------------- */
+
+/* Extended opcodes. */
+/* These all have an opcode of EXT_OPCODE and specify the actual opcode in the immediate field. */
+
+#define LDM_EXT_OPCODE 0   /* Load from temporary memory, e.g. "ldm R0,5" */
+  /* Values 0-15 represent loading the different temporary memory slots. */
+#define STM_EXT_OPCODE 16  /* Store to temporary memory, e.g. "stm R0,5" */
+  /* Values 16-31 represent storing to the different temporary memory slots. */
+#define NOT_EXT_OPCODE 32  /* Not, e.g. "not R0" */
+#define NEG_EXT_OPCODE 33  /* Negate, e.g. "neg R0" */
+#define SWAP_EXT_OPCODE 34 /* Swap, e.g. "swap R0,R1" */
+#define MOV_EXT_OPCODE 35  /* Move, e.g. "move R0,R1" */
+
+/* Allocate writable output buffer.
+ * R=0: register R0 specifies the length
+ * R=1: length provided in u16 imm2
+ * e.g. "allocate R0" or "allocate 123"
+ * On failure automatically executes 'pass 3'
+ */
+#define ALLOCATE_EXT_OPCODE 36
+
+/* Transmit and deallocate the buffer (transmission can be delayed until the program
+ * terminates).  Length of buffer is the output buffer pointer (0 means discard).
+ * R=1 iff udp style L4 checksum
+ * u8 imm2 - ip header offset from start of buffer (255 for non-ip packets)
+ * u8 imm3 - offset from start of buffer to store L4 checksum (255 for no L4 checksum)
+ * u8 imm4 - offset from start of buffer to begin L4 checksum calculation (present iff imm3 != 255)
+ * u16 imm5 - partial checksum value to include in L4 checksum (present iff imm3 != 255)
+ * "e.g. transmit"
+ */
+#define TRANSMIT_EXT_OPCODE 37
+
+/* Write 1, 2 or 4 byte value from register to the output buffer and auto-increment the
+ * output buffer pointer.
+ * e.g. "ewrite1 r0" or "ewrite2 r1"
+ */
+#define EWRITE1_EXT_OPCODE 38
+#define EWRITE2_EXT_OPCODE 39
+#define EWRITE4_EXT_OPCODE 40
+
+/* Copy bytes from input packet/APF program/data region to output buffer and
+ * auto-increment the output buffer pointer.
+ * Register bit is used to specify the source of data copy.
+ * R=0 means copy from packet.
+ * R=1 means copy from APF program/data region.
+ * The source offset is stored in R0, copy length is stored in u8 imm2 or R1.
+ * APFv6.1: if u8 imm2 is 0 then copy length is 256 + extra u8 imm3.
+ * e.g. "epktcopy r0, 16", "edatacopy r0, 16", "epktcopy r0, r1", "edatacopy r0, r1"
+ */
+#define EPKTDATACOPYIMM_EXT_OPCODE 41
+#define EPKTDATACOPYR1_EXT_OPCODE 42
+
+/* Jumps if the UDP payload content (starting at R0) does [not] match one
+ * of the specified QNAMEs in question records, applying case insensitivity.
+ * SAFE version PASSES corrupt packets, while the other one DROPS.
+ * R=0/1 meaning 'does not match'/'matches'
+ * R0: Offset to UDP payload content
+ * imm1: Extended opcode
+ * imm2: Jump label offset
+ * imm3(u8): Question type (PTR/SRV/TXT/A/AAAA)
+ *   note: imm3 is instead u16 in '1' version
+ * imm4(bytes): null terminated list of null terminated LV-encoded QNAMEs
+ * e.g.: "jdnsqeq R0,label,0xc,\002aa\005local\0\0", "jdnsqne R0,label,0xc,\002aa\005local\0\0"
+ */
+#define JDNSQMATCH_EXT_OPCODE 43
+#define JDNSQMATCHSAFE_EXT_OPCODE 45
+#define JDNSQMATCH1_EXT_OPCODE 55
+#define JDNSQMATCHSAFE1_EXT_OPCODE 57
+
+/* Jumps if the UDP payload content (starting at R0) does [not] match one
+ * of the specified NAMEs in answers/authority/additional records, applying
+ * case insensitivity.
+ * SAFE version PASSES corrupt packets, while the other one DROPS.
+ * R=0/1 meaning 'does not match'/'matches'
+ * R0: Offset to UDP payload content
+ * imm1: Extended opcode
+ * imm2: Jump label offset
+ * imm3(bytes): null terminated list of null terminated LV-encoded NAMEs
+ * e.g.: "jdnsaeq R0,label,0xc,\002aa\005local\0\0", "jdnsane R0,label,0xc,\002aa\005local\0\0"
+ */
+#define JDNSAMATCH_EXT_OPCODE 44
+#define JDNSAMATCHSAFE_EXT_OPCODE 46
+
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
+/* Jump if register is [not] one of the list of values
+ * R bit - specifies the register (R0/R1) to test
+ * imm1: Extended opcode
+ * imm2: Jump label offset
+ * imm3(u8): top 5 bits - number 'n' of following u8/be16/be32 values - 2
+ *        middle 2 bits - 1..4 length of immediates - 1
+ *        bottom 1 bit  - =0 jmp if in set, =1 if not in set
+ * imm4(n * 1/2/3/4 bytes): the *UNIQUE* values to compare against
+ */
+#define JONEOF_EXT_OPCODE 47
+
+/* Specify length of exception buffer, which is populated on abnormal program termination.
+ * imm1: Extended opcode
+ * imm2(u16): Length of exception buffer (located *immediately* after the program itself)
+ */
+#define EXCEPTIONBUFFER_EXT_OPCODE 48
+
+/* Note: 51, 53, 55, 57 used up above for DNS matching */
+
+/* This extended opcode is used to implement PKTDATACOPY_OPCODE */
+#define PKTDATACOPYIMM_EXT_OPCODE 65536
+
+#define EXTRACT_OPCODE(i) (((i) >> 3) & 31)
+#define EXTRACT_REGISTER(i) ((i) & 1)
+#define EXTRACT_IMM_LENGTH(i) (((i) >> 1) & 3)
+
+#endif  /* ANDROID_APF_APF_H */
+/* End include of apf.h */
+/* Begin include of apf_utils.h */
+static u32 read_be16(const u8* buf) {
+    return buf[0] * 256u + buf[1];
+}
+
+static void store_be16(u8* const buf, const u16 v) {
+    buf[0] = (u8)(v >> 8);
+    buf[1] = (u8)v;
+}
+
+static u8 uppercase(u8 c) {
+    return (c >= 'a') && (c <= 'z') ? c - ('a' - 'A') : c;
+}
+/* End include of apf_utils.h */
+/* Begin include of apf_dns.h */
+/**
+ * Compares a (Q)NAME starting at udp[*ofs] with the target name.
+ *
+ * @param needle - non-NULL - pointer to DNS encoded target name to match against.
+ *   example: [11]_googlecast[4]_tcp[5]local[0]  (where [11] is a byte with value 11)
+ * @param needle_bound - non-NULL - points at first invalid byte past needle.
+ * @param udp - non-NULL - pointer to the start of the UDP payload (DNS header).
+ * @param udp_len - length of the UDP payload.
+ * @param ofs - non-NULL - pointer to the offset of the beginning of the (Q)NAME.
+ *   On non-error return will be updated to point to the first unread offset,
+ *   ie. the next position after the (Q)NAME.
+ *
+ * @return 1 if matched, 0 if not matched, -1 if error in packet, -2 if error in program.
+ */
+FUNC(match_result_type apf_internal_match_single_name(const u8* needle,
+                                    const u8* const needle_bound,
+                                    const u8* const udp,
+                                    const u32 udp_len,
+                                    u32* const ofs)) {
+    u32 first_unread_offset = *ofs;
+    Boolean is_qname_match = True;
+    int lvl;
+
+    /* DNS names are <= 255 characters including terminating 0, since >= 1 char + '.' per level => max. 127 levels */
+    for (lvl = 1; lvl <= 127; ++lvl) {
+        u8 v;
+        if (*ofs >= udp_len) return error_packet;
+        v = udp[(*ofs)++];
+        if (v >= 0xC0) { /* RFC 1035 4.1.4 - handle message compression */
+            u8 w;
+            u32 new_ofs;
+            if (*ofs >= udp_len) return error_packet;
+            w = udp[(*ofs)++];
+            if (*ofs > first_unread_offset) first_unread_offset = *ofs;
+            new_ofs = (v - 0xC0) * 256u + w;
+            if (new_ofs >= *ofs) return error_packet;  /* RFC 1035 4.1.4 allows only backward pointers */
+            *ofs = new_ofs;
+        } else if (v > 63) {
+            return error_packet;  /* RFC 1035 2.3.4 - label size is 1..63. */
+        } else if (v) {
+            u8 label_size = v;
+            if (*ofs + label_size > udp_len) return error_packet;
+            if (needle >= needle_bound) return error_program;
+            if (is_qname_match) {
+                u8 len = *needle++;
+                if (len == label_size) {
+                    if (needle + label_size > needle_bound) return error_program;
+                    while (label_size--) {
+                        u8 w = udp[(*ofs)++];
+                        is_qname_match &= (uppercase(w) == *needle++);
+                    }
+                } else {
+                    if (len != 0xFF) is_qname_match = False;
+                    *ofs += label_size;
+                }
+            } else {
+                is_qname_match = False;
+                *ofs += label_size;
+            }
+        } else { /* reached the end of the name */
+            if (first_unread_offset > *ofs) *ofs = first_unread_offset;
+            return (is_qname_match && *needle == 0) ? match : nomatch;
+        }
+    }
+    return error_packet;  /* too many dns domain name levels */
+}
+
+/**
+ * Check if DNS packet contains any of the target names with the provided
+ * question_types.
+ *
+ * @param needles - non-NULL - pointer to DNS encoded target nameS to match against.
+ *   example: [3]foo[3]com[0][3]bar[3]net[0][0]  -- note ends with an extra NULL byte.
+ * @param needle_bound - non-NULL - points at first invalid byte past needles.
+ * @param udp - non-NULL - pointer to the start of the UDP payload (DNS header).
+ * @param udp_len - length of the UDP payload.
+ * @param question_type1 - question type to match against or -1 to match answers.
+ *                         If question_type1 is -1, we won't check question_type2.
+ * @param question_type2 - question type to match against or -1 to match answers.
+ *
+ * @return 1 if matched, 0 if not matched, -1 if error in packet, -2 if error in program.
+ */
+FUNC(match_result_type apf_internal_match_names(const u8* needles,
+                              const u8* const needle_bound,
+                              const u8* const udp,
+                              const u32 udp_len,
+                              const int question_type1,
+                              const int question_type2)) {
+    u32 num_questions, num_answers;
+    if (udp_len < 12) return error_packet;  /* lack of dns header */
+
+    /* dns header: be16 tid, flags, num_{questions,answers,authority,additional} */
+    num_questions = read_be16(udp + 4);
+    num_answers = read_be16(udp + 6) + read_be16(udp + 8) + read_be16(udp + 10);
+
+    /* loop until we hit final needle, which is a null byte */
+    while (True) {
+        u32 i, ofs = 12;  /* dns header is 12 bytes */
+        if (needles >= needle_bound) return error_program;
+        if (!*needles) return nomatch;  /* we've run out of needles without finding a match */
+        /* match questions */
+        for (i = 0; i < num_questions; ++i) {
+            match_result_type m = apf_internal_match_single_name(needles, needle_bound, udp, udp_len, &ofs);
+            int qtype;
+            if (m < nomatch) return m;
+            if (ofs + 2 > udp_len) return error_packet;
+            qtype = (int)read_be16(udp + ofs);
+            ofs += 4; /* skip be16 qtype & qclass */
+            if (question_type1 == -1) continue;
+            if (m == nomatch) continue;
+            if (qtype == 0xFF /* QTYPE_ANY */ || qtype == question_type1 || qtype == question_type2)
+              return match;
+        }
+        /* match answers */
+        if (question_type1 == -1) for (i = 0; i < num_answers; ++i) {
+            match_result_type m = apf_internal_match_single_name(needles, needle_bound, udp, udp_len, &ofs);
+            if (m < nomatch) return m;
+            ofs += 8; /* skip be16 type, class & be32 ttl */
+            if (ofs + 2 > udp_len) return error_packet;
+            ofs += 2 + read_be16(udp + ofs);  /* skip be16 rdata length field, plus length bytes */
+            if (m == match) return match;
+        }
+        /* move needles pointer to the next needle. */
+        do {
+            u8 len = *needles++;
+            if (len == 0xFF) continue;
+            if (len > 63) return error_program;
+            needles += len;
+            if (needles >= needle_bound) return error_program;
+        } while (*needles);
+        needles++;  /* skip the NULL byte at the end of *a* DNS name */
+    }
+}
+/* End include of apf_dns.h */
+/* Begin include of apf_checksum.h */
+/**
+ * Calculate big endian 16-bit sum of a buffer (max 128kB),
+ * then fold and negate it, producing a 16-bit result in [0..FFFE].
+ */
+FUNC(u16 apf_internal_calc_csum(u32 sum, const u8* const buf, const s32 len)) {
+    u16 csum;
+    s32 i;
+    for (i = 0; i < len; ++i) sum += buf[i] * ((i & 1) ? 1u : 256u);
+
+    sum = (sum & 0xFFFF) + (sum >> 16);  /* max after this is 1FFFE */
+    csum = sum + (sum >> 16);
+    return ~csum;  /* assuming sum > 0 on input, this is in [0..FFFE] */
+}
+
+static u16 fix_udp_csum(u16 csum) {
+    return csum ? csum : 0xFFFF;
+}
+
+/**
+ * Calculate and store packet checksums and return dscp.
+ *
+ * @param pkt - pointer to the very start of the to-be-transmitted packet,
+ *              ie. the start of the ethernet header (if one is present)
+ *     WARNING: at minimum 266 bytes of buffer pointed to by 'pkt' pointer
+ *              *MUST* be writable.
+ * (IPv4 header checksum is a 2 byte value, 10 bytes after ip_ofs,
+ * which has a maximum value of 254.  Thus 254[ip_ofs] + 10 + 2[u16] = 266)
+ *
+ * @param len - length of the packet (this may be < 266).
+ * @param ip_ofs - offset from beginning of pkt to IPv4 or IPv6 header:
+ *                 IP version detected based on top nibble of this byte,
+ *                 for IPv4 we will calculate and store IP header checksum,
+ *                 but only for the first 20 bytes of the header,
+ *                 prior to calling this the IPv4 header checksum field
+ *                 must be initialized to the partial checksum of the IPv4
+ *                 options (0 if none)
+ *                 255 means there is no IP header (for example ARP)
+ *                 DSCP will be retrieved from this IP header (0 if none).
+ * @param partial_csum - additional value to include in L4 checksum
+ * @param csum_start - offset from beginning of pkt to begin L4 checksum
+ *                     calculation (until end of pkt specified by len)
+ * @param csum_ofs - offset from beginning of pkt to store L4 checksum
+ *                   255 means do not calculate/store L4 checksum
+ * @param udp - True iff we should generate a UDP style L4 checksum (0 -> 0xFFFF)
+ *
+ * @return 6-bit DSCP value [0..63], garbage on parse error.
+ */
+FUNC(int apf_internal_csum_and_return_dscp(u8* const pkt, const s32 len, const u8 ip_ofs,
+  const u16 partial_csum, const u8 csum_start, const u8 csum_ofs, const Boolean udp)) {
+    if (csum_ofs < 255) {
+        /* note that apf_internal_calc_csum() treats negative lengths as zero */
+        u32 csum = apf_internal_calc_csum(partial_csum, pkt + csum_start, len - csum_start);
+        if (udp) csum = fix_udp_csum(csum);
+        store_be16(pkt + csum_ofs, csum);
+    }
+    if (ip_ofs < 255) {
+        u8 ip = pkt[ip_ofs] >> 4;
+        if (ip == 4) {
+            store_be16(pkt + ip_ofs + 10, apf_internal_calc_csum(0, pkt + ip_ofs, IPV4_HLEN));
+            return pkt[ip_ofs + 1] >> 2;  /* DSCP */
+        } else if (ip == 6) {
+            return (read_be16(pkt + ip_ofs) >> 6) & 0x3F;  /* DSCP */
+        }
+    }
+    return 0;
+}
+/* End include of apf_checksum.h */
+
+/* User hook for interpreter debug tracing. */
+#ifdef APF_TRACE_HOOK
+extern void APF_TRACE_HOOK(u32 pc, const u32* regs, const u8* program,
+                           u32 program_len, const u8 *packet, u32 packet_len,
+                           const u32* memory, u32 ram_len);
+#else
+#define APF_TRACE_HOOK(pc, regs, program, program_len, packet, packet_len, memory, memory_len) \
+    do { /* nop*/                                                                              \
+    } while (0)
+#endif
+
+/* Return code indicating "packet" should accepted. */
+#define PASS 1
+/* Return code indicating "packet" should be accepted (and something unexpected happened). */
+#define EXCEPTION 2
+/* Return code indicating "packet" should be dropped. */
+#define DROP 0
+/* Verify an internal condition and accept packet if it fails. */
+#define ASSERT_RETURN(c) if (!(c)) return EXCEPTION
+/* If "c" is of an unsigned type, generate a compile warning that gets promoted to an error. */
+/* This makes bounds checking simpler because ">= 0" can be avoided. Otherwise adding */
+/* superfluous ">= 0" with unsigned expressions generates compile warnings. */
+#define ENFORCE_UNSIGNED(c) ((c)==(u32)(c))
+
+u32 apf_version(void) {
+    return 6100;
+}
+
+typedef struct {
+    /* Note: the following 4 fields take up exactly 8 bytes. */
+    u16 except_buf_sz; /* Length of the exception buffer (at program_len offset) */
+    u8 ptr_size;       /* sizeof(void*) */
+    u8 v6;             /* Set to 1 by first jmpdata (APFv6+) instruction */
+    u32 pc;            /* Program counter. */
+    /* All the pointers should be next to each other for better struct packing. */
+    /* We are at offset 8, so even 64-bit pointers will not need extra padding. */
+    void *caller_ctx;  /* Passed in to interpreter, passed through to alloc/transmit. */
+    u8* tx_buf;        /* The output buffer pointer */
+    u8* program;       /* Pointer to program/data buffer */
+    const u8* packet;  /* Pointer to input packet buffer */
+    /* Order fields in order of decreasing size */
+    u32 tx_buf_len;    /* The length of the output buffer */
+    u32 program_len;   /* Length of the program */
+    u32 ram_len;       /* Length of the entire apf program/data region */
+    u32 packet_len;    /* Length of the input packet buffer */
+    u32 R[2];          /* Register values. */
+    memory_type mem;   /* Memory slot values.  (array of u32s) */
+    /* Note: any extra u16s go here, then u8s */
+} apf_context;
+
+FUNC(int apf_internal_do_transmit_buffer(apf_context* ctx, u32 pkt_len, u8 dscp)) {
+    int ret = apf_transmit_buffer(ctx->caller_ctx, ctx->tx_buf, pkt_len, dscp);
+    ctx->tx_buf = NULL;
+    ctx->tx_buf_len = 0;
+    return ret;
+}
+
+static int do_discard_buffer(apf_context* ctx) {
+    return apf_internal_do_transmit_buffer(ctx, 0 /* pkt_len */, 0 /* dscp */);
+}
+
+#define DECODE_U8() (ctx->program[ctx->pc++])
+
+static u16 decode_be16(apf_context* ctx) {
+    u16 v = DECODE_U8();
+    v <<= 8;
+    v |= DECODE_U8();
+    return v;
+}
+
+/* Decode an immediate, lengths [0..4] all work, does not do range checking. */
+/* But note that program is at least 20 bytes shorter than ram, so first few */
+/* immediates can always be safely decoded without exceeding ram buffer. */
+static u32 decode_imm(apf_context* ctx, u32 length) {
+    u32 i, v = 0;
+    for (i = 0; i < length; ++i) v = (v << 8) | DECODE_U8();
+    return v;
+}
+
+/* Warning: 'ofs' should be validated by caller! */
+static u8 read_packet_u8(apf_context* ctx, u32 ofs) {
+    return ctx->packet[ofs];
+}
+
+static int do_apf_run(apf_context* ctx) {
+/* Is offset within ram bounds? */
+#define IN_RAM_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < ctx->ram_len)
+/* Is offset within packet bounds? */
+#define IN_PACKET_BOUNDS(p) (ENFORCE_UNSIGNED(p) && (p) < ctx->packet_len)
+/* Is access to offset |p| length |size| within data bounds? */
+#define IN_DATA_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
+                                 ENFORCE_UNSIGNED(size) && \
+                                 (p) + (size) <= ctx->ram_len && \
+                                 (p) + (size) >= (p))  /* catch wraparounds */
+/* Accept packet if not within ram bounds */
+#define ASSERT_IN_RAM_BOUNDS(p) ASSERT_RETURN(IN_RAM_BOUNDS(p))
+/* Accept packet if not within packet bounds */
+#define ASSERT_IN_PACKET_BOUNDS(p) ASSERT_RETURN(IN_PACKET_BOUNDS(p))
+/* Accept packet if not within data bounds */
+#define ASSERT_IN_DATA_BOUNDS(p, size) ASSERT_RETURN(IN_DATA_BOUNDS(p, size))
+
+    /* Counters start at end of RAM and count *backwards* so this array takes negative integers. */
+    u32 *counter = (u32*)(ctx->program + ctx->ram_len);
+
+    /* Count of instructions remaining to execute. This is done to ensure an */
+    /* upper bound on execution time. It should never be hit and is only for */
+    /* safety. Initialize to the number of bytes in the program which is an */
+    /* upper bound on the number of instructions in the program. */
+    u32 instructions_remaining = ctx->program_len;
+
+    /* APFv6.1 requires at least 6 u32 counters at the end of ram, this makes counter[-6]++ valid */
+    /* This cannot wrap due to previous check, that enforced program_len & ram_len < 2GiB. */
+    if (ctx->program_len + 24 > ctx->ram_len) return EXCEPTION;
+
+    /* Only populate if packet long enough, and IP version is IPv4. */
+    /* Note: this doesn't actually check the ethertype... */
+    if ((ctx->packet_len >= ETH_HLEN + IPV4_HLEN)
+        && ((read_packet_u8(ctx, ETH_HLEN) & 0xf0) == 0x40)) {
+        ctx->mem.named.ipv4_header_size = (read_packet_u8(ctx, ETH_HLEN) & 15) * 4;
+    }
+
+/* Is access to offset |p| length |size| within output buffer bounds? */
+#define IN_OUTPUT_BOUNDS(p, size) (ENFORCE_UNSIGNED(p) && \
+                                 ENFORCE_UNSIGNED(size) && \
+                                 (p) + (size) <= ctx->tx_buf_len && \
+                                 (p) + (size) >= (p))
+/* Accept packet if not write within allocated output buffer */
+#define ASSERT_IN_OUTPUT_BOUNDS(p, size) ASSERT_RETURN(IN_OUTPUT_BOUNDS(p, size))
+
+    do {
+      APF_TRACE_HOOK(ctx->pc, ctx->R, ctx->program, ctx->program_len,
+                     ctx->packet, ctx->packet_len, ctx->mem.slot, ctx->ram_len);
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
+
+      {  /* half indent to avoid needless line length... */
+
+        const u8 bytecode = DECODE_U8();
+        const u8 opcode = EXTRACT_OPCODE(bytecode);
+        const u8 reg_num = EXTRACT_REGISTER(bytecode);
+#define REG (ctx->R[reg_num])
+#define OTHER_REG (ctx->R[reg_num ^ 1])
+        /* All instructions have immediate fields, so load them now. */
+        const u8 len_field = EXTRACT_IMM_LENGTH(bytecode);
+        const u8 imm_len = ((len_field + 1u) >> 2) + len_field; /* 0,1,2,3 -> 0,1,2,4 */
+        u32 pktcopy_src_offset = 0;  /* used for various pktdatacopy opcodes */
+        u32 imm = 0;
+        s32 signed_imm = 0;
+        u32 arith_imm;
+        s32 arith_signed_imm;
+        if (len_field != 0) {
+            imm = decode_imm(ctx, imm_len); /* 1st imm, at worst bytes 1-4 past opcode/program_len */
+            /* Sign extend imm into signed_imm. */
+            signed_imm = (s32)(imm << ((4 - imm_len) * 8));
+            signed_imm >>= (4 - imm_len) * 8;
+        }
+
+        /* See comment at ADD_OPCODE for the reason for ARITH_REG/arith_imm/arith_signed_imm. */
+#define ARITH_REG (ctx->R[reg_num & ctx->v6])
+        arith_imm = (ctx->v6) ? (len_field ? imm : OTHER_REG) : (reg_num ? ctx->R[1] : imm);
+        arith_signed_imm = (ctx->v6) ? (len_field ? signed_imm : (s32)OTHER_REG) : (reg_num ? (s32)ctx->R[1] : signed_imm);
+
+        switch (opcode) {
+          case PASSDROP_OPCODE: {  /* APFv6+ */
+            if (len_field > 2) return EXCEPTION;  /* max 64K counters (ie. imm < 64K) */
+            if (imm) {
+                if (4 * imm > ctx->ram_len) return EXCEPTION;
+                counter[-(s32)imm]++;
+            }
+            return reg_num ? DROP : PASS;
+          }
+          case LDB_OPCODE:
+          case LDH_OPCODE:
+          case LDW_OPCODE:
+          case LDBX_OPCODE:
+          case LDHX_OPCODE:
+          case LDWX_OPCODE: {
+            u32 load_size = 0;
+            u32 offs = imm;
+            /* Note: this can overflow and actually decrease offs. */
+            if (opcode >= LDBX_OPCODE) offs += ctx->R[1];
+            switch (opcode) {
+              case LDB_OPCODE:
+              case LDBX_OPCODE:
+                load_size = 1;
+                break;
+              case LDH_OPCODE:
+              case LDHX_OPCODE:
+                load_size = 2;
+                break;
+              case LDW_OPCODE:
+              case LDWX_OPCODE:
+                load_size = 4;
+                break;
+              /* Immediately enclosing switch statement guarantees */
+              /* opcode cannot be any other value. */
+            }
+            {
+                const u32 end_offs = offs + (load_size - 1);
+                u32 val = 0;
+                /* Catch overflow/wrap-around. */
+                ASSERT_RETURN(end_offs >= offs);
+                ASSERT_IN_PACKET_BOUNDS(end_offs);
+                /* load_size underflow on final iteration not an issue as not used after loop. */
+                while (load_size--) val = (val << 8) | read_packet_u8(ctx, offs++);
+                REG = val;
+            }
+            break;
+          }
+          case JMP_OPCODE:
+            if (reg_num && !ctx->v6) {  /* APFv6+ */
+                /* First invocation of APFv6 jmpdata instruction */
+                counter[-1] = 0x12345678;  /* endianness marker */
+                counter[-2]++;  /* total packets ++ */
+                ctx->v6 = (u8)True;
+            }
+            /* This can jump backwards. Infinite looping prevented by instructions_remaining. */
+            ctx->pc += imm;
+            break;
+          case JEQ_OPCODE:
+          case JNE_OPCODE:
+          case JGT_OPCODE:
+          case JLT_OPCODE:
+          case JSET_OPCODE:
+          case JNSET_OPCODE: {
+            u32 cmp_imm = 0;
+            /* Load second immediate field. */
+            if (reg_num == 1) {
+                cmp_imm = ctx->R[1];
+            } else {
+                cmp_imm = decode_imm(ctx, imm_len); /* 2nd imm, at worst 8 bytes past prog_len */
+            }
+            switch (opcode) {
+              case JEQ_OPCODE:   if (  ctx->R[0] == cmp_imm ) ctx->pc += imm; break;
+              case JNE_OPCODE:   if (  ctx->R[0] != cmp_imm ) ctx->pc += imm; break;
+              case JGT_OPCODE:   if (  ctx->R[0] >  cmp_imm ) ctx->pc += imm; break;
+              case JLT_OPCODE:   if (  ctx->R[0] <  cmp_imm ) ctx->pc += imm; break;
+              case JSET_OPCODE:  if (  ctx->R[0] &  cmp_imm ) ctx->pc += imm; break;
+              case JNSET_OPCODE: if (!(ctx->R[0] &  cmp_imm)) ctx->pc += imm; break;
+            }
+            break;
+          }
+          case JBSMATCH_OPCODE: {
+            /* Load second immediate field. */
+            u32 cmp_imm = decode_imm(ctx, imm_len); /* 2nd imm, at worst 8 bytes past prog_len */
+            u32 cnt = (cmp_imm >> 11) + 1; /* 1+, up to 32 fits in u16 */
+            u32 len = cmp_imm & 2047; /* 0..2047 */
+            u32 bytes = cnt * len;
+            const u32 last_packet_offs = ctx->R[0] + len - 1;
+            Boolean matched = False;
+            /* bytes = cnt * len is size in bytes of data to compare. */
+            /* pc is offset of program bytes to compare. */
+            /* imm is jump target offset. */
+            /* R0 is offset of packet bytes to compare. */
+            if (bytes > 0xFFFF) return EXCEPTION;
+            /* pc < program_len < ram_len < 2GiB, thus pc + bytes cannot wrap */
+            if (!IN_RAM_BOUNDS(ctx->pc + bytes - 1)) return EXCEPTION;
+            ASSERT_IN_PACKET_BOUNDS(ctx->R[0]);
+            /* Note: this will return EXCEPTION (due to wrap) if imm_len (ie. len) is 0 */
+            ASSERT_RETURN(last_packet_offs >= ctx->R[0]);
+            ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
+            /* cnt underflow on final iteration not an issue as not used after loop. */
+            while (cnt--) {
+                matched |= !memcmp(ctx->program + ctx->pc, ctx->packet + ctx->R[0], len);
+                /* skip past comparison bytes */
+                ctx->pc += len;
+            }
+            if (matched ^ !reg_num) ctx->pc += imm;
+            break;
+          }
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
+          /* There is a difference in APFv4 and APFv6 arithmetic behaviour! */
+          /* APFv4:  R[0] op= Rbit ? R[1] : imm;  (and it thus doesn't make sense to have R=1 && len_field>0) */
+          /* APFv6+: REG  op= len_field ? imm : OTHER_REG;  (note: this is *DIFFERENT* with R=1 len_field==0) */
+          /* Furthermore APFv4 uses unsigned imm (except SH), while APFv6 uses signed_imm for ADD/AND/SH. */
+          case ADD_OPCODE: ARITH_REG += (ctx->v6) ? (u32)arith_signed_imm : arith_imm; break;
+          case MUL_OPCODE: ARITH_REG *= arith_imm; break;
+          case AND_OPCODE: ARITH_REG &= (ctx->v6) ? (u32)arith_signed_imm : arith_imm; break;
+          case OR_OPCODE:  ARITH_REG |= arith_imm; break;
+          case DIV_OPCODE: {  /* see above comment! */
+            const u32 div_operand = arith_imm;
+            ASSERT_RETURN(div_operand);
+            ARITH_REG /= div_operand;
+            break;
+          }
+          case SH_OPCODE: {  /* see above comment! */
+            if (arith_signed_imm >= 0)
+                ARITH_REG <<= arith_signed_imm;
+            else
+                ARITH_REG >>= -arith_signed_imm;
+            break;
+          }
+          case LI_OPCODE:
+            REG = (u32)signed_imm;
+            break;
+          case PKTDATACOPY_OPCODE:
+            pktcopy_src_offset = imm;
+            imm = PKTDATACOPYIMM_EXT_OPCODE;
+            FALLTHROUGH;
+          case EXT_OPCODE:
+            if (/* imm >= LDM_EXT_OPCODE &&  -- but note imm is u32 and LDM_EXT_OPCODE is 0 */
+                imm < (LDM_EXT_OPCODE + MEMORY_ITEMS)) {
+                REG = ctx->mem.slot[imm - LDM_EXT_OPCODE];
+            } else if (imm >= STM_EXT_OPCODE && imm < (STM_EXT_OPCODE + MEMORY_ITEMS)) {
+                ctx->mem.slot[imm - STM_EXT_OPCODE] = REG;
+            } else switch (imm) {
+              case NOT_EXT_OPCODE: REG = ~REG;      break;
+              case NEG_EXT_OPCODE: REG = -REG;      break;
+              case MOV_EXT_OPCODE: REG = OTHER_REG; break;
+              case SWAP_EXT_OPCODE: {
+                u32 tmp = ctx->R[0];
+                ctx->R[0] = ctx->R[1];
+                ctx->R[1] = tmp;
+                break;
+              }
+              case ALLOCATE_EXT_OPCODE:
+              do_allocate:
+                ASSERT_RETURN(ctx->tx_buf == NULL);
+                if (opcode == ALLOC_XMIT_OPCODE) {
+                    ctx->tx_buf_len = 266 + 8 * imm;
+                } else if (reg_num == 0) {
+                    ctx->tx_buf_len = REG;
+                } else {
+                    ctx->tx_buf_len = decode_be16(ctx); /* 2nd imm, at worst 6 B past prog_len */
+                }
+                /* checksumming functions require minimum 266 byte buffer for correctness */
+                if (ctx->tx_buf_len < 266) ctx->tx_buf_len = 266;
+                ctx->tx_buf = apf_allocate_buffer(ctx->caller_ctx, ctx->tx_buf_len);
+                if (!ctx->tx_buf) {  /* allocate failure */
+                    ctx->tx_buf_len = 0;
+                    counter[-3]++;
+                    return EXCEPTION;
+                }
+                memset(ctx->tx_buf, 0, ctx->tx_buf_len);
+                ctx->mem.named.tx_buf_offset = 0;
+                break;
+              case TRANSMIT_EXT_OPCODE:
+              do_transmit: {
+                /* tx_buf_len cannot be large because we'd run out of RAM, */
+                /* so the above unsigned comparison effectively guarantees casting pkt_len */
+                /* to a signed value does not result in it going negative. */
+                u8 ip_ofs;
+                u8 csum_ofs;
+                u8 csum_start = 0;
+                u16 partial_csum = 0;
+                Boolean udp = reg_num;
+                u32 pkt_len = ctx->mem.named.tx_buf_offset;
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
+                ASSERT_RETURN(ctx->tx_buf);
+                /* If pkt_len > allocate_buffer_len, it means sth. wrong */
+                /* happened and the tx_buf should be deallocated. */
+                if (pkt_len > ctx->tx_buf_len) {
+                    do_discard_buffer(ctx);
+                    return EXCEPTION;
+                }
+                {
+                    int dscp = apf_internal_csum_and_return_dscp(ctx->tx_buf, (s32)pkt_len, ip_ofs,
+                                                    partial_csum, csum_start, csum_ofs, udp);
+                    int ret = apf_internal_do_transmit_buffer(ctx, pkt_len, dscp);
+                    if (ret) { counter[-4]++; return EXCEPTION; } /* transmit failure */
+                }
+                break;
+              }
+              case EPKTDATACOPYIMM_EXT_OPCODE:  /* 41 */
+              case EPKTDATACOPYR1_EXT_OPCODE:   /* 42 */
+                pktcopy_src_offset = ctx->R[0];
+                FALLTHROUGH;
+              case PKTDATACOPYIMM_EXT_OPCODE: { /* 65536 */
+                u32 dst_offs = ctx->mem.named.tx_buf_offset;
+                u32 copy_len = ctx->R[1];
+                if (imm != EPKTDATACOPYR1_EXT_OPCODE) {
+                    copy_len = DECODE_U8();  /* 2nd imm, at worst 8 bytes past prog_len */
+                    if (!copy_len) copy_len = 256 + DECODE_U8(); /* at worst 9 bytes past prog_len */
+                }
+                ASSERT_RETURN(ctx->tx_buf);
+                ASSERT_IN_OUTPUT_BOUNDS(dst_offs, copy_len);
+                if (reg_num == 0) {  /* copy from packet */
+                    const u32 last_packet_offs = pktcopy_src_offset + copy_len - 1;
+                    ASSERT_IN_PACKET_BOUNDS(pktcopy_src_offset);
+                    ASSERT_RETURN(last_packet_offs >= pktcopy_src_offset);
+                    ASSERT_IN_PACKET_BOUNDS(last_packet_offs);
+                    memcpy(ctx->tx_buf + dst_offs, ctx->packet + pktcopy_src_offset, copy_len);
+                } else {  /* copy from data */
+                    ASSERT_IN_RAM_BOUNDS(pktcopy_src_offset + copy_len - 1);
+                    memcpy(ctx->tx_buf + dst_offs, ctx->program + pktcopy_src_offset, copy_len);
+                }
+                dst_offs += copy_len;
+                ctx->mem.named.tx_buf_offset = dst_offs;
+                break;
+              }
+              case JDNSQMATCH_EXT_OPCODE:        /* 43 - 43 =  0 = 0b0000, u8 */
+              case JDNSAMATCH_EXT_OPCODE:        /* 44 - 43 =  1 = 0b0001, */
+              case JDNSQMATCHSAFE_EXT_OPCODE:    /* 45 - 43 =  2 = 0b0010, u8 */
+              case JDNSAMATCHSAFE_EXT_OPCODE:    /* 46 - 43 =  3 = 0b0011, */
+              case JDNSQMATCH2_EXT_OPCODE:       /* 51 - 43 =  8 = 0b1000, u8 u8 */
+              case JDNSQMATCHSAFE2_EXT_OPCODE:   /* 53 - 43 = 10 = 0b1010, u8 u8 */
+              case JDNSQMATCH1_EXT_OPCODE:       /* 55 - 43 = 12 = 0b1100, u16 */
+              case JDNSQMATCHSAFE1_EXT_OPCODE: { /* 57 - 43 = 14 = 0b1110, u16 */
+                u32 jump_offs = decode_imm(ctx, imm_len); /* 2nd imm, at worst 8 B past prog_len */
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
+                }
+                /* bit 2 set means we need to join the two u8s into a be16 */
+                if (imm & 4) qtype2 = qtype1 = (qtype1 << 8) | qtype2;
+                {
+                    u32 udp_payload_offset = ctx->R[0];
+                    match_result_type match_rst = apf_internal_match_names(ctx->program + ctx->pc,
+                                                              ctx->program + ctx->program_len,
+                                                              ctx->packet + udp_payload_offset,
+                                                              ctx->packet_len - udp_payload_offset,
+                                                              qtype1,
+                                                              qtype2);
+                    if (match_rst == error_program) return EXCEPTION;
+                    if (match_rst == error_packet) {
+                        counter[-5]++; /* increment error dns packet counter */
+                        return (imm & 2) ? PASS : DROP;  /* imm & 2 detects SAFE opcodes */
+                    }
+                    while (ctx->pc + 1 < ctx->program_len &&
+                           (ctx->program[ctx->pc] || ctx->program[ctx->pc + 1])) {
+                        ctx->pc++;
+                    }
+                    ctx->pc += 2;  /* skip the final double 0 needle end */
+                    /* relies on reg_num in {0,1} and match_rst being {False=0, True=1} */
+                    if (!(reg_num ^ (u32)match_rst)) ctx->pc += jump_offs;
+                }
+                break;
+              }
+              case EWRITE1_EXT_OPCODE:
+              case EWRITE2_EXT_OPCODE:
+              case EWRITE4_EXT_OPCODE: {
+                const u32 write_len = 1 << (imm - EWRITE1_EXT_OPCODE);
+                u32 i;
+                ASSERT_RETURN(ctx->tx_buf);
+                ASSERT_IN_OUTPUT_BOUNDS(ctx->mem.named.tx_buf_offset, write_len);
+                for (i = 0; i < write_len; ++i) {
+                    ctx->tx_buf[ctx->mem.named.tx_buf_offset++] =
+                        (u8)(REG >> (write_len - 1 - i) * 8);
+                }
+                break;
+              }
+              case JONEOF_EXT_OPCODE: {
+                u32 jump_offs = decode_imm(ctx, imm_len); /* 2nd imm, at worst 8 B past prog_len */
+                u8 imm3 = DECODE_U8();  /* 3rd imm, at worst 9 bytes past prog_len */
+                Boolean jmp = imm3 & 1;  /* =0 jmp on match, =1 jmp on no match */
+                u8 len = ((imm3 >> 1) & 3) + 1;  /* size [1..4] in bytes of an element */
+                u8 cnt = (imm3 >> 3) + 2;  /* number [2..33] of elements in set */
+                if (ctx->pc + cnt * len > ctx->program_len) return EXCEPTION;
+                /* cnt underflow on final iteration not an issue as not used after loop. */
+                while (cnt--) {
+                    u32 v = 0;
+                    int i;
+                    for (i = 0; i < len; ++i) v = (v << 8) | DECODE_U8();
+                    if (REG == v) jmp ^= True;
+                }
+                if (jmp) ctx->pc += jump_offs;
+                break;
+              }
+              case EXCEPTIONBUFFER_EXT_OPCODE: {
+                ctx->except_buf_sz = decode_be16(ctx);
+                break;
+              }
+              default:  /* Unknown extended opcode */
+                return EXCEPTION;  /* Bail out */
+            }
+            break;
+          case LDDW_OPCODE:
+          case STDW_OPCODE:
+            if (ctx->v6) {
+                if (!imm) return EXCEPTION;
+                if (imm > 0xFFFF) return EXCEPTION;
+                if (imm * 4 > ctx->ram_len) return EXCEPTION;
+                if (opcode == LDDW_OPCODE) {
+                    REG = counter[-(s32)imm];
+                } else {
+                    counter[-(s32)imm] = REG;
+                }
+            } else {
+                u32 size = 4;
+                u32 offs = OTHER_REG + (u32)signed_imm;
+                /* Negative offsets wrap around the end of the address space. */
+                /* This allows us to efficiently access the end of the */
+                /* address space with one-byte immediates without using %=. */
+                if (offs & 0x80000000) offs += ctx->ram_len;  /* unsigned overflow intended */
+                ASSERT_IN_DATA_BOUNDS(offs, size);
+                if (opcode == LDDW_OPCODE) {
+                    u32 val = 0;
+                    /* size underflow on final iteration not an issue as not used after loop. */
+                    while (size--) val = (val << 8) | ctx->program[offs++];
+                    REG = val;
+                } else {
+                    u32 val = REG;
+                    /* size underflow on final iteration not an issue as not used after loop. */
+                    while (size--) {
+                        ctx->program[offs++] = (val >> 24);
+                        val <<= 8;
+                    }
+                }
+            }
+            break;
+          case WRITE_OPCODE: {
+            ASSERT_RETURN(ctx->tx_buf);
+            ASSERT_RETURN(len_field);
+            {
+                const u32 write_len = 1 << (len_field - 1);
+                u32 i;
+                ASSERT_IN_OUTPUT_BOUNDS(ctx->mem.named.tx_buf_offset, write_len);
+                for (i = 0; i < write_len; ++i) {
+                    ctx->tx_buf[ctx->mem.named.tx_buf_offset++] =
+                        (u8)(imm >> (write_len - 1 - i) * 8);
+                }
+            }
+            break;
+          }
+          case ALLOC_XMIT_OPCODE:
+            if (reg_num) goto do_allocate; else goto do_transmit;
+            break;
+          default:  /* Unknown opcode */
+            return EXCEPTION;  /* Bail out */
+        }
+      }
+    /* instructions_remaining underflow on final iteration not an issue as not used after loop. */
+    } while (instructions_remaining--);
+    return EXCEPTION;
+}
+
+static int apf_runner(void* ctx, u32* const program, const u32 program_len,
+                      const u32 ram_len, const u8* const packet,
+                      const u32 packet_len, const u32 filter_age_16384ths) {
+    /* Due to direct 32-bit read/write access to counters at end of ram */
+    /* APFv6 interpreter requires program & ram_len to be 4 byte aligned. */
+    if (3 & (uintptr_t)program) return EXCEPTION;
+    if (3 & ram_len) return EXCEPTION;
+    if (ram_len < 1024) return EXCEPTION; /* due to JBSPTR */
+
+    /* We rely on ram_len + 65536 not overflowing, so require ram_len < 2GiB */
+    /* Similarly LDDW/STDW have special meaning for negative ram offsets. */
+    /* We also don't want garbage like program_len == 0xFFFFFFFF */
+    if ((program_len | ram_len) >> 31) return EXCEPTION;
+
+    {
+        apf_context apf_ctx = { 0 };
+        int ret;
+
+        apf_ctx.ptr_size = sizeof(void*);
+        apf_ctx.caller_ctx = ctx;
+        apf_ctx.program = (u8*)program;
+        apf_ctx.program_len = program_len;
+        apf_ctx.ram_len = ram_len;
+        apf_ctx.packet = packet;
+        apf_ctx.packet_len = packet_len;
+        /* Fill in pre-filled memory slot values. */
+        apf_ctx.mem.named.program_size = program_len;
+        apf_ctx.mem.named.ram_len = ram_len;
+        apf_ctx.mem.named.packet_size = packet_len;
+        apf_ctx.mem.named.apf_version = apf_version();
+        apf_ctx.mem.named.filter_age = filter_age_16384ths >> 14;
+        apf_ctx.mem.named.filter_age_16384ths = filter_age_16384ths;
+
+        ret = do_apf_run(&apf_ctx);
+        if (apf_ctx.tx_buf) do_discard_buffer(&apf_ctx);
+        /* Convert any exceptions internal to the program to just normal 'PASS' */
+        if (ret >= EXCEPTION) {
+            u16 buf_size = apf_ctx.except_buf_sz;
+            if (buf_size >= sizeof(apf_ctx) && apf_ctx.program_len + buf_size <= apf_ctx.ram_len) {
+                u8* buf = apf_ctx.program + apf_ctx.program_len;
+                memcpy(buf, &apf_ctx, sizeof(apf_ctx));
+                buf_size -= sizeof(apf_ctx);
+                buf += sizeof(apf_ctx);
+                if (buf_size > apf_ctx.packet_len) buf_size = apf_ctx.packet_len;
+                memcpy(buf, apf_ctx.packet, buf_size);
+            }
+            ret = PASS;
+        }
+        return ret;
+    }
+}
+
+int apf_run(void* ctx, u32* const program, const u32 program_len,
+            const u32 ram_len, const u8* const packet,
+            const u32 packet_len, const u32 filter_age_16384ths) {
+    /* Any valid ethernet packet should be at least ETH_HLEN long... */
+    if (!packet) return EXCEPTION;
+    if (packet_len < ETH_HLEN) return EXCEPTION;
+
+    return apf_runner(ctx, program, program_len, ram_len, packet, packet_len, filter_age_16384ths);
+}
diff --git a/v6.1/apf_interpreter.h b/v6.1/apf_interpreter.h
new file mode 100644
index 0000000..01408b5
--- /dev/null
+++ b/v6.1/apf_interpreter.h
@@ -0,0 +1,175 @@
+/*
+ * Copyright 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ * http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#ifndef APF_INTERPRETER_V61_H_
+#define APF_INTERPRETER_V61_H_
+
+#include <stdint.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+/**
+ * Returns the max version of the APF instruction set supported by apf_run().
+ * APFv6 is a superset of APFv4. APFv6 interpreters are able to run APFv4 code.
+ */
+uint32_t apf_version(void);
+
+/**
+ * Allocates a buffer for the APF program to build a reply packet.
+ *
+ * Unless in a critical low memory state, the firmware must allow allocating at
+ * least one 1514 byte buffer for every call to apf_run(). The interpreter will
+ * have at most one active allocation at any given time, and will always either
+ * transmit or deallocate the buffer before apf_run() returns.
+ *
+ * It is OK if the firmware decides to limit allocations to at most one per
+ * apf_run() invocation. This allows the firmware to delay transmitting
+ * the buffer until after apf_run() has returned (by keeping track of whether
+ * a buffer was allocated/deallocated/scheduled for transmit) and may
+ * allow the use of a single statically allocated 1514+ byte buffer.
+ *
+ * The firmware MAY choose to allocate a larger buffer than requested, and
+ * give the apf_interpreter a pointer to the middle of the buffer. This will
+ * allow firmware to later (during or after apf_transmit_buffer call) populate
+ * any required headers, trailers, etc.
+ *
+ * @param ctx - unmodified ctx pointer passed into apf_run().
+ * @param size - the minimum size of buffer to allocate
+ * @return the pointer to the allocated region. The function can return NULL to
+ *         indicate allocation failure, for example if too many buffers are
+ *         pending transmit. Returning NULL will most likely result in
+ *         apf_run() returning PASS.
+ */
+uint8_t* apf_allocate_buffer(void* ctx, uint32_t size);
+
+/**
+ * Transmits the allocated buffer and deallocates it.
+ *
+ * The apf_interpreter will not read/write from/to the buffer once it calls
+ * this function.
+ *
+ * The content of the buffer between [ptr, ptr + len) are the bytes to be
+ * transmitted, starting from the ethernet header and not including any
+ * ethernet CRC bytes at the end.
+ *
+ * The firmware is expected to make its best effort to transmit. If it
+ * exhausts retries, or if there is no channel for too long and the transmit
+ * queue is full, then it is OK for the packet to be dropped. The firmware should
+ * prefer to fail allocation if it can predict transmit will fail.
+ *
+ * apf_transmit_buffer() may be asynchronous, which means the actual packet
+ * transmission can happen sometime after the function returns.
+ *
+ * @param ctx - unmodified ctx pointer passed into apf_run().
+ * @param ptr - pointer to the transmit buffer, must have been previously
+ *              returned by apf_allocate_buffer() and not deallocated.
+ * @param len - the number of bytes to be transmitted (possibly less than
+ *              the allocated buffer), 0 means don't transmit the buffer
+ *              but only deallocate it.
+ * @param dscp - value in [0..63] - the upper 6 bits of the TOS field in
+ *               the IPv4 header or traffic class field in the IPv6 header.
+ * @return non-zero if the firmware *knows* the transmit will fail, zero if
+ *         the transmit succeeded or the firmware thinks it will succeed.
+ *         Returning an error will likely result in apf_run() returning PASS.
+ */
+int apf_transmit_buffer(void* ctx, uint8_t* ptr, uint32_t len, uint8_t dscp);
+
+/**
+ * Runs an APF program over a packet.
+ *
+ * The return value of apf_run indicates whether the packet should
+ * be passed or dropped. As a part of apf_run() execution, the APF
+ * program can call apf_allocate_buffer()/apf_transmit_buffer() to construct
+ * a reply packet and transmit it.
+ *
+ * The text section containing the program instructions starts at address
+ * program and stops at + program_len - 1, and the writable data section
+ * begins at program + program_len and ends at program + ram_len - 1,
+ * as described in the following diagram:
+ *
+ *     program         program + program_len    program + ram_len
+ *        |    text section    |      data section      |
+ *        +--------------------+------------------------+
+ *
+ * @param ctx - pointer to any additional context required for allocation and transmit.
+ *              May be NULL if no such context is required. This is opaque to
+ *              the interpreter and will be passed through unmodified
+ *              to apf_allocate_buffer() and apf_transmit_buffer() calls.
+ * @param program - the program bytecode, followed by the writable data region.
+ *                  Note: this *MUST* be a 4 byte aligned region.
+ * @param program_len - the length in bytes of the read-only portion of the APF
+ *                    buffer pointed to by {@code program}.
+ *                    This is determined by the size of the loaded APF program.
+ * @param ram_len - total length of the APF buffer pointed to by
+ *                  {@code program}, including the read-only bytecode
+ *                  portion and the read-write data portion.
+ *                  This is expected to be a constant which doesn't change
+ *                  value even when a new APF program is loaded.
+ *                  Note: this *MUST* be a multiple of 4.
+ * @param packet - the packet bytes, starting from the ethernet header.
+ * @param packet_len - the length of {@code packet} in bytes, not
+ *                     including trailers/CRC.
+ * @param filter_age_16384ths - the number of 1/16384 seconds since the filter
+ *                     was programmed.
+ *
+ * @return zero if packet should be dropped,
+ *         non-zero if packet should be passed, specifically:
+ *         - 1 on normal apf program execution,
+ *         - 2 on exceptional circumstances (caused by bad firmware integration),
+ *           these include:
+ *             - program pointer which is not aligned to 4 bytes
+ *             - ram_len which is not a multiple of 4 bytes
+ *             - excessively large (>= 2GiB) program_len or ram_len
+ *             - packet pointer which is a null pointer
+ *             - packet_len shorter than ETH_HLEN (14)
+ *           As such, you may want to log a firmware exception if 2 is ever returned...
+ *
+ *
+ * NOTE: How to calculate filter_age_16384ths:
+ *
+ * - if you have a u64 clock source counting nanoseconds:
+ *     u64 nanoseconds = current_nanosecond_time_u64() - filter_installation_nanosecond_time_u64;
+ *     u32 filter_age_16384ths = (u32)((nanoseconds << 5) / 1953125);
+ *
+ * - if you have a u64 clock source counting microseconds:
+ *     u64 microseconds = current_microsecond_time_u64() - filter_installation_microsecond_time_u64;
+ *     u32 filter_age_16384ths = (u32)((microseconds << 8) / 15625);
+ *
+ * - if you have a u64 clock source counting milliseconds:
+ *     u64 milliseconds = current_millisecond_time_u64() - filter_installation_millisecond_time_u64;
+ *     u32 filter_age_16384ths = (u32)((milliseconds << 11) / 125);
+ *
+ * - if you have a u32 clock source counting milliseconds and cannot use 64-bit arithmetic:
+ *     u32 milliseconds = current_millisecond_time_u32() - filter_installation_millisecond_time_u32;
+ *     u32 filter_age_16384ths = ((((((milliseconds << 4) / 5) << 2) / 5) << 2) / 5) << 3;
+ *   or the less precise:
+ *     u32 filter_age_16384ths = ((milliseconds << 4) / 125) << 7;
+ *
+ * - if you have a u32 clock source counting seconds:
+ *     u32 seconds = current_second_time_u32() - filter_installation_second_time_u32;
+ *     u32 filter_age_16384ths = seconds << 14;
+ */
+int apf_run(void* ctx, uint32_t* const program, const uint32_t program_len,
+            const uint32_t ram_len, const uint8_t* const packet,
+            const uint32_t packet_len, const uint32_t filter_age_16384ths);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif  /* APF_INTERPRETER_V61_H_ */
diff --git a/v6/Android.bp b/v6/Android.bp
deleted file mode 100644
index 405ddef..0000000
--- a/v6/Android.bp
+++ /dev/null
@@ -1,49 +0,0 @@
-//
-// Copyright (C) 2025 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-//
-
-package {
-    default_applicable_licenses: ["hardware_google_apf_license"],
-}
-
-cc_defaults {
-    name: "apfv6_defaults",
-
-    cflags: [
-        "-Wall",
-        "-Werror",
-        "-Werror=implicit-fallthrough",
-        "-Werror=missing-prototypes",
-        "-Werror=strict-prototypes",
-        "-Wnullable-to-nonnull-conversion",
-        "-Wsign-compare",
-        "-Wsign-conversion",
-        "-Wthread-safety",
-        "-Wunused-parameter",
-        "-Wuninitialized",
-    ],
-}
-
-cc_library_static {
-    name: "libapf_v6",
-    defaults: ["apfv6_defaults"],
-    static_libs: [
-        "libapfbuf",
-    ],
-    srcs: [
-        "apf_interpreter.c",
-    ],
-    sdk_version: "24",
-}
```

