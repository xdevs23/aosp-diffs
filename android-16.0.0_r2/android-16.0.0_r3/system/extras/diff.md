```diff
diff --git a/bootctl/bootctl.cpp b/bootctl/bootctl.cpp
index 1bf91815..d8f0001a 100644
--- a/bootctl/bootctl.cpp
+++ b/bootctl/bootctl.cpp
@@ -29,7 +29,7 @@ using android::hal::BootControlClient;
 using android::hal::BootControlVersion;
 using android::hal::CommandResult;
 
-static void usage(FILE* where, BootControlVersion bootVersion, int /* argc */, char* argv[]) {
+static void usage(FILE* where, int /* argc */, char* argv[]) {
     fprintf(where,
             "%s - command-line wrapper for the boot HAL.\n"
             "\n"
@@ -46,16 +46,13 @@ static void usage(FILE* where, BootControlVersion bootVersion, int /* argc */, c
             "  set-slot-as-unbootable SLOT    - Mark SLOT as invalid.\n"
             "  is-slot-bootable SLOT          - Returns 0 only if SLOT is bootable.\n"
             "  is-slot-marked-successful SLOT - Returns 0 only if SLOT is marked GOOD.\n"
-            "  get-suffix SLOT                - Prints suffix for SLOT.\n",
+            "  get-suffix SLOT                - Prints suffix for SLOT.\n"
+            "  set-snapshot-merge-status STAT - Sets whether a snapshot-merge of any dynamic\n"
+            "                                   partition is in progress. Valid STAT values\n"
+            "                                   are: none, unknown, snapshotted, merging,\n"
+            "                                   or cancelled.\n"
+            "  get-snapshot-merge-status      - Prints the current snapshot-merge status.\n",
             argv[0], argv[0]);
-    if (bootVersion >= BootControlVersion::BOOTCTL_V1_1) {
-        fprintf(where,
-                "  set-snapshot-merge-status STAT - Sets whether a snapshot-merge of any dynamic\n"
-                "                                   partition is in progress. Valid STAT values\n"
-                "                                   are: none, unknown, snapshotted, merging,\n"
-                "                                   or cancelled.\n"
-                "  get-snapshot-merge-status      - Prints the current snapshot-merge status.\n");
-    }
     fprintf(where,
             "\n"
             "SLOT parameter is the zero-based slot-number.\n");
@@ -63,10 +60,6 @@ static void usage(FILE* where, BootControlVersion bootVersion, int /* argc */, c
 
 static constexpr auto ToString(BootControlVersion ver) {
     switch (ver) {
-        case BootControlVersion::BOOTCTL_V1_0:
-            return "android.hardware.boot@1.0::IBootControl";
-        case BootControlVersion::BOOTCTL_V1_1:
-            return "android.hardware.boot@1.1::IBootControl";
         case BootControlVersion::BOOTCTL_V1_2:
             return "android.hardware.boot@1.2::IBootControl";
         case BootControlVersion::BOOTCTL_AIDL:
@@ -155,17 +148,16 @@ std::optional<MergeStatus> stringToMergeStatus(const std::string& status) {
     return {};
 }
 
-static int do_set_snapshot_merge_status(BootControlClient* module, BootControlVersion bootVersion,
-                                        int argc, char* argv[]) {
+static int do_set_snapshot_merge_status(BootControlClient* module, int argc, char* argv[]) {
     if (argc != 3) {
-        usage(stderr, bootVersion, argc, argv);
+        usage(stderr, argc, argv);
         exit(EX_USAGE);
         return -1;
     }
 
     auto status = stringToMergeStatus(argv[2]);
     if (!status.has_value()) {
-        usage(stderr, bootVersion, argc, argv);
+        usage(stderr, argc, argv);
         exit(EX_USAGE);
         return -1;
     }
@@ -209,16 +201,16 @@ static int do_get_suffix(BootControlClient* module, int32_t slot_number) {
     return EX_OK;
 }
 
-static uint32_t parse_slot(BootControlVersion bootVersion, int pos, int argc, char* argv[]) {
+static uint32_t parse_slot(int pos, int argc, char* argv[]) {
     if (pos > argc - 1) {
-        usage(stderr, bootVersion, argc, argv);
+        usage(stderr, argc, argv);
         exit(EX_USAGE);
         return -1;
     }
     errno = 0;
     uint64_t ret = strtoul(argv[pos], NULL, 10);
     if (errno != 0 || ret > UINT_MAX) {
-        usage(stderr, bootVersion, argc, argv);
+        usage(stderr, argc, argv);
         exit(EX_USAGE);
         return -1;
     }
@@ -234,7 +226,7 @@ int main(int argc, char* argv[]) {
     const auto bootVersion = client->GetVersion();
 
     if (argc < 2) {
-        usage(stderr, bootVersion, argc, argv);
+        usage(stderr, argc, argv);
         return EX_USAGE;
     }
 
@@ -248,41 +240,24 @@ int main(int argc, char* argv[]) {
     } else if (strcmp(argv[1], "mark-boot-successful") == 0) {
         return do_mark_boot_successful(client.get());
     } else if (strcmp(argv[1], "set-active-boot-slot") == 0) {
-        return do_set_active_boot_slot(client.get(), parse_slot(bootVersion, 2, argc, argv));
+        return do_set_active_boot_slot(client.get(), parse_slot(2, argc, argv));
     } else if (strcmp(argv[1], "set-slot-as-unbootable") == 0) {
-        return do_set_slot_as_unbootable(client.get(), parse_slot(bootVersion, 2, argc, argv));
+        return do_set_slot_as_unbootable(client.get(), parse_slot(2, argc, argv));
     } else if (strcmp(argv[1], "is-slot-bootable") == 0) {
-        return do_is_slot_bootable(client.get(), parse_slot(bootVersion, 2, argc, argv));
+        return do_is_slot_bootable(client.get(), parse_slot(2, argc, argv));
     } else if (strcmp(argv[1], "is-slot-marked-successful") == 0) {
-        return do_is_slot_marked_successful(client.get(), parse_slot(bootVersion, 2, argc, argv));
+        return do_is_slot_marked_successful(client.get(), parse_slot(2, argc, argv));
     } else if (strcmp(argv[1], "get-suffix") == 0) {
-        return do_get_suffix(client.get(), parse_slot(bootVersion, 2, argc, argv));
-    }
-
-    // Functions present from version 1.1
-    if (strcmp(argv[1], "set-snapshot-merge-status") == 0 ||
-        strcmp(argv[1], "get-snapshot-merge-status") == 0) {
-        if (bootVersion < BootControlVersion::BOOTCTL_V1_1) {
-            fprintf(stderr, "Error getting bootctrl v1.1 module.\n");
-            return EX_SOFTWARE;
-        }
-        if (strcmp(argv[1], "set-snapshot-merge-status") == 0) {
-            return do_set_snapshot_merge_status(client.get(), bootVersion, argc, argv);
-        } else if (strcmp(argv[1], "get-snapshot-merge-status") == 0) {
-            return do_get_snapshot_merge_status(client.get());
-        }
-    }
-
-    if (strcmp(argv[1], "get-active-boot-slot") == 0) {
-        if (bootVersion < BootControlVersion::BOOTCTL_V1_2) {
-            fprintf(stderr, "Error getting bootctrl v1.2 module.\n");
-            return EX_SOFTWARE;
-        }
-
+        return do_get_suffix(client.get(), parse_slot(2, argc, argv));
+    } else if (strcmp(argv[1], "set-snapshot-merge-status") == 0) {
+        return do_set_snapshot_merge_status(client.get(), argc, argv);
+    } else if (strcmp(argv[1], "get-snapshot-merge-status") == 0) {
+        return do_get_snapshot_merge_status(client.get());
+    } else if (strcmp(argv[1], "get-active-boot-slot") == 0) {
         return do_get_active_boot_slot(client.get());
     }
 
     // Parameter not matched, print usage
-    usage(stderr, bootVersion, argc, argv);
+    usage(stderr, argc, argv);
     return EX_USAGE;
 }
diff --git a/boottime_tools/bootanalyze/bootanalyze.py b/boottime_tools/bootanalyze/bootanalyze.py
index 5bdcb546..e13ec5d0 100755
--- a/boottime_tools/bootanalyze/bootanalyze.py
+++ b/boottime_tools/bootanalyze/bootanalyze.py
@@ -90,7 +90,8 @@ def main():
   cfg = yaml.load(args.config, Loader=yaml.SafeLoader)
 
   if args.stressfs:
-    if run_adb_cmd('install -r -g ' + args.stressfs) != 0:
+    _, err = run_adb_cmd('install -r -g ' + args.stressfs)
+    if err != 0:
       raise Exception('StressFS APK not installed')
 
   if args.iterate > 1 and args.bootchart:
@@ -879,24 +880,32 @@ def reboot(serial, use_stressfs, permissive, use_adb_reboot, adb_buffersize=None
 
   if adb_buffersize is not None:
     # increase the buffer size
-    if run_adb_cmd('logcat -G {}'.format(adb_buffersize)) != 0:
+    _, err = run_adb_cmd('logcat -G {}'.format(adb_buffersize))
+    if err != 0:
       debug('Fail to set logcat buffer size as {}'.format(adb_buffersize))
 
-'''
-Runs adb command. If do_return_result is true then output of command is
-returned otherwise an empty string is returned.
-'''
-def run_adb_cmd(cmd, do_return_result=False):
-  if do_return_result:
-    return subprocess.check_output(ADB_CMD + ' ' + cmd, shell=True).decode('utf-8', 'ignore').strip()
-  subprocess.call(ADB_CMD + ' ' + cmd, shell=True)
-  return ""
-
-def run_adb_shell_cmd(cmd, do_return_result=False):
-  return run_adb_cmd('shell ' + cmd, do_return_result)
-
-def run_adb_shell_cmd_as_root(cmd, do_return_result=False):
-  return run_adb_shell_cmd('su root ' + cmd, do_return_result)
+def run_adb_cmd(cmd):
+  """Runs adb command and returns its result.
+
+  Args:
+    cmd: the command to be run
+
+  Returns:
+    A tuple with the output of the command and the return code (zero if
+    successful).
+  """
+  try:
+    result = subprocess.check_output(ADB_CMD + ' ' + cmd, shell=True).decode(
+        'utf-8', 'ignore').strip()
+    return result, 0
+  except subprocess.CalledProcessError as err:
+    return err.output, err.returncode
+
+def run_adb_shell_cmd(cmd):
+  return run_adb_cmd('shell ' + cmd)
+
+def run_adb_shell_cmd_as_root(cmd):
+  return run_adb_shell_cmd('su root ' + cmd)
 
 def logcat_time_func(offset_year):
   def f(date_str):
diff --git a/libfec/fec_open.cpp b/libfec/fec_open.cpp
index 6825942b..e3c7eeab 100644
--- a/libfec/fec_open.cpp
+++ b/libfec/fec_open.cpp
@@ -48,7 +48,7 @@ static int find_offset(uint64_t file_size, int roots, uint64_t *offset,
 
     if (file_size % FEC_BLOCKSIZE) {
         /* must be a multiple of block size */
-        error("file size not multiple of " stringify(FEC_BLOCKSIZE));
+        error("file size not multiple of " STRINGIFY(FEC_BLOCKSIZE));
         errno = EINVAL;
         return -1;
     }
diff --git a/libfec/fec_private.h b/libfec/fec_private.h
index 0c633223..445f5cf1 100644
--- a/libfec/fec_private.h
+++ b/libfec/fec_private.h
@@ -29,6 +29,7 @@
 #include <string>
 #include <vector>
 
+#include <android-base/stringify.h>
 #include <android-base/threads.h>
 #include <crypto_utils/android_pubkey.h>
 #include <fec/ecc.h>
@@ -173,11 +174,6 @@ extern int verity_parse_header(fec_handle *f, uint64_t offset);
     #define likely(x)   __builtin_expect(!!(x), 1)
 #endif
 
-#ifndef stringify
-    #define __stringify(x) #x
-    #define stringify(x) __stringify(x)
-#endif
-
 /*  warnings, errors, debug output */
 #ifdef FEC_NO_KLOG
     #define __log(func, type, format, args...) \
diff --git a/libfec/fec_verity.cpp b/libfec/fec_verity.cpp
index 45c197ff..8d208c06 100644
--- a/libfec/fec_verity.cpp
+++ b/libfec/fec_verity.cpp
@@ -373,7 +373,7 @@ static int parse_table(fec_handle *f, uint64_t offset, uint32_t size, bool useec
     for (const auto& token : tokens) {
         switch (i++) {
         case 0: /* version */
-            if (token != stringify(VERITY_TABLE_VERSION)) {
+            if (token != STRINGIFY(VERITY_TABLE_VERSION)) {
                 error("unsupported verity table version: %s", token.c_str());
                 return -1;
             }
@@ -381,7 +381,7 @@ static int parse_table(fec_handle *f, uint64_t offset, uint32_t size, bool useec
         case 3: /* data_block_size */
         case 4: /* hash_block_size */
             /* assume 4 KiB block sizes for everything */
-            if (token != stringify(FEC_BLOCKSIZE)) {
+            if (token != STRINGIFY(FEC_BLOCKSIZE)) {
                 error("unsupported verity block size: %s", token.c_str());
                 return -1;
             }
@@ -436,7 +436,7 @@ static int parse_table(fec_handle *f, uint64_t offset, uint32_t size, bool useec
 
     if (i < VERITY_TABLE_ARGS) {
         error("not enough arguments in verity table: %d; expected at least "
-            stringify(VERITY_TABLE_ARGS), i);
+            STRINGIFY(VERITY_TABLE_ARGS), i);
         return -1;
     }
 
@@ -512,8 +512,8 @@ static int validate_header(const fec_handle *f, const verity_header *header,
     if (header->length < VERITY_MIN_TABLE_SIZE ||
         header->length > VERITY_MAX_TABLE_SIZE) {
         error("invalid verity table size: %u; expected ["
-            stringify(VERITY_MIN_TABLE_SIZE) ", "
-            stringify(VERITY_MAX_TABLE_SIZE) ")", header->length);
+            STRINGIFY(VERITY_MIN_TABLE_SIZE) ", "
+            STRINGIFY(VERITY_MAX_TABLE_SIZE) ")", header->length);
         return -1;
     }
 
diff --git a/memory_replay/Pointers.cpp b/memory_replay/Pointers.cpp
index b04b9310..4a3498c4 100644
--- a/memory_replay/Pointers.cpp
+++ b/memory_replay/Pointers.cpp
@@ -16,7 +16,6 @@
 
 #include <err.h>
 #include <inttypes.h>
-#include <stdatomic.h>
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
@@ -54,7 +53,7 @@ void Pointers::Add(uintptr_t key_pointer, void* pointer) {
   if (data == nullptr) {
     errx(1, "No empty entry found for 0x%" PRIxPTR, key_pointer);
   }
-  atomic_store(&data->key_pointer, key_pointer);
+  data->key_pointer.store(key_pointer);
   data->pointer = pointer;
 }
 
@@ -69,7 +68,7 @@ void* Pointers::Remove(uintptr_t key_pointer) {
   }
 
   void* pointer = data->pointer;
-  atomic_store(&data->key_pointer, uintptr_t(0));
+  data->key_pointer.store(uintptr_t(0));
 
   return pointer;
 }
@@ -77,7 +76,7 @@ void* Pointers::Remove(uintptr_t key_pointer) {
 Pointers::pointer_data* Pointers::Find(uintptr_t key_pointer) {
   size_t index = GetHash(key_pointer);
   for (size_t entries = max_pointers_; entries != 0; entries--) {
-    if (atomic_load(&pointers_[index].key_pointer) == key_pointer) {
+    if (pointers_[index].key_pointer.load() == key_pointer) {
       return pointers_ + index;
     }
     if (++index == max_pointers_) {
@@ -91,8 +90,7 @@ Pointers::pointer_data* Pointers::FindEmpty(uintptr_t key_pointer) {
   size_t index = GetHash(key_pointer);
   for (size_t entries = 0; entries < max_pointers_; entries++) {
     uintptr_t empty = 0;
-    if (atomic_compare_exchange_strong(&pointers_[index].key_pointer, &empty,
-        uintptr_t(1))) {
+    if (pointers_[index].key_pointer.compare_exchange_strong(empty, uintptr_t(1))) {
       return pointers_ + index;
     }
     if (++index == max_pointers_) {
@@ -108,7 +106,7 @@ size_t Pointers::GetHash(uintptr_t key_pointer) {
 
 void Pointers::FreeAll() {
   for (size_t i = 0; i < max_pointers_; i++) {
-    if (atomic_load(&pointers_[i].key_pointer) != 0) {
+    if (pointers_[i].key_pointer.load() != 0) {
       free(pointers_[i].pointer);
     }
   }
diff --git a/memory_replay/Pointers.h b/memory_replay/Pointers.h
index 040027bf..d0398e19 100644
--- a/memory_replay/Pointers.h
+++ b/memory_replay/Pointers.h
@@ -16,9 +16,10 @@
 
 #pragma once
 
-#include <stdatomic.h>
 #include <stdint.h>
 
+#include <atomic>
+
 class Pointers {
  public:
   struct pointer_data {
diff --git a/partition_tools/lpmake.cc b/partition_tools/lpmake.cc
index d7085222..83d980dd 100644
--- a/partition_tools/lpmake.cc
+++ b/partition_tools/lpmake.cc
@@ -248,7 +248,6 @@ int main(int argc, char* argv[]) {
     std::map<std::string, std::string> images;
     bool output_sparse = false;
     bool has_implied_super = false;
-    bool auto_slot_suffixing = false;
     bool force_full_image = false;
     bool virtual_ab = false;
     bool auto_blockdevice_size = false;
@@ -364,8 +363,8 @@ int main(int argc, char* argv[]) {
                 break;
             }
             case Option::kAutoSlotSuffixing:
-                auto_slot_suffixing = true;
-                break;
+                fprintf(stderr, "Auto slot suffixing is no longer supported.\n");
+                return EX_USAGE;
             case Option::kForceFullImage:
                 force_full_image = true;
                 break;
@@ -435,9 +434,6 @@ int main(int argc, char* argv[]) {
         return EX_USAGE;
     }
 
-    if (auto_slot_suffixing) {
-        builder->SetAutoSlotSuffixing();
-    }
     if (virtual_ab) {
         builder->SetVirtualABDeviceFlag();
     }
diff --git a/showslab/Android.bp b/showslab/Android.bp
deleted file mode 100644
index 27a71c43..00000000
--- a/showslab/Android.bp
+++ /dev/null
@@ -1,28 +0,0 @@
-// Copyright 2007 The Android Open Source Project
-
-package {
-    default_applicable_licenses: ["system_extras_showslab_license"],
-}
-
-// Added automatically by a large-scale-change
-// See: http://go/android-license-faq
-license {
-    name: "system_extras_showslab_license",
-    visibility: [":__subpackages__"],
-    license_kinds: [
-        "SPDX-license-identifier-Apache-2.0",
-    ],
-    license_text: [
-        "NOTICE",
-    ],
-}
-
-cc_binary {
-    name: "showslab",
-
-    srcs: ["showslab.c"],
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
-}
diff --git a/showslab/MODULE_LICENSE_APACHE2 b/showslab/MODULE_LICENSE_APACHE2
deleted file mode 100644
index e69de29b..00000000
diff --git a/showslab/NOTICE b/showslab/NOTICE
deleted file mode 100644
index c5b1efa7..00000000
--- a/showslab/NOTICE
+++ /dev/null
@@ -1,190 +0,0 @@
-
-   Copyright (c) 2005-2008, The Android Open Source Project
-
-   Licensed under the Apache License, Version 2.0 (the "License");
-   you may not use this file except in compliance with the License.
-
-   Unless required by applicable law or agreed to in writing, software
-   distributed under the License is distributed on an "AS IS" BASIS,
-   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-   See the License for the specific language governing permissions and
-   limitations under the License.
-
-
-                                 Apache License
-                           Version 2.0, January 2004
-                        http://www.apache.org/licenses/
-
-   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION
-
-   1. Definitions.
-
-      "License" shall mean the terms and conditions for use, reproduction,
-      and distribution as defined by Sections 1 through 9 of this document.
-
-      "Licensor" shall mean the copyright owner or entity authorized by
-      the copyright owner that is granting the License.
-
-      "Legal Entity" shall mean the union of the acting entity and all
-      other entities that control, are controlled by, or are under common
-      control with that entity. For the purposes of this definition,
-      "control" means (i) the power, direct or indirect, to cause the
-      direction or management of such entity, whether by contract or
-      otherwise, or (ii) ownership of fifty percent (50%) or more of the
-      outstanding shares, or (iii) beneficial ownership of such entity.
-
-      "You" (or "Your") shall mean an individual or Legal Entity
-      exercising permissions granted by this License.
-
-      "Source" form shall mean the preferred form for making modifications,
-      including but not limited to software source code, documentation
-      source, and configuration files.
-
-      "Object" form shall mean any form resulting from mechanical
-      transformation or translation of a Source form, including but
-      not limited to compiled object code, generated documentation,
-      and conversions to other media types.
-
-      "Work" shall mean the work of authorship, whether in Source or
-      Object form, made available under the License, as indicated by a
-      copyright notice that is included in or attached to the work
-      (an example is provided in the Appendix below).
-
-      "Derivative Works" shall mean any work, whether in Source or Object
-      form, that is based on (or derived from) the Work and for which the
-      editorial revisions, annotations, elaborations, or other modifications
-      represent, as a whole, an original work of authorship. For the purposes
-      of this License, Derivative Works shall not include works that remain
-      separable from, or merely link (or bind by name) to the interfaces of,
-      the Work and Derivative Works thereof.
-
-      "Contribution" shall mean any work of authorship, including
-      the original version of the Work and any modifications or additions
-      to that Work or Derivative Works thereof, that is intentionally
-      submitted to Licensor for inclusion in the Work by the copyright owner
-      or by an individual or Legal Entity authorized to submit on behalf of
-      the copyright owner. For the purposes of this definition, "submitted"
-      means any form of electronic, verbal, or written communication sent
-      to the Licensor or its representatives, including but not limited to
-      communication on electronic mailing lists, source code control systems,
-      and issue tracking systems that are managed by, or on behalf of, the
-      Licensor for the purpose of discussing and improving the Work, but
-      excluding communication that is conspicuously marked or otherwise
-      designated in writing by the copyright owner as "Not a Contribution."
-
-      "Contributor" shall mean Licensor and any individual or Legal Entity
-      on behalf of whom a Contribution has been received by Licensor and
-      subsequently incorporated within the Work.
-
-   2. Grant of Copyright License. Subject to the terms and conditions of
-      this License, each Contributor hereby grants to You a perpetual,
-      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
-      copyright license to reproduce, prepare Derivative Works of,
-      publicly display, publicly perform, sublicense, and distribute the
-      Work and such Derivative Works in Source or Object form.
-
-   3. Grant of Patent License. Subject to the terms and conditions of
-      this License, each Contributor hereby grants to You a perpetual,
-      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
-      (except as stated in this section) patent license to make, have made,
-      use, offer to sell, sell, import, and otherwise transfer the Work,
-      where such license applies only to those patent claims licensable
-      by such Contributor that are necessarily infringed by their
-      Contribution(s) alone or by combination of their Contribution(s)
-      with the Work to which such Contribution(s) was submitted. If You
-      institute patent litigation against any entity (including a
-      cross-claim or counterclaim in a lawsuit) alleging that the Work
-      or a Contribution incorporated within the Work constitutes direct
-      or contributory patent infringement, then any patent licenses
-      granted to You under this License for that Work shall terminate
-      as of the date such litigation is filed.
-
-   4. Redistribution. You may reproduce and distribute copies of the
-      Work or Derivative Works thereof in any medium, with or without
-      modifications, and in Source or Object form, provided that You
-      meet the following conditions:
-
-      (a) You must give any other recipients of the Work or
-          Derivative Works a copy of this License; and
-
-      (b) You must cause any modified files to carry prominent notices
-          stating that You changed the files; and
-
-      (c) You must retain, in the Source form of any Derivative Works
-          that You distribute, all copyright, patent, trademark, and
-          attribution notices from the Source form of the Work,
-          excluding those notices that do not pertain to any part of
-          the Derivative Works; and
-
-      (d) If the Work includes a "NOTICE" text file as part of its
-          distribution, then any Derivative Works that You distribute must
-          include a readable copy of the attribution notices contained
-          within such NOTICE file, excluding those notices that do not
-          pertain to any part of the Derivative Works, in at least one
-          of the following places: within a NOTICE text file distributed
-          as part of the Derivative Works; within the Source form or
-          documentation, if provided along with the Derivative Works; or,
-          within a display generated by the Derivative Works, if and
-          wherever such third-party notices normally appear. The contents
-          of the NOTICE file are for informational purposes only and
-          do not modify the License. You may add Your own attribution
-          notices within Derivative Works that You distribute, alongside
-          or as an addendum to the NOTICE text from the Work, provided
-          that such additional attribution notices cannot be construed
-          as modifying the License.
-
-      You may add Your own copyright statement to Your modifications and
-      may provide additional or different license terms and conditions
-      for use, reproduction, or distribution of Your modifications, or
-      for any such Derivative Works as a whole, provided Your use,
-      reproduction, and distribution of the Work otherwise complies with
-      the conditions stated in this License.
-
-   5. Submission of Contributions. Unless You explicitly state otherwise,
-      any Contribution intentionally submitted for inclusion in the Work
-      by You to the Licensor shall be under the terms and conditions of
-      this License, without any additional terms or conditions.
-      Notwithstanding the above, nothing herein shall supersede or modify
-      the terms of any separate license agreement you may have executed
-      with Licensor regarding such Contributions.
-
-   6. Trademarks. This License does not grant permission to use the trade
-      names, trademarks, service marks, or product names of the Licensor,
-      except as required for reasonable and customary use in describing the
-      origin of the Work and reproducing the content of the NOTICE file.
-
-   7. Disclaimer of Warranty. Unless required by applicable law or
-      agreed to in writing, Licensor provides the Work (and each
-      Contributor provides its Contributions) on an "AS IS" BASIS,
-      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
-      implied, including, without limitation, any warranties or conditions
-      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
-      PARTICULAR PURPOSE. You are solely responsible for determining the
-      appropriateness of using or redistributing the Work and assume any
-      risks associated with Your exercise of permissions under this License.
-
-   8. Limitation of Liability. In no event and under no legal theory,
-      whether in tort (including negligence), contract, or otherwise,
-      unless required by applicable law (such as deliberate and grossly
-      negligent acts) or agreed to in writing, shall any Contributor be
-      liable to You for damages, including any direct, indirect, special,
-      incidental, or consequential damages of any character arising as a
-      result of this License or out of the use or inability to use the
-      Work (including but not limited to damages for loss of goodwill,
-      work stoppage, computer failure or malfunction, or any and all
-      other commercial damages or losses), even if such Contributor
-      has been advised of the possibility of such damages.
-
-   9. Accepting Warranty or Additional Liability. While redistributing
-      the Work or Derivative Works thereof, You may choose to offer,
-      and charge a fee for, acceptance of support, warranty, indemnity,
-      or other liability obligations and/or rights consistent with this
-      License. However, in accepting such obligations, You may act only
-      on Your own behalf and on Your sole responsibility, not on behalf
-      of any other Contributor, and only if You agree to indemnify,
-      defend, and hold each Contributor harmless for any liability
-      incurred by, or claims asserted against, such Contributor by reason
-      of your accepting any such warranty or additional liability.
-
-   END OF TERMS AND CONDITIONS
-
diff --git a/showslab/showslab.c b/showslab/showslab.c
deleted file mode 100644
index 08acbf81..00000000
--- a/showslab/showslab.c
+++ /dev/null
@@ -1,351 +0,0 @@
-#include <stdlib.h>
-#include <stdio.h>
-#include <string.h>
-#include <unistd.h>
-#include <errno.h>
-#include <ctype.h>
-#include <limits.h>
-
-#define STRINGIFY_ARG(a)        #a
-#define STRINGIFY(a)            STRINGIFY_ARG(a)
-
-#define DEF_SORT_FUNC		sort_nr_objs
-#define SLABINFO_LINE_LEN	512	/* size of longest line */
-#define SLABINFO_NAME_LEN	32	/* cache name size (will truncate) */
-#define SLABINFO_FILE		"/proc/slabinfo"
-#define DEF_NR_ROWS		15	/* default nr of caches to show */
-
-/* object representing a slab cache (each line of slabinfo) */
-struct slab_info {
-	char name[SLABINFO_NAME_LEN];	/* name of this cache */
-	struct slab_info *next;
-	unsigned long nr_pages;		/* size of cache in pages */
-	unsigned long nr_objs;		/* number of objects in this cache */
-	unsigned long nr_active_objs;	/* number of active objects */
-	unsigned long obj_size;		/* size of each object */
-	unsigned long objs_per_slab;	/* number of objects per slab */
-	unsigned long nr_slabs;		/* number of slabs in this cache */
-	unsigned long use;		/* percent full: total / active */
-};
-
-/* object representing system-wide statistics */
-struct slab_stat {
-	unsigned long total_size;	/* size of all objects */
-	unsigned long active_size;	/* size of all active objects */
-	unsigned long nr_objs;		/* total number of objects */
-	unsigned long nr_active_objs;	/* total number of active objects */
-	unsigned long nr_slabs;		/* total number of slabs */
-	unsigned long nr_active_slabs;	/* total number of active slabs*/
-	unsigned long nr_caches;	/* number of caches */
-	unsigned long nr_active_caches;	/* number of active caches */
-	unsigned long avg_obj_size;	/* average object size */
-	unsigned long min_obj_size;	/* size of smallest object */
-	unsigned long max_obj_size;	/* size of largest object */
-};
-
-typedef int (*sort_t)(const struct slab_info *, const struct slab_info *);
-static sort_t sort_func;
-
-/*
- * get_slabinfo - open, read, and parse a slabinfo 2.x file, which has the
- * following format:
- *
- * slabinfo - version: 2.1
- * <name>  <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab>
- * : tunables <limit> <batchcount> <sharedfactor>
- * : slabdata <active_slabs> <num_slabs> <sharedavail>
- *
- * Returns the head of the new list of slab_info structures, or NULL on error.
- */
-static struct slab_info * get_slabinfo(struct slab_stat *stats)
-{
-	struct slab_info *head = NULL, *p = NULL, *prev = NULL;
-	FILE *slabfile;
-	char line[SLABINFO_LINE_LEN];
-	unsigned int major, minor;
-
-	slabfile = fopen(SLABINFO_FILE, "r");
-	if (!slabfile) {
-		perror("fopen");
-		return NULL;
-	}
-
-	if (!fgets(line, SLABINFO_LINE_LEN, slabfile)) {
-		fprintf(stderr, "cannot read from " SLABINFO_FILE "\n");
-		return NULL;
-	}
-
-	if (sscanf(line, "slabinfo - version: %u.%u", &major, &minor) != 2) {
-		fprintf(stderr, "unable to parse slabinfo version!\n");
-		return NULL;
-	}
-
-	if (major != 2 || minor > 1) {
-		fprintf(stderr, "we only support slabinfo 2.0 and 2.1!\n");
-		return NULL;
-	}
-
-	stats->min_obj_size = INT_MAX;
-
-	while (fgets(line, SLABINFO_LINE_LEN, slabfile)) {
-		unsigned long nr_active_slabs, pages_per_slab;
-		int ret;
-
-		if (line[0] == '#')
-			continue;
-
-		p = malloc(sizeof (struct slab_info));
-		if (!p) {
-			perror("malloc");
-			head = NULL;
-			break;
-		}
-		if (stats->nr_caches++ == 0)
-			head = prev = p;
-
-		ret = sscanf(line, "%" STRINGIFY(SLABINFO_NAME_LEN) "s"
-			     " %lu %lu %lu %lu %lu : tunables %*d %*d %*d : \
-			     slabdata %lu %lu %*d", p->name, 
-			     &p->nr_active_objs, &p->nr_objs, 
-			     &p->obj_size, &p->objs_per_slab,
-			     &pages_per_slab,
-			     &nr_active_slabs,
-			     &p->nr_slabs);
-
-		if (ret != 8) {
-			fprintf(stderr, "unrecognizable data in slabinfo!\n");
-			head = NULL;
-			break;
-		}
-
-		if (p->obj_size < stats->min_obj_size)
-			stats->min_obj_size = p->obj_size;
-		if (p->obj_size > stats->max_obj_size)
-			stats->max_obj_size = p->obj_size;
-
-		p->nr_pages = p->nr_slabs * pages_per_slab;
-
-		if (p->nr_objs) {
-			p->use = 100 * p->nr_active_objs / p->nr_objs;
-			stats->nr_active_caches++;
-		} else
-			p->use = 0;
-
-		stats->nr_objs += p->nr_objs;
-		stats->nr_active_objs += p->nr_active_objs;
-		stats->total_size += p->nr_objs * p->obj_size;
-		stats->active_size += p->nr_active_objs * p->obj_size;
-		stats->nr_slabs += p->nr_slabs;
-		stats->nr_active_slabs += nr_active_slabs;
-
-		prev->next = p;
-		prev = p;
-	}
-
-	if (fclose(slabfile))
-		perror("fclose");
-
-	if (p)
-		p->next = NULL;
-	if (stats->nr_objs)
-		stats->avg_obj_size = stats->total_size / stats->nr_objs;
-
-	return head;
-}
-
-/*
- * free_slablist - deallocate the memory associated with each node in the
- * provided slab_info linked list
- */
-static void free_slablist(struct slab_info *list)
-{
-	while (list) {
-		struct slab_info *temp = list->next;
-		free(list);
-		list = temp;
-	}
-}
-
-static struct slab_info *merge_objs(struct slab_info *a, struct slab_info *b)
-{
-	struct slab_info list;
-	struct slab_info *p = &list;
-
-	while (a && b) {
-		if (sort_func(a, b)) {
-			p->next = a;
-			p = a;
-			a = a->next;
-		} else {
-			p->next = b;
-			p = b;
-			b = b->next;
-		}
-	}
-
-	p->next = (a == NULL) ? b : a;
-	return list.next;
-}
-
-/* 
- * slabsort - merge sort the slab_info linked list based on sort_func
- */
-static struct slab_info *slabsort(struct slab_info *list)
-{
-	struct slab_info *a, *b;
-
-	if (!list || !list->next)
-		return list;
-
-	a = list;
-	b = list->next;
-
-	while (b && b->next) {
-		list = list->next;
-		b = b->next->next;
-	}
-
-	b = list->next;
-	list->next = NULL;
-
-	return merge_objs(slabsort(a), slabsort(b));
-}
-
-/*
- * Sort Routines.  Each of these should be associated with a command-line
- * search option.  The functions should fit the prototype:
- *
- *	int sort_foo(const struct slab_info *a, const struct slab_info *b)
- *
- * They return zero if the first parameter is smaller than the second.
- * Otherwise, they return nonzero.
- */
-
-static int sort_name(const struct slab_info *a, const struct slab_info *b)
-{
-	return (strcmp(a->name, b->name) < 0 ) ? 1: 0;
-}
-
-#define BUILD_SORT_FUNC(VAL) \
-	static int sort_ ## VAL \
-		(const struct slab_info *a, const struct slab_info *b) { \
-			return (a-> VAL > b-> VAL); }
-
-BUILD_SORT_FUNC(nr_objs)
-BUILD_SORT_FUNC(nr_active_objs)
-BUILD_SORT_FUNC(obj_size)
-BUILD_SORT_FUNC(objs_per_slab)
-BUILD_SORT_FUNC(nr_slabs)
-BUILD_SORT_FUNC(use)
-BUILD_SORT_FUNC(nr_pages)
-
-/*
- * set_sort_func - return the slab_sort_func that matches the given key.
- * On unrecognizable key, the call returns NULL.
- */
-static sort_t set_sort_func(char key)
-{
-	switch (tolower(key)) {
-	case 'a':
-		return sort_nr_active_objs;
-	case 'c':
-		return sort_nr_pages;
-	case 'l':
-		return sort_nr_slabs;	
-	case 'n':
-		return sort_name;
-	case 'o':
-		return sort_nr_objs;
-	case 'p':
-		return sort_objs_per_slab;	
-	case 's':
-		return sort_obj_size;
-	case 'u':
-		return sort_use;
-	default:
-		return NULL;
-	}
-}
-
-int main(int argc, char *argv[])
-{
-	struct slab_info *list, *p;
-	struct slab_stat stats = { .nr_objs = 0 };
-	unsigned int page_size = getpagesize() / 1024, nr_rows = DEF_NR_ROWS, i;
-
-	sort_func = DEF_SORT_FUNC;
-
-	if (argc > 1) {
-		/* FIXME: Ugh. */
-		if (argc == 3 && !strcmp(argv[1], "-n")) {
-			errno = 0;
-			nr_rows = (unsigned int) strtoul(argv[2], NULL, 0);
-			if (errno) {
-				perror("strtoul");
-				exit(EXIT_FAILURE);
-			}
-		}
-		else if (argc == 3 && !strcmp(argv[1], "-s"))
-			sort_func = set_sort_func(argv[2][0]) ? : DEF_SORT_FUNC;
-		else {
-			fprintf(stderr, "usage: %s [options]\n\n", argv[0]);
-			fprintf(stderr, "options:\n");
-			fprintf(stderr, "  -s S   specify sort criteria S\n");
-			fprintf(stderr, "  -h     display this help\n\n");
-			fprintf(stderr, "Valid sort criteria:\n");
-			fprintf(stderr, "  a: number of Active objects\n");
-			fprintf(stderr, "  c: Cache size\n");
-			fprintf(stderr, "  l: number of sLabs\n");
-			fprintf(stderr, "  n: Name\n");
-			fprintf(stderr, "  o: number of Objects\n");
-			fprintf(stderr, "  p: objects Per slab\n");
-			fprintf(stderr, "  s: object Size\n");
-			fprintf(stderr, "  u: cache Utilization\n");
-			exit(EXIT_FAILURE);
-		}
-	}
-
-	list = get_slabinfo (&stats);
-	if (!list)
-		exit(EXIT_FAILURE);
-
-	printf(" Active / Total Objects (%% used) : %lu / %lu (%.1f%%)\n"
-	       " Active / Total Slabs (%% used)   : %lu / %lu (%.1f%%)\n"
-	       " Active / Total Caches (%% used)  : %lu / %lu (%.1f%%)\n"
-	       " Active / Total Size (%% used)    : %.2fK / %.2fK (%.1f%%)\n"
-	       " Min / Avg / Max Object Size     : %.2fK / %.2fK / %.2fK\n\n",
-	       stats.nr_active_objs,
-	       stats.nr_objs,
-	       100.0 * stats.nr_active_objs / stats.nr_objs,
-	       stats.nr_active_slabs,
-	       stats.nr_slabs,
-	       100.0 * stats.nr_active_slabs / stats.nr_slabs,
-	       stats.nr_active_caches,
-	       stats.nr_caches,
-	       100.0 * stats.nr_active_caches / stats.nr_caches,
-	       stats.active_size / 1024.0,
-	       stats.total_size / 1024.0,
-	       100.0 * stats.active_size / stats.total_size,
-	       stats.min_obj_size / 1024.0,
-	       stats.avg_obj_size / 1024.0,
-	       stats.max_obj_size / 1024.0);
-
-	printf("%6s %6s %4s %8s %6s %8s %10s %-23s\n",
-	       "OBJS", "ACTIVE", "USE", "OBJ SIZE", "SLABS",
-	       "OBJ/SLAB", "CACHE SIZE", "NAME");
-
-	p = list = slabsort(list);
-	for (i = 0; i < nr_rows && p; i++) {
-		printf("%6lu %6lu %3lu%% %7.2fK %6lu %8lu %9luK %-23s\n",
-		       p->nr_objs, p->nr_active_objs, p->use,
-		       p->obj_size / 1024.0, p->nr_slabs,
-		       p->objs_per_slab,
-		       p->nr_pages * page_size,
-		       p->name);
-		p = p->next;
-	}
-
-	free_slablist(list);
-
-	return 0;
-}
diff --git a/simpleperf/Android.bp b/simpleperf/Android.bp
index ac412398..255ccd9c 100644
--- a/simpleperf/Android.bp
+++ b/simpleperf/Android.bp
@@ -726,6 +726,7 @@ cc_fuzz {
     name: "libsimpleperf_report_fuzzer",
     defaults: [
         "simpleperf_static_libs",
+        "libdexfile_static_transitive_defaults",
     ],
     fuzzing_frameworks: {
         afl: false,
@@ -754,6 +755,7 @@ cc_fuzz {
     name: "simpleperf_writer_fuzzer",
     defaults: [
         "simpleperf_static_libs",
+        "libdexfile_static_transitive_defaults",
     ],
     fuzzing_frameworks: {
         afl: false,
diff --git a/simpleperf/BranchListFile.cpp b/simpleperf/BranchListFile.cpp
index 13ab72ee..3e9d6fb3 100644
--- a/simpleperf/BranchListFile.cpp
+++ b/simpleperf/BranchListFile.cpp
@@ -411,7 +411,7 @@ bool BranchListProtoWriter::Write(const ETMBinaryMap& etm_data) {
 }
 
 bool BranchListProtoWriter::Write(const LBRData& lbr_data) {
-  if (!output_fp_ && !WriteHeader()) {
+  if (!is_header_written_ && !WriteHeader()) {
     return false;
   }
   proto::BranchList proto_branch_list;
@@ -458,6 +458,7 @@ bool BranchListProtoWriter::WriteHeader() {
   if (!WriteData(&compress, sizeof(compress))) {
     return false;
   }
+  is_header_written_ = true;
   return true;
 }
 
@@ -519,12 +520,13 @@ bool BranchListProtoReader::Read(ETMBinaryMap& etm_data, LBRData& lbr_data) {
     return false;
   }
   compress_ = compress == 1;
-  long file_offset = ftell(input_fp_.get());
-  if (file_offset == -1) {
-    PLOG(ERROR) << "failed to call ftell";
+  uint64_t file_offset = 0;
+  if (auto offset = GetCurrentOffset(); offset.has_value()) {
+    file_offset = offset.value();
+  } else {
     return false;
   }
-  uint64_t file_size = GetFileSize(input_filename_);
+  uint64_t file_size = GetTotalSize();
   while (file_offset < file_size) {
     uint32_t msg_size;
     if (!ReadData(&msg_size, sizeof(msg_size))) {
@@ -670,6 +672,25 @@ bool BranchListProtoReader::ReadOldFileFormat(ETMBinaryMap& etm_data, LBRData& l
   return true;
 }
 
+std::optional<uint64_t> BranchListProtoReader::GetCurrentOffset() {
+  if (input_fp_) {
+    long file_offset = ftell(input_fp_.get());
+    if (file_offset == -1) {
+      PLOG(ERROR) << "failed to call ftell";
+      return std::nullopt;
+    }
+    return file_offset;
+  }
+  return input_str_pos_;
+}
+
+uint64_t BranchListProtoReader::GetTotalSize() {
+  if (input_fp_) {
+    return GetFileSize(input_filename_);
+  }
+  return input_str_.size();
+}
+
 bool DumpBranchListFile(std::string filename) {
   ETMBinaryMap etm_data;
   LBRData lbr_data;
diff --git a/simpleperf/BranchListFile.h b/simpleperf/BranchListFile.h
index 64a00abb..cef9eb33 100644
--- a/simpleperf/BranchListFile.h
+++ b/simpleperf/BranchListFile.h
@@ -211,6 +211,7 @@ class BranchListProtoWriter {
   const size_t max_branches_per_message_;
   std::unique_ptr<FILE, decltype(&fclose)> output_fp_;
   std::string* output_str_;
+  bool is_header_written_ = false;
 };
 
 class BranchListProtoReader {
@@ -228,6 +229,8 @@ class BranchListProtoReader {
   void Rewind();
   bool ReadData(void* data, size_t size);
   bool ReadOldFileFormat(ETMBinaryMap& etm_data, LBRData& lbr_data);
+  std::optional<uint64_t> GetCurrentOffset();
+  uint64_t GetTotalSize();
 
   const std::string input_filename_;
   std::unique_ptr<FILE, decltype(&fclose)> input_fp_;
diff --git a/simpleperf/BranchListFile_test.cpp b/simpleperf/BranchListFile_test.cpp
index b5c7ec60..96746991 100644
--- a/simpleperf/BranchListFile_test.cpp
+++ b/simpleperf/BranchListFile_test.cpp
@@ -149,6 +149,24 @@ TEST(BranchListProtoReaderWriter, smoke) {
       ASSERT_TRUE(IsLBRDataEqual(lbr_data, new_lbr_data));
     }
   }
+
+  for (size_t max_branches_per_message : {100, 100000000}) {
+    for (bool compress : {false, true}) {
+      std::string s;
+      auto writer = BranchListProtoWriter::CreateForString(&s, compress, max_branches_per_message);
+      ASSERT_TRUE(writer);
+      ASSERT_TRUE(writer->Write(etm_data));
+      ASSERT_TRUE(writer->Write(lbr_data));
+      writer = nullptr;
+      auto reader = BranchListProtoReader::CreateForString(s);
+      ASSERT_TRUE(reader);
+      ETMBinaryMap new_etm_data;
+      LBRData new_lbr_data;
+      ASSERT_TRUE(reader->Read(new_etm_data, new_lbr_data));
+      ASSERT_TRUE(IsETMDataEqual(etm_data, new_etm_data));
+      ASSERT_TRUE(IsLBRDataEqual(lbr_data, new_lbr_data));
+    }
+  }
 }
 
 // @CddTest = 6.1/C-0-2
diff --git a/simpleperf/ETMRecorder.cpp b/simpleperf/ETMRecorder.cpp
index 79642070..3ec147b3 100644
--- a/simpleperf/ETMRecorder.cpp
+++ b/simpleperf/ETMRecorder.cpp
@@ -101,20 +101,21 @@ int ETMRecorder::GetEtmEventType() {
   return event_type_;
 }
 
-std::unique_ptr<EventType> ETMRecorder::BuildEventType() {
+void ETMRecorder::BuildEventTypes(std::set<EventType>& event_types) {
   int etm_event_type = GetEtmEventType();
   if (etm_event_type == -1) {
-    return nullptr;
+    return;
   }
-  return std::make_unique<EventType>("cs-etm", etm_event_type, 0,
-                                     "CoreSight ETM instruction tracing", "arm");
+  event_types.emplace("cs-etm", etm_event_type, 0, "Coresight ETM instruction tracing", "arm");
+  event_types.emplace("cs-etm/@tmc_etr0/", etm_event_type, 0,
+                      "Coresight ETM instruction tracing (via ETR)", "arm");
 }
 
 bool ETMRecorder::IsETMDriverAvailable() {
   return IsDir(ETM_DIR);
 }
 
-expected<bool, std::string> ETMRecorder::CheckEtmSupport() {
+expected<bool, std::string> ETMRecorder::CheckEtmSupport(bool need_etr) {
   if (GetEtmEventType() == -1) {
     return unexpected("etm event type isn't supported on device");
   }
@@ -132,18 +133,25 @@ expected<bool, std::string> ETMRecorder::CheckEtmSupport() {
       return unexpected("etm device isn't enabled by the bootloader");
     }
   }
-  if (!FindSinkConfig()) {
-    // Trigger a manual probe of etr. Then wait and recheck.
+  bool has_sink = CheckSinkSupport();
+  if (!has_sink || (need_etr && !has_etr_sink)) {
+    // Trigger a manual ETR probe under the following two cases:
+    // 1. No ETR or TRBE sinks were found.
+    // 2. An ETR sink is required but no ETR sinks were found.
     std::string prop_name = "profcollectd.etr.probe";
     bool res = android::base::SetProperty(prop_name, "1");
     if (!res) {
       LOG(ERROR) << "fails to setprop" << prop_name;
     }
     usleep(200000);  // Wait for 200ms.
-    if (!FindSinkConfig()) {
+    has_sink = CheckSinkSupport();
+    if (need_etr && !has_etr_sink) {
       return unexpected("can't find etr device, which moves etm data to memory");
     }
   }
+  if (!has_sink) {
+    return unexpected("can't find etr/trbe device, which moves etm data to memory");
+  }
   etm_supported_ = true;
   return true;
 }
@@ -180,34 +188,40 @@ bool ETMRecorder::ReadEtmInfo() {
   return (etm_info_.size() == online_cpus.size());
 }
 
-bool ETMRecorder::FindSinkConfig() {
-  bool has_etr = false;
-  bool has_trbe = false;
+bool ETMRecorder::CheckSinkSupport() {
+  has_etr_sink = false;
+  has_trbe_sink = false;
+  etr_sink_config_ = 0;
+  trbe_supported_cpus_.clear();
+
   for (const auto& name : GetEntriesInDir(ETM_DIR + "sinks")) {
-    if (!has_etr && name.find("etr") != -1) {
-      if (ReadValueInEtmDir("sinks/" + name, &sink_config_)) {
-        has_etr = true;
+    if (name.find("etr") != -1) {
+      if (ReadValueInEtmDir("sinks/" + name, &etr_sink_config_)) {
+        has_etr_sink = true;
+      }
+    } else if (name.find("trbe") != -1) {
+      int cpu;
+      if (android::base::ParseInt(&name[4], &cpu)) {
+        trbe_supported_cpus_.insert(cpu);
+        has_trbe_sink = true;
       }
     }
-    if (name.find("trbe") != -1) {
-      has_trbe = true;
-      break;
-    }
-  }
-  if (has_trbe) {
-    // When TRBE is present, let the driver choose the most suitable
-    // configuration.
-    sink_config_ = 0;
   }
-  return has_trbe || has_etr;
+  return has_trbe_sink || has_etr_sink;
 }
 
-void ETMRecorder::SetEtmPerfEventAttr(perf_event_attr* attr) {
+void ETMRecorder::SetEtmPerfEventAttr(const EventType& event_type, perf_event_attr& attr) {
   CHECK(etm_supported_);
   BuildEtmConfig();
-  attr->config = etm_event_config_;
-  attr->config2 = sink_config_;
-  attr->config3 = cc_threshold_config_;
+  attr.config = etm_event_config_;
+  if (has_trbe_sink && event_type.name.find("@tmc_etr0") == std::string::npos) {
+    // When TRBE is present and user doesn't explicitly choose ETR, let the driver choose the most
+    // suitable configuration.
+    attr.config2 = 0;
+  } else {
+    attr.config2 = etr_sink_config_;
+  }
+  attr.config3 = cc_threshold_config_;
 }
 
 void ETMRecorder::BuildEtmConfig() {
@@ -304,4 +318,11 @@ void ETMRecorder::SetCycleThreshold(size_t threshold) {
   cycle_threshold_ = threshold;
 }
 
+bool ETMRecorder::IsUsingTRBE(const perf_event_attr& attr, int cpu) const {
+  if (attr.config2 != 0) {
+    return false;
+  }
+  return trbe_supported_cpus_.find(cpu) != trbe_supported_cpus_.end();
+}
+
 }  // namespace simpleperf
diff --git a/simpleperf/ETMRecorder.h b/simpleperf/ETMRecorder.h
index 925c14e0..18ee8f56 100644
--- a/simpleperf/ETMRecorder.h
+++ b/simpleperf/ETMRecorder.h
@@ -20,6 +20,7 @@
 
 #include <map>
 #include <memory>
+#include <set>
 
 #include <android-base/expected.h>
 
@@ -57,25 +58,32 @@ class ETMRecorder {
 
   // If not found, return -1.
   int GetEtmEventType();
-  std::unique_ptr<EventType> BuildEventType();
+  void BuildEventTypes(std::set<EventType>& event_types);
   bool IsETMDriverAvailable();
-  android::base::expected<bool, std::string> CheckEtmSupport();
-  void SetEtmPerfEventAttr(perf_event_attr* attr);
+  // If need_etr is true, then return true only if ETR is ready.
+  // Otherwise, return true if either ETR or TRBE is ready.
+  android::base::expected<bool, std::string> CheckEtmSupport(bool need_etr = true);
+  void SetEtmPerfEventAttr(const EventType& event_type, perf_event_attr& attr);
   AuxTraceInfoRecord CreateAuxTraceInfoRecord();
   size_t GetAddrFilterPairs();
   void SetRecordTimestamp(bool record);
   void SetRecordCycles(bool record);
   void SetCycleThreshold(size_t threshold);
+  bool IsUsingTRBE(const perf_event_attr& attr, int cpu) const;
+  const std::set<int>& GetCPUsHavingTRBESink() const { return trbe_supported_cpus_; }
 
  private:
   bool ReadEtmInfo();
-  bool FindSinkConfig();
+  bool CheckSinkSupport();
   void BuildEtmConfig();
 
   int event_type_ = 0;
   bool etm_supported_ = false;
+  bool has_etr_sink = false;
+  bool has_trbe_sink = false;
   // select ETR device, setting in perf_event_attr->config2
-  uint32_t sink_config_ = 0;
+  uint32_t etr_sink_config_ = 0;
+  std::set<int> trbe_supported_cpus_;
   // use EL2 PID tracing or not
   bool use_contextid2_ = false;
   // select etm options (timestamp, context_id, ...), setting in perf_event_attr->config
diff --git a/simpleperf/RecordReadThread.cpp b/simpleperf/RecordReadThread.cpp
index 2d034bc1..7495d461 100644
--- a/simpleperf/RecordReadThread.cpp
+++ b/simpleperf/RecordReadThread.cpp
@@ -22,6 +22,7 @@
 #include <algorithm>
 #include <unordered_map>
 
+#include "ETMRecorder.h"
 #include "environment.h"
 #include "event_type.h"
 #include "record.h"
@@ -221,16 +222,38 @@ bool KernelRecordReader::MoveToNextRecord(const RecordParser& parser) {
   return true;
 }
 
+timeval ETMDataRateLimiter::GetNextReadInterval(uint64_t data_size, uint64_t timestamp) {
+  // desired_time_elapsed_ns: The target elapsed time (in nanoseconds) to receive data_size bytes,
+  // based on max_size_per_second_.
+  uint64_t desired_time_elapsed_ns = (data_size * 1000000000) / max_size_per_second_;
+
+  // actual_time_elapsed_ns: The actual time elapsed (in nanoseconds) since the start timestamp.
+  uint64_t actual_time_elapsed_ns = timestamp - start_timestamp_;
+
+  uint64_t read_interval_ns = min_read_interval_ns_;
+  if (actual_time_elapsed_ns < desired_time_elapsed_ns) {
+    read_interval_ns = std::max(read_interval_ns, desired_time_elapsed_ns - actual_time_elapsed_ns);
+  }
+
+  timeval tv;
+  tv.tv_sec = read_interval_ns / 1000000000;
+  tv.tv_usec = read_interval_ns % 1000000000 / 1000;
+  return tv;
+}
+
 RecordReadThread::RecordReadThread(size_t record_buffer_size, const perf_event_attr& attr,
                                    size_t min_mmap_pages, size_t max_mmap_pages,
                                    size_t aux_buffer_size, bool allow_truncating_samples,
-                                   bool exclude_perf)
+                                   bool exclude_perf, std::chrono::milliseconds etm_flush_interval)
     : record_buffer_(record_buffer_size),
       record_parser_(attr),
       attr_(attr),
       min_mmap_pages_(min_mmap_pages),
       max_mmap_pages_(max_mmap_pages),
-      aux_buffer_size_(aux_buffer_size) {
+      aux_buffer_size_(aux_buffer_size),
+      // max_size_per_second is based on the ETM data generation rate from ETR-based ETM events.
+      etm_data_rate_limiter_(aux_buffer_size * 1000 / etm_flush_interval.count(),
+                             etm_flush_interval, GetSystemClock()) {
   if (attr.sample_type & PERF_SAMPLE_STACK_USER) {
     stack_size_in_sample_record_ = attr.sample_stack_user;
   }
@@ -372,7 +395,11 @@ bool RecordReadThread::HandleCmd(IOEventLoop& loop) {
       result = HandleRemoveEventFds(*static_cast<std::vector<EventFd*>*>(cmd_arg_));
       break;
     case CMD_SYNC_KERNEL_BUFFER:
-      result = ReadRecordsFromKernelBuffer();
+      if (has_etm_events_) {
+        result = ReadETMData();
+      } else {
+        result = ReadRecordsFromKernelBuffer();
+      }
       break;
     case CMD_STOP_THREAD:
       result = loop.ExitLoop();
@@ -402,13 +429,21 @@ bool RecordReadThread::HandleAddEventFds(IOEventLoop& loop,
           success = false;
           break;
         }
-        if (IsEtmEventType(fd->attr().type)) {
+        if (IsEtmEventName(fd->EventName())) {
           if (!fd->CreateAuxBuffer(aux_buffer_size_, report_error)) {
             fd->DestroyMappedBuffer();
             success = false;
             break;
           }
           has_etm_events_ = true;
+          // Ideally we only need to periodically disable and enable event fds to flush ETM data
+          // for ETR. Because TRBE has an interrupt to move ETM data automatically on buffer
+          // overflow. However, TRBE driver lacks a patch of handling CPU idle. As a result, TRBE
+          // can lose power in CPU idle, and we can no longer get ETM data after that. So before
+          // the kernel patch is available (which is currently in review in
+          // https://lists.infradead.org/pipermail/linux-arm-kernel/2025-May/1028966.html), we need
+          // a workaround to also periodically disable and enable event fds for TRBE.
+          etm_with_etr_fds_.push_back(fd);
         }
         cpu_map[fd->Cpu()] = fd;
       } else {
@@ -432,10 +467,21 @@ bool RecordReadThread::HandleAddEventFds(IOEventLoop& loop,
     return false;
   }
   for (auto& pair : cpu_map) {
-    if (!pair.second->StartPolling(loop, [this]() { return ReadRecordsFromKernelBuffer(); })) {
+    kernel_record_readers_.emplace_back(pair.second);
+  }
+  if (has_etm_events_) {
+    // To prevent ETM data flooding from TRBE, read ETM data periodically instead of polling.
+    if (!loop.AddOneTimeEvent(etm_data_rate_limiter_.GetNextReadInterval(0, GetSystemClock()),
+                              [&]() { return PeriodicallyReadETMData(loop); })) {
       return false;
     }
-    kernel_record_readers_.emplace_back(pair.second);
+  } else {
+    for (auto& reader : kernel_record_readers_) {
+      if (!reader.GetEventFd()->StartPolling(loop,
+                                             [this]() { return ReadRecordsFromKernelBuffer(); })) {
+        return false;
+      }
+    }
   }
   return true;
 }
@@ -483,8 +529,8 @@ bool RecordReadThread::ReadRecordsFromKernelBuffer() {
       } else {
         // Use a binary heap to merge records from different buffers. As records from the same
         // buffer are already ordered by time, we only need to merge the first record from all
-        // buffers. And each time a record is popped from the heap, we put the next record from its
-        // buffer into the heap.
+        // buffers. And each time a record is popped from the heap, we put the next record from
+        // its buffer into the heap.
         for (auto& reader : readers) {
           reader->MoveToNextRecord(record_parser_);
         }
@@ -516,7 +562,8 @@ bool RecordReadThread::ReadRecordsFromKernelBuffer() {
       return false;
     }
     // If there are no commands, we can loop until there is no more data from the kernel.
-  } while (GetCmd() == NO_CMD);
+    // To prevent ETM data flooding from TRBE, avoid reading ETM data in a loop.
+  } while (GetCmd() == NO_CMD && !has_etm_events_);
   return true;
 }
 
@@ -682,4 +729,50 @@ bool RecordReadThread::SendDataNotificationToMainThread() {
   return true;
 }
 
+bool RecordReadThread::PeriodicallyReadETMData(IOEventLoop& loop) {
+  if (!ReadETMData()) {
+    return false;
+  }
+  timeval read_interval =
+      etm_data_rate_limiter_.GetNextReadInterval(stat_.aux_data_size, GetSystemClock());
+  return loop.AddOneTimeEvent(read_interval, [&]() { return PeriodicallyReadETMData(loop); }) !=
+         nullptr;
+}
+
+bool RecordReadThread::ReadETMData() {
+  if (!etm_with_etr_fds_.empty()) {
+    // For ETM events using ETR as the sink:
+    // ETM data is dumped to kernel buffer only when there is no thread traced by ETM. It happens
+    // either when all monitored threads are scheduled off cpu, or when all ETM perf events are
+    // disabled. If ETM data isn't dumped to kernel buffer in time, overflow parts will be
+    // dropped. This makes less than expected data, especially in system wide recording. So flush
+    // ETM data by temporarily disabling all perf events.
+    EventFd* last_fd = nullptr;
+    for (size_t i = 0; i < etm_with_etr_fds_.size(); i++) {
+      if (i == last_to_disable_etm_index_) {
+        last_fd = etm_with_etr_fds_[i];
+        continue;
+      }
+      if (!etm_with_etr_fds_[i]->SetEnableEvent(false)) {
+        return false;
+      }
+    }
+    if (!last_fd->SetEnableEvent(false)) {
+      return false;
+    }
+    // When using ETR, ETM data is flushed to the aux buffer of the last cpu disabling ETM events.
+    // To avoid overflowing the aux buffer for one cpu, rotate the last cpu disabling ETM events.
+    // Disable ETM event on each cpu except for the last cpu.
+    last_to_disable_etm_index_ = (last_to_disable_etm_index_ + 1) % etm_with_etr_fds_.size();
+
+    // Enable ETM events to restart ETM tracing.
+    for (auto fd : etm_with_etr_fds_) {
+      if (!fd->SetEnableEvent(true)) {
+        return false;
+      }
+    }
+  }
+  return ReadRecordsFromKernelBuffer();
+}
+
 }  // namespace simpleperf
diff --git a/simpleperf/RecordReadThread.h b/simpleperf/RecordReadThread.h
index 893f8234..4d58f9ba 100644
--- a/simpleperf/RecordReadThread.h
+++ b/simpleperf/RecordReadThread.h
@@ -16,9 +16,11 @@
 
 #pragma once
 
+#include <sys/time.h>
 #include <sys/types.h>
 
 #include <atomic>
+#include <chrono>
 #include <condition_variable>
 #include <functional>
 #include <memory>
@@ -32,6 +34,8 @@
 #include "event_fd.h"
 #include "record.h"
 
+using namespace std::chrono_literals;
+
 namespace simpleperf {
 
 // RecordBuffer is a circular buffer used to cache records in user-space. It allows one read
@@ -126,13 +130,37 @@ class KernelRecordReader {
   uint64_t record_time_ = 0;
 };
 
+// ETR-based ETM events aggregate data from all CPUs into a single buffer, while TRBE-based ETM
+// events send data to per-CPU buffers. So they have significant differences in data generate rates.
+// To provide a consistent user experience (not flooding data when switching from ETR to TRBE), we
+// use ETMDataRateLimiter to dynamically adjust ETM data read interval.
+class ETMDataRateLimiter {
+ public:
+  ETMDataRateLimiter(uint64_t max_size_per_second, std::chrono::milliseconds min_read_interval,
+                     uint64_t start_timestamp)
+      : max_size_per_second_(max_size_per_second),
+        min_read_interval_ns_(min_read_interval.count() * 1000000),
+        start_timestamp_(start_timestamp) {}
+
+  // data_size: the total size of ETM data read so far
+  // timestamp: current monotonic timestamp (in nonoseconds)
+  // Return a time interval to sleep before reading new ETM data.
+  timeval GetNextReadInterval(uint64_t data_size, uint64_t timestamp);
+
+ private:
+  uint64_t max_size_per_second_;
+  uint64_t min_read_interval_ns_;
+  uint64_t start_timestamp_;
+};
+
 // To reduce sample lost rate when recording dwarf based call graph, RecordReadThread uses a
 // separate high priority (nice -20) thread to read records from kernel buffers to a RecordBuffer.
 class RecordReadThread {
  public:
   RecordReadThread(size_t record_buffer_size, const perf_event_attr& attr, size_t min_mmap_pages,
                    size_t max_mmap_pages, size_t aux_buffer_size,
-                   bool allow_truncating_samples = true, bool exclude_perf = false);
+                   bool allow_truncating_samples = true, bool exclude_perf = false,
+                   std::chrono::milliseconds etm_flush_interval = 100ms);
   ~RecordReadThread();
   void SetBufferLevels(size_t record_buffer_low_level, size_t record_buffer_critical_level) {
     record_buffer_low_level_ = record_buffer_low_level;
@@ -180,6 +208,8 @@ class RecordReadThread {
   void PushRecordToRecordBuffer(KernelRecordReader* kernel_record_reader);
   void ReadAuxDataFromKernelBuffer(bool* has_data);
   bool SendDataNotificationToMainThread();
+  bool PeriodicallyReadETMData(IOEventLoop& loop);
+  bool ReadETMData();
 
   RecordBuffer record_buffer_;
   // When free size in record buffer is below low level, we cut stack data of sample records to 1K.
@@ -211,7 +241,12 @@ class RecordReadThread {
   std::unique_ptr<std::thread> read_thread_;
   std::vector<KernelRecordReader> kernel_record_readers_;
   pid_t exclude_pid_ = -1;
+
+  // ETM related members
   bool has_etm_events_ = false;
+  ETMDataRateLimiter etm_data_rate_limiter_;
+  std::vector<EventFd*> etm_with_etr_fds_;
+  size_t last_to_disable_etm_index_ = 0;
 
   std::unordered_set<EventFd*> event_fds_disabled_by_kernel_;
 
diff --git a/simpleperf/RecordReadThread_test.cpp b/simpleperf/RecordReadThread_test.cpp
index 2ff9a460..6844806b 100644
--- a/simpleperf/RecordReadThread_test.cpp
+++ b/simpleperf/RecordReadThread_test.cpp
@@ -24,8 +24,11 @@
 #include "record.h"
 #include "record_equal_test.h"
 #include "record_file.h"
+#include "utils.h"
 
+using namespace std::chrono_literals;
 using ::testing::_;
+using ::testing::AnyNumber;
 using ::testing::Eq;
 using ::testing::Return;
 using ::testing::Truly;
@@ -138,8 +141,8 @@ TEST(RecordParser, GetStackSizePos_with_PerfSampleReadType) {
 
 struct MockEventFd : public EventFd {
   MockEventFd(const perf_event_attr& attr, int cpu, char* buffer, size_t buffer_size,
-              bool mock_aux_buffer)
-      : EventFd(attr, -1, "", 0, cpu) {
+              bool mock_aux_buffer, const std::string& event_name = "")
+      : EventFd(attr, -1, event_name, 0, cpu) {
     mmap_data_buffer_ = buffer;
     mmap_data_buffer_size_ = buffer_size;
     if (mock_aux_buffer) {
@@ -147,6 +150,7 @@ struct MockEventFd : public EventFd {
     }
   }
 
+  MOCK_METHOD1(SetEnableEvent, bool(bool));
   MOCK_METHOD2(CreateMappedBuffer, bool(size_t, bool));
   MOCK_METHOD0(DestroyMappedBuffer, void());
   MOCK_METHOD2(StartPolling, bool(IOEventLoop&, const std::function<bool()>&));
@@ -234,6 +238,38 @@ TEST(KernelRecordReader, smoke) {
   ASSERT_FALSE(reader.MoveToNextRecord(parser));
 }
 
+bool operator==(const timeval& a, const timeval& b) {
+  return a.tv_sec == b.tv_sec && a.tv_usec == b.tv_usec;
+}
+
+// @CddTest = 6.1/C-0-2
+TEST(ETMDataRateLimiter, smoke) {
+  constexpr uint64_t MB = 1000 * 1000;
+  const uint64_t start_timestamp = GetSystemClock();
+
+  auto get_timestamp = [&](double seconds) {
+    return start_timestamp + static_cast<uint64_t>(seconds * 1000000000);
+  };
+
+  ETMDataRateLimiter limiter(40 * MB, 100ms, start_timestamp);
+  // Test receiving more than limit.
+  // First sleep is 0.1s (minimum interval).
+  ASSERT_EQ(limiter.GetNextReadInterval(0, get_timestamp(0)), SecondToTimeval(0.1));
+  // We received 20 MB in 0.1s, while it should take 0.5s. So sleep 0.4s.
+  ASSERT_EQ(limiter.GetNextReadInterval(20 * MB, get_timestamp(0.1)), SecondToTimeval(0.4));
+  // We received 30 MB in 0.5s, while it should take 0.75s. So sleep 0.25s.
+  ASSERT_EQ(limiter.GetNextReadInterval(30 * MB, get_timestamp(0.5)), SecondToTimeval(0.25));
+  // We received 40 MB in 0.75s, while it should take 1s. So sleep 0.25s.
+  ASSERT_EQ(limiter.GetNextReadInterval(40 * MB, get_timestamp(0.75)), SecondToTimeval(0.25));
+  // We received 50 MB in 1s, while it should take 1.25s. So sleep 0.25s.
+  ASSERT_EQ(limiter.GetNextReadInterval(50 * MB, get_timestamp(1)), SecondToTimeval(0.25));
+  // Test receiving less than limit.
+  // We received 50 MB in 1.25s, while it should take 1.25s. So sleep 0.1s (minimum interval).
+  ASSERT_EQ(limiter.GetNextReadInterval(50 * MB, get_timestamp(1.25)), SecondToTimeval(0.1));
+  // We received 50 MB in 1.35s, while it should take 1.25s. So sleep 0.1s (minimum interval).
+  ASSERT_EQ(limiter.GetNextReadInterval(50 * MB, get_timestamp(1.35)), SecondToTimeval(0.1));
+}
+
 // @CddTest = 6.1/C-0-2
 class RecordReadThreadTest : public ::testing::Test {
  protected:
@@ -525,10 +561,10 @@ TEST_F(RecordReadThreadTest, read_aux_data) {
   const size_t AUX_BUFFER_SIZE = 4096;
 
   perf_event_attr attr = CreateDefaultPerfEventAttr(*type);
-  MockEventFd fd(attr, 0, nullptr, 1, true);
+  MockEventFd fd(attr, 0, nullptr, 1, true, "cs-etm");
   EXPECT_CALL(fd, CreateMappedBuffer(_, _)).Times(1).WillOnce(Return(true));
   EXPECT_CALL(fd, CreateAuxBuffer(Eq(AUX_BUFFER_SIZE), _)).Times(1).WillOnce(Return(true));
-  EXPECT_CALL(fd, StartPolling(_, _)).Times(1).WillOnce(Return(true));
+  EXPECT_CALL(fd, SetEnableEvent(_)).Times(AnyNumber()).WillRepeatedly(Return(true));
   EXPECT_CALL(fd, GetAvailableMmapDataSize(_)).Times(aux_data.size()).WillRepeatedly(Return(0));
   EXPECT_CALL(fd,
               GetAvailableAuxData(Truly(SetBuf1), Truly(SetSize1), Truly(SetBuf2), Truly(SetSize2)))
diff --git a/simpleperf/cmd_inject.cpp b/simpleperf/cmd_inject.cpp
index 380b6468..a2275ba9 100644
--- a/simpleperf/cmd_inject.cpp
+++ b/simpleperf/cmd_inject.cpp
@@ -140,7 +140,7 @@ class PerfDataReader {
       return "unknown";
     }
     const perf_event_attr& attr = attrs[0].attr;
-    if (IsEtmEventType(attr.type)) {
+    if (IsEtmEventName(GetEventNameByAttr(attr))) {
       return "etm";
     }
     if (attr.sample_type & PERF_SAMPLE_BRANCH_STACK) {
diff --git a/simpleperf/cmd_inject_test.cpp b/simpleperf/cmd_inject_test.cpp
index 8ecdec20..0003ffc4 100644
--- a/simpleperf/cmd_inject_test.cpp
+++ b/simpleperf/cmd_inject_test.cpp
@@ -370,3 +370,43 @@ TEST(cmd_inject, exclude_process_name_option) {
   ASSERT_EQ(stat(tmpfile.path, &st), -1);
   ASSERT_EQ(errno, ENOENT);
 }
+
+// @CddTest = 6.1/C-0-2
+TEST(cmd_inject, check_missing_aux_data) {
+  // Inject a malformed perf.data where an aux record's offset was changed to
+  // point outside the file. It should report warnings and generate an empty file.
+  android::base::ScopedLogSeverity severity(android::base::INFO);
+  CapturedStderr capture;
+  TemporaryFile tmpfile;
+  close(tmpfile.release());
+  ASSERT_TRUE(RunInjectCmd({"-i", GetTestData("etm/perf_etm_wrong_aux.data"), "-o", tmpfile.path}));
+  capture.Stop();
+  const std::string INFO_MSG = "aux data is missing";
+  ASSERT_NE(capture.str().find(INFO_MSG), std::string::npos);
+  std::string data;
+  ASSERT_TRUE(android::base::ReadFileToString(tmpfile.path, &data));
+  ASSERT_TRUE(data.empty());
+
+  // Inject a compressed perf.data which has no missing aux data. It should report no warnings
+  // and generate a non empty file.
+  capture.Reset();
+  capture.Start();
+  ASSERT_TRUE(
+      RunInjectCmd({"-i", GetTestData("etm/perf_etm_compressed.data"), "-o", tmpfile.path}));
+  capture.Stop();
+  ASSERT_EQ(capture.str().find(INFO_MSG), std::string::npos);
+  ASSERT_TRUE(android::base::ReadFileToString(tmpfile.path, &data));
+  ASSERT_FALSE(data.empty());
+}
+
+// @CddTest = 6.1/C-0-2
+TEST(cmd_inject, perf_data_with_decode_etm_option) {
+  // Test reading perf.data generated with --decode-etm.
+  TemporaryFile tmpfile;
+  close(tmpfile.release());
+  ASSERT_TRUE(RunInjectCmd({"--output", "branch-list", "-i",
+                            GetTestData("etm/perf_etm_with_decode_etm.data"), "-o", tmpfile.path}));
+  std::string autofdo_data;
+  ASSERT_TRUE(RunInjectCmd({"-i", tmpfile.path, "--output", "autofdo"}, &autofdo_data));
+  CheckMatchingExpectedData("perf_inject.data", autofdo_data);
+}
diff --git a/simpleperf/cmd_list.cpp b/simpleperf/cmd_list.cpp
index 1f904c2e..e2a4a61f 100644
--- a/simpleperf/cmd_list.cpp
+++ b/simpleperf/cmd_list.cpp
@@ -35,6 +35,7 @@
 #include "event_fd.h"
 #include "event_selection_set.h"
 #include "event_type.h"
+#include "utils.h"
 
 namespace simpleperf {
 
@@ -78,8 +79,8 @@ static void RawEventTestThread(RawEventTestThreadArg* arg) {
 }
 
 struct RawEventSupportStatus {
-  std::vector<int> supported_cpus;
-  std::vector<int> may_supported_cpus;
+  std::set<int> supported_cpus;
+  std::set<int> may_supported_cpus;
 };
 
 #if defined(__riscv)
@@ -174,11 +175,9 @@ class RawEventSupportChecker {
       }
 
       if (supported) {
-        status.supported_cpus.insert(status.supported_cpus.end(), model.cpus.begin(),
-                                     model.cpus.end());
+        status.supported_cpus.insert(model.cpus.begin(), model.cpus.end());
       } else if (may_supported) {
-        status.may_supported_cpus.insert(status.may_supported_cpus.end(), model.cpus.begin(),
-                                         model.cpus.end());
+        status.may_supported_cpus.insert(model.cpus.begin(), model.cpus.end());
       }
     }
     return status;
@@ -259,30 +258,6 @@ class RawEventSupportChecker {
   std::vector<std::string> cpu_model_names_;
 };
 
-static std::string ToCpuString(const std::vector<int>& cpus) {
-  std::string s;
-  if (cpus.empty()) {
-    return s;
-  }
-  s += std::to_string(cpus[0]);
-  int last_cpu = cpus[0];
-  bool added = true;
-  for (size_t i = 1; i < cpus.size(); ++i) {
-    if (cpus[i] == last_cpu + 1) {
-      last_cpu = cpus[i];
-      added = false;
-    } else {
-      s += "-" + std::to_string(last_cpu) + "," + std::to_string(cpus[i]);
-      last_cpu = cpus[i];
-      added = true;
-    }
-  }
-  if (!added) {
-    s += "-" + std::to_string(last_cpu);
-  }
-  return s;
-}
-
 static void PrintRawEventTypes(const std::string& type_desc) {
   printf("List of %s:\n", type_desc.c_str());
 #if defined(__aarch64__) || defined(__arm__)
diff --git a/simpleperf/cmd_record.cpp b/simpleperf/cmd_record.cpp
index 6c8f793f..e287f3eb 100644
--- a/simpleperf/cmd_record.cpp
+++ b/simpleperf/cmd_record.cpp
@@ -593,6 +593,10 @@ bool RecordCommand::PrepareRecording(Workload* workload) {
         LOG(INFO) << "Hardware events are not available, switch to cpu-clock.";
       }
     }
+    if (!IsKernelEventSupported()) {
+      event_type += ":u";
+      LOG(INFO) << "Can't record kernel samples, switch to " << event_type;
+    }
     if (!event_selection_set_.AddEventType(event_type)) {
       return false;
     }
@@ -781,18 +785,6 @@ bool RecordCommand::PrepareRecording(Workload* workload) {
         return false;
       }
     }
-    // ETM data is dumped to kernel buffer only when there is no thread traced by ETM. It happens
-    // either when all monitored threads are scheduled off cpu, or when all etm perf events are
-    // disabled.
-    // If ETM data isn't dumped to kernel buffer in time, overflow parts will be dropped. This
-    // makes less than expected data, especially in system wide recording. So add a periodic event
-    // to flush etm data by temporarily disable all perf events.
-    auto etm_flush = [this]() {
-      return event_selection_set_.DisableETMEvents() && event_selection_set_.EnableETMEvents();
-    };
-    if (!loop->AddPeriodicEvent(SecondToTimeval(etm_flush_interval_.count() / 1000.0), etm_flush)) {
-      return false;
-    }
 
     if (etm_branch_list_generator_) {
       if (exclude_perf_) {
@@ -825,12 +817,6 @@ bool RecordCommand::DoRecording(Workload* workload) {
     return false;
   }
   time_stat_.stop_recording_time = GetSystemClock();
-  if (event_selection_set_.HasAuxTrace()) {
-    // Disable ETM events to flush the last ETM data.
-    if (!event_selection_set_.DisableETMEvents()) {
-      return false;
-    }
-  }
   if (!event_selection_set_.SyncKernelBuffer()) {
     return false;
   }
@@ -2163,6 +2149,9 @@ bool RecordCommand::DumpBuildIdFeature() {
   BuildId build_id;
   std::vector<Dso*> dso_v = thread_tree_.GetAllDsos();
   for (Dso* dso : dso_v) {
+    if (dso->type() == DSO_UNKNOWN_FILE) {
+      continue;
+    }
     // For aux tracing, we don't know which binaries are traced.
     // So dump build ids for all binaries.
     if (!dso->HasDumpId() && !event_selection_set_.HasAuxTrace()) {
@@ -2173,6 +2162,23 @@ bool RecordCommand::DumpBuildIdFeature() {
       build_id_records.emplace_back(in_kernel, UINT_MAX, build_id, dso->Path());
     }
   }
+  if (event_selection_set_.HasAuxTrace()) {
+    // If [vdso]->GetDebugFilePath() exists, copy it to "./vdso.so". If it does exist, the build id
+    // of [vdso] was read out from it, and [vdso] itself was already added to the vector in the loop
+    // above.
+    constexpr uint64_t force_64bit = (sizeof(size_t) == sizeof(uint64_t)) ? 1ULL << 32 : 1;
+    Dso* vdso = thread_tree_.FindUserDsoOrNew("[vdso]", force_64bit);
+    if (std::filesystem::exists(vdso->GetDebugFilePath())) {
+      std::string saved_vdso =
+          std::filesystem::absolute(android::base::Dirname(record_filename_) + "/vdso.so");
+      std::filesystem::copy_file(vdso->GetDebugFilePath(), saved_vdso,
+                                 std::filesystem::copy_options::overwrite_existing);
+      Dso* saved_vdso_dso = thread_tree_.FindUserDsoOrNew(saved_vdso, force_64bit);
+      if (GetBuildId(*saved_vdso_dso, build_id)) {
+        build_id_records.emplace_back(false, UINT_MAX, build_id, saved_vdso);
+      }
+    }
+  }
   if (!record_file_writer_->WriteBuildIdFeature(build_id_records)) {
     return false;
   }
diff --git a/simpleperf/cmd_record_test.cpp b/simpleperf/cmd_record_test.cpp
index a7aef6b4..045873ca 100644
--- a/simpleperf/cmd_record_test.cpp
+++ b/simpleperf/cmd_record_test.cpp
@@ -804,14 +804,14 @@ class RecordingAppHelper {
       return success;
     };
     ProcessSymbolsInPerfDataFile(GetDataPath(), callback);
-    size_t sample_count = GetSampleCount();
     if (!success) {
       if (IsInEmulator()) {
-        // In emulator, the monitored app may not have a chance to run.
+        // In emulator, the main thread of the monitored app may not have a chance to run.
         constexpr size_t MIN_SAMPLES_TO_CHECK_SYMBOLS = 1000;
-        if (size_t sample_count = GetSampleCount(); sample_count < MIN_SAMPLES_TO_CHECK_SYMBOLS) {
-          GTEST_LOG_(INFO) << "Only " << sample_count
-                           << " samples recorded in the emulator. Skip checking symbols (need "
+        if (size_t sample_count = GetMainThreadSampleCount();
+            sample_count < MIN_SAMPLES_TO_CHECK_SYMBOLS) {
+          GTEST_LOG_(INFO) << "Only " << sample_count << " samples recorded for the main thread in"
+                           << " the emulator. Skip checking symbols (need "
                            << MIN_SAMPLES_TO_CHECK_SYMBOLS << " samples).";
           return true;
         }
@@ -826,7 +826,7 @@ class RecordingAppHelper {
   std::string GetDataPath() const { return perf_data_file_.path; }
 
  private:
-  size_t GetSampleCount() {
+  size_t GetMainThreadSampleCount() {
     size_t sample_count = 0;
     std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(GetDataPath());
     if (!reader) {
@@ -834,7 +834,10 @@ class RecordingAppHelper {
     }
     auto process_record = [&](std::unique_ptr<Record> r) {
       if (r->type() == PERF_RECORD_SAMPLE) {
-        sample_count++;
+        auto sr = static_cast<SampleRecord*>(r.get());
+        if (sr->tid_data.pid == sr->tid_data.tid) {
+          sample_count++;
+        }
       }
       return true;
     };
@@ -1107,6 +1110,11 @@ TEST(record_cmd, cs_etm_event) {
   ASSERT_TRUE(has_auxtrace);
   ASSERT_TRUE(has_aux);
   ASSERT_TRUE(!reader->ReadBuildIdFeature().empty());
+  // Reset reader to avoid interfering with next event type detection for cs-etm/@tmc_etr0/.
+  reader.reset();
+
+  // We can explicitly use ETR. Because ETR is ready after CheckEtmSupport().
+  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm/@tmc_etr0/"}, tmpfile.path));
 }
 
 // @CddTest = 6.1/C-0-2
@@ -1176,13 +1184,22 @@ TEST(record_cmd, addr_filter_option) {
       CreateCommandInstance("inject")->Run({"-i", record_file.path, "-o", inject_file.path}));
   std::string data;
   ASSERT_TRUE(android::base::ReadFileToString(inject_file.path, &data));
-  // Only instructions in sleep_exec_path are traced.
+  // Trace should ideally be limited to sleep_exec_path. However, due to potential early child
+  // command execution before filter setup, some other binary ETM data might exist. Thus, only
+  // checking for the presence of sleep_exec_path traces.
+  bool seen_sleep = false;
   for (auto& line : android::base::Split(data, "\n")) {
-    if (android::base::StartsWith(line, "dso ")) {
-      std::string dso = line.substr(strlen("dso "), sleep_exec_path.size());
-      ASSERT_EQ(dso, sleep_exec_path);
+    if (android::base::StartsWith(line, "// ")) {
+      if (android::base::StartsWith(line, "// build_id: ")) {
+        continue;
+      }
+      std::string dso = line.substr(strlen("// "), sleep_exec_path.size());
+      if (dso == sleep_exec_path) {
+        seen_sleep = true;
+      }
     }
   }
+  ASSERT_TRUE(seen_sleep);
 
   // Test if different filter types are accepted by the kernel.
   auto elf = ElfFile::Open(sleep_exec_path);
@@ -1267,6 +1284,29 @@ TEST(record_cmd, etm_flush_interval_option) {
   ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm", "--etm-flush-interval", "10"}));
 }
 
+TEST(record_cmd, etm_uses_vdso) {
+  if (!ETMRecorder::GetInstance().CheckEtmSupport().ok()) {
+    GTEST_LOG_(INFO) << "Omit this test since etm isn't supported on this device";
+    return;
+  }
+  TemporaryFile record_file;
+  ASSERT_TRUE(RunRecordCmd({"-e", "cs-etm"}, record_file.path));
+  TemporaryFile inject_file;
+  ASSERT_TRUE(CreateCommandInstance("inject")->Run(
+      {"-i", record_file.path, "-o", inject_file.path, "--binary", "\\[vdso\\]"}));
+
+  std::string data;
+  ASSERT_TRUE(android::base::ReadFileToString(inject_file.path, &data));
+  bool seen_vdso = false;
+  for (auto& line : android::base::Split(data, "\n")) {
+    if ("// [vdso]" == line) {
+      seen_vdso = true;
+      break;
+    }
+  }
+  ASSERT_TRUE(seen_vdso);
+}
+
 // @CddTest = 6.1/C-0-2
 TEST(record_cmd, pmu_event_option) {
   TEST_REQUIRE_PMU_COUNTER();
diff --git a/simpleperf/cmd_stat.cpp b/simpleperf/cmd_stat.cpp
index 8f8e416f..e637be87 100644
--- a/simpleperf/cmd_stat.cpp
+++ b/simpleperf/cmd_stat.cpp
@@ -1050,6 +1050,46 @@ void StatCommand::AdjustToIntervalOnlyValues(std::vector<CountersInfo>& counters
   }
 }
 
+// Normalize a single entry intended for use in a CSV file.
+//
+// If the given string contains a comma, the entire entry needs to be quoted. If
+// the string contains a double quote character, it should also be quoted and
+// the double quotes escaped by doubling them.
+//
+// See https://en.wikipedia.org/wiki/Comma-separated_values for more details.
+std::string NormalizeCsvEntry(std::string_view entry) {
+  bool needs_quotes = false;
+  int num_quotes = 0;
+  for (char ch : entry) {
+    switch (ch) {
+      case '"':
+        ++num_quotes;
+        needs_quotes = true;
+        break;
+      case ',':
+        needs_quotes = true;
+        break;
+      default:
+        break;
+    }
+  }
+  if (!needs_quotes) {
+    return std::string(entry);
+  }
+  std::string normalized_entry;
+  normalized_entry.reserve(entry.size() + num_quotes + 2);
+  normalized_entry += '"';
+  for (char ch : entry) {
+    if (ch == '"') {
+      normalized_entry += "\"\"";
+    } else {
+      normalized_entry += ch;
+    }
+  }
+  normalized_entry += '"';
+  return normalized_entry;
+}
+
 bool StatCommand::ShowCounters(const std::vector<CountersInfo>& counters, double duration_in_sec,
                                FILE* fp) {
   if (csv_) {
@@ -1065,8 +1105,8 @@ bool StatCommand::ShowCounters(const std::vector<CountersInfo>& counters, double
           fprintf(fp,
                   "%s,tid,%d,cpu,%d,count,%" PRIu64 ",time_enabled,%" PRIu64
                   ",time running,%" PRIu64 ",id,%" PRIu64 ",\n",
-                  counters_info.event_name.c_str(), counter_info.tid, counter_info.cpu,
-                  counter_info.counter.value, counter_info.counter.time_enabled,
+                  NormalizeCsvEntry(counters_info.event_name).c_str(), counter_info.tid,
+                  counter_info.cpu, counter_info.counter.value, counter_info.counter.time_enabled,
                   counter_info.counter.time_running, counter_info.counter.id);
         } else {
           fprintf(fp,
diff --git a/simpleperf/command.cpp b/simpleperf/command.cpp
index 2019a0d3..dbf6f9c0 100644
--- a/simpleperf/command.cpp
+++ b/simpleperf/command.cpp
@@ -220,8 +220,7 @@ void RegisterAllCommands() {
 
 static void StderrLogger(android::base::LogId, android::base::LogSeverity severity, const char*,
                          const char* file, unsigned int line, const char* message) {
-  static const char log_characters[] = "VDIWEFF";
-  char severity_char = log_characters[severity];
+  char severity_char = android::base::kSeverityChars[severity];
   fprintf(stderr, "simpleperf %c %s:%u] %s\n", severity_char, file, line, message);
 }
 
diff --git a/simpleperf/dso.cpp b/simpleperf/dso.cpp
index e953acff..e21cf3b1 100644
--- a/simpleperf/dso.cpp
+++ b/simpleperf/dso.cpp
@@ -1114,6 +1114,11 @@ bool GetBuildId(const Dso& dso, BuildId& build_id) {
     if (GetBuildIdFromDsoPath(dso.Path(), &build_id)) {
       return true;
     }
+    if (dso.Path() == "[vdso]") {
+      if (GetBuildIdFromDsoPath(dso.GetDebugFilePath(), &build_id)) {
+        return true;
+      }
+    }
   }
   return false;
 }
diff --git a/simpleperf/event_fd.h b/simpleperf/event_fd.h
index 90791a53..a320d177 100644
--- a/simpleperf/event_fd.h
+++ b/simpleperf/event_fd.h
@@ -49,6 +49,7 @@ class EventFd {
 
   // Give information about this perf_event_file, like (event_name, tid, cpu).
   std::string Name() const;
+  const std::string EventName() const { return event_name_; }
 
   uint64_t Id() const;
 
@@ -60,7 +61,7 @@ class EventFd {
 
   // It tells the kernel to start counting and recording events specified by
   // this file.
-  bool SetEnableEvent(bool enable);
+  virtual bool SetEnableEvent(bool enable);
   bool SetFilter(const std::string& filter);
 
   bool ReadCounter(PerfCounter* counter);
diff --git a/simpleperf/event_selection_set.cpp b/simpleperf/event_selection_set.cpp
index b2426429..a15a59b7 100644
--- a/simpleperf/event_selection_set.cpp
+++ b/simpleperf/event_selection_set.cpp
@@ -182,6 +182,16 @@ bool IsKernelEventSupported() {
   return IsEventAttrSupported(attr, type->name);
 }
 
+static bool IsKernelUsingContiguousAuxBuffer() {
+  // Old kernels allocates contiguous pages for AUX buffer. This is changed by kernel patch
+  // "perf/aux: Allocate non-contiguous AUX pages by default". The patch is available on Android
+  // 6.6 kernel.
+  if (auto version = GetKernelVersion(); version && version.value() < std::make_pair(6, 6)) {
+    return true;
+  }
+  return false;
+}
+
 std::string AddrFilter::ToString() const {
   switch (type) {
     case FILE_RANGE:
@@ -227,23 +237,33 @@ bool EventSelectionSet::BuildAndCheckEventSelection(const std::string& event_nam
   selection->event_attr.exclude_host = event_type->exclude_host;
   selection->event_attr.exclude_guest = event_type->exclude_guest;
   selection->event_attr.precise_ip = event_type->precise_ip;
-  if (IsEtmEventType(event_type->event_type.type)) {
+  if (event_type->event_type.IsEtmEvent()) {
     auto& etm_recorder = ETMRecorder::GetInstance();
-    if (auto result = etm_recorder.CheckEtmSupport(); !result.ok()) {
+    bool need_etr = event_type->event_type.name.find("@tmc_etr0") != std::string::npos;
+    if (auto result = etm_recorder.CheckEtmSupport(need_etr); !result.ok()) {
       LOG(ERROR) << result.error();
       return false;
     }
-    ETMRecorder::GetInstance().SetEtmPerfEventAttr(&selection->event_attr);
-    // The kernel (rb_allocate_aux) allocates high order of pages based on aux_watermark.
-    // To avoid that, use aux_watermark <= 1 page size.
-    selection->event_attr.aux_watermark = 4096;
+#if defined(__ANDROID__)
+    // To prevent KASLR disclosure, disallow recording kernel ETM data for profileable apps.
+    if (!selection->event_attr.exclude_kernel && IsInAppUid()) {
+      LOG(ERROR) << "Can't record kernel ETM data from app uid.";
+      return false;
+    }
+#endif
+    ETMRecorder::GetInstance().SetEtmPerfEventAttr(event_type->event_type, selection->event_attr);
+    if (IsKernelUsingContiguousAuxBuffer()) {
+      // The kernel (rb_allocate_aux) allocates high order of pages based on aux_watermark.
+      // To avoid that, use aux_watermark <= 1 page size.
+      selection->event_attr.aux_watermark = 4096;
+    }
   }
   bool set_default_sample_freq = false;
   if (!for_stat_cmd_) {
     if (event_type->event_type.type == PERF_TYPE_TRACEPOINT) {
       selection->event_attr.freq = 0;
       selection->event_attr.sample_period = DEFAULT_SAMPLE_PERIOD_FOR_TRACEPOINT_EVENT;
-    } else if (IsEtmEventType(event_type->event_type.type)) {
+    } else if (event_type->event_type.IsEtmEvent()) {
       // ETM recording has no sample frequency to adjust. Using sample frequency only wastes time
       // enabling/disabling etm devices. So don't adjust frequency by default.
       selection->event_attr.freq = 0;
@@ -272,6 +292,14 @@ bool EventSelectionSet::BuildAndCheckEventSelection(const std::string& event_nam
     // PMU events are provided by kernel, so they should be supported
     if (!event_type->event_type.IsPmuEvent() &&
         !IsEventAttrSupported(selection->event_attr, selection->event_type_modifier.name)) {
+      if (selection->event_attr.exclude_kernel == 0) {
+        selection->event_attr.exclude_kernel = 1;
+        if (IsEventAttrSupported(selection->event_attr, selection->event_type_modifier.name)) {
+          LOG(ERROR) << "Can't record kernel samples. Please try `-e " << event_type->name
+                     << ":u` instead.";
+          return false;
+        }
+      }
       LOG(ERROR) << "Event type '" << event_type->name << "' is not supported on the device";
       return false;
     }
@@ -314,7 +342,7 @@ bool EventSelectionSet::AddEventGroup(const std::vector<std::string>& event_name
     if (!BuildAndCheckEventSelection(event_name, first_event, &selection, check)) {
       return false;
     }
-    if (IsEtmEventType(selection.event_attr.type)) {
+    if (selection.event_type_modifier.event_type.IsEtmEvent()) {
       has_aux_trace_ = true;
     }
     if (first_in_group) {
@@ -819,7 +847,7 @@ bool EventSelectionSet::ApplyAddrFilters() {
 
   for (auto& group : groups_) {
     for (auto& selection : group.selections) {
-      if (IsEtmEventType(selection.event_type_modifier.event_type.type)) {
+      if (selection.event_type_modifier.event_type.IsEtmEvent()) {
         for (auto& event_fd : selection.event_fds) {
           if (!event_fd->SetFilter(filter_str)) {
             return false;
@@ -1004,45 +1032,4 @@ bool EventSelectionSet::EnableETMEvents() {
   return true;
 }
 
-bool EventSelectionSet::DisableETMEvents() {
-  for (auto& group : groups_) {
-    for (auto& sel : group.selections) {
-      if (!sel.event_type_modifier.event_type.IsEtmEvent()) {
-        continue;
-      }
-      // When using ETR, ETM data is flushed to the aux buffer of the last cpu disabling ETM events.
-      // To avoid overflowing the aux buffer for one cpu, rotate the last cpu disabling ETM events.
-      if (etm_event_cpus_.empty()) {
-        for (const auto& fd : sel.event_fds) {
-          etm_event_cpus_.insert(fd->Cpu());
-        }
-        if (etm_event_cpus_.empty()) {
-          continue;
-        }
-        etm_event_cpus_it_ = etm_event_cpus_.begin();
-      }
-      int last_disabled_cpu = *etm_event_cpus_it_;
-      if (++etm_event_cpus_it_ == etm_event_cpus_.end()) {
-        etm_event_cpus_it_ = etm_event_cpus_.begin();
-      }
-
-      for (auto& fd : sel.event_fds) {
-        if (fd->Cpu() != last_disabled_cpu) {
-          if (!fd->SetEnableEvent(false)) {
-            return false;
-          }
-        }
-      }
-      for (auto& fd : sel.event_fds) {
-        if (fd->Cpu() == last_disabled_cpu) {
-          if (!fd->SetEnableEvent(false)) {
-            return false;
-          }
-        }
-      }
-    }
-  }
-  return true;
-}
-
 }  // namespace simpleperf
diff --git a/simpleperf/event_type.cpp b/simpleperf/event_type.cpp
index d54ac274..c37143ac 100644
--- a/simpleperf/event_type.cpp
+++ b/simpleperf/event_type.cpp
@@ -300,20 +300,10 @@ class ETMTypeFinder : public EventTypeFinder {
  public:
   ETMTypeFinder() : EventTypeFinder(EventFinderType::ETM) {}
 
-  const EventType* FindType(const std::string& name) override {
-    if (name != kETMEventName) {
-      return nullptr;
-    }
-    return EventTypeFinder::FindType(name);
-  }
-
  protected:
   void LoadTypes() override {
 #if defined(__linux__)
-    std::unique_ptr<EventType> etm_type = ETMRecorder::GetInstance().BuildEventType();
-    if (etm_type) {
-      types_.emplace(std::move(*etm_type));
-    }
+    ETMRecorder::GetInstance().BuildEventTypes(types_);
 #endif
   }
 };
@@ -594,9 +584,4 @@ std::unique_ptr<EventTypeAndModifier> ParseEventType(const std::string& event_ty
   return event_type_modifier;
 }
 
-bool IsEtmEventType(uint32_t type) {
-  const EventType* event_type = EventTypeManager::Instance().FindType(kETMEventName);
-  return (event_type != nullptr) && (event_type->type == type);
-}
-
 }  // namespace simpleperf
diff --git a/simpleperf/event_type.h b/simpleperf/event_type.h
index ecc3d175..d9038d46 100644
--- a/simpleperf/event_type.h
+++ b/simpleperf/event_type.h
@@ -29,7 +29,9 @@
 
 namespace simpleperf {
 
-inline const std::string kETMEventName = "cs-etm";
+static inline bool IsEtmEventName(const std::string& name) {
+  return name.find("cs-etm") != std::string::npos;
+}
 
 // EventType represents one type of event, like cpu_cycle_event, cache_misses_event.
 // The user knows one event type by its name, and the kernel knows one event type by its
@@ -51,8 +53,8 @@ struct EventType {
     return strcasecmp(name.c_str(), other.name.c_str()) < 0;
   }
 
-  bool IsPmuEvent() const { return name.find('/') != std::string::npos; }
-  bool IsEtmEvent() const { return name == kETMEventName; }
+  bool IsPmuEvent() const { return name.find('/') != std::string::npos && !IsEtmEvent(); }
+  bool IsEtmEvent() const { return IsEtmEventName(name); }
   bool IsHardwareEvent() const {
     return type == PERF_TYPE_HARDWARE || type == PERF_TYPE_HW_CACHE || type == PERF_TYPE_RAW;
   }
@@ -132,7 +134,6 @@ class EventTypeManager {
 
 const EventType* FindEventTypeByName(const std::string& name, bool report_error = true);
 std::unique_ptr<EventTypeAndModifier> ParseEventType(const std::string& event_type_str);
-bool IsEtmEventType(uint32_t type);
 
 }  // namespace simpleperf
 
diff --git a/simpleperf/libsimpleperf_report_fuzzer.cpp b/simpleperf/libsimpleperf_report_fuzzer.cpp
index 3656be60..716857ab 100644
--- a/simpleperf/libsimpleperf_report_fuzzer.cpp
+++ b/simpleperf/libsimpleperf_report_fuzzer.cpp
@@ -18,6 +18,7 @@
 #include <record_file.h>
 #include "command.h"
 #include "fuzzer/FuzzedDataProvider.h"
+#include "report_lib_interface.cpp"
 #include "test_util.h"
 
 using namespace simpleperf;
@@ -33,6 +34,7 @@ class SimplePerfReportFuzzer {
     const int32_t dataSize = mFdp.ConsumeIntegralInRange<int32_t>(0, (size * 80) / 100);
     std::vector<uint8_t> dataPointer = mFdp.ConsumeBytes<uint8_t>(dataSize);
     android::base::WriteFully(mTempfile.fd, dataPointer.data(), dataPointer.size());
+    android::base::WriteFully(mTempfileWholeData.fd, data, size);
     RegisterDumpRecordCommand();
   }
   void process();
@@ -40,18 +42,22 @@ class SimplePerfReportFuzzer {
  private:
   FuzzedDataProvider mFdp;
   TemporaryFile mTempfile;
-  void TestDumpCmd();
+  TemporaryFile mTempfileWholeData;
+  void TestPerfDataReader(const char* perf_data_path);
+  void TestDumpCmd(const char* perf_data_path);
+  void TestReportLib(const char* perf_data_path);
 };
 
-void SimplePerfReportFuzzer::TestDumpCmd() {
-  std::unique_ptr<Command> dump_cmd = CreateCommandInstance("dump");
-  CaptureStdout capture;
-  capture.Start();
-  dump_cmd->Run({"-i", mTempfile.path, "--dump-etm", "raw,packet,element"});
+void SimplePerfReportFuzzer::process() {
+  TestPerfDataReader(mTempfile.path);
+  TestDumpCmd(mTempfile.path);
+  // It is better to use whole data as input to report lib. Because the init corpuses are real
+  // recording files.
+  TestReportLib(mTempfileWholeData.path);
 }
 
-void SimplePerfReportFuzzer::process() {
-  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(mTempfile.path);
+void SimplePerfReportFuzzer::TestPerfDataReader(const char* perf_data_path) {
+  std::unique_ptr<RecordFileReader> reader = RecordFileReader::CreateInstance(perf_data_path);
   if (!reader.get()) {
     return;
   }
@@ -76,10 +82,39 @@ void SimplePerfReportFuzzer::process() {
     });
     InvokeReader();
   }
-  TestDumpCmd();
   reader->Close();
 }
 
+void SimplePerfReportFuzzer::TestDumpCmd(const char* perf_data_path) {
+  std::unique_ptr<Command> dump_cmd = CreateCommandInstance("dump");
+  CaptureStdout capture;
+  capture.Start();
+  dump_cmd->Run({"-i", perf_data_path, "--dump-etm", "raw,packet,element"});
+}
+
+void SimplePerfReportFuzzer::TestReportLib(const char* perf_data_path) {
+  ReportLib report_lib;
+  if (!report_lib.SetRecordFile(perf_data_path)) {
+    return;
+  }
+  vector<char> raw_data;
+  while (true) {
+    Sample* sample = report_lib.GetNextSample();
+    if (sample == nullptr) {
+      break;
+    }
+    const char* tracing_data = report_lib.GetTracingDataOfCurrentSample();
+    Event* event = report_lib.GetEventOfCurrentSample();
+    if (event == nullptr) {
+      break;
+    }
+    if (event->tracing_data_format.size != 0) {
+      // Test if we can read tracing data.
+      raw_data.assign(tracing_data, tracing_data + event->tracing_data_format.size);
+    }
+  }
+}
+
 extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
   SimplePerfReportFuzzer simplePerfReportFuzzer(data, size);
   simplePerfReportFuzzer.process();
diff --git a/simpleperf/profcollect.cpp b/simpleperf/profcollect.cpp
index 411dc658..439f3a88 100644
--- a/simpleperf/profcollect.cpp
+++ b/simpleperf/profcollect.cpp
@@ -25,11 +25,13 @@
 #include <include/simpleperf_profcollect.hpp>
 
 #include "ETMRecorder.h"
+#include "android-base/logging.h"
 #include "command.h"
 #include "event_attr.h"
 #include "event_fd.h"
 #include "event_selection_set.h"
 #include "event_type.h"
+#include "utils.h"
 
 using namespace simpleperf;
 
@@ -54,11 +56,17 @@ bool IsETMDriverAvailable() {
 }
 
 bool IsETMDeviceAvailable() {
-  auto result = ETMRecorder::GetInstance().CheckEtmSupport();
+  auto result = ETMRecorder::GetInstance().CheckEtmSupport(false);
   if (!result.ok()) {
     LOG(INFO) << "HasDeviceSupport check failed: " << result.error();
     return false;
   }
+  if (auto version = GetKernelVersion(); version && version.value() >= std::make_pair(6, 6)) {
+    if (ETMRecorder::GetInstance().GetCPUsHavingTRBESink().empty()) {
+      LOG(INFO) << "HasDeviceSupport check failed: requiring TRBE on >= 6.6 kernel";
+      return false;
+    }
+  }
   const EventType* type = FindEventTypeByName("cs-etm", false);
   if (type == nullptr) {
     LOG(INFO) << "HasDeviceSupport check failed: no etm event";
@@ -83,6 +91,16 @@ static std::vector<std::string> ConvertArgs(const char** args, int arg_count) {
 
 bool RunRecordCmd(const char** args, int arg_count) {
   std::vector<std::string> cmd_args = ConvertArgs(args, arg_count);
+  // If TRBE is available, only record ETM data on cpus having TRBE.
+  auto check_etm_event = [](const std::string& s) { return s.find("cs-etm") != s.npos; };
+  if (std::find_if(cmd_args.begin(), cmd_args.end(), check_etm_event) != cmd_args.end()) {
+    const std::set<int>& cpus_having_trbe = ETMRecorder::GetInstance().GetCPUsHavingTRBESink();
+    if (!cpus_having_trbe.empty()) {
+      cmd_args.push_back("--cpu");
+      cmd_args.push_back(ToCpuString(cpus_having_trbe));
+    }
+  }
+
   LOG(INFO) << "Record " << android::base::Join(cmd_args, " ");
   // The kernel may panic when trying to hibernate or hotplug CPUs while collecting
   // ETM data. So get wakelock to keep the CPUs on.
@@ -110,8 +128,7 @@ static android::base::LogFunction saved_log_func;
 static void FileLogger(android::base::LogId id, android::base::LogSeverity severity,
                        const char* tag, const char* file, unsigned int line, const char* message) {
   if (log_fd.ok()) {
-    static const char log_characters[] = "VDIWEFF";
-    char severity_char = log_characters[severity];
+    char severity_char = android::base::kSeverityChars[severity];
     struct tm now;
     time_t t = time(nullptr);
     localtime_r(&t, &now);
diff --git a/simpleperf/record_file_reader.cpp b/simpleperf/record_file_reader.cpp
index d0afb96e..344d8dca 100644
--- a/simpleperf/record_file_reader.cpp
+++ b/simpleperf/record_file_reader.cpp
@@ -808,7 +808,16 @@ bool RecordFileReader::ReadInitMapFeature(
 bool RecordFileReader::LoadBuildIdAndFileFeatures(ThreadTree& thread_tree) {
   std::vector<BuildIdRecord> records = ReadBuildIdFeature();
   std::vector<std::pair<std::string, BuildId>> build_ids;
+  std::optional<BuildId> vdso_build_id;
+
   for (auto& r : records) {
+    if (!vdso_build_id.has_value() && strcmp("[vdso]", r.filename) == 0) {
+      vdso_build_id = r.build_id;
+    } else if (vdso_build_id.has_value() && r.build_id == *vdso_build_id &&
+               std::filesystem::exists(r.filename)) {
+      Dso::SetVdsoFile(r.filename, sizeof(size_t) == sizeof(uint64_t));
+    }
+
     build_ids.push_back(std::make_pair(r.filename, r.build_id));
   }
   Dso::SetBuildIds(build_ids);
@@ -857,7 +866,8 @@ bool RecordFileReader::ReadAuxData(uint32_t cpu, uint64_t aux_offset, size_t siz
       location = &*location_it;
     }
   }
-  if (location == nullptr) {
+  if (location == nullptr ||
+      (!decompressor_ && location->aux_offset + location->aux_size < aux_offset + size)) {
     // ETM data can be dropped when recording if the userspace buffer is full. This isn't an error.
     LOG(INFO) << "aux data is missing: cpu " << cpu << ", aux_offset " << aux_offset << ", size "
               << size << ". Probably the data is lost when recording.";
diff --git a/simpleperf/report_lib_interface.cpp b/simpleperf/report_lib_interface.cpp
index 42a0ac95..cb472aba 100644
--- a/simpleperf/report_lib_interface.cpp
+++ b/simpleperf/report_lib_interface.cpp
@@ -255,7 +255,9 @@ class ReportLib {
     event_counters_view_.event_counter = event_counters_.data();
     return &event_counters_view_;
   }
-  const char* GetTracingDataOfCurrentSample() { return current_tracing_data_; }
+  const char* GetTracingDataOfCurrentSample() {
+    return current_tracing_data_.empty() ? nullptr : current_tracing_data_.data();
+  }
   const char* GetProcessNameOfCurrentSample() {
     const ThreadEntry* thread = thread_tree_.FindThread(current_sample_.pid);
     return (thread != nullptr) ? thread->comm : "unknown";
@@ -297,7 +299,7 @@ class ReportLib {
   CallChain current_callchain_;
   std::vector<EventCounter> event_counters_;
   EventCountersView event_counters_view_;
-  const char* current_tracing_data_;
+  std::vector<char> current_tracing_data_;
   std::vector<std::unique_ptr<Mapping>> current_mappings_;
   std::vector<CallChainEntry> callchain_entries_;
   std::string build_id_string_;
@@ -626,9 +628,9 @@ bool ReportLib::SetCurrentSample(std::unique_ptr<SampleRecord> sample_record) {
   current_event_.tracing_data_format = event.tracing_info.data_format;
   if (current_event_.tracing_data_format.size > 0u && (r.sample_type & PERF_SAMPLE_RAW)) {
     CHECK_GE(r.raw_data.size, current_event_.tracing_data_format.size);
-    current_tracing_data_ = r.raw_data.data;
+    current_tracing_data_.assign(r.raw_data.data, r.raw_data.data + r.raw_data.size);
   } else {
-    current_tracing_data_ = nullptr;
+    current_tracing_data_.clear();
   }
   SetEventCounters(r);
   return true;
diff --git a/simpleperf/scripts/bin/android/arm/simpleperf b/simpleperf/scripts/bin/android/arm/simpleperf
index 405f57fb..780dda07 100755
Binary files a/simpleperf/scripts/bin/android/arm/simpleperf and b/simpleperf/scripts/bin/android/arm/simpleperf differ
diff --git a/simpleperf/scripts/bin/android/arm64/simpleperf b/simpleperf/scripts/bin/android/arm64/simpleperf
index 95edda55..813d6d72 100755
Binary files a/simpleperf/scripts/bin/android/arm64/simpleperf and b/simpleperf/scripts/bin/android/arm64/simpleperf differ
diff --git a/simpleperf/scripts/bin/android/riscv64/simpleperf b/simpleperf/scripts/bin/android/riscv64/simpleperf
index 0253f1a8..74da2ec0 100755
Binary files a/simpleperf/scripts/bin/android/riscv64/simpleperf and b/simpleperf/scripts/bin/android/riscv64/simpleperf differ
diff --git a/simpleperf/scripts/bin/android/x86/simpleperf b/simpleperf/scripts/bin/android/x86/simpleperf
index 73d1108d..6f3b0315 100755
Binary files a/simpleperf/scripts/bin/android/x86/simpleperf and b/simpleperf/scripts/bin/android/x86/simpleperf differ
diff --git a/simpleperf/scripts/bin/android/x86_64/simpleperf b/simpleperf/scripts/bin/android/x86_64/simpleperf
index 7276e3ed..aecadf09 100755
Binary files a/simpleperf/scripts/bin/android/x86_64/simpleperf and b/simpleperf/scripts/bin/android/x86_64/simpleperf differ
diff --git a/simpleperf/scripts/bin/darwin/x86_64/libsimpleperf_report.dylib b/simpleperf/scripts/bin/darwin/x86_64/libsimpleperf_report.dylib
old mode 100755
new mode 100644
index b7f10324..2baae29d
Binary files a/simpleperf/scripts/bin/darwin/x86_64/libsimpleperf_report.dylib and b/simpleperf/scripts/bin/darwin/x86_64/libsimpleperf_report.dylib differ
diff --git a/simpleperf/scripts/bin/darwin/x86_64/simpleperf b/simpleperf/scripts/bin/darwin/x86_64/simpleperf
index 96b4a2e2..7818cc89 100755
Binary files a/simpleperf/scripts/bin/darwin/x86_64/simpleperf and b/simpleperf/scripts/bin/darwin/x86_64/simpleperf differ
diff --git a/simpleperf/scripts/bin/linux/x86_64/libsimpleperf_report.so b/simpleperf/scripts/bin/linux/x86_64/libsimpleperf_report.so
old mode 100755
new mode 100644
index 4924726d..9096e1da
Binary files a/simpleperf/scripts/bin/linux/x86_64/libsimpleperf_report.so and b/simpleperf/scripts/bin/linux/x86_64/libsimpleperf_report.so differ
diff --git a/simpleperf/scripts/bin/linux/x86_64/simpleperf b/simpleperf/scripts/bin/linux/x86_64/simpleperf
index b4aede5f..56d27785 100755
Binary files a/simpleperf/scripts/bin/linux/x86_64/simpleperf and b/simpleperf/scripts/bin/linux/x86_64/simpleperf differ
diff --git a/simpleperf/scripts/report.py b/simpleperf/scripts/report.py
index 973d93ee..d93f87fa 100755
--- a/simpleperf/scripts/report.py
+++ b/simpleperf/scripts/report.py
@@ -31,15 +31,6 @@ import re
 import subprocess
 import sys
 
-try:
-    from tkinter import *
-    from tkinter.font import Font
-    from tkinter.ttk import *
-except ImportError:
-    from Tkinter import *
-    from tkFont import Font
-    from ttk import *
-
 from simpleperf_utils import *
 
 PAD_X = 3
@@ -195,6 +186,10 @@ class ReportWindow(object):
     """A window used to display report file."""
 
     def __init__(self, main, report_context, title_line, report_items):
+        from tkinter import Frame, Label, Scrollbar, X, Y, W, BOTTOM, LEFT, RIGHT, BOTH, HORIZONTAL
+        from tkinter.font import Font
+        from tkinter.ttk import Treeview
+
         frame = Frame(main)
         frame.pack(fill=BOTH, expand=1)
 
@@ -270,6 +265,8 @@ class ReportWindow(object):
 
 
 def display_report_file(report_file, self_kill_after_sec):
+    from tkinter import Tk, Toplevel
+
     fh = open(report_file, 'r')
     lines = fh.readlines()
     fh.close()
diff --git a/simpleperf/scripts/simpleperf_report_lib.py b/simpleperf/scripts/simpleperf_report_lib.py
index 832bc8bb..43f7047b 100644
--- a/simpleperf/scripts/simpleperf_report_lib.py
+++ b/simpleperf/scripts/simpleperf_report_lib.py
@@ -113,18 +113,25 @@ class TracingFieldFormatStruct(ct.Structure):
         """
         if self.is_dynamic:
             offset, max_len = struct.unpack('<HH', data[self.offset:self.offset + 4])
-            length = 0
-            while length < max_len and bytes_to_str(data[offset + length]) != '\x00':
-                length += 1
-            return bytes_to_str(data[offset: offset + length])
+            try:
+                length = 0
+                while length < max_len and bytes_to_str(data[offset + length]) != '\x00':
+                    length += 1
+                return bytes_to_str(data[offset: offset + length])
+            except UnicodeDecodeError:
+                return data[offset: offset + max_len]
 
         if self.elem_count > 1 and self.elem_size == 1:
             # Probably the field is a string.
             # Don't use self.is_signed, which has different values on x86 and arm.
-            length = 0
-            while length < self.elem_count and bytes_to_str(data[self.offset + length]) != '\x00':
-                length += 1
-            return bytes_to_str(data[self.offset: self.offset + length])
+            try:
+                length = 0
+                while length < self.elem_count and bytes_to_str(
+                        data[self.offset + length]) != '\x00':
+                    length += 1
+                return bytes_to_str(data[self.offset: self.offset + length])
+            except UnicodeDecodeError:
+                pass
         unpack_key = self._unpack_key_dict.get(self.elem_size)
         if unpack_key:
             if not self.is_signed:
@@ -240,6 +247,7 @@ class EventCounterStructure(ct.Structure):
     def name(self) -> str:
         return _char_pt_to_str(self._name)
 
+
 class EventCountersViewStructure(ct.Structure):
     """ An array of event counter.
         nr: number of event counters in the array.
@@ -249,7 +257,6 @@ class EventCountersViewStructure(ct.Structure):
                 ('event_counter', ct.POINTER(EventCounterStructure))]
 
 
-
 class FeatureSectionStructure(ct.Structure):
     """ A feature section in perf.data to store information like record cmd, device arch, etc.
         data: a pointer to a buffer storing the section data.
diff --git a/simpleperf/scripts/update.py b/simpleperf/scripts/update.py
index ef2f84d3..d20f5959 100755
--- a/simpleperf/scripts/update.py
+++ b/simpleperf/scripts/update.py
@@ -35,35 +35,35 @@ class InstallEntry(object):
 
 INSTALL_LIST = [
     # simpleperf on device.
-    InstallEntry('MODULES-IN-system-extras-simpleperf',
+    InstallEntry('simpleperf_linux_arm64-trunk_staging',
                  'simpleperf/android/arm64/simpleperf_ndk',
                  'android/arm64/simpleperf'),
-    InstallEntry('MODULES-IN-system-extras-simpleperf_arm',
+    InstallEntry('simpleperf_linux_arm64-trunk_staging',
                  'simpleperf/android/arm/simpleperf_ndk32',
                  'android/arm/simpleperf'),
-    InstallEntry('MODULES-IN-system-extras-simpleperf_x86',
+    InstallEntry('simpleperf_linux_x86_64-trunk_staging',
                  'simpleperf/android/x86_64/simpleperf_ndk',
                  'android/x86_64/simpleperf'),
-    InstallEntry('MODULES-IN-system-extras-simpleperf_x86',
+    InstallEntry('simpleperf_linux_x86_64-trunk_staging',
                  'simpleperf/android/x86/simpleperf_ndk32',
                  'android/x86/simpleperf'),
-    InstallEntry('MODULES-IN-system-extras-simpleperf_riscv64',
+    InstallEntry('simpleperf_linux_riscv64-trunk_staging',
                  'simpleperf_ndk',
                  'android/riscv64/simpleperf'),
 
     # simpleperf on host.
-    InstallEntry('MODULES-IN-system-extras-simpleperf',
+    InstallEntry('simpleperf_linux_arm64-trunk_staging',
                  'simpleperf/linux/x86_64/simpleperf',
                  'linux/x86_64/simpleperf', True),
-    InstallEntry('MODULES-IN-system-extras-simpleperf_mac',
+    InstallEntry('simpleperf_mac-trunk_staging',
                  'simpleperf/darwin/x86_64/simpleperf',
                  'darwin/x86_64/simpleperf'),
 
     # libsimpleperf_report.so on host
-    InstallEntry('MODULES-IN-system-extras-simpleperf',
+    InstallEntry('simpleperf_linux_arm64-trunk_staging',
                  'simpleperf/linux/x86_64/libsimpleperf_report.so',
                  'linux/x86_64/libsimpleperf_report.so', True),
-    InstallEntry('MODULES-IN-system-extras-simpleperf_mac',
+    InstallEntry('simpleperf_mac-trunk_staging',
                  'simpleperf/darwin/x86_64/libsimpleperf_report.dylib',
                  'darwin/x86_64/libsimpleperf_report.dylib'),
 ]
@@ -154,7 +154,7 @@ def get_args():
     parser = argparse.ArgumentParser()
 
     parser.add_argument(
-        '-b', '--branch', default='aosp-simpleperf-release',
+        '-b', '--branch', default='git_main-without-vendor',
         help='Branch to pull build from.')
     parser.add_argument('--build', required=True, help='Build number to pull.')
     parser.add_argument(
diff --git a/simpleperf/simpleperf_app_runner/simpleperf_app_runner.cpp b/simpleperf/simpleperf_app_runner/simpleperf_app_runner.cpp
index f3e6b4b5..70605e9e 100644
--- a/simpleperf/simpleperf_app_runner/simpleperf_app_runner.cpp
+++ b/simpleperf/simpleperf_app_runner/simpleperf_app_runner.cpp
@@ -124,41 +124,62 @@ static void CheckSimpleperfArguments(std::string_view cmd_name, char** args) {
   }
 
   for (size_t i = 0; args[i] != nullptr; ++i) {
-    auto it = formats->find(args[i]);
+    std::string option = args[i];
+    std::string option_value;
+    auto it = formats->find(option);
     if (it == formats->end()) {
-      it = common_formats.find(args[i]);
+      if (auto pos = option.find("="); pos != std::string::npos) {
+        option_value = option.substr(pos + 1);
+        option.resize(pos);
+        it = formats->find(option);
+      }
+      it = common_formats.find(option);
       if (it == common_formats.end()) {
-        error(1, 0, "arg isn't allowed: %s", args[i]);
+        error(1, 0, "arg isn't allowed: %s", option.c_str());
       }
     }
     const OptionFormat& format = it->second;
-    if (format.value_type != OptionValueType::NONE && args[i + 1] == nullptr) {
-      error(1, 0, "invalid arg: %s", args[i]);
+    switch (format.value_type) {
+      case OptionValueType::NONE:
+        break;
+      case OptionValueType::OPT_STRING:
+        if (args[i + 1] != nullptr && args[i + 1][0] != '-') {
+          option_value = args[++i];
+        }
+        break;
+      case OptionValueType::OPT_STRING_AFTER_EQUAL:
+        break;
+      case OptionValueType::STRING:
+      case OptionValueType::UINT:
+      case OptionValueType::DOUBLE:
+        if (args[i + 1] == nullptr) {
+          error(1, 0, "arg missing value: %s", option.c_str());
+        }
+        option_value = args[++i];
+        break;
     }
+
     switch (format.app_runner_type) {
       case AppRunnerType::ALLOWED:
         break;
       case AppRunnerType::NOT_ALLOWED:
-        error(1, 0, "arg isn't allowed: %s", args[i]);
+        error(1, 0, "arg isn't allowed: %s", option.c_str());
         break;
       case AppRunnerType::CHECK_FD: {
         int fd;
-        if (!ParseInt(args[i + 1], &fd) || fd < 3 || fcntl(fd, F_GETFD) == -1) {
-          error(1, 0, "invalid fd for arg: %s", args[i]);
+        if (!ParseInt(option_value, &fd) || fd < 3 || fcntl(fd, F_GETFD) == -1) {
+          error(1, 0, "invalid fd for arg: %s", option.c_str());
         }
         break;
       }
       case AppRunnerType::CHECK_PATH: {
         std::string path;
-        if (!Realpath(args[i + 1], &path) || !StartsWith(path, "/data/local/tmp/")) {
-          error(1, 0, "invalid path for arg: %s", args[i]);
+        if (!Realpath(option_value, &path) || !StartsWith(path, "/data/local/tmp/")) {
+          error(1, 0, "invalid path for arg: %s", option.c_str());
         }
         break;
       }
     }
-    if (format.value_type != OptionValueType::NONE) {
-      ++i;
-    }
   }
 }
 
diff --git a/simpleperf/testdata/etm/perf_etm_compressed.data b/simpleperf/testdata/etm/perf_etm_compressed.data
new file mode 100644
index 00000000..722e388f
Binary files /dev/null and b/simpleperf/testdata/etm/perf_etm_compressed.data differ
diff --git a/simpleperf/testdata/etm/perf_etm_with_decode_etm.data b/simpleperf/testdata/etm/perf_etm_with_decode_etm.data
new file mode 100644
index 00000000..bce5987f
Binary files /dev/null and b/simpleperf/testdata/etm/perf_etm_with_decode_etm.data differ
diff --git a/simpleperf/testdata/etm/perf_etm_wrong_aux.data b/simpleperf/testdata/etm/perf_etm_wrong_aux.data
new file mode 100644
index 00000000..654938ad
Binary files /dev/null and b/simpleperf/testdata/etm/perf_etm_wrong_aux.data differ
diff --git a/simpleperf/utils.cpp b/simpleperf/utils.cpp
index dc0d8447..95c1d688 100644
--- a/simpleperf/utils.cpp
+++ b/simpleperf/utils.cpp
@@ -410,6 +410,39 @@ std::optional<std::set<int>> GetCpusFromString(const std::string& s) {
   return cpus;
 }
 
+std::string ToCpuString(const std::set<int>& cpus) {
+  if (cpus.empty()) {
+    return "";
+  }
+  auto it = cpus.begin();
+  int cpu1 = -1;
+  int cpu2 = -1;
+  std::string s;
+  auto add_cpu_range = [&]() {
+    if (!s.empty()) {
+      s.push_back(',');
+    }
+    if (cpu1 == cpu2) {
+      s += std::to_string(cpu1);
+    } else {
+      s += std::to_string(cpu1) + "-" + std::to_string(cpu2);
+    }
+  };
+
+  for (int cpu : cpus) {
+    if (cpu1 == -1) {
+      cpu1 = cpu2 = cpu;
+    } else if (cpu2 + 1 == cpu) {
+      cpu2 = cpu;
+    } else {
+      add_cpu_range();
+      cpu1 = cpu2 = cpu;
+    }
+  }
+  add_cpu_range();
+  return s;
+}
+
 std::optional<std::set<pid_t>> GetTidsFromString(const std::string& s, bool check_if_exists) {
   std::set<pid_t> tids;
   for (const auto& p : Split(s, ",")) {
diff --git a/simpleperf/utils.h b/simpleperf/utils.h
index 4ae9164f..fb626f7a 100644
--- a/simpleperf/utils.h
+++ b/simpleperf/utils.h
@@ -255,6 +255,7 @@ timeval SecondToTimeval(double time_in_sec);
 std::string GetSimpleperfVersion();
 
 std::optional<std::set<int>> GetCpusFromString(const std::string& s);
+std::string ToCpuString(const std::set<int>& cpus);
 std::optional<std::set<pid_t>> GetTidsFromString(const std::string& s, bool check_if_exists);
 std::optional<std::set<pid_t>> GetPidsFromStrings(const std::vector<std::string>& strs,
                                                   bool check_if_exists,
diff --git a/simpleperf/utils_test.cpp b/simpleperf/utils_test.cpp
index 747c020f..f60f1091 100644
--- a/simpleperf/utils_test.cpp
+++ b/simpleperf/utils_test.cpp
@@ -73,6 +73,10 @@ TEST(utils, GetCpusFromString) {
   ASSERT_EQ(GetCpusFromString(""), std::nullopt);
   ASSERT_EQ(GetCpusFromString("-3"), std::nullopt);
   ASSERT_EQ(GetCpusFromString("3,2-1"), std::nullopt);
+  ASSERT_EQ("0-2", ToCpuString(std::set<int>({0, 1, 2})));
+  ASSERT_EQ("0,2-3", ToCpuString(std::set<int>({0, 2, 3})));
+  ASSERT_EQ("0-3,5,7-8", ToCpuString(std::set<int>({0, 1, 2, 3, 5, 7, 8})));
+  ASSERT_EQ("", ToCpuString(std::set<int>({})));
 }
 
 // @CddTest = 6.1/C-0-2
diff --git a/torq/Android.bp b/torq/Android.bp
index 6546f0f0..d0b853dc 100644
--- a/torq/Android.bp
+++ b/torq/Android.bp
@@ -74,6 +74,17 @@ python_test_host {
     },
 }
 
+python_test_host {
+    name: "config_command_executor_unit_test",
+    main: "tests/config_command_executor_unit_test.py",
+    srcs: ["tests/config_command_executor_unit_test.py"],
+    defaults: ["torq_defaults"],
+    embedded_launcher: false,
+    test_options: {
+        unit_test: true,
+    },
+}
+
 python_test_host {
     name: "validate_simpleperf_unit_test",
     main: "tests/validate_simpleperf_unit_test.py",
diff --git a/torq/README.md b/torq/README.md
index 6acb3618..784a5fc5 100644
--- a/torq/README.md
+++ b/torq/README.md
@@ -70,7 +70,7 @@ config, in which the ftrace event, power/cpu_idle, is not collected.
 | `-e, --event`                              | The event to trace/profile.                                                                                                                                                                                                                                                        | `boot`, `user-switch`,`app-startup`, `custom`                                                | `custom`                             |
 | `-p, --profiler`                           | The performance data profiler.                                                                                                                                                                                                                                                     | `perfetto`, (`simpleperf` coming soon)                                                       | `perfetto`                           |
 | `-o, --out-dir`                            | The path to the output directory.                                                                                                                                                                                                                                                  | Any local path                                                                               | Current directory: `.`               |
-| `-d, --dur-ms`                             | The duration (ms) of the event. Determines when to stop collecting performance data.                                                                                                                                                                                               | Float >= `3000`                                                                              | `10000`                              |
+| `-d, --dur-ms`                             | The duration (ms) of the event. Determines when to stop collecting performance data.                                                                                                                                                                                               | Float >= `3000`                                                                              | Indefinite until CTRL+C              |
 | `-a, --app`                                | The package name of the app to start.<br/>(Requires use of `-e app-startup`)                                                                                                                                                                                                       | Any package on connected device                                                              |                                      |
 | `-r, --runs`                               | The amount of times to run the event and capture the performance data.                                                                                                                                                                                                             | Integer >= `1`                                                                               | `1`                                  |
 | `-s, --simpleperf-event`                   | Simpleperf supported events that should be collected. Can be defined multiple times in a command. (Requires use of `-p simpleperf`).                                                                                                                                               | Any supported simpleperf event<br/>(e.g., `cpu-cycles`, `instructions`)                      | `cpu-clock`                          |
diff --git a/torq/src/command.py b/torq/src/command.py
index 699fd2da..a963f933 100644
--- a/torq/src/command.py
+++ b/torq/src/command.py
@@ -22,6 +22,7 @@ from .validation_error import ValidationError
 from .open_ui import open_trace
 
 ANDROID_SDK_VERSION_T = 33
+PERFETTO_DEVICE_TRACE_FOLDER = "/data/misc/perfetto-traces"
 
 class Command(ABC):
   """
@@ -82,6 +83,9 @@ class ProfilerCommand(Command):
 
   def validate(self, device):
     print("Further validating arguments of ProfilerCommand.")
+    error = self.validate_trace_folder(device)
+    if error is not None:
+      return error
     if self.simpleperf_event is not None:
       error = device.simpleperf_event_exists(self.simpleperf_event)
       if error is not None:
@@ -139,6 +143,15 @@ class ProfilerCommand(Command):
                               % (device.serial, self.app, self.app)))
     return None
 
+  def validate_trace_folder(self, device):
+    if not device.file_exists(PERFETTO_DEVICE_TRACE_FOLDER):
+      return ValidationError("%s folder does not exist on device with"
+                             " serial %s." % (PERFETTO_DEVICE_TRACE_FOLDER,
+                                              device.serial),
+                             "Make sure that your device has %s properly"
+                             " configured." % self.profiler.capitalize())
+    return None
+
 
 class ConfigCommand(Command):
   """
diff --git a/torq/src/command_executor.py b/torq/src/command_executor.py
index 5993cac6..c472e684 100644
--- a/torq/src/command_executor.py
+++ b/torq/src/command_executor.py
@@ -15,12 +15,14 @@
 #
 
 import datetime
+import signal
 import subprocess
 import time
 from abc import ABC, abstractmethod
 from .config_builder import PREDEFINED_PERFETTO_CONFIGS, build_custom_config
+from .handle_input import HandleInput
 from .open_ui import open_trace
-from .device import SIMPLEPERF_TRACE_FILE
+from .device import SIMPLEPERF_TRACE_FILE, POLLING_INTERVAL_SECS
 from .utils import convert_simpleperf_to_gecko
 
 PERFETTO_TRACE_FILE = "/data/misc/perfetto-traces/trace.perfetto-trace"
@@ -29,6 +31,7 @@ WEB_UI_ADDRESS = "https://ui.perfetto.dev"
 TRACE_START_DELAY_SECS = 0.5
 MAX_WAIT_FOR_INIT_USER_SWITCH_SECS = 180
 ANDROID_SDK_VERSION_T = 33
+SIMPLEPERF_STOP_TIMEOUT_SECS = 60
 
 
 class CommandExecutor(ABC):
@@ -39,6 +42,8 @@ class CommandExecutor(ABC):
     pass
 
   def execute(self, command, device):
+    for sig in [signal.SIGINT, signal.SIGTERM]:
+      signal.signal(sig, lambda s, f: self.signal_handler(s,f))
     error = device.check_device_connection()
     if error is not None:
       return error
@@ -52,9 +57,14 @@ class CommandExecutor(ABC):
   def execute_command(self, command, device):
     raise NotImplementedError
 
+  def signal_handler(self, sig, frame):
+    pass
 
 class ProfilerCommandExecutor(CommandExecutor):
 
+  def __init__(self):
+    self.trace_cancelled = False
+
   def execute_command(self, command, device):
     config, error = self.create_config(command, device.get_android_sdk_version())
     if error is not None:
@@ -74,24 +84,38 @@ class ProfilerCommandExecutor(CommandExecutor):
       error = self.prepare_device_for_run(command, device)
       if error is not None:
         return error
+      start_time = time.time()
+      if self.trace_cancelled:
+        return self.cleanup(command, device)
       error = self.execute_run(command, device, config, run)
       if error is not None:
         return error
-      error = self.retrieve_perf_data(command, device, host_raw_trace_filename,
+      print("Run lasted for %.3f seconds." % (time.time() - start_time))
+      error = self.retrieve_perf_data(command, device,
+                                      host_raw_trace_filename,
                                       host_gecko_trace_filename)
       if error is not None:
         return error
       if command.runs != run:
+        if self.trace_cancelled:
+          if not HandleInput("Continue with remaining runs? [Y/n]: ",
+                             "",
+                             {"y": lambda: True,
+                              "n": lambda: False}, "y").handle_input():
+            return self.cleanup(command, device)
+          self.trace_cancelled = False
+        print("Waiting for %d seconds before next run."
+              % (command.between_dur_ms / 1000))
         time.sleep(command.between_dur_ms / 1000)
     error = self.cleanup(command, device)
     if error is not None:
       return error
     if command.use_ui:
-        error = open_trace(host_raw_trace_filename
-                           if command.profiler == "perfetto" else
-                           host_gecko_trace_filename, WEB_UI_ADDRESS, False)
-        if error is not None:
-          return error
+      error = open_trace(host_raw_trace_filename
+                         if command.profiler == "perfetto" else
+                         host_gecko_trace_filename, WEB_UI_ADDRESS, False)
+      if error is not None:
+        return error
     return None
 
   @staticmethod
@@ -112,7 +136,7 @@ class ProfilerCommandExecutor(CommandExecutor):
       device.remove_file(SIMPLEPERF_TRACE_FILE)
 
   def execute_run(self, command, device, config, run):
-    print("Performing run %s" % run)
+    print("Performing run %s. Press CTRL+C to end the trace." % run)
     if command.profiler == "perfetto":
       process = device.start_perfetto_trace(config)
     else:
@@ -120,9 +144,15 @@ class ProfilerCommandExecutor(CommandExecutor):
     time.sleep(TRACE_START_DELAY_SECS)
     error = self.trigger_system_event(command, device)
     if error is not None:
-      device.kill_pid(command.profiler)
+      print("Trace interrupted.")
+      self.stop_process(device, command.profiler)
       return error
-    process.wait()
+    while process.poll() is None and not self.trace_cancelled:
+      continue
+    if process.poll() is None:
+      print("Trace interrupted.")
+      self.stop_process(device, command.profiler)
+    return None
 
   def trigger_system_event(self, command, device):
     return None
@@ -139,21 +169,39 @@ class ProfilerCommandExecutor(CommandExecutor):
   def cleanup(self, command, device):
     return None
 
+  def signal_handler(self, sig, frame):
+    self.trace_cancelled = True
+
+  def stop_process(self, device, name):
+    if name == "simpleperf":
+      device.send_signal(name, "SIGINT")
+      # Simpleperf does post-processing, need to wait until the package stops
+      # running
+      print("Doing post-processing.")
+      if not device.poll_is_task_completed(SIMPLEPERF_STOP_TIMEOUT_SECS,
+                                           POLLING_INTERVAL_SECS,
+                                           lambda:
+                                           not device.is_package_running(name)):
+        raise Exception("Simpleperf post-processing took too long.")
+    else:
+      device.kill_process(name)
+
 
 class UserSwitchCommandExecutor(ProfilerCommandExecutor):
 
   def prepare_device_for_run(self, command, device):
     super().prepare_device_for_run(command, device)
     current_user = device.get_current_user()
+    if self.trace_cancelled:
+      return None
     if command.from_user != current_user:
-      dur_seconds = min(command.dur_ms / 1000,
-                        MAX_WAIT_FOR_INIT_USER_SWITCH_SECS)
-      print("Switching from the current user, %s, to the from-user, %s. Waiting"
-            " for %s seconds."
-            % (current_user, command.from_user, dur_seconds))
+      print("Switching from the current user, %s, to the from-user, %s."
+            % (current_user, command.from_user))
       device.perform_user_switch(command.from_user)
-      time.sleep(dur_seconds)
-      if device.get_current_user() != command.from_user:
+      if not device.poll_is_task_completed(MAX_WAIT_FOR_INIT_USER_SWITCH_SECS,
+                                           POLLING_INTERVAL_SECS,
+                                           lambda: device.get_current_user()
+                                                   == command.from_user):
         raise Exception(("Device with serial %s took more than %d secs to "
                          "switch to the initial user."
                          % (device.serial, dur_seconds)))
@@ -180,14 +228,23 @@ class BootCommandExecutor(ProfilerCommandExecutor):
     device.set_prop("persist.debug.perfetto.boottrace", "1")
 
   def execute_run(self, command, device, config, run):
-    print("Performing run %s" % run)
+    print("Performing run %s. Triggering reboot." % run)
     self.trigger_system_event(command, device)
     device.wait_for_device()
     device.root_device()
-    dur_seconds = command.dur_ms / 1000
-    print("Tracing for %s seconds." % dur_seconds)
-    time.sleep(dur_seconds)
+    if command.dur_ms is not None:
+      print("Tracing for %s seconds. Press CTRL+C to end early."
+            % (command.dur_ms / 1000))
+    else:
+      print("Tracing. Press CTRL+C to end.")
     device.wait_for_boot_to_complete()
+    while (device.is_package_running(command.profiler)
+           and not self.trace_cancelled):
+      continue
+    if device.is_package_running(command.profiler):
+      print("Trace interrupted.")
+      self.stop_process(device, command.profiler)
+    return None
 
   def trigger_system_event(self, command, device):
     device.reboot()
diff --git a/torq/src/config_builder.py b/torq/src/config_builder.py
index 5a004a7d..b8ae438b 100644
--- a/torq/src/config_builder.py
+++ b/torq/src/config_builder.py
@@ -54,10 +54,6 @@ def create_ftrace_events_string(predefined_ftrace_events,
 
 
 def build_default_config(command, android_sdk_version):
-  if command.dur_ms is None:
-    # This is always defined because it has a default value that is always
-    # set in torq.py.
-    raise ValueError("Cannot create config because a valid dur_ms was not set.")
   predefined_ftrace_events = [
       "dmabuf_heap/dma_heap_stat",
       "ftrace/print",
@@ -96,6 +92,9 @@ def build_default_config(command, android_sdk_version):
   cpufreq_period_string = "cpufreq_period_ms: 500"
   if android_sdk_version < ANDROID_SDK_VERSION_T:
     cpufreq_period_string = ""
+  duration_string = ""
+  if command.dur_ms is not None:
+    duration_string = "duration_ms: %d" % command.dur_ms
   config = f'''\
     <<EOF
 
@@ -211,21 +210,158 @@ def build_default_config(command, android_sdk_version):
           atrace_categories: "video"
           atrace_categories: "view"
           atrace_categories: "wm"
+          atrace_apps: "*"
+          buffer_size_kb: 16384
+          drain_period_ms: 150
+          symbolize_ksyms: true
+        }}
+      }}
+    }}
+
+    data_sources {{
+      config {{
+        name: "perfetto.metatrace"
+        target_buffer: 2
+      }}
+      producer_name_filter: "perfetto.traced_probes"
+    }}
+
+    {duration_string}
+    write_into_file: true
+    file_write_period_ms: 5000
+    max_file_size_bytes: 100000000000
+    flush_period_ms: 5000
+    incremental_state_config {{
+      clear_period_ms: 5000
+    }}
+
+    EOF'''
+  return textwrap.dedent(config), None
+
+
+def build_lightweight_config(command, android_sdk_version):
+  predefined_ftrace_events = [
+      "power/cpu_idle",
+      "sched/sched_blocked_reason",
+      "sched/sched_switch",
+      "sched/sched_wakeup",
+      "sched/sched_wakeup_new",
+      "sched/sched_waking",
+  ]
+  ftrace_events_string, error = create_ftrace_events_string(
+      predefined_ftrace_events, command.excluded_ftrace_events,
+      command.included_ftrace_events)
+  if error is not None:
+    return None, error
+  cpufreq_period_string = "cpufreq_period_ms: 500"
+  if android_sdk_version < ANDROID_SDK_VERSION_T:
+    cpufreq_period_string = ""
+  duration_string = ""
+  if command.dur_ms is not None:
+    duration_string = "duration_ms: %d" % command.dur_ms
+  config = f'''\
+    <<EOF
+
+    buffers: {{
+      size_kb: 4096
+      fill_policy: RING_BUFFER
+    }}
+    buffers {{
+      size_kb: 4096
+      fill_policy: RING_BUFFER
+    }}
+    buffers: {{
+      size_kb: 260096
+      fill_policy: RING_BUFFER
+    }}
+
+    data_sources: {{
+      config {{
+        name: "linux.process_stats"
+        process_stats_config {{
+          scan_all_processes_on_start: true
+        }}
+      }}
+    }}
+
+    data_sources: {{
+      config {{
+        name: "android.log"
+        android_log_config {{
+          min_prio: PRIO_ERROR
+        }}
+      }}
+    }}
+
+    data_sources {{
+      config {{
+        name: "android.packages_list"
+      }}
+    }}
+
+    data_sources: {{
+      config {{
+        name: "linux.sys_stats"
+        target_buffer: 1
+        sys_stats_config {{
+          stat_period_ms: 500
+          stat_counters: STAT_CPU_TIMES
+          meminfo_period_ms: 1000
+          meminfo_counters: MEMINFO_MEM_FREE
+          {cpufreq_period_string}
+        }}
+      }}
+    }}
+
+    data_sources: {{
+      config {{
+        name: "linux.ftrace"
+        target_buffer: 2
+        ftrace_config {{
+          {ftrace_events_string}
+          atrace_categories: "aidl"
+          atrace_categories: "am"
+          atrace_categories: "binder_lock"
+          atrace_categories: "binder_driver"
+          atrace_categories: "dalvik"
+          atrace_categories: "disk"
+          atrace_categories: "freq"
+          atrace_categories: "idle"
+          atrace_categories: "gfx"
+          atrace_categories: "hal"
+          atrace_categories: "input"
+          atrace_categories: "pm"
+          atrace_categories: "power"
+          atrace_categories: "res"
+          atrace_categories: "rro"
+          atrace_categories: "sched"
+          atrace_categories: "sm"
+          atrace_categories: "ss"
+          atrace_categories: "view"
+          atrace_categories: "wm"
           atrace_apps: "lmkd"
           atrace_apps: "system_server"
+          atrace_apps: "com.android.car"
           atrace_apps: "com.android.systemui"
           atrace_apps: "com.google.android.gms"
           atrace_apps: "com.google.android.gms.persistent"
           atrace_apps: "android:ui"
-          atrace_apps: "com.google.android.apps.maps"
-          atrace_apps: "*"
           buffer_size_kb: 16384
           drain_period_ms: 150
           symbolize_ksyms: true
         }}
       }}
     }}
-    duration_ms: {command.dur_ms}
+
+    data_sources {{
+      config {{
+        name: "perfetto.metatrace"
+        target_buffer: 2
+      }}
+      producer_name_filter: "perfetto.traced_probes"
+    }}
+
+    {duration_string}
     write_into_file: true
     file_write_period_ms: 5000
     max_file_size_bytes: 100000000000
@@ -238,12 +374,184 @@ def build_default_config(command, android_sdk_version):
   return textwrap.dedent(config), None
 
 
-def build_lightweight_config(command, android_sdk_version):
-  raise NotImplementedError
+def build_memory_config(command, android_sdk_version):
+  predefined_ftrace_events = [
+      "dmabuf_heap/dma_heap_stat",
+      "ftrace/print",
+      "gpu_mem/gpu_mem_total",
+      "ion/ion_stat",
+      "kmem/ion_heap_grow",
+      "kmem/ion_heap_shrink",
+      "kmem/rss_stat",
+      "lowmemorykiller/lowmemory_kill",
+      "mm_event/mm_event_record",
+      "oom/mark_victim",
+      "oom/oom_score_adj_update",
+      "sched/sched_blocked_reason",
+      "sched/sched_switch",
+      "sched/sched_wakeup",
+      "sched/sched_wakeup_new",
+      "sched/sched_waking",
+  ]
+  ftrace_events_string, error = create_ftrace_events_string(
+      predefined_ftrace_events, command.excluded_ftrace_events,
+      command.included_ftrace_events)
+  if error is not None:
+    return None, error
+  cpufreq_period_string = "cpufreq_period_ms: 500"
+  if android_sdk_version < ANDROID_SDK_VERSION_T:
+    cpufreq_period_string = ""
+  duration_string = ""
+  if command.dur_ms is not None:
+    duration_string = "duration_ms: %d" % command.dur_ms
+  config = f'''\
+    <<EOF
 
+    buffers: {{
+      size_kb: 4096
+      fill_policy: RING_BUFFER
+    }}
+    buffers {{
+      size_kb: 4096
+      fill_policy: RING_BUFFER
+    }}
+    buffers: {{
+      size_kb: 260096
+      fill_policy: RING_BUFFER
+    }}
 
-def build_memory_config(command, android_sdk_version):
-  raise NotImplementedError
+    data_sources: {{
+      config {{
+        name: "linux.process_stats"
+        process_stats_config {{
+          scan_all_processes_on_start: true
+        }}
+      }}
+    }}
+
+    data_sources: {{
+      config {{
+        name: "android.log"
+        android_log_config {{
+          min_prio: PRIO_ERROR
+        }}
+      }}
+    }}
+
+    data_sources {{
+      config {{
+        name: "android.packages_list"
+      }}
+    }}
+
+    data_sources: {{
+      config {{
+        name: "linux.sys_stats"
+        target_buffer: 1
+        sys_stats_config {{
+          stat_period_ms: 500
+          stat_counters: STAT_CPU_TIMES
+          stat_counters: STAT_FORK_COUNT
+          meminfo_period_ms: 1000
+          meminfo_counters: MEMINFO_ACTIVE_ANON
+          meminfo_counters: MEMINFO_ACTIVE_FILE
+          meminfo_counters: MEMINFO_INACTIVE_ANON
+          meminfo_counters: MEMINFO_INACTIVE_FILE
+          meminfo_counters: MEMINFO_KERNEL_STACK
+          meminfo_counters: MEMINFO_MLOCKED
+          meminfo_counters: MEMINFO_SHMEM
+          meminfo_counters: MEMINFO_SLAB
+          meminfo_counters: MEMINFO_SLAB_UNRECLAIMABLE
+          meminfo_counters: MEMINFO_VMALLOC_USED
+          meminfo_counters: MEMINFO_MEM_FREE
+          meminfo_counters: MEMINFO_SWAP_FREE
+          meminfo_counters: MEMINFO_MEM_AVAILABLE
+          meminfo_counters: MEMINFO_MEM_TOTAL
+          vmstat_period_ms: 1000
+          vmstat_counters: VMSTAT_NR_FREE_PAGES
+          vmstat_counters: VMSTAT_NR_ALLOC_BATCH
+          vmstat_counters: VMSTAT_NR_INACTIVE_ANON
+          vmstat_counters: VMSTAT_NR_ACTIVE_ANON
+          vmstat_counters: VMSTAT_PGFAULT
+          vmstat_counters: VMSTAT_PGMAJFAULT
+          vmstat_counters: VMSTAT_PGFREE
+          vmstat_counters: VMSTAT_PGPGIN
+          vmstat_counters: VMSTAT_PGPGOUT
+          vmstat_counters: VMSTAT_PSWPIN
+          vmstat_counters: VMSTAT_PSWPOUT
+          vmstat_counters: VMSTAT_PGSCAN_DIRECT
+          vmstat_counters: VMSTAT_PGSTEAL_DIRECT
+          vmstat_counters: VMSTAT_PGSCAN_KSWAPD
+          vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
+          vmstat_counters: VMSTAT_WORKINGSET_REFAULT
+          {cpufreq_period_string}
+        }}
+      }}
+    }}
+
+    data_sources {{
+      config {{
+        name: "android.java_hprof"
+        target_buffer: 2
+        java_hprof_config {{
+          process_cmdline: "system_server"
+        }}
+      }}
+    }}
+
+    data_sources: {{
+      config {{
+        name: "linux.ftrace"
+        target_buffer: 2
+        ftrace_config {{
+          {ftrace_events_string}
+          atrace_categories: "aidl"
+          atrace_categories: "am"
+          atrace_categories: "binder_lock"
+          atrace_categories: "binder_driver"
+          atrace_categories: "dalvik"
+          atrace_categories: "disk"
+          atrace_categories: "freq"
+          atrace_categories: "idle"
+          atrace_categories: "gfx"
+          atrace_categories: "hal"
+          atrace_categories: "input"
+          atrace_categories: "pm"
+          atrace_categories: "power"
+          atrace_categories: "res"
+          atrace_categories: "rro"
+          atrace_categories: "sched"
+          atrace_categories: "sm"
+          atrace_categories: "ss"
+          atrace_categories: "view"
+          atrace_categories: "wm"
+          atrace_apps: "*"
+          buffer_size_kb: 16384
+          drain_period_ms: 150
+          symbolize_ksyms: true
+        }}
+      }}
+    }}
+
+    data_sources {{
+      config {{
+        name: "perfetto.metatrace"
+        target_buffer: 2
+      }}
+      producer_name_filter: "perfetto.traced_probes"
+    }}
+
+    {duration_string}
+    write_into_file: true
+    file_write_period_ms: 5000
+    max_file_size_bytes: 100000000000
+    flush_period_ms: 5000
+    incremental_state_config {{
+      clear_period_ms: 5000
+    }}
+
+    EOF'''
+  return textwrap.dedent(config), None
 
 
 PREDEFINED_PERFETTO_CONFIGS = {
@@ -256,7 +564,9 @@ PREDEFINED_PERFETTO_CONFIGS = {
 def build_custom_config(command):
   file_content = ""
   duration_prefix = "duration_ms:"
-  appended_duration = duration_prefix + " " + str(command.dur_ms)
+  appended_duration = ""
+  if command.dur_ms is not None:
+    appended_duration = duration_prefix + " " + str(command.dur_ms)
   try:
     with open(command.perfetto_config, "r") as file:
       for line in file:
diff --git a/torq/src/device.py b/torq/src/device.py
index f4c51d87..cb0df3c1 100644
--- a/torq/src/device.py
+++ b/torq/src/device.py
@@ -84,13 +84,13 @@ class AdbDevice:
       # Remove last \t
       options = options[:-1]
       chosen_serial = (HandleInput("There is more than one device currently "
-                                  "connected. Press the corresponding number "
-                                  "for the following options to choose the "
-                                  "device you want to use.\n\t%sSelect "
-                                  "device[0-%d]: "
-                                  % (options, len(devices) - 1),
-                                  "Please select a valid option.",
-                                  choices)
+                                   "connected. Press the corresponding number "
+                                   "for the following options to choose the "
+                                   "device you want to use.\n\t%sSelect "
+                                   "device[0-%d]: "
+                                   % (options, len(devices) - 1),
+                                   "Please select a valid option.",
+                                   choices)
                        .handle_input())
       if isinstance(chosen_serial, ValidationError):
         return chosen_serial
@@ -120,6 +120,11 @@ class AdbDevice:
   def remove_file(self, file_path):
     subprocess.run(["adb", "-s", self.serial, "shell", "rm", "-f", file_path])
 
+  def file_exists(self, file):
+    process = subprocess.run(["adb", "-s", self.serial, "shell", "ls",
+                              file], capture_output=True)
+    return not "No such file or directory" in process.stderr.decode("utf-8")
+
   def start_perfetto_trace(self, config):
     return subprocess.Popen(("adb -s %s shell perfetto -c - --txt -o"
                              " /data/misc/perfetto-traces/"
@@ -128,12 +133,14 @@ class AdbDevice:
 
   def start_simpleperf_trace(self, command):
     events_param = "-e " + ",".join(command.simpleperf_event)
+    duration = ""
+    if command.dur_ms is not None:
+      duration = "--duration %d" % int(math.ceil(command.dur_ms/1000))
     return subprocess.Popen(("adb -s %s shell simpleperf record -a -f 1000 "
                              "--exclude-perf --post-unwind=yes -m 8192 -g "
-                             "--duration %d %s -o %s"
-                             % (self.serial,
-                                int(math.ceil(command.dur_ms/1000)),
-                                events_param, SIMPLEPERF_TRACE_FILE)),
+                             "%s %s -o %s"
+                             % (self.serial, duration, events_param,
+                                SIMPLEPERF_TRACE_FILE)),
                             shell=True)
 
   def pull_file(self, file_path, host_file):
@@ -223,11 +230,15 @@ class AdbDevice:
                               % (package, self.serial, package)), None)
     return None
 
-  def kill_pid(self, package):
-    pid = self.get_pid(package)
+  def kill_process(self, name):
+    pid = self.get_pid(name)
     if pid != "":
       subprocess.run(["adb", "-s", self.serial, "shell", "kill", "-9", pid])
 
+  def send_signal(self, process_name, signal):
+    subprocess.run(["adb", "-s", self.serial, "shell", "pkill", "-l",
+                    signal, process_name])
+
   def force_stop_package(self, package):
     subprocess.run(["adb", "-s", self.serial, "shell", "am", "force-stop",
                     package])
diff --git a/torq/src/open_ui.py b/torq/src/open_ui.py
index d80bc169..d9dda3c5 100644
--- a/torq/src/open_ui.py
+++ b/torq/src/open_ui.py
@@ -30,7 +30,7 @@ TRACE_PROCESSOR_BINARY = "/trace_processor"
 TORQ_TEMP_TRACE_PROCESSOR = TORQ_TEMP_DIR + TRACE_PROCESSOR_BINARY
 ANDROID_PERFETTO_TOOLS_DIR = "/external/perfetto/tools"
 ANDROID_TRACE_PROCESSOR = ANDROID_PERFETTO_TOOLS_DIR + TRACE_PROCESSOR_BINARY
-LARGE_FILE_SIZE = 1024 * 1024 * 512  # 512 MB
+LARGE_FILE_SIZE = 1024 * 1024 * 1024 * 4  # 4 GiB
 WAIT_FOR_TRACE_PROCESSOR_MS = 3000
 
 
diff --git a/torq/src/torq.py b/torq/src/torq.py
index de272c8f..657c041f 100644
--- a/torq/src/torq.py
+++ b/torq/src/torq.py
@@ -56,7 +56,7 @@ def create_parser():
                       default='perfetto', help='The performance data source.')
   profiler_parser.add_argument('-o', '--out-dir', default=DEFAULT_OUT_DIR,
                       help='The path to the output directory.')
-  profiler_parser.add_argument('-d', '--dur-ms', type=int, default=DEFAULT_DUR_MS,
+  profiler_parser.add_argument('-d', '--dur-ms', type=int,
                       help=('The duration (ms) of the event. Determines when'
                             ' to stop collecting performance data.'))
   profiler_parser.add_argument('-a', '--app',
@@ -110,7 +110,7 @@ def create_parser():
                                   choices=['lightweight', 'default', 'memory'],
                                   help=('Name of the predefined perfetto'
                                         ' config to print.'))
-  config_show_parser.add_argument('-d', '--dur-ms', type=int, default=DEFAULT_DUR_MS,
+  config_show_parser.add_argument('-d', '--dur-ms', type=int,
                       help=('The duration (ms) of the event. Determines when'
                             ' to stop collecting performance data.'))
   config_show_parser.add_argument('--excluded-ftrace-events', action='append',
@@ -131,7 +131,7 @@ def create_parser():
   config_pull_parser.add_argument('file_path', nargs='?',
                                   help=('File path to copy the predefined'
                                         ' config to'))
-  config_pull_parser.add_argument('-d', '--dur-ms', type=int, default=DEFAULT_DUR_MS,
+  config_pull_parser.add_argument('-d', '--dur-ms', type=int,
                       help=('The duration (ms) of the event. Determines when'
                             ' to stop collecting performance data.'))
   config_pull_parser.add_argument('--excluded-ftrace-events', action='append',
@@ -160,30 +160,13 @@ def create_parser():
 
   return parser
 
-
-def user_changed_default_arguments(args):
-  return any([args.event != "custom",
-              args.profiler != "perfetto",
-              args.out_dir != DEFAULT_OUT_DIR,
-              args.dur_ms != DEFAULT_DUR_MS,
-              args.app is not None,
-              args.runs != 1,
-              args.simpleperf_event is not None,
-              args.perfetto_config != "default",
-              args.between_dur_ms != DEFAULT_DUR_MS,
-              args.ui is not None,
-              args.excluded_ftrace_events is not None,
-              args.included_ftrace_events is not None,
-              args.from_user is not None,
-              args.to_user is not None])
-
 def verify_profiler_args(args):
   if args.out_dir != DEFAULT_OUT_DIR and not os.path.isdir(args.out_dir):
     return None, ValidationError(
         ("Command is invalid because --out-dir is not a valid directory"
          " path: %s." % args.out_dir), None)
 
-  if args.dur_ms < MIN_DURATION_MS:
+  if args.dur_ms is not None and args.dur_ms < MIN_DURATION_MS:
     return None, ValidationError(
         ("Command is invalid because --dur-ms cannot be set to a value smaller"
          " than %d." % MIN_DURATION_MS),
diff --git a/torq/tests/config_builder_unit_test.py b/torq/tests/config_builder_unit_test.py
index e206950e..26a4f4ae 100644
--- a/torq/tests/config_builder_unit_test.py
+++ b/torq/tests/config_builder_unit_test.py
@@ -17,7 +17,8 @@
 import unittest
 import builtins
 from unittest import mock
-from src.config_builder import build_default_config, build_custom_config
+from src.config_builder import (build_default_config, build_custom_config,
+                                build_lightweight_config, build_memory_config)
 from src.command import ProfilerCommand
 from src.torq import DEFAULT_DUR_MS
 
@@ -27,7 +28,95 @@ INVALID_DUR_MS = "invalid-dur-ms"
 ANDROID_SDK_VERSION_T = 33
 ANDROID_SDK_VERSION_S_V2 = 32
 
-COMMON_DEFAULT_CONFIG_BEGINNING_STRING_1 = f'''\
+COMMON_DEFAULT_SYS_EVENTS = f'''\
+      stat_period_ms: 500
+      stat_counters: STAT_CPU_TIMES
+      stat_counters: STAT_FORK_COUNT
+      meminfo_period_ms: 1000
+      meminfo_counters: MEMINFO_ACTIVE_ANON
+      meminfo_counters: MEMINFO_ACTIVE_FILE
+      meminfo_counters: MEMINFO_INACTIVE_ANON
+      meminfo_counters: MEMINFO_INACTIVE_FILE
+      meminfo_counters: MEMINFO_KERNEL_STACK
+      meminfo_counters: MEMINFO_MLOCKED
+      meminfo_counters: MEMINFO_SHMEM
+      meminfo_counters: MEMINFO_SLAB
+      meminfo_counters: MEMINFO_SLAB_UNRECLAIMABLE
+      meminfo_counters: MEMINFO_VMALLOC_USED
+      meminfo_counters: MEMINFO_MEM_FREE
+      meminfo_counters: MEMINFO_SWAP_FREE
+      vmstat_period_ms: 1000
+      vmstat_counters: VMSTAT_PGFAULT
+      vmstat_counters: VMSTAT_PGMAJFAULT
+      vmstat_counters: VMSTAT_PGFREE
+      vmstat_counters: VMSTAT_PGPGIN
+      vmstat_counters: VMSTAT_PGPGOUT
+      vmstat_counters: VMSTAT_PSWPIN
+      vmstat_counters: VMSTAT_PSWPOUT
+      vmstat_counters: VMSTAT_PGSCAN_DIRECT
+      vmstat_counters: VMSTAT_PGSTEAL_DIRECT
+      vmstat_counters: VMSTAT_PGSCAN_KSWAPD
+      vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
+      vmstat_counters: VMSTAT_WORKINGSET_REFAULT'''
+
+COMMON_DEFAULT_FTRACE_EVENTS = f'''\
+      ftrace_events: "dmabuf_heap/dma_heap_stat"
+      ftrace_events: "ftrace/print"
+      ftrace_events: "gpu_mem/gpu_mem_total"
+      ftrace_events: "ion/ion_stat"
+      ftrace_events: "kmem/ion_heap_grow"
+      ftrace_events: "kmem/ion_heap_shrink"
+      ftrace_events: "kmem/rss_stat"
+      ftrace_events: "lowmemorykiller/lowmemory_kill"
+      ftrace_events: "mm_event/mm_event_record"
+      ftrace_events: "oom/mark_victim"
+      ftrace_events: "oom/oom_score_adj_update"
+      ftrace_events: "power/cpu_frequency"
+      ftrace_events: "power/cpu_idle"
+      ftrace_events: "power/gpu_frequency"
+      ftrace_events: "power/suspend_resume"
+      ftrace_events: "power/wakeup_source_activate"
+      ftrace_events: "power/wakeup_source_deactivate"
+      ftrace_events: "sched/sched_blocked_reason"
+      ftrace_events: "sched/sched_process_exit"
+      ftrace_events: "sched/sched_process_free"
+      ftrace_events: "sched/sched_switch"
+      ftrace_events: "sched/sched_wakeup"
+      ftrace_events: "sched/sched_wakeup_new"
+      ftrace_events: "sched/sched_waking"
+      ftrace_events: "task/task_newtask"
+      ftrace_events: "task/task_rename"
+      ftrace_events: "vmscan/*"
+      ftrace_events: "workqueue/*"'''
+
+COMMON_DEFAULT_ATRACE_EVENTS = f'''\
+      atrace_categories: "aidl"
+      atrace_categories: "am"
+      atrace_categories: "dalvik"
+      atrace_categories: "binder_lock"
+      atrace_categories: "binder_driver"
+      atrace_categories: "bionic"
+      atrace_categories: "camera"
+      atrace_categories: "disk"
+      atrace_categories: "freq"
+      atrace_categories: "idle"
+      atrace_categories: "gfx"
+      atrace_categories: "hal"
+      atrace_categories: "input"
+      atrace_categories: "pm"
+      atrace_categories: "power"
+      atrace_categories: "res"
+      atrace_categories: "rro"
+      atrace_categories: "sched"
+      atrace_categories: "sm"
+      atrace_categories: "ss"
+      atrace_categories: "thermal"
+      atrace_categories: "video"
+      atrace_categories: "view"
+      atrace_categories: "wm"
+      atrace_apps: "*"'''
+
+COMMON_DEFAULT_CONFIG_BEGINNING_STRING = f'''\
 <<EOF
 
 buffers: {{
@@ -55,7 +144,9 @@ data_sources: {{
 data_sources: {{
   config {{
     name: "android.log"
-    android_log_config {{
+    android_log_config {{'''
+
+COMMON_DEFAULT_CONFIG_SYS_STATS_BEGINNING = f'''\
     }}
   }}
 }}
@@ -70,7 +161,129 @@ data_sources: {{
   config {{
     name: "linux.sys_stats"
     target_buffer: 1
-    sys_stats_config {{
+    sys_stats_config {{'''
+
+CPUFREQ_STRING_NEW_ANDROID = f'      cpufreq_period_ms: 500'
+
+COMMON_DEFAULT_CONFIG_FTRACE_BEGINNING = f'''\
+    }}
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "android.surfaceflinger.frametimeline"
+    target_buffer: 2
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.ftrace"
+    target_buffer: 2
+    ftrace_config {{'''
+
+COMMON_DEFAULT_CONFIG_MIDDLE_STRING = f'''\
+      buffer_size_kb: 16384
+      drain_period_ms: 150
+      symbolize_ksyms: true
+    }}
+  }}
+}}
+
+data_sources {{
+  config {{
+    name: "perfetto.metatrace"
+    target_buffer: 2
+  }}
+  producer_name_filter: "perfetto.traced_probes"
+}}
+'''
+
+COMMON_CONFIG_ENDING_STRING = f'''\
+write_into_file: true
+file_write_period_ms: 5000
+max_file_size_bytes: 100000000000
+flush_period_ms: 5000
+incremental_state_config {{
+  clear_period_ms: 5000
+}}
+
+'''
+
+DEFAULT_CONFIG_9000_DUR_MS = f'''\
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING}
+{COMMON_DEFAULT_CONFIG_SYS_STATS_BEGINNING}
+{COMMON_DEFAULT_SYS_EVENTS}
+{CPUFREQ_STRING_NEW_ANDROID}
+{COMMON_DEFAULT_CONFIG_FTRACE_BEGINNING}
+{COMMON_DEFAULT_FTRACE_EVENTS}
+{COMMON_DEFAULT_ATRACE_EVENTS}
+{COMMON_DEFAULT_CONFIG_MIDDLE_STRING}
+duration_ms: {TEST_DUR_MS}
+{COMMON_CONFIG_ENDING_STRING}EOF'''
+
+
+LIGHTWEIGHT_CONFIG_9000_DUR_MS = f'''\
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING}
+      min_prio: PRIO_ERROR
+{COMMON_DEFAULT_CONFIG_SYS_STATS_BEGINNING}
+      stat_period_ms: 500
+      stat_counters: STAT_CPU_TIMES
+      meminfo_period_ms: 1000
+      meminfo_counters: MEMINFO_MEM_FREE
+{CPUFREQ_STRING_NEW_ANDROID}
+    }}
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.ftrace"
+    target_buffer: 2
+    ftrace_config {{
+      ftrace_events: "power/cpu_idle"
+      ftrace_events: "sched/sched_blocked_reason"
+      ftrace_events: "sched/sched_switch"
+      ftrace_events: "sched/sched_wakeup"
+      ftrace_events: "sched/sched_wakeup_new"
+      ftrace_events: "sched/sched_waking"
+      atrace_categories: "aidl"
+      atrace_categories: "am"
+      atrace_categories: "binder_lock"
+      atrace_categories: "binder_driver"
+      atrace_categories: "dalvik"
+      atrace_categories: "disk"
+      atrace_categories: "freq"
+      atrace_categories: "idle"
+      atrace_categories: "gfx"
+      atrace_categories: "hal"
+      atrace_categories: "input"
+      atrace_categories: "pm"
+      atrace_categories: "power"
+      atrace_categories: "res"
+      atrace_categories: "rro"
+      atrace_categories: "sched"
+      atrace_categories: "sm"
+      atrace_categories: "ss"
+      atrace_categories: "view"
+      atrace_categories: "wm"
+      atrace_apps: "lmkd"
+      atrace_apps: "system_server"
+      atrace_apps: "com.android.car"
+      atrace_apps: "com.android.systemui"
+      atrace_apps: "com.google.android.gms"
+      atrace_apps: "com.google.android.gms.persistent"
+      atrace_apps: "android:ui"
+{COMMON_DEFAULT_CONFIG_MIDDLE_STRING}
+duration_ms: {TEST_DUR_MS}
+{COMMON_CONFIG_ENDING_STRING}EOF'''
+
+
+MEMORY_CONFIG_9000_DUR_MS = f'''\
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING}
+      min_prio: PRIO_ERROR
+{COMMON_DEFAULT_CONFIG_SYS_STATS_BEGINNING}
       stat_period_ms: 500
       stat_counters: STAT_CPU_TIMES
       stat_counters: STAT_FORK_COUNT
@@ -87,7 +300,13 @@ data_sources: {{
       meminfo_counters: MEMINFO_VMALLOC_USED
       meminfo_counters: MEMINFO_MEM_FREE
       meminfo_counters: MEMINFO_SWAP_FREE
+      meminfo_counters: MEMINFO_MEM_AVAILABLE
+      meminfo_counters: MEMINFO_MEM_TOTAL
       vmstat_period_ms: 1000
+      vmstat_counters: VMSTAT_NR_FREE_PAGES
+      vmstat_counters: VMSTAT_NR_ALLOC_BATCH
+      vmstat_counters: VMSTAT_NR_INACTIVE_ANON
+      vmstat_counters: VMSTAT_NR_ACTIVE_ANON
       vmstat_counters: VMSTAT_PGFAULT
       vmstat_counters: VMSTAT_PGMAJFAULT
       vmstat_counters: VMSTAT_PGFREE
@@ -99,19 +318,19 @@ data_sources: {{
       vmstat_counters: VMSTAT_PGSTEAL_DIRECT
       vmstat_counters: VMSTAT_PGSCAN_KSWAPD
       vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
-      vmstat_counters: VMSTAT_WORKINGSET_REFAULT'''
-
-CPUFREQ_STRING_NEW_ANDROID = f'      cpufreq_period_ms: 500'
-
-COMMON_DEFAULT_CONFIG_BEGINNING_STRING_2 = f'''\
+      vmstat_counters: VMSTAT_WORKINGSET_REFAULT
+{CPUFREQ_STRING_NEW_ANDROID}
     }}
   }}
 }}
 
-data_sources: {{
+data_sources {{
   config {{
-    name: "android.surfaceflinger.frametimeline"
+    name: "android.java_hprof"
     target_buffer: 2
+    java_hprof_config {{
+      process_cmdline: "system_server"
+    }}
   }}
 }}
 
@@ -119,16 +338,28 @@ data_sources: {{
   config {{
     name: "linux.ftrace"
     target_buffer: 2
-    ftrace_config {{'''
-
-COMMON_DEFAULT_CONFIG_MIDDLE_STRING = f'''\
+    ftrace_config {{
+      ftrace_events: "dmabuf_heap/dma_heap_stat"
+      ftrace_events: "ftrace/print"
+      ftrace_events: "gpu_mem/gpu_mem_total"
+      ftrace_events: "ion/ion_stat"
+      ftrace_events: "kmem/ion_heap_grow"
+      ftrace_events: "kmem/ion_heap_shrink"
+      ftrace_events: "kmem/rss_stat"
+      ftrace_events: "lowmemorykiller/lowmemory_kill"
+      ftrace_events: "mm_event/mm_event_record"
+      ftrace_events: "oom/mark_victim"
+      ftrace_events: "oom/oom_score_adj_update"
+      ftrace_events: "sched/sched_blocked_reason"
+      ftrace_events: "sched/sched_switch"
+      ftrace_events: "sched/sched_wakeup"
+      ftrace_events: "sched/sched_wakeup_new"
+      ftrace_events: "sched/sched_waking"
       atrace_categories: "aidl"
       atrace_categories: "am"
-      atrace_categories: "dalvik"
       atrace_categories: "binder_lock"
       atrace_categories: "binder_driver"
-      atrace_categories: "bionic"
-      atrace_categories: "camera"
+      atrace_categories: "dalvik"
       atrace_categories: "disk"
       atrace_categories: "freq"
       atrace_categories: "idle"
@@ -142,79 +373,33 @@ COMMON_DEFAULT_CONFIG_MIDDLE_STRING = f'''\
       atrace_categories: "sched"
       atrace_categories: "sm"
       atrace_categories: "ss"
-      atrace_categories: "thermal"
-      atrace_categories: "video"
       atrace_categories: "view"
       atrace_categories: "wm"
-      atrace_apps: "lmkd"
-      atrace_apps: "system_server"
-      atrace_apps: "com.android.systemui"
-      atrace_apps: "com.google.android.gms"
-      atrace_apps: "com.google.android.gms.persistent"
-      atrace_apps: "android:ui"
-      atrace_apps: "com.google.android.apps.maps"
       atrace_apps: "*"
       buffer_size_kb: 16384
       drain_period_ms: 150
       symbolize_ksyms: true
     }}
   }}
-}}'''
-
-COMMON_CONFIG_ENDING_STRING = f'''\
-write_into_file: true
-file_write_period_ms: 5000
-max_file_size_bytes: 100000000000
-flush_period_ms: 5000
-incremental_state_config {{
-  clear_period_ms: 5000
 }}
 
-'''
-
-COMMON_DEFAULT_FTRACE_EVENTS = f'''\
-      ftrace_events: "dmabuf_heap/dma_heap_stat"
-      ftrace_events: "ftrace/print"
-      ftrace_events: "gpu_mem/gpu_mem_total"
-      ftrace_events: "ion/ion_stat"
-      ftrace_events: "kmem/ion_heap_grow"
-      ftrace_events: "kmem/ion_heap_shrink"
-      ftrace_events: "kmem/rss_stat"
-      ftrace_events: "lowmemorykiller/lowmemory_kill"
-      ftrace_events: "mm_event/mm_event_record"
-      ftrace_events: "oom/mark_victim"
-      ftrace_events: "oom/oom_score_adj_update"
-      ftrace_events: "power/cpu_frequency"
-      ftrace_events: "power/cpu_idle"
-      ftrace_events: "power/gpu_frequency"
-      ftrace_events: "power/suspend_resume"
-      ftrace_events: "power/wakeup_source_activate"
-      ftrace_events: "power/wakeup_source_deactivate"
-      ftrace_events: "sched/sched_blocked_reason"
-      ftrace_events: "sched/sched_process_exit"
-      ftrace_events: "sched/sched_process_free"
-      ftrace_events: "sched/sched_switch"
-      ftrace_events: "sched/sched_wakeup"
-      ftrace_events: "sched/sched_wakeup_new"
-      ftrace_events: "sched/sched_waking"
-      ftrace_events: "task/task_newtask"
-      ftrace_events: "task/task_rename"
-      ftrace_events: "vmscan/*"
-      ftrace_events: "workqueue/*"'''
+data_sources {{
+  config {{
+    name: "perfetto.metatrace"
+    target_buffer: 2
+  }}
+  producer_name_filter: "perfetto.traced_probes"
+}}
 
-DEFAULT_CONFIG_9000_DUR_MS = f'''\
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_1}
-{CPUFREQ_STRING_NEW_ANDROID}
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_2}
-{COMMON_DEFAULT_FTRACE_EVENTS}
-{COMMON_DEFAULT_CONFIG_MIDDLE_STRING}
 duration_ms: {TEST_DUR_MS}
 {COMMON_CONFIG_ENDING_STRING}EOF'''
 
 DEFAULT_CONFIG_EXCLUDED_FTRACE_EVENTS = f'''\
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_1}
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING}
+{COMMON_DEFAULT_CONFIG_SYS_STATS_BEGINNING}
+{COMMON_DEFAULT_SYS_EVENTS}
 {CPUFREQ_STRING_NEW_ANDROID}
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_2}
+{COMMON_DEFAULT_CONFIG_FTRACE_BEGINNING}
       ftrace_events: "dmabuf_heap/dma_heap_stat"
       ftrace_events: "ftrace/print"
       ftrace_events: "gpu_mem/gpu_mem_total"
@@ -241,14 +426,17 @@ DEFAULT_CONFIG_EXCLUDED_FTRACE_EVENTS = f'''\
       ftrace_events: "task/task_rename"
       ftrace_events: "vmscan/*"
       ftrace_events: "workqueue/*"
+{COMMON_DEFAULT_ATRACE_EVENTS}
 {COMMON_DEFAULT_CONFIG_MIDDLE_STRING}
 duration_ms: {DEFAULT_DUR_MS}
 {COMMON_CONFIG_ENDING_STRING}EOF'''
 
 DEFAULT_CONFIG_INCLUDED_FTRACE_EVENTS = f'''\
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_1}
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING}
+{COMMON_DEFAULT_CONFIG_SYS_STATS_BEGINNING}
+{COMMON_DEFAULT_SYS_EVENTS}
 {CPUFREQ_STRING_NEW_ANDROID}
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_2}
+{COMMON_DEFAULT_CONFIG_FTRACE_BEGINNING}
       ftrace_events: "dmabuf_heap/dma_heap_stat"
       ftrace_events: "ftrace/print"
       ftrace_events: "gpu_mem/gpu_mem_total"
@@ -279,15 +467,19 @@ DEFAULT_CONFIG_INCLUDED_FTRACE_EVENTS = f'''\
       ftrace_events: "workqueue/*"
       ftrace_events: "mock_ftrace_event1"
       ftrace_events: "mock_ftrace_event2"
+{COMMON_DEFAULT_ATRACE_EVENTS}
 {COMMON_DEFAULT_CONFIG_MIDDLE_STRING}
 duration_ms: {DEFAULT_DUR_MS}
 {COMMON_CONFIG_ENDING_STRING}EOF'''
 
 DEFAULT_CONFIG_OLD_ANDROID = f'''\
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_1}
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING}
+{COMMON_DEFAULT_CONFIG_SYS_STATS_BEGINNING}
+{COMMON_DEFAULT_SYS_EVENTS}
 
-{COMMON_DEFAULT_CONFIG_BEGINNING_STRING_2}
+{COMMON_DEFAULT_CONFIG_FTRACE_BEGINNING}
 {COMMON_DEFAULT_FTRACE_EVENTS}
+{COMMON_DEFAULT_ATRACE_EVENTS}
 {COMMON_DEFAULT_CONFIG_MIDDLE_STRING}
 duration_ms: {DEFAULT_DUR_MS}
 {COMMON_CONFIG_ENDING_STRING}EOF'''
@@ -333,6 +525,18 @@ CUSTOM_CONFIG_NO_DUR_MS = f'''\
 {COMMON_CUSTOM_CONFIG_BEGINNING_STRING}
 {COMMON_CONFIG_ENDING_STRING}'''
 
+DEFAULT_CONFIG_NO_DUR_MS = f'''\
+{COMMON_DEFAULT_CONFIG_BEGINNING_STRING}
+{COMMON_DEFAULT_CONFIG_SYS_STATS_BEGINNING}
+{COMMON_DEFAULT_SYS_EVENTS}
+{CPUFREQ_STRING_NEW_ANDROID}
+{COMMON_DEFAULT_CONFIG_FTRACE_BEGINNING}
+{COMMON_DEFAULT_FTRACE_EVENTS}
+{COMMON_DEFAULT_ATRACE_EVENTS}
+{COMMON_DEFAULT_CONFIG_MIDDLE_STRING}
+
+{COMMON_CONFIG_ENDING_STRING}EOF'''
+
 
 class ConfigBuilderUnitTest(unittest.TestCase):
 
@@ -349,20 +553,36 @@ class ConfigBuilderUnitTest(unittest.TestCase):
     self.assertEqual(error, None)
     self.assertEqual(config, DEFAULT_CONFIG_9000_DUR_MS)
 
+  def test_build_lightweight_config_setting_valid_dur_ms(self):
+    self.command.dur_ms = TEST_DUR_MS
+
+    config, error = build_lightweight_config(self.command, ANDROID_SDK_VERSION_T)
+
+    self.assertEqual(error, None)
+    self.assertEqual(config, LIGHTWEIGHT_CONFIG_9000_DUR_MS)
+
+  def test_build_memory_config_setting_valid_dur_ms(self):
+    self.maxDiff = None
+    self.command.dur_ms = TEST_DUR_MS
+
+    config, error = build_memory_config(self.command, ANDROID_SDK_VERSION_T)
+
+    self.assertEqual(error, None)
+    self.assertEqual(config, MEMORY_CONFIG_9000_DUR_MS)
+
   def test_build_default_config_on_old_android_version(self):
     config, error = build_default_config(self.command, ANDROID_SDK_VERSION_S_V2)
 
     self.assertEqual(error, None)
     self.assertEqual(config, DEFAULT_CONFIG_OLD_ANDROID)
 
-  def test_build_default_config_setting_invalid_dur_ms(self):
+  def test_build_default_config_setting_no_dur_ms(self):
     self.command.dur_ms = None
 
-    with self.assertRaises(ValueError) as e:
-      build_default_config(self.command, ANDROID_SDK_VERSION_T)
+    config, error = build_default_config(self.command, ANDROID_SDK_VERSION_T)
 
-    self.assertEqual(str(e.exception), ("Cannot create config because a valid"
-                                        " dur_ms was not set."))
+    self.assertEqual(error, None)
+    self.assertEqual(config, DEFAULT_CONFIG_NO_DUR_MS)
 
   def test_build_default_config_removing_valid_excluded_ftrace_events(self):
     self.command.excluded_ftrace_events = ["power/suspend_resume",
diff --git a/torq/tests/config_command_executor_unit_test.py b/torq/tests/config_command_executor_unit_test.py
new file mode 100644
index 00000000..83f34e45
--- /dev/null
+++ b/torq/tests/config_command_executor_unit_test.py
@@ -0,0 +1,465 @@
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
+#
+
+import unittest
+import subprocess
+import sys
+import io
+from unittest import mock
+from src.command import ConfigCommand
+from src.device import AdbDevice
+from src.validation_error import ValidationError
+from src.torq import DEFAULT_DUR_MS, PREDEFINED_PERFETTO_CONFIGS
+
+TEST_ERROR_MSG = "test-error"
+TEST_VALIDATION_ERROR = ValidationError(TEST_ERROR_MSG, None)
+TEST_SERIAL = "test-serial"
+ANDROID_SDK_VERSION_S = 32
+ANDROID_SDK_VERSION_T = 33
+
+TEST_DEFAULT_CONFIG = f'''\
+buffers: {{
+  size_kb: 4096
+  fill_policy: RING_BUFFER
+}}
+buffers {{
+  size_kb: 4096
+  fill_policy: RING_BUFFER
+}}
+buffers: {{
+  size_kb: 260096
+  fill_policy: RING_BUFFER
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.process_stats"
+    process_stats_config {{
+      scan_all_processes_on_start: true
+    }}
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "android.log"
+    android_log_config {{
+    }}
+  }}
+}}
+
+data_sources {{
+  config {{
+    name: "android.packages_list"
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.sys_stats"
+    target_buffer: 1
+    sys_stats_config {{
+      stat_period_ms: 500
+      stat_counters: STAT_CPU_TIMES
+      stat_counters: STAT_FORK_COUNT
+      meminfo_period_ms: 1000
+      meminfo_counters: MEMINFO_ACTIVE_ANON
+      meminfo_counters: MEMINFO_ACTIVE_FILE
+      meminfo_counters: MEMINFO_INACTIVE_ANON
+      meminfo_counters: MEMINFO_INACTIVE_FILE
+      meminfo_counters: MEMINFO_KERNEL_STACK
+      meminfo_counters: MEMINFO_MLOCKED
+      meminfo_counters: MEMINFO_SHMEM
+      meminfo_counters: MEMINFO_SLAB
+      meminfo_counters: MEMINFO_SLAB_UNRECLAIMABLE
+      meminfo_counters: MEMINFO_VMALLOC_USED
+      meminfo_counters: MEMINFO_MEM_FREE
+      meminfo_counters: MEMINFO_SWAP_FREE
+      vmstat_period_ms: 1000
+      vmstat_counters: VMSTAT_PGFAULT
+      vmstat_counters: VMSTAT_PGMAJFAULT
+      vmstat_counters: VMSTAT_PGFREE
+      vmstat_counters: VMSTAT_PGPGIN
+      vmstat_counters: VMSTAT_PGPGOUT
+      vmstat_counters: VMSTAT_PSWPIN
+      vmstat_counters: VMSTAT_PSWPOUT
+      vmstat_counters: VMSTAT_PGSCAN_DIRECT
+      vmstat_counters: VMSTAT_PGSTEAL_DIRECT
+      vmstat_counters: VMSTAT_PGSCAN_KSWAPD
+      vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
+      vmstat_counters: VMSTAT_WORKINGSET_REFAULT
+      cpufreq_period_ms: 500
+    }}
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "android.surfaceflinger.frametimeline"
+    target_buffer: 2
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.ftrace"
+    target_buffer: 2
+    ftrace_config {{
+      ftrace_events: "dmabuf_heap/dma_heap_stat"
+      ftrace_events: "ftrace/print"
+      ftrace_events: "gpu_mem/gpu_mem_total"
+      ftrace_events: "ion/ion_stat"
+      ftrace_events: "kmem/ion_heap_grow"
+      ftrace_events: "kmem/ion_heap_shrink"
+      ftrace_events: "kmem/rss_stat"
+      ftrace_events: "lowmemorykiller/lowmemory_kill"
+      ftrace_events: "mm_event/mm_event_record"
+      ftrace_events: "oom/mark_victim"
+      ftrace_events: "oom/oom_score_adj_update"
+      ftrace_events: "power/cpu_frequency"
+      ftrace_events: "power/cpu_idle"
+      ftrace_events: "power/gpu_frequency"
+      ftrace_events: "power/suspend_resume"
+      ftrace_events: "power/wakeup_source_activate"
+      ftrace_events: "power/wakeup_source_deactivate"
+      ftrace_events: "sched/sched_blocked_reason"
+      ftrace_events: "sched/sched_process_exit"
+      ftrace_events: "sched/sched_process_free"
+      ftrace_events: "sched/sched_switch"
+      ftrace_events: "sched/sched_wakeup"
+      ftrace_events: "sched/sched_wakeup_new"
+      ftrace_events: "sched/sched_waking"
+      ftrace_events: "task/task_newtask"
+      ftrace_events: "task/task_rename"
+      ftrace_events: "vmscan/*"
+      ftrace_events: "workqueue/*"
+      atrace_categories: "aidl"
+      atrace_categories: "am"
+      atrace_categories: "dalvik"
+      atrace_categories: "binder_lock"
+      atrace_categories: "binder_driver"
+      atrace_categories: "bionic"
+      atrace_categories: "camera"
+      atrace_categories: "disk"
+      atrace_categories: "freq"
+      atrace_categories: "idle"
+      atrace_categories: "gfx"
+      atrace_categories: "hal"
+      atrace_categories: "input"
+      atrace_categories: "pm"
+      atrace_categories: "power"
+      atrace_categories: "res"
+      atrace_categories: "rro"
+      atrace_categories: "sched"
+      atrace_categories: "sm"
+      atrace_categories: "ss"
+      atrace_categories: "thermal"
+      atrace_categories: "video"
+      atrace_categories: "view"
+      atrace_categories: "wm"
+      atrace_apps: "*"
+      buffer_size_kb: 16384
+      drain_period_ms: 150
+      symbolize_ksyms: true
+    }}
+  }}
+}}
+
+data_sources {{
+  config {{
+    name: "perfetto.metatrace"
+    target_buffer: 2
+  }}
+  producer_name_filter: "perfetto.traced_probes"
+}}
+
+duration_ms: 10000
+write_into_file: true
+file_write_period_ms: 5000
+max_file_size_bytes: 100000000000
+flush_period_ms: 5000
+incremental_state_config {{
+  clear_period_ms: 5000
+}}
+'''
+
+TEST_DEFAULT_CONFIG_OLD_ANDROID = f'''\
+buffers: {{
+  size_kb: 4096
+  fill_policy: RING_BUFFER
+}}
+buffers {{
+  size_kb: 4096
+  fill_policy: RING_BUFFER
+}}
+buffers: {{
+  size_kb: 260096
+  fill_policy: RING_BUFFER
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.process_stats"
+    process_stats_config {{
+      scan_all_processes_on_start: true
+    }}
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "android.log"
+    android_log_config {{
+    }}
+  }}
+}}
+
+data_sources {{
+  config {{
+    name: "android.packages_list"
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.sys_stats"
+    target_buffer: 1
+    sys_stats_config {{
+      stat_period_ms: 500
+      stat_counters: STAT_CPU_TIMES
+      stat_counters: STAT_FORK_COUNT
+      meminfo_period_ms: 1000
+      meminfo_counters: MEMINFO_ACTIVE_ANON
+      meminfo_counters: MEMINFO_ACTIVE_FILE
+      meminfo_counters: MEMINFO_INACTIVE_ANON
+      meminfo_counters: MEMINFO_INACTIVE_FILE
+      meminfo_counters: MEMINFO_KERNEL_STACK
+      meminfo_counters: MEMINFO_MLOCKED
+      meminfo_counters: MEMINFO_SHMEM
+      meminfo_counters: MEMINFO_SLAB
+      meminfo_counters: MEMINFO_SLAB_UNRECLAIMABLE
+      meminfo_counters: MEMINFO_VMALLOC_USED
+      meminfo_counters: MEMINFO_MEM_FREE
+      meminfo_counters: MEMINFO_SWAP_FREE
+      vmstat_period_ms: 1000
+      vmstat_counters: VMSTAT_PGFAULT
+      vmstat_counters: VMSTAT_PGMAJFAULT
+      vmstat_counters: VMSTAT_PGFREE
+      vmstat_counters: VMSTAT_PGPGIN
+      vmstat_counters: VMSTAT_PGPGOUT
+      vmstat_counters: VMSTAT_PSWPIN
+      vmstat_counters: VMSTAT_PSWPOUT
+      vmstat_counters: VMSTAT_PGSCAN_DIRECT
+      vmstat_counters: VMSTAT_PGSTEAL_DIRECT
+      vmstat_counters: VMSTAT_PGSCAN_KSWAPD
+      vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
+      vmstat_counters: VMSTAT_WORKINGSET_REFAULT
+
+    }}
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "android.surfaceflinger.frametimeline"
+    target_buffer: 2
+  }}
+}}
+
+data_sources: {{
+  config {{
+    name: "linux.ftrace"
+    target_buffer: 2
+    ftrace_config {{
+      ftrace_events: "dmabuf_heap/dma_heap_stat"
+      ftrace_events: "ftrace/print"
+      ftrace_events: "gpu_mem/gpu_mem_total"
+      ftrace_events: "ion/ion_stat"
+      ftrace_events: "kmem/ion_heap_grow"
+      ftrace_events: "kmem/ion_heap_shrink"
+      ftrace_events: "kmem/rss_stat"
+      ftrace_events: "lowmemorykiller/lowmemory_kill"
+      ftrace_events: "mm_event/mm_event_record"
+      ftrace_events: "oom/mark_victim"
+      ftrace_events: "oom/oom_score_adj_update"
+      ftrace_events: "power/cpu_frequency"
+      ftrace_events: "power/cpu_idle"
+      ftrace_events: "power/gpu_frequency"
+      ftrace_events: "power/suspend_resume"
+      ftrace_events: "power/wakeup_source_activate"
+      ftrace_events: "power/wakeup_source_deactivate"
+      ftrace_events: "sched/sched_blocked_reason"
+      ftrace_events: "sched/sched_process_exit"
+      ftrace_events: "sched/sched_process_free"
+      ftrace_events: "sched/sched_switch"
+      ftrace_events: "sched/sched_wakeup"
+      ftrace_events: "sched/sched_wakeup_new"
+      ftrace_events: "sched/sched_waking"
+      ftrace_events: "task/task_newtask"
+      ftrace_events: "task/task_rename"
+      ftrace_events: "vmscan/*"
+      ftrace_events: "workqueue/*"
+      atrace_categories: "aidl"
+      atrace_categories: "am"
+      atrace_categories: "dalvik"
+      atrace_categories: "binder_lock"
+      atrace_categories: "binder_driver"
+      atrace_categories: "bionic"
+      atrace_categories: "camera"
+      atrace_categories: "disk"
+      atrace_categories: "freq"
+      atrace_categories: "idle"
+      atrace_categories: "gfx"
+      atrace_categories: "hal"
+      atrace_categories: "input"
+      atrace_categories: "pm"
+      atrace_categories: "power"
+      atrace_categories: "res"
+      atrace_categories: "rro"
+      atrace_categories: "sched"
+      atrace_categories: "sm"
+      atrace_categories: "ss"
+      atrace_categories: "thermal"
+      atrace_categories: "video"
+      atrace_categories: "view"
+      atrace_categories: "wm"
+      atrace_apps: "*"
+      buffer_size_kb: 16384
+      drain_period_ms: 150
+      symbolize_ksyms: true
+    }}
+  }}
+}}
+
+data_sources {{
+  config {{
+    name: "perfetto.metatrace"
+    target_buffer: 2
+  }}
+  producer_name_filter: "perfetto.traced_probes"
+}}
+
+duration_ms: 10000
+write_into_file: true
+file_write_period_ms: 5000
+max_file_size_bytes: 100000000000
+flush_period_ms: 5000
+incremental_state_config {{
+  clear_period_ms: 5000
+}}
+'''
+
+
+class ConfigCommandExecutorUnitTest(unittest.TestCase):
+
+  def setUp(self):
+    self.mock_device = mock.create_autospec(AdbDevice, instance=True,
+                                            serial=TEST_SERIAL)
+    self.mock_device.check_device_connection.return_value = None
+    self.mock_device.get_android_sdk_version.return_value = (
+        ANDROID_SDK_VERSION_T)
+
+  @staticmethod
+  def generate_mock_completed_process(stdout_string=b'\n', stderr_string=b'\n'):
+    return mock.create_autospec(subprocess.CompletedProcess, instance=True,
+                                stdout=stdout_string, stderr=stderr_string)
+
+  def test_config_list(self):
+    terminal_output = io.StringIO()
+    sys.stdout = terminal_output
+
+    self.command = ConfigCommand("config list", None, None, None, None, None)
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+    self.assertEqual(terminal_output.getvalue(), (
+        "%s\n" % "\n".join(list(PREDEFINED_PERFETTO_CONFIGS.keys()))))
+
+  def test_config_show(self):
+    terminal_output = io.StringIO()
+    sys.stdout = terminal_output
+
+    self.command = ConfigCommand("config show", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+    self.assertEqual(terminal_output.getvalue(), TEST_DEFAULT_CONFIG)
+
+  def test_config_show_no_device_connection(self):
+    self.mock_device.check_device_connection.return_value = (
+        TEST_VALIDATION_ERROR)
+    terminal_output = io.StringIO()
+    sys.stdout = terminal_output
+
+    self.command = ConfigCommand("config show", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+    self.assertEqual(terminal_output.getvalue(), TEST_DEFAULT_CONFIG)
+
+  def test_config_show_old_android_version(self):
+    self.mock_device.get_android_sdk_version.return_value = (
+        ANDROID_SDK_VERSION_S)
+    terminal_output = io.StringIO()
+    sys.stdout = terminal_output
+
+    self.command = ConfigCommand("config show", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+    self.assertEqual(terminal_output.getvalue(),
+                     TEST_DEFAULT_CONFIG_OLD_ANDROID)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_config_pull(self, mock_subprocess_run):
+    mock_subprocess_run.return_value = self.generate_mock_completed_process()
+    self.command = ConfigCommand("config pull", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_config_pull_no_device_connection(self, mock_subprocess_run):
+    self.mock_device.check_device_connection.return_value = (
+        TEST_VALIDATION_ERROR)
+    mock_subprocess_run.return_value = self.generate_mock_completed_process()
+    self.command = ConfigCommand("config pull", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_config_pull_old_android_version(self, mock_subprocess_run):
+    self.mock_device.get_android_sdk_version.return_value = (
+        ANDROID_SDK_VERSION_S)
+    mock_subprocess_run.return_value = self.generate_mock_completed_process()
+    self.command = ConfigCommand("config pull", "default", None, DEFAULT_DUR_MS,
+                                 None, None)
+
+    error = self.command.execute(self.mock_device)
+
+    self.assertEqual(error, None)
+
+
+if __name__ == '__main__':
+  unittest.main()
diff --git a/torq/tests/device_unit_test.py b/torq/tests/device_unit_test.py
index 01d5d7b9..aa0a1aa3 100644
--- a/torq/tests/device_unit_test.py
+++ b/torq/tests/device_unit_test.py
@@ -737,32 +737,32 @@ class DeviceUnitTest(unittest.TestCase):
     self.assertEqual(str(e.exception), TEST_FAILURE_MSG)
 
   @mock.patch.object(subprocess, "run", autospec=True)
-  def test_kill_pid_success(self, mock_subprocess_run):
+  def test_kill_process_success(self, mock_subprocess_run):
     mock_subprocess_run.side_effect = [
         self.generate_mock_completed_process(TEST_PID_OUTPUT), None]
     adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
 
     # No exception is expected to be thrown
-    adbDevice.kill_pid(TEST_PACKAGE_1)
+    adbDevice.kill_process(TEST_PACKAGE_1)
 
   @mock.patch.object(subprocess, "run", autospec=True)
-  def test_kill_pid_and_get_pid_failure(self, mock_subprocess_run):
+  def test_kill_process_and_get_pid_failure(self, mock_subprocess_run):
     mock_subprocess_run.side_effect = TEST_EXCEPTION
     adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
 
     with self.assertRaises(Exception) as e:
-      adbDevice.kill_pid(TEST_PACKAGE_1)
+      adbDevice.kill_process(TEST_PACKAGE_1)
 
     self.assertEqual(str(e.exception), TEST_FAILURE_MSG)
 
   @mock.patch.object(subprocess, "run", autospec=True)
-  def test_kill_pid_failure(self, mock_subprocess_run):
+  def test_kill_process_failure(self, mock_subprocess_run):
     mock_subprocess_run.side_effect = [
         self.generate_mock_completed_process(TEST_PID_OUTPUT), TEST_EXCEPTION]
     adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
 
     with self.assertRaises(Exception) as e:
-      adbDevice.kill_pid(TEST_PACKAGE_1)
+      adbDevice.kill_process(TEST_PACKAGE_1)
 
     self.assertEqual(str(e.exception), TEST_FAILURE_MSG)
 
@@ -884,5 +884,27 @@ class DeviceUnitTest(unittest.TestCase):
     self.assertEqual(error.message, "Simpleperf was not found in the device")
     self.assertEqual(error.suggestion, "Push the simpleperf binary to the device")
 
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_file_exists_success(self, mock_subprocess_run):
+    mock_subprocess_run.return_value = (
+        self.generate_mock_completed_process(
+            b'',
+            b'')
+    )
+    adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
+
+    self.assertEqual(adbDevice.file_exists("perfetto"), True)
+
+  @mock.patch.object(subprocess, "run", autospec=True)
+  def test_file_exists_failure(self, mock_subprocess_run):
+    mock_subprocess_run.return_value = (
+        self.generate_mock_completed_process(
+            b'',
+            b'ls: /data/misc: No such file or directory\n')
+    )
+    adbDevice = AdbDevice(TEST_DEVICE_SERIAL)
+
+    self.assertEqual(adbDevice.file_exists("perfetto"), False)
+
 if __name__ == '__main__':
   unittest.main()
diff --git a/torq/tests/open_ui_unit_test.py b/torq/tests/open_ui_unit_test.py
index 1d6aeec4..d5e414bb 100644
--- a/torq/tests/open_ui_unit_test.py
+++ b/torq/tests/open_ui_unit_test.py
@@ -35,7 +35,7 @@ PERFETTO_BINARY = "/trace_processor"
 TORQ_TEMP_TRACE_PROCESSOR = TORQ_TEMP_DIR + PERFETTO_BINARY
 ANDROID_PERFETTO_TOOLS_DIR = "/external/perfetto/tools"
 ANDROID_TRACE_PROCESSOR = ANDROID_PERFETTO_TOOLS_DIR + PERFETTO_BINARY
-LARGE_FILE_SIZE = 1024 * 1024 * 512  # 512 MB
+LARGE_FILE_SIZE = 1024 * 1024 * 1024 * 4  # 4 GiB
 WEB_UI_ADDRESS = "https://ui.perfetto.dev"
 
 
diff --git a/torq/tests/perfetto_command_executor_unit_test.py b/torq/tests/perfetto_command_executor_unit_test.py
index db91a768..bee7b8cb 100644
--- a/torq/tests/perfetto_command_executor_unit_test.py
+++ b/torq/tests/perfetto_command_executor_unit_test.py
@@ -16,14 +16,13 @@
 
 import os
 import unittest
+import signal
 import subprocess
-import sys
-import io
 from unittest import mock
-from src.command import ProfilerCommand, ConfigCommand
+from src.command import ProfilerCommand
 from src.device import AdbDevice
 from src.validation_error import ValidationError
-from src.torq import DEFAULT_DUR_MS, DEFAULT_OUT_DIR, PREDEFINED_PERFETTO_CONFIGS
+from src.torq import DEFAULT_DUR_MS, DEFAULT_OUT_DIR
 
 PROFILER_COMMAND_TYPE = "profiler"
 TEST_ERROR_MSG = "test-error"
@@ -41,334 +40,6 @@ TEST_DURATION = 0
 ANDROID_SDK_VERSION_S = 32
 ANDROID_SDK_VERSION_T = 33
 
-TEST_DEFAULT_CONFIG = f'''\
-buffers: {{
-  size_kb: 4096
-  fill_policy: RING_BUFFER
-}}
-buffers {{
-  size_kb: 4096
-  fill_policy: RING_BUFFER
-}}
-buffers: {{
-  size_kb: 260096
-  fill_policy: RING_BUFFER
-}}
-
-data_sources: {{
-  config {{
-    name: "linux.process_stats"
-    process_stats_config {{
-      scan_all_processes_on_start: true
-    }}
-  }}
-}}
-
-data_sources: {{
-  config {{
-    name: "android.log"
-    android_log_config {{
-    }}
-  }}
-}}
-
-data_sources {{
-  config {{
-    name: "android.packages_list"
-  }}
-}}
-
-data_sources: {{
-  config {{
-    name: "linux.sys_stats"
-    target_buffer: 1
-    sys_stats_config {{
-      stat_period_ms: 500
-      stat_counters: STAT_CPU_TIMES
-      stat_counters: STAT_FORK_COUNT
-      meminfo_period_ms: 1000
-      meminfo_counters: MEMINFO_ACTIVE_ANON
-      meminfo_counters: MEMINFO_ACTIVE_FILE
-      meminfo_counters: MEMINFO_INACTIVE_ANON
-      meminfo_counters: MEMINFO_INACTIVE_FILE
-      meminfo_counters: MEMINFO_KERNEL_STACK
-      meminfo_counters: MEMINFO_MLOCKED
-      meminfo_counters: MEMINFO_SHMEM
-      meminfo_counters: MEMINFO_SLAB
-      meminfo_counters: MEMINFO_SLAB_UNRECLAIMABLE
-      meminfo_counters: MEMINFO_VMALLOC_USED
-      meminfo_counters: MEMINFO_MEM_FREE
-      meminfo_counters: MEMINFO_SWAP_FREE
-      vmstat_period_ms: 1000
-      vmstat_counters: VMSTAT_PGFAULT
-      vmstat_counters: VMSTAT_PGMAJFAULT
-      vmstat_counters: VMSTAT_PGFREE
-      vmstat_counters: VMSTAT_PGPGIN
-      vmstat_counters: VMSTAT_PGPGOUT
-      vmstat_counters: VMSTAT_PSWPIN
-      vmstat_counters: VMSTAT_PSWPOUT
-      vmstat_counters: VMSTAT_PGSCAN_DIRECT
-      vmstat_counters: VMSTAT_PGSTEAL_DIRECT
-      vmstat_counters: VMSTAT_PGSCAN_KSWAPD
-      vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
-      vmstat_counters: VMSTAT_WORKINGSET_REFAULT
-      cpufreq_period_ms: 500
-    }}
-  }}
-}}
-
-data_sources: {{
-  config {{
-    name: "android.surfaceflinger.frametimeline"
-    target_buffer: 2
-  }}
-}}
-
-data_sources: {{
-  config {{
-    name: "linux.ftrace"
-    target_buffer: 2
-    ftrace_config {{
-      ftrace_events: "dmabuf_heap/dma_heap_stat"
-      ftrace_events: "ftrace/print"
-      ftrace_events: "gpu_mem/gpu_mem_total"
-      ftrace_events: "ion/ion_stat"
-      ftrace_events: "kmem/ion_heap_grow"
-      ftrace_events: "kmem/ion_heap_shrink"
-      ftrace_events: "kmem/rss_stat"
-      ftrace_events: "lowmemorykiller/lowmemory_kill"
-      ftrace_events: "mm_event/mm_event_record"
-      ftrace_events: "oom/mark_victim"
-      ftrace_events: "oom/oom_score_adj_update"
-      ftrace_events: "power/cpu_frequency"
-      ftrace_events: "power/cpu_idle"
-      ftrace_events: "power/gpu_frequency"
-      ftrace_events: "power/suspend_resume"
-      ftrace_events: "power/wakeup_source_activate"
-      ftrace_events: "power/wakeup_source_deactivate"
-      ftrace_events: "sched/sched_blocked_reason"
-      ftrace_events: "sched/sched_process_exit"
-      ftrace_events: "sched/sched_process_free"
-      ftrace_events: "sched/sched_switch"
-      ftrace_events: "sched/sched_wakeup"
-      ftrace_events: "sched/sched_wakeup_new"
-      ftrace_events: "sched/sched_waking"
-      ftrace_events: "task/task_newtask"
-      ftrace_events: "task/task_rename"
-      ftrace_events: "vmscan/*"
-      ftrace_events: "workqueue/*"
-      atrace_categories: "aidl"
-      atrace_categories: "am"
-      atrace_categories: "dalvik"
-      atrace_categories: "binder_lock"
-      atrace_categories: "binder_driver"
-      atrace_categories: "bionic"
-      atrace_categories: "camera"
-      atrace_categories: "disk"
-      atrace_categories: "freq"
-      atrace_categories: "idle"
-      atrace_categories: "gfx"
-      atrace_categories: "hal"
-      atrace_categories: "input"
-      atrace_categories: "pm"
-      atrace_categories: "power"
-      atrace_categories: "res"
-      atrace_categories: "rro"
-      atrace_categories: "sched"
-      atrace_categories: "sm"
-      atrace_categories: "ss"
-      atrace_categories: "thermal"
-      atrace_categories: "video"
-      atrace_categories: "view"
-      atrace_categories: "wm"
-      atrace_apps: "lmkd"
-      atrace_apps: "system_server"
-      atrace_apps: "com.android.systemui"
-      atrace_apps: "com.google.android.gms"
-      atrace_apps: "com.google.android.gms.persistent"
-      atrace_apps: "android:ui"
-      atrace_apps: "com.google.android.apps.maps"
-      atrace_apps: "*"
-      buffer_size_kb: 16384
-      drain_period_ms: 150
-      symbolize_ksyms: true
-    }}
-  }}
-}}
-duration_ms: 10000
-write_into_file: true
-file_write_period_ms: 5000
-max_file_size_bytes: 100000000000
-flush_period_ms: 5000
-incremental_state_config {{
-  clear_period_ms: 5000
-}}
-'''
-
-TEST_DEFAULT_CONFIG_OLD_ANDROID = f'''\
-buffers: {{
-  size_kb: 4096
-  fill_policy: RING_BUFFER
-}}
-buffers {{
-  size_kb: 4096
-  fill_policy: RING_BUFFER
-}}
-buffers: {{
-  size_kb: 260096
-  fill_policy: RING_BUFFER
-}}
-
-data_sources: {{
-  config {{
-    name: "linux.process_stats"
-    process_stats_config {{
-      scan_all_processes_on_start: true
-    }}
-  }}
-}}
-
-data_sources: {{
-  config {{
-    name: "android.log"
-    android_log_config {{
-    }}
-  }}
-}}
-
-data_sources {{
-  config {{
-    name: "android.packages_list"
-  }}
-}}
-
-data_sources: {{
-  config {{
-    name: "linux.sys_stats"
-    target_buffer: 1
-    sys_stats_config {{
-      stat_period_ms: 500
-      stat_counters: STAT_CPU_TIMES
-      stat_counters: STAT_FORK_COUNT
-      meminfo_period_ms: 1000
-      meminfo_counters: MEMINFO_ACTIVE_ANON
-      meminfo_counters: MEMINFO_ACTIVE_FILE
-      meminfo_counters: MEMINFO_INACTIVE_ANON
-      meminfo_counters: MEMINFO_INACTIVE_FILE
-      meminfo_counters: MEMINFO_KERNEL_STACK
-      meminfo_counters: MEMINFO_MLOCKED
-      meminfo_counters: MEMINFO_SHMEM
-      meminfo_counters: MEMINFO_SLAB
-      meminfo_counters: MEMINFO_SLAB_UNRECLAIMABLE
-      meminfo_counters: MEMINFO_VMALLOC_USED
-      meminfo_counters: MEMINFO_MEM_FREE
-      meminfo_counters: MEMINFO_SWAP_FREE
-      vmstat_period_ms: 1000
-      vmstat_counters: VMSTAT_PGFAULT
-      vmstat_counters: VMSTAT_PGMAJFAULT
-      vmstat_counters: VMSTAT_PGFREE
-      vmstat_counters: VMSTAT_PGPGIN
-      vmstat_counters: VMSTAT_PGPGOUT
-      vmstat_counters: VMSTAT_PSWPIN
-      vmstat_counters: VMSTAT_PSWPOUT
-      vmstat_counters: VMSTAT_PGSCAN_DIRECT
-      vmstat_counters: VMSTAT_PGSTEAL_DIRECT
-      vmstat_counters: VMSTAT_PGSCAN_KSWAPD
-      vmstat_counters: VMSTAT_PGSTEAL_KSWAPD
-      vmstat_counters: VMSTAT_WORKINGSET_REFAULT
-
-    }}
-  }}
-}}
-
-data_sources: {{
-  config {{
-    name: "android.surfaceflinger.frametimeline"
-    target_buffer: 2
-  }}
-}}
-
-data_sources: {{
-  config {{
-    name: "linux.ftrace"
-    target_buffer: 2
-    ftrace_config {{
-      ftrace_events: "dmabuf_heap/dma_heap_stat"
-      ftrace_events: "ftrace/print"
-      ftrace_events: "gpu_mem/gpu_mem_total"
-      ftrace_events: "ion/ion_stat"
-      ftrace_events: "kmem/ion_heap_grow"
-      ftrace_events: "kmem/ion_heap_shrink"
-      ftrace_events: "kmem/rss_stat"
-      ftrace_events: "lowmemorykiller/lowmemory_kill"
-      ftrace_events: "mm_event/mm_event_record"
-      ftrace_events: "oom/mark_victim"
-      ftrace_events: "oom/oom_score_adj_update"
-      ftrace_events: "power/cpu_frequency"
-      ftrace_events: "power/cpu_idle"
-      ftrace_events: "power/gpu_frequency"
-      ftrace_events: "power/suspend_resume"
-      ftrace_events: "power/wakeup_source_activate"
-      ftrace_events: "power/wakeup_source_deactivate"
-      ftrace_events: "sched/sched_blocked_reason"
-      ftrace_events: "sched/sched_process_exit"
-      ftrace_events: "sched/sched_process_free"
-      ftrace_events: "sched/sched_switch"
-      ftrace_events: "sched/sched_wakeup"
-      ftrace_events: "sched/sched_wakeup_new"
-      ftrace_events: "sched/sched_waking"
-      ftrace_events: "task/task_newtask"
-      ftrace_events: "task/task_rename"
-      ftrace_events: "vmscan/*"
-      ftrace_events: "workqueue/*"
-      atrace_categories: "aidl"
-      atrace_categories: "am"
-      atrace_categories: "dalvik"
-      atrace_categories: "binder_lock"
-      atrace_categories: "binder_driver"
-      atrace_categories: "bionic"
-      atrace_categories: "camera"
-      atrace_categories: "disk"
-      atrace_categories: "freq"
-      atrace_categories: "idle"
-      atrace_categories: "gfx"
-      atrace_categories: "hal"
-      atrace_categories: "input"
-      atrace_categories: "pm"
-      atrace_categories: "power"
-      atrace_categories: "res"
-      atrace_categories: "rro"
-      atrace_categories: "sched"
-      atrace_categories: "sm"
-      atrace_categories: "ss"
-      atrace_categories: "thermal"
-      atrace_categories: "video"
-      atrace_categories: "view"
-      atrace_categories: "wm"
-      atrace_apps: "lmkd"
-      atrace_apps: "system_server"
-      atrace_apps: "com.android.systemui"
-      atrace_apps: "com.google.android.gms"
-      atrace_apps: "com.google.android.gms.persistent"
-      atrace_apps: "android:ui"
-      atrace_apps: "com.google.android.apps.maps"
-      atrace_apps: "*"
-      buffer_size_kb: 16384
-      drain_period_ms: 150
-      symbolize_ksyms: true
-    }}
-  }}
-}}
-duration_ms: 10000
-write_into_file: true
-file_write_period_ms: 5000
-max_file_size_bytes: 100000000000
-flush_period_ms: 5000
-incremental_state_config {{
-  clear_period_ms: 5000
-}}
-'''
-
 
 class ProfilerCommandExecutorUnitTest(unittest.TestCase):
 
@@ -395,6 +66,25 @@ class ProfilerCommandExecutorUnitTest(unittest.TestCase):
       self.assertEqual(error, None)
       self.assertEqual(self.mock_device.pull_file.call_count, 1)
 
+  @mock.patch.object(subprocess, "Popen", autospec=True)
+  def test_execute_one_run_no_dur_ms_success(self, mock_process):
+    def poll():
+      # Send the SIGINT signal to the process to simulate a user pressing CTRL+C
+      os.kill(os.getpid(), signal.SIGINT)
+      return None
+
+    with (mock.patch("src.command_executor.open_trace", autospec=True)
+          as mock_open_trace):
+      self.command.dur_ms = None
+      mock_open_trace.return_value = None
+      mock_process.poll = poll
+      self.mock_device.start_perfetto_trace.return_value = mock_process
+
+      error = self.command.execute(self.mock_device)
+
+      self.assertEqual(error, None)
+      self.assertEqual(self.mock_device.pull_file.call_count, 1)
+
   @mock.patch.object(subprocess, "run", autospec=True)
   @mock.patch.object(subprocess, "Popen", autospec=True)
   @mock.patch.object(os.path, "exists", autospec=True)
@@ -464,16 +154,6 @@ class ProfilerCommandExecutorUnitTest(unittest.TestCase):
     self.assertEqual(str(e.exception), TEST_ERROR_MSG)
     self.assertEqual(self.mock_device.pull_file.call_count, 0)
 
-  def test_execute_create_default_config_no_dur_ms_error(self):
-    self.command.dur_ms = None
-
-    with self.assertRaises(ValueError) as e:
-      self.command.execute(self.mock_device)
-
-    self.assertEqual(str(e.exception),
-                     "Cannot create config because a valid dur_ms was not set.")
-    self.assertEqual(self.mock_device.pull_file.call_count, 0)
-
   def test_execute_create_default_config_bad_excluded_ftrace_event_error(self):
     self.command.excluded_ftrace_events = ["mock-ftrace-event"]
 
@@ -578,9 +258,9 @@ class ProfilerCommandExecutorUnitTest(unittest.TestCase):
     self.assertEqual(self.mock_device.pull_file.call_count, 0)
 
   @mock.patch.object(subprocess, "Popen", autospec=True)
-  def test_execute_process_wait_failure(self, mock_process):
+  def test_execute_process_poll_failure(self, mock_process):
     self.mock_device.start_perfetto_trace.return_value = mock_process
-    mock_process.wait.side_effect = TEST_EXCEPTION
+    mock_process.poll.side_effect = TEST_EXCEPTION
 
     with self.assertRaises(Exception) as e:
       self.command.execute(self.mock_device)
@@ -737,6 +417,7 @@ class BootCommandExecutorUnitTest(unittest.TestCase):
     self.mock_device = mock.create_autospec(AdbDevice, instance=True,
                                             serial=TEST_SERIAL)
     self.mock_device.check_device_connection.return_value = None
+    self.mock_device.is_package_running.return_value = False
     self.mock_device.get_android_sdk_version.return_value = ANDROID_SDK_VERSION_T
 
   def test_execute_reboot_success(self):
@@ -931,7 +612,7 @@ class AppStartupExecutorUnitTest(unittest.TestCase):
     self.assertEqual(self.mock_device.start_package.call_count, 1)
     self.assertEqual(self.mock_device.pull_file.call_count, 0)
 
-  def test_kill_pid_success(self):
+  def test_kill_process_success(self):
     self.mock_device.start_package.return_value = TEST_VALIDATION_ERROR
 
     error = self.command.execute(self.mock_device)
@@ -940,119 +621,21 @@ class AppStartupExecutorUnitTest(unittest.TestCase):
     self.assertEqual(error.message, TEST_ERROR_MSG)
     self.assertEqual(error.suggestion, None)
     self.assertEqual(self.mock_device.start_package.call_count, 1)
-    self.assertEqual(self.mock_device.kill_pid.call_count, 1)
+    self.assertEqual(self.mock_device.kill_process.call_count, 1)
     self.assertEqual(self.mock_device.pull_file.call_count, 0)
 
-  def test_kill_pid_failure(self):
+  def test_kill_process_failure(self):
     self.mock_device.start_package.return_value = TEST_VALIDATION_ERROR
-    self.mock_device.kill_pid.side_effect = TEST_EXCEPTION
+    self.mock_device.kill_process.side_effect = TEST_EXCEPTION
 
     with self.assertRaises(Exception) as e:
       self.command.execute(self.mock_device)
 
     self.assertEqual(str(e.exception), TEST_ERROR_MSG)
     self.assertEqual(self.mock_device.start_package.call_count, 1)
-    self.assertEqual(self.mock_device.kill_pid.call_count, 1)
+    self.assertEqual(self.mock_device.kill_process.call_count, 1)
     self.assertEqual(self.mock_device.pull_file.call_count, 0)
 
 
-class ConfigCommandExecutorUnitTest(unittest.TestCase):
-
-  def setUp(self):
-    self.mock_device = mock.create_autospec(AdbDevice, instance=True,
-                                            serial=TEST_SERIAL)
-    self.mock_device.check_device_connection.return_value = None
-    self.mock_device.get_android_sdk_version.return_value = (
-        ANDROID_SDK_VERSION_T)
-
-  @staticmethod
-  def generate_mock_completed_process(stdout_string=b'\n', stderr_string=b'\n'):
-    return mock.create_autospec(subprocess.CompletedProcess, instance=True,
-                                stdout=stdout_string, stderr=stderr_string)
-
-  def test_config_list(self):
-    terminal_output = io.StringIO()
-    sys.stdout = terminal_output
-
-    self.command = ConfigCommand("config list", None, None, None, None, None)
-    error = self.command.execute(self.mock_device)
-
-    self.assertEqual(error, None)
-    self.assertEqual(terminal_output.getvalue(), (
-        "%s\n" % "\n".join(list(PREDEFINED_PERFETTO_CONFIGS.keys()))))
-
-  def test_config_show(self):
-    terminal_output = io.StringIO()
-    sys.stdout = terminal_output
-
-    self.command = ConfigCommand("config show", "default", None, DEFAULT_DUR_MS,
-                                 None, None)
-    error = self.command.execute(self.mock_device)
-
-    self.assertEqual(error, None)
-    self.assertEqual(terminal_output.getvalue(), TEST_DEFAULT_CONFIG)
-
-  def test_config_show_no_device_connection(self):
-    self.mock_device.check_device_connection.return_value = (
-        TEST_VALIDATION_ERROR)
-    terminal_output = io.StringIO()
-    sys.stdout = terminal_output
-
-    self.command = ConfigCommand("config show", "default", None, DEFAULT_DUR_MS,
-                                 None, None)
-    error = self.command.execute(self.mock_device)
-
-    self.assertEqual(error, None)
-    self.assertEqual(terminal_output.getvalue(), TEST_DEFAULT_CONFIG)
-
-  def test_config_show_old_android_version(self):
-    self.mock_device.get_android_sdk_version.return_value = (
-        ANDROID_SDK_VERSION_S)
-    terminal_output = io.StringIO()
-    sys.stdout = terminal_output
-
-    self.command = ConfigCommand("config show", "default", None, DEFAULT_DUR_MS,
-                                 None, None)
-    error = self.command.execute(self.mock_device)
-
-    self.assertEqual(error, None)
-    self.assertEqual(terminal_output.getvalue(),
-                     TEST_DEFAULT_CONFIG_OLD_ANDROID)
-
-  @mock.patch.object(subprocess, "run", autospec=True)
-  def test_config_pull(self, mock_subprocess_run):
-    mock_subprocess_run.return_value = self.generate_mock_completed_process()
-    self.command = ConfigCommand("config pull", "default", None, DEFAULT_DUR_MS,
-                                 None, None)
-
-    error = self.command.execute(self.mock_device)
-
-    self.assertEqual(error, None)
-
-  @mock.patch.object(subprocess, "run", autospec=True)
-  def test_config_pull_no_device_connection(self, mock_subprocess_run):
-    self.mock_device.check_device_connection.return_value = (
-        TEST_VALIDATION_ERROR)
-    mock_subprocess_run.return_value = self.generate_mock_completed_process()
-    self.command = ConfigCommand("config pull", "default", None, DEFAULT_DUR_MS,
-                                 None, None)
-
-    error = self.command.execute(self.mock_device)
-
-    self.assertEqual(error, None)
-
-  @mock.patch.object(subprocess, "run", autospec=True)
-  def test_config_pull_old_android_version(self, mock_subprocess_run):
-    self.mock_device.get_android_sdk_version.return_value = (
-        ANDROID_SDK_VERSION_S)
-    mock_subprocess_run.return_value = self.generate_mock_completed_process()
-    self.command = ConfigCommand("config pull", "default", None, DEFAULT_DUR_MS,
-                                 None, None)
-
-    error = self.command.execute(self.mock_device)
-
-    self.assertEqual(error, None)
-
-
 if __name__ == '__main__':
   unittest.main()
diff --git a/torq/tests/torq_unit_test.py b/torq/tests/torq_unit_test.py
index 88a115ba..de2ecb31 100644
--- a/torq/tests/torq_unit_test.py
+++ b/torq/tests/torq_unit_test.py
@@ -18,7 +18,7 @@ import unittest
 import sys
 import os
 from unittest import mock
-from src.torq import create_parser, verify_args, get_command_type,\
+from src.torq import create_parser, verify_args, get_command_type, \
   DEFAULT_DUR_MS, DEFAULT_OUT_DIR
 
 TEST_USER_ID = 10
@@ -46,7 +46,7 @@ class TorqUnitTest(unittest.TestCase):
     self.assertEqual(args.out_dir, DEFAULT_OUT_DIR)
     self.assertEqual(args.runs, 1)
     self.assertEqual(args.perfetto_config, "default")
-    self.assertEqual(args.dur_ms, DEFAULT_DUR_MS)
+    self.assertEqual(args.dur_ms, None)
     self.assertEqual(args.between_dur_ms, DEFAULT_DUR_MS)
 
   def test_create_parser_valid_event_names(self):
@@ -645,7 +645,7 @@ class TorqUnitTest(unittest.TestCase):
 
     self.assertEqual(error, None)
     self.assertEqual(args.excluded_ftrace_events, ["power/cpu_idle",
-                                                 "ion/ion_stat"])
+                                                   "ion/ion_stat"])
 
   def test_verify_args_multiple_invalid_excluded_ftrace_events(self):
     parser = self.set_up_parser(("torq.py --excluded-ftrace-events"
```

