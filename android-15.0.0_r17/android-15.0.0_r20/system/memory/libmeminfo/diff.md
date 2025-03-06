```diff
diff --git a/OWNERS b/OWNERS
index dd9c4c8..501c1d0 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,4 +3,3 @@ surenb@google.com
 tjmercier@google.com
 kaleshsingh@google.com
 jyescas@google.com
-carlosgalo@google.com
diff --git a/androidprocheaps.cpp b/androidprocheaps.cpp
index 018eca4..ed01339 100644
--- a/androidprocheaps.cpp
+++ b/androidprocheaps.cpp
@@ -15,7 +15,6 @@
  */
 
 #include <android-base/stringprintf.h>
-#include <android-base/strings.h>
 
 #include "meminfo_private.h"
 
@@ -38,43 +37,43 @@ bool ExtractAndroidHeapStatsFromFile(const std::string& smaps_path, AndroidHeapS
         int sub_heap = HEAP_UNKNOWN;
         bool is_swappable = false;
         std::string name;
-        if (base::EndsWith(vma.name, " (deleted)")) {
+        if (vma.name.ends_with(" (deleted)")) {
             name = vma.name.substr(0, vma.name.size() - strlen(" (deleted)"));
         } else {
             name = vma.name;
         }
 
         uint32_t namesz = name.size();
-        if (base::StartsWith(name, "[heap]")) {
+        if (name.starts_with("[heap]")) {
             which_heap = HEAP_NATIVE;
-        } else if (base::StartsWith(name, "[anon:libc_malloc]")) {
+        } else if (name.starts_with("[anon:libc_malloc]")) {
             which_heap = HEAP_NATIVE;
-        } else if (base::StartsWith(name, "[anon:scudo:")) {
+        } else if (name.starts_with("[anon:scudo:")) {
             which_heap = HEAP_NATIVE;
-        } else if (base::StartsWith(name, "[anon:GWP-ASan")) {
+        } else if (name.starts_with("[anon:GWP-ASan")) {
             which_heap = HEAP_NATIVE;
-        } else if (base::StartsWith(name, "[stack")) {
+        } else if (name.starts_with("[stack")) {
             which_heap = HEAP_STACK;
-        } else if (base::StartsWith(name, "[anon:stack_and_tls:")) {
+        } else if (name.starts_with("[anon:stack_and_tls:")) {
             which_heap = HEAP_STACK;
-        } else if (base::EndsWith(name, ".so")) {
+        } else if (name.ends_with(".so")) {
             which_heap = HEAP_SO;
             is_swappable = true;
-        } else if (base::EndsWith(name, ".jar")) {
+        } else if (name.ends_with(".jar")) {
             which_heap = HEAP_JAR;
             is_swappable = true;
-        } else if (base::EndsWith(name, ".apk")) {
+        } else if (name.ends_with(".apk")) {
             which_heap = HEAP_APK;
             is_swappable = true;
-        } else if (base::EndsWith(name, ".ttf")) {
+        } else if (name.ends_with(".ttf")) {
             which_heap = HEAP_TTF;
             is_swappable = true;
-        } else if ((base::EndsWith(name, ".odex")) ||
+        } else if ((name.ends_with(".odex")) ||
                    (namesz > 4 && strstr(name.c_str(), ".dex") != nullptr)) {
             which_heap = HEAP_DEX;
             sub_heap = HEAP_DEX_APP_DEX;
             is_swappable = true;
-        } else if (base::EndsWith(name, ".vdex")) {
+        } else if (name.ends_with(".vdex")) {
             which_heap = HEAP_DEX;
             // Handle system@framework@boot and system/framework/boot|apex
             if ((strstr(name.c_str(), "@boot") != nullptr) ||
@@ -85,10 +84,10 @@ bool ExtractAndroidHeapStatsFromFile(const std::string& smaps_path, AndroidHeapS
                 sub_heap = HEAP_DEX_APP_VDEX;
             }
             is_swappable = true;
-        } else if (base::EndsWith(name, ".oat")) {
+        } else if (name.ends_with(".oat")) {
             which_heap = HEAP_OAT;
             is_swappable = true;
-        } else if (base::EndsWith(name, ".art") || base::EndsWith(name, ".art]")) {
+        } else if (name.ends_with(".art") || name.ends_with(".art]")) {
             which_heap = HEAP_ART;
             // Handle system@framework@boot* and system/framework/boot|apex*
             if ((strstr(name.c_str(), "@boot") != nullptr) ||
@@ -99,51 +98,51 @@ bool ExtractAndroidHeapStatsFromFile(const std::string& smaps_path, AndroidHeapS
                 sub_heap = HEAP_ART_APP;
             }
             is_swappable = true;
-        } else if (base::StartsWith(name, "/dev/")) {
+        } else if (name.find("kgsl-3d0") != std::string::npos) {
+            which_heap = HEAP_GL_DEV;
+        } else if (name.starts_with("/dev/")) {
             which_heap = HEAP_UNKNOWN_DEV;
-            if (base::StartsWith(name, "/dev/kgsl-3d0")) {
-                which_heap = HEAP_GL_DEV;
-            } else if (base::StartsWith(name, "/dev/ashmem/CursorWindow")) {
+            if (name.starts_with("/dev/ashmem/CursorWindow")) {
                 which_heap = HEAP_CURSOR;
-            } else if (base::StartsWith(name, "/dev/ashmem/jit-zygote-cache")) {
+            } else if (name.starts_with("/dev/ashmem/jit-zygote-cache")) {
                 which_heap = HEAP_DALVIK_OTHER;
                 sub_heap = HEAP_DALVIK_OTHER_ZYGOTE_CODE_CACHE;
-            } else if (base::StartsWith(name, "/dev/ashmem")) {
+            } else if (name.starts_with("/dev/ashmem")) {
                 which_heap = HEAP_ASHMEM;
             }
-        } else if (base::StartsWith(name, "/memfd:jit-cache")) {
+        } else if (name.starts_with("/memfd:jit-cache")) {
             which_heap = HEAP_DALVIK_OTHER;
             sub_heap = HEAP_DALVIK_OTHER_APP_CODE_CACHE;
-        } else if (base::StartsWith(name, "/memfd:jit-zygote-cache")) {
+        } else if (name.starts_with("/memfd:jit-zygote-cache")) {
             which_heap = HEAP_DALVIK_OTHER;
             sub_heap = HEAP_DALVIK_OTHER_ZYGOTE_CODE_CACHE;
-        } else if (base::StartsWith(name, "[anon:")) {
+        } else if (name.starts_with("[anon:")) {
             which_heap = HEAP_UNKNOWN;
-            if (base::StartsWith(name, "[anon:dalvik-")) {
+            if (name.starts_with("[anon:dalvik-")) {
                 which_heap = HEAP_DALVIK_OTHER;
-                if (base::StartsWith(name, "[anon:dalvik-LinearAlloc")) {
+                if (name.starts_with("[anon:dalvik-LinearAlloc")) {
                     sub_heap = HEAP_DALVIK_OTHER_LINEARALLOC;
-                } else if (base::StartsWith(name, "[anon:dalvik-alloc space") ||
-                           base::StartsWith(name, "[anon:dalvik-main space")) {
+                } else if (name.starts_with("[anon:dalvik-alloc space") ||
+                           name.starts_with("[anon:dalvik-main space")) {
                     // This is the regular Dalvik heap.
                     which_heap = HEAP_DALVIK;
                     sub_heap = HEAP_DALVIK_NORMAL;
-                } else if (base::StartsWith(name, "[anon:dalvik-large object space") ||
-                           base::StartsWith(name, "[anon:dalvik-free list large object space")) {
+                } else if (name.starts_with("[anon:dalvik-large object space") ||
+                           name.starts_with("[anon:dalvik-free list large object space")) {
                     which_heap = HEAP_DALVIK;
                     sub_heap = HEAP_DALVIK_LARGE;
-                } else if (base::StartsWith(name, "[anon:dalvik-non moving space")) {
+                } else if (name.starts_with("[anon:dalvik-non moving space")) {
                     which_heap = HEAP_DALVIK;
                     sub_heap = HEAP_DALVIK_NON_MOVING;
-                } else if (base::StartsWith(name, "[anon:dalvik-zygote space")) {
+                } else if (name.starts_with("[anon:dalvik-zygote space")) {
                     which_heap = HEAP_DALVIK;
                     sub_heap = HEAP_DALVIK_ZYGOTE;
-                } else if (base::StartsWith(name, "[anon:dalvik-indirect ref")) {
+                } else if (name.starts_with("[anon:dalvik-indirect ref")) {
                     sub_heap = HEAP_DALVIK_OTHER_INDIRECT_REFERENCE_TABLE;
-                } else if (base::StartsWith(name, "[anon:dalvik-jit-code-cache") ||
-                           base::StartsWith(name, "[anon:dalvik-data-code-cache")) {
+                } else if (name.starts_with("[anon:dalvik-jit-code-cache") ||
+                           name.starts_with("[anon:dalvik-data-code-cache")) {
                     sub_heap = HEAP_DALVIK_OTHER_APP_CODE_CACHE;
-                } else if (base::StartsWith(name, "[anon:dalvik-CompilerMetadata")) {
+                } else if (name.starts_with("[anon:dalvik-CompilerMetadata")) {
                     sub_heap = HEAP_DALVIK_OTHER_COMPILER_METADATA;
                 } else {
                     sub_heap = HEAP_DALVIK_OTHER_ACCOUNTING;  // Default to accounting.
@@ -201,4 +200,4 @@ bool ExtractAndroidHeapStatsFromFile(const std::string& smaps_path, AndroidHeapS
     return ForEachVmaFromFile(smaps_path, vma_scan);
 }
 }  // namespace meminfo
-}  // namespace android
\ No newline at end of file
+}  // namespace android
diff --git a/libdmabufinfo/dmabufinfo.cpp b/libdmabufinfo/dmabufinfo.cpp
index ff532b0..3fd2006 100644
--- a/libdmabufinfo/dmabufinfo.cpp
+++ b/libdmabufinfo/dmabufinfo.cpp
@@ -32,7 +32,6 @@
 #include <android-base/logging.h>
 #include <android-base/parseint.h>
 #include <android-base/stringprintf.h>
-#include <android-base/strings.h>
 #include <procinfo/process_map.h>
 
 #include <dmabufinfo/dmabuf_sysfs_stats.h>
@@ -42,7 +41,7 @@ namespace android {
 namespace dmabufinfo {
 
 static bool FileIsDmaBuf(const std::string& path) {
-    return ::android::base::StartsWith(path, "/dmabuf");
+    return path.starts_with("/dmabuf");
 }
 
 enum FdInfoResult {
diff --git a/libdmabufinfo/tools/include/dmabuf_output_helper.h b/libdmabufinfo/tools/include/dmabuf_output_helper.h
index f97dbc6..5a7926b 100644
--- a/libdmabufinfo/tools/include/dmabuf_output_helper.h
+++ b/libdmabufinfo/tools/include/dmabuf_output_helper.h
@@ -98,14 +98,15 @@ class CsvOutput final : public DmabufOutputHelper {
     // Per Process
     void PerProcessHeader(const std::string& process, const pid_t pid) override {
         printf("\t%s:%d\n", process.c_str(), pid);
-        printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n", "Name", "Rss(kB)", "Pss(kB)", "nr_procs",
-               "Inode");
+        printf("\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",
+               "Name", "Rss(kB)", "Pss(kB)", "nr_procs", "Inode", "Exporter");
     }
 
     void PerProcessBufStats(const android::dmabufinfo::DmaBuffer& buf) override {
-        printf("\"%s\",%" PRIu64 ",%" PRIu64 ",%zu,%" PRIuMAX "\n",
+        printf("\"%s\",%" PRIu64 ",%" PRIu64 ",%zu,%" PRIuMAX  ",%s" "\n",
                buf.name().empty() ? "<unknown>" : buf.name().c_str(), buf.size() / 1024,
-               buf.Pss() / 1024, buf.pids().size(), static_cast<uintmax_t>(buf.inode()));
+               buf.Pss() / 1024, buf.pids().size(), static_cast<uintmax_t>(buf.inode()),
+               buf.exporter().empty() ? "<unknown>" : buf.exporter().c_str());
     }
 
     void PerProcessTotalStat(const uint64_t pss, const uint64_t rss) override {
@@ -184,13 +185,15 @@ class RawOutput final : public DmabufOutputHelper {
     // PerProcess
     void PerProcessHeader(const std::string& process, const pid_t pid) override {
         printf("%16s:%-5d\n", process.c_str(), pid);
-        printf("%22s %16s %16s %16s %16s\n", "Name", "Rss", "Pss", "nr_procs", "Inode");
+        printf("%22s %16s %16s %16s %16s %22s\n",
+               "Name", "Rss", "Pss", "nr_procs", "Inode", "Exporter");
     }
 
     void PerProcessBufStats(const android::dmabufinfo::DmaBuffer& buf) override {
-        printf("%22s %13" PRIu64 " kB %13" PRIu64 " kB %16zu %16" PRIuMAX "\n",
+        printf("%22s %13" PRIu64 " kB %13" PRIu64 " kB %16zu %16" PRIuMAX "  %22s" "\n",
                buf.name().empty() ? "<unknown>" : buf.name().c_str(), buf.size() / 1024,
-               buf.Pss() / 1024, buf.pids().size(), static_cast<uintmax_t>(buf.inode()));
+               buf.Pss() / 1024, buf.pids().size(), static_cast<uintmax_t>(buf.inode()),
+               buf.exporter().empty() ? "<unknown>" : buf.exporter().c_str());
     }
     void PerProcessTotalStat(const uint64_t pss, const uint64_t rss) override {
         printf("%22s %13" PRIu64 " kB %13" PRIu64 " kB %16s\n", "PROCESS TOTAL", rss / 1024,
diff --git a/libelf64/Android.bp b/libelf64/Android.bp
index 316f9c9..d9f6b52 100644
--- a/libelf64/Android.bp
+++ b/libelf64/Android.bp
@@ -27,9 +27,10 @@ cc_library {
         "include",
     ],
     srcs: [
-        "elf64_writer.cpp",
+        "comparator.cpp",
         "iter.cpp",
         "parse.cpp",
+        "writer.cpp",
     ],
     shared_libs: [
         "libbase",
@@ -41,9 +42,26 @@ cc_library {
 }
 
 cc_binary {
-    name: "geninvalelf64",
+    name: "gen_invalid_libs",
     srcs: [
-        "invalid_elf64_gen.cpp",
+        "gen_invalid_libs.cpp",
+    ],
+    static_libs: [
+        "libelf64",
+    ],
+    shared_libs: [
+        "libbase",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+}
+
+cc_binary {
+    name: "compare_libs",
+    srcs: [
+        "compare_libs.cpp",
     ],
     static_libs: [
         "libelf64",
diff --git a/libelf64/comparator.cpp b/libelf64/comparator.cpp
new file mode 100644
index 0000000..4aef3ab
--- /dev/null
+++ b/libelf64/comparator.cpp
@@ -0,0 +1,309 @@
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
+#include <libelf64/comparator.h>
+
+#include <libelf64/elf64.h>
+
+#include <cstring>
+#include <iostream>
+#include <string>
+#include <vector>
+
+#include <elf.h>
+
+namespace android {
+namespace elf64 {
+
+static void printEhdrDiff(const std::string& name, unsigned long long hdrField1,
+                          unsigned long long hdrField2) {
+    std::cout << "\tDiff ehdr1." << name << " = 0x" << std::hex << hdrField1 << " != " << "ehdr2."
+              << name << " = 0x" << std::hex << hdrField2 << std::endl;
+}
+
+static void printFieldDiff(const std::string& strPrefix, const std::string& fieldName, int index,
+                           unsigned long long shdrField1, unsigned long long shdrField2) {
+    std::cout << "\tDiff " << strPrefix << "1[" << index << "]." << fieldName << " = 0x" << std::hex
+              << shdrField1 << " != " << strPrefix << "2[" << index << "]." << fieldName << " = 0x"
+              << std::hex << shdrField2 << std::endl;
+}
+
+// Compares the ELF64 Executable Header.
+// Returns true if they are equal, otherwise false.
+bool Elf64Comparator::compare(const Elf64_Ehdr& ehdr1, const Elf64_Ehdr& ehdr2) {
+    bool equal = true;
+
+    std::cout << "\nComparing ELF64 Executable Headers ..." << std::endl;
+
+    // Comparing magic number and other info.
+    for (int i = 0; i < EI_NIDENT; i++) {
+        if (ehdr1.e_ident[i] != ehdr2.e_ident[i]) {
+            std::cout << "Diff ehdr1.e_ident[" << std::dec << i << "]=" << ehdr1.e_ident[i]
+                      << " != " << "ehdr2.e_ident[" << i << "]=" << ehdr2.e_ident[i] << std::endl;
+            equal = false;
+        }
+    }
+
+    if (ehdr1.e_type != ehdr2.e_type) {
+        printEhdrDiff("e_type", ehdr1.e_type, ehdr2.e_type);
+        equal = false;
+    }
+
+    if (ehdr1.e_machine != ehdr2.e_machine) {
+        printEhdrDiff("e_machine", ehdr1.e_machine, ehdr2.e_machine);
+        equal = false;
+    }
+
+    if (ehdr1.e_version != ehdr2.e_version) {
+        printEhdrDiff("e_version", ehdr1.e_version, ehdr2.e_version);
+        equal = false;
+    }
+
+    if (ehdr1.e_entry != ehdr2.e_entry) {
+        printEhdrDiff("e_entry", ehdr1.e_entry, ehdr2.e_entry);
+        equal = false;
+    }
+
+    if (ehdr1.e_phoff != ehdr2.e_phoff) {
+        printEhdrDiff("e_phoff", ehdr1.e_phoff, ehdr2.e_phoff);
+        equal = false;
+    }
+
+    if (ehdr1.e_shoff != ehdr2.e_shoff) {
+        printEhdrDiff("e_shoff", ehdr1.e_shoff, ehdr2.e_shoff);
+        equal = false;
+    }
+
+    if (ehdr1.e_flags != ehdr2.e_flags) {
+        printEhdrDiff("e_flags", ehdr1.e_flags, ehdr2.e_flags);
+        equal = false;
+    }
+
+    if (ehdr1.e_ehsize != ehdr2.e_ehsize) {
+        printEhdrDiff("e_ehsize", ehdr1.e_ehsize, ehdr2.e_ehsize);
+        equal = false;
+    }
+
+    if (ehdr1.e_phentsize != ehdr2.e_phentsize) {
+        printEhdrDiff("e_phentsize", ehdr1.e_phentsize, ehdr2.e_phentsize);
+        equal = false;
+    }
+
+    if (ehdr1.e_phnum != ehdr2.e_phnum) {
+        printEhdrDiff("e_phnum", ehdr1.e_phnum, ehdr2.e_phnum);
+        equal = false;
+    }
+
+    if (ehdr1.e_shentsize != ehdr2.e_shentsize) {
+        printEhdrDiff("e_shentsize", ehdr1.e_shentsize, ehdr2.e_shentsize);
+        equal = false;
+    }
+
+    if (ehdr1.e_shnum != ehdr2.e_shnum) {
+        printEhdrDiff("e_shnum", ehdr1.e_shnum, ehdr2.e_shnum);
+        equal = false;
+    }
+
+    if (ehdr1.e_shstrndx != ehdr2.e_shstrndx) {
+        printEhdrDiff("e_shstrndx", ehdr1.e_shstrndx, ehdr2.e_shstrndx);
+        equal = false;
+    }
+
+    return equal;
+}
+
+// Compares the ELF64 Program (Segment) Headers.
+// Returns true if they are equal, otherwise false.
+bool Elf64Comparator::compare(const std::vector<Elf64_Phdr>& phdrs1,
+                              const std::vector<Elf64_Phdr>& phdrs2) {
+    bool equal = true;
+
+    std::cout << "\nComparing ELF64 Program Headers ..." << std::endl;
+
+    if (phdrs1.size() != phdrs2.size()) {
+        std::cout << "\tDiff phdrs1.size() = " << std::dec << phdrs1.size()
+                  << " != " << "phdrs2.size() = " << phdrs2.size() << std::endl;
+        return false;
+    }
+
+    for (int i = 0; i < phdrs1.size(); i++) {
+        Elf64_Phdr phdr1 = phdrs1.at(i);
+        Elf64_Phdr phdr2 = phdrs2.at(i);
+
+        if (phdr1.p_type != phdr2.p_type) {
+            printFieldDiff("phdrs", "p_type", i, phdr1.p_type, phdr2.p_type);
+            equal = false;
+        }
+
+        if (phdr1.p_flags != phdr2.p_flags) {
+            printFieldDiff("phdrs", "p_flags", i, phdr1.p_flags, phdr2.p_flags);
+            equal = false;
+        }
+
+        if (phdr1.p_offset != phdr2.p_offset) {
+            printFieldDiff("phdrs", "p_offset", i, phdr1.p_offset, phdr2.p_offset);
+            equal = false;
+        }
+
+        if (phdr1.p_vaddr != phdr2.p_vaddr) {
+            printFieldDiff("phdrs", "p_vaddr", i, phdr1.p_vaddr, phdr2.p_vaddr);
+            equal = false;
+        }
+
+        if (phdr1.p_paddr != phdr2.p_paddr) {
+            printFieldDiff("phdrs", "p_paddr", i, phdr1.p_paddr, phdr2.p_paddr);
+            equal = false;
+        }
+
+        if (phdr1.p_filesz != phdr2.p_filesz) {
+            printFieldDiff("phdrs", "p_filesz", i, phdr1.p_filesz, phdr2.p_filesz);
+            equal = false;
+        }
+
+        if (phdr1.p_memsz != phdr2.p_memsz) {
+            printFieldDiff("phdrs", "p_memsz", i, phdr1.p_memsz, phdr2.p_memsz);
+            equal = false;
+        }
+
+        if (phdr1.p_align != phdr2.p_align) {
+            printFieldDiff("phdrs", "p_align", i, phdr1.p_align, phdr2.p_align);
+            equal = false;
+        }
+    }
+
+    return equal;
+}
+
+// Compares the ELF64 Section Headers.
+// Returns true if they are equal, otherwise false.
+bool Elf64Comparator::compare(const std::vector<Elf64_Shdr>& shdrs1,
+                              const std::vector<Elf64_Shdr>& shdrs2) {
+    bool equal = true;
+
+    std::cout << "\nComparing ELF64 Section Headers ..." << std::endl;
+
+    if (shdrs1.size() != shdrs2.size()) {
+        std::cout << "\tDiff shdrs1.size() = " << std::dec << shdrs1.size()
+                  << " != " << "shdrs2.size() = " << shdrs2.size() << std::endl;
+        return false;
+    }
+
+    for (int i = 0; i < shdrs1.size(); i++) {
+        Elf64_Shdr shdr1 = shdrs1.at(i);
+        Elf64_Shdr shdr2 = shdrs2.at(i);
+
+        if (shdr1.sh_name != shdr2.sh_name) {
+            printFieldDiff("shdrs", "sh_name", i, shdr1.sh_name, shdr2.sh_name);
+            equal = false;
+        }
+
+        if (shdr1.sh_type != shdr2.sh_type) {
+            printFieldDiff("shdrs", "sh_type", i, shdr1.sh_type, shdr2.sh_type);
+            equal = false;
+        }
+
+        if (shdr1.sh_flags != shdr2.sh_flags) {
+            printFieldDiff("shdrs", "sh_flags", i, shdr1.sh_flags, shdr2.sh_flags);
+            equal = false;
+        }
+
+        if (shdr1.sh_addr != shdr2.sh_addr) {
+            printFieldDiff("shdrs", "sh_addr", i, shdr1.sh_addr, shdr2.sh_addr);
+            equal = false;
+        }
+
+        if (shdr1.sh_offset != shdr2.sh_offset) {
+            printFieldDiff("shdrs", "sh_offset", i, shdr1.sh_offset, shdr2.sh_offset);
+            equal = false;
+        }
+
+        if (shdr1.sh_size != shdr2.sh_size) {
+            printFieldDiff("shdrs", "sh_size", i, shdr1.sh_size, shdr2.sh_size);
+            equal = false;
+        }
+
+        if (shdr1.sh_link != shdr2.sh_link) {
+            printFieldDiff("shdrs", "sh_link", i, shdr1.sh_link, shdr2.sh_link);
+            equal = false;
+        }
+
+        if (shdr1.sh_info != shdr2.sh_info) {
+            printFieldDiff("shdrs", "sh_info", i, shdr1.sh_info, shdr2.sh_info);
+            equal = false;
+        }
+
+        if (shdr1.sh_addralign != shdr2.sh_addralign) {
+            printFieldDiff("shdrs", "sh_addralign", i, shdr1.sh_addralign, shdr2.sh_addralign);
+            equal = false;
+        }
+
+        if (shdr1.sh_entsize != shdr2.sh_entsize) {
+            printFieldDiff("shdrs", "sh_entsize", i, shdr1.sh_entsize, shdr2.sh_entsize);
+            equal = false;
+        }
+    }
+
+    return equal;
+}
+
+// Compares the ELF64 Section content.
+// Returns true if they are equal, otherwise false.
+bool Elf64Comparator::compare(const std::vector<Elf64_Sc>& sections1,
+                              const std::vector<Elf64_Sc>& sections2) {
+    bool equal = true;
+
+    std::cout << "\nComparing ELF64 Sections (content) ..." << std::endl;
+
+    if (sections1.size() != sections2.size()) {
+        std::cout << "\tDiff sections1.size() = " << std::dec << sections1.size()
+                  << " != " << "sections2.size() = " << sections2.size() << std::endl;
+        return false;
+    }
+
+    for (int i = 0; i < sections1.size(); i++) {
+        if (sections1.at(i).size != sections2.at(i).size) {
+            std::cout << "\tDiff sections1[" << std::dec << i << "].size = " << sections1.at(i).size
+                      << " != " << "sections2[" << i << "].size = " << sections2.at(i).size
+                      << std::endl;
+            equal = false;
+            // If size is different, data is not compared.
+            continue;
+        }
+
+        if (sections1.at(i).data.empty() && sections2.at(i).data.empty()) {
+            // The .bss section is empty.
+            continue;
+        }
+
+        if (sections1.at(i).data.empty() || sections2.at(i).data.empty()) {
+            // The index of the .bss section is different for both files.
+            equal = false;
+            continue;
+        }
+
+        if (sections1.at(i).data != sections2.at(i).data) {
+            std::cout << "\tDiff " << std::dec << "section1[" << i << "].data != " << "section2["
+                      << i << "].data" << std::endl;
+
+            equal = false;
+        }
+    }
+
+    return equal;
+}
+
+}  // namespace elf64
+}  // namespace android
diff --git a/libelf64/compare_libs.cpp b/libelf64/compare_libs.cpp
new file mode 100644
index 0000000..dcbae75
--- /dev/null
+++ b/libelf64/compare_libs.cpp
@@ -0,0 +1,90 @@
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
+#include <libelf64/comparator.h>
+#include <libelf64/elf64.h>
+#include <libelf64/parse.h>
+
+#include <iostream>
+#include <set>
+#include <string>
+#include <vector>
+
+#include <elf.h>
+#include <stdlib.h>
+
+void usage() {
+    const std::string progname = getprogname();
+
+    std::cout << "Usage: " << progname << " [shared_lib_1] [shared_lib_2]\n"
+              << R"(
+Options:
+shared_lib_1    elf64 shared library to compare with shared_lib_2
+shared_lib_2    elf64 shared library to compare with shared_lib_1
+)" << std::endl;
+}
+
+// Compare ELF64 binaries (shared libraries, executables).
+int main(int argc, char* argv[]) {
+    if (argc < 3) {
+        usage();
+        return EXIT_FAILURE;
+    }
+
+    std::string baseSharedLibName1(argv[1]);
+    std::string baseSharedLibName2(argv[2]);
+
+    android::elf64::Elf64Binary elf64Binary1;
+    android::elf64::Elf64Binary elf64Binary2;
+
+    bool parse = android::elf64::Elf64Parser::ParseElfFile(baseSharedLibName1, elf64Binary1);
+    if (!parse) {
+        std::cerr << "Failed to parse file " << baseSharedLibName1 << std::endl;
+        return EXIT_FAILURE;
+    }
+
+    parse = android::elf64::Elf64Parser::ParseElfFile(baseSharedLibName2, elf64Binary2);
+    if (!parse) {
+        std::cerr << "Failed to parse file " << baseSharedLibName2 << std::endl;
+        return EXIT_FAILURE;
+    }
+
+    if (android::elf64::Elf64Comparator::compare(elf64Binary1.ehdr, elf64Binary2.ehdr)) {
+        std::cout << "Executable Headers are equal" << std::endl;
+    } else {
+        std::cout << "Executable Headers are NOT equal" << std::endl;
+    }
+
+    if (android::elf64::Elf64Comparator::compare(elf64Binary1.phdrs, elf64Binary2.phdrs)) {
+        std::cout << "Program Headers are equal" << std::endl;
+    } else {
+        std::cout << "Program Headers are NOT equal" << std::endl;
+    }
+
+    if (android::elf64::Elf64Comparator::compare(elf64Binary1.shdrs, elf64Binary2.shdrs)) {
+        std::cout << "Section Headers are equal" << std::endl;
+    } else {
+        std::cout << "Section Headers are NOT equal" << std::endl;
+    }
+
+    if (android::elf64::Elf64Comparator::compare(elf64Binary1.sections, elf64Binary2.sections)) {
+        std::cout << "Sections are equal" << std::endl;
+    } else {
+        std::cout << "Sections are NOT equal" << std::endl;
+    }
+
+    return 0;
+}
diff --git a/libelf64/invalid_elf64_gen.cpp b/libelf64/gen_invalid_libs.cpp
similarity index 63%
rename from libelf64/invalid_elf64_gen.cpp
rename to libelf64/gen_invalid_libs.cpp
index 9288883..5656041 100644
--- a/libelf64/invalid_elf64_gen.cpp
+++ b/libelf64/gen_invalid_libs.cpp
@@ -15,8 +15,8 @@
  */
 
 #include <libelf64/elf64.h>
-#include <libelf64/elf64_writer.h>
 #include <libelf64/parse.h>
+#include <libelf64/writer.h>
 
 #include <iostream>
 #include <set>
@@ -143,13 +143,81 @@ void gen_lib_with_text_relocs_dyn_entry(const android::elf64::Elf64Binary& elf64
     android::elf64::Elf64Writer::WriteElf64File(copyElf64Binary, newSharedLibName);
 }
 
+// Generates a shared library which executable header indicates that there
+// are ZERO section headers.
+//
+// For example:
+//
+// $ readelf -h libtest_invalid-empty_shdr_table.so | grep Number
+// Number of program headers:         8
+// Number of section headers:         0 (0)
+void gen_lib_with_empty_shdr_table(const android::elf64::Elf64Binary& elf64Binary,
+                                   const std::string& newSharedLibName) {
+    android::elf64::Elf64Binary copyElf64Binary = elf64Binary;
+
+    copyElf64Binary.ehdr.e_shnum = 0;
+    android::elf64::Elf64Writer::WriteElf64File(copyElf64Binary, newSharedLibName);
+}
+
+void set_shdr_table_offset(const android::elf64::Elf64Binary& elf64Binary,
+                           const std::string& newSharedLibName, const Elf64_Off invalidOffset) {
+    android::elf64::Elf64Binary copyElf64Binary = elf64Binary;
+
+    // Set an invalid offset for the section headers.
+    copyElf64Binary.ehdr.e_shoff = invalidOffset;
+
+    std::cout << "Writing ELF64 binary to file " << newSharedLibName << std::endl;
+    android::elf64::Elf64Writer elf64Writer(newSharedLibName);
+    elf64Writer.WriteHeader(copyElf64Binary.ehdr);
+    elf64Writer.WriteProgramHeaders(copyElf64Binary.phdrs, copyElf64Binary.ehdr.e_phoff);
+    elf64Writer.WriteSections(copyElf64Binary.sections, copyElf64Binary.shdrs);
+
+    // Use the original e_shoff to store the section headers.
+    elf64Writer.WriteSectionHeaders(copyElf64Binary.shdrs, elf64Binary.ehdr.e_shoff);
+}
+
+// Generates a shared library which executable header has an invalid
+// section header offset.
+void gen_lib_with_unaligned_shdr_offset(const android::elf64::Elf64Binary& elf64Binary,
+                                        const std::string& newSharedLibName) {
+    const Elf64_Off unalignedOffset = elf64Binary.ehdr.e_shoff + 1;
+    set_shdr_table_offset(elf64Binary, newSharedLibName, unalignedOffset);
+}
+
+// Generates a shared library which executable header has ZERO as
+// section header offset.
+void gen_lib_with_zero_shdr_table_offset(const android::elf64::Elf64Binary& elf64Binary,
+                                         const std::string& newSharedLibName) {
+    const Elf64_Off zeroOffset = 0;
+    set_shdr_table_offset(elf64Binary, newSharedLibName, zeroOffset);
+}
+
+// Generates a shared library which section headers are all ZERO.
+void gen_lib_with_zero_shdr_table_content(const android::elf64::Elf64Binary& elf64Binary,
+                                          const std::string& newSharedLibName) {
+    android::elf64::Elf64Binary copyElf64Binary = elf64Binary;
+
+    std::cout << "Writing ELF64 binary to file " << newSharedLibName << std::endl;
+    android::elf64::Elf64Writer elf64Writer(newSharedLibName);
+    elf64Writer.WriteHeader(copyElf64Binary.ehdr);
+    elf64Writer.WriteProgramHeaders(copyElf64Binary.phdrs, copyElf64Binary.ehdr.e_phoff);
+    elf64Writer.WriteSections(copyElf64Binary.sections, copyElf64Binary.shdrs);
+
+    // Make the content of Elf64_Shdr zero.
+    for (int i = 0; i < copyElf64Binary.shdrs.size(); i++) {
+        copyElf64Binary.shdrs[i] = {0};
+    }
+
+    elf64Writer.WriteSectionHeaders(copyElf64Binary.shdrs, elf64Binary.ehdr.e_shoff);
+}
+
 void usage() {
     const std::string progname = getprogname();
 
     std::cout << "Usage: " << progname << " [shared_lib] [out_dir]...\n"
               << R"(
 Options:
-shared_lib       shared library that will be used as reference.
+shared_lib       elf64 shared library that will be used as reference.
 out_dir          the invalid shared libraries that are
                  generated will be placed in this directory.)"
               << std::endl;
@@ -180,6 +248,14 @@ int main(int argc, char* argv[]) {
         gen_lib_with_text_relocs_in_flags(elf64Binary, outputDir + "/libtest_invalid-textrels.so");
         gen_lib_with_text_relocs_dyn_entry(elf64Binary,
                                            outputDir + "/libtest_invalid-textrels2.so");
+        gen_lib_with_empty_shdr_table(elf64Binary,
+                                      outputDir + "/libtest_invalid-empty_shdr_table.so");
+        gen_lib_with_unaligned_shdr_offset(elf64Binary,
+                                           outputDir + "/libtest_invalid-unaligned_shdr_offset.so");
+        gen_lib_with_zero_shdr_table_content(
+                elf64Binary, outputDir + "/libtest_invalid-zero_shdr_table_content.so");
+        gen_lib_with_zero_shdr_table_offset(
+                elf64Binary, outputDir + "/libtest_invalid-zero_shdr_table_offset.so");
     }
 
     return 0;
diff --git a/libelf64/include/libelf64/comparator.h b/libelf64/include/libelf64/comparator.h
new file mode 100644
index 0000000..0ea1b76
--- /dev/null
+++ b/libelf64/include/libelf64/comparator.h
@@ -0,0 +1,58 @@
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
+#pragma once
+
+#include <libelf64/elf64.h>
+
+#include <elf.h>
+#include <vector>
+
+namespace android {
+namespace elf64 {
+
+// Class to compare ELF64 binaries (shared libraries, executables).
+//
+// This class provides methods to compare:
+//
+// - Executable header (Elf64_Ehdr)
+// - Program headers (Elf64_Phdr)
+// - Section contents
+// - Section headers (Elf64_Shdr)
+class Elf64Comparator {
+  public:
+    // Compares the ELF64 Executable Header.
+    // Returns true if they are equal, otherwise false.
+    static bool compare(const Elf64_Ehdr& ehdr1, const Elf64_Ehdr& ehdr2);
+
+    // Compares the ELF64 Program (Segment) Headers.
+    // Returns true if they are equal, otherwise false.
+    static bool compare(const std::vector<Elf64_Phdr>& phdrs1,
+                        const std::vector<Elf64_Phdr>& phdrs2);
+
+    // Compares the ELF64 Section Headers.
+    // Returns true if they are equal, otherwise false.
+    static bool compare(const std::vector<Elf64_Shdr>& shdrs1,
+                        const std::vector<Elf64_Shdr>& shdrs2);
+
+    // Compares the ELF64 Section content.
+    // Returns true if they are equal, otherwise false.
+    static bool compare(const std::vector<Elf64_Sc>& sections1,
+                        const std::vector<Elf64_Sc>& sections2);
+};
+
+}  // namespace elf64
+}  // namespace android
diff --git a/libelf64/include/libelf64/elf64_writer.h b/libelf64/include/libelf64/writer.h
similarity index 100%
rename from libelf64/include/libelf64/elf64_writer.h
rename to libelf64/include/libelf64/writer.h
diff --git a/libelf64/parse.cpp b/libelf64/parse.cpp
index 010d2e1..2c7e9c9 100644
--- a/libelf64/parse.cpp
+++ b/libelf64/parse.cpp
@@ -107,7 +107,10 @@ bool Elf64Parser::ParseSections() {
         uint32_t nameIdx = elfBinaryPtr->shdrs[i].sh_name;
         char* st = sStrTblPtr.data.data();
 
-        elfBinaryPtr->sections[i].name = &st[nameIdx];
+        if (nameIdx < sStrTblPtr.size) {
+            CHECK_NE(nullptr, memchr(&st[nameIdx], 0, sStrTblPtr.size - nameIdx));
+            elfBinaryPtr->sections[i].name = &st[nameIdx];
+        }
     }
 
     return true;
diff --git a/libelf64/tests/page_size_16kb/Android.bp b/libelf64/tests/page_size_16kb/Android.bp
index 5afe72e..14ade6f 100644
--- a/libelf64/tests/page_size_16kb/Android.bp
+++ b/libelf64/tests/page_size_16kb/Android.bp
@@ -31,8 +31,6 @@ cc_test {
         "elf_alignment_test.cpp",
     ],
 
-    cpp_std: "gnu++20",
-
     static_libs: [
         "libdm",
         "libext2_uuid",
diff --git a/libelf64/tests/page_size_16kb/elf_alignment_test.cpp b/libelf64/tests/page_size_16kb/elf_alignment_test.cpp
index dae2f2e..33f3aee 100644
--- a/libelf64/tests/page_size_16kb/elf_alignment_test.cpp
+++ b/libelf64/tests/page_size_16kb/elf_alignment_test.cpp
@@ -18,6 +18,7 @@
 #include <mntent.h>
 #include <gtest/gtest.h>
 
+#include <regex>
 #include <set>
 
 #include <libelf64/iter.h>
@@ -32,6 +33,19 @@ constexpr char kVendorApiLevelProp[] = "ro.vendor.api_level";
 // 16KB by default (unsupported devices must explicitly opt-out)
 constexpr size_t kRequiredMaxSupportedPageSize = 0x4000;
 
+static inline std::string escapeForRegex(const std::string& str) {
+  // Regex metacharacters to be escaped
+  static const std::regex specialChars(R"([.^$|(){}\[\]+*?\\])");
+
+  // Replace each special character with its escaped version
+  return std::regex_replace(str, specialChars, R"(\$&)");
+}
+
+static inline bool startsWithPattern(const std::string& str, const std::string& pattern) {
+    std::regex _pattern("^" + pattern + ".*");
+    return std::regex_match(str, _pattern);
+}
+
 static std::set<std::string> GetMounts() {
     std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "re"), endmntent);
     std::set<std::string> exclude ({ "/", "/config", "/data", "/data_mirror", "/dev",
@@ -61,24 +75,33 @@ static std::set<std::string> GetMounts() {
 class ElfAlignmentTest :public ::testing::TestWithParam<std::string> {
   protected:
     static void LoadAlignmentCb(const android::elf64::Elf64Binary& elf) {
-      static constexpr std::array ignored_directories{
+      static std::array ignored_directories{
         // Ignore VNDK APEXes. They are prebuilts from old branches, and would
         // only be used on devices with old vendor images.
-        "/apex/com.android.vndk.v",
-        // This directory contains the trusty kernel.
-        // TODO(b/365240530): Remove this once 16K pages will work on the trusty kernel.
-        "/system_ext/etc/hw/",
+        escapeForRegex("/apex/com.android.vndk.v"),
+        // Ignore Trusty VM images as they don't run in userspace, so 16K is not
+        // required. See b/365240530 for more context.
+        escapeForRegex("/system_ext/etc/vm/trusty_vm"),
         // Ignore non-Android firmware images.
-        "/odm/firmware",
-        "/vendor/firmware",
-        "/vendor/firmware_mnt/image"
+        escapeForRegex("/odm/firmware/"),
+        escapeForRegex("/vendor/firmware/"),
+        escapeForRegex("/vendor/firmware_mnt/image"),
+        // Ignore TEE binaries ("glob: /apex/com.*.android.authfw.ta*")
+        escapeForRegex("/apex/com.") + ".*" + escapeForRegex(".android.authfw.ta")
       };
 
-      for (const auto& dir : ignored_directories) {
-        if (elf.path.starts_with(dir)) {
+      for (const auto& pattern : ignored_directories) {
+        if (startsWithPattern(elf.path, pattern)) {
           return;
         }
       }
+
+      // Ignore ART Odex files for now. They are not 16K aligned.
+      // b/376814207
+      if (elf.path.ends_with(".odex")) {
+        return;
+      }
+
       for (int i = 0; i < elf.phdrs.size(); i++) {
         Elf64_Phdr phdr = elf.phdrs[i];
 
diff --git a/libelf64/elf64_writer.cpp b/libelf64/writer.cpp
similarity index 98%
rename from libelf64/elf64_writer.cpp
rename to libelf64/writer.cpp
index 387d951..d3e7c6c 100644
--- a/libelf64/elf64_writer.cpp
+++ b/libelf64/writer.cpp
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-#include <libelf64/elf64_writer.h>
+#include <libelf64/writer.h>
 
 #include <libelf64/elf64.h>
 
diff --git a/libmemevents/bpfprogs/bpfMemEvents.c b/libmemevents/bpfprogs/bpfMemEvents.c
index 540dfd6..66c6bde 100644
--- a/libmemevents/bpfprogs/bpfMemEvents.c
+++ b/libmemevents/bpfprogs/bpfMemEvents.c
@@ -27,7 +27,7 @@ DEFINE_BPF_RINGBUF(ams_rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_
 DEFINE_BPF_RINGBUF(lmkd_rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID,
                    AID_SYSTEM, 0660)
 
-DEFINE_BPF_PROG("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM, tp_ams)
+DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM, tp_ams, KVER_5_8)
 (struct mark_victim_args* args) {
     unsigned long long timestamp_ns = bpf_ktime_get_ns();
     struct mem_event_t* data = bpf_ams_rb_reserve();
@@ -52,8 +52,8 @@ DEFINE_BPF_PROG("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM, tp_ams)
     return 0;
 }
 
-DEFINE_BPF_PROG("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin/lmkd", AID_ROOT, AID_SYSTEM,
-                tp_lmkd_dr_start)
+DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin/lmkd", AID_ROOT, AID_SYSTEM,
+                     tp_lmkd_dr_start, KVER_5_8)
 (struct direct_reclaim_begin_args* __unused args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -65,8 +65,8 @@ DEFINE_BPF_PROG("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin/lmkd", AID_ROO
     return 0;
 }
 
-DEFINE_BPF_PROG("tracepoint/vmscan/mm_vmscan_direct_reclaim_end/lmkd", AID_ROOT, AID_SYSTEM,
-                tp_lmkd_dr_end)
+DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_direct_reclaim_end/lmkd", AID_ROOT, AID_SYSTEM,
+                     tp_lmkd_dr_end, KVER_5_8)
 (struct direct_reclaim_end_args* __unused args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -78,8 +78,8 @@ DEFINE_BPF_PROG("tracepoint/vmscan/mm_vmscan_direct_reclaim_end/lmkd", AID_ROOT,
     return 0;
 }
 
-DEFINE_BPF_PROG("tracepoint/vmscan/mm_vmscan_kswapd_wake/lmkd", AID_ROOT, AID_SYSTEM,
-                tp_lmkd_kswapd_wake)
+DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_kswapd_wake/lmkd", AID_ROOT, AID_SYSTEM,
+                     tp_lmkd_kswapd_wake, KVER_5_8)
 (struct kswapd_wake_args* args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
@@ -94,8 +94,8 @@ DEFINE_BPF_PROG("tracepoint/vmscan/mm_vmscan_kswapd_wake/lmkd", AID_ROOT, AID_SY
     return 0;
 }
 
-DEFINE_BPF_PROG("tracepoint/vmscan/mm_vmscan_kswapd_sleep/lmkd", AID_ROOT, AID_SYSTEM,
-                tp_lmkd_kswapd_sleep)
+DEFINE_BPF_PROG_KVER("tracepoint/vmscan/mm_vmscan_kswapd_sleep/lmkd", AID_ROOT, AID_SYSTEM,
+                     tp_lmkd_kswapd_sleep, KVER_5_8)
 (struct kswapd_sleep_args* args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
diff --git a/libmemevents/bpfprogs/bpfMemEventsTest.c b/libmemevents/bpfprogs/bpfMemEventsTest.c
index 0cb4033..36d8b84 100644
--- a/libmemevents/bpfprogs/bpfMemEventsTest.c
+++ b/libmemevents/bpfprogs/bpfMemEventsTest.c
@@ -25,7 +25,7 @@
 DEFINE_BPF_RINGBUF(rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID, AID_SYSTEM,
                    0660)
 
-DEFINE_BPF_PROG("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tp_ams)
+DEFINE_BPF_PROG_KVER("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tp_ams, KVER_5_8)
 (struct mark_victim_args* args) {
     unsigned long long timestamp_ns = bpf_ktime_get_ns();
     struct mem_event_t* data = bpf_rb_reserve();
@@ -56,7 +56,7 @@ DEFINE_BPF_PROG("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tp_ams)
  * executed manually with BPF_PROG_RUN, and the tracepoint bpf-progs do not
  * currently implement this BPF_PROG_RUN operation.
  */
-DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, tp_memevents_test_oom, KVER(5, 8, 0))
+DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, tp_memevents_test_oom, KVER_5_8)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -81,7 +81,7 @@ DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, tp_memevents_test_
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_begin", AID_ROOT, AID_ROOT,
-                     tp_memevents_test_dr_begin, KVER(5, 8, 0))
+                     tp_memevents_test_dr_begin, KVER_5_8)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -94,7 +94,7 @@ DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_begin", AID_ROOT, AID_ROOT,
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_end", AID_ROOT, AID_ROOT, tp_memevents_test_dr_end,
-                     KVER(5, 8, 0))
+                     KVER_5_8)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -107,7 +107,7 @@ DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_end", AID_ROOT, AID_ROOT, tp_memev
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/kswapd_wake", AID_ROOT, AID_ROOT, tp_memevents_test_kswapd_wake,
-                     KVER(5, 8, 0))
+                     KVER_5_8)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
@@ -124,7 +124,7 @@ DEFINE_BPF_PROG_KVER("skfilter/kswapd_wake", AID_ROOT, AID_ROOT, tp_memevents_te
 }
 
 DEFINE_BPF_PROG_KVER("skfilter/kswapd_sleep", AID_ROOT, AID_ROOT, tp_memevents_test_kswapd_sleep,
-                     KVER(5, 8, 0))
+                     KVER_5_8)
 (void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
diff --git a/libmemevents/include/memevents/bpf_types.h b/libmemevents/include/memevents/bpf_types.h
index 004b15c..9950d6d 100644
--- a/libmemevents/include/memevents/bpf_types.h
+++ b/libmemevents/include/memevents/bpf_types.h
@@ -62,7 +62,7 @@ struct mem_event_t {
         struct OomKill {
             uint32_t pid;
             uint64_t timestamp_ms;
-            uint64_t oom_score_adj;
+            short oom_score_adj;
             uint32_t uid;
             char process_name[MEM_EVENT_PROC_NAME_LEN];
             uint64_t total_vm_kb;
diff --git a/libmemevents/include/memevents/memevents.h b/libmemevents/include/memevents/memevents.h
index 9282ab9..e91f631 100644
--- a/libmemevents/include/memevents/memevents.h
+++ b/libmemevents/include/memevents/memevents.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <android-base/thread_annotations.h>
+
 #include <memory>
 #include <vector>
 
@@ -130,7 +132,12 @@ class MemEventListener final {
     bool mEventsRegistered[NR_MEM_EVENTS];
     int mNumEventsRegistered;
     MemEventClient mClient;
-    std::unique_ptr<MemBpfRingbuf> memBpfRb;
+    /*
+     * BFP ring buffer is designed as single producer single consumer.
+     * Protect against concurrent accesses.
+     */
+    std::mutex mRingBufMutex;
+    std::unique_ptr<MemBpfRingbuf> memBpfRb GUARDED_BY(mRingBufMutex);
     bool mAttachTpForTests;
 
     bool isValidEventType(mem_event_type_t event_type) const;
diff --git a/libmemevents/memevents.cpp b/libmemevents/memevents.cpp
index ca29263..c27303b 100644
--- a/libmemevents/memevents.cpp
+++ b/libmemevents/memevents.cpp
@@ -26,6 +26,7 @@
 #include <algorithm>
 #include <cstdio>
 #include <functional>
+#include <mutex>
 #include <optional>
 #include <sstream>
 #include <string>
@@ -335,14 +336,20 @@ void MemEventListener::deregisterAllEvents() {
 }
 
 bool MemEventListener::getMemEvents(std::vector<mem_event_t>& mem_events) {
+    // Ensure consuming from the BPF ring buffer is thread safe.
+    std::lock_guard<std::mutex> lock(mRingBufMutex);
+
     if (!ok()) {
         LOG(ERROR) << "memevent failed getting memory events, failure to initialize";
         return false;
     }
 
     base::Result<int> ret = memBpfRb->ConsumeAll([&](const mem_event_t& mem_event) {
-        if (isValidEventType(mem_event.type) && mEventsRegistered[mem_event.type])
-            mem_events.emplace_back(mem_event);
+        if (!isValidEventType(mem_event.type))
+            LOG(FATAL) << "Unexpected mem_event type: this should never happen: "
+                       << "there is likely data corruption due to memory ordering";
+
+        if (mEventsRegistered[mem_event.type]) mem_events.emplace_back(mem_event);
     });
 
     if (!ret.ok()) {
diff --git a/libmeminfo_test.cpp b/libmeminfo_test.cpp
index 2d89ee5..2d59e42 100644
--- a/libmeminfo_test.cpp
+++ b/libmeminfo_test.cpp
@@ -35,7 +35,6 @@
 #include <android-base/logging.h>
 #include <android-base/properties.h>
 #include <android-base/stringprintf.h>
-#include <android-base/strings.h>
 
 using namespace std;
 using namespace android::meminfo;
@@ -403,7 +402,7 @@ TEST(ProcMemInfo, ForEachExistingVmaTest) {
     EXPECT_EQ(vmas[0].name, "[anon:dalvik-zygote-jit-code-cache]");
     EXPECT_EQ(vmas[1].name, "/system/framework/x86_64/boot-framework.art");
     EXPECT_TRUE(vmas[2].name == "[anon:libc_malloc]" ||
-                android::base::StartsWith(vmas[2].name, "[anon:scudo:"))
+                vmas[2].name.starts_with("[anon:scudo:"))
             << "Unknown map name " << vmas[2].name;
     EXPECT_EQ(vmas[3].name, "/system/priv-app/SettingsProvider/oat/x86_64/SettingsProvider.odex");
     EXPECT_EQ(vmas[4].name, "/system/lib64/libhwui.so");
@@ -554,7 +553,7 @@ TEST(ProcMemInfo, ForEachVmaFromFile_SmapsTest) {
     EXPECT_EQ(vmas[0].name, "[anon:dalvik-zygote-jit-code-cache]");
     EXPECT_EQ(vmas[1].name, "/system/framework/x86_64/boot-framework.art");
     EXPECT_TRUE(vmas[2].name == "[anon:libc_malloc]" ||
-                android::base::StartsWith(vmas[2].name, "[anon:scudo:"))
+                vmas[2].name.starts_with("[anon:scudo:"))
             << "Unknown map name " << vmas[2].name;
     EXPECT_EQ(vmas[3].name, "/system/priv-app/SettingsProvider/oat/x86_64/SettingsProvider.odex");
     EXPECT_EQ(vmas[4].name, "/system/lib64/libhwui.so");
@@ -701,7 +700,7 @@ TEST(ProcMemInfo, ForEachVmaFromFile_MapsTest) {
     EXPECT_EQ(vmas[0].name, "[anon:dalvik-zygote-jit-code-cache]");
     EXPECT_EQ(vmas[1].name, "/system/framework/x86_64/boot-framework.art");
     EXPECT_TRUE(vmas[2].name == "[anon:libc_malloc]" ||
-                android::base::StartsWith(vmas[2].name, "[anon:scudo:"))
+                vmas[2].name.starts_with("[anon:scudo:"))
             << "Unknown map name " << vmas[2].name;
     EXPECT_EQ(vmas[3].name, "/system/priv-app/SettingsProvider/oat/x86_64/SettingsProvider.odex");
     EXPECT_EQ(vmas[4].name, "/system/lib64/libhwui.so");
@@ -793,7 +792,7 @@ TEST(ProcMemInfo, SmapsTest) {
     EXPECT_EQ(vmas[0].name, "[anon:dalvik-zygote-jit-code-cache]");
     EXPECT_EQ(vmas[1].name, "/system/framework/x86_64/boot-framework.art");
     EXPECT_TRUE(vmas[2].name == "[anon:libc_malloc]" ||
-                android::base::StartsWith(vmas[2].name, "[anon:scudo:"))
+                vmas[2].name.starts_with("[anon:scudo:"))
             << "Unknown map name " << vmas[2].name;
     EXPECT_EQ(vmas[3].name, "/system/priv-app/SettingsProvider/oat/x86_64/SettingsProvider.odex");
     EXPECT_EQ(vmas[4].name, "/system/lib64/libhwui.so");
diff --git a/libsmapinfo/smapinfo.cpp b/libsmapinfo/smapinfo.cpp
index 1d2e4e8..8fe6bee 100644
--- a/libsmapinfo/smapinfo.cpp
+++ b/libsmapinfo/smapinfo.cpp
@@ -31,7 +31,6 @@
 #include <android-base/file.h>
 #include <android-base/parseint.h>
 #include <android-base/stringprintf.h>
-#include <android-base/strings.h>
 #include <meminfo/sysmeminfo.h>
 
 #include <processrecord.h>
@@ -538,8 +537,7 @@ static bool populate_libs(struct params* params, uint64_t pgflags, uint64_t pgfl
         LibProcRecord record(proc);
         for (const Vma& map : maps) {
             // Skip library/map if the prefix for the path doesn't match.
-            if (!params->lib_prefix.empty() &&
-                !::android::base::StartsWith(map.name, params->lib_prefix)) {
+            if (!params->lib_prefix.empty() && !map.name.starts_with(params->lib_prefix)) {
                 continue;
             }
             // Skip excluded library/map names.
@@ -925,7 +923,7 @@ void VmaInfo::to_json(bool total, std::ostream& out) const {
 }
 
 static bool is_library(const std::string& name) {
-    return (name.size() > 4) && (name[0] == '/') && ::android::base::EndsWith(name, ".so");
+    return (name.size() > 4) && (name[0] == '/') && name.ends_with(".so");
 }
 
 static void infer_vma_name(VmaInfo& current, const VmaInfo& recent) {
diff --git a/procmeminfo.cpp b/procmeminfo.cpp
index e604bce..91ffa68 100644
--- a/procmeminfo.cpp
+++ b/procmeminfo.cpp
@@ -32,7 +32,6 @@
 #include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/stringprintf.h>
-#include <android-base/strings.h>
 #include <android-base/unique_fd.h>
 #include <procinfo/process_map.h>
 
diff --git a/sysmeminfo.cpp b/sysmeminfo.cpp
index 60c1c83..f64becc 100644
--- a/sysmeminfo.cpp
+++ b/sysmeminfo.cpp
@@ -42,7 +42,6 @@
 #include <android-base/logging.h>
 #include <android-base/parseint.h>
 #include <android-base/stringprintf.h>
-#include <android-base/strings.h>
 #include <android-base/unique_fd.h>
 #include <dmabufinfo/dmabuf_sysfs_stats.h>
 
diff --git a/vts/Android.bp b/vts/Android.bp
index ec7f58a..dc0aa2f 100644
--- a/vts/Android.bp
+++ b/vts/Android.bp
@@ -13,6 +13,7 @@
 // limitations under the License.
 
 package {
+    default_team: "trendy_team_android_kernel",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
```

