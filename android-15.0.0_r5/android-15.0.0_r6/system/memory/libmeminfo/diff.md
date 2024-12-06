```diff
diff --git a/libelf64/Android.bp b/libelf64/Android.bp
index 835975c..316f9c9 100644
--- a/libelf64/Android.bp
+++ b/libelf64/Android.bp
@@ -27,8 +27,29 @@ cc_library {
         "include",
     ],
     srcs: [
-        "parse.cpp",
+        "elf64_writer.cpp",
         "iter.cpp",
+        "parse.cpp",
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
+    name: "geninvalelf64",
+    srcs: [
+        "invalid_elf64_gen.cpp",
+    ],
+    static_libs: [
+        "libelf64",
+    ],
+    shared_libs: [
+        "libbase",
     ],
     cflags: [
         "-Wall",
diff --git a/libelf64/elf64_writer.cpp b/libelf64/elf64_writer.cpp
new file mode 100644
index 0000000..387d951
--- /dev/null
+++ b/libelf64/elf64_writer.cpp
@@ -0,0 +1,94 @@
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
+#include <libelf64/elf64_writer.h>
+
+#include <libelf64/elf64.h>
+
+#include <stdlib.h>
+#include <fstream>
+#include <iostream>
+#include <string>
+#include <vector>
+
+#include <elf.h>
+
+namespace android {
+namespace elf64 {
+
+void Elf64Writer::WriteElf64File(const Elf64Binary& elf64Binary, const std::string& fileName) {
+    std::cout << "Writing ELF64 binary to file " << fileName << std::endl;
+
+    Elf64Writer elf64Writer(fileName);
+    elf64Writer.WriteHeader(elf64Binary.ehdr);
+    elf64Writer.WriteProgramHeaders(elf64Binary.phdrs, elf64Binary.ehdr.e_phoff);
+    elf64Writer.WriteSections(elf64Binary.sections, elf64Binary.shdrs);
+    elf64Writer.WriteSectionHeaders(elf64Binary.shdrs, elf64Binary.ehdr.e_shoff);
+}
+
+Elf64Writer::Elf64Writer(const std::string& fileName) {
+    elf64stream.open(fileName.c_str(), std::ofstream::out | std::ofstream::binary);
+    if (!elf64stream) {
+        std::cerr << "Failed to open the file: " << fileName << std::endl;
+        exit(-1);
+    }
+}
+
+void Elf64Writer::WriteHeader(const Elf64_Ehdr& ehdr) {
+    Write((char*)&ehdr, sizeof(ehdr));
+}
+
+void Elf64Writer::WriteProgramHeaders(const std::vector<Elf64_Phdr>& phdrs, const Elf64_Off phoff) {
+    elf64stream.seekp(phoff);
+
+    for (int i = 0; i < phdrs.size(); i++) {
+        Write((char*)&phdrs[i], sizeof(phdrs[i]));
+    }
+}
+
+void Elf64Writer::WriteSectionHeaders(const std::vector<Elf64_Shdr>& shdrs, const Elf64_Off shoff) {
+    elf64stream.seekp(shoff);
+
+    for (int i = 0; i < shdrs.size(); i++) {
+        Write((char*)&shdrs[i], sizeof(shdrs[i]));
+    }
+}
+
+void Elf64Writer::WriteSections(const std::vector<Elf64_Sc>& sections,
+                                const std::vector<Elf64_Shdr>& shdrs) {
+    for (int i = 0; i < sections.size(); i++) {
+        if (shdrs[i].sh_type == SHT_NOBITS) {
+            // Skip .bss section because it is empty.
+            continue;
+        }
+
+        // Move the cursor position to offset provided by the section header.
+        elf64stream.seekp(shdrs[i].sh_offset);
+
+        Write(sections[i].data.data(), sections[i].size);
+    }
+}
+
+void Elf64Writer::Write(const char* const data, const std::streamsize size) {
+    elf64stream.write(data, size);
+    if (!elf64stream) {
+        std::cerr << "Failed to write [" << size << "] bytes" << std::endl;
+        exit(-1);
+    }
+}
+
+}  // namespace elf64
+}  // namespace android
diff --git a/libelf64/include/libelf64/elf64.h b/libelf64/include/libelf64/elf64.h
index b882e31..4abcbd6 100644
--- a/libelf64/include/libelf64/elf64.h
+++ b/libelf64/include/libelf64/elf64.h
@@ -16,11 +16,12 @@
 
 #pragma once
 
-#include <elf.h>
+#include <sys/types.h>
 #include <string>
 #include <vector>
 
-using namespace std;
+#include <android-base/logging.h>
+#include <elf.h>
 
 namespace android {
 namespace elf64 {
@@ -74,6 +75,84 @@ class Elf64Binary {
     std::vector<Elf64_Shdr> shdrs;
     std::vector<Elf64_Sc> sections;
     std::string path;
+
+    bool IsElf64() { return ehdr.e_ident[EI_CLASS] == ELFCLASS64; }
+
+    // Returns the index of the dynamic section header if found,
+    // otherwise it returns -1.
+    //
+    // Note: The dynamic section can be identified by:
+    //
+    //   - the section header with name .dynamic
+    //   - the section header type SHT_DYNAMIC
+    int GetDynamicSectionIndex() {
+        for (int i = 0; i < shdrs.size(); i++) {
+            if (shdrs.at(i).sh_type == SHT_DYNAMIC) {
+                return i;
+            }
+        }
+
+        return -1;
+    }
+
+    // Populate dynEntries with the entries in the .dynamic section.
+    void AppendDynamicEntries(std::vector<Elf64_Dyn>* dynEntries) {
+        int idx = GetDynamicSectionIndex();
+
+        if (idx == -1) {
+            return;
+        }
+
+        Elf64_Dyn* dynPtr = (Elf64_Dyn*)sections.at(idx).data.data();
+        int numEntries = sections.at(idx).data.size() / sizeof(*dynPtr);
+
+        for (int j = 0; j < numEntries; j++) {
+            Elf64_Dyn dynEntry;
+            memcpy(&dynEntry, dynPtr, sizeof(*dynPtr));
+            dynPtr++;
+
+            dynEntries->push_back(dynEntry);
+        }
+    }
+
+    // Set the dynEntries in the .dynamic section.
+    void SetDynamicEntries(const std::vector<Elf64_Dyn>* dynEntries) {
+        int idx = GetDynamicSectionIndex();
+
+        if (idx == -1) {
+            return;
+        }
+
+        Elf64_Dyn* dynPtr = (Elf64_Dyn*)sections.at(idx).data.data();
+        int numEntries = sections.at(idx).data.size() / sizeof(*dynPtr);
+
+        for (int j = 0; j < dynEntries->size() && j < numEntries; j++) {
+            memcpy(dynPtr, &dynEntries->at(j), sizeof(*dynPtr));
+            dynPtr++;
+        }
+    }
+
+    // Returns the string at the given offset in the dynamic string table.
+    // If .dynamic or .dynstr sections are not found, it returns an empty string.
+    // If the offset is invalid, it returns an empty  string.
+    std::string GetStrFromDynStrTable(Elf64_Xword offset) {
+        int idx = GetDynamicSectionIndex();
+
+        if (idx == -1) {
+            return "";
+        }
+
+        // Get the index of the string table .dynstr.
+        Elf64_Word dynStrIdx = shdrs.at(idx).sh_link;
+        if (offset >= sections.at(dynStrIdx).data.size()) {
+            return "";
+        }
+
+        char* st = sections.at(dynStrIdx).data.data();
+
+        CHECK_NE(nullptr, memchr(&st[offset], 0, sections.at(dynStrIdx).data.size() - offset));
+        return &st[offset];
+    }
 };
 
 }  // namespace elf64
diff --git a/libelf64/include/libelf64/elf64_writer.h b/libelf64/include/libelf64/elf64_writer.h
new file mode 100644
index 0000000..8de993d
--- /dev/null
+++ b/libelf64/include/libelf64/elf64_writer.h
@@ -0,0 +1,78 @@
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
+#include <stdint.h>
+#include <fstream>
+#include <string>
+#include <vector>
+
+#include <elf.h>
+
+namespace android {
+namespace elf64 {
+
+// Class to write elf64 binaries to files. It provides methods
+// to write the different parts of the efl64 binary:
+//
+// - Executable Header (Elf64_Ehdr)
+// - Program Headers (Elf64_Phdr)
+// - Section Headers (Elf64_Shdr)
+// - Sections (content)
+//
+// The basic usage of the library is:
+//
+//       android::elf64::Elf64Binary elf64Binary;
+//       // Populate elf64Binary
+//       elf64Binary.ehdr.e_phoff = 0xBEEFFADE
+//       std::string fileName("new_binary.so");
+//       android::elf64::Elf64Writer::WriteElfFile(elf64Binary, fileName);
+//
+// If it is necessary to have more control about the different parts
+// that need to be written or omitted, we can use:
+//
+//       android::elf64::Elf64Binary elf64Binary;
+//       // Populate elf64Binary
+//
+//       std::string fileName("new_binary.so");
+//       Elf64Writer elf64Writer(fileName);
+//
+//       elf64Writer.WriteHeader(elf64Binary.ehdr);
+//       elf64Writer.WriteProgramHeaders(elf64Binary.phdrs, 0xBEEF);
+//       elf64Writer.WriteSectionHeaders(elf64Binary.shdrs, 0xFADE);
+//       elf64Writer.WriteSections(elf64Binary.sections, elf64Binary.shdrs);
+//
+class Elf64Writer {
+  public:
+    Elf64Writer(const std::string& fileName);
+
+    void WriteHeader(const Elf64_Ehdr& ehdr);
+    void WriteProgramHeaders(const std::vector<Elf64_Phdr>& phdrs, const Elf64_Off phoff);
+    void WriteSectionHeaders(const std::vector<Elf64_Shdr>& shdrs, const Elf64_Off shoff);
+    void WriteSections(const std::vector<Elf64_Sc>& sections, const std::vector<Elf64_Shdr>& shdrs);
+
+    static void WriteElf64File(const Elf64Binary& elf64Binary, const std::string& fileName);
+
+  private:
+    std::ofstream elf64stream;
+    void Write(const char* const data, const std::streamsize size);
+};
+
+}  // namespace elf64
+}  // namespace android
diff --git a/libelf64/include/libelf64/parse.h b/libelf64/include/libelf64/parse.h
index 1b43fe8..35734e4 100644
--- a/libelf64/include/libelf64/parse.h
+++ b/libelf64/include/libelf64/parse.h
@@ -27,24 +27,34 @@ namespace elf64 {
 //
 // The class will parse the 4 parts if present:
 //
-// - Executable header.
-// - Program headers (present in executables or shared libraries).
+// - Executable header (Elf64_Ehdr).
+// - Program headers (Elf64_Phdr - present in executables or shared libraries).
+// - Section headers (Elf64_Shdr)
 // - Sections (.interp, .init, .plt, .text, .rodata, .data, .bss, .shstrtab, etc).
-// - Section headers.
+//
+// The basic usage of the library is:
+//
+//       android::elf64::Elf64Binary elf64Binary;
+//       std::string fileName("new_binary.so");
+//       // The content of the elf file will be populated in elf64Binary.
+//       android::elf64::Elf64Parser::ParseElfFile(fileName, elf64Binary);
 //
 class Elf64Parser {
   public:
     // Parse the elf file and populate the elfBinary object.
-    static bool ParseElfFile(const std::string& fileName, Elf64Binary& elfBinary);
+    // Returns true if the parsing was successful, otherwise false.
+    [[nodiscard]] static bool ParseElfFile(const std::string& fileName, Elf64Binary& elfBinary);
+    static bool IsElf64(const std::string& fileName);
 
   private:
-    static bool OpenElfFile(const std::string& fileName, std::ifstream& elfFile);
-    static void CloseElfFile(std::ifstream& elfFile);
-    static bool ParseExecutableHeader(std::ifstream& elfFile, Elf64Binary& elfBinary);
-    static bool IsElf64(Elf64Binary& elf64Binary);
-    static bool ParseProgramHeaders(std::ifstream& elfFile, Elf64Binary& elfBinary);
-    static bool ParseSections(std::ifstream& elfFile, Elf64Binary& elfBinary);
-    static bool ParseSectionHeaders(std::ifstream& elfFile, Elf64Binary& elfBinary);
+    std::ifstream elf64stream;
+    Elf64Binary* elfBinaryPtr;
+
+    Elf64Parser(const std::string& fileName, Elf64Binary& elfBinary);
+    bool ParseExecutableHeader();
+    bool ParseProgramHeaders();
+    bool ParseSections();
+    bool ParseSectionHeaders();
 };
 
 }  // namespace elf64
diff --git a/libelf64/invalid_elf64_gen.cpp b/libelf64/invalid_elf64_gen.cpp
new file mode 100644
index 0000000..9288883
--- /dev/null
+++ b/libelf64/invalid_elf64_gen.cpp
@@ -0,0 +1,186 @@
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
+#include <libelf64/elf64.h>
+#include <libelf64/elf64_writer.h>
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
+// Remove the sharedLibs from the .dynamic section.
+// In order to remove the sharedLibs from the .dynamic
+// section, it sets the Elf64_Dyn.d_tag to DT_DEBUG.
+void remove_needed_shared_libs(android::elf64::Elf64Binary& elf64Binary,
+                               const std::set<std::string>& sharedLibs) {
+    std::vector<Elf64_Dyn> dynEntries;
+
+    elf64Binary.AppendDynamicEntries(&dynEntries);
+
+    for (int i = 0; i < dynEntries.size(); i++) {
+        if (dynEntries[i].d_tag == DT_NEEDED) {
+            std::string libName = elf64Binary.GetStrFromDynStrTable(dynEntries[i].d_un.d_val);
+
+            if (sharedLibs.count(libName)) {
+                dynEntries[i].d_tag = DT_DEBUG;
+            }
+        }
+    }
+
+    elf64Binary.SetDynamicEntries(&dynEntries);
+}
+
+void set_exec_segments_as_rwx(android::elf64::Elf64Binary& elf64Binary) {
+    for (int i = 0; i < elf64Binary.phdrs.size(); i++) {
+        if (elf64Binary.phdrs[i].p_flags & PF_X) {
+            elf64Binary.phdrs[i].p_flags |= PF_W;
+        }
+    }
+}
+
+// Generates a shared library with the executable segments as read/write/exec.
+void gen_lib_with_rwx_segment(const android::elf64::Elf64Binary& elf64Binary,
+                              const std::string& newSharedLibName) {
+    android::elf64::Elf64Binary copyElf64Binary = elf64Binary;
+    set_exec_segments_as_rwx(copyElf64Binary);
+    android::elf64::Elf64Writer::WriteElf64File(copyElf64Binary, newSharedLibName);
+}
+
+// Generates a shared library with the size of the section headers as zero.
+void gen_lib_with_zero_shentsize(const android::elf64::Elf64Binary& elf64Binary,
+                                 const std::string& newSharedLibName) {
+    android::elf64::Elf64Binary copyElf64Binary = elf64Binary;
+
+    copyElf64Binary.ehdr.e_shentsize = 0;
+    android::elf64::Elf64Writer::WriteElf64File(copyElf64Binary, newSharedLibName);
+}
+
+// Generates a shared library with invalid section header string table index.
+void gen_lib_with_zero_shstrndx(const android::elf64::Elf64Binary& elf64Binary,
+                                const std::string& newSharedLibName) {
+    android::elf64::Elf64Binary copyElf64Binary = elf64Binary;
+
+    copyElf64Binary.ehdr.e_shstrndx = 0;
+    android::elf64::Elf64Writer::WriteElf64File(copyElf64Binary, newSharedLibName);
+}
+
+// Generates a shared library with text relocations set in DT_FLAGS dynamic
+// entry. For example:
+//
+//  $ readelf -d libtest_invalid-textrels.so | grep TEXTREL
+//  0x000000000000001e (FLAGS)              TEXTREL BIND_NOW
+void gen_lib_with_text_relocs_in_flags(const android::elf64::Elf64Binary& elf64Binary,
+                                       const std::string& newSharedLibName) {
+    android::elf64::Elf64Binary copyElf64Binary = elf64Binary;
+    std::vector<Elf64_Dyn> dynEntries;
+    bool found = false;
+
+    copyElf64Binary.AppendDynamicEntries(&dynEntries);
+    for (int i = 0; i < dynEntries.size(); i++) {
+        if (dynEntries[i].d_tag == DT_FLAGS) {
+            // Indicate that binary contains text relocations.
+            dynEntries[i].d_un.d_val |= DF_TEXTREL;
+            found = true;
+            break;
+        }
+    }
+
+    if (!found) {
+        std::cerr << "Unable to set text relocations in DT_FLAGS. File " << newSharedLibName
+                  << " not created." << std::endl;
+        return;
+    }
+
+    copyElf64Binary.SetDynamicEntries(&dynEntries);
+    android::elf64::Elf64Writer::WriteElf64File(copyElf64Binary, newSharedLibName);
+}
+
+// Generates a shared library with a DT_TEXTREL dynamic entry.
+// For example:
+//
+// $ readelf -d arm64/libtest_invalid-textrels2.so  | grep TEXTREL
+// 0x0000000000000016 (TEXTREL)            0x0
+void gen_lib_with_text_relocs_dyn_entry(const android::elf64::Elf64Binary& elf64Binary,
+                                        const std::string& newSharedLibName) {
+    android::elf64::Elf64Binary copyElf64Binary = elf64Binary;
+    std::vector<Elf64_Dyn> dynEntries;
+    bool found = false;
+
+    copyElf64Binary.AppendDynamicEntries(&dynEntries);
+    for (int i = 0; i < dynEntries.size(); i++) {
+        if (dynEntries[i].d_tag == DT_FLAGS) {
+            dynEntries[i].d_tag = DT_TEXTREL;
+            found = true;
+            break;
+        }
+    }
+
+    if (!found) {
+        std::cerr << "Unable to create shared library with DT_TEXTREL dynamic entry. File "
+                  << newSharedLibName << " not created." << std::endl;
+        return;
+    }
+
+    copyElf64Binary.SetDynamicEntries(&dynEntries);
+    android::elf64::Elf64Writer::WriteElf64File(copyElf64Binary, newSharedLibName);
+}
+
+void usage() {
+    const std::string progname = getprogname();
+
+    std::cout << "Usage: " << progname << " [shared_lib] [out_dir]...\n"
+              << R"(
+Options:
+shared_lib       shared library that will be used as reference.
+out_dir          the invalid shared libraries that are
+                 generated will be placed in this directory.)"
+              << std::endl;
+}
+
+// Generate shared libraries with invalid:
+//
+//   - executable header
+//   - segment headers
+//   - section headers
+int main(int argc, char* argv[]) {
+    if (argc < 3) {
+        usage();
+        return EXIT_FAILURE;
+    }
+
+    std::string baseSharedLibName(argv[1]);
+    std::string outputDir(argv[2]);
+
+    android::elf64::Elf64Binary elf64Binary;
+    if (android::elf64::Elf64Parser::ParseElfFile(baseSharedLibName, elf64Binary)) {
+        std::set<std::string> libsToRemove = {"libc++_shared.so"};
+        remove_needed_shared_libs(elf64Binary, libsToRemove);
+
+        gen_lib_with_rwx_segment(elf64Binary, outputDir + "/libtest_invalid-rw_load_segment.so");
+        gen_lib_with_zero_shentsize(elf64Binary, outputDir + "/libtest_invalid-zero_shentsize.so");
+        gen_lib_with_zero_shstrndx(elf64Binary, outputDir + "/libtest_invalid-zero_shstrndx.so");
+        gen_lib_with_text_relocs_in_flags(elf64Binary, outputDir + "/libtest_invalid-textrels.so");
+        gen_lib_with_text_relocs_dyn_entry(elf64Binary,
+                                           outputDir + "/libtest_invalid-textrels2.so");
+    }
+
+    return 0;
+}
diff --git a/libelf64/parse.cpp b/libelf64/parse.cpp
index f58457d..010d2e1 100644
--- a/libelf64/parse.cpp
+++ b/libelf64/parse.cpp
@@ -18,108 +18,96 @@
 #include <elf.h>
 
 #include <fstream>
-
-using namespace std;
+#include <iostream>
 
 namespace android {
 namespace elf64 {
 
-bool Elf64Parser::OpenElfFile(const std::string& fileName, std::ifstream& elfFile) {
-    elfFile.open(fileName.c_str(), std::ifstream::in);
-
-    return elfFile.is_open();
-}
+Elf64Parser::Elf64Parser(const std::string& fileName, Elf64Binary& elfBinary)
+    : elf64stream(fileName) {
+    if (!elf64stream) {
+        std::cerr << "Failed to open the file: " << fileName << std::endl;
+    }
 
-void Elf64Parser::CloseElfFile(std::ifstream& elfFile) {
-    if (!elfFile.is_open())
-        elfFile.close();
+    elfBinaryPtr = &elfBinary;
 }
 
 // Parse the executable header.
 //
 // Note: The command below can be used to print the executable header:
 //
-//  $ readelf -h ../a.out
-bool Elf64Parser::ParseExecutableHeader(std::ifstream& elfFile, Elf64Binary& elf64Binary) {
+//  $ readelf -h ../shared_lib.so
+bool Elf64Parser::ParseExecutableHeader() {
     // Move the cursor position to the very beginning.
-    elfFile.seekg(0);
-    elfFile.read((char*)&elf64Binary.ehdr, sizeof(elf64Binary.ehdr));
-
-    return elfFile.good();
-}
+    elf64stream.seekg(0);
+    elf64stream.read((char*)&elfBinaryPtr->ehdr, sizeof(elfBinaryPtr->ehdr));
 
-bool Elf64Parser::IsElf64(Elf64Binary& elf64Binary) {
-    return elf64Binary.ehdr.e_ident[EI_CLASS] == ELFCLASS64;
+    return elf64stream.good();
 }
 
 // Parse the Program or Segment Headers.
 //
 // Note: The command below can be used to print the program headers:
 //
-//  $ readelf --program-headers ./example_4k
-//  $ readelf -l ./example_4k
-bool Elf64Parser::ParseProgramHeaders(std::ifstream& elfFile, Elf64Binary& elf64Binary) {
-    uint64_t phOffset = elf64Binary.ehdr.e_phoff;
-    uint16_t phNum = elf64Binary.ehdr.e_phnum;
+//  $ readelf --program-headers ./shared_lib.so
+//  $ readelf -l ./shared_lib.so
+bool Elf64Parser::ParseProgramHeaders() {
+    uint64_t phOffset = elfBinaryPtr->ehdr.e_phoff;
+    uint16_t phNum = elfBinaryPtr->ehdr.e_phnum;
 
     // Move the cursor position to the program header offset.
-    elfFile.seekg(phOffset);
+    elf64stream.seekg(phOffset);
 
     for (int i = 0; i < phNum; i++) {
         Elf64_Phdr phdr;
 
-        elfFile.read((char*)&phdr, sizeof(phdr));
-        if (!elfFile.good())
-            return false;
+        elf64stream.read((char*)&phdr, sizeof(phdr));
+        if (!elf64stream) return false;
 
-        elf64Binary.phdrs.push_back(phdr);
+        elfBinaryPtr->phdrs.push_back(phdr);
     }
 
     return true;
 }
 
-bool Elf64Parser::ParseSections(std::ifstream& elfFile, Elf64Binary& elf64Binary) {
+bool Elf64Parser::ParseSections() {
     Elf64_Sc sStrTblPtr;
 
     // Parse sections after reading all the section headers.
-    for (int i = 0; i < elf64Binary.shdrs.size(); i++) {
-        Elf64_Shdr shdr = elf64Binary.shdrs[i];
-        uint64_t sOffset = shdr.sh_offset;
-        uint64_t sSize = shdr.sh_size;
+    for (int i = 0; i < elfBinaryPtr->shdrs.size(); i++) {
+        uint64_t sOffset = elfBinaryPtr->shdrs[i].sh_offset;
+        uint64_t sSize = elfBinaryPtr->shdrs[i].sh_size;
 
         Elf64_Sc section;
 
         // Skip .bss section.
-        if (shdr.sh_type != SHT_NOBITS) {
+        if (elfBinaryPtr->shdrs[i].sh_type != SHT_NOBITS) {
             section.data.resize(sSize);
 
             // Move the cursor position to the section offset.
-            elfFile.seekg(sOffset);
-            elfFile.read(section.data.data(), sSize);
-            if (!elfFile.good())
-                return false;
+            elf64stream.seekg(sOffset);
+            elf64stream.read(section.data.data(), sSize);
+            if (!elf64stream) return false;
         }
 
         section.size = sSize;
         section.index = i;
 
         // The index of the string table is in the executable header.
-        if (elf64Binary.ehdr.e_shstrndx == i) {
+        if (elfBinaryPtr->ehdr.e_shstrndx == i) {
             sStrTblPtr = section;
         }
 
-        elf64Binary.sections.push_back(section);
+        elfBinaryPtr->sections.push_back(section);
     }
 
     // Set the data section name.
     // This is done after reading the data section with index e_shstrndx.
-    for (int i = 0; i < elf64Binary.sections.size(); i++) {
-        Elf64_Sc section = elf64Binary.sections[i];
-        Elf64_Shdr shdr = elf64Binary.shdrs[i];
-        uint32_t nameIdx = shdr.sh_name;
+    for (int i = 0; i < elfBinaryPtr->sections.size(); i++) {
+        uint32_t nameIdx = elfBinaryPtr->shdrs[i].sh_name;
         char* st = sStrTblPtr.data.data();
 
-        section.name = &st[nameIdx];
+        elfBinaryPtr->sections[i].name = &st[nameIdx];
     }
 
     return true;
@@ -129,23 +117,22 @@ bool Elf64Parser::ParseSections(std::ifstream& elfFile, Elf64Binary& elf64Binary
 //
 // Note: The command below can be used to print the section headers:
 //
-//   $ readelf --sections ./example_4k
-//   $ readelf -S ./example_4k
-bool Elf64Parser::ParseSectionHeaders(std::ifstream& elfFile, Elf64Binary& elf64Binary) {
-    uint64_t shOffset = elf64Binary.ehdr.e_shoff;
-    uint16_t shNum = elf64Binary.ehdr.e_shnum;
+//   $ readelf --sections ./shared_lib.so
+//   $ readelf -S ./shared_lib.so
+bool Elf64Parser::ParseSectionHeaders() {
+    uint64_t shOffset = elfBinaryPtr->ehdr.e_shoff;
+    uint16_t shNum = elfBinaryPtr->ehdr.e_shnum;
 
     // Move the cursor position to the section headers offset.
-    elfFile.seekg(shOffset);
+    elf64stream.seekg(shOffset);
 
     for (int i = 0; i < shNum; i++) {
         Elf64_Shdr shdr;
 
-        elfFile.read((char*)&shdr, sizeof(shdr));
-        if (!elfFile.good())
-            return false;
+        elf64stream.read((char*)&shdr, sizeof(shdr));
+        if (!elf64stream) return false;
 
-        elf64Binary.shdrs.push_back(shdr);
+        elfBinaryPtr->shdrs.push_back(shdr);
     }
 
     return true;
@@ -153,22 +140,26 @@ bool Elf64Parser::ParseSectionHeaders(std::ifstream& elfFile, Elf64Binary& elf64
 
 // Parse the elf file and populate the elfBinary object.
 bool Elf64Parser::ParseElfFile(const std::string& fileName, Elf64Binary& elf64Binary) {
-    std::ifstream elfFile;
-    bool ret = false;
-
-    if (OpenElfFile(fileName, elfFile) &&
-        ParseExecutableHeader(elfFile, elf64Binary) &&
-        IsElf64(elf64Binary) &&
-        ParseProgramHeaders(elfFile, elf64Binary) &&
-        ParseSectionHeaders(elfFile, elf64Binary) &&
-        ParseSections(elfFile, elf64Binary)) {
+    Elf64Parser elf64Parser(fileName, elf64Binary);
+    if (elf64Parser.elf64stream && elf64Parser.ParseExecutableHeader() && elf64Binary.IsElf64() &&
+        elf64Parser.ParseProgramHeaders() && elf64Parser.ParseSectionHeaders() &&
+        elf64Parser.ParseSections()) {
         elf64Binary.path = fileName;
-        ret = true;
+        return true;
     }
 
-    CloseElfFile(elfFile);
+    return false;
+}
+
+bool Elf64Parser::IsElf64(const std::string& fileName) {
+    Elf64Binary elf64Binary;
+
+    Elf64Parser elf64Parser(fileName, elf64Binary);
+    if (elf64Parser.elf64stream && elf64Parser.ParseExecutableHeader() && elf64Binary.IsElf64()) {
+        return true;
+    }
 
-    return ret;
+    return false;
 }
 
 }  // namespace elf64
diff --git a/libelf64/tests/page_size_16kb/elf_alignment_test.cpp b/libelf64/tests/page_size_16kb/elf_alignment_test.cpp
index 92143b6..dae2f2e 100644
--- a/libelf64/tests/page_size_16kb/elf_alignment_test.cpp
+++ b/libelf64/tests/page_size_16kb/elf_alignment_test.cpp
@@ -65,6 +65,9 @@ class ElfAlignmentTest :public ::testing::TestWithParam<std::string> {
         // Ignore VNDK APEXes. They are prebuilts from old branches, and would
         // only be used on devices with old vendor images.
         "/apex/com.android.vndk.v",
+        // This directory contains the trusty kernel.
+        // TODO(b/365240530): Remove this once 16K pages will work on the trusty kernel.
+        "/system_ext/etc/hw/",
         // Ignore non-Android firmware images.
         "/odm/firmware",
         "/vendor/firmware",
@@ -100,11 +103,11 @@ class ElfAlignmentTest :public ::testing::TestWithParam<std::string> {
     }
 
     void SetUp() override {
-      if (VendorApiLevel() < __ANDROID_API_V__) {
-        GTEST_SKIP() << "16kB support is only required on V and later releases.";
-      } else if (IsLowRamDevice()) {
-        GTEST_SKIP() << "Low Ram devices only support 4kB page size";
-      }
+        if (VendorApiLevel() < 202404) {
+            GTEST_SKIP() << "16kB support is only required on V and later releases.";
+        } else if (IsLowRamDevice()) {
+            GTEST_SKIP() << "Low Ram devices only support 4kB page size";
+        }
     }
 };
 
diff --git a/libmemevents/bpfprogs/Android.bp b/libmemevents/bpfprogs/Android.bp
index b2afff7..68c6a14 100644
--- a/libmemevents/bpfprogs/Android.bp
+++ b/libmemevents/bpfprogs/Android.bp
@@ -17,10 +17,7 @@ bpf {
     include_dirs: [
         "system/memory/libmeminfo/libmemevents/include",
     ],
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
+    sub_dir: "memevents",
 }
 
 bpf {
@@ -29,8 +26,5 @@ bpf {
     include_dirs: [
         "system/memory/libmeminfo/libmemevents/include",
     ],
-    cflags: [
-        "-Wall",
-        "-Werror",
-    ],
+    sub_dir: "memevents",
 }
diff --git a/libmemevents/bpfprogs/bpfMemEvents.c b/libmemevents/bpfprogs/bpfMemEvents.c
index 95c4564..540dfd6 100644
--- a/libmemevents/bpfprogs/bpfMemEvents.c
+++ b/libmemevents/bpfprogs/bpfMemEvents.c
@@ -21,15 +21,11 @@
 #include <memevents/bpf_helpers.h>
 #include <memevents/bpf_types.h>
 
-DEFINE_BPF_RINGBUF_EXT(ams_rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID,
-                       AID_SYSTEM, 0660, DEFAULT_BPF_MAP_SELINUX_CONTEXT,
-                       DEFAULT_BPF_MAP_PIN_SUBDIR, PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER,
-                       LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG)
+DEFINE_BPF_RINGBUF(ams_rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID,
+                   AID_SYSTEM, 0660)
 
-DEFINE_BPF_RINGBUF_EXT(lmkd_rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID,
-                       AID_SYSTEM, 0660, DEFAULT_BPF_MAP_SELINUX_CONTEXT,
-                       DEFAULT_BPF_MAP_PIN_SUBDIR, PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER,
-                       LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG)
+DEFINE_BPF_RINGBUF(lmkd_rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID,
+                   AID_SYSTEM, 0660)
 
 DEFINE_BPF_PROG("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM, tp_ams)
 (struct mark_victim_args* args) {
@@ -58,7 +54,7 @@ DEFINE_BPF_PROG("tracepoint/oom/mark_victim/ams", AID_ROOT, AID_SYSTEM, tp_ams)
 
 DEFINE_BPF_PROG("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin/lmkd", AID_ROOT, AID_SYSTEM,
                 tp_lmkd_dr_start)
-(struct direct_reclaim_begin_args* args) {
+(struct direct_reclaim_begin_args* __unused args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
 
@@ -71,7 +67,7 @@ DEFINE_BPF_PROG("tracepoint/vmscan/mm_vmscan_direct_reclaim_begin/lmkd", AID_ROO
 
 DEFINE_BPF_PROG("tracepoint/vmscan/mm_vmscan_direct_reclaim_end/lmkd", AID_ROOT, AID_SYSTEM,
                 tp_lmkd_dr_end)
-(struct direct_reclaim_end_args* args) {
+(struct direct_reclaim_end_args* __unused args) {
     struct mem_event_t* data = bpf_lmkd_rb_reserve();
     if (data == NULL) return 1;
 
diff --git a/libmemevents/bpfprogs/bpfMemEventsTest.c b/libmemevents/bpfprogs/bpfMemEventsTest.c
index b15ab2a..0cb4033 100644
--- a/libmemevents/bpfprogs/bpfMemEventsTest.c
+++ b/libmemevents/bpfprogs/bpfMemEventsTest.c
@@ -22,10 +22,8 @@
 #include <memevents/bpf_types.h>
 #include <memevents/memevents_test.h>
 
-DEFINE_BPF_RINGBUF_EXT(rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID,
-                       AID_SYSTEM, 0660, DEFAULT_BPF_MAP_SELINUX_CONTEXT,
-                       DEFAULT_BPF_MAP_PIN_SUBDIR, PRIVATE, BPFLOADER_MIN_VER, BPFLOADER_MAX_VER,
-                       LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG)
+DEFINE_BPF_RINGBUF(rb, struct mem_event_t, MEM_EVENTS_RINGBUF_SIZE, DEFAULT_BPF_MAP_UID, AID_SYSTEM,
+                   0660)
 
 DEFINE_BPF_PROG("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tp_ams)
 (struct mark_victim_args* args) {
@@ -59,7 +57,7 @@ DEFINE_BPF_PROG("tracepoint/oom/mark_victim", AID_ROOT, AID_SYSTEM, tp_ams)
  * currently implement this BPF_PROG_RUN operation.
  */
 DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, tp_memevents_test_oom, KVER(5, 8, 0))
-(void* unused_ctx) {
+(void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
 
@@ -84,7 +82,7 @@ DEFINE_BPF_PROG_KVER("skfilter/oom_kill", AID_ROOT, AID_ROOT, tp_memevents_test_
 
 DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_begin", AID_ROOT, AID_ROOT,
                      tp_memevents_test_dr_begin, KVER(5, 8, 0))
-(void* unused_ctx) {
+(void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
 
@@ -97,7 +95,7 @@ DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_begin", AID_ROOT, AID_ROOT,
 
 DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_end", AID_ROOT, AID_ROOT, tp_memevents_test_dr_end,
                      KVER(5, 8, 0))
-(void* unused_ctx) {
+(void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
 
@@ -110,7 +108,7 @@ DEFINE_BPF_PROG_KVER("skfilter/direct_reclaim_end", AID_ROOT, AID_ROOT, tp_memev
 
 DEFINE_BPF_PROG_KVER("skfilter/kswapd_wake", AID_ROOT, AID_ROOT, tp_memevents_test_kswapd_wake,
                      KVER(5, 8, 0))
-(void* unused_ctx) {
+(void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
 
@@ -127,7 +125,7 @@ DEFINE_BPF_PROG_KVER("skfilter/kswapd_wake", AID_ROOT, AID_ROOT, tp_memevents_te
 
 DEFINE_BPF_PROG_KVER("skfilter/kswapd_sleep", AID_ROOT, AID_ROOT, tp_memevents_test_kswapd_sleep,
                      KVER(5, 8, 0))
-(void* unused_ctx) {
+(void* __unused ctx) {
     struct mem_event_t* data = bpf_rb_reserve();
     if (data == NULL) return 1;
 
diff --git a/libmemevents/include/memevents/bpf_types.h b/libmemevents/include/memevents/bpf_types.h
index 42e2ff3..004b15c 100644
--- a/libmemevents/include/memevents/bpf_types.h
+++ b/libmemevents/include/memevents/bpf_types.h
@@ -35,23 +35,24 @@ typedef unsigned int mem_event_type_t;
 #define NR_MEM_EVENTS 5
 
 /* BPF-Rb Paths */
-#define MEM_EVENTS_AMS_RB "/sys/fs/bpf/map_bpfMemEvents_ams_rb"
-#define MEM_EVENTS_LMKD_RB "/sys/fs/bpf/map_bpfMemEvents_lmkd_rb"
-#define MEM_EVENTS_TEST_RB "/sys/fs/bpf/map_bpfMemEventsTest_rb"
+#define MEM_EVENTS_AMS_RB "/sys/fs/bpf/memevents/map_bpfMemEvents_ams_rb"
+#define MEM_EVENTS_LMKD_RB "/sys/fs/bpf/memevents/map_bpfMemEvents_lmkd_rb"
+#define MEM_EVENTS_TEST_RB "/sys/fs/bpf/memevents/map_bpfMemEventsTest_rb"
 
 /* BPF-Prog Paths */
 #define MEM_EVENTS_AMS_OOM_MARK_VICTIM_TP \
-    "/sys/fs/bpf/prog_bpfMemEvents_tracepoint_oom_mark_victim_ams"
+    "/sys/fs/bpf/memevents/prog_bpfMemEvents_tracepoint_oom_mark_victim_ams"
 #define MEM_EVENTS_LMKD_VMSCAN_DR_BEGIN_TP \
-    "/sys/fs/bpf/prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_direct_reclaim_begin_lmkd"
+    "/sys/fs/bpf/memevents/"               \
+    "prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_direct_reclaim_begin_lmkd"
 #define MEM_EVENTS_LMKD_VMSCAN_DR_END_TP \
-    "/sys/fs/bpf/prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_direct_reclaim_end_lmkd"
+    "/sys/fs/bpf/memevents/prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_direct_reclaim_end_lmkd"
 #define MEM_EVENTS_LMKD_VMSCAN_KSWAPD_WAKE_TP \
-    "/sys/fs/bpf/prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_kswapd_wake_lmkd"
+    "/sys/fs/bpf/memevents/prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_kswapd_wake_lmkd"
 #define MEM_EVENTS_LMKD_VMSCAN_KSWAPD_SLEEP_TP \
-    "/sys/fs/bpf/prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_kswapd_sleep_lmkd"
+    "/sys/fs/bpf/memevents/prog_bpfMemEvents_tracepoint_vmscan_mm_vmscan_kswapd_sleep_lmkd"
 #define MEM_EVENTS_TEST_OOM_MARK_VICTIM_TP \
-    "/sys/fs/bpf/prog_bpfMemEventsTest_tracepoint_oom_mark_victim"
+    "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_tracepoint_oom_mark_victim"
 
 /* Struct to collect data from tracepoints */
 struct mem_event_t {
diff --git a/libmemevents/include/memevents/memevents_test.h b/libmemevents/include/memevents/memevents_test.h
index b646962..de6660b 100644
--- a/libmemevents/include/memevents/memevents_test.h
+++ b/libmemevents/include/memevents/memevents_test.h
@@ -22,13 +22,15 @@
 #include <memevents/bpf_types.h>
 
 /* BPF-Prog Paths */
-#define MEM_EVENTS_TEST_OOM_KILL_TP "/sys/fs/bpf/prog_bpfMemEventsTest_skfilter_oom_kill"
+#define MEM_EVENTS_TEST_OOM_KILL_TP "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_skfilter_oom_kill"
 #define MEM_EVENTS_TEST_DIRECT_RECLAIM_START_TP \
-    "/sys/fs/bpf/prog_bpfMemEventsTest_skfilter_direct_reclaim_begin"
+    "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_skfilter_direct_reclaim_begin"
 #define MEM_EVENTS_TEST_DIRECT_RECLAIM_END_TP \
-    "/sys/fs/bpf/prog_bpfMemEventsTest_skfilter_direct_reclaim_end"
-#define MEM_EVENTS_TEST_KSWAPD_WAKE_TP "/sys/fs/bpf/prog_bpfMemEventsTest_skfilter_kswapd_wake"
-#define MEM_EVENTS_TEST_KSWAPD_SLEEP_TP "/sys/fs/bpf/prog_bpfMemEventsTest_skfilter_kswapd_sleep"
+    "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_skfilter_direct_reclaim_end"
+#define MEM_EVENTS_TEST_KSWAPD_WAKE_TP \
+    "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_skfilter_kswapd_wake"
+#define MEM_EVENTS_TEST_KSWAPD_SLEEP_TP \
+    "/sys/fs/bpf/memevents/prog_bpfMemEventsTest_skfilter_kswapd_sleep"
 
 // clang-format off
 const struct mem_event_t mocked_oom_event = {
diff --git a/libmemevents/memevents.cpp b/libmemevents/memevents.cpp
index 889a8e2..ca29263 100644
--- a/libmemevents/memevents.cpp
+++ b/libmemevents/memevents.cpp
@@ -341,7 +341,8 @@ bool MemEventListener::getMemEvents(std::vector<mem_event_t>& mem_events) {
     }
 
     base::Result<int> ret = memBpfRb->ConsumeAll([&](const mem_event_t& mem_event) {
-        if (mEventsRegistered[mem_event.type]) mem_events.emplace_back(mem_event);
+        if (isValidEventType(mem_event.type) && mEventsRegistered[mem_event.type])
+            mem_events.emplace_back(mem_event);
     });
 
     if (!ret.ok()) {
diff --git a/libmemevents/memevents_test.cpp b/libmemevents/memevents_test.cpp
index 5df00c4..82aac86 100644
--- a/libmemevents/memevents_test.cpp
+++ b/libmemevents/memevents_test.cpp
@@ -54,6 +54,28 @@ static const std::string testBpfSkfilterProgPaths[NR_MEM_EVENTS] = {
         MEM_EVENTS_TEST_KSWAPD_SLEEP_TP};
 static const std::filesystem::path sysrq_trigger_path = "proc/sysrq-trigger";
 
+static void initializeTestListener(std::unique_ptr<MemEventListener>& memevent_listener,
+                                   const bool attachTpForTests) {
+    if (!memevent_listener) {
+        memevent_listener = std::make_unique<MemEventListener>(mem_test_client, attachTpForTests);
+    }
+    ASSERT_TRUE(memevent_listener) << "Memory event listener is not initialized";
+
+    /*
+     * Some test suite seems to have issues when trying to re-initialize
+     * the BPF manager for the MemEventsTest, therefore we retry.
+     */
+    if (!memevent_listener->ok()) {
+        memevent_listener.reset();
+        /* This sleep is needed in order to allow for the BPF manager to
+         * initialize without failure.
+         */
+        sleep(1);
+        memevent_listener = std::make_unique<MemEventListener>(mem_test_client);
+    }
+    ASSERT_TRUE(memevent_listener->ok()) << "BPF ring buffer manager didn't initialize";
+}
+
 /*
  * Test suite to test on devices that don't support BPF, kernel <= 5.8.
  * We allow for the listener to iniailize gracefully, but every public API will
@@ -61,7 +83,7 @@ static const std::filesystem::path sysrq_trigger_path = "proc/sysrq-trigger";
  */
 class MemEventListenerUnsupportedKernel : public ::testing::Test {
   protected:
-    MemEventListener memevent_listener = MemEventListener(mem_test_client);
+    std::unique_ptr<MemEventListener> memevent_listener;
 
     static void SetUpTestSuite() {
         if (isBpfRingBufferSupported) {
@@ -70,11 +92,9 @@ class MemEventListenerUnsupportedKernel : public ::testing::Test {
         }
     }
 
-    void SetUp() override {
-        ASSERT_FALSE(memevent_listener.ok()) << "BPF ring buffer manager shouldn't initialize";
-    }
+    void SetUp() override { initializeTestListener(memevent_listener, false); }
 
-    void TearDown() override { memevent_listener.deregisterAllEvents(); }
+    void TearDown() override { memevent_listener.reset(); }
 };
 
 /*
@@ -90,9 +110,9 @@ TEST_F(MemEventListenerUnsupportedKernel, initialize_invalid_client) {
  * Register will fail when running on a older kernel, even when we pass a valid event type.
  */
 TEST_F(MemEventListenerUnsupportedKernel, fail_to_register) {
-    ASSERT_FALSE(memevent_listener.registerEvent(MEM_EVENT_OOM_KILL))
+    ASSERT_FALSE(memevent_listener->registerEvent(MEM_EVENT_OOM_KILL))
             << "Listener should fail to register valid event type on an unsupported kernel";
-    ASSERT_FALSE(memevent_listener.registerEvent(NR_MEM_EVENTS))
+    ASSERT_FALSE(memevent_listener->registerEvent(NR_MEM_EVENTS))
             << "Listener should fail to register invalid event type";
 }
 
@@ -102,7 +122,7 @@ TEST_F(MemEventListenerUnsupportedKernel, fail_to_register) {
  * therefore we don't need to register for an event before trying to call listen.
  */
 TEST_F(MemEventListenerUnsupportedKernel, fail_to_listen) {
-    ASSERT_FALSE(memevent_listener.listen()) << "listen() should fail on unsupported kernel";
+    ASSERT_FALSE(memevent_listener->listen()) << "listen() should fail on unsupported kernel";
 }
 
 /*
@@ -110,9 +130,9 @@ TEST_F(MemEventListenerUnsupportedKernel, fail_to_listen) {
  * kernel.
  */
 TEST_F(MemEventListenerUnsupportedKernel, fail_to_unregister_event) {
-    ASSERT_FALSE(memevent_listener.deregisterEvent(MEM_EVENT_OOM_KILL))
+    ASSERT_FALSE(memevent_listener->deregisterEvent(MEM_EVENT_OOM_KILL))
             << "Listener should fail to deregister valid event type on an older kernel";
-    ASSERT_FALSE(memevent_listener.deregisterEvent(NR_MEM_EVENTS))
+    ASSERT_FALSE(memevent_listener->deregisterEvent(NR_MEM_EVENTS))
             << "Listener should fail to deregister invalid event type, regardless of kernel "
                "version";
 }
@@ -122,7 +142,7 @@ TEST_F(MemEventListenerUnsupportedKernel, fail_to_unregister_event) {
  */
 TEST_F(MemEventListenerUnsupportedKernel, fail_to_get_mem_events) {
     std::vector<mem_event_t> mem_events;
-    ASSERT_FALSE(memevent_listener.getMemEvents(mem_events))
+    ASSERT_FALSE(memevent_listener->getMemEvents(mem_events))
             << "Fetching memory events should fail on an older kernel";
 }
 
@@ -130,7 +150,7 @@ TEST_F(MemEventListenerUnsupportedKernel, fail_to_get_mem_events) {
  * The `getRingBufferFd()` API should fail on an older kernel
  */
 TEST_F(MemEventListenerUnsupportedKernel, fail_to_get_rb_fd) {
-    ASSERT_LT(memevent_listener.getRingBufferFd(), 0)
+    ASSERT_LT(memevent_listener->getRingBufferFd(), 0)
             << "Fetching bpf-rb file descriptor should fail on an older kernel";
 }
 
@@ -191,7 +211,7 @@ TEST_F(MemEventsBpfSetupTest, loaded_ring_buffers) {
 
 class MemEventsListenerTest : public ::testing::Test {
   protected:
-    MemEventListener memevent_listener = MemEventListener(mem_test_client);
+    std::unique_ptr<MemEventListener> memevent_listener;
 
     static void SetUpTestSuite() {
         if (!isBpfRingBufferSupported) {
@@ -199,12 +219,9 @@ class MemEventsListenerTest : public ::testing::Test {
         }
     }
 
-    void SetUp() override {
-        ASSERT_TRUE(memevent_listener.ok())
-                << "Memory listener failed to initialize bpf ring buffer manager";
-    }
+    void SetUp() override { initializeTestListener(memevent_listener, false); }
 
-    void TearDown() override { memevent_listener.deregisterAllEvents(); }
+    void TearDown() override { memevent_listener.reset(); }
 };
 
 /*
@@ -229,21 +246,6 @@ TEST_F(MemEventsListenerTest, initialize_valid_client_with_test_flag) {
     }
 }
 
-/*
- * MemEventListener should NOT fail when initializing for all valid `MemEventClient`.
- * We considered a `MemEventClient` valid if its between 0 and MemEventClient::NR_CLIENTS.
- */
-TEST_F(MemEventsListenerTest, initialize_valid_clients) {
-    std::unique_ptr<MemEventListener> listener;
-    for (int i = 0; i < MemEventClient::NR_CLIENTS; i++) {
-        const MemEventClient client = static_cast<MemEventClient>(i);
-        listener = std::make_unique<MemEventListener>(client);
-        ASSERT_TRUE(listener) << "MemEventListener failed to initialize with valid client value: "
-                              << client;
-        ASSERT_TRUE(listener->ok()) << "MemEventListener failed to initialize with bpf rb manager";
-    }
-}
-
 /*
  * MemEventClient base client should equal to AMS client.
  */
@@ -256,9 +258,9 @@ TEST_F(MemEventsListenerTest, base_client_equal_ams_client) {
  * Validate `registerEvent()` fails with values >= `NR_MEM_EVENTS`.
  */
 TEST_F(MemEventsListenerTest, register_event_invalid_values) {
-    ASSERT_FALSE(memevent_listener.registerEvent(NR_MEM_EVENTS));
-    ASSERT_FALSE(memevent_listener.registerEvent(NR_MEM_EVENTS + 1));
-    ASSERT_FALSE(memevent_listener.registerEvent(-1));
+    ASSERT_FALSE(memevent_listener->registerEvent(NR_MEM_EVENTS));
+    ASSERT_FALSE(memevent_listener->registerEvent(NR_MEM_EVENTS + 1));
+    ASSERT_FALSE(memevent_listener->registerEvent(-1));
 }
 
 /*
@@ -267,9 +269,9 @@ TEST_F(MemEventsListenerTest, register_event_invalid_values) {
  */
 TEST_F(MemEventsListenerTest, register_event_repeated_event) {
     const int event_type = MEM_EVENT_OOM_KILL;
-    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
-    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
-    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
 }
 
 /*
@@ -278,14 +280,14 @@ TEST_F(MemEventsListenerTest, register_event_repeated_event) {
  */
 TEST_F(MemEventsListenerTest, register_event_valid_values) {
     for (unsigned int i = 0; i < NR_MEM_EVENTS; i++)
-        ASSERT_TRUE(memevent_listener.registerEvent(i)) << "Failed to register event: " << i;
+        ASSERT_TRUE(memevent_listener->registerEvent(i)) << "Failed to register event: " << i;
 }
 
 /*
  * `listen()` should return false when no events have been registered.
  */
 TEST_F(MemEventsListenerTest, listen_no_registered_events) {
-    ASSERT_FALSE(memevent_listener.listen());
+    ASSERT_FALSE(memevent_listener->listen());
 }
 
 /*
@@ -293,9 +295,9 @@ TEST_F(MemEventsListenerTest, listen_no_registered_events) {
  * Exactly like `register_event_invalid_values` test.
  */
 TEST_F(MemEventsListenerTest, deregister_event_invalid_values) {
-    ASSERT_FALSE(memevent_listener.deregisterEvent(NR_MEM_EVENTS));
-    ASSERT_FALSE(memevent_listener.deregisterEvent(NR_MEM_EVENTS + 1));
-    ASSERT_FALSE(memevent_listener.deregisterEvent(-1));
+    ASSERT_FALSE(memevent_listener->deregisterEvent(NR_MEM_EVENTS));
+    ASSERT_FALSE(memevent_listener->deregisterEvent(NR_MEM_EVENTS + 1));
+    ASSERT_FALSE(memevent_listener->deregisterEvent(-1));
 }
 
 /*
@@ -304,9 +306,9 @@ TEST_F(MemEventsListenerTest, deregister_event_invalid_values) {
  */
 TEST_F(MemEventsListenerTest, deregister_repeated_event) {
     const int event_type = MEM_EVENT_DIRECT_RECLAIM_BEGIN;
-    ASSERT_TRUE(memevent_listener.registerEvent(event_type));
-    ASSERT_TRUE(memevent_listener.deregisterEvent(event_type));
-    ASSERT_TRUE(memevent_listener.deregisterEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->deregisterEvent(event_type));
+    ASSERT_TRUE(memevent_listener->deregisterEvent(event_type));
 }
 
 /*
@@ -314,7 +316,7 @@ TEST_F(MemEventsListenerTest, deregister_repeated_event) {
  * when we deregister a non-registered, valid, event.
  */
 TEST_F(MemEventsListenerTest, deregister_unregistered_event) {
-    ASSERT_TRUE(memevent_listener.deregisterEvent(MEM_EVENT_DIRECT_RECLAIM_END));
+    ASSERT_TRUE(memevent_listener->deregisterEvent(MEM_EVENT_DIRECT_RECLAIM_END));
 }
 
 /*
@@ -322,10 +324,10 @@ TEST_F(MemEventsListenerTest, deregister_unregistered_event) {
  * events.
  */
 TEST_F(MemEventsListenerTest, deregister_all_events) {
-    ASSERT_TRUE(memevent_listener.registerEvent(MEM_EVENT_OOM_KILL));
-    ASSERT_TRUE(memevent_listener.registerEvent(MEM_EVENT_DIRECT_RECLAIM_BEGIN));
-    memevent_listener.deregisterAllEvents();
-    ASSERT_FALSE(memevent_listener.listen())
+    ASSERT_TRUE(memevent_listener->registerEvent(MEM_EVENT_OOM_KILL));
+    ASSERT_TRUE(memevent_listener->registerEvent(MEM_EVENT_DIRECT_RECLAIM_BEGIN));
+    memevent_listener->deregisterAllEvents();
+    ASSERT_FALSE(memevent_listener->listen())
             << "Expected to fail since we are not registered to any events";
 }
 
@@ -341,7 +343,7 @@ TEST_F(MemEventsListenerTest, base_and_oom_events_are_equal) {
  * Validate that `getRingBufferFd()` returns a valid file descriptor.
  */
 TEST_F(MemEventsListenerTest, get_client_rb_fd) {
-    ASSERT_GE(memevent_listener.getRingBufferFd(), 0)
+    ASSERT_GE(memevent_listener->getRingBufferFd(), 0)
             << "Failed to get a valid bpf-rb file descriptor";
 }
 
@@ -398,7 +400,7 @@ class MemEventsListenerBpf : public ::testing::Test {
     }
 
   protected:
-    MemEventListener mem_listener = MemEventListener(mem_test_client);
+    std::unique_ptr<MemEventListener> memevent_listener;
 
     static void SetUpTestSuite() {
         if (!isAtLeastKernelVersion(5, 8, 0)) {
@@ -406,11 +408,9 @@ class MemEventsListenerBpf : public ::testing::Test {
         }
     }
 
-    void SetUp() override {
-        ASSERT_TRUE(mem_listener.ok()) << "Listener failed to initialize bpf rb manager";
-    }
+    void SetUp() override { initializeTestListener(memevent_listener, false); }
 
-    void TearDown() override { mem_listener.deregisterAllEvents(); }
+    void TearDown() override { memevent_listener.reset(); }
 
     /*
      * Helper function to insert mocked data into the testing [bpf] ring buffer.
@@ -431,7 +431,7 @@ class MemEventsListenerBpf : public ::testing::Test {
 
         setMockDataInRb(event_type);
 
-        ASSERT_TRUE(mem_listener.listen(5000));  // 5 second timeout
+        ASSERT_TRUE(memevent_listener->listen(5000));  // 5 second timeout
     }
 
     void validateMockedEvent(const mem_event_t& mem_event) {
@@ -506,11 +506,11 @@ class MemEventsListenerBpf : public ::testing::Test {
 TEST_F(MemEventsListenerBpf, listener_bpf_oom_kill) {
     const mem_event_type_t event_type = MEM_EVENT_OOM_KILL;
 
-    ASSERT_TRUE(mem_listener.registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
     testListenEvent(event_type);
 
     std::vector<mem_event_t> mem_events;
-    ASSERT_TRUE(mem_listener.getMemEvents(mem_events)) << "Failed fetching events";
+    ASSERT_TRUE(memevent_listener->getMemEvents(mem_events)) << "Failed fetching events";
     ASSERT_FALSE(mem_events.empty()) << "Expected for mem_events to have at least 1 mocked event";
     ASSERT_EQ(mem_events[0].type, event_type) << "Didn't receive a OOM event";
     validateMockedEvent(mem_events[0]);
@@ -523,11 +523,11 @@ TEST_F(MemEventsListenerBpf, listener_bpf_oom_kill) {
 TEST_F(MemEventsListenerBpf, listener_bpf_direct_reclaim_begin) {
     const mem_event_type_t event_type = MEM_EVENT_DIRECT_RECLAIM_BEGIN;
 
-    ASSERT_TRUE(mem_listener.registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
     testListenEvent(event_type);
 
     std::vector<mem_event_t> mem_events;
-    ASSERT_TRUE(mem_listener.getMemEvents(mem_events)) << "Failed fetching events";
+    ASSERT_TRUE(memevent_listener->getMemEvents(mem_events)) << "Failed fetching events";
     ASSERT_FALSE(mem_events.empty()) << "Expected for mem_events to have at least 1 mocked event";
     ASSERT_EQ(mem_events[0].type, event_type) << "Didn't receive a direct reclaim begin event";
     validateMockedEvent(mem_events[0]);
@@ -540,11 +540,11 @@ TEST_F(MemEventsListenerBpf, listener_bpf_direct_reclaim_begin) {
 TEST_F(MemEventsListenerBpf, listener_bpf_direct_reclaim_end) {
     const mem_event_type_t event_type = MEM_EVENT_DIRECT_RECLAIM_END;
 
-    ASSERT_TRUE(mem_listener.registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
     testListenEvent(event_type);
 
     std::vector<mem_event_t> mem_events;
-    ASSERT_TRUE(mem_listener.getMemEvents(mem_events)) << "Failed fetching events";
+    ASSERT_TRUE(memevent_listener->getMemEvents(mem_events)) << "Failed fetching events";
     ASSERT_FALSE(mem_events.empty()) << "Expected for mem_events to have at least 1 mocked event";
     ASSERT_EQ(mem_events[0].type, event_type) << "Didn't receive a direct reclaim end event";
     validateMockedEvent(mem_events[0]);
@@ -553,11 +553,11 @@ TEST_F(MemEventsListenerBpf, listener_bpf_direct_reclaim_end) {
 TEST_F(MemEventsListenerBpf, listener_bpf_kswapd_wake) {
     const mem_event_type_t event_type = MEM_EVENT_KSWAPD_WAKE;
 
-    ASSERT_TRUE(mem_listener.registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
     testListenEvent(event_type);
 
     std::vector<mem_event_t> mem_events;
-    ASSERT_TRUE(mem_listener.getMemEvents(mem_events)) << "Failed fetching events";
+    ASSERT_TRUE(memevent_listener->getMemEvents(mem_events)) << "Failed fetching events";
     ASSERT_FALSE(mem_events.empty()) << "Expected for mem_events to have at least 1 mocked event";
     ASSERT_EQ(mem_events[0].type, event_type) << "Didn't receive a kswapd wake event";
     validateMockedEvent(mem_events[0]);
@@ -566,11 +566,11 @@ TEST_F(MemEventsListenerBpf, listener_bpf_kswapd_wake) {
 TEST_F(MemEventsListenerBpf, listener_bpf_kswapd_sleep) {
     const mem_event_type_t event_type = MEM_EVENT_KSWAPD_SLEEP;
 
-    ASSERT_TRUE(mem_listener.registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
     testListenEvent(event_type);
 
     std::vector<mem_event_t> mem_events;
-    ASSERT_TRUE(mem_listener.getMemEvents(mem_events)) << "Failed fetching events";
+    ASSERT_TRUE(memevent_listener->getMemEvents(mem_events)) << "Failed fetching events";
     ASSERT_FALSE(mem_events.empty()) << "Expected for mem_events to have at least 1 mocked event";
     ASSERT_EQ(mem_events[0].type, event_type) << "Didn't receive a kswapd sleep event";
     validateMockedEvent(mem_events[0]);
@@ -583,7 +583,7 @@ TEST_F(MemEventsListenerBpf, listener_bpf_kswapd_sleep) {
 TEST_F(MemEventsListenerBpf, no_register_events_listen_fails) {
     const mem_event_type_t event_type = MEM_EVENT_DIRECT_RECLAIM_END;
     setMockDataInRb(event_type);
-    ASSERT_FALSE(mem_listener.listen(5000));  // 5 second timeout
+    ASSERT_FALSE(memevent_listener->listen(5000));  // 5 second timeout
 }
 
 /*
@@ -595,7 +595,7 @@ TEST_F(MemEventsListenerBpf, getMemEvents_no_register_events) {
     setMockDataInRb(event_type);
 
     std::vector<mem_event_t> mem_events;
-    ASSERT_TRUE(mem_listener.getMemEvents(mem_events)) << "Failed fetching events";
+    ASSERT_TRUE(memevent_listener->getMemEvents(mem_events)) << "Failed fetching events";
     ASSERT_TRUE(mem_events.empty());
 }
 
@@ -611,10 +611,10 @@ TEST_F(MemEventsListenerBpf, listen_then_create_event) {
     std::condition_variable cv;
     bool didReceiveEvent = false;
 
-    ASSERT_TRUE(mem_listener.registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
 
     std::thread t([&] {
-        bool listen_result = mem_listener.listen(10000);
+        bool listen_result = memevent_listener->listen(10000);
         std::lock_guard lk(mtx);
         didReceiveEvent = listen_result;
         cv.notify_one();
@@ -638,9 +638,9 @@ TEST_F(MemEventsListenerBpf, getRb_poll_and_create_event) {
     std::condition_variable cv;
     bool didReceiveEvent = false;
 
-    ASSERT_TRUE(mem_listener.registerEvent(event_type));
+    ASSERT_TRUE(memevent_listener->registerEvent(event_type));
 
-    int rb_fd = mem_listener.getRingBufferFd();
+    int rb_fd = memevent_listener->getRingBufferFd();
     ASSERT_GE(rb_fd, 0) << "Received invalid file descriptor";
 
     std::thread t([&] {
@@ -676,13 +676,11 @@ class MemoryPressureTest : public ::testing::Test {
     }
 
   protected:
-    MemEventListener mem_listener = MemEventListener(mem_test_client, true);
+    std::unique_ptr<MemEventListener> memevent_listener;
 
-    void SetUp() override {
-        ASSERT_TRUE(mem_listener.ok()) << "listener failed to initialize bpf ring buffer manager";
-    }
+    void SetUp() override { initializeTestListener(memevent_listener, true); }
 
-    void TearDown() override { mem_listener.deregisterAllEvents(); }
+    void TearDown() override { memevent_listener.reset(); }
 
     /**
      * Helper function that will force the OOM killer to claim a [random]
@@ -751,7 +749,7 @@ class MemoryPressureTest : public ::testing::Test {
              * is called by the parent, but the child hasn't even been scheduled to run yet.
              */
             wait(NULL);
-            if (!mem_listener.listen(2000)) {
+            if (!memevent_listener->listen(2000)) {
                 LOG(ERROR) << "Failed to receive a memory event";
                 return false;
             }
@@ -803,13 +801,13 @@ TEST_F(MemoryPressureTest, oom_e2e_flow) {
     if (!isUpdatedMarkVictimTpSupported())
         GTEST_SKIP() << "New oom/mark_victim fields not supported";
 
-    ASSERT_TRUE(mem_listener.registerEvent(MEM_EVENT_OOM_KILL))
+    ASSERT_TRUE(memevent_listener->registerEvent(MEM_EVENT_OOM_KILL))
             << "Failed registering OOM events as an event of interest";
 
     ASSERT_TRUE(triggerOom()) << "Failed to trigger OOM killer";
 
     std::vector<mem_event_t> oom_events;
-    ASSERT_TRUE(mem_listener.getMemEvents(oom_events)) << "Failed to fetch memory oom events";
+    ASSERT_TRUE(memevent_listener->getMemEvents(oom_events)) << "Failed to fetch memory oom events";
     ASSERT_FALSE(oom_events.empty()) << "We expect at least 1 OOM event";
 }
 
@@ -820,13 +818,13 @@ TEST_F(MemoryPressureTest, register_after_deregister_event) {
     if (!isUpdatedMarkVictimTpSupported())
         GTEST_SKIP() << "New oom/mark_victim fields not supported";
 
-    ASSERT_TRUE(mem_listener.registerEvent(MEM_EVENT_OOM_KILL))
+    ASSERT_TRUE(memevent_listener->registerEvent(MEM_EVENT_OOM_KILL))
             << "Failed registering OOM events as an event of interest";
 
-    ASSERT_TRUE(mem_listener.deregisterEvent(MEM_EVENT_OOM_KILL))
+    ASSERT_TRUE(memevent_listener->deregisterEvent(MEM_EVENT_OOM_KILL))
             << "Failed deregistering OOM events";
 
-    ASSERT_TRUE(mem_listener.registerEvent(MEM_EVENT_OOM_KILL))
+    ASSERT_TRUE(memevent_listener->registerEvent(MEM_EVENT_OOM_KILL))
             << "Failed to register for OOM events after deregister it";
 }
 
diff --git a/libsmapinfo/smapinfo.cpp b/libsmapinfo/smapinfo.cpp
index 4dd3586..1d2e4e8 100644
--- a/libsmapinfo/smapinfo.cpp
+++ b/libsmapinfo/smapinfo.cpp
@@ -1007,6 +1007,7 @@ static bool collect_vma(const Vma& vma) {
 
     VmaInfo& match = iter->second;
     add_mem_usage(&match.vma.usage, current.vma.usage);
+    match.count += 1;
     match.is_bss &= current.is_bss;
     return true;
 }
```

