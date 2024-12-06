```diff
diff --git a/include/procinfo/process_map.h b/include/procinfo/process_map.h
index d7e8d94..a4fc181 100644
--- a/include/procinfo/process_map.h
+++ b/include/procinfo/process_map.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <inttypes.h>
+#include <stdint.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/mman.h>
@@ -54,6 +56,35 @@ struct MapInfo {
   std::string name;
   bool shared;
 
+  // With MTE globals, segments are remapped as anonymous mappings. They're
+  // named specifically to preserve offsets and as much of the basename as
+  // possible. For example,
+  // "[anon:mt:/data/local/tmp/debuggerd_test/arm64/debuggerd_test64+108000]" is
+  // the name of anonymized mapping for debuggerd_test64 of the segment starting
+  // at 0x108000. The kernel only supports 80 characters (excluding the '[anon:'
+  // prefix and ']' suffix, but including the null terminator), and in those
+  // instances, we maintain the offset and as much of the basename as possible
+  // by left-truncation. For example:
+  // "[anon:mt:/data/nativetest64/bionic-unit-tests/bionic-loader-test-libs/libdlext_test.so+e000]"
+  // would become:
+  // "[anon:mt:...ivetest64/bionic-unit-tests/bionic-loader-test-libs/libdlext_test.so+e000]".
+  // For mappings under MTE globals, we thus post-process the name to extract the page offset, and
+  // canonicalize the name.
+  static constexpr const char* kMtePrefix = "[anon:mt:";
+  static constexpr size_t kMtePrefixLength = sizeof(kMtePrefix) - 1;
+
+  void MaybeExtractMemtagGlobalsInfo() {
+    if (!this->name.starts_with(kMtePrefix)) return;
+    if (this->name.back() != ']') return;
+
+    size_t offset_to_plus = this->name.rfind('+');
+    if (offset_to_plus == std::string::npos) return;
+    if (sscanf(this->name.c_str() + offset_to_plus + 1, "%" SCNx64 "]", &this->pgoff) != 1) return;
+
+    this->name =
+        std::string(this->name.begin() + kMtePrefixLength + 2, this->name.begin() + offset_to_plus);
+  }
+
   MapInfo(uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, ino_t inode,
           const char* name, bool shared)
       : start(start),
@@ -62,7 +93,9 @@ struct MapInfo {
         pgoff(pgoff),
         inode(inode),
         name(name),
-        shared(shared) {}
+        shared(shared) {
+    MaybeExtractMemtagGlobalsInfo();
+  }
 
   MapInfo(const MapInfo& params)
       : start(params.start),
diff --git a/process_map_test.cpp b/process_map_test.cpp
index 61f142a..27dd382 100644
--- a/process_map_test.cpp
+++ b/process_map_test.cpp
@@ -28,6 +28,8 @@
 
 #include <gtest/gtest.h>
 
+using android::procinfo::MapInfo;
+
 TEST(process_map, ReadMapFile) {
   std::string map_file = android::base::GetExecutableDirectory() + "/testdata/maps";
   std::vector<android::procinfo::MapInfo> maps;
@@ -390,3 +392,73 @@ TEST_F(ProcessMapMappedFileSize, invalid_map_name) {
   mapped_file_size = android::procinfo::MappedFileSize(map);
   ASSERT_EQ(mapped_file_size, 0UL);
 }
+
+static MapInfo CreateMapWithOnlyName(const char* name) {
+  return MapInfo(0, 0, 0, UINT64_MAX, 0, name, false);
+}
+
+TEST(process_map, TaggedMappingNames) {
+  MapInfo info = CreateMapWithOnlyName(
+      "[anon:mt:/data/local/tmp/debuggerd_test/arm64/debuggerd_test64+108000]");
+  ASSERT_EQ(info.name, "/data/local/tmp/debuggerd_test/arm64/debuggerd_test64");
+  ASSERT_EQ(info.pgoff, 0x108000ull);
+
+  info = CreateMapWithOnlyName("[anon:mt:/data/local/tmp/debuggerd_test/arm64/debuggerd_test64+0]");
+  ASSERT_EQ(info.name, "/data/local/tmp/debuggerd_test/arm64/debuggerd_test64");
+  ASSERT_EQ(info.pgoff, 0x0ull);
+
+  info =
+      CreateMapWithOnlyName("[anon:mt:/data/local/tmp/debuggerd_test/arm64/debuggerd_test64+0000]");
+  ASSERT_EQ(info.name, "/data/local/tmp/debuggerd_test/arm64/debuggerd_test64");
+  ASSERT_EQ(info.pgoff, 0x0ull);
+
+  info = CreateMapWithOnlyName(
+      "[anon:mt:...ivetest64/bionic-unit-tests/bionic-loader-test-libs/libdlext_test.so+e000]");
+  ASSERT_EQ(info.name, "...ivetest64/bionic-unit-tests/bionic-loader-test-libs/libdlext_test.so");
+  ASSERT_EQ(info.pgoff, 0xe000ull);
+
+  info = CreateMapWithOnlyName("[anon:mt:/bin/x+e000]");
+  ASSERT_EQ(info.name, "/bin/x");
+  ASSERT_EQ(info.pgoff, 0xe000ull);
+
+  info = CreateMapWithOnlyName("[anon:mt:/bin/x+0]");
+  ASSERT_EQ(info.name, "/bin/x");
+  ASSERT_EQ(info.pgoff, 0x0ull);
+
+  info = CreateMapWithOnlyName("[anon:mt:/bin/x+1]");
+  ASSERT_EQ(info.name, "/bin/x");
+  ASSERT_EQ(info.pgoff, 0x1ull);
+
+  info = CreateMapWithOnlyName("[anon:mt:/bin/x+f]");
+  ASSERT_EQ(info.name, "/bin/x");
+  ASSERT_EQ(info.pgoff, 0xfull);
+
+  info = CreateMapWithOnlyName("[anon:mt:/bin/with/plus+/x+f]");
+  ASSERT_EQ(info.name, "/bin/with/plus+/x");
+  ASSERT_EQ(info.pgoff, 0xfull);
+
+  info = CreateMapWithOnlyName("[anon:mt:/bin/+with/mu+ltiple/plus+/x+f]");
+  ASSERT_EQ(info.name, "/bin/+with/mu+ltiple/plus+/x");
+  ASSERT_EQ(info.pgoff, 0xfull);
+
+  info = CreateMapWithOnlyName("[anon:mt:/bin/trailing/plus++f]");
+  ASSERT_EQ(info.name, "/bin/trailing/plus+");
+  ASSERT_EQ(info.pgoff, 0xfull);
+
+  info = CreateMapWithOnlyName("[anon:mt:++f]");
+  ASSERT_EQ(info.name, "+");
+  ASSERT_EQ(info.pgoff, 0xfull);
+}
+
+TEST(process_map, AlmostTaggedMappingNames) {
+  for (const char* almost_tagged_name :
+       {"[anon:mt:/bin/x+]",
+        "[anon:mt:/bin/x]"
+        "[anon:mt:+]",
+        "[anon:mt", "[anon:mt:/bin/x+1", "[anon:mt:/bin/x+e000",
+        "anon:mt:/data/local/tmp/debuggerd_test/arm64/debuggerd_test64+e000]"}) {
+    MapInfo info = CreateMapWithOnlyName(almost_tagged_name);
+    ASSERT_EQ(info.name, almost_tagged_name);
+    ASSERT_EQ(info.pgoff, UINT64_MAX) << almost_tagged_name;
+  }
+}
```

