```diff
diff --git a/Android.bp b/Android.bp
index 3a31bf2..b06d0f4 100644
--- a/Android.bp
+++ b/Android.bp
@@ -20,7 +20,6 @@ package {
 
 cc_defaults {
     name: "libziparchive_flags",
-    cpp_std: "c++2a",
     cflags: [
         // ZLIB_CONST turns on const for input buffers, which is pretty standard.
         "-DZLIB_CONST",
diff --git a/include/ziparchive/zip_writer.h b/include/ziparchive/zip_writer.h
index 268e8b6..964bba0 100644
--- a/include/ziparchive/zip_writer.h
+++ b/include/ziparchive/zip_writer.h
@@ -16,8 +16,9 @@
 
 #pragma once
 
-#include <cstdio>
-#include <ctime>
+#include <stdint.h>
+#include <stdio.h>
+#include <time.h>
 
 #include <gtest/gtest_prod.h>
 #include <memory>
diff --git a/zip_cd_entry_map.cc b/zip_cd_entry_map.cc
index 87ed7cf..704ecf1 100644
--- a/zip_cd_entry_map.cc
+++ b/zip_cd_entry_map.cc
@@ -21,7 +21,7 @@ static uint32_t ComputeHash(std::string_view name) {
 }
 
 template <typename ZipStringOffset>
-const std::string_view ToStringView(ZipStringOffset& entry, const uint8_t *start) {
+std::string_view ToStringView(const ZipStringOffset& entry, const uint8_t* start) {
   auto name = reinterpret_cast<const char*>(start + entry.name_offset);
   return std::string_view{name, entry.name_length};
 }
diff --git a/zip_cd_entry_map.h b/zip_cd_entry_map.h
index 838acad..fac3739 100644
--- a/zip_cd_entry_map.h
+++ b/zip_cd_entry_map.h
@@ -18,6 +18,7 @@
 
 #include <stdint.h>
 
+#include <bit>
 #include <map>
 #include <memory>
 #include <string_view>
@@ -28,25 +29,6 @@
 
 #include "zip_error.h"
 
-/*
- * Round up to the next highest power of 2.
- *
- * Found on http://graphics.stanford.edu/~seander/bithacks.html.
- *
- * TODO: could switch to use std::bit_ceil() once ready
- */
-static constexpr uint32_t RoundUpPower2(uint32_t val) {
-  val--;
-  val |= val >> 1;
-  val |= val >> 2;
-  val |= val >> 4;
-  val |= val >> 8;
-  val |= val >> 16;
-  val++;
-
-  return val;
-}
-
 // This class is the interface of the central directory entries map. The map
 // helps to locate a particular cd entry based on the filename.
 class CdEntryMapInterface {
@@ -122,7 +104,7 @@ class CdEntryMapZip32 : public CdEntryMapInterface {
      * low as 50% after we round off to a power of 2.  There must be at
      * least one unused entry to avoid an infinite loop during creation.
      */
-    hash_table_size_ = RoundUpPower2(1 + (num_entries * 4) / 3);
+    hash_table_size_ = std::bit_ceil(1u + (num_entries * 4) / 3);
     hash_table_.reset(static_cast<ZipStringOffset*>(
         calloc(hash_table_size_, sizeof(ZipStringOffset))));
 
```

