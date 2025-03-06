```diff
diff --git a/Android.bp b/Android.bp
index 3bad5bd..3a31bf2 100644
--- a/Android.bp
+++ b/Android.bp
@@ -231,8 +231,8 @@ cc_benchmark {
     },
 }
 
-cc_binary {
-    name: "ziptool",
+cc_defaults {
+    name: "ziptool_defaults",
     defaults: ["libziparchive_flags"],
     srcs: ["ziptool.cpp"],
     shared_libs: [
@@ -240,8 +240,6 @@ cc_binary {
         "libziparchive",
         "libz",
     ],
-    recovery_available: true,
-    host_supported: true,
     target: {
         android: {
             symlinks: [
@@ -252,6 +250,19 @@ cc_binary {
     },
 }
 
+cc_binary {
+    name: "ziptool",
+    defaults: ["ziptool_defaults"],
+    host_supported: true,
+}
+
+cc_binary {
+    name: "ziptool.recovery",
+    defaults: ["ziptool_defaults"],
+    recovery: true,
+    stem: "ziptool",
+}
+
 cc_fuzz {
     name: "libziparchive_fuzzer",
     srcs: ["libziparchive_fuzzer.cpp"],
diff --git a/include/ziparchive/zip_archive.h b/include/ziparchive/zip_archive.h
index 0150039..3739f7b 100644
--- a/include/ziparchive/zip_archive.h
+++ b/include/ziparchive/zip_archive.h
@@ -95,16 +95,16 @@ struct ZipEntryCommon {
 };
 
 struct ZipEntry64;
-// Many users of the library assume the entry size is capped at UNIT32_MAX. So we keep
+// Many users of the library assume the entry size is capped at UINT32_MAX. So we keep
 // the interface for the old ZipEntry here; and we could switch them over to the new
 // ZipEntry64 later.
 struct ZipEntry : public ZipEntryCommon {
-  // Compressed length of this ZipEntry. The maximum value is UNIT32_MAX.
+  // Compressed length of this ZipEntry. The maximum value is UINT32_MAX.
   // Might be present either in the local file header or in the data
   // descriptor footer.
   uint32_t compressed_length{0};
 
-  // Uncompressed length of this ZipEntry. The maximum value is UNIT32_MAX.
+  // Uncompressed length of this ZipEntry. The maximum value is UINT32_MAX.
   // Might be present either in the local file header or in the data
   // descriptor footer.
   uint32_t uncompressed_length{0};
@@ -123,12 +123,12 @@ struct ZipEntry : public ZipEntryCommon {
 
 // Represents information about a zip entry in a zip file.
 struct ZipEntry64 : public ZipEntryCommon {
-  // Compressed length of this ZipEntry. The maximum value is UNIT64_MAX.
+  // Compressed length of this ZipEntry. The maximum value is UINT64_MAX.
   // Might be present either in the local file header, the zip64 extended field,
   // or in the data descriptor footer.
   uint64_t compressed_length{0};
 
-  // Uncompressed length of this ZipEntry. The maximum value is UNIT64_MAX.
+  // Uncompressed length of this ZipEntry. The maximum value is UINT64_MAX.
   // Might be present either in the local file header, the zip64 extended field,
   // or in the data descriptor footer.
   uint64_t uncompressed_length{0};
```

