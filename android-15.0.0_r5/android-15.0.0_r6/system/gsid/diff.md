```diff
diff --git a/include/libgsi/libgsi.h b/include/libgsi/libgsi.h
index 969ea28..955119b 100644
--- a/include/libgsi/libgsi.h
+++ b/include/libgsi/libgsi.h
@@ -46,6 +46,9 @@ static constexpr char kDsuMetadataKeyDirPrefix[] = "/metadata/vold/metadata_encr
 
 static constexpr char kDsuSDPrefix[] = "/mnt/media_rw/";
 
+// GSI-specific init script defined in build/make/target/product/gsi/Android.mk
+static constexpr char kGsiSpecificInitRcFile[] = "/system/system_ext/etc/init/init.gsi.rc";
+
 static inline std::string DsuLpMetadataFile(const std::string& dsu_slot) {
     return DSU_METADATA_PREFIX + dsu_slot + "/lp_metadata";
 }
@@ -95,7 +98,10 @@ static inline bool GetActiveDsu(std::string* active_dsu) {
     return android::base::ReadFileToString(kDsuActiveFile, active_dsu);
 }
 
-// Returns true if the currently running system image is a live GSI.
+// Returns true if the currently running system image is a GSI (both dynamic and flashed).
+bool IsGsiImage();
+
+// Returns true if the currently running system image is a live (dynamic) GSI.
 bool IsGsiRunning();
 
 // Return true if a GSI is installed (but not necessarily running).
diff --git a/libgsi.cpp b/libgsi.cpp
index 3b0db51..097fcb6 100644
--- a/libgsi.cpp
+++ b/libgsi.cpp
@@ -37,6 +37,10 @@ using android::base::ReadFileToString;
 using android::base::Split;
 using android::base::unique_fd;
 
+bool IsGsiImage() {
+    return !access(kGsiSpecificInitRcFile, F_OK);
+}
+
 bool IsGsiRunning() {
     return !access(kGsiBootedIndicatorFile, F_OK);
 }
diff --git a/tests/DSUEndtoEndTest.java b/tests/DSUEndtoEndTest.java
index 8179d59..1fa661d 100644
--- a/tests/DSUEndtoEndTest.java
+++ b/tests/DSUEndtoEndTest.java
@@ -71,14 +71,25 @@ public class DSUEndtoEndTest extends DsuTestBase {
                 "Failed to fetch system image. See system_image_path parameter", imgZip);
 
         File superImg = getTempPath("super.img");
-        try (ZipFile zip = new ZipFile(imgZip)) {
-            File systemImg = getTempPath("system.img");
-            if (ZipUtil2.extractFileFromZip(zip, "system.img", systemImg)) {
+        if (imgZip.isDirectory()) {
+            File systemImg = new File(imgZip, "system.img");
+            if (systemImg.exists()) {
                 return systemImg;
             }
+            superImg = new File(imgZip, "super.img");
             Assert.assertTrue(
                     "No system.img or super.img in img zip.",
-                    ZipUtil2.extractFileFromZip(zip, "super.img", superImg));
+                    superImg.exists());
+        } else {
+            try (ZipFile zip = new ZipFile(imgZip)) {
+                File systemImg = getTempPath("system.img");
+                if (ZipUtil2.extractFileFromZip(zip, "system.img", systemImg)) {
+                    return systemImg;
+                }
+                Assert.assertTrue(
+                        "No system.img or super.img in img zip.",
+                        ZipUtil2.extractFileFromZip(zip, "super.img", superImg));
+            }
         }
 
         if (SparseImageUtil.isSparse(superImg)) {
```

