```diff
diff --git a/Android.bp b/Android.bp
index 7ea6396..fe48c20 100644
--- a/Android.bp
+++ b/Android.bp
@@ -38,12 +38,12 @@ java_library {
         "//apex_available:platform",
         "com.android.adservices",
         "com.android.extservices",
-	"com.android.ondevicepersonalization",
+        "com.android.ondevicepersonalization",
     ],
 }
 
 android_library {
-        name: "mdd-robolectric-library",
+    name: "mdd-robolectric-library",
     srcs: [
         "javatests/com/google/android/libraries/mobiledatadownload/internal/MddTestUtil.java",
         "javatests/com/google/android/libraries/mobiledatadownload/testing/**/*.java",
@@ -58,7 +58,7 @@ android_library {
         "javatests/com/google/android/libraries/mobiledatadownload/testing/BlockingFileDownloader.java", // Missing GoogleLogger
         "javatests/com/google/android/libraries/mobiledatadownload/testing/FakeMobileDataDownload.java", // Missing GoogleLogger
         "javatests/com/google/android/libraries/mobiledatadownload/testing/MddTestDependencies.java", // Missing BaseFileDownloaderModule
-        "javatests/com/google/android/libraries/mobiledatadownload/internal/ExpirationHandlerTest.java" // Test failed
+        "javatests/com/google/android/libraries/mobiledatadownload/internal/ExpirationHandlerTest.java", // Test failed
     ],
 
     libs: [
@@ -113,13 +113,14 @@ android_library {
     min_sdk_version: "30",
     apex_available: [
         "//apex_available:platform",
-         "com.android.adservices",
-         "com.android.extservices",
-         "com.android.ondevicepersonalization",
+        "com.android.adservices",
+        "com.android.extservices",
+        "com.android.ondevicepersonalization",
     ],
     visibility: [
         "//packages/modules/AdServices:__subpackages__",
-	"//packages/modules/OnDevicePersonalization:__subpackages__",
+        "//packages/modules/OnDevicePersonalization:__subpackages__",
+        "//vendor:__subpackages__",
         ":__subpackages__",
     ],
     errorprone: {
diff --git a/OWNERS b/OWNERS
index 370ff32..f022250 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,5 @@
-npattan@google.com
+arunjoseph@google.com
 binhnguyen@google.com
 haoliuu@google.com
+mouad@google.com
+
diff --git a/java/com/google/android/libraries/mobiledatadownload/populator/ManifestFileMetadataStore.java b/java/com/google/android/libraries/mobiledatadownload/populator/ManifestFileMetadataStore.java
index 874571b..f07c221 100644
--- a/java/com/google/android/libraries/mobiledatadownload/populator/ManifestFileMetadataStore.java
+++ b/java/com/google/android/libraries/mobiledatadownload/populator/ManifestFileMetadataStore.java
@@ -20,7 +20,7 @@ import com.google.common.util.concurrent.ListenableFuture;
 import com.google.mobiledatadownload.populator.MetadataProto.ManifestFileBookkeeping;
 
 /** Storage mechanism for ManifestFileBookkeeping. */
-interface ManifestFileMetadataStore {
+public interface ManifestFileMetadataStore {
   /** Returns the metadata associated with {@code manifestId} if it exists. */
   ListenableFuture<Optional<ManifestFileBookkeeping>> read(String manifestId);
 
```

