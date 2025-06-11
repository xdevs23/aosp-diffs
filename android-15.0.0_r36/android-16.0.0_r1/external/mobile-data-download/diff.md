```diff
diff --git a/Android.bp b/Android.bp
index fe48c20..f5061f7 100644
--- a/Android.bp
+++ b/Android.bp
@@ -60,7 +60,8 @@ android_library {
         "javatests/com/google/android/libraries/mobiledatadownload/testing/MddTestDependencies.java", // Missing BaseFileDownloaderModule
         "javatests/com/google/android/libraries/mobiledatadownload/internal/ExpirationHandlerTest.java", // Test failed
     ],
-
+    sdk_version: "current",
+    min_sdk_version: "30",
     libs: [
         "androidx.test.uiautomator_uiautomator",
         "androidx.test.ext.truth",
@@ -73,6 +74,7 @@ android_library {
         "checker-qual",
     ],
     visibility: [
+        "//packages/modules/AdServices/adservices/tests:__subpackages__",
         ":__subpackages__",
     ],
 }
diff --git a/OWNERS b/OWNERS
index f022250..8def93c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -3,3 +3,4 @@ binhnguyen@google.com
 haoliuu@google.com
 mouad@google.com
 
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/javatests/Android.bp b/javatests/Android.bp
index 1b52f4c..7958145 100644
--- a/javatests/Android.bp
+++ b/javatests/Android.bp
@@ -16,7 +16,6 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-
 //###########################################################
 // Robolectric test target for testing mdd test lib classes #
 //###########################################################
@@ -26,7 +25,7 @@ android_app {
     platform_apis: true,
     libs: [
         "android.test.runner.stubs.system",
-    ]
+    ],
 }
 
 android_robolectric_test {
@@ -48,15 +47,15 @@ android_robolectric_test {
         "com/google/android/libraries/mobiledatadownload/internal/MddIsolatedStructuresTest.java", //android.os.symlink and android.os.readlink do not work with robolectric
         "com/google/android/libraries/mobiledatadownload/testing/FakeMobileDataDownload.java", // Missing GoogleLogger
         "com/google/android/libraries/mobiledatadownload/testing/MddTestDependencies.java", // Missing BaseFileDownloaderModule
-        "com/google/android/libraries/mobiledatadownload/internal/ExpirationHandlerTest.java" // Test failed
+        "com/google/android/libraries/mobiledatadownload/internal/ExpirationHandlerTest.java", // Test failed
 
     ],
 
     java_resource_dirs: ["config"],
 
     libs: [
-        // This jar should not be included, android_robolectric_test soong tasks either ads 
-        // "Robolectric_all-target" or "Robolectric_all-target_upstream" based on the "upstream"
+        // This jar should not be included, android_robolectric_test soong tasks either ads
+        // "Robolectric_all-target" or "Robolectric_all-target" based on the "upstream"
         // flag below.
         "androidx.test.core",
         "mobile_data_downloader_lib",
@@ -64,7 +63,6 @@ android_robolectric_test {
     ],
 
     // use external/robolectric, rather than the outdated external/robolectric-shadows.
-    upstream: true,
 
     instrumentation_for: "MobileDataDownloadPlaceHolderApp",
 
diff --git a/javatests/com/google/android/libraries/mobiledatadownload/testing/LocalFileDownloader.java b/javatests/com/google/android/libraries/mobiledatadownload/testing/LocalFileDownloader.java
index fb2a90c..77e32c8 100644
--- a/javatests/com/google/android/libraries/mobiledatadownload/testing/LocalFileDownloader.java
+++ b/javatests/com/google/android/libraries/mobiledatadownload/testing/LocalFileDownloader.java
@@ -1,5 +1,5 @@
 /*
- * Copyright 2022 Google LLC
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,19 +13,22 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
+
 package com.google.android.libraries.mobiledatadownload.testing;
 
 import static com.google.common.util.concurrent.Futures.immediateFailedFuture;
 import static com.google.common.util.concurrent.Futures.immediateVoidFuture;
 
 import android.net.Uri;
+
+import androidx.test.core.app.ApplicationProvider;
+
 import com.google.android.libraries.mobiledatadownload.DownloadException;
 import com.google.android.libraries.mobiledatadownload.DownloadException.DownloadResultCode;
 import com.google.android.libraries.mobiledatadownload.downloader.DownloadRequest;
 import com.google.android.libraries.mobiledatadownload.downloader.FileDownloader;
 import com.google.android.libraries.mobiledatadownload.file.Opener;
 import com.google.android.libraries.mobiledatadownload.file.SynchronousFileStorage;
-import com.google.android.libraries.mobiledatadownload.file.openers.ReadStreamOpener;
 import com.google.android.libraries.mobiledatadownload.file.openers.WriteStreamOpener;
 import com.google.android.libraries.mobiledatadownload.internal.logging.LogUtil;
 import com.google.common.io.ByteStreams;
@@ -38,56 +41,61 @@ import java.io.OutputStream;
 import java.util.concurrent.Executor;
 
 /**
- * A {@link FileDownloader} that "downloads" by copying the file from the local folder.
+ * A {@link FileDownloader} that "downloads" by copying the file from the application's assets.
+ *
+ * <p>This downloader retrieves files by matching the filename in the provided `urlToDownload` with
+ * a file in the assets. For example, to "download" a file named "image.png" located in the assets,
+ * you would use a URL like "https://example.com/images/image.png".
  *
- * <p>Note that LocalFileDownloader ignores DownloadConditions.
+ * <p><b>Note:</b> This implementation ignores DownloadConditions.
  */
 public final class LocalFileDownloader implements FileDownloader {
 
-  private static final String TAG = "LocalFileDownloader";
+    private static final String TAG = "LocalFileDownloader";
 
-  private final Executor backgroudExecutor;
-  private final SynchronousFileStorage fileStorage;
+    private final Executor backgroudExecutor;
+    private final SynchronousFileStorage fileStorage;
 
-  public LocalFileDownloader(
-      SynchronousFileStorage fileStorage, ListeningExecutorService executor) {
-    this.fileStorage = fileStorage;
-    this.backgroudExecutor = executor;
-  }
+    public LocalFileDownloader(
+            SynchronousFileStorage fileStorage, ListeningExecutorService executor) {
+        this.fileStorage = fileStorage;
+        this.backgroudExecutor = executor;
+    }
 
-  @Override
-  public ListenableFuture<Void> startDownloading(DownloadRequest downloadRequest) {
-    return Futures.submitAsync(() -> startDownloadingInternal(downloadRequest), backgroudExecutor);
-  }
+    @Override
+    public ListenableFuture<Void> startDownloading(DownloadRequest downloadRequest) {
+        return Futures.submitAsync(
+                () -> startDownloadingInternal(downloadRequest), backgroudExecutor);
+    }
 
-  private ListenableFuture<Void> startDownloadingInternal(DownloadRequest downloadRequest) {
-    Uri fileUri = downloadRequest.fileUri();
-    String urlToDownload = downloadRequest.urlToDownload();
-    LogUtil.d("%s: startDownloading; fileUri: %s; urlToDownload: %s", TAG, fileUri, urlToDownload);
+    private ListenableFuture<Void> startDownloadingInternal(DownloadRequest downloadRequest) {
+        Uri fileUri = downloadRequest.fileUri();
+        String urlToDownload = downloadRequest.urlToDownload();
+        LogUtil.d(
+                "%s: startDownloadingInternal;  urlToDownload: %s; fileUri: %s;",
+                TAG, urlToDownload, fileUri);
 
-    Uri uriToDownload = Uri.parse(urlToDownload);
-    if (uriToDownload == null) {
-      LogUtil.e("%s: Invalid urlToDownload %s", TAG, urlToDownload);
-      return immediateFailedFuture(new IllegalArgumentException("Invalid urlToDownload"));
-    }
+        try {
+            Opener<OutputStream> writeStreamOpener = WriteStreamOpener.create();
+            long writtenBytes;
+            try (InputStream in =
+                            ApplicationProvider.getApplicationContext()
+                                    .getAssets()
+                                    .open(urlToDownload);
+                    OutputStream out = fileStorage.open(fileUri, writeStreamOpener)) {
+                writtenBytes = ByteStreams.copy(in, out);
+            }
+            LogUtil.d(
+                    "%s: File URI %s download complete, writtenBytes: %d",
+                    TAG, fileUri, writtenBytes);
+        } catch (IOException e) {
+            LogUtil.e(e, "%s: startDownloading got exception", TAG);
+            return immediateFailedFuture(
+                    DownloadException.builder()
+                            .setDownloadResultCode(DownloadResultCode.ANDROID_DOWNLOADER_HTTP_ERROR)
+                            .build());
+        }
 
-    try {
-      Opener<InputStream> readStreamOpener = ReadStreamOpener.create();
-      Opener<OutputStream> writeStreamOpener = WriteStreamOpener.create();
-      long writtenBytes;
-      try (InputStream in = fileStorage.open(uriToDownload, readStreamOpener);
-          OutputStream out = fileStorage.open(fileUri, writeStreamOpener)) {
-        writtenBytes = ByteStreams.copy(in, out);
-      }
-      LogUtil.d("%s: File URI %s download complete, writtenBytes: %d", TAG, fileUri, writtenBytes);
-    } catch (IOException e) {
-      LogUtil.e(e, "%s: startDownloading got exception", TAG);
-      return immediateFailedFuture(
-          DownloadException.builder()
-              .setDownloadResultCode(DownloadResultCode.ANDROID_DOWNLOADER_HTTP_ERROR)
-              .build());
+        return immediateVoidFuture();
     }
-
-    return immediateVoidFuture();
-  }
 }
diff --git a/javatests/com/google/android/libraries/mobiledatadownload/testing/TestFileDownloader.java b/javatests/com/google/android/libraries/mobiledatadownload/testing/TestFileDownloader.java
index a7f9db2..e67624f 100644
--- a/javatests/com/google/android/libraries/mobiledatadownload/testing/TestFileDownloader.java
+++ b/javatests/com/google/android/libraries/mobiledatadownload/testing/TestFileDownloader.java
@@ -1,5 +1,5 @@
 /*
- * Copyright 2022 Google LLC
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -13,73 +13,55 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.google.android.libraries.mobiledatadownload.testing;
 
-import static com.google.common.util.concurrent.Futures.immediateVoidFuture;
+package com.google.android.libraries.mobiledatadownload.testing;
 
 import android.net.Uri;
-import android.os.Environment;
+
 import com.google.android.libraries.mobiledatadownload.downloader.DownloadConstraints;
 import com.google.android.libraries.mobiledatadownload.downloader.DownloadRequest;
 import com.google.android.libraries.mobiledatadownload.downloader.FileDownloader;
-import com.google.android.libraries.mobiledatadownload.file.SynchronousFileStorage;
-import com.google.android.libraries.mobiledatadownload.file.backends.FileUri;
 import com.google.android.libraries.mobiledatadownload.internal.logging.LogUtil;
+import com.google.android.libraries.mobiledatadownload.file.SynchronousFileStorage;
 import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.ListeningExecutorService;
 
 /**
- * A {@link FileDownloader} that "downloads" by copying the file from the testdata folder.
+ * A {@link FileDownloader} that "downloads" by copying the file from the application's assets.
  *
- * <p>The filename is the Last Path Segment of the urlToDownload. For example, the URL
- * https://www.gstatic.com/icing/idd/sample_group/step1.txt will be mapped to the file
- * testDataAbsolutePath/step1.txt.
+ * <p>The filename is the Last Path Segment of the provided `urlToDownload`. For example, the URL
+ * https://www.gstatic.com/icing/idd/sample_group/step1.txt will be mapped to the asset named
+ * "step1.txt".
  *
  * <p>Note that TestFileDownloader ignores the DownloadConditions.
  */
 public final class TestFileDownloader implements FileDownloader {
 
-  private static final String TAG = "TestDataFileDownloader";
+    private static final String TAG = "TestDataFileDownloader";
 
-  private static final String GOOGLE3_ABSOLUTE_PATH =
-      Environment.getExternalStorageDirectory() + "/googletest/test_runfiles/google3/";
+    private final FileDownloader delegateDownloader;
 
-  private final String testDataAbsolutePath;
-  private final FileDownloader delegateDownloader;
+    public TestFileDownloader(
+            SynchronousFileStorage fileStorage, ListeningExecutorService executor) {
+        this.delegateDownloader = new LocalFileDownloader(fileStorage, executor);
+    }
 
-  public TestFileDownloader(
-      String testDataRelativePath,
-      SynchronousFileStorage fileStorage,
-      ListeningExecutorService executor) {
-    this.testDataAbsolutePath = GOOGLE3_ABSOLUTE_PATH + testDataRelativePath;
-    this.delegateDownloader = new LocalFileDownloader(fileStorage, executor);
-  }
+    @Override
+    public ListenableFuture<Void> startDownloading(DownloadRequest downloadRequest) {
+        LogUtil.d(
+                "%s: startDownloading; urlToDownload: %s; uriToDownload: %s;",
+                TAG, downloadRequest.urlToDownload(), downloadRequest.fileUri());
 
-  @Override
-  public ListenableFuture<Void> startDownloading(DownloadRequest downloadRequest) {
-    Uri fileUri = downloadRequest.fileUri();
-    String urlToDownload = downloadRequest.urlToDownload();
-    DownloadConstraints downloadConstraints = downloadRequest.downloadConstraints();
+        Uri fileUri = downloadRequest.fileUri();
+        String urlToDownload = downloadRequest.urlToDownload();
+        Uri uriToDownload = Uri.parse(urlToDownload);
+        DownloadConstraints downloadConstraints = downloadRequest.downloadConstraints();
 
-    // We need to translate the real urlToDownload to the one representing the local file in
-    // testdata folder.
-    Uri uriToDownload = Uri.parse(urlToDownload.trim());
-    if (uriToDownload == null) {
-      LogUtil.e("%s: Invalid urlToDownload %s", TAG, urlToDownload);
-      return immediateVoidFuture();
+        return delegateDownloader.startDownloading(
+                DownloadRequest.newBuilder()
+                        .setFileUri(fileUri)
+                        .setUrlToDownload(uriToDownload.getLastPathSegment())
+                        .setDownloadConstraints(downloadConstraints)
+                        .build());
     }
-
-    String testDataUrl =
-        FileUri.builder()
-            .setPath(testDataAbsolutePath + uriToDownload.getLastPathSegment())
-            .build()
-            .toString();
-
-    return delegateDownloader.startDownloading(
-        DownloadRequest.newBuilder()
-            .setFileUri(fileUri)
-            .setUrlToDownload(testDataUrl)
-            .setDownloadConstraints(downloadConstraints)
-            .build());
-  }
 }
```

