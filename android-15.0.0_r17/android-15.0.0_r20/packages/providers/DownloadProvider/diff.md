```diff
diff --git a/Android.bp b/Android.bp
index 710f0388..c331f9d1 100644
--- a/Android.bp
+++ b/Android.bp
@@ -38,7 +38,12 @@ android_app {
 
     privileged: true,
 
-    static_libs: ["guava"],
+    static_libs: [
+        "guava",
+        "com.android.providers.downloads.flags-aconfig-java",
+    ],
+
+    libs: ["framework-connectivity.stubs.module_lib"],
 
     jacoco: {
         include_filter: ["com.android.providers.downloads.*"],
diff --git a/flags/Android.bp b/flags/Android.bp
new file mode 100644
index 00000000..86eeb36e
--- /dev/null
+++ b/flags/Android.bp
@@ -0,0 +1,27 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+//
+
+aconfig_declarations {
+    name: "com.android.providers.downloads.flags-aconfig",
+    package: "com.android.providers.downloads.flags",
+    container: "system",
+    srcs: ["download_manager_flags.aconfig"],
+}
+
+java_aconfig_library {
+    name: "com.android.providers.downloads.flags-aconfig-java",
+    aconfig_declarations: "com.android.providers.downloads.flags-aconfig",
+}
diff --git a/flags/download_manager_flags.aconfig b/flags/download_manager_flags.aconfig
new file mode 100644
index 00000000..cb45848e
--- /dev/null
+++ b/flags/download_manager_flags.aconfig
@@ -0,0 +1,9 @@
+package: "com.android.providers.downloads.flags"
+container: "system"
+
+flag {
+  name: "download_via_platform_http_engine"
+  namespace: "android_core_networking"
+  description: "Use HttpEngine for downloading content instead of UrlConnection."
+  bug: "371965430"
+}
\ No newline at end of file
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 96bfba0c..f6107bdb 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -19,17 +19,17 @@
     <string name="app_label" msgid="5264040740662487684">"Aflaaibestuurder"</string>
     <string name="storage_description" msgid="169690279447532621">"Aflaaie"</string>
     <string name="permlab_downloadManager" msgid="4241473724446132797">"Kry toegang tot aflaaibestuurder."</string>
-    <string name="permdesc_downloadManager" msgid="5562734314998369030">"Laat die program toe om toegang te kry tot die aflaaibestuurder en dit te gebruik om lêers af te laai. Kwaadwillige programme kan dit gebruik om aflaaie te ontwrig en toegang tot private inligting te kry."</string>
+    <string name="permdesc_downloadManager" msgid="5562734314998369030">"Laat die app toe om toegang te kry tot die aflaaibestuurder en dit te gebruik om lêers af te laai. Kwaadwillige apps kan dit gebruik om aflaaie te ontwrig en toegang tot private inligting te kry."</string>
     <string name="permlab_downloadManagerAdvanced" msgid="2225663947531460795">"Gevorderde aflaaibestuurder-funksies"</string>
-    <string name="permdesc_downloadManagerAdvanced" msgid="3902478062563030716">"Laat die program toe om toegang te kry tot die aflaaibestuurder se gevorderde instellings. Kwaadwillige programme kan dit gebruik om aflaaie te ontwrig en toegang tot private inligting te kry."</string>
+    <string name="permdesc_downloadManagerAdvanced" msgid="3902478062563030716">"Laat die app toe om toegang te kry tot die aflaaibestuurder se gevorderde instellings. Kwaadwillige apps kan dit gebruik om aflaaie te ontwrig en toegang tot private inligting te kry."</string>
     <string name="permlab_downloadCompletedIntent" msgid="2674407390116052956">"Stuur aflaaikennisgewings."</string>
-    <string name="permdesc_downloadCompletedIntent" msgid="3384693829639860032">"Laat die program toe om kennisgewings te stuur oor voltooide aflaaie. Kwaadwillige programme kan dit gebruik om ander programme wat lêers aflaai, te verwar."</string>
+    <string name="permdesc_downloadCompletedIntent" msgid="3384693829639860032">"Laat die app toe om kennisgewings te stuur oor voltooide aflaaie. Kwaadwillige apps kan dit gebruik om ander apps wat lêers aflaai, te verwar."</string>
     <string name="permlab_downloadCacheNonPurgeable" msgid="4538031250425141333">"Reserveer ruimte in die aflaaikas"</string>
-    <string name="permdesc_downloadCacheNonPurgeable" msgid="3071381088686444674">"Laat die program toe om lêers af te laai na die aflaaikas, wat nie outomaties uitgevee kan word as die aflaaibestuurder meer spasie benodig nie."</string>
+    <string name="permdesc_downloadCacheNonPurgeable" msgid="3071381088686444674">"Laat die app toe om lêers af te laai na die aflaaikas, wat nie outomaties uitgevee kan word as die aflaaibestuurder meer spasie benodig nie."</string>
     <string name="permlab_downloadWithoutNotification" msgid="4877101864770265405">"laai lêers af sonder kennisgewing"</string>
-    <string name="permdesc_downloadWithoutNotification" msgid="7699189763226483523">"Laat die program toe om lêers deur die aflaaibestuurder af te laai sonder enige kennisgewing wat aan die gebruiker gewys word."</string>
+    <string name="permdesc_downloadWithoutNotification" msgid="7699189763226483523">"Laat die app toe om lêers deur die aflaaibestuurder af te laai sonder enige kennisgewing wat aan die gebruiker gewys word."</string>
     <string name="permlab_accessAllDownloads" msgid="8227356876527248611">"Kry toegang tot alle stelselaflaaisels"</string>
-    <string name="permdesc_accessAllDownloads" msgid="7541731738152145079">"Laat die program toe om alle aflaaie wat deur enige program op hierdie stelsel geïnisieer is, te sien en te wysig."</string>
+    <string name="permdesc_accessAllDownloads" msgid="7541731738152145079">"Laat die app toe om alle aflaaie wat deur enige app op hierdie stelsel geïnisieer is, te sien en te wysig."</string>
     <string name="download_unknown_title" msgid="1017800350818840396">"&lt;Ongetiteld&gt;"</string>
     <string name="notification_download_complete" msgid="466652037490092787">"Aflaai voltooi."</string>
     <string name="notification_download_failed" msgid="3932167763860605874">"Aflaai onsuksesvol."</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 93f40be9..08e949f2 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -25,7 +25,7 @@
     <string name="permlab_downloadCompletedIntent" msgid="2674407390116052956">"اعلان‌های بارگیری ارسال شود."</string>
     <string name="permdesc_downloadCompletedIntent" msgid="3384693829639860032">"به برنامه اجازه می‌دهد اعلان‌های مربوط به بارگیریهای کامل شده را ارسال کند. برنامه‌های مضر می‌توانند از این امکان استفاده کرده و برای سایر برنامه‌هایی که فایل‌ها را بارگیری می‌کنند، مشکلاتی را ایجاد کنند."</string>
     <string name="permlab_downloadCacheNonPurgeable" msgid="4538031250425141333">"رزرو فضا در حافظه موقت بارگیری"</string>
-    <string name="permdesc_downloadCacheNonPurgeable" msgid="3071381088686444674">"‏به برنامه اجازه می‌دهد فایل‌ها را در حافظهٔ پنهان بارگیری کند، تا هنگامی که Download Manager به فضای بیشتری احتیاج دارد، به‌طور خودکار حذف نشوند.+"</string>
+    <string name="permdesc_downloadCacheNonPurgeable" msgid="3071381088686444674">"‏به برنامه اجازه می‌دهد فایل‌ها را در حافظه نهان بارگیری کند، تا هنگامی که Download Manager به فضای بیشتری احتیاج دارد، به‌طور خودکار حذف نشوند.+"</string>
     <string name="permlab_downloadWithoutNotification" msgid="4877101864770265405">"بارگیری فایل‌ها بدون اطلاع"</string>
     <string name="permdesc_downloadWithoutNotification" msgid="7699189763226483523">"‏به برنامه اجازه می‌دهد فایل‌ها را از طریق Download Manager، بدون نمایش اعلان به کاربر بارگیری کند."</string>
     <string name="permlab_accessAllDownloads" msgid="8227356876527248611">"دسترسی به همه بارگیری‌های سیستم"</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 67f6a4a5..e89b3a41 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="app_label" msgid="5264040740662487684">"内容下载管理器"</string>
+    <string name="app_label" msgid="5264040740662487684">"下载管理器"</string>
     <string name="storage_description" msgid="169690279447532621">"下载内容"</string>
     <string name="permlab_downloadManager" msgid="4241473724446132797">"访问下载管理器。"</string>
     <string name="permdesc_downloadManager" msgid="5562734314998369030">"允许该应用使用下载管理器并通过它下载文件。恶意应用可能会借此中断下载并访问私人信息。"</string>
diff --git a/src/com/android/providers/downloads/DownloadProvider.java b/src/com/android/providers/downloads/DownloadProvider.java
index 77fe8832..c43e8c6d 100644
--- a/src/com/android/providers/downloads/DownloadProvider.java
+++ b/src/com/android/providers/downloads/DownloadProvider.java
@@ -84,6 +84,7 @@ import java.io.FileDescriptor;
 import java.io.FileNotFoundException;
 import java.io.IOException;
 import java.io.PrintWriter;
+import java.util.Arrays;
 import java.util.Iterator;
 import java.util.Map;
 
@@ -1053,9 +1054,7 @@ public final class DownloadProvider extends ContentProvider {
             values.put(COLUMN_MEDIA_SCANNED, mediaScannable);
             values.put(COLUMN_IS_VISIBLE_IN_DOWNLOADS_UI, visibleInDownloadsUi);
         } else {
-            if (!values.containsKey(COLUMN_IS_VISIBLE_IN_DOWNLOADS_UI)) {
-                values.put(COLUMN_IS_VISIBLE_IN_DOWNLOADS_UI, true);
-            }
+            values.put(COLUMN_IS_VISIBLE_IN_DOWNLOADS_UI, true);
         }
     }
 
@@ -1120,8 +1119,48 @@ public final class DownloadProvider extends ContentProvider {
         Helpers.checkDestinationFilePathRestrictions(file, getCallingPackage(), getContext(),
                 mAppOpsManager, getCallingAttributionTag(), isLegacyMode,
                 /* allowDownloadsDirOnly */ true);
+        // check whether record already exists in MP or getCallingPackage owns this file
+        checkWhetherCallingAppHasAccess(file.getPath(), Binder.getCallingUid());
+    }
+
+    private void checkWhetherCallingAppHasAccess(String filePath, int uid) {
+        try (ContentProviderClient client = getContext().getContentResolver()
+                .acquireContentProviderClient(MediaStore.AUTHORITY)) {
+            if (client == null) {
+                Log.w(Constants.TAG, "Failed to acquire ContentProviderClient for MediaStore");
+                return;
+            }
+
+            Uri filesUri = MediaStore.setIncludePending(
+                    Helpers.getContentUriForPath(getContext(), filePath));
+
+            try (Cursor cursor = client.query(filesUri,
+                    new String[]{MediaStore.Files.FileColumns._ID,
+                            MediaStore.Files.FileColumns.OWNER_PACKAGE_NAME},
+                    MediaStore.Files.FileColumns.DATA + "=?", new String[]{filePath},
+                    null)) {
+                if (cursor != null && cursor.moveToFirst()) {
+                    String fetchedOwnerPackageName = cursor.getString(
+                            cursor.getColumnIndexOrThrow(
+                                    MediaStore.Files.FileColumns.OWNER_PACKAGE_NAME));
+                    String[] packageNames = getContext().getPackageManager().getPackagesForUid(uid);
+
+                    if (fetchedOwnerPackageName != null && packageNames != null) {
+                        boolean isCallerAuthorized = Arrays.asList(packageNames)
+                                .contains(fetchedOwnerPackageName);
+                        if (!isCallerAuthorized) {
+                            throw new SecurityException("Caller does not have access to this path");
+                        }
+                    }
+                }
+            }
+        } catch (RemoteException e) {
+            Log.w(Constants.TAG, "Failed to query MediaStore: " + e.getMessage());
+        }
     }
 
+
+
     /**
      * Apps with the ACCESS_DOWNLOAD_MANAGER permission can access this provider freely, subject to
      * constraints in the rest of the code. Apps without that may still access this provider through
@@ -1647,7 +1686,16 @@ public final class DownloadProvider extends ContentProvider {
                                     Log.v(Constants.TAG,
                                             "Deleting " + file + " via provider delete");
                                     file.delete();
-                                    MediaStore.scanFile(getContext().getContentResolver(), file);
+                                    // if external_primary volume is mounted, then do the scan
+                                    if (Environment.getExternalStorageState().equals(
+                                            Environment.MEDIA_MOUNTED)) {
+                                        MediaStore.scanFile(getContext().getContentResolver(),
+                                                file);
+                                    } else {
+                                        Log.w(Constants.TAG,
+                                                "external_primary volume is not mounted,"
+                                                        + " skipping scan");
+                                    }
                                 } else {
                                     Log.d(Constants.TAG, "Ignoring invalid file: " + file);
                                 }
diff --git a/src/com/android/providers/downloads/DownloadThread.java b/src/com/android/providers/downloads/DownloadThread.java
index 8522e26b..498030d5 100644
--- a/src/com/android/providers/downloads/DownloadThread.java
+++ b/src/com/android/providers/downloads/DownloadThread.java
@@ -40,6 +40,7 @@ import static android.provider.Downloads.Impl.STATUS_WAITING_TO_RETRY;
 import static android.text.format.DateUtils.SECOND_IN_MILLIS;
 
 import static com.android.providers.downloads.Constants.TAG;
+import static com.android.providers.downloads.flags.Flags.downloadViaPlatformHttpEngine;
 
 import static java.net.HttpURLConnection.HTTP_INTERNAL_ERROR;
 import static java.net.HttpURLConnection.HTTP_MOVED_PERM;
@@ -56,14 +57,13 @@ import android.content.Context;
 import android.content.Intent;
 import android.drm.DrmManagerClient;
 import android.drm.DrmOutputStream;
-import android.net.ConnectivityManager;
 import android.net.INetworkPolicyListener;
 import android.net.Network;
 import android.net.NetworkCapabilities;
-import android.net.NetworkInfo;
 import android.net.NetworkPolicyManager;
 import android.net.TrafficStats;
 import android.net.Uri;
+import android.net.http.HttpEngine;
 import android.os.ParcelFileDescriptor;
 import android.os.Process;
 import android.os.SystemClock;
@@ -244,6 +244,9 @@ public class DownloadThread extends Thread {
     /** Flag indicating that thread must be halted */
     private volatile boolean mShutdownRequested;
 
+    /** This is initialized lazily in startDownload */
+    private HttpEngine mHttpEngine;
+
     public DownloadThread(DownloadJobService service, JobParameters params, DownloadInfo info) {
         mContext = service;
         mSystemFacade = Helpers.getSystemFacade(mContext);
@@ -256,9 +259,14 @@ public class DownloadThread extends Thread {
 
         mId = info.mId;
         mInfo = info;
+
         mInfoDelta = new DownloadInfoDelta(info);
     }
 
+    private boolean isUsingHttpEngine() {
+        return mHttpEngine != null;
+    }
+
     @Override
     public void run() {
         Process.setThreadPriority(Process.THREAD_PRIORITY_BACKGROUND);
@@ -422,7 +430,7 @@ public class DownloadThread extends Thread {
             if ((!cleartextTrafficPermitted) && ("http".equalsIgnoreCase(url.getProtocol()))) {
                 throw new StopRequestException(STATUS_BAD_REQUEST,
                         "Cleartext traffic not permitted for package " + mInfo.mPackage + ": "
-                        + Uri.parse(url.toString()).toSafeString());
+                                + Uri.parse(url.toString()).toSafeString());
             }
 
             // Open connection and follow any redirects until we have a useful
@@ -432,14 +440,29 @@ public class DownloadThread extends Thread {
                 // Check that the caller is allowed to make network connections. If so, make one on
                 // their behalf to open the url.
                 checkConnectivity();
-                conn = (HttpURLConnection) mNetwork.openConnection(url);
+                if (downloadViaPlatformHttpEngine() && !mSystemFacade.hasPerDomainConfig(
+                        mInfo.mPackage)) {
+                    // Disable HttpEngine if the caller APK has a per-domain networkConfig as this
+                    // could mean that the APK does have its own CAs / trust anchors. This is a
+                    // feature which Cronet does not support but we plan to add compatibility for
+                    // in the future.
+                    mHttpEngine = new HttpEngine.Builder(mContext).build();
+                    logDebug("HttpEngine is being used for this download");
+                    mHttpEngine.bindToNetwork(mNetwork);
+                    conn = (HttpURLConnection) mHttpEngine.openConnection(url);
+                } else {
+                    // HttpEngine does not support setConnectTimeout on its HttpUrlConnection
+                    // implementation. The default timeout in HttpEngine is 4 minutes which is much
+                    // longer than what's defined here but that should not be a problem.
+                    conn = (HttpURLConnection) mNetwork.openConnection(url);
+                    conn.setConnectTimeout(DEFAULT_TIMEOUT);
+                }
                 conn.setInstanceFollowRedirects(false);
-                conn.setConnectTimeout(DEFAULT_TIMEOUT);
                 conn.setReadTimeout(DEFAULT_TIMEOUT);
                 // If this is going over HTTPS configure the trust to be the same as the calling
                 // package.
                 if (conn instanceof HttpsURLConnection) {
-                    ((HttpsURLConnection)conn).setSSLSocketFactory(appContext.getSocketFactory());
+                    ((HttpsURLConnection) conn).setSSLSocketFactory(appContext.getSocketFactory());
                 }
 
                 addRequestHeaders(conn, resuming);
@@ -827,9 +850,16 @@ public class DownloadThread extends Thread {
             conn.addRequestProperty("User-Agent", mInfo.getUserAgent());
         }
 
-        // Defeat transparent gzip compression, since it doesn't allow us to
-        // easily resume partial downloads.
-        conn.setRequestProperty("Accept-Encoding", "identity");
+        // It's fine to use HttpEngine with a compression algorithm since the default behaviour
+        // of DownloadManager is to always download via plaintext. Using a compression algorithm
+        // with decoding on the fly will greatly reduce the downloaded bytes.
+        // HttpEngine will automatically default to using identity if it's trying to do a partial
+        // download (resumption of previous download).
+        if (!isUsingHttpEngine()) {
+            // Defeat transparent gzip compression, since it doesn't allow us to
+            // easily resume partial downloads.
+            conn.setRequestProperty("Accept-Encoding", "identity");
+        }
 
         // Defeat connection reuse, since otherwise servers may continue
         // streaming large downloads after cancelled.
diff --git a/src/com/android/providers/downloads/RealSystemFacade.java b/src/com/android/providers/downloads/RealSystemFacade.java
index ba4068e4..71a68a30 100644
--- a/src/com/android/providers/downloads/RealSystemFacade.java
+++ b/src/com/android/providers/downloads/RealSystemFacade.java
@@ -100,7 +100,7 @@ class RealSystemFacade implements SystemFacade {
             return SSLContext.getDefault();
         }
         SSLContext ctx = SSLContext.getInstance("TLS");
-        ctx.init(null, new TrustManager[] {appConfig.getTrustManager()}, null);
+        ctx.init(null, new TrustManager[]{appConfig.getTrustManager()}, null);
         return ctx;
     }
 
@@ -118,4 +118,21 @@ class RealSystemFacade implements SystemFacade {
         }
         return appConfig.isCleartextTrafficPermitted(host);
     }
+
+    /**
+     * Returns whether the provided package has per-domain configuration through its
+     * network_security_config.xml. If the package is not found then true is returned
+     * by default.
+     * {@code packageName}.
+     */
+    @Override
+    public boolean hasPerDomainConfig(String packageName) {
+        try {
+            return NetworkSecurityPolicy.getApplicationConfigForPackage(mContext,
+                    packageName).hasPerDomainConfigs();
+        } catch (NameNotFoundException e) {
+            // Unknown package -- fail for safety
+            return true;
+        }
+    }
 }
diff --git a/src/com/android/providers/downloads/SystemFacade.java b/src/com/android/providers/downloads/SystemFacade.java
index 1fda858b..2fd80cf8 100644
--- a/src/com/android/providers/downloads/SystemFacade.java
+++ b/src/com/android/providers/downloads/SystemFacade.java
@@ -78,4 +78,11 @@ interface SystemFacade {
      */
     public SSLContext getSSLContextForPackage(Context context, String pckg)
             throws GeneralSecurityException;
+
+    /**
+     * Returns whether the provided {@code packageName} has per-domain configuration through its
+     * network_security_config.xml. If the {@code packageName} is not found or an exception
+     * is thrown then {@code true} is returned.
+     */
+    public boolean hasPerDomainConfig(String packageName);
 }
diff --git a/tests/Android.bp b/tests/Android.bp
index 554cbb90..bc045edd 100644
--- a/tests/Android.bp
+++ b/tests/Android.bp
@@ -32,10 +32,14 @@ android_test {
     ],
 
     static_libs: [
+        "androidx.test.ext.junit",
+        "junit",
         "androidx.core_core",
         "androidx.test.rules",
         "mockito-target",
         "mockwebserver",
+        "flag-junit",
+        "com.android.providers.downloads.flags-aconfig-java",
     ],
 
     platform_apis: true,
diff --git a/tests/src/com/android/providers/downloads/DownloadProviderFunctionalTest.java b/tests/src/com/android/providers/downloads/DownloadProviderFunctionalTest.java
index 5dfe19aa..3944963f 100644
--- a/tests/src/com/android/providers/downloads/DownloadProviderFunctionalTest.java
+++ b/tests/src/com/android/providers/downloads/DownloadProviderFunctionalTest.java
@@ -27,13 +27,23 @@ import android.net.ConnectivityManager;
 import android.net.Uri;
 import android.os.Environment;
 import android.os.SystemClock;
+import android.platform.test.annotations.EnableFlags;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.SetFlagsRule;
 import android.provider.Downloads;
 
 import androidx.test.filters.LargeTest;
 
+import com.android.providers.downloads.flags.Flags;
+
 import com.google.mockwebserver.MockWebServer;
 import com.google.mockwebserver.RecordedRequest;
 
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+
 import java.io.InputStream;
 import java.net.MalformedURLException;
 import java.net.UnknownHostException;
@@ -46,15 +56,30 @@ import java.util.concurrent.TimeoutException;
  * device to serve downloads.
  */
 @LargeTest
+@EnableFlags({Flags.FLAG_DOWNLOAD_VIA_PLATFORM_HTTP_ENGINE})
 public class DownloadProviderFunctionalTest extends AbstractDownloadProviderFunctionalTest {
     private static final String TAG = "DownloadManagerFunctionalTest";
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
 
     public DownloadProviderFunctionalTest() {
         super(new FakeSystemFacade());
     }
 
+    @Before
+    public void setupTest() throws Exception {
+        super.setUp();
+    }
+
+    @After
+    public void tearDownTest() throws Exception {
+        super.tearDown();
+    }
+
+    @Test
     public void testDownloadTextFile() throws Exception {
-        enqueueResponse(buildResponse(HTTP_OK, FILE_CONTENT));
+        enqueueResponse(
+                buildResponse(HTTP_OK, FILE_CONTENT));
 
         String path = "/download_manager_test_path";
         Uri downloadUri = requestDownload(path);
@@ -66,21 +91,23 @@ public class DownloadProviderFunctionalTest extends AbstractDownloadProviderFunc
         assertEquals(path, request.getPath());
         assertEquals(FILE_CONTENT, getDownloadContents(downloadUri));
         assertStartsWith(Environment.getExternalStorageDirectory().getPath(),
-                         getDownloadFilename(downloadUri));
+                getDownloadFilename(downloadUri));
     }
 
+    @Test
     public void testDownloadToCache() throws Exception {
         enqueueResponse(buildResponse(HTTP_OK, FILE_CONTENT));
 
         Uri downloadUri = requestDownload("/path");
         updateDownload(downloadUri, Downloads.Impl.COLUMN_DESTINATION,
-                       Integer.toString(Downloads.Impl.DESTINATION_CACHE_PARTITION));
+                Integer.toString(Downloads.Impl.DESTINATION_CACHE_PARTITION));
         runUntilStatus(downloadUri, Downloads.Impl.STATUS_SUCCESS);
         assertEquals(FILE_CONTENT, getDownloadContents(downloadUri));
         assertStartsWith(getContext().getCacheDir().getCanonicalPath(),
-                         getDownloadFilename(downloadUri));
+                getDownloadFilename(downloadUri));
     }
 
+    @Test
     public void testRoaming() throws Exception {
         enqueueResponse(buildResponse(HTTP_OK, FILE_CONTENT));
         enqueueResponse(buildResponse(HTTP_OK, FILE_CONTENT));
@@ -95,7 +122,7 @@ public class DownloadProviderFunctionalTest extends AbstractDownloadProviderFunc
         // when roaming is disallowed, the download should pause...
         downloadUri = requestDownload("/path");
         updateDownload(downloadUri, Downloads.Impl.COLUMN_DESTINATION,
-                       Integer.toString(Downloads.Impl.DESTINATION_CACHE_PARTITION_NOROAMING));
+                Integer.toString(Downloads.Impl.DESTINATION_CACHE_PARTITION_NOROAMING));
         runUntilStatus(downloadUri, Downloads.Impl.STATUS_WAITING_FOR_NETWORK);
 
         // ...and pick up when we're off roaming
@@ -103,6 +130,7 @@ public class DownloadProviderFunctionalTest extends AbstractDownloadProviderFunc
         runUntilStatus(downloadUri, Downloads.Impl.STATUS_SUCCESS);
     }
 
+    @Test
     public void testCleartextTrafficPermittedFlagHonored() throws Exception {
         enqueueResponse(buildResponse(HTTP_OK, FILE_CONTENT));
         enqueueResponse(buildResponse(HTTP_OK, FILE_CONTENT));
@@ -157,7 +185,7 @@ public class DownloadProviderFunctionalTest extends AbstractDownloadProviderFunc
     }
 
     private String getDownloadField(Uri downloadUri, String column) {
-        final String[] columns = new String[] {column};
+        final String[] columns = new String[]{column};
         Cursor cursor = mResolver.query(downloadUri, columns, null, null, null);
         try {
             assertEquals(1, cursor.getCount());
diff --git a/tests/src/com/android/providers/downloads/FakeSystemFacade.java b/tests/src/com/android/providers/downloads/FakeSystemFacade.java
index fadcd369..76a0cb2b 100644
--- a/tests/src/com/android/providers/downloads/FakeSystemFacade.java
+++ b/tests/src/com/android/providers/downloads/FakeSystemFacade.java
@@ -40,6 +40,9 @@ public class FakeSystemFacade implements SystemFacade {
     List<Intent> mBroadcastsSent = new ArrayList<Intent>();
     Bundle mLastBroadcastOptions;
     boolean mCleartextTrafficPermitted = true;
+
+    boolean hasPerDomainConfig = false;
+
     private boolean mReturnActualTime = false;
     private SSLContext mSSLContext = null;
 
@@ -141,6 +144,11 @@ public class FakeSystemFacade implements SystemFacade {
         return mSSLContext;
     }
 
+    @Override
+    public boolean hasPerDomainConfig(String pckg) {
+        return hasPerDomainConfig;
+    }
+
     public void setSSLContext(SSLContext context) {
         mSSLContext = context;
     }
```

