```diff
diff --git a/tests/src/com/android/providers/downloads/HelpersTest.java b/tests/src/com/android/providers/downloads/HelpersTest.java
index 6becb1db..ac15a095 100644
--- a/tests/src/com/android/providers/downloads/HelpersTest.java
+++ b/tests/src/com/android/providers/downloads/HelpersTest.java
@@ -44,6 +44,7 @@ import android.net.Uri;
 import android.os.Binder;
 import android.os.Environment;
 import android.os.Process;
+import android.os.UserHandle;
 import android.provider.Downloads;
 import android.test.AndroidTestCase;
 import android.util.LongArray;
@@ -53,6 +54,7 @@ import androidx.test.filters.SmallTest;
 
 import java.io.File;
 import java.util.Arrays;
+import java.util.Locale;
 import java.util.regex.Matcher;
 import java.util.regex.Pattern;
 
@@ -176,62 +178,98 @@ public class HelpersTest extends AndroidTestCase {
     public void testCheckDestinationFilePathRestrictions_noPermission() throws Exception {
         // Downloading to our own private app directory should always be allowed, even for
         // permission-less app
-        checkDestinationFilePathRestrictions_noPermission(
-                "/storage/emulated/0/Android/data/DownloadManagerHelpersTest/test",
+        checkDestinationFilePathRestrictions_noPermission(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Android/data/DownloadManagerHelpersTest/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ false);
-        checkDestinationFilePathRestrictions_noPermission(
-                "/storage/emulated/0/Android/data/DownloadManagerHelpersTest/test",
+        checkDestinationFilePathRestrictions_noPermission(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Android/data/DownloadManagerHelpersTest/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ true);
-        checkDestinationFilePathRestrictions_noPermission(
-                "/storage/emulated/0/Android/obb/DownloadManagerHelpersTest/test",
+        checkDestinationFilePathRestrictions_noPermission(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Android/obb/DownloadManagerHelpersTest/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ false);
-        checkDestinationFilePathRestrictions_noPermission(
-                "/storage/emulated/0/Android/obb/DownloadManagerHelpersTest/test",
+        checkDestinationFilePathRestrictions_noPermission(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Android/obb/DownloadManagerHelpersTest/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ true);
-        checkDestinationFilePathRestrictions_noPermission(
-                "/storage/emulated/0/Android/media/DownloadManagerHelpersTest/test",
+        checkDestinationFilePathRestrictions_noPermission(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Android/media/DownloadManagerHelpersTest/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ false);
-        checkDestinationFilePathRestrictions_noPermission(
-                "/storage/emulated/0/Android/media/DownloadManagerHelpersTest/test",
+        checkDestinationFilePathRestrictions_noPermission(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Android/media/DownloadManagerHelpersTest/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ true);
 
         // All apps can write to Environment.STANDARD_DIRECTORIES
-        checkDestinationFilePathRestrictions_noPermission("/storage/emulated/0/Pictures/test",
+        checkDestinationFilePathRestrictions_noPermission(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Pictures/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ false);
-        checkDestinationFilePathRestrictions_noPermission("/storage/emulated/0/Download/test",
+        checkDestinationFilePathRestrictions_noPermission(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Download/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ false);
-        checkDestinationFilePathRestrictions_noPermission("/storage/emulated/0/Pictures/test",
+        checkDestinationFilePathRestrictions_noPermission(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Pictures/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ true);
-        checkDestinationFilePathRestrictions_noPermission("/storage/emulated/0/Download/test",
+        checkDestinationFilePathRestrictions_noPermission(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Download/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ true);
 
         // Apps can never access other app's private directories (Android/data, Android/obb) paths
         // (unless they are installers in which case they can access Android/obb paths)
         try {
-            checkDestinationFilePathRestrictions_noPermission(
-                    "/storage/emulated/0/Android/data/foo/test", /* isLegacyMode */ false);
+            checkDestinationFilePathRestrictions_noPermission(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/data/foo/test",
+                            UserHandle.myUserId()),
+                    /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot access other app's private packages");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_noPermission(
-                    "/storage/emulated/0/Android/data/foo/test", /* isLegacyMode */ true);
+            checkDestinationFilePathRestrictions_noPermission(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/data/foo/test",
+                            UserHandle.myUserId()),
+                    /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot access other app's private packages"
                     + " even in legacy mode");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_noPermission(
-                    "/storage/emulated/0/Android/obb/foo/test", /* isLegacyMode */ false);
+            checkDestinationFilePathRestrictions_noPermission(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/data/foo/test",
+                            UserHandle.myUserId()),
+                    /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot access other app's private packages");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_noPermission(
-                    "/storage/emulated/0/Android/obb/foo/test", /* isLegacyMode */ true);
+            checkDestinationFilePathRestrictions_noPermission(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/obb/foo/test",
+                            UserHandle.myUserId()),
+                    /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot access other app's private packages"
                     + " even in legacy mode");
         } catch (SecurityException expected) {
@@ -239,22 +277,31 @@ public class HelpersTest extends AndroidTestCase {
 
         // Non-legacy apps can never access Android/ or Android/media dirs for other packages.
         try {
-            checkDestinationFilePathRestrictions_noPermission("/storage/emulated/0/Android/",
+            checkDestinationFilePathRestrictions_noPermission(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/",
+                            UserHandle.myUserId()),
                     /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot write to Android dir");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_noPermission(
-                    "/storage/emulated/0/Android/media/", /* isLegacyMode */ false);
+            checkDestinationFilePathRestrictions_noPermission(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/media/",
+                            UserHandle.myUserId()),
+                    /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot write to Android dir");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_noPermission(
-                    "/storage/emulated/0/Android/media/foo", /* isLegacyMode */ false);
+            checkDestinationFilePathRestrictions_noPermission(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/media/foo",
+                            UserHandle.myUserId()),
+                    /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot write to Android dir");
         } catch (SecurityException expected) {
         }
@@ -262,7 +309,10 @@ public class HelpersTest extends AndroidTestCase {
         // Legacy apps require WRITE_EXTERNAL_STORAGE permission to access Android/ or Android/media
         // dirs.
         try {
-            checkDestinationFilePathRestrictions_noPermission("/storage/emulated/0/Android/",
+            checkDestinationFilePathRestrictions_noPermission(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/",
+                            UserHandle.myUserId()),
                     /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot write to Android/ as it does not"
                     + " have WRITE_EXTERNAL_STORAGE permission");
@@ -270,16 +320,22 @@ public class HelpersTest extends AndroidTestCase {
         }
 
         try {
-            checkDestinationFilePathRestrictions_noPermission(
-                    "/storage/emulated/0/Android/media/", /* isLegacyMode */ true);
+            checkDestinationFilePathRestrictions_noPermission(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/media/",
+                            UserHandle.myUserId()),
+                    /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot write to Android/ as it does not"
                     + " have WRITE_EXTERNAL_STORAGE permission");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_noPermission(
-                    "/storage/emulated/0/Android/media/foo", /* isLegacyMode */ true);
+            checkDestinationFilePathRestrictions_noPermission(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/media/foo",
+                            UserHandle.myUserId()),
+                    /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot write to Android/media as it does not"
                     + " have WRITE_EXTERNAL_STORAGE permission");
         } catch (SecurityException expected) {
@@ -288,22 +344,38 @@ public class HelpersTest extends AndroidTestCase {
 
     public void testCheckDestinationFilePathRestrictions_installer() throws Exception {
         // Downloading to other obb dirs should be allowed as installer
-        checkDestinationFilePathRestrictions_installer("/storage/emulated/0/Android/obb/foo/test",
+        checkDestinationFilePathRestrictions_installer(
+                String.format(
+                    Locale.ROOT,
+                    "/storage/emulated/%d/Android/obb/foo/test",
+                    UserHandle.myUserId()),
                 /* isLegacyMode */ false);
-        checkDestinationFilePathRestrictions_installer("/storage/emulated/0/Android/obb/foo/test",
+        checkDestinationFilePathRestrictions_installer(
+                String.format(
+                    Locale.ROOT,
+                    "/storage/emulated/%d/Android/obb/foo/test",
+                    UserHandle.myUserId()),
                 /* isLegacyMode */ true);
 
         // Installer apps can not access other app's Android/data private dirs
         try {
             checkDestinationFilePathRestrictions_installer(
-                    "/storage/emulated/0/Android/data/foo/test", /* isLegacyMode */ false);
+                String.format(
+                    Locale.ROOT,
+                    "/storage/emulated/%d/Android/data/foo/test",
+                    UserHandle.myUserId()),
+                /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot access other app's private packages");
         } catch (SecurityException expected) {
         }
 
         try {
             checkDestinationFilePathRestrictions_installer(
-                    "/storage/emulated/0/Android/data/foo/test", /* isLegacyMode */ true);
+                String.format(
+                    Locale.ROOT,
+                    "/storage/emulated/%d/Android/data/foo/test",
+                    UserHandle.myUserId()),
+                /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot access other app's private packages"
                     + " even in legacy mode");
         } catch (SecurityException expected) {
@@ -311,22 +383,34 @@ public class HelpersTest extends AndroidTestCase {
 
         // Non-legacy apps can never access Android/ or Android/media dirs for other packages.
         try {
-            checkDestinationFilePathRestrictions_installer("/storage/emulated/0/Android/",
-                    /* isLegacyMode */ false);
+            checkDestinationFilePathRestrictions_installer(
+                String.format(
+                    Locale.ROOT,
+                    "/storage/emulated/%d/Android/",
+                    UserHandle.myUserId()),
+                /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot write to Android dir");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_installer("/storage/emulated/0/Android/media/",
-                    /* isLegacyMode */ false);
+            checkDestinationFilePathRestrictions_installer(
+                String.format(
+                    Locale.ROOT,
+                    "/storage/emulated/%d/Android/media/",
+                    UserHandle.myUserId()),
+                /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot write to Android dir");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_installer("/storage/emulated/0/Android/media/foo",
-                    /* isLegacyMode */ false);
+            checkDestinationFilePathRestrictions_installer(
+                String.format(
+                    Locale.ROOT,
+                    "/storage/emulated/%d/Android/media/foo",
+                    UserHandle.myUserId()),
+                /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot write to Android dir");
         } catch (SecurityException expected) {
         }
@@ -334,24 +418,36 @@ public class HelpersTest extends AndroidTestCase {
         // Legacy apps require WRITE_EXTERNAL_STORAGE permission to access Android/ or Android/media
         // dirs.
         try {
-            checkDestinationFilePathRestrictions_installer("/storage/emulated/0/Android/",
-                    /* isLegacyMode */ true);
+            checkDestinationFilePathRestrictions_installer(
+                String.format(
+                    Locale.ROOT,
+                    "/storage/emulated/%d/Android/",
+                    UserHandle.myUserId()),
+                /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot write to Android/ as it does not"
                     + " have WRITE_EXTERNAL_STORAGE permission");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_installer("/storage/emulated/0/Android/media/",
-                    /* isLegacyMode */ true);
+            checkDestinationFilePathRestrictions_installer(
+                String.format(
+                    Locale.ROOT,
+                    "/storage/emulated/%d/Android/media/",
+                    UserHandle.myUserId()),
+                /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot write to Android/ as it does not"
                     + " have WRITE_EXTERNAL_STORAGE permission");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_installer("/storage/emulated/0/Android/media/foo",
-                    /* isLegacyMode */ true);
+            checkDestinationFilePathRestrictions_installer(
+                  String.format(
+                    Locale.ROOT,
+                    "/storage/emulated/%d/Android/media/foo",
+                    UserHandle.myUserId()),
+                  /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot write to Android/media as it does not"
                     + " have WRITE_EXTERNAL_STORAGE permission");
         } catch (SecurityException expected) {
@@ -362,14 +458,20 @@ public class HelpersTest extends AndroidTestCase {
         // Apps with WRITE_EXTERNAL_STORAGE can not access other app's private dirs
         // (Android/data and Android/obb paths)
         try {
-            checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Android/data/foo/test",
+            checkDestinationFilePathRestrictions_WES(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/data/foo/test",
+                            UserHandle.myUserId()),
                     /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot access other app's private packages");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Android/data/foo/test",
+            checkDestinationFilePathRestrictions_WES(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/data/foo/test",
+                            UserHandle.myUserId()),
                     /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot access other app's private packages"
                     + " even in legacy mode");
@@ -377,14 +479,20 @@ public class HelpersTest extends AndroidTestCase {
         }
 
         try {
-            checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Android/obb/foo/test",
+            checkDestinationFilePathRestrictions_WES(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/obb/foo/test",
+                            UserHandle.myUserId()),
                     /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot access other app's private packages");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Android/obb/foo/test",
+            checkDestinationFilePathRestrictions_WES(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/obb/foo/test",
+                            UserHandle.myUserId()),
                     /* isLegacyMode */ true);
             fail("Expected SecurityException as caller cannot access other app's private packages"
                     + " even in legacy mode");
@@ -393,21 +501,30 @@ public class HelpersTest extends AndroidTestCase {
 
         // Non-legacy apps can never access Android/ or Android/media dirs for other packages.
         try {
-            checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Android/",
+            checkDestinationFilePathRestrictions_WES(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/",
+                            UserHandle.myUserId()),
                     /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot write to Android dir");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Android/media/",
+            checkDestinationFilePathRestrictions_WES(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/media/",
+                            UserHandle.myUserId()),
                     /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot write to Android dir");
         } catch (SecurityException expected) {
         }
 
         try {
-            checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Android/media/foo",
+            checkDestinationFilePathRestrictions_WES(String.format(
+                            Locale.ROOT,
+                            "/storage/emulated/%d/Android/media/foo",
+                            UserHandle.myUserId()),
                     /* isLegacyMode */ false);
             fail("Expected SecurityException as caller cannot write to Android dir");
         } catch (SecurityException expected) {
@@ -415,15 +532,30 @@ public class HelpersTest extends AndroidTestCase {
 
         // Legacy apps with WRITE_EXTERNAL_STORAGE can access shared storage file path including
         // Android/ and Android/media dirs
-        checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Pictures/test",
+        checkDestinationFilePathRestrictions_WES(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Pictures/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ true);
-        checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Download/test",
+        checkDestinationFilePathRestrictions_WES(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Download/test",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ true);
-        checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Android/",
+        checkDestinationFilePathRestrictions_WES(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Android/",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ true);
-        checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Android/media/",
+        checkDestinationFilePathRestrictions_WES(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Android/media/",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ true);
-        checkDestinationFilePathRestrictions_WES("/storage/emulated/0/Android/media/foo",
+        checkDestinationFilePathRestrictions_WES(String.format(
+                        Locale.ROOT,
+                        "/storage/emulated/%d/Android/media/foo",
+                        UserHandle.myUserId()),
                 /* isLegacyMode */ true);
     }
 
diff --git a/tests/src/com/android/providers/downloads/PublicApiFunctionalTest.java b/tests/src/com/android/providers/downloads/PublicApiFunctionalTest.java
index 1e4452a6..9d62c319 100644
--- a/tests/src/com/android/providers/downloads/PublicApiFunctionalTest.java
+++ b/tests/src/com/android/providers/downloads/PublicApiFunctionalTest.java
@@ -20,9 +20,9 @@ import static android.app.DownloadManager.STATUS_FAILED;
 import static android.app.DownloadManager.STATUS_PAUSED;
 import static android.text.format.DateUtils.SECOND_IN_MILLIS;
 
-import static org.mockito.Matchers.anyInt;
-import static org.mockito.Matchers.anyString;
-import static org.mockito.Matchers.isA;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.isA;
 import static org.mockito.Mockito.atLeastOnce;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
```

