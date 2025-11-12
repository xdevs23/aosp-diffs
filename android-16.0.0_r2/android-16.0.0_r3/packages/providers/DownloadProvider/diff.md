```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index a2398115..c900bbea 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -9,10 +9,10 @@
             ]
         },
         {
-            "name": "CtsAppTestCases",
+            "name": "CtsDownloadManagerTestCases",
             "options": [
                 {
-                    "include-filter": "android.app.cts.DownloadManagerTest"
+                    "include-filter": "android.app.cts.downloadmanager.DownloadManagerTest"
                 }
             ]
         },
diff --git a/src/com/android/providers/downloads/DownloadProvider.java b/src/com/android/providers/downloads/DownloadProvider.java
index c43e8c6d..f3f3bc31 100644
--- a/src/com/android/providers/downloads/DownloadProvider.java
+++ b/src/com/android/providers/downloads/DownloadProvider.java
@@ -87,6 +87,7 @@ import java.io.PrintWriter;
 import java.util.Arrays;
 import java.util.Iterator;
 import java.util.Map;
+import java.util.Objects;
 
 /**
  * Allows application to interact with the download manager.
@@ -723,8 +724,8 @@ public final class DownloadProvider extends ContentProvider {
 
         ContentValues filteredValues = new ContentValues();
 
-        boolean isPublicApi =
-                values.getAsBoolean(Downloads.Impl.COLUMN_IS_PUBLIC_API) == Boolean.TRUE;
+        boolean isPublicApi = Objects.equals(
+            values.getAsBoolean(Downloads.Impl.COLUMN_IS_PUBLIC_API), Boolean.TRUE);
 
         // validate the destination column
         Integer dest = values.getAsInteger(Downloads.Impl.COLUMN_DESTINATION);
```

