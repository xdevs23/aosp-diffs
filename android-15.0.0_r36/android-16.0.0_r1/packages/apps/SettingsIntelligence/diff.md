```diff
diff --git a/src/com/android/settings/intelligence/search/query/InstalledAppResultTask.java b/src/com/android/settings/intelligence/search/query/InstalledAppResultTask.java
index 6d9060e..7a14748 100644
--- a/src/com/android/settings/intelligence/search/query/InstalledAppResultTask.java
+++ b/src/com/android/settings/intelligence/search/query/InstalledAppResultTask.java
@@ -21,6 +21,7 @@ import static com.android.settings.intelligence.search.sitemap.HighlightableMenu
 import android.content.Context;
 import android.content.Intent;
 import android.content.pm.ApplicationInfo;
+import android.content.pm.ModuleInfo;
 import android.content.pm.PackageManager;
 import android.net.Uri;
 import android.provider.Settings;
@@ -82,6 +83,17 @@ public class InstalledAppResultTask extends SearchQueryTask.QueryWorker {
                 // Disabled by something other than user, skip.
                 continue;
             }
+            try {
+                ModuleInfo moduleInfo = mPackageManager.getModuleInfo(info.packageName, 0);
+                if(moduleInfo.isHidden()) {
+                    // The app is hidden, skip
+                    continue;
+                }
+            } catch (PackageManager.NameNotFoundException e) {
+                // this should not happen here
+                continue;
+            }
+
             final CharSequence label = info.loadLabel(mPackageManager);
             final int wordDiff = SearchQueryUtils.getWordDifference(label.toString(), mQuery);
             if (wordDiff == SearchQueryUtils.NAME_NO_MATCH) {
```

