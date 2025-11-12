```diff
diff --git a/OWNERS b/OWNERS
index 0d92786..e5a42d7 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,4 @@
 amreddy@google.com
 radhikaagrawal@google.com
 pochunlee@google.com
-apsankar@google.com
 tairuw@google.com
diff --git a/src/com/google/android/iwlan/IwlanSilentRestart.java b/src/com/google/android/iwlan/IwlanSilentRestart.java
index 04ebc91..8fa8b22 100644
--- a/src/com/google/android/iwlan/IwlanSilentRestart.java
+++ b/src/com/google/android/iwlan/IwlanSilentRestart.java
@@ -59,7 +59,7 @@ public class IwlanSilentRestart extends ContentProvider {
 
     private void clearAndExit() {
         deinitService();
-        Log.i(TAG, "Restart com.google.pixel.iwlan by killing it");
+        Log.i(TAG, "Restart com.google.android.iwlan by killing it");
         System.exit(0);
     }
 
```

