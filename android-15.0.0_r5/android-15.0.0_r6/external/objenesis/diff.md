```diff
diff --git a/tck-android/Android.bp b/tck-android/Android.bp
index 3e75810..7b95535 100644
--- a/tck-android/Android.bp
+++ b/tck-android/Android.bp
@@ -39,6 +39,6 @@ android_test {
         "junit",
         "androidx.test.rules",
     ],
-    libs: ["android.test.base"],
+    libs: ["android.test.base.stubs"],
     srcs: ["src/main/java/**/*.java"],
 }
```

