```diff
diff --git a/Android.bp b/Android.bp
index 307a17e..12c5f6a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -44,7 +44,7 @@ cc_library_static {
     ],
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.ondevicepersonalization",
     ],
 }
diff --git a/OWNERS b/OWNERS
index 011f513..95e7cbf 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 miaowang@google.com
-qiaoli@google.com
\ No newline at end of file
+qiaoli@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

