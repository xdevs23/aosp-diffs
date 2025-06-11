```diff
diff --git a/Android.bp b/Android.bp
index f4d5095..b25791b 100644
--- a/Android.bp
+++ b/Android.bp
@@ -90,7 +90,6 @@ cc_library_headers {
     host_supported: true,
     apex_available: [
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
         "//apex_available:platform",
         "com.android.ondevicepersonalization",
     ],
diff --git a/OWNERS b/OWNERS
index e77f139..8888d2c 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,4 @@
 miaowang@google.com
 timmurray@google.com
 ianhua@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

