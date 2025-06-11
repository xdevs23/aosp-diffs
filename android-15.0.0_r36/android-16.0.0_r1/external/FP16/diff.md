```diff
diff --git a/Android.bp b/Android.bp
index ee98f6f..3471d5a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -39,7 +39,6 @@ cc_library_headers {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "test_com.android.neuralnetworks",
         "com.android.extservices",
         "com.android.adservices",
         "com.android.ondevicepersonalization",
diff --git a/OWNERS b/OWNERS
index 196fe51..dc0d96b 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 include platform/packages/modules/NeuralNetworks:/NNAPI_OWNERS
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
```

