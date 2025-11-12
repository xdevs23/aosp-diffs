```diff
diff --git a/Android.bp b/Android.bp
index 667d9c1..28d5d60 100644
--- a/Android.bp
+++ b/Android.bp
@@ -186,7 +186,6 @@ cc_test {
     ],
     static_libs: [
         "federated-compute-cc-proto-lite",
-        "libabsl",
         "libbase_ndk",
         "libgmock",
         "liblog",
```

