```diff
diff --git a/boringssl/Android.bp b/boringssl/Android.bp
index deddd25..52ad27c 100644
--- a/boringssl/Android.bp
+++ b/boringssl/Android.bp
@@ -52,6 +52,8 @@ rust_test {
         "libauthgraph_core_test",
         "libhex",
     ],
+    // Needed for the vendor test variant
+    require_root: true,
     test_options: {
         unit_test: true,
     },
```

