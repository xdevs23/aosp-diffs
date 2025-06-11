```diff
diff --git a/Android.bp b/Android.bp
index 9f8e3ee2..5ab779a9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -99,6 +99,7 @@ cc_library {
         "-D_GNU_SOURCE",
         "-D_NL_SYSCONFDIR_LIBNL=\"\\\"/etc/libnl\\\"\"",
     ],
+    c_std: "gnu11",
 
     sanitize: {
         integer_overflow: true,
```

