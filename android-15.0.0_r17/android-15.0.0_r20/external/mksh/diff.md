```diff
diff --git a/Android.bp b/Android.bp
index ca930d0..5d8cd4f 100644
--- a/Android.bp
+++ b/Android.bp
@@ -145,10 +145,16 @@ cc_defaults {
 cc_binary {
     name: "sh",
     defaults: ["sh-defaults"],
-    recovery_available: true,
     vendor_ramdisk_available: true,
 }
 
+cc_binary {
+    name: "sh.recovery",
+    defaults: ["sh-defaults"],
+    recovery: true,
+    stem: "sh",
+}
+
 cc_binary {
     name: "sh_vendor",
     defaults: ["sh-defaults"],
```

