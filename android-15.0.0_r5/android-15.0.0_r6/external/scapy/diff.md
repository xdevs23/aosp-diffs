```diff
diff --git a/Android.bp b/Android.bp
index 6756b4a..d157228 100644
--- a/Android.bp
+++ b/Android.bp
@@ -34,6 +34,7 @@ license {
 python_library {
     name: "scapy",
     srcs: [
-       "scapy/**/*.py",
+        "scapy/**/*.py",
     ],
+    host_supported: true,
 }
```

