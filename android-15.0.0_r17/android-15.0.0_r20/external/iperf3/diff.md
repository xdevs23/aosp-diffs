```diff
diff --git a/Android.bp b/Android.bp
index 7de1b67..2f9d1cb 100644
--- a/Android.bp
+++ b/Android.bp
@@ -47,6 +47,7 @@ license {
 
 cc_binary {
     name: "iperf3",
+    host_supported: true,
     srcs: [
         "src/*.c",
     ],
```

