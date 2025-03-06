```diff
diff --git a/Android.bp b/Android.bp
index 258a027c..cb5827ee 100644
--- a/Android.bp
+++ b/Android.bp
@@ -47,7 +47,7 @@ cc_library {
     defaults: ["libpcap_defaults"],
 
     // (Matches order in libpcap's Makefile.)
-    srcs: [     
+    srcs: [
         "bpf_dump.c",
         "bpf_filter.c",
         "bpf_image.c",
```

