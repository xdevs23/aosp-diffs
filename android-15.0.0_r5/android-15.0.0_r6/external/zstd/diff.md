```diff
diff --git a/Android.bp b/Android.bp
index b51d11ed..a8913ed9 100644
--- a/Android.bp
+++ b/Android.bp
@@ -54,6 +54,7 @@ cc_library {
     visibility: [
         "//art:__subpackages__",
         "//bootable/recovery:__subpackages__",
+        "//cts/tests/tests/simpleperf:__subpackages__",
         "//device/google/contexthub/util/nanoapp_postprocess:__subpackages__",
         "//external/bcc/libbpf-tools:__subpackages__",
         "//external/bpftool:__subpackages__",
@@ -70,6 +71,7 @@ cc_library {
         "//system/core/init:__subpackages__",
         "//system/core/fastboot:__subpackages__",
         "//system/extras/partition_tools:__subpackages__",
+        "//system/extras/simpleperf:__subpackages__",
         "//system/unwinding/libunwindstack:__subpackages__",
     ],
     product_available: true,
```

