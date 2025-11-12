```diff
diff --git a/Android.bp b/Android.bp
index 91be187..76cd24a 100644
--- a/Android.bp
+++ b/Android.bp
@@ -169,6 +169,7 @@ cc_library_static {
 cc_library_static {
     name: "libopen_dice_clear_memory",
     defaults: ["cc_baremetal_defaults"],
+    host_supported: true,
     srcs: ["src/clear_memory.c"],
     header_libs: ["libopen_dice_headers"],
     visibility: [
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 0f3c468..2382a1d 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -3,4 +3,3 @@ android_test_mapping_format = true
 bpfmt = true
 
 [Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
```

