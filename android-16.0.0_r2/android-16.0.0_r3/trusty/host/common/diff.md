```diff
diff --git a/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py b/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
index c68de7d..1fc5e18 100644
--- a/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
+++ b/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
@@ -120,8 +120,14 @@ class RamdiskImage:
             decompression_cmd = [
                 compression_util, '-d', '-c', self._ramdisk_img]
 
-            decompressed_result = subprocess.run(
-                decompression_cmd, check=False, capture_output=True)
+            try:
+                decompressed_result = subprocess.run(
+                    decompression_cmd, check=False, capture_output=True)
+            except FileNotFoundError:
+                logger.warning(
+                    "Could not find compression tool %s, skipping.",
+                    compression_util)
+                continue
 
             if decompressed_result.returncode == 0:
                 self._ramdisk_format = compression_type
```

