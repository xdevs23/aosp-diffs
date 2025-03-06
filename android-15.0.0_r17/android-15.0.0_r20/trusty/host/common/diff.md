```diff
diff --git a/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py b/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
index c799f8f..dc12fa2 100644
--- a/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
+++ b/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
@@ -157,22 +157,36 @@ class RamdiskImage:
         with open(modules_file_path, "r", encoding="utf-8") as modules_file:
             return [line.strip() for line in modules_file]
 
+    def write_modules(self, modules):
+        """Writes the list of modules used in this ramdisk."""
+        modules_file_path = os.path.join(
+            self._ramdisk_dir, "lib/modules/modules.load")
+        with open(modules_file_path, "w", encoding="utf-8") as modules_file:
+            for module in modules:
+                modules_file.write(f"{module}\n")
+
 
 def _replace_modules(dest_ramdisk, src_ramdisk):
     """Replace any modules in dest_ramdisk with modules from src_ramdisk"""
     src_dir = pathlib.Path(src_ramdisk.ramdisk_dir)
     dest_dir = os.path.join(dest_ramdisk.ramdisk_dir, "lib/modules")
+    updated_modules = []
     for module in dest_ramdisk.get_modules():
+        dest_module = os.path.join(dest_dir, module)
         matches = list(src_dir.glob(f"**/{module}"))
         if len(matches) > 1:
             raise RuntimeError(
                 f"Found multiple candidates for module {module}")
         if len(matches) == 0:
             logger.warning(
-                "Could not find module %s, not replacing this module.",
+                "Could not find module %s, deleting this module.",
                 module)
+            os.remove(dest_module)
             continue
-        shutil.copy(matches[0], os.path.join(dest_dir, module))
+        shutil.copy(matches[0], dest_module)
+        updated_modules.append(module)
+
+    dest_ramdisk.write_modules(updated_modules)
 
 
 def main():
```

