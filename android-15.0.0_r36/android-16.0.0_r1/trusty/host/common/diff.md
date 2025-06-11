```diff
diff --git a/scripts/metrics_atoms_protoc_plugin/Android.bp b/scripts/metrics_atoms_protoc_plugin/Android.bp
index 9ef1775..6934cec 100644
--- a/scripts/metrics_atoms_protoc_plugin/Android.bp
+++ b/scripts/metrics_atoms_protoc_plugin/Android.bp
@@ -24,11 +24,6 @@ python_binary_host {
         "templates_package/templates/metrics_atoms.c.j2",
         "templates_package/templates/metrics_atoms.h.j2",
     ],
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
     libs: [
         "libprotobuf-python",
         "py-jinja",
diff --git a/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py b/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
index dc12fa2..c68de7d 100644
--- a/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
+++ b/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
@@ -22,6 +22,7 @@ initramfs image, and repacks the ramdisk.
 
 import argparse
 import enum
+import itertools
 import logging
 import os
 import pathlib
@@ -34,6 +35,13 @@ logger = logging.getLogger(__name__)
 _ANDROID_RAMDISK_DIR = "android_ramdisk"
 _KERNEL_RAMDISK_DIR = "kernel_ramdisk"
 
+_KNOWN_MODULES_FILES = [
+    "modules.alias",
+    "modules.dep",
+    "modules.softdep",
+    "modules.devname",
+]
+
 def _parse_args():
     """Parse command-line options."""
     parser = argparse.ArgumentParser(
@@ -53,6 +61,19 @@ def _parse_args():
         '--output-ramdisk',
         help='filename of repacked ramdisk',
         required=True)
+    parser.add_argument(
+        '--override-modules-load',
+        help='replace the modules.load file in ramdisk with an override',
+        required=False)
+    parser.add_argument(
+        '--check-modules-order',
+        action='store_true',
+        help='check all the modules.order.* files and '
+             'discard modules not found in them')
+    parser.add_argument(
+        '--extra-modules-order',
+        action='append',
+        help='names of additional modules.order.* files to check')
 
     return parser.parse_args()
 
@@ -166,10 +187,48 @@ class RamdiskImage:
                 modules_file.write(f"{module}\n")
 
 
-def _replace_modules(dest_ramdisk, src_ramdisk):
+def _load_modules_order(src_dir, extra_modules_order):
+    # Concatenate all the modules.order.* files because out-of-tree
+    # modules get their own order file separate from the one for
+    # the kernel build
+    full_modules_order = set()
+    for (dir_path, subdirs, files) in os.walk(src_dir):
+        for file in files:
+            if file == "modules.order" or file in extra_modules_order:
+                modules_order_path = os.path.join(dir_path, file)
+                with open(modules_order_path, "r", encoding="utf-8") as modules_order:
+                    for line in modules_order:
+                        full_modules_order.add(line.strip())
+
+    return full_modules_order
+
+
+def _replace_modules(dest_ramdisk, src_ramdisk, override_modules_load,
+                     check_modules_order, extra_modules_order):
     """Replace any modules in dest_ramdisk with modules from src_ramdisk"""
     src_dir = pathlib.Path(src_ramdisk.ramdisk_dir)
     dest_dir = os.path.join(dest_ramdisk.ramdisk_dir, "lib/modules")
+
+    # Replace the modules.load file with a new one if the caller gave it
+    if override_modules_load:
+        dest_modules_load = os.path.join(dest_dir, "modules.load")
+        shutil.copy(override_modules_load, dest_modules_load)
+
+        # Update the dependency and alias files as well
+        for (dir_path, subdirs, files) in os.walk(src_dir):
+            for file in files:
+                if file == "modules.load":
+                    raise RuntimeError(
+                        "Unexpected modules.load in kernel build")
+
+                if file in _KNOWN_MODULES_FILES:
+                    src_file = os.path.join(dir_path, file)
+                    dest_file = os.path.join(dest_dir, file)
+                    shutil.copy(src_file, dest_file)
+
+    if check_modules_order:
+        modules_order = _load_modules_order(src_dir, extra_modules_order)
+
     updated_modules = []
     for module in dest_ramdisk.get_modules():
         dest_module = os.path.join(dest_dir, module)
@@ -177,12 +236,29 @@ def _replace_modules(dest_ramdisk, src_ramdisk):
         if len(matches) > 1:
             raise RuntimeError(
                 f"Found multiple candidates for module {module}")
+
+        # Ramdisks produced by Android have all the modules under /lib/modules
+        dest_base_module = os.path.join(dest_dir, os.path.basename(module))
+        if os.path.exists(dest_base_module):
+            os.remove(dest_base_module)
+
         if len(matches) == 0:
             logger.warning(
                 "Could not find module %s, deleting this module.",
                 module)
-            os.remove(dest_module)
+            if os.path.exists(dest_module):
+                os.remove(dest_module)
             continue
+
+        if check_modules_order and module not in modules_order:
+            logger.warning(
+                "Module %s not in modules.order, deleting this module.",
+                module)
+            if os.path.exists(dest_module):
+                os.remove(dest_module)
+            continue
+
+        os.makedirs(os.path.dirname(dest_module), exist_ok=True)
         shutil.copy(matches[0], dest_module)
         updated_modules.append(module)
 
@@ -203,7 +279,8 @@ def main():
         kernel_ramdisk = RamdiskImage(
             args.kernel_ramdisk, os.path.join(tempdir, _KERNEL_RAMDISK_DIR),
             allow_dir=True)
-        _replace_modules(android_ramdisk, kernel_ramdisk)
+        _replace_modules(android_ramdisk, kernel_ramdisk, args.override_modules_load,
+                         args.check_modules_order, args.extra_modules_order)
         android_ramdisk.repack(args.output_ramdisk)
 
 
```

