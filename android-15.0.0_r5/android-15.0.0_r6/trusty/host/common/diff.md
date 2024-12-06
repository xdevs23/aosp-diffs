```diff
diff --git a/scripts/replace_ramdisk_modules/Android.bp b/scripts/replace_ramdisk_modules/Android.bp
new file mode 100644
index 0000000..7b3d19e
--- /dev/null
+++ b/scripts/replace_ramdisk_modules/Android.bp
@@ -0,0 +1,29 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//      http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+python_binary_host {
+    name: "replace_ramdisk_modules",
+    srcs: [
+        "replace_ramdisk_modules.py",
+    ],
+    required: [
+        "mkbootfs",
+        "toybox",
+    ],
+}
diff --git a/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py b/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
new file mode 100644
index 0000000..c799f8f
--- /dev/null
+++ b/scripts/replace_ramdisk_modules/replace_ramdisk_modules.py
@@ -0,0 +1,197 @@
+#!/usr/bin/env python3
+#
+# Copyright 2024, The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#     http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+
+"""Repacks the ramdisk image to add kernel modules.
+
+Unpacks a ramdisk image, extracts and replaces kernel modules from another
+initramfs image, and repacks the ramdisk.
+"""
+
+import argparse
+import enum
+import logging
+import os
+import pathlib
+import shutil
+import subprocess
+import tempfile
+
+logger = logging.getLogger(__name__)
+
+_ANDROID_RAMDISK_DIR = "android_ramdisk"
+_KERNEL_RAMDISK_DIR = "kernel_ramdisk"
+
+def _parse_args():
+    """Parse command-line options."""
+    parser = argparse.ArgumentParser(
+        description='Repacks ramdisk image with modules from --kernel-ramdisk',
+    )
+
+    parser.add_argument(
+        '--android-ramdisk',
+        help='filename of input android ramdisk',
+        required=True)
+    parser.add_argument(
+        '--kernel-ramdisk',
+        help='filename of ramdisk to extract kernel modules from, '
+             'or the path of an existing directory containing the modules',
+        required=True)
+    parser.add_argument(
+        '--output-ramdisk',
+        help='filename of repacked ramdisk',
+        required=True)
+
+    return parser.parse_args()
+
+
+class RamdiskFormat(enum.Enum):
+    """Enum class for different ramdisk compression formats."""
+    LZ4 = 1
+    GZIP = 2
+
+
+# Based on system/tools/mkbootimg/repack_bootimg.py
+class RamdiskImage:
+    """A class that supports packing/unpacking a ramdisk."""
+    def __init__(self, ramdisk_img, directory, allow_dir):
+        # The caller gave us a directory instead of an image
+        # Assume it's already been extracted.
+        if os.path.isdir(ramdisk_img):
+            if not allow_dir:
+                raise RuntimeError(
+                    f"Directory not allowed for image {ramdisk_img}")
+
+            self._ramdisk_img = None
+            self._ramdisk_format = None
+            self._ramdisk_dir = ramdisk_img
+            return
+
+        self._ramdisk_img = ramdisk_img
+        self._ramdisk_format = None
+        self._ramdisk_dir = directory
+
+        self._unpack()
+
+    def _unpack(self):
+        """Unpacks the ramdisk."""
+        # The compression format might be in 'lz4' or 'gzip' format,
+        # trying lz4 first.
+        for compression_type, compression_util in [
+            (RamdiskFormat.LZ4, 'lz4'),
+            (RamdiskFormat.GZIP, 'gzip')]:
+
+            # Command arguments:
+            #   -d: decompression
+            #   -c: write to stdout
+            decompression_cmd = [
+                compression_util, '-d', '-c', self._ramdisk_img]
+
+            decompressed_result = subprocess.run(
+                decompression_cmd, check=False, capture_output=True)
+
+            if decompressed_result.returncode == 0:
+                self._ramdisk_format = compression_type
+                break
+
+        if self._ramdisk_format is not None:
+            # toybox cpio arguments:
+            #   -i: extract files from stdin
+            #   -d: create directories if needed
+            #   -u: override existing files
+            cpio_run = subprocess.run(
+                ['toybox', 'cpio', '-idu'], check=False,
+                input=decompressed_result.stdout, cwd=self._ramdisk_dir,
+                capture_output=True)
+            if (cpio_run.returncode != 0 and
+                b"Operation not permitted" not in cpio_run.stderr):
+                raise RuntimeError(f"cpio failed:\n{cpio_run.stderr}")
+
+            print(f"=== Unpacked ramdisk: '{self._ramdisk_img}' at "
+                  f"'{self._ramdisk_dir}' ===")
+        else:
+            raise RuntimeError('Failed to decompress ramdisk.')
+
+    def repack(self, out_ramdisk_file):
+        """Repacks a ramdisk from self._ramdisk_dir.
+
+        Args:
+            out_ramdisk_file: the output ramdisk file to save.
+        """
+        compression_cmd = ['lz4', '-l', '-12', '--favor-decSpeed']
+        if self._ramdisk_format == RamdiskFormat.GZIP:
+            compression_cmd = ['gzip']
+
+        print('Repacking ramdisk, which might take a few seconds ...')
+
+        mkbootfs_result = subprocess.run(
+            ['mkbootfs', self._ramdisk_dir], check=True, capture_output=True)
+
+        with open(out_ramdisk_file, 'wb') as output_fd:
+            subprocess.run(compression_cmd, check=True,
+                           input=mkbootfs_result.stdout, stdout=output_fd)
+
+        print(f"=== Repacked ramdisk: '{out_ramdisk_file}' ===")
+
+    @property
+    def ramdisk_dir(self):
+        """Returns the internal ramdisk dir."""
+        return self._ramdisk_dir
+
+    def get_modules(self):
+        """Returns the list of modules used in this ramdisk."""
+        modules_file_path = os.path.join(
+            self._ramdisk_dir, "lib/modules/modules.load")
+        with open(modules_file_path, "r", encoding="utf-8") as modules_file:
+            return [line.strip() for line in modules_file]
+
+
+def _replace_modules(dest_ramdisk, src_ramdisk):
+    """Replace any modules in dest_ramdisk with modules from src_ramdisk"""
+    src_dir = pathlib.Path(src_ramdisk.ramdisk_dir)
+    dest_dir = os.path.join(dest_ramdisk.ramdisk_dir, "lib/modules")
+    for module in dest_ramdisk.get_modules():
+        matches = list(src_dir.glob(f"**/{module}"))
+        if len(matches) > 1:
+            raise RuntimeError(
+                f"Found multiple candidates for module {module}")
+        if len(matches) == 0:
+            logger.warning(
+                "Could not find module %s, not replacing this module.",
+                module)
+            continue
+        shutil.copy(matches[0], os.path.join(dest_dir, module))
+
+
+def main():
+    """Parse arguments and repack ramdisk image."""
+    args = _parse_args()
+    with tempfile.TemporaryDirectory() as tempdir:
+        android_ramdisk = os.path.join(tempdir, _ANDROID_RAMDISK_DIR)
+        os.mkdir(android_ramdisk)
+        kernel_ramdisk = os.path.join(tempdir, _KERNEL_RAMDISK_DIR)
+        os.mkdir(kernel_ramdisk)
+        android_ramdisk = RamdiskImage(
+            args.android_ramdisk, os.path.join(tempdir, _ANDROID_RAMDISK_DIR),
+            allow_dir=False)
+        kernel_ramdisk = RamdiskImage(
+            args.kernel_ramdisk, os.path.join(tempdir, _KERNEL_RAMDISK_DIR),
+            allow_dir=True)
+        _replace_modules(android_ramdisk, kernel_ramdisk)
+        android_ramdisk.repack(args.output_ramdisk)
+
+
+if __name__ == '__main__':
+    main()
```

