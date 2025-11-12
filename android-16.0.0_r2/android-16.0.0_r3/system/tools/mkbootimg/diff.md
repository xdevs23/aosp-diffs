```diff
diff --git a/Android.bp b/Android.bp
index 89ed4b3..51d4488 100644
--- a/Android.bp
+++ b/Android.bp
@@ -21,13 +21,8 @@ cc_library_headers {
     ],
 }
 
-python_defaults {
-    name: "mkbootimg_defaults",
-}
-
 python_binary_host {
     name: "mkbootimg",
-    defaults: ["mkbootimg_defaults"],
     main: "mkbootimg.py",
     srcs: [
         "mkbootimg.py",
@@ -40,7 +35,6 @@ python_binary_host {
 
 python_binary_host {
     name: "unpack_bootimg",
-    defaults: ["mkbootimg_defaults"],
     srcs: [
         "unpack_bootimg.py",
     ],
@@ -48,7 +42,6 @@ python_binary_host {
 
 python_binary_host {
     name: "repack_bootimg",
-    defaults: ["mkbootimg_defaults"],
     srcs: [
         "repack_bootimg.py",
     ],
@@ -63,7 +56,6 @@ python_binary_host {
 
 python_binary_host {
     name: "certify_bootimg",
-    defaults: ["mkbootimg_defaults"],
     main: "gki/certify_bootimg.py",
     srcs: [
         "gki/certify_bootimg.py",
@@ -77,7 +69,6 @@ python_binary_host {
 
 python_test_host {
     name: "mkbootimg_test",
-    defaults: ["mkbootimg_defaults"],
     main: "tests/mkbootimg_test.py",
     srcs: [
         "tests/mkbootimg_test.py",
diff --git a/BUILD.bazel b/BUILD.bazel
index 6fc323b..f2967f5 100644
--- a/BUILD.bazel
+++ b/BUILD.bazel
@@ -12,7 +12,17 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+load("@rules_python//python:defs.bzl", "py_binary")
+
 exports_files([
     "mkbootimg.py",
     "gki/testdata/testkey_rsa4096.pem",
 ])
+
+py_binary(
+    name = "unpack_bootimg",
+    srcs = [
+        "unpack_bootimg.py",
+    ],
+    visibility = ["//visibility:public"],
+)
diff --git a/gki/Android.bp b/gki/Android.bp
index 41a1c3e..46ffcda 100644
--- a/gki/Android.bp
+++ b/gki/Android.bp
@@ -18,7 +18,6 @@ package {
 
 python_test_host {
     name: "certify_bootimg_test",
-    defaults: ["mkbootimg_defaults"],
     main: "certify_bootimg_test.py",
     srcs: [
         "certify_bootimg_test.py",
@@ -37,7 +36,6 @@ python_test_host {
 
 python_binary_host {
     name: "generate_gki_certificate",
-    defaults: ["mkbootimg_defaults"],
     srcs: [
         "generate_gki_certificate.py",
     ],
diff --git a/gki/certify_bootimg.py b/gki/certify_bootimg.py
index 68a042e..1a8baea 100755
--- a/gki/certify_bootimg.py
+++ b/gki/certify_bootimg.py
@@ -109,7 +109,7 @@ def erase_certificate_and_avb_footer(boot_img):
         result = subprocess.run(avbtool_info_cmd, check=False,
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
-        has_boot_signature = (result.returncode == 0)
+        has_boot_signature = result.returncode == 0
 
     if has_boot_signature:
         new_file_size = os.path.getsize(boot_img) - BOOT_SIGNATURE_SIZE
diff --git a/gki/certify_bootimg_test.py b/gki/certify_bootimg_test.py
index 4619d8c..7dbe0fb 100644
--- a/gki/certify_bootimg_test.py
+++ b/gki/certify_bootimg_test.py
@@ -16,7 +16,6 @@
 
 """Tests certify_bootimg."""
 
-import logging
 import glob
 import os
 import random
@@ -1125,10 +1124,5 @@ class CertifyBootimgTest(unittest.TestCase):
                     self._EXPECTED_BOOT_GZ_SIGNATURE2_RSA4096})
 
 
-# I don't know how, but we need both the logger configuration and verbosity
-# level > 2 to make atest work. And yes this line needs to be at the very top
-# level, not even in the "__main__" indentation block.
-logging.basicConfig(stream=sys.stdout)
-
 if __name__ == '__main__':
     unittest.main(verbosity=2)
diff --git a/pylintrc b/pylintrc
index b65d218..e5076c6 100644
--- a/pylintrc
+++ b/pylintrc
@@ -155,12 +155,6 @@ disable=abstract-method,
 # mypackage.mymodule.MyReporterClass.
 output-format=text
 
-# Put messages in a separate file for each module / package specified on the
-# command line instead of printing them on stdout. Reports (if any) will be
-# written in a file name "pylint_global.[txt|html]". This option is deprecated
-# and it will be removed in Pylint 2.0.
-files-output=no
-
 # Tells whether to display a full report or only the messages
 reports=no
 
@@ -279,12 +273,6 @@ ignore-long-lines=(?x)(
 # else.
 single-line-if-stmt=yes
 
-# List of optional constructs for which whitespace checking is disabled. `dict-
-# separator` is used to allow tabulation in dicts, etc.: {1  : 1,\n222: 2}.
-# `trailing-comma` allows a space between comma and closing bracket: (a, ).
-# `empty-line` allows space-only lines.
-no-space-check=
-
 # Maximum number of lines in a module
 max-module-lines=99999
 
@@ -334,6 +322,7 @@ callbacks=cb_,_cb
 # builtins.
 redefining-builtins-modules=six,six.moves,past.builtins,future.builtins,functools
 
+max-positional-arguments=10
 
 [LOGGING]
 
@@ -435,6 +424,6 @@ valid-metaclass-classmethod-first-arg=mcs
 
 # Exceptions that will emit a warning when being caught. Defaults to
 # "Exception"
-overgeneral-exceptions=StandardError,
-                       Exception,
-                       BaseException
+overgeneral-exceptions=builtin.StandardError,
+                       builtin.Exception,
+                       builtin.BaseException
diff --git a/repack_bootimg.py b/repack_bootimg.py
index a322a68..3665873 100755
--- a/repack_bootimg.py
+++ b/repack_bootimg.py
@@ -148,11 +148,11 @@ class RamdiskImage:
         mkbootfs_result = subprocess.run(
             ['mkbootfs', self._ramdisk_dir], check=True, capture_output=True)
 
-        with open(out_ramdisk_file, 'w') as output_fd:
+        with open(out_ramdisk_file, 'wb') as output_fd:
             subprocess.run(compression_cmd, check=True,
                            input=mkbootfs_result.stdout, stdout=output_fd)
 
-        print("=== Repacked ramdisk: '{}' ===".format(out_ramdisk_file))
+        print(f"=== Repacked ramdisk: '{out_ramdisk_file}' ===")
 
     @property
     def ramdisk_dir(self):
@@ -193,7 +193,7 @@ class BootImage:
         result = subprocess.run(unpack_bootimg_cmds, check=True,
                                 capture_output=True, encoding='utf-8')
         self._previous_mkbootimg_args = shlex.split(result.stdout)
-        print("=== Unpacked boot image: '{}' ===".format(self._bootimg))
+        print(f"=== Unpacked boot image: '{self._bootimg}' ===")
 
         # From the output dir, checks there is 'ramdisk' or 'vendor_ramdisk'.
         ramdisk = os.path.join(self._bootimg_dir, 'ramdisk')
@@ -249,15 +249,15 @@ class BootImage:
             mkbootimg_cmd.extend(['--vendor_boot', self._bootimg])
 
         if ramdisk_option and ramdisk_option not in mkbootimg_cmd:
-            raise RuntimeError("Failed to find '{}' from:\n  {}".format(
-                ramdisk_option, shlex.join(mkbootimg_cmd)))
+            raise RuntimeError(f"Failed to find '{ramdisk_option}' from:\n"
+                               f"  {shlex.join(mkbootimg_cmd)}")
         # Replaces the original ramdisk with the newly packed ramdisk.
         if ramdisk_option:
             ramdisk_index = mkbootimg_cmd.index(ramdisk_option) + 1
             mkbootimg_cmd[ramdisk_index] = new_ramdisk
 
         subprocess.check_call(mkbootimg_cmd)
-        print("=== Repacked boot image: '{}' ===".format(self._bootimg))
+        print(f"=== Repacked boot image: '{self._bootimg}' ===")
 
     def add_files(self, copy_pairs):
         """Copy files specified by copy_pairs into current ramdisk.
@@ -271,7 +271,7 @@ class BootImage:
             dst_pathname = os.path.join(self.ramdisk_dir, dst_file)
             dst_dir = os.path.dirname(dst_pathname)
             if not os.path.exists(dst_dir):
-                print("Creating dir '{}'".format(dst_dir))
+                print(f"Creating dir '{dst_dir}'")
                 os.makedirs(dst_dir, 0o755)
             print(f"Copying file '{src_pathname}' to '{dst_pathname}'")
             shutil.copy2(src_pathname, dst_pathname, follow_symlinks=False)
diff --git a/tests/mkbootimg_test.py b/tests/mkbootimg_test.py
index 3902116..ed74288 100644
--- a/tests/mkbootimg_test.py
+++ b/tests/mkbootimg_test.py
@@ -17,7 +17,6 @@
 """Tests mkbootimg and unpack_bootimg."""
 
 import filecmp
-import logging
 import os
 import random
 import shlex
@@ -799,7 +798,7 @@ class MkbootimgTest(unittest.TestCase):
                 self.fail(msg)
 
     def test_unpack_vendor_boot_image_v4_without_dtb(self):
-        """Tests that mkbootimg(unpack_bootimg(image)) is an identity when no dtb image."""
+        """mkbootimg(unpack_bootimg(image)) is an identity when no dtb image."""
         with tempfile.TemporaryDirectory() as temp_out_dir:
             vendor_boot_img = os.path.join(temp_out_dir, 'vendor_boot.img')
             vendor_boot_img_reconstructed = os.path.join(
@@ -835,10 +834,5 @@ class MkbootimgTest(unittest.TestCase):
                 'reconstructed vendor_boot image differ from the original')
 
 
-# I don't know how, but we need both the logger configuration and verbosity
-# level > 2 to make atest work. And yes this line needs to be at the very top
-# level, not even in the "__main__" indentation block.
-logging.basicConfig(stream=sys.stdout)
-
 if __name__ == '__main__':
     unittest.main(verbosity=2)
diff --git a/unpack_bootimg.py b/unpack_bootimg.py
index a3f1a50..2578fce 100755
--- a/unpack_bootimg.py
+++ b/unpack_bootimg.py
@@ -318,7 +318,8 @@ class VendorBootImageInfoFormatter:
             lines.append(
                 f'vendor ramdisk table size: {self.vendor_ramdisk_table_size}')
             lines.append('vendor ramdisk table: [')
-            indent = lambda level: ' ' * 4 * level
+            def indent(level):
+                return ' ' * 4 * level
             for entry in self.vendor_ramdisk_table:
                 (output_ramdisk_name, ramdisk_size, ramdisk_offset,
                  ramdisk_type, ramdisk_name, board_id) = entry
```

