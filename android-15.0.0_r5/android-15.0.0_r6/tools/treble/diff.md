```diff
diff --git a/cuttlefish/OWNERS b/cuttlefish/OWNERS
new file mode 100644
index 0000000..c730c22
--- /dev/null
+++ b/cuttlefish/OWNERS
@@ -0,0 +1,3 @@
+denniscy@google.com
+jaeman@google.com
+jeongik@google.com
diff --git a/cuttlefish/build_cf_hybrid_device.py b/cuttlefish/build_cf_hybrid_device.py
index 0207dc3..14c0dde 100644
--- a/cuttlefish/build_cf_hybrid_device.py
+++ b/cuttlefish/build_cf_hybrid_device.py
@@ -20,7 +20,7 @@ import os
 import subprocess
 import tempfile
 
-from build_chd_debug_ramdisk import add_debug_ramdisk_files
+from build_chd_debug_ramdisk import build_chd_debug_ramdisk, ImageOptions
 from build_chd_utils import copy_files, merge_chd_sepolicy, unzip_otatools
 
 """Test command:
@@ -36,11 +36,11 @@ python3 tools/treble/cuttlefish/build_cf_hybrid_device.py \
 """
 
 
-def _parse_args():
+def _parse_args() -> argparse.Namespace:
   """Parse the arguments for building cuttlefish hybrid devices.
 
   Returns:
-    An object of argparse.Namespace.
+    An object of the parsed arguments.
   """
   parser = argparse.ArgumentParser()
 
@@ -62,7 +62,7 @@ def _parse_args():
   return parser.parse_args()
 
 
-def run(temp_dir):
+def run(temp_dir: str) -> None:
   args = _parse_args()
 
   # unzip otatools
@@ -128,13 +128,29 @@ def run(temp_dir):
     files_to_add.append(f'{chd_debug_prop}:adb_debug.prop')
 
   cf_debug_img = os.path.join(args.output_dir, 'vendor_boot-debug.img')
-  if files_to_add and os.path.exists(cf_debug_img):
-    chd_debug_img = os.path.join(args.output_dir, 'vendor_boot-chd_debug.img')
-    try:
-      add_debug_ramdisk_files(
-          cf_debug_img, files_to_add, otatools, temp_dir, chd_debug_img)
-    except Exception as error:
-      print(f'Warning - cannot build {chd_debug_img}: {error}')
+  chd_debug_image_userdebug = 'vendor_boot-chd_debug.img'
+  chd_debug_image_user = 'vendor_boot-chd_debug_user.img'
+  if os.path.exists(cf_debug_img):
+    for image_name in [chd_debug_image_userdebug, chd_debug_image_user]:
+      image_path = os.path.join(args.output_dir, image_name)
+      image_dir = os.path.join(temp_dir, image_name)
+      os.mkdir(image_dir)
+      image_option = ImageOptions(
+          input_image=cf_debug_img,
+          output_image=image_path,
+          otatools_dir=otatools,
+          temp_dir=image_dir,
+          files_to_add=files_to_add)
+
+      # Remove userdebug_plat_sepolicy.cil from CHD's debug ramdisk to build a
+      # debug ramdisk for user builds.
+      if image_name == chd_debug_image_user:
+        image_option.files_to_remove = ['userdebug_plat_sepolicy.cil']
+
+      try:
+        build_chd_debug_ramdisk(image_option)
+      except Exception as error:
+        print(f'Warning - cannot build {image_name}: {error}')
 
 
 if __name__ == '__main__':
diff --git a/cuttlefish/build_chd_debug_ramdisk.py b/cuttlefish/build_chd_debug_ramdisk.py
index da16a5d..ff23553 100644
--- a/cuttlefish/build_chd_debug_ramdisk.py
+++ b/cuttlefish/build_chd_debug_ramdisk.py
@@ -15,10 +15,12 @@
 # the License.
 
 import argparse
+import dataclasses
 import os
 import shlex
 import subprocess
 import tempfile
+from typing import List
 
 from build_chd_utils import copy_files, unzip_otatools
 
@@ -41,11 +43,11 @@ python3 tools/treble/cuttlefish/build_chd_debug_ramdisk.py \
 _VENDOR_RAMDISK_TYPE_PLATFORM = '1'
 
 
-def _parse_args():
+def _parse_args() -> argparse.Namespace:
   """Parse the arguments for building the chd debug ramdisk.
 
   Returns:
-    An object of argparse.Namespace.
+    An object of the parsed arguments.
   """
   parser = argparse.ArgumentParser()
   parser.add_argument('input_img',
@@ -60,133 +62,255 @@ def _parse_args():
   return parser.parse_args()
 
 
+@dataclasses.dataclass
+class ImageOptions:
+  """The options for building the CHD vendor boot debug image.
+
+  Attributes:
+    input_image: path of the input vendor boot debug image.
+    output_image: path of the output CHD vendor boot debug image.
+    otatools_dir: path of the otatools directory.
+    temp_dir: path of the temporary directory for ramdisk filesystem.
+    files_to_add: a list of files to be added in the debug ramdisk, where a
+      pair defines the src and dst path of each file.
+    files_to_remove: a list of files to be removed from the input vendor boot
+      debug image.
+  """
+  input_image: str
+  output_image: str
+  otatools_dir: str
+  temp_dir: str
+  files_to_add: List[str] = dataclasses.field(default_factory=list)
+  files_to_remove: List[str] = dataclasses.field(default_factory=list)
+
+
+@dataclasses.dataclass
 class BootImage:
-  """A class that supports adding a new ramdisk fragment into a boot.img."""
-
-  def __init__(self, bootimg, bootimg_dir, unpack_bootimg_bin, mkbootfs_bin,
-               mkbootimg_bin, lz4_bin):
-    self._bootimg = bootimg
-    self._bootimg_dir = bootimg_dir
-    self._unpack_bootimg_bin = unpack_bootimg_bin
-    self._mkbootfs_bin = mkbootfs_bin
-    self._mkbootimg_bin = mkbootimg_bin
-    self._lz4_bin = lz4_bin
-    self._bootimg_args = []
-
-  def unpack(self):
-    """Unpacks the boot.img and capture the bootimg arguments."""
-    if self._bootimg_args:
-      raise RuntimeError(f'cannot unpack {self._bootimg} twice')
-    print(f'Unpacking {self._bootimg} to {self._bootimg_dir}')
+  """Provide some functions to modify a boot image.
+
+  Attributes:
+    bootimg: path of the input boot image to be modified.
+    bootimg_dir: path of a temporary directory that would be used to extract
+      the input boot image.
+    unpack_bootimg_bin: path of the `unpack_bootimg` executable.
+    mkbootfs_bin: path of the `mkbootfs` executable.
+    mkbootimg_bin: path of the `mkbootimg` executable.
+    lz4_bin: path of the `lz4` executable.
+    toybox_bin: path of the `toybox` executable.
+    bootimg_args: the arguments that were used to build this boot image.
+  """
+  bootimg: str
+  bootimg_dir: str
+  unpack_bootimg_bin: str
+  mkbootfs_bin: str
+  mkbootimg_bin: str
+  lz4_bin: str
+  toybox_bin: str
+  bootimg_args: List[str] = dataclasses.field(default_factory=list)
+
+  def _get_ramdisk_fragments(self) -> List[str]:
+    """Get the path to all ramdisk fragments at `self.bootimg_dir`."""
+    return [os.path.join(self.bootimg_dir, file)
+            for file in os.listdir(self.bootimg_dir)
+            if file.startswith('vendor_ramdisk')]
+
+  def _compress_ramdisk(self, root_dir: str, ramdisk_file: str) -> None:
+    """Compress all the files under `root_dir` to generate `ramdisk_file`.
+
+    Args:
+      root_dir: root directory of the ramdisk content.
+      ramdisk_file: path of the output ramdisk file.
+    """
+    mkbootfs_cmd = [self.mkbootfs_bin, root_dir]
+    mkbootfs_result = subprocess.run(
+        mkbootfs_cmd, check=True, capture_output=True)
+    compress_cmd = [self.lz4_bin, '-l', '-12', '--favor-decSpeed']
+    with open(ramdisk_file, 'w') as o:
+      subprocess.run(
+          compress_cmd, check=True, input=mkbootfs_result.stdout, stdout=o)
+
+  def _decompress_ramdisk(self, ramdisk_file: str, output_dir: str) -> str:
+    """Decompress `ramdisk_file` to a new file at `output_dir`.
+
+    Args:
+      ramdisk_file: path of the ramdisk file to be decompressed.
+      output_dir: path of the output directory.
+
+    Returns:
+      Path of the uncompressed ramdisk.
+    """
+    if not os.path.exists(output_dir):
+      raise FileNotFoundError(f'Decompress output {output_dir} does not exist')
+    uncompressed_ramdisk = os.path.join(output_dir, 'uncompressed_ramdisk')
+    decompress_cmd = [self.lz4_bin, '-d', ramdisk_file, uncompressed_ramdisk]
+    subprocess.run(decompress_cmd, check=True)
+    return uncompressed_ramdisk
+
+  def _extract_ramdisk(self, ramdisk_file: str, root_dir: str) -> None:
+    """Extract the files from a uncompressed ramdisk to `root_dir`.
+
+    Args:
+      ramdisk_file: path of the ramdisk file to be extracted.
+      root_dir: path of the extracted ramdisk root directory.
+    """
+    # Use `toybox cpio` instead of `cpio` to avoid invoking cpio from the host
+    # environment.
+    extract_cmd = [self.toybox_bin, 'cpio', '-i', '-F', ramdisk_file]
+    subprocess.run(extract_cmd, cwd=root_dir, check=True)
+
+  def unpack(self) -> None:
+    """Unpack the boot.img and capture the bootimg arguments."""
+    if self.bootimg_args:
+      raise RuntimeError(f'cannot unpack {self.bootimg} twice')
+    print(f'Unpacking {self.bootimg} to {self.bootimg_dir}')
     unpack_cmd = [
-        self._unpack_bootimg_bin,
-        '--boot_img', self._bootimg,
-        '--out', self._bootimg_dir,
+        self.unpack_bootimg_bin,
+        '--boot_img', self.bootimg,
+        '--out', self.bootimg_dir,
         '--format', 'mkbootimg'
     ]
     unpack_result = subprocess.run(unpack_cmd, check=True,
                                    capture_output=True, encoding='utf-8')
-    self._bootimg_args = shlex.split(unpack_result.stdout)
+    self.bootimg_args = shlex.split(unpack_result.stdout)
+
+  def add_ramdisk(self, ramdisk_root: str) -> None:
+    """Add a new ramdisk fragment and update the bootimg arguments.
 
-  def add_ramdisk(self, ramdisk_root):
-    """Adds a new ramdisk fragment and update the bootimg arguments."""
+    Args:
+      ramdisk_root: path of the root directory which contains the content of
+        the new ramdisk fragment.
+    """
     # Name the new ramdisk using the smallest unused index.
-    ramdisk_files = [file for file in os.listdir(self._bootimg_dir)
-                     if file.startswith('vendor_ramdisk')]
-    new_ramdisk_name = f'vendor_ramdisk{len(ramdisk_files):02d}'
-    new_ramdisk_file = os.path.join(self._bootimg_dir, new_ramdisk_name)
+    ramdisk_fragments = self._get_ramdisk_fragments()
+    new_ramdisk_name = f'vendor_ramdisk{len(ramdisk_fragments):02d}'
+    new_ramdisk_file = os.path.join(self.bootimg_dir, new_ramdisk_name)
     if os.path.exists(new_ramdisk_file):
       raise FileExistsError(f'{new_ramdisk_file} already exists')
-
     print(f'Adding a new vendor ramdisk fragment {new_ramdisk_file}')
-    mkbootfs_cmd = [self._mkbootfs_bin, ramdisk_root]
-    mkbootfs_result = subprocess.run(mkbootfs_cmd, check=True,
-                                     capture_output=True)
-
-    compress_cmd = [self._lz4_bin, '-l', '-12', '--favor-decSpeed']
-    with open(new_ramdisk_file, 'w') as o:
-      subprocess.run(compress_cmd, check=True,
-                     input=mkbootfs_result.stdout, stdout=o)
+    self._compress_ramdisk(ramdisk_root, new_ramdisk_file)
 
     # Update the bootimg arguments to include the new ramdisk file.
-    self._bootimg_args.extend([
+    self.bootimg_args.extend([
         '--ramdisk_type', _VENDOR_RAMDISK_TYPE_PLATFORM,
         '--ramdisk_name', 'chd',
         '--vendor_ramdisk_fragment', new_ramdisk_file
     ])
 
-  def pack(self, output_img):
-    """Packs the boot.img."""
-    print(f'Packing {output_img} with args: {self._bootimg_args}')
+  def remove_file(self, file_name: str) -> None:
+    """Remove `file_name` from all the existing ramdisk fragments.
+
+    Args:
+      file_name: path of the file to be removed, relative to the ramdisk root
+        directory.
+    """
+    ramdisk_fragments = self._get_ramdisk_fragments()
+    for ramdisk in ramdisk_fragments:
+      print(f'Removing {file_name} from {ramdisk}')
+      with tempfile.TemporaryDirectory() as temp_dir:
+        uncompressed_ramdisk = self._decompress_ramdisk(ramdisk, temp_dir)
+        extracted_ramdisk_dir = os.path.join(temp_dir, 'extracted_ramdisk')
+        os.mkdir(extracted_ramdisk_dir)
+        self._extract_ramdisk(uncompressed_ramdisk, extracted_ramdisk_dir)
+
+        file_path = os.path.join(extracted_ramdisk_dir, file_name)
+        if not os.path.exists(file_path):
+          raise FileNotFoundError(f'Cannot Remove {file_name} from {ramdisk}')
+        os.remove(file_path)
+
+        self._compress_ramdisk(extracted_ramdisk_dir, ramdisk)
+
+  def pack(self, output_img: str) -> None:
+    """Pack the boot.img using `self.bootimg_args`.
+
+    Args:
+      output_img: path of the output boot image.
+    """
+    print(f'Packing {output_img} with args: {self.bootimg_args}')
     mkbootimg_cmd = [
-        self._mkbootimg_bin, '--vendor_boot', output_img
-    ] + self._bootimg_args
+        self.mkbootimg_bin, '--vendor_boot', output_img
+    ] + self.bootimg_args
     subprocess.check_call(mkbootimg_cmd)
 
 
-def _prepare_env(otatools_dir):
+def _prepare_env(otatools_dir: str) -> List[str]:
   """Get the executable path of the required otatools.
 
-  We need `unpack_bootimg`, `mkbootfs`, `mkbootimg` and `lz4` for building CHD
-  debug ramdisk. This function returns the path to the above tools in order.
+  We need `unpack_bootimg`, `mkbootfs`, `mkbootimg`, `lz4` and `toybox` for
+  building CHD debug ramdisk. This function returns the path to the above tools
+  in order.
 
   Args:
-    otatools_dir: The path to the otatools directory.
+    otatools_dir: path of the otatools directory.
 
   Raises:
     FileNotFoundError if any required otatool does not exist.
   """
   tools_path = []
-  for tool_name in ['unpack_bootimg', 'mkbootfs', 'mkbootimg', 'lz4']:
-    tool_path = os.path.join(otatools_dir, 'bin', tool_name)
+  for tool in ['unpack_bootimg', 'mkbootfs', 'mkbootimg', 'lz4', 'toybox']:
+    tool_path = os.path.join(otatools_dir, 'bin', tool)
     if not os.path.exists(tool_path):
       raise FileNotFoundError(f'otatool {tool_path} does not exist')
     tools_path.append(tool_path)
   return tools_path
 
 
-def add_debug_ramdisk_files(input_image, files_to_add, otatools_dir, temp_dir,
-                            output_image):
-  """Add files to a vendor boot debug image.
+def build_chd_debug_ramdisk(options: ImageOptions) -> None:
+  """Build a new vendor boot debug image.
 
-  This function creates a new ramdisk fragment, add this fragment into the
-  input vendor boot debug image, and generate an output image.
+  1. If `options.files_to_remove` present, remove these files from all the
+     existing ramdisk fragments.
+  2. If `options.files_to_add` present, create a new ramdisk fragment which
+     adds these files, and add this new fragment into the input image.
 
   Args:
-    input_image: The path to the input vendor boot debug image.
-    files_to_add: A list of files to be added in the debug ramdisk, where a
-                  pair defines the src and dst path of each file.
-    otatools_dir: The path to the otatools directory.
-    temp_dir: The path to the temporary directory for ramdisk filesystem.
-    output_img: The path to the output vendor boot debug image.
+    options: a `ImageOptions` object which specifies the options for building
+      a CHD vendor boot debug image.
 
   Raises:
     FileExistsError if having duplicated ramdisk fragments.
-    FileNotFoundError if any required otatool does not exist.
+    FileNotFoundError if any required otatool does not exist or if the
+      userdebug sepolicy is not present at `input_image`.
   """
-  print(f'Adding {files_to_add} to {input_image}')
-  ramdisk_root = os.path.join(temp_dir, 'ramdisk_root')
-  os.mkdir(ramdisk_root)
-  copy_files(files_to_add, ramdisk_root)
-
-  bootimg_dir = os.path.join(temp_dir, 'bootimg')
-  unpack_bootimg, mkbootfs, mkbootimg, lz4 = _prepare_env(otatools_dir)
-  bootimg = BootImage(input_image, bootimg_dir, unpack_bootimg, mkbootfs,
-                      mkbootimg, lz4)
+  unpack_bootimg, mkbootfs, mkbootimg, lz4, toybox = _prepare_env(
+      options.otatools_dir)
+  bootimg = BootImage(
+      bootimg=options.input_image,
+      bootimg_dir=os.path.join(options.temp_dir, 'bootimg'),
+      unpack_bootimg_bin=unpack_bootimg,
+      mkbootfs_bin=mkbootfs,
+      mkbootimg_bin=mkbootimg,
+      lz4_bin=lz4,
+      toybox_bin=toybox)
   bootimg.unpack()
-  bootimg.add_ramdisk(ramdisk_root)
-  bootimg.pack(output_image)
+
+  for f in options.files_to_remove:
+    bootimg.remove_file(f)
+
+  if options.files_to_add:
+    print(f'Adding {options.files_to_add} to {options.input_image}')
+    new_ramdisk_fragment = os.path.join(options.temp_dir,
+                                        'new_ramdisk_fragment')
+    os.mkdir(new_ramdisk_fragment)
+    copy_files(options.files_to_add, new_ramdisk_fragment)
+    bootimg.add_ramdisk(new_ramdisk_fragment)
+
+  bootimg.pack(options.output_image)
 
 
-def main(temp_dir):
+def main(temp_dir: str) -> None:
   args = _parse_args()
   otatools_dir = os.path.join(temp_dir, 'otatools')
   unzip_otatools(args.otatools_zip, otatools_dir, [
       'bin/unpack_bootimg', 'bin/mkbootfs', 'bin/mkbootimg', 'bin/lz4',
-      'lib64/*'
+      'bin/toybox', 'lib64/*'
   ])
-  add_debug_ramdisk_files(args.input_img, args.add_file, otatools_dir,
-                          temp_dir, args.output_img)
+  options = ImageOptions(
+      input_image=args.input_img,
+      output_image=args.output_img,
+      otatools_dir=otatools_dir,
+      temp_dir=temp_dir,
+      files_to_add=args.add_file)
+  build_chd_debug_ramdisk(options)
 
 
 if __name__ == '__main__':
diff --git a/cuttlefish/build_chd_utils.py b/cuttlefish/build_chd_utils.py
index 45cae9e..1bffa0c 100644
--- a/cuttlefish/build_chd_utils.py
+++ b/cuttlefish/build_chd_utils.py
@@ -20,10 +20,13 @@ import os
 import shutil
 import subprocess
 import tempfile
+from typing import List, Tuple
 import zipfile
 
 
-def unzip_otatools(otatools_zip_path, output_dir, patterns=None):
+def unzip_otatools(
+    otatools_zip_path: str, output_dir: str, patterns: List[str] = None
+) -> None:
   """Unzip otatools to a directory and set the permissions for execution.
 
   Args:
@@ -44,7 +47,7 @@ def unzip_otatools(otatools_zip_path, output_dir, patterns=None):
     os.chmod(f, 0o777)
 
 
-def _parse_copy_file_pair(copy_file_pair):
+def _parse_copy_file_pair(copy_file_pair: str) -> Tuple[str, str]:
   """Convert a string to a source path and a destination path.
 
   Args:
@@ -66,7 +69,7 @@ def _parse_copy_file_pair(copy_file_pair):
   return src_list[0], split_pair[1]
 
 
-def copy_files(copy_files_list, output_dir):
+def copy_files(copy_files_list: List[str], output_dir: str) -> None:
   """Copy files to the output directory.
 
   Args:
@@ -88,7 +91,7 @@ def copy_files(copy_files_list, output_dir):
     shutil.copyfile(src, dst)
 
 
-def _extract_cil_files(target_files_zip, output_dir):
+def _extract_cil_files(target_files_zip: str, output_dir: str) -> None:
   """Extract sepolicy cil files from a target files zip archive.
 
   Args:
@@ -101,7 +104,7 @@ def _extract_cil_files(target_files_zip, output_dir):
       zf.extract(f, output_dir)
 
 
-def _get_sepolicy_plat_version(target_files_zip):
+def _get_sepolicy_plat_version(target_files_zip: str) -> str:
   """Get the platform sepolicy version from a vendor target files zip archive.
 
   Args:
@@ -119,8 +122,10 @@ def _get_sepolicy_plat_version(target_files_zip):
       raise
 
 
-def merge_chd_sepolicy(framework_target_files_zip, vendor_target_files_zip,
-                       otatools_dir, output_dir):
+def merge_chd_sepolicy(
+    framework_target_files_zip: str, vendor_target_files_zip: str,
+    otatools_dir: str, output_dir: str
+) -> str:
   """Merge the sepolicy files for CHD.
 
   This function takes both the system and vendor sepolicy files from
```

