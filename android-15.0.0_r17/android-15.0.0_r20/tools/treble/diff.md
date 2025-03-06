```diff
diff --git a/build/sandbox/rbe_action.py b/build/sandbox/rbe_action.py
index 9748fdf..ff09ef3 100644
--- a/build/sandbox/rbe_action.py
+++ b/build/sandbox/rbe_action.py
@@ -40,6 +40,7 @@ def main():
       os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../../..'))
   env = rbe.env_array_to_dict(rbe.prepare_env(env))
   env['PATH'] = os.getenv('PATH')
+  env['HOME'] = os.getenv('HOME')
   for d in ['FLAG_log_dir', 'RBE_output_dir', 'RBE_proxy_log_dir']:
     env[d] = '/tmp'  # We want the logs in /tmp instead of out.
   try:
diff --git a/cuttlefish/build_chd_debug_ramdisk.py b/cuttlefish/build_chd_debug_ramdisk.py
index ff23553..cdb883c 100644
--- a/cuttlefish/build_chd_debug_ramdisk.py
+++ b/cuttlefish/build_chd_debug_ramdisk.py
@@ -202,23 +202,32 @@ class BootImage:
     Args:
       file_name: path of the file to be removed, relative to the ramdisk root
         directory.
+
+    Raises:
+      FileNotFoundError if `file_name` cannot be found in any of the ramdisk
+        fragments.
     """
     ramdisk_fragments = self._get_ramdisk_fragments()
+    is_removed = False
     for ramdisk in ramdisk_fragments:
-      print(f'Removing {file_name} from {ramdisk}')
+      print(f'Attempting to remove {file_name} from {ramdisk}')
       with tempfile.TemporaryDirectory() as temp_dir:
         uncompressed_ramdisk = self._decompress_ramdisk(ramdisk, temp_dir)
         extracted_ramdisk_dir = os.path.join(temp_dir, 'extracted_ramdisk')
         os.mkdir(extracted_ramdisk_dir)
         self._extract_ramdisk(uncompressed_ramdisk, extracted_ramdisk_dir)
-
         file_path = os.path.join(extracted_ramdisk_dir, file_name)
-        if not os.path.exists(file_path):
-          raise FileNotFoundError(f'Cannot Remove {file_name} from {ramdisk}')
-        os.remove(file_path)
-
+        if os.path.exists(file_path):
+          os.remove(file_path)
+          is_removed = True
+          print(f'{file_path} was removed')
         self._compress_ramdisk(extracted_ramdisk_dir, ramdisk)
 
+    if not is_removed:
+      raise FileNotFoundError(
+          f'cannot remove {file_name} from {ramdisk_fragments}'
+      )
+
   def pack(self, output_img: str) -> None:
     """Pack the boot.img using `self.bootimg_args`.
 
@@ -268,8 +277,9 @@ def build_chd_debug_ramdisk(options: ImageOptions) -> None:
 
   Raises:
     FileExistsError if having duplicated ramdisk fragments.
-    FileNotFoundError if any required otatool does not exist or if the
-      userdebug sepolicy is not present at `input_image`.
+    FileNotFoundError if any required otatool does not exist or if
+      `options.files_to_remove` is not present in any of the ramdisk fragments
+      of `input_image`.
   """
   unpack_bootimg, mkbootfs, mkbootimg, lz4, toybox = _prepare_env(
       options.otatools_dir)
diff --git a/vf/merge.sh b/vf/merge.sh
index 8e76241..9989e04 100755
--- a/vf/merge.sh
+++ b/vf/merge.sh
@@ -5,7 +5,7 @@
 
 set -e
 
-while getopts ":t:d:v:b:m:r:" option ; do
+while getopts ":t:d:v:b:m:r:s:p:" option ; do
   case "${option}" in
     t) TARGET=${OPTARG} ;;
     d) DIST_DIR=${OPTARG} ;;
@@ -13,6 +13,8 @@ while getopts ":t:d:v:b:m:r:" option ; do
     b) BUILD_ID=${OPTARG} ;;
     m) MERGE_CONFIG_DIR=${OPTARG} ;;
     r) HAS_RADIO_IMG=${OPTARG} ;;
+    s) TRUNK_STAGING=${OPTARG} ;;
+    p) SUPER_IMG=${OPTARG} ;;
     *) echo "Unexpected argument: -${OPTARG}" >&2 ;;
   esac
 done
@@ -36,6 +38,14 @@ fi
 if [[ -z "${HAS_RADIO_IMG}" ]]; then
   HAS_RADIO_IMG="true"
 fi
+if [[ -z "${TRUNK_STAGING}" ]]; then
+  TARGET_RELEASE="${TARGET}"
+else
+  TARGET_RELEASE="${TARGET}-${TRUNK_STAGING}"
+fi
+if [[ -n "${SUPER_IMG}" ]]; then
+  BUILD_SUPER_IMG="true"
+fi
 
 # Move the system-only build artifacts to a separate folder
 # so that the flashing tools use the merged files instead.
@@ -45,7 +55,8 @@ mv -f ${DIST_DIR}/android-info.txt ${SYSTEM_DIR}
 mv -f ${DIST_DIR}/${TARGET}-*.zip ${SYSTEM_DIR}
 
 source build/envsetup.sh
-lunch ${TARGET}-userdebug
+lunch ${TARGET_RELEASE}-userdebug
+
 
 EXTRA_FLAGS=""
 if [[ "${MERGE_CONFIG_DIR}" ]]; then
@@ -53,6 +64,7 @@ if [[ "${MERGE_CONFIG_DIR}" ]]; then
   --framework-misc-info-keys ${MERGE_CONFIG_DIR}/framework_misc_info_keys.txt \
   --vendor-item-list ${MERGE_CONFIG_DIR}/vendor_item_list.txt"
 fi
+
 out/host/linux-x86/bin/merge_target_files \
   --framework-target-files ${SYSTEM_DIR}/${TARGET}-target_files*.zip \
   --vendor-target-files ${VENDOR_DIR}/*-target_files-*.zip \
@@ -74,6 +86,14 @@ if [[ -f "${VENDOR_DIR}/otatools.zip" ]]; then
   cp ${VENDOR_DIR}/otatools.zip ${DIST_DIR}/otatools_vendor.zip
 fi
 
-unzip -j -d ${DIST_DIR} \
+#Build super image if required
+if [[ $BUILD_SUPER_IMG = "true" ]]; then
+  out/host/linux-x86/bin/build_super_image \
+  ${DIST_DIR}/${TARGET}-target_files-${BUILD_ID}.zip \
+  ${DIST_DIR}/super.img
+  unzip -j -o -d ${DIST_DIR} ${DIST_DIR}/${TARGET}-img-${BUILD_ID}.zip
+fi
+
+unzip -j -o -d ${DIST_DIR} \
   ${VENDOR_DIR}/*-target_files-*.zip \
-  OTA/android-info.txt
\ No newline at end of file
+  OTA/android-info.txt
```

