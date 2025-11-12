```diff
diff --git a/vf/merge.sh b/vf/merge.sh
index 9989e04..209dd6b 100755
--- a/vf/merge.sh
+++ b/vf/merge.sh
@@ -3,9 +3,67 @@
 # Thin wrapper around merge_target_files for vendor-frozen targets to
 # allow flag changes to be made in a presubmit-guarded change.
 
+print_help() {
+  cat <<EOF
+Thin wrapper around merge_target_files for vendor-frozen targets.
+
+This script automates the process of merging vendor-specific files with
+system artifacts to create final flashable images. It takes several
+command-line arguments to configure the merging process.
+
+Usage: $0 [OPTIONS]
+
+Options:
+  -t TARGET          Specify the build target name (required).This is
+                     value of $TARGET_PRODUCT.
+  -d DIST_DIR        Specify the output directory for the generated
+                     images (required). This is where the merged
+                     target files, images, and OTA packages will be placed.
+  -v VENDOR_DIR      Specify the directory containing the vendor-specific
+                     target files (required). This directory should contain
+                     files like *-target_files-*.zip, bootloader.img,
+                     radio.img (if applicable), and potentially otatools.zip.
+  -b BUILD_ID        Specify the build ID (required). This identifier is
+                     included in the names of the output files.
+  -m MERGE_CONFIG_DIR Specify the directory containing configuration files
+                     for merging framework and vendor items. If provided,
+                     the script will look for:
+                       - framework_item_list.txt
+                       - framework_misc_info_keys.txt
+                       - vendor_item_list.txt
+                     These files control which specific files or keys are
+                     included during the merge process.
+  -r HAS_RADIO_IMG   Specify whether the vendor directory contains a
+                     radio.img file. Defaults to "true". Set to "false"
+                     for devices that do not have a separate radio image
+                     (e.g., Android TV targets).
+  -s TRUNK_STAGING   Optional suffix to append to the TARGET name for
+                     the lunch command. This is useful for specifying
+                     variant builds (e.g., lineage_x-trunk). If not set,
+                     TARGET is used directly.
+  -p SUPER_IMG       Optional flag to enable building a super image. If
+                     this argument is present (even without a value),
+                     the script will attempt to build a super.img file
+                     from the merged target files.
+  -o                 Optional flag to enable using vendor otatools by
+                     passing --vendor-otatools otatools.zip to merge_target_files
+  -h | --help       Show this help message and exit.
+
+Examples:
+  # Basic usage:
+  $0 -t <MY_TARGET> -d out/dist -v vendor/my_target -b 20231027
+
+  # Usage with a specific trunk staging and no radio image:
+  $0 -t <MY_TARGET> -d out/dist -v vendor/my_target -b 20231027 -s trunk -r false
+
+  # Usage with merge configuration files:
+  $0 -t <MY_TARGET> -d out/dist -v vendor/my_target -b 20231027 -m config/merge
+EOF
+}
+
 set -e
 
-while getopts ":t:d:v:b:m:r:s:p:" option ; do
+while getopts ":t:d:v:b:m:r:s:p:o" option ; do
   case "${option}" in
     t) TARGET=${OPTARG} ;;
     d) DIST_DIR=${OPTARG} ;;
@@ -15,24 +73,29 @@ while getopts ":t:d:v:b:m:r:s:p:" option ; do
     r) HAS_RADIO_IMG=${OPTARG} ;;
     s) TRUNK_STAGING=${OPTARG} ;;
     p) SUPER_IMG=${OPTARG} ;;
+    o) OPT_USE_VENDOR_OTATOOLS=1 ;;
     *) echo "Unexpected argument: -${OPTARG}" >&2 ;;
   esac
 done
 
 if [[ -z "${TARGET}" ]]; then
   echo "error: -t target argument not set"
+  print_help
   exit 1
 fi
 if [[ -z "${DIST_DIR}" ]]; then
   echo "error: -d dist dir argument not set"
+  print_help
   exit 1
 fi
 if [[ -z "${VENDOR_DIR}" ]]; then
   echo "error: -v vendor dir argument not set"
+  print_help
   exit 1
 fi
 if [[ -z "${BUILD_ID}" ]]; then
   echo "error: -b build id argument not set"
+  print_help
   exit 1
 fi
 if [[ -z "${HAS_RADIO_IMG}" ]]; then
@@ -54,9 +117,13 @@ mkdir -p ${SYSTEM_DIR}
 mv -f ${DIST_DIR}/android-info.txt ${SYSTEM_DIR}
 mv -f ${DIST_DIR}/${TARGET}-*.zip ${SYSTEM_DIR}
 
-source build/envsetup.sh
-lunch ${TARGET_RELEASE}-userdebug
-
+# Avoid to lunch target twice if it is already launched
+if [[ -n "$ANDROID_BUILD_TOP" ]]; then
+  echo "Already in an Android build environment!"
+else
+  source build/envsetup.sh
+  lunch ${TARGET_RELEASE}-userdebug
+fi
 
 EXTRA_FLAGS=""
 if [[ "${MERGE_CONFIG_DIR}" ]]; then
@@ -65,6 +132,12 @@ if [[ "${MERGE_CONFIG_DIR}" ]]; then
   --vendor-item-list ${MERGE_CONFIG_DIR}/vendor_item_list.txt"
 fi
 
+# (b/411270463): add the optional flag to pass vendor provided otatools for
+# vendor or odm image.
+if [[ $OPT_USE_VENDOR_OTATOOLS -eq 1 ]]; then
+  EXTRA_FLAGS+=" --vendor-otatools ${VENDOR_DIR}/otatools.zip"
+fi
+
 out/host/linux-x86/bin/merge_target_files \
   --framework-target-files ${SYSTEM_DIR}/${TARGET}-target_files*.zip \
   --vendor-target-files ${VENDOR_DIR}/*-target_files-*.zip \
```

