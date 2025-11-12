```diff
diff --git a/scripts/Android.bp b/scripts/Android.bp
index 06b7920..4f0805a 100644
--- a/scripts/Android.bp
+++ b/scripts/Android.bp
@@ -37,6 +37,7 @@ dirgroup {
         ":trusty_dirgroup_external_rust_crates_async-trait",
         ":trusty_dirgroup_external_rust_crates_bit_field",
         ":trusty_dirgroup_external_rust_crates_bitflags",
+        ":trusty_dirgroup_external_rust_crates_buddy_system_allocator",
         ":trusty_dirgroup_external_rust_crates_byteorder",
         ":trusty_dirgroup_external_rust_crates_cfg-if",
         ":trusty_dirgroup_external_rust_crates_ciborium",
@@ -62,8 +63,11 @@ dirgroup {
         ":trusty_dirgroup_external_rust_crates_num-integer",
         ":trusty_dirgroup_external_rust_crates_num-traits",
         ":trusty_dirgroup_external_rust_crates_once_cell",
+        ":trusty_dirgroup_external_rust_crates_open-enum",
+        ":trusty_dirgroup_external_rust_crates_open-enum-derive",
         ":trusty_dirgroup_external_rust_crates_openssl",
         ":trusty_dirgroup_external_rust_crates_openssl-macros",
+        ":trusty_dirgroup_external_rust_crates_paste",
         ":trusty_dirgroup_external_rust_crates_pkcs1",
         ":trusty_dirgroup_external_rust_crates_pkcs8",
         ":trusty_dirgroup_external_rust_crates_proc-macro2",
@@ -103,6 +107,7 @@ dirgroup {
         ":trusty_dirgroup_hardware_interfaces_staging_security_see",
         ":trusty_dirgroup_hardware_libhardware",
         ":trusty_dirgroup_packages_modules_virtualization_libs_dice_sample_inputs",
+        ":trusty_dirgroup_packages_modules_virtualization_libs_libfdt",
         ":trusty_dirgroup_packages_modules_virtualization_libs_libhypervisor_backends",
         ":trusty_dirgroup_packages_modules_virtualization_libs_open_dice",
         ":trusty_dirgroup_prebuilts_build-tools",
@@ -122,6 +127,7 @@ dirgroup {
         ":trusty_dirgroup_system_see_authmgr",
         ":trusty_dirgroup_system_teeui",
         ":trusty_dirgroup_system_tools_aidl",
+        ":trusty_dirgroup_test_vts-testcase_hal_treble_vintf_aidl",
         ":trusty_dirgroup_trusty_device_arm_generic-arm64",
         ":trusty_dirgroup_trusty_device_common",
         ":trusty_dirgroup_trusty_device_desktop",
@@ -155,11 +161,14 @@ filegroup {
 genrule_defaults {
     name: "trusty_aosp.gen.defaults",
     use_nsjail: true,
+    uses_order_only_build_date_file: true,
+    uses_order_only_build_number_file: true,
     dir_srcs: [
         ":trusty_aosp_dirgroups",
     ],
     srcs: [":trusty_aosp_filegroups"],
     tools: [
+        "aidl",
         "aidl_rust_glue",
         "aprotoc",
         "build_trusty",
@@ -168,12 +177,13 @@ genrule_defaults {
     keep_gendir: true,
 }
 
-// TODO(b/375543636): determine whether we'll include the Android build ID or not.
 genrule_cmd_template = "(mkdir -p $(genDir)/build-root && " +
     "cp -t . external/trusty/lk/makefile trusty/vendor/google/aosp/lk_inc.mk && " +
+    "AIDL_TOOL=$(location aidl) " +
     "AIDL_RUST_GLUE_TOOL=$(location aidl_rust_glue) PROTOC_TOOL=$(location aprotoc) " +
     "PROTOC_PLUGIN_BINARY=$(location trusty_metrics_atoms_protoc_plugin) TRUSTY_SKIP_DOCS=true " +
-    "$(location build_trusty) --script-dir trusty/vendor/google/aosp/scripts --buildid AVF_BUILTIN --verbose $$PROJECT_NAME " +
+    "BUILDDATE=\"$$(date --date=@$$(cat $(build_date_file)))\" " +
+    "$(location build_trusty) --script-dir trusty/vendor/google/aosp/scripts --buildid \"$$(cat $(build_number_file))\" --verbose $$PROJECT_NAME " +
     "--build-root $(genDir)/build-root 1>$(genDir)/stdout.log 2>$(genDir)/stderr.log || (" +
     "echo Trusty build FAILED; echo stdout:; cat $(genDir)/stdout.log; echo stderr:; cat $(genDir)/stderr.log; false)) && " +
     "cp -f $(genDir)/build-root/build-$$PROJECT_NAME/lk.$$OUT_EXT $(out)"
@@ -188,14 +198,13 @@ genrule {
     ],
     // IMPORTANT: OUT_EXT=bin for arm64
     // the raw binary (not the elf) is needed for the avb signature process
-    cmd: "PROJECT_NAME=vm-arm64-test" + select(soong_config_variable("trusty_system_vm", "placeholder_trusted_hal"), {
-        true: "-placeholder-trusted-hal",
-        default: "",
-    }) + select(soong_config_variable("trusty_system_vm", "buildtype"), {
-        "userdebug": "-userdebug",
-        "eng": "-userdebug",
-        default: "-user",
-    }) + "; OUT_EXT=bin;" + genrule_cmd_template,
+    // b/390206831 remove -placeholder-trusted-hal when VM2TZ is up
+    cmd: "PROJECT_NAME=vm-arm64-test-placeholder-trusted-hal" +
+        select(soong_config_variable("trusty_system_vm", "buildtype"), {
+            "userdebug": "-userdebug",
+            "eng": "-userdebug",
+            default: "-user",
+        }) + "; OUT_EXT=bin;" + genrule_cmd_template,
 }
 
 genrule {
@@ -208,14 +217,13 @@ genrule {
     ],
     // IMPORTANT: OUT_EXT=elf for x86_64
     // x86_64 VM payloads are not yet signed; crosvm consumes the elf
-    cmd: "PROJECT_NAME=vm-x86_64-test" + select(soong_config_variable("trusty_system_vm", "placeholder_trusted_hal"), {
-        true: "-placeholder-trusted-hal",
-        default: "",
-    }) + select(soong_config_variable("trusty_system_vm", "buildtype"), {
-        "userdebug": "-userdebug",
-        "eng": "-userdebug",
-        default: "-user",
-    }) + "; OUT_EXT=elf;" + genrule_cmd_template,
+    // b/390206831 remove -placeholder-trusted-hal when VM2TZ is up
+    cmd: "PROJECT_NAME=vm-x86_64-test-placeholder-trusted-hal" +
+        select(soong_config_variable("trusty_system_vm", "buildtype"), {
+            "userdebug": "-userdebug",
+            "eng": "-userdebug",
+            default: "-user",
+        }) + "; OUT_EXT=elf;" + genrule_cmd_template,
 }
 
 genrule {
@@ -400,16 +408,17 @@ prebuilt_etc {
 }
 
 // Trusty TEE image with Widevine OPK TA
-// TODO(b/375543636): determine whether we'll include the Android build ID or not.
 genrule_tee_cmd_template = "(mkdir -p $(genDir)/build-root && " +
     "cp -t . external/trusty/lk/makefile trusty/vendor/google/aosp/lk_inc.mk && " +
+    "AIDL_TOOL=$(location aidl) " +
     "AIDL_RUST_GLUE_TOOL=$(location aidl_rust_glue) PROTOC_TOOL=$(location aprotoc) " +
     "PROTOC_PLUGIN_BINARY=$(location trusty_metrics_atoms_protoc_plugin) " +
     "QEMU_PREBUILTS_DIR=$(location trusty_qemu_system_aarch64) " +
     "MKE2FS=$(location mke2fs) " +
     "TRUSTY_SKIP_DOCS=true " +
     "PACKAGE_TRUSTY_IMAGES_ONLY=true " +
-    "$(location build_trusty) --script-dir trusty/vendor/google/aosp/scripts --buildid AVF_BUILTIN --verbose $$PROJECT_NAME " +
+    "BUILDDATE=\"$$(date --date=@$$(cat $(build_date_file)))\" " +
+    "$(location build_trusty) --script-dir trusty/vendor/google/aosp/scripts --buildid \"$$(cat $(build_number_file))\" --verbose $$PROJECT_NAME " +
     "--skip-tests --build-root $(genDir)/build-root 1>$(genDir)/stdout.log 2>$(genDir)/stderr.log || (" +
     "echo Trusty build FAILED; echo stdout:; cat $(genDir)/stdout.log; echo stderr:; cat $(genDir)/stderr.log; false)) && " +
     "cp -f $(genDir)/build-root/build-$$PROJECT_NAME/trusty_image_package.tar.gz $(out)"
diff --git a/scripts/build.py b/scripts/build.py
index 104c262..6bf8476 100755
--- a/scripts/build.py
+++ b/scripts/build.py
@@ -320,6 +320,8 @@ def build(args):
         cmd = (
             f"export BUILDROOT={args.build_root};"
             f"export BUILDID={args.buildid};"
+            f"export ANDROID_BUILD_ARTIFACTS={args.android_artifacts};"
+            f"export KERNEL_BUILD_ARTIFACTS={args.kernel_artifacts};"
             f"{nice} $BUILDTOOLS_BINDIR/make {project} "
             f"-f $LKROOT/makefile -j {args.jobs}"
         )
@@ -746,6 +748,18 @@ def main(default_config=None, emulator=True):
         type=str,
         help="Path to an Android build to run tests against.",
     )
+    parser.add_argument(
+        "--android-artifacts",
+        type=str,
+        help="Path to an Android artifacts to run tests against.",
+        default="",
+    )
+    parser.add_argument(
+        "--kernel-artifacts",
+        type=str,
+        help="Path to an Linux Kernel artifacts to run tests against.",
+        default="",
+    )
     parser.add_argument(
         "--color-log",
         action="store_true",
```

