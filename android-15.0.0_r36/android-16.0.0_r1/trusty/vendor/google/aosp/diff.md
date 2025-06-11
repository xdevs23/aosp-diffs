```diff
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index a558a38..9485e66 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -14,9 +14,12 @@ trusty_build_config_selftest = ./scripts/trusty_build_config.py selftest
 
 [Builtin Hooks]
 clang_format = true
+rustfmt = true
+bpfmt = true
 commit_msg_bug_field = true
 commit_msg_changeid_field = true
 pylint3 = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
+rustfmt = --config-path=rustfmt.toml
diff --git a/lk_inc_aosp.mk b/lk_inc_aosp.mk
index 321b07d..fef7439 100644
--- a/lk_inc_aosp.mk
+++ b/lk_inc_aosp.mk
@@ -21,6 +21,8 @@ LKINC ?=  $(LKROOT) \
           trusty/user/base \
           trusty/device/arm/generic-arm64 \
           trusty/device/arm/vexpress-a15 \
+          trusty/device/common \
+          trusty/device/desktop \
           trusty/device/desktop/arm64/desktop-arm64 \
           trusty/device/desktop/x86_64/desktop-x86_64 \
           trusty/device/nxp/imx7d \
diff --git a/scripts/Android.bp b/scripts/Android.bp
index 39bcec1..06b7920 100644
--- a/scripts/Android.bp
+++ b/scripts/Android.bp
@@ -1,18 +1,26 @@
+// Copyright (C) 2025 The Android Open Source Project
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
 python_binary_host {
     name: "build_trusty",
     srcs: ["*.py"],
     main: "build.py",
-    version: {
-        py3: {
-            embedded_launcher: true,
-        },
-    },
 }
 
-genrule_defaults {
-    name: "lk.elf.defaults",
-    use_nsjail: true,
-    dir_srcs: [
+dirgroup {
+    name: "trusty_aosp_dirgroups",
+    dirs: [
         ":trusty_dirgroup_external_boringssl",
         ":trusty_dirgroup_external_dtc",
         ":trusty_dirgroup_external_freetype",
@@ -39,11 +47,14 @@ genrule_defaults {
         ":trusty_dirgroup_external_rust_crates_der",
         ":trusty_dirgroup_external_rust_crates_der_derive",
         ":trusty_dirgroup_external_rust_crates_downcast-rs",
+        ":trusty_dirgroup_external_rust_crates_either",
         ":trusty_dirgroup_external_rust_crates_enumn",
         ":trusty_dirgroup_external_rust_crates_flagset",
         ":trusty_dirgroup_external_rust_crates_foreign-types",
         ":trusty_dirgroup_external_rust_crates_foreign-types-shared",
         ":trusty_dirgroup_external_rust_crates_half",
+        ":trusty_dirgroup_external_rust_crates_hex",
+        ":trusty_dirgroup_external_rust_crates_itertools",
         ":trusty_dirgroup_external_rust_crates_lazy_static",
         ":trusty_dirgroup_external_rust_crates_libc",
         ":trusty_dirgroup_external_rust_crates_log",
@@ -73,7 +84,7 @@ genrule_defaults {
         ":trusty_dirgroup_external_rust_crates_unicode-ident",
         ":trusty_dirgroup_external_rust_crates_unicode-xid",
         ":trusty_dirgroup_external_rust_crates_uuid",
-        ":trusty_dirgroup_external_rust_crates_virtio-drivers",
+        ":trusty_dirgroup_external_rust_crates_virtio-drivers-and-devices",
         ":trusty_dirgroup_external_rust_crates_vm-memory",
         ":trusty_dirgroup_external_rust_crates_x509-cert",
         ":trusty_dirgroup_external_rust_crates_zerocopy",
@@ -91,7 +102,9 @@ genrule_defaults {
         ":trusty_dirgroup_hardware_interfaces_security_see",
         ":trusty_dirgroup_hardware_interfaces_staging_security_see",
         ":trusty_dirgroup_hardware_libhardware",
+        ":trusty_dirgroup_packages_modules_virtualization_libs_dice_sample_inputs",
         ":trusty_dirgroup_packages_modules_virtualization_libs_libhypervisor_backends",
+        ":trusty_dirgroup_packages_modules_virtualization_libs_open_dice",
         ":trusty_dirgroup_prebuilts_build-tools",
         ":trusty_dirgroup_prebuilts_clang-tools",
         ":trusty_dirgroup_prebuilts_clang_host_linux-x86",
@@ -106,11 +119,15 @@ genrule_defaults {
         ":trusty_dirgroup_system_libbase",
         ":trusty_dirgroup_system_libcppbor",
         ":trusty_dirgroup_system_secretkeeper",
+        ":trusty_dirgroup_system_see_authmgr",
         ":trusty_dirgroup_system_teeui",
         ":trusty_dirgroup_system_tools_aidl",
         ":trusty_dirgroup_trusty_device_arm_generic-arm64",
+        ":trusty_dirgroup_trusty_device_common",
+        ":trusty_dirgroup_trusty_device_desktop",
         ":trusty_dirgroup_trusty_device_x86_generic-x86_64",
         ":trusty_dirgroup_trusty_kernel",
+        ":trusty_dirgroup_trusty_user_app_authmgr",
         ":trusty_dirgroup_trusty_user_app_avb",
         ":trusty_dirgroup_trusty_user_app_cast-auth",
         ":trusty_dirgroup_trusty_user_app_confirmationui",
@@ -121,9 +138,27 @@ genrule_defaults {
         ":trusty_dirgroup_trusty_user_app_secretkeeper",
         ":trusty_dirgroup_trusty_user_app_storage",
         ":trusty_dirgroup_trusty_user_base",
+        ":trusty_dirgroup_trusty_user_desktop",
         ":trusty_dirgroup_trusty_vendor_google_aosp",
     ],
+    visibility: [
+        "//trusty/vendor/google/aosp/scripts",
+        "//trusty/vendor/google/proprietary/scripts",
+    ],
+}
+
+filegroup {
+    name: "trusty_aosp_filegroups",
     srcs: [":trusty_filegroup_external_libcxx"],
+}
+
+genrule_defaults {
+    name: "trusty_aosp.gen.defaults",
+    use_nsjail: true,
+    dir_srcs: [
+        ":trusty_aosp_dirgroups",
+    ],
+    srcs: [":trusty_aosp_filegroups"],
     tools: [
         "aidl_rust_glue",
         "aprotoc",
@@ -137,68 +172,266 @@ genrule_defaults {
 genrule_cmd_template = "(mkdir -p $(genDir)/build-root && " +
     "cp -t . external/trusty/lk/makefile trusty/vendor/google/aosp/lk_inc.mk && " +
     "AIDL_RUST_GLUE_TOOL=$(location aidl_rust_glue) PROTOC_TOOL=$(location aprotoc) " +
-    "PROTOC_PLUGIN_BINARY=$(location trusty_metrics_atoms_protoc_plugin) " +
+    "PROTOC_PLUGIN_BINARY=$(location trusty_metrics_atoms_protoc_plugin) TRUSTY_SKIP_DOCS=true " +
     "$(location build_trusty) --script-dir trusty/vendor/google/aosp/scripts --buildid AVF_BUILTIN --verbose $$PROJECT_NAME " +
     "--build-root $(genDir)/build-root 1>$(genDir)/stdout.log 2>$(genDir)/stderr.log || (" +
     "echo Trusty build FAILED; echo stdout:; cat $(genDir)/stdout.log; echo stderr:; cat $(genDir)/stderr.log; false)) && " +
-    "cp -f $(genDir)/build-root/build-$$PROJECT_NAME/lk.elf $(out)"
+    "cp -f $(genDir)/build-root/build-$$PROJECT_NAME/lk.$$OUT_EXT $(out)"
+
+genrule {
+    name: "trusty_test_vm_arm64.bin",
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    out: [
+        "trusty_test_vm_arm64.bin",
+    ],
+    // IMPORTANT: OUT_EXT=bin for arm64
+    // the raw binary (not the elf) is needed for the avb signature process
+    cmd: "PROJECT_NAME=vm-arm64-test" + select(soong_config_variable("trusty_system_vm", "placeholder_trusted_hal"), {
+        true: "-placeholder-trusted-hal",
+        default: "",
+    }) + select(soong_config_variable("trusty_system_vm", "buildtype"), {
+        "userdebug": "-userdebug",
+        "eng": "-userdebug",
+        default: "-user",
+    }) + "; OUT_EXT=bin;" + genrule_cmd_template,
+}
+
+genrule {
+    name: "trusty_test_vm_x86_64.elf",
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    out: [
+        "trusty_test_vm_x86_64.elf",
+    ],
+    // IMPORTANT: OUT_EXT=elf for x86_64
+    // x86_64 VM payloads are not yet signed; crosvm consumes the elf
+    cmd: "PROJECT_NAME=vm-x86_64-test" + select(soong_config_variable("trusty_system_vm", "placeholder_trusted_hal"), {
+        true: "-placeholder-trusted-hal",
+        default: "",
+    }) + select(soong_config_variable("trusty_system_vm", "buildtype"), {
+        "userdebug": "-userdebug",
+        "eng": "-userdebug",
+        default: "-user",
+    }) + "; OUT_EXT=elf;" + genrule_cmd_template,
+}
+
+genrule {
+    name: "trusty_test_vm_os_arm64.bin",
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    out: [
+        "trusty_test_vm_os_arm64.bin",
+    ],
+    // IMPORTANT: OUT_EXT=bin for arm64
+    // the raw binary (not the elf) is needed for the avb signature process
+    cmd: "PROJECT_NAME=vm-arm64-test_os" + select(soong_config_variable("trusty_system_vm", "buildtype"), {
+        "userdebug": "-userdebug",
+        "eng": "-userdebug",
+        default: "-user",
+    }) + "; OUT_EXT=bin;" + genrule_cmd_template,
+}
 
 genrule {
-    name: "trusty-arm64.lk.elf.gen",
-    defaults: ["lk.elf.defaults"],
-    out: ["generic-arm64.lk.elf"],
-    cmd: "PROJECT_NAME=generic-arm64; " + genrule_cmd_template,
+    name: "trusty_test_vm_os_x86_64.elf",
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    out: [
+        "trusty_test_vm_os_x86_64.elf",
+    ],
+    // IMPORTANT: OUT_EXT=elf for x86_64
+    // x86_64 VM payloads are not yet signed; crosvm consumes the elf
+    cmd: "PROJECT_NAME=vm-x86_64-test_os" + select(soong_config_variable("trusty_system_vm", "buildtype"), {
+        "userdebug": "-userdebug",
+        "eng": "-userdebug",
+        default: "-user",
+    }) + "; OUT_EXT=elf;" + genrule_cmd_template,
 }
 
 genrule {
-    name: "trusty-arm64-virt-test-debug.lk.elf.gen",
-    defaults: ["lk.elf.defaults"],
-    out: ["generic-arm64-virt-test-debug.lk.elf"],
-    cmd: "PROJECT_NAME=generic-arm64-virt-test-debug; " + genrule_cmd_template,
+    name: "trusty_security_vm_arm64.bin",
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    out: [
+        "trusty_security_vm_arm64.bin",
+    ],
+    // IMPORTANT: OUT_EXT=bin for arm64
+    // the raw binary (not the elf) is needed for the avb signature process
+    cmd: "PROJECT_NAME=vm-arm64-security" + select(soong_config_variable("trusty_system_vm", "placeholder_trusted_hal"), {
+        true: "-placeholder-trusted-hal",
+        default: "",
+    }) + select(soong_config_variable("trusty_system_vm", "buildtype"), {
+        "userdebug": "-userdebug",
+        "eng": "-userdebug",
+        default: "-user",
+    }) + "; OUT_EXT=bin;" + genrule_cmd_template,
 }
 
 genrule {
-    name: "trusty-x86_64.lk.elf.gen",
-    defaults: ["lk.elf.defaults"],
-    out: ["generic-x86_64.lk.elf"],
-    cmd: "PROJECT_NAME=generic-x86_64; " + genrule_cmd_template,
+    name: "trusty_security_vm_x86_64.elf",
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    out: [
+        "trusty_security_vm_x86_64.elf",
+    ],
+    // IMPORTANT: OUT_EXT=elf for x86_64
+    // x86_64 VM payloads are not yet signed; crosvm consumes the elf
+    cmd: "PROJECT_NAME=vm-x86_64-security" + select(soong_config_variable("trusty_system_vm", "placeholder_trusted_hal"), {
+        true: "-placeholder-trusted-hal",
+        default: "",
+    }) + select(soong_config_variable("trusty_system_vm", "buildtype"), {
+        "userdebug": "-userdebug",
+        "eng": "-userdebug",
+        default: "-user",
+    }) + "; OUT_EXT=elf;" + genrule_cmd_template,
 }
 
 genrule {
-    name: "trusty-x86_64-test.lk.elf.gen",
-    defaults: ["lk.elf.defaults"],
-    out: ["generic-x86_64-test.lk.elf"],
-    cmd: "PROJECT_NAME=generic-x86_64-test; " + genrule_cmd_template,
+    name: "trusty_desktop_vm_arm64.bin",
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    out: [
+        "trusty_desktop_vm_arm64.bin",
+    ],
+    cmd: "PROJECT_NAME=desktop-arm64; OUT_EXT=bin;" + genrule_cmd_template,
 }
 
+genrule {
+    name: "trusty_desktop_test_vm_arm64.bin",
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    out: [
+        "trusty_desktop_test_vm_arm64.bin",
+    ],
+    cmd: "PROJECT_NAME=desktop-arm64-test; OUT_EXT=bin;" + genrule_cmd_template,
+}
+
+genrule {
+    name: "trusty_desktop_vm_x86_64.bin",
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    out: [
+        "trusty_desktop_vm_x86_64.bin",
+    ],
+    cmd: "PROJECT_NAME=desktop-x86_64; OUT_EXT=bin;" + genrule_cmd_template,
+}
+
+genrule {
+    name: "trusty_desktop_test_vm_x86_64.bin",
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    out: [
+        "trusty_desktop_test_vm_x86_64.bin",
+    ],
+    cmd: "PROJECT_NAME=desktop-x86_64-test; OUT_EXT=bin;" + genrule_cmd_template,
+}
+
+// - Trusty VM payloads on arm64 are pvmfw enabled
+//   AVF VM build system uses the raw binary image,
+//   adds pvmfw footer and generates a pvmfw-compliant signed elf file)
+// - Trusty VM payload on x86 are for now loaded in Cuttlefish unsigned
+//   the unsigned generated elf is used directly by AV
+//
+// see packages/modules/Virtualization/guest/trusty
+
 prebuilt_etc {
-    name: "trusty-lk.elf",
+    name: "trusty_test_vm_unsigned",
     enabled: false,
     arch: {
         arm64: {
-            src: ":trusty-arm64.lk.elf.gen",
+            src: ":trusty_test_vm_arm64.bin",
+            filename: "trusty-test_vm.bin",
             enabled: true,
         },
         x86_64: {
-            src: ":trusty-x86_64.lk.elf.gen",
+            src: ":trusty_test_vm_x86_64.elf",
+            filename: "trusty-test_vm.elf",
             enabled: true,
         },
     },
-    filename: "trusty-lk.elf",
 }
 
 prebuilt_etc {
-    name: "trusty-test-lk.elf",
+    name: "trusty_test_vm_os_unsigned",
     enabled: false,
     arch: {
         arm64: {
-            src: ":trusty-arm64-virt-test-debug.lk.elf.gen",
+            src: ":trusty_test_vm_os_arm64.bin",
+            filename: "trusty-test_vm_os.bin",
             enabled: true,
         },
         x86_64: {
-            src: ":trusty-x86_64-test.lk.elf.gen",
+            src: ":trusty_test_vm_os_x86_64.elf",
+            filename: "trusty-test_vm_os.elf",
             enabled: true,
         },
     },
-    filename: "trusty-test-lk.elf",
+}
+
+prebuilt_etc {
+    name: "trusty_security_vm_unsigned",
+    enabled: select((os(), arch(), soong_config_variable("trusty_system_vm", "enabled")), {
+        ("android", "arm64", true): true,
+        ("android", "x86_64", true): true,
+        (default, default, default): false,
+    }),
+    relative_install_path: "vm/trusty_vm",
+    system_ext_specific: true,
+    arch: {
+        arm64: {
+            src: ":trusty_security_vm_arm64.bin",
+            filename: "trusty_security_vm_unsigned.bin",
+        },
+        x86_64: {
+            src: ":trusty_security_vm_x86_64.elf",
+            filename: "trusty_security_vm_unsigned.elf",
+        },
+    },
+}
+
+// Trusty TEE image with Widevine OPK TA
+// TODO(b/375543636): determine whether we'll include the Android build ID or not.
+genrule_tee_cmd_template = "(mkdir -p $(genDir)/build-root && " +
+    "cp -t . external/trusty/lk/makefile trusty/vendor/google/aosp/lk_inc.mk && " +
+    "AIDL_RUST_GLUE_TOOL=$(location aidl_rust_glue) PROTOC_TOOL=$(location aprotoc) " +
+    "PROTOC_PLUGIN_BINARY=$(location trusty_metrics_atoms_protoc_plugin) " +
+    "QEMU_PREBUILTS_DIR=$(location trusty_qemu_system_aarch64) " +
+    "MKE2FS=$(location mke2fs) " +
+    "TRUSTY_SKIP_DOCS=true " +
+    "PACKAGE_TRUSTY_IMAGES_ONLY=true " +
+    "$(location build_trusty) --script-dir trusty/vendor/google/aosp/scripts --buildid AVF_BUILTIN --verbose $$PROJECT_NAME " +
+    "--skip-tests --build-root $(genDir)/build-root 1>$(genDir)/stdout.log 2>$(genDir)/stderr.log || (" +
+    "echo Trusty build FAILED; echo stdout:; cat $(genDir)/stdout.log; echo stderr:; cat $(genDir)/stderr.log; false)) && " +
+    "cp -f $(genDir)/build-root/build-$$PROJECT_NAME/trusty_image_package.tar.gz $(out)"
+
+genrule {
+    name: "trusty_tee_package",
+    enabled: select(soong_config_variable("trusty_tee", "enabled"), {
+        true: true,
+        default: false,
+    }),
+    defaults: [
+        "trusty_aosp.gen.defaults",
+    ],
+    tools: [
+        "trusty_qemu_system_aarch64",
+        "mke2fs",
+    ],
+    out: [
+        "trusty_tee_package.tar.gz",
+    ],
+    dist: {
+        targets: ["trusty-tee_package"],
+    },
+    cmd: "PROJECT_NAME=qemu-generic-arm64-gicv3-test-debug; " + genrule_tee_cmd_template,
 }
diff --git a/scripts/build-config b/scripts/build-config
index f88476d..0ffea0f 100644
--- a/scripts/build-config
+++ b/scripts/build-config
@@ -61,6 +61,7 @@
         projects=[
             "desktop-arm64",
             "desktop-arm64-test",
+            "desktop-arm64-test-debug",
             "desktop-x86_64",
             "desktop-x86_64-test",
             "generic-arm32-debug",
@@ -78,9 +79,11 @@
             "vexpress-a15-trusty",
             "imx7d",
             "pico7d",
+            "qemu-desktop-arm64-test-debug",
             "qemu-generic-arm32-gicv3-test-debug",
             "qemu-generic-arm32-test-debug",
             "qemu-generic-arm64-fuzz-test-debug",
+            "qemu-generic-arm64-gicv3-hafnium-test-debug",
             "qemu-generic-arm64-gicv3-spd-ffa-test-debug",
             "qemu-generic-arm64-gicv3-spd-noffa-test-debug",
             "qemu-generic-arm64-gicv3-test-debug",
diff --git a/scripts/envsetup.sh b/scripts/envsetup.sh
index f6e9147..8a00235 100644
--- a/scripts/envsetup.sh
+++ b/scripts/envsetup.sh
@@ -29,10 +29,11 @@ gettop() {
 }
 
 if [ -z ${TRUSTY_BUILD_CLANG_VERSION} ]; then
-    TRUSTY_BUILD_CLANG_VERSION=clang-r522817
+    #clang-r536225 reports version as 19.0.1 which is also what Rust 1.82 was built with
+    TRUSTY_BUILD_CLANG_VERSION=clang-r536225
 fi
 if [ -z ${TRUSTY_BUILD_RUST_VERSION} ]; then
-    TRUSTY_BUILD_RUST_VERSION=1.80.1
+    TRUSTY_BUILD_RUST_VERSION=1.82.0
 fi
 export TRUSTY_TOP=$(gettop)
 export CLANG_BINDIR=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/${TRUSTY_BUILD_CLANG_VERSION}/bin
@@ -53,6 +54,7 @@ export BUILDTOOLS_BINDIR=${TRUSTY_TOP}/prebuilts/build-tools/linux-x86/bin
 export BUILDTOOLS_COMMON=${TRUSTY_TOP}/prebuilts/build-tools/common
 export PY3=$BUILDTOOLS_BINDIR/py3-cmd
 export PATH_TOOLS_BINDIR=${TRUSTY_TOP}/prebuilts/build-tools/path/linux-x86
+export LINUX_BUILD_TOOLS=${TRUSTY_TOP}/prebuilts/kernel-build-tools/linux-x86
 
 SOONG_UI=$TRUSTY_TOP/build/soong/soong_ui.bash
 if [ -f "$SOONG_UI" ]; then
@@ -60,9 +62,9 @@ if [ -f "$SOONG_UI" ]; then
 fi
 
 if [ -f "$TRUSTY_TOP/external/lk/engine.mk" ]; then
-    export LKROOT=$TRUSTY_TOP/external/lk
+    export LKROOT=external/lk
 elif [ -f "$TRUSTY_TOP/external/trusty/lk/engine.mk" ]; then
-    export LKROOT=$TRUSTY_TOP/external/trusty/lk
+    export LKROOT=external/trusty/lk
 else
     echo "Error: Couldn't locate the LK root directory." 1>&2
     exit 1
diff --git a/scripts/run_tests.py b/scripts/run_tests.py
index c80df71..ad839fd 100755
--- a/scripts/run_tests.py
+++ b/scripts/run_tests.py
@@ -41,6 +41,7 @@ from trusty_build_config import PortType, TrustyCompositeTest, TrustyTest
 from trusty_build_config import TrustyAndroidTest, TrustyBuildConfig
 from trusty_build_config import TrustyHostTest, TrustyRebootCommand
 from trusty_build_config import TrustyPrintCommand
+from trusty_build_config import TrustyHostcommandTest
 
 
 TEST_STATUS = Enum("TEST_STATUS", ["PASSED", "FAILED", "SKIPPED"])
@@ -419,6 +420,8 @@ def run_tests(
                 else:
                     if isinstance(test, TrustyAndroidTest):
                         print_test_command(test.name, [test.shell_command])
+                    elif isinstance(test, TrustyHostcommandTest):
+                        print_test_command(test.name, test.command[3:])
                     else:
                         # port tests are identified by their port name,
                         # no command
diff --git a/scripts/test-map b/scripts/test-map
index c497e91..8a2ac56 100644
--- a/scripts/test-map
+++ b/scripts/test-map
@@ -83,6 +83,22 @@
         ],
     ),
 
+    testmap(
+        projects=[
+            "qemu-generic-arm64-gicv3-hafnium-test-debug",
+        ],
+        tests=[
+            # TODO(b/122357282): the Hafnium build should run all the tests,
+            # but currently it does not even boot. When that is fixed,
+            # we should just move qemu-generic-arm64-gicv3-hafnium-test-debug
+            # below to the full testmap.
+            #
+            # For now, we're adding a placeholder test so we can get some
+            # build artifacts.
+            hosttest("avb_test"),
+        ],
+    ),
+
 
     testmap(
         projects=[
@@ -91,7 +107,6 @@
         tests=[
             hosttest("avb_test"),
             hosttest("cbor_test"),
-            hosttest("keymaster_test"),
             hosttest("mock_storage_test"),
             hosttest("storage_block_test"),
             hosttest("storage_host_test"),
@@ -199,14 +214,26 @@
                                 "/sys/bus/platform/drivers/trusty-irq/bind"),
 
             androidtest(name="log-driver",
+                        # logd currently goes into a busy loop if the trusty
+                        # log driver starts returning errors from poll and
+                        # read. Additionally, the trusty-log driver does not
+                        # wake up any waiters in unbind. This happens later
+                        # when there is output from trusty ready for them to
+                        # read. Stop logd while unbinding to work around these
+                        # bugs for now and avoid filling the kernel log with
+                        # error messages. (b/397453308)
                         command="TRUSTY_DEV=$(basename /sys/bus/platform/devices/"
                                 "?(*:)trusty?(-core):log)"
                                 "&&"
+                                "stop logd"
+                                "&&"
                                 "echo $TRUSTY_DEV >"
                                 "/sys/bus/platform/drivers/trusty-log/unbind"
                                 "&&"
                                 "echo $TRUSTY_DEV >"
-                                "/sys/bus/platform/drivers/trusty-log/bind"),
+                                "/sys/bus/platform/drivers/trusty-log/bind"
+                                "&&"
+                                "start logd"),
 
             androidtest(name="virtio-driver",
                         # virtio remove currently hangs (bug: 142275662).
@@ -510,6 +537,7 @@
 
             # Test Binder RPC between Android and Trusty
             androidtest(name="binder-rpc-to-trusty-test",
+                        enabled=False,
                         command="/data/nativetest64/vendor/"
                                 "binderRpcToTrustyTest/"
                                 "binderRpcToTrustyTest64"),
diff --git a/scripts/trusty_build_config.py b/scripts/trusty_build_config.py
index a5f7385..61701a4 100755
--- a/scripts/trusty_build_config.py
+++ b/scripts/trusty_build_config.py
@@ -98,7 +98,12 @@ class TrustyTest(object):
         return self
 
 class TrustyHostTest(TrustyTest):
-    """Stores a pair of a test name and a command to run on host."""
+    """Stores a pair of a test name and a command to run on host.
+
+    TrustyHostTest is for tests that run solely on the host.
+    This is different from TrustyHostcommandTest, which runs tests on
+    the host that issue commands to a running Android device via adb.
+    """
 
     class TrustyHostTestFlags:
         """Enable needs to be matched with provides without special casing"""
@@ -135,6 +140,35 @@ class TrustyAndroidTest(TrustyTest):
         self.need.set(**need)
         return self
 
+class TrustyHostcommandTest(TrustyTest):
+    """Stores a test name and command to run on the host.
+
+    TrustyHostcommandTest runs tests on the host that issue commands to a
+    running Android device via adb. This is different from TrustyHostTest,
+    which is for tests that run solely on the host.
+    """
+
+    def __init__(self, name, command, need=None,
+                 port_type=PortType.TEST, enabled=True, nameprefix="",
+                 timeout=None):
+        nameprefix = nameprefix + "hostcommandtest:"
+
+        # cmd stores arguments that are passed to the test runner in qemu.py.
+        # The first item in the list isn't used.
+        cmd = [None, "--headless", "--host-command", command]
+        if timeout:
+            cmd += ['--timeout', str(timeout)]
+        super().__init__(nameprefix + name, cmd, enabled, port_type)
+
+        if need:
+            self.need = need
+        else:
+            self.need = TrustyPortTestFlags()
+
+    def needs(self, **need):
+        self.need.set(**need)
+        return self
+
 
 class TrustyPortTest(TrustyTest):
     """Stores a trusty port name for a test to run."""
@@ -428,6 +462,7 @@ class TrustyBuildConfig(object):
             "hosttests": hosttests,
             "boottests": boottests,
             "androidtest": TrustyAndroidTest,
+            "hostcommandtest": TrustyHostcommandTest,
             "androidporttests": androidporttests,
             "needs": needs,
             "reboot": TrustyRebootCommand,
```

