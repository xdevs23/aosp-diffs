```diff
diff --git a/Android.bp b/Android.bp
new file mode 100644
index 0000000..4874229
--- /dev/null
+++ b/Android.bp
@@ -0,0 +1,5 @@
+dirgroup {
+    name: "trusty_dirgroup_trusty_vendor_google_aosp",
+    dirs: ["."],
+    visibility: ["//trusty/vendor/google/aosp/scripts"],
+}
diff --git a/scripts/Android.bp b/scripts/Android.bp
new file mode 100644
index 0000000..39bcec1
--- /dev/null
+++ b/scripts/Android.bp
@@ -0,0 +1,204 @@
+python_binary_host {
+    name: "build_trusty",
+    srcs: ["*.py"],
+    main: "build.py",
+    version: {
+        py3: {
+            embedded_launcher: true,
+        },
+    },
+}
+
+genrule_defaults {
+    name: "lk.elf.defaults",
+    use_nsjail: true,
+    dir_srcs: [
+        ":trusty_dirgroup_external_boringssl",
+        ":trusty_dirgroup_external_dtc",
+        ":trusty_dirgroup_external_freetype",
+        ":trusty_dirgroup_external_googletest",
+        ":trusty_dirgroup_external_libcxx",
+        ":trusty_dirgroup_external_libcxxabi",
+        ":trusty_dirgroup_external_nanopb-c",
+        ":trusty_dirgroup_external_open-dice",
+        ":trusty_dirgroup_external_python_jinja",
+        ":trusty_dirgroup_external_python_markupsafe",
+        ":trusty_dirgroup_external_python_six",
+        ":trusty_dirgroup_external_rust_crates_acpi",
+        ":trusty_dirgroup_external_rust_crates_arrayvec",
+        ":trusty_dirgroup_external_rust_crates_async-trait",
+        ":trusty_dirgroup_external_rust_crates_bit_field",
+        ":trusty_dirgroup_external_rust_crates_bitflags",
+        ":trusty_dirgroup_external_rust_crates_byteorder",
+        ":trusty_dirgroup_external_rust_crates_cfg-if",
+        ":trusty_dirgroup_external_rust_crates_ciborium",
+        ":trusty_dirgroup_external_rust_crates_ciborium-io",
+        ":trusty_dirgroup_external_rust_crates_ciborium-ll",
+        ":trusty_dirgroup_external_rust_crates_const-oid",
+        ":trusty_dirgroup_external_rust_crates_coset",
+        ":trusty_dirgroup_external_rust_crates_der",
+        ":trusty_dirgroup_external_rust_crates_der_derive",
+        ":trusty_dirgroup_external_rust_crates_downcast-rs",
+        ":trusty_dirgroup_external_rust_crates_enumn",
+        ":trusty_dirgroup_external_rust_crates_flagset",
+        ":trusty_dirgroup_external_rust_crates_foreign-types",
+        ":trusty_dirgroup_external_rust_crates_foreign-types-shared",
+        ":trusty_dirgroup_external_rust_crates_half",
+        ":trusty_dirgroup_external_rust_crates_lazy_static",
+        ":trusty_dirgroup_external_rust_crates_libc",
+        ":trusty_dirgroup_external_rust_crates_log",
+        ":trusty_dirgroup_external_rust_crates_num-derive",
+        ":trusty_dirgroup_external_rust_crates_num-integer",
+        ":trusty_dirgroup_external_rust_crates_num-traits",
+        ":trusty_dirgroup_external_rust_crates_once_cell",
+        ":trusty_dirgroup_external_rust_crates_openssl",
+        ":trusty_dirgroup_external_rust_crates_openssl-macros",
+        ":trusty_dirgroup_external_rust_crates_pkcs1",
+        ":trusty_dirgroup_external_rust_crates_pkcs8",
+        ":trusty_dirgroup_external_rust_crates_proc-macro2",
+        ":trusty_dirgroup_external_rust_crates_protobuf",
+        ":trusty_dirgroup_external_rust_crates_protobuf-support",
+        ":trusty_dirgroup_external_rust_crates_quote",
+        ":trusty_dirgroup_external_rust_crates_sec1",
+        ":trusty_dirgroup_external_rust_crates_serde",
+        ":trusty_dirgroup_external_rust_crates_serde_derive",
+        ":trusty_dirgroup_external_rust_crates_smccc",
+        ":trusty_dirgroup_external_rust_crates_spin",
+        ":trusty_dirgroup_external_rust_crates_spki",
+        ":trusty_dirgroup_external_rust_crates_static_assertions",
+        ":trusty_dirgroup_external_rust_crates_syn",
+        ":trusty_dirgroup_external_rust_crates_synstructure",
+        ":trusty_dirgroup_external_rust_crates_thiserror",
+        ":trusty_dirgroup_external_rust_crates_thiserror-impl",
+        ":trusty_dirgroup_external_rust_crates_unicode-ident",
+        ":trusty_dirgroup_external_rust_crates_unicode-xid",
+        ":trusty_dirgroup_external_rust_crates_uuid",
+        ":trusty_dirgroup_external_rust_crates_virtio-drivers",
+        ":trusty_dirgroup_external_rust_crates_vm-memory",
+        ":trusty_dirgroup_external_rust_crates_x509-cert",
+        ":trusty_dirgroup_external_rust_crates_zerocopy",
+        ":trusty_dirgroup_external_rust_crates_zerocopy-derive",
+        ":trusty_dirgroup_external_rust_crates_zeroize",
+        ":trusty_dirgroup_external_rust_crates_zeroize_derive",
+        ":trusty_dirgroup_external_scudo",
+        ":trusty_dirgroup_external_trusty_arm-trusted-firmware",
+        ":trusty_dirgroup_external_trusty_bootloader",
+        ":trusty_dirgroup_external_trusty_headers",
+        ":trusty_dirgroup_external_trusty_lk",
+        ":trusty_dirgroup_external_trusty_musl",
+        ":trusty_dirgroup_frameworks_hardware_interfaces",
+        ":trusty_dirgroup_frameworks_native",
+        ":trusty_dirgroup_hardware_interfaces_security_see",
+        ":trusty_dirgroup_hardware_interfaces_staging_security_see",
+        ":trusty_dirgroup_hardware_libhardware",
+        ":trusty_dirgroup_packages_modules_virtualization_libs_libhypervisor_backends",
+        ":trusty_dirgroup_prebuilts_build-tools",
+        ":trusty_dirgroup_prebuilts_clang-tools",
+        ":trusty_dirgroup_prebuilts_clang_host_linux-x86",
+        ":trusty_dirgroup_prebuilts_gcc_linux-x86_host_x86_64-linux-glibc2.17-4.8",
+        ":trusty_dirgroup_prebuilts_misc",
+        ":trusty_dirgroup_prebuilts_rust",
+        ":trusty_dirgroup_system_authgraph",
+        ":trusty_dirgroup_system_core",
+        ":trusty_dirgroup_system_gatekeeper",
+        ":trusty_dirgroup_system_keymaster",
+        ":trusty_dirgroup_system_keymint",
+        ":trusty_dirgroup_system_libbase",
+        ":trusty_dirgroup_system_libcppbor",
+        ":trusty_dirgroup_system_secretkeeper",
+        ":trusty_dirgroup_system_teeui",
+        ":trusty_dirgroup_system_tools_aidl",
+        ":trusty_dirgroup_trusty_device_arm_generic-arm64",
+        ":trusty_dirgroup_trusty_device_x86_generic-x86_64",
+        ":trusty_dirgroup_trusty_kernel",
+        ":trusty_dirgroup_trusty_user_app_avb",
+        ":trusty_dirgroup_trusty_user_app_cast-auth",
+        ":trusty_dirgroup_trusty_user_app_confirmationui",
+        ":trusty_dirgroup_trusty_user_app_gatekeeper",
+        ":trusty_dirgroup_trusty_user_app_keymaster",
+        ":trusty_dirgroup_trusty_user_app_keymint",
+        ":trusty_dirgroup_trusty_user_app_sample",
+        ":trusty_dirgroup_trusty_user_app_secretkeeper",
+        ":trusty_dirgroup_trusty_user_app_storage",
+        ":trusty_dirgroup_trusty_user_base",
+        ":trusty_dirgroup_trusty_vendor_google_aosp",
+    ],
+    srcs: [":trusty_filegroup_external_libcxx"],
+    tools: [
+        "aidl_rust_glue",
+        "aprotoc",
+        "build_trusty",
+        "trusty_metrics_atoms_protoc_plugin",
+    ],
+    keep_gendir: true,
+}
+
+// TODO(b/375543636): determine whether we'll include the Android build ID or not.
+genrule_cmd_template = "(mkdir -p $(genDir)/build-root && " +
+    "cp -t . external/trusty/lk/makefile trusty/vendor/google/aosp/lk_inc.mk && " +
+    "AIDL_RUST_GLUE_TOOL=$(location aidl_rust_glue) PROTOC_TOOL=$(location aprotoc) " +
+    "PROTOC_PLUGIN_BINARY=$(location trusty_metrics_atoms_protoc_plugin) " +
+    "$(location build_trusty) --script-dir trusty/vendor/google/aosp/scripts --buildid AVF_BUILTIN --verbose $$PROJECT_NAME " +
+    "--build-root $(genDir)/build-root 1>$(genDir)/stdout.log 2>$(genDir)/stderr.log || (" +
+    "echo Trusty build FAILED; echo stdout:; cat $(genDir)/stdout.log; echo stderr:; cat $(genDir)/stderr.log; false)) && " +
+    "cp -f $(genDir)/build-root/build-$$PROJECT_NAME/lk.elf $(out)"
+
+genrule {
+    name: "trusty-arm64.lk.elf.gen",
+    defaults: ["lk.elf.defaults"],
+    out: ["generic-arm64.lk.elf"],
+    cmd: "PROJECT_NAME=generic-arm64; " + genrule_cmd_template,
+}
+
+genrule {
+    name: "trusty-arm64-virt-test-debug.lk.elf.gen",
+    defaults: ["lk.elf.defaults"],
+    out: ["generic-arm64-virt-test-debug.lk.elf"],
+    cmd: "PROJECT_NAME=generic-arm64-virt-test-debug; " + genrule_cmd_template,
+}
+
+genrule {
+    name: "trusty-x86_64.lk.elf.gen",
+    defaults: ["lk.elf.defaults"],
+    out: ["generic-x86_64.lk.elf"],
+    cmd: "PROJECT_NAME=generic-x86_64; " + genrule_cmd_template,
+}
+
+genrule {
+    name: "trusty-x86_64-test.lk.elf.gen",
+    defaults: ["lk.elf.defaults"],
+    out: ["generic-x86_64-test.lk.elf"],
+    cmd: "PROJECT_NAME=generic-x86_64-test; " + genrule_cmd_template,
+}
+
+prebuilt_etc {
+    name: "trusty-lk.elf",
+    enabled: false,
+    arch: {
+        arm64: {
+            src: ":trusty-arm64.lk.elf.gen",
+            enabled: true,
+        },
+        x86_64: {
+            src: ":trusty-x86_64.lk.elf.gen",
+            enabled: true,
+        },
+    },
+    filename: "trusty-lk.elf",
+}
+
+prebuilt_etc {
+    name: "trusty-test-lk.elf",
+    enabled: false,
+    arch: {
+        arm64: {
+            src: ":trusty-arm64-virt-test-debug.lk.elf.gen",
+            enabled: true,
+        },
+        x86_64: {
+            src: ":trusty-x86_64-test.lk.elf.gen",
+            enabled: true,
+        },
+    },
+    filename: "trusty-test-lk.elf",
+}
diff --git a/scripts/build-config b/scripts/build-config
index 8c59658..f88476d 100644
--- a/scripts/build-config
+++ b/scripts/build-config
@@ -60,7 +60,9 @@
     build(
         projects=[
             "desktop-arm64",
+            "desktop-arm64-test",
             "desktop-x86_64",
+            "desktop-x86_64-test",
             "generic-arm32-debug",
             "generic-arm32",
             "generic-arm32-test-debug",
@@ -79,6 +81,8 @@
             "qemu-generic-arm32-gicv3-test-debug",
             "qemu-generic-arm32-test-debug",
             "qemu-generic-arm64-fuzz-test-debug",
+            "qemu-generic-arm64-gicv3-spd-ffa-test-debug",
+            "qemu-generic-arm64-gicv3-spd-noffa-test-debug",
             "qemu-generic-arm64-gicv3-test-debug",
             "qemu-generic-arm64-test-debug",
             "qemu-generic-arm64u32-test-debug",
@@ -91,6 +95,9 @@
         "trusty/device/arm/generic-arm64/project/keys/apploader_sign_test_private_key_0.der",
         "trusty/device/arm/generic-arm64/project/keys/apploader_sign_test_public_key_0.der"
     ]),
+    docs([
+        "trusty/user/base/sdk/README.md",
+    ]),
     include("./test-map"),
     include("../../proprietary/scripts/build-config", optional=True),
 ]
diff --git a/scripts/build.py b/scripts/build.py
index 7216402..104c262 100755
--- a/scripts/build.py
+++ b/scripts/build.py
@@ -46,9 +46,6 @@ from trusty_build_config import (
 
 from log_processor import LogEngine
 
-script_dir = os.path.dirname(os.path.abspath(__file__))
-
-SDK_README_PATH = "trusty/user/base/sdk/README.md"
 TRUSTED_APP_MAKEFILE_PATH = "trusty/user/base/make/trusted_app.mk"
 TRUSTED_LOADABLE_APP_MAKEFILE_PATH = "trusty/kernel/make/loadable_app.mk"
 GEN_MANIFEST_MAKEFILE_PATH = "trusty/user/base/make/gen_manifest.mk"
@@ -255,11 +252,12 @@ def assemble_sdk(build_config, args):
         archive_file(sdk_archive, TRUSTED_LOADABLE_APP_MAKEFILE_PATH, "make")
         archive_file(sdk_archive, GEN_MANIFEST_MAKEFILE_PATH, "make")
 
-        # Copy SDK README
-        archive_file(sdk_archive, SDK_README_PATH)
+        # Copy doc files
+        for doc_file in build_config.doc_files:
+            archive_file(sdk_archive, doc_file)
 
         # Add clang version info
-        envsetup = os.path.join(script_dir, "envsetup.sh")
+        envsetup = os.path.join(args.script_dir, "envsetup.sh")
         cmd = f"source {envsetup} && echo $CLANG_BINDIR"
         clang_bindir = (
             subprocess.check_output(cmd, shell=True, executable="/bin/bash")
@@ -326,7 +324,7 @@ def build(args):
             f"-f $LKROOT/makefile -j {args.jobs}"
         )
         # Call envsetup.  If it fails, abort.
-        envsetup = os.path.join(script_dir, "envsetup.sh")
+        envsetup = os.path.join(args.script_dir, "envsetup.sh")
         cmd = f"source {envsetup:s} && ({cmd:s})"
 
         # check if we are attached to a real terminal
@@ -478,7 +476,7 @@ def create_uuid_map(args, project):
 
 def create_scripts_archive(args, project):
     """Create an archive for the scripts"""
-    coverage_script = os.path.join(script_dir, "genReport.py")
+    coverage_script = os.path.join(args.script_dir, "genReport.py")
     scripts_zip = os.path.join(
         args.archive, f"{project}-{args.buildid}.scripts.zip"
     )
@@ -667,8 +665,6 @@ def create_test_map(args, build_config, projects):
 
 
 def main(default_config=None, emulator=True):
-    top = os.path.abspath(os.path.join(script_dir, "../../../../.."))
-
     parser = argparse.ArgumentParser()
 
     parser.add_argument(
@@ -681,7 +677,7 @@ def main(default_config=None, emulator=True):
     parser.add_argument(
         "--build-root",
         type=os.path.abspath,
-        default=os.path.join(top, "build-root"),
+        default=None,
         help="Root of intermediate build directory.",
     )
     parser.add_argument(
@@ -760,17 +756,35 @@ def main(default_config=None, emulator=True):
         action="store_true",
         help="Do not use nice to run the build.",
     )
+    parser.add_argument(
+        "--script-dir",
+        type=os.path.abspath,
+        default=os.path.dirname(os.path.abspath(__file__)),
+        help="Override the path to the directory of the script. This is for a "
+             "workaround to support the Soong-built binary."
+    )
     args = parser.parse_args()
 
+
     # Change the current directory to the Trusty root
     # We do this after parsing all the arguments because
-    # some of the paths, e.g., build-root, might be relative
+    # some of the paths, e.g., script-dir, might be relative
     # to the directory that the script was called from, not
     # to the Trusty root directory
+    top = os.path.abspath(os.path.join(args.script_dir, "../../../../.."))
     os.chdir(top)
 
+    if not args.build_root:
+        args.build_root = os.path.join(top, "build-root")
+
+    # Depending on trusty_build_config.py's default config path doesn't work on
+    # the Soong-built python binary.
+    config_file = args.config
+    if not config_file:
+        config_file = os.path.join(args.script_dir, "build-config")
+
     build_config = TrustyBuildConfig(
-        config_file=args.config, android=args.android
+        config_file=config_file, android=args.android
     )
 
     projects = []
diff --git a/scripts/envsetup.sh b/scripts/envsetup.sh
index 0f7f5a9..f6e9147 100644
--- a/scripts/envsetup.sh
+++ b/scripts/envsetup.sh
@@ -28,16 +28,22 @@ gettop() {
     echo $TOPDIR
 }
 
+if [ -z ${TRUSTY_BUILD_CLANG_VERSION} ]; then
+    TRUSTY_BUILD_CLANG_VERSION=clang-r522817
+fi
+if [ -z ${TRUSTY_BUILD_RUST_VERSION} ]; then
+    TRUSTY_BUILD_RUST_VERSION=1.80.1
+fi
 export TRUSTY_TOP=$(gettop)
-export CLANG_BINDIR=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/clang-r498229b/bin
+export CLANG_BINDIR=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/${TRUSTY_BUILD_CLANG_VERSION}/bin
 export CLANG_HOST_LIBDIR=${CLANG_BINDIR}/../lib
 export CLANG_GCC_TOOLCHAIN=${TRUSTY_TOP}/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.17-4.8
 export CLANG_HOST_SYSROOT=${CLANG_GCC_TOOLCHAIN}/sysroot
 export CLANG_HOST_SEARCHDIR=${CLANG_GCC_TOOLCHAIN}/lib/gcc/x86_64-linux/4.8.3
 export CLANG_HOST_LDDIRS="${CLANG_GCC_TOOLCHAIN}/lib/gcc/x86_64-linux/4.8.3 ${CLANG_GCC_TOOLCHAIN}/x86_64-linux/lib64"
 export CLANG_TOOLS_BINDIR=${TRUSTY_TOP}/prebuilts/clang-tools/linux-x86/bin
-export LINUX_CLANG_BINDIR=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/clang-r498229b/bin
-export RUST_BINDIR=${TRUSTY_TOP}/prebuilts/rust/linux-x86/1.80.1/bin
+export LINUX_CLANG_BINDIR=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/${TRUSTY_BUILD_CLANG_VERSION}/bin
+export RUST_BINDIR=${TRUSTY_TOP}/prebuilts/rust/linux-x86/${TRUSTY_BUILD_RUST_VERSION}/bin
 export RUST_HOST_LIBDIR=${RUST_BINDIR}/../lib/rustlib/x86_64-unknown-linux-gnu/lib
 export ARCH_arm_TOOLCHAIN_PREFIX=${CLANG_BINDIR}/llvm-
 export ARCH_arm64_TOOLCHAIN_PREFIX=${CLANG_BINDIR}/llvm-
@@ -78,5 +84,5 @@ export PYTHONPATH
 
 # Bindgen uses clang and libclang at runtime, so we need to tell it where to
 # look for these tools.
-export BINDGEN_CLANG_PATH=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/clang-r498229b/bin/clang
-export BINDGEN_LIBCLANG_PATH=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/clang-r498229b/lib
+export BINDGEN_CLANG_PATH=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/${TRUSTY_BUILD_CLANG_VERSION}/bin/clang
+export BINDGEN_LIBCLANG_PATH=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/${TRUSTY_BUILD_CLANG_VERSION}/lib
diff --git a/scripts/genReport.py b/scripts/genReport.py
index 4d16f5a..fb57f83 100644
--- a/scripts/genReport.py
+++ b/scripts/genReport.py
@@ -25,13 +25,30 @@ import sys
 
 def genProfdata(files, llvmDir):
     llvmProfdataBin = os.path.join(llvmDir, 'llvm-profdata')
-    subprocess_cmd = [llvmProfdataBin, 'merge']
 
-    subprocess_cmd.extend(files)
-    subprocess_cmd.extend(['-o=out.profdata'])
+    # To prevent args characters from exceeding the limitation,
+    # we split the files into several batches and merge them one by one.
+    batch_size = 10
+    profraws_length = len(files)
+    profdata_list = []
+    for offset in range(0, profraws_length, batch_size):
+        profdata_filename = f'{offset}.profdata'
+        profdata_list.append(profdata_filename)
+
+        subprocess_cmd = [llvmProfdataBin, 'merge']
+        subprocess_cmd.extend(files[offset:min(offset+batch_size, profraws_length)])
+        subprocess_cmd.extend([f'-o={profdata_filename}'])
+
+        subprocess.call(subprocess_cmd)
 
+    subprocess_cmd = [llvmProfdataBin, 'merge']
+    subprocess_cmd.extend(profdata_list)
+    subprocess_cmd.extend(['-o=out.profdata'])
     subprocess.call(subprocess_cmd)
 
+    for profdata in profdata_list:
+        os.remove(profdata)
+
 def genHtml(llvmDir, objects, out):
     llvmCovBin = os.path.join(llvmDir, 'llvm-cov')
     subprocess_cmd = [
diff --git a/scripts/run_tests.py b/scripts/run_tests.py
index ad2ff26..c80df71 100755
--- a/scripts/run_tests.py
+++ b/scripts/run_tests.py
@@ -342,6 +342,15 @@ def run_tests(
         try:
             if run := sys.modules.get("run"):
                 if not run.__file__.startswith(project_root):
+                    # Reload qemu and its dependencies because run.py uses them
+                    # We do this in topological sort order
+                    if qemu_error := sys.modules.get("qemu_error"):
+                        importlib.reload(qemu_error)
+                    if qemu_options := sys.modules.get("qemu_options"):
+                        importlib.reload(qemu_options)
+                    if qemu := sys.modules.get("qemu"):
+                        importlib.reload(qemu)
+
                     # run module was imported for another project and needs
                     # to be replaced with the one for the current project.
                     run = importlib.reload(run)
diff --git a/scripts/test-map b/scripts/test-map
index aebc680..c497e91 100644
--- a/scripts/test-map
+++ b/scripts/test-map
@@ -107,6 +107,8 @@
             "qemu-generic-arm32-gicv3-test-debug",
             "qemu-generic-arm32-test-debug",
             "qemu-generic-arm64-fuzz-test-debug",
+            "qemu-generic-arm64-gicv3-spd-ffa-test-debug",
+            "qemu-generic-arm64-gicv3-spd-noffa-test-debug",
             "qemu-generic-arm64-gicv3-test-debug",
             "qemu-generic-arm64-test-debug",
             "qemu-generic-arm64u32-test-debug",
@@ -187,43 +189,55 @@
             # Trusty linux driver tests. Unbind and bind to trigger remove and
             # probe function.
             androidtest(name="irq-driver",
-                        command="echo 'trusty:irq' >"
+                        command="TRUSTY_DEV=$(basename /sys/bus/platform/devices/"
+                                "?(*:)trusty?(-core):irq)"
+                                "&&"
+                                "echo $TRUSTY_DEV >"
                                 "/sys/bus/platform/drivers/trusty-irq/unbind"
                                 "&&"
-                                "echo 'trusty:irq' >"
+                                "echo $TRUSTY_DEV >"
                                 "/sys/bus/platform/drivers/trusty-irq/bind"),
 
             androidtest(name="log-driver",
-                        command="echo 'trusty:log' >"
+                        command="TRUSTY_DEV=$(basename /sys/bus/platform/devices/"
+                                "?(*:)trusty?(-core):log)"
+                                "&&"
+                                "echo $TRUSTY_DEV >"
                                 "/sys/bus/platform/drivers/trusty-log/unbind"
                                 "&&"
-                                "echo 'trusty:log' >"
+                                "echo $TRUSTY_DEV >"
                                 "/sys/bus/platform/drivers/trusty-log/bind"),
 
             androidtest(name="virtio-driver",
                         # virtio remove currently hangs (bug: 142275662).
                         # Disable test until fixed
                         enabled=False,
-                        command="echo 'trusty:virtio' >"
+                        command="TRUSTY_DEV=$(basename /sys/bus/platform/devices/"
+                                "?(*:)trusty?(-core):virtio)"
+                                "&&"
+                                "echo $TRUSTY_DEV >"
                                 "/sys/bus/platform/drivers/trusty-virtio/unbind"
                                 "&&"
-                                "echo 'trusty:virtio' >"
+                                "echo $TRUSTY_DEV >"
                                 "/sys/bus/platform/drivers/trusty-virtio/bind"),
 
             androidtest(name="trusty-driver",
                         # virtio remove currently hangs (bug: 142275662).
                         # Disable affected test until fixed
                         enabled=False,
-                        command="echo trusty >"
-                                "/sys/bus/platform/drivers/trusty/unbind"
+                        command="TRUSTY_DEV=$(basename /sys/bus/platform/devices/"
+                                "?(*:)trusty?(-core))"
                                 "&&"
-                                "echo trusty >"
-                                "/sys/bus/platform/drivers/trusty/bind"),
+                                "echo $TRUSTY_DEV >"
+                                "$(echo /sys/bus/platform/drivers/trusty?(-core)/unbind)"
+                                "&&"
+                                "echo $TRUSTY_DEV >"
+                                "$(echo /sys/bus/platform/drivers/trusty?(-core)/bind)"),
 
             # test that trusty driver started and got a version string
             androidtest(name="trusty-driver-version",
                         command="TRUSTY_VERSION=$(cat /sys/bus/platform/"
-                                "devices/trusty/trusty_version)"
+                                "devices/?(*:)trusty?(-core)/trusty_version)"
                                 "&&"
                                 "echo Trusty version: ${TRUSTY_VERSION}"
                                 "&&"
@@ -260,8 +274,13 @@
                                 "0x800000,10,2,2 "
                                 "0x800000,2,100,0 "
                                 "0x1000,10,10,10' >"
-                                "'/sys/devices/platform/trusty/"
-                                "trusty:test/trusty_test_run'"),
+                                "$(echo /sys/bus/platform/devices/"
+                                "?(*:)trusty?(-core):test/trusty_test_run)"),
+
+            androidtest(name="fpsimdtest",
+                        command="echo 'fpsimd:1000' >"
+                                "$(echo /sys/bus/platform/devices/"
+                                "?(*:)trusty?(-core):test/trusty_test_run)"),
 
             # TIPC tests
             androidtest(name="tipc:ta2ta",
@@ -308,6 +327,50 @@
                                 "/vendor/bin/trusty-ut-ctrl "
                                 "com.android.keymaster-unittest"),
 
+            # Test that storage sessions behave correctly when proxy restarts
+            androidtest(
+                name="com.android.storage-reconnect-test.tp.reconnect",
+                command="/vendor/bin/trusty-ut-ctrl "
+                        "com.android.storage-reconnect-test.tp.before "
+                        "&&"
+                        "stop storageproxyd"
+                        "&&"
+                        "/vendor/bin/trusty-ut-ctrl "
+                        "com.android.storage-reconnect-test.tp.during "
+                        "&&"
+                        "start storageproxyd"
+                        "&&"
+                        "/vendor/bin/trusty-ut-ctrl "
+                        "com.android.storage-reconnect-test.tp.after "),
+            androidtest(
+                name="com.android.storage-reconnect-test.td.reconnect",
+                command="/vendor/bin/trusty-ut-ctrl "
+                        "com.android.storage-reconnect-test.td.before "
+                        "&&"
+                        "stop storageproxyd"
+                        "&&"
+                        "/vendor/bin/trusty-ut-ctrl "
+                        "com.android.storage-reconnect-test.td.during "
+                        "&&"
+                        "start storageproxyd"
+                        "&&"
+                        "/vendor/bin/trusty-ut-ctrl "
+                        "com.android.storage-reconnect-test.td.after "),
+            androidtest(
+                name="com.android.storage-reconnect-test.tdp.reconnect",
+                command="/vendor/bin/trusty-ut-ctrl "
+                        "com.android.storage-reconnect-test.tdp.before "
+                        "&&"
+                        "stop storageproxyd"
+                        "&&"
+                        "/vendor/bin/trusty-ut-ctrl "
+                        "com.android.storage-reconnect-test.tdp.during "
+                        "&&"
+                        "start storageproxyd"
+                        "&&"
+                        "/vendor/bin/trusty-ut-ctrl "
+                        "com.android.storage-reconnect-test.tdp.after "),
+
             # Test confirmation UI
             androidtest(name="vts:confirmationui@1.0",
                         command="/data/nativetest64/"
diff --git a/scripts/trusty_build_config.py b/scripts/trusty_build_config.py
index de9418e..a5f7385 100755
--- a/scripts/trusty_build_config.py
+++ b/scripts/trusty_build_config.py
@@ -277,6 +277,8 @@ class TrustyBuildConfig(object):
         self.projects = {}
         self.dist = []
         self.default_signing_keys = []
+        self.doc_files = []
+
         if config_file is None:
             config_file = os.path.join(script_dir, "build-config")
         self.read_config_file(config_file)
@@ -408,6 +410,8 @@ class TrustyBuildConfig(object):
                     project.signing_keys = []
                 project.signing_keys.extend(overrides)
 
+        def docs(doc_files: List[str]):
+            self.doc_files.extend(doc_files)
 
         file_format = {
             "BENCHMARK": PortType.BENCHMARK,
@@ -430,6 +434,7 @@ class TrustyBuildConfig(object):
             "RebootMode": RebootMode,
             "devsigningkeys": devsigningkeys,
             "print": TrustyPrintCommand,
+            "docs": docs,
         }
 
         with open(path, encoding="utf8") as f:
```

