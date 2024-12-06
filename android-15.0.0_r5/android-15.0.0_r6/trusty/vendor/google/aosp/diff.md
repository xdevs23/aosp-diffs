```diff
diff --git a/lk_inc_aosp.mk b/lk_inc_aosp.mk
index 8afbcec..321b07d 100644
--- a/lk_inc_aosp.mk
+++ b/lk_inc_aosp.mk
@@ -21,6 +21,8 @@ LKINC ?=  $(LKROOT) \
           trusty/user/base \
           trusty/device/arm/generic-arm64 \
           trusty/device/arm/vexpress-a15 \
+          trusty/device/desktop/arm64/desktop-arm64 \
+          trusty/device/desktop/x86_64/desktop-x86_64 \
           trusty/device/nxp/imx7d \
           trusty/device/x86/generic-x86_64 \
           trusty/vendor/google/aosp \
diff --git a/scripts/build-config b/scripts/build-config
index c74f5b6..8c59658 100644
--- a/scripts/build-config
+++ b/scripts/build-config
@@ -59,6 +59,8 @@
 [
     build(
         projects=[
+            "desktop-arm64",
+            "desktop-x86_64",
             "generic-arm32-debug",
             "generic-arm32",
             "generic-arm32-test-debug",
@@ -79,7 +81,6 @@
             "qemu-generic-arm64-fuzz-test-debug",
             "qemu-generic-arm64-gicv3-test-debug",
             "qemu-generic-arm64-test-debug",
-            "qemu-generic-arm64l32-test-debug",
             "qemu-generic-arm64u32-test-debug",
             "qemu-generic-arm64-test-debug-release",
             "qemu-generic-arm32-test-debug-release",
diff --git a/scripts/build.py b/scripts/build.py
index b5752c3..7216402 100755
--- a/scripts/build.py
+++ b/scripts/build.py
@@ -530,6 +530,11 @@ def archive(build_config, args):
             args, project, "trusty_qemu_package.zip", optional=True
         )
 
+        # copy out emulator image package if it exists
+        archive_build_file(
+            args, project, "trusty_image_package.tar.gz", optional=True
+        )
+
         # copy out test package if it exists
         archive_build_file(
             args, project, "trusty_test_package.zip", optional=True
@@ -829,6 +834,7 @@ def main(default_config=None, emulator=True):
             build_config,
             args.build_root,
             projects,
+            qemu_instance_id=None,
             run_disabled_tests=args.run_disabled_tests,
             test_filters=test_filters,
             verbose=args.verbose,
diff --git a/scripts/check_system_dependencies.sh b/scripts/check_system_dependencies.sh
index cfdcbb5..c8fd1df 100755
--- a/scripts/check_system_dependencies.sh
+++ b/scripts/check_system_dependencies.sh
@@ -9,9 +9,7 @@ DEPS=(
   libssl-dev
   libusb-1.0-0-dev
   mypy
-  pkg-config
   pylint
-  xxd
 )
 
 if !(echo ${DEPS[@]} | tr " " "\n" | sort --check); then
diff --git a/scripts/envsetup.sh b/scripts/envsetup.sh
index c733aaa..0f7f5a9 100644
--- a/scripts/envsetup.sh
+++ b/scripts/envsetup.sh
@@ -31,9 +31,13 @@ gettop() {
 export TRUSTY_TOP=$(gettop)
 export CLANG_BINDIR=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/clang-r498229b/bin
 export CLANG_HOST_LIBDIR=${CLANG_BINDIR}/../lib
+export CLANG_GCC_TOOLCHAIN=${TRUSTY_TOP}/prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.17-4.8
+export CLANG_HOST_SYSROOT=${CLANG_GCC_TOOLCHAIN}/sysroot
+export CLANG_HOST_SEARCHDIR=${CLANG_GCC_TOOLCHAIN}/lib/gcc/x86_64-linux/4.8.3
+export CLANG_HOST_LDDIRS="${CLANG_GCC_TOOLCHAIN}/lib/gcc/x86_64-linux/4.8.3 ${CLANG_GCC_TOOLCHAIN}/x86_64-linux/lib64"
 export CLANG_TOOLS_BINDIR=${TRUSTY_TOP}/prebuilts/clang-tools/linux-x86/bin
 export LINUX_CLANG_BINDIR=${TRUSTY_TOP}/prebuilts/clang/host/linux-x86/clang-r498229b/bin
-export RUST_BINDIR=${TRUSTY_TOP}/prebuilts/rust/linux-x86/1.77.1.p1/bin
+export RUST_BINDIR=${TRUSTY_TOP}/prebuilts/rust/linux-x86/1.80.1/bin
 export RUST_HOST_LIBDIR=${RUST_BINDIR}/../lib/rustlib/x86_64-unknown-linux-gnu/lib
 export ARCH_arm_TOOLCHAIN_PREFIX=${CLANG_BINDIR}/llvm-
 export ARCH_arm64_TOOLCHAIN_PREFIX=${CLANG_BINDIR}/llvm-
@@ -42,6 +46,7 @@ export ARCH_x86_TOOLCHAIN_PREFIX=${CLANG_BINDIR}/llvm-
 export BUILDTOOLS_BINDIR=${TRUSTY_TOP}/prebuilts/build-tools/linux-x86/bin
 export BUILDTOOLS_COMMON=${TRUSTY_TOP}/prebuilts/build-tools/common
 export PY3=$BUILDTOOLS_BINDIR/py3-cmd
+export PATH_TOOLS_BINDIR=${TRUSTY_TOP}/prebuilts/build-tools/path/linux-x86
 
 SOONG_UI=$TRUSTY_TOP/build/soong/soong_ui.bash
 if [ -f "$SOONG_UI" ]; then
diff --git a/scripts/genReport.py b/scripts/genReport.py
index 36d3704..4d16f5a 100644
--- a/scripts/genReport.py
+++ b/scripts/genReport.py
@@ -1,4 +1,9 @@
-#
+"""This script helps to generate source based code coverage report.
+
+Usage:
+    python genReport.py --objects [OBJECTS] --format [FORMAT]
+
+"""
 # Copyright (C) 2023 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
@@ -13,22 +18,13 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-"""
-This script helps to generate source based code coverage report.
-
-Usage:
-    python genReport.py --objects [OBJECTS] --format [FORMAT]
-
-"""
-
 import argparse
 import os
 import subprocess
 import sys
-import pathlib
 
 def genProfdata(files, llvmDir):
-    llvmProfdataBin = str(str(os.path.join(llvmDir, "./llvm-profdata")))
+    llvmProfdataBin = os.path.join(llvmDir, 'llvm-profdata')
     subprocess_cmd = [llvmProfdataBin, 'merge']
 
     subprocess_cmd.extend(files)
@@ -37,22 +33,45 @@ def genProfdata(files, llvmDir):
     subprocess.call(subprocess_cmd)
 
 def genHtml(llvmDir, objects, out):
-    llvmCovBin = str(str(os.path.join(llvmDir, "./llvm-cov")))
-    subprocess_cmd = [llvmCovBin, 'show', '-instr-profile=out.profdata', '-object']
-
+    llvmCovBin = os.path.join(llvmDir, 'llvm-cov')
+    subprocess_cmd = [
+        llvmCovBin,
+        'show',
+        '-instr-profile=out.profdata',
+    ]
     subprocess_cmd.extend(objects)
     subprocess_cmd.extend(['-use-color', '--format=html'])
-    with(open(out+".html", "w")) as f:
-        output = subprocess.call(subprocess_cmd, stdout=f)
-
-def genJson(llvmDir, objects, out):
-    llvmCovBin = str(str(os.path.join(llvmDir, "./llvm-cov")))
-    subprocess_cmd = [llvmCovBin, 'export', '-summary-only',
-                       '-instr-profile=out.profdata', '-object']
-
+    with(open(out+'.html', 'w', encoding='utf-8')) as f:
+        subprocess.call(subprocess_cmd, stdout=f)
+
+def genJson(llvmDir, objects, out, summary_only=True):
+    llvmCovBin = os.path.join(llvmDir, 'llvm-cov')
+    subprocess_cmd = [
+        llvmCovBin,
+        'export',
+        '-instr-profile=out.profdata',
+    ]
+    subprocess_cmd.extend(objects)
+    if summary_only:
+        subprocess_cmd.extend(['-summary-only'])
+
+    with(open(out+'.json', 'w', encoding='utf-8')) as f:
+        subprocess.call(subprocess_cmd, stdout=f)
+
+def genLcov(llvmDir, objects, out, summary_only=True):
+    llvmCovBin = os.path.join(llvmDir, 'llvm-cov')
+    subprocess_cmd = [
+        llvmCovBin,
+        'export',
+        '-format=lcov',
+        '-instr-profile=out.profdata',
+    ]
     subprocess_cmd.extend(objects)
-    with(open(out+".json", "w")) as f:
-        output = subprocess.call(subprocess_cmd, stdout=f)
+    if summary_only:
+        subprocess_cmd.extend(['-summary-only'])
+
+    with(open(out+'.lcov', 'w', encoding='utf-8')) as f:
+        subprocess.call(subprocess_cmd, stdout=f)
 
 
 def main():
@@ -75,48 +94,58 @@ def main():
     arg_parser.add_argument(
         '--llvm-dir',
         type=str,
-        default="prebuilts/clang/host/linux-x86/llvm-binutils-stable/",
-        help='Provide path to LLVM binary directory to override the default one')
+        default='prebuilts/clang/host/linux-x86/llvm-binutils-stable/',
+        help='Provide path to LLVM binary directory to override the default '
+             'one')
 
     arg_parser.add_argument(
         '--profraw-dir',
         type=str,
-        default="tmp/",
+        default='tmp/',
         help='Provide path to directory containing .profraw files')
 
     arg_parser.add_argument(
         '--output',
         type=str,
-        default="out",
-        help='provide output filename(without extension)')
+        default='out',
+        help='Provide output filename(without extension)')
 
+    arg_parser.add_argument(
+        '--summary-only',
+        default=True,
+        action=argparse.BooleanOptionalAction,
+        help='Flag of whether to enable summary only')
 
     args = arg_parser.parse_args()
 
-    if (not os.path.isdir(args.llvm_dir)):
-        print("Provide path to LLVM binary directory")
+    if not os.path.isdir(args.llvm_dir):
+        print('Provide path to LLVM binary directory')
         return
 
-    if (not os.path.isdir(args.profraw_dir)):
-        print("Provide path to directory containing .profraw files")
+    if not os.path.isdir(args.profraw_dir):
+        print('Provide path to directory containing .profraw files')
         return
 
-    profrawFiles = [str(os.path.join(args.profraw_dir, f))
-                        for f in os.listdir(args.profraw_dir) if f.endswith('.profraw')]
-    if (len(profrawFiles) == 0):
-        print("No profraw files found in directory " + args.profraw_dir)
+    profrawFiles = [
+        os.path.join(args.profraw_dir, f)
+        for f in os.listdir(args.profraw_dir) if f.endswith('.profraw')]
+    if len(profrawFiles) == 0:
+        print('No profraw files found in directory ' + args.profraw_dir)
 
     genProfdata(profrawFiles, args.llvm_dir)
-
-    if (args.format == "html"):
-        genHtml(args.llvm_dir, args.objects, args.output)
-
-    elif (args.format == "json"):
-        genJson(args.llvm_dir, args.objects, args.output)
-
+    objects = []
+    for obj in args.objects:
+        objects.extend(['-object', obj])
+
+    if args.format == 'html':
+        genHtml(args.llvm_dir, objects, args.output)
+    elif args.format == 'json':
+        genJson(args.llvm_dir, objects, args.output, args.summary_only)
+    elif args.format == 'lcov':
+        genLcov(args.llvm_dir, objects, args.output, args.summary_only)
     else:
-        print("Only json and html supported")
+        print('Only json / html / lcov supported')
         return
 
 if __name__ == '__main__':
-    sys.exit(main())
\ No newline at end of file
+    sys.exit(main())
diff --git a/scripts/run_tests.py b/scripts/run_tests.py
index 913b7ac..ad2ff26 100755
--- a/scripts/run_tests.py
+++ b/scripts/run_tests.py
@@ -40,6 +40,7 @@ from typing import Optional
 from trusty_build_config import PortType, TrustyCompositeTest, TrustyTest
 from trusty_build_config import TrustyAndroidTest, TrustyBuildConfig
 from trusty_build_config import TrustyHostTest, TrustyRebootCommand
+from trusty_build_config import TrustyPrintCommand
 
 
 TEST_STATUS = Enum("TEST_STATUS", ["PASSED", "FAILED", "SKIPPED"])
@@ -301,6 +302,7 @@ def run_tests(
     build_config: TrustyBuildConfig,
     root: os.PathLike,
     project: str,
+    qemu_instance_id: Optional[str],
     run_disabled_tests: bool = False,
     test_filters: Optional[list[re.Pattern]] = None,
     verbose: bool = False,
@@ -313,6 +315,9 @@ def run_tests(
         build_config: TrustyBuildConfig object.
         root: Trusty build root output directory.
         project: Project name.
+        qemu_instance_id: name of the QEmu instance to use. If the instance
+            doesn't already exist, a new fresh instance will be created. If
+            None, use the default instance.
         run_disabled_tests: Also run disabled tests from config file.
         test_filters: Optional list that limits the tests to run.
         verbose: Enable debug output.
@@ -328,6 +333,10 @@ def run_tests(
     test_env = None
     test_runner = None
 
+    if not qemu_instance_id:
+        qemu_instance_id = "default"
+    qemu_instance_dir = f"{project_root}/qemu-instances/{qemu_instance_id}"
+
     def load_test_environment():
         sys.path.append(project_root)
         try:
@@ -412,6 +421,7 @@ def run_tests(
                         if not test_runner:
                             test_runner = test_env.init(
                                 android=build_config.android,
+                                instance_dir=qemu_instance_dir,
                                 disable_rpmb=disable_rpmb,
                                 verbose=verbose,
                                 debug_on_error=debug_on_error,
@@ -423,9 +433,11 @@ def run_tests(
             case TrustyRebootCommand() if parent_test:
                 assert isinstance(parent_test, TrustyCompositeTest)
                 if test_env:
-                    test_env.shutdown(test_runner)
+                    test_env.shutdown(test_runner, test.mode.factory_reset(),
+                                      full_wipe=test.mode.full_wipe())
                     test_runner = None
-                    print("Shut down test environment on", test_results.project)
+                    print(f"Shutting down to {test.mode} test environment on "
+                          f"{test_results.project}")
                 # return early so we do not report the time to reboot or try to
                 # add the reboot command to test results.
                 return None
@@ -433,6 +445,13 @@ def run_tests(
                 raise RuntimeError(
                     "Reboot may only be used inside compositetest"
                 )
+            case TrustyPrintCommand() if parent_test:
+                print(test.msg())
+                return None
+            case TrustyPrintCommand():
+                raise RuntimeError(
+                    "Print may only be used inside compositetest"
+                )
             case _:
                 raise NotImplementedError(f"Don't know how to run {test.name}")
 
@@ -490,6 +509,7 @@ def test_projects(
     build_config: TrustyBuildConfig,
     root: os.PathLike,
     projects: list[str],
+    qemu_instance_id: Optional[str] = None,
     run_disabled_tests: bool = False,
     test_filters: Optional[list[re.Pattern]] = None,
     verbose: bool = False,
@@ -502,6 +522,9 @@ def test_projects(
         build_config: TrustyBuildConfig object.
         root: Trusty build root output directory.
         projects: Names of the projects to run tests for.
+        qemu_instance_id: name of the QEmu instance to use. If the instance
+            doesn't already exist, a new fresh instance will be created. If
+            None, use the default instance.
         run_disabled_tests: Also run disabled tests from config file.
         test_filters: Optional list that limits the tests to run. Projects
           without any tests that match a filter will be skipped.
@@ -526,6 +549,7 @@ def test_projects(
                 build_config,
                 root,
                 project,
+                qemu_instance_id=qemu_instance_id,
                 run_disabled_tests=run_disabled_tests,
                 test_filters=test_filters,
                 verbose=verbose,
@@ -547,6 +571,14 @@ def main():
     parser.add_argument(
         "project", type=str, nargs="+", help="Project(s) to test."
     )
+    parser.add_argument(
+        "--instance-id",
+        type=str,
+        default=None,
+        help=("ID of a QEmu instance to use for the tests. A fresh instance "
+              "will be created if no instance with this ID already exists."
+              "'default' will be used if no value is provided.")
+    )
     parser.add_argument(
         "--build-root",
         type=str,
@@ -572,9 +604,14 @@ def main():
         help="Wait for debugger connection on errors.",
         action="store_true",
     )
+    parser.add_argument(
+        "--android",
+        type=str,
+        help="Path to an Android build to run tests against.",
+    )
     args = parser.parse_args()
 
-    build_config = TrustyBuildConfig()
+    build_config = TrustyBuildConfig(android=args.android)
 
     test_filters = (
         [re.compile(test) for test in args.test] if args.test else None
@@ -583,6 +620,7 @@ def main():
         build_config,
         args.build_root,
         args.project,
+        qemu_instance_id=args.instance_id,
         run_disabled_tests=args.run_disabled_tests,
         test_filters=test_filters,
         verbose=args.verbose,
diff --git a/scripts/test-map b/scripts/test-map
index c80a1f5..aebc680 100644
--- a/scripts/test-map
+++ b/scripts/test-map
@@ -123,6 +123,65 @@
             androidporttests([
                 include("trusty/kernel/build-config-kerneltests"),
                 include("trusty/user/base/build-config-usertests"),
+
+                # Test automatic clearing of td filesystem when userdata is cleared
+                # - Stage 1
+                # -- Wipe user-data and reboot
+                # -- Create a valid filesystem (with both superblocks written)
+                #
+                # - Stage 2
+                # -- Wipe user-data and reboot
+                # -- Create a valid filesystem (with a single committed superblock)
+                # -- Reboot (keep all data)
+                # -- Check that filesystem is accessible (with a small uncommitted
+                #    transaction to more avoid super block updates)
+                #
+                #    If only one super block was written, it could have used the
+                #    wrong version. If the new filesystem always writes superblock
+                #    version 1, then it will fail if the old version was 2 or 3 as
+                #    those two starting points have version 2 in the first
+                #    superblock. Stage one will leave the filesystem at version 2 if
+                #    b/190109878 has not been fixed or at version 3 if it has been
+                #    partially fixed.
+                #
+                # - Stage 3
+                # -- Wipe user-data and reboot
+                # -- Write to the filesystem without commiting anything
+                # -- Reboot (Should trigger cleanup path for b/190109878
+                #    bugfix as generated initial superblock is not needed)
+                #
+                # - Stage 4
+                # -- Write a large transaction to the filesystem without commiting
+                #    anything
+                # -- Reboot
+                # -- Check that filesystem is accessible. If superblock was not
+                #    written (b/190109878) this step would fail as the data file is
+                #    no longer empty, but the old super blocks refer to data in the
+                #    previous deleted file.
+                # -- Trigger cleanup in test app.
+                compositetest(
+                    name="storage-td-clear-test",
+                    sequence=[
+                        print("[ -------- ] Stage 1 - 2 commit setup"),
+                        reboot(mode=RebootMode.FACTORY_RESET),
+                        porttest("com.android.storage-unittest.td.init"),
+                        porttest("com.android.storage-unittest.td.init"),
+                        print("[ -------- ] Stage 2 - 1 commit setup"),
+                        reboot(mode=RebootMode.FACTORY_RESET),
+                        porttest("com.android.storage-unittest.td.init"),
+                        reboot(mode=RebootMode.REGULAR),
+                        porttest("com.android.storage-unittest.td.initnocommitsmall"),
+                        print("[ -------- ] Stage 3 - no commit small"),
+                        reboot(mode=RebootMode.FACTORY_RESET),
+                        porttest("com.android.storage-unittest.td.initnocommitsmall"),
+                        reboot(mode=RebootMode.REGULAR),
+                        print("[ -------- ] Stage 4 - no commit large"),
+                        porttest("com.android.storage-unittest.td.initnocommitlarge"),
+                        reboot(mode=RebootMode.REGULAR),
+                        porttest("com.android.storage-unittest.td.initnocommitsmall"),
+                        porttest("com.android.storage-unittest.td.initnocommitcleanup"),
+                    ]
+                ).needs(storage_full=True),
             ]),
 
             # Trusty linux driver tests. Unbind and bind to trigger remove and
@@ -174,10 +233,12 @@
                                 "exit 1;"
                                 "fi"),
 
+            # Check whether the kernel has been tainted, ignoring
+            # certain causes like out-of-tree and unsigned modules.
             androidtest(name="untainted-linux",
                         command="TAINTED=$(cat /proc/sys/kernel/tainted)"
                                 "&&"
-                                "if [[ \"${TAINTED}\" != \"0\" ]];"
+                                "if (( ${TAINTED} & ~0x3000 ));"
                                 "then "
                                 "echo Linux kernel tainted ${TAINTED};"
                                 "exit 1;"
@@ -247,102 +308,6 @@
                                 "/vendor/bin/trusty-ut-ctrl "
                                 "com.android.keymaster-unittest"),
 
-            # Test automatic clearing of td filesystem when userdata is cleared
-            # - Stage 1
-            # -- Simulate user-data wipe (by removing data/vendor/ss/0 and
-            #    restarting storageproxyd)
-            # -- Create a valid filesystem (with both superblocks written)
-            #
-            # - Stage 2
-            # -- Simulate user-data wipe
-            # -- Create a valid filesystem (with a single committed superblock)
-            # -- Simulate reboot (by restarting storageproxyd)
-            # -- Check that filesystem is accessible (with a small uncommitted
-            #    transaction to more avoid super block updates)
-            #
-            #    If only one super block was written, it could have used the
-            #    wrong version. If the new filesystem always writes superblock
-            #    version 1, then it will fail if the old version was 2 or 3 as
-            #    those two starting points have version 2 in the first
-            #    superblock. Stage one will leave the filesystem at version 2 if
-            #    b/190109878 has not been fixed or at version 3 if it has been
-            #    partially fixed.
-            #
-            # - Stage 3
-            # -- Simulate user-data wipe
-            # -- Write to the filesystem without commiting anything
-            # -- Simulate reboot (Should trigger cleanup path for b/190109878
-            #    bugfix as generated initial superblock is not needed)
-            #
-            # - Stage 4
-            # -- Write a large transaction to the filesystem without commiting
-            #    anything
-            # -- Simulate reboot
-            # -- Check that filesystem is accessible. If superblock was not
-            #    written (b/190109878) this step would fail as the data file is
-            #    no longer empty, but the old super blocks refer to data in the
-            #    previous deleted file.
-            # -- Trigger cleanup in test app.
-            androidtest(name="storage-td-clear-test",
-                        command="function storage-unittest { "
-                                "/vendor/bin/trusty-ut-ctrl "
-                                "com.android.storage-unittest.$1"
-                                ";}"
-                                "&&"
-                                "function wipe-restart-storageproxyd { "
-                                "echo '[ -------- ] wipe-restart-storageproxyd'"
-                                "&&"
-                                "stop storageproxyd"
-                                "&&"
-                                "rm /data/vendor/ss/0"
-                                "&&"
-                                "start storageproxyd"
-                                ";}"
-                                "&&"
-                                "function restart-storageproxyd { "
-                                "echo '[ -------- ] restart-storageproxyd'"
-                                "&&"
-                                "stop storageproxyd"
-                                "&&"
-                                "start storageproxyd"
-                                ";}"
-                                "&&"
-                                "echo '[ -------- ] Stage 1 - 2 commit setup'"
-                                "&&"
-                                "wipe-restart-storageproxyd"
-                                "&&"
-                                "storage-unittest td.init"
-                                "&&"
-                                "storage-unittest td.init"
-                                "&&"
-                                "echo '[ -------- ] Stage 2 - 1 commit setup'"
-                                "&&"
-                                "wipe-restart-storageproxyd"
-                                "&&"
-                                "storage-unittest td.init"
-                                "&&"
-                                "restart-storageproxyd"
-                                "&&"
-                                "storage-unittest td.initnocommitsmall"
-                                "&&"
-                                "echo '[ -------- ] Stage 3 - no commit small'"
-                                "&&"
-                                "wipe-restart-storageproxyd"
-                                "&&"
-                                "storage-unittest td.initnocommitsmall"
-                                "&&"
-                                "restart-storageproxyd"
-                                "&&"
-                                "echo '[ -------- ] Stage 4 - no commit large'"
-                                "&&"
-                                "storage-unittest td.initnocommitlarge"
-                                "&&"
-                                "restart-storageproxyd"
-                                "&&"
-                                "storage-unittest td.initnocommitsmall"
-                                "&&"
-                                "storage-unittest td.initnocommitcleanup"),
-
             # Test confirmation UI
             androidtest(name="vts:confirmationui@1.0",
                         command="/data/nativetest64/"
@@ -484,7 +449,7 @@
             androidtest(name="binder-rpc-to-trusty-test",
                         command="/data/nativetest64/vendor/"
                                 "binderRpcToTrustyTest/"
-                                "binderRpcToTrustyTest"),
+                                "binderRpcToTrustyTest64"),
         ],
     ),
 ]
diff --git a/scripts/trusty_build_config.py b/scripts/trusty_build_config.py
index e2fb67c..de9418e 100755
--- a/scripts/trusty_build_config.py
+++ b/scripts/trusty_build_config.py
@@ -185,16 +185,50 @@ class TrustyCommand:
         return self
 
 
+class RebootMode(StrEnum):
+    REGULAR = "reboot"
+    FACTORY_RESET = "reboot (with factory reset)"
+    FULL_WIPE = "reboot (with full wipe)"
+
+    def factory_reset(self) -> bool:
+        """Whether this reboot includes a factory reset.
+        This function exists because we can't make the test runner module depend
+        on types defined here, so its function args have to be builtins.
+        """
+        match self:
+            case RebootMode.REGULAR:
+                return False
+            case RebootMode.FACTORY_RESET:
+                return True
+            case RebootMode.FULL_WIPE:
+                return True
+
+    def full_wipe(self) -> bool:
+        """Whether this reboot includes a an RPMB wipe.
+        This function exists because we can't make the test runner module depend
+        on types defined here, so its function args have to be builtins.
+        """
+        match self:
+            case RebootMode.REGULAR:
+                return False
+            case RebootMode.FACTORY_RESET:
+                return False
+            case RebootMode.FULL_WIPE:
+                return True
+
+
 class TrustyRebootCommand(TrustyCommand):
     """Marker object which causes the test environment to be rebooted before the
        next test is run. Used to reset the test environment and to test storage.
-
-       TODO: The current qemu.py script does a factory reset as part a reboot.
-             We probably want a parameter or separate command to control that.
     """
-    def __init__(self):
-        super().__init__("reboot command")
+    def __init__(self, mode: RebootMode = RebootMode.FACTORY_RESET):
+        super().__init__(mode)
+        self.mode = mode
+
+class TrustyPrintCommand(TrustyCommand):
 
+    def msg(self) -> str:
+        return self.name
 
 class TrustyCompositeTest(TrustyTest):
     """Stores a sequence of tests that must execute in order"""
@@ -393,7 +427,9 @@ class TrustyBuildConfig(object):
             "androidporttests": androidporttests,
             "needs": needs,
             "reboot": TrustyRebootCommand,
+            "RebootMode": RebootMode,
             "devsigningkeys": devsigningkeys,
+            "print": TrustyPrintCommand,
         }
 
         with open(path, encoding="utf8") as f:
```

