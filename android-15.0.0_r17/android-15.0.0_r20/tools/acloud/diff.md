```diff
diff --git a/create/avd_spec.py b/create/avd_spec.py
index 5eafe30..0b8172f 100644
--- a/create/avd_spec.py
+++ b/create/avd_spec.py
@@ -180,6 +180,7 @@ class AVDSpec():
         # Fields only used for trusty type.
         self._local_trusty_image = None
         self._trusty_host_package = None
+        self._trusty_build_info = {}
 
         # The maximum time in seconds used to wait for the AVD to boot.
         self._boot_timeout_secs = None
@@ -431,6 +432,12 @@ class AVDSpec():
                 instance = list_instance.ChooseOneRemoteInstance(self._cfg)
                 self._instance_name_to_reuse = instance.name
 
+        self._local_trusty_image = args.local_trusty_image
+        self._trusty_build_info = {
+            constants.BUILD_ID: args.trusty_build_id,
+            constants.BUILD_BRANCH: args.trusty_branch,
+            constants.BUILD_TARGET: args.trusty_build_target}
+
     def _GetFetchCVDVersion(self, args):
         """Get the fetch_cvd version.
 
@@ -484,7 +491,6 @@ class AVDSpec():
             self._ProcessFVPLocalImageArgs()
         elif self._avd_type == constants.TYPE_TRUSTY:
             self._ProcessTrustyLocalImageArgs(args.local_image)
-            self._local_trusty_image = args.local_trusty_image
         elif self._avd_type == constants.TYPE_GF:
             local_image_path = self._GetLocalImagePath(args.local_image)
             if os.path.isdir(local_image_path):
@@ -1227,6 +1233,11 @@ class AVDSpec():
         """Return trusty_host_package."""
         return self._trusty_host_package
 
+    @property
+    def trusty_build_info(self):
+        """Return trusty_build_info."""
+        return self._trusty_build_info
+
     @property
     def extra_files(self):
         """Return extra_files."""
diff --git a/create/avd_spec_test.py b/create/avd_spec_test.py
index 018fff1..33807cf 100644
--- a/create/avd_spec_test.py
+++ b/create/avd_spec_test.py
@@ -400,6 +400,11 @@ class AvdSpecTest(driver_test_lib.BaseDriverTest):
         self.AvdSpec._ProcessRemoteBuildArgs(self.args)
         self.assertTrue(self.AvdSpec.avd_type == "goldfish")
 
+        # Verify auto-assigned avd_type if build_target contains "_trusty_".
+        self.args.build_target = "qemu_trusty_arm64-trunk_staging-userdebug"
+        self.AvdSpec._ProcessRemoteBuildArgs(self.args)
+        self.assertTrue(self.AvdSpec.avd_type == "trusty")
+
         # Verify extra build info.
         self.args.system_branch = "system_branch"
         self.args.system_build_target = "system_build_target"
@@ -577,6 +582,16 @@ class AvdSpecTest(driver_test_lib.BaseDriverTest):
         self.AvdSpec._ProcessMiscArgs(self.args)
         self.assertEqual(self.AvdSpec.fetch_cvd_version, "23456")
 
+        self.args.trusty_branch = "trusty_branch"
+        self.args.trusty_build_id = "trusty_build_id"
+        self.args.trusty_build_target = "trusty_build_target"
+        self.AvdSpec._ProcessMiscArgs(self.args)
+        self.assertEqual(
+            {constants.BUILD_BRANCH: "trusty_branch",
+             constants.BUILD_TARGET: "trusty_build_target",
+             constants.BUILD_ID: "trusty_build_id"},
+            self.AvdSpec.trusty_build_info)
+
 
 if __name__ == "__main__":
     unittest.main()
diff --git a/create/create.py b/create/create.py
index 6487827..a8bcb16 100644
--- a/create/create.py
+++ b/create/create.py
@@ -91,6 +91,8 @@ _CREATOR_CLASS_DICT = {
     # Trusty types
     (constants.TYPE_TRUSTY, constants.IMAGE_SRC_LOCAL, constants.INSTANCE_TYPE_REMOTE):
         local_image_remote_instance.LocalImageRemoteInstance,
+    (constants.TYPE_TRUSTY, constants.IMAGE_SRC_REMOTE, constants.INSTANCE_TYPE_REMOTE):
+        remote_image_remote_instance.RemoteImageRemoteInstance,
 }
 
 
diff --git a/create/create_args.py b/create/create_args.py
index 505b86c..1d2ede3 100644
--- a/create/create_args.py
+++ b/create/create_args.py
@@ -261,19 +261,21 @@ def AddCommonCreateArgs(parser):
         type=str,
         dest="host_package_branch",
         required=False,
-        help="'cuttlefish only' Host package branch name. e.g. aosp-main")
+        help="'cuttlefish and trusty only' Host package branch name. e.g. "
+        "aosp-main")
     parser.add_argument(
         "--host-package-build-id", "--host_package_build_id",
         type=str,
         dest="host_package_build_id",
         required=False,
-        help="'cuttlefish only' Host package build id, e.g. 2145099, P2804227")
+        help="'cuttlefish and trusty only' Host package build id, e.g. "
+        "2145099, P2804227")
     parser.add_argument(
         "--host-package-build-target", "--host_package_build_target",
         type=str,
         dest="host_package_build_target",
         required=False,
-        help="'cuttlefish only' Host package build target, e.g. "
+        help="'cuttlefish and trusty only' Host package build target, e.g. "
         "cf_x86_64_phone-userdebug.")
     parser.add_argument(
         "--system-branch",
@@ -638,15 +640,6 @@ def GetCreateArgParser(subparser):
         "if no argument is provided. e.g., --local-vendor-boot-image, or "
         "--local-vendor-boot-image /path/to/dir, or "
         "--local-vendor-boot-image /path/to/img")
-    create_parser.add_argument(
-        "--local-trusty-image",
-        type=str,
-        dest="local_trusty_image",
-        required=False,
-        help="'trusty only' Use the specified path for the locally built "
-        "trusty emulator images package, built with "
-        "PACKAGE_TRUSTY_IMAGE_TARBALL=true in the Trusty build. E.g., "
-        "/path/trusty_image_package.tar.gz")
     create_parser.add_argument(
         "--local-tool",
         type=str,
@@ -664,13 +657,6 @@ def GetCreateArgParser(subparser):
         required=False,
         help="Use the specified path of the cvd host package to create "
         "instances. e.g. /path/cvd-host_package_v1.tar.gz")
-    create_parser.add_argument(
-        "--trusty-host-package",
-        type=str,
-        dest="trusty_host_package",
-        required=False,
-        help="Use the specified path of the trusty host package to create "
-        "instances. e.g. /path/trusty-host_package.tar.gz")
     create_parser.add_argument(
         "--image-download-dir",
         type=str,
@@ -836,6 +822,43 @@ def GetCreateArgParser(subparser):
         default=[],
         help=("'cheeps only' Cheeps feature to enable. Can be repeated."))
 
+    # Arguments for trusty type
+    create_parser.add_argument(
+        "--trusty-host-package",
+        type=str,
+        dest="trusty_host_package",
+        required=False,
+        help="Use the specified path of the trusty host package to create "
+        "instances. e.g. /path/trusty-host_package.tar.gz")
+    create_parser.add_argument(
+        "--local-trusty-image",
+        type=str,
+        dest="local_trusty_image",
+        required=False,
+        help="'trusty only' Use the specified path for the locally built "
+        "trusty emulator images package, built with "
+        "PACKAGE_TRUSTY_IMAGE_TARBALL=true in the Trusty build. E.g., "
+        "/path/trusty_image_package.tar.gz")
+    create_parser.add_argument(
+        "--trusty-build-id",
+        type=str,
+        dest="trusty_build_id",
+        required=False,
+        help="Trusty image package build ID, e.g., 8747889, 8748012.")
+    create_parser.add_argument(
+        "--trusty-branch",
+        type=str,
+        dest="trusty_branch",
+        required=False,
+        help="Trusty image package branch, e.g., aosp-trusty-master.")
+    create_parser.add_argument(
+        "--trusty-build-target",
+        type=str,
+        dest="trusty_build_target",
+        required=False,
+        help="Trusty image package build target, "
+        "e.g., qemu_generic_arm64_test_debug.")
+
     AddCommonCreateArgs(create_parser)
     return create_parser
 
@@ -1016,14 +1039,54 @@ def _VerifyTrustyArgs(args):
         # Only check these args if AVD type is Trusty
         return
 
-    if args.local_trusty_image is None:
+    for arg_type, unsupported_args in [
+        (
+            "--boot-*",
+            [
+                args.boot_build_id,
+                args.boot_build_target,
+                args.boot_branch,
+                args.boot_artifact,
+            ],
+        ),
+        (
+            "--bootloader-*",
+            [
+                args.bootloader_build_id,
+                args.bootloader_build_target,
+                args.bootloader_branch,
+            ],
+        ),
+        (
+            "--android-efi-loader-*",
+            [
+                args.android_efi_loader_build_id,
+                args.android_efi_loader_artifact,
+            ],
+        ),
+        (
+            "--ota-*",
+            [
+                args.ota_branch,
+                args.ota_build_target,
+                args.ota_build_id,
+            ],
+        ),
+    ]:
+        if any(unsupported_args):
+            raise errors.UnsupportedCreateArgs(
+                f"{arg_type} is not supported for Trusty."
+            )
+
+    if args.local_image is None and not args.build_target:
         raise errors.UnsupportedCreateArgs(
-            "Trusty image package not provided, use --local-trusty-image to "
-            "specify path to trusty_image_package.tar.gz containing trusty "
-            "images.")
-    if not os.path.exists(args.local_trusty_image):
-        raise errors.CheckPathError(
-            f"Specified path doesn't exist: {args.local_trusty_image}")
+            "Trusty android build target not provided and cannot be "
+            "auto-detected, use --build-target to specify a build target, "
+            "e.g. qemu_trusty_arm64-trunk_staging-userdebug")
+    if args.local_trusty_image:
+        if not os.path.exists(args.local_trusty_image):
+            raise errors.CheckPathError(
+                f"Specified path doesn't exist: {args.local_trusty_image}")
     if args.trusty_host_package:
         if not os.path.exists(args.trusty_host_package):
             raise errors.CheckPathError(
diff --git a/create/create_args_test.py b/create/create_args_test.py
index e32bc1b..b5737ef 100644
--- a/create/create_args_test.py
+++ b/create/create_args_test.py
@@ -44,6 +44,9 @@ def _CreateArgs():
         local_vendor_boot_image=None,
         local_trusty_image=None,
         trusty_host_package=None,
+        trusty_build_id=None,
+        trusty_branch=None,
+        trusty_build_target=None,
         kernel_branch=None,
         kernel_build_id=None,
         kernel_build_target="kernel",
@@ -54,6 +57,14 @@ def _CreateArgs():
         system_branch=None,
         system_build_id=None,
         system_build_target=None,
+        bootloader_branch=None,
+        bootloader_build_id=None,
+        bootloader_build_target=None,
+        android_efi_loader_build_id=None,
+        android_efi_loader_artifact=None,
+        ota_branch=None,
+        ota_build_id=None,
+        ota_build_target=None,
         local_instance=None,
         remote_host=None,
         remote_image_dir=None,
@@ -128,6 +139,29 @@ class CreateArgsTest(driver_test_lib.BaseDriverTest):
         mock_args.remote_host = "192.0.2.2"
         create_args.VerifyArgs(mock_args)
 
+    def testVerifyTrustyArgs(self):
+        """test trusty arguments."""
+        self.Patch(os.path, "exists", return_value=True)
+
+        # wrong avd_type.
+        mock_args = _CreateArgs()
+        mock_args.local_trusty_image = "trusty_image_package.tar.gz"
+        self.assertRaises(errors.UnsupportedCreateArgs,
+                          create_args.VerifyArgs, mock_args)
+        mock_args = _CreateArgs()
+        mock_args.trusty_host_package = "trusty-host_package.tar.gz"
+        self.assertRaises(errors.UnsupportedCreateArgs,
+                          create_args.VerifyArgs, mock_args)
+        mock_args.local_trusty_image = "trusty_image_package.tar.gz"
+        # valid args for Trusty avd type.
+        mock_args.avd_type = constants.TYPE_TRUSTY
+        create_args.VerifyArgs(mock_args)
+        # remote image requires an explicit build target
+        mock_args.build_target = None
+        mock_args.local_image = None
+        self.assertRaises(errors.UnsupportedCreateArgs,
+                          create_args.VerifyArgs, mock_args)
+
     def testVerifyArgs_ConnectWebRTC(self):
         """test VerifyArgs args.autconnect webrtc.
 
@@ -180,18 +214,6 @@ class CreateArgsTest(driver_test_lib.BaseDriverTest):
         self.assertRaises(errors.UnsupportedCreateArgs,
                           create_args._VerifyLocalArgs, mock_args)
 
-        # wrong avd_type
-        mock_args = _CreateArgs()
-        mock_args.local_trusty_image = "/tmp/trusty_image_package.tar.gz"
-        self.assertRaises(errors.UnsupportedCreateArgs,
-                          create_args.VerifyArgs, mock_args)
-
-        # wrong avd_type
-        mock_args = _CreateArgs()
-        mock_args.trusty_host_package = "/tmp/trusty_host_package.tar.gz"
-        self.assertRaises(errors.UnsupportedCreateArgs,
-                          create_args.VerifyArgs, mock_args)
-
 
 if __name__ == "__main__":
     unittest.main()
diff --git a/create/remote_image_remote_instance.py b/create/remote_image_remote_instance.py
index c1f7753..25aea4b 100644
--- a/create/remote_image_remote_instance.py
+++ b/create/remote_image_remote_instance.py
@@ -30,6 +30,7 @@ from acloud.internal.lib import oxygen_client
 from acloud.internal.lib import utils
 from acloud.public.actions import common_operations
 from acloud.public.actions import remote_instance_cf_device_factory
+from acloud.public.actions import remote_instance_trusty_device_factory
 from acloud.public import report
 
 
@@ -62,13 +63,22 @@ class RemoteImageRemoteInstance(base_avd_create.BaseAVDCreate):
             return self._LeaseOxygenAVD(avd_spec)
         if avd_spec.gce_only:
             return self._CreateGceInstance(avd_spec)
-        device_factory = remote_instance_cf_device_factory.RemoteInstanceDeviceFactory(
-            avd_spec)
+        if avd_spec.avd_type == constants.TYPE_CF:
+            command = "create_cf"
+            device_factory = remote_instance_cf_device_factory.RemoteInstanceDeviceFactory(
+                avd_spec)
+        elif avd_spec.avd_type == constants.TYPE_TRUSTY:
+            command = "create_trusty"
+            device_factory = remote_instance_trusty_device_factory.RemoteInstanceDeviceFactory(
+                avd_spec)
+        else:
+            # This type isn't correctly registered in create.py.
+            raise ValueError(f"Unsupported AVD type: {avd_spec.avd_type}")
         create_report = common_operations.CreateDevices(
-            "create_cf", avd_spec.cfg, device_factory, avd_spec.num,
+            command, avd_spec.cfg, device_factory, avd_spec.num,
             report_internal_ip=avd_spec.report_internal_ip,
             autoconnect=avd_spec.autoconnect,
-            avd_type=constants.TYPE_CF,
+            avd_type=avd_spec.avd_type,
             boot_timeout_secs=avd_spec.boot_timeout_secs,
             unlock_screen=avd_spec.unlock_screen,
             wait_for_boot=False,
diff --git a/create/remote_image_remote_instance_test.py b/create/remote_image_remote_instance_test.py
index 34387b9..160dae5 100644
--- a/create/remote_image_remote_instance_test.py
+++ b/create/remote_image_remote_instance_test.py
@@ -63,6 +63,7 @@ class RemoteImageRemoteInstanceTest(driver_test_lib.BaseDriverTest):
         avd_spec.connect_webrtc = True
         avd_spec.connect_vnc = False
         avd_spec.gce_only = False
+        avd_spec.avd_type = constants.TYPE_CF
         create_report = mock.Mock()
         create_report.status = report.Status.SUCCESS
         self.Patch(common_operations, "CreateDevices",
diff --git a/public/actions/remote_host_cf_device_factory.py b/public/actions/remote_host_cf_device_factory.py
index 257c581..6c96d04 100644
--- a/public/actions/remote_host_cf_device_factory.py
+++ b/public/actions/remote_host_cf_device_factory.py
@@ -120,8 +120,14 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
 
         if error_msg:
             self._all_failures[instance] = error_msg
-        self._FindLogFiles(
-            instance, (error_msg and not self._avd_spec.no_pull_log))
+
+        try:
+            self._FindLogFiles(
+                instance, (error_msg and not self._avd_spec.no_pull_log))
+        except (errors.SubprocessFail, errors.DeviceConnectionError,
+                subprocess.CalledProcessError) as e:
+            logger.error("Fail to find log files: %s", e)
+
         return instance
 
     def _GetInstancePath(self, relative_path=""):
diff --git a/public/actions/remote_host_cf_device_factory_test.py b/public/actions/remote_host_cf_device_factory_test.py
index a4fa22c..49036ec 100644
--- a/public/actions/remote_host_cf_device_factory_test.py
+++ b/public/actions/remote_host_cf_device_factory_test.py
@@ -97,6 +97,8 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         factory = remote_host_cf_device_factory.RemoteHostDeviceFactory(
             mock_avd_spec, cvd_host_package_artifact="/mock/cvd.tar.gz")
 
+        mock_pull.PullLogs.side_effect = errors.DeviceConnectionError
+
         log = {"path": "/log.txt"}
         mock_cvd_utils.GetRemoteHostBaseDir.return_value = "acloud_cf_2"
         mock_cvd_utils.FormatRemoteHostInstanceName.return_value = "inst"
diff --git a/public/actions/remote_instance_cf_device_factory.py b/public/actions/remote_instance_cf_device_factory.py
index ba618c1..1fbab05 100644
--- a/public/actions/remote_instance_cf_device_factory.py
+++ b/public/actions/remote_instance_cf_device_factory.py
@@ -18,8 +18,10 @@ device factory."""
 import logging
 import os
 import shutil
+import subprocess
 import tempfile
 
+from acloud import errors
 from acloud.create import create_common
 from acloud.internal import constants
 from acloud.internal.lib import cvd_utils
@@ -71,9 +73,15 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
         except Exception as e:
             self._SetFailures(instance, e)
 
-        self._FindLogFiles(
-            instance,
-            instance in self.GetFailures() and not self._avd_spec.no_pull_log)
+        try:
+            self._FindLogFiles(
+                instance,
+                (instance in self.GetFailures() and
+                 not self._avd_spec.no_pull_log))
+        except (errors.SubprocessFail, errors.DeviceConnectionError,
+                subprocess.CalledProcessError) as e:
+            logger.error("Fail to find log files: %s", e)
+
         return instance
 
     def _ProcessArtifacts(self):
diff --git a/public/actions/remote_instance_cf_device_factory_test.py b/public/actions/remote_instance_cf_device_factory_test.py
index 9d736a2..a658a12 100644
--- a/public/actions/remote_instance_cf_device_factory_test.py
+++ b/public/actions/remote_instance_cf_device_factory_test.py
@@ -21,6 +21,7 @@ import uuid
 
 from unittest import mock
 
+from acloud import errors
 from acloud.create import avd_spec
 from acloud.internal import constants
 from acloud.internal.lib import android_build_client
@@ -245,6 +246,8 @@ class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         mock_cvd_utils.UploadExtraImages.return_value = [
             ("-boot_image", "/boot/img")]
 
+        mock_pull.PullLogs.side_effect = errors.DeviceConnectionError
+
         fake_host_package_name = "/fake/host_package.tar.gz"
         fake_image_name = ""
         factory = remote_instance_cf_device_factory.RemoteInstanceDeviceFactory(
diff --git a/public/actions/remote_instance_trusty_device_factory.py b/public/actions/remote_instance_trusty_device_factory.py
index 0997852..48ac608 100644
--- a/public/actions/remote_instance_trusty_device_factory.py
+++ b/public/actions/remote_instance_trusty_device_factory.py
@@ -35,10 +35,20 @@ from acloud.pull import pull
 
 logger = logging.getLogger(__name__)
 _CONFIG_JSON_FILENAME = "config.json"
-_TRUSTY_HOST_TARBALL = "trusty-host_package.tar.gz"
-_TRUSTY_HOST_PACKAGE = "trusty-host_package"
 _REMOTE_STDOUT_PATH = "kernel.log"
 _REMOTE_STDERR_PATH = "qemu_trusty_err.log"
+_TRUSTY_IMAGE_PACKAGE = "trusty_image_package.tar.gz"
+_TRUSTY_HOST_PACKAGE_DIR = "trusty-host_package"
+_TRUSTY_HOST_TARBALL = "trusty-host_package.tar.gz"
+
+# Default Trusty image build. This does not depend on the android branch.
+_DEFAULT_TRUSTY_BUILD_BRANCH = "aosp-trusty-master"
+_DEFAULT_TRUSTY_BUILD_TARGET = "qemu_generic_arm64_test_debug"
+
+
+def _TrustyImagePackageFilename(build_target):
+    trusty_target = build_target.replace("_", "-")
+    return f"{trusty_target}.{_TRUSTY_IMAGE_PACKAGE}"
 
 
 def _FindHostPackage(package_path=None):
@@ -53,7 +63,7 @@ def _FindHostPackage(package_path=None):
         dirs_to_check.append(dist_dir)
 
     for path in dirs_to_check:
-        for name in [_TRUSTY_HOST_TARBALL, _TRUSTY_HOST_PACKAGE]:
+        for name in [_TRUSTY_HOST_TARBALL, _TRUSTY_HOST_PACKAGE_DIR]:
             trusty_host_package = os.path.join(path, name)
             if os.path.exists(trusty_host_package):
                 return trusty_host_package
@@ -94,15 +104,13 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
             instance in self.GetFailures() and not self._avd_spec.no_pull_log)
         return instance
 
-    @utils.TimeExecute(function_description="Process Trusty artifacts")
     def _ProcessArtifacts(self):
         """Process artifacts.
 
         - If images source is local, tool will upload images from local site to
           remote instance.
         - If images source is remote, tool will download images from android
-          build to remote instance. Before download images, we have to update
-          fetch_cvd to remote instance.
+          build to remote instance.
         """
         avd_spec = self._avd_spec
         if avd_spec.image_source == constants.IMAGE_SRC_LOCAL:
@@ -111,35 +119,125 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
                 cvd_utils.GCE_BASE_DIR,
                 (self._local_image_artifact or avd_spec.local_image_dir),
                 self._host_package_artifact)
-
-            # Upload Trusty image archive
-            remote_cmd = (f"tar -xzf - -C {cvd_utils.GCE_BASE_DIR} < "
-                          + avd_spec.local_trusty_image)
-            logger.debug("remote_cmd:\n %s", remote_cmd)
-            self._ssh.Run(remote_cmd)
-
-            config = {
-                "linux": "kernel",
-                "linux_arch": "arm64",
-                "atf": "atf/qemu/debug",
-                "qemu": "bin/trusty_qemu_system_aarch64",
-                "extra_qemu_flags": ["-machine", "gic-version=2"],
-                "android_image_dir": ".",
-                "rpmbd": "bin/rpmb_dev",
-                "arch": "arm64",
-                "adb": "bin/adb",
-            }
-
-            with tempfile.NamedTemporaryFile(mode="w+t") as config_json_file:
-                json.dump(config, config_json_file)
-                config_json_file.flush()
-                remote_config_path = remote_path.join(
-                    cvd_utils.GCE_BASE_DIR, _CONFIG_JSON_FILENAME)
-                self._ssh.ScpPushFile(config_json_file.name, remote_config_path)
         elif avd_spec.image_source == constants.IMAGE_SRC_REMOTE:
-            # TODO(b/360427987)
-            raise NotImplementedError(
-                "Remote image source not yet implemented for trusty instance")
+            self._FetchBuild()
+            if self._compute_client.build_api.GetKernelBuild(
+                    avd_spec.kernel_build_info):
+                self._ReplaceModules()
+        if avd_spec.local_trusty_image:
+            self._UploadTrustyImages(avd_spec.local_trusty_image)
+        else:
+            self._FetchAndUploadTrustyImages()
+
+        config = {
+            "linux": "kernel",
+            "linux_arch": "arm64",
+            "atf": "atf/qemu/debug",
+            "qemu": "bin/trusty_qemu_system_aarch64",
+            "extra_qemu_flags": ["-machine", "gic-version=2"],
+            "android_image_dir": ".",
+            "rpmbd": "bin/rpmb_dev",
+            "arch": "arm64",
+            "adb": "bin/adb",
+        }
+        with tempfile.NamedTemporaryFile(mode="w+t") as config_json_file:
+            json.dump(config, config_json_file)
+            config_json_file.flush()
+            remote_config_path = remote_path.join(
+                cvd_utils.GCE_BASE_DIR, _CONFIG_JSON_FILENAME)
+            self._ssh.ScpPushFile(config_json_file.name, remote_config_path)
+
+    # We are building our own command-line instead of using
+    # self._compute_client.FetchBuild() because we need to use the host cvd
+    # tool rather than `fetch_cvd`. The downloaded fetch_cvd tool is too
+    # old and cannot handle a custom host package filename. This can be
+    # removed when b/298447306 is fixed.
+    @utils.TimeExecute(function_description="Fetching builds")
+    def _FetchBuild(self):
+        """Fetch builds from android build server."""
+        avd_spec = self._avd_spec
+        build_client = self._compute_client.build_api
+
+        # Provide the default trusty host package artifact filename. We must
+        # explicitly use the default build id/branch and target for the host
+        # package if those values were not set for the host package so that we
+        # can override the artifact filename.
+        host_package = avd_spec.host_package_build_info.copy()
+        if not (
+            host_package[constants.BUILD_ID]
+            or host_package[constants.BUILD_BRANCH]
+        ):
+            host_package[constants.BUILD_ID] = avd_spec.remote_image[
+                constants.BUILD_ID]
+            host_package[constants.BUILD_BRANCH] = avd_spec.remote_image[
+                constants.BUILD_BRANCH]
+        if not host_package[constants.BUILD_TARGET]:
+            host_package[constants.BUILD_TARGET] = avd_spec.remote_image[
+                constants.BUILD_TARGET]
+        host_package.setdefault(constants.BUILD_ARTIFACT, _TRUSTY_HOST_TARBALL)
+
+        fetch_args = build_client.GetFetchBuildArgs(
+            avd_spec.remote_image,
+            {},
+            avd_spec.kernel_build_info,
+            {},
+            {},
+            {},
+            {},
+            host_package,
+        )
+        fetch_cmd = (
+            constants.CMD_CVD_FETCH
+            + ["-credential_source=gce"]
+            + fetch_args
+        )
+        self._ssh.Run(" ".join(fetch_cmd), timeout=constants.DEFAULT_SSH_TIMEOUT)
+
+    def _ReplaceModules(self):
+        """Replace modules in android ramdisk with modules from the kernel build"""
+        android_ramdisk = remote_path.join(cvd_utils.GCE_BASE_DIR, "ramdisk.img")
+        kernel_ramdisk = remote_path.join(cvd_utils.GCE_BASE_DIR, "initramfs.img")
+        # We are switching to the bin/ directory so host tools are in the
+        # current directory for python to find.
+        self._ssh.Run(
+            f"cd {cvd_utils.GCE_BASE_DIR}/bin && ./replace_ramdisk_modules "
+            f"--android-ramdisk={android_ramdisk} "
+            f"--kernel-ramdisk={kernel_ramdisk} "
+            f"--output-ramdisk={android_ramdisk}",
+            timeout=constants.DEFAULT_SSH_TIMEOUT)
+
+    @utils.TimeExecute(function_description="Downloading and uploading Trusty image")
+    def _FetchAndUploadTrustyImages(self):
+        """Download Trusty image archive"""
+        build_client = self._compute_client.build_api
+        trusty_build_info = self._avd_spec.trusty_build_info
+        build_id = trusty_build_info[constants.BUILD_ID]
+        build_branch = (
+            trusty_build_info[constants.BUILD_BRANCH]
+            or _DEFAULT_TRUSTY_BUILD_BRANCH
+        )
+        build_target = (
+            trusty_build_info[constants.BUILD_TARGET]
+            or _DEFAULT_TRUSTY_BUILD_TARGET
+        )
+        if not build_id:
+            build_id = build_client.GetLKGB(build_target, build_branch)
+        with tempfile.NamedTemporaryFile(suffix=".tar.gz") as image_local_file:
+            image_local_path = image_local_file.name
+            build_client.DownloadArtifact(
+                build_target,
+                build_id,
+                _TrustyImagePackageFilename(build_target),
+                image_local_path,
+            )
+            self._UploadTrustyImages(image_local_path)
+
+    def _UploadTrustyImages(self, archive_path):
+        """Upload Trusty image archive"""
+        remote_cmd = (f"tar -xzf - -C {cvd_utils.GCE_BASE_DIR} < "
+                      + archive_path)
+        logger.debug("remote_cmd:\n %s", remote_cmd)
+        self._ssh.Run(remote_cmd)
 
     @utils.TimeExecute(function_description="Starting Trusty")
     def _StartTrusty(self):
diff --git a/public/actions/remote_instance_trusty_device_factory_test.py b/public/actions/remote_instance_trusty_device_factory_test.py
index a6ad78c..d61804d 100644
--- a/public/actions/remote_instance_trusty_device_factory_test.py
+++ b/public/actions/remote_instance_trusty_device_factory_test.py
@@ -46,6 +46,7 @@ class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         super().setUp()
         self.Patch(auth, "CreateCredentials", return_value=mock.MagicMock())
         self.Patch(android_build_client.AndroidBuildClient, "InitResourceHandle")
+        self.Patch(android_build_client.AndroidBuildClient, "DownloadArtifact")
         self.Patch(cvd_compute_client_multi_stage.CvdComputeClient, "InitResourceHandle")
         self.Patch(list_instances, "GetInstancesFromInstanceNames", return_value=mock.MagicMock())
         self.Patch(list_instances, "ChooseOneRemoteInstance", return_value=mock.MagicMock())
@@ -54,9 +55,8 @@ class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
     # pylint: disable=protected-access
     @mock.patch("acloud.public.actions.remote_instance_trusty_device_factory."
                 "cvd_utils")
-    def testProcessArtifacts(self, mock_cvd_utils):
-        """test ProcessArtifacts."""
-        # Test image source type is local.
+    def testLocalImage(self, mock_cvd_utils):
+        """test ProcessArtifacts with local image."""
         fake_emulator_package = "/fake/trusty_build/trusty_image_package.tar.gz"
         fake_image_name = "/fake/qemu_trusty_arm64-img-eng.username.zip"
         fake_host_package_name = "/fake/trusty_host_package.tar.gz"
@@ -72,9 +72,11 @@ class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         args.local_trusty_image = fake_emulator_package
         args.trusty_host_package = fake_host_package_name
         args.reuse_gce = None
-        avd_spec_local_img = avd_spec.AVDSpec(args)
         mock_cvd_utils.GCE_BASE_DIR = "gce_base_dir"
 
+        # Test local images
+        avd_spec_local_img = avd_spec.AVDSpec(args)
+
         self.Patch(os.path, "exists", return_value=True)
         factory_local_img = remote_instance_trusty_device_factory.RemoteInstanceDeviceFactory(
             avd_spec_local_img,
@@ -103,6 +105,72 @@ class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         mock_ssh.ScpPushFile.assert_called_with(
             fake_tmp_path, f"{mock_cvd_utils.GCE_BASE_DIR}/config.json")
 
+    # pylint: disable=protected-access
+    @mock.patch("acloud.public.actions.remote_instance_trusty_device_factory."
+                "cvd_utils")
+    def testRemoteImage(self, mock_cvd_utils):
+        """test ProcessArtifacts with remote image source."""
+        fake_tmp_path = "/fake/tmp_file"
+
+        args = mock.MagicMock()
+        args.config_file = ""
+        args.avd_type = constants.TYPE_TRUSTY
+        args.flavor = "phone"
+        args.local_image = None
+        args.launch_args = None
+        args.autoconnect = constants.INS_KEY_WEBRTC
+        args.local_trusty_image = None
+        args.reuse_gce = None
+        args.build_id = "default_build_id"
+        args.branch = "default_branch"
+        args.build_target = "default_target"
+        args.kernel_build_id = "kernel_build_id"
+        args.kernel_build_target = "kernel_target"
+        args.host_package_build_id = None
+        args.host_package_branch = None
+        args.host_package_build_target = None
+        mock_cvd_utils.GCE_BASE_DIR = "gce_base_dir"
+
+        avd_spec_remote_img = avd_spec.AVDSpec(args)
+        factory_remote_img = remote_instance_trusty_device_factory.RemoteInstanceDeviceFactory(
+            avd_spec_remote_img)
+        mock_ssh = mock.Mock()
+        factory_remote_img._ssh = mock_ssh
+
+        temp_file_mock = mock.MagicMock()
+        temp_file_mock.__enter__().name = fake_tmp_path
+        self.Patch(tempfile, "NamedTemporaryFile", return_value=temp_file_mock)
+
+        factory_remote_img._ProcessArtifacts()
+
+        # Download trusty image package
+        factory_remote_img.GetComputeClient().build_api.DownloadArtifact.called_once()
+
+        mock_ssh.Run.assert_has_calls(
+            [
+                mock.call(
+                    "cvd fetch -credential_source=gce "
+                    "-default_build=default_build_id/default_target "
+                    "-kernel_build=kernel_build_id/kernel_target "
+                    "-host_package_build=default_build_id/default_target{trusty-host_package.tar.gz}",
+                    timeout=300,
+                ),
+                mock.call(
+                    f"cd {mock_cvd_utils.GCE_BASE_DIR}/bin && "
+                    "./replace_ramdisk_modules "
+                    f"--android-ramdisk={mock_cvd_utils.GCE_BASE_DIR}/ramdisk.img "
+                    f"--kernel-ramdisk={mock_cvd_utils.GCE_BASE_DIR}/initramfs.img "
+                    f"--output-ramdisk={mock_cvd_utils.GCE_BASE_DIR}/ramdisk.img",
+                    timeout=300,
+                ),
+                mock.call(
+                    f"tar -xzf - -C {mock_cvd_utils.GCE_BASE_DIR} "
+                    f"< {fake_tmp_path}"
+                ),
+            ]
+        )
+
+
     @mock.patch.object(remote_instance_trusty_device_factory.RemoteInstanceDeviceFactory,
                        "CreateGceInstance")
     @mock.patch("acloud.public.actions.remote_instance_trusty_device_factory."
```

