```diff
diff --git a/create/avd_spec.py b/create/avd_spec.py
index 1879aaf..5eafe30 100644
--- a/create/avd_spec.py
+++ b/create/avd_spec.py
@@ -65,11 +65,11 @@ _Y_RES = "y_res"
 _COMMAND_GIT_REMOTE = ["git", "remote"]
 
 # The branch prefix is necessary for the Android Build system to know what we're
-# talking about. For instance, on an aosp remote repo in the master branch,
-# Android Build will recognize it as aosp-master.
+# talking about. For instance, on an aosp remote repo in the main branch,
+# Android Build will recognize it as aosp-main.
 _BRANCH_PREFIX = {"aosp": "aosp-"}
 _DEFAULT_BRANCH_PREFIX = "git_"
-_DEFAULT_BRANCH = "aosp-master"
+_DEFAULT_BRANCH = "aosp-main"
 
 # The target prefix is needed to help concoct the lunch target name given a
 # the branch, avd type and device flavor:
@@ -177,6 +177,10 @@ class AVDSpec():
         self._cheeps_betty_image = None
         self._cheeps_features = None
 
+        # Fields only used for trusty type.
+        self._local_trusty_image = None
+        self._trusty_host_package = None
+
         # The maximum time in seconds used to wait for the AVD to boot.
         self._boot_timeout_secs = None
         # The maximum time in seconds used to wait for the instance ready.
@@ -379,6 +383,7 @@ class AVDSpec():
         self._local_instance_dir = args.local_instance_dir
         self._local_tool_dirs = args.local_tool
         self._cvd_host_package = args.cvd_host_package
+        self._trusty_host_package = args.trusty_host_package
         self._num_of_instances = args.num
         self._num_avds_per_instance = args.num_avds_per_instance
         self._no_pull_log = args.no_pull_log
@@ -477,6 +482,9 @@ class AVDSpec():
             self._ProcessCFLocalImageArgs(args.local_image, args.flavor)
         elif self._avd_type == constants.TYPE_FVP:
             self._ProcessFVPLocalImageArgs()
+        elif self._avd_type == constants.TYPE_TRUSTY:
+            self._ProcessTrustyLocalImageArgs(args.local_image)
+            self._local_trusty_image = args.local_trusty_image
         elif self._avd_type == constants.TYPE_GF:
             local_image_path = self._GetLocalImagePath(args.local_image)
             if os.path.isdir(local_image_path):
@@ -621,6 +629,38 @@ class AVDSpec():
                 "No image found(Did you choose a lunch target and run `m`?)"
                 ": %s.\n " % self._local_image_dir)
 
+    def _ProcessTrustyLocalImageArgs(self, local_image_arg):
+        """Get local built image path for Trusty-type AVD."""
+        if local_image_arg == constants.FIND_IN_BUILD_ENV:
+            build_target = utils.GetBuildEnvironmentVariable(
+                constants.ENV_BUILD_TARGET)
+            if build_target != "qemu_trusty_arm64":
+                utils.PrintColorString(
+                    f"{build_target} is not a trusty target (Try lunching "
+                    "qemu_trusty_arm64-trunk_staging-userdebug "
+                    "and running 'm')",
+                    utils.TextColors.WARNING)
+            local_image_path = utils.GetBuildEnvironmentVariable(
+                _ENV_ANDROID_PRODUCT_OUT)
+            # Since dir is provided, check that any images exist to ensure user
+            # didn't forget to 'make' before launch AVD.
+            image_list = glob.glob(os.path.join(local_image_path, "*.img"))
+            if not image_list:
+                raise errors.GetLocalImageError(
+                    "No image found(Did you choose a lunch target and run `m`?)" +
+                    f": {local_image_path}.\n ")
+        else:
+            local_image_path = local_image_arg
+
+        if os.path.isfile(local_image_path):
+            self._local_image_artifact = local_image_arg
+            # Since file is provided and I assume it's a zip, so print the
+            # warning message.
+            utils.PrintColorString(_LOCAL_ZIP_WARNING_MSG,
+                                   utils.TextColors.WARNING)
+        else:
+            self._local_image_dir = local_image_path
+
     def _ProcessRemoteBuildArgs(self, args):
         """Get the remote build args.
 
@@ -750,10 +790,10 @@ class AVDSpec():
         """Get branch information from command "repo info".
 
         If branch can't get from "repo info", it will be set as default branch
-        "aosp-master".
+        "aosp-main".
 
         Returns:
-            branch: String, git branch name. e.g. "aosp-master"
+            branch: String, git branch name. e.g. "aosp-main"
         """
         branch = None
         # TODO(149460014): Migrate acloud to py3, then remove this
@@ -866,6 +906,11 @@ class AVDSpec():
         """Return local vendor boot image path."""
         return self._local_vendor_boot_image
 
+    @property
+    def local_trusty_image(self):
+        """Return local trusty qemu package path."""
+        return self._local_trusty_image
+
     @property
     def local_tool_dirs(self):
         """Return a list of local tool directories."""
@@ -1177,6 +1222,11 @@ class AVDSpec():
         """Return cvd_host_package."""
         return self._cvd_host_package
 
+    @property
+    def trusty_host_package(self):
+        """Return trusty_host_package."""
+        return self._trusty_host_package
+
     @property
     def extra_files(self):
         """Return extra_files."""
diff --git a/create/avd_spec_test.py b/create/avd_spec_test.py
index 173322b..018fff1 100644
--- a/create/avd_spec_test.py
+++ b/create/avd_spec_test.py
@@ -231,7 +231,7 @@ class AvdSpecTest(driver_test_lib.BaseDriverTest):
         return_value = "Manifest branch:"
         fake_subprocess.communicate = mock.MagicMock(return_value=(return_value, ''))
         self.Patch(subprocess, "Popen", return_value=fake_subprocess)
-        self.assertEqual(self.AvdSpec._GetBranchFromRepo(), "aosp-master")
+        self.assertEqual(self.AvdSpec._GetBranchFromRepo(), "aosp-main")
 
     def testGetBuildBranch(self):
         """Test GetBuildBranch function"""
diff --git a/create/create.py b/create/create.py
index d4104af..6487827 100644
--- a/create/create.py
+++ b/create/create.py
@@ -88,6 +88,9 @@ _CREATOR_CLASS_DICT = {
     # FVP types
     (constants.TYPE_FVP, constants.IMAGE_SRC_LOCAL, constants.INSTANCE_TYPE_REMOTE):
         local_image_remote_instance.LocalImageRemoteInstance,
+    # Trusty types
+    (constants.TYPE_TRUSTY, constants.IMAGE_SRC_LOCAL, constants.INSTANCE_TYPE_REMOTE):
+        local_image_remote_instance.LocalImageRemoteInstance,
 }
 
 
diff --git a/create/create_args.py b/create/create_args.py
index 3bd3dba..505b86c 100644
--- a/create/create_args.py
+++ b/create/create_args.py
@@ -561,7 +561,7 @@ def GetCreateArgParser(subparser):
         dest="avd_type",
         default=constants.TYPE_CF,
         choices=[constants.TYPE_GCE, constants.TYPE_CF, constants.TYPE_GF, constants.TYPE_CHEEPS,
-                 constants.TYPE_FVP],
+                 constants.TYPE_FVP, constants.TYPE_TRUSTY],
         help="Android Virtual Device type (default %s)." % constants.TYPE_CF)
     create_parser.add_argument(
         "--config", "--flavor",
@@ -638,6 +638,15 @@ def GetCreateArgParser(subparser):
         "if no argument is provided. e.g., --local-vendor-boot-image, or "
         "--local-vendor-boot-image /path/to/dir, or "
         "--local-vendor-boot-image /path/to/img")
+    create_parser.add_argument(
+        "--local-trusty-image",
+        type=str,
+        dest="local_trusty_image",
+        required=False,
+        help="'trusty only' Use the specified path for the locally built "
+        "trusty emulator images package, built with "
+        "PACKAGE_TRUSTY_IMAGE_TARBALL=true in the Trusty build. E.g., "
+        "/path/trusty_image_package.tar.gz")
     create_parser.add_argument(
         "--local-tool",
         type=str,
@@ -655,6 +664,13 @@ def GetCreateArgParser(subparser):
         required=False,
         help="Use the specified path of the cvd host package to create "
         "instances. e.g. /path/cvd-host_package_v1.tar.gz")
+    create_parser.add_argument(
+        "--trusty-host-package",
+        type=str,
+        dest="trusty_host_package",
+        required=False,
+        help="Use the specified path of the trusty host package to create "
+        "instances. e.g. /path/trusty-host_package.tar.gz")
     create_parser.add_argument(
         "--image-download-dir",
         type=str,
@@ -844,7 +860,7 @@ def _VerifyLocalArgs(args):
     Raises:
         errors.CheckPathError: Image path doesn't exist.
         errors.UnsupportedCreateArgs: The specified avd type does not support
-                                      --local-system-image.
+                                      a provided argument.
         errors.UnsupportedLocalInstanceId: Local instance ID is invalid.
     """
     if args.local_image and not os.path.exists(args.local_image):
@@ -977,6 +993,43 @@ def _VerifyGoldfishArgs(args):
             "remote host.")
 
 
+def _VerifyTrustyArgs(args):
+    """Verify trusty args.
+
+    Args:
+        args: Namespace object from argparse.parse_args.
+
+    Raises:
+        errors.UnsupportedCreateArgs: When specified arguments are
+                                      unsupported for trusty.
+        errors.CheckPathError: A specified local path does not exist.
+    """
+    if args.avd_type != constants.TYPE_TRUSTY:
+        if args.local_trusty_image:
+            raise errors.UnsupportedCreateArgs(
+                "--local-trusty-image is only valid with "
+                f"avd_type == {constants.TYPE_TRUSTY}")
+        if args.trusty_host_package:
+            raise errors.UnsupportedCreateArgs(
+                "--trusty-host-package is only valid with "
+                f"avd_type == {constants.TYPE_TRUSTY}")
+        # Only check these args if AVD type is Trusty
+        return
+
+    if args.local_trusty_image is None:
+        raise errors.UnsupportedCreateArgs(
+            "Trusty image package not provided, use --local-trusty-image to "
+            "specify path to trusty_image_package.tar.gz containing trusty "
+            "images.")
+    if not os.path.exists(args.local_trusty_image):
+        raise errors.CheckPathError(
+            f"Specified path doesn't exist: {args.local_trusty_image}")
+    if args.trusty_host_package:
+        if not os.path.exists(args.trusty_host_package):
+            raise errors.CheckPathError(
+                f"Specified path doesn't exist: {args.trusty_host_package}")
+
+
 def VerifyArgs(args):
     """Verify args.
 
@@ -1043,5 +1096,6 @@ def VerifyArgs(args):
                          "passed in together.")
 
     _VerifyGoldfishArgs(args)
+    _VerifyTrustyArgs(args)
     _VerifyLocalArgs(args)
     _VerifyHostArgs(args)
diff --git a/create/create_args_test.py b/create/create_args_test.py
index 279844b..e32bc1b 100644
--- a/create/create_args_test.py
+++ b/create/create_args_test.py
@@ -42,6 +42,8 @@ def _CreateArgs():
         local_system_image=None,
         local_instance_dir=None,
         local_vendor_boot_image=None,
+        local_trusty_image=None,
+        trusty_host_package=None,
         kernel_branch=None,
         kernel_build_id=None,
         kernel_build_target="kernel",
@@ -178,6 +180,18 @@ class CreateArgsTest(driver_test_lib.BaseDriverTest):
         self.assertRaises(errors.UnsupportedCreateArgs,
                           create_args._VerifyLocalArgs, mock_args)
 
+        # wrong avd_type
+        mock_args = _CreateArgs()
+        mock_args.local_trusty_image = "/tmp/trusty_image_package.tar.gz"
+        self.assertRaises(errors.UnsupportedCreateArgs,
+                          create_args.VerifyArgs, mock_args)
+
+        # wrong avd_type
+        mock_args = _CreateArgs()
+        mock_args.trusty_host_package = "/tmp/trusty_host_package.tar.gz"
+        self.assertRaises(errors.UnsupportedCreateArgs,
+                          create_args.VerifyArgs, mock_args)
+
 
 if __name__ == "__main__":
     unittest.main()
diff --git a/create/local_image_remote_instance.py b/create/local_image_remote_instance.py
index 58bbb0b..b085832 100644
--- a/create/local_image_remote_instance.py
+++ b/create/local_image_remote_instance.py
@@ -25,6 +25,7 @@ from acloud.internal.lib import utils
 from acloud.public.actions import common_operations
 from acloud.public.actions import remote_instance_cf_device_factory
 from acloud.public.actions import remote_instance_fvp_device_factory
+from acloud.public.actions import remote_instance_trusty_device_factory
 from acloud.public import report
 
 
@@ -53,6 +54,10 @@ class LocalImageRemoteInstance(base_avd_create.BaseAVDCreate):
             device_factory = remote_instance_fvp_device_factory.RemoteInstanceDeviceFactory(
                 avd_spec)
             command = "create_fvp"
+        elif avd_spec.avd_type == constants.TYPE_TRUSTY:
+            device_factory = remote_instance_trusty_device_factory.RemoteInstanceDeviceFactory(
+                avd_spec, avd_spec.local_image_artifact)
+            command = "create_trusty"
 
         create_report = common_operations.CreateDevices(
             command, avd_spec.cfg, device_factory,
diff --git a/create/remote_image_local_instance.py b/create/remote_image_local_instance.py
index 445ab12..bed1ad9 100644
--- a/create/remote_image_local_instance.py
+++ b/create/remote_image_local_instance.py
@@ -136,19 +136,21 @@ def DownloadAndProcessImageFiles(avd_spec):
     if not os.path.exists(extract_path):
         os.makedirs(extract_path)
 
-        # Download rom images via fetch_cvd
-        fetch_cvd = os.path.join(extract_path, constants.FETCH_CVD)
-        build_api.DownloadFetchcvd(fetch_cvd, avd_spec.fetch_cvd_version)
+        # Download rom images via cvd fetch
+        fetch_cvd_args = list(constants.CMD_CVD_FETCH)
         creds_cache_file = os.path.join(_HOME_FOLDER, cfg.creds_cache_file)
         fetch_cvd_cert_arg = build_api.GetFetchCertArg(creds_cache_file)
-        fetch_cvd_args = [fetch_cvd, "-directory=%s" % extract_path,
-                          fetch_cvd_cert_arg]
+        fetch_cvd_args.extend([f"-directory={extract_path}",
+                          fetch_cvd_cert_arg])
         fetch_cvd_args.extend(fetch_cvd_build_args)
         logger.debug("Download images command: %s", fetch_cvd_args)
+        if not setup_common.PackageInstalled(constants.CUTTLEFISH_COMMOM_PKG):
+            raise errors.NoCuttlefishCommonInstalled(
+                "cuttlefish-common package is required to run cvd fetch")
         try:
             subprocess.check_call(fetch_cvd_args)
         except subprocess.CalledProcessError as e:
-            raise errors.GetRemoteImageError("Fails to download images: %s" % e)
+            raise errors.GetRemoteImageError(f"Fails to download images: {e}")
 
         # Save the fetch cvd build args when the fetch command succeeds
         with open(fetch_cvd_args_file, "w") as output:
diff --git a/errors.py b/errors.py
index 5f605d4..7fd6452 100644
--- a/errors.py
+++ b/errors.py
@@ -199,6 +199,10 @@ class GetCvdLocalHostPackageError(CreateError):
     """Can't find the lost host package."""
 
 
+class GetTrustyLocalHostPackageError(CreateError):
+    """Can't find the trusty host package."""
+
+
 class GetSdkRepoPackageError(CreateError):
     """Can't find the local SDK repository package for goldfish."""
 
diff --git a/internal/constants.py b/internal/constants.py
index e17eca5..f5cefe2 100755
--- a/internal/constants.py
+++ b/internal/constants.py
@@ -43,6 +43,7 @@ TYPE_CF = "cuttlefish"
 TYPE_GCE = "gce"
 TYPE_GF = "goldfish"
 TYPE_FVP = "fvp"
+TYPE_TRUSTY = "trusty"
 
 # Image types
 IMAGE_SRC_REMOTE = "remote_image"
@@ -55,6 +56,7 @@ AVD_TYPES_MAPPING = {
     TYPE_GF: "sdk",
     # Cheeps uses the cheets target.
     TYPE_CHEEPS: "cheets",
+    TYPE_TRUSTY: "trusty",
 }
 
 # Instance types
@@ -132,6 +134,8 @@ GF_ADB_PORT = 5555
 GF_VNC_PORT = 6444
 # For FVP remote instances (no VNC support)
 FVP_ADB_PORT = 5555
+# For Trusty remote instances (no VNC support)
+TRUSTY_ADB_PORT = 5555
 # Maximum port number
 MAX_PORT = 65535
 # Time info to write in report.
@@ -141,6 +145,8 @@ TIME_LAUNCH = "launch_cvd_time"
 
 COMMAND_PS = ["ps", "aux"]
 CMD_CVD = "cvd"
+# the newer download tool
+CMD_CVD_FETCH = ["cvd", "fetch"]
 CMD_LAUNCH_CVD = "launch_cvd"
 CMD_PGREP = "pgrep"
 CMD_STOP_CVD = "stop_cvd"
diff --git a/internal/lib/cheeps_compute_client.py b/internal/lib/cheeps_compute_client.py
index dea3806..f8c7584 100644
--- a/internal/lib/cheeps_compute_client.py
+++ b/internal/lib/cheeps_compute_client.py
@@ -102,7 +102,7 @@ class CheepsComputeClient(android_compute_client.AndroidComputeClient):
             instance=instance,
             image_name=image_name,
             image_project=image_project,
-            disk_args=None,
+            disk_type='pd-balanced',
             metadata=metadata,
             machine_type=self._machine_type,
             network=self._network,
diff --git a/internal/lib/cheeps_compute_client_test.py b/internal/lib/cheeps_compute_client_test.py
index 8e51592..3b85f5a 100644
--- a/internal/lib/cheeps_compute_client_test.py
+++ b/internal/lib/cheeps_compute_client_test.py
@@ -126,7 +126,7 @@ class CheepsComputeClientTest(driver_test_lib.BaseDriverTest):
             instance=self.INSTANCE,
             image_name=self.IMAGE,
             image_project=self.IMAGE_PROJECT,
-            disk_args=None,
+            disk_type='pd-balanced',
             metadata=expected_metadata,
             machine_type=self.MACHINE_TYPE,
             network=self.NETWORK,
@@ -175,7 +175,7 @@ class CheepsComputeClientTest(driver_test_lib.BaseDriverTest):
             instance=self.INSTANCE,
             image_name=self.IMAGE,
             image_project=self.IMAGE_PROJECT,
-            disk_args=None,
+            disk_type='pd-balanced',
             metadata=expected_metadata,
             machine_type=self.MACHINE_TYPE,
             network=self.NETWORK,
diff --git a/internal/lib/cvd_utils.py b/internal/lib/cvd_utils.py
index 9943a1c..7b82baf 100644
--- a/internal/lib/cvd_utils.py
+++ b/internal/lib/cvd_utils.py
@@ -86,11 +86,12 @@ _IMAGE_DIR_LINK_NAME = "image_dir_link"
 _REF_CNT_FILE_EXT = ".lock"
 
 # Remote host instance name
+# hostname can be a domain name. "-" in hostname must be replaced with "_".
 _REMOTE_HOST_INSTANCE_NAME_FORMAT = (
     constants.INSTANCE_TYPE_HOST +
-    "-%(ip_addr)s-%(num)d-%(build_id)s-%(build_target)s")
+    "-%(hostname)s-%(num)d-%(build_id)s-%(build_target)s")
 _REMOTE_HOST_INSTANCE_NAME_PATTERN = re.compile(
-    constants.INSTANCE_TYPE_HOST + r"-(?P<ip_addr>[\d.]+)-(?P<num>\d+)-.+")
+    constants.INSTANCE_TYPE_HOST + r"-(?P<hostname>[\w.]+)-(?P<num>\d+)-.+")
 # android-info.txt contents.
 _CONFIG_PATTERN = re.compile(r"^config=(?P<config>.+)$", re.MULTILINE)
 # launch_cvd arguments.
@@ -265,7 +266,8 @@ def UploadArtifacts(ssh_obj, remote_image_dir, image_path, cvd_host_package):
         _UploadImageDir(ssh_obj, remote_image_dir, FindImageDir(image_path))
     else:
         _UploadImageZip(ssh_obj, remote_image_dir, image_path)
-    _UploadCvdHostPackage(ssh_obj, remote_image_dir, cvd_host_package)
+    if cvd_host_package:
+        _UploadCvdHostPackage(ssh_obj, remote_image_dir, cvd_host_package)
 
 
 def FindBootImages(search_path):
@@ -613,12 +615,12 @@ def GetRemoteHostBaseDir(base_instance_num):
     return _REMOTE_HOST_BASE_DIR_FORMAT % {"num": base_instance_num or 1}
 
 
-def FormatRemoteHostInstanceName(ip_addr, base_instance_num, build_id,
+def FormatRemoteHostInstanceName(hostname, base_instance_num, build_id,
                                  build_target):
-    """Convert an IP address and build info to an instance name.
+    """Convert a hostname and build info to an instance name.
 
     Args:
-        ip_addr: String, the IP address of the remote host.
+        hostname: String, the IPv4 address or domain name of the remote host.
         base_instance_num: Integer or None, the instance number of the device.
         build_id: String, the build id.
         build_target: String, the build target, e.g., aosp_cf_x86_64_phone.
@@ -627,25 +629,25 @@ def FormatRemoteHostInstanceName(ip_addr, base_instance_num, build_id,
         String, the instance name.
     """
     return _REMOTE_HOST_INSTANCE_NAME_FORMAT % {
-        "ip_addr": ip_addr,
+        "hostname": hostname.replace("-", "_"),
         "num": base_instance_num or 1,
         "build_id": build_id,
         "build_target": build_target}
 
 
 def ParseRemoteHostAddress(instance_name):
-    """Parse IP address from a remote host instance name.
+    """Parse hostname from a remote host instance name.
 
     Args:
         instance_name: String, the instance name.
 
     Returns:
-        The IP address and the base directory as strings.
+        The hostname and the base directory as strings.
         None if the name does not represent a remote host instance.
     """
     match = _REMOTE_HOST_INSTANCE_NAME_PATTERN.fullmatch(instance_name)
     if match:
-        return (match.group("ip_addr"),
+        return (match.group("hostname").replace("_", "-"),
                 GetRemoteHostBaseDir(int(match.group("num"))))
     return None
 
diff --git a/internal/lib/cvd_utils_test.py b/internal/lib/cvd_utils_test.py
index d174cda..893d3f6 100644
--- a/internal/lib/cvd_utils_test.py
+++ b/internal/lib/cvd_utils_test.py
@@ -35,11 +35,12 @@ class CvdUtilsTest(driver_test_lib.BaseDriverTest):
     # Remote host instance name.
     _PRODUCT_NAME = "aosp_cf_x86_64_phone"
     _BUILD_ID = "2263051"
-    _REMOTE_HOST_IP = "192.0.2.1"
+    _REMOTE_HOSTNAME_1 = "192.0.2.1"
+    _REMOTE_HOSTNAME_2 = "host.NAME-1234"
     _REMOTE_HOST_INSTANCE_NAME_1 = (
         "host-192.0.2.1-1-2263051-aosp_cf_x86_64_phone")
     _REMOTE_HOST_INSTANCE_NAME_2 = (
-        "host-192.0.2.1-2-2263051-aosp_cf_x86_64_phone")
+        "host-host.NAME_1234-2-2263051-aosp_cf_x86_64_phone")
 
     def testGetAdbPorts(self):
         """Test GetAdbPorts."""
@@ -347,22 +348,22 @@ class CvdUtilsTest(driver_test_lib.BaseDriverTest):
     def testFormatRemoteHostInstanceName(self):
         """Test FormatRemoteHostInstanceName."""
         name = cvd_utils.FormatRemoteHostInstanceName(
-            self._REMOTE_HOST_IP, None, self._BUILD_ID, self._PRODUCT_NAME)
+            self._REMOTE_HOSTNAME_1, None, self._BUILD_ID, self._PRODUCT_NAME)
         self.assertEqual(name, self._REMOTE_HOST_INSTANCE_NAME_1)
 
         name = cvd_utils.FormatRemoteHostInstanceName(
-            self._REMOTE_HOST_IP, 2, self._BUILD_ID, self._PRODUCT_NAME)
+            self._REMOTE_HOSTNAME_2, 2, self._BUILD_ID, self._PRODUCT_NAME)
         self.assertEqual(name, self._REMOTE_HOST_INSTANCE_NAME_2)
 
     def testParseRemoteHostAddress(self):
         """Test ParseRemoteHostAddress."""
         result = cvd_utils.ParseRemoteHostAddress(
             self._REMOTE_HOST_INSTANCE_NAME_1)
-        self.assertEqual(result, (self._REMOTE_HOST_IP, "acloud_cf_1"))
+        self.assertEqual(result, (self._REMOTE_HOSTNAME_1, "acloud_cf_1"))
 
         result = cvd_utils.ParseRemoteHostAddress(
             self._REMOTE_HOST_INSTANCE_NAME_2)
-        self.assertEqual(result, (self._REMOTE_HOST_IP, "acloud_cf_2"))
+        self.assertEqual(result, (self._REMOTE_HOSTNAME_2, "acloud_cf_2"))
 
         result = cvd_utils.ParseRemoteHostAddress(
             "host-goldfish-192.0.2.1-5554-123456-sdk_x86_64-sdk")
diff --git a/internal/lib/goldfish_utils.py b/internal/lib/goldfish_utils.py
index e5eefae..02c8a47 100644
--- a/internal/lib/goldfish_utils.py
+++ b/internal/lib/goldfish_utils.py
@@ -45,10 +45,11 @@ _SYSTEM_DLKM_IMAGE_NAMES = (
     "system_dlkm.img",  # goldfish artifact
 )
 # Remote host instance name.
+# hostname can be a domain name. "-" in hostname must be replaced with "_".
 _REMOTE_HOST_INSTANCE_NAME_FORMAT = (
-    "host-goldfish-%(ip_addr)s-%(console_port)s-%(build_info)s")
+    "host-goldfish-%(hostname)s-%(console_port)s-%(build_info)s")
 _REMOTE_HOST_INSTANCE_NAME_PATTERN = re.compile(
-    r"host-goldfish-(?P<ip_addr>[\d.]+)-(?P<console_port>\d+)-.+")
+    r"host-goldfish-(?P<hostname>[\w.]+)-(?P<console_port>\d+)-.+")
 
 
 def _FindFileByNames(parent_dir, names):
@@ -242,11 +243,11 @@ def MixDiskImage(output_dir, image_dir, system_image_path,
     return disk_image
 
 
-def FormatRemoteHostInstanceName(ip_addr, console_port, build_info):
+def FormatRemoteHostInstanceName(hostname, console_port, build_info):
     """Convert address and build info to a remote host instance name.
 
     Args:
-        ip_addr: A string, the IP address of the host.
+        hostname: A string, the IPv4 address or domain name of the host.
         console_port: An integer, the emulator console port.
         build_info: A dict containing the build ID and target.
 
@@ -259,7 +260,7 @@ def FormatRemoteHostInstanceName(ip_addr, console_port, build_info):
                       build_id and build_target else
                       "userbuild")
     return _REMOTE_HOST_INSTANCE_NAME_FORMAT % {
-        "ip_addr": ip_addr,
+        "hostname": hostname.replace("-", "_"),
         "console_port": console_port,
         "build_info": build_info_str,
     }
@@ -272,11 +273,12 @@ def ParseRemoteHostConsoleAddress(instance_name):
         instance_name: A string, the instance name.
 
     Returns:
-        The IP address as a string and the console port as an integer.
+        The hostname as a string and the console port as an integer.
         None if the name does not represent a goldfish instance on remote host.
     """
     match = _REMOTE_HOST_INSTANCE_NAME_PATTERN.fullmatch(instance_name)
-    return ((match.group("ip_addr"), int(match.group("console_port")))
+    return ((match.group("hostname").replace("_", "-"),
+             int(match.group("console_port")))
             if match else None)
 
 
diff --git a/internal/lib/goldfish_utils_test.py b/internal/lib/goldfish_utils_test.py
index 51f7b99..a56f4f4 100644
--- a/internal/lib/goldfish_utils_test.py
+++ b/internal/lib/goldfish_utils_test.py
@@ -32,11 +32,14 @@ class GoldfishUtilsTest(unittest.TestCase):
 
     # Remote host instance name.
     _IP_ADDRESS = "192.0.2.1"
+    _DOMAIN_NAME = "host.NAME-1234"
     _CONSOLE_PORT = 5554
     _BUILD_INFO = {"build_id": "123456",
                    "build_target": "sdk_phone_x86_64-userdebug"}
-    _INSTANCE_NAME = ("host-goldfish-192.0.2.1-5554-"
-                      "123456-sdk_phone_x86_64-userdebug")
+    _INSTANCE_NAME_WITH_IP = ("host-goldfish-192.0.2.1-5554-"
+                              "123456-sdk_phone_x86_64-userdebug")
+    _INSTANCE_NAME_WITH_DOMAIN = ("host-goldfish-host.NAME_1234-5554-"
+                                  "123456-sdk_phone_x86_64-userdebug")
     _INSTANCE_NAME_WITHOUT_INFO = "host-goldfish-192.0.2.1-5554-userbuild"
     _INVALID_NAME = "host-192.0.2.1-123456-aosp_cf_x86_phone-userdebug"
 
@@ -187,9 +190,13 @@ class GoldfishUtilsTest(unittest.TestCase):
     def testParseRemoteHostConsoleAddress(self):
         """Test ParseRemoteHostConsoleAddress."""
         console_addr = goldfish_utils.ParseRemoteHostConsoleAddress(
-            self._INSTANCE_NAME)
+            self._INSTANCE_NAME_WITH_IP)
         self.assertEqual((self._IP_ADDRESS, self._CONSOLE_PORT), console_addr)
 
+        console_addr = goldfish_utils.ParseRemoteHostConsoleAddress(
+            self._INSTANCE_NAME_WITH_DOMAIN)
+        self.assertEqual((self._DOMAIN_NAME, self._CONSOLE_PORT), console_addr)
+
         console_addr = goldfish_utils.ParseRemoteHostConsoleAddress(
             self._INVALID_NAME)
         self.assertIsNone(console_addr)
@@ -198,7 +205,11 @@ class GoldfishUtilsTest(unittest.TestCase):
         """Test FormatRemoteHostInstanceName."""
         instance_name = goldfish_utils.FormatRemoteHostInstanceName(
             self._IP_ADDRESS, self._CONSOLE_PORT, self._BUILD_INFO)
-        self.assertEqual(self._INSTANCE_NAME, instance_name)
+        self.assertEqual(self._INSTANCE_NAME_WITH_IP, instance_name)
+
+        instance_name = goldfish_utils.FormatRemoteHostInstanceName(
+            self._DOMAIN_NAME, self._CONSOLE_PORT, self._BUILD_INFO)
+        self.assertEqual(self._INSTANCE_NAME_WITH_DOMAIN, instance_name)
 
         instance_name = goldfish_utils.FormatRemoteHostInstanceName(
             self._IP_ADDRESS, self._CONSOLE_PORT, {})
diff --git a/internal/lib/utils.py b/internal/lib/utils.py
index 3a6a202..9829035 100755
--- a/internal/lib/utils.py
+++ b/internal/lib/utils.py
@@ -94,6 +94,7 @@ AVD_PORT_DICT = {
     constants.TYPE_CHEEPS: ForwardedPorts(constants.CHEEPS_VNC_PORT,
                                           constants.CHEEPS_ADB_PORT),
     constants.TYPE_FVP: ForwardedPorts(None, constants.FVP_ADB_PORT),
+    constants.TYPE_TRUSTY: ForwardedPorts(None, constants.TRUSTY_ADB_PORT),
 }
 
 _VNC_BIN = "ssvnc"
diff --git a/public/actions/remote_host_cf_device_factory.py b/public/actions/remote_host_cf_device_factory.py
index 134922d..257c581 100644
--- a/public/actions/remote_host_cf_device_factory.py
+++ b/public/actions/remote_host_cf_device_factory.py
@@ -346,8 +346,9 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
             self._avd_spec.host_package_build_info)
 
         fetch_cvd_args = self._avd_spec.fetch_cvd_wrapper.split(',') + [
+            f"-fetch_cvd_path={constants.CMD_CVD_FETCH[0]}",
+            constants.CMD_CVD_FETCH[1],
             f"-directory={self._GetArtifactPath()}",
-            f"-fetch_cvd_path={self._GetArtifactPath(constants.FETCH_CVD)}",
             self._GetRemoteFetchCredentialArg()]
         fetch_cvd_args.extend(fetch_cvd_build_args)
 
@@ -372,9 +373,9 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
             self._avd_spec.ota_build_info,
             self._avd_spec.host_package_build_info)
 
-        fetch_cvd_args = [self._GetArtifactPath(constants.FETCH_CVD),
-                          f"-directory={self._GetArtifactPath()}",
-                          self._GetRemoteFetchCredentialArg()]
+        fetch_cvd_args = list(constants.CMD_CVD_FETCH)
+        fetch_cvd_args.extend([f"-directory={self._GetArtifactPath()}",
+                               self._GetRemoteFetchCredentialArg()])
         fetch_cvd_args.extend(fetch_cvd_build_args)
 
         ssh_cmd = self._ssh.GetBaseCmd(constants.SSH_BIN)
@@ -384,17 +385,13 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
 
     @utils.TimeExecute(function_description="Download and upload fetch_cvd")
     def _UploadFetchCvd(self, extract_path):
-        """Download fetch_cvd, duplicate service account json private key when available and upload
+        """Duplicate service account json private key when available and upload
            to remote host.
 
         Args:
             extract_path: String, a path include extracted files.
         """
         cfg = self._avd_spec.cfg
-        is_arm_flavor = cvd_utils.RunOnArmMachine(self._ssh) and self._avd_spec.remote_fetch
-        fetch_cvd = os.path.join(extract_path, constants.FETCH_CVD)
-        self._build_api.DownloadFetchcvd(
-            fetch_cvd, self._avd_spec.fetch_cvd_version, is_arm_flavor)
         # Duplicate fetch_cvd API key when available
         if cfg.service_account_json_private_key_path:
             shutil.copyfile(
@@ -419,9 +416,6 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
         cfg = self._avd_spec.cfg
 
         # Download images with fetch_cvd
-        fetch_cvd = os.path.join(extract_path, constants.FETCH_CVD)
-        self._build_api.DownloadFetchcvd(
-            fetch_cvd, self._avd_spec.fetch_cvd_version)
         fetch_cvd_build_args = self._build_api.GetFetchBuildArgs(
             self._avd_spec.remote_image,
             self._avd_spec.system_build_info,
@@ -433,8 +427,8 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
             self._avd_spec.host_package_build_info)
         creds_cache_file = os.path.join(_HOME_FOLDER, cfg.creds_cache_file)
         fetch_cvd_cert_arg = self._build_api.GetFetchCertArg(creds_cache_file)
-        fetch_cvd_args = [fetch_cvd, f"-directory={extract_path}",
-                          fetch_cvd_cert_arg]
+        fetch_cvd_args = list(constants.CMD_CVD_FETCH)
+        fetch_cvd_args.extend([f"-directory={extract_path}", fetch_cvd_cert_arg])
         fetch_cvd_args.extend(fetch_cvd_build_args)
         logger.debug("Download images command: %s", fetch_cvd_args)
         try:
diff --git a/public/actions/remote_host_cf_device_factory_test.py b/public/actions/remote_host_cf_device_factory_test.py
index 89c4b05..a4fa22c 100644
--- a/public/actions/remote_host_cf_device_factory_test.py
+++ b/public/actions/remote_host_cf_device_factory_test.py
@@ -270,7 +270,6 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         self._mock_build_api.DownloadArtifact.assert_called_once_with(
             "aosp_cf_x86_64_phone-userdebug", "100000", "mock.zip", mock.ANY)
         mock_cvd_utils.ExtractTargetFilesZip.assert_called_once()
-        self._mock_build_api.DownloadFetchcvd.assert_called_once()
         mock_check_call.assert_called_once()
         mock_ssh.ShellCmdWithRetry.assert_called_once()
         self.assertRegex(mock_ssh.ShellCmdWithRetry.call_args[0][0],
@@ -315,13 +314,12 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         self.assertEqual("inst", factory.CreateInstance())
         mock_cvd_utils.CleanUpRemoteCvd.assert_called_once()
         mock_ssh_obj.Run.assert_called_with("mkdir -p acloud_cf_1")
-        self._mock_build_api.DownloadFetchcvd.assert_called_once()
         mock_shutil.copyfile.assert_called_with("/mock/key", mock.ANY)
         self.assertRegex(mock_ssh.ShellCmdWithRetry.call_args_list[0][0][0],
                          r"^tar -cf - --lzop -S -C \S+ fetch_cvd \| "
                          r"/mock/ssh -- tar -xf - --lzop -S -C acloud_cf_1$")
         self.assertRegex(mock_ssh.ShellCmdWithRetry.call_args_list[1][0][0],
-                         r"^/mock/ssh -- acloud_cf_1/fetch_cvd "
+                         r"^/mock/ssh -- cvd fetch "
                          r"-directory=acloud_cf_1 "
                          r"-credential_source=acloud_cf_1/credential_key.json "
                          r"-test$")
@@ -368,7 +366,6 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         self.assertEqual("inst", factory.CreateInstance())
         mock_cvd_utils.CleanUpRemoteCvd.assert_called_once()
         mock_ssh_obj.Run.assert_called_with("mkdir -p acloud_cf_1")
-        self._mock_build_api.DownloadFetchcvd.assert_called_once()
         mock_shutil.copyfile.assert_called_with("/mock/key", mock.ANY)
         self.assertRegex(mock_ssh.ShellCmdWithRetry.call_args_list[0][0][0],
                          r"^tar -cf - --lzop -S -C \S+ fetch_cvd \| "
@@ -378,8 +375,9 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
                          r"GOOGLE_APPLICATION_CREDENTIALS=/fake_key.json "
                          r"CACHE_CONFIG=/home/shared/cache.properties "
                          r"java -jar /home/shared/FetchCvdWrapper.jar "
+                         r"-fetch_cvd_path=cvd "
+                         r"fetch "
                          r"-directory=acloud_cf_1 "
-                         r"-fetch_cvd_path=acloud_cf_1/fetch_cvd "
                          r"-credential_source=acloud_cf_1/credential_key.json "
                          r"-test$")
         mock_cvd_utils.ExecuteRemoteLaunchCvd.assert_called()
@@ -430,7 +428,6 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
             mock_ssh_obj, "mock_img_dir/acloud_image_args.txt",
             [("arg", "mock_img_dir/1")])
         mock_ssh_obj.Run.assert_called_with("cp -frT mock_img_dir acloud_cf_1")
-        self._mock_build_api.DownloadFetchcvd.assert_called_once()
         self.assertEqual(["arg", "acloud_cf_1/1"],
                          mock_cvd_utils.GetRemoteLaunchCvdCmd.call_args[0][3])
 
@@ -439,12 +436,10 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
             ["arg", "mock_img_dir/2"]]
         mock_cvd_utils.SaveRemoteImageArgs.reset_mock()
         mock_ssh_obj.reset_mock()
-        self._mock_build_api.DownloadFetchcvd.reset_mock()
 
         self.assertEqual("inst", factory.CreateInstance())
         mock_cvd_utils.SaveRemoteImageArgs.assert_not_called()
         mock_ssh_obj.Run.assert_called_with("cp -frT mock_img_dir acloud_cf_1")
-        self._mock_build_api.DownloadFetchcvd.assert_not_called()
         self.assertEqual(["arg", "acloud_cf_1/2"],
                          mock_cvd_utils.GetRemoteLaunchCvdCmd.call_args[0][3])
 
diff --git a/public/actions/remote_instance_trusty_device_factory.py b/public/actions/remote_instance_trusty_device_factory.py
new file mode 100644
index 0000000..0997852
--- /dev/null
+++ b/public/actions/remote_instance_trusty_device_factory.py
@@ -0,0 +1,189 @@
+# Copyright 2024 - The Android Open Source Project
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
+"""RemoteInstanceDeviceFactory provides basic interface to create a Trusty
+device factory."""
+
+import json
+import logging
+import os
+import posixpath as remote_path
+import shlex
+import tempfile
+import traceback
+
+from acloud import errors
+from acloud.create import create_common
+from acloud.internal import constants
+from acloud.internal.lib import cvd_utils
+from acloud.internal.lib import utils
+from acloud.public import report
+from acloud.public.actions import gce_device_factory
+from acloud.pull import pull
+
+
+logger = logging.getLogger(__name__)
+_CONFIG_JSON_FILENAME = "config.json"
+_TRUSTY_HOST_TARBALL = "trusty-host_package.tar.gz"
+_TRUSTY_HOST_PACKAGE = "trusty-host_package"
+_REMOTE_STDOUT_PATH = "kernel.log"
+_REMOTE_STDERR_PATH = "qemu_trusty_err.log"
+
+
+def _FindHostPackage(package_path=None):
+    if package_path:
+        # checked in create_args._VerifyTrustyArgs
+        return package_path
+    dirs_to_check = create_common.GetNonEmptyEnvVars(
+        constants.ENV_ANDROID_SOONG_HOST_OUT, constants.ENV_ANDROID_HOST_OUT
+    )
+    dist_dir = utils.GetDistDir()
+    if dist_dir:
+        dirs_to_check.append(dist_dir)
+
+    for path in dirs_to_check:
+        for name in [_TRUSTY_HOST_TARBALL, _TRUSTY_HOST_PACKAGE]:
+            trusty_host_package = os.path.join(path, name)
+            if os.path.exists(trusty_host_package):
+                return trusty_host_package
+    raise errors.GetTrustyLocalHostPackageError(
+        "Can't find the trusty host package (Try lunching a trusty target "
+        "like qemu_trusty_arm64-trunk_staging-userdebug and running 'm'): \n"
+        + "\n".join(dirs_to_check))
+
+
+class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
+    """A class that can produce a Trusty device."""
+
+    def __init__(self, avd_spec, local_android_image_artifact=None):
+        super().__init__(avd_spec, local_android_image_artifact)
+        self._all_logs = {}
+        self._host_package_artifact = _FindHostPackage(
+            avd_spec.trusty_host_package)
+
+    # pylint: disable=broad-except
+    def CreateInstance(self):
+        """Create and start a single Trusty instance.
+
+        Returns:
+            The instance name as a string.
+        """
+        instance = self.CreateGceInstance()
+        if instance in self.GetFailures():
+            return instance
+
+        try:
+            self._ProcessArtifacts()
+            self._StartTrusty()
+        except Exception as e:
+            self._SetFailures(instance, traceback.format_exception(e))
+
+        self._FindLogFiles(
+            instance,
+            instance in self.GetFailures() and not self._avd_spec.no_pull_log)
+        return instance
+
+    @utils.TimeExecute(function_description="Process Trusty artifacts")
+    def _ProcessArtifacts(self):
+        """Process artifacts.
+
+        - If images source is local, tool will upload images from local site to
+          remote instance.
+        - If images source is remote, tool will download images from android
+          build to remote instance. Before download images, we have to update
+          fetch_cvd to remote instance.
+        """
+        avd_spec = self._avd_spec
+        if avd_spec.image_source == constants.IMAGE_SRC_LOCAL:
+            cvd_utils.UploadArtifacts(
+                self._ssh,
+                cvd_utils.GCE_BASE_DIR,
+                (self._local_image_artifact or avd_spec.local_image_dir),
+                self._host_package_artifact)
+
+            # Upload Trusty image archive
+            remote_cmd = (f"tar -xzf - -C {cvd_utils.GCE_BASE_DIR} < "
+                          + avd_spec.local_trusty_image)
+            logger.debug("remote_cmd:\n %s", remote_cmd)
+            self._ssh.Run(remote_cmd)
+
+            config = {
+                "linux": "kernel",
+                "linux_arch": "arm64",
+                "atf": "atf/qemu/debug",
+                "qemu": "bin/trusty_qemu_system_aarch64",
+                "extra_qemu_flags": ["-machine", "gic-version=2"],
+                "android_image_dir": ".",
+                "rpmbd": "bin/rpmb_dev",
+                "arch": "arm64",
+                "adb": "bin/adb",
+            }
+
+            with tempfile.NamedTemporaryFile(mode="w+t") as config_json_file:
+                json.dump(config, config_json_file)
+                config_json_file.flush()
+                remote_config_path = remote_path.join(
+                    cvd_utils.GCE_BASE_DIR, _CONFIG_JSON_FILENAME)
+                self._ssh.ScpPushFile(config_json_file.name, remote_config_path)
+        elif avd_spec.image_source == constants.IMAGE_SRC_REMOTE:
+            # TODO(b/360427987)
+            raise NotImplementedError(
+                "Remote image source not yet implemented for trusty instance")
+
+    @utils.TimeExecute(function_description="Starting Trusty")
+    def _StartTrusty(self):
+        """Start the model on the GCE instance."""
+
+        # We use an explicit subshell so we can run this command in the
+        # background.
+        cmd = "-- sh -c " + shlex.quote(shlex.quote(
+            f"{cvd_utils.GCE_BASE_DIR}/run.py "
+            f"--config={_CONFIG_JSON_FILENAME} "
+            f"> {_REMOTE_STDOUT_PATH} 2> {_REMOTE_STDERR_PATH} &"
+        ))
+        self._ssh.Run(cmd, self._avd_spec.boot_timeout_secs or 30, retry=0)
+
+    def _FindLogFiles(self, instance, download):
+        """Find and pull all log files from instance.
+
+        Args:
+            instance: String, instance name.
+            download: Whether to download the files to a temporary directory
+                      and show messages to the user.
+        """
+        logs = [cvd_utils.HOST_KERNEL_LOG]
+        if self._avd_spec.image_source == constants.IMAGE_SRC_REMOTE:
+            logs.append(
+                cvd_utils.GetRemoteFetcherConfigJson(cvd_utils.GCE_BASE_DIR))
+        logs.append(
+            report.LogFile(_REMOTE_STDOUT_PATH, constants.LOG_TYPE_KERNEL_LOG))
+        logs.append(
+            report.LogFile(_REMOTE_STDERR_PATH, constants.LOG_TYPE_TEXT))
+        self._all_logs[instance] = logs
+
+        logger.debug("logs: %s", logs)
+        if download:
+            # To avoid long download time, fetch from the first device only.
+            log_paths = [log["path"] for log in logs]
+            error_log_folder = pull.PullLogs(self._ssh, log_paths, instance)
+            self._compute_client.ExtendReportData(
+                constants.ERROR_LOG_FOLDER, error_log_folder)
+
+    def GetLogs(self):
+        """Get all device logs.
+
+        Returns:
+            A dictionary that maps instance names to lists of report.LogFile.
+        """
+        return self._all_logs
diff --git a/public/actions/remote_instance_trusty_device_factory_test.py b/public/actions/remote_instance_trusty_device_factory_test.py
new file mode 100644
index 0000000..a6ad78c
--- /dev/null
+++ b/public/actions/remote_instance_trusty_device_factory_test.py
@@ -0,0 +1,146 @@
+# Copyright 2024 - The Android Open Source Project
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
+"""Tests for remote_instance_trusty_device_factory."""
+
+import glob
+import logging
+import os
+import tempfile
+import unittest
+import uuid
+
+from unittest import mock
+
+from acloud.create import avd_spec
+from acloud.internal import constants
+from acloud.internal.lib import android_build_client
+from acloud.internal.lib import auth
+from acloud.internal.lib import cvd_compute_client_multi_stage
+from acloud.internal.lib import driver_test_lib
+from acloud.list import list as list_instances
+from acloud.public.actions import remote_instance_trusty_device_factory
+
+logger = logging.getLogger(__name__)
+
+_EXPECTED_CONFIG_JSON = '''{"linux": "kernel", "linux_arch": "arm64", \
+"atf": "atf/qemu/debug", "qemu": "bin/trusty_qemu_system_aarch64", \
+"extra_qemu_flags": ["-machine", "gic-version=2"], "android_image_dir": ".", \
+"rpmbd": "bin/rpmb_dev", "arch": "arm64", "adb": "bin/adb"}'''
+
+
+class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
+    """Test RemoteInstanceDeviceFactory."""
+
+    def setUp(self):
+        super().setUp()
+        self.Patch(auth, "CreateCredentials", return_value=mock.MagicMock())
+        self.Patch(android_build_client.AndroidBuildClient, "InitResourceHandle")
+        self.Patch(cvd_compute_client_multi_stage.CvdComputeClient, "InitResourceHandle")
+        self.Patch(list_instances, "GetInstancesFromInstanceNames", return_value=mock.MagicMock())
+        self.Patch(list_instances, "ChooseOneRemoteInstance", return_value=mock.MagicMock())
+        self.Patch(glob, "glob", return_value=["fake.img"])
+
+    # pylint: disable=protected-access
+    @mock.patch("acloud.public.actions.remote_instance_trusty_device_factory."
+                "cvd_utils")
+    def testProcessArtifacts(self, mock_cvd_utils):
+        """test ProcessArtifacts."""
+        # Test image source type is local.
+        fake_emulator_package = "/fake/trusty_build/trusty_image_package.tar.gz"
+        fake_image_name = "/fake/qemu_trusty_arm64-img-eng.username.zip"
+        fake_host_package_name = "/fake/trusty_host_package.tar.gz"
+        fake_tmp_path = "/fake/tmp_file"
+
+        args = mock.MagicMock()
+        args.config_file = ""
+        args.avd_type = constants.TYPE_TRUSTY
+        args.flavor = "phone"
+        args.local_image = constants.FIND_IN_BUILD_ENV
+        args.launch_args = None
+        args.autoconnect = constants.INS_KEY_WEBRTC
+        args.local_trusty_image = fake_emulator_package
+        args.trusty_host_package = fake_host_package_name
+        args.reuse_gce = None
+        avd_spec_local_img = avd_spec.AVDSpec(args)
+        mock_cvd_utils.GCE_BASE_DIR = "gce_base_dir"
+
+        self.Patch(os.path, "exists", return_value=True)
+        factory_local_img = remote_instance_trusty_device_factory.RemoteInstanceDeviceFactory(
+            avd_spec_local_img,
+            fake_image_name)
+        mock_ssh = mock.Mock()
+        factory_local_img._ssh = mock_ssh
+
+        temp_config = ""
+        def WriteTempConfig(s):
+            nonlocal temp_config
+            temp_config += s
+        temp_config_mock = mock.MagicMock()
+        temp_config_mock.__enter__().name = fake_tmp_path
+        temp_config_mock.__enter__().write.side_effect = WriteTempConfig
+        self.Patch(tempfile, "NamedTemporaryFile", return_value=temp_config_mock)
+
+        factory_local_img._ProcessArtifacts()
+
+        mock_cvd_utils.UploadArtifacts.assert_called_once_with(
+            mock.ANY, mock_cvd_utils.GCE_BASE_DIR, fake_image_name,
+            fake_host_package_name)
+        mock_ssh.Run.assert_called_once_with(
+            f"tar -xzf - -C {mock_cvd_utils.GCE_BASE_DIR} "
+            f"< {fake_emulator_package}")
+        self.assertEqual(temp_config, _EXPECTED_CONFIG_JSON)
+        mock_ssh.ScpPushFile.assert_called_with(
+            fake_tmp_path, f"{mock_cvd_utils.GCE_BASE_DIR}/config.json")
+
+    @mock.patch.object(remote_instance_trusty_device_factory.RemoteInstanceDeviceFactory,
+                       "CreateGceInstance")
+    @mock.patch("acloud.public.actions.remote_instance_trusty_device_factory."
+                "cvd_utils")
+    def testLocalImageCreateInstance(self, mock_cvd_utils, mock_create_gce_instance):
+        """Test CreateInstance with local images."""
+        self.Patch(
+            cvd_compute_client_multi_stage,
+            "CvdComputeClient",
+            return_value=mock.MagicMock())
+        mock_cvd_utils.GCE_BASE_DIR = "gce_base_dir"
+        mock_create_gce_instance.return_value = "instance"
+        fake_avd_spec = mock.MagicMock()
+        fake_avd_spec.image_source = constants.IMAGE_SRC_LOCAL
+        fake_avd_spec._instance_name_to_reuse = None
+        fake_avd_spec.no_pull_log = False
+        fake_avd_spec.base_instance_num = None
+        fake_avd_spec.num_avds_per_instance = None
+
+        mock_cvd_utils.HOST_KERNEL_LOG = {"path": "/host_kernel.log"}
+
+        fake_image_name = ""
+        factory = remote_instance_trusty_device_factory.RemoteInstanceDeviceFactory(
+            fake_avd_spec,
+            fake_image_name)
+        mock_ssh = mock.Mock()
+        factory._ssh = mock_ssh
+        factory.CreateInstance()
+        mock_create_gce_instance.assert_called_once()
+        mock_cvd_utils.UploadArtifacts.assert_called_once()
+        # First call is unpacking image archive
+        self.assertEqual(mock_ssh.Run.call_count, 2)
+        self.assertIn(
+            "gce_base_dir/run.py --config=config.json",
+            mock_ssh.Run.call_args[0][0])
+
+        self.assertEqual(3, len(factory.GetLogs().get("instance")))
+
+
+if __name__ == "__main__":
+    unittest.main()
```

