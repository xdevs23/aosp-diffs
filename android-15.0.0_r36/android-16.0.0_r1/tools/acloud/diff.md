```diff
diff --git a/Android.bp b/Android.bp
index 7dee67f..164d280 100644
--- a/Android.bp
+++ b/Android.bp
@@ -67,12 +67,8 @@ python_binary_host {
     dist: {
         targets: ["droidcore"],
     },
-    version: {
-        py3: {
-            // TODO(b/174041232): Make acloud work with embedded_launcher
-            embedded_launcher: false,
-        },
-    },
+    // TODO(b/174041232): Make acloud work with embedded_launcher
+    embedded_launcher: false,
 }
 
 python_test_host {
diff --git a/OWNERS b/OWNERS
index 76c6e4e..7d2b1c7 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,5 +1,2 @@
-herbertxue@google.com
-hsinyichen@google.com
-kevcheng@google.com
-samchiu@google.com
-file:device/google/cuttlefish:/OWNERS
+set noparent
+file:device/google/cuttlefish:/OWNERS_techleads
diff --git a/README.md b/README.md
index 3b8a14f..fb4aacd 100755
--- a/README.md
+++ b/README.md
@@ -77,10 +77,10 @@ target and/or build id (e.g. `--branch my_branch`). Acloud will assume the
 following if they're not specified:
 
 * `--branch`: The branch of the repo you're running the acloud command in, e.g.
-in an aosp repo on the master branch, acloud will infer the aosp-main (aosp-master) branch.
+in an aosp repo on the master branch, acloud will infer the aosp-main (aosp-main) branch.
 
 * `--build-target`: Defaults to the phone target for cuttlefish (e.g.
-aosp\_cf\_x86\_phone-userdebug in aosp-main (aosp-master)).
+aosp\_cf\_x86\_64\_phone-trunk\_staging-userdebug in aosp-main (aosp-main)).
 
 * `--build-id`: Default to the Last Known Good Build (LKGB) id for the branch and
 target set from above.
diff --git a/create/avd_spec.py b/create/avd_spec.py
index 0b8172f..f331e8d 100644
--- a/create/avd_spec.py
+++ b/create/avd_spec.py
@@ -158,7 +158,8 @@ class AVDSpec():
         self._webrtc_device_id = None
         self._connect_hostname = None
         self._fetch_cvd_wrapper = None
-        self._fetch_cvd_version = None
+        self._enable_fetch_local_caching = None
+        self._mix_system_dlkm_into_vendor_ramdisk = None
 
         # Create config instance for android_build_client to query build api.
         self._cfg = config.GetAcloudConfig(args)
@@ -421,7 +422,9 @@ class AVDSpec():
         self._webrtc_device_id = args.webrtc_device_id
         self._connect_hostname = args.connect_hostname or self._cfg.connect_hostname
         self._fetch_cvd_wrapper = args.fetch_cvd_wrapper
-        self._fetch_cvd_version = self._GetFetchCVDVersion(args)
+        self._enable_fetch_local_caching = args.enable_fetch_local_caching
+        self._mix_system_dlkm_into_vendor_ramdisk = (
+            args.mix_system_dlkm_into_vendor_ramdisk)
 
         if args.reuse_gce:
             if args.reuse_gce != constants.SELECT_ONE_GCE_INSTANCE:
@@ -438,21 +441,6 @@ class AVDSpec():
             constants.BUILD_BRANCH: args.trusty_branch,
             constants.BUILD_TARGET: args.trusty_build_target}
 
-    def _GetFetchCVDVersion(self, args):
-        """Get the fetch_cvd version.
-
-        Acloud will get the LKGB of fetch_cvd if no version specified.
-
-        Args:
-            args: Namespace object from argparse.parse_args.
-
-        Returns:
-            The build id of fetch_cvd.
-        """
-        if args.fetch_cvd_build_id:
-            return args.fetch_cvd_build_id
-        return constants.LKGB
-
     @staticmethod
     def _GetFlavorFromString(flavor_string):
         """Get flavor name from flavor string.
@@ -835,7 +823,7 @@ class AVDSpec():
 
         Target = {REPO_PREFIX}{avd_type}_{bitness}_{flavor}-
             {DEFAULT_BUILD_TARGET_TYPE}.
-        Example target: aosp_cf_x86_64_phone-userdebug
+        Example target: aosp_cf_x86_64_phone-trunk_staging-userdebug
 
         Args:
             args: Namespace object from argparse.parse_args.
@@ -988,9 +976,11 @@ class AVDSpec():
         return self._fetch_cvd_wrapper
 
     @property
-    def fetch_cvd_version(self):
-        """Return fetch_cvd_version."""
-        return self._fetch_cvd_version
+    def enable_fetch_local_caching(self):
+        """Use cvd fetch local caching
+        Return: Boolean
+        """
+        return self._enable_fetch_local_caching
 
     @property
     def num(self):
@@ -1257,3 +1247,8 @@ class AVDSpec():
     def connect_hostname(self):
         """Return connect_hostname"""
         return self._connect_hostname
+
+    @property
+    def mix_system_dlkm_into_vendor_ramdisk(self):
+        """Return mix_system_dlkm_into_vendor_ramdisk."""
+        return self._mix_system_dlkm_into_vendor_ramdisk
diff --git a/create/avd_spec_test.py b/create/avd_spec_test.py
index 33807cf..8306537 100644
--- a/create/avd_spec_test.py
+++ b/create/avd_spec_test.py
@@ -264,12 +264,12 @@ class AvdSpecTest(driver_test_lib.BaseDriverTest):
             self.AvdSpec._GetBuildTarget(self.args, branch),
             "gce_x86_64_iot-userdebug")
 
-        branch = "aosp-master"
+        branch = "aosp-main"
         self.AvdSpec._flavor = constants.FLAVOR_PHONE
         self.args.avd_type = constants.TYPE_CF
         self.assertEqual(
             self.AvdSpec._GetBuildTarget(self.args, branch),
-            "aosp_cf_x86_64_phone-userdebug")
+            "aosp_cf_x86_64_phone-trunk_staging-userdebug")
 
         branch = "aosp-main"
         self.AvdSpec._flavor = constants.FLAVOR_PHONE
@@ -381,7 +381,7 @@ class AvdSpecTest(driver_test_lib.BaseDriverTest):
         self.assertTrue(self.AvdSpec.avd_type == "gce")
 
         # Verify auto-assigned avd_type if build_targe contains "_cf_".
-        self.args.build_target = "aosp_cf_x86_64_phone-userdebug"
+        self.args.build_target = "aosp_cf_x86_64_phone-trunk_staging-userdebug"
         self.AvdSpec._ProcessRemoteBuildArgs(self.args)
         self.assertTrue(self.AvdSpec.avd_type == "cuttlefish")
 
@@ -573,15 +573,6 @@ class AvdSpecTest(driver_test_lib.BaseDriverTest):
         self.mock_config.connect_hostname = False
         self.assertTrue(self.AvdSpec.connect_hostname)
 
-        # Verify fetch_cvd_version
-        self.args.fetch_cvd_build_id = None
-        self.AvdSpec._ProcessMiscArgs(self.args)
-        self.assertEqual(self.AvdSpec.fetch_cvd_version, "LKGB")
-
-        self.args.fetch_cvd_build_id = "23456"
-        self.AvdSpec._ProcessMiscArgs(self.args)
-        self.assertEqual(self.AvdSpec.fetch_cvd_version, "23456")
-
         self.args.trusty_branch = "trusty_branch"
         self.args.trusty_build_id = "trusty_build_id"
         self.args.trusty_build_target = "trusty_build_target"
diff --git a/create/base_avd_create.py b/create/base_avd_create.py
index fdc8256..4a8a56b 100644
--- a/create/base_avd_create.py
+++ b/create/base_avd_create.py
@@ -53,7 +53,7 @@ class BaseAVDCreate():
         Example:
             Creating remote AVD instance with the following details:
             Image:
-              aosp/master - aosp_cf_x86_64_phone-userdebug [1234]
+              aosp-main - aosp_cf_x86_64_phone-trunk_staging-userdebug [1234]
             hw config:
               cpu - 2
               ram - 2GB
diff --git a/create/create_args.py b/create/create_args.py
index 1d2ede3..d8f69e1 100644
--- a/create/create_args.py
+++ b/create/create_args.py
@@ -143,7 +143,7 @@ def AddCommonCreateArgs(parser):
         "--build-target",
         type=str,
         dest="build_target",
-        help="Android build target, e.g. aosp_cf_x86_64_phone-userdebug, "
+        help="Android build target, e.g. aosp_cf_x86_64_phone-trunk_staging-userdebug, "
              "or short names: phone, tablet, or tablet_mobile.")
     parser.add_argument(
         "--branch",
@@ -222,14 +222,14 @@ def AddCommonCreateArgs(parser):
         type=str,
         dest="boot_branch",
         required=False,
-        help="Boot image branch, e.g., aosp-gki13-boot-release, aosp-master.")
+        help="Boot image branch, e.g., aosp-gki13-boot-release, aosp-main.")
     parser.add_argument(
         "--boot-build-target",
         type=str,
         dest="boot_build_target",
         required=False,
         help="Boot image build target, "
-        "e.g., gki_x86_64-userdebug, aosp_cf_x86_64_phone-userdebug.")
+        "e.g., gki_x86_64-userdebug, aosp_cf_x86_64_phone-trunk_staging-userdebug.")
     parser.add_argument(
         "--boot-artifact",
         type=str,
@@ -242,7 +242,7 @@ def AddCommonCreateArgs(parser):
         type=str,
         dest="ota_branch",
         required=False,
-        help="'cuttlefish only' OTA tools branch name. e.g. aosp-master")
+        help="'cuttlefish only' OTA tools branch name. e.g. aosp-main")
     parser.add_argument(
         "--ota-build-id",
         type=str,
@@ -255,7 +255,7 @@ def AddCommonCreateArgs(parser):
         dest="ota_build_target",
         required=False,
         help="'cuttlefish only' OTA tools build target, e.g. "
-        "cf_x86_64_phone-userdebug.")
+        "cf_x86_64_phone-trunk_staging-userdebug.")
     parser.add_argument(
         "--host-package-branch", "--host_package_branch",
         type=str,
@@ -276,7 +276,7 @@ def AddCommonCreateArgs(parser):
         dest="host_package_build_target",
         required=False,
         help="'cuttlefish and trusty only' Host package build target, e.g. "
-        "cf_x86_64_phone-userdebug.")
+        "cf_x86_64_phone-trunk_staging-userdebug.")
     parser.add_argument(
         "--system-branch",
         type=str,
@@ -324,7 +324,7 @@ def AddCommonCreateArgs(parser):
         type=str,
         dest="fetch_cvd_build_id",
         required=False,
-        help="'cuttlefish only' Build id of fetch_cvd, e.g. 2145099, P2804227")
+        help="Deprecated - any values input through this param are ignored")
     # TODO(146314062): Remove --multi-stage-launch after infra don't use this
     # args.
     parser.add_argument(
@@ -398,6 +398,16 @@ def AddCommonCreateArgs(parser):
         dest="local_instance_dir",
         required=False,
         help=argparse.SUPPRESS)
+    parser.add_argument(
+        "--mix-system_dlkm-into-vendor-ramdisk",
+        dest="mix_system_dlkm_into_vendor_ramdisk",
+        action="store_true",
+        required=False,
+        # Extract system_dlkm image and mix it into vendor ramdisk. The mixing
+        # process overwrites some of the modules in the vendor ramdisk. It is
+        # effective only if both --local-boot-image and
+        # --local-system_dlkm-image are specified.
+        help=argparse.SUPPRESS)
     parser.add_argument(
         "--remote-image-dir",
         dest="remote_image_dir",
@@ -516,6 +526,15 @@ def AddCommonCreateArgs(parser):
         " provided static executable fetch cvd wrapper file. "
         " (Still in experiment, this flag only works on lab hosts"
         " with special setup.)")
+    parser.add_argument(
+        "--enable_fetch_local_caching",
+        action="store_true",
+        dest="enable_fetch_local_caching",
+        required=False,
+        help="'cuttlefish only' When enabled, fetched artifacts may be saved "
+        "to a local cache to avoid network requests on repeated fetches of the"
+        " same artifacts."
+    )
 
 
 def GetCreateArgParser(subparser):
@@ -886,14 +905,26 @@ def _VerifyLocalArgs(args):
                                       a provided argument.
         errors.UnsupportedLocalInstanceId: Local instance ID is invalid.
     """
-    if args.local_image and not os.path.exists(args.local_image):
-        raise errors.CheckPathError(
-            "Specified path doesn't exist: %s" % args.local_image)
+    for local_path in [args.local_image, args.local_instance_dir,
+                       args.local_kernel_image, args.local_system_image,
+                       args.local_system_dlkm_image, args.local_vendor_image,
+                       args.local_vendor_boot_image] + args.local_tool:
+        if local_path and not os.path.exists(local_path):
+            raise errors.CheckPathError(
+                f"Specified path doesn't exist: {local_path}")
 
     if args.local_instance_dir and not os.path.exists(args.local_instance_dir):
         raise errors.CheckPathError(
             "Specified path doesn't exist: %s" % args.local_instance_dir)
 
+    if args.mix_system_dlkm_into_vendor_ramdisk and (
+            args.local_kernel_image is None or
+            args.local_system_dlkm_image is None):
+        raise errors.UnsupportedCreateArgs(
+            "If --mix-system_dlkm-into-vendor-ramdisk is specified, "
+            "--local-system_dlkm-image and --local-kernel-image must be "
+            "specified.")
+
     if not (args.local_system_image is None or
             args.avd_type in (constants.TYPE_CF, constants.TYPE_GF)):
         raise errors.UnsupportedCreateArgs("%s instance does not support "
@@ -909,16 +940,6 @@ def _VerifyLocalArgs(args):
             args.local_image if args.local_image else
             utils.GetBuildEnvironmentVariable(constants.ENV_ANDROID_PRODUCT_OUT)))
 
-    if (args.local_system_image and
-            not os.path.exists(args.local_system_image)):
-        raise errors.CheckPathError(
-            "Specified path doesn't exist: %s" % args.local_system_image)
-
-    for tool_dir in args.local_tool:
-        if not os.path.exists(tool_dir):
-            raise errors.CheckPathError(
-                "Specified path doesn't exist: %s" % tool_dir)
-
 
 def _VerifyHostArgs(args):
     """Verify args starting with --host.
@@ -969,11 +990,13 @@ def _VerifyGoldfishArgs(args):
     goldfish_only_flags = [
         args.emulator_build_id,
         args.emulator_build_target,
-        args.emulator_zip
+        args.emulator_zip,
+        args.mix_system_dlkm_into_vendor_ramdisk,
     ]
     if args.avd_type != constants.TYPE_GF and any(goldfish_only_flags):
         raise errors.UnsupportedCreateArgs(
-            f"--emulator-* is only valid with avd_type == {constants.TYPE_GF}")
+            "--emulator-* and --mix-system_dlkm-into-vendor-ramdisk are only "
+            f"valid with avd_type == {constants.TYPE_GF}")
 
     # Exclude kernel_build_target because the default value isn't empty.
     remote_kernel_flags = [
diff --git a/create/create_args_test.py b/create/create_args_test.py
index b5737ef..81f38e8 100644
--- a/create/create_args_test.py
+++ b/create/create_args_test.py
@@ -40,8 +40,10 @@ def _CreateArgs():
         local_image=None,
         local_kernel_image=None,
         local_system_image=None,
+        local_system_dlkm_image=None,
         local_instance_dir=None,
         local_vendor_boot_image=None,
+        local_tool=[],
         local_trusty_image=None,
         trusty_host_package=None,
         trusty_build_id=None,
@@ -73,6 +75,7 @@ def _CreateArgs():
         emulator_build_id=None,
         emulator_build_target=None,
         emulator_zip=None,
+        mix_system_dlkm_into_vendor_ramdisk=False,
         avd_type=constants.TYPE_CF,
         autoconnect=constants.INS_KEY_WEBRTC)
     return mock_args
@@ -121,7 +124,7 @@ class CreateArgsTest(driver_test_lib.BaseDriverTest):
                           create_args.VerifyArgs, mock_args)
         mock_args.boot_build_target = None
         # System build info without remote_host.
-        mock_args.system_branch = "aosp-master"
+        mock_args.system_branch = "aosp-main"
         mock_args.system_build_target = "aosp_x86_64-userdebug"
         mock_args.system_build_id = "123456"
         mock_args.remote_host = None
@@ -129,10 +132,10 @@ class CreateArgsTest(driver_test_lib.BaseDriverTest):
                           create_args.VerifyArgs, mock_args)
         # Valid build info.
         mock_args.emulator_build_target = "emulator-linux_x64_nolocationui"
-        mock_args.system_branch = "aosp-master"
+        mock_args.system_branch = "aosp-main"
         mock_args.system_build_target = "aosp_x86_64-userdebug"
         mock_args.system_build_id = "123456"
-        mock_args.boot_branch = "aosp-master"
+        mock_args.boot_branch = "aosp-main"
         mock_args.boot_build_target = "aosp_x86_64-userdebug"
         mock_args.boot_build_id = "123456"
         mock_args.boot_artifact = "boot-5.10.img"
@@ -194,6 +197,7 @@ class CreateArgsTest(driver_test_lib.BaseDriverTest):
         mock_args = _CreateArgs()
         mock_args.local_system_image = "/tmp/local_system_image_dir"
         mock_args.avd_type = "cheeps"
+        self.Patch(os.path, "exists", return_value=True)
         self.assertRaises(errors.UnsupportedCreateArgs,
                           create_args._VerifyLocalArgs, mock_args)
         mock_args.avd_type = "cuttlefish"
diff --git a/create/create_common.py b/create/create_common.py
index 8897e6e..c07746e 100644
--- a/create/create_common.py
+++ b/create/create_common.py
@@ -161,7 +161,7 @@ def GetCvdHostPackage(package_path=None):
                 return cvd_host_package
     raise errors.GetCvdLocalHostPackageError(
         "Can't find the cvd host package (Try lunching a cuttlefish target"
-        " like aosp_cf_x86_64_phone-userdebug and running 'm'): \n%s" %
+        " like aosp_cf_x86_64_phone-trunk_staging-userdebug and running 'm'): \n%s" %
         '\n'.join(dirs_to_check))
 
 
diff --git a/create/create_common_test.py b/create/create_common_test.py
index 52d361a..2e54bb2 100644
--- a/create/create_common_test.py
+++ b/create/create_common_test.py
@@ -244,10 +244,10 @@ class CreateCommonTest(driver_test_lib.BaseDriverTest):
         self.Patch(auth, "CreateCredentials", return_value=mock.MagicMock())
         avd_spec = mock.MagicMock()
         avd_spec.cfg = mock.MagicMock()
-        avd_spec.remote_image = {"build_target" : "aosp_cf_x86_64_phone-userdebug",
+        avd_spec.remote_image = {"build_target" : "aosp_cf_x86_64_phone-trunk_staging-userdebug",
                                  "build_id": "1234"}
         build_id = "1234"
-        build_target = "aosp_cf_x86_64_phone-userdebug"
+        build_target = "aosp_cf_x86_64_phone-trunk_staging-userdebug"
         checkfile1 = "aosp_cf_x86_phone-img-1234.zip"
         checkfile2 = "cvd-host_package.tar.gz"
         extract_path = "/tmp/1234"
diff --git a/create/remote_image_local_instance.py b/create/remote_image_local_instance.py
index bed1ad9..c4e07ad 100644
--- a/create/remote_image_local_instance.py
+++ b/create/remote_image_local_instance.py
@@ -140,8 +140,11 @@ def DownloadAndProcessImageFiles(avd_spec):
         fetch_cvd_args = list(constants.CMD_CVD_FETCH)
         creds_cache_file = os.path.join(_HOME_FOLDER, cfg.creds_cache_file)
         fetch_cvd_cert_arg = build_api.GetFetchCertArg(creds_cache_file)
-        fetch_cvd_args.extend([f"-directory={extract_path}",
+        fetch_cvd_args.extend([f"-target_directory={extract_path}",
                           fetch_cvd_cert_arg])
+        # Android boolean parsing does not recognize capitalized True/False as valid
+        lowercase_enable_value = str(avd_spec.enable_fetch_local_caching).lower()
+        fetch_cvd_args.extend([f"-enable_caching={lowercase_enable_value}"])
         fetch_cvd_args.extend(fetch_cvd_build_args)
         logger.debug("Download images command: %s", fetch_cvd_args)
         if not setup_common.PackageInstalled(constants.CUTTLEFISH_COMMOM_PKG):
diff --git a/create/remote_image_local_instance_test.py b/create/remote_image_local_instance_test.py
index 8f9790b..f85a69d 100644
--- a/create/remote_image_local_instance_test.py
+++ b/create/remote_image_local_instance_test.py
@@ -49,7 +49,7 @@ class RemoteImageLocalInstanceTest(driver_test_lib.BaseDriverTest):
             return_value=self.build_client)
         self.Patch(auth, "CreateCredentials", return_value=mock.MagicMock())
         self.RemoteImageLocalInstance = remote_image_local_instance.RemoteImageLocalInstance()
-        self._fake_remote_image = {"build_target" : "aosp_cf_x86_64_phone-userdebug",
+        self._fake_remote_image = {"build_target" : "aosp_cf_x86_64_phone-trunk_staging-userdebug",
                                    "build_id": "1234",
                                    "branch": "aosp_master"}
         self._extract_path = "/tmp/acloud_image_artifacts/1234"
@@ -102,7 +102,7 @@ class RemoteImageLocalInstanceTest(driver_test_lib.BaseDriverTest):
                    side_effect=errors.GetCvdLocalHostPackageError("not found"))
         paths = self.RemoteImageLocalInstance.GetImageArtifactsPath(avd_spec)
         create_common.DownloadRemoteArtifact.assert_called_with(
-            avd_spec.cfg, "aosp_cf_x86_64_phone-userdebug", "1234",
+            avd_spec.cfg, "aosp_cf_x86_64_phone-trunk_staging-userdebug", "1234",
             "aosp_cf_x86_64_phone-target_files-1234.zip", "/unit/test/mix_image_1234",
             decompress=True)
         self.assertEqual(paths.image_dir, "/mix_image_1234/IMAGES")
diff --git a/errors.py b/errors.py
index 7fd6452..db69830 100644
--- a/errors.py
+++ b/errors.py
@@ -203,6 +203,10 @@ class GetTrustyLocalHostPackageError(CreateError):
     """Can't find the trusty host package."""
 
 
+class GetTrustyLocalImagePackageError(CreateError):
+    """Can't find the trusty image package."""
+
+
 class GetSdkRepoPackageError(CreateError):
     """Can't find the local SDK repository package for goldfish."""
 
diff --git a/internal/constants.py b/internal/constants.py
index f5cefe2..4df259f 100755
--- a/internal/constants.py
+++ b/internal/constants.py
@@ -18,7 +18,7 @@ BRANCH_PREFIX = "git_"
 BUILD_TARGET_MAPPING = {
     # TODO: Add aosp goldfish targets and internal cf targets to vendor code
     # base.
-    "aosp_phone": "aosp_cf_x86_64_phone-userdebug",
+    "aosp_phone": "aosp_cf_x86_64_phone-trunk_staging-userdebug",
     "aosp_tablet": "aosp_cf_x86_tablet-userdebug",
 }
 SPEC_NAMES = {
@@ -82,9 +82,10 @@ FLAVOR_IOT = "iot"
 FLAVOR_TABLET = "tablet"
 FLAVOR_TABLET_3G = "tablet_3g"
 FLAVOR_FOLDABLE = "foldable"
+FLAVOR_DESKTOP = "desktop"
 ALL_FLAVORS = [
     FLAVOR_PHONE, FLAVOR_AUTO, FLAVOR_WEAR, FLAVOR_TV, FLAVOR_IOT,
-    FLAVOR_TABLET, FLAVOR_TABLET_3G, FLAVOR_FOLDABLE
+    FLAVOR_TABLET, FLAVOR_TABLET_3G, FLAVOR_FOLDABLE, FLAVOR_DESKTOP
 ]
 
 # HW Property
diff --git a/internal/lib/android_build_client.py b/internal/lib/android_build_client.py
index 4960bd0..a5538ca 100644
--- a/internal/lib/android_build_client.py
+++ b/internal/lib/android_build_client.py
@@ -41,7 +41,7 @@ BuildInfo = collections.namedtuple("BuildInfo", [
     "build_id",  # The build id string
     "build_target",  # The build target string
     "release_build_id"])  # The release build id string
-_DEFAULT_BRANCH = "aosp-master"
+_DEFAULT_BRANCH = "aosp-main"
 
 
 class AndroidBuildClient(base_cloud_client.BaseCloudApiClient):
@@ -64,14 +64,6 @@ class AndroidBuildClient(base_cloud_client.BaseCloudApiClient):
     ONE_RESULT = 1
     BUILD_SUCCESSFUL = True
     LATEST = "latest"
-    # FETCH_CVD variables.
-    FETCHER_NAME = "fetch_cvd"
-    FETCHER_BUILD_TARGET = "aosp_cf_x86_64_phone-trunk_staging-userdebug"
-    FETCHER_BUILD_TARGET_ARM = "aosp_cf_arm64_only_phone-trunk_staging-userdebug"
-    # TODO(b/297085994): cvd fetch is migrating from AOSP to github artifacts, so
-    # temporary returning hardcoded values instead of LKGB
-    FETCHER_BUILD_ID = 11559438
-    FETCHER_BUILD_ID_ARM = 11559085
     MAX_RETRY = 3
     RETRY_SLEEP_SECS = 3
 
@@ -89,7 +81,7 @@ class AndroidBuildClient(base_cloud_client.BaseCloudApiClient):
         """Get Android build attempt information.
 
         Args:
-            build_target: Target name, e.g. "aosp_cf_x86_64_phone-userdebug"
+            build_target: Target name, e.g. "aosp_cf_x86_64_phone-trunk_staging-userdebug"
             build_id: Build id, a string, e.g. "2263051", "P2804227"
             resource_id: Id of the resource, e.g "avd-system.tar.gz".
             local_dest: A local path where the artifact should be stored.
@@ -117,53 +109,6 @@ class AndroidBuildClient(base_cloud_client.BaseCloudApiClient):
             logger.error("Downloading artifact failed: %s", str(e))
             raise errors.DriverError(str(e))
 
-    def DownloadFetchcvd(
-            self,
-            local_dest,
-            fetch_cvd_version,
-            is_arm_version=False):
-        """Get fetch_cvd from Android Build.
-
-        Args:
-            local_dest: A local path where the artifact should be stored.
-                        e.g. "/tmp/fetch_cvd"
-            fetch_cvd_version: String of fetch_cvd version.
-            is_arm_version: is ARM version fetch_cvd.
-        """
-        if fetch_cvd_version == constants.LKGB:
-            fetch_cvd_version = self.GetFetcherVersion(is_arm_version)
-        fetch_cvd_build_target = (
-            self.FETCHER_BUILD_TARGET_ARM if is_arm_version
-            else self.FETCHER_BUILD_TARGET)
-        try:
-            utils.RetryExceptionType(
-                exception_types=(ssl.SSLError, errors.DriverError),
-                max_retries=self.MAX_RETRY,
-                functor=self.DownloadArtifact,
-                sleep_multiplier=self.RETRY_SLEEP_SECS,
-                retry_backoff_factor=utils.DEFAULT_RETRY_BACKOFF_FACTOR,
-                build_target=fetch_cvd_build_target,
-                build_id=fetch_cvd_version,
-                resource_id=self.FETCHER_NAME,
-                local_dest=local_dest,
-                attempt_id=self.LATEST)
-        except Exception:
-            logger.debug("Download fetch_cvd with build id: %s",
-                         constants.FETCH_CVD_SECOND_VERSION)
-            utils.RetryExceptionType(
-                exception_types=(ssl.SSLError, errors.DriverError),
-                max_retries=self.MAX_RETRY,
-                functor=self.DownloadArtifact,
-                sleep_multiplier=self.RETRY_SLEEP_SECS,
-                retry_backoff_factor=utils.DEFAULT_RETRY_BACKOFF_FACTOR,
-                build_target=fetch_cvd_build_target,
-                build_id=constants.FETCH_CVD_SECOND_VERSION,
-                resource_id=self.FETCHER_NAME,
-                local_dest=local_dest,
-                attempt_id=self.LATEST)
-        fetch_cvd_stat = os.stat(local_dest)
-        os.chmod(local_dest, fetch_cvd_stat.st_mode | stat.S_IEXEC)
-
     @staticmethod
     def ProcessBuild(build_info, ignore_artifact=False):
         """Create a Cuttlefish fetch_cvd build string.
@@ -199,8 +144,8 @@ class AndroidBuildClient(base_cloud_client.BaseCloudApiClient):
         Each build_info is a dictionary that contains 3 items, for example,
         {
             constants.BUILD_ID: "2263051",
-            constants.BUILD_TARGET: "aosp_cf_x86_64_phone-userdebug",
-            constants.BUILD_BRANCH: "aosp-master",
+            constants.BUILD_TARGET: "aosp_cf_x86_64_phone-trunk_staging-userdebug",
+            constants.BUILD_BRANCH: "aosp-main",
         }
 
         Args:
@@ -331,7 +276,7 @@ class AndroidBuildClient(base_cloud_client.BaseCloudApiClient):
         """Copy an Android Build artifact to a storage bucket.
 
         Args:
-            build_target: Target name, e.g. "aosp_cf_x86_64_phone-userdebug"
+            build_target: Target name, e.g. "aosp_cf_x86_64_phone-trunk_staging-userdebug"
             build_id: Build id, a string, e.g. "2263051", "P2804227"
             artifact_name: Name of the artifact, e.g "avd-system.tar.gz".
             destination_bucket: String, a google storage bucket name.
@@ -367,7 +312,7 @@ class AndroidBuildClient(base_cloud_client.BaseCloudApiClient):
         """Derives branch name.
 
         Args:
-            build_target: Target name, e.g. "aosp_cf_x86_64_phone-userdebug"
+            build_target: Target name, e.g. "aosp_cf_x86_64_phone-trunk_staging-userdebug"
             build_id: Build ID, a string, e.g. "2263051", "P2804227"
 
         Returns:
@@ -385,8 +330,8 @@ class AndroidBuildClient(base_cloud_client.BaseCloudApiClient):
         ... u'buildId': u'4949805', u'machineName'...}]}
 
         Args:
-            build_target: String, target name, e.g. "aosp_cf_x86_64_phone-userdebug"
-            build_branch: String, git branch name, e.g. "aosp-master"
+            build_target: String, target name, e.g. "aosp_cf_x86_64_phone-trunk_staging-userdebug"
+            build_branch: String, git branch name, e.g. "aosp-main"
 
         Returns:
             A string, string of build id number.
diff --git a/internal/lib/android_build_client_test.py b/internal/lib/android_build_client_test.py
index 247a2f7..ff30d45 100644
--- a/internal/lib/android_build_client_test.py
+++ b/internal/lib/android_build_client_test.py
@@ -135,7 +135,7 @@ class AndroidBuildClientTest(driver_test_lib.BaseDriverTest):
 
     def testGetBranch(self):
         """Test GetBuild."""
-        build_info = {"branch": "aosp-master"}
+        build_info = {"branch": "aosp-main"}
         mock_api = mock.MagicMock()
         mock_build = mock.MagicMock()
         mock_build.get.return_value = mock_api
diff --git a/internal/lib/android_compute_client.py b/internal/lib/android_compute_client.py
index 4dd07ee..37b61ad 100755
--- a/internal/lib/android_compute_client.py
+++ b/internal/lib/android_compute_client.py
@@ -164,7 +164,7 @@ class AndroidComputeClient(gcompute_client.ComputeClient):
         """Generate an image name given build_target, build_id.
 
         Args:
-            build_target: Target name, e.g. "aosp_cf_x86_64_phone-userdebug"
+            build_target: Target name, e.g. "aosp_cf_x86_64_phone-trunk_staging-userdebug"
             build_id: Build id, a string, e.g. "2263051", "P2804227"
 
         Returns:
@@ -197,7 +197,7 @@ class AndroidComputeClient(gcompute_client.ComputeClient):
         Target is not used as instance name has a length limit.
 
         Args:
-            build_target: Target name, e.g. "aosp_cf_x86_64_phone-userdebug"
+            build_target: Target name, e.g. "aosp_cf_x86_64_phone-trunk_staging-userdebug"
             build_id: Build id, a string, e.g. "2263051", "P2804227"
 
         Returns:
diff --git a/internal/lib/android_compute_client_test.py b/internal/lib/android_compute_client_test.py
index 1d36b6d..62e73e2 100644
--- a/internal/lib/android_compute_client_test.py
+++ b/internal/lib/android_compute_client_test.py
@@ -40,7 +40,7 @@ class AndroidComputeClientTest(driver_test_lib.BaseDriverTest):
     ZONE = "fake-zone"
     ORIENTATION = "portrait"
     DEVICE_RESOLUTION = "1200x1200x1200x1200"
-    TARGET = "aosp_cf_x86_64_phone-userdebug"
+    TARGET = "aosp_cf_x86_64_phone-trunk_staging-userdebug"
     BUILD_ID = "2263051"
     INSTANCE = "fake-instance"
     BOOT_COMPLETED_MSG = "VIRTUAL_DEVICE_BOOT_COMPLETED"
diff --git a/internal/lib/cvd_compute_client_multi_stage.py b/internal/lib/cvd_compute_client_multi_stage.py
index c6ba1b9..342523b 100644
--- a/internal/lib/cvd_compute_client_multi_stage.py
+++ b/internal/lib/cvd_compute_client_multi_stage.py
@@ -55,7 +55,6 @@ from acloud.setup import mkcert
 logger = logging.getLogger(__name__)
 
 _DEFAULT_WEBRTC_DEVICE_ID = "cvd-1"
-_FETCHER_NAME = "fetch_cvd"
 _TRUST_REMOTE_INSTANCE_COMMAND = (
     f"\"sudo cp -p ~/{constants.WEBRTC_CERTS_PATH}/{constants.SSL_CA_NAME}.pem "
     f"{constants.SSL_TRUST_CA_DIR}/{constants.SSL_CA_NAME}.crt;"
@@ -303,25 +302,6 @@ class CvdComputeClient(android_compute_client.AndroidComputeClient):
         self._execution_time[constants.TIME_GCE] = time.time() - timestart
         return ip
 
-    @utils.TimeExecute(function_description="Uploading build fetcher to instance")
-    def UpdateFetchCvd(self, fetch_cvd_version):
-        """Download fetch_cvd from the Build API, and upload it to a remote instance.
-
-        The version of fetch_cvd to use is retrieved from the configuration file. Once fetch_cvd
-        is on the instance, future commands can use it to download relevant Cuttlefish files from
-        the Build API on the instance itself.
-
-        Args:
-            fetch_cvd_version: String. The build id of fetch_cvd.
-        """
-        self.SetStage(constants.STAGE_ARTIFACT)
-        download_dir = tempfile.mkdtemp()
-        download_target = os.path.join(download_dir, _FETCHER_NAME)
-        self._build_api.DownloadFetchcvd(download_target, fetch_cvd_version)
-        self._ssh.ScpPushFile(src_file=download_target, dst_file=_FETCHER_NAME)
-        os.remove(download_target)
-        os.rmdir(download_dir)
-
     @utils.TimeExecute(function_description="Downloading build on instance")
     def FetchBuild(self, default_build_info, system_build_info,
                    kernel_build_info, boot_build_info, bootloader_build_info,
@@ -341,15 +321,16 @@ class CvdComputeClient(android_compute_client.AndroidComputeClient):
         Returns:
             List of string args for fetch_cvd.
         """
+        self.SetStage(constants.STAGE_ARTIFACT)
         timestart = time.time()
-        fetch_cvd_args = ["-credential_source=gce"]
+        cmd = list(constants.CMD_CVD_FETCH) + ["-credential_source=gce"]
         fetch_cvd_build_args = self._build_api.GetFetchBuildArgs(
             default_build_info, system_build_info, kernel_build_info,
             boot_build_info, bootloader_build_info, android_efi_loader_build_info,
             ota_build_info, host_package_build_info)
-        fetch_cvd_args.extend(fetch_cvd_build_args)
+        cmd.extend(fetch_cvd_build_args)
 
-        self._ssh.Run("./fetch_cvd " + " ".join(fetch_cvd_args),
+        self._ssh.Run(" ".join(cmd),
                       timeout=constants.DEFAULT_SSH_TIMEOUT)
         self._execution_time[constants.TIME_ARTIFACT] = time.time() - timestart
 
@@ -375,7 +356,7 @@ class CvdComputeClient(android_compute_client.AndroidComputeClient):
             try:
                 self._ssh.ScpPushFiles(upload_files, constants.WEBRTC_CERTS_PATH)
                 self._ssh.Run(_TRUST_REMOTE_INSTANCE_COMMAND)
-            except subprocess.CalledProcessError:
+            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                 logger.debug("Update WebRTC frontend certificate failed.")
 
     @utils.TimeExecute(function_description="Upload extra files to instance")
diff --git a/internal/lib/cvd_compute_client_multi_stage_test.py b/internal/lib/cvd_compute_client_multi_stage_test.py
index 8c31504..b5a2002 100644
--- a/internal/lib/cvd_compute_client_multi_stage_test.py
+++ b/internal/lib/cvd_compute_client_multi_stage_test.py
@@ -52,7 +52,7 @@ class CvdComputeClientTest(driver_test_lib.BaseDriverTest):
     ZONE = "fake-zone"
     PROJECT = "fake-project"
     BRANCH = "fake-branch"
-    TARGET = "aosp_cf_x86_64_phone-userdebug"
+    TARGET = "aosp_cf_x86_64_phone-trunk_staging-userdebug"
     BUILD_ID = "2263051"
     KERNEL_BRANCH = "fake-kernel-branch"
     KERNEL_BUILD_ID = "1234567"
diff --git a/internal/lib/cvd_utils.py b/internal/lib/cvd_utils.py
index 7b82baf..1035751 100644
--- a/internal/lib/cvd_utils.py
+++ b/internal/lib/cvd_utils.py
@@ -932,10 +932,12 @@ def ExecuteRemoteLaunchCvd(ssh_obj, cmd, boot_timeout_secs):
     """
     try:
         ssh_obj.Run(f"-t '{cmd}'", boot_timeout_secs, retry=0)
-    except (subprocess.CalledProcessError, errors.DeviceConnectionError,
-            errors.LaunchCVDFail) as e:
-        error_msg = ("Device did not finish on boot within "
-                     f"{boot_timeout_secs} secs)")
+    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
+            errors.DeviceConnectionError, errors.LaunchCVDFail) as e:
+        error_msg = "Device did not boot"
+        if isinstance(e, subprocess.TimeoutExpired):
+            error_msg = ("Device did not finish on boot within "
+                         f"{boot_timeout_secs} secs)")
         if constants.ERROR_MSG_VNC_NOT_SUPPORT in str(e):
             error_msg = ("VNC is not supported in the current build. Please "
                          "try WebRTC such as '$acloud create' or "
@@ -970,7 +972,7 @@ def _GetRemoteRuntimeDirs(ssh_obj, remote_dir, base_instance_num,
                                  _REMOTE_RUNTIME_DIR_FORMAT %
                                  {"num": base_instance_num + num})
                 for num in range(num_avds_per_instance)]
-    except subprocess.CalledProcessError:
+    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
         logger.debug("%s is not the runtime directory.", runtime_dir)
 
     legacy_runtime_dirs = [
diff --git a/internal/lib/cvd_utils_test.py b/internal/lib/cvd_utils_test.py
index 893d3f6..58fdfb0 100644
--- a/internal/lib/cvd_utils_test.py
+++ b/internal/lib/cvd_utils_test.py
@@ -769,7 +769,7 @@ class CvdUtilsTest(driver_test_lib.BaseDriverTest):
         remote_image = {
             "branch": "aosp-android-12-gsi",
             "build_id": "100000",
-            "build_target": "aosp_cf_x86_64_phone-userdebug"}
+            "build_target": "aosp_cf_x86_64_phone-trunk_staging-userdebug"}
         mock_avd_spec = mock.Mock(
             spec=[],
             remote_image=remote_image,
diff --git a/internal/lib/goldfish_utils.py b/internal/lib/goldfish_utils.py
index 02c8a47..582ad12 100644
--- a/internal/lib/goldfish_utils.py
+++ b/internal/lib/goldfish_utils.py
@@ -17,6 +17,7 @@
 import os
 import re
 import shutil
+import tempfile
 
 from acloud import errors
 from acloud.internal import constants
@@ -98,33 +99,60 @@ def _UnpackBootImage(output_dir, boot_image_path, ota):
     return kernel_path, ramdisk_path
 
 
-def _MixRamdiskImages(output_path, original_ramdisk_path,
-                      boot_ramdisk_path):
-    """Mix an emulator ramdisk with a boot ramdisk.
+def _ConvertSystemDlkmToRamdisk(output_path, system_dlkm_image_path, ota):
+    """Convert a system_dlkm image to a ramdisk.
+
+    This function creates a ramdisk that will be passed to _MixRamdiskImages.
+    The ramdisk includes kernel modules only. They will overwrite some of the
+    modules on emulator ramdisk.
+
+    Args:
+        output_path: The path to the output image.
+        system_dlkm_image_path: The path to the input image.
+        ota: An instance of ota_tools.OtaTools.
+    """
+    with tempfile.NamedTemporaryFile(
+            prefix="system_dlkm", suffix=".cpio") as system_dlkm_cpio:
+        with tempfile.TemporaryDirectory(
+                prefix="system_dlkm", suffix=".dir") as system_dlkm_dir:
+            # ext4 is not supported.
+            ota.ExtractErofsImage(system_dlkm_dir, system_dlkm_image_path)
+            # Do not overwrite modules.alias, modules.dep, modules.load, and
+            # modules.softdep when _MixRamdiskImages.
+            for parent_dir, _, file_names in os.walk(system_dlkm_dir):
+                for file_name in file_names:
+                    if not file_name.endswith(".ko"):
+                        os.remove(os.path.join(parent_dir, file_name))
+            ota.MkBootFs(system_dlkm_cpio.name, system_dlkm_dir)
+            ota.Lz4(output_path, system_dlkm_cpio.name)
+
+
+def _MixRamdiskImages(output_path, *ramdisk_paths):
+    """Mix an emulator ramdisk with other ramdisks.
 
     An emulator ramdisk consists of a boot ramdisk and a vendor ramdisk.
-    This method overlays a new boot ramdisk on the emulator ramdisk by
-    concatenating them.
+    This function overlays a new boot ramdisk and an optional system_dlkm
+    ramdisk on the emulator ramdisk by concatenating them.
 
     Args:
         output_path: The path to the output ramdisk.
-        original_ramdisk_path: The path to the emulator ramdisk.
-        boot_ramdisk_path: The path to the boot ramdisk.
+        ramdisk_paths: The path to the ramdisks to be overlaid.
     """
     with open(output_path, "wb") as mixed_ramdisk:
-        with open(original_ramdisk_path, "rb") as ramdisk:
-            shutil.copyfileobj(ramdisk, mixed_ramdisk)
-        with open(boot_ramdisk_path, "rb") as ramdisk:
-            shutil.copyfileobj(ramdisk, mixed_ramdisk)
+        for ramdisk_path in ramdisk_paths:
+            with open(ramdisk_path, "rb") as ramdisk:
+                shutil.copyfileobj(ramdisk, mixed_ramdisk)
 
 
-def MixWithBootImage(output_dir, image_dir, boot_image_path, ota):
+def MixWithBootImage(output_dir, image_dir, boot_image_path,
+                     system_dlkm_image_path, ota):
     """Mix emulator kernel images with a boot image.
 
     Args:
         output_dir: The directory containing the output and intermediate files.
         image_dir: The directory containing emulator kernel and ramdisk images.
         boot_image_path: The path to the boot image.
+        system_dlkm_image_path: The path to the system_dlkm_image. Can be None.
         ota: An instance of ota_tools.OtaTools.
 
     Returns:
@@ -140,13 +168,26 @@ def MixWithBootImage(output_dir, image_dir, boot_image_path, ota):
 
     kernel_path, boot_ramdisk_path = _UnpackBootImage(
         unpack_dir, boot_image_path, ota)
-    # The ramdisk unpacked from boot_image_path does not include emulator's
-    # kernel modules. The ramdisk in image_dir contains the modules. This
-    # method mixes the two ramdisks.
+    # The ramdisk in image_dir contains the emulator's kernel modules.
+    # The ramdisk unpacked from boot_image_path contains no module.
+    # The ramdisk converted from system_dlkm_image_path contains the modules
+    # that must be updated with the kernel.
     mixed_ramdisk_path = os.path.join(output_dir, _MIXED_RAMDISK_IMAGE_NAME)
-    original_ramdisk_path = _FindFileByNames(image_dir, _RAMDISK_IMAGE_NAMES)
-    _MixRamdiskImages(mixed_ramdisk_path, original_ramdisk_path,
-                      boot_ramdisk_path)
+    ramdisks = [_FindFileByNames(image_dir, _RAMDISK_IMAGE_NAMES),
+                boot_ramdisk_path]
+    system_dlkm_ramdisk = None
+    try:
+        if system_dlkm_image_path:
+            system_dlkm_ramdisk = tempfile.NamedTemporaryFile(
+                prefix="system_dlkm", suffix=".lz4")
+            _ConvertSystemDlkmToRamdisk(
+                system_dlkm_ramdisk.name, system_dlkm_image_path, ota)
+            ramdisks.append(system_dlkm_ramdisk.name)
+
+        _MixRamdiskImages(mixed_ramdisk_path, *ramdisks)
+    finally:
+        if system_dlkm_ramdisk:
+            system_dlkm_ramdisk.close()
     return kernel_path, mixed_ramdisk_path
 
 
diff --git a/internal/lib/goldfish_utils_test.py b/internal/lib/goldfish_utils_test.py
index a56f4f4..beea002 100644
--- a/internal/lib/goldfish_utils_test.py
+++ b/internal/lib/goldfish_utils_test.py
@@ -75,17 +75,26 @@ class GoldfishUtilsTest(unittest.TestCase):
             with open(os.path.join(out_dir, "ramdisk"), "w") as ramdisk:
                 ramdisk.write("boot")
 
+        def _MockLz4(out_path, _input_path):
+            with open(out_path, "w") as out_file:
+                out_file.write("system_dlkm")
+
         mock_ota = mock.Mock()
         mock_ota.UnpackBootImg.side_effect = _MockUnpackBootImg
+        mock_ota.Lz4.side_effect = _MockLz4
 
         kernel_path, ramdisk_path = goldfish_utils.MixWithBootImage(
-            mix_dir, image_dir, boot_image_path, mock_ota)
+            mix_dir, image_dir, boot_image_path, "/mock/system_dlkm", mock_ota)
 
         mock_ota.UnpackBootImg.assert_called_with(unpack_dir, boot_image_path)
+        mock_ota.ExtractErofsImage.assert_called_once_with(
+            mock.ANY, "/mock/system_dlkm")
+        mock_ota.MkBootFs.assert_called_once()
+        mock_ota.Lz4.assert_called_once()
         self.assertEqual(os.path.join(unpack_dir, "kernel"), kernel_path)
         self.assertEqual(os.path.join(mix_dir, "mixed_ramdisk"), ramdisk_path)
         with open(ramdisk_path, "r") as ramdisk:
-            self.assertEqual("originalboot", ramdisk.read())
+            self.assertEqual("originalbootsystem_dlkm", ramdisk.read())
 
     def testFindKernelImage(self):
         """Test FindKernelImage."""
diff --git a/internal/lib/ota_tools.py b/internal/lib/ota_tools.py
index 5048770..ad74aaa 100644
--- a/internal/lib/ota_tools.py
+++ b/internal/lib/ota_tools.py
@@ -26,13 +26,19 @@ _BIN_DIR_NAME = "bin"
 _LPMAKE = "lpmake"
 _BUILD_SUPER_IMAGE = "build_super_image"
 _AVBTOOL = "avbtool"
+_FSCK_EROFS= "fsck.erofs"
+_LZ4 = "lz4"
+_MKBOOTFS = "mkbootfs"
 _SGDISK = "sgdisk"
 _SIMG2IMG = "simg2img"
 _MK_COMBINED_IMG = "mk_combined_img"
 _UNPACK_BOOTIMG = "unpack_bootimg"
 
-_BUILD_SUPER_IMAGE_TIMEOUT_SECS = 30
+_BUILD_SUPER_IMAGE_TIMEOUT_SECS = 150
 _AVBTOOL_TIMEOUT_SECS = 30
+_FSCK_EROFS_TIMEOUT_SECS = 30
+_LZ4_TIMEOUT_SECS = 30
+_MKBOOTFS_TIMEOUT_SECS = 30
 _MK_COMBINED_IMG_TIMEOUT_SECS = 180
 _UNPACK_BOOTIMG_TIMEOUT_SECS = 30
 
@@ -206,6 +212,31 @@ class OtaTools:
             if new_misc_info_path:
                 os.remove(new_misc_info_path)
 
+    @utils.TimeExecute(function_description="Extract EROFS image")
+    @utils.TimeoutException(_FSCK_EROFS_TIMEOUT_SECS)
+    def ExtractErofsImage(self, output_dir, image_path):
+        """Use fsck.erofs to extract an image.
+
+        Args:
+            output_dir: The path to the output files.
+            image_path: The path to the EROFS image.
+        """
+        fsck_erofs = self._GetBinary(_FSCK_EROFS)
+        utils.Popen(fsck_erofs, "--extract=" + output_dir, image_path)
+
+    @utils.TimeExecute(function_description="lz4")
+    @utils.TimeoutException(_LZ4_TIMEOUT_SECS)
+    def Lz4(self, output_path, input_path):
+        """Compress a file into lz4.
+
+        Args:
+            output_path: The path to the output file.
+            input_path: The path to the input file.
+        """
+        lz4 = self._GetBinary(_LZ4)
+        # -l is the legacy format for Linux kernel.
+        utils.Popen(lz4, "-l", "-f", input_path, output_path)
+
     @utils.TimeExecute(function_description="Make disabled vbmeta image.")
     @utils.TimeoutException(_AVBTOOL_TIMEOUT_SECS)
     def MakeDisabledVbmetaImage(self, output_path):
@@ -220,6 +251,19 @@ class OtaTools:
                     "--padding_size", "4096",
                     "--output", output_path)
 
+    @utils.TimeExecute(function_description="mkbootfs")
+    @utils.TimeoutException(_MKBOOTFS_TIMEOUT_SECS)
+    def MkBootFs(self, output_path, input_dir):
+        """Use mkbootfs to create a cpio file.
+
+         Args:
+             output_path: The path to the output file.
+             input_dir: The path to the input directory.
+         """
+        mkbootfs = self._GetBinary(_MKBOOTFS)
+        with open(output_path, "wb") as output_file:
+            utils.Popen(mkbootfs, input_dir, stdout=output_file)
+
     @staticmethod
     def _RewriteSystemQemuConfig(output_file, input_file, get_image):
         """Rewrite image paths in system-qemu-config.txt.
diff --git a/internal/lib/ota_tools_test.py b/internal/lib/ota_tools_test.py
index d49f93f..8d987e3 100644
--- a/internal/lib/ota_tools_test.py
+++ b/internal/lib/ota_tools_test.py
@@ -240,6 +240,26 @@ class OtaToolsTest(unittest.TestCase):
         self.assertEqual(mock_popen.call_args[0][0], expected_cmd)
         self.assertFalse(mock_popen.call_args[1]["env"])
 
+    @mock.patch("acloud.internal.lib.utils.subprocess.Popen")
+    def testMkBootFs(self, mock_popen):
+        """Test MkBootFs."""
+        mkbootfs = self._CreateBinary("mkbootfs")
+        output_path = os.path.join(self._temp_dir, "out")
+
+        mock_popen.return_value = self._MockPopen(return_value=0)
+        mock_open = mock.mock_open()
+
+        with mock.patch("acloud.internal.lib.ota_tools.open",
+                        mock_open):
+            self._ota.MkBootFs(output_path, "/in/dir")
+
+        expected_cmd = (mkbootfs, "/in/dir")
+
+        mock_popen.assert_called_once()
+        mock_open.assert_called_once_with(output_path, "wb")
+        self.assertEqual(mock_popen.call_args[0][0], expected_cmd)
+        self.assertEqual(mock_popen.call_args[1]["stdout"], mock_open())
+
     # pylint: disable=broad-except
     def _TestMkCombinedImg(self, mock_popen, mock_popen_object,
                            expected_error=None):
diff --git a/internal/lib/oxygen_client.py b/internal/lib/oxygen_client.py
index 24daa15..a6cedeb 100644
--- a/internal/lib/oxygen_client.py
+++ b/internal/lib/oxygen_client.py
@@ -32,9 +32,9 @@ class OxygenClient():
         """Lease one cuttlefish device.
 
         Args:
-            build_target: Target name, e.g. "aosp_cf_x86_64_phone-userdebug"
+            build_target: Target name, e.g. "aosp_cf_x86_64_phone-trunk_staging-userdebug"
             build_id: Build ID, a string, e.g. "2263051", "P2804227"
-            build_branch: Build branch, e.g. "aosp-master"
+            build_branch: Build branch, e.g. "aosp-main"
             system_build_target: Target name of system build
             system_build_id: Build ID of system build
             kernel_build_target: Target name of kernel build
diff --git a/internal/lib/ssh.py b/internal/lib/ssh.py
index 524a297..01c50ae 100755
--- a/internal/lib/ssh.py
+++ b/internal/lib/ssh.py
@@ -18,7 +18,6 @@ import logging
 import re
 import subprocess
 import sys
-import threading
 
 from acloud import errors
 from acloud.internal import constants
@@ -40,60 +39,6 @@ _ERROR_MSG_DEL_TAGS_RE = (r"(<[\/]*(a|b|p|span|ins|code|title)>)|"
                           r"(<(a|span|meta|html|!)[^>]*>)")
 
 
-def _SshCallWait(cmd, timeout=None):
-    """Runs a single SSH command.
-
-    - SSH returns code 0 for "Successful execution".
-    - Use wait() until the process is complete without receiving any output.
-
-    Args:
-        cmd: String of the full SSH command to run, including the SSH binary
-             and its arguments.
-        timeout: Optional integer, number of seconds to give
-
-    Returns:
-        An exit status of 0 indicates that it ran successfully.
-    """
-    logger.info("Running command \"%s\"", cmd)
-    process = subprocess.Popen(cmd, shell=True, stdin=None,
-                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
-    if timeout:
-        # TODO: if process is killed, out error message to log.
-        timer = threading.Timer(timeout, process.kill)
-        timer.start()
-    process.wait()
-    if timeout:
-        timer.cancel()
-    return process.returncode
-
-
-def _SshCall(cmd, timeout=None):
-    """Runs a single SSH command.
-
-    - SSH returns code 0 for "Successful execution".
-    - Use communicate() until the process and the child thread are complete.
-
-    Args:
-        cmd: String of the full SSH command to run, including the SSH binary
-             and its arguments.
-        timeout: Optional integer, number of seconds to give
-
-    Returns:
-        An exit status of 0 indicates that it ran successfully.
-    """
-    logger.info("Running command \"%s\"", cmd)
-    process = subprocess.Popen(cmd, shell=True, stdin=None,
-                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
-    if timeout:
-        # TODO: if process is killed, out error message to log.
-        timer = threading.Timer(timeout, process.kill)
-        timer.start()
-    process.communicate()
-    if timeout:
-        timer.cancel()
-    return process.returncode
-
-
 def _SshLogOutput(cmd, timeout=None, show_output=False, hide_error_msg=False):
     """Runs a single SSH command while logging its output and processes its return code.
 
@@ -114,6 +59,7 @@ def _SshLogOutput(cmd, timeout=None, show_output=False, hide_error_msg=False):
     Raises:
         errors.DeviceConnectionError: Failed to connect to the GCE instance.
         subprocess.CalledProcessError: The process exited with an error on the instance.
+        subprocess.TimeoutExpired: The process timed out.
         errors.LaunchCVDFail: Happened on launch_cvd with specific pattern of error message.
     """
     # Use "exec" to let cmd to inherit the shell process, instead of having the
@@ -123,19 +69,22 @@ def _SshLogOutput(cmd, timeout=None, show_output=False, hide_error_msg=False):
     process = subprocess.Popen(cmd, shell=True, stdin=None,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True)
-    if timeout:
-        # TODO: if process is killed, out error message to log.
-        timer = threading.Timer(timeout, process.kill)
-        timer.start()
-    stdout, _ = process.communicate()
-    if stdout:
-        if (show_output or process.returncode != 0) and not hide_error_msg:
-            print(stdout.strip(), file=sys.stderr)
-        else:
-            # fetch_cvd and launch_cvd can be noisy, so left at debug
-            logger.debug(stdout.strip())
-    if timeout:
-        timer.cancel()
+
+    stdout = None
+    try:
+        stdout, _ = process.communicate(timeout=timeout)
+    except subprocess.TimeoutExpired:
+        process.kill()
+        stdout, _ = process.communicate()
+        raise
+    finally:
+        if stdout:
+            if (show_output or process.returncode != 0) and not hide_error_msg:
+                print(stdout.strip(), file=sys.stderr)
+            else:
+                # fetch_cvd and launch_cvd can be noisy, so left at debug
+                logger.debug(stdout.strip())
+
     if process.returncode == 255:
         error_msg = (f"Failed to send command to instance {cmd}\n"
                      f"Error message: {_GetErrorMessage(stdout)}")
@@ -210,11 +159,13 @@ def ShellCmdWithRetry(cmd, timeout=None, show_output=False,
         errors.DeviceConnectionError: For any non-zero return code of remote_cmd.
         errors.LaunchCVDFail: Happened on launch_cvd with specific pattern of error message.
         subprocess.CalledProcessError: The process exited with an error on the instance.
+        subprocess.TimeoutExpired: The process timed out.
     """
     return utils.RetryExceptionType(
         exception_types=(errors.DeviceConnectionError,
                          errors.LaunchCVDFail,
-                         subprocess.CalledProcessError),
+                         subprocess.CalledProcessError,
+                         subprocess.TimeoutExpired),
         max_retries=retry,
         functor=_SshLogOutput,
         sleep_multiplier=_SSH_CMD_RETRY_SLEEP,
@@ -352,7 +303,7 @@ class Ssh():
         remote_cmd.append("uptime")
         try:
             _SshLogOutput(" ".join(remote_cmd), timeout, hide_error_msg=True)
-        except subprocess.CalledProcessError as e:
+        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
             raise errors.DeviceConnectionError(
                 "Ssh isn't ready in the remote instance.") from e
 
diff --git a/internal/lib/ssh_test.py b/internal/lib/ssh_test.py
index 72ba397..cb8f56c 100644
--- a/internal/lib/ssh_test.py
+++ b/internal/lib/ssh_test.py
@@ -18,7 +18,6 @@
 
 import io
 import subprocess
-import threading
 import time
 import unittest
 
@@ -238,47 +237,11 @@ class SshTest(driver_test_lib.BaseDriverTest):
                           timeout=1,
                           max_retry=1)
 
-    def testSshCallWait(self):
-        """Test SshCallWait."""
-        self.Patch(subprocess, "Popen", return_value=self.created_subprocess)
-        self.Patch(threading, "Timer")
-        fake_cmd = "fake command"
-        ssh._SshCallWait(fake_cmd)
-        threading.Timer.assert_not_called()
-
-    def testSshCallWaitTimeout(self):
-        """Test SshCallWait with timeout."""
-        self.Patch(subprocess, "Popen", return_value=self.created_subprocess)
-        self.Patch(threading, "Timer")
-        fake_cmd = "fake command"
-        fake_timeout = 30
-        ssh._SshCallWait(fake_cmd, fake_timeout)
-        threading.Timer.assert_called_once()
-
-    def testSshCall(self):
-        """Test _SshCall."""
-        self.Patch(subprocess, "Popen", return_value=self.created_subprocess)
-        self.Patch(threading, "Timer")
-        fake_cmd = "fake command"
-        ssh._SshCall(fake_cmd)
-        threading.Timer.assert_not_called()
-
-    def testSshCallTimeout(self):
-        """Test SshCallWait with timeout."""
-        self.Patch(subprocess, "Popen", return_value=self.created_subprocess)
-        self.Patch(threading, "Timer")
-        fake_cmd = "fake command"
-        fake_timeout = 30
-        ssh._SshCall(fake_cmd, fake_timeout)
-        threading.Timer.assert_called_once()
-
     def testSshLogOutput(self):
-        """Test _SshCall."""
+        """Test _SshLogOutput."""
         self.Patch(subprocess, "Popen", return_value=self.created_subprocess)
-        self.Patch(threading, "Timer")
         fake_cmd = "fake command"
         ssh._SshLogOutput(fake_cmd)
-        threading.Timer.assert_not_called()
 
         # Test with all kind of exceptions.
         self.created_subprocess.returncode = 255
@@ -302,13 +265,18 @@ class SshTest(driver_test_lib.BaseDriverTest):
                 errors.LaunchCVDFail, ssh._SshLogOutput, fake_cmd)
 
     def testSshLogOutputTimeout(self):
-        """Test SshCallWait with timeout."""
+        """Test SshLogOutput with timeout."""
         self.Patch(subprocess, "Popen", return_value=self.created_subprocess)
-        self.Patch(threading, "Timer")
         fake_cmd = "fake command"
         fake_timeout = 30
-        ssh._SshLogOutput(fake_cmd, fake_timeout)
-        threading.Timer.assert_called_once()
+        self.created_subprocess.communicate.side_effect = [
+            subprocess.TimeoutExpired(fake_cmd, fake_timeout),
+            ("stdout", None)]
+        with self.assertRaises(subprocess.TimeoutExpired) as e:
+            ssh._SshLogOutput(fake_cmd, fake_timeout)
+            self.assertEqual(constants.ERROR_MSG_TIMEOUT, str(e.exception))
+        self.assertEqual(self.created_subprocess.communicate.call_count, 2)
+        self.created_subprocess.kill.assert_called_once()
 
     def testGetErrorMessage(self):
         """Test _GetErrorMessage."""
diff --git a/internal/lib/utils.py b/internal/lib/utils.py
index 9829035..51f0082 100755
--- a/internal/lib/utils.py
+++ b/internal/lib/utils.py
@@ -1551,9 +1551,8 @@ def Popen(*command, **popen_args):
     proc = None
     try:
         logger.info("Execute %s", command)
-        popen_args["stdin"] = subprocess.PIPE
-        popen_args["stdout"] = subprocess.PIPE
-        popen_args["stderr"] = subprocess.PIPE
+        for io_arg in ("stdin", "stdout", "stderr"):
+            popen_args.setdefault(io_arg, subprocess.PIPE)
 
         # Some OTA tools are Python scripts in different versions. The
         # PYTHONPATH for acloud may be incompatible with the tools.
diff --git a/list/instance.py b/list/instance.py
index 0372a30..a244f39 100644
--- a/list/instance.py
+++ b/list/instance.py
@@ -659,7 +659,7 @@ class LocalInstance(Instance):
                     if os.environ.get(env_host_out, _NO_ANDROID_ENV) in cvd_status_cmd:
                         logger.warning(
                             "Can't find the cvd_status tool (Try lunching a "
-                            "cuttlefish target like aosp_cf_x86_64_phone-userdebug "
+                            "cuttlefish target like aosp_cf_x86_64_phone-trunk_staging-userdebug "
                             "and running 'make hosttar' before list/delete local "
                             "instances)")
                 return False
diff --git a/powerwash/powerwash.py b/powerwash/powerwash.py
index 05ab4e5..7862c6a 100644
--- a/powerwash/powerwash.py
+++ b/powerwash/powerwash.py
@@ -64,7 +64,8 @@ def PowerwashDevice(ssh, instance_id):
     ssh_command = "./bin/powerwash_cvd --instance_num=%d" % (instance_id)
     try:
         ssh.Run(ssh_command)
-    except (subprocess.CalledProcessError, errors.DeviceConnectionError) as e:
+    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
+            errors.DeviceConnectionError) as e:
         logger.debug(str(e))
         utils.PrintColorString(str(e), utils.TextColors.FAIL)
 
diff --git a/public/actions/remote_host_cf_device_factory.py b/public/actions/remote_host_cf_device_factory.py
index 6c96d04..15a50ae 100644
--- a/public/actions/remote_host_cf_device_factory.py
+++ b/public/actions/remote_host_cf_device_factory.py
@@ -103,7 +103,7 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
         try:
             image_args = self._ProcessRemoteHostArtifacts(deadline)
         except (errors.CreateError, errors.DriverError,
-                subprocess.CalledProcessError) as e:
+                subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
             logger.exception("Fail to prepare artifacts.")
             self._all_failures[instance] = str(e)
             # If an SSH error or timeout happens, report the name for the
@@ -125,7 +125,7 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
             self._FindLogFiles(
                 instance, (error_msg and not self._avd_spec.no_pull_log))
         except (errors.SubprocessFail, errors.DeviceConnectionError,
-                subprocess.CalledProcessError) as e:
+                subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
             logger.error("Fail to find log files: %s", e)
 
         return instance
@@ -351,11 +351,14 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
             self._avd_spec.ota_build_info,
             self._avd_spec.host_package_build_info)
 
+        # Android boolean parsing does not recognize capitalized True/False as valid
+        lowercase_enable_value = str(self._avd_spec.enable_fetch_local_caching).lower()
         fetch_cvd_args = self._avd_spec.fetch_cvd_wrapper.split(',') + [
             f"-fetch_cvd_path={constants.CMD_CVD_FETCH[0]}",
             constants.CMD_CVD_FETCH[1],
-            f"-directory={self._GetArtifactPath()}",
-            self._GetRemoteFetchCredentialArg()]
+            f"-target_directory={self._GetArtifactPath()}",
+            self._GetRemoteFetchCredentialArg(),
+            f"-enable_caching={lowercase_enable_value}"]
         fetch_cvd_args.extend(fetch_cvd_build_args)
 
         ssh_cmd = self._ssh.GetBaseCmd(constants.SSH_BIN)
@@ -380,8 +383,11 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
             self._avd_spec.host_package_build_info)
 
         fetch_cvd_args = list(constants.CMD_CVD_FETCH)
-        fetch_cvd_args.extend([f"-directory={self._GetArtifactPath()}",
-                               self._GetRemoteFetchCredentialArg()])
+        # Android boolean parsing does not recognize capitalized True/False as valid
+        lowercase_enable_value = str(self._avd_spec.enable_fetch_local_caching).lower()
+        fetch_cvd_args.extend([f"-target_directory={self._GetArtifactPath()}",
+                               self._GetRemoteFetchCredentialArg(),
+                               f"-enable_caching={lowercase_enable_value}"])
         fetch_cvd_args.extend(fetch_cvd_build_args)
 
         ssh_cmd = self._ssh.GetBaseCmd(constants.SSH_BIN)
@@ -434,7 +440,11 @@ class RemoteHostDeviceFactory(base_device_factory.BaseDeviceFactory):
         creds_cache_file = os.path.join(_HOME_FOLDER, cfg.creds_cache_file)
         fetch_cvd_cert_arg = self._build_api.GetFetchCertArg(creds_cache_file)
         fetch_cvd_args = list(constants.CMD_CVD_FETCH)
-        fetch_cvd_args.extend([f"-directory={extract_path}", fetch_cvd_cert_arg])
+        # Android boolean parsing does not recognize capitalized True/False as valid
+        lowercase_enable_value = str(self._avd_spec.enable_fetch_local_caching).lower()
+        fetch_cvd_args.extend([f"-target_directory={extract_path}",
+                               fetch_cvd_cert_arg,
+                               f"-enable_caching={lowercase_enable_value}"])
         fetch_cvd_args.extend(fetch_cvd_build_args)
         logger.debug("Download images command: %s", fetch_cvd_args)
         try:
diff --git a/public/actions/remote_host_cf_device_factory_test.py b/public/actions/remote_host_cf_device_factory_test.py
index 49036ec..39752b7 100644
--- a/public/actions/remote_host_cf_device_factory_test.py
+++ b/public/actions/remote_host_cf_device_factory_test.py
@@ -46,14 +46,13 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         mock_cfg = mock.Mock(spec=[],
                              ssh_private_key_path="/mock/id_rsa",
                              extra_args_ssh_tunnel="extra args",
-                             fetch_cvd_version="123456",
                              creds_cache_file="credential",
                              service_account_json_private_key_path="/mock/key")
         return mock.Mock(spec=[],
                          remote_image={
                              "branch": "aosp-android12-gsi",
                              "build_id": "100000",
-                             "build_target": "aosp_cf_x86_64_phone-userdebug"},
+                             "build_target": "aosp_cf_x86_64_phone-trunk_staging-userdebug"},
                          system_build_info={},
                          kernel_build_info={},
                          boot_build_info={},
@@ -76,8 +75,8 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
                          fetch_cvd_wrapper=None,
                          base_instance_num=None,
                          num_avds_per_instance=None,
-                         fetch_cvd_version="123456",
                          openwrt=True,
+                         enable_fetch_local_caching=False,
                          cfg=mock_cfg)
 
     @mock.patch("acloud.public.actions.remote_host_cf_device_factory.ssh")
@@ -270,7 +269,7 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         # ProcessRemoteHostArtifacts
         mock_ssh_obj.Run.assert_called_with("mkdir -p acloud_cf_1")
         self._mock_build_api.DownloadArtifact.assert_called_once_with(
-            "aosp_cf_x86_64_phone-userdebug", "100000", "mock.zip", mock.ANY)
+            "aosp_cf_x86_64_phone-trunk_staging-userdebug", "100000", "mock.zip", mock.ANY)
         mock_cvd_utils.ExtractTargetFilesZip.assert_called_once()
         mock_check_call.assert_called_once()
         mock_ssh.ShellCmdWithRetry.assert_called_once()
@@ -322,8 +321,9 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
                          r"/mock/ssh -- tar -xf - --lzop -S -C acloud_cf_1$")
         self.assertRegex(mock_ssh.ShellCmdWithRetry.call_args_list[1][0][0],
                          r"^/mock/ssh -- cvd fetch "
-                         r"-directory=acloud_cf_1 "
+                         r"-target_directory=acloud_cf_1 "
                          r"-credential_source=acloud_cf_1/credential_key.json "
+                         r"-enable_caching=false "
                          r"-test$")
         mock_cvd_utils.ExecuteRemoteLaunchCvd.assert_called()
         mock_pull.GetAllLogFilePaths.assert_not_called()
@@ -379,8 +379,9 @@ class RemoteHostDeviceFactoryTest(driver_test_lib.BaseDriverTest):
                          r"java -jar /home/shared/FetchCvdWrapper.jar "
                          r"-fetch_cvd_path=cvd "
                          r"fetch "
-                         r"-directory=acloud_cf_1 "
+                         r"-target_directory=acloud_cf_1 "
                          r"-credential_source=acloud_cf_1/credential_key.json "
+                         r"-enable_caching=false "
                          r"-test$")
         mock_cvd_utils.ExecuteRemoteLaunchCvd.assert_called()
         mock_pull.GetAllLogFilePaths.assert_not_called()
diff --git a/public/actions/remote_host_gf_device_factory.py b/public/actions/remote_host_gf_device_factory.py
index a55fd30..f2d2f59 100644
--- a/public/actions/remote_host_gf_device_factory.py
+++ b/public/actions/remote_host_gf_device_factory.py
@@ -202,7 +202,8 @@ class RemoteHostGoldfishDeviceFactory(base_device_factory.BaseDeviceFactory):
             self._logs[instance_name] = self._GetEmulatorLogs()
             self._StartEmulator(remote_paths)
             self._WaitForEmulator()
-        except (errors.DriverError, subprocess.CalledProcessError) as e:
+        except (errors.DriverError, subprocess.CalledProcessError,
+                subprocess.TimeoutExpired) as e:
             # Catch the generic runtime error and CalledProcessError which is
             # raised by the ssh module.
             self._failures[instance_name] = e
@@ -557,7 +558,8 @@ class RemoteHostGoldfishDeviceFactory(base_device_factory.BaseDeviceFactory):
                 if artifact_paths.boot_image:
                     remote_kernel_path, remote_ramdisk_path = (
                         self._MixAndUploadKernelImages(
-                            image_dir, artifact_paths.boot_image, ota))
+                            image_dir, artifact_paths.boot_image,
+                            artifact_paths.system_dlkm_image, ota))
 
         return RemotePaths(remote_image_dir, remote_emulator_dir,
                            remote_kernel_path, remote_ramdisk_path)
@@ -659,12 +661,15 @@ class RemoteHostGoldfishDeviceFactory(base_device_factory.BaseDeviceFactory):
 
         return remote_disk_image_path
 
-    def _MixAndUploadKernelImages(self, image_dir, boot_image_path, ota):
+    def _MixAndUploadKernelImages(self, image_dir, boot_image_path,
+                                  system_dlkm_image_path, ota):
         """Mix emulator kernel images with a boot image and upload them.
 
         Args:
             image_dir: The directory containing emulator images.
             boot_image_path: The path to the boot image.
+            system_dlkm_image_path: The path to the system_dlkm image.
+                                    Can be None.
             ota: An instance of ota_tools.OtaTools.
 
         Returns:
@@ -674,7 +679,10 @@ class RemoteHostGoldfishDeviceFactory(base_device_factory.BaseDeviceFactory):
         remote_ramdisk_path = self._GetInstancePath(_REMOTE_RAMDISK_PATH)
         with tempfile.TemporaryDirectory("host_gf_kernel") as temp_dir:
             kernel_path, ramdisk_path = goldfish_utils.MixWithBootImage(
-                temp_dir, image_dir, boot_image_path, ota)
+                temp_dir, image_dir, boot_image_path,
+                (system_dlkm_image_path if
+                 self._avd_spec.mix_system_dlkm_into_vendor_ramdisk else None),
+                ota)
 
             self._ssh.ScpPushFile(kernel_path, remote_kernel_path)
             self._ssh.ScpPushFile(ramdisk_path, remote_ramdisk_path)
diff --git a/public/actions/remote_host_gf_device_factory_test.py b/public/actions/remote_host_gf_device_factory_test.py
index 09a25e1..293f91f 100644
--- a/public/actions/remote_host_gf_device_factory_test.py
+++ b/public/actions/remote_host_gf_device_factory_test.py
@@ -67,6 +67,7 @@ class RemoteHostGoldfishDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         "local_kernel_image": None,
         "local_system_image": None,
         "local_system_dlkm_image": None,
+        "mix_system_dlkm_into_vendor_ramdisk": False,
         "local_tool_dirs": [],
         "base_instance_num": None,
         "boot_timeout_secs": None,
@@ -303,7 +304,8 @@ class RemoteHostGoldfishDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         self.assertEqual(
             5, self._mock_android_build_client.DownloadArtifact.call_count)
         # Images.
-        mock_gf_utils.MixWithBootImage.assert_called_once()
+        mock_gf_utils.MixWithBootImage.assert_called_once_with(
+             mock.ANY, mock.ANY, mock.ANY, None, mock.ANY)
         self._mock_ssh.ScpPushFile.assert_any_call(
             "/path/to/kernel", "acloud_gf_1/kernel")
         self._mock_ssh.ScpPushFile.assert_any_call(
@@ -340,8 +342,12 @@ class RemoteHostGoldfishDeviceFactoryTest(driver_test_lib.BaseDriverTest):
             self._mock_avd_spec.local_system_image = system_image_path
             self._mock_avd_spec.local_system_dlkm_image = (
                 system_dlkm_image_path)
+            self._mock_avd_spec.mix_system_dlkm_into_vendor_ramdisk = True
             self._mock_avd_spec.local_tool_dirs.append("/otatools")
             mock_gf_utils.ConvertAvdSpecToArgs.return_value = ["-gpu", "auto"]
+            mock_gf_utils.FindBootImage.return_value = boot_image_path
+            mock_gf_utils.FindSystemDlkmImage.return_value = (
+                system_dlkm_image_path)
             mock_gf_utils.MixWithBootImage.return_value = (
                 "/path/to/kernel", "/path/to/ramdisk")
             self._mock_create_credentials.side_effect = AssertionError(
@@ -351,8 +357,8 @@ class RemoteHostGoldfishDeviceFactoryTest(driver_test_lib.BaseDriverTest):
                 self._mock_avd_spec)
             factory.CreateInstance()
 
-            mock_gf_utils.FindSystemDlkmImage.assert_called_once()
-            mock_gf_utils.MixWithBootImage.assert_called_once()
+            mock_gf_utils.MixWithBootImage.assert_called_once_with(
+                mock.ANY, mock.ANY, boot_image_path, system_dlkm_image_path, mock.ANY)
             mock_gf_utils.MixDiskImage.assert_called_once()
             mock_ota_tools.FindOtaToolsDir.assert_called_once()
             self.assertEqual("/otatools",
diff --git a/public/actions/remote_instance_cf_device_factory.py b/public/actions/remote_instance_cf_device_factory.py
index 1fbab05..8db867b 100644
--- a/public/actions/remote_instance_cf_device_factory.py
+++ b/public/actions/remote_instance_cf_device_factory.py
@@ -79,7 +79,7 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
                 (instance in self.GetFailures() and
                  not self._avd_spec.no_pull_log))
         except (errors.SubprocessFail, errors.DeviceConnectionError,
-                subprocess.CalledProcessError) as e:
+                subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
             logger.error("Fail to find log files: %s", e)
 
         return instance
@@ -112,7 +112,6 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
                      avd_spec.local_image_dir),
                     self._cvd_host_package_artifact)
             elif avd_spec.image_source == constants.IMAGE_SRC_REMOTE:
-                self._compute_client.UpdateFetchCvd(avd_spec.fetch_cvd_version)
                 self._compute_client.FetchBuild(
                     avd_spec.remote_image,
                     avd_spec.system_build_info,
diff --git a/public/actions/remote_instance_cf_device_factory_test.py b/public/actions/remote_instance_cf_device_factory_test.py
index a658a12..f0cbad7 100644
--- a/public/actions/remote_instance_cf_device_factory_test.py
+++ b/public/actions/remote_instance_cf_device_factory_test.py
@@ -43,7 +43,6 @@ class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         self.Patch(android_build_client.AndroidBuildClient, "InitResourceHandle")
         self.Patch(cvd_compute_client_multi_stage.CvdComputeClient, "InitResourceHandle")
         self.Patch(cvd_compute_client_multi_stage.CvdComputeClient, "LaunchCvd")
-        self.Patch(cvd_compute_client_multi_stage.CvdComputeClient, "UpdateFetchCvd")
         self.Patch(cvd_compute_client_multi_stage.CvdComputeClient, "FetchBuild")
         self.Patch(list_instances, "GetInstancesFromInstanceNames", return_value=mock.MagicMock())
         self.Patch(list_instances, "ChooseOneRemoteInstance", return_value=mock.MagicMock())
@@ -111,7 +110,6 @@ class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         factory_remote_img._ProcessArtifacts()
 
         compute_client = factory_remote_img.GetComputeClient()
-        compute_client.UpdateFetchCvd.assert_called_once()
         compute_client.FetchBuild.assert_called_once()
 
     # pylint: disable=protected-access
diff --git a/public/actions/remote_instance_trusty_device_factory.py b/public/actions/remote_instance_trusty_device_factory.py
index 48ac608..2ecc090 100644
--- a/public/actions/remote_instance_trusty_device_factory.py
+++ b/public/actions/remote_instance_trusty_device_factory.py
@@ -35,20 +35,38 @@ from acloud.pull import pull
 
 logger = logging.getLogger(__name__)
 _CONFIG_JSON_FILENAME = "config.json"
-_REMOTE_STDOUT_PATH = "kernel.log"
-_REMOTE_STDERR_PATH = "qemu_trusty_err.log"
-_TRUSTY_IMAGE_PACKAGE = "trusty_image_package.tar.gz"
+
+# log files under REMOTE_LOG_FOLDER in order to
+# enable `acloud pull` to retrieve them
+_REMOTE_LOG_FOLDER = constants.REMOTE_LOG_FOLDER
+_REMOTE_STDOUT_PATH = f"{_REMOTE_LOG_FOLDER}/kernel.log"
+_REMOTE_STDERR_PATH = f"{_REMOTE_LOG_FOLDER}/qemu_trusty_err.log"
+
+# below Trusty image archive is generated by
+# branch:aosp-trusty-main / target: qemu_generic_arm64_gicv3* targets
+_TRUSTY_MANIFEST_TRUSTY_IMAGE_PACKAGE = "trusty_image_package.tar.gz"
+
+# below Trusty image archive is generated by:
+# branch: git_main-throttled-nightly / target: qemu_trusty_arm64
+_PLATFORM_MANIFEST_TRUSTY_IMAGE_PACKAGE = "trusty_tee_package_goog.tar.gz"
+
+# below Trusty image archive is generated by:
+# aosp developers for --local-image usage
+_PLATFORM_MANIFEST_TRUSTY_IMAGE_PACKAGE_LOCAL = "trusty_tee_package.tar.gz"
+
+# below Host tools archive is generated by:
+# branch: git_main-throttled-nightly / target: qemu_trusty_arm64
 _TRUSTY_HOST_PACKAGE_DIR = "trusty-host_package"
 _TRUSTY_HOST_TARBALL = "trusty-host_package.tar.gz"
 
 # Default Trusty image build. This does not depend on the android branch.
-_DEFAULT_TRUSTY_BUILD_BRANCH = "aosp-trusty-master"
-_DEFAULT_TRUSTY_BUILD_TARGET = "qemu_generic_arm64_test_debug"
+_DEFAULT_TRUSTY_BUILD_BRANCH = "aosp-trusty-main"
+_DEFAULT_TRUSTY_BUILD_TARGET = "qemu_generic_arm64_gicv3_test_debug"
 
 
 def _TrustyImagePackageFilename(build_target):
     trusty_target = build_target.replace("_", "-")
-    return f"{trusty_target}.{_TRUSTY_IMAGE_PACKAGE}"
+    return f"{trusty_target}.{_TRUSTY_MANIFEST_TRUSTY_IMAGE_PACKAGE}"
 
 
 def _FindHostPackage(package_path=None):
@@ -70,7 +88,24 @@ def _FindHostPackage(package_path=None):
     raise errors.GetTrustyLocalHostPackageError(
         "Can't find the trusty host package (Try lunching a trusty target "
         "like qemu_trusty_arm64-trunk_staging-userdebug and running 'm'): \n"
-        + "\n".join(dirs_to_check))
+        + "\n".join(dirs_to_check)
+    )
+
+
+def _FindTrustyImagePackage():
+    dist_dir = utils.GetDistDir()
+    if dist_dir:
+        for name in [
+            _PLATFORM_MANIFEST_TRUSTY_IMAGE_PACKAGE,
+            _PLATFORM_MANIFEST_TRUSTY_IMAGE_PACKAGE_LOCAL,
+        ]:
+            trusty_image_package = os.path.join(dist_dir, name)
+            if os.path.exists(trusty_image_package):
+                return trusty_image_package
+    raise errors.GetTrustyLocalImagePackageError(
+        "Can't find the trusty image package (Try lunching a trusty target "
+        "like qemu_trusty_arm64-trunk_staging-userdebug and running 'm dist trusty-tee_package')"
+    )
 
 
 class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
@@ -79,8 +114,6 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
     def __init__(self, avd_spec, local_android_image_artifact=None):
         super().__init__(avd_spec, local_android_image_artifact)
         self._all_logs = {}
-        self._host_package_artifact = _FindHostPackage(
-            avd_spec.trusty_host_package)
 
     # pylint: disable=broad-except
     def CreateInstance(self):
@@ -100,8 +133,8 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
             self._SetFailures(instance, traceback.format_exception(e))
 
         self._FindLogFiles(
-            instance,
-            instance in self.GetFailures() and not self._avd_spec.no_pull_log)
+            instance, instance in self.GetFailures() and not self._avd_spec.no_pull_log
+        )
         return instance
 
     def _ProcessArtifacts(self):
@@ -114,27 +147,39 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
         """
         avd_spec = self._avd_spec
         if avd_spec.image_source == constants.IMAGE_SRC_LOCAL:
+            host_package_artifact = _FindHostPackage(
+                avd_spec.trusty_host_package
+            )
             cvd_utils.UploadArtifacts(
                 self._ssh,
                 cvd_utils.GCE_BASE_DIR,
                 (self._local_image_artifact or avd_spec.local_image_dir),
-                self._host_package_artifact)
+                host_package_artifact,
+            )
         elif avd_spec.image_source == constants.IMAGE_SRC_REMOTE:
             self._FetchBuild()
             if self._compute_client.build_api.GetKernelBuild(
-                    avd_spec.kernel_build_info):
+                avd_spec.kernel_build_info
+            ):
                 self._ReplaceModules()
+            else:
+                # fetch the kernel image from the android build artifacts
+                self._FetchAndUploadKernelImage()
         if avd_spec.local_trusty_image:
-            self._UploadTrustyImages(avd_spec.local_trusty_image)
+            self._UploadBuildArchive(avd_spec.local_trusty_image)
+        elif avd_spec.image_source == constants.IMAGE_SRC_LOCAL:
+            local_trusty_image = _FindTrustyImagePackage()
+            self._UploadBuildArchive(local_trusty_image)
         else:
             self._FetchAndUploadTrustyImages()
 
         config = {
             "linux": "kernel",
             "linux_arch": "arm64",
+            "initrd": "ramdisk.img",
             "atf": "atf/qemu/debug",
             "qemu": "bin/trusty_qemu_system_aarch64",
-            "extra_qemu_flags": ["-machine", "gic-version=2"],
+            "extra_qemu_flags": ["-machine", "gic-version=3"],
             "android_image_dir": ".",
             "rpmbd": "bin/rpmb_dev",
             "arch": "arm64",
@@ -144,7 +189,8 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
             json.dump(config, config_json_file)
             config_json_file.flush()
             remote_config_path = remote_path.join(
-                cvd_utils.GCE_BASE_DIR, _CONFIG_JSON_FILENAME)
+                cvd_utils.GCE_BASE_DIR, _CONFIG_JSON_FILENAME
+            )
             self._ssh.ScpPushFile(config_json_file.name, remote_config_path)
 
     # We are building our own command-line instead of using
@@ -164,16 +210,16 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
         # can override the artifact filename.
         host_package = avd_spec.host_package_build_info.copy()
         if not (
-            host_package[constants.BUILD_ID]
-            or host_package[constants.BUILD_BRANCH]
+            host_package[constants.BUILD_ID] or host_package[constants.BUILD_BRANCH]
         ):
-            host_package[constants.BUILD_ID] = avd_spec.remote_image[
-                constants.BUILD_ID]
+            host_package[constants.BUILD_ID] = avd_spec.remote_image[constants.BUILD_ID]
             host_package[constants.BUILD_BRANCH] = avd_spec.remote_image[
-                constants.BUILD_BRANCH]
+                constants.BUILD_BRANCH
+            ]
         if not host_package[constants.BUILD_TARGET]:
             host_package[constants.BUILD_TARGET] = avd_spec.remote_image[
-                constants.BUILD_TARGET]
+                constants.BUILD_TARGET
+            ]
         host_package.setdefault(constants.BUILD_ARTIFACT, _TRUSTY_HOST_TARBALL)
 
         fetch_args = build_client.GetFetchBuildArgs(
@@ -186,11 +232,7 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
             {},
             host_package,
         )
-        fetch_cmd = (
-            constants.CMD_CVD_FETCH
-            + ["-credential_source=gce"]
-            + fetch_args
-        )
+        fetch_cmd = constants.CMD_CVD_FETCH + ["-credential_source=gce"] + fetch_args
         self._ssh.Run(" ".join(fetch_cmd), timeout=constants.DEFAULT_SSH_TIMEOUT)
 
     def _ReplaceModules(self):
@@ -204,52 +246,88 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
             f"--android-ramdisk={android_ramdisk} "
             f"--kernel-ramdisk={kernel_ramdisk} "
             f"--output-ramdisk={android_ramdisk}",
-            timeout=constants.DEFAULT_SSH_TIMEOUT)
+            timeout=constants.DEFAULT_SSH_TIMEOUT,
+        )
 
-    @utils.TimeExecute(function_description="Downloading and uploading Trusty image")
+    @utils.TimeExecute(function_description="Fetching & Uploading Trusty image")
     def _FetchAndUploadTrustyImages(self):
-        """Download Trusty image archive"""
+        """Fetch Trusty image archive from ab, Upload to GCE"""
         build_client = self._compute_client.build_api
         trusty_build_info = self._avd_spec.trusty_build_info
-        build_id = trusty_build_info[constants.BUILD_ID]
-        build_branch = (
-            trusty_build_info[constants.BUILD_BRANCH]
-            or _DEFAULT_TRUSTY_BUILD_BRANCH
-        )
-        build_target = (
-            trusty_build_info[constants.BUILD_TARGET]
-            or _DEFAULT_TRUSTY_BUILD_TARGET
-        )
-        if not build_id:
-            build_id = build_client.GetLKGB(build_target, build_branch)
+        if trusty_build_info[constants.BUILD_BRANCH]:
+            build_id = trusty_build_info[constants.BUILD_ID]
+            build_branch = trusty_build_info[constants.BUILD_BRANCH]
+            build_target = (
+                trusty_build_info[constants.BUILD_TARGET]
+                or _DEFAULT_TRUSTY_BUILD_TARGET
+            )
+            if not build_id:
+                build_id = build_client.GetLKGB(build_target, build_branch)
+            trusty_image_package = _TrustyImagePackageFilename(build_target)
+        else:
+            # if Trusty build_branch not specified, use the android build branch
+            # get the Trusty image package from the android platform manifest
+            android_build_info = self._avd_spec.remote_image
+            build_id = android_build_info[constants.BUILD_ID]
+            build_branch = android_build_info[constants.BUILD_BRANCH]
+            build_target = android_build_info[constants.BUILD_TARGET]
+            trusty_image_package = _PLATFORM_MANIFEST_TRUSTY_IMAGE_PACKAGE
         with tempfile.NamedTemporaryFile(suffix=".tar.gz") as image_local_file:
             image_local_path = image_local_file.name
             build_client.DownloadArtifact(
                 build_target,
                 build_id,
-                _TrustyImagePackageFilename(build_target),
+                trusty_image_package,
+                image_local_path,
+            )
+            self._UploadBuildArchive(image_local_path)
+
+    @utils.TimeExecute(function_description="Fetching & Uploading Kernel Image")
+    def _FetchAndUploadKernelImage(self):
+        """Fetch Kernel image from ab, Upload to GCE"""
+        build_client = self._compute_client.build_api
+        android_build_info = self._avd_spec.remote_image
+        build_id = android_build_info[constants.BUILD_ID]
+        build_target = android_build_info[constants.BUILD_TARGET]
+        with tempfile.NamedTemporaryFile(prefix="kernel") as image_local_file:
+            image_local_path = image_local_file.name
+            logger.debug('DownloadArtifact "kernel" to %s\n', image_local_path)
+            ret = build_client.DownloadArtifact(
+                build_target,
+                build_id,
+                "kernel",
+                image_local_path,
+            )
+            logger.debug("DownloadArtifact to %s Returned %d\n", image_local_path, ret)
+            self._ssh.ScpPushFile(image_local_path, f"{cvd_utils.GCE_BASE_DIR}/kernel")
+            logger.debug(
+                "ScpPushFile from %s to %s\n",
                 image_local_path,
+                f"{cvd_utils.GCE_BASE_DIR}/kernel",
             )
-            self._UploadTrustyImages(image_local_path)
 
-    def _UploadTrustyImages(self, archive_path):
-        """Upload Trusty image archive"""
-        remote_cmd = (f"tar -xzf - -C {cvd_utils.GCE_BASE_DIR} < "
-                      + archive_path)
+    def _UploadBuildArchive(self, archive_path):
+        """Upload Build Artifact (Trusty images archive or Kernel image)"""
+        remote_cmd = f"tar -xzf - -C {cvd_utils.GCE_BASE_DIR} < " + archive_path
         logger.debug("remote_cmd:\n %s", remote_cmd)
         self._ssh.Run(remote_cmd)
 
     @utils.TimeExecute(function_description="Starting Trusty")
     def _StartTrusty(self):
         """Start the model on the GCE instance."""
+        self._ssh.Run(f"mkdir -p {_REMOTE_LOG_FOLDER}")
 
         # We use an explicit subshell so we can run this command in the
         # background.
-        cmd = "-- sh -c " + shlex.quote(shlex.quote(
-            f"{cvd_utils.GCE_BASE_DIR}/run.py "
-            f"--config={_CONFIG_JSON_FILENAME} "
-            f"> {_REMOTE_STDOUT_PATH} 2> {_REMOTE_STDERR_PATH} &"
-        ))
+        cmd = "-- sh -c " + shlex.quote(
+            shlex.quote(
+                f"{cvd_utils.GCE_BASE_DIR}/run.py "
+                f"--verbose --config={_CONFIG_JSON_FILENAME} "
+                f"{self._avd_spec.launch_args} "
+                f"> {_REMOTE_STDOUT_PATH} "
+                f"2> {_REMOTE_STDERR_PATH} &"
+            )
+        )
         self._ssh.Run(cmd, self._avd_spec.boot_timeout_secs or 30, retry=0)
 
     def _FindLogFiles(self, instance, download):
@@ -262,12 +340,9 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
         """
         logs = [cvd_utils.HOST_KERNEL_LOG]
         if self._avd_spec.image_source == constants.IMAGE_SRC_REMOTE:
-            logs.append(
-                cvd_utils.GetRemoteFetcherConfigJson(cvd_utils.GCE_BASE_DIR))
-        logs.append(
-            report.LogFile(_REMOTE_STDOUT_PATH, constants.LOG_TYPE_KERNEL_LOG))
-        logs.append(
-            report.LogFile(_REMOTE_STDERR_PATH, constants.LOG_TYPE_TEXT))
+            logs.append(cvd_utils.GetRemoteFetcherConfigJson(cvd_utils.GCE_BASE_DIR))
+        logs.append(report.LogFile(_REMOTE_STDOUT_PATH, constants.LOG_TYPE_KERNEL_LOG))
+        logs.append(report.LogFile(_REMOTE_STDERR_PATH, constants.LOG_TYPE_TEXT))
         self._all_logs[instance] = logs
 
         logger.debug("logs: %s", logs)
@@ -276,7 +351,8 @@ class RemoteInstanceDeviceFactory(gce_device_factory.GCEDeviceFactory):
             log_paths = [log["path"] for log in logs]
             error_log_folder = pull.PullLogs(self._ssh, log_paths, instance)
             self._compute_client.ExtendReportData(
-                constants.ERROR_LOG_FOLDER, error_log_folder)
+                constants.ERROR_LOG_FOLDER, error_log_folder
+            )
 
     def GetLogs(self):
         """Get all device logs.
diff --git a/public/actions/remote_instance_trusty_device_factory_test.py b/public/actions/remote_instance_trusty_device_factory_test.py
index d61804d..5cfcb4a 100644
--- a/public/actions/remote_instance_trusty_device_factory_test.py
+++ b/public/actions/remote_instance_trusty_device_factory_test.py
@@ -33,10 +33,11 @@ from acloud.public.actions import remote_instance_trusty_device_factory
 
 logger = logging.getLogger(__name__)
 
-_EXPECTED_CONFIG_JSON = '''{"linux": "kernel", "linux_arch": "arm64", \
-"atf": "atf/qemu/debug", "qemu": "bin/trusty_qemu_system_aarch64", \
-"extra_qemu_flags": ["-machine", "gic-version=2"], "android_image_dir": ".", \
-"rpmbd": "bin/rpmb_dev", "arch": "arm64", "adb": "bin/adb"}'''
+_EXPECTED_CONFIG_JSON = """{"linux": "kernel", "linux_arch": "arm64", \
+"initrd": "ramdisk.img", "atf": "atf/qemu/debug", \
+"qemu": "bin/trusty_qemu_system_aarch64", \
+"extra_qemu_flags": ["-machine", "gic-version=3"], "android_image_dir": ".", \
+"rpmbd": "bin/rpmb_dev", "arch": "arm64", "adb": "bin/adb"}"""
 
 
 class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
@@ -170,7 +171,6 @@ class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
             ]
         )
 
-
     @mock.patch.object(remote_instance_trusty_device_factory.RemoteInstanceDeviceFactory,
                        "CreateGceInstance")
     @mock.patch("acloud.public.actions.remote_instance_trusty_device_factory."
@@ -201,11 +201,14 @@ class RemoteInstanceDeviceFactoryTest(driver_test_lib.BaseDriverTest):
         factory.CreateInstance()
         mock_create_gce_instance.assert_called_once()
         mock_cvd_utils.UploadArtifacts.assert_called_once()
-        # First call is unpacking image archive
-        self.assertEqual(mock_ssh.Run.call_count, 2)
+        # First call is unpacking host package
+        # then unpacking image archive
+        # and finally run
+        self.assertEqual(mock_ssh.Run.call_count, 3)
         self.assertIn(
-            "gce_base_dir/run.py --config=config.json",
-            mock_ssh.Run.call_args[0][0])
+            "gce_base_dir/run.py --verbose --config=config.json",
+            mock_ssh.Run.call_args[0][0],
+        )
 
         self.assertEqual(3, len(factory.GetLogs().get("instance")))
 
diff --git a/public/config.py b/public/config.py
index 3548b7c..23dd6a4 100755
--- a/public/config.py
+++ b/public/config.py
@@ -246,9 +246,6 @@ class AcloudConfig():
         self.instance_name_pattern = (
             usr_cfg.instance_name_pattern or
             internal_cfg.default_usr_cfg.instance_name_pattern)
-        self.fetch_cvd_version = (
-            usr_cfg.fetch_cvd_version or
-            internal_cfg.default_usr_cfg.fetch_cvd_version)
         if usr_cfg.HasField("enable_multi_stage") is not None:
             self.enable_multi_stage = usr_cfg.enable_multi_stage
         elif internal_cfg.default_usr_cfg.HasField("enable_multi_stage"):
diff --git a/public/config_test.py b/public/config_test.py
index d0e0aa3..96d3499 100644
--- a/public/config_test.py
+++ b/public/config_test.py
@@ -100,7 +100,7 @@ device_default_orientation_map {
 }
 
 valid_branch_and_min_build_id {
-    key: "aosp-master"
+    key: "aosp-main"
     value: 0
 }
 
@@ -233,7 +233,7 @@ common_hw_property_map {
             {"nexus5": "portrait"})
         self.assertEqual(
             dict(cfg.valid_branch_and_min_build_id.items()),
-            {"aosp-master": 0})
+            {"aosp-main": 0})
         self.assertEqual(cfg.default_usr_cfg.stable_host_image_name,
                          "fake_stable_host_image_name")
         self.assertEqual(cfg.default_usr_cfg.stable_host_image_project,
diff --git a/public/data/default.config b/public/data/default.config
index 9a2327c..be7313e 100644
--- a/public/data/default.config
+++ b/public/data/default.config
@@ -18,7 +18,6 @@ default_usr_cfg {
   network: "default"
   extra_data_disk_size_gb: 0
   instance_name_pattern: "ins-{uuid}-{build_id}-{build_target}"
-  fetch_cvd_version: "9123511"
 
   metadata_variable {
     key: "camera_front"
@@ -80,6 +79,11 @@ common_hw_property_map {
   value: "cpu:4,resolution:1768x2208,dpi:386,memory:4g"
 }
 
+common_hw_property_map {
+  key: "local-desktop"
+  value: "cpu:8,resolution:1600x900,dpi:160,memory:8g"
+}
+
 common_hw_property_map {
   key: "phone"
   value: "cpu:4,resolution:720x1280,dpi:320,memory:2g"
@@ -110,6 +114,11 @@ common_hw_property_map {
   value: "cpu:4,resolution:1768x2208,dpi:386,memory:4g"
 }
 
+common_hw_property_map {
+  key: "desktop"
+  value: "cpu:8,resolution:1600x900,dpi:160,memory:8g"
+}
+
 # Device resolution
 device_resolution_map {
   key: "nexus5"
diff --git a/public/device_driver.py b/public/device_driver.py
index 9cb38b0..c6e5823 100755
--- a/public/device_driver.py
+++ b/public/device_driver.py
@@ -73,7 +73,7 @@ class AndroidVirtualDevicePool():
         using launch control api. And then create a Gce image.
 
         Args:
-            build_target: Target name, e.g. "aosp_cf_x86_64_phone-userdebug"
+            build_target: Target name, e.g. "aosp_cf_x86_64_phone-trunk_staging-userdebug"
             build_id: Build id, a string, e.g. "2263051", "P2804227"
 
         Returns:
@@ -179,7 +179,7 @@ class AndroidVirtualDevicePool():
 
         Args:
             num: Number of devices to create.
-            build_target: Target name, e.g. "aosp_cf_x86_64_phone-userdebug"
+            build_target: Target name, e.g. "aosp_cf_x86_64_phone-trunk_staging-userdebug"
             build_id: Build id, a string, e.g. "2263051", "P2804227"
             gce_image: string, if given, will use this image
                        instead of creating a new one.
@@ -350,7 +350,7 @@ def CreateGCETypeAVD(cfg,
 
     Args:
         cfg: An AcloudConfig instance.
-        build_target: Target name, e.g. "aosp_cf_x86_64_phone-userdebug"
+        build_target: Target name, e.g. "aosp_cf_x86_64_phone-trunk_staging-userdebug"
         build_id: Build id, a string, e.g. "2263051", "P2804227"
         num: Number of devices to create.
         gce_image: string, if given, will use this gce image
diff --git a/restart/restart.py b/restart/restart.py
index b10901e..069f72d 100644
--- a/restart/restart.py
+++ b/restart/restart.py
@@ -77,7 +77,8 @@ def RestartDevice(ssh, instance_id):
     ssh_command = "./bin/restart_cvd --instance_num=%d" % (instance_id)
     try:
         ssh.Run(ssh_command)
-    except (subprocess.CalledProcessError, errors.DeviceConnectionError) as e:
+    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
+            errors.DeviceConnectionError) as e:
         logger.debug(str(e))
         utils.PrintColorString(str(e), utils.TextColors.FAIL)
 
diff --git a/setup/setup.py b/setup/setup.py
index 8f13144..e35dc6a 100644
--- a/setup/setup.py
+++ b/setup/setup.py
@@ -83,13 +83,12 @@ def Run(args):
 def _PrintWelcomeMessage():
     """Print welcome message when acloud setup been called."""
 
-    # pylint: disable=anomalous-backslash-in-string
-    asc_art = "                                    \n" \
-            "   ___  _______   ____  __  _____ \n" \
-            "  / _ |/ ___/ /  / __ \/ / / / _ \\ \n" \
-            " / __ / /__/ /__/ /_/ / /_/ / // /  \n" \
-            "/_/ |_\\___/____/\\____/\\____/____/ \n" \
-            "                                  \n"
+    asc_art = r"                                   " + "\n" \
+              r"   ___  _______   ____  __  _____  " + "\n" \
+              r"  / _ |/ ___/ /  / __ \/ / / / _ \ " + "\n" \
+              r" / __ / /__/ /__/ /_/ / /_/ / // / " + "\n" \
+              r"/_/ |_\___/____/\____/\____/____/  " + "\n" \
+              r"                                   " + "\n"
 
     print("\nWelcome to")
     print(asc_art)
@@ -109,7 +108,7 @@ def _RunPreSetup():
     setup occurs (e.g. copying configs).
     """
     if constants.ENV_ANDROID_BUILD_TOP not in os.environ:
-        print("Can't find $%s." % constants.ENV_ANDROID_BUILD_TOP)
+        print(f"Can't find ${constants.ENV_ANDROID_BUILD_TOP}.")
         print("Please run '#source build/envsetup.sh && lunch <target>' first.")
         sys.exit(constants.EXIT_BY_USER)
 
@@ -134,6 +133,6 @@ def _UpdateConfig(config_file, field, value):
     config_mgr = config.AcloudConfigManager(config_file)
     config_mgr.Load()
     user_config = config_mgr.user_config_path
-    print("Your config (%s) is updated." % user_config)
+    print(f"Your config ({user_config}) is updated.")
     gcp_setup_runner.UpdateConfigFile(user_config, field, value)
     _PrintUsage()
```

