```diff
diff --git a/Android.bp b/Android.bp
index 5ff75aa63..64ad350ec 100644
--- a/Android.bp
+++ b/Android.bp
@@ -81,10 +81,10 @@ cc_defaults {
         },
     },
     cflags: [
-        "-Werror",
-        "-Wall",
-        "-D_FILE_OFFSET_BITS=64",
         "-DNODISCARD_EXPECTED=true",
+        "-D_FILE_OFFSET_BITS=64",
+        "-Wall",
+        "-Werror",
         "-Wno-error=unused-result", // TODO(b/314526051): Fix Result<> uses
     ],
     apex_available: [
@@ -99,8 +99,8 @@ soong_config_module_type {
     config_namespace: "cvdhost",
     bool_variables: ["enforce_mac80211_hwsim"],
     value_variables: [
-        "default_userdata_fs_type",
         "board_f2fs_blocksize",
+        "default_userdata_fs_type",
     ],
     properties: ["cflags"],
 }
diff --git a/Android.mk b/Android.mk
deleted file mode 100644
index f26e65aa3..000000000
--- a/Android.mk
+++ /dev/null
@@ -1,54 +0,0 @@
-# Copyright (C) 2017 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,.idc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,default-permissions.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,libnfc-nci.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,fstab.postinstall,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,ueventd.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,hals.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,device_state_configuration.xml,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,p2p_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,wpa_supplicant.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,wpa_supplicant_overlay.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,wpa_supplicant.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,init.cutf_cvm.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,fstab.cf.f2fs.hctr2,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,fstab.cf.f2fs.cts,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,fstab.cf.ext4.hctr2,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,fstab.cf.ext4.cts,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,init.rc,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish,audio_policy.conf,SPDX-license-identifier-Apache-2.0,notice,build/soong/licenses/LICENSE,))
-
-$(eval $(call declare-copy-files-license-metadata,device/google/cuttlefish/shared/config,pci.ids,SPDX-license-identifier-BSD-3-Clause,notice,device/google/cuttlefish/shared/config/LICENSE_BSD,))
-
-$(eval $(call declare-1p-copy-files,device/google/cuttlefish,privapp-permissions-cuttlefish.xml))
-$(eval $(call declare-1p-copy-files,device/google/cuttlefish,media_profiles_V1_0.xml))
-$(eval $(call declare-1p-copy-files,device/google/cuttlefish,media_codecs_performance.xml))
-$(eval $(call declare-1p-copy-files,device/google/cuttlefish,cuttlefish_excluded_hardware.xml))
-$(eval $(call declare-1p-copy-files,device/google/cuttlefish,media_codecs.xml))
-$(eval $(call declare-1p-copy-files,device/google/cuttlefish,media_codecs_google_video.xml))
-$(eval $(call declare-1p-copy-files,device/google/cuttlefish,car_audio_configuration.xml))
-$(eval $(call declare-1p-copy-files,device/google/cuttlefish,audio_policy_configuration.xml))
-$(eval $(call declare-1p-copy-files,device/google/cuttlefish,preinstalled-packages-product-car-cuttlefish.xml))
-$(eval $(call declare-1p-copy-files,hardware/google/camera/devices,.json))
-
-ifneq ($(filter vsoc_arm vsoc_arm64 vsoc_riscv64 vsoc_x86 vsoc_x86_64, $(TARGET_BOARD_PLATFORM)),)
-LOCAL_PATH:= $(call my-dir)
-
-include $(CLEAR_VARS)
-include $(LOCAL_PATH)/host_package.mk
-
-endif
diff --git a/AndroidProducts.mk b/AndroidProducts.mk
index 8ee4162a3..25f7873d1 100644
--- a/AndroidProducts.mk
+++ b/AndroidProducts.mk
@@ -36,6 +36,7 @@ PRODUCT_MAKEFILES := \
 	aosp_cf_x86_64_auto_portrait:$(LOCAL_DIR)/vsoc_x86_64_only/auto_portrait/aosp_cf.mk \
 	aosp_cf_x86_64_pc:$(LOCAL_DIR)/vsoc_x86_64_only/pc/aosp_cf.mk \
 	aosp_cf_x86_64_phone:$(LOCAL_DIR)/vsoc_x86_64/phone/aosp_cf.mk \
+	aosp_cf_x86_64_phone_soong_system:$(LOCAL_DIR)/vsoc_x86_64/phone/aosp_cf_soong_system.mk \
 	aosp_cf_x86_64_phone_vendor:$(LOCAL_DIR)/vsoc_x86_64/phone/aosp_cf_vendor.mk \
 	aosp_cf_x86_64_ssi:$(LOCAL_DIR)/vsoc_x86_64/phone/aosp_cf_ssi.mk \
 	aosp_cf_x86_64_tv:$(LOCAL_DIR)/vsoc_x86_64/tv/aosp_cf.mk \
@@ -47,8 +48,6 @@ PRODUCT_MAKEFILES := \
 	aosp_cf_x86_64_only_phone_hsum:$(LOCAL_DIR)/vsoc_x86_64_only/phone/aosp_cf_hsum.mk \
 	aosp_cf_x86_64_slim:$(LOCAL_DIR)/vsoc_x86_64_only/slim/aosp_cf.mk \
 	aosp_cf_x86_64_wear:$(LOCAL_DIR)/vsoc_x86_64_only/wear/aosp_cf.mk \
-	aosp_cf_x86_pasan:$(LOCAL_DIR)/vsoc_x86/pasan/aosp_cf.mk \
-	aosp_cf_x86_phone:$(LOCAL_DIR)/vsoc_x86/phone/aosp_cf.mk \
 	aosp_cf_x86_only_phone:$(LOCAL_DIR)/vsoc_x86_only/phone/aosp_cf.mk \
 	aosp_cf_x86_go_phone:$(LOCAL_DIR)/vsoc_x86/go/aosp_cf.mk \
 	aosp_cf_x86_tv:$(LOCAL_DIR)/vsoc_x86/tv/aosp_cf.mk \
@@ -64,6 +63,5 @@ COMMON_LUNCH_CHOICES := \
 	aosp_cf_x86_64_foldable-trunk_staging-userdebug \
 	aosp_cf_x86_64_auto-trunk_staging-userdebug \
 	aosp_cf_x86_64_auto_mdnd-trunk_staging-userdebug \
-	aosp_cf_x86_phone-trunk_staging-userdebug \
 	aosp_cf_x86_tv-trunk_staging-userdebug \
 	aosp_cf_x86_64_tv-trunk_staging-userdebug
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index 7ba873b13..d90073fef 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -1,7 +1,9 @@
 [Builtin Hooks]
+bpfmt = true
 clang_format = true
 rustfmt = true
 
 [Builtin Hooks Options]
+bpfmt = -s
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 rustfmt = --config-path=rustfmt.toml
diff --git a/apex/com.google.cf.wpa_supplicant/Android.bp b/apex/com.google.cf.wpa_supplicant/Android.bp
index 1bda23faa..19ec13ad0 100644
--- a/apex/com.google.cf.wpa_supplicant/Android.bp
+++ b/apex/com.google.cf.wpa_supplicant/Android.bp
@@ -26,17 +26,17 @@ apex {
     vendor: true,
 
     binaries: [
-        "//external/wpa_supplicant_8/wpa_supplicant/wpa_supplicant:wpa_supplicant",
         "//external/wpa_supplicant_8/wpa_supplicant/wpa_supplicant:hostapd",
+        "//external/wpa_supplicant_8/wpa_supplicant/wpa_supplicant:wpa_supplicant",
     ],
     prebuilts: [
         "com.google.cf.wpa_supplicant.rc",
+        "p2p_supplicant.conf.cf",
         "wpa_supplicant.conf.cf",
         "wpa_supplicant_overlay.conf.cf",
-        "p2p_supplicant.conf.cf",
     ],
-    vintf_fragments: [
-        ":android.hardware.wifi.supplicant.xml",
-        ":android.hardware.wifi.hostapd.xml",
+    vintf_fragment_modules: [
+        "android.hardware.wifi.hostapd.xml",
+        "android.hardware.wifi.supplicant.xml",
     ],
 }
diff --git a/build/Android.bp b/build/Android.bp
index d004e80f0..639ffeac8 100644
--- a/build/Android.bp
+++ b/build/Android.bp
@@ -38,10 +38,10 @@ soong_config_module_type {
     module_type: "cvd_host_package",
     config_namespace: "cvd",
     value_variables: [
-        "grub_config",
-        "launch_configs",
         "custom_action_config",
         "custom_action_servers",
+        "grub_config",
+        "launch_configs",
     ],
 }
 
@@ -103,26 +103,32 @@ cvd_host_tools = [
     "adb_connector",
     "allocd_client",
     "assemble_cvd",
+    "automotive_vsock_proxy",
     "avbtool",
     "build_super_image",
-    "tcp_connector",
+    "casimir",
     "casimir_control_server",
     "common_crosvm",
     "config_server",
     "console_forwarder",
     "control_env_proxy_server",
     "crosvm",
+    "cvd_host_bugreport",
+    "cvd_import_locations",
     "cvd_internal_display",
     "cvd_internal_env",
-    "echo_server",
     "cvd_internal_host_bugreport",
     "cvd_internal_start",
     "cvd_internal_status",
     "cvd_internal_stop",
-    "cvd_host_bugreport",
+    "cvd_send_id_disclosure",
+    "cvd_send_sms",
     "cvd_status",
+    "cvd_update_location",
+    "cvd_update_security_algorithm",
     "cvdremote",
     "e2fsdroid",
+    "echo_server",
     "extract-ikconfig",
     "extract-vmlinux",
     "fastboot",
@@ -141,22 +147,23 @@ cvd_host_tools = [
     "lpunpack",
     "lz4",
     "make_f2fs",
+    "mcopy",
     "metrics",
     "metrics_launcher",
     "mkbootfs",
     "mkbootimg",
-    "mkenvimage_slim",
     "mke2fs",
+    "mkenvimage_slim",
     "mkuserimg_mke2fs",
+    "mmd",
     "modem_simulator",
     "ms-tpm-20-ref",
-    "mcopy",
-    "mmd",
     "mtools",
     "netsim",
     "netsimd",
     "newfs_msdos",
     "openwrt_control_server",
+    "operator_proxy",
     "pica",
     "powerbtn_cvd",
     "powerwash_cvd",
@@ -165,40 +172,34 @@ cvd_host_tools = [
     "record_cvd",
     "restart_cvd",
     "root-canal",
-    "casimir",
-    "snapshot_util_cvd",
     "run_cvd",
+    "sandboxer_proxy",
     "screen_recording_server",
     "secure_env",
     "sefcontext_compile",
-    "cvd_send_id_disclosure",
-    "cvd_send_sms",
-    "cvd_update_location",
-    "cvd_update_security_algorithm",
-    "cvd_import_locations",
     "simg2img",
+    "snapshot_util_cvd",
     "socket_vsock_proxy",
     "stop_cvd",
+    "tcp_connector",
     "test_cvd_load_parser",
     "tombstone_receiver",
     "toybox",
     "unpack_bootimg",
+    "vhal_proxy_server",
+    "vhost_device_vsock",
+    "vulkan.pastel",
     "webRTC",
     "webrtc_operator",
-    "operator_proxy",
     "wmediumd",
     "wmediumd_gen_config",
-    "vulkan.pastel",
-    "automotive_vsock_proxy",
-    "vhost_device_vsock",
-    "vhal_proxy_server",
 ]
 
 cvd_openwrt_images = [
-    "openwrt_kernel_x86_64",
-    "openwrt_rootfs_x86_64",
     "openwrt_kernel_aarch64",
+    "openwrt_kernel_x86_64",
     "openwrt_rootfs_aarch64",
+    "openwrt_rootfs_x86_64",
 ]
 
 cvd_host_tests = [
@@ -209,21 +210,21 @@ cvd_host_tests = [
 cvd_host_webrtc_assets = [
     "webrtc_adb.js",
     "webrtc_app.js",
-    "webrtc_index.js",
-    "webrtc_controls.js",
     "webrtc_cf.js",
-    "webrtc_server_connector.js",
-    "webrtc_index.html",
     "webrtc_client.html",
-    "webrtc_rootcanal.js",
+    "webrtc_controls.css",
+    "webrtc_controls.js",
+    "webrtc_index.css",
+    "webrtc_index.html",
+    "webrtc_index.js",
     "webrtc_location.js",
-    "webrtc_touch.js",
+    "webrtc_rootcanal.js",
     "webrtc_server.crt",
     "webrtc_server.key",
     "webrtc_server.p12",
+    "webrtc_server_connector.js",
     "webrtc_style.css",
-    "webrtc_index.css",
-    "webrtc_controls.css",
+    "webrtc_touch.js",
     "webrtc_trusted.pem",
 ]
 
@@ -261,6 +262,11 @@ cvd_host_aarch64_graphics_detector = [
     "aarch64_linux_gnu_gfxstream_graphics_detector_for_crosvm",
 ]
 
+cvd_host_aarch64_swiftshader = [
+    "aarch64_linux_gnu_libvk_swiftshader.so",
+    "aarch64_linux_gnu_vk_swiftshader_icd.json",
+]
+
 cvd_host_x86_64 = cvd_host_x86_64_graphics_detector + cvd_host_x86_64_crosvm + qemu_x86_64_linux_gnu_binary
 
 cvd_host_aarch64_crosvm = [
@@ -275,7 +281,7 @@ cvd_host_aarch64_crosvm = [
     "aarch64_linux_gnu_libwayland_client.so.0_for_crosvm",
 ]
 
-cvd_host_aarch64 = cvd_host_aarch64_crosvm + cvd_host_aarch64_graphics_detector + qemu_aarch64_linux_gnu_binary
+cvd_host_aarch64 = cvd_host_aarch64_crosvm + cvd_host_aarch64_graphics_detector + qemu_aarch64_linux_gnu_binary + cvd_host_aarch64_swiftshader
 
 cvd_host_seccomp_policy_x86_64 = [
     "9p_device.policy_x86_64",
@@ -338,8 +344,8 @@ cvd_host_seccomp_policy_aarch64 = [
 ]
 
 cvd_host_bootloader = [
-    "bootloader_crosvm_x86_64",
     "bootloader_crosvm_aarch64",
+    "bootloader_crosvm_x86_64",
     "bootloader_qemu_aarch64",
     "bootloader_qemu_arm",
     "bootloader_qemu_riscv64",
@@ -362,6 +368,12 @@ automotive_proxy_config = [
     "automotive_proxy_config",
 ]
 
+automotive_vhal_prop_configs = [
+    "Host_Prebuilt_VehicleHalDefaultProperties_JSON",
+    "Host_Prebuilt_VehicleHalTestProperties_JSON",
+    "Host_Prebuilt_VehicleHalVendorClusterTestProperties_JSON",
+]
+
 cvd_host_avb_testkey = [
     "cvd_avb_pubkey_rsa2048",
     "cvd_avb_pubkey_rsa4096",
@@ -370,6 +382,11 @@ cvd_host_avb_testkey = [
 ]
 
 cvd_host_netsim_gui_assets = [
+    "netsim_ui_assets_grid-background.svg",
+    "netsim_ui_assets_hexagonal-background.png",
+    "netsim_ui_assets_netsim-logo-b.svg",
+    "netsim_ui_assets_netsim-logo.svg",
+    "netsim_ui_assets_polar-background.svg",
     "netsim_ui_index.html",
     "netsim_ui_js_cube-sprite.js",
     "netsim_ui_js_customize-map-button.js",
@@ -385,11 +402,6 @@ cvd_host_netsim_gui_assets = [
     "netsim_ui_js_packet-info.js",
     "netsim_ui_js_pyramid-sprite.js",
     "netsim_ui_tslib",
-    "netsim_ui_assets_grid-background.svg",
-    "netsim_ui_assets_hexagonal-background.png",
-    "netsim_ui_assets_netsim-logo-b.svg",
-    "netsim_ui_assets_netsim-logo.svg",
-    "netsim_ui_assets_polar-background.svg",
 ]
 
 genrule {
@@ -439,7 +451,8 @@ cvd_host_package_customization {
                 cvd_host_swiftshader_files +
                 cvd_openwrt_images +
                 cvd_host_netsim_gui_assets +
-                automotive_proxy_config,
+                automotive_proxy_config +
+                automotive_vhal_prop_configs,
         },
     },
 
diff --git a/build/cvd-host-package.go b/build/cvd-host-package.go
index 596ce41d0..a5d81eb84 100644
--- a/build/cvd-host-package.go
+++ b/build/cvd-host-package.go
@@ -19,17 +19,21 @@ import (
 	"strings"
 
 	"github.com/google/blueprint"
+	"github.com/google/blueprint/proptools"
 
 	"android/soong/android"
 )
 
 func init() {
 	android.RegisterModuleType("cvd_host_package", cvdHostPackageFactory)
+	android.RegisterParallelSingletonType("cvd_host_package_singleton", cvdHostPackageSingletonFactory)
 }
 
 type cvdHostPackage struct {
 	android.ModuleBase
 	android.PackagingBase
+	tarballFile android.InstallPath
+	stampFile   android.InstallPath
 }
 
 func cvdHostPackageFactory() android.Module {
@@ -40,10 +44,18 @@ func cvdHostPackageFactory() android.Module {
 	return module
 }
 
+type cvdHostPackageSingleton struct {
+	tarballPaths android.Paths
+}
+
+func cvdHostPackageSingletonFactory() android.Singleton {
+	return &cvdHostPackageSingleton{}
+}
+
 type dependencyTag struct {
 	blueprint.BaseDependencyTag
 	android.InstallAlwaysNeededDependencyTag // to force installation of both "deps" and manually added dependencies
-	android.PackagingItemAlwaysDepTag  // to force packaging of both "deps" and manually added dependencies
+	android.PackagingItemAlwaysDepTag        // to force packaging of both "deps" and manually added dependencies
 }
 
 var cvdHostPackageDependencyTag = dependencyTag{}
@@ -110,6 +122,7 @@ func (c *cvdHostPackage) GenerateAndroidBuildActions(ctx android.ModuleContext)
 	dirBuilder.Command().Text("touch").Output(stamp)
 	dirBuilder.Build("cvd_host_package", fmt.Sprintf("Packaging %s", c.BaseModuleName()))
 	ctx.InstallFile(android.PathForModuleInstall(ctx), c.BaseModuleName()+".stamp", stamp)
+	c.stampFile = android.PathForModuleInPartitionInstall(ctx, c.BaseModuleName()+".stamp")
 
 	tarball := android.PathForModuleOut(ctx, "package.tar.gz")
 	tarballBuilder := android.NewRuleBuilder(pctx, ctx)
@@ -122,4 +135,63 @@ func (c *cvdHostPackage) GenerateAndroidBuildActions(ctx android.ModuleContext)
 		Text(".")
 	tarballBuilder.Build("cvd_host_tarball", fmt.Sprintf("Creating tarball for %s", c.BaseModuleName()))
 	ctx.InstallFile(android.PathForModuleInstall(ctx), c.BaseModuleName()+".tar.gz", tarball)
+	c.tarballFile = android.PathForModuleInstall(ctx, c.BaseModuleName()+".tar.gz")
+}
+
+type cvdHostPackageMetadataProvider interface {
+	tarballMetadata() android.Path
+	stampMetadata() android.Path
+}
+
+func (p *cvdHostPackage) tarballMetadata() android.Path {
+	return p.tarballFile
+}
+
+func (p *cvdHostPackage) stampMetadata() android.Path {
+	return p.stampFile
+}
+
+// Create "hosttar" phony target with "cvd-host_package.tar.gz" path.
+// Add stamp files into "droidcore" dependency.
+func (p *cvdHostPackageSingleton) GenerateBuildActions(ctx android.SingletonContext) {
+	var cvdHostPackageTarball android.Paths
+	var cvdHostPackageStamp android.Paths
+
+	ctx.VisitAllModules(func(module android.Module) {
+		if !module.Enabled(ctx) {
+			return
+		}
+		if c, ok := module.(cvdHostPackageMetadataProvider); ok {
+			if !android.IsModulePreferred(module) {
+				return
+			}
+			cvdHostPackageTarball = append(cvdHostPackageTarball, c.tarballMetadata())
+			cvdHostPackageStamp = append(cvdHostPackageStamp, c.stampMetadata())
+		}
+	})
+
+	if cvdHostPackageTarball == nil {
+		// nothing to do.
+		return
+	}
+
+	board_platform := proptools.String(ctx.Config().ProductVariables().BoardPlatform)
+	if (board_platform == "vsoc_arm") || (board_platform == "vsoc_arm64") || (board_platform == "vsoc_riscv64") || (board_platform == "vsoc_x86") || (board_platform == "vsoc_x86_64") {
+		p.tarballPaths = cvdHostPackageTarball
+		ctx.Phony("hosttar", cvdHostPackageTarball...)
+		ctx.Phony("droidcore", cvdHostPackageStamp...)
+	}
+}
+
+func (p *cvdHostPackageSingleton) MakeVars(ctx android.MakeVarsContext) {
+	if p.tarballPaths != nil {
+		for _, path := range p.tarballPaths {
+			// The riscv64 cuttlefish builds can be run on qemu on an x86_64 or arm64 host. Dist both sets of host packages.
+			if len(p.tarballPaths) > 1 && strings.Contains(path.String(), "linux-x86") {
+				ctx.DistForGoalWithFilename("dist_files", path, "cvd-host_package-x86_64.tar.gz")
+			} else {
+				ctx.DistForGoal("dist_files", path)
+			}
+		}
+	}
 }
diff --git a/common/frontend/socket_vsock_proxy/socket_vsock_proxy.cpp b/common/frontend/socket_vsock_proxy/socket_vsock_proxy.cpp
index fc47391d1..03b54f516 100644
--- a/common/frontend/socket_vsock_proxy/socket_vsock_proxy.cpp
+++ b/common/frontend/socket_vsock_proxy/socket_vsock_proxy.cpp
@@ -181,28 +181,37 @@ static Result<void> ListenEventsAndProxy(int events_fd,
           "Could not read restore pipe: " << restore_pipe_read->StrError());
     }
     LOG(INFO) << "restoring proxy on CUTTLEFISH_HOST - success";
-    proxy = std::move(CF_EXPECT(StartProxyAsync(server, client)));
+    proxy = CF_EXPECT(StartProxyAsync(server, client));
   }
 #endif
 
   LOG(DEBUG) << "Start reading events to start/stop proxying";
   while (events->IsOpen()) {
-    std::optional<monitor::ReadEventResult> received_event = monitor::ReadEvent(events);
+    Result<std::optional<monitor::ReadEventResult>> received_event =
+        monitor::ReadEvent(events);
 
+    // TODO(schuffelen): Investigate if any errors here are recoverable, and
+    // remove the distinction between EOF and other errors if none are
+    // recoverable.
     if (!received_event) {
-      LOG(ERROR) << "Failed to read a complete kernel log event";
+      LOG(ERROR) << "Failed reading kernel log event: "
+                 << received_event.error().FormatForEnv();
       continue;
     }
+    if (!(*received_event)) {
+      LOG(DEBUG) << "Kernel log message channel closed";
+      break;
+    }
 
-    if (start != -1 && received_event->event == start) {
+    if (start != -1 && (*received_event)->event == start) {
       if (!proxy) {
         LOG(INFO) << "Start event (" << start << ") received. Starting proxy";
-        proxy = std::move(CF_EXPECT(StartProxyAsync(server, client)));
+        proxy = CF_EXPECT(StartProxyAsync(server, client));
       }
       continue;
     }
 
-    if (stop != -1 && received_event->event == stop) {
+    if (stop != -1 && (*received_event)->event == stop) {
       LOG(INFO) << "Stop event (" << start << ") received. Stopping proxy";
       proxy.reset();
       continue;
diff --git a/common/libs/fs/shared_fd.cpp b/common/libs/fs/shared_fd.cpp
index 2442787b2..0f5393975 100644
--- a/common/libs/fs/shared_fd.cpp
+++ b/common/libs/fs/shared_fd.cpp
@@ -46,6 +46,21 @@ namespace cuttlefish {
 
 namespace {
 
+class LocalErrno {
+ public:
+  LocalErrno(int& local_errno) : local_errno_(local_errno), preserved_(errno) {
+    errno = 0;
+  }
+  ~LocalErrno() {
+    local_errno_ = errno;
+    errno = preserved_;
+  }
+
+ private:
+  int& local_errno_;
+  int preserved_;
+};
+
 void MarkAll(const SharedFDSet& input, fd_set* dest, int* max_index) {
   for (SharedFDSet::const_iterator it = input.begin(); it != input.end();
        ++it) {
@@ -111,6 +126,7 @@ constexpr size_t kPreferredBufferSize = 8192;
 }  // namespace
 
 bool FileInstance::CopyFrom(FileInstance& in, size_t length, FileInstance* stop) {
+  LocalErrno record_errno(errno_);
   std::vector<char> buffer(kPreferredBufferSize);
   while (length > 0) {
     int nfds = stop == nullptr ? 2 : 3;
@@ -130,9 +146,7 @@ bool FileInstance::CopyFrom(FileInstance& in, size_t length, FileInstance* stop)
       pollfds[STOP].events = POLLIN;
       pollfds[STOP].revents = 0;
     }
-    int res = poll(pollfds, nfds, -1 /* indefinitely */);
-    if (res < 0) {
-      errno_ = errno;
+    if (poll(pollfds, nfds, -1 /* indefinitely */) < 0) {
       return false;
     }
     if (stop && pollfds[STOP].revents & POLLIN) {
@@ -198,13 +212,9 @@ void FileInstance::Close() {
 }
 
 bool FileInstance::Chmod(mode_t mode) {
-  int original_error = errno;
-  int ret = fchmod(fd_, mode);
-  if (ret != 0) {
-    errno_ = errno;
-  }
-  errno = original_error;
-  return ret == 0;
+  LocalErrno record_errno(errno_);
+
+  return fchmod(fd_, mode) == 0;
 }
 
 int FileInstance::ConnectWithTimeout(const struct sockaddr* addr,
@@ -485,10 +495,9 @@ int SharedFD::Fchdir(SharedFD shared_fd) {
   if (!shared_fd.value_) {
     return -1;
   }
-  errno = 0;
-  int rval = TEMP_FAILURE_RETRY(fchdir(shared_fd->fd_));
-  shared_fd->errno_ = errno;
-  return rval;
+  LocalErrno record_errno(shared_fd->errno_);
+
+  return TEMP_FAILURE_RETRY(fchdir(shared_fd->fd_));
 }
 
 Result<SharedFD> SharedFD::Fifo(const std::string& path, mode_t mode) {
@@ -706,11 +715,8 @@ SharedFD SharedFD::VsockServer(
          "guest";
 #endif
   if (vhost_user_vsock_listening_cid) {
-    // TODO(b/277909042): better path than /tmp/vsock_{}/vm.vsock_{}
     return SharedFD::SocketLocalServer(
-        fmt::format("/tmp/vsock_{}_{}/vm.vsock_{}",
-                    *vhost_user_vsock_listening_cid, std::to_string(getuid()),
-                    port),
+        GetVhostUserVsockServerAddr(port, *vhost_user_vsock_listening_cid),
         false /* abstract */, type, 0666 /* mode */);
   }
 
@@ -743,6 +749,20 @@ SharedFD SharedFD::VsockServer(
   return VsockServer(VMADDR_PORT_ANY, type, vhost_user_vsock_listening_cid);
 }
 
+std::string SharedFD::GetVhostUserVsockServerAddr(
+    unsigned int port, int vhost_user_vsock_listening_cid) {
+  // TODO(b/277909042): better path than /tmp/vsock_{}/vm.vsock_{}
+  return fmt::format(
+      "{}_{}", GetVhostUserVsockClientAddr(vhost_user_vsock_listening_cid),
+      port);
+}
+
+std::string SharedFD::GetVhostUserVsockClientAddr(int cid) {
+  // TODO(b/277909042): better path than /tmp/vsock_{}/vm.vsock_{}
+  return fmt::format("/tmp/vsock_{}_{}/vm.vsock", cid,
+                     std::to_string(getuid()));
+}
+
 SharedFD SharedFD::VsockClient(unsigned int cid, unsigned int port, int type,
                                bool vhost_user) {
 #ifndef CUTTLEFISH_HOST
@@ -750,9 +770,8 @@ SharedFD SharedFD::VsockClient(unsigned int cid, unsigned int port, int type,
 #endif
   if (vhost_user) {
     // TODO(b/277909042): better path than /tmp/vsock_{}/vm.vsock
-    auto client = SharedFD::SocketLocalClient(
-        fmt::format("/tmp/vsock_{}_{}/vm.vsock", cid, std::to_string(getuid())),
-        false /* abstract */, type);
+    auto client = SharedFD::SocketLocalClient(GetVhostUserVsockClientAddr(cid),
+                                              false /* abstract */, type);
     const std::string msg = fmt::format("connect {}\n", port);
     SendAll(client, msg);
 
@@ -816,62 +835,52 @@ ScopedMMap::~ScopedMMap() {
 }
 
 int FileInstance::Bind(const struct sockaddr* addr, socklen_t addrlen) {
-  errno = 0;
-  int rval = bind(fd_, addr, addrlen);
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return bind(fd_, addr, addrlen);
 }
 
 int FileInstance::Connect(const struct sockaddr* addr, socklen_t addrlen) {
-  errno = 0;
-  int rval = connect(fd_, addr, addrlen);
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return connect(fd_, addr, addrlen);
 }
 
 int FileInstance::UNMANAGED_Dup() {
-  errno = 0;
-  int rval = TEMP_FAILURE_RETRY(dup(fd_));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(dup(fd_));
 }
 
 int FileInstance::UNMANAGED_Dup2(int newfd) {
-  errno = 0;
-  int rval = TEMP_FAILURE_RETRY(dup2(fd_, newfd));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(dup2(fd_, newfd));
 }
 
 int FileInstance::Fcntl(int command, int value) {
-  errno = 0;
-  int rval = TEMP_FAILURE_RETRY(fcntl(fd_, command, value));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(fcntl(fd_, command, value));
 }
 
 int FileInstance::Fsync() {
-  errno = 0;
-  int rval = TEMP_FAILURE_RETRY(fsync(fd_));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(fsync(fd_));
 }
 
 Result<void> FileInstance::Flock(int operation) {
-  errno = 0;
-  int rval = TEMP_FAILURE_RETRY(flock(fd_, operation));
-  errno_ = errno;
-  CF_EXPECT(rval == 0, StrError());
+  LocalErrno record_errno(errno_);
+
+  CF_EXPECT(TEMP_FAILURE_RETRY(flock(fd_, operation)) == 0, strerror(errno));
   return {};
 }
 
 int FileInstance::GetSockName(struct sockaddr* addr, socklen_t* addrlen) {
-  errno = 0;
-  int rval = TEMP_FAILURE_RETRY(getsockname(fd_, addr, addrlen));
-  if (rval == -1) {
-    errno_ = errno;
-  }
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(getsockname(fd_, addr, addrlen));
 }
 
 #ifdef __linux__
@@ -884,131 +893,112 @@ unsigned int FileInstance::VsockServerPort() {
 #endif
 
 int FileInstance::Ioctl(int request, void* val) {
-  errno = 0;
-  int rval = TEMP_FAILURE_RETRY(ioctl(fd_, request, val));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(ioctl(fd_, request, val));
 }
 
 int FileInstance::LinkAtCwd(const std::string& path) {
+  LocalErrno record_errno(errno_);
+
   std::string name = "/proc/self/fd/";
   name += std::to_string(fd_);
-  errno = 0;
-  int rval =
-      linkat(-1, name.c_str(), AT_FDCWD, path.c_str(), AT_SYMLINK_FOLLOW);
-  errno_ = errno;
-  return rval;
+  return linkat(-1, name.c_str(), AT_FDCWD, path.c_str(), AT_SYMLINK_FOLLOW);
 }
 
 int FileInstance::Listen(int backlog) {
-  errno = 0;
-  int rval = listen(fd_, backlog);
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return listen(fd_, backlog);
 }
 
 off_t FileInstance::LSeek(off_t offset, int whence) {
-  errno = 0;
-  off_t rval = TEMP_FAILURE_RETRY(lseek(fd_, offset, whence));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(lseek(fd_, offset, whence));
 }
 
 ssize_t FileInstance::Recv(void* buf, size_t len, int flags) {
-  errno = 0;
-  ssize_t rval = TEMP_FAILURE_RETRY(recv(fd_, buf, len, flags));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(recv(fd_, buf, len, flags));
 }
 
 ssize_t FileInstance::RecvMsg(struct msghdr* msg, int flags) {
-  errno = 0;
-  ssize_t rval = TEMP_FAILURE_RETRY(recvmsg(fd_, msg, flags));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(recvmsg(fd_, msg, flags));
 }
 
 ssize_t FileInstance::Read(void* buf, size_t count) {
-  errno = 0;
-  ssize_t rval = TEMP_FAILURE_RETRY(read(fd_, buf, count));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(read(fd_, buf, count));
 }
 
 #ifdef __linux__
 int FileInstance::EventfdRead(eventfd_t* value) {
-  errno = 0;
-  auto rval = eventfd_read(fd_, value);
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return eventfd_read(fd_, value);
 }
 #endif
 
 ssize_t FileInstance::Send(const void* buf, size_t len, int flags) {
-  errno = 0;
-  ssize_t rval = TEMP_FAILURE_RETRY(send(fd_, buf, len, flags));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(send(fd_, buf, len, flags));
 }
 
 ssize_t FileInstance::SendMsg(const struct msghdr* msg, int flags) {
-  errno = 0;
-  ssize_t rval = TEMP_FAILURE_RETRY(sendmsg(fd_, msg, flags));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(sendmsg(fd_, msg, flags));
 }
 
 int FileInstance::Shutdown(int how) {
-  errno = 0;
-  int rval = shutdown(fd_, how);
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return shutdown(fd_, how);
 }
 
 int FileInstance::SetSockOpt(int level, int optname, const void* optval,
                              socklen_t optlen) {
-  errno = 0;
-  int rval = setsockopt(fd_, level, optname, optval, optlen);
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return setsockopt(fd_, level, optname, optval, optlen);
 }
 
 int FileInstance::GetSockOpt(int level, int optname, void* optval,
                              socklen_t* optlen) {
-  errno = 0;
-  int rval = getsockopt(fd_, level, optname, optval, optlen);
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return getsockopt(fd_, level, optname, optval, optlen);
 }
 
 int FileInstance::SetTerminalRaw() {
-  errno = 0;
+  LocalErrno record_errno(errno_);
+
   termios terminal_settings;
-  int rval = tcgetattr(fd_, &terminal_settings);
-  errno_ = errno;
-  if (rval < 0) {
+  if (int rval = tcgetattr(fd_, &terminal_settings); rval < 0) {
     return rval;
   }
   cfmakeraw(&terminal_settings);
-  rval = tcsetattr(fd_, TCSANOW, &terminal_settings);
-  errno_ = errno;
-  if (rval < 0) {
+  if (int rval = tcsetattr(fd_, TCSANOW, &terminal_settings); rval < 0) {
     return rval;
   }
 
-  // tcsetattr() success if any of the requested change success.
+  // tcsetattr() succeeds if any of the requested change success.
   // So double check whether everything is applied.
   termios raw_settings;
-  rval = tcgetattr(fd_, &raw_settings);
-  errno_ = errno;
-  if (rval < 0) {
+  if (int rval = tcgetattr(fd_, &raw_settings); rval < 0) {
     return rval;
   }
   if (memcmp(&terminal_settings, &raw_settings, sizeof(terminal_settings))) {
-    errno_ = EPROTO;
+    errno = EPROTO;
     return -1;
   }
-  return rval;
+  return 0;
 }
 
 std::string FileInstance::StrError() const {
@@ -1018,50 +1008,46 @@ std::string FileInstance::StrError() const {
 
 ScopedMMap FileInstance::MMap(void* addr, size_t length, int prot, int flags,
                               off_t offset) {
-  errno = 0;
+  LocalErrno record_errno(errno_);
+
   auto ptr = mmap(addr, length, prot, flags, fd_, offset);
-  errno_ = errno;
   return ScopedMMap(ptr, length);
 }
 
 ssize_t FileInstance::Truncate(off_t length) {
-  errno = 0;
-  ssize_t rval = TEMP_FAILURE_RETRY(ftruncate(fd_, length));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(ftruncate(fd_, length));
 }
 
 ssize_t FileInstance::Write(const void* buf, size_t count) {
   if (count == 0 && !IsRegular()) {
     return 0;
   }
-  errno = 0;
-  ssize_t rval = TEMP_FAILURE_RETRY(write(fd_, buf, count));
-  errno_ = errno;
-  return rval;
+
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(write(fd_, buf, count));
 }
 
 #ifdef __linux__
 int FileInstance::EventfdWrite(eventfd_t value) {
-  errno = 0;
-  int rval = eventfd_write(fd_, value);
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return eventfd_write(fd_, value);
 }
 #endif
 
 bool FileInstance::IsATTY() {
-  errno = 0;
-  int rval = isatty(fd_);
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return isatty(fd_);
 }
 
 int FileInstance::Futimens(const struct timespec times[2]) {
-  errno = 0;
-  int rval = TEMP_FAILURE_RETRY(futimens(fd_, times));
-  errno_ = errno;
-  return rval;
+  LocalErrno record_errno(errno_);
+
+  return TEMP_FAILURE_RETRY(futimens(fd_, times));
 }
 
 #ifdef __linux__
diff --git a/common/libs/fs/shared_fd.h b/common/libs/fs/shared_fd.h
index b38462f1a..3f6730efd 100644
--- a/common/libs/fs/shared_fd.h
+++ b/common/libs/fs/shared_fd.h
@@ -197,6 +197,9 @@ class SharedFD {
       int type, std::optional<int> vhost_user_vsock_listening_cid);
   static SharedFD VsockClient(unsigned int cid, unsigned int port, int type,
                               bool vhost_user);
+  static std::string GetVhostUserVsockServerAddr(
+      unsigned int port, int vhost_user_vsock_listening_cid);
+  static std::string GetVhostUserVsockClientAddr(int cid);
 #endif
 
   bool operator==(const SharedFD& rhs) const { return value_ == rhs.value_; }
diff --git a/common/libs/utils/Android.bp b/common/libs/utils/Android.bp
index 6ac56bfc7..2bb9e3b02 100644
--- a/common/libs/utils/Android.bp
+++ b/common/libs/utils/Android.bp
@@ -26,6 +26,7 @@ cc_library {
         "files.cpp",
         "flag_parser.cpp",
         "flags_validator.cpp",
+        "in_sandbox.cpp",
         "json.cpp",
         "network.cpp",
         "proc_file_utils.cpp",
@@ -40,8 +41,8 @@ cc_library {
     shared: {
         shared_libs: [
             "libbase",
-            "libcuttlefish_fs",
             "libcrypto",
+            "libcuttlefish_fs",
             "libjsoncpp",
         ],
     },
@@ -52,7 +53,7 @@ cc_library {
             "libjsoncpp",
         ],
         shared_libs: [
-          "libcrypto", // libcrypto_static is not accessible from all targets
+            "libcrypto", // libcrypto_static is not accessible from all targets
         ],
     },
     target: {
@@ -64,7 +65,7 @@ cc_library {
                 "inotify.cpp",
                 "socket2socket_proxy.cpp", // TODO(b/285989475): Find eventfd alternative
                 "vsock_connection.cpp",
-            ]
+            ],
         },
     },
     whole_static_libs: ["libcuttlefish_utils_result"],
@@ -82,7 +83,6 @@ cc_test_host {
         "network_test.cpp",
         "proc_file_utils_test.cpp",
         "result_test.cpp",
-        "unique_resource_allocator_test.cpp",
         "unix_sockets_test.cpp",
     ],
     static_libs: [
@@ -105,7 +105,12 @@ cc_test_host {
 cc_library {
     name: "libvsock_utils",
     srcs: ["vsock_connection.cpp"],
-    shared_libs: ["libbase", "libcuttlefish_fs", "liblog", "libjsoncpp"],
+    shared_libs: [
+        "libbase",
+        "libcuttlefish_fs",
+        "libjsoncpp",
+        "liblog",
+    ],
     defaults: ["cuttlefish_guest_only"],
     include_dirs: ["device/google/cuttlefish"],
     export_include_dirs: ["."],
@@ -126,4 +131,3 @@ cc_library {
     },
     defaults: ["cuttlefish_host"],
 }
-
diff --git a/common/libs/utils/collect.h b/common/libs/utils/collect.h
deleted file mode 100644
index 08d5287b1..000000000
--- a/common/libs/utils/collect.h
+++ /dev/null
@@ -1,61 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#pragma once
-
-#include <algorithm>
-
-#include "common/libs/utils/result.h"
-
-namespace cuttlefish {
-
-/**
- * return all the elements in container that satisfies predicate.
- *
- * Container could be mostly any type, and Set should be any sort of set.
- */
-template <typename T, typename Set, typename Container>
-Set Collect(const Container& container,
-            std::function<bool(const T&)> predicate) {
-  Set output;
-  std::copy_if(container.cbegin(), container.cend(),
-               std::inserter(output, output.end()), predicate);
-  return output;
-}
-
-/**
- * Collect all Ts from each container inside the "Containers"
- *
- * Containers are a set/list of Container. Container can be viewed as a set/list
- * of Ts.
- *
- */
-template <typename T, typename Set, typename Containers>
-Set Flatten(const Containers& containers) {
-  Set output;
-  for (const auto& container : containers) {
-    output.insert(container.cbegin(), container.cend());
-  }
-  return output;
-}
-
-template <typename S>
-Result<typename std::remove_reference<S>::type> AtMostN(S&& s, const size_t n) {
-  CF_EXPECT(s.size() <= n);
-  return {std::forward<S>(s)};
-}
-
-}  // namespace cuttlefish
diff --git a/common/libs/utils/environment.cpp b/common/libs/utils/environment.cpp
index 5fc7819cf..b8ff0d2d8 100644
--- a/common/libs/utils/environment.cpp
+++ b/common/libs/utils/environment.cpp
@@ -16,6 +16,8 @@
 
 #include "common/libs/utils/environment.h"
 
+#include <sys/utsname.h>
+
 #include <cstdio>
 #include <cstdlib>
 #include <memory>
@@ -23,6 +25,7 @@
 #include <string>
 
 #include <android-base/logging.h>
+#include <android-base/no_destructor.h>
 #include <android-base/strings.h>
 
 #include "common/libs/utils/files.h"
@@ -38,49 +41,14 @@ std::string StringFromEnv(const std::string& varname,
   return valstr;
 }
 
-/**
- * at runtime, return the arch of the host: e.g. aarch64, x86_64, etc
- *
- * uses "`which uname` -m"
- *
- * @return arch string on success, "" on failure
- */
-std::string HostArchStr() {
-  static std::string arch;
-  if (!arch.empty()) {
-    return arch;
-  }
-
-  // good to check if uname exists and is executable
-  // or, guarantee uname is available by dependency list
-  FILE* pip = popen("uname -m", "r");
-  if (!pip) {
-    return std::string{};
-  }
-
-  auto read_from_file =
-      [](FILE* fp, size_t len) {
-        /*
-         * to see if input is longer than len,
-         * we read up to len+1. If the length is len+1,
-         * then the input is too long
-         */
-        decltype(len) upper = len + 1;
-        std::string format("%");
-        format.append(std::to_string(upper)).append("s");
-        // 1 extra character needed for the terminating null
-        // character added by fscanf.
-        std::shared_ptr<char> buf(new char[upper + 1],
-                                  std::default_delete<char[]>());
-        if (fscanf(fp, format.c_str(), buf.get()) == EOF) {
-          return std::string{};
-        }
-        std::string result(buf.get());
-        return (result.length() < upper) ? result : std::string{};
-      };
-  arch = android::base::Trim(std::string_view{read_from_file(pip, 20)});
-  pclose(pip);
-  return arch;
+/** Returns e.g. aarch64, x86_64, etc */
+const std::string& HostArchStr() {
+  static android::base::NoDestructor<std::string> arch([] {
+    utsname buf;
+    CHECK_EQ(uname(&buf), 0) << strerror(errno);
+    return std::string(buf.machine);
+  }());
+  return *arch;
 }
 
 Arch HostArch() {
diff --git a/common/libs/utils/environment.h b/common/libs/utils/environment.h
index b84c03616..7bea0a581 100644
--- a/common/libs/utils/environment.h
+++ b/common/libs/utils/environment.h
@@ -30,7 +30,7 @@ enum class Arch {
 std::string StringFromEnv(const std::string& varname,
                           const std::string& defval);
 
-std::string HostArchStr();
+const std::string& HostArchStr();
 Arch HostArch();
 bool IsHostCompatible(Arch arch);
 
diff --git a/common/libs/utils/files.cpp b/common/libs/utils/files.cpp
index 095674af6..51131c7df 100644
--- a/common/libs/utils/files.cpp
+++ b/common/libs/utils/files.cpp
@@ -65,6 +65,7 @@
 #include "common/libs/fs/shared_buf.h"
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/contains.h"
+#include "common/libs/utils/in_sandbox.h"
 #include "common/libs/utils/inotify.h"
 #include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
@@ -152,6 +153,9 @@ Result<std::vector<std::string>> DirectoryContents(const std::string& path) {
   CF_EXPECTF(dir != nullptr, "Could not read from dir \"{}\"", path);
   struct dirent* ent{};
   while ((ent = readdir(dir.get()))) {
+    if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
+      continue;
+    }
     ret.emplace_back(ent->d_name);
   }
   return ret;
@@ -189,6 +193,10 @@ Result<void> EnsureDirectoryExists(const std::string& directory_path,
     return CF_ERRNO("Failed to create directory: \"" << directory_path << "\""
                                                      << strerror(errno));
   }
+  // TODO(schuffelen): Find an alternative for host-sandboxing mode
+  if (InSandbox()) {
+    return {};
+  }
 
   CF_EXPECTF(chmod(directory_path.c_str(), mode) == 0,
              "Failed to set permission on {}: {}", directory_path,
@@ -524,17 +532,6 @@ FileSizes SparseFileSizes(const std::string& path) {
   return (FileSizes) { .sparse_size = farthest_seek, .disk_size = data_bytes };
 }
 
-std::string cpp_basename(const std::string& str) {
-  char* copy = strdup(str.c_str()); // basename may modify its argument
-  std::string ret(basename(copy));
-  free(copy);
-  return ret;
-}
-
-std::string cpp_dirname(const std::string& str) {
-  return android::base::Dirname(str);
-}
-
 bool FileIsSocket(const std::string& path) {
   struct stat st {};
   return stat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode);
@@ -580,7 +577,7 @@ std::string FindFile(const std::string& path, const std::string& target_name) {
   std::string ret;
   WalkDirectory(path,
                 [&ret, &target_name](const std::string& filename) mutable {
-                  if (cpp_basename(filename) == target_name) {
+                  if (android::base::Basename(filename) == target_name) {
                     ret = filename;
                   }
                   return true;
@@ -595,9 +592,6 @@ Result<void> WalkDirectory(
     const std::function<bool(const std::string&)>& callback) {
   const auto files = CF_EXPECT(DirectoryContents(dir));
   for (const auto& filename : files) {
-    if (filename == "." || filename == "..") {
-      continue;
-    }
     auto file_path = dir + "/";
     file_path.append(filename);
     callback(file_path);
@@ -633,8 +627,8 @@ static Result<void> WaitForFileInternal(const std::string& path, int timeoutSec,
   const auto targetTime =
       std::chrono::system_clock::now() + std::chrono::seconds(timeoutSec);
 
-  const auto parentPath = cpp_dirname(path);
-  const auto filename = cpp_basename(path);
+  const std::string parentPath = android::base::Dirname(path);
+  const std::string filename = android::base::Basename(path);
 
   CF_EXPECT(WaitForFile(parentPath, timeoutSec),
             "Error while waiting for parent directory creation");
@@ -747,7 +741,7 @@ Result<void> WaitForUnixSocketListeningWithoutConnect(const std::string& path,
       return CF_ERR("Timed out");
     }
 
-    Command lsof("lsof");
+    Command lsof("/usr/bin/lsof");
     lsof.AddParameter(/*"format"*/ "-F", /*"connection state"*/ "TST");
     lsof.AddParameter(path);
     std::string lsof_out;
diff --git a/common/libs/utils/files.h b/common/libs/utils/files.h
index e47ad432d..64a05d3fa 100644
--- a/common/libs/utils/files.h
+++ b/common/libs/utils/files.h
@@ -56,9 +56,8 @@ Result<std::string> RenameFile(const std::string& current_filepath,
 std::string ReadFile(const std::string& file);
 Result<std::string> ReadFileContents(const std::string& filepath);
 bool MakeFileExecutable(const std::string& path);
-std::chrono::system_clock::time_point FileModificationTime(const std::string& path);
-std::string cpp_dirname(const std::string& str);
-std::string cpp_basename(const std::string& str);
+std::chrono::system_clock::time_point FileModificationTime(
+    const std::string& path);
 // Whether a file exists and is a unix socket
 bool FileIsSocket(const std::string& path);
 // Get disk usage of a path. If this path is a directory, disk usage will
diff --git a/common/libs/utils/in_sandbox.cpp b/common/libs/utils/in_sandbox.cpp
new file mode 100644
index 000000000..7032f5c7b
--- /dev/null
+++ b/common/libs/utils/in_sandbox.cpp
@@ -0,0 +1,24 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "common/libs/utils/in_sandbox.h"
+
+#include <unistd.h>
+
+namespace cuttlefish {
+
+bool InSandbox() { return access("/manager.sock", F_OK) == 0; }
+
+}  // namespace cuttlefish
diff --git a/shared/api_level.h b/common/libs/utils/in_sandbox.h
similarity index 85%
rename from shared/api_level.h
rename to common/libs/utils/in_sandbox.h
index 06cf49c5b..e6bddc631 100644
--- a/shared/api_level.h
+++ b/common/libs/utils/in_sandbox.h
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2022 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -15,4 +15,8 @@
  */
 #pragma once
 
-#define PRODUCT_SHIPPING_API_LEVEL 35
+namespace cuttlefish {
+
+bool InSandbox();
+
+}
diff --git a/common/libs/utils/json.h b/common/libs/utils/json.h
index bd5cf5882..d2f62d89e 100644
--- a/common/libs/utils/json.h
+++ b/common/libs/utils/json.h
@@ -49,6 +49,11 @@ inline bool As(const Json::Value& v) {
   return v.asBool();
 }
 
+template <>
+inline Json::Value As(const Json::Value& v) {
+  return v;
+}
+
 template <typename T>
 Result<T> GetValue(const Json::Value& root,
                    const std::vector<std::string>& selectors) {
diff --git a/common/libs/utils/network.cpp b/common/libs/utils/network.cpp
index 9c2a75166..e99266c53 100644
--- a/common/libs/utils/network.cpp
+++ b/common/libs/utils/network.cpp
@@ -33,14 +33,8 @@
 
 #include <cstdint>
 #include <cstring>
-#include <functional>
-#include <iomanip>
-#include <ios>
-#include <memory>
 #include <ostream>
 #include <set>
-#include <sstream>
-#include <streambuf>
 #include <string>
 #include <utility>
 #include <vector>
@@ -49,6 +43,7 @@
 #include <android-base/strings.h>
 #include <fmt/format.h>
 
+#include "common/libs/utils/files.h"
 #include "common/libs/utils/subprocess.h"
 
 namespace cuttlefish {
@@ -105,46 +100,51 @@ bool NetworkInterfaceExists(const std::string& interface_name) {
 }
 
 #ifdef __linux__
-SharedFD OpenTapInterface(const std::string& interface_name) {
-  constexpr auto TUNTAP_DEV = "/dev/net/tun";
+static std::optional<Command> EgrepCommand() {
+  if (FileExists("/usr/bin/egrep")) {
+    return Command("/usr/bin/egrep");
+  } else if (FileExists("/bin/egrep")) {
+    return Command("/bin/egrep");
+  } else {
+    return {};
+  }
+}
+
+std::set<std::string> TapInterfacesInUse() {
+  std::vector<std::string> fdinfo_list;
+
+  Result<std::vector<std::string>> processes = DirectoryContents("/proc");
+  if (!processes.ok()) {
+    LOG(ERROR) << "Failed to get contents of `/proc/`";
+    return {};
+  }
+  for (const std::string& process : *processes) {
+    std::string fdinfo_path = fmt::format("/proc/{}/fdinfo", process);
+    Result<std::vector<std::string>> fdinfos = DirectoryContents(fdinfo_path);
+    if (!fdinfos.ok()) {
+      LOG(VERBOSE) << "Failed to get contents of '" << fdinfo_path << "'";
+      continue;
+    }
+    for (const std::string& fdinfo : *fdinfos) {
+      std::string path = fmt::format("/proc/{}/fdinfo/{}", process, fdinfo);
+      fdinfo_list.emplace_back(std::move(path));
+    }
+  }
 
-  auto tap_fd = SharedFD::Open(TUNTAP_DEV, O_RDWR | O_NONBLOCK);
-  if (!tap_fd->IsOpen()) {
-    LOG(ERROR) << "Unable to open tun device: " << tap_fd->StrError();
-    return tap_fd;
+  std::optional<Command> cmd = EgrepCommand();
+  if (!cmd) {
+    LOG(WARNING) << "Unable to test TAP interface usage";
+    return {};
   }
+  cmd->AddParameter("-h").AddParameter("-e").AddParameter("^iff:.*");
 
-  struct ifreq ifr;
-  memset(&ifr, 0, sizeof(ifr));
-  ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
-  strncpy(ifr.ifr_name, interface_name.c_str(), IFNAMSIZ);
-
-  int err = tap_fd->Ioctl(TUNSETIFF, &ifr);
-  if (err < 0) {
-    LOG(ERROR) << "Unable to connect to " << interface_name
-               << " tap interface: " << tap_fd->StrError();
-    tap_fd->Close();
-    return SharedFD();
+  for (const std::string& fdinfo : fdinfo_list) {
+    cmd->AddParameter(fdinfo);
   }
 
-  // The interface's configuration may have been modified or just not set
-  // correctly on creation. While qemu checks this and enforces the right
-  // configuration, crosvm does not, so it needs to be set before it's passed to
-  // it.
-  tap_fd->Ioctl(TUNSETOFFLOAD,
-                reinterpret_cast<void*>(TUN_F_CSUM | TUN_F_UFO | TUN_F_TSO4 |
-                                        TUN_F_TSO6));
-  int len = SIZE_OF_VIRTIO_NET_HDR_V1;
-  tap_fd->Ioctl(TUNSETVNETHDRSZ, &len);
-  return tap_fd;
-}
+  std::string stdout_str, stderr_str;
+  RunWithManagedStdio(std::move(*cmd), nullptr, &stdout_str, &stderr_str);
 
-std::set<std::string> TapInterfacesInUse() {
-  Command cmd("/bin/bash");
-  cmd.AddParameter("-c");
-  cmd.AddParameter("egrep -h -e \"^iff:.*\" /proc/*/fdinfo/*");
-  std::string stdin_str, stdout_str, stderr_str;
-  RunWithManagedStdio(std::move(cmd), &stdin_str, &stdout_str, &stderr_str);
   auto lines = android::base::Split(stdout_str, "\n");
   std::set<std::string> tap_interfaces;
   for (const auto& line : lines) {
diff --git a/common/libs/utils/network.h b/common/libs/utils/network.h
index 228df949a..cf144f707 100644
--- a/common/libs/utils/network.h
+++ b/common/libs/utils/network.h
@@ -19,18 +19,11 @@
 #include <set>
 #include <string>
 
-#include "common/libs/fs/shared_fd.h"
-
 namespace cuttlefish {
 // Check network interface with given name exists, such as cvd-ebr.
 bool NetworkInterfaceExists(const std::string& interface_name);
 
 #ifdef __linux__
-// Creates, or connects to if it already exists, a tap network interface. The
-// user needs CAP_NET_ADMIN to create such interfaces or be the owner to connect
-// to one.
-SharedFD OpenTapInterface(const std::string& interface_name);
-
 // Returns a list of TAP devices that have open file descriptors
 std::set<std::string> TapInterfacesInUse();
 #endif
diff --git a/common/libs/utils/proc_file_utils.cpp b/common/libs/utils/proc_file_utils.cpp
index 1a3410c88..ae96afd2c 100644
--- a/common/libs/utils/proc_file_utils.cpp
+++ b/common/libs/utils/proc_file_utils.cpp
@@ -211,7 +211,7 @@ static Result<void> CheckExecNameFromStatus(const std::string& exec_name,
 
 Result<std::vector<pid_t>> CollectPidsByExecName(const std::string& exec_name,
                                                  const uid_t uid) {
-  CF_EXPECT(cpp_basename(exec_name) == exec_name);
+  CF_EXPECT_EQ(android::base::Basename(exec_name), exec_name);
   auto input_pids = CF_EXPECT(CollectPids(uid));
   std::vector<pid_t> output_pids;
   for (const auto pid : input_pids) {
diff --git a/common/libs/utils/proc_file_utils.h b/common/libs/utils/proc_file_utils.h
index e8a2e0603..4e5494770 100644
--- a/common/libs/utils/proc_file_utils.h
+++ b/common/libs/utils/proc_file_utils.h
@@ -50,7 +50,7 @@ Result<std::vector<pid_t>> CollectPids(const uid_t uid = getuid());
 /* collects all pids that meet the following:
  *
  * 1. Belongs to the uid
- * 2. cpp_basename(readlink(/proc/<pid>/exe)) == exec_name
+ * 2. Basename(readlink(/proc/<pid>/exe)) == exec_name
  *
  */
 Result<std::vector<pid_t>> CollectPidsByExecName(const std::string& exec_name,
diff --git a/common/libs/utils/subprocess.cpp b/common/libs/utils/subprocess.cpp
index c8ae8f91f..dd35a15c0 100644
--- a/common/libs/utils/subprocess.cpp
+++ b/common/libs/utils/subprocess.cpp
@@ -141,18 +141,6 @@ SubprocessOptions SubprocessOptions::ExitWithParent(bool v) && {
 }
 #endif
 
-SubprocessOptions& SubprocessOptions::SandboxArguments(
-    std::vector<std::string> args) & {
-  sandbox_arguments_ = std::move(args);
-  return *this;
-}
-
-SubprocessOptions SubprocessOptions::SandboxArguments(
-    std::vector<std::string> args) && {
-  sandbox_arguments_ = std::move(args);
-  return *this;
-}
-
 SubprocessOptions& SubprocessOptions::InGroup(bool in_group) & {
   in_group_ = in_group;
   return *this;
@@ -424,24 +412,6 @@ Subprocess Command::Start(SubprocessOptions options) const {
     return Subprocess(-1, {});
   }
 
-  std::string fds_arg;
-  if (!options.SandboxArguments().empty()) {
-    std::vector<int> fds;
-    for (const auto& redirect : redirects_) {
-      fds.emplace_back(static_cast<int>(redirect.first));
-    }
-    for (const auto& inherited_fd : inherited_fds_) {
-      fds.emplace_back(inherited_fd.second);
-    }
-    fds_arg = "--inherited_fds=" + fmt::format("{}", fmt::join(fds, ","));
-
-    auto forwarding_args = {fds_arg.c_str(), "--"};
-    cmd.insert(cmd.begin(), forwarding_args);
-    auto sbox_ptrs = ToCharPointers(options.SandboxArguments());
-    sbox_ptrs.pop_back();  // Final null pointer will end argv early
-    cmd.insert(cmd.begin(), sbox_ptrs.begin(), sbox_ptrs.end());
-  }
-
   pid_t pid = fork();
   if (!pid) {
 #ifdef __linux__
diff --git a/common/libs/utils/subprocess.h b/common/libs/utils/subprocess.h
index 4fadd757e..243b6e092 100644
--- a/common/libs/utils/subprocess.h
+++ b/common/libs/utils/subprocess.h
@@ -123,16 +123,12 @@ class SubprocessOptions {
 
   bool Verbose() const { return verbose_; }
   bool ExitWithParent() const { return exit_with_parent_; }
-  const std::vector<std::string>& SandboxArguments() const {
-    return sandbox_arguments_;
-  }
   bool InGroup() const { return in_group_; }
   const std::string& Strace() const { return strace_; }
 
  private:
   bool verbose_;
   bool exit_with_parent_;
-  std::vector<std::string> sandbox_arguments_;
   bool in_group_;
   std::string strace_;
 };
diff --git a/common/libs/utils/tee_logging.cpp b/common/libs/utils/tee_logging.cpp
index a8cb52e95..cd5349c34 100644
--- a/common/libs/utils/tee_logging.cpp
+++ b/common/libs/utils/tee_logging.cpp
@@ -265,7 +265,8 @@ static std::vector<SeverityTarget> SeverityTargetsForFiles(
         SharedFD::Open(file, O_CREAT | O_WRONLY | O_APPEND,
                        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
     if (!log_file_fd->IsOpen()) {
-      LOG(FATAL) << "Failed to create log file: " << log_file_fd->StrError();
+      LOG(FATAL) << "Failed to create log file '" << file
+                 << "': " << log_file_fd->StrError();
     }
     log_severities.push_back(
         SeverityTarget{LogFileSeverity(), log_file_fd, MetadataLevel::FULL});
diff --git a/common/libs/utils/unique_resource_allocator.h b/common/libs/utils/unique_resource_allocator.h
deleted file mode 100644
index 54a6b1fb2..000000000
--- a/common/libs/utils/unique_resource_allocator.h
+++ /dev/null
@@ -1,295 +0,0 @@
-/*
- * Copyright (C) 2022 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-#pragma once
-
-#include <functional>
-#include <memory>
-#include <mutex>
-#include <optional>
-#include <type_traits>
-#include <unordered_set>
-#include <utility>
-#include <vector>
-
-#include <android-base/logging.h>
-
-#include "common/libs/utils/contains.h"
-
-namespace cuttlefish {
-
-/**
- * Generic allocator that can provide RAII-aware resource reservations.
- *
- * See go/cf-resource-allocator-utils for more details.
- */
-template <typename T>
-class UniqueResourceAllocator {
-  template <typename U>
-  using RemoveCvref =
-      typename std::remove_cv_t<typename std::remove_reference_t<U>>;
-
- public:
-  /*
-   * Returning the inner resource to the pool at destruction time
-   *
-   * The pool must live longer than the resources. Use this like you use
-   * std::unique_ptr.
-   */
-  class Reservation {
-    friend class UniqueResourceAllocator;
-    friend class ReservationSet;
-
-   public:
-    Reservation(const Reservation&) = delete;
-    Reservation(Reservation&& src)
-        : resource_pool_(src.resource_pool_), resource_(src.resource_) {
-      src.resource_pool_ = nullptr;
-    }
-    Reservation& operator=(const Reservation&) = delete;
-    Reservation& operator=(Reservation&& src) = delete;
-
-    bool operator==(const Reservation& src) const {
-      return (resource_ == src.resource_ &&
-              resource_pool_ == src.resource_pool_);
-    }
-
-    ~Reservation() {
-      if (resource_pool_) {
-        resource_pool_->Reclaim(*resource_);
-      }
-    }
-    const T& Get() const { return *resource_; }
-
-   private:
-    Reservation(UniqueResourceAllocator& resource_pool, const T& resource)
-        : resource_pool_(std::addressof(resource_pool)),
-          resource_(std::addressof(resource)) {}
-    /*
-     * Once this Reservation is std::move-ed out to other object,
-     * resource_pool_ should be invalidated, and resource_ shouldn't
-     * be tried to be returned to the invalid resource_pool_
-     */
-    UniqueResourceAllocator* resource_pool_;
-    const T* resource_;
-  };
-
-  struct ReservationHash {
-    std::size_t operator()(const Reservation& resource_wrapper) const {
-      return std::hash<const T*>()(std::addressof(resource_wrapper.Get()));
-    }
-  };
-  using ReservationSet = std::unordered_set<Reservation, ReservationHash>;
-  /*
-   * Creates the singleton object.
-   *
-   * Call this function once during the entire program's life
-   */
-  static UniqueResourceAllocator& Create(const std::vector<T>& pool) {
-    static UniqueResourceAllocator singleton_allocator(pool);
-    return singleton_allocator;
-  }
-
-  static std::unique_ptr<UniqueResourceAllocator> New(
-      const std::vector<T>& pool) {
-    UniqueResourceAllocator* new_allocator = new UniqueResourceAllocator(pool);
-    return std::unique_ptr<UniqueResourceAllocator>(new_allocator);
-  }
-
-  // Adds the elements from new pool that did not belong to and have not
-  // belonged to the current pool of the allocator. returns the leftover
-  std::vector<T> ExpandPool(std::vector<T> another_pool) {
-    std::lock_guard lock(mutex_);
-    std::vector<T> not_selected;
-    for (auto& new_item : another_pool) {
-      if (Contains(available_resources_, new_item) ||
-          Contains(allocated_resources_, new_item)) {
-        not_selected.emplace_back(std::move(new_item));
-        continue;
-      }
-      available_resources_.insert(std::move(new_item));
-    }
-    return not_selected;
-  }
-
-  std::vector<T> ExpandPool(T&& t) {
-    std::vector<T> pool_to_add;
-    pool_to_add.emplace_back(std::move(t));
-    return ExpandPool(std::move(pool_to_add));
-  }
-
-  std::vector<T> ExpandPool(const T& t) {
-    std::vector<T> pool_to_add;
-    pool_to_add.emplace_back(t);
-    return ExpandPool(std::move(pool_to_add));
-  }
-
-  std::optional<Reservation> UniqueItem() {
-    std::lock_guard<std::mutex> lock(mutex_);
-    auto itr = available_resources_.begin();
-    if (itr == available_resources_.end()) {
-      return std::nullopt;
-    }
-    Reservation r(*this, *(RemoveFromPool(itr)));
-    return {std::move(r)};
-  }
-
-  // gives n unique integers from the pool, and then remove them from the pool
-  std::optional<ReservationSet> UniqueItems(const int n) {
-    std::lock_guard<std::mutex> lock(mutex_);
-    if (n <= 0 || available_resources_.size() < n) {
-      return std::nullopt;
-    }
-    ReservationSet result;
-    for (int i = 0; i < n; i++) {
-      auto itr = available_resources_.begin();
-      result.insert(Reservation{*this, *(RemoveFromPool(itr))});
-    }
-    return {std::move(result)};
-  }
-
-  template <typename V = T>
-  std::enable_if_t<std::is_integral<V>::value, std::optional<ReservationSet>>
-  UniqueConsecutiveItems(const std::size_t n) {
-    static_assert(std::is_same<T, V>::value);
-    std::lock_guard<std::mutex> lock(mutex_);
-    if (n <= 0 || available_resources_.size() < n) {
-      return std::nullopt;
-    }
-
-    for (const auto& available_resource : available_resources_) {
-      auto start_inclusive = available_resource;
-      auto resources_opt =
-          TakeRangeInternal(start_inclusive, start_inclusive + n);
-      if (!resources_opt) {
-        continue;
-      }
-      return resources_opt;
-    }
-    return std::nullopt;
-  }
-
-  // takes t if available
-  // returns false if not available or not in the pool at all
-  std::optional<Reservation> Take(const T& t) {
-    std::lock_guard<std::mutex> lock(mutex_);
-    auto itr = available_resources_.find(t);
-    if (itr == available_resources_.end()) {
-      return std::nullopt;
-    }
-    Reservation resource{*this, *(RemoveFromPool(itr))};
-    return resource;
-  }
-
-  template <typename Container>
-  std::optional<ReservationSet> TakeAll(const Container& ts) {
-    std::lock_guard<std::mutex> lock(mutex_);
-    for (const auto& t : ts) {
-      if (!Contains(available_resources_, t)) {
-        return std::nullopt;
-      }
-    }
-    ReservationSet resources;
-    for (const auto& t : ts) {
-      auto itr = available_resources_.find(t);
-      resources.insert(Reservation{*this, *(RemoveFromPool(itr))});
-    }
-    return resources;
-  }
-
-  /*
-   * If the range is available, returns the resources from the pool
-   *
-   * Otherwise, makes no change in the internal data structure but
-   * returns false.
-   */
-  template <typename V = T>
-  std::enable_if_t<std::is_integral<V>::value, std::optional<ReservationSet>>
-  TakeRange(const T& start_inclusive, const T& end_exclusive) {
-    static_assert(std::is_same<T, V>::value);
-    std::lock_guard<std::mutex> lock(mutex_);
-    return TakeRangeInternal(start_inclusive, end_exclusive);
-  }
-
- private:
-  template <typename Container>
-  UniqueResourceAllocator(const Container& items)
-      : available_resources_{items.cbegin(), items.cend()} {}
-
-  bool operator==(const UniqueResourceAllocator& other) const {
-    return std::addressof(*this) == std::addressof(other);
-  }
-
-  // only called by the destructor of Reservation
-  // harder to use Result as this is called by destructors only
-  void Reclaim(const T& t) {
-    std::lock_guard<std::mutex> lock(mutex_);
-    auto itr = allocated_resources_.find(t);
-    if (itr == allocated_resources_.end()) {
-      if (!Contains(available_resources_, t)) {
-        LOG(ERROR) << "The resource " << t << " does not belong to this pool";
-        return;
-      }
-      // already reclaimed.
-      return;
-    }
-    T tmp = std::move(*itr);
-    allocated_resources_.erase(itr);
-    available_resources_.insert(std::move(tmp));
-  }
-
-  /*
-   * If the range is available, returns the resources from the pool
-   *
-   * Otherwise, makes no change in the internal data structure but
-   * returns false.
-   */
-  template <typename V = T>
-  std::enable_if_t<std::is_integral<V>::value, std::optional<ReservationSet>>
-  TakeRangeInternal(const T& start_inclusive, const T& end_exclusive) {
-    static_assert(std::is_same<T, V>::value);
-    for (auto cursor = start_inclusive; cursor < end_exclusive; cursor++) {
-      if (!Contains(available_resources_, cursor)) {
-        return std::nullopt;
-      }
-    }
-    ReservationSet resources;
-    for (auto cursor = start_inclusive; cursor < end_exclusive; cursor++) {
-      auto itr = available_resources_.find(cursor);
-      resources.insert(Reservation{*this, *(RemoveFromPool(itr))});
-    }
-    return resources;
-  }
-
-  /*
-   * Moves *itr from available_resources_ to allocated_resources_, and returns
-   * the pointer of the object in the allocated_resources_. The pointer is never
-   * nullptr as it is std::addressof(an object in the unordered_set buffer).
-   *
-   * The itr must belong to available_resources_.
-   */
-  const T* RemoveFromPool(const typename std::unordered_set<T>::iterator itr) {
-    T tmp = std::move(*itr);
-    available_resources_.erase(itr);
-    const auto [new_itr, _] = allocated_resources_.insert(std::move(tmp));
-    return std::addressof(*new_itr);
-  }
-  std::unordered_set<T> available_resources_;
-  std::unordered_set<T> allocated_resources_;
-  std::mutex mutex_;
-};
-
-}  // namespace cuttlefish
diff --git a/common/libs/utils/unique_resource_allocator_test.cpp b/common/libs/utils/unique_resource_allocator_test.cpp
deleted file mode 100644
index 88ab2a935..000000000
--- a/common/libs/utils/unique_resource_allocator_test.cpp
+++ /dev/null
@@ -1,202 +0,0 @@
-//
-// Copyright (C) 2022 The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//      http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include <unordered_set>
-#include <vector>
-
-#include "common/libs/utils/contains.h"
-#include "common/libs/utils/unique_resource_allocator.h"
-#include "common/libs/utils/unique_resource_allocator_test.h"
-
-namespace cuttlefish {
-
-TEST_P(OneEachTest, GetAnyAvailableOne) {
-  const auto resources = GetParam();
-  auto allocator = UniqueResourceAllocator<unsigned>::New(resources);
-  if (!allocator) {
-    GTEST_SKIP() << "Memory allocation failed but we aren't testing it.";
-  }
-  std::unordered_set<unsigned> expected_ids{resources.cbegin(),
-                                            resources.cend()};
-  using Reservation = UniqueResourceAllocator<unsigned>::Reservation;
-
-  std::vector<Reservation> allocated;
-  for (int i = 0; i < resources.size(); i++) {
-    auto id_opt = allocator->UniqueItem();
-    ASSERT_TRUE(id_opt);
-    ASSERT_TRUE(Contains(expected_ids, id_opt->Get()));
-    allocated.emplace_back(std::move(*id_opt));
-  }
-  ASSERT_FALSE(allocator->UniqueItem());
-}
-
-INSTANTIATE_TEST_SUITE_P(
-    CvdIdAllocator, OneEachTest,
-    testing::Values(std::vector<unsigned>{}, std::vector<unsigned>{1},
-                    std::vector<unsigned>{1, 22, 3, 43, 5}));
-
-TEST_F(CvdIdAllocatorTest, ClaimAll) {
-  std::vector<unsigned> inputs{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
-  auto allocator = UniqueResourceAllocator<unsigned>::New(inputs);
-  if (!allocator) {
-    GTEST_SKIP() << "Memory allocation failed but we aren't testing it.";
-  }
-
-  // request inputs.size() items
-  auto allocated_items_opt = allocator->UniqueItems(inputs.size());
-  ASSERT_TRUE(allocated_items_opt);
-  ASSERT_EQ(allocated_items_opt->size(), inputs.size());
-  // did it claim all?
-  ASSERT_FALSE(allocator->UniqueItem());
-}
-
-TEST_F(CvdIdAllocatorTest, StrideBeyond) {
-  std::vector<unsigned> inputs{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
-  auto allocator = UniqueResourceAllocator<unsigned>::New(inputs);
-  if (!allocator) {
-    GTEST_SKIP() << "Memory allocation failed but we aren't testing it.";
-  }
-
-  auto three_opt = allocator->UniqueItems(3);
-  auto four_opt = allocator->UniqueItems(4);
-  auto five_opt = allocator->UniqueItems(5);
-  auto two_opt = allocator->UniqueItems(2);
-  auto another_two_opt = allocator->UniqueItems(2);
-
-  ASSERT_TRUE(three_opt);
-  ASSERT_TRUE(four_opt);
-  ASSERT_FALSE(five_opt);
-  ASSERT_TRUE(two_opt);
-  ASSERT_FALSE(another_two_opt);
-}
-
-TEST_F(CvdIdAllocatorTest, Consecutive) {
-  std::vector<unsigned> inputs{1, 2, 4, 5, 6, 7, 9, 10, 11};
-  auto allocator = UniqueResourceAllocator<unsigned>::New(inputs);
-  if (!allocator) {
-    GTEST_SKIP() << "Memory allocation failed but we aren't testing it.";
-  }
-
-  auto four_consecutive = allocator->UniqueConsecutiveItems(4);
-  auto three_consecutive = allocator->UniqueConsecutiveItems(3);
-  auto another_three_consecutive = allocator->UniqueConsecutiveItems(3);
-  auto two_consecutive = allocator->UniqueConsecutiveItems(2);
-
-  ASSERT_TRUE(four_consecutive);
-  ASSERT_TRUE(three_consecutive);
-  ASSERT_FALSE(another_three_consecutive);
-  ASSERT_TRUE(two_consecutive);
-  // it's empty
-  ASSERT_FALSE(allocator->UniqueItem()) << "one or more left";
-}
-
-TEST_F(CvdIdAllocatorTest, Take) {
-  std::vector<unsigned> inputs{4, 5, 9};
-  auto allocator = UniqueResourceAllocator<unsigned>::New(inputs);
-  if (!allocator) {
-    GTEST_SKIP() << "Memory allocation failed but we aren't testing it.";
-  }
-
-  auto four = allocator->Take(4);
-  auto nine = allocator->Take(9);
-  // wrong
-  auto twenty = allocator->Take(20);
-
-  ASSERT_TRUE(four);
-  ASSERT_TRUE(nine);
-  ASSERT_FALSE(twenty);
-}
-
-TEST_F(CvdIdAllocatorTest, TakeAll) {
-  std::vector<unsigned> inputs{4, 5, 9, 10};
-  auto allocator = UniqueResourceAllocator<unsigned>::New(inputs);
-  if (!allocator) {
-    GTEST_SKIP() << "Memory allocation failed but we aren't testing it.";
-  }
-
-  auto take_4_5_11 = allocator->TakeAll<std::vector<unsigned>>({4, 5, 11});
-  auto take_4_5_10 = allocator->TakeAll<std::vector<unsigned>>({4, 5, 10});
-  auto take_9_10 = allocator->TakeAll<std::vector<unsigned>>({9, 10});
-  auto take_9 = allocator->TakeAll<std::vector<unsigned>>({9});
-
-  ASSERT_FALSE(take_4_5_11);
-  ASSERT_TRUE(take_4_5_10);
-  ASSERT_FALSE(take_9_10);
-  ASSERT_TRUE(take_9);
-}
-
-TEST_F(CvdIdAllocatorTest, TakeRange) {
-  std::vector<unsigned> inputs{1, 2, 4, 5, 6, 7, 8, 9, 10, 11};
-  auto allocator = UniqueResourceAllocator<unsigned>::New(inputs);
-  if (!allocator) {
-    GTEST_SKIP() << "Memory allocation failed but we aren't testing it.";
-  }
-
-  auto take_range_5_12 = allocator->TakeRange(5, 12);
-  // shall fail as 3 is missing
-  auto take_range_2_4 = allocator->TakeRange(2, 4);
-
-  ASSERT_TRUE(take_range_5_12);
-  ASSERT_FALSE(take_range_2_4);
-}
-
-TEST_F(CvdIdAllocatorTest, Reclaim) {
-  std::vector<unsigned> inputs{1, 2, 4, 5, 6, 7, 8, 9, 10, 11};
-  auto allocator = UniqueResourceAllocator<unsigned>::New(inputs);
-  if (!allocator) {
-    GTEST_SKIP() << "Memory allocation failed but we aren't testing it.";
-  }
-  unsigned one_resource = 0;
-  {
-    auto take_range_5_12 = allocator->TakeRange(5, 12);
-    auto any_single_item = allocator->UniqueItem();
-
-    ASSERT_TRUE(take_range_5_12);
-    ASSERT_TRUE(any_single_item);
-    one_resource = any_single_item->Get();
-
-    ASSERT_FALSE(allocator->TakeRange(5, 12));
-    ASSERT_FALSE(allocator->Take(one_resource));
-  }
-  // take_range_5_12 went out of scope, so resources were reclaimed
-  ASSERT_TRUE(allocator->TakeRange(5, 12));
-  ASSERT_TRUE(allocator->Take(one_resource));
-}
-
-TEST(CvdIdAllocatorExpandTest, Expand) {
-  std::vector<unsigned> inputs{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
-  auto allocator = UniqueResourceAllocator<unsigned>::New(inputs);
-  if (!allocator) {
-    GTEST_SKIP() << "Memory allocation failed but we aren't testing it.";
-  }
-  auto hold_6_to_10 = allocator->TakeRange(6, 11);
-  if (!hold_6_to_10) {
-    GTEST_SKIP() << "TakeRange(6, 11) failed but it's not what is tested here";
-  }
-
-  auto expand =
-      allocator->ExpandPool(std::vector<unsigned>{2, 4, 6, 8, 12, 14});
-  auto take_12 = allocator->Take(12);
-  auto take_14 = allocator->Take(14);
-  auto take_6 = allocator->Take(6);
-
-  std::vector<unsigned> expected_return_from_expand{2, 4, 6, 8};
-  ASSERT_EQ(expand, expected_return_from_expand);
-  ASSERT_TRUE(take_12);
-  ASSERT_TRUE(take_14);
-  ASSERT_FALSE(take_6);
-}
-
-}  // namespace cuttlefish
diff --git a/common/libs/utils/vsock_connection.cpp b/common/libs/utils/vsock_connection.cpp
index 310869c3a..cb573515d 100644
--- a/common/libs/utils/vsock_connection.cpp
+++ b/common/libs/utils/vsock_connection.cpp
@@ -67,6 +67,10 @@ void VsockConnection::SetDisconnectCallback(std::function<void()> callback) {
   disconnect_callback_ = callback;
 }
 
+// This method created due to a race condition in IsConnected().
+// TODO(b/345285391): remove this method once a fix found
+bool VsockConnection::IsConnected_Unguarded() { return fd_->IsOpen(); }
+
 bool VsockConnection::IsConnected() {
   // We need to serialize all accesses to the SharedFD.
   std::lock_guard<std::recursive_mutex> read_lock(read_mutex_);
diff --git a/common/libs/utils/vsock_connection.h b/common/libs/utils/vsock_connection.h
index 29e2c93bc..905253d14 100644
--- a/common/libs/utils/vsock_connection.h
+++ b/common/libs/utils/vsock_connection.h
@@ -39,6 +39,7 @@ class VsockConnection {
                                  std::optional<int> vhost_user_vsock_cid);
   void SetDisconnectCallback(std::function<void()> callback);
 
+  bool IsConnected_Unguarded();
   bool IsConnected();
   bool DataAvailable();
   int32_t Read();
diff --git a/guest/commands/v4l2_streamer/Android.bp b/guest/commands/v4l2_streamer/Android.bp
new file mode 100644
index 000000000..02cab5675
--- /dev/null
+++ b/guest/commands/v4l2_streamer/Android.bp
@@ -0,0 +1,42 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_binary {
+    name: "cuttlefish_v4l2_streamer",
+    srcs: [
+        "main.cpp",
+        "v4l2_helpers.cpp",
+        "yuv2rgb.cpp",
+        "vsock_frame_source.cpp",
+    ],
+    shared_libs: [
+        "libbase",
+        "libbinder_ndk",
+        "liblog",
+        "libutils",
+        "libvsock_utils",
+        "libjsoncpp",
+        "libcuttlefish_fs",
+    ],
+    static_libs: [
+        "libgflags",
+        "libcuttlefish_utils",
+    ],
+    defaults: ["cuttlefish_guest_only"],
+}
diff --git a/guest/commands/v4l2_streamer/main.cpp b/guest/commands/v4l2_streamer/main.cpp
new file mode 100644
index 000000000..219ebd045
--- /dev/null
+++ b/guest/commands/v4l2_streamer/main.cpp
@@ -0,0 +1,52 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <stdio.h>
+
+#include <android-base/logging.h>
+#include <gflags/gflags.h>
+
+#include "guest/commands/v4l2_streamer/vsock_frame_source.h"
+
+DEFINE_bool(service_mode, false,
+            "true to log output to Logd, false for stderr");
+
+int main(int argc, char **argv) {
+  google::ParseCommandLineFlags(&argc, &argv, true);
+
+  if (FLAGS_service_mode) {
+    ::android::base::InitLogging(
+        argv, android::base::LogdLogger(android::base::SYSTEM));
+  } else {
+    ::android::base::InitLogging(argv, android::base::StderrLogger);
+  }
+
+  android::base::SetDefaultTag("cuttlefish_v4l2_streamer");
+
+  LOG(INFO) << "streamer starting...  ";
+
+  auto vfs = cuttlefish::VsockFrameSource::Start("/dev/video0");
+
+  if (vfs.ok()) {
+    LOG(INFO) << "streamer initialized, streaming in progress...";
+
+    vfs->get()->VsockReadLoop();
+
+    LOG(INFO) << "streamer terminated.";
+  } else {
+    LOG(FATAL) << "start failed.";
+  }
+}
\ No newline at end of file
diff --git a/guest/commands/v4l2_streamer/v4l2_helpers.cpp b/guest/commands/v4l2_streamer/v4l2_helpers.cpp
new file mode 100644
index 000000000..3472cf023
--- /dev/null
+++ b/guest/commands/v4l2_streamer/v4l2_helpers.cpp
@@ -0,0 +1,184 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "v4l2_helpers.h"
+
+#include <fcntl.h>
+#include <linux/videodev2.h>
+#include <log/log.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <sys/ioctl.h>
+#include <unistd.h>
+
+namespace cuttlefish {
+
+Result<size_t> V4l2GetBpp(int format) {
+  CF_EXPECT(format == V4L2_PIX_FMT_BGRX32,
+            "Error: v4l2_get_bpp; only V4L2_PIX_FMT_BGRX32 supported");
+  return 4;
+}
+
+Result<size_t> V4l2GetFrameSize(int format, int width, int height) {
+  size_t bytes_per_pixel =
+      CF_EXPECT(V4l2GetBpp(format), "Error: invalid bpp format");
+
+  return width * height * bytes_per_pixel;
+}
+
+Result<size_t> V4l2GetLineWidth(int format, int width) {
+  size_t bytes_per_pixel =
+      CF_EXPECT(V4l2GetBpp(format), "Error: invalid bpp format");
+
+  return width * bytes_per_pixel;
+}
+
+void V4l2PrintFormat(struct v4l2_format* vid_format) {
+  ALOGI("	vid_format->type                =%d", vid_format->type);
+  ALOGI("	vid_format->fmt.pix.width       =%d",
+        vid_format->fmt.pix.width);
+  ALOGI("	vid_format->fmt.pix.height      =%d",
+        vid_format->fmt.pix.height);
+  ALOGI("	vid_format->fmt.pix.pixelformat =%d",
+        vid_format->fmt.pix.pixelformat);
+  ALOGI("	vid_format->fmt.pix.sizeimage   =%d",
+        vid_format->fmt.pix.sizeimage);
+  ALOGI("	vid_format->fmt.pix.field       =%d",
+        vid_format->fmt.pix.field);
+  ALOGI("	vid_format->fmt.pix.bytesperline=%d",
+        vid_format->fmt.pix.bytesperline);
+  ALOGI("	vid_format->fmt.pix.colorspace  =%d",
+        vid_format->fmt.pix.colorspace);
+}
+
+Result<std::vector<char>> V4l2ReadRawFile(const std::string& filename) {
+  std::streampos filepos = 0;
+  std::ifstream file(filename, std::ios::binary);
+
+  filepos = file.tellg();
+  file.seekg(0, std::ios::end);
+  long buffersize = file.tellg() - filepos;
+  file.seekg(0, std::ios::beg);
+
+  std::vector<char> buffer;
+  buffer.resize(buffersize);
+
+  file.read(buffer.data(), buffersize);
+
+  CF_EXPECT_NE(file.fail(), 0,
+               "Error reading Raw file buffer: " << strerror(errno));
+
+  ALOGI("Allocated and read %ld bytes", buffersize);
+
+  return buffer;
+}
+
+Result<SharedFD> V4l2InitDevice(const std::string& device_path, int format,
+                                int width, int height) {
+  int framesize = CF_EXPECT(V4l2GetFrameSize(format, width, height),
+                            "Error calculating frame size");
+  int linewidth =
+      CF_EXPECT(V4l2GetLineWidth(format, width), "Error calculating linewidth");
+
+  SharedFD fdwr = SharedFD::Open(device_path, O_RDWR);
+
+  CF_EXPECT(fdwr->IsOpen(), "Error: Could not open v4l2 device for O_RDWR: "
+                                << fdwr->StrError());
+
+  struct v4l2_capability vid_caps;
+  int ret_code = fdwr->Ioctl(VIDIOC_QUERYCAP, &vid_caps);
+
+  CF_EXPECT_NE(ret_code, -1,
+               "Error: VIDIOC_QUERYCAP failed: " << fdwr->StrError());
+
+  struct v4l2_format vid_format = v4l2_format{};
+
+  V4l2PrintFormat(&vid_format);
+
+  vid_format.type = V4L2_BUF_TYPE_VIDEO_OUTPUT;
+  vid_format.fmt.pix.width = width;
+  vid_format.fmt.pix.height = height;
+  vid_format.fmt.pix.pixelformat = format;
+  vid_format.fmt.pix.sizeimage = framesize;
+  vid_format.fmt.pix.field = V4L2_FIELD_NONE;
+  vid_format.fmt.pix.bytesperline = linewidth;
+  vid_format.fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;
+
+  V4l2PrintFormat(&vid_format);
+
+  ret_code = fdwr->Ioctl(VIDIOC_S_FMT, &vid_format);
+
+  CF_EXPECT_NE(ret_code, -1,
+               "Error: VIDIOC_S_FMT failed: " << fdwr->StrError());
+
+  ALOGI("frame: format=%d\tsize=%d", format, framesize);
+  V4l2PrintFormat(&vid_format);
+
+  return fdwr;
+}
+
+// This is a testing / debugging method. Only used optionally for
+// troubleshooting a v4l2 by dumping raw movie frames direct to the device. It
+// avoids using the network for simplifying the debug process.   It also shows
+// how to use the API methods provided in this file.
+Result<void> V4l2StreamFile(const std::string& device_path,
+                            const std::string& raw_movie_file) {
+  int width = 640;
+  int height = 480;
+  int format = V4L2_PIX_FMT_BGRX32;
+  int framesize = CF_EXPECT(V4l2GetFrameSize(format, width, height),
+                            "Error getting frame size");
+
+  ALOGI("Starting.... using framesize(%d)", framesize);
+
+  std::vector<char> buffer =
+      CF_EXPECT(V4l2ReadRawFile(raw_movie_file), "Error reading buffer");
+
+  ALOGI("Beginning frame push with buffersize(%ld)", buffer.size());
+
+  SharedFD fdwr = CF_EXPECT(V4l2InitDevice(device_path, format, width, height),
+                            "Error initializing device");
+
+  CF_EXPECT(fdwr->IsOpen(), "Error: initdevice == 0");
+
+  ALOGI("Device initialized(%s)", device_path.c_str());
+
+  ALOGI("Beginning stream:");
+
+  CF_EXPECT(buffer.size() > framesize, "Error: invalid buffer size");
+
+  for (long i = 0; i < buffer.size() - framesize; i += framesize) {
+    ALOGI("Beginning frame:");
+    if (fdwr->Write(((char*)buffer.data()) + i, framesize) == -1) {
+      ALOGE("Error writing buffer data: %s", fdwr->StrError().c_str());
+    }
+    sleep(1);
+    if (i % 20 == 0) {
+      ALOGI("Wrote %ld frames", ((i + framesize) / framesize));
+    }
+  }
+
+  ALOGI("ended stream:");
+
+  fdwr->Close();
+
+  ALOGI("Streaming complete.");
+
+  return {};
+}
+
+}  // End namespace cuttlefish
\ No newline at end of file
diff --git a/guest/commands/v4l2_streamer/v4l2_helpers.h b/guest/commands/v4l2_streamer/v4l2_helpers.h
new file mode 100644
index 000000000..14deca556
--- /dev/null
+++ b/guest/commands/v4l2_streamer/v4l2_helpers.h
@@ -0,0 +1,55 @@
+
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <linux/videodev2.h>
+#include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/result.h"
+
+namespace cuttlefish {
+
+// Opens a v4l2 device, located at given [device_path]. The device is then
+// configured to receive frames of the given format, width, and height. Note
+// that only format V4L2_PIX_FMT_BGRX32 is supported at this time
+Result<SharedFD> V4l2InitDevice(const std::string& device_path, int format,
+                                int width, int height);
+
+// Returns # of bytes per pixel of given format, for
+// frame size calculations
+// Note that only format V4L2_PIX_FMT_BGRX32 is supported at this time
+Result<size_t> V4l2GetBPP(int format);
+
+// Returns size in bytes of single frame of given v4l2 format
+// Note that only format V4L2_PIX_FMT_BGRX32 is supported at this time
+Result<size_t> V4l2GetFrameSize(int format, int width, int height);
+
+// Returns size in bytes of a single line data in video fram image
+// Note that only format V4L2_PIX_FMT_BGRX32 is supported at this time
+Result<size_t> V4l2GetLineWidth(int format, int width);
+
+// Dump to logger debug info of the given v4l2_format
+void V4l2PrintFormat(struct v4l2_format* vid_format);
+
+// The following two optional methods are used for debugging / testing v4l2
+// devices, not by the runtime streamer.
+Result<void> V4l2StreamFile();
+
+// Reads a file containing raw frames in BGRA32 format.
+Result<std::vector<char>> V4l2ReadRawFile(const std::string& filename);
+
+}  // End namespace cuttlefish
\ No newline at end of file
diff --git a/guest/commands/v4l2_streamer/vsock_frame_source.cpp b/guest/commands/v4l2_streamer/vsock_frame_source.cpp
new file mode 100644
index 000000000..89c5c7aa3
--- /dev/null
+++ b/guest/commands/v4l2_streamer/vsock_frame_source.cpp
@@ -0,0 +1,177 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <assert.h>
+#include <fcntl.h>
+#include <log/log.h>
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <sys/ioctl.h>
+#include <unistd.h>
+
+#include "guest/commands/v4l2_streamer/v4l2_helpers.h"
+#include "guest/commands/v4l2_streamer/vsock_frame_source.h"
+#include "guest/commands/v4l2_streamer/yuv2rgb.h"
+
+namespace cuttlefish {
+
+VsockFrameSource::~VsockFrameSource() { Stop(); }
+
+bool VsockFrameSource::IsBlob(const std::vector<char>& blob) {
+  static const char kPng[] = "\x89PNG";
+  static const char kJpeg[] = "\xff\xd8";
+  bool is_png =
+      blob.size() > 4 && std::memcmp(blob.data(), kPng, sizeof(kPng)) == 0;
+  bool is_jpeg =
+      blob.size() > 2 && std::memcmp(blob.data(), kJpeg, sizeof(kJpeg)) == 0;
+  return is_png || is_jpeg;
+}
+
+bool VsockFrameSource::WriteJsonEventMessage(const std::string& message) {
+  Json::Value json_message;
+  json_message["event"] = message;
+  return connection_ && connection_->WriteMessage(json_message);
+}
+
+Result<bool> VsockFrameSource::ReadSettingsFromJson(const Json::Value& json) {
+  frame_width_ = json["width"].asInt();
+  frame_height_ = json["height"].asInt();
+  frame_rate_ = json["frame_rate"].asDouble();
+
+  if (frame_width_ > 0 && frame_height_ > 0 && frame_rate_ > 0) {
+    frame_size_ =
+        CF_EXPECT(V4l2GetFrameSize(format_, frame_width_, frame_height_),
+                  "Error getting framesize");
+    ALOGI("%s: readSettingsFromJson received: w/h/fps(%d,%d,%d)", __FUNCTION__,
+          frame_width_, frame_height_, frame_rate_);
+    return true;
+  } else {
+    ALOGE("%s: readSettingsFromJson received invalid values: w/h/fps(%d,%d,%d)",
+          __FUNCTION__, frame_width_, frame_height_, frame_rate_);
+    return false;
+  }
+}
+
+bool VsockFrameSource::Connect() {
+  connection_ = std::make_unique<
+      cuttlefish::VsockServerConnection>();  // VsockServerConnection
+  if (connection_->Connect(
+          7600, VMADDR_CID_ANY,
+          std::nullopt /* vhost_user_vsock: because it's guest */)) {
+    auto json_settings = connection_->ReadJsonMessage();
+
+    if (ReadSettingsFromJson(json_settings)) {
+      std::lock_guard<std::mutex> lock(settings_mutex_);
+      ALOGI("%s: VsockFrameSource connected", __FUNCTION__);
+      return true;
+    } else {
+      ALOGE("%s: Could not read settings", __FUNCTION__);
+    }
+  } else {
+    ALOGE("%s: VsockFrameSource connection failed", __FUNCTION__);
+  }
+  return false;
+}
+
+Result<std::unique_ptr<VsockFrameSource>> VsockFrameSource::Start(
+    const std::string& v4l2_device_path) {
+  auto frame_source = std::unique_ptr<VsockFrameSource>(new VsockFrameSource);
+
+  frame_source->v4l2_device_path_ = v4l2_device_path;
+
+  CF_EXPECT(frame_source->Connect(), "connect failed");
+
+  ALOGI("%s: VsockFrameSource connected", __FUNCTION__);
+
+  frame_source->running_ = true;
+
+  frame_source->WriteJsonEventMessage("VIRTUAL_DEVICE_START_CAMERA_SESSION");
+
+  frame_source->fd_v4l2_device_ = CF_EXPECT(
+      V4l2InitDevice(frame_source->v4l2_device_path_, frame_source->format_,
+                     frame_source->frame_width_, frame_source->frame_height_),
+      "Error opening v4l2 device");
+
+  CF_EXPECT(frame_source->fd_v4l2_device_->IsOpen(),
+            "Error: fd_v4l2_device_->IsOpen() failed");
+
+  ALOGI("%s: successful v4l2 device open.", __FUNCTION__);
+
+  return frame_source;
+}
+
+void VsockFrameSource::Stop() {
+  if (running_.exchange(false)) {
+    if (reader_thread_.joinable()) {
+      reader_thread_.join();
+    }
+    WriteJsonEventMessage("VIRTUAL_DEVICE_STOP_CAMERA_SESSION");
+    connection_ = nullptr;
+    fd_v4l2_device_->Close();
+  }
+}
+
+void VsockFrameSource::WriteFrame(const std::vector<char>& frame,
+                                  std::vector<char>& rgb_frame) {
+  if (rgb_frame.size() != frame_size_) {
+    rgb_frame.resize(frame_size_);
+  }
+  Yuv2Rgb((unsigned char*)frame.data(), (unsigned char*)rgb_frame.data(),
+          frame_width_, frame_height_);
+  fd_v4l2_device_->Write((unsigned char*)rgb_frame.data(), frame_size_);
+}
+
+bool VsockFrameSource::Running() { return running_; }
+
+bool VsockFrameSource::FramesizeMatches(const std::vector<char>& data) {
+  return data.size() == 3 * frame_width_ * frame_height_ / 2;
+}
+
+Result<void> VsockFrameSource::VsockReadLoopThreaded() {
+  CF_EXPECT(fd_v4l2_device_->IsOpen(), "Error: v4l2_initdevice == 0");
+
+  reader_thread_ = std::thread([this] { VsockReadLoop(); });
+
+  return {};
+}
+
+void VsockFrameSource::VsockReadLoop() {
+  std::vector<char> frame;
+  std::vector<char> next_frame;
+  std::vector<char> rgb_frame;
+
+  while (running_.load() && connection_->ReadMessage(next_frame)) {
+    if (FramesizeMatches(next_frame)) {
+      std::lock_guard<std::mutex> lock(frame_mutex_);
+      timestamp_ = systemTime();
+      frame.swap(next_frame);
+      yuv_frame_updated_.notify_one();
+      WriteFrame(frame, rgb_frame);
+    } else if (IsBlob(next_frame)) {
+    }  // TODO
+    else {
+      ALOGE("%s: Unexpected data of %zu bytes", __FUNCTION__,
+            next_frame.size());
+    }
+  }
+  if (!connection_->IsConnected_Unguarded()) {
+    ALOGE("%s: Connection closed - exiting", __FUNCTION__);
+    running_ = false;
+  }
+}
+
+}  // End namespace cuttlefish
\ No newline at end of file
diff --git a/guest/commands/v4l2_streamer/vsock_frame_source.h b/guest/commands/v4l2_streamer/vsock_frame_source.h
new file mode 100644
index 000000000..a9834104e
--- /dev/null
+++ b/guest/commands/v4l2_streamer/vsock_frame_source.h
@@ -0,0 +1,111 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <linux/videodev2.h>
+#include <iostream>
+#include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/result.h"
+#include "utils/Timers.h"
+#include "vsock_connection.h"
+
+namespace cuttlefish {
+
+// VsockFrameSource accepts WebRTC YUV camera stream data
+// over vsock, converts it to v4l2 format BGRX32, and then
+// writes the result to a v4l2 device.  This allows for creation
+// of v4l2 devices in guest VMs, and streaming to them
+// from Cuttlefish's WebRTC UI via any connected camera.
+class VsockFrameSource {
+ public:
+  // Starts a Frame Source streaming session targeting a
+  // specific v4l2 device
+  static Result<std::unique_ptr<VsockFrameSource>> Start(
+      const std::string& v4l2_device_path);
+
+  ~VsockFrameSource();
+
+  // Stops a thread managing the stream if running, and closes the v4l2 device.
+  void Stop();
+
+  // Returns true if there is a camera stream currently running
+  bool Running();
+
+  // This is a blocking method, that runs while connection is valid.
+  // It receives frames from a vsock socket, formats the data stream and
+  // sends it to a v4l2 output device.
+  void VsockReadLoop();
+
+  // Starts a Thread which invokes VsockReadLoop(). This allows the calling
+  // thread to perform other operations while this frame source is sending data.
+  Result<void> VsockReadLoopThreaded();
+
+ private:
+  // The v4l2 device path to receive camera frames, ie /dev/video0
+  std::string v4l2_device_path_;
+  std::unique_ptr<cuttlefish::VsockConnection> connection_;
+  std::thread reader_thread_;
+  std::atomic<bool> running_;
+  std::mutex frame_mutex_;
+  std::mutex settings_mutex_;
+  std::atomic<nsecs_t> timestamp_;
+  std::condition_variable yuv_frame_updated_;
+
+  // File handle of v4l2 device to be written to
+  SharedFD fd_v4l2_device_;
+
+  // Following frame_* values will be set after successful connection.
+  // Host process sends a message which conveys the camera dimensions
+  // to this guest instance over the vsock connection.
+  int frame_width_ = 0;
+  int frame_height_ = 0;
+  int frame_rate_ = 0;
+  int frame_size_ = 0;
+
+  // Currently this class only supports writing to v4l2 devices
+  // via this format.
+  int format_ = V4L2_PIX_FMT_BGRX32;
+
+  // Verifies that given data is a video frame. Used to
+  // distinguish control messages.
+  bool FramesizeMatches(const std::vector<char>& data);
+
+  // Determines if a vsock packet contains special data
+  // that is not camera frame.
+  bool IsBlob(const std::vector<char>& blob);
+
+  // Sends message to Host process communicating an event in the
+  // camera connection state. ie - when to start or stop streaming.
+  bool WriteJsonEventMessage(const std::string& message);
+
+  // After connect, this is called to retrieve camera dimensions
+  // and properties needed to initialize the v4l2 device and allocate
+  // buffers necessary for streaming.
+  Result<bool> ReadSettingsFromJson(const Json::Value& json);
+
+  // Established the vsock connection
+  bool Connect();
+
+  // Called once every frame to write a frame buffer to the v4l2
+  // output device.
+  void WriteFrame(const std::vector<char>& frame, std::vector<char>& rgb_frame);
+
+ protected:
+  VsockFrameSource() = default;
+};
+
+}  // End namespace cuttlefish
\ No newline at end of file
diff --git a/guest/commands/v4l2_streamer/yuv2rgb.cpp b/guest/commands/v4l2_streamer/yuv2rgb.cpp
new file mode 100644
index 000000000..1a21cd7ca
--- /dev/null
+++ b/guest/commands/v4l2_streamer/yuv2rgb.cpp
@@ -0,0 +1,90 @@
+
+/*
+ * Copyright 2018 Google LLC. All rights reserved.
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License"); you may not
+ * use this file except in compliance with the License. You may obtain a copy of
+ * the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
+ * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
+ * License for the specific language governing permissions and limitations under
+ * the License.
+ */
+
+// This file contains an adaptation of the algorithm at:
+// https://github.com/GoogleChromeLabs/wasm-av1/blob/master/yuv-to-rgb.c
+
+// The algorithm here creates precomputed lookup tables to speed up converting
+// YUV frames to RGB. Since it is done once every camera frame it needs to be
+// efficient.
+//
+// NOTE: This is code is being used temporarily until Cuttlefish supports
+// hardware-accelerated camera frame transfer from host to guest.  Ideally the
+// conversions will be done via DMA or GPU algorithms, not via CPU copy
+
+// Number of luminance values to precompute tables of for speed. Value is higher
+// than 255 as to allow for future color depth expansion
+#define ZOF_TAB 65536
+
+// Size of single output pixel in bytes (RGBA x 1 byte each = 4 bytes)
+#define ZOF_RGB 4
+
+namespace cuttlefish {
+
+// These tables will store precomputes values
+static int T1[ZOF_TAB], T2[ZOF_TAB], T3[ZOF_TAB], T4[ZOF_TAB];
+static int tables_initialized;
+
+// Called once to initialize tables
+static void build_yuv2rgb_tables() {
+  for (int i = 0; i < ZOF_TAB; i++) {
+    T1[i] = (int)(1.370705 * (float)(i - 128));
+    T2[i] = (int)(-0.698001 * (float)(i - 128));
+    T3[i] = (int)(-0.337633 * (float)(i - 128));
+    T4[i] = (int)(1.732446 * (float)(i - 128));
+  }
+}
+
+#define clamp(val) ((val) < 0 ? 0 : (255 < (val) ? 255 : (val)))
+
+void Yuv2Rgb(unsigned char *src, unsigned char *dst, int width, int height) {
+  if (tables_initialized == 0) {
+    tables_initialized = !0;
+    build_yuv2rgb_tables();
+  }
+  // Setup pointers to the Y, U, V planes
+  unsigned char *y = src;
+  unsigned char *u = src + (width * height);
+  unsigned char *v =
+      u + (width * height) / 4;  // Each chroma does 4 pixels in 4:2:0
+  // Loop the image, taking into account sub-sample for the chroma channels
+  for (int h = 0; h < height; h++) {
+    unsigned char *uline = u;
+    unsigned char *vline = v;
+    for (int w = 0; w < width; w++, y++) {
+      int r = *y + T1[*vline];
+      int g = *y + T2[*vline] + T3[*uline];
+      int b = *y + T4[*uline];
+      // Note: going BGRA here not RGBA
+      dst[0] = clamp(b);  // 16-bit to 8-bit, chuck precision
+      dst[1] = clamp(g);
+      dst[2] = clamp(r);
+      dst[3] = 255;
+      dst += ZOF_RGB;
+      if (w & 0x01) {
+        uline++;
+        vline++;
+      }
+    }
+    if (h & 0x01) {
+      u += width / 2;
+      v += width / 2;
+    }
+  }
+}
+
+}  // End namespace cuttlefish
\ No newline at end of file
diff --git a/guest/commands/v4l2_streamer/yuv2rgb.h b/guest/commands/v4l2_streamer/yuv2rgb.h
new file mode 100644
index 000000000..c3115dfe4
--- /dev/null
+++ b/guest/commands/v4l2_streamer/yuv2rgb.h
@@ -0,0 +1,29 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+namespace cuttlefish {
+
+// Read from the given [src] buffer, expected to be in WebRTC YUV format,
+// writing data the [dst] buffer in v4l2 BGRX32 format. [width] and [height]
+// must be valid to describe the frame size, so that indexing calculations are
+// accurate. Note that [src] and [dst] buffers are both required to be
+// pre-allocated, [src] will need to contain valid YUV data, and [dst] contents
+// will be overwritten.
+void Yuv2Rgb(unsigned char *src, unsigned char *dst, int width, int height);
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/guest/hals/health/health-aidl.cpp b/guest/hals/health/health-aidl.cpp
index 38df5048e..3c9ef7449 100644
--- a/guest/hals/health/health-aidl.cpp
+++ b/guest/hals/health/health-aidl.cpp
@@ -103,10 +103,13 @@ ScopedAStatus HealthImpl::getChargeStatus(BatteryStatus* out) {
 }
 
 ScopedAStatus HealthImpl::getBatteryHealthData(BatteryHealthData* out) {
-  out->batteryManufacturingDateSeconds = 0;
-  out->batteryFirstUsageSeconds = 0;
+  out->batteryManufacturingDateSeconds =
+      1689787603;  // Wednesday, 19 July 2023 17:26:43
+  out->batteryFirstUsageSeconds =
+      1691256403;  // Saturday, 5 August 2023 17:26:43
   out->batteryStateOfHealth = 99;
-  out->batterySerialNumber = std::nullopt;
+  out->batterySerialNumber =
+      "d1f92fe7591ff096ca3a29c450a5a3d1";  // MD5("battery serial")
   out->batteryPartStatus = BatteryPartStatus::UNSUPPORTED;
   return ScopedAStatus::ok();
 }
diff --git a/guest/hals/keymint/rust/Android.bp b/guest/hals/keymint/rust/Android.bp
index e12425015..441e69f3a 100644
--- a/guest/hals/keymint/rust/Android.bp
+++ b/guest/hals/keymint/rust/Android.bp
@@ -26,9 +26,9 @@ rust_binary {
         "libandroid_logger",
         "libbinder_rs",
         "libhex",
-        "libkmr_wire",
         "libkmr_hal",
         "libkmr_hal_nonsecure",
+        "libkmr_wire",
         "liblibc",
         "liblog_rust",
     ],
@@ -64,6 +64,27 @@ prebuilt_etc {
     src: "android.hardware.security.secureclock-service.rust.xml",
 }
 
+prebuilt_etc {
+    name: "android.hardware.security.keymint-service.trusty.system.xml",
+    sub_dir: "vintf",
+    vendor: true,
+    src: "android.hardware.security.keymint-service.trusty.system.xml",
+}
+
+prebuilt_etc {
+    name: "android.hardware.security.sharedsecret-service.trusty.system.xml",
+    sub_dir: "vintf",
+    vendor: true,
+    src: "android.hardware.security.sharedsecret-service.trusty.system.xml",
+}
+
+prebuilt_etc {
+    name: "android.hardware.security.secureclock-service.trusty.system.xml",
+    sub_dir: "vintf",
+    vendor: true,
+    src: "android.hardware.security.secureclock-service.trusty.system.xml",
+}
+
 // permissions
 prebuilt_etc {
     name: "android.hardware.hardware_keystore.rust-keymint.xml",
@@ -72,14 +93,23 @@ prebuilt_etc {
     src: "android.hardware.hardware_keystore.rust-keymint.xml",
 }
 
-apex {
-    name: "com.android.hardware.keymint.rust_cf_remote",
+apex_defaults {
+    name: "com.android.hardware.keymint.rust_defaults",
     manifest: "manifest.json",
-    file_contexts: "file_contexts",
     key: "com.google.cf.apex.key",
     certificate: ":com.google.cf.apex.certificate",
     soc_specific: true,
     updatable: false,
+    prebuilts: [
+        // permissions
+        "android.hardware.hardware_keystore.rust-keymint.xml",
+    ],
+}
+
+apex {
+    name: "com.android.hardware.keymint.rust_cf_remote",
+    defaults: ["com.android.hardware.keymint.rust_defaults"],
+    file_contexts: "file_contexts",
     binaries: [
         "android.hardware.security.keymint-service.rust",
     ],
@@ -90,7 +120,17 @@ apex {
         "android.hardware.security.keymint-service.rust.xml",
         "android.hardware.security.secureclock-service.rust.xml",
         "android.hardware.security.sharedsecret-service.rust.xml",
-        // permissions
-        "android.hardware.hardware_keystore.rust-keymint.xml",
+    ],
+}
+
+apex {
+    name: "com.android.hardware.keymint.rust_cf_guest_trusty_nonsecure",
+    defaults: ["com.android.hardware.keymint.rust_defaults"],
+    file_contexts: "file_contexts_trusty",
+    prebuilts: [
+        // vintf_fragments
+        "android.hardware.security.keymint-service.trusty.system.xml",
+        "android.hardware.security.secureclock-service.trusty.system.xml",
+        "android.hardware.security.sharedsecret-service.trusty.system.xml",
     ],
 }
diff --git a/guest/hals/keymint/rust/android.hardware.security.keymint-service.trusty.system.xml b/guest/hals/keymint/rust/android.hardware.security.keymint-service.trusty.system.xml
new file mode 100644
index 000000000..5b493c4d4
--- /dev/null
+++ b/guest/hals/keymint/rust/android.hardware.security.keymint-service.trusty.system.xml
@@ -0,0 +1,12 @@
+<manifest version="1.0" type="device">
+    <hal format="aidl" updatable-via-system="true">
+        <name>android.hardware.security.keymint</name>
+        <version>3</version>
+        <fqname>IKeyMintDevice/default</fqname>
+    </hal>
+    <hal format="aidl" updatable-via-system="true">
+        <name>android.hardware.security.keymint</name>
+        <version>3</version>
+        <fqname>IRemotelyProvisionedComponent/default</fqname>
+    </hal>
+</manifest>
diff --git a/guest/hals/keymint/rust/android.hardware.security.secureclock-service.trusty.system.xml b/guest/hals/keymint/rust/android.hardware.security.secureclock-service.trusty.system.xml
new file mode 100644
index 000000000..51e7ae5e6
--- /dev/null
+++ b/guest/hals/keymint/rust/android.hardware.security.secureclock-service.trusty.system.xml
@@ -0,0 +1,6 @@
+<manifest version="1.0" type="device">
+    <hal format="aidl" updatable-via-system="true">
+        <name>android.hardware.security.secureclock</name>
+        <fqname>ISecureClock/default</fqname>
+    </hal>
+</manifest>
diff --git a/guest/hals/keymint/rust/android.hardware.security.sharedsecret-service.trusty.system.xml b/guest/hals/keymint/rust/android.hardware.security.sharedsecret-service.trusty.system.xml
new file mode 100644
index 000000000..9d9185a4e
--- /dev/null
+++ b/guest/hals/keymint/rust/android.hardware.security.sharedsecret-service.trusty.system.xml
@@ -0,0 +1,6 @@
+<manifest version="1.0" type="device">
+    <hal format="aidl" updatable-via-system="true">
+        <name>android.hardware.security.sharedsecret</name>
+        <fqname>ISharedSecret/default</fqname>
+    </hal>
+</manifest>
diff --git a/guest/hals/keymint/rust/file_contexts_trusty b/guest/hals/keymint/rust/file_contexts_trusty
new file mode 100644
index 000000000..fafd0eae1
--- /dev/null
+++ b/guest/hals/keymint/rust/file_contexts_trusty
@@ -0,0 +1,2 @@
+(/.*)?                                                      u:object_r:vendor_file:s0
+/etc(/.*)?                                                  u:object_r:vendor_configs_file:s0
diff --git a/guest/hals/nfc/Android.bp b/guest/hals/nfc/Android.bp
index 2f6c4ec84..79ecb6b82 100644
--- a/guest/hals/nfc/Android.bp
+++ b/guest/hals/nfc/Android.bp
@@ -31,7 +31,7 @@ rust_binary {
         "liblibc",
         "libnix",
         "libclap",
-        "android.hardware.nfc-V1-rust",
+        "android.hardware.nfc-V2-rust",
         "libanyhow",
         "libthiserror",
         "libbytes",
diff --git a/guest/hals/nfc/nfc-service-cuttlefish.xml b/guest/hals/nfc/nfc-service-cuttlefish.xml
index 70fed205b..650643774 100644
--- a/guest/hals/nfc/nfc-service-cuttlefish.xml
+++ b/guest/hals/nfc/nfc-service-cuttlefish.xml
@@ -1,6 +1,7 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.nfc</name>
+        <version>2</version>
         <fqname>INfc/default</fqname>
     </hal>
 </manifest>
diff --git a/guest/hals/nfc/src/nfc.rs b/guest/hals/nfc/src/nfc.rs
index 71e3986bf..a7b9dda8b 100644
--- a/guest/hals/nfc/src/nfc.rs
+++ b/guest/hals/nfc/src/nfc.rs
@@ -336,4 +336,9 @@ impl INfcAsyncServer for NfcService {
         let config = self.config.lock().await;
         Ok(config.dbg_logging)
     }
+
+    async fn controlGranted(&self) -> binder::Result<NfcStatus> {
+        info!("controlGranted");
+        Ok(NfcStatus::OK)
+    }
 }
diff --git a/guest/hals/vehicle/Android.bp b/guest/hals/vehicle/Android.bp
index e5ec96cfe..ac18d07fe 100644
--- a/guest/hals/vehicle/Android.bp
+++ b/guest/hals/vehicle/Android.bp
@@ -16,9 +16,10 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-filegroup {
+vintf_fragment {
     name: "android.hardware.automotive.vehicle@V3-cf-service.xml",
-    srcs: ["android.hardware.automotive.vehicle@V3-cf-service.xml"],
+    src: "android.hardware.automotive.vehicle@V3-cf-service.xml",
+    vendor: true,
 }
 
 cc_binary {
@@ -35,9 +36,9 @@ cc_binary {
         "vhal_vsockinfo",
     ],
     static_libs: [
-        "android.hardware.automotive.vehicle@default-grpc-hardware-lib",
         "DefaultVehicleHal",
         "VehicleHalUtils",
+        "android.hardware.automotive.vehicle@default-grpc-hardware-lib",
     ],
     shared_libs: [
         "libbase",
@@ -49,5 +50,5 @@ cc_binary {
     cflags: [
         "-Wno-unused-parameter",
     ],
-    vintf_fragments: ["android.hardware.automotive.vehicle@V3-cf-service.xml"],
+    vintf_fragment_modules: ["android.hardware.automotive.vehicle@V3-cf-service.xml"],
 }
diff --git a/guest/hals/vehicle/apex/Android.bp b/guest/hals/vehicle/apex/Android.bp
index 90fa25782..4c38b9af4 100644
--- a/guest/hals/vehicle/apex/Android.bp
+++ b/guest/hals/vehicle/apex/Android.bp
@@ -33,7 +33,6 @@ apex {
     manifest: "apex_manifest.json",
     key: "com.android.hardware.automotive.vehicle.test.key",
     file_contexts: "file_contexts",
-    use_vndk_as_stable: true,
     updatable: false,
     soc_specific: true,
     binaries: [
@@ -42,5 +41,5 @@ apex {
     prebuilts: [
         "com.android.hardware.automotive.vehicle.cf.rc",
     ],
-    vintf_fragments: [":android.hardware.automotive.vehicle@V3-cf-service.xml"],
+    vintf_fragment_modules: ["android.hardware.automotive.vehicle@V3-cf-service.xml"],
 }
diff --git a/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/BluetoothChecker.java b/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/BluetoothChecker.java
index c39865dd8..54146cd47 100644
--- a/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/BluetoothChecker.java
+++ b/guest/monitoring/cuttlefish_service/java/com/android/google/gce/gceservice/BluetoothChecker.java
@@ -30,6 +30,9 @@ public class BluetoothChecker extends JobBase {
     private static final String LOG_TAG = "GceBluetoothChecker";
     private final GceFuture<Boolean> mEnabled = new GceFuture<Boolean>("Bluetooth");
 
+    /* Delay in seconds before rechecking if Bluetooth is enabled. */
+    private static final int BLUETOOTH_RETRY_TIMEOUT_SECONDS = 5;
+
 
     public BluetoothChecker(Context context) {
         super(LOG_TAG);
@@ -55,11 +58,12 @@ public class BluetoothChecker extends JobBase {
             if (bluetoothAdapter.isEnabled()) {
                 Log.i(LOG_TAG, "Bluetooth enabled with name: " + bluetoothAdapter.getName());
                 mEnabled.set(true);
+                return 0;
             } else {
                 Log.i(LOG_TAG, "Bluetooth disabled with name: " + bluetoothAdapter.getName());
             }
         }
-        return 0;
+        return BLUETOOTH_RETRY_TIMEOUT_SECONDS;
     }
 
 
diff --git a/guest/services/cf_satellite_service/src/com/google/android/telephony/satellite/CFSatelliteService.java b/guest/services/cf_satellite_service/src/com/google/android/telephony/satellite/CFSatelliteService.java
index 59530da0c..0a31815ad 100644
--- a/guest/services/cf_satellite_service/src/com/google/android/telephony/satellite/CFSatelliteService.java
+++ b/guest/services/cf_satellite_service/src/com/google/android/telephony/satellite/CFSatelliteService.java
@@ -17,7 +17,6 @@
 package com.google.android.telephony.satellite;
 
 import android.annotation.NonNull;
-import android.annotation.Nullable;
 import android.content.Intent;
 import android.os.Binder;
 import android.os.IBinder;
@@ -26,19 +25,18 @@ import android.telephony.IIntegerConsumer;
 import android.telephony.satellite.stub.ISatelliteCapabilitiesConsumer;
 import android.telephony.satellite.stub.ISatelliteListener;
 import android.telephony.satellite.stub.NTRadioTechnology;
-import android.telephony.satellite.stub.PointingInfo;
 import android.telephony.satellite.stub.SatelliteCapabilities;
 import android.telephony.satellite.stub.SatelliteDatagram;
-import android.telephony.satellite.stub.SatelliteResult;
 import android.telephony.satellite.stub.SatelliteImplBase;
 import android.telephony.satellite.stub.SatelliteModemState;
+import android.telephony.satellite.stub.SatelliteResult;
 import android.telephony.satellite.stub.SatelliteService;
+import android.telephony.satellite.stub.SatelliteModemEnableRequestAttributes;
 import android.telephony.satellite.stub.SystemSelectionSpecifier;
 
 import com.android.internal.util.FunctionalUtils;
 import com.android.telephony.Rlog;
 
-import java.util.ArrayList;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
@@ -61,7 +59,6 @@ public class CFSatelliteService extends SatelliteImplBase {
 
     private boolean mIsCommunicationAllowedInLocation;
     private boolean mIsEnabled;
-    private boolean mIsProvisioned;
     private boolean mIsSupported;
     private int mModemState;
     private boolean mIsEmergnecy;
@@ -76,7 +73,6 @@ public class CFSatelliteService extends SatelliteImplBase {
         super(executor);
         mIsCommunicationAllowedInLocation = true;
         mIsEnabled = false;
-        mIsProvisioned = false;
         mIsSupported = true;
         mModemState = SatelliteModemState.SATELLITE_MODEM_STATE_OFF;
         mIsEmergnecy = false;
@@ -132,15 +128,15 @@ public class CFSatelliteService extends SatelliteImplBase {
     }
 
     @Override
-    public void requestSatelliteEnabled(boolean enableSatellite, boolean enableDemoMode,
-        boolean isEmergency, @NonNull IIntegerConsumer errorCallback) {
+    public void requestSatelliteEnabled(SatelliteModemEnableRequestAttributes enableAttributes,
+            @NonNull IIntegerConsumer errorCallback) {
         logd("requestSatelliteEnabled");
-        if (enableSatellite) {
+        if (enableAttributes.isEnabled) {
             enableSatellite(errorCallback);
         } else {
             disableSatellite(errorCallback);
         }
-        mIsEmergnecy = isEmergency;
+        mIsEmergnecy = enableAttributes.isEmergencyMode;
     }
 
     private void enableSatellite(@NonNull IIntegerConsumer errorCallback) {
@@ -195,29 +191,6 @@ public class CFSatelliteService extends SatelliteImplBase {
         runWithExecutor(() -> errorCallback.accept(SatelliteResult.SATELLITE_RESULT_SUCCESS));
     }
 
-    @Override
-    public void provisionSatelliteService(@NonNull String token, @NonNull byte[] provisionData,
-            @NonNull IIntegerConsumer errorCallback) {
-        logd("provisionSatelliteService");
-        runWithExecutor(() -> errorCallback.accept(SatelliteResult.SATELLITE_RESULT_SUCCESS));
-        updateSatelliteProvisionState(true);
-    }
-
-    @Override
-    public void deprovisionSatelliteService(@NonNull String token,
-            @NonNull IIntegerConsumer errorCallback) {
-        logd("deprovisionSatelliteService");
-        runWithExecutor(() -> errorCallback.accept(SatelliteResult.SATELLITE_RESULT_SUCCESS));
-        updateSatelliteProvisionState(false);
-    }
-
-    @Override
-    public void requestIsSatelliteProvisioned(@NonNull IIntegerConsumer errorCallback,
-            @NonNull IBooleanConsumer callback) {
-        logd("requestIsSatelliteProvisioned");
-        runWithExecutor(() -> callback.accept(mIsProvisioned));
-    }
-
     @Override
     public void pollPendingSatelliteDatagrams(@NonNull IIntegerConsumer errorCallback) {
         logd("pollPendingSatelliteDatagrams");
@@ -274,11 +247,6 @@ public class CFSatelliteService extends SatelliteImplBase {
                 SatelliteResult.SATELLITE_RESULT_REQUEST_NOT_SUPPORTED));
             return false;
         }
-        if (!mIsProvisioned) {
-            runWithExecutor(() -> errorCallback.accept(
-                SatelliteResult.SATELLITE_RESULT_SERVICE_NOT_PROVISIONED));
-            return false;
-        }
         if (!mIsEnabled) {
             runWithExecutor(() -> errorCallback.accept(
                 SatelliteResult.SATELLITE_RESULT_INVALID_MODEM_STATE));
@@ -301,21 +269,6 @@ public class CFSatelliteService extends SatelliteImplBase {
         mModemState = modemState;
     }
 
-    /**
-     * Update the satellite provision state and notify listeners if it changed.
-     *
-     * @param isProvisioned {@code true} if the satellite is currently provisioned and
-     *                      {@code false} if it is not.
-     */
-    private void updateSatelliteProvisionState(boolean isProvisioned) {
-        if (isProvisioned == mIsProvisioned) {
-            return;
-        }
-        mIsProvisioned = isProvisioned;
-        mListeners.forEach(listener -> runWithExecutor(() ->
-                listener.onSatelliteProvisionStateChanged(mIsProvisioned)));
-    }
-
     /**
      * Get the emergency mode or not
      */
diff --git a/guest/services/trusty_vm_launcher/Android.bp b/guest/services/trusty_vm_launcher/Android.bp
new file mode 100644
index 000000000..a77da1113
--- /dev/null
+++ b/guest/services/trusty_vm_launcher/Android.bp
@@ -0,0 +1,36 @@
+rust_binary {
+    name: "trusty_vm_launcher",
+    crate_name: "trusty_vm_launcher",
+    srcs: ["src/main.rs"],
+    edition: "2021",
+    prefer_rlib: true,
+    rustlibs: [
+        "android.system.virtualizationservice-rust",
+        "libanyhow",
+        "libvmclient",
+    ],
+    init_rc: ["trusty_vm_launcher.rc"],
+    bootstrap: true,
+    apex_available: ["//apex_available:platform"],
+    system_ext_specific: true,
+    required: [
+        "cf-early_vms.xml",
+        "lk_trusty.elf",
+    ],
+    enabled: select(release_flag("RELEASE_AVF_ENABLE_EARLY_VM"), {
+        true: true,
+        false: false,
+    }),
+}
+
+prebuilt_etc {
+    name: "cf-early_vms.xml",
+    src: "early_vms.xml",
+    filename: "early_vms.xml",
+    relative_install_path: "avf",
+    system_ext_specific: true,
+    enabled: select(release_flag("RELEASE_AVF_ENABLE_EARLY_VM"), {
+        true: true,
+        false: false,
+    }),
+}
diff --git a/shared/permissions/cuttlefish_excluded_hardware.xml b/guest/services/trusty_vm_launcher/early_vms.xml
similarity index 73%
rename from shared/permissions/cuttlefish_excluded_hardware.xml
rename to guest/services/trusty_vm_launcher/early_vms.xml
index 3fba9f64c..9019d511d 100644
--- a/shared/permissions/cuttlefish_excluded_hardware.xml
+++ b/guest/services/trusty_vm_launcher/early_vms.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright 2020 The Android Open Source Project
+<!-- Copyright 2024 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,6 +13,10 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
-<permissions>
-    <unavailable-feature name="android.software.print" />
-</permissions>
+<early_vms>
+    <early_vm>
+        <name>trusty_vm_launcher</name>
+        <cid>200</cid>
+        <path>/system_ext/bin/trusty_vm_launcher</path>
+    </early_vm>
+</early_vms>
diff --git a/guest/services/trusty_vm_launcher/src/main.rs b/guest/services/trusty_vm_launcher/src/main.rs
new file mode 100644
index 000000000..a459318f2
--- /dev/null
+++ b/guest/services/trusty_vm_launcher/src/main.rs
@@ -0,0 +1,70 @@
+// Copyright 2024, The Android Open Source Project
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     http://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+//! A client for early boot VM running trusty.
+
+use android_system_virtualizationservice::aidl::android::system::virtualizationservice::{
+    IVirtualizationService::IVirtualizationService, VirtualMachineConfig::VirtualMachineConfig,
+    VirtualMachineRawConfig::VirtualMachineRawConfig,
+};
+use android_system_virtualizationservice::binder::{ParcelFileDescriptor, Strong};
+use anyhow::{Context, Result};
+use std::fs::File;
+use vmclient::VmInstance;
+
+const KERNEL_PATH: &str = "/system_ext/etc/hw/lk_trusty.elf";
+
+fn get_service() -> Result<Strong<dyn IVirtualizationService>> {
+    let virtmgr = vmclient::VirtualizationService::new_early()
+        .context("Failed to spawn VirtualizationService")?;
+    virtmgr.connect().context("Failed to connect to VirtualizationService")
+}
+
+fn main() -> Result<()> {
+    let service = get_service()?;
+
+    let kernel =
+        File::open(KERNEL_PATH).with_context(|| format!("Failed to open {KERNEL_PATH}"))?;
+
+    let vm_config = VirtualMachineConfig::RawConfig(VirtualMachineRawConfig {
+        name: "trusty_vm_launcher".to_owned(),
+        kernel: Some(ParcelFileDescriptor::new(kernel)),
+        protectedVm: false,
+        memoryMib: 128,
+        platformVersion: "~1.0".to_owned(),
+        // TODO: add instanceId
+        ..Default::default()
+    });
+
+    println!("creating VM");
+    let vm = VmInstance::create(
+        service.as_ref(),
+        &vm_config,
+        // console_in, console_out, and log will be redirected to the kernel log by virtmgr
+        None, // console_in
+        None, // console_out
+        None, // log
+        None, // callback
+    )
+    .context("Failed to create VM")?;
+    vm.start().context("Failed to start VM")?;
+
+    println!("started trusty_vm_launcher VM");
+    let death_reason = vm.wait_for_death();
+    eprintln!("trusty_vm_launcher ended: {:?}", death_reason);
+
+    // TODO(b/331320802): we may want to use android logger instead of stdio_to_kmsg?
+
+    Ok(())
+}
diff --git a/guest/services/trusty_vm_launcher/trusty_vm_launcher.rc b/guest/services/trusty_vm_launcher/trusty_vm_launcher.rc
new file mode 100644
index 000000000..4bdf41c56
--- /dev/null
+++ b/guest/services/trusty_vm_launcher/trusty_vm_launcher.rc
@@ -0,0 +1,13 @@
+service trusty_vm_launcher /system_ext/bin/trusty_vm_launcher
+    disabled
+    user system
+    group system virtualmachine
+    capabilities IPC_LOCK NET_BIND_SERVICE SYS_RESOURCE SYS_NICE
+    stdio_to_kmsg
+
+# Starts the non-secure Trusty VM in /system_ext when the feature is enabled through
+# the system property set in vendor init.
+on init && property:ro.hardware.security.trusty_vm.system=1
+    setprop trusty_vm_system_nonsecure.ready 1
+    setprop trusty_vm_system.vm_cid 200
+    start trusty_vm_launcher
diff --git a/host/commands/assemble_cvd/assemble_cvd.cc b/host/commands/assemble_cvd/assemble_cvd.cc
index c386c3d48..56fc6c170 100644
--- a/host/commands/assemble_cvd/assemble_cvd.cc
+++ b/host/commands/assemble_cvd/assemble_cvd.cc
@@ -28,6 +28,7 @@
 #include "common/libs/utils/environment.h"
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/flag_parser.h"
+#include "common/libs/utils/in_sandbox.h"
 #include "common/libs/utils/tee_logging.h"
 #include "host/commands/assemble_cvd/clean.h"
 #include "host/commands/assemble_cvd/disk_flags.h"
@@ -107,9 +108,12 @@ Result<void> SaveConfig(const CuttlefishConfig& tmp_config_obj) {
             "Failed to save to \"" << legacy_config_file << "\"");
 
   setenv(kCuttlefishConfigEnvVarName, config_file.c_str(), true);
-  if (symlink(config_file.c_str(), config_link.c_str()) != 0) {
-    return CF_ERRNO("symlink(\"" << config_file << "\", \"" << config_link
-                                 << ") failed");
+  // TODO(schuffelen): Find alternative for host-sandboxing mode
+  if (!InSandbox()) {
+    if (symlink(config_file.c_str(), config_link.c_str()) != 0) {
+      return CF_ERRNO("symlink(\"" << config_file << "\", \"" << config_link
+                                   << ") failed");
+    }
   }
 
   return {};
@@ -156,9 +160,13 @@ Result<void> CreateLegacySymlinks(
     CF_EXPECT(RemoveFile(legacy_instance_path),
               "Failed to remove instance_dir symlink " << legacy_instance_path);
   }
-  if (symlink(instance.instance_dir().c_str(), legacy_instance_path.c_str())) {
-    return CF_ERRNO("symlink(\"" << instance.instance_dir() << "\", \""
-                                 << legacy_instance_path << "\") failed");
+  // TODO(schuffelen): Find alternative for host-sandboxing mode
+  if (!InSandbox()) {
+    if (symlink(instance.instance_dir().c_str(),
+                legacy_instance_path.c_str())) {
+      return CF_ERRNO("symlink(\"" << instance.instance_dir() << "\", \""
+                                   << legacy_instance_path << "\") failed");
+    }
   }
 
   const auto mac80211_uds_name = "vhost_user_mac80211";
@@ -184,7 +192,8 @@ Result<void> RestoreHostFiles(const std::string& cuttlefish_root_dir,
       CF_EXPECT(GuestSnapshotDirectories(snapshot_dir_path));
   auto filter_guest_dir =
       [&guest_snapshot_dirs](const std::string& src_dir) -> bool {
-    return !Contains(guest_snapshot_dirs, src_dir);
+    return !(Contains(guest_snapshot_dirs, src_dir) ||
+             src_dir.ends_with("logs"));
   };
   // cp -r snapshot_dir_path HOME
   CF_EXPECT(CopyDirectoryRecursively(snapshot_dir_path, cuttlefish_root_dir,
@@ -199,7 +208,11 @@ Result<std::set<std::string>> PreservingOnResume(
   const auto snapshot_path = FLAGS_snapshot_path;
   const bool resume_requested = FLAGS_resume || !snapshot_path.empty();
   if (!resume_requested) {
-    return std::set<std::string>{};
+    if (InSandbox()) {
+      return {{"launcher.log"}};
+    } else {
+      return {};
+    }
   }
   CF_EXPECT(snapshot_path.empty() || !creating_os_disk,
             "Restoring from snapshot requires not creating OS disks");
@@ -208,7 +221,11 @@ Result<std::set<std::string>> PreservingOnResume(
     LOG(INFO) << "Requested resuming a previous session (the default behavior) "
               << "but the base images have changed under the overlay, making "
               << "the overlay incompatible. Wiping the overlay files.";
-    return std::set<std::string>{};
+    if (InSandbox()) {
+      return {{"launcher.log"}};
+    } else {
+      return {};
+    }
   }
 
   // either --resume && !creating_os_disk, or restoring from a snapshot
@@ -260,6 +277,9 @@ Result<std::set<std::string>> PreservingOnResume(
     preserving.insert("crosvm_openwrt_boot.log");
     preserving.insert("metrics.log");
   }
+  if (InSandbox()) {
+    preserving.insert("launcher.log");  // Created before `assemble_cvd` runs
+  }
   for (int i = 0; i < modem_simulator_count; i++) {
     std::stringstream ss;
     ss << "iccprofile_for_sim" << i << ".xml";
@@ -269,24 +289,30 @@ Result<std::set<std::string>> PreservingOnResume(
 }
 
 Result<SharedFD> SetLogger(std::string runtime_dir_parent) {
-  while (runtime_dir_parent[runtime_dir_parent.size() - 1] == '/') {
+  SharedFD log_file;
+  if (InSandbox()) {
+    log_file = SharedFD::Open(
+        runtime_dir_parent + "/instances/cvd-1/logs/launcher.log",
+        O_WRONLY | O_APPEND);
+  } else {
+    while (runtime_dir_parent[runtime_dir_parent.size() - 1] == '/') {
+      runtime_dir_parent =
+          runtime_dir_parent.substr(0, FLAGS_instance_dir.rfind('/'));
+    }
     runtime_dir_parent =
         runtime_dir_parent.substr(0, FLAGS_instance_dir.rfind('/'));
+    log_file = SharedFD::Open(runtime_dir_parent, O_WRONLY | O_TMPFILE,
+                              S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
   }
-  runtime_dir_parent =
-      runtime_dir_parent.substr(0, FLAGS_instance_dir.rfind('/'));
-  auto log = SharedFD::Open(runtime_dir_parent, O_WRONLY | O_TMPFILE,
-                            S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
-  if (!log->IsOpen()) {
-    LOG(ERROR) << "Could not open O_TMPFILE precursor to assemble_cvd.log: "
-               << log->StrError();
+  if (!log_file->IsOpen()) {
+    LOG(ERROR) << "Could not open initial log file: " << log_file->StrError();
   } else {
     android::base::SetLogger(TeeLogger({
         {ConsoleSeverity(), SharedFD::Dup(2), MetadataLevel::ONLY_MESSAGE},
-        {LogFileSeverity(), log, MetadataLevel::FULL},
+        {LogFileSeverity(), log_file, MetadataLevel::FULL},
     }));
   }
-  return log;
+  return log_file;
 }
 
 Result<const CuttlefishConfig*> InitFilesystemAndCreateConfig(
@@ -319,9 +345,6 @@ Result<const CuttlefishConfig*> InitFilesystemAndCreateConfig(
         const auto log_files =
             CF_EXPECT(DirectoryContents(instance.PerInstanceLogPath("")));
         for (const auto& filename : log_files) {
-          if (filename == "." || filename == "..") {
-            continue;
-          }
           const std::string path = instance.PerInstanceLogPath(filename);
           auto fd = SharedFD::Open(path, O_WRONLY | O_APPEND);
           CF_EXPECT(fd->IsOpen(),
@@ -453,10 +476,12 @@ Result<const CuttlefishConfig*> InitFilesystemAndCreateConfig(
     CF_EXPECT(RemoveFile(FLAGS_assembly_dir),
               "Failed to remove file" << FLAGS_assembly_dir);
   }
-  if (symlink(config->assembly_dir().c_str(),
-              FLAGS_assembly_dir.c_str())) {
-    return CF_ERRNO("symlink(\"" << config->assembly_dir() << "\", \""
-                                 << FLAGS_assembly_dir << "\") failed");
+  // TODO(schuffelen): Find alternative for host-sandboxing mode
+  if (!InSandbox()) {
+    if (symlink(config->assembly_dir().c_str(), FLAGS_assembly_dir.c_str())) {
+      return CF_ERRNO("symlink(\"" << config->assembly_dir() << "\", \""
+                                   << FLAGS_assembly_dir << "\") failed");
+    }
   }
 
   std::string first_instance = config->Instances()[0].instance_dir();
@@ -465,10 +490,13 @@ Result<const CuttlefishConfig*> InitFilesystemAndCreateConfig(
     CF_EXPECT(RemoveFile(double_legacy_instance_dir),
               "Failed to remove symlink " << double_legacy_instance_dir);
   }
-  if (symlink(first_instance.c_str(), double_legacy_instance_dir.c_str())) {
-    return CF_ERRNO("symlink(\"" << first_instance << "\", \""
-                                 << double_legacy_instance_dir
-                                 << "\") failed");
+  // TODO(schuffelen): Find alternative for host-sandboxing mode
+  if (!InSandbox()) {
+    if (symlink(first_instance.c_str(), double_legacy_instance_dir.c_str())) {
+      return CF_ERRNO("symlink(\"" << first_instance << "\", \""
+                                   << double_legacy_instance_dir
+                                   << "\") failed");
+    }
   }
 
   CF_EXPECT(CreateDynamicDiskFiles(fetcher_config, *config));
diff --git a/host/commands/assemble_cvd/boot_image_utils.cc b/host/commands/assemble_cvd/boot_image_utils.cc
index 1fbeef543..ae1171c56 100644
--- a/host/commands/assemble_cvd/boot_image_utils.cc
+++ b/host/commands/assemble_cvd/boot_image_utils.cc
@@ -22,7 +22,6 @@
 #include <fstream>
 #include <memory>
 #include <regex>
-#include <sstream>
 #include <string>
 
 #include <android-base/logging.h>
@@ -33,16 +32,47 @@
 #include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/avb/avb.cpp"
+#include "host/libs/config/config_utils.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/known_paths.h"
 
-const char TMP_EXTENSION[] = ".tmp";
-const char CPIO_EXT[] = ".cpio";
-const char TMP_RD_DIR[] = "stripped_ramdisk_dir";
-const char STRIPPED_RD[] = "stripped_ramdisk";
-const char CONCATENATED_VENDOR_RAMDISK[] = "concatenated_vendor_ramdisk";
 namespace cuttlefish {
 namespace {
+
+constexpr char TMP_EXTENSION[] = ".tmp";
+constexpr char kCpioExt[] = ".cpio";
+constexpr char TMP_RD_DIR[] = "stripped_ramdisk_dir";
+constexpr char STRIPPED_RD[] = "stripped_ramdisk";
+constexpr char kConcatenatedVendorRamdisk[] = "concatenated_vendor_ramdisk";
+
+void RunMkBootFs(const std::string& input_dir, const std::string& output) {
+  SharedFD output_fd = SharedFD::Open(output, O_CREAT | O_RDWR | O_TRUNC, 0644);
+  CHECK(output_fd->IsOpen()) << output_fd->StrError();
+
+  int success = Command(HostBinaryPath("mkbootfs"))
+                    .AddParameter(input_dir)
+                    .RedirectStdIO(Subprocess::StdIOChannel::kStdOut, output_fd)
+                    .Start()
+                    .Wait();
+  CHECK_EQ(success, 0) << "`mkbootfs` failed.";
+}
+
+void RunLz4(const std::string& input, const std::string& output) {
+  SharedFD output_fd = SharedFD::Open(output, O_CREAT | O_RDWR | O_TRUNC, 0644);
+  CHECK(output_fd->IsOpen()) << output_fd->StrError();
+  int success = Command(HostBinaryPath("lz4"))
+                    .AddParameter("-c")
+                    .AddParameter("-l")
+                    .AddParameter("-12")
+                    .AddParameter("--favor-decSpeed")
+                    .AddParameter(input)
+                    .RedirectStdIO(Subprocess::StdIOChannel::kStdOut, output_fd)
+                    .Start()
+                    .Wait();
+  CHECK_EQ(success, 0) << "`lz4` failed to transform '" << input << "' to '"
+                       << output << "'";
+}
+
 std::string ExtractValue(const std::string& dictionary, const std::string& key) {
   std::size_t index = dictionary.find(key);
   if (index != std::string::npos) {
@@ -91,17 +121,8 @@ void RepackVendorRamdisk(const std::string& kernel_modules_ramdisk_path,
                       << "Exited with status " << success;
 
   const std::string stripped_ramdisk_path = build_dir + "/" + STRIPPED_RD;
-  success = Execute({"/bin/bash", "-c",
-                     HostBinaryPath("mkbootfs") + " " + ramdisk_stage_dir +
-                         " > " + stripped_ramdisk_path + CPIO_EXT});
-  CHECK(success == 0) << "Unable to run cd or cpio. Exited with status "
-                      << success;
-
-  success = Execute({"/bin/bash", "-c",
-                     HostBinaryPath("lz4") + " -c -l -12 --favor-decSpeed " +
-                         stripped_ramdisk_path + CPIO_EXT + " > " +
-                         stripped_ramdisk_path});
-  CHECK(success == 0) << "Unable to run lz4. Exited with status " << success;
+
+  PackRamdisk(ramdisk_stage_dir, stripped_ramdisk_path);
 
   // Concatenates the stripped ramdisk and input ramdisk and places the result at new_ramdisk_path
   std::ofstream final_rd(new_ramdisk_path, std::ios_base::binary | std::ios_base::trunc);
@@ -124,42 +145,48 @@ bool IsCpioArchive(const std::string& path) {
 
 void PackRamdisk(const std::string& ramdisk_stage_dir,
                  const std::string& output_ramdisk) {
-  int success = Execute({"/bin/bash", "-c",
-                         HostBinaryPath("mkbootfs") + " " + ramdisk_stage_dir +
-                             " > " + output_ramdisk + CPIO_EXT});
-  CHECK(success == 0) << "Unable to run cd or cpio. Exited with status "
-                      << success;
-
-  success = Execute({"/bin/bash", "-c",
-                     HostBinaryPath("lz4") + " -c -l -12 --favor-decSpeed " +
-                         output_ramdisk + CPIO_EXT + " > " + output_ramdisk});
-  CHECK(success == 0) << "Unable to run lz4. Exited with status " << success;
+  RunMkBootFs(ramdisk_stage_dir, output_ramdisk + kCpioExt);
+  RunLz4(output_ramdisk + kCpioExt, output_ramdisk);
 }
 
 void UnpackRamdisk(const std::string& original_ramdisk_path,
                    const std::string& ramdisk_stage_dir) {
   int success = 0;
   if (IsCpioArchive(original_ramdisk_path)) {
-    CHECK(Copy(original_ramdisk_path, original_ramdisk_path + CPIO_EXT))
+    CHECK(Copy(original_ramdisk_path, original_ramdisk_path + kCpioExt))
         << "failed to copy " << original_ramdisk_path << " to "
-        << original_ramdisk_path + CPIO_EXT;
+        << original_ramdisk_path + kCpioExt;
   } else {
-    success =
-        Execute({"/bin/bash", "-c",
-                 HostBinaryPath("lz4") + " -c -d -l " + original_ramdisk_path +
-                     " > " + original_ramdisk_path + CPIO_EXT});
-    CHECK(success == 0) << "Unable to run lz4 on file " << original_ramdisk_path
-                        << " . Exited with status " << success;
+    SharedFD output_fd = SharedFD::Open(original_ramdisk_path + kCpioExt,
+                                        O_CREAT | O_RDWR | O_TRUNC, 0644);
+    CHECK(output_fd->IsOpen()) << output_fd->StrError();
+
+    success = Command(HostBinaryPath("lz4"))
+                  .AddParameter("-c")
+                  .AddParameter("-d")
+                  .AddParameter("-l")
+                  .AddParameter(original_ramdisk_path)
+                  .RedirectStdIO(Subprocess::StdIOChannel::kStdOut, output_fd)
+                  .Start()
+                  .Wait();
+    CHECK_EQ(success, 0) << "Unable to run lz4 on file '"
+                         << original_ramdisk_path << "'.";
   }
   const auto ret = EnsureDirectoryExists(ramdisk_stage_dir);
   CHECK(ret.ok()) << ret.error().FormatForEnv();
 
-  success = Execute(
-      {"/bin/bash", "-c",
-       "(cd " + ramdisk_stage_dir + " && while " + HostBinaryPath("toybox") +
-           " cpio -idu; do :; done) < " + original_ramdisk_path + CPIO_EXT});
-  CHECK(success == 0) << "Unable to run cd or cpio. Exited with status "
-                      << success;
+  SharedFD input = SharedFD::Open(original_ramdisk_path + kCpioExt, O_RDONLY);
+  int cpio_status;
+  do {
+    LOG(ERROR) << "Running";
+    cpio_status = Command(HostBinaryPath("toybox"))
+                      .AddParameter("cpio")
+                      .AddParameter("-idu")
+                      .SetWorkingDirectory(ramdisk_stage_dir)
+                      .RedirectStdIO(Subprocess::StdIOChannel::kStdIn, input)
+                      .Start()
+                      .Wait();
+  } while (cpio_status == 0);
 }
 
 bool GetAvbMetadataFromBootImage(const std::string& boot_image_path,
@@ -174,30 +201,24 @@ bool GetAvbMetadataFromBootImage(const std::string& boot_image_path,
   return true;
 }
 
-bool UnpackBootImage(const std::string& boot_image_path,
-                     const std::string& unpack_dir) {
-  auto unpack_path = HostBinaryPath("unpack_bootimg");
-  Command unpack_cmd(unpack_path);
-  unpack_cmd.AddParameter("--boot_img");
-  unpack_cmd.AddParameter(boot_image_path);
-  unpack_cmd.AddParameter("--out");
-  unpack_cmd.AddParameter(unpack_dir);
+Result<void> UnpackBootImage(const std::string& boot_image_path,
+                             const std::string& unpack_dir) {
+  SharedFD output_file = SharedFD::Creat(unpack_dir + "/boot_params", 0666);
+  CF_EXPECTF(output_file->IsOpen(),
+             "Unable to create intermediate boot params file: '{}'",
+             output_file->StrError());
 
-  auto output_file = SharedFD::Creat(unpack_dir + "/boot_params", 0666);
-  if (!output_file->IsOpen()) {
-    LOG(ERROR) << "Unable to create intermediate boot params file: "
-               << output_file->StrError();
-    return false;
-  }
-  unpack_cmd.RedirectStdIO(Subprocess::StdIOChannel::kStdOut, output_file);
+  Command unpack_cmd =
+      Command(HostBinaryPath("unpack_bootimg"))
+          .AddParameter("--boot_img")
+          .AddParameter(boot_image_path)
+          .AddParameter("--out")
+          .AddParameter(unpack_dir)
+          .RedirectStdIO(Subprocess::StdIOChannel::kStdOut, output_file);
 
-  int success = unpack_cmd.Start().Wait();
-  if (success != 0) {
-    LOG(ERROR) << "Unable to run unpack_bootimg. Exited with status "
-               << success;
-    return false;
-  }
-  return true;
+  CF_EXPECT_EQ(unpack_cmd.Start().Wait(), 0, "Unable to run unpack_bootimg.");
+
+  return {};
 }
 
 bool UnpackVendorBootImageIfNotUnpacked(
@@ -229,22 +250,37 @@ bool UnpackVendorBootImageIfNotUnpacked(
   }
 
   // Concatenates all vendor ramdisk into one single ramdisk.
-  Command concat_cmd("/bin/bash");
-  concat_cmd.AddParameter("-c");
-  concat_cmd.AddParameter("cat " + unpack_dir + "/vendor_ramdisk*");
-  auto concat_file =
-      SharedFD::Creat(unpack_dir + "/" + CONCATENATED_VENDOR_RAMDISK, 0666);
+  std::string concat_file_path = unpack_dir + "/" + kConcatenatedVendorRamdisk;
+  SharedFD concat_file = SharedFD::Creat(concat_file_path, 0666);
   if (!concat_file->IsOpen()) {
     LOG(ERROR) << "Unable to create concatenated vendor ramdisk file: "
                << concat_file->StrError();
     return false;
   }
-  concat_cmd.RedirectStdIO(Subprocess::StdIOChannel::kStdOut, concat_file);
-  success = concat_cmd.Start().Wait();
-  if (success != 0) {
-    LOG(ERROR) << "Unable to run cat. Exited with status " << success;
+
+  Result<std::vector<std::string>> unpack_files = DirectoryContents(unpack_dir);
+  if (!unpack_files.ok()) {
+    LOG(ERROR) << "No unpacked files: " << unpack_files.error().FormatForEnv();
     return false;
   }
+  for (const std::string& unpacked : *unpack_files) {
+    LOG(ERROR) << "acs: " << unpacked;
+    if (!android::base::StartsWith(unpacked, "vendor_ramdisk")) {
+      continue;
+    }
+    std::string input_path = unpack_dir + "/" + unpacked;
+    SharedFD input = SharedFD::Open(input_path, O_RDONLY);
+    if (!input->IsOpen()) {
+      LOG(ERROR) << "Failed to open '" << input_path << ": "
+                 << input->StrError();
+      return false;
+    }
+    if (!concat_file->CopyAllFrom(*input)) {
+      LOG(ERROR) << "Failed to copy from '" << input_path << "' to '"
+                 << concat_file_path << "'";
+      return false;
+    }
+  }
   return true;
 }
 
@@ -296,11 +332,11 @@ bool RepackVendorBootImage(const std::string& new_ramdisk,
     ramdisk_path = unpack_dir + "/vendor_ramdisk_repacked";
     if (!FileExists(ramdisk_path)) {
       RepackVendorRamdisk(new_ramdisk,
-                          unpack_dir + "/" + CONCATENATED_VENDOR_RAMDISK,
+                          unpack_dir + "/" + kConcatenatedVendorRamdisk,
                           ramdisk_path, unpack_dir);
     }
   } else {
-    ramdisk_path = unpack_dir + "/" + CONCATENATED_VENDOR_RAMDISK;
+    ramdisk_path = unpack_dir + "/" + kConcatenatedVendorRamdisk;
   }
 
   std::string bootconfig = ReadFile(unpack_dir + "/bootconfig");
@@ -384,7 +420,7 @@ void RepackGem5BootImage(const std::string& initrd_path,
   // Test to make sure new ramdisk hasn't already been repacked if input ramdisk is provided
   if (FileExists(input_ramdisk_path) && !FileExists(new_ramdisk_path)) {
     RepackVendorRamdisk(input_ramdisk_path,
-                        unpack_dir + "/" + CONCATENATED_VENDOR_RAMDISK,
+                        unpack_dir + "/" + kConcatenatedVendorRamdisk,
                         new_ramdisk_path, unpack_dir);
   }
   std::ifstream vendor_boot_ramdisk(FileExists(new_ramdisk_path) ? new_ramdisk_path : unpack_dir +
@@ -468,8 +504,9 @@ Result<std::string> ReadAndroidVersionFromBootImage(
   RecursivelyRemoveDirectory(unpack_dir);
   std::string os_version =
       ExtractValue(boot_params, "Prop: com.android.build.boot.os_version -> ");
-  // if the OS version is "None", it wasn't set when the boot image was made.
-  if (os_version == "None") {
+  // if the OS version is "None", or the prop does not exist, it wasn't set
+  // when the boot image was made.
+  if (os_version == "None" || os_version.empty()) {
     LOG(INFO) << "Could not extract os version from " << boot_image_path
               << ". Defaulting to 0.0.0.";
     return "0.0.0";
diff --git a/host/commands/assemble_cvd/boot_image_utils.h b/host/commands/assemble_cvd/boot_image_utils.h
index 26a3dc38c..377fa0275 100644
--- a/host/commands/assemble_cvd/boot_image_utils.h
+++ b/host/commands/assemble_cvd/boot_image_utils.h
@@ -37,8 +37,10 @@ bool RepackVendorBootImageWithEmptyRamdisk(
     const std::string& vendor_boot_image_path,
     const std::string& new_vendor_boot_image_path,
     const std::string& unpack_dir, bool bootconfig_supported);
-bool UnpackBootImage(const std::string& boot_image_path,
-                     const std::string& unpack_dir);
+
+Result<void> UnpackBootImage(const std::string& boot_image_path,
+                             const std::string& unpack_dir);
+
 bool UnpackVendorBootImageIfNotUnpacked(
     const std::string& vendor_boot_image_path, const std::string& unpack_dir);
 void RepackGem5BootImage(const std::string& initrd_path,
diff --git a/host/commands/assemble_cvd/bootconfig_args.cpp b/host/commands/assemble_cvd/bootconfig_args.cpp
index 0d9739aca..1c4d3ccb1 100644
--- a/host/commands/assemble_cvd/bootconfig_args.cpp
+++ b/host/commands/assemble_cvd/bootconfig_args.cpp
@@ -43,9 +43,7 @@ void AppendMapWithReplacement(T* destination, const T& source) {
   }
 }
 
-// TODO(schuffelen): Move more of this into host/libs/vm_manager, as a
-// substitute for the vm_manager comparisons.
-Result<std::unordered_map<std::string, std::string>> VmManagerBootconfig(
+Result<std::unordered_map<std::string, std::string>> ConsoleBootconfig(
     const CuttlefishConfig::InstanceSpecific& instance) {
   std::unordered_map<std::string, std::string> bootconfig_args;
   if (instance.console()) {
@@ -76,7 +74,7 @@ Result<std::unordered_map<std::string, std::string>> BootconfigArgsFromConfig(
   std::unordered_map<std::string, std::string> bootconfig_args;
 
   AppendMapWithReplacement(&bootconfig_args,
-                           CF_EXPECT(VmManagerBootconfig(instance)));
+                           CF_EXPECT(ConsoleBootconfig(instance)));
 
   auto vmm =
       vm_manager::GetVmManager(config.vm_manager(), instance.target_arch());
@@ -190,14 +188,21 @@ Result<std::unordered_map<std::string, std::string>> BootconfigArgsFromConfig(
     bootconfig_args["androidboot.ramdisk_hotswapped"] = "1";
   }
 
-  bootconfig_args["androidboot.vendor.apex.com.android.hardware.keymint"] =
-      config.secure_hals().count(SecureHal::GuestKeymintInsecure)
-          ? "com.android.hardware.keymint.rust_nonsecure"
-          : "com.android.hardware.keymint.rust_cf_remote";
+  const auto& secure_hals = CF_EXPECT(config.secure_hals());
+  if (secure_hals.count(SecureHal::kGuestKeymintInsecure)) {
+    bootconfig_args["androidboot.vendor.apex.com.android.hardware.keymint"] =
+        "com.android.hardware.keymint.rust_nonsecure";
+  } else if (secure_hals.count(SecureHal::kGuestKeymintTrustyInsecure)) {
+    bootconfig_args["androidboot.vendor.apex.com.android.hardware.keymint"] =
+        "com.android.hardware.keymint.rust_cf_guest_trusty_nonsecure";
+  } else {
+    bootconfig_args["androidboot.vendor.apex.com.android.hardware.keymint"] =
+        "com.android.hardware.keymint.rust_cf_remote";
+  }
 
   // Preemptive for when we set up the HAL to be runtime selectable
   bootconfig_args["androidboot.vendor.apex.com.android.hardware.gatekeeper"] =
-      config.secure_hals().count(SecureHal::GuestGatekeeperInsecure)
+      secure_hals.count(SecureHal::kGuestGatekeeperInsecure)
           ? "com.android.hardware.gatekeeper.nonsecure"
           : "com.android.hardware.gatekeeper.cf_remote";
 
diff --git a/host/commands/assemble_cvd/clean.cc b/host/commands/assemble_cvd/clean.cc
index 7b26951b2..00736353c 100644
--- a/host/commands/assemble_cvd/clean.cc
+++ b/host/commands/assemble_cvd/clean.cc
@@ -19,23 +19,23 @@
 #include <errno.h>
 #include <sys/stat.h>
 
-#include <regex>
 #include <vector>
 
+#include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/strings.h>
 
-#include "common/libs/utils/files.h"
+#include "common/libs/utils/in_sandbox.h"
 #include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
-#include "host/commands/assemble_cvd/flags.h"
+#include "host/libs/config/config_utils.h"
 
 namespace cuttlefish {
 namespace {
 
 Result<void> CleanPriorFiles(const std::string& path,
                              const std::set<std::string>& preserving) {
-  if (preserving.count(cpp_basename(path))) {
+  if (preserving.count(android::base::Basename(path))) {
     LOG(DEBUG) << "Preserving: " << path;
     return {};
   }
@@ -71,9 +71,11 @@ Result<void> CleanPriorFiles(const std::string& path,
                   << "\"");
   }
   if (rmdir(path.c_str()) < 0) {
-    if (!(errno == EEXIST || errno == ENOTEMPTY)) {
-      // If EEXIST or ENOTEMPTY, probably because a file was preserved
-      return CF_ERRNO("Could not rmdir \"" << path << "\"");
+    if (!(errno == EEXIST || errno == ENOTEMPTY || errno == EROFS ||
+          errno == EBUSY)) {
+      // If EEXIST or ENOTEMPTY, probably because a file was preserved. EROFS
+      // or EBUSY likely means a bind mount for host-sandboxing mode.
+      return CF_ERRF("Could not rmdir '{}': '{}'", path, strerror(errno));
     }
   }
   return {};
@@ -97,7 +99,8 @@ Result<void> CleanPriorFiles(const std::vector<std::string>& paths,
   LOG(DEBUG) << fmt::format("Prior dirs: {}", fmt::join(prior_dirs, ", "));
   LOG(DEBUG) << fmt::format("Prior files: {}", fmt::join(prior_files, ", "));
 
-  if (prior_dirs.size() > 0 || prior_files.size() > 0) {
+  // TODO(schuffelen): Fix logic for host-sandboxing mode.
+  if (!InSandbox() && (prior_dirs.size() > 0 || prior_files.size() > 0)) {
     Command lsof("lsof");
     lsof.AddParameter("-t");
     for (const auto& prior_dir : prior_dirs) {
@@ -133,8 +136,6 @@ Result<void> CleanPriorFiles(const std::vector<std::string>& paths,
 Result<void> CleanPriorFiles(const std::set<std::string>& preserving,
                              const std::vector<std::string>& clean_dirs) {
   std::vector<std::string> paths = {
-      // The environment file
-      GetCuttlefishEnvPath(),
       // The global link to the config file
       GetGlobalConfigFileLink(),
   };
diff --git a/host/commands/assemble_cvd/disk/disk.h b/host/commands/assemble_cvd/disk/disk.h
index 5cc5b4f4a..6c00b01b4 100644
--- a/host/commands/assemble_cvd/disk/disk.h
+++ b/host/commands/assemble_cvd/disk/disk.h
@@ -16,8 +16,6 @@
 
 #pragma once
 
-#include <fruit/fruit.h>
-
 #include "host/commands/assemble_cvd/boot_config.h"
 #include "host/libs/avb/avb.h"
 #include "host/libs/config/cuttlefish_config.h"
@@ -25,18 +23,15 @@
 
 namespace cuttlefish {
 
-class KernelRamdiskRepacker : public SetupFeature {};
-
-fruit::Component<fruit::Required<const CuttlefishConfig,
-                                 const CuttlefishConfig::InstanceSpecific,
-                                 const Avb>,
-                 KernelRamdiskRepacker>
-KernelRamdiskRepackerComponent();
+Result<void> RepackKernelRamdisk(
+    const CuttlefishConfig& config,
+    const CuttlefishConfig::InstanceSpecific& instance, const Avb& avb);
 
 Result<void> GeneratePersistentBootconfig(
     const CuttlefishConfig&, const CuttlefishConfig::InstanceSpecific&);
 
-Result<void> Gem5ImageUnpacker(const CuttlefishConfig&, KernelRamdiskRepacker&);
+Result<void> Gem5ImageUnpacker(const CuttlefishConfig&,
+                               AutoSetup<RepackKernelRamdisk>::Type&);
 
 Result<void> GeneratePersistentVbmeta(
     const CuttlefishConfig::InstanceSpecific&,
diff --git a/host/commands/assemble_cvd/disk/gem5_image_unpacker.cpp b/host/commands/assemble_cvd/disk/gem5_image_unpacker.cpp
index b60bd39ba..d1f8203f0 100644
--- a/host/commands/assemble_cvd/disk/gem5_image_unpacker.cpp
+++ b/host/commands/assemble_cvd/disk/gem5_image_unpacker.cpp
@@ -16,16 +16,17 @@
 
 #include "host/commands/assemble_cvd/disk/disk.h"
 
-#include <fruit/fruit.h>
+#include <android-base/file.h>
 
 #include "common/libs/utils/files.h"
 #include "host/commands/assemble_cvd/boot_image_utils.h"
-#include "host/libs/vm_manager/gem5_manager.h"
+#include "host/libs/config/feature.h"
 
 namespace cuttlefish {
 
-Result<void> Gem5ImageUnpacker(const CuttlefishConfig& config,
-                               KernelRamdiskRepacker& /* dependency */) {
+Result<void> Gem5ImageUnpacker(
+    const CuttlefishConfig& config,
+    AutoSetup<RepackKernelRamdisk>::Type& /* dependency */) {
   if (config.vm_manager() != VmmMode::kGem5) {
     return {};
   }
@@ -71,15 +72,15 @@ Result<void> Gem5ImageUnpacker(const CuttlefishConfig& config,
       mkdir(binaries_dir.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0 ||
           errno == EEXIST,
       "\"" << binaries_dir << "\": " << strerror(errno));
-  CF_EXPECT(cuttlefish::Copy(
+  CF_EXPECT(Copy(
       instance_.bootloader(),
-      binaries_dir + "/" + cpp_basename(instance_.bootloader())));
+      binaries_dir + "/" + android::base::Basename(instance_.bootloader())));
 
   // Gem5 also needs the ARM version of the bootloader, even though it
   // doesn't use it. It'll even open it to check it's a valid ELF file.
   // Work around this by copying such a named file from the same directory
-  CF_EXPECT(cuttlefish::Copy(cpp_dirname(instance_.bootloader()) + "/boot.arm",
-                             binaries_dir + "/boot.arm"));
+  CF_EXPECT(Copy(android::base::Dirname(instance_.bootloader()) + "/boot.arm",
+                 binaries_dir + "/boot.arm"));
 
   return {};
 }
diff --git a/host/commands/assemble_cvd/disk/generate_persistent_bootconfig.cpp b/host/commands/assemble_cvd/disk/generate_persistent_bootconfig.cpp
index 04ebafa87..2b4f0b098 100644
--- a/host/commands/assemble_cvd/disk/generate_persistent_bootconfig.cpp
+++ b/host/commands/assemble_cvd/disk/generate_persistent_bootconfig.cpp
@@ -20,8 +20,6 @@
 #include <string>
 #include <unordered_set>
 
-#include <fruit/fruit.h>
-
 #include "common/libs/fs/shared_buf.h"
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/files.h"
diff --git a/host/commands/assemble_cvd/disk/generate_persistent_vbmeta.cpp b/host/commands/assemble_cvd/disk/generate_persistent_vbmeta.cpp
index add41dc07..cc0c36029 100644
--- a/host/commands/assemble_cvd/disk/generate_persistent_vbmeta.cpp
+++ b/host/commands/assemble_cvd/disk/generate_persistent_vbmeta.cpp
@@ -18,8 +18,6 @@
 
 #include <string>
 
-#include <fruit/fruit.h>
-
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/commands/assemble_cvd/boot_config.h"
diff --git a/host/commands/assemble_cvd/disk/kernel_ramdisk_repacker.cpp b/host/commands/assemble_cvd/disk/kernel_ramdisk_repacker.cpp
index ac5f85bc7..28d7b2dad 100644
--- a/host/commands/assemble_cvd/disk/kernel_ramdisk_repacker.cpp
+++ b/host/commands/assemble_cvd/disk/kernel_ramdisk_repacker.cpp
@@ -18,183 +18,146 @@
 
 #include <string>
 
-#include <fruit/fruit.h>
-#include <gflags/gflags.h>
-
 #include "common/libs/utils/files.h"
 #include "host/commands/assemble_cvd/boot_image_utils.h"
 #include "host/commands/assemble_cvd/vendor_dlkm_utils.h"
 #include "host/libs/avb/avb.h"
 #include "host/libs/config/cuttlefish_config.h"
-#include "host/libs/config/feature.h"
-#include "host/libs/vm_manager/gem5_manager.h"
 
 namespace cuttlefish {
+namespace {
+
+Result<void> RebuildDlkmAndVbmeta(const std::string& build_dir,
+                                  const std::string& partition_name,
+                                  const std::string& output_image,
+                                  const std::string& vbmeta_image) {
+  // TODO(b/149866755) For now, we assume that vendor_dlkm is ext4. Add
+  // logic to handle EROFS once the feature stabilizes.
+  const auto tmp_output_image = output_image + ".tmp";
+  CF_EXPECTF(BuildDlkmImage(build_dir, false, partition_name, tmp_output_image),
+             "Failed to build `{}' image from '{}'", partition_name, build_dir);
+
+  CF_EXPECT(MoveIfChanged(tmp_output_image, output_image));
+
+  CF_EXPECT(BuildVbmetaImage(output_image, vbmeta_image),
+            "Failed to rebuild vbmeta vendor.");
+
+  return {};
+}
+
+Result<void> RepackSuperAndVbmeta(
+    const CuttlefishConfig::InstanceSpecific& instance,
+    const std::string& superimg_build_dir,
+    const std::string& vendor_dlkm_build_dir,
+    const std::string& system_dlkm_build_dir, const std::string& ramdisk_path) {
+  const auto ramdisk_stage_dir = instance.instance_dir() + "/ramdisk_staged";
+  CF_EXPECT(SplitRamdiskModules(ramdisk_path, ramdisk_stage_dir,
+                                vendor_dlkm_build_dir, system_dlkm_build_dir),
+            "Failed to move ramdisk modules to vendor_dlkm");
+
+  const auto new_vendor_dlkm_img =
+      superimg_build_dir + "/vendor_dlkm_repacked.img";
+  CF_EXPECTF(RebuildDlkmAndVbmeta(vendor_dlkm_build_dir, "vendor_dlkm",
+                                  new_vendor_dlkm_img,
+                                  instance.new_vbmeta_vendor_dlkm_image()),
+             "Failed to build vendor_dlkm image from '{}'",
+             vendor_dlkm_build_dir);
 
-using vm_manager::Gem5Manager;
+  const auto new_system_dlkm_img =
+      superimg_build_dir + "/system_dlkm_repacked.img";
+  CF_EXPECTF(RebuildDlkmAndVbmeta(system_dlkm_build_dir, "system_dlkm",
+                                  new_system_dlkm_img,
+                                  instance.new_vbmeta_system_dlkm_image()),
+             "Failed to build system_dlkm image from '{}'",
+             system_dlkm_build_dir);
 
-class KernelRamdiskRepackerImpl : public KernelRamdiskRepacker {
- public:
-  INJECT(KernelRamdiskRepackerImpl(
-      const CuttlefishConfig& config,
-      const CuttlefishConfig::InstanceSpecific& instance,
-      const Avb& avb))
-      : config_(config), instance_(instance), avb_(avb) {}
+  const auto new_super_img = instance.new_super_image();
+  CF_EXPECTF(Copy(instance.super_image(), new_super_img),
+             "Failed to copy super image '{}' to '{}': '{}'",
+             instance.super_image(), new_super_img, strerror(errno));
 
-  // SetupFeature
-  std::string Name() const override { return "KernelRamdiskRepacker"; }
-  std::unordered_set<SetupFeature*> Dependencies() const override { return {}; }
-  bool Enabled() const override {
+  CF_EXPECT(RepackSuperWithPartition(new_super_img, new_vendor_dlkm_img,
+                                     "vendor_dlkm"),
+            "Failed to repack super image with new vendor dlkm image.");
+
+  CF_EXPECT(RepackSuperWithPartition(new_super_img, new_system_dlkm_img,
+                                     "system_dlkm"),
+            "Failed to repack super image with new system dlkm image.");
+
+  return {};
+}
+
+}  // namespace
+
+Result<void> RepackKernelRamdisk(
+    const CuttlefishConfig& config,
+    const CuttlefishConfig::InstanceSpecific& instance, const Avb& avb) {
+  if (instance.protected_vm()) {
     // If we are booting a protected VM, for now, assume that image repacking
     // isn't trusted. Repacking requires resigning the image and keys from an
     // android host aren't trusted.
-    return !instance_.protected_vm();
+    return {};
   }
 
- protected:
-  static bool RebuildDlkmAndVbmeta(const std::string& build_dir,
-                                   const std::string& partition_name,
-                                   const std::string& output_image,
-                                   const std::string& vbmeta_image) {
-    // TODO(b/149866755) For now, we assume that vendor_dlkm is ext4. Add
-    // logic to handle EROFS once the feature stabilizes.
-    const auto tmp_output_image = output_image + ".tmp";
-    if (!BuildDlkmImage(build_dir, false, partition_name, tmp_output_image)) {
-      LOG(ERROR) << "Failed to build `" << partition_name << "` image from "
-                 << build_dir;
-      return false;
-    }
-    if (!MoveIfChanged(tmp_output_image, output_image)) {
-      return false;
-    }
-    if (!BuildVbmetaImage(output_image, vbmeta_image)) {
-      LOG(ERROR) << "Failed to rebuild vbmeta vendor.";
-      return false;
-    }
-    return true;
+  CF_EXPECTF(FileHasContent(instance.boot_image()), "File not found: {}",
+             instance.boot_image());
+  // The init_boot partition is be optional for testing boot.img
+  // with the ramdisk inside.
+  if (!FileHasContent(instance.init_boot_image())) {
+    LOG(WARNING) << "File not found: " << instance.init_boot_image();
   }
-  bool RepackSuperAndVbmeta(const std::string& superimg_build_dir,
-                            const std::string& vendor_dlkm_build_dir,
-                            const std::string& system_dlkm_build_dir,
-                            const std::string& ramdisk_path) {
-    const auto ramdisk_stage_dir = instance_.instance_dir() + "/ramdisk_staged";
-    if (!SplitRamdiskModules(ramdisk_path, ramdisk_stage_dir,
-                             vendor_dlkm_build_dir, system_dlkm_build_dir)) {
-      LOG(ERROR) << "Failed to move ramdisk modules to vendor_dlkm";
-      return false;
-    }
-    const auto new_vendor_dlkm_img =
-        superimg_build_dir + "/vendor_dlkm_repacked.img";
-    if (!RebuildDlkmAndVbmeta(vendor_dlkm_build_dir, "vendor_dlkm",
-                              new_vendor_dlkm_img,
-                              instance_.new_vbmeta_vendor_dlkm_image())) {
-      LOG(ERROR) << "Failed to build vendor_dlkm image from "
-                 << vendor_dlkm_build_dir;
-      return false;
-    }
-    const auto new_system_dlkm_img =
-        superimg_build_dir + "/system_dlkm_repacked.img";
-    if (!RebuildDlkmAndVbmeta(system_dlkm_build_dir, "system_dlkm",
-                              new_system_dlkm_img,
-                              instance_.new_vbmeta_system_dlkm_image())) {
-      LOG(ERROR) << "Failed to build system_dlkm image from "
-                 << system_dlkm_build_dir;
-      return false;
-    }
-    const auto new_super_img = instance_.new_super_image();
-    if (!Copy(instance_.super_image(), new_super_img)) {
-      PLOG(ERROR) << "Failed to copy super image " << instance_.super_image()
-                  << " to " << new_super_img;
-      return false;
-    }
-    if (!RepackSuperWithPartition(new_super_img, new_vendor_dlkm_img,
-                                  "vendor_dlkm")) {
-      LOG(ERROR) << "Failed to repack super image with new vendor dlkm image.";
-      return false;
-    }
-    if (!RepackSuperWithPartition(new_super_img, new_system_dlkm_img,
-                                  "system_dlkm")) {
-      LOG(ERROR) << "Failed to repack super image with new system dlkm image.";
-      return false;
-    }
-    return true;
-  }
-  Result<void> ResultSetup() override {
-    CF_EXPECTF(FileHasContent(instance_.boot_image()), "File not found: {}",
-               instance_.boot_image());
-    // The init_boot partition is be optional for testing boot.img
-    // with the ramdisk inside.
-    if (!FileHasContent(instance_.init_boot_image())) {
-      LOG(WARNING) << "File not found: " << instance_.init_boot_image();
-    }
 
-    CF_EXPECTF(FileHasContent(instance_.vendor_boot_image()),
-               "File not found: {}", instance_.vendor_boot_image());
-
-    // Repacking a boot.img doesn't work with Gem5 because the user must always
-    // specify a vmlinux instead of an arm64 Image, and that file can be too
-    // large to be repacked. Skip repack of boot.img on Gem5, as we need to be
-    // able to extract the ramdisk.img in a later stage and so this step must
-    // not fail (..and the repacked kernel wouldn't be used anyway).
-    if (instance_.kernel_path().size() &&
-        config_.vm_manager() != VmmMode::kGem5) {
-      CF_EXPECT(RepackBootImage(avb_, instance_.kernel_path(), instance_.boot_image(),
-                                instance_.new_boot_image(), instance_.instance_dir()),
-                "Failed to regenerate the boot image with the new kernel");
-    }
+  CF_EXPECTF(FileHasContent(instance.vendor_boot_image()), "File not found: {}",
+             instance.vendor_boot_image());
 
-    if (instance_.kernel_path().size() || instance_.initramfs_path().size()) {
-      const std::string new_vendor_boot_image_path =
-          instance_.new_vendor_boot_image();
-      // Repack the vendor boot images if kernels and/or ramdisks are passed in.
-      if (instance_.initramfs_path().size()) {
-        const auto superimg_build_dir = instance_.instance_dir() + "/superimg";
-        const auto ramdisk_repacked =
-            instance_.instance_dir() + "/ramdisk_repacked";
-        CF_EXPECTF(Copy(instance_.initramfs_path(), ramdisk_repacked),
-                   "Failed to copy {} to {}", instance_.initramfs_path(),
-                   ramdisk_repacked);
-        const auto vendor_dlkm_build_dir = superimg_build_dir + "/vendor_dlkm";
-        const auto system_dlkm_build_dir = superimg_build_dir + "/system_dlkm";
+  // Repacking a boot.img doesn't work with Gem5 because the user must always
+  // specify a vmlinux instead of an arm64 Image, and that file can be too
+  // large to be repacked. Skip repack of boot.img on Gem5, as we need to be
+  // able to extract the ramdisk.img in a later stage and so this step must
+  // not fail (..and the repacked kernel wouldn't be used anyway).
+  if (instance.kernel_path().size() && config.vm_manager() != VmmMode::kGem5) {
+    CF_EXPECT(
+        RepackBootImage(avb, instance.kernel_path(), instance.boot_image(),
+                        instance.new_boot_image(), instance.instance_dir()),
+        "Failed to regenerate the boot image with the new kernel");
+  }
+
+  if (instance.kernel_path().size() || instance.initramfs_path().size()) {
+    const std::string new_vendor_boot_image_path =
+        instance.new_vendor_boot_image();
+    // Repack the vendor boot images if kernels and/or ramdisks are passed in.
+    if (instance.initramfs_path().size()) {
+      const auto superimg_build_dir = instance.instance_dir() + "/superimg";
+      const auto ramdisk_repacked =
+          instance.instance_dir() + "/ramdisk_repacked";
+      CF_EXPECTF(Copy(instance.initramfs_path(), ramdisk_repacked),
+                 "Failed to copy {} to {}", instance.initramfs_path(),
+                 ramdisk_repacked);
+      const auto vendor_dlkm_build_dir = superimg_build_dir + "/vendor_dlkm";
+      const auto system_dlkm_build_dir = superimg_build_dir + "/system_dlkm";
+      CF_EXPECT(RepackSuperAndVbmeta(instance, superimg_build_dir,
+                                     vendor_dlkm_build_dir,
+                                     system_dlkm_build_dir, ramdisk_repacked));
+      bool success = RepackVendorBootImage(
+          ramdisk_repacked, instance.vendor_boot_image(),
+          new_vendor_boot_image_path, config.assembly_dir(),
+          instance.bootconfig_supported());
+      if (!success) {
+        LOG(ERROR) << "Failed to regenerate the vendor boot image with the "
+                      "new ramdisk";
+      } else {
+        // This control flow implies a kernel with all configs built in.
+        // If it's just the kernel, repack the vendor boot image without a
+        // ramdisk.
         CF_EXPECT(
-            RepackSuperAndVbmeta(superimg_build_dir, vendor_dlkm_build_dir,
-                                 system_dlkm_build_dir, ramdisk_repacked));
-        bool success = RepackVendorBootImage(
-            ramdisk_repacked, instance_.vendor_boot_image(),
-            new_vendor_boot_image_path, config_.assembly_dir(),
-            instance_.bootconfig_supported());
-        if (!success) {
-          LOG(ERROR) << "Failed to regenerate the vendor boot image with the "
-                        "new ramdisk";
-        } else {
-          // This control flow implies a kernel with all configs built in.
-          // If it's just the kernel, repack the vendor boot image without a
-          // ramdisk.
-          CF_EXPECT(
-              RepackVendorBootImageWithEmptyRamdisk(
-                  instance_.vendor_boot_image(), new_vendor_boot_image_path,
-                  config_.assembly_dir(), instance_.bootconfig_supported()),
-              "Failed to regenerate the vendor boot image without a ramdisk");
-        }
+            RepackVendorBootImageWithEmptyRamdisk(
+                instance.vendor_boot_image(), new_vendor_boot_image_path,
+                config.assembly_dir(), instance.bootconfig_supported()),
+            "Failed to regenerate the vendor boot image without a ramdisk");
       }
     }
-    return {};
   }
-
- private:
-  const CuttlefishConfig& config_;
-  const CuttlefishConfig::InstanceSpecific& instance_;
-  const Avb& avb_;
-};
-
-fruit::Component<fruit::Required<const CuttlefishConfig,
-                                 const CuttlefishConfig::InstanceSpecific,
-                                 const Avb>,
-                 KernelRamdiskRepacker>
-KernelRamdiskRepackerComponent() {
-  return fruit::createComponent()
-      .addMultibinding<SetupFeature, KernelRamdiskRepackerImpl>()
-      .bind<KernelRamdiskRepacker, KernelRamdiskRepackerImpl>();
+  return {};
 }
 
 }  // namespace cuttlefish
diff --git a/host/commands/assemble_cvd/disk_builder.cpp b/host/commands/assemble_cvd/disk_builder.cpp
index d6ee26ba4..964b0b4ba 100644
--- a/host/commands/assemble_cvd/disk_builder.cpp
+++ b/host/commands/assemble_cvd/disk_builder.cpp
@@ -196,6 +196,7 @@ Result<bool> DiskBuilder::BuildCompositeDiskIfNecessary() {
   }
 
   CF_EXPECT(vm_manager_ != VmmMode::kUnknown);
+  // TODO: b/346855591 - run with QEMU when crosvm block device is integrated
   if (vm_manager_ == VmmMode::kCrosvm) {
     CF_EXPECT(!header_path_.empty(), "No header path");
     CF_EXPECT(!footer_path_.empty(), "No footer path");
diff --git a/host/commands/assemble_cvd/disk_flags.cc b/host/commands/assemble_cvd/disk_flags.cc
index f7144f9c6..91430bfd3 100644
--- a/host/commands/assemble_cvd/disk_flags.cc
+++ b/host/commands/assemble_cvd/disk_flags.cc
@@ -123,6 +123,10 @@ DEFINE_string(custom_partition_path, CF_DEFAULTS_CUSTOM_PARTITION_PATH,
               "Location of custom image that will be passed as a \"custom\" partition"
               "to rootfs and can be used by /dev/block/by-name/custom");
 
+DEFINE_string(
+    hibernation_image, CF_DEFAULTS_HIBERNATION_IMAGE,
+    "Location of the hibernation path that will be used when hibernating.");
+
 DEFINE_string(blank_metadata_image_mb, CF_DEFAULTS_BLANK_METADATA_IMAGE_MB,
               "The size of the blank metadata image to generate, MB.");
 DEFINE_string(
@@ -177,6 +181,7 @@ Result<void> ResolveInstanceFiles() {
   std::string default_vbmeta_system_dlkm_image = "";
   std::string default_16k_kernel_image = "";
   std::string default_16k_ramdisk_image = "";
+  std::string default_hibernation_image = "";
 
   std::string cur_system_image_dir;
   std::string comma_str = "";
@@ -208,6 +213,8 @@ Result<void> ResolveInstanceFiles() {
         comma_str + cur_system_image_dir + "/vbmeta_vendor_dlkm.img";
     default_vbmeta_system_dlkm_image +=
         comma_str + cur_system_image_dir + "/vbmeta_system_dlkm.img";
+    default_hibernation_image +=
+        comma_str + cur_system_image_dir + "/hibernation_swap.img";
     if (FLAGS_use_16k) {
       const auto kernel_16k = cur_system_image_dir + "/kernel_16k";
       const auto ramdisk_16k = cur_system_image_dir + "/ramdisk_16k.img";
@@ -255,6 +262,9 @@ Result<void> ResolveInstanceFiles() {
   SetCommandLineOptionWithMode("vbmeta_system_dlkm_image",
                                default_vbmeta_system_dlkm_image.c_str(),
                                google::FlagSettingMode::SET_FLAGS_DEFAULT);
+  SetCommandLineOptionWithMode("hibernation_image",
+                               default_hibernation_image.c_str(),
+                               google::FlagSettingMode::SET_FLAGS_DEFAULT);
 
   return {};
 }
@@ -439,6 +449,15 @@ std::vector<ImagePartition> android_composite_disk_config(
       .image_file_path = AbsolutePath(instance.metadata_image()),
       .read_only = FLAGS_use_overlay,
   });
+  const auto hibernation_partition_image =
+      instance.hibernation_partition_image();
+  if (FileExists(hibernation_partition_image)) {
+    partitions.push_back(ImagePartition{
+        .label = "hibernation",
+        .image_file_path = AbsolutePath(hibernation_partition_image),
+        .read_only = FLAGS_use_overlay,
+    });
+  }
   const auto custom_partition_path = instance.custom_partition_path();
   if (!custom_partition_path.empty()) {
     partitions.push_back(ImagePartition{
@@ -681,7 +700,7 @@ static fruit::Component<> DiskChangesComponent(
       .install(CuttlefishKeyAvbComponent)
       .install(AutoSetup<InitializeMetadataImage>::Component)
       .install(AutoSetup<InitializeChromeOsState>::Component)
-      .install(KernelRamdiskRepackerComponent)
+      .install(AutoSetup<RepackKernelRamdisk>::Component)
       .install(AutoSetup<VbmetaEnforceMinimumSize>::Component)
       .install(AutoSetup<BootloaderPresentCheck>::Component)
       .install(AutoSetup<Gem5ImageUnpacker>::Component)
@@ -764,6 +783,8 @@ Result<void> DiskImageFlagsVectorization(CuttlefishConfig& config, const Fetcher
 
   std::vector<std::string> custom_partition_path =
       android::base::Split(FLAGS_custom_partition_path, ",");
+  std::vector<std::string> hibernation_image =
+      android::base::Split(FLAGS_hibernation_image, ",");
 
   std::vector<std::string> bootloader =
       android::base::Split(FLAGS_bootloader, ",");
@@ -902,6 +923,12 @@ Result<void> DiskImageFlagsVectorization(CuttlefishConfig& config, const Fetcher
     } else {
       instance.set_custom_partition_path(custom_partition_path[instance_index]);
     }
+    if (instance_index >= hibernation_image.size()) {
+      instance.set_hibernation_partition_image(hibernation_image[0]);
+    } else {
+      instance.set_hibernation_partition_image(
+          hibernation_image[instance_index]);
+    }
     if (instance_index >= bootloader.size()) {
       instance.set_bootloader(bootloader[0]);
     } else {
diff --git a/host/commands/assemble_cvd/flags.cc b/host/commands/assemble_cvd/flags.cc
index 9e6a39eaa..4a385bd3a 100644
--- a/host/commands/assemble_cvd/flags.cc
+++ b/host/commands/assemble_cvd/flags.cc
@@ -42,6 +42,7 @@
 #include "common/libs/utils/contains.h"
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/flag_parser.h"
+#include "common/libs/utils/in_sandbox.h"
 #include "common/libs/utils/json.h"
 #include "common/libs/utils/network.h"
 #include "host/commands/assemble_cvd/alloc.h"
@@ -60,6 +61,7 @@
 #include "host/libs/config/esp.h"
 #include "host/libs/config/host_tools_version.h"
 #include "host/libs/config/instance_nums.h"
+#include "host/libs/config/secure_hals.h"
 #include "host/libs/config/touchpad.h"
 #include "host/libs/vm_manager/crosvm_manager.h"
 #include "host/libs/vm_manager/gem5_manager.h"
@@ -511,18 +513,21 @@ DEFINE_string(straced_host_executables, CF_DEFAULTS_STRACED_HOST_EXECUTABLES,
               "Comma-separated list of executable names to run under strace "
               "to collect their system call information.");
 
-DEFINE_bool(enable_host_sandbox, CF_DEFAULTS_HOST_SANDBOX,
-            "Lock down host processes with sandbox2");
-
 DEFINE_vec(
     fail_fast, CF_DEFAULTS_FAIL_FAST ? "true" : "false",
     "Whether to exit when a heuristic predicts the boot will not complete");
 
+DEFINE_vec(vhost_user_block, CF_DEFAULTS_VHOST_USER_BLOCK ? "true" : "false",
+           "(experimental) use crosvm vhost-user block device implementation ");
+
 DECLARE_string(assembly_dir);
 DECLARE_string(boot_image);
 DECLARE_string(system_image_dir);
 DECLARE_string(snapshot_path);
 
+DEFINE_vec(vcpu_config_path, CF_DEFAULTS_VCPU_CONFIG_PATH,
+           "configuration file for Virtual Cpufreq");
+
 namespace cuttlefish {
 using vm_manager::QemuManager;
 using vm_manager::Gem5Manager;
@@ -616,55 +621,63 @@ Result<std::vector<GuestConfig>> ReadGuestConfig() {
       kernel_image_path = cur_boot_image;
     }
 
-    Command ikconfig_cmd(HostBinaryPath("extract-ikconfig"));
-    ikconfig_cmd.AddParameter(kernel_image_path);
-    ikconfig_cmd.SetEnvironment({new_path});
-
-    std::string ikconfig_path =
-        StringFromEnv("TEMP", "/tmp") + "/ikconfig.XXXXXX";
-    auto ikconfig_fd = SharedFD::Mkstemp(&ikconfig_path);
-    CF_EXPECT(ikconfig_fd->IsOpen(),
-              "Unable to create ikconfig file: " << ikconfig_fd->StrError());
-    ikconfig_cmd.RedirectStdIO(Subprocess::StdIOChannel::kStdOut, ikconfig_fd);
-
-    auto ikconfig_proc = ikconfig_cmd.Start();
-    CF_EXPECT(ikconfig_proc.Started() && ikconfig_proc.Wait() == 0,
-              "Failed to extract ikconfig from " << kernel_image_path);
-
-    std::string config = ReadFile(ikconfig_path);
-
     GuestConfig guest_config;
     guest_config.android_version_number =
         CF_EXPECT(ReadAndroidVersionFromBootImage(cur_boot_image),
                   "Failed to read guest's android version");
 
-    if (config.find("\nCONFIG_ARM=y") != std::string::npos) {
-      guest_config.target_arch = Arch::Arm;
-    } else if (config.find("\nCONFIG_ARM64=y") != std::string::npos) {
-      guest_config.target_arch = Arch::Arm64;
-    } else if (config.find("\nCONFIG_ARCH_RV64I=y") != std::string::npos) {
-      guest_config.target_arch = Arch::RiscV64;
-    } else if (config.find("\nCONFIG_X86_64=y") != std::string::npos) {
-      guest_config.target_arch = Arch::X86_64;
-    } else if (config.find("\nCONFIG_X86=y") != std::string::npos) {
-      guest_config.target_arch = Arch::X86;
+    if (InSandbox()) {
+      // TODO: b/359309462 - real sandboxing for extract-ikconfig
+      guest_config.target_arch = HostArch();
+      guest_config.bootconfig_supported = true;
+      guest_config.hctr2_supported = true;
     } else {
-      return CF_ERR("Unknown target architecture");
+      Command ikconfig_cmd(HostBinaryPath("extract-ikconfig"));
+      ikconfig_cmd.AddParameter(kernel_image_path);
+      ikconfig_cmd.UnsetFromEnvironment("PATH").AddEnvironmentVariable(
+          "PATH", new_path);
+      std::string ikconfig_path =
+          StringFromEnv("TEMP", "/tmp") + "/ikconfig.XXXXXX";
+      auto ikconfig_fd = SharedFD::Mkstemp(&ikconfig_path);
+      CF_EXPECT(ikconfig_fd->IsOpen(),
+                "Unable to create ikconfig file: " << ikconfig_fd->StrError());
+      ikconfig_cmd.RedirectStdIO(Subprocess::StdIOChannel::kStdOut,
+                                 ikconfig_fd);
+
+      auto ikconfig_proc = ikconfig_cmd.Start();
+      CF_EXPECT(ikconfig_proc.Started() && ikconfig_proc.Wait() == 0,
+                "Failed to extract ikconfig from " << kernel_image_path);
+
+      std::string config = ReadFile(ikconfig_path);
+
+      if (config.find("\nCONFIG_ARM=y") != std::string::npos) {
+        guest_config.target_arch = Arch::Arm;
+      } else if (config.find("\nCONFIG_ARM64=y") != std::string::npos) {
+        guest_config.target_arch = Arch::Arm64;
+      } else if (config.find("\nCONFIG_ARCH_RV64I=y") != std::string::npos) {
+        guest_config.target_arch = Arch::RiscV64;
+      } else if (config.find("\nCONFIG_X86_64=y") != std::string::npos) {
+        guest_config.target_arch = Arch::X86_64;
+      } else if (config.find("\nCONFIG_X86=y") != std::string::npos) {
+        guest_config.target_arch = Arch::X86;
+      } else {
+        return CF_ERR("Unknown target architecture");
+      }
+      guest_config.bootconfig_supported =
+          config.find("\nCONFIG_BOOT_CONFIG=y") != std::string::npos;
+      // Once all Cuttlefish kernel versions are at least 5.15, this code can be
+      // removed. CONFIG_CRYPTO_HCTR2=y will always be set.
+      // Note there's also a platform dep for hctr2 introduced in Android 14.
+      // Hence the version check.
+      guest_config.hctr2_supported =
+          (config.find("\nCONFIG_CRYPTO_HCTR2=y") != std::string::npos) &&
+          (guest_config.android_version_number != "11.0.0") &&
+          (guest_config.android_version_number != "13.0.0") &&
+          (guest_config.android_version_number != "11") &&
+          (guest_config.android_version_number != "13");
+
+      unlink(ikconfig_path.c_str());
     }
-    guest_config.bootconfig_supported =
-        config.find("\nCONFIG_BOOT_CONFIG=y") != std::string::npos;
-    // Once all Cuttlefish kernel versions are at least 5.15, this code can be
-    // removed. CONFIG_CRYPTO_HCTR2=y will always be set.
-    // Note there's also a platform dep for hctr2 introduced in Android 14.
-    // Hence the version check.
-    guest_config.hctr2_supported =
-        (config.find("\nCONFIG_CRYPTO_HCTR2=y") != std::string::npos) &&
-        (guest_config.android_version_number != "11.0.0") &&
-        (guest_config.android_version_number != "13.0.0") &&
-        (guest_config.android_version_number != "11") &&
-        (guest_config.android_version_number != "13");
-
-    unlink(ikconfig_path.c_str());
 
     std::string instance_android_info_txt;
     if (instance_index >= system_image_dir.size()) {
@@ -675,10 +688,16 @@ Result<std::vector<GuestConfig>> ReadGuestConfig() {
       instance_android_info_txt =
           system_image_dir[instance_index] + "/android-info.txt";
     }
+
     auto res = GetAndroidInfoConfig(instance_android_info_txt, "gfxstream");
     guest_config.gfxstream_supported =
         res.ok() && res.value() == "supported";
 
+    res = GetAndroidInfoConfig(instance_android_info_txt,
+                               "gfxstream_gl_program_binary_link_status");
+    guest_config.gfxstream_gl_program_binary_link_status_supported =
+        res.ok() && res.value() == "supported";
+
     auto res_bgra_support = GetAndroidInfoConfig(instance_android_info_txt,
                                                  "supports_bgra_framebuffers");
     guest_config.supports_bgra_framebuffers =
@@ -940,6 +959,24 @@ Result<void> CheckSnapshotCompatible(
   return {};
 }
 
+std::optional<std::string> EnvironmentUdsDir() {
+  auto environments_uds_dir = "/tmp/cf_env_" + std::to_string(getuid());
+  if (DirectoryExists(environments_uds_dir) &&
+      !CanAccess(environments_uds_dir, R_OK | W_OK | X_OK)) {
+    return std::nullopt;
+  }
+  return environments_uds_dir;
+}
+
+std::optional<std::string> InstancesUdsDir() {
+  auto instances_uds_dir = "/tmp/cf_avd_" + std::to_string(getuid());
+  if (DirectoryExists(instances_uds_dir) &&
+      !CanAccess(instances_uds_dir, R_OK | W_OK | X_OK)) {
+    return std::nullopt;
+  }
+  return instances_uds_dir;
+}
+
 } // namespace
 
 Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
@@ -967,6 +1004,11 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
 
   tmp_config_obj.set_root_dir(root_dir);
 
+  tmp_config_obj.set_environments_uds_dir(
+      EnvironmentUdsDir().value_or(tmp_config_obj.environments_dir()));
+  tmp_config_obj.set_instances_uds_dir(
+      InstancesUdsDir().value_or(tmp_config_obj.instances_dir()));
+
   auto instance_nums =
       CF_EXPECT(InstanceNumsCalculator().FromGlobalGflags().Calculate());
 
@@ -1007,20 +1049,9 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
     SetCommandLineOptionWithMode("secure_hals", kDefaultSecure,
                                  google::FlagSettingMode::SET_FLAGS_DEFAULT);
   }
-  auto secure_hals_strs =
-      android::base::Tokenize(FLAGS_secure_hals, ",:;|/\\+");
-  tmp_config_obj.set_secure_hals(
-      std::set<std::string>(secure_hals_strs.begin(), secure_hals_strs.end()));
-  auto secure_hals = tmp_config_obj.secure_hals();
-  CF_EXPECT(!secure_hals.count(SecureHal::HostKeymintSecure) ||
-                !secure_hals.count(SecureHal::HostKeymintInsecure),
-            "Choose at most one host keymint implementation");
-  CF_EXPECT(!secure_hals.count(SecureHal::HostGatekeeperSecure) ||
-                !secure_hals.count(SecureHal::HostGatekeeperInsecure),
-            "Choose at most one host gatekeeper implementation");
-  CF_EXPECT(!secure_hals.count(SecureHal::HostOemlockSecure) ||
-                !secure_hals.count(SecureHal::HostOemlockInsecure),
-            "Choose at most one host oemlock implementation");
+  auto secure_hals = CF_EXPECT(ParseSecureHals(FLAGS_secure_hals));
+  CF_EXPECT(ValidateSecureHals(secure_hals));
+  tmp_config_obj.set_secure_hals(secure_hals);
 
   tmp_config_obj.set_extra_kernel_cmdline(FLAGS_extra_kernel_cmdline);
 
@@ -1229,8 +1260,14 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
 
   std::vector<bool> fail_fast_vec = CF_EXPECT(GET_FLAG_BOOL_VALUE(fail_fast));
 
+  std::vector<bool> vhost_user_block_vec =
+      CF_EXPECT(GET_FLAG_BOOL_VALUE(vhost_user_block));
+
   std::vector<std::string> mcu_config_vec = CF_EXPECT(GET_FLAG_STR_VALUE(mcu_config_path));
 
+  std::vector<std::string> vcpu_config_vec =
+      CF_EXPECT(GET_FLAG_STR_VALUE(vcpu_config_path));
+
   std::string default_enable_sandbox = "";
   std::string default_enable_virtiofs = "";
   std::string comma_str = "";
@@ -1295,8 +1332,6 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
   std::set<std::string> straced_set(straced.begin(), straced.end());
   tmp_config_obj.set_straced_host_executables(straced_set);
 
-  tmp_config_obj.set_host_sandbox(FLAGS_enable_host_sandbox);
-
   auto vhal_proxy_server_instance_num = *instance_nums.begin() - 1;
   if (FLAGS_vhal_proxy_server_instance_num > 0) {
     vhal_proxy_server_instance_num = FLAGS_vhal_proxy_server_instance_num - 1;
@@ -1344,6 +1379,9 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
     mutable_env_config.set_start_wmediumd(false);
   }
 
+  const auto graphics_availability =
+      GetGraphicsAvailabilityWithSubprocessCheck();
+
   // Instance specific configs
   bool is_first_instance = true;
   int instance_index = 0;
@@ -1474,6 +1512,11 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
     instance.set_blank_data_image_mb(blank_data_image_mb_vec[instance_index]);
     instance.set_gdb_port(gdb_port_vec[instance_index]);
     instance.set_fail_fast(fail_fast_vec[instance_index]);
+    if (vhost_user_block_vec[instance_index]) {
+      CF_EXPECT_EQ(tmp_config_obj.vm_manager(), VmmMode::kCrosvm,
+                   "vhost-user block only supported on crosvm");
+    }
+    instance.set_vhost_user_block(vhost_user_block_vec[instance_index]);
 
     std::optional<std::vector<CuttlefishConfig::DisplayConfig>>
         binding_displays_configs;
@@ -1588,7 +1631,8 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
 
     // gpu related settings
     const std::string gpu_mode = CF_EXPECT(ConfigureGpuSettings(
-        gpu_mode_vec[instance_index], gpu_vhost_user_mode_vec[instance_index],
+        graphics_availability, gpu_mode_vec[instance_index],
+        gpu_vhost_user_mode_vec[instance_index],
         gpu_renderer_features_vec[instance_index],
         gpu_context_types_vec[instance_index], vmm_mode,
         guest_configs[instance_index], instance));
@@ -1825,6 +1869,12 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
       instance.set_mcu(CF_EXPECT(ParseJson(file_content), "Failed parsing JSON file"));
     }
 
+    if (!vcpu_config_vec[instance_index].empty()) {
+      auto vcpu_cfg_path = vcpu_config_vec[instance_index];
+      CF_EXPECT(FileExists(vcpu_cfg_path), "vCPU config file does not exist");
+      instance.set_vcpu_config_path(AbsolutePath(vcpu_cfg_path));
+    }
+
     instance_index++;
   }  // end of num_instances loop
 
@@ -2170,10 +2220,6 @@ std::string GetConfigFilePath(const CuttlefishConfig& config) {
   return config.AssemblyPath("cuttlefish_config.json");
 }
 
-std::string GetCuttlefishEnvPath() {
-  return StringFromEnv("HOME", ".") + "/.cuttlefish.sh";
-}
-
 std::string GetSeccompPolicyDir() {
   static const std::string kSeccompDir = std::string("usr/share/crosvm/") +
                                          cuttlefish::HostArchStr() +
diff --git a/host/commands/assemble_cvd/flags.h b/host/commands/assemble_cvd/flags.h
index 8ab0fa604..9b70c024f 100644
--- a/host/commands/assemble_cvd/flags.h
+++ b/host/commands/assemble_cvd/flags.h
@@ -34,6 +34,7 @@ struct GuestConfig {
   bool hctr2_supported = false;
   std::string android_version_number;
   bool gfxstream_supported = false;
+  bool gfxstream_gl_program_binary_link_status_supported = false;
   bool vhost_user_vsock = false;
   bool supports_bgra_framebuffers = false;
 };
@@ -46,7 +47,6 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
     fruit::Injector<>& injector, const FetcherConfig& fetcher_config);
 
 std::string GetConfigFilePath(const CuttlefishConfig& config);
-std::string GetCuttlefishEnvPath();
 std::string GetSeccompPolicyDir();
 
 } // namespace cuttlefish
diff --git a/host/commands/assemble_cvd/flags_defaults.h b/host/commands/assemble_cvd/flags_defaults.h
index b2f594fe9..1e019b196 100644
--- a/host/commands/assemble_cvd/flags_defaults.h
+++ b/host/commands/assemble_cvd/flags_defaults.h
@@ -54,9 +54,7 @@
   cuttlefish::ForCurrentInstance(cuttlefish::kDefaultUuidPrefix)
 #define CF_DEFAULTS_FILE_VERBOSITY "DEBUG"
 #define CF_DEFAULTS_VERBOSITY "INFO"
-#define CF_DEFAULTS_RUN_FILE_DISCOVERY true
 #define CF_DEFAULTS_MEMORY_MB CF_DEFAULTS_DYNAMIC_INT
-#define CF_DEFAULTS_SHARE_SCHED_CORE false
 #define CF_DEFAULTS_TRACK_HOST_TOOLS_CRC false
 // TODO: defined twice, please remove redundant definitions
 #define CF_DEFAULTS_USE_OVERLAY true
@@ -120,6 +118,7 @@
 #define CF_DEFAULTS_FUCHSIA_MULTIBOOT_BIN_PATH CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_FUCHSIA_ROOT_IMAGE CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_CUSTOM_PARTITION_PATH CF_DEFAULTS_DYNAMIC_STRING
+#define CF_DEFAULTS_HIBERNATION_IMAGE CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_SUPER_IMAGE CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_VBMETA_IMAGE CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_VBMETA_SYSTEM_IMAGE CF_DEFAULTS_DYNAMIC_STRING
@@ -249,3 +248,10 @@
 
 // Whether to exit when heuristics predict the boot will not complete
 #define CF_DEFAULTS_FAIL_FAST true
+
+// Whether to use the crosvm vhost-user block device implementation with QEMU
+// TODO: b/346855591 - default to `true`
+#define CF_DEFAULTS_VHOST_USER_BLOCK false
+
+// Virtual Cpufreq default configuration path
+#define CF_DEFAULTS_VCPU_CONFIG_PATH ""
diff --git a/host/commands/assemble_cvd/graphics_flags.cc b/host/commands/assemble_cvd/graphics_flags.cc
index d843f5118..7cf8caff2 100644
--- a/host/commands/assemble_cvd/graphics_flags.cc
+++ b/host/commands/assemble_cvd/graphics_flags.cc
@@ -19,11 +19,13 @@
 #include <ostream>
 
 #include <GraphicsDetector.pb.h>
+#include <android-base/file.h>
 #include <android-base/strings.h>
 #include <fmt/format.h>
 #include <google/protobuf/text_format.h>
 
 #include "common/libs/utils/contains.h"
+#include "common/libs/utils/files.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/config/cuttlefish_config.h"
 
@@ -205,26 +207,32 @@ GetNeededVhostUserGpuHostRendererFeatures(
     const ::gfxstream::proto::GraphicsAvailability& availability) {
   VhostUserGpuHostRendererFeatures features = {};
 
-  CF_EXPECT(
-      mode == RenderingMode::kGfxstream ||
-          mode == RenderingMode::kGfxstreamGuestAngle,
-      "vhost-user-gpu is only currently supported with --gpu_mode=gfxstream "
-      "and --gpu_mode=gfxstream_guest_angle");
+  // No features needed for guest rendering.
+  if (mode == RenderingMode::kGuestSwiftShader) {
+    return features;
+  }
 
+  // For any passthrough graphics mode, external blob is needed for sharing
+  // buffers between the vhost-user-gpu VMM process and the main VMM process.
   features.external_blob = true;
 
-  const bool has_external_memory_host =
-      availability.has_vulkan() &&
-      !availability.vulkan().physical_devices().empty() &&
-      Contains(availability.vulkan().physical_devices(0).extensions(),
-               "VK_EXT_external_memory_host");
+  // Prebuilt SwiftShader includes VK_EXT_external_memory_host.
+  if (mode == RenderingMode::kGfxstreamGuestAngleHostSwiftshader) {
+    features.system_blob = true;
+  } else {
+    const bool has_external_memory_host =
+        availability.has_vulkan() &&
+        !availability.vulkan().physical_devices().empty() &&
+        Contains(availability.vulkan().physical_devices(0).extensions(),
+                 "VK_EXT_external_memory_host");
 
-  CF_EXPECT(
-      has_external_memory_host || mode != RenderingMode::kGfxstreamGuestAngle,
-      "VK_EXT_external_memory_host is required for running with "
-      "--gpu_mode=gfxstream_guest_angle and --enable_gpu_vhost_user=true");
+    CF_EXPECT(
+        has_external_memory_host || mode != RenderingMode::kGfxstreamGuestAngle,
+        "VK_EXT_external_memory_host is required for running with "
+        "--gpu_mode=gfxstream_guest_angle and --enable_gpu_vhost_user=true");
 
-  features.system_blob = has_external_memory_host;
+    features.system_blob = has_external_memory_host;
+  }
 
   return features;
 }
@@ -305,8 +313,7 @@ Result<bool> SelectGpuVhostUserMode(const std::string& gpu_mode,
             gpu_vhost_user_mode_arg == kGpuVhostUserModeOn ||
             gpu_vhost_user_mode_arg == kGpuVhostUserModeOff);
   if (gpu_vhost_user_mode_arg == kGpuVhostUserModeAuto) {
-    if (gpu_mode == kGpuModeGuestSwiftshader ||
-        gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
+    if (gpu_mode == kGpuModeGuestSwiftshader) {
       LOG(INFO) << "GPU vhost user auto mode: not needed for --gpu_mode="
                 << gpu_mode << ". Not enabling vhost user gpu.";
       return false;
@@ -352,25 +359,6 @@ Result<std::string> GraphicsDetectorBinaryPath() {
   return CF_ERR("Graphics detector unavailable for host arch.");
 }
 
-CF_UNUSED_ON_MACOS
-Result<const gfxstream::proto::GraphicsAvailability>
-GetGraphicsAvailabilityWithSubprocessCheck() {
-  Command graphics_detector_cmd(CF_EXPECT(GraphicsDetectorBinaryPath()));
-  std::string graphics_detector_stdout;
-  auto ret = RunWithManagedStdio(std::move(graphics_detector_cmd), nullptr,
-                                 &graphics_detector_stdout, nullptr);
-  CF_EXPECT_EQ(ret, 0, "Failed to run graphics detector, bad return value");
-
-  gfxstream::proto::GraphicsAvailability availability;
-  google::protobuf::TextFormat::Parser parser;
-  if (!parser.ParseFromString(graphics_detector_stdout, &availability)) {
-    return CF_ERR("Failed to parse graphics detector stdout: "
-                  << graphics_detector_stdout);
-  }
-
-  return availability;
-}
-
 bool IsAmdGpu(const gfxstream::proto::GraphicsAvailability& availability) {
   return (availability.has_egl() &&
           ((availability.egl().has_gles2_availability() &&
@@ -457,10 +445,17 @@ Result<void> SetGfxstreamFlags(
   }
 
   std::unordered_map<std::string, bool> features;
+
   // Apply features from host/mode requirements.
   if (gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
     features["VulkanUseDedicatedAhbMemoryType"] = true;
   }
+
+  // Apply features from guest/mode requirements.
+  if (guest_config.gfxstream_gl_program_binary_link_status_supported) {
+    features["GlProgramBinaryLinkStatus"] = true;
+  }
+
   // Apply feature overrides from --gpu_renderer_features.
   const auto feature_overrides =
       CF_EXPECT(ParseGfxstreamRendererFlag(gpu_renderer_features_arg));
@@ -470,6 +465,7 @@ Result<void> SetGfxstreamFlags(
                << " via command line argument.";
     features[feature_name] = feature_enabled;
   }
+
   // Convert features back to a string for passing to the VMM.
   const std::string features_string =
       GetGfxstreamRendererFeaturesString(features);
@@ -481,18 +477,75 @@ Result<void> SetGfxstreamFlags(
   return {};
 }
 
-}  // namespace
-
 static std::unordered_set<std::string> kSupportedGpuContexts{
     "gfxstream-vulkan", "gfxstream-composer", "cross-domain", "magma"};
 
+}  // namespace
+
+gfxstream::proto::GraphicsAvailability
+GetGraphicsAvailabilityWithSubprocessCheck() {
+#ifdef __APPLE__
+  return {};
+#else
+  auto graphics_detector_binary_result = GraphicsDetectorBinaryPath();
+  if (!graphics_detector_binary_result.ok()) {
+    LOG(ERROR) << "Failed to run graphics detector, graphics detector path "
+               << " not available: "
+               << graphics_detector_binary_result.error().FormatForEnv()
+               << ". Assuming no availability.";
+    return {};
+  }
+
+  TemporaryFile graphics_availability_file;
+
+  Command graphics_detector_cmd(graphics_detector_binary_result.value());
+  graphics_detector_cmd.AddParameter(graphics_availability_file.path);
+
+  std::string graphics_detector_stdout;
+  auto ret = RunWithManagedStdio(std::move(graphics_detector_cmd), nullptr,
+                                 &graphics_detector_stdout, nullptr);
+  if (ret != 0) {
+    LOG(ERROR) << "Failed to run graphics detector, bad return value: " << ret
+               << ". Assuming no availability.";
+    return {};
+  }
+  LOG(DEBUG) << graphics_detector_stdout;
+
+  auto graphics_availability_content_result =
+      ReadFileContents(graphics_availability_file.path);
+  if (!graphics_availability_content_result.ok()) {
+    LOG(ERROR) << "Failed to read graphics availability from file "
+               << graphics_availability_file.path << ":"
+               << graphics_availability_content_result.error().FormatForEnv()
+               << ". Assuming no availability.";
+    return {};
+  }
+  const std::string& graphics_availability_content =
+      graphics_availability_content_result.value();
+
+  gfxstream::proto::GraphicsAvailability availability;
+  google::protobuf::TextFormat::Parser parser;
+  if (!parser.ParseFromString(graphics_availability_content, &availability)) {
+    LOG(ERROR) << "Failed to parse graphics detector output: "
+               << graphics_availability_content
+               << ". Assuming no availability.";
+    return {};
+  }
+
+  LOG(DEBUG) << "Host Graphics Availability:" << availability.DebugString();
+  return availability;
+#endif
+}
+
 Result<std::string> ConfigureGpuSettings(
+    const gfxstream::proto::GraphicsAvailability& graphics_availability,
     const std::string& gpu_mode_arg, const std::string& gpu_vhost_user_mode_arg,
     const std::string& gpu_renderer_features_arg,
     std::string& gpu_context_types_arg, VmmMode vmm,
     const GuestConfig& guest_config,
     CuttlefishConfig::MutableInstanceSpecific& instance) {
 #ifdef __APPLE__
+  (void)graphics_availability;
   (void)gpu_vhost_user_mode_arg;
   (void)vmm;
   (void)guest_config;
@@ -506,20 +559,6 @@ Result<std::string> ConfigureGpuSettings(
   instance.set_gpu_mode(gpu_mode);
   instance.set_enable_gpu_vhost_user(false);
 #else
-  gfxstream::proto::GraphicsAvailability graphics_availability;
-
-  auto graphics_availability_result =
-      GetGraphicsAvailabilityWithSubprocessCheck();
-  if (!graphics_availability_result.ok()) {
-    LOG(ERROR) << "Failed to get graphics availability: "
-               << graphics_availability_result.error().Message()
-               << ". Assuming none.";
-  } else {
-    graphics_availability = graphics_availability_result.value();
-    LOG(DEBUG) << "Host Graphics Availability:"
-               << graphics_availability.DebugString();
-  }
-
   const std::string gpu_mode = CF_EXPECT(
       SelectGpuMode(gpu_mode_arg, vmm, guest_config, graphics_availability));
   const bool enable_gpu_vhost_user =
diff --git a/host/commands/assemble_cvd/graphics_flags.h b/host/commands/assemble_cvd/graphics_flags.h
index 83297243f..f5d1ce884 100644
--- a/host/commands/assemble_cvd/graphics_flags.h
+++ b/host/commands/assemble_cvd/graphics_flags.h
@@ -17,6 +17,8 @@
 
 #include <string>
 
+#include <GraphicsDetector.pb.h>
+
 #include "common/libs/utils/result.h"
 #include "host/commands/assemble_cvd/flags.h"
 #include "host/libs/config/config_utils.h"
@@ -24,7 +26,11 @@
 
 namespace cuttlefish {
 
+gfxstream::proto::GraphicsAvailability
+GetGraphicsAvailabilityWithSubprocessCheck();
+
 Result<std::string> ConfigureGpuSettings(
+    const gfxstream::proto::GraphicsAvailability& graphics_availability,
     const std::string& gpu_mode_arg, const std::string& gpu_vhost_user_mode_arg,
     const std::string& gpu_renderer_features_arg,
     std::string& gpu_context_types_arg, VmmMode vmm,
diff --git a/host/commands/assemble_cvd/vendor_dlkm_utils.cc b/host/commands/assemble_cvd/vendor_dlkm_utils.cc
index 57890e4a7..7f2fafec1 100644
--- a/host/commands/assemble_cvd/vendor_dlkm_utils.cc
+++ b/host/commands/assemble_cvd/vendor_dlkm_utils.cc
@@ -28,12 +28,15 @@
 #include <android-base/strings.h>
 #include <fmt/format.h>
 
+#include "common/libs/fs/shared_buf.h"
+#include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/contains.h"
+#include "common/libs/utils/environment.h"
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/commands/assemble_cvd/boot_image_utils.h"
 #include "host/commands/assemble_cvd/kernel_module_parser.h"
-#include "host/libs/config/cuttlefish_config.h"
+#include "host/libs/config/config_utils.h"
 #include "host/libs/config/known_paths.h"
 
 namespace cuttlefish {
@@ -263,61 +266,58 @@ std::set<std::string> ComputeTransitiveClosure(
 
 // Generate a file_context.bin file which can be used by selinux tools to assign
 // selinux labels to files
-bool GenerateFileContexts(const char* output_path,
-                          const std::string& mount_point,
-                          std::string_view file_label) {
-  const auto file_contexts_txt = std::string(output_path) + ".txt";
-  android::base::unique_fd fd(open(file_contexts_txt.c_str(),
-                                   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
-                                   0644));
-  if (!fd.ok()) {
-    PLOG(ERROR) << "Failed to open " << output_path;
-    return false;
-  }
+Result<void> GenerateFileContexts(const std::string& output_path,
+                                  std::string_view mount_point,
+                                  std::string_view file_label) {
+  const std::string file_contexts_txt = output_path + ".txt";
+  SharedFD fd = SharedFD::Open(file_contexts_txt,
+                               O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
+  CF_EXPECTF(fd->IsOpen(), "Can't open '{}': {}", output_path, fd->StrError());
+
+  std::string line = fmt::format("{}(/.*)?         u:object_r:{}:s0\n",
+                                 mount_point, file_label);
+  CF_EXPECT_EQ(WriteAll(fd, line), line.size(), fd->StrError());
+
+  int exit_code = Execute({
+      HostBinaryPath("sefcontext_compile"),
+      "-o",
+      output_path,
+      file_contexts_txt,
+  });
 
-  if (!android::base::WriteStringToFd(
-          fmt::format("{}(/.*)?         u:object_r:{}:s0\n", mount_point,
-                      file_label),
-          fd)) {
-    return false;
-  }
-  Command cmd(HostBinaryPath("sefcontext_compile"));
-  cmd.AddParameter("-o");
-  cmd.AddParameter(output_path);
-  cmd.AddParameter(file_contexts_txt);
-  const auto exit_code = cmd.Start().Wait();
-  return exit_code == 0;
+  CF_EXPECT_EQ(exit_code, 0);
+
+  return {};
 }
 
-bool AddVbmetaFooter(const std::string& output_image,
-                     const std::string& partition_name) {
+Result<void> AddVbmetaFooter(const std::string& output_image,
+                             const std::string& partition_name) {
   // TODO(b/335742241): update to use Avb
-  auto avbtool_path = AvbToolBinary();
-  Command avb_cmd(avbtool_path);
-  // Add host binary path to PATH, so that avbtool can locate host util
-  // binaries such as 'fec'
-  auto PATH =
-      StringFromEnv("PATH", "") + ":" + cpp_dirname(avb_cmd.Executable());
-  // Must unset an existing environment variable in order to modify it
-  avb_cmd.UnsetFromEnvironment("PATH");
-  avb_cmd.AddEnvironmentVariable("PATH", PATH);
-
-  avb_cmd.AddParameter("add_hashtree_footer");
-  // Arbitrary salt to keep output consistent
-  avb_cmd.AddParameter("--salt");
-  avb_cmd.AddParameter("62BBAAA0", "E4BD99E783AC");
-  avb_cmd.AddParameter("--image");
-  avb_cmd.AddParameter(output_image);
-  avb_cmd.AddParameter("--partition_name");
-  avb_cmd.AddParameter(partition_name);
-
-  auto exit_code = avb_cmd.Start().Wait();
-  if (exit_code != 0) {
-    LOG(ERROR) << "Failed to add avb footer to image " << output_image;
-    return false;
-  }
-
-  return true;
+  std::string avbtool_path = AvbToolBinary();
+  // Add host binary path to PATH, so that avbtool can locate host util binaries
+  // such as 'fec'
+  std::string env_path =
+      StringFromEnv("PATH", "") + ":" + android::base::Dirname(avbtool_path);
+  Command avb_cmd =
+      Command(AvbToolBinary())
+          // Must unset an existing environment variable in order to modify it
+          .UnsetFromEnvironment("PATH")
+          .AddEnvironmentVariable("PATH", env_path)
+          .AddParameter("add_hashtree_footer")
+          // Arbitrary salt to keep output consistent
+          .AddParameter("--salt")
+          .AddParameter("62BBAAA0", "E4BD99E783AC")
+          .AddParameter("--hash_algorithm")
+          .AddParameter("sha256")
+          .AddParameter("--image")
+          .AddParameter(output_image)
+          .AddParameter("--partition_name")
+          .AddParameter(partition_name);
+
+  CF_EXPECT_EQ(avb_cmd.Start().Wait(), 0,
+               "Failed to add avb footer to image " << output_image);
+
+  return {};
 }
 
 }  // namespace
@@ -331,30 +331,23 @@ bool AddVbmetaFooter(const std::string& output_image,
 // file_contexts previously generated
 // 5. call avbtool to add hashtree footer, so that init/bootloader can verify
 // AVB chain
-bool BuildDlkmImage(const std::string& src_dir, const bool is_erofs,
-                    const std::string& partition_name,
-                    const std::string& output_image) {
-  if (is_erofs) {
-    LOG(ERROR)
-        << "Building DLKM image in EROFS format is currently not supported!";
-    return false;
-  }
-  const auto mount_point = "/" + partition_name;
-  const auto fs_config = output_image + ".fs_config";
-  if (!WriteFsConfig(fs_config.c_str(), src_dir, mount_point)) {
-    return false;
-  }
-  const auto file_contexts_bin = output_image + ".file_contexts";
+Result<void> BuildDlkmImage(const std::string& src_dir, const bool is_erofs,
+                            const std::string& partition_name,
+                            const std::string& output_image) {
+  CF_EXPECT(!is_erofs,
+            "Building DLKM image in EROFS format is currently not supported!");
+
+  const std::string mount_point = "/" + partition_name;
+  const std::string fs_config = output_image + ".fs_config";
+  CF_EXPECT(WriteFsConfig(fs_config.c_str(), src_dir, mount_point));
+
+  const std::string file_contexts_bin = output_image + ".file_contexts";
   if (partition_name == "system_dlkm") {
-    if (!GenerateFileContexts(file_contexts_bin.c_str(), mount_point,
-                              "system_dlkm_file")) {
-      return false;
-    }
+    CF_EXPECT(GenerateFileContexts(file_contexts_bin.c_str(), mount_point,
+                                   "system_dlkm_file"));
   } else {
-    if (!GenerateFileContexts(file_contexts_bin.c_str(), mount_point,
-                              "vendor_file")) {
-      return false;
-    }
+    CF_EXPECT(GenerateFileContexts(file_contexts_bin.c_str(), mount_point,
+                                   "vendor_file"));
   }
 
   // We are using directory size as an estimate of final image size. To avoid
@@ -362,62 +355,60 @@ bool BuildDlkmImage(const std::string& src_dir, const bool is_erofs,
   const auto fs_size = RoundUp(GetDiskUsage(src_dir) + 16 * 1024 * 1024, 4096);
   LOG(INFO) << mount_point << " src dir " << src_dir << " has size "
             << fs_size / 1024 << " KB";
-  const auto mkfs = HostBinaryPath("mkuserimg_mke2fs");
-  Command mkfs_cmd(mkfs);
-  // Arbitrary UUID/seed, just to keep output consistent between runs
-  mkfs_cmd.AddParameter("--mke2fs_uuid");
-  mkfs_cmd.AddParameter("cb09b942-ed4e-46a1-81dd-7d535bf6c4b1");
-  mkfs_cmd.AddParameter("--mke2fs_hash_seed");
-  mkfs_cmd.AddParameter("765d8aba-d93f-465a-9fcf-14bb794eb7f4");
-  // Arbitrary date, just to keep output consistent
-  mkfs_cmd.AddParameter("-T");
-  mkfs_cmd.AddParameter("900979200000");
-
-  // selinux permission to keep selinux happy
-  mkfs_cmd.AddParameter("--fs_config");
-  mkfs_cmd.AddParameter(fs_config);
-
-  mkfs_cmd.AddParameter(src_dir);
-  mkfs_cmd.AddParameter(output_image);
-  mkfs_cmd.AddParameter("ext4");
-  mkfs_cmd.AddParameter(mount_point);
-  mkfs_cmd.AddParameter(std::to_string(fs_size));
-  mkfs_cmd.AddParameter(file_contexts_bin);
-
-  int exit_code = mkfs_cmd.Start().Wait();
-  if (exit_code != 0) {
-    LOG(ERROR) << "Failed to build vendor_dlkm ext4 image";
-    return false;
-  }
-  return AddVbmetaFooter(output_image, partition_name);
+
+  Command mkfs_cmd =
+      Command(HostBinaryPath("mkuserimg_mke2fs"))
+          // Arbitrary UUID/seed, just to keep output consistent between runs
+          .AddParameter("--mke2fs_uuid")
+          .AddParameter("cb09b942-ed4e-46a1-81dd-7d535bf6c4b1")
+          .AddParameter("--mke2fs_hash_seed")
+          .AddParameter("765d8aba-d93f-465a-9fcf-14bb794eb7f4")
+          // Arbitrary date, just to keep output consistent
+          .AddParameter("-T")
+          .AddParameter(900979200000)
+          // selinux permission to keep selinux happy
+          .AddParameter("--fs_config")
+          .AddParameter(fs_config)
+
+          .AddParameter(src_dir)
+          .AddParameter(output_image)
+          .AddParameter("ext4")
+          .AddParameter(mount_point)
+          .AddParameter(fs_size)
+          .AddParameter(file_contexts_bin);
+
+  CF_EXPECT_EQ(mkfs_cmd.Start().Wait(), 0,
+               "Failed to build vendor_dlkm ext4 image");
+  CF_EXPECT(AddVbmetaFooter(output_image, partition_name));
+
+  return {};
 }
 
-bool RepackSuperWithPartition(const std::string& superimg_path,
-                              const std::string& image_path,
-                              const std::string& partition_name) {
-  Command lpadd(HostBinaryPath("lpadd"));
-  lpadd.AddParameter("--replace");
-  lpadd.AddParameter(superimg_path);
-  lpadd.AddParameter(partition_name + "_a");
-  lpadd.AddParameter("google_vendor_dynamic_partitions_a");
-  lpadd.AddParameter(image_path);
-  const auto exit_code = lpadd.Start().Wait();
-  return exit_code == 0;
+Result<void> RepackSuperWithPartition(const std::string& superimg_path,
+                                      const std::string& image_path,
+                                      const std::string& partition_name) {
+  int exit_code = Execute({
+      HostBinaryPath("lpadd"),
+      "--replace",
+      superimg_path,
+      partition_name + "_a",
+      "google_vendor_dynamic_partitions_a",
+      image_path,
+  });
+  CF_EXPECT_EQ(exit_code, 0);
+
+  return {};
 }
 
-bool BuildVbmetaImage(const std::string& image_path,
-                      const std::string& vbmeta_path) {
-  CHECK(!image_path.empty());
-  CHECK(FileExists(image_path));
+Result<void> BuildVbmetaImage(const std::string& image_path,
+                              const std::string& vbmeta_path) {
+  CF_EXPECT(!image_path.empty());
+  CF_EXPECTF(FileExists(image_path), "'{}' does not exist", image_path);
 
   std::unique_ptr<Avb> avbtool = GetDefaultAvb();
-  Result<void> result = avbtool->MakeVbMetaImage(vbmeta_path, {}, {image_path},
-                                                 {"--padding_size", "4096"});
-  if (!result.ok()) {
-    LOG(ERROR) << result.error().Trace();
-    return false;
-  }
-  return true;
+  CF_EXPECT(avbtool->MakeVbMetaImage(vbmeta_path, {}, {image_path},
+                                     {"--padding_size", "4096"}));
+  return {};
 }
 
 std::vector<std::string> Dedup(std::vector<std::string>&& vec) {
@@ -446,7 +437,7 @@ bool SplitRamdiskModules(const std::string& ramdisk_path,
   LOG(INFO) << "modules.load location " << module_load_file;
   const auto module_list =
       Dedup(android::base::Tokenize(ReadFile(module_load_file), "\n"));
-  const auto module_base_dir = cpp_dirname(module_load_file);
+  const auto module_base_dir = android::base::Dirname(module_load_file);
   const auto deps = LoadModuleDeps(module_base_dir + "/modules.dep");
   const auto ramdisk_modules =
       ComputeTransitiveClosure(GetRamdiskModules(module_list), deps);
@@ -467,13 +458,15 @@ bool SplitRamdiskModules(const std::string& ramdisk_path,
     if (IsKernelModuleSigned(module_location)) {
       const auto system_dlkm_module_location =
           fmt::format("{}/{}", system_modules_dir, module_path);
-      EnsureDirectoryExists(cpp_dirname(system_dlkm_module_location));
+      EnsureDirectoryExists(
+          android::base::Dirname(system_dlkm_module_location));
       RenameFile(module_location, system_dlkm_module_location);
       system_dlkm_modules.emplace(module_path);
     } else {
       const auto vendor_dlkm_module_location =
           fmt::format("{}/{}", vendor_modules_dir, module_path);
-      EnsureDirectoryExists(cpp_dirname(vendor_dlkm_module_location));
+      EnsureDirectoryExists(
+          android::base::Dirname(vendor_dlkm_module_location));
       RenameFile(module_location, vendor_dlkm_module_location);
       vendor_dlkm_modules.emplace(module_path);
     }
diff --git a/host/commands/assemble_cvd/vendor_dlkm_utils.h b/host/commands/assemble_cvd/vendor_dlkm_utils.h
index 0aeac9072..77fcbbee8 100644
--- a/host/commands/assemble_cvd/vendor_dlkm_utils.h
+++ b/host/commands/assemble_cvd/vendor_dlkm_utils.h
@@ -17,6 +17,8 @@
 
 #include <string>
 
+#include "common/libs/utils/result.h"
+
 namespace cuttlefish {
 
 bool SplitRamdiskModules(const std::string& ramdisk_path,
@@ -27,18 +29,16 @@ bool SplitRamdiskModules(const std::string& ramdisk_path,
 bool WriteFsConfig(const char* output_path, const std::string& fs_root,
                    const std::string& mount_point);
 
-bool GenerateFileContexts(const char* output_path,
-                          const std::string& mount_point);
+Result<void> RepackSuperWithPartition(const std::string& superimg_path,
+                                      const std::string& image_path,
+                                      const std::string& partition_name);
 
-bool RepackSuperWithPartition(const std::string& superimg_path,
-                              const std::string& image_path,
-                              const std::string& partition_name);
+Result<void> BuildVbmetaImage(const std::string& vendor_dlkm_img,
+                              const std::string& vbmeta_path);
 
-bool BuildVbmetaImage(const std::string& vendor_dlkm_img,
-                      const std::string& vbmeta_path);
-bool BuildDlkmImage(const std::string& src_dir, const bool is_erofs,
-                    const std::string& partition_name,
-                    const std::string& output_image);
+Result<void> BuildDlkmImage(const std::string& src_dir, const bool is_erofs,
+                            const std::string& partition_name,
+                            const std::string& output_image);
 
 // Move file `src` to `dst` if the contents of these files differ.
 // Return true if and only if the move happened.
diff --git a/host/commands/casimir_control_server/casimir_controller.cpp b/host/commands/casimir_control_server/casimir_controller.cpp
index a2b65e661..0f4bdbb36 100644
--- a/host/commands/casimir_control_server/casimir_controller.cpp
+++ b/host/commands/casimir_control_server/casimir_controller.cpp
@@ -100,7 +100,7 @@ Result<std::shared_ptr<std::vector<uint8_t>>> CasimirController::SendApdu(
   if (rf_packet.IsValid()) {
     auto data = DataView::Create(rf_packet);
     if (data.IsValid() && rf_packet.GetSender() == receiver_id) {
-      return std::make_shared<std::vector<uint8_t>>(std::move(data.GetData()));
+      return std::make_shared<std::vector<uint8_t>>(data.GetData());
     }
   }
   return CF_ERR("Invalid APDU response");
diff --git a/host/commands/cvd_env/Android.bp b/host/commands/cvd_env/Android.bp
index 885088d7c..36162ac71 100644
--- a/host/commands/cvd_env/Android.bp
+++ b/host/commands/cvd_env/Android.bp
@@ -24,7 +24,9 @@ cc_binary_host {
     ],
     shared_libs: [
         "libbase",
+        "libcuttlefish_host_config",
         "libcuttlefish_utils",
+        "libgflags",
         "libgrpc++",
         "libjsoncpp",
         "libprotobuf-cpp-full",
@@ -33,8 +35,6 @@ cc_binary_host {
         "grpc_cli_libs",
         "libabsl_host",
         "libcuttlefish_control_env",
-        "libcuttlefish_host_config",
-        "libgflags",
     ],
     cflags: [
         "-Wno-unused-parameter",
diff --git a/host/commands/gnss_grpc_proxy/gnss_grpc_proxy.cpp b/host/commands/gnss_grpc_proxy/gnss_grpc_proxy.cpp
index 10f94f51c..e9ba3e42b 100644
--- a/host/commands/gnss_grpc_proxy/gnss_grpc_proxy.cpp
+++ b/host/commands/gnss_grpc_proxy/gnss_grpc_proxy.cpp
@@ -442,7 +442,6 @@ void RunServer() {
     return;
   }
 
-  auto server_address("0.0.0.0:" + std::to_string(FLAGS_gnss_grpc_port));
   GnssGrpcProxyServiceImpl service(gnss_in, gnss_out, fixed_location_in,
                                    fixed_location_out);
   service.StartServer();
@@ -457,18 +456,27 @@ void RunServer() {
     }
   } else {
     ServerBuilder builder;
-    // Listen on the given address without any authentication mechanism.
-    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
+
+    if (FLAGS_gnss_grpc_port >= 0) {
+      std::string address = fmt::format("0.0.0.0:{}", FLAGS_gnss_grpc_port);
+      builder.AddListeningPort(address, grpc::InsecureServerCredentials());
+    }
+
     if (!FLAGS_gnss_grpc_socket.empty()) {
-      builder.AddListeningPort("unix:" + FLAGS_gnss_grpc_socket,
-                               grpc::InsecureServerCredentials());
+      std::string address = fmt::format("unix:{}", FLAGS_gnss_grpc_socket);
+      builder.AddListeningPort(address, grpc::InsecureServerCredentials());
     }
     // Register "service" as the instance through which we'll communicate with
     // clients. In this case it corresponds to an *synchronous* service.
     builder.RegisterService(&service);
     // Finally assemble the server.
     std::unique_ptr<Server> server(builder.BuildAndStart());
-    std::cout << "Server listening on " << server_address << std::endl;
+    if (FLAGS_gnss_grpc_port >= 0) {
+      LOG(DEBUG) << "Server listening on port " << FLAGS_gnss_grpc_port;
+    }
+    if (!FLAGS_gnss_grpc_socket.empty()) {
+      LOG(DEBUG) << "Server listening on at " << FLAGS_gnss_grpc_socket;
+    }
 
     // Wait for the server to shutdown. Note that some other thread must be
     // responsible for shutting down the server for this call to ever return.
diff --git a/host/commands/host_bugreport/main.cc b/host/commands/host_bugreport/main.cc
index 299e76174..7767fe1ad 100644
--- a/host/commands/host_bugreport/main.cc
+++ b/host/commands/host_bugreport/main.cc
@@ -18,6 +18,7 @@
 #include <fstream>
 #include <string>
 
+#include <android-base/file.h>
 #include <android-base/logging.h>
 #include <android-base/strings.h>
 #include <gflags/gflags.h>
@@ -25,6 +26,8 @@
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/fs/shared_select.h"
 #include "common/libs/utils/files.h"
+#include "common/libs/utils/subprocess.h"
+#include "common/libs/utils/tee_logging.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "ziparchive/zip_writer.h"
 
@@ -48,10 +51,78 @@ void SaveFile(ZipWriter& writer, const std::string& zip_path,
   }
 }
 
+void AddNetsimdLogs(ZipWriter& writer) {
+  // The temp directory name depends on whether the `USER` environment variable
+  // is defined.
+  // https://source.corp.google.com/h/googleplex-android/platform/superproject/main/+/main:tools/netsim/rust/common/src/system/mod.rs;l=37-57;drc=360ddb57df49472a40275b125bb56af2a65395c7
+  std::string user = StringFromEnv("USER", "");
+  std::string dir = user.empty() ? "/tmp/android/netsimd"
+                                 : fmt::format("/tmp/android-{}/netsimd", user);
+  if (!DirectoryExists(dir)) {
+    LOG(INFO) << "netsimd logs directory: `" << dir << "` does not exist.";
+    return;
+  }
+  auto names = DirectoryContents(dir);
+  if (!names.ok()) {
+    LOG(ERROR) << "Cannot read from netsimd directory `" << dir
+               << "`: " << names.error().FormatForEnv(/* color = */ false);
+    return;
+  }
+  for (const auto& name : names.value()) {
+    SaveFile(writer, "netsimd/" + name, dir + "/" + name);
+  }
+}
+
+Result<void> CreateDeviceBugreport(
+    const CuttlefishConfig::InstanceSpecific& ins, const std::string& out_dir) {
+  std::string adb_bin_path = HostBinaryPath("adb");
+  CF_EXPECT(FileExists(adb_bin_path),
+            "adb binary not found at: " << adb_bin_path);
+  Command connect_cmd("timeout");
+  connect_cmd.SetWorkingDirectory(
+      "/");  // Use a deterministic working directory
+  connect_cmd.AddParameter("30s")
+      .AddParameter(adb_bin_path)
+      .AddParameter("connect")
+      .AddParameter(ins.adb_ip_and_port());
+  CF_EXPECT_EQ(connect_cmd.Start().Wait(), 0, "adb connect failed");
+  Command wait_for_device_cmd("timeout");
+  wait_for_device_cmd.SetWorkingDirectory(
+      "/");  // Use a deterministic working directory
+  wait_for_device_cmd.AddParameter("30s")
+      .AddParameter(adb_bin_path)
+      .AddParameter("-s")
+      .AddParameter(ins.adb_ip_and_port())
+      .AddParameter("wait-for-device");
+  CF_EXPECT_EQ(wait_for_device_cmd.Start().Wait(), 0,
+               "adb wait-for-device failed");
+  Command bugreport_cmd("timeout");
+  bugreport_cmd.SetWorkingDirectory(
+      "/");  // Use a deterministic working directory
+  bugreport_cmd.AddParameter("300s")
+      .AddParameter(adb_bin_path)
+      .AddParameter("-s")
+      .AddParameter(ins.adb_ip_and_port())
+      .AddParameter("bugreport")
+      .AddParameter(out_dir);
+  CF_EXPECT_EQ(bugreport_cmd.Start().Wait(), 0, "adb bugreport failed");
+  return {};
+}
+
 Result<void> CvdHostBugreportMain(int argc, char** argv) {
   ::android::base::InitLogging(argv, android::base::StderrLogger);
   google::ParseCommandLineFlags(&argc, &argv, true);
 
+  std::string log_filename = "/tmp/cvd_hbr.log.XXXXXX";
+  {
+    auto fd = SharedFD::Mkstemp(&log_filename);
+    CF_EXPECT(fd->IsOpen(), "Unable to create log file: " << fd->StrError());
+    android::base::SetLogger(TeeLogger({
+        {ConsoleSeverity(), SharedFD::Dup(2), MetadataLevel::ONLY_MESSAGE},
+        {LogFileSeverity(), fd, MetadataLevel::FULL},
+    }));
+  }
+
   auto config = CuttlefishConfig::Get();
   CHECK(config) << "Unable to find the config";
 
@@ -73,34 +144,84 @@ Result<void> CvdHostBugreportMain(int argc, char** argv) {
     };
     save("cuttlefish_config.json");
     save("disk_config.txt");
-    save("kernel.log");
-    save("launcher.log");
-    save("logcat");
-    save("metrics.log");
-    auto tombstones =
-        CF_EXPECT(DirectoryContents(instance.PerInstancePath("tombstones")),
-                  "Cannot read from tombstones directory.");
-    for (const auto& tombstone : tombstones) {
-      if (tombstone == "." || tombstone == "..") {
-        continue;
+    if (DirectoryExists(instance.PerInstancePath("logs"))) {
+      auto result = DirectoryContents(instance.PerInstancePath("logs"));
+      if (result.ok()) {
+        for (const auto& log : result.value()) {
+          save("logs/" + log);
+        }
+      } else {
+        LOG(ERROR) << "Cannot read from logs directory: "
+                   << result.error().FormatForEnv(/* color = */ false);
       }
-      save("tombstones/" + tombstone);
+    } else {
+      save("kernel.log");
+      save("launcher.log");
+      save("logcat");
+      save("metrics.log");
     }
-    auto recordings =
-        CF_EXPECT(DirectoryContents(instance.PerInstancePath("recording")),
-                  "Cannot read from recording directory.");
-    for (const auto& recording : recordings) {
-      if (recording == "." || recording == "..") {
-        continue;
+
+    {
+      auto result = DirectoryContents(instance.PerInstancePath("tombstones"));
+      if (result.ok()) {
+        for (const auto& tombstone : result.value()) {
+          save("tombstones/" + tombstone);
+        }
+      } else {
+        LOG(ERROR) << "Cannot read from tombstones directory: "
+                   << result.error().FormatForEnv(/* color = */ false);
       }
-      save("recording/" + recording);
+    }
+
+    {
+      auto result = DirectoryContents(instance.PerInstancePath("recording"));
+      if (result.ok()) {
+        for (const auto& recording : result.value()) {
+          save("recording/" + recording);
+        }
+      } else {
+        LOG(ERROR) << "Cannot read from recording directory: "
+                   << result.error().FormatForEnv(/* color = */ false);
+      }
+    }
+
+    {
+      // TODO(b/359657254) Create the `adb bugreport` asynchronously.
+      std::string device_br_dir = "/tmp/cvd_dbrXXXXXX";
+      CF_EXPECTF(mkdtemp(device_br_dir.data()) != nullptr,
+                 "mkdtemp failed: '{}'", strerror(errno));
+      auto result = CreateDeviceBugreport(instance, device_br_dir);
+      if (result.ok()) {
+        auto names = DirectoryContents(device_br_dir);
+        if (names.ok()) {
+          for (const auto& name : names.value()) {
+            std::string filename = device_br_dir + "/" + name;
+            SaveFile(writer, android::base::Basename(filename), filename);
+          }
+        } else {
+          LOG(ERROR) << "Cannot read from device bugreport directory: "
+                     << names.error().FormatForEnv(/* color = */ false);
+        }
+      } else {
+        LOG(ERROR) << "Failed to create device bugreport: "
+                   << result.error().FormatForEnv(/* color = */ false);
+      }
+      static_cast<void>(RecursivelyRemoveDirectory(device_br_dir));
     }
   }
 
+  AddNetsimdLogs(writer);
+
+  SaveFile(writer, "cvd_host_bugreport.log", log_filename);
+
   writer.Finish();
 
   LOG(INFO) << "Saved to \"" << FLAGS_output << "\"";
 
+  if (!RemoveFile(log_filename)) {
+    LOG(INFO) << "Failed to remove host bug report log file: " << log_filename;
+  }
+
   return {};
 }
 
diff --git a/host/commands/kernel_log_monitor/kernel_log_server.cc b/host/commands/kernel_log_monitor/kernel_log_server.cc
index 75f200be3..e7df6c40f 100644
--- a/host/commands/kernel_log_monitor/kernel_log_server.cc
+++ b/host/commands/kernel_log_monitor/kernel_log_server.cc
@@ -26,11 +26,9 @@
 #include "common/libs/fs/shared_select.h"
 #include "host/libs/config/cuttlefish_config.h"
 
+namespace cuttlefish::monitor {
 namespace {
 
-using cuttlefish::SharedFD;
-using monitor::Event;
-
 constexpr struct {
   std::string_view match;   // Substring to match in the kernel logs
   std::string_view prefix;  // Prefix value to output, describing the entry
@@ -51,34 +49,33 @@ constexpr struct {
   Event event;             // emitted when the stage is encountered
   EventFormat format;      // how the log message is formatted
 } kStageTable[] = {
-    {cuttlefish::kBootStartedMessage, Event::BootStarted, kBare},
-    {cuttlefish::kBootPendingMessage, Event::BootPending, kPrefix},
-    {cuttlefish::kBootCompletedMessage, Event::BootCompleted, kBare},
-    {cuttlefish::kBootFailedMessage, Event::BootFailed, kPrefix},
-    {cuttlefish::kMobileNetworkConnectedMessage, Event::MobileNetworkConnected,
-     kBare},
-    {cuttlefish::kWifiConnectedMessage, Event::WifiNetworkConnected, kBare},
-    {cuttlefish::kEthernetConnectedMessage, Event::EthernetNetworkConnected,
-     kBare},
-    {cuttlefish::kAdbdStartedMessage, Event::AdbdStarted, kBare},
-    {cuttlefish::kFastbootdStartedMessage, Event::FastbootStarted, kBare},
-    {cuttlefish::kFastbootStartedMessage, Event::FastbootStarted, kBare},
-    {cuttlefish::kScreenChangedMessage, Event::ScreenChanged, kKeyValuePair},
-    {cuttlefish::kBootloaderLoadedMessage, Event::BootloaderLoaded, kBare},
-    {cuttlefish::kKernelLoadedMessage, Event::KernelLoaded, kBare},
-    {cuttlefish::kDisplayPowerModeChangedMessage,
-     monitor::Event::DisplayPowerModeChanged, kKeyValuePair},
+    {kBootStartedMessage, Event::BootStarted, kBare},
+    {kBootPendingMessage, Event::BootPending, kPrefix},
+    {kBootCompletedMessage, Event::BootCompleted, kBare},
+    {kBootFailedMessage, Event::BootFailed, kPrefix},
+    {kMobileNetworkConnectedMessage, Event::MobileNetworkConnected, kBare},
+    {kWifiConnectedMessage, Event::WifiNetworkConnected, kBare},
+    {kEthernetConnectedMessage, Event::EthernetNetworkConnected, kBare},
+    {kAdbdStartedMessage, Event::AdbdStarted, kBare},
+    {kFastbootdStartedMessage, Event::FastbootStarted, kBare},
+    {kFastbootStartedMessage, Event::FastbootStarted, kBare},
+    {kScreenChangedMessage, Event::ScreenChanged, kKeyValuePair},
+    {kBootloaderLoadedMessage, Event::BootloaderLoaded, kBare},
+    {kKernelLoadedMessage, Event::KernelLoaded, kBare},
+    {kDisplayPowerModeChangedMessage, Event::DisplayPowerModeChanged,
+     kKeyValuePair},
+    {kHibernationExitMessage, Event::HibernationExited, kBare},
+    {kHibernationExitMessage, Event::AdbdStarted, kBare},
 };
 
-void ProcessSubscriptions(
-    Json::Value message,
-    std::vector<monitor::EventCallback>* subscribers) {
+void ProcessSubscriptions(Json::Value message,
+                          std::vector<EventCallback>* subscribers) {
   auto active_subscription_count = subscribers->size();
   std::size_t idx = 0;
   while (idx < active_subscription_count) {
     // Call the callback
     auto action = (*subscribers)[idx](message);
-    if (action == monitor::SubscriptionAction::ContinueSubscription) {
+    if (action == SubscriptionAction::ContinueSubscription) {
       ++idx;
     } else {
       // Cancel the subscription by swapping it with the last active subscription
@@ -92,24 +89,22 @@ void ProcessSubscriptions(
 }
 }  // namespace
 
-namespace monitor {
-KernelLogServer::KernelLogServer(cuttlefish::SharedFD pipe_fd,
-                                 const std::string& log_name)
+KernelLogServer::KernelLogServer(SharedFD pipe_fd, const std::string& log_name)
     : pipe_fd_(pipe_fd),
-      log_fd_(cuttlefish::SharedFD::Open(log_name.c_str(),
-                                         O_CREAT | O_RDWR | O_APPEND, 0666)) {}
+      log_fd_(SharedFD::Open(log_name.c_str(), O_CREAT | O_RDWR | O_APPEND,
+                             0666)) {}
 
-void KernelLogServer::BeforeSelect(cuttlefish::SharedFDSet* fd_read) const {
+void KernelLogServer::BeforeSelect(SharedFDSet* fd_read) const {
   fd_read->Set(pipe_fd_);
 }
 
-void KernelLogServer::AfterSelect(const cuttlefish::SharedFDSet& fd_read) {
+void KernelLogServer::AfterSelect(const SharedFDSet& fd_read) {
   if (fd_read.IsSet(pipe_fd_)) {
     HandleIncomingMessage();
   }
 }
 
-void KernelLogServer::SubscribeToEvents(monitor::EventCallback callback) {
+void KernelLogServer::SubscribeToEvents(EventCallback callback) {
   subscribers_.push_back(callback);
 }
 
@@ -185,4 +180,4 @@ bool KernelLogServer::HandleIncomingMessage() {
   return true;
 }
 
-}  // namespace monitor
+}  // namespace cuttlefish::monitor
diff --git a/host/commands/kernel_log_monitor/kernel_log_server.h b/host/commands/kernel_log_monitor/kernel_log_server.h
index 2e5f8e24d..214827860 100644
--- a/host/commands/kernel_log_monitor/kernel_log_server.h
+++ b/host/commands/kernel_log_monitor/kernel_log_server.h
@@ -26,7 +26,7 @@
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/fs/shared_select.h"
 
-namespace monitor {
+namespace cuttlefish::monitor {
 
 enum Event : int32_t {
   BootStarted = 0,
@@ -44,6 +44,7 @@ enum Event : int32_t {
   DisplayPowerModeChanged = 10,
   FastbootStarted = 11,
   BootPending = 12,
+  HibernationExited = 13,
 };
 
 enum class SubscriptionAction {
@@ -57,17 +58,17 @@ using EventCallback = std::function<SubscriptionAction(Json::Value)>;
 // Only accept one connection.
 class KernelLogServer {
  public:
-  KernelLogServer(cuttlefish::SharedFD pipe_fd, const std::string& log_name);
+  KernelLogServer(SharedFD pipe_fd, const std::string& log_name);
 
   ~KernelLogServer() = default;
 
   // BeforeSelect is Called right before Select() to populate interesting
   // SharedFDs.
-  void BeforeSelect(cuttlefish::SharedFDSet* fd_read) const;
+  void BeforeSelect(SharedFDSet* fd_read) const;
 
   // AfterSelect is Called right after Select() to detect and respond to changes
   // on affected SharedFDs.
-  void AfterSelect(const cuttlefish::SharedFDSet& fd_read);
+  void AfterSelect(const SharedFDSet& fd_read);
 
   void SubscribeToEvents(EventCallback callback);
 
@@ -76,8 +77,8 @@ class KernelLogServer {
   // Returns false, if client disconnected.
   bool HandleIncomingMessage();
 
-  cuttlefish::SharedFD pipe_fd_;
-  cuttlefish::SharedFD log_fd_;
+  SharedFD pipe_fd_;
+  SharedFD log_fd_;
   std::string line_;
   std::vector<EventCallback> subscribers_;
 
@@ -85,4 +86,4 @@ class KernelLogServer {
   KernelLogServer& operator=(const KernelLogServer&) = delete;
 };
 
-}  // namespace monitor
+}  // namespace cuttlefish::monitor
diff --git a/host/commands/kernel_log_monitor/main.cc b/host/commands/kernel_log_monitor/main.cc
index 737548d0d..ad433fe6d 100644
--- a/host/commands/kernel_log_monitor/main.cc
+++ b/host/commands/kernel_log_monitor/main.cc
@@ -40,7 +40,10 @@ DEFINE_string(subscriber_fds, "",
              "A comma separated list of file descriptors (most likely pipes) to"
              " send kernel log events to.");
 
-std::vector<cuttlefish::SharedFD> SubscribersFromCmdline() {
+namespace cuttlefish::monitor {
+namespace {
+
+std::vector<SharedFD> SubscribersFromCmdline() {
   // Validate the parameter
   std::string fd_list = FLAGS_subscriber_fds;
   for (auto c: fd_list) {
@@ -51,10 +54,10 @@ std::vector<cuttlefish::SharedFD> SubscribersFromCmdline() {
   }
 
   auto fds = android::base::Split(FLAGS_subscriber_fds, ",");
-  std::vector<cuttlefish::SharedFD> shared_fds;
+  std::vector<SharedFD> shared_fds;
   for (auto& fd_str: fds) {
     auto fd = std::stoi(fd_str);
-    auto shared_fd = cuttlefish::SharedFD::Dup(fd);
+    auto shared_fd = SharedFD::Dup(fd);
     close(fd);
     shared_fds.push_back(shared_fd);
   }
@@ -62,11 +65,11 @@ std::vector<cuttlefish::SharedFD> SubscribersFromCmdline() {
   return shared_fds;
 }
 
-int main(int argc, char** argv) {
-  cuttlefish::DefaultSubprocessLogging(argv);
+int KernelLogMonitorMain(int argc, char** argv) {
+  DefaultSubprocessLogging(argv);
   google::ParseCommandLineFlags(&argc, &argv, true);
 
-  auto config = cuttlefish::CuttlefishConfig::Get();
+  auto config = CuttlefishConfig::Get();
 
   CHECK(config) << "Could not open cuttlefish config";
 
@@ -80,12 +83,12 @@ int main(int argc, char** argv) {
   new_action.sa_handler = SIG_IGN;
   sigaction(SIGPIPE, &new_action, &old_action);
 
-  cuttlefish::SharedFD pipe;
+  SharedFD pipe;
   if (FLAGS_log_pipe_fd < 0) {
     auto log_name = instance.kernel_log_pipe_name();
-    pipe = cuttlefish::SharedFD::Open(log_name.c_str(), O_RDONLY);
+    pipe = SharedFD::Open(log_name.c_str(), O_RDONLY);
   } else {
-    pipe = cuttlefish::SharedFD::Dup(FLAGS_log_pipe_fd);
+    pipe = SharedFD::Dup(FLAGS_log_pipe_fd);
     close(FLAGS_log_pipe_fd);
   }
 
@@ -94,21 +97,20 @@ int main(int argc, char** argv) {
     return 2;
   }
 
-  monitor::KernelLogServer klog{pipe,
-                                instance.PerInstanceLogPath("kernel.log")};
+  KernelLogServer klog{pipe, instance.PerInstanceLogPath("kernel.log")};
 
   for (auto subscriber_fd: subscriber_fds) {
     if (subscriber_fd->IsOpen()) {
       klog.SubscribeToEvents([subscriber_fd](Json::Value message) {
-        if (!monitor::WriteEvent(subscriber_fd, message)) {
+        if (!WriteEvent(subscriber_fd, message)) {
           if (subscriber_fd->GetErrno() != EPIPE) {
             LOG(ERROR) << "Error while writing to pipe: "
                        << subscriber_fd->StrError();
           }
           subscriber_fd->Close();
-          return monitor::SubscriptionAction::CancelSubscription;
+          return SubscriptionAction::CancelSubscription;
         }
-        return monitor::SubscriptionAction::ContinueSubscription;
+        return SubscriptionAction::ContinueSubscription;
       });
     } else {
       LOG(ERROR) << "Subscriber fd isn't valid: " << subscriber_fd->StrError();
@@ -117,12 +119,12 @@ int main(int argc, char** argv) {
   }
 
   for (;;) {
-    cuttlefish::SharedFDSet fd_read;
+    SharedFDSet fd_read;
     fd_read.Zero();
 
     klog.BeforeSelect(&fd_read);
 
-    int ret = cuttlefish::Select(&fd_read, nullptr, nullptr, nullptr);
+    int ret = Select(&fd_read, nullptr, nullptr, nullptr);
     if (ret <= 0) {
       continue;
     }
@@ -132,3 +134,10 @@ int main(int argc, char** argv) {
 
   return 0;
 }
+
+}  // namespace
+}  // namespace cuttlefish::monitor
+
+int main(int argc, char** argv) {
+  return cuttlefish::monitor::KernelLogMonitorMain(argc, argv);
+}
diff --git a/host/commands/kernel_log_monitor/utils.cc b/host/commands/kernel_log_monitor/utils.cc
index 96496684a..047af4b62 100644
--- a/host/commands/kernel_log_monitor/utils.cc
+++ b/host/commands/kernel_log_monitor/utils.cc
@@ -19,49 +19,44 @@
 #include <android-base/logging.h>
 
 #include "common/libs/fs/shared_buf.h"
+#include "common/libs/utils/json.h"
+#include "common/libs/utils/result.h"
 
-namespace monitor {
+namespace cuttlefish::monitor {
 
-std::optional<ReadEventResult> ReadEvent(cuttlefish::SharedFD fd) {
+Result<std::optional<ReadEventResult>> ReadEvent(SharedFD fd) {
   size_t length;
-  ssize_t bytes_read = cuttlefish::ReadExactBinary(fd, &length);
-  if (bytes_read <= 0) {
-    LOG(ERROR) << "Failed to read event buffer size: " << fd->StrError();
+  ssize_t bytes_read = ReadExactBinary(fd, &length);
+
+  CF_EXPECTF(bytes_read >= 0, "Failed reading length: '{}'", fd->StrError());
+  if (bytes_read == 0) {
     return std::nullopt;
   }
+
   std::string buf(length, ' ');
-  bytes_read = cuttlefish::ReadExact(fd, &buf);
-  if (bytes_read <= 0) {
-    LOG(ERROR) << "Failed to read event buffer: " << fd->StrError();
+  bytes_read = ReadExact(fd, &buf);
+  CF_EXPECTF(bytes_read >= 0, "Failed reading event: '{}'", fd->StrError());
+  if (bytes_read == 0) {
     return std::nullopt;
   }
 
-  Json::CharReaderBuilder builder;
-  std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
-  std::string errorMessage;
-  Json::Value message;
-  if (!reader->parse(&*buf.begin(), &*buf.end(), &message, &errorMessage)) {
-    LOG(ERROR) << "Unable to parse event JSON: " << errorMessage;
-    return std::nullopt;
-  }
+  Json::Value message = CF_EXPECT(ParseJson(buf));
 
-  ReadEventResult result = {
-    static_cast<monitor::Event>(message["event"].asInt()),
-    message["metadata"]
-  };
+  ReadEventResult result = {static_cast<Event>(message["event"].asInt()),
+                            message["metadata"]};
   return result;
 }
 
-bool WriteEvent(cuttlefish::SharedFD fd, const Json::Value& event_message) {
+bool WriteEvent(SharedFD fd, const Json::Value& event_message) {
   Json::StreamWriterBuilder factory;
   std::string message_string = Json::writeString(factory, event_message);
   size_t length = message_string.length();
-  ssize_t retval = cuttlefish::WriteAllBinary(fd, &length);
+  ssize_t retval = WriteAllBinary(fd, &length);
   if (retval <= 0) {
     LOG(ERROR) << "Failed to write event buffer size: " << fd->StrError();
     return false;
   }
-  retval = cuttlefish::WriteAll(fd, message_string);
+  retval = WriteAll(fd, message_string);
   if (retval <= 0) {
     LOG(ERROR) << "Failed to write event buffer: " << fd->StrError();
     return false;
@@ -69,4 +64,4 @@ bool WriteEvent(cuttlefish::SharedFD fd, const Json::Value& event_message) {
   return true;
 }
 
-}  // namespace monitor
+}  // namespace cuttlefish::monitor
diff --git a/host/commands/kernel_log_monitor/utils.h b/host/commands/kernel_log_monitor/utils.h
index 1293a121d..98bfc5c65 100644
--- a/host/commands/kernel_log_monitor/utils.h
+++ b/host/commands/kernel_log_monitor/utils.h
@@ -19,19 +19,23 @@
 #include <optional>
 
 #include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/result.h"
 #include "host/commands/kernel_log_monitor/kernel_log_server.h"
 
-namespace monitor {
+namespace cuttlefish::monitor {
 
 struct ReadEventResult {
   Event event;
   Json::Value metadata;
 };
 
-// Read a kernel log event from fd.
-std::optional<ReadEventResult> ReadEvent(cuttlefish::SharedFD fd);
+// TODO(schuffelen): Remove `std::optional` if `socket_vsock_proxy` doesn't need
+// this distinction.
+/** Read a kernel log event from fd. A failed result indicates an error occurred
+ * while reading the event, while an empty optional indicates EOF. */
+Result<std::optional<ReadEventResult>> ReadEvent(SharedFD fd);
 
 // Writes a kernel log event to the fd, in a format expected by ReadEvent.
-bool WriteEvent(cuttlefish::SharedFD fd, const Json::Value& event_message);
+bool WriteEvent(SharedFD fd, const Json::Value& event_message);
 
-}  // namespace monitor
+}  // namespace cuttlefish::monitor
diff --git a/host/commands/metrics/Android.bp b/host/commands/metrics/Android.bp
index e8749f762..3209c9339 100644
--- a/host/commands/metrics/Android.bp
+++ b/host/commands/metrics/Android.bp
@@ -25,6 +25,11 @@ cc_binary {
         "metrics.cc",
         "utils.cc",
     ],
+    product_variables: {
+        shipping_api_level: {
+            cflags: ["-DPRODUCT_SHIPPING_API_LEVEL=%s"],
+        },
+    },
     shared_libs: [
         "cf_metrics_proto",
         "libbase",
diff --git a/host/commands/metrics/events.cc b/host/commands/metrics/events.cc
index ec0147e9a..4cf9d1bec 100644
--- a/host/commands/metrics/events.cc
+++ b/host/commands/metrics/events.cc
@@ -25,7 +25,6 @@
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/vm_manager/crosvm_manager.h"
 #include "host/libs/vm_manager/qemu_manager.h"
-#include "shared/api_level.h"
 
 namespace cuttlefish {
 
@@ -63,44 +62,44 @@ std::unique_ptr<CuttlefishLogEvent> BuildCfLogEvent(
   return cfEvent;
 }
 
-cuttlefish::MetricsEvent::OsType GetOsType() {
+MetricsEvent::OsType GetOsType() {
   struct utsname buf;
   if (uname(&buf) != 0) {
     LOG(ERROR) << "failed to retrieve system information";
-    return cuttlefish::MetricsEvent::CUTTLEFISH_OS_TYPE_UNSPECIFIED;
+    return MetricsEvent::CUTTLEFISH_OS_TYPE_UNSPECIFIED;
   }
   std::string sysname(buf.sysname);
   std::string machine(buf.machine);
 
   if (sysname != "Linux") {
-    return cuttlefish::MetricsEvent::CUTTLEFISH_OS_TYPE_UNSPECIFIED;
+    return MetricsEvent::CUTTLEFISH_OS_TYPE_UNSPECIFIED;
   }
   if (machine == "x86_64") {
-    return cuttlefish::MetricsEvent::CUTTLEFISH_OS_TYPE_LINUX_X86_64;
+    return MetricsEvent::CUTTLEFISH_OS_TYPE_LINUX_X86_64;
   }
   if (machine == "x86") {
-    return cuttlefish::MetricsEvent::CUTTLEFISH_OS_TYPE_LINUX_X86;
+    return MetricsEvent::CUTTLEFISH_OS_TYPE_LINUX_X86;
   }
   if (machine == "aarch64" || machine == "arm64") {
-    return cuttlefish::MetricsEvent::CUTTLEFISH_OS_TYPE_LINUX_AARCH64;
+    return MetricsEvent::CUTTLEFISH_OS_TYPE_LINUX_AARCH64;
   }
   if (machine[0] == 'a') {
-    return cuttlefish::MetricsEvent::CUTTLEFISH_OS_TYPE_LINUX_AARCH32;
+    return MetricsEvent::CUTTLEFISH_OS_TYPE_LINUX_AARCH32;
   }
-  return cuttlefish::MetricsEvent::CUTTLEFISH_OS_TYPE_UNSPECIFIED;
+  return MetricsEvent::CUTTLEFISH_OS_TYPE_UNSPECIFIED;
 }
 
-cuttlefish::MetricsEvent::VmmType GetVmmManager() {
-  auto config = cuttlefish::CuttlefishConfig::Get();
+MetricsEvent::VmmType GetVmmManager() {
+  auto config = CuttlefishConfig::Get();
   CHECK(config) << "Could not open cuttlefish config";
   auto vmm = config->vm_manager();
-  if (vmm == cuttlefish::VmmMode::kCrosvm) {
-    return cuttlefish::MetricsEvent::CUTTLEFISH_VMM_TYPE_CROSVM;
+  if (vmm == VmmMode::kCrosvm) {
+    return MetricsEvent::CUTTLEFISH_VMM_TYPE_CROSVM;
   }
-  if (vmm == cuttlefish::VmmMode::kQemu) {
-    return cuttlefish::MetricsEvent::CUTTLEFISH_VMM_TYPE_QEMU;
+  if (vmm == VmmMode::kQemu) {
+    return MetricsEvent::CUTTLEFISH_VMM_TYPE_QEMU;
   }
-  return cuttlefish::MetricsEvent::CUTTLEFISH_VMM_TYPE_UNSPECIFIED;
+  return MetricsEvent::CUTTLEFISH_VMM_TYPE_UNSPECIFIED;
 }
 
 // Builds the 2nd level MetricsEvent.
@@ -109,7 +108,7 @@ void AddCfMetricsEventToLog(uint64_t now_ms, CuttlefishLogEvent* cfEvent,
   auto [now_s, now_ns] = ConvertMillisToTime(now_ms);
 
   // "metrics_event" is the 2nd level MetricsEvent
-  cuttlefish::MetricsEvent* metrics_event = cfEvent->mutable_metrics_event();
+  MetricsEvent* metrics_event = cfEvent->mutable_metrics_event();
   metrics_event->set_event_type(event_type);
   metrics_event->set_os_type(GetOsType());
   metrics_event->set_os_version(metrics::GetOsVersion());
@@ -193,10 +192,9 @@ int Clearcut::SendLockScreen(CuttlefishLogEvent::DeviceType device) {
 }
 
 // TODO (moelsherif@): remove this function in the future since it is not used
-cuttlefish::CuttlefishLogEvent* sampleEvent() {
-  cuttlefish::CuttlefishLogEvent* event = new cuttlefish::CuttlefishLogEvent();
-  event->set_device_type(
-      cuttlefish::CuttlefishLogEvent::CUTTLEFISH_DEVICE_TYPE_HOST);
+CuttlefishLogEvent* sampleEvent() {
+  CuttlefishLogEvent* event = new CuttlefishLogEvent();
+  event->set_device_type(CuttlefishLogEvent::CUTTLEFISH_DEVICE_TYPE_HOST);
   return event;
 }
 
@@ -209,4 +207,4 @@ std::string ProtoToString(LogEvent* event) {
   return output;
 }
 
-}  // namespace cuttlefish
\ No newline at end of file
+}  // namespace cuttlefish
diff --git a/host/commands/metrics/events.h b/host/commands/metrics/events.h
index 391361f9a..83ba15e36 100644
--- a/host/commands/metrics/events.h
+++ b/host/commands/metrics/events.h
@@ -21,19 +21,16 @@ namespace cuttlefish {
 
 class Clearcut {
  private:
-  static int SendEvent(cuttlefish::CuttlefishLogEvent::DeviceType device_type,
-                       cuttlefish::MetricsEvent::EventType event_type);
+  static int SendEvent(CuttlefishLogEvent::DeviceType device_type,
+                       MetricsEvent::EventType event_type);
 
  public:
   Clearcut() = default;
   ~Clearcut() = default;
-  static int SendVMStart(
-      cuttlefish::CuttlefishLogEvent::DeviceType device_type);
-  static int SendVMStop(cuttlefish::CuttlefishLogEvent::DeviceType device_type);
-  static int SendDeviceBoot(
-      cuttlefish::CuttlefishLogEvent::DeviceType device_type);
-  static int SendLockScreen(
-      cuttlefish::CuttlefishLogEvent::DeviceType device_type);
+  static int SendVMStart(CuttlefishLogEvent::DeviceType device_type);
+  static int SendVMStop(CuttlefishLogEvent::DeviceType device_type);
+  static int SendDeviceBoot(CuttlefishLogEvent::DeviceType device_type);
+  static int SendLockScreen(CuttlefishLogEvent::DeviceType device_type);
 };
 
 }  // namespace cuttlefish
diff --git a/host/commands/metrics/host_receiver.cc b/host/commands/metrics/host_receiver.cc
index 9eb09f145..02106dc76 100644
--- a/host/commands/metrics/host_receiver.cc
+++ b/host/commands/metrics/host_receiver.cc
@@ -23,8 +23,6 @@
 #include "host/libs/metrics/metrics_receiver.h"
 #include "host/libs/msg_queue/msg_queue.h"
 
-using cuttlefish::MetricsExitCodes;
-
 namespace cuttlefish {
 
 MetricsHostReceiver::MetricsHostReceiver(bool is_metrics_enabled)
@@ -70,7 +68,7 @@ bool MetricsHostReceiver::Initialize(const std::string& metrics_queue_name) {
 }
 
 void MetricsHostReceiver::ProcessMessage(const std::string& text) {
-  auto hostDev = cuttlefish::CuttlefishLogEvent::CUTTLEFISH_DEVICE_TYPE_HOST;
+  auto hostDev = CuttlefishLogEvent::CUTTLEFISH_DEVICE_TYPE_HOST;
 
   int rc = MetricsExitCodes::kSuccess;
 
diff --git a/host/commands/metrics/metrics.cc b/host/commands/metrics/metrics.cc
index 23633ea56..d704c2c50 100644
--- a/host/commands/metrics/metrics.cc
+++ b/host/commands/metrics/metrics.cc
@@ -21,32 +21,32 @@
 #include "host/commands/metrics/metrics_defs.h"
 #include "host/libs/config/cuttlefish_config.h"
 
-using cuttlefish::MetricsExitCodes;
+namespace cuttlefish {
+namespace {
 
-int main(int argc, char** argv) {
+int MetricsMain(int argc, char** argv) {
   google::ParseCommandLineFlags(&argc, &argv, true);
   ::android::base::InitLogging(argv, android::base::StderrLogger);
-  auto config = cuttlefish::CuttlefishConfig::Get();
+  auto config = CuttlefishConfig::Get();
   CHECK(config) << "Could not open cuttlefish config";
   auto instance = config->ForDefaultInstance();
   auto metrics_log_path = instance.PerInstanceLogPath("metrics.log");
   if (instance.run_as_daemon()) {
     android::base::SetLogger(
-        cuttlefish::LogToFiles({metrics_log_path, instance.launcher_log_path()}));
+        LogToFiles({metrics_log_path, instance.launcher_log_path()}));
   } else {
     android::base::SetLogger(
-        cuttlefish::LogToStderrAndFiles(
-            {metrics_log_path, instance.launcher_log_path()}));
+        LogToStderrAndFiles({metrics_log_path, instance.launcher_log_path()}));
   }
-  if (config->enable_metrics() != cuttlefish::CuttlefishConfig::Answer::kYes) {
+  if (config->enable_metrics() != CuttlefishConfig::Answer::kYes) {
     LOG(ERROR) << "metrics not enabled, but metrics were launched.";
     return MetricsExitCodes::kInvalidHostConfiguration;
   }
 
   bool is_metrics_enabled =
-      cuttlefish::CuttlefishConfig::Answer::kYes == config->enable_metrics();
-  cuttlefish::MetricsHostReceiver host_receiver(is_metrics_enabled);
-  if (!host_receiver.Initialize(cuttlefish::kCfMetricsQueueName)) {
+      CuttlefishConfig::Answer::kYes == config->enable_metrics();
+  MetricsHostReceiver host_receiver(is_metrics_enabled);
+  if (!host_receiver.Initialize(kCfMetricsQueueName)) {
     LOG(ERROR) << "metrics host_receiver failed to init";
     return MetricsExitCodes::kMetricsError;
   }
@@ -54,3 +54,8 @@ int main(int argc, char** argv) {
   host_receiver.Join();
   return MetricsExitCodes::kMetricsError;
 }
+
+}  // namespace
+}  // namespace cuttlefish
+
+int main(int argc, char** argv) { return cuttlefish::MetricsMain(argc, argv); }
diff --git a/host/commands/metrics/utils.cc b/host/commands/metrics/utils.cc
index 0a1d6fe48..1f03b5312 100644
--- a/host/commands/metrics/utils.cc
+++ b/host/commands/metrics/utils.cc
@@ -31,9 +31,7 @@
 #include "host/commands/metrics/metrics_defs.h"
 #include "host/commands/metrics/utils.h"
 
-using cuttlefish::MetricsExitCodes;
-
-namespace metrics {
+namespace cuttlefish::metrics {
 
 static std::string Hashing(const std::string& input) {
   const std::hash<std::string> hasher;
@@ -165,7 +163,7 @@ MetricsExitCodes PostRequest(const std::string& output,
   std::unique_ptr<CURLU, void (*)(CURLU*)> url(curl_url(), curl_url_cleanup);
   if (!url) {
     LOG(ERROR) << "Failed to initialize CURLU.";
-    return cuttlefish::kMetricsError;
+    return kMetricsError;
   }
 
   CURLUcode urc =
@@ -173,7 +171,7 @@ MetricsExitCodes PostRequest(const std::string& output,
   if (urc != 0) {
     LOG(ERROR) << "Failed to set url to " << url.get() << clearcut_url
                << "': " << curl_url_strerror(urc) << "'";
-    return cuttlefish::kMetricsError;
+    return kMetricsError;
   }
   curl_global_init(CURL_GLOBAL_ALL);
 
@@ -182,7 +180,7 @@ MetricsExitCodes PostRequest(const std::string& output,
 
   if (!curl) {
     LOG(ERROR) << "Failed to initialize CURL.";
-    return cuttlefish::kMetricsError;
+    return kMetricsError;
   }
 
   curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, &curl_out_writer);
@@ -198,10 +196,11 @@ MetricsExitCodes PostRequest(const std::string& output,
     LOG(ERROR) << "Metrics message failed: [" << output << "]";
     LOG(ERROR) << "http error code: " << http_code;
     LOG(ERROR) << "curl error code: " << rc << " | " << curl_easy_strerror(rc);
-    return cuttlefish::kMetricsError;
+    return kMetricsError;
   }
   LOG(INFO) << "Metrics posted to ClearCut";
   curl_global_cleanup();
-  return cuttlefish::kSuccess;
+  return kSuccess;
 }
-}  // namespace metrics
+
+}  // namespace cuttlefish::metrics
diff --git a/host/commands/metrics/utils.h b/host/commands/metrics/utils.h
index e78019547..60dce86d8 100644
--- a/host/commands/metrics/utils.h
+++ b/host/commands/metrics/utils.h
@@ -15,12 +15,11 @@
  */
 #pragma once
 
-#include <string.h>
-
 #include <clientanalytics.pb.h>
 #include "host/commands/metrics/metrics_defs.h"
 
-namespace metrics {
+namespace cuttlefish::metrics {
+
 enum ClearcutServer : int {
   kLocal = 0,
   kStaging = 1,
@@ -36,7 +35,6 @@ std::string GetCompany();
 std::string GetVmmVersion();
 uint64_t GetEpochTimeMs();
 std::string ProtoToString(LogEvent* event);
-cuttlefish::MetricsExitCodes PostRequest(const std::string& output,
-                                         ClearcutServer server);
+MetricsExitCodes PostRequest(const std::string& output, ClearcutServer server);
 
-}  // namespace metrics
+}  // namespace cuttlefish::metrics
diff --git a/host/commands/openwrt_control_server/main.cpp b/host/commands/openwrt_control_server/main.cpp
index f1a7ba89c..1b8a6cb07 100644
--- a/host/commands/openwrt_control_server/main.cpp
+++ b/host/commands/openwrt_control_server/main.cpp
@@ -59,6 +59,12 @@ constexpr char kErrorMessageRpcAuth[] = "Luci authentication request failed";
 
 namespace cuttlefish {
 
+static Status ErrorResultToStatus(const std::string_view prefix,
+                                  const StackTraceError& error) {
+  std::string msg = fmt::format("{}:\n\n{}", prefix, error.FormatForEnv(false));
+  return Status(StatusCode::UNAVAILABLE, msg);
+}
+
 class OpenwrtControlServiceImpl final : public OpenwrtControlService::Service {
  public:
   OpenwrtControlServiceImpl(HttpClient& http_client)
@@ -68,8 +74,9 @@ class OpenwrtControlServiceImpl final : public OpenwrtControlService::Service {
                  LuciRpcReply* response) override {
     // Update authentication key when it's empty.
     if (auth_key_.empty()) {
-      if (!TypeIsSuccess(UpdateLuciRpcAuthKey())) {
-        return Status(StatusCode::UNAVAILABLE, kErrorMessageRpcAuth);
+      Result<void> auth_res = UpdateLuciRpcAuthKey();
+      if (!auth_res.ok()) {
+        return ErrorResultToStatus(kErrorMessageRpcAuth, auth_res.error());
       }
     }
 
@@ -77,14 +84,15 @@ class OpenwrtControlServiceImpl final : public OpenwrtControlService::Service {
                                 ToVector(request->params()));
 
     // When RPC request fails, update authentication key and retry once.
-    if (!TypeIsSuccess(reply)) {
-      if (!TypeIsSuccess(UpdateLuciRpcAuthKey())) {
-        return Status(StatusCode::UNAVAILABLE, kErrorMessageRpcAuth);
+    if (!reply.ok()) {
+      Result<void> auth_res = UpdateLuciRpcAuthKey();
+      if (!auth_res.ok()) {
+        return ErrorResultToStatus(kErrorMessageRpcAuth, auth_res.error());
       }
       reply = RequestLuciRpc(request->subpath(), request->method(),
                              ToVector(request->params()));
-      if (!TypeIsSuccess(reply)) {
-        return Status(StatusCode::UNAVAILABLE, kErrorMessageRpc);
+      if (!reply.ok()) {
+        return ErrorResultToStatus(kErrorMessageRpc, reply.error());
       }
     }
 
@@ -100,10 +108,10 @@ class OpenwrtControlServiceImpl final : public OpenwrtControlService::Service {
                        OpenwrtIpaddrReply* response) override {
     // TODO(seungjaeyoo) : Find IP address from crosvm_openwrt.log when using
     // cvd-wtap-XX after disabling DHCP inside OpenWRT in bridged_wifi_tap mode.
-    auto ipaddr = FindIpaddrLauncherLog();
-    if (!TypeIsSuccess(ipaddr)) {
-      return Status(StatusCode::FAILED_PRECONDITION,
-                    "Failed to get Openwrt IP address");
+    Result<std::string> ipaddr = FindIpaddrLauncherLog();
+    if (!ipaddr.ok()) {
+      return ErrorResultToStatus("Failed to get Openwrt IP address",
+                                 ipaddr.error());
     }
     response->set_ipaddr(*ipaddr);
     return Status::OK;
@@ -237,4 +245,4 @@ int main(int argc, char** argv) {
   RunServer();
 
   return 0;
-}
\ No newline at end of file
+}
diff --git a/host/commands/process_restarter/Android.bp b/host/commands/process_restarter/Android.bp
index d5c59f49e..1944f30f0 100644
--- a/host/commands/process_restarter/Android.bp
+++ b/host/commands/process_restarter/Android.bp
@@ -12,21 +12,21 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
 cc_binary_host {
     name: "process_restarter",
-    defaults: ["cuttlefish_host",],
-    srcs: ["main.cc", "parser.cc"],
+    defaults: ["cuttlefish_host"],
+    srcs: [
+        "main.cc",
+        "parser.cc",
+    ],
     shared_libs: [
         "libbase",
+        "libcuttlefish_host_config",
         "libcuttlefish_utils",
         "libjsoncpp",
     ],
-    static_libs: [
-        "libcuttlefish_host_config",
-    ],
 }
diff --git a/host/commands/process_sandboxer/Android.bp b/host/commands/process_sandboxer/Android.bp
index a685a7194..2ae909c4b 100644
--- a/host/commands/process_sandboxer/Android.bp
+++ b/host/commands/process_sandboxer/Android.bp
@@ -24,15 +24,91 @@ cc_binary_host {
     name: "process_sandboxer",
     defaults: ["cuttlefish_buildhost_only"],
     srcs: [
+        "credentialed_unix_server.cpp",
+        "filesystem.cpp",
+        "logs.cpp",
         "main.cpp",
+        "pidfd.cpp",
         "policies.cpp",
+        "policies/adb_connector.cpp",
+        "policies/assemble_cvd.cpp",
+        "policies/avbtool.cpp",
+        "policies/baseline.cpp",
+        "policies/casimir.cpp",
+        "policies/casimir_control_server.cpp",
+        "policies/control_env_proxy_server.cpp",
+        "policies/cvd_internal_start.cpp",
+        "policies/echo_server.cpp",
+        "policies/gnss_grpc_proxy.cpp",
         "policies/kernel_log_monitor.cpp",
+        "policies/log_tee.cpp",
         "policies/logcat_receiver.cpp",
+        "policies/metrics.cpp",
+        "policies/mkenvimage_slim.cpp",
+        "policies/modem_simulator.cpp",
+        "policies/netsimd.cpp",
+        "policies/newfs_msdos.cpp",
+        "policies/no_policy.cpp",
+        "policies/openwrt_control_server.cpp",
+        "policies/operator_proxy.cpp",
+        "policies/process_restarter.cpp",
+        "policies/run_cvd.cpp",
+        "policies/screen_recording_server.cpp",
+        "policies/secure_env.cpp",
+        "policies/simg2img.cpp",
+        "policies/socket_vsock_proxy.cpp",
+        "policies/tcp_connector.cpp",
+        "policies/tombstone_receiver.cpp",
+        "policies/vhost_device_vsock.cpp",
+        "policies/webrtc.cpp",
+        "policies/webrtc_operator.cpp",
+        "policies/wmediumd.cpp",
+        "policies/wmediumd_gen_config.cpp",
+        "poll_callback.cpp",
+        "sandbox_manager.cpp",
+        "signal_fd.cpp",
+        "unique_fd.cpp",
     ],
     shared_libs: ["sandboxed_api_sandbox2"],
     static_libs: [
         "libabsl_host",
         "libcap",
+        "libprocess_sandboxer_proxy_common",
+    ],
+    target: {
+        darwin: {
+            enabled: false,
+        },
+        windows: {
+            enabled: false,
+        },
+    },
+}
+
+cc_library_static {
+    name: "libprocess_sandboxer_proxy_common",
+    defaults: ["cuttlefish_buildhost_only"],
+    srcs: ["proxy_common.cpp"],
+    static_libs: ["libabsl_host"],
+    target: {
+        darwin: {
+            enabled: false,
+        },
+        windows: {
+            enabled: false,
+        },
+    },
+}
+
+cc_binary_host {
+    name: "sandboxer_proxy",
+    defaults: ["cuttlefish_buildhost_only"],
+    srcs: [
+        "sandboxer_proxy.cpp",
+    ],
+    static_libs: [
+        "libabsl_host",
+        "libprocess_sandboxer_proxy_common",
     ],
     target: {
         darwin: {
diff --git a/host/commands/process_sandboxer/credentialed_unix_server.cpp b/host/commands/process_sandboxer/credentialed_unix_server.cpp
new file mode 100644
index 000000000..3aac0ab73
--- /dev/null
+++ b/host/commands/process_sandboxer/credentialed_unix_server.cpp
@@ -0,0 +1,74 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/credentialed_unix_server.h"
+
+#include <sys/socket.h>
+#include <sys/un.h>
+
+#include <cstring>
+#include <string>
+
+#include <absl/status/statusor.h>
+
+#include "host/commands/process_sandboxer/unique_fd.h"
+
+namespace cuttlefish::process_sandboxer {
+
+CredentialedUnixServer::CredentialedUnixServer(UniqueFd fd)
+    : fd_(std::move(fd)) {}
+
+absl::StatusOr<CredentialedUnixServer> CredentialedUnixServer::Open(
+    const std::string& path) {
+  UniqueFd fd(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
+
+  if (fd.Get() < 0) {
+    return absl::ErrnoToStatus(errno, "`socket` failed");
+  }
+  sockaddr_un socket_name = {
+      .sun_family = AF_UNIX,
+  };
+  std::snprintf(socket_name.sun_path, sizeof(socket_name.sun_path), "%s",
+                path.c_str());
+  sockaddr* sockname_ptr = reinterpret_cast<sockaddr*>(&socket_name);
+  if (bind(fd.Get(), sockname_ptr, sizeof(socket_name)) < 0) {
+    return absl::ErrnoToStatus(errno, "`bind` failed");
+  }
+
+  int enable_passcred = 1;
+  if (setsockopt(fd.Get(), SOL_SOCKET, SO_PASSCRED, &enable_passcred,
+                 sizeof(enable_passcred)) < 0) {
+    static constexpr char kErr[] = "`setsockopt(..., SO_PASSCRED, ...)` failed";
+    return absl::ErrnoToStatus(errno, kErr);
+  }
+
+  if (listen(fd.Get(), 10) < 0) {
+    return absl::ErrnoToStatus(errno, "`listen` failed");
+  }
+
+  return CredentialedUnixServer(std::move(fd));
+}
+
+absl::StatusOr<UniqueFd> CredentialedUnixServer::AcceptClient() {
+  UniqueFd client(accept4(fd_.Get(), nullptr, nullptr, SOCK_CLOEXEC));
+  if (client.Get() < 0) {
+    return absl::ErrnoToStatus(errno, "`accept` failed");
+  }
+  return client;
+}
+
+int CredentialedUnixServer::Fd() const { return fd_.Get(); }
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/credentialed_unix_server.h b/host/commands/process_sandboxer/credentialed_unix_server.h
new file mode 100644
index 000000000..aa149b837
--- /dev/null
+++ b/host/commands/process_sandboxer/credentialed_unix_server.h
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#ifndef ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_CREDENTIALED_UNIX_SERVER_H
+#define ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_CREDENTIALED_UNIX_SERVER_H
+
+#include <string>
+
+#include <absl/status/statusor.h>
+
+#include "host/commands/process_sandboxer/unique_fd.h"
+
+namespace cuttlefish::process_sandboxer {
+
+class CredentialedUnixServer {
+ public:
+  static absl::StatusOr<CredentialedUnixServer> Open(const std::string& path);
+
+  absl::StatusOr<UniqueFd> AcceptClient();
+
+  int Fd() const;
+
+ private:
+  CredentialedUnixServer(UniqueFd);
+
+  UniqueFd fd_;
+};
+
+}  // namespace cuttlefish::process_sandboxer
+
+#endif
diff --git a/host/commands/process_sandboxer/filesystem.cpp b/host/commands/process_sandboxer/filesystem.cpp
new file mode 100644
index 000000000..5de15cc25
--- /dev/null
+++ b/host/commands/process_sandboxer/filesystem.cpp
@@ -0,0 +1,131 @@
+// Copyright 2019 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include "host/commands/process_sandboxer/filesystem.h"
+
+#include <sys/stat.h>
+
+#include <deque>
+#include <initializer_list>
+#include <string>
+#include <string_view>
+
+#include <absl/strings/str_cat.h>
+#include <absl/strings/str_join.h>
+#include <absl/strings/str_split.h>
+#include <absl/strings/strip.h>
+
+namespace cuttlefish::process_sandboxer {
+
+// Copied from sandboxed_api/util/path.cc
+
+namespace internal {
+
+constexpr char kPathSeparator[] = "/";
+
+std::string JoinPathImpl(std::initializer_list<absl::string_view> paths) {
+  std::string result;
+  for (const auto& path : paths) {
+    if (path.empty()) {
+      continue;
+    }
+    if (result.empty()) {
+      absl::StrAppend(&result, path);
+      continue;
+    }
+    const auto comp = absl::StripPrefix(path, kPathSeparator);
+    if (absl::EndsWith(result, kPathSeparator)) {
+      absl::StrAppend(&result, comp);
+    } else {
+      absl::StrAppend(&result, kPathSeparator, comp);
+    }
+  }
+  return result;
+}
+
+}  // namespace internal
+
+// Copied from sandboxed_api/util/fileops.cc
+
+namespace {
+
+std::string StripBasename(std::string_view path) {
+  const auto last_slash = path.find_last_of('/');
+  if (last_slash == std::string::npos) {
+    return "";
+  }
+  if (last_slash == 0) {
+    return "/";
+  }
+  return std::string(path.substr(0, last_slash));
+}
+
+}  // namespace
+
+bool CreateDirectoryRecursively(const std::string& path, int mode) {
+  if (mkdir(path.c_str(), mode) == 0 || errno == EEXIST) {
+    return true;
+  }
+
+  // We couldn't create the dir for reasons we can't handle.
+  if (errno != ENOENT) {
+    return false;
+  }
+
+  // The ENOENT case, the parent directory doesn't exist yet.
+  // Let's create it.
+  const std::string dir = StripBasename(path);
+  if (dir == "/" || dir.empty()) {
+    return false;
+  }
+  if (!CreateDirectoryRecursively(dir, mode)) {
+    return false;
+  }
+
+  // Now the parent dir exists, retry creating the directory.
+  return mkdir(path.c_str(), mode) == 0;
+}
+
+std::string CleanPath(const std::string_view unclean_path) {
+  int dotdot_num = 0;
+  std::deque<absl::string_view> parts;
+  for (absl::string_view part :
+       absl::StrSplit(unclean_path, '/', absl::SkipEmpty())) {
+    if (part == "..") {
+      if (parts.empty()) {
+        ++dotdot_num;
+      } else {
+        parts.pop_back();
+      }
+    } else if (part != ".") {
+      parts.push_back(part);
+    }
+  }
+  if (absl::StartsWith(unclean_path, "/")) {
+    if (parts.empty()) {
+      return "/";
+    }
+    parts.push_front("");
+  } else {
+    for (; dotdot_num; --dotdot_num) {
+      parts.push_front("..");
+    }
+    if (parts.empty()) {
+      return ".";
+    }
+  }
+  return absl::StrJoin(parts, "/");
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/filesystem.h b/host/commands/process_sandboxer/filesystem.h
new file mode 100644
index 000000000..26d9c4b8a
--- /dev/null
+++ b/host/commands/process_sandboxer/filesystem.h
@@ -0,0 +1,49 @@
+// Copyright 2019 Google LLC
+//
+// Licensed under the Apache License, Version 2.0 (the "License");
+// you may not use this file except in compliance with the License.
+// You may obtain a copy of the License at
+//
+//     https://www.apache.org/licenses/LICENSE-2.0
+//
+// Unless required by applicable law or agreed to in writing, software
+// distributed under the License is distributed on an "AS IS" BASIS,
+// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+// See the License for the specific language governing permissions and
+// limitations under the License.
+
+#include <initializer_list>
+#include <string>
+#include <string_view>
+
+namespace cuttlefish::process_sandboxer {
+
+// Copied from sandboxed_api/util/fileops.h
+
+// Recursively creates a directory, skipping segments that already exist.
+bool CreateDirectoryRecursively(const std::string& path, int mode);
+
+// Copied from sandboxed_api/util/path.h
+
+namespace internal {
+// Not part of the public API.
+std::string JoinPathImpl(std::initializer_list<std::string_view> paths);
+}  // namespace internal
+
+// Joins multiple paths together using the platform-specific path separator.
+// Arguments must be convertible to absl::string_view.
+template <typename... T>
+inline std::string JoinPath(const T&... args) {
+  return internal::JoinPathImpl({args...});
+}
+
+// Collapses duplicate "/"s, resolve ".." and "." path elements, removes
+// trailing "/".
+//
+// NOTE: This respects relative vs. absolute paths, but does not
+// invoke any system calls in order to resolve relative paths to the actual
+// working directory. That is, this is purely a string manipulation, completely
+// independent of process state.
+std::string CleanPath(std::string_view path);
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/logs.cpp b/host/commands/process_sandboxer/logs.cpp
new file mode 100644
index 000000000..adbb643eb
--- /dev/null
+++ b/host/commands/process_sandboxer/logs.cpp
@@ -0,0 +1,90 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/logs.h"
+
+#include <fcntl.h>
+#include <unistd.h>
+
+#include <memory>
+#include <sstream>
+#include <string>
+
+#include <absl/log/log.h>
+#include <absl/log/log_sink.h>
+#include <absl/log/log_sink_registry.h>
+#include <absl/status/statusor.h>
+
+namespace cuttlefish {
+namespace process_sandboxer {
+namespace {
+
+// Implementation based on absl::log_internal::StderrLogSink
+class FileLogSink final : absl::LogSink {
+ public:
+  static absl::StatusOr<std::unique_ptr<FileLogSink>> FromPath(
+      const std::string& path) {
+    std::unique_ptr<FileLogSink> sink(new FileLogSink());
+    sink->fd_ = open(path.c_str(), O_APPEND | O_CREAT | O_WRONLY, 0666);
+    if (sink->fd_ < 0) {
+      return absl::ErrnoToStatus(errno, "open failed");
+    }
+    absl::AddLogSink(sink.get());
+    return sink;
+  }
+  FileLogSink(FileLogSink&) = delete;
+  ~FileLogSink() {
+    absl::RemoveLogSink(this);
+    if (fd_ >= 0 && close(fd_) < 0) {
+      PLOG(ERROR) << "Failed to close fd '" << fd_ << "'";
+    }
+  }
+
+  void Send(const absl::LogEntry& entry) override {
+    std::stringstream message_stream;
+    if (!entry.stacktrace().empty()) {
+      message_stream << entry.stacktrace();
+    }
+    message_stream << entry.text_message_with_prefix_and_newline();
+    auto message = message_stream.str();
+    auto written = write(fd_, message.c_str(), message.size());
+    if (written < 0) {
+      // LOG calls inside here would recurse infinitely because of AddLogSink
+      std::cerr << "FileLogSink: write(" << fd_
+                << ") failed: " << strerror(errno) << '\n';
+    }
+  }
+
+ private:
+  FileLogSink() = default;
+
+  int fd_ = -1;
+};
+
+}  // namespace
+
+absl::Status LogToFiles(const std::vector<std::string>& paths) {
+  for (const auto& path : paths) {
+    auto sink_status = FileLogSink::FromPath(path);
+    if (!sink_status.ok()) {
+      return sink_status.status();
+    }
+    sink_status->release();  // Deliberate leak so LOG always writes here
+  }
+  return absl::OkStatus();
+}
+
+}  // namespace process_sandboxer
+}  // namespace cuttlefish
diff --git a/host/commands/process_sandboxer/logs.h b/host/commands/process_sandboxer/logs.h
new file mode 100644
index 000000000..081dae56e
--- /dev/null
+++ b/host/commands/process_sandboxer/logs.h
@@ -0,0 +1,35 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#ifndef ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_LOGS_H
+#define ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_LOGS_H
+
+#include <memory>
+#include <string>
+#include <vector>
+
+#include <absl/log/log_sink.h>
+#include <absl/status/status.h>
+#include <absl/status/statusor.h>
+
+namespace cuttlefish {
+namespace process_sandboxer {
+
+absl::Status LogToFiles(const std::vector<std::string>& paths);
+
+}  // namespace process_sandboxer
+}  // namespace cuttlefish
+
+#endif
diff --git a/host/commands/process_sandboxer/main.cpp b/host/commands/process_sandboxer/main.cpp
index 2ddcfb5f3..9197c046f 100644
--- a/host/commands/process_sandboxer/main.cpp
+++ b/host/commands/process_sandboxer/main.cpp
@@ -14,68 +14,227 @@
  * limitations under the License.
  */
 
+#include <fcntl.h>
 #include <stdlib.h>
+#include <sys/prctl.h>
 
 #include <memory>
+#include <optional>
 #include <string>
+#include <string_view>
+#include <utility>
 #include <vector>
 
-#include "absl/flags/flag.h"
-#include "absl/flags/parse.h"
-#include "absl/log/check.h"
-#include "absl/log/initialize.h"
-#include "absl/strings/numbers.h"
-#pragma clang diagnostic push
-#pragma clang diagnostic ignored "-Wunused-parameter"
-#include "sandboxed_api/sandbox2/executor.h"
-#include "sandboxed_api/sandbox2/sandbox2.h"
-#pragma clang diagnostic pop
-#include "sandboxed_api/util/path.h"
-
+#include <absl/flags/flag.h>
+#include <absl/flags/parse.h>
+#include <absl/log/check.h>
+#include <absl/log/globals.h>
+#include <absl/log/initialize.h>
+#include <absl/log/log.h>
+#include <absl/status/status.h>
+#include <absl/strings/numbers.h>
+#include <absl/strings/str_cat.h>
+
+#include "host/commands/process_sandboxer/filesystem.h"
+#include "host/commands/process_sandboxer/logs.h"
+#include "host/commands/process_sandboxer/pidfd.h"
 #include "host/commands/process_sandboxer/policies.h"
+#include "host/commands/process_sandboxer/sandbox_manager.h"
+#include "host/commands/process_sandboxer/unique_fd.h"
 
 inline constexpr char kCuttlefishConfigEnvVarName[] = "CUTTLEFISH_CONFIG_FILE";
 
+ABSL_FLAG(std::string, assembly_dir, "", "cuttlefish/assembly build dir");
 ABSL_FLAG(std::string, host_artifacts_path, "", "Host exes and libs");
+ABSL_FLAG(std::string, environments_dir, "", "Cross-instance environment dir");
+ABSL_FLAG(std::string, environments_uds_dir, "", "Environment unix sockets");
+ABSL_FLAG(std::string, instance_uds_dir, "", "Instance unix domain sockets");
+ABSL_FLAG(std::string, guest_image_path, "", "Directory with `system.img`");
 ABSL_FLAG(std::string, log_dir, "", "Where to write log files");
-ABSL_FLAG(std::vector<std::string>, inherited_fds, std::vector<std::string>(),
-          "File descriptors to keep in the sandbox");
+ABSL_FLAG(std::vector<std::string>, log_files, std::vector<std::string>(),
+          "File paths outside the sandbox to write logs to");
+ABSL_FLAG(std::string, runtime_dir, "",
+          "Working directory of host executables");
+ABSL_FLAG(bool, verbose_stderr, false, "Write debug messages to stderr");
+ABSL_FLAG(std::string, vsock_device_dir, "/tmp/vsock_3_1000",
+          "Directory path for unix sockets representing vsock connections");
+
+namespace cuttlefish::process_sandboxer {
+namespace {
+
+std::optional<std::string_view> FromEnv(const std::string& name) {
+  char* value = getenv(name.c_str());
+  return value == NULL ? std::optional<std::string_view>() : value;
+}
 
-using sapi::file::CleanPath;
-using sapi::file::JoinPath;
+absl::Status ProcessSandboxerMain(int argc, char** argv) {
+  std::vector<char*> args = absl::ParseCommandLine(argc, argv);
+  /* When building in AOSP, the flags in absl/log/flags.cc are missing. This
+   * uses the absl/log/globals.h interface to log ERROR severity to stderr, and
+   * write all LOG and VLOG(1) messages to log sinks pointing to log files. */
+  absl::InitializeLog();
+  if (absl::GetFlag(FLAGS_verbose_stderr)) {
+    absl::SetStderrThreshold(absl::LogSeverity::kError);
+  } else {
+    absl::SetStderrThreshold(absl::LogSeverity::kInfo);
+  }
+  absl::EnableLogPrefix(true);
+  absl::SetGlobalVLogLevel(1);
 
-namespace cuttlefish {
+  if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
+    return absl::ErrnoToStatus(errno, "prctl(PR_SET_CHILD_SUBREAPER failed");
+  }
 
-int ProcessSandboxerMain(int argc, char** argv) {
-  absl::InitializeLog();
-  auto args = absl::ParseCommandLine(argc, argv);
+  HostInfo host{
+      .assembly_dir = CleanPath(absl::GetFlag(FLAGS_assembly_dir)),
+      .cuttlefish_config_path =
+          CleanPath(FromEnv(kCuttlefishConfigEnvVarName).value_or("")),
+      .environments_dir = CleanPath(absl::GetFlag(FLAGS_environments_dir)),
+      .environments_uds_dir =
+          CleanPath(absl::GetFlag(FLAGS_environments_uds_dir)),
+      .guest_image_path = CleanPath(absl::GetFlag(FLAGS_guest_image_path)),
+      .host_artifacts_path =
+          CleanPath(absl::GetFlag(FLAGS_host_artifacts_path)),
+      .instance_uds_dir = CleanPath(absl::GetFlag(FLAGS_instance_uds_dir)),
+      .log_dir = CleanPath(absl::GetFlag(FLAGS_log_dir)),
+      .runtime_dir = CleanPath(absl::GetFlag(FLAGS_runtime_dir)),
+      .vsock_device_dir = CleanPath(absl::GetFlag(FLAGS_vsock_device_dir)),
+  };
+
+  // TODO: schuffelen - try to guess these from the cvd_internal_start arguments
+
+  std::optional<std::string_view> home = FromEnv("HOME");
+
+  // CleanPath will set empty strings to ".", so consider that the unset value.
+  if (host.assembly_dir == "." && home.has_value()) {
+    host.assembly_dir = CleanPath(JoinPath(*home, "cuttlefish", "assembly"));
+  }
+  if (host.cuttlefish_config_path == "." && home.has_value()) {
+    host.cuttlefish_config_path = CleanPath(
+        JoinPath(*home, "cuttlefish", "assembly", "cuttlefish_config.json"));
+  }
+  if (host.environments_dir == "." && home.has_value()) {
+    host.environments_dir =
+        CleanPath(JoinPath(*home, "cuttlefish", "environments"));
+  }
+  if (host.environments_uds_dir == ".") {
+    host.environments_uds_dir = "/tmp/cf_env_1000";
+  }
+  if (host.instance_uds_dir == ".") {
+    host.instance_uds_dir = "/tmp/cf_avd_1000/cvd-1";
+  }
+  if (host.log_dir == "." && home.has_value()) {
+    host.log_dir =
+        CleanPath(JoinPath(*home, "cuttlefish", "instances", "cvd-1", "logs"));
+  }
+  if (host.runtime_dir == "." && home.has_value()) {
+    host.runtime_dir =
+        CleanPath(JoinPath(*home, "cuttlefish", "instances", "cvd-1"));
+  }
+
+  std::optional<std::string_view> product_out = FromEnv("ANDROID_PRODUCT_OUT");
 
-  HostInfo host;
-  host.artifacts_path = CleanPath(absl::GetFlag(FLAGS_host_artifacts_path));
-  host.cuttlefish_config_path = CleanPath(getenv(kCuttlefishConfigEnvVarName));
-  host.log_dir = CleanPath(absl::GetFlag(FLAGS_log_dir));
-  setenv("LD_LIBRARY_PATH", JoinPath(host.artifacts_path, "lib64").c_str(), 1);
+  if (host.guest_image_path == ".") {
+    if (product_out.has_value()) {
+      host.guest_image_path = CleanPath(*product_out);
+    } else if (home.has_value()) {
+      host.guest_image_path = CleanPath(*home);
+    }
+  }
+
+  std::optional<std::string_view> host_out = FromEnv("ANDROID_HOST_OUT");
+
+  if (host.host_artifacts_path == ".") {
+    if (host_out.has_value()) {
+      host.host_artifacts_path = CleanPath(*host_out);
+    } else if (home.has_value()) {
+      host.host_artifacts_path = CleanPath(*home);
+    }
+  }
 
-  CHECK_GE(args.size(), 1);
-  auto exe = CleanPath(args[1]);
+  absl::Status dir_creation = host.EnsureOutputDirectoriesExist();
+  if (!dir_creation.ok()) {
+    return dir_creation;
+  }
+
+  absl::Status logs_status;
+  if (absl::GetFlag(FLAGS_log_files).empty()) {
+    std::string default_log_path = JoinPath(host.log_dir, "launcher.log");
+    unlink(default_log_path.c_str());  // Clean from previous run
+    logs_status = LogToFiles({default_log_path});
+  } else {
+    logs_status = LogToFiles(absl::GetFlag(FLAGS_log_files));
+    if (!logs_status.ok()) {
+      return logs_status;
+    }
+  }
+  if (!logs_status.ok()) {
+    return logs_status;
+  }
+
+  VLOG(1) << host;
+
+  setenv("LD_LIBRARY_PATH", JoinPath(host.host_artifacts_path, "lib64").c_str(),
+         1);
+
+  if (args.size() < 2) {
+    std::string err = absl::StrCat("Wanted argv.size() > 1, was ", args.size());
+    return absl::InvalidArgumentError(err);
+  }
+  std::string exe = CleanPath(args[1]);
   std::vector<std::string> exe_argv(++args.begin(), args.end());
-  auto executor = std::make_unique<sandbox2::Executor>(exe, exe_argv);
 
-  for (const auto& inherited_fd : absl::GetFlag(FLAGS_inherited_fds)) {
-    int fd;
-    CHECK(absl::SimpleAtoi(inherited_fd, &fd));
-    executor->ipc()->MapFd(fd, fd);  // Will close `fd` in this process
+  auto sandbox_manager_res = SandboxManager::Create(std::move(host));
+  if (!sandbox_manager_res.ok()) {
+    return sandbox_manager_res.status();
+  }
+  std::unique_ptr<SandboxManager> manager = std::move(*sandbox_manager_res);
+
+  std::vector<std::pair<UniqueFd, int>> fds;
+  for (int i = 0; i <= 2; i++) {
+    auto duped = fcntl(i, F_DUPFD_CLOEXEC, 0);
+    if (duped < 0) {
+      static constexpr char kErr[] = "Failed to `dup` stdio file descriptor";
+      return absl::ErrnoToStatus(errno, kErr);
+    }
+    fds.emplace_back(UniqueFd(duped), i);
   }
 
-  sandbox2::Sandbox2 sb(std::move(executor), PolicyForExecutable(host, exe));
+  std::vector<std::string> this_env;
+  for (size_t i = 0; environ[i] != nullptr; i++) {
+    this_env.emplace_back(environ[i]);
+  }
+
+  absl::Status status = manager->RunProcess(std::nullopt, std::move(exe_argv),
+                                            std::move(fds), this_env);
+  if (!status.ok()) {
+    return status;
+  }
+
+  while (manager->Running()) {
+    absl::Status iter = manager->Iterate();
+    if (!iter.ok()) {
+      LOG(ERROR) << "Error in SandboxManager::Iterate: " << iter.ToString();
+    }
+  }
+
+  absl::StatusOr<PidFd> self_pidfd = PidFd::FromRunningProcess(getpid());
+  if (!self_pidfd.ok()) {
+    return self_pidfd.status();
+  }
 
-  auto res = sb.Run();
-  CHECK_EQ(res.final_status(), sandbox2::Result::OK) << res.ToString();
-  return 0;
+  return self_pidfd->HaltChildHierarchy();
 }
 
-}  // namespace cuttlefish
+}  // namespace
+}  // namespace cuttlefish::process_sandboxer
 
 int main(int argc, char** argv) {
-  return cuttlefish::ProcessSandboxerMain(argc, argv);
+  auto status = cuttlefish::process_sandboxer::ProcessSandboxerMain(argc, argv);
+  if (status.ok()) {
+    VLOG(1) << "process_sandboxer exiting normally";
+    return 0;
+  }
+  LOG(ERROR) << status.ToString();
+  return status.raw_code();
 }
diff --git a/host/commands/process_sandboxer/pidfd.cpp b/host/commands/process_sandboxer/pidfd.cpp
new file mode 100644
index 000000000..c67480368
--- /dev/null
+++ b/host/commands/process_sandboxer/pidfd.cpp
@@ -0,0 +1,271 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/pidfd.h"
+
+#include <dirent.h>
+#include <fcntl.h>
+#include <linux/sched.h>
+#include <signal.h>
+#include <sys/prctl.h>
+#include <sys/syscall.h>
+#include <sys/types.h>
+#include <unistd.h>
+
+#include <fstream>
+#include <memory>
+#include <utility>
+#include <vector>
+
+#include <absl/log/check.h>
+#include <absl/log/log.h>
+#include <absl/status/status.h>
+#include <absl/status/statusor.h>
+#include <absl/strings/numbers.h>
+#include <absl/strings/str_cat.h>
+#include <absl/strings/str_format.h>
+#include <absl/strings/str_join.h>
+#include <absl/strings/str_split.h>
+#include <absl/types/span.h>
+
+#include "host/commands/process_sandboxer/unique_fd.h"
+
+namespace cuttlefish::process_sandboxer {
+
+absl::StatusOr<PidFd> PidFd::FromRunningProcess(pid_t pid) {
+  UniqueFd fd(syscall(SYS_pidfd_open, pid, 0));  // Always CLOEXEC
+  if (fd.Get() < 0) {
+    return absl::ErrnoToStatus(errno, "`pidfd_open` failed");
+  }
+  return PidFd(std::move(fd), pid);
+}
+
+absl::StatusOr<PidFd> PidFd::LaunchSubprocess(
+    absl::Span<const std::string> argv,
+    std::vector<std::pair<UniqueFd, int>> fds,
+    absl::Span<const std::string> env) {
+  int pidfd;
+  clone_args args_for_clone = clone_args{
+      .flags = CLONE_PIDFD,
+      .pidfd = reinterpret_cast<std::uintptr_t>(&pidfd),
+  };
+
+  pid_t res = syscall(SYS_clone3, &args_for_clone, sizeof(args_for_clone));
+  if (res < 0) {
+    std::string argv_str = absl::StrJoin(argv, "','");
+    std::string error = absl::StrCat("clone3 failed: argv=['", argv_str, "']");
+    return absl::ErrnoToStatus(errno, error);
+  } else if (res > 0) {
+    std::string argv_str = absl::StrJoin(argv, "','");
+    VLOG(1) << res << ": Running w/o sandbox ['" << argv_str << "]";
+
+    UniqueFd fd(pidfd);
+    return PidFd(std::move(fd), res);
+  }
+
+  /* Duplicate every input in `fds` into a range higher than the highest output
+   * in `fds`, in case there is any overlap between inputs and outputs. */
+  int minimum_backup_fd = -1;
+  for (const auto& [my_fd, target_fd] : fds) {
+    if (target_fd + 1 > minimum_backup_fd) {
+      minimum_backup_fd = target_fd + 1;
+    }
+  }
+
+  std::unordered_map<int, int> backup_mapping;
+  for (const auto& [my_fd, target_fd] : fds) {
+    int backup = fcntl(my_fd.Get(), F_DUPFD, minimum_backup_fd);
+    PCHECK(backup >= 0) << "fcntl(..., F_DUPFD) failed";
+    int flags = fcntl(backup, F_GETFD);
+    PCHECK(flags >= 0) << "fcntl(..., F_GETFD failed";
+    flags &= FD_CLOEXEC;
+    PCHECK(fcntl(backup, F_SETFD, flags) >= 0) << "fcntl(..., F_SETFD failed";
+    backup_mapping[backup] = target_fd;
+  }
+
+  for (const auto& [backup_fd, target_fd] : backup_mapping) {
+    // dup2 always unsets FD_CLOEXEC
+    PCHECK(dup2(backup_fd, target_fd) >= 0) << "dup2 failed";
+  }
+
+  std::vector<std::string> argv_clone(argv.begin(), argv.end());
+  std::vector<char*> argv_cstr;
+  for (auto& arg : argv_clone) {
+    argv_cstr.emplace_back(arg.data());
+  }
+  argv_cstr.emplace_back(nullptr);
+
+  std::vector<std::string> env_clone(env.begin(), env.end());
+  std::vector<char*> env_cstr;
+  for (std::string& env_member : env_clone) {
+    env_cstr.emplace_back(env_member.data());
+  }
+  env_cstr.emplace_back(nullptr);
+
+  if (prctl(PR_SET_PDEATHSIG, SIGHUP) < 0) {  // Die when parent dies
+    PLOG(FATAL) << "prctl failed";
+  }
+
+  execve(argv_cstr[0], argv_cstr.data(), env_cstr.data());
+
+  PLOG(FATAL) << "execv failed";
+}
+
+PidFd::PidFd(UniqueFd fd, pid_t pid) : fd_(std::move(fd)), pid_(pid) {}
+
+int PidFd::Get() const { return fd_.Get(); }
+
+absl::StatusOr<std::vector<std::pair<UniqueFd, int>>> PidFd::AllFds() {
+  std::vector<std::pair<UniqueFd, int>> fds;
+
+  std::string dir_name = absl::StrFormat("/proc/%d/fd", pid_);
+  std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(dir_name.c_str()), closedir);
+  if (dir.get() == nullptr) {
+    return absl::ErrnoToStatus(errno, "`opendir` failed");
+  }
+  for (dirent* ent = readdir(dir.get()); ent; ent = readdir(dir.get())) {
+    int other_fd;
+    // `d_name` is guaranteed to be null terminated
+    std::string_view name{ent->d_name};
+    if (name == "." || name == "..") {
+      continue;
+    }
+    if (!absl::SimpleAtoi(name, &other_fd)) {
+      std::string error = absl::StrFormat("'%v/%v' not an int", dir_name, name);
+      return absl::InternalError(error);
+    }
+    // Always CLOEXEC
+    UniqueFd our_fd(syscall(SYS_pidfd_getfd, fd_.Get(), other_fd, 0));
+    if (our_fd.Get() < 0) {
+      return absl::ErrnoToStatus(errno, "`pidfd_getfd` failed");
+    }
+    fds.emplace_back(std::move(our_fd), other_fd);
+  }
+
+  return fds;
+}
+
+static absl::StatusOr<std::vector<std::string>> ReadNullSepFile(
+    const std::string& path) {
+  std::ifstream cmdline_file(path, std::ios::binary);
+  if (!cmdline_file) {
+    auto err = absl::StrFormat("Failed to open '%v'", path);
+    return absl::InternalError(err);
+  }
+  std::stringstream buffer;
+  buffer << cmdline_file.rdbuf();
+  if (!cmdline_file) {
+    auto err = absl::StrFormat("Failed to read '%v'", path);
+    return absl::InternalError(err);
+  }
+
+  std::vector<std::string> members = absl::StrSplit(buffer.str(), '\0');
+  if (members.empty()) {
+    return absl::InternalError(absl::StrFormat("'%v' is empty", path));
+  } else if (members.back() == "") {
+    members.pop_back();  // may end in a null terminator
+  }
+  return members;
+}
+
+absl::StatusOr<std::vector<std::string>> PidFd::Argv() {
+  return ReadNullSepFile(absl::StrFormat("/proc/%d/cmdline", pid_));
+}
+
+absl::StatusOr<std::vector<std::string>> PidFd::Env() {
+  return ReadNullSepFile(absl::StrFormat("/proc/%d/environ", pid_));
+}
+
+absl::Status PidFd::HaltHierarchy() {
+  if (absl::Status stop = SendSignal(SIGSTOP); !stop.ok()) {
+    return stop;
+  }
+  if (absl::Status halt_children = HaltChildHierarchy(); !halt_children.ok()) {
+    return halt_children;
+  }
+  return SendSignal(SIGKILL);
+}
+
+/* Assumes the process referred to by `pid` does not spawn any more children or
+ * reap any children while this function is running. */
+static absl::StatusOr<std::vector<pid_t>> FindChildPids(pid_t pid) {
+  std::vector<pid_t> child_pids;
+
+  std::string task_dir = absl::StrFormat("/proc/%d/task", pid);
+  std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(task_dir.c_str()), closedir);
+  if (dir.get() == nullptr) {
+    return absl::ErrnoToStatus(errno, "`opendir` failed");
+  }
+
+  while (dirent* ent = readdir(dir.get())) {
+    // `d_name` is guaranteed to be null terminated
+    std::string_view name = ent->d_name;
+    if (name == "." || name == "..") {
+      continue;
+    }
+    std::string children_file =
+        absl::StrFormat("/proc/%d/task/%s/children", pid, name);
+    std::ifstream children_stream(children_file);
+    if (!children_stream) {
+      std::string err = absl::StrCat("can't read child file: ", children_file);
+      return absl::InternalError(err);
+    }
+
+    std::string children_str;
+    std::getline(children_stream, children_str);
+    for (std::string_view child_str : absl::StrSplit(children_str, " ")) {
+      if (child_str.empty()) {
+        continue;
+      }
+      pid_t child_pid;
+      if (!absl::SimpleAtoi(child_str, &child_pid)) {
+        std::string error = absl::StrFormat("'%s' is not a pid_t", child_str);
+        return absl::InternalError(error);
+      }
+      child_pids.emplace_back(child_pid);
+    }
+  }
+
+  return child_pids;
+}
+
+absl::Status PidFd::HaltChildHierarchy() {
+  absl::StatusOr<std::vector<pid_t>> children = FindChildPids(pid_);
+  if (!children.ok()) {
+    return children.status();
+  }
+  for (pid_t child : *children) {
+    absl::StatusOr<PidFd> child_pidfd = FromRunningProcess(child);
+    if (!child_pidfd.ok()) {
+      return child_pidfd.status();
+    }
+    // HaltHierarchy will SIGSTOP the child so it cannot spawn more children
+    // or reap its own children while everything is being stopped.
+    if (absl::Status halt = child_pidfd->HaltHierarchy(); !halt.ok()) {
+      return halt;
+    }
+  }
+
+  return absl::OkStatus();
+}
+
+absl::Status PidFd::SendSignal(int signal) {
+  if (syscall(SYS_pidfd_send_signal, fd_.Get(), signal, nullptr, 0) < 0) {
+    return absl::ErrnoToStatus(errno, "pidfd_send_signal failed");
+  }
+  return absl::OkStatus();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/pidfd.h b/host/commands/process_sandboxer/pidfd.h
new file mode 100644
index 000000000..23e53896f
--- /dev/null
+++ b/host/commands/process_sandboxer/pidfd.h
@@ -0,0 +1,76 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#ifndef ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_SANDBOX_PROCESS_PIDFD_H
+#define ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_SANDBOX_PROCESS_PIDFD_H
+
+#include <sys/types.h>
+
+#include <utility>
+#include <vector>
+
+#include <absl/status/statusor.h>
+#include <absl/types/span.h>
+
+#include "host/commands/process_sandboxer/unique_fd.h"
+
+namespace cuttlefish {
+namespace process_sandboxer {
+
+class PidFd {
+ public:
+  /** Returns a managed pidfd tracking a previously started process with `pid`.
+   *
+   * Only reliably refers to the process `pid` if the caller can guarantee it
+   * was not reaped while this is executing, otherwise it may refer to an
+   * unknown process. */
+  static absl::StatusOr<PidFd> FromRunningProcess(pid_t pid);
+
+  /** Launches a subprocess and returns a pidfd tracking the newly launched
+   * process. */
+  static absl::StatusOr<PidFd> LaunchSubprocess(
+      absl::Span<const std::string> argv,
+      std::vector<std::pair<UniqueFd, int>> fds,
+      absl::Span<const std::string> env);
+
+  int Get() const;
+
+  /** Copies file descriptors from the target process, mapping them into the
+   * current process.
+   *
+   * Keys are file descriptor numbers in the target process, values are open
+   * file descriptors in the current process.
+   */
+  absl::StatusOr<std::vector<std::pair<UniqueFd, int>>> AllFds();
+  absl::StatusOr<std::vector<std::string>> Argv();
+  absl::StatusOr<std::vector<std::string>> Env();
+
+  /** Halt the process and all its descendants. */
+  absl::Status HaltHierarchy();
+  /** Halt all descendants of the process. Only safe to use if the caller
+   * guarantees the process doesn't spawn or reap any children while running. */
+  absl::Status HaltChildHierarchy();
+
+ private:
+  PidFd(UniqueFd, pid_t);
+  absl::Status SendSignal(int signal);
+
+  UniqueFd fd_;
+  pid_t pid_;
+};
+
+}  // namespace process_sandboxer
+}  // namespace cuttlefish
+#endif
diff --git a/host/commands/process_sandboxer/policies.cpp b/host/commands/process_sandboxer/policies.cpp
index f9777e8c3..12e197c16 100644
--- a/host/commands/process_sandboxer/policies.cpp
+++ b/host/commands/process_sandboxer/policies.cpp
@@ -17,35 +17,126 @@
 #include "host/commands/process_sandboxer/policies.h"
 
 #include <memory>
+#include <ostream>
+#include <string_view>
 
-#include "absl/container/flat_hash_map.h"
-#include "absl/log/log.h"
-#include "sandboxed_api/sandbox2/policybuilder.h"
-#include "sandboxed_api/util/path.h"
+#include <absl/container/flat_hash_map.h>
+#include <absl/log/log.h>
+#include <absl/status/status.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
 
-using sapi::file::JoinPath;
+#include "host/commands/process_sandboxer/filesystem.h"
+#include "host/commands/process_sandboxer/proxy_common.h"
 
-namespace cuttlefish {
+namespace cuttlefish::process_sandboxer {
+
+absl::Status HostInfo::EnsureOutputDirectoriesExist() {
+  if (!CreateDirectoryRecursively(assembly_dir, 0700)) {
+    return absl::ErrnoToStatus(errno, "Failed to create " + assembly_dir);
+  }
+  if (!CreateDirectoryRecursively(environments_dir, 0700)) {
+    return absl::ErrnoToStatus(errno, "Failed to create " + environments_dir);
+  }
+  if (!CreateDirectoryRecursively(environments_uds_dir, 0700)) {
+    return absl::ErrnoToStatus(errno,
+                               "Failed to create " + environments_uds_dir);
+  }
+  if (!CreateDirectoryRecursively(instance_uds_dir, 0700)) {
+    return absl::ErrnoToStatus(errno, "Failed to create " + instance_uds_dir);
+  }
+  if (!CreateDirectoryRecursively(log_dir, 0700)) {
+    return absl::ErrnoToStatus(errno, "Failed to create " + log_dir);
+  }
+  if (!CreateDirectoryRecursively(runtime_dir, 0700)) {
+    return absl::ErrnoToStatus(errno, "Failed to create " + runtime_dir);
+  }
+  return absl::OkStatus();
+}
+
+std::string HostInfo::HostToolExe(std::string_view exe) const {
+  return JoinPath(host_artifacts_path, "bin", exe);
+}
+
+std::ostream& operator<<(std::ostream& out, const HostInfo& host) {
+  out << "HostInfo {\n";
+  out << "\tassembly_dir: \"" << host.assembly_dir << "\"\n";
+  out << "\tcuttlefish_config_path: \"" << host.cuttlefish_config_path
+      << "\"\n";
+  out << "\tenvironments_dir: \"" << host.environments_dir << "\"\n";
+  out << "\tenvironments_uds_dir: " << host.environments_uds_dir << "\"\n";
+  out << "\tguest_image_path: " << host.guest_image_path << "\t\n";
+  out << "\thost_artifacts_path: \"" << host.host_artifacts_path << "\"\n";
+  out << "\tinstance_uds_dir: " << host.instance_uds_dir << "\"\n";
+  out << "\tlog_dir: " << host.log_dir << "\"\n";
+  out << "\truntime_dir: " << host.runtime_dir << "\"\n";
+  return out << "}";
+}
 
 std::unique_ptr<sandbox2::Policy> PolicyForExecutable(
-    const HostInfo& host, std::string_view executable) {
+    const HostInfo& host, std::string_view server_socket_outside_path,
+    std::string_view executable) {
   using Builder = sandbox2::PolicyBuilder(const HostInfo&);
   absl::flat_hash_map<std::string, Builder*> builders;
 
-  builders[JoinPath(host.artifacts_path, "bin", "kernel_log_monitor")] =
-      KernelLogMonitorPolicy;
-  builders[JoinPath(host.artifacts_path, "bin", "logcat_receiver")] =
-      LogcatReceiverPolicy;
+  builders[host.HostToolExe("adb_connector")] = AdbConnectorPolicy;
+  builders[host.HostToolExe("assemble_cvd")] = AssembleCvdPolicy;
+  builders[host.HostToolExe("avbtool")] = AvbToolPolicy;
+  builders[host.HostToolExe("casimir")] = CasimirPolicy;
+  builders[host.HostToolExe("casimir_control_server")] =
+      CasimirControlServerPolicy;
+  builders[host.HostToolExe("control_env_proxy_server")] =
+      ControlEnvProxyServerPolicy;
+  builders[host.HostToolExe("cvd_internal_start")] = CvdInternalStartPolicy;
+  builders[host.HostToolExe("echo_server")] = EchoServerPolicy;
+  builders[host.HostToolExe("gnss_grpc_proxy")] = GnssGrpcProxyPolicy;
+  builders[host.HostToolExe("kernel_log_monitor")] = KernelLogMonitorPolicy;
+  builders[host.HostToolExe("log_tee")] = LogTeePolicy;
+  builders[host.HostToolExe("logcat_receiver")] = LogcatReceiverPolicy;
+  builders[host.HostToolExe("metrics")] = MetricsPolicy;
+  builders[host.HostToolExe("mkenvimage_slim")] = MkEnvImgSlimPolicy;
+  builders[host.HostToolExe("modem_simulator")] = ModemSimulatorPolicy;
+  builders[host.HostToolExe("netsimd")] = NetsimdPolicy;
+  builders[host.HostToolExe("newfs_msdos")] = NewFsMsDosPolicy;
+  builders[host.HostToolExe("openwrt_control_server")] =
+      OpenWrtControlServerPolicy;
+  builders[host.HostToolExe("operator_proxy")] = OperatorProxyPolicy;
+  builders[host.HostToolExe("process_restarter")] = ProcessRestarterPolicy;
+  builders[host.HostToolExe("run_cvd")] = RunCvdPolicy;
+  builders[host.HostToolExe("screen_recording_server")] =
+      ScreenRecordingServerPolicy;
+  builders[host.HostToolExe("secure_env")] = SecureEnvPolicy;
+  builders[host.HostToolExe("simg2img")] = Simg2ImgPolicy;
+  builders[host.HostToolExe("socket_vsock_proxy")] = SocketVsockProxyPolicy;
+  builders[host.HostToolExe("tcp_connector")] = TcpConnectorPolicy;
+  builders[host.HostToolExe("tombstone_receiver")] = TombstoneReceiverPolicy;
+  builders[host.HostToolExe("vhost_device_vsock")] = VhostDeviceVsockPolicy;
+  builders[host.HostToolExe("webRTC")] = WebRtcPolicy;
+  builders[host.HostToolExe("webrtc_operator")] = WebRtcOperatorPolicy;
+  builders[host.HostToolExe("wmediumd")] = WmediumdPolicy;
+  builders[host.HostToolExe("wmediumd_gen_config")] = WmediumdGenConfigPolicy;
+
+  std::set<std::string> no_policy_set = NoPolicy(host);
+  for (const auto& [exe, policy_builder] : builders) {
+    if (no_policy_set.count(exe)) {
+      LOG(FATAL) << "Overlap in policy map and no-policy set: '" << exe << "'";
+    }
+  }
 
   if (auto it = builders.find(executable); it != builders.end()) {
-    return (it->second)(host).BuildOrDie();
-  } else {
-    for (const auto& [target, unused] : builders) {
-      LOG(ERROR) << "Available policy: '" << target << "'";
+    // TODO(schuffelen): Only share this with executables known to launch others
+    auto r1 = (it->second)(host);
+    r1.AddFileAt(server_socket_outside_path, kManagerSocketPath, false);
+    auto r2 = r1.TryBuild();
+    if (!r2.ok()) {
+      LOG(INFO) << r2.status().ToString();
+      abort();
     }
-    LOG(FATAL) << "No policy defined for '" << executable << "'";
-    return sandbox2::PolicyBuilder().BuildOrDie();
+    return std::move(*r2);
+  } else if (no_policy_set.count(std::string(executable))) {
+    return nullptr;
+  } else {
+    LOG(FATAL) << "Unknown executable '" << executable << "'";
   }
 }
 
-}  // namespace cuttlefish
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies.h b/host/commands/process_sandboxer/policies.h
index 0f38b2a50..8ba2348ab 100644
--- a/host/commands/process_sandboxer/policies.h
+++ b/host/commands/process_sandboxer/policies.h
@@ -16,25 +16,77 @@
 #ifndef ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_SANDBOX_PROCESS_POLICIES_H
 #define ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_SANDBOX_PROCESS_POLICIES_H
 
+#include <memory>
+#include <ostream>
+#include <set>
 #include <string>
 #include <string_view>
 
+#include <absl/status/status.h>
+
 #include "sandboxed_api/sandbox2/policybuilder.h"
 
-namespace cuttlefish {
+namespace cuttlefish::process_sandboxer {
 
 struct HostInfo {
-  std::string artifacts_path;
+  absl::Status EnsureOutputDirectoriesExist();
+  std::string HostToolExe(std::string_view exe) const;
+
+  std::string assembly_dir;
   std::string cuttlefish_config_path;
+  std::string environments_dir;
+  std::string environments_uds_dir;
+  std::string guest_image_path;
+  std::string host_artifacts_path;
+  std::string instance_uds_dir;
   std::string log_dir;
+  std::string runtime_dir;
+  std::string vsock_device_dir;
 };
 
+std::ostream& operator<<(std::ostream&, const HostInfo&);
+
+sandbox2::PolicyBuilder BaselinePolicy(const HostInfo&, std::string_view exe);
+
+sandbox2::PolicyBuilder AdbConnectorPolicy(const HostInfo&);
+sandbox2::PolicyBuilder AssembleCvdPolicy(const HostInfo&);
+sandbox2::PolicyBuilder AvbToolPolicy(const HostInfo&);
+sandbox2::PolicyBuilder CasimirPolicy(const HostInfo&);
+sandbox2::PolicyBuilder CasimirControlServerPolicy(const HostInfo&);
+sandbox2::PolicyBuilder ControlEnvProxyServerPolicy(const HostInfo&);
+sandbox2::PolicyBuilder CvdInternalStartPolicy(const HostInfo&);
+sandbox2::PolicyBuilder EchoServerPolicy(const HostInfo&);
+sandbox2::PolicyBuilder GnssGrpcProxyPolicy(const HostInfo&);
 sandbox2::PolicyBuilder KernelLogMonitorPolicy(const HostInfo&);
+sandbox2::PolicyBuilder LogTeePolicy(const HostInfo&);
 sandbox2::PolicyBuilder LogcatReceiverPolicy(const HostInfo&);
+sandbox2::PolicyBuilder MetricsPolicy(const HostInfo& host);
+sandbox2::PolicyBuilder MkEnvImgSlimPolicy(const HostInfo& host);
+sandbox2::PolicyBuilder ModemSimulatorPolicy(const HostInfo&);
+sandbox2::PolicyBuilder NetsimdPolicy(const HostInfo&);
+sandbox2::PolicyBuilder NewFsMsDosPolicy(const HostInfo&);
+sandbox2::PolicyBuilder OpenWrtControlServerPolicy(const HostInfo& host);
+sandbox2::PolicyBuilder OperatorProxyPolicy(const HostInfo& host);
+sandbox2::PolicyBuilder ProcessRestarterPolicy(const HostInfo&);
+sandbox2::PolicyBuilder RunCvdPolicy(const HostInfo&);
+sandbox2::PolicyBuilder ScreenRecordingServerPolicy(const HostInfo&);
+sandbox2::PolicyBuilder SecureEnvPolicy(const HostInfo&);
+sandbox2::PolicyBuilder Simg2ImgPolicy(const HostInfo&);
+sandbox2::PolicyBuilder SocketVsockProxyPolicy(const HostInfo&);
+sandbox2::PolicyBuilder TcpConnectorPolicy(const HostInfo&);
+sandbox2::PolicyBuilder TombstoneReceiverPolicy(const HostInfo&);
+sandbox2::PolicyBuilder VhostDeviceVsockPolicy(const HostInfo&);
+sandbox2::PolicyBuilder WebRtcPolicy(const HostInfo&);
+sandbox2::PolicyBuilder WebRtcOperatorPolicy(const HostInfo&);
+sandbox2::PolicyBuilder WmediumdPolicy(const HostInfo&);
+sandbox2::PolicyBuilder WmediumdGenConfigPolicy(const HostInfo&);
+
+std::set<std::string> NoPolicy(const HostInfo&);
 
 std::unique_ptr<sandbox2::Policy> PolicyForExecutable(
-    const HostInfo& host_info, std::string_view executable_path);
+    const HostInfo& host_info, std::string_view server_socket_outside_path,
+    std::string_view executable_path);
 
-}  // namespace cuttlefish
+}  // namespace cuttlefish::process_sandboxer
 
 #endif
diff --git a/host/commands/process_sandboxer/policies/adb_connector.cpp b/host/commands/process_sandboxer/policies/adb_connector.cpp
new file mode 100644
index 000000000..ad7979900
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/adb_connector.cpp
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder AdbConnectorPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("adb_connector"))
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      .Allow(sandbox2::UnrestrictedNetworking())  // Used to message adb server
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW),
+                                        JEQ32(AF_UNIX, ALLOW)})
+      .AllowSafeFcntl()
+      .AllowSleep()
+      .AllowSyscall(__NR_clone)  // Multithreading
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_sendto)
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/assemble_cvd.cpp b/host/commands/process_sandboxer/policies/assemble_cvd.cpp
new file mode 100644
index 000000000..fb8730ec5
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/assemble_cvd.cpp
@@ -0,0 +1,104 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/mman.h>
+#include <sys/prctl.h>
+#include <sys/syscall.h>
+
+#include <absl/strings/str_cat.h>
+#include <absl/strings/str_replace.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+#include "host/commands/process_sandboxer/filesystem.h"
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder AssembleCvdPolicy(const HostInfo& host) {
+  std::string sandboxer_proxy = host.HostToolExe("sandboxer_proxy");
+  return BaselinePolicy(host, host.HostToolExe("assemble_cvd"))
+      .AddDirectory(host.assembly_dir, /* is_ro= */ false)
+      // TODO(schuffelen): Don't resize vbmeta in-place
+      .AddDirectory(host.guest_image_path, /* is_ro= */ false)
+      .AddDirectory(JoinPath(host.host_artifacts_path, "etc", "cvd_config"))
+      // TODO(schuffelen): Copy these files before modifying them
+      .AddDirectory(JoinPath(host.host_artifacts_path, "etc", "openwrt"),
+                    /* is_ro= */ false)
+      // TODO(schuffelen): Premake the directory for boot image unpack outputs
+      .AddDirectory("/tmp", /* is_ro= */ false)
+      .AddDirectory(host.environments_dir, /* is_ro= */ false)
+      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.runtime_dir, /* is_ro= */ false)
+      // `webRTC` actually uses this file, but `assemble_cvd` first checks
+      // whether it exists in order to decide whether to connect to it.
+      .AddFile("/run/cuttlefish/operator")
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("avbtool"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("crosvm"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("mkenvimage_slim"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("newfs_msdos"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("simg2img"))
+      .AddDirectory(host.environments_dir)
+      .AddDirectory(host.environments_uds_dir, false)
+      .AddDirectory(host.instance_uds_dir, false)
+      // The UID inside the sandbox2 namespaces is always 1000.
+      .AddDirectoryAt(host.environments_uds_dir,
+                      absl::StrReplaceAll(
+                          host.environments_uds_dir,
+                          {{absl::StrCat("cf_env_", getuid()), "cf_env_1000"}}),
+                      false)
+      .AddDirectoryAt(host.instance_uds_dir,
+                      absl::StrReplaceAll(
+                          host.instance_uds_dir,
+                          {{absl::StrCat("cf_avd_", getuid()), "cf_avd_1000"}}),
+                      false)
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      .AddPolicyOnSyscall(__NR_prctl,
+                          {ARG_32(0), JEQ32(PR_SET_PDEATHSIG, ALLOW)})
+      /* sandboxer_proxy needs AF_UNIX. `assemble_cvd/network_flags.cpp` calls
+       * `getifaddrs` which won't give any interesting output in the network
+       * namespace anyway. */
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW),
+                                        JEQ32(AF_INET, ERRNO(EACCES)),
+                                        JEQ32(AF_NETLINK, ERRNO(EACCES))})
+      .AllowDup()
+      .AllowFork()
+      .AllowGetIDs()
+      .AllowLink()
+      .AllowMkdir()
+      .AllowPipe()
+      .AllowReaddir()
+      .AllowRename()
+      .AllowSafeFcntl()
+      .AllowSymlink()
+      .AllowUnlink()
+      .AllowSyscall(__NR_execve)
+      .AllowSyscall(__NR_flock)
+      .AllowSyscall(__NR_ftruncate)
+      .AllowSyscall(__NR_fsync)
+      .AllowSyscall(__NR_umask)
+      .AllowTCGETS()
+      .AllowWait()
+      // For sandboxer_proxy
+      .AllowExit()
+      .AllowSyscall(SYS_connect)
+      .AllowSyscall(SYS_recvmsg)
+      .AllowSyscall(SYS_sendmsg);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/avbtool.cpp b/host/commands/process_sandboxer/policies/avbtool.cpp
new file mode 100644
index 000000000..5a3e04da1
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/avbtool.cpp
@@ -0,0 +1,99 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/ioctl.h>
+#include <syscall.h>
+
+#include <absl/log/check.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+#include "host/commands/process_sandboxer/filesystem.h"
+
+namespace cuttlefish::process_sandboxer {
+
+/*
+ * This executable is built as a `python_binary_host`:
+ * https://cs.android.com/android/platform/superproject/main/+/main:external/avb/Android.bp;l=136;drc=1bbcd661f0afe4ab56c7031f57d518a19015805e
+ *
+ * A `python_binary_host` executable is a python interpreter concatenated with a
+ * zip file of the python code for this executable and the python standard
+ * library.
+ * https://cs.android.com/android/platform/superproject/main/+/main:build/soong/python/python.go;l=416;drc=4ce4f8893e5c5ee9b9b2669ceb36a01d85ea39f4
+ *
+ * Concatenation works because the interpreter is a ELF executable, identified
+ * by an ELF prefix header, while zip files are identifier by a table added to
+ * the file as a suffix.
+ *
+ * The python interpreter is an executable built out of the Android build system
+ * with some custom code.
+ * https://cs.android.com/android/platform/superproject/main/+/main:external/python/cpython3/android/launcher_main.cpp;drc=02afc01277f68e081dad208f2d660fc74d67be88
+ */
+sandbox2::PolicyBuilder AvbToolPolicy(const HostInfo& host) {
+  /*
+   * `launcher_main.cpp` relies on `android::base::GetExecutablePath()` which
+   * tries to `readlink("/proc/self/exe")`. Sandbox2 doesn't mount a procfs at
+   * /proc in the mount namespace, so we can do this mount ourselves.  However,
+   * this specifically needs to appear inside the mount namespace as a symlink
+   * so that `readlink` works correctly. Bind-mounting the file with `AddFileAt`
+   * or even bind-mounting a symlink directly doesn't appear to work correctly
+   * with `readlink`, so we have to bind-mount a parent directory into
+   * /proc/self and create an `exe` symlink.
+   *
+   * https://cs.android.com/android/platform/superproject/main/+/main:system/libbase/file.cpp;l=491;drc=a4ac93b700ed623bdb333ccb2ac567b8a33081a7
+   */
+  std::string executable = host.HostToolExe("avbtool");
+
+  char fake_proc_self[] = "/tmp/avbtool_XXXXXX";
+  PCHECK(mkdtemp(fake_proc_self)) << "Failed to create fake /proc/self dir";
+  PCHECK(symlink(executable.c_str(), JoinPath(fake_proc_self, "exe").c_str()) >=
+         0)
+      << "Failed to create 'exe' symlink for avbtool";
+  return BaselinePolicy(host, executable)
+      .AddDirectory(host.host_artifacts_path)
+      .AddDirectory(host.guest_image_path)
+      .AddDirectory(host.runtime_dir, /* is_ro= */ false)
+      .AddDirectoryAt(fake_proc_self, "/proc/self")
+      // `assemble_cvd` uses `mkdtemp` in `/tmp` and passes the path to avbtool.
+      // TODO: schuffelen - make this more predictable
+      .AddDirectory("/tmp", /* is_ro= */ false)
+      .AddFile("/dev/urandom")  // For Python
+      .AddFileAt(host.HostToolExe("sandboxer_proxy"), "/usr/bin/openssl")
+      // The executable `open`s itself to load the python files.
+      .AddFile(executable)
+      .AddLibrariesForBinary(host.HostToolExe("sandboxer_proxy"),
+                             JoinPath(host.host_artifacts_path, "lib64"))
+      .AddPolicyOnSyscall(__NR_ioctl, {ARG_32(1), JEQ32(TIOCGWINSZ, ALLOW)})
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW)})
+      .AllowDup()
+      .AllowEpoll()
+      .AllowFork()
+      .AllowHandleSignals()
+      .AllowPipe()
+      .AllowSafeFcntl()
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_execve)
+      .AllowSyscall(__NR_ftruncate)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_sysinfo)
+      .AllowTCGETS()
+      .AllowWait();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/baseline.cpp b/host/commands/process_sandboxer/policies/baseline.cpp
new file mode 100644
index 000000000..2f8678914
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/baseline.cpp
@@ -0,0 +1,77 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/mman.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+#include "host/commands/process_sandboxer/filesystem.h"
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder BaselinePolicy(const HostInfo& host,
+                                       std::string_view exe) {
+  return sandbox2::PolicyBuilder()
+      .AddLibrariesForBinary(exe, JoinPath(host.host_artifacts_path, "lib64"))
+      // For dynamic linking and memory allocation
+      .AllowDynamicStartup()
+      .AllowExit()
+      .AllowGetPIDs()
+      .AllowGetRandom()
+      // Observed by `strace` on `socket_vsock_proxy` with x86_64 AOSP `glibc`.
+      .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
+        return {
+            ARG_32(2),  // prot
+            JEQ32(PROT_NONE, JUMP(&labels, cf_mmap_prot_none)),
+            JEQ32(PROT_READ, JUMP(&labels, cf_mmap_prot_read)),
+            JEQ32(PROT_READ | PROT_EXEC, JUMP(&labels, cf_mmap_prot_read_exec)),
+            JNE32(PROT_READ | PROT_WRITE, JUMP(&labels, cf_mmap_prot_end)),
+            // PROT_READ | PROT_WRITE
+            ARG_32(3),  // flags
+            JEQ32(MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, ALLOW),
+            JUMP(&labels, cf_mmap_prot_end),
+            // PROT_READ | PROT_EXEC
+            LABEL(&labels, cf_mmap_prot_read_exec),
+            ARG_32(3),  // flags
+            JEQ32(MAP_PRIVATE | MAP_DENYWRITE, ALLOW),
+            JEQ32(MAP_PRIVATE | MAP_FIXED | MAP_DENYWRITE, ALLOW),
+            JUMP(&labels, cf_mmap_prot_end),
+            // PROT_READ
+            LABEL(&labels, cf_mmap_prot_read),
+            ARG_32(3),  // flags
+            JEQ32(MAP_PRIVATE | MAP_ANONYMOUS, ALLOW),
+            JEQ32(MAP_PRIVATE | MAP_DENYWRITE, ALLOW),
+            JEQ32(MAP_PRIVATE | MAP_FIXED | MAP_DENYWRITE, ALLOW),
+            JEQ32(MAP_PRIVATE, ALLOW),
+            JUMP(&labels, cf_mmap_prot_end),
+            // PROT_NONE
+            LABEL(&labels, cf_mmap_prot_none),
+            ARG_32(3),  // flags
+            JEQ32(MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, ALLOW),
+            JEQ32(MAP_PRIVATE | MAP_ANONYMOUS, ALLOW),
+
+            LABEL(&labels, cf_mmap_prot_end),
+        };
+      })
+      .AllowReadlink()
+      .AllowRestartableSequences(sandbox2::PolicyBuilder::kAllowSlowFences)
+      .AllowWrite();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/casimir.cpp b/host/commands/process_sandboxer/policies/casimir.cpp
new file mode 100644
index 000000000..481ce65a5
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/casimir.cpp
@@ -0,0 +1,71 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <netinet/ip_icmp.h>
+#include <sys/mman.h>
+#include <sys/prctl.h>
+#include <sys/syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder CasimirPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("casimir"))
+      .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
+        return {
+            ARG_32(2),  // prot
+            JNE32(PROT_READ | PROT_WRITE, JUMP(&labels, cf_casimir_mmap_end)),
+            ARG_32(3),  // flags
+            JEQ32(MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, ALLOW),
+            LABEL(&labels, cf_casimir_mmap_end),
+        };
+      })
+      .AddPolicyOnSyscall(
+          __NR_setsockopt,
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),  // level
+                JNE32(IPPROTO_ICMP, JUMP(&labels, cf_casimir_setsockopt_end)),
+                // IPPROTO_ICMP
+                ARG_32(2),  // optname
+                JEQ32(ICMP_REDIR_NETTOS, ALLOW),
+                LABEL(&labels, cf_casimir_setsockopt_end)};
+          })
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW)})
+      .Allow(sandbox2::UnrestrictedNetworking())
+      .AllowEpoll()
+      .AllowEpollWait()
+      .AllowEventFd()
+      .AllowHandleSignals()
+      .AllowPrctlSetName()
+      .AllowSafeFcntl()
+      .AllowSyscall(__NR_accept4)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)
+      .AllowSyscall(__NR_listen)
+      // Uses GRND_INSECURE which is not covered by AllowGetRandom()
+      .AllowSyscall(__NR_getrandom)
+      .AllowSyscall(__NR_recvfrom)
+      .AllowSyscall(__NR_sendto)
+      .AllowSyscall(__NR_shutdown);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/casimir_control_server.cpp b/host/commands/process_sandboxer/policies/casimir_control_server.cpp
new file mode 100644
index 000000000..cabce4c5c
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/casimir_control_server.cpp
@@ -0,0 +1,69 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/mman.h>
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder CasimirControlServerPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("casimir_control_server"))
+      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddFile("/dev/urandom")                    // For gRPC
+      .Allow(sandbox2::UnrestrictedNetworking())  // Communicate with casimir
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      .AddPolicyOnSyscall(
+          __NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW), JEQ32(AF_INET, ALLOW),
+                        JEQ32(AF_INET6, ALLOW)})
+      .AddPolicyOnSyscalls(
+          {__NR_getsockopt, __NR_setsockopt},
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),  // level
+                JNE32(SOL_SOCKET,
+                      JUMP(&labels, cf_control_env_proxy_server_sockopt_end)),
+                ARG_32(2),  // optname
+                JEQ32(SO_REUSEPORT, ALLOW),
+                LABEL(&labels, cf_control_env_proxy_server_sockopt_end),
+            };
+          })
+      .AllowEventFd()
+      .AllowSafeFcntl()
+      .AllowSleep()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)  // Multithreading
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_getpeername)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sched_getparam)
+      .AllowSyscall(__NR_sched_getscheduler)
+      .AllowSyscall(__NR_sched_yield)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_shutdown);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/control_env_proxy_server.cpp b/host/commands/process_sandboxer/policies/control_env_proxy_server.cpp
new file mode 100644
index 000000000..9db224693
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/control_env_proxy_server.cpp
@@ -0,0 +1,69 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/mman.h>
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder ControlEnvProxyServerPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("control_env_proxy_server"))
+      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddFile("/dev/urandom")  // For gRPC
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW),
+                                        JEQ32(AF_INET, ERRNO(EACCES)),
+                                        JEQ32(AF_INET6, ERRNO(EACCES))})
+      .AddPolicyOnSyscalls(
+          {__NR_getsockopt, __NR_setsockopt},
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),  // level
+                JNE32(SOL_SOCKET,
+                      JUMP(&labels, cf_control_env_proxy_server_sockopt_end)),
+                ARG_32(2),  // optname
+                JEQ32(SO_REUSEPORT, ALLOW),
+                LABEL(&labels, cf_control_env_proxy_server_sockopt_end),
+            };
+          })
+      .AllowChmod()
+      .AllowEventFd()
+      .AllowReaddir()
+      .AllowSafeFcntl()
+      .AllowSleep()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)  // Multi-threading
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_getpeername)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_shutdown)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_sched_getparam)
+      .AllowSyscall(__NR_sched_getscheduler)
+      .AllowSyscall(__NR_sched_yield);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/cvd_internal_start.cpp b/host/commands/process_sandboxer/policies/cvd_internal_start.cpp
new file mode 100644
index 000000000..165cab237
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/cvd_internal_start.cpp
@@ -0,0 +1,57 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/mman.h>
+#include <sys/prctl.h>
+#include <sys/syscall.h>
+#include <sys/un.h>
+
+#include <absl/log/log.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder CvdInternalStartPolicy(const HostInfo& host) {
+  std::string sandboxer_proxy = host.HostToolExe("sandboxer_proxy");
+  return BaselinePolicy(host, host.HostToolExe("cvd_internal_start"))
+      .AddDirectory(host.assembly_dir)
+      .AddDirectory(host.runtime_dir)
+      .AddFile("/dev/null")
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("assemble_cvd"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("run_cvd"))
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      .AddPolicyOnSyscall(__NR_prctl,
+                          {ARG_32(0), JEQ32(PR_SET_PDEATHSIG, ALLOW)})
+      .AllowDup()
+      .AllowPipe()
+      .AllowFork()
+      .AllowSafeFcntl()
+      .AllowSyscall(__NR_execve)
+      .AllowSyscall(__NR_getcwd)
+      .AllowSyscall(__NR_fchdir)
+      .AllowWait()
+      // sandboxer_proxy
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW)})
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sendmsg);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/echo_server.cpp b/host/commands/process_sandboxer/policies/echo_server.cpp
new file mode 100644
index 000000000..10e2d70cf
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/echo_server.cpp
@@ -0,0 +1,57 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/mman.h>
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder EchoServerPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("echo_server"))
+      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddFile("/dev/urandom")  // For gRPC
+      .AddFile(host.cuttlefish_config_path)
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      // Unclear where the INET and INET6 sockets come from
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW),
+                                        JEQ32(AF_INET, ERRNO(EACCES)),
+                                        JEQ32(AF_INET6, ERRNO(EACCES))})
+      .AllowEventFd()
+      .AllowSafeFcntl()
+      .AllowSleep()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)  // Multithreading
+      .AllowSyscall(__NR_getpeername)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_sched_getparam)
+      .AllowSyscall(__NR_sched_getscheduler)
+      .AllowSyscall(__NR_sched_yield)
+      .AllowSyscall(__NR_shutdown);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/gnss_grpc_proxy.cpp b/host/commands/process_sandboxer/policies/gnss_grpc_proxy.cpp
new file mode 100644
index 000000000..24ba97169
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/gnss_grpc_proxy.cpp
@@ -0,0 +1,57 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <errno.h>
+#include <sys/mman.h>
+#include <sys/syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder GnssGrpcProxyPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("gnss_grpc_proxy"))
+      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddFile("/dev/urandom")  // For gRPC
+      .AddFile(host.cuttlefish_config_path)
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW),
+                                        JEQ32(AF_INET, ERRNO(EACCES)),
+                                        JEQ32(AF_INET6, ERRNO(EACCES))})
+      .AllowEventFd()
+      .AllowSafeFcntl()
+      .AllowSleep()
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)  // multithreading
+      .AllowSyscall(__NR_getpeername)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_listen)
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sched_getparam)
+      .AllowSyscall(__NR_sched_getscheduler)
+      .AllowSyscall(__NR_sched_yield)
+      .AllowSyscall(__NR_shutdown)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscalls({__NR_accept, __NR_accept4})
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/kernel_log_monitor.cpp b/host/commands/process_sandboxer/policies/kernel_log_monitor.cpp
index 97b1611d4..d963c184e 100644
--- a/host/commands/process_sandboxer/policies/kernel_log_monitor.cpp
+++ b/host/commands/process_sandboxer/policies/kernel_log_monitor.cpp
@@ -18,39 +18,20 @@
 
 #include <sys/prctl.h>
 
-#include "sandboxed_api/sandbox2/policybuilder.h"
-#include "sandboxed_api/sandbox2/util/bpf_helper.h"
-#include "sandboxed_api/util/path.h"
+#include <sandboxed_api/sandbox2/policybuilder.h>
 
-using sapi::file::JoinPath;
-
-namespace cuttlefish {
+namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder KernelLogMonitorPolicy(const HostInfo& host) {
-  auto exe = JoinPath(host.artifacts_path, "bin", "kernel_log_monitor");
-  auto lib64 = JoinPath(host.artifacts_path, "lib64");
-  return sandbox2::PolicyBuilder()
-      .AddDirectory(lib64)
+  return BaselinePolicy(host, host.HostToolExe("kernel_log_monitor"))
       .AddDirectory(host.log_dir, /* is_ro= */ false)
       .AddFile(host.cuttlefish_config_path)
-      .AddLibrariesForBinary(exe, lib64)
-      // For dynamic linking
-      .AddPolicyOnSyscall(__NR_prctl,
-                          {ARG_32(0), JEQ32(PR_CAPBSET_READ, ALLOW)})
-      .AllowDynamicStartup()
-      .AllowGetPIDs()
-      .AllowGetRandom()
       .AllowHandleSignals()
-      .AllowMmap()
       .AllowOpen()
       .AllowRead()
-      .AllowReadlink()
-      .AllowRestartableSequences(sandbox2::PolicyBuilder::kAllowSlowFences)
       .AllowSelect()
       .AllowSafeFcntl()
-      .AllowSyscall(__NR_tgkill)
-      .AllowTCGETS()
-      .AllowWrite();
+      .AllowTCGETS();
 }
 
-}  // namespace cuttlefish
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/log_tee.cpp b/host/commands/process_sandboxer/policies/log_tee.cpp
new file mode 100644
index 000000000..6da317715
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/log_tee.cpp
@@ -0,0 +1,35 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder LogTeePolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("log_tee"))
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      .AllowPoll()
+      .AllowSafeFcntl()
+      .AllowSyscall(__NR_signalfd4)
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/logcat_receiver.cpp b/host/commands/process_sandboxer/policies/logcat_receiver.cpp
index b761144eb..62d187638 100644
--- a/host/commands/process_sandboxer/policies/logcat_receiver.cpp
+++ b/host/commands/process_sandboxer/policies/logcat_receiver.cpp
@@ -18,38 +18,19 @@
 
 #include <sys/prctl.h>
 
-#include "sandboxed_api/sandbox2/policybuilder.h"
-#include "sandboxed_api/sandbox2/util/bpf_helper.h"
-#include "sandboxed_api/util/path.h"
+#include <sandboxed_api/sandbox2/policybuilder.h>
 
-using sapi::file::JoinPath;
-
-namespace cuttlefish {
+namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder LogcatReceiverPolicy(const HostInfo& host) {
-  auto exe = JoinPath(host.artifacts_path, "bin", "logcat_receiver");
-  auto lib64 = JoinPath(host.artifacts_path, "lib64");
-  return sandbox2::PolicyBuilder()
-      .AddDirectory(lib64)
+  return BaselinePolicy(host, host.HostToolExe("logcat_receiver"))
       .AddDirectory(host.log_dir, /* is_ro= */ false)
       .AddFile(host.cuttlefish_config_path)
-      .AddLibrariesForBinary(exe, lib64)
-      // For dynamic linking
-      .AddPolicyOnSyscall(__NR_prctl,
-                          {ARG_32(0), JEQ32(PR_CAPBSET_READ, ALLOW)})
-      .AllowDynamicStartup()
-      .AllowExit()
-      .AllowGetPIDs()
-      .AllowGetRandom()
       .AllowHandleSignals()
-      .AllowMmap()
       .AllowOpen()
       .AllowRead()
-      .AllowReadlink()
-      .AllowRestartableSequences(sandbox2::PolicyBuilder::kAllowSlowFences)
       .AllowSafeFcntl()
-      .AllowSyscall(__NR_tgkill)
       .AllowWrite();
 }
 
-}  // namespace cuttlefish
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/metrics.cpp b/host/commands/process_sandboxer/policies/metrics.cpp
new file mode 100644
index 000000000..2b6e0b1f6
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/metrics.cpp
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder MetricsPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("metrics"))
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      .Allow(sandbox2::UnrestrictedNetworking())
+      .AllowSafeFcntl()
+      .AllowSyscall(__NR_clone)  // Multithreading
+      // TODO: b/367481626 - Switch `metrics` from System V IPC to another
+      // mechanism that is easier to share in isolation with another sandbox.
+      .AllowSyscall(__NR_msgget)
+      .AllowSyscall(__NR_msgrcv)
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/mkenvimage_slim.cpp b/host/commands/process_sandboxer/policies/mkenvimage_slim.cpp
new file mode 100644
index 000000000..47aa1c395
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/mkenvimage_slim.cpp
@@ -0,0 +1,29 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder MkEnvImgSlimPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("mkenvimage_slim"))
+      .AddDirectory(host.runtime_dir, /* is_ro= */ false)
+      .AllowSafeFcntl();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/modem_simulator.cpp b/host/commands/process_sandboxer/policies/modem_simulator.cpp
new file mode 100644
index 000000000..97aefe04c
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/modem_simulator.cpp
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder ModemSimulatorPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("modem_simulator"))
+      .AddDirectory(host.host_artifacts_path + "/etc/modem_simulator")
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddDirectory(host.runtime_dir, /* is_ro= */ false)  // modem_nvram.json
+      .AddFile(host.cuttlefish_config_path)
+      .AddPolicyOnSyscall(
+          __NR_setsockopt,
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),
+                JNE32(SOL_SOCKET, JUMP(&labels, cf_setsockopt_end)),
+                ARG_32(2),
+                JEQ32(SO_REUSEADDR, ALLOW),
+                LABEL(&labels, cf_setsockopt_end),
+            };
+          })
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW)})
+      .AllowHandleSignals()
+      .AllowPipe()
+      .AllowSafeFcntl()
+      .AllowSelect()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)  // multithreading
+      .AllowSyscall(__NR_listen)
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/netsimd.cpp b/host/commands/process_sandboxer/policies/netsimd.cpp
new file mode 100644
index 000000000..e9620e17f
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/netsimd.cpp
@@ -0,0 +1,98 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <netinet/in.h>
+#include <netinet/tcp.h>
+#include <sys/mman.h>
+#include <sys/prctl.h>
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+#include "host/commands/process_sandboxer/filesystem.h"
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder NetsimdPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("netsimd"))
+      .AddDirectory(JoinPath(host.host_artifacts_path, "bin", "netsim-ui"))
+      .AddDirectory("/tmp", /* is_ro= */ false)  // to create new directories
+      .AddDirectory(JoinPath(host.runtime_dir, "internal"), /* is_ro= */ false)
+      .AddFile("/dev/urandom")  // For gRPC
+      .AddPolicyOnSyscalls(
+          {__NR_getsockopt, __NR_setsockopt},
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),  // level
+                JEQ32(IPPROTO_TCP, JUMP(&labels, cf_netsimd_getsockopt_tcp)),
+                JEQ32(IPPROTO_IPV6, JUMP(&labels, cf_netsimd_getsockopt_ipv6)),
+                JNE32(SOL_SOCKET, JUMP(&labels, cf_netsimd_getsockopt_end)),
+                // SOL_SOCKET
+                ARG_32(2),  // optname
+                JEQ32(SO_REUSEADDR, ALLOW),
+                JEQ32(SO_REUSEPORT, ALLOW),
+                JUMP(&labels, cf_netsimd_getsockopt_end),
+                // IPPROTO_TCP
+                LABEL(&labels, cf_netsimd_getsockopt_tcp),
+                ARG_32(2),  // optname
+                JEQ32(TCP_NODELAY, ALLOW),
+                JEQ32(TCP_USER_TIMEOUT, ALLOW),
+                JUMP(&labels, cf_netsimd_getsockopt_end),
+                // IPPROTO_IPV6
+                LABEL(&labels, cf_netsimd_getsockopt_ipv6),
+                ARG_32(2),  // optname
+                JEQ32(IPV6_V6ONLY, ALLOW),
+                LABEL(&labels, cf_netsimd_getsockopt_end),
+            };
+          })
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      .AddPolicyOnSyscall(__NR_prctl,
+                          {ARG_32(0), JEQ32(PR_CAPBSET_READ, ALLOW)})
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW),
+                                        JEQ32(AF_INET6, ALLOW)})
+      .Allow(sandbox2::UnrestrictedNetworking())
+      .AllowDup()
+      .AllowEpoll()
+      .AllowEpollWait()
+      .AllowEventFd()
+      .AllowHandleSignals()
+      .AllowMkdir()
+      .AllowPipe()
+      .AllowPrctlSetName()
+      .AllowReaddir()
+      .AllowSafeFcntl()
+      .AllowSelect()
+      .AllowSleep()
+      .AllowSyscall(__NR_accept4)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)
+      .AllowSyscall(__NR_getcwd)
+      .AllowSyscall(__NR_getrandom)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_sched_getparam)
+      .AllowSyscall(__NR_sched_getscheduler)
+      .AllowSyscall(__NR_sched_yield)
+      .AllowSyscall(__NR_statx);  // Not covered by AllowStat
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/newfs_msdos.cpp b/host/commands/process_sandboxer/policies/newfs_msdos.cpp
new file mode 100644
index 000000000..326df5db0
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/newfs_msdos.cpp
@@ -0,0 +1,31 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder NewFsMsDosPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("newfs_msdos"))
+      .AddDirectory(host.runtime_dir, /* is_ro= */ false)
+      .AllowSyscall(__NR_ftruncate);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/no_policy.cpp b/host/commands/process_sandboxer/policies/no_policy.cpp
new file mode 100644
index 000000000..9bfa2c1dd
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/no_policy.cpp
@@ -0,0 +1,33 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <set>
+#include <string>
+
+namespace cuttlefish::process_sandboxer {
+
+// TODO(schuffelen): Reduce this list down to only `crosvm`
+// Note that executables launched by executables listed here won't be tracked at
+// all.
+std::set<std::string> NoPolicy(const HostInfo& host) {
+  return {
+      host.HostToolExe("crosvm"),
+      "/usr/bin/openssl",  // TODO
+  };
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/openwrt_control_server.cpp b/host/commands/process_sandboxer/policies/openwrt_control_server.cpp
new file mode 100644
index 000000000..c6ac46dd4
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/openwrt_control_server.cpp
@@ -0,0 +1,84 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <netinet/tcp.h>
+#include <sys/mman.h>
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder OpenWrtControlServerPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("openwrt_control_server"))
+      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.log_dir)
+      .AddFile("/dev/urandom")  // For gRPC
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      .AddPolicyOnSyscall(
+          __NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW), JEQ32(AF_INET, ALLOW),
+                        JEQ32(AF_INET6, ALLOW)})
+      .AddPolicyOnSyscalls(
+          {__NR_getsockopt, __NR_setsockopt},
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),  // level
+                JEQ32(IPPROTO_TCP,
+                      JUMP(&labels, cf_open_wrt_control_server_sockopt_ip)),
+                JNE32(SOL_SOCKET,
+                      JUMP(&labels, cf_open_wrt_control_server_sockopt_end)),
+                // SOL_SOCKET
+                ARG_32(2),  // optname
+                JEQ32(SO_ERROR, ALLOW),
+                JEQ32(SO_REUSEPORT, ALLOW),
+                JUMP(&labels, cf_open_wrt_control_server_sockopt_end),
+                // IPPROTO_TCP
+                LABEL(&labels, cf_open_wrt_control_server_sockopt_ip),
+                ARG_32(2),  // optname
+                JEQ32(TCP_NODELAY, ALLOW),
+                LABEL(&labels, cf_open_wrt_control_server_sockopt_end),
+            };
+          })
+      .Allow(sandbox2::UnrestrictedNetworking())  // HTTP calls to luci
+      .AllowEventFd()
+      .AllowSafeFcntl()
+      .AllowHandleSignals()
+      .AllowPipe()
+      .AllowSleep()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)  // Multithreading
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_getpeername)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_recvfrom)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sched_getparam)
+      .AllowSyscall(__NR_sched_getscheduler)
+      .AllowSyscall(__NR_sched_yield)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_sendto)
+      .AllowSyscall(__NR_shutdown);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/operator_proxy.cpp b/host/commands/process_sandboxer/policies/operator_proxy.cpp
new file mode 100644
index 000000000..3c7da6127
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/operator_proxy.cpp
@@ -0,0 +1,33 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder OperatorProxyPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("openwrt_control_server"))
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AllowSyscall(__NR_tgkill)
+      .Allow(sandbox2::UnrestrictedNetworking());  // Public HTTP server
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/process_restarter.cpp b/host/commands/process_sandboxer/policies/process_restarter.cpp
new file mode 100644
index 000000000..14adad7fe
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/process_restarter.cpp
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/prctl.h>
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <absl/log/log.h>
+#include <absl/strings/str_cat.h>
+#include <absl/strings/str_replace.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder ProcessRestarterPolicy(const HostInfo& host) {
+  std::string sandboxer_proxy = host.HostToolExe("sandboxer_proxy");
+  return BaselinePolicy(host, host.HostToolExe("process_restarter"))
+      .AddDirectory(host.runtime_dir, /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("adb_connector"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("casimir"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("crosvm"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("root-canal"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("vhost_device_vsock"))
+      .AddPolicyOnSyscall(__NR_prctl,
+                          {ARG_32(0), JEQ32(PR_SET_PDEATHSIG, ALLOW)})
+      .AllowFork()
+      .AllowSafeFcntl()
+      .AllowSyscall(SYS_execve)  // To enter sandboxer_proxy
+      .AllowSyscall(SYS_waitid)
+      .AllowTCGETS()
+      // For sandboxer_proxy
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW)})
+      .AllowExit()
+      .AllowSyscall(SYS_connect)
+      .AllowSyscall(SYS_recvmsg)
+      .AllowSyscall(SYS_sendmsg);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/run_cvd.cpp b/host/commands/process_sandboxer/policies/run_cvd.cpp
new file mode 100644
index 000000000..0ec1fcc08
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/run_cvd.cpp
@@ -0,0 +1,139 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/mman.h>
+#include <sys/prctl.h>
+#include <sys/socket.h>
+#include <sys/stat.h>
+#include <syscall.h>
+
+#include <absl/strings/str_cat.h>
+#include <absl/strings/str_replace.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder RunCvdPolicy(const HostInfo& host) {
+  std::string sandboxer_proxy = host.HostToolExe("sandboxer_proxy");
+  return BaselinePolicy(host, host.HostToolExe("run_cvd"))
+      .AddDirectory(host.runtime_dir, /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("adb_connector"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("casimir_control_server"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("control_env_proxy_server"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("crosvm"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("echo_server"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("gnss_grpc_proxy"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("kernel_log_monitor"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("log_tee"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("logcat_receiver"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("metrics"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("modem_simulator"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("netsimd"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("openwrt_control_server"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("operator_proxy"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("process_restarter"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("screen_recording_server"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("secure_env"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("socket_vsock_proxy"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("tcp_connector"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("tombstone_receiver"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("webRTC"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("webrtc_operator"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("wmediumd"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("wmediumd_gen_config"))
+      .AddDirectory(host.environments_dir)
+      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
+      // The UID inside the sandbox2 namespaces is always 1000.
+      .AddDirectoryAt(host.environments_uds_dir,
+                      absl::StrReplaceAll(
+                          host.environments_uds_dir,
+                          {{absl::StrCat("cf_env_", getuid()), "cf_env_1000"}}),
+                      false)
+      .AddDirectoryAt(host.instance_uds_dir,
+                      absl::StrReplaceAll(
+                          host.instance_uds_dir,
+                          {{absl::StrCat("cf_avd_", getuid()), "cf_avd_1000"}}),
+                      false)
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      .AddPolicyOnSyscall(
+          __NR_mknodat,
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(2),
+                // a <- a & S_IFMT // Mask to only the file type bits
+                BPF_STMT(BPF_ALU + BPF_AND + BPF_K,
+                         static_cast<uint32_t>(S_IFMT)),
+                // Only allow `mkfifo`
+                JNE32(S_IFIFO, JUMP(&labels, cf_mknodat_end)),
+                ARG_32(3),
+                JEQ32(0, ALLOW),
+                LABEL(&labels, cf_mknodat_end),
+            };
+          })
+      .AddPolicyOnSyscall(__NR_prctl,
+                          {ARG_32(0), JEQ32(PR_SET_PDEATHSIG, ALLOW),
+                           JEQ32(PR_SET_CHILD_SUBREAPER, ALLOW)})
+      .AddPolicyOnSyscall(
+          __NR_setsockopt,
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),
+                JNE32(SOL_SOCKET, JUMP(&labels, cf_setsockopt_end)),
+                ARG_32(2),
+                JEQ32(SO_REUSEADDR, ALLOW),
+                JEQ32(SO_RCVTIMEO, ALLOW),
+                LABEL(&labels, cf_setsockopt_end),
+            };
+          })
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW),
+                                        JEQ32(AF_VSOCK, ALLOW)})
+      .AllowChmod()
+      .AllowDup()
+      .AllowEventFd()
+      .AllowFork()  // Multithreading, sandboxer_proxy, process monitor
+      .AllowGetIDs()
+      .AllowInotifyInit()
+      .AllowMkdir()
+      .AllowPipe()
+      .AllowSafeFcntl()
+      .AllowSelect()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_execve)  // sandboxer_proxy
+      .AllowSyscall(__NR_getsid)
+      .AllowSyscall(__NR_inotify_add_watch)
+      .AllowSyscall(__NR_inotify_rm_watch)
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_msgget)  // Metrics SysV RPC
+      .AllowSyscall(__NR_msgsnd)  // Metrics SysV RPC
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_setpgid)
+      .AllowSyscall(__NR_socketpair)
+      .AllowSyscall(__NR_waitid)  // Not covered by `AllowWait()`
+      .AllowTCGETS()
+      .AllowUnlink()
+      .AllowWait();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/screen_recording_server.cpp b/host/commands/process_sandboxer/policies/screen_recording_server.cpp
new file mode 100644
index 000000000..b260da865
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/screen_recording_server.cpp
@@ -0,0 +1,72 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <errno.h>
+#include <sys/mman.h>
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder ScreenRecordingServerPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("screen_recording_server"))
+      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddFile("/dev/urandom")  // For gRPC
+      .AddFile(host.cuttlefish_config_path)
+      .AddPolicyOnSyscalls(
+          {__NR_getsockopt, __NR_setsockopt},
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),  // level
+                JNE32(SOL_SOCKET,
+                      JUMP(&labels, cf_screen_recording_server_getsockopt_end)),
+                ARG_32(2),  // optname
+                JEQ32(SO_REUSEPORT, ALLOW),
+                LABEL(&labels, cf_screen_recording_server_getsockopt_end),
+            };
+          })
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      // Unclear where the INET and INET6 sockets come from
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW),
+                                        JEQ32(AF_INET, ERRNO(EACCES)),
+                                        JEQ32(AF_INET6, ERRNO(EACCES))})
+      .AllowEventFd()
+      .AllowSafeFcntl()
+      .AllowSleep()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)  // Multithreading
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_getpeername)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sched_getparam)
+      .AllowSyscall(__NR_sched_getscheduler)
+      .AllowSyscall(__NR_sched_yield)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_shutdown)
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/secure_env.cpp b/host/commands/process_sandboxer/policies/secure_env.cpp
new file mode 100644
index 000000000..1b5629729
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/secure_env.cpp
@@ -0,0 +1,52 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder SecureEnvPolicy(const HostInfo& host) {
+  std::string exe = host.HostToolExe("secure_env");
+  return BaselinePolicy(host, exe)
+      // ms-tpm-20-ref creates a NVChip file in the runtime directory
+      .AddDirectory(host.runtime_dir, /* is_ro= */ false)
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      .AddFile(exe)  // to exec itself
+      .AllowDup()
+      .AllowFork()    // Something is using clone, not sure what
+      .AllowGetIDs()  // For getuid
+      .AllowSafeFcntl()
+      .AllowSelect()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_execve)  // to exec itself
+      // Something is using arguments not allowed by AllowGetRandom()
+      .AllowSyscall(__NR_getrandom)
+      .AllowSyscall(__NR_madvise)
+      // statx not covered by AllowStat()
+      .AllowSyscall(__NR_statx)
+      .AllowSyscall(__NR_socketpair)
+      .AllowSyscall(__NR_tgkill)
+      .AllowUnlink()  // keymint_secure_deletion_data
+      .AllowTCGETS()
+      .AllowTime();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/simg2img.cpp b/host/commands/process_sandboxer/policies/simg2img.cpp
new file mode 100644
index 000000000..a3266aa77
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/simg2img.cpp
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/mman.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder Simg2ImgPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("simg2img"))
+      .AddDirectory(host.guest_image_path, /* is_ro= */ false)
+      .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
+        return {
+            ARG_32(2),  // prot
+            JNE32(PROT_READ, JUMP(&labels, cf_simg2img_mmap_end)),
+            ARG_32(3),  // flags
+            JEQ32(MAP_SHARED, ALLOW),
+            LABEL(&labels, cf_simg2img_mmap_end),
+        };
+      })
+      .AllowSyscall(__NR_ftruncate);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/socket_vsock_proxy.cpp b/host/commands/process_sandboxer/policies/socket_vsock_proxy.cpp
new file mode 100644
index 000000000..053536e68
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/socket_vsock_proxy.cpp
@@ -0,0 +1,53 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder SocketVsockProxyPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("socket_vsock_proxy"))
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      .AddPolicyOnSyscall(
+          __NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW), JEQ32(AF_INET, ALLOW),
+                        JEQ32(AF_INET6, ALLOW), JEQ32(AF_VSOCK, ALLOW)})
+      .Allow(sandbox2::UnrestrictedNetworking())
+      .AllowEventFd()
+      .AllowFork()  // `clone` for multithreading
+      .AllowGetIDs()
+      .AllowHandleSignals()
+      .AllowSafeFcntl()
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_madvise)
+      .AllowSyscall(__NR_sendto)
+      .AllowSyscall(__NR_setsockopt)
+      .AllowSyscall(__NR_shutdown)
+      .AllowSyscalls({__NR_accept, __NR_accept4})
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/tcp_connector.cpp b/host/commands/process_sandboxer/policies/tcp_connector.cpp
new file mode 100644
index 000000000..ea683f759
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/tcp_connector.cpp
@@ -0,0 +1,40 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder TcpConnectorPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("tcp_connector"))
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW)})
+      .Allow(sandbox2::UnrestrictedNetworking())
+      .AllowSafeFcntl()
+      .AllowSleep()
+      .AllowSyscall(__NR_clone)  // Multithreading
+      .AllowSyscall(__NR_connect)
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/tombstone_receiver.cpp b/host/commands/process_sandboxer/policies/tombstone_receiver.cpp
new file mode 100644
index 000000000..446cee2f9
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/tombstone_receiver.cpp
@@ -0,0 +1,41 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+
+#include "host/commands/process_sandboxer/filesystem.h"
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder TombstoneReceiverPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("tombstone_receiver"))
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddDirectory(JoinPath(host.runtime_dir, "tombstones"),
+                    /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      .AllowSafeFcntl()
+      .AllowSelect()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_recvfrom)
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/vhost_device_vsock.cpp b/host/commands/process_sandboxer/policies/vhost_device_vsock.cpp
new file mode 100644
index 000000000..d9f109200
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/vhost_device_vsock.cpp
@@ -0,0 +1,62 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/ioctl.h>
+#include <sys/mman.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder VhostDeviceVsockPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("vhost_device_vsock"))
+      .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
+      .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
+        return {
+            ARG_32(2),  // prot
+            JNE32(PROT_READ | PROT_WRITE, JUMP(&labels, cf_webrtc_mmap_end)),
+            ARG_32(3),  // flags
+            JEQ32(MAP_STACK | MAP_PRIVATE | MAP_ANONYMOUS, ALLOW),
+            JEQ32(MAP_NORESERVE | MAP_SHARED, ALLOW),
+            LABEL(&labels, cf_webrtc_mmap_end),
+        };
+      })
+      .AddPolicyOnSyscall(__NR_ioctl, {ARG_32(1), JEQ32(FIONBIO, ALLOW)})
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW)})
+      .AllowDup()
+      .AllowEpoll()
+      .AllowEpollWait()
+      .AllowEventFd()
+      .AllowHandleSignals()
+      .AllowPrctlSetName()
+      .AllowSafeFcntl()
+      .AllowSyscall(__NR_accept4)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_getrandom)  // AllowGetRandom won't take GRND_INSECURE
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_recvfrom)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowUnlink();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/webrtc.cpp b/host/commands/process_sandboxer/policies/webrtc.cpp
new file mode 100644
index 000000000..3272ad059
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/webrtc.cpp
@@ -0,0 +1,153 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <netinet/in.h>
+#include <netinet/tcp.h>
+#include <sys/ioctl.h>
+#include <sys/mman.h>
+#include <sys/prctl.h>
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+#include "host/commands/process_sandboxer/filesystem.h"
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder WebRtcPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("webRTC"))
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddDirectory(host.host_artifacts_path + "/usr/share/webrtc/assets")
+      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
+      .AddDirectory(JoinPath(host.runtime_dir, "recording"), /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      .AddFile("/dev/urandom")
+      .AddFile("/run/cuttlefish/operator")
+      // Shared memory with crosvm for audio
+      .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
+        return {
+            ARG_32(2),  // prot
+            JNE32(PROT_READ | PROT_WRITE, JUMP(&labels, cf_webrtc_mmap_end)),
+            ARG_32(3),  // flags
+            JEQ32(MAP_SHARED, ALLOW),
+            LABEL(&labels, cf_webrtc_mmap_end),
+        };
+      })
+      .AddPolicyOnSyscall(
+          __NR_getsockopt,
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),  // level
+                JNE32(SOL_SOCKET, JUMP(&labels, cf_webrtc_getsockopt_end)),
+                ARG_32(2),  // optname
+                JEQ32(SO_ERROR, ALLOW),
+                JEQ32(SO_PEERCRED, ALLOW),
+                LABEL(&labels, cf_webrtc_getsockopt_end),
+            };
+          })
+      .AddPolicyOnSyscall(__NR_ioctl, {ARG_32(1), JEQ32(SIOCGSTAMP, ALLOW),
+                                       JEQ32(FIONREAD, ALLOW)})
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_WIPEONFORK, ALLOW),
+                           JEQ32(MADV_DONTNEED, ALLOW),
+                           // TODO: schuffelen - find out what this is
+                           JEQ32(0xffffffff, ALLOW)})
+      .AddPolicyOnSyscall(__NR_prctl,
+                          {ARG_32(0), JEQ32(PR_CAPBSET_READ, ALLOW)})
+      .AddPolicyOnSyscall(
+          __NR_setsockopt,
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),  // level
+                JEQ32(SOL_IP, JUMP(&labels, cf_webrtc_setsockopt_ip)),
+                JEQ32(SOL_IPV6, JUMP(&labels, cf_webrtc_setsockopt_ipv6)),
+                JEQ32(SOL_SOCKET, JUMP(&labels, cf_webrtc_setsockopt_sol)),
+                JNE32(IPPROTO_TCP, JUMP(&labels, cf_webrtc_setsockopt_end)),
+                // IPPROTO_TCP
+                ARG_32(2),  // optname
+                JEQ32(TCP_NODELAY, ALLOW),
+                JUMP(&labels, cf_webrtc_setsockopt_end),
+                // SOL_IP
+                LABEL(&labels, cf_webrtc_setsockopt_ip),
+                ARG_32(2),  // optname
+                JEQ32(IP_RECVERR, ALLOW),
+                JEQ32(IP_TOS, ALLOW),
+                JEQ32(IP_RETOPTS, ALLOW),
+                JEQ32(IP_PKTINFO, ALLOW),
+                JUMP(&labels, cf_webrtc_setsockopt_end),
+                // SOL_IPV6
+                LABEL(&labels, cf_webrtc_setsockopt_ipv6),
+                ARG_32(2),  // optname
+                JEQ32(IPV6_TCLASS, ALLOW),
+                JUMP(&labels, cf_webrtc_setsockopt_end),
+                // SOL_SOCKET
+                LABEL(&labels, cf_webrtc_setsockopt_sol),
+                ARG_32(2),  // optname
+                JEQ32(SO_REUSEADDR, ALLOW),
+                JEQ32(SO_SNDBUF, ALLOW),
+                JEQ32(SO_RCVBUF, ALLOW),
+                LABEL(&labels, cf_webrtc_setsockopt_end),
+            };
+          })
+      .AddPolicyOnSyscall(
+          __NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW), JEQ32(AF_UNIX, ALLOW),
+                        JEQ32(AF_INET6, ALLOW),
+                        // webrtc/rtc_base/ifaddrs_android.cc
+                        JEQ32(AF_NETLINK, ALLOW), JEQ32(AF_VSOCK, ALLOW)})
+      .Allow(sandbox2::UnrestrictedNetworking())
+      .AllowEpoll()
+      .AllowEpollWait()
+      .AllowEventFd()
+      .AllowGetIDs()
+      .AllowHandleSignals()
+      .AllowPipe()
+      .AllowPrctlSetName()
+      .AllowSafeFcntl()
+      .AllowSelect()
+      .AllowSleep()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_accept4)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)  // Multithreading
+      .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_ftruncate)
+      .AllowSyscall(__NR_getpeername)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_memfd_create)
+      .AllowSyscall(__NR_recvfrom)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sched_get_priority_max)
+      .AllowSyscall(__NR_sched_get_priority_min)
+      .AllowSyscall(__NR_sched_getparam)
+      .AllowSyscall(__NR_sched_getscheduler)
+      .AllowSyscall(__NR_sched_setscheduler)
+      .AllowSyscall(__NR_sched_yield)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_sendmmsg)
+      .AllowSyscall(__NR_sendto)
+      .AllowSyscall(__NR_shutdown)
+      .AllowSyscall(__NR_socketpair)
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/webrtc_operator.cpp b/host/commands/process_sandboxer/policies/webrtc_operator.cpp
new file mode 100644
index 000000000..938779492
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/webrtc_operator.cpp
@@ -0,0 +1,76 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <netinet/ip_icmp.h>
+#include <netinet/tcp.h>
+#include <sys/mman.h>
+#include <sys/prctl.h>
+#include <sys/syscall.h>
+
+#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+#include "host/commands/process_sandboxer/filesystem.h"
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder WebRtcOperatorPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("webrtc_operator"))
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddDirectory(
+          JoinPath(host.host_artifacts_path, "usr", "share", "webrtc"))
+      .AddFile("/dev/urandom")  // For libwebsockets
+      .AddFile(host.cuttlefish_config_path)
+      .AllowEventFd()
+      .AllowHandleSignals()
+      .AddPolicyOnSyscall(
+          __NR_madvise,
+          {ARG_32(2), JEQ32(MADV_WIPEONFORK, ALLOW), JEQ32(0xffffffff, ALLOW)})
+      .AddPolicyOnSyscall(__NR_prctl,
+                          {ARG_32(0), JEQ32(PR_CAPBSET_READ, ALLOW)})
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW)})
+      .AddPolicyOnSyscall(
+          __NR_setsockopt,
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {ARG_32(1),  // level
+                    JEQ32(IPPROTO_ICMP,
+                          JUMP(&labels, cf_webrtc_operator_setsockopt_icmp)),
+                    JNE32(IPPROTO_TCP,
+                          JUMP(&labels, cf_webrtc_operator_setsockopt_end)),
+                    // IPPROTO_TCP
+                    ARG_32(2),  // optname
+                    JEQ32(TCP_NODELAY, ALLOW),
+                    JUMP(&labels, cf_webrtc_operator_setsockopt_end),
+                    // IPPROTO_ICMP
+                    LABEL(&labels, cf_webrtc_operator_setsockopt_icmp),
+                    ARG_32(2),  // optname
+                    JEQ32(ICMP_REDIR_NETTOS, ALLOW),
+                    LABEL(&labels, cf_webrtc_operator_setsockopt_end)};
+          })
+      .Allow(sandbox2::UnrestrictedNetworking())
+      .AllowSafeFcntl()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_getpeername)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_listen)
+      .AllowTCGETS();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/wmediumd.cpp b/host/commands/process_sandboxer/policies/wmediumd.cpp
new file mode 100644
index 000000000..ac51ef5a2
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/wmediumd.cpp
@@ -0,0 +1,91 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sys/mman.h>
+#include <sys/socket.h>
+#include <syscall.h>
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/sandbox2/util/bpf_helper.h>
+
+#include "host/commands/process_sandboxer/filesystem.h"
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder WmediumdPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("wmediumd"))
+      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.log_dir, /* is_ro= */ false)
+      .AddFile("/dev/urandom")  // For gRPC
+      .AddFile(JoinPath(host.environments_dir, "env-1", "wmediumd.cfg"),
+               /* is_ro= */ false)
+      .AddFile(host.cuttlefish_config_path)
+      // Shared memory with crosvm for wifi
+      .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
+        return {
+            ARG_32(2),  // prot
+            JNE32(PROT_READ | PROT_WRITE, JUMP(&labels, cf_webrtc_mmap_end)),
+            ARG_32(3),  // flags
+            JEQ32(MAP_SHARED, ALLOW),
+            LABEL(&labels, cf_webrtc_mmap_end),
+        };
+      })
+      .AddPolicyOnSyscalls(
+          {__NR_getsockopt, __NR_setsockopt},
+          [](bpf_labels& labels) -> std::vector<sock_filter> {
+            return {
+                ARG_32(1),  // level
+                JNE32(SOL_SOCKET,
+                      JUMP(&labels, cf_screen_recording_server_getsockopt_end)),
+                ARG_32(2),  // optname
+                JEQ32(SO_REUSEPORT, ALLOW),
+                LABEL(&labels, cf_screen_recording_server_getsockopt_end),
+            };
+          })
+      .AddPolicyOnSyscall(__NR_madvise,
+                          {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
+      // Unclear what's creating the INET and INET6 sockets
+      .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW),
+                                        JEQ32(AF_INET, ERRNO(EACCES)),
+                                        JEQ32(AF_INET6, ERRNO(EACCES))})
+      .AllowEventFd()
+      .AllowHandleSignals()
+      .AllowSafeFcntl()
+      .AllowSelect()
+      .AllowSleep()
+      .AllowSyscall(__NR_accept)
+      .AllowSyscall(__NR_bind)
+      .AllowSyscall(__NR_clone)  // Multithreading
+      .AllowSyscall(__NR_getpeername)
+      .AllowSyscall(__NR_getsockname)
+      .AllowSyscall(__NR_listen)
+      .AllowSyscall(__NR_msgget)
+      .AllowSyscall(__NR_msgsnd)
+      .AllowSyscall(__NR_msgrcv)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sched_getparam)
+      .AllowSyscall(__NR_sched_getscheduler)
+      .AllowSyscall(__NR_sched_yield)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_shutdown)
+      .AllowSyscall(__NR_timerfd_create)
+      .AllowSyscall(__NR_timerfd_settime);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/wmediumd_gen_config.cpp b/host/commands/process_sandboxer/policies/wmediumd_gen_config.cpp
new file mode 100644
index 000000000..5a6477a30
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/wmediumd_gen_config.cpp
@@ -0,0 +1,31 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/policies.h"
+
+#include <sandboxed_api/sandbox2/policybuilder.h>
+
+#include "host/commands/process_sandboxer/filesystem.h"
+
+namespace cuttlefish::process_sandboxer {
+
+sandbox2::PolicyBuilder WmediumdGenConfigPolicy(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("wmediumd_gen_config"))
+      .AddDirectory(JoinPath(host.environments_dir, "env-1"),
+                    /* is_ro= */ false);
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/poll_callback.cpp b/host/commands/process_sandboxer/poll_callback.cpp
new file mode 100644
index 000000000..6b4d398be
--- /dev/null
+++ b/host/commands/process_sandboxer/poll_callback.cpp
@@ -0,0 +1,60 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/commands/process_sandboxer/poll_callback.h"
+
+#include <poll.h>
+
+#include <functional>
+#include <vector>
+
+#include <absl/log/log.h>
+#include <absl/status/status.h>
+
+namespace cuttlefish {
+namespace process_sandboxer {
+
+void PollCallback::Add(int fd, std::function<absl::Status(short)> cb) {
+  pollfds_.emplace_back(pollfd{
+      .fd = fd,
+      .events = POLLIN,
+  });
+  callbacks_.emplace_back(std::move(cb));
+}
+
+absl::Status PollCallback::Poll() {
+  int poll_ret = poll(pollfds_.data(), pollfds_.size(), 0);
+  if (poll_ret < 0) {
+    return absl::Status(absl::ErrnoToStatusCode(errno), "`poll` failed");
+  }
+
+  VLOG(2) << "`poll` returned " << poll_ret;
+
+  for (size_t i = 0; i < pollfds_.size() && i < callbacks_.size(); i++) {
+    const auto& poll_fd = pollfds_[i];
+    if (poll_fd.revents == 0) {
+      continue;
+    }
+    auto status = callbacks_[i](poll_fd.revents);
+    if (!status.ok()) {
+      return status;
+    }
+  }
+  return absl::OkStatus();
+}
+
+}  // namespace process_sandboxer
+}  // namespace cuttlefish
diff --git a/host/commands/process_sandboxer/poll_callback.h b/host/commands/process_sandboxer/poll_callback.h
new file mode 100644
index 000000000..fdc77765a
--- /dev/null
+++ b/host/commands/process_sandboxer/poll_callback.h
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#ifndef ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_POLL_CALLBACK_H
+#define ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_POLL_CALLBACK_H
+
+#include <poll.h>
+
+#include <functional>
+#include <vector>
+
+#include <absl/status/status.h>
+
+namespace cuttlefish {
+namespace process_sandboxer {
+
+class PollCallback {
+ public:
+  void Add(int fd, std::function<absl::Status(short)> cb);
+
+  absl::Status Poll();
+
+ private:
+  std::vector<pollfd> pollfds_;
+  std::vector<std::function<absl::Status(short)>> callbacks_;
+};
+
+}  // namespace process_sandboxer
+}  // namespace cuttlefish
+
+#endif
diff --git a/host/commands/process_sandboxer/proxy_common.cpp b/host/commands/process_sandboxer/proxy_common.cpp
new file mode 100644
index 000000000..4b12cb281
--- /dev/null
+++ b/host/commands/process_sandboxer/proxy_common.cpp
@@ -0,0 +1,94 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "proxy_common.h"
+
+#include <sys/socket.h>
+
+#include <absl/status/statusor.h>
+#include <absl/strings/numbers.h>
+
+#include <cstdlib>
+#include <string>
+#include "absl/status/status.h"
+
+namespace cuttlefish::process_sandboxer {
+
+absl::StatusOr<Message> Message::RecvFrom(int sock) {
+  msghdr empty_hdr;
+  int len = recvmsg(sock, &empty_hdr, MSG_PEEK | MSG_TRUNC);
+  if (len < 0) {
+    return absl::ErrnoToStatus(errno, "recvmsg with MSG_PEEK failed");
+  }
+
+  Message message;
+  message.data_ = std::string(len, '\0');
+
+  iovec msg_iovec = iovec{
+      .iov_base = reinterpret_cast<void*>(message.data_.data()),
+      .iov_len = static_cast<size_t>(len),
+  };
+
+  union {
+    char buf[CMSG_SPACE(sizeof(ucred))];
+    struct cmsghdr align;
+  } cmsg_data;
+  std::memset(cmsg_data.buf, 0, sizeof(cmsg_data.buf));
+
+  msghdr hdr = msghdr{
+      .msg_iov = &msg_iovec,
+      .msg_iovlen = 1,
+      .msg_control = cmsg_data.buf,
+      .msg_controllen = sizeof(cmsg_data.buf),
+  };
+
+  auto recvmsg_ret = recvmsg(sock, &hdr, 0);
+  if (recvmsg_ret < 0) {
+    return absl::ErrnoToStatus(errno, "recvmsg failed");
+  }
+
+  for (auto cmsg = CMSG_FIRSTHDR(&hdr); cmsg != nullptr;
+       cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
+    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
+      message.credentials_ = *(ucred*)CMSG_DATA(cmsg);
+    }
+  }
+
+  return message;
+}
+
+const std::string& Message::Data() const { return data_; }
+
+const std::optional<ucred>& Message::Credentials() const {
+  return credentials_;
+}
+
+absl::StatusOr<size_t> SendStringMsg(int sock, std::string_view msg) {
+  iovec msg_iovec = iovec{
+      .iov_base = (void*)msg.data(),
+      .iov_len = msg.length(),
+  };
+
+  msghdr hdr = msghdr{
+      .msg_iov = &msg_iovec,
+      .msg_iovlen = 1,
+  };
+
+  auto ret = sendmsg(sock, &hdr, MSG_EOR | MSG_NOSIGNAL);
+  return ret >= 0 ? absl::StatusOr<size_t>(ret)
+                  : absl::ErrnoToStatus(errno, "sendmsg failed");
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/proxy_common.h b/host/commands/process_sandboxer/proxy_common.h
new file mode 100644
index 000000000..fe80c0656
--- /dev/null
+++ b/host/commands/process_sandboxer/proxy_common.h
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#ifndef ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_SANDBOX_PROCESS_PROXY_COMMON_H
+#define ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_SANDBOX_PROCESS_PROXY_COMMON_H
+
+#include <sys/socket.h>
+#include <sys/un.h>
+
+#include "absl/status/statusor.h"
+
+#include <optional>
+#include <string>
+#include <string_view>
+
+namespace cuttlefish {
+namespace process_sandboxer {
+
+static const constexpr std::string_view kHandshakeBegin = "hello";
+static const constexpr std::string_view kManagerSocketPath = "/manager.sock";
+
+class Message {
+ public:
+  static absl::StatusOr<Message> RecvFrom(int sock);
+
+  const std::string& Data() const;
+  absl::StatusOr<int> DataAsInt() const;
+
+  const std::optional<ucred>& Credentials() const;
+
+  std::string StrError() const;
+
+ private:
+  Message() = default;
+
+  std::string data_;
+  std::optional<ucred> credentials_;
+};
+
+absl::StatusOr<size_t> SendStringMsg(int sock, std::string_view msg);
+
+}  // namespace process_sandboxer
+}  // namespace cuttlefish
+#endif
diff --git a/host/commands/process_sandboxer/sandbox_manager.cpp b/host/commands/process_sandboxer/sandbox_manager.cpp
new file mode 100644
index 000000000..e6cf6fd64
--- /dev/null
+++ b/host/commands/process_sandboxer/sandbox_manager.cpp
@@ -0,0 +1,572 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/sandbox_manager.h"
+
+#include <fcntl.h>
+#include <linux/sched.h>
+#include <signal.h>
+#include <sys/eventfd.h>
+#include <sys/prctl.h>
+#include <sys/signalfd.h>
+#include <sys/socket.h>
+#include <sys/syscall.h>
+#include <sys/un.h>
+#include <sys/wait.h>
+#include <unistd.h>
+
+#include <memory>
+#include <sstream>
+#include <utility>
+
+#include <absl/functional/bind_front.h>
+#include <absl/log/log.h>
+#include <absl/log/vlog_is_on.h>
+#include <absl/memory/memory.h>
+#include <absl/status/status.h>
+#include <absl/status/statusor.h>
+#include <absl/strings/numbers.h>
+#include <absl/strings/str_cat.h>
+#include <absl/strings/str_format.h>
+#include <absl/strings/str_join.h>
+#include <absl/types/span.h>
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wunused-parameter"
+#include <sandboxed_api/sandbox2/executor.h>
+#include <sandboxed_api/sandbox2/notify.h>
+#include <sandboxed_api/sandbox2/policy.h>
+#include <sandboxed_api/sandbox2/sandbox2.h>
+#include <sandboxed_api/sandbox2/util.h>
+#pragma clang diagnostic pop
+
+#include "host/commands/process_sandboxer/credentialed_unix_server.h"
+#include "host/commands/process_sandboxer/filesystem.h"
+#include "host/commands/process_sandboxer/pidfd.h"
+#include "host/commands/process_sandboxer/policies.h"
+#include "host/commands/process_sandboxer/poll_callback.h"
+#include "host/commands/process_sandboxer/proxy_common.h"
+
+namespace cuttlefish::process_sandboxer {
+
+using sandbox2::Executor;
+using sandbox2::Policy;
+using sandbox2::Sandbox2;
+using sandbox2::Syscall;
+using sandbox2::util::GetProgName;
+
+namespace {
+
+std::string ServerSocketOutsidePath(std::string_view runtime_dir) {
+  return JoinPath(runtime_dir, "/", "server.sock");
+}
+
+}  // namespace
+
+class SandboxManager::ProcessNoSandbox : public SandboxManager::ManagedProcess {
+ public:
+  ProcessNoSandbox(int client_fd, PidFd pid_fd)
+      : client_fd_(client_fd), pid_fd_(std::move(pid_fd)) {}
+  ~ProcessNoSandbox() {
+    auto halt = pid_fd_.HaltHierarchy();
+    if (!halt.ok()) {
+      LOG(ERROR) << "Failed to halt children: " << halt.ToString();
+    }
+  }
+
+  std::optional<int> ClientFd() const override { return client_fd_; }
+  int PollFd() const override { return pid_fd_.Get(); }
+
+  absl::StatusOr<uintptr_t> ExitCode() override {
+    siginfo_t infop;
+    idtype_t id_type = (idtype_t)3;  // P_PIDFD
+    if (waitid(id_type, pid_fd_.Get(), &infop, WEXITED | WNOWAIT) < 0) {
+      return absl::ErrnoToStatus(errno, "`waitid` failed");
+    }
+    switch (infop.si_code) {
+      case CLD_EXITED:
+        return infop.si_status;
+      case CLD_DUMPED:
+      case CLD_KILLED:
+        LOG(ERROR) << "Child killed by signal " << infop.si_code;
+        return 255;
+      default:
+        LOG(ERROR) << "Unexpected si_code: " << infop.si_code;
+        return 255;
+    }
+  }
+
+ private:
+  int client_fd_;
+  PidFd pid_fd_;
+};
+
+class SandboxManager::SandboxedProcess : public SandboxManager::ManagedProcess {
+ public:
+  SandboxedProcess(std::optional<int> client_fd, UniqueFd event_fd,
+                   std::unique_ptr<Sandbox2> sandbox)
+      : client_fd_(client_fd),
+        event_fd_(std::move(event_fd)),
+        sandbox_(std::move(sandbox)) {
+    waiter_thread_ = std::thread([this]() { WaitForExit(); });
+  }
+  ~SandboxedProcess() override {
+    sandbox_->Kill();
+    waiter_thread_.join();
+    auto res = sandbox_->AwaitResult().ToStatus();
+    if (!res.ok()) {
+      LOG(ERROR) << "Issue in closing sandbox: '" << res.ToString() << "'";
+    }
+  }
+
+  std::optional<int> ClientFd() const override { return client_fd_; }
+  int PollFd() const override { return event_fd_.Get(); }
+
+  absl::StatusOr<uintptr_t> ExitCode() override {
+    return sandbox_->AwaitResult().reason_code();
+  }
+
+ private:
+  void WaitForExit() {
+    sandbox_->AwaitResult().IgnoreResult();
+    uint64_t buf = 1;
+    if (write(event_fd_.Get(), &buf, sizeof(buf)) < 0) {
+      PLOG(ERROR) << "Failed to write to eventfd";
+    }
+  }
+
+  std::optional<int> client_fd_;
+  UniqueFd event_fd_;
+  std::thread waiter_thread_;
+  std::unique_ptr<Sandbox2> sandbox_;
+};
+
+class SandboxManager::SocketClient {
+ public:
+  SocketClient(SandboxManager& manager, UniqueFd client_fd)
+      : manager_(manager), client_fd_(std::move(client_fd)) {}
+  SocketClient(SocketClient&) = delete;
+
+  int ClientFd() const { return client_fd_.Get(); }
+
+  absl::Status HandleMessage() {
+    auto message_status = Message::RecvFrom(client_fd_.Get());
+    if (!message_status.ok()) {
+      return message_status.status();
+    }
+    auto creds_status = UpdateCredentials(message_status->Credentials());
+    if (!creds_status.ok()) {
+      return creds_status;
+    }
+
+    /* This handshake process is to reliably build a `pidfd` based on the pid
+     * supplied in the process `ucreds`, through the following steps:
+     * 1. Proxy process opens a socket and sends an opening message.
+     * 2. Server receives opening message with a kernel-validated `ucreds`
+     *    containing the outside-sandbox pid.
+     * 3. Server opens a pidfd matching this pid.
+     * 4. Server sends a message to the client with some unique data.
+     * 5. Client responds with the unique data.
+     * 6. Server validates the unique data and credentials match.
+     * 7. Server launches a possible sandboxed subprocess based on the pidfd and
+     *    /proc/{pid}/
+     *
+     * Step 5 builds confidence that the pidfd opened in step 3 still
+     * corresponds to the client sending messages on the client socket. The
+     * pidfd and /proc/{pid} data provide everything necessary to launch the
+     * subprocess.
+     */
+    auto& message = message_status->Data();
+    switch (client_state_) {
+      case ClientState::kInitial: {
+        if (message != kHandshakeBegin) {
+          auto err = absl::StrFormat("'%v' != '%v'", kHandshakeBegin, message);
+          return absl::InternalError(err);
+        }
+        pingback_ = std::chrono::steady_clock::now().time_since_epoch().count();
+        auto stat = SendStringMsg(client_fd_.Get(), std::to_string(pingback_));
+        if (stat.ok()) {
+          client_state_ = ClientState::kIgnoredFd;
+        }
+        return stat.status();
+      }
+      case ClientState::kIgnoredFd:
+        if (!absl::SimpleAtoi(message, &ignored_fd_)) {
+          auto error = absl::StrFormat("Expected integer, got '%v'", message);
+          return absl::InternalError(error);
+        }
+        client_state_ = ClientState::kPingback;
+        return absl::OkStatus();
+      case ClientState::kPingback: {
+        size_t comp;
+        if (!absl::SimpleAtoi(message, &comp)) {
+          auto error = absl::StrFormat("Expected integer, got '%v'", message);
+          return absl::InternalError(error);
+        } else if (comp != pingback_) {
+          auto err = absl::StrFormat("Incorrect '%v' != '%v'", comp, pingback_);
+          return absl::InternalError(err);
+        }
+        client_state_ = ClientState::kWaitingForExit;
+        return LaunchProcess();
+      }
+      case ClientState::kWaitingForExit:
+        return absl::InternalError("No messages allowed");
+    }
+  }
+
+  absl::Status SendExitCode(int code) {
+    auto send_exit_status = SendStringMsg(client_fd_.Get(), "exit");
+    if (!send_exit_status.ok()) {
+      return send_exit_status.status();
+    }
+
+    return SendStringMsg(client_fd_.Get(), std::to_string(code)).status();
+  }
+
+ private:
+  enum class ClientState { kInitial, kIgnoredFd, kPingback, kWaitingForExit };
+
+  absl::Status UpdateCredentials(const std::optional<ucred>& credentials) {
+    if (!credentials) {
+      return absl::InvalidArgumentError("no creds");
+    } else if (!credentials_) {
+      credentials_ = credentials;
+    } else if (credentials_->pid != credentials->pid) {
+      std::string err = absl::StrFormat("pid went from '%d' to '%d'",
+                                        credentials_->pid, credentials->pid);
+      return absl::PermissionDeniedError(err);
+    } else if (credentials_->uid != credentials->uid) {
+      return absl::PermissionDeniedError("uid changed");
+    } else if (credentials_->gid != credentials->gid) {
+      return absl::PermissionDeniedError("gid changed");
+    }
+    if (!pid_fd_) {
+      absl::StatusOr<PidFd> pid_fd =
+          PidFd::FromRunningProcess(credentials_->pid);
+      if (!pid_fd.ok()) {
+        return pid_fd.status();
+      }
+      pid_fd_ = std::move(*pid_fd);
+    }
+    return absl::OkStatus();
+  }
+
+  absl::Status LaunchProcess() {
+    if (!pid_fd_) {
+      return absl::InternalError("missing pid_fd_");
+    }
+    absl::StatusOr<std::vector<std::string>> argv = pid_fd_->Argv();
+    if (!argv.ok()) {
+      return argv.status();
+    }
+    if ((*argv)[0] == "openssl") {
+      (*argv)[0] = "/usr/bin/openssl";
+    }
+    absl::StatusOr<std::vector<std::pair<UniqueFd, int>>> fds =
+        pid_fd_->AllFds();
+    if (!fds.ok()) {
+      return fds.status();
+    }
+    absl::StatusOr<std::vector<std::string>> env = pid_fd_->Env();
+    if (!env.ok()) {
+      return env.status();
+    }
+    fds->erase(std::remove_if(fds->begin(), fds->end(), [this](auto& arg) {
+      return arg.second == ignored_fd_;
+    }));
+    return manager_.RunProcess(client_fd_.Get(), std::move(*argv),
+                               std::move(*fds), *env);
+  }
+
+  SandboxManager& manager_;
+  UniqueFd client_fd_;
+  std::optional<ucred> credentials_;
+  std::optional<PidFd> pid_fd_;
+
+  ClientState client_state_ = ClientState::kInitial;
+  size_t pingback_;
+  int ignored_fd_ = -1;
+};
+
+SandboxManager::SandboxManager(HostInfo host_info, std::string runtime_dir,
+                               SignalFd signals, CredentialedUnixServer server)
+    : host_info_(std::move(host_info)),
+      runtime_dir_(std::move(runtime_dir)),
+      signals_(std::move(signals)),
+      server_(std::move(server)) {}
+
+absl::StatusOr<std::unique_ptr<SandboxManager>> SandboxManager::Create(
+    HostInfo host_info) {
+  std::string runtime_dir =
+      absl::StrFormat("/tmp/sandbox_manager.%u.XXXXXX", getpid());
+  if (mkdtemp(runtime_dir.data()) == nullptr) {
+    return absl::ErrnoToStatus(errno, "mkdtemp failed");
+  }
+  VLOG(1) << "Created temporary directory '" << runtime_dir << "'";
+
+  absl::StatusOr<SignalFd> signals = SignalFd::AllExceptSigChld();
+  if (!signals.ok()) {
+    return signals.status();
+  }
+
+  absl::StatusOr<CredentialedUnixServer> server =
+      CredentialedUnixServer::Open(ServerSocketOutsidePath(runtime_dir));
+  if (!server.ok()) {
+    return server.status();
+  }
+
+  return absl::WrapUnique(
+      new SandboxManager(std::move(host_info), std::move(runtime_dir),
+                         std::move(*signals), std::move(*server)));
+}
+
+SandboxManager::~SandboxManager() {
+  VLOG(1) << "Sandbox shutting down";
+  if (!runtime_dir_.empty()) {
+    if (unlink(ServerSocketOutsidePath(runtime_dir_).c_str()) < 0) {
+      PLOG(ERROR) << "`unlink` failed";
+    }
+    if (rmdir(runtime_dir_.c_str()) < 0) {
+      PLOG(ERROR) << "Failed to remove '" << runtime_dir_ << "'";
+    }
+  }
+}
+
+absl::Status SandboxManager::RunProcess(
+    std::optional<int> client_fd, absl::Span<const std::string> argv,
+    std::vector<std::pair<UniqueFd, int>> fds,
+    absl::Span<const std::string> env) {
+  if (argv.empty()) {
+    return absl::InvalidArgumentError("Not enough arguments");
+  }
+  bool stdio_mapped[3] = {false, false, false};
+  for (const auto& [input_fd, target_fd] : fds) {
+    if (0 <= target_fd && target_fd <= 2) {
+      stdio_mapped[target_fd] = true;
+    }
+  }
+  // If stdio is not filled in, file descriptors opened by the target process
+  // may occupy the standard stdio positions. This can cause unexpected
+  for (int i = 0; i <= 2; i++) {
+    if (stdio_mapped[i]) {
+      continue;
+    }
+    auto& [stdio_dup, stdio] = fds.emplace_back(dup(i), i);
+    if (stdio_dup.Get() < 0) {
+      return absl::ErrnoToStatus(errno, "Failed to `dup` stdio descriptor");
+    }
+  }
+  std::string exe = CleanPath(argv[0]);
+  std::unique_ptr<Policy> policy = PolicyForExecutable(
+      host_info_, ServerSocketOutsidePath(runtime_dir_), exe);
+  if (policy) {
+    return RunSandboxedProcess(client_fd, argv, std::move(fds), env,
+                               std::move(policy));
+  } else {
+    return RunProcessNoSandbox(client_fd, argv, std::move(fds), env);
+  }
+}
+
+class TraceAndAllow : public sandbox2::Notify {
+ public:
+  TraceAction EventSyscallTrace(const Syscall& syscall) override {
+    std::string prog_name = GetProgName(syscall.pid());
+    LOG(WARNING) << "[PERMITTED]: SYSCALL ::: PID: " << syscall.pid()
+                 << ", PROG: '" << prog_name
+                 << "' : " << syscall.GetDescription();
+    return TraceAction::kAllow;
+  }
+};
+
+absl::Status SandboxManager::RunSandboxedProcess(
+    std::optional<int> client_fd, absl::Span<const std::string> argv,
+    std::vector<std::pair<UniqueFd, int>> fds,
+    absl::Span<const std::string> env, std::unique_ptr<Policy> policy) {
+  if (VLOG_IS_ON(1)) {
+    std::stringstream process_stream;
+    process_stream << "Launching executable with argv: [\n";
+    for (const auto& arg : argv) {
+      process_stream << "\t\"" << arg << "\",\n";
+    }
+    process_stream << "] with FD mapping: [\n";
+    for (const auto& [fd_in, fd_out] : fds) {
+      process_stream << '\t' << fd_in.Get() << " -> " << fd_out << ",\n";
+    }
+    process_stream << "]\n";
+    VLOG(1) << process_stream.str();
+  }
+
+  std::string exe = CleanPath(argv[0]);
+  auto executor = std::make_unique<Executor>(exe, argv, env);
+  executor->set_cwd(host_info_.runtime_dir);
+
+  // https://cs.android.com/android/platform/superproject/main/+/main:external/sandboxed-api/sandboxed_api/sandbox2/limits.h;l=116;drc=d451478e26c0352ecd6912461e867a1ae64b17f5
+  // Default is 120 seconds
+  executor->limits()->set_walltime_limit(absl::InfiniteDuration());
+  // Default is 1024 seconds
+  executor->limits()->set_rlimit_cpu(RLIM64_INFINITY);
+
+  for (auto& [fd_outer, fd_inner] : fds) {
+    // Will close `fd_outer` in this process
+    executor->ipc()->MapFd(fd_outer.Release(), fd_inner);
+  }
+
+  UniqueFd event_fd(eventfd(0, EFD_CLOEXEC));
+  if (event_fd.Get() < 0) {
+    return absl::ErrnoToStatus(errno, "`eventfd` failed");
+  }
+
+  // TODO: b/318576505 - Don't allow unknown system calls.
+  std::unique_ptr<sandbox2::Notify> notify(new TraceAndAllow());
+
+  auto sbx = std::make_unique<Sandbox2>(std::move(executor), std::move(policy),
+                                        std::move(notify));
+  if (!sbx->RunAsync()) {
+    return sbx->AwaitResult().ToStatus();
+  }
+
+  // A pidfd over the sandbox is another option, but there are two problems:
+  //
+  // 1. There's a race between launching the sandbox and opening the pidfd. If
+  // the sandboxed process exits too quickly, the monitor thread in sandbox2
+  // could reap it and another process could reuse the pid before `pidfd_open`
+  // runs. Sandbox2 could produce a pidfd itself using `CLONE_PIDFD`, but it
+  // does not do this at the time of writing.
+  //
+  // 2. The sandbox could outlive its top-level process. It's not clear to me if
+  // sandbox2 allows this in practice, but `AwaitResult` could theoretically
+  // wait on subprocesses of the original sandboxed process as well.
+  //
+  // To deal with these concerns, we use another thread blocked on AwaitResult
+  // that signals the eventfd when sandbox2 says the sandboxed process has
+  // exited.
+
+  subprocesses_.emplace_back(
+      new SandboxedProcess(client_fd, std::move(event_fd), std::move(sbx)));
+
+  return absl::OkStatus();
+}
+
+absl::Status SandboxManager::RunProcessNoSandbox(
+    std::optional<int> client_fd, absl::Span<const std::string> argv,
+    std::vector<std::pair<UniqueFd, int>> fds,
+    absl::Span<const std::string> env) {
+  if (!client_fd) {
+    return absl::InvalidArgumentError("no client for unsandboxed process");
+  }
+
+  absl::StatusOr<PidFd> fd = PidFd::LaunchSubprocess(argv, std::move(fds), env);
+  if (!fd.ok()) {
+    return fd.status();
+  }
+  subprocesses_.emplace_back(new ProcessNoSandbox(*client_fd, std::move(*fd)));
+
+  return absl::OkStatus();
+}
+
+bool SandboxManager::Running() const { return running_; }
+
+absl::Status SandboxManager::Iterate() {
+  PollCallback poll_cb;
+
+  poll_cb.Add(signals_.Fd(), bind_front(&SandboxManager::Signalled, this));
+  poll_cb.Add(server_.Fd(), bind_front(&SandboxManager::NewClient, this));
+
+  for (auto it = subprocesses_.begin(); it != subprocesses_.end(); it++) {
+    int fd = (*it)->PollFd();
+    poll_cb.Add(fd, bind_front(&SandboxManager::ProcessExit, this, it));
+  }
+  for (auto it = clients_.begin(); it != clients_.end(); it++) {
+    int fd = (*it)->ClientFd();
+    poll_cb.Add(fd, bind_front(&SandboxManager::ClientMessage, this, it));
+  }
+
+  return poll_cb.Poll();
+}
+
+absl::Status SandboxManager::Signalled(short revents) {
+  if (revents != POLLIN) {
+    running_ = false;
+    return absl::InternalError("signalfd exited");
+  }
+
+  absl::StatusOr<signalfd_siginfo> info = signals_.ReadSignal();
+  if (!info.ok()) {
+    return info.status();
+  }
+  VLOG(1) << "Received signal with signo '" << info->ssi_signo << "'";
+
+  switch (info->ssi_signo) {
+    case SIGHUP:
+    case SIGINT:
+    case SIGTERM:
+      LOG(INFO) << "Received signal '" << info->ssi_signo << "', exiting";
+      running_ = false;
+      return absl::OkStatus();
+    default:
+      std::string err = absl::StrCat("Unexpected signal ", info->ssi_signo);
+      return absl::InternalError(err);
+  }
+}
+
+absl::Status SandboxManager::NewClient(short revents) {
+  if (revents != POLLIN) {
+    running_ = false;
+    return absl::InternalError("server socket exited");
+  }
+  absl::StatusOr<UniqueFd> client = server_.AcceptClient();
+  if (!client.ok()) {
+    return client.status();
+  }
+  clients_.emplace_back(new SocketClient(*this, std::move(*client)));
+  return absl::OkStatus();
+}
+
+absl::Status SandboxManager::ProcessExit(SandboxManager::SboxIter it,
+                                         short revents) {
+  if ((*it)->ClientFd()) {
+    int client_fd = *(*it)->ClientFd();
+    for (auto& client : clients_) {
+      if (client->ClientFd() != client_fd) {
+        continue;
+      }
+      auto exit_code = (*it)->ExitCode();
+      if (!exit_code.ok()) {
+        LOG(ERROR) << exit_code.status();
+      }
+      // TODO(schuffelen): Forward more complete exit information
+      auto send_res = client->SendExitCode(exit_code.value_or(254));
+      if (!send_res.ok()) {
+        return send_res;
+      }
+    }
+  }
+  subprocesses_.erase(it);
+  if (subprocesses_.empty()) {
+    running_ = false;
+  }
+  static constexpr char kErr[] = "eventfd exited";
+  return revents == POLLIN ? absl::OkStatus() : absl::InternalError(kErr);
+}
+
+absl::Status SandboxManager::ClientMessage(SandboxManager::ClientIter it,
+                                           short rev) {
+  if (rev == POLLIN) {
+    return (*it)->HandleMessage();
+  }
+  clients_.erase(it);
+  return absl::InternalError("client dropped file descriptor");
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/sandbox_manager.h b/host/commands/process_sandboxer/sandbox_manager.h
new file mode 100644
index 000000000..8051ba60a
--- /dev/null
+++ b/host/commands/process_sandboxer/sandbox_manager.h
@@ -0,0 +1,104 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#ifndef ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_SANDBOX_MANAGER_H
+#define ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_SANDBOX_MANAGER_H
+
+#include <list>
+#include <memory>
+#include <optional>
+#include <string>
+#include <utility>
+#include <vector>
+
+#include <absl/status/status.h>
+#include <absl/status/statusor.h>
+#include <absl/types/span.h>
+#include <sandboxed_api/sandbox2/policy.h>
+
+#include "host/commands/process_sandboxer/credentialed_unix_server.h"
+#include "host/commands/process_sandboxer/policies.h"
+#include "host/commands/process_sandboxer/signal_fd.h"
+#include "host/commands/process_sandboxer/unique_fd.h"
+
+namespace cuttlefish::process_sandboxer {
+
+class SandboxManager {
+ public:
+  static absl::StatusOr<std::unique_ptr<SandboxManager>> Create(
+      HostInfo host_info);
+
+  SandboxManager(SandboxManager&) = delete;
+  ~SandboxManager();
+
+  /** Start a process with the given `argv` and file descriptors in `fds`.
+   *
+   * For (key, value) pairs in `fds`, `key` on the outside is mapped to `value`
+   * in the sandbox, and `key` is `close`d on the outside. */
+  absl::Status RunProcess(std::optional<int> client_fd,
+                          absl::Span<const std::string> argv,
+                          std::vector<std::pair<UniqueFd, int>> fds,
+                          absl::Span<const std::string> env);
+
+  /** Block until an event happens, and process all open events. */
+  absl::Status Iterate();
+  bool Running() const;
+
+ private:
+  class ManagedProcess {
+   public:
+    virtual ~ManagedProcess() = default;
+    virtual std::optional<int> ClientFd() const = 0;
+    virtual int PollFd() const = 0;
+    virtual absl::StatusOr<uintptr_t> ExitCode() = 0;
+  };
+  class ProcessNoSandbox;
+  class SandboxedProcess;
+  class SocketClient;
+
+  using ClientIter = std::list<std::unique_ptr<SocketClient>>::iterator;
+  using SboxIter = std::list<std::unique_ptr<ManagedProcess>>::iterator;
+
+  SandboxManager(HostInfo, std::string runtime_dir, SignalFd,
+                 CredentialedUnixServer);
+
+  absl::Status RunSandboxedProcess(std::optional<int> client_fd,
+                                   absl::Span<const std::string> argv,
+                                   std::vector<std::pair<UniqueFd, int>> fds,
+                                   absl::Span<const std::string> env,
+                                   std::unique_ptr<sandbox2::Policy> policy);
+  absl::Status RunProcessNoSandbox(std::optional<int> client_fd,
+                                   absl::Span<const std::string> argv,
+                                   std::vector<std::pair<UniqueFd, int>> fds,
+                                   absl::Span<const std::string> env);
+
+  // Callbacks for the Iterate() `poll` loop.
+  absl::Status ClientMessage(ClientIter it, short revents);
+  absl::Status NewClient(short revents);
+  absl::Status ProcessExit(SboxIter it, short revents);
+  absl::Status Signalled(short revents);
+
+  HostInfo host_info_;
+  bool running_ = true;
+  std::string runtime_dir_;
+  std::list<std::unique_ptr<ManagedProcess>> subprocesses_;
+  std::list<std::unique_ptr<SocketClient>> clients_;
+  SignalFd signals_;
+  CredentialedUnixServer server_;
+};
+
+}  // namespace cuttlefish::process_sandboxer
+
+#endif
diff --git a/host/commands/process_sandboxer/sandboxer_proxy.cpp b/host/commands/process_sandboxer/sandboxer_proxy.cpp
new file mode 100644
index 000000000..a99c0798f
--- /dev/null
+++ b/host/commands/process_sandboxer/sandboxer_proxy.cpp
@@ -0,0 +1,93 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <sys/socket.h>
+#include <sys/un.h>
+
+#include <iostream>
+
+#include <absl/status/status.h>
+#include <absl/status/statusor.h>
+
+#include "absl/strings/numbers.h"
+#include "proxy_common.h"
+
+namespace cuttlefish::process_sandboxer {
+namespace {
+
+template <typename T>
+T UnwrapStatusOr(absl::StatusOr<T> status_or) {
+  if (!status_or.ok()) {
+    std::cerr << status_or.status().ToString() << '\n';
+    abort();
+  }
+  return std::move(*status_or);
+}
+
+template <typename T>
+absl::StatusOr<T> AtoiOr(std::string_view str) {
+  T out;
+  if (!absl::SimpleAtoi(str, &out)) {
+    return absl::InvalidArgumentError("Not an integer");
+  }
+  return out;
+}
+
+absl::StatusOr<int> OpenSandboxManagerSocket() {
+  int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
+  if (sock < 0) {
+    return absl::ErrnoToStatus(errno, "`socket` failed");
+  }
+
+  sockaddr_un addr = sockaddr_un{
+      .sun_family = AF_UNIX,
+  };
+  size_t size = std::min(sizeof(addr.sun_path), kManagerSocketPath.size());
+  strncpy(addr.sun_path, kManagerSocketPath.data(), size);
+
+  if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
+    return absl::ErrnoToStatus(errno, "`connect` failed");
+  }
+
+  return sock;
+}
+
+int ProcessSandboxerMain() {
+  int sock = UnwrapStatusOr(OpenSandboxManagerSocket());
+  UnwrapStatusOr(SendStringMsg(sock, kHandshakeBegin));
+  UnwrapStatusOr(SendStringMsg(sock, std::to_string(sock)));
+  Message pingback = UnwrapStatusOr(Message::RecvFrom(sock));
+  UnwrapStatusOr(SendStringMsg(sock, pingback.Data()));
+
+  // If signals other than SIGKILL become relevant, this should `poll` to check
+  // both `sock` and a `signalfd`.
+  while (true) {
+    Message command = UnwrapStatusOr(Message::RecvFrom(sock));
+    if (command.Data() == "exit") {
+      Message message = UnwrapStatusOr(Message::RecvFrom(sock));
+      return UnwrapStatusOr(AtoiOr<int>(message.Data()));
+    }
+    std::cerr << "Unexpected message: '" << command.Data() << "'\n";
+    return 1;
+  }
+
+  return 0;
+}
+
+}  // namespace
+}  // namespace cuttlefish::process_sandboxer
+
+int main() { return cuttlefish::process_sandboxer::ProcessSandboxerMain(); }
diff --git a/host/commands/process_sandboxer/signal_fd.cpp b/host/commands/process_sandboxer/signal_fd.cpp
new file mode 100644
index 000000000..d3a2ee7a7
--- /dev/null
+++ b/host/commands/process_sandboxer/signal_fd.cpp
@@ -0,0 +1,67 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/signal_fd.h"
+
+#include <signal.h>
+#include <sys/signalfd.h>
+
+#include <absl/status/status.h>
+#include <absl/status/statusor.h>
+#include <absl/strings/str_cat.h>
+
+#include "host/commands/process_sandboxer/unique_fd.h"
+
+namespace cuttlefish::process_sandboxer {
+
+SignalFd::SignalFd(UniqueFd fd) : fd_(std::move(fd)) {}
+
+absl::StatusOr<SignalFd> SignalFd::AllExceptSigChld() {
+  sigset_t mask;
+  if (sigfillset(&mask) < 0) {
+    return absl::ErrnoToStatus(errno, "sigfillset failed");
+  }
+  // TODO(schuffelen): Explore interaction between catching SIGCHLD and sandbox2
+  if (sigdelset(&mask, SIGCHLD) < 0) {
+    return absl::ErrnoToStatus(errno, "sigdelset failed");
+  }
+  if (sigprocmask(SIG_SETMASK, &mask, NULL) < 0) {
+    return absl::ErrnoToStatus(errno, "sigprocmask failed");
+  }
+
+  UniqueFd fd(signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
+  if (fd.Get() < 0) {
+    return absl::ErrnoToStatus(errno, "signalfd failed");
+  }
+  return SignalFd(std::move(fd));
+}
+
+absl::StatusOr<signalfd_siginfo> SignalFd::ReadSignal() {
+  signalfd_siginfo info;
+  auto read_res = read(fd_.Get(), &info, sizeof(info));
+  if (read_res < 0) {
+    return absl::ErrnoToStatus(errno, "`read(signal_fd_, ...)` failed");
+  } else if (read_res == 0) {
+    return absl::InternalError("read(signal_fd_, ...) returned EOF");
+  } else if (read_res != (ssize_t)sizeof(info)) {
+    std::string err = absl::StrCat("read(signal_fd_, ...) gave '", read_res);
+    return absl::InternalError(err);
+  }
+  return info;
+}
+
+int SignalFd::Fd() const { return fd_.Get(); }
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/signal_fd.h b/host/commands/process_sandboxer/signal_fd.h
new file mode 100644
index 000000000..e21672b72
--- /dev/null
+++ b/host/commands/process_sandboxer/signal_fd.h
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#ifndef ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_SIGNAL_FD_H
+#define ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_SIGNAL_FD_H
+
+#include <sys/signalfd.h>
+
+#include <absl/status/statusor.h>
+
+#include "host/commands/process_sandboxer/unique_fd.h"
+
+namespace cuttlefish::process_sandboxer {
+
+class SignalFd {
+ public:
+  static absl::StatusOr<SignalFd> AllExceptSigChld();
+
+  absl::StatusOr<signalfd_siginfo> ReadSignal();
+
+  int Fd() const;
+
+ private:
+  SignalFd(UniqueFd);
+
+  UniqueFd fd_;
+};
+
+}  // namespace cuttlefish::process_sandboxer
+
+#endif
diff --git a/host/commands/process_sandboxer/unique_fd.cpp b/host/commands/process_sandboxer/unique_fd.cpp
new file mode 100644
index 000000000..5208b9477
--- /dev/null
+++ b/host/commands/process_sandboxer/unique_fd.cpp
@@ -0,0 +1,58 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/commands/process_sandboxer/unique_fd.h"
+
+#include <unistd.h>
+
+#include <absl/log/log.h>
+
+namespace cuttlefish {
+namespace process_sandboxer {
+
+UniqueFd::UniqueFd(int fd) : fd_(fd) {}
+
+UniqueFd::UniqueFd(UniqueFd&& other) { std::swap(fd_, other.fd_); }
+
+UniqueFd::~UniqueFd() { Close(); }
+
+UniqueFd& UniqueFd::operator=(UniqueFd&& other) {
+  Close();
+  std::swap(fd_, other.fd_);
+  return *this;
+}
+
+int UniqueFd::Get() const { return fd_; }
+
+int UniqueFd::Release() {
+  int ret = -1;
+  std::swap(ret, fd_);
+  return ret;
+}
+
+void UniqueFd::Reset(int fd) {
+  Close();
+  fd_ = fd;
+}
+
+void UniqueFd::Close() {
+  if (fd_ > 0 && close(fd_) < 0) {
+    PLOG(ERROR) << "Failed to close fd " << fd_;
+  }
+  fd_ = -1;
+}
+
+}  // namespace process_sandboxer
+}  // namespace cuttlefish
diff --git a/host/commands/process_sandboxer/unique_fd.h b/host/commands/process_sandboxer/unique_fd.h
new file mode 100644
index 000000000..b923db452
--- /dev/null
+++ b/host/commands/process_sandboxer/unique_fd.h
@@ -0,0 +1,44 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#ifndef ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_UNIQUE_FD_H
+#define ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_UNIQUE_FD_H
+
+namespace cuttlefish {
+namespace process_sandboxer {
+
+class UniqueFd {
+ public:
+  UniqueFd() = default;
+  explicit UniqueFd(int fd);
+  UniqueFd(UniqueFd&&);
+  UniqueFd(UniqueFd&) = delete;
+  ~UniqueFd();
+  UniqueFd& operator=(UniqueFd&&);
+
+  int Get() const;
+  int Release();
+  void Reset(int fd);
+
+ private:
+  void Close();
+
+  int fd_ = -1;
+};
+
+}  // namespace process_sandboxer
+}  // namespace cuttlefish
+
+#endif
diff --git a/host/commands/run_cvd/Android.bp b/host/commands/run_cvd/Android.bp
index e04cceee4..e1d0355e7 100644
--- a/host/commands/run_cvd/Android.bp
+++ b/host/commands/run_cvd/Android.bp
@@ -64,6 +64,7 @@ cc_binary_host {
         "libfruit",
         "libjsoncpp",
         "libprotobuf-cpp-full",
+        "libgrpc++_unsecure",
     ],
     static_libs: [
         "libbuildversion",
@@ -76,6 +77,7 @@ cc_binary_host {
         "libcuttlefish_process_monitor",
         "libcuttlefish_utils",
         "libcuttlefish_vm_manager",
+        "libopenwrt_control_server",
         "libgflags",
     ],
     required: [
diff --git a/host/commands/run_cvd/boot_state_machine.cc b/host/commands/run_cvd/boot_state_machine.cc
index e78aac072..733ed2e04 100644
--- a/host/commands/run_cvd/boot_state_machine.cc
+++ b/host/commands/run_cvd/boot_state_machine.cc
@@ -24,6 +24,11 @@
 #include <android-base/file.h>
 #include <android-base/logging.h>
 #include <gflags/gflags.h>
+#include <grpc/grpc.h>
+#include <grpcpp/channel.h>
+#include <grpcpp/client_context.h>
+#include <grpcpp/create_channel.h>
+#include "common/libs/utils/result.h"
 
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/tee_logging.h"
@@ -34,6 +39,13 @@
 #include "host/libs/command_util/runner/defs.h"
 #include "host/libs/command_util/util.h"
 #include "host/libs/config/feature.h"
+#include "openwrt_control.grpc.pb.h"
+
+using grpc::ClientContext;
+using openwrtcontrolserver::LuciRpcReply;
+using openwrtcontrolserver::LuciRpcRequest;
+using openwrtcontrolserver::OpenwrtControlService;
+using openwrtcontrolserver::OpenwrtIpaddrReply;
 
 DEFINE_int32(reboot_notification_fd, CF_DEFAULTS_REBOOT_NOTIFICATION_FD,
              "A file descriptor to notify when boot completes.");
@@ -247,6 +259,28 @@ class CvdBootStateMachine : public SetupFeature, public KernelLogPipeConsumer {
                 << "Error writing to adbd restore pipe: "
                 << restore_adbd_pipe->StrError() << ". This is unrecoverable.";
 
+            // Restart network service in OpenWRT, broken on restore.
+            CHECK(FileExists(instance_.grpc_socket_path() +
+                             "/OpenwrtControlServer.sock"))
+                << "unable to find grpc socket for OpenwrtControlServer";
+            auto openwrt_channel =
+                grpc::CreateChannel("unix:" + instance_.grpc_socket_path() +
+                                        "/OpenwrtControlServer.sock",
+                                    grpc::InsecureChannelCredentials());
+            auto stub_ = OpenwrtControlService::NewStub(openwrt_channel);
+            LuciRpcRequest request;
+            request.set_subpath("sys");
+            request.set_method("exec");
+            request.add_params("service network restart");
+            LuciRpcReply response;
+            ClientContext context;
+            grpc::Status status = stub_->LuciRpc(&context, request, &response);
+            CHECK(status.ok())
+                << "Failed to send network service reset" << status.error_code()
+                << ": " << status.error_message();
+            LOG(DEBUG) << "OpenWRT `service network restart` response: "
+                       << response.result();
+
             auto SubtoolPath = [](const std::string& subtool_name) {
               auto my_own_dir = android::base::GetExecutableDirectory();
               std::stringstream subtool_path_stream;
@@ -257,20 +291,18 @@ class CvdBootStateMachine : public SetupFeature, public KernelLogPipeConsumer {
               }
               return subtool_path;
             };
-            const auto adb_bin_path = SubtoolPath("adb");
-            CHECK(Execute({adb_bin_path, "-s", instance_.adb_ip_and_port(),
-                           "wait-for-device"},
-                          SubprocessOptions(), WEXITED)
-                      .ok())
-                << "Failed to suspend bluetooth manager.";
-            CHECK(Execute({adb_bin_path, "-s", instance_.adb_ip_and_port(),
-                           "shell", "cmd", "bluetooth_manager", "enable"},
-                          SubprocessOptions(), WEXITED)
-                      .ok());
-            CHECK(Execute({adb_bin_path, "-s", instance_.adb_ip_and_port(),
-                           "shell", "cmd", "uwb", "enable-uwb"},
-                          SubprocessOptions(), WEXITED)
-                      .ok());
+            // Run the in-guest post-restore script.
+            Command adb_command(SubtoolPath("adb"));
+            // Avoid the adb server being started in the runtime directory and
+            // looking like a process that is still using the directory.
+            adb_command.SetWorkingDirectory("/");
+            adb_command.AddParameter("-s").AddParameter(
+                instance_.adb_ip_and_port());
+            adb_command.AddParameter("wait-for-device");
+            adb_command.AddParameter("shell");
+            adb_command.AddParameter("/vendor/bin/snapshot_hook_post_resume");
+            CHECK_EQ(adb_command.Start().Wait(), 0)
+                << "Failed to run /vendor/bin/snapshot_hook_post_resume";
             // Done last so that adb is more likely to be ready.
             CHECK(cuttlefish::WriteAll(restore_complete_pipe_write, "1") == 1)
                 << "Error writing to restore complete pipe: "
@@ -368,18 +400,23 @@ class CvdBootStateMachine : public SetupFeature, public KernelLogPipeConsumer {
 
   // Returns true if the machine is left in a final state
   bool OnBootEvtReceived(SharedFD boot_events_pipe) {
-    std::optional<monitor::ReadEventResult> read_result =
+    Result<std::optional<monitor::ReadEventResult>> read_result =
         monitor::ReadEvent(boot_events_pipe);
     if (!read_result) {
-      LOG(ERROR) << "Failed to read a complete kernel log boot event.";
+      LOG(ERROR) << "Failed to read a complete kernel log boot event: "
+                 << read_result.error().FormatForEnv();
+      state_ |= kGuestBootFailed;
+      return MaybeWriteNotification();
+    } else if (!*read_result) {
+      LOG(ERROR) << "EOF from kernel log monitor";
       state_ |= kGuestBootFailed;
       return MaybeWriteNotification();
     }
 
-    if (read_result->event == monitor::Event::BootCompleted) {
+    if ((*read_result)->event == monitor::Event::BootCompleted) {
       LOG(INFO) << "Virtual device booted successfully";
       state_ |= kGuestBootCompleted;
-    } else if (read_result->event == monitor::Event::BootFailed) {
+    } else if ((*read_result)->event == monitor::Event::BootFailed) {
       LOG(ERROR) << "Virtual device failed to boot";
       state_ |= kGuestBootFailed;
     }  // Ignore the other signals
diff --git a/host/commands/run_cvd/launch/gnss_grpc_proxy.cpp b/host/commands/run_cvd/launch/gnss_grpc_proxy.cpp
index 65c39b661..29ce64c3d 100644
--- a/host/commands/run_cvd/launch/gnss_grpc_proxy.cpp
+++ b/host/commands/run_cvd/launch/gnss_grpc_proxy.cpp
@@ -21,6 +21,7 @@
 #include <fruit/fruit.h>
 
 #include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/in_sandbox.h"
 #include "common/libs/utils/result.h"
 #include "host/libs/config/command_source.h"
 #include "host/libs/config/known_paths.h"
@@ -50,10 +51,12 @@ Result<std::optional<MonitorCommand>> GnssGrpcProxyServer(
           .AddParameter("--gnss_out_fd=", fifos[1])
           .AddParameter("--fixed_location_in_fd=", fifos[2])
           .AddParameter("--fixed_location_out_fd=", fifos[3])
-          .AddParameter("--gnss_grpc_port=",
-                        instance.gnss_grpc_proxy_server_port())
           .AddParameter("--gnss_grpc_socket=",
                         grpc_socket.CreateGrpcSocket("GnssGrpcProxyServer"));
+  if (!InSandbox()) {
+    gnss_grpc_proxy_cmd.AddParameter("--gnss_grpc_port=",
+                                     instance.gnss_grpc_proxy_server_port());
+  }
   if (!instance.gnss_file_path().empty()) {
     // If path is provided, proxy will start as local mode.
     gnss_grpc_proxy_cmd.AddParameter("--gnss_file_path=",
diff --git a/host/commands/run_cvd/launch/kernel_log_monitor.cpp b/host/commands/run_cvd/launch/kernel_log_monitor.cpp
index 2f67daa4e..be3ed690f 100644
--- a/host/commands/run_cvd/launch/kernel_log_monitor.cpp
+++ b/host/commands/run_cvd/launch/kernel_log_monitor.cpp
@@ -65,7 +65,7 @@ class KernelLogMonitor : public CommandSource,
       }
     }
     std::vector<MonitorCommand> commands;
-    commands.emplace_back(std::move(command)).can_sandbox = true;
+    commands.emplace_back(std::move(command));
     return commands;
   }
 
diff --git a/host/commands/run_cvd/launch/logcat_receiver.cpp b/host/commands/run_cvd/launch/logcat_receiver.cpp
index c1465e6b9..647950c7e 100644
--- a/host/commands/run_cvd/launch/logcat_receiver.cpp
+++ b/host/commands/run_cvd/launch/logcat_receiver.cpp
@@ -40,12 +40,9 @@ Result<MonitorCommand> LogcatReceiver(
   // done and the logcat_receiver crashes for some reason the VMM may get
   // SIGPIPE.
   auto log_name = instance.logcat_pipe_name();
-  auto cmd = Command(LogcatReceiverBinary())
-                 .AddParameter("-log_pipe_fd=",
-                               CF_EXPECT(SharedFD::Fifo(log_name, 0600)));
-  MonitorCommand monitor_cmd = std::move(cmd);
-  monitor_cmd.can_sandbox = true;
-  return monitor_cmd;
+
+  return Command(LogcatReceiverBinary())
+      .AddParameter("-log_pipe_fd=", CF_EXPECT(SharedFD::Fifo(log_name, 0600)));
 }
 
 }  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/netsim_server.cpp b/host/commands/run_cvd/launch/netsim_server.cpp
index 4b6466a26..e352e3600 100644
--- a/host/commands/run_cvd/launch/netsim_server.cpp
+++ b/host/commands/run_cvd/launch/netsim_server.cpp
@@ -35,9 +35,13 @@ namespace {
 //
 // netsimd -s '{devices:[
 //  {"name":"0.0.0.0:5000", "chips":[
-//    {"kind":"BLUETOOTH", "fdIn":10, "fdOut":11}]},
+//    {"kind":"BLUETOOTH", "fdIn":10, "fdOut":11}],
+//   "device_kind": {
+//     "name":"0.0.0.0:5000", "kind":"CUTTLEFISH"}},
 //  {"name":"0.0.0.0:5010", "chips":[
-//    {"kind":"BLUETOOTH", "fdIn":14, "fdOut":15}]}]}
+//    {"kind":"BLUETOOTH", "fdIn":14, "fdOut":15}],
+//   "device_kind": {
+//     "name":"0.0.0.0:5010", "kind":"CUTTLEFISH"}}]}
 
 // Chip and Device classes pass SharedFD fifos between ResultSetup and Commands
 // and format the netsim json command line.
@@ -71,7 +75,8 @@ class Device {
         c.AppendToLastParameter(",");
       }
     }
-    c.AppendToLastParameter("]}");
+    c.AppendToLastParameter(R"(],"device_info":{"name":")", name_,
+                            R"(", "kind":"CUTTLEFISH"}})");
   }
 
   std::vector<Chip> chips;
diff --git a/host/commands/run_cvd/launch/nfc_connector.cpp b/host/commands/run_cvd/launch/nfc_connector.cpp
index c45b18e00..ede35fa09 100644
--- a/host/commands/run_cvd/launch/nfc_connector.cpp
+++ b/host/commands/run_cvd/launch/nfc_connector.cpp
@@ -45,8 +45,7 @@ Result<MonitorCommand> NfcConnector(
       .AddParameter("-fifo_out=", fifos[0])
       .AddParameter("-fifo_in=", fifos[1])
       .AddParameter("-data_port=", config.casimir_nci_port())
-      .AddParameter("-buffer_size=", kBufferSize)
-      .AddParameter("-dump_packet_size=", 10);
+      .AddParameter("-buffer_size=", kBufferSize);
 }
 
 }  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/open_wrt.cpp b/host/commands/run_cvd/launch/open_wrt.cpp
index 289d63f7a..734f65690 100644
--- a/host/commands/run_cvd/launch/open_wrt.cpp
+++ b/host/commands/run_cvd/launch/open_wrt.cpp
@@ -25,8 +25,10 @@
 #include <fruit/fruit.h>
 
 #include "common/libs/utils/files.h"
+#include "common/libs/utils/json.h"
 #include "common/libs/utils/network.h"
 #include "common/libs/utils/result.h"
+#include "host/libs/command_util/snapshot_utils.h"
 #include "host/libs/config/command_source.h"
 #include "host/libs/config/known_paths.h"
 #include "host/libs/config/openwrt_args.h"
@@ -62,12 +64,27 @@ class OpenWrt : public CommandSource {
       return wmediumd_server_.WaitForAvailability();
     });
 
+    std::string first_time_argument;
+    if (IsRestoring(config_)) {
+      const std::string snapshot_dir_path = config_.snapshot_path();
+      auto meta_info_json = CF_EXPECT(LoadMetaJson(snapshot_dir_path));
+      const std::vector<std::string> selectors{kGuestSnapshotField,
+                                               instance_.id()};
+      const auto guest_snapshot_dir_suffix =
+          CF_EXPECT(GetValue<std::string>(meta_info_json, selectors));
+      // guest_snapshot_dir_suffix is a relative to
+      // the snapshot_path
+      const auto restore_path = snapshot_dir_path + "/" +
+                                guest_snapshot_dir_suffix + "/" +
+                                kGuestSnapshotBase + "_openwrt";
+      first_time_argument = "--restore=" + restore_path;
+    }
+
     /* TODO(b/305102099): Due to hostapd issue of OpenWRT 22.03.X versions,
      * OpenWRT instance should be rebooted.
      */
     LOG(DEBUG) << "Restart OpenWRT due to hostapd issue";
-    ap_cmd.ApplyProcessRestarter(instance_.crosvm_binary(),
-                                 /*first_time_argument=*/"",
+    ap_cmd.ApplyProcessRestarter(instance_.crosvm_binary(), first_time_argument,
                                  kOpenwrtVmResetExitCode);
     ap_cmd.Cmd().AddParameter("run");
     ap_cmd.AddControlSocket(
@@ -81,18 +98,10 @@ class OpenWrt : public CommandSource {
       ap_cmd.Cmd().AddParameter("--vhost-user=mac80211-hwsim,socket=",
                                 environment_.vhost_user_mac80211_hwsim());
     }
-    SharedFD wifi_tap;
     if (environment_.enable_wifi()) {
-      wifi_tap = ap_cmd.AddTap(instance_.wifi_tap_name());
+      ap_cmd.AddTap(instance_.wifi_tap_name());
     }
 
-    // TODO(khei): Enable restore once open_wrt instance restoring is fixed
-    // if (IsRestoring(config_)) {
-    //  const std::string snapshot_dir = config_.snapshot_path();
-    //  CF_EXPECT(ap_cmd.SetToRestoreFromSnapshot(snapshot_dir, instance_.id(),
-    //                                            "_openwrt"));
-    //}
-
     /* TODO(kwstephenkim): delete this code when Minidroid completely disables
      * the AP VM itself
      */
diff --git a/host/commands/run_cvd/launch/secure_env.cpp b/host/commands/run_cvd/launch/secure_env.cpp
index 5f499fad7..5debe5b65 100644
--- a/host/commands/run_cvd/launch/secure_env.cpp
+++ b/host/commands/run_cvd/launch/secure_env.cpp
@@ -18,7 +18,6 @@
 #include <unistd.h>
 
 #include <string>
-#include <utility>
 #include <vector>
 
 #include <fruit/fruit.h>
@@ -64,22 +63,22 @@ Result<MonitorCommand> SecureEnv(
   command.AddParameter("-keymint_fd_out=", fifos[6]);
   command.AddParameter("-keymint_fd_in=", fifos[7]);
 
-  const auto& secure_hals = config.secure_hals();
-  bool secure_keymint = secure_hals.count(SecureHal::HostKeymintSecure) > 0;
+  const auto& secure_hals = CF_EXPECT(config.secure_hals());
+  bool secure_keymint = secure_hals.count(SecureHal::kHostKeymintSecure) > 0;
   command.AddParameter("-keymint_impl=", secure_keymint ? "tpm" : "software");
   bool secure_gatekeeper =
-      secure_hals.count(SecureHal::HostGatekeeperSecure) > 0;
+      secure_hals.count(SecureHal::kHostGatekeeperSecure) > 0;
   auto gatekeeper_impl = secure_gatekeeper ? "tpm" : "software";
   command.AddParameter("-gatekeeper_impl=", gatekeeper_impl);
 
-  bool secure_oemlock = secure_hals.count(SecureHal::HostOemlockSecure) > 0;
+  bool secure_oemlock = secure_hals.count(SecureHal::kHostOemlockSecure) > 0;
   auto oemlock_impl = secure_oemlock ? "tpm" : "software";
   command.AddParameter("-oemlock_impl=", oemlock_impl);
 
   command.AddParameter("-kernel_events_fd=",
                        kernel_log_pipe_provider.KernelLogPipe());
 
-  return std::move(command);
+  return command;
 }
 
 }  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/vhal_proxy_server.cpp b/host/commands/run_cvd/launch/vhal_proxy_server.cpp
index 97bfca7c3..a2bd5c1ba 100644
--- a/host/commands/run_cvd/launch/vhal_proxy_server.cpp
+++ b/host/commands/run_cvd/launch/vhal_proxy_server.cpp
@@ -15,10 +15,13 @@
 
 #include "host/commands/run_cvd/launch/launch.h"
 
+#include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/config/command_source.h"
 #include "host/libs/config/known_paths.h"
 
+#include <linux/vm_sockets.h>
+
 namespace cuttlefish {
 
 std::optional<MonitorCommand> VhalProxyServer(
@@ -27,9 +30,18 @@ std::optional<MonitorCommand> VhalProxyServer(
   if (!instance.start_vhal_proxy_server()) {
     return {};
   }
-  return Command(VhalProxyServerBinary())
-      .AddParameter(VhalProxyServerConfig())
-      .AddParameter(config.vhal_proxy_server_port());
+  int port = config.vhal_proxy_server_port();
+  Command command = Command(VhalProxyServerBinary())
+                        .AddParameter(VhalProxyServerConfig())
+                        .AddParameter(fmt::format("localhost:{}", port));
+  if (instance.vhost_user_vsock()) {
+    command.AddParameter(
+        fmt::format("unix://{}", SharedFD::GetVhostUserVsockServerAddr(
+                                     port, instance.vsock_guest_cid())));
+  } else {
+    command.AddParameter(fmt::format("vsock:{}:{}", VMADDR_CID_HOST, port));
+  }
+  return command;
 }
 
 }  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/vhost_device_vsock.cpp b/host/commands/run_cvd/launch/vhost_device_vsock.cpp
index 4a08435a5..5f9d2cd6a 100644
--- a/host/commands/run_cvd/launch/vhost_device_vsock.cpp
+++ b/host/commands/run_cvd/launch/vhost_device_vsock.cpp
@@ -70,8 +70,8 @@ Result<std::vector<MonitorCommand>> VhostDeviceVsock::Commands() {
   }
 
   std::vector<MonitorCommand> commands;
-  commands.emplace_back(std::move(
-      CF_EXPECT(log_tee_.CreateLogTee(command, "vhost_device_vsock"))));
+  commands.emplace_back(
+      CF_EXPECT(log_tee_.CreateLogTee(command, "vhost_device_vsock")));
   commands.emplace_back(std::move(command));
   return commands;
 }
diff --git a/host/commands/run_cvd/main.cc b/host/commands/run_cvd/main.cc
index 163199be5..1cbe1439d 100644
--- a/host/commands/run_cvd/main.cc
+++ b/host/commands/run_cvd/main.cc
@@ -184,24 +184,6 @@ Result<void> StdinValid() {
   return {};
 }
 
-Result<const CuttlefishConfig*> FindConfigFromStdin() {
-  std::string input_files_str;
-  {
-    auto input_fd = SharedFD::Dup(0);
-    auto bytes_read = ReadAll(input_fd, &input_files_str);
-    CF_EXPECT(bytes_read >= 0, "Failed to read input files. Error was \""
-                                   << input_fd->StrError() << "\"");
-  }
-  std::vector<std::string> input_files =
-      android::base::Split(input_files_str, "\n");
-  for (const auto& file : input_files) {
-    if (file.find("cuttlefish_config.json") != std::string::npos) {
-      setenv(kCuttlefishConfigEnvVarName, file.c_str(), /* overwrite */ false);
-    }
-  }
-  return CF_EXPECT(CuttlefishConfig::Get());  // Null check
-}
-
 void ConfigureLogs(const CuttlefishConfig& config,
                    const CuttlefishConfig::InstanceSpecific& instance) {
   auto log_path = instance.launcher_log_path();
@@ -222,18 +204,6 @@ void ConfigureLogs(const CuttlefishConfig& config,
   ::android::base::SetLogger(LogToStderrAndFiles({log_path}, prefix));
 }
 
-Result<void> ChdirIntoRuntimeDir(
-    const CuttlefishConfig::InstanceSpecific& instance) {
-  // Change working directory to the instance directory as early as possible to
-  // ensure all host processes have the same working dir. This helps stop_cvd
-  // find the running processes when it can't establish a communication with the
-  // launcher.
-  CF_EXPECT(chdir(instance.instance_dir().c_str()) == 0,
-            "Unable to change dir into instance directory \""
-                << instance.instance_dir() << "\": " << strerror(errno));
-  return {};
-}
-
 }  // namespace
 
 Result<void> RunCvdMain(int argc, char** argv) {
@@ -242,11 +212,10 @@ Result<void> RunCvdMain(int argc, char** argv) {
   google::ParseCommandLineFlags(&argc, &argv, false);
 
   CF_EXPECT(StdinValid(), "Invalid stdin");
-  auto config = CF_EXPECT(FindConfigFromStdin());
+  auto config = CF_EXPECT(CuttlefishConfig::Get());
   auto environment = config->ForDefaultEnvironment();
   auto instance = config->ForDefaultInstance();
   ConfigureLogs(*config, instance);
-  CF_EXPECT(ChdirIntoRuntimeDir(instance));
 
   fruit::Injector<> injector(runCvdComponent, config, &environment, &instance);
 
diff --git a/host/commands/run_cvd/server_loop_impl.cpp b/host/commands/run_cvd/server_loop_impl.cpp
index f5caa7c2d..f326ac2e8 100644
--- a/host/commands/run_cvd/server_loop_impl.cpp
+++ b/host/commands/run_cvd/server_loop_impl.cpp
@@ -20,7 +20,6 @@
 
 #include <memory>
 #include <string>
-#include <unordered_set>
 #include <utility>
 #include <vector>
 
@@ -82,7 +81,6 @@ Result<void> ServerLoopImpl::Run() {
   auto process_monitor_properties =
       ProcessMonitor::Properties()
           .RestartSubprocesses(instance_.restart_subprocesses())
-          .SandboxProcesses(config_.host_sandbox())
           .StraceLogDir(instance_.PerInstanceLogPath(""))
           .StraceCommands(config_.straced_host_executables());
 
@@ -110,7 +108,12 @@ Result<void> ServerLoopImpl::Run() {
                    << launcher_action_with_info_result.error().FormatForEnv();
         break;
       }
-      auto launcher_action = std::move(*launcher_action_with_info_result);
+      auto launcher_action_opt = std::move(*launcher_action_with_info_result);
+      if (!launcher_action_opt.has_value()) {
+        // client disconnected
+        break;
+      }
+      auto launcher_action = *launcher_action_opt;
       if (launcher_action.action != LauncherAction::kExtended) {
         HandleActionWithNoData(launcher_action.action, client, process_monitor);
         continue;
diff --git a/host/commands/run_cvd/validate.cpp b/host/commands/run_cvd/validate.cpp
index 36cb72b1d..defef1e23 100644
--- a/host/commands/run_cvd/validate.cpp
+++ b/host/commands/run_cvd/validate.cpp
@@ -21,6 +21,7 @@
 #include <android-base/logging.h>
 #include <fruit/fruit.h>
 
+#include "common/libs/utils/in_sandbox.h"
 #include "common/libs/utils/network.h"
 #include "common/libs/utils/result.h"
 #include "host/libs/config/cuttlefish_config.h"
@@ -31,6 +32,9 @@ namespace cuttlefish {
 static Result<void> TestTapDevices(
     const CuttlefishConfig::InstanceSpecific& instance) {
 #ifdef __linux__
+  if (InSandbox()) {
+    return {};
+  }
   auto taps = TapInterfacesInUse();
   auto wifi = instance.wifi_tap_name();
   CF_EXPECTF(taps.count(wifi) == 0, "Device \"{}\" in use", wifi);
diff --git a/host/commands/screen_recording_server/main.cpp b/host/commands/screen_recording_server/main.cpp
index a577c4049..3a635be40 100644
--- a/host/commands/screen_recording_server/main.cpp
+++ b/host/commands/screen_recording_server/main.cpp
@@ -23,12 +23,14 @@
 #include <grpcpp/grpcpp.h>
 #include <grpcpp/health_check_service_interface.h>
 
+#include "run_cvd.pb.h"
+#include "screen_recording.grpc.pb.h"
+
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/result.h"
 #include "host/libs/command_util/util.h"
 #include "host/libs/config/cuttlefish_config.h"
-#include "run_cvd.pb.h"
-#include "screen_recording.grpc.pb.h"
+#include "host/libs/config/logging.h"
 
 using google::protobuf::Empty;
 using grpc::Server;
@@ -101,7 +103,10 @@ class ScreenRecordingServiceImpl final
   }
 };
 
-void RunScreenRecordingServer() {
+void RunScreenRecordingServer(int argc, char** argv) {
+  ::gflags::ParseCommandLineFlags(&argc, &argv, true);
+  DefaultSubprocessLogging(argv);
+
   std::string server_address("unix:" + FLAGS_grpc_uds_path);
   ScreenRecordingServiceImpl service;
 
@@ -115,7 +120,7 @@ void RunScreenRecordingServer() {
   builder.RegisterService(&service);
   // Finally assemble the server.
   std::unique_ptr<Server> server(builder.BuildAndStart());
-  std::cout << "Server listening on " << server_address << std::endl;
+  LOG(DEBUG) << "Server listening on " << server_address;
 
   // Wait for the server to shutdown. Note that some other thread must be
   // responsible for shutting down the server for this call to ever return.
@@ -126,8 +131,7 @@ void RunScreenRecordingServer() {
 }  // namespace cuttlefish
 
 int main(int argc, char** argv) {
-  ::gflags::ParseCommandLineFlags(&argc, &argv, true);
-  cuttlefish::RunScreenRecordingServer();
+  cuttlefish::RunScreenRecordingServer(argc, argv);
 
   return 0;
 }
diff --git a/host/commands/secure_env/secure_env_not_windows_main.cpp b/host/commands/secure_env/secure_env_not_windows_main.cpp
index 38be9a488..6c4272cc5 100644
--- a/host/commands/secure_env/secure_env_not_windows_main.cpp
+++ b/host/commands/secure_env/secure_env_not_windows_main.cpp
@@ -127,8 +127,9 @@ std::thread StartKernelEventMonitor(SharedFD kernel_events_fd,
   return std::thread([kernel_events_fd, &oemlock_lock]() {
     while (kernel_events_fd->IsOpen()) {
       auto read_result = monitor::ReadEvent(kernel_events_fd);
-      CHECK(read_result.has_value()) << kernel_events_fd->StrError();
-      if (read_result->event == monitor::Event::BootloaderLoaded) {
+      CHECK(read_result.ok()) << read_result.error().FormatForEnv();
+      CHECK(read_result->has_value()) << "EOF in kernel log monitor";
+      if ((*read_result)->event == monitor::Event::BootloaderLoaded) {
         LOG(DEBUG) << "secure_env detected guest reboot, restarting.";
 
         // secure_env app potentially may become stuck at IO during holding the
diff --git a/host/commands/secure_env/suspend_resume_handler.cpp b/host/commands/secure_env/suspend_resume_handler.cpp
index cf689f729..b7b09c061 100644
--- a/host/commands/secure_env/suspend_resume_handler.cpp
+++ b/host/commands/secure_env/suspend_resume_handler.cpp
@@ -76,9 +76,11 @@ Result<void> SnapshotCommandHandler::SuspendResumeHandler() {
   using ActionsCase =
       ::cuttlefish::run_cvd::ExtendedLauncherAction::ActionsCase;
 
-  auto launcher_action =
+  auto launcher_action_opt =
       CF_EXPECT(ReadLauncherActionFromFd(channel_to_run_cvd_),
                 "Failed to read LauncherAction from run_cvd");
+  auto launcher_action = CF_EXPECT(std::move(launcher_action_opt),
+                                   "Channel to run_cvd closed unexpectedly");
   CF_EXPECT(launcher_action.action == LauncherAction::kExtended);
 
   switch (launcher_action.extended_action.actions_case()) {
diff --git a/host/commands/start/Android.bp b/host/commands/start/Android.bp
index 73b9e25b6..24c8592ef 100644
--- a/host/commands/start/Android.bp
+++ b/host/commands/start/Android.bp
@@ -24,6 +24,8 @@ cc_binary {
         "filesystem_explorer.cc",
         "flag_forwarder.cc",
         "main.cc",
+        "override_bool_arg.cpp",
+        "validate_metrics_confirmation.cpp",
     ],
     shared_libs: [
         "libbase",
diff --git a/host/commands/start/filesystem_explorer.cc b/host/commands/start/filesystem_explorer.cc
index fde449c99..d9e490146 100644
--- a/host/commands/start/filesystem_explorer.cc
+++ b/host/commands/start/filesystem_explorer.cc
@@ -28,22 +28,25 @@
 #include "common/libs/utils/environment.h"
 #include "host/libs/config/fetcher_config.h"
 
-cuttlefish::FetcherConfig AvailableFilesReport() {
-  std::string current_directory = cuttlefish::AbsolutePath(cuttlefish::CurrentDirectory());
-  cuttlefish::FetcherConfig config;
+namespace cuttlefish {
 
-  if (cuttlefish::FileExists(current_directory + "/fetcher_config.json")) {
+FetcherConfig AvailableFilesReport() {
+  std::string current_directory = AbsolutePath(CurrentDirectory());
+  FetcherConfig config;
+
+  if (FileExists(current_directory + "/fetcher_config.json")) {
     config.LoadFromFile(current_directory + "/fetcher_config.json");
     return config;
   }
 
   // If needed check if `fetch_config.json` exists inside the $HOME directory.
   // `assemble_cvd` will perform a similar check.
-  std::string home_directory =
-      cuttlefish::StringFromEnv("HOME", cuttlefish::CurrentDirectory());
+  std::string home_directory = StringFromEnv("HOME", CurrentDirectory());
   std::string fetcher_config_path = home_directory + "/fetcher_config.json";
-  if (cuttlefish::FileExists(fetcher_config_path)) {
+  if (FileExists(fetcher_config_path)) {
     config.LoadFromFile(fetcher_config_path);
   }
   return config;
 }
+
+}  // namespace cuttlefish
diff --git a/host/commands/start/filesystem_explorer.h b/host/commands/start/filesystem_explorer.h
index ceae50448..6b3e4ca2e 100644
--- a/host/commands/start/filesystem_explorer.h
+++ b/host/commands/start/filesystem_explorer.h
@@ -17,4 +17,8 @@
 
 #include "host/libs/config/fetcher_config.h"
 
-cuttlefish::FetcherConfig AvailableFilesReport();
+namespace cuttlefish {
+
+FetcherConfig AvailableFilesReport();
+
+}
diff --git a/host/commands/start/flag_forwarder.cc b/host/commands/start/flag_forwarder.cc
index b4b5f0e73..5cae06fe2 100644
--- a/host/commands/start/flag_forwarder.cc
+++ b/host/commands/start/flag_forwarder.cc
@@ -32,6 +32,8 @@
 #include "common/libs/utils/contains.h"
 #include "common/libs/utils/subprocess.h"
 
+namespace cuttlefish {
+
 /**
  * Superclass for a flag loaded from another process.
  *
@@ -241,7 +243,7 @@ FlagForwarder::FlagForwarder(std::set<std::string> subprocesses,
 
   int subprocess_index = 0;
   for (const auto& subprocess : subprocesses_) {
-    cuttlefish::Command cmd(subprocess);
+    Command cmd(subprocess);
     cmd.AddParameter("--helpxml");
 
     if (subprocess_index < args.size()) {
@@ -252,11 +254,11 @@ FlagForwarder::FlagForwarder(std::set<std::string> subprocesses,
     subprocess_index++;
 
     std::string helpxml_input, helpxml_output, helpxml_error;
-    cuttlefish::SubprocessOptions options;
+    SubprocessOptions options;
     options.Verbose(false);
-    int helpxml_ret = cuttlefish::RunWithManagedStdio(
-        std::move(cmd), &helpxml_input, &helpxml_output, &helpxml_error,
-        std::move(options));
+    int helpxml_ret =
+        RunWithManagedStdio(std::move(cmd), &helpxml_input, &helpxml_output,
+                            &helpxml_error, std::move(options));
     if (helpxml_ret != 1) {
       LOG(FATAL) << subprocess << " --helpxml returned unexpected response "
                  << helpxml_ret << ". Stderr was " << helpxml_error;
@@ -288,7 +290,7 @@ FlagForwarder::~FlagForwarder() = default;
 void FlagForwarder::UpdateFlagDefaults() const {
 
   for (const auto& subprocess : subprocesses_) {
-    cuttlefish::Command cmd(subprocess);
+    Command cmd(subprocess);
     std::vector<std::string> invocation = {subprocess};
     for (const auto& flag : ArgvForSubprocess(subprocess)) {
       cmd.AddParameter(flag);
@@ -305,10 +307,10 @@ void FlagForwarder::UpdateFlagDefaults() const {
     // Ensure this is set on by putting it at the end.
     cmd.AddParameter("--helpxml");
     std::string helpxml_input, helpxml_output, helpxml_error;
-    auto options = cuttlefish::SubprocessOptions().Verbose(false);
-    int helpxml_ret = cuttlefish::RunWithManagedStdio(
-        std::move(cmd), &helpxml_input, &helpxml_output, &helpxml_error,
-        std::move(options));
+    auto options = SubprocessOptions().Verbose(false);
+    int helpxml_ret =
+        RunWithManagedStdio(std::move(cmd), &helpxml_input, &helpxml_output,
+                            &helpxml_error, std::move(options));
     if (helpxml_ret != 1) {
       LOG(FATAL) << subprocess << " --helpxml returned unexpected response "
                  << helpxml_ret << ". Stderr was " << helpxml_error;
@@ -345,7 +347,7 @@ std::vector<std::string> FlagForwarder::ArgvForSubprocess(
       if (qual_pos == std::string::npos) {
         // to handle error cases: --flag value and -flag value
         // but it only apply to repeatable flag case
-        if (cuttlefish::Contains(kRepeatableFlags, argument)) {
+        if (Contains(kRepeatableFlags, argument)) {
           // matched
           LOG(FATAL) << subprocess
                      << " has wrong flag input: " << args[index];
@@ -356,9 +358,9 @@ std::vector<std::string> FlagForwarder::ArgvForSubprocess(
       const std::string value(
           argument.substr(qual_pos + 1, argument.length() - qual_pos - 1));
 
-      if (cuttlefish::Contains(kRepeatableFlags, name)) {
+      if (Contains(kRepeatableFlags, name)) {
         // matched
-        if (!cuttlefish::Contains(name_to_value, name)) {
+        if (!Contains(name_to_value, name)) {
           // this flag is new
           std::vector<std::string> values;
           name_to_value[name] = values;
@@ -370,8 +372,8 @@ std::vector<std::string> FlagForwarder::ArgvForSubprocess(
 
   for (const auto& flag : flags_) {
     if (flag->Subprocess() == subprocess) {
-      if (cuttlefish::Contains(kRepeatableFlags, flag->Name()) &&
-          cuttlefish::Contains(name_to_value, flag->Name())) {
+      if (Contains(kRepeatableFlags, flag->Name()) &&
+          Contains(name_to_value, flag->Name())) {
         // this is a repeatable flag with input values
         for (const auto& value : name_to_value[flag->Name()]) {
           subprocess_argv.push_back("--" + flag->Name() + "=" + value);
@@ -389,3 +391,5 @@ std::vector<std::string> FlagForwarder::ArgvForSubprocess(
   }
   return subprocess_argv;
 }
+
+}  // namespace cuttlefish
diff --git a/host/commands/start/flag_forwarder.h b/host/commands/start/flag_forwarder.h
index 69994e1ed..8fd9fb03d 100644
--- a/host/commands/start/flag_forwarder.h
+++ b/host/commands/start/flag_forwarder.h
@@ -20,6 +20,8 @@
 #include <string>
 #include <vector>
 
+namespace cuttlefish {
+
 class SubprocessFlag;
 
 class FlagForwarder {
@@ -40,3 +42,5 @@ public:
      const std::string& subprocess,
      const std::vector<std::string>& args = std::vector<std::string>()) const;
 };
+
+}  // namespace cuttlefish
diff --git a/host/commands/start/main.cc b/host/commands/start/main.cc
index 236f1a782..1c39e3e05 100644
--- a/host/commands/start/main.cc
+++ b/host/commands/start/main.cc
@@ -13,10 +13,6 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-#ifdef __linux__
-#include <sys/prctl.h>
-#endif
-
 #include <fstream>
 #include <iostream>
 #include <sstream>
@@ -24,6 +20,7 @@
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include <android-base/no_destructor.h>
 #include <android-base/parseint.h>
 #include <gflags/gflags.h>
 
@@ -35,22 +32,14 @@
 #include "host/commands/assemble_cvd/flags_defaults.h"
 #include "host/commands/start/filesystem_explorer.h"
 #include "host/commands/start/flag_forwarder.h"
+#include "host/commands/start/override_bool_arg.h"
+#include "host/commands/start/validate_metrics_confirmation.h"
+#include "host/libs/config/config_utils.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/fetcher_config.h"
 #include "host/libs/config/host_tools_version.h"
 #include "host/libs/config/instance_nums.h"
-/**
- * If stdin is a tty, that means a user is invoking launch_cvd on the command
- * line and wants automatic file detection for assemble_cvd.
- *
- * If stdin is not a tty, that means launch_cvd is being passed a list of files
- * and that list should be forwarded to assemble_cvd.
- *
- * Controllable with a flag for extraordinary scenarios such as running from a
- * daemon which closes its own stdin.
- */
-DEFINE_bool(run_file_discovery, CF_DEFAULTS_RUN_FILE_DISCOVERY,
-            "Whether to run file discovery or get input files from stdin.");
+
 DEFINE_int32(num_instances, CF_DEFAULTS_NUM_INSTANCES,
              "Number of Android guests to launch");
 DEFINE_string(report_anonymous_usage_stats,
@@ -73,160 +62,64 @@ DEFINE_string(file_verbosity, CF_DEFAULTS_FILE_VERBOSITY,
 DEFINE_bool(use_overlay, CF_DEFAULTS_USE_OVERLAY,
             "Capture disk writes an overlay. This is a "
             "prerequisite for powerwash_cvd or multiple instances.");
-DEFINE_bool(share_sched_core, CF_DEFAULTS_SHARE_SCHED_CORE,
-            "Enable sharing cores between Cuttlefish processes.");
 DEFINE_bool(track_host_tools_crc, CF_DEFAULTS_TRACK_HOST_TOOLS_CRC,
             "Track changes to host executables");
 
+namespace cuttlefish {
 namespace {
 
-#ifdef __linux__
-void ShareSchedCore() {
-  // Address ~32% performance penalty introduced with CONFIG_SCHED_CORE=y.
-  // Allowing co-scheduling reduces the performance penalty to ~16% on
-  // n2-standard-4 instances at best.
-#ifndef PR_SCHED_CORE
-#define PR_SCHED_CORE 62
-#endif
-#ifndef PR_SCHED_CORE_CREATE
-#define PR_SCHED_CORE_CREATE 1
-#endif
-#ifndef PR_SCHED_CORE_SCOPE_PROCESS_GROUP
-#define PR_SCHED_CORE_SCOPE_PROCESS_GROUP 2
-#endif
-  int sched = prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, getpid(),
-                    PR_SCHED_CORE_SCOPE_PROCESS_GROUP, 0);
-  if (sched != 0) {
-    PLOG(VERBOSE) << "Failed to apply co-scheduling policy. If the kernel has"
-                  << " CONFIG_SCHED_CORE=y, may be performance penalties.";
-  } else {
-    LOG(VERBOSE) << "Applied PR_SCHED_CORE co-scheduling policy";
-  }
-}
-#endif
+using android::base::NoDestructor;
 
 std::string SubtoolPath(const std::string& subtool_base) {
   auto my_own_dir = android::base::GetExecutableDirectory();
   std::stringstream subtool_path_stream;
   subtool_path_stream << my_own_dir << "/" << subtool_base;
   auto subtool_path = subtool_path_stream.str();
-  if (my_own_dir.empty() || !cuttlefish::FileExists(subtool_path)) {
-    return cuttlefish::HostBinaryPath(subtool_base);
+  if (my_own_dir.empty() || !FileExists(subtool_path)) {
+    return HostBinaryPath(subtool_base);
   }
   return subtool_path;
 }
 
-std::string kAssemblerBin = SubtoolPath("assemble_cvd");
-std::string kRunnerBin = SubtoolPath("run_cvd");
+std::string AssemblerPath() { return SubtoolPath("assemble_cvd"); }
+std::string RunnerPath() { return SubtoolPath("run_cvd"); }
 
-cuttlefish::Subprocess StartAssembler(cuttlefish::SharedFD assembler_stdin,
-                               cuttlefish::SharedFD assembler_stdout,
-                               const std::vector<std::string>& argv) {
-  cuttlefish::Command assemble_cmd(kAssemblerBin);
+int InvokeAssembler(const std::string& assembler_stdin,
+                    std::string& assembler_stdout,
+                    const std::vector<std::string>& argv) {
+  Command assemble_cmd(AssemblerPath());
   for (const auto& arg : argv) {
     assemble_cmd.AddParameter(arg);
   }
-  if (assembler_stdin->IsOpen()) {
-    assemble_cmd.RedirectStdIO(cuttlefish::Subprocess::StdIOChannel::kStdIn, assembler_stdin);
-  }
-  assemble_cmd.RedirectStdIO(cuttlefish::Subprocess::StdIOChannel::kStdOut, assembler_stdout);
-  return assemble_cmd.Start();
+  return RunWithManagedStdio(std::move(assemble_cmd), &assembler_stdin,
+                             &assembler_stdout, nullptr);
 }
 
-cuttlefish::Subprocess StartRunner(cuttlefish::SharedFD runner_stdin,
-                            const std::vector<std::string>& argv) {
-  cuttlefish::Command run_cmd(kRunnerBin);
+Subprocess StartRunner(SharedFD runner_stdin,
+                       const CuttlefishConfig::InstanceSpecific& instance,
+                       const std::vector<std::string>& argv) {
+  Command run_cmd(RunnerPath());
   for (const auto& arg : argv) {
     run_cmd.AddParameter(arg);
   }
-  run_cmd.RedirectStdIO(cuttlefish::Subprocess::StdIOChannel::kStdIn, runner_stdin);
+  run_cmd.RedirectStdIO(Subprocess::StdIOChannel::kStdIn, runner_stdin);
+  run_cmd.SetWorkingDirectory(instance.instance_dir());
   return run_cmd.Start();
 }
 
-void WriteFiles(cuttlefish::FetcherConfig fetcher_config, cuttlefish::SharedFD out) {
+std::string WriteFiles(FetcherConfig fetcher_config) {
   std::stringstream output_streambuf;
   for (const auto& file : fetcher_config.get_cvd_files()) {
     output_streambuf << file.first << "\n";
   }
-  std::string output_string = output_streambuf.str();
-  int written = cuttlefish::WriteAll(out, output_string);
-  if (written < 0) {
-    LOG(FATAL) << "Could not write file report (" << strerror(out->GetErrno())
-               << ")";
-  }
-}
-
-std::string ValidateMetricsConfirmation(std::string use_metrics) {
-  if (use_metrics == "") {
-    if (cuttlefish::CuttlefishConfig::ConfigExists()) {
-      auto config = cuttlefish::CuttlefishConfig::Get();
-      if (config) {
-        if (config->enable_metrics() ==
-            cuttlefish::CuttlefishConfig::Answer::kYes) {
-          use_metrics = "y";
-        } else if (config->enable_metrics() ==
-                   cuttlefish::CuttlefishConfig::Answer::kNo) {
-          use_metrics = "n";
-        }
-      }
-    }
-  }
-
-  std::cout << "===================================================================\n";
-  std::cout << "NOTICE:\n\n";
-  std::cout << "By using this Android Virtual Device, you agree to\n";
-  std::cout << "Google Terms of Service (https://policies.google.com/terms).\n";
-  std::cout << "The Google Privacy Policy (https://policies.google.com/privacy)\n";
-  std::cout << "describes how Google handles information generated as you use\n";
-  std::cout << "Google Services.";
-  char ch = !use_metrics.empty() ? tolower(use_metrics.at(0)) : -1;
-  if (ch != 'n') {
-    if (use_metrics.empty()) {
-      std::cout << "\n===================================================================\n";
-      std::cout << "Automatically send diagnostic information to Google, such as crash\n";
-      std::cout << "reports and usage data from this Android Virtual Device. You can\n";
-      std::cout << "adjust this permission at any time by running\n";
-      std::cout << "\"launch_cvd -report_anonymous_usage_stats=n\". (Y/n)?:";
-    } else {
-      std::cout << " You can adjust the permission for sending\n";
-      std::cout << "diagnostic information to Google, such as crash reports and usage\n";
-      std::cout << "data from this Android Virtual Device, at any time by running\n";
-      std::cout << "\"launch_cvd -report_anonymous_usage_stats=n\"\n";
-      std::cout << "===================================================================\n\n";
-    }
-  } else {
-    std::cout << "\n===================================================================\n\n";
-  }
-  for (;;) {
-    switch (ch) {
-      case 0:
-      case '\r':
-      case '\n':
-      case 'y':
-        return "y";
-      case 'n':
-        return "n";
-      default:
-        std::cout << "Must accept/reject anonymous usage statistics reporting (Y/n): ";
-        FALLTHROUGH_INTENDED;
-      case -1:
-        std::cin.get(ch);
-        // if there's no tty the EOF flag is set, in which case default to 'n'
-        if (std::cin.eof()) {
-          ch = 'n';
-          std::cout << "n\n";  // for consistency with user input
-        }
-        ch = tolower(ch);
-    }
-  }
-  return "";
+  return output_streambuf.str();
 }
 
 bool HostToolsUpdated() {
-  if (cuttlefish::CuttlefishConfig::ConfigExists()) {
-    auto config = cuttlefish::CuttlefishConfig::Get();
+  if (CuttlefishConfig::ConfigExists()) {
+    auto config = CuttlefishConfig::Get();
     if (config) {
-      auto current_tools = cuttlefish::HostToolsCrc();
+      auto current_tools = HostToolsCrc();
       auto last_tools = config->host_tools_version();
       return current_tools != last_tools;
     }
@@ -238,107 +131,42 @@ bool HostToolsUpdated() {
 // Used to find bool flag and convert "flag"/"noflag" to "--flag=value"
 // This is the solution for vectorize bool flags in gFlags
 
-std::unordered_set<std::string> kBoolFlags = {
-    "guest_enforce_security",
-    "use_random_serial",
-    "use_allocd",
-    "use_sdcard",
-    "pause_in_bootloader",
-    "daemon",
-    "enable_minimal_mode",
-    "enable_modem_simulator",
-    "console",
-    "enable_sandbox",
-    "enable_virtiofs",
-    "enable_usb",
-    "restart_subprocesses",
-    "enable_gpu_udmabuf",
-    "enable_gpu_vhost_user",
-    "enable_audio",
-    "start_gnss_proxy",
-    "enable_bootanimation",
-    "record_screen",
-    "protected_vm",
-    "enable_kernel_log",
-    "kgdb",
-    "start_webrtc",
-    "smt",
-    "vhost_net",
-    "vhost_user_vsock",
-    "chromeos_boot",
-    "enable_host_sandbox",
-    "fail_fast",
-};
-
-struct BooleanFlag {
-  bool is_bool_flag;
-  bool bool_flag_value;
-  std::string name;
-};
-BooleanFlag IsBoolArg(const std::string& argument) {
-  // Validate format
-  // we only deal with special bool case: -flag, --flag, -noflag, --noflag
-  // and convert to -flag=true, --flag=true, -flag=false, --flag=false
-  // others not in this format just return false
-  std::string_view name = argument;
-  if (!android::base::ConsumePrefix(&name, "-")) {
-    return {false, false, ""};
-  }
-  android::base::ConsumePrefix(&name, "-");
-  std::size_t found = name.find('=');
-  if (found != std::string::npos) {
-    // found "=", --flag=value case, it doesn't need convert
-    return {false, false, ""};
-  }
-
-  // Validate it is part of the set
-  std::string result_name(name);
-  std::string_view new_name = result_name;
-  if (result_name.length() == 0) {
-    return {false, false, ""};
-  }
-  if (kBoolFlags.find(result_name) != kBoolFlags.end()) {
-    // matched -flag, --flag
-    return {true, true, result_name};
-  } else if (android::base::ConsumePrefix(&new_name, "no")) {
-    // 2nd chance to check -noflag, --noflag
-    result_name = new_name;
-    if (kBoolFlags.find(result_name) != kBoolFlags.end()) {
-      // matched -noflag, --noflag
-      return {true, false, result_name};
-    }
-  }
-  // return status
-  return {false, false, ""};
+const std::unordered_set<std::string>& BoolFlags() {
+  static const NoDestructor<std::unordered_set<std::string>> bool_flags({
+      "chromeos_boot",
+      "console",
+      "daemon",
+      "enable_audio",
+      "enable_bootanimation",
+      "enable_gpu_udmabuf",
+      "enable_gpu_vhost_user",
+      "enable_kernel_log",
+      "enable_minimal_mode",
+      "enable_modem_simulator",
+      "enable_sandbox",
+      "enable_usb",
+      "enable_virtiofs",
+      "fail_fast",
+      "guest_enforce_security",
+      "kgdb",
+      "pause_in_bootloader",
+      "protected_vm",
+      "record_screen",
+      "restart_subprocesses",
+      "smt",
+      "start_gnss_proxy",
+      "start_webrtc",
+      "use_allocd",
+      "use_random_serial",
+      "use_sdcard",
+      "vhost_net",
+      "vhost_user_block",
+      "vhost_user_vsock",
+  });
+  return *bool_flags;
 }
 
-std::string FormatBoolString(const std::string& name_str, bool value) {
-  std::string new_flag = "--" + name_str;
-  if (value) {
-    new_flag += "=true";
-  } else {
-    new_flag += "=false";
-  }
-  return new_flag;
-}
-
-bool OverrideBoolArg(std::vector<std::string>& args) {
-  bool overridden = false;
-  for (int index = 0; index < args.size(); index++) {
-    const std::string curr_arg = args[index];
-    BooleanFlag value = IsBoolArg(curr_arg);
-    if (value.is_bool_flag) {
-      // Override the value
-      args[index] = FormatBoolString(value.name, value.bool_flag_value);
-      overridden = true;
-    }
-  }
-  return overridden;
-}
-
-} // namespace
-
-int main(int argc, char** argv) {
+int CvdInternalStartMain(int argc, char** argv) {
   ::android::base::InitLogging(argv, android::base::StderrLogger);
 
   std::vector<std::string> args(argv + 1, argv + argc);
@@ -346,8 +174,8 @@ int main(int argc, char** argv) {
   std::vector<std::string> assemble_args;
   std::string image_dir;
   std::vector<std::string> args_copy = args;
-  auto parse_res = cuttlefish::ConsumeFlags(
-      {cuttlefish::GflagsCompatFlag("system_image_dir", image_dir)}, args_copy);
+  auto parse_res = ConsumeFlags(
+      {GflagsCompatFlag("system_image_dir", image_dir)}, args_copy);
   LOG(INFO) << "Using system_image_dir of: " << image_dir;
 
   if (!parse_res.ok()) {
@@ -359,26 +187,17 @@ int main(int argc, char** argv) {
   }
 
   std::vector<std::vector<std::string>> spargs = {assemble_args, {}};
-  FlagForwarder forwarder({kAssemblerBin, kRunnerBin}, spargs);
+  FlagForwarder forwarder({AssemblerPath(), RunnerPath()}, spargs);
 
   // Used to find bool flag and convert "flag"/"noflag" to "--flag=value"
   // This is the solution for vectorize bool flags in gFlags
-  if (OverrideBoolArg(args)) {
-    for (int i = 1; i < argc; i++) {
-      argv[i] = &args[i-1][0]; // args[] start from 0
-    }
+  args = OverrideBoolArg(std::move(args), BoolFlags());
+  for (int i = 1; i < argc; i++) {
+    argv[i] = args[i - 1].data();  // args[] start from 0
   }
 
   gflags::ParseCommandLineNonHelpFlags(&argc, &argv, false);
 
-  if (FLAGS_share_sched_core) {
-#ifdef __linux__
-    ShareSchedCore();
-#else
-    LOG(ERROR) << "--shared_sched_core is unsupported on this platform";
-#endif
-  }
-
   forwarder.UpdateFlagDefaults();
 
   gflags::HandleCommandLineHelpFlags();
@@ -394,24 +213,16 @@ int main(int argc, char** argv) {
     LOG(INFO) << "Host changed from last run: " << HostToolsUpdated();
   }
 
-  cuttlefish::SharedFD assembler_stdout, assembler_stdout_capture;
-  cuttlefish::SharedFD::Pipe(&assembler_stdout_capture, &assembler_stdout);
-
-  cuttlefish::SharedFD launcher_report, assembler_stdin;
-  bool should_generate_report = FLAGS_run_file_discovery;
-  if (should_generate_report) {
-    cuttlefish::SharedFD::Pipe(&assembler_stdin, &launcher_report);
-  }
-
-  auto instance_nums =
-      cuttlefish::InstanceNumsCalculator().FromGlobalGflags().Calculate();
+  auto instance_nums = InstanceNumsCalculator().FromGlobalGflags().Calculate();
   if (!instance_nums.ok()) {
     LOG(ERROR) << instance_nums.error().FormatForEnv();
     abort();
   }
 
-  if (cuttlefish::CuttlefishConfig::ConfigExists()) {
-    auto previous_config = cuttlefish::CuttlefishConfig::Get();
+  // TODO(schuffelen): Lift instance id assumptions in sandboxing
+
+  if (CuttlefishConfig::ConfigExists()) {
+    auto previous_config = CuttlefishConfig::Get();
     CHECK(previous_config);
     CHECK(!previous_config->Instances().empty());
     auto previous_instance = previous_config->Instances()[0];
@@ -428,35 +239,26 @@ int main(int argc, char** argv) {
 
   CHECK(!instance_nums->empty()) << "Expected at least one instance";
   auto instance_num_str = std::to_string(*instance_nums->begin());
-  setenv(cuttlefish::kCuttlefishInstanceEnvVarName, instance_num_str.c_str(),
+  setenv(kCuttlefishInstanceEnvVarName, instance_num_str.c_str(),
          /* overwrite */ 1);
 
 #if defined(__BIONIC__)
   // These environment variables are needed in case when Bionic is used.
   // b/171754977
-  setenv("ANDROID_DATA", cuttlefish::DefaultHostArtifactsPath("").c_str(), /* overwrite */ 0);
-  setenv("ANDROID_TZDATA_ROOT", cuttlefish::DefaultHostArtifactsPath("").c_str(), /* overwrite */ 0);
-  setenv("ANDROID_ROOT", cuttlefish::DefaultHostArtifactsPath("").c_str(), /* overwrite */ 0);
+  setenv("ANDROID_DATA", DefaultHostArtifactsPath("").c_str(),
+         /* overwrite */ 0);
+  setenv("ANDROID_TZDATA_ROOT", DefaultHostArtifactsPath("").c_str(),
+         /* overwrite */ 0);
+  setenv("ANDROID_ROOT", DefaultHostArtifactsPath("").c_str(),
+         /* overwrite */ 0);
 #endif
 
-  // SharedFDs are std::move-d in to avoid dangling references.
-  // Removing the std::move will probably make run_cvd hang as its stdin never closes.
-  auto assemble_proc =
-      StartAssembler(std::move(assembler_stdin), std::move(assembler_stdout),
-                     forwarder.ArgvForSubprocess(kAssemblerBin, args));
-
-  if (should_generate_report) {
-    WriteFiles(AvailableFilesReport(), std::move(launcher_report));
-  }
-
+  auto assembler_input = WriteFiles(AvailableFilesReport());
   std::string assembler_output;
-  if (cuttlefish::ReadAll(assembler_stdout_capture, &assembler_output) < 0) {
-    int error_num = errno;
-    LOG(ERROR) << "Read error getting output from assemble_cvd: " << strerror(error_num);
-    return -1;
-  }
+  auto assemble_ret =
+      InvokeAssembler(assembler_input, assembler_output,
+                      forwarder.ArgvForSubprocess(AssemblerPath(), args));
 
-  auto assemble_ret = assemble_proc.Wait();
   if (assemble_ret != 0) {
     LOG(ERROR) << "assemble_cvd returned " << assemble_ret;
     return assemble_ret;
@@ -464,22 +266,27 @@ int main(int argc, char** argv) {
     LOG(DEBUG) << "assemble_cvd exited successfully.";
   }
 
-  std::vector<cuttlefish::Subprocess> runners;
-  for (const auto& instance_num : *instance_nums) {
-    cuttlefish::SharedFD runner_stdin_in, runner_stdin_out;
-    cuttlefish::SharedFD::Pipe(&runner_stdin_out, &runner_stdin_in);
-    std::string instance_num_str = std::to_string(instance_num);
-    setenv(cuttlefish::kCuttlefishInstanceEnvVarName, instance_num_str.c_str(),
+  std::string conf_path;
+  for (const auto& line : android::base::Tokenize(assembler_output, "\n")) {
+    if (android::base::EndsWith(line, "cuttlefish_config.json")) {
+      conf_path = line;
+    }
+  }
+  CHECK(!conf_path.empty()) << "could not find config";
+  auto config = CuttlefishConfig::GetFromFile(conf_path);
+  CHECK(config) << "Could not load config object";
+  setenv(kCuttlefishConfigEnvVarName, conf_path.c_str(), /* overwrite */ true);
+
+  std::vector<Subprocess> runners;
+  for (const auto& instance : config->Instances()) {
+    SharedFD runner_stdin = SharedFD::Open("/dev/null", O_RDONLY);
+    CHECK(runner_stdin->IsOpen()) << runner_stdin->StrError();
+    setenv(kCuttlefishInstanceEnvVarName, instance.id().c_str(),
            /* overwrite */ 1);
 
-    auto run_proc = StartRunner(std::move(runner_stdin_out),
-                                forwarder.ArgvForSubprocess(kRunnerBin));
+    auto run_proc = StartRunner(std::move(runner_stdin), instance,
+                                forwarder.ArgvForSubprocess(RunnerPath()));
     runners.push_back(std::move(run_proc));
-    if (cuttlefish::WriteAll(runner_stdin_in, assembler_output) < 0) {
-      int error_num = errno;
-      LOG(ERROR) << "Could not write to run_cvd: " << strerror(error_num);
-      return -1;
-    }
   }
 
   bool run_cvd_failure = false;
@@ -494,3 +301,10 @@ int main(int argc, char** argv) {
   }
   return run_cvd_failure ? -1 : 0;
 }
+
+}  // namespace
+}  // namespace cuttlefish
+
+int main(int argc, char** argv) {
+  return cuttlefish::CvdInternalStartMain(argc, argv);
+}
diff --git a/host/commands/start/override_bool_arg.cpp b/host/commands/start/override_bool_arg.cpp
new file mode 100644
index 000000000..8a9cd5c65
--- /dev/null
+++ b/host/commands/start/override_bool_arg.cpp
@@ -0,0 +1,95 @@
+//
+// Copyright (C) 2022 The Android Open Source Project
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
+#include "host/commands/start/override_bool_arg.h"
+
+#include <string>
+#include <unordered_set>
+#include <vector>
+
+#include <android-base/strings.h>
+
+namespace cuttlefish {
+namespace {
+
+struct BooleanFlag {
+  bool is_bool_flag;
+  bool bool_flag_value;
+  std::string name;
+};
+BooleanFlag IsBoolArg(const std::string& argument,
+                      const std::unordered_set<std::string>& flag_set) {
+  // Validate format
+  // we only deal with special bool case: -flag, --flag, -noflag, --noflag
+  // and convert to -flag=true, --flag=true, -flag=false, --flag=false
+  // others not in this format just return false
+  std::string_view name = argument;
+  if (!android::base::ConsumePrefix(&name, "-")) {
+    return {false, false, ""};
+  }
+  android::base::ConsumePrefix(&name, "-");
+  std::size_t found = name.find('=');
+  if (found != std::string::npos) {
+    // found "=", --flag=value case, it doesn't need convert
+    return {false, false, ""};
+  }
+
+  // Validate it is part of the set
+  std::string result_name(name);
+  std::string_view new_name = result_name;
+  if (result_name.length() == 0) {
+    return {false, false, ""};
+  }
+  if (flag_set.find(result_name) != flag_set.end()) {
+    // matched -flag, --flag
+    return {true, true, result_name};
+  } else if (android::base::ConsumePrefix(&new_name, "no")) {
+    // 2nd chance to check -noflag, --noflag
+    result_name = new_name;
+    if (flag_set.find(result_name) != flag_set.end()) {
+      // matched -noflag, --noflag
+      return {true, false, result_name};
+    }
+  }
+  // return status
+  return {false, false, ""};
+}
+
+std::string FormatBoolString(const std::string& name_str, bool value) {
+  std::string new_flag = "--" + name_str;
+  if (value) {
+    new_flag += "=true";
+  } else {
+    new_flag += "=false";
+  }
+  return new_flag;
+}
+
+}  // namespace
+
+std::vector<std::string> OverrideBoolArg(
+    std::vector<std::string> args,
+    const std::unordered_set<std::string>& flag_set) {
+  for (int index = 0; index < args.size(); index++) {
+    const std::string curr_arg = args[index];
+    BooleanFlag value = IsBoolArg(curr_arg, flag_set);
+    if (value.is_bool_flag) {
+      // Override the value
+      args[index] = FormatBoolString(value.name, value.bool_flag_value);
+    }
+  }
+  return args;
+}
+
+}  // namespace cuttlefish
diff --git a/common/libs/utils/unique_resource_allocator_test.h b/host/commands/start/override_bool_arg.h
similarity index 68%
rename from common/libs/utils/unique_resource_allocator_test.h
rename to host/commands/start/override_bool_arg.h
index 82cd1c0ff..b418b12d6 100644
--- a/common/libs/utils/unique_resource_allocator_test.h
+++ b/host/commands/start/override_bool_arg.h
@@ -12,23 +12,16 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
-
 #pragma once
 
+#include <string>
+#include <unordered_set>
 #include <vector>
 
-#include <gtest/gtest.h>
-
 namespace cuttlefish {
 
-// Get one unique item at a time
-class OneEachTest : public testing::TestWithParam<std::vector<unsigned>> {};
-
-/*
- * ClaimAll, StrideBeyond, Consecutive, Take, TakeAll, TakeRange,
- * Reclaim
- *
- */
-class CvdIdAllocatorTest : public testing::Test {};
+std::vector<std::string> OverrideBoolArg(
+    std::vector<std::string> args,
+    const std::unordered_set<std::string>& flag_set);
 
-}  // namespace cuttlefish
+}
diff --git a/host/commands/start/validate_metrics_confirmation.cpp b/host/commands/start/validate_metrics_confirmation.cpp
new file mode 100644
index 000000000..98db2c669
--- /dev/null
+++ b/host/commands/start/validate_metrics_confirmation.cpp
@@ -0,0 +1,99 @@
+//
+// Copyright (C) 2020 The Android Open Source Project
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
+#include "host/commands/start/validate_metrics_confirmation.h"
+
+#include <iostream>
+#include <string>
+
+#include "host/libs/config/cuttlefish_config.h"
+
+namespace cuttlefish {
+
+std::string ValidateMetricsConfirmation(std::string use_metrics) {
+  if (use_metrics == "") {
+    if (CuttlefishConfig::ConfigExists()) {
+      auto config = CuttlefishConfig::Get();
+      if (config) {
+        if (config->enable_metrics() == CuttlefishConfig::Answer::kYes) {
+          use_metrics = "y";
+        } else if (config->enable_metrics() == CuttlefishConfig::Answer::kNo) {
+          use_metrics = "n";
+        }
+      }
+    }
+  }
+
+  std::cout << "==============================================================="
+               "====\n";
+  std::cout << "NOTICE:\n\n";
+  std::cout << "By using this Android Virtual Device, you agree to\n";
+  std::cout << "Google Terms of Service (https://policies.google.com/terms).\n";
+  std::cout
+      << "The Google Privacy Policy (https://policies.google.com/privacy)\n";
+  std::cout
+      << "describes how Google handles information generated as you use\n";
+  std::cout << "Google Services.";
+  char ch = !use_metrics.empty() ? tolower(use_metrics.at(0)) : -1;
+  if (ch != 'n') {
+    if (use_metrics.empty()) {
+      std::cout << "\n========================================================="
+                   "==========\n";
+      std::cout << "Automatically send diagnostic information to Google, such "
+                   "as crash\n";
+      std::cout << "reports and usage data from this Android Virtual Device. "
+                   "You can\n";
+      std::cout << "adjust this permission at any time by running\n";
+      std::cout << "\"launch_cvd -report_anonymous_usage_stats=n\". (Y/n)?:";
+    } else {
+      std::cout << " You can adjust the permission for sending\n";
+      std::cout << "diagnostic information to Google, such as crash reports "
+                   "and usage\n";
+      std::cout
+          << "data from this Android Virtual Device, at any time by running\n";
+      std::cout << "\"launch_cvd -report_anonymous_usage_stats=n\"\n";
+      std::cout << "==========================================================="
+                   "========\n\n";
+    }
+  } else {
+    std::cout << "\n==========================================================="
+                 "========\n\n";
+  }
+  for (;;) {
+    switch (ch) {
+      case 0:
+      case '\r':
+      case '\n':
+      case 'y':
+        return "y";
+      case 'n':
+        return "n";
+      default:
+        std::cout << "Must accept/reject anonymous usage statistics reporting "
+                     "(Y/n): ";
+        FALLTHROUGH_INTENDED;
+      case -1:
+        std::cin.get(ch);
+        // if there's no tty the EOF flag is set, in which case default to 'n'
+        if (std::cin.eof()) {
+          ch = 'n';
+          std::cout << "n\n";  // for consistency with user input
+        }
+        ch = tolower(ch);
+    }
+  }
+  return "";
+}
+
+}  // namespace cuttlefish
diff --git a/host/commands/start/validate_metrics_confirmation.h b/host/commands/start/validate_metrics_confirmation.h
new file mode 100644
index 000000000..8976eb6b4
--- /dev/null
+++ b/host/commands/start/validate_metrics_confirmation.h
@@ -0,0 +1,23 @@
+//
+// Copyright (C) 2020 The Android Open Source Project
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
+#pragma once
+
+#include <string>
+
+namespace cuttlefish {
+
+std::string ValidateMetricsConfirmation(std::string use_metrics);
+
+}
diff --git a/host/commands/tcp_connector/main.cpp b/host/commands/tcp_connector/main.cpp
index 05dbc68d1..1a6296692 100644
--- a/host/commands/tcp_connector/main.cpp
+++ b/host/commands/tcp_connector/main.cpp
@@ -16,16 +16,15 @@
 #include <fcntl.h>
 #include <poll.h>
 #include <unistd.h>
-#include <ios>
+
 #include <mutex>
+#include <thread>
 
 #include <android-base/logging.h>
 #include <gflags/gflags.h>
-#include <thread>
 
 #include "common/libs/fs/shared_buf.h"
 #include "common/libs/fs/shared_fd.h"
-#include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/logging.h"
 
 DEFINE_int32(fifo_in, -1, "A pipe for incoming communication");
@@ -35,15 +34,18 @@ DEFINE_int32(buffer_size, -1, "The buffer size");
 DEFINE_int32(dump_packet_size, -1,
              "Dump incoming/outgoing packets up to given size");
 
-void OpenSocket(cuttlefish::SharedFD* fd, int port) {
+namespace cuttlefish {
+namespace {
+
+SharedFD OpenSocket(int port) {
   static std::mutex mutex;
   std::unique_lock<std::mutex> lock(mutex);
   for (;;) {
-    *fd = cuttlefish::SharedFD::SocketLocalClient(port, SOCK_STREAM);
-    if ((*fd)->IsOpen()) {
-      return;
+    SharedFD fd = SharedFD::SocketLocalClient(port, SOCK_STREAM);
+    if (fd->IsOpen()) {
+      return fd;
     }
-    LOG(ERROR) << "Failed to open socket: " << (*fd)->StrError();
+    LOG(ERROR) << "Failed to open socket: " << fd->StrError();
     // Wait a little and try again
     sleep(1);
   }
@@ -71,10 +73,10 @@ void DumpPackets(const char* prefix, char* buf, int size) {
   }
 }
 
-int main(int argc, char** argv) {
-  cuttlefish::DefaultSubprocessLogging(argv);
+int TcpConnectorMain(int argc, char** argv) {
+  DefaultSubprocessLogging(argv);
   gflags::ParseCommandLineFlags(&argc, &argv, true);
-  auto fifo_in = cuttlefish::SharedFD::Dup(FLAGS_fifo_in);
+  auto fifo_in = SharedFD::Dup(FLAGS_fifo_in);
   if (!fifo_in->IsOpen()) {
     LOG(ERROR) << "Error dupping fd " << FLAGS_fifo_in << ": "
                << fifo_in->StrError();
@@ -82,15 +84,14 @@ int main(int argc, char** argv) {
   }
   close(FLAGS_fifo_in);
 
-  auto fifo_out = cuttlefish::SharedFD::Dup(FLAGS_fifo_out);
+  auto fifo_out = SharedFD::Dup(FLAGS_fifo_out);
   if (!fifo_out->IsOpen()) {
     LOG(ERROR) << "Error dupping fd " << FLAGS_fifo_out << ": "
                << fifo_out->StrError();
     return 1;
   }
   close(FLAGS_fifo_out);
-  cuttlefish::SharedFD sock;
-  OpenSocket(&sock, FLAGS_data_port);
+  SharedFD sock = OpenSocket(FLAGS_data_port);
 
   auto guest_to_host = std::thread([&]() {
     while (true) {
@@ -102,12 +103,12 @@ int main(int argc, char** argv) {
         continue;
       }
       DumpPackets("Read from FIFO", buf, read);
-      while (cuttlefish::WriteAll(sock, buf, read) == -1) {
+      while (WriteAll(sock, buf, read) == -1) {
         LOG(WARNING) << "Failed to write to host socket (will retry): "
                      << sock->StrError();
         // Wait for the host process to be ready
         sleep(1);
-        OpenSocket(&sock, FLAGS_data_port);
+        sock = OpenSocket(FLAGS_data_port);
       }
     }
   });
@@ -122,10 +123,10 @@ int main(int argc, char** argv) {
                      << sock->StrError();
         // Wait for the host process to be ready
         sleep(1);
-        OpenSocket(&sock, FLAGS_data_port);
+        sock = OpenSocket(FLAGS_data_port);
         continue;
       }
-      auto wrote = cuttlefish::WriteAll(fifo_out, buf, read);
+      auto wrote = WriteAll(fifo_out, buf, read);
       if (wrote < 0) {
         LOG(WARNING) << "Failed to write to guest: " << fifo_out->StrError();
         sleep(1);
@@ -135,4 +136,13 @@ int main(int argc, char** argv) {
   });
   guest_to_host.join();
   host_to_guest.join();
+
+  return 0;
+}
+
+}  // namespace
+}  // namespace cuttlefish
+
+int main(int argc, char** argv) {
+  return cuttlefish::TcpConnectorMain(argc, argv);
 }
diff --git a/host/commands/vhal_proxy_server/VhalProxyServer.cpp b/host/commands/vhal_proxy_server/VhalProxyServer.cpp
index 1de12c3f4..e9f46f0b3 100644
--- a/host/commands/vhal_proxy_server/VhalProxyServer.cpp
+++ b/host/commands/vhal_proxy_server/VhalProxyServer.cpp
@@ -18,14 +18,17 @@
 #include "GRPCVehicleProxyServer.h"
 #include "vsockinfo.h"
 
+#include <VehicleUtils.h>
+#include <aidl/android/hardware/automotive/vehicle/VehicleApPowerStateConfigFlag.h>
 #include <android-base/logging.h>
 #include <cutils/properties.h>
-#include <linux/vm_sockets.h>
-#include <sys/socket.h>
 
 #include <memory>
 
+using ::aidl::android::hardware::automotive::vehicle::
+    VehicleApPowerStateConfigFlag;
 using ::android::hardware::automotive::utils::VsockConnectionInfo;
+using ::android::hardware::automotive::vehicle::toInt;
 using ::android::hardware::automotive::vehicle::fake::FakeVehicleHardware;
 using ::android::hardware::automotive::vehicle::virtualization::
     GrpcVehicleProxyServer;
@@ -33,18 +36,28 @@ using ::android::hardware::automotive::vehicle::virtualization::
 // A GRPC server for VHAL running on the guest Android.
 // argv[1]: Config directory path containing property config file (e.g.
 // DefaultProperties.json).
-// argv[2]: The vsock port number used by this server.
+// argv[2]: The IP address for this server.
+// argv[3]: The vsock address for this server.
 int main(int argc, char* argv[]) {
-  CHECK(argc >= 3) << "Not enough arguments, require at least 2: config file "
-                      "path and vsock port";
-  VsockConnectionInfo vsock = {
-      .cid = VMADDR_CID_HOST, .port = static_cast<unsigned int>(atoi(argv[2]))};
-  LOG(INFO) << "VHAL Server is listening on " << vsock.str();
+  CHECK(argc >= 4) << "Not enough arguments, require at least 3: config file "
+                      "path, IP address, vsock address";
 
-  auto fakeHardware = std::make_unique<FakeVehicleHardware>(argv[1], "", false);
-  auto proxyServer = std::make_unique<GrpcVehicleProxyServer>(
-      vsock.str(), std::move(fakeHardware));
+  std::string eth_addr = argv[2];
+  std::string grpc_server_addr = argv[3];
+  std::vector<std::string> listen_addrs = {grpc_server_addr, eth_addr};
 
-  proxyServer->Start().Wait();
+  // For cuttlefish we support S2R and S2D.
+  int32_t s2rS2dConfig =
+      toInt(VehicleApPowerStateConfigFlag::ENABLE_DEEP_SLEEP_FLAG) |
+      toInt(VehicleApPowerStateConfigFlag::ENABLE_HIBERNATION_FLAG);
+  auto fake_hardware =
+      std::make_unique<FakeVehicleHardware>(argv[1], "", false, s2rS2dConfig);
+  auto proxy_server = std::make_unique<GrpcVehicleProxyServer>(
+      listen_addrs, std::move(fake_hardware));
+
+  LOG(INFO) << "VHAL Server is listening on " << grpc_server_addr << ", "
+            << eth_addr;
+
+  proxy_server->Start().Wait();
   return 0;
 }
diff --git a/host/commands/vhal_proxy_server/debug/Android.bp b/host/commands/vhal_proxy_server/debug/Android.bp
new file mode 100644
index 000000000..78916c7af
--- /dev/null
+++ b/host/commands/vhal_proxy_server/debug/Android.bp
@@ -0,0 +1,39 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+cc_binary_host {
+    name: "vhal_proxy_server_cmd",
+    defaults: [
+        "cuttlefish_host",
+    ],
+    srcs: [
+        "VhalProxyServerCmd.cpp",
+    ],
+    cflags: [
+        "-Wno-unused-parameter",
+    ],
+    static_libs: [
+        "android.hardware.automotive.vehicle@default-grpc-libgrpc",
+        "libcuttlefish_fs",
+        "libcuttlefish_utils",
+    ],
+    shared_libs: [
+        "libbase",
+        "libcutils",
+        "libgrpc++",
+        "liblog",
+        "libprotobuf-cpp-full",
+    ],
+}
diff --git a/host/commands/vhal_proxy_server/debug/VhalProxyServerCmd.cpp b/host/commands/vhal_proxy_server/debug/VhalProxyServerCmd.cpp
new file mode 100644
index 000000000..8cb65a2de
--- /dev/null
+++ b/host/commands/vhal_proxy_server/debug/VhalProxyServerCmd.cpp
@@ -0,0 +1,69 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "VehicleServer.grpc.pb.h"
+#include "VehicleServer.pb.h"
+
+#include <android-base/logging.h>
+#include <grpc++/grpc++.h>
+#include "common/libs/utils/flag_parser.h"
+
+using ::android::hardware::automotive::vehicle::proto::DumpOptions;
+using ::android::hardware::automotive::vehicle::proto::DumpResult;
+using ::android::hardware::automotive::vehicle::proto::VehicleServer;
+using ::cuttlefish::Flag;
+using ::cuttlefish::FlagAliasMode;
+using ::cuttlefish::GflagsCompatFlag;
+using ::grpc::ClientContext;
+using ::grpc::CreateChannel;
+using ::grpc::InsecureChannelCredentials;
+using ::grpc::Status;
+
+static constexpr int DEFAULT_ETH_PORT = 9300;
+
+// A GRPC server for VHAL running on the guest Android.
+// argv[1]: Config directory path containing property config file (e.g.
+// DefaultProperties.json).
+// argv[2]: The vsock port number used by this server.
+int main(int argc, char* argv[]) {
+  std::vector<std::string> args;
+  for (int i = 1; i < argc; i++) {
+    args.push_back(std::string(argv[i]));
+  }
+
+  int32_t eth_port = DEFAULT_ETH_PORT;
+  std::vector<Flag> flags{GflagsCompatFlag("port", eth_port)};
+  CHECK(cuttlefish::ConsumeFlags(flags, args).ok()) << "Failed to parse flags";
+
+  DumpOptions dump_options;
+  // The rest of the arguments are commands passed to VHAL.
+  for (const auto& arg : args) {
+    dump_options.add_options(arg);
+  }
+
+  auto eth_addr = fmt::format("localhost:{}", eth_port);
+
+  auto channel = CreateChannel(eth_addr, InsecureChannelCredentials());
+  auto stub = VehicleServer::NewStub(channel);
+  ClientContext context;
+  DumpResult result;
+  auto status = stub->Dump(&context, dump_options, &result);
+  CHECK(status.ok()) << "Failed to call Dump on VHAL proxy server, error: "
+                     << status.error_message();
+
+  std::cout << "Debug command finished, result: \n" << result.buffer();
+  return 0;
+}
diff --git a/host/commands/vhal_proxy_server/vsockinfo.h b/host/commands/vhal_proxy_server/vsockinfo.h
index fde879b00..c38b2a083 100644
--- a/host/commands/vhal_proxy_server/vsockinfo.h
+++ b/host/commands/vhal_proxy_server/vsockinfo.h
@@ -18,6 +18,7 @@
 
 #include <array>
 #include <optional>
+#include <sstream>
 #include <string>
 
 namespace android::hardware::automotive::utils {
diff --git a/host/frontend/webrtc/Android.bp b/host/frontend/webrtc/Android.bp
index e77faf810..3dbc31518 100644
--- a/host/frontend/webrtc/Android.bp
+++ b/host/frontend/webrtc/Android.bp
@@ -46,6 +46,7 @@ cc_binary_host {
         "webrtc_signaling_headers",
         "libdrm_headers",
         "libwebrtc_absl_headers",
+        "libcuttlefish_confui_host_headers",
         "libeigen",
     ],
     static_libs: [
@@ -53,9 +54,12 @@ cc_binary_host {
         "libcap",
         "libcn-cbor",
         "libcuttlefish_audio_connector",
+        "libcuttlefish_confui",
+        "libcuttlefish_confui_host",
         "libcuttlefish_host_config",
         "libcuttlefish_input_connector",
         "libcuttlefish_security",
+        "libcuttlefish_screen_connector",
         "libcuttlefish_utils",
         "libcuttlefish_wayland_server",
         "libft2.nodep",
diff --git a/host/frontend/webrtc/connection_observer.cpp b/host/frontend/webrtc/connection_observer.cpp
index aaa903cff..08de3d29c 100644
--- a/host/frontend/webrtc/connection_observer.cpp
+++ b/host/frontend/webrtc/connection_observer.cpp
@@ -69,12 +69,19 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
         lights_observer_(lights_observer) {}
   virtual ~ConnectionObserverImpl() {
     auto display_handler = weak_display_handler_.lock();
+    if (display_handler) {
+      display_handler->RemoveDisplayClient();
+    }
     if (kernel_log_subscription_id_ != -1) {
       kernel_log_events_handler_->Unsubscribe(kernel_log_subscription_id_);
     }
   }
 
   void OnConnected() override {
+    auto display_handler = weak_display_handler_.lock();
+    if (display_handler) {
+      display_handler->AddDisplayClient();
+    }
     SendLastFrameAsync(/*all displays*/ std::nullopt);
   }
 
diff --git a/host/frontend/webrtc/connection_observer.h b/host/frontend/webrtc/connection_observer.h
index b04151f2a..f71845c74 100644
--- a/host/frontend/webrtc/connection_observer.h
+++ b/host/frontend/webrtc/connection_observer.h
@@ -26,6 +26,7 @@
 #include "host/frontend/webrtc/libdevice/connection_observer.h"
 #include "host/frontend/webrtc/libdevice/lights_observer.h"
 #include "host/frontend/webrtc/sensors_handler.h"
+#include "host/libs/confui/host_virtual_input.h"
 #include "host/libs/input_connector/input_connector.h"
 
 namespace cuttlefish {
diff --git a/host/frontend/webrtc/display_handler.cpp b/host/frontend/webrtc/display_handler.cpp
index f8bd293d2..185e34a0b 100644
--- a/host/frontend/webrtc/display_handler.cpp
+++ b/host/frontend/webrtc/display_handler.cpp
@@ -17,7 +17,6 @@
 #include "host/frontend/webrtc/display_handler.h"
 
 #include <chrono>
-#include <functional>
 #include <memory>
 
 #include <drm/drm_fourcc.h>
@@ -28,15 +27,12 @@
 namespace cuttlefish {
 
 DisplayHandler::DisplayHandler(webrtc_streaming::Streamer& streamer,
-                               int wayland_socket_fd,
-                               bool wayland_frames_are_rgba)
-    : streamer_(streamer) {
-  int wayland_fd = fcntl(wayland_socket_fd, F_DUPFD_CLOEXEC, 3);
-  CHECK(wayland_fd != -1) << "Unable to dup server, errno " << errno;
-  close(wayland_socket_fd);
-  wayland_server_ = std::make_unique<wayland::WaylandServer>(
-      wayland_fd, wayland_frames_are_rgba);
-  wayland_server_->SetDisplayEventCallback([this](const DisplayEvent& event) {
+                               ScreenConnector& screen_connector)
+    : streamer_(streamer),
+      screen_connector_(screen_connector),
+      frame_repeater_([this]() { RepeatFramesPeriodically(); }) {
+  screen_connector_.SetCallback(GetScreenConnectorCallback());
+  screen_connector_.SetDisplayEventCallback([this](const DisplayEvent& event) {
     std::visit(
         [this](auto&& e) {
           using T = std::decay_t<decltype(e)>;
@@ -70,57 +66,95 @@ DisplayHandler::DisplayHandler(webrtc_streaming::Streamer& streamer,
         },
         event);
   });
-  wayland_server_->SetFrameCallback([this](
-                                        std::uint32_t display_number,       //
-                                        std::uint32_t frame_width,          //
-                                        std::uint32_t frame_height,         //
-                                        std::uint32_t frame_fourcc_format,  //
-                                        std::uint32_t frame_stride_bytes,   //
-                                        std::uint8_t* frame_pixels) {
-    auto buf = std::make_shared<CvdVideoFrameBuffer>(frame_width, frame_height);
-    if (frame_fourcc_format == DRM_FORMAT_ARGB8888 ||
-        frame_fourcc_format == DRM_FORMAT_XRGB8888) {
-      libyuv::ARGBToI420(frame_pixels, frame_stride_bytes, buf->DataY(),
-                         buf->StrideY(), buf->DataU(), buf->StrideU(),
-                         buf->DataV(), buf->StrideV(), frame_width,
-                         frame_height);
-    } else if (frame_fourcc_format == DRM_FORMAT_ABGR8888 ||
-               frame_fourcc_format == DRM_FORMAT_XBGR8888) {
-      libyuv::ABGRToI420(frame_pixels, frame_stride_bytes, buf->DataY(),
-                         buf->StrideY(), buf->DataU(), buf->StrideU(),
-                         buf->DataV(), buf->StrideV(), frame_width,
-                         frame_height);
-    } else {
-      LOG(ERROR) << "Unhandled frame format: " << frame_fourcc_format;
-      return;
-    }
+}
+
+DisplayHandler::~DisplayHandler() {
+  {
+    std::lock_guard lock(repeater_state_mutex_);
+    repeater_state_ = RepeaterState::STOPPED;
+    repeater_state_condvar_.notify_one();
+  }
+  frame_repeater_.join();
+}
+
+DisplayHandler::GenerateProcessedFrameCallback
+DisplayHandler::GetScreenConnectorCallback() {
+  // only to tell the producer how to create a ProcessedFrame to cache into the
+  // queue
+  DisplayHandler::GenerateProcessedFrameCallback callback =
+      [](std::uint32_t display_number, std::uint32_t frame_width,
+         std::uint32_t frame_height, std::uint32_t frame_fourcc_format,
+         std::uint32_t frame_stride_bytes, std::uint8_t* frame_pixels,
+         WebRtcScProcessedFrame& processed_frame) {
+        processed_frame.display_number_ = display_number;
+        processed_frame.buf_ =
+            std::make_unique<CvdVideoFrameBuffer>(frame_width, frame_height);
+        if (frame_fourcc_format == DRM_FORMAT_ARGB8888 ||
+            frame_fourcc_format == DRM_FORMAT_XRGB8888) {
+          libyuv::ARGBToI420(
+              frame_pixels, frame_stride_bytes, processed_frame.buf_->DataY(),
+              processed_frame.buf_->StrideY(), processed_frame.buf_->DataU(),
+              processed_frame.buf_->StrideU(), processed_frame.buf_->DataV(),
+              processed_frame.buf_->StrideV(), frame_width, frame_height);
+          processed_frame.is_success_ = true;
+        } else if (frame_fourcc_format == DRM_FORMAT_ABGR8888 ||
+                   frame_fourcc_format == DRM_FORMAT_XBGR8888) {
+          libyuv::ABGRToI420(
+              frame_pixels, frame_stride_bytes, processed_frame.buf_->DataY(),
+              processed_frame.buf_->StrideY(), processed_frame.buf_->DataU(),
+              processed_frame.buf_->StrideU(), processed_frame.buf_->DataV(),
+              processed_frame.buf_->StrideV(), frame_width, frame_height);
+          processed_frame.is_success_ = true;
+        } else {
+          processed_frame.is_success_ = false;
+        }
+      };
+  return callback;
+}
+
+[[noreturn]] void DisplayHandler::Loop() {
+  for (;;) {
+    auto processed_frame = screen_connector_.OnNextFrame();
 
+    std::shared_ptr<CvdVideoFrameBuffer> buffer =
+        std::move(processed_frame.buf_);
+
+    const uint32_t display_number = processed_frame.display_number_;
     {
-      std::lock_guard<std::mutex> lock(last_buffer_mutex_);
+      std::lock_guard<std::mutex> lock(last_buffers_mutex_);
       display_last_buffers_[display_number] =
-          std::static_pointer_cast<webrtc_streaming::VideoFrameBuffer>(buf);
+          std::make_shared<BufferInfo>(BufferInfo{
+              .last_sent_time_stamp = std::chrono::system_clock::now(),
+              .buffer =
+                  std::static_pointer_cast<webrtc_streaming::VideoFrameBuffer>(
+                      buffer),
+          });
     }
-
-    SendLastFrame(display_number);
-  });
+    if (processed_frame.is_success_) {
+      SendLastFrame(display_number);
+    }
+  }
 }
 
 void DisplayHandler::SendLastFrame(std::optional<uint32_t> display_number) {
-  std::map<uint32_t, std::shared_ptr<webrtc_streaming::VideoFrameBuffer>>
-      buffers;
+  std::map<uint32_t, std::shared_ptr<BufferInfo>> buffers;
   {
-    std::lock_guard<std::mutex> lock(last_buffer_mutex_);
+    std::lock_guard<std::mutex> lock(last_buffers_mutex_);
     if (display_number) {
       // Resend the last buffer for a single display.
       auto last_buffer_it = display_last_buffers_.find(*display_number);
       if (last_buffer_it == display_last_buffers_.end()) {
         return;
       }
-      auto& last_buffer = last_buffer_it->second;
+      auto& last_buffer_info = last_buffer_it->second;
+      if (!last_buffer_info) {
+        return;
+      }
+      auto& last_buffer = last_buffer_info->buffer;
       if (!last_buffer) {
         return;
       }
-      buffers[*display_number] = last_buffer;
+      buffers[*display_number] = last_buffer_info;
     } else {
       // Resend the last buffer for all displays.
       buffers = display_last_buffers_;
@@ -131,21 +165,85 @@ void DisplayHandler::SendLastFrame(std::optional<uint32_t> display_number) {
     // send any frame.
     return;
   }
-  {
-    // SendLastFrame can be called from multiple threads simultaneously, locking
-    // here avoids injecting frames with the timestamps in the wrong order.
-    std::lock_guard<std::mutex> lock(next_frame_mutex_);
-    int64_t time_stamp =
-        std::chrono::duration_cast<std::chrono::microseconds>(
-            std::chrono::system_clock::now().time_since_epoch())
-            .count();
-
-    for (const auto& [display_number, buffer] : buffers) {
-      auto it = display_sinks_.find(display_number);
-      if (it != display_sinks_.end()) {
-        it->second->OnFrame(buffer, time_stamp);
+  SendBuffers(buffers);
+}
+
+void DisplayHandler::SendBuffers(
+    std::map<uint32_t, std::shared_ptr<BufferInfo>> buffers) {
+  // SendBuffers can be called from multiple threads simultaneously, locking
+  // here avoids injecting frames with the timestamps in the wrong order and
+  // protects writing the BufferInfo timestamps.
+  std::lock_guard<std::mutex> lock(send_mutex_);
+  auto time_stamp = std::chrono::system_clock::now();
+  int64_t time_stamp_since_epoch =
+      std::chrono::duration_cast<std::chrono::microseconds>(
+          time_stamp.time_since_epoch())
+          .count();
+
+  for (const auto& [display_number, buffer_info] : buffers) {
+    auto it = display_sinks_.find(display_number);
+    if (it != display_sinks_.end()) {
+      it->second->OnFrame(buffer_info->buffer, time_stamp_since_epoch);
+      buffer_info->last_sent_time_stamp = time_stamp;
+    }
+  }
+}
+
+void DisplayHandler::RepeatFramesPeriodically() {
+  // SendBuffers can be called from multiple threads simultaneously, locking
+  // here avoids injecting frames with the timestamps in the wrong order and
+  // protects writing the BufferInfo timestamps.
+  const std::chrono::milliseconds kRepeatingInterval(20);
+  auto next_send = std::chrono::system_clock::now() + kRepeatingInterval;
+  std::unique_lock lock(repeater_state_mutex_);
+  while (repeater_state_ != RepeaterState::STOPPED) {
+    if (repeater_state_ == RepeaterState::REPEATING) {
+      repeater_state_condvar_.wait_until(lock, next_send);
+    } else {
+      repeater_state_condvar_.wait(lock);
+    }
+    if (repeater_state_ != RepeaterState::REPEATING) {
+      continue;
+    }
+
+    std::map<uint32_t, std::shared_ptr<BufferInfo>> buffers;
+    {
+      std::lock_guard last_buffers_lock(last_buffers_mutex_);
+      auto time_stamp = std::chrono::system_clock::now();
+
+      for (auto& [display_number, buffer_info] : display_last_buffers_) {
+        if (time_stamp >
+            buffer_info->last_sent_time_stamp + kRepeatingInterval) {
+          buffers[display_number] = buffer_info;
+        }
       }
     }
+    SendBuffers(buffers);
+    {
+      std::lock_guard last_buffers_lock(last_buffers_mutex_);
+      for (const auto& [_, buffer_info] : display_last_buffers_) {
+        next_send = std::min(
+            next_send, buffer_info->last_sent_time_stamp + kRepeatingInterval);
+      }
+    }
+  }
+}
+
+void DisplayHandler::AddDisplayClient() {
+  std::lock_guard lock(repeater_state_mutex_);
+  ++num_active_clients_;
+  if (num_active_clients_ == 1) {
+    repeater_state_ = RepeaterState::REPEATING;
+    repeater_state_condvar_.notify_one();
+  }
+}
+
+void DisplayHandler::RemoveDisplayClient() {
+  std::lock_guard lock(repeater_state_mutex_);
+  --num_active_clients_;
+  if (num_active_clients_ == 0) {
+    repeater_state_ = RepeaterState::PAUSED;
+    repeater_state_condvar_.notify_one();
   }
 }
 
diff --git a/host/frontend/webrtc/display_handler.h b/host/frontend/webrtc/display_handler.h
index 8df888ec7..334a0ae2c 100644
--- a/host/frontend/webrtc/display_handler.h
+++ b/host/frontend/webrtc/display_handler.h
@@ -16,17 +16,37 @@
 
 #pragma once
 
-#include <map>
+#include <chrono>
 #include <memory>
 #include <mutex>
 #include <optional>
-#include <vector>
+#include <thread>
 
 #include "host/frontend/webrtc/cvd_video_frame_buffer.h"
 #include "host/frontend/webrtc/libdevice/video_sink.h"
-#include "host/libs/wayland/wayland_server.h"
+#include "host/libs/screen_connector/screen_connector.h"
 
 namespace cuttlefish {
+/**
+ * ScreenConnectorImpl will generate this, and enqueue
+ *
+ * It's basically a (processed) frame, so it:
+ *   must be efficiently std::move-able
+ * Also, for the sake of algorithm simplicity:
+ *   must be default-constructable & assignable
+ *
+ */
+struct WebRtcScProcessedFrame : public ScreenConnectorFrameInfo {
+  // must support move semantic
+  std::unique_ptr<CvdVideoFrameBuffer> buf_;
+  std::unique_ptr<WebRtcScProcessedFrame> Clone() {
+    // copy internal buffer, not move
+    CvdVideoFrameBuffer* new_buffer = new CvdVideoFrameBuffer(*(buf_.get()));
+    auto cloned_frame = std::make_unique<WebRtcScProcessedFrame>();
+    cloned_frame->buf_ = std::unique_ptr<CvdVideoFrameBuffer>(new_buffer);
+    return cloned_frame;
+  }
+};
 
 namespace webrtc_streaming {
 class Streamer;
@@ -34,21 +54,49 @@ class Streamer;
 
 class DisplayHandler {
  public:
-  DisplayHandler(webrtc_streaming::Streamer& streamer, int wayland_socket_fd,
-                 bool wayland_frames_are_rgba);
-  ~DisplayHandler() = default;
+  using ScreenConnector = cuttlefish::ScreenConnector<WebRtcScProcessedFrame>;
+  using GenerateProcessedFrameCallback =
+      ScreenConnector::GenerateProcessedFrameCallback;
+  using WebRtcScProcessedFrame = cuttlefish::WebRtcScProcessedFrame;
+
+  DisplayHandler(webrtc_streaming::Streamer& streamer,
+                 ScreenConnector& screen_connector);
+  ~DisplayHandler();
+
+  [[noreturn]] void Loop();
 
   // If std::nullopt, send last frame for all displays.
   void SendLastFrame(std::optional<uint32_t> display_number);
 
+  void AddDisplayClient();
+  void RemoveDisplayClient();
+
  private:
-  std::unique_ptr<wayland::WaylandServer> wayland_server_;
+  struct BufferInfo {
+    std::chrono::system_clock::time_point last_sent_time_stamp;
+    std::shared_ptr<webrtc_streaming::VideoFrameBuffer> buffer;
+  };
+  enum class RepeaterState: int {
+    PAUSED = 0,
+    REPEATING = 1,
+    STOPPED = 2,
+  };
+
+  GenerateProcessedFrameCallback GetScreenConnectorCallback();
+  void SendBuffers(std::map<uint32_t, std::shared_ptr<BufferInfo>> buffers);
+  void RepeatFramesPeriodically();
+
   std::map<uint32_t, std::shared_ptr<webrtc_streaming::VideoSink>>
       display_sinks_;
   webrtc_streaming::Streamer& streamer_;
-  std::map<uint32_t, std::shared_ptr<webrtc_streaming::VideoFrameBuffer>>
-      display_last_buffers_;
-  std::mutex last_buffer_mutex_;
-  std::mutex next_frame_mutex_;
+  ScreenConnector& screen_connector_;
+  std::map<uint32_t, std::shared_ptr<BufferInfo>> display_last_buffers_;
+  std::mutex last_buffers_mutex_;
+  std::mutex send_mutex_;
+  std::thread frame_repeater_;
+  RepeaterState repeater_state_ = RepeaterState::PAUSED;
+  int num_active_clients_ = 0;
+  std::mutex repeater_state_mutex_;
+  std::condition_variable repeater_state_condvar_;
 };
 }  // namespace cuttlefish
diff --git a/host/frontend/webrtc/gpx_locations_handler.cpp b/host/frontend/webrtc/gpx_locations_handler.cpp
index 7fb2fdbed..c8f607722 100644
--- a/host/frontend/webrtc/gpx_locations_handler.cpp
+++ b/host/frontend/webrtc/gpx_locations_handler.cpp
@@ -15,21 +15,19 @@
  */
 
 #include "host/frontend/webrtc/gpx_locations_handler.h"
-#include <android-base/logging.h>
+
 #include <unistd.h>
+
+#include <iostream>
+#include <string>
+
+#include <android-base/logging.h>
+
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/location/GnssClient.h"
 #include "host/libs/location/GpxParser.h"
-#include "string.h"
-
-#include <chrono>
-#include <iostream>
-#include <sstream>
-#include <thread>
-#include <vector>
 
-namespace cuttlefish {
-namespace webrtc_streaming {
+namespace cuttlefish::webrtc_streaming {
 
 GpxLocationsHandler::GpxLocationsHandler(
     std::function<void(const uint8_t *, size_t)> send_to_client) {}
@@ -53,17 +51,16 @@ void GpxLocationsHandler::HandleMessage(const uint8_t *msg, size_t len) {
     return;
   }
   auto instance = config->ForDefaultInstance();
-  auto server_port = instance.gnss_grpc_proxy_server_port();
   std::string socket_name =
-      std::string("localhost:") + std::to_string(server_port);
-  LOG(DEBUG) << "Server port: " << server_port << " socket: " << socket_name
-             << std::endl;
-
+      fmt::format("unix:{}.sock",
+                  instance.PerInstanceGrpcSocketPath("GnssGrpcProxyServer"));
   GnssClient gpsclient(
       grpc::CreateChannel(socket_name, grpc::InsecureChannelCredentials()));
 
-  auto reply = gpsclient.SendGpsLocations(1000,coordinates);
+  Result<void> reply = gpsclient.SendGpsLocations(1000, coordinates);
+  if (!reply.ok()) {
+    LOG(ERROR) << reply.error().FormatForEnv();
+  }
 }
 
-}  // namespace webrtc_streaming
-}  // namespace cuttlefish
+}  // namespace cuttlefish::webrtc_streaming
diff --git a/host/frontend/webrtc/html_client/client.html b/host/frontend/webrtc/html_client/client.html
index e6ab8f0f7..7cd1d472e 100644
--- a/host/frontend/webrtc/html_client/client.html
+++ b/host/frontend/webrtc/html_client/client.html
@@ -49,7 +49,7 @@
             <button id='volume_off_btn' title='Volume off' class='material-icons'>volume_off</button>
             <button id='camera_off_btn' title='Capture camera' class='material-icons'>videocam_off</button>
             <button id='record_video_btn' title='Record screen' class='material-icons'>movie_creation</button>
-            <button id='mic_btn' title='Microphone' disabled='true' class='material-icons'>mic</button>
+            <button id='mic_btn' title='Microphone' disabled='true' class='material-icons'>mic_off</button>
             <button id='location-modal-button' title='location console' class='material-icons'>location_on</button>
             <button id='device-details-button' title='Device Details' class='material-icons'>info</button>
             <button id='rotation-modal-button' title='Rotation sensors' class='material-icons'>more_vert</button>
diff --git a/host/frontend/webrtc/html_client/js/app.js b/host/frontend/webrtc/html_client/js/app.js
index 5cdb2f093..52c37872e 100644
--- a/host/frontend/webrtc/html_client/js/app.js
+++ b/host/frontend/webrtc/html_client/js/app.js
@@ -1048,7 +1048,9 @@ class DeviceControlApp {
       return;
     }
     this.#micActive = nextState;
-    this.#deviceConnection.useMic(nextState);
+    this.#deviceConnection.useMic(nextState,
+      () => document.querySelector('#mic_btn').innerHTML = 'mic',
+      () => document.querySelector('#mic_btn').innerHTML = 'mic_off');
   }
 
   #onCameraCaptureToggle(enabled) {
diff --git a/host/frontend/webrtc/html_client/js/cf_webrtc.js b/host/frontend/webrtc/html_client/js/cf_webrtc.js
index 702cd6297..1be5c846c 100644
--- a/host/frontend/webrtc/html_client/js/cf_webrtc.js
+++ b/host/frontend/webrtc/html_client/js/cf_webrtc.js
@@ -331,8 +331,8 @@ class DeviceConnection {
     this.#controlChannel.send(msg);
   }
 
-  async #useDevice(
-      in_use, senders_arr, device_opt, requestedFn = () => {in_use}, enabledFn = (stream) => {}) {
+  async #useDevice(in_use, senders_arr, device_opt, requestedFn = () => {in_use},
+      enabledFn = (stream) => {}, disabledFn = () => {}) {
     // An empty array means no tracks are currently in use
     if (senders_arr.length > 0 === !!in_use) {
       return in_use;
@@ -368,6 +368,7 @@ class DeviceConnection {
       }
       // Empty the array passed by reference, just assigning [] won't do that.
       senders_arr.length = 0;
+      disabledFn();
     }
     if (renegotiation_needed) {
       await this.#control.renegotiateConnection();
@@ -376,14 +377,18 @@ class DeviceConnection {
     return senders_arr.length > 0;
   }
 
-  async useMic(in_use) {
+  // enabledFn: a callback function that will be called if the mic is successfully enabled.
+  // disabledFn: a callback function that will be called if the mic is successfully disabled.
+  async useMic(in_use, enabledFn = () => {}, disabledFn = () => {}) {
     if (this.#micRequested == !!in_use) {
       return in_use;
     }
     this.#micRequested = !!in_use;
     return this.#useDevice(
         in_use, this.#micSenders, {audio: true, video: false},
-        () => this.#micRequested);
+        () => this.#micRequested,
+        enabledFn,
+        disabledFn);
   }
 
   async useCamera(in_use) {
diff --git a/host/frontend/webrtc/kernel_log_events_handler.cpp b/host/frontend/webrtc/kernel_log_events_handler.cpp
index 7bd8e5a9f..f03a7b2dc 100644
--- a/host/frontend/webrtc/kernel_log_events_handler.cpp
+++ b/host/frontend/webrtc/kernel_log_events_handler.cpp
@@ -62,34 +62,37 @@ void KernelLogEventsHandler::ReadLoop() {
       }
     }
     if (read_set.IsSet(kernel_log_fd_)) {
-      std::optional<monitor::ReadEventResult> read_result =
+      Result<std::optional<monitor::ReadEventResult>> read_result =
           monitor::ReadEvent(kernel_log_fd_);
       if (!read_result) {
         LOG(ERROR) << "Failed to read kernel log event: "
-                   << kernel_log_fd_->StrError();
+                   << read_result.error().FormatForEnv();
+        break;
+      } else if (!(*read_result)) {
+        LOG(ERROR) << "EOF from kernel_log_monitor";
         break;
       }
 
-      if (read_result->event == monitor::Event::BootStarted) {
+      if ((*read_result)->event == monitor::Event::BootStarted) {
         Json::Value message;
         message["event"] = kBootStartedMessage;
         DeliverEvent(message);
       }
-      if (read_result->event == monitor::Event::BootCompleted) {
+      if ((*read_result)->event == monitor::Event::BootCompleted) {
         Json::Value message;
         message["event"] = kBootCompletedMessage;
         DeliverEvent(message);
       }
-      if (read_result->event == monitor::Event::ScreenChanged) {
+      if ((*read_result)->event == monitor::Event::ScreenChanged) {
         Json::Value message;
         message["event"] = kScreenChangedMessage;
-        message["metadata"] = read_result->metadata;
+        message["metadata"] = (*read_result)->metadata;
         DeliverEvent(message);
       }
-      if (read_result->event == monitor::Event::DisplayPowerModeChanged) {
+      if ((*read_result)->event == monitor::Event::DisplayPowerModeChanged) {
         Json::Value message;
         message["event"] = kDisplayPowerModeChangedMessage;
-        message["metadata"] = read_result->metadata;
+        message["metadata"] = (*read_result)->metadata;
         DeliverEvent(message);
       }
     }
diff --git a/host/frontend/webrtc/kml_locations_handler.cpp b/host/frontend/webrtc/kml_locations_handler.cpp
index a181b848b..e2537571e 100644
--- a/host/frontend/webrtc/kml_locations_handler.cpp
+++ b/host/frontend/webrtc/kml_locations_handler.cpp
@@ -15,21 +15,19 @@
  */
 
 #include "host/frontend/webrtc/kml_locations_handler.h"
-#include <android-base/logging.h>
+
 #include <unistd.h>
+
+#include <iostream>
+#include <string>
+
+#include <android-base/logging.h>
+
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/location/GnssClient.h"
 #include "host/libs/location/KmlParser.h"
-#include "string.h"
 
-#include <chrono>
-#include <iostream>
-#include <sstream>
-#include <thread>
-#include <vector>
-
-namespace cuttlefish {
-namespace webrtc_streaming {
+namespace cuttlefish::webrtc_streaming {
 
 KmlLocationsHandler::KmlLocationsHandler(
     std::function<void(const uint8_t *, size_t)> send_to_client) {}
@@ -53,19 +51,16 @@ void KmlLocationsHandler::HandleMessage(const uint8_t *msg, size_t len) {
     return;
   }
   auto instance = config->ForDefaultInstance();
-  auto server_port = instance.gnss_grpc_proxy_server_port();
   std::string socket_name =
-      std::string("localhost:") + std::to_string(server_port);
-  LOG(DEBUG) << "Server port: " << server_port << " socket: " << socket_name
-             << std::endl;
-
-
+      fmt::format("unix:{}.sock",
+                  instance.PerInstanceGrpcSocketPath("GnssGrpcProxyServer"));
   GnssClient gpsclient(
       grpc::CreateChannel(socket_name, grpc::InsecureChannelCredentials()));
 
-
-  auto reply = gpsclient.SendGpsLocations(1000,coordinates);
+  Result<void> reply = gpsclient.SendGpsLocations(1000, coordinates);
+  if (!reply.ok()) {
+    LOG(ERROR) << reply.error().FormatForEnv();
+  }
 }
 
-}  // namespace webrtc_streaming
-}  // namespace cuttlefish
+}  // namespace cuttlefish::webrtc_streaming
diff --git a/host/frontend/webrtc/libdevice/Android.bp b/host/frontend/webrtc/libdevice/Android.bp
index 9ec8d3ee6..bb928496c 100644
--- a/host/frontend/webrtc/libdevice/Android.bp
+++ b/host/frontend/webrtc/libdevice/Android.bp
@@ -46,6 +46,7 @@ cc_library {
     static_libs: [
         "libsrtp2",
         "libcuttlefish_host_config",
+        "libcuttlefish_screen_connector",
         "libcuttlefish_wayland_server",
         "libcuttlefish_webrtc_common",
         "libgflags",
diff --git a/host/frontend/webrtc/libdevice/camera_streamer.cpp b/host/frontend/webrtc/libdevice/camera_streamer.cpp
index bd7acce2c..78650fd37 100644
--- a/host/frontend/webrtc/libdevice/camera_streamer.cpp
+++ b/host/frontend/webrtc/libdevice/camera_streamer.cpp
@@ -34,7 +34,8 @@ CameraStreamer::~CameraStreamer() { Disconnect(); }
 // We are getting frames from the client so try forwarding those to the CVD
 void CameraStreamer::OnFrame(const webrtc::VideoFrame& client_frame) {
   std::lock_guard<std::mutex> lock(onframe_mutex_);
-  if (!cvd_connection_.IsConnected() && !pending_connection_.valid()) {
+  if (!cvd_connection_.IsConnected_Unguarded() &&
+      !pending_connection_.valid()) {
     // Start new connection
     pending_connection_ =
         cvd_connection_.ConnectAsync(port_, cid_, vhost_user_);
diff --git a/host/frontend/webrtc/libdevice/streamer.cpp b/host/frontend/webrtc/libdevice/streamer.cpp
index e4daf1d14..b07a70840 100644
--- a/host/frontend/webrtc/libdevice/streamer.cpp
+++ b/host/frontend/webrtc/libdevice/streamer.cpp
@@ -60,6 +60,7 @@ constexpr auto kAudioStreamsField = "audio_streams";
 constexpr auto kHardwareField = "hardware";
 constexpr auto kOpenwrtDeviceIdField = "openwrt_device_id";
 constexpr auto kOpenwrtAddrField = "openwrt_addr";
+constexpr auto kAdbPortField = "adb_port";
 constexpr auto kControlEnvProxyServerPathField =
     "control_env_proxy_server_path";
 constexpr auto kControlPanelButtonCommand = "command";
@@ -452,6 +453,7 @@ void Streamer::Impl::OnOpen() {
     device_info[kHardwareField] = hardware;
     device_info[kOpenwrtDeviceIdField] = config_.openwrt_device_id;
     device_info[kOpenwrtAddrField] = config_.openwrt_addr;
+    device_info[kAdbPortField] = config_.adb_port;
     device_info[kControlEnvProxyServerPathField] =
         config_.control_env_proxy_server_path;
     Json::Value custom_control_panel_buttons(Json::arrayValue);
diff --git a/host/frontend/webrtc/libdevice/streamer.h b/host/frontend/webrtc/libdevice/streamer.h
index a0c50c8c1..d153f2943 100644
--- a/host/frontend/webrtc/libdevice/streamer.h
+++ b/host/frontend/webrtc/libdevice/streamer.h
@@ -57,6 +57,8 @@ struct StreamerConfig {
   std::string openwrt_device_id;
   // Openwrt IP address for accessing Luci interface.
   std::string openwrt_addr;
+  // Adb port number of the device.
+  int adb_port;
   // Path of ControlEnvProxyServer for serving Rest API in WebUI.
   std::string control_env_proxy_server_path;
 };
diff --git a/host/frontend/webrtc/location_handler.cpp b/host/frontend/webrtc/location_handler.cpp
index 10557b1d6..30aa69f7e 100644
--- a/host/frontend/webrtc/location_handler.cpp
+++ b/host/frontend/webrtc/location_handler.cpp
@@ -15,17 +15,16 @@
  */
 
 #include "host/frontend/webrtc/location_handler.h"
-#include <android-base/logging.h>
+
 #include <unistd.h>
+
+#include <android-base/logging.h>
+#include <fmt/format.h>
+
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/location/GnssClient.h"
 
-#include <sstream>
-#include <vector>
-using namespace std;
-
-namespace cuttlefish {
-namespace webrtc_streaming {
+namespace cuttlefish::webrtc_streaming {
 
 LocationHandler::LocationHandler(
     std::function<void(const uint8_t *, size_t)> send_to_client) {}
@@ -41,23 +40,24 @@ void LocationHandler::HandleMessage(const float longitude,
     return;
   }
   auto instance = config->ForDefaultInstance();
-  auto server_port = instance.gnss_grpc_proxy_server_port();
   std::string socket_name =
-      std::string("localhost:") + std::to_string(server_port);
+      fmt::format("unix:{}.sock",
+                  instance.PerInstanceGrpcSocketPath("GnssGrpcProxyServer"));
   GnssClient gpsclient(
       grpc::CreateChannel(socket_name, grpc::InsecureChannelCredentials()));
 
-  GpsFixArray coordinates;
   GpsFix location;
-  location.longitude=longitude;
-  location.latitude=latitude;
-  location.elevation=elevation;
+  location.longitude = longitude;
+  location.latitude = latitude;
+  location.elevation = elevation;
+
+  GpsFixArray coordinates;
   coordinates.push_back(location);
 
-  auto reply = gpsclient.SendGpsLocations(1000,coordinates);
-  LOG(INFO) << "Server port: " << server_port << " socket: " << socket_name
-            << std::endl;
+  Result<void> reply = gpsclient.SendGpsLocations(1000, coordinates);
+  if (!reply.ok()) {
+    LOG(ERROR) << reply.error().FormatForEnv();
+  }
 }
 
-}  // namespace webrtc_streaming
-}  // namespace cuttlefish
+}  // namespace cuttlefish::webrtc_streaming
diff --git a/host/frontend/webrtc/main.cpp b/host/frontend/webrtc/main.cpp
index 8136a7cb8..b60333455 100644
--- a/host/frontend/webrtc/main.cpp
+++ b/host/frontend/webrtc/main.cpp
@@ -23,7 +23,6 @@
 #include <gflags/gflags.h>
 #include <libyuv.h>
 
-#include "common/libs/fs/shared_buf.h"
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/files.h"
 #include "host/frontend/webrtc/audio_handler.h"
@@ -40,7 +39,10 @@
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/logging.h"
 #include "host/libs/config/openwrt_args.h"
+#include "host/libs/confui/host_mode_ctrl.h"
+#include "host/libs/confui/host_server.h"
 #include "host/libs/input_connector/socket_input_connector.h"
+#include "host/libs/screen_connector/screen_connector.h"
 
 DEFINE_bool(multitouch, true,
             "Whether to send multi-touch or single-touch events");
@@ -110,6 +112,27 @@ fruit::Component<cuttlefish::CustomActionConfigProvider> WebRtcComponent() {
       .install(cuttlefish::CustomActionsComponent);
 };
 
+fruit::Component<
+    cuttlefish::ScreenConnector<DisplayHandler::WebRtcScProcessedFrame>,
+    cuttlefish::confui::HostServer, cuttlefish::confui::HostVirtualInput>
+CreateConfirmationUIComponent(
+    int* frames_fd, bool* frames_are_rgba,
+    cuttlefish::confui::PipeConnectionPair* pipe_io_pair,
+    cuttlefish::InputConnector* input_connector) {
+  using cuttlefish::ScreenConnectorFrameRenderer;
+  using ScreenConnector = cuttlefish::DisplayHandler::ScreenConnector;
+  return fruit::createComponent()
+      .bindInstance<
+          fruit::Annotated<cuttlefish::WaylandScreenConnector::FramesFd, int>>(
+          *frames_fd)
+      .bindInstance<fruit::Annotated<
+          cuttlefish::WaylandScreenConnector::FramesAreRgba, bool>>(
+          *frames_are_rgba)
+      .bindInstance(*pipe_io_pair)
+      .bind<ScreenConnectorFrameRenderer, ScreenConnector>()
+      .bindInstance(*input_connector);
+}
+
 int main(int argc, char** argv) {
   cuttlefish::DefaultSubprocessLogging(argv);
   ::gflags::ParseCommandLineFlags(&argc, &argv, true);
@@ -165,8 +188,30 @@ int main(int argc, char** argv) {
       cuttlefish::SharedFD::Dup(FLAGS_kernel_log_events_fd);
   close(FLAGS_kernel_log_events_fd);
 
+  cuttlefish::confui::PipeConnectionPair conf_ui_comm_fd_pair{
+      .from_guest_ = cuttlefish::SharedFD::Dup(FLAGS_confui_out_fd),
+      .to_guest_ = cuttlefish::SharedFD::Dup(FLAGS_confui_in_fd)};
+  close(FLAGS_confui_in_fd);
+  close(FLAGS_confui_out_fd);
+
+  int frames_fd = FLAGS_frame_server_fd;
+  bool frames_are_rgba = true;
+  fruit::Injector<
+      cuttlefish::ScreenConnector<DisplayHandler::WebRtcScProcessedFrame>,
+      cuttlefish::confui::HostServer, cuttlefish::confui::HostVirtualInput>
+      conf_ui_components_injector(CreateConfirmationUIComponent,
+                                  std::addressof(frames_fd),
+                                  std::addressof(frames_are_rgba),
+                                  &conf_ui_comm_fd_pair, input_connector.get());
+  auto& screen_connector =
+      conf_ui_components_injector.get<DisplayHandler::ScreenConnector&>();
+
   auto client_server = cuttlefish::ClientFilesServer::New(FLAGS_client_dir);
   CHECK(client_server) << "Failed to initialize client files server";
+  auto& host_confui_server =
+      conf_ui_components_injector.get<cuttlefish::confui::HostServer&>();
+  auto& confui_virtual_input =
+      conf_ui_components_injector.get<cuttlefish::confui::HostVirtualInput&>();
 
   StreamerConfig streamer_config;
 
@@ -179,6 +224,7 @@ int main(int argc, char** argv) {
       cvd_config->Instances()[0].webrtc_device_id();
   streamer_config.openwrt_addr = OpenwrtArgsFromConfig(
       cvd_config->Instances()[0])[kOpewnrtWanIpAddressName];
+  streamer_config.adb_port = instance.adb_host_port();
   streamer_config.control_env_proxy_server_path =
       instance.grpc_socket_path() + "/ControlEnvProxyServer.sock";
   streamer_config.operator_server.addr = cvd_config->sig_server_address();
@@ -206,7 +252,7 @@ int main(int argc, char** argv) {
   }
 
   auto observer_factory = std::make_shared<CfConnectionObserverFactory>(
-      *input_connector.get(), &kernel_logs_event_handler, lights_observer);
+      confui_virtual_input, &kernel_logs_event_handler, lights_observer);
 
   RecordingManager recording_manager;
 
@@ -214,10 +260,8 @@ int main(int argc, char** argv) {
       Streamer::Create(streamer_config, recording_manager, observer_factory);
   CHECK(streamer) << "Could not create streamer";
 
-  int frames_fd = FLAGS_frame_server_fd;
-  bool frames_are_rgba = !instance.guest_uses_bgra_framebuffers();
   auto display_handler =
-      std::make_shared<DisplayHandler>(*streamer, frames_fd, frames_are_rgba);
+      std::make_shared<DisplayHandler>(*streamer, screen_connector);
 
   if (instance.camera_server_port()) {
     auto camera_controller = streamer->AddCamera(instance.camera_server_port(),
@@ -363,6 +407,7 @@ int main(int argc, char** argv) {
   if (audio_handler) {
     audio_handler->Start();
   }
+  host_confui_server.Start();
 
   if (instance.record_screen()) {
     LOG(VERBOSE) << "Waiting for recording manager initializing.";
@@ -370,7 +415,7 @@ int main(int argc, char** argv) {
     recording_manager.Start();
   }
 
-  control_thread.join();
+  display_handler->Loop();
 
   return 0;
 }
diff --git a/host/libs/avb/avb.cpp b/host/libs/avb/avb.cpp
index 6ffa0aba6..4a5f420f1 100644
--- a/host/libs/avb/avb.cpp
+++ b/host/libs/avb/avb.cpp
@@ -70,7 +70,7 @@ Command Avb::GenerateAddHashFooter(const std::string& image_path,
   command.AddParameter(partition_name);
   command.AddParameter("--partition_size");
   command.AddParameter(partition_size_bytes);
-  return std::move(command);
+  return command;
 }
 
 Result<void> Avb::AddHashFooter(const std::string& image_path,
@@ -177,4 +177,4 @@ fruit::Component<Avb> CuttlefishKeyAvbComponent() {
       []() -> Avb* { return GetDefaultAvb().release(); });
 }
 
-} // namespace cuttlefish
\ No newline at end of file
+}  // namespace cuttlefish
diff --git a/host/libs/command_util/snapshot_utils.cc b/host/libs/command_util/snapshot_utils.cc
index 4161ee8a4..ccb427a29 100644
--- a/host/libs/command_util/snapshot_utils.cc
+++ b/host/libs/command_util/snapshot_utils.cc
@@ -70,10 +70,6 @@ Result<void> CopyDirectoryImpl(
     if (!predicate(src_dir_path + "/" + src_base_path)) {
       continue;
     }
-    if (src_base_path == "." || src_base_path == "..") {
-      LOG(DEBUG) << "Skipping \"" << src_base_path << "\"";
-      continue;
-    }
     std::string src_path = src_dir_path + "/" + src_base_path;
     std::string dest_path = dest_dir_path + "/" + src_base_path;
 
diff --git a/host/libs/command_util/util.cc b/host/libs/command_util/util.cc
index 561bdd8d9..bedcba541 100644
--- a/host/libs/command_util/util.cc
+++ b/host/libs/command_util/util.cc
@@ -19,6 +19,7 @@
 #include "sys/time.h"
 #include "sys/types.h"
 
+#include <optional>
 #include <string>
 
 #include "common/libs/fs/shared_buf.h"
@@ -52,12 +53,17 @@ static Result<void> WriteAllBinaryResult(const SharedFD& fd, const T* t) {
   return {};
 }
 
+// Rerturns true if something was read, false if the file descriptor reached
+// EOF.
 template <typename T>
-static Result<void> ReadExactBinaryResult(const SharedFD& fd, T* t) {
+static Result<bool> ReadExactBinaryResult(const SharedFD& fd, T* t) {
   ssize_t n = ReadExactBinary(fd, t);
+  if (n == 0) {
+    return false;
+  }
   CF_EXPECTF(n > 0, "Read error: {}", fd->StrError());
   CF_EXPECT(n == sizeof(*t), "Unexpected EOF on read");
-  return {};
+  return true;
 }
 
 }  // namespace
@@ -90,10 +96,13 @@ Result<SharedFD> GetLauncherMonitor(const CuttlefishConfig& config,
   return GetLauncherMonitorFromInstance(instance_config, timeout_seconds);
 }
 
-Result<LauncherActionInfo> ReadLauncherActionFromFd(SharedFD monitor_socket) {
+Result<std::optional<LauncherActionInfo>> ReadLauncherActionFromFd(SharedFD monitor_socket) {
   LauncherAction action;
-  CF_EXPECT(ReadExactBinaryResult(monitor_socket, &action),
+  auto read_something = CF_EXPECT(ReadExactBinaryResult(monitor_socket, &action),
             "Error reading LauncherAction");
+  if (!read_something) {
+    return std::nullopt;
+  }
   if (IsShortAction(action)) {
     return LauncherActionInfo{
         .action = action,
diff --git a/host/libs/command_util/util.h b/host/libs/command_util/util.h
index 29406c8b2..775d4cd8b 100644
--- a/host/libs/command_util/util.h
+++ b/host/libs/command_util/util.h
@@ -16,6 +16,8 @@
 
 #pragma once
 
+#include <optional>
+
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/utils/result.h"
 #include "device/google/cuttlefish/host/libs/command_util/runner/run_cvd.pb.h"
@@ -38,7 +40,8 @@ struct LauncherActionInfo {
   LauncherAction action;
   run_cvd::ExtendedLauncherAction extended_action;
 };
-Result<LauncherActionInfo> ReadLauncherActionFromFd(SharedFD monitor_socket);
+Result<std::optional<LauncherActionInfo>> ReadLauncherActionFromFd(
+    SharedFD monitor_socket);
 
 Result<void> WaitForRead(SharedFD monitor_socket, const int timeout_seconds);
 
diff --git a/host/libs/config/Android.bp b/host/libs/config/Android.bp
index 974d8f9d7..4cb036feb 100644
--- a/host/libs/config/Android.bp
+++ b/host/libs/config/Android.bp
@@ -20,8 +20,6 @@ package {
 cc_library {
     name: "libcuttlefish_host_config",
     srcs: [
-        "display.cpp",
-        "touchpad.cpp",
         "config_flag.cpp",
         "config_utils.cpp",
         "custom_actions.cpp",
@@ -29,21 +27,24 @@ cc_library {
         "cuttlefish_config_environment.cpp",
         "cuttlefish_config_instance.cpp",
         "data_image.cpp",
+        "display.cpp",
         "esp.cpp",
         "feature.cpp",
         "fetcher_config.cpp",
         "host_tools_version.cpp",
+        "instance_nums.cpp",
         "kernel_args.cpp",
         "known_paths.cpp",
-        "instance_nums.cpp",
         "logging.cpp",
         "openwrt_args.cpp",
+        "secure_hals.cpp",
+        "touchpad.cpp",
     ],
     shared_libs: [
-        "libext2_blkid",
+        "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libbase",
+        "libext2_blkid",
         "libfruit",
         "libgflags",
         "libjsoncpp",
diff --git a/host/libs/config/command_source.h b/host/libs/config/command_source.h
index a5feb1de8..bead72ff2 100644
--- a/host/libs/config/command_source.h
+++ b/host/libs/config/command_source.h
@@ -30,12 +30,9 @@ namespace cuttlefish {
 struct MonitorCommand {
   Command command;
   bool is_critical;
-  bool can_sandbox;
 
   MonitorCommand(Command command, bool is_critical = false)
-      : command(std::move(command)),
-        is_critical(is_critical),
-        can_sandbox(false) {}
+      : command(std::move(command)), is_critical(is_critical) {}
 };
 
 class CommandSource : public virtual SetupFeature {
diff --git a/host/libs/config/config_constants.h b/host/libs/config/config_constants.h
index c0b8bfb34..a26e4f703 100644
--- a/host/libs/config/config_constants.h
+++ b/host/libs/config/config_constants.h
@@ -41,6 +41,8 @@ inline constexpr char kAdbdStartedMessage[] =
     "init: starting service 'adbd'...";
 inline constexpr char kFastbootdStartedMessage[] =
     "init: starting service 'fastbootd'...";
+inline constexpr char kHibernationExitMessage[] =
+    "PM: hibernation: hibernation exit";
 inline constexpr char kFastbootStartedMessage[] =
     "Listening for fastboot command on tcp";
 inline constexpr char kScreenChangedMessage[] = "VIRTUAL_DEVICE_SCREEN_CHANGED";
diff --git a/host/libs/config/config_utils.cpp b/host/libs/config/config_utils.cpp
index c4fea49cc..ba22ed381 100644
--- a/host/libs/config/config_utils.cpp
+++ b/host/libs/config/config_utils.cpp
@@ -26,8 +26,9 @@
 
 #include "common/libs/utils/contains.h"
 #include "common/libs/utils/environment.h"
+#include "common/libs/utils/in_sandbox.h"
+#include "common/libs/utils/subprocess.h"
 #include "host/libs/config/config_constants.h"
-#include "host/libs/config/cuttlefish_config.h"
 
 namespace cuttlefish {
 
@@ -92,7 +93,6 @@ std::string ForCurrentInstance(const char* prefix) {
   stream << prefix << std::setfill('0') << std::setw(2) << GetInstance();
   return stream.str();
 }
-int ForCurrentInstance(int base) { return base + GetInstance() - 1; }
 
 std::string RandomSerialNumber(const std::string& prefix) {
   const char hex_characters[] = "0123456789ABCDEF";
@@ -153,11 +153,17 @@ std::string DefaultGuestImagePath(const std::string& file_name) {
          file_name;
 }
 
+// In practice this is mostly validating that the `cuttlefish-base` debian
+// package is installed, which implies that more things are present like the
+// predefined network setup.
 bool HostSupportsQemuCli() {
   static bool supported =
 #ifdef __linux__
-      std::system(
-          "/usr/lib/cuttlefish-common/bin/capability_query.py qemu_cli") == 0;
+      InSandbox() ||
+      RunWithManagedStdio(
+          Command("/usr/lib/cuttlefish-common/bin/capability_query.py")
+              .AddParameter("qemu_cli"),
+          nullptr, nullptr, nullptr) == 0;
 #else
       true;
 #endif
diff --git a/host/libs/config/config_utils.h b/host/libs/config/config_utils.h
index aeb30f937..ee0b830ed 100644
--- a/host/libs/config/config_utils.h
+++ b/host/libs/config/config_utils.h
@@ -36,11 +36,10 @@ int GetVsockServerPort(const int base,
 // it easily discoverable regardless of what vm manager is in use
 std::string GetGlobalConfigFileLink();
 
-// These functions modify a given base value to make it different across
+// This function modifies a given base value to make it different across
 // different instances by appending the instance id in case of strings or adding
 // it in case of integers.
 std::string ForCurrentInstance(const char* prefix);
-int ForCurrentInstance(int base);
 
 int InstanceFromString(std::string instance_str);
 
diff --git a/host/libs/config/custom_actions.cpp b/host/libs/config/custom_actions.cpp
index 9254d57bb..207f5d181 100644
--- a/host/libs/config/custom_actions.cpp
+++ b/host/libs/config/custom_actions.cpp
@@ -176,11 +176,10 @@ std::string DefaultCustomActionConfig() {
     CHECK(directory_contents_result.ok())
         << directory_contents_result.error().FormatForEnv();
     auto custom_action_configs = std::move(*directory_contents_result);
-    // Two entries are always . and ..
-    if (custom_action_configs.size() > 3) {
+    if (custom_action_configs.size() > 1) {
       LOG(ERROR) << "Expected at most one custom action config in "
                  << custom_action_config_dir << ". Please delete extras.";
-    } else if (custom_action_configs.size() == 3) {
+    } else if (custom_action_configs.size() == 1) {
       for (const auto& config : custom_action_configs) {
         if (android::base::EndsWithIgnoreCase(config, ".json")) {
           return custom_action_config_dir + "/" + config;
diff --git a/host/libs/config/cuttlefish_config.cpp b/host/libs/config/cuttlefish_config.cpp
index ab11c98e2..6bc5d6564 100644
--- a/host/libs/config/cuttlefish_config.cpp
+++ b/host/libs/config/cuttlefish_config.cpp
@@ -127,41 +127,18 @@ void CuttlefishConfig::set_ap_vm_manager(const std::string& name) {
   (*dictionary_)[kApVmManager] = name;
 }
 
-static SecureHal StringToSecureHal(std::string mode) {
-  std::transform(mode.begin(), mode.end(), mode.begin(), ::tolower);
-  std::unordered_map<std::string, SecureHal> mapping = {
-      {"keymint", SecureHal::HostKeymintSecure},
-      {"host_secure_keymint", SecureHal::HostKeymintSecure},
-      {"host_keymint_secure", SecureHal::HostKeymintSecure},
-      {"guest_gatekeeper_insecure", SecureHal::GuestGatekeeperInsecure},
-      {"guest_insecure_gatekeeper", SecureHal::GuestGatekeeperInsecure},
-      {"guest_insecure_keymint", SecureHal::GuestKeymintInsecure},
-      {"guest_keymint_insecure", SecureHal::GuestKeymintInsecure},
-      {"gatekeeper", SecureHal::HostGatekeeperSecure},
-      {"host_gatekeeper_secure", SecureHal::HostGatekeeperSecure},
-      {"host_secure_gatekeeper", SecureHal::HostGatekeeperSecure},
-      {"host_gatekeeper_insecure", SecureHal::HostGatekeeperInsecure},
-      {"host_insecure_gatekeeper", SecureHal::HostGatekeeperInsecure},
-      {"oemlock", SecureHal::HostOemlockSecure},
-      {"host_oemlock_secure", SecureHal::HostOemlockSecure},
-      {"host_secure_oemlock", SecureHal::HostOemlockSecure},
-  };
-  auto it = mapping.find(mode);
-  return it == mapping.end() ? SecureHal::Unknown : it->second;
-}
-
 static constexpr char kSecureHals[] = "secure_hals";
-std::set<SecureHal> CuttlefishConfig::secure_hals() const {
+Result<std::set<SecureHal>> CuttlefishConfig::secure_hals() const {
   std::set<SecureHal> args_set;
   for (auto& hal : (*dictionary_)[kSecureHals]) {
-    args_set.insert(StringToSecureHal(hal.asString()));
+    args_set.insert(CF_EXPECT(ParseSecureHal(hal.asString())));
   }
   return args_set;
 }
-void CuttlefishConfig::set_secure_hals(const std::set<std::string>& hals) {
+void CuttlefishConfig::set_secure_hals(const std::set<SecureHal>& hals) {
   Json::Value hals_json_obj(Json::arrayValue);
   for (const auto& hal : hals) {
-    hals_json_obj.append(hal);
+    hals_json_obj.append(ToString(hal));
   }
   (*dictionary_)[kSecureHals] = hals_json_obj;
 }
@@ -581,14 +558,6 @@ std::set<std::string> CuttlefishConfig::straced_host_executables() const {
   return straced_host_executables;
 }
 
-static constexpr char kHostSandbox[] = "host_sandbox";
-bool CuttlefishConfig::host_sandbox() const {
-  return (*dictionary_)[kHostSandbox].asBool();
-}
-void CuttlefishConfig::set_host_sandbox(bool host_sandbox) {
-  (*dictionary_)[kHostSandbox] = host_sandbox;
-}
-
 /*static*/ CuttlefishConfig* CuttlefishConfig::BuildConfigImpl(
     const std::string& path) {
   auto ret = new CuttlefishConfig();
@@ -676,18 +645,12 @@ std::string CuttlefishConfig::AssemblyPath(
   return AbsolutePath(assembly_dir() + "/" + file_name);
 }
 
+static constexpr char kInstancesUdsDir[] = "instances_uds_dir";
+void CuttlefishConfig::set_instances_uds_dir(const std::string& dir) {
+  (*dictionary_)[kInstancesUdsDir] = dir;
+}
 std::string CuttlefishConfig::instances_uds_dir() const {
-  // Try to use /tmp/cf_avd_{uid}/ for UDS directory.
-  // If it fails, use HOME directory(legacy) instead.
-
-  auto defaultPath = AbsolutePath("/tmp/cf_avd_" + std::to_string(getuid()));
-
-  if (!DirectoryExists(defaultPath) ||
-      CanAccess(defaultPath, R_OK | W_OK | X_OK)) {
-    return defaultPath;
-  }
-
-  return instances_dir();
+  return (*dictionary_)[kInstancesUdsDir].asString();
 }
 
 std::string CuttlefishConfig::InstancesUdsPath(
@@ -704,18 +667,12 @@ std::string CuttlefishConfig::EnvironmentsPath(
   return AbsolutePath(environments_dir() + "/" + file_name);
 }
 
+static constexpr char kEnvironmentsUdsDir[] = "environments_uds_dir";
+void CuttlefishConfig::set_environments_uds_dir(const std::string& dir) {
+  (*dictionary_)[kEnvironmentsUdsDir] = dir;
+}
 std::string CuttlefishConfig::environments_uds_dir() const {
-  // Try to use /tmp/cf_env_{uid}/ for UDS directory.
-  // If it fails, use HOME directory instead.
-
-  auto defaultPath = AbsolutePath("/tmp/cf_env_" + std::to_string(getuid()));
-
-  if (!DirectoryExists(defaultPath) ||
-      CanAccess(defaultPath, R_OK | W_OK | X_OK)) {
-    return defaultPath;
-  }
-
-  return environments_dir();
+  return (*dictionary_)[kEnvironmentsUdsDir].asString();
 }
 
 std::string CuttlefishConfig::EnvironmentsUdsPath(
diff --git a/host/libs/config/cuttlefish_config.h b/host/libs/config/cuttlefish_config.h
index 23d05f7b3..c28f337f8 100644
--- a/host/libs/config/cuttlefish_config.h
+++ b/host/libs/config/cuttlefish_config.h
@@ -33,6 +33,7 @@
 #include "host/libs/config/config_constants.h"
 #include "host/libs/config/config_fragment.h"
 #include "host/libs/config/config_utils.h"
+#include "host/libs/config/secure_hals.h"
 
 namespace Json {
 class Value;
@@ -40,18 +41,6 @@ class Value;
 
 namespace cuttlefish {
 
-enum class SecureHal {
-  Unknown,
-  GuestGatekeeperInsecure,
-  GuestKeymintInsecure,
-  HostKeymintInsecure,
-  HostKeymintSecure,
-  HostGatekeeperInsecure,
-  HostGatekeeperSecure,
-  HostOemlockInsecure,
-  HostOemlockSecure,
-};
-
 enum class VmmMode {
   kUnknown,
   kCrosvm,
@@ -102,12 +91,15 @@ class CuttlefishConfig {
   std::string assembly_dir() const;
   std::string AssemblyPath(const std::string&) const;
 
+  void set_instances_uds_dir(const std::string&);
   std::string instances_uds_dir() const;
   std::string InstancesUdsPath(const std::string&) const;
 
+  void set_environments_dir(const std::string&);
   std::string environments_dir() const;
   std::string EnvironmentsPath(const std::string&) const;
 
+  void set_environments_uds_dir(const std::string&);
   std::string environments_uds_dir() const;
   std::string EnvironmentsUdsPath(const std::string&) const;
 
@@ -133,8 +125,8 @@ class CuttlefishConfig {
     static TouchpadConfig Deserialize(const Json::Value& config_json);
   };
 
-  void set_secure_hals(const std::set<std::string>& hals);
-  std::set<SecureHal> secure_hals() const;
+  void set_secure_hals(const std::set<SecureHal>&);
+  Result<std::set<SecureHal>> secure_hals() const;
 
   void set_crosvm_binary(const std::string& crosvm_binary);
   std::string crosvm_binary() const;
@@ -283,9 +275,6 @@ class CuttlefishConfig {
   std::set<std::string> straced_host_executables() const;
   void set_straced_host_executables(const std::set<std::string>& executables);
 
-  bool host_sandbox() const;
-  void set_host_sandbox(bool host_sandbox);
-
   bool IsCrosvm() const;
 
   class InstanceSpecific;
@@ -554,6 +543,8 @@ class CuttlefishConfig {
 
     int cpus() const;
 
+    std::string vcpu_config_path() const;
+
     std::string data_policy() const;
 
     int blank_data_image_mb() const;
@@ -583,6 +574,7 @@ class CuttlefishConfig {
     bool mte() const;
     std::string boot_slot() const;
     bool fail_fast() const;
+    bool vhost_user_block() const;
 
     // Kernel and bootloader logging
     bool enable_kernel_log() const;
@@ -684,6 +676,8 @@ class CuttlefishConfig {
 
     std::string custom_partition_path() const;
 
+    std::string hibernation_partition_image() const;
+
     int blank_metadata_image_mb() const;
     int blank_sdcard_image_mb() const;
     std::string bootloader() const;
@@ -775,6 +769,7 @@ class CuttlefishConfig {
     void set_kgdb(bool kgdb);
     void set_target_arch(Arch target_arch);
     void set_cpus(int cpus);
+    void set_vcpu_config_path(const std::string& vcpu_config_path);
     void set_data_policy(const std::string& data_policy);
     void set_blank_data_image_mb(int blank_data_image_mb);
     void set_gdb_port(int gdb_port);
@@ -801,6 +796,7 @@ class CuttlefishConfig {
     void set_boot_slot(const std::string& boot_slot);
     void set_grpc_socket_path(const std::string& sockets);
     void set_fail_fast(bool fail_fast);
+    void set_vhost_user_block(bool qemu_vhost_user_block);
 
     // Kernel and bootloader logging
     void set_enable_kernel_log(bool enable_kernel_log);
@@ -902,6 +898,8 @@ class CuttlefishConfig {
     void set_bootconfig_supported(bool bootconfig_supported);
     void set_filename_encryption_mode(const std::string& userdata_format);
     void set_external_network_mode(ExternalNetworkMode network_mode);
+    void set_hibernation_partition_image(
+        const std::string& hibernation_partition_image);
 
     // Whether we should start vhal_proxy_server for the guest-side VHAL to
     // connect to.
diff --git a/host/libs/config/cuttlefish_config_instance.cpp b/host/libs/config/cuttlefish_config_instance.cpp
index 1311e7e3f..af17eb56a 100644
--- a/host/libs/config/cuttlefish_config_instance.cpp
+++ b/host/libs/config/cuttlefish_config_instance.cpp
@@ -373,6 +373,16 @@ void CuttlefishConfig::MutableInstanceSpecific::set_custom_partition_path(
 std::string CuttlefishConfig::InstanceSpecific::custom_partition_path() const {
   return (*Dictionary())[kCustomPartitionPath].asString();
 }
+static constexpr char kHibernationPartitionImage[] =
+    "hibernation_partition_image";
+void CuttlefishConfig::MutableInstanceSpecific::set_hibernation_partition_image(
+    const std::string& hibernation_partition_image) {
+  (*Dictionary())[kHibernationPartitionImage] = hibernation_partition_image;
+}
+std::string CuttlefishConfig::InstanceSpecific::hibernation_partition_image()
+    const {
+  return (*Dictionary())[kHibernationPartitionImage].asString();
+}
 static constexpr char kBlankMetadataImageMb[] = "blank_metadata_image_mb";
 int CuttlefishConfig::InstanceSpecific::blank_metadata_image_mb() const {
   return (*Dictionary())[kBlankMetadataImageMb].asInt();
@@ -586,6 +596,15 @@ static constexpr char kCpus[] = "cpus";
 void CuttlefishConfig::MutableInstanceSpecific::set_cpus(int cpus) { (*Dictionary())[kCpus] = cpus; }
 int CuttlefishConfig::InstanceSpecific::cpus() const { return (*Dictionary())[kCpus].asInt(); }
 
+static constexpr char kVcpuInfo[] = "vcpu_config_path";
+void CuttlefishConfig::MutableInstanceSpecific::set_vcpu_config_path(
+    const std::string& vcpu_config_path) {
+  (*Dictionary())[kVcpuInfo] = vcpu_config_path;
+}
+std::string CuttlefishConfig::InstanceSpecific::vcpu_config_path() const {
+  return (*Dictionary())[kVcpuInfo].asString();
+}
+
 static constexpr char kDataPolicy[] = "data_policy";
 void CuttlefishConfig::MutableInstanceSpecific::set_data_policy(
     const std::string& data_policy) {
@@ -968,6 +987,15 @@ bool CuttlefishConfig::InstanceSpecific::fail_fast() const {
   return (*Dictionary())[kFailFast].asBool();
 }
 
+static constexpr char kVhostUserBlock[] = "vhost_user_block";
+void CuttlefishConfig::MutableInstanceSpecific::set_vhost_user_block(
+    bool block) {
+  (*Dictionary())[kVhostUserBlock] = block;
+}
+bool CuttlefishConfig::InstanceSpecific::vhost_user_block() const {
+  return (*Dictionary())[kVhostUserBlock].asBool();
+}
+
 static constexpr char kEnableWebRTC[] = "enable_webrtc";
 void CuttlefishConfig::MutableInstanceSpecific::set_enable_webrtc(bool enable_webrtc) {
   (*Dictionary())[kEnableWebRTC] = enable_webrtc;
diff --git a/host/libs/config/data_image.cpp b/host/libs/config/data_image.cpp
index 915728efc..ad389fe91 100644
--- a/host/libs/config/data_image.cpp
+++ b/host/libs/config/data_image.cpp
@@ -61,7 +61,7 @@ Result<void> ForceFsckImage(
 Result<void> ResizeImage(const std::string& data_image, int data_image_mb,
                          const CuttlefishConfig::InstanceSpecific& instance) {
   auto file_mb = FileSize(data_image) >> 20;
-  CF_EXPECTF(data_image_mb <= file_mb, "'{}' is already {} MB, won't downsize",
+  CF_EXPECTF(data_image_mb >= file_mb, "'{}' is already {} MB, won't downsize",
              data_image, file_mb);
   if (file_mb == data_image_mb) {
     LOG(INFO) << data_image << " is already the right size";
diff --git a/host/libs/config/esp.cpp b/host/libs/config/esp.cpp
index 4a9d67891..bc1f5107c 100644
--- a/host/libs/config/esp.cpp
+++ b/host/libs/config/esp.cpp
@@ -300,7 +300,7 @@ EspBuilder PrepareESP(const std::string& image_path, Arch arch) {
     }
   }
 
-  return std::move(builder);
+  return builder;
 }
 
 // TODO(b/260338443, b/260337906) remove ubuntu and debian variations
diff --git a/host/libs/config/fetcher_config.cpp b/host/libs/config/fetcher_config.cpp
index b20c0276e..1160404db 100644
--- a/host/libs/config/fetcher_config.cpp
+++ b/host/libs/config/fetcher_config.cpp
@@ -17,14 +17,14 @@
 #include "host/libs/config/fetcher_config.h"
 
 #include <fstream>
-#include <map>
 #include <string>
 #include <vector>
 
-#include "android-base/logging.h"
-#include "android-base/strings.h"
-#include "gflags/gflags.h"
-#include "json/json.h"
+#include <android-base/file.h>
+#include <android-base/logging.h>
+#include <android-base/strings.h>
+#include <gflags/gflags.h>
+#include <json/json.h>
 
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/result.h"
@@ -141,7 +141,7 @@ bool FetcherConfig::LoadFromFile(const std::string& file) {
     return false;
   }
 
-  auto base_dir = cpp_dirname(file);
+  std::string base_dir = android::base::Dirname(file);
   if (base_dir != "." && dictionary_->isMember(kCvdFiles)) {
     LOG(INFO) << "Adjusting cvd_file paths to directory: " << base_dir;
     for (const auto& member_name : (*dictionary_)[kCvdFiles].getMemberNames()) {
diff --git a/host/libs/config/host_tools_version.cpp b/host/libs/config/host_tools_version.cpp
index 9ef895d0b..5c73e5c89 100644
--- a/host/libs/config/host_tools_version.cpp
+++ b/host/libs/config/host_tools_version.cpp
@@ -48,13 +48,6 @@ static std::map<std::string, uint32_t> DirectoryCrc(const std::string& path) {
   auto files_result = DirectoryContents(full_path);
   CHECK(files_result.ok()) << files_result.error().FormatForEnv();
   std::vector<std::string> files = std::move(*files_result);
-  for (auto it = files.begin(); it != files.end();) {
-    if (*it == "." || *it == "..") {
-      it = files.erase(it);
-    } else {
-      it++;
-    }
-  }
   std::vector<std::future<uint32_t>> calculations;
   calculations.reserve(files.size());
   for (auto& file : files) {
diff --git a/host/libs/config/secure_hals.cpp b/host/libs/config/secure_hals.cpp
new file mode 100644
index 000000000..adb322083
--- /dev/null
+++ b/host/libs/config/secure_hals.cpp
@@ -0,0 +1,120 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#include "host/libs/config/secure_hals.h"
+
+#include <cctype>
+#include <set>
+#include <string>
+#include <unordered_map>
+
+#include <android-base/no_destructor.h>
+#include <android-base/strings.h>
+
+#include "common/libs/utils/result.h"
+
+using android::base::NoDestructor;
+using android::base::Tokenize;
+
+namespace cuttlefish {
+namespace {
+
+NoDestructor<std::unordered_map<std::string_view, SecureHal>> kMapping([] {
+  return std::unordered_map<std::string_view, SecureHal>{
+      {"keymint", SecureHal::kHostKeymintSecure},
+      {"host_secure_keymint", SecureHal::kHostKeymintSecure},
+      {"host_keymint_secure", SecureHal::kHostKeymintSecure},
+      {"guest_keymint_trusty_insecure", SecureHal::kGuestKeymintTrustyInsecure},
+      {"guest_keymint_insecure_trusty", SecureHal::kGuestKeymintTrustyInsecure},
+      {"guest_gatekeeper_insecure", SecureHal::kGuestGatekeeperInsecure},
+      {"guest_insecure_gatekeeper", SecureHal::kGuestGatekeeperInsecure},
+      {"guest_insecure_keymint", SecureHal::kGuestKeymintInsecure},
+      {"guest_keymint_insecure", SecureHal::kGuestKeymintInsecure},
+      {"gatekeeper", SecureHal::kHostGatekeeperSecure},
+      {"host_gatekeeper_secure", SecureHal::kHostGatekeeperSecure},
+      {"host_secure_gatekeeper", SecureHal::kHostGatekeeperSecure},
+      {"host_gatekeeper_insecure", SecureHal::kHostGatekeeperInsecure},
+      {"host_insecure_gatekeeper", SecureHal::kHostGatekeeperInsecure},
+      {"oemlock", SecureHal::kHostOemlockSecure},
+      {"host_oemlock_secure", SecureHal::kHostOemlockSecure},
+      {"host_secure_oemlock", SecureHal::kHostOemlockSecure},
+  };
+}());
+
+}  // namespace
+
+Result<SecureHal> ParseSecureHal(std::string mode) {
+  for (char& c : mode) {
+    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
+  }
+  auto it = kMapping->find(mode);
+  CF_EXPECTF(it != kMapping->end(), "Unknown secure HAL '{}'", mode);
+  return it->second;
+}
+
+Result<std::set<SecureHal>> ParseSecureHals(const std::string& hals) {
+  std::set<SecureHal> args_set;
+  for (auto& hal : Tokenize(hals, ",:;|/\\+")) {
+    args_set.emplace(CF_EXPECT(ParseSecureHal(hal)));
+  }
+  return args_set;
+}
+
+Result<void> ValidateSecureHals(const std::set<SecureHal>& secure_hals) {
+  auto keymint_impls =
+      secure_hals.count(SecureHal::kGuestKeymintInsecure) +
+      secure_hals.count(SecureHal::kGuestKeymintTrustyInsecure) +
+      secure_hals.count(SecureHal::kHostKeymintInsecure) +
+      secure_hals.count(SecureHal::kHostKeymintSecure);
+  CF_EXPECT_LE(keymint_impls, 1, "Choose at most one keymint implementation");
+
+  auto gatekeeper_impls =
+      secure_hals.count(SecureHal::kGuestGatekeeperInsecure) +
+      secure_hals.count(SecureHal::kHostGatekeeperInsecure) +
+      secure_hals.count(SecureHal::kHostGatekeeperSecure);
+  CF_EXPECT_LE(gatekeeper_impls, 1,
+               "Choose at most one gatekeeper implementation");
+
+  auto oemlock_impls = secure_hals.count(SecureHal::kHostOemlockInsecure) +
+                       secure_hals.count(SecureHal::kHostOemlockSecure);
+  CF_EXPECT_LE(oemlock_impls, 1, "Choose at most one oemlock implementation");
+
+  return {};
+}
+
+std::string ToString(SecureHal hal_in) {
+  switch (hal_in) {
+    case SecureHal::kGuestGatekeeperInsecure:
+      return "guest_gatekeeper_insecure";
+    case SecureHal::kGuestKeymintInsecure:
+      return "guest_keymint_insecure";
+    case SecureHal::kGuestKeymintTrustyInsecure:
+      return "guest_keymint_trusty_insecure";
+    case SecureHal::kHostKeymintInsecure:
+      return "host_keymint_insecure";
+    case SecureHal::kHostKeymintSecure:
+      return "host_keymint_secure";
+    case SecureHal::kHostGatekeeperInsecure:
+      return "host_gatekeeper_insecure";
+    case SecureHal::kHostGatekeeperSecure:
+      return "host_gatekeeper_secure";
+    case SecureHal::kHostOemlockInsecure:
+      return "host_oemlock_insecure";
+    case SecureHal::kHostOemlockSecure:
+      return "host_oemlock_secure";
+  }
+}
+
+}  // namespace cuttlefish
diff --git a/host/libs/config/secure_hals.h b/host/libs/config/secure_hals.h
new file mode 100644
index 000000000..94c9a6589
--- /dev/null
+++ b/host/libs/config/secure_hals.h
@@ -0,0 +1,42 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#pragma once
+
+#include <set>
+#include <string>
+
+#include "common/libs/utils/result.h"
+
+namespace cuttlefish {
+
+enum class SecureHal {
+  kGuestGatekeeperInsecure,
+  kGuestKeymintInsecure,
+  kGuestKeymintTrustyInsecure,
+  kHostKeymintInsecure,
+  kHostKeymintSecure,
+  kHostGatekeeperInsecure,
+  kHostGatekeeperSecure,
+  kHostOemlockInsecure,
+  kHostOemlockSecure,
+};
+
+Result<SecureHal> ParseSecureHal(std::string);
+Result<std::set<SecureHal>> ParseSecureHals(const std::string&);
+std::string ToString(SecureHal);
+Result<void> ValidateSecureHals(const std::set<SecureHal>&);
+
+}  // namespace cuttlefish
diff --git a/host/libs/confui/Android.bp b/host/libs/confui/Android.bp
new file mode 100644
index 000000000..24cdfc31d
--- /dev/null
+++ b/host/libs/confui/Android.bp
@@ -0,0 +1,72 @@
+//
+// Copyright (C) 2021 The Android Open Source Project
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
+// copied from cuttlefish top level Android.bp, cuttlefish_common_headers
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library_headers {
+    name: "libcuttlefish_confui_host_headers",
+    vendor_available: true,
+    product_available: true,
+    host_supported: true,
+    apex_available: [
+        "//apex_available:platform",
+        "com.android.virt",
+    ],
+}
+
+cc_library {
+    name: "libcuttlefish_confui_host",
+    srcs: [
+        "cbor.cc",
+        "host_renderer.cc",
+        "host_server.cc",
+        "host_utils.cc",
+        "host_virtual_input.cc",
+        "secure_input.cc",
+        "server_common.cc",
+        "session.cc",
+        "sign.cc",
+        "fonts.S",
+    ],
+    shared_libs: [
+        "libcn-cbor",
+        "libcuttlefish_fs",
+        "libbase",
+        "libfruit",
+        "libjsoncpp",
+        "liblog",
+        "libcrypto",
+        "android.hardware.keymaster@4.0",
+    ],
+    header_libs: [
+        "libcuttlefish_confui_host_headers",
+        "libdrm_headers",
+    ],
+    static_libs: [
+        "libcuttlefish_host_config",
+        "libcuttlefish_utils",
+        "libcuttlefish_confui",
+        "libcuttlefish_input_connector",
+        "libcuttlefish_security",
+        "libcuttlefish_wayland_server",
+        "libft2.nodep",
+        "libteeui",
+        "libteeui_localization",
+    ],
+    defaults: ["cuttlefish_buildhost_only"],
+}
diff --git a/host/libs/confui/Roboto-Medium.ttf b/host/libs/confui/Roboto-Medium.ttf
new file mode 100644
index 000000000..1a7f3b0bb
Binary files /dev/null and b/host/libs/confui/Roboto-Medium.ttf differ
diff --git a/host/libs/confui/Roboto-Regular.ttf b/host/libs/confui/Roboto-Regular.ttf
new file mode 100644
index 000000000..2c97eeadf
Binary files /dev/null and b/host/libs/confui/Roboto-Regular.ttf differ
diff --git a/host/libs/confui/Shield.ttf b/host/libs/confui/Shield.ttf
new file mode 100644
index 000000000..a2f5e33f3
Binary files /dev/null and b/host/libs/confui/Shield.ttf differ
diff --git a/host/libs/confui/cbor.cc b/host/libs/confui/cbor.cc
new file mode 100644
index 000000000..e7f667b43
--- /dev/null
+++ b/host/libs/confui/cbor.cc
@@ -0,0 +1,108 @@
+/*
+ * Copyright 2021, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/confui/cbor.h"
+
+#include "common/libs/confui/confui.h"
+
+namespace cuttlefish {
+namespace confui {
+/**
+ * basically, this creates a map as follows:
+ * {"prompt" : prompt_text_in_UTF8,
+ *  "extra"  : extra_data_in_bytes}
+ */
+void Cbor::Init() {
+  cn_cbor_errback err;
+  cb_map_ = std::unique_ptr<cn_cbor, CborDeleter>(cn_cbor_map_create(&err));
+
+  buffer_status_ = CheckUTF8Copy(prompt_text_);
+  if (!IsOk()) {
+    return;
+  }
+
+  auto cb_prompt_as_value = cn_cbor_string_create(prompt_text_.data(), &err);
+  auto cb_extra_data_as_value =
+      cn_cbor_data_create(extra_data_.data(), extra_data_.size(), &err);
+  cn_cbor_mapput_string(cb_map_.get(), "prompt", cb_prompt_as_value, &err);
+  cn_cbor_mapput_string(cb_map_.get(), "extra", cb_extra_data_as_value, &err);
+
+  // cn_cbor_encoder_write wants buffer_ to have a trailing 0 at the end
+  auto n_chars =
+      cn_cbor_encoder_write(buffer_.data(), 0, buffer_.size(), cb_map_.get());
+  ConfUiLog(ERROR) << "Cn-cbor encoder wrote " << n_chars << " while "
+                   << "kMax is " << kMax;
+  if (n_chars < 0) {
+    // it's either message being too long, or a potential cn_cbor bug
+    ConfUiLog(ERROR) << "Cn-cbor returns -1 which is likely message too long.";
+    buffer_status_ = Error::OUT_OF_DATA;
+  }
+  if (!IsOk()) {
+    return;
+  }
+  buffer_.resize(n_chars);
+}
+
+std::vector<std::uint8_t>&& Cbor::GetMessage() { return std::move(buffer_); }
+
+Cbor::Error Cbor::CheckUTF8Copy(const std::string& text) {
+  auto begin = text.cbegin();
+  auto end = text.cend();
+
+  if (!IsOk()) {
+    return buffer_status_;
+  }
+
+  uint32_t multi_byte_length = 0;
+  Cbor::Error err_code = buffer_status_;  // OK
+
+  while (begin != end) {
+    if (multi_byte_length) {
+      // parsing multi byte character - must start with 10xxxxxx
+      --multi_byte_length;
+      if ((*begin & 0xc0) != 0x80) {
+        return Cbor::Error::MALFORMED_UTF8;
+      }
+    } else if (!((*begin) & 0x80)) {
+      // 7bit character -> nothing to be done
+    } else {
+      // msb is set and we were not parsing a multi byte character
+      // so this must be a header byte
+      char c = *begin << 1;
+      while (c & 0x80) {
+        ++multi_byte_length;
+        c <<= 1;
+      }
+      // headers of the form 10xxxxxx are not allowed
+      if (multi_byte_length < 1) {
+        return Cbor::Error::MALFORMED_UTF8;
+      }
+      // chars longer than 4 bytes are not allowed (multi_byte_length does not
+      // count the header thus > 3
+      if (multi_byte_length > 3) {
+        return Cbor::Error::MALFORMED_UTF8;
+      }
+    }
+    ++begin;
+  }
+  // if the string ends in the middle of a multi byte char it is invalid
+  if (multi_byte_length) {
+    return Cbor::Error::MALFORMED_UTF8;
+  }
+  return err_code;
+}
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/cbor.h b/host/libs/confui/cbor.h
new file mode 100644
index 000000000..b77e0c7eb
--- /dev/null
+++ b/host/libs/confui/cbor.h
@@ -0,0 +1,101 @@
+/*
+ * Copyright 2021, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <cstdint>
+#include <memory>
+#include <string>
+#include <vector>
+
+#include <android/hardware/keymaster/4.0/types.h>
+
+#include <cn-cbor/cn-cbor.h>
+
+namespace cuttlefish {
+namespace confui {
+
+/** take prompt_text_, extra_data
+ * returns CBOR map, created with the two
+ *
+ * Usage:
+ *  if (IsOk()) GetMessage()
+ *
+ * The CBOR map is used to create signed confirmation
+ */
+class Cbor {
+  enum class Error : uint32_t {
+    OK = 0,
+    OUT_OF_DATA = 1,
+    MALFORMED = 2,
+    MALFORMED_UTF8 = 3,
+  };
+
+  enum class MessageSize : uint32_t { MAX = 6144u };
+
+  enum class Type : uint8_t {
+    NUMBER = 0,
+    NEGATIVE = 1,
+    BYTE_STRING = 2,
+    TEXT_STRING = 3,
+    ARRAY = 4,
+    MAP = 5,
+    TAG = 6,
+    FLOAT = 7,
+  };
+
+ public:
+  Cbor(const std::string& prompt_text,
+       const std::vector<std::uint8_t>& extra_data)
+      : prompt_text_(prompt_text),
+        extra_data_(extra_data),
+        buffer_status_{Error::OK},
+        buffer_(kMax + 1) {
+    Init();
+  }
+
+  bool IsOk() const { return buffer_status_ == Error::OK; }
+  Error GetErrorCode() const { return buffer_status_; }
+  bool IsMessageTooLong() const { return buffer_status_ == Error::OUT_OF_DATA; }
+  bool IsMalformedUtf8() const {
+    return buffer_status_ == Error::MALFORMED_UTF8;
+  }
+  // call this only when IsOk() returns true
+  std::vector<std::uint8_t>&& GetMessage();
+
+  /** When encoded, the Cbor object should not exceed this limit in terms of
+   * size in bytes
+   */
+  const std::uint32_t kMax = static_cast<std::uint32_t>(MessageSize::MAX);
+
+ private:
+  class CborDeleter {
+   public:
+    void operator()(cn_cbor* ptr) { cn_cbor_free(ptr); }
+  };
+
+  std::unique_ptr<cn_cbor, CborDeleter> cb_map_;
+  std::string prompt_text_;
+  std::vector<std::uint8_t> extra_data_;
+  Error buffer_status_;
+  std::vector<std::uint8_t> buffer_;
+
+  void Init();
+  Error CheckUTF8Copy(const std::string& text);
+};
+
+}  // namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/fonts.S b/host/libs/confui/fonts.S
new file mode 100644
index 000000000..5a134dfce
--- /dev/null
+++ b/host/libs/confui/fonts.S
@@ -0,0 +1,21 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include <teeui/incfont.h>
+
+TEEUI_INCFONT(RobotoMedium, "Roboto-Medium.ttf");
+TEEUI_INCFONT(RobotoRegular, "Roboto-Regular.ttf");
+TEEUI_INCFONT(Shield, "Shield.ttf");
diff --git a/host/libs/confui/host_mode_ctrl.h b/host/libs/confui/host_mode_ctrl.h
new file mode 100644
index 000000000..4a5fb5162
--- /dev/null
+++ b/host/libs/confui/host_mode_ctrl.h
@@ -0,0 +1,119 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <atomic>
+#include <condition_variable>
+#include <cstdint>
+#include <functional>
+#include <mutex>
+
+#include <fruit/fruit.h>
+
+#include "common/libs/confui/confui.h"
+#include "host/libs/confui/host_utils.h"
+
+namespace cuttlefish {
+/**
+ * mechanism to orchestrate concurrent executions of threads
+ * that work for screen connector
+ *
+ * Within WebRTC service, it tells when it is now in the Android Mode or
+ * Confirmation UI mode
+ */
+class HostModeCtrl {
+ public:
+  enum class ModeType : std::uint8_t { kAndroidMode = 55, kConfUI_Mode = 77 };
+  INJECT(HostModeCtrl()) : atomic_mode_(ModeType::kAndroidMode) {}
+  /**
+   * The thread that enqueues Android frames will call this to wait until
+   * the mode is kAndroidMode
+   *
+   * Logically, using atomic_mode_ alone is not sufficient. Using mutex alone
+   * is logically complete but slow.
+   *
+   * Note that most of the time, the mode is kAndroidMode. Also, note that
+   * this method is called at every single frame.
+   *
+   * As an optimization, we check atomic_mode_ first. If failed, we wait for
+   * kAndroidMode with mutex-based lock
+   *
+   * The actual synchronization is not at the and_mode_cv_.wait line but at
+   * this line:
+   *     if (atomic_mode_ == ModeType::kAndroidMode) {
+   *
+   * This trick reduces the flag checking delays by 70+% on a Gentoo based
+   * amd64 desktop, with Linux 5.10
+   */
+  void WaitAndroidMode() {
+    ConfUiLog(DEBUG) << cuttlefish::confui::thread::GetName()
+                     << "checking atomic Android mode";
+    if (atomic_mode_ == ModeType::kAndroidMode) {
+      ConfUiLog(DEBUG) << cuttlefish::confui::thread::GetName()
+                       << "returns as it is already Android mode";
+      return;
+    }
+    auto check = [this]() -> bool {
+      return atomic_mode_ == ModeType::kAndroidMode;
+    };
+    std::unique_lock<std::mutex> lock(mode_mtx_);
+    and_mode_cv_.wait(lock, check);
+    ConfUiLog(DEBUG) << cuttlefish::confui::thread::GetName()
+                     << "awakes from cond var waiting for Android mode";
+  }
+
+  void SetMode(const ModeType mode) {
+    ConfUiLog(DEBUG) << cuttlefish::confui::thread::GetName()
+                     << " tries to acquire the lock in SetMode";
+    std::lock_guard<std::mutex> lock(mode_mtx_);
+    ConfUiLog(DEBUG) << cuttlefish::confui::thread::GetName()
+                     << " acquired the lock in SetMode";
+    atomic_mode_ = mode;
+    if (atomic_mode_ == ModeType::kAndroidMode) {
+      ConfUiLog(DEBUG) << cuttlefish::confui::thread::GetName()
+                       << " signals kAndroidMode in SetMode";
+      and_mode_cv_.notify_all();
+      return;
+    }
+    ConfUiLog(DEBUG) << cuttlefish::confui::thread::GetName()
+                     << "signals kConfUI_Mode in SetMode";
+    confui_mode_cv_.notify_all();
+  }
+
+  auto GetMode() {
+    ModeType ret_val = atomic_mode_;
+    return ret_val;
+  }
+
+  auto IsConfirmatioUiMode() {
+    return (atomic_mode_ == ModeType::kConfUI_Mode);
+  }
+
+  auto IsAndroidMode() { return (atomic_mode_ == ModeType::kAndroidMode); }
+
+  static HostModeCtrl& Get() {
+    static HostModeCtrl host_mode_controller;
+    return host_mode_controller;
+  }
+
+ private:
+  std::mutex mode_mtx_;
+  std::condition_variable and_mode_cv_;
+  std::condition_variable confui_mode_cv_;
+  std::atomic<ModeType> atomic_mode_;
+};
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/host_renderer.cc b/host/libs/confui/host_renderer.cc
new file mode 100644
index 000000000..698c5c3ff
--- /dev/null
+++ b/host/libs/confui/host_renderer.cc
@@ -0,0 +1,444 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/confui/host_renderer.h"
+
+#include <drm/drm_fourcc.h>
+
+#include "host/libs/config/cuttlefish_config.h"
+
+namespace cuttlefish {
+namespace confui {
+static teeui::Color alfaCombineChannel(std::uint32_t shift, double alfa,
+                                       teeui::Color a, teeui::Color b) {
+  a >>= shift;
+  a &= 0xff;
+  b >>= shift;
+  b &= 0xff;
+  double acc = alfa * a + (1 - alfa) * b;
+  if (acc <= 0) {
+    return 0;
+  }
+  std::uint32_t result = acc;
+  if (result > 255) {
+    return 255 << shift;
+  }
+  return result << shift;
+}
+
+/**
+ * create a raw frame for confirmation UI dialog
+ *
+ * Many rendering code borrowed from the following source
+ *  https://android.googlesource.com/trusty/app/confirmationui/+/0429cc7/src
+ */
+class ConfUiRendererImpl {
+  friend class ConfUiRenderer;
+
+ public:
+  using LabelConfMsg = teeui::LabelBody;
+
+ private:
+  static Result<std::unique_ptr<ConfUiRendererImpl>> GenerateRenderer(
+      const std::uint32_t display, const std::string& confirmation_msg,
+      const std::string& locale, const bool inverted, const bool magnified);
+
+  /**
+   * this does not repaint from the scratch all the time
+   *
+   * It does repaint its frame buffer only when w/h of
+   * current display has changed
+   */
+  std::unique_ptr<TeeUiFrameWrapper>& RenderRawFrame();
+
+  bool IsFrameReady() const { return raw_frame_ && !raw_frame_->IsEmpty(); }
+
+  bool IsInConfirm(const std::uint32_t x, const std::uint32_t y) {
+    return IsInside<teeui::LabelOK>(x, y);
+  }
+  bool IsInCancel(const std::uint32_t x, const std::uint32_t y) {
+    return IsInside<teeui::LabelCancel>(x, y);
+  }
+
+  bool IsSetUpSuccessful() const { return is_setup_well_; }
+  ConfUiRendererImpl(const std::uint32_t display,
+                     const std::string& confirmation_msg,
+                     const std::string& locale, const bool inverted,
+                     const bool magnified);
+
+  struct Boundary {            // inclusive but.. LayoutElement's size is float
+    std::uint32_t x, y, w, h;  // (x, y) is the top left
+  };
+
+  template <typename LayoutElement>
+  Boundary GetBoundary(LayoutElement&& e) const {
+    auto box = e.bounds_;
+    Boundary b;
+    // (x,y) is left top. so floor() makes sense
+    // w, h are width and height in float. perhaps ceiling makes more
+    // sense
+    b.x = static_cast<std::uint32_t>(box.x().floor().count());
+    b.y = static_cast<std::uint32_t>(box.y().floor().count());
+    b.w = static_cast<std::uint32_t>(box.w().ceil().count());
+    b.h = static_cast<std::uint32_t>(box.h().ceil().count());
+    return b;
+  }
+
+  template <typename Element>
+  bool IsInside(const std::uint32_t x, const std::uint32_t y) const {
+    auto box = GetBoundary(std::get<Element>(layout_));
+    if (x >= box.x && x <= box.x + box.w && y >= box.y && y <= box.y + box.h) {
+      return true;
+    }
+    return false;
+  }
+  // essentially, to repaint from the scratch, so returns new frame
+  // when successful. Or, nullopt
+  std::unique_ptr<TeeUiFrameWrapper> RepaintRawFrame(const int w, const int h);
+
+  bool InitLayout(const std::string& lang_id);
+  teeui::Error UpdateTranslations();
+  teeui::Error UpdateLocale();
+  void SetDeviceContext(const unsigned long long w, const unsigned long long h,
+                        bool is_inverted, bool is_magnified);
+
+  // a callback function to be effectively sent to TeeUI library
+  teeui::Error UpdatePixels(TeeUiFrameWrapper& buffer, std::uint32_t x,
+                            std::uint32_t y, teeui::Color color);
+
+  // second param is for type deduction
+  template <typename... Elements>
+  static teeui::Error drawElements(std::tuple<Elements...>& layout,
+                                   const teeui::PixelDrawer& drawPixel) {
+    // Error::operator|| is overloaded, so we don't get short circuit
+    // evaluation. But we get the first error that occurs. We will still try and
+    // draw the remaining elements in the order they appear in the layout tuple.
+    return (std::get<Elements>(layout).draw(drawPixel) || ...);
+  }
+  void UpdateColorScheme(const bool is_inverted);
+  template <typename Label>
+  auto SetText(const std::string& text) {
+    return std::get<Label>(layout_).setText(
+        {text.c_str(), text.c_str() + text.size()});
+  }
+
+  template <typename Label>
+  teeui::Error UpdateString();
+
+  std::uint32_t display_num_;
+  teeui::layout_t<teeui::ConfUILayout> layout_;
+  std::string lang_id_;
+  std::string prompt_text_;  // confirmation ui message
+
+  /**
+   * Potentially, the same frame could be requested multiple times.
+   *
+   * While another thread/caller is using this frame, the frame should
+   * be kept here, too, to be returned upon future requests.
+   *
+   */
+  std::unique_ptr<TeeUiFrameWrapper> raw_frame_;
+  std::uint32_t current_height_;
+  std::uint32_t current_width_;
+  teeui::Color color_bg_;
+  teeui::Color color_text_;
+  teeui::Color shield_color_;
+  bool is_inverted_;
+  bool is_magnified_;
+  teeui::context<teeui::ConfUIParameters> ctx_;
+  bool is_setup_well_;
+
+  static constexpr const teeui::Color kColorBackground = 0xffffffff;
+  static constexpr const teeui::Color kColorBackgroundInv = 0xff212121;
+  static constexpr const teeui::Color kColorDisabled = 0xffbdbdbd;
+  static constexpr const teeui::Color kColorDisabledInv = 0xff424242;
+  static constexpr const teeui::Color kColorEnabled = 0xff212121;
+  static constexpr const teeui::Color kColorEnabledInv = 0xffdedede;
+  static constexpr const teeui::Color kColorShield = 0xff778500;
+  static constexpr const teeui::Color kColorShieldInv = 0xffc4cb80;
+  static constexpr const teeui::Color kColorText = 0xff212121;
+  static constexpr const teeui::Color kColorTextInv = 0xffdedede;
+};
+
+Result<std::unique_ptr<ConfUiRendererImpl>>
+ConfUiRendererImpl::GenerateRenderer(const std::uint32_t display,
+                                     const std::string& confirmation_msg,
+                                     const std::string& locale,
+                                     const bool inverted,
+                                     const bool magnified) {
+  ConfUiRendererImpl* raw_ptr = new ConfUiRendererImpl(
+      display, confirmation_msg, locale, inverted, magnified);
+  CF_EXPECT(raw_ptr && raw_ptr->IsSetUpSuccessful(),
+            "Failed to create ConfUiRendererImpl");
+  return std::unique_ptr<ConfUiRendererImpl>(raw_ptr);
+}
+
+static int GetDpi(const int display_num = 0) {
+  auto config = CuttlefishConfig::Get();
+  CHECK(config) << "Config is Missing";
+  auto instance = config->ForDefaultInstance();
+  auto display_configs = instance.display_configs();
+  CHECK_GT(display_configs.size(), display_num)
+      << "Invalid display number " << display_num;
+  return display_configs[display_num].dpi;
+}
+
+/**
+ * device configuration
+ *
+ * ctx_{# of pixels in 1 mm, # of pixels per 1 density independent pixels}
+ *
+ * The numbers are, however, to fit for the host webRTC local/remote clients
+ * in general, not necessarily the supposedly guest device (e.g. Auto, phone,
+ * etc)
+ *
+ * In general, for a normal PC, roughly ctx_(6.45211, 400.0/412.0) is a good
+ * combination for the default DPI, 320. If we want to see the impact
+ * of the change in the guest DPI, we could adjust the combination above
+ * proportionally
+ *
+ */
+ConfUiRendererImpl::ConfUiRendererImpl(const std::uint32_t display,
+                                       const std::string& confirmation_msg,
+                                       const std::string& locale,
+                                       const bool inverted,
+                                       const bool magnified)
+    : display_num_{display},
+      lang_id_{locale},
+      prompt_text_{confirmation_msg},
+      current_height_{ScreenConnectorInfo::ScreenHeight(display_num_)},
+      current_width_{ScreenConnectorInfo::ScreenWidth(display_num_)},
+      is_inverted_(inverted),
+      is_magnified_(magnified),
+      ctx_(6.45211 * GetDpi() / 320.0, 400.0 / 412.0 * GetDpi() / 320.0),
+      is_setup_well_(false) {
+  SetDeviceContext(current_width_, current_height_, is_inverted_,
+                   is_magnified_);
+  layout_ = teeui::instantiateLayout(teeui::ConfUILayout(), ctx_);
+
+  if (auto error = UpdateLocale()) {
+    ConfUiLog(ERROR) << "Update Translation Error: " << Enum2Base(error.code());
+    // is_setup_well_ = false;
+    return;
+  }
+  UpdateColorScheme(is_inverted_);
+  SetText<LabelConfMsg>(prompt_text_);
+  is_setup_well_ = true;
+}
+
+teeui::Error ConfUiRendererImpl::UpdateLocale() {
+  using teeui::Error;
+  teeui::localization::selectLangId(lang_id_.c_str());
+  if (auto error = UpdateTranslations()) {
+    return error;
+  }
+  return Error::OK;
+}
+
+template <typename Label>
+teeui::Error ConfUiRendererImpl::UpdateString() {
+  using namespace teeui;
+  const char* str;
+  auto& label = std::get<Label>(layout_);
+  str = localization::lookup(TranslationId(label.textId()));
+  if (str == nullptr) {
+    ConfUiLog(ERROR) << "Given translation_id" << label.textId() << "not found";
+    return Error::Localization;
+  }
+  label.setText({str, str + strlen(str)});
+  return Error::OK;
+}
+
+teeui::Error ConfUiRendererImpl::UpdateTranslations() {
+  using namespace teeui;
+  if (auto error = UpdateString<LabelOK>()) {
+    return error;
+  }
+  if (auto error = UpdateString<LabelCancel>()) {
+    return error;
+  }
+  if (auto error = UpdateString<LabelTitle>()) {
+    return error;
+  }
+  if (auto error = UpdateString<LabelHint>()) {
+    return error;
+  }
+  return Error::OK;
+}
+
+void ConfUiRendererImpl::SetDeviceContext(const unsigned long long w,
+                                          const unsigned long long h,
+                                          const bool is_inverted,
+                                          const bool is_magnified) {
+  using namespace teeui;
+  const auto screen_width = operator""_px(w);
+  const auto screen_height = operator""_px(h);
+  ctx_.setParam<RightEdgeOfScreen>(pxs(screen_width));
+  ctx_.setParam<BottomOfScreen>(pxs(screen_height));
+  if (is_magnified) {
+    ctx_.setParam<DefaultFontSize>(18_dp);
+    ctx_.setParam<BodyFontSize>(20_dp);
+  } else {
+    ctx_.setParam<DefaultFontSize>(14_dp);
+    ctx_.setParam<BodyFontSize>(16_dp);
+  }
+  if (is_inverted) {
+    ctx_.setParam<ShieldColor>(kColorShieldInv);
+    ctx_.setParam<ColorText>(kColorTextInv);
+    ctx_.setParam<ColorBG>(kColorBackgroundInv);
+    ctx_.setParam<ColorButton>(kColorShieldInv);
+  } else {
+    ctx_.setParam<ShieldColor>(kColorShield);
+    ctx_.setParam<ColorText>(kColorText);
+    ctx_.setParam<ColorBG>(kColorBackground);
+    ctx_.setParam<ColorButton>(kColorShield);
+  }
+}
+
+teeui::Error ConfUiRendererImpl::UpdatePixels(TeeUiFrameWrapper& raw_frame,
+                                              std::uint32_t x, std::uint32_t y,
+                                              teeui::Color color) {
+  auto buffer = raw_frame.data();
+  const auto height = raw_frame.Height();
+  const auto width = raw_frame.Width();
+  auto pos = width * y + x;
+  if (pos >= (height * width)) {
+    ConfUiLog(ERROR) << "Rendering Out of Bound";
+    return teeui::Error::OutOfBoundsDrawing;
+  }
+  const double alfa = ((color & 0xff000000) >> 24) / 255.0;
+  auto& pixel = *reinterpret_cast<teeui::Color*>(buffer + pos);
+  pixel = alfaCombineChannel(0, alfa, color, pixel) |
+          alfaCombineChannel(8, alfa, color, pixel) |
+          alfaCombineChannel(16, alfa, color, pixel);
+  return teeui::Error::OK;
+}
+
+void ConfUiRendererImpl::UpdateColorScheme(const bool is_inverted) {
+  using namespace teeui;
+  color_text_ = is_inverted ? kColorDisabledInv : kColorDisabled;
+  shield_color_ = is_inverted ? kColorShieldInv : kColorShield;
+  color_bg_ = is_inverted ? kColorBackgroundInv : kColorBackground;
+
+  ctx_.setParam<ShieldColor>(shield_color_);
+  ctx_.setParam<ColorText>(color_text_);
+  ctx_.setParam<ColorBG>(color_bg_);
+  return;
+}
+
+std::unique_ptr<TeeUiFrameWrapper>& ConfUiRendererImpl::RenderRawFrame() {
+  /* we repaint only if one or more of the following meet:
+   *
+   *  1. raw_frame_ is empty
+   *  2. the current_width_ and current_height_ is out of date
+   *
+   */
+  const int w = ScreenConnectorInfo::ScreenWidth(display_num_);
+  const int h = ScreenConnectorInfo::ScreenHeight(display_num_);
+  if (!IsFrameReady() || current_height_ != h || current_width_ != w) {
+    auto new_frame = RepaintRawFrame(w, h);
+    if (!new_frame) {
+      // must repaint but failed
+      raw_frame_ = nullptr;
+      return raw_frame_;
+    }
+    // repainting from the scratch successful in a new frame
+    raw_frame_ = std::move(new_frame);
+    current_width_ = w;
+    current_height_ = h;
+  }
+  return raw_frame_;
+}
+
+std::unique_ptr<TeeUiFrameWrapper> ConfUiRendererImpl::RepaintRawFrame(
+    const int w, const int h) {
+  std::get<teeui::LabelOK>(layout_).setTextColor(kColorEnabled);
+  std::get<teeui::LabelCancel>(layout_).setTextColor(kColorEnabled);
+
+  /**
+   * should be uint32_t for teeui APIs.
+   * It assumes that each raw frame buffer element is 4 bytes
+   */
+  const teeui::Color background_color =
+      is_inverted_ ? kColorBackgroundInv : kColorBackground;
+  auto new_raw_frame =
+      std::make_unique<TeeUiFrameWrapper>(w, h, background_color);
+  auto draw_pixel = teeui::makePixelDrawer(
+      [this, &new_raw_frame](std::uint32_t x, std::uint32_t y,
+                             teeui::Color color) -> teeui::Error {
+        return this->UpdatePixels(*new_raw_frame, x, y, color);
+      });
+
+  // render all components
+  const auto error = drawElements(layout_, draw_pixel);
+  if (error) {
+    ConfUiLog(ERROR) << "Painting failed: " << error.code();
+    return nullptr;
+  }
+
+  return new_raw_frame;
+}
+
+ConfUiRenderer::ConfUiRenderer(ScreenConnectorFrameRenderer& screen_connector)
+    : screen_connector_{screen_connector} {}
+
+ConfUiRenderer::~ConfUiRenderer() {}
+
+Result<void> ConfUiRenderer::RenderDialog(
+    const std::uint32_t display_num, const std::string& prompt_text,
+    const std::string& locale, const std::vector<teeui::UIOption>& ui_options) {
+  renderer_impl_ = CF_EXPECT(ConfUiRendererImpl::GenerateRenderer(
+      display_num, prompt_text, locale, IsInverted(ui_options),
+      IsMagnified(ui_options)));
+  auto& teeui_frame = renderer_impl_->RenderRawFrame();
+  CF_EXPECT(teeui_frame != nullptr, "RenderRawFrame() failed.");
+  ConfUiLog(VERBOSE) << "actually trying to render the frame"
+                     << thread::GetName();
+  auto frame_width = teeui_frame->Width();
+  auto frame_height = teeui_frame->Height();
+  auto frame_stride_bytes = teeui_frame->ScreenStrideBytes();
+  auto frame_bytes = reinterpret_cast<std::uint8_t*>(teeui_frame->data());
+  CF_EXPECT(screen_connector_.RenderConfirmationUi(
+      display_num, frame_width, frame_height, DRM_FORMAT_ABGR8888,
+      frame_stride_bytes, frame_bytes));
+  return {};
+}
+
+bool ConfUiRenderer::IsInverted(
+    const std::vector<teeui::UIOption>& ui_options) const {
+  return Contains(ui_options, teeui::UIOption::AccessibilityInverted);
+}
+
+bool ConfUiRenderer::IsMagnified(
+    const std::vector<teeui::UIOption>& ui_options) const {
+  return Contains(ui_options, teeui::UIOption::AccessibilityMagnified);
+}
+
+bool ConfUiRenderer::IsInConfirm(const std::uint32_t x, const std::uint32_t y) {
+  if (!renderer_impl_) {
+    ConfUiLog(INFO) << "renderer_impl_ is nullptr";
+  }
+  return renderer_impl_ && renderer_impl_->IsInConfirm(x, y);
+}
+bool ConfUiRenderer::IsInCancel(const std::uint32_t x, const std::uint32_t y) {
+  if (!renderer_impl_) {
+    ConfUiLog(INFO) << "renderer_impl_ is nullptr";
+  }
+  return renderer_impl_ && renderer_impl_->IsInCancel(x, y);
+}
+
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/host_renderer.h b/host/libs/confui/host_renderer.h
new file mode 100644
index 000000000..c8a47bc6c
--- /dev/null
+++ b/host/libs/confui/host_renderer.h
@@ -0,0 +1,84 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <cstdint>
+#include <functional>
+#include <memory>
+#include <string>
+#include <tuple>
+#include <vector>
+
+#include <android-base/logging.h>
+#include <freetype/ftglyph.h>  // $(croot)/external/freetype
+#include <fruit/fruit.h>
+#include <teeui/utils.h>  // $(croot)/system/teeui/libteeui/.../include
+
+#include "common/libs/confui/confui.h"
+#include "common/libs/utils/result.h"
+#include "host/libs/confui/layouts/layout.h"
+#include "host/libs/confui/server_common.h"
+#include "host/libs/screen_connector/screen_connector.h"
+
+namespace cuttlefish {
+namespace confui {
+class TeeUiFrameWrapper {
+ public:
+  TeeUiFrameWrapper(const int w, const int h, const teeui::Color color)
+      : w_(w), h_(h), teeui_frame_(ScreenSizeInBytes(w, h), color) {}
+  TeeUiFrameWrapper() = delete;
+  auto data() { return teeui_frame_.data(); }
+  int Width() const { return w_; }
+  int Height() const { return h_; }
+  bool IsEmpty() const { return teeui_frame_.empty(); }
+  auto Size() const { return teeui_frame_.size(); }
+  auto& operator[](const int idx) { return teeui_frame_[idx]; }
+  std::uint32_t ScreenStrideBytes() const {
+    return ScreenConnectorInfo::ComputeScreenStrideBytes(w_);
+  }
+
+ private:
+  static std::uint32_t ScreenSizeInBytes(const int w, const int h) {
+    return ScreenConnectorInfo::ComputeScreenSizeInBytes(w, h);
+  }
+
+  int w_;
+  int h_;
+  TeeUiFrame teeui_frame_;
+};
+
+class ConfUiRendererImpl;
+class ConfUiRenderer {
+ public:
+  INJECT(ConfUiRenderer(ScreenConnectorFrameRenderer& screen_connector));
+  ~ConfUiRenderer();
+  Result<void> RenderDialog(const std::uint32_t display_num,
+                            const std::string& prompt_text,
+                            const std::string& locale,
+                            const std::vector<teeui::UIOption>& ui_options);
+  bool IsInConfirm(const std::uint32_t x, const std::uint32_t y);
+  bool IsInCancel(const std::uint32_t x, const std::uint32_t y);
+
+ private:
+  bool IsInverted(const std::vector<teeui::UIOption>& ui_options) const;
+  bool IsMagnified(const std::vector<teeui::UIOption>& ui_options) const;
+  ScreenConnectorFrameRenderer& screen_connector_;
+  std::unique_ptr<ConfUiRendererImpl> renderer_impl_;
+};
+
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/host_server.cc b/host/libs/confui/host_server.cc
new file mode 100644
index 000000000..4077f9f3f
--- /dev/null
+++ b/host/libs/confui/host_server.cc
@@ -0,0 +1,268 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/confui/host_server.h"
+
+#include <functional>
+#include <memory>
+#include <optional>
+#include <tuple>
+
+#include "common/libs/confui/confui.h"
+#include "common/libs/fs/shared_buf.h"
+#include "host/libs/config/cuttlefish_config.h"
+#include "host/libs/confui/host_utils.h"
+#include "host/libs/confui/secure_input.h"
+
+namespace cuttlefish {
+namespace confui {
+namespace {
+
+template <typename Derived, typename Base>
+std::unique_ptr<Derived> DowncastTo(std::unique_ptr<Base>&& base) {
+  Base* tmp = base.release();
+  Derived* derived = static_cast<Derived*>(tmp);
+  return std::unique_ptr<Derived>(derived);
+}
+
+}  // namespace
+
+/**
+ * null if not user/touch, or wrap it and ConfUiSecure{Selection,Touch}Message
+ *
+ * ConfUiMessage must NOT ConfUiSecure{Selection,Touch}Message types
+ */
+static std::unique_ptr<ConfUiMessage> WrapWithSecureFlag(
+    std::unique_ptr<ConfUiMessage>&& base_msg, const bool secure) {
+  switch (base_msg->GetType()) {
+    case ConfUiCmd::kUserInputEvent: {
+      auto as_selection =
+          DowncastTo<ConfUiUserSelectionMessage>(std::move(base_msg));
+      return ToSecureSelectionMessage(std::move(as_selection), secure);
+    }
+    case ConfUiCmd::kUserTouchEvent: {
+      auto as_touch = DowncastTo<ConfUiUserTouchMessage>(std::move(base_msg));
+      return ToSecureTouchMessage(std::move(as_touch), secure);
+    }
+    default:
+      return nullptr;
+  }
+}
+
+HostServer::HostServer(HostModeCtrl& host_mode_ctrl,
+                       ConfUiRenderer& host_renderer,
+                       const PipeConnectionPair& fd_pair)
+    : display_num_(0),
+      host_renderer_{host_renderer},
+      host_mode_ctrl_(host_mode_ctrl),
+      from_guest_fifo_fd_(fd_pair.from_guest_),
+      to_guest_fifo_fd_(fd_pair.to_guest_) {
+  const size_t max_elements = 20;
+  auto ignore_new =
+      [](ThreadSafeQueue<std::unique_ptr<ConfUiMessage>>::QueueImpl*) {
+        // no op, so the queue is still full, and the new item will be discarded
+        return;
+      };
+  hal_cmd_q_id_ = input_multiplexer_.RegisterQueue(
+      HostServer::Multiplexer::CreateQueue(max_elements, ignore_new));
+  user_input_evt_q_id_ = input_multiplexer_.RegisterQueue(
+      HostServer::Multiplexer::CreateQueue(max_elements, ignore_new));
+}
+
+bool HostServer::IsVirtioConsoleOpen() const {
+  return from_guest_fifo_fd_->IsOpen() && to_guest_fifo_fd_->IsOpen();
+}
+
+bool HostServer::CheckVirtioConsole() {
+  if (IsVirtioConsoleOpen()) {
+    return true;
+  }
+  ConfUiLog(FATAL) << "Virtio console is not open";
+  return false;
+}
+
+void HostServer::Start() {
+  if (!CheckVirtioConsole()) {
+    return;
+  }
+  auto hal_cmd_fetching = [this]() { this->HalCmdFetcherLoop(); };
+  auto main = [this]() { this->MainLoop(); };
+  hal_input_fetcher_thread_ =
+      thread::RunThread("HalInputLoop", hal_cmd_fetching);
+  main_loop_thread_ = thread::RunThread("MainLoop", main);
+  ConfUiLog(DEBUG) << "host service started.";
+  return;
+}
+
+void HostServer::HalCmdFetcherLoop() {
+  while (true) {
+    if (!CheckVirtioConsole()) {
+      return;
+    }
+    auto msg = RecvConfUiMsg(from_guest_fifo_fd_);
+    if (!msg) {
+      ConfUiLog(ERROR) << "Error in RecvConfUiMsg from HAL";
+      // TODO(kwstephenkim): error handling
+      // either file is not open, or ill-formatted message
+      continue;
+    }
+    /*
+     * In case of Vts test, the msg could be a user input. For now, we do not
+     * enforce the input grace period for Vts. However, if ever we do, here is
+     * where the time point check should happen. Once it is enqueued, it is not
+     * always guaranteed to be picked up reasonably soon.
+     */
+    constexpr bool is_secure = false;
+    auto to_override_if_user_input =
+        WrapWithSecureFlag(std::move(msg), is_secure);
+    if (to_override_if_user_input) {
+      msg = std::move(to_override_if_user_input);
+    }
+    input_multiplexer_.Push(hal_cmd_q_id_, std::move(msg));
+  }
+}
+
+/**
+ * Send inputs generated not by auto-tester but by the human users
+ *
+ * Send such inputs into the command queue consumed by the state machine
+ * in the main loop/current session.
+ */
+void HostServer::SendUserSelection(std::unique_ptr<ConfUiMessage>& input) {
+  if (!curr_session_ ||
+      curr_session_->GetState() != MainLoopState::kInSession ||
+      !curr_session_->IsReadyForUserInput()) {
+    // ignore
+    return;
+  }
+  constexpr bool is_secure = true;
+  auto secure_input = WrapWithSecureFlag(std::move(input), is_secure);
+  input_multiplexer_.Push(user_input_evt_q_id_, std::move(secure_input));
+}
+
+void HostServer::TouchEvent(const int x, const int y, const bool is_down) {
+  if (!is_down || !curr_session_) {
+    return;
+  }
+  std::unique_ptr<ConfUiMessage> input =
+      std::make_unique<ConfUiUserTouchMessage>(GetCurrentSessionId(), x, y);
+  SendUserSelection(input);
+}
+
+void HostServer::UserAbortEvent() {
+  if (!curr_session_) {
+    return;
+  }
+  std::unique_ptr<ConfUiMessage> input =
+      std::make_unique<ConfUiUserSelectionMessage>(GetCurrentSessionId(),
+                                                   UserResponse::kUserAbort);
+  SendUserSelection(input);
+}
+
+// read the comments in the header file
+[[noreturn]] void HostServer::MainLoop() {
+  while (true) {
+    // this gets one input from either queue:
+    // from HAL or from all webrtc clients
+    // if no input, sleep until there is
+    auto input_ptr = input_multiplexer_.Pop();
+    auto& input = *input_ptr;
+    const auto session_id = input.GetSessionId();
+    const auto cmd = input.GetType();
+    const std::string cmd_str(ToString(cmd));
+
+    // take input for the Finite States Machine below
+    std::string src = input.IsUserInput() ? "input" : "hal";
+    ConfUiLog(VERBOSE) << "In Session " << GetCurrentSessionId() << ", "
+                       << "in state " << GetCurrentState() << ", "
+                       << "received input from " << src << " cmd =" << cmd_str
+                       << " going to session " << session_id;
+
+    if (!curr_session_) {
+      if (cmd != ConfUiCmd::kStart) {
+        ConfUiLog(VERBOSE) << ToString(cmd) << " to " << session_id
+                           << " is ignored as there is no session to receive";
+        continue;
+      }
+      // the session is created as kInit
+      curr_session_ = CreateSession(input.GetSessionId());
+    }
+    if (cmd == ConfUiCmd::kUserTouchEvent) {
+      ConfUiSecureUserTouchMessage& touch_event =
+          static_cast<ConfUiSecureUserTouchMessage&>(input);
+      auto [x, y] = touch_event.GetLocation();
+      const bool is_confirm = curr_session_->IsConfirm(x, y);
+      const bool is_cancel = curr_session_->IsCancel(x, y);
+      ConfUiLog(INFO) << "Touch at [" << x << ", " << y << "] was "
+                      << (is_cancel ? "CANCEL"
+                                    : (is_confirm ? "CONFIRM" : "INVALID"));
+      if (!is_confirm && !is_cancel) {
+        // ignore, take the next input
+        continue;
+      }
+      decltype(input_ptr) tmp_input_ptr =
+          std::make_unique<ConfUiUserSelectionMessage>(
+              GetCurrentSessionId(),
+              (is_confirm ? UserResponse::kConfirm : UserResponse::kCancel));
+      input_ptr =
+          WrapWithSecureFlag(std::move(tmp_input_ptr), touch_event.IsSecure());
+    }
+    Transition(input_ptr);
+
+    // finalize
+    if (curr_session_ &&
+        curr_session_->GetState() == MainLoopState::kAwaitCleanup) {
+      curr_session_->CleanUp();
+      curr_session_ = nullptr;
+    }
+  }  // end of the infinite while loop
+}
+
+std::shared_ptr<Session> HostServer::CreateSession(const std::string& name) {
+  return std::make_shared<Session>(name, display_num_, host_renderer_,
+                                   host_mode_ctrl_);
+}
+
+static bool IsUserAbort(ConfUiMessage& msg) {
+  if (msg.GetType() != ConfUiCmd::kUserInputEvent) {
+    return false;
+  }
+  ConfUiUserSelectionMessage& selection =
+      static_cast<ConfUiUserSelectionMessage&>(msg);
+  return (selection.GetResponse() == UserResponse::kUserAbort);
+}
+
+void HostServer::Transition(std::unique_ptr<ConfUiMessage>& input_ptr) {
+  auto& input = *input_ptr;
+  const auto session_id = input.GetSessionId();
+  const auto cmd = input.GetType();
+  const std::string cmd_str(ToString(cmd));
+  FsmInput fsm_input = ToFsmInput(input);
+  ConfUiLog(VERBOSE) << "Handling " << ToString(cmd);
+  if (IsUserAbort(input)) {
+    curr_session_->UserAbort(to_guest_fifo_fd_);
+    return;
+  }
+
+  if (cmd == ConfUiCmd::kAbort) {
+    curr_session_->Abort();
+    return;
+  }
+  curr_session_->Transition(to_guest_fifo_fd_, fsm_input, input);
+}
+
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/host_server.h b/host/libs/confui/host_server.h
new file mode 100644
index 000000000..8affafdc6
--- /dev/null
+++ b/host/libs/confui/host_server.h
@@ -0,0 +1,165 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <atomic>
+#include <cstdint>
+#include <memory>
+#include <mutex>
+#include <string>
+#include <thread>
+#include <unordered_map>
+#include <vector>
+
+#include <android-base/logging.h>
+#include <fruit/fruit.h>
+#include <teeui/utils.h>
+
+#include "common/libs/concurrency/multiplexer.h"
+#include "common/libs/concurrency/semaphore.h"
+#include "common/libs/confui/confui.h"
+#include "common/libs/fs/shared_fd.h"
+#include "host/commands/kernel_log_monitor/utils.h"
+#include "host/libs/config/logging.h"
+#include "host/libs/confui/host_mode_ctrl.h"
+#include "host/libs/confui/host_renderer.h"
+#include "host/libs/confui/server_common.h"
+#include "host/libs/confui/session.h"
+
+namespace cuttlefish {
+namespace confui {
+struct PipeConnectionPair {
+  SharedFD from_guest_;
+  SharedFD to_guest_;
+};
+
+class HostServer {
+ public:
+  INJECT(HostServer(HostModeCtrl& host_mode_ctrl, ConfUiRenderer& host_renderer,
+                    const PipeConnectionPair& fd_pair));
+
+  void Start();  // start this server itself
+  virtual ~HostServer() {}
+
+  // implement input interfaces. called by webRTC
+  void TouchEvent(const int x, const int y, const bool is_down);
+  void UserAbortEvent();
+
+ private:
+  HostServer() = delete;
+
+  /**
+   * basic prompt flow:
+   * (1) Without preemption
+   *  send "kStart" with confirmation message
+   *  wait kCliAck from the host service with the echoed command
+   *  wait the confirmation/cancellation (or perhaps reset?)
+   *  send kStop
+   *  wait kCliAck from the host service with the echoed command
+   *
+   * (2) With preemption (e.g.)
+   *  send "kStart" with confirmation message
+   *  wait kCliAck from the host service with the echoed command
+   *  wait the confirmation/cancellation (or perhaps reset?)
+   *  send kSuspend  // when HAL is preempted
+   *  send kRestore  // when HAL resumes
+   *  send kStop
+   *
+   *  From the host end, it is a close-to-Mealy FSM.
+   *  There are four states S = {init, session, wait_ack, suspended}
+   *
+   *  'session' means in a confirmation session. 'wait_ack' means
+   *  server sends the confirmation and waiting "stop" command from HAL
+   *  'suspended' means the HAL service is preemptied. So, the host
+   *  should render the Android guest frames but keep the confirmation
+   *  UI session and frame
+   *
+   *  The inputs are I = {u, g}. 'u' is the user input from webRTC
+   *  clients. Note that the host service serialized the concurrent user
+   *  inputs from multiple clients. 'g' is the command from the HAL service
+   *
+   *  The transition rules:
+   *    (S, I) --> (S, O) where O is the output
+   *
+   *   init, g(start) -->  session, set Conf UI mode, render a frame
+   *   session, u(cancel/confirm) --> waitstop, send the result to HAL
+   *   session, g(suspend) --> suspend, create a saved session
+   *   session, g(abort)   --> init, clear saved frame
+   *   waitstop, g(stop) --> init, clear saved frame
+   *   waitstop, g(suspend) --> suspend, no need to save the session
+   *   waitstop, g(abort) --> init, clear saved frame
+   *   suspend, g(restore) --> return to the saved state, restore if there's a
+   *                           saved session
+   *   suspend, g(abort) --> init, clear saved frame
+   *
+   * For now, we did not yet implement suspend or abort.
+   *
+   */
+  [[noreturn]] void MainLoop();
+  void HalCmdFetcherLoop();
+
+  bool IsVirtioConsoleOpen() const;
+  // If !IsVirtioConsoleOpen(), LOG(FATAL) and return false
+  bool CheckVirtioConsole();
+  std::shared_ptr<Session> CreateSession(const std::string& session_name);
+  void SendUserSelection(std::unique_ptr<ConfUiMessage>& input);
+
+  void Transition(std::unique_ptr<ConfUiMessage>& input_ptr);
+  std::string GetCurrentSessionId() {
+    if (curr_session_) {
+      return curr_session_->GetId();
+    }
+    return SESSION_ANY;
+  }
+
+  std::string GetCurrentState() {
+    if (!curr_session_) {
+      return {"kInvalid"};
+    }
+    return ToString(curr_session_->GetState());
+  }
+
+  const std::uint32_t display_num_;
+  ConfUiRenderer& host_renderer_;
+  HostModeCtrl& host_mode_ctrl_;
+
+  std::shared_ptr<Session> curr_session_;
+
+  SharedFD from_guest_fifo_fd_;
+  SharedFD to_guest_fifo_fd_;
+
+  using Multiplexer =
+      Multiplexer<std::unique_ptr<ConfUiMessage>,
+                  ThreadSafeQueue<std::unique_ptr<ConfUiMessage>>>;
+  /*
+   * Multiplexer has N queues. When pop(), it is going to sleep until
+   * there's at least one item in at least one queue. The lower the Q
+   * index is, the higher the priority is.
+   *
+   * For HostServer, we have a queue for the user input events, and
+   * another for hal cmd/msg queues
+   */
+  Multiplexer input_multiplexer_;
+  int hal_cmd_q_id_;         // Q id in input_multiplexer_
+  int user_input_evt_q_id_;  // Q id in input_multiplexer_
+
+  std::thread main_loop_thread_;
+  std::thread hal_input_fetcher_thread_;
+};
+
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/host_utils.cc b/host/libs/confui/host_utils.cc
new file mode 100644
index 000000000..bc5d23ee9
--- /dev/null
+++ b/host/libs/confui/host_utils.cc
@@ -0,0 +1,77 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/confui/host_utils.h"
+
+namespace cuttlefish {
+namespace confui {
+namespace thread {
+std::string ThreadTracer::Get(const std::thread::id tid) {
+  std::lock_guard<std::mutex> lock(mtx_);
+  if (Contains(id2name_, tid)) {
+    return id2name_[tid];
+  }
+  std::stringstream ss;
+  ss << "Thread@" << tid;
+  return ss.str();
+}
+
+void ThreadTracer::Set(const std::string& name, const std::thread::id tid) {
+  std::lock_guard<std::mutex> lock(mtx_);
+  if (Contains(name2id_, name)) {
+    // has the name already
+    if (name2id_[name] != tid) {  // used for another thread
+      ConfUiLog(FATAL) << "Thread name is duplicated.";
+    }
+    // name and id are already set correctly
+    return;
+  }
+  if (Contains(id2name_, tid)) {
+    // tid exists but has a different name
+    name2id_.erase(id2name_[tid]);  // delete old_name -> tid map
+  }
+  id2name_[tid] = name;
+  name2id_[name] = tid;
+  return;
+}
+
+std::optional<std::thread::id> ThreadTracer::Get(const std::string& name) {
+  std::lock_guard<std::mutex> lock(mtx_);
+  if (Contains(name2id_, name)) {
+    return {name2id_[name]};
+  }
+  return std::nullopt;
+}
+
+ThreadTracer& GetThreadTracer() {
+  static ThreadTracer thread_tracer;
+  return thread_tracer;
+}
+
+std::string GetName(const std::thread::id tid) {
+  return GetThreadTracer().Get(tid);
+}
+
+std::optional<std::thread::id> GetId(const std::string& name) {
+  return GetThreadTracer().Get(name);
+}
+
+void Set(const std::string& name, const std::thread::id tid) {
+  GetThreadTracer().Set(name, tid);
+}
+}  // namespace thread
+}  // namespace confui
+}  // namespace cuttlefish
diff --git a/host/libs/confui/host_utils.h b/host/libs/confui/host_utils.h
new file mode 100644
index 000000000..403741901
--- /dev/null
+++ b/host/libs/confui/host_utils.h
@@ -0,0 +1,102 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <functional>
+#include <map>
+#include <mutex>
+#include <optional>
+#include <sstream>
+#include <string>
+#include <thread>
+
+#include <android-base/logging.h>
+
+#include "common/libs/confui/confui.h"
+#include "common/libs/utils/contains.h"
+#include "host/commands/kernel_log_monitor/utils.h"
+#include "host/libs/config/logging.h"
+
+namespace cuttlefish {
+namespace confui {
+
+namespace thread {
+/* thread id to name
+ * these three functions internally uses the singleton ThreadTracer object.
+ *
+ * When running a thread, use the global RunThread function
+ */
+std::string GetName(const std::thread::id tid = std::this_thread::get_id());
+std::optional<std::thread::id> GetId(const std::string& name);
+void Set(const std::string& name, const std::thread::id tid);
+
+/*
+ * This is wrapping std::thread. However, we keep the bidirectional map
+ * between the given thread name and the thread id. The main purpose is
+ * to help debugging.
+ *
+ */
+template <typename F, typename... Args>
+std::thread RunThread(const std::string& name, F&& f, Args&&... args);
+
+class ThreadTracer;
+ThreadTracer& GetThreadTracer();
+
+class ThreadTracer {
+  friend ThreadTracer& GetThreadTracer();
+  friend std::string GetName(const std::thread::id tid);
+  friend std::optional<std::thread::id> GetId(const std::string& name);
+  friend void Set(const std::string& name, const std::thread::id tid);
+
+  template <typename F, typename... Args>
+  friend std::thread RunThread(const std::string& name, F&& f, Args&&... args);
+
+ private:
+  template <typename F, typename... Args>
+  std::thread RunThread(const std::string& name, F&& f, Args&&... args) {
+    auto th = std::thread(std::forward<F>(f), std::forward<Args>(args)...);
+    if (Contains(name2id_, name)) {
+      ConfUiLog(FATAL) << "Thread name is duplicated";
+    }
+    name2id_[name] = th.get_id();
+    id2name_[th.get_id()] = name;
+    ConfUiLog(DEBUG) << name << "thread started.";
+    return th;
+  }
+  std::string Get(const std::thread::id id = std::this_thread::get_id());
+  std::optional<std::thread::id> Get(const std::string& name);
+
+  // add later on even though it wasn't started with RunThread
+  // if tid is already added, update the name only
+  void Set(const std::string& name, const std::thread::id tid);
+
+  ThreadTracer() = default;
+  std::map<std::thread::id, std::string> id2name_;
+  std::map<std::string, std::thread::id> name2id_;
+  std::mutex mtx_;
+};
+
+template <typename F, typename... Args>
+std::thread RunThread(const std::string& name, F&& f, Args&&... args) {
+  auto& tracer = GetThreadTracer();
+  return tracer.RunThread(name, std::forward<F>(f),
+                          std::forward<Args>(args)...);
+}
+
+}  // namespace thread
+}  // namespace confui
+}  // namespace cuttlefish
diff --git a/host/libs/confui/host_virtual_input.cc b/host/libs/confui/host_virtual_input.cc
new file mode 100644
index 000000000..511688680
--- /dev/null
+++ b/host/libs/confui/host_virtual_input.cc
@@ -0,0 +1,128 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0f
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/confui/host_virtual_input.h"
+
+#include <android-base/logging.h>
+
+namespace cuttlefish {
+namespace confui {
+
+HostVirtualInput::HostVirtualInput(HostServer& host_server,
+                                   HostModeCtrl& host_mode_ctrl,
+                                   InputConnector& android_mode_input)
+    : host_server_(host_server),
+      host_mode_ctrl_(host_mode_ctrl),
+      android_mode_input_(android_mode_input) {}
+
+void HostVirtualInput::UserAbortEvent() { host_server_.UserAbortEvent(); }
+
+bool HostVirtualInput::IsConfUiActive() {
+  return host_mode_ctrl_.IsConfirmatioUiMode();
+}
+
+class HostVirtualInputEventSink : public InputConnector::EventSink {
+ public:
+  HostVirtualInputEventSink(std::unique_ptr<EventSink> android_mode_input,
+                            HostVirtualInput& host_virtual_input)
+      : android_mode_input_(std::move(android_mode_input)),
+        host_virtual_input_(host_virtual_input) {}
+
+  // EventSink implementation
+  Result<void> SendTouchEvent(const std::string& device_label, int x, int y,
+                              bool down) override;
+  Result<void> SendMultiTouchEvent(const std::string& device_label,
+                                   const std::vector<MultitouchSlot>& slots,
+                                   bool down) override;
+  Result<void> SendKeyboardEvent(uint16_t code, bool down) override;
+  Result<void> SendRotaryEvent(int pixels) override;
+  Result<void> SendSwitchesEvent(uint16_t code, bool state) override;
+
+ private:
+  std::unique_ptr<EventSink> android_mode_input_;
+  HostVirtualInput& host_virtual_input_;
+};
+
+Result<void> HostVirtualInputEventSink::SendTouchEvent(
+    const std::string& device_label, int x, int y, bool down) {
+  if (!host_virtual_input_.IsConfUiActive()) {
+    return android_mode_input_->SendTouchEvent(device_label, x, y, down);
+  }
+
+  if (down) {
+    ConfUiLog(INFO) << "TouchEvent occurs in Confirmation UI Mode at [" << x
+                    << ", " << y << "]";
+    host_virtual_input_.host_server().TouchEvent(x, y, down);
+  }
+  return {};
+}
+
+Result<void> HostVirtualInputEventSink::SendMultiTouchEvent(
+    const std::string& device_label, const std::vector<MultitouchSlot>& slots,
+    bool down) {
+  if (!host_virtual_input_.IsConfUiActive()) {
+    CF_EXPECT(
+        android_mode_input_->SendMultiTouchEvent(device_label, slots, down));
+    return {};
+  }
+  for (auto& slot : slots) {
+    if (down) {
+      auto this_x = slot.x;
+      auto this_y = slot.y;
+      ConfUiLog(INFO) << "TouchEvent occurs in Confirmation UI Mode at ["
+                      << this_x << ", " << this_y << "]";
+      host_virtual_input_.host_server().TouchEvent(this_x, this_y, down);
+    }
+  }
+  return {};
+}
+
+Result<void> HostVirtualInputEventSink::SendKeyboardEvent(uint16_t code,
+                                                          bool down) {
+  if (!host_virtual_input_.IsConfUiActive()) {
+    CF_EXPECT(android_mode_input_->SendKeyboardEvent(code, down));
+    return {};
+  }
+  ConfUiLog(VERBOSE) << "keyboard event ignored in confirmation UI mode";
+  return {};
+}
+
+Result<void> HostVirtualInputEventSink::SendRotaryEvent(int pixels) {
+  if (!host_virtual_input_.IsConfUiActive()) {
+    CF_EXPECT(android_mode_input_->SendRotaryEvent(pixels));
+    return {};
+  }
+  ConfUiLog(VERBOSE) << "rotary event ignored in confirmation UI mode";
+  return {};
+}
+
+Result<void> HostVirtualInputEventSink::SendSwitchesEvent(uint16_t code,
+                                                          bool state) {
+  if (!host_virtual_input_.IsConfUiActive()) {
+    CF_EXPECT(android_mode_input_->SendSwitchesEvent(code, state));
+    return {};
+  }
+  ConfUiLog(VERBOSE) << "switches event ignored in confirmation UI mode";
+  return {};
+}
+
+std::unique_ptr<InputConnector::EventSink> HostVirtualInput::CreateSink() {
+  return std::unique_ptr<EventSink>(
+      new HostVirtualInputEventSink(android_mode_input_.CreateSink(), *this));
+}
+
+}  // namespace confui
+}  // namespace cuttlefish
diff --git a/host/libs/confui/host_virtual_input.h b/host/libs/confui/host_virtual_input.h
new file mode 100644
index 000000000..808d04e8c
--- /dev/null
+++ b/host/libs/confui/host_virtual_input.h
@@ -0,0 +1,59 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0f
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <cstdint>
+
+#include <memory>
+
+#include <fruit/fruit.h>
+
+#include "host/libs/confui/host_server.h"
+#include "host/libs/input_connector/input_connector.h"
+
+namespace cuttlefish {
+namespace confui {
+enum class ConfUiKeys : std::uint32_t { Confirm = 7, Cancel = 8 };
+
+/**
+ * webrtc will deliver the user inputs from their client
+ * to this class object
+ */
+class HostVirtualInput : public InputConnector {
+ public:
+  INJECT(HostVirtualInput(HostServer& host_server, HostModeCtrl& host_mode_ctrl,
+                          InputConnector& android_mode_input));
+
+  ~HostVirtualInput() = default;
+
+  void UserAbortEvent();
+
+  // guarantees that if this returns true, it is confirmation UI mode
+  bool IsConfUiActive();
+
+  HostServer& host_server() { return host_server_; }
+
+  // InputConnector implementation.
+  std::unique_ptr<EventSink> CreateSink() override;
+
+ private:
+  HostServer& host_server_;
+  HostModeCtrl& host_mode_ctrl_;
+  InputConnector& android_mode_input_;
+};
+}  // namespace confui
+}  // namespace cuttlefish
diff --git a/host/libs/confui/layouts/fonts.h b/host/libs/confui/layouts/fonts.h
new file mode 100644
index 000000000..cdba8d0c4
--- /dev/null
+++ b/host/libs/confui/layouts/fonts.h
@@ -0,0 +1,30 @@
+/*
+ * Copyright 2021, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <teeui/incfont.h>
+
+/*
+ * Each entry TEEUI_INCFONT(<name>) declares:
+ *    extern unsigned char <name>[];
+ *    extern unsigned int <name>_length;
+ * The first one pointing to a raw ttf font file in the .rodata section, and the
+ * second being the size of the buffer.
+ */
+TEEUI_INCFONT(RobotoMedium);
+TEEUI_INCFONT(RobotoRegular);
+TEEUI_INCFONT(Shield);
diff --git a/host/libs/confui/layouts/layout.h b/host/libs/confui/layouts/layout.h
new file mode 100644
index 000000000..4f6c4dcfa
--- /dev/null
+++ b/host/libs/confui/layouts/layout.h
@@ -0,0 +1,165 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <teeui/button.h>
+#include <teeui/label.h>
+#include <teeui/localization/ConfirmationUITranslations.h>
+#include <teeui/utils.h>
+
+#include "fonts.h"
+
+using teeui::localization::TranslationId;
+
+namespace teeui {
+
+DECLARE_PARAMETER(RightEdgeOfScreen);
+DECLARE_PARAMETER(BottomOfScreen);
+DECLARE_PARAMETER(DefaultFontSize);  // 14_dp regular and 18_dp magnified
+DECLARE_PARAMETER(BodyFontSize);     // 16_dp regular and 20_dp magnified
+DECLARE_TYPED_PARAMETER(ShieldColor, ::teeui::Color);
+DECLARE_TYPED_PARAMETER(ColorText, ::teeui::Color);
+DECLARE_TYPED_PARAMETER(ColorBG, ::teeui::Color);
+
+CONSTANT(BorderWidth, 24_dp);
+
+DECLARE_FONT_BUFFER(RobotoMedium, RobotoMedium, RobotoMedium_length);
+DECLARE_FONT_BUFFER(RobotoRegular, RobotoRegular, RobotoRegular_length);
+DECLARE_FONT_BUFFER(Shield, Shield, Shield_length);
+
+CONSTANT(DefaultFont, FONT(RobotoRegular));
+
+DECLARE_TYPED_PARAMETER(ColorButton, ::teeui::Color);
+
+NEW_PARAMETER_SET(ConfUIParameters, RightEdgeOfScreen, BottomOfScreen,
+                  DefaultFontSize, BodyFontSize, ShieldColor, ColorText,
+                  ColorBG, ColorButton);
+
+CONSTANT(IconShieldDistanceFromTop, 100_dp);
+CONSTANT(LabelBorderZone, 4_dp);
+CONSTANT(RightLabelEdge, RightEdgeOfScreen() - BorderWidth);
+CONSTANT(LabelWidth, RightLabelEdge - BorderWidth);
+CONSTANT(ButtonHeight, 72_dp);
+CONSTANT(ButtonPositionX, 0);
+CONSTANT(ButtonPositionY, BottomOfScreen() - ButtonHeight);
+CONSTANT(ButtonWidth, 130_dp);
+CONSTANT(ButtonLabelDistance, 12_dp);
+
+BEGIN_ELEMENT(IconShield, teeui::Label)
+FontSize(24_dp);
+LineHeight(24_dp);
+NumberOfLines(1);
+Dimension(LabelWidth, HeightFromLines);
+Position(BorderWidth, IconShieldDistanceFromTop);
+DefaultText(
+    "A");  // ShieldTTF has just one glyph at the code point for capital A
+TextColor(ShieldColor());
+HorizontalTextAlignment(Alignment::CENTER);
+Font(FONT(Shield));
+END_ELEMENT();
+
+BEGIN_ELEMENT(LabelTitle, teeui::Label)
+FontSize(20_dp);
+LineHeight(20_dp);
+NumberOfLines(1);
+Dimension(LabelWidth, HeightFromLines);
+Position(BorderWidth, BOTTOM_EDGE_OF(IconShield) + 16_dp);
+DefaultText("Android Protected Confirmation");
+Font(FONT(RobotoMedium));
+VerticallyCentered;
+TextColor(ColorText());
+TextID(TEXT_ID(TranslationId::TITLE));
+END_ELEMENT();
+
+BEGIN_ELEMENT(IconOk, teeui::Button, ConvexObjectCount(1))
+Dimension(ButtonWidth, ButtonHeight - BorderWidth);
+Position(RightEdgeOfScreen() - ButtonWidth - BorderWidth,
+         ButtonPositionY + ButtonLabelDistance);
+CornerRadius(4_dp);
+ButtonColor(ColorButton());
+RoundTopLeft;
+RoundBottomLeft;
+RoundTopRight;
+RoundBottomRight;
+END_ELEMENT();
+
+BEGIN_ELEMENT(LabelOK, teeui::Label)
+FontSize(BodyFontSize());
+LineHeight(BodyFontSize() * 1.4_px);
+NumberOfLines(1);
+Dimension(ButtonWidth - (LabelBorderZone * 2_dp),
+          ButtonHeight - BorderWidth - (LabelBorderZone * 2_dp));
+Position(RightEdgeOfScreen() - ButtonWidth - BorderWidth + LabelBorderZone,
+         ButtonPositionY + ButtonLabelDistance + LabelBorderZone);
+DefaultText("Confirm");
+Font(FONT(RobotoMedium));
+HorizontalTextAlignment(Alignment::CENTER);
+VerticalTextAlignment(Alignment::CENTER);
+TextColor(ColorBG());
+TextID(TEXT_ID(TranslationId::CONFIRM));
+END_ELEMENT();
+
+BEGIN_ELEMENT(LabelCancel, teeui::Label)
+FontSize(BodyFontSize());
+LineHeight(BodyFontSize() * 1.4_px);
+NumberOfLines(1);
+Dimension(ButtonWidth - (LabelBorderZone * 2_dp),
+          ButtonHeight - BorderWidth - (LabelBorderZone * 2_dp));
+Position(BorderWidth + LabelBorderZone,
+         ButtonPositionY + ButtonLabelDistance + LabelBorderZone);
+DefaultText("Cancel");
+HorizontalTextAlignment(Alignment::LEFT);
+Font(FONT(RobotoMedium));
+VerticallyCentered;
+TextColor(ColorButton());
+TextID(TEXT_ID(TranslationId::CANCEL));
+END_ELEMENT();
+
+BEGIN_ELEMENT(LabelHint, teeui::Label)
+FontSize(DefaultFontSize());
+LineHeight(DefaultFontSize() * 1.5_px);
+NumberOfLines(4);
+Dimension(LabelWidth, HeightFromLines);
+Position(BorderWidth, ButtonPositionY - dim_h - 48_dp);
+DefaultText(
+    "This confirmation provides an extra layer of security for the action "
+    "you're "
+    "about to take.");
+VerticalTextAlignment(Alignment::BOTTOM);
+TextColor(ColorText());
+Font(DefaultFont);
+TextID(TEXT_ID(TranslationId::DESCRIPTION));
+END_ELEMENT();
+
+BEGIN_ELEMENT(LabelBody, teeui::Label)
+FontSize(BodyFontSize());
+LineHeight(BodyFontSize() * 1.4_px);
+NumberOfLines(20);
+Position(BorderWidth, BOTTOM_EDGE_OF(LabelTitle) + 16_dp);
+Dimension(LabelWidth, LabelHint::pos_y - pos_y - 24_dp);
+DefaultText(
+    "12345678901234567890123456789012345678901234567890123456789012345678901234"
+    "567890123456"
+    "78901234567890");
+TextColor(ColorText());
+Font(FONT(RobotoRegular));
+END_ELEMENT();
+
+NEW_LAYOUT(ConfUILayout, IconShield, LabelTitle, LabelHint, LabelBody, IconOk,
+           LabelOK, LabelCancel);
+
+}  // namespace teeui
diff --git a/host/libs/confui/secure_input.cc b/host/libs/confui/secure_input.cc
new file mode 100644
index 000000000..0ce6f2292
--- /dev/null
+++ b/host/libs/confui/secure_input.cc
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/confui/secure_input.h"
+
+namespace cuttlefish {
+namespace confui {
+namespace {
+
+template <typename T>
+auto CheckAndReturnSessionId(const std::unique_ptr<T>& msg) {
+  CHECK(msg) << "ConfUiUserSelectionMessage must not be null";
+  return msg->GetSessionId();
+}
+
+}  // end of namespace
+
+ConfUiSecureUserSelectionMessage::ConfUiSecureUserSelectionMessage(
+    std::unique_ptr<ConfUiUserSelectionMessage>&& msg, const bool secure)
+    : ConfUiMessage(CheckAndReturnSessionId(msg)),
+      msg_(std::move(msg)),
+      is_secure_(secure) {}
+
+ConfUiSecureUserTouchMessage::ConfUiSecureUserTouchMessage(
+    std::unique_ptr<ConfUiUserTouchMessage>&& msg, const bool secure)
+    : ConfUiMessage(CheckAndReturnSessionId(msg)),
+      msg_(std::move(msg)),
+      is_secure_(secure) {}
+
+std::unique_ptr<ConfUiSecureUserSelectionMessage> ToSecureSelectionMessage(
+    std::unique_ptr<ConfUiUserSelectionMessage>&& msg, const bool secure) {
+  return std::make_unique<ConfUiSecureUserSelectionMessage>(std::move(msg),
+                                                            secure);
+}
+
+std::unique_ptr<ConfUiSecureUserTouchMessage> ToSecureTouchMessage(
+    std::unique_ptr<ConfUiUserTouchMessage>&& msg, const bool secure) {
+  return std::make_unique<ConfUiSecureUserTouchMessage>(std::move(msg), secure);
+}
+
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/secure_input.h b/host/libs/confui/secure_input.h
new file mode 100644
index 000000000..a56af5e29
--- /dev/null
+++ b/host/libs/confui/secure_input.h
@@ -0,0 +1,75 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <memory>
+
+#include "common/libs/confui/confui.h"
+
+/** ConfUiUserSelectionMessage with a security flag
+ *
+ * Inputs generated by something that belong to (virtualized) TEE is regarded
+ * as secure. Otherwise (e.g. inputs generated by the guest calling
+ * deliverSecureInputEvent), it is regarded as insecure.
+ *
+ * The host marks the security field, and use it internally and exclusively.
+ *
+ */
+namespace cuttlefish {
+namespace confui {
+class ConfUiSecureUserSelectionMessage : public ConfUiMessage {
+ public:
+  ConfUiSecureUserSelectionMessage(
+      std::unique_ptr<ConfUiUserSelectionMessage>&& msg, const bool secure);
+  ConfUiSecureUserSelectionMessage() = delete;
+  virtual ~ConfUiSecureUserSelectionMessage() = default;
+  std::string ToString() const override { return msg_->ToString(); }
+  ConfUiCmd GetType() const override { return msg_->GetType(); }
+  auto GetResponse() const { return msg_->GetResponse(); }
+  // SendOver is between guest and host, so it doesn't send the is_secure_
+  bool SendOver(SharedFD fd) override { return msg_->SendOver(fd); }
+  bool IsSecure() const { return is_secure_; }
+  // SetSecure() might be needed later on but not now.
+
+ private:
+  std::unique_ptr<ConfUiUserSelectionMessage> msg_;
+  bool is_secure_;
+};
+
+class ConfUiSecureUserTouchMessage : public ConfUiMessage {
+ public:
+  ConfUiSecureUserTouchMessage(std::unique_ptr<ConfUiUserTouchMessage>&& msg,
+                               const bool secure);
+  virtual ~ConfUiSecureUserTouchMessage() = default;
+  std::string ToString() const override { return msg_->ToString(); }
+  ConfUiCmd GetType() const override { return msg_->GetType(); }
+  auto GetResponse() const { return msg_->GetResponse(); }
+  bool SendOver(SharedFD fd) override { return msg_->SendOver(fd); }
+  std::pair<int, int> GetLocation() const { return msg_->GetLocation(); }
+  bool IsSecure() const { return is_secure_; }
+
+ private:
+  std::unique_ptr<ConfUiUserTouchMessage> msg_;
+  bool is_secure_;
+};
+
+std::unique_ptr<ConfUiSecureUserSelectionMessage> ToSecureSelectionMessage(
+    std::unique_ptr<ConfUiUserSelectionMessage>&& msg, const bool secure);
+std::unique_ptr<ConfUiSecureUserTouchMessage> ToSecureTouchMessage(
+    std::unique_ptr<ConfUiUserTouchMessage>&& msg, const bool secure);
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/server_common.cc b/host/libs/confui/server_common.cc
new file mode 100644
index 000000000..66adb5560
--- /dev/null
+++ b/host/libs/confui/server_common.cc
@@ -0,0 +1,78 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/confui/server_common.h"
+namespace cuttlefish {
+namespace confui {
+FsmInput ToFsmInput(const ConfUiMessage& msg) {
+  const auto cmd = msg.GetType();
+  switch (cmd) {
+    case ConfUiCmd::kUserInputEvent:
+      return FsmInput::kUserEvent;
+    case ConfUiCmd::kUnknown:
+      return FsmInput::kHalUnknown;
+    case ConfUiCmd::kStart:
+      return FsmInput::kHalStart;
+    case ConfUiCmd::kStop:
+      return FsmInput::kHalStop;
+    case ConfUiCmd::kAbort:
+      return FsmInput::kHalAbort;
+    case ConfUiCmd::kCliAck:
+    case ConfUiCmd::kCliRespond:
+    default:
+      ConfUiLog(FATAL) << "The" << ToString(cmd)
+                       << "is not handled by the Session FSM but "
+                       << "directly calls Abort()";
+  }
+  return FsmInput::kHalUnknown;
+}
+
+std::string ToString(FsmInput input) {
+  switch (input) {
+    case FsmInput::kUserEvent:
+      return {"kUserEvent"};
+    case FsmInput::kHalStart:
+      return {"kHalStart"};
+    case FsmInput::kHalStop:
+      return {"kHalStop"};
+    case FsmInput::kHalAbort:
+      return {"kHalAbort"};
+    case FsmInput::kHalUnknown:
+    default:
+      break;
+  }
+  return {"kHalUnknown"};
+}
+
+std::string ToString(const MainLoopState& state) {
+  switch (state) {
+    case MainLoopState::kInit:
+      return "kInit";
+    case MainLoopState::kInSession:
+      return "kInSession";
+    case MainLoopState::kWaitStop:
+      return "kWaitStop";
+    case MainLoopState::kAwaitCleanup:
+      return "kAwaitCleanup";
+    case MainLoopState::kTerminated:
+      return "kTerminated";
+    default:
+      return "kInvalid";
+  }
+}
+
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/server_common.h b/host/libs/confui/server_common.h
new file mode 100644
index 000000000..8ffd57859
--- /dev/null
+++ b/host/libs/confui/server_common.h
@@ -0,0 +1,55 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <cstdint>
+#include <memory>
+#include <vector>
+
+#include "common/libs/confui/confui.h"
+
+namespace cuttlefish {
+namespace confui {
+enum class MainLoopState : std::uint32_t {
+  kInit = 1,
+  kInSession = 2,
+  kWaitStop = 3,  // wait ack after sending confirm/cancel
+  kAwaitCleanup = 5,
+  kTerminated = 8,
+  kInvalid = 9
+};
+
+using TeeUiFrame = std::vector<std::uint32_t>;
+
+// FSM input to Session FSM
+enum class FsmInput : std::uint32_t {
+  kUserEvent = 1,
+  kHalStart,
+  kHalStop,
+  kHalAbort,
+  kHalUnknown
+};
+
+std::string ToString(FsmInput input);
+std::string ToString(const MainLoopState& state);
+
+FsmInput ToFsmInput(const ConfUiMessage& msg);
+
+std::unique_ptr<ConfUiMessage> CreateFromUserSelection(
+    const std::string& session_id, const UserResponse::type user_selection);
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/session.cc b/host/libs/confui/session.cc
new file mode 100644
index 000000000..b2cf1985a
--- /dev/null
+++ b/host/libs/confui/session.cc
@@ -0,0 +1,274 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/confui/session.h"
+
+#include <algorithm>
+
+#include "common/libs/utils/contains.h"
+#include "host/libs/confui/secure_input.h"
+
+namespace cuttlefish {
+namespace confui {
+
+Session::Session(const std::string& session_name,
+                 const std::uint32_t display_num, ConfUiRenderer& host_renderer,
+                 HostModeCtrl& host_mode_ctrl, const std::string& locale)
+    : session_id_{session_name},
+      display_num_{display_num},
+      renderer_{host_renderer},
+      host_mode_ctrl_{host_mode_ctrl},
+      locale_{locale},
+      state_{MainLoopState::kInit},
+      saved_state_{MainLoopState::kInit} {}
+
+/** return grace period + alpha
+ *
+ * grace period is the gap between user seeing the dialog
+ * and the UI starts to take the user inputs
+ * Grace period should be at least 1s.
+ * Session requests the Renderer to render the dialog,
+ * but it might not be immediate. So, add alpha to 1s
+ */
+static const std::chrono::milliseconds GetGracePeriod() {
+  using std::literals::chrono_literals::operator""ms;
+  return 1000ms + 100ms;
+}
+
+bool Session::IsReadyForUserInput() const {
+  using std::literals::chrono_literals::operator""ms;
+  if (!start_time_) {
+    return false;
+  }
+  const auto right_now = Clock::now();
+  return (right_now - *start_time_) >= GetGracePeriod();
+}
+
+bool Session::RenderDialog() {
+  auto result =
+      renderer_.RenderDialog(display_num_, prompt_text_, locale_, ui_options_);
+  if (!result.ok()) {
+    LOG(ERROR) << result.error().FormatForEnv();
+    return false;
+  }
+  return true;
+}
+
+MainLoopState Session::Transition(SharedFD& hal_cli, const FsmInput fsm_input,
+                                  const ConfUiMessage& conf_ui_message) {
+  bool should_keep_running = false;
+  bool already_terminated = false;
+  switch (state_) {
+    case MainLoopState::kInit: {
+      should_keep_running = HandleInit(hal_cli, fsm_input, conf_ui_message);
+    } break;
+    case MainLoopState::kInSession: {
+      should_keep_running =
+          HandleInSession(hal_cli, fsm_input, conf_ui_message);
+    } break;
+    case MainLoopState::kWaitStop: {
+      if (IsUserInput(fsm_input)) {
+        ConfUiLog(VERBOSE) << "User input ignored " << ToString(fsm_input)
+                           << " : " << ToString(conf_ui_message)
+                           << " at the state " << ToString(state_);
+      }
+      should_keep_running = HandleWaitStop(hal_cli, fsm_input);
+    } break;
+    case MainLoopState::kTerminated: {
+      already_terminated = true;
+    } break;
+    default:
+      ConfUiLog(FATAL) << "Must not be in the state of " << ToString(state_);
+      break;
+  }
+  if (!should_keep_running && !already_terminated) {
+    ScheduleToTerminate();
+  }
+  return state_;
+};
+
+void Session::CleanUp() {
+  if (state_ != MainLoopState::kAwaitCleanup) {
+    ConfUiLog(FATAL) << "Clean up a session only when in kAwaitCleanup";
+  }
+  state_ = MainLoopState::kTerminated;
+  // common action done when the state is back to init state
+  host_mode_ctrl_.SetMode(HostModeCtrl::ModeType::kAndroidMode);
+}
+
+void Session::ScheduleToTerminate() {
+  state_ = MainLoopState::kAwaitCleanup;
+  saved_state_ = MainLoopState::kInvalid;
+}
+
+bool Session::ReportErrorToHal(SharedFD hal_cli, const std::string& msg) {
+  ScheduleToTerminate();
+  if (!SendAck(hal_cli, session_id_, false, msg)) {
+    ConfUiLog(ERROR) << "I/O error in sending ack to report rendering failure";
+    return false;
+  }
+  return true;
+}
+
+void Session::Abort() {
+  ConfUiLog(VERBOSE) << "Abort is called";
+  ScheduleToTerminate();
+  return;
+}
+
+void Session::UserAbort(SharedFD hal_cli) {
+  ConfUiLog(VERBOSE) << "it is a user abort input.";
+  SendAbortCmd(hal_cli, GetId());
+  Abort();
+  ScheduleToTerminate();
+}
+
+bool Session::HandleInit(SharedFD hal_cli, const FsmInput fsm_input,
+                         const ConfUiMessage& conf_ui_message) {
+  if (IsUserInput(fsm_input)) {
+    // ignore user input
+    state_ = MainLoopState::kInit;
+    return true;
+  }
+
+  ConfUiLog(VERBOSE) << ToString(fsm_input) << "is handled in HandleInit";
+  if (fsm_input != FsmInput::kHalStart) {
+    ConfUiLog(ERROR) << "invalid cmd for Init State:" << ToString(fsm_input);
+    // ReportErrorToHal returns true if error report was successful
+    // However, anyway we abort this session on the host
+    ReportErrorToHal(hal_cli, HostError::kSystemError);
+    return false;
+  }
+
+  // Start Session
+  ConfUiLog(VERBOSE) << "Sending ack to hal_cli: "
+                     << Enum2Base(ConfUiCmd::kCliAck);
+  host_mode_ctrl_.SetMode(HostModeCtrl::ModeType::kConfUI_Mode);
+
+  auto start_cmd_msg = static_cast<const ConfUiStartMessage&>(conf_ui_message);
+  prompt_text_ = start_cmd_msg.GetPromptText();
+  locale_ = start_cmd_msg.GetLocale();
+  extra_data_ = start_cmd_msg.GetExtraData();
+  ui_options_ = start_cmd_msg.GetUiOpts();
+
+  // cbor_ can be correctly created after the session received kStart cmd
+  // at runtime
+  cbor_ = std::make_unique<Cbor>(prompt_text_, extra_data_);
+  if (cbor_->IsMessageTooLong()) {
+    ConfUiLog(ERROR) << "The prompt text and extra_data are too long to be "
+                     << "properly encoded.";
+    ReportErrorToHal(hal_cli, HostError::kMessageTooLongError);
+    return false;
+  }
+  if (cbor_->IsMalformedUtf8()) {
+    ConfUiLog(ERROR) << "The prompt text appears to have incorrect UTF8 format";
+    ReportErrorToHal(hal_cli, HostError::kIncorrectUTF8);
+    return false;
+  }
+  if (!cbor_->IsOk()) {
+    ConfUiLog(ERROR) << "Unknown Error in cbor implementation";
+    ReportErrorToHal(hal_cli, HostError::kSystemError);
+    return false;
+  }
+
+  if (!RenderDialog()) {
+    // the confirmation UI is driven by a user app, not running from the start
+    // automatically so that means webRTC should have been set up
+    ConfUiLog(ERROR) << "Dialog is not rendered. However, it should."
+                     << "No webRTC can't initiate any confirmation UI.";
+    ReportErrorToHal(hal_cli, HostError::kUIError);
+    return false;
+  }
+  start_time_ = std::make_unique<TimePoint>(Clock::now());
+  if (!SendAck(hal_cli, session_id_, true, "started")) {
+    ConfUiLog(ERROR) << "Ack to kStart failed in I/O";
+    return false;
+  }
+  state_ = MainLoopState::kInSession;
+  return true;
+}
+
+bool Session::HandleInSession(SharedFD hal_cli, const FsmInput fsm_input,
+                              const ConfUiMessage& conf_ui_msg) {
+  auto invalid_input_handler = [&, this]() {
+    ReportErrorToHal(hal_cli, HostError::kSystemError);
+    ConfUiLog(ERROR) << "cmd " << ToString(fsm_input)
+                     << " should not be handled in HandleInSession";
+  };
+
+  if (!IsUserInput(fsm_input)) {
+    invalid_input_handler();
+    return false;
+  }
+
+  const auto& user_input_msg =
+      static_cast<const ConfUiSecureUserSelectionMessage&>(conf_ui_msg);
+  const auto response = user_input_msg.GetResponse();
+  if (response == UserResponse::kUnknown ||
+      response == UserResponse::kUserAbort) {
+    invalid_input_handler();
+    return false;
+  }
+  const bool is_secure_input = user_input_msg.IsSecure();
+
+  ConfUiLog(VERBOSE) << "In HandleInSession, session " << session_id_
+                     << " is sending the user input " << ToString(fsm_input);
+
+  bool is_success = false;
+  if (response == UserResponse::kCancel) {
+    // no need to sign
+    is_success =
+        SendResponse(hal_cli, session_id_, UserResponse::kCancel,
+                     std::vector<std::uint8_t>{}, std::vector<std::uint8_t>{});
+  } else {
+    message_ = std::move(cbor_->GetMessage());
+    auto message_opt = (is_secure_input ? Sign(message_) : TestSign(message_));
+    if (!message_opt) {
+      ReportErrorToHal(hal_cli, HostError::kSystemError);
+      return false;
+    }
+    signed_confirmation_ = message_opt.value();
+    is_success = SendResponse(hal_cli, session_id_, UserResponse::kConfirm,
+                              signed_confirmation_, message_);
+  }
+
+  if (!is_success) {
+    ConfUiLog(ERROR) << "I/O error in sending user response to HAL";
+    return false;
+  }
+  state_ = MainLoopState::kWaitStop;
+  return true;
+}
+
+bool Session::HandleWaitStop(SharedFD hal_cli, const FsmInput fsm_input) {
+  if (IsUserInput(fsm_input)) {
+    // ignore user input
+    state_ = MainLoopState::kWaitStop;
+    return true;
+  }
+  if (fsm_input == FsmInput::kHalStop) {
+    ConfUiLog(VERBOSE) << "Handling Abort in kWaitStop.";
+    ScheduleToTerminate();
+    return true;
+  }
+  ReportErrorToHal(hal_cli, HostError::kSystemError);
+  ConfUiLog(FATAL) << "In WaitStop, received wrong HAL command "
+                   << ToString(fsm_input);
+  return false;
+}
+
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/session.h b/host/libs/confui/session.h
new file mode 100644
index 000000000..ad4046f46
--- /dev/null
+++ b/host/libs/confui/session.h
@@ -0,0 +1,139 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <atomic>
+#include <chrono>
+#include <memory>
+#include <string>
+
+#include <teeui/msg_formatting.h>
+
+#include "common/libs/confui/confui.h"
+#include "host/libs/confui/cbor.h"
+#include "host/libs/confui/host_mode_ctrl.h"
+#include "host/libs/confui/host_renderer.h"
+#include "host/libs/confui/server_common.h"
+#include "host/libs/confui/sign.h"
+
+namespace cuttlefish {
+namespace confui {
+
+/**
+ * Confirmation UI Session
+ *
+ * E.g. Two guest apps could drive confirmation UI respectively,
+ * and both are alive at the moment. Each needs one session
+ *
+ */
+class Session {
+ public:
+  Session(const std::string& session_name, const std::uint32_t display_num,
+          ConfUiRenderer& host_renderer, HostModeCtrl& host_mode_ctrl,
+          const std::string& locale = "en");
+
+  std::string GetId() { return session_id_; }
+
+  MainLoopState GetState() { return state_; }
+
+  MainLoopState Transition(SharedFD& hal_cli, const FsmInput fsm_input,
+                           const ConfUiMessage& conf_ui_message);
+
+  /**
+   * this make a transition from kWaitStop or kInSession to kSuspend
+   */
+  bool Suspend(SharedFD hal_cli);
+
+  /**
+   * this make a transition from kRestore to the saved state
+   */
+  bool Restore(SharedFD hal_cli);
+
+  // abort session
+  void Abort();
+
+  // client on the host wants to abort
+  // should let the guest know it
+  void UserAbort(SharedFD hal_cli);
+
+  bool IsSuspended() const;
+  void CleanUp();
+
+  bool IsConfirm(const int x, const int y) {
+    return renderer_.IsInConfirm(x, y);
+  }
+
+  bool IsCancel(const int x, const int y) { return renderer_.IsInCancel(x, y); }
+
+  // tell if grace period has passed
+  bool IsReadyForUserInput() const;
+
+ private:
+  bool IsUserInput(const FsmInput fsm_input) {
+    return fsm_input == FsmInput::kUserEvent;
+  }
+
+  /** create a frame, and render it on the webRTC client
+   *
+   * note that this does not check host_ctrl_mode_
+   */
+  bool RenderDialog();
+
+  // transition actions on each state per input
+  // the new state will be save to the state_ at the end of each call
+  //
+  // when false is returned, the FSM must terminate
+  // and, no need to let the guest know
+  bool HandleInit(SharedFD hal_cli, const FsmInput fsm_input,
+                  const ConfUiMessage& conf_ui_msg);
+
+  bool HandleWaitStop(SharedFD hal_cli, const FsmInput fsm_input);
+
+  bool HandleInSession(SharedFD hal_cli, const FsmInput fsm_input,
+                       const ConfUiMessage& conf_ui_msg);
+
+  // report with an error ack to HAL, and reset the FSM
+  bool ReportErrorToHal(SharedFD hal_cli, const std::string& msg);
+
+  void ScheduleToTerminate();
+
+  const std::string session_id_;
+  const std::uint32_t display_num_;
+  ConfUiRenderer& renderer_;
+  HostModeCtrl& host_mode_ctrl_;
+
+  // only context to save
+  std::string prompt_text_;
+  std::string locale_;
+  std::vector<teeui::UIOption> ui_options_;
+  std::vector<std::uint8_t> extra_data_;
+  // the second argument for resultCB of promptUserConfirmation
+  std::vector<std::uint8_t> signed_confirmation_;
+  std::vector<std::uint8_t> message_;
+
+  std::unique_ptr<Cbor> cbor_;
+
+  // effectively, this variables are shared with webRTC thread
+  // the input demuxer will check the confirmation UI mode based on this
+  std::atomic<MainLoopState> state_;
+  MainLoopState saved_state_;  // for restore/suspend
+  using Clock = std::chrono::steady_clock;
+  using TimePoint = std::chrono::time_point<Clock>;
+  std::unique_ptr<TimePoint> start_time_;
+};
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/sign.cc b/host/libs/confui/sign.cc
new file mode 100644
index 000000000..bbaac8398
--- /dev/null
+++ b/host/libs/confui/sign.cc
@@ -0,0 +1,130 @@
+/*
+ * Copyright 2021, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/confui/sign.h"
+
+#include <openssl/hmac.h>
+#include <openssl/sha.h>
+
+#include <string>
+
+#include <android-base/logging.h>
+
+#include "common/libs/confui/confui.h"
+#include "common/libs/fs/shared_fd.h"
+#include "common/libs/security/confui_sign.h"
+#include "host/commands/kernel_log_monitor/utils.h"
+#include "host/libs/config/cuttlefish_config.h"
+#include "host/libs/confui/sign_utils.h"
+
+namespace cuttlefish {
+namespace confui {
+namespace {
+std::string GetSecureEnvSocketPath() {
+  auto config = cuttlefish::CuttlefishConfig::Get();
+  CHECK(config) << "Config must not be null";
+  auto instance = config->ForDefaultInstance();
+  return instance.PerInstanceInternalUdsPath("confui_sign.sock");
+}
+
+/**
+ * the secure_env signing server may be on slightly later than
+ * confirmation UI host/webRTC process.
+ */
+SharedFD ConnectToSecureEnv() {
+  auto socket_path = GetSecureEnvSocketPath();
+  SharedFD socket_to_secure_env =
+      SharedFD::SocketLocalClient(socket_path, false, SOCK_STREAM);
+  return socket_to_secure_env;
+}
+}  // end of namespace
+
+class HMacImplementation {
+ public:
+  static std::optional<support::hmac_t> hmac256(
+      const support::auth_token_key_t& key,
+      std::initializer_list<support::ByteBufferProxy> buffers);
+};
+
+std::optional<support::hmac_t> HMacImplementation::hmac256(
+    const support::auth_token_key_t& key,
+    std::initializer_list<support::ByteBufferProxy> buffers) {
+  HMAC_CTX hmacCtx;
+  HMAC_CTX_init(&hmacCtx);
+  if (!HMAC_Init_ex(&hmacCtx, key.data(), key.size(), EVP_sha256(), nullptr)) {
+    return {};
+  }
+  for (auto& buffer : buffers) {
+    if (!HMAC_Update(&hmacCtx, buffer.data(), buffer.size())) {
+      return {};
+    }
+  }
+  support::hmac_t result;
+  if (!HMAC_Final(&hmacCtx, result.data(), nullptr)) {
+    return {};
+  }
+  return result;
+}
+
+/**
+ * The test key is 32byte word with all bytes set to TestKeyBits::BYTE.
+ */
+enum class TestKeyBits : uint8_t {
+  BYTE = 165 /* 0xA5 */,
+};
+
+std::optional<std::vector<std::uint8_t>> TestSign(
+    const std::vector<std::uint8_t>& message) {
+  // the same as userConfirm()
+  using namespace support;
+  auth_token_key_t key;
+  key.fill(static_cast<std::uint8_t>(TestKeyBits::BYTE));
+  using HMacer = HMacImplementation;
+  auto confirm_signed_opt =
+      HMacer::hmac256(key, {"confirmation token", message});
+  if (!confirm_signed_opt) {
+    return std::nullopt;
+  }
+  auto confirm_signed = confirm_signed_opt.value();
+  return {
+      std::vector<std::uint8_t>(confirm_signed.begin(), confirm_signed.end())};
+}
+
+std::optional<std::vector<std::uint8_t>> Sign(
+    const std::vector<std::uint8_t>& message) {
+  SharedFD socket_to_secure_env = ConnectToSecureEnv();
+  if (!socket_to_secure_env->IsOpen()) {
+    ConfUiLog(ERROR) << "Failed to connect to secure_env signing server.";
+    return std::nullopt;
+  }
+  ConfUiSignRequester sign_client(socket_to_secure_env);
+  // request signature
+  sign_client.Request(message);
+  auto response_opt = sign_client.Receive();
+  if (!response_opt) {
+    ConfUiLog(ERROR) << "Received nullopt";
+    return std::nullopt;
+  }
+  // respond should be either error code or the signature
+  auto response = std::move(response_opt.value());
+  if (response.error_ != SignMessageError::kOk) {
+    ConfUiLog(ERROR) << "Response was received with non-OK error code";
+    return std::nullopt;
+  }
+  return {response.payload_};
+}
+}  // namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/sign.h b/host/libs/confui/sign.h
new file mode 100644
index 000000000..234df8d1a
--- /dev/null
+++ b/host/libs/confui/sign.h
@@ -0,0 +1,35 @@
+/*
+ * Copyright 2021, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <cstdint>
+#include <optional>
+#include <vector>
+
+namespace cuttlefish {
+namespace confui {
+
+// sign with the local test key
+std::optional<std::vector<std::uint8_t>> TestSign(
+    const std::vector<std::uint8_t>& message);
+
+// sign with secure_env
+std::optional<std::vector<std::uint8_t>> Sign(
+    const std::vector<std::uint8_t>& message);
+
+}  // namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/confui/sign_utils.h b/host/libs/confui/sign_utils.h
new file mode 100644
index 000000000..929f32a34
--- /dev/null
+++ b/host/libs/confui/sign_utils.h
@@ -0,0 +1,126 @@
+/*
+ * Copyright 2021, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <array>
+#include <cstdint>
+
+namespace cuttlefish {
+namespace confui {
+namespace support {
+using auth_token_key_t = std::array<std::uint8_t, 32>;
+using hmac_t = auth_token_key_t;
+
+template <typename T>
+auto bytes_cast(const T& v) -> const uint8_t (&)[sizeof(T)] {
+  return *reinterpret_cast<const uint8_t(*)[sizeof(T)]>(&v);
+}
+template <typename T>
+auto bytes_cast(T& v) -> uint8_t (&)[sizeof(T)] {
+  return *reinterpret_cast<uint8_t(*)[sizeof(T)]>(&v);
+}
+
+template <typename IntType, uint32_t byteOrder>
+struct choose_hton;
+
+template <typename IntType>
+struct choose_hton<IntType, __ORDER_LITTLE_ENDIAN__> {
+  inline static IntType hton(const IntType& value) {
+    IntType result = {};
+    const unsigned char* inbytes =
+        reinterpret_cast<const unsigned char*>(&value);
+    unsigned char* outbytes = reinterpret_cast<unsigned char*>(&result);
+    for (int i = sizeof(IntType) - 1; i >= 0; --i) {
+      *(outbytes++) = inbytes[i];
+    }
+    return result;
+  }
+};
+
+template <typename IntType>
+struct choose_hton<IntType, __ORDER_BIG_ENDIAN__> {
+  inline static IntType hton(const IntType& value) { return value; }
+};
+
+template <typename IntType>
+inline IntType hton(const IntType& value) {
+  return choose_hton<IntType, __BYTE_ORDER__>::hton(value);
+}
+
+class ByteBufferProxy {
+  template <typename T>
+  struct has_data {
+    template <typename U>
+    static int f(const U*, const void*) {
+      return 0;
+    }
+    template <typename U>
+    static int* f(const U* u, decltype(u->data())) {
+      return nullptr;
+    }
+    static constexpr bool value =
+        std::is_pointer<decltype(f((T*)nullptr, ""))>::value;
+  };
+
+ public:
+  template <typename T>
+  ByteBufferProxy(const T& buffer, decltype(buffer.data()) = nullptr)
+      : data_(reinterpret_cast<const uint8_t*>(buffer.data())),
+        size_(buffer.size()) {
+    static_assert(sizeof(decltype(*buffer.data())) == 1, "elements to large");
+  }
+
+  // this overload kicks in for types that have .c_str() but not .data(), such
+  // as hidl_string. std::string has both so we need to explicitly disable this
+  // overload if .data() is present.
+  template <typename T>
+  ByteBufferProxy(
+      const T& buffer,
+      std::enable_if_t<!has_data<T>::value, decltype(buffer.c_str())> = nullptr)
+      : data_(reinterpret_cast<const uint8_t*>(buffer.c_str())),
+        size_(buffer.size()) {
+    static_assert(sizeof(decltype(*buffer.c_str())) == 1, "elements to large");
+  }
+
+  template <size_t size>
+  ByteBufferProxy(const char (&buffer)[size])
+      : data_(reinterpret_cast<const uint8_t*>(buffer)), size_(size - 1) {
+    static_assert(size > 0, "even an empty string must be 0-terminated");
+  }
+
+  template <size_t size>
+  ByteBufferProxy(const uint8_t (&buffer)[size]) : data_(buffer), size_(size) {}
+
+  ByteBufferProxy() : data_(nullptr), size_(0) {}
+
+  const uint8_t* data() const { return data_; }
+  size_t size() const { return size_; }
+
+  const uint8_t* begin() const { return data_; }
+  const uint8_t* end() const { return data_ + size_; }
+
+ private:
+  const uint8_t* data_;
+  size_t size_;
+};
+
+// copied from:
+// hardware/interface/confirmationui/support/include/android/hardware/confirmationui/support/confirmationui_utils.h
+
+}  // end of namespace support
+}  // end of namespace confui
+}  // end of namespace cuttlefish
diff --git a/host/libs/image_aggregator/image_aggregator.cc b/host/libs/image_aggregator/image_aggregator.cc
index 632bc56da..03b51fc95 100644
--- a/host/libs/image_aggregator/image_aggregator.cc
+++ b/host/libs/image_aggregator/image_aggregator.cc
@@ -453,8 +453,9 @@ bool WriteEnd(SharedFD out, const GptEnd& end) {
  */
 void DeAndroidSparse(const std::vector<ImagePartition>& partitions) {
   for (const auto& partition : partitions) {
-    if (!ConvertToRawImage(partition.image_file_path)) {
-      LOG(DEBUG) << "Failed to desparse " << partition.image_file_path;
+    Result<void> res = ForceRawImage(partition.image_file_path);
+    if (!res.ok()) {
+      LOG(FATAL) << "Desparse failed: " << res.error().FormatForEnv();
     }
   }
 }
diff --git a/host/libs/image_aggregator/sparse_image_utils.cc b/host/libs/image_aggregator/sparse_image_utils.cc
index 33676b8c7..61ff17135 100644
--- a/host/libs/image_aggregator/sparse_image_utils.cc
+++ b/host/libs/image_aggregator/sparse_image_utils.cc
@@ -22,100 +22,70 @@
 #include <sys/file.h>
 
 #include <fstream>
+#include <string>
+#include <string_view>
 
 #include "common/libs/fs/shared_fd.h"
-#include "common/libs/fs/shared_select.h"
+#include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
+#include "host/libs/config/config_utils.h"
 #include "host/libs/config/cuttlefish_config.h"
 
-
-const char ANDROID_SPARSE_IMAGE_MAGIC[] = "\x3A\xFF\x26\xED";
 namespace cuttlefish {
+namespace {
 
-void ReleaseLock(const SharedFD& fd,
-                 const std::string& tmp_lock_image_path) {
-  auto funlock_result = fd->Flock(LOCK_UN | LOCK_NB);
-  fd->Close();
-  if (!funlock_result.ok()) {
-    LOG(FATAL) << "It failed to unlock file " << tmp_lock_image_path;
-  }
-}
+constexpr std::string_view kAndroidSparseImageMagic = "\x3A\xFF\x26\xED";
 
-bool AcquireLock(SharedFD& fd, const std::string& tmp_lock_image_path) {
-  fd = SharedFD::Open(tmp_lock_image_path.c_str(),
-                        O_RDWR | O_CREAT, 0666);
-  if (!fd->IsOpen()) {
-    LOG(FATAL) << tmp_lock_image_path << " file open failed";
-    return false;
-  }
-  auto flock_result = fd->Flock(LOCK_EX);
-  if (!flock_result.ok()) {
-    LOG(FATAL) << "flock failed";
-    return false;
-  }
-  return true;
+Result<SharedFD> AcquireLock(const std::string& tmp_lock_image_path) {
+  SharedFD fd =
+      SharedFD::Open(tmp_lock_image_path.c_str(), O_RDWR | O_CREAT, 0666);
+  CF_EXPECTF(fd->IsOpen(), "Failed to open '{}': '{}'", tmp_lock_image_path,
+             fd->StrError());
+
+  CF_EXPECT(fd->Flock(LOCK_EX));
+
+  return fd;
 }
 
-bool IsSparseImage(const std::string& image_path) {
+Result<bool> IsSparseImage(const std::string& image_path) {
   std::ifstream file(image_path, std::ios::binary);
-  if (!file) {
-    LOG(FATAL) << "Could not open '" << image_path << "'";
-    return false;
-  }
-  char buffer[5] = {0};
-  file.read(buffer, 4);
-  file.close();
-  return strcmp(ANDROID_SPARSE_IMAGE_MAGIC, buffer) == 0;
+  CF_EXPECTF(file.good(), "Could not open '{}'", image_path);
+
+  std::string buffer(4, ' ');
+  file.read(buffer.data(), 4);
+
+  return buffer == kAndroidSparseImageMagic;
 }
 
-bool ConvertToRawImage(const std::string& image_path) {
-  SharedFD fd;
+}  // namespace
+
+Result<void> ForceRawImage(const std::string& image_path) {
   std::string tmp_lock_image_path = image_path + ".lock";
 
-  if(AcquireLock(fd, tmp_lock_image_path) == false) {
-    return false;
-  }
+  SharedFD fd = CF_EXPECT(AcquireLock(tmp_lock_image_path));
 
-  if (!IsSparseImage(image_path)) {
-    // Release lock before return
-    LOG(DEBUG) << "Skip non-sparse image " << image_path;
-    return false;
+  if (!CF_EXPECT(IsSparseImage(image_path))) {
+    return {};
   }
 
-  auto simg2img_path = HostBinaryPath("simg2img");
-  Command simg2img_cmd(simg2img_path);
   std::string tmp_raw_image_path = image_path + ".raw";
-  simg2img_cmd.AddParameter(image_path);
-  simg2img_cmd.AddParameter(tmp_raw_image_path);
-
-  // Use simg2img to convert sparse image to raw image.
-  int success = simg2img_cmd.Start().Wait();
-  if (success != 0) {
-    // Release lock before FATAL and return
-    LOG(FATAL) << "Unable to convert Android sparse image " << image_path
-               << " to raw image. " << success;
-    return false;
-  }
+  // Use simg2img to convert sparse image to raw images.
+  int simg2img_status =
+      Execute({HostBinaryPath("simg2img"), image_path, tmp_raw_image_path});
 
-  // Replace the original sparse image with the raw image.
-  if (unlink(image_path.c_str()) != 0) {
-    // Release lock before FATAL and return
-    PLOG(FATAL) << "Unable to delete original sparse image";
-  }
-
-  Command mv_cmd("/bin/mv");
-  mv_cmd.AddParameter("-f");
-  mv_cmd.AddParameter(tmp_raw_image_path);
-  mv_cmd.AddParameter(image_path);
-  success = mv_cmd.Start().Wait();
-  // Release lock and leave critical section
-  ReleaseLock(fd, tmp_lock_image_path);
-  if (success != 0) {
-    LOG(FATAL) << "Unable to rename raw image " << success;
-    return false;
-  }
+  CF_EXPECT_EQ(simg2img_status, 0,
+               "Unable to convert Android sparse image '"
+                   << image_path << "' to raw image: " << simg2img_status);
 
-  return true;
+  // Replace the original sparse image with the raw image.
+  // `rename` can fail if these are on different mounts, but they are files
+  // within the same directory so they can only be in different mounts if one
+  // is a bind mount, in which case `rename` won't work anyway.
+  CF_EXPECTF(rename(tmp_raw_image_path.c_str(), image_path.c_str()) == 0,
+             "rename('{}','{}') failed: {}", tmp_raw_image_path, image_path,
+             strerror(errno));
+
+  return {};
 }
 
 }  // namespace cuttlefish
diff --git a/host/libs/image_aggregator/sparse_image_utils.h b/host/libs/image_aggregator/sparse_image_utils.h
index bf9b3351f..64e2b7b76 100644
--- a/host/libs/image_aggregator/sparse_image_utils.h
+++ b/host/libs/image_aggregator/sparse_image_utils.h
@@ -16,10 +16,10 @@
 
 #include <string>
 
-namespace cuttlefish {
+#include "common/libs/utils/result.h"
 
-bool IsSparseImage(const std::string& image_path);
+namespace cuttlefish {
 
-bool ConvertToRawImage(const std::string& image_path);
+Result<void> ForceRawImage(const std::string& image_path);
 
 }  // namespace cuttlefish
diff --git a/host/libs/location/GnssClient.cpp b/host/libs/location/GnssClient.cpp
index 9f04f1c83..5fe732f5f 100644
--- a/host/libs/location/GnssClient.cpp
+++ b/host/libs/location/GnssClient.cpp
@@ -14,11 +14,15 @@
  * limitations under the License.
  */
 
-#include "GnssClient.h"
+#include "host/libs/location/GnssClient.h"
+
+#include <memory>
+
 #include <android-base/logging.h>
-#include <host/libs/config/logging.h>
-#include <cassert>
-#include <string>
+#include <grpcpp/channel.h>
+#include <grpcpp/support/status.h>
+
+#include "common/libs/utils/result.h"
 
 using gnss_grpc_proxy::GnssGrpcProxy;
 using gnss_grpc_proxy::GpsCoordinates;
@@ -31,8 +35,8 @@ namespace cuttlefish {
 GnssClient::GnssClient(const std::shared_ptr<grpc::Channel>& channel)
     : stub_(GnssGrpcProxy::NewStub(channel)) {}
 
-Result<grpc::Status> GnssClient::SendGpsLocations(
-    int delay, const GpsFixArray& coordinates) {
+Result<void> GnssClient::SendGpsLocations(int delay,
+                                          const GpsFixArray& coordinates) {
   // Data we are sending to the server.
   SendGpsCoordinatesRequest request;
   request.set_delay(delay);
@@ -51,13 +55,13 @@ Result<grpc::Status> GnssClient::SendGpsLocations(
   // The actual RPC.
   grpc::Status status = stub_->SendGpsVector(&context, request, &reply);
   // Act upon its status.
-  CF_EXPECT(status.ok(), "GPS data sending failed" << status.error_code()
-                                                   << ": "
-                                                   << status.error_message());
+  CF_EXPECTF(status.ok(), "GPS data sending failed: {} ({})",
+             status.error_message(),
+             static_cast<std::uint32_t>(status.error_code()));
 
   LOG(DEBUG) << reply.status();
 
-  return status;
+  return {};
 }
 
 }  // namespace cuttlefish
diff --git a/host/libs/location/GnssClient.h b/host/libs/location/GnssClient.h
index 0cda44bbb..4c8710649 100644
--- a/host/libs/location/GnssClient.h
+++ b/host/libs/location/GnssClient.h
@@ -13,25 +13,30 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-
 #pragma once
+
+#include <memory>
+
 #include <grpc/grpc.h>
 #include <grpcpp/channel.h>
 #include <grpcpp/client_context.h>
 #include <grpcpp/create_channel.h>
-#include "common/libs/utils/result.h"
+
 #include "gnss_grpc_proxy.grpc.pb.h"
+
+#include "common/libs/utils/result.h"
 #include "host/libs/location/GpsFix.h"
 
 namespace cuttlefish {
+
 class GnssClient {
  public:
   GnssClient(const std::shared_ptr<grpc::Channel>& channel);
 
-  Result<grpc::Status> SendGpsLocations(
-      int delay, const GpsFixArray& coordinates);
+  Result<void> SendGpsLocations(int delay, const GpsFixArray& coordinates);
 
  private:
   std::unique_ptr<gnss_grpc_proxy::GnssGrpcProxy::Stub> stub_;
 };
+
 }  // namespace cuttlefish
diff --git a/host/libs/process_monitor/process_monitor.cc b/host/libs/process_monitor/process_monitor.cc
index 89039af05..c14e60412 100644
--- a/host/libs/process_monitor/process_monitor.cc
+++ b/host/libs/process_monitor/process_monitor.cc
@@ -43,6 +43,7 @@
 #include "common/libs/fs/shared_buf.h"
 #include "common/libs/fs/shared_select.h"
 #include "common/libs/utils/contains.h"
+#include "common/libs/utils/files.h"
 #include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/command_util/runner/defs.h"
@@ -87,7 +88,7 @@ void LogSubprocessExit(const std::string& name, const siginfo_t& infop) {
   }
 }
 
-Result<void> MonitorLoop(const std::atomic_bool& running,
+Result<void> MonitorLoop(std::atomic_bool& running,
                          std::mutex& properties_mutex,
                          const bool restart_subprocesses,
                          std::vector<MonitorEntry>& monitored) {
@@ -121,8 +122,8 @@ Result<void> MonitorLoop(const std::atomic_bool& running,
         if (running.load() && is_critical) {
           LOG(ERROR) << "Stopping all monitored processes due to unexpected "
                         "exit of critical process";
-          Command stop_cmd(StopCvdBinary());
-          stop_cmd.Start();
+          running.store(false);
+          break;
         }
       }
     }
@@ -244,13 +245,6 @@ Result<void> ProcessMonitor::StartSubprocesses(
     if (Contains(properties_.strace_commands_, short_name)) {
       options.Strace(properties.strace_log_dir_ + "/strace-" + short_name);
     }
-    if (properties.sandbox_processes_ && monitored.can_sandbox) {
-      options.SandboxArguments({
-          HostBinaryPath("process_sandboxer"),
-          "--log_dir=" + properties.strace_log_dir_,
-          "--host_artifacts_path=" + DefaultHostArtifactsPath(""),
-      });
-    }
     monitored.proc.reset(
         new Subprocess(monitored.cmd->Start(std::move(options))));
     CF_EXPECT(monitored.proc->Started(), "Failed to start subprocess");
@@ -314,8 +308,7 @@ ProcessMonitor::Properties ProcessMonitor::Properties::RestartSubprocesses(
 
 ProcessMonitor::Properties& ProcessMonitor::Properties::AddCommand(
     MonitorCommand cmd) & {
-  auto& entry = entries_.emplace_back(std::move(cmd.command), cmd.is_critical);
-  entry.can_sandbox = cmd.can_sandbox;
+  entries_.emplace_back(std::move(cmd.command), cmd.is_critical);
   return *this;
 }
 
@@ -344,16 +337,6 @@ ProcessMonitor::Properties ProcessMonitor::Properties::StraceLogDir(
   return std::move(StraceLogDir(std::move(log_dir)));
 }
 
-ProcessMonitor::Properties& ProcessMonitor::Properties::SandboxProcesses(
-    bool r) & {
-  sandbox_processes_ = r;
-  return *this;
-}
-ProcessMonitor::Properties ProcessMonitor::Properties::SandboxProcesses(
-    bool r) && {
-  return std::move(SandboxProcesses(r));
-}
-
 ProcessMonitor::ProcessMonitor(ProcessMonitor::Properties&& properties,
                                const SharedFD& secure_env_fd)
     : properties_(std::move(properties)),
diff --git a/host/libs/process_monitor/process_monitor.h b/host/libs/process_monitor/process_monitor.h
index f080e19e2..2f14a150b 100644
--- a/host/libs/process_monitor/process_monitor.h
+++ b/host/libs/process_monitor/process_monitor.h
@@ -20,7 +20,6 @@
 #include <mutex>
 #include <set>
 #include <string>
-#include <thread>
 #include <utility>
 #include <vector>
 
@@ -32,7 +31,6 @@ namespace cuttlefish {
 
 struct MonitorEntry {
   std::unique_ptr<Command> cmd;
-  bool can_sandbox;
   std::unique_ptr<Subprocess> proc;
   bool is_critical;
 
@@ -58,9 +56,6 @@ class ProcessMonitor {
     Properties& StraceLogDir(std::string) &;
     Properties StraceLogDir(std::string) &&;
 
-    Properties& SandboxProcesses(bool) &;
-    Properties SandboxProcesses(bool) &&;
-
     template <typename T>
     Properties& AddCommands(T commands) & {
       for (auto& command : commands) {
@@ -79,7 +74,6 @@ class ProcessMonitor {
     std::vector<MonitorEntry> entries_;
     std::set<std::string> strace_commands_;
     std::string strace_log_dir_;
-    bool sandbox_processes_;
 
     friend class ProcessMonitor;
   };
diff --git a/host/libs/screen_connector/Android.bp b/host/libs/screen_connector/Android.bp
new file mode 100644
index 000000000..a0c63a6f3
--- /dev/null
+++ b/host/libs/screen_connector/Android.bp
@@ -0,0 +1,50 @@
+//
+// Copyright (C) 2020 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_library {
+    name: "libcuttlefish_screen_connector",
+    srcs: [
+        "wayland_screen_connector.cpp",
+    ],
+    shared_libs: [
+        "libcuttlefish_fs",
+        "libbase",
+        "libfruit",
+        "libjsoncpp",
+        "liblog",
+    ],
+    header_libs: [
+        "libcuttlefish_confui_host_headers",
+    ],
+    static_libs: [
+        "libcuttlefish_host_config",
+        "libcuttlefish_utils",
+        "libcuttlefish_confui",
+        "libcuttlefish_wayland_server",
+        "libcuttlefish_confui_host",
+        "libffi",
+        "libft2.nodep",
+        "libteeui",
+        "libteeui_localization",
+        "libwayland_crosvm_gpu_display_extension_server_protocols",
+        "libwayland_extension_server_protocols",
+        "libwayland_server",
+    ],
+    defaults: ["cuttlefish_buildhost_only"],
+}
diff --git a/host/libs/screen_connector/screen_connector.h b/host/libs/screen_connector/screen_connector.h
new file mode 100644
index 000000000..f9e8be97a
--- /dev/null
+++ b/host/libs/screen_connector/screen_connector.h
@@ -0,0 +1,204 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <cstdint>
+#include <functional>
+#include <memory>
+#include <mutex>
+#include <optional>
+#include <string>
+#include <string_view>
+#include <thread>
+#include <type_traits>
+#include <unordered_set>
+
+#include <android-base/logging.h>
+#include <fruit/fruit.h>
+
+#include "common/libs/confui/confui.h"
+#include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/contains.h"
+#include "common/libs/utils/size_utils.h"
+#include "host/libs/config/cuttlefish_config.h"
+#include "host/libs/confui/host_mode_ctrl.h"
+#include "host/libs/confui/host_utils.h"
+#include "host/libs/screen_connector/screen_connector_common.h"
+#include "host/libs/screen_connector/screen_connector_multiplexer.h"
+#include "host/libs/screen_connector/screen_connector_queue.h"
+#include "host/libs/screen_connector/wayland_screen_connector.h"
+
+namespace cuttlefish {
+
+template <typename ProcessedFrameType>
+class ScreenConnector : public ScreenConnectorInfo,
+                        public ScreenConnectorFrameRenderer {
+ public:
+  static_assert(cuttlefish::is_movable<ProcessedFrameType>::value,
+                "ProcessedFrameType should be std::move-able.");
+  static_assert(
+      std::is_base_of<ScreenConnectorFrameInfo, ProcessedFrameType>::value,
+      "ProcessedFrameType should inherit ScreenConnectorFrameInfo");
+
+  using FrameMultiplexer = ScreenConnectorInputMultiplexer<ProcessedFrameType>;
+
+  INJECT(ScreenConnector(WaylandScreenConnector& sc_android_src,
+                         HostModeCtrl& host_mode_ctrl))
+      : sc_android_src_(sc_android_src),
+        host_mode_ctrl_{host_mode_ctrl},
+        on_next_frame_cnt_{0},
+        render_confui_cnt_{0},
+        sc_frame_multiplexer_{host_mode_ctrl_} {
+    auto config = cuttlefish::CuttlefishConfig::Get();
+    if (!config) {
+      LOG(FATAL) << "CuttlefishConfig is not available.";
+    }
+    auto instance = config->ForDefaultInstance();
+    std::unordered_set<std::string_view> valid_gpu_modes{
+        cuttlefish::kGpuModeCustom,
+        cuttlefish::kGpuModeDrmVirgl,
+        cuttlefish::kGpuModeGfxstream,
+        cuttlefish::kGpuModeGfxstreamGuestAngle,
+        cuttlefish::kGpuModeGfxstreamGuestAngleHostSwiftShader,
+        cuttlefish::kGpuModeGuestSwiftshader};
+    if (!Contains(valid_gpu_modes, instance.gpu_mode())) {
+      LOG(FATAL) << "Invalid gpu mode: " << instance.gpu_mode();
+    }
+  }
+
+  /**
+   * This is the type of the callback function WebRTC is supposed to provide
+   * ScreenConnector with.
+   *
+   * The callback function is how a raw bytes frame should be processed for
+   * WebRTC
+   *
+   */
+  using GenerateProcessedFrameCallback = std::function<void(
+      std::uint32_t /*display_number*/, std::uint32_t /*frame_width*/,
+      std::uint32_t /*frame_height*/, std::uint32_t /*frame_fourcc_format*/,
+      std::uint32_t /*frame_stride_bytes*/, std::uint8_t* /*frame_bytes*/,
+      /* ScImpl enqueues this type into the Q */
+      ProcessedFrameType& msg)>;
+
+  virtual ~ScreenConnector() = default;
+
+  /**
+   * set the callback function to be eventually used by Wayland-Based
+   * Connector
+   *
+   */
+  void SetCallback(GenerateProcessedFrameCallback&& frame_callback) {
+    std::lock_guard<std::mutex> lock(streamer_callback_mutex_);
+    callback_from_streamer_ = std::move(frame_callback);
+    streamer_callback_set_cv_.notify_all();
+
+    sc_android_src_.SetFrameCallback(
+        [this](std::uint32_t display_number, std::uint32_t frame_w,
+               std::uint32_t frame_h, std::uint32_t frame_fourcc_format,
+               std::uint32_t frame_stride_bytes, std::uint8_t* frame_bytes) {
+          const bool is_confui_mode = host_mode_ctrl_.IsConfirmatioUiMode();
+          if (is_confui_mode) {
+            return;
+          }
+
+          ProcessedFrameType processed_frame;
+
+          {
+            std::lock_guard<std::mutex> lock(streamer_callback_mutex_);
+            callback_from_streamer_(display_number, frame_w, frame_h,
+                                    frame_fourcc_format, frame_stride_bytes,
+                                    frame_bytes, processed_frame);
+          }
+
+          sc_frame_multiplexer_.PushToAndroidQueue(std::move(processed_frame));
+        });
+  }
+
+  bool IsCallbackSet() const override {
+    if (callback_from_streamer_) {
+      return true;
+    }
+    return false;
+  }
+
+  void SetDisplayEventCallback(DisplayEventCallback event_callback) {
+    sc_android_src_.SetDisplayEventCallback(std::move(event_callback));
+  }
+
+  /* returns the processed frame that also includes meta-info such as
+   * success/fail and display number from the guest
+   *
+   * NOTE THAT THIS IS THE ONLY CONSUMER OF THE TWO QUEUES
+   */
+  ProcessedFrameType OnNextFrame() { return sc_frame_multiplexer_.Pop(); }
+
+  /**
+   * ConfUi calls this when it has frames to render
+   *
+   * This won't be called if not by Confirmation UI. This won't affect rendering
+   * Android guest frames if Confirmation UI HAL is not active.
+   *
+   */
+  bool RenderConfirmationUi(std::uint32_t display_number,
+                            std::uint32_t frame_width,
+                            std::uint32_t frame_height,
+                            std::uint32_t frame_fourcc_format,
+                            std::uint32_t frame_stride_bytes,
+                            std::uint8_t* frame_bytes) override {
+    render_confui_cnt_++;
+    // wait callback is not set, the streamer is not ready
+    // return with LOG(ERROR)
+    if (!IsCallbackSet()) {
+      ConfUiLog(ERROR) << "callback function to process frames is not yet set";
+      return false;
+    }
+    ProcessedFrameType processed_frame;
+    auto this_thread_name = cuttlefish::confui::thread::GetName();
+    ConfUiLog(DEBUG) << this_thread_name
+                     << "is sending a #" + std::to_string(render_confui_cnt_)
+                     << "Conf UI frame";
+    callback_from_streamer_(display_number, frame_width, frame_height,
+                            frame_fourcc_format, frame_stride_bytes,
+                            frame_bytes, processed_frame);
+    // now add processed_frame to the queue
+    sc_frame_multiplexer_.PushToConfUiQueue(std::move(processed_frame));
+    return true;
+  }
+
+ protected:
+  ScreenConnector() = delete;
+
+ private:
+  WaylandScreenConnector& sc_android_src_;
+  HostModeCtrl& host_mode_ctrl_;
+  unsigned long long int on_next_frame_cnt_;
+  unsigned long long int render_confui_cnt_;
+  /**
+   * internally has conf ui & android queues.
+   *
+   * multiplexting the two input queues, so the consumer gets one input
+   * at a time from the right queue
+   */
+  FrameMultiplexer sc_frame_multiplexer_;
+  GenerateProcessedFrameCallback callback_from_streamer_;
+  std::mutex
+      streamer_callback_mutex_;  // mutex to set & read callback_from_streamer_
+  std::condition_variable streamer_callback_set_cv_;
+};
+
+}  // namespace cuttlefish
diff --git a/host/libs/screen_connector/screen_connector_common.h b/host/libs/screen_connector/screen_connector_common.h
new file mode 100644
index 000000000..2d69841ae
--- /dev/null
+++ b/host/libs/screen_connector/screen_connector_common.h
@@ -0,0 +1,110 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <cstdint>
+#include <functional>
+
+#include <android-base/logging.h>
+
+#include "common/libs/utils/size_utils.h"
+#include "host/libs/config/cuttlefish_config.h"
+
+namespace cuttlefish {
+
+template <typename T>
+struct is_movable {
+  static constexpr const bool value =
+      std::is_move_constructible<T>::value && std::is_move_assignable<T>::value;
+};
+
+// this callback type is going directly to socket-based or wayland
+// ScreenConnector
+using GenerateProcessedFrameCallbackImpl =
+    std::function<void(std::uint32_t /*display_number*/,       //
+                       std::uint32_t /*frame_width*/,          //
+                       std::uint32_t /*frame_height*/,         //
+                       std::uint32_t /*frame_fourcc_format*/,  //
+                       std::uint32_t /*frame_stride_bytes*/,   //
+                       std::uint8_t* /*frame_pixels*/)>;
+
+struct ScreenConnectorInfo {
+  // functions are intended to be inlined
+  static constexpr std::uint32_t BytesPerPixel() { return 4; }
+  static std::uint32_t ScreenCount() {
+    auto config = ChkAndGetConfig();
+    auto instance = config->ForDefaultInstance();
+    auto display_configs = instance.display_configs();
+    return static_cast<std::uint32_t>(display_configs.size());
+  }
+  static std::uint32_t ScreenHeight(std::uint32_t display_number) {
+    auto config = ChkAndGetConfig();
+    auto instance = config->ForDefaultInstance();
+    auto display_configs = instance.display_configs();
+    CHECK_GT(display_configs.size(), display_number);
+    return display_configs[display_number].height;
+  }
+  static std::uint32_t ScreenWidth(std::uint32_t display_number) {
+    auto config = ChkAndGetConfig();
+    auto instance = config->ForDefaultInstance();
+    auto display_configs = instance.display_configs();
+    CHECK_GE(display_configs.size(), display_number);
+    return display_configs[display_number].width;
+  }
+  static std::uint32_t ComputeScreenStrideBytes(const std::uint32_t w) {
+    return AlignToPowerOf2(w * BytesPerPixel(), 4);
+  }
+  static std::uint32_t ComputeScreenSizeInBytes(const std::uint32_t w,
+                                                const std::uint32_t h) {
+    return ComputeScreenStrideBytes(w) * h;
+  }
+  static std::uint32_t ScreenStrideBytes(const std::uint32_t display_number) {
+    return ComputeScreenStrideBytes(ScreenWidth(display_number));
+  }
+  static std::uint32_t ScreenSizeInBytes(const std::uint32_t display_number) {
+    return ComputeScreenStrideBytes(ScreenWidth(display_number)) *
+           ScreenHeight(display_number);
+  }
+
+ private:
+  static auto ChkAndGetConfig()
+      -> decltype(cuttlefish::CuttlefishConfig::Get()) {
+    auto config = cuttlefish::CuttlefishConfig::Get();
+    CHECK(config) << "Config is Missing";
+    return config;
+  }
+};
+
+struct ScreenConnectorFrameRenderer {
+  virtual bool RenderConfirmationUi(std::uint32_t display_number,
+                                    std::uint32_t frame_width,
+                                    std::uint32_t frame_height,
+                                    std::uint32_t frame_fourcc_format,
+                                    std::uint32_t frame_stride_bytes,
+                                    std::uint8_t* frame_bytes) = 0;
+  virtual bool IsCallbackSet() const = 0;
+  virtual ~ScreenConnectorFrameRenderer() = default;
+};
+
+// this is inherited by the data type that represents the processed frame
+// being moved around.
+struct ScreenConnectorFrameInfo {
+  std::uint32_t display_number_;
+  bool is_success_;
+};
+
+}  // namespace cuttlefish
diff --git a/host/libs/screen_connector/screen_connector_ctrl.h b/host/libs/screen_connector/screen_connector_ctrl.h
new file mode 100644
index 000000000..01569d2bd
--- /dev/null
+++ b/host/libs/screen_connector/screen_connector_ctrl.h
@@ -0,0 +1,103 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <atomic>
+#include <condition_variable>
+#include <functional>
+#include <memory>
+#include <mutex>
+#include <thread>
+
+#include "common/libs/concurrency/semaphore.h"
+
+namespace cuttlefish {
+/**
+ * mechanism to orchestrate concurrent executions of threads
+ * that work for screen connector
+ *
+ * One thing is when any of wayland/socket-based connector or
+ * confirmation UI has a frame, it should wake up the consumer
+ * The two queues are separate, so the conditional variables,
+ * etc, can't be in the queue
+ */
+class ScreenConnectorCtrl {
+ public:
+  enum class ModeType { kAndroidMode, kConfUI_Mode };
+
+  ScreenConnectorCtrl() : atomic_mode_(ModeType::kAndroidMode) {}
+
+  /**
+   * The thread that enqueues Android frames will call this to wait until
+   * the mode is kAndroidMode
+   *
+   * Logically, using atomic_mode_ alone is not sufficient. Using mutex alone
+   * is logically complete but slow.
+   *
+   * Note that most of the time, the mode is kAndroidMode. Also, note that
+   * this method is called at every single frame.
+   *
+   * As an optimization, we check atomic_mode_ first. If failed, we wait for
+   * kAndroidMode with mutex-based lock
+   *
+   * The actual synchronization is not at the and_mode_cv_.wait line but at
+   * this line:
+   *     if (atomic_mode_ == ModeType::kAndroidMode) {
+   *
+   * This trick reduces the flag checking delays by 70+% on a Gentoo based
+   * amd64 desktop, with Linux 5.10
+   */
+  void WaitAndroidMode() {
+    if (atomic_mode_ == ModeType::kAndroidMode) {
+      return;
+    }
+    auto check = [this]() -> bool {
+      return atomic_mode_ == ModeType::kAndroidMode;
+    };
+    std::unique_lock<std::mutex> lock(mode_mtx_);
+    and_mode_cv_.wait(lock, check);
+  }
+
+  void SetMode(const ModeType mode) {
+    std::lock_guard<std::mutex> lock(mode_mtx_);
+    atomic_mode_ = mode;
+    if (atomic_mode_ == ModeType::kAndroidMode) {
+      and_mode_cv_.notify_all();
+    }
+  }
+
+  auto GetMode() {
+    std::lock_guard<std::mutex> lock(mode_mtx_);
+    ModeType ret_val = atomic_mode_;
+    return ret_val;
+  }
+
+  void SemWait() { sem_.SemWait(); }
+
+  // Only called by the producers
+  void SemPost() { sem_.SemPost(); }
+
+ private:
+  std::mutex mode_mtx_;
+  std::condition_variable and_mode_cv_;
+  std::atomic<ModeType> atomic_mode_;
+
+  // track the total number of items in all queues
+  Semaphore sem_;
+};
+
+}  // namespace cuttlefish
diff --git a/host/libs/screen_connector/screen_connector_multiplexer.h b/host/libs/screen_connector/screen_connector_multiplexer.h
new file mode 100644
index 000000000..b620531ce
--- /dev/null
+++ b/host/libs/screen_connector/screen_connector_multiplexer.h
@@ -0,0 +1,104 @@
+/*
+ * Copyright (C) 2021 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <cstdint>
+
+#include "common/libs/concurrency/multiplexer.h"
+#include "common/libs/confui/confui.h"
+
+#include "host/libs/confui/host_mode_ctrl.h"
+#include "host/libs/screen_connector/screen_connector_queue.h"
+
+namespace cuttlefish {
+template <typename ProcessedFrameType>
+class ScreenConnectorInputMultiplexer {
+  using Queue = ScreenConnectorQueue<ProcessedFrameType>;
+  using Multiplexer = Multiplexer<ProcessedFrameType, Queue>;
+
+ public:
+  ScreenConnectorInputMultiplexer(HostModeCtrl& host_mode_ctrl)
+      : host_mode_ctrl_(host_mode_ctrl) {
+    sc_android_queue_id_ =
+        multiplexer_.RegisterQueue(multiplexer_.CreateQueue(/* q size */ 2));
+    sc_confui_queue_id_ =
+        multiplexer_.RegisterQueue(multiplexer_.CreateQueue(/* q size */ 2));
+  }
+
+  virtual ~ScreenConnectorInputMultiplexer() = default;
+
+  void PushToAndroidQueue(ProcessedFrameType&& t) {
+    multiplexer_.Push(sc_android_queue_id_, std::move(t));
+  }
+
+  void PushToConfUiQueue(ProcessedFrameType&& t) {
+    multiplexer_.Push(sc_confui_queue_id_, std::move(t));
+  }
+
+  // customize Pop()
+  ProcessedFrameType Pop() {
+    on_next_frame_cnt_++;
+
+    // is_discard_frame is thread-specific
+    bool is_discard_frame = false;
+
+    // callback to select the queue index, and update is_discard_frame
+    auto selector = [this, &is_discard_frame]() -> int {
+      if (multiplexer_.IsEmpty(sc_android_queue_id_)) {
+        ConfUiLog(VERBOSE)
+            << "Streamer gets Conf UI frame with host ctrl mode = "
+            << static_cast<std::uint32_t>(host_mode_ctrl_.GetMode())
+            << " and cnd = #" << on_next_frame_cnt_;
+        return sc_confui_queue_id_;
+      }
+      auto mode = host_mode_ctrl_.GetMode();
+      if (mode != HostModeCtrl::ModeType::kAndroidMode) {
+        // AndroidFrameFetchingLoop could have added 1 or 2 frames
+        // before it becomes Conf UI mode.
+        ConfUiLog(VERBOSE)
+            << "Streamer ignores Android frame with host ctrl mode ="
+            << static_cast<std::uint32_t>(mode) << "and cnd = #"
+            << on_next_frame_cnt_;
+        is_discard_frame = true;
+      }
+      ConfUiLog(VERBOSE) << "Streamer gets Android frame with host ctrl mode ="
+                         << static_cast<std::uint32_t>(mode) << "and cnd = #"
+                         << on_next_frame_cnt_;
+      return sc_android_queue_id_;
+    };
+
+    while (true) {
+      ConfUiLog(VERBOSE) << "Streamer waiting Semaphore with host ctrl mode ="
+                         << static_cast<std::uint32_t>(
+                                host_mode_ctrl_.GetMode())
+                         << " and cnd = #" << on_next_frame_cnt_;
+      auto processed_frame = multiplexer_.Pop(selector);
+      if (!is_discard_frame) {
+        return processed_frame;
+      }
+      is_discard_frame = false;
+    }
+  }
+
+ private:
+  HostModeCtrl& host_mode_ctrl_;
+  Multiplexer multiplexer_;
+  unsigned long long int on_next_frame_cnt_;
+  int sc_android_queue_id_;
+  int sc_confui_queue_id_;
+};
+}  // end of namespace cuttlefish
diff --git a/host/libs/screen_connector/screen_connector_queue.h b/host/libs/screen_connector/screen_connector_queue.h
new file mode 100644
index 000000000..2d1c3fcaf
--- /dev/null
+++ b/host/libs/screen_connector/screen_connector_queue.h
@@ -0,0 +1,108 @@
+/*
+ * Copyright (C) 2020 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <condition_variable>
+#include <deque>
+#include <memory>
+#include <mutex>
+#include <thread>
+
+#include "common/libs/concurrency/semaphore.h"
+
+namespace cuttlefish {
+// move-based concurrent queue
+template <typename T>
+class ScreenConnectorQueue {
+ public:
+  static_assert(is_movable<T>::value,
+                "Items in ScreenConnectorQueue should be std::mov-able");
+
+  ScreenConnectorQueue(const int q_max_size = 2)
+      : q_mutex_(std::make_unique<std::mutex>()), q_max_size_{q_max_size} {}
+  ScreenConnectorQueue(ScreenConnectorQueue&& cq) = delete;
+  ScreenConnectorQueue(const ScreenConnectorQueue& cq) = delete;
+  ScreenConnectorQueue& operator=(const ScreenConnectorQueue& cq) = delete;
+  ScreenConnectorQueue& operator=(ScreenConnectorQueue&& cq) = delete;
+
+  bool IsEmpty() const {
+    const std::lock_guard<std::mutex> lock(*q_mutex_);
+    return buffer_.empty();
+  }
+
+  auto Size() const {
+    const std::lock_guard<std::mutex> lock(*q_mutex_);
+    return buffer_.size();
+  }
+
+  void WaitEmpty() {
+    auto is_empty = [this](void) { return buffer_.empty(); };
+    std::unique_lock<std::mutex> lock(*q_mutex_);
+    q_empty_.wait(lock, is_empty);
+  }
+
+  /*
+   * Push( std::move(src) );
+   *
+   * Note: this queue is supposed to be used only by ScreenConnector-
+   * related components such as ScreenConnectorSource
+   *
+   * The traditional assumption was that when webRTC calls
+   * OnFrameAfter, the call should be block until it could return
+   * one frame.
+   *
+   * Thus, the producers of this queue must not produce frames
+   * much faster than the consumer, WebRTC consumes.
+   * Therefore, when the small buffer is full -- which means
+   * WebRTC would not call OnNextFrame --, the producer
+   * should stop adding items to the queue.
+   *
+   */
+  void Push(T&& item) {
+    std::unique_lock<std::mutex> lock(*q_mutex_);
+    if (Full()) {
+      auto is_empty = [this](void) { return buffer_.empty(); };
+      q_empty_.wait(lock, is_empty);
+    }
+    buffer_.push_back(std::move(item));
+  }
+  void Push(T& item) = delete;
+  void Push(const T& item) = delete;
+
+  T Pop() {
+    const std::lock_guard<std::mutex> lock(*q_mutex_);
+    auto item = std::move(buffer_.front());
+    buffer_.pop_front();
+    if (buffer_.empty()) {
+      q_empty_.notify_all();
+    }
+    return item;
+  }
+
+ private:
+  bool Full() const {
+    // call this in a critical section
+    // after acquiring q_mutex_
+    return q_max_size_ == buffer_.size();
+  }
+  std::deque<T> buffer_;
+  std::unique_ptr<std::mutex> q_mutex_;
+  std::condition_variable q_empty_;
+  const int q_max_size_;
+};
+
+}  // namespace cuttlefish
diff --git a/host/libs/screen_connector/wayland_screen_connector.cpp b/host/libs/screen_connector/wayland_screen_connector.cpp
new file mode 100644
index 000000000..e1982873f
--- /dev/null
+++ b/host/libs/screen_connector/wayland_screen_connector.cpp
@@ -0,0 +1,50 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/screen_connector/wayland_screen_connector.h"
+
+#include <fcntl.h>
+#include <unistd.h>
+
+#include <android-base/logging.h>
+
+#include "host/libs/wayland/wayland_server.h"
+
+namespace cuttlefish {
+
+WaylandScreenConnector::WaylandScreenConnector(ANNOTATED(FramesFd, int)
+                                                   frames_fd,
+                                               ANNOTATED(FramesAreRgba, bool)
+                                                   wayland_frames_are_rgba) {
+  int wayland_fd = fcntl(frames_fd, F_DUPFD_CLOEXEC, 3);
+  CHECK(wayland_fd != -1) << "Unable to dup server, errno " << errno;
+  close(frames_fd);
+
+  server_.reset(
+      new wayland::WaylandServer(wayland_fd, wayland_frames_are_rgba));
+}
+
+void WaylandScreenConnector::SetFrameCallback(
+    GenerateProcessedFrameCallbackImpl frame_callback) {
+  server_->SetFrameCallback(std::move(frame_callback));
+}
+
+void WaylandScreenConnector::SetDisplayEventCallback(
+    DisplayEventCallback event_callback) {
+  server_->SetDisplayEventCallback(std::move(event_callback));
+}
+
+}  // namespace cuttlefish
diff --git a/host/libs/screen_connector/wayland_screen_connector.h b/host/libs/screen_connector/wayland_screen_connector.h
new file mode 100644
index 000000000..afcd1583a
--- /dev/null
+++ b/host/libs/screen_connector/wayland_screen_connector.h
@@ -0,0 +1,44 @@
+/*
+ * Copyright (C) 2019 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#pragma once
+
+#include <memory>
+
+#include <fruit/fruit.h>
+
+#include "host/libs/screen_connector/screen_connector_common.h"
+#include "host/libs/wayland/wayland_server.h"
+
+namespace cuttlefish {
+
+class WaylandScreenConnector {
+ public:
+  struct FramesFd {};
+  struct FramesAreRgba {};
+  INJECT(WaylandScreenConnector(ANNOTATED(FramesFd, int) frames_fd,
+                                ANNOTATED(FramesAreRgba, bool)
+                                    frames_are_rgba));
+
+  void SetFrameCallback(GenerateProcessedFrameCallbackImpl frame_callback);
+
+  void SetDisplayEventCallback(DisplayEventCallback event_callback);
+
+ private:
+  std::unique_ptr<wayland::WaylandServer> server_;
+};
+
+}  // namespace cuttlefish
diff --git a/host/libs/vm_manager/Android.bp b/host/libs/vm_manager/Android.bp
index 1bc3ee0be..aa6b18e8e 100644
--- a/host/libs/vm_manager/Android.bp
+++ b/host/libs/vm_manager/Android.bp
@@ -26,6 +26,7 @@ cc_library {
         "host_configuration.cpp",
         "pci.cpp",
         "qemu_manager.cpp",
+        "vhost_user_block.cpp",
         "vm_manager.cpp",
     ],
     header_libs: [
diff --git a/host/libs/vm_manager/crosvm_builder.cpp b/host/libs/vm_manager/crosvm_builder.cpp
index 5e44a1673..1a631c285 100644
--- a/host/libs/vm_manager/crosvm_builder.cpp
+++ b/host/libs/vm_manager/crosvm_builder.cpp
@@ -88,11 +88,11 @@ void CrosvmBuilder::AddHvcReadWrite(const std::string& output,
 }
 
 void CrosvmBuilder::AddReadOnlyDisk(const std::string& path) {
-  command_.AddParameter("--disk=", path);
+  command_.AddParameter("--block=path=", path, ",ro=true");
 }
 
 void CrosvmBuilder::AddReadWriteDisk(const std::string& path) {
-  command_.AddParameter("--rwdisk=", path);
+  command_.AddParameter("--block=path=", path);
 }
 
 void CrosvmBuilder::AddSerialSink() {
@@ -117,40 +117,17 @@ void CrosvmBuilder::AddSerial(const std::string& output,
 }
 
 #ifdef __linux__
-SharedFD CrosvmBuilder::AddTap(const std::string& tap_name,
-                               std::optional<std::string_view> mac,
-                               const std::optional<pci::Address>& pci) {
-  auto tap_fd = OpenTapInterface(tap_name);
-  if (tap_fd->IsOpen()) {
-    command_.AddParameter("--net=tap-fd=", tap_fd, MacCrosvmArgument(mac), PciCrosvmArgument(pci));
-  } else {
-    LOG(ERROR) << "Unable to connect to \"" << tap_name
-               << "\": " << tap_fd->StrError();
-  }
-  return tap_fd;
+void CrosvmBuilder::AddTap(const std::string& tap_name,
+                           std::optional<std::string_view> mac,
+                           const std::optional<pci::Address>& pci) {
+  command_.AddParameter("--net=tap-name=", tap_name, MacCrosvmArgument(mac),
+                        PciCrosvmArgument(pci));
 }
 
 #endif
 
 int CrosvmBuilder::HvcNum() { return hvc_num_; }
 
-Result<void> CrosvmBuilder::SetToRestoreFromSnapshot(
-    const std::string& snapshot_dir_path, const std::string& instance_id_in_str,
-    const std::string& snapshot_name) {
-  auto meta_info_json = CF_EXPECT(LoadMetaJson(snapshot_dir_path));
-  const std::vector<std::string> selectors{kGuestSnapshotField,
-                                           instance_id_in_str};
-  const auto guest_snapshot_dir_suffix =
-      CF_EXPECT(GetValue<std::string>(meta_info_json, selectors));
-  // guest_snapshot_dir_suffix is a relative to
-  // the snapshot_path
-  const auto restore_path = snapshot_dir_path + "/" +
-                            guest_snapshot_dir_suffix + "/" +
-                            kGuestSnapshotBase + snapshot_name;
-  command_.AddParameter("--restore=", restore_path);
-  return {};
-}
-
 Command& CrosvmBuilder::Cmd() { return command_; }
 
 }  // namespace cuttlefish
diff --git a/host/libs/vm_manager/crosvm_builder.h b/host/libs/vm_manager/crosvm_builder.h
index 123d01a6a..4d473b3a6 100644
--- a/host/libs/vm_manager/crosvm_builder.h
+++ b/host/libs/vm_manager/crosvm_builder.h
@@ -17,10 +17,7 @@
 
 #include <optional>
 #include <string>
-#include <utility>
 
-#include "common/libs/fs/shared_fd.h"
-#include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/vm_manager/pci.h"
 
@@ -50,20 +47,13 @@ class CrosvmBuilder {
   void AddSerial(const std::string& output, const std::string& input);
 
 #ifdef __linux__
-  SharedFD AddTap(const std::string& tap_name,
-                  std::optional<std::string_view> mac = std::nullopt,
-                  const std::optional<pci::Address>& pci = std::nullopt);
+  void AddTap(const std::string& tap_name,
+              std::optional<std::string_view> mac = std::nullopt,
+              const std::optional<pci::Address>& pci = std::nullopt);
 #endif
 
   int HvcNum();
 
-  /**
-   * Configures the crosvm to start with --restore=<guest snapshot path>
-   */
-  Result<void> SetToRestoreFromSnapshot(const std::string& snapshot_dir_path,
-                                        const std::string& instance_id,
-                                        const std::string& snapshot_name);
-
   Command& Cmd();
 
  private:
diff --git a/host/libs/vm_manager/crosvm_manager.cpp b/host/libs/vm_manager/crosvm_manager.cpp
index a0b2c7603..16ae525c3 100644
--- a/host/libs/vm_manager/crosvm_manager.cpp
+++ b/host/libs/vm_manager/crosvm_manager.cpp
@@ -44,6 +44,7 @@
 #include "host/libs/config/known_paths.h"
 #include "host/libs/vm_manager/crosvm_builder.h"
 #include "host/libs/vm_manager/qemu_manager.h"
+#include "host/libs/vm_manager/vhost_user.h"
 
 namespace cuttlefish {
 namespace vm_manager {
@@ -182,15 +183,35 @@ std::string ToSingleLineString(const Json::Value& value) {
   return Json::writeString(builder, value);
 }
 
-void MaybeConfigureVulkanIcd(const CuttlefishConfig& config, Command* command) {
+Result<std::string> HostSwiftShaderIcdPathForArch() {
+  switch (HostArch()) {
+    case Arch::Arm64:
+      return HostBinaryPath("aarch64-linux-gnu/vk_swiftshader_icd.json");
+    case Arch::X86:
+    case Arch::X86_64:
+      return HostUsrSharePath("vulkan/icd.d/vk_swiftshader_icd.json");
+    default:
+      break;
+  }
+  return CF_ERR("Unhandled host arch " << HostArchStr()
+                                       << " for finding SwiftShader ICD.");
+}
+
+Result<void> MaybeConfigureVulkanIcd(const CuttlefishConfig& config,
+                                     Command* command) {
   const auto& gpu_mode = config.ForDefaultInstance().gpu_mode();
   if (gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
+    const std::string swiftshader_icd_json_path =
+        CF_EXPECT(HostSwiftShaderIcdPathForArch());
+
     // See https://github.com/KhronosGroup/Vulkan-Loader.
-    const std::string swiftshader_icd_json =
-        HostUsrSharePath("vulkan/icd.d/vk_swiftshader_icd.json");
-    command->AddEnvironmentVariable("VK_DRIVER_FILES", swiftshader_icd_json);
-    command->AddEnvironmentVariable("VK_ICD_FILENAMES", swiftshader_icd_json);
+    command->AddEnvironmentVariable("VK_DRIVER_FILES",
+                                    swiftshader_icd_json_path);
+    command->AddEnvironmentVariable("VK_ICD_FILENAMES",
+                                    swiftshader_icd_json_path);
   }
+
+  return {};
 }
 
 Result<std::string> CrosvmPathForVhostUserGpu(const CuttlefishConfig& config) {
@@ -208,10 +229,6 @@ Result<std::string> CrosvmPathForVhostUserGpu(const CuttlefishConfig& config) {
                                        << " for vhost user gpu crosvm");
 }
 
-struct VhostUserDeviceCommands {
-  Command device_cmd;
-  Command device_logs_cmd;
-};
 Result<VhostUserDeviceCommands> BuildVhostUserGpu(
     const CuttlefishConfig& config, Command* main_crosvm_cmd) {
   const auto& instance = config.ForDefaultInstance();
@@ -276,6 +293,9 @@ Result<VhostUserDeviceCommands> BuildVhostUserGpu(
   gpu_params_json["surfaceless"] = true;
   gpu_params_json["external-blob"] = instance.enable_gpu_external_blob();
   gpu_params_json["system-blob"] = instance.enable_gpu_system_blob();
+  if (!instance.gpu_renderer_features().empty()) {
+    gpu_params_json["renderer-features"] = instance.gpu_renderer_features();
+  }
 
   if (instance.hwcomposer() != kHwComposerNone) {
     // "displays": [
@@ -322,14 +342,6 @@ Result<VhostUserDeviceCommands> BuildVhostUserGpu(
   // Connect device to main crosvm:
   gpu_device_cmd.Cmd().AddParameter("--socket=", gpu_device_socket_path);
 
-  main_crosvm_cmd->AddPrerequisite([gpu_device_socket_path]() -> Result<void> {
-#ifdef __linux__
-    return WaitForUnixSocketListeningWithoutConnect(gpu_device_socket_path,
-                                                    /*timeoutSec=*/30);
-#else
-    return CF_ERR("Unhandled check if vhost user gpu ready.");
-#endif
-  });
   main_crosvm_cmd->AddParameter(
       "--vhost-user=gpu,pci-address=", gpu_pci_address,
       ",socket=", gpu_device_socket_path);
@@ -337,7 +349,7 @@ Result<VhostUserDeviceCommands> BuildVhostUserGpu(
   gpu_device_cmd.Cmd().AddParameter("--params");
   gpu_device_cmd.Cmd().AddParameter(ToSingleLineString(gpu_params_json));
 
-  MaybeConfigureVulkanIcd(config, &gpu_device_cmd.Cmd());
+  CF_EXPECT(MaybeConfigureVulkanIcd(config, &gpu_device_cmd.Cmd()));
 
   gpu_device_cmd.Cmd().RedirectStdIO(Subprocess::StdIOChannel::kStdOut,
                                      gpu_device_logs);
@@ -347,6 +359,7 @@ Result<VhostUserDeviceCommands> BuildVhostUserGpu(
   return VhostUserDeviceCommands{
       .device_cmd = std::move(gpu_device_cmd.Cmd()),
       .device_logs_cmd = std::move(gpu_device_logs_cmd),
+      .socket_path = gpu_device_socket_path,
   };
 }
 
@@ -382,49 +395,54 @@ Result<void> ConfigureGpu(const CuttlefishConfig& config, Command* crosvm_cmd) {
       gpu_common_string + ",egl=true,surfaceless=true,glx=false" + gles_string +
       gpu_renderer_features_param;
 
-  if (gpu_mode == kGpuModeGuestSwiftshader) {
-    crosvm_cmd->AddParameter("--gpu=backend=2D", gpu_common_string);
-  } else if (gpu_mode == kGpuModeDrmVirgl) {
-    crosvm_cmd->AddParameter("--gpu=backend=virglrenderer,context-types=virgl2",
-                             gpu_common_3d_string);
-  } else if (gpu_mode == kGpuModeGfxstream) {
-    crosvm_cmd->AddParameter(
-        "--gpu=context-types=gfxstream-gles:gfxstream-vulkan:gfxstream-"
-        "composer",
-        gpu_common_3d_string);
-  } else if (gpu_mode == kGpuModeGfxstreamGuestAngle ||
-             gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
-    crosvm_cmd->AddParameter(
-        "--gpu=context-types=gfxstream-vulkan:gfxstream-composer",
-        gpu_common_3d_string);
-  } else if (gpu_mode == kGpuModeCustom) {
-    const std::string gpu_context_types =
-        "--gpu=context-types=" + instance.gpu_context_types();
-    crosvm_cmd->AddParameter(gpu_context_types, gpu_common_string);
-  }
-
-  MaybeConfigureVulkanIcd(config, crosvm_cmd);
-
+  std::string gpu_displays_string = "";
   if (instance.hwcomposer() != kHwComposerNone) {
+    std::vector<std::string> gpu_displays_strings;
     for (const auto& display_config : instance.display_configs()) {
       const auto display_w = std::to_string(display_config.width);
       const auto display_h = std::to_string(display_config.height);
       const auto display_dpi = std::to_string(display_config.dpi);
       const auto display_rr = std::to_string(display_config.refresh_rate_hz);
-      const auto display_params = android::base::Join(
+      gpu_displays_strings.push_back(android::base::Join(
           std::vector<std::string>{
               "mode=windowed[" + display_w + "," + display_h + "]",
               "dpi=[" + display_dpi + "," + display_dpi + "]",
               "refresh-rate=" + display_rr,
           },
-          ",");
-
-      crosvm_cmd->AddParameter("--gpu-display=", display_params);
+          ","));
     }
+    gpu_displays_string =
+        "displays=[[" + android::base::Join(gpu_displays_strings, "],[") + "]],";
 
     crosvm_cmd->AddParameter("--wayland-sock=", instance.frames_socket_path());
   }
 
+  if (gpu_mode == kGpuModeGuestSwiftshader) {
+    crosvm_cmd->AddParameter("--gpu=", gpu_displays_string, "backend=2D",
+                             gpu_common_string);
+  } else if (gpu_mode == kGpuModeDrmVirgl) {
+    crosvm_cmd->AddParameter("--gpu=", gpu_displays_string,
+                             "backend=virglrenderer,context-types=virgl2",
+                             gpu_common_3d_string);
+  } else if (gpu_mode == kGpuModeGfxstream) {
+    crosvm_cmd->AddParameter(
+        "--gpu=", gpu_displays_string,
+        "context-types=gfxstream-gles:gfxstream-vulkan:gfxstream-composer",
+        gpu_common_3d_string);
+  } else if (gpu_mode == kGpuModeGfxstreamGuestAngle ||
+             gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
+    crosvm_cmd->AddParameter(
+        "--gpu=", gpu_displays_string,
+        "context-types=gfxstream-vulkan:gfxstream-composer",
+        gpu_common_3d_string);
+  } else if (gpu_mode == kGpuModeCustom) {
+    crosvm_cmd->AddParameter("--gpu=", gpu_displays_string,
+                             "context-types=" + instance.gpu_context_types(),
+                             gpu_common_string);
+  }
+
+  CF_EXPECT(MaybeConfigureVulkanIcd(config, crosvm_cmd));
+
   return {};
 }
 
@@ -434,6 +452,8 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
   auto instance = config.ForDefaultInstance();
   auto environment = config.ForDefaultEnvironment();
 
+  std::vector<MonitorCommand> commands;
+
   CrosvmBuilder crosvm_cmd;
   crosvm_cmd.Cmd().AddPrerequisite([&dependencyCommands]() -> Result<void> {
     for (auto dependencyCommand : dependencyCommands) {
@@ -484,6 +504,8 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
 
   crosvm_cmd.Cmd().AddParameter("--core-scheduling=false");
 
+  crosvm_cmd.Cmd().AddParameter("--vhost-user-connect-timeout-ms=", 30 * 1000);
+
   if (instance.vhost_net()) {
     crosvm_cmd.Cmd().AddParameter("--vhost-net");
   }
@@ -522,7 +544,7 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
   if (instance.hwcomposer() != kHwComposerNone) {
     const bool pmem_disabled = instance.mte() || !instance.use_pmem();
     if (!pmem_disabled && FileExists(instance.hwcomposer_pmem_path())) {
-      crosvm_cmd.Cmd().AddParameter("--rw-pmem-device=",
+      crosvm_cmd.Cmd().AddParameter("--pmem=path=",
                                     instance.hwcomposer_pmem_path());
     }
   }
@@ -536,16 +558,81 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
     crosvm_cmd.Cmd().AddParameter("--mte");
   }
 
+  if (!instance.vcpu_config_path().empty()) {
+    auto vcpu_config_json =
+        CF_EXPECT(LoadFromFile(instance.vcpu_config_path()));
+    std::string affinity_arg = "--cpu-affinity=";
+    std::string capacity_arg = "--cpu-capacity=";
+    std::string frequencies_arg = "--cpu-frequencies-khz=";
+
+    for (int i = 0; i < instance.cpus(); i++) {
+      if (i != 0) {
+        capacity_arg += ",";
+        affinity_arg += ":";
+        frequencies_arg += ";";
+      }
+
+      auto cpu_cluster = fmt::format("--cpu-cluster={}", i);
+
+      auto cpu = fmt::format("cpu{}", i);
+      const auto cpu_json =
+          CF_EXPECT(GetValue<Json::Value>(vcpu_config_json, {cpu}),
+                    "Missing vCPU config!");
+
+      const auto affinity =
+          CF_EXPECT(GetValue<std::string>(cpu_json, {"affinity"}));
+      auto affine_arg = fmt::format("{}={}", i, affinity);
+
+      const auto freqs =
+          CF_EXPECT(GetValue<std::string>(cpu_json, {"frequencies"}));
+      auto freq_arg = fmt::format("{}={}", i, freqs);
+
+      const auto capacity =
+          CF_EXPECT(GetValue<std::string>(cpu_json, {"capacity"}));
+      auto cap_arg = fmt::format("{}={}", i, capacity);
+
+      capacity_arg += cap_arg;
+      affinity_arg += affine_arg;
+      frequencies_arg += freq_arg;
+
+      crosvm_cmd.Cmd().AddParameter(cpu_cluster);
+    }
+
+    crosvm_cmd.Cmd().AddParameter(affinity_arg);
+    crosvm_cmd.Cmd().AddParameter(capacity_arg);
+    crosvm_cmd.Cmd().AddParameter(frequencies_arg);
+    crosvm_cmd.Cmd().AddParameter("--virt-cpufreq");
+  }
+
   auto disk_num = instance.virtual_disk_paths().size();
   CF_EXPECT(VmManager::kMaxDisks >= disk_num,
             "Provided too many disks (" << disk_num << "), maximum "
                                         << VmManager::kMaxDisks << "supported");
+  size_t disk_i = 0;
   for (const auto& disk : instance.virtual_disk_paths()) {
     if (instance.protected_vm()) {
       crosvm_cmd.AddReadOnlyDisk(disk);
+    } else if (instance.vhost_user_block() && disk_i == 2) {
+      // TODO: b/346855591 - Run on all devices
+      auto block = CF_EXPECT(VhostUserBlockDevice(config, disk_i, disk));
+      commands.emplace_back(std::move(block.device_cmd));
+      commands.emplace_back(std::move(block.device_logs_cmd));
+      auto socket_path = std::move(block.socket_path);
+      crosvm_cmd.Cmd().AddPrerequisite([socket_path]() -> Result<void> {
+#ifdef __linux__
+        return WaitForUnixSocketListeningWithoutConnect(socket_path,
+                                                        /*timeoutSec=*/30);
+#else
+        return CF_ERR("Unhandled check if vhost user block ready.");
+#endif
+      });
+      auto pci_addr = fmt::format("00:{:0>2x}.0", 0x13 + disk_i);
+      crosvm_cmd.Cmd().AddParameter("--vhost-user=block,socket=", socket_path,
+                                    ",pci-address=", pci_addr);
     } else {
       crosvm_cmd.AddReadWriteDisk(disk);
     }
+    disk_i++;
   }
 
   if (instance.enable_webrtc()) {
@@ -586,7 +673,6 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
                                   instance.switches_socket_path(), "]");
   }
 
-  SharedFD wifi_tap;
   // GPU capture can only support named files and not file descriptors due to
   // having to pass arguments to crosvm via a wrapper script.
 #ifdef __linux__
@@ -603,14 +689,14 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
     crosvm_cmd.AddTap(instance.ethernet_tap_name(), instance.ethernet_mac(), ethernet_pci);
 
     if (!config.virtio_mac80211_hwsim() && environment.enable_wifi()) {
-      wifi_tap = crosvm_cmd.AddTap(instance.wifi_tap_name());
+      crosvm_cmd.AddTap(instance.wifi_tap_name());
     }
   }
 #endif
 
   const bool pmem_disabled = instance.mte() || !instance.use_pmem();
   if (!pmem_disabled && FileExists(instance.access_kregistry_path())) {
-    crosvm_cmd.Cmd().AddParameter("--rw-pmem-device=",
+    crosvm_cmd.Cmd().AddParameter("--pmem=path=",
                                   instance.access_kregistry_path());
   }
 
@@ -819,10 +905,12 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
   if (instance.enable_virtiofs()) {
     CF_EXPECT(instance.enable_sandbox(),
               "virtiofs is currently not supported without sandboxing");
-    // Set up directory shared with virtiofs
+    // Set up directory shared with virtiofs, setting security_ctx option to
+    // false prevents host error when unable to write data in the
+    // /proc/thread-self/attr/fscreate file.
     crosvm_cmd.Cmd().AddParameter(
         "--shared-dir=", instance.PerInstancePath(kSharedDirName),
-        ":shared:type=fs");
+        ":shared:type=fs:security_ctx=false");
   }
 
   if (instance.target_arch() == Arch::X86_64) {
@@ -832,8 +920,6 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
   // This needs to be the last parameter
   crosvm_cmd.Cmd().AddParameter("--bios=", instance.bootloader());
 
-  std::vector<MonitorCommand> commands;
-
   if (vhost_user_gpu) {
     // The vhost user gpu crosvm command should be added before the main
     // crosvm command so that the main crosvm command can use a prerequisite
@@ -848,7 +934,7 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
 
   if (gpu_capture_enabled) {
     const std::string gpu_capture_basename =
-        cpp_basename(instance.gpu_capture_binary());
+        android::base::Basename(instance.gpu_capture_binary());
 
     auto gpu_capture_logs_path =
         instance.PerInstanceInternalPath("gpu_capture.fifo");
diff --git a/host/libs/vm_manager/qemu_manager.cpp b/host/libs/vm_manager/qemu_manager.cpp
index 1bbcc331b..4855cee6c 100644
--- a/host/libs/vm_manager/qemu_manager.cpp
+++ b/host/libs/vm_manager/qemu_manager.cpp
@@ -40,6 +40,7 @@
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/config/command_source.h"
 #include "host/libs/config/cuttlefish_config.h"
+#include "host/libs/vm_manager/vhost_user.h"
 
 namespace cuttlefish {
 namespace vm_manager {
@@ -220,7 +221,9 @@ QemuManager::ConfigureBootDevices(
 }
 
 Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
-    const CuttlefishConfig& config, std::vector<VmmDependencyCommand*>&) {
+    const CuttlefishConfig& config,
+    std::vector<VmmDependencyCommand*>& dependency_commands) {
+  std::vector<MonitorCommand> commands;
   auto instance = config.ForDefaultInstance();
   std::string qemu_binary = instance.qemu_binary_dir();
   switch (arch_) {
@@ -244,6 +247,14 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
   auto qemu_version = CF_EXPECT(GetQemuVersion(qemu_binary));
   Command qemu_cmd(qemu_binary, KillSubprocessFallback(Stop));
 
+  qemu_cmd.AddPrerequisite([&dependency_commands]() -> Result<void> {
+    for (auto dependencyCommand : dependency_commands) {
+      CF_EXPECT(dependencyCommand->WaitForAvailability());
+    }
+
+    return {};
+  });
+
   int hvc_num = 0;
   int serial_num = 0;
   auto add_hvc_sink = [&qemu_cmd, &hvc_num]() {
@@ -621,17 +632,35 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
   auto readonly = instance.protected_vm() ? ",readonly" : "";
   size_t i = 0;
   for (const auto& disk : instance.virtual_disk_paths()) {
-    qemu_cmd.AddParameter("-drive");
-    qemu_cmd.AddParameter("file=", disk, ",if=none,id=drive-virtio-disk", i,
-                          ",aio=threads", readonly);
-    qemu_cmd.AddParameter("-device");
-    qemu_cmd.AddParameter(
-#ifdef __APPLE__
-        "virtio-blk-pci-non-transitional,drive=drive-virtio-disk", i,
+    if (instance.vhost_user_block()) {
+      auto block = CF_EXPECT(VhostUserBlockDevice(config, i, disk));
+      commands.emplace_back(std::move(block.device_cmd));
+      commands.emplace_back(std::move(block.device_logs_cmd));
+      auto socket_path = std::move(block.socket_path);
+      qemu_cmd.AddPrerequisite([socket_path]() -> Result<void> {
+#ifdef __linux__
+        return WaitForUnixSocketListeningWithoutConnect(socket_path,
+                                                        /*timeoutSec=*/30);
 #else
-        "virtio-blk-pci-non-transitional,scsi=off,drive=drive-virtio-disk", i,
+        return CF_ERR("Unhandled check if vhost user block ready.");
 #endif
-        ",id=virtio-disk", i, (i == 0 ? ",bootindex=1" : ""));
+      });
+
+      qemu_cmd.AddParameter("-chardev");
+      qemu_cmd.AddParameter("socket,id=vhost-user-block-", i,
+                            ",path=", socket_path);
+      qemu_cmd.AddParameter("-device");
+      qemu_cmd.AddParameter(
+          "vhost-user-blk-pci-non-transitional,chardev=vhost-user-block-", i);
+    } else {
+      qemu_cmd.AddParameter("-drive");
+      qemu_cmd.AddParameter("file=", disk, ",if=none,id=drive-virtio-disk", i,
+                            ",aio=threads", readonly);
+      qemu_cmd.AddParameter("-device");
+      qemu_cmd.AddParameter(
+          "virtio-blk-pci-non-transitional,drive=drive-virtio-disk", i,
+          ",id=virtio-disk", i, (i == 0 ? ",bootindex=1" : ""));
+    }
     ++i;
   }
 
@@ -808,7 +837,6 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
     qemu_cmd.AddParameter("tcp::", instance.gdb_port());
   }
 
-  std::vector<MonitorCommand> commands;
   commands.emplace_back(std::move(qemu_cmd), true);
   return commands;
 }
diff --git a/host/libs/vm_manager/vhost_user.h b/host/libs/vm_manager/vhost_user.h
new file mode 100644
index 000000000..f1784fd24
--- /dev/null
+++ b/host/libs/vm_manager/vhost_user.h
@@ -0,0 +1,37 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+#pragma once
+
+#include <string>
+#include <string_view>
+
+#include "common/libs/utils/subprocess.h"
+#include "host/libs/config/cuttlefish_config.h"
+
+namespace cuttlefish {
+namespace vm_manager {
+
+struct VhostUserDeviceCommands {
+  Command device_cmd;
+  Command device_logs_cmd;
+  std::string socket_path;
+};
+
+Result<VhostUserDeviceCommands> VhostUserBlockDevice(
+    const CuttlefishConfig& config, int num, std::string_view disk_path);
+
+}  // namespace vm_manager
+}  // namespace cuttlefish
diff --git a/host/libs/vm_manager/vhost_user_block.cpp b/host/libs/vm_manager/vhost_user_block.cpp
new file mode 100644
index 000000000..bc7005546
--- /dev/null
+++ b/host/libs/vm_manager/vhost_user_block.cpp
@@ -0,0 +1,107 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *      http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+
+#include "host/libs/vm_manager/vhost_user.h"
+
+#include <sys/socket.h>
+#include <sys/stat.h>
+#include <sys/types.h>
+#include <sys/un.h>
+#include <sys/wait.h>
+#include <unistd.h>
+
+#include <cstdlib>
+#include <string>
+#include <utility>
+
+#include <android-base/logging.h>
+#include <android-base/strings.h>
+#include <vulkan/vulkan.h>
+
+#include "common/libs/utils/files.h"
+#include "common/libs/utils/result.h"
+#include "common/libs/utils/subprocess.h"
+#include "host/libs/config/cuttlefish_config.h"
+#include "host/libs/vm_manager/crosvm_builder.h"
+
+namespace cuttlefish {
+namespace vm_manager {
+
+// TODO(schuffelen): Deduplicate with BuildVhostUserGpu
+Result<VhostUserDeviceCommands> VhostUserBlockDevice(
+    const CuttlefishConfig& config, int num, std::string_view disk_path) {
+  const auto& instance = config.ForDefaultInstance();
+
+  CF_EXPECT(instance.vhost_user_block(), "Feature is not enabled");
+
+  auto block_device_socket_path = instance.PerInstanceInternalUdsPath(
+      fmt::format("vhost-user-block-{}-socket", num));
+  auto block_device_logs_path = instance.PerInstanceInternalPath(
+      fmt::format("crosvm_vhost_user_block_{}.fifo", num));
+  auto block_device_logs =
+      CF_EXPECT(SharedFD::Fifo(block_device_logs_path, 0666));
+
+  Command block_device_logs_cmd(HostBinaryPath("log_tee"));
+  block_device_logs_cmd.AddParameter("--process_name=crosvm_block_", num);
+  block_device_logs_cmd.AddParameter("--log_fd_in=", block_device_logs);
+  block_device_logs_cmd.SetStopper(KillSubprocessFallback([](Subprocess* proc) {
+    // Ask nicely so that log_tee gets a chance to process all the logs.
+    // TODO: b/335934714 - Make sure the process actually exits
+    bool res = kill(proc->pid(), SIGINT) == 0;
+    return res ? StopperResult::kStopSuccess : StopperResult::kStopFailure;
+  }));
+
+  const std::string crosvm_path = config.crosvm_binary();
+
+  CrosvmBuilder block_device_cmd;
+
+  // NOTE: The "main" crosvm process returns a kCrosvmVmResetExitCode when the
+  // guest exits but the "block" crosvm just exits cleanly with 0 after the
+  // "main" crosvm disconnects.
+  block_device_cmd.ApplyProcessRestarter(config.crosvm_binary(),
+                                         /*first_time_argument=*/"",
+                                         /*exit_code=*/0);
+
+  block_device_cmd.Cmd().AddParameter("devices");
+  block_device_cmd.Cmd().AddParameter("--block");
+  block_device_cmd.Cmd().AddParameter("vhost=", block_device_socket_path,
+                                      ",path=", disk_path);
+
+  if (instance.enable_sandbox()) {
+    const bool seccomp_exists = DirectoryExists(instance.seccomp_policy_dir());
+    const std::string& var_empty_dir = kCrosvmVarEmptyDir;
+    const bool var_empty_available = DirectoryExists(var_empty_dir);
+    CF_EXPECT(var_empty_available && seccomp_exists,
+              var_empty_dir << " is not an existing, empty directory."
+                            << "seccomp-policy-dir, "
+                            << instance.seccomp_policy_dir()
+                            << " does not exist");
+    block_device_cmd.Cmd().AddParameter("--jail");
+    block_device_cmd.Cmd().AddParameter("seccomp-policy-dir=",
+                                        instance.seccomp_policy_dir());
+  } else {
+    block_device_cmd.Cmd().AddParameter("--disable-sandbox");
+  }
+
+  return (VhostUserDeviceCommands){
+      .device_cmd = std::move(block_device_cmd.Cmd()),
+      .device_logs_cmd = std::move(block_device_logs_cmd),
+      .socket_path = block_device_socket_path,
+  };
+}
+
+}  // namespace vm_manager
+}  // namespace cuttlefish
diff --git a/host_package.mk b/host_package.mk
deleted file mode 100644
index 00abaa54c..000000000
--- a/host_package.mk
+++ /dev/null
@@ -1,28 +0,0 @@
-cvd_host_packages := $(HOST_OUT)/cvd-host_package
-ifeq ($(HOST_CROSS_OS), linux_musl)
-  cvd_host_packages := $(OUT_DIR)/host/$(HOST_CROSS_OS)-$(HOST_CROSS_ARCH)/cvd-host_package $(cvd_host_packages)
-endif
-
-cvd_host_dir_stamps := $(addsuffix .stamp,$(cvd_host_packages))
-cvd_host_tarballs := $(addsuffix .tar.gz,$(cvd_host_packages))
-
-.PHONY: hosttar
-hosttar: $(cvd_host_tarballs)
-
-# Build this by default when a developer types make.
-# Skip the tarballs by default as it is time consuming.
-droidcore: $(cvd_host_dir_stamps)
-
-# Dist
-# Dist the first package as cvd-host_package.tar.gz.  It would be from x86 in case of cf_x86_phone,
-# and from arm64 in case of cf_arm64_phone.
-$(call dist-for-goals, dist_files,$(firstword $(cvd_host_tarballs)))
-ifeq ($(HOST_CROSS_OS)-$(HOST_CROSS_ARCH), linux_musl-arm64)
-  # If the normal package is arm64, also dist an x86_64 package.
-  $(call dist-for-goals, dist_files,$(lastword $(cvd_host_tarballs)):cvd-host_package-x86_64.tar.gz)
-endif
-
-
-cvd_host_dir_stamps :=
-cvd_host_packages :=
-cvd_host_tarballs :=
diff --git a/required_images b/required_images
index ab6c2c0ab..837224b75 100644
--- a/required_images
+++ b/required_images
@@ -1,10 +1,11 @@
+android-info.txt
 boot.img
-init_boot.img
 bootloader
+init_boot.img
 super.img
 userdata.img
 vbmeta.img
+vbmeta_system_dlkm.img
 vbmeta_system.img
 vbmeta_vendor_dlkm.img
-vbmeta_system_dlkm.img
 vendor_boot.img
diff --git a/shared/BoardConfig.mk b/shared/BoardConfig.mk
index 3dadfbca4..b9f1bcb36 100644
--- a/shared/BoardConfig.mk
+++ b/shared/BoardConfig.mk
@@ -22,8 +22,6 @@
 # 32 bit devices (Wear, Go, Auto)
 ifeq (true,$(CLOCKWORK_EMULATOR_PRODUCT))
 TARGET_KERNEL_USE ?= 6.1
-else ifneq (,$(findstring x86_phone,$(PRODUCT_NAME)))
-TARGET_KERNEL_USE ?= 6.1
 else ifneq (,$(findstring x86_tv,$(PRODUCT_NAME)))
 TARGET_KERNEL_USE ?= 6.1
 else
@@ -39,6 +37,13 @@ PRODUCT_COPY_FILES += $(TARGET_KERNEL_PATH):kernel
 
 BOARD_KERNEL_VERSION := $(word 1,$(subst vermagic=,,$(shell egrep -h -ao -m 1 'vermagic=.*' $(KERNEL_MODULES_PATH)/nd_virtio.ko)))
 
+ifneq (,$(findstring auto, $(PRODUCT_NAME)))
+HIB_SWAP_IMAGE_SIZE_GB ?= 4
+ifeq ("$(wildcard $(PRODUCT_OUT)/hibernation_swap.img)", "")
+$(shell dd if=/dev/zero of=$(PRODUCT_OUT)/hibernation_swap.img bs=1K count=$(HIB_SWAP_IMAGE_SIZE_GB)M)
+endif
+endif
+
 # The list of modules strictly/only required either to reach second stage
 # init, OR for recovery. Do not use this list to workaround second stage
 # issues.
@@ -56,12 +61,6 @@ RAMDISK_KERNEL_MODULES ?= \
     virtio-rng.ko \
     vmw_vsock_virtio_transport.ko \
 
-ifeq ($(TARGET_KERNEL_ARCH),arm64)
-BOARD_KERNEL_PATH_16K := kernel/prebuilts/mainline/$(TARGET_KERNEL_ARCH)/16k/kernel-mainline
-BOARD_KERNEL_MODULES_16K += $(wildcard kernel/prebuilts/mainline/$(TARGET_KERNEL_ARCH)/16k/*.ko)
-BOARD_KERNEL_MODULES_16K += $(wildcard kernel/prebuilts/common-modules/virtual-device/mainline/$(TARGET_KERNEL_ARCH)/16k/*.ko)
-endif
-
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(patsubst %,$(KERNEL_MODULES_PATH)/%,$(RAMDISK_KERNEL_MODULES))
 
@@ -83,15 +82,24 @@ BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_DLKM_SRC)/libarc4.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_DLKM_SRC)/rfkill.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_DLKM_SRC)/cfg80211.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_DLKM_SRC)/mac80211.ko)
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/libarc4.ko)
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/rfkill.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/cfg80211.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/mac80211.ko)
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/mac80211_hwsim.ko)
 BOARD_DO_NOT_STRIP_VENDOR_RAMDISK_MODULES := true
-ALL_KERNEL_MODULES := $(wildcard $(KERNEL_MODULES_PATH)/*.ko)
 BOARD_VENDOR_KERNEL_MODULES := \
     $(filter-out $(BOARD_VENDOR_RAMDISK_KERNEL_MODULES),\
                  $(wildcard $(KERNEL_MODULES_PATH)/*.ko))
 
+ifeq ($(TARGET_KERNEL_ARCH),arm64)
+ifeq (true,$(PRODUCT_16K_DEVELOPER_OPTION))
+BOARD_KERNEL_PATH_16K := kernel/prebuilts/mainline/$(TARGET_KERNEL_ARCH)/16k/kernel-mainline
+BOARD_KERNEL_MODULES_16K += $(wildcard kernel/prebuilts/mainline/$(TARGET_KERNEL_ARCH)/16k/*.ko)
+BOARD_KERNEL_MODULES_16K += $(wildcard kernel/prebuilts/common-modules/virtual-device/mainline/$(TARGET_KERNEL_ARCH)/16k/*.ko)
+endif
+endif
+
 # TODO(b/170639028): Back up TARGET_NO_BOOTLOADER
 __TARGET_NO_BOOTLOADER := $(TARGET_NO_BOOTLOADER)
 include build/make/target/board/BoardConfigMainlineCommon.mk
@@ -350,11 +358,6 @@ BOARD_KERNEL_CMDLINE += firmware_class.path=/vendor/etc/
 BOARD_KERNEL_CMDLINE += loop.max_part=7
 BOARD_KERNEL_CMDLINE += init=/init
 
-# Enable KUnit for userdebug and eng builds
-ifneq (,$(filter userdebug eng, $(TARGET_BUILD_VARIANT)))
-  BOARD_KERNEL_CMDLINE += kunit.enable=1
-endif
-
 BOARD_BOOTCONFIG += androidboot.hardware=cutf_cvm
 
 # TODO(b/182417593): vsock transport is a module on some kernels and builtin
diff --git a/shared/auto/Android.bp b/shared/auto/Android.bp
new file mode 100644
index 000000000..2bc750507
--- /dev/null
+++ b/shared/auto/Android.bp
@@ -0,0 +1,24 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_auto.json",
+    src: "config_auto.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/auto/OWNERS b/shared/auto/OWNERS
index f97912a73..6523f0f0b 100644
--- a/shared/auto/OWNERS
+++ b/shared/auto/OWNERS
@@ -1,4 +1,6 @@
 # Android Auto leads
 include platform/packages/services/Car:/OWNERS
 ankitarora@google.com
-egranata@google.com
+changyeon@google.com
+gurchetansingh@google.com
+skeys@google.com
diff --git a/shared/auto/TEST_MAPPING b/shared/auto/TEST_MAPPING
index 99fe08355..d938af55c 100644
--- a/shared/auto/TEST_MAPPING
+++ b/shared/auto/TEST_MAPPING
@@ -19,10 +19,61 @@
       "name": "CtsCarBuiltinApiHostTestCases"
     },
     {
-      "name": "CarServiceTest"
+      "name": "CarServiceAudioTest"
+    },
+    {
+      "name": "CarServiceCarTest"
+    },
+    {
+      "name": "CarServiceClusterTest"
+    },
+    {
+      "name": "CarServiceDiagnosticTest"
+    },
+    {
+      "name": "CarServiceDrivingStateTest"
+    },
+    {
+      "name": "CarServiceEvsTest"
+    },
+    {
+      "name": "CarServiceGarageModeTest"
+    },
+    {
+      "name": "CarServiceInputTest"
+    },
+    {
+      "name": "CarServiceOsTest"
+    },
+    {
+      "name": "CarServicePmTest"
+    },
+    {
+      "name": "CarServicePowerTest"
+    },
+    {
+      "name": "CarServicePropertyTest"
+    },
+    {
+      "name": "CarServiceRemoteAccessTest"
+    },
+    {
+      "name": "CarServiceStorageMonitoringTest"
+    },
+    {
+      "name": "CarServiceTelemetryTest"
     },
     {
       "name": "CarServiceUnitTest"
+    },
+    {
+      "name": "CarServiceVmsTest"
+    },
+    {
+      "name": "CarServiceWatchdogTest"
+    },
+    {
+      "name": "VtsHalAutomotiveVehicle_TargetTest"
     }
   ]
 }
diff --git a/shared/auto/android-info.txt b/shared/auto/android-info.txt
index 74c0e2ebc..1b3dd601b 100644
--- a/shared/auto/android-info.txt
+++ b/shared/auto/android-info.txt
@@ -1,2 +1,4 @@
 config=auto
 gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
+vhost_user_vsock=true
diff --git a/shared/config/config_auto.json b/shared/auto/config_auto.json
similarity index 63%
rename from shared/config/config_auto.json
rename to shared/auto/config_auto.json
index 67dd3bc8c..0e6835145 100644
--- a/shared/config/config_auto.json
+++ b/shared/auto/config_auto.json
@@ -1,5 +1,6 @@
 {
 	"display0": "width=1080,height=600,dpi=120",
 	"display1": "width=400,height=600,dpi=120",
-	"memory_mb" : 4096
+	"memory_mb" : 4096,
+	"enable_vhal_proxy_server": true
 }
diff --git a/shared/auto/device_vendor.mk b/shared/auto/device_vendor.mk
index 99856ac2a..2cd311fe7 100644
--- a/shared/auto/device_vendor.mk
+++ b/shared/auto/device_vendor.mk
@@ -49,6 +49,10 @@ endif
 PRODUCT_PRODUCT_PROPERTIES += \
     ro.boot.uwbcountrycode=US
 
+PRODUCT_SYSTEM_PROPERTIES += \
+    ro.sys.hibernate_enabled=1 \
+    ro.sys.swap_storage_device=/dev/block/vda19
+
 PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/car_core_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/car_core_hardware.xml \
     frameworks/native/data/etc/android.hardware.broadcastradio.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.broadcastradio.xml \
@@ -79,9 +83,13 @@ PRODUCT_PACKAGES += \
 PRODUCT_COPY_FILES += \
     device/google/cuttlefish/shared/auto/display_settings.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings.xml
 
+# Include the fstab needed for suspend to disk
+PRODUCT_COPY_FILES += \
+    device/google/cuttlefish/shared/auto/hibernation_swap/fstab.hibernationswap:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.hibernationswap
+
 # vehicle HAL
 ifeq ($(LOCAL_VHAL_PRODUCT_PACKAGE),)
-    LOCAL_VHAL_PRODUCT_PACKAGE := android.hardware.automotive.vehicle@V3-emulator-service
+    LOCAL_VHAL_PRODUCT_PACKAGE := com.android.hardware.automotive.vehicle.cf
     BOARD_SEPOLICY_DIRS += device/google/cuttlefish/shared/auto/sepolicy/vhal
 endif
 PRODUCT_PACKAGES += $(LOCAL_VHAL_PRODUCT_PACKAGE)
@@ -132,12 +140,11 @@ ENABLE_CARTELEMETRY_SERVICE ?= true
 
 ifeq ($(ENABLE_MOCK_EVSHAL), true)
 CUSTOMIZE_EVS_SERVICE_PARAMETER := true
-USE_AIDL_DISPLAY_SERVICE := true
 PRODUCT_PACKAGES += android.hardware.automotive.evs-aidl-default-service
 PRODUCT_COPY_FILES += \
     device/google/cuttlefish/shared/auto/evs/init.evs.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/init.evs.rc
-BOARD_SEPOLICY_DIRS += device/google/cuttlefish/shared/auto/sepolicy/evs
 endif
+BOARD_SEPOLICY_DIRS += device/google/cuttlefish/shared/auto/sepolicy/evs
 
 ifeq ($(ENABLE_SAMPLE_EVS_APP), true)
 PRODUCT_COPY_FILES += \
@@ -155,3 +162,4 @@ PRODUCT_PACKAGES += ConnectivityOverlayCuttleFish
 GOOGLE_CAR_SERVICE_OVERLAY += ConnectivityOverlayCuttleFishGoogle
 
 TARGET_BOARD_INFO_FILE ?= device/google/cuttlefish/shared/auto/android-info.txt
+BOARD_BOOTCONFIG += androidboot.hibernation_resume_device=259:3
diff --git a/shared/auto/hibernation_swap/fstab.hibernationswap b/shared/auto/hibernation_swap/fstab.hibernationswap
new file mode 100644
index 000000000..7e39360c2
--- /dev/null
+++ b/shared/auto/hibernation_swap/fstab.hibernationswap
@@ -0,0 +1 @@
+/dev/block/vda19 none swap defaults defaults
diff --git a/shared/auto/preinstalled-packages-product-car-cuttlefish.xml b/shared/auto/preinstalled-packages-product-car-cuttlefish.xml
index 0d0cc0636..3a5adbf2c 100644
--- a/shared/auto/preinstalled-packages-product-car-cuttlefish.xml
+++ b/shared/auto/preinstalled-packages-product-car-cuttlefish.xml
@@ -146,9 +146,6 @@
     </install-in-user-type>
     <install-in-user-type package="com.android.car.linkviewer">
         <install-in user-type="FULL" />
-    </install-in-user-type>
-    <install-in-user-type package="com.android.car.multidisplay">
-        <install-in user-type="FULL" />
     </install-in-user-type>
       <install-in-user-type package="com.android.car.voicecontrol">
         <install-in user-type="FULL" />
diff --git a/shared/auto/rro_overlay/CarServiceOverlay/res/values/config.xml b/shared/auto/rro_overlay/CarServiceOverlay/res/values/config.xml
index b2dc997be..95a4ed3f5 100644
--- a/shared/auto/rro_overlay/CarServiceOverlay/res/values/config.xml
+++ b/shared/auto/rro_overlay/CarServiceOverlay/res/values/config.xml
@@ -92,7 +92,7 @@
 
     <!-- A name of a camera device that provides the rearview through EVS service -->
     <string-array name="config_carEvsService" translatable="false">
-        <item>serviceType=REARVIEW,cameraId=/dev/video10,activityName=com.android.car/com.google.android.car.evs.CarEvsCameraPreviewActivity</item>
+        <item>serviceType=REARVIEW,cameraId=/dev/video10,activityName=com.google.android.car.evs/com.google.android.car.evs.CarEvsCameraPreviewActivity</item>
         <item>serviceType=FRONTVIEW,cameraId=/dev/video11</item>
     </string-array>
 </resources>
diff --git a/shared/auto/sepolicy/vendor/file_contexts b/shared/auto/sepolicy/vendor/file_contexts
index a99d79d13..03868c641 100644
--- a/shared/auto/sepolicy/vendor/file_contexts
+++ b/shared/auto/sepolicy/vendor/file_contexts
@@ -2,3 +2,4 @@
 /vendor/bin/hw/android\.hardware\.automotive\.vehicle@V[0-9]+-cf-service    u:object_r:hal_vehicle_default_exec:s0
 # Battery Health HAL
 /vendor/bin/hw/android\.hardware\.health-service\.automotive                u:object_r:hal_health_default_exec:s0
+/dev/block/vda19                                                            u:object_r:swap_block_device:s0
diff --git a/shared/auto_dd/Android.bp b/shared/auto_dd/Android.bp
new file mode 100644
index 000000000..355a2b429
--- /dev/null
+++ b/shared/auto_dd/Android.bp
@@ -0,0 +1,24 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_auto_dd.json",
+    src: "config_auto_dd.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/auto_dd/config_auto_dd.json b/shared/auto_dd/config_auto_dd.json
new file mode 100644
index 000000000..0f90134cd
--- /dev/null
+++ b/shared/auto_dd/config_auto_dd.json
@@ -0,0 +1,5 @@
+{
+	"display0": "width=1080,height=600,dpi=120",
+	"display1": "width=4000,height=800,dpi=160",
+	"memory_mb" : 8096
+}
diff --git a/shared/auto_md/Android.bp b/shared/auto_md/Android.bp
new file mode 100644
index 000000000..ad40f1d5c
--- /dev/null
+++ b/shared/auto_md/Android.bp
@@ -0,0 +1,24 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_auto_md.json",
+    src: "config_auto_md.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/auto_md/android-info.txt b/shared/auto_md/android-info.txt
index 1a130ffe4..9021818c8 100644
--- a/shared/auto_md/android-info.txt
+++ b/shared/auto_md/android-info.txt
@@ -1,2 +1,3 @@
 config=auto_md
 gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
diff --git a/shared/config/config_auto_md.json b/shared/auto_md/config_auto_md.json
similarity index 77%
rename from shared/config/config_auto_md.json
rename to shared/auto_md/config_auto_md.json
index 7eb22c322..0ec423f15 100644
--- a/shared/config/config_auto_md.json
+++ b/shared/auto_md/config_auto_md.json
@@ -3,5 +3,6 @@
 	"display1": "width=400,height=600,dpi=120",
 	"display2": "width=800,height=600,dpi=120",
 	"display3": "width=800,height=600,dpi=120",
-	"memory_mb" : 4096
+	"memory_mb" : 4096,
+	"enable_vhal_proxy_server": true
 }
diff --git a/shared/auto_md/overlay/frameworks/base/core/res/res/values/config.xml b/shared/auto_md/overlay/frameworks/base/core/res/res/values/config.xml
index f12cba55c..45415898d 100644
--- a/shared/auto_md/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/shared/auto_md/overlay/frameworks/base/core/res/res/values/config.xml
@@ -28,14 +28,6 @@
     <!-- Maximum number of users we allow to be running at a time -->
     <integer name="config_multiuserMaxRunningUsers">5</integer>
 
-    <!-- True if the device supports system decorations on secondary displays. -->
-    <bool name="config_supportsSystemDecorsOnSecondaryDisplays">true</bool>
-    <!-- This is the default launcher package with an activity to use on secondary displays that
-         support system decorations.
-         This launcher package must have an activity that supports multiple instances and has
-         corresponding launch mode set in AndroidManifest.
-         {@see android.view.Display#FLAG_SHOULD_SHOW_SYSTEM_DECORATIONS} -->
-    <string name="config_secondaryHomePackage" translatable="false">com.android.car.multidisplay</string>
     <!-- Whether to only install system packages on a user if they're whitelisted for that user
          type. These are flags and can be freely combined.
          0  - disable whitelist (install all system packages; no logging)
@@ -58,6 +50,5 @@
 
     <!-- Whether the device allows users to start in background visible on displays.
          Should be false for most devices, except automotive vehicle with passenger displays. -->
-    <!-- The config is enabled for the development purpose only. -->
     <bool name="config_multiuserVisibleBackgroundUsers">true</bool>
 </resources>
diff --git a/shared/auto_md/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml b/shared/auto_md/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
new file mode 100644
index 000000000..f1faa1118
--- /dev/null
+++ b/shared/auto_md/overlay/frameworks/base/packages/SettingsProvider/res/values/defaults.xml
@@ -0,0 +1,24 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+/**
+ * Copyright (c) 2024, The Android Open Source Project
+ *
+ * Licensed under the Apache License, Version 2.0 (the "License");
+ * you may not use this file except in compliance with the License.
+ * You may obtain a copy of the License at
+ *
+ *     http://www.apache.org/licenses/LICENSE-2.0
+ *
+ * Unless required by applicable law or agreed to in writing, software
+ * distributed under the License is distributed on an "AS IS" BASIS,
+ * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+ * See the License for the specific language governing permissions and
+ * limitations under the License.
+ */
+-->
+
+<resources>
+    <!-- Allow users to use both the on-screen keyboard, as well as a real
+         keyboard -->
+    <bool name="def_show_ime_with_hard_keyboard">true</bool>
+</resources>
diff --git a/shared/auto_mdnd/OWNERS b/shared/auto_mdnd/OWNERS
new file mode 100644
index 000000000..5482d9b91
--- /dev/null
+++ b/shared/auto_mdnd/OWNERS
@@ -0,0 +1 @@
+include device/google/cuttlefish:/shared/auto_md/OWNERS
diff --git a/shared/auto_mdnd/overlay/frameworks/base/core/res/res/values/config.xml b/shared/auto_mdnd/overlay/frameworks/base/core/res/res/values/config.xml
index 9c02715b6..b23af7af8 100644
--- a/shared/auto_mdnd/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/shared/auto_mdnd/overlay/frameworks/base/core/res/res/values/config.xml
@@ -21,6 +21,5 @@
     <!-- Whether the device allows users to start in background visible on the default display.
          Should be false for most devices, except passenger-only automotive build (i.e., when
          Android runs in a separate system in the back seat to manage the passenger displays) -->
-    <!-- The config is enabled for the development purpose only. -->
     <bool name="config_multiuserVisibleBackgroundUsersOnDefaultDisplay">true</bool>
 </resources>
diff --git a/shared/auto_portrait/Android.bp b/shared/auto_portrait/Android.bp
new file mode 100644
index 000000000..8b62f0de6
--- /dev/null
+++ b/shared/auto_portrait/Android.bp
@@ -0,0 +1,24 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_auto_portrait.json",
+    src: "config_auto_portrait.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/auto_portrait/android-info.txt b/shared/auto_portrait/android-info.txt
index ea15130d8..110c70aa6 100644
--- a/shared/auto_portrait/android-info.txt
+++ b/shared/auto_portrait/android-info.txt
@@ -1,2 +1,3 @@
 config=auto_portrait
 gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
diff --git a/shared/auto_portrait/config_auto_portrait.json b/shared/auto_portrait/config_auto_portrait.json
new file mode 100644
index 000000000..a322dc407
--- /dev/null
+++ b/shared/auto_portrait/config_auto_portrait.json
@@ -0,0 +1,5 @@
+{
+	"display0": "width=1224,height=2175,dpi=140",
+	"memory_mb" : 4096,
+	"enable_vhal_proxy_server": true
+}
diff --git a/shared/biometrics_face/device_vendor.mk b/shared/biometrics_face/device_vendor.mk
index de76343a4..7fe490880 100644
--- a/shared/biometrics_face/device_vendor.mk
+++ b/shared/biometrics_face/device_vendor.mk
@@ -15,4 +15,5 @@
 #
 
 PRODUCT_PACKAGES += \
-    com.android.hardware.biometrics.face.virtual
+    com.android.hardware.biometrics.face.virtual \
+    android.hardware.biometrics.face-service.default
diff --git a/shared/biometrics_fingerprint/device_vendor.mk b/shared/biometrics_fingerprint/device_vendor.mk
index b09535541..c9e03413c 100644
--- a/shared/biometrics_fingerprint/device_vendor.mk
+++ b/shared/biometrics_fingerprint/device_vendor.mk
@@ -18,4 +18,5 @@ PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.hardware.fingerprint.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.fingerprint.xml
 
 PRODUCT_PACKAGES += \
-    com.android.hardware.biometrics.fingerprint.virtual
+    com.android.hardware.biometrics.fingerprint.virtual \
+    android.hardware.biometrics.fingerprint-service.default
diff --git a/shared/config/Android.bp b/shared/config/Android.bp
index ef10cc28b..877b37a13 100644
--- a/shared/config/Android.bp
+++ b/shared/config/Android.bp
@@ -30,78 +30,6 @@ license {
     license_text: ["LICENSE_BSD"],
 }
 
-prebuilt_etc_host {
-    name: "cvd_config_auto.json",
-    src: "config_auto.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_auto_md.json",
-    src: "config_auto_md.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_auto_dd.json",
-    src: "config_auto_dd.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_auto_portrait.json",
-    src: "config_auto_portrait.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_foldable.json",
-    src: "config_foldable.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_go.json",
-    src: "config_go.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_minidroid.json",
-    src: "config_minidroid.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_phone.json",
-    src: "config_phone.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_slim.json",
-    src: "config_slim.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_tablet.json",
-    src: "config_tablet.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_tv.json",
-    src: "config_tv.json",
-    sub_dir: "cvd_config",
-}
-
-prebuilt_etc_host {
-    name: "cvd_config_wear.json",
-    src: "config_wear.json",
-    sub_dir: "cvd_config",
-}
-
 prebuilt_etc {
     name: "wpa_supplicant_overlay.conf.cf",
     src: "wpa_supplicant_overlay.conf",
diff --git a/shared/config/audio/policy/audio_policy_configuration.xml b/shared/config/audio/policy/audio_policy_configuration.xml
new file mode 100644
index 000000000..6e57dd04b
--- /dev/null
+++ b/shared/config/audio/policy/audio_policy_configuration.xml
@@ -0,0 +1,46 @@
+<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<audioPolicyConfiguration version="7.0" xmlns:xi="http://www.w3.org/2001/XInclude">
+    <!-- version section contains a “version” tag in the form “major.minor” e.g. version=”1.0” -->
+
+    <!-- Global configuration Decalaration -->
+    <globalConfiguration speaker_drc_enabled="false"/>
+
+    <modules>
+        <!-- Primary Audio HAL -->
+        <xi:include href="primary_audio_policy_configuration.xml"/>
+
+        <!-- Remote Submix Audio HAL -->
+        <xi:include href="r_submix_audio_policy_configuration.xml"/>
+
+        <!-- Bluetooth Audio HAL -->
+        <xi:include href="bluetooth_audio_policy_configuration_7_0.xml"/>
+    </modules>
+    <!-- End of Modules section -->
+
+    <!-- Volume section:
+        IMPORTANT NOTE: Volume tables have been moved to engine configuration.
+                        Keep it here for legacy.
+                        Engine will fallback on these files if none are provided by engine.
+     -->
+
+    <xi:include href="audio_policy_volumes.xml"/>
+    <xi:include href="default_volume_tables.xml"/>
+
+    <!-- End of Volume section -->
+
+</audioPolicyConfiguration>
diff --git a/shared/config/audio/policy/primary_audio_policy_configuration.xml b/shared/config/audio/policy/primary_audio_policy_configuration.xml
new file mode 100644
index 000000000..3d2a15108
--- /dev/null
+++ b/shared/config/audio/policy/primary_audio_policy_configuration.xml
@@ -0,0 +1,84 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- Copyright (C) 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<!-- Default Primary Audio HAL Module Audio Policy Configuration include file -->
+<module name="primary" halVersion="3.0">
+    <attachedDevices>
+        <item>Speaker</item>
+        <item>Built-In Mic</item>
+        <item>Telephony Tx</item>
+        <item>Telephony Rx</item>
+        <item>FM Tuner</item>
+    </attachedDevices>
+    <defaultOutputDevice>Speaker</defaultOutputDevice>
+    <mixPorts>
+        <mixPort name="primary output" role="source" flags="AUDIO_OUTPUT_FLAG_PRIMARY">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
+                     samplingRates="8000 11025 16000 32000 44100 48000"
+                     channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO"/>
+        </mixPort>
+        <mixPort name="primary input" role="sink">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
+                     samplingRates="8000 11025 16000 32000 44100 48000"
+                     channelMasks="AUDIO_CHANNEL_IN_MONO AUDIO_CHANNEL_IN_STEREO"/>
+        </mixPort>
+
+        <mixPort name="telephony_tx" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
+                     samplingRates="8000 11025 16000 32000 44100 48000"
+                     channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO"/>
+        </mixPort>
+        <mixPort name="telephony_rx" role="sink">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
+                     samplingRates="8000 11025 16000 32000 44100 48000"
+                     channelMasks="AUDIO_CHANNEL_IN_MONO AUDIO_CHANNEL_IN_STEREO"/>
+        </mixPort>
+
+        <mixPort name="fm_tuner" role="sink">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
+                     samplingRates="8000 11025 16000 32000 44100 48000"
+                     channelMasks="AUDIO_CHANNEL_IN_MONO AUDIO_CHANNEL_IN_STEREO"/>
+        </mixPort>
+   </mixPorts>
+   <devicePorts>
+        <devicePort tagName="Speaker" type="AUDIO_DEVICE_OUT_SPEAKER" role="sink">
+        </devicePort>
+        <devicePort tagName="Telephony Tx" type="AUDIO_DEVICE_OUT_TELEPHONY_TX" role="sink">
+        </devicePort>
+
+        <devicePort tagName="Built-In Mic" type="AUDIO_DEVICE_IN_BUILTIN_MIC" role="source">
+        </devicePort>
+        <devicePort tagName="Telephony Rx" type="AUDIO_DEVICE_IN_TELEPHONY_RX" role="source">
+        </devicePort>
+
+        <devicePort tagName="FM Tuner" type="AUDIO_DEVICE_IN_FM_TUNER" role="source">
+        </devicePort>
+    </devicePorts>
+    <routes>
+        <route type="mix" sink="Speaker"
+               sources="primary output"/>
+        <route type="mix" sink="primary input"
+               sources="Built-In Mic"/>
+
+        <route type="mix" sink="telephony_rx"
+               sources="Telephony Rx"/>
+        <route type="mix" sink="Telephony Tx"
+               sources="telephony_tx"/>
+
+        <route type="mix" sink="fm_tuner"
+               sources="FM Tuner"/>
+    </routes>
+</module>
diff --git a/shared/config/config_auto_dd.json b/shared/config/config_auto_dd.json
index 0f90134cd..37b24f5f8 100644
--- a/shared/config/config_auto_dd.json
+++ b/shared/config/config_auto_dd.json
@@ -1,5 +1,6 @@
 {
 	"display0": "width=1080,height=600,dpi=120",
 	"display1": "width=4000,height=800,dpi=160",
-	"memory_mb" : 8096
+	"memory_mb" : 8096,
+	"enable_vhal_proxy_server": true
 }
diff --git a/shared/config/config_auto_portrait.json b/shared/config/config_auto_portrait.json
deleted file mode 100644
index 565f3dc9d..000000000
--- a/shared/config/config_auto_portrait.json
+++ /dev/null
@@ -1,4 +0,0 @@
-{
-	"display0": "width=1224,height=2175,dpi=140",
-	"memory_mb" : 4096
-}
diff --git a/shared/config/init.vendor.rc b/shared/config/init.vendor.rc
index 4925c5d39..4c2fbad84 100644
--- a/shared/config/init.vendor.rc
+++ b/shared/config/init.vendor.rc
@@ -10,6 +10,12 @@ on early-init
     # specially load zram as it is a "leaf" GKI module
     exec u:r:modprobe:s0 -- /system/bin/modprobe -a -d /system/lib/modules zram.ko
 
+on early-init && property:ro.boot.vendor.apex.com.android.hardware.keymint=\
+com.android.hardware.keymint.rust_cf_guest_trusty_nonsecure
+    # Enable Trusty VM and KeyMint VM
+    setprop ro.hardware.security.trusty_vm.system 1
+    setprop ro.hardware.security.keymint.trusty.system 1
+
 on init
     # ZRAM setup
     write /sys/block/zram0/comp_algorithm lz4
diff --git a/shared/config/manifest.xml b/shared/config/manifest.xml
index 012d3831c..5ac59208e 100644
--- a/shared/config/manifest.xml
+++ b/shared/config/manifest.xml
@@ -16,7 +16,7 @@
 ** limitations under the License.
 */
 -->
-<manifest version="1.0" type="device" target-level="202404">
+<manifest version="1.0" type="device" target-level="202504">
 
     <!-- DO NOT ADD MORE - use vintf_fragments -->
 
diff --git a/shared/config/previous_manifest.xml b/shared/config/previous_manifest.xml
new file mode 100644
index 000000000..18ae50ee5
--- /dev/null
+++ b/shared/config/previous_manifest.xml
@@ -0,0 +1,23 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!--
+/*
+** Copyright 2024, The Android Open Source Project.
+**
+** Licensed under the Apache License, Version 2.0 (the "License");
+** you may not use this file except in compliance with the License.
+** You may obtain a copy of the License at
+**
+**     http://www.apache.org/licenses/LICENSE-2.0
+**
+** Unless required by applicable law or agreed to in writing, software
+** distributed under the License is distributed on an "AS IS" BASIS,
+** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+** See the License for the specific language governing permissions and
+** limitations under the License.
+*/
+-->
+<manifest version="1.0" type="device" target-level="202404">
+
+    <!-- DO NOT ADD MORE - use vintf_fragments -->
+
+</manifest>
diff --git a/shared/device.mk b/shared/device.mk
index 2bb4c08f2..f9107ffc6 100644
--- a/shared/device.mk
+++ b/shared/device.mk
@@ -39,6 +39,8 @@ PRODUCT_SOONG_NAMESPACES += device/generic/goldfish # for audio, wifi and sensor
 
 PRODUCT_USE_DYNAMIC_PARTITIONS := true
 DISABLE_RILD_OEM_HOOK := true
+# For customize cflags for libril share library building by soong.
+$(call soong_config_set,ril,disable_rild_oem_hook,true)
 
 # TODO(b/294888357) Remove this condition when OpenWRT is supported for RISC-V.
 ifndef PRODUCT_ENFORCE_MAC80211_HWSIM
@@ -49,6 +51,7 @@ PRODUCT_SET_DEBUGFS_RESTRICTIONS := true
 
 PRODUCT_FS_COMPRESSION := 1
 TARGET_RO_FILE_SYSTEM_TYPE ?= erofs
+BOARD_EROFS_COMPRESS_HINTS := device/google/cuttlefish/shared/erofs_compress_hints.txt
 TARGET_USERDATAIMAGE_FILE_SYSTEM_TYPE ?= f2fs
 TARGET_USERDATAIMAGE_PARTITION_SIZE ?= 8589934592
 
@@ -211,8 +214,14 @@ PRODUCT_PACKAGES += CFSatelliteService
 #
 # Common manifest for all targets
 #
-PRODUCT_SHIPPING_API_LEVEL := 35
+
+ifeq ($(RELEASE_AIDL_USE_UNFROZEN),true)
+PRODUCT_SHIPPING_API_LEVEL := 36
 LOCAL_DEVICE_FCM_MANIFEST_FILE ?= device/google/cuttlefish/shared/config/manifest.xml
+else
+PRODUCT_SHIPPING_API_LEVEL := 35
+LOCAL_DEVICE_FCM_MANIFEST_FILE ?= device/google/cuttlefish/shared/config/previous_manifest.xml
+endif
 DEVICE_MANIFEST_FILE += $(LOCAL_DEVICE_FCM_MANIFEST_FILE)
 
 PRODUCT_CHECK_PREBUILT_MAX_PAGE_SIZE := true
@@ -231,7 +240,6 @@ PRODUCT_COPY_FILES += \
     device/google/cuttlefish/shared/config/media_profiles.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_profiles_vendor.xml \
     device/google/cuttlefish/shared/config/seriallogging.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/seriallogging.rc \
     device/google/cuttlefish/shared/config/ueventd.rc:$(TARGET_COPY_OUT_VENDOR)/etc/ueventd.rc \
-    device/google/cuttlefish/shared/permissions/cuttlefish_excluded_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/cuttlefish_excluded_hardware.xml \
     device/google/cuttlefish/shared/permissions/privapp-permissions-cuttlefish.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/privapp-permissions-cuttlefish.xml \
     frameworks/av/media/libeffects/data/audio_effects.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_effects.xml \
     frameworks/av/media/libstagefright/data/media_codecs_google_audio.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_audio.xml \
@@ -301,8 +309,8 @@ endif
 
 ifndef LOCAL_AUDIO_PRODUCT_COPY_FILES
 LOCAL_AUDIO_PRODUCT_COPY_FILES := \
-    device/generic/goldfish/audio/policy/audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_configuration.xml \
-    device/generic/goldfish/audio/policy/primary_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/primary_audio_policy_configuration.xml \
+    device/google/cuttlefish/shared/config/audio/policy/audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_configuration.xml \
+    device/google/cuttlefish/shared/config/audio/policy/primary_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/primary_audio_policy_configuration.xml \
     frameworks/av/services/audiopolicy/config/r_submix_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/r_submix_audio_policy_configuration.xml \
     frameworks/av/services/audiopolicy/config/audio_policy_volumes.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_volumes.xml \
     frameworks/av/services/audiopolicy/config/default_volume_tables.xml:$(TARGET_COPY_OUT_VENDOR)/etc/default_volume_tables.xml
@@ -404,12 +412,25 @@ PRODUCT_PACKAGES += \
 
 endif
 
+#
+# Trusty VM for Keymint and Gatekeeper HAL
+#
+ifeq ($(RELEASE_AVF_ENABLE_EARLY_VM),true)
+  TRUSTY_KEYMINT_IMPL ?= rust
+  TRUSTY_SYSTEM_VM ?= nonsecure
+endif
+ifeq ($(TRUSTY_SYSTEM_VM),nonsecure)
+    $(call inherit-product, system/core/trusty/keymint/trusty-keymint.mk)
+    PRODUCT_PACKAGES += lk_trusty.elf trusty_vm_launcher cf-early_vms.xml
+endif
+
 #
 # KeyMint HAL
 #
 PRODUCT_PACKAGES += \
 	com.android.hardware.keymint.rust_cf_remote \
 	com.android.hardware.keymint.rust_nonsecure \
+	com.android.hardware.keymint.rust_cf_guest_trusty_nonsecure \
 
 # Indicate that KeyMint includes support for the ATTEST_KEY key purpose.
 PRODUCT_COPY_FILES += \
diff --git a/shared/erofs_compress_hints.txt b/shared/erofs_compress_hints.txt
new file mode 100644
index 000000000..8b2a711b8
--- /dev/null
+++ b/shared/erofs_compress_hints.txt
@@ -0,0 +1 @@
+0 .*\.apex$
\ No newline at end of file
diff --git a/shared/foldable/Android.bp b/shared/foldable/Android.bp
new file mode 100644
index 000000000..c6f4fed23
--- /dev/null
+++ b/shared/foldable/Android.bp
@@ -0,0 +1,24 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_foldable.json",
+    src: "config_foldable.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/foldable/android-info.txt b/shared/foldable/android-info.txt
index 53cfa1129..76f3f8a42 100644
--- a/shared/foldable/android-info.txt
+++ b/shared/foldable/android-info.txt
@@ -1,2 +1,3 @@
 config=foldable
 gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
diff --git a/shared/config/config_foldable.json b/shared/foldable/config_foldable.json
similarity index 100%
rename from shared/config/config_foldable.json
rename to shared/foldable/config_foldable.json
diff --git a/shared/foldable/device_state_configuration.xml b/shared/foldable/device_state_configuration.xml
index ef859a3b7..88f443fee 100644
--- a/shared/foldable/device_state_configuration.xml
+++ b/shared/foldable/device_state_configuration.xml
@@ -3,10 +3,10 @@
     <identifier>0</identifier>
     <name>CLOSED</name>
     <properties>
-      <property>PROPERTY_POLICY_CANCEL_OVERRIDE_REQUESTS</property>
-      <property>PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_CLOSED</property>
-      <property>PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY</property>
-      <property>PROPERTY_POWER_CONFIGURATION_TRIGGER_SLEEP</property>
+      <property>com.android.server.policy.PROPERTY_POLICY_CANCEL_OVERRIDE_REQUESTS</property>
+      <property>com.android.server.policy.PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_CLOSED</property>
+      <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY</property>
+      <property>com.android.server.policy.PROPERTY_POWER_CONFIGURATION_TRIGGER_SLEEP</property>
     </properties>
     <conditions>
       <lid-switch>
@@ -18,9 +18,9 @@
     <identifier>1</identifier>
     <name>HALF_OPENED</name>
     <properties>
-      <property>PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_HALF_OPEN</property>
-      <property>PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY</property>
-      <property>PROPERTY_POWER_CONFIGURATION_TRIGGER_WAKE</property>
+      <property>com.android.server.policy.PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_HALF_OPEN</property>
+      <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY</property>
+      <property>com.android.server.policy.PROPERTY_POWER_CONFIGURATION_TRIGGER_WAKE</property>
     </properties>
     <conditions>
       <lid-switch>
@@ -40,9 +40,9 @@
     <identifier>2</identifier>
     <name>OPENED</name>
     <properties>
-      <property>PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_OPEN</property>
-      <property>PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY</property>
-      <property>PROPERTY_POWER_CONFIGURATION_TRIGGER_WAKE</property>
+      <property>com.android.server.policy.PROPERTY_FOLDABLE_HARDWARE_CONFIGURATION_FOLD_IN_OPEN</property>
+      <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY</property>
+      <property>com.android.server.policy.PROPERTY_POWER_CONFIGURATION_TRIGGER_WAKE</property>
     </properties>
     <conditions>
       <lid-switch>
@@ -54,10 +54,10 @@
     <identifier>3</identifier>
     <name>REAR_DISPLAY_MODE</name>
     <properties>
-      <property>PROPERTY_EMULATED_ONLY</property>
-      <property>PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY</property>
-      <property>PROPERTY_POLICY_AVAILABLE_FOR_APP_REQUEST</property>
-      <property>PROPERTY_FEATURE_REAR_DISPLAY</property>
+      <property>com.android.server.policy.PROPERTY_EMULATED_ONLY</property>
+      <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_OUTER_PRIMARY</property>
+      <property>com.android.server.policy.PROPERTY_POLICY_AVAILABLE_FOR_APP_REQUEST</property>
+      <property>com.android.server.policy.PROPERTY_FEATURE_REAR_DISPLAY</property>
     </properties>
   </device-state>
 </device-state-config>
diff --git a/shared/go/Android.bp b/shared/go/Android.bp
new file mode 100644
index 000000000..8a69756cb
--- /dev/null
+++ b/shared/go/Android.bp
@@ -0,0 +1,24 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_go.json",
+    src: "config_go.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/go/android-info.txt b/shared/go/android-info.txt
index ae9578c4e..c80fecf34 100644
--- a/shared/go/android-info.txt
+++ b/shared/go/android-info.txt
@@ -1,2 +1,3 @@
 config=go
 gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
diff --git a/shared/config/config_go.json b/shared/go/config_go.json
similarity index 100%
rename from shared/config/config_go.json
rename to shared/go/config_go.json
diff --git a/shared/minidroid/Android.bp b/shared/minidroid/Android.bp
new file mode 100644
index 000000000..8665e3ff6
--- /dev/null
+++ b/shared/minidroid/Android.bp
@@ -0,0 +1,24 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_minidroid.json",
+    src: "config_minidroid.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/minidroid/android-info.txt b/shared/minidroid/android-info.txt
index 50453d60c..c48d4b76f 100644
--- a/shared/minidroid/android-info.txt
+++ b/shared/minidroid/android-info.txt
@@ -1,2 +1,3 @@
 config=minidroid
 gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
diff --git a/shared/config/config_minidroid.json b/shared/minidroid/config_minidroid.json
similarity index 100%
rename from shared/config/config_minidroid.json
rename to shared/minidroid/config_minidroid.json
diff --git a/shared/permissions/Android.bp b/shared/permissions/Android.bp
index 5cfafe0c3..e73383939 100644
--- a/shared/permissions/Android.bp
+++ b/shared/permissions/Android.bp
@@ -16,10 +16,3 @@
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
-
-prebuilt_etc {
-    name: "cuttlefish_excluded_hardware.prebuilt.xml",
-    src: "cuttlefish_excluded_hardware.xml",
-    relative_install_path: "permissions",
-    soc_specific: true,
-}
diff --git a/shared/phone/Android.bp b/shared/phone/Android.bp
new file mode 100644
index 000000000..d11e3f7c0
--- /dev/null
+++ b/shared/phone/Android.bp
@@ -0,0 +1,24 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_phone.json",
+    src: "config_phone.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/phone/android-info.txt b/shared/phone/android-info.txt
index 169f04d21..3c40b9774 100644
--- a/shared/phone/android-info.txt
+++ b/shared/phone/android-info.txt
@@ -1,2 +1,3 @@
 config=phone
 gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
diff --git a/shared/config/config_phone.json b/shared/phone/config_phone.json
similarity index 100%
rename from shared/config/config_phone.json
rename to shared/phone/config_phone.json
diff --git a/shared/sepolicy/system_ext/private/file_contexts b/shared/sepolicy/system_ext/private/file_contexts
index 4aa5c6f6e..26eaa40d2 100644
--- a/shared/sepolicy/system_ext/private/file_contexts
+++ b/shared/sepolicy/system_ext/private/file_contexts
@@ -1,2 +1,6 @@
 /data/vendor/radio(/.*)?               u:object_r:radio_vendor_data_file:s0
 /(system_ext|system/system_ext)/bin/hw/android\.hardware\.audio\.parameter_parser\.example_service u:object_r:audio_vendor_parameter_parser_exec:s0
+/(system_ext|system/system_ext)/bin/hw/android\.hardware\.security\.keymint-service\.rust\.trusty\.system\.nonsecure  u:object_r:hal_keymint_system_exec:s0
+is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `
+    /(system_ext|system/system_ext)/bin/trusty_vm_launcher u:object_r:trusty_vm_launcher_exec:s0
+')
diff --git a/shared/sepolicy/system_ext/private/hal_keymint_system.te b/shared/sepolicy/system_ext/private/hal_keymint_system.te
new file mode 100644
index 000000000..42bf85f4c
--- /dev/null
+++ b/shared/sepolicy/system_ext/private/hal_keymint_system.te
@@ -0,0 +1,5 @@
+# Read device's serial number from system properties
+get_prop(hal_keymint_system, serialno_prop)
+
+# Read the OS patch level from system properties
+get_prop(hal_keymint_system, vendor_security_patch_level_prop)
diff --git a/shared/sepolicy/system_ext/private/platform_app.te b/shared/sepolicy/system_ext/private/platform_app.te
index fc1b99f4d..8eb3c3af7 100644
--- a/shared/sepolicy/system_ext/private/platform_app.te
+++ b/shared/sepolicy/system_ext/private/platform_app.te
@@ -5,3 +5,4 @@ set_prop(platform_app, bootanim_system_prop);
 
 # allow platform_app/systemui access to fingerprint
 hal_client_domain(platform_app, hal_fingerprint)
+hal_client_domain(platform_app, hal_face)
diff --git a/shared/sepolicy/system_ext/private/trusty_vm_launcher.te b/shared/sepolicy/system_ext/private/trusty_vm_launcher.te
new file mode 100644
index 000000000..a5d16b749
--- /dev/null
+++ b/shared/sepolicy/system_ext/private/trusty_vm_launcher.te
@@ -0,0 +1,18 @@
+is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `
+    type trusty_vm_launcher, domain, coredomain;
+    type trusty_vm_launcher_exec, system_file_type, exec_type, file_type;
+    type trusty_vm_launcher_tmpfs, file_type;
+
+    init_daemon_domain(trusty_vm_launcher)
+    domain_auto_trans(init, trusty_vm_launcher_exec, trusty_vm_launcher)
+
+    early_virtmgr_use(trusty_vm_launcher)
+    binder_use(trusty_vm_launcher)
+
+    allow trusty_vm_launcher kmsg_debug_device:chr_file rw_file_perms;
+    use_bootstrap_libs(trusty_vm_launcher)
+
+    allow trusty_vm_launcher self:global_capability_class_set { net_bind_service ipc_lock sys_resource };
+
+    tmpfs_domain(trusty_vm_launcher)
+')
diff --git a/shared/slim/Android.bp b/shared/slim/Android.bp
index 52715758c..ff0c17a9f 100644
--- a/shared/slim/Android.bp
+++ b/shared/slim/Android.bp
@@ -23,3 +23,9 @@ prebuilt_etc {
     relative_install_path: "permissions",
     soc_specific: true,
 }
+
+prebuilt_etc_host {
+    name: "cvd_config_slim.json",
+    src: "config_slim.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/slim/android-info.txt b/shared/slim/android-info.txt
index e7e5bf0ce..2b0586a4b 100644
--- a/shared/slim/android-info.txt
+++ b/shared/slim/android-info.txt
@@ -1,2 +1,3 @@
 config=slim
 gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
diff --git a/shared/config/config_slim.json b/shared/slim/config_slim.json
similarity index 100%
rename from shared/config/config_slim.json
rename to shared/slim/config_slim.json
diff --git a/shared/tablet/Android.bp b/shared/tablet/Android.bp
index 83ae87d58..b9af16525 100644
--- a/shared/tablet/Android.bp
+++ b/shared/tablet/Android.bp
@@ -22,4 +22,10 @@ prebuilt_etc {
     src: "tablet_excluded_hardware.xml",
     relative_install_path: "permissions",
     soc_specific: true,
-}
\ No newline at end of file
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_tablet.json",
+    src: "config_tablet.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/config/config_tablet.json b/shared/tablet/config_tablet.json
similarity index 100%
rename from shared/config/config_tablet.json
rename to shared/tablet/config_tablet.json
diff --git a/shared/tv/Android.bp b/shared/tv/Android.bp
index b9153cc82..225dd39bb 100644
--- a/shared/tv/Android.bp
+++ b/shared/tv/Android.bp
@@ -23,3 +23,9 @@ prebuilt_etc {
     relative_install_path: "permissions",
     soc_specific: true,
 }
+
+prebuilt_etc_host {
+    name: "cvd_config_tv.json",
+    src: "config_tv.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/tv/android-info.txt b/shared/tv/android-info.txt
index c4386094f..4714af6e1 100644
--- a/shared/tv/android-info.txt
+++ b/shared/tv/android-info.txt
@@ -1,2 +1,3 @@
 config=tv
 gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
diff --git a/shared/config/config_tv.json b/shared/tv/config_tv.json
similarity index 100%
rename from shared/config/config_tv.json
rename to shared/tv/config_tv.json
diff --git a/shared/wear/Android.bp b/shared/wear/Android.bp
new file mode 100644
index 000000000..383fa1acd
--- /dev/null
+++ b/shared/wear/Android.bp
@@ -0,0 +1,24 @@
+//
+// Copyright (C) 2024 The Android Open Source Project
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_wear.json",
+    src: "config_wear.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/wear/OWNERS b/shared/wear/OWNERS
new file mode 100644
index 000000000..4c2704249
--- /dev/null
+++ b/shared/wear/OWNERS
@@ -0,0 +1 @@
+# Nobody
diff --git a/shared/wear/android-info.txt b/shared/wear/android-info.txt
index 02e029bdc..db1b7bf46 100644
--- a/shared/wear/android-info.txt
+++ b/shared/wear/android-info.txt
@@ -1,2 +1,3 @@
 config=wear
 gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
diff --git a/shared/wear/aosp_vendor.mk b/shared/wear/aosp_vendor.mk
index 9ce5d967b..4609ec742 100644
--- a/shared/wear/aosp_vendor.mk
+++ b/shared/wear/aosp_vendor.mk
@@ -34,8 +34,9 @@ PRODUCT_PACKAGES += \
 
 PRODUCT_MINIMIZE_JAVA_DEBUG_INFO := true
 
+TARGET_SYSTEM_PROP += device/google/cuttlefish/shared/wear/wearable-1024.prop
+
+# Use the low memory allocator outside of eng builds to save RSS.
 ifneq (,$(filter eng, $(TARGET_BUILD_VARIANT)))
-    PRODUCT_DISABLE_SCUDO := true
+    MALLOC_LOW_MEMORY := true
 endif
-
-TARGET_SYSTEM_PROP += device/google/cuttlefish/shared/wear/wearable-1024.prop
diff --git a/shared/config/config_wear.json b/shared/wear/config_wear.json
similarity index 100%
rename from shared/config/config_wear.json
rename to shared/wear/config_wear.json
diff --git a/system_image/Android.bp b/system_image/Android.bp
index 7d25613ad..0220f22b5 100644
--- a/system_image/Android.bp
+++ b/system_image/Android.bp
@@ -56,6 +56,26 @@ android_symlinks = [
         target: "/system_dlkm/lib/modules",
         name: "system/lib/modules",
     },
+    {
+        target: "/data/user_de/0/com.android.shell/files/bugreports",
+        name: "bugreports",
+    },
+    {
+        target: "/data/cache",
+        name: "cache",
+    },
+    {
+        target: "/sys/kernel/debug",
+        name: "d",
+    },
+    {
+        target: "/storage/self/primary",
+        name: "sdcard",
+    },
+    {
+        target: "/product/etc/security/adb_keys",
+        name: "adb_keys",
+    },
 ]
 
 phony {
@@ -69,7 +89,6 @@ phony {
         "DroidSansMono.ttf",
         "NotoColorEmoji.ttf",
         "NotoColorEmojiFlags.ttf",
-        "NotoColorEmojiLegacy.ttf",
         "NotoNaskhArabic-Bold.ttf",
         "NotoNaskhArabic-Regular.ttf",
         "NotoNaskhArabicUI-Bold.ttf",
@@ -242,6 +261,7 @@ phony {
         "NotoSerifGurmukhi-VF.ttf",
         "NotoSerifHebrew-Bold.ttf",
         "NotoSerifHebrew-Regular.ttf",
+        "NotoSerifHentaigana.ttf",
         "NotoSerifKannada-VF.ttf",
         "NotoSerifKhmer-Bold.otf",
         "NotoSerifKhmer-Regular.otf",
@@ -284,9 +304,9 @@ android_system_image {
     fsverity: {
         inputs: [
             "etc/boot-image.prof",
+            "etc/classpaths/*.pb",
             "etc/dirty-image-objects",
             "etc/preloaded-classes",
-            "etc/classpaths/*.pb",
             "framework/*",
             "framework/*/*", // framework/{arch}
             "framework/oat/*/*", // framework/oat/{arch}
@@ -304,26 +324,18 @@ android_system_image {
     avb_hash_algorithm: "sha256",
 
     deps: [
-        "android.hardware.biometrics.fingerprint@2.1", // generic_system
-        "android.hardware.radio@1.0", // generic_system
-        "android.hardware.radio@1.1", // generic_system
-        "android.hardware.radio@1.2", // generic_system
-        "android.hardware.radio@1.3", // generic_system
-        "android.hardware.radio@1.4", // generic_system
-        "android.hardware.radio.config@1.0", // generic_system
-        "android.hardware.radio.deprecated@1.0", // generic_system
-        "android.hardware.secure_element@1.0", // generic_system
         "abx",
         "aconfigd",
         "aflags",
         "am",
-        "android_build_prop",
-        "android_vintf_manifest",
         "android.software.credentials.prebuilt.xml", // generic_system
+        "android.software.webview.prebuilt.xml", // media_system
+        "android.software.window_magnification.prebuilt.xml", // handheld_system
         "android.system.suspend-service",
+        "android_vintf_manifest",
         "apexd",
-        "app_process",
         "appops",
+        "approved-ogki-builds.xml", // base_system
         "appwidget",
         "atrace",
         "audioserver",
@@ -333,7 +345,6 @@ android_system_image {
         "bmgr",
         "bootanimation",
         "bootstat",
-        "boringssl_self_test",
         "bpfloader",
         "bu",
         "bugreport",
@@ -355,23 +366,23 @@ android_system_image {
         "dumpstate",
         "dumpsys",
         "e2fsck",
+        "enhanced-confirmation.xml", // base_system
         "etc_hosts",
         "flags_health_check",
         "framework-audio_effects.xml", // for handheld // handheld_system
         "framework-sysconfig.xml",
-        "fsck_msdos",
+        "fs_config_dirs_system",
+        "fs_config_files_system",
         "fsck.erofs",
         "fsck.f2fs", // for media_system
+        "fsck_msdos",
         "fsverity-release-cert-der",
-        "fs_config_files_system",
-        "fs_config_dirs_system",
         "gatekeeperd",
         "gpu_counter_producer",
         "gpuservice",
         "group_system",
         "gsi_tool",
         "gsid",
-        "heapprofd_client",
         "heapprofd",
         "hid",
         "hiddenapi-package-whitelist.xml", // from runtime_libart
@@ -379,37 +390,35 @@ android_system_image {
         "idmap2",
         "idmap2d",
         "ime",
-        "incident_helper",
-        "incident-helper-cmd",
         "incident",
+        "incident-helper-cmd",
+        "incident_helper",
         "incidentd",
-        "init_first_stage", // for boot partition
-        // "init.environ.rc", // TODO: move to soong
+        "init.environ.rc-soong",
         "init.usb.configfs.rc",
         "init.usb.rc",
         "init.zygote32.rc",
-        "init.zygote64_32.rc",
         "init.zygote64.rc",
+        "init.zygote64_32.rc",
+        "init_first_stage", // for boot partition
         "initial-package-stopped-states.xml",
         "input",
         "installd",
         "ip", // base_system
         "iptables",
         "kcmdlinectrl",
+        "kernel-lifetimes.xml", // base_system
         "keychars_data",
         "keylayout_data",
         "keystore2",
         "ld.mc",
-        "libaaudio",
-        "libalarm_jni",
-        "libamidi",
-        "linker", // ok
         "llkd", // base_system
         "lmkd", // base_system
         "local_time.default", // handheld_vendo
         "locksettings", // base_system
         "logcat", // base_system
         "logd", // base_system
+        "logpersist.start",
         "lpdump", // base_system
         "lshal", // base_system
         "make_f2fs", // media_system
@@ -426,8 +435,10 @@ android_system_image {
         "ndc", // base_system
         "netd", // base_system
         "netutils-wrapper-1.0", // full_base
+        "notice_xml_system",
         "odsign", // base_system
         "otapreopt_script", // generic_system
+        "package-shareduid-allowlist.xml", // base_system
         "passwd_system", // base_system
         "perfetto", // base_system
         "ping", // base_system
@@ -464,8 +475,8 @@ android_system_image {
         "sgdisk", // base_system
         "sm", // base_system
         "snapshotctl", // base_system
-        "snapuserd_ramdisk", // ramdisk
         "snapuserd", // base_system
+        "snapuserd_ramdisk", // ramdisk
         "storaged", // base_system
         "surfaceflinger", // base_system
         "svc", // base_system
@@ -473,14 +484,14 @@ android_system_image {
         "tc", // base_system
         "telecom", // base_system
         "tombstoned", // base_system
-        "traced_probes", // base_system
         "traced", // base_system
+        "traced_probes", // base_system
         "tune2fs", // base_system
         "uiautomator", // base_system
         "uinput", // base_system
         "uncrypt", // base_system
-        "update_engine_sideload", // recovery
         "update_engine", // generic_system
+        "update_engine_sideload", // recovery
         "update_verifier", // generic_system
         "usbd", // base_system
         "vdc", // base_system
@@ -491,7 +502,17 @@ android_system_image {
         "wifi.rc", // base_system
         "wificond", // base_system
         "wm", // base_system
-    ] + select(product_variable("debuggable"), {
+    ] + select(release_flag("RELEASE_PLATFORM_VERSION_CODENAME"), {
+        "REL": [],
+        default: [
+            "android.software.preview_sdk.prebuilt.xml", // media_system
+        ],
+    }) + select(soong_config_variable("ANDROID", "release_package_profiling_module"), {
+        "true": [
+            "trace_redactor", // base_system (RELEASE_PACKAGE_PROFILING_MODULE)
+        ],
+        default: [],
+    }) + select(product_variable("debuggable"), {
         true: [
             "adevice_fingerprint",
             "arping",
@@ -505,7 +526,6 @@ android_system_image {
             "iperf3",
             "iw",
             "layertracegenerator",
-            "logpersist.start",
             "logtagd.rc",
             "ot-cli-ftd",
             "ot-ctl",
@@ -534,25 +554,16 @@ android_system_image {
             "unwind_symbols",
             "update_engine_client",
         ],
-
         default: [],
     }),
     multilib: {
         common: {
             deps: [
-                "adbd_system_api", // base_system
-                "android.hidl.base-V1.0-java", // base_system
-                "android.hidl.manager-V1.0-java", // base_system
-                "android.test.base", // from runtime_libart
-                "android.test.mock", // base_system
-                "android.test.runner", // base_system
-                "aosp_mainline_modules", // ok
                 "BackupRestoreConfirmation", // base_system
                 "BasicDreams", // handheld_system
                 "BlockedNumberProvider", // handheld_system
                 "BluetoothMidiService", // handheld_system
                 "BookmarkProvider", // handheld_system
-                "build_flag_system", // base_system
                 "BuiltInPrintService", // handheld_system
                 "CalendarProvider", // handheld_system
                 "CallLogBackup", // telephony_system
@@ -561,46 +572,24 @@ android_system_image {
                 "CarrierDefaultApp", // telephony_system
                 "CellBroadcastLegacyApp", // telephony_system
                 "CertInstaller", // handheld_system
-                "charger_res_images", // generic_system
-                "com.android.apex.cts.shim.v1_prebuilt", // ok
-                "com.android.cellbroadcast", // telephony_system
-                "com.android.future.usb.accessory", // media_system
-                "com.android.location.provider", // base_system
-                "com.android.media.remotedisplay.xml", // media_system
-                "com.android.media.remotedisplay", // media_system
-                "com.android.mediadrm.signer", // media_system
-                "com.android.nfc_extras", // ok
-                "com.android.runtime", // ok
                 "CompanionDeviceManager", // media_system
                 "ContactsProvider", // base_system
                 "CredentialManager", // handheld_system
                 "DeviceAsWebcam", // handheld_system
-                "dex_bootjars",
                 "DocumentsUI", // handheld_system
                 "DownloadProvider", // base_system
                 "DownloadProviderUi", // handheld_system
                 "DynamicSystemInstallationService", // base_system
+                "E2eeContactKeysProvider", // base_system
                 "EasterEgg", // handheld_system
-                "ext", // from runtime_libart
-                "ExternalStorageProvider", // handheld_system
                 "ExtShared", // base_system
-                "fonts", // ok
-                "framework-graphics", // base_system
-                "framework-location", // base_system
-                "framework-minus-apex-install-dependencies", // base_system
-                "framework-nfc", // base_system
+                "ExternalStorageProvider", // handheld_system
                 "FusedLocation", // handheld_system
                 "HTMLViewer", // media_system
-                "hwservicemanager_compat_symlink_module", // base_system
-                "hyph-data",
-                "ims-common", // base_system
-                "init_system", // base_system
                 "InputDevices", // handheld_system
                 "IntentResolver", // base_system
-                "javax.obex", // base_system
                 "KeyChain", // handheld_system
                 "LiveWallpapersPicker", // generic_system, full_base
-                "llndk.libraries.txt", //ok
                 "LocalTransport", // base_system
                 "ManagedProvisioning", // handheld_system
                 "MediaProviderLegacy", // base_system
@@ -608,40 +597,88 @@ android_system_image {
                 "MtpService", // handheld_system
                 "MusicFX", // handheld_system
                 "NetworkStack", // base_system
-                "NfcNci", // base_system
                 "ONS", // telephony_system
-                "org.apache.http.legacy", // base_system
-                "perfetto-extras", // system
-                "PackageInstaller", // base_system
                 "PacProcessor", // handheld_system
+                "PackageInstaller", // base_system
                 "PartnerBookmarksProvider", // generic_system
                 "PhotoTable", // full_base
                 "PrintRecommendationService", // handheld_system
                 "PrintSpooler", // handheld_system
                 "ProxyHandler", // handheld_system
-                "sanitizer.libraries.txt", // base_system
                 "SecureElement", // handheld_system
-                "selinux_policy_system_soong", // ok
-                "services", // base_system
                 "SettingsProvider", // base_system
                 "SharedStorageBackup", // handheld_system
-                "shell_and_utilities_system", // ok
                 "Shell", // base_system
                 "SimAppDialog", // handheld_system
                 "SoundPicker", // not installed by anyone
                 "StatementService", // media_system
                 "Stk", // generic_system
                 "Tag", // generic_system
+                "TeleService", // handheld_system
                 "Telecom", // handheld_system
-                "telephony-common", // libs from TeleService
                 "TelephonyProvider", // handheld_system
-                "TeleService", // handheld_system
                 "Traceur", // handheld_system
                 "UserDictionaryProvider", // handheld_system
-                "voip-common", // base_system
                 "VpnDialogs", // handheld_system
                 "WallpaperBackup", // base_system
-            ],
+                "adbd_system_api", // base_system
+                "android.hidl.base-V1.0-java", // base_system
+                "android.hidl.manager-V1.0-java", // base_system
+                "android.test.base", // from runtime_libart
+                "android.test.mock", // base_system
+                "android.test.runner", // base_system
+                "aosp_mainline_modules", // ok
+                "build_flag_system", // base_system
+                "charger_res_images", // generic_system
+                "com.android.apex.cts.shim.v1_prebuilt", // ok
+                "com.android.cellbroadcast", // telephony_system
+                "com.android.future.usb.accessory", // media_system
+                "com.android.location.provider", // base_system
+                "com.android.media.remotedisplay", // media_system
+                "com.android.media.remotedisplay.xml", // media_system
+                "com.android.mediadrm.signer", // media_system
+                "com.android.nfc_extras", // ok
+                "com.android.nfcservices", // base_system (RELEASE_PACKAGE_NFC_STACK != NfcNci)
+                "com.android.runtime", // ok
+                "dex_bootjars",
+                "ext", // from runtime_libart
+                "fonts", // ok
+                "framework-graphics", // base_system
+                "framework-location", // base_system
+                "framework-minus-apex-install-dependencies", // base_system
+                "framework_compatibility_matrix.device.xml",
+                "hwservicemanager_compat_symlink_module", // base_system
+                "hyph-data",
+                "ims-common", // base_system
+                "init_system", // base_system
+                "javax.obex", // base_system
+                "llndk.libraries.txt", //ok
+                "org.apache.http.legacy", // base_system
+                "perfetto-extras", // system
+                "sanitizer.libraries.txt", // base_system
+                "selinux_policy_system_soong", // ok
+                "services", // base_system
+                "shell_and_utilities_system", // ok
+                "system-build.prop",
+                "system_compatibility_matrix.xml", //base_system
+                "telephony-common", // libs from TeleService
+                "voip-common", // base_system
+            ] + select(soong_config_variable("ANDROID", "release_crashrecovery_module"), {
+                "true": [
+                    "com.android.crashrecovery", // base_system (RELEASE_CRASHRECOVERY_MODULE)
+                ],
+                default: [],
+            }) + select(soong_config_variable("ANDROID", "release_package_profiling_module"), {
+                "true": [
+                    "com.android.profiling", // base_system (RELEASE_PACKAGE_PROFILING_MODULE)
+                ],
+                default: [],
+            }) + select(release_flag("RELEASE_AVATAR_PICKER_APP"), {
+                true: [
+                    "AvatarPicker", // generic_system (RELEASE_AVATAR_PICKER_APP)
+                ],
+                default: [],
+            }),
         },
         prefer32: {
             deps: [
@@ -651,50 +688,68 @@ android_system_image {
         },
         lib64: {
             deps: [
-                "boringssl_self_test",
+                "android.system.virtualizationcommon-ndk",
+                "android.system.virtualizationservice-ndk",
                 "libgsi",
                 "servicemanager",
             ],
         },
         both: {
             deps: [
+                "android.hardware.biometrics.fingerprint@2.1", // generic_system
+                "android.hardware.radio.config@1.0", // generic_system
+                "android.hardware.radio.deprecated@1.0", // generic_system
+                "android.hardware.radio@1.0", // generic_system
+                "android.hardware.radio@1.1", // generic_system
+                "android.hardware.radio@1.2", // generic_system
+                "android.hardware.radio@1.3", // generic_system
+                "android.hardware.radio@1.4", // generic_system
+                "android.hardware.secure_element@1.0", // generic_system
+                "app_process", // base_system
+                "boringssl_self_test", // base_system
+                "heapprofd_client", // base_system
+                "libEGL", // base_system
+                "libEGL_angle", // base_system
+                "libETC1", // base_system
+                "libFFTEm", // base_system
+                "libGLESv1_CM", // base_system
+                "libGLESv1_CM_angle", // base_system
+                "libGLESv2", // base_system
+                "libGLESv2_angle", // base_system
+                "libGLESv3", // base_system
+                "libOpenMAXAL", // base_system
+                "libOpenSLES", // base_system
+                "libaaudio", // base_system
+                "libalarm_jni", // base_system
+                "libamidi", // base_system
+                "libandroid",
                 "libandroid_runtime",
                 "libandroid_servers",
-                "libandroid",
                 "libandroidfw",
                 "libartpalette-system",
                 "libaudio-resampler", // generic-system
                 "libaudioeffect_jni",
                 "libaudiohal", // generic-system
                 "libaudiopolicyengineconfigurable", // generic-system
+                "libbinder",
                 "libbinder_ndk",
                 "libbinder_rpc_unstable",
-                "libbinder",
                 "libcamera2ndk",
                 "libclang_rt.asan",
                 "libcompiler_rt",
                 "libcutils", // used by many libs
                 "libdmabufheap", // used by many libs
                 "libdrm", // used by many libs // generic_system
-                "libdrmframework_jni", // base_system
                 "libdrmframework", // base_system
-                "libEGL_angle", // base_system
-                "libEGL", // base_system
-                "libETC1", // base_system
+                "libdrmframework_jni", // base_system
                 "libfdtrack", // base_system
-                "libFFTEm", // base_system
                 "libfilterfw", // base_system
                 "libfilterpack_imageproc", // media_system
                 "libfwdlockengine", // generic_system
                 "libgatekeeper", // base_system
-                "libGLESv1_CM_angle", // base_system
-                "libGLESv1_CM", // base_system
-                "libGLESv2_angle", // base_system
-                "libGLESv2", // base_system
-                "libGLESv3", // base_system
                 "libgui", // base_system
-                "libhardware_legacy", // base_system
                 "libhardware", // base_system
+                "libhardware_legacy", // base_system
                 "libhidltransport", // generic_system
                 "libhwbinder", // generic_system
                 "libinput", // base_system
@@ -705,18 +760,17 @@ android_system_image {
                 "liblog", // base_system
                 "liblogwrap", // generic_system
                 "liblz4", // generic_system
-                "libmedia_jni", // base_system
                 "libmedia", // base_system
+                "libmedia_jni", // base_system
                 "libmediandk", // base_system
                 "libminui", // generic_system
+                "libmonkey_jni", // base_system
                 "libmtp", // base_system
                 "libnetd_client", // base_system
                 "libnetlink", // base_system
                 "libnetutils", // base_system
                 "libneuralnetworks_packageinfo", // base_system
                 "libnl", // generic_system
-                "libOpenMAXAL", // base_system
-                "libOpenSLES", // base_system
                 "libpdfium", // base_system
                 "libpolicy-subsystem", // generic_system
                 "libpower", // base_system
@@ -733,9 +787,9 @@ android_system_image {
                 "libsoundpool", // base_system
                 "libspeexresampler", // base_system
                 "libsqlite", // base_system
+                "libstagefright", // base_system
                 "libstagefright_foundation", // base_system
                 "libstagefright_omx", // base_system
-                "libstagefright", // base_system
                 "libstdc++", // base_system
                 "libsysutils", // base_system
                 "libui", // base_system
@@ -746,6 +800,7 @@ android_system_image {
                 "libwebviewchromium_loader", // media_system
                 "libwebviewchromium_plat_support", // media_system
                 "libwilhelm", // base_system
+                "linker", // base_system
             ] + select(soong_config_variable("ANDROID", "TARGET_DYNAMIC_64_32_DRMSERVER"), {
                 "true": ["drmserver"],
                 default: [],
@@ -762,12 +817,5 @@ prebuilt_etc {
     src: "manifest.xml",
     filename: "manifest.xml",
     relative_install_path: "vintf",
-    installable: false,
-}
-
-prebuilt_root {
-    name: "android_build_prop",
-    filename: "build.prop",
-    src: "build.prop",
-    installable: false,
+    no_full_install: true,
 }
diff --git a/system_image/OWNERS b/system_image/OWNERS
new file mode 100644
index 000000000..6d1446f09
--- /dev/null
+++ b/system_image/OWNERS
@@ -0,0 +1,6 @@
+# Bug component: 1322713
+inseob@google.com
+jeongik@google.com
+jiyong@google.com
+justinyun@google.com
+kiyoungkim@google.com
diff --git a/system_image/build.prop b/system_image/build.prop
deleted file mode 100644
index e65b5284f..000000000
--- a/system_image/build.prop
+++ /dev/null
@@ -1,118 +0,0 @@
-####################################
-# from generate-common-build-props
-# These properties identify this partition image.
-####################################
-ro.product.system.brand=Android
-ro.product.system.device=generic
-ro.product.system.manufacturer=Android
-ro.product.system.model=mainline
-ro.product.system.name=mainline
-ro.system.product.cpu.abilist=x86_64,arm64-v8a
-ro.system.product.cpu.abilist32=
-ro.system.product.cpu.abilist64=x86_64,arm64-v8a
-ro.system.build.date=Tue Jan 23 13:45:29 KST 2024
-ro.system.build.date.utc=1705985129
-ro.system.build.id=MAIN
-ro.system.build.tags=test-keys
-ro.system.build.type=userdebug
-ro.system.build.version.release=14
-ro.system.build.version.release_or_codename=VanillaIceCream
-ro.system.build.version.sdk=34
-####################################
-# from out/target/product/vsoc_x86_64_only/obj/PACKAGING/system_build_prop_intermediates/buildinfo.prop
-####################################
-# begin build properties
-# autogenerated by buildinfo.sh
-ro.build.legacy.id=MAIN
-ro.build.version.sdk=34
-ro.build.version.preview_sdk=1
-ro.build.version.preview_sdk_fingerprint=67142e4165a8947eaad71ba44204ce05
-ro.build.version.codename=VanillaIceCream
-ro.build.version.all_codenames=UpsideDownCake,VanillaIceCream
-ro.build.version.known_codenames=Base,Base11,Cupcake,Donut,Eclair,Eclair01,EclairMr1,Froyo,Gingerbread,GingerbreadMr1,Honeycomb,HoneycombMr1,HoneycombMr2,IceCreamSandwich,IceCreamSandwichMr1,JellyBean,JellyBeanMr1,JellyBeanMr2,Kitkat,KitkatWatch,Lollipop,LollipopMr1,M,N,NMr1,O,OMr1,P,Q,R,S,Sv2,Tiramisu,UpsideDownCake,VanillaIceCream
-ro.build.version.release=14
-ro.build.version.release_or_codename=VanillaIceCream
-ro.build.version.release_or_preview_display=VanillaIceCream
-ro.build.version.security_patch=2023-12-05
-ro.build.version.base_os=
-ro.build.version.min_supported_target_sdk=28
-ro.build.date=Tue Jan 23 13:45:29 KST 2024
-ro.build.date.utc=1705985129
-ro.build.type=userdebug
-ro.build.tags=test-keys
-ro.build.flavor=aosp_cf_x86_64_only_phone-userdebug
-# ro.product.cpu.abi and ro.product.cpu.abi2 are obsolete,
-# use ro.product.cpu.abilist instead.
-ro.product.cpu.abi=x86_64
-ro.product.locale=en-US
-ro.wifi.channels=
-# ro.build.product is obsolete; use ro.product.device
-ro.build.product=vsoc_x86_64_only
-# Do not try to parse description or thumbprint
-# end build properties
-####################################
-# from variable ADDITIONAL_SYSTEM_PROPERTIES
-####################################
-ro.treble.enabled=true
-ro.llndk.api_level=202404
-ro.actionable_compatible_property.enabled=true
-persist.debug.dalvik.vm.core_platform_api_policy=just-warn
-ro.postinstall.fstab.prefix=/system
-ro.vndk.deprecate=true
-ro.secure=1
-security.perf_harden=1
-ro.allow.mock.location=0
-ro.debuggable=1
-dalvik.vm.lockprof.threshold=500
-net.bt.name=Android
-ro.force.debuggable=0
-####################################
-# from variable PRODUCT_SYSTEM_PROPERTIES
-####################################
-debug.atrace.tags.enableflags=0
-persist.traced.enable=1
-dalvik.vm.image-dex2oat-Xms=64m
-dalvik.vm.image-dex2oat-Xmx=64m
-dalvik.vm.dex2oat-Xms=64m
-dalvik.vm.dex2oat-Xmx=512m
-dalvik.vm.usejit=true
-dalvik.vm.dexopt.secondary=true
-dalvik.vm.dexopt.thermal-cutoff=2
-dalvik.vm.appimageformat=lz4
-ro.dalvik.vm.native.bridge=0
-pm.dexopt.post-boot=verify
-pm.dexopt.first-boot=verify
-pm.dexopt.boot-after-ota=verify
-pm.dexopt.boot-after-mainline-update=verify
-pm.dexopt.install=speed-profile
-pm.dexopt.install-fast=skip
-pm.dexopt.install-bulk=speed-profile
-pm.dexopt.install-bulk-secondary=verify
-pm.dexopt.install-bulk-downgraded=verify
-pm.dexopt.install-bulk-secondary-downgraded=verify
-pm.dexopt.bg-dexopt=speed-profile
-pm.dexopt.ab-ota=speed-profile
-pm.dexopt.inactive=verify
-pm.dexopt.cmdline=verify
-pm.dexopt.shared=speed
-dalvik.vm.dex2oat-resolve-startup-strings=true
-dalvik.vm.dex2oat-max-image-block-size=524288
-dalvik.vm.minidebuginfo=true
-dalvik.vm.dex2oat-minidebuginfo=true
-dalvik.vm.madvise.vdexfile.size=104857600
-dalvik.vm.madvise.odexfile.size=104857600
-dalvik.vm.madvise.artfile.size=4294967295
-dalvik.vm.usap_pool_enabled=false
-dalvik.vm.usap_refill_threshold=1
-dalvik.vm.usap_pool_size_max=3
-dalvik.vm.usap_pool_size_min=1
-dalvik.vm.usap_pool_refill_delay_ms=3000
-dalvik.vm.useartservice=true
-ro.apex.updatable=true
-ro.launcher.depth.widget=0
-####################################
-# from variable PRODUCT_SYSTEM_DEFAULT_PROPERTIES
-####################################
-# Auto-added by post_process_props.py
-persist.sys.usb.config=adb
-# end of file
diff --git a/system_image/manifest.xml b/system_image/manifest.xml
index 68062c014..1df2c0d0c 100644
--- a/system_image/manifest.xml
+++ b/system_image/manifest.xml
@@ -48,7 +48,7 @@
         <version>32</version>
         <version>33</version>
         <version>34</version>
-        <version>UpsideDownCake</version>
+        <version>35</version>
         <version>VanillaIceCream</version>
     </system-sdk>
 </manifest>
diff --git a/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishDisplayHotplugTest.java b/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishDisplayHotplugTest.java
index dc17a468f..7f1fa3f3b 100644
--- a/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishDisplayHotplugTest.java
+++ b/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishDisplayHotplugTest.java
@@ -302,11 +302,9 @@ public class CuttlefishDisplayHotplugTest extends CuttlefishHostTest {
         }
 
         List<String> addDisplaysCommand = Lists.newArrayList("display", "add");
-        for (int i = 0; i < params.size(); i++) {
-            AddDisplayParams display = params.get(i);
-
+        for (AddDisplayParams display : params) {
             addDisplaysCommand.add(String.format(
-                "--display%d=width=%d,height=%d", i, display.width(), display.height()));
+                "--display=width=%d,height=%d", display.width(), display.height()));
         }
 
         CommandResult addDisplayResult = runCvdCommand(addDisplaysCommand);
diff --git a/tests/hal/hal_implementation_test.cpp b/tests/hal/hal_implementation_test.cpp
index 5ed62d768..1b6667087 100644
--- a/tests/hal/hal_implementation_test.cpp
+++ b/tests/hal/hal_implementation_test.cpp
@@ -221,6 +221,7 @@ static const std::set<std::string> kAlwaysMissingAidl = {
     "android.hardware.camera.metadata",
     "android.hardware.common",
     "android.hardware.common.fmq",
+    "android.hardware.drm.common",
     "android.hardware.graphics.common",
     "android.hardware.input.common",
     "android.media.audio.common.types",
@@ -262,8 +263,8 @@ static const std::vector<VersionedAidlPackage> kKnownMissingAidl = {
     {"android.hardware.identity.", 5, 266869317},
 
     {"android.se.omapi.", 1, 266870904},
-    {"android.hardware.soundtrigger3.", 2, 266941225},
-    {"android.media.soundtrigger.", 2, 266941225},
+    {"android.hardware.soundtrigger3.", 3, 266941225},
+    {"android.media.soundtrigger.", 3, 266941225},
     {"android.hardware.weaver.", 2, 262418065},
 
     {"android.automotive.computepipe.registry.", 2, 273549907},
diff --git a/tools/create_base_image.go b/tools/create_base_image.go
index 62ee40b95..a5ba91a1c 100644
--- a/tools/create_base_image.go
+++ b/tools/create_base_image.go
@@ -122,7 +122,7 @@ func init() {
 		"Name of the instance to launch with the new image")
 	flag.StringVar(&arch, "arch", "gce_x86_64",
 		"Which CPU arch, arm/x86_64/gce_x86_64")
-	flag.StringVar(&source_image_family, "source_image_family", "debian-11",
+	flag.StringVar(&source_image_family, "source_image_family", "debian-12",
 		"Image familty to use as the base")
 	flag.StringVar(&source_image_project, "source_image_project", "debian-cloud",
 		"Project holding the base image")
@@ -130,7 +130,7 @@ func init() {
 		"https://github.com/google/android-cuttlefish.git",
 		"URL to the repository with host changes")
 	flag.StringVar(&repository_branch, "repository_branch",
-		"main", "Branch to check out")
+		"v0.9.30", "Branch to check out")
 	flag.StringVar(&version, "version", "", "cuttlefish-common version")
 	flag.StringVar(&internal_ip_flag, "INTERNAL_IP", "",
 		"INTERNAL_IP can be set to --internal-ip run on a GCE instance."+
@@ -366,7 +366,7 @@ func main() {
 	// TODO rammuthiah if the instance is clobbered with ssh commands within
 	// 5 seconds of reboot, it becomes inaccessible. Workaround that by sleeping
 	// 50 seconds.
-	time.Sleep(50 * time.Second)
+	time.Sleep(70 * time.Second)
 	gce(ExitOnFail, `compute ssh `+internal_ip_flag+` `+PZ+` "`+build_instance+
 		`"`+` -- `+ssh_flags.AsArgs()+` ./remove_old_gce_kernel.sh`)
 
diff --git a/tools/create_base_image_gce.sh b/tools/create_base_image_gce.sh
index 7073c834f..4e851fb50 100755
--- a/tools/create_base_image_gce.sh
+++ b/tools/create_base_image_gce.sh
@@ -106,19 +106,36 @@ if [ ! -f /mnt/image/etc/resolv.conf ]; then
 fi
 sudo chroot /mnt/image /usr/bin/apt update
 sudo chroot /mnt/image /usr/bin/apt install -y "${tmp_debs[@]}"
+
+# Install JDK.
+#
+# JDK it's not required to launch a CF device. It's required to run
+# some of Tradefed tests that are run from the CF host side like
+# some CF gfx tests, adb tests, etc.
+sudo chroot /mnt/image /usr/bin/wget -P /usr/java https://download.java.net/java/GA/jdk21.0.2/f2283984656d49d69e91c558476027ac/13/GPL/openjdk-21.0.2_linux-x64_bin.tar.gz
+# https://download.java.net/java/GA/jdk21.0.2/f2283984656d49d69e91c558476027ac/13/GPL/openjdk-21.0.2_linux-x64_bin.tar.gz.sha256
+export JDK21_SHA256SUM=a2def047a73941e01a73739f92755f86b895811afb1f91243db214cff5bdac3f
+if ! echo "$JDK21_SHA256SUM /usr/java/openjdk-21.0.2_linux-x64_bin.tar.gz" | sudo chroot /mnt/image /usr/bin/sha256sum -c ; then
+  echo "** ERROR: KEY MISMATCH **"; popd >/dev/null; exit 1;
+fi
+sudo chroot /mnt/image /usr/bin/tar xvzf /usr/java/openjdk-21.0.2_linux-x64_bin.tar.gz -C /usr/java
+sudo chroot /mnt/image /usr/bin/rm /usr/java/openjdk-21.0.2_linux-x64_bin.tar.gz
+echo 'JAVA_HOME=/usr/java/jdk-21.0.2' | sudo chroot /mnt/image /usr/bin/tee -a /etc/environment >/dev/null
+echo 'JAVA_HOME=/usr/java/jdk-21.0.2' | sudo chroot /mnt/image /usr/bin/tee -a /etc/profile >/dev/null
+echo 'PATH=$JAVA_HOME/bin:$PATH' | sudo chroot /mnt/image /usr/bin/tee -a /etc/profile >/dev/null
+
 # install tools dependencies
-sudo chroot /mnt/image /usr/bin/apt install -y openjdk-21-jre
 sudo chroot /mnt/image /usr/bin/apt install -y unzip bzip2 lzop
 sudo chroot /mnt/image /usr/bin/apt install -y aapt
 sudo chroot /mnt/image /usr/bin/apt install -y screen # needed by tradefed
 
 sudo chroot /mnt/image /usr/bin/find /home -ls
-sudo chroot /mnt/image /usr/bin/apt install -t bullseye-backports -y linux-image-cloud-amd64
+sudo chroot /mnt/image /usr/bin/apt install -t bookworm-security -y linux-image-cloud-amd64
 
 # update QEMU version to most recent backport
-sudo chroot /mnt/image /usr/bin/apt install -y --only-upgrade qemu-system-x86 -t bullseye-backports
-sudo chroot /mnt/image /usr/bin/apt install -y --only-upgrade qemu-system-arm -t bullseye-backports
-sudo chroot /mnt/image /usr/bin/apt install -y --only-upgrade qemu-system-misc -t bullseye-backports
+sudo chroot /mnt/image /usr/bin/apt install -y --only-upgrade qemu-system-x86 -t bookworm
+sudo chroot /mnt/image /usr/bin/apt install -y --only-upgrade qemu-system-arm -t bookworm
+sudo chroot /mnt/image /usr/bin/apt install -y --only-upgrade qemu-system-misc -t bookworm
 
 # Install GPU driver dependencies
 sudo cp install_nvidia.sh /mnt/image/
@@ -126,11 +143,11 @@ sudo chroot /mnt/image /usr/bin/bash install_nvidia.sh
 sudo rm /mnt/image/install_nvidia.sh
 
 # Vulkan loader
-sudo chroot /mnt/image /usr/bin/apt install -y libvulkan1 -t bullseye-backports
+sudo chroot /mnt/image /usr/bin/apt install -y libvulkan1 -t bookworm
 
 # Wayland-server needed to have Nvidia driver fail gracefully when attempting to
 # use the EGL API on GCE instances without a GPU.
-sudo chroot /mnt/image /usr/bin/apt install -y libwayland-server0 -t bullseye-backports
+sudo chroot /mnt/image /usr/bin/apt install -y libwayland-server0 -t bookworm
 
 # Clean up the builder's version of resolv.conf
 sudo rm /mnt/image/etc/resolv.conf
diff --git a/tools/create_base_image_hostlib.sh b/tools/create_base_image_hostlib.sh
index 8045f77ec..03d0c992a 100755
--- a/tools/create_base_image_hostlib.sh
+++ b/tools/create_base_image_hostlib.sh
@@ -33,14 +33,14 @@ DEFINE_string dest_project "$(gcloud config get-value project)" \
   "Project to use for the new image" "p"
 DEFINE_string launch_instance "" \
   "Name of the instance to launch with the new image" "l"
-DEFINE_string source_image_family "debian-11" \
+DEFINE_string source_image_family "debian-12" \
   "Image familty to use as the base" "s"
 DEFINE_string source_image_project debian-cloud \
   "Project holding the base image" "m"
 DEFINE_string repository_url \
   "https://github.com/google/android-cuttlefish.git" \
   "URL to the repository with host changes" "u"
-DEFINE_string repository_branch main \
+DEFINE_string repository_branch v0.9.30 \
   "Branch to check out" "b"
 
 
diff --git a/tools/install_nvidia.sh b/tools/install_nvidia.sh
index 9f82e4456..7c6e1e24c 100755
--- a/tools/install_nvidia.sh
+++ b/tools/install_nvidia.sh
@@ -34,7 +34,7 @@ kmodver=$(dpkg -s linux-image-cloud-${arch} | grep ^Depends: | \
 
 apt-get install -y wget
 # Install headers from backports, to match the linux-image
-apt-get install -y -t bullseye-backports $(echo linux-headers-${kmodver})
+apt-get install -y -t bookworm-security $(echo linux-headers-${kmodver})
 # Dependencies for nvidia-installer
 apt-get install -y dkms libglvnd-dev libc6-dev pkg-config
 
diff --git a/tools/launch_cvd_arm64_server.sh b/tools/launch_cvd_arm64_server.sh
index 8bfea1fd3..ad9ba6cb6 100755
--- a/tools/launch_cvd_arm64_server.sh
+++ b/tools/launch_cvd_arm64_server.sh
@@ -55,6 +55,10 @@ mkdir -p $temp_dir
 # copy and compress the artifacts to the temp directory
 cvd_home_dir=cvd_home
 ssh $server -t "mkdir -p ~/.cvd_artifact; mkdir -p ~/$cvd_home_dir"
+
+# android-info.txt is required for cvd launcher to pick up the correct config file.
+rsync -avch $img_dir/android-info.txt $server:~/$cvd_home_dir --info=progress2
+
 if [ -f $img_dir/required_images ]; then
   rsync -aSvch --recursive $img_dir --files-from=$img_dir/required_images $server:~/$cvd_home_dir --info=progress2
 else
diff --git a/tools/launch_cvd_arm64_server_docker.sh b/tools/launch_cvd_arm64_server_docker.sh
index d3fccebc6..11b4b891f 100755
--- a/tools/launch_cvd_arm64_server_docker.sh
+++ b/tools/launch_cvd_arm64_server_docker.sh
@@ -18,10 +18,11 @@ color_plain="\033[0m"
 color_yellow="\033[0;33m"
 
 # validate number of arguments
-if [ "$#" -lt 1 ] || [ "$#" -gt 4 ]; then
-  echo "This script requires 1 mandatory and 3 optional parameters,"
+if [ "$#" -lt 1 ] || [ "$#" -gt 5 ]; then
+  echo "This script requires 1 mandatory and 4 optional parameters,"
   echo "server address and optionally cvd instances per docker, and number of " \
-       "docker instances to invoke, and vendor_boot image to replace."
+       "docker instances to invoke, vendor_boot image to replace, and config " \
+       "file path for launching configuration."
   exit 1
 fi
 
@@ -50,6 +51,22 @@ else
  vendor_boot_image=$4
 fi
 
+if [ "$#" -lt 5 ]; then
+ config_path=""
+else
+ config_path=$5
+ if [ ! -f $config_path ]; then
+  echo Config file $config_path does not exist
+  exit 1
+ fi
+
+ if ! cat $config_path | jq > /dev/null ; then
+  echo Failed to parse config file $config_path
+  exit 1
+ fi
+fi
+
+
 # set img_dir and cvd_host_tool_dir
 img_dir=${ANDROID_PRODUCT_OUT:-$PWD}
 cvd_host_tool_dir=${ANDROID_HOST_OUT:+"$ANDROID_HOST_OUT/../linux_musl-arm64"}
@@ -58,6 +75,10 @@ cvd_host_tool_dir=${cvd_host_tool_dir:-$PWD}
 # upload artifacts into ARM server
 cvd_home_dir=cvd_home
 ssh $server -t "mkdir -p ~/.cvd_artifact; mkdir -p ~/$cvd_home_dir"
+
+# android-info.txt is required for cvd launcher to pick up the correct config file.
+rsync -avch $img_dir/android-info.txt $server:~/$cvd_home_dir --info=progress2
+
 if [ -f $img_dir/required_images ]; then
   rsync -aSvch --recursive $img_dir --files-from=$img_dir/required_images $server:~/$cvd_home_dir --info=progress2
   cvd_home_files=($(rsync -rzan --recursive $img_dir --out-format="%n" --files-from=$img_dir/required_images $server:~/$cvd_home_dir --info=name2 | awk '{print $1}'))
@@ -205,17 +226,52 @@ for docker_inspect in ${docker_inspects[*]}; do
   host_orchestrator_ports+=($port)
 done
 
+if [[ $config_path != "" ]]; then
+  cvd_creation_data=$(cat $config_path | jq -c)
+else
+  cvd_creation_data="{\"cvd\":{\"build_source\": \
+    {\"user_build_source\":{\"artifacts_dir\":\"$user_artifacts_dir\"}}}, \
+    \"additional_instances_num\":$((num_instances_per_docker - 1))}";
+fi
+cvd_creation_data=$(echo $cvd_creation_data | sed s/\$user_artifact_id/$user_artifacts_dir/g)
+
 # start Cuttlefish instance on top of docker instance
 # TODO(b/317942272): support starting the instance with an optional vendor boot debug image.
 echo -e "Starting Cuttlefish"
-ssh $server "for port in ${host_orchestrator_ports[*]}; do \
+ssh $server "job_ids=() && \
+for port in ${host_orchestrator_ports[*]}; do \
   host_orchestrator_url=https://localhost:\$port && \
-  curl -s -k -X POST \$host_orchestrator_url/cvds \
-  -H 'Content-Type: application/json' \
-  -d '{\"cvd\": {\"build_source\": {\"user_build_source\": {\"artifacts_dir\": \"$user_artifacts_dir\"}}}, \
-       \"additional_instances_num\": $((num_instances_per_docker - 1))}'; \
-done
+  job_id=\"\" && \
+  while [ -z \"\$job_id\" ]; do \
+    job_id=\$(curl -s -k -X POST \$host_orchestrator_url/cvds \
+      -H 'Content-Type: application/json' \
+      -d '$cvd_creation_data' \
+        | jq -r '.name') && \
+    if [ -z \"\$job_id\" ]; then \
+      echo \"  Failed to request creating Cuttlefish, retrying\" && \
+      sleep 1; \
+    else \
+      echo \"  Succeeded to request: \$job_id\" && \
+      job_ids+=(\${job_id}); \
+    fi; \
+  done; \
+done \
+
+echo \"Waiting Cuttlefish instances to be booted\" && \
+i=0 && \
+for port in ${host_orchestrator_ports[*]}; do \
+  job_id=\${job_ids[\$i]} && \
+  i=\$((i+1)) && \
+  host_orchestrator_url=https://localhost:\$port && \
+  job_done=\"false\" && \
+  while [[ \$job_done == \"false\" ]]; do \
+    sleep 1 && \
+    job_done=\$(curl -s -k \${host_orchestrator_url}/operations/\$job_id | jq -r '.done'); \
+  done && \
+  echo \"  Boot completed: \$job_id\"; \
+done \
 "
+echo -e "Done"
 
 # Web UI port is 3443 instead 1443 because there could be a running operator or host orchestrator in this machine as well.
 web_ui_port=3443
diff --git a/tools/remove_old_gce_kernel.sh b/tools/remove_old_gce_kernel.sh
index 191b6d013..106307f89 100755
--- a/tools/remove_old_gce_kernel.sh
+++ b/tools/remove_old_gce_kernel.sh
@@ -17,4 +17,5 @@
 set -x
 set -o errexit
 
+dpkg --list | grep -v $(uname -r) | grep -E 'linux-image-[0-9]|linux-headers-[0-9]' | awk '{print $2" "$3}' | sort -k2,2 | awk '{print $1}' | xargs sudo apt-get -y purge
 sudo update-grub2
diff --git a/tools/update_gce_kernel.sh b/tools/update_gce_kernel.sh
index 2075a682e..2c9515916 100755
--- a/tools/update_gce_kernel.sh
+++ b/tools/update_gce_kernel.sh
@@ -17,5 +17,6 @@
 set -x
 set -o errexit
 
-sudo apt install -t bullseye-backports -y linux-image-cloud-amd64
+sudo apt update
+sudo apt install -t bookworm-security -y linux-image-cloud-amd64
 sudo reboot
diff --git a/tools/upload_to_gce_and_run.py b/tools/upload_to_gce_and_run.py
index 221ce5325..c067a79f2 100755
--- a/tools/upload_to_gce_and_run.py
+++ b/tools/upload_to_gce_and_run.py
@@ -35,7 +35,7 @@ def upload_artifacts(args):
   try:
     os.chdir(args.image_dir)
     artifacts = []
-    artifact_patterns = ['*.img', 'bootloader']
+    artifact_patterns = ['*.img', 'bootloader', 'android-info.txt']
     for artifact_pattern in artifact_patterns:
       artifacts.extend(glob.glob(artifact_pattern))
     if len(artifacts) == 0:
diff --git a/vsoc_arm64_only/auto/OWNERS b/vsoc_arm64_only/auto/OWNERS
index f97912a73..f311e6d98 100644
--- a/vsoc_arm64_only/auto/OWNERS
+++ b/vsoc_arm64_only/auto/OWNERS
@@ -1,4 +1 @@
-# Android Auto leads
-include platform/packages/services/Car:/OWNERS
-ankitarora@google.com
-egranata@google.com
+include device/google/cuttlefish:/shared/auto/OWNERS
diff --git a/vsoc_arm64_pgagnostic/phone/aosp_cf.mk b/vsoc_arm64_pgagnostic/phone/aosp_cf.mk
index e9fcaf605..ff10dca22 100644
--- a/vsoc_arm64_pgagnostic/phone/aosp_cf.mk
+++ b/vsoc_arm64_pgagnostic/phone/aosp_cf.mk
@@ -66,3 +66,5 @@ PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.model=$(PRODUCT_DEVICE)
 
 PRODUCT_16K_DEVELOPER_OPTION := true
+
+TARGET_BOOTS_16K := true
diff --git a/vsoc_riscv64/wear/OWNERS b/vsoc_riscv64/wear/OWNERS
new file mode 100644
index 000000000..c97d372a2
--- /dev/null
+++ b/vsoc_riscv64/wear/OWNERS
@@ -0,0 +1 @@
+include device/google/cuttlefish:/shared/wear/OWNERS
diff --git a/vsoc_x86/OWNERS b/vsoc_x86/OWNERS
new file mode 100644
index 000000000..13a1451af
--- /dev/null
+++ b/vsoc_x86/OWNERS
@@ -0,0 +1,3 @@
+include device/google/cuttlefish:/shared/go/OWNERS
+include device/google/cuttlefish:/shared/tv/OWNERS
+include device/google/cuttlefish:/shared/wear/OWNERS
diff --git a/vsoc_x86/go/OWNERS b/vsoc_x86/go/OWNERS
index 0c77d0e42..38bdcde56 100644
--- a/vsoc_x86/go/OWNERS
+++ b/vsoc_x86/go/OWNERS
@@ -1,2 +1 @@
-rajekumar@google.com
-tjoines@google.com
+include device/google/cuttlefish:/shared/go/OWNERS
diff --git a/vsoc_x86/pasan/aosp_cf.mk b/vsoc_x86/pasan/aosp_cf.mk
deleted file mode 100644
index f0b4967ad..000000000
--- a/vsoc_x86/pasan/aosp_cf.mk
+++ /dev/null
@@ -1,56 +0,0 @@
-#
-# Copyright (C) 2019 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-#
-# All components inherited here go to system image (same as GSI system)
-#
-$(call inherit-product, $(SRC_TARGET_DIR)/product/generic_system.mk)
-
-PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
-
-#
-# All components inherited here go to system_ext image (same as GSI system_ext)
-#
-$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system_ext.mk)
-$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
-
-#
-# All components inherited here go to product image (same as GSI product)
-#
-$(call inherit-product, $(SRC_TARGET_DIR)/product/aosp_product.mk)
-
-#
-# All components inherited here go to vendor image
-#
-$(call inherit-product, device/google/cuttlefish/shared/phone/device_vendor.mk)
-
-#
-# Special settings for the target
-#
-$(call inherit-product, device/google/cuttlefish/vsoc_x86_64/bootloader.mk)
-
-# Exclude features that are not available on AOSP devices.
-PRODUCT_COPY_FILES += \
-    frameworks/native/data/etc/aosp_excluded_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/aosp_excluded_hardware.xml
-
-PRODUCT_NAME := aosp_cf_x86_pasan
-PRODUCT_DEVICE := vsoc_x86
-PRODUCT_MANUFACTURER := Google
-PRODUCT_MODEL := Cuttlefish x86 phone
-
-PRODUCT_VENDOR_PROPERTIES += \
-    ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
-    ro.soc.model=$(PRODUCT_DEVICE)
diff --git a/vsoc_x86/phone/aosp_cf.mk b/vsoc_x86/phone/aosp_cf.mk
deleted file mode 100644
index b0df4487e..000000000
--- a/vsoc_x86/phone/aosp_cf.mk
+++ /dev/null
@@ -1,56 +0,0 @@
-#
-# Copyright (C) 2019 The Android Open Source Project
-#
-# Licensed under the Apache License, Version 2.0 (the "License");
-# you may not use this file except in compliance with the License.
-# You may obtain a copy of the License at
-#
-#      http://www.apache.org/licenses/LICENSE-2.0
-#
-# Unless required by applicable law or agreed to in writing, software
-# distributed under the License is distributed on an "AS IS" BASIS,
-# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-# See the License for the specific language governing permissions and
-# limitations under the License.
-#
-
-#
-# All components inherited here go to system image (same as GSI system)
-#
-$(call inherit-product, $(SRC_TARGET_DIR)/product/generic_system.mk)
-
-PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
-
-#
-# All components inherited here go to system_ext image (same as GSI system_ext)
-#
-$(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system_ext.mk)
-$(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
-
-#
-# All components inherited here go to product image (same as GSI product)
-#
-$(call inherit-product, $(SRC_TARGET_DIR)/product/aosp_product.mk)
-
-#
-# All components inherited here go to vendor image
-#
-$(call inherit-product, device/google/cuttlefish/shared/phone/device_vendor.mk)
-
-#
-# Special settings for the target
-#
-$(call inherit-product, device/google/cuttlefish/vsoc_x86_64/bootloader.mk)
-
-# Exclude features that are not available on AOSP devices.
-PRODUCT_COPY_FILES += \
-    frameworks/native/data/etc/aosp_excluded_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/aosp_excluded_hardware.xml
-
-PRODUCT_NAME := aosp_cf_x86_phone
-PRODUCT_DEVICE := vsoc_x86
-PRODUCT_MANUFACTURER := Google
-PRODUCT_MODEL := Cuttlefish x86 phone
-
-PRODUCT_VENDOR_PROPERTIES += \
-    ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
-    ro.soc.model=$(PRODUCT_DEVICE)
diff --git a/vsoc_x86/tv/OWNERS b/vsoc_x86/tv/OWNERS
new file mode 100644
index 000000000..2d0968924
--- /dev/null
+++ b/vsoc_x86/tv/OWNERS
@@ -0,0 +1,2 @@
+include device/google/cuttlefish:/shared/tv/OWNERS
+
diff --git a/vsoc_x86/wear/OWNERS b/vsoc_x86/wear/OWNERS
new file mode 100644
index 000000000..c97d372a2
--- /dev/null
+++ b/vsoc_x86/wear/OWNERS
@@ -0,0 +1 @@
+include device/google/cuttlefish:/shared/wear/OWNERS
diff --git a/vsoc_x86_64/phone/aosp_cf.mk b/vsoc_x86_64/phone/aosp_cf.mk
index a101d68bb..52aaec465 100644
--- a/vsoc_x86_64/phone/aosp_cf.mk
+++ b/vsoc_x86_64/phone/aosp_cf.mk
@@ -61,3 +61,13 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/window_extensions.mk)
 PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
     ro.soc.model=$(PRODUCT_DEVICE)
+
+# Compare target product name directly to avoid this from any product inherits aosp_cf.mk
+ifneq ($(filter aosp_cf_x86_64_phone aosp_cf_x86_64_phone_soong_system,$(TARGET_PRODUCT)),)
+# TODO(b/350000347) Enable Soong defined system image from coverage build
+ifneq ($(CLANG_COVERAGE),true)
+ifneq ($(NATIVE_COVERAGE),true)
+PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := aosp_cf_system_x86_64
+endif # NATIVE_COVERAGE
+endif # CLANG_COVERAGE
+endif # aosp_cf_x86_64_phone
diff --git a/vsoc_x86_64/phone/aosp_cf_soong_system.mk b/vsoc_x86_64/phone/aosp_cf_soong_system.mk
new file mode 100644
index 000000000..59b8719f3
--- /dev/null
+++ b/vsoc_x86_64/phone/aosp_cf_soong_system.mk
@@ -0,0 +1,20 @@
+#
+# Copyright (C) 2024 The Android Open Source Project
+#
+# Licensed under the Apache License, Version 2.0 (the "License");
+# you may not use this file except in compliance with the License.
+# You may obtain a copy of the License at
+#
+#      http://www.apache.org/licenses/LICENSE-2.0
+#
+# Unless required by applicable law or agreed to in writing, software
+# distributed under the License is distributed on an "AS IS" BASIS,
+# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+# See the License for the specific language governing permissions and
+# limitations under the License.
+#
+
+$(call inherit-product, device/google/cuttlefish/vsoc_x86_64/phone/aosp_cf.mk)
+PRODUCT_NAME := aosp_cf_x86_64_phone_soong_system
+
+USE_SOONG_DEFINED_SYSTEM_IMAGE := true
diff --git a/vsoc_x86_64/tv/OWNERS b/vsoc_x86_64/tv/OWNERS
index 4df9f2711..ea0209fb9 100644
--- a/vsoc_x86_64/tv/OWNERS
+++ b/vsoc_x86_64/tv/OWNERS
@@ -1,2 +1 @@
-# Bug component: 760438
-include device/google/atv:/OWNERS
+include device/google/cuttlefish:/shared/tv/OWNERS
diff --git a/vsoc_x86_64_only/auto/OWNERS b/vsoc_x86_64_only/auto/OWNERS
index f97912a73..f311e6d98 100644
--- a/vsoc_x86_64_only/auto/OWNERS
+++ b/vsoc_x86_64_only/auto/OWNERS
@@ -1,4 +1 @@
-# Android Auto leads
-include platform/packages/services/Car:/OWNERS
-ankitarora@google.com
-egranata@google.com
+include device/google/cuttlefish:/shared/auto/OWNERS
diff --git a/vsoc_x86_64_only/auto/aosp_cf.mk b/vsoc_x86_64_only/auto/aosp_cf.mk
index 92768192c..bf8ca68ff 100644
--- a/vsoc_x86_64_only/auto/aosp_cf.mk
+++ b/vsoc_x86_64_only/auto/aosp_cf.mk
@@ -55,6 +55,12 @@ $(call inherit-product, device/google/cuttlefish/vsoc_x86_64/bootloader.mk)
 PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/aosp_excluded_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/aosp_excluded_hardware.xml
 
+# Exclude features that are not available on automotive cuttlefish devices.
+# TODO(b/351896700): Remove this workaround once support for uncalibrated accelerometer and
+# uncalibrated gyroscope are added to automotive cuttlefish.
+PRODUCT_COPY_FILES += \
+    device/google/cuttlefish/vsoc_x86_64_only/auto/exclude_unavailable_imu_features.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/exclude_unavailable_imu_features.xml
+
 PRODUCT_NAME := aosp_cf_x86_64_only_auto
 PRODUCT_DEVICE := vsoc_x86_64_only
 PRODUCT_MANUFACTURER := Google
diff --git a/vsoc_x86_64_only/auto/exclude_unavailable_imu_features.xml b/vsoc_x86_64_only/auto/exclude_unavailable_imu_features.xml
new file mode 100644
index 000000000..612843084
--- /dev/null
+++ b/vsoc_x86_64_only/auto/exclude_unavailable_imu_features.xml
@@ -0,0 +1,24 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright 2024 The Android Open Source Project
+
+     Licensed under the Apache License, Version 2.0 (the "License");
+     you may not use this file except in compliance with the License.
+     You may obtain a copy of the License at
+
+          http://www.apache.org/licenses/LICENSE-2.0
+
+     Unless required by applicable law or agreed to in writing, software
+     distributed under the License is distributed on an "AS IS" BASIS,
+     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+     See the License for the specific language governing permissions and
+     limitations under the License.
+-->
+
+<permissions>
+    <!-- Uncalibrated acceleromter and gyroscope aren't supported on cuttlefish. Until support is
+    added, the limited axes versions of these sensors won't be generated and as a result should not
+    be included in the device through package manager features. Removing these until support is
+    added for these sensors. -->
+    <unavailable-feature name="android.hardware.sensor.accelerometer_limited_axes_uncalibrated" />
+    <unavailable-feature name="android.hardware.sensor.gyroscope_limited_axes_uncalibrated" />
+</permissions>
diff --git a/vsoc_x86_64_only/auto_dd/aosp_cf.mk b/vsoc_x86_64_only/auto_dd/aosp_cf.mk
index 3c882fdd8..eb1618f95 100644
--- a/vsoc_x86_64_only/auto_dd/aosp_cf.mk
+++ b/vsoc_x86_64_only/auto_dd/aosp_cf.mk
@@ -16,9 +16,6 @@
 # AOSP Car UI Distant Display Cuttlefish Target
 TARGET_BOARD_INFO_FILE := device/google/cuttlefish/shared/auto_dd/android-info.txt
 
-# Exclude AAE Car System UI
-DO_NOT_INCLUDE_AAE_CAR_SYSTEM_UI := true
-
 PRODUCT_COPY_FILES += \
     device/google/cuttlefish/shared/auto_dd/display_settings.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings.xml
 
diff --git a/vsoc_x86_64_only/auto_md/aosp_cf.mk b/vsoc_x86_64_only/auto_md/aosp_cf.mk
index 5ad8200ce..5adfbb014 100644
--- a/vsoc_x86_64_only/auto_md/aosp_cf.mk
+++ b/vsoc_x86_64_only/auto_md/aosp_cf.mk
@@ -36,14 +36,17 @@ PRODUCT_PACKAGES += \
     ClusterOsDouble \
     CarServiceOverlayEmulatorOsDouble \
     CarServiceOverlayMdEmulatorOsDouble \
-    MultiDisplaySecondaryHomeTestLauncher \
-    MultiDisplayTest
+    MultiDisplayTest \
+    AAECarControlCenterApp
 
 PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
     com.android.car.internal.debug.num_auto_populated_users=1 # 1 passenger only (so 2nd display shows user picker)
 # TODO(b/233370174): add audio multi-zone
 #   ro.vendor.simulateMultiZoneAudio=true \
 
+# enables the rro package for passenger(secondary) user.
+ENABLE_PASSENGER_SYSTEMUI_RRO := true
+
 # Enable per-display power management
 PRODUCT_COPY_FILES += \
     device/google/cuttlefish/vsoc_x86_64_only/auto_md/display_layout_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/displayconfig/display_layout_configuration.xml
diff --git a/vsoc_x86_64_only/auto_portrait/OWNERS b/vsoc_x86_64_only/auto_portrait/OWNERS
index 5bc897b71..2a3eac8c5 100644
--- a/vsoc_x86_64_only/auto_portrait/OWNERS
+++ b/vsoc_x86_64_only/auto_portrait/OWNERS
@@ -1,4 +1 @@
-include device/google/cuttlefish:/shared/auto/OWNERS
-babakbo@google.com
-calhuang@google.com
-priyanksingh@google.com
+include device/google/cuttlefish:/shared/auto_portrait/OWNERS
diff --git a/vsoc_x86_64_only/auto_portrait/aosp_cf.mk b/vsoc_x86_64_only/auto_portrait/aosp_cf.mk
index e23c01a15..c09aba7f1 100644
--- a/vsoc_x86_64_only/auto_portrait/aosp_cf.mk
+++ b/vsoc_x86_64_only/auto_portrait/aosp_cf.mk
@@ -21,8 +21,8 @@ TARGET_BOARD_INFO_FILE := device/google/cuttlefish/shared/auto_portrait/android-
 PRODUCT_COPY_FILES += \
     device/google/cuttlefish/shared/auto_portrait/display_settings.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings.xml
 
-# Exclude AAE Car System UI
-DO_NOT_INCLUDE_AAE_CAR_SYSTEM_UI := true
+# Exclude GAS Car Launcher
+DO_NOT_INCLUDE_GAS_CAR_LAUNCHER := true
 
 # Exclude Car UI Reference Design
 DO_NOT_INCLUDE_CAR_UI_REFERENCE_DESIGN := true
diff --git a/vsoc_x86_64_only/wear/OWNERS b/vsoc_x86_64_only/wear/OWNERS
new file mode 100644
index 000000000..c97d372a2
--- /dev/null
+++ b/vsoc_x86_64_only/wear/OWNERS
@@ -0,0 +1 @@
+include device/google/cuttlefish:/shared/wear/OWNERS
diff --git a/vsoc_x86_64_pgagnostic/BoardConfig.mk b/vsoc_x86_64_pgagnostic/BoardConfig.mk
index c0def09e2..ae9082936 100644
--- a/vsoc_x86_64_pgagnostic/BoardConfig.mk
+++ b/vsoc_x86_64_pgagnostic/BoardConfig.mk
@@ -37,7 +37,7 @@ KERNEL_MODULES_PATH ?= \
     kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))
 
 # Emulate 16KB page size
-BOARD_KERNEL_CMDLINE += androidboot.page_shift=14
+BOARD_KERNEL_CMDLINE += page_shift=14
 
 TARGET_USERDATAIMAGE_FILE_SYSTEM_TYPE := ext4
 TARGET_RO_FILE_SYSTEM_TYPE := ext4
diff --git a/vsoc_x86_64_pgagnostic/phone/aosp_cf.mk b/vsoc_x86_64_pgagnostic/phone/aosp_cf.mk
index 2c8d842fc..8b7064546 100644
--- a/vsoc_x86_64_pgagnostic/phone/aosp_cf.mk
+++ b/vsoc_x86_64_pgagnostic/phone/aosp_cf.mk
@@ -69,3 +69,5 @@ PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.model=$(PRODUCT_DEVICE)
 
 PRODUCT_16K_DEVELOPER_OPTION := true
+
+TARGET_BOOTS_16K := true
```

